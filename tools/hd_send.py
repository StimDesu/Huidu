#!/usr/bin/env python3
"""
hd_send.py — upload a project (.boo + images) to a Huidu BoxPlayer board the way
HDPlayer 7.6.27 does it. Standard library only (Pillow optional, for resizing).

Protocol: binary "project update" session on TCP 9527, reproduced 1:1 from a capture of
HDPlayer 7.6.27.0 -> HD-C35 firmware 7.1.51.0. See
products/BoxPlayer/PROJECT_UPLOAD_PROTOCOL.md.

Nothing is transmitted without --yes; without it the script only prints the plan.

Commands
  extract   pull the files HDPlayer sent out of a .pcap/.pcapng
              python hd_send.py extract capture.pcapng -o out_dir
  replay    re-send exactly what HDPlayer sent in a capture (board ends up in the same
            state it is in now — the safest real test of the upload path)
              python hd_send.py replay capture.pcapng --host 10.10.206.175 --yes
  send      send an existing .boo plus the images it references
              python hd_send.py send --host IP --boo project.boo img1.png ... --yes
  slideshow build a new one-area slideshow .boo from images and send it
              python hd_send.py slideshow --host IP a.png b.png --hold 50 --yes
            any input format (JPG/PNG/BMP…, needs Pillow unless already a PNG of the
            exact area size); area size from the board or --size WxH; --fit
            contain|cover|stretch; --preview DIR saves the converted PNGs. With --size
            and no reply from the board it runs offline (convert/preview only):
              python hd_send.py slideshow --host IP *.jpg --size 352x384 --preview prev
            images may be files, folders (all images inside, natural name order) or
            wildcards:  python hd_send.py slideshow --host IP C:\\ads\\screen206 --yes
"""

import argparse
import datetime
import glob
import hashlib
import os
import socket
import struct
import sys
import time
import uuid

PORT = 9527
CHUNK = 9212             # 0x0019 payload size used by HDPlayer
WINDOW = 3               # max unacknowledged 0x0019 chunks (HDPlayer ran ~3 ahead)
CONN_VERSION = 0x01000007

VERBOSE = False


def log(msg):
    print(msg)


def dbg(msg):
    if VERBOSE:
        print("   · " + msg)


def hexs(b, limit=48):
    s = b[:limit].hex(" ")
    return s + (" …(+%d)" % (len(b) - limit) if len(b) > limit else "")


def md5(data):
    return hashlib.md5(data).hexdigest()


# ─────────────────────────────── transport ────────────────────────────────────

class Session:
    def __init__(self, host, port=PORT, timeout=15.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, cmd, payload=b""):
        dbg("-> 0x%04x len=%d  %s" % (cmd, len(payload), hexs(payload)))
        self.sock.sendall(struct.pack("<HH", 4 + len(payload), cmd) + payload)

    def recv(self):
        while True:
            while len(self.buf) < 4 or len(self.buf) < struct.unpack_from("<H", self.buf)[0]:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise ConnectionError("устройство закрыло соединение")
                self.buf += chunk
            total, cmd = struct.unpack_from("<HH", self.buf)
            if total < 4:
                raise ConnectionError("битый кадр: длина %d" % total)
            payload, self.buf = self.buf[4:total], self.buf[total:]
            dbg("<- 0x%04x len=%d  %s" % (cmd, len(payload), hexs(payload)))
            if cmd == 0x005F:
                self.send(0x0060)
                continue
            if cmd == 0x0060:
                continue
            return cmd, payload

    def expect(self, want, what):
        cmd, payload = self.recv()
        if cmd != want:
            raise ConnectionError("%s: ждали 0x%04x, пришло 0x%04x (%s)" % (what, want, cmd, hexs(payload)))
        return payload

    def call(self, cmd, payload, what):
        self.send(cmd, payload)
        return self.expect(cmd + 1, what)


def u32(p):
    return struct.unpack_from("<I", p)[0] if len(p) >= 4 else None


def upload_file(s, name, data):
    st = u32(s.call(0x0017, name.encode("utf-8") + b"\0", "OpenFile " + name))
    if st:
        raise ConnectionError("OpenFile %s: статус %d" % (name, st))
    sent = acked = 0
    for off in range(0, len(data), CHUNK):
        while sent - acked >= WINDOW:
            s.expect(0x001A, "ack чанка")
            acked += 1
        s.send(0x0019, data[off:off + CHUNK])
        sent += 1
        log("   %s: %d/%d байт" % (name, min(off + CHUNK, len(data)), len(data)))
    s.send(0x001B)
    while True:  # remaining 0x001a acks, then CloseFile answer 0x001c
        cmd, p = s.recv()
        if cmd == 0x001A:
            acked += 1
            continue
        if cmd == 0x001C:
            if u32(p):
                raise ConnectionError("CloseFile %s: статус %d" % (name, u32(p)))
            return
        raise ConnectionError("после CloseFile пришло 0x%04x" % cmd)


def run_session(host, boo_name, boo, files, force_all=False):
    """files: {device_file_name: bytes}. The .boo is always sent last."""
    total = len(boo) + sum(len(d) for d in files.values())
    s = Session(host)
    in_project = False
    try:
        dev = u32(s.call(0x000B, struct.pack("<I", CONN_VERSION), "Version"))
        log("Подключено, версия протокола устройства 0x%08x" % dev)
        now = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        s.call(0x0410, ("admin,%s,%s" % (uuid.uuid4(), now)).encode() + b"\0", "Login")
        st = u32(s.call(0x000D, b"", "UpdateProject"))
        in_project = True
        if st:
            raise ConnectionError("UpdateProject: статус %d (плата занята/отказала)" % st)
        s.call(0x040A, b"", "0x040a")
        free = u32(s.call(0x000F, struct.pack("<Q", total), "FreeSpace"))
        if free != 1:
            raise ConnectionError("FreeSpace вернул %r (HDPlayer получил 1) — не хватает места?" % free)
        have = set()
        while True:
            p = s.call(0x0011, b"", "FileList")
            names = [x.decode("ascii", "replace") for x in p.split(b"\0") if x]
            if not names:
                break
            have.update(names)
        log("На плате файлов (по MD5): %d" % len(have))
        inc = s.call(0x0013, b"", "ImcompleteFile")
        if inc.strip(b"\0"):
            log("! ImcompleteFile вернул %s (у HDPlayer были нули)" % hexs(inc))
        s.call(0x0015, struct.pack("<I", 8), "RemoveFileList")
        for name, data in files.items():
            if not force_all and name.split(".")[0] in have:
                log("   %s уже есть на плате — пропускаю" % name)
                continue
            upload_file(s, name, data)
        upload_file(s, boo_name, boo)
        s.call(0x001D, b"", "TransEnd")
        s.call(0x001F, b"", "UpdateProjectQuit")
        in_project = False
        log("Готово. Плата перезагрузит программу (экран гаснет на ~2 с).")
    finally:
        if in_project:
            try:  # leave project mode so the board keeps its current program
                log("Прерываю сессию (UpdateProjectQuit)…")
                s.call(0x001F, b"", "UpdateProjectQuit")
            except Exception as e:
                log("   не удалось: %s" % e)
        s.close()


# ─────────────────────────────── pcap extract ─────────────────────────────────

def pcap_packets(path):
    d = open(path, "rb").read()
    if d[:4] == b"\n\r\r\n":
        i, links = 0, []
        while i + 8 <= len(d):
            bt, bl = struct.unpack_from("<II", d, i)
            if bl < 12:
                break
            if bt == 1:
                links.append(struct.unpack_from("<H", d, i + 8)[0])
            elif bt == 6:
                iid, _, _, cap = struct.unpack_from("<IIII", d, i + 8)
                yield links[iid] if iid < len(links) else 1, d[i + 28:i + 28 + cap]
            i += bl
    else:
        end = "<" if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        link = struct.unpack_from(end + "I", d, 20)[0]
        i = 24
        while i + 16 <= len(d):
            cap = struct.unpack_from(end + "I", d, i + 8)[0]
            yield link, d[i + 16:i + 16 + cap]
            i += 16 + cap


def extract(path):
    """Return [(name, bytes)] of files PC sent with 0x0017/0x0019 to port 9527."""
    streams = {}
    for link, p in pcap_packets(path):
        if link == 1:
            if struct.unpack(">H", p[12:14])[0] != 0x0800:
                continue
            p = p[14:]
        elif link == 113:
            p = p[16:]
        elif link == 0:
            p = p[4:]
        if len(p) < 20 or p[0] >> 4 != 4 or p[9] != 6:
            continue
        ihl = (p[0] & 15) * 4
        p = p[:struct.unpack(">H", p[2:4])[0]]
        sp, dp, seq = struct.unpack_from(">HHI", p, ihl)
        pl = p[ihl + (p[ihl + 12] >> 4) * 4:]
        if dp != PORT or not pl:
            continue
        key = (p[12:16], sp)
        streams.setdefault(key, {}).setdefault(seq, pl)
    out = []
    for segs in streams.values():
        data, nxt = b"", None
        for seq in sorted(segs):
            pl = segs[seq]
            if nxt is not None and seq < nxt:
                pl = pl[nxt - seq:]
            data += pl
            nxt = seq + len(segs[seq]) if nxt is None or seq + len(segs[seq]) > nxt else nxt
        i, cur = 0, None
        while i + 4 <= len(data):
            total, cmd = struct.unpack_from("<HH", data, i)
            if total < 4:
                break
            p = data[i + 4:i + total]
            if cmd == 0x0017:
                cur = [p.split(b"\0")[0].decode("utf-8", "replace"), b""]
                out.append(cur)
            elif cmd == 0x0019 and cur:
                cur[1] += p
            i += total
    return [(n, d) for n, d in out]


# ─────────────────────────────── .boo builder ─────────────────────────────────

def png_size(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


def prepare_image(path, w, h, fit="contain", bg=(0, 0, 0)):
    """Any image (JPG/PNG/BMP/...) -> PNG of exactly w x h, like HDPlayer's ConvertImage.

    fit: stretch = scale to w x h ignoring aspect (HDPlayer KeepRatio=0);
         contain = whole picture visible, bars filled with bg;
         cover   = fill the area, crop the overflow (centred).
    """
    data = open(path, "rb").read()
    if png_size(data) == (w, h):
        return data, "PNG %dx%d, без изменений" % (w, h)
    try:
        from PIL import Image, ImageOps
    except ImportError:
        raise SystemExit("%s: нужна конвертация в PNG %dx%d. Установите Pillow:\n"
                         "    python -m pip install pillow" % (path, w, h))
    import io
    im = Image.open(io.BytesIO(data))
    src = "%s %dx%d" % (im.format, im.width, im.height)
    im = ImageOps.exif_transpose(im).convert("RGBA")   # phone photos: honour EXIF rotation
    resample = getattr(Image, "Resampling", Image).LANCZOS
    if fit == "stretch":
        im = im.resize((w, h), resample)
    elif fit == "cover":
        im = ImageOps.fit(im, (w, h), resample)
    else:
        im = ImageOps.contain(im, (w, h), resample)
        canvas = Image.new("RGBA", (w, h), bg + (255,))
        canvas.paste(im, ((w - im.width) // 2, (h - im.height) // 2), im)
        im = canvas
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue(), "%s -> PNG %dx%d (%s)" % (src, w, h, fit)


IMAGE_EXT = (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff")


def natural_key(path):
    """'2.jpg' before '10.jpg'."""
    import re
    name = os.path.basename(path).lower()
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", name)]


def expand_images(args):
    """Files, folders (their images, natural order, not recursive) and wildcards
    (cmd.exe does not expand *.jpg itself) -> list of image paths."""
    out = []
    for arg in args:
        if os.path.isdir(arg):
            found = sorted((os.path.join(arg, n) for n in os.listdir(arg)
                            if n.lower().endswith(IMAGE_EXT)
                            and os.path.isfile(os.path.join(arg, n))), key=natural_key)
            if not found:
                log("! в папке %s нет изображений (%s)" % (arg, ", ".join(IMAGE_EXT)))
            out += found
        elif any(c in arg for c in "*?["):
            found = sorted((f for f in glob.glob(arg) if os.path.isfile(f)), key=natural_key)
            if not found:
                log("! по шаблону %s ничего не найдено" % arg)
            out += found
        elif os.path.isfile(arg):
            out.append(arg)
        else:
            raise SystemExit("Нет такого файла или папки: %s" % arg)
    if not out:
        raise SystemExit("Не найдено ни одного изображения")
    return out


def parse_size(txt):
    try:
        w, h = (int(x) for x in txt.lower().replace("х", "x").split("x"))
        return w, h
    except ValueError:
        raise SystemExit("--size ожидает ШxВ, например 352x384")


def build_boo(images, dev_id, dev_name, model, width, height, rotation, hold, title):
    """images: [(label, md5)]. width/height = area size after rotation (as HDPlayer writes)."""
    tz = -time.altzone if time.daylight and time.localtime().tm_isdst else -time.timezone
    A = lambda n, v, ind: '%s<Attribute Name="%s">%s</Attribute>' % (ind, n, v)
    L = ['<?xml version="1.0" encoding="UTF-8"?>',
         '<Node Level="1" Type="HD_Controller_Plugin">']
    i1, i2, i3, i4, i5 = (" " * n for n in (4, 8, 12, 16, 20))
    for n, v in [("AppVersion", "7.6.27.0"), ("DeviceModel", model), ("Height", height),
                 ("Rotation", rotation), ("SvnVersion", "10168"), ("TimeZone", tz),
                 ("Width", width), ("ZoomModulus", 0), ("__NAME__", dev_name), ("mimiScreen", 0)]:
        L.append(A(n, v, i1))
    L += [i1 + '<List Name="communication" Index="0">',
          i2 + '<ListItem name="%s" id="%s"/>' % (dev_name, dev_id),
          i1 + '</List>',
          i1 + '<Node Level="2" Type="HD_OrdinaryScene_Plugin">']
    for n, v in [("Alpha", 255), ("BgColor", -16777216), ("BgMode", "BgImage"),
                 ("FixedDuration", 30000), ("FrameEffect", 0), ("FrameSpeed", 4), ("FrameType", 0),
                 ("MotleyIndex", 0), ("PlayIndex", 0), ("PlayMode", "LoopTime"), ("PlayTimes", 1),
                 ("PlayeTime", 30), ("PurityColor", 255), ("PurityIndex", 0),
                 ("SpaceStartTime", "00:00:00"), ("SpaceStopTime", "23:59:59"), ("TricolorIndex", 0),
                 ("UseSpacifiled", 0), ("Volume", 100), ("__GUID__", "{%s}" % uuid.uuid4()),
                 ("__NAME__", title)]:
        L.append(A(n, v, i2))
    L += [i2 + '<List Name="__FileList__" Index="-1"/>',
          i2 + '<Node Level="3" Type="HD_Frame_Plugin">']
    for n, v in [("Alpha", 255), ("ChildType", "HD_CustomArea_Plugin"), ("FrameSpeed", 4),
                 ("FrameType", 0), ("Height", height), ("Index", 8), ("LockArea", 1),
                 ("MotleyIndex", 0), ("PurityColor", 255), ("PurityIndex", 0), ("TricolorIndex", 0),
                 ("Width", width), ("X", 0), ("Y", 0), ("__NAME__", "Area1")]:
        L.append(A(n, v, i3))
    for label, m in images:
        fake = "C:/HDPlayer/outputpath/Image/%s.png" % m
        L.append(i3 + '<Node Level="4" Type="HD_Photo_Plugin">')
        for n, v in [("ClearEffect", 0), ("ClearTime", 4), ("ConvertImage", fake), ("DispEffect", 0),
                     ("DispTime", 4), ("HoldTime", hold), ("KeepRatio", 0), ("__NAME__", label)]:
            L.append(A(n, v, i4))
        L += [i4 + '<List Name="__FileList__" Index="0">',
              i5 + '<ListItem MD5="%s" FileKey="Photo" FileName="%s"/>' % (m, fake),
              i4 + '</List>',
              i3 + '</Node>']
    L += [i2 + '</Node>', i1 + '</Node>', '</Node>', '']
    return "\r\n".join(L).encode("utf-8")


def xml_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


# ─────────────────────────────── UDP info (for slideshow) ─────────────────────

def udp_info(host, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    s.settimeout(0.5)
    s.sendto(bytes([0, 0, 0, 1, 1, 0]), (host, PORT))
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            try:
                d, frm = s.recvfrom(4096)
            except (socket.timeout, ConnectionResetError):
                continue
            if frm[0] != host or len(d) < 21:
                continue
            cmd = struct.unpack_from("<H", d, 4)[0]
            if cmd == 0x0002:
                s.sendto(bytes([3, 0, 0, 1, 3, 0]) + d[6:21], (host, PORT))
            elif cmd == 0x0004 and len(d) >= 78:
                dev_id = d[6:21].split(b"\0")[0].decode()
                w, h = struct.unpack_from("<HH", d, 72)
                name = d[78:78 + d[77]].decode("utf-8", "replace")
                rot = 0
                if b"ScreenR" in d:
                    try:
                        rot = int(d.split(b'ScreenR Value="')[1].split(b'"')[0])
                    except (IndexError, ValueError):
                        pass
                return {"id": dev_id, "model": dev_id.split("-")[0], "w": w, "h": h,
                        "name": name, "rot": rot}
    finally:
        s.close()
    return None


# ─────────────────────────────── CLI ──────────────────────────────────────────

def confirm(a, host, boo_name, boo, files):
    log("План отправки на %s:%d" % (host, PORT))
    for n, d in files.items():
        log("   %-40s %8d байт" % (n, len(d)))
    log("   %-40s %8d байт  (проект)" % (boo_name, len(boo)))
    if not a.yes:
        log("Ничего не отправлено. Добавьте --yes, чтобы выполнить.")
        return False
    return True


def main():
    global VERBOSE
    ap = argparse.ArgumentParser(description="Huidu BoxPlayer project uploader (HDPlayer 7.6 protocol)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("extract")
    e.add_argument("pcap")
    e.add_argument("-o", "--out", default=".")

    r = sub.add_parser("replay")
    r.add_argument("pcap")

    s = sub.add_parser("send")
    s.add_argument("--boo", required=True)
    s.add_argument("files", nargs="*", help="изображения; на плату уйдут как <md5>.<ext>")

    sl = sub.add_parser("slideshow")
    sl.add_argument("images", nargs="+", help="файлы, папки (все картинки в папке по порядку имён) или шаблоны *.jpg")
    sl.add_argument("--hold", type=int, default=50, help="HoldTime, как в HDPlayer (по умолчанию 50)")
    sl.add_argument("--title", default="Project1")
    sl.add_argument("--save-boo", help="сохранить сгенерированный .boo в файл")
    sl.add_argument("--size", help="размер области ШxВ как в HDPlayer (по умолчанию — из платы с учётом поворота)")
    sl.add_argument("--fit", choices=["contain", "cover", "stretch"], default="contain",
                    help="contain: целиком с полями (по умолч.), cover: заполнить с обрезкой, stretch: растянуть")
    sl.add_argument("--bg", default="000000", help="цвет полей для contain, RRGGBB")
    sl.add_argument("--preview", help="сохранить сконвертированные картинки в эту папку")

    for p in (r, s, sl):
        p.add_argument("--host", required=True)
        p.add_argument("--yes", action="store_true", help="реально отправить")
        p.add_argument("--resend", action="store_true", help="слать файлы даже если они уже на плате")
        p.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    VERBOSE = getattr(a, "verbose", False)

    if a.cmd == "extract":
        os.makedirs(a.out, exist_ok=True)
        for n, d in extract(a.pcap):
            ok = "md5 OK" if n.split(".")[0] == md5(d) else "md5 != имя"
            open(os.path.join(a.out, n), "wb").write(d)
            log("%-40s %8d байт  %s" % (n, len(d), ok))
        return 0

    if a.cmd == "replay":
        got = extract(a.pcap)
        boos = [(n, d) for n, d in got if n.endswith(".boo")]
        if not boos:
            raise SystemExit("В дампе нет .boo")
        boo_name, boo = boos[-1]
        files = {n: d for n, d in got if not n.endswith(".boo")}
    elif a.cmd == "send":
        boo = open(a.boo, "rb").read()
        boo_name = md5(boo) + ".boo"
        files = {}
        for f in a.files:
            d = open(f, "rb").read()
            files[md5(d) + os.path.splitext(f)[1].lower()] = d
    else:
        paths = expand_images(a.images)
        log("Изображений: %d" % len(paths))
        info = udp_info(a.host)
        if not info:
            if a.yes or not a.size:
                raise SystemExit("Плата не ответила по UDP — нужны её ID/имя для проекта "
                                 "(для офлайн-предпросмотра укажите --size без --yes)")
            info = {"id": "OFFLINE", "model": "C35", "w": 0, "h": 0, "name": "OFFLINE", "rot": 0}
            log("Плата не ответила — офлайн-режим, только конвертация/предпросмотр")
        else:
            log("Плата %s (%s), экран %dx%d, поворот %d"
                % (info["id"], info["name"], info["w"], info["h"], info["rot"]))
        if a.size:
            w, h = parse_size(a.size)
        else:
            w, h = (info["h"], info["w"]) if info["rot"] % 2 else (info["w"], info["h"])
        log("Размер области проекта: %dx%d" % (w, h))
        bg = tuple(int(a.bg[i:i + 2], 16) for i in (0, 2, 4))
        if a.preview:
            os.makedirs(a.preview, exist_ok=True)
        files, imgs = {}, []
        for f in paths:
            d, how = prepare_image(f, w, h, a.fit, bg)
            m = md5(d)
            dup = "  (такой же файл уже в списке — на плату уйдёт один раз)" if m + ".png" in files else ""
            log("   %-28s %s -> %s.png %d байт%s" % (os.path.basename(f), how, m, len(d), dup))
            files[m + ".png"] = d
            imgs.append((xml_escape(os.path.splitext(os.path.basename(f))[0]), m))
            if a.preview:
                open(os.path.join(a.preview, os.path.splitext(os.path.basename(f))[0] + ".png"), "wb").write(d)
        log("Слайдов: %d, уникальных файлов: %d" % (len(imgs), len(files)))
        boo = build_boo(imgs, info["id"], xml_escape(info["name"]), info["model"], w, h,
                        info["rot"], a.hold, xml_escape(a.title))
        boo_name = md5(boo) + ".boo"
        if a.save_boo:
            open(a.save_boo, "wb").write(boo)
        if info["id"] == "OFFLINE":
            log("Офлайн-режим: отправка невозможна.")
            return 0

    if not confirm(a, a.host, boo_name, boo, files):
        return 0
    try:
        run_session(a.host, boo_name, boo, files, force_all=a.resend)
    except (OSError, ConnectionError) as e:
        log("ОШИБКА: %s" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
