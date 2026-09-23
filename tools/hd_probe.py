#!/usr/bin/env python3
"""
hd_probe.py — minimal READ-ONLY probe for Huidu BoxPlayer controllers (C15/C35/C36/A-series).

Answers one question: "does the reverse-engineered protocol talk to my board at all?"
Standard library only, Python 3.8+, works on Windows/Linux/macOS.

Nothing here changes device state:
  * no TryLock (unless --trylock), no Set*/Add*/Delete*/Reboot, no port 9528 (upgrade service),
  * no file transfer.

Steps
  discover  UDP 9527: send a search trigger, answer the device's 0x0002 announce with
            0x0003 and parse the 0x0004 info reply (ID/model, IP, MAC, firmware, FPGA,
            screen size). Same thing HDPlayer does every time it scans.
  info      TCP 9527 (BoxStream): connect handshake, GetIFVersion, then a list of Get*
            queries, one per request. Prints the answers.

Protocol source: products/BoxPlayer/v7.11.18.0/SDK_BOXSTREAM_PROTOCOL.md and the
captures Huidu.pcapng / More Huidu.pcapng / hdplayer_real.pcapng in this repo.

Examples
  python hd_probe.py discover
  python hd_probe.py discover --host 192.168.1.50
  python hd_probe.py info --host 192.168.1.50 -v
  python hd_probe.py info --host 192.168.1.50 --save c35_dump.txt
"""

import argparse
import datetime
import getpass
import os
import socket
import struct
import sys
import time
import uuid
import xml.etree.ElementTree as ET

UDP_PORT = 9527
TCP_PORT = 9527

VERBOSE = False
LOG = None


def out(msg=""):
    print(msg)
    if LOG:
        LOG.write(msg + "\n")
        LOG.flush()


def dbg(msg):
    if VERBOSE:
        out("   · " + msg)


def hexs(b, limit=64):
    s = b[:limit].hex(" ")
    return s + (" …(+%d)" % (len(b) - limit) if len(b) > limit else "")


def ver4(b):
    """[major, minor, patch_lo, patch_hi] -> "7.4.61.0" as the device reports it."""
    return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])


# ─────────────────────────────── UDP discovery ────────────────────────────────

def parse_info_0004(d):
    """Parse the UDP cmd=0x0004 extended-info packet (layout from hdplayer_real.pcapng)."""
    info = {}
    info["device_id"] = d[6:21].split(b"\0")[0].decode("ascii", "replace")
    info["model_guess"] = info["device_id"].split("-")[0]
    if len(d) >= 76:
        info["ip"] = socket.inet_ntoa(d[22:26])
        info["mac"] = ":".join("%02x" % x for x in d[26:32])
        info["netmask"] = socket.inet_ntoa(d[32:36])
        info["gateway"] = socket.inet_ntoa(d[36:40])
        info["dns"] = socket.inet_ntoa(d[40:44])
        info["fpga_version"] = ver4(d[48:52])
        info["firmware"] = ver4(d[68:72])
        w, h = struct.unpack_from("<HH", d, 72)
        info["screen"] = "%dx%d" % (w, h)
    if len(d) >= 78:
        n = d[77]
        info["player"] = d[78:78 + n].decode("utf-8", "replace")
        p = 78 + n + 1  # skip NUL
        if p < len(d):
            xlen = d[p]
            info["xml"] = d[p + 1:p + 1 + xlen].split(b"\0")[0].decode("utf-8", "replace")
    return info


def discover(host=None, timeout=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("0.0.0.0", 0))  # ephemeral port: device answers to the trigger's source port
    s.settimeout(0.5)

    trigger = bytes([0, 0, 0, 1, 1, 0])        # search, "new" format
    trigger_old = bytes([2, 0, 1, 0])          # search, "old" format
    targets = [(host, UDP_PORT)] if host else [("255.255.255.255", UDP_PORT)]
    for t in targets:
        for pkt in (trigger, trigger_old):
            try:
                s.sendto(pkt, t)
                dbg("UDP -> %s:%d  %s" % (t[0], t[1], hexs(pkt)))
            except OSError as e:
                out("! не удалось отправить на %s: %s" % (t, e))

    found = {}
    acked = set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            d, frm = s.recvfrom(4096)
        except socket.timeout:
            continue
        except ConnectionResetError:  # Windows: ICMP port unreachable
            continue
        if host and frm[0] != host:
            continue
        dbg("UDP <- %s:%d  %s" % (frm[0], frm[1], hexs(d)))
        if len(d) < 21:
            continue
        cmd = struct.unpack_from("<H", d, 4)[0]
        dev_id = d[6:21]
        if cmd == 0x0002 and frm[0] not in acked:
            ack = bytes([3, 0, 0, 1, 3, 0]) + dev_id  # cmd=0x0003, as HDPlayer does
            s.sendto(ack, (frm[0], UDP_PORT))
            dbg("UDP -> %s:%d  %s" % (frm[0], UDP_PORT, hexs(ack)))
            acked.add(frm[0])
            found.setdefault(frm[0], {"device_id": dev_id.split(b"\0")[0].decode("ascii", "replace")})
        elif cmd == 0x0004:
            found[frm[0]] = parse_info_0004(d)
            if host:
                break
    s.close()
    return found


# ─────────────────────────────── TCP BoxStream ────────────────────────────────

class BoxStream:
    def __init__(self, host, port=TCP_PORT, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(timeout)
        self.buf = b""

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, cmd, payload=b""):
        pkt = struct.pack("<HH", 4 + len(payload), cmd) + payload
        dbg("TCP -> cmd=0x%04x len=%d  %s" % (cmd, len(payload), hexs(payload)))
        self.sock.sendall(pkt)

    def recv(self):
        """Return (cmd, payload); answers device heartbeats transparently."""
        while True:
            while len(self.buf) < 4 or len(self.buf) < struct.unpack_from("<H", self.buf, 0)[0]:
                chunk = self.sock.recv(65536)
                if not chunk:
                    raise ConnectionError("устройство закрыло соединение")
                self.buf += chunk
            total, cmd = struct.unpack_from("<HH", self.buf, 0)
            if total < 4:
                raise ConnectionError("битый кадр: длина %d" % total)
            payload, self.buf = self.buf[4:total], self.buf[total:]
            dbg("TCP <- cmd=0x%04x len=%d  %s" % (cmd, len(payload), hexs(payload)))
            if cmd == 0x005F:            # heartbeat ask from device
                self.send(0x0060)
                continue
            if cmd == 0x0060:            # heartbeat answer
                continue
            return cmd, payload

    def expect(self, want, what):
        cmd, payload = self.recv()
        if cmd != want:
            raise ConnectionError("%s: ждали 0x%04x, пришло 0x%04x (%s)" % (what, want, cmd, hexs(payload)))
        return payload

    def handshake(self):
        # ConnReq 0x000b (version 0x01000009) -> ConnAck 0x000c
        self.send(0x000B, struct.pack("<I", 0x01000009))
        ack = self.expect(0x000C, "ConnReq")
        dev_ver = struct.unpack_from("<I", ack)[0] if len(ack) >= 4 else 0
        # ClientInfoReq 0x0410 (CSV, NUL-terminated) -> 0x0411
        now = datetime.datetime.now()
        csv = "Windows,HDPlayer,%s,%s,,,_,%s,Ethernet 00-00-00-00-00-00,%s,%s" % (
            safe_user(), socket.gethostname() or "HDPLAYER",
            now.strftime("%Y-%m-%d_%H:%M:%S"), uuid.uuid4(), now.strftime("%Y/%m/%d %H:%M:%S"))
        self.send(0x0410, csv.encode("utf-8") + b"\0")
        self.expect(0x0411, "ClientInfoReq")
        # 0x0300 -> 0x0301
        self.send(0x0300)
        cmd, _ = self.recv()
        if cmd != 0x0301:
            out("! после 0x0300 пришло 0x%04x (ожидали 0x0301) — продолжаю" % cmd)
        return dev_ver

    def xml_request(self, xml):
        """One SDK XML exchange, exactly as in Huidu.pcapng (6 frames each direction)."""
        self.send(0x0200, b"\0\0\0\0")
        self.expect(0x0201, "BoxStreamInit")
        self.send(0x0202, b"\0\0" + xml.encode("utf-8"))
        self.expect(0x0203, "StreamData ack")
        self.send(0x0204, b"\0\0")
        self.expect(0x0205, "0x0204 ack")
        # device -> PC
        self.expect(0x0200, "ответ: BoxStreamInit")
        self.send(0x0201, b"\0\0")
        data = self.expect(0x0202, "ответ: StreamData")
        self.send(0x0203, b"\0\0")
        self.expect(0x0204, "ответ: 0x0204")
        self.send(0x0205, b"\0\0")
        return data[2:].decode("utf-8", "replace")


def safe_user():
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME", "user")


def sdk(method, body=""):
    return ('<?xml version="1.0" encoding="utf-8"?>\n<sdk guid="##GUID">\n'
            '    <in method="%s">%s</in>\n</sdk>\n' % (method, body))


READ_ONLY_METHODS = [
    "GetDeviceName", "GetFirewareVersion", "GetScreenInfo", "GetDeviceInfo",
    "GetHardwareInfo", "GetEth0Info", "GetWifiInfo", "GetTimeInfo",
    "GetCurrentLuminance", "GetLuminancePloy", "GetSwitchTime", "GetPlayStatus",
    "GetSystemVolume", "GetScreenRotation", "GetCurrentPlayProgramGUID",
    "GetCurrentTemperature", "GetSensorInfo", "GetLicense",
]


def summarize(xml_text):
    """Print <out> results as `method [result]` + child attributes."""
    try:
        root = ET.fromstring(xml_text.encode("utf-8"))
    except ET.ParseError:
        out(xml_text)
        return
    for o in root.iter("out"):
        out("  %s [%s]" % (o.get("method"), o.get("result")))
        for el in o.iter():
            if el is o:
                continue
            attrs = " ".join('%s="%s"' % kv for kv in el.attrib.items())
            text = (el.text or "").strip()
            if attrs or text:
                out("      %s %s %s" % (el.tag, attrs, text))


def info(host, port, methods, trylock, raw):
    out("== TCP %s:%d ==" % (host, port))
    bs = BoxStream(host, port)
    try:
        dev_ver = bs.handshake()
        out("Рукопожатие OK, версия протокола устройства: 0x%08x" % dev_ver)
        r = bs.xml_request(sdk("GetIFVersion", '<version value="1000000"/>'))
        summarize(r)
        if trylock:
            summarize(bs.xml_request(sdk("TryLock")))
        for m in methods:
            try:
                r = bs.xml_request(sdk(m))
            except (ConnectionError, socket.timeout) as e:
                out("  %s: ОШИБКА %s" % (m, e))
                break
            if raw:
                out(r)
            else:
                summarize(r)
        if trylock:
            try:
                bs.xml_request(sdk("Unlock"))
            except Exception:
                pass
    finally:
        bs.close()


def main():
    global VERBOSE, LOG
    ap = argparse.ArgumentParser(description="Read-only probe for Huidu BoxPlayer boards")
    ap.add_argument("step", choices=["discover", "info", "all"], nargs="?", default="all")
    ap.add_argument("--host", help="IP платы (без него — широковещательный поиск)")
    ap.add_argument("--port", type=int, default=TCP_PORT)
    ap.add_argument("--timeout", type=float, default=4.0, help="время ожидания UDP-ответов, c")
    ap.add_argument("--methods", help="список Get*-методов через запятую вместо стандартного")
    ap.add_argument("--trylock", action="store_true",
                    help="захватить блокировку, как HDPlayer (НЕ нужно для чтения)")
    ap.add_argument("--raw", action="store_true", help="печатать ответы XML целиком")
    ap.add_argument("-v", "--verbose", action="store_true", help="hex-дамп всех пакетов")
    ap.add_argument("--save", help="дублировать вывод в файл")
    a = ap.parse_args()
    VERBOSE = a.verbose
    if a.save:
        LOG = open(a.save, "w", encoding="utf-8")

    host = a.host
    if a.step in ("discover", "all"):
        out("== UDP-поиск (%s) ==" % (host or "broadcast"))
        devs = discover(host, a.timeout)
        if not devs:
            out("Нет ответа по UDP 9527. Проверьте подсеть/фаервол (разрешите входящий UDP для python).")
        for ip, d in devs.items():
            out("Устройство %s" % ip)
            for k, v in d.items():
                out("  %-13s %s" % (k, v))
        if not host and len(devs) == 1:
            host = next(iter(devs))
    if a.step in ("info", "all"):
        if not host:
            out("Для шага info нужен --host (или ровно одно найденное устройство).")
            return 2
        methods = a.methods.split(",") if a.methods else READ_ONLY_METHODS
        try:
            info(host, a.port, methods, a.trylock, a.raw)
        except (OSError, ConnectionError) as e:
            out("TCP: %s" % e)
            out("Запустите с -v и пришлите вывод — по нему видно, на каком шаге отказ.")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
