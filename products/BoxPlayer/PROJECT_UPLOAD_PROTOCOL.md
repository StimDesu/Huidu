# Project upload protocol (TCP 9527) — HDPlayer 7.6.27 → HD-C35 fw 7.1.51

Ground truth: capture of stock **HDPlayer 7.6.27.0** sending a 9-image project to an
**HD-C35** (`C35-C19-A0769`, firmware **7.1.51.0**, FPGA 6.3.75.0, 384×320, rotation 3).
Implemented in `tools/hd_send.py`; replaying the capture through it produces the identical
command sequence (only the login UUID/date differ).

Unlike `SDK_BOXSTREAM_PROTOCOL.md` (fw 7.4.x), there is **no SDK XML / BoxStream
(0x0200–0x0205)** and **no UDP registration** in this session. HDPlayer only polls UDP
(`0x0001` → `0x0002`, every 2 s); the TCP connection is opened directly. The whole upload
took < 1 s.

Framing as everywhere: `[u16 LE total_len incl. header][u16 LE cmd][payload]`.
Command names come from the HCatNet.dll string table in `HDPLAYER_DECOMPILATION.md` §4.3 —
the numeric codes observed here line up with that table's order exactly.

## Sequence

| # | PC → device | payload | device → PC | payload | name |
|---|---|---|---|---|---|
| 1 | `0x000b` | u32 `0x01000007` | `0x000c` | u32 `0x01000007` | kVersionAsk |
| 2 | `0x0410` | `admin,<uuid>,<YYYY/MM/DD HH:MM:SS>\0` | `0x0411` | `00 00` | login |
| 3 | `0x000d` | — | `0x000e` | u32 0 | kUpdateProjectAsk (enter project mode) |
| 4 | `0x040a` | — | `0x040b` | `00` | (capability query) |
| 5 | `0x000f` | u64 total project size (953 990) | `0x0010` | u32 **1** | kFreeSpaceSizeAsk (1 = enough) |
| 6 | `0x0011` | — | `0x0012` | `md5\0md5\0…` | kFileListAsk: MD5s of files already on the board |
| 6b | `0x0011` | — | `0x0012` | `00` | …repeat until an empty list |
| 7 | `0x0013` | — | `0x0014` | 9 × `00` | kImcompleteFileAsk (nothing to resume) |
| 8 | `0x0015` | u32 `8` | `0x0016` | u32 0 | kRemoveFileListAsk (meaning of `8` unknown; sent verbatim) |
| 9 | `0x0017` | `<md5>.png\0` | `0x0018` | u32 0 | kOpenFileAsk (name only, no size) |
| 10 | `0x0019` × N | raw bytes, 9212 per chunk | `0x001a` × N | u32 0 | file content; one ack per chunk, HDPlayer runs ~3 chunks ahead |
| 11 | `0x001b` | — | (`0x001a`…) `0x001c` | u32 0 | kCloseFileAsk / answer |
| 12 | 9–11 again for `<md5>.boo` | | | | the project file, always last |
| 13 | `0x001d` | — | `0x001e` | — | kTransEndAsk / kRecvEndAnswer |
| 14 | `0x001f` | — | `0x0020` | `00 00` | kUpdateProjectQuit / kProjectQuitAnswer; then FIN |

Only files whose MD5 is missing from step 6 are sent (here 1 of 9 images). Files are
named `<lowercase md5 of content>.<ext>` on the wire.

After step 14 the board pushes UDP `0x0005` + `0x0340` (status: `ScreenOnOff=0`,
`PlayStatus=3`, `ProgramIndex=-1`) and HDPlayer acks with `0x0006` + `0x0341` carrying the
same 4-byte token; ~2 s later a second pair reports `PlayStatus=1`, `ProgramIndex=0`
(new program playing). So `0x0005` is a state-change notification, not a login token.

## The `.boo` project file

UTF-8 XML with CRLF line endings, a tree of `Node Level=N Type=HD_*_Plugin` elements:

```
HD_Controller_Plugin   AppVersion, DeviceModel=C35, Width=320, Height=384 (already rotated),
                       Rotation=3, TimeZone (seconds), __NAME__, List communication{name,id}
 └ HD_OrdinaryScene_Plugin   one program: PlayMode, PlayTimes, __GUID__, __NAME__, …
    └ HD_Frame_Plugin        an area: X, Y, Width, Height, ChildType=HD_CustomArea_Plugin
       └ HD_Photo_Plugin × N  HoldTime (50), DispEffect/ClearEffect, KeepRatio,
                              List __FileList__ { ListItem MD5=… FileKey=Photo FileName=<PC path> }
```

The board resolves images by `MD5`; `FileName`/`ConvertImage` are HDPlayer's local paths.
HDPlayer pre-renders every photo to the area size (here a 320×384 RGBA PNG) before sending.
