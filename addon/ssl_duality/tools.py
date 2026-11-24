"""SSL Duality Control: talks to an SSL Duality console over its Remote protocol (UDP 50081).

Every packet is a 16-byte header (4 x int32 big-endian: cmdCode, destCode, deskSerial, remoteSerial) and a
payload of bytes, shorts, ints and NUL-terminated ASCII strings. The console answers on UDP 50081 with
destCode 2; answers to this add-on carry its remoteSerial, unsolicited pushes carry 0.
On the Duality, Total Recall commands are fire-and-forget: the console sends no acknowledgement.
"""
from __future__ import annotations

import socket
import struct
import time

from .toolkit import ToolError, VALUES, prop, setting, tool

MODULE = "duality"
PORT = 50081
TO_DESK = 1
HDR = 16
NUM_CHANS = 96

setting("consoleIp", "text", "Console IP address", "192.168.4.181",
        "The Duality's IP on the studio network (SSL > Misc > Net on the console).")
setting("deskSerial", "number", "Console serial", 150, "The console's serial number (find_console answers it).",
        minimum=0, maximum=2147483647)
setting("remoteSerial", "number", "Remote serial", 12345, "The id this add-on uses on the wire.",
        minimum=1, maximum=2147483647)
setting("localPort", "number", "Local UDP port", 50081,
        "The port answers are received on. The console answers on 50081; DualityRemote must be closed to use it.",
        minimum=0, maximum=65535)


# ---- wire helpers ----------------------------------------------------------------------------------------------------
def _cs(text) -> bytes:
    s = str(text)
    try:
        return s.encode("ascii") + b"\x00"
    except UnicodeEncodeError:
        raise ToolError("%r has characters outside ASCII; the console only takes plain ASCII (no accents)" % s,
                        "not_ascii")


class Cur:
    def __init__(self, buf: bytes, i: int = HDR):
        self.b, self.i = buf, i

    def left(self):
        return len(self.b) - self.i

    def u8(self):
        v = self.b[self.i]
        self.i += 1
        return v

    def i16(self):
        v = struct.unpack_from(">h", self.b, self.i)[0]
        self.i += 2
        return v

    def i32(self):
        v = struct.unpack_from(">i", self.b, self.i)[0]
        self.i += 4
        return v

    def cs(self):
        j = self.b.index(0, self.i)
        s = self.b[self.i:j].decode("ascii", "replace")
        self.i = j + 1
        return s


def _ip() -> str:
    ip = str(VALUES.get("consoleIp") or "").strip()
    if not ip:
        raise ToolError("set the console's IP address in the add-on's settings", "no_ip")
    return ip


def _desk() -> int:
    return int(VALUES.get("deskSerial") or 0)


def _rser() -> int:
    return int(VALUES.get("remoteSerial") or 12345)


def _net_error(e: BaseException, what: str) -> ToolError:
    errno = getattr(e, "errno", None)
    if errno in (1, 13):
        return ToolError("%s was refused on this Mac (%s): the add-on needs network access to the local network, "
                         "which AiAudioHub does not grant add-ons yet" % (what, e), "no_network")
    if errno in (48,):
        return ToolError("%s: UDP port %s is in use - close DualityRemote (it holds 50081), or set the add-on's "
                         "Local UDP port to 0" % (what, VALUES.get("localPort")), "port_busy")
    if errno in (51, 64, 65):
        return ToolError("%s: the console at %s cannot be reached (%s) - is it on, and on the same network as this "
                         "Mac?" % (what, VALUES.get("consoleIp"), e), "unreachable")
    return ToolError("%s failed (%s)" % (what, e), "network")


class Link:
    """One UDP socket for one conversation with the console."""

    def __init__(self, broadcast: bool = False):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if broadcast:
                self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            port = int(VALUES.get("localPort") or 0)
            if port:
                self.s.bind(("0.0.0.0", port))
        except OSError as e:
            self.s.close()
            raise _net_error(e, "opening the UDP port")
        self.s.settimeout(0.3)

    def close(self):
        self.s.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def send(self, op: int, payload: bytes = b"", target: str = "", desk: int = -1):
        pkt = struct.pack(">4i", op, TO_DESK, _desk() if desk < 0 else desk, _rser()) + payload
        try:
            self.s.sendto(pkt, (target or _ip(), PORT))
        except OSError as e:
            raise _net_error(e, "sending to the console")

    def collect(self, wanted, wait: float, done=None, idle: float = 0.0):
        """Packets whose opcode is in `wanted` until `wait` seconds pass, done(packets) is true, or (with `idle`)
        no wanted packet came for `idle` seconds after the first one."""
        got = []
        end = time.time() + wait
        last = 0.0
        while time.time() < end:
            if idle and got and time.time() - last > idle:
                break
            try:
                data, addr = self.s.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError as e:
                raise _net_error(e, "receiving from the console")
            if len(data) < HDR:
                continue
            cmd = struct.unpack_from(">i", data, 0)[0]
            if cmd in wanted:
                got.append((cmd, data, addr))
                last = time.time()
                if done and done(got):
                    break
        return got


# ---- list parsing (lists come in several datagrams, ended by a 0 sequence number) ------------------------------------
def _dir_records(data: bytes):
    c = Cur(data)
    path = c.cs()
    recs, ended = [], False
    while c.left() >= 2:
        seq = c.i16()
        if seq == 0:
            ended = True
            break
        recs.append((seq, {"folder": c.cs(), "info": c.cs(), "isDir": bool(c.u8()), "time": c.cs(),
                           "date": c.cs(), "bytes": c.i32()}))
    return path, recs, ended


def _list_dir(path: str, wait: float = 4.0) -> list:
    with Link() as ln:
        ln.send(60, bytes([1]) + _cs(path))
        entries, state = {}, {"ended": False}

        def done(got):
            cmd, data, _ = got[-1]
            p, recs, ended = _dir_records(data)
            if p == path:
                for seq, r in recs:
                    entries[seq] = r
                state["ended"] = state["ended"] or ended
            return False

        ln.collect({61}, wait, done, idle=1.0)
    if not entries and not state["ended"]:
        raise ToolError("the console did not answer the listing of %s" % path, "no_answer")
    rows = []
    for seq in sorted(entries):
        r = entries[seq]
        r["name"] = r["info"].split("\n")[0].strip() or r["folder"]
        rows.append(r)
    missing = [k for k in range(1, max(entries) + 1) if k not in entries] if entries else []
    return rows, missing


def _current():
    with Link() as ln:
        ln.send(10)
        got = ln.collect({11}, 3.0, lambda g: True)
    if not got:
        raise ToolError("the console did not say which title is open", "no_answer")
    c = Cur(got[0][1])
    pdir, pinfo, tdir, tinfo = c.cs(), c.cs(), c.cs(), c.cs()
    p, t = pinfo.split("\n"), tinfo.split("\n")
    return {"projectFolder": pdir, "project": p[0].strip(),
            "artist": p[3] if len(p) > 3 else "", "client": p[4] if len(p) > 4 else "",
            "titleFolder": tdir, "title": t[0].strip(),
            "producer": t[3] if len(t) > 3 else "", "engineer": t[4] if len(t) > 4 else "",
            "assistant": t[5] if len(t) > 5 else ""}


def _snapshots(wait: float = 3.0):
    with Link() as ln:
        ln.send(64)
        rows, state = {}, {"ended": False}

        def done(got):
            c = Cur(got[-1][1])
            c.cs()
            while c.left() >= 2:
                idx = c.i16()
                if idx == 0:
                    state["ended"] = True
                    break
                raw = c.cs()
                info = c.cs()
                c.u8()
                rows[idx] = {"number": idx, "name": raw[:-4] if len(raw) > 4 else raw, "info": info,
                             "time": c.cs(), "date": c.cs()}
                rows[idx]["bytes"] = c.i32()
            return state["ended"]

        ln.collect({65}, wait, done)
    return [rows[k] for k in sorted(rows)]


def _tr_dir() -> str:
    with Link() as ln:
        ln.send(64)
        got = ln.collect({65}, 3.0, lambda g: True)
    if not got:
        raise ToolError("the console did not answer the Total Recall list", "no_answer")
    return Cur(got[0][1]).cs()


def _read_file(path: str, limit: int = 1 << 20, size: int = 0) -> bytes:
    """Reads a file off the console in 1024-byte blocks (110 -> 111; a block of length 0 ends it)."""
    out = bytearray()
    with Link() as ln:
        while len(out) < limit:
            off = len(out)
            chunk = None
            for _ in range(4):
                ln.send(110, _cs(path) + struct.pack(">iii", off, 1024, 0))
                def mine(g, off=off):
                    c = Cur(g[-1][1])
                    c.cs()
                    return c.i32() == off

                got = ln.collect({111}, 1.5, mine)
                got = [g for g in got if mine([g])]
                if got:
                    c = Cur(got[0][1])
                    c.cs()
                    c.i32()
                    n = c.i32()
                    chunk = got[0][1][c.i:c.i + max(n, 0)]
                    break
                time.sleep(0.05)
            if chunk is None:
                raise ToolError("the console stopped answering at byte %d of %s" % (off, path), "no_answer")
            if not chunk:
                break
            out += chunk
            if size and len(out) >= size:
                break
            time.sleep(0.05)
    if size and len(out) != size:
        raise ToolError("read %d bytes of %s but it holds %d - ask again" % (len(out), path, size), "short_read")
    return bytes(out)


# ---- tools: read -----------------------------------------------------------------------------------------------------
@tool("find_console", "Asks the console who it is (GET_DESK) at its IP, or by broadcast on the local network, and "
      "answers its product, firmware version, build and serial.",
      props={"broadcast": prop("boolean", "Ask everything on the local network instead of the set IP.")},
      module=MODULE, timeout_ms=15000)
def find_console(a: dict) -> dict:
    bc = bool(a.get("broadcast"))
    with Link(broadcast=bc) as ln:
        ln.send(5, b"", target="255.255.255.255" if bc else "", desk=0)
        got = ln.collect({6}, 3.0, None if bc else (lambda g: True))
    out, seen = [], set()
    for _, data, addr in got:
        if addr[0] in seen:
            continue
        seen.add(addr[0])
        c = Cur(data)
        name = c.cs()
        ver, sub, issue = c.i32(), c.i32(), c.i32()
        label = c.cs() if c.left() else ""
        build = c.cs() if c.left() else ""
        out.append({"ip": addr[0], "product": name, "version": label or "%d.%d/%d" % (ver, sub, issue),
                    "build": build, "deskSerial": struct.unpack_from(">i", data, 8)[0]})
    return {"consoles": out, "found": len(out)}


@tool("current_title", "The project and title open on the console now, with their folders and credits.",
      module=MODULE, timeout_ms=10000)
def current_title(a: dict) -> dict:
    return _current()


@tool("list_projects", "The console's projects: folder number and name, as its /projects listing gives them.",
      module=MODULE, timeout_ms=15000)
def list_projects(a: dict) -> dict:
    rows, missing = _list_dir("/projects")
    out = {"projects": [{"folder": r["folder"], "name": r["name"]} for r in rows if r["isDir"]]}
    if missing:
        out["warning"] = "some datagrams were lost (entries %s): ask again for the full list" % missing
    return out


@tool("list_titles", "The titles of one project on the console: folder number and name.",
      props={"project": prop("string", "The project's folder number, as list_projects answers it.")},
      required=("project",), module=MODULE, timeout_ms=15000)
def list_titles(a: dict) -> dict:
    p = str(a["project"]).strip().strip("/")
    rows, missing = _list_dir("/projects/" + p)
    out = {"project": p, "titles": [{"folder": r["folder"], "name": r["name"]} for r in rows if r["isDir"]]}
    if missing:
        out["warning"] = "some datagrams were lost (entries %s): ask again" % missing
    return out


@tool("list_snapshots", "The Total Recall snapshots of the open title, numbered from 1 as recall_snapshot takes them.",
      module=MODULE, timeout_ms=10000)
def list_snapshots(a: dict) -> dict:
    rows = _snapshots()
    return {"snapshots": rows, "count": len(rows)}


@tool("list_mixes", "The automation mix passes of the open title: number, name, which mix each was based on.",
      module=MODULE, timeout_ms=10000)
def list_mixes(a: dict) -> dict:
    with Link() as ln:
        ln.send(62)
        rows, state = {}, {"ended": False}

        def done(got):
            c = Cur(got[-1][1])
            c.cs()
            while c.left() >= 2:
                seq = c.i16()
                if seq == 0:
                    state["ended"] = True
                    break
                rows[seq] = {"name": c.cs(), "mix": c.i32(), "basedOn": c.i32(), "time": c.cs(), "date": c.cs()}
                c.i32()
            return state["ended"]

        ln.collect({63}, 3.0, done)
    return {"mixes": [rows[k] for k in sorted(rows)], "count": len(rows)}


@tool("channel_names", "The scribble-strip names (and Eyeconix pictures) of a range of channels, 1-96.",
      props={"first": prop("integer", "First channel (default 1).", minimum=1, maximum=NUM_CHANS),
             "last": prop("integer", "Last channel (default 96).", minimum=1, maximum=NUM_CHANS)},
      module=MODULE, timeout_ms=20000)
def channel_names(a: dict) -> dict:
    first, last = int(a.get("first", 1)), int(a.get("last", NUM_CHANS))
    if last < first:
        raise ToolError("`last` must not be below `first`", field="last")
    names = {}
    with Link() as ln:
        lo = first
        while lo <= last:
            hi = min(lo + 23, last)
            ln.send(20, bytes([lo, hi]))
            for _, data, _ in ln.collect({21}, 2.0, lambda g: True):
                c = Cur(data)
                while c.left() >= 1:
                    ch = c.u8()
                    if ch == 0:
                        break
                    names[ch] = {"channel": ch, "name": c.cs(), "picture": c.cs()}
            lo = hi + 1
    if not names:
        raise ToolError("the console did not answer the channel names", "no_answer")
    return {"channels": [names[k] for k in sorted(names)]}


@tool("channel_stereo", "Whether each channel of a range is stereo (GET_IS_CHAN_STEREO).",
      props={"first": prop("integer", "First channel (default 1).", minimum=1, maximum=NUM_CHANS),
             "last": prop("integer", "Last channel (default 24).", minimum=1, maximum=NUM_CHANS)},
      module=MODULE, timeout_ms=60000)
def channel_stereo(a: dict) -> dict:
    first, last = int(a.get("first", 1)), int(a.get("last", 24))
    out = []
    with Link() as ln:
        for ch in range(first, last + 1):
            ln.send(34, bytes([ch]))
            got = ln.collect({35}, 1.0, lambda g: True)
            if got:
                raw = got[0][1][HDR:]
                out.append({"channel": ch, "raw": raw.hex(), "stereo": bool(raw and raw[-1])})
            else:
                out.append({"channel": ch, "raw": None, "stereo": None})
    return {"channels": out}


@tool("read_snapshot", "Reads one Total Recall snapshot file (.trs) of the open title off the console, read only: "
      "its size and bytes as hex, for decoding the per-channel data.",
      props={"number": prop("integer", "The snapshot's number (list_snapshots).", minimum=1, maximum=10000),
             "offset": prop("integer", "Return the hex from this byte (default 0).", minimum=0),
             "length": prop("integer", "How many bytes of hex to return (default 4096, at most 32768).",
                            minimum=1, maximum=32768)},
      required=("number",), module=MODULE, timeout_ms=120000)
def read_snapshot(a: dict) -> dict:
    n = int(a["number"])
    snaps = _snapshots()
    hit = next((s for s in snaps if s["number"] == n), None)
    if not hit:
        raise ToolError("the open title has %d snapshots" % len(snaps), field="number")
    d = _tr_dir().rstrip("/")
    path = "%s/%s.trs" % (d, hit["name"])
    data = _read_file(path)
    off, ln = int(a.get("offset", 0)), int(a.get("length", 4096))
    part = data[off:off + ln]
    rows = ["%06x  %s" % (off + i, part[i:i + 32].hex()) for i in range(0, len(part), 32)]
    return {"path": path, "snapshot": hit, "size": len(data), "offset": off, "hex": rows}


TR_MARK = bytes.fromhex("01000001000000004908")


def _tr_records(data: bytes):
    """Splits a .trs into its repeating channel records (each starts with TR_MARK) and reads every aligned int32."""
    marks, i = [], data.find(TR_MARK)
    while i >= 0:
        marks.append(i)
        i = data.find(TR_MARK, i + 1)
    # Mapped live (2026-10-31): channel N's record starts at 50 + (N-1) * 204; ch 1 HF Gain is at byte 98 of it.
    stride, first = 204, 50
    marks = [first + k * stride for k in range(NUM_CHANS) if first + (k + 1) * stride <= len(data)]
    recs = []
    for k, m in enumerate(marks):
        end = m + stride
        vals = {}
        p = m + (-m % 4)
        while p + 4 <= end:
            vals[p - m] = struct.unpack_from(">i", data, p)[0]
            p += 4
        recs.append({"start": m, "length": end - m, "values": vals})
    return marks, recs


def _snapshot_bytes(n: int):
    snaps = _snapshots()
    hit = next((s for s in snaps if s["number"] == n), None)
    if not hit:
        raise ToolError("the open title has %d snapshots" % len(snaps), field="number")
    d = _tr_dir().rstrip("/")
    rows, _ = _list_dir(d)
    ent = next((r for r in rows if r["folder"] in (hit["name"] + ".trs", hit["name"])), None)
    size = int(ent["bytes"]) if ent else int(hit.get("bytes") or 0)
    return hit, _read_file("%s/%s.trs" % (d, hit["name"]), size=size)


# Byte offset in a channel record -> control, mapped live on the console (2026-10-31), one knob at a time.
TR_MAP = {
    22: "Pan", 38: "Aux 4", 42: "Aux 3", 46: "Aux 2", 50: "Aux 1", 54: "Cue Level", 58: "Cue Pan",
    62: "LF Gain", 66: "LF Freq", 70: "LMF Q", 74: "LMF Freq", 78: "LMF Gain", 82: "HMF Q", 86: "HMF Freq",
    90: "HMF Gain", 94: "HF Freq", 98: "HF Gain", 102: "HPF", 106: "LPF", 114: "Gate Threshold",
    118: "Gate Range", 122: "Comp Threshold", 126: "Comp Release", 130: "Comp Ratio", 134: "Line Trim",
    142: "Mic Gain",
}
POT_FULL = 3908  # a pot turned fully clockwise reads about 3904-3908


# APPROXIMATE scales (classic SSL E/G channel ranges, not yet calibrated on this console): name -> (kind, lo, hi).
TR_SCALE = {
    "HF Gain": ("db", -15, 15), "HMF Gain": ("db", -15, 15), "LMF Gain": ("db", -15, 15), "LF Gain": ("db", -15, 15),
    "HF Freq": ("hz", 1500, 16000), "HMF Freq": ("hz", 600, 7000), "LMF Freq": ("hz", 200, 2500),
    "LF Freq": ("hz", 30, 450), "HMF Q": ("q", 0.5, 2.5), "LMF Q": ("q", 0.5, 2.5),
    "HPF": ("hpf", 20, 350), "LPF": ("lpf", 22000, 3000), "Comp Ratio": ("ratio", 1, 20),
    "Comp Threshold": ("db", 10, -20), "Comp Release": ("s", 0.1, 4.0), "Gate Threshold": ("db", -30, 10),
    "Gate Range": ("db", 0, 40), "Line Trim": ("db", -20, 20), "Aux 1": ("send", 0, 0), "Aux 2": ("send", 0, 0),
    "Aux 3": ("send", 0, 0), "Aux 4": ("send", 0, 0), "Cue Level": ("send", 0, 0), "Pan": ("pan", 0, 0),
    "Cue Pan": ("pan", 0, 0),
}


def _approx(name: str, raw: int):
    import math
    s = TR_SCALE.get(name)
    p = max(0.0, min(1.0, raw / float(POT_FULL)))
    if not s:
        return "%d%%" % round(p * 100)
    kind, lo, hi = s
    if (kind == "db" and lo == -hi) or kind == "pan":
        # centre-detent pots rest at about 1864, not half of full scale
        c = 1864.0
        p = 0.5 + 0.5 * ((raw - c) / c if raw < c else (raw - c) / (POT_FULL - c))
        p = max(0.0, min(1.0, p))
    if kind == "db":
        return "%+.1f dB" % (lo + (hi - lo) * p)
    if kind in ("hz", "hpf", "lpf"):
        if kind == "hpf" and p < 0.02:
            return "off"
        if kind == "lpf" and p < 0.02:
            return "off"
        f = lo * (hi / float(lo)) ** p
        return "%.1f kHz" % (f / 1000) if f >= 1000 else "%d Hz" % round(f)
    if kind == "q":
        return "Q %.1f" % (lo * (hi / lo) ** p)
    if kind == "ratio":
        return "inf:1" if p > 0.97 else "%.1f:1" % (1 + 19 * p * p)
    if kind == "s":
        return "%.2f s" % (lo * (hi / lo) ** p)
    if kind == "send":
        return "-inf" if p < 0.02 else "%+.1f dB" % (10 + 60 * math.log10(p))
    if kind == "pan":
        v = round((p - 0.5) * 200)
        return "C" if abs(v) < 3 else ("L%d" % -v if v < 0 else "R%d" % v)
    return "%d%%" % round(p * 100)


@tool("channel_settings", "Reads each channel's Total Recall pots from a snapshot of the open title: EQ, filters, "
      "dynamics, sends, cue, pan, gain - by name, raw (0-4095) and as % of the knob's travel. Read only.",
      props={"number": prop("integer", "The snapshot's number (list_snapshots; default the newest).", minimum=1,
                            maximum=10000),
             "first": prop("integer", "First channel (default 1).", minimum=1, maximum=NUM_CHANS),
             "last": prop("integer", "Last channel (default 24).", minimum=1, maximum=NUM_CHANS)},
      module=MODULE, timeout_ms=120000)
def channel_settings(a: dict) -> dict:
    n = a.get("number")
    if not n:
        snaps = _snapshots()
        if not snaps:
            raise ToolError("the open title has no snapshots", "no_snapshots")
        n = snaps[-1]["number"]
    hit, data = _snapshot_bytes(int(n))
    _, recs = _tr_records(data)
    first, last = int(a.get("first", 1)), int(a.get("last", 24))
    try:
        names = {c["channel"]: c["name"] for c in channel_names({"first": first, "last": last})["channels"]}
    except ToolError:
        names = {}
    out = []
    for ch in range(first, min(last, len(recs)) + 1):
        v = recs[ch - 1]["values"]
        pots = {name: {"raw": v.get(o, 0), "pct": round(100.0 * min(v.get(o, 0), POT_FULL) / POT_FULL),
                       "approx": _approx(name, v.get(o, 0))}
                for o, name in sorted(TR_MAP.items(), key=lambda kv: kv[1])}
        unmapped = {str(o): x for o, x in v.items() if x and o not in TR_MAP and o > 10}
        out.append({"channel": ch, "name": names.get(ch, ""), "pots": pots, "unmapped": unmapped})
    return {"snapshot": hit, "channels": out,
            "note": "pct is the knob's travel (0 fully anticlockwise, 100 fully clockwise). `approx` uses the classic SSL "
                    "E/G ranges, NOT calibrated on this console yet: a guide, not a recall value. Switches not decoded."}


@tool("decode_snapshot", "Splits a Total Recall snapshot of the open title into its channel records and lists each "
      "record's non-zero values (byte offset in the record -> value; the pots read 0-4095). Read only.",
      props={"number": prop("integer", "The snapshot's number (list_snapshots).", minimum=1, maximum=10000),
             "first": prop("integer", "First record (default 1).", minimum=1),
             "last": prop("integer", "Last record (default first + 3).", minimum=1)},
      required=("number",), module=MODULE, timeout_ms=120000)
def decode_snapshot(a: dict) -> dict:
    hit, data = _snapshot_bytes(int(a["number"]))
    marks, recs = _tr_records(data)
    first = int(a.get("first", 1))
    last = int(a.get("last", first + 3))
    out = []
    for k in range(first - 1, min(last, len(recs))):
        r = recs[k]
        out.append({"record": k + 1, "start": r["start"], "length": r["length"],
                    "values": {str(o): v for o, v in r["values"].items() if v}})
    tail = len(data) - (marks[-1] + recs[-1]["length"]) if marks else len(data)
    return {"snapshot": hit, "size": len(data), "records": len(recs), "firstAt": marks[0] if marks else None,
            "stride": sorted({marks[i + 1] - marks[i] for i in range(len(marks) - 1)}), "bytesAfter": tail,
            "channels": out}


@tool("compare_snapshots", "Compares two Total Recall snapshots of the open title, channel record by record: every "
      "value that differs (record, byte offset, value in A and in B). Read only.",
      props={"a": prop("integer", "First snapshot's number.", minimum=1, maximum=10000),
             "b": prop("integer", "Second snapshot's number.", minimum=1, maximum=10000),
             "max": prop("integer", "At most this many differences (default 300).", minimum=1, maximum=3000),
             "jitter": prop("integer", "Ignore pot moves this small (default 64 of 4095).", minimum=0, maximum=4095)},
      required=("a", "b"), module=MODULE, timeout_ms=180000)
def compare_snapshots(a: dict) -> dict:
    ha, da = _snapshot_bytes(int(a["a"]))
    hb, db = _snapshot_bytes(int(a["b"]))
    _, ra = _tr_records(da)
    _, rb = _tr_records(db)
    diffs, cap = [], int(a.get("max", 300))
    jitter = int(a.get("jitter", 64))
    for k in range(min(len(ra), len(rb))):
        va, vb = ra[k]["values"], rb[k]["values"]
        for o in sorted(set(va) | set(vb)):
            x, y = va.get(o) or 0, vb.get(o) or 0
            if x != y and (abs(x - y) > jitter or max(x, y) > 4095):
                diffs.append({"record": k + 1, "offset": o, "a": va.get(o), "b": vb.get(o)})
    head_a = da[:ra[0]["start"]] if ra else da
    head_b = db[:rb[0]["start"]] if rb else db
    headerDiff = [i for i in range(min(len(head_a), len(head_b))) if head_a[i] != head_b[i]]
    perRecord = {}
    for d in diffs:
        perRecord[d["record"]] = perRecord.get(d["record"], 0) + 1
    return {"a": ha, "b": hb, "sizes": [len(da), len(db)], "records": [len(ra), len(rb)],
            "differences": len(diffs), "perRecord": perRecord, "headerBytesDiffer": headerDiff[:50],
            "list": diffs[:cap]}


# ---- tools: write ----------------------------------------------------------------------------------------------------
@tool("select_title", "Opens another project/title on the console (what the console loads changes), then reads back "
      "which title is open.",
      props={"project": prop("string", "The project's folder number (list_projects)."),
             "title": prop("string", "The title's folder number (list_titles).")},
      required=("project", "title"), writes=True, module=MODULE, timeout_ms=20000)
def select_title(a: dict) -> dict:
    p, t = str(a["project"]).strip(), str(a["title"]).strip()
    before = _current()
    with Link() as ln:
        ln.send(220, _cs(p) + _cs(t))
        ack = bool(ln.collect({221}, 4.0, lambda g: True))
    time.sleep(1.0)
    after = _current()
    return {"before": before, "after": after, "acknowledged": ack,
            "changed": after["projectFolder"] == p and after["titleFolder"] == t}


@tool("take_snapshot", "Stores a new Total Recall snapshot of the console in the open title (like STORE on the "
      "desk), then lists the snapshots.", writes=True, module=MODULE, timeout_ms=20000)
def take_snapshot(a: dict) -> dict:
    before = _snapshots()
    with Link() as ln:
        ln.send(310)
    time.sleep(1.5)
    after = _snapshots()
    return {"before": len(before), "after": len(after), "new": after[len(before):] if len(after) > len(before) else [],
            "note": "" if len(after) > len(before) else "no new snapshot appeared yet: check the console"}


@tool("recall_snapshot", "Selects a Total Recall snapshot of the open title on the console, by its number in "
      "list_snapshots. The Duality sends no confirmation: check the desk.",
      props={"number": prop("integer", "The snapshot's number, from 1.", minimum=1, maximum=10000)},
      required=("number",), writes=True, module=MODULE, timeout_ms=10000)
def recall_snapshot(a: dict) -> dict:
    n = int(a["number"])
    snaps = _snapshots()
    if snaps and n > len(snaps):
        raise ToolError("the open title has %d snapshots" % len(snaps), field="number",
                        candidates=[s["number"] for s in snaps])
    with Link() as ln:
        ln.send(320, struct.pack(">i", n - 1))
    hit = next((s for s in snaps if s["number"] == n), None)
    return {"sent": True, "snapshot": hit, "note": "the Duality does not confirm a recall: look at the desk"}


@tool("set_channel_name", "Writes one channel's scribble-strip name on the console (6 characters show), then reads "
      "it back.",
      props={"channel": prop("integer", "Channel 1-96.", minimum=1, maximum=NUM_CHANS),
             "name": prop("string", "The name, plain ASCII.", minLength=1, maxLength=16)},
      required=("channel", "name"), writes=True, module=MODULE, timeout_ms=10000)
def set_channel_name(a: dict) -> dict:
    ch, name = int(a["channel"]), str(a["name"])
    with Link() as ln:
        ln.send(30, bytes([ch]) + _cs(name) + b"\x00")
        ack = bool(ln.collect({32}, 2.0, lambda g: True))
    back = channel_names({"first": ch, "last": ch})["channels"]
    now = back[0]["name"] if back else None
    return {"channel": ch, "asked": name, "now": now, "acknowledged": ack, "ok": now is not None and now.strip() ==
            name.strip()[:len(now.strip())]}


@tool("set_channel_names", "Writes several channels' scribble-strip names on the console in one go (6 characters "
      "show), then reads them back.",
      props={"names": prop("array", "[{channel: 1-96, name: plain ASCII}], at most 96.")},
      required=("names",), writes=True, module=MODULE, timeout_ms=60000)
def set_channel_names(a: dict) -> dict:
    items = a.get("names") or []
    if not isinstance(items, list) or not items or len(items) > NUM_CHANS:
        raise ToolError("`names` takes 1 to 96 {channel, name}", field="names")
    todo = []
    for it in items:
        ch, name = int(it.get("channel", 0)), str(it.get("name", "")).strip()
        if not 1 <= ch <= NUM_CHANS:
            raise ToolError("each entry needs a channel 1-96 and a name (an empty name leaves the strip blank)",
                            field="names")
        if not name:
            name = " "
        todo.append((ch, name[:16], _cs(name[:16])))
    with Link() as ln:
        for ch, name, raw in todo:
            ln.send(30, bytes([ch]) + raw + b"\x00")
            time.sleep(0.05)
    time.sleep(0.5)
    lo, hi = min(t[0] for t in todo), max(t[0] for t in todo)
    back = {c["channel"]: c["name"] for c in channel_names({"first": lo, "last": hi})["channels"]}
    out = []
    for ch, name, _ in todo:
        now = back.get(ch)
        out.append({"channel": ch, "asked": name, "now": now,
                    "ok": now is not None and now.strip() == name[:len(now.strip())]})
    return {"channels": out, "ok": sum(1 for o in out if o["ok"]), "failed": [o for o in out if not o["ok"]]}


def _projects_now() -> dict:
    rows, _ = _list_dir("/projects")
    return {r["folder"]: r["name"] for r in rows if r["isDir"]}


def _titles_now(p: str) -> dict:
    rows, _ = _list_dir("/projects/" + p)
    return {r["folder"]: r["name"] for r in rows if r["isDir"]}


@tool("create_project", "Creates a new project on the console with a name (and, given a title, its first title with "
      "that name), then reads back the projects and titles to show the folders the console gave them.",
      props={"name": prop("string", "The project's name, plain ASCII (no accents).", minLength=1, maxLength=40),
             "title": prop("string", "The first title's name, plain ASCII.", minLength=1, maxLength=40),
             "channelNames": prop("string", "Channel names the new title starts with: default (factory) or last "
                                  "(the last used).", enum=["default", "last"])},
      required=("name",), writes=True, module=MODULE, timeout_ms=40000)
def create_project(a: dict) -> dict:
    name = str(a["name"]).strip()
    title = str(a.get("title") or "").strip()
    raw_name = _cs(name)
    raw_title = _cs(title) if title else b""
    before = _projects_now()
    with Link() as ln:
        ln.send(264, raw_name)
        ack_p = bool(ln.collect({265}, 4.0, lambda g: True))
    after, folder = before, None
    for _ in range(6):
        time.sleep(1.0)
        after = _projects_now()
        new = [f for f in after if f not in before]
        named = [f for f in new if after[f] == name] or new
        if named:
            folder = named[0]
            break
    out = {"project": {"name": name, "folder": folder, "acknowledged": ack_p,
                       "shownAs": after.get(folder) if folder else None}}
    if not folder:
        out["note"] = "no new project appeared in /projects: look at the console"
        return out
    if after.get(folder) != name:
        with Link() as ln:
            ln.send(70, _cs("/projects/" + folder) + _cs("%s\n1\n0\n%s\n\n" % (name, name)) + _cs(""))
            ln.collect({71}, 2.0, lambda g: True)
        time.sleep(0.5)
        out["project"]["shownAs"] = _projects_now().get(folder)
    if title:
        mode = 0 if a.get("channelNames") == "last" else 1
        t_before = _titles_now(folder)
        with Link() as ln:
            ln.send(212, _cs(folder) + raw_title + bytes([mode]) + _cs("") + bytes([1]) + _cs(""))
            ack_t = bool(ln.collect({213}, 4.0, lambda g: True))
        t_after, tfolder = t_before, None
        for _ in range(6):
            time.sleep(1.0)
            t_after = _titles_now(folder)
            new = [f for f in t_after if f not in t_before]
            if new:
                tfolder = ([f for f in new if t_after[f] == title] or new)[0]
                break
        out["title"] = {"name": title, "folder": tfolder, "acknowledged": ack_t,
                        "shownAs": t_after.get(tfolder) if tfolder else None, "titles": t_after}
        if not tfolder:
            out["note"] = "the project was made but no title appeared in it: look at the console"
    try:
        out["open"] = _current()
    except ToolError:
        out["open"] = None
    return out


@tool("create_title", "Creates a new title with a name in an existing project on the console, then reads the project's "
      "titles back and says which title is open.",
      props={"project": prop("string", "The project's folder number (list_projects)."),
             "title": prop("string", "The title's name, plain ASCII.", minLength=1, maxLength=40),
             "channelNames": prop("string", "Channel names the new title starts with: default (factory) or last "
                                  "(the last used).", enum=["default", "last"])},
      required=("project", "title"), writes=True, module=MODULE, timeout_ms=30000)
def create_title(a: dict) -> dict:
    folder, title = str(a["project"]).strip().strip("/"), str(a["title"]).strip()
    raw_title = _cs(title)
    if folder not in _projects_now():
        raise ToolError("there is no project folder %s on the console" % folder, field="project")
    mode = 0 if a.get("channelNames") == "last" else 1
    t_before = _titles_now(folder)
    with Link() as ln:
        ln.send(212, _cs(folder) + raw_title + bytes([mode]) + _cs("") + bytes([1]) + _cs(""))
        ack = bool(ln.collect({213}, 4.0, lambda g: True))
    t_after, tfolder = t_before, None
    for _ in range(6):
        time.sleep(1.0)
        t_after = _titles_now(folder)
        new = [f for f in t_after if f not in t_before]
        if new:
            tfolder = ([f for f in new if t_after[f] == title] or new)[0]
            break
    out = {"project": folder, "title": {"name": title, "folder": tfolder, "acknowledged": ack,
                                        "shownAs": t_after.get(tfolder) if tfolder else None},
           "titles": t_after}
    if not tfolder:
        out["note"] = "no new title appeared: look at the console"
    try:
        out["open"] = _current()
    except ToolError:
        out["open"] = None
    return out


@tool("rename_snapshot", "Gives a Total Recall snapshot of the open title a name (its label on the console), then "
      "reads the snapshot list back.",
      props={"number": prop("integer", "The snapshot's number (list_snapshots).", minimum=1, maximum=10000),
             "name": prop("string", "The new name, plain ASCII.", minLength=1, maxLength=40)},
      required=("number", "name"), writes=True, module=MODULE, timeout_ms=20000)
def rename_snapshot(a: dict) -> dict:
    n, name = int(a["number"]), str(a["name"]).strip()
    raw = _cs(name)
    snaps = _snapshots()
    hit = next((s for s in snaps if s["number"] == n), None)
    if not hit:
        raise ToolError("the open title has %d snapshots" % len(snaps), field="number",
                        candidates=[s["number"] for s in snaps])
    path = "%s/%s.trs" % (_tr_dir().rstrip("/"), hit["name"])
    with Link() as ln:
        ln.send(70, _cs(path) + raw + _cs(""))
        ack = bool(ln.collect({71}, 2.0, lambda g: True))
    time.sleep(0.8)
    after = _snapshots()
    now = next((s for s in after if s["number"] == n), None)
    ok = bool(now and (now["info"].split("\n")[0].strip() == name or now["name"] == name))
    return {"path": path, "asked": name, "before": hit, "after": now, "acknowledged": ack, "ok": ok}


@tool("sync_clock", "Sets the console's clock to this Mac's time, so new snapshots and mixes get the right date.",
      writes=True, module=MODULE, timeout_ms=10000)
def sync_clock(a: dict) -> dict:
    t = time.localtime()
    with Link() as ln:
        ln.send(170, struct.pack(">6i", t.tm_hour, t.tm_min, t.tm_sec, t.tm_mday, t.tm_mon, t.tm_year - 2000))
    return {"sent": time.strftime("%Y-%m-%d %H:%M:%S", t)}
