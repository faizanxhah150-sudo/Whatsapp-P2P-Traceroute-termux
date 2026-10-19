"""Incremental parser for a PCAP byte stream (what ``tcpdump -w -`` writes to stdout).

Handles both byte orders, microsecond and nanosecond timestamps, and the link
types tcpdump may report on Android/Linux:

    0    BSD loopback (4-byte family header)
    1    Ethernet
    12   raw IP (OpenBSD/Linux DLT_RAW)
    101  raw IP
    113  Linux cooked capture (SLL, 16-byte header)
    276  Linux cooked capture v2 (SLL2, 20-byte header)

Data may arrive in arbitrary chunks (partial reads); ``feed()`` buffers
leftovers and only returns complete frames.
"""
from __future__ import annotations

import struct
from typing import NamedTuple

from utils.netif import LINK_ETHERNET, LINK_RAW

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_ALT = 12
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

SUPPORTED_LINKTYPES = frozenset({
    LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW_ALT, LINKTYPE_RAW,
    LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
})

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16
MAX_CAPLEN = 1 << 22  # 4 MiB: far above any real frame; guards against a corrupt stream

# magic as read little-endian from the first 4 bytes -> (struct endianness, nanosecond?)
_MAGICS = {
    0xA1B2C3D4: ("<", False),
    0xA1B23C4D: ("<", True),
    0xD4C3B2A1: (">", False),
    0x4D3CB2A1: (">", True),
}


class PcapStreamError(ValueError):
    """The stream is not a PCAP, uses an unsupported link type, or is corrupt."""


class Frame(NamedTuple):
    ts: float
    data: bytes
    kind: str              # "ethernet" or "raw" (SLL/NULL headers already stripped)
    direction: str | None  # "in" / "out" when the link type carries it (SLL), else None


def _direction(pkttype: int) -> str | None:
    if pkttype == 4:
        return "out"
    if pkttype in (0, 1, 2):
        return "in"
    return None


class PcapStreamParser:
    def __init__(self):
        self._buf = bytearray()
        self._header_done = False
        self._rec = "<IIII"
        self._frac_div = 1e6
        self.linktype: int | None = None
        self.snaplen = 0
        self.frames = 0

    @property
    def leftover(self) -> int:
        """Bytes buffered but not yet a complete record (non-zero after a truncated stream)."""
        return len(self._buf)

    def _parse_header(self, hdr: bytes) -> None:
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic not in _MAGICS:
            raise PcapStreamError(f"not a pcap stream (magic 0x{magic:08x})")
        endian, nano = _MAGICS[magic]
        _maj, _min, _zone, _sig, snaplen, network = struct.unpack(endian + "HHiIII", hdr[4:])
        linktype = network & 0x0FFFFFFF  # upper bits carry FCS info
        if linktype not in SUPPORTED_LINKTYPES:
            raise PcapStreamError(f"unsupported pcap linktype {linktype}")
        self._rec = endian + "IIII"
        self._frac_div = 1e9 if nano else 1e6
        self.linktype = linktype
        self.snaplen = snaplen
        self._header_done = True

    def _convert(self, ts: float, data: bytes) -> Frame | None:
        lt = self.linktype
        if lt == LINKTYPE_ETHERNET:
            return Frame(ts, data, LINK_ETHERNET, None)
        if lt in (LINKTYPE_RAW, LINKTYPE_RAW_ALT):
            return Frame(ts, data, LINK_RAW, None)
        if lt == LINKTYPE_LINUX_SLL:
            if len(data) < 16:
                return None
            return Frame(ts, data[16:], LINK_RAW, _direction(int.from_bytes(data[0:2], "big")))
        if lt == LINKTYPE_LINUX_SLL2:
            if len(data) < 20:
                return None
            return Frame(ts, data[20:], LINK_RAW, _direction(data[10]))
        if lt == LINKTYPE_NULL:
            return Frame(ts, data[4:], LINK_RAW, None) if len(data) > 4 else None
        return None

    def feed(self, chunk: bytes) -> list[Frame]:
        """Add stream bytes; return every complete frame now available."""
        buf = self._buf
        buf += chunk
        out: list[Frame] = []
        pos = 0
        if not self._header_done:
            if len(buf) < GLOBAL_HEADER_LEN:
                return out
            self._parse_header(bytes(buf[:GLOBAL_HEADER_LEN]))
            pos = GLOBAL_HEADER_LEN
        total = len(buf)
        while total - pos >= RECORD_HEADER_LEN:
            sec, frac, caplen, _orig = struct.unpack_from(self._rec, buf, pos)
            if caplen > MAX_CAPLEN:
                raise PcapStreamError(f"corrupt pcap stream (record length {caplen})")
            start = pos + RECORD_HEADER_LEN
            if total - start < caplen:
                break  # partial packet: wait for more bytes
            frame = self._convert(sec + frac / self._frac_div, bytes(buf[start:start + caplen]))
            pos = start + caplen
            if frame is not None:
                self.frames += 1
                out.append(frame)
        del buf[:pos]
        return out
