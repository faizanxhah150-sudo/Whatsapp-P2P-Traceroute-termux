"""Minimal dependency-free PCAP writer with the correct link-layer type.

Wireshark needs LINKTYPE_ETHERNET (1) for Ethernet frames (Wi-Fi) and
LINKTYPE_RAW (101) for raw-IP frames (cellular ccmni*/rmnet*).
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

_MAGIC = 0xA1B2C3D4


def linktype_for_kind(kind: str) -> int:
    """'ethernet' -> 1, 'raw' -> 101. Unknown frames are treated as raw IP."""
    return LINKTYPE_ETHERNET if kind == "ethernet" else LINKTYPE_RAW


class PcapWriter:
    def __init__(self, path: str | Path, linktype: int, snaplen: int = 65535,
                 flush_interval: float = 1.0):
        self.path = Path(path)
        self.linktype = linktype
        self.snaplen = snaplen
        self.count = 0
        self._flush_interval = flush_interval
        self._last_flush = time.monotonic()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "wb")
        self._fh.write(struct.pack("<IHHiIII", _MAGIC, 2, 4, 0, 0, snaplen, linktype))

    def write(self, data: bytes, ts: float | None = None) -> None:
        if self._fh is None:
            return
        ts = time.time() if ts is None else ts
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        caplen = min(len(data), self.snaplen)
        self._fh.write(struct.pack("<IIII", sec, usec, caplen, len(data)))
        self._fh.write(data[:caplen])
        self.count += 1
        now = time.monotonic()
        if now - self._last_flush >= self._flush_interval:
            self._fh.flush()
            self._last_flush = now

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.flush()
            finally:
                self._fh.close()
                self._fh = None

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
