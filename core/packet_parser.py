"""Pure-Python IPv4/IPv6 + TCP/UDP header parser.

Works on raw frame bytes and takes the link type into account: Ethernet frames
(Wi-Fi, type 1) carry a 14-byte header, raw-IP frames (cellular, type 519/512)
start directly at the IP header. No Scapy or libpcap needed, which keeps the
capture path light and dependable on Android.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from utils.netif import LINK_ETHERNET, LINK_RAW, LINK_UNKNOWN  # noqa: F401

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_ETH_VLAN = (0x8100, 0x88A8)

_EXT_HEADERS = (0, 43, 60)  # hop-by-hop, routing, destination options


@dataclass
class PacketInfo:
    version: int          # 4 or 6
    proto: str            # "tcp", "udp", "icmp", "icmp6" or "other"
    src: str
    dst: str
    sport: int
    dport: int
    length: int           # full frame length in bytes


def _l4(data: bytes, off: int, proto_num: int, n: int):
    """Return (name, sport, dport) for TCP/UDP; (name, 0, 0) otherwise."""
    if proto_num in (6, 17):
        if n < off + 4:
            return None
        sport, dport = struct.unpack_from("!HH", data, off)
        return ("tcp" if proto_num == 6 else "udp"), sport, dport
    if proto_num == 1:
        return "icmp", 0, 0
    if proto_num == 58:
        return "icmp6", 0, 0
    return "other", 0, 0


def _parse_ipv4(data: bytes, off: int, n: int) -> PacketInfo | None:
    if n < off + 20:
        return None
    ihl = (data[off] & 0x0F) * 4
    if ihl < 20 or n < off + ihl:
        return None
    frag_offset = ((data[off + 6] & 0x1F) << 8) | data[off + 7]
    if frag_offset:
        return None  # non-first fragment: no L4 header to read
    l4 = _l4(data, off + ihl, data[off + 9], n)
    if l4 is None:
        return None
    return PacketInfo(
        4, l4[0], socket.inet_ntoa(bytes(data[off + 12:off + 16])),
        socket.inet_ntoa(bytes(data[off + 16:off + 20])), l4[1], l4[2], n,
    )


def _parse_ipv6(data: bytes, off: int, n: int) -> PacketInfo | None:
    if n < off + 40:
        return None
    nh = data[off + 6]
    pos = off + 40
    for _ in range(8):  # bounded walk over extension headers
        if nh in _EXT_HEADERS and n >= pos + 8:
            nxt = data[pos]
            pos += (data[pos + 1] + 1) * 8
            nh = nxt
        elif nh == 44 and n >= pos + 8:  # fragment header
            nxt = data[pos]
            if (((data[pos + 2] << 8) | data[pos + 3]) >> 3) != 0:
                return None
            pos += 8
            nh = nxt
        else:
            break
    l4 = _l4(data, pos, nh, n)
    if l4 is None:
        return None
    return PacketInfo(
        6, l4[0], socket.inet_ntop(socket.AF_INET6, bytes(data[off + 8:off + 24])),
        socket.inet_ntop(socket.AF_INET6, bytes(data[off + 24:off + 40])), l4[1], l4[2], n,
    )


def parse_frame(data: bytes, kind: str) -> PacketInfo | None:
    """Parse one captured frame. ``kind`` is ``ethernet``, ``raw`` or ``unknown``.

    ``unknown`` is treated as raw IP and detected by the IP version nibble.
    Returns None for anything that is not IPv4/IPv6.
    """
    n = len(data)
    off = 0
    if kind == LINK_ETHERNET:
        if n < 14:
            return None
        ethertype = (data[12] << 8) | data[13]
        off = 14
        while ethertype in _ETH_VLAN and n >= off + 4:
            ethertype = (data[off + 2] << 8) | data[off + 3]
            off += 4
        if ethertype == _ETH_IPV4:
            return _parse_ipv4(data, off, n)
        if ethertype == _ETH_IPV6:
            return _parse_ipv6(data, off, n)
        return None
    if n < 1:
        return None
    version = data[0] >> 4
    if version == 4:
        return _parse_ipv4(data, 0, n)
    if version == 6:
        return _parse_ipv6(data, 0, n)
    return None
