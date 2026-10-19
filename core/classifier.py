"""Turn a parsed packet into a structured, enriched record and score it.

Key idea: passive capture mostly sees Meta relay servers. A *non-Meta* remote
IP appearing during media (UDP/STUN) traffic is the interesting signal - a
possible peer-to-peer endpoint. We flag those.

On a phone the capture sees the phone's own traffic, so the *remote* side is
chosen from packet direction (AF_PACKET reports in/out) and the phone's own
addresses first, and only then from the private-vs-public heuristic. This also
works on cellular networks where the phone itself may hold a public IPv6
address or a CGNAT (100.64.0.0/10) IPv4 address.
"""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

from core.dns_resolver import is_meta_hostname, reverse_dns
from core.ip_filter import is_whatsapp_ip
from core.packet_parser import PacketInfo
from utils.geo_ip import get_geo_info

# Ports strongly associated with WhatsApp signaling / STUN media.
SIGNALING_PORTS = {443, 5222, 3478}
# Ordinary infrastructure UDP (DNS, DoT/DoQ, NTP, mDNS, SSDP, DHCP, NetBIOS) is never
# call media; without this every DNS query to a public resolver looked like a peer.
NON_MEDIA_PORTS = {53, 67, 68, 123, 137, 138, 853, 1900, 5353}

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_private(ip: str) -> bool:
    """True for anything that is not a routable public address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 4 and addr in _CGNAT:
        return True
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_unspecified or addr.is_reserved
    )


@dataclass
class FlowRecord:
    ts: str
    src: str
    dst: str
    remote: str          # the non-local endpoint
    proto: str
    sport: int
    dport: int
    length: int
    is_meta: bool
    host: str
    country: str
    city: str
    latitude: float
    longitude: float
    asn: int
    org: str
    candidate_peer: bool  # non-Meta, public, media traffic => possible P2P leak
    score: int            # 0-100 "interesting" heuristic

    def to_dict(self):
        return asdict(self)


def pick_remote(src: str, dst: str, direction: str | None = None,
                local_ips: Iterable[str] | None = None) -> str | None:
    """Return the non-local endpoint of a packet, or None if there isn't one."""
    local = set(local_ips or ())
    src_ok = src not in local and not _is_private(src)
    dst_ok = dst not in local and not _is_private(dst)

    if src_ok and not dst_ok:
        return src
    if dst_ok and not src_ok:
        return dst
    if not (src_ok and dst_ok):
        return None  # both local/private: LAN chatter

    # Both look public and the phone's own address is unknown.
    if direction == "out":
        return dst
    if direction == "in":
        return src
    meta_src, meta_dst = is_whatsapp_ip(src), is_whatsapp_ip(dst)
    if meta_dst and not meta_src:
        return dst
    if meta_src and not meta_dst:
        return src
    return None


def classify_info(info: PacketInfo, direction: str | None = None,
                  local_ips: Iterable[str] | None = None) -> FlowRecord | None:
    if info.proto not in ("tcp", "udp"):
        return None
    remote = pick_remote(info.src, info.dst, direction, local_ips)
    if remote is None:
        return None

    proto = info.proto.upper()
    is_meta = is_whatsapp_ip(remote)

    host = reverse_dns(remote)  # non-blocking: None until the lookup finishes
    if host and is_meta_hostname(host):
        is_meta = True

    geo = get_geo_info(remote)
    if geo.get("asn") == 32934:
        is_meta = True

    sport, dport = info.sport, info.dport
    ignored = SIGNALING_PORTS | NON_MEDIA_PORTS
    is_media = proto == "UDP" and (sport not in ignored and dport not in ignored)
    public_remote = not _is_private(remote)
    candidate_peer = (not is_meta) and public_remote and is_media

    score = 0
    if candidate_peer:
        score = 90
    elif not is_meta and public_remote:
        score = 60
    elif is_meta and is_media:
        score = 30

    return FlowRecord(
        ts=datetime.now(timezone.utc).isoformat(),
        src=info.src,
        dst=info.dst,
        remote=remote,
        proto=proto,
        sport=sport,
        dport=dport,
        length=info.length,
        is_meta=is_meta,
        host=host or "",
        country=geo.get("country") or "",
        city=geo.get("city") or "",
        latitude=geo.get("latitude"),
        longitude=geo.get("longitude"),
        asn=geo.get("asn"),
        org=geo.get("org") or "",
        candidate_peer=candidate_peer,
        score=score,
    )


def packet_to_info(packet) -> PacketInfo | None:
    """Convert a Scapy packet (IP or IPv6 over anything) to PacketInfo."""
    from scapy.layers.inet import IP, TCP, UDP

    try:
        from scapy.layers.inet6 import IPv6
    except Exception:  # very old/partial scapy
        IPv6 = None

    if IP in packet:
        version, ip = 4, packet[IP]
    elif IPv6 is not None and IPv6 in packet:
        version, ip = 6, packet[IPv6]
    else:
        return None

    if TCP in packet:
        proto, l4 = "tcp", packet[TCP]
    elif UDP in packet:
        proto, l4 = "udp", packet[UDP]
    else:
        return None
    return PacketInfo(version, proto, ip.src, ip.dst, int(l4.sport), int(l4.dport), len(packet))


def classify(packet, direction: str | None = None,
             local_ips: Iterable[str] | None = None) -> FlowRecord | None:
    """Scapy-packet entry point (kept for compatibility and offline analysis)."""
    info = packet_to_info(packet)
    if info is None:
        return None
    return classify_info(info, direction, local_ips)
