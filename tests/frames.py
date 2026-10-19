"""Tiny raw-frame builders so tests need neither Scapy nor root."""
import socket
import struct

MAC_A = b"\x02\x00\x00\x00\x00\x01"  # locally administered: first nibble is NOT 4 or 6
MAC_B = b"\x02\x00\x00\x00\x00\x02"


def udp(sport, dport, payload=b"x" * 20):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, payload=b"data"):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 65535, 0, 0) + payload


def ipv4(src, dst, proto, l4):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + l4


def ipv6(src, dst, next_header, l4):
    hdr = struct.pack("!IHBB16s16s", 0x60000000, len(l4), next_header, 64,
                      socket.inet_pton(socket.AF_INET6, src),
                      socket.inet_pton(socket.AF_INET6, dst))
    return hdr + l4


def ether(payload, ethertype=0x0800):
    return MAC_A + MAC_B + struct.pack("!H", ethertype) + payload


def udp4(src, dst, sport, dport):
    return ipv4(src, dst, 17, udp(sport, dport))


def tcp4(src, dst, sport, dport):
    return ipv4(src, dst, 6, tcp(sport, dport))


def udp6(src, dst, sport, dport):
    return ipv6(src, dst, 17, udp(sport, dport))


# --- pcap stream builders (what `tcpdump -w -` emits) -------------------------------------
def pcap_header(endian="<", nano=False, linktype=1, snaplen=262144):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    return struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)


def pcap_record(payload, ts=1700000000.5, endian="<", nano=False):
    sec = int(ts)
    frac = int(round((ts - sec) * (1_000_000_000 if nano else 1_000_000)))
    return struct.pack(endian + "IIII", sec, frac, len(payload), len(payload)) + payload


def pcap_bytes(payloads, endian="<", nano=False, linktype=1, ts=1700000000.5):
    out = pcap_header(endian, nano, linktype)
    for i, p in enumerate(payloads):
        out += pcap_record(p, ts + i, endian, nano)
    return out


def sll(pkttype, payload, proto=0x0800):
    """Linux cooked capture v1 header (16 bytes)."""
    return struct.pack("!HHH8sH", pkttype, 1, 6, MAC_A + b"\x00\x00", proto) + payload


def sll2(pkttype, payload, proto=0x0800):
    """Linux cooked capture v2 header (20 bytes; pkttype at offset 10)."""
    return struct.pack("!HHIHBB8s", proto, 0, 3, 1, pkttype, 6, MAC_A + b"\x00\x00") + payload
