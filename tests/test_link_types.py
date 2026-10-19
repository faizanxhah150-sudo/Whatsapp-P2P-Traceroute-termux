"""Ethernet (Wi-Fi, type 1) vs raw-IP (cellular, type 519/512) handling."""
import struct

from core.packet_parser import LINK_ETHERNET, LINK_RAW, LINK_UNKNOWN, parse_frame
from core.packet_sniffer import PacketSniffer
from tests.frames import ether, tcp4, udp4, udp6
from utils.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, PcapWriter, linktype_for_kind


def test_ethernet_frame_parsed_with_ethernet_kind():
    info = parse_frame(ether(udp4("192.168.1.2", "157.240.1.5", 5000, 5001)), LINK_ETHERNET)
    assert (info.version, info.proto, info.src, info.dst) == (4, "udp", "192.168.1.2", "157.240.1.5")
    assert (info.sport, info.dport) == (5000, 5001)


def test_raw_ip_frame_parsed_without_ethernet_header():
    info = parse_frame(udp4("10.1.2.3", "157.240.1.5", 5000, 5001), LINK_RAW)
    assert info is not None and info.src == "10.1.2.3" and info.dport == 5001


def test_raw_ipv6_frame():
    info = parse_frame(udp6("2001:db8::1", "2a03:2880::5", 4000, 4001), LINK_RAW)
    assert info.version == 6 and info.dst == "2a03:2880::5" and info.sport == 4000


def test_ethernet_ipv6_and_vlan_tag():
    plain = ether(udp6("2001:db8::1", "2a03:2880::5", 1, 2), ethertype=0x86DD)
    assert parse_frame(plain, LINK_ETHERNET).version == 6
    inner = udp4("192.168.1.2", "157.240.1.5", 1, 2)
    tagged = (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
              + struct.pack("!HHH", 0x8100, 0x0005, 0x0800) + inner)
    assert parse_frame(tagged, LINK_ETHERNET).dst == "157.240.1.5"


def test_wrong_link_kind_never_misparses():
    raw = udp4("10.1.2.3", "157.240.1.5", 1, 2)
    eth = ether(raw)
    assert parse_frame(raw, LINK_ETHERNET) is None   # IP bytes are not an Ethernet header
    assert parse_frame(eth, LINK_RAW) is None        # MAC starts with 0x02: not an IP version


def test_unknown_kind_sniffs_ip_version_nibble():
    assert parse_frame(udp4("10.1.2.3", "157.240.1.5", 1, 2), LINK_UNKNOWN) is not None


def test_non_ip_and_truncated_frames_return_none():
    assert parse_frame(b"", LINK_RAW) is None
    assert parse_frame(b"\x45\x00", LINK_RAW) is None
    assert parse_frame(ether(b"\x00" * 28, ethertype=0x0806), LINK_ETHERNET) is None  # ARP
    assert parse_frame(b"\x00" * 10, LINK_ETHERNET) is None


def test_tcp_ports_parsed():
    info = parse_frame(tcp4("10.0.0.2", "157.240.1.5", 40000, 443), LINK_RAW)
    assert info.proto == "tcp" and info.dport == 443


def test_linktype_for_kind():
    assert linktype_for_kind("ethernet") == LINKTYPE_ETHERNET == 1
    assert linktype_for_kind("raw") == LINKTYPE_RAW == 101
    assert linktype_for_kind("unknown") == 101


def _pcap_header(path):
    data = path.read_bytes()
    magic, vmaj, vmin, _tz, _sig, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
    return magic, vmaj, vmin, snaplen, linktype, data[24:]


def test_pcap_writer_header_and_record(tmp_path):
    p = tmp_path / "x.pcap"
    with PcapWriter(p, LINKTYPE_RAW) as w:
        w.write(b"\x45\x00abcd", ts=1700000000.5)
    magic, vmaj, vmin, snaplen, linktype, body = _pcap_header(p)
    assert (magic, vmaj, vmin, snaplen, linktype) == (0xA1B2C3D4, 2, 4, 65535, 101)
    sec, usec, caplen, origlen = struct.unpack("<IIII", body[:16])
    assert (sec, usec, caplen, origlen) == (1700000000, 500000, 6, 6)
    assert body[16:] == b"\x45\x00abcd"


def test_sniffer_writes_raw_linktype_for_cellular(tmp_path):
    s = PacketSniffer(log_file=tmp_path / "raw.pcap", bpf="")
    assert s.process_frame(udp4("10.1.2.3", "157.240.1.5", 5000, 5001), LINK_RAW, "out")
    s.save_packets()
    assert _pcap_header(tmp_path / "raw.pcap")[4] == 101


def test_sniffer_writes_ethernet_linktype_for_wifi(tmp_path):
    s = PacketSniffer(log_file=tmp_path / "eth.pcap", bpf="")
    assert s.process_frame(ether(udp4("192.168.1.2", "157.240.1.5", 5000, 5001)), LINK_ETHERNET, "out")
    s.save_packets()
    assert _pcap_header(tmp_path / "eth.pcap")[4] == 1


def test_link_kind_switch_does_not_corrupt_pcap(tmp_path):
    s = PacketSniffer(log_file=tmp_path / "m.pcap", bpf="")
    s.process_frame(udp4("10.1.2.3", "157.240.1.5", 5000, 5001), LINK_RAW, "out")
    s.process_frame(ether(udp4("192.168.1.2", "157.240.1.5", 5000, 5001)), LINK_ETHERNET, "out")
    s.save_packets()
    assert s.packets_saved == 1 and len(s.records) == 2
