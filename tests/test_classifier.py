import pytest

from core.classifier import classify, classify_info, pick_remote
from core.ip_filter import load_networks
from core.packet_parser import LINK_RAW, parse_frame
from tests.frames import tcp4, udp4, udp6


def setup_module(_):
    load_networks(["157.240.0.0/16", "2a03:2880::/32"])


def _classify(frame, direction=None, local_ips=None):
    return classify_info(parse_frame(frame, LINK_RAW), direction, local_ips)


def test_meta_udp_flow_local_to_server():
    rec = _classify(udp4("192.168.1.20", "157.240.1.5", 50000, 50001))
    assert rec is not None
    assert rec.remote == "157.240.1.5"
    assert rec.is_meta is True
    assert rec.candidate_peer is False


def test_candidate_peer_public_media():
    # Public, non-Meta remote on high UDP ports during media => flagged peer.
    rec = _classify(udp4("192.168.1.20", "45.55.100.10", 50000, 50002))
    assert rec is not None
    assert rec.remote == "45.55.100.10"
    assert rec.is_meta is False
    assert rec.candidate_peer is True
    assert rec.score >= 90


def test_signaling_port_not_peer():
    rec = _classify(tcp4("192.168.1.20", "157.240.1.5", 50000, 443))
    assert rec.candidate_peer is False


def test_two_private_hosts_ignored():
    assert _classify(udp4("192.168.1.20", "192.168.1.30", 1, 2)) is None


def test_non_tcp_udp_ignored():
    from core.packet_parser import PacketInfo

    assert classify_info(PacketInfo(4, "icmp", "10.0.0.2", "8.8.8.8", 0, 0, 60)) is None


def test_cellular_cgnat_phone_address_is_local():
    # 100.64.0.0/10 is carrier-grade NAT, not a public peer.
    rec = _classify(udp4("100.72.3.9", "157.240.1.5", 40000, 40001))
    assert rec.remote == "157.240.1.5"
    assert _classify(udp4("100.72.3.9", "100.72.3.10", 1, 2)) is None


def test_phone_with_public_ipv6_uses_local_ips():
    me = "2001:db8::1"  # stands in for the phone's global IPv6 address
    frame = udp6("2a03:2880::5", me, 40000, 40001)
    rec = _classify(frame, direction="in", local_ips={me})
    assert rec is not None and rec.remote == "2a03:2880::5" and rec.is_meta


def test_pick_remote_uses_direction_when_both_public():
    assert pick_remote("45.55.0.1", "46.55.0.2", "out") == "46.55.0.2"
    assert pick_remote("45.55.0.1", "46.55.0.2", "in") == "45.55.0.1"
    assert pick_remote("45.55.0.1", "46.55.0.2") is None  # ambiguous, no hints


def test_pick_remote_prefers_meta_side_when_ambiguous():
    assert pick_remote("45.55.0.1", "157.240.1.5") == "157.240.1.5"


def test_hotspot_client_traffic_picks_public_side():
    # Seen on ap0: a hotspot client (private) talking to a Meta server.
    assert pick_remote("192.168.43.7", "157.240.1.5", "in") == "157.240.1.5"
    assert pick_remote("157.240.1.5", "192.168.43.7", "out") == "157.240.1.5"


def test_multicast_and_broadcast_ignored():
    assert _classify(udp4("192.168.1.20", "239.255.255.250", 1900, 1900)) is None
    assert _classify(udp4("192.168.1.20", "255.255.255.255", 68, 67)) is None


def test_scapy_packet_adapter():
    scapy_inet = pytest.importorskip("scapy.layers.inet")
    pkt = scapy_inet.IP(src="192.168.1.20", dst="45.55.100.10") / scapy_inet.UDP(
        sport=50000, dport=50002
    )
    rec = classify(pkt)
    assert rec is not None and rec.candidate_peer is True


def test_dns_to_public_resolver_is_not_a_peer():
    rec = _classify(udp4("192.168.1.20", "8.8.8.8", 51807, 53))
    assert rec is not None and rec.candidate_peer is False and rec.score == 60
