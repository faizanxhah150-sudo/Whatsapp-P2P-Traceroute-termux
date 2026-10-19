import socket

import pytest

import config
from core import packet_sniffer as ps
from core.ip_filter import load_networks
from tests.frames import ether, udp4, udp6


def setup_module(_):
    load_networks(["157.240.0.0/16", "2a03:2880::/32"])


class FakeSock:
    """Replays (frame, sockaddr_ll) pairs, then times out like a real idle socket."""

    def __init__(self, frames):
        self.frames = list(frames)
        self.closed = False

    def recvfrom(self, _n):
        if self.frames:
            return self.frames.pop(0)
        raise socket.timeout()

    def close(self):
        self.closed = True


def addr(pkttype, hatype, iface="ccmni1"):
    return (iface, 0x0800, pkttype, hatype, b"")


@pytest.fixture
def patched(monkeypatch):
    monkeypatch.setattr(ps, "pick_interface", lambda requested="": requested or "ccmni1")
    monkeypatch.setattr(ps, "af_packet_supported", lambda: True)
    monkeypatch.setattr(ps.netif, "local_addresses", lambda name: set())


def run(monkeypatch, tmp_path, frames, kind="raw", **kwargs):
    monkeypatch.setattr(ps.netif, "link_kind_for", lambda name: kind)
    sock = FakeSock(frames)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    monkeypatch.setattr(s, "_open_socket", lambda iface: sock)
    s.start_sniffing(iface="ccmni1", **kwargs)
    return s, sock


def test_cellular_raw_capture_end_to_end(patched, monkeypatch, tmp_path):
    frames = [
        (udp4("10.1.2.3", "157.240.1.5", 40000, 40001), addr(4, 519)),   # outgoing to Meta
        (udp4("45.55.100.10", "10.1.2.3", 50002, 50000), addr(0, 519)),  # incoming from a non-Meta peer
    ]
    s, sock = run(monkeypatch, tmp_path, frames, count=2)
    assert sock.closed and s.frames_seen == 2
    rows = {r["remote"]: r for r in s.rows()}
    assert rows["157.240.1.5"]["is_meta"] is True
    assert rows["45.55.100.10"]["candidate_peer"] is True
    assert (tmp_path / "t.pcap").read_bytes()[20:24] == (101).to_bytes(4, "little")


def test_wifi_ethernet_capture(patched, monkeypatch, tmp_path):
    frames = [(ether(udp4("192.168.1.2", "157.240.1.5", 1111, 2222)), addr(4, 1, "wlan0"))]
    s, _ = run(monkeypatch, tmp_path, frames, kind="ethernet", count=1)
    assert s.rows()[0]["remote"] == "157.240.1.5"
    assert (tmp_path / "t.pcap").read_bytes()[20:24] == (1).to_bytes(4, "little")


def test_unknown_link_type_is_decided_per_packet(patched, monkeypatch, tmp_path):
    frames = [(udp4("10.1.2.3", "157.240.1.5", 1, 2), addr(4, 519)),
              (ether(udp4("192.168.1.2", "157.240.1.5", 1, 2)), addr(4, 1))]
    s, _ = run(monkeypatch, tmp_path, frames, kind="unknown", count=2)
    assert s.frames_seen == 2 and s.packets_saved == 1  # kinds differ -> second not written to pcap


def test_phone_with_public_ipv6_on_cellular(patched, monkeypatch, tmp_path):
    me = "2001:db8::77"
    monkeypatch.setattr(ps.netif, "local_addresses", lambda name: {me})
    frames = [(udp6(me, "2a03:2880::9", 5000, 5001), addr(4, 519))]
    s, _ = run(monkeypatch, tmp_path, frames, count=1)
    assert s.rows()[0]["remote"] == "2a03:2880::9"


def test_timeout_stops_idle_capture(patched, monkeypatch, tmp_path):
    s, sock = run(monkeypatch, tmp_path, [], timeout=1)
    assert sock.closed and s.frames_seen == 0
    assert not (tmp_path / "t.pcap").exists()  # nothing captured -> no empty pcap


def test_stop_event_ends_capture_loop(patched, monkeypatch, tmp_path):
    import threading
    import time

    monkeypatch.setattr(ps.netif, "link_kind_for", lambda name: "raw")
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    sock = FakeSock([])
    monkeypatch.setattr(s, "_open_socket", lambda iface: sock)
    t = threading.Thread(target=lambda: s.start_sniffing(iface="ccmni1"))
    t.start()
    time.sleep(0.2)
    s.stop()
    t.join(3)
    assert not t.is_alive() and sock.closed


def test_on_record_callback_errors_do_not_break_capture(patched, monkeypatch, tmp_path):
    monkeypatch.setattr(ps.netif, "link_kind_for", lambda name: "raw")
    seen = []

    def cb(rec):
        seen.append(rec["remote"])
        raise RuntimeError("websocket gone")

    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", on_record=cb, bpf="")
    assert s.process_frame(udp4("10.1.2.3", "157.240.1.5", 1, 2), "raw", "out")
    assert seen == ["157.240.1.5"]
    s.save_packets()


def test_permission_error_gives_actionable_message(monkeypatch):
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    monkeypatch.setattr(ps, "pick_interface", lambda requested="": requested)
    monkeypatch.setattr(ps, "af_packet_supported", lambda: True)

    def denied(*a, **k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(ps.socket, "socket", denied)
    monkeypatch.setattr(ps.netif, "link_kind_for", lambda name: "raw")
    monkeypatch.setattr(ps.netif, "local_addresses", lambda name: set())
    s = ps.PacketSniffer(bpf="")
    with pytest.raises(ps.CapturePermissionError) as exc:
        s.start_sniffing(iface="wlan0")
    msg = str(exc.value)
    assert "scripts/run_root.sh" in msg and "Magisk" in msg and "wlan0" in msg
    assert isinstance(exc.value, PermissionError)


def test_missing_interface_gives_clear_error(monkeypatch):
    import errno

    class Sock:
        def setsockopt(self, *a):
            pass

        def bind(self, _a):
            raise OSError(errno.ENODEV, "No such device")

        def close(self):
            pass

    monkeypatch.setattr(ps, "pick_interface", lambda requested="": requested)
    monkeypatch.setattr(ps, "af_packet_supported", lambda: True)
    monkeypatch.setattr(ps.socket, "socket", lambda *a, **k: Sock())
    monkeypatch.setattr(ps.netif, "link_kind_for", lambda name: "raw")
    monkeypatch.setattr(ps.netif, "local_addresses", lambda name: set())
    s = ps.PacketSniffer(bpf="")
    with pytest.raises(ps.CaptureError, match="does not exist"):
        s.start_sniffing(iface="nope0")


def fake_ifaces(monkeypatch, names=("wlan0", "ccmni1")):
    items = [ps.netif.IfaceInfo(n, "up", 1, "ethernet", "10.0.0.2", 5, 5, ps.netif.categorize(n))
             for n in names]
    monkeypatch.setattr(ps, "netif_available", lambda: True)
    monkeypatch.setattr(ps.netif, "list_interfaces", lambda: items)
    monkeypatch.setattr(ps.netif, "default_route_ifaces", lambda: [])


def test_pick_interface_accepts_known_explicit_name(monkeypatch):
    fake_ifaces(monkeypatch)
    assert ps.pick_interface("ccmni1") == "ccmni1"


def test_pick_interface_unknown_name_lists_available_without_traceback(monkeypatch):
    fake_ifaces(monkeypatch)
    with pytest.raises(ps.InterfaceNotFoundError) as exc:
        ps.pick_interface("wlan9")
    msg = str(exc.value)
    assert "wlan9" in msg and "wlan0" in msg and "ccmni1" in msg and "--list-ifaces" in msg
    assert isinstance(exc.value, ps.CaptureError)  # main() turns this into a clean error line


def test_pick_interface_explicit_name_accepted_when_sysfs_unreadable(monkeypatch):
    monkeypatch.setattr(ps, "netif_available", lambda: False)
    assert ps.pick_interface("wlan0") == "wlan0"


def test_pick_interface_errors_when_nothing_usable(monkeypatch):
    monkeypatch.setattr(ps, "netif_available", lambda: True)
    monkeypatch.setattr(ps.netif, "list_interfaces", lambda: [
        ps.netif.IfaceInfo("lo", "unknown", 772, "ethernet", "127.0.0.1", 1, 1, "skip")])
    monkeypatch.setattr(ps.netif, "default_route_ifaces", lambda: [])
    with pytest.raises(ps.CaptureError, match="--list-ifaces"):
        ps.pick_interface("")


def test_pick_interface_env_default(monkeypatch):
    fake_ifaces(monkeypatch)
    monkeypatch.setattr(config, "DEFAULT_IFACE", "wlan0")
    assert ps.pick_interface(config.DEFAULT_IFACE) == "wlan0"
