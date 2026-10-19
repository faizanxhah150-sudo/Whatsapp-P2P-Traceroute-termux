import subprocess
import types

import pytest

from core import bpf
from core.packet_parser import PacketInfo
from core.packet_sniffer import PacketSniffer


def info(proto="udp", sport=5000, dport=5001, src="10.0.0.2", dst="157.240.1.5", version=4):
    return PacketInfo(version, proto, src, dst, sport, dport, 100)


DDD = "3\n40 0 0 12\n21 0 1 2048\n6 0 0 262144\n"


def test_parse_ddd_ok_and_errors():
    insns, why = bpf.parse_ddd(DDD)
    assert insns == [(40, 0, 0, 12), (21, 0, 1, 2048), (6, 0, 0, 262144)] and why == ""
    assert bpf.parse_ddd("")[0] is None
    assert bpf.parse_ddd("2\n1 2 3 4\n")[0] is None       # count mismatch
    assert bpf.parse_ddd("1\nfoo bar\n")[0] is None       # garbage


def test_compile_kernel_filter_missing_tcpdump():
    insns, why = bpf.compile_kernel_filter("udp", "wlan0", which=lambda _n: None)
    assert insns is None and "tcpdump" in why


def test_compile_kernel_filter_success_and_failure_modes():
    ok = types.SimpleNamespace(returncode=0, stdout=DDD, stderr="")
    insns, _ = bpf.compile_kernel_filter("udp", "wlan0", runner=lambda *a, **k: ok,
                                         which=lambda _n: "/usr/bin/tcpdump")
    assert len(insns) == 3

    bad = types.SimpleNamespace(returncode=1, stdout="", stderr="tcpdump: no such device")
    insns, why = bpf.compile_kernel_filter("udp", "zz9", runner=lambda *a, **k: bad,
                                           which=lambda _n: "/usr/bin/tcpdump")
    assert insns is None and "no such device" in why

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("tcpdump", 5)

    insns, why = bpf.compile_kernel_filter("udp", "wlan0", runner=boom,
                                           which=lambda _n: "/usr/bin/tcpdump")
    assert insns is None and "failed" in why


def test_attach_kernel_filter_packs_sock_fprog():
    calls = []

    class FakeSock:
        def setsockopt(self, level, opt, value):
            calls.append((level, opt, value))

    bpf.attach_kernel_filter(FakeSock(), [(40, 0, 0, 12), (6, 0, 0, 262144)])
    assert len(calls) == 1
    _level, opt, fprog = calls[0]
    assert opt == bpf.SO_ATTACH_FILTER and isinstance(fprog, bytes)
    assert int.from_bytes(fprog[:2], "little") == 2  # sock_fprog.len


# --- Python-side expression evaluation ---------------------------------------
@pytest.mark.parametrize("expr,pkt,expected", [
    ("udp or tcp", info("udp"), True),
    ("udp or tcp", info("tcp"), True),
    ("udp or tcp", info("icmp"), False),
    ("udp port 5001", info("udp", dport=5001), True),
    ("udp port 5001", info("tcp", dport=5001), False),
    ("not tcp", info("udp"), True),
    ("not tcp", info("tcp"), False),
    ("(udp and port 3478) or tcp", info("udp", dport=3478), True),
    ("(udp and port 3478) or tcp", info("udp", dport=9), False),
    ("host 157.240.1.5", info(), True),
    ("src host 157.240.1.5", info(), False),
    ("dst port 5001 and udp", info(), True),
    ("net 157.240.0.0/16", info(), True),
    ("ip6", info(version=6, src="::1", dst="::2"), True),
    ("udp && !port 5000", info(sport=5000), False),
])
def test_python_filter_semantics(expr, pkt, expected):
    assert bpf.compile_python_filter(expr)(pkt) is expected


def test_empty_expression_means_no_filter():
    assert bpf.compile_python_filter("") is None
    assert bpf.compile_python_filter("   ") is None


def test_unsupported_expression_raises_but_fallback_builder_never_does():
    with pytest.raises(bpf.FilterError):
        bpf.compile_python_filter("ether proto 0x0800")
    assert bpf.build_fallback_filter("ether proto 0x0800") is None
    assert bpf.build_fallback_filter("udp or (tcp") is None  # unbalanced


# --- Sniffer: kernel BPF -> Python fallback ----------------------------------
class DummySock:
    pass


def test_sniffer_falls_back_when_tcpdump_missing(monkeypatch):
    monkeypatch.setattr("core.packet_sniffer.compile_kernel_filter",
                        lambda expr, iface: (None, "tcpdump not found"))
    s = PacketSniffer(bpf="udp or tcp")
    s._setup_filter(DummySock(), "wlan0")
    assert s.filter_mode == "python" and s._py_filter is not None


def test_sniffer_falls_back_when_attach_fails(monkeypatch):
    monkeypatch.setattr("core.packet_sniffer.compile_kernel_filter",
                        lambda expr, iface: ([(6, 0, 0, 262144)], ""))

    def refuse(_sock, _insns):
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr("core.packet_sniffer.attach_kernel_filter", refuse)
    s = PacketSniffer(bpf="udp")
    s._setup_filter(DummySock(), "wlan0")  # must not raise
    assert s.filter_mode == "python"


def test_sniffer_uses_kernel_filter_when_available(monkeypatch):
    attached = []
    monkeypatch.setattr("core.packet_sniffer.compile_kernel_filter",
                        lambda expr, iface: ([(6, 0, 0, 262144)], ""))
    monkeypatch.setattr("core.packet_sniffer.attach_kernel_filter",
                        lambda sock, insns: attached.append(insns))
    s = PacketSniffer(bpf="udp")
    s._setup_filter(DummySock(), "wlan0")
    assert s.filter_mode == "kernel" and s._py_filter is None and attached


def test_sniffer_unsupported_expression_does_not_crash(monkeypatch):
    monkeypatch.setattr("core.packet_sniffer.compile_kernel_filter",
                        lambda expr, iface: (None, "no tcpdump"))
    s = PacketSniffer(bpf="ether proto 0x0800")
    s._setup_filter(DummySock(), "wlan0")
    assert s.filter_mode == "none" and s._py_filter is None


def test_empty_bpf_skips_everything(monkeypatch):
    def must_not_run(*a, **k):
        raise AssertionError("tcpdump must not be invoked for an empty filter")

    monkeypatch.setattr("core.packet_sniffer.compile_kernel_filter", must_not_run)
    s = PacketSniffer(bpf="")
    s._setup_filter(DummySock(), "wlan0")
    assert s.filter_mode == "none"


def test_python_filter_applied_in_pipeline(tmp_path):
    from tests.frames import tcp4, udp4

    s = PacketSniffer(log_file=tmp_path / "f.pcap", bpf="udp")
    s._py_filter = bpf.compile_python_filter("udp")
    assert s.process_frame(udp4("10.0.0.2", "157.240.1.5", 5000, 5001), "raw", "out")
    assert not s.process_frame(tcp4("10.0.0.2", "157.240.1.5", 5000, 443), "raw", "out")
    assert s.frames_seen == 1
    s.save_packets()
