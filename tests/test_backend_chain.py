"""Backend fallback chain, tcpdump pipe backend, explicit scapy on Android."""
import errno
import logging
import os
import subprocess
import sys
import threading
import time
import types

import pytest

from core import packet_sniffer as ps
from tests.frames import pcap_bytes, pcap_header, sll, udp4


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")  # root help mentions run_root.sh
    monkeypatch.setattr(ps, "pick_interface", lambda requested="": requested or "wlan0")
    monkeypatch.setattr(ps, "af_packet_supported", lambda: True)
    monkeypatch.setattr(ps.netif, "link_kind_for", lambda name: "raw")
    monkeypatch.setattr(ps.netif, "local_addresses", lambda name: set())


def sniffer(tmp_path, backend="auto"):
    return ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="", backend=backend)


def deny_socket(monkeypatch, exc):
    def raiser(*a, **k):
        raise exc

    monkeypatch.setattr(ps.socket, "socket", raiser)


class RecordTcpdump:
    def __init__(self):
        self.calls = []

    def __call__(self, iface, count, timeout):
        self.calls.append(iface)


def test_eperm_never_falls_back_and_shows_root_help(env, monkeypatch, tmp_path):
    deny_socket(monkeypatch, PermissionError(errno.EPERM, "Operation not permitted"))
    s = sniffer(tmp_path)
    tcpdump = RecordTcpdump()
    monkeypatch.setattr(s, "_sniff_tcpdump", tcpdump)
    with pytest.raises(ps.CapturePermissionError) as exc:
        s.start_sniffing(iface="wlan0")
    assert tcpdump.calls == []
    assert "scripts/run_root.sh" in str(exc.value) and "Magisk" in str(exc.value)
    assert s.backend == "afpacket"


def test_eacces_oserror_is_also_a_permission_error(env, monkeypatch, tmp_path):
    deny_socket(monkeypatch, OSError(errno.EACCES, "Permission denied"))
    s = sniffer(tmp_path)
    monkeypatch.setattr(s, "_sniff_tcpdump", RecordTcpdump())
    with pytest.raises(ps.CapturePermissionError):
        s.start_sniffing(iface="wlan0")


def test_enodev_falls_back_to_tcpdump(env, monkeypatch, tmp_path):
    class Sock:
        def setsockopt(self, *a):
            pass

        def bind(self, _a):
            raise OSError(errno.ENODEV, "No such device")

        def close(self):
            pass

    monkeypatch.setattr(ps.socket, "socket", lambda *a, **k: Sock())
    s = sniffer(tmp_path)
    tcpdump = RecordTcpdump()
    monkeypatch.setattr(s, "_sniff_tcpdump", tcpdump)
    s.start_sniffing(iface="wlan0")
    assert tcpdump.calls == ["wlan0"] and s.backend == "tcpdump"


def test_other_socket_errors_fall_back_to_tcpdump(env, monkeypatch, tmp_path):
    deny_socket(monkeypatch, OSError(errno.EAFNOSUPPORT, "Address family not supported"))
    s = sniffer(tmp_path)
    tcpdump = RecordTcpdump()
    monkeypatch.setattr(s, "_sniff_tcpdump", tcpdump)
    s.start_sniffing(iface="wlan0")
    assert tcpdump.calls == ["wlan0"]


def test_afpacket_fails_and_tcpdump_missing_gives_one_clear_error(env, monkeypatch, tmp_path):
    deny_socket(monkeypatch, OSError(errno.EAFNOSUPPORT, "Address family not supported"))
    monkeypatch.setattr(ps, "find_tcpdump", lambda: None)
    with pytest.raises(ps.CaptureError) as exc:
        sniffer(tmp_path).start_sniffing(iface="wlan0")
    msg = str(exc.value)
    assert "afpacket:" in msg and "tcpdump:" in msg and "pkg install tcpdump" in msg


def test_explicit_tcpdump_missing(env, monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "find_tcpdump", lambda: None)
    with pytest.raises(ps.CaptureError, match="tcpdump not found") as exc:
        sniffer(tmp_path, "tcpdump").start_sniffing(iface="wlan0")
    assert "All capture backends failed" not in str(exc.value)


def test_explicit_afpacket_does_not_fall_back(env, monkeypatch, tmp_path):
    deny_socket(monkeypatch, OSError(errno.EAFNOSUPPORT, "nope"))
    s = sniffer(tmp_path, "afpacket")
    tcpdump = RecordTcpdump()
    monkeypatch.setattr(s, "_sniff_tcpdump", tcpdump)
    with pytest.raises(ps.CaptureError):
        s.start_sniffing(iface="wlan0")
    assert tcpdump.calls == []


def test_no_fallback_after_frames_were_captured(env, monkeypatch, tmp_path):
    s = sniffer(tmp_path)

    def dies_midway(iface, count, timeout):
        s.process_frame(udp4("10.1.2.3", "157.240.1.5", 1, 2), "raw", "out")
        raise ps.CaptureError("interface vanished")

    tcpdump = RecordTcpdump()
    monkeypatch.setattr(s, "_sniff_af_packet", dies_midway)
    monkeypatch.setattr(s, "_sniff_tcpdump", tcpdump)
    with pytest.raises(ps.CaptureError, match="vanished"):
        s.start_sniffing(iface="wlan0")
    assert tcpdump.calls == []


def test_no_afpacket_support_goes_straight_to_tcpdump(env, monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "af_packet_supported", lambda: False)
    s = sniffer(tmp_path)
    tcpdump = RecordTcpdump()
    monkeypatch.setattr(s, "_sniff_tcpdump", tcpdump)
    s.start_sniffing(iface="wlan0")
    assert tcpdump.calls == ["wlan0"]


def test_backend_and_interface_are_logged_at_info(env, monkeypatch, tmp_path):
    records = []

    class H(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("wit")
    old_level = logger.level
    handler = H()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        s = sniffer(tmp_path, "tcpdump")
        monkeypatch.setattr(s, "_sniff_tcpdump", RecordTcpdump())
        s.start_sniffing(iface="ap0")
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
    line = next(r.getMessage() for r in records if "Capture backend" in r.getMessage())
    assert "tcpdump" in line and "ap0" in line and records[0].levelno == logging.INFO


# --- explicit scapy on Android --------------------------------------------------------------
def fake_scapy(monkeypatch, sniff):
    conf = types.SimpleNamespace(use_pcap=True)

    def forbidden(*a, **k):
        raise AssertionError("get_if_list()/resolve_iface() must never be called")

    mod = types.SimpleNamespace(Ether=type("Ether", (), {}), conf=conf, sniff=sniff,
                                get_if_list=forbidden, resolve_iface=forbidden,
                                get_working_ifaces=forbidden)
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.all", mod)
    return conf


def test_explicit_scapy_on_android_fails_with_actionable_message(env, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "android")
    seen = {}

    def sniff(**kwargs):
        seen.update(kwargs)
        raise RuntimeError("Interface not found")

    conf = fake_scapy(monkeypatch, sniff)
    with pytest.raises(ps.CaptureError) as exc:
        sniffer(tmp_path, "scapy").start_sniffing(iface="wlan0")
    msg = str(exc.value)
    assert "--backend afpacket" in msg and "--backend tcpdump" in msg and "Android" in msg
    assert seen["iface"] == "wlan0"       # plain string, nothing resolved by us
    assert conf.use_pcap is False


def test_explicit_scapy_missing_on_android_is_actionable(env, monkeypatch, tmp_path):
    import builtins

    monkeypatch.setattr(sys, "platform", "android")
    real_import = builtins.__import__

    def no_scapy(name, *a, **k):
        if name.startswith("scapy"):
            raise ImportError("No module named 'scapy'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_scapy)
    with pytest.raises(ps.CaptureError, match="--backend afpacket"):
        sniffer(tmp_path, "scapy").start_sniffing(iface="wlan0")


# --- tcpdump pipe backend -------------------------------------------------------------------
class FakeProc:
    """Behaves like Popen(stdout=PIPE, stderr=PIPE) using real OS pipes."""

    def __init__(self, stdout=b"", stderr=b"", rc=0, hang=False, stubborn=False, chunk=0, delay=0.0):
        r, w = os.pipe()
        er, ew = os.pipe()
        self.stdout = os.fdopen(r, "rb", buffering=0)
        self.stderr = os.fdopen(er, "rb", buffering=0)
        self._w, self._ew = w, ew
        self._lock = threading.Lock()
        self._closed = False
        self.rc = rc
        self.returncode = None
        self.terminated = self.killed = False
        self.stubborn = stubborn
        threading.Thread(target=self._feed, args=(stdout, stderr, hang, chunk, delay), daemon=True).start()

    def _close_pipes(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        for fd in (self._w, self._ew):
            try:
                os.close(fd)
            except OSError:
                pass

    def _feed(self, stdout, stderr, hang, chunk, delay):
        try:
            if stderr:
                os.write(self._ew, stderr)
            step = chunk or max(len(stdout), 1)
            for i in range(0, len(stdout), step):
                os.write(self._w, stdout[i:i + step])
                if delay:
                    time.sleep(delay)
        except OSError:
            return
        if not hang:
            self.returncode = self.rc  # the process "exited" before closing its pipes
            self._close_pipes()

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self._close_pipes()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self._close_pipes()

    def wait(self, timeout=None):
        if self.stubborn and not self.killed:
            raise subprocess.TimeoutExpired("tcpdump", timeout)
        if self.returncode is None:
            self.returncode = -15 if self.terminated else self.rc
        return self.returncode


@pytest.fixture
def tcpdump(env, monkeypatch):
    calls = []
    holder = {}

    def popen(cmd, **kwargs):
        calls.append(cmd)
        return holder["proc"]

    monkeypatch.setattr(ps, "find_tcpdump", lambda: "/usr/bin/tcpdump")
    monkeypatch.setattr(ps.subprocess, "Popen", popen)
    return calls, holder


META = udp4("10.1.2.3", "157.240.1.5", 40000, 40001)
PEER = udp4("10.1.2.3", "45.55.100.10", 40000, 50002)


def test_stream_frames_reach_process_frame_and_command_is_correct(tcpdump, tmp_path):
    calls, holder = tcpdump
    holder["proc"] = FakeProc(pcap_bytes([META, PEER], linktype=101))
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="udp or tcp")
    s._sniff_tcpdump("wlan0", 0, 5)
    assert calls == [["/usr/bin/tcpdump", "-i", "wlan0", "-n", "-U", "-s", "0", "-w", "-", "udp or tcp"]]
    assert s.frames_seen == 2 and s.filter_mode == "tcpdump"
    assert {r["remote"] for r in s.rows()} == {"157.240.1.5", "45.55.100.10"}
    s.save_packets()
    assert (tmp_path / "t.pcap").read_bytes()[20:24] == (101).to_bytes(4, "little")


def test_no_bpf_means_no_filter_argument(tcpdump, tmp_path):
    calls, holder = tcpdump
    holder["proc"] = FakeProc(pcap_bytes([META], linktype=101))
    ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")._sniff_tcpdump("wlan0", 0, 5)
    assert calls[0][-2:] == ["-w", "-"]


def test_partial_reads(tcpdump, tmp_path):
    _, holder = tcpdump
    holder["proc"] = FakeProc(pcap_bytes([META, PEER, META], linktype=101), chunk=7, delay=0.001)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    s._sniff_tcpdump("wlan0", 0, 10)
    assert s.frames_seen == 3


def test_ethernet_and_cooked_streams(tcpdump, tmp_path):
    from tests.frames import ether

    _, holder = tcpdump
    holder["proc"] = FakeProc(pcap_bytes([ether(META)], linktype=1))
    s = ps.PacketSniffer(log_file=tmp_path / "e.pcap", bpf="")
    s._sniff_tcpdump("wlan0", 0, 5)
    assert s.frames_seen == 1

    # SLL carries direction: both addresses are public, "out" => remote is the destination.
    both_public = udp4("45.55.0.1", "46.55.0.2", 40000, 50002)
    holder["proc"] = FakeProc(pcap_bytes([sll(4, both_public)], linktype=113))
    s2 = ps.PacketSniffer(log_file=tmp_path / "s.pcap", bpf="")
    s2._sniff_tcpdump("any", 0, 5)
    assert s2.rows()[0]["remote"] == "46.55.0.2"


def test_large_packet_through_the_pipe(tcpdump, tmp_path):
    _, holder = tcpdump
    big = udp4("10.1.2.3", "157.240.1.5", 1, 2)[:20] + b"\x00" * 60000
    import struct

    big = big[:2] + struct.pack("!H", len(big)) + big[4:]  # fix IPv4 total length
    holder["proc"] = FakeProc(pcap_bytes([big], linktype=101))
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    s._sniff_tcpdump("wlan0", 0, 5)
    assert s.frames_seen == 1


def test_truncated_stream_is_not_fatal(tcpdump, tmp_path):
    _, holder = tcpdump
    stream = pcap_bytes([META, PEER], linktype=101)
    holder["proc"] = FakeProc(stream[:-12])
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    s._sniff_tcpdump("wlan0", 0, 5)
    assert s.frames_seen == 1


def test_count_terminates_process(tcpdump, tmp_path):
    _, holder = tcpdump
    proc = holder["proc"] = FakeProc(pcap_bytes([META, PEER, META], linktype=101), hang=True)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    s._sniff_tcpdump("wlan0", 2, 10)
    assert s.frames_seen == 2 and proc.terminated


def test_stop_terminates_cleanly(tcpdump, tmp_path):
    _, holder = tcpdump
    proc = holder["proc"] = FakeProc(pcap_header(linktype=101), hang=True)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    t = threading.Thread(target=lambda: s._sniff_tcpdump("wlan0", 0, None))
    t.start()
    time.sleep(0.3)
    s.stop()
    t.join(5)
    assert not t.is_alive() and proc.terminated and not proc.killed


def test_stubborn_process_is_killed(tcpdump, tmp_path):
    _, holder = tcpdump
    proc = holder["proc"] = FakeProc(b"", hang=True, stubborn=True)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    s._sniff_tcpdump("wlan0", 0, 0.6)
    assert proc.terminated and proc.killed


def test_timeout_ends_capture(tcpdump, tmp_path):
    _, holder = tcpdump
    holder["proc"] = FakeProc(b"", hang=True)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    t0 = time.monotonic()
    s._sniff_tcpdump("wlan0", 0, 1)
    assert 0.9 <= time.monotonic() - t0 < 4


def test_early_exit_surfaces_stderr(tcpdump, tmp_path):
    _, holder = tcpdump
    holder["proc"] = FakeProc(b"", stderr=b"tcpdump: wlan0: No such device exists\n", rc=1)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    with pytest.raises(ps.CaptureError, match="No such device exists") as exc:
        s._sniff_tcpdump("wlan0", 0, 5)
    assert "exited early" in str(exc.value) and not isinstance(exc.value, PermissionError)


def test_tcpdump_permission_error_is_not_a_generic_failure(tcpdump, tmp_path):
    _, holder = tcpdump
    holder["proc"] = FakeProc(
        b"", stderr=b"tcpdump: wlan0: You don't have permission to perform this capture on that device\n", rc=1)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    with pytest.raises(ps.CapturePermissionError):
        s._sniff_tcpdump("wlan0", 0, 5)


def test_garbage_stream_is_reported(tcpdump, tmp_path):
    _, holder = tcpdump
    holder["proc"] = FakeProc(b"this is not a pcap file at all, sorry!")
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    with pytest.raises(ps.CaptureError, match="unreadable pcap stream"):
        s._sniff_tcpdump("wlan0", 0, 5)


def test_popen_failures(env, monkeypatch, tmp_path):
    monkeypatch.setattr(ps, "find_tcpdump", lambda: "/usr/bin/tcpdump")

    def eperm(cmd, **kw):
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(ps.subprocess, "Popen", eperm)
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="")
    with pytest.raises(ps.CapturePermissionError):
        s._sniff_tcpdump("wlan0", 0, 1)

    def enoent(cmd, **kw):
        raise FileNotFoundError(errno.ENOENT, "gone")

    monkeypatch.setattr(ps.subprocess, "Popen", enoent)
    with pytest.raises(ps.CaptureError, match="Cannot start tcpdump"):
        s._sniff_tcpdump("wlan0", 0, 1)


def test_full_chain_enodev_then_working_tcpdump(env, tcpdump, monkeypatch, tmp_path):
    calls, holder = tcpdump
    holder["proc"] = FakeProc(pcap_bytes([META, PEER], linktype=101))

    class Sock:
        def setsockopt(self, *a):
            pass

        def bind(self, _a):
            raise OSError(errno.ENODEV, "No such device")

        def close(self):
            pass

    monkeypatch.setattr(ps.socket, "socket", lambda *a, **k: Sock())
    s = ps.PacketSniffer(log_file=tmp_path / "t.pcap", bpf="udp", backend="auto")
    s.start_sniffing(iface="wlan0", timeout=5)
    assert s.backend == "tcpdump" and s.frames_seen == 2 and len(calls) == 1
    assert (tmp_path / "t.pcap").exists()
