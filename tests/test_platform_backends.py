"""sys.platform == 'android' (Python 3.13+) must behave like Linux; Scapy is never implicit there."""
import builtins
import importlib
import sys
import types

import pytest

import config
import main
from core import packet_sniffer as ps
from tests.frames import udp4
from utils import platform_utils as pu

PLATFORMS = ("linux", "android", "win32", "darwin")


@pytest.fixture
def clean_env(monkeypatch):
    for name in ("PREFIX", "TERMUX_VERSION", "ANDROID_ROOT", "ANDROID_DATA"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("plat,expected", [("linux", True), ("android", True), ("win32", False), ("darwin", False)])
def test_is_linux(monkeypatch, plat, expected):
    monkeypatch.setattr(sys, "platform", plat)
    assert pu.is_linux() is expected


@pytest.mark.parametrize("plat", PLATFORMS)
def test_is_android_platform(monkeypatch, plat):
    monkeypatch.setattr(sys, "platform", plat)
    assert pu.is_android_platform({}) is (plat == "android")
    assert pu.is_android_platform({"PREFIX": "/data/data/com.termux/files/usr"}) is True
    assert pu.is_android_platform({"ANDROID_ROOT": "/system"}) is True


@pytest.mark.parametrize("plat", PLATFORMS)
def test_af_packet_support_is_a_capability_not_an_os_name(monkeypatch, tmp_path, plat):
    monkeypatch.setattr(sys, "platform", plat)
    sys_net = tmp_path / "net"
    sys_net.mkdir()
    monkeypatch.setattr(pu, "SYS_CLASS_NET", str(sys_net))
    monkeypatch.setattr(pu, "PROC_NET_DEV_PATH", str(tmp_path / "missing"))
    assert pu.af_packet_supported() is True            # same answer on every platform string

    monkeypatch.setattr(pu, "SYS_CLASS_NET", str(tmp_path / "gone"))
    assert pu.af_packet_supported() is False           # no kernel interface info

    proc_dev = tmp_path / "dev"
    proc_dev.write_text("x")
    monkeypatch.setattr(pu, "PROC_NET_DEV_PATH", str(proc_dev))
    assert pu.af_packet_supported() is True            # /proc/net/dev readable is enough

    monkeypatch.setattr(pu, "socket", types.SimpleNamespace())  # module without AF_PACKET
    assert pu.af_packet_supported() is False


def test_find_tcpdump_checks_termux_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(pu.shutil, "which", lambda _n: None)
    monkeypatch.setenv("PREFIX", str(tmp_path))
    assert pu.find_tcpdump() is None
    (tmp_path / "bin").mkdir()
    exe = tmp_path / "bin" / "tcpdump"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    assert pu.find_tcpdump() == str(exe)
    monkeypatch.setattr(pu.shutil, "which", lambda _n: "/usr/sbin/tcpdump")
    assert pu.find_tcpdump() == "/usr/sbin/tcpdump"


@pytest.mark.parametrize("plat,afp,expected", [
    ("linux", True, ["afpacket", "tcpdump"]),
    ("android", True, ["afpacket", "tcpdump"]),
    ("android", False, ["tcpdump"]),
    ("win32", True, ["scapy"]),
    ("darwin", False, ["scapy"]),
])
def test_backend_selection_per_platform(monkeypatch, clean_env, plat, afp, expected):
    monkeypatch.setattr(sys, "platform", plat)
    monkeypatch.setattr(ps, "af_packet_supported", lambda: afp)
    assert ps.select_backends("auto") == expected
    assert ps.select_backends("") == expected


@pytest.mark.parametrize("plat", PLATFORMS)
def test_explicit_backend_is_honoured_and_validated(monkeypatch, clean_env, plat):
    monkeypatch.setattr(sys, "platform", plat)
    for name in ("afpacket", "tcpdump", "scapy"):
        assert ps.select_backends(name) == [name]
    assert ps.select_backends("TCPDUMP") == ["tcpdump"]
    with pytest.raises(ps.CaptureError, match="Unknown backend"):
        ps.select_backends("pcap")


def test_backend_env_var_validated(monkeypatch):
    try:
        monkeypatch.setenv("WIT_BACKEND", "TcpDump")
        importlib.reload(config)
        assert config.DEFAULT_BACKEND == "tcpdump"
        monkeypatch.setenv("WIT_BACKEND", "bogus")
        importlib.reload(config)
        assert config.DEFAULT_BACKEND == "auto"
    finally:
        monkeypatch.delenv("WIT_BACKEND")
        importlib.reload(config)
    assert main.build_parser().parse_args(["--backend", "tcpdump"]).backend == "tcpdump"


def _forbid_scapy(monkeypatch):
    real_import = builtins.__import__

    def guard(name, *args, **kwargs):
        if name == "scapy" or name.startswith("scapy."):
            raise AssertionError(f"scapy was imported implicitly: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guard)


def _fake_iface_env(monkeypatch):
    items = [ps.netif.IfaceInfo("wlan0", "up", 1, "ethernet", "192.168.1.5", 10, 10, "wifi")]
    monkeypatch.setattr(ps, "netif_available", lambda: True)
    monkeypatch.setattr(ps.netif, "list_interfaces", lambda: items)
    monkeypatch.setattr(ps.netif, "default_route_ifaces", lambda: [])
    monkeypatch.setattr(ps.netif, "link_kind_for", lambda name: "ethernet")
    monkeypatch.setattr(ps.netif, "local_addresses", lambda name: set())


def test_scapy_is_never_imported_implicitly_on_android(monkeypatch, tmp_path, clean_env):
    from tests.frames import ether

    monkeypatch.setattr(sys, "platform", "android")
    _forbid_scapy(monkeypatch)
    _fake_iface_env(monkeypatch)
    monkeypatch.setattr(ps, "af_packet_supported", lambda: True)

    assert ps.select_backends("auto") == ["afpacket", "tcpdump"]
    assert ps.pick_interface("") == "wlan0"                 # /sys based, not Scapy
    assert main.cmd_list_ifaces() == 0                      # --list-ifaces without Scapy

    class Sock:
        closed = False

        def __init__(self):
            self.frames = [(ether(udp4("192.168.1.5", "157.240.1.5", 1, 2)),
                            ("wlan0", 0x0800, 4, 1, b""))]

        def recvfrom(self, _n):
            if self.frames:
                return self.frames.pop(0)
            raise ps.socket.timeout()

        def close(self):
            Sock.closed = True

    s = ps.PacketSniffer(log_file=tmp_path / "a.pcap", bpf="", backend="auto")
    monkeypatch.setattr(s, "_open_socket", lambda iface: Sock())
    s.start_sniffing(count=1)
    assert s.backend == "afpacket" and s.frames_seen == 1 and Sock.closed


def test_android_without_sysfs_gives_actionable_error_not_scapy(monkeypatch, clean_env):
    monkeypatch.setattr(sys, "platform", "android")
    _forbid_scapy(monkeypatch)
    monkeypatch.setattr(ps, "netif_available", lambda: False)
    with pytest.raises(ps.CaptureError, match="--iface"):
        ps.pick_interface("")
    assert ps.pick_interface("wlan0") == "wlan0"  # explicit names are accepted as plain strings


def test_android_list_ifaces_without_sysfs_does_not_touch_scapy(monkeypatch, clean_env):
    monkeypatch.setattr(sys, "platform", "android")
    _forbid_scapy(monkeypatch)
    monkeypatch.setattr(main, "netif_available", lambda: False)
    assert main.cmd_list_ifaces() == 1


@pytest.mark.parametrize("plat", ["win32", "darwin"])
def test_desktop_platforms_use_scapy_for_autodetect(monkeypatch, clean_env, plat):
    monkeypatch.setattr(sys, "platform", plat)
    monkeypatch.setattr(ps, "netif_available", lambda: False)
    fake_all = types.SimpleNamespace(get_working_ifaces=lambda: [types.SimpleNamespace(name="en0")])
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.all", fake_all)
    assert ps.pick_interface("") == "en0"
