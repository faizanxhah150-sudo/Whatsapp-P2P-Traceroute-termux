#!/usr/bin/env python3
"""Preflight diagnostics. Prints PASS / WARN / FAIL lines; exit code 1 on any FAIL.

    python scripts/check_env.py [--iface wlan0] [--offline]
On Termux run it as root:  bash scripts/run_root.sh --check-env
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config  # noqa: E402
from utils import netif  # noqa: E402
from utils.platform_utils import (  # noqa: E402
    af_packet_supported,
    find_tcpdump,
    is_android,
    is_android_python_build,
    is_linux,
    is_root,
    is_termux,
    netif_available,
    platform_summary,
    root_help_message,
    setup_ca_bundle,
)

_results = {"PASS": 0, "WARN": 0, "FAIL": 0}


def report(level: str, message: str) -> None:
    _results[level] += 1
    print(f"[{level}] {message}")


def check_python() -> None:
    v = sys.version_info
    text = f"Python {v.major}.{v.minor}.{v.micro}"
    if v < (3, 10):
        report("FAIL", f"{text} - Python 3.10+ required (3.11+ recommended)")
    elif v < (3, 11):
        report("WARN", f"{text} - works, but 3.11+ is recommended")
    else:
        report("PASS", text)


def check_platform() -> None:
    info = platform_summary()
    report("PASS", f"sys.platform={info['sys.platform']!r}, platform.system()={info['platform.system()']!r}, "
                   f"Python {info['python']}")
    where = "Termux" if is_termux() else ("Android" if is_android() else info["sys.platform"])
    report("PASS", f"Platform: {where} (treated as Linux-like: {info['is_linux']})")
    if is_android_python_build():
        report("PASS", "Python 3.13+ on Android detected (sys.platform == 'android'); native backends are used, "
                       "Scapy is never imported implicitly")
    if is_android() and not is_termux():
        report("WARN", "Android detected but PREFIX/TERMUX_VERSION unset - launch via scripts/run_root.sh")


def check_root() -> None:
    if is_root():
        report("PASS", "Running as root/administrator")
    else:
        msg = root_help_message().replace("\n", " ")
        report("FAIL", f"Not root - capture will not work. {msg}")


def check_interfaces(requested: str) -> str | None:
    if not netif_available():
        report("WARN", "Interface info (/sys/class/net, /proc/net/dev) not readable here; "
                       "on Windows/macOS the Scapy backend resolves interfaces")
        return requested or None
    ifaces = netif.list_interfaces()
    if not ifaces:
        report("FAIL", "No interfaces readable from /sys/class/net or /proc/net/dev (try as root)")
        return None
    for i in ifaces:
        if i.skipped:
            continue
        report("PASS", f"iface {i.name}: state={i.operstate}, ipv4={i.ipv4 or '-'}, "
                       f"link type={i.link_type} ({i.link_kind}), packets={i.packets}, {i.category}")
    chosen, warnings = netif.choose_interface(ifaces, netif.default_route_ifaces())
    name = requested or (chosen.name if chosen else None)
    if name is None:
        report("FAIL", "No usable interface found (use --list-ifaces, then --iface NAME)")
        return None
    info = next((i for i in ifaces if i.name == name), None)
    if info is None:
        report("FAIL", f"Interface {name} does not exist (available: "
                       f"{', '.join(sorted(i.name for i in ifaces))})")
        return None
    report("PASS", f"Selected interface: {name}")
    if info.link_kind == netif.LINK_UNKNOWN:
        report("WARN", f"Unknown link type {info.link_type} on {name}; it will be detected per packet")
    elif info.link_kind == netif.LINK_RAW:
        report("PASS", "Raw-IP link: no Ethernet header; PCAP will use linktype 101")
    else:
        report("PASS", "Ethernet link: PCAP will use linktype 1")
    for w in warnings:
        report("WARN", w)
    return name


def check_packet_socket(iface: str | None) -> bool:
    if not af_packet_supported():
        report("WARN", "AF_PACKET backend not usable here (no AF_PACKET or no /sys/class/net)")
        return False
    sock = None
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        if iface:
            sock.bind((iface, 3))
        report("PASS", "AF_PACKET raw socket opens" + (f" and binds to {iface}" if iface else ""))
        return True
    except PermissionError as exc:
        report("FAIL", f"AF_PACKET socket denied ({exc}). Run through root: bash scripts/run_root.sh")
    except OSError as exc:
        report("FAIL", f"AF_PACKET socket error: {exc}")
    finally:
        if sock is not None:
            sock.close()
    return False


def check_backends(afpacket_ok: bool) -> list[str]:
    from core.packet_sniffer import select_backends

    chain = select_backends("auto")
    report("PASS", "Auto backend chain: " + " -> ".join(chain))
    usable = []
    report("PASS" if afpacket_ok else "WARN", f"backend afpacket: {'usable' if afpacket_ok else 'NOT usable'}")
    if afpacket_ok:
        usable.append("afpacket")
    exe = find_tcpdump()
    if exe:
        report("PASS", f"backend tcpdump: usable ({exe}); also used for kernel BPF filters")
        usable.append("tcpdump")
    else:
        report("WARN", "backend tcpdump: NOT usable - tcpdump not found (Termux: pkg install tcpdump)")
    if importlib.util.find_spec("scapy") is None:
        report("WARN", "backend scapy: scapy not installed (only needed on Windows/macOS)")
    elif is_linux() or is_android():
        report("PASS", "backend scapy: installed but never used automatically on Linux/Android "
                       "(force with --backend scapy; not supported on Android)")
    else:
        report("PASS", "backend scapy: installed (default on Windows/macOS)")
        usable.append("scapy")
    return usable


def check_python_deps() -> None:
    for module, level, hint in (
        ("scapy", "WARN", "pip install -r requirements.txt (needed on Windows/macOS; optional on Linux/Android)"),
        ("requests", "WARN", "pip install -r requirements.txt (needed for the RIPEstat refresh)"),
        ("maxminddb", "WARN", "pip install -r requirements.txt (needed for GeoLite2 lookups)"),
        ("dotenv", "WARN", "pip install -r requirements.txt (.env support)"),
        ("starlette", "WARN", "pip install -r requirements-dashboard.txt (dashboard only)"),
        ("uvicorn", "WARN", "pip install -r requirements-dashboard.txt (dashboard only)"),
        ("websockets", "WARN", "pip install -r requirements-dashboard.txt (dashboard only)"),
    ):
        try:
            if module == "scapy":  # never import it: on Android it prints a misleading CRITICAL
                if importlib.util.find_spec("scapy") is None:
                    raise ImportError("not installed")
            else:
                __import__(module)
            report("PASS", f"Python module '{module}' available")
        except Exception as exc:
            report(level, f"Python module '{module}' missing/broken ({exc.__class__.__name__}): {hint}")


def check_geoip() -> None:
    present = 0
    for label, path in (("City", config.GEO_CITY_DB), ("ASN", config.GEO_ASN_DB)):
        if Path(path).is_file():
            present += 1
            report("PASS", f"GeoLite2-{label} database: {path}")
        else:
            report("WARN", f"GeoLite2-{label} database missing: {path} (those columns stay blank; "
                           "capture still works - see docs/TERMUX.md)")
    if present == 2:
        from utils import geo_ip

        probe = geo_ip.get_geo_info("8.8.8.8")
        geo_ip.close()
        ok = bool(probe.get("country") or probe.get("asn"))
        report("PASS" if ok else "WARN",
               "GeoLite2 lookup test: " + ("ok" if ok else "no data (corrupt file or maxminddb missing?)"))


def check_dirs() -> None:
    for d in (config.OUTPUT_DIR, config.LOG_DIR, config.DATA_DIR):
        try:
            Path(d).mkdir(parents=True, exist_ok=True)
            probe = Path(d) / ".write_test"
            probe.write_text("x")
            probe.unlink()
            report("PASS", f"Writable: {d}")
        except OSError as exc:
            report("FAIL", f"Not writable: {d} ({exc})")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        st = os.stat(config.BASE_DIR)
        if st.st_uid != 0:
            report("PASS", f"Project owned by uid {st.st_uid}; output files will be chown'ed back to it")
        else:
            report("WARN", "Project dir is owned by root; files will stay root-owned")


def check_network() -> None:
    bundle = setup_ca_bundle()
    if bundle:
        report("PASS", f"CA bundle configured: {bundle}")
    url = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS32934"
    try:
        import requests

        resp = requests.get(url, timeout=(5, 10), headers={"User-Agent": "wit-check-env"})
        resp.raise_for_status()
        n = len(resp.json()["data"]["prefixes"])
        report("PASS", f"RIPEstat reachable ({n} prefixes for AS32934)")
    except Exception as exc:
        report("WARN", f"RIPEstat not reachable ({exc.__class__.__name__}: {exc}). The bundled seed "
                       "ranges are used instead; run with --no-refresh to skip the attempt.")


def main() -> int:
    ap = argparse.ArgumentParser(description="WhatsApp IP Tracker preflight checks")
    ap.add_argument("--iface", default=config.DEFAULT_IFACE, help="Interface to check (default: auto)")
    ap.add_argument("--offline", action="store_true", help="Skip internet / RIPEstat check")
    args = ap.parse_args()

    check_python()
    check_platform()
    check_root()
    iface = check_interfaces(args.iface)
    afpacket_ok = check_packet_socket(iface)
    usable = check_backends(afpacket_ok)
    check_python_deps()
    check_geoip()
    check_dirs()
    if not args.offline:
        check_network()

    print(f"\nSummary: {_results['PASS']} PASS, {_results['WARN']} WARN, {_results['FAIL']} FAIL")
    if _results["FAIL"]:
        verdict = "NOT READY - fix the FAIL lines above (most often: run through bash scripts/run_root.sh)"
    elif not usable:
        verdict = "NOT READY - no usable capture backend (pkg install tcpdump, or run as root for afpacket)"
    else:
        verdict = f"READY - capture backends: {', '.join(usable)}; interface: {iface}"
    print(f"Verdict: {verdict}")
    return 1 if _results["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
