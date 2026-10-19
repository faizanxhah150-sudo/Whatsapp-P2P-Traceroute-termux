"""WhatsApp IP Tracker - CLI entrypoint.

AUTHORIZED / EDUCATIONAL USE ONLY. Capture only traffic on networks you own or
have explicit permission to monitor. Using this to deanonymize or track a person
without consent may be illegal (privacy/anti-stalking laws).
"""
from __future__ import annotations

import argparse
import sys

import config
from core.dns_resolver import shutdown as shutdown_dns
from core.ip_filter import load_networks
from core.meta_ranges import refresh_ranges
from core.packet_sniffer import CaptureError, PacketSniffer
from core.reporting import write_rows
from utils import netif
from utils.geo_ip import close as close_geo
from utils.helpers import (
    acquire_wake_lock,
    ensure_dirs,
    finalize_outputs,
    is_termux,
    require_root,
    setup_ca_bundle,
    setup_logging,
)
from utils.platform_utils import is_android_platform, is_linux, netif_available, platform_summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="WhatsApp IP Tracker (authorized use only) - passive capture and analysis "
                    "of Meta/WhatsApp flows. Needs root (Termux: use scripts/run_root.sh)."
    )
    p.add_argument("--iface", default=config.DEFAULT_IFACE,
                   help="Interface to sniff, e.g. wlan0, ccmni1, ap0 (blank = auto; env WIT_IFACE)")
    p.add_argument("--list-ifaces", action="store_true",
                   help="List interfaces (state, link type, IPv4, packets) and exit")
    p.add_argument("--backend", choices=config.BACKENDS, default=config.DEFAULT_BACKEND,
                   help="Capture backend (default auto: afpacket, then tcpdump; env WIT_BACKEND). "
                        "scapy is for Windows/macOS only")
    p.add_argument("--count", type=int, default=config.DEFAULT_COUNT,
                   help="Packet count (0 = until Ctrl+C)")
    p.add_argument("--timeout", type=int, default=None, help="Stop after N seconds")
    p.add_argument("--no-refresh", action="store_true", help="Skip online Meta-range refresh")
    p.add_argument("--dashboard", action="store_true",
                   help="Launch live web dashboard instead of CLI")
    p.add_argument("--export-dir", default=config.EXPORT_DIR or None,
                   help="Also copy reports + pcap here, e.g. /sdcard/WhatsAppP2P "
                        "(env WIT_EXPORT_DIR)")
    p.add_argument("--no-wake-lock", action="store_true",
                   help="Do not call termux-wake-lock")
    p.add_argument("--version", action="version", version=f"whatsapp-ip-tracker {config.VERSION}")
    return p


def cmd_list_ifaces() -> int:
    info = platform_summary()
    print(f"Platform: sys.platform={info['sys.platform']} python={info['python']} "
          f"android={info['is_android_platform']} termux={info['is_termux']}")
    ifaces = netif.list_interfaces() if netif_available() else []
    if not ifaces:
        print("No interfaces found via /sys/class/net or /proc/net/dev "
              "(blocked or not Linux/Android - try again through root).")
        if not (is_linux() or is_android_platform()):  # Windows/macOS only; Scapy never on Android
            try:
                from scapy.all import get_if_list

                print("Scapy sees:", ", ".join(get_if_list()))
            except Exception:
                pass
        return 1
    print(netif.format_iface_table(ifaces))
    chosen, warnings = netif.choose_interface(ifaces, netif.default_route_ifaces())
    print()
    print(f"Auto-detect would use: {chosen.name}" if chosen else "Auto-detect found no usable interface.")
    for w in warnings:
        print(f"WARNING: {w}")
    print("Raw-IP links (cellular) have no Ethernet header; the tool handles both automatically.")
    return 0


def run_cli(args, log) -> int:
    ranges = config.WHATSAPP_IP_RANGES if args.no_refresh else refresh_ranges()
    load_networks(ranges)

    sniffer = PacketSniffer(backend=args.backend)
    code = 0
    try:
        sniffer.start_sniffing(iface=args.iface, count=args.count, timeout=args.timeout)
    except KeyboardInterrupt:
        log.info("Interrupted; saving captured data.")
    except PermissionError as exc:
        log.error("%s", exc)
        code = 1
    except CaptureError as exc:
        log.error("%s", exc)
        code = 1
    except OSError as exc:
        log.error("Capture failed: %s", exc)
        code = 1

    rows = sniffer.rows()
    if rows:
        write_rows(rows)
        peers = [r for r in rows if r["candidate_peer"]]
        log.info("Done. %d unique remotes, %d candidate peer(s).", len(rows), len(peers))
        for r in peers[:10]:
            log.info("  PEER? %s %s %s", r["remote"], r["org"], r["country"])
    else:
        log.info("No WhatsApp/Meta traffic captured.")

    close_geo()
    shutdown_dns()
    finalize_outputs(args.export_dir)
    return code


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    log = setup_logging()
    setup_ca_bundle()

    if args.list_ifaces:
        return cmd_list_ifaces()

    require_root(log)
    ensure_dirs()
    if is_termux() and not args.no_wake_lock:
        acquire_wake_lock()

    if args.dashboard:
        from dashboard.server import run

        return run(
            iface=args.iface,
            count=args.count,
            timeout=args.timeout,
            no_refresh=args.no_refresh,
            export_dir=args.export_dir,
            backend=args.backend,
        )
    return run_cli(args, log)


if __name__ == "__main__":
    sys.exit(main())
