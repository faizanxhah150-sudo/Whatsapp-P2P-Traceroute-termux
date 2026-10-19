"""Network interface discovery for Linux / Android without netlink or ``ip``.

Android 11+ blocks netlink for apps and the ``ip`` tool is often missing, so
everything here is read from ``/sys/class/net``, ``/proc/net/{dev,route,
if_inet6}`` and a single SIOCGIFADDR ioctl. Every function takes optional path
overrides so it can be unit-tested against a fake tree in ``tmp_path``.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

log = logging.getLogger("wit")

SYS_NET = Path("/sys/class/net")
PROC_NET_DEV = Path("/proc/net/dev")
PROC_NET_ROUTE = Path("/proc/net/route")
PROC_NET_IF_INET6 = Path("/proc/net/if_inet6")

# ARPHRD_* values from <linux/if_arp.h>
ARPHRD_ETHER = 1
ARPHRD_PPP = 512
ARPHRD_RAWIP = 519
ARPHRD_LOOPBACK = 772
ARPHRD_NONE = 0xFFFE

# Interfaces whose frames start directly with the IP header (no Ethernet header).
RAW_IP_TYPES = frozenset({ARPHRD_PPP, ARPHRD_RAWIP, ARPHRD_NONE})

LINK_ETHERNET = "ethernet"
LINK_RAW = "raw"
LINK_UNKNOWN = "unknown"

SKIP_PREFIXES = (
    "dummy", "sit", "ip6tnl", "p2p", "bond", "docker", "veth", "virbr", "br-",
    "tunl", "gre", "ip6gre", "ifb", "teql", "nlmon", "ip_vti", "ip6_vti", "erspan",
)
VPN_PREFIXES = ("tun", "wg", "ppp", "tap")
CELLULAR_PREFIXES = ("ccmni", "rmnet", "wwan")
HOTSPOT_PREFIXES = ("ap", "swlan", "softap")
ETHERNET_PREFIXES = ("eth", "en")

CAT_WIFI = "wifi"
CAT_CELLULAR = "cellular"
CAT_VPN = "vpn"
CAT_HOTSPOT = "hotspot"
CAT_ETHERNET = "ethernet"
CAT_OTHER = "other"
CAT_SKIP = "skip"

_ACTIVE_STATES = ("up", "unknown")
_SIOCGIFADDR = 0x8915


@dataclass
class IfaceInfo:
    name: str
    operstate: str
    link_type: int | None
    link_kind: str
    ipv4: str | None
    rx_packets: int
    tx_packets: int
    category: str

    @property
    def packets(self) -> int:
        return self.rx_packets + self.tx_packets

    @property
    def skipped(self) -> bool:
        return self.category == CAT_SKIP

    @property
    def usable(self) -> bool:
        """Up (or 'unknown', typical for cellular) and showing signs of life."""
        return (
            not self.skipped
            and self.operstate in _ACTIVE_STATES
            and bool(self.ipv4 or self.packets > 0)
        )


# --- Link type -------------------------------------------------------------
def link_kind_from_type(link_type: int | None) -> str:
    if link_type is None:
        return LINK_UNKNOWN
    if link_type in (ARPHRD_ETHER, ARPHRD_LOOPBACK):
        return LINK_ETHERNET
    if link_type in RAW_IP_TYPES:
        return LINK_RAW
    return LINK_UNKNOWN


def categorize(name: str) -> str:
    n = name.lower()
    if n == "lo" or n.startswith(SKIP_PREFIXES):
        return CAT_SKIP
    if n.startswith(VPN_PREFIXES):
        return CAT_VPN
    if n == "wlan0" or n.startswith("wlp"):
        return CAT_WIFI
    if re.fullmatch(r"wlan[1-9]\d*", n) or n.startswith(HOTSPOT_PREFIXES):
        return CAT_HOTSPOT
    if n.startswith(CELLULAR_PREFIXES):
        return CAT_CELLULAR
    if n.startswith(ETHERNET_PREFIXES):
        return CAT_ETHERNET
    return CAT_OTHER


# --- Readers ---------------------------------------------------------------
def _read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except (OSError, ValueError):
        return None


def read_link_type(name: str, sys_net: Path | None = None) -> int | None:
    base = Path(sys_net) if sys_net is not None else SYS_NET
    raw = _read_text(base / name / "type")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def link_kind_for(name: str, sys_net: Path | None = None) -> str:
    return link_kind_from_type(read_link_type(name, sys_net))


def parse_proc_net_dev(path: Path | None = None) -> dict[str, tuple[int, int]]:
    """Return ``{iface: (rx_packets, tx_packets)}`` from /proc/net/dev."""
    text = _read_text(Path(path) if path is not None else PROC_NET_DEV)
    result: dict[str, tuple[int, int]] = {}
    if not text:
        return result
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        fields = rest.split()
        if len(fields) < 10:
            continue
        try:
            result[name.strip()] = (int(fields[1]), int(fields[9]))
        except ValueError:
            continue
    return result


def default_route_ifaces(path: Path | None = None) -> list[str]:
    """Interfaces owning a default route in the main table, lowest metric first.

    Android uses per-network policy tables, so this is often empty; callers
    must treat it as a hint only.
    """
    text = _read_text(Path(path) if path is not None else PROC_NET_ROUTE)
    routes: list[tuple[int, str]] = []
    if not text:
        return []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        try:
            flags = int(f[3], 16)
            metric = int(f[6])
        except ValueError:
            continue
        if f[1] == "00000000" and f[7] == "00000000" and flags & 0x1:
            routes.append((metric, f[0]))
    return [name for _, name in sorted(routes)]


def ioctl_ipv4(name: str) -> str | None:
    """IPv4 address via SIOCGIFADDR (works without netlink); None on failure."""
    try:
        import fcntl
    except ImportError:
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = struct.pack("256s", name.encode()[:15])
        res = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, packed)
        return socket.inet_ntoa(res[20:24])
    except (OSError, UnicodeError):
        return None
    finally:
        if sock is not None:
            sock.close()


def ipv6_addresses(name: str, path: Path | None = None) -> list[str]:
    """IPv6 addresses of ``name`` from /proc/net/if_inet6."""
    text = _read_text(Path(path) if path is not None else PROC_NET_IF_INET6)
    out: list[str] = []
    if not text:
        return out
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[5] != name:
            continue
        try:
            out.append(str(ipaddress.IPv6Address(int(f[0], 16))))
        except ValueError:
            continue
    return out


def local_addresses(name: str, ipv4_lookup: Callable[[str], str | None] | None = None,
                    inet6_path: Path | None = None) -> set[str]:
    """All addresses the phone itself uses on ``name`` (IPv4 + IPv6)."""
    lookup = ioctl_ipv4 if ipv4_lookup is None else ipv4_lookup
    addrs: set[str] = set()
    try:
        v4 = lookup(name)
    except Exception:  # never let address lookup break capture
        v4 = None
    if v4:
        addrs.add(v4)
    try:
        addrs.update(ipv6_addresses(name, inet6_path))
    except Exception:
        pass
    return addrs


# --- Enumeration / selection -----------------------------------------------
def list_interfaces(sys_net: Path | None = None, proc_net_dev: Path | None = None,
                    ipv4_lookup: Callable[[str], str | None] | None = None) -> list[IfaceInfo]:
    base = Path(sys_net) if sys_net is not None else SYS_NET
    lookup = ioctl_ipv4 if ipv4_lookup is None else ipv4_lookup
    counters = parse_proc_net_dev(proc_net_dev)

    names: set[str] = set(counters)
    try:
        names.update(p.name for p in base.iterdir())
    except OSError:  # ENOENT / EACCES: some Android ROMs hide /sys/class/net
        pass

    result: list[IfaceInfo] = []
    for name in sorted(names):
        rx, tx = counters.get(name, (0, 0))
        try:
            link_type = read_link_type(name, base)
            try:
                ipv4 = lookup(name)
            except Exception:
                ipv4 = None
            operstate = (_read_text(base / name / "operstate") or "unknown").lower()
        except Exception as exc:  # one broken entry must never hide the others
            log.debug("Skipping unreadable attributes of %s: %s", name, exc)
            link_type, ipv4, operstate = None, None, "unknown"
        result.append(
            IfaceInfo(
                name=name,
                operstate=operstate,
                link_type=link_type,
                link_kind=link_kind_from_type(link_type),
                ipv4=ipv4,
                rx_packets=rx,
                tx_packets=tx,
                category=categorize(name),
            )
        )
    return result


def choose_interface(ifaces: Iterable[IfaceInfo],
                     default_routes: Iterable[str] = ()) -> tuple[IfaceInfo | None, list[str]]:
    """Pick the capture interface. Returns ``(iface_or_None, warnings)``.

    Order: default-route interface -> wlan0 -> hotspot (ap0/swlan0/wlan1...) that has
    traffic -> cellular (ccmni*/rmnet*) -> other usable (Wi-Fi, ethernet, ...).
    VPN (tun*/wg*) is never auto-selected, only warned about.
    """
    items = list(ifaces)
    routes = list(default_routes)
    warnings: list[str] = []

    def rank(i: IfaceInfo):
        in_route = routes.index(i.name) if i.name in routes else len(routes)
        return (in_route, -i.packets)

    def best(pool: list[IfaceInfo]) -> IfaceInfo | None:
        return sorted(pool, key=rank)[0] if pool else None

    chosen: IfaceInfo | None = None
    for name in routes:  # 1. interface that owns the default route
        chosen = next((i for i in items if i.name == name and i.usable
                       and i.category not in (CAT_VPN, CAT_SKIP)), None)
        if chosen:
            break
    if chosen is None:  # 2. wlan0
        chosen = next((i for i in items if i.name == "wlan0" and i.usable), None)
    if chosen is None:  # 3. hotspot interfaces, only if they carry traffic
        chosen = best([i for i in items if i.category == CAT_HOTSPOT and i.usable and i.packets > 0])
    if chosen is None:  # 4. cellular, then everything else usable
        for category in (CAT_CELLULAR, CAT_WIFI, CAT_ETHERNET, CAT_OTHER):
            chosen = best([i for i in items if i.category == category and i.usable])
            if chosen:
                break

    vpns = [i for i in items if i.category == CAT_VPN and i.usable]
    if vpns:
        names = ", ".join(i.name for i in vpns)
        warnings.append(
            f"VPN interface detected ({names}). On the physical interface you only see "
            "encrypted tunnel traffic; capture on the tunnel interface (e.g. --iface "
            f"{vpns[0].name}) to see the inner packets, or disable the VPN."
        )
    return chosen, warnings


def format_iface_table(ifaces: Iterable[IfaceInfo]) -> str:
    header = f"{'NAME':<18}{'STATE':<10}{'LINK':<14}{'IPV4':<17}{'PACKETS':>10}  NOTE"
    lines = [header, "-" * len(header)]
    for i in ifaces:
        link = f"{i.link_type if i.link_type is not None else '?'}/{i.link_kind}"
        note = "skipped by auto-detect" if i.skipped else i.category
        lines.append(
            f"{i.name:<18}{i.operstate:<10}{link:<14}{(i.ipv4 or '-'):<17}{i.packets:>10}  {note}"
        )
    return "\n".join(lines)
