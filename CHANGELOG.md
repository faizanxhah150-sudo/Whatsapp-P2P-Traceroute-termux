# Changelog

## 1.1.1

### Fixed
- **Android detection.** Python 3.13+ reports `sys.platform == "android"` (PEP 738), not `"linux"`. The old
  `is_linux()` returned False there, so interface detection and the native `AF_PACKET` path were skipped and Scapy
  was imported, which prints "Scapy currently does not support android! I/O will NOT work!" and cannot list
  interfaces ("Interface not found"). `is_linux()` now accepts `linux*` and `android`; backend choice is based on
  capabilities (`af_packet_supported()` = `AF_PACKET` exists and `/sys/class/net` or `/proc/net/dev` is readable),
  not OS names. All platform checks live in `utils/platform_utils.py`.

### Added
- `--backend {auto,afpacket,tcpdump,scapy}` / `WIT_BACKEND`. `auto` = `afpacket`, then a new **tcpdump pipe**
  backend (`tcpdump -w -`, parsed by `core/pcap_stream.py`: LE/BE, micro/nano, linktypes 0/1/12/101/113/276).
  Permission errors never fall back silently; they print the root help.
- Scapy is only imported lazily inside the Scapy backend (Windows/macOS or explicit `--backend scapy`), never
  implicitly on Android/Linux; `--list-ifaces` and interface selection work purely from `/sys` and `/proc`.
- `--iface` is validated against the kernel's interface list; typos print the available names.
- Auto interface order: default-route interface, `wlan0`, hotspot interfaces (`ap0`/`swlan0`/`wlan1`) with traffic,
  then cellular; VPN (`tun*`, `wg*`) is warned about, never auto-selected.
- `--version`; backend/interface logged at INFO; `scripts/check_env.py` prints platform details, usable backends,
  interfaces with link types, GeoLite2 status and a verdict.

### Changed
- GeoLite2: a single clear warning when databases are missing, unreadable or corrupt; fields stay blank and
  everything else keeps working. `netif` tolerates ENOENT/EACCES on individual `/sys` files.

## 1.1.0
- Termux/rooted Android support: native AF_PACKET capture, raw-IP vs Ethernet link types, root launcher,
  installer, non-blocking reverse DNS, Starlette dashboard.
