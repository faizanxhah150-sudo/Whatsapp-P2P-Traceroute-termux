# WhatsApp P2P Traceroute

A network traffic analyzer for **WhatsApp / Meta** flows. It captures packets on
an interface you control, filters traffic belonging to Meta's network
(AS32934), enriches every remote endpoint with **geolocation, ASN, and
reverse-DNS**, and flags **candidate peer-to-peer endpoints** — the non-Meta
public IPs seen during media traffic that are the only realistic way passive
capture can surface a real peer instead of a relay server.

> ⚠️ **Authorized / educational use only.**
> Capture only traffic on networks you own or have explicit permission to
> monitor. Using this to locate or deanonymize a person without consent may
> violate privacy and anti-stalking laws. You are responsible for lawful use.

---

## Reality check (read this first)

Modern WhatsApp voice/video calls are usually **relayed through Meta's TURN
servers**, so most IPs you capture are Meta's, not the other person's. A direct
peer IP only leaks in narrow peer-to-peer situations. This tool surfaces those
as `candidate_peer` records, but there is **no guarantee** any appear. Treat
"get someone's IP from WhatsApp" as mostly a myth — this project is a
traffic-analysis and learning tool, not a locator.

---

## Platforms

| Platform | Status | Capture backend |
|---|---|---|
| **Rooted Android (Termux)** | primary target (Python 3.13+ `sys.platform == "android"` handled) | native `AF_PACKET`, else `tcpdump` pipe; Scapy never used implicitly |
| Desktop Linux | supported | native `AF_PACKET`, else `tcpdump` pipe |
| Windows / macOS | supported (secondary) | Scapy `sniff()`; needs Npcap (Windows) / libpcap |

## Features

- **TCP + UDP capture** — signaling (443 / 5222) *and* media/STUN (UDP), IPv4 and IPv6.
- **Android-aware interface handling** — detects the active interface from `/sys/class/net` and
  `/proc/net/*` (no netlink, no `ip` tool). Prefers `wlan0`, then cellular (`ccmni*`, `rmnet*`),
  warns about VPNs (`tun*`, `wg*`). Handles **Ethernet** (Wi-Fi) and **raw-IP** (cellular) links
  and writes the PCAP with the matching linktype (1 / 101).
- **BPF with graceful fallback** — tries a kernel BPF filter (via `tcpdump -ddd`); if that is
  unavailable it filters in Python with a clear warning. It never crashes over a filter.
- **Live Meta prefix refresh** — pulls the AS32934 prefix list from RIPEstat with timeouts and
  retries, caches it, and falls back to a bundled seed list when offline.
- **Geo + ASN enrichment** — MaxMind GeoLite2 City + ASN, read with the lightweight `maxminddb`
  package. Degrades gracefully if the DBs are absent.
- **Non-blocking reverse DNS** — resolved on background threads with a timeout; never stalls capture.
- **Peer heuristic scoring** — **Meta relay**, **Remote**, or **candidate P2P peer**, scored 0–100.
- **CSV + JSON reports + PCAP** — per-IP aggregation, ranked by score. Optional `--export-dir`.
- **Live web dashboard** — Starlette + WebSocket, bound to `127.0.0.1:8000`, mobile-friendly.
- **Root-friendly output** — files created via `su` are chown'ed back to the Termux user.

---

## Termux (rooted Android) — quick start

Full guide with troubleshooting: **[docs/TERMUX.md](docs/TERMUX.md)**.

```bash
# in Termux (F-Droid/GitHub build), after granting Termux root in Magisk (test: su -c id)
git clone https://github.com/<USER>/<REPO>.git && cd <REPO>
bash scripts/termux_setup.sh

bash scripts/run_root.sh --list-ifaces
bash scripts/run_root.sh --check-env
bash scripts/run_root.sh --count 500
bash scripts/run_root.sh --dashboard        # open http://127.0.0.1:8000 in the phone browser
```

Place the WhatsApp call **from the same phone**; only the phone's own traffic is visible.

---

## Desktop install (Linux / Windows / macOS)

```bash
git clone https://github.com/<USER>/<REPO>.git
cd <REPO>
python3 -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt                    # core
pip install -r requirements-dashboard.txt          # optional dashboard
cp .env.example .env                               # optional tuning
```

Requirements: **Python 3.10+**, root/Administrator to capture, optionally MaxMind
**GeoLite2-City** / **GeoLite2-ASN** (`.mmdb` into `./data/`;
free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)).
Windows additionally needs [Npcap](https://npcap.com) for the Scapy backend.

## Usage

Run with root (`sudo` on Linux; Termux: `bash scripts/run_root.sh ...`; Windows: elevated terminal).

```bash
python main.py --list-ifaces                 # no root needed
sudo python main.py --count 500              # 500 packets then write reports
sudo python main.py --iface wlan0 --timeout 60
sudo python main.py --no-refresh             # fully offline
sudo python main.py --dashboard              # http://127.0.0.1:8000
```

### All options

| Flag | Default | Description |
|------|---------|-------------|
| `--iface` | auto (`WIT_IFACE`) | Interface to sniff, e.g. `wlan0`, `ccmni1`, `ap0` |
| `--list-ifaces` | off | List interfaces (state, link type, IPv4, packets) and exit |
| `--backend` | `auto` (`WIT_BACKEND`) | `auto`, `afpacket`, `tcpdump` or `scapy` (auto = afpacket then tcpdump; Scapy only on Windows/macOS) |
| `--count` | `0` | Packet count (`0` = until Ctrl+C) |
| `--timeout` | none | Stop capture after N seconds |
| `--no-refresh` | off | Skip online Meta-prefix refresh |
| `--dashboard` | off | Launch web dashboard instead of CLI |
| `--export-dir` | none (`WIT_EXPORT_DIR`) | Also copy reports + pcap here, e.g. `/sdcard/WhatsAppP2P` |
| `--no-wake-lock` | off | Do not call `termux-wake-lock` |
| `--version` | - | Print the version and exit |

Environment overrides (`.env`): `WIT_IFACE`, `WIT_BACKEND`, `WIT_COUNT`, `WIT_BPF`, `WIT_HOST`, `WIT_PORT`,
`WIT_RANGE_MAX_AGE`, `WIT_EXPORT_DIR`, `WIT_RDNS`, `WIT_RDNS_TIMEOUT`, `WIT_HTTP_RETRIES`,
`WIT_HTTP_CONNECT_TIMEOUT`, `WIT_HTTP_READ_TIMEOUT`, `WIT_MAX_RECORDS`, `GEO_CITY_DB`, `GEO_ASN_DB`.
Relative paths are resolved against the project root, not the current directory.

---

## Output

| File | Contents |
|------|----------|
| `output/ip_report.csv` | Per-remote summary, ranked by score |
| `output/ip_report.json` | Same data as JSON |
| `logs/packet_logs.pcap` | Raw matched packets (open in Wireshark; linktype 1 or 101) |
| `data/meta_ranges.json` | Cached AS32934 prefix list |

**Report columns:** `remote`, `packets`, `bytes`, `protocols`, `ports`, `is_meta`,
`candidate_peer`, `max_score`, `host`, `asn`, `org`, `country`, `city`, `latitude`,
`longitude`, `first_seen`, `last_seen`.

**Flow types:**
- 🟢 **Meta** — endpoint in Meta's network (relay/server). Expected majority.
- 🟡 **Remote** — public non-Meta endpoint, non-media.
- 🔴 **PEER?** (`candidate_peer`) — public non-Meta IP during media traffic; possible direct peer.
  Ordinary infrastructure UDP (DNS, NTP, mDNS, …) is not counted as media.

---

## Docker

```bash
docker build -t wit .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN -e WIT_HOST=0.0.0.0 wit --dashboard
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
```

All tests run on a normal Linux machine without root or Android.

## Project structure

```
main.py                 CLI entrypoint (capture | --dashboard | --list-ifaces)
config.py               env-driven settings, project-root paths, seed Meta ranges
core/
  packet_sniffer.py     backend chain: AF_PACKET -> tcpdump pipe (Scapy: Windows/macOS only)
  pcap_stream.py        incremental parser for `tcpdump -w -` output (LE/BE, micro/nano, 1/101/12/113/276)
  packet_parser.py      Ethernet / raw-IP, IPv4/IPv6, TCP/UDP parsing (no libpcap)
  bpf.py                kernel BPF via tcpdump -ddd + Python-side filter
  classifier.py         packet -> enriched FlowRecord + peer scoring
  ip_filter.py          guarded CIDR membership (cached)
  meta_ranges.py        RIPEstat AS32934 refresh, retries, cache, offline fallback
  reporting.py          incremental per-IP aggregation -> CSV/JSON
  dns_resolver.py       non-blocking reverse DNS
utils/
  netif.py              /sys + /proc interface detection, link types
  pcap.py               tiny PCAP writer (linktype 1 / 101)
  platform_utils.py     Termux/Android/root detection, CA bundle, wake-lock, chown, export
  geo_ip.py             GeoLite2 City+ASN via maxminddb
  helpers.py            logging, dirs, output finalisation
dashboard/              Starlette server + static page
scripts/                termux_setup.sh, run_root.sh, check_env.py
docs/TERMUX.md          full Termux guide
tests/                  pytest suite
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Operation not permitted` / `Not running as root` | Run as root (`sudo`, or on Termux `bash scripts/run_root.sh ...`). |
| No packets captured | Wrong interface or VPN — `--list-ifaces`, then `--iface NAME`. |
| `tcpdump not found` warning | Harmless for the default backend; only `--backend tcpdump` needs it (`pkg install tcpdump`). |
| `Scapy currently does not support android` / `Interface not found` | Old version on Python 3.13+ (`sys.platform == "android"`). `git pull`; see docs/TERMUX.md. |
| Blank city/country/ASN | Add GeoLite2 `.mmdb` files to `./data/`. |
| Only Meta IPs, no `PEER?` | Expected — calls are relayed. A P2P leak is rare. |

More (Termux-specific) in [docs/TERMUX.md](docs/TERMUX.md).

## License

For authorized security research and education. Use responsibly and lawfully.
