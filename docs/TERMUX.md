# Running on a rooted Android phone (Termux)

Capture happens **on the phone itself**: no PC, no hotspot needed. It only sees this phone's own
traffic, so the WhatsApp call must be made **on this phone**.

> ⚠️ **Authorized / educational use only.** Capture only your own traffic or networks you have explicit
> permission to monitor. WhatsApp calls are mostly relayed through Meta TURN servers, so a real peer IP
> rarely appears. See the main README.

Target: Redmi Note 9 (ARM64), Magisk root, Android 10-13, Termux from F-Droid/GitHub (**not** Play Store).

## 1. Prerequisites

1. Magisk root. Install Termux from F-Droid or the GitHub releases page.
2. In Magisk, open **Superuser** and allow **Termux** (accept the prompt when it appears).
3. Test root in Termux:

```bash
su -c id
```

Expect `uid=0(root)`. If you see "not found" or "permission denied", fix root first.

## 2. Packages and storage

`scripts/termux_setup.sh` does all of this for you (step 3). To do it by hand:

```bash
pkg update -y && pkg upgrade -y
pkg install -y root-repo
pkg update -y
pkg install -y python git python-pip clang make libffi openssl libxml2 libxslt tcpdump libpcap tsu termux-api
termux-setup-storage        # optional: gives ~/storage/shared (grant the permission popup)
```

Do **not** run `pip install -U pip` in Termux (it breaks pip); upgrade with `pkg upgrade python-pip`.
If a package name is not found, check with `pkg search <name>`.

## 3. Get the project and run the installer

```bash
git clone https://github.com/<USER>/<REPO>.git && cd <REPO>
bash scripts/termux_setup.sh
```

Run it as the **normal Termux user** (not through `su`). It is idempotent: re-run any time.
Options: `--no-dashboard` (skip dashboard deps), `--skip-pkg` (skip `pkg` steps).

It creates `.venv` (with `--system-site-packages`), installs `requirements.txt` and
`requirements-dashboard.txt`, creates `output/ logs/ data/` and copies `.env.example` to `.env`.

## 4. Optional: GeoLite2 location/ASN databases

Free MaxMind account: <https://www.maxmind.com/en/geolite2/signup>. Download `GeoLite2-City.mmdb` and
`GeoLite2-ASN.mmdb` (on the phone browser they land in `/sdcard/Download`), then:

```bash
termux-setup-storage                       # once
cp ~/storage/downloads/GeoLite2-City.mmdb ~/storage/downloads/GeoLite2-ASN.mmdb data/
# or: cp /sdcard/Download/GeoLite2-*.mmdb data/
ls -l data/
```

Without them the tool still works; location/ASN columns stay blank.

## 5. Preflight

All capture commands go through the root launcher. It works from a normal shell (uses `su -c`) **or**
from inside a root shell you opened with `tsu`.

```bash
bash scripts/run_root.sh --list-ifaces
bash scripts/run_root.sh --check-env          # runs scripts/check_env.py as root
```

`--check-env` prints PASS / WARN / FAIL for: `sys.platform` / `platform.system()` / Python version, root, every interface
with its link type, usable backends (afpacket / tcpdump / scapy), Python modules, GeoLite2 files, writable folders and
RIPEstat reachability (add `--offline` to skip the network test), then a one-line verdict.
You can also run `python scripts/check_env.py` directly (it will FAIL the root check when not root).

Interface hints: Wi-Fi is `wlan0` (Ethernet link type 1); mobile data is `ccmni*` / `rmnet_data*`
(raw-IP link type 519/512, no Ethernet header - handled automatically); `tun*`/`wg*` means a VPN (warned).

## 5b. Capture backends (`--backend`)

| Backend | What it is | When used |
|---|---|---|
| `afpacket` | native raw socket, no extra tools | default on Android/Linux |
| `tcpdump` | pipes `tcpdump -w -` into the same analyser | `auto` falls back to it if AF_PACKET fails for a reason other than permissions |
| `scapy` | Scapy `sniff()` | Windows/macOS only (not supported on Android); never used automatically here |

`auto` (default, also `WIT_BACKEND=auto`) = `afpacket`, then `tcpdump`. A permission error is **never** retried
with another backend: it means "not root" (see the first troubleshooting row). Force one with:

```bash
bash scripts/run_root.sh --backend tcpdump --iface wlan0 --count 50 --no-refresh
pkg install tcpdump        # needed for --backend tcpdump (verify with: pkg search tcpdump)
```

Python 3.13+ reports `sys.platform == "android"` instead of `"linux"`; this version handles both. Check yours:
`python -c "import sys;print(sys.platform)"`.

## 6. Run

```bash
# CLI, 500 packets then write reports
bash scripts/run_root.sh --count 500

# Timed: 60 seconds
bash scripts/run_root.sh --timeout 60

# Specific interface and backend
bash scripts/run_root.sh --iface wlan0 --timeout 120
bash scripts/run_root.sh --backend tcpdump --iface wlan0 --count 50 --no-refresh
bash scripts/run_root.sh --iface ccmni1 --timeout 120

# Hotspot clients (phone hotspot on): pick the hotspot interface from --list-ifaces
bash scripts/run_root.sh --iface ap0 --timeout 120        # or wlan1 / swlan0

# Fully offline (skip the RIPEstat refresh) and copy results to shared storage
bash scripts/run_root.sh --no-refresh --export-dir /sdcard/WhatsAppP2P

# Live dashboard: then open http://127.0.0.1:8000 in the phone browser
bash scripts/run_root.sh --dashboard
```

Stop with **Ctrl+C**: the capture, DNS workers and dashboard shut down cleanly and the reports are written.

### Smoke tests after updating (`git pull`)

```bash
python -c "import sys;print(sys.platform)"                          # 'android' on Python 3.13+, else 'linux'
bash scripts/run_root.sh --list-ifaces
bash scripts/run_root.sh --iface wlan0 --count 50 --no-refresh
bash scripts/run_root.sh --backend tcpdump --iface wlan0 --count 50 --no-refresh
bash scripts/run_root.sh --iface ap0 --count 50 --no-refresh        # hotspot on (or wlan1 / swlan0)
```

## 7. Test a WhatsApp call

1. Start a capture: `bash scripts/run_root.sh --timeout 120` (or `--dashboard`).
2. Place a WhatsApp voice/video call **from this phone** (Termux stays running in the background).
3. Stop the capture (Ctrl+C or wait for the timeout).
4. Read the report:

```bash
column -s, -t < output/ip_report.csv | less -S
```

5. Copy the PCAP for Wireshark (it already has the right linktype: 1 = Ethernet, 101 = raw IP):

```bash
cp logs/packet_logs.pcap /sdcard/Download/
```

`candidate_peer = True` rows are non-Meta public IPs seen during media traffic. Most calls only show Meta relays.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `CRITICAL: Scapy currently does not support android! I/O will NOT work!` | Older versions mis-detected Android: Termux Python 3.13+ reports `sys.platform == 'android'` (not `'linux'`), so the native capture path was skipped and Scapy was imported. **Fix: update** (`cd <REPO> && git pull`). This version uses native `afpacket` (or `tcpdump`) and never imports Scapy on Android. |
| `Interface not found` / `get_if_list()` returns `[]` | Same cause as above (Scapy cannot list interfaces on Android). `git pull`, then `bash scripts/run_root.sh --list-ifaces`. If you typed a wrong name the tool now lists the real ones (`wlan0`, `ap0`, `wlan1`, `swlan0`, `ccmni*`, `rmnet_data*`). |
| Want to force a backend / `afpacket` fails with a non-permission error | `bash scripts/run_root.sh --backend tcpdump --iface wlan0 ...` (install with `pkg install tcpdump`). `--backend afpacket` forces the native socket. |
| `GeoLite2 DB not found in data/ - city/ASN columns will be blank` | Only a notice: capture, scoring, reports and dashboard work; city/country/ASN stay blank until you copy `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` into `data/` (section 4). A corrupt file gives a similar one-line warning. |
| `Permission denied` / `Operation not permitted` opening the socket | Not running as root. Always use `bash scripts/run_root.sh ...`. Re-check `su -c id`; in Magisk > Superuser make sure Termux is allowed. SELinux is a last-resort suspect only (`su -c getenforce`). |
| `No 'su' binary found` / `did not grant root` | Phone not rooted or Termux denied in Magisk. Open Magisk > Superuser, allow Termux, accept the on-screen prompt, retry. |
| No packets captured | Wrong interface: run `--list-ifaces` and pass `--iface`. Using a VPN (`tun0`/`wg0`)? Capture on the tunnel interface or disable the VPN. Wi-Fi and mobile data can be active together: pick the one WhatsApp uses. Private DNS / VPN do not hide the Meta IPs but encrypted tunnels do. Make sure the call is placed from this phone. |
| Link type confusion (garbled PCAP, 0 flows on mobile data) | Cellular is raw-IP (type 519/512). The tool reads `/sys/class/net/<if>/type` and handles it; `--list-ifaces` shows the detected link type. Report an unknown type if you see one. |
| `tcpdump not found` warning | Only needed for kernel BPF filters. The tool falls back to Python-side filtering automatically. Install with `pkg install tcpdump` (verify: `pkg search tcpdump`). |
| pip build errors: `pydantic-core`, `cryptography`, `Rust`, `maturin` | The dashboard uses Starlette, so **no pydantic-core / Rust is needed**; make sure you installed `requirements-dashboard.txt` and not FastAPI. If you want FastAPI anyway: check `pkg search pydantic` for a prebuilt package (then the venv's `--system-site-packages` will see it), otherwise `pkg install rust binutils` and build (slow). `cryptography` is not required by this tool. |
| `maxminddb` fails to build | Its C extension is optional (pure-Python fallback exists). Re-run `bash scripts/termux_setup.sh` after `pkg install clang make`. Without it only GeoLite2 enrichment is disabled; capture still works. |
| SSL / certificate errors as root | The tool auto-sets `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` to `$PREFIX/etc/tls/cert.pem`. Check `ls $PREFIX/etc/tls/cert.pem` (`pkg install ca-certificates` if missing). Use `--no-refresh` to skip the online range refresh; bundled seed ranges are used. |
| Process killed in the background | Run `termux-wake-lock` (done automatically when available). Disable battery optimisation for Termux (Settings > Apps > Termux > Battery > No restrictions). On MIUI/HyperOS enable **Autostart** for Termux and lock it in the recent-apps screen. Install the *Termux:API* app + `pkg install termux-api` for reliable wake-locks. |
| Output files owned by root | Files are chown'ed back to the Termux user automatically at the end of each run. If a run was killed before that: `su -c "chown -R $(id -u):$(id -g) $PWD/output $PWD/logs $PWD/data"`. If the app still cannot read them: `su -c "restorecon -R $PWD"`. |
| `--export-dir` fails | Run `termux-setup-storage` first; as root try `/sdcard/WhatsAppP2P` or `/storage/emulated/0/WhatsAppP2P`. |
| `termux-wake-lock: command not found` / Termux:API missing | Optional. `pkg install termux-api` and install the Termux:API app from the same source (F-Droid/GitHub) as Termux. The tool continues without it. |
| Dashboard port busy | Another instance is running. Change `WIT_PORT` in `.env`. |
