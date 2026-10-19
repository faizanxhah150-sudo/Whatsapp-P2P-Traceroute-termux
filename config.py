"""Central configuration.

Values are read from environment variables (see .env.example) with sane
defaults so the tool runs out of the box for authorized/educational use.
Every path is resolved relative to the project root (never the current
working directory), so the tool behaves the same when launched through
``su -c`` on Android, from a cron job, or from an IDE.
"""
from __future__ import annotations

import os
from pathlib import Path

VERSION = "1.1.1"

BASE_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except Exception:  # python-dotenv is optional
    pass


# --- Small env helpers -----------------------------------------------------
def _env_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None else value.strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_path(value: str | os.PathLike | None, default: Path) -> Path:
    """Resolve ``value`` against the project root; ``default`` when empty."""
    if not value:
        return default
    path = Path(value).expanduser()
    return path if path.is_absolute() else (BASE_DIR / path).resolve()


# --- Paths -----------------------------------------------------------------
LOG_DIR = BASE_DIR / "logs"
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"

LOG_FILE = LOG_DIR / "packet_logs.pcap"
CSV_REPORT = OUTPUT_DIR / "ip_report.csv"
JSON_REPORT = OUTPUT_DIR / "ip_report.json"

# GeoLite2 databases (download from MaxMind, free account).
GEO_CITY_DB = resolve_path(os.getenv("GEO_CITY_DB"), DATA_DIR / "GeoLite2-City.mmdb")
GEO_ASN_DB = resolve_path(os.getenv("GEO_ASN_DB"), DATA_DIR / "GeoLite2-ASN.mmdb")

# Optional copy of the reports/pcap, e.g. /sdcard/WhatsAppP2P on Android.
EXPORT_DIR = _env_str("WIT_EXPORT_DIR", "")

# --- Capture settings ------------------------------------------------------
# Empty string => auto-detect (wlan0, then cellular, then anything else usable).
DEFAULT_IFACE = _env_str("WIT_IFACE", "")
DEFAULT_COUNT = _env_int("WIT_COUNT", 0)  # 0 = capture until stopped
# Both protocols: WhatsApp uses UDP (RTP/STUN media) and TCP (443/5222 signaling).
# An explicitly empty WIT_BPF disables filtering.
BPF_FILTER = os.getenv("WIT_BPF", "udp or tcp").strip()
# Capture backend: auto | afpacket | tcpdump | scapy (auto = afpacket, then tcpdump; Scapy only
# on Windows/macOS). An invalid value falls back to auto.
BACKENDS = ("auto", "afpacket", "tcpdump", "scapy")
DEFAULT_BACKEND = _env_str("WIT_BACKEND", "auto").lower()
if DEFAULT_BACKEND not in BACKENDS:
    DEFAULT_BACKEND = "auto"
# How many recent FlowRecords are kept in memory (aggregates are unbounded-safe).
MAX_RECORDS = _env_int("WIT_MAX_RECORDS", 20000)

# --- Meta / WhatsApp networks ---------------------------------------------
# Seed ranges. Refreshed at runtime from Meta's published prefix list for
# AS32934 when network access is available (see core.meta_ranges).
WHATSAPP_IP_RANGES = [
    "31.13.24.0/21",
    "31.13.64.0/18",
    "66.220.144.0/20",
    "69.63.176.0/20",
    "69.171.224.0/19",
    "74.119.76.0/22",
    "103.4.96.0/22",
    "129.134.0.0/17",
    "157.240.0.0/16",
    "173.252.64.0/18",
    "179.60.192.0/22",
    "185.60.216.0/22",
    "204.15.20.0/22",
    "2a03:2880::/32",
]

META_ASN = 32934  # Meta Platforms / Facebook

# Cache of the auto-refreshed prefix list.
META_RANGE_CACHE = DATA_DIR / "meta_ranges.json"
META_RANGE_MAX_AGE_HOURS = _env_int("WIT_RANGE_MAX_AGE", 24)

# RIPEstat refresh: timeouts in seconds, retries with exponential backoff.
HTTP_CONNECT_TIMEOUT = _env_float("WIT_HTTP_CONNECT_TIMEOUT", 5.0)
HTTP_READ_TIMEOUT = _env_float("WIT_HTTP_READ_TIMEOUT", 15.0)
HTTP_RETRIES = max(1, _env_int("WIT_HTTP_RETRIES", 3))
HTTP_BACKOFF = _env_float("WIT_HTTP_BACKOFF", 1.0)

# --- Reverse DNS (never blocks capture; see core.dns_resolver) -------------
RDNS_ENABLED = _env_bool("WIT_RDNS", True)
RDNS_TIMEOUT = _env_float("WIT_RDNS_TIMEOUT", 2.0)
RDNS_WORKERS = max(1, _env_int("WIT_RDNS_WORKERS", 4))

# --- Dashboard -------------------------------------------------------------
DASH_HOST = _env_str("WIT_HOST", "127.0.0.1")
DASH_PORT = _env_int("WIT_PORT", 8000)
