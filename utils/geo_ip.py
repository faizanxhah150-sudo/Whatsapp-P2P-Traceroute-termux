"""Geolocation + ASN enrichment from MaxMind GeoLite2 .mmdb files.

Uses the small ``maxminddb`` reader directly (not ``geoip2``): geoip2 pulls in
aiohttp, which needs compiled wheels that are painful on Termux.

Contract: ``get_geo_info()`` NEVER raises. If either database is missing,
unreadable or corrupt (or ``maxminddb`` is not installed) the affected fields are
``None`` (rendered as empty strings in reports), ONE clear message is logged on
first use, and capture, scoring, reports and the dashboard keep working.
"""
from __future__ import annotations

import logging
import threading
from functools import lru_cache
from pathlib import Path

import config

log = logging.getLogger("wit")

_readers: dict[str, object] = {}
_initialised = False
_lock = threading.Lock()


def _display_dir(path: Path) -> str:
    try:
        return str(Path(path).parent.relative_to(config.BASE_DIR)) + "/"
    except ValueError:
        return str(Path(path).parent) + "/"


def _open(path, label: str):
    """Return ``(reader_or_None, problem_or_None, kind)``; kind is 'missing' or 'broken'."""
    try:
        import maxminddb
    except ImportError:
        return None, "maxminddb Python module not installed (pip install -r requirements.txt)", "broken"
    p = Path(path)
    try:
        if not p.is_file():
            return None, f"{label} not found", "missing"
        return maxminddb.open_database(str(p)), None, ""
    except Exception as exc:  # corrupt (InvalidDatabaseError), unreadable (OSError), ...
        return None, f"{label} unreadable/corrupt ({exc.__class__.__name__}: {exc})", "broken"


def _init() -> None:
    global _initialised
    if _initialised:
        return
    with _lock:
        if _initialised:
            return
        problems: list[tuple[str, str]] = []
        for kind, label, path in (
            ("city", "GeoLite2-City.mmdb", config.GEO_CITY_DB),
            ("asn", "GeoLite2-ASN.mmdb", config.GEO_ASN_DB),
        ):
            reader, problem, problem_kind = _open(path, label)
            _readers[kind] = reader
            if problem:
                problems.append((problem_kind, problem))
        _initialised = True
        if not problems:
            return
        if len(problems) == 2 and all(k == "missing" for k, _ in problems):
            log.warning(
                "GeoLite2 DB not found in %s - city/ASN columns will be blank; "
                "see docs/TERMUX.md", _display_dir(config.GEO_CITY_DB),
            )
        else:
            log.warning(
                "GeoLite2 enrichment degraded: %s - affected city/country/ASN columns will "
                "be blank; see docs/TERMUX.md", "; ".join(dict.fromkeys(p for _, p in problems)),
            )


def _name(block) -> str | None:
    if isinstance(block, dict):
        return (block.get("names") or {}).get("en")
    return None


@lru_cache(maxsize=4096)
def get_geo_info(ip: str) -> dict:
    info = {
        "ip": ip,
        "country": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": None,
    }
    try:
        _init()
    except Exception as exc:  # defensive: enrichment must never break capture
        log.debug("GeoLite2 init failed: %s", exc)
        return info

    city = _readers.get("city")
    if city:
        try:
            rec = city.get(ip) or {}
            loc = rec.get("location") or {}
            info.update(
                country=_name(rec.get("country")),
                city=_name(rec.get("city")),
                latitude=loc.get("latitude"),
                longitude=loc.get("longitude"),
            )
        except Exception as exc:  # ValueError for bad IP / IPv6-vs-IPv4 DB, corrupt data, ...
            log.debug("City lookup failed for %s: %s", ip, exc)

    asn = _readers.get("asn")
    if asn:
        try:
            rec = asn.get(ip) or {}
            info.update(
                asn=rec.get("autonomous_system_number"),
                org=rec.get("autonomous_system_organization"),
            )
        except Exception as exc:
            log.debug("ASN lookup failed for %s: %s", ip, exc)

    return info


def close() -> None:
    global _initialised
    for reader in list(_readers.values()):
        if reader:
            try:
                reader.close()
            except Exception:
                pass
    _readers.clear()
    _initialised = False
    get_geo_info.cache_clear()


def reset() -> None:
    """Forget readers/caches so the next lookup re-opens the databases (tests, DB swap)."""
    close()
