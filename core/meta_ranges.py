"""Auto-refresh Meta/WhatsApp IP prefixes for AS32934.

Pulls the current prefix list from RIPEstat (public BGP data) and caches it,
so the hardcoded seed list in config.py does not rot. Resolution order:

    fresh cache -> RIPEstat (timeouts + retries) -> stale cache -> seed list

so the tool works fully offline (DNS failure, airplane mode, no CA store).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timezone

import config

log = logging.getLogger("wit")

RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
USER_AGENT = "whatsapp-p2p-traceroute/1.1 (+authorized-analysis)"


def _cache_fresh() -> bool:
    p = config.META_RANGE_CACHE
    if not p.exists():
        return False
    age_h = (time.time() - p.stat().st_mtime) / 3600
    return age_h < config.META_RANGE_MAX_AGE_HOURS


def _read_cache():
    try:
        data = json.loads(config.META_RANGE_CACHE.read_text(encoding="utf-8"))["prefixes"]
        return _validate(data) or None
    except Exception:
        return None


def _write_cache(prefixes) -> None:
    path = config.META_RANGE_CACHE
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"updated": datetime.now(timezone.utc).isoformat(), "prefixes": prefixes}
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)  # atomic: a killed process never leaves a half file


def _validate(prefixes) -> list[str]:
    valid = []
    for p in prefixes or []:
        try:
            ipaddress.ip_network(p, strict=False)
        except (ValueError, TypeError):
            continue
        valid.append(p)
    return valid


def _fetch_prefixes(url: str, getter=None, sleep=time.sleep) -> list[str]:
    """GET the prefix list with connect/read timeouts and exponential backoff."""
    if getter is None:
        import requests  # lazy: missing requests just means "offline"

        getter = requests.get
    last_exc: Exception | None = None
    for attempt in range(1, config.HTTP_RETRIES + 1):
        try:
            resp = getter(
                url,
                timeout=(config.HTTP_CONNECT_TIMEOUT, config.HTTP_READ_TIMEOUT),
                headers={"User-Agent": USER_AGENT},
            )
            resp.raise_for_status()
            data = resp.json()
            prefixes = _validate([p["prefix"] for p in data["data"]["prefixes"]])
            if not prefixes:
                raise ValueError("empty prefix list")
            return prefixes
        except Exception as exc:
            last_exc = exc
            log.debug("RIPEstat attempt %d/%d failed: %s", attempt, config.HTTP_RETRIES, exc)
            if attempt < config.HTTP_RETRIES:
                sleep(config.HTTP_BACKOFF * (2 ** (attempt - 1)))
    raise last_exc if last_exc else RuntimeError("RIPEstat fetch failed")


def refresh_ranges(force: bool = False, getter=None, sleep=time.sleep) -> list[str]:
    """Return a list of CIDR strings. Uses cache/seed when offline."""
    if not force and _cache_fresh():
        cached = _read_cache()
        if cached:
            log.info("Loaded %d Meta prefixes from cache.", len(cached))
            return cached

    try:
        prefixes = _fetch_prefixes(
            RIPESTAT_URL.format(asn=config.META_ASN), getter=getter, sleep=sleep
        )
    except Exception as exc:
        stale = _read_cache()
        if stale:
            log.warning("Range refresh failed (%s); using stale cache (%d prefixes).",
                        exc, len(stale))
            return stale
        log.warning("Range refresh failed (%s); using bundled seed ranges.", exc)
        return list(config.WHATSAPP_IP_RANGES)

    try:
        _write_cache(prefixes)
    except OSError as exc:
        log.warning("Could not write prefix cache: %s", exc)
    log.info("Refreshed %d Meta prefixes from RIPEstat (AS%d).", len(prefixes), config.META_ASN)
    return prefixes
