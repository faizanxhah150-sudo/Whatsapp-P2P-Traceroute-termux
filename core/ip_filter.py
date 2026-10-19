"""WhatsApp/Meta IP membership test with error guards + caching."""
from __future__ import annotations

import ipaddress
import logging

import config

log = logging.getLogger("wit")

_MAX_CACHE = 16384

# Pre-parsed networks, rebuilt when ranges are refreshed at runtime.
_networks: list = []
_cache: dict[str, bool] = {}


def load_networks(ranges=None):
    """(Re)build the parsed network list. Call after a range refresh."""
    global _networks
    ranges = ranges if ranges is not None else config.WHATSAPP_IP_RANGES
    parsed = []
    for r in ranges:
        try:
            parsed.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            log.warning("Skipping invalid network range: %s", r)
    _networks = parsed
    _cache.clear()
    return _networks


def is_whatsapp_ip(ip: str) -> bool:
    if not _networks:
        load_networks()
    cached = _cache.get(ip)
    if cached is not None:
        return cached
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    result = False
    for net in _networks:
        # Guard IPv4-vs-IPv6 version mismatch (raises in older Python).
        if addr.version != net.version:
            continue
        if addr in net:
            result = True
            break
    if len(_cache) >= _MAX_CACHE:
        _cache.clear()
    _cache[ip] = result
    return result
