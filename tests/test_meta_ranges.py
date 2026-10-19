import json
import os
import time

import pytest

import config
from core import meta_ranges


class FakeResp:
    def __init__(self, prefixes):
        self._prefixes = prefixes

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": {"prefixes": [{"prefix": p} for p in self._prefixes]}}


@pytest.fixture(autouse=True)
def _cache_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "META_RANGE_CACHE", tmp_path / "data" / "meta_ranges.json")
    monkeypatch.setattr(config, "HTTP_RETRIES", 3)
    monkeypatch.setattr(config, "HTTP_BACKOFF", 1.0)


def offline(*args, **kwargs):
    raise ConnectionError("Name or service not known")  # what a DNS failure looks like


def test_offline_falls_back_to_seed_ranges_with_retries_and_backoff():
    sleeps = []
    got = meta_ranges.refresh_ranges(getter=offline, sleep=sleeps.append)
    assert got == config.WHATSAPP_IP_RANGES
    assert sleeps == [1.0, 2.0]  # 3 attempts -> 2 exponential backoffs


def test_success_writes_cache_and_drops_invalid_prefixes(tmp_path):
    seen = {}

    def getter(url, timeout, headers):
        seen["timeout"] = timeout
        seen["url"] = url
        return FakeResp(["157.240.0.0/16", "garbage", "2a03:2880::/32"])

    got = meta_ranges.refresh_ranges(getter=getter, sleep=lambda s: None)
    assert got == ["157.240.0.0/16", "2a03:2880::/32"]
    assert seen["timeout"] == (config.HTTP_CONNECT_TIMEOUT, config.HTTP_READ_TIMEOUT)
    assert "AS32934" in seen["url"]
    cached = json.loads(config.META_RANGE_CACHE.read_text())
    assert cached["prefixes"] == got
    assert not list(config.META_RANGE_CACHE.parent.glob("*.tmp"))  # atomic write cleaned up


def test_fresh_cache_skips_network():
    config.META_RANGE_CACHE.parent.mkdir(parents=True)
    config.META_RANGE_CACHE.write_text(json.dumps({"prefixes": ["31.13.64.0/18"]}))
    assert meta_ranges.refresh_ranges(getter=offline, sleep=lambda s: None) == ["31.13.64.0/18"]


def test_stale_cache_used_when_offline():
    config.META_RANGE_CACHE.parent.mkdir(parents=True)
    config.META_RANGE_CACHE.write_text(json.dumps({"prefixes": ["31.13.64.0/18"]}))
    old = time.time() - 72 * 3600
    os.utime(config.META_RANGE_CACHE, (old, old))
    assert meta_ranges.refresh_ranges(getter=offline, sleep=lambda s: None) == ["31.13.64.0/18"]


def test_corrupt_cache_and_empty_answer_fall_back_to_seed():
    config.META_RANGE_CACHE.parent.mkdir(parents=True)
    config.META_RANGE_CACHE.write_text("{not json")
    got = meta_ranges.refresh_ranges(getter=lambda *a, **k: FakeResp([]), sleep=lambda s: None)
    assert got == config.WHATSAPP_IP_RANGES


def test_missing_requests_module_means_offline(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_requests(name, *a, **k):
        if name == "requests":
            raise ImportError("no requests")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_requests)
    assert meta_ranges.refresh_ranges(sleep=lambda s: None) == config.WHATSAPP_IP_RANGES


def test_seed_ranges_all_parse():
    import ipaddress

    for r in config.WHATSAPP_IP_RANGES:
        ipaddress.ip_network(r)
