"""Keep tests hermetic: no real DNS threads, no GeoLite2 files, no network."""
import pytest

from core import dns_resolver
from utils import geo_ip


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    monkeypatch.setattr(dns_resolver, "_default", dns_resolver.Resolver(enabled=False))
    geo_ip.reset()
    yield
    geo_ip.reset()
