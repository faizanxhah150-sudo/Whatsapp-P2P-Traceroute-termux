import threading
import time

from core.dns_resolver import Resolver, is_meta_hostname


def test_lookup_never_blocks_and_result_arrives_later():
    release = threading.Event()

    def slow(ip):
        release.wait(2)
        return ("edge.whatsapp.net", [], [ip])

    r = Resolver(workers=2, timeout=5, resolver=slow)
    t0 = time.monotonic()
    assert r.lookup("157.240.1.5") is None          # returns instantly although resolver hangs
    assert time.monotonic() - t0 < 0.5
    release.set()
    assert r.wait_for("157.240.1.5", timeout=2) == "edge.whatsapp.net"
    assert r.lookup("157.240.1.5") == "edge.whatsapp.net"  # now cached
    r.shutdown()


def test_failed_lookup_is_cached_as_unknown():
    calls = []

    def fail(ip):
        calls.append(ip)
        raise OSError("NXDOMAIN")

    r = Resolver(resolver=fail)
    assert r.wait_for("45.55.100.10", timeout=1) is None
    time.sleep(0.05)
    r.lookup("45.55.100.10")
    r.lookup("45.55.100.10")
    assert calls == ["45.55.100.10"]  # asked once only
    r.shutdown()


def test_hung_lookup_times_out_and_does_not_stall_other_lookups():
    block = threading.Event()

    def resolver(ip):
        if ip == "9.9.9.9":
            block.wait(5)           # simulates a resolver that never answers
        return (f"host-{ip}", [], [ip])

    r = Resolver(workers=2, timeout=0.1, resolver=resolver)
    assert r.lookup("9.9.9.9") is None
    time.sleep(0.2)
    assert r.lookup("9.9.9.9") is None              # gave up after the timeout (negative cached)
    assert r.wait_for("8.8.8.8", timeout=2) == "host-8.8.8.8"  # second worker still serves
    block.set()
    r.shutdown()


def test_disabled_resolver_never_looks_up():
    def boom(_ip):
        raise AssertionError("must not be called")

    r = Resolver(enabled=False, resolver=boom)
    assert r.lookup("1.1.1.1") is None


def test_pending_queue_is_bounded():
    block = threading.Event()
    r = Resolver(workers=1, max_pending=2, resolver=lambda ip: (block.wait(2), (ip,))[1])
    for i in range(10):
        r.lookup(f"10.0.0.{i}")
    assert len(r._pending) <= 2
    block.set()
    r.shutdown()


def test_is_meta_hostname():
    assert is_meta_hostname("edge-star-mini-shv-01.fbcdn.net")
    assert is_meta_hostname("MMX.WHATSAPP.NET")
    assert not is_meta_hostname("example.com")
    assert not is_meta_hostname(None)
