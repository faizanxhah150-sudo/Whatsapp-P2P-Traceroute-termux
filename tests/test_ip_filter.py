from core.ip_filter import is_whatsapp_ip, load_networks


def setup_module(_):
    load_networks(["157.240.0.0/16", "2a03:2880::/32"])


def test_meta_ipv4_in_range():
    assert is_whatsapp_ip("157.240.1.2") is True


def test_public_non_meta():
    assert is_whatsapp_ip("8.8.8.8") is False


def test_meta_ipv6():
    assert is_whatsapp_ip("2a03:2880::1") is True


def test_malformed_ip_returns_false():
    assert is_whatsapp_ip("not-an-ip") is False
    assert is_whatsapp_ip("") is False


def test_version_mismatch_no_crash():
    # IPv6 addr vs IPv4-only network list must not raise (and the cache must reset).
    load_networks(["157.240.0.0/16"])
    assert is_whatsapp_ip("2a03:2880::1") is False
    load_networks(["157.240.0.0/16", "2a03:2880::/32"])
    assert is_whatsapp_ip("2a03:2880::1") is True
