"""GeoLite2 missing / partial / corrupt: never raise, warn once, keep every field empty-safe."""
import logging
import sys
import types

import pytest

import config
from utils import geo_ip


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def logs():
    logger = logging.getLogger("wit")
    handler = Capture()
    old = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(old)


def warnings_of(handler):
    return [r.getMessage() for r in handler.records if r.levelno >= logging.WARNING]


class Reader:
    def __init__(self, kind):
        self.kind = kind

    def get(self, ip):
        if ip == "bad":
            raise ValueError("bad ip")
        if self.kind == "city":
            return {"country": {"names": {"en": "Ireland"}}, "city": {"names": {"en": "Dublin"}},
                    "location": {"latitude": 53.3, "longitude": -6.2}}
        return {"autonomous_system_number": 32934, "autonomous_system_organization": "FACEBOOK"}

    def close(self):
        pass


def install_fake_maxminddb(monkeypatch, opener=None):
    def default(path):
        return Reader("city" if "city" in path.lower() else "asn")

    fake = types.SimpleNamespace(open_database=opener or default)
    monkeypatch.setitem(sys.modules, "maxminddb", fake)


def point_to(monkeypatch, city, asn):
    monkeypatch.setattr(config, "GEO_CITY_DB", city)
    monkeypatch.setattr(config, "GEO_ASN_DB", asn)
    geo_ip.reset()


EMPTY = {"country": None, "city": None, "latitude": None, "longitude": None, "asn": None, "org": None}


def test_both_databases_missing_logs_one_clear_warning(tmp_path, monkeypatch, logs):
    install_fake_maxminddb(monkeypatch)
    point_to(monkeypatch, tmp_path / "data" / "GeoLite2-City.mmdb", tmp_path / "data" / "GeoLite2-ASN.mmdb")
    for ip in ("157.240.1.5", "8.8.8.8", "2a03:2880::1"):
        info = geo_ip.get_geo_info(ip)
        assert {k: info[k] for k in EMPTY} == EMPTY
    msgs = warnings_of(logs)
    assert len(msgs) == 1                                  # ONE message, not one per DB or lookup
    assert "GeoLite2 DB not found in" in msgs[0] and "data/" in msgs[0]
    assert "city/ASN columns will be blank" in msgs[0] and "docs/TERMUX.md" in msgs[0]


def test_only_city_present(tmp_path, monkeypatch, logs):
    install_fake_maxminddb(monkeypatch)
    city = tmp_path / "GeoLite2-City.mmdb"
    city.write_bytes(b"x")
    point_to(monkeypatch, city, tmp_path / "GeoLite2-ASN.mmdb")
    info = geo_ip.get_geo_info("157.240.1.5")
    assert (info["country"], info["city"], info["latitude"]) == ("Ireland", "Dublin", 53.3)
    assert info["asn"] is None and info["org"] is None
    msgs = warnings_of(logs)
    assert len(msgs) == 1 and "GeoLite2-ASN.mmdb not found" in msgs[0]


def test_only_asn_present(tmp_path, monkeypatch, logs):
    install_fake_maxminddb(monkeypatch)
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    asn.write_bytes(b"x")
    point_to(monkeypatch, tmp_path / "GeoLite2-City.mmdb", asn)
    info = geo_ip.get_geo_info("157.240.1.5")
    assert (info["asn"], info["org"]) == (32934, "FACEBOOK")
    assert info["country"] is None and info["latitude"] is None
    assert len(warnings_of(logs)) == 1


def test_both_present_no_warning(tmp_path, monkeypatch, logs):
    install_fake_maxminddb(monkeypatch)
    for n in ("city", "asn"):
        (tmp_path / f"{n}.mmdb").write_bytes(b"x")
    point_to(monkeypatch, tmp_path / "city.mmdb", tmp_path / "asn.mmdb")
    info = geo_ip.get_geo_info("157.240.1.5")
    assert info["country"] == "Ireland" and info["asn"] == 32934
    assert warnings_of(logs) == []
    assert geo_ip.get_geo_info("bad")["country"] is None   # lookup errors never propagate


def test_corrupt_files_do_not_raise(tmp_path, monkeypatch, logs):
    class InvalidDatabaseError(RuntimeError):
        pass

    def corrupt(path):
        raise InvalidDatabaseError("Error opening database file. Is this a valid MaxMind DB file?")

    install_fake_maxminddb(monkeypatch, corrupt)
    for n in ("city", "asn"):
        (tmp_path / f"{n}.mmdb").write_bytes(b"garbage, not a database")
    point_to(monkeypatch, tmp_path / "city.mmdb", tmp_path / "asn.mmdb")
    info = geo_ip.get_geo_info("157.240.1.5")
    assert {k: info[k] for k in EMPTY} == EMPTY
    msgs = warnings_of(logs)
    assert len(msgs) == 1 and "unreadable/corrupt" in msgs[0] and "InvalidDatabaseError" in msgs[0]


def test_one_corrupt_one_good(tmp_path, monkeypatch, logs):
    def opener(path):
        if "asn" in path.lower():
            raise ValueError("corrupt")
        return Reader("city")

    install_fake_maxminddb(monkeypatch, opener)
    for n in ("city", "asn"):
        (tmp_path / f"{n}.mmdb").write_bytes(b"x")
    point_to(monkeypatch, tmp_path / "city.mmdb", tmp_path / "asn.mmdb")
    info = geo_ip.get_geo_info("157.240.1.5")
    assert info["country"] == "Ireland" and info["asn"] is None
    assert len(warnings_of(logs)) == 1


def test_unreadable_file_permission_error(tmp_path, monkeypatch, logs):
    def opener(path):
        raise PermissionError(13, "Permission denied")

    install_fake_maxminddb(monkeypatch, opener)
    for n in ("city", "asn"):
        (tmp_path / f"{n}.mmdb").write_bytes(b"x")
    point_to(monkeypatch, tmp_path / "city.mmdb", tmp_path / "asn.mmdb")
    assert geo_ip.get_geo_info("1.2.3.4")["country"] is None
    assert len(warnings_of(logs)) == 1


def test_reader_that_explodes_on_lookup_is_contained(tmp_path, monkeypatch):
    class Exploding:
        def get(self, ip):
            raise RuntimeError("corrupt record")

        def close(self):
            pass

    install_fake_maxminddb(monkeypatch, lambda path: Exploding())
    for n in ("city", "asn"):
        (tmp_path / f"{n}.mmdb").write_bytes(b"x")
    point_to(monkeypatch, tmp_path / "city.mmdb", tmp_path / "asn.mmdb")
    assert geo_ip.get_geo_info("1.2.3.4")["asn"] is None


def test_maxminddb_module_missing_is_not_fatal(monkeypatch, tmp_path, logs):
    import builtins

    p = tmp_path / "x.mmdb"
    p.write_bytes(b"x")
    point_to(monkeypatch, p, p)
    real_import = builtins.__import__

    def blocker(name, *a, **k):
        if name == "maxminddb":
            raise ImportError("not installed")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocker)
    assert geo_ip.get_geo_info("1.2.3.4")["asn"] is None
    msgs = warnings_of(logs)
    assert len(msgs) == 1 and "maxminddb" in msgs[0]


def test_pipeline_works_end_to_end_without_databases(tmp_path, monkeypatch):
    """Capture, scoring, CSV/JSON and PCAP all keep working with blank GeoLite2 columns."""
    import csv
    import json

    from core.ip_filter import load_networks
    from core.packet_sniffer import PacketSniffer
    from core.reporting import write_rows
    from tests.frames import udp4

    install_fake_maxminddb(monkeypatch)
    point_to(monkeypatch, tmp_path / "none-city.mmdb", tmp_path / "none-asn.mmdb")
    load_networks(["157.240.0.0/16"])
    s = PacketSniffer(log_file=tmp_path / "x.pcap", bpf="")
    assert s.process_frame(udp4("10.1.2.3", "157.240.1.5", 40000, 40001), "raw", "out")
    assert s.process_frame(udp4("10.1.2.3", "45.55.100.10", 40000, 50002), "raw", "out")
    s.save_packets()
    rows = s.rows()
    peer = next(r for r in rows if r["remote"] == "45.55.100.10")
    assert peer["candidate_peer"] is True and peer["max_score"] == 90
    assert peer["country"] in ("", None) and peer["latitude"] is None
    write_rows(rows, tmp_path / "r.csv", tmp_path / "r.json")
    with open(tmp_path / "r.csv", newline="") as f:
        first = next(csv.DictReader(f))
    assert first["country"] == "" and first["latitude"] == ""
    assert json.loads((tmp_path / "r.json").read_text())[0]["latitude"] is None
    assert (tmp_path / "x.pcap").stat().st_size > 24


def test_missing_module_message_is_not_repeated(monkeypatch, tmp_path, logs):
    import builtins

    p = tmp_path / "x.mmdb"
    p.write_bytes(b"x")
    point_to(monkeypatch, p, p)
    real_import = builtins.__import__

    def blocker(name, *a, **k):
        if name == "maxminddb":
            raise ImportError("not installed")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocker)
    geo_ip.get_geo_info("1.2.3.4")
    assert warnings_of(logs)[0].count("maxminddb Python module not installed") == 1
