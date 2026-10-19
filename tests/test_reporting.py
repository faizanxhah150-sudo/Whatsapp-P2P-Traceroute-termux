import csv
import json

from core.reporting import Aggregator, aggregate, write_reports


def _rec(remote, length, proto="UDP", dport=50000, meta=False, peer=False, score=0,
         ts="2026-01-01T00:00:00+00:00", host="", org="Meta"):
    return {
        "ts": ts, "src": "192.168.1.5", "dst": remote, "remote": remote,
        "proto": proto, "sport": 40000, "dport": dport, "length": length,
        "is_meta": meta, "host": host, "country": "US", "city": "NY",
        "latitude": 1.0, "longitude": 2.0, "asn": 32934, "org": org,
        "candidate_peer": peer, "score": score,
    }


def test_aggregate_counts_and_bytes():
    recs = [_rec("157.240.1.5", 100), _rec("157.240.1.5", 200)]
    agg = aggregate(recs)
    a = agg["157.240.1.5"]
    assert a["packets"] == 2
    assert a["bytes"] == 300


def test_write_reports_creates_files(tmp_path):
    recs = [_rec("203.0.113.9", 120, peer=True, score=90), _rec("157.240.1.5", 80, meta=True)]
    csv_p = tmp_path / "r.csv"
    json_p = tmp_path / "r.json"
    rows = write_reports(recs, csv_path=csv_p, json_path=json_p)
    assert csv_p.exists() and json_p.exists()
    # Highest score first.
    assert rows[0]["remote"] == "203.0.113.9"
    data = json.loads(json_p.read_text())
    assert len(data) == 2
    with open(csv_p, newline="", encoding="utf-8") as f:
        assert next(csv.DictReader(f))["remote"] == "203.0.113.9"


def test_write_reports_creates_missing_parent_dirs(tmp_path):
    out = tmp_path / "deep" / "er"
    write_reports([_rec("1.2.3.4", 10)], csv_path=out / "a.csv", json_path=out / "a.json")
    assert (out / "a.csv").exists()


def test_late_reverse_dns_demotes_false_peer():
    # First packets look like a peer (rDNS pending); a later packet reveals a Meta host.
    agg = Aggregator()
    agg.add(_rec("31.13.99.9", 100, peer=True, score=90))
    agg.add(_rec("31.13.99.9", 100, meta=True, score=30, host="edge.whatsapp.net"))
    row = agg.rows()[0]
    assert row["is_meta"] is True
    assert row["candidate_peer"] is False
    assert row["max_score"] <= 30
    assert row["host"] == "edge.whatsapp.net"  # filled in from the later record
