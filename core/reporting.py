"""Aggregate FlowRecords into per-IP summaries and write CSV + JSON reports."""
from __future__ import annotations

import csv
import json
import logging
import threading
from pathlib import Path

import config

log = logging.getLogger("wit")

CSV_FIELDS = [
    "remote", "packets", "bytes", "protocols", "ports", "is_meta",
    "candidate_peer", "max_score", "host", "asn", "org",
    "country", "city", "latitude", "longitude", "first_seen", "last_seen",
]

_FILL_FIELDS = ("host", "asn", "org", "country", "city", "latitude", "longitude")
# Reverse DNS arrives after the first packets, so a flow can start out looking
# like a candidate peer and later turn out to be a Meta host. Cap such scores.
_META_SCORE_CAP = 30


class Aggregator:
    """Incremental per-remote aggregation (bounded memory for long captures)."""

    def __init__(self):
        self._agg: dict[str, dict] = {}
        self._lock = threading.Lock()

    def add(self, r: dict) -> None:
        key = r["remote"]
        with self._lock:
            a = self._agg.get(key)
            if a is None:
                a = self._agg[key] = {
                    "remote": key, "packets": 0, "bytes": 0,
                    "protocols": set(), "ports": set(),
                    "is_meta": False, "candidate_peer": False, "max_score": 0,
                    "host": r.get("host"), "asn": r.get("asn"), "org": r.get("org"),
                    "country": r.get("country"), "city": r.get("city"),
                    "latitude": r.get("latitude"), "longitude": r.get("longitude"),
                    "first_seen": r["ts"], "last_seen": r["ts"],
                }
            a["packets"] += 1
            a["bytes"] += r["length"]
            a["protocols"].add(r["proto"])
            a["ports"].add(r["dport"])
            a["is_meta"] = a["is_meta"] or bool(r["is_meta"])
            a["candidate_peer"] = a["candidate_peer"] or bool(r["candidate_peer"])
            a["max_score"] = max(a["max_score"], r["score"])
            a["first_seen"] = min(a["first_seen"], r["ts"])
            a["last_seen"] = max(a["last_seen"], r["ts"])
            for f in _FILL_FIELDS:
                if a[f] in (None, "") and r.get(f) not in (None, ""):
                    a[f] = r[f]

    def snapshot(self) -> dict[str, dict]:
        with self._lock:
            out = {}
            for key, a in self._agg.items():
                c = dict(a)
                c["protocols"] = set(a["protocols"])
                c["ports"] = set(a["ports"])
                if c["is_meta"]:
                    c["candidate_peer"] = False
                    c["max_score"] = min(c["max_score"], _META_SCORE_CAP)
                out[key] = c
            return out

    def rows(self) -> list[dict]:
        rows = [serialize(a) for a in self.snapshot().values()]
        rows.sort(key=lambda r: r["max_score"], reverse=True)
        return rows


def aggregate(records) -> dict[str, dict]:
    """records: list of dicts (FlowRecord.to_dict()). Returns per-remote summary."""
    agg = Aggregator()
    for r in records:
        agg.add(r)
    return agg.snapshot()


def serialize(a: dict) -> dict:
    d = dict(a)
    d["protocols"] = ",".join(sorted(d["protocols"]))
    d["ports"] = ",".join(str(p) for p in sorted(d["ports"]))
    return d


_serializable = serialize  # old private name, kept for compatibility


def write_rows(rows: list[dict], csv_path=None, json_path=None) -> list[dict]:
    csv_path = Path(csv_path or config.CSV_REPORT)
    json_path = Path(json_path or config.JSON_REPORT)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in CSV_FIELDS})

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    log.info("Wrote %d unique remotes to %s and %s", len(rows), csv_path, json_path)
    return rows


def write_reports(records, csv_path=None, json_path=None) -> list[dict]:
    agg = Aggregator()
    for r in records:
        agg.add(r)
    return write_rows(agg.rows(), csv_path=csv_path, json_path=json_path)
