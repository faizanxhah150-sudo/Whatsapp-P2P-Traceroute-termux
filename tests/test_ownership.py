"""chown helper (mocked: tests never need root), export, wake-lock."""
import os

import config
from utils import helpers
from utils import platform_utils as pu


def _setup(tmp_path, monkeypatch, root=True, owner=(10234, 10234)):
    chowned = []
    monkeypatch.setattr(os, "chown", lambda p, uid, gid: chowned.append((str(p), uid, gid)))
    monkeypatch.setattr(pu, "is_root", lambda: root)
    monkeypatch.setattr(pu, "reference_owner", lambda _ref: owner)
    monkeypatch.setattr(pu, "is_android", lambda env=None: False)
    out = tmp_path / "output"
    (out / "sub").mkdir(parents=True)
    (out / "a.csv").write_text("x")
    (out / "sub" / "b.json").write_text("y")
    return out, chowned


def test_chowns_tree_to_project_owner(tmp_path, monkeypatch):
    out, chowned = _setup(tmp_path, monkeypatch)
    n = pu.fix_ownership([out], ref=tmp_path)
    paths = {p for p, _, _ in chowned}
    assert {str(out), str(out / "a.csv"), str(out / "sub"), str(out / "sub" / "b.json")} <= paths
    assert all((uid, gid) == (10234, 10234) for _, uid, gid in chowned)
    assert n == len(chowned) == 4


def test_noop_when_not_root(tmp_path, monkeypatch):
    out, chowned = _setup(tmp_path, monkeypatch, root=False)
    assert pu.fix_ownership([out], ref=tmp_path) == 0 and chowned == []


def test_noop_when_project_is_owned_by_root(tmp_path, monkeypatch):
    out, chowned = _setup(tmp_path, monkeypatch, owner=(0, 0))
    assert pu.fix_ownership([out], ref=tmp_path) == 0 and chowned == []


def test_noop_when_reference_missing(tmp_path, monkeypatch):
    out, chowned = _setup(tmp_path, monkeypatch, owner=None)
    assert pu.fix_ownership([out], ref=tmp_path) == 0 and chowned == []


def test_non_recursive_and_missing_paths(tmp_path, monkeypatch):
    out, chowned = _setup(tmp_path, monkeypatch)
    pu.fix_ownership([out, tmp_path / "nope"], ref=tmp_path, recursive=False)
    assert [p for p, _, _ in chowned] == [str(out)]


def test_chown_errors_are_swallowed(tmp_path, monkeypatch):
    out, _ = _setup(tmp_path, monkeypatch)

    def deny(_p, _u, _g):
        raise PermissionError("fuse")

    monkeypatch.setattr(os, "chown", deny)
    assert pu.fix_ownership([out], ref=tmp_path) == 0  # must not raise


def test_symlinks_are_not_followed(tmp_path, monkeypatch):
    out, chowned = _setup(tmp_path, monkeypatch)
    (out / "link").symlink_to(tmp_path)
    pu.fix_ownership([out], ref=tmp_path)
    assert str(out / "link") not in {p for p, _, _ in chowned}


def test_reference_owner_reads_stat(tmp_path):
    uid, gid = pu.reference_owner(tmp_path)
    assert (uid, gid) == (tmp_path.stat().st_uid, tmp_path.stat().st_gid)
    assert pu.reference_owner(tmp_path / "missing") is None


def test_finalize_outputs_chowns_project_dirs_and_exports(tmp_path, monkeypatch):
    chowned = []
    monkeypatch.setattr(pu, "is_root", lambda: True)
    monkeypatch.setattr(pu, "is_android", lambda env=None: False)
    monkeypatch.setattr(pu, "reference_owner", lambda _r: (1000, 1000))
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowned.append(str(p)))
    for name in ("LOG_DIR", "OUTPUT_DIR", "DATA_DIR"):
        d = tmp_path / name.lower()
        d.mkdir()
        monkeypatch.setattr(config, name, d)
    monkeypatch.setattr(config, "CSV_REPORT", tmp_path / "output_dir" / "ip_report.csv")
    monkeypatch.setattr(config, "JSON_REPORT", tmp_path / "output_dir" / "ip_report.json")
    monkeypatch.setattr(config, "LOG_FILE", tmp_path / "log_dir" / "packet_logs.pcap")
    config.CSV_REPORT.write_text("remote\n")
    config.LOG_FILE.write_bytes(b"pcap")
    export = tmp_path / "sdcard" / "WhatsAppP2P"
    helpers.finalize_outputs(str(export))
    assert str(config.CSV_REPORT) in chowned
    assert (export / "ip_report.csv").read_text() == "remote\n"
    assert (export / "packet_logs.pcap").read_bytes() == b"pcap"
    assert not (export / "ip_report.json").exists()  # missing files are skipped quietly


def test_export_failure_is_not_fatal(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("not a dir")
    assert pu.export_files(blocker / "sub", [tmp_path / "x"]) == []


def test_wake_lock_is_optional_and_silent(monkeypatch):
    monkeypatch.setattr(pu.shutil, "which", lambda _n: None)
    assert pu.acquire_wake_lock() is False

    calls = []
    monkeypatch.setattr(pu.shutil, "which", lambda n: f"/bin/{n}")
    monkeypatch.setattr(pu.atexit, "register", lambda fn: None)
    monkeypatch.setattr(pu, "_wake_lock_held", False)
    assert pu.acquire_wake_lock(runner=lambda cmd, **k: calls.append(cmd)) is True
    assert calls == [["/bin/termux-wake-lock"]]
    pu.release_wake_lock(runner=lambda cmd, **k: calls.append(cmd))
    assert calls[-1] == ["/bin/termux-wake-unlock"]


def test_wake_lock_swallows_runner_errors(monkeypatch):
    monkeypatch.setattr(pu.shutil, "which", lambda n: f"/bin/{n}")

    def boom(*a, **k):
        raise OSError("no termux services")

    assert pu.acquire_wake_lock(runner=boom) is False


def test_ca_bundle_fallback_to_termux_prefix(tmp_path):
    cert = tmp_path / "etc" / "tls" / "cert.pem"
    cert.parent.mkdir(parents=True)
    cert.write_text("PEM")
    env = {"PREFIX": str(tmp_path)}

    class NoStore:
        cafile = "/nonexistent/cert.pem"
        capath = "/nonexistent"

    assert pu.setup_ca_bundle(env, verify_paths=NoStore()) == str(cert)
    assert env["SSL_CERT_FILE"] == env["REQUESTS_CA_BUNDLE"] == str(cert)


def test_ca_bundle_untouched_when_store_exists(tmp_path):
    cert = tmp_path / "ca.pem"
    cert.write_text("PEM")
    env = {"SSL_CERT_FILE": str(cert)}
    assert pu.setup_ca_bundle(env) is None
    assert env["REQUESTS_CA_BUNDLE"] == str(cert)
