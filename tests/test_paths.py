import importlib
from pathlib import Path

import config
from utils import helpers


def test_paths_are_absolute_and_under_project_root():
    root = Path(config.__file__).resolve().parent
    assert config.BASE_DIR == root
    for p in (config.LOG_DIR, config.OUTPUT_DIR, config.DATA_DIR, config.LOG_FILE,
              config.CSV_REPORT, config.JSON_REPORT, config.META_RANGE_CACHE,
              config.GEO_CITY_DB, config.GEO_ASN_DB):
        assert Path(p).is_absolute()
        assert root in Path(p).parents
        assert "\\" not in str(p) or Path("a\\b").name == "b"  # no hardcoded backslash paths on POSIX


def test_resolve_path_is_relative_to_project_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    resolved = config.resolve_path("data/x.mmdb", config.DATA_DIR / "default.mmdb")
    assert resolved == (config.BASE_DIR / "data" / "x.mmdb").resolve()
    assert tmp_path not in resolved.parents


def test_resolve_path_absolute_empty_and_tilde(tmp_path, monkeypatch):
    default = config.DATA_DIR / "d.mmdb"
    assert config.resolve_path("", default) == default
    assert config.resolve_path(None, default) == default
    assert config.resolve_path(str(tmp_path / "a.mmdb"), default) == tmp_path / "a.mmdb"
    monkeypatch.setenv("HOME", str(tmp_path))
    assert config.resolve_path("~/a.mmdb", default) == tmp_path / "a.mmdb"


def test_env_geo_paths_resolve_against_project_root(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GEO_CITY_DB", "data/custom-city.mmdb")
    try:
        importlib.reload(config)
        assert config.GEO_CITY_DB == config.BASE_DIR / "data" / "custom-city.mmdb"
    finally:
        monkeypatch.delenv("GEO_CITY_DB")
        importlib.reload(config)


def test_invalid_numeric_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("WIT_PORT", "not-a-number")
    monkeypatch.setenv("WIT_COUNT", "")
    try:
        importlib.reload(config)
        assert config.DASH_PORT == 8000 and config.DEFAULT_COUNT == 0
    finally:
        monkeypatch.delenv("WIT_PORT")
        monkeypatch.delenv("WIT_COUNT")
        importlib.reload(config)


def test_ensure_dirs_creates_all_three(tmp_path, monkeypatch):
    for name in ("LOG_DIR", "OUTPUT_DIR", "DATA_DIR"):
        monkeypatch.setattr(config, name, tmp_path / name.lower())
    helpers.ensure_dirs()
    assert all((tmp_path / n).is_dir() for n in ("log_dir", "output_dir", "data_dir"))
    helpers.ensure_dirs()  # idempotent
