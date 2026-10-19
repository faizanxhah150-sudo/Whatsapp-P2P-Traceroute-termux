"""The dashboard map must cope with null lat/lon (GeoLite2 missing) without JS errors."""
from pathlib import Path

import config

HTML = (Path(config.BASE_DIR) / "dashboard" / "static" / "index.html").read_text(encoding="utf-8")


def test_map_skips_records_without_coordinates():
    assert "r.latitude == null || r.longitude == null" in HTML
    assert "continue" in HTML.split("r.latitude == null")[1][:80]


def test_no_unguarded_numeric_formatting_of_coordinates():
    assert ".toFixed" not in HTML  # null.toFixed() would throw


def test_network_strings_are_escaped_before_innerhtml():
    assert "function esc(" in HTML
    assert "${r.host||''}" not in HTML and "${r.org||''}" not in HTML
