"""Shared helpers: logging, privilege checks, filesystem setup, output finalisation."""
from __future__ import annotations

import logging
from pathlib import Path

import config
from utils.platform_utils import (  # noqa: F401  (re-exported for callers/tests)
    acquire_wake_lock,
    export_files,
    fix_ownership,
    is_android,
    is_root,
    is_termux,
    is_windows,
    require_root,
    root_help_message,
    setup_ca_bundle,
)

# Backwards-compatible names from the original Windows-only version.
is_admin = is_root
require_admin = require_root


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    # Scapy is chatty on Android (routes, IPv6, libpcap probes). Keep errors only.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    return logging.getLogger("wit")


def ensure_dirs() -> None:
    """Create output/log/data dirs and hand them to the project owner."""
    dirs = (config.LOG_DIR, config.OUTPUT_DIR, config.DATA_DIR)
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    fix_ownership(dirs, ref=config.BASE_DIR, recursive=False)


def report_files() -> list[Path]:
    return [config.CSV_REPORT, config.JSON_REPORT, config.LOG_FILE]


def finalize_outputs(export_dir: str | None = None) -> None:
    """chown everything we wrote back to the Termux user, then optionally export."""
    fix_ownership(
        (config.OUTPUT_DIR, config.LOG_DIR, config.DATA_DIR), ref=config.BASE_DIR
    )
    target = export_dir or config.EXPORT_DIR
    if target:
        export_files(target, report_files())
