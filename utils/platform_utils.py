"""Platform detection, privilege checks and Android/Termux helpers.

Only the standard library is used here so these helpers work before any
third-party dependency is installed (``scripts/check_env.py`` relies on it).
"""
from __future__ import annotations

import atexit
import logging
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Mapping

log = logging.getLogger("wit")

TERMUX_DEFAULT_PREFIX = "/data/data/com.termux/files/usr"

# Kernel interface info used for capability checks (module-level so tests can redirect them).
SYS_CLASS_NET = "/sys/class/net"
PROC_NET_DEV_PATH = "/proc/net/dev"


# --- Platform detection ----------------------------------------------------
# Single source of truth: no other module may inspect sys.platform / platform.system().
# Python 3.13+ (PEP 738) reports sys.platform == "android" on Android, older builds say "linux".
def is_windows() -> bool:
    return sys.platform == "win32"


def is_macos() -> bool:
    return sys.platform == "darwin"


def is_android_platform(env: Mapping[str, str] | None = None) -> bool:
    """True on Android: sys.platform == 'android' (3.13+), Termux, or Android env vars."""
    env = os.environ if env is None else env
    return (
        sys.platform == "android"
        or is_termux(env)
        or bool(env.get("ANDROID_ROOT") or env.get("ANDROID_DATA"))
    )


def is_android_python_build() -> bool:
    """True when this interpreter itself is an Android build (sys.platform == 'android', 3.13+)."""
    return sys.platform == "android"


def is_linux() -> bool:
    """True on desktop Linux *and* Android ('linux' on <=3.12 builds, 'android' on 3.13+)."""
    return sys.platform.startswith("linux") or sys.platform == "android"


def platform_summary() -> dict:
    """Diagnostic facts for check_env / bug reports."""
    return {
        "sys.platform": sys.platform,
        "platform.system()": platform.system() or "?",
        "python": platform.python_version(),
        "is_linux": is_linux(),
        "is_android_platform": is_android_platform(),
        "is_termux": is_termux(),
    }


def netif_available() -> bool:
    """Can we enumerate interfaces from the kernel (/sys/class/net or /proc/net/dev)?"""
    return os.path.isdir(SYS_CLASS_NET) or os.access(PROC_NET_DEV_PATH, os.R_OK)


def af_packet_supported() -> bool:
    """Capability check (never the OS name): AF_PACKET exists and the kernel exposes interfaces."""
    return hasattr(socket, "AF_PACKET") and netif_available()


def find_tcpdump() -> str | None:
    """Locate tcpdump on PATH, then in $PREFIX/bin (Termux)."""
    exe = shutil.which("tcpdump")
    if exe:
        return exe
    candidate = termux_prefix() / "bin" / "tcpdump"
    if os.access(candidate, os.X_OK) and candidate.is_file():
        return str(candidate)
    return None


def is_termux(env: Mapping[str, str] | None = None) -> bool:
    """Termux sets PREFIX=/data/data/com.termux/files/usr and TERMUX_VERSION."""
    env = os.environ if env is None else env
    return "com.termux" in env.get("PREFIX", "") or bool(env.get("TERMUX_VERSION"))


def is_android(env: Mapping[str, str] | None = None) -> bool:
    """Kept for existing callers; same as is_android_platform()."""
    return is_android_platform(env)


def termux_prefix(env: Mapping[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("PREFIX") or TERMUX_DEFAULT_PREFIX)


# --- Privileges ------------------------------------------------------------
def is_root() -> bool:
    """Root on POSIX (euid 0), Administrator on Windows."""
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def root_help_message() -> str:
    if is_windows():
        return (
            "Packet capture needs Administrator rights. Re-run from an elevated "
            "terminal (and install Npcap for the scapy backend)."
        )
    if is_termux() or is_android():
        return (
            "Packet capture needs root. Launch through the root launcher:\n"
            "    bash scripts/run_root.sh <options>\n"
            "or open a root shell first with `tsu` (or `su`) and run the launcher "
            "there. Check root with `su -c id` (expect uid=0) and make sure Termux "
            "is granted in Magisk > Superuser."
        )
    return "Packet capture needs root. Re-run with sudo (or grant CAP_NET_RAW)."


def require_root(logger: logging.Logger | None = None) -> None:
    """Exit with an actionable message when not privileged."""
    if is_root():
        return
    (logger or log).error("Not running as root. %s", root_help_message())
    sys.exit(1)


# --- TLS / CA bundle -------------------------------------------------------
def ca_bundle_candidates(env: Mapping[str, str] | None = None) -> list[Path]:
    prefix = termux_prefix(env)
    candidates = [
        prefix / "etc" / "tls" / "cert.pem",
        prefix / "etc" / "ssl" / "cert.pem",
        Path("/etc/ssl/certs/ca-certificates.crt"),
        Path("/etc/ssl/cert.pem"),
    ]
    try:
        import certifi

        candidates.append(Path(certifi.where()))
    except Exception:
        pass
    return candidates


def _default_ca_available(verify_paths) -> bool:
    cafile = getattr(verify_paths, "cafile", None)
    capath = getattr(verify_paths, "capath", None)
    return bool(
        (cafile and Path(cafile).is_file()) or (capath and Path(capath).is_dir())
    )


def setup_ca_bundle(env: dict | None = None, verify_paths=None) -> str | None:
    """Point SSL_CERT_FILE / REQUESTS_CA_BUNDLE at a real CA file if needed.

    Android root shells often lose the CA store that Termux's Python expects.
    Returns the file that was configured, or None when nothing had to change.
    """
    target = os.environ if env is None else env
    configured = target.get("SSL_CERT_FILE")
    if configured and Path(configured).is_file():
        requests_bundle = target.get("REQUESTS_CA_BUNDLE")
        if not requests_bundle or not Path(requests_bundle).is_file():
            target["REQUESTS_CA_BUNDLE"] = configured
        return None

    verify_paths = verify_paths or ssl.get_default_verify_paths()
    if _default_ca_available(verify_paths):
        return None

    for candidate in ca_bundle_candidates(target):
        if candidate.is_file():
            target["SSL_CERT_FILE"] = str(candidate)
            target["REQUESTS_CA_BUNDLE"] = str(candidate)
            log.debug("Using CA bundle %s", candidate)
            return str(candidate)
    log.warning("No CA bundle found; HTTPS requests (RIPEstat refresh) may fail.")
    return None


# --- Termux keep-alive -----------------------------------------------------
_wake_lock_held = False


def release_wake_lock(runner=subprocess.run) -> None:
    global _wake_lock_held
    if not _wake_lock_held:
        return
    _wake_lock_held = False
    exe = shutil.which("termux-wake-unlock")
    if exe:
        try:
            runner([exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=5, check=False)
        except Exception:
            pass


def acquire_wake_lock(runner=subprocess.run) -> bool:
    """Call ``termux-wake-lock`` when available; silent no-op otherwise."""
    global _wake_lock_held
    exe = shutil.which("termux-wake-lock")
    if not exe:
        return False
    try:
        runner([exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
               timeout=5, check=False)
    except Exception:
        return False
    if not _wake_lock_held:
        _wake_lock_held = True
        atexit.register(release_wake_lock)
    return True


# --- File ownership (root-created files -> Termux app user) ----------------
def reference_owner(ref: str | os.PathLike) -> tuple[int, int] | None:
    try:
        st = os.stat(ref)
    except OSError:
        return None
    return st.st_uid, st.st_gid


def _iter_targets(paths: Iterable[str | os.PathLike], recursive: bool):
    for raw in paths:
        path = Path(raw)
        if not path.exists() and not path.is_symlink():
            continue
        yield path
        if recursive and path.is_dir() and not path.is_symlink():
            for child in path.rglob("*"):
                yield child


def fix_ownership(paths: Iterable[str | os.PathLike], ref: str | os.PathLike | None = None,
                  recursive: bool = True) -> int:
    """chown ``paths`` to the owner of ``ref`` (the project dir by default).

    Only acts when running as root and the reference owner is not root, so
    files created through ``su`` stay readable/deletable by the Termux user.
    Returns how many entries were changed.
    """
    if not hasattr(os, "chown") or not is_root():
        return 0
    if ref is None:
        import config

        ref = config.BASE_DIR
    owner = reference_owner(ref)
    if owner is None or owner[0] == 0:
        return 0
    uid, gid = owner
    changed = 0
    for target in _iter_targets(paths, recursive):
        if target.is_symlink():
            continue
        try:
            os.chown(target, uid, gid)
            changed += 1
        except OSError as exc:
            log.debug("chown %s failed: %s", target, exc)
    if changed and is_android():
        _restorecon(paths)
    return changed


def _restorecon(paths: Iterable[str | os.PathLike], runner=subprocess.run) -> None:
    """Best effort: relabel files so the app's SELinux domain can read them."""
    exe = shutil.which("restorecon")
    if not exe:
        return
    for raw in paths:
        try:
            runner([exe, "-R", str(raw)], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=15, check=False)
        except Exception:
            pass


# --- Optional export (e.g. /sdcard/WhatsAppP2P) ----------------------------
def export_files(export_dir: str | os.PathLike, files: Iterable[str | os.PathLike]) -> list[Path]:
    """Copy report/pcap files into ``export_dir``. Never raises."""
    dest = Path(export_dir).expanduser()
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning(
            "Cannot create export dir %s (%s). On Android run `termux-setup-storage` "
            "or try /sdcard/<name> / /storage/emulated/0/<name>.", dest, exc,
        )
        return []
    copied: list[Path] = []
    for raw in files:
        src = Path(raw)
        if not src.is_file():
            continue
        target = dest / src.name
        try:
            shutil.copyfile(src, target)  # copyfile: no chmod, works on FUSE storage
            copied.append(target)
        except OSError as exc:
            log.warning("Could not export %s: %s", src, exc)
    if copied:
        log.info("Exported %d file(s) to %s", len(copied), dest)
    return copied
