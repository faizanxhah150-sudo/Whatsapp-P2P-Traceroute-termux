#!/usr/bin/env bash
# Root launcher for Termux (Magisk). Works from a normal shell (uses `su -c`) or
# from inside a root shell you opened with `tsu` / `su`.
#
#   bash scripts/run_root.sh --list-ifaces
#   bash scripts/run_root.sh --count 500
#   bash scripts/run_root.sh --check-env          # runs scripts/check_env.py as root
#   bash scripts/run_root.sh --dashboard
set -u

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="$(cd "$(dirname "$SCRIPT")/.." && pwd)"

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
TERMUX_HOME="${HOME:-/data/data/com.termux/files/home}"
VENV="$ROOT/.venv"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------- inner (root) part
run_inner() {
  export PREFIX
  export HOME="${WIT_HOME:-$TERMUX_HOME}"
  export PATH="$PREFIX/bin:$PREFIX/bin/applets:${PATH:-/system/bin}"
  export LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export TMPDIR="${TMPDIR:-$PREFIX/tmp}"
  export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
  if [ -z "${SSL_CERT_FILE:-}" ] || [ ! -f "${SSL_CERT_FILE:-}" ]; then
    export SSL_CERT_FILE="$PREFIX/etc/tls/cert.pem"
  fi
  export REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-$SSL_CERT_FILE}"
  export TERMUX_VERSION="${TERMUX_VERSION:-1}"

  mkdir -p "$TMPDIR" 2>/dev/null || true
  [ -f "$VENV/bin/activate" ] || die "venv not found at $VENV. Run: bash scripts/termux_setup.sh"
  # shellcheck disable=SC1091
  . "$VENV/bin/activate" || die "cannot activate $VENV"
  cd "$ROOT" || die "cannot cd to $ROOT"

  if [ "${1:-}" = "--check-env" ]; then
    shift
    exec python scripts/check_env.py "$@"
  fi
  exec python main.py "$@"
}

if [ "${WIT_ROOT_INNER:-0}" = "1" ] || [ "$(id -u)" = "0" ]; then
  run_inner "$@"
fi

# ---------------------------------------------------------------- outer (normal user) part
# --help needs no privileges.
for a in "$@"; do
  case "$a" in -h|--help) WIT_ROOT_INNER=1 run_inner "$@" ;; esac
done

SU=""
for c in "$(command -v su 2>/dev/null)" /system/bin/su /system/xbin/su /sbin/su /su/bin/su \
         /debug_ramdisk/su /data/adb/ksu/bin/su /data/adb/magisk/su; do
  if [ -n "$c" ] && [ -x "$c" ]; then SU="$c"; break; fi
done
[ -n "$SU" ] || die "No 'su' binary found. This phone is not rooted, or root is hidden from Termux.
Install/enable Magisk and grant Termux in Magisk > Superuser, then test:  su -c id"

if ! "$SU" -c id 2>/dev/null | grep -q 'uid=0'; then
  die "'su' exists but did not grant root (expected uid=0 from: su -c id).
Open Magisk > Superuser, allow Termux (and accept the prompt on screen), then retry."
fi

# Build one safely-quoted command string for `su -c` (arguments survive spaces/quotes).
CMD="$(printf '%q ' env \
  WIT_ROOT_INNER=1 \
  "PREFIX=$PREFIX" \
  "WIT_HOME=$TERMUX_HOME" \
  "PATH=$PREFIX/bin:$PREFIX/bin/applets:${PATH:-}" \
  "LD_LIBRARY_PATH=$PREFIX/lib" \
  "TMPDIR=$PREFIX/tmp" \
  "SSL_CERT_FILE=${SSL_CERT_FILE:-$PREFIX/etc/tls/cert.pem}" \
  "$PREFIX/bin/bash" "$SCRIPT" "$@")"

exec "$SU" -c "$CMD"
