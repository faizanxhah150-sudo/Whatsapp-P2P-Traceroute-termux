#!/usr/bin/env bash
# Idempotent Termux installer. Safe to re-run.
#   bash scripts/termux_setup.sh [--no-dashboard] [--skip-pkg]
# Run it as the NORMAL Termux user (not through su/tsu) so the venv is owned by Termux.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/.venv"
WITH_DASHBOARD=1
SKIP_PKG=0

for arg in "$@"; do
  case "$arg" in
    --no-dashboard) WITH_DASHBOARD=0 ;;
    --skip-pkg) SKIP_PKG=1 ;;
    -h|--help) sed -n '2,5p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mWARN: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

case "${PREFIX:-}" in
  *com.termux*) ;;
  *) die "This script is for Termux (PREFIX does not contain com.termux). On desktop Linux use: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dashboard.txt" ;;
esac
[ "$(id -u)" = "0" ] && die "Run this as the normal Termux user, not root (no su/tsu). Root is only used by scripts/run_root.sh."

if [ "$SKIP_PKG" = "0" ]; then
  say "Updating Termux packages"
  export DEBIAN_FRONTEND=noninteractive
  pkg update -y || warn "pkg update failed (mirror problem? try 'termux-change-repo')"
  pkg upgrade -y -o Dpkg::Options::="--force-confold" || warn "pkg upgrade reported problems"

  say "Enabling the root repository"
  pkg install -y root-repo || warn "root-repo not installed"
  pkg update -y || true

  say "Installing required packages"
  for p in python git; do
    pkg install -y "$p" || die "Could not install required package: $p"
  done
  # python-pip is the Termux-packaged pip. NEVER 'pip install -U pip' in Termux.
  pkg install -y python-pip || warn "python-pip not installed/upgraded"

  say "Installing build + capture helpers (non-fatal if one is missing)"
  for p in clang make libffi openssl libxml2 libxslt tcpdump libpcap tsu; do
    pkg install -y "$p" || warn "package '$p' not installed (verify: pkg search $p)"
  done

  say "Installing optional Termux:API command-line tools"
  pkg install -y termux-api || warn "termux-api not installed (optional; wake-lock still works via termux-tools if present)"
else
  warn "Skipping pkg steps (--skip-pkg)"
fi

command -v python >/dev/null 2>&1 || die "python not found. Run without --skip-pkg."

say "Creating virtual environment (--system-site-packages) in $VENV"
if [ ! -x "$VENV/bin/python" ]; then
  python -m venv --system-site-packages "$VENV" || die "venv creation failed"
else
  echo "venv already exists - reusing"
fi
# shellcheck disable=SC1091
. "$VENV/bin/activate" || die "cannot activate venv"

say "Installing Python requirements (core)"
if ! pip install -r "$ROOT/requirements.txt"; then
  warn "Bulk install failed; retrying package by package"
  failed=""
  while IFS= read -r line; do
    case "$line" in ""|\#*) continue ;; esac
    pip install "$line" || failed="$failed $line"
  done < "$ROOT/requirements.txt"
  case "$failed" in
    *scapy*|*requests*|*dotenv*) die "Core requirements failed:$failed (see docs/TERMUX.md > Troubleshooting)" ;;
    "") ;;
    *) warn "Optional packages not installed:$failed (tool still runs; e.g. no GeoLite2 enrichment)" ;;
  esac
fi

if [ "$WITH_DASHBOARD" = "1" ]; then
  say "Installing dashboard requirements"
  pip install -r "$ROOT/requirements-dashboard.txt" \
    || warn "Dashboard requirements failed. CLI still works. See docs/TERMUX.md > Troubleshooting."
fi

say "Preparing project folders"
mkdir -p "$ROOT/output" "$ROOT/logs" "$ROOT/data"
[ -f "$ROOT/.env" ] || cp "$ROOT/.env.example" "$ROOT/.env"
chmod +x "$ROOT/scripts/"*.sh 2>/dev/null || true

say "Done. Next steps"
cat <<MSG
  1. (Optional) shared storage access:   termux-setup-storage
  2. (Optional) GeoLite2 databases:      copy GeoLite2-City.mmdb and GeoLite2-ASN.mmdb into  $ROOT/data/
  3. Check root:                         su -c id        (expect uid=0)
  4. Preflight (as root):                bash scripts/run_root.sh --list-ifaces
                                         bash scripts/run_root.sh --check-env
  5. Capture:                            bash scripts/run_root.sh --count 500
  Full guide: docs/TERMUX.md
MSG
