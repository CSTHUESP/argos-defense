#!/usr/bin/env bash
# ARGOS Defense launcher (Linux/macOS). Checks prerequisites; changes nothing system-wide.
# Usage: scripts/start.sh [--demo] [--port 8789]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PORT=8789; DEMO=0
while [ $# -gt 0 ]; do case "$1" in --demo) DEMO=1;; --port) PORT="$2"; shift;; *) echo "unknown option $1"; exit 2;; esac; shift; done
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "python3 not found (need >= 3.11)"; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' || { echo "Python >= 3.11 required"; exit 1; }
if [ ! -x .venv/bin/python ]; then
  echo "Creating virtual environment in $ROOT/.venv"
  "$PY" -m venv .venv
  if ! .venv/bin/pip install -r requirements.lock; then
     echo "Dependency install failed (offline?). Retry with: $PY -m venv --system-site-packages .venv  (uses already-installed packages)"; exit 1
  fi
  .venv/bin/pip install --no-deps --no-build-isolation -e .
fi
.venv/bin/python -m argos doctor
[ "$DEMO" = 1 ] && .venv/bin/python -m argos demo
echo "Activate later with:  source .venv/bin/activate"
exec .venv/bin/python -m argos serve --host 127.0.0.1 --port "$PORT"
