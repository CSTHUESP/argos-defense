#!/usr/bin/env bash
# Retrieve the exact ARTEX source reviewed for ARGOS (static research only).
# Does NOT build, install or run anything from it. Submodules and hooks are disabled.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/reference/ARTEX"
COMMIT=a13c68cb7078d43b66fb398db3d610e513b6d77a
if [ -e "$DEST" ]; then echo "$DEST exists; remove it first"; exit 1; fi
git -c core.hooksPath=/dev/null clone --no-recurse-submodules --depth 1 --branch v0.6.0 https://github.com/BaaRai/ARTEX "$DEST"
GOT="$(git -C "$DEST" rev-parse HEAD)"
if [ "$GOT" != "$COMMIT" ]; then echo "ERROR: tag v0.6.0 now points to $GOT, expected $COMMIT - not the reviewed source"; exit 2; fi
echo "OK: $DEST at $COMMIT (AGPL-3.0; research reference only)"
