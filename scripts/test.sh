#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/env.sh"
# Keep tests independent of the user's live daemon and model registry.
MOP_STATE_DIR="$(mktemp -d "$ROOT/.runtime/test-state-XXXXXX")"
export MOP_STATE_DIR
trap 'rm -rf -- "$MOP_STATE_DIR"' EXIT
"$ROOT/.venv/bin/python" -m unittest discover -s "$ROOT/tests" -v "$@"
