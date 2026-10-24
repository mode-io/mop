# Source from bash: source scripts/env.sh
MOP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export MOP_ROOT
mkdir -p "$MOP_ROOT/.cache" "$MOP_ROOT/.runtime" "$MOP_ROOT/artifacts"
# Preserve the existing env file and its values; never echo them.
if [ -f "$MOP_ROOT/.env" ]; then
    set -a
    source "$MOP_ROOT/.env"
    set +a
fi
export UV_CACHE_DIR="$MOP_ROOT/.cache/uv"
export PIP_CACHE_DIR="$MOP_ROOT/.cache/pip"
export TMPDIR="$MOP_ROOT/.runtime"
export PYTHONPATH="$MOP_ROOT${PYTHONPATH:+:$PYTHONPATH}"
# Generic OPENAI_* credentials are intentionally not selected by the guard.

# Session-local command entrypoints; no shell profile changes.
export PATH="$MOP_ROOT/.venv/bin:$PATH"
