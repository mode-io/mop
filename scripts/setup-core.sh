#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/env.sh"
# Install the pinned capture dependency in the project environment only.
if [ ! -x "$ROOT/.venv/bin/python" ]; then
    /usr/bin/python3 -m venv --without-pip "$ROOT/.venv"
fi
if ! "$ROOT/.venv/bin/python" -c 'import importlib.metadata; assert importlib.metadata.version("viztracer") == "1.1.1"; assert importlib.metadata.version("tokenizers") == "0.22.2"' >/dev/null 2>&1; then
    if command -v uv >/dev/null 2>&1; then
        uv pip install --python "$ROOT/.venv/bin/python" 'viztracer==1.1.1' 'tokenizers==0.22.2'
    else
        "$ROOT/.venv/bin/python" -m ensurepip --upgrade
        "$ROOT/.venv/bin/python" -m pip install 'viztracer==1.1.1' 'tokenizers==0.22.2'
    fi
fi
for command in mop hmop bmop mop-network; do
    ln -sfn "$ROOT/scripts/$command" "$ROOT/.venv/bin/$command"
done
# Per-user command links: no root install, no shell profile mutation.
mkdir -p "$HOME/.local/bin"
for command in mop hmop bmop mop-network; do
    target="$HOME/.local/bin/$command"
    if [ -e "$target" ] && [ ! -L "$target" ]; then
        echo "Refusing to replace an existing command: $target" >&2
        exit 1
    fi
    ln -sfn "$ROOT/scripts/$command" "$target"
done
"$ROOT/.venv/bin/python" -m mop --version
