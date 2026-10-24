#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
source "$ROOT/scripts/env.sh"
# Keep the interpreter inside its venv directory so Python finds pyvenv.cfg.
RUNTIME="${MOP_VLLM_PYTHON:-$ROOT/.runtime/vllm-runtime/bin/python}"
if [ ! -x "$RUNTIME" ]; then
  echo "Set MOP_VLLM_PYTHON to the original vLLM-Jev environment's bin/python." >&2
  exit 1
fi
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--check-only" ]; }; then
  echo "Usage: serve-jev-2b.sh [--check-only]" >&2
  exit 2
fi
MODEL="${MOP_JEV_MODEL:-$ROOT/.runtime/models/Open-Jev-2B}"
SOURCE="${MOP_JEV_SOURCE:-$ROOT/.runtime/vllm-jev-source}"
GPU="${MOP_JEV_GPU:-2}"
PORT="${MOP_JEV_PORT:-18936}"
if [ -d "$SOURCE/vllm_jev" ]; then export PYTHONPATH="$SOURCE:$ROOT"; fi
"$RUNTIME" - <<'CHECK_RUNTIME'
import sys
import huggingface_hub, torch, transformers, vllm, vllm_jev.cli
print("Serving Python:", sys.executable)
print("Serving environment:", sys.prefix)
print("vLLM-Jev dependency check passed.")
CHECK_RUNTIME
if [ "${1:-}" = "--check-only" ]; then exit 0; fi
test -f "$MODEL/jev_manifest.json"
"$ROOT/.venv/bin/python" - "$GPU" <<'CHECK'
import subprocess,sys
s=subprocess.check_output(["nvidia-smi","-i",sys.argv[1],"--query-gpu=memory.used,utilization.gpu","--format=csv,noheader,nounits"],text=True)
memory,utilization=map(int,s.strip().split(","))
if memory>256 or utilization>0:raise SystemExit("Selected GPU is occupied.")
CHECK
mkdir -p "$ROOT/.cache/jev-2b" "$ROOT/artifacts/jev-2b"
export CUDA_VISIBLE_DEVICES="$GPU"
export HF_HOME="$ROOT/.cache/jev-2b/hf" XDG_CACHE_HOME="$ROOT/.cache/jev-2b"
export VLLM_CACHE_ROOT="$ROOT/.cache/jev-2b/vllm" TORCH_HOME="$ROOT/.cache/jev-2b/torch"
export TORCHINDUCTOR_CACHE_DIR="$ROOT/.cache/jev-2b/inductor" TRITON_CACHE_DIR="$ROOT/.cache/jev-2b/triton"
export CUDA_CACHE_PATH="$ROOT/.cache/jev-2b/cuda" TORCH_EXTENSIONS_DIR="$ROOT/.cache/jev-2b/extensions"
export FLASHINFER_WORKSPACE_BASE="$ROOT/.cache/jev-2b"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1
export VLLM_NO_USAGE_STATS=1 DO_NOT_TRACK=1 HF_HUB_DISABLE_TELEMETRY=1
export VLLM_USE_FLASHINFER_SAMPLER=0 VLLM_WORKER_MULTIPROC_METHOD=spawn
export VLLM_PLUGINS=vllm_jev_model,vllm_jev_endpoint
unset VIRTUAL_ENV
exec "$RUNTIME" -m vllm_jev.cli serve "$MODEL" \
 --workspace "$ROOT/.runtime/jev-2b" --host 127.0.0.1 --port "$PORT" \
 --served-model-name mop-open-jev-2b --gpu-memory-utilization 0.25 \
 --kv-cache-memory-bytes 4294967296 --max-num-seqs 64 --max-num-batched-tokens 8192 \
 --no-enable-log-requests
