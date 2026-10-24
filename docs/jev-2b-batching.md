# Native vLLM-Jev hosting and batching

MOP calls `/plugins/vllm-jev/choice` for a single input and
`/plugins/vllm-jev/batch` for independent inputs. The endpoint must serve a
compatible Open-Jev model. No Noul extension or MOP-specific server patch is needed.

The current deployment serves Open-Jev-2B on `127.0.0.1:18936`. The selected client
configuration is `config/mop.json`: 8 workers, at most 4 operations per HTTP batch,
2 concurrent batches, and no deliberate coalescing delay. This is separate from
semantic aggregation, which summarizes multiple operations into one assessment.

## Host a model

Use a Python environment with vLLM-Jev and its dependencies installed. Optional
`MOP_JEV_SOURCE` prepends an existing vLLM-Jev checkout to PYTHONPATH. This project
neither vendors nor patches that inference engine.

```bash
MOP_VLLM_PYTHON=/absolute/vllm-environment/bin/python \
MOP_JEV_MODEL=/absolute/Open-Jev-2B \
MOP_JEV_SOURCE=/absolute/vllm-jev \
MOP_JEV_GPU=2 MOP_JEV_PORT=18936 \
  bash scripts/serve-jev-2b.sh
```

Use the original environment `bin/python` path, or a symlink to the entire
environment directory. A standalone symlink to its Python executable can lose
virtual-environment dependency discovery. The launcher never falls back to the
active shell Python. Verify dependencies without starting a service:

```bash
bash scripts/serve-jev-2b.sh --check-only
```

The default project-local interpreter is `.runtime/vllm-runtime/bin/python`.
The launcher checks that the selected GPU is free and stores caches/runtime state
under the project. For this existing host, project-local runtime/model/source links
are already configured. A new deployment must provide its own compatible runtime
and model. The serving model is selected server-side; the client model name is
identifying metadata, not an automatic model switch.

## Validate

```bash
mop check
mop assess /absolute/operation.json
```

Changing category names, descriptions or instructions does not require restarting
the server. Responses must contain exactly the configured candidates with valid
probabilities and a consistent selected candidate; malformed responses become
`unknown`. Batch result counts are validated and each input preserves its own state.

[Retention/load measurements](retention-sizing.md) document a shared-server stress
run. They are not accuracy guarantees or an isolated saturation benchmark.
