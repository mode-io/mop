# Operations

## Install and start

```bash
bash scripts/setup.sh
mop check
mop
hmop
bmop
```

The setup script installs symlinks in the project virtual environment and
`~/.local/bin`. It does not require root or edit shell profiles. Ensure
`~/.local/bin` is on PATH. Wrappers resolve the project and its configuration
independently of the current directory. All three commands report version 0.8.0.

`config/mop.json` is the editable source-install configuration. `MOP_CONFIG`
selects an alternate file; explicit `--config` takes precedence. Optional endpoint
overrides are `MOP_BASE_URL`, `MOP_MODEL`, `MOP_API_KEY`, `MOP_ALLOW_REMOTE`.
Existing `.env` is preserved. Endpoint overrides should be deliberate; secrets
must not be placed in JSON files or URLs. Remote endpoints require explicit opt-in
and HTTPS. HTTP redirects and inherited proxies are disabled.

## Inspect or capture

```bash
mop --plain --duration 5
mop review --pid 12345 --task-log /absolute/task.log
mop trace --sudo --tui -- /bin/sleep 2
mop trace --sudo --pid 12345 --duration 5
mop replay /absolute/events.jsonl
```

The tracer may need `--sudo` under restrictive ptrace policy; the launched command
keeps the caller's UID. Workload stderr is isolated from tracer evidence.
Logs use `--log`, final summaries use `--summary`. Full bounded system snapshots
use `--evidence-log`; exact model payloads use `--prompt-log`. Log paths in JSON are relative
to the config file; CLI paths are relative to the invoking directory. Prefer
absolute paths when launching from arbitrary directories. Default log rotation is
10 MiB with three backups. Evidence is sent only to the selected model service.

## Failures and updates

`mop check` runs a synthetic classification and exits nonzero if the model path
fails. Model errors are `unknown`; there is no simulated fallback. No classification
is equivalent to a kernel security boundary. Inspect `waiting`, `unassessed`,
`unknown` and log-error counters rather than assuming an empty alert list is safe.

Restart running observers after a code or config update. tmux detachment keeps
an observer running; pressing q stops it. The model server and observer are separate.
This project does not install a system-wide monitoring daemon.

## Development

```bash
scripts/test.sh
MOP_TEST_SUDO_TRACE=1 scripts/test.sh
```

The second command enables explicit privileged tracing integration tests.
GitHub Actions is disabled and must not be re-enabled without authorization.
