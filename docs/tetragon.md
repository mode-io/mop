# Tetragon evidence integration

## Default managed mode

On the configured host, `mop`, `hmop` and `bmop` now attach to `mop-tetragon.service` without extra flags. The single observation collector is enabled at boot and continues collecting when a UI closes. Inference still runs inside each open MOP session; opening multiple UIs can duplicate classification work, but does not create duplicate kernel collectors. No enforcement policy is enabled.

```bash
hmop
mop --no-tetragon
systemctl status mop-tetragon.service
sudo systemctl stop mop-tetragon.service
sudo systemctl start mop-tetragon.service
```

`--no-tetragon` disables ingestion in that session; it does not stop the shared collector. To disable persistence, use `sudo systemctl disable --now mop-tetragon.service`. If the default service is unavailable, MOP reports an error instead of silently pretending kernel monitoring is active. During a live session, service health is checked every five seconds and source failure increments the visible log-error counter.

The reproducible installer is `sudo .venv/bin/python scripts/install-tetragon-service.py --uid UID --gid GID`. It verifies the pinned archive, copies runtime binaries and policies to root-owned `/opt/mop-tetragon`, installs `/etc/systemd/system/mop-tetragon.service`, and stores rotating exports in `/var/log/mop-tetragon`. A privileged persistent service does not execute mutable repository binaries. Export is restricted to the configured effective UID or audit UID. MOP likewise accepts its current UID or audit UID unless `--all-users` is explicit. Defaults observe configured file prefixes, TCP connection hooks, and `openat` for selected sensitive absolute paths; relative paths and other open variants are not complete coverage.

The service has a 512 MiB memory limit, one CPU core quota, no TCP API listener and a bounded export (10 MiB plus three backups). Raw exports are group-readable in a root-owned restricted directory; they may contain command arguments. No model runs in the service.

## Kernel inference optimization

Default `tetragon_window_ms` is 250; use `--tetragon-window-ms 0` to disable coalescing. The adapter groups same-execution, same-thread, same-credential observations within the window, retains distinct operations and results, and counts duplicates. Source timestamps also delimit windows during replay. Groups are bounded by eight distinct observations, a byte budget, 64 raw events and 256 active groups. Captured negative returns bypass grouping. Buffer flushing occurs on timeout, process exit, capacity, end of file and cancellation. Group decisions never imply clearance for each operation.

Process execution IDs are represented by stable SHA-256 tokens so content redaction cannot erase their distinction. Raw event accounting remains independent from the number of model decisions. One replay of 34 real events produced 34 decisions with coalescing off and 8 decisions with it on, preserving a raw count of 34. Measured replay elapsed time was 4.63 s versus 1.06 s; this single ordered run is not a controlled long-term latency benchmark.


MOP can consume Tetragon JSONL exports alongside its existing process observer. The terminal layouts are unchanged. Tetragon remains a separate, explicitly started privileged collector. MOP converts its observations into ordinary events and submits them through the existing native vLLM-Jev microbatch provider.

## Installed project-local runtime

This integration was validated with Tetragon v1.7.0 amd64 on Linux 5.4.119 with `/sys/kernel/btf/vmlinux`. The release archive SHA-256, verified against GitHub's release metadata, is:

```text
67fe2cad1fbf601a3617eb441423f7e3a01a5cefc8ef56045406c60a68d0f772
```

For a new compatible amd64 Linux checkout, install under the repository (do not run the upstream system-wide install script):

```bash
mkdir -p .runtime/tetragon
curl -fL https://github.com/cilium/tetragon/releases/download/v1.7.0/tetragon-v1.7.0-amd64.tar.gz -o .runtime/tetragon/verified.tar.gz
echo '67fe2cad1fbf601a3617eb441423f7e3a01a5cefc8ef56045406c60a68d0f772  .runtime/tetragon/verified.tar.gz' | sha256sum -c -
tar -xzf .runtime/tetragon/verified.tar.gz -C .runtime/tetragon
```

## Optional standalone foreground mode

Stop the managed service first; only one Tetragon daemon can own its singleton PID file. These commands are an alternative to the default service, not an additional requirement.

From the repository, in terminal one:

```bash
.venv/bin/python scripts/run-tetragon.py --binary-regex '/python3?(\.[0-9]+)?$' --path-prefix /etc --path-prefix /data1/hjingaa/github --network
```

The executable regex explicitly scopes exported events. Adjust it to the binaries you need; `.*` exports every binary and can be very noisy. File hooks are scoped by the supplied path prefixes. Network hooks are opt-in and observe TCP connection operations, not HTTP bodies. Export filters reduce exported volume, not all kernel-side collection work. No enforcement actions are installed. Use `--duration 60` for a finite run; otherwise Ctrl-C stops the foreground collector. The launcher does not install a systemd service or enable autostart. It disables the gRPC TCP and health listeners and uses a separate BPF pin directory. Another Tetragon daemon may prevent startup via its singleton PID file; never remove another daemon's PID file to bypass that protection.

The launcher requests sudo for kernel collection. Files stay under `.runtime/tetragon/live`; JSON export rotates at 5 MiB with two backups. Its parent directory is private. Raw Tetragon exports can contain command arguments before MOP redaction; protect them accordingly. MOP redaction is best effort, not a guarantee.

In terminal two, keep the familiar UI:

```bash
hmop --tetragon-log /data1/hjingaa/github/all-in-one-modeio/.runtime/tetragon/live/events.jsonl
```

`mop` and `bmop` accept the same flag. Press Tab for the existing decisions view and Enter for event evidence. The process table retains its existing snapshot-based advice: kernel events are not assigned to rows by PID alone. The follower starts at the current end, so it reviews new events without replaying historical logs on each UI launch. It follows rename rotation and truncation; reset counters indicate a possible gap. Stopping the UI stops its reader, not the separately launched collector. A readable stale log does not prove that the collector is still alive.

For a finite replay or headless stream:

```bash
mop tetragon .runtime/tetragon/live/events.jsonl --log artifacts/kernel-decisions.jsonl
mop tetragon .runtime/tetragon/live/events.jsonl --follow --from-end --duration 60 --log artifacts/kernel-live.jsonl
```

The adapter accepts only the current effective UID by default. `--all-users` broadens MOP ingestion; the collector's own export filter still applies. UID transitions to root can be excluded by the default filter, so this is not complete privilege-transition coverage. MOP itself is excluded to limit inference feedback.

## Evidence and limits

Supported events: process execution/exit, kprobe, tracepoint and uprobe. Retained fields include binary, arguments (unless disabled), working directory, UID, TID, parent, exec IDs, credentials/namespaces when enabled, typed file/socket arguments, hook return, policy, source timestamp and action. A bounded six-step history uses `(node, exec_id)` rather than PID alone. Unsupported events and malformed lines are counted. No `/proc` start generation is guessed from Tetragon execution timestamps.

Tetragon events preserve individual evidence even when process snapshot aggregation is changed in the UI; native inference batching still applies. This avoids losing hook arguments in generic short aggregation previews. Queue overflow remains visible through existing engine counters.

A `security_file_permission` return of zero means that permission hook returned zero, not that a file's entire contents were read. A `tcp_connect` return of zero is not proof of a completed TLS or HTTP exchange. Entry-only observations have `outcome=not_reported`. Default-valued fields omitted by upstream protobuf JSON are not invented. No variable values, full file contents or business authorization are inferred. Upstream kernel loss is not measurable from this JSON stream alone.

Limits: 64 KiB input lines, 2048-character strings, 16 list entries, 32 mapping keys, nesting depth five and bounded model projection. Recent execution histories are capped at 4096 keys. Long values are omitted; scope and projection limits travel with each event. Exact model requests can be saved with `--prompt-log`.

## Validation

Real finite host probes captured process lifecycle, file-permission checks and a loopback TCP connection. The latter retained actual socket endpoints, credentials, namespaces and parent identity. Requests were submitted to the existing local Jev model, without restarting it. Benign permission checks were classified suspicious in an early probe: this is a preserved false-positive example, not evidence of attack detection. Initial validation used finite collectors. The subsequent default-mode installation enables the managed observation service persistently.

References: https://tetragon.io/docs/installation/package/ and https://tetragon.io/docs/reference/grpc-api/

## Experimental advanced probes

`scripts/enable-advanced-tetragon.py` is a separate privileged operation, not part of normal MOP startup. Stack collection is off unless `--stacks` is explicitly supplied. It also clears pre-existing kernel-stack flags when that option is absent. A successful policy load does not prove event delivery or operational safety. Earlier stack probes produced no expected sample events, and SSH connectivity failed during the same investigation; the cause has not been established. Validate advanced policies in an isolated host before production use. This script's readiness rollback cannot protect against loss of host connectivity or kernel failures.
