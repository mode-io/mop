# Application content capture

MOP can inspect actual task output and HTTP application inputs/results in addition
to process snapshots. These are explicit capture paths; ordinary `mop` cannot
recover arbitrary existing terminal/pipe history or observe all application inputs.

## Run any ordinary command with the same safety policy

```bash
mop run -- df -h /data1
mop run -- uname -sr
mop run -- ps -u "$USER" -o pid,comm
```

The command is executed as supplied. MOP never creates a business question or
command-specific answer options. The configured global security prompt and
categories are identical for every command. Captured argv, output, exit status
and available runtime evidence become bounded decision units. Every unit retains
its launch command and observed process identity. Output statements remain data,
not proof that their claims were executed.

`run` uses process/output capture without language-specific instrumentation.
`capture` uses the same command review path and can additionally capture supported
Python functions. No operator intent or authorization declaration is required.
Use `--log` for audit decisions, `--prompt-log` for exact model inputs, and
`--summary` for counters. Classification lines go to stderr; original command
stdout stays separate. `--decision-tokens` defaults to 2048 with the local guard
tokenizer; when unavailable, a conservative byte budget is used.

Repeated identical runtime snapshots are referenced by hash rather than reviewed
again. Oversized context and rejected units are reported as review gaps. A failed
review makes a successful command return 2; an unsuccessful command keeps its
own exit status. The final display is bounded by the configured history limit.

This is a shared observation strategy, not complete visibility into every program.
Stdin, arbitrary variables and GPU tensor contents are not captured by `run`.
Short-lived processes may exit before a runtime snapshot can be read. Interactive
TUI programs may behave differently when stdout/stderr are pipes. Commands are
not blocked based on model categories, and fragment labels do not establish
whole-task safety.

## Launch a task with stdout/stderr review

```bash
mop capture \
  --log /absolute/task-audit.jsonl \
  --prompt-log /absolute/task-prompts.jsonl \
  --summary /absolute/task-summary.jsonl \
  -- python -u /absolute/task.py
```

The command is executed directly, without shell interpolation. Its original stdout
and stderr bytes are forwarded to the caller; MOP does not append a summary to
those streams. Use `--summary` for the final counters and `--log` for verdicts.
The exit code is the task exit code, or 124 on `--duration` expiry, not a security
approval. `--capture-window` defaults to one second (0.1–30 allowed).

The classifier receives bounded decision units derived from task-start, output-window, runtime-snapshot and task-exit observations. Each output
window includes command arguments, PID/start identity, task context and bounded
runtime evidence when available. Runtime samples carry their own capture timestamp;
a process that exits before sampling has an explicit gap. Output from descendants
that inherit these pipes is included, but the event PID identifies the launched
task, not necessarily the individual writer. Cross-stream arrival order is approximate.

Output capture is bounded to 4096 redacted text bytes and 32 pieces per window.
A line over 4096 bytes is omitted with a byte-count marker, rather than sending an
unredacted partial credential. Binary content is marked and omitted. Incomplete
lines are held until newline or EOF; this is not a character-by-character monitor.
Raw forwarding continues even when an evidence line is omitted. Piping can change
an application's buffering/isatty behavior; use unbuffered output where appropriate.
Stdin, environment and process memory are not captured. Descendants left in the
owned process group are terminated at task end; detached sessions are outside scope.

## Review real JSON and SSE API calls

Keep the upstream model running and start MOP's explicit loopback proxy:

```bash
mop proxy --listen-port 18937 --upstream http://127.0.0.1:18936   --base-url http://127.0.0.1:18936 --decision-tokens 2048   --log /absolute/http-audit.jsonl --prompt-log /absolute/http-prompts.jsonl
```

Point the business client at port 18937. The guard calls the classifier directly,
so its own requests do not recursively enter the proxy. Upstream and classifier
endpoints pointing at the proxy itself are rejected. Only loopback HTTP upstreams
and the native Jev Choice/batch and `/v1/chat/completions`, `/v1/completions` POST
routes are accepted. The upstream must support the selected route.

JSON responses are buffered; SSE response bytes are forwarded incrementally.
Review runs after response collection, including for SSE. This is observation,
not inline enforcement. There is no automatic interception of unrelated clients.
One Content-Length is required; chunked/compressed requests are rejected. Bodies
are limited to 1 MiB, upstream reads have a 15-second idle timeout, streams have
an additional 120-second duration limit, and concurrent handlers are capped at 16.
A stream exceeding the bounds is closed and captured evidence is marked partial.

The generic decision splitter keeps operation/series IDs, part numbers, character
ranges and content hashes. Every response part includes the complete redacted
original request as untrusted evidence. An oversized request that cannot fit with
a response produces a visible review gap; context is never silently discarded.
This implementation splits content by budget and prefers line boundaries. It does
not infer business phases or automatically join conclusions across parts.

The budget includes the state, classification question, options and a 256-token
reserve with the local Open-Jev tokenizer. Set `MOP_TOKENIZER_PATH` to the matching
`tokenizer.json` for another guard model. If no tokenizer is available, a conservative
UTF-8 byte budget is used instead; this fallback is not an exact token measurement.
The service's actual context limit must still accommodate its prompt template.

Inspect completed units and their original inputs:

```bash
curl -s http://127.0.0.1:18937/mop/reviews | python -m json.tool
```

This endpoint contains bounded recent history, review gaps and engine counters.
It may expose captured application content to local users with access to the port.
Use private audit/prompt logs for persistent records. Queue rejection counters mean
some units were not reviewed; classifier failures remain unknown. Normal fragments
do not establish whole-request safety. Transport headers and inferred OS PIDs are
not included in model evidence. Use `--duration` or Ctrl-C to stop the proxy.

## Exact model requests

`--prompt-log` works across commands. It records the exact JSON payload prepared
for the native classifier, including complete question, state and candidate options.
Batch envelopes and their event IDs are preserved. Headers and API credentials are
excluded. A logged request is an attempt, not proof that a response succeeded;
match event IDs with the audit verdicts. Logs use private files, rotation and exclusive
writer locks, and must have paths distinct from audit and summary logs.

Captured text uses best-effort secret redaction, including sensitive JSON keys,
common textual credentials and private-key blocks. Structured JSON is normalized
when redacted. Arbitrary secret formats may remain; do not treat redaction as a
complete data-loss prevention boundary. Caller-supplied task context and prompt
configuration are sent as supplied. Model context limits still apply even when
capture limits are satisfied. Missing or truncated evidence is always a limitation.

[Three complete real-call examples](content-examples.md) include original controlled
application data, full classifier payloads and actual returned scores. They use
synthetic tasks, not private business requests, and do not establish detection accuracy.
