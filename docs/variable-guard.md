# Python variable guard prototype

Run an opt-in Python script and review small runtime steps through the existing local vLLM-Jev classifier:

```bash
.venv/bin/python -m mop.variables --output artifacts/variables.json \
  --review-config config/mop.json examples/tasks/variable_flow.py /tmp/mop-text-result.txt
```

Both report and demo output must be new paths. The report is created with mode 0600. Omit `--review-config` to collect without inference. No GitHub upload, daemon, debugger attachment or global instrumentation is involved.

Each event contains an invocation ID, parent invocation, source line, observed local bindings, binding versions, values before the line, changes afterwards and syntactic call candidates. Expand these records to follow text transformations and uses. Function-entry arguments are observed, but caller-to-callee taint propagation is not proven. Events retain empty operator context. Review occurs after execution, using batches of four and the unchanged default categories. Only steps with call candidates request inference; isolated assignments are collected without a verdict. The classification prompt adds a variable-use instruction: sensitive-looking values alone are not grounds for suspicion, and candidates are not proof of execution. It does not prevent operations.

Scope is the selected Python file and initiating thread. Native code, imported files, child processes, async task identity, globals not present in locals, and arbitrary object internals are not covered. Short-circuit expressions can contain call/read candidates that were not executed. Exceptions are distinguished from advancing lines. Generator resumption is represented as a new invocation. Line events cannot reveal every intermediate expression value. This is not exhaustive variable or dataflow tracing.

Bounds: 32 locals, 2048 units per string, eight container items, two container levels, 256 events by default (4096 maximum), 8 MiB event budget. Large values are omitted, not partially exposed. Opaque values do not invoke custom repr or iteration. Secret-name and content redaction is best effort, not a guarantee. Reports can still contain sensitive application text: enable only for an explicitly selected workload.

The demo transforms synthetic text, writes it to a new file, and attempts to open `/etc/shadow` without reading contents. A permission failure is a real runtime exception, not proof of theft. Model categories are observations from the run, never expected labels baked into the collector.


## Browse reports

The installed `mop`, `hmop` and `bmop` commands now accept `variables` and `inspect`:

```bash
mop variables --output artifacts/new-report.json --review-config config/mop.json examples/tasks/variable_flow.py /tmp/new-mop-result.txt
hmop inspect artifacts/new-report.json
mop inspect --plain artifacts/new-report.json
```

The offline inspector has a step list and a variable detail pane. Up/Down selects a step; PgUp/PgDn scrolls details; `f` cycles all/reviewed/alerts; `/` searches event evidence; `p` shows the exact model request; `=` clears filters; `q` exits. It never reruns the task or calls inference. `recorded` means no classification was requested, not normal. The three commands share this inspector; their live process dashboards retain their respective layouts.

All three live dashboards also support wrapped, scrollable evidence details. In a detail panel, use Up/Down, PgUp/PgDn, Home/End, then Esc to close.

When the variable collector exhausts its event or byte budget, it stops tracing while the application continues. `collection_stopped_reason` explains the gap, and `dropped_count_is_lower_bound` marks that subsequent operations were not counted. This improves bounded-capture cost but does not preserve full coverage. Failed inference batches retain their attempted request and error type; successful batches remain available. A normal SystemExit(0) is not a target error.

Validation of this engineering pass: unit/integration tests, actual local Jev classification, and PTY launch/navigation/exit of all three inspector entrypoints. A paired benchmark with 1000 short text transformations and a 256-event cap measured 61.08 ms before and 26.95 ms after (seven timed pairs, no inference). Both retain only bounded coverage; full tracing still costs substantially more than uninstrumented execution.
