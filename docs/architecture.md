# Architecture

MOP has one classification domain model and three terminal renderers.

```text
/proc snapshots / scoped tracing / replay / explicit PID review / task output / HTTP exchanges
  -> bounded runtime evidence
  -> event or aggregate assessment units
  -> bounded engine queue and workers
  -> independent-request microbatcher
  -> native vLLM-Jev Choice / batch
  -> category + scores, or unknown on error
  -> recent history + live-identity advice index + optional audit log
  -> MOP / H-MOP / B-MOP
```

- `mop/cli.py`, `config.py`: commands and one default configuration.
- `classification.py`: task validation, endpoint safety and native Choice transport.
- `core.py`, `microbatch.py`: queues, bounded concurrency, lifecycle and retention.
- `proc.py`, `collectors.py`, `evidence.py`, `system_facts.py`, `trace_evidence.py`: observation and bounded evidence.
- `content.py`, `proxy.py`: bounded task output and explicit loopback JSON exchange capture.
- `granularity.py`: configurable assessment units; grouped results are labelled.
- `security_view.py`: consistent category counters and identity matching.
- `ui.py`, `frontends.py`, `ui_state.py`: presentation and interaction.
- `audit.py`: private rotating JSONL records with exclusive writer locks.

`Verdict.category` is the sole model label. `unknown` indicates a failed assessment;
it is not an alternate risk class. Queue drops are counted separately as unassessed.
Sampling, assessment frequency and aggregation windows are separate settings.

Observation does not enforce OS isolation. Watch mode may miss short-lived tasks;
trace covers only the launched command and descendants. Runtime evidence is bounded
and not atomic. See [runtime evidence](runtime-evidence.md) and [operations](operations.md).

Test fixtures live under `tests/`; no fixture provider is shipped as a CLI mode.
