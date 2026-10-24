# Retention sizing and stress results

Measured on 2026-10-15 on tecent_2. The default history limit is now **512**, selected for a smaller memory footprint.
At the sampled rate this retains about 88 seconds; the 16 KiB/record model estimates
8 MiB for history alone. Live advice, queues and runtime memory are separate.
The 8192-entry sizing example below targets 15 minutes with headroom and remains
an optional larger setting, not the current default. Recorded measurements are unchanged.

## Size by time and memory

Let `r` be completed judgments/second, `T` the desired history duration in seconds,
`h` the headroom factor, `b` estimated resident bytes/record, and `M` the history
memory budget. Compute:

```text
required = ceil(r * T * h)
capacity = min(round_up(required, 1024), round_down(floor(M / b), 1024))
```

The helper also respects the configuration maximum of 100000, handles budgets
below 1024 records, and reports when the requested time window cannot be met.
This is an estimate, not automatic resizing or an RSS enforcement limit.

A 72-second sample of the existing deep observer completed 418 judgments
(including unknown results): **5.806/s**, with 119–121 visible processes. The model
server was shared with this stress test and other MOP observers. Treat this as a
short descriptive sample; production sizing needs a longer representative window.
A planning approximation is `r = observed identities / review interval + discovery rate`.
Queue drops are not completed judgments and need separate monitoring.

For a chosen 15-minute target and 1.5x headroom:

```text
ceil(5.806 * 900 * 1.5) = 7838 records
round up to a 1024-record block = 8192
8192 * 16 KiB = 128 MiB history budget
```

At this sampled rate, 100 entries retain about 17 seconds, 4096 about 11.8 minutes,
and 8192 about 23.5 minutes. These windows vary with workload.

```bash
.venv/bin/python scripts/size-retention.py --rate 5.806 \
  --minutes 15 --headroom 1.5 --budget-mib 128 --bytes-per-record 16384
```

The budget is for history only. Base Python/runtime memory, live-process advice,
in-flight work, UI freeze snapshots and logs require additional memory. Higher
custom context sizes or different evidence structures require remeasurement.

## Memory and UI stress

Each cell used a fresh Python process, 20000 judgments, a real Engine and a
zero-delay fixture provider. This isolates retention and UI costs from GPU speed.
RSS deltas include allocator behavior and small engine buffers. They are not
measurements of model throughput or exact per-object heap size.

Two evidence shapes were tested: mostly log text (~5370 serialized record bytes),
and nested runtime evidence (~5135 bytes) with 16 FDs, status/I/O maps and three
log tails. Nested Python objects use materially more memory despite similar JSON size.

| History limit | Log-heavy RSS delta, 128 identities | Nested RSS delta, 128 identities |
| --- | ---: | ---: |
| 100 | 2.9 MiB | 4.9 MiB |
| 4096 | 30.5 MiB | 62.4 MiB |
| 8192 | 59.5 MiB | 122.2 MiB |
| 16384 | 117.9 MiB | 241.6 MiB |

The incremental nested cost is about 15 KiB/record; the sizing helper defaults to
16 KiB/record and a 128 MiB history budget. This is conservative for these fixtures,
not a bound on arbitrary input payloads.

Stress also exposed two issues, now fixed:

1. Watch mode retained latest results for exited identities. It now prunes to the
   latest capture snapshot and rejects late completions for identities no longer
   present. History remains separate. A scope change can prune hidden threads.
2. Each displayed row scanned the entire advice list. A shared identity index now
   performs one indexing pass and constant-time row lookups while preserving
   generation, thread, wildcard and group matching semantics.

For 12000 identity churn with 512 currently visible identities, the log-heavy
workload at history=8192 changed from **88.7 to 60.6 MiB** incremental RSS, and
512-row `visible()` processing changed from **669.7 to 2.4ms** (median of 3 calls).
At history=100, memory fell from **88.6 to 5.7 MiB**. Nested evidence after the fix
used **122.7 MiB** at history=8192, with **1.4ms** row processing.
These are list-processing timings, not full terminal-frame or inference latency.
Latest-advice count fell from 12000 stale-inclusive identities to 512 visible ones.
Sources without capture snapshots retain the existing 65536-identity hard cap.

## Native Jev pressure test

The shared local Open-Jev-2B Choice server received synthetic log-heavy events,
using 8 workers, batch size 4 and two concurrent batches. Inputs may benefit from
prefix caching. Runs were single trials with background observers active; these
are descriptive load tests, not isolated saturation or security-accuracy benchmarks.

| Simultaneous arrivals | Queue capacity | Completed | Queue-full drops | End-to-end p95 |
| --- | ---: | ---: | ---: | ---: |
| 8 | 256 | 8 | 0 | 458ms |
| 32 | 256 | 32 | 0 | 1507ms |
| 128 | 256 | 128 | 0 | 5924ms |
| 512 | 64 | 64 | 448 | 3047ms |

All 232 accepted requests completed with zero provider errors. The 32/128/64-
completion trials sustained about 21 completed judgments/s over their respective
runs. The last test deliberately submitted the entire burst before workers could
drain the 64-slot queue; every rejected event was counted as unassessed.
Increasing history cannot fix admission overload or inference queuing latency.

The recorded runs predate the 0.8 package rename and category-only cleanup; they
remain historical evidence. The current script uses the current classification model.

## Reproduce

```bash
# Memory and UI, no model calls.
.venv/bin/python scripts/stress-retention.py --prune-live \
  --output artifacts/retention/optimized.json
.venv/bin/python scripts/stress-retention.py --prune-live --nested \
  --output artifacts/retention/nested.json

# Explicit local model load; uses the existing server on port 18936.
.venv/bin/python scripts/stress-retention.py --model \
  --output artifacts/retention/model-rerun.json
scripts/test.sh
```

The baseline used the pre-fix checkout (2831343 plus the benchmark script); running
the script on a later checkout does not reproduce the old linear lookup. Output
parent directories must exist. No GPU service was restarted, and unrelated GPU
workloads were left running. GitHub Actions remains disabled.

[Recorded measurements](benchmarks/retention-2026-10-15.json) include all trials.
Local progress streams and observer snapshots are under `artifacts/retention/`.
