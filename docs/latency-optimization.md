# Latency and navigation

Same 24 recorded events (16 small, 8 large), warm local OpenJev, 8 concurrent clients. Observer paused during paired tests; serving and collectors stayed running.

| Metric | Before | After |
| --- | ---: | ---: |
| Review p50 | 977 ms | 520 ms |
| Review p95 | 1216 ms | 777 ms |
| Entire 24-event burst | 2.93 s | 1.66 s |
| Events per second | 8.19 | 14.45 |
| Unknown | 0 | 0 |
| Fragments | 48 | 40 |

The old split path processed original events and their fragment groups serially. The new path combines fragments across events, sends at most eight per native request and keeps at most two requests in flight per transport. It caches fixed prompt token costs and uses a 3072-token estimated budget, including the existing reserve. Byte-based fallback remains conservative when no tokenizer is available. Stable context fields precede changing observation fields for prefix reuse. All evidence remains present; fragment reconstruction is tested.

Original event batching remains four. Raising it to eight was slower in this experiment. Native sizes four and twelve were also compared before retaining eight.

Review latency includes preparation, batch waiting and completion of all fragments. It is not GPU-only time. The burst completion measurement includes the eight-client admission queue. Live host collector and inference queues are separate and can add delay under sustained traffic. The daemon is restored after the comparison.

## Models navigation

| State refresh | Payload | p95 |
| --- | ---: | ---: |
| Full snapshot (old Models path) | 1,031,714 bytes | 41.33 ms |
| Models-only state | 3,935 bytes | 1.67 ms |

Twenty local socket reads per endpoint were measured against the same running daemon. This is state-fetch time, not a measurement of physical keyboard or SSH network latency.

The Models view skips process sampling, uses a 20 ms interaction loop, drains queued navigation keys and shows the selected card with a thick border. Up/Down, Tab, Home/End, PageUp/PageDown and the mouse wheel navigate cards. Clicking a card selects it; clicking its action starts the model check. Process selection follows identity through CPU resorting.

## Reproduce

The helper creates a private fixed corpus from local daemon audit records on its first run, then reuses it and records its hash. Raw observations remain in `.runtime/perf-corpus.json` and are not committed. Run once to warm the model, then measure again:

```bash
mop daemon stop
.venv/bin/python scripts/bench-latency.py warm
.venv/bin/python scripts/bench-latency.py measured
mop daemon start
```

[Numeric results](benchmarks/latency-2026-10-24.json). Classifications agreed on these inputs; this run does not estimate detection accuracy.

## Continuous-operation fixes

The live queue also contained the proxy's own heartbeat writes. These are now
counted as `tetragon_telemetry_filtered`, using an exact executable, UID, private
status-file path, write mask and successful permission-hook return. Business files,
certificate keys, other processes and denied permission checks are retained.

A 60-second live observation saw the queue fall from 256 to zero. The bounded
queue rejected 245 admissions early in that burst; its overflow counter stayed
flat during the final 30 seconds. No additional unknown results appeared during
that minute. This is a burst-recovery observation, separate from the fixed-corpus
latency comparison.

Twenty alternating Up/Down actions in a local tmux terminal selected the correct
card every time. Key injection to rendered selection measured 28.8 ms median,
35.4 ms p95 and 107.2 ms maximum, excluding physical keyboard and SSH transit.

Daemon shutdown now aborts its UI socket connections and bounds close waits, so
an idle or stalled viewer cannot hold a restart open indefinitely.

In short terminals, the card viewport now moves only when selection crosses its boundary; Up no longer repositions the whole list on every press.
