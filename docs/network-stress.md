# Network and guard stress results

Measured on the shared host on 2026-10-22. This is a bounded capacity check, not an accuracy or saturation benchmark.

## Real requests through the installed proxy

| Concurrency | Requests | Requests/s | Client p95 (ms) |
| --- | --- | --- | --- |
| 1 | 32 | 57.4 | 21.3 |
| 4 | 32 | 150.5 | 35.7 |
| 16 | 32 | 216.1 | 65.6 |

All 192 expected request/response guard records arrived. Missing: 0; body mismatches: 0; unknown: 0.

Client latency includes client/connection setup. The guard is asynchronous; these numbers are not guard latency. The run uses ordinary loopback HTTP; TLS/HTTP3/WSS/gRPC correctness is covered by the separate protocol checks.

| Guard metric | p50 (ms) | p95 (ms) | Maximum (ms) |
| --- | --- | --- | --- |
| inference_ms | 229.5 | 322.1 | 364.5 |
| queue_ms | 2014.8 | 4373.8 | 4664.4 |
| end_to_end_ms | 2230.6 | 4588.6 | 4935.7 |

These guard timings start at engine enqueue; they exclude time waiting in the collector log before ingestion. The observer also processes other captured activity, so this is a shared pipeline measurement.

## Retention and overload

The simulated retention run completed 20000 events across 12000 identities, retaining 512 unique records. RSS increased by 10.8 MiB; UI data filtering for 512 rows took a median 1.42 ms. This does not measure terminal rendering or model throughput.

| Offered | Queue capacity | Completed | Rejected at queue | Decisions/s | End-to-end p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| 8 | 256 | 8 | 0 | 21.0 | 380.5 |
| 32 | 256 | 32 | 0 | 24.8 | 1287.0 |
| 128 | 256 | 128 | 0 | 25.4 | 4918.7 |
| 512 | 64 | 64 | 448 | 25.0 | 2554.3 |

The overload test intentionally offers 512 events without yielding to a queue of 64. Rejections are explicit and are not successful reviews. These model fixtures use full inputs; the network workload uses the installed compact policy.

The bottleneck under bursts is asynchronous guard backlog. Fast application responses do not imply immediate security decisions. Bounded queues prevent unlimited memory growth but cannot guarantee review of all offered work.

## Reproduce

Use an environment with httpx for the network load; the installed collectors and local Jev service must be running. Raw audit files remain private under artifacts/.

```bash
source scripts/env.sh
.runtime/vllm-runtime/bin/python scripts/stress-network.py
.venv/bin/python scripts/stress-retention.py --child --history 512 --identities 12000 --events 20000 --payload 4500 --nested --prune-live
```

See [numeric results](benchmarks/network-stress-2026-10-22.json) for sampled resource peaks and measurement limits. No external model API was called.
