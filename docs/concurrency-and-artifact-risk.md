# Concurrency and generated-artifact review

## Transport and scheduling

The native Jev adapter reuses HTTP connections within a provider instance. Connections are never shared concurrently, redirects and proxies are not used, error bodies are not logged, and idle connections are closed on shutdown. A stale reused connection is retried once on a disconnect; failures on a fresh connection are surfaced. Requests already running in a worker thread remain bounded by their socket timeout. Change an endpoint by creating a new provider; a validated provider's endpoint is immutable.

Microbatches validate every returned verdict before completing any member, and copy verdicts before adding per-request timings. Metrics expose connection creation/reuse, peak pending work, batch fill and batch service latency. File replay now waits for queue capacity instead of discarding finite input when its producer outruns inference. The existing Tetragon file follower and function capture also use backpressure; this does not promise unlimited live-log retention.

A finite 5000-event replay test uses an explicitly simulated 5 ms batch transport, 8 workers, batch size 4 and at most 2 concurrent batches. It checks complete accounting, zero queue loss and a bounded 512-record history. This is a scheduling test, not a claim about model throughput.

Real Open-Jev-2B scheduling measurements used 48 decisions per run, two interleaved rounds with reversed configuration order and a model warmup. Old HTTP, pooled HTTP, 16 workers/batch 8/concurrency 2, and 16 workers/batch 4/concurrency 4 all measured about 31 decisions/s with about 1.54–1.55 seconds per run. This small repeated workload showed no throughput benefit from increasing concurrency, so defaults remain 8 workers, batch 4, concurrency 2. Pooling reduced 12 newly established connections to 2 connections with 10 reuses in a representative run; it did not materially reduce wall time here.

## Model assessment and artifact rules

`artifact_rules: true` enables two narrow checks for VizTracer function-return evidence:

* A single DELETE/UPDATE statement loses its top-level WHERE constraint while the preceding statement text remains unchanged. The parser excludes quoted words, comments, nested predicates and multiple statements from this narrow match.
* A structured recursive `rm` argument list or recognized directory-deletion tool request changes from a narrower absolute path to filesystem root.

These are pre-use artifact-risk checks. They do not establish command execution, database modification, intent, authorization or actual damage. They do not evaluate arbitrary expressions or execute supplied text. They do not cover arbitrary SQL dialects or all dangerous commands.

If a rule matches, the final guard category is `high_risk`, with `provider: vllm-jev+artifact-rules`, an explicit rule reason, and no invented confidence. `model_assessment` retains the original model category and probabilities; `rule_findings` contains the concrete checks. An unmodified model verdict retains its own probabilities. Model failures remain unknown and are not hidden by these checks.

Use `--no-artifact-rules` for model-only review. Custom category names require disabling these built-in checks; no mapping to arbitrary labels is guessed.

## Experimental function policy

`function_classification` optionally supplies a separate question and descriptions for `viztracer` and `python-runtime` events. Labels and order must match the main classification policy. Every member of a mixed batch is decoded using the options actually sent for that event. The operating-system policy remains separate.

The tested experimental prompt is not enabled by default. On eight new synthetic cases, it fixed one quoted-text false positive and recognized a root-target change, but also flagged an unchanged temporary-directory cleanup and still missed an unconstrained UPDATE. There was no clear overall improvement sufficient to replace the default model policy.

For the same eight cases, the original model had three mismatches against the declared artifact-risk expectations. Applying the two deterministic checks corrected the destructive UPDATE and root-deletion cases; a quoted attack description remained a false positive. Both corrected cases still had a model category of normal, and that fact is retained. These cases were reused during rule development, so the combined result is a development-set result, not independent accuracy evidence. No dangerous artifact was executed.

No kernel probe configuration was changed. The temporary evaluation model was stopped after measurements. Detailed runtime logs and input contents remain in ignored artifacts rather than source control.
