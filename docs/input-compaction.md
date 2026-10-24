# Compact model input

`input_mode: compact` is the default for the MOP CLI. Use `--input-mode full` to send the original event structure. This changes the request sent to the classifier, not the original audit event, native evidence files, category definitions or deterministic artifact-rule input.

The first supported compact schema is `mop.function.v1` for VizTracer function observations with the known capture schema. Known decision units also support `mop.decision.v2`; other sources and unrecognized schemas retain their full event payload. Custom prompts that depend on the original metadata layout can select full mode.

## What is folded

* Event UUID, import timestamp, PID/TID display identity, invocation display identifiers and relative timing fields remain in the audit event but are omitted from this individual-function model view.
* Known repeated scope and limitations text becomes one concise interpretation statement. Nonstandard scope, limitations and unknown metadata are not discarded; unsupported source schemas fall back to full mode.
* Named inputs, every assignment string and the return representation are retained. Long identical strings used more than once share a values-table entry. A step can carry a prefix plus a value reference; concatenating them reproduces the exact recorded assignment string.
* Zero omission counters are omitted. Nonzero omissions, workload exit status, custom metadata, source filename/line, phase, return-observed state and nonempty operator context remain available.

No business strings are summarized by another model or truncated by this projection. The adapter falls back to full mode if the compact JSON is not smaller. The original capture itself may have limits, so exact round-trip preservation applies to the captured representations, not arbitrary process memory.

`--prompt-log` records the actual compact request; the normal event audit log still records the original event. Request event IDs link the two. `state_bytes_before`, `state_bytes_after` and `compacted_events` expose projection activity. These are byte counts, not tokenizer estimates.

## Measurement

The comparison used the same 25 captured function observations (11 normal pipeline steps, six controlled text/artifact cases and eight additional synthetic cases), the same Open-Jev-2B model, question and category options. Artifact rules were disabled so they could not hide changes in the model result.

The actual model tokenizer counted 10,358 state tokens before and 5,293 after, a 48.90% reduction. Average state size was 414.32 versus 211.72 tokens. State counts exclude the shared question, options and server template. The native Choice API reported 49,374 versus 34,179 total candidate prompt tokens, a 30.78% reduction; this count repeats shared context across candidate scoring and is not unique-text or billing-token usage.

All 25 selected categories were unchanged. All arguments, assignment strings and return representations passed exact reconstruction checks. Probability scores were not identical: the maximum candidate score shift was 24.13 percentage points. This is a finite formatting comparison, not proof of universal classification equivalence or accuracy improvement. Do not assume confidence-threshold behavior is unchanged.

The model was run temporarily on an idle GPU and stopped after the experiment. The kernel collector was not changed. Detailed requests and comparison data stay in ignored artifacts.

## Decision-unit projection

Known `mop.decision.v1` audit events now have a separate `mop.decision.v2` model
view. Audit UUIDs, timestamps, capture hashes, character offsets and budget
bookkeeping are excluded. Command argv appears once, empty identity fields are
omitted, and intact collector text envelopes lose repeated redaction/byte-count
metadata. Actual text, nonzero truncation/omission markers, original HTTP requests,
process facts, permission values and unrecognized metadata remain. Evidence hashes
inside runtime records or application payloads are not removed. Partial fragments
remain text and retain their part numbers; they are never parsed as complete JSON.

A comparison on 13 previously captured real df/uname/ps observations reduced
state tokens from 9,215 to 3,196 (65.32%). The classification prompt and options
were identical. One category changed: the df output changed from normal to
suspicious. Its state shrank from 878 to 234 tokens. The maximum probability shift
was 65.11 percentage points. This is not an accuracy improvement claim; formatting
can materially affect the classifier. The full audit remains available and
`--input-mode full` provides the original model representation for comparison.

## System-derived input fields

The default decision view is now `mop.decision.v3`. Collector-authored scope,
limitations, redaction explanations and gap sentences are removed from the model
state. Relevant collection outcomes become flags or enum codes, such as
`stdin_captured: false`, `capture_status: unavailable`, or `omitted_bytes`.
Unrecognized gap descriptions are counted as `other_gap_count`, with no inferred
cause. Original command output and HTTP request/response text are not rewritten.
The common security policy carries the interpretation rules for all commands.
Known process/kernel collectors and function views also omit their explanatory
framing. Full/debug mode and unsupported schemas remain unprojected.

On twelve recorded real id/free/nvidia-smi observations, state tokens fell from
2,050 to 1,393. Counting state, question and all options, but excluding the native
server template, input tokens fell from 4,966 to 4,645. All twelve labels stayed
normal. This benign-only comparison does not measure suspicious/high-risk recall.
