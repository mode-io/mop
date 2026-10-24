# Product design implementation

The product design proposes a familiar process monitor with pluggable safety models.
This release implements the following product path with OpenJev:

| Design | Working implementation |
| --- | --- |
| Three interfaces, shared state | A per-user daemon; mop/hmop/bmop attach to its session |
| Model slot panel | `m`, plus model manifests, probe, active/shadow/disabled states |
| Version changes | Atomic configuration revisions and rollback |
| Core and specialist routing | Core-first review; scoped specialists; parallel secondary calls |
| Shadow evaluation | Recorded comparison without affecting the final category |
| Plain-language rules | Versioned shared prompt policy, reloaded by running observers |
| Decision details | Model/version path, scores, timing, rules supplied, original evidence |
| Approval and enforcement | Explicit pre-execution `mop gate` with an approval prompt and audit |

Specialist research models, automatic weight downloads, a natural-language-to-kernel
rule compiler, host-wide pre-execution enforcement and multi-host management are
future integrations. Demo latency figures are not used as product measurements.

[Use these features](model-slots.md)
