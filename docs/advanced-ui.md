# Advanced terminal workflows

These controls work in MOP, H-MOP and B-MOP. They are display tools, not changes
to authorization or capture scope. All controls are session-local.

| Reference | MOP implementation | Controls |
| --- | --- | --- |
| top: field filtering and idle toggle | Combined resource, identity and classification filters | F4, i, = |
| top: runtime update interval | Adjust process sampling from 0.1 to 10 seconds | + faster, - slower |
| htop: process tagging | Identity-aware investigation tags; tagged-only view | Space, y, U |
| btop: pause process list | Freeze list data while collection and inference continue | z |
| btop: process details | Inspect latest advice, observation age, inference latency and candidate scores | Enter |

## Filter by evidence

Press **F4**, type an expression, then Enter. Terms are combined with AND.

```text
advice:high_risk
user:hjingaa cpu>=5
name:python mem>100
state:R advice:suspicious
pid=12345
```

Numeric fields: `cpu` (single-core percent), `mem` (resident MiB), `pid`, `tid`.
Operators: `=`, `!=`, `<`, `<=`, `>`, `>=`. String fields: `user`, `state`,
`advice` use case-insensitive exact matching; `name` and `operation` use substring
matching. Bare words search names, users, identities, operation and advice.
Quote a value containing spaces. Invalid syntax produces an explicit filter
error and no rows. There is no shell execution, eval, or user-supplied regex.

In decision view, `advice`, `name`, `operation`, `pid` and `tid` can be used.
Unavailable fields never match numeric or named field conditions.
Press **=** to clear filters, tagged-only mode and idle hiding.
Filtering hides rows only: all captured events continue through the same pipeline.

## Keep investigation targets visible

Press **Space** to tag a selected process (`*` before its name), **y** to show
only tagged processes, and **U** to clear tags. Tags match PID, TID and start
identity, so a reused PID does not inherit an old tag. Up to 4096 tags are kept.
Tags do not send signals or change model decisions. They reset on observer exit.

## Freeze and inspect

Press **z** to freeze the current list, including its displayed advice. The footer
reads `FROZEN list; monitoring live`. Collection, model evaluation, host meters
and summary counters continue. Each view is frozen when first opened while this
mode is active. Press **z** again to return to current data.

**Enter** opens details. Process details deliberately show the *latest live*
matching advice, even when the list is frozen. Observation age measures time since
the event was captured, not time since model completion. Candidate scores are not
calibrated security probabilities. `normal` is not an execution authorization.

## Tune sampling

**+** halves the process sampling interval; **-** doubles it, bounded to
0.1–10 seconds. The new value applies to subsequent scheduling; an already
scheduled sample may still use the prior interval. The footer and F2 show it.
The initial interval still comes from `--interval`.
This is distinct from **[ / ]**, which changes semantic aggregation windows.
It does not make existing processes receive a new inference every sample.

## References and scope

- [top manual](https://man7.org/linux/man-pages/man1/top.1.html): field filters, idle toggle, update timing.
- [htop manual](https://man7.org/linux/man-pages/man1/htop.1.html): tagging and inspection controls.
- [btop features](https://github.com/aristocratos/btop#features): process-list pausing and process details.

These workflows are adapted for MOP, not a claim of full feature parity. Existing
search, tree, sorting, thread view and dashboard graphs remain available.
Signal delivery, renicing, interactive tracing attachment, mouse support,
persistent layout presets and arbitrary column editing are not implemented here.
