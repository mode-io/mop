# System-derived runtime evidence

The default configuration collects facts from Linux, not fabricated task intent.
A normal watch/review request has `context: {}` unless an operator explicitly
supplies a context file. Supplied context is not an OS permission grant. The default
prompt now explicitly forbids inventing intent, authorization or file sensitivity.

## Default facts

| Evidence | System source |
| --- | --- |
| PID/TID/start identity, state, CPU counters | procfs stat |
| Ordered command line, including duplicate and late flags | procfs cmdline |
| Allowlisted runtime flags (library/Python paths, environment location, CUDA device selection and thread settings) | procfs environ; other values excluded |
| Executable/cwd, file ownership/mode, inode and executable SHA-256 | procfs links and stat; executable bytes only |
| Parent chain, children, thread identities/counters | procfs stat and task directories |
| UID/GID/groups, capabilities, NoNewPrivs, Seccomp, security label | procfs status and attr/current |
| User/group mappings, namespaces, cgroups and resource limits | procfs mapping/ns/cgroup/limits files |
| Open file targets, FD access modes, offsets and attributes | procfs fd/fdinfo |
| Owned TCP/UDP/Unix socket endpoints and state | FD socket inodes matched to the process network namespace tables |
| Executable mapping paths and writable-executable region count | procfs maps; no memory contents |
| GPU memory for the process and captured direct children | optional nvidia-smi query, cached up to 30 seconds with PID/start matching |
| Owned regular stdout/stderr file tails | separate read offset, no pipe/terminal consumption |
| Changes since the previous sample | CPU/I/O deltas, observed file/endpoint changes, privilege/executable-link changes |

Thread observations use the selected thread's procfs entries where available;
parent/child enumeration and GPU attribution retain process-level scope. Source
paths, sample times, read limits and omissions are recorded. A socket in the same
network namespace is not attributed to a process unless its FD inode matches.
A LISTEN socket confirms the actual bound port even when argv contains duplicate
port flags; MOP does not guess an application's flag-precedence rules.

The executable fingerprint covers the on-disk inode, not loaded memory integrity,
and is not compared against a known-good baseline. File mode bits do not include a
complete ACL/LSM authorization evaluation. Writable mappings and open device files
are facts, not automatic evidence of malware or GPU compute allocation.

## Start and inspect

```bash
mop
mop review --pid 12345
mop review --pid 12345 \
  --evidence-log /absolute/system-evidence.jsonl \
  --prompt-log /absolute/model-requests.jsonl \
  --log /absolute/verdicts.jsonl
```

`--evidence-log` stores the full bounded source snapshot before model projection.
`--prompt-log` records exactly what is sent to the classifier. These are distinct:
large evidence snapshots cannot fit unboundedly into a model context window.

Default watch/review includes redacted arguments and tails of regular stdout/stderr
files owned by the current user. Disable them with `--no-include-args` and
`--no-output-files`. `--output-root` can explicitly restrict output-file reads in
review mode; `--task-log` adds explicitly selected task logs. Credential-like paths,
nonregular files and symlinks are skipped. A separate read offset preserves the
workload's output position. JSON credential fields, common textual secrets and
private-key patterns are redacted on a best-effort basis, not a guaranteed DLP boundary.

Sampling defaults to one second; model review defaults to 30 seconds per existing
identity, plus new discoveries. `--review-interval 0` disables periodic reviews.
Changing the sampling interval does not recover operations that happened between
samples. No system-wide daemon or automatic ptrace attachment is installed.

## Source bounds and model projection

- Runtime environment: bounded 64 KiB source read; only the fixed configuration allowlist is retained, with 512 characters per value. Other values are never logged or sent to the model.
- Command line: up to 16 KiB / 128 arguments; overlong individual arguments are
  omitted. Argument order is retained. The former 24-argument cutoff is removed.
- Snapshot: up to 256 descriptors, 128 threads, 32 children and 6 parents.
- Socket tables: bounded reads per protocol; unmatched socket inodes are explicit.
- Executable hash: up to 16 MiB, cached by file identity/version; changes during
  hashing invalidate the result. Memory is never dumped.
- Mapping metadata: bounded source read and at most 32 executable paths.
- Log tails: up to 1024 bytes each, with partial first lines removed.
- Change comparison: up to 32 file targets and 16 endpoints per cached identity;
  at most 4096 identities retained. Changes mean newly/no-longer observed, not
  proof of an exact open/close time or of file-to-network dataflow.

The model projection remains capped at 6000 serialized UTF-8 bytes. It prioritizes
arguments, concrete endpoints and identity relationships; bulky maps, thread/FD
lists and other details are trimmed with `projection_omissions`. Regular output
may also be omitted under budget pressure. Full bounded evidence can be retained
in the separate private rotating evidence log. Even that log is not every readable
host byte: each source has its own bounds and permission/race limitations.

`evidence_sufficiency.status` is **limited**. Its missing-evidence list explicitly
includes past operations between snapshots, encrypted traffic content and business
authorization. The OS cannot supply the operator's intent or an organization's
file-sensitivity policy. Normal means no concrete risk established in the observed
scope, not proof that the whole process is safe.

## Observe actual operations

```bash
# New task, with decoded paths/addresses and syscall return values.
mop trace --sudo --duration 5 --log /absolute/syscalls.jsonl -- /bin/sleep 2

# Explicit attachment to an existing process; detach after five seconds.
mop trace --sudo --pid 12345 --duration 5 --log /absolute/syscalls.jsonl
```

Tracing is opt-in and adds ptrace overhead. This host has ptrace_scope=2, so it
requires the explicit `--sudo` tracer flag; launched commands retain the caller UID.
No sysctl or host security setting is changed. Attachment does not terminate the
target on timeout. Self-attachment is rejected.

Security scope includes execution, file open/delete/rename/permission changes,
network endpoints, process creation and selected privilege/memory-protection calls.
Paths, addresses and results are decoded and redacted. Payload-bearing reads/writes,
message buffers, random bytes and xattr contents are rendered raw rather than copied.
There is no claim to capture encrypted plaintext or every language-level statement.
Use `--no-include-args` for the prior raw-argument trace mode.

Unfinished/resumed calls are joined before classification. Missing completions remain
explicitly unknown outcomes. Trace data comes from a private FIFO separate from
workload stderr, so printing a fake strace line is not a kernel observation.

For `--pid`, up to 4096 events are buffered until detachment before classification.
This prevents review requests from recursively creating traced activity when the
target is the classifier server itself. Capture overflow, pending-call eviction,
unparsed lines and inference queue drops are separately counted in the summary.
The existing queue and drain bounds still apply; attaching to a busy process does
not guarantee every captured event receives a model result. A trace of a launched
command retains live processing. All traces cover only the selected scope, not the
whole machine or historical operations.

Use [application capture](content-capture.md) for explicit stdout/stderr streams and
application request/response content. Those sources do not prove that text in a log
was executed. Kernel operation evidence and application text remain distinguished.

## Validation

The running Jev service was inspected without supplied context: all 40 arguments,
its real 127.0.0.1:18936 listener, parent/child identities and GPU worker allocation
were obtained from system sources. The full snapshot was approximately 52 KiB;
the actual model projection stayed below 6000 bytes and was accepted by the model.

Controlled real tracing observed successful open, chmod, rename, unlink and connect
calls with their actual arguments and return values, with `context: {}`. A timed
attachment to a disposable process left that target alive. These checks validate
observation and transport, not general security-classification accuracy.
