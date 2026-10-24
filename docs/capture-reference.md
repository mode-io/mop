# Collector reference

For installation and everyday commands, see [Install MOP](system-install.md).

## Coverage and bounds

| Source | Current coverage | Bound or gap |
| --- | --- | --- |
| stdout/stderr | Successful `write(1/2)` calls, complete text lines | 3 KiB per write, 200 writes/s per process and 1,000 writes/s globally; oversized writes are metadata only |
| TLS | Selected system OpenSSL library; HTTP/1 Content-Length, chunked bodies and SSE | 3 KiB per TLS call, 200 calls/s; HTTP/2 is bounded; gzip/deflate decoded; other codecs require a suitable adapter |
| HTTP body | Reassembled bounded messages | 256 KiB per message; long evidence is exported as numbered JSON fragments |
| Process association | Observed PID and UID | Not a claim of complete thread/function context; no joining by recycled PID alone |
| Other internals | Existing procfs/Tetragon sources | No arbitrary variables or stdin; unrecognized TLS libraries remain gaps |

These are partial observations, not proof that an unobserved process is safe.
Streaming SSE events are reviewed as they arrive. This does not imply coverage of
all LLM APIs or all TLS libraries. A client that closes at an application marker
such as `[DONE]` can leave HTTP framing incomplete; this remains a capture gap.
The UI displays collector gaps and availability. Queries and HTTP authorization
headers are not exported. Text/JSON secrets are redacted best-effort before writing;
unknown secret formats can remain. A capture gap is never a normal classification.

The root-owned service is `mop-content-<uid>.service`, limited to 512 MiB and one
CPU core. It stores rotating exports in `/var/log/mop-content/<uid>/` (4 MiB plus
three backups), readable by the user's primary group. Raw collector streams stay
in memory. Reports are in `.runtime/installation/report.json`; live capability
and loss counters are in `/var/log/mop-content/<uid>/status.json`.
The collector runs independently of the UI; guard inference occurs while MOP is
watching. Installation does not download or start a model automatically.

## Association and long content

Requests and responses are paired by process lifetime, SSL object, opposite I/O
direction and HTTP/1 FIFO order. Connection close, malformed framing and known
capture gaps clear association state. Interim 1xx responses do not consume a
pending request. Missing context is marked explicitly; no business intent or
application authorization is inferred. SSL object reuse is cleared by SSL_free.

Responses and SSE events include `original_request` and `request_id`. Very large
request contexts are bounded: over 16 KiB the retained body is omitted; a long
export uses at most 1,400 encoded characters of request context and marks
`request_context_partial`. The original request is independently exported in
numbered fragments. These references do not mean the guard saw an omitted body.

Evidence is redacted before splitting. Long records carry `content_id`, `part`,
`parts`, `encoding: json_fragment`, and `content_fragment`; concatenating fragments
in order and JSON-decoding reconstructs the redacted evidence. Each envelope is
valid JSON. The fragment itself is explicitly partial content, not standalone
JSON. Fragment payloads contain at most 900 ASCII JSON characters, with a maximum
of 512 parts; any omitted parts are counted. The guard uses the same shared policy.

SSE events have `event_complete: true` but `complete: false` until HTTP framing
finishes. A final `http_response_end` records transport completion separately.
`capture_gap` records remain in collector logs and UI counters; they are not sent
as standalone safety decisions. Missing bytes are never evidence of an attack.

Framing follows [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html) and the
[SSE parsing specification](https://html.spec.whatwg.org/multipage/server-sent-events.html).
Duplicate or conflicting length headers, unsupported transfer codings, upgrades,
and unknown response lengths fail closed with a gap. Collection is best-effort;
perf-buffer loss and concurrent I/O can prevent reconstruction. No whole-process
safety guarantee is implied.
