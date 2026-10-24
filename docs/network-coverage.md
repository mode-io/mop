# Network capture coverage

MOP combines passive process probes with authenticated protocol proxies. All
business content comes from observed traffic. Adapter names, message IDs, parts,
coverage flags and gaps are collector metadata. The guard uses the shared policy;
there are no command-specific prompts or inferred authorizations.

## Verified paths

| Runtime / protocol | Capture path | Verification |
| --- | --- | --- |
| System OpenSSL, TLS 1.2 and TLS 1.3 | Passive bpftrace probes | Both negotiated versions and their response bodies captured |
| Python with statically linked OpenSSL | Executable symbol probes | OpenAI SDK 3.19.2 calling DeepSeek; request and response reviewed |
| Conda OpenSSL | Environment library discovery | Conda curl request and gzip response captured |
| Go `crypto/tls` | eCapture GoTLS adapter | Real Go HTTPS client against a private CA-verified server |
| GnuTLS | `gnutls_record_send/recv` probes | Real gnutls-cli HTTPS request and response |
| NSS / NSPR | `PR_Read/Write` probes | Real NSS TLS handshake with an isolated trusted certificate database |
| HTTP/1, chunked bodies and SSE | Passive parser or web proxy | DeepSeek non-streaming and streaming requests, plus local checks |
| HTTP/2 | Bounded passive HPACK/frame decoding or web proxy | Direct HTTP/2 curl with gzip; real gRPC over HTTP/2 |
| HTTP/3 / QUIC v1 | Explicit reverse route | Real aioquic HTTP/3 request and response reviewed by Jev |
| WebSocket / WSS | Web proxy | Both directions of a real WSS echo connection reviewed |
| gRPC | Web proxy | TLS gRPC request/response frames; schema-free protobuf wire values |
| DNS | DNS adapter on loopback port 18953 | Real question and answer reviewed |
| Generic TCP | Dedicated authenticated SOCKS5 adapter | Both directions of a real TCP echo connection reviewed |

A probe starting is not proof of captured content. `mop-network status` reports
running adapters, discovery gaps, source freshness and the latest validation
reports separately. Service health includes restart counts, memory use and the
last systemd result; old successful validation reports are not current health checks. Library discovery runs every 30 seconds; previously unseen,
short-lived binaries can finish before attachment. Existing processes using a
probed library are covered without changing their launch command.

## Use

```bash
bash scripts/setup.sh
mop
mop-network status
```

The installer adds `mop-network` to the existing user command links. Passive
collection starts automatically for the installed UID. Current process display
and kernel collection continue to work independently of content adapters.

For applications requiring the protocol proxy, route a command without editing
its source code:

```bash
mop-network exec -- python app.py
```

This sets proxy and CA-bundle variables only for that process and its children.
It preserves TLS verification. The application must honor those variables and
trust the configured CA. `mop-network env` emits equivalent shell exports; its
output contains the private proxy credentials and should not be logged or shared.
Neither the system trust store nor global routing, firewall, or DNS settings are
changed. Programs that ignore proxy settings require their own route/trust setup.

The web proxy listens on `127.0.0.1:18938`; the dedicated generic TCP SOCKS5 proxy
listens on `127.0.0.1:18939`. Both require per-user credentials. DNS is available
on `127.0.0.1:18953` but is not installed as the machine's resolver. The private
configuration and CA files live under `.runtime/network/` with owner-only access.
No upstream certificate verification is disabled.

HTTP/3 requires an explicit reverse route to a QUIC-capable HTTPS origin:

```bash
mop-network reverse --upstream https://your-http3-origin.example:443 --port 18940
```

This runs in the foreground and listens on loopback TCP/UDP. Configure the client
endpoint and CA trust for that route. Supply `Proxy-Authorization: Basic ...`
using the private per-user proxy credentials. This header is verified and removed
before forwarding; the application's own `Authorization` header remains intact.
The verified HTTP/3 path is QUIC v1 to a QUIC-capable upstream, not automatic
translation to an HTTP/1-only upstream or interception of arbitrary UDP traffic.

## What the guard receives

HTTP responses include the observed request when association is available. HTTP/2
uses stream IDs rather than socket timing. SSE emits complete events before the
whole response finishes. Long, redacted evidence uses numbered JSON fragments.

The proxy decodes gzip and deflate and includes Brotli/Zstandard decoder adapters
when their bundled codec is available. A decode failure is an explicit body
capture gap, not invented plaintext. Protobuf messages retain their original
bytes and can expose field numbers and wire values; field names, signed numeric
types and business schemas are never guessed. Generic binary payloads remain
base64 with semantic decoding marked unavailable.

The same stream can be observed by a passive probe and a routed adapter. These
are separate observations, not two independent confirmations of safety. Proxy
records do not infer a client PID from a socket number. NSPR probes observe a
user-space I/O boundary; an NSPR record alone does not prove that TLS was used.

## Bounds and exclusions

- Passive probes are UID-scoped, limited to eight additional targets, and use
  bounded buffers. TLS/write capture is 3 KiB per call; the Go adapter has its own
  16 KiB event bound. Missing or oversized bytes are reported as gaps.
- HTTP bodies and decompression are bounded at 256 KiB. Passive HTTP/2 buffers
  finite messages until END_STREAM; use the proxy for incremental HTTP/2 SSE.
- Protocol proxies are user services with 512 MiB and one-CPU limits per instance.
  Guard inference is asynchronous and does not block a request on an AI verdict.
- Certificate pinning is not bypassed. Untrusted custom CAs, unknown or stripped
  TLS implementations, library replacement and container namespaces can leave gaps.
- QUIC v2, arbitrary DTLS/UDP, SSH/SFTP plaintext, Unix-socket contents and custom
  application encryption are not universally decoded. Java/Rust/native applications
  are not all individually certified; the routed path requires compatible trust.
- Full process memory, every variable and every operating-system action are not
  covered. Headers such as authorization/cookies and URL queries are omitted;
  payload redaction is best-effort. Capture gaps are not standalone risk findings.

## Validation

```bash
bash scripts/test.sh
/usr/bin/python3 -m unittest discover -s tests -p test_http2_capture.py
python scripts/check-protocols.py
python scripts/check-network.py
python scripts/check-http3.py
```

The protocol client checks require Go, gnutls-cli and certutil; the routed checks
require a Python environment with grpcio, websockets and httpx. `--live` on the
routed check additionally tests the configured DeepSeek endpoint through the
OpenAI SDK. Without it, traffic uses owned local servers. The HTTP/3 check uses
mitmproxy's bundled QUIC implementation and pinned, MIT-licensed aioquic 1.2.0
test helpers cached under `.runtime/aioquic-test` (downloaded only if absent).

Reports are saved in `artifacts/` and are not committed with credentials, payload
logs or private keys. The protocols and limitations of the underlying tools are
also documented by [eCapture](https://ecapture.cc/en/2-core-tls-modules/index.html)
and [mitmproxy](https://docs.mitmproxy.org/stable/concepts/protocols/).

Tetragon has a separate 1 GiB memory ceiling and a 640 MiB Go runtime soft
limit to trigger garbage collection before the service reaches its hard ceiling.
The [Go runtime limit](https://pkg.go.dev/runtime#hdr-Environment_Variables)
does not include all memory attributed to the service. The previous 512 MiB ceiling
caused repeated collector OOM kills on the shared host. This provides headroom,
not a guarantee against memory growth or an explanation of host reboots.
