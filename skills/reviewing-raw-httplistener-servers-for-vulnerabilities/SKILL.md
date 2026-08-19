---
name: reviewing-raw-httplistener-servers-for-vulnerabilities
description: >-
  Review hand-rolled HTTP servers built directly on socket/HttpListener-style
  APIs (System.Net.HttpListener, Node net/http without a framework, raw
  Python socketserver) for the vulnerability classes a framework would
  normally close off: missing request body size limits, slowloris-style
  connection exhaustion, header injection, path/route traversal, token
  leakage via URL query strings, and timing side channels in hand-rolled
  auth comparisons. Use when auditing a lightweight agent, IoT device,
  local dashboard, or fleet-telemetry server that implements HTTP handling
  itself instead of using ASP.NET, Express, Flask, etc.
domain: cybersecurity
subdomain: web-application-security
tags:
  - http
  - httplistener
  - dos
  - slowloris
  - request-smuggling
  - path-traversal
  - header-injection
  - timing-attack
  - secure-code-review
version: '1.0'
author: rollinghills3382
license: Apache-2.0
---
# Reviewing Raw HttpListener Servers for Vulnerabilities

> **Authorized-use-only notice:** This skill is for reviewing servers you own or are authorized to assess (source review, internal pentest, code audit). Do not use the DoS/exhaustion techniques described here against systems you do not have written permission to test.

## Overview

Frameworks like ASP.NET Core, Express, or Flask absorb a long list of HTTP
edge cases for you: they bound request sizes, normalize and validate paths,
reject malformed headers, and time out slow clients. A server built
directly on a low-level listener API (`System.Net.HttpListener` in .NET,
Node's raw `http`/`net` modules, Python's `http.server`/`socketserver`) gets
none of that for free — every one of those protections has to be
hand-written, and it is common for only some of them to be. This is a
frequent pattern in lightweight agents, embedded dashboards, local
management APIs, and fleet-telemetry ingest servers, where a full web
framework is deliberately avoided to keep the dependency footprint small.

This skill is a systematic pass over that hand-rolled HTTP-handling code,
looking specifically for the classes of bug a framework would otherwise
prevent: unbounded request bodies, connection-exhaustion DoS, header/CRLF
injection, path or route traversal in file/route-name inputs, secrets
leaking through URLs, and non-constant-time credential comparisons.

## When to Use

- Reviewing any server that constructs HTTP responses/parses requests
  directly from a socket or `HttpListener`-style API instead of a
  framework.
- Auditing a local agent's "remote view" / management HTTP endpoint bound
  to a LAN interface.
- Reviewing a telemetry-ingest or fleet-dashboard server that receives
  pushes from many untrusted or semi-trusted clients.
- Before shipping a new route or auth mechanism added to an existing
  hand-rolled HTTP server.
- Comparing two servers in the same codebase that share a pattern (e.g. one
  has body-size bounding and a sibling server does not) to find drift.

## Prerequisites

- Read access to the server's request-handling source (listener setup,
  routing dispatch, auth check, response writer).
- A way to run the server locally or in a test environment for the manual
  probes in this workflow.
- `curl`, `openssl s_client` (if TLS is involved), and a scripting
  language (Python or similar) for crafting malformed requests.

```bash
# Common probing tools
curl --version
python3 -c "import socket; print('ok')"
```

## Workflow

### 1. Map the listener and dispatch path
Find where the server binds (`HttpListener.Prefixes`, `net.createServer`,
etc.), what interface/port it binds to (`localhost` only vs. `0.0.0.0`/LAN),
and how requests are dispatched to handlers (per-connection thread,
ThreadPool work item, single-threaded event loop). Note whether dispatch
happens before or after authentication — unauthenticated code paths that do
expensive work (file reads, JSON parsing) are the most valuable DoS targets.

### 2. Check for a body-size bound
Search for `Content-Length` handling and whether it's trusted verbatim or
independently enforced while reading the stream. A server that trusts a
client-supplied `Content-Length` for buffer allocation, or that has no cap
at all on bytes read from the request body, is vulnerable to memory
exhaustion from a single oversized POST.

```bash
# Send an oversized body and watch server memory/CPU
python3 -c "
import socket
s = socket.create_connection(('TARGET_HOST', PORT))
body = b'A' * (200 * 1024 * 1024)
req = b'POST /ingest HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n' % len(body)
s.sendall(req + body)
print(s.recv(200))
"
```

A safe implementation reads the body through a bounded/counting stream that
enforces a max size independent of the declared `Content-Length` (which the
client can lie about) and rejects or truncates over-limit requests before
buffering the whole thing in memory.

### 3. Probe for slowloris-style connection exhaustion
If connections are dispatched one-per-thread or one-per-worker with no idle
timeout, a client that opens many connections and sends bytes slowly (or
never finishes headers) can exhaust the thread pool or file-descriptor
limit.

```bash
# Simple slow-header probe against a single connection
python3 -c "
import socket, time
s = socket.create_connection(('TARGET_HOST', PORT))
s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n')
for _ in range(30):
    s.sendall(b'X-Pad: a\r\n')
    time.sleep(2)
"
```

Confirm the server has a read/idle timeout on both the header and body
phases, and a cap on total concurrent connections/threads so one slow
client can't monopolize the pool.

### 4. Check header and status-line construction for CRLF injection
Any place the server writes a value it received from elsewhere (a redirect
`Location`, an echoed header, a log line formatted into a response) into a
raw response header must strip or reject `\r`/`\n`. Grep for string
concatenation into header-writing code rather than use of an API that
handles this for you.

```bash
grep -rn "Headers\[" --include="*.cs" .
grep -rn "response.setHeader\|res.header(" --include="*.js" .
```

### 5. Check route/path-segment handling for traversal
For any route that takes a path segment or filename from the URL (e.g.
`/machine/{name}`, `/file/{path}`) and uses it to build a file path, key
lookup, or nested route, confirm the segment is URL-decoded exactly once
and then rejected (not silently stripped) if it contains `/`, `\`, or `..`.
Decoding twice, or decoding after the traversal check, reintroduces the
bug.

```bash
curl "http://TARGET_HOST:PORT/machine/..%2f..%2fetc%2fpasswd"
curl "http://TARGET_HOST:PORT/machine/%2e%2e%2f%2e%2e%2fsecret"
```

### 6. Check where auth tokens travel
If the server accepts a shared token via `?token=` query string as well as
a header, confirm the code doesn't only support the URL form (query strings
land in server access logs, browser history, and `Referer` headers sent to
third parties). If a token is embedded in an HTML page for client-side JS
to use, confirm it's stripped from the visible URL (e.g. via
`history.replaceState`) rather than left in the address bar.

### 7. Check the token/credential comparison for timing safety
Find the comparison used to validate the shared token or session
credential. A `==`/`Equals` comparison, or a loop that returns as soon as
it finds a mismatching byte, leaks timing information proportional to the
number of correct leading bytes. Confirm a constant-time comparison is
used — and check whether it *also* short-circuits on a length mismatch
before that loop runs, which still leaks the correct length even in an
otherwise constant-time implementation.

```csharp
// Weaker: leaks length via early return
if (a.Length != b.Length) return false;
for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
return true;

// Stronger: compare over a fixed length regardless of input length
// (e.g. HMAC both inputs to a fixed-size digest first, or pad to a
// known max length before the constant-time loop)
```

### 8. Confirm exception handling doesn't leak internals or crash the listener
Verify every request handler is wrapped so an unhandled exception in one
request doesn't take down the whole listener loop, and that error
responses don't include stack traces, file paths, or internal exception
messages to the client.

## Key Concepts

| Concept | Why it matters |
|---|---|
| Trusted `Content-Length` | Client-controlled; must not size allocations without an independent cap |
| Idle/read timeout | Missing timeout turns slow clients into a DoS primitive (slowloris) |
| CRLF injection | Unsanitized values written into raw headers can split/smuggle responses |
| Path traversal via decode-then-check ordering | Decoding twice or checking before final decode reintroduces the bug |
| Token-in-URL leakage | Query-string tokens land in logs, history, and `Referer` headers |
| Timing side channel | Non-constant-time compares, or length short-circuits, leak credential info |
| Per-request exception isolation | One bad request must not crash the shared listener loop |

## Tools & Systems

| Tool | Purpose |
|---|---|
| `curl` | Manual request crafting, header/path traversal probes |
| Raw `socket` (Python) | Crafting oversized bodies, slow-header connections, malformed requests |
| `ss` / `netstat` | Confirm bind interface (localhost vs. 0.0.0.0) and connection counts under load |
| Static grep across handler code | Locate header-writing, path-building, and comparison logic quickly |
| Load-testing tool (e.g. `hey`, `wrk`) | Confirm behavior under many concurrent slow/fast connections |

## Common Scenarios

- **Two sibling servers in one codebase, one hardened one not.** A common
  finding: an internal/admin server reuses the same auth pattern as a
  public-facing one but skips the body-size bound "because it's internal" —
  flag this explicitly, since internal-only assumptions erode over time.
- **Token embedded in dashboard HTML.** Confirm the token is scrubbed from
  the URL bar after page load and never appears in an `<a href>` or
  external resource request that would send it via `Referer`.
- **Route parameter reused as a cache/file key.** Even without full
  filesystem traversal, an unvalidated route segment used as a dictionary
  key or log-file name can enable log injection or unbounded key growth.

## Output Format

For each finding report: file/line, the vulnerable pattern, a concrete
proof-of-concept request or script, the impact (DoS, info leak, auth
bypass), and a specific remediation (e.g. "wrap the request stream in a
bounded/counting stream capped at N bytes before the JSON parser runs").
Group findings by server/listener if the codebase has more than one.

## Validation Criteria

- [ ] Listener bind interface and dispatch model documented
- [ ] Body-size bound tested with an oversized request
- [ ] Idle/read timeout tested with a slow-header connection
- [ ] Header-writing code checked for CRLF injection
- [ ] Route/path-segment handling tested for traversal (encoded and
      double-encoded)
- [ ] Token transport checked for URL/log/Referer leakage
- [ ] Auth comparison checked for constant-time behavior, including length
      short-circuit
- [ ] Exception handling confirmed isolated per-request
- [ ] Findings documented with PoC and remediation per issue
