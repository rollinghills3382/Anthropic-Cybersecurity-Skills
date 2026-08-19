---
name: hardening-json-deserialization-of-untrusted-telemetry
description: >-
  Review and harden server-side JSON parsing of telemetry, metrics, or
  event payloads pushed by many untrusted or semi-trusted remote clients
  (agents, IoT devices, fleet nodes). Covers size and depth limits,
  malformed/oversized payload handling, resource-exhaustion patterns
  (deeply nested structures, huge arrays/strings, numeric overflow),
  deserializer selection (hand-rolled vs. hardened library), and
  ingest-endpoint rate limiting. Use when reviewing a fleet-telemetry
  ingest endpoint, a metrics-collection server, or any endpoint that
  deserializes JSON from many independent, network-reachable senders.
domain: cybersecurity
subdomain: application-security
tags:
  - deserialization
  - json
  - dos
  - resource-exhaustion
  - input-validation
  - telemetry
  - secure-code-review
version: '1.0'
author: rollinghills3382
license: Apache-2.0
---
# Hardening JSON Deserialization of Untrusted Telemetry

> **Authorized-use-only notice:** This skill is for reviewing and testing ingest endpoints you own or are authorized to assess. Resource-exhaustion tests can degrade or crash a live service — run them against a test environment.

## Overview

Fleet-telemetry and metrics-ingest endpoints have a distinctive trust
profile: they accept JSON payloads over the network from many independent
senders (agents deployed across a fleet of machines), often with a shared
or per-client token rather than strong per-request authentication, and the
payload structure is dictated by the sender, not the server. This is a
textbook untrusted-input boundary, but it's easy to under-scope the review
to "did we validate the fields" while missing the resource-exhaustion
angle: a single crafted payload — deeply nested JSON, a multi-gigabyte
string field, a huge array — can consume disproportionate CPU or memory
during parsing alone, before any field-level validation runs, especially
when the deserializer in use predates modern hardened defaults (e.g.
`System.Web.Script.Serialization.JavaScriptSerializer`, older Jackson/
Gson configurations, or a hand-rolled parser).

This skill reviews the ingest path end-to-end: transport-level size
bounding, the deserializer's own limits, post-parse structural validation,
and the operational controls (rate limiting, per-client quotas) that back
up the code-level defenses.

## When to Use

- Reviewing any endpoint that deserializes JSON (or another structured
  format) from network clients that aren't fully trusted.
- Auditing a fleet-telemetry, metrics-collection, or webhook-ingest server
  before or after adding a new field to the wire format.
- Investigating a resource-exhaustion or availability incident traced to
  the ingest path.
- Evaluating whether to switch a deserializer (e.g. from a legacy
  `JavaScriptSerializer`/hand-rolled parser to a modern, hardened library).

## Prerequisites

- Read access to the ingest handler and the deserializer configuration in
  use.
- A test environment where oversized/malformed payloads can be sent
  without affecting production.
- A scripting language for generating pathological JSON payloads.

```bash
python3 --version   # for payload generation scripts below
```

## Workflow

### 1. Confirm a transport-level size bound exists independent of the parser
Before any JSON parsing happens, confirm the request body is read through a
bounded stream that caps total bytes read, independent of (and not solely
reliant on) a client-supplied `Content-Length` header. This bound should
sit in front of the deserializer, not rely on the deserializer to reject
an oversized string after most of it has already been buffered.

```bash
grep -n "MaxJsonLength\|BoundedStream\|Content-Length" IngestHandler.cs
```

### 2. Identify the deserializer and its known limits
Determine exactly which JSON library/API is in use and what its default
behavior is for nesting depth, string length, and numeric parsing. Legacy
or "simple" deserializers (`JavaScriptSerializer`, hand-rolled recursive-
descent parsers) often have weak or absent depth limits by default; modern
libraries (`System.Text.Json`, recent Jackson/Gson) generally have safer
defaults but can still be misconfigured.

```bash
grep -rn "JavaScriptSerializer\|JsonSerializer\|JObject.Parse\|json.loads" .
```

### 3. Test deeply nested payloads for stack/resource exhaustion
Craft a payload with pathological nesting depth and confirm the server
rejects it gracefully (a controlled error) rather than exhausting the call
stack or taking disproportionate CPU/memory.

```python
# generate_deep_nesting.py
import json
depth = 100000
payload = "[" * depth + "1" + "]" * depth
open("deep.json", "w").write(payload)
```

```bash
curl -X POST http://TEST_HOST/ingest \
  -H "Content-Type: application/json" \
  --data-binary @deep.json
```

### 4. Test oversized string/array fields
Craft a payload that's within any overall size cap but concentrates the
bytes into a single field (a huge string value, a huge array of small
elements) and confirm per-field limits exist, not just an overall payload
cap — some parsers handle total size fine but choke on a single
pathologically large token.

```python
payload = {"hostname": "A" * (50 * 1024 * 1024), "metrics": []}
```

### 5. Test numeric edge cases
Send fields with values at or beyond the expected numeric type's range
(e.g. a metric value of `1e400`, a negative timestamp, `NaN`/`Infinity` if
the format allows it) and confirm downstream code handles out-of-range or
non-finite values without throwing an unhandled exception or corrupting
stored data.

### 6. Confirm malformed payloads produce a clean 4xx, not a 5xx or hang
Send syntactically invalid JSON (truncated, mismatched brackets, invalid
UTF-8) and confirm the server responds quickly with a client-error status
rather than hanging, crashing the worker, or logging the entire raw
(potentially huge) payload at high verbosity.

```bash
curl -X POST http://TEST_HOST/ingest \
  -H "Content-Type: application/json" \
  --data-binary '{"hostname": "test", "metrics": [1,2,'
```

### 7. Check post-parse structural validation
After successful deserialization, confirm the code validates the resulting
object graph against an expected shape (required fields present, arrays
bounded in length, string fields bounded in length) before using it —
successful parsing is not the same as a well-formed, trustworthy payload.

### 8. Review rate limiting and per-client quotas
Determine whether the ingest endpoint has any per-client (per-token, per-
source-IP) rate limit. Even with all the above hardened, an endpoint with
no rate limit is still vulnerable to volumetric abuse from a single
compromised or malicious legitimate client sending valid-but-excessive
traffic.

## Key Concepts

| Concept | Why it matters |
|---|---|
| Transport-level size bound before parsing | Prevents buffering an oversized body before the parser ever sees it |
| Nesting-depth limits | Deep nesting can exhaust the call stack in recursive-descent parsers |
| Per-field vs. total-size limits | A parser can be safe on total size but still vulnerable to one huge field |
| Numeric edge-case handling | Out-of-range/non-finite values can crash or corrupt downstream logic |
| Clean failure on malformed input | Malformed payloads should fail fast with a 4xx, not hang or crash the worker |
| Post-parse structural validation | A successfully parsed object is not automatically a well-formed one |
| Per-client rate limiting | Code-level hardening doesn't substitute for volumetric abuse controls |

## Tools & Systems

| Tool | Purpose |
|---|---|
| `curl` | Send crafted malformed/oversized/deeply-nested payloads |
| Python payload generators | Construct pathological JSON test cases |
| Load-testing tool (`hey`, `wrk`, `ab`) | Measure resource consumption under crafted-payload load |
| Process/resource monitor (`top`, Task Manager, `dotnet-counters`) | Observe CPU/memory during payload tests |

## Common Scenarios

- **Legacy deserializer inherited from an older codebase.** A hand-rolled
  or older-generation JSON library kept for compatibility often lacks the
  depth/size defaults a modern library would apply automatically — treat
  its absence of documented limits as a finding, not an assumption of
  safety.
- **A shared size cap reused across agent and server.** If the same
  constant defines the max payload size on both the sending agent and the
  receiving server, confirm the server still independently enforces it
  (never trust the sender to have applied the client-side limit) and that
  the cap is actually large enough for legitimate payloads while still
  bounding worst-case memory use.
- **High-verbosity logging of raw ingest payloads.** Logging full request
  bodies at debug/info level on a malformed-payload path can itself become
  a disk-exhaustion or log-injection vector — check log level and any
  truncation applied to logged payloads.

## Output Format

For each finding report: the endpoint/handler, the specific missing or
weak limit, a reproducing payload or script, the observed resource impact
(CPU spike, memory growth, hang duration), and remediation (e.g. "wrap the
request stream in a size-bounded reader capped at N MB before handing it
to the deserializer" or "configure the parser's max depth explicitly
rather than relying on default behavior").

## Validation Criteria

- [ ] Transport-level size bound confirmed independent of client-supplied
      `Content-Length`
- [ ] Deserializer identified and its depth/size defaults documented
- [ ] Deeply nested payload tested for stack/resource exhaustion
- [ ] Oversized single-field payload tested independent of total size cap
- [ ] Numeric edge cases tested for unhandled exceptions/corruption
- [ ] Malformed payload confirmed to produce a fast, clean 4xx response
- [ ] Post-parse structural validation confirmed present
- [ ] Per-client rate limiting reviewed and documented
- [ ] Findings documented with reproducing payload and remediation per
      issue
