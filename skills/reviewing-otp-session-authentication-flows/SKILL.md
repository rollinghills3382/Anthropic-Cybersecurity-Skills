---
name: reviewing-otp-session-authentication-flows
description: >-
  Review email/SMS one-time-code (OTP) login flows and the session-cookie
  mechanism they establish, as distinct from static shared-token or API-key
  auth in the same application. Covers session-cookie attribute checks
  (HttpOnly, Secure, SameSite), OTP brute-force and rate-limiting, account-
  enumeration timing parity, OTP entropy and expiry, and session fixation.
  Use when reviewing a hosted/multi-tenant login flow added alongside an
  existing shared-token auth model, or any passwordless OTP-based
  authentication system.
domain: cybersecurity
subdomain: identity-access-management
tags:
  - otp
  - session-management
  - authentication
  - account-enumeration
  - session-fixation
  - cookie-security
  - secure-code-review
version: '1.0'
author: rollinghills3382
license: Apache-2.0
---
# Reviewing OTP Session Authentication Flows

> **Authorized-use-only notice:** This skill is for reviewing authentication systems you own or are authorized to assess. Do not run brute-force or enumeration probes against a login flow you don't have permission to test.

## Overview

It's common for an application to grow a second authentication mechanism
over time: it starts with a single shared token or API key (simple,
adequate for a single-tenant or trusted-network deployment), and later
adds an email- or SMS-based one-time-code login for a hosted, multi-tenant,
or human-facing surface. This second flow introduces an entirely different
set of security properties to get right — session cookies instead of a
static token, a code-guessing/brute-force surface instead of a
compare-a-string surface, account enumeration risk from the "does this
email have an account" step, and session-lifecycle concerns (fixation,
logout, expiry) that a bearer-token model doesn't have. Because it's newer
and layered on top of an existing auth model, it's also the piece most
likely to have received less security scrutiny than the original
mechanism.

This skill reviews that OTP + session flow specifically, separately from
whatever token-based auth coexists with it.

## When to Use

- Reviewing a newly added or existing email/SMS OTP login flow.
- Auditing the session-cookie mechanism a login flow establishes (cookie
  attributes, session storage, expiry, logout).
- Investigating a report of account takeover, session hijacking, or
  brute-forced OTP codes.
- Comparing a hosted/multi-tenant auth surface against a simpler existing
  shared-token model in the same codebase to ensure it wasn't held to a
  lower bar.

## Prerequisites

- Test accounts with valid and invalid email addresses on the target
  system.
- `curl` or a scripted HTTP client for timing and enumeration tests.
- Read access to the OTP generation, verification, and session-issuance
  code.

```bash
curl --version
```

## Workflow

### 1. Check OTP entropy and expiry
Confirm the one-time code has enough entropy to resist brute-forcing
within its validity window (a 6-digit numeric code, for example, is
1,000,000 possibilities — this is only safe if paired with rate limiting
and a short expiry; without both, it's guessable). Confirm the code
expires and becomes unusable after a bounded time, and that requesting a
new code invalidates any previous outstanding code for that account rather
than leaving multiple valid codes active simultaneously.

```bash
grep -n "GenerateCode\|OtpLength\|CodeExpiry\|TimeSpan.From" LoginFlow.cs
```

### 2. Test for OTP brute-force / rate limiting
Attempt repeated incorrect code submissions against a single login attempt
and confirm the server locks out, delays, or invalidates the attempt after
a small number of failures — rather than allowing unlimited guesses within
the code's validity window.

```bash
for code in 000000 000001 000002 000003 000004; do
  curl -s -X POST http://TEST_HOST/login/verify \
    -d "email=test@example.com&code=$code"
done
```

### 3. Check for account-enumeration timing/response differences
Compare the server's response (timing and content) for a login-code
request against a known-existing account versus a known-nonexistent one.
Both the response body/status and the response *timing* should be
indistinguishable — a flow that does real work (send email, hash lookups)
only for existing accounts and returns immediately for nonexistent ones
leaks account existence via a timing side channel even if the response
bodies look identical.

```bash
time curl -s -X POST http://TEST_HOST/login/request -d "email=real@example.com"
time curl -s -X POST http://TEST_HOST/login/request -d "email=definitely-not-registered-xyz@example.com"
```

### 4. Verify session-cookie attributes
Inspect the `Set-Cookie` header issued on successful login and confirm:
- `HttpOnly` is set (prevents JS/XSS access to the session token).
- `Secure` is set (prevents transmission over plain HTTP).
- `SameSite` is set to `Lax` or `Strict` as appropriate (mitigates CSRF).
- The cookie has a reasonable expiry/idle-timeout rather than being
  effectively permanent.

```bash
curl -s -i -X POST http://TEST_HOST/login/verify \
  -d "email=test@example.com&code=$VALID_CODE" | grep -i "set-cookie"
```

### 5. Test for session fixation
Attempt to set a known session identifier before authentication (if the
application issues any pre-auth session/cookie) and confirm that
completing login issues a *new* session identifier rather than continuing
to honor the pre-auth one. If a session ID can be fixed before login and
remains valid after, an attacker who tricks a victim into using an
attacker-chosen session ID can hijack the post-login session.

### 6. Confirm logout actually invalidates the server-side session
Log in, capture the session cookie, call logout, and then replay the
captured cookie against an authenticated endpoint. Confirm the request is
rejected — logout must invalidate server-side session state, not merely
clear the cookie client-side (which does nothing against a replayed
cookie).

```bash
curl -s -X POST http://TEST_HOST/logout -b "smsession=$CAPTURED_COOKIE"
curl -s -i http://TEST_HOST/api/protected -b "smsession=$CAPTURED_COOKIE"
```

### 7. Check how this flow coexists with any static shared-token auth
If the application also supports a static shared token or API key
alongside OTP/session login, confirm the two mechanisms are cleanly
separated — a session cookie shouldn't grant access to token-authenticated
endpoints or vice versa unless that's an explicit, reviewed design
decision, and confirm neither mechanism was implemented to a lower
security bar under the assumption "the other one is the primary defense."

## Key Concepts

| Concept | Why it matters |
|---|---|
| OTP entropy vs. rate limiting | Numeric codes are only safe when brute-force attempts are strictly bounded |
| Single active code per account | Multiple simultaneously valid codes widen the guessing window |
| Account-enumeration timing parity | Differing response time/content for real vs. fake accounts leaks account existence |
| Session-cookie attributes | `HttpOnly`/`Secure`/`SameSite` each close a distinct attack vector (XSS, cleartext transit, CSRF) |
| Session fixation | Login must always issue a fresh session identifier, never continue a pre-auth one |
| Server-side logout invalidation | Client-side cookie clearing alone doesn't stop a replayed session token |
| Cross-mechanism auth boundaries | Session and static-token auth must not silently grant each other's access |

## Tools & Systems

| Tool | Purpose |
|---|---|
| `curl` | Scripted login/verify/logout requests, cookie inspection, timing comparisons |
| Browser DevTools (Application/Storage tab) | Inspect actual cookie attributes as set by the browser |
| Scripted timing harness | Measure response-time parity between real and fake account requests |
| Burp Suite / OWASP ZAP (optional) | Intercept and replay session tokens, automate brute-force rate-limit testing |

## Common Scenarios

- **OTP flow added later, held to a lower bar than the original auth.**
  When a codebase's primary auth is a well-reviewed shared token and OTP
  login was added afterward for a new hosted tier, explicitly check
  whether the newer flow received the same scrutiny — rate limiting and
  enumeration parity are easy to skip under time pressure.
- **"Constant-time" login response that still leaks via side effects.**
  A response body deliberately worded identically for real/fake accounts
  can still leak account existence if only real accounts trigger an
  observable side effect (an email actually sent, a database write) with a
  measurably different latency.
- **Session cookie scoped too broadly.** If the session cookie's `Domain`
  or `Path` is broader than necessary, it may be sent to endpoints or
  subdomains that don't need it, widening exposure if any of those
  surfaces has an XSS or open-redirect issue.

## Output Format

For each finding report: the specific step or endpoint, the property that
failed (missing rate limit, missing cookie attribute, enumeration leak,
etc.), a reproducing request sequence, the impact (account takeover,
session hijack, account enumeration), and remediation.

## Validation Criteria

- [ ] OTP entropy and expiry documented and assessed as adequate given
      the rate-limiting in place
- [ ] Requesting a new code confirmed to invalidate prior outstanding
      codes
- [ ] Brute-force attempt tested and confirmed rate-limited/locked out
- [ ] Account-enumeration response and timing parity tested for
      real vs. fake accounts
- [ ] Session cookie attributes (`HttpOnly`, `Secure`, `SameSite`, expiry)
      verified
- [ ] Session fixation tested (pre-auth session ID not honored post-login)
- [ ] Logout confirmed to invalidate the session server-side, not just
      client-side
- [ ] Coexistence with any static shared-token auth reviewed for
      cross-mechanism boundary issues
- [ ] Findings documented with reproducing steps and remediation per
      issue
