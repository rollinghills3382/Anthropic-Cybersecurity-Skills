---
name: auditing-ecdsa-license-signature-schemes
description: >-
  Audit hand-rolled software license and signed-assertion verification
  code (ECDSA, RSA, or similar public-key signature schemes used to sign
  license keys, entitlement tokens, or revocation assertions) for
  verify-before-parse ordering bugs, missing or unbounded replay windows,
  algorithm-confusion/downgrade attacks, embedded public-key tampering
  risk, and offline signing-key isolation. Use when reviewing a license
  activation system, an offline key generator paired with an in-app
  verifier, or any signed-token scheme that isn't using a standard,
  well-audited library like JWT/JWS end-to-end.
domain: cybersecurity
subdomain: cryptography
tags:
  - ecdsa
  - signature-verification
  - license-key
  - replay-attack
  - algorithm-confusion
  - secure-code-review
  - public-key-cryptography
version: '1.0'
author: rollinghills3382
license: Apache-2.0
---
# Auditing ECDSA License Signature Schemes

> **Authorized-use-only notice:** This skill is for reviewing signature-verification code you own or are authorized to assess. Do not use it to bypass licensing on software you don't have rights to.

## Overview

Many desktop and agent applications implement their own license-key or
entitlement scheme rather than adopting a full licensing platform: an
offline tool signs a payload (customer ID, expiry, tier) with a private
key, and the shipped application verifies that signature with an embedded
public key before trusting the payload. This is a reasonable design, but
because it's hand-rolled rather than built on a vetted library like JWS, it
reproduces classic signature-verification bugs: parsing the payload before
checking the signature, trusting a client-supplied algorithm identifier,
unbounded replay windows on time-limited assertions, and public-key
material that can be swapped or bypassed if the check isn't wired
correctly. A second, related pattern shows up when the app also accepts
short-lived signed assertions from a server at runtime (e.g. "license has
been revoked") — these need their own replay-window analysis distinct from
the long-lived license key itself.

This skill walks through a systematic review of that verification path,
from key embedding through signature check to payload trust.

## When to Use

- Reviewing a license-key verification routine that uses raw
  ECDSA/RSA/DSA APIs (e.g. `ECDsaCng`, `RSACryptoServiceProvider`,
  OpenSSL bindings) rather than a standard JWT/JWS library.
- Auditing an offline key generator/signer tool alongside the in-app
  verifier it pairs with.
- Reviewing any "signed server assertion" mechanism used for runtime
  entitlement or revocation checks distinct from the primary license key.
- Before changing the public key embedding, the payload format, or the
  signature algorithm in an existing licensing system.

## Prerequisites

- Read access to both the verifier code (in the shipped app) and the
  signer code (in the offline/vendor tool), if both exist.
- A way to generate test key pairs and craft signed/unsigned/tampered
  payloads for the algorithm in use.
- OpenSSL or a language-native crypto library for constructing test
  vectors.

```bash
openssl ecparam -name prime256v1 -genkey -noout -out test_priv.pem
openssl ec -in test_priv.pem -pubout -out test_pub.pem
```

## Workflow

### 1. Identify the algorithm and confirm it's not client-selectable
Confirm the verifier hardcodes the expected curve/algorithm (e.g. ECDSA
P-256 with SHA-256) rather than reading an algorithm identifier from the
untrusted payload and dispatching based on it. A verifier that trusts a
payload-supplied "alg" field is vulnerable to algorithm-confusion attacks
(e.g. an attacker crafting a payload that claims a weaker or
symmetric-keyed scheme the verifier will happily check against embedded
key material never meant for that purpose).

```bash
grep -rn "ECDsa\|RSACryptoServiceProvider\|SignatureAlgorithm" --include="*.cs" .
```

### 2. Confirm signature verification happens before payload parsing
The single most important ordering check: the code must verify the
signature over the raw bytes first, and only parse/deserialize the payload
into structured fields (expiry date, tier, customer ID) after verification
succeeds. If the payload is parsed first (e.g. to decide *how* to verify
it, or because parsing and verifying are interleaved), a malformed or
crafted payload can reach parsing logic — and any bug there — without ever
holding a valid signature.

```bash
# Trace the call order: does Parse() happen before or after Verify()?
grep -n "Verify\|Parse\|Deserialize" LicensingFile.cs | head -30
```

### 3. Test with a tampered payload and an unmodified signature
Confirm that changing even one byte of the signed payload (e.g. flipping
the tier field or extending the expiry date) while leaving the signature
untouched causes verification to fail. This is the most basic
"does verification actually gate trust" sanity check, but it's worth
running explicitly rather than assuming from reading code.

```python
# pseudo-workflow
payload = load_valid_license()
payload_tampered = flip_one_byte(payload, offset=EXPIRY_FIELD_OFFSET)
assert verify(payload_tampered, original_signature) == False
```

### 4. Check the embedded public key for tamper resistance
Confirm the public key used for verification is a compiled-in constant
(not read from a user-writable config file, registry key, or adjacent
file the license itself could influence). If the public key ever comes
from anything other than the binary itself, an attacker who can write to
that location can substitute their own key pair and self-sign licenses.

```bash
grep -n "PublicKeyBlob\|EccPublicBlob\|pubkey" LicensingFile.cs
```

### 5. Audit replay windows on short-lived signed assertions
For any secondary signed-assertion scheme (e.g. a server-issued
"revocation status" or "entitlement refresh" token distinct from the
primary license), find the max-age/expiry check applied after signature
verification. Confirm:
- There **is** a max-age check (a validly-signed assertion with no
  expiry embedded, or with expiry never checked, can be replayed forever).
- The max-age window is bounded to what the use case actually needs (a
  60-minute window for a revocation check is reasonable; an unbounded or
  multi-day window materially weakens the revocation mechanism it exists
  to support).
- The check compares against a trustworthy clock source and handles clock
  skew/rollback sanely (a naive check can be defeated by setting the local
  clock backward).

```bash
grep -n "MaxAge\|DateTime.UtcNow\|Expiry\|TimeSpan.From" LicensingFile.cs
```

### 6. Confirm the private signing key never ships
Verify the private key used to sign licenses exists only in the offline
generator/vendor tool source and build output, never in the shipped
application, its installer, or any file that ends up on a customer
machine. Check build scripts for accidental inclusion.

```bash
grep -rln "PrivateKeyBlob\|BEGIN EC PRIVATE KEY" src/ scripts/ 2>/dev/null
```

### 7. Check machine-binding/fingerprint derivation (if present)
If the license binds to a machine fingerprint, confirm the fingerprint is
derived one-way (e.g. hashed) from a stable machine identifier, and assess
how easily that identifier can be spoofed or how it behaves across
legitimate hardware changes (this is a product-design tradeoff to surface,
not necessarily a bug).

## Key Concepts

| Concept | Why it matters |
|---|---|
| Verify-then-parse ordering | Parsing before verification exposes unauthenticated data to parsing bugs |
| Algorithm confusion | A client/payload-selectable algorithm lets an attacker choose a weak path |
| Embedded public key integrity | A key sourced outside the binary can be swapped by an attacker |
| Replay window | Signed-but-expired assertions must be rejected, with a deliberately bounded max-age |
| Private key isolation | The signing key must never exist outside the offline signer/vendor tooling |
| Machine-fingerprint one-wayness | Binding identifiers should be hashed, not stored/transmitted raw |

## Tools & Systems

| Tool | Purpose |
|---|---|
| OpenSSL | Generate test key pairs, sign/verify test vectors by hand |
| Language-native crypto API (`ECDsaCng`, `cryptography`, etc.) | Match the exact algorithm/curve under test |
| Hex editor / byte-level scripting | Craft tampered payloads with unmodified signatures |
| Static grep across signer + verifier source | Trace verify/parse ordering and key sourcing |

## Common Scenarios

- **Shared verification code compiled into multiple targets.** When the
  same license-verification file compiles into the main app, a vendor key
  server, and a hosted-mode server component, confirm each target embeds
  only the public key and never links against signing-key code paths not
  meant for it.
- **Revocation-assertion replay.** A signed "not revoked" assertion cached
  client-side with no expiry effectively disables revocation — confirm the
  max-age is enforced on every check, not just at initial activation.
- **Legacy/back-compat algorithm paths.** If the codebase carries an older
  verification path for a previous key format, confirm it can't be forced
  as a downgrade by an attacker presenting an old-format payload against a
  still-accepted legacy verifier.

## Output Format

For each finding report: file/line, the specific ordering or validation
gap, a proof-of-concept payload/signature pair demonstrating the issue
where practical, the impact (license bypass, revocation bypass, key
compromise), and remediation. Note explicitly whether private key material
was found anywhere in the shipped artifact tree.

## Validation Criteria

- [ ] Algorithm/curve confirmed hardcoded, not payload-selectable
- [ ] Signature verification confirmed to precede payload parsing
- [ ] Tampered-payload test confirms verification actually gates trust
- [ ] Embedded public key confirmed sourced from the binary, not a
      writable location
- [ ] Replay window on any short-lived signed assertion confirmed present
      and appropriately bounded
- [ ] Private signing key confirmed absent from shipped artifacts
- [ ] Machine-fingerprint derivation (if present) confirmed one-way
- [ ] Findings documented with PoC and remediation per issue
