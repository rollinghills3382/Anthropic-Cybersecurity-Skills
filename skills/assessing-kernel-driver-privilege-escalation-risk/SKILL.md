---
name: assessing-kernel-driver-privilege-escalation-risk
description: >-
  Assess privilege-escalation risk in elevated (administrator/root) desktop
  applications that load third-party kernel drivers or driver-backed
  libraries for low-level hardware access — MSR reads, sensor/HID access,
  hardware monitoring libraries that install their own driver service.
  Covers driver-service privilege boundaries, arbitrary-MSR read/write
  exposure, DLL search-order and side-loading risk for vendored native
  binaries, and blast-radius analysis for a compromised elevated process.
  Use when reviewing a hardware-monitoring app, a system-tray utility that
  runs elevated, or any Windows/Linux app that ships or loads a kernel
  driver as a dependency.
domain: cybersecurity
subdomain: endpoint-security
tags:
  - privilege-escalation
  - kernel-driver
  - dll-hijacking
  - msr
  - elevation
  - windows-security
  - secure-code-review
version: '1.0'
author: rollinghills3382
license: Apache-2.0
---
# Assessing Kernel Driver Privilege Escalation Risk

> **Authorized-use-only notice:** This skill is for reviewing applications and drivers you own or are authorized to assess. Loading or probing kernel drivers can crash or destabilize a system — test only in a disposable VM.

## Overview

Applications that need low-level hardware telemetry — CPU temperature,
voltage, fan speed, raw MSR (Model-Specific Register) access, HID device
data — often can't get it from userland alone. The common solution is to
run the whole process elevated and either load a kernel driver directly, or
depend on a third-party library (a hardware-monitoring SDK, an MSR-access
helper) that installs and loads its own kernel driver service as a side
effect. This is a legitimate and common pattern, but it meaningfully raises
the stakes of *everything else* in that process: a memory-safety bug,
DLL-hijacking opportunity, or logic flaw anywhere in an elevated process
that also holds a live handle to a kernel driver capable of arbitrary MSR
access is a much higher-value target than the same bug in an unprivileged
app, because it sits one step from ring-0 code execution or system
instability.

This skill is a review pass focused specifically on that elevation +
driver-dependency combination: what the driver actually exposes, how it's
loaded, whether the loading path is tamper-resistant, and what the blast
radius looks like if the elevated process itself is compromised.

## When to Use

- Reviewing any application that ships with `requireAdministrator` (or
  runs as root/via a privileged service) and links against a
  hardware-access library.
- Auditing a vendored kernel-driver-backed library (a hardware monitoring
  SDK, an MSR helper module) before adding it as a dependency.
- Investigating whether a memory-corruption or injection bug elsewhere in
  an elevated process could be escalated via a co-resident driver handle.
- Reviewing update/patch cadence and provenance for vendored driver
  binaries that aren't fetched via a package manager with signature
  verification.

## Prerequisites

- A disposable VM or sandboxed test machine — do not run driver-loading
  experiments on a primary machine.
- Sysinternals tools (`Process Explorer`, `Sigcheck`, `Autoruns`) on
  Windows, or `lsmod`/`modinfo` on Linux, for inspecting loaded drivers.
- Read access to the application's driver-loading code and its vendored
  binary directory.

```powershell
# Windows: inspect a loaded driver's signer and version
sigcheck.exe -a C:\path\to\driver.sys
driverquery /v
```

## Workflow

### 1. Confirm why elevation is actually required
Read the application's stated rationale for `requireAdministrator` (a
manifest comment, a privacy/security doc, an issue thread). Confirm every
capability that requires elevation genuinely needs it — MSR access and
kernel-driver loading do, but confirm the app isn't also doing unrelated,
unprivileged work (network servers, file I/O, UI) inside the same elevated
process when it could be split into an unprivileged front-end plus a
narrow elevated helper.

### 2. Enumerate every driver-backed dependency
List every vendored binary that installs or talks to a kernel driver
service, not just the obvious one. Hardware-monitoring SDKs commonly do
this transparently — the app author may not always realize a bundled
library is installing a driver service as a side effect of first use.

```bash
grep -rn "CreateFile.*\\\\\\\\.\\\\|DeviceIoControl\|InstallDriver\|OpenSCManager" \
  --include="*.cs" .
```

### 3. Map what the driver interface actually exposes
For each driver, determine the IOCTL surface: does it expose a narrow,
purpose-built API (e.g. "read this specific set of known-safe MSRs"), or a
general-purpose primitive (arbitrary MSR read/write, arbitrary physical
memory access, arbitrary port I/O)? A general-purpose primitive is
significantly more dangerous if reachable by anything other than the
intended caller, because it effectively grants kernel-level read/write to
whoever can talk to the driver.

```bash
grep -n "IOCTL_\|MSR_READ\|MSR_WRITE\|PhysicalMemory" HardwareInteropFile.cs
```

### 4. Check whether the driver's access is scoped to the loading process
Confirm the driver device object's ACL (or equivalent access control) is
scoped tightly — ideally callable only by the elevated process that loaded
it — rather than left with a permissive default that any local process
(including an unprivileged one) could open and issue IOCTLs against. A
driver with a wide-open device object turns "elevated app has a driver
handle" into "any local user has an MSR read/write primitive," which is a
full local privilege-escalation path independent of any bug in the app
itself.

```powershell
# Inspect device object security descriptor
accesschk.exe -d \Device\YourDriverName
```

### 5. Audit the driver/DLL load path for hijacking risk
For vendored native DLLs and driver files loaded from disk (rather than
registered as a proper signed Windows service), check the load order: is
the binary loaded by an absolute, validated path, or by a bare filename
that's subject to Windows DLL search-order rules (application directory,
system directories, PATH)? A bare-filename load of a vendored DLL from an
elevated process is a classic side-loading target — an attacker who can
place a malicious same-named DLL earlier in the search order gets it
loaded with the process's elevated privileges.

```csharp
// Vulnerable pattern: relies on search-order resolution
[DllImport("VendorLib.dll")]

// Safer: load via an explicit, validated absolute path
// (e.g. LoadLibraryEx with LOAD_LIBRARY_SEARCH_APPLICATION_DIR or a
// full path constructed from a trusted install directory)
```

### 6. Verify driver/binary signing and integrity
Confirm vendored driver files are signed by a trusted publisher (kernel
drivers on modern Windows generally must be, but confirm the app doesn't
disable driver signature enforcement or load an unsigned test-signed
driver in production). For non-driver vendored binaries with no
lockfile/package-manager provenance, note the absence of a checksum or
signature-verification step at load time as a supply-chain gap.

```powershell
sigcheck.exe -a C:\path\to\vendored.dll
```

### 7. Assess process-level blast radius
Given the elevated process also has a live driver handle, walk through
what an attacker who achieves arbitrary code execution *inside that
process* (via any other bug — a parsing flaw, a deserialization issue, a
DLL side-load) can now do that they couldn't in an unprivileged process:
issue arbitrary MSR writes, destabilize the OS, potentially escalate to
kernel code execution depending on the driver's IOCTL surface. Document
this explicitly as the "so what" for any other finding elsewhere in the
same process.

## Key Concepts

| Concept | Why it matters |
|---|---|
| Elevation scope creep | Unrelated unprivileged work inside an elevated process widens the exploitable surface unnecessarily |
| General-purpose vs. narrow driver IOCTL surface | Arbitrary MSR/memory access is a much higher-value target than a narrow, purpose-built API |
| Device object ACL scoping | A permissive driver ACL can turn "app has a handle" into "any local process has the primitive" |
| DLL search-order hijacking | Bare-filename loads of vendored DLLs are side-loadable by anything earlier in the search path |
| Signing/provenance of vendored binaries | Unsigned or unverified driver/DLL updates are a supply-chain risk with kernel-level consequences |
| Blast radius of co-resident privilege | Any other bug in the same elevated process inherits the driver's capability, not just the app's own permissions |

## Tools & Systems

| Tool | Purpose |
|---|---|
| Sysinternals Process Explorer / Autoruns | Inspect loaded drivers, handles, and load-time behavior |
| Sigcheck | Verify signing status of drivers and vendored DLLs |
| AccessChk | Inspect device object / driver ACLs |
| Process Monitor | Trace DLL search-order resolution and file-load attempts at runtime |
| `driverquery` / `lsmod` | Enumerate currently loaded drivers/modules |

## Common Scenarios

- **A hardware-monitoring SDK bundled for one metric drags in a full
  driver.** Confirm whether a narrower, driver-free alternative exists for
  the specific metrics actually needed before accepting the elevated
  driver dependency as necessary.
- **Vendored binaries with no lockfile.** When native dependencies are
  vendored as binary blobs rather than restored via a package manager,
  flag the lack of a checksum/provenance check as a standing gap, even if
  no immediate tampering is found.
- **A single elevated process doing both hardware polling and network
  serving.** If the same elevated process that holds the driver handle
  also runs an HTTP server or handles untrusted network input, cross-
  reference with an HTTP-server-focused review — a bug there has
  kernel-adjacent blast radius here.

## Output Format

For each finding report: the driver/binary involved, file/line of the
loading or IOCTL code, the specific gap (wide-open ACL, search-order load,
missing signature check), the escalation path an attacker would follow,
and remediation. Include an explicit blast-radius statement summarizing
what a code-execution bug elsewhere in the same elevated process could now
achieve.

## Validation Criteria

- [ ] Elevation rationale confirmed necessary for every elevated code path
- [ ] All driver-backed dependencies enumerated, including transitive ones
- [ ] Driver IOCTL surface characterized (narrow vs. general-purpose)
- [ ] Device object ACL/access scoping checked
- [ ] Vendored DLL/driver load paths checked for search-order hijacking
- [ ] Signing/provenance of vendored driver and DLL binaries verified
- [ ] Blast-radius statement written for co-resident privilege in the
      elevated process
- [ ] Findings documented with escalation path and remediation per issue
