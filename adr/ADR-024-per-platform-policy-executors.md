---
title: "ADR-024: Per-platform policy executors (CSE / MDM / SSSD-conf)"
status: Accepted (partial)
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-047
severity: high
tags: [adr, policy-engine, cse, cross-platform, executor-framework]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
  - ../docs/09-linux-equivalents/03-sssd-gpo-access.md
last_updated: 2026-08-13
---

# ADR-024: Per-platform policy executors (CSE / MDM / SSSD-conf)

## Status

Accepted (partial) — 2026-08-13. The confident sub-decision (ship per-platform executors that map to Windows CSEs, macOS MDM payload types, and Linux SSSD-conf-equivalent areas) is locked. The deferred sub-decision — the unified executor plugin framework design (generic plugin contract vs. per-platform native code paths) — is gated by Tier-3 ORQ-090/091 and resolved in a future ADR.

## Context

AD Group Policy applies policy via Client-Side Extensions: native Windows DLLs registered under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<GUID>}` exporting `ProcessGroupPolicy` and `ProcessGroupPolicyEx` (prototype `PFNPROCESSGROUPPOLICYEX` in `<userenv.h>`). When `gpsvc.dll` processes a GPO it iterates the CSE-GUID list in `gPCMachineExtensionNames` / `gPCUserExtensionNames` (format `[{CSE-GUID}{SnapIn-GUID}]...`) and invokes each CSE via `GetProcAddress`, per [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md). Sixteen-plus CSEs cover Registry (`{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` in `userenv.dll`), Security (`{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` in `scecli.dll`), Scripts, Folder Redirection, AppLocker, Software Install, and 14 Preferences CSEs hosted in `gppref.dll`.

The CSE model is Windows-only. macOS and Linux have no equivalent abstraction: SSSD implements only the Security CSE subset (`[Privilege Rights]` from `GptTmpl.inf`) via `ad_gpo.c:ad_gpo_evaluate_gpo`; Samba's `samba-gpupdate` implements a partial Registry CSE that hard-codes a fixed set of key mappings; macOS MDM uses monolithic `.mobileconfig` payloads where each payload type is a single CSE-equivalent applied atomically. The cross-platform coverage matrix in [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) shows the gap: the same GPO applied to Windows/macOS/Linux produces wildly different effective configuration because each OS consumes only its CSE-equivalent subset.

For the framework, the CSE model must be honored on Windows for AD interop (existing `gpsvc.dll` invocation) while platform-native equivalents must be defined on macOS (MDM payload types) and Linux (PAM/NSS/systemd/CUPS/SSSD-conf). The constraint is bidirectional: a Windows host joined to a framework domain must continue to consume GPOs via `gpsvc.dll`, and a macOS or Linux host joined to the same domain must consume equivalent policy through its native mechanism, per [PC-047](../catalog/04-policy-engine.md).

The framework cannot wait for ORQ-090/091 (unified executor framework design — generic plugin contract vs. per-platform native code paths) because shipping policy enforcement on all three platforms is a blocker for cross-platform parity. The framework therefore commits to shipping per-platform executors now, with a stable internal contract that can later be refactored into the unified plugin framework once ORQ-090/091 resolves.

## Decision

The framework shall ship three per-platform policy executors that map to the same logical policy areas:

1. **Windows** — a synthetic CSE (single DLL registered under `HKLM\...\CSEs\{<framework-CSE-GUID>}`) that exports `ProcessGroupPolicyEx` and internally delegates to the framework's executor. The synthetic CSE consumes the framework's JSON policy format (per ADR-029) and writes via native Windows APIs (`RegSetValueExW`, `LsaCreateAccount`, `SceSetSecurityPolicyInfo`). Existing AD-issued GPOs continue to be honored via the native CSEs registered by `gPCMachineExtensionNames`; the framework CSE runs alongside them.
2. **macOS** — a per-area MDM payload emitter that translates framework policy areas into MDM payload types (e.g., `com.apple.security.firewall`, `com.apple.passwordpolicy`, `com.apple.applicationaccess`). The framework enrolls macOS hosts via MDM (per ADR-052) and pushes payloads through the MDM channel.
3. **Linux** — a per-area executor that writes to native Linux config surfaces: PAM (`/etc/pam.d/`), NSS (`/etc/nsswitch.conf`), systemd (`/etc/systemd/system/`), CUPS (`/etc/cups/`), SSSD-conf (`/etc/sssd/sssd.conf`), and sudoers (`/etc/sudoers.d/`). The executor calls `authselect` (per ADR-050) for PAM profile changes.

Each executor implements the same logical operations: `Snapshot()`, `Apply()`, `Rollback()`, `DryRun()` (per ADR-025). The framework defines a stable per-area executor contract (an interface in the framework's Client SDK) that maps each policy area to a single executor implementation per platform. The deferred decision is whether this contract becomes a public plugin framework (third parties can register custom executors) or remains an internal abstraction — that is ORQ-090/091.

**Concrete specification**:

- The framework defines a `PolicyArea` enum with values: `Registry`, `Security`, `Scripts`, `FolderRedirection`, `AppLocker`, `SoftwareInstall`, `Preferences` (sub-areas: `Files`, `Printers`, `Drives`, `Shortcuts`, `Environment`, `Folders`, `IniFiles`, `Services`, `NetworkOptions`, `PowerOptions`, `RegistrySettings`, `ScheduledTasks`, `InternetSettings`), `AuditPolicy`, `RestrictedGroups`, `AccountPolicy`, `Firewall`, `PasswordPolicy`, `TrustManager`, `Custom`.
- Each platform ships one executor per `PolicyArea` value. The Windows executor for `Registry` consumes JSON policy and writes to `HKLM\Software\Policies\` / `HKCU\Software\Policies\`. The macOS executor for `Registry` translates to a `com.apple.managedpreferences` payload. The Linux executor for `Registry` writes to `/etc/adrian/policy.d/<area>.conf` (a key-value file mapped to the registry path).
- On Windows, the synthetic CSE GUID is allocated (`{<new-GUID>}`) and registered via the framework's installer. The CSE is listed in `gPCMachineExtensionNames` for framework-authored GPOs; legacy AD-authored GPOs continue to use native CSEs.
- The macOS MDM payload emitter produces `.mobileconfig` payloads compliant with the Apple Configuration Profile schema (per ADR-052). Each payload carries `PayloadType`, `PayloadIdentifier`, `PayloadUUID`, and the area-specific keys.
- The Linux executor calls `authselect` for PAM-affecting changes (`Security`, `AccountPolicy`) and writes config files atomically via `rename(2)` for other areas.
- Every executor exposes `Snapshot()` (capture pre-apply state), `Apply()` (write changes), `Rollback()` (restore from snapshot), and `DryRun()` (compute effective policy without applying). These four operations are the contract shared with ADR-025.
- Executor invocation order is the same across platforms: `Snapshot()` → `DryRun()` → `Apply()` (or `Rollback()` on failure).

## Rationale

Three alternatives were considered.

**Alternative 1: Single "framework CSE" on every platform.** A single executor implementation, written once and ported to each OS. Rejected because the native surfaces differ fundamentally: Windows writes to the registry, macOS to plist, Linux to text files; pretending they share an executor forces a lowest-common-denominator abstraction that loses native fidelity. The framework would end up wrapping platform-specific writes anyway, just with an indirection cost.

**Alternative 2: Preserve Windows CSEs as the canonical model and port all 16+ CSEs to macOS/Linux.** Rejected because the CSE contract (`ProcessGroupPolicyEx` signature, registry-driven config, `gPCMachineExtensionNames` GUID encoding) is Windows-implementation-shaped. Porting it to macOS MDM (which has no concept of CSE GUIDs) and Linux (which has no `gpsvc.dll` invocation) would require emulating the Windows host environment — exactly the Winbind-style "emulate AD on Linux" trap that SSSD was designed to escape.

**Alternative 3: Defer the entire decision until ORQ-090/091 resolves.** Rejected because shipping policy enforcement on macOS/Linux is a blocker for cross-platform parity (PC-047 is high-severity, blocking PC-053 SSSD coverage expansion). The framework cannot wait for a research spike that may take months. The current decision ships a working per-platform executor set now, with a stable internal contract that can later be opened as a public plugin framework without breaking the executor implementations.

The decision aligns with industry practice: Jamf Pro ships per-area macOS MDM payload generators; Chef/Puppet/Salt ship per-platform resources (file, package, service, user) with platform-specific implementations behind a unified interface; FreeIPA ships per-platform SSSD-conf-equivalent executors. The framework's per-platform executor model is the same shape.

Cost: three executor implementations per area per platform. For ~20 areas × 3 platforms = 60 executor implementations, mostly thin wrappers around native APIs. Effort: ~12 person-weeks for the initial set, with the synthetic Windows CSE being the highest-risk item (CSE registration and `gpsvc.dll` integration testing).

## Consequences

**Positive**. Cross-platform policy enforcement becomes real: the same logical policy area (e.g., `AuditPolicy`) produces platform-native configuration on all three OSes. The framework can ship a working Policy Engine on macOS and Linux without waiting for ORQ-090/091. The stable internal contract (`Snapshot` / `Apply` / `Rollback` / `DryRun`) is the foundation for ADR-025 (transactional apply with rollback) and ADR-029 (JSON canonical policy format).

**Negative**. Three code paths per area means three places to fix bugs. The synthetic Windows CSE is a non-trivial integration surface with `gpsvc.dll` — CSE registration, `ProcessGroupPolicyEx` prototype conformance, and per-GPO invocation order must match Windows expectations exactly. macOS MDM payload emission depends on MDM enrollment (ADR-052), so policy enforcement on macOS is gated on MDM infrastructure. Linux executors must coordinate with `authselect` and systemd — version skew across distros (RHEL 8 vs. Ubuntu 22.04 vs. Debian 12) will surface as bug reports.

**Neutral**. The deferred decision (unified plugin framework vs. internal abstraction) does not change the executor implementations — it only changes whether third parties can register custom executors. The current internal contract can be opened as a public API later without rewrites.

**Implementation cost**. ~12 person-weeks for the initial executor set across all three platforms. The Windows synthetic CSE is the highest-risk item (~4 person-weeks of integration testing against `gpsvc.dll`).

**Operational impact**. Operators author policy once (in the JSON canonical format per ADR-029) and the framework compiles to platform-native forms. Debugging per-host policy requires platform-specific tooling (`gpresult /h` on Windows, `profiles show` on macOS, `adrian-policy show` on Linux) — the framework provides a unified `adrian-policy status --host <name>` command that calls the platform-specific tooling under the hood.

## Alternatives Considered

### Alternative A: Single cross-platform executor

A single executor implementation, written in the framework's Client SDK language (per ORQ-169/170), ported to each OS via a runtime layer. The executor would receive the JSON policy and write to an abstracted "config store" that the framework implements per platform (registry on Windows, plist on macOS, files on Linux).

Rejected because the abstraction leaks: Windows registry has typed values (REG_DWORD vs. REG_SZ vs. REG_MULTI_SZ) with no macOS plist equivalent (plist has string/integer/data/array but the type semantics differ); Linux text files have no native typing at all. Forcing a single executor through a leaky abstraction produces bugs that surface only on one platform — the worst possible failure mode for cross-platform policy.

### Alternative B: Port all 16+ CSEs to all platforms

Implement `ProcessGroupPolicyEx` and the CSE registry layout on macOS and Linux, emulating the Windows host environment. This is the Winbind/Samba approach.

Rejected because it couples macOS and Linux to Windows implementation details (CSE GUIDs, registry-driven CSE registration, `gPCMachineExtensionNames` parsing) that have no native meaning on those platforms. The maintenance cost of emulating Windows CSEs on macOS (which uses MDM payloads) and Linux (which uses text files and PAM) exceeds the value of conceptual uniformity. SSSD's design explicitly rejected this approach for the same reason.

### Alternative C: Defer until ORQ-090/091 resolves

Wait for the Tier-3 ORQ-090/091 research spike on the unified executor framework before shipping any per-platform executor.

Rejected because PC-047 is high-severity and blocks PC-053 (SSSD coverage expansion) and the broader cross-platform parity story. The framework cannot ship without policy enforcement on macOS and Linux; deferring the decision defers the framework. The current decision ships a working executor set now with an internal contract that can be refactored into a public plugin framework later without breaking the implementations.

## Open Questions

- **Deferred sub-decision (PARTIAL)**: whether the per-area executor contract becomes a public plugin framework (third parties register custom executors via a documented API) or remains an internal abstraction. Gated by Tier-3 ORQ-090 (unified executor framework design) and ORQ-091 (plugin SDK contract). The current internal contract is stable enough that opening it as a public API later does not require rewriting existing executors.
- Should the framework ship a default `Custom` executor that runs arbitrary scripts (Ansible-equivalent), or require all executors to be type-safe per-area implementations? Security implications of script execution must be evaluated.
- How does the framework handle policy areas that have no native macOS equivalent (e.g., Windows Defender signature toggles)? The current design documents the gap; should the framework produce a warning, or silently skip?

## Cross-capability impact

- **Client SDK (PC-085..PC-093)**: The per-platform executors live in the Client SDK and are invoked by the SDK's policy daemon. ORQ-169/170 (Client SDK architecture) gates the implementation language and base.
- **Cross-Platform Parity (PC-094..PC-105)**: PC-053 (SSSD GPO access control) is directly enabled — the Linux `Security` executor expands SSSD's 1/50th-of-Windows coverage. PC-094 (Windows-only Preferences XML) is addressed by the macOS/Linux `Preferences` executors.
- **Operations (PC-106..PC-115)**: The unified `adrian-policy status` command (per ADR-063) calls the per-platform executor's `DryRun()` operation.
- **Migration (PC-124..PC-130)**: PC-046 (ADMX-to-unified-schema translation) produces policy documents consumed by the executors; the executor contract is the migration target.

## References

- [PC-047](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — CSE GUID table, `ProcessGroupPolicy` prototype, `gPCMachineExtensionNames` encoding
- [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Cross-platform coverage per CSE-equivalent
- [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md) — SSSD's GPO coverage and gaps
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol
- [Apple MDM Protocol Reference](https://developer.apple.com/business/documentation/MDM-Protocol-Reference.pdf) — MDM payload schema
