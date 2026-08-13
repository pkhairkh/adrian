---
title: "ADR-092: Per-platform policy executor trait `PolicyExecutor` and synthetic Windows CSE (resolves PC-046)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-046
severity: high
unblocked_by: Workshop Decision 7
tags: [adr, policy-engine, cse, policy-executor, trait, synthetic-cse, plugin, cross-platform, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../workshop/decision-07-policy-format.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ../docs/04-group-policy/02-gpo-processing-order.md
  - ./ADR-024-per-platform-policy-executors.md
  - ./ADR-025-transactional-policy-rollback.md
  - ./ADR-089-declarative-policy-gpc-gpt-synthesis.md
last_updated: 2026-08-14
---

# ADR-092: Per-platform policy executor trait `PolicyExecutor` and synthetic Windows CSE (resolves PC-046)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 7](../workshop/decision-07-policy-format.md) §6 and §9, which specify the framework's public `PolicyExecutor` Rust trait, the `inventory`-based registration model, the "no dynamic loading of untrusted native code" security boundary, and the synthetic Windows CSE that consumes `Adrian/policy.json` from the synthesised GPT. This ADR operationalises Decision 7's executor specification against the PC-046 problem surface (note: the catalog triage maps PC-046 to "ADMX schema Windows-specific"; the executor/CSE problem is PC-047, but per the wave-2c task mapping, ADR-092 covers the CSE-for-non-Windows sub-decision — the executor trait that replaces the CSE model on non-Windows platforms — and the synthetic Windows CSE that preserves AD-interop). It promotes ADR-024 (per-platform policy executors) from PARTIAL to FULLY RESOLVED.

## Context

AD's CSE (Client-Side Extension) model is the per-area plugin architecture that `gpsvc.dll` invokes during Group Policy refresh. Per [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md), each CSE is a DLL registered under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<GUID>}` with `DllName`, `Description`, `NoUserPolicy`, `NoMachinePolicy` flags. Each CSE exports `ProcessGroupPolicy` and `ProcessGroupPolicyEx` (prototype in `<userenv.h>` `PFNPROCESSGROUPPOLICYEX`). When `gpsvc.dll` processes a GPO, it iterates the CSE-GUID list in `gPCMachineExtensionNames`/`gPCUserExtensionNames` (format `[{CSE-GUID}{SnapIn-GUID}]...`) and invokes each CSE via `GetProcAddress`. There are 16+ CSEs covering Registry (`{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`, `userenv.dll`), Security (`{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`, `scecli.dll`), Scripts (`{42B5FAAE-6536-11D1-AE59-0000FED75982}`, `gptext.dll`), Folder Redirection (`{426031c0-0b47-4852-b0ca-ac3d37bfcb39}`, `fdeploy.dll`), AppLocker (`{16be69fa-4209-4250-9b8c-6539af50c92b}`, `appidsvc.dll`), Software Install (`{c6dc5466-785a-11d2-84ed-00c04fb1692f}`, `appmgmts.dll`), plus 14 Preferences CSEs all hosted in `gppref.dll`, per the same KB.

The CSE model is Windows-only. Each CSE is a Windows DLL with Windows-specific entry points (`ProcessGroupPolicyEx` takes `UINT`, `DWORD`, `HKEY`, `GROUP_POLICY_OBJECT_TYPE`, `RSOP_MODE`, `CSE_GPT_NAME`, `HKCU`/`HKLM` parameters), Windows-specific APIs (`RegCreateKeyExW`, `LsaQueryInformationPolicy`, `SceSetSecurityPolicyInfo`, `LsaCreateAccount`), and Windows-specific assumptions (registry hive writes, ESE-database updates, COM-object invocations). macOS has no equivalent — MDM uses monolithic `.mobileconfig` payloads (each payload type is a single "CSE-equivalent" applied atomically). Linux SSSD implements only the Security CSE subset (the `[Privilege Rights]` section of `GptTmpl.inf`) via `ad_gpo.c:ad_gpo_evaluate_gpo`. Samba `samba-gpupdate` implements a partial Registry CSE that translates a fixed set of known policy keys to Linux config files. Per [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), the per-CSE invocation order is significant (Security CSE applies before Scripts CSE; Registry CSE applies before Preferences CSE); the framework's executor model must preserve this ordering for AD-interop.

Workshop Decision 7 §9 specifies the framework's answer: a public Rust `PolicyExecutor` trait with `Snapshot`/`DryRun`/`Apply`/`Rollback` methods, `inventory`-based registration, semver-checked loading, and a hard security boundary (no dynamic loading of untrusted `.so`/`.dll`/`.dylib` files). Decision 7 §6 specifies the synthetic Windows CSE that consumes `Adrian/policy.json` and dispatches to the registered Windows executors. This ADR defines the executor trait's contract, the registration model, the synthetic CSE's invocation flow, and the CSE-GUID-to-executor mapping for AD-interop.

## Decision

The framework publishes the `adrian-policy-executor` crate with the `PolicyExecutor` trait. Per-platform executors implement the trait, register via `inventory::submit!{}` at compile time, and are loaded at process start. The framework's policy daemon (`adrian-policy-daemon`) dispatches each canonical-JSON `area` to the registered executor. On Windows, the framework registers a synthetic CSE (`adrian_cse.dll`) that bridges `gpsvc.dll`'s CSE invocation to the framework's daemon.

### Concrete specification

1. **`PolicyExecutor` trait.** The public Rust trait (per Decision 7 §9):
   ```rust
   pub trait PolicyExecutor: Send + Sync {
       fn area(&self) -> PolicyArea;
       fn snapshot(&self, ctx: &ExecutorContext) -> Result<Snapshot, ExecutorError>;
       fn dry_run(&self, ctx: &ExecutorContext, policy: &PolicyDoc)
           -> Result<DryRunReport, ExecutorError>;
       fn apply(&self, ctx: &ExecutorContext, policy: &PolicyDoc, snap: &Snapshot)
           -> Result<ApplyReport, ExecutorError>;
       fn rollback(&self, ctx: &ExecutorContext, snap: &Snapshot)
           -> Result<(), ExecutorError>;
       fn capabilities(&self) -> Capabilities; // { supports_dry_run, supports_rollback, ... }
   }
   ```
   The `ExecutorContext` carries the host's identity (UUID, role, site), the host's facts document (per ADR-026), a handle to the framework's secret service (for `secret_ref` resolution), and a logger. The `Snapshot` is an opaque `Vec<u8>` whose content is executor-defined (the Registry executor snapshots the registry hive; the Files executor snapshots file content hashes; the Security executor snapshots the LSA policy). The `DryRunReport` lists the proposed changes per setting with a `change_kind` enum (`Add`, `Modify`, `Remove`, `NoChange`). The `ApplyReport` lists the applied changes with a `result` enum (`Applied`, `Skipped`, `Failed`) per setting. The `Capabilities` struct reports which operations the executor supports (executors for non-transactional areas like `Scripts` may report `supports_rollback = false`).

2. **Registration via `inventory`.** Executors register at compile time via `inventory::submit!{ PolicyExecutorRegistration { area, factory } }`, where `factory` is a `fn() -> Box<dyn PolicyExecutor>`. The `adrian-policy-daemon` binary links all executor crates statically (the framework does not ship a plugin loader for `.so`/`.dll`/`.dylib` files). At process start, the daemon iterates `inventory::iter::<PolicyExecutorRegistration>()` and constructs one instance per area. The daemon refuses to start if two executors register for the same area (duplicate-registration error at startup).

3. **Semver check.** Each executor crate declares its `adrian-policy-executor` version via `const EXECUTOR_API_VERSION: &str = env!("CARGO_PKG_VERSION")`. The daemon checks each executor's `EXECUTOR_API_VERSION` against its own `adrian-policy-executor` version; if the major versions differ, the daemon refuses to start with an error indicating the incompatible executor crate. This is the framework's semver guarantee: executors compiled against `adrian-policy-executor` 1.x work with daemon 1.x; executors compiled against 2.x require daemon 2.x.

4. **No dynamic loading of untrusted native code.** The framework does not load `.so`/`.dll`/`.dylib` files at runtime. Executors must be compiled into the `adrian-policy-daemon` binary (or a statically-linked sidecar) at build time. This is a deliberate security boundary: a policy executor runs as SYSTEM/root, and accepting operator-supplied native code would create an arbitrary-code-execution channel via policy. The framework's threat model (per PC-123) documents the `PolicyExecutor` trait as a trusted-code boundary: only executors compiled into the framework's signed binary are loaded; operator-supplied native code is rejected. Operators who need arbitrary automation use the framework's separate Ansible collection integration (not a policy executor).

5. **Synthetic Windows CSE.** Per Decision 7 §6, the framework registers a synthetic CSE on Windows via `adrian_cse.dll` (a Rust dynamic library compiled with `cdylib` crate type). The CSE's GUID is allocated at build time and written to the framework's installer MSI; the installer registers the CSE under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<framework-CSE-GUID>}`. The DLL exports `ProcessGroupPolicyEx` with the prototype matching `<userenv.h>`:
   ```c
   typedef DWORD (WINAPI *PFNPROCESSGROUPPOLICYEX)(
       DWORD dwFlags, HKEY hKeyRoot, GROUP_POLICY_OBJECT_TYPE gpoType,
       RSOP_MODE rsopMode, wchar_t *pszGPOName, wchar_t *pszGPOSection,
       DWORD dwPrecedence, DWORD dwHint, GUID *pGPOList,
       BOOL *pbAbort, PFNSTATUSMESSAGECALLBACK pStatusCallback
   );
   ```
   The C ABI is provided by `windows-sys = "0.52"` and `windows = "0.54"` (for `userenv.h` types). When `gpsvc.dll` invokes the synthetic CSE, the CSE: (a) reads `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Adrian\policy.json` from the SMB share; (b) loads `policy.json` via the framework's `adrian-sdk` C ABI (the SDK links the `adrian-policy-core` library); (c) dispatches each `area` in the policy to the registered Windows executor (the daemon runs in-process within `gpsvc.dll`'s CSE invocation — no IPC required); (d) runs `Snapshot → DryRun → Apply` (or `Rollback` on failure); (e) returns `ERROR_SUCCESS` to `gpsvc.dll` on success or an error code on failure (the error code triggers Event 1090 in `Applications and Services Logs\Microsoft\Windows\GroupPolicy\Operational`).

6. **CSE-GUID-to-executor mapping for AD-interop.** The synthetic CSE's GUID is added to the synthesised GPC's `gPCMachineExtensionNames`/`gPCUserExtensionNames` list (per ADR-089 §2) for all framework-authored policies, in addition to the native CSE GUIDs that the GPT-synthesis emits for legacy areas (`{35378EAC-...}` for Registry, `{827D319E-...}` for Security, etc.). The native CSEs process the synthesised GPT files (`Registry.pol`, `GptTmpl.inf`); the synthetic CSE processes `Adrian/policy.json`. The two coexist without conflict because they target disjoint registry subtrees (`HKLM\Software\Policies\Adrian\` vs `HKLM\Software\Policies\Microsoft\`) and disjoint LSA namespaces (the framework's `Security` area targets `PermitLogonLocally` etc. via the same `LsaQueryInformationPolicy` API as `scecli.dll`, but the framework's settings are applied via the synthetic CSE while legacy `scecli.dll` applies its `GptTmpl.inf`-derived settings — the framework's distribution service avoids emitting `GptTmpl.inf` for `Security` area settings that are also in `Adrian/policy.json`, preventing double-apply).

7. **macOS executor invocation.** On macOS, the framework's `adrian-policy-daemon` runs as a launchd daemon (`/Library/LaunchDaemons/dev.adrian.policy-daemon.plist`). The daemon receives policy updates via the WebSocket push (per ADR-028) or HTTPS pull fallback, dispatches each `area` to the registered macOS executor, and applies the policy via the executor's `Apply` method. The macOS executors call the MDM-payload-installation APIs (`mdmclient` via the framework's Swift bridge) for MDM-payload-based areas (per ADR-091 §3) and call platform-native APIs (`mkdir`, `chmod`, `diskutil`, `dscl`) for file/system areas.

8. **Linux executor invocation.** On Linux, the framework's `adrian-policy-daemon` runs as a systemd service (`/etc/systemd/system/adrian-policy-daemon.service`). The daemon receives policy updates via the WebSocket push (per ADR-028) or HTTPS pull fallback, dispatches each `area` to the registered Linux executor, and applies the policy via the executor's `Apply` method. The Linux executors call platform-native APIs (`nix` crate for POSIX, `systemd` D-Bus for unit management, `cups` API for printer management) per ADR-091 §4.

9. **Executor ordering.** The daemon applies executors in a fixed order matching AD's CSE invocation order (per [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md)): `Security` → `AuditPolicy` → `AccountPolicy` → `Registry` → `Preferences.*` → `Scripts` (Scripts is applied last so script-based settings see the final policy state). Within `Preferences.*`, the executor applies sub-areas in the order `LocalUsersGroups` → `Files` → `Folders` → `DriveMaps` → `Services` → `ScheduledTasks` → `Shortcuts` → `Environment` → `IniFiles` → `Printers` → `Registry` → `InternetSettings` → `PowerOptions` → `NetworkOptions` (matching `gppref.dll`'s per-area CSE invocation order).

## Rationale

Three alternatives were considered.

**Alternative A: Preserve CSE model; ship per-platform CSE-emulators.** Implement a `gpsvc.dll`-equivalent on macOS and Linux that emulates the CSE dispatch loop, with per-platform CSE-emulator libraries for each area. Rejected because (a) the CSE model's `ProcessGroupPolicyEx` ABI is Windows-specific (HKEY, registry hives, `GROUP_POLICY_OBJECT_TYPE` enum) — forcing this ABI onto macOS and Linux produces a leaky abstraction; (b) per-platform CSE-emulators for 16+ areas × 3 platforms is 48+ separate libraries, each reimplementing the same dispatch loop; (c) the CSE model has no transactional apply (per PC-048, ADR-025) — preserving it preserves the no-rollback limitation; (d) the framework's `PolicyExecutor` trait with `Snapshot`/`DryRun`/`Apply`/`Rollback` is strictly more capable than the CSE model's `ProcessGroupPolicyEx`. Decision 7 §Rationale rejects this candidate (Candidate A) explicitly.

**Alternative B: Per-platform native executors, no shared trait.** Each platform ships its own executor framework with no shared trait; the macOS daemon dispatches to Objective-C executors, the Linux daemon dispatches to C executors, the Windows CSE dispatches to Rust executors. Rejected because (a) the framework's Rust core (per Decision 11) is the natural language for all three platforms — abandoning Rust on macOS/Linux would require a separate language ecosystem per platform; (b) the canonical JSON's typed value model is defined in Rust (`adrian-policy-core`); per-platform executors that don't link `adrian-policy-core` would need a separate JSON-binding layer; (c) the framework's audit log (per ADR-060) needs a uniform `ApplyReport` schema across platforms — per-platform executors with no shared trait produce per-platform report schemas. Decision 7 §Implementation impact specifies the Rust crate graph for all executors.

**Alternative C: Dynamic loading of operator-supplied executors.** Allow operators to ship `.so`/`.dll`/`.dylib` files that the daemon loads at runtime via `libloading`. Rejected because (a) a policy executor runs as SYSTEM/root, and accepting operator-supplied native code creates an arbitrary-code-execution channel via policy — a `PolicyExecutor` that runs `system("rm -rf /")` in its `Apply` method would be indistinguishable from a legitimate executor at load time; (b) the framework's threat model (per PC-123) requires that all privileged code paths be reproducible from a signed build — dynamic loading breaks the reproducibility guarantee; (c) operators who need arbitrary automation should use the framework's separate Ansible collection (per Decision 7 §9), not a policy executor. The hard boundary is a security-critical control.

The chosen model — public `PolicyExecutor` Rust trait, `inventory`-based registration, semver check, no dynamic loading, synthetic Windows CSE for AD-interop — gives the framework: (a) a uniform executor contract across platforms (the same trait on Windows/macOS/Linux); (b) transactional apply (the `Snapshot`/`Rollback` methods, per ADR-025); (c) a security boundary (only executors compiled into the framework's signed binary are loaded); (d) AD-interop (the synthetic CSE bridges `gpsvc.dll`'s invocation to the framework's daemon).

## Consequences

**Positive**. The framework's executor model is uniform across platforms — the same trait, the same `ApplyReport` schema, the same audit-log format. Transactional apply (per ADR-025) is a first-class capability. The synthetic Windows CSE provides AD-interop without forcing the framework to preserve the CSE model on macOS/Linux. The security boundary (no dynamic loading) eliminates the arbitrary-code-execution-via-policy attack vector.

**Negative**. Third-party LOB apps cannot ship framework-native executors without recompiling the framework's `adrian-policy-daemon` binary (the framework's release cadence becomes a bottleneck for vendor-executor delivery). The synthetic Windows CSE is the highest-risk implementation item (per Decision 7 §Implementation impact): CSE registration requires a stable GUID, a DLL exporting `ProcessGroupPolicyEx` with the correct prototype, and per-GPO invocation order that matches `gpsvc.dll`'s expectations. The CSE must coexist with native CSEs without duplicate registry writes or version-counter desync.

**Neutral**. The framework's executor catalogue is fixed at build time — operators cannot add executors at runtime. The framework's release notes document the executor catalogue per release. Operators who need a custom executor contribute it upstream (per the framework's contribution guide).

**Implementation cost**. ~5 person-weeks for v1 (per Decision 7 §Implementation impact): public `PolicyExecutor` trait + `inventory` registration + semver check (1 pw), synthetic Windows CSE with `ProcessGroupPolicyEx` ABI (3 pw, highest-risk), macOS and Linux daemon dispatch (1 pw). Ongoing maintenance: ~0.5 person-weeks per year for executor API evolution (semver-minor additions).

**Operational impact**. Operators do not interact with executors directly — they author policy in canonical JSON and the daemon dispatches to the appropriate executor. The framework's audit log records the executor's `ApplyReport` per policy application. The `adrian-policy status --host <name> --area <area>` CLI shows the executor's last-apply result.

## Alternatives Considered

### Alternative A: Preserve CSE model; per-platform CSE-emulators

Implement a `gpsvc.dll`-equivalent on macOS and Linux with per-platform CSE-emulator libraries for each of the 16+ areas.

Rejected as detailed in §Rationale and Decision 7 §Rationale Candidate A: the CSE ABI is Windows-specific; 48+ separate libraries is unsustainable; the CSE model has no transactional apply; the `PolicyExecutor` trait is strictly more capable.

### Alternative B: Per-platform native executors, no shared trait

Each platform ships its own executor framework (Objective-C on macOS, C on Linux, Rust on Windows) with no shared trait.

Rejected as detailed in §Rationale: the framework's Rust core is the natural language for all three platforms; the canonical JSON's typed value model is Rust-defined; the audit log needs a uniform `ApplyReport` schema.

### Alternative C: Dynamic loading of operator-supplied executors

Allow operators to ship `.so`/`.dll`/`.dylib` files that the daemon loads at runtime via `libloading`.

Rejected as detailed in §Rationale: a policy executor runs as SYSTEM/root; accepting operator-supplied native code creates an arbitrary-code-execution channel via policy; the framework's threat model requires reproducible-from-signed-build privileged code paths; operators who need arbitrary automation use the framework's Ansible collection.

## Open Questions

- **Executor-side concurrency.** Should the daemon apply multiple areas concurrently (e.g., `Registry` and `Files` in parallel) or strictly sequentially? Current decision: sequentially in the fixed order (per §9), because some executors have implicit dependencies (`Scripts` must run last; `Preferences.Files` may need `Preferences.Folders` to create the target directory first). Revisit if performance profiling shows sequential apply is a bottleneck on large policies.
- **Executor-side retry.** Should the daemon retry a failed executor apply (e.g., `Files` executor fails because the target SMB share is temporarily unavailable)? Current decision: no automatic retry; the executor's `ApplyReport` records the failure and the daemon re-applies on the next policy refresh (default 90 minutes). Revisit if customers report transient-failure issues.
- **Executor catalog publication.** Should the framework publish the executor catalog (which areas are supported on which platforms) at install time so operators can audit coverage before authoring policy? Current decision: yes, via `adrian-policy catalog --platform <platform>` CLI; the catalog is generated at build time from the `inventory` registrations.

## Cross-capability impact

- **Policy Engine (PC-048 rollback)**: ADR-025 (transactional policy rollback) depends on the `PolicyExecutor::snapshot`/`rollback` methods defined here; ADR-025's implementation can proceed against the locked trait contract.
- **Policy Engine (PC-046 ADMX schema)**: ADMX-driven settings invoke the Registry executor on Windows; the `admx2adrian` compiler (per ADR-090) emits canonical JSON that the Registry executor consumes.
- **Policy Engine (PC-045 Preferences)**: ADR-091's Preferences executors implement the `PolicyExecutor` trait for each `Preferences.*` sub-area.
- **Client SDK (Decision 11)**: The `adrian-policy-daemon` is a Client SDK component; the SDK's C ABI exposes the daemon's API to the synthetic Windows CSE, the macOS launchd daemon, and the Linux systemd service.
- **Security (PC-123 threat model)**: The "no dynamic loading of untrusted native code" rule is a security-critical control documented in the threat model.
- **Operations (PC-115 unified CLI)**: The `adrian-policy status` and `adrian-policy catalog` CLI subcommands query the daemon's executor state.

## References

- [PC-046](../catalog/04-policy-engine.md) — problem statement in the catalog (this ADR also covers PC-047 per the wave-2c mapping)
- [Workshop Decision 7](../workshop/decision-07-policy-format.md) §6 and §9 — synthetic Windows CSE + `PolicyExecutor` trait specification
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — CSE registration, `ProcessGroupPolicyEx` prototype, per-area CSE GUIDs
- [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md) — CSE invocation order, `gpsvc.dll` dispatch loop
- [ADR-024](./ADR-024-per-platform-policy-executors.md) — per-platform policy executors (this ADR resolves ADR-024's deferred sub-decision; ADR-024 promoted from PARTIAL to FULLY RESOLVED)
- [ADR-025](./ADR-025-transactional-policy-rollback.md) — transactional policy rollback (depends on `PolicyExecutor::snapshot`/`rollback`)
- [ADR-089](./ADR-089-declarative-policy-gpc-gpt-synthesis.md) — GPC/GPT synthesis (the synthetic CSE consumes `Adrian/policy.json` from the synthesised GPT)
- [`inventory` crate](https://docs.rs/inventory) — Rust compile-time plugin registration
- [`windows` crate](https://docs.rs/windows) — Rust Windows API bindings (used by the synthetic CSE)
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol (CSE model reference)
