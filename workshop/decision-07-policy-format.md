---
title: "Workshop Decision 07 — Policy format: hybrid declarative JSON + ADMX compiler + PReg adapter (resolves ORQ-090/091)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Policy Engine
orqs_resolved: [ORQ-090, ORQ-091]
gates: [PC-046, PC-047, PC-095]
tags: [workshop, decision, policy-engine, declarative, admx, preg, cse, cel, rego, rust]
related:
  - ./CONTEXT.md
  - ../adr/TRIAGE.md
  - ../adr/ADR-024-per-platform-policy-executors.md
  - ../adr/ADR-029-json-canonical-policy-preg-adapter.md
  - ../adr/ADR-025-transactional-policy-rollback.md
  - ../adr/ADR-026-declarative-host-facts-wmi-adapter.md
  - ../adr/ADR-031-git-backed-policy-history.md
  - ../catalog/04-policy-engine.md
last_updated: 2026-08-14
---

# Workshop Decision 07 — Policy format: hybrid declarative JSON + ADMX compiler + PReg adapter

## Status

Accepted — 2026-08-14. Tier-1 (architectural) decision made at the Day 2 morning session of the Tier-1 ORQ Resolution Workshop. Resolves ORQ-090 (generic policy executor framework with per-platform plugins) and ORQ-091 (declarative policy that compiles to CSE invocations on Windows and shell scripts on Linux). Promotes ADR-024 from PARTIAL to FULLY RESOLVED and supersedes the open-question section of ADR-029 by fixing the executor plugin contract.

## ORQs resolved

- **ORQ-090** — "Generic 'policy executor' framework with per-platform plugins?" → **Yes, with a stable Rust trait object contract.** The plugin framework is a public Rust trait (`PolicyExecutor`) distributed as `adrian-policy-executor` crate; third-party executors register via `inventory`-style submission and are loaded at process start. No dynamic loading of untrusted native code; all plugins must compile against the framework SDK.
- **ORQ-091** — "Declarative policy that compiles to CSE invocations on Windows and shell scripts on Linux?" → **Yes, with a declarative canonical JSON policy compiled to platform-native forms.** Windows: compiled to PReg `Registry.pol` for the legacy Registry CSE plus a synthetic-CSE JSON blob for non-Registry areas (per ADR-024). macOS: compiled to a `com.apple.managedpreferences` payload and per-area MDM payload types. Linux: compiled to `authselect` profiles, systemd drop-ins, `/etc/sssd/sssd.conf` fragments, auditd rules, and small idempotent shell-equivalent scripts generated from a pure-Rust executor (no arbitrary operator shell scripts).

## Decision

The framework adopts a **hybrid policy format**: a single declarative canonical JSON document per policy, with an ADMX-to-JSON compiler for AD interop, a PReg adapter for `Registry.pol` legacy output, a synthetic Windows CSE that consumes the same canonical JSON for non-Registry areas, and a public Rust `PolicyExecutor` plugin trait.

### Concrete specification

1. **Canonical policy document.** Each policy is a JSON document with the top-level structure already specified in [ADR-029](../adr/ADR-029-json-canonical-policy-preg-adapter.md), extended here with explicit targeting and selector-language fields. The schema is versioned `adrian/v1` and published at `https://adrian.dev/schemas/policy/v1.json`. The `spec.target` block is redefined to use a single `selector` field whose value is a CEL (Common Expression Language, Google) expression evaluated against a host-facts document (per [ADR-026](../adr/ADR-026-declarative-host-facts-wmi-adapter.md)). CEL is chosen over Rego because CEL is expression-oriented (returns a boolean for the target decision), embeddable in ~600 lines of Rust, and has a strict type system that catches authoring errors at validate time. Rego remains available as an opt-in selector engine for customers with existing OPA-based policy stacks; the framework's `adrian-policy validate` CLI dispatches on a `selector.lang` field (`cel` default, `rego` opt-in).

2. **Canonical value model.** Each setting in `spec.areas[].settings` is `{ "type": <TypeEnum>, "value": <typed-value> }` where `TypeEnum` is one of `string | integer | boolean | string_list | bytes | nested | secret_ref`. The `secret_ref` type is new: it carries a URI (`adrian-secret://<vault>/<key>?version=<n>`) resolved at apply-time by the Client SDK against the framework's secret service (per Decision 11). This eliminates the GPP "cPassword" XOR-encrypted-password antipattern and the SSSD limitation of never being able to deliver secrets via policy.

3. **ADMX-to-JSON compiler.** The framework ships `admx2adrian`, a Rust binary that ingests an ADMX file pair (`.admx` + language-specific `.adml`) and emits a canonical JSON **policy template** plus a JSON Schema fragment. The compiler parses ADMX XML via `quick-xml`, walks the `policyDefinition` elements, and translates each `policy` element into a `PolicyArea`-typed setting skeleton. ADMX `elements` (`boolean`, `decimal`, `text`, `enum`, `multitext`, `list`) map to the framework's `TypeEnum` (`boolean`, `integer`, `string`, `string`, `string_list`). ADMX `registryKey`/`valueName` are preserved as an `admx.registry` annotation so the PReg adapter can emit the correct Windows registry path. ADMX `supportedOn` (a `windows:versions` reference) is preserved as a `target.facts.os.windows_version` predicate. ADMX `presentation` (the form layout) is preserved as a `presentation` annotation consumed by the framework's authoring UI. The compiler is **lossy on round-trip** (ADMX's `boolean` inverted-value semantics and `enableKey` deletion-on-disable are flattened to the framework's typed model); the round-trip is documented as one-way (ADMX → JSON only).

4. **PReg adapter (output side, Windows-only).** Implemented per [ADR-029](../adr/ADR-029-json-canonical-policy-preg-adapter.md). The adapter reads canonical JSON `area == "Registry"` settings, produces `Registry.pol` with the correct PReg record encoding (UTF-16LE, `[key;value;type;size;data;]`), and writes it to the framework's SMB-served SYSVOL-equivalent share. For non-`Registry` areas, the adapter emits `GptTmpl.inf` (Security), `Scripts.ini` (Scripts), `Audit.csv` (AuditPolicy), and the GPP XML files (Preferences) — reusing the canonical JSON's typed values to fill the AD-specific formats. The adapter is implemented in the `adrian-policy-distribution` service (a Windows-service-compatible Rust binary) and runs only on the framework's policy distribution hosts; it is not shipped to clients.

5. **PReg reader (input side, migration).** Implemented per [ADR-029](../adr/ADR-029-json-canonical-policy-preg-adapter.md). The `preg2adrian` migration tool reads existing `Registry.pol` from an AD GPO backup and emits canonical JSON. This is the migration path for customers with hand-authored GPO Preferences and registry policy.

6. **Synthetic Windows CSE.** Per [ADR-024](../adr/ADR-024-per-platform-policy-executors.md), the framework registers a synthetic CSE (`{<framework-CSE-GUID>}`) on Windows. The synthetic CSE consumes a framework-JSON blob written to `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Adrian\policy.json` (alongside the legacy `Registry.pol`). The synthetic CSE loads `policy.json` via the framework's `adrian-sdk` C ABI, dispatches each `area` to the registered Windows executor, and runs `Snapshot → DryRun → Apply` (or `Rollback` on failure). Legacy AD-authored GPOs continue to flow through native CSEs; framework-authored GPOs flow through the synthetic CSE plus PReg for the Registry area. The two coexist without conflict because they target disjoint registry subtrees (`HKLM\Software\Policies\Adrian\` vs `HKLM\Software\Policies\Microsoft\`).

7. **macOS compilation target.** The macOS executor (per ADR-024) compiles canonical JSON to a set of MDM payloads emitted via the MDM channel (per ADR-052 DDM-first). `area == "Registry"` → `com.apple.managedpreferences` payload. `area == "Security"` → `com.apple.security.firewall` + `com.apple.applicationaccess`. `area == "AccountPolicy"` → `com.apple.passwordpolicy`. `area == "AuditPolicy"` → `com.apple.systempolicy.logging` (where supported). `area == "Preferences.Files"` → `com.apple.configuration.files`. Settings that have no macOS MDM payload equivalent are dropped with a `WARN` log and a per-policy coverage report accessible via `adrian-policy coverage --host <name> --area <area>`.

8. **Linux compilation target.** The Linux executor (per ADR-024) compiles canonical JSON to platform-native config fragments. `area == "Security"` → `authselect` profile (per [ADR-050](../adr/ADR-050-authselect-standard-pam.md)) plus `/etc/security/limits.conf.d/<policy>.conf`. `area == "AuditPolicy"` → `/etc/audit/rules.d/<policy>.rules`. `area == "AccountPolicy"` → `/etc/login.defs.d/<policy>.conf`. `area == "Firewall"` → `firewalld` direct rules or `nftables` drop-ins (distro-detected). `area == "Preferences.Files"` → atomic `rename(2)` writes via a pure-Rust executor (no shell scripts). Where a setting has no native Linux representation (e.g., Windows Defender signature toggles), the executor drops the setting with a `WARN` log.

9. **Public `PolicyExecutor` plugin trait.** The framework publishes the `adrian-policy-executor` crate with the following Rust trait:
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
   Third-party executors implement this trait, register via `inventory::submit!{ PolicyExecutorRegistration { area, factory } }`, and are discovered at process start. The framework refuses to load executors compiled against a different `adrian-policy-executor` major version (semver check). **No dynamic loading of untrusted `.so`/`.dll`/`.dylib` files**: executors must be compiled into the framework's policy daemon binary or into a statically-linked sidecar. This is a deliberate security boundary: arbitrary operator-supplied shell scripts (the Ansible-equivalent "Custom" executor) are NOT supported as a policy mechanism; operators who need that capability should use the framework's separate Ansible-collection integration.

10. **Selector language: CEL by default, Rego opt-in.** The `spec.target.selector` field is a CEL expression evaluated against a host-facts document. The facts document is a JSON object with the schema defined in [ADR-026](../adr/ADR-026-declarative-host-facts-wmi-adapter.md): `os.name`, `os.version`, `os.arch`, `host.role`, `host.site`, `host.groups[]`, `host.facts{}`. The framework's `adrian-policy evaluate` CLI evaluates a selector against a host's facts and returns `true`/`false` plus a per-clause evaluation trace (useful for debugging why a policy did or did not apply to a host). Rego is supported via the `regorus` crate (a pure-Rust OPA-compatible Rego engine) when `selector.lang == "rego"`; the host-facts document is passed as Rego's `input` document.

11. **Policy distribution.** The framework's policy distribution service (per [ADR-028](../adr/ADR-028-push-based-policy-websocket.md)) pushes policy updates to enrolled clients via a WebSocket-based push channel, with HTTPS pull fallback for clients behind restrictive proxies. Policy documents are stored in the framework's Git-backed policy repository (per [ADR-031](../adr/ADR-031-git-backed-policy-history.md)) and compiled to platform-native forms on-demand by the distribution service.

12. **Slow-link handling.** Per [ADR-027](../adr/ADR-027-http-head-slow-link-detection.md), the framework uses HTTP HEAD probe to a well-known policy endpoint as the slow-link detection mechanism. The canonical JSON's `slow_link_policy` field per area controls behavior: `always_apply` (default for security-relevant areas), `skip_on_slow_link` (default for cosmetic preferences), `warn_on_slow_link`.

## Rationale

Three candidate architectures were considered before locking the hybrid declarative+compiler model.

**Candidate A: Pure ADMX/GPO format with a cross-platform CSE emulator.** Preserve ADMX as canonical, ship a `gpsvc.dll`-equivalent on macOS and Linux that emulates the CSE dispatch loop. Rejected because (a) ADMX is Windows-implementation-shaped (registry-path-centric, `enabledValue`/`disabledValue` bitmask, `Registry.pol` PReg binary) and forcing it onto macOS MDM payloads and Linux `authselect` profiles produces the same lowest-common-denominator leak that ADR-024 Alternative B rejected; (b) ADMX's typed-value system (REG_SZ/REG_DWORD/REG_MULTI_SZ) is insufficient for the framework's `secret_ref` and `nested` types; (c) SSSD's experience parsing ADMX-equivalent policy via `ad_gpo.c` shows that every CSE-equivalent must be hand-coded per platform.

**Candidate B: Pure declarative JSON, no ADMX interop.** Drop ADMX entirely; require all policies authored in canonical JSON. Rejected because (a) enterprises have thousands of existing ADMX-defined policies (Microsoft's built-in ADMX set alone is ~3,500 policies; customer-specific ADMX from LOB apps adds another ~500-2,000); forcing re-authoring is a multi-year effort that defeats the framework's migration value proposition; (b) ADMX is the lingua franca for third-party Windows LOB apps (Chrome, Office, Zoom all ship ADMX); dropping ADMX drops the ability to manage those apps without re-authoring each vendor's ADMX; (c) the ADMX-to-JSON compiler is a one-time investment (~2 person-weeks for a robust compiler) that pays for itself the first time a customer imports the Chrome ADMX and gets 200 managed-preferences keys for free.

**Candidate C: Hybrid with YAML canonical instead of JSON.** Same hybrid model but with YAML as canonical. Rejected for the reasons in [ADR-029](../adr/ADR-029-json-canonical-policy-preg-adapter.md) Alternative A: YAML's type inference (`1.0` float vs. `1.0.0` string; `yes`/`no`/`on`/`off` boolean ambiguity) is unacceptable for a typed policy format where a registry value `1.0` REG_SZ and `1.0` REG_DWORD are different settings. Operators who prefer YAML for human authoring can use the authoring UI's YAML view (which converts to canonical JSON on save).

The chosen hybrid model — canonical JSON + ADMX compiler + PReg adapter + synthetic Windows CSE + public Rust plugin trait — satisfies three constraints simultaneously: (1) Windows interop (legacy `gpsvc.dll` + native CSEs continue to work via PReg; the synthetic CSE adds non-Registry area coverage); (2) cross-platform parity (canonical JSON is the single authoring surface, compiled to platform-native forms); (3) extensibility (the `PolicyExecutor` trait allows third-party LOB apps to ship framework-native executors).

CEL is chosen over Rego as the default selector language because CEL is expression-oriented (returns a single boolean, matching the targeting decision), the `cel-rust` crate is ~600 lines and embeddable, and CEL is used by Kubernetes (CEL validation rules in CRDs) and Envoy. Rego remains opt-in for OPA-using customers.

The "no dynamic loading of untrusted native code" rule is forced by security: a policy executor runs as SYSTEM/root, and accepting operator-supplied `.so`/`.dll` files would create an arbitrary-code-execution channel via policy. The framework's threat model requires that all privileged code paths be reproducible from a signed build.

## Trade-offs accepted

- **ADMX → JSON is one-way.** The framework does not round-trip ADMX → JSON → ADMX. Operators who need to maintain ADMX authoring for legacy AD-only environments must keep their ADMX source-of-truth in existing GPO tooling. Acceptable because the migration direction is one-way.
- **ADMX features not preserved in JSON.** ADMX's `enabledValue`/`disabledValue` bitmask, `enableKey` deletion-on-disable, and `range` constraints are flattened to explicit `value_when_enabled` / `value_when_disabled` / `delete_on_disable` JSON annotations. Acceptable because the synthetic Windows CSE handles the deletion-on-disable explicitly.
- **Rego is opt-in, not first-class.** OPA-using customers get Rego selectors; non-OPA customers get CEL by default. Acceptable because the framework's reference policy library is authored in CEL.
- **No arbitrary script executor.** Operators cannot ship shell scripts or PowerShell as policy; operators who need arbitrary automation use the framework's Ansible collection. Acceptable because arbitrary-script-as-policy is the GPP "Run programs" abuse pattern.
- **macOS coverage gaps are documented, not fixed.** Where canonical policy defines an area with no macOS MDM payload equivalent (e.g., Windows Defender signature toggles), the macOS executor drops the setting with `WARN` and the framework's coverage report makes the gap visible. Acceptable because pretending to manage an unmanageable setting is worse than admitting the gap.

## Rust implementation implications

The decision is implementable in pure Rust with the following crate graph:

- **`adrian-policy-core`** (workspace member) — defines `PolicyDoc`, `PolicyArea` enum, `TypeEnum`, `Setting`, `Snapshot`, `DryRunReport`, `ApplyReport`, `ExecutorContext`. Crates: `serde = "1"`, `serde_json = "1"`, `thiserror = "1"`, `tracing = "0.1"`.
- **`adrian-policy-executor`** (workspace member, public) — defines the `PolicyExecutor` trait, `PolicyExecutorRegistration`, and the `inventory`-based registration infrastructure. Crates: `inventory = "0.3"`, `async-trait = "0.1"`, plus `adrian-policy-core`.
- **`adrian-policy-validate`** (workspace member) — implements JSON Schema validation against the canonical schema. Crates: `jsonschema = "0.17"` (boon-based, pure Rust), `serde_json`, `miette = "5"` for diagnostic rendering with line/column.
- **`adrian-policy-cel`** (workspace member) — wraps the CEL engine for selector evaluation. Crates: `cel-parser = "0.1"`, `cel-interpreter = "0.6"` (the `cel-rust` family; pure Rust, no LLVM dep). The host-facts document is passed as a `serde_json::Value` and converted to CEL's `Value` type via the crate's `From` impls.
- **`adrian-policy-rego`** (workspace member, opt-in) — wraps `regorus = "0.1"` (pure-Rust OPA Rego engine) for customers who select `selector.lang == "rego"`. Compiled behind a cargo feature flag `rego` so the binary stays small for CEL-only deployments.
- **`admx2adrian`** (workspace member, binary) — the ADMX-to-JSON compiler. Crates: `quick-xml = "0.27"` (streaming XML parser), `serde_json`, `clap = "4"`, `tracing`. The compiler is single-pass: stream-parse the ADMX, build the JSON template in memory, emit on completion. The `adml` (language resource) file is parsed alongside to provide human-readable display strings, which are emitted as a `_display` annotation on each setting.
- **`preg2adrian`** and the PReg adapter (workspace member, library `adrian-policy-preg`) — binary PReg encode/decode. Crates: `encoding_rs = "0.8"` (UTF-16LE ↔ UTF-8), `byteorder = "1"`, `hex = "0.4"`, `serde_json`. The PReg record format is hand-rolled (no published Rust crate); the implementation is ~400 lines including the `PReg\0` signature, UTF-16LE string fields, hex-encoded data, and multi-string null-terminator handling.
- **`adrian-policy-distribution`** (workspace member, service binary) — the policy distribution service that reads canonical JSON from Git, compiles to platform-native forms (calls `adrian-policy-preg` for Windows targets, calls the macOS MDM payload emitter, calls the Linux config-fragment emitter), and pushes via WebSocket per ADR-028. Crates: `tokio = "1"`, `axum = "0.7"` (HTTPS pull endpoint), `tokio-tungstenite = "0.21"` (WebSocket push), `git2 = "0.18"` (Git history read), `tower-http = "0.5"` (auth middleware).
- **`adrian-policy-daemon`** (workspace member, client-side binary) — runs on each enrolled client, receives policy updates from the distribution service, dispatches each area to the registered `PolicyExecutor`, and reports apply/rollback status. Crates: `tokio`, `adrian-policy-executor`, `adrian-policy-core`, `tracing-subscriber = "0.3"`. On Windows, this runs as a service; on macOS, as a launchd daemon; on Linux, as a systemd service.

The synthetic Windows CSE is a Rust dynamic library (`adrian_cse.dll`) compiled with `cdylib` crate type, exposing `extern "C"` entry points matching the `ProcessGroupPolicyEx` signature. The C ABI is provided by `windows-sys = "0.52"` and `windows = "0.54"` (for `userenv.h` types). The CSE GUID is allocated at build time and written to the framework's installer MSI; the installer registers the CSE under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<framework-CSE-GUID>}`.

The framework's authoring UI (a React/TypeScript single-page app, not part of the Rust workspace) calls the `adrian-policy-validate` library via a WebAssembly build of the validation crate (`wasm-bindgen = "0.2"`, `serde-wasm-bindgen = "0.6"`). This gives the UI client-side schema validation with the same logic as the server-side validator, eliminating a class of "validates in browser, fails on server" bugs.

Estimated effort: ~14 person-weeks for v1. Breakdown: ADMX compiler (3 pw), PReg adapter + reader (2 pw), CEL selector engine integration (1 pw), Rego opt-in (1 pw), public `PolicyExecutor` trait + inventory registration (1 pw), synthetic Windows CSE (3 pw, highest-risk), macOS/Linux compilation targets (2 pw), authoring UI WASM validation (1 pw).

## Problems unblocked

| Problem | Capability | Severity | Gating ORQ before | Status after |
|---------|-----------|----------|---------------------|--------------|
| PC-046 — ADMX schema Windows-specific; cross-platform equivalent fragmented | Policy Engine | high | ORQ-030/031 (Day 1 resolved) + ORQ-090/091 | Unblocked — ADMX → JSON compiler (`admx2adrian`) produces canonical JSON; third-party ADMX files compile to framework-native policy templates |
| PC-047 — CSE model Windows-only; per-CSE GUIDs | Policy Engine | high | ORQ-090/091 (PARTIAL via ADR-024) | Fully unblocked — public `PolicyExecutor` plugin trait resolves the deferred sub-decision in ADR-024; ADR-024 promoted to FULLY RESOLVED |
| PC-095 — No unified policy authoring | Cross-Platform Parity | blocker | ORQ-030/031 (Day 1) + ORQ-169/170 (Day 2 Decision 11) + ORQ-090/091 | Unblocked — canonical JSON is the single authoring surface; ADMX compiler imports existing policies; per-platform compilation targets produce native forms |
| PC-048 — GPO no rollback/transactional semantics | Policy Engine | medium | (ADR-ELIGIBLE, gated on executor contract) | Implementation locked — `PolicyExecutor::snapshot`/`rollback` are part of the public trait, ADR-025 implementation can proceed against the locked contract |
| PC-052 — Registry.pol PReg format | Policy Engine | medium | (ADR-ELIGIBLE per ADR-029) | Implementation locked — PReg adapter spec is finalized; `adrian-policy-preg` crate can be implemented |
| PC-056 — No native policy versioning / history | Policy Engine | medium | (ADR-ELIGIBLE per ADR-031) | Implementation locked — canonical JSON is Git-diffable; PR review pipeline runs `adrian-policy validate` |

## Implementation impact

The decision locks the Policy Engine's v1 architecture. `adrian-policy-core` and `adrian-policy-executor` are the foundation for all subsequent Policy Engine work; their public APIs are stable for v1 (semver guarantee). The ADMX compiler is migration-critical: customers cannot adopt the framework without importing existing ADMX-defined policies, so the compiler must ship in v1.0 and must handle the Microsoft-built-in ADMX set (Windows 11 23H2 is ~3,500 policies across 75 ADMX files) without errors.

The synthetic Windows CSE is the highest-risk item. CSE registration requires a stable GUID, a DLL exporting `ProcessGroupPolicyEx` with the correct prototype, and per-GPO invocation order that matches `gpsvc.dll`'s expectations. The CSE must coexist with native CSEs without duplicate registry writes or version-counter desync. The framework's CI includes a Windows Server 2022 VM running the CSE regression suite on every PR.

The macOS compilation target depends on MDM enrollment (per ADR-052); unenrolled macOS hosts cannot receive framework policy. The Linux target depends on `authselect` (per ADR-050) for PAM-affecting areas; distros without `authselect` fall back to direct PAM-file editing with `WARN`.

## Cross-capability dependencies

- **Client SDK (Decision 11).** The `PolicyExecutor` trait is consumed by the framework's client SDK daemon (`adrian-policy-daemon`). The SDK's C ABI exposes the daemon's API to Windows (synthetic CSE), macOS (launchd daemon), and Linux (systemd service). The SDK language choice (Rust core, per Decision 11) is the natural fit because the executor trait is Rust-native.
- **Cert Service (Decision 8).** Cert autoenrollment policy (`area == "CertAutoenroll"`) is a Policy Engine setting consumed by the Client SDK's cert enrollment module. The canonical JSON's `secret_ref` type is used for certificate private key references.
- **Cross-Platform Parity (PC-094 Windows-only Preferences XML).** The framework's `Preferences` area compilation targets (macOS MDM payloads, Linux config files) close this gap. PC-094 was gated by ORQ-072/074/075 (NTLM) but is also blocked on the policy compilation target; once the NTLM decision is made (Day 2 afternoon), the Preferences compilation targets can be finalized.
- **Operations (PC-115 unified CLI).** The `adrian-policy` CLI (validate, compile, evaluate, coverage, status) is part of the framework's unified cross-platform CLI (per [ADR-063](../adr/ADR-063-unified-cross-platform-cli.md)). The CLI is implemented in Rust against the `adrian-policy-core` library.
- **Migration (PC-124 AD FS-to-framework, PC-127 GPO-to-framework).** The ADMX compiler and PReg reader are the migration entry points for customers moving from AD. The `adrian-migrate from-gpo` CLI walks an AD GPO backup, runs `preg2adrian` on `Registry.pol`, runs `admx2adrian` on the ADMX templates referenced by the GPO, and emits canonical JSON policies.
- **Security (PC-123 threat model).** The "no dynamic loading of untrusted native code" rule is a security-critical control. The framework's threat model documents the `PolicyExecutor` trait as a trusted-code boundary: only executors compiled into the framework's signed binary are loaded; operator-supplied native code is rejected.

## References

- [ADR-024](../adr/ADR-024-per-platform-policy-executors.md) — per-platform policy executors (this decision resolves its deferred sub-decision; ADR-024 promoted from PARTIAL to FULLY RESOLVED)
- [ADR-029](../adr/ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy format; PReg adapter (this decision locks the executor contract and selector language that ADR-029 left open)
- [ADR-025](../adr/ADR-025-transactional-policy-rollback.md) — transactional policy application (depends on `PolicyExecutor::snapshot`/`rollback`)
- [ADR-026](../adr/ADR-026-declarative-host-facts-wmi-adapter.md) — declarative host facts (the facts document consumed by the CEL selector)
- [ADR-027](../adr/ADR-027-http-head-slow-link-detection.md) — slow-link detection
- [ADR-028](../adr/ADR-028-push-based-policy-websocket.md) — push-based policy distribution
- [ADR-031](../adr/ADR-031-git-backed-policy-history.md) — Git-backed policy history
- [ADR-050](../adr/ADR-050-authselect-standard-pam.md) — authselect standard PAM
- [ADR-052](../adr/ADR-052-ddm-first-authoring-macos.md) — DDM-first macOS authoring
- [ADR-063](../adr/ADR-063-unified-cross-platform-cli.md) — unified cross-platform CLI
- [PC-046, PC-047, PC-095](../catalog/04-policy-engine.md) — problem statements
- [CEL specification](https://github.com/google/cel-spec) — Common Expression Language
- [regorus](https://github.com/microsoft/regorus) — pure-Rust OPA Rego engine
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol (PReg format reference)
- [ADMX schema reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/admx-backed-policy) — ADMX policy configuration
