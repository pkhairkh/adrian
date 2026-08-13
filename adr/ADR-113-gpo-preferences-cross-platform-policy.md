---
title: "ADR-113: GPO Preferences and Cross-Platform Policy Compilation"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-095
severity: blocker
unblocked_by: [workshop-decision-07, workshop-decision-11]
tags: [adr, cross-platform-parity, gpo, gpp, mdm, configuration-profiles, sssd-conf, admx, preg, cel, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-024-per-platform-policy-executors.md
  - ./ADR-026-declarative-host-facts-wmi-adapter.md
  - ./ADR-028-push-based-policy-websocket.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ../catalog/09-cross-platform-parity.md
  - ../workshop/decision-07-policy-format.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md
last_updated: 2026-08-14
---

# ADR-113: GPO Preferences and Cross-Platform Policy Compilation

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 7](../workshop/decision-07-policy-format.md) (hybrid declarative JSON + ADMX compiler + PReg adapter) and [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK with `PolicyModule`). Resolves the blocker problem [PC-095](../catalog/09-cross-platform-parity.md) (macOS Configuration Profiles vs Windows GPO vs Linux SSSD-conf have no unified authoring). Promotes [ADR-024](./ADR-024-per-platform-policy-executors.md) from PARTIAL to FULLY RESOLVED and locks the concrete `PolicyModule` compilation paths in the SDK.

## Context

The three target platforms use entirely different policy authoring, distribution, and application models. Windows uses GPO: ADMX templates (XML schema in `%SystemRoot%\PolicyDefinitions\*.admx`) define policy settings; the GPO container (GPC) lives in AD at `CN={<guid>},CN=Policies,CN=System,<domain>`; the GPO template (GPT) lives in SYSVOL at `\\<domain>\SysVol\<domain>\Policies\{<guid>}\`; client-side extensions (CSEs) in `%SystemRoot%\System32\` apply the policy (`scecli.dll` for Security, `gppref.dll` for Preferences, `gpsvc.dll` for Registry.pol). macOS uses Configuration Profiles (`.mobileconfig`, CMS-signed plist XML at the top level, payload dicts under `PayloadContent` array); ~80 payload types (`com.apple.mobiledevice.passwordpolicy`, `com.apple.security.firewall`, `com.apple.security.FDERecoveryKeyEscrow`, `com.apple.KerberosSSO`, `com.apple.configuration-ext.platform-sso`, `com.apple.applicationaccess.new`, etc.); profiles are pushed via MDM (APNs transport to `*.push.apple.com`, then HTTPS to MDM vendor's `ServerURL`); the `profiles` binary (`/usr/bin/profiles`) installs/removes/validates profiles locally. Linux uses `sssd.conf` (INI format, `[domain/<name>]` sections), `krb5.conf` (INI with `[realms]`, `[domain_realm]`, `[capaths]` sections), `smb.conf` (INI for Samba), `nsswitch.conf` (NSS source lists), PAM files (`/etc/pam.d/<service>`), plus Ansible/Puppet/Salt playbooks for everything else. There is no unified authoring across the three platforms, per [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) and [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md).

The GPO Preferences (GPP) subset deserves particular attention. GPP is the part of GPO that handles Drive Maps, Files, Local Users and Groups, Scheduled Tasks, Folder Redirection, Environment Variables, Registry preferences, Printers, Network Options, and Power Options. GPP was introduced in Server 2008 and has known security issues: the `cPassword` attribute in GPP XML files is XOR-encrypted with a published Microsoft key (MS14-025, deprecated in 2014), and the GPP XML files in SYSVOL are world-readable to authenticated users. Microsoft removed the `cPassword` functionality in MS14-025 but the GPP XML structure remains; SSSD's `ad_gpo.c` does not parse GPP XML; macOS has no GPP equivalent; Linux compensates with Ansible playbooks. The framework must provide a GPP replacement that: (a) compiles GPP-equivalent settings to platform-native formats (Configuration Profile on macOS, `authselect` profile on Linux, PReg on Windows); (b) eliminates the `cPassword` antipattern by using the framework's `secret_ref` type (per Decision 7 §2); (c) supports User Configuration GPOs (current SSSD is computer-context-only).

Workshop Decision 7 ([workshop/decision-07-policy-format.md](../workshop/decision-07-policy-format.md)) resolved the gating ORQs ORQ-090/091 in favor of: hybrid declarative JSON + ADMX compiler + PReg adapter, with a public Rust `PolicyExecutor` plugin trait, CEL selector by default (Rego opt-in), and per-platform compilation targets (PReg + synthetic CSE on Windows, MDM Configuration Profile on macOS, `authselect` profile + `audit.rules` on Linux). This ADR locks the SDK-side `PolicyModule` implementation that compiles canonical JSON to platform-native formats and dispatches to registered executors.

## Decision

The `adrian-sdk` Rust core ships a `PolicyModule` that compiles the framework's canonical JSON policy (per Decision 7 §1) to platform-native formats (PReg `Registry.pol` + synthetic CSE JSON on Windows, MDM Configuration Profile on macOS, `authselect` profile + `audit.rules` + `pam_faillock` config on Linux) and dispatches each `PolicyArea` to a registered `PolicyExecutor` (per Decision 7 §9). The `PolicyModule` eliminates the `cPassword` antipattern by replacing GPP's `cPassword` with the framework's `secret_ref` type (per Decision 7 §2). The `PolicyModule` runs as the host-side `adrian-policy-daemon` on every enrolled host, receiving policy updates via the WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)) and applying them via the platform-native executors.

**Concrete specification**:

- The `PolicyModule` exposes:
  ```rust
  impl PolicyModule {
      pub async fn fetch(&self, policy_id: &str) -> Result<PolicyDoc, PolicyError>;
      pub async fn fetch_all(&self) -> Result<Vec<PolicyDoc>, PolicyError>;
      pub async fn evaluate(&self, doc: &PolicyDoc, host_facts: &HostFacts) -> Result<bool, PolicyError>;
      pub async fn compile(&self, doc: &PolicyDoc, target: Platform) -> Result<CompiledPolicy, PolicyError>;
      pub async fn apply(&self, doc: &PolicyDoc) -> Result<ApplyReport, PolicyError>;
      pub async fn rollback(&self, policy_id: &str) -> Result<(), PolicyError>;
      pub async fn coverage_report(&self, host: &str) -> Result<CoverageReport, PolicyError>;
  }
  ```
  `compile()` produces a `CompiledPolicy` enum: `Windows(Registry.pol_bytes, cse_json_bytes)`, `MacOs(Vec<MdmPayload>)`, `Linux(Vec<ConfigFragment>)`. The compiled policy is platform-specific; the source `PolicyDoc` is unified.

- The `compile()` method dispatches on `PolicyArea` (per Decision 7 §1) and `Platform`:
  - `PolicyArea::Registry` → `Windows`: PReg `Registry.pol` (UTF-16LE, `[key;value;type;size;data;]` records per [ADR-029](./ADR-029-json-canonical-policy-preg-adapter.md)); `MacOs`: `com.apple.ManagedClient.preferences` payload (Custom Settings writing to any plist, per [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) §ManagedClient/MCX legacy); `Linux`: dropped with `WARN` log (Linux has no registry concept).
  - `PolicyArea::Security` → `Windows`: `GptTmpl.inf` (`[Privilege Rights]`, `[System Access]`, `[Event Audit]`); `MacOs`: `com.apple.security.firewall` + `com.apple.applicationaccess` + `com.apple.passwordpolicy` payloads; `Linux`: `authselect` profile fragments + `/etc/security/limits.conf.d/<policy>.conf` + `/etc/audit/rules.d/<policy>.rules`.
  - `PolicyArea::AuditPolicy` → `Windows`: `Audit.csv`; `MacOs`: `com.apple.systempolicy.logging` payload (where supported); `Linux`: `/etc/audit/rules.d/<policy>.rules`.
  - `PolicyArea::AccountPolicy` → `Windows`: `GptTmpl.inf` `[System Access]` (`PasswordHistorySize`, `MinPasswordLength`, `PasswordComplexity`, `MinPasswordAge`, `MaxPasswordAge`, `LockoutBadCount`, `ResetLockoutCount`); `MacOs`: `com.apple.mobiledevice.passwordpolicy` payload; `Linux`: `/etc/login.defs.d/<policy>.conf` + `pam_faillock` config in `/etc/security/faillock.conf`.
  - `PolicyArea::Preferences.Files` → `Windows`: GPP XML `<Files>` element (per MS-GPPCF); `MacOs`: `com.apple.configuration.files` payload (per Decision 7 §8); `Linux`: atomic `rename(2)` writes via the framework's pure-Rust executor (no shell scripts, per Decision 7 §8).
  - `PolicyArea::Preferences.DriveMaps` → `Windows`: GPP XML `<DriveMaps>` element; `MacOs`: dropped with `WARN` log (no native drive-map payload; framework applications use `mount_smbfs`); `Linux`: `/etc/auto.master.d/<policy>` + `/etc/auto.adrian` autofs map fragments.
  - `PolicyArea::Preferences.LocalUsersGroups` → `Windows`: GPP XML `<LocalUsersAndGroups>` element; `MacOs`: dropped with `WARN` log (no native payload; framework's macOS client manages local users via `dscl`); `Linux`: `authselect` profile with `with-mkhomedir` + `/etc/security/group.conf` fragments.
  - `PolicyArea::Preferences.ScheduledTasks` → `Windows`: GPP XML `<ScheduledTasks>` element; `MacOs`: `com.apple.applicationaccess.new` + custom LaunchAgent/LaunchDaemon plist embedded as a custom payload; `Linux`: systemd unit fragments at `/etc/systemd/system/<name>.{service,timer}`.
  - `PolicyArea::Preferences.Environment` → `Windows`: GPP XML `<Environment>` element; `MacOs`: `com.apple.ManagedClient.preferences` writing to `~/Library/LaunchAgents/com.corp.env.plist`; `Linux`: `/etc/environment.d/<policy>.conf` fragments.
  - `PolicyArea::Preferences.Printers` → `Windows`: GPP XML `<Printers>` element; `MacOs`: `com.apple.printer` payload; `Linux`: CUPS `lpadmin` config fragments at `/etc/cups/printers.conf`.
  - `PolicyArea::Firewall` → `Windows`: `GptTmpl.inf` `[Windows Firewall]`; `MacOs`: `com.apple.security.firewall` payload; `Linux`: `firewalld` direct rules or `nftables` drop-ins (distro-detected).
  - `PolicyArea::Scripts` (Startup/Shutdown/Logon/Logoff) → `Windows`: `Scripts.ini` (`[Startup]`, `[Shutdown]`, `[Logon]`, `[Logoff]`); `MacOs`: `com.apple.ManagedClient.preferences` writing to `/Library/LaunchDaemons/com.adrian.scripts.<event>.plist`; `Linux`: systemd unit fragments at `/etc/systemd/system/<event>.service` with `Type=oneshot`.
  - `PolicyArea::Sudoers` → `Windows`: dropped with `WARN` log (no sudo concept); `MacOs`: `/etc/sudoers.d/<policy>` fragments via `visudo -c` validation; `Linux`: `/etc/sudoers.d/<policy>` fragments via `visudo -c` validation.

- The `cPassword` antipattern is eliminated by replacing GPP's `cPassword` field with the framework's `secret_ref` type (per Decision 7 §2). For example, a GPP `<LocalUsersAndGroups>` entry that sets a local user's password would previously have used `cPassword` (XOR-encrypted with the published Microsoft key, world-readable in SYSVOL). The framework's canonical JSON uses `{ "type": "secret_ref", "value": "adrian-secret://framework/local-admin?version=<n>" }`, resolved at apply-time by the SDK against the framework's secret service. The secret is never present in the canonical JSON, never written to SYSVOL, never visible to authenticated users.

- The `apply()` method dispatches on `Platform` and `PolicyArea`:
  ```rust
  pub trait PolicyExecutor: Send + Sync {
      fn area(&self) -> PolicyArea;
      fn snapshot(&self, ctx: &ExecutorContext) -> Result<Snapshot, ExecutorError>;
      fn dry_run(&self, ctx: &ExecutorContext, policy: &PolicyDoc) -> Result<DryRunReport, ExecutorError>;
      fn apply(&self, ctx: &ExecutorContext, policy: &PolicyDoc, snap: &Snapshot) -> Result<ApplyReport, ExecutorError>;
      fn rollback(&self, ctx: &ExecutorContext, snap: &Snapshot) -> Result<(), ExecutorError>;
      fn capabilities(&self) -> Capabilities;
  }
  ```
  Three platform-specific executors are shipped:
  - **Windows** (`WindowsPolicyExecutor`): writes `Registry.pol` to `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Machine\Registry.pol`, writes GPP XML to `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Machine\Preferences\`, writes `GptTmpl.inf` to `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>>\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`, writes `Scripts.ini` to `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Machine\Scripts\`, writes `Audit.csv` to `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Machine\Microsoft\Windows NT\Audit\Audit.csv`. The synthetic CSE (per Decision 7 §6) writes a framework-JSON blob to `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Adrian\policy.json` for non-`Registry` areas; the synthetic CSE loads `policy.json` via the SDK's C ABI and dispatches each `area` to the registered Windows executor.
  - **macOS** (`MacOsPolicyExecutor`): emits MDM payloads via the MDM channel (per [ADR-052](./ADR-052-ddm-first-authoring.md) DDM-first). `PolicyArea::Registry` → `com.apple.ManagedClient.preferences` payload (per Decision 7 §7); `PolicyArea::Security` → `com.apple.security.firewall` + `com.apple.applicationaccess`; `PolicyArea::AccountPolicy` → `com.apple.passwordpolicy`; `PolicyArea::AuditPolicy` → `com.apple.systempolicy.logging` (where supported); `PolicyArea::Preferences.Files` → `com.apple.configuration.files`. Settings that have no macOS MDM payload equivalent are dropped with a `WARN` log and a per-policy coverage report accessible via `adrian-cli policy coverage --host <name> --area <area>`.
  - **Linux** (`LinuxPolicyExecutor`): writes `authselect` profile fragments (per Decision 7 §8), `/etc/security/limits.conf.d/<policy>.conf`, `/etc/audit/rules.d/<policy>.rules`, `/etc/login.defs.d/<policy>.conf`, `firewalld` direct rules or `nftables` drop-ins (distro-detected), and atomic `rename(2)` writes via the pure-Rust executor for `Preferences.Files`. Where a setting has no native Linux representation, the executor drops the setting with a `WARN` log.

- The `PolicyModule` is the host-side policy daemon (`adrian-policy-daemon`), running on every enrolled host as a Windows Service / launchd daemon / systemd service. The daemon receives policy updates via the WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)), evaluates the CEL selector (per Decision 7 §10) against the host's facts (per [ADR-026](./ADR-026-declarative-host-facts-wmi-adapter.md)), and dispatches each `PolicyArea` to the registered `PolicyExecutor`. The daemon runs with the platform's highest privileges (SYSTEM on Windows, root on Linux, root on macOS via launchd) to write to system configuration files.

- The C ABI exposes the `PolicyModule` as opaque-handle functions:
  ```c
  typedef struct AdrianPolicy AdrianPolicy;
  typedef struct AdrianPolicyDoc AdrianPolicyDoc;
  typedef struct AdrianCompiledPolicy AdrianCompiledPolicy;
  int32_t adrian_policy_fetch(AdrianPolicy*, const char* policy_id, AdrianPolicyDoc** out);
  int32_t adrian_policy_fetch_all(AdrianPolicy*, AdrianPolicyDoc*** out_docs, size_t* out_count);
  int32_t adrian_policy_evaluate(AdrianPolicy*, const AdrianPolicyDoc*, const char* host_facts_json, int* out_match);
  int32_t adrian_policy_compile(AdrianPolicy*, const AdrianPolicyDoc*, int platform, AdrianCompiledPolicy** out);
  int32_t adrian_policy_apply(AdrianPolicy*, const AdrianPolicyDoc*, char** out_report_json);
  int32_t adrian_policy_rollback(AdrianPolicy*, const char* policy_id);
  int32_t adrian_policy_coverage(AdrianPolicy*, const char* host, char** out_report_json);
  int32_t adrian_policy_doc_free(AdrianPolicyDoc*);
  int32_t adrian_policy_compiled_free(AdrianCompiledPolicy*);
  ```

- Audit logging: every `fetch`, `apply`, `rollback` operation emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "sdk_policy_op"`, `op`, `policy_id`, `host_facts_hash`, `areas_applied`, `result`, `platform`. PII redaction: `secret_ref` values are NOT logged (only the URI scheme is logged as `adrian-secret://...`).

## Rationale

The choice to ship a `PolicyModule` in the SDK that compiles canonical JSON to platform-native formats is forced by Decision 7 §1 (canonical policy document) and Decision 7 §6-§8 (per-platform compilation targets). The framework's canonical JSON is the unified source; the compiled output is platform-specific. Without the `PolicyModule`'s compilation, framework-native applications would need to call platform-specific policy APIs (GPO + CSE on Windows, MDM + Configuration Profile on macOS, `authselect` + Ansible on Linux), defeating the unified-SDK goal.

The choice to replace GPP's `cPassword` with the framework's `secret_ref` type is forced by the `cPassword` antipattern documented in MS14-025. The XOR-encrypted `cPassword` field in GPP XML files is decryptable by any authenticated user with read access to SYSVOL; the framework cannot ship a security-sensitive secret-management mechanism that is world-readable. The `secret_ref` type (per Decision 7 §2) resolves the secret at apply-time via the framework's secret service, which enforces ACL-gated retrieval and audit logging. The secret is never present in the canonical JSON, never written to SYSVOL, never visible to authenticated users.

The choice to ship three platform-specific `PolicyExecutor` implementations (Windows, macOS, Linux) is forced by Decision 7 §9 (public `PolicyExecutor` plugin trait). The framework's executors are the reference implementations; third-party executors can be registered via `inventory::submit!{ PolicyExecutorRegistration { area, factory } }` (per Decision 7 §9). The framework's executors handle the most common `PolicyArea` values; third-party executors handle framework-specific areas (e.g., a custom `PolicyArea::Kubernetes` for Kubernetes-specific settings).

The choice to run the `PolicyModule` as a system daemon (`adrian-policy-daemon`) with platform-highest privileges is forced by the need to write to system configuration files. On Windows, the daemon runs as `NT AUTHORITY\SYSTEM` to write to `HKLM\Software\Policies\Adrian\` and `\\<domain>\SYSVOL\`; on Linux, the daemon runs as root to write to `/etc/security/limits.conf.d/`, `/etc/audit/rules.d/`, `/etc/login.defs.d/`, `/etc/systemd/system/`; on macOS, the daemon runs as root (via launchd) to write to `/etc/sudoers.d/`, `/Library/LaunchDaemons/`, `/etc/auto.master.d/`. The daemon's audit logging (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)) records every configuration write, providing operational visibility.

The choice to use `authselect` as the Linux compilation target for `PolicyArea::Security` is forced by Decision 12 §9 (`authselect` profile) and [ADR-050](./ADR-050-authselect-standard-pam.md). `authselect` is the modern Linux PAM/NSS profile generator (RHEL, Fedora, Rocky, CentOS Stream); the framework ships a custom `adrian-with-sudo` profile that uses `pam_adrian.so` (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §PAM/NSS provider) and `pam_sss.so` (per Decision 12 §1) for SSSD-primary compatibility. Debian and SUSE do not ship `authselect` by default; the framework's Linux executor detects the distro and uses `pam-auth-update` (Debian) or `pam-config` (SUSE) as fallbacks (per Decision 12 §11 distro-detection pattern).

## Consequences

**Positive**. The framework gains a single policy authoring surface (canonical JSON) that compiles to platform-native formats on every platform, eliminating the "two parallel policy systems" problem documented in [PC-095](../catalog/09-cross-platform-parity.md) (GPO for Windows, Ansible for Linux, MDM for macOS). The `cPassword` antipattern is eliminated; secrets are resolved at apply-time via the framework's secret service. The `PolicyModule`'s coverage report (`adrian-cli policy coverage`) provides per-host per-area coverage visibility, allowing operators to identify settings that have no platform-native equivalent. The framework's SSSD GPO coverage gap (per [PC-088](../catalog/08-client-sdk.md)) is closed: the framework's `LinuxPolicyExecutor` extends coverage from SSSD's `[Privilege Rights]`-only subset to the full `Security` PolicyArea (logon hours, host access control, group policy access control) plus `AccountPolicy`, `AuditPolicy`, `Preferences.*`, `Firewall`, `Scripts`, and `Sudoers`. User Configuration GPOs (computer-context-only in SSSD) are supported: the framework's `PolicyModule` evaluates the CEL selector against user facts as well as host facts.

**Negative**. The `PolicyModule` is a new code surface that must be maintained and patched as platform-native policy formats evolve (Apple adds new MDM payload types per macOS release; Microsoft adds new CSE GUIDs per Windows release; Linux distros change PAM/NSS generators per major release). The `adrian-policy-daemon` runs with platform-highest privileges, making it a high-risk code path for privilege escalation; the daemon's audit logging (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)) records every configuration write, but the daemon itself is a target. The `PolicyExecutor` plugin trait's `apply` method writes arbitrary system configuration; third-party executors must be audited carefully before being loaded (per Decision 7 §9, no dynamic loading of untrusted native code).

**Neutral**. The `PolicyModule` is invisible to end users (they see the policy's effects, not the compilation). The `PolicyModule` is invisible to platform-native applications (GPO, Configuration Profile, `authselect` continue to work alongside the framework). The `PolicyModule` is visible to framework-native applications (they call `policy.apply()` directly).

**Implementation cost**. ~10 person-weeks. Breakdown: `PolicyModule` Rust core + compilation logic (3 pw), `WindowsPolicyExecutor` (2 pw, including synthetic CSE), `MacOsPolicyExecutor` (2 pw, including MDM payload generation), `LinuxPolicyExecutor` (2 pw, including distro-detection and `authselect`/`pam-auth-update`/`pam-config` fallbacks), C ABI surface + audit logging integration (1 pw).

**Operational impact**. Operations teams gain a single policy audit event type (`sdk_policy_op`) across all platforms, queryable via OpenTelemetry. Operations teams gain a coverage report (`adrian-cli policy coverage`) identifying settings that have no platform-native equivalent. Operations teams must understand the platform-native policy formats for troubleshooting (the runbook includes a "PolicyModule troubleshooting" section per platform).

## Alternatives Considered

**Alternative 1: OPA Rego as the unified policy format.** The framework uses Rego as the canonical policy format, with per-platform executors that compile Rego to GPO/MDM/`authselect`. **Rejection rationale**: Decision 7 §10 explicitly chose CEL over Rego as the default selector engine. Rego is rule-oriented (returns a set of decisions), not expression-oriented (returns a boolean for the target decision); Rego's evaluation model is harder to embed in the framework's `adrian-policy validate` CLI. Rego is available as an opt-in selector engine via the `regorus` crate (per Decision 7 §10); the framework does not force Rego as the canonical format.

**Alternative 2: Per-policy-type DSL (similar to Terraform HCL).** The framework ships one DSL per policy area (`password_policy`, `firewall_policy`, `audit_policy`, etc.), each with its own syntax. **Rejection rationale**: This fragments the policy authoring surface, requiring operators to learn N DSLs. The framework's canonical JSON (per Decision 7 §1) is a single format with typed `TypeEnum` values; the framework's `adrian-policy validate` CLI validates against a JSON Schema. The per-policy-area structure is encoded in the canonical JSON's `spec.areas[]` array, not in separate DSLs.

**Alternative 3: Adopt Microsoft's ADMX schema as the source format and compile to macOS MDM + Linux sssd.conf/Ansible.** The framework uses ADMX as the canonical format, with `admx2adrian` compiling to platform-native formats. **Rejection rationale**: ADMX is Windows-centric; some macOS/Linux concepts (LaunchDaemons, systemd units, MDM supervised-only restrictions) have no ADMX representation. The framework's canonical JSON (per Decision 7 §1) is platform-neutral; the `admx2adrian` compiler (per Decision 7 §3) ingests ADMX as a source format for AD-interop, but the canonical JSON is the framework's source of truth, not ADMX.

## Open Questions

None. The decision is fully specified by Decision 7 §1-§12 and Decision 11 §1. The implementation details (per-area compilation logic, platform-native executor implementations) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Policy Engine** (Decision 7): The `PolicyModule` is the host-side policy daemon, consuming the framework's canonical JSON policy and dispatching to registered executors.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The `PolicyModule` is the policy surface of the unified SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)).
- **Client SDK** ([PC-088](../catalog/08-client-sdk.md)): The `LinuxPolicyExecutor` closes SSSD's GPO coverage gaps.
- **Cross-Platform Parity** ([PC-095](../catalog/09-cross-platform-parity.md)): The `PolicyModule` provides unified authoring across Windows GPO, macOS MDM, and Linux `authselect`/`sssd.conf`.
- **Operations** ([ADR-060](./ADR-060-structured-audit-logs-otel.md)): The `PolicyModule`'s audit events (`sdk_policy_op`) are queryable via OpenTelemetry.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): The `admx2adrian` compiler (per Decision 7 §3) and the `preg2adrian` migration tool (per Decision 7 §5) are the migration paths from AD GPO to the framework's canonical JSON.

## References

- [PC-095](../catalog/09-cross-platform-parity.md) — problem statement
- [Workshop Decision 7 — Policy Format](../workshop/decision-07-policy-format.md) — hybrid declarative JSON + ADMX compiler + PReg adapter
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — CSE architecture, GPP XML, Registry.pol, GptTmpl.inf, Scripts.ini
- [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) — Configuration Profile payload types, ManagedClient/MCX legacy, DDM
- [ADR-024](./ADR-024-per-platform-policy-executors.md) — per-platform policy executors (promoted from PARTIAL by this ADR)
- [ADR-026](./ADR-026-declarative-host-facts-wmi-adapter.md) — declarative host facts (CEL selector input)
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution
- [ADR-029](./ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy + PReg adapter
- [ADR-050](./ADR-050-authselect-standard-pam.md) — authselect standard PAM (Linux compilation target)
- [ADR-052](./ADR-052-ddm-first-authoring.md) — DDM-first authoring (macOS compilation target)
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [MS-GPPCF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppcf) — Group Policy: Preferences Extension Data Structure
- [MS14-025](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025) — Vulnerability in Group Policy Preferences could allow elevation of privilege
- [cel Rust crate](https://docs.rs/cel) — Common Expression Language interpreter
- [regorus Rust crate](https://docs.rs/regorus) — OPA-compatible Rego engine (opt-in per Decision 7 §10)
- [quick-xml Rust crate](https://docs.rs/quick-xml) — XML parsing (ADMX compiler, GPP XML)
