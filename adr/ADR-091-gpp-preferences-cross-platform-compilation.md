---
title: "ADR-091: Group Policy Preferences cross-platform compilation targets (resolves PC-045)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-045
severity: blocker
unblocked_by: Workshop Decision 7
tags: [adr, policy-engine, gpp, preferences, drive-maps, files, scheduled-tasks, services, mdm, launchd, systemd, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../workshop/decision-07-policy-format.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
  - ./ADR-024-per-platform-policy-executors.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
  - ./ADR-089-declarative-policy-gpc-gpt-synthesis.md
last_updated: 2026-08-14
---

# ADR-091: Group Policy Preferences cross-platform compilation targets (resolves PC-045)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 7](../workshop/decision-07-policy-format.md) §7 and §8, which specify that the framework's macOS and Linux compilation targets cover the canonical JSON's `Preferences.<area>` settings (drive maps, files, scheduled tasks, services, local users/groups, registry/plist, environment variables). This ADR operationalises Decision 7's compilation-target specification against the PC-045 problem surface: the Windows-only nature of GPO Preferences XML and the lack of macOS/Linux equivalents.

## Context

GPO Preferences are the most-used GPO feature in enterprise AD deployments. Per [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md), Preferences are 14+ XML files under `Machine\Preferences\` and `User\Preferences\` in the GPT, processed by `gppref.dll` (a single DLL hosting all 14 Preferences CSEs, with per-area CSE GUIDs `{nnnnnnnn-nnnn-nnnn-nnnn-nnnnnnnnnnnn}` registered at `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<GUID>}`). The 14 areas are: Drive Maps (`{5794DAFD-BE60-433f-88A2-1A3C39322536}`), Files (`{71587597-1207-11d2-8250-00A0C903A8CB}`), Folders, Ini Files, Local Users and Groups (`{17D1F0BD-7235-4A89-8B0E-601CB7C68D7E}`), Printers, Scheduled Tasks (`{CAB54552-71EA-4238-9141-161F1AC6CBD4}`), Services (`{16be69fa-4209-4250-9b8c-6539af50c92b}`), Shortcuts, Environment, Registry (`{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` — same GUID as the Registry-policy CSE; Preferences uses a different file), Internet Settings, Drive Maps (user-only), and Power Options. Each file has a root `<Collection>` or area-specific root (`<DrivesCls>`, `<NTServices>`, `<ScheduledTasks>`, `<Files>`, etc.) and per-item elements with `action="C|U|R|D"` (Create/Update/Replace/Delete) attributes, per-item `name`, `path`, `attrs`, and type-specific child elements.

Cross-platform support for Preferences is poor. SSSD does not parse any Preferences XML — its `ad_gpo_access` module reads only `[Privilege Rights]` from `GptTmpl.inf`, per [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md). Samba's `samba-gpupdate` reads `Registry.pol` and translates a fixed set of keys to Linux config files (`/etc/krb5.conf`, `/etc/security/limits.conf`, `/etc/sudoers.d/`) but has no Preferences XML support. macOS MDM Configuration Profile payloads cover a subset of the same surface (drive maps via `autofs`, scheduled tasks via `launchd`, printers via `com.apple.mobileconfig.airprint`) but with different schemas and no common authoring format. The matrix in [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) shows that for many Preferences areas the macOS equivalent is a `scripts` payload running shell commands — there is no native MDM payload at all.

Workshop Decision 7 §7 and §8 specify that the framework's macOS executor compiles `Preferences.*` areas to MDM payloads and the Linux executor compiles to platform-native config fragments. This ADR defines the per-area compilation targets and the GPP-XML emission for AD-interop.

## Decision

The framework's macOS and Linux executors (per ADR-024) compile the canonical JSON's `Preferences.*` areas to platform-native forms. For Windows-interop, the framework's distribution service emits GPP-XML files into the synthesised GPT folder (per ADR-089 §3). The compilation is bi-directional in coverage (the canonical JSON's `Preferences.*` enum covers all 14 GPP areas) but one-way in authoring (operators author in canonical JSON; the framework compiles to platform-native forms).

### Concrete specification

1. **Canonical `Preferences` PolicyArea.** The canonical JSON's `PolicyArea` enum (per ADR-029 and Decision 7 §1) includes a `Preferences` parent area with sub-areas matching the 14 GPP areas: `Preferences.DriveMaps`, `Preferences.Files`, `Preferences.Folders`, `Preferences.IniFiles`, `Preferences.LocalUsersGroups`, `Preferences.Printers`, `Preferences.ScheduledTasks`, `Preferences.Services`, `Preferences.Shortcuts`, `Preferences.Environment`, `Preferences.Registry`, `Preferences.InternetSettings`, `Preferences.PowerOptions`, `Preferences.NetworkOptions`. Each sub-area has its own typed settings schema (e.g., `Preferences.DriveMaps.settings{}` has `drives[]` with `drive_letter`, `path`, `action`, `persistent`, `label`, `username_ref` fields). The `action` field uses the framework's `Action` enum (`Create`, `Update`, `Replace`, `Delete`) matching GPP's `C|U|R|D`.

2. **Windows compilation target (GPP-XML emission).** The framework's distribution service (per Decision 7 §11 and ADR-089 §3) emits the synthesised GPT folder's `Machine\Preferences\<area>\<area>.xml` and `User\Preferences\<area>\<area>.xml` files from the canonical JSON's `Preferences.<area>` settings. The emission uses the exact GPP-XML schema that `gppref.dll` parses — root element `<DrivesCls>`, `<NTServices>`, `<ScheduledTasks>`, `<Files>`, etc.; per-item element `<Drive>`, `<Service>`, `<ImmediateTask>`, `<File>`, etc.; attributes `clsid`, `name`, `status`, `changed`, `uid`; per-action child elements `<Properties action="C|U|R|D" ...>`. The `username_ref` field is resolved at emission time: for non-secret references (a `domain\user` literal), the GPP-XML `username` attribute is set directly; for secret references (a `secret_ref` URI per Decision 7 §2), the GPP-XML is emitted with a `cPassword` placeholder and the actual secret is delivered via the framework's secret service (per Decision 11) — eliminating the GPP `cPassword` XOR-encrypted-password antipattern that was a known AD security vulnerability (MS14-025).

3. **macOS compilation target (MDM payloads).** The macOS executor (per ADR-024 and Decision 7 §7) compiles `Preferences.*` areas to MDM payloads:
   - `Preferences.DriveMaps` → `com.apple.autofs` payload (auto_master entry) for SMB-mounted drives; the mount point is created via `com.apple.configuration.files` (a directory placeholder file); the SMB credentials are delivered via the framework's secret service into the user's Keychain via a `com.apple.security.keychain` payload.
   - `Preferences.Files` → `com.apple.configuration.files` payload (atomic file deployment with hash verification; the file content is base64-encoded in the payload).
   - `Preferences.Folders` → `com.apple.configuration.files` payload (a directory-creation marker; the executor creates the directory at apply time via `mkdir -p`).
   - `Preferences.ScheduledTasks` → `com.apple.applicationaccess` payload (for restricted-app settings) plus a `com.apple.configuration.files` payload that drops a `launchd` plist into `~/Library/LaunchAgents/` (user-scope) or `/Library/LaunchDaemons/` (machine-scope); the executor runs `launchctl bootstrap` to load the agent.
   - `Preferences.Services` → `com.apple.configuration.files` payload (drops a `launchd` plist for system services; for service-control settings like startup type, the executor translates to `launchctl enable`/`disable`).
   - `Preferences.LocalUsersGroups` → `com.apple.configuration.users` payload (where supported on macOS 14+) for user creation; for group membership, `dseditgroup` is invoked by the executor.
   - `Preferences.Shortcuts` → `com.apple.configuration.files` payload (drops a `.webloc` or symbolic link).
   - `Preferences.Environment` → `com.apple.configuration.files` payload (drops a `.bash_profile`/`.zshrc` fragment with `export` lines; the executor appends to the existing file idempotently).
   - `Preferences.Registry` → `com.apple.managedpreferences` payload (writes the plist-equivalent key).
   - `Preferences.Printers` → `com.apple.mobileconfig.airprint` payload.
   - `Preferences.InternetSettings` → `com.apple.security.firewall` + `com.apple.applicationaccess` payloads (where supported; macOS's internet-settings surface is limited).
   - `Preferences.PowerOptions` → `com.apple.systempolicy.powermanagement` payload (where supported).
   - `Preferences.NetworkOptions` → `com.apple.networkusagedescription` and related payloads (where supported).
   - `Preferences.IniFiles` → no macOS equivalent; dropped with `WARN` and recorded in the per-policy coverage report (per Decision 7 §7).

4. **Linux compilation target (config fragments).** The Linux executor (per ADR-024 and Decision 7 §8) compiles `Preferences.*` areas to platform-native config fragments:
   - `Preferences.DriveMaps` → `/etc/auto.master.d/<policy>.direct` (autofs direct-map entry) + `/etc/auto.<policy>` (the map file with the SMB share path); SMB credentials stored in `/etc/samba/cifsblob/<policy>.cred` (mode 0600, owned by root); the executor runs `automount -r` to reload. Distros without `autofs` fall back to per-user `systemd` mount units in `~/.config/systemd/user/`.
   - `Preferences.Files` → atomic file deployment via the framework's pure-Rust executor (no shell scripts); `rename(2)` for atomic placement; hash verification before placement; the file content is delivered via the WebSocket push (per ADR-028).
   - `Preferences.Folders` → `mkdir -p` with `chmod`/`chown` per the setting's `mode`/`owner`/`group` fields; the executor uses `nix::unistd::mkdir` and `nix::sys::stat::fchmodat` for atomic operation.
   - `Preferences.ScheduledTasks` → `systemd` timer + service units in `/etc/systemd/system/<policy>.{timer,service}` (machine-scope) or `~/.config/systemd/user/<policy>.{timer,service}` (user-scope); the executor runs `systemctl daemon-reload` and `systemctl enable --now <policy>.timer`.
   - `Preferences.Services` → `systemctl enable`/`disable`/`mask` per the setting's `startup_type` field (`Automatic` → `enable`, `Manual` → `disable`, `Disabled` → `mask`); for service creation (a new unit), the executor drops a unit file in `/etc/systemd/system/`.
   - `Preferences.LocalUsersGroups` → `useradd`/`usermod`/`groupadd`/`gpasswd` via the framework's pure-Rust executor (no shell scripts); password hashes delivered via the framework's secret service.
   - `Preferences.Shortcuts` → symbolic link creation via `nix::unistd::symlink`; for `.desktop` files (Linux desktop shortcuts), the executor writes the `.desktop` file to `~/.local/share/applications/` or `/usr/share/applications/`.
   - `Preferences.Environment` → `/etc/profile.d/<policy>.sh` (machine-scope) or `~/.bash_profile.d/<policy>.sh` (user-scope) with `export` lines; the executor writes atomically via `rename(2)`.
   - `Preferences.Registry` → no direct Linux equivalent (Linux has no registry); the setting is dropped with `WARN` unless a `linux_translation` annotation is present (the annotation maps the registry path to a Linux config file path — used by the `admx2adrian` compiler to record known Linux equivalents for Microsoft ADMX policies).
   - `Preferences.Printers` → CUPS configuration via `lpadmin` (the executor invokes `lpadmin -p <name> -E -v <uri> -m <model>` for printer creation; `lpadmin -x <name>` for deletion).
   - `Preferences.InternetSettings` → no direct Linux equivalent; dropped with `WARN`.
   - `Preferences.PowerOptions` → `systemd-logind` configuration drop-in (`/etc/systemd/logind.conf.d/<policy>.conf`) for idle/sleep settings; `tlp` configuration for power-management profiles (where `tlp` is installed).
   - `Preferences.NetworkOptions` → `NetworkManager` configuration via `nmcli` (the executor invokes `nmcli connection modify <id> ...` for network settings); for hosts without `NetworkManager`, `/etc/network/interfaces` drop-ins (Debian) or `netctl` profiles (Arch).
   - `Preferences.IniFiles` → direct INI-file edit via the framework's pure-Rust INI parser/writer (`rust-ini = "0.19"`); the executor parses the target INI file, applies the setting (Create/Update/Replace/Delete per section/key), writes atomically.

5. **Atomic application and rollback.** All Linux executor operations use the framework's `PolicyExecutor` trait (per Decision 7 §9) — `Snapshot` records the current state (existing file content, existing unit files, existing user/group entries), `DryRun` computes the proposed changes, `Apply` performs the changes atomically, `Rollback` restores the snapshot on failure. macOS executor operations use the same trait; the `Snapshot` for MDM-payload-based settings records the current payload state (via the macOS MDM query API), and `Rollback` removes the payload (MDM payloads are inherently removable via `mdmclient removeProfile`).

6. **`secret_ref` delivery.** For Preferences settings that require secrets (SMB credentials for drive maps, passwords for local users, file contents for sensitive files), the canonical JSON uses the `secret_ref` type (per Decision 7 §2). The secret URI `adrian-secret://<vault>/<key>?version=<n>` is resolved at apply-time by the Client SDK against the framework's secret service (per Decision 11). The framework's secret service integrates with HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault (per Decision 11). This eliminates the GPP `cPassword` antipattern (MS14-025 — a known AD vulnerability where GPP-stored passwords were XOR-encrypted with a published key) and the SSSD limitation of never being able to deliver secrets via policy.

7. **Coverage reporting.** Per Decision 7 §7, the framework's `adrian-policy coverage --host <name> --area Preferences.<area>` CLI reports per-host coverage for each Preferences sub-area: which settings are supported on the host's platform, which are dropped with `WARN`, and which would require additional configuration (e.g., `autofs` installation on Linux for `Preferences.DriveMaps`). Operators use this report to identify cross-platform gaps before policy deployment.

## Rationale

Three alternatives were considered.

**Alternative A: Preserve GPP-XML as canonical; write a cross-platform `gppref.dll`-equivalent.** Use GPP-XML as the canonical Preferences format; ship a Rust library that parses GPP-XML and applies it on macOS and Linux. Rejected because (a) GPP-XML is Windows-implementation-shaped (the `<Properties action="C|U|R|D" ...>` schema is tied to `gppref.dll`'s per-area CSE invocation model; the `clsid` attribute is a Windows COM class ID; the `changed`/`uid` attributes assume a Windows-AD-authoring workflow); (b) GPP-XML's `cPassword` field is a security antipattern (XOR-encrypted with a published key per MS14-025); preserving it as canonical inherits the vulnerability; (c) the macOS and Linux compilation targets (MDM payloads, systemd units, autofs maps) do not map cleanly to GPP-XML's per-area schemas — a `Preferences.DriveMaps` setting on macOS needs an `auto_master` entry plus a Keychain credential, which GPP-XML's `<Drive>` element has no field for. Decision 7 §Rationale rejects this candidate explicitly.

**Alternative B: Drop Preferences entirely; require operators to use Ansible/Chef for cross-platform config.** Acknowledge that Preferences is Windows-specific; tell operators to use Ansible for macOS/Linux config management. Rejected because (a) Preferences is the most-used GPO feature in enterprise AD — dropping it from the framework would block migration for the majority of AD customers; (b) the framework's value proposition is unified policy across platforms; requiring a separate Ansible stack alongside the framework defeats the unification; (c) the framework's `PolicyExecutor` trait (per Decision 7 §9) is explicitly designed to support Preferences-like settings with snapshot/rollback semantics that Ansible's `--check` mode approximates but does not match.

**Alternative C: Per-platform native authoring (GPP-XML on Windows, MDM payloads on macOS, Ansible playbooks on Linux).** Preserve per-platform authoring surfaces; the framework's distribution service emits each platform's native format. Rejected because (a) it forces operators to author three versions of every Preferences policy — the same fragmentation problem as the current AD+SSSD+MDM state that the framework is solving; (b) the framework's audit and coverage-reporting features cannot answer "what is the effective Preferences policy on this host?" without reading three formats; (c) the framework's transactional apply (per ADR-025) requires a uniform `PolicyExecutor` contract that per-platform authoring breaks.

The chosen model — canonical JSON `Preferences.*` areas compiled to platform-native forms — gives the framework: (a) unified authoring (operators author once in JSON, the framework compiles to Windows GPP-XML, macOS MDM payloads, Linux config fragments); (b) transactional apply (the `PolicyExecutor` trait operates on the canonical JSON, not on the platform-native forms); (c) a documented coverage gap (the `WARN`-and-report model makes the macOS/Linux coverage gaps explicit rather than silent).

## Consequences

**Positive**. Operators author Preferences policies once and apply them across Windows, macOS, and Linux. The framework's `PolicyExecutor::snapshot`/`rollback` contract provides transactional apply with dry-run preview (per ADR-025) — a capability AD's `gppref.dll` lacks. The `secret_ref` type eliminates the GPP `cPassword` antipattern (MS14-025). The coverage report makes cross-platform gaps explicit and auditable.

**Negative**. Some Preferences areas have no macOS or Linux equivalent (`Preferences.IniFiles` on macOS, `Preferences.Registry` on Linux without explicit translation, `Preferences.InternetSettings` on both); these settings are dropped with `WARN` and the operator must use a different mechanism (e.g., Ansible for `Preferences.IniFiles` on macOS). The framework's macOS compilation target depends on MDM enrollment (per ADR-052) — unenrolled macOS hosts cannot receive Preferences policy. The Linux compilation target depends on `systemd`, `autofs`, and CUPS for full coverage; distros without these (e.g., Alpine Linux without `systemd`) fall back to degraded coverage with `WARN`.

**Neutral**. The framework's Preferences coverage is documented per-platform per-area in the `adrian-policy coverage` CLI; operators can audit coverage before deployment. The framework does not promise 100% coverage — it promises explicit reporting of gaps.

**Implementation cost**. ~6 person-weeks for v1 (per Decision 7 §Implementation impact, subsumed in the "macOS/Linux compilation targets" line item): GPP-XML emission for Windows (1.5 pw), macOS MDM payload compilation (1.5 pw), Linux config-fragment compilation (1.5 pw), `secret_ref` integration with the secret service (1 pw), coverage reporting CLI (0.5 pw). Ongoing maintenance: ~1 person-week per year for new macOS MDM payload types and new `systemd` features.

**Operational impact**. Operators author Preferences policies via the framework's UI (which emits canonical JSON). The `adrian-policy coverage --host <name> --area Preferences.DriveMaps` CLI previews coverage before deployment. The `adrian-policy compile --target macos <file>` CLI previews the macOS MDM payload output without applying.

## Alternatives Considered

### Alternative A: Preserve GPP-XML as canonical

Use GPP-XML as the canonical Preferences format; ship a cross-platform `gppref.dll`-equivalent that parses and applies GPP-XML on macOS and Linux.

Rejected as detailed in §Rationale and Decision 7 §Rationale Candidate A: GPP-XML is Windows-implementation-shaped; the `cPassword` antipattern (MS14-025) is a security vulnerability; macOS/Linux native formats do not map cleanly to GPP-XML schemas. The canonical JSON model with per-platform compilation is cleaner and more secure.

### Alternative B: Drop Preferences; require Ansible for cross-platform config

Acknowledge Preferences as Windows-specific; tell operators to use Ansible for macOS/Linux config management.

Rejected as detailed in §Rationale: Preferences is the most-used GPO feature; dropping it blocks migration; the framework's value proposition is unified policy; Ansible's `--check` mode does not match the framework's transactional apply contract.

### Alternative C: Per-platform native authoring

Preserve per-platform authoring surfaces (GPP-XML on Windows, MDM payloads on macOS, Ansible playbooks on Linux); the framework's distribution service emits each platform's native format.

Rejected as detailed in §Rationale: per-platform authoring forces three versions of every policy (the same fragmentation the framework is solving); audit and coverage-reporting cannot answer "what is the effective policy?" without reading three formats; transactional apply requires a uniform executor contract.

## Open Questions

- **`Preferences.DriveMaps` on macOS without MDM enrollment.** The `com.apple.autofs` payload requires MDM enrollment (per ADR-052). For unenrolled macOS hosts, the only path is a `launchd` daemon that runs `mount_smbfs` at login — but this requires storing the SMB credential in Keychain via a login-hook, which is deprecated. Current decision: macOS DriveMaps requires MDM enrollment; unenrolled macOS hosts get `WARN` and no drive map. Revisit if customers report unenrolled-macOS drive-map demand.
- **`Preferences.ScheduledTasks` trigger types.** GPP Scheduled Tasks support four trigger types (Immediate, Daily, Weekly, Monthly) plus `AtLogon`/`AtStartup`. The Linux compilation target maps these to `systemd` timer `OnCalendar`/`OnBootSec`/`OnUnitActiveSec` directives; the macOS target maps to `launchd` `StartCalendarInterval`/`RunAtLoad`/`StartInterval`. Some GPP trigger types (e.g., "On Event" — triggered by Windows event log) have no Linux/macOS equivalent and are dropped with `WARN`. Revisit if customer demand for event-triggered tasks emerges.
- **`Preferences.LocalUsersGroups` password rotation.** The framework's `secret_ref` type supports versioned secrets (`?version=<n>`); the executor should re-apply the user's password when the secret version changes. Current decision: the executor polls the secret service at every policy refresh (default 90 minutes) and re-applies on version change. Revisit if password-rotation latency is a concern (some customers want sub-15-minute rotation).

## Cross-capability impact

- **Policy Engine (PC-043 GPC/GPT split)**: ADR-089's GPT synthesis includes the GPP-XML files emitted by this ADR's Windows compilation target.
- **Policy Engine (PC-047 CSE model)**: The framework's synthetic Windows CSE (per Decision 7 §6) does not consume GPP-XML — legacy `gppref.dll` CSEs continue to consume the synthesised GPP-XML. The synthetic CSE consumes `Adrian/policy.json` for non-Preferences areas.
- **Client SDK (Decision 11)**: The `secret_ref` type is resolved by the Client SDK against the framework's secret service.
- **Cross-Platform Parity (PC-094 Windows-only Preferences XML)**: This ADR closes the PC-094 gap by providing macOS and Linux compilation targets.
- **Migration (PC-127 GPO-to-framework)**: The `adrian-migrate from-gpo` CLI reads existing GPP-XML files, translates them to canonical JSON `Preferences.*` settings, and emits a single canonical JSON document per GPO.
- **Security (PC-123 threat model)**: The `secret_ref` type eliminates the GPP `cPassword` antipattern (MS14-025); the threat model documents this as a security improvement over AD.

## References

- [PC-045](../catalog/04-policy-engine.md) — problem statement in the catalog
- [Workshop Decision 7](../workshop/decision-07-policy-format.md) §7 and §8 — macOS and Linux compilation targets
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — Preferences CSE GUIDs, `gppref.dll`, per-area XML schemas
- [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — Preferences area × platform coverage matrix
- [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md) — SSSD's lack of Preferences support
- [ADR-024](./ADR-024-per-platform-policy-executors.md) — per-platform policy executors (the trait consumed by this ADR's executors)
- [ADR-029](./ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy format (the `Preferences.*` PolicyArea enum)
- [ADR-089](./ADR-089-declarative-policy-gpc-gpt-synthesis.md) — GPC/GPT synthesis (consumes the GPP-XML emission)
- [MS14-025](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2014/ms14-025) — GPP `cPassword` vulnerability
- [`rust-ini` crate](https://docs.rs/rust-ini) — Rust INI parser/writer used by `Preferences.IniFiles` executor
- [`nix` crate](https://docs.rs/nix) — Rust POSIX bindings used by the Linux executor
