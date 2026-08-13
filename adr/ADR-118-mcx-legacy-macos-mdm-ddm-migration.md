---
title: "ADR-118: MCX Legacy on macOS — Migrate to MDM Configuration Profiles + DDM"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-103
severity: low
unblocked_by: [workshop-decision-07]
tags: [adr, cross-platform-parity, macos, mcx, managedclient, mdm, configuration-profiles, ddm, admx, preg, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-024-per-platform-policy-executors.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
  - ./ADR-052-ddm-first-authoring.md
  - ./ADR-113-gpo-preferences-cross-platform-policy.md
  - ../catalog/09-cross-platform-parity.md
  - ../workshop/decision-07-policy-format.md
  - ../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
last_updated: 2026-08-14
---

# ADR-118: MCX Legacy on macOS — Migrate to MDM Configuration Profiles + DDM

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 7](../workshop/decision-07-policy-format.md) (hybrid declarative JSON + ADMX compiler + PReg adapter with `PolicyArea::Registry` compiling to `com.apple.ManagedClient.preferences` on macOS). Resolves the low-severity problem [PC-103](../catalog/09-cross-platform-parity.md) (mcx legacy on macOS — the `com.apple.ManagedClient.preferences` payload type, inherited from the pre-10.7 MCX system, is the macOS equivalent of GPP Registry preferences but has operational quirks that the framework must address). Locks the framework's posture toward MCX-style preferences on macOS and the migration path to DDM (Declarative Device Management) on macOS 13+.

## Context

Before Configuration Profiles (pre-10.7), macOS used MCX (Managed Client for OS X). MCX was stored in OpenDirectory records (`mcx_settings` attribute on a user/computer/group record in OpenDirectory). The local copy of MCX was at `/Library/Managed Preferences/`. The MCX system is fully deprecated since macOS 10.14; the file format remains readable via `mcxrefresh -u <user>` (which mostly no-ops). MCX lives on as the legacy format for the `com.apple.ManagedClient.preferences` payload type — this is a "custom settings" profile that writes arbitrary preference keys, per [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) §ManagedClient/MCX legacy and [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

The `com.apple.ManagedClient.preferences` payload type is the macOS equivalent of GPP Registry preferences on Windows. It writes arbitrary preference keys to any plist (`~/Library/Preferences/com.example.app.plist`, `/Library/Preferences/com.example.app.plist`, `/Library/Managed Preferences/com.example.app.plist`). The payload structure is a nested dict where each top-level key is a domain (`com.example.app`) and each domain's value is a dict of `Forced` (mandatory settings) and `Set-Once` (one-time settings) arrays. Example:

```xml
<dict>
    <key>PayloadType</key>
    <string>com.apple.ManagedClient.preferences</string>
    <key>PayloadContent</key>
    <dict>
        <key>com.example.app</key>
        <dict>
            <key>Forced</key>
            <array>
                <dict>
                    <key>mcx_domain_settings</key>
                    <dict>
                        <key>SettingOne</key>
                        <string>value1</string>
                        <key>SettingTwo</key>
                        <integer>42</integer>
                    </dict>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

The operational quirks that bite: (a) **MCX `mcxrefresh` is mostly no-op since macOS 10.14** — applications that previously responded to MCX changes via `mcxrefresh` notifications no longer do so; the `com.apple.ManagedClient.preferences` payload is read once at application launch and not refreshed mid-session. (b) **MCX `Set-Once` semantics are unreliable** — `Set-Once` is supposed to set a preference once and then leave it user-manageable, but on macOS 11+, `Set-Once` is often overwritten by the user's changes without framework re-application. (c) **MCX `Forced` semantics require application support** — applications that do not check the `~/Library/Managed Preferences/` plist (a small minority of legacy apps) ignore `Forced` settings entirely; the framework cannot force them. (d) **MCX is incompatible with DDM (Declarative Device Management)** — DDM on macOS 13+ does not have a `com.apple.ManagedClient.preferences` equivalent; DDM declarations are typed (`com.apple.configuration.management-status`, `com.apple.configuration.software-update`, etc.) and do not write arbitrary preference keys. (e) **MCX is incompatible with System Integrity Protection (SIP)** for system-level plists (`/System/Library/Preferences/`); the framework cannot write to these plists via MCX.

Per [PC-103](../catalog/09-cross-platform-parity.md), the framework must address MCX legacy by: (a) supporting `com.apple.ManagedClient.preferences` as the macOS compilation target for `PolicyArea::Registry` (the macOS equivalent of GPP Registry preferences); (b) documenting the operational quirks; (c) providing a migration path from MCX to DDM as Apple expands DDM coverage; (d) documenting settings that cannot be enforced via MCX (system-level plists, applications that do not check MCX). Workshop Decision 7 ([workshop/decision-07-policy-format.md](../workshop/decision-07-policy-format.md)) §7 specifies the macOS compilation target: `area == "Registry"` → `com.apple.managedpreferences` payload (note: the Decision uses `com.apple.managedpreferences` as a shorthand; the actual payload type is `com.apple.ManagedClient.preferences`); §10 specifies DDM-first authoring on macOS 13+ (per [ADR-052](./ADR-052-ddm-first-authoring.md)). This ADR locks the framework's MCX legacy posture and the DDM migration path.

## Decision

The framework's posture toward MCX legacy on macOS is: **support `com.apple.ManagedClient.preferences` as the macOS compilation target for `PolicyArea::Registry`** (the macOS equivalent of GPP Registry preferences), **document the operational quirks** (no `mcxrefresh` mid-session, unreliable `Set-Once`, `Forced` requires application support, SIP-protected system-level plists cannot be written), **provide a migration path from MCX to DDM** as Apple expands DDM coverage, **document settings that cannot be enforced via MCX** (system-level plists, applications that do not check MCX). The framework's `PolicyModule` (per [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md)) compiles `PolicyArea::Registry` to `com.apple.ManagedClient.preferences` payloads, with DDM-first fallback for `PolicyArea` values that have DDM coverage (SoftwareUpdate, Passcode, Wallpaper, Organization Info per [ADR-052](./ADR-052-ddm-first-authoring.md)).

**Concrete specification**:

- **`PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` on macOS** (per Decision 7 §7 and [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md) §Decision). The framework's `MacOsPolicyExecutor` (per [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md)) compiles canonical JSON `area == "Registry"` settings to a `com.apple.ManagedClient.preferences` MDM payload. The compilation:
  - Reads the canonical JSON's `spec.areas[].settings[]` array where each setting has `{ "type": <TypeEnum>, "value": <typed-value> }` per Decision 7 §2.
  - For each setting, the framework interprets the setting's `key` as a macOS preference domain + key path: `com.example.app/SettingOne` → domain `com.example.app`, key `SettingOne`; `com.example.app/nested/key` → domain `com.example.app`, key path `nested.key` (nested dict).
  - The framework emits a `com.apple.ManagedClient.preferences` payload with the setting under `Forced` (mandatory; the framework's default for `PolicyArea::Registry` since `Set-Once` is unreliable per §Context).
  - The payload is emitted via the MDM channel (per [ADR-052](./ADR-052-ddm-first-authoring.md) DDM-first on macOS 13+, Configuration Profile fallback on macOS 12 and earlier).
  - Settings that target SIP-protected system-level plists (`/System/Library/Preferences/`) are dropped with a `WARN` log and a per-policy coverage report accessible via `adrian-cli policy coverage --host <name> --area Registry`.
  - Settings that target application preference domains where the application does not check MCX (the framework maintains a known-incompatible list: `com.apple.loginwindow` for some sub-keys, `com.apple.systempolicy` for some sub-keys, system-level `~/Library/Preferences/com.apple.systemconfiguration.plist`) are dropped with a `WARN` log.

- **MCX operational quirks are documented** in the framework's `adrian-cli policy coverage` output and in the framework's documentation. The documentation explicitly states:
  - **No `mcxrefresh` mid-session**: applications read the `com.apple.ManagedClient.preferences` payload at application launch; changes to the payload (via MDM push) take effect on the next application launch. The framework's MDM push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)) sends the updated payload immediately, but the application's behavior does not change until the user restarts the application.
  - **Unreliable `Set-Once`**: the framework uses `Forced` (mandatory) for all `PolicyArea::Registry` settings; `Set-Once` is not used (the framework's posture is that policy settings are mandatory, not one-time-set-and-user-manageable).
  - **`Forced` requires application support**: most modern macOS applications (built on AppKit) check `~/Library/Managed Preferences/com.example.app.plist` at launch and apply `Forced` settings; legacy applications that do not check this plist ignore `Forced` settings. The framework's known-incompatible list documents these legacy applications.
  - **SIP-protected system-level plists**: `/System/Library/Preferences/` is read-only on macOS 11+ (SIP); the framework cannot write to these plists via MCX. The framework's `adrian-cli policy coverage` output flags settings that target SIP-protected plists.

- **DDM-first fallback for `PolicyArea` values that have DDM coverage** (per Decision 7 §7 and [ADR-052](./ADR-052-ddm-first-authoring.md)). The framework's `MacOsPolicyExecutor` detects the macOS version (via `sw_vers -productVersion`) and dispatches:
  - On macOS 13+ where DDM covers the `PolicyArea` (SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets, ScreenTime per [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) §DDM coverage), the framework emits a DDM declaration (per [ADR-052](./ADR-052-ddm-first-authoring.md)) rather than a Configuration Profile.
  - On macOS 13+ where DDM does not cover the `PolicyArea` (the long tail: Kerberos SSO, Platform SSO, FileVault, firewall, app restrictions, `com.apple.ManagedClient.preferences` for arbitrary preference keys), the framework emits a Configuration Profile (per Decision 7 §7).
  - On macOS 12 and earlier (no DDM support), the framework emits a Configuration Profile for all `PolicyArea` values.
  - The framework's `adrian-cli policy coverage --host <name>` output shows which `PolicyArea` values are compiled to DDM declarations vs Configuration Profiles on each host.

- **MCX-to-DDM migration path**. As Apple expands DDM coverage in future macOS releases, the framework's `MacOsPolicyExecutor` automatically migrates `PolicyArea` values from Configuration Profile to DDM. The migration:
  - The framework's `MacOsPolicyExecutor` checks the DDM coverage matrix (a static configuration in the framework's `adrian-policy` crate, updated per macOS release) for each `PolicyArea`.
  - If a `PolicyArea` value moves from Configuration Profile to DDM in a new macOS release, the framework's `MacOsPolicyExecutor` emits a DDM declaration on the new macOS release and a Configuration Profile on the old macOS release.
  - The framework's `adrian-cli policy coverage --host <name>` output shows the compilation target per `PolicyArea` per host, allowing operators to verify the migration.
  - The framework does NOT auto-migrate existing Configuration Profile policies to DDM declarations; the framework's `MacOsPolicyExecutor` emits both (DDM declaration on macOS 13+ where DDM covers the area, Configuration Profile on macOS 12 and earlier) for the same canonical JSON policy. The two are not in conflict because they target disjoint settings (DDM declarations cover specific areas; Configuration Profiles cover the long tail).

- **Settings that cannot be enforced via MCX** (per §Context) are documented in the framework's `adrian-cli policy coverage` output:
  - **System-level plists under SIP**: `/System/Library/Preferences/` is read-only on macOS 11+; the framework cannot write to these plists via MCX. The framework's `adrian-cli policy coverage` output flags settings that target SIP-protected plists with `WARN: target_plist_under_sip`.
  - **Applications that do not check MCX**: the framework's known-incompatible list (maintained in the framework's `adrian-policy` crate) documents applications that do not check `~/Library/Managed Preferences/com.example.app.plist` at launch. Settings targeting these applications are flagged with `WARN: target_app_does_not_check_mcx`.
  - **`Set-Once` semantics**: the framework uses `Forced` (mandatory) for all `PolicyArea::Registry` settings; `Set-Once` is not used. Settings with `Set-Once` semantics in the canonical JSON (per Decision 7 §2 `TypeEnum::nested` with `set_once = true`) are flagged with `WARN: set_once_not_supported_on_macos` and dropped.

- **Rust crates**:
  - `quick-xml = "0.31"` (XML parsing for the `com.apple.ManagedClient.preferences` payload — the payload is a plist XML, parsed and emitted via `plist` crate)
  - `plist = "1"` (macOS plist parsing and emission — the framework's `MacOsPolicyExecutor` uses `plist` to emit the `com.apple.ManagedClient.preferences` payload's nested dict structure)
  - `serde = "1"` + `serde_json = "1"` (canonical JSON parsing per Decision 7 §1)
  - `cel = "0.2"` (CEL selector evaluation per Decision 7 §10)
  - `tracing = "0.1"` (structured logging)
  - `clap = "4"` (CLI argument parsing for `adrian-cli policy coverage`)
  - `tokio = "1"` (async runtime for the `MacOsPolicyExecutor`'s WebSocket push subscription per [ADR-028](./ADR-028-push-based-policy-websocket.md))

- **Audit logging**: every `PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "sdk_policy_compile_op"`, `area = "Registry"`, `target_platform = "macos"`, `target_format` (`managed_client_preferences`/`ddm_declaration`/`configuration_profile`), `settings_count`, `dropped_count` (settings dropped due to SIP/incompatible-app/set-once), `result`, `platform = "macos"`. The framework's `adrian-cli policy coverage` output is queryable via the framework's REST API (per [ADR-061](./ADR-061-rest-grpc-api.md)) for fleet-wide coverage reporting.

## Rationale

The choice to support `com.apple.ManagedClient.preferences` as the macOS compilation target for `PolicyArea::Registry` is forced by Decision 7 §7 (macOS compilation target) and the lack of a better alternative. `com.apple.ManagedClient.preferences` is the only MDM payload type that writes arbitrary preference keys; DDM declarations are typed and do not cover arbitrary preference keys. The framework's `PolicyArea::Registry` is the cross-platform equivalent of Windows Registry preferences (GPP Registry), which writes to any registry path; on macOS, the equivalent is writing to any plist, which requires `com.apple.ManagedClient.preferences`. The framework's documentation makes the operational quirks explicit so operators can make informed decisions about which settings to enforce via `PolicyArea::Registry` on macOS.

The choice to use `Forced` (mandatory) for all `PolicyArea::Registry` settings on macOS (rather than `Set-Once`) is forced by the unreliability of `Set-Once` on macOS 11+. `Set-Once` is supposed to set a preference once and then leave it user-manageable, but on macOS 11+, `Set-Once` is often overwritten by the user's changes without framework re-application. The framework's posture is that policy settings are mandatory (the operator's intent is to enforce the setting, not to suggest it); `Forced` is the appropriate semantic. Settings that the operator wants to be one-time-set-and-user-manageable should not be in `PolicyArea::Registry` (which is for enforced settings); they should be in a different `PolicyArea` (e.g., a future `PolicyArea::Preferences.Defaults` for one-time-set preferences — not in v1).

The choice to provide a DDM-first fallback for `PolicyArea` values that have DDM coverage is forced by [ADR-052](./ADR-052-ddm-first-authoring.md) and Decision 7 §7. DDM is Apple's future direction (per [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) §DDM coverage); the framework's `MacOsPolicyExecutor` emits DDM declarations where DDM coverage exists (SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets, ScreenTime on macOS 13+) and Configuration Profiles where DDM does not cover the area (the long tail). The framework's `adrian-cli policy coverage` output shows the compilation target per `PolicyArea` per host, allowing operators to verify the DDM migration.

The choice to document settings that cannot be enforced via MCX (SIP-protected plists, applications that do not check MCX) is forced by the framework's cross-platform-parity commitment. The framework cannot guarantee that a `PolicyArea::Registry` setting will be enforced on macOS if the target plist is SIP-protected or the target application does not check MCX; the framework's `adrian-cli policy coverage` output flags these settings with `WARN`, allowing operators to identify the gap and either (a) accept the gap (the setting is informational, not enforced), (b) find an alternative `PolicyArea` that enforces the same intent (e.g., a `com.apple.security.firewall` payload instead of writing to `/Library/Preferences/com.apple.alf.plist`), or (c) document the setting as out of scope for macOS.

The choice to NOT auto-migrate existing Configuration Profile policies to DDM declarations (but to emit both where DDM covers the area) is forced by the operational complexity of auto-migration. Auto-migration would require the framework to track which Configuration Profiles have been migrated to DDM and which have not, and to remove the migrated Configuration Profiles without affecting the unmigrated ones. Emitting both (DDM declaration on macOS 13+ where DDM covers the area, Configuration Profile on macOS 12 and earlier) is simpler and avoids the operational complexity of auto-migration. The two are not in conflict because they target disjoint settings (DDM declarations cover specific areas; Configuration Profiles cover the long tail).

## Consequences

**Positive**. The framework's `PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` provides a cross-platform equivalent of Windows GPP Registry preferences, allowing operators to write arbitrary preference keys on macOS from a unified policy source. The DDM-first fallback aligns with Apple's future direction, automatically migrating `PolicyArea` values from Configuration Profile to DDM as Apple expands DDM coverage. The framework's `adrian-cli policy coverage` output provides operational visibility into settings that cannot be enforced via MCX (SIP-protected plists, applications that do not check MCX), allowing operators to identify and address the gaps. The framework's documentation makes the MCX operational quirks explicit, enabling operators to make informed decisions about which settings to enforce via `PolicyArea::Registry` on macOS.

**Negative**. The `com.apple.ManagedClient.preferences` payload type is MCX legacy and inherits the operational quirks documented in §Context (no `mcxrefresh` mid-session, unreliable `Set-Once`, `Forced` requires application support, SIP-protected plists cannot be written). The framework's `adrian-cli policy coverage` output flags these quirks, but operators must understand them to interpret the coverage report correctly. The DDM coverage matrix is a static configuration that must be updated per macOS release (Apple expands DDM coverage in each major release); the framework's `adrian-policy` crate must track Apple's DDM coverage matrix, which requires ongoing maintenance. The framework's known-incompatible list (applications that do not check MCX) requires ongoing maintenance as new applications are released.

**Neutral**. The framework's MCX legacy posture is invisible to end users (they see the application's behavior, not the underlying MCX mechanism). The framework's MCX legacy posture is invisible to platform-native applications (Configuration Profiles continue to work alongside the framework). The framework's MCX legacy posture is visible to operators (they run `adrian-cli policy coverage --host <name> --area Registry` to see the coverage report).

**Implementation cost**. ~4 person-weeks. Breakdown: `MacOsPolicyExecutor` `PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` (1 pw), DDM coverage matrix and DDM-first fallback (1 pw), `adrian-cli policy coverage` output for `PolicyArea::Registry` quirks (0.5 pw), known-incompatible list (0.5 pw), documentation (1 pw).

**Operational impact**. Operations teams gain a cross-platform `PolicyArea::Registry` that compiles to `com.apple.ManagedClient.preferences` on macOS, PReg `Registry.pol` on Windows, and is dropped on Linux (Linux has no registry concept). Operations teams gain a DDM-first fallback that automatically migrates `PolicyArea` values to DDM as Apple expands DDM coverage. Operations teams gain a coverage report (`adrian-cli policy coverage`) that flags settings that cannot be enforced via MCX. Operations teams must understand the MCX operational quirks to interpret the coverage report correctly (the runbook includes a "MCX legacy on macOS" section).

## Alternatives Considered

**Alternative 1: Drop `PolicyArea::Registry` on macOS entirely; document GPP Registry preferences as Windows-only.** The framework does not compile `PolicyArea::Registry` on macOS; operators who need to write arbitrary preference keys on macOS use a different mechanism (e.g., a custom `PolicyArea::Preferences.Files` that writes plist files directly). **Rejection rationale**: This forces operators to maintain two parallel policy surfaces (one for Windows Registry preferences, one for macOS plist preferences), defeating the unified-policy goal (per Decision 7 §1). The `com.apple.ManagedClient.preferences` payload type, despite its quirks, is the only MDM payload type that writes arbitrary preference keys; the framework's `PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` is the cross-platform-equivalent path.

**Alternative 2: Use DDM-only on macOS 13+; drop Configuration Profile support entirely.** The framework uses DDM declarations for all `PolicyArea` values on macOS 13+; Configuration Profiles are dropped. **Rejection rationale**: DDM coverage on macOS 13+ is ~10-15% of the Configuration Profile payload breadth (per catalog PC-096 §Problem statement); the remaining 85-90% requires Configuration Profile fallback. DDM does not have a `com.apple.ManagedClient.preferences` equivalent; dropping Configuration Profile support would eliminate the framework's ability to write arbitrary preference keys on macOS 13+, which is the entire point of `PolicyArea::Registry` on macOS. DDM is supported as the compilation target where DDM coverage exists (SoftwareUpdate, Passcode, Wallpaper, Organization Info); Configuration Profile is the fallback for the long tail.

**Alternative 3: Write plist files directly via a pure-Rust executor (no `com.apple.ManagedClient.preferences` payload).** The framework's `MacOsPolicyExecutor` writes plist files directly to `~/Library/Preferences/` and `/Library/Preferences/` via a pure-Rust executor (similar to the Linux `Preferences.Files` executor per Decision 7 §8). **Rejection rationale**: Writing plist files directly bypasses the MDM channel, which means the framework's `adrian-policy-daemon` must run as root on macOS (to write to `/Library/Preferences/`) and must track user sessions (to write to `~/Library/Preferences/` for each user). The MDM channel handles this automatically (the `com.apple.ManagedClient.preferences` payload is delivered via MDM and applied by the OS's `mdmd` daemon). Direct plist writes also bypass the OS's preference caching layer (`cfprefsd`), which can cause inconsistent reads by applications. The `com.apple.ManagedClient.preferences` payload is the macOS-native mechanism for writing preference keys via MDM; the framework's `PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` is the macOS-idiomatic path.

## Open Questions

None. The decision is fully specified by Decision 7 §7 (macOS compilation target), Decision 7 §10 (DDM-first), [ADR-052](./ADR-052-ddm-first-authoring.md) (DDM-first authoring), and [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md) (cross-platform policy compilation). The implementation details (DDM coverage matrix maintenance, known-incompatible list maintenance) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Policy Engine** (Decision 7): The `MacOsPolicyExecutor`'s `PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` is the macOS path of the cross-platform policy compilation (per [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md)).
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The `PolicyModule`'s `MacOsPolicyExecutor` is part of the unified SDK's `PolicyModule` (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) and [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md)).
- **Cross-Platform Parity** ([PC-095](../catalog/09-cross-platform-parity.md)): The `PolicyArea::Registry` compilation to `com.apple.ManagedClient.preferences` provides a cross-platform equivalent of Windows GPP Registry preferences on macOS.
- **Cross-Platform Parity** ([PC-096](../catalog/09-cross-platform-parity.md)): The DDM-first fallback aligns with Apple's future direction, automatically migrating `PolicyArea` values from Configuration Profile to DDM as Apple expands DDM coverage.
- **Operations** ([ADR-060](./ADR-060-structured-audit-logs-otel.md)): The `sdk_policy_compile_op` audit event provides operational visibility into the macOS compilation target per `PolicyArea` per host.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): The `admx2adrian` compiler (per Decision 7 §3) ingests ADMX (including GPP Registry preferences) and emits canonical JSON; the framework's `MacOsPolicyExecutor` compiles the canonical JSON to `com.apple.ManagedClient.preferences` on macOS, providing the migration path from AD GPP Registry preferences to the framework's `PolicyArea::Registry` on macOS.

## References

- [PC-103](../catalog/09-cross-platform-parity.md) — problem statement (mcx legacy on macOS)
- [PC-096](../catalog/09-cross-platform-parity.md) — macOS DDM is the future but not yet full-coverage
- [Workshop Decision 7 — Policy Format](../workshop/decision-07-policy-format.md) — hybrid declarative JSON + ADMX compiler + PReg adapter (macOS compilation target per §7)
- [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) — MCX legacy, `com.apple.ManagedClient.preferences` payload type, DDM coverage on macOS 13+
- [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — GPO equivalents matrix (Registry preferences → `com.apple.ManagedClient.preferences`)
- [ADR-024](./ADR-024-per-platform-policy-executors.md) — per-platform policy executors
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution (MDM push channel)
- [ADR-029](./ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy + PReg adapter
- [ADR-052](./ADR-052-ddm-first-authoring.md) — DDM-first authoring (DDM coverage on macOS 13+)
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-061](./ADR-061-rest-grpc-api.md) — REST/gRPC API (coverage report query)
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md) — GPO Preferences and cross-platform policy compilation
- [Apple Configuration Profile Reference](https://developer.apple.com/business-education/mdm/) — Apple MDM payload reference (including `com.apple.ManagedClient.preferences`)
- [Apple DDM Reference](https://developer.apple.com/documentation/devicemanagement/declarativeconfiguration) — Apple Declarative Device Management reference
- [MS-GPPCF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppcf) — Group Policy: Preferences Extension Data Structure (GPP Registry preferences)
- [quick-xml Rust crate](https://docs.rs/quick-xml) — XML parsing (plist XML for `com.apple.ManagedClient.preferences`)
- [plist Rust crate](https://docs.rs/plist) — macOS plist parsing and emission
- [cel Rust crate](https://docs.rs/cel) — Common Expression Language interpreter (selector evaluation)
