---
title: "ADR-052: DDM-First Authoring; Auto-Fallback to Configuration Profile"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-096
severity: low
tags: [adr, cross-platform-parity, macos, ddm, declarative-device-management, configuration-profiles, mdm]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/09-cross-platform-parity.md
  - ../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
last_updated: 2026-08-13
---

# ADR-052: DDM-First Authoring; Auto-Fallback to Configuration Profile

## Status

Accepted — 2026-08-13

## Context

Declarative Device Management (DDM), introduced in macOS 13 and extended in macOS 14 and 15, is a stateful, declarative alternative to the imperative MDM protocol. With DDM, the MDM server declares desired state as JSON (not plist); the device reconciles to that state and reports back asynchronously via the existing MDM check-in channel (`CheckInURL` of the MDM enrollment). Each declaration has a `DeclarationType`, `Identifier`, and `ServerToken` (used for change detection). Declarations are organized into Activations (bind a declaration set to a scope), Assets (files referenced by other declarations, like a wallpaper PNG), Configurations (a flat list of `ConfigurationType`-keyed declarations similar to payload types), and Management (server assertions like "Organizational Information" displayed in System Settings). Declarations live in `/private/var/db/ConfigurationProfiles/Declarations/` on the device, per [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md).

As of macOS 14, DDM covers: SoftwareUpdate restrictions, Passcode, Wallpaper, Organization Info, Asset declarations, and (in macOS 15) extensions to ScreenTime and a few more. Configuration Profiles remain necessary for the long tail — Kerberos SSO Extension, Platform SSO, FileVault, firewall, application restrictions, custom settings, etc. The migration is gradual; Apple has not announced a sunset date for Configuration Profiles. DDM's value-add over Configuration Profiles includes: (a) stateful reconciliation (the device reports current state, the server can detect drift), (b) asynchronous execution (no blocking on MDM push), (c) cleaner schema (JSON, not plist XML), (d) better support for declarative concepts (the device tells the server what it can do, the server tells the device what to do).

The framework's policy compilation target depends on macOS version (DDM on 13+, Configuration Profile on 12 and earlier), requiring the framework's macOS client to detect the OS version and choose the appropriate compilation path. Per [PC-096](../catalog/09-cross-platform-parity.md#pc-096--macos-ddm-declarative-device-management-is-the-future-but-not-yet-full-coverage)'s impact analysis, as of macOS 15, DDM covers ~10-15% of the Configuration Profile payload breadth; the remaining 85-90% requires Configuration Profile fallback. The framework cannot ship a v1 that only supports DDM (too narrow coverage) or only supports Configuration Profiles (legacy, will be deprecated). The hybrid approach (DDM where available, Configuration Profile fallback) is the only viable strategy.

The constraints from [PC-096](../catalog/09-cross-platform-parity.md#pc-096--macos-ddm-declarative-device-management-is-the-future-but-not-yet-full-coverage) require the framework to: support DDM declarations (SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets, ScreenTime) on macOS 13+; support Configuration Profile fallback for the long tail (~80 payload types not yet covered by DDM); detect macOS version and choose the appropriate compilation path; support DDM migration (auto-convert existing Configuration Profile policies to DDM declarations where DDM coverage exists); support DDM status reporting (the device's asynchronous state reports must be consumed by the framework's Policy Engine).

## Decision

The framework's macOS policy compilation will be DDM-first: for every policy area where DDM coverage exists (SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets, ScreenTime on macOS 13+), the framework's Policy Engine MUST emit DDM declarations as the primary compilation target. For every policy area where DDM coverage does not exist (Kerberos SSO, Platform SSO, FileVault, firewall, application restrictions, custom settings, etc.), the framework's Policy Engine MUST auto-fallback to Configuration Profile (`.mobileconfig`) as the secondary compilation target. The framework's macOS client will detect the OS version at enrollment and at every check-in, advertising DDM capability to the Policy Engine; the Policy Engine uses this capability advertisement to choose the compilation path per-policy. The framework's Policy Engine will auto-migrate Configuration Profile policies to DDM declarations as Apple expands DDM coverage, tracked via a per-macOS-version coverage matrix maintained in the framework's source tree.

**Concrete specification**:

- The framework's Policy Engine MUST maintain a DDM coverage matrix in source (`policy/ddm_coverage.yaml`) that maps each macOS version to the set of supported DDM declaration types. The matrix MUST be updated with each macOS release (e.g. macOS 13 supported SoftwareUpdate + Passcode + Wallpaper + Organization Info + Assets; macOS 14 added ScreenTime; macOS 15 added more). The matrix MUST include the corresponding Configuration Profile payload type for each DDM declaration type, for fallback purposes.
- The framework's Policy Engine MUST emit DDM declarations (JSON, per the DDM specification at `/private/var/db/ConfigurationProfiles/Declarations/`) for every policy area where the target macOS version's DDM coverage matrix indicates support. The declaration MUST include `DeclarationType`, `Identifier`, `ServerToken`, and the policy-specific payload.
- The framework's Policy Engine MUST emit Configuration Profile (`.mobileconfig`, CMS-signed plist XML at the top level, payload dicts under `PayloadContent` array) for every policy area where the target macOS version's DDM coverage matrix indicates no support. The profile MUST follow the Apple Configuration Profile schema (`PayloadType`, `PayloadVersion`, `PayloadIdentifier`, `PayloadUUID`, `PayloadDisplayName`).
- The framework's macOS client MUST advertise DDM capability to the Policy Engine at enrollment and at every check-in. The capability advertisement MUST include the macOS version (`sw_vers -productVersion`) and the supported DDM declaration types (queried via the `DeclarativeDeviceManagement` framework's `DDMDeviceCapabilities` API on macOS 13+).
- The framework's macOS client MUST consume DDM declarations from the Policy Engine via the existing MDM check-in channel (`CheckInURL`). The client MUST store declarations in `/private/var/db/ConfigurationProfiles/Declarations/` and apply them via the `DeclarativeDeviceManagement` framework's `DDMDeclarationSet` API. The client MUST report declaration status (acknowledged, pending, error) back to the Policy Engine via the same check-in channel.
- The framework's macOS client MUST consume Configuration Profile fallback via the existing MDM profile-installation channel (`InstallProfile` MDM command). The client MUST install profiles via `profiles install -path <profile.mobileconfig>` (or the MDM-equivalent `InstallProfile` command) and report installation status back to the Policy Engine.
- The framework's Policy Engine MUST auto-migrate existing Configuration Profile policies to DDM declarations as Apple expands DDM coverage. The migration: (a) on macOS upgrade, the macOS client re-advertises DDM capability (with the new macOS version's expanded coverage); (b) the Policy Engine checks each Configuration Profile policy against the new DDM coverage matrix; (c) for each policy that now has DDM coverage, the Policy Engine emits a DDM declaration and removes the Configuration Profile; (d) the macOS client applies the DDM declaration and uninstalls the Configuration Profile via `RemoveProfile` MDM command; (e) the migration is logged and reversible.
- The framework's documentation MUST include a "DDM coverage matrix" section listing the supported DDM declaration types per macOS version, the corresponding Configuration Profile payload types, and the auto-migration status (covered by DDM / Configuration Profile only / pending DDM coverage in future macOS).
- The framework's automated test suite MUST include DDM-Configuration Profile parity tests: for each policy area that has DDM coverage (SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets, ScreenTime), apply the policy via DDM on a macOS 14+ test host and verify the device state matches; apply the same policy via Configuration Profile on a macOS 12 test host (or a macOS 13+ host with DDM disabled) and verify the device state matches the DDM-applied host. The parity tests MUST run on every framework release.
- The framework's automated test suite MUST include a DDM migration test: deploy a Configuration Profile policy on a macOS 13 test host (DDM coverage exists for the policy area), simulate macOS upgrade to 14 (which expands DDM coverage), verify the Policy Engine auto-migrates the Configuration Profile to a DDM declaration, verify the macOS client applies the DDM declaration and uninstalls the Configuration Profile.
- The framework's Prometheus exporter MUST expose `mdm_ddm_declarations_total{type="...",result="..."}` and `mdm_configuration_profiles_total{type="...",result="..."}` metrics so operations teams can monitor the DDM-vs-Configuration Profile mix.

## Rationale

The decision to be DDM-first is forced by Apple's direction. DDM is the future; Configuration Profiles are legacy; Apple has not announced a sunset date but the trajectory is clear. The framework's macOS strategy aligns with Apple's trajectory rather than fighting it. DDM-first authoring means the framework's Policy Engine emits DDM declarations wherever DDM coverage exists, ensuring the framework's macOS posture uses the modern API as it expands.

The decision to auto-fallback to Configuration Profile is forced by DDM's incomplete coverage. As of macOS 15, DDM covers ~10-15% of the Configuration Profile payload breadth; the remaining 85-90% requires Configuration Profile fallback. The framework cannot ship a v1 that only supports DDM (too narrow coverage); the Configuration Profile fallback is mandatory for v1 functionality. The auto-fallback is per-policy (the Policy Engine checks the DDM coverage matrix per policy area and chooses the compilation target), so the framework's macOS posture is always the best available (DDM where possible, Configuration Profile where required).

The decision to auto-migrate Configuration Profile policies to DDM declarations as Apple expands DDM coverage is forced by the operational reality of macOS upgrades. When a customer upgrades their Mac fleet from macOS 14 to 15 (which expands DDM coverage to include ScreenTime), the framework's Policy Engine should automatically migrate the ScreenTime Configuration Profile to a DDM declaration. This is a one-time migration per policy area, triggered by the macOS client's re-advertised DDM capability after upgrade. The migration is logged and reversible (the framework can rollback to Configuration Profile if the DDM declaration fails to apply).

The decision to maintain a DDM coverage matrix in source is forced by the need to track Apple's coverage expansion per macOS release. The matrix is the source of truth for the Policy Engine's compilation-target choice; the matrix is updated with each macOS release (Apple publishes DDM coverage in the WWDC sessions and the MDM schema reference). The framework's matrix update is a source-tree commit; the framework's release notes document the matrix changes.

The decision to advertise DDM capability per-Mac (rather than per-fleet) is forced by the operational reality of mixed Mac fleets. Customers have Macs running different macOS versions (13, 14, 15, and earlier during upgrade windows); the framework's Policy Engine must compile different policy targets for different Macs based on each Mac's DDM capability. Per-Mac capability advertisement (via the MDM check-in channel) is the correct granularity.

## Consequences

**Positive**. The framework's macOS policy posture aligns with Apple's DDM trajectory. The framework's Policy Engine emits DDM declarations wherever DDM coverage exists, ensuring the framework's macOS clients use the modern API. The framework's auto-fallback to Configuration Profile for uncovered policy areas ensures v1 functionality. The framework's auto-migration of Configuration Profile policies to DDM declarations as Apple expands coverage reduces operational burden on customers.

**Negative**. The framework's Policy Engine must maintain two compilation targets (DDM JSON and Configuration Profile plist XML) for the foreseeable future, adding engineering complexity. The framework's DDM coverage matrix must be updated with each macOS release, requiring ongoing maintenance. The framework's macOS client must support both DDM declaration consumption and Configuration Profile installation, adding client-side complexity. The auto-migration logic is non-trivial (it must handle macOS upgrade events, capability re-advertisement, policy re-compilation, declaration application, profile removal, and rollback on failure).

**Neutral**. The framework's DDM-first posture is invisible to end users (they see policy applied, not the compilation target). The framework's Configuration Profile fallback is invisible to operations teams (the framework's CLI displays the compilation target per policy, but operations teams do not need to choose).

**Implementation cost**. Medium-high. Estimated 12-16 engineer-weeks for: the DDM coverage matrix, the Policy Engine's dual-target compilation, the macOS client's DDM declaration consumption, the auto-migration logic, the parity tests, the migration tests, the documentation. The DDM declaration consumption on the macOS client is the largest single component (~5-6 engineer-weeks for a correct, well-tested implementation).

**Operational impact**. Operations teams gain a single policy authoring surface (the framework's Policy Engine) that compiles to DDM or Configuration Profile as appropriate. Operations teams gain visibility into the DDM-vs-Configuration Profile mix via Prometheus metrics (`mdm_ddm_declarations_total` and `mdm_configuration_profiles_total`). Operations teams lose direct control over the compilation target (the framework's Policy Engine chooses automatically); the framework's CLI provides per-policy override for advanced use cases (e.g. force a policy to use Configuration Profile even when DDM coverage exists, for testing). The framework's runbook must include a "DDM vs Configuration Profile troubleshooting" section.

## Alternatives Considered

**Alternative 1: Configuration Profile-first authoring, auto-migrate to DDM as coverage expands.** The framework's Policy Engine emits Configuration Profile for every policy by default, and auto-migrates to DDM only when explicitly requested by the customer. **Rejection rationale**: This fights Apple's trajectory. Configuration Profile is the legacy API; the framework should use DDM where possible from v1, not defer to a future migration. The framework's customers would be running on the legacy API while Apple and the MDM ecosystem move to DDM, creating a technical-debt tail.

**Alternative 2: DDM-only authoring, refuse to support Configuration Profile.** The framework's Policy Engine emits DDM declarations only; policy areas without DDM coverage are documented as out of scope. **Rejection rationale**: DDM covers ~10-15% of the Configuration Profile payload breadth as of macOS 15; the framework cannot ship a v1 that supports only 10-15% of macOS policy areas. Kerberos SSO Extension, Platform SSO (per ADR-048), FileVault (per ADR-053), and firewall are all v1 must-haves that require Configuration Profile. DDM-only is not viable for v1.

**Alternative 3: Per-policy explicit choice (DDM vs Configuration Profile), no auto-fallback.** The framework's Policy Engine requires the policy author to choose DDM or Configuration Profile per policy at authoring time. **Rejection rationale**: This offloads the DDM coverage matrix knowledge to the policy author, which is operationally infeasible. Policy authors do not track Apple's DDM coverage expansion per macOS release; the framework's Policy Engine should track this and choose automatically. Per-policy explicit choice is appropriate for advanced use cases (e.g. testing a policy on DDM before rolling out) but should not be the default.

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the policy authoring format choice (OPA Rego vs JSON Schema vs per-policy-type DSL, per PC-095 deferred), but the DDM-vs-Configuration Profile compilation target is independent of the authoring format: the Policy Engine compiles any authoring format to DDM or Configuration Profile based on the coverage matrix.

## Cross-capability impact

- **Cross-Platform Parity** ([PC-095](../catalog/09-cross-platform-parity.md)): The unified policy authoring format (deferred per PC-095) compiles to DDM where covered, Configuration Profile where not (per this ADR), GPO (Windows), and sssd.conf + Ansible (Linux).
- **Cross-Platform Parity** ([PC-086](../catalog/09-cross-platform-parity.md via PC-086]): PSSO Extension is delivered via Configuration Profile (not DDM); the framework's macOS client must support Configuration Profile for PSSO until DDM coverage expands.
- **Policy Engine** ([PC-050](../catalog/04-policy-engine.md)): The Policy Engine is the server-side compilation component; this ADR defines the macOS compilation target.
- **Operations** ([PC-106](../catalog/10-operations.md)): Prometheus exporter exposes `mdm_ddm_declarations_total` and `mdm_configuration_profiles_total` metrics.

## References

- [PC-096](../catalog/09-cross-platform-parity.md) — problem statement
- [docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) — DDM framework architecture, Configuration Profile fallback, `ServerToken` change detection
- [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — DDM migration playbook showing Windows GPO → macOS MDM translation
- [Apple Declarative Device Management](https://developer.apple.com/documentation/devicemanagement/declarative-device-management) — DDM specification
- [Apple MDM Schema Reference](https://developer.apple.com/business/documentation/MDM-Protocol-Ref.pdf) — MDM protocol reference (Configuration Profile installation)
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) — The JSON Data Interchange Syntax (DDM declarations are JSON)
