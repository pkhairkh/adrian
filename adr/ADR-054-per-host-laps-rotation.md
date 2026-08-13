---
title: "ADR-054: Per-Host Local-Admin Password Rotation; LAPS Schema"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-098
severity: medium
tags: [adr, cross-platform-parity, laps, local-admin, password-rotation, privileged-access]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/09-cross-platform-parity.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
  - ../docs/10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

# ADR-054: Per-Host Local-Admin Password Rotation; LAPS Schema

## Status

Accepted — 2026-08-13

## Context

Windows LAPS (Local Administrator Password Solution) stores the local admin password hash + history in AD on the computer object. Legacy Microsoft LAPS (the 2015-era GPO + ADMX + CSE solution) uses the `ms-MCS-AdmPwd` attribute for the cleartext password and `ms-MCS-AdmPwdExpirationTime` for the expiry timestamp. New Windows LAPS (built into Windows Server 2022 and Windows 10 22H2+) uses `msLAPS-Password` (a JSON blob with `n`, `p`, `exp` fields — encrypted to a password encryption key), `msLAPS-EncryptedPassword` (the ciphertext), `msLAPS-PasswordExpirationTime`, and `msLAPS-EncryptedPasswordHistory`. The GPO "Password Settings" (Computer Config → Administrative Templates → LAPS ADMX) controls password complexity, length, age; the GPO "Account Settings" controls which local account to manage; the GPO "Backup/Restore" controls AD write behavior. The CSE (`laps.dll` in `svchost -k netsvcs`) runs every 90 minutes, checks `msLAPS-PasswordExpirationTime`, and rotates the password if expired, per the LAPS row in [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) and the LAPS row in [docs/10-comparison-matrices/01-feature-os-matrix.md](../docs/10-comparison-matrices/01-feature-os-matrix.md).

macOS has no native LAPS equivalent. The de facto standard is Jamf Pro's "LAPS" feature (Jamf rotates the local admin password via a daemon policy on the Mac, escrows the new password to the Jamf server, with retrieval gated by Jamf RBAC). On macOS 14+, Apple introduced `com.apple.configuration.device.password.rotation` as a DDM declaration (a future-direction replacement for Jamf LAPS), but coverage is limited. Linux has no native LAPS equivalent either. The standard pattern is an Ansible role that rotates the local admin password on a schedule, encrypts the new password to an Ansible Vault secret, and stores the encrypted secret in the Ansible controller. FreeIPA has `ipa host-mod --password=<otp>` which rotates the host's enrollment password (conceptually similar but not the same as LAPS — it's for host enrollment, not local admin password rotation).

The parity gap is clear: local admin password rotation is per-OS. Per [PC-098](../catalog/09-cross-platform-parity.md#pc-098--laps-local-admin-password-rotation-has-no-macoslinux-native-equivalent)'s impact analysis, a typical enterprise rotates local admin passwords every 30 days; with three platforms, that's three rotation mechanisms × 30 days × N hosts = significant operational overhead, plus the security risk of unrotated passwords on hosts that fall out of compliance. The framework must provide a unified LAPS-equivalent across platforms.

The constraints from [PC-098](../catalog/09-cross-platform-parity.md#pc-098--laps-local-admin-password-rotation-has-no-macoslinux-native-equivalent) require the framework to: support per-host password rotation (configurable schedule, on-demand, on enrollment); support directory escrow + ACL-gated retrieval (only helpdesk group can read; the host can write its own password); support password history (N previous passwords retained for audit); support password encryption at rest (Windows LAPS encrypts to a password encryption key; the framework must do the same); support Windows LAPS interop (read existing `ms-MCS-AdmPwd`/`msLAPS-Password` from AD; write new passwords to AD for Windows clients during migration); adopt Windows LAPS schema for compat (reusing `msLAPS-Password` for cross-platform parity).

## Decision

The framework will implement per-host local-admin password rotation across Windows, macOS, and Linux, with passwords stored in the framework directory on the computer object using the Windows LAPS schema (`msLAPS-Password` for cross-platform parity). The framework's Policy Engine will deploy per-platform LAPS agents: Windows client uses the built-in Windows LAPS CSE (Server 2022+) with a GPO that points at the framework directory; macOS client ships a LaunchDaemon (`com.framework.laps-rotation`) that rotates the local admin password on a 30-day interval via `dscl . -passwd /Users/admin <newpass>` and writes the new password to the framework directory's `msLAPS-Password` attribute; Linux client ships a systemd timer (`framework-laps-rotation.timer`) that rotates the local admin password on a 30-day interval via `chpasswd` and writes the new password to the framework directory's `msLAPS-Password` attribute. The framework's directory enforces ACL-gated retrieval (helpdesk group only); the framework's audit log records every retrieval.

**Concrete specification**:

- The framework's Core Directory MUST support the Windows LAPS schema on computer objects: `msLAPS-Password` (JSON blob with `n` (account name), `p` (cleartext password), `exp` (expiration timestamp)), `msLAPS-EncryptedPassword` (ciphertext encrypted to the framework's KMS or an HSM-bound key per ADR-032), `msLAPS-PasswordExpirationTime`, `msLAPS-EncryptedPasswordHistory` (N previous ciphertexts).
- The framework's Core Directory MUST enforce ACL-gated access on `msLAPS-*` attributes: the computer object's own account can write the attributes (via GSSAPI Kerberos authenticated write) but cannot read them after writing; the helpdesk group can read the attributes; standard users cannot read or write the attributes.
- The framework's Policy Engine MUST deploy a Windows GPO (compiled from the unified policy format per PC-095 deferred) that configures Windows LAPS for all framework-managed Windows hosts. The GPO MUST set: `LAPS_PwdSettings_PwdComplexity = Large letters + small letters + numbers + special characters`, `LAPS_PwdSettings_PwdLength = 20`, `LAPS_PwdSettings_PwdAgeDays = 30`, `LAPS_AccountSettings_AdminAccountName = <framework-managed local admin name>`, `LAPS_Backup_BackupTarget = Active Directory` (pointing at the framework directory).
- The framework's macOS client MUST ship a LaunchDaemon at `/Library/LaunchDaemons/com.framework.laps-rotation.plist` that runs `framework-laps-rotate` every 24 hours. The `framework-laps-rotate` binary checks the framework directory's `msLAPS-PasswordExpirationTime` attribute on the computer object; if expired, the binary generates a new 20-character password (complexity matching the Windows LAPS policy), writes the new password to the local admin account via `dscl . -passwd /Users/admin <newpass>`, then writes the new `msLAPS-Password` JSON blob (with `n`, `p`, `exp`) to the framework directory via LDAP modify.
- The framework's Linux client MUST ship a systemd timer at `/etc/systemd/system/framework-laps-rotation.timer` (with corresponding `.service`) that runs `framework-laps-rotate` every 24 hours. The `framework-laps-rotate` binary checks the framework directory's `msLAPS-PasswordExpirationTime` attribute on the computer object; if expired, the binary generates a new 20-character password, writes the new password to the local admin account via `chpasswd`, then writes the new `msLAPS-Password` JSON blob to the framework directory via LDAP modify.
- The framework's macOS client MUST support the `com.apple.configuration.device.password.rotation` DDM declaration on macOS 14+ as a future-direction replacement for the LaunchDaemon. The DDM declaration triggers the framework's `framework-laps-rotate` binary via a DDM-managed schedule; the binary's logic is identical to the LaunchDaemon path.
- The framework MUST ship a `framework-recover-laps` CLI that the helpdesk uses to retrieve a host's local admin password from the framework directory. The CLI authenticates to the framework directory via Kerberos, queries the `msLAPS-EncryptedPassword` attribute on the computer object, decrypts the password with the framework's KMS, and displays the cleartext password. The CLI MUST log every retrieval event to the framework's audit log (per ADR-060) with the helpdesk user, the computer object, the timestamp, and the reason.
- The framework's Policy Engine MUST deploy the rotation schedule (30 days default, configurable per-host or per-OU via the framework's policy). The Policy Engine MUST expose a per-host "rotate now" API (`POST /api/v1/hosts/<hostname>/laps/rotate`) that triggers immediate rotation on the next agent check-in.
- The framework's Windows client MUST support reading existing `ms-MCS-AdmPwd`/`msLAPS-Password` from AD for migration scenarios (customer migrating from AD to the framework). The framework's installer MUST detect existing LAPS data in AD and migrate it to the framework directory's `msLAPS-Password` attribute on first enrollment.
- The framework's macOS client MUST support migration from Jamf Pro's "LAPS" feature: the framework's installer MUST detect existing Jamf-managed local admin passwords (via Jamf Pro API or the `com.jamf.connect.login.plist` plist), generate a new framework-managed password, write it to the local admin account, write it to the framework directory, and disable the Jamf Pro LAPS policy (via Jamf Pro API call or documentation guidance).
- The framework's documentation MUST include a "LAPS deployment" section explaining the per-platform agents (Windows CSE, macOS LaunchDaemon, Linux systemd timer), the helpdesk retrieval workflow (`framework-recover-laps` CLI), the rotation schedule configuration, the migration paths (legacy Microsoft LAPS, Jamf Pro LAPS, Ansible-based rotation), and the audit logging.
- The framework's automated test suite MUST include end-to-end LAPS tests: enroll a Windows host, verify the LAPS GPO applies and `msLAPS-Password` is written to the framework directory within 90 minutes; enroll a macOS host, verify the LaunchDaemon rotates the password and writes `msLAPS-Password` to the framework directory within 24 hours; enroll a Linux host, verify the systemd timer rotates the password and writes `msLAPS-Password` to the framework directory within 24 hours; verify the helpdesk CLI retrieves the password for each platform; verify the audit log records each retrieval; verify the rotation schedule can be configured per-OU.
- The framework's Prometheus exporter MUST expose `laps_rotation_total{platform="...",result="..."}` and `laps_retrieval_total{platform="...",result="..."}` metrics so operations teams can monitor rotation compliance and retrieval patterns.

## Rationale

The decision to adopt the Windows LAPS schema (`msLAPS-Password`) for cross-platform storage is forced by Windows interop. Windows LAPS (built into Server 2022+ and Windows 10 22H2+) is the modern Microsoft LAPS; the framework's Windows client uses the built-in CSE without modification, writing to the framework directory's `msLAPS-Password` attribute. The framework's macOS and Linux clients use the same schema for cross-platform parity; the schema is JSON-based (`n`/`p`/`exp` fields), so it is platform-agnostic. The legacy Microsoft LAPS schema (`ms-MCS-AdmPwd`) is supported for migration but is documented as deprecated.

The decision to deploy per-platform LAPS agents (Windows CSE, macOS LaunchDaemon, Linux systemd timer) is forced by the framework's cross-platform parity commitment. Windows has a built-in LAPS CSE that the framework's Policy Engine configures via GPO; macOS and Linux do not have built-in LAPS, so the framework ships a LaunchDaemon and systemd timer that implement the same logic. The per-platform agents share a common pattern: check `msLAPS-PasswordExpirationTime`, generate a new password if expired, write the password to the local admin account, write the `msLAPS-Password` JSON blob to the framework directory. The framework's `framework-laps-rotate` binary is a single codebase (Rust or Go) compiled for each platform, ensuring consistency.

The decision to encrypt the password at rest (`msLAPS-EncryptedPassword`) is forced by the security-sensitivity of local admin passwords. The cleartext password is in `msLAPS-Password` (which is ACL-gated to the helpdesk group only), but the encrypted form (`msLAPS-EncryptedPassword`) provides defense-in-depth: even if an attacker gains read access to the `msLAPS-Password` attribute via a directory exploit, they cannot decrypt the `msLAPS-EncryptedPassword` without the framework's KMS key. The framework's KMS (or HSM-bound key per ADR-032) is the encryption root.

The decision to use a 30-day default rotation interval is forced by the operational balance between security and operational overhead. The 30-day interval matches the Windows LAPS default and the typical enterprise password-rotation cadence; shorter intervals (e.g. 7 days) increase helpdesk retrieval frequency without significant security benefit; longer intervals (e.g. 90 days) increase the window during which a compromised local admin password is valid. The framework's Policy Engine allows per-OU override of the rotation interval for customers with specific compliance requirements (e.g. PCI-DSS requires 90-day rotation, NIST 800-53 IA-5(1) requires periodic rotation).

The decision to ship a `framework-recover-laps` CLI for helpdesk retrieval is forced by the framework's commitment to a unified helpdesk workflow. The CLI is platform-agnostic (the helpdesk runs it from any framework-managed host or from the framework's management server); the CLI handles the per-platform differences (Windows LAPS retrieval via LDAP query, macOS/Linux retrieval via the same LDAP query). The CLI's audit logging (per ADR-060) provides accountability for every retrieval.

The decision to support migration from Jamf Pro LAPS is forced by the operational reality of macOS deployments. Many enterprises use Jamf Pro's "LAPS" feature for macOS local admin password rotation; the framework's installer detects this and migrates the rotation to the framework's LaunchDaemon. The migration is non-destructive (the local admin password is rotated to a new framework-managed value; the Jamf Pro LAPS policy is disabled but not deleted, allowing rollback).

## Consequences

**Positive**. The framework gains a unified LAPS-equivalent across Windows, macOS, and Linux, eliminating the per-platform rotation mechanisms that today consume significant operational overhead. The framework's directory is the single source of truth for local admin passwords, regardless of host OS. The framework's `framework-recover-laps` CLI provides a unified helpdesk workflow. The framework's audit logging provides accountability for every retrieval. The framework's migration paths (legacy Microsoft LAPS, Jamf Pro LAPS, Ansible-based) enable customer migration without losing existing rotation state.

**Negative**. The framework's macOS and Linux clients must ship and operate LAPS agents (LaunchDaemon and systemd timer), adding operational surface. The framework's Core Directory must support the Windows LAPS schema (`msLAPS-*` attributes) with appropriate ACLs; this is a schema change with migration considerations. The framework's KMS (or HSM-bound key per ADR-032) is a new operational dependency for password encryption. The framework's helpdesk must use the `framework-recover-laps` CLI (rather than the Jamf Pro console or the ADUC "LAPS" tab) for macOS and Linux retrieval; this is a workflow change for helpdesk staff trained on Jamf Pro.

**Neutral**. The framework's LAPS schema (`msLAPS-Password`) is invisible to end users (the local admin password is rotated transparently). The framework's rotation schedule (30 days default) is invisible to end users.

**Implementation cost**. Medium-high. Estimated 12-16 engineer-weeks for: the Windows LAPS schema support, the macOS LaunchDaemon, the Linux systemd timer, the `framework-laps-rotate` binary (cross-platform), the `framework-recover-laps` CLI, the KMS integration for password encryption, the migration paths (legacy Microsoft LAPS, Jamf Pro LAPS, Ansible), the audit logging integration, the end-to-end tests, and the documentation.

**Operational impact**. Operations teams gain a unified LAPS workflow via the `framework-recover-laps` CLI. Operations teams gain audit logging of every retrieval. Operations teams lose the per-platform LAPS consoles (Jamf Pro LAPS, ADUC LAPS tab, Ansible Vault); the framework's CLI is the unified replacement. The framework's runbook must include a "LAPS retrieval" section explaining the CLI, the audit log, and the rotation schedule configuration. The framework's Prometheus metrics let operations teams monitor rotation compliance (detect hosts that have not rotated within the expected interval).

## Alternatives Considered

**Alternative 1: Per-platform LAPS solutions (Windows LAPS for Windows, Jamf Pro LAPS for macOS, Ansible for Linux).** The framework does not implement its own LAPS; instead, it documents per-platform solutions and provides integration guides. **Rejection rationale**: This perpetuates the per-OS fragmentation that [PC-098](../catalog/09-cross-platform-parity.md#pc-098--laps-local-admin-password-rotation-has-no-macoslinux-native-equivalent) identifies as the problem. The framework's cross-platform parity commitment requires a unified LAPS-equivalent; per-platform solutions break this commitment.

**Alternative 2: Define a fresh LAPS schema (not the Windows LAPS schema).** The framework defines a fresh schema (`frameworkLAPS-Password`, `frameworkLAPS-ExpirationTime`, etc.) rather than reusing `msLAPS-Password`. **Rejection rationale**: This breaks Windows interop. Windows LAPS (built into Server 2022+) writes to `msLAPS-Password`; the framework's Windows client would have to implement a parallel schema, requiring a custom CSE instead of the built-in one. The Windows LAPS schema is JSON-based and platform-agnostic; reusing it for cross-platform storage is the right choice.

**Alternative 3: Use Apple's `com.apple.configuration.device.password.rotation` DDM declaration on macOS 14+ as the only macOS LAPS mechanism; do not ship a LaunchDaemon.** The framework does not ship a macOS LAPS agent; instead, it relies on Apple's DDM declaration (macOS 14+) for rotation. **Rejection rationale**: DDM coverage is limited (the declaration was introduced in macOS 14 and may not support all rotation scenarios — e.g. complexity requirements, history). macOS 13 and earlier do not support DDM at all; the framework's macOS 13 customers would have no LAPS mechanism. The framework's LaunchDaemon provides consistent rotation across macOS 13+ (with DDM as a future-direction replacement on macOS 14+).

## Open Questions

None. The decision is fully specified and has no Tier-1 ORQ dependency. The deferred Tier-1 question is the identity model choice (SID vs UUID, per ORQ-026/027), which affects the computer object's identifier but not the LAPS design (the local admin password is stored on the computer object regardless of identifier type).

## Cross-capability impact

- **Cross-Platform Parity** ([PC-097](../catalog/09-cross-platform-parity.md)): Disk-encryption recovery (per ADR-053) shares the directory-storage model with this ADR; both use ACL-gated retrieval of secrets from the framework directory.
- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): The directory must support the `msLAPS-*` schema with appropriate ACLs.
- **Policy Engine** ([PC-050](../catalog/04-policy-engine.md)): The Policy Engine deploys the Windows LAPS GPO and the macOS/Linux LAPS agents.
- **Operations** ([PC-106](../catalog/10-operations.md)): The audit log (per ADR-060) records every LAPS retrieval; Prometheus exporter exposes `laps_rotation_total` and `laps_retrieval_total` metrics.

## References

- [PC-098](../catalog/09-cross-platform-parity.md) — problem statement
- [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — LAPS row showing Windows native GPO, macOS MDM partial (Jamf), Linux SSSD partial (homemade), FreeIPA partial
- [docs/10-comparison-matrices/01-feature-os-matrix.md](../docs/10-comparison-matrices/01-feature-os-matrix.md) — LAPS row showing Win10/11 native, macOS Native OD ✗, macOS Enterprise MDM partial (Jamf LAPS-like), Linux SSSD partial, FreeIPA partial
- [Microsoft LAPS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) — Windows LAPS architecture and schema
- [Apple Password Rotation DDM](https://developer.apple.com/documentation/devicemanagement/managedpasswordrotation) — macOS 14+ DDM password rotation declaration
- [NIST SP 800-53 IA-5(1)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — Identifier Management control (password rotation requirement)
