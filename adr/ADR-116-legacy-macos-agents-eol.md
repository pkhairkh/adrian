---
title: "ADR-116: Legacy macOS Agents (NoMAD / Enterprise Connect / Jamf Connect / Centrify / PBIS) EOL"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-101
severity: medium
unblocked_by: [workshop-decision-11, workshop-decision-12]
tags: [adr, cross-platform-parity, macos, nomad, enterprise-connect, jamf-connect, centrify, pbis, psso, migration, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-048-psso-macos-jamf-connect-migration.md
  - ./ADR-055-legacy-agent-migration-dzdo-sudoers.md
  - ./ADR-056-psso-modern-macos-kerberos-path.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ./ADR-114-linux-identity-stack-sssd-primary.md
  - ../catalog/09-cross-platform-parity.md
  - ../workshop/decision-11-client-sdk.md
  - ../workshop/decision-12-linux-tier.md
  - ../docs/08-macos-equivalents/06-enterprise-connect-nomad.md
  - ../docs/08-macos-equivalents/07-third-party-agents-mac.md
last_updated: 2026-08-14
---

# ADR-116: Legacy macOS Agents (NoMAD / Enterprise Connect / Jamf Connect / Centrify / PBIS) EOL

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK + macOS PSSO Extension integration) and [Workshop Decision 12](../workshop/decision-12-linux-tier.md) (PBIS unsupported, Winbind deprecated). Resolves the medium-severity problem [PC-101](../catalog/09-cross-platform-parity.md) (legacy macOS agents EOL — NoMAD/Enterprise Connect, plus Centrify/PBIS/AdmitMac/DAVE per catalog PC-104). Locks the framework's `adrian-cli migrate from-{nomad,enterprise-connect,jamf-connect,centrify,pbis}` migration tooling and the framework's macOS PSSO-first strategy.

## Context

Five legacy third-party macOS AD agents predate Apple's first-party Kerberos SSO Extension (macOS 10.15+) and Platform SSO (macOS 13+):

- **Enterprise Connect** (Apple's per-user Kerberos app, deprecated in macOS 10.15 alongside the Kerberos SSO Extension introduction). Removed from macOS 10.15+; customers with Enterprise Connect must migrate to PSSO or the Kerberos SSO Extension.
- **NoMAD** (Orchard & Grove's open-source MIT-licensed menu-bar Kerberos app, EOL after Jamf acquired Orchard & Grove in May 2021). NoMAD's `com.trusourcelabs.NoMAD.plist` schema with `LocalPasswordSync = true`, `LocalPasswordSyncOnMatchOnly` flag, PAM-based password sync pre-PSSO. NoMAD Login Window (NoLoAD) is also EOL. NoMAD is community-maintained only; no commercial support.
- **Jamf Connect** (Jamf's commercial OIDC + Kerberos app, the de facto standard for Jamf-managed Macs). Two cooperating binaries: `Jamf Connect Login` (a `SecurityAgentPlugins` bundle that replaces `loginwindow:login` in `AuthorizationDB`'s `system.login.console` right with `jamf_connect_login:login`) and `Jamf Connect Menu Bar` (a user LaunchAgent at `com.jamf.connect.menubar` that maintains an OIDC refresh token in the user's keychain and optionally drives the Apple Kerberos SSO Extension for on-prem AD Kerberos). The fragile path is the password sync agent (`com.jamf.connect.sync` LaunchAgent, runs every 15 minutes by default) — see catalog PC-087 and [docs/08-macos-equivalents/06-enterprise-connect-nomad.md](../docs/08-macos-equivalents/06-enterprise-connect-nomad.md).
- **Centrify DirectControl** (now CyberArk since the 2024 acquisition, `/usr/local/share/centrifydc/bin/adjoin` + `/usr/local/share/centrifydc/sbin/adclient` + `dzdo` sudo replacement + Centrify Heimdal fork). Most invasive legacy agent; ships its own Kerberos implementation for deterministic behavior across macOS/Linux/AIX/HP-UX/Solaris. Centrify is the only actively-maintained legacy agent (under CyberArk), per [docs/08-macos-equivalents/07-third-party-agents-mac.md](../docs/08-macos-equivalents/07-third-party-agents-mac.md).
- **BeyondTrust PBIS** (formerly Likewise, deprecated macOS 2022). PBIS macOS is EOL since 2022; PBIS uses a Winbind-equivalent stack (`pam_lwidentity.so` + `libnss_lwidentity.so.2` + `lwreg` registry + bundled Kerberos). PBIS Linux is also EOL'd by BeyondTrust in 2023, per [docs/09-linux-equivalents/07-pbis-powerbroker.md](../docs/09-linux-equivalents/07-pbis-powerbroker.md).

Per [PC-101](../catalog/09-cross-platform-parity.md) (and catalog PC-104), ~10-15% of enterprise macOS deployments still run Centrify (the only actively-maintained agent); ~5% still run PBIS (deprecated); <1% still run NoMAD/AdmitMac/DAVE (maintenance-only). The framework cannot depend on these agents. Workshop Decision 11 §7 specifies the macOS integration uses the system Heimdal for PSSO Extension compatibility; Decision 12 §5 specifies PBIS is unsupported. This ADR locks the framework's macOS PSSO-first strategy (already established by [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md), [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md), and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)) and the migration tooling from each legacy agent to the framework's PSSO Extension.

## Decision

The framework's macOS strategy is **PSSO Extension (Platform SSO) first** with the framework's Client SDK providing PSSO integration (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §Platform-native integrations). All five legacy macOS agents are **explicitly deprecated by the framework** — the framework does not support, test, or interoperate with Enterprise Connect, NoMAD, Jamf Connect (with ROPG password sync), Centrify DirectControl, or PBIS. The framework ships `adrian-cli migrate from-{nomad,enterprise-connect,jamf-connect,centrify,pbis}` migration tools that detect the legacy agent's installation, translate its configuration to the framework's PSSO + Client SDK configuration, and schedule the legacy agent's removal on next reboot. PSSO Hardware_Bound mode (SEP-bound ECDSA P-256 key) is the default for Macs with T2 or Apple Silicon; Password-derived PSSO mode is the fallback for Intel Macs without T2.

**Concrete specification**:

- **PSSO Extension as the macOS authentication strategy**. The framework's macOS client uses PSSO Extension (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) and Decision 11 §7) for all Kerberos operations: TGT acquisition, TGS-REQ, ticket renewal, password change. The framework's macOS client MUST NOT install a parallel Kerberos implementation that competes with system Heimdal for ticket acquisition (per [ADR-049](./ADR-049-standardize-mit-krb5.md) and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)). The framework's macOS client MUST install the framework's MIT krb5 at `/opt/adrian/lib/mit-krb5/` (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) for framework-application Kerberos operations that do not conflict with PSSO (e.g. service-side Kerberos for framework-hosted SMB shares, keytab management for framework service principals). The framework's macOS client MUST use the `adrian-kerberos-sync` daemon (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) to synchronize PSSO-acquired tickets to the framework's MIT cache.

- **PSSO MDM profile template**. The framework ships an MDM profile template for `com.apple.configuration-ext.platform-sso` and `com.apple.KerberosSSO` (per catalog PC-086 §Constraints). The profile is distributed via the framework's MDM integration (the framework's macOS client auto-configures PSSO on first enrollment via `sso_util configure -a kerberos -r <REALM> -u <user>`). The profile's `AuthenticationMethod` is `Hardware_Bound` for Macs with T2 or Apple Silicon (the default), `Password` for Intel Macs without T2 (the fallback). The profile's `PlatformSSOProfile` is `User` (per-user PSSO, not device-wide). The profile's `TokenToUserSharing` is `Enable` (the framework's macOS client uses the PSSO token for IdP auth). The profile's `UseSharedDeviceKey` is `true` (a single device key for all users on the Mac, simplifying key management). The profile's `AuthenticationClient` is `{ Type: Kerberos, Realm: <framework-realm> }`.

- **`adrian-cli migrate from-enterprise-connect`** migration tool:
  - Detects Enterprise Connect's `com.apple.Enterprise-Connect` MDM payload presence (via `profiles -C` output).
  - Reads the Enterprise Connect configuration (realm, username, password sync settings).
  - Generates the framework's `com.apple.configuration-ext.platform-sso` MDM profile with equivalent settings.
  - Installs the framework's PSSO profile via `profiles -I -F <profile.mobileconfig>`.
  - Schedules Enterprise Connect's removal on next reboot (via `launchctl bootout system/com.apple.EnterpriseConnect` and `rm -rf /Applications/Enterprise\ Connect.app`).
  - Verifies PSSO configuration via `sso_util cache -l` (PSSO ticket cache should be populated after the user's next login).

- **`adrian-cli migrate from-nomad`** migration tool:
  - Detects NoMAD's `com.trusourcelabs.NoMAD.plist` presence (in `~/Library/Preferences/`).
  - Reads the NoMAD configuration (realm, username, `LocalPasswordSync` flag).
  - Generates the framework's `com.apple.configuration-ext.platform-sso` MDM profile with equivalent settings.
  - Installs the framework's PSSO profile via `profiles -I -F <profile.mobileconfig>`.
  - Schedules NoMAD's removal on next reboot (via `launchctl bootout gui/$(id -u)/com.trusourcelabs.NoMAD` and `rm -rf /Applications/NoMAD.app`).
  - Removes NoMAD Login Window (NoLoAD) if present (via `rm -rf /Library/Security/SecurityAgentPlugins/NoMADLogin` and restoration of `AuthorizationDB`'s `system.login.console` right to `loginwindow:login`).
  - Verifies PSSO configuration via `sso_util cache -l`.

- **`adrian-cli migrate from-jamf-connect`** migration tool (per [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md)):
  - Detects Jamf Connect's `com.jamf.connect.login.plist` presence (in `/Library/Preferences/`).
  - Reads the Jamf Connect configuration (IdP client ID, IdP authorize URL, Kerberos realm, ROPG password sync flag).
  - Generates the framework's `com.apple.configuration-ext.platform-sso` MDM profile with the Kerberos sub-payload (per catalog PC-086).
  - Translates Jamf Connect's OIDC `client_id` to the framework's `AuthenticationClient.OAuth.ClientID` (if the customer wants to continue using their existing OIDC IdP alongside the framework's PSSO).
  - Installs the framework's PSSO profile via `profiles -I -F <profile.mobileconfig>`.
  - Schedules Jamf Connect's removal on next reboot (via `launchctl bootout system/com.jamf.connect.login` and `rm -rf /Library/Security/SecurityAgentPlugins/JamfConnectLogin.bundle` and `launchctl bootout gui/$(id -u)/com.jamf.connect.menubar` and `rm -rf /Applications/Jamf\ Connect.app`).
  - Restores `AuthorizationDB`'s `system.login.console` right to `loginwindow:login` (or to the framework's PSSO login mechanism if PSSO Hardware_Bound mode is enabled).
  - Verifies PSSO configuration via `sso_util cache -l`.
  - Handles the FileVault recovery scenario: if the user is locked out of FileVault (because the Jamf Connect ROPG password sync diverged from the IdP password), the framework's migration tool supports a recovery key escrow flow that re-derives the FileVault key from a helpdesk-issued token (per catalog PC-087 §Constraints and [ADR-053](./ADR-053-key-escrow-and-nbde.md)).

- **`adrian-cli migrate from-centrify`** migration tool:
  - Detects Centrify DirectControl's `/usr/local/share/centrifydc/bin/adjoin` or `/usr/local/share/centrifydc/sbin/adclient` presence.
  - Reads the Centrify configuration from `/etc/centrifydc/centrifydc.conf` (INI format) — extracts `CENTRIFYDC_DOMAIN`, `CENTRIFYDC_KRB5_REALM`, `CENTRIFYDC_ZONE`, `ADCLIENT_USER_IGNORE`, `ADCLIENT_GROUP_IGNORE`.
  - Reads the Centrify-managed `dzdo` rules (Centrify's AD-stored RBAC rules in `dzdoCommandRights`/`dzdoRole` auxiliary classes on AD user/group objects) — the migration tool queries the framework's directory (which has the Centrify-augmented schema if the customer was previously Centrify-managed) for these rules.
  - Translates the `dzdo` rules to `/etc/sudoers.d/centrify-migrated` files (per [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md)) — `dzdoCommandRights` becomes `Cmnd_Alias`, `dzdoRole` becomes `User_Alias` + `Runas_Alias` + `Defaults`, the `dzdo` allow/deny rules become `sudoers` `+`/`-` rules.
  - Generates the framework's `com.apple.configuration-ext.platform-sso` MDM profile with the Kerberos sub-payload.
  - Installs the framework's PSSO profile via `profiles -I -F <profile.mobileconfig>`.
  - Schedules Centrify's removal on next reboot (via `launchctl bootout system/com.centrify.adclient` and `rm -rf /usr/local/share/centrifydc/`).
  - Verifies PSSO configuration via `sso_util cache -l` and `sudo -l` (the migrated sudoers rules should be active).

- **`adrian-cli migrate from-pbis`** migration tool (macOS variant of the Linux `from-pbis` tool per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md) §PBIS unsupported):
  - Detects PBIS's `/opt/pbis/bin/domainjoin-cli` or `/opt/pbis/sbin/lwsmd` presence.
  - Reads the PBIS configuration from `/opt/pbis/config/reg.dat` (TDB registry, parsed via `lwreg` command-line tool).
  - Translates the PBIS configuration to the framework's PSSO + Client SDK configuration.
  - Generates the framework's `com.apple.configuration-ext.platform-sso` MDM profile.
  - Installs the framework's PSSO profile via `profiles -I -F <profile.mobileconfig>`.
  - Schedules PBIS's removal on next reboot (via `launchctl bootout system/com.pbis.lwsmd` and `rm -rf /opt/pbis/`).
  - Verifies PSSO configuration via `sso_util cache -l`.

- **`adrian-cli migrate from-{admitmac,dave}`** migration tool:
  - Detects AdmitMac's `/Library/Filesystems/AdmitMac.fs/` kernel extension presence (legacy, kext-based — deprecated since macOS 11) and Thursby DAVE's `/Library/Filesystems/DAVE.fs/` kernel extension presence (legacy, SMB-client-only — predates SMBX).
  - For AdmitMac: removes the AdmitMac kernel extension (via `kextunload -b com.thursby.AdmitMac` and `rm -rf /Library/Filesystems/AdmitMac.fs/`) and translates AdmitMac AD auth to the framework's PSSO Extension (per the Enterprise Connect migration path).
  - For DAVE: removes the DAVE kernel extension (via `kextunload -b com.thursby.DAVE` and `rm -rf /Library/Filesystems/DAVE.fs/`); SMB client functionality is now provided by macOS native SMBX (since macOS 10.14), so no further migration is needed for SMB.
  - Verifies PSSO configuration via `sso_util cache -l`.

- **Rust crates**:
  - `clap = "4"` (CLI argument parsing)
  - `tokio = "1"` (async runtime)
  - `serde = "1"` + `serde_json = "1"` (configuration parsing and generation)
  - `plist = "1"` (macOS plist parsing for NoMAD, Jamf Connect, PSSO profile generation)
  - `ini = "1"` (Centrify `centrifydc.conf` INI parsing)
  - `tdb = "0.1"` (PBIS `reg.dat` TDB parsing — pure-Rust TDB reader)
  - `objc2 = "0.5"` + `core-foundation = "0.10"` (macOS framework integration — `AuthorizationDB` right restoration, `sso_util` invocation)
  - `tracing = "0.1"` (structured logging)

- **Audit logging**: every `migrate from-{nomad,enterprise-connect,jamf-connect,centrify,pbis,admitmac,dave}` operation emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "sdk_macos_migration_op"`, `op` (`detect`/`translate_config`/`install_psso_profile`/`schedule_removal`/`verify`), `legacy_agent` (`enterprise_connect`/`nomad`/`jamf_connect`/`centrify`/`pbis`/`admitmac`/`dave`), `result`, `platform = "macos"`.

## Rationale

The choice to standardize on PSSO Extension as the macOS authentication strategy is forced by Apple's direction (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) §Rationale). Apple introduced PSSO in macOS 13 (Ventura, October 2022) as the first-party passwordless path; the system Heimdal underpins PSSO and cannot be replaced without breaking PSSO. The framework's macOS strategy (per [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md) and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)) is PSSO-first; this ADR documents the migration tooling from each legacy agent to PSSO. Legacy patterns (Enterprise Connect, NoMAD, Jamf Connect with ROPG, Centrify, PBIS, AdmitMac, DAVE) are deprecated by their respective vendors; the framework's documentation aligns with the vendor trajectory.

The choice to deprecate Jamf Connect with ROPG password sync (rather than supporting it as an alternative to PSSO) is forced by the FileVault lockout problem documented in catalog PC-087. Jamf Connect's `com.jamf.connect.sync` LaunchAgent runs every 15 minutes by default, syncing the local ShadowHash with the IdP password via ROPG. During the divergence window — between the IdP password change and the user entering the new password in Jamf Connect — FileVault unlock uses the OLD password (because FileVault unlock happens at boot, before the user session starts and before the sync agent runs). If the user has forgotten the old password (because they changed it remotely), they are locked out of FileVault. PSSO Hardware_Bound mode eliminates this problem entirely by using SEP-bound keys for IdP auth (no password sync needed because the SEP key never changes on password rotation). The framework's migration tooling detects Jamf Connect deployments and migrates them to PSSO Hardware_Bound mode (or Password-derived mode for Intel Macs without T2, with the FileVault recovery scenario handled by the framework's recovery key escrow flow per [ADR-053](./ADR-053-key-escrow-and-nbde.md)).

The choice to deprecate Centrify DirectControl (the only actively-maintained legacy agent under CyberArk) is forced by the framework's "do not depend on third-party agents" posture. Centrify ships its own Kerberos implementation (Centrify Heimdal fork) for deterministic behavior across macOS/Linux/AIX/HP-UX/Solaris; this conflicts with the framework's MIT krb5 standardization (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) and with PSSO Extension's use of system Heimdal. Centrify's `dzdo` sudo replacement (with AD-stored RBAC rules in `dzdoCommandRights`/`dzdoRole` auxiliary classes) is a feature gap that the framework closes by migrating `dzdo` rules to standard `/etc/sudoers.d/` files (per [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md)). Customers who require Centrify's cross-platform RBAC (macOS/Linux/AIX/HP-UX/Solaris) can continue to use Centrify alongside the framework, but the framework does not test or support this configuration.

The choice to deprecate PBIS on macOS (per Decision 12 §5) is forced by BeyondTrust's 2022 EOL of PBIS macOS. PBIS uses a Winbind-equivalent stack that the framework's SSSD-primary strategy (per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md)) replaces on Linux; on macOS, the framework's PSSO Extension replaces PBIS. The migration tooling reuses the Linux `adrian-cli migrate from-pbis` logic (per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md) §PBIS unsupported) for the configuration translation, with macOS-specific PSSO profile generation.

The choice to deprecate AdmitMac and DAVE is forced by their maintenance-only status. AdmitMac is a kernel-extension-based SMB/Kerberos stack that predates Apple's AD plug-in; macOS native SMBX (since macOS 10.14) replaces AdmitMac's SMB client functionality, and PSSO Extension replaces AdmitMac's AD auth. DAVE is a kernel-extension-based SMB-client-only stack that predates SMBX; macOS native SMBX replaces DAVE's SMB client functionality entirely. The migration tooling removes the AdmitMac and DAVE kernel extensions (via `kextunload` and `rm -rf`); no further configuration translation is needed.

## Consequences

**Positive**. The framework gains a single macOS authentication strategy (PSSO Extension first), aligning with Apple's direction and reducing the framework's support surface. The migration tooling (`adrian-cli migrate from-{nomad,enterprise-connect,jamf-connect,centrify,pbis,admitmac,dave}`) automates the painful migration from each legacy agent, reducing the per-Mac migration time from ~2 hours to ~15 minutes. The FileVault lockout problem (catalog PC-087) is eliminated for migrated Macs (PSSO Hardware_Bound mode does not require password sync). The `dzdo` rules migration (per [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md)) preserves Centrify customers' RBAC investment in standard `sudoers` files. The framework's macOS posture is consistent with the framework's Windows and Linux posture (PSSO on macOS, LSA on Windows, SSSD on Linux).

**Negative**. Customers with existing Centrify deployments that require Centrify's cross-platform RBAC (macOS/Linux/AIX/HP-UX/Solaris) must continue to run Centrify alongside the framework; the framework does not test or support this configuration. Customers with existing Jamf Connect deployments that use Jamf Connect's OIDC ROPG for non-MDM Macs (where PSSO cannot be MDM-configured) must accept the password sync fragility for that subset or migrate those Macs to MDM enrollment. The framework's PSSO Hardware_Bound mode requires T2 or Apple Silicon; Intel Macs without T2 fall back to Password-derived PSSO mode (still fragile) or are documented as out of scope for passwordless.

**Neutral**. The framework's macOS posture is invisible to end users (they see PSSO, not the migration tooling). The framework's macOS posture is invisible to platform-native applications (OpenDirectory, Authorization framework continue to work alongside the framework's SDK). The framework's macOS posture is visible to operators (they run `adrian-cli migrate from-{nomad,enterprise-connect,jamf-connect,centrify,pbis}` to migrate existing deployments).

**Implementation cost**. ~8 person-weeks. Breakdown: PSSO MDM profile template generation (1 pw), `adrian-cli migrate from-enterprise-connect` (0.5 pw), `adrian-cli migrate from-nomad` (1 pw, including NoLoAD restoration), `adrian-cli migrate from-jamf-connect` (2 pw, including OIDC client ID translation and FileVault recovery), `adrian-cli migrate from-centrify` (2 pw, including `dzdo` rules translation per [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md)), `adrian-cli migrate from-pbis` macOS variant (0.5 pw, reusing the Linux tooling logic per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md)), `adrian-cli migrate from-{admitmac,dave}` (0.5 pw, kernel extension removal only), audit logging integration (0.5 pw).

**Operational impact**. Operations teams gain automated migration tooling for legacy macOS agents. Operations teams must understand PSSO Extension (the runbook includes a "PSSO troubleshooting" section). Operations teams gain unified audit logging of migration operations (`sdk_macos_migration_op` event type). Operations teams lose the ability to use Centrify's `dzdo` cross-platform RBAC (the framework's `sudoers` migration is macOS/Linux-only; AIX/HP-UX/Solaris customers must continue to use Centrify on those platforms).

## Alternatives Considered

**Alternative 1: Support Jamf Connect as an alternative to PSSO.** The framework's macOS client integrates with Jamf Connect (rather than PSSO) for customers who prefer Jamf Connect's OIDC ROPG flow. **Rejection rationale**: Jamf Connect's ROPG password sync has the FileVault lockout problem documented in catalog PC-087; PSSO Hardware_Bound mode eliminates this problem. Apple's direction is PSSO; Jamf Connect's own documentation recommends PSSO Hardware_Bound mode for Jamf Connect deployments on macOS 13+. The framework's macOS strategy aligns with Apple's direction.

**Alternative 2: Support Centrify DirectControl as an alternative to PSSO.** The framework's macOS client integrates with Centrify DirectControl for customers who require Centrify's cross-platform RBAC. **Rejection rationale**: Centrify ships its own Kerberos implementation (Centrify Heimdal fork) that conflicts with the framework's MIT krb5 standardization (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) and with PSSO Extension's use of system Heimdal. Centrify's `dzdo` rules are migrated to standard `sudoers` files (per [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md)) for macOS/Linux; AIX/HP-UX/Solaris customers continue to use Centrify on those platforms (the framework does not support AIX/HP-UX/Solaris in v1).

**Alternative 3: Document legacy macOS agents as out of scope without migration tooling.** The framework does not provide migration tooling for legacy macOS agents; customers must manually migrate. **Rejection rationale**: Manual migration is error-prone and time-consuming (~2 hours per Mac); the framework's automated tooling reduces this to ~15 minutes per Mac. Without automated tooling, customers with existing Centrify/Jamf Connect/PBIS deployments are locked into those agents, blocking framework adoption.

## Open Questions

None. The decision is fully specified by Decision 11 §7 (macOS PSSO integration), Decision 12 §5 (PBIS unsupported), [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md) (Jamf Connect migration), [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md) (`dzdo` rules migration), and [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) (PSSO modern macOS Kerberos path). The implementation details (PSSO MDM profile schema, `dzdo` rules translation) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The framework's macOS client uses PSSO Extension (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §Platform-native integrations).
- **Client SDK** ([PC-086](../catalog/08-client-sdk.md)): PSSO Extension is the macOS Kerberos path (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)).
- **Cross-Platform Parity** ([PC-094](../catalog/09-cross-platform-parity.md)): The framework's macOS NTLM client (`adrian-ntlm-client` per [ADR-112](./ADR-112-macos-ntlm-client-rust-crate.md)) closes the macOS NTLM gap left by the legacy agents' removal.
- **Cross-Platform Parity** ([PC-099](../catalog/09-cross-platform-parity.md)): PBIS macOS migration reuses the Linux `adrian-cli migrate from-pbis` tooling logic (per [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md)).
- **Cert Service** (Decision 8): The framework's macOS client uses `adrian-cert-agent` for cert enrollment (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §Cert enrollment), replacing Centrify's `certmonger`-equivalent.
- **File Gateway** (Decision 10): The framework's macOS SMB client uses native SMBX (since macOS 10.14), replacing AdmitMac/DAVE's kernel-extension-based SMB clients.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): The `adrian-cli migrate from-{nomad,enterprise-connect,jamf-connect,centrify,pbis,admitmac,dave}` tools are the macOS migration entry points.

## References

- [PC-101](../catalog/09-cross-platform-parity.md) — problem statement (legacy macOS agents EOL — NoMAD/Enterprise Connect)
- [PC-104](../catalog/09-cross-platform-parity.md) — Centrify / PBIS / AdmitMac / DAVE are legacy third-party macOS agents
- [PC-087](../catalog/08-client-sdk.md) — macOS Jamf Connect + ROPG password sync is fragile during IdP password change
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings (macOS PSSO integration)
- [Workshop Decision 12 — Linux Tier](../workshop/decision-12-linux-tier.md) — PBIS unsupported
- [docs/08-macos-equivalents/06-enterprise-connect-nomad.md](../docs/08-macos-equivalents/06-enterprise-connect-nomad.md) — Enterprise Connect and NoMAD internals, PAM-based password sync pre-PSSO
- [docs/08-macos-equivalents/07-third-party-agents-mac.md](../docs/08-macos-equivalents/07-third-party-agents-mac.md) — Centrify DirectControl, PBIS macOS, Thursby AdmitMac, Thursby DAVE
- [ADR-048](./ADR-048-psso-macos-jamf-connect-migration.md) — PSSO macOS Jamf Connect migration
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization (macOS framework-application Kerberos at `/opt/adrian/lib/mit-krb5/`)
- [ADR-053](./ADR-053-key-escrow-and-nbde.md) — key escrow (FileVault recovery key escrow)
- [ADR-055](./ADR-055-legacy-agent-migration-dzdo-sudoers.md) — `dzdo` rules migration to `sudoers`
- [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) — PSSO modern macOS Kerberos path
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [ADR-114](./ADR-114-linux-identity-stack-sssd-primary.md) — Linux identity stack (PBIS unsupported)
- [Apple Platform SSO Documentation](https://support.apple.com/guide/deployment/platform-sso-dep7a0ced6d7/1/web/1.0) — Apple PSSO reference
- [Jamf Connect Documentation](https://docs.jamf.com/jamf-connect/) — Jamf Connect reference
- [Centrify DirectControl Documentation](https://docs.cyberark.com/Product-Doc/OnlineHelp/centrify/) — Centrify reference
- [plist Rust crate](https://docs.rs/plist) — macOS plist parsing
- [objc2 Rust crate](https://docs.rs/objc2) — macOS framework bindings
