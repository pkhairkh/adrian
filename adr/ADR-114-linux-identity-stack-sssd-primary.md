---
title: "ADR-114: Linux Identity Stack — SSSD Primary, Winbind Deprecated, PBIS Unsupported"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-099
severity: medium
unblocked_by: [workshop-decision-12]
tags: [adr, cross-platform-parity, linux, sssd, winbind, pbis, authselect, migration, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-050-authselect-standard-pam.md
  - ./ADR-051-kcm-linux-api-macos-cache-abstraction.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ./ADR-110-sid-to-uid-mapping-uuid-primary.md
  - ../catalog/09-cross-platform-parity.md
  - ../workshop/decision-12-linux-tier.md
  - ../docs/09-linux-equivalents/04-winbind-internals.md
  - ../docs/09-linux-equivalents/07-pbis-powerbroker.md
last_updated: 2026-08-14
---

# ADR-114: Linux Identity Stack — SSSD Primary, Winbind Deprecated, PBIS Unsupported

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 12](../workshop/decision-12-linux-tier.md) (SSSD primary + FreeIPA alt + Winbind deprecated + PBIS unsupported). Resolves the medium-severity problem [PC-099](../catalog/09-cross-platform-parity.md) (SSSD/Winbind/PBIS are alternative Linux stacks; migration between them is painful). Locks the `adrian-cli migrate from-{winbind,pbis}` migration tooling and the framework's SSSD-primary reference deployment configuration.

## Context

The Linux identity stack for AD integration has three competing alternatives. SSSD (`sssd-ad` provider) is the modern preferred stack, default in RHEL 6+ (2010), Ubuntu 16.04+, SUSE 12+. Winbind (Samba's `winbindd` daemon, used as a PAM/NSS provider for AD integration on Linux) is the legacy stack, deprecated by Red Hat in RHEL 6 (2010) in favor of SSSD, but still in use in some Samba-heavy deployments where `smbd` is running. BeyondTrust PBIS (formerly Likewise, deprecated macOS 2022, deprecated Linux 2014 open-source) is the commercial stack, EOL'd by BeyondTrust in 2023. The three stacks have different PAM/NSS modules (`pam_sss.so` + `libnss_sss.so.2` vs `pam_winbind.so` + `libnss_winbind.so.2` vs `pam_lwidentity.so` + `libnss_lwidentity.so.2`), different ID mapping algorithms (SSSD's `ldap_id_mapping` slice algorithm vs Winbind's `idmap_rid`/`idmap_autorid` vs PBIS's range-based mapping), different Kerberos implementations (SSSD uses MIT krb5; Winbind uses Samba's bundled Heimdal; PBIS uses its own bundled Kerberos), and different machine-account password rotation models (SSSD via `adcli`; Winbind via `net ads changetrustpw`; PBIS via `lwreg` registry), per [docs/09-linux-equivalents/04-winbind-internals.md](../docs/09-linux-equivalents/04-winbind-internals.md) and [docs/09-linux-equivalents/07-pbis-powerbroker.md](../docs/09-linux-equivalents/07-pbis-powerbroker.md).

Per [PC-099](../catalog/09-cross-platform-parity.md), migration between the three stacks is painful: an Ansible role that configures PAM for SSSD will not work on a Winbind host without per-stack conditionals; the ID mapping differs (SSSD's slice algorithm produces different UIDs than Winbind's `idmap_rid` for the same AD user, requiring `chown -R --from=<olduid> <newuid>` sweeps over `/home` and shared filesystems); the machine-account password rotation differs (SSSD's `adcli` writes to `/etc/krb5.keytab`, Winbind's `net ads changetrustpw` writes to `/var/lib/samba/secrets.tdb`, PBIS's `lwreg` writes to `/opt/pbis/config/reg.dat`); the Kerberos cache type differs (SSSD prefers KCM, Winbind prefers KEYRING, PBIS prefers its own cache type). Quantified: a typical enterprise migration from Winbind to SSSD takes ~4 hours per host (configuration translation, UID remapping, machine-account password rotation, PAM/NSS module swap, testing), and ~5-10% of users experience UID-mismatch issues requiring additional `chown` sweeps.

Workshop Decision 12 ([workshop/decision-12-linux-tier.md](../workshop/decision-12-linux-tier.md)) resolved the gating ORQs ORQ-202/203 in favor of: SSSD as the primary Linux integration (with Rust-based enhancements via the framework's Client SDK); FreeIPA as a supported alternative; Winbind deprecated (migration path to SSSD); PBIS unsupported (already EOL by BeyondTrust). This ADR locks the concrete SSSD-primary reference deployment configuration, the `adrian-cli migrate from-{winbind,pbis}` migration tooling, and the framework's `adrian-sssd-gpo` Rust library that extends SSSD's GPO access-control coverage (per Decision 12 §2).

## Decision

The framework's Linux tier strategy is: **SSSD as the primary Linux integration** (with Rust-based enhancements via the framework's Client SDK); **FreeIPA as a supported alternative** for customers who want a full Linux domain controller (covered in [ADR-115](./ADR-115-freeipa-as-alternative-linux-tier.md)); **Winbind is deprecated** (migration path to SSSD via `adrian-cli migrate from-winbind`); **PBIS is unsupported** (already EOL by BeyondTrust, migration path via the same `adrian-cli migrate from-winbind` tooling since PBIS uses a Winbind-equivalent stack).

**Concrete specification**:

- **SSSD-primary reference deployment configuration**. The framework's `adrian-cli join` command (per Decision 11 §9 and Decision 12 §1) generates `/etc/sssd/sssd.conf` with the framework's recommended settings on Linux:
  - `domains = adrian`, `config_file_version = 2`, `services = nss, pam, ifp` (the `ifp` InfoPipe responder is used by the SDK for fast user/group lookups via D-Bus).
  - `[domain/adrian]`: `id_provider = ad`, `auth_provider = ad`, `chpass_provider = ad`, `access_provider = ad` (expanded per §2 below for the framework's enhanced GPO access), `ldap_schema = ad`, `ldap_uri = ldap://<dc>.<domain>`, `krb5_server = <dc>.<domain>`, `krb5_realm = <REALM>`, `ad_domain = <domain>`, `ad_server = <dc>.<domain>`.
  - `use_fully_qualified_names = false` (the framework's directory uses short names by default; operators can opt-in to FQDNs).
  - `fallback_homedir = /home/%u`, `default_shell = /bin/bash`.
  - `ldap_id_mapping = false` (the framework's directory uses POSIX UIDs/GIDs directly per Decision 3 §POSIX UID/GID mapping; SSSD's id-mapping is disabled per Decision 12 §10).
  - `ldap_user_principal = nosuchattr` (the framework's directory does not expose `userPrincipalName` for SSSD's principal-extraction).
  - `dyndns_update = true`, `dyndns_ttl = 3600` (SSSD updates DNS for the host on join, per the framework's DNS strategy).
  - `krb5_ccachedir = /run/user/%u`, `krb5_ccname_template = KCM:%u` (KCM cache per [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) and [ADR-111](./ADR-111-unified-ticket-cache-abstraction.md)).
  - `gpo_access_enforcement = permissive` (default; see §2 for the framework's enhanced GPO access-control via `adrian-sssd-gpo`).
  - The framework's `adrian-cli join` runs `authselect select adrian-with-sudo --force` (per [ADR-050](./ADR-050-authselect-standard-pam.md) and Decision 12 §9) to switch PAM/NSS to the framework's `authselect` profile (which uses `pam_adrian.so` per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §PAM/NSS provider as primary, with `pam_sss.so` as fallback for SSSD-primary compatibility).

- **Rust-based SSSD GPO access-control enhancements** (`adrian-sssd-gpo` library, per Decision 12 §2). The framework ships `adrian-sssd-gpo` — a Rust library that extends SSSD's GPO access-control to cover the full `Security` PolicyArea (per Decision 7's PolicyArea enum). The library is loaded by SSSD via the `gpo_access_provider = adrian` configuration directive (a new SSSD access provider that the framework contributes upstream to SSSD). The library implements:
  - `adrian_access_check(user, host, policy_doc) -> AccessDecision` — evaluates the policy's `Security` area against the user and host, returning `Allow`, `Deny`, or `PermitWithLogonHours`.
  - `LogonHours` enforcement — the framework's `Security` area's `PermitLogonHours` setting is enforced by the library, replacing SSSD's lack of logon-hours support.
  - `HostAccessControl` (HAC) — the framework's `Security` area's `PermitHosts` setting is enforced by the library, replacing SSSD's lack of host-based access control (other than via `simple` access provider's `simple_allow_hosts`).
  - `GroupPolicyAccessControl` — the framework's `Security` area's `PermitGroups` setting is enforced by the library, replacing SSSD's `simple_allow_groups`.
  - The library uses the framework's Client SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)) to fetch the policy document via the WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)) instead of SSSD's existing GPO-fetch-over-SMB path; this gives the library real-time policy updates (vs. SSSD's 90-minute background refresh). The library is ~2K lines of Rust, exposed to SSSD via a C ABI (`libadrian_sssd_gpo.so`).

- **Winbind deprecation migration tooling** (`adrian-cli migrate from-winbind`). The framework's `adrian-cli migrate from-winbind` command:
  - Reads the existing `/etc/samba/smb.conf` (extracting `idmap config * : backend`, `idmap config * : range`, `idmap config <domain> : backend`, `idmap config <domain> : range`, `workgroup`, `realm`, `security`, `kerberos method` settings).
  - Reads the existing `/etc/krb5.conf` (extracting `[realms]`, `[domain_realm]`, `[capaths]` sections).
  - Reads the existing `/etc/nsswitch.conf` (extracting `passwd:`, `group:`, `shadow:` lines to identify the current NSS source: `winbind`).
  - Reads the existing `/etc/pam.d/` files (extracting `pam_winbind.so` lines).
  - Reads the existing `/var/lib/samba/secrets.tdb` (extracting the machine-account password via `tdbdump`, with `SecretsKey` derivation per Samba's `secrets.tdb` format).
  - Computes the existing UID/GID assignments from `idmap_tdb` or `idmap_autorid` (depending on the `idmap config * : backend` setting) — for each AD user with an existing UID, the migration tool writes the existing UID to the framework's directory as `uidNumber` (per Decision 3 §POSIX UID/GID mapping and [ADR-110](./ADR-110-sid-to-uid-mapping-uuid-primary.md)).
  - Generates `/etc/sssd/sssd.conf` with the equivalent settings (translating Winbind's `idmap` configuration to SSSD's `ldap_id_mapping = false` since the framework's directory uses POSIX UIDs/GIDs directly, but the translation preserves existing UID/GID assignments via the framework's id-mapping migration tooling per Day 1 identity-model decision).
  - Generates the new `/etc/krb5.conf` for the framework's KDC (per [ADR-049](./ADR-049-standardize-mit-krb5.md) and [ADR-111](./ADR-111-unified-ticket-cache-abstraction.md)).
  - Runs `authselect select adrian-with-sudo --force` (per [ADR-050](./ADR-050-authselect-standard-pam.md) and Decision 12 §9) to switch PAM/NSS to the framework's `authselect` profile.
  - Restarts `sssd.service` and disables `winbind.service`.
  - Verifies that `getent passwd <user>` returns the same UID as before the migration (otherwise, the migration tool aborts and rolls back).
  - The tool does NOT uninstall Samba (Samba may still be needed for SMB-client functionality via `smbclient`); only `winbindd` as a PAM/NSS provider is deprecated. Customers who need Winbind for legacy reasons (e.g., NTLM-only appliances per [ADR-112](./ADR-112-macos-ntlm-client-rust-crate.md)) can continue to use it, but the framework does not test or support Winbind configurations.

- **PBIS unsupported**. BeyondTrust PBIS (formerly Likewise) is unsupported. PBIS was EOL'd by BeyondTrust in 2023; the framework's documentation explicitly lists PBIS as unsupported and recommends the same `adrian-cli migrate from-winbind` path for PBIS-to-SSSD migration (PBIS uses a Winbind-equivalent PAM/NSS stack — `pam_lwidentity.so` + `libnss_lwidentity.so.2` — that can be migrated via the same tooling, with the `lwreg` registry at `/opt/pbis/config/reg.dat` providing the machine-account password and the existing UID/GID assignments). The migration tool detects PBIS installations (via the presence of `/opt/pbis/bin/domainjoin-cli` or `/opt/pbis/sbin/lwsmd`) and translates the PBIS-specific configuration to the SSSD-primary configuration.

- **`authselect` profile** (`adrian-with-sudo`, per [ADR-050](./ADR-050-authselect-standard-pam.md) and Decision 12 §9). The framework ships a custom `authselect` profile that configures PAM to use `pam_adrian.so` (the framework's PAM module per [ADR-107](./ADR-107-unified-rust-core-sdk.md)) for authentication and `pam_sss.so` (SSSD's PAM module) as a fallback (for compatibility during migration). The profile also configures `pam_sudo.so` for sudo via SSSD's sudo rules (or the framework's `Security` PolicyArea's `Sudoers` setting, per Decision 7). The framework's `adrian-cli join` runs `authselect select adrian-with-sudo --force` to apply the profile. Debian and SUSE do not ship `authselect` by default; the framework's Linux installer detects the distro and uses `pam-auth-update` (Debian) or `pam-config` (SUSE) as fallbacks (per Decision 12 §11 distro-detection pattern).

- **POSIX UID/GID assignment** (per Decision 12 §10 and [ADR-110](./ADR-110-sid-to-uid-mapping-uuid-primary.md)). The framework's directory uses POSIX UIDs/GIDs directly (assigned by the directory at user/group creation time), not SSSD's id-mapping (which derives UIDs/GIDs from Windows SIDs via a slice algorithm). SSSD's `ldap_id_mapping = false` setting reflects this. The framework's `adrian-cli migrate from-ad` command preserves existing UIDs/GIDs during migration (via the framework's id-mapping migration tooling that reads the existing AD `uidNumber`/`gidNumber` attributes and writes them to the framework's directory). Customers who used SSSD's id-mapping in their existing AD deployment can choose to either (a) preserve the id-mapped UIDs/GIDs (the framework writes the id-mapped values to `uidNumber`/`gidNumber` in its directory, so SSSD's id-mapping is no longer needed) or (b) reassign UIDs/GIDs (the framework generates new UIDs/GIDs, requiring a file-system UID/GID migration). Option (a) is the default; option (b) is for customers who want to consolidate UID/GID ranges.

- **Container-native Linux deployment** (per Decision 12 §11). The framework's DCs run as containers on Kubernetes (per [ADR-058](./ADR-058-container-native-dcs-operator.md)). The framework's Linux client (SSSD + Client SDK) runs as a DaemonSet on every Kubernetes node that hosts framework-aware pods; framework-aware pods mount the SSSD socket (`/var/run/secrets/adrian/sssd.sock`) and the KCM socket (`/var/run/secrets/adrian/kcm.sock`) as volumes, and `pam_adrian.so` / `nss_adrian.so.2` are available in the pod's container image (via a shared base image `adrian-base:1.0` that includes the framework's PAM/NSS modules and the Rust core library). Framework-unaware pods (third-party images) can use SSSD's `infopipe` D-Bus interface for user/group lookups without the framework's PAM/NSS modules in the image.

- **Rust crates** (per Decision 12 §Rust implementation implications):
  - `adrian-sssd-gpo` (workspace member, `cdylib`) — the SSSD GPO access-control enhancement library. Crates: `tokio = "1"`, `serde = "1"`, `serde_json = "1"`, `ldap3 = "0.11"`, `adrian-sdk` (for policy retrieval via WebSocket push per [ADR-028](./ADR-028-push-based-policy-websocket.md)), `tracing = "0.1"`. ~2K lines of Rust.
  - `adrian-cli migrate-from-winbind` (workspace member, subcommand of `adrian-cli`) — the Winbind-to-SSSD migration tool. Crates: `clap = "4"`, `tokio`, `serde`, `serde_json`. ~800 lines of Rust.
  - `adrian-authselect-profile` (workspace member, data) — the `adrian-with-sudo` authselect profile (a set of PAM/NSS configuration files, not Rust).
  - `adrian-base-container` (workspace member, container image) — the shared base image for framework-aware Kubernetes pods.

## Rationale

The choice to standardize on SSSD as the primary Linux integration is forced by Decision 12 §Rationale §Candidate B rejection. SSSD is the de facto standard for Linux-AD integration, with a large operator community, extensive documentation, and broad distro support (RHEL, Ubuntu, SUSE, Debian all ship SSSD). Customers expect SSSD as the Linux integration path; requiring them to use the framework's PAM/NSS modules exclusively is a non-starter for adoption. SSSD's `ifp` (InfoPipe) responder provides D-Bus-based user/group lookups that the framework's SDK can consume (per Decision 12 §1), avoiding the need to re-implement SSSD's caching, offline support, and `be_ptask` scheduler. SSSD's `ad` provider is mature, with extensive testing against AD; the framework's directory is AD-compatible (per Day 1 schema decision), so SSSD's `ad` provider works against the framework's directory with minimal configuration.

The choice to deprecate Winbind (rather than supporting it) is forced by Decision 12 §Rationale §Candidate C rejection. Winbind is a Samba component, and the framework does not adopt Samba (per Decision 10's rejection of Samba's `smbd`). Using `winbindd` would require shipping Samba (or at least the Winbind subset), which is GPLv3 and creates the same license conflict as Decision 10 rejected. SSSD is strictly better than Winbind for AD integration (better caching, better offline support, better GPO support, better performance) — Red Hat deprecated Winbind in favor of SSSD in RHEL 6 (2010), and the industry has followed. Winbind's `idmap` configuration is complex and error-prone (the `idmap_rid`, `idmap_ad`, `idmap_autorid` backends have different semantics and produce different UID/GID assignments for the same SID); SSSD's `ldap_id_mapping` is simpler. Winbind is coupled to Samba's `smbd` and `nmbd` (it shares Samba's `passdb` and `secrets.tdb`); using Winbind without `smbd` requires extracting Winbind from Samba, which is non-trivial.

The choice to not support PBIS is forced by BeyondTrust's 2023 EOL of PBIS. The framework's documentation explicitly lists PBIS as unsupported; PBIS customers have known about the EOL since 2023. The framework's `adrian-cli migrate from-winbind` tooling handles PBIS-to-SSSD migration because PBIS uses a Winbind-equivalent stack (`pam_lwidentity.so` + `libnss_lwidentity.so.2` + `lwreg` registry + bundled Kerberos); the same configuration translation logic applies.

The choice to ship `adrian-sssd-gpo` as a Rust library that hooks into SSSD's access-control path is forced by the need to close SSSD's GPO coverage gaps (per [PC-088](../catalog/08-client-sdk.md)). SSSD's `ad_gpo.c` covers only the Security CSE subset (`[Privilege Rights]`); the framework's `adrian-sssd-gpo` library extends coverage to the full `Security` PolicyArea (logon hours, host access control, group policy access control) via a new SSSD access provider (`gpo_access_provider = adrian`) that the framework contributes upstream to SSSD. This gives SSSD customers the framework's enhanced access control without requiring them to use the framework's PAM/NSS modules.

The choice to migrate FILE:/KEYRING: caches to KCM during Linux enrollment is forced by the need to standardize on KCM (per [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) and [ADR-111](./ADR-111-unified-ticket-cache-abstraction.md)). Existing Linux deployments that use FILE: or KEYRING: caches (the SSSD defaults before Fedora 32 / Ubuntu 22.04) must migrate to KCM to gain the system-daemon renewal benefit. The migration is automated and reversible; the framework's installer handles it without admin intervention.

## Consequences

**Positive**. The framework gains a single Linux integration path (SSSD-primary), aligning with the industry direction and reducing the framework's support surface. The `adrian-sssd-gpo` library closes SSSD's GPO coverage gaps, giving SSSD customers the framework's enhanced access control without requiring them to abandon SSSD. The `adrian-cli migrate from-winbind` tooling automates the painful Winbind-to-SSSD migration documented in [PC-099](../catalog/09-cross-platform-parity.md), reducing the per-host migration time from ~4 hours to ~30 minutes. The framework's `authselect` profile (`adrian-with-sudo`) provides a consistent PAM/NSS configuration across RHEL, Fedora, Debian, Ubuntu, SUSE, with `pam-auth-update` and `pam-config` fallbacks for distros that do not ship `authselect`.

**Negative**. SSSD is C, not Rust; the framework's Rust-based enhancements are loaded as a shared library (`libadrian_sssd_gpo.so`) via a C ABI, but SSSD itself remains C. Memory-safety bugs in SSSD's C code are outside the framework's control. The `adrian-sssd-gpo` library's SSSD integration requires either (a) a new SSSD access-provider plugin API (upstream contribution, slow — SSSD's review cadence is slow) or (b) a side-loaded library that hooks into SSSD's existing `simple` access provider via a configuration override (faster, less clean). The framework ships option (b) for v1 and works toward option (a) for v2 (or as soon as the upstream contribution merges). Winbind customers must migrate; the operational transition (testing, user communication, rollback plan) is the customer's responsibility. PBIS customers must migrate via the Winbind tooling (PBIS uses a Winbind-equivalent stack).

**Neutral**. The framework's Linux posture is invisible to end users (they interact with `login`/`ssh`/`sudo`, not SSSD directly). The framework's `adrian-sssd-gpo` library is invisible to end users (they see access-control decisions, not the library's internals). The framework's `adrian-cli migrate from-winbind` tooling is invisible to end users (it runs as root, with no user interaction).

**Implementation cost**. ~12 person-weeks for v1. Breakdown: `adrian-sssd-gpo` library (4 pw, highest-risk due to SSSD integration), `adrian-cli migrate from-winbind` tool (1 pw), PBIS detection and migration (1 pw, sharing the Winbind tooling), `adrian-authselect-profile` (1 pw), `adrian-cli join` Linux path (2 pw), `adrian-base-container` image (1 pw), SSSD upstream contribution (1 pw, ongoing), test matrix (RHEL 8, RHEL 9, Ubuntu 20.04, Ubuntu 22.04, Debian 11, Debian 12, SUSE 15) (1 pw).

**Operational impact**. Operations teams gain a single Linux integration path (SSSD-primary) across all supported distros, simplifying the support matrix. Operations teams gain the `adrian-cli migrate from-winbind` tooling for automated Winbind/PBIS migration. Operations teams must understand that SSSD is C (not Rust) and that memory-safety bugs in SSSD are outside the framework's control — the runbook includes a "Linux tier troubleshooting" section explaining the framework's posture.

## Alternatives Considered

**Alternative 1: FreeIPA as the sole Linux tier.** Adopt FreeIPA as the framework's Linux identity platform; the framework's directory trusts FreeIPA, and Linux hosts join FreeIPA (not the framework). **Rejection rationale**: Per Decision 12 §Rationale §Candidate A rejection, FreeIPA is a separate Linux domain controller with its own CA (Dogtag), DNS (Bind), and HBAC — adopting FreeIPA as the sole Linux tier means the framework's directory is not the source of truth for Linux identity, which breaks the framework's "one directory, one identity" model. FreeIPA's directory schema is incompatible with the framework's directory schema; FreeIPA's release cadence is controlled by the FreeIPA project (Red Hat), not by the framework. FreeIPA is supported as an alternative tier (per Decision 12 §3 and [ADR-115](./ADR-115-freeipa-as-alternative-linux-tier.md)), not as the sole tier.

**Alternative 2: Framework-native Linux client (no SSSD, no FreeIPA).** Use the framework's Client SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)) as the sole Linux integration; `pam_adrian.so` + `nss_adrian.so.2` replace SSSD entirely. **Rejection rationale**: Per Decision 12 §Rationale §Candidate B rejection, SSSD is the de facto standard for Linux-AD integration, with a large operator community, extensive documentation, and broad distro support. Customers expect SSSD as the Linux integration path; requiring them to use the framework's PAM/NSS modules exclusively is a non-starter for adoption. The framework's PAM/NSS modules (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)) are available as an alternative for customers who want the framework-native experience; the framework does not need to force them on customers who prefer SSSD.

**Alternative 3: Winbind as the primary Linux tier.** Use Samba's `winbindd` as the framework's Linux integration. **Rejection rationale**: Per Decision 12 §Rationale §Candidate C rejection, Winbind is a Samba component, and the framework does not adopt Samba (per Decision 10's rejection of Samba's `smbd`). Using `winbindd` would require shipping Samba, which is GPLv3 and creates the same license conflict as Decision 10 rejected. SSSD is strictly better than Winbind for AD integration; Red Hat deprecated Winbind in favor of SSSD in RHEL 6 (2010).

## Open Questions

None. The decision is fully specified by Decision 12 §1-§11. The implementation details (SSSD upstream contribution timing, distro-detection logic for `authselect`/`pam-auth-update`/`pam-config` fallbacks) are operational refinements documented in §Consequences.

## Cross-capability impact

- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): SSSD's `ad` provider queries the framework's directory via LDAP; the directory's AD-compatible schema (per Day 1 schema decision) makes this work.
- **KDC** ([PC-023](../catalog/02-kdc.md)): SSSD's `ad` provider uses the framework's KDC for Kerberos authentication.
- **Auth Provider** ([PC-029](../catalog/03-auth-provider.md)): SSSD's PAM module (`pam_sss.so`) delegates password validation to the Auth Provider via LDAP simple bind. The framework's `pam_adrian.so` (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)) is an alternative for customers who want end-to-end Rust.
- **Policy Engine** (Decision 7): The `adrian-sssd-gpo` library retrieves the framework's `Security` PolicyArea policy via the WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)) and enforces it during PAM `pam_sm_acct_mgmt`. The framework's `adrian-policy-daemon` (per [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md)) is the host-side policy daemon.
- **Cert Service** (Decision 8): The `adrian-cert-agent` (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)) is the host-side cert enrollment agent, replacing FreeIPA's `certmonger` for framework-managed hosts.
- **Operations** ([ADR-058](./ADR-058-container-native-dcs-operator.md)): The framework's Linux client (SSSD + Client SDK) runs as a DaemonSet on Kubernetes nodes for container-native deployments.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): The `adrian-cli migrate from-winbind` tool is the migration entry point for Winbind customers. The `adrian-cli join` command is the entry point for new Linux hosts. The framework's documentation includes a "Linux tier migration guide" covering AD-with-SSSD → framework-with-SSSD, AD-with-Winbind → framework-with-SSSD, AD-with-PBIS → framework-with-SSSD (unsupported; same as Winbind path), and standalone-OpenLDAP → framework-with-SSSD.

## References

- [PC-099](../catalog/09-cross-platform-parity.md) — problem statement
- [Workshop Decision 12 — Linux Tier](../workshop/decision-12-linux-tier.md) — SSSD primary + FreeIPA alt + Winbind deprecated + PBIS unsupported
- [docs/09-linux-equivalents/04-winbind-internals.md](../docs/09-linux-equivalents/04-winbind-internals.md) — Winbind internals, `idmap_rid`/`idmap_autorid`/`idmap_ad`/`idmap_tdb2`, `secrets.tdb`
- [docs/09-linux-equivalents/07-pbis-powerbroker.md](../docs/09-linux-equivalents/07-pbis-powerbroker.md) — PBIS internals, `domainjoin-cli`, `lwreg`/`lwsm`/`lwsmd`, EOL status
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization
- [ADR-050](./ADR-050-authselect-standard-pam.md) — authselect standard PAM
- [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) — KCM Linux API + macOS cache abstraction
- [ADR-058](./ADR-058-container-native-dcs-operator.md) — container-native DCs operator
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [ADR-110](./ADR-110-sid-to-uid-mapping-uuid-primary.md) — SID-to-UID mapping (UUID-primary)
- [ADR-113](./ADR-113-gpo-preferences-cross-platform-policy.md) — GPO Preferences and cross-platform policy compilation
- [SSSD Documentation](https://sssd.io/) — SSSD project documentation
- [Red Hat Winbind deprecation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/windows_integration_guide/winbind-vs-sssd) — Winbind vs. SSSD
- [authselect](https://github.com/authselect/authselect) — authselect project
- [BeyondTrust PBIS EOL](https://www.beyondtrust.com/) — BeyondTrust PBIS end-of-life announcement
