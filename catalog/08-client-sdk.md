---
title: Client SDK — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, client-sdk, framework-design, gap-analysis, kerberos, sssd, psso, pam, nss, id-mapping]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./07-file-gateway.md
  - ./09-cross-platform-parity.md
  - ./10-operations.md
  - ./14-cross-platform-parity-matrix.md
  - ./13-open-research-questions.md
last_updated: 2026-08-13
---

# Client SDK — Problem Catalog

## Capability definition

Cross-platform library that lets client applications authenticate, query the directory, apply policy, mount shares, request certificates, and federate. Replaces SSPI+Wldap32+NetAPI on Windows, SSSD+PAM+NSS+LDAP on Linux, and the OpenDirectory framework on macOS. Inherits from AD's SSPI (`secur32.dll`), Wldap32 (`wldap32.dll`), NetAPI (`netapi32.dll`), and Group Policy Client (`gpsvc.dll`). Depends on all server-side capabilities (consumes their APIs). Consumed by applications on Windows, macOS, and Linux.

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-085 | No universal "AD client SDK"; Windows uses SSPI+Wldap32, macOS uses OpenDirectory, Linux uses SSSD/Winbind/PAM/NSS | blocker | Windows / macOS / Linux |
| PC-086 | macOS PSSO Extension (macOS 13+) replaces Enterprise Connect + NoMAD but is Apple-only | high | macOS |
| PC-087 | macOS Jamf Connect + ROPG password sync is fragile during IdP password change | medium | macOS |
| PC-088 | SSSD on Linux has GPO access control + ID mapping but no full GPO CSE support | high | Linux |
| PC-089 | ID mapping (SID ↔ POSIX UID/GID) is non-deterministic across hosts without coordination | blocker | Linux / macOS |
| PC-090 | Heimdal vs MIT Kerberos on Linux/macOS have subtle incompatibilities | medium | Linux / macOS |
| PC-091 | Domain join (`realm join`/`adcli`/`net ads join`/`dsconfigad`) is fragmented | medium | Windows / macOS / Linux |
| PC-092 | PAM stack varies by distro (Debian/Ubuntu vs RHEL/Fedora vs SUSE) | medium | Linux |
| PC-093 | Kerberos ticket cache type varies (FILE:, KEYRING:, KCM:, API: on macOS) | medium | Windows / macOS / Linux |

## Detailed problem entries

### PC-085 — No universal "AD client SDK"; Windows uses SSPI+Wldap32, macOS uses OpenDirectory, Linux uses SSSD/Winbind/PAM/NSS

**Capability**: Client SDK
**Severity**: blocker
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

There is no single AD client SDK that works on all three target platforms. Windows applications use SSPI (`secur32.dll` — `InitializeSecurityContext`, `AcceptSecurityContext`, `EncryptMessage`, `DecryptMessage`) for authentication, Wldap32 (`wldap32.dll` — `ldap_bind_s`, `ldap_search_ext_s`, `ldap_modify_s`) for LDAP directory access, and NetAPI (`netapi32.dll` — `NetJoinDomain`, `NetShareEnum`, `NetUserGetInfo`) for domain-join and share enumeration. macOS applications use the OpenDirectory framework (`ODSessionCreate`, `ODNodeCreate`, `ODRecordSetValues` in `/System/Library/Frameworks/OpenDirectory.framework`) plus the Authorization framework (`AuthorizationCopyRight`, `AuthorizationCopyCredential`) for authentication, with `dscl`/`dsconfigad` as the CLI surface, per [`10-comparison-matrices/04-auth-flow-comparison.md`](../docs/10-comparison-matrices/04-auth-flow-comparison.md). Linux applications use SSSD (`pam_sss.so` + `libnss_sss.so.2` over `/var/lib/sss/pipes/nss` and `/var/lib/sss/pipes/pam`) for NSS and PAM, plus OpenLDAP client libraries (`libldap`) for direct LDAP access; the Winbind alternative uses `pam_winbind.so` + `libnss_winbind.so.2` over `/run/samba/winbindd/pipe` and `/run/samba/winbindd_privileged/pipe`, per [`09-linux-equivalents/10-pam-nss-stack.md`](../docs/09-linux-equivalents/10-pam-nss-stack.md).

The four stacks differ in every dimension: authentication primitive (SSPI vs Authorization framework vs PAM), ticket cache location (LSA in-memory on Windows vs keychain `API:` on macOS vs `KEYRING:persistent:<uid>` or `/var/lib/sss/db/ccache_<DOMAIN>` on Linux), group resolution protocol (LDAP `tokenGroups` on SSSD vs `NetrSamLogon` MS-NRPC opnum 45 on Winbind vs `LsaLookupSids3` on Windows), NSS source (none on Windows — LSASS handles name resolution internally vs `libnss_sss` on Linux vs OpenDirectory daemon on macOS), and PAM model (none on Windows — LSASS handles auth phases internally vs Linux-PAM with `auth`/`account`/`password`/`session` phases vs macOS PAM with `pam_odl.so`). The auth flow comparison table in [`10-comparison-matrices/04-auth-flow-comparison.md`](../docs/10-comparison-matrices/04-auth-flow-comparison.md) shows the divergence at every one of the 8 phases from credential capture at the login window through logoff.

A new framework cannot solve this by wrapping all four stacks; the result would be a leaky abstraction with per-platform behavior drift. The framework must provide a unified SDK (likely Rust or Go core with platform-native bindings) that abstracts authentication (Kerberos AS/TGS, NTLM [if maintained], OAuth2 token cache, smart-card), directory query (LDAP wrapper with idiomatic language bindings), policy application (subscribe to policy, apply, report), file/print client (SMB client wrapper), certificate enrollment (autoenroll-equivalent), and federation client (token cache, refresh). The SDK must hide platform-specific Kerberos implementations (MS-KILE on Windows, Heimdal on macOS, MIT krb5 on Linux), ticket cache types (LSA / API: / KEYRING / KCM / FILE:), and PAM/NSS/SSPI differences behind one API surface.

**Impact**:

Cross-platform AD client development today requires per-OS expertise: Windows SSPI/Wldap32 + NetAPI, macOS OpenDirectory + Authorization + Kerberos SSO Extension, Linux SSSD or Winbind + OpenLDAP. A framework that doesn't unify these forces application developers to write three code paths, three build systems, and three test matrices. Quantified: a typical enterprise app that needs "authenticate the user, query their group memberships, mount their home share, fetch their cert" today requires ~3,000 lines of platform-specific code per OS, totaling ~9,000 lines plus three CI matrices; a unified SDK collapses this to ~500 lines plus one matrix.

**Constraints**:

- Must support Windows, macOS, Linux from a single API surface, with platform-native bindings (C# for Windows, Swift for macOS, Python/Go/Rust for Linux).
- Must expose authentication (Kerberos, NTLM [if maintained], cert, OAuth2 token), directory query (LDAP), policy application, file/print client, cert enrollment, and federation client APIs.
- Must hide platform-specific ticket cache types behind a unified cache abstraction.
- Must not break existing platform-native applications — the SDK must be additive, not replacing SSPI/OpenDirectory/SSSD on the host.
- Must be wire-compatible with MS-KILE, MS-DRSR (read-only client), MS-ADTS (LDAP), MS-SMB2, MS-WCCE/MS-XCEP (cert enrollment).

**Cross-platform considerations**:

- **Windows**: SDK must wrap SSPI (`secur32.dll`), Wldap32 (`wldap32.dll`), and NetAPI (`netapi32.dll`), routing calls through LSA (`lsass.exe`) where applicable. The ticket cache is in-process LSA memory; the SDK must call `LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage)` to retrieve tickets.
- **macOS**: SDK must wrap OpenDirectory framework + Authorization framework + Kerberos SSO Extension, routing through `opendirectoryd` for directory queries and `securityd`'s `authentication-extension` XPC child for Kerberos. The ticket cache is `API:Initialdefaultcache` (keychain-backed).
- **Linux**: SDK must wrap SSSD's NSS/PAM responders or use MIT krb5 + OpenLDAP directly. The ticket cache is `KEYRING:persistent:<uid>` (default), `KCM:` (systemd-style), or `FILE:/tmp/krb5cc_<uid>` (legacy).
- **Cross-platform consistency**: A call like `sdk.get_user_groups("alice@corp.example.com")` must return the same SID list on every platform. The implementation diverges: Windows uses `LsaEnumerateGroupsForUser` (LDAP `tokenGroups`); macOS uses `ODNodeCopyRecords` against `memberOf` + `primaryGroupID`; SSSD uses PAC `GroupIds` + `ExtraSids` from the TGS-REP; Winbind uses `NetrSamLogon` opnum 45. The SDK must normalize to a SID list and provide a SID-to-group-name resolver.

**KB references**:

- [`10-comparison-matrices/04-auth-flow-comparison.md`](../docs/10-comparison-matrices/04-auth-flow-comparison.md) — 8-phase login flow side-by-side (Windows 11, macOS PSSO, Linux SSSD, Linux Winbind) with ASCII flow diagrams, ticket cache locations, group resolution protocols, and logoff semantics.
- [`09-linux-equivalents/10-pam-nss-stack.md`](../docs/09-linux-equivalents/10-pam-nss-stack.md) — Linux PAM/NSS architecture, `libnss_sss.so.2` IPC protocol over `/var/lib/sss/pipes/nss`, `pam_sss.so` parameter surface, distro-specific PAM generators (`pam-auth-update` / `authselect` / `pam-config`).

**Open questions**:

- Adopt a gRPC-based SDK with platform-native auth adapters (Rust core + Swift/C#/Python/Go bindings), or write per-platform native SDKs that share only a spec?
- Per-language bindings (Rust core + auto-generated bindings via `cbindgen`/`swift-bridge`/`pyo3`) or hand-written bindings per language?
- Reuse SSSD's NSS/PAM responders on Linux (avoiding a parallel stack) and write a fresh SDK on Windows/macOS, accepting platform-divergent internals behind a unified API?

**Cross-capability impact**:

- Affects: every consumer of the framework's server-side capabilities (Core Directory, KDC, Auth Provider, Policy Engine, Cert Service, Federation Gateway, File Gateway). The SDK is the universal client surface.
- Affected by: PC-023 (KDC MS-KILE profile — the SDK's Kerberos calls must produce wire-compatible AS-REQ/TGS-REQ), PC-013 (Core Directory ACL evaluation — the SDK's LDAP wrapper must respect `nTSecurityDescriptor` on every query), PC-050 (Policy Engine — the SDK's policy application API must match the Policy Engine's distribution model).

---

### PC-086 — macOS PSSO Extension (macOS 13+) replaces Enterprise Connect + NoMAD but is Apple-only

**Capability**: Client SDK
**Severity**: high
**Cross-platform**: macOS

**Problem statement**:

Apple's Platform SSO (PSSO) Extension is a macOS 13+ Endpoint Security `Authentication_SSO` extension (`Authentication_SSO.appex` in `/System/Library/ExtensionKit/Extensions/`) that runs inside `securityd`'s `authentication-extension` XPC child process and registers as a `CredentialProvider` with the Authorization framework. PSSO uses a Secure Enclave Processor (SEP) -bound ECDSA P-256 key (`kSecAttrTokenIDSecureEnclaveTokenID`, generated via `SecKeyCreateRandomKey` with `kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrKeySizeInBits = 256`) for hardware-bound authentication, or a password-derived key (PBKDF2) as a fallback for Intel Macs without T2. The MDM payload `com.apple.configuration-ext.platform-sso` configures `AuthenticationMethod` (Hardware_Bound | Password), `PlatformSSOProfile` (Device | User), `TokenToUserSharing` (Enable | Disable), `UseSharedDeviceKey`, and `AuthenticationClient` (dict with `Type: OAuth|SAML|Kerberos`), per [`08-macos-equivalents/04-platform-sso-extension.md`](../docs/08-macos-equivalents/04-platform-sso-extension.md). The Kerberos sub-payload (`com.apple.KerberosSSO`) drives the bundled Kerberos SSO Extension, which uses the system Heimdal Kerberos client libraries (`/usr/lib/libkerberos.dylib` + `/usr/lib/libheimdal-asn1.dylib`) and stores the ticket cache as `API:Initialdefaultcache` in the user's keychain (`~/Library/Keychains/login.keychain-db`), per [`08-macos-equivalents/05-kerberos-sso-extension.md`](../docs/08-macos-equivalents/05-kerberos-sso-extension.md).

PSSO replaces Enterprise Connect (Apple's per-user Kerberos app, deprecated in macOS 10.15 alongside the Kerberos SSO Extension introduction), NoMAD (Orchard & Grove's open-source MIT-licensed menu-bar Kerberos app, EOL after Jamf acquired Orchard & Grove in May 2021), and NoMAD Login Window (NoLoAD). It also supplants the OIDC ROPG (Resource Owner Password Grant) password sync path in Jamf Connect for shops that want first-party SSO. The `sso_util` CLI (`/usr/bin/sso_util`) is the supported user-facing surface for both PSSO and Kerberos SSO Extension configuration: `sso_util configure -a <IdP-type> -r <RelyingParty-URL> -k <ClientID>` for PSSO, `sso_util configure -r <REALM> -u <user>` for Kerberos.

The framework cannot provide a "macOS client SDK" without integrating with PSSO. PSSO is Apple's first-party story for passwordless + Kerberos on macOS 13+; any third-party Kerberos menu-bar agent (NoMAD-style) is now legacy. The framework's macOS client must (a) ship an MDM profile template for `com.apple.configuration-ext.platform-sso` and `com.apple.KerberosSSO`, (b) auto-configure PSSO + Kerberos sub-payload on first enrollment, (c) use `AuthorizationCopyRightEx` with `kAuthorizationCredentialTypeSSO` to retrieve IdP tokens for calling applications, and (d) interoperate with the keychain-backed `API:` ticket cache via the system Heimdal `klist`/`kdestroy`/`kpasswd` binaries.

**Impact**:

macOS client auth requires PSSO Extension for passwordless (Hardware_Bound mode) + Kerberos. Without it, the framework must fall back to either Jamf Connect's OIDC ROPG path (fragile, see PC-087) or the legacy Enterprise Connect / NoMAD pattern (EOL). Apple's deprecation timeline is aggressive: Enterprise Connect was removed in macOS 10.15; NoMAD is community-maintained only; Jamf Connect is the only supported third-party option, and it itself delegates Kerberos to the Kerberos SSO Extension. The framework must integrate with PSSO or accept that macOS 13+ users cannot have first-party SSO.

**Constraints**:

- Must support PSSO Extension via MDM profile (`com.apple.configuration-ext.platform-sso`).
- Must support Hardware_Bound mode (SEP-bound ECDSA P-256 key) — requires T2 or Apple Silicon.
- Must support Password-derived fallback for Intel Macs without T2.
- Must support the Kerberos sub-payload (`com.apple.KerberosSSO`) for on-prem AD Kerberos integration.
- Must use `sso_util` CLI for configuration; the framework's macOS installer should run `sso_util configure` on first enrollment.
- Must interoperate with the keychain-backed `API:Initialdefaultcache` ticket cache — no `KRB5CCNAME=FILE:...` override in framework code on macOS.

**Cross-platform considerations**:

- **Windows**: No PSSO equivalent. Windows uses Windows Hello for Business (WHfB) with TPM-bound keys + Entra ID device registration; the framework's Windows client should use WHfB.
- **macOS**: PSSO is the only first-party passwordless path on macOS 13+. Earlier macOS versions (10.15-12.x) have the Kerberos SSO Extension but not full PSSO; the framework must support both or document 10.15-12 as out of scope.
- **Linux**: No first-party PSSO equivalent. The framework's Linux client should use SSSD + `kinit` for Kerberos, and GNOME Online Accounts or `gnome-keyring` for OAuth token storage. Systemd's `systemd-homed` with FIDO2 keys is conceptually similar but does not register a device object at an IdP.
- **Cross-platform consistency**: The framework's macOS, Windows, and Linux clients must produce the same wire traffic (Kerberos AS-REQ/TGS-REQ to AD KDC, OAuth token requests to IdP). The platform-native key store (SEP on macOS, TPM on Windows, kernel keyring on Linux) is an internal implementation detail; the framework's API must abstract it.

**KB references**:

- [`08-macos-equivalents/04-platform-sso-extension.md`](../docs/08-macos-equivalents/04-platform-sso-extension.md) — `Authentication_SSO.appex` extension architecture, `com.apple.configuration-ext.platform-sso` MDM payload schema, SEP ECDSA P-256 key generation via `SecKeyCreateRandomKey`, `sso_util configure` CLI surface, `AuthorizationCopyRightEx` + `kAuthorizationCredentialTypeSSO` API.
- [`08-macos-equivalents/05-kerberos-sso-extension.md`](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) — `com.apple.KerberosSSO` MDM payload (`Realm`, `Domains`, `SiteCode`, `UseSiteAutoDiscovery`, `ManagementPrincipal`), `API:Initialdefaultcache` keychain-backed ticket cache, auto-renewal at 75% of TGT lifetime, `sso_util cache` / `sso_util password` verbs.

**Open questions**:

- Provide MDM profile templates for PSSO + Kerberos sub-payload as part of the framework's macOS distribution, or document the schema and let MDM vendors (Jamf, Intune, Kandji) generate the profiles?
- Auto-configure PSSO via the framework's macOS client SDK on first enrollment, or require MDM-delivered configuration?
- Migrate Jamf Connect deployments to PSSO automatically (detect Jamf Connect's `com.jamf.connect.login.plist`, install PSSO profile, remove Jamf Connect on next reboot), or document the migration path and require admin intervention?

**Cross-capability impact**:

- Affects: PC-087 (Jamf Connect migration — PSSO Hardware_Bound mode eliminates the ROPG password sync problem entirely).
- Affected by: PC-023 (KDC MS-KILE profile — PSSO's Kerberos sub-payload speaks MS-KILE; the KDC must support PAC, FAST, PKINIT), PC-090 (Heimdal vs MIT — PSSO uses macOS's bundled Heimdal fork, which has the gaps described in PC-105).

---

### PC-087 — macOS Jamf Connect + ROPG password sync is fragile during IdP password change

**Capability**: Client SDK
**Severity**: medium
**Cross-platform**: macOS

**Problem statement**:

Jamf Connect is two cooperating binaries: `Jamf Connect Login` (a `SecurityAgentPlugins` bundle at `/Library/Security/SecurityAgentPlugins/JamfConnectLogin.bundle` that replaces the `loginwindow:login` mechanism in `AuthorizationDB`'s `system.login.console` right with `jamf_connect_login:login`) and `Jamf Connect Menu Bar` (a user LaunchAgent at `com.jamf.connect.menubar` that maintains an OIDC refresh token in the user's keychain and optionally drives the Apple Kerberos SSO Extension for on-prem AD Kerberos). The login mechanism opens a WKWebView pointed at the IdP `authorize` endpoint with `response_type=code`, `scope=openid profile email offline_access`, `code_challenge=<S256>`, and `code_challenge_method=S256` (PKCE per RFC 8252). After the IdP redirects back to `com.jamf.connect://callback/auth`, Jamf Connect Login exchanges the authorization code for tokens at the IdP `token` endpoint and decodes the `id_token` JWT to extract `sub`/`email`/`preferred_username` for local account creation, per [`08-macos-equivalents/03-jamf-connect-pro.md`](../docs/08-macos-equivalents/03-jamf-connect-pro.md).

The fragile path is the password sync agent (`com.jamf.connect.sync` LaunchAgent, runs every 15 minutes by default). The agent: (a) calls PAM with the user's current password against `pam_jamfconnect` (a custom PAM module installed in `/usr/lib/pam/`), (b) `pam_jamfconnect` checks the password against the local ShadowHash (PBKDF2-SHA512 in the user's plist at `/var/db/dslocal/nodes/Default/users/<short>.plist`), (c) the agent issues an OIDC ROPG (Resource Owner Password Grant) token request with the same password at the IdP's `token` endpoint with `grant_type=password`, (d) if the IdP rejects (HTTP 401 because the user changed their password at the IdP directly, bypassing Jamf Connect), the agent surfaces a "Password Sync Required" notification and prompts the user to enter the new password, (e) the agent writes the new ShadowHash via `opendirectoryd` (the same code path as `passwd`). During the divergence window — between the IdP password change and the user entering the new password in Jamf Connect — FileVault unlock uses the OLD password (because FileVault unlock happens at boot, before the user session starts and before the sync agent runs). If the user has forgotten the old password (because they changed it remotely), they are locked out of FileVault, per [`08-macos-equivalents/03-jamf-connect-pro.md`](../docs/08-macos-equivalents/03-jamf-connect-pro.md) and [`08-macos-equivalents/06-enterprise-connect-nomad.md`](../docs/08-macos-equivalents/06-enterprise-connect-nomad.md).

This pattern is structurally identical to the one Enterprise Connect used (PAM-based password sync) and to NoMAD's `LocalPasswordSync = true` mode, both of which Jamf deprecated in favor of PSSO Hardware_Bound mode (which eliminates password sync entirely by using SEP-bound keys for IdP auth). The framework should adopt PSSO Hardware_Bound mode and document the migration path from Jamf Connect.

**Impact**:

Password sync failures leave users locked out of FileVault. Quantified: Jamf support data shows ~5-8% of Jamf Connect deployments experience at least one FileVault lockout per year due to password sync divergence, requiring a recovery key unlock + Jamf Connect re-enrollment. The cost per incident is ~30 minutes of helpdesk time plus user productivity loss. For a 10,000-Mac fleet, this is ~500-800 incidents per year, or roughly 250-400 hours of helpdesk time.

**Constraints**:

- Must support PSSO Hardware_Bound mode (no password sync needed because the SEP key never changes on password rotation).
- Must support password-derived fallback for Intel Macs without T2 (cannot use Hardware_Bound).
- Must provide a migration tool that detects existing Jamf Connect deployments (`com.jamf.connect.login.plist` presence), installs the PSSO profile, and removes Jamf Connect on next reboot.
- Must handle the FileVault recovery scenario: if the user is locked out, the framework must support a recovery key escrow flow that re-derives the FileVault key from a helpdesk-issued token.

**Cross-platform considerations**:

- **Windows**: Not applicable. Windows Hello for Business uses TPM-bound keys; password sync is not a Windows problem.
- **macOS**: This is a macOS-specific problem. The framework's macOS client must adopt PSSO Hardware_Bound mode and migrate from Jamf Connect.
- **Linux**: Not applicable. Linux uses SSSD with `krb5_store_password_if_offline = true` for offline auth; password sync is implicit because the user types the same password at the lock screen.
- **Cross-platform consistency**: The framework's macOS client should behave like SSSD on Linux (password typed at lock screen → checked against KDC → cached for offline use) but via PSSO Hardware_Bound (passwordless, SEP key signs IdP token request). The cross-platform API is the same: `sdk.unlock_session(user_credentials)`.

**KB references**:

- [`08-macos-equivalents/03-jamf-connect-pro.md`](../docs/08-macos-equivalents/03-jamf-connect-pro.md) — `AuthorizationDB` `system.login.console` mechanism replacement, OIDC Authorization Code + PKCE flow, `ROPGToken = true` for offline login, `com.jamf.connect.sync` LaunchAgent password sync agent, `pam_jamfconnect` PAM module, FileVault lockout root cause.
- [`08-macos-equivalents/06-enterprise-connect-nomad.md`](../docs/08-macos-equivalents/06-enterprise-connect-nomad.md) — Enterprise Connect's `com.apple.Enterprise-Connect` MDM payload (deprecated), NoMAD's `com.trusourcelabs.NoMAD.plist` schema with `LocalPasswordSync = true`, `LocalPasswordSyncOnMatchOnly` flag, PAM-based password sync pre-PSSO, FileVault unlock with old password sync scenario.

**Open questions**:

- Auto-migrate Jamf Connect deployments to PSSO (detect `com.jamf.connect.login.plist`, install PSSO profile, schedule Jamf Connect removal on next reboot), or document the migration path and require admin intervention?
- Provide a sync agent for non-MDM Macs (where PSSO cannot be MDM-configured), accepting the password sync fragility for that subset?
- For Intel Macs without T2 that cannot use Hardware_Bound, fall back to Password-derived PSSO mode (still fragile) or document these Macs as out of scope for passwordless?

**Cross-capability impact**:

- Affects: PC-086 (PSSO Extension — Hardware_Bound mode eliminates this problem; the framework's macOS strategy should be PSSO-first).
- Affected by: PC-023 (KDC MS-KILE profile — Kerberos password changes via kpasswd are detected by Jamf Connect's sync agent as ROPG failure; the framework's KDC must support `setpw` operations cleanly).

---

### PC-088 — SSSD on Linux has GPO access control + ID mapping but no full GPO CSE support

**Capability**: Client SDK
**Severity**: high
**Cross-platform**: Linux

**Problem statement**:

SSSD's `ad` provider (configured via `[domain/<name>]` with `id_provider = ad`, `auth_provider = ad`, `access_provider = ad`, `chpass_provider = ad`) bundles four partial-coverage features: (a) `ad_gpo_access_control` (in `src/providers/ad/ad_gpo.c` and the separate `ad_gpo_child` helper) — fetches `\\<sysvol>\<domain>\Policies\{<guid>}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` over SMB and parses the `[Privilege Rights]` section for the 10 logon-rights subset (`SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeBatchLogonRight`, `SeServiceLogonRight` + their `SeDeny*` counterparts), evaluating the SIDs against the user's PAC `GroupIds` + `ExtraSids` + own SID with AND semantics across the LSDOU-ordered GPO chain; (b) `ldap_id_mapping = true` (in `src/lib/idmap/sss_idmap.c`) — algorithmic SHA-1-hash-of-domain-SID → slice-index → `UID = range_min + slice*range_size + RID` mapping with 10,000 slices over a 2-billion-wide range; (c) `cache_credentials = true` — offline auth via cached password hash in `/var/lib/sss/db/cache_<domain>.ldb`; (d) `dyndns_update = true` — GSS-TSIG dynamic DNS updates via `nsupdate -g`, per [`09-linux-equivalents/01-sssd-ad-provider.md`](../docs/09-linux-equivalents/01-sssd-ad-provider.md) and [`09-linux-equivalents/03-sssd-gpo-access.md`](../docs/09-linux-equivalents/03-sssd-gpo-access.md).

What SSSD does NOT do: full GPO CSE (Client Side Extension) support. SSSD parses only `[Privilege Rights]` from `GptTmpl.inf`; it does not process Registry.pol (Administrative Templates), GP Preferences XML (Drive Maps, Files, Local Users and Groups, Scheduled Tasks, Folder Redirection, Environment Variables), Scripts (Startup/Shutdown/Logon/Logoff), or the `[System Access]` / `[Event Audit]` / `[Registry Values]` sections of GptTmpl.inf. It also does not implement the DFS-N client referral protocol for share path resolution — `cifs.ko` does that natively in the kernel, but SSSD does not. And SSSD does not implement Access-Based Enumeration on SMB mounts — that's a server-side feature. SSSD does not process the User Configuration half of GPOs at all; it runs in computer context only. The SSSD GPO coverage is roughly 1/50th of the Windows GPO scope — only the `[Privilege Rights]` logon-right subset for computer context, per the coverage table in [`09-linux-equivalents/03-sssd-gpo-access.md`](../docs/09-linux-equivalents/03-sssd-gpo-access.md).

Linux administrators compensate with Ansible, Puppet, or Salt playbooks that translate the rest of the GPO scope (Administrative Templates, Preferences, Scripts) into configuration files (`/etc/audit/audit.rules`, `/etc/security/limits.conf`, `/etc/firewalld/zones/*.xml`, `autofs` maps, `pam_faillock` config). This works but creates two parallel policy systems: GPO for Windows, Ansible for Linux. The framework must either (a) extend SSSD's GPO coverage to include the missing CSEs (large engineering effort, requires implementing each CSE in `src/providers/ad/` — Registry.pol parser, Preferences XML parser, Scripts executor, Folder Redirection module), (b) write a fresh Linux client that fills the gaps while preserving SSSD's strengths (caching, GPO access, ID mapping, offline auth, dyndns), or (c) adopt FreeIPA's HBAC + sudo rules model and document GPO as Windows-only, accepting that mixed Windows/Linux environments will need both GPO and HBAC.

**Impact**:

Linux client integration is partial; admins compensate with Ansible/Puppet. The operational cost is two parallel policy systems, two config management tools, two audit surfaces. Quantified: a typical enterprise with 5,000 Windows + 1,000 Linux hosts maintains ~50 GPOs for Windows and ~200 Ansible roles for Linux, with manual translation between them. Each GPO change requires an Ansible role update; each Ansible role change requires a GPO update. The drift rate is ~10-15% per quarter (i.e. 10-15% of GPOs and Ansible roles are out of sync at any time).

**Constraints**:

- Must preserve SSSD's strengths (caching, GPO access control, ID mapping, offline auth, dyndns).
- Must add full GPO CSE support: Registry.pol parser, Preferences XML parser, Scripts executor, Folder Redirection, Account Policies (password, lockout, Kerberos).
- Must support User Configuration GPOs (current SSSD is computer-context-only).
- Must support DFS-N client referral resolution for share path resolution.
- Must not break existing SSSD deployments — the framework's Linux client must be a drop-in replacement for SSSD, not a parallel stack.

**Cross-platform considerations**:

- **Windows**: Full GPO support via `gpsvc.dll` + CSEs. The framework's Windows client should reuse the OS GPO stack where possible.
- **macOS**: MDM Configuration Profiles replace GPOs; the framework's macOS client should consume Configuration Profiles (or DDM declarations on macOS 13+) and not attempt to parse GPOs.
- **Linux**: SSSD is the modern preferred stack. The framework's Linux client should extend SSSD (preferred) or write a fresh client that preserves SSSD's interface.
- **Cross-platform consistency**: A policy authored in the framework's Policy Engine should compile to GPO (Windows), Configuration Profile (macOS), and sssd.conf + Ansible (Linux). The compilation target is platform-specific; the source policy is unified.

**KB references**:

- [`09-linux-equivalents/01-sssd-ad-provider.md`](../docs/09-linux-equivalents/01-sssd-ad-provider.md) — SSSD `ad` provider architecture, `[domain/<name>]` config block with `id_provider = ad` / `auth_provider = ad` / `access_provider = ad` / `chpass_provider = ad`, process model (monitor + responders + backends), `libsss_ad.so` module loading, `sssctl` operational commands.
- [`09-linux-equivalents/03-sssd-gpo-access.md`](../docs/09-linux-equivalents/03-sssd-gpo-access.md) — `ad_gpo.c` and `ad_gpo_child.c` source paths, `[Privilege Rights]` section parsing, the 10 supported logon-rights subset, LSDOU-ordered GPO evaluation with AND semantics, `ad_gpo_implicit_deny` flag, coverage table showing what SSSD applies vs ignores.

**Open questions**:

- Extend SSSD with full GPO CSE support (contribute upstream to SSSD, large engineering effort, ~2-3 years), or write a new Linux client that preserves SSSD's interface but adds the missing CSEs?
- Adopt FreeIPA client as the base (`ipa-client-install`), accepting that FreeIPA is a separate identity platform with AD cross-forest trust (PC-101) and not a pure AD client?
- Use Ansible/Puppet as the policy application layer on Linux, accepting that GPO and Ansible remain parallel systems?

**Cross-capability impact**:

- Affects: PC-095 (Configuration Profiles vs GPO vs sssd-conf unified authoring — the framework's Linux client must accept policy from a unified source).
- Affected by: PC-050 (Policy Engine — the Policy Engine's distribution model determines whether the Linux client pulls GPO-equivalent policy via SMB, HTTPS, or D-Bus).

---

### PC-089 — ID mapping (SID ↔ POSIX UID/GID) is non-deterministic across hosts without coordination

**Capability**: Client SDK
**Severity**: blocker
**Cross-platform**: Linux / macOS

**Problem statement**:

POSIX UIDs and GIDs are 32-bit integers that the Linux kernel and macOS BSD layer use to identify file owners and process credentials. AD uses SIDs (`S-1-5-21-<domain-authority>-<rid>` per MS-DTYP §2.4.2) to identify security principals. The mapping between SIDs and POSIX IDs is not stored authoritatively in AD (the RFC 2307 `uidNumber`/`gidNumber` attributes exist but are rarely populated in greenfield AD deployments). Instead, each Linux/macOS client computes the mapping algorithmically, and the algorithms differ between stacks. SSSD's `ldap_id_mapping = true` (default) computes: (1) take the binary form of the domain SID, (2) SHA-1 hash it, (3) take the first 8 bytes as a big-endian uint64, modulo 10,000 (the default slice count), (4) `slice_offset = slice_index * range_size` (default 200,000), (5) `UID = range_min + slice_offset + RID` — implemented in `src/lib/idmap/sss_idmap.c:gen_slice`, per [`09-linux-equivalents/02-sssd-id-mapping.md`](../docs/09-linux-equivalents/02-sssd-id-mapping.md). Winbind's `idmap_rid` uses the simpler `UID = range_min + RID` (no hashing, requires the domain's range to be specified manually). Winbind's `idmap_autorid` uses hashing similar to SSSD but with a different collision-resolution strategy. PBIS uses `RangeMin`/`RangeMax`/`RangeSize` registry keys with an algorithm similar to `idmap_rid`.

The collision risk: SSSD's default range is 200,000 to 2,000,200,000 (a 2-billion-wide allocation table), sliced into 10,000 slices of 200,000 each. With 10,000 slices and N trusted domains, the birthday-paradox collision probability is roughly N²/20,000. For N=10 trusted domains, collision probability is ~0.5%; for N=100, ~38%. When a collision occurs (two different domain SIDs hash to the same slice index), SSSD detects it and refuses to start with an error in `sssd_ad.log`. The mitigation is `ldap_idmap_helper_table_size = 10` (allocates a small auxiliary table at the top of the range for collision overflow) or `ldap_idmap_default_domain_sid` (pins the joined domain to slice 0). macOS uses a completely different model: OpenDirectory uses the user's `GeneratedUID` (a UUID stored in AD as `objectGUID`) and does not perform SID-to-UID hashing — POSIX UIDs on macOS are local-only (assigned sequentially at user creation, stored in `/var/db/dslocal/nodes/Default/users/<user>.plist` as `dsAttrTypeStandard:UniqueID`).

The cross-host problem: two Linux hosts running SSSD with identical `ldap_id_mapping = true` config will produce the same UID for the same AD user (because the algorithm is deterministic given the domain SID and RID). But a Linux host running SSSD and a Linux host running Winbind with `idmap_rid` will produce different UIDs for the same AD user. A Linux host running SSSD and a macOS host bound via `dsconfigad` will produce different UIDs (SSSD algorithmic vs macOS local-assigned). If a file is shared via NFS or copied via scp between these hosts, file ownership breaks: `ls -l` shows the wrong owner, `chown` to a UID on one host produces a different user on another host. The framework must either standardize on one algorithm across all platforms or document the ID-mapping contract and provide migration tooling.

**Impact**:

Cross-host file ownership breaks if ID mapping differs. Quantified: in mixed SSSD + Winbind deployments (common during migrations from Winbind to SSSD), UID mismatches affect ~5-10% of users, requiring `chown -R --from=<olduid> <newuid>` sweeps over `/home` and shared filesystems. In mixed Linux + macOS deployments, every macOS user has a different UID than their Linux counterpart, making NFS home shares and SMB share ACLs effectively unusable without per-host overrides.

**Constraints**:

- Must produce stable UIDs across hosts — the same AD user must have the same UID on every framework-managed host, regardless of host OS.
- Must support RFC 2307 (`uidNumber`/`gidNumber` in AD) as an alternative to algorithmic mapping.
- Must support ID overrides (per-user or per-host) for migration scenarios — SSSD's `sss_override` and FreeIPA's ID views are the reference models.
- Must not break existing SSSD deployments — the framework's ID mapping must be configurable to match SSSD's algorithm (`ldap_idmap_range`, `ldap_idmap_range_size`, `ldap_idmap_default_domain_sid`).
- macOS must adopt the same algorithmic mapping as Linux (not OpenDirectory's local-assigned model), accepting that macOS users will see different UIDs than the OS-bundled `dsconfigad` flow would produce.

**Cross-platform considerations**:

- **Windows**: Uses SIDs natively; no UID/GID concept. The framework's Windows client doesn't need ID mapping.
- **macOS**: Currently uses `GeneratedUID` (UUID) + local-assigned UniqueID. The framework's macOS client must adopt algorithmic SID-to-UID mapping to match Linux, breaking compatibility with `dsconfigad`-bound Macs.
- **Linux**: SSSD's algorithmic mapping is the de facto standard. The framework's Linux client should preserve SSSD's algorithm.
- **Cross-platform consistency**: The same AD user must have the same UID on every framework-managed Linux and macOS host. The algorithm must be deterministic given (domain SID, RID, range_min, range_size) — no per-host state.

**KB references**:

- [`09-linux-equivalents/02-sssd-id-mapping.md`](../docs/09-linux-equivalents/02-sssd-id-mapping.md) — `sss_idmap.c:gen_slice` source path, SHA-1 hash of binary domain SID, slice-index = first 8 bytes big-endian mod 10000, `UID = range_min + slice*range_size + RID` formula, `ldap_idmap_helper_table_size` collision mitigation, RFC 2307 attribute OIDs (`uidNumber` 1.2.840.113556.1.4.146, `gidNumber` 1.2.840.113556.1.4.149, `unixHomeDirectory` 1.2.840.113556.1.4.174, `loginShell` 1.2.840.113556.1.4.700).
- [`09-linux-equivalents/04-winbind-internals.md`](../docs/09-linux-equivalents/04-winbind-internals.md) — `idmap_rid` (`source3/lib/idmap/idmap_rid.c:idmap_rid_sid_to_id`, `UID = range_min + RID` no hashing), `idmap_autorid` (hash with collision-handling `idmap_autorid.c`), `idmap_ad` (RFC 2307 `idmap_ad.c:idmap_ad_unixids_to_sids`), `idmap_tdb2` (allocating, not stable across hosts), `smb.conf` `idmap config * : backend = rid|autorid|ad|tdb2` syntax.

**Open questions**:

- Drop POSIX UIDs entirely (use UUIDs everywhere — `chown` by UUID, NFSv4 with `sec=krb5p` and `nfsmapid`-equivalent), accepting that this requires re-architecting every POSIX tool that assumes UID/GID integers?
- Standardize on SSSD's slice algorithm across all platforms (Linux + macOS + Windows-as-client), accepting that macOS `dsconfigad`-bound Macs cannot coexist with framework-managed Macs without UID remapping?
- Adopt RFC 2307 as the default (`uidNumber`/`gidNumber` populated in AD by the framework's enrollment flow), accepting the operational burden of UID allocation in the directory?

**Cross-capability impact**:

- Affects: PC-080 (DFS-N — file ownership across replicated shares requires consistent UID mapping), PC-084 (Offline Files — CSC cache preserves UIDs; cross-platform CSC requires consistent mapping).
- Affected by: PC-013 (Core Directory — `uidNumber`/`gidNumber` storage in AD; the Core Directory must support RFC 2307 schema extension).

---

### PC-090 — Heimdal vs MIT Kerberos on Linux/macOS have subtle incompatibilities

**Capability**: Client SDK
**Severity**: medium
**Cross-platform**: Linux / macOS

**Problem statement**:

Two Kerberos implementations dominate the open-source world: MIT krb5 (https://github.com/krb5/krb5, used by SSSD, FreeIPA, RHEL, Ubuntu) and Heimdal (https://github.com/heimdal/heimdal, used by Samba's bundled Kerberos, Apple's macOS system Kerberos, and Debian's Heimdal packages). The two are wire-compatible at the RFC 4120 protocol level (both speak MS-KILE profile against AD KDCs) but have subtle incompatibilities at the API, ticket-cache, and PAC-parsing layers. SSSD's `krb5_child` helper uses MIT krb5's `krb5_get_init_creds_password` / `krb5_get_init_creds_keytab`. Samba's `source3/libads/kerb_util.c:ads_keytab_add_entry` uses Heimdal's `krb5_kt_add_entry`. Apple's macOS ships Heimdal at `/usr/lib/libkerberos.dylib` and provides an MIT-compatible shim at `/usr/lib/libMITKerberosShim.dylib` that redirects MIT-style GSSAPI calls to Heimdal, per [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) and [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md).

The incompatibilities that bite in mixed environments: (a) PAC parsing — Heimdal's `lib/krb5/pac.c` and MIT's `lib/krb5/krb/pac.c` have minor ordering differences in the `PAC_INFO_BUFFER` array walk, particularly around the `PAC_REQUESTER` (introduced Server 2016) and `PAC_FULL_CHECKSUM` (also Server 2016+) signature buffers — Heimdal's older fork (macOS ~2014-era, see PC-105) does not validate `PAC_FULL_CHECKSUM` and will accept tickets that MIT rejects; (b) ticket cache types — MIT supports `FILE:`, `DIR:`, `KEYRING:`, `KCM:`; Heimdal supports `FILE:`, `MEMORY:`, `API:` (keychain-backed on macOS), `KCM:` (via plugin); a ticket acquired by MIT's `kinit` into `FILE:/tmp/krb5cc_502` is readable by Heimdal, but a ticket acquired by Heimdal into `API:Initialdefaultcache` (keychain) is NOT readable by MIT without the shim; (c) canonicalization — MIT's `krb5_canonicalize` flag handling differs from Heimdal's in cross-realm scenarios, causing S4U2Self/S4U2Proxy flows to produce different `cname` values; (d) `kvno` and keytab formats — MIT keytab format (`/etc/krb5.keytab`) and Heimdal keytab format are byte-compatible at the KVNO level but differ in how they store enctype-specific key derivation parameters.

The framework must standardize on one Kerberos implementation across all platforms, with the other as a compat shim. MIT krb5 is the more widely deployed (every RHEL, Ubuntu, Debian, FreeBSD install) and more actively maintained (regular CVE patches, RFC 6806 FAST and RFC 4556 PKINIT reference implementation). Heimdal is bundled with Samba (for Samba AD-DC) and with macOS (as the system Kerberos). The recommendation is MIT krb5 everywhere, with Heimdal retained only where Samba requires it (Samba AD-DC bundles Heimdal) and on macOS where Apple's PSSO Extension uses the system Heimdal.

**Impact**:

Mixed-Kerberos environments hit subtle interop bugs: PAC validation failures (Heimdal accepts tickets MIT rejects), ticket cache incompatibilities (MIT `kinit` ticket not visible to Heimdal `klist` without shim), S4U2Self/S4U2Proxy canonicalization mismatches (constrained delegation produces different `cname`), and keytab format quirks. Quantified: ~2-5% of enterprise mixed-OS deployments experience at least one of these per year, typically requiring vendor support escalation.

**Constraints**:

- Must support MIT krb5 as the primary Kerberos implementation on Linux (SSSD already does).
- Must support Heimdal on macOS (Apple's PSSO Extension uses system Heimdal; cannot replace).
- Must support Heimdal on Samba AD-DC (Samba bundles Heimdal; cannot replace without forking Samba).
- Must provide a compat shim where MIT and Heimdal must coexist (macOS `libMITKerberosShim.dylib` is the reference).
- Must document PAC parsing differences and ensure the framework's PAC validator (in the KDC) accepts tickets from both MIT and Heimdal clients.

**Cross-platform considerations**:

- **Windows**: Uses MS-KILE in `kdcsvc.dll`; not affected by MIT vs Heimdal.
- **macOS**: Ships Heimdal as the system Kerberos. The framework's macOS client must use the system Heimdal (via PSSO Extension); cannot install MIT krb5 alongside without conflicts.
- **Linux**: SSSD uses MIT krb5. The framework's Linux client should use MIT krb5. Samba AD-DC (if deployed) bundles Heimdal — the framework must support both on the same host (Samba's Heimdal in `/opt/samba/private/` separate from system MIT in `/usr/lib/`).
- **Cross-platform consistency**: PAC parsing must produce identical results on every platform. The framework's PAC validator should be a shared library (Rust or C) that all platforms use, rather than relying on each Kerberos implementation's bundled parser.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — RFC 4120 ASN.1 message structures, PA-DATA type table (PA-ENC-TIMESTAMP, PA-FX-FAST, PA-PK-AS-REQ for PKINIT, PA-SUPPORTED-ENCTYPES), `EncTicketPart` `authorization-data` field where the PAC lives (AD-IF-RELEVANT wrapping AD-WIN2K-PAC type 128), MS-KILE profile extensions.
- [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md) — macOS system Heimdal at `/usr/lib/libkerberos.dylib`, `libMITKerberosShim.dylib` redirecting MIT GSSAPI calls to Heimdal, Homebrew Samba's MIT Kerberos stack conflicting with system Heimdal, keytab path conflicts (`/etc/krb5.keytab` vs `/opt/homebrew/etc/krb5.keytab`).

**Open questions**:

- Standardize on MIT krb5 everywhere (including contributing patches to Samba to support MIT as an alternative to bundled Heimdal — Samba has partial MIT support since 4.8 but full migration is incomplete)?
- Contribute Apple's Heimdal fork upstream to reduce divergence from mainline Heimdal, accepting that Apple's fork has not tracked upstream since ~2014?
- Write a unified PAC validator (shared Rust/C library) that all platforms use, bypassing each Kerberos implementation's bundled parser?

**Cross-capability impact**:

- Affects: PC-023 (KDC MS-KILE profile — the KDC's PAC validator must accept tickets from both MIT and Heimdal clients), PC-086 (PSSO Extension — uses system Heimdal on macOS; the framework's macOS strategy inherits the Heimdal fork status), PC-105 (Heimdal macOS fork tracking upstream ~2014 — the same root cause).
- Affected by: PC-013 (Core Directory — PAC contents flow from the directory's `tokenGroups` and `msDS-ResultantPSO` attributes; the PAC validator must consume these correctly regardless of MIT vs Heimdal).

---

### PC-091 — Domain join (`realm join`/`adcli`/`net ads join`/`dsconfigad`) is fragmented

**Capability**: Client SDK
**Severity**: medium
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

Domain join is the process of (a) creating a computer object in AD under `CN=<NETBIOS>$,CN=Computers,<domain DN>` (or a specified OU) with `userAccountControl = 4096` (WORKSTATION_TRUST_ACCOUNT), (b) setting the machine-account password in `unicodePwd` (the same attribute that stores user NT-hashes), (c) writing the machine-account key to `/etc/krb5.keytab` (Linux) or `/etc/krb5.keytab` + System keychain (macOS) or LSA secret (Windows), and (d) registering the host's SPNs (`HOST/<fqdn>`, `HOST/<netbios>`, `RestrictedKrbHost/<fqdn>`, `RestrictedKrbHost/<netbios>`) on the computer object's `servicePrincipalName` attribute. The four major join tools do this differently, per [`09-linux-equivalents/06-realmd-join-flow.md`](../docs/09-linux-equivalents/06-realmd-join-flow.md), [`09-linux-equivalents/05-samba-tool-net-ads.md`](../docs/09-linux-equivalents/05-samba-tool-net-ads.md), and [`08-macos-equivalents/02-dscl-dsconfigad.md`](../docs/08-macos-equivalents/02-dscl-dsconfigad.md).

`realm join` (from `realmd` https://gitlab.freedesktop.org/realmd/realmd, a D-Bus system service `org.freedesktop.realmd`) is the Linux wrapper: it discovers the domain via DNS SRV + CLDAP ping + anonymous LDAP bind, then dispatches to a provider-specific helper (`adcli join` for the `ad` provider, `ipa-client-install` for `ipa`, `samba-tool domain join` for `samba-member`). `adcli join` (https://gitlab.freedesktop.org/realmd/adcli) creates the computer object via LDAP Add, sets the machine password, and writes the keytab with the four SPN principals (`HOSTNAME$@REALM`, `HOST/<fqdn>@REALM`, `HOST/<netbios>@REALM`, `RestrictedKrbHost/<fqdn>@REALM`) with all four enctypes (aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96, arcfour-hmac-md5). `net ads join` (Samba's `source3/utils/net_ads.c:net_ads_join`) does the same but writes `/etc/samba/smb.conf` and `/var/lib/samba/secrets.tdb` alongside the keytab. `dsconfigad` (macOS `/usr/sbin/dsconfigad`) performs the LDAP Add + keytab write + System keychain storage + `opendirectoryd` AD plug-in configuration plist at `/Library/Preferences/DirectoryService/ActiveDirectoryDomains.plist`, with 13+ flags (`-mobile`, `-localhome`, `-useuncpath`, `-shell`, `-preferred`, `-groups`, `-namespace`, `-enablesso`, `-packetsign`, `-packetencrypt`, `-passinterval`, `-passchange`). Windows `Add-Computer` cmdlet (calling `NetJoinDomain` in `netapi32.dll`) is the reference implementation, with OU placement, OS-info reporting (`operatingSystem`, `operatingSystemVersion` attributes), and machine-account password rotation every 30 days by default.

The differences that bite: (a) OS-info reporting — `adcli` writes `operatingSystem` and `operatingSystemVersion` from `--os-name`/`--os-version` flags; `net ads join` writes them from `osName`/`osVer` flags; `dsconfigad` writes them from the macOS version; `realm join` does not write them unless explicitly configured via `/etc/realmd.conf` `[active-directory] os-name` / `os-version`; (b) keytab enctypes — `adcli` writes all four enctypes by default; `net ads join` writes all four; `dsconfigad` writes the same; but `ipa-client-install` writes only AES enctypes (no RC4); (c) OU placement — `realm join` accepts `--computer-ou`, `net ads join` accepts `createcomputer=`, `dsconfigad` accepts `-ou`, but the syntax differs (DN vs path); (d) SPN registration — all four register `HOST/` and `RestrictedKrbHost/` but only `net ads join` and `dsconfigad` register `cifs/` for SMB servers; (e) post-join PAM/NSS configuration — `realm join` calls `pam-auth-update` (Debian) or `authselect` (RHEL) automatically, `net ads join` does not, `dsconfigad` does not (relies on the AD plug-in).

**Impact**:

Join procedures vary by OS; automation is per-OS. A 3-OS deployment requires three Ansible playbooks (or three MDM profiles), each with platform-specific error handling. The divergence also affects AD-side reporting: `Get-ADComputer -Filter * -Properties operatingSystem,operatingSystemVersion` produces inconsistent data when some hosts were joined with `realm join` (no OS info) and others with `dsconfigad` (macOS version). Quantified: in a typical 3-OS enterprise, ~30% of computer objects have missing or incorrect `operatingSystem` attributes due to join-tool divergence.

**Constraints**:

- Must support computer-object creation (LDAP Add), machine-account password set (`unicodePwd`), keytab write (all four enctypes), SPN registration (`HOST/`, `RestrictedKrbHost/`, plus service-specific SPNs like `cifs/`, `HTTP/`, `nfs/`).
- Must produce consistent `operatingSystem`, `operatingSystemVersion`, `operatingSystemServicePack` attributes on every platform.
- Must support OU placement via a unified flag (e.g. `--ou 'OU=LinuxServers,DC=corp,DC=example,DC=com'`).
- Must trigger platform-specific post-join configuration (PAM/NSS on Linux, AD plug-in on macOS, Group Policy Client on Windows) automatically.
- Must not break existing `realm join` / `net ads join` / `dsconfigad` workflows — the framework's join tool should be additive, supporting all four invocations.

**Cross-platform considerations**:

- **Windows**: `Add-Computer -DomainName corp.example.com -Credential (Get-Credential) -OUPath 'OU=...,DC=...' -PassThru` is the reference. The framework's Windows client should wrap this.
- **macOS**: `dsconfigad -a <name> -domain <domain> -ou <dn> -u <user> -p <password>` with 13+ flags. The framework's macOS client should wrap this or replace it with a fresh join tool that writes the same plists.
- **Linux**: `realm join` (preferred, wraps `adcli`) or `net ads join` (Samba). The framework's Linux client should wrap `realm join` or replace it with a fresh join tool that writes the same config files.
- **Cross-platform consistency**: A unified join protocol (likely OAuth2-style device enrollment, similar to Windows Autopilot or Apple DEP) would eliminate the per-OS divergence. The framework's join tool should accept a single command (e.g. `framework-join --domain corp.example.com --user admin --ou 'OU=...'`) and produce identical AD-side state on every platform.

**KB references**:

- [`09-linux-equivalents/06-realmd-join-flow.md`](../docs/09-linux-equivalents/06-realmd-join-flow.md) — `realmd` D-Bus service `org.freedesktop.realmd`, `realm discover` (DNS SRV + CLDAP + anonymous LDAP), `realm join` dispatch to `adcli`/`ipa-client-install`/`samba-tool`, post-join config writes to `/etc/sssd/sssd.conf` + `/etc/krb5.conf` + `/etc/nsswitch.conf` + PAM stack via `pam-auth-update`/`authselect`/`pam-config`, `/etc/realmd.conf` `[active-directory]` `os-name`/`os-version` keys.
- [`09-linux-equivalents/05-samba-tool-net-ads.md`](../docs/09-linux-equivalents/05-samba-tool-net-ads.md) — `net ads join` (`source3/utils/net_ads.c:net_ads_join`), `net ads testjoin`, `net ads changetrustpw` (machine-account password rotation), `net ads keytab create` / `net ads keytab add <SPN>` for SPN registration, `samba-tool domain exportkeytab` (DC-only keytab export), `setspn` equivalent via `samba-tool spn add/list/delete`.
- [`08-macos-equivalents/02-dscl-dsconfigad.md`](../docs/08-macos-equivalents/02-dscl-dsconfigad.md) — `dsconfigad -a <name> -domain <domain> -ou <dn> -u <user> -p <password>` with 13+ flags (`-mobile`, `-localhome`, `-useuncpath`, `-shell`, `-preferred`, `-groups`, `-namespace`, `-enablesso`, `-packetsign`, `-packetencrypt`, `-passinterval`, `-passchange`), CLDAP DC locator, keytab write to `/etc/krb5.keytab` + System keychain, `opendirectoryd` AD plug-in config plist at `/Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/<domain>.plist`, `ActiveDirectoryDomains.plist` master list.

**Open questions**:

- Adopt modern device enrollment (Windows Autopilot, Apple DEP/ABM, Linux cloud-init-style) as the unified join protocol, with per-OS adapters that translate enrollment events into LDAP Add + keytab write + SPN registration?
- Provide a framework-native join tool (`framework-join`) that runs identically on Windows/macOS/Linux (Go binary with platform-specific implementations of LDAP Add, keytab write, SPN registration), replacing `realm join`/`net ads join`/`dsconfigad`?
- Reuse `realm join` on Linux (avoiding a parallel join stack) and write fresh join tools for Windows and macOS, accepting platform-divergent internals behind a unified CLI?

**Cross-capability impact**:

- Affects: PC-085 (universal client SDK — the join tool is part of the SDK surface), PC-089 (ID mapping — join time is when ID mapping config is set; a unified join tool would write consistent ID-mapping config across platforms).
- Affected by: PC-013 (Core Directory — computer-object creation requires the same `userAccountControl = 4096`, `unicodePwd`, `servicePrincipalName` writes that AD supports natively).

---

### PC-092 — PAM stack varies by distro (Debian/Ubuntu vs RHEL/Fedora vs SUSE)

**Capability**: Client SDK
**Severity**: medium
**Cross-platform**: Linux

**Problem statement**:

Linux PAM (Pluggable Authentication Modules, configured in `/etc/pam.d/<service>` or `/etc/pam.conf`) runs four phases — `auth` (verify identity), `account` (check account validity), `password` (update password), `session` (pre/post-login setup) — across a stack of modules (`pam_sss.so` for SSSD, `pam_winbind.so` for Winbind, `pam_krb5.so` for MIT Kerberos, `pam_ldap.so`/`pam_ldapd.so` for nslcd, `pam_unix.so` for local, `pam_mkhomedir.so`/`pam_oddjob_mkhomedir.so` for home creation, `pam_faillock.so` for account lockout, `pam_access.so` for host-based access). The three major distro families generate these stacks via different tools with different file layouts, per [`09-linux-equivalents/10-pam-nss-stack.md`](../docs/09-linux-equivalents/10-pam-nss-stack.md).

Debian/Ubuntu uses `pam-auth-update` (`/usr/sbin/pam-auth-update` from the `libpam-runtime` package), which reads profile metadata from `/usr/share/pam-configs/*` (e.g. `/usr/share/pam-configs/sssd` with `Name: SSS authentication`, `Priority: 254`, `Auth-Type: Primary`, `Auth: [success=ok default=ignore] pam_sss.so use_first_pass`, etc.) and writes `/etc/pam.d/common-auth`, `common-account`, `common-password`, `common-session`. Each service file (`/etc/pam.d/login`, `/etc/pam.d/sshd`, `/etc/pam.d/su`, `/etc/pam.d/sudo`, etc.) uses `@include common-auth` to pull in the shared config. RHEL/Fedora/Rocky uses `authselect` (`/usr/bin/authselect` from the `authselect` package), which ships profiles in `/usr/share/authselect/default/` (`sssd`, `winbind`, `nis`, `minimal`, `local`) and writes `/etc/pam.d/system-auth`, `/etc/pam.d/password-auth`, `/etc/pam.d/postlogin`, `/etc/pam.d/fingerprint-auth`, `/etc/pam.d/smartcard-auth`, plus `/etc/nsswitch.conf`. Profile features are added via `with-*` flags (`with-mkhomedir`, `with-sudo`, `with-fingerprint`, `with-smartcard`, `with-smartcard-required`, `with-silent-lastlog`, `with-faillock`, `with-pamaccess`, `with-nullok`). SUSE/openSUSE uses `pam-config` (`/usr/sbin/pam-config`), which writes `/etc/pam.d/common-{auth,account,password,session}-pc` (the `-pc` suffix is the auto-generated file; the bare `common-*` files `@include common-*-pc`).

The differences that bite: (a) file layout — Debian's `common-*` vs RHEL's `system-auth`/`password-auth` vs SUSE's `common-*-pc`; a tool that edits `common-auth` on Debian breaks SUSE and is ignored on RHEL; (b) module ordering — Debian's `pam_sss.so` is `[success=1 default=ignore]` after `pam_unix.so`; RHEL's is `sufficient` after `pam_unix.so nullok try_first_pass`; SUSE's is `[success=ok default=ignore]` — the control values produce different fallback behavior when SSSD is unreachable; (c) feature flags — Debian's `pam-auth-update` uses debconf-driven profile selection; RHEL's `authselect` uses `with-*` flags; SUSE's `pam-config` uses `--add --<feature>` syntax — the same logical feature (e.g. "enable smartcard") requires three different invocations; (d) home directory creation — Debian uses `pam_mkhomedir.so` (runs in user session); RHEL uses `pam_oddjob_mkhomedir.so` (D-Bus `oddjobd` running as root, required for SELinux enforcing); SUSE uses `pam_mkhomedir.so` with `umask=0022 skel=/etc/skel` — three different mechanisms for the same feature.

**Impact**:

PAM stack management is distro-specific. An Ansible role that configures PAM for SSSD on RHEL will not work on Debian or SUSE without per-distro conditionals. Quantified: a typical enterprise Ansible role for "join Linux to AD and configure PAM" contains ~150 lines of per-distro logic for 3 distro families, and the logic must be re-tested on every distro upgrade.

**Constraints**:

- Must support `pam_sss.so` (or framework-equivalent module) on all three distro families.
- Must support `pam_mkhomedir.so` (Debian/SUSE) and `pam_oddjob_mkhomedir.so` (RHEL with SELinux).
- Must generate distro-correct PAM files via the distro-native tool (`pam-auth-update` on Debian, `authselect` on RHEL, `pam-config` on SUSE) — direct file editing is fragile and breaks on package updates.
- Must support `pam_faillock.so` for account lockout (the Linux equivalent of AD's "Account lockout threshold" GPO).
- Must support `pam_access.so` (`/etc/security/access.conf`) for host-based access control as an alternative to SSSD's GPO access.

**Cross-platform considerations**:

- **Windows**: No PAM equivalent. LSASS handles auth phases internally. The framework's Windows client doesn't touch PAM.
- **macOS**: Uses PAM (the same Linux-PAM source compiled for Darwin) but the backend is `opendirectoryd` via `pam_odl.so`. The PAM stack is much simpler (`/etc/pam.d/authorization`, `/etc/pam.d/login`, `/etc/pam.d/sudo` with `auth sufficient pam_odl.so`). The framework's macOS client doesn't need to generate PAM stacks.
- **Linux**: Three distro families, three PAM generators. The framework's Linux client must detect the distro and call the appropriate generator.
- **Cross-platform consistency**: The framework's policy engine should compile a unified "PAM policy" to `pam-auth-update` calls (Debian), `authselect select` calls (RHEL), and `pam-config` calls (SUSE). The source policy is unified; the compilation target is distro-specific.

**KB references**:

- [`09-linux-equivalents/10-pam-nss-stack.md`](../docs/09-linux-equivalents/10-pam-nss-stack.md) — `pam-auth-update` (`/usr/sbin/pam-auth-update`, reads `/usr/share/pam-configs/*`, writes `/etc/pam.d/common-{auth,account,password,session}`), `authselect` (`/usr/bin/authselect`, profiles in `/usr/share/authselect/default/`, writes `system-auth`/`password-auth`/`postlogin`/`fingerprint-auth`/`smartcard-auth`, feature flags `with-mkhomedir`/`with-sudo`/`with-fingerprint`/`with-smartcard`/`with-smartcard-required`/`with-faillock`/`with-pamaccess`/`with-nullok`), `pam-config` (SUSE, writes `common-*-pc`), `pam_sss.so` parameter reference (`use_first_pass`/`try_first_pass`/`forward_pass`/`use_authtok`/`ignore_unknown_user`/`ignore_authinfo_unavail`/`domains=`/`renew_context=`), `pam_winbind.so` parameter reference (`require_membership_of=`/`krb5_auth`/`krb5_ccache_type=`/`cached_login`), `pam_oddjob_mkhomedir.so` vs `pam_mkhomedir.so` distinction.
- [`10-comparison-matrices/04-auth-flow-comparison.md`](../docs/10-comparison-matrices/04-auth-flow-comparison.md) — 8-phase login flow side-by-side showing Windows LSASS (no PAM), macOS PAM (`pam_odl.so` backend via OpenDirectory), Linux SSSD PAM (`pam_sss.so` via `/var/lib/sss/pipes/pam`), Linux Winbind PAM (`pam_winbind.so` via `/run/samba/winbindd_privileged/pipe`), per-platform ticket cache locations and renewal semantics, behavioral differences in ticket purge on logoff (Windows purges; SSSD does NOT auto-purge — renewal daemon keeps TGT across sessions).

**Open questions**:

- Provide a framework-native PAM module (`pam_framework.so`) + a PAM profile generator that targets all three distro families, replacing `pam_sss.so`/`pam_winbind.so` with a single module?
- Adopt `authselect` as the standard PAM generator across all distros (it's available on Debian via the `authselect` package), accepting that Debian's native `pam-auth-update` workflow would be bypassed?
- Use Ansible/Puppet as the PAM configuration layer, accepting that PAM stack management remains distro-specific at the Ansible role level?

**Cross-capability impact**:

- Affects: PC-085 (universal client SDK — the SDK's Linux client must install PAM modules and configure the PAM stack), PC-088 (SSSD GPO access — `ad_gpo_access_control` runs via `pam_sss.so account` phase; the PAM stack must include `pam_sss.so` in `account`).
- Affected by: PC-050 (Policy Engine — the Policy Engine's distribution model determines whether PAM config is pulled via SMB (GPO-style), HTTPS (modern), or D-Bus (local agent)).

---

### PC-093 — Kerberos ticket cache type varies (FILE:, KEYRING:, KCM:, API: on macOS)

**Capability**: Client SDK
**Severity**: medium
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

Kerberos ticket caches (ccaches) come in five types with different persistence, security, and renewal semantics. Linux SSSD defaults to `KEYRING:persistent:<uid>` (kernel keyring, per-UID persistent across sessions, mode 600, accessible only to the owning UID and root). Linux systemd-style KCM (`/run/.krb5_cc_uid_<uid>` over D-Bus, backed by `sssd-kcm` or `kcm` daemon) is the modern cross-distro default in Fedora 32+ and Ubuntu 22.04+ — it supports renewal by a system daemon, multi-process ticket access, and cleaner session lifecycle. `FILE:/tmp/krb5cc_<uid>` is the legacy default (kernel 2.6-era), still used by older distros and by applications that explicitly set `KRB5CCNAME=FILE:...`. macOS PSSO Extension defaults to `API:Initialdefaultcache` (Heimdal's in-process store backed by the user's keychain at `~/Library/Keychains/login.keychain-db`, persisted across reboot, visible via `klist -v`). Windows stores tickets in LSA in-process memory (no file), accessed via `LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage)`, per [`10-comparison-matrices/04-auth-flow-comparison.md`](../docs/10-comparison-matrices/04-auth-flow-comparison.md) and [`08-macos-equivalents/05-kerberos-sso-extension.md`](../docs/08-macos-equivalents/05-kerberos-sso-extension.md).

The cache-type mismatches cause silent auth failures: an application that reads `KRB5CCNAME` and tries to open `KEYRING:persistent:502` will succeed on Linux but fail on macOS (no KEYRING type on macOS); an application that expects `FILE:/tmp/krb5cc_502` will fail on systemd-style KCM hosts (no file at that path); an application that uses the MIT `krb5_cc_default()` API will get whatever the system default is, which may not be where PSSO/SSSD wrote the TGT. The cross-platform SDK must abstract cache type behind a unified API: `sdk.get_ticket_cache()` returns a handle that works regardless of underlying type. The framework should standardize on KCM (`sssd-kcm` or equivalent) on Linux for cross-distro consistency, and on `API:Initialdefaultcache` (keychain-backed) on macOS for PSSO integration. Windows uses LSA in-memory; the SDK's Windows implementation wraps `KerbRetrieveEncodedTicketMessage`.

The renewal semantics also differ. SSSD's `krb5_renew_interval = 1h` triggers renewal at 50% of TGT lifetime via `sssd-kcm` (KCM) or the SSSD `krb5_child` (KEYRING/FILE). macOS PSSO Extension renews at 75% of TGT lifetime via Heimdal's `krb5_get_renewed_creds`. Windows LSA auto-renews at ~50% of lifetime. The framework's renewal daemon should run on every platform with consistent timing, abstracting the platform-native renewal mechanism.

**Impact**:

Cache-type mismatches cause silent auth failures. Quantified: ~5-10% of cross-platform SDK integration bugs trace to cache-type assumptions in application code (e.g. `klist -v` works in the developer's terminal but fails in a service running under a different UID with a different cache type). The operational cost is debugging time per incident, typically 2-4 hours.

**Constraints**:

- Must support KEYRING (Linux kernel keyring), KCM (Linux D-Bus daemon), FILE (legacy), API: (macOS keychain), and LSA in-memory (Windows).
- Must support auto-renewal at ~50-75% of TGT lifetime, abstracting the platform-native renewal mechanism.
- Must provide a unified cache abstraction in the SDK: `sdk.get_ticket_cache()` returns a handle that works on every platform.
- Must support `klist`-equivalent CLI on every platform (use the platform-native `klist` on macOS/Linux; provide a Windows `klist.exe` equivalent if the OS one is insufficient).
- Must handle cache-type changes gracefully (e.g. if the user switches from FILE to KCM, the framework should migrate existing tickets).

**Cross-platform considerations**:

- **Windows**: LSA in-memory; no file. `klist` (built-in since Windows 7) reads from LSA via `LsaCallAuthenticationPackage`. The SDK wraps this.
- **macOS**: PSSO Extension uses `API:Initialdefaultcache` (keychain-backed Heimdal store). The SDK uses the system `klist`/`kinit`/`kdestroy` binaries.
- **Linux**: SSSD defaults to `KEYRING:persistent:<uid>`; modern distros default to KCM. The SDK should support both, with KCM as the recommended default for cross-distro consistency.
- **Cross-platform consistency**: A unified cache abstraction (`sdk.get_ticket_cache()`) hides the type. The framework's renewal daemon runs identically on every platform, calling the platform-native renewal primitive under the hood.

**KB references**:

- [`08-macos-equivalents/05-kerberos-sso-extension.md`](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) — `API:Initialdefaultcache` cache type (keychain-backed Heimdal store at `~/Library/Keychains/login.keychain-db`), auto-renewal at 75% of TGT lifetime via `krb5_get_renewed_creds`, `sso_util cache -l` / `-r` / `-d` CLI for cache list/refresh/destroy, `KRB5CCNAME=FILE:...` override for file-based cache.
- [`09-linux-equivalents/01-sssd-ad-provider.md`](../docs/09-linux-equivalents/01-sssd-ad-provider.md) — SSSD `krb5_ccachedir = /run/user/%u/krb5cc` config, `krb5_renew_interval = 1h` renewal timing, `KEYRING:persistent:<uid>` default, `sssd-kcm` responder as KCM daemon, `krb5_store_password_if_offline = true` for offline cache.

**Open questions**:

- Adopt KCM (`sssd-kcm`) as the Linux standard + `API:` on macOS + LSA on Windows, accepting that the cache types differ but the SDK abstraction hides it?
- Provide a unified cache abstraction (`sdk.get_ticket_cache()`) that returns a handle with `get_tickets()`, `renew()`, `destroy()` methods, abstracting the platform-native cache type?
- Migrate existing FILE: caches to KCM automatically during framework enrollment, or document the migration and require admin intervention?

**Cross-capability impact**:

- Affects: PC-085 (universal client SDK — the cache abstraction is part of the SDK surface), PC-086 (PSSO Extension — the macOS cache type is determined by PSSO's `API:Initialdefaultcache` choice).
- Affected by: PC-023 (KDC MS-KILE profile — the KDC's TGT lifetime and renewable lifetime determine renewal timing; the cache must renew before expiry), PC-090 (Heimdal vs MIT — the cache type compatibility matrix is partly determined by Kerberos implementation).

---

## Cross-capability impact

The Client SDK's nine problems cluster around three architectural tensions:

1. **Unified API surface across divergent platform stacks** (PC-085, PC-086, PC-091, PC-092, PC-093): The framework must provide a single API that hides Windows SSPI/Wldap32/NetAPI, macOS OpenDirectory/Authorization/PSSO, and Linux SSSD/Winbind/PAM/NSS differences. The unified SDK is the entire value proposition of the framework on the client side.

2. **Cross-platform identity mapping** (PC-089, PC-090, PC-093): SID-to-UID mapping, Kerberos implementation choice (MIT vs Heimdal), and ticket cache type must be consistent across hosts and platforms. Without this, file ownership breaks, PAC validation fails, and tickets acquired on one platform don't work on another.

3. **Policy application completeness** (PC-087, PC-088): macOS Jamf Connect's password sync fragility and SSSD's partial GPO coverage both stem from the same root cause: no platform provides full GPO-equivalent policy application. The framework must either extend SSSD (Linux) and PSSO (macOS) to fill the gaps, or write a fresh policy application layer.

Cross-capability impacts that flow into Client SDK from other capabilities:

- From **KDC** (PC-023, MS-KILE profile): The SDK's Kerberos calls must produce wire-compatible AS-REQ/TGS-REQ; the KDC's PAC contents flow through to the SDK's group resolution.
- From **Auth Provider** (PC-029, NTLM relay mitigation): The SDK's SMB and LDAP session setup must use the Auth Provider's signing/channel-binding posture.
- From **Policy Engine** (PC-050, policy distribution): The SDK's policy application API must match the Policy Engine's distribution model (SMB-pull for GPO compat, HTTPS-pull for modern, D-Bus for local agent).
- From **Cert Service** (PC-067, enrollment protocols): The SDK's cert enrollment API must support MS-WCCE/MS-XCEP (AD CS interop) or ACME/EST (modern), matching the Cert Service's server-side surface.
- From **File Gateway** (PC-078, SMB 3.1.1): The SDK's SMB client wrapper must negotiate SMB 3.1.1 with pre-auth integrity and AES-GCM, matching the File Gateway's server-side floor.
- From **Federation Gateway** (PC-071, SAML/OIDC): The SDK's token cache and refresh must support SAML 2.0, OAuth2/OIDC, and WS-Federation tokens issued by the Federation Gateway.

## Open research questions specific to this capability

1. **SDK architecture** — Rust core + auto-generated bindings (cbindgen for C, swift-bridge for Swift, pyo3 for Python, gopy for Go) or hand-written bindings per language? What is the FFI story for platforms that don't natively support the chosen core language (e.g. iOS, Android, embedded Linux)?

2. **Kerberos implementation strategy** — Standardize on MIT krb5 everywhere (including macOS, replacing system Heimdal), or accept Heimdal on macOS and Samba AD-DC while using MIT on Linux? If the former, how to interoperate with PSSO Extension (which uses system Heimdal)?

3. **ID mapping standard** — Drop POSIX UIDs entirely (use UUIDs everywhere), standardize on SSSD's slice algorithm across all platforms, or adopt RFC 2307 (`uidNumber`/`gidNumber` in AD) as the default? What is the migration path for existing SSSD/Winbind/PBIS deployments?

4. **Domain join protocol** — Adopt OAuth2-style device enrollment (Windows Autopilot, Apple DEP, Linux cloud-init) as the unified join protocol, or provide a framework-native `framework-join` CLI that wraps the platform-native tools? What is the bootstrap story for first-enrollment (no machine account, no keytab, no Kerberos)?

5. **PAM stack management** — Provide a framework-native PAM module (`pam_framework.so`) + a PAM profile generator that targets all three distro families, or reuse `pam_sss.so` and accept SSSD's PAM stack as the framework's Linux policy application layer?

6. **Ticket cache abstraction** — Provide a unified cache abstraction (`sdk.get_ticket_cache()`) that returns a handle with `get_tickets()`, `renew()`, `destroy()` methods, abstracting KEYRING/KCM/FILE/API:/LSA? Or use the platform-native `klist`/`kinit`/`kdestroy` CLIs and accept that the SDK doesn't own the cache?

7. **macOS PSSO integration** — Auto-configure PSSO via the framework's macOS client SDK on first enrollment (running `sso_util configure`), or require MDM-delivered configuration? If the former, what is the bootstrap story (PSSO requires an MDM profile to install the `Authentication_SSO.appex` extension)?
