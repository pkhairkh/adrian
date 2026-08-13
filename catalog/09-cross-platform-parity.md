---
title: Cross-Platform Parity — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, cross-platform-parity, framework-design, gap-analysis, macos, linux, windows, ntLM, gpo, mdm, freeipa, rodc]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./07-file-gateway.md
  - ./08-client-sdk.md
  - ./10-operations.md
  - ./14-cross-platform-parity-matrix.md
  - ./13-open-research-questions.md
last_updated: 2026-08-13
---

# Cross-Platform Parity — Problem Catalog

## Capability definition

Ensure that every feature works equivalently on Windows, macOS, and Linux. Track parity gaps. Define platform-specific implementations where required. Not inherited from AD — AD is Windows-only; parity is a new requirement for the framework. Cross-cutting concern (not a service): defines parity requirements for every capability. All capabilities must satisfy parity requirements.

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-094 | macOS has no native NTLM support; legacy apps fail | high | macOS / Linux |
| PC-095 | macOS Configuration Profiles vs Windows GPO vs Linux SSSD-conf have no unified authoring | blocker | Windows / macOS / Linux |
| PC-096 | macOS DDM (Declarative Device Management) is the future but not yet full-coverage | low | macOS |
| PC-097 | macOS FileVault recovery key escrow goes to Apple or MDM, not AD | medium | Windows / macOS / Linux |
| PC-098 | LAPS (local admin password rotation) has no macOS/Linux native equivalent | medium | Windows / macOS / Linux |
| PC-099 | SSSD/Winbind/PBIS are alternative Linux stacks; migration between them is painful | medium | Linux |
| PC-100 | macOS OpenDirectory AD plug-in has gaps (GPO, ABE, full DFS-N) | medium | macOS |
| PC-101 | FreeIPA is a separate Linux identity platform with AD cross-forest trust | medium | Linux / cross-platform |
| PC-102 | RODC (Read-Only DC) has no Linux/macOS equivalent | medium | cross-platform |
| PC-103 | OpenLDAP + MIT Kerberos (roll-your-own) is high-effort, low-feature | low | Linux |
| PC-104 | Centrify / PBIS / AdmitMac / DAVE are legacy third-party macOS agents | low | macOS |
| PC-105 | Heimdal Kerberos on macOS is a fork tracking upstream ~2014 | medium | macOS |

## Detailed problem entries

### PC-094 — macOS has no native NTLM support; legacy apps fail

**Capability**: Cross-Platform Parity
**Severity**: high
**Cross-platform**: macOS / Linux

**Problem statement**:

NTLM is the challenge-response authentication protocol carried inside an SPNEGO- or raw-NTLMSSP-branded GSS-API token, with a fixed three-message handshake (NEGOTIATE → CHALLENGE → AUTHENTICATE) where the server issues an 8-byte server challenge and the client returns an HMAC-MD5-derived 24-byte NTLMv2 response plus a variable-length client blob. The protocol authenticates the user without sending the password over the wire, but is considered deprecated because (a) the NT hash (MD4 of UTF-16-LE password) is the entire secret and is reusable offline (pass-the-hash), (b) the protocol has no mutual authentication, (c) NTLM relay attacks are trivial without channel binding, and (d) LM hash compatibility (`NoLMHash = 0`) leaves 14-char passwords crackable, per [`02-protocols/04-ntlm-internals.md`](../docs/02-protocols/04-ntlm-internals.md). The wire signature `NTLMSSP\0` (8 bytes, `0x4E 0x54 0x4C 0x4D 0x53 0x53 0x50 0x00`) is constant across all three messages (Type 1 NEGOTIATE MessageType `0x00000001`, Type 2 CHALLENGE `0x00000002`, Type 3 AUTHENTICATE `0x00000003`).

macOS SMBX client (`smbx.kext`, replacing `smbfs.kext` in macOS 10.14) does not implement NTLMSSP natively. Apple's strategy since macOS 10.14 has been Kerberos-first for SMB 2+ to AD-joined servers, with NTLM fallback only for legacy SMB 1 dialect connections (which are themselves disabled by default). Samba (Homebrew installable) or third-party agents (Centrify DirectControl, now Delinea/CyberArk) provide NTLM on macOS. Apps that hard-require NTLM — legacy SQL Server drivers (pre-ODBC Driver 17), old IIS-integrated apps that haven't been reconfigured for Kerberos, some legacy SMB appliances that don't support Kerberos — fail on macOS without these third-party stacks, per the feature×OS matrix in [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) (NTLM fallback row: macOS native = ✗, macOS MDM = ✗, macOS 3rd-party = partial Admit).

Linux SSSD does NOT implement NTLM either; it relies on Samba's `libsmbclient` and `pam_winbind` for any NTLM need. Samba's `client ntlm auth = disabled` is the modern default. The Linux platforms that need NTLM are file servers (Samba `smbd` accepting NTLM client connections for non-Kerberos clients) and proxy servers (Squid via `ntlm_auth` helper). End-user applications on Linux rarely need NTLM because Kerberos is the universal default for AD-integrated services.

The parity gap: Windows ships NTLM natively (`msv1_0.dll` in `lsass.exe` for both client and server, with `LmCompatibilityLevel` registry under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` controlling NTLMv1/v2 negotiation). macOS and Linux clients lack a first-party NTLM client. The framework must either (a) provide NTLM as opt-in via a cross-platform SSP (likely Samba's `libnss_winbind` or a fresh implementation in the framework's SDK), (b) document NTLM-requiring legacy apps as out of scope and require Kerberos migration, or (c) provide an NTLM compat shim only on the server side (framework SMB server accepts NTLM clients for legacy interop) and require Kerberos on the framework's clients.

**Impact**:

Legacy app compat on macOS is poor. Apps that hard-require NTLM include pre-2018 SQL Server JDBC drivers, IIS apps with Windows Authentication enabled but Kerberos not configured (SPN missing), legacy SMB appliances (NetApp ONTAP 7-mode, old Synology DSM), and some legacy proxy appliances. Quantified: ~5-10% of enterprise macOS users have at least one NTLM-requiring app; without a workaround, those users must run the app in a Windows VM or use Citrix/RDS.

**Constraints**:

- Must support NTLMv2 only (NTLMv1 disabled — `LmCompatibilityLevel >= 3`).
- Must support channel binding for relay defense (TLS `tls-server-end-point` per RFC 5929, computed as `MsvAvChannelBindings` AV_PAIR value `SHA-256(channel_bindings)`).
- Must support SMB signing (mandatory when NTLM is used; NTLM relay mitigation).
- Must NOT enable NTLM by default — opt-in only, with explicit configuration.
- Must provide audit logging of all NTLM usage (per Microsoft's "Restrict NTLM" audit policy equivalent).

**Cross-platform considerations**:

- **Windows**: Native NTLM via `msv1_0.dll`; `LmCompatibilityLevel = 5` (refuse LM & NTLM, accept only NTLMv2) is the modern recommended setting. NTLM is on by default but restrictable via GPO.
- **macOS**: No native NTLM. Framework must provide via Samba winbind (Homebrew) or a fresh NTLM client in the framework's macOS SDK. SMBX cannot be extended to add NTLM.
- **Linux**: Samba provides NTLM via `winbindd` + `ntlm_auth` helper. Framework can reuse Samba's NTLM stack. SSSD does not provide NTLM.
- **Cross-platform consistency**: NTLM posture must be identical across platforms. If the framework enables NTLM on one platform (for legacy interop), it must be enabled consistently on all platforms. The audit log format must be unified.

**KB references**:

- [`02-protocols/04-ntlm-internals.md`](../docs/02-protocols/04-ntlm-internals.md) — NTLMSSP three-message handshake (Type 1/2/3 message structures at offsets 0x00-0x50), `NTLMv2_RESPONSE = HMAC-MD5(NTOWFv2, ServerChallenge + ClientBlob)` formula, `NTOWFv2 = HMAC-MD5(NT-hash, UTF-16-LE(UPPER(user) + Domain))` derivation, `MsvAvChannelBindings` AV_PAIR for TLS channel binding, `LmCompatibilityLevel` registry values 0-5, Samba `ntlm auth = ntlmv2-only` default since 4.5.
- [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) — NTLM fallback row showing macOS Native OD = ✗, macOS Enterprise MDM = ✗, macOS 3rd-party agent = partial (Admit), Linux SSSD = partial (winbind only), Linux Winbind = ✓ (`nmb/winbind`), per-feature deep notes on macOS SMBX's zero native NTLM support.

**Open questions**:

- Provide NTLM via Samba winbind on macOS (Homebrew dependency, separate `winbindd` process) or write a fresh NTLM client in the framework's macOS SDK (Rust or Swift, ~3000 lines for NTLMv2 client + channel binding)?
- Document legacy NTLM-requiring apps as out of scope and require Kerberos migration (register SPNs via `setspn -S`, configure app for Kerberos), accepting that some apps cannot be migrated?
- Provide NTLM compat only on the server side (framework SMB server accepts NTLM clients) and require Kerberos on framework clients, accepting asymmetric posture?

**Cross-capability impact**:

- Affects: PC-029 (NTLM relay mitigation — the framework's NTLM implementation must enforce channel binding and SMB signing).
- Affected by: PC-023 (KDC MS-KILE — Kerberos is the preferred alternative; the KDC must be reachable from every client to enable Kerberos-first posture).

---

### PC-095 — macOS Configuration Profiles vs Windows GPO vs Linux SSSD-conf have no unified authoring

**Capability**: Cross-Platform Parity
**Severity**: blocker
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

The three target platforms use entirely different policy authoring, distribution, and application models. Windows uses GPO: ADMX templates (XML schema in `%SystemRoot%\PolicyDefinitions\*.admx`) define policy settings; the GPO container (GPC) lives in AD at `CN={<guid>},CN=Policies,CN=System,<domain>`; the GPO template (GPT) lives in SYSVOL at `\\<domain>\SysVol\<domain>\Policies\{<guid>}\`; client-side extensions (CSEs) in `%SystemRoot%\System32\` apply the policy (`scecli.dll` for Security, `gppref.dll` for Preferences, `gpsvc.dll` for Registry.pol, etc.); the Group Policy Client service (`gpsvc.dll` in `svchost -k netsvcs`) pulls policy every 90 minutes with 0-30 minute jitter. macOS uses Configuration Profiles (`.mobileconfig`, CMS-signed plist XML at the top level, payload dicts under `PayloadContent` array); ~80 payload types (`com.apple.mobiledevice.passwordpolicy`, `com.apple.security.firewall`, `com.apple.security.FDERecoveryKeyEscrow`, `com.apple.KerberosSSO`, `com.apple.configuration-ext.platform-sso`, `com.apple.applicationaccess.new`, etc.); profiles are pushed via MDM (APNs transport to `*.push.apple.com`, then HTTPS to MDM vendor's `ServerURL`); the `profiles` binary (`/usr/bin/profiles`) installs/removes/validates profiles locally. Linux uses `sssd.conf` (INI format, `[domain/<name>]` sections), `krb5.conf` (INI with `[realms]`, `[domain_realm]`, `[capaths]` sections), `smb.conf` (INI for Samba), `nsswitch.conf` (NSS source lists), PAM files (`/etc/pam.d/<service>`), plus Ansible/Puppet/Salt playbooks for everything else. There is no unified authoring across the three platforms, per [`08-macos-equivalents/09-mac-mdm-gpo-equivalents.md`](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) and [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

The translation cost is enormous. The GPO-equivalents matrix in [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) maps 20+ common ADMX settings to their macOS MDM payload and Linux SSSD/Ansible equivalents, with caveats on every row. Password policy maps to `com.apple.mobileconfig.passwordpolicy` (macOS) and `sssd.conf` reading `maxPwdAge` from AD (Linux), but Kerberos policy has no macOS equivalent and no Linux equivalent beyond `krb5.conf` ticket lifetime. User Rights Assignment maps to SSSD's `ad_gpo_map_*` (Linux, 5 logon rights subset only) and to `com.apple.systempolicy.managed` `LoginWindowAllowedUsers` (macOS, very partial). Drive Maps (a GP Preference) has no macOS MDM equivalent — Jamf Connect's menu-bar agent handles share mounts via `mount_smbfs` in a login script. Folder Redirection has no macOS MDM equivalent — mobile accounts with `NFSHomeDirectory` on a network share is the partial equivalent. BitLocker maps to FileVault (`com.apple.security.FDERecoveryKeyEscrow` + `com.apple.security.FDE`), but FileVault has no PIN equivalent and the recovery key escrow goes to Apple or MDM, not AD (see PC-097). LAPS has no macOS equivalent at all (see PC-098).

The framework must adopt a single declarative policy format that compiles to platform-native. The format must support the full ADMX breadth (Registry.pol, Security CSE GptTmpl.inf, GP Preferences XML, Scripts) on Windows; ~80 Configuration Profile payload types on macOS; and sssd.conf + Ansible on Linux. The compilation must be deterministic, idempotent, and auditable. Candidate formats include OPA Rego (policy-as-code, used by Kubernetes), JSON Schema + per-platform executors, or a per-policy-type DSL (similar to Terraform HCL). The Policy Engine (PC-050+) is the framework's server-side component that stores and distributes policy; the Client SDK (PC-085+) is the client-side component that compiles and applies policy. This problem is about the authoring format and the cross-platform compilation.

**Impact**:

Policy authoring is per-OS; cross-platform policies require manual translation. Quantified: a typical enterprise maintains ~50-100 GPOs for Windows, ~30-50 MDM Configuration Profiles for macOS, and ~100-200 Ansible roles for Linux. Each policy change requires translation to all three platforms (where applicable), typically by three different administrators. The drift rate is ~10-15% per quarter (i.e. 10-15% of policies are out of sync at any time), causing security posture gaps and compliance audit failures.

**Constraints**:

- Must compile to ADMX + Registry.pol (Windows GPO), Configuration Profile (macOS MDM), sssd.conf + Ansible (Linux).
- Must support the full ADMX breadth on Windows, ~80 Configuration Profile payload types on macOS, and sssd.conf + Ansible on Linux.
- Must be deterministic — the same source policy must produce identical compiled output across runs.
- Must be idempotent — re-applying the same policy must not change platform state.
- Must be auditable — every policy change must produce a diff that an administrator can review.
- Must support policy versioning (rollback to a previous version on failure).

**Cross-platform considerations**:

- **Windows**: GPO via ADMX + Registry.pol + Security CSE GptTmpl.inf + Preferences XML. The framework's Windows client applies compiled GPO via the existing Group Policy Client service.
- **macOS**: Configuration Profile (`.mobileconfig`) with ~80 payload types. The framework's macOS client applies compiled profiles via `profiles install -path`.
- **Linux**: sssd.conf + Ansible playbooks. The framework's Linux client applies compiled sssd.conf and runs Ansible playbooks via `ansible-playbook` or an embedded Ansible runner.
- **Cross-platform consistency**: The source policy is unified; the compiled output is platform-specific. The Policy Engine (server-side) compiles per-platform and distributes via the platform-native channel (SMB-pull for GPO compat, MDM-APNs for macOS Configuration Profiles, HTTPS-pull for Linux Ansible).

**KB references**:

- [`08-macos-equivalents/09-mac-mdm-gpo-equivalents.md`](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) — Configuration Profile (`.mobileconfig`) CMS-signed plist XML structure, `PayloadType` discriminator (~80 types including `com.apple.mobiledevice.passwordpolicy`, `com.apple.security.firewall`, `com.apple.security.FDERecoveryKeyEscrow`, `com.apple.KerberosSSO`, `com.apple.configuration-ext.platform-sso`), `profiles` binary CLI, MDM protocol via APNs, Declarative Device Management (DDM) on macOS 13+ as the future direction (see PC-096).
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — 20+ ADMX setting × cross-platform equivalent matrix (Password policy, Account lockout, User Rights Assignment, Restricted Groups, Security Options, Windows Firewall, AppLocker, WMI Filtering, Drive Maps, File preference, Registry preference, Environment variables, Scheduled Tasks, Folder Redirection, Scripts, Deploy printer, BitLocker PIN, LAPS, Audit Policy, Kerberos Policy, Windows Time, Power Management, Custom ADMX Defender), SSSD GPO access control subset (5 logon rights only), macOS MDM payload types quick reference, FreeIPA HBAC vs Windows URA mapping, Ansible platform-coverage matrix, migration playbooks for Windows GPO → macOS MDM and Windows GPO → Linux SSSD/FreeIPA.

**Open questions**:

- OPA Rego as the unified policy format (policy-as-code, used by Kubernetes, with mature tooling), or JSON Schema + per-platform executors (simpler, less expressive)?
- Per-policy-type DSL (similar to Terraform HCL — one DSL per policy area like `password_policy`, `firewall_policy`, `audit_policy`), or a single unified DSL for all policy areas?
- Adopt Microsoft's ADMX schema as the source format and compile to macOS MDM + Linux sssd.conf/Ansible, accepting that ADMX is Windows-centric and some macOS/Linux concepts (LaunchDaemons, systemd units, MDM supervised-only restrictions) have no ADMX representation?

**Cross-capability impact**:

- Affects: PC-050 (Policy Engine — the unified format is the Policy Engine's source format), PC-085 (Client SDK — the SDK's policy application API consumes compiled platform-native policy).
- Affected by: PC-088 (SSSD GPO access — the Linux client's policy application is bounded by what SSSD can consume; the unified format must compile to sssd.conf keys that SSSD understands).

---

### PC-096 — macOS DDM (Declarative Device Management) is the future but not yet full-coverage

**Capability**: Cross-Platform Parity
**Severity**: low
**Cross-platform**: macOS

**Problem statement**:

Declarative Device Management (DDM), introduced in macOS 13 and extended in macOS 14 and 15, is a stateful, declarative alternative to the imperative MDM protocol. With DDM, the MDM server declares desired state as JSON (not plist); the device reconciles to that state and reports back asynchronously via the existing MDM check-in channel (`CheckInURL` of the MDM enrollment). Each declaration has a `DeclarationType`, `Identifier`, and `ServerToken` (used for change detection). Declarations are organized into Activations (bind a declaration set to a scope), Assets (files referenced by other declarations, like a wallpaper PNG), Configurations (a flat list of `ConfigurationType`-keyed declarations similar to payload types), and Management (server assertions like "Organizational Information" displayed in System Settings). Declarations live in `/private/var/db/ConfigurationProfiles/Declarations/` on the device, per [`08-macos-equivalents/09-mac-mdm-gpo-equivalents.md`](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md).

As of macOS 14, DDM covers: SoftwareUpdate restrictions, Passcode, Wallpaper, Organization Info, Asset declarations, and (in macOS 15) extensions to ScreenTime and a few more. Configuration Profiles remain necessary for the long tail — Kerberos SSO Extension, Platform SSO, FileVault, firewall, application restrictions, custom settings, etc. The migration is gradual; Apple has not announced a sunset date for Configuration Profiles. DDM's value-add over Configuration Profiles includes: (a) stateful reconciliation (the device reports current state, the server can detect drift), (b) asynchronous execution (no blocking on MDM push), (c) cleaner schema (JSON, not plist XML), (d) better support for declarative concepts (the device tells the server what it can do, the server tells the device what to do).

The framework must support DDM where available (macOS 13+) and Configuration Profile fallback for the long tail. The unified policy format (PC-095) must compile to DDM declarations where the policy area is DDM-covered (SoftwareUpdate, Passcode, Wallpaper, Organization Info) and to Configuration Profiles where it is not (Kerberos SSO, Platform SSO, FileVault, firewall, app restrictions). The compilation target depends on the macOS version (DDM on 13+, Configuration Profile on 12 and earlier), requiring the framework's macOS client to detect the OS version and choose the appropriate compilation path.

**Impact**:

DDM is the future; Configuration Profiles are legacy. The framework cannot ship a v1 that only supports DDM (too narrow coverage) or only supports Configuration Profiles (legacy, will be deprecated). The hybrid approach (DDM where available, Configuration Profile fallback) is the only viable strategy. Quantified: as of macOS 15, DDM covers ~10-15% of the Configuration Profile payload breadth; the remaining 85-90% requires Configuration Profile fallback.

**Constraints**:

- Must support DDM declarations (SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets, ScreenTime) on macOS 13+.
- Must support Configuration Profile fallback for the long tail (~80 payload types not yet covered by DDM).
- Must detect macOS version and choose the appropriate compilation path.
- Must support DDM migration (auto-convert existing Configuration Profile policies to DDM declarations where DDM coverage exists).
- Must support DDM status reporting (the device's asynchronous state reports must be consumed by the framework's Policy Engine).

**Cross-platform considerations**:

- **Windows**: No DDM equivalent. Windows uses GPO + MDM (OMA-DM/OMA-CP per SyncML). The framework's Windows client uses GPO + Intune.
- **macOS**: DDM is Apple's future direction. The framework's macOS client must support both DDM and Configuration Profiles.
- **Linux**: No DDM equivalent. Linux uses sssd.conf + Ansible. The framework's Linux client does not touch DDM.
- **Cross-platform consistency**: The unified policy format compiles to DDM (macOS 13+ where covered), Configuration Profile (macOS 12 and earlier + macOS 13+ long tail), GPO (Windows), and sssd.conf + Ansible (Linux). The source policy is unified; the compilation target is platform- and version-specific.

**KB references**:

- [`08-macos-equivalents/09-mac-mdm-gpo-equivalents.md`](../docs/08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) — DDM framework architecture (Activations, Assets, Configurations, Management), JSON-over-MDM-check-in protocol, `/private/var/db/ConfigurationProfiles/Declarations/` on-disk storage, DDM coverage as of macOS 14 (SoftwareUpdate, Passcode, Wallpaper, Organization Info, Assets), Configuration Profile fallback for the long tail, `ServerToken` change detection.
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — DDM migration playbook showing Windows GPO → macOS MDM translation for each policy area, Configuration Profile payload types quick reference (the ~80 types that DDM does not yet cover and that require Configuration Profile fallback), migration playbook for Windows GPO → macOS MDM including Password Policy → `com.apple.mobileconfig.passwordpolicy`, BitLocker → FileVault, Software Restriction → Gatekeeper.

**Open questions**:

- Adopt DDM-first authoring (write policies as DDM declarations, compile down to Configuration Profile for uncovered areas), or Configuration Profile-first authoring (write policies as Configuration Profiles, auto-migrate to DDM as coverage expands)?
- Auto-fallback to Configuration Profile when DDM doesn't cover a policy area, or require explicit per-policy choice (DDM vs Configuration Profile)?
- Track Apple's DDM coverage expansion (per macOS release) and auto-migrate policies from Configuration Profile to DDM as coverage expands, or require admin-initiated migration?

**Cross-capability impact**:

- Affects: PC-095 (unified policy authoring — the unified format must compile to DDM where covered, Configuration Profile where not).
- Affected by: PC-086 (PSSO Extension — PSSO is delivered via Configuration Profile, not DDM; the framework's macOS client must support Configuration Profile for PSSO until DDM coverage expands).

---

### PC-097 — macOS FileVault recovery key escrow goes to Apple or MDM, not AD

**Capability**: Cross-Platform Parity
**Severity**: medium
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

Windows BitLocker recovery password backs up to AD as a child object of the computer account: `CN=<GUID>,CN=<computer>,CN=BitLocker Recovery,CN=<domain>,DC=...` (the BitLocker Recovery container, created by the BitLocker ADM schema extension). The recovery password (a 48-digit number) is stored as a `msFVE-RecoveryPassword` attribute on a `msFVE-RecoveryInformation` object. The GPO "Choose how BitLocker-protected operating system drives can be recovered" (Computer Config → Administrative Templates → Windows Components → BitLocker Drive Encryption → Operating System Drives) controls backup behavior; "Save BitLocker recovery information to AD DS" must be enabled for the backup to occur, per the BitLocker row in [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) and the BitLocker section in [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

macOS FileVault recovery key escrow goes to Apple (iCloud account recovery) or to the MDM server (Jamf, Intune, Kandji, Mosyle), not to AD. The MDM payload `com.apple.security.FDERecoveryKeyEscrow` specifies the escrow location (URL + cert); the MDM payload `com.apple.security.FDE` enables FileVault. On FileVault enablement, the recovery key is generated, encrypted to the escrow server's public key (from the cert in the payload), and POSTed to the escrow URL. The MDM server stores the recovery key in its own database, with retrieval gated by the MDM vendor's RBAC (Jamf uses Jamf Pro's computer object; Intune uses the device object in Entra ID). There is no AD-integrated FileVault recovery key escrow. The LAPS-equivalent matrix in [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) (LAPS row) shows macOS MDM = n/a (no native LAPS for Mac; Jamf rotates local admin password via policy and escrows to Jamf server).

Linux LUKS has no AD recovery. The standard alternative is NBDE (Network-Bound Disk Encryption) via Clevis + Tang: Tang server (typically FreeIPA-managed) holds the decryption key; the Clevis client (on the Linux host) needs network access to Tang to decrypt the LUKS volume at boot. If the network is unavailable, the LUKS passphrase is the fallback. FreeIPA can manage Tang servers and Clevis clients, providing a directory-integrated NBDE story — but this is FreeIPA-specific, not AD-integrated.

The parity gap: disk-encryption recovery is fragmented. Windows backs up to AD; macOS backs up to Apple or MDM; Linux uses NBDE (Clevis/Tang). The framework must provide a unified disk-encryption recovery escrow: per-computer recovery key in the framework directory, with rotation, ACL-gated retrieval, and audit logging. The framework's directory must support a `recoveryKey` attribute on computer objects (or a child `recoveryInformation` object like BitLocker's schema).

**Impact**:

Cross-platform disk-encryption recovery is fragmented. Without unification, IT helpdesk must use three different tools to recover three platforms: ADUC for BitLocker, MDM console for FileVault, IPA CLI or Clevis/Tang for LUKS. Quantified: a typical enterprise helpdesk handles ~5-10 disk-encryption recovery requests per week per 10,000 devices; with three platforms, each request requires the helpdesk to identify the platform, locate the right tool, retrieve the key, and assist the user — total time ~15-30 minutes per incident.

**Constraints**:

- Must support per-computer recovery key in the framework directory.
- Must support recovery key rotation (on schedule, on demand, on enrollment).
- Must support ACL-gated retrieval (only helpdesk group can read; the user cannot read their own recovery key).
- Must support audit logging of all retrieval events.
- Must support Windows BitLocker interop (read existing `msFVE-RecoveryPassword` from AD; write new keys to AD for BitLocker clients during migration).
- Must support macOS FileVault recovery key escrow via MDM payload `com.apple.security.FDERecoveryKeyEscrow` pointing at the framework's escrow endpoint.
- Must support Linux LUKS recovery via NBDE (Clevis/Tang) with the framework managing the Tang server.

**Cross-platform considerations**:

- **Windows**: BitLocker recovery password in AD as `msFVE-RecoveryInformation` child object of the computer account. The framework's Windows client reuses the OS BitLocker stack and the AD schema extension for recovery key storage.
- **macOS**: FileVault recovery key via MDM `com.apple.security.FDERecoveryKeyEscrow` payload pointing at the framework's escrow endpoint. The framework's macOS client installs the MDM payload and triggers FileVault enablement.
- **Linux**: LUKS + Clevis/Tang (NBDE). The framework manages the Tang server and configures Clevis clients. For non-NBDE recovery, LUKS passphrase can be stored in the framework directory (similar to LAPS — see PC-098).
- **Cross-platform consistency**: The framework directory's `recoveryKey` attribute (or equivalent) is the unified escrow. Per-platform code reads/writes this attribute using platform-native crypto (BitLocker's `msFVE-RecoveryPassword`, FileVault's PRK converted from base36, LUKS passphrase as a string).

**KB references**:

- [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) — BitLocker row showing Win10/11 native = ✓ (BDREncrypt), Win Server DC = ✓ (schema ext), macOS = ✗ (use LUKS), macOS MDM = ✗, macOS 3rd-party = partial (FileVault to ADP), Linux SSSD = ✗ (use LUKS), Linux FreeIPA = partial (Clevis/Tang), per-feature deep notes on BitLocker AD backup and macOS FileVault-to-Apple/MDM escrow.
- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — BitLocker PIN enforcement row showing Windows = ✓, macOS = n/a (FileVault uses recovery key; no PIN equivalent), Linux = n/a (LUKS has passphrase; no network PIN), LAPS row showing Windows = ✓, macOS = n/a (Jamf rotates local admin), Linux = ✗ (Ansible custom role), FreeIPA = partial (`ipa host-mod --password=<otp>` rotates host OTP).

**Open questions**:

- Per-computer recovery key in framework directory with ACL-gated read, or NBDE (Clevis/Tang) for all platforms (Tang server holds the decryption key; client needs network to decrypt)?
- Adopt Windows LAPS schema for compat (reusing `msFVE-RecoveryPassword` for BitLocker and `msLAPS-Password` for local admin — see PC-098)?
- For macOS, escrow FileVault recovery key to the framework directory via MDM `com.apple.security.FDERecoveryKeyEscrow` payload pointing at a framework-provided escrow HTTPS endpoint, or use Apple's institutional recovery key (a single key for all Macs in the org)?

**Cross-capability impact**:

- Affects: PC-098 (LAPS — disk-encryption recovery and local admin password rotation share the directory-storage model).
- Affected by: PC-013 (Core Directory — the directory must support the `recoveryKey` attribute or `msFVE-RecoveryInformation`-equivalent child object).

---

### PC-098 — LAPS (local admin password rotation) has no macOS/Linux native equivalent

**Capability**: Cross-Platform Parity
**Severity**: medium
**Cross-platform**: Windows / macOS / Linux

**Problem statement**:

Windows LAPS (Local Administrator Password Solution) stores the local admin password hash + history in AD on the computer object. Legacy Microsoft LAPS (the 2015-era GPO + ADMX + CSE solution) uses the `ms-MCS-AdmPwd` attribute for the cleartext password and `ms-MCS-AdmPwdExpirationTime` for the expiry timestamp. New Windows LAPS (built into Windows Server 2022 and Windows 10 22H2+) uses `msLAPS-Password` (a JSON blob with `n`, `p`, `exp` fields — encrypted to a password encryption key), `msLAPS-EncryptedPassword` (the ciphertext), `msLAPS-PasswordExpirationTime`, and `msLAPS-EncryptedPasswordHistory`. The GPO "Password Settings" (Computer Config → Administrative Templates → LAPS ADMX) controls password complexity, length, age; the GPO "Account Settings" controls which local account to manage; the GPO "Backup/Restore" controls AD write behavior. The CSE (`laps.dll` in `svchost -k netsvcs`) runs every 90 minutes, checks `msLAPS-PasswordExpirationTime`, and rotates the password if expired, per the LAPS row in [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) and the LAPS row in [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md).

macOS has no native LAPS equivalent. The de facto standard is Jamf Pro's "LAPS" feature (Jamf rotates the local admin password via a daemon policy on the Mac, escrows the new password to the Jamf server, with retrieval gated by Jamf RBAC). On macOS 14+, Apple introduced `com.apple.configuration.device.password.rotation` as a DDM declaration (a future-direction replacement for Jamf LAPS), but coverage is limited. Linux has no native LAPS equivalent either. The standard pattern is an Ansible role that rotates the local admin password on a schedule, encrypts the new password to an Ansible Vault secret, and stores the encrypted secret in the Ansible controller. FreeIPA has `ipa host-mod --password=<otp>` which rotates the host's enrollment password (conceptually similar but not the same as LAPS — it's for host enrollment, not local admin password rotation).

The parity gap: local admin password rotation is per-OS. The framework must provide a unified LAPS-equivalent across platforms. The unified solution: per-host password in framework directory with ACL-gated read, scheduled rotation via the Client SDK's policy application, and per-platform code that actually sets the local admin password (Windows: `NetUserSetInfo` for the local SAM; macOS: `dscl . -passwd /Users/admin <newpass>` via PAM; Linux: `chpasswd` via PAM). The framework directory's `msLAPS-Password`-equivalent attribute stores the encrypted password; ACLs gate read access to the helpdesk group only.

**Impact**:

Local admin password rotation is per-OS. Without unification, IT must maintain three rotation mechanisms (Windows LAPS, Jamf LAPS for macOS, Ansible custom role for Linux), each with its own audit log, retrieval workflow, and rotation schedule. Quantified: a typical enterprise rotates local admin passwords every 30 days; with three platforms, that's three rotation mechanisms × 30 days × N hosts = significant operational overhead, plus the security risk of unrotated passwords on hosts that fall out of compliance.

**Constraints**:

- Must support per-host password rotation (configurable schedule, on-demand, on enrollment).
- Must support directory escrow + ACL-gated retrieval (only helpdesk group can read; the host can write its own password).
- Must support password history (N previous passwords retained for audit).
- Must support password encryption at rest (Windows LAPS encrypts to a password encryption key; the framework must do the same).
- Must support Windows LAPS interop (read existing `ms-MCS-AdmPwd`/`msLAPS-Password` from AD; write new passwords to AD for Windows clients during migration).
- Must adopt Windows LAPS schema for compat (reusing `msLAPS-Password` for cross-platform parity).

**Cross-platform considerations**:

- **Windows**: Windows LAPS (built into Server 2022+) writes `msLAPS-Password` to AD. The framework's Windows client can reuse the OS LAPS CSE and the framework directory's `msLAPS-Password` attribute.
- **macOS**: Jamf LAPS (or DDM `com.apple.configuration.device.password.rotation` on macOS 14+). The framework's macOS client must implement its own LAPS agent (LaunchDaemon that rotates the password on schedule and writes the new password to the framework directory).
- **Linux**: Ansible custom role. The framework's Linux client must implement its own LAPS agent (systemd timer that rotates the password via `chpasswd` and writes the new password to the framework directory).
- **Cross-platform consistency**: The framework directory's `msLAPS-Password` attribute (or equivalent) stores the encrypted local admin password. Per-platform code reads/writes this attribute. The retrieval workflow (helpdesk requests password → framework ACL check → decrypt → return to helpdesk) is unified.

**KB references**:

- [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — LAPS row showing Windows native GPO = ✓ (Microsoft LAPS ADMX), macOS MDM = n/a (no native LAPS for Mac; Jamf rotates via policy), macOS MCX = n/a, Linux SSSD = n/a (homemade scripts typically use Ansible), Linux FreeIPA = partial (`ipa host-mod --password=<otp>` rotates host OTP, not local admin), Ansible = `community.windows.win_laps` (Windows) + custom Ansible for macOS/Linux.
- [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) — LAPS row showing Win10/11 native = ✓ (LAPS ADMX/CSE), Win Server DC = ✓ (schema ext), macOS Native OD = ✗, macOS Enterprise MDM = partial (Jamf LAPS-like), macOS 3rd-party agent = partial (ADP), Linux SSSD = partial (homemade scripts), Linux FreeIPA = partial (IPA host pw), per-feature deep notes on LAPS schema (`ms-MCS-AdmPwd`/`msLAPS-Password`) and the macOS Jamf-rotates-local-admin pattern.

**Open questions**:

- Per-host password in framework directory with ACL-gated read (reusing Windows LAPS schema `msLAPS-Password`), or per-platform solutions (Windows LAPS for Windows, Jamf LAPS for macOS, Ansible for Linux)?
- Adopt Windows LAPS schema for compat (so the framework directory's LAPS attribute is readable by Windows LAPS tools), or define a fresh schema?
- For macOS, use Apple's `com.apple.configuration.device.password.rotation` DDM declaration on macOS 14+ (future direction) or implement a LaunchDaemon that rotates the password on schedule?

**Cross-capability impact**:

- Affects: PC-097 (disk-encryption recovery — both LAPS and disk-encryption recovery share the directory-storage model with ACL-gated retrieval).
- Affected by: PC-013 (Core Directory — the directory must support the `msLAPS-Password` attribute with appropriate ACLs).

---

### PC-099 — SSSD/Winbind/PBIS are alternative Linux stacks; migration between them is painful

**Capability**: Cross-Platform Parity
**Severity**: medium
**Cross-platform**: Linux

**Problem statement**:

Three Linux AD-integration stacks exist, each with different ID mapping, GPO support, PAM/NSS modules, and config file formats. SSSD (`sssd-ad` provider, modern, Red Hat-backed, the de facto standard on RHEL/Fedora/Ubuntu/Debian) uses MIT Kerberos + LDAP via SASL GSSAPI, algorithmic SID-to-UID mapping (`ldap_id_mapping = true` in `src/lib/idmap/sss_idmap.c`), GPO access control subset (`ad_gpo_access_control` in `src/providers/ad/ad_gpo.c`), offline auth via `cache_credentials = true`, dyndns via `nsupdate -g`. Winbind (`winbindd` from Samba, file-server-focused, the only option when Samba `smbd` is the SMB server) uses Heimdal Kerberos (bundled with Samba) + Netlogon secure channel (`NetrServerAuthenticate3` + `NetrLogonSamLogonEx` over MS-NRPC) + SAMR/LSA, ID mapping via `idmap_rid`/`idmap_autorid`/`idmap_ad`/`idmap_tdb2` backends, no GPO access control (relies on `pam_winbind.so require_membership_of=` for ad-hoc group checks), offline auth via `cached_login`. PBIS (PowerBroker Identity Services, BeyondTrust, deprecated 2023 for macOS, deprecated 2014 for Linux open-source edition) uses its own `lsassd` + `netlogond` (Likewise-derived), LWI registry at `/opt/pbis/config/reg.dat` for all config, ID mapping via `RangeMin`/`RangeMax`/`RangeSize` registry keys, no GPO access control (commercial PBIS has limited support), per [`09-linux-equivalents/01-sssd-ad-provider.md`](../docs/09-linux-equivalents/01-sssd-ad-provider.md), [`09-linux-equivalents/04-winbind-internals.md`](../docs/09-linux-equivalents/04-winbind-internals.md), and [`09-linux-equivalents/07-pbis-powerbroker.md`](../docs/09-linux-equivalents/07-pbis-powerbroker.md).

The migration problems: (a) UID remapping — SSSD's `ldap_id_mapping = true` algorithm differs from Winbind's `idmap_rid` and from PBIS's `RangeMin`/`RangeMax`/`RangeSize` algorithm; migrating from one stack to another changes every user's UID, breaking file ownership on `/home` and shared filesystems. The mitigation is to mirror the range (`ldap_idmap_range` in SSSD = `idmap config * : range` in Winbind = `RangeMin`/`RangeMax` in PBIS) and run `chown -R --from=<olduid> <newuid>` sweeps, but this requires careful planning and downtime; (b) PAM/NSS module replacement — `pam_sss.so` ↔ `pam_winbind.so` ↔ `pam_lsass.so` are not interchangeable; switching requires regenerating the PAM stack via `authselect` (RHEL) or `pam-auth-update` (Debian); (c) config file format — `/etc/sssd/sssd.conf` (INI) ↔ `/etc/samba/smb.conf` (INI, different keys) ↔ `/opt/pbis/config/reg.dat` (LWI binary registry); (d) cache format — `/var/lib/sss/db/cache_<domain>.ldb` (LDB) ↔ `/var/lib/samba/winbindd_cache.tdb` (TDB) ↔ `/var/lib/pbis/lwidata/cache/` (LWI binary); (e) machine-account keytab — all three write `/etc/krb5.keytab` but with different enctype sets (SSSD writes all four, Winbind writes all four, PBIS writes all four) and different SPN sets (SSSD writes `HOST/` + `RestrictedKrbHost/`, Winbind adds `cifs/` if `smbd` is running, PBIS writes `HOST/` + `RestrictedKrbHost/`).

The framework should standardize on SSSD as the primary Linux stack and provide migration tooling from Winbind and PBIS. The migration tool should: (a) read the existing stack's ID mapping config and produce equivalent SSSD config, (b) plan the UID remapping (compute old-vs-new UID deltas for every user, output a `chown` script), (c) swap the PAM stack via `authselect`/`pam-auth-update`, (d) remove the old stack's packages and config files, (e) verify the new stack with a test login before declaring migration complete.

**Impact**:

Mixed-stack deployments cause UID/group drift. Quantified: in enterprises that have grown through M&A, ~30-40% of Linux fleets run mixed SSSD + Winbind + PBIS stacks due to legacy acquisitions. Each migration project takes ~3-6 months per 1000 hosts, with UID remapping being the highest-risk step. Failed migrations (UID drift not caught in testing) cause file ownership breaks that take weeks to detect and remediate.

**Constraints**:

- Must support SSSD as primary (modern, actively maintained, Red Hat-backed).
- Must provide migration tooling from Winbind (Samba-only deployments that want to migrate to SSSD while keeping `smbd` for SMB share serving).
- Must provide migration tooling from PBIS (deprecated 2023 for macOS, deprecated 2014 for open-source Linux edition).
- Must preserve UID stability across migration (mirror the ID mapping range, plan the UID remap, output a `chown` script).
- Must support mixed mode (SSSD for NSS/PAM + Winbind for `smbd` SID/name resolution) for transition periods.

**Cross-platform considerations**:

- **Windows**: Not applicable. Windows uses LSASS natively.
- **macOS**: Not applicable. macOS uses OpenDirectory + PSSO.
- **Linux**: Three stacks (SSSD, Winbind, PBIS). The framework's Linux client should standardize on SSSD and provide migration tooling.
- **Cross-platform consistency**: The framework's ID mapping must match SSSD's algorithm (see PC-089). Migration from Winbind/PBIS to SSSD is a Linux-only problem; Windows and macOS are unaffected.

**KB references**:

- [`09-linux-equivalents/01-sssd-ad-provider.md`](../docs/09-linux-equivalents/01-sssd-ad-provider.md) — SSSD `ad` provider architecture, `[domain/<name>]` config block, `libsss_ad.so` module loading, `sssctl` operational commands, comparison-to-Winbind guidance ("most distros recommend SSSD for NSS/PAM and Winbind only when SMB shares are served").
- [`09-linux-equivalents/04-winbind-internals.md`](../docs/09-linux-equivalents/04-winbind-internals.md) — `winbindd` daemon architecture, `/run/samba/winbindd/pipe` and `/run/samba/winbindd_privileged/pipe` IPC sockets, `idmap config * : backend = rid|autorid|ad|tdb2` syntax, `pam_winbind.so` parameter reference, comparison-to-SSSD table, switching idmap backends requires `net cache flush` + `chown` sweep.
- [`09-linux-equivalents/07-pbis-powerbroker.md`](../docs/09-linux-equivalents/07-pbis-powerbroker.md) — PBIS `lwsmd` service broker + `lsassd`/`netlogond`/`lwregd`/`eventlogd`/`dcerpcd` daemons, `/opt/pbis/config/reg.dat` LWI registry, `domainjoin-cli` join tool, comparison-to-SSSD table, migration PBIS → SSSD steps (note algorithmic ID mapping range, mirror in `ldap_idmap_range`, `domainjoin-cli leave`, `realm join`).

**Open questions**:

- Hard-deprecate Winbind for NSS/PAM (keep for SMB only via `smbd`'s internal use), or support both SSSD and Winbind for NSS/PAM indefinitely, accepting the maintenance burden?
- Auto-migrate PBIS to SSSD (detect `lwsmd` running, plan UID remap, swap stack, verify with test login), or document the migration path and require admin intervention?
- For Samba AD-DC deployments (which bundle Heimdal and require `winbindd` for AD-DC operation), accept that Samba AD-DC is a special case where Winbind is mandatory, and document the framework's Linux client as separate from Samba AD-DC?

**Cross-capability impact**:

- Affects: PC-089 (ID mapping — the framework's ID mapping algorithm must match SSSD's for migration to preserve UID stability).
- Affected by: PC-088 (SSSD GPO access — the framework's Linux client extends SSSD, so migration from Winbind/PBIS to SSSD is a prerequisite for GPO access control).

---

### PC-100 — macOS OpenDirectory AD plug-in has gaps (GPO, ABE, full DFS-N)

**Capability**: Cross-Platform Parity
**Severity**: medium
**Cross-platform**: macOS

**Problem statement**:

Apple's OpenDirectory AD plug-in (`DSP.ActiveDirectory.bundle` in `/System/Library/OpenDirectory/Modules/`) implements AD binding via `dsconfigad`, LDAP queries via the LDAPv3 plug-in (`DSP.LDAPv3.bundle`), Kerberos auth via the system Heimdal Kerberos (`/usr/lib/libkerberos.dylib`), and CLDAP DC locator queries (UDP 389). The plug-in surfaces `/Active Directory/<DOMAIN>` magic node in `opendirectoryd`, with sub-nodes `/Active Directory/<DOMAIN>/All Domains` (forest-GC aggregate view via LDAP port 3268) and `/Active Directory/<DOMAIN>/GlobalAddressList` (Exchange GAL subset), per [`08-macos-equivalents/01-opendirectory-internals.md`](../docs/08-macos-equivalents/01-opendirectory-internals.md) and [`08-macos-equivalents/02-dscl-dsconfigad.md`](../docs/08-macos-equivalents/02-dscl-dsconfigad.md).

The gaps: (a) GPO consumption — macOS has no native GPO engine. The `dsconfigad -enablesso` flag enables Kerberos + NTLM SSO for SMB/AFP and the Authorization framework, but does not enable GPO processing. Third-party agents (Centrify DirectControl, Jamf Connect) fill the GPO gap; (b) Access-Based Enumeration on SMB mounts — macOS SMBX client does not implement ABE client-side filtering, and server-side ABE requires the SMB server to support it (SMBX server does not); (c) full DFS-N referral support — macOS SMBX client resolves DFS-N referrals for `mount_smbfs` access to Windows-hosted namespaces, but only for the first referral (no site-aware referral caching, no referral refresh on TTL expiry, no fallback to next target on first-target failure); (d) Group Policy Preferences (Drive Maps, Files, Local Users and Groups, Scheduled Tasks, Folder Redirection) — none of these are processed on macOS; MDM Configuration Profiles replace a subset but lack the full GPP breadth; (e) Registry.pol processing — macOS has no registry; Administrative Templates have no macOS equivalent, per the feature×OS matrix in [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) (GPO distribution row: macOS Native OD = ✗, macOS Enterprise MDM = partial profiles only, macOS 3rd-party = partial Jamf/Centrify).

The third-party agents that fill the gaps: Centrify DirectControl (now Delinea/CyberArk) ships its own Kerberos fork + `adclient` daemon + `dzdo` sudo replacement, providing GPO consumption via Centrify's GPO engine; BeyondTrust PBIS (deprecated macOS 2022) ports the Linux stack to macOS, providing limited GPO support; Jamf Connect provides OIDC login + Kerberos SSO Extension but no GPO engine (relies on MDM Configuration Profiles for policy). Apple's recommended modern stack is PSSO Extension (macOS 13+) + Jamf Connect + MDM, accepting that GPO is not consumed natively, per [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md).

The framework must adopt PSSO + Jamf Connect + MDM as the macOS stack and document the gaps that remain (GPO consumption, ABE on SMB mounts, full DFS-N referral). For the gaps, the framework must either (a) provide first-party macOS client code that fills them (GPO engine, ABE client, DFS-N client referral caching), (b) document third-party agents as required (Centrify for GPO, Mountain Duck for ABE), or (c) document the gaps as out of scope and require platform-native alternatives (MDM Configuration Profiles for policy, direct share paths for ABE, direct server paths for DFS-N).

**Impact**:

macOS AD integration is partial without third-party tooling. Quantified: a typical enterprise macOS deployment requires ~3-5 third-party tools to fill the gaps (Centrify or Jamf Connect for SSO, Mountain Duck or ExpanDrive for offline files, a custom ABE solution, an MDM for policy). Total cost: ~$30-50 per Mac per year for the third-party tools, plus the operational overhead of managing multiple agents.

**Constraints**:

- Must support PSSO Extension (Kerberos SSO via `com.apple.KerberosSSO` MDM payload).
- Must support Jamf Connect (OIDC login via `com.jamf.connect.login` MDM payload) for cloud-first deployments.
- Must support MDM Configuration Profiles for policy distribution (the macOS GPO equivalent).
- Must document gaps: GPO consumption (no native engine), ABE on SMB mounts (SMBX has no client-side ABE), full DFS-N referral (SMBX has limited referral support).
- Must provide first-party macOS client code for the gaps where feasible (DFS-N client referral caching is feasible; GPO engine is large engineering effort).

**Cross-platform considerations**:

- **Windows**: Full AD integration natively. No gaps.
- **macOS**: Partial AD integration via OpenDirectory + PSSO. Gaps filled by third-party agents (Centrify, Jamf Connect, Mountain Duck).
- **Linux**: SSSD provides partial AD integration (GPO access control subset, ID mapping, offline auth). Gaps filled by Ansible for full GPO coverage.
- **Cross-platform consistency**: The framework's macOS client must provide equivalent functionality to the Linux SSSD client and the Windows native client. Where macOS cannot match (GPO engine, ABE), the framework must document the gap and provide a workaround.

**KB references**:

- [`08-macos-equivalents/01-opendirectory-internals.md`](../docs/08-macos-equivalents/01-opendirectory-internals.md) — `opendirectoryd` daemon architecture, plug-in registry (`DSP.local.bundle`, `DSP.LDAPv3.bundle`, `DSP.ActiveDirectory.bundle`, `DSP.Bonjour.bundle`, `DSP.Configure.bundle`, `DSP.XMLPlugIn.bundle`), OD node namespace (`/Local/Default`, `/LDAPv3/<host>`, `/Active Directory/<DOMAIN>`, `/Active Directory/<DOMAIN>/All Domains`, `/Search`), `dsAttrTypeStandard:` schema mapping to AD attributes, LKDC (Local KDC) on macOS 11+.
- [`08-macos-equivalents/02-dscl-dsconfigad.md`](../docs/08-macos-equivalents/02-dscl-dsconfigad.md) — `dsconfigad` 13+ flags (`-a`, `-domain`, `-ou`, `-u`, `-p`, `-mobile`, `-mobileconfirm`, `-localhome`, `-useuncpath`, `-homeprotocol`, `-home`, `-shell`, `-preferred`, `-groups`, `-namespace`, `-enablesso`, `-packetsign`, `-packetencrypt`, `-passinterval`, `-passchange`, `-show`, `-remove`), CLDAP DC locator, `/Library/Preferences/DirectoryService/ActiveDirectoryDomains.plist` master list, `/Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/<domain>.plist` per-domain config, `dscl /Active Directory/<DOMAIN>` magic node queries.
- [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md) — Centrify DirectControl (`adclient` daemon, `adjoin`, `dzdo` sudo replacement, Centrify Heimdal fork), BeyondTrust PBIS (`domainjoin-cli`, `lwsmd`, `lwreg` registry), Thursby AdmitMac/DAVE (legacy SMB/Kerberos stacks), Homebrew Samba/Heimdal/OpenLDAP, comparison summary table showing maintenance status.

**Open questions**:

- Provide first-party macOS client SDK that fills GPO/DFS-N/ABE gaps (large engineering effort, ~2-3 years for full GPO engine), or document third-party agents as required (Centrify for GPO, Mountain Duck for ABE)?
- Document third-party agents as required (Centrify, Jamf Connect, Mountain Duck) and provide integration guides for each, accepting that macOS deployments have a third-party dependency?
- For GPO consumption specifically, provide a first-party macOS GPO engine that parses `GptTmpl.inf` and Registry.pol and translates to macOS plist settings, or rely on MDM Configuration Profiles as the macOS-native GPO equivalent?

**Cross-capability impact**:

- Affects: PC-086 (PSSO Extension — the macOS stack is PSSO + Jamf Connect + MDM), PC-088 (SSSD GPO access — the macOS equivalent is no native GPO; the framework must document this gap).
- Affected by: PC-095 (unified policy authoring — the unified format must compile to macOS Configuration Profiles, not GPO).

---

### PC-101 — FreeIPA is a separate Linux identity platform with AD cross-forest trust

**Capability**: Cross-Platform Parity
**Severity**: medium
**Cross-platform**: Linux / cross-platform

**Problem statement**:

FreeIPA (Free Identity Policy & Authentication, https://www.freeipa.org/) is a Linux-side identity and policy platform that bundles 389-DS LDAP (`ns-slapd`), MIT Kerberos (`krb5kdc` + `kadmind` with the IPA KDB plugin `ipa_kdb`), BIND DNS (with `bind-dyndb-ldap` plugin for LDAP-backed zones), Dogtag PKI (`pki-tomcatd` for CA + KRA), certmonger for certificate lifecycle, and SSSD for client-side integration. When configured with a cross-forest trust to AD via `ipa trust-add --type=ad corp.example.com --admin admin --password`, the FreeIPA KDC establishes Kerberos cross-realm TGT-referral routing (RFC 4120 §3.3.3) and the FreeIPA directory server exposes AD users and groups to POSIX clients through the `ipa-extdom-plugin` (LDAP extended operation OID `2.16.840.1.113730.3.8.10.4`) which proxies lookups to Samba's `libads`/`librpc` to resolve SIDs from the AD Global Catalog, per [`09-linux-equivalents/08-freeipa-trust.md`](../docs/09-linux-equivalents/08-freeipa-trust.md).

The trust creation flow: (a) `kinit admin@CORP.EXAMPLE.COM` to obtain an AD TGT; (b) `net rpc trust create` (Samba's `source3/librpc/cli_lsa.c:cli_lsa_create_trust`) calls `LsaOpenPolicy3` + `LsaCreateTrustedDomainEx3` with `TRUST_ATTRIBUTE_FOREST_TRANSITIVE` (0x8) and `TRUST_TYPE_UPLEVEL` (2) on an AD DC; (c) IPA-side `ipaNTTrustedDomain` object is created at `cn=corp.example.com,cn=ad,cn=trusts,cn=ipa,cn=etc,dc=example,dc=com` with attributes `ipaNTTrustedDomainSID`, `ipaNTTrustDirection: 3` (two-way), `ipaNTTrustType: 2` (uplevel AD), `ipaNTTrustAttributes: 8` (FOREST_TRANSITIVE), `ipaNTAuthTrustBlob` (LSA_AUTH_INFORMATION array); (d) cross-realm principals `krbtgt/CORP.EXAMPLE.COM@EXAMPLE.COM` and `krbtgt/EXAMPLE.COM@CORP.EXAMPLE.COM` are created in the MIT KDB with the trust password; (e) `[capaths]` section in `/var/kerberos/krb5kdc/kdc.conf` is updated for direct cross-realm referral; (f) `ipa idrange-add` creates the `ipaIDRange` object with `ipaBaseID`, `ipaIDRangeSize`, `ipaRangeType: ipa-ad-trust`, `ipaNTTrustedDomainSID` for AD user ID mapping.

The framework faces a strategic choice: (a) adopt FreeIPA as the Linux identity layer with AD cross-forest trust — the framework's Linux clients enroll in FreeIPA via `ipa-client-install`, FreeIPA holds the trust to AD, AD users appear as `user@corp.example.com` in the IPA directory and resolve via `ipa-extdom-plugin`; (b) provide a unified identity platform that subsumes both AD and FreeIPA roles — the framework's Core Directory replaces both AD DS and 389-DS, the framework's KDC replaces both `kdcsvc.dll` and `krb5kdc`, etc.; or (c) provide direct AD-join via SSSD (no FreeIPA in the picture) and document FreeIPA as out of scope for the framework.

The first option (FreeIPA as Linux tier) preserves existing FreeIPA deployments and leverages FreeIPA's HBAC (Host-Based Access Control), sudo rules, ID views, cert management, and automount. The second option (unified platform) is cleaner architecturally but requires re-implementing FreeIPA's value-add in the framework. The third option (direct AD-join) is simplest but loses FreeIPA's Linux-specific features.

**Impact**:

FreeIPA is the de facto Linux identity platform; integration with AD is via trust. Quantified: ~30-40% of enterprise Linux deployments use FreeIPA as the identity tier with AD cross-forest trust (common in RHEL shops). The framework's choice affects migration: if the framework adopts FreeIPA, existing FreeIPA deployments can be preserved; if the framework provides a unified platform, existing FreeIPA deployments must be migrated (a 6-12 month project for a typical enterprise); if the framework requires direct AD-join, existing FreeIPA deployments must be torn down (loss of HBAC, sudo rules, ID views).

**Constraints**:

- Must support cross-forest trust if FreeIPA is in scope (implement MS-LSAD `LsaCreateTrustedDomainEx3` opnum 44 equivalent, `TRUST_ATTRIBUTE_FOREST_TRANSITIVE`).
- Must support HBAC (Host-Based Access Control) as the unified access model if FreeIPA's value-add is preserved.
- Must support IPA ID views (per-host or per-user overrides) for migration scenarios.
- Must support `ipa-extdom-plugin`-equivalent (LDAP extended operation that proxies AD SID lookups to AD GC).
- If FreeIPA is out of scope, must document the migration path from FreeIPA to direct AD-join (loss of HBAC, sudo rules, ID views — admins must reimplement these via SSSD `simple_allow_users` + `pam_access` + `sss_override`).

**Cross-platform considerations**:

- **Windows**: AD is the reference identity platform. FreeIPA is a separate Linux tier with trust to AD. The framework's Windows client uses AD natively.
- **macOS**: OpenDirectory is the macOS equivalent of FreeIPA (a platform-native directory service that can bridge to AD). The framework's macOS client uses OpenDirectory + PSSO.
- **Linux**: FreeIPA is the de facto identity platform. The framework's Linux client should either enroll in FreeIPA (preserving existing deployments) or join AD directly via SSSD (simpler, loses FreeIPA features).
- **Cross-platform consistency**: If the framework adopts FreeIPA as the Linux tier, the cross-platform API must abstract AD-join (Windows, macOS) vs FreeIPA-enroll (Linux) behind a unified `framework-enroll` command. The user identity is the same on every platform (`user@corp.example.com` for AD-joined, `user@example.com` for IPA-enrolled — but cross-forest trust makes `user@corp.example.com` resolvable on IPA-enrolled hosts).

**KB references**:

- [`09-linux-equivalents/08-freeipa-trust.md`](../docs/09-linux-equivalents/08-freeipa-trust.md) — FreeIPA architecture (389-DS + MIT krb5 + BIND + Dogtag + certmonger + SSSD + `ipa-extdom-plugin`), `ipa trust-add` creation flow (`kinit` + `net rpc trust create` + `LsaCreateTrustedDomainEx3` opnum 44 + `ipaNTTrustedDomain` object creation + `krbtgt/<foreign-realm>` cross-realm principals + `[capaths]` + `ipa idrange-add`), `ipa-extdom-plugin` extended operation (OID `2.16.840.1.113730.3.8.10.4` with `extdomRequest ::= SEQUENCE { input InputType, request CHOICE { name [0] SEQUENCE {...}, sid [1] OCTET STRING, uid [2] INTEGER, gid [3] INTEGER }, extended BOOLEAN }`), HBAC vs Windows User Rights Assignment mapping, ID views and `sss_override`, FreeIPA-AD trust vs intra-forest AD trust comparison table.
- [`09-linux-equivalents/01-sssd-ad-provider.md`](../docs/09-linux-equivalents/01-sssd-ad-provider.md) — SSSD `ad` provider as the alternative direct-AD-join path (no FreeIPA tier), `[domain/<name>]` config block with `id_provider = ad` + `auth_provider = ad` + `access_provider = ad`, comparison to Winbind noting that "most distros recommend SSSD for NSS/PAM and Winbind only when SMB shares are served", highlighting that direct-AD-join via SSSD is the simpler alternative to FreeIPA but loses HBAC, sudo rules, ID views, and IPA-managed cert lifecycle.

**Open questions**:

- Adopt FreeIPA as the Linux tier (preserve existing deployments, leverage HBAC/sudo/ID views/cert management), accepting that the framework's Linux story depends on FreeIPA?
- Build native IPA-equivalent in the framework (re-implement HBAC, sudo rules, ID views, cert management in the framework's Core Directory + Policy Engine), accepting ~2-3 years of engineering effort?
- For Linux, prefer direct AD-join via SSSD (no FreeIPA in the picture), accepting the loss of HBAC/sudo/ID views, and document FreeIPA as out of scope?

**Cross-capability impact**:

- Affects: PC-013 (Core Directory — if FreeIPA is adopted, the framework's Core Directory must interoperate with 389-DS via LDAP; if a unified platform is built, the Core Directory subsumes 389-DS).
- Affected by: PC-001 (Core Directory replication — FreeIPA uses 389-DS Multi-Master Replication; the framework's replication model must interoperate or subsume this).

---

### PC-102 — RODC (Read-Only DC) has no Linux/macOS equivalent

**Capability**: Cross-Platform Parity
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

An RODC (Read-Only Domain Controller) is a Windows Server DC variant that holds a read-only copy of the AD database (no originating writes — all writes are forwarded to a writable DC), does not store password hashes by default (the `msDS-RevealedUsers` attribute on the RODC computer object controls which user/computer passwords are cached locally; users not on the list must authenticate against a writable DC over the WAN), and is designed for branch-office and DMZ deployments where physical security is weak. RODC has the `userAccountControl` bit `PARTIAL_SECRETS_ACCOUNT` (0x10000000) on its computer object and the `options` attribute bit `NTDSCONN_OPT_RODC_topology` on its `NTDSSettings` object, per [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) and the RODC row in [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md).

Linux SSSD has RODC-aware mode (not RODC server-side): `ad_site` pinning forces SSSD to query a specific AD site's DCs (which may be RODCs), `krb5_confd_path` for partial-KDC environments, and SSSD correctly handles the KDC's `KDC_ERR_SVC_UNAVAILABLE` response when the RODC doesn't have the user's password (SSSD falls back to a writable DC). SSSD does not implement an RODC server. There is no Linux/macOS RODC server implementation — Samba 4 AD DC implements a writable DC only. macOS OpenDirectory's AD plug-in is a client only.

The framework must decide whether RODC is in scope. If yes, the design must support: (a) read-only DIT (the framework's Core Directory must support a read-only replica mode where writes are forwarded to a writable replica), (b) per-DC password replication policy (`msDS-RevealedUsers`-equivalent — the framework's KDC must support a per-DC password cache list), (c) unidirectional replication (RODC pulls from a writable DC; writable DC never pulls from RODC), (d) KCC topology awareness (RODC is a special topology node; the KCC equivalent must not generate inbound replication links from RODCs). If no, the framework must document branch-office and DMZ scenarios as out of scope or recommend alternative architectures (Kubernetes-style read-replica with no secrets, edge-deployed DC with HSM-bound subset).

**Impact**:

Branch-office deployments without RODC risk full-DC compromise. Quantified: in a 100-site enterprise, ~20-30% of sites are branch offices with weak physical security (no locked server room, no CCTV, shared building access). Without RODC, each branch office either has a writable DC (high risk if the box is stolen — the entire domain's password hashes are exposed) or no DC (high latency — every auth goes over the WAN to a hub-site DC). RODC is the standard mitigation: a stolen RODC exposes only the `msDS-RevealedUsers` list (typically <100 branch-office users), not the entire domain.

**Constraints**:

- If in scope, must support read-only DIT (writes forwarded to a writable replica).
- If in scope, must support per-DC password replication policy (`msDS-RevealedUsers`-equivalent — per-DC list of users whose passwords can be cached).
- If in scope, must support unidirectional replication (RODC pulls from writable DC; writable DC never pulls from RODC).
- If in scope, must support KCC topology awareness (RODC is a special topology node).
- If out of scope, must document branch-office and DMZ scenarios as out of scope or recommend alternative architectures.

**Cross-platform considerations**:

- **Windows**: RODC is a Windows Server role. The framework's Windows DC could implement RODC by reusing the Windows RODC code (if licensed) or by writing a fresh RODC implementation.
- **macOS**: No RODC equivalent. macOS OpenDirectory cannot be a DC.
- **Linux**: SSSD has RODC-aware client mode. Samba 4 AD DC does not implement RODC. The framework's Linux DC could implement RODC by extending Samba 4 (large engineering effort) or by writing a fresh RODC implementation.
- **Cross-platform consistency**: If the framework implements RODC, the implementation must be cross-platform (Windows, macOS, Linux). The macOS case is awkward because macOS is not typically a DC platform; the framework's macOS DC would need to implement RODC from scratch.

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — AD DS architecture (DSA in `lsass.exe!ntdsa.dll`, ESE/JET Blue database, DRSUAPI replication interface `[e3514235-8b63-11d0-a26c-00a0c92b955c]`), `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` registry keys including `DSA Database File`, `Options` (bit 1 = IS_GC, etc.), transaction commit path, USN allocation.
- [`10-comparison-matrices/01-feature-os-matrix.md`](../docs/10-comparison-matrices/01-feature-os-matrix.md) — RODC row showing Win10/11 native = ✓ (client), Win Server DC = ✓ (RODC role), macOS Native OD = ✗, macOS Enterprise MDM = ✗, macOS 3rd-party agent = ✗, Linux SSSD = ✓ (sssd has RODC mode — client-side RODC-aware, not RODC server), Linux Winbind = ✗, Linux PBIS = ✗, Linux FreeIPA = ✗, Linux Pure OSS = ✗, coverage caveats noting that "RODC for Linux SSSD refers to RODC-aware behavior: `ad_site`, `ad_server` pinning, and `krb5_confd_path` for partial-KDC environments — not running as RODC itself (impossible)".

**Open questions**:

- Kubernetes-style read-replica with no secrets (the framework's Core Directory runs as a read-only replica in the branch office, no KDC, no password hashes — all auth forwarded to a hub-site DC), or edge-deployed DC with HSM-bound subset (the framework's KDC runs in the branch office with an HSM-bound master key, password hashes cached only for the `msDS-RevealedUsers` list)?
- Implement MS-DRSR read-only replication (RODC pulls from writable DC via `DRSGetNCChanges` opnum 3 with `DS_replica_info` flags indicating read-only), or use a fresh replication protocol (Raft consensus with read-only replica mode)?

**Cross-capability impact**:

- Affects: PC-001 (Core Directory replication — RODC requires unidirectional replication, which constrains the replication protocol), PC-023 (KDC MS-KILE profile — RODC requires per-DC password replication policy, which constrains the KDC's password cache).
- Affected by: PC-013 (Core Directory ACL evaluation — RODC's read-only DIT means ACL writes are forwarded to a writable replica; the ACL evaluation engine on the RODC is read-only).

---

### PC-103 — OpenLDAP + MIT Kerberos (roll-your-own) is high-effort, low-feature

**Capability**: Cross-Platform Parity
**Severity**: low
**Cross-platform**: Linux

**Problem statement**:

The "roll-your-own" alternative to AD is a manually composed stack of OpenLDAP `slapd` (the directory service, configured via `cn=config` at `/etc/openldap/slapd.d/cn=config.ldif` or legacy `/etc/openldap/slapd.conf`), MIT Kerberos `krb5kdc` + `kadmind` (the KDC + admin server, with KDB backend `kldap` storing principal keys in LDAP via `krbPrincipalKey` attribute on `krbPrincipalAux` auxiliary objectClass), BIND DNS (the dynamic-update-aware name service, with optional GSS-TSIG dynamic updates per RFC 3645 if compiled with `--with-gssapi`), `nslcd` (the NSS LDAP daemon, configured via `/etc/nslcd.conf` with `filter passwd (objectClass=posixAccount)` etc.), and `pam_krb5.so` + `pam_ldap.so` (the PAM auth/account modules), per [`09-linux-equivalents/09-openldap-mit-kerberos.md`](../docs/09-linux-equivalents/09-openldap-mit-kerberos.md).

The limitations vs AD or FreeIPA: (a) multi-master replication — OpenLDAP supports MirrorMode (2-node active-passive) or N-Way Multi-Master (limited, requires careful conflict resolution), but neither is as robust as AD's KCC + USN or 389-DS's Multi-Master Replication; (b) no Group Policy — OpenLDAP + MIT Kerberos has no GPO equivalent; configuration management must be done via Ansible/Puppet/Salt; (c) no DFS — OpenLDAP has no DFS-N or DFS-R equivalent; (d) no forest trusts — cross-realm Kerberos trusts are possible but lack `FOREST_TRANSITIVE` semantics; (e) no computer accounts framework — manual host principal creation via `kadmin.local -q "addprinc -randkey host/host01.example.com@EXAMPLE.COM"` + `ktadd -k /etc/krb5.keytab` for each host; (f) no PKI integration — manual cert distribution; certmonger optional; (g) no site awareness — no sites/subnets/replication topology; (h) limited schema extensibility — yes via LDIF, but no formal schema FSMO.

FreeIPA bundles the exact same components (389-DS = OpenLDAP-derived, MIT Kerberos, BIND, Dogtag PKI) into a managed product with web UI, CLI, and a full schema for hosts/HBAC/sudo. The roll-your-own stack is high-effort, low-feature; FreeIPA is the modern replacement. The framework should explicitly document roll-your-own as out of scope and recommend FreeIPA or framework-native as the alternative.

**Impact**:

Roll-your-own is a maintenance burden; FreeIPA is the modern replacement. Quantified: a typical roll-your-own deployment requires ~1-2 FTE to maintain (patching OpenLDAP + MIT Kerberos + BIND + nslcd + PAM, schema extensions, replication topology, cert distribution). The same functionality via FreeIPA requires ~0.2-0.5 FTE (FreeIPA bundles everything and provides `ipa` CLI for management).

**Constraints**:

- N/A — out of scope. The framework should document roll-your-own as out of scope and recommend FreeIPA or framework-native.

**Cross-platform considerations**:

- **Windows**: Not applicable. Windows uses AD natively.
- **macOS**: Not applicable. macOS uses OpenDirectory.
- **Linux**: Roll-your-own is documented as out of scope. FreeIPA is the recommended alternative.
- **Cross-platform consistency**: N/A — out of scope.

**KB references**:

- [`09-linux-equivalents/09-openldap-mit-kerberos.md`](../docs/09-linux-equivalents/09-openldap-mit-kerberos.md) — `slapd` `cn=config` online config, `kerberos.schema` defining `krbPrincipal` (AUXILIARY) + `krbPrincipalName` (OID `1.3.6.1.4.1.5322.10.1.1`) + `krbPrincipalKey` (OID `1.3.6.1.4.1.5322.10.1.2`) + `krbPrincipalEncryptionKvno` + `krbPrincipalRealm` + `krbPwdPolicyReference` + `krbMaxTicketLife` + `krbMaxRenewableAge` + `krbPrincipalFlags`, MIT Kerberos `kldap` KDB backend (`dbmodules = { LDAP = { db_library = kldap; ldap_kerberos_container_dn = cn=kerberos,dc=example,dc=com; ldap_kdc_dn = uid=kdc-service,...; ldap_kadmind_dn = uid=kadmin-service,...; ldap_servers = ldaps://ldap01.example.com; ldap_conns_per_server = 5 } }`), `kdb5_ldap_util create` + `stashsrvpw` bootstrap, `nslcd.conf` filter mapping, BIND with optional GSS-TSIG, limitations table vs AD/FreeIPA (multi-master replication, GPO, DFS, forest trusts, computer accounts, PKI, site awareness, schema FSMO).
- [`08-macos-equivalents/01-opendirectory-internals.md`](../docs/08-macos-equivalents/01-opendirectory-internals.md) — macOS OpenDirectory as the analogous "platform-native directory service that bridges to AD" (conceptually similar to the roll-your-own OpenLDAP + MIT Kerberos stack), `opendirectoryd` daemon with plug-in registry (`DSP.local`, `DSP.LDAPv3`, `DSP.ActiveDirectory`), `dsAttrTypeStandard:` schema mapping to AD attributes, local `dslocal` Berkeley-DB-style backing store at `/var/db/dslocal/nodes/Default/`, demonstrating that even Apple's bundled platform-native directory is closer to AD LDS (LDAP directory without DC functions) than to full AD DS.

**Open questions**:

- Document as out of scope (recommend FreeIPA or framework-native), or provide migration tooling from OpenLDAP + MIT Kerberos to FreeIPA (`ipa-replica-prepare` from a snapshot of the LDAP DIT)?
- For academic/research environments that prefer roll-your-own (no vendor lock-in), provide a "framework-lite" mode that bundles OpenLDAP + MIT Kerberos + BIND + certmonger as the framework's identity layer?

**Cross-capability impact**:

- Affects: PC-101 (FreeIPA — roll-your-own is the alternative to FreeIPA; documenting both as out of scope pushes users toward framework-native or FreeIPA).
- Affected by: N/A (out of scope).

---

### PC-104 — Centrify / PBIS / AdmitMac / DAVE are legacy third-party macOS agents

**Capability**: Cross-Platform Parity
**Severity**: low
**Cross-platform**: macOS

**Problem statement**:

Four third-party macOS AD agents predate Apple's first-party Kerberos SSO Extension (macOS 10.15+) and Platform SSO (macOS 13+) and survive in legacy/regulated deployments where the Apple-bundled OD AD plug-in is insufficient. Centrify DirectControl (now CyberArk since the 2024 acquisition, `/usr/local/share/centrifydc/bin/adjoin` + `/usr/local/share/centrifydc/sbin/adclient` + `dzdo` sudo replacement + Centrify Heimdal fork) — most invasive, ships its own Kerberos implementation for deterministic behavior across macOS/Linux/AIX/HP-UX/Solaris. BeyondTrust PBIS (formerly Likewise, deprecated macOS 2022, `/opt/pbis/bin/domainjoin-cli` + `/opt/pbis/sbin/lwsmd` + `lwreg`/`lwsm` + `libnss_pbis.dylib` shim) — ports the Linux stack to macOS, deprecated in favor of Apple PSSO. Thursby AdmitMac (legacy, `/Library/Filesystems/AdmitMac.fs/` kernel extension + `pam_admitmac.so` PAM module + Thursby Kerberos) — alternative SMB/Kerberos stack, predates Apple's AD plug-in. Thursby DAVE (legacy, `/Library/Filesystems/DAVE.fs/` kernel extension) — SMB-client-only (no AD authentication), predates SMBX, per [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md).

All four are being superseded by Apple PSSO + Jamf Connect. Centrify is the only actively-maintained agent (under CyberArk); PBIS macOS is EOL (2022); AdmitMac and DAVE are maintenance-only. The framework should not depend on these; provide first-party macOS support via PSSO. For migration, the framework should document paths from each legacy agent to PSSO, including: (a) Centrify `adjoin`-bound Macs → `dsconfigad` or PSSO enrollment, with `dzdo` rules → `/etc/sudoers.d/` migration; (b) PBIS `domainjoin-cli`-bound Macs → `dsconfigad` or PSSO enrollment, with `/opt/pbis/config/reg.dat` settings → MDM Configuration Profile translation; (c) AdmitMac/DAV-E → native SMBX (already default since macOS 10.14), no migration needed for SMB; AdmitMac AD auth → PSSO.

**Impact**:

Legacy agents are EOL or maintenance-only. Quantified: ~10-15% of enterprise macOS deployments still run Centrify (the only actively-maintained agent); ~5% still run PBIS (deprecated); <1% still run AdmitMac/DAVE (maintenance-only). The framework's macOS strategy cannot depend on these agents.

**Constraints**:

- N/A — out of scope. The framework should not depend on legacy third-party macOS agents.
- Must provide first-party macOS support via PSSO.
- Must document migration paths from Centrify/PBIS/AdmitMac/DAVE to PSSO.

**Cross-platform considerations**:

- **Windows**: Not applicable.
- **macOS**: Legacy agents are EOL or maintenance-only. PSSO is the modern path.
- **Linux**: Not applicable (Centrify and PBIS have Linux variants; Centrify Linux is still active, PBIS Linux is deprecated 2014 open-source).
- **Cross-platform consistency**: N/A — out of scope.

**KB references**:

- [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md) — Centrify DirectControl (`adclient` daemon, `adjoin`/`adleave`/`adinfo`/`adquery`/`cinfo`/`dzdo`/`dzinfo` CLIs, `/etc/centrifydc/centrifydc.conf` INI config, `/var/centrifycc/` runtime, Centrify Heimdal fork with audit hooks, `dzdoCommandRights`/`dzdoRole` auxiliary classes on AD user/group objects pushed by Centrify Access Manager Console), BeyondTrust PBIS (`domainjoin-cli`, `lwreg`/`lwsm`/`lwsmd`, `/opt/pbis/config/reg.dat` TDB registry, `libnss_pbis.dylib` shim via DYLD insert), Thursby AdmitMac (`/Library/Filesystems/AdmitMac.fs/` kernel extension + `pam_admitmac.so` + Thursby Kerberos + `DAVEmount`), Thursby DAVE (`/Library/Filesystems/DAVE.fs/` SMB-client-only), comparison summary table showing maintenance status (Apple OD AD plug-in active, Kerberos SSO Extension active, PSSO active, Centrify active, PBIS macOS EOL, AdmitMac maintenance, DAVE maintenance).
- [`08-macos-equivalents/04-platform-sso-extension.md`](../docs/08-macos-equivalents/04-platform-sso-extension.md) — PSSO Extension (`Authentication_SSO.appex`) as the modern replacement for all four legacy agents, `com.apple.configuration-ext.platform-sso` MDM payload schema with `AuthenticationMethod: Hardware_Bound | Password`, SEP-bound ECDSA P-256 key generation via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclaveTokenID`, `sso_util configure -a <IdP-type>` CLI, demonstrating that the framework's macOS strategy should be PSSO-first with documented migration paths from Centrify/PBIS/AdmitMac/DAVE.

**Open questions**:

- Document migration paths from Centrify/PBIS/AdmitMac/DAVE to PSSO, including `dzdo` rules → `sudoers` migration for Centrify?
- Provide import tooling for `dzdo` rules (Centrify's AD-stored RBAC rules in `dzdoCommandRights`/`dzdoRole` auxiliary classes) → `/etc/sudoers.d/` files for PSSO-managed Macs?

**Cross-capability impact**:

- Affects: PC-086 (PSSO Extension — PSSO replaces all four legacy agents).
- Affected by: N/A (out of scope).

---

### PC-105 — Heimdal Kerberos on macOS is a fork tracking upstream ~2014

**Capability**: Cross-Platform Parity
**Severity**: medium
**Cross-platform**: macOS

**Problem statement**:

Apple ships Heimdal Kerberos at `/usr/lib/libkerberos.dylib` and `/usr/lib/libheimdal-asn1.dylib`, exposed via `/usr/bin/kinit`, `/usr/bin/klist`, `/usr/bin/kdestroy`, `/usr/bin/kpasswd`. The fork has not tracked upstream Heimdal since approximately 2014. Missing features vs upstream Heimdal and vs MIT krb5: (a) `PAC_FULL_CHECKSUM` (introduced Server 2016, MS-KILE §2.2) — a full-ticket signature over the entire PAC, separate from the per-buffer signatures, that defends against PAC tampering; macOS Heimdal fork does not validate `PAC_FULL_CHECKSUM` and will accept tickets that MIT krb5 1.16+ and Heimdal 7.5+ reject; (b) claims-based Kerberos (compound identity, MS-KILE ` compound identity` for constrained delegation across forest trusts) — macOS Heimdal fork does not produce or consume compound identity PACs; (c) `PAC_REQUESTER` (Server 2016+) — a PAC buffer identifying the requesting client principal in TGS-REQ, used for KDC audit logging; macOS Heimdal fork ignores this buffer; (d) recent Kerberos CVE patches — Apple backports critical CVEs (e.g. CVE-2020-17049 Kerberos Bronze Bit) but less-critical CVEs (e.g. CVE-2024-26458, CVE-2024-26461) may not be backported, per [`08-macos-equivalents/05-kerberos-sso-extension.md`](../docs/08-macos-equivalents/05-kerberos-sso-extension.md), [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md), and [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md).

Apple recommends PSSO Extension for new deployments, which uses the system Heimdal under the hood (so the fork status affects PSSO too). The framework's macOS client must use PSSO + system Heimdal and document the gaps. For features that require `PAC_FULL_CHECKSUM` or compound identity (rare in practice — most deployments don't enable these on AD), the framework must either (a) document macOS as limited (PAC validation accepts tickets that other platforms reject), or (b) provide a fresh Kerberos implementation on macOS that tracks upstream Heimdal or MIT krb5 (large engineering effort, conflicts with PSSO's use of system Heimdal).

Apple also ships an MIT-compatible shim at `/usr/lib/libMITKerberosShim.dylib` that redirects MIT-style GSSAPI calls to Heimdal. This is what allows MIT-kerberos-compiled code (Homebrew packages) to work against the system keychain. The shim does not add the missing features (PAC_FULL_CHECKSUM, etc.) — it just maps API calls. So Homebrew MIT krb5 packages on macOS are also affected by the underlying Heimdal fork's limitations when they call into the system Kerberos via the shim.

**Impact**:

macOS Kerberos is missing modern PAC features. Quantified: in AD deployments that enable `PAC_FULL_CHECKSUM` enforcement (Server 2016+ default for new forests, but not retroactive on upgraded forests), macOS clients may accept tickets that should be rejected, creating a security gap. In AD deployments that use compound identity for constrained delegation (rare, requires forest functional level 2016+), macOS clients cannot participate. For typical AD deployments (Server 2012 R2 functional level, no `PAC_FULL_CHECKSUM` enforcement), macOS clients work fine.

**Constraints**:

- Must support `PAC_FULL_CHECKSUM` validation (KDC-side and client-side) for interop with Server 2016+ forests that enforce it.
- Must support `PAC_REQUESTER` (KDC-side audit logging) for Server 2016+ forests.
- Must support compound identity for constrained delegation across forest trusts.
- On macOS, must use PSSO Extension + system Heimdal (cannot replace system Heimdal without breaking PSSO).
- Must document macOS limitations where the system Heimdal fork cannot support modern PAC features.

**Cross-platform considerations**:

- **Windows**: Uses MS-KILE in `kdcsvc.dll`; full `PAC_FULL_CHECKSUM` and compound identity support since Server 2016.
- **macOS**: System Heimdal fork (~2014-era). Missing `PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, compound identity. PSSO Extension uses system Heimdal, so inherits the gaps.
- **Linux**: MIT krb5 (SSSD) and Heimdal (Samba) both track upstream and support `PAC_FULL_CHECKSUM` since 2018 (MIT) and 2017 (Heimdal).
- **Cross-platform consistency**: PAC validation must produce identical results on every platform. The framework's PAC validator should be a shared library (Rust or C) that all platforms use, rather than relying on each Kerberos implementation's bundled parser. This is the only viable path to consistent PAC validation across macOS (stale Heimdal), Linux (MIT or Heimdal), and Windows (MS-KILE).

**KB references**:

- [`08-macos-equivalents/05-kerberos-sso-extension.md`](../docs/08-macos-equivalents/05-kerberos-sso-extension.md) — PSSO Extension's use of system Heimdal via `Kerberos.framework`, `/usr/lib/libkerberos.dylib` + `/usr/lib/libheimdal-asn1.dylib` library paths, `kinit --version` confirming Heimdal banner, ticket cache `API:Initialdefaultcache` (Heimdal's in-process store backed by keychain).
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — RFC 4120 ASN.1 message structures, PA-DATA type table (PA-ENC-TIMESTAMP type 2, PA-FX-FAST type 133, PA-PK-AS-REQ type 17 for PKINIT, PA-SUPPORTED-ENCTYPES type 167 for AD-extension KDC enctype advertisement), `EncTicketPart` `authorization-data` field where the PAC lives (AD-IF-RELEVANT type 0 wrapping AD-WIN2K-PAC type 128), MS-KILE profile extensions including `PAC_FULL_CHECKSUM` and `PAC_REQUESTER` (Server 2016+).
- [`08-macos-equivalents/07-third-party-agents-mac.md`](../docs/08-macos-equivalents/07-third-party-agents-mac.md) — macOS system Heimdal version (`kinit --version` outputs `heimdal "Heimdal 1.21" (Apple MITKerberosShim-1.21)` — version string suggests Heimdal 1.21-equivalent API surface but the underlying PAC validation code is older), `libMITKerberosShim.dylib` MIT-compat shim, Homebrew Samba's MIT Kerberos stack conflicting with system Heimdal.

**Open questions**:

- Contribute Apple's Heimdal fork upstream to reduce divergence from mainline Heimdal, accepting that Apple has shown limited interest in upstreaming?
- Document PSSO as the only modern path on macOS and document the missing PAC features (`PAC_FULL_CHECKSUM`, `PAC_REQUESTER`, compound identity) as macOS limitations?
- Write a unified PAC validator (shared Rust/C library) that all platforms use, bypassing each Kerberos implementation's bundled parser, so macOS gets `PAC_FULL_CHECKSUM` validation despite the stale Heimdal fork?

**Cross-capability impact**:

- Affects: PC-023 (KDC MS-KILE profile — the KDC must produce `PAC_FULL_CHECKSUM`-bearing tickets for Server 2016+ interop; the macOS client's stale Heimdal cannot validate them), PC-090 (Heimdal vs MIT — the macOS Heimdal fork is the most stale of the three implementations).
- Affected by: PC-086 (PSSO Extension — PSSO uses system Heimdal, so PSSO inherits the fork's limitations).

---

## Cross-capability impact

The Cross-Platform Parity capability's twelve problems cluster around three architectural tensions:

1. **Policy unification** (PC-095, PC-096, PC-098): The framework must provide a single declarative policy format that compiles to GPO (Windows), Configuration Profile + DDM (macOS), and sssd.conf + Ansible (Linux). Without unification, policy drift between platforms causes security gaps and compliance audit failures. The Policy Engine (PC-050+) is the server-side compilation target; the Client SDK (PC-085+) is the client-side application layer.

2. **Secrets management parity** (PC-097, PC-098, PC-102): Disk-encryption recovery, local admin password rotation, and RODC password replication policy all share the directory-storage model with ACL-gated retrieval. The framework must provide a unified secrets-escrow architecture that works on every platform. The Core Directory (PC-013+) must support the necessary schema (`msFVE-RecoveryInformation` for BitLocker, `msLAPS-Password` for LAPS, `msDS-RevealedUsers` for RODC).

3. **Kerberos and identity stack fragmentation** (PC-094, PC-099, PC-100, PC-101, PC-103, PC-104, PC-105): macOS lacks native NTLM (PC-094); Linux has three competing AD-integration stacks (PC-099); macOS OpenDirectory has gaps vs Windows AD (PC-100); FreeIPA is a separate Linux identity platform (PC-101); roll-your-own OpenLDAP + MIT Kerberos is high-effort (PC-103); legacy third-party macOS agents are EOL (PC-104); macOS Heimdal fork is stale (PC-105). The framework must standardize on a unified identity stack — SSSD on Linux (PC-088), PSSO on macOS (PC-086), native AD on Windows — with documented gaps where platform-native stacks cannot match.

Cross-capability impacts that flow into Cross-Platform Parity from other capabilities:

- From **Core Directory** (PC-013, ACL evaluation engine): The unified secrets-escrow architecture (PC-097, PC-098) depends on the directory's ACL evaluation engine to gate retrieval.
- From **KDC** (PC-023, MS-KILE profile): Kerberos PAC validation parity (PC-105) depends on the KDC producing tickets that all platform clients can validate.
- From **Auth Provider** (PC-029, NTLM relay mitigation): NTLM parity (PC-094) depends on the Auth Provider's NTLM implementation being available on every platform.
- From **Policy Engine** (PC-050, policy distribution): Unified policy authoring (PC-095) depends on the Policy Engine's compilation target supporting all three platforms.
- From **Client SDK** (PC-085, universal SDK): Platform-specific gaps (PC-100, PC-105) are addressed by the Client SDK's platform-native code.
- From **File Gateway** (PC-078, SMB 3.1.1): DFS-N referral parity (PC-100) depends on the File Gateway's MS-DFSC referral implementation.
- From **Operations** (PC-106, observability): Cross-platform observability (Prometheus + OpenTelemetry) must produce identical metrics from every platform's native stack.

## Open research questions specific to this capability

1. **Unified policy format** — OPA Rego (policy-as-code, Kubernetes-native), JSON Schema + per-platform executors, or a per-policy-type DSL (similar to Terraform HCL)? What is the compilation target for each platform (ADMX + Registry.pol + Security CSE for Windows, Configuration Profile + DDM for macOS, sssd.conf + Ansible for Linux)?

2. **Cross-platform secrets escrow** — Per-computer recovery key in framework directory (reusing Windows LAPS schema `msLAPS-Password` and BitLocker schema `msFVE-RecoveryInformation`), or NBDE (Clevis/Tang) for all platforms (Tang server holds decryption key; client needs network to decrypt)? What is the macOS FileVault recovery key escrow story (MDM `com.apple.security.FDERecoveryKeyEscrow` pointing at framework endpoint, or Apple's institutional recovery key)?

3. **macOS Kerberos PAC parity** — Contribute Apple's Heimdal fork upstream to reduce divergence, write a unified PAC validator (shared Rust/C library) that bypasses each Kerberos implementation's bundled parser, or document macOS as limited (PAC validation accepts tickets that other platforms reject)?

4. **RODC cross-platform** — Kubernetes-style read-replica with no secrets (framework's Core Directory runs as a read-only replica in the branch office, no KDC, no password hashes — all auth forwarded to a hub-site DC), or edge-deployed DC with HSM-bound subset (framework's KDC runs in the branch office with an HSM-bound master key, password hashes cached only for the `msDS-RevealedUsers` list)?

5. **FreeIPA strategy** — Adopt FreeIPA as the Linux tier (preserve existing deployments, leverage HBAC/sudo/ID views/cert management), build native IPA-equivalent in the framework (re-implement HBAC, sudo rules, ID views, cert management — ~2-3 years of engineering effort), or document FreeIPA as out of scope and require direct AD-join via SSSD (loss of HBAC/sudo/ID views)?

6. **Legacy third-party macOS agents** — Document migration paths from Centrify/PBIS/AdmitMac/DAVE to PSSO, including `dzdo` rules → `sudoers` migration for Centrify? Provide import tooling for `dzdo` rules (Centrify's AD-stored RBAC rules in `dzdoCommandRights`/`dzdoRole` auxiliary classes) → `/etc/sudoers.d/` files for PSSO-managed Macs?

7. **NTLM cross-platform** — Provide NTLM via Samba winbind on macOS (Homebrew dependency, separate `winbindd` process), write a fresh NTLM client in the framework's macOS SDK (Rust or Swift, ~3000 lines for NTLMv2 client + channel binding), or document legacy NTLM-requiring apps as out of scope and require Kerberos migration?
