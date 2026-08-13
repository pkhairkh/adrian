---
title: Master Feature × OS Matrix
audience: senior-engineers
tags: [matrix, comparison, features, os-support, cross-platform]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../01-ad-core/02-ad-cs-cert-services.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../01-ad-core/04-ad-lds-adam.md
  - ../01-ad-core/05-ad-rms-rights.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/07-ntp-time-sync.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../03-directory-schema/03-global-catalog.md
  - ../04-group-policy/01-gpo-architecture.md
  - ../04-group-policy/04-cse-client-side-extensions.md
  - ../08-macos-equivalents/01-opendirectory-internals.md
  - ../08-macos-equivalents/07-third-party-agents-mac.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../08-macos-equivalents/05-kerberos-sso-extension.md
  - ../08-macos-equivalents/01-opendirectory-internals.md
  - ../08-macos-equivalents/07-third-party-agents-mac.md
  - ../08-macos-equivalents/07-third-party-agents-mac.md
  - ../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../09-linux-equivalents/03-sssd-gpo-access.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../09-linux-equivalents/08-freeipa-trust.md
  - ../09-linux-equivalents/09-openldap-mit-kerberos.md
  - ./02-protocol-implementation-matrix.md
  - ./05-gpo-equivalents-matrix.md
last_updated: 2026-08-13
---

# Master Feature × OS Matrix

Authoritative capability grid: AD feature rows × operating-system columns. Cells use ✓ native, ✗, or `partial (note)`. Link column points to the topic file that documents the feature in depth.

## Legend

| Symbol | Meaning |
|---|---|
| ✓ | Native, fully supported by the platform vendor |
| ✗ | Not implemented; third-party workarounds only |
| partial | Works with caveats — note in cell |

## Feature × OS matrix

| Feature | Win10/11 native | Win Server DC | macOS Native OD | macOS Enterprise MDM | macOS 3rd-party agent | Linux SSSD | Linux Winbind | Linux PBIS | Linux FreeIPA | Linux Pure OSS | Detail |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Kerberos auth (AS/TGS) | ✓ (klist, LSA) | ✓ (KDC) | ✓ (Heimdal kdc, deprecated) | ✓ via Kerberos SSO Ext | ✓ (Admit/ADP) | ✓ (MIT krb5) | ✓ (Heimdal via Samba) | ✓ (bundled MIT) | ✓ (MIT krb5) | ✓ (MIT or Heimdal) | [02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) |
| NTLM fallback | ✓ (SSP, on by default) | ✓ (DC validates) | ✗ | ✗ | partial (Admit) | partial (winbind only) | ✓ (nmb/winbind) | ✓ | ✗ | partial (Samba client) | [02-protocols/04-ntlm-internals.md](../02-protocols/04-ntlm-internals.md) |
| LDAP directory | ✓ (WLDAP32) | ✓ (w3wp/lsass) | ✓ (OpenDirectory slapd) | ✗ | ✓ (Admit LDAP) | ✓ (openldap) | ✓ (openldap) | ✓ (openldap) | ✓ (389DS) | ✓ (OpenLDAP/389) | [02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) |
| GPO distribution (SYSVOL) | ✓ (gpsvc.dll) | ✓ (sysvol share) | ✗ | partial (profiles only) | partial (Jamf/Centrify) | partial (sssd-gpo) | ✗ | ✓ (Centrify GPO) | ✗ | ✗ | [04-group-policy/01-gpo-architecture.md](../04-group-policy/01-gpo-architecture.md) |
| GPO access control (security filter) | ✓ | ✓ | ✗ | partial (scope) | partial | partial (sssd-gpo) | ✗ | partial | ✗ | ✗ | [04-group-policy/02-gpo-processing-order.md](../04-group-policy/02-gpo-processing-order.md) |
| GPO Preferences (Drive Maps, Files, Reg, Tasks) | ✓ (gppref.dll) | ✓ | ✗ | partial (profile payloads) | ✗ | partial (sssd only reads subset) | ✗ | ✗ | ✗ | ✗ | [04-group-policy/04-cse-client-side-extensions.md](../04-group-policy/04-cse-client-side-extensions.md) |
| ADMX (Central Store) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | [04-group-policy/03-admx-templates.md](../04-group-policy/03-admx-templates.md) |
| Global Catalog | ✓ (ldap port 3268) | ✓ (GC role) | ✗ | ✗ | partial (ldap query) | partial (ldap query) | partial (ldap query) | partial | partial (IPA) | partial | [03-directory-schema/03-global-catalog.md](../03-directory-schema/03-global-catalog.md) |
| Universal Group Caching | ✓ (transparent) | ✓ (site opt) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | [03-directory-schema/03-global-catalog.md](../03-directory-schema/03-global-catalog.md) |
| AD-integrated DNS | ✓ (DNS client) | ✓ (dns.exe + AD) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | partial (FreeIPA DNS) | partial (BIND + dlz) | [02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| Dynamic DNS updates (GSS-TSIG) | ✓ | ✓ | ✓ (dns-sd only mDNS) | ✓ via config profile | ✓ (Admit) | ✓ (sssd_dyndns) | ✓ (net ads dns) | ✓ | ✓ (ipa dnsupdate) | ✓ (nsupdate -g) | [02-protocols/05-dns-dynamic-updates.md](../02-protocols/05-dns-dynamic-updates.md) |
| PKI / CA (AD CS) | ✓ (client) | ✓ (AD CS role) | ✗ | partial (SCEP profile) | partial (ADP) | partial (certmonger) | partial (certmonger) | partial | ✓ (Dogtag/FreeIPA CA) | ✓ (Dogtag/OpenXPKI) | [01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| Cert autoenrollment | ✓ (certreq -enroll) | ✓ (policy/exit mods) | ✗ | partial (SCEP) | partial (ADP) | partial (certmonger + SCEP) | ✗ | ✓ (BeyondTrust) | ✓ (IPA cert-get-request) | partial (certmonger) | [01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| OCSP responder query | ✓ (crypt32) | ✓ (AD CS Online Responder) | ✓ (Security framework) | ✓ | ✓ | ✓ (openssl/nss) | ✓ | ✓ | ✓ (Dogtag OCSP) | ✓ (openssl) | [01-ad-core/02-ad-cs-cert-services.md](../01-ad-core/02-ad-cs-cert-services.md) |
| AD FS (SAML/WS-Fed/OIDC) | ✓ (claims-aware app) | ✓ (AD FS role) | partial (browser only) | partial (browser) | partial | partial (browser) | partial | partial | partial (Keycloak bridge) | partial (Keycloak) | [01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| Web Application Proxy | ✓ (client) | ✓ (WAP role) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ (use nginx/mod_auth_mellon) | [01-ad-core/03-ad-fs-federation.md](../01-ad-core/03-ad-fs-federation.md) |
| RMS / IRM (AD RMS) | ✓ (msipc.dll) | ✓ (AD RMS role) | partial (Azure RMS) | partial (Azure RMS) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | [01-ad-core/05-ad-rms-rights.md](../01-ad-core/05-ad-rms-rights.md) |
| SMB file shares (client) | ✓ (mrxsmb.sys) | ✓ (srv2.sys) | ✓ (SMBX/smbd) | ✗ | ✓ (Acronis) | ✓ (cifs-utils/mount.cifs) | ✓ (cifs-utils) | ✓ | ✓ | ✓ (cifs-utils) | [02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| DFS-N (namespace) | ✓ (mup.sys) | ✓ (DFS role) | ✓ (mount_smbfs resolves) | ✗ | partial | ✓ (mount -t cifs) | ✓ | ✓ | ✓ | ✓ | [02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| DFS-R (replication) | ✓ (DFSR service) | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ (rsync/syncthing) | [02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| Print services (Print Mgmt) | ✓ (spoolsv) | ✓ (Print role) | ✓ (CUPS) | ✓ (AirPrint) | partial | ✓ (CUPS) | ✓ (CUPS) | ✓ | ✓ (CUPS) | ✓ (CUPS) | [02-protocols/03-smb-cifs-protocol.md](../02-protocols/03-smb-cifs-protocol.md) |
| Offline Files (CSC) | ✓ (cscsvc) | ✓ (share perms) | partial (Docs To Go) | partial | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | [04-group-policy/04-cse-client-side-extensions.md](../04-group-policy/04-cse-client-side-extensions.md) |
| RODC | ✓ (client) | ✓ (RODC role) | ✗ | ✗ | ✗ | ✓ (sssd has RODC mode) | ✗ | ✗ | ✗ | ✗ | [01-ad-core/01-ad-ds-internals.md](../01-ad-core/01-ad-ds-internals.md) |
| BitLocker with AD recovery | ✓ (BDREncrypt) | ✓ (schema ext) | ✗ | ✗ | partial (FileVault to ADP) | ✗ (use LUKS) | ✗ | ✗ | partial (Clevis/Tang) | ✗ (LUKS only) | [01-ad-core/01-ad-ds-internals.md](../01-ad-core/01-ad-ds-internals.md) |
| LAPS (local admin pw mgmt) | ✓ (LAPS ADMX/CSE) | ✓ (schema ext) | ✗ | partial (Jamf LAPS-like) | partial (ADP) | partial (homemade scripts) | ✗ | partial | partial (IPA host pw) | ✗ | [04-group-policy/03-admx-templates.md](../04-group-policy/03-admx-templates.md) |

## Notes on matrix columns

- **Win10/11 native** — out-of-box capability with no extra agent. SMB, Kerberos, LDAP, NTLM, GPO, BitLocker, LAPS all shipped.
- **Win Server DC** — full server role set: KDC, AD CS, AD FS, AD RMS, AD LDS, DNS, Print, File, Hyper-V Replica host (out of scope here).
- **macOS Native OD** — OpenDirectory uses Heimdal Kerberos and an LDAP store; binds to AD via `dsconfigad` only — no GPO.
- **macOS Enterprise MDM** — Configuration Profiles (`.mobileconfig`) replace most GPOs. PSSO Extension (macOS 13+) replaces Enterprise Connect.
- **macOS 3rd-party agent** — Centrify (now Delinea), Admit+Jamf Connect, BeyondTrust PBIS (deprecated). Adds Kerberos SSO, GPO-like config, AD-side cert enrollment.
- **Linux SSSD** — `sssd-ad` provider; integrates with realmd, MIT krb5, and Samba client libs. Reads a subset of GPO (security filtering for logon rights).
- **Linux Winbind** — Samba `winbindd` with `idmap_rid`; full SMB client/DC integration but no GPO consumption.
- **Linux PBIS** — BeyondTrust PBIS Open (formerly Likewise); GPO engine for Linux; LGPL layer. Deprecated 2023.
- **Linux FreeIPA** — IdM with cross-forest trust to AD; clients use SSSD underneath. FreeIPA CA (Dogtag) replaces AD CS for IPA-issued certs.
- **Linux Pure OSS** — MIT krb5 + OpenLDAP + Samba + BIND + certmonger + nsupdate; no domain-join framework — manual `ksetup`-equivalent glue.

## Coverage caveats

- Only first-class AD features are rows. Secondary surfaces (e.g., ADWS, Active Directory Administrative Center, RSAT) are tooling, not features — see [03-tool-function-matrix.md](03-tool-function-matrix.md).
- NTLM on macOS/Linux clients is *possible* via Samba's `libsmbclient` but never the default; application stacks that hard-require NTLM (old SQL Server drivers, old IIS-integrated apps) fail.
- DFS-N namespace lookup works on any SMB client; DFS-R is a server-only feature (Linux replicas use rsync/syncthing, semantically different).
- "RODC" for Linux SSSD refers to RODC-aware behavior: `ad_site`, `ad_server` pinning, and `krb5_confd_path` for partial-KDC environments — not running as RODC itself (impossible).
- "LAPS" on macOS/Linux is approximate: no native equivalent; MDM/Jamf can rotate local admin passwords and report to a server, but the storage model differs (not the AD `ms-MCS-AdmPwd` attribute).

## Per-feature deep notes

### Kerberos auth
- **Win10/11 + Win Server DC**: end-to-end native. KDC = `kdcsvc` in lsass. Pre-auth via `PA-ENC-TIMESTAMP` (RFC 4120 §5.2.7.2) using the user's long-term key derived from password per `string2key` (RFC 3961). AES-256 (etype 0x12) is the default since Server 2012 R2; RC4 (etype 0x17) is disabled by default since Server 2022.
- **macOS Native OD**: Apple ships a Heimdal Kerberos fork. As of macOS 14 Sonoma, the fork has not tracked upstream since approximately 2014 — known gap on PAC_FULL_CHECKSUM (Server 2016+) and claims-based Kerberos (compound identity). Apple recommends migrating to the Platform SSO Extension (PSSO) for new deployments.
- **macOS Enterprise MDM**: PSSO Extension (`com.apple.applesso`) implements Kerberos AS-REQ/TGS-REQ through the system Heimdal libs. Supports FAST armoring (Server 2012+) and PKINIT (smart-card / PIV / CAC). Enrollment requires a configuration profile with the `com.apple.applesso` payload.
- **macOS 3rd-party agent**: Centrify (Delinea) DirectControl, Jamf Connect, BeyondTrust PBIS, Admit. Each bundles a Kerberos implementation (typically MIT krb5 with platform-specific patches). Adds GPO consumption that macOS natively lacks.
- **Linux SSSD**: Uses MIT krb5 (`/usr/lib64/libkrb5.so`) via `krb5_child` helper. TGT cached in `KEYRING:persistent:<uid>` (default) or `DIR:`/`FILE:` per `krb5_ccache_template`. Renewal daemon auto-renews at 50% lifetime (`krb5_renew_interval = 1h`).
- **Linux Winbind**: Bundles Heimdal (the Samba build choice). TGT in `/var/cache/samba/krb5cc_<uid>`. Renewal is *not* automatic — relies on `winbind refresh tickets = yes` and the user session lifetime.
- **Linux PBIS**: Ships MIT krb5 with custom patches for AD compat. Deprecated 2023; Delinea recommends migrating to DirectControl or SSSD.
- **Linux FreeIPA**: MIT krb5 + custom KDB plugin (`ipa_kdb`) that reads principals from 389DS. For cross-forest AD trusts, the KDC issues MS-PAC-bearing tickets via `ipa_kdb_mspac.c`.
- **Linux Pure OSS**: Pure MIT krb5 + OpenLDAP + BIND; no domain-join framework. Manual config of `/etc/krb5.conf`, `/etc/ldap/ldap.conf`, `/etc/nslcd.conf` (or `nss-pam-ldapd`), `pam_krb5`, `nss_ldap`.

### NTLM fallback
- Microsoft deprecated NTLMv1 in Server 2008 R2; NTLMv2 is still supported but disabled by default in newer builds. The "Restrict NTLM" GPOs allow inbound/outgoing auditing and blocking per-direction.
- macOS has zero native NTLM support. SMBX will fail-back to guest or refuse connection if NTLM is the only option. Third-party agents (Centrify) provide an NTLMSSP module.
- SSSD does NOT implement NTLM — it relies on Samba's `libsmbclient` and `pam_winbind` for any NTLM need. Samba's `client ntlm auth = disabled` is the modern default.

### GPO distribution (SYSVOL)
- SYSVOL is an SMB share (`\\<domain>\SYSVOL\`) replicated between DCs via DFS-R (Server 2008+). Each GPO has a GPC in the AD partition (LDAP) and a GPT in SYSVOL (SMB). Client pulls both via SMB and LDAP at refresh.
- macOS has zero native GPO support. MDM Configuration Profiles replace a subset (security policies, password rules, firewall, certificate deployment) but lack the full ADMX breadth. Most enterprise GPOs map to MDM payloads imperfectly — see [05-gpo-equivalents-matrix.md](05-gpo-equivalents-matrix.md).
- SSSD reads a subset of GPOs (`GptTmpl.inf` security CSE) for URA-based access control. Does NOT process Preferences, ADMX-backed registry policies, scripts, or Folder Redirection.

### BitLocker with AD recovery
- Windows backs up BitLocker recovery passwords to AD as a child object of the computer account: `CN=<GUID>,CN=<computer>,CN=BitLocker Recovery,CN=...`. Requires schema extension (BitLocker ADM templates) and GPO enabled.
- macOS FileVault recovery key escrow goes to Apple or MDM (Jamf/Intune), not AD. MDM can rotate the recovery key on schedule (similar functional outcome).
- Linux LUKS has no AD recovery. Clevis+Tang network-bound disk encryption (NBDE) is the standard alternative — Tang server (typically FreeIPA-managed) holds the decryption key; client needs network access to decrypt.

### LAPS
- Microsoft LAPS (legacy + the new Windows LAPS in Server 2022+) stores the local admin password hash + history in `ms-MCS-AdmPwd` / `msLAPS-Password` on the computer object. GPO-managed rotation; read access via AD ACLs.
- macOS has no native equivalent. MDM (Jamf) rotates the local admin password via a daemon policy and escrows to the Jamf server, with retrieval gated by Jamf RBAC.
- Linux clients typically rely on Ansible or Puppet for local-admin password rotation. FreeIPA has `ipa host-mod --password=<otp>` which rotates the host's enrollment password — conceptually similar but not the same as LAPS.

## Security and hardening flags per OS

| OS | Key hardening | Default posture |
|---|---|---|
| Win10/11 native | LSA Protected Mode (`RunAsPPL`), Credential Guard, SMB signing required, LDAP signing/enforcement | Mixed (depends on build) |
| Win Server DC | Disable NTLMv1, require LDAP signing, enable AES-only Kerberos, audit NTLM usage | Mixed (Server 2022+ tighter) |
| macOS Native OD | System Integrity Protection (SIP), Gatekeeper, sandbox; no native NTLM | Tight (SIP blocks LSA-like injection) |
| macOS Enterprise MDM | PSSO Extension in user-space (no kernel),`Security.framework` for cert validation | Tight |
| macOS 3rd-party agent | Varies; Centrify runs as root daemon, can intercept auth | Varies |
| Linux SSSD | `sssd` runs as `sssd` user; `krb5_child` setuid to target user; KEYRING ccaches mode 600 | Tight |
| Linux Winbind | `winbindd` runs as root; needs root for IDMAP, NSS, PAM | Moderate (root daemons) |
| Linux PBIS | Runs `lwregd`, `lwsmd`, `eventlogd` as root | Moderate |
| Linux FreeIPA | `sssd` (client) or `dirsrv`/`krb5kdc`/`kadmin`/`pki-tomcatd`/`named` (server); server daemons need root for <1024 ports | Tight (SELinux enforcing) |
| Linux Pure OSS | Depends entirely on operator choices; manual hardening required | Varies |

## See also

- [02-protocol-implementation-matrix.md](02-protocol-implementation-matrix.md) — wire-level protocol support across implementations.
- [03-tool-function-matrix.md](03-tool-function-matrix.md) — function-to-tool mapping (commands per OS).
- [04-auth-flow-comparison.md](04-auth-flow-comparison.md) — side-by-side login flow.
- [05-gpo-equivalents-matrix.md](05-gpo-equivalents-matrix.md) — ADMX → cross-platform equivalents.

## Interop cheatsheet (most common friction points)

| Pain point | Symptom | Cause | Workaround |
|---|---|---|---|
| macOS can't read SYSVOL GPOs | GPO-managed setting not applied on Mac | macOS has no GPO engine | Replicate via MDM Configuration Profile — see [05-gpo-equivalents-matrix.md](05-gpo-equivalents-matrix.md) |
| Linux client can't get service ticket for `MSSQLSvc` SPN | TGS-REQ fails with `KDC_ERR_S_PRINCIPAL_UNKNOWN` (7) | SQL Server SPN not registered | Run `setspn -S MSSQLSvc/sql01.corp.example.com:1433 svc-sql` on Windows |
| SSSD group resolution diverges from Windows | User gets different group list | `ldap_group_member = memberUid` vs `member` | Set `ldap_group_member = member` + `ldap_group_nesting_level = 2` |
| Winbind UID differs across hosts | Same AD user has different UID on two Linux boxes | `idmap config * : range` mismatch or default backend | Pin `idmap config CORP : backend = rid` + identical range on every host |
| macOS PSSO ticket not renewed | User prompted for password mid-session | PSSO Extension config lacks `autoRenew` or KDC rejects renewable flag | Set `krb5_renewable_lifetime` on DC + ensure GPO allows renewable tickets |
| Linux can't access AD CS autoenrolled cert | `certmonger` fails with `Request 1: submitted - ca error` | MS-WCCE / MS-XCEP protocol mismatch | Use SCEP if AD CS supports it, or MS-WSTEP via `certmonger dogtag-ipa-renew-agent` |
| Kerberos AES-256 ticket rejected by legacy service | Event 4 KDC_ERR_ETYPE_NOTSUPP | Service account lacks AES key in AD | Set `msDS-SupportedEncryptionTypes` to include 0x18 (AES-128 + AES-256) on service account |
| NTLM fallback blocked by GPO | App fails with "The target principal name is incorrect" | `Restrict NTLM: Outgoing NTLM authentication to remote servers` = Deny all | Register SPN or use Kerberos-aware client |
| Cross-forest trust TGT referral fails | `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) | `trustAttributes` lacks `FOREST_TRANSITIVE` (0x8) or selective auth blocks user | Re-establish trust with `/foresttransitive` flag; check `msDS-TrustForestTrustInfo` |
| BitLocker recovery password not in AD | Recovery shows "48-digit number" but AD has nothing | GPO `Choose how BitLocker-protected operating system drives can be recovered` not enabled | Enable GPO; require backup to AD before encryption |

## Decision tree: which integration model for which OS?

```
Windows 10/11 ──► Native AD (always — no decision needed)
                  │
                  └─ Use RSAT + GPO + Intune co-management if hybrid

Windows Server  ─► Native AD (DC role or member server)
                  │
                  └─ Use ADWS, PowerShell, GPO, AD CS, AD FS, AD RMS as needed

macOS 13+       ─► PSSO Extension via MDM (default for greenfield)
                  │
                  ├─ SMB shares: native SMBX
                  ├─ Certs: SCEP profile payload
                  └─ Avoid: third-party agent unless you need GPO consumption

macOS 12 and older ─► dsconfigad + Enterprise Connect (legacy)
                       │
                       └─ Plan migration to PSSO Extension (macOS 13+)

Linux (new deployment) ─► SSSD (adcli/realm) — default
                          │
                          ├─ Native Kerberos (MIT), LDAP via SASL GSSAPI
                          ├─ GPO access control subset supported
                          └─ Avoid: Winbind unless you need Samba AD-DC role

Linux (existing Winbind deployment) ─► Stay on Winbind OR migrate to SSSD
                                       │
                                       ├─ Migration requires UID remap planning
                                       └─ Mixed mode (SSSD + Winbind) is supported but discouraged

Linux (FreeIPA-managed) ─► FreeIPA with cross-forest trust to AD
                            │
                            ├─ IPA clients use SSSD underneath
                            └─ IPA CA (Dogtag) replaces AD CS for IPA-issued certs

Linux (bare / minimal) ─► Pure OSS stack (MIT krb5 + OpenLDAP + Samba client)
                          │
                          └─ Manual glue; only for constrained environments
```

## Revision history

| Date | Change |
|---|---|
| 2026-08-13 | Initial version — 25 features × 10 OS columns; added per-feature deep notes, interop cheatsheet, decision tree, hardening matrix. |
