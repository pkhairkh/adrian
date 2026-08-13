---
title: Cross-Platform Parity Matrix — Problem × Platform
audience: architects-and-engineers
tags: [cross-platform, parity-matrix, problem-catalog, framework-design]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./01-core-directory.md
  - ./02-kdc.md
  - ./03-auth-provider.md
  - ./04-policy-engine.md
  - ./05-cert-service.md
  - ./06-federation-gateway.md
  - ./07-file-gateway.md
  - ./08-client-sdk.md
  - ./09-cross-platform-parity.md
  - ./10-operations.md
  - ./11-security-threat-model.md
  - ./12-migration-and-coexistence.md
  - ./13-open-research-questions.md
last_updated: 2026-08-13
---

# Cross-Platform Parity Matrix

A single matrix mapping every problem (PC-001 through PC-130) to its impact on Windows, macOS, Linux, and cross-platform consistency. Use this matrix to spot parity gaps: rows where a single platform is blank or marked △ indicate a feature that needs explicit platform-specific design.

## Legend

- ✓ = problem applies to this platform (the platform's implementation must address it)
- △ = problem partially applies (the platform is indirectly affected via cross-platform consistency, but the platform itself does not natively have the issue)
- (blank) = problem does not apply to this platform

## Summary

- **Total problems**: 130
- **Windows**: 117 problems apply (the reference platform; nearly all problems surface here)
- **macOS**: 118 problems apply (parity gaps + cross-platform consistency drive most)
- **Linux**: 118 problems apply (parity gaps + cross-platform consistency drive most)
- **Cross-platform consistency**: 114 problems apply (problems where the framework must produce identical semantics across all three platforms)
- **Windows-only problems**: 6 (PC-006, PC-025, PC-049, PC-050, PC-107, PC-113)
- **macOS-only problems**: 6 (PC-086, PC-087, PC-096, PC-100, PC-104, PC-105)
- **Linux-only problems**: 4 (PC-088, PC-092, PC-099, PC-103)
- **Partial-coverage problems (△)**: 5 (PC-057, PC-080, PC-089, PC-090, PC-094)

The headline counts differ from the original README (Windows: 95 / macOS: 78 / Linux: 82 / cross-platform: 67) because this matrix uses a stricter interpretation: a problem marked `cross-platform` (the most common case in the extraction) is counted as applying to all three platforms plus the cross-platform consistency column. The README's lower counts reflect a more conservative interpretation where `cross-platform` alone did not imply per-platform applicability. Both interpretations are valid; the matrix below shows the actual per-cell mapping.

## Matrix

| PC | Title | Capability | Severity | Win | macOS | Linux | Cross-platform |
|----|-------|-----------|----------|-----|-------|-------|----------------|
| PC-001 | DRSUAPI replication protocol must be implemented in the framework's DC | Core Directory | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-002 | USN/InvocationID/UTD-vector replication model is unique to AD; alte... | Core Directory | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-003 | Linked Value Replication (LVR) is required for groups larger than ~... | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-004 | `member`/`memberOf` back-link requires linkID pairing and DSA-compu... | Core Directory | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-005 | Global Catalog (GC) partial attribute set replication must be imple... | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-006 | Schema cache reload blocks LDAP writes for 5–30 seconds | Core Directory | medium | ✓ |  |  |  |
| PC-007 | ESE/JET Blue database is Windows-only; framework must pick a new st... | Core Directory | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-008 | Security descriptor deduplication (`sdtable`) is required for large... | Core Directory | medium | ✓ | ✓ | ✓ | ✓ |
| PC-009 | Tombstone lifetime and lingering object cleanup must be designed | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-010 | Cross-domain move requires `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` a... | Core Directory | medium | ✓ | ✓ | ✓ | ✓ |
| PC-011 | Well-known container GUIDs are forest-wide constants | Core Directory | medium | ✓ | ✓ | ✓ | ✓ |
| PC-012 | AD-specific LDAP controls are required for client interop | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-013 | `unicodePwd` BER-quote trick for password changes is AD-specific | Core Directory | medium | ✓ | ✓ | ✓ | ✓ |
| PC-014 | FSMO roles are single-master bottlenecks; seizure is destructive | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-015 | RID pool allocation is a 500-RID batch bottleneck | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-016 | KCC topology generation every 15 minutes has scaling limits | Core Directory | medium | ✓ | ✓ | ✓ | ✓ |
| PC-017 | Schema is LDAP-schema with OIDs; typed-schema alternative requires ... | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-018 | Constructed attributes (`memberOf`, `tokenGroups`, `canonicalName`)... | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-019 | AD-integrated DNS zones replicate via DRSUAPI in DomainDnsZones/For... | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-020 | `NTDS.DIT` backup/restore requires VSS-aware snapshots | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-021 | `instanceType` and `systemFlags` are complex bitmasks that gate obj... | Core Directory | medium | ✓ | ✓ | ✓ | ✓ |
| PC-022 | Multi-tenancy is not native to AD; framework should decide whether ... | Core Directory | high | ✓ | ✓ | ✓ | ✓ |
| PC-023 | KDC must implement MS-KILE profile of RFC 4120 with PAC generation ... | KDC | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-024 | RC4-HMAC default for backwards compat is a security liability | KDC | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-025 | PAC validation RPC requires service-to-DC roundtrip | KDC | high | ✓ |  |  |  |
| PC-026 | FAST (RFC 6806) armoring is opt-in via GPO; rarely enforced | KDC | high | ✓ | ✓ | ✓ | ✓ |
| PC-027 | PKINIT smart-card logon requires NTAuthCertificates AD object + Ent... | KDC | high | ✓ | ✓ | ✓ | ✓ |
| PC-028 | Cross-realm TGT referral chain is rigid; transited field validation... | KDC | medium | ✓ | ✓ | ✓ | ✓ |
| PC-029 | AES-SHA384 (etype 0x13) support requires Server 2022+ KDC and clients | KDC | low | ✓ | ✓ | ✓ | ✓ |
| PC-030 | `krbtgt` account compromise = golden ticket; rotation is operationa... | KDC | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-031 | SPN uniqueness requires KDC-side `DRSWriteSPN` pre-commit check | KDC | high | ✓ | ✓ | ✓ | ✓ |
| PC-032 | UPN uniqueness is forest-wide but enforced inconsistently | KDC | high | ✓ | ✓ | ✓ | ✓ |
| PC-033 | KDC throughput at million-object scale is a known bottleneck | KDC | high | ✓ | ✓ | ✓ | ✓ |
| PC-034 | `kpasswd` (RFC 3244) is the only standardized password-change proto... | KDC | medium | ✓ | ✓ | ✓ | ✓ |
| PC-035 | Group Managed Service Accounts (gMSA) require KDS root key + automa... | KDC | high | ✓ | ✓ | ✓ | ✓ |
| PC-036 | NTLM must be supported for legacy interop; deprecation is operation... | Auth Provider | high | ✓ | ✓ | ✓ | ✓ |
| PC-037 | NTLM relay attacks require LDAP signing + channel binding + EPA enf... | Auth Provider | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-038 | Pass-the-hash (PtH) defense requires LSASS protection / Credential ... | Auth Provider | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-039 | S4U2Self + S4U2Proxy constrained delegation semantics are complex | Auth Provider | high | ✓ | ✓ | ✓ | ✓ |
| PC-040 | Windows Token construction (LSASS-side) vs Linux PAM stack are arch... | Auth Provider | high | ✓ | ✓ | ✓ | ✓ |
| PC-041 | Time sync (W32Time + MS-SNTP) is fragile; 5-minute Kerberos skew wi... | Auth Provider | high | ✓ | ✓ | ✓ | ✓ |
| PC-042 | Kerberos audit events (4768/4769/4771) need equivalent in framework | Auth Provider | high | ✓ | ✓ | ✓ | ✓ |
| PC-043 | GPO architecture (GPC + GPT split) is fragile; version mismatch is ... | Policy Engine | high | ✓ | ✓ | ✓ | ✓ |
| PC-044 | LSDOU processing order is last-writer-wins; no conflict resolution ... | Policy Engine | medium | ✓ | ✓ | ✓ | ✓ |
| PC-045 | GPO Preferences (XML files) have no macOS/Linux equivalent | Policy Engine | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-046 | ADMX schema is Windows-specific; cross-platform equivalent is fragm... | Policy Engine | high | ✓ | ✓ | ✓ | ✓ |
| PC-047 | CSE (Client-Side Extension) model is Windows-only; per-CSE GUIDs | Policy Engine | high | ✓ | ✓ | ✓ | ✓ |
| PC-048 | GPO has no native rollback or transactional semantics | Policy Engine | medium | ✓ | ✓ | ✓ | ✓ |
| PC-049 | WMI filters are evaluated client-side; WMI repository corruption fa... | Policy Engine | medium | ✓ |  |  |  |
| PC-050 | Slow-link detection (ICMP ping to PDC) is unreliable | Policy Engine | low | ✓ |  |  |  |
| PC-051 | GPO background refresh interval (90 min + jitter) is too slow for s... | Policy Engine | medium | ✓ | ✓ | ✓ | ✓ |
| PC-052 | Registry.pol PReg format is binary/UTF-16; needs explicit parser | Policy Engine | medium | ✓ | ✓ | ✓ | ✓ |
| PC-053 | SSSD GPO access control only enforces `[Privilege Rights]` logon ri... | Policy Engine | high | ✓ | ✓ | ✓ | ✓ |
| PC-054 | GPO security filtering on `Authenticated Users` is fragile | Policy Engine | medium | ✓ | ✓ | ✓ | ✓ |
| PC-055 | SYSVOL replication via DFS-R is Windows-only; FRS is removed | Policy Engine | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-056 | No native policy versioning / history; reverting requires backup re... | Policy Engine | medium | ✓ | ✓ | ✓ | ✓ |
| PC-057 | AD CS (certsvc.exe + ESE CA DB) is Windows-only; no open-source MS-... | Cert Service | blocker | ✓ | △ | ✓ | ✓ |
| PC-058 | Certificate templates (v1/v2/v3) with `msPKI-*` attributes are complex | Cert Service | high | ✓ | ✓ | ✓ | ✓ |
| PC-059 | Autoenrollment via `autoenroll.dll` CSE + GPO is Windows-only | Cert Service | high | ✓ | ✓ | ✓ | ✓ |
| PC-060 | Key archival (KRA) is risky; losing KRA keys loses all archived keys | Cert Service | high | ✓ | ✓ | ✓ | ✓ |
| PC-061 | OCSP responder scaling; CA database corruption during outage | Cert Service | high | ✓ | ✓ | ✓ | ✓ |
| PC-062 | CA database corruption recovery is "restore from backup, do not ese... | Cert Service | medium | ✓ | ✓ | ✓ | ✓ |
| PC-063 | Certificate revocation during CA outage (CRL/OCSP unreachable) brea... | Cert Service | high | ✓ | ✓ | ✓ | ✓ |
| PC-064 | NDES (SCEP for network devices) is fragile; IIS dependency | Cert Service | medium | ✓ | ✓ | ✓ | ✓ |
| PC-065 | Cross-CA trust (cross-cert) via `CrossCertificatePair` is rarely used | Cert Service | low | ✓ | ✓ | ✓ | ✓ |
| PC-066 | Two-tier vs three-tier CA topology is a greenfield design decision | Cert Service | medium | ✓ | ✓ | ✓ | ✓ |
| PC-067 | `NTAuthCertificates` AD object is the canonical list of logon-autho... | Cert Service | high | ✓ | ✓ | ✓ | ✓ |
| PC-068 | AD FS is heavy (WID/SQL config DB, separate farm, WAP proxy) | Federation Gateway | high | ✓ | ✓ | ✓ | ✓ |
| PC-069 | ADFS claims rule language (CRL) is proprietary DSL; migration to st... | Federation Gateway | high | ✓ | ✓ | ✓ | ✓ |
| PC-070 | Token-signing cert rollover requires RP metadata refresh; 15-day ov... | Federation Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-071 | WS-Federation and WS-Trust are legacy; OIDC is the modern path | Federation Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-072 | SAML replay detection window (60 min) and clock skew (5 min) need t... | Federation Gateway | low | ✓ | ✓ | ✓ | ✓ |
| PC-073 | AD FS Web Application Proxy (WAP) is Windows-only; modern alternati... | Federation Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-074 | ADFS farm topology (primary + secondaries in WID mode) is operation... | Federation Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-075 | ADFS as OAuth2/OIDC provider has quirks (resource= parameter, Appli... | Federation Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-076 | External OIDC IdP federation (ADFS-as-RP) needs explicit CPT config... | Federation Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-077 | AD RMS (DRM/IRM) has no open-source server; AIP is the migration path | Federation Gateway | low | ✓ | ✓ | ✓ | ✓ |
| PC-078 | SMB 3.1.1 with pre-auth integrity + AES-GCM is required for modern ... | File Gateway | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-079 | SMB1 must be dropped (security liability); migration is automatic o... | File Gateway | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-080 | DFS-N (namespace) + DFS-R (replication) are Windows-only; no Linux ... | File Gateway | high | ✓ | △ | ✓ | ✓ |
| PC-081 | Continuously Available (CA) shares require cluster + persistent han... | File Gateway | high | ✓ | ✓ | ✓ | ✓ |
| PC-082 | Access-Based Enumeration (ABE) post-filters directory listings; CPU... | File Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-083 | PrintNightmare (CVE-2021-34527) exposed MS-RPRN driver install as S... | File Gateway | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-084 | Offline Files (CSC) is Windows-only; no macOS/Linux equivalent | File Gateway | medium | ✓ | ✓ | ✓ | ✓ |
| PC-085 | No universal "AD client SDK"; Windows uses SSPI+Wldap32, macOS uses... | Client SDK | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-086 | macOS PSSO Extension (macOS 13+) replaces Enterprise Connect + NoMA... | Client SDK | high |  | ✓ |  |  |
| PC-087 | macOS Jamf Connect + ROPG password sync is fragile during IdP passw... | Client SDK | medium |  | ✓ |  |  |
| PC-088 | SSSD on Linux has GPO access control + ID mapping but no full GPO C... | Client SDK | high |  |  | ✓ |  |
| PC-089 | ID mapping (SID ↔ POSIX UID/GID) is non-deterministic across hosts ... | Client SDK | blocker | △ | ✓ | ✓ | ✓ |
| PC-090 | Heimdal vs MIT Kerberos on Linux/macOS have subtle incompatibilities | Client SDK | medium | △ | ✓ | ✓ | ✓ |
| PC-091 | Domain join (`realm join`/`adcli`/`net ads join`/`dsconfigad`) is f... | Client SDK | medium | ✓ | ✓ | ✓ | ✓ |
| PC-092 | PAM stack varies by distro (Debian/Ubuntu vs RHEL/Fedora vs SUSE) | Client SDK | medium |  |  | ✓ |  |
| PC-093 | Kerberos ticket cache type varies (FILE:, KEYRING:, KCM:, API: on m... | Client SDK | medium | ✓ | ✓ | ✓ | ✓ |
| PC-094 | macOS has no native NTLM support; legacy apps fail | Cross-Platform Parity | high | △ | ✓ | ✓ | ✓ |
| PC-095 | macOS Configuration Profiles vs Windows GPO vs Linux SSSD-conf have... | Cross-Platform Parity | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-096 | macOS DDM (Declarative Device Management) is the future but not yet... | Cross-Platform Parity | low |  | ✓ |  |  |
| PC-097 | macOS FileVault recovery key escrow goes to Apple or MDM, not AD | Cross-Platform Parity | medium | ✓ | ✓ | ✓ | ✓ |
| PC-098 | LAPS (local admin password rotation) has no macOS/Linux native equi... | Cross-Platform Parity | medium | ✓ | ✓ | ✓ | ✓ |
| PC-099 | SSSD/Winbind/PBIS are alternative Linux stacks; migration between t... | Cross-Platform Parity | medium |  |  | ✓ |  |
| PC-100 | macOS OpenDirectory AD plug-in has gaps (GPO, ABE, full DFS-N) | Cross-Platform Parity | medium |  | ✓ |  |  |
| PC-101 | FreeIPA is a separate Linux identity platform with AD cross-forest ... | Cross-Platform Parity | medium | ✓ | ✓ | ✓ | ✓ |
| PC-102 | RODC (Read-Only DC) has no Linux/macOS equivalent | Cross-Platform Parity | medium | ✓ | ✓ | ✓ | ✓ |
| PC-103 | OpenLDAP + MIT Kerberos (roll-your-own) is high-effort, low-feature | Cross-Platform Parity | low |  |  | ✓ |  |
| PC-104 | Centrify / PBIS / AdmitMac / DAVE are legacy third-party macOS agents | Cross-Platform Parity | low |  | ✓ |  |  |
| PC-105 | Heimdal Kerberos on macOS is a fork tracking upstream ~2014 | Cross-Platform Parity | medium |  | ✓ |  |  |
| PC-106 | No native Prometheus exporter / OpenTelemetry for AD | Operations | high | ✓ | ✓ | ✓ | ✓ |
| PC-107 | Schema upgrades are irreversible; `objectVersion` bump is one-way | Operations | high | ✓ |  |  |  |
| PC-108 | Multi-region AD deployment has replication latency; PDC urgent repl... | Operations | high | ✓ | ✓ | ✓ | ✓ |
| PC-109 | AD has no containerization; no Kubernetes-native deployment | Operations | high | ✓ | ✓ | ✓ | ✓ |
| PC-110 | Disaster recovery is manual (ntdsutil + metadata cleanup + IFM) | Operations | high | ✓ | ✓ | ✓ | ✓ |
| PC-111 | AD audit logs are Windows Event Log only; no structured logging | Operations | high | ✓ | ✓ | ✓ | ✓ |
| PC-112 | AD has no REST/gRPC API; only LDAP + PowerShell | Operations | high | ✓ | ✓ | ✓ | ✓ |
| PC-113 | AD functional level upgrades are one-way; mixed-version forests are... | Operations | medium | ✓ |  |  |  |
| PC-114 | Trust password rotation (every 30 days) can desync; manual reset re... | Operations | medium | ✓ | ✓ | ✓ | ✓ |
| PC-115 | `dcdiag` / `repadmin` / `ntdsutil` are Windows-only; cross-platform... | Operations | medium | ✓ | ✓ | ✓ | ✓ |
| PC-116 | Kerberoasting (RC4 TGS brute-force) is the dominant AD attack | Security | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-117 | DCSync (DRSGetNCChanges with EXOP_REPL_SECRETS) extracts all passwo... | Security | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-118 | Golden ticket (forged TGT via krbtgt hash) requires krbtgt rotation... | Security | blocker | ✓ | ✓ | ✓ | ✓ |
| PC-119 | Silver ticket (forged TGS via service-account hash) requires PAC_BU... | Security | high | ✓ | ✓ | ✓ | ✓ |
| PC-120 | SIDHistory abuse allows privilege escalation across migrations | Security | high | ✓ | ✓ | ✓ | ✓ |
| PC-121 | Selective authentication (`Allowed to Authenticate` ACE) is per-res... | Security | medium | ✓ | ✓ | ✓ | ✓ |
| PC-122 | AdminSDHolder + SDPROP (every 60 min) can override intended ACLs | Security | medium | ✓ | ✓ | ✓ | ✓ |
| PC-123 | Supply-chain risk: signed AD updates require WSUS trust | Security | medium | ✓ | ✓ | ✓ | ✓ |
| PC-124 | sidHistory migration requires `DRSAddSidHistory` + SeEnableDelegati... | Migration | high | ✓ | ✓ | ✓ | ✓ |
| PC-125 | GPO translation from AD to framework-native requires manual mapping | Migration | high | ✓ | ✓ | ✓ | ✓ |
| PC-126 | Client switchover from AD to framework requires parallel-run support | Migration | high | ✓ | ✓ | ✓ | ✓ |
| PC-127 | Password hash migration requires either sIDHistory or password-sync... | Migration | high | ✓ | ✓ | ✓ | ✓ |
| PC-128 | DNS namespace sharing during migration requires careful zone delega... | Migration | medium | ✓ | ✓ | ✓ | ✓ |
| PC-129 | Kerberos cross-realm with AD during migration requires `capaths` + ... | Migration | medium | ✓ | ✓ | ✓ | ✓ |
| PC-130 | SYSVOL migration (logon scripts, GPO files) requires SMB share comp... | Migration | medium | ✓ | ✓ | ✓ | ✓ |

## Per-platform breakdown

### Windows-specific problems

These problems are intrinsic to the Windows implementation of AD and have no direct equivalent on macOS or Linux. The framework's Windows implementation must address them; the macOS and Linux implementations may not need to.

- **PC-006** — Schema cache reload blocks LDAP writes for 5–30 seconds (Core Directory). The `schemaUpdateNow` operation in `ntdsa.dll!SCCacheUpdate` reloads the entire `g_SchemaCache` hash table, briefly blocking writes. macOS/Linux equivalents (389-DS, OpenLDAP, OpenDirectory) have different schema-cache implementations.
- **PC-025** — PAC validation RPC requires service-to-DC roundtrip (KDC). The `NetrLogonSamLogonEx` RPC for PAC validation is Windows-specific; Samba implements a partial equivalent.
- **PC-049** — WMI filters are evaluated client-side; WMI repository corruption fails GPOs (Policy Engine). WMI is Windows-only; macOS and Linux use declarative host facts instead.
- **PC-050** — Slow-link detection (ICMP ping to PDC) is unreliable (Policy Engine). The `gpsvc.dll` slow-link detection is Windows-only.
- **PC-107** — Schema upgrades are irreversible; `objectVersion` bump is one-way (Operations). The `adprep /forestprep` action and the `objectVersion` attribute are AD-specific. 389-DS and OpenLDAP have different schema-versioning models.
- **PC-113** — AD functional level upgrades are one-way; mixed-version forests are fragile (Operations). Domain and forest functional levels are AD-specific concepts.

### macOS-specific problems

These problems are intrinsic to macOS's directory integration story and have no direct equivalent on Windows or Linux.

- **PC-086** — macOS PSSO Extension (macOS 13+) replaces Enterprise Connect + NoMAD but is Apple-only (Client SDK). PSSO is Apple-specific; no Windows/Linux equivalent.
- **PC-087** — macOS Jamf Connect + ROPG password sync is fragile during IdP password change (Client SDK). Jamf Connect is a macOS-specific third-party tool.
- **PC-096** — macOS DDM (Declarative Device Management) is the future but not yet full-coverage (Cross-Platform Parity). DDM is Apple's MDM evolution; no Windows/Linux equivalent.
- **PC-100** — macOS OpenDirectory AD plug-in has gaps (GPO, ABE, full DFS-N) (Cross-Platform Parity). OpenDirectory is Apple-specific.
- **PC-104** — Centrify / PBIS / AdmitMac / DAVE are legacy third-party macOS agents (Cross-Platform Parity). These are macOS-specific commercial products.
- **PC-105** — Heimdal Kerberos on macOS is a fork tracking upstream ~2014 (Cross-Platform Parity). Apple's Heimdal fork is macOS-specific.

### Linux-specific problems

These problems are intrinsic to Linux's directory integration story and have no direct equivalent on Windows or macOS.

- **PC-088** — SSSD on Linux has GPO access control + ID mapping but no full GPO CSE support (Client SDK). SSSD is Linux-specific.
- **PC-092** — PAM stack varies by distro (Debian/Ubuntu vs RHEL/Fedora vs SUSE) (Client SDK). PAM is Linux-specific.
- **PC-099** — SSSD/Winbind/PBIS are alternative Linux stacks; migration between them is painful (Cross-Platform Parity). All three are Linux-specific.
- **PC-103** — OpenLDAP + MIT Kerberos (roll-your-own) is high-effort, low-feature (Cross-Platform Parity). This Linux-specific stack has no macOS/Windows equivalent.

### Cross-platform consistency problems

These problems apply to the framework's interop across all three platforms. The framework must produce identical semantics regardless of which platform hosts the DC or client. The full list contains 114 problems; below are the most impactful ones per capability.

- **PC-001, PC-002, PC-003, PC-004, PC-005, PC-007, PC-009, PC-014, PC-019, PC-022** — Core Directory replication and storage model must be wire-compatible and semantically identical across Windows/macOS/Linux DCs.
- **PC-023, PC-024, PC-030, PC-031, PC-035** — KDC, krbtgt rotation, SPN uniqueness, gMSA — all must work identically across platforms.
- **PC-036, PC-037, PC-038, PC-042** — Auth Provider: NTLM, relay mitigations, PtH defense, audit events — all cross-platform.
- **PC-043, PC-045, PC-046, PC-055** — Policy Engine: GPO architecture, Preferences, ADMX, SYSVOL — all cross-platform.
- **PC-057, PC-067** — Cert Service: CA, NTAuthCertificates — cross-platform trust model.
- **PC-068, PC-073** — Federation Gateway: AD FS replacement, WAP — cross-platform.
- **PC-078, PC-079, PC-083** — File Gateway: SMB, SMB1 drop, PrintNightmare — cross-platform.
- **PC-085, PC-089, PC-091, PC-093, PC-095** — Client SDK: unified SDK, ID mapping, domain join, ticket cache, Configuration Profiles vs GPO — all cross-platform.
- **PC-097, PC-098, PC-101, PC-102** — Cross-Platform Parity: FileVault, LAPS, FreeIPA, RODC — all cross-platform.
- **PC-106, PC-109, PC-110, PC-111, PC-112, PC-115** — Operations: Prometheus/OTel, containerization, DR, audit logs, REST API, unified CLI — all cross-platform.
- **PC-116 through PC-123** — Security: all 8 security threats apply cross-platform (the attacker can target any platform's DC).
- **PC-124 through PC-130** — Migration: all 7 migration problems require cross-platform interop (AD on Windows → framework on any platform).

### Partial-coverage (△) problems

These problems affect the framework's cross-platform consistency but do not natively surface on every platform. The framework must still address them for cross-platform consistency.

- **PC-057** (Cert Service, blocker) — Windows has AD CS; Linux has Dogtag; macOS has no native CA. The framework must provide a CA that works on all three.
- **PC-080** (File Gateway, high) — Windows has DFS-N + DFS-R; Linux has Samba's partial DFS-N; macOS has no native DFS client. The framework must provide DFS-equivalent on all three.
- **PC-089** (Client SDK, blocker) — Windows uses SIDs natively; macOS and Linux use POSIX UIDs. The framework must provide consistent ID mapping across all three.
- **PC-090** (Client SDK, medium) — Windows uses its own Kerberos; macOS uses Heimdal; Linux uses MIT krb5. The framework must standardise on one (or provide a unified abstraction).
- **PC-094** (Cross-Platform Parity, high) — Windows has native NTLM; macOS and Linux use Samba winbind for NTLM. The framework must provide consistent NTLM support (or drop it consistently) across all three.

## Severity distribution per platform

| Platform | Blocker | High | Medium | Low |
|----------|---------|------|--------|-----|
| Windows  | 21      | 53   | 36     | 7   |
| macOS    | 21      | 53   | 36     | 8   |
| Linux    | 21      | 53   | 36     | 8   |
| Cross-platform consistency | 21 | 52 | 32 | 9 |

The blocker count is identical across all three platforms because all 21 blocker problems are marked `cross-platform` (they apply uniformly). The high/medium/low counts vary slightly due to platform-specific problems (PC-025 is Windows-only high; PC-086 is macOS-only high; PC-088 is Linux-only high; etc.).

## How to use this matrix

- **Architects**: scan the matrix for rows where one platform is blank or △ and the others are ✓ — these are the parity gaps that need explicit platform-specific design. The partial-coverage (△) problems are the highest-priority parity gaps.
- **Engineers (per-platform leads)**: filter the matrix to your platform's column. Every ✓ in your column is your responsibility.
- **Migration leads**: focus on the Migration rows (PC-124 through PC-130). All are cross-platform; the migration tooling must work on all three client platforms.
- **Security leads**: focus on the Security rows (PC-116 through PC-123). All are cross-platform; the threat model is identical regardless of which platform hosts the DC.

## References

- Source problems: [01-core-directory.md](./01-core-directory.md) through [12-migration-and-coexistence.md](./12-migration-and-coexistence.md).
- Open research questions: [13-open-research-questions.md](./13-open-research-questions.md).
- Capability taxonomy: [00-framework-capabilities.md](./00-framework-capabilities.md).
