---
title: Problem Catalog Synthesis — Distilled View of 130 AD-Equivalence Problems
audience: architects-and-engineers
tags: [rough-draft, synthesis, problem-catalog, framework-design, blockers, stride, parity-gaps]
related:
  - ./README.md
  - ./01-executive-summary.md
  - ./03-problem-catalog-synthesis.md
  - ./04-open-research-questions.md
  - ../catalog/README.md
  - ../catalog/13-open-research-questions.md
last_updated: 2026-08-13
---

# Problem Catalog Synthesis — Distilled View of 130 AD-Equivalence Problems

This section distills the 130-problem catalog ([`catalog/README.md`](../catalog/README.md)) into a readable synthesis for architects. The catalog itself is a 16-file reference covering every protocol gap, cross-platform inconsistency, scalability bottleneck, security threat, operational footgun, and greenfield design tension that surfaces when building a framework equivalent to Active Directory across Windows, macOS, and Linux. This synthesis does not restate the catalog — it prioritises it. Where the catalog lists every problem with equal weight, this synthesis calls out the 23 blockers, the 8 security threats, the 12 cross-platform parity gaps, and the 10 cross-cutting tensions that an architect must resolve before any line of framework code is written.

## 1. Catalog at a glance

The catalog inventory is **130 problems across 12 framework capabilities**. By severity: **23 blocker** (framework cannot ship without solving), **64 high** (significant gap or security risk), **33 medium** (workaround exists but gap should be acknowledged), **10 low** (nuisance or future-compatibility item). The blocker / high / medium / low mix is roughly 18% / 49% / 25% / 8% — a heavy distribution toward "must solve" and "should solve," reflecting that AD-equivalence is a high bar. The catalog is not exhaustive of nice-to-haves; it is exhaustive of must-haves.

By platform impact (using the parity matrix's stricter interpretation in [`catalog/14-cross-platform-parity-matrix.md`](../catalog/14-cross-platform-parity-matrix.md)): **Windows 117 / macOS 118 / Linux 118 / cross-platform consistency 114**. The near-uniform distribution is the headline finding — almost every problem touches every platform, because the framework's value proposition is itself cross-platform parity. The handful of platform-specific problems (6 Windows-only, 6 macOS-only, 4 Linux-only) are the long tail; the 21 blockers are all uniformly cross-platform. The framework cannot ship a Windows-only tier and call itself AD-equivalent.

The catalog was mined from the 72-file AD knowledge base. Every problem carries KB citations, impact statements, constraints, and open questions. The open questions are consolidated separately in [`catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md) — 262 of them — and synthesised in the companion file [`./04-open-research-questions.md`](./04-open-research-questions.md).

## 2. The 12 framework capabilities

The framework is decomposed into 12 capabilities, each with a clear responsibility, public interface, and dependency graph ([`catalog/00-framework-capabilities.md`](../catalog/00-framework-capabilities.md)). The decomposition mirrors AD where it makes sense (Core Directory ↔ AD DS; KDC ↔ `kdcsvc.dll`; Cert Service ↔ AD CS; Federation Gateway ↔ AD FS; File Gateway ↔ lanmanserver + DFS + RMS) and splits cross-cutting concerns that AD conflates (Auth Provider split from KDC; Policy Engine split from GPO; Operations, Security, Cross-Platform Parity, Migration as first-class concerns).

| # | Capability | Problems | Blockers | Top problem |
|---|------------|----------|----------|-------------|
| 1 | Core Directory Service | 22 | 4 | PC-001 — DRSUAPI replication must be implemented server-side |
| 2 | KDC (Kerberos Key Distribution Center) | 13 | 3 | PC-023 — MS-KILE profile with PAC generation/signing |
| 3 | Auth Provider (NTLM, SASL, SSPI-equivalent) | 7 | 2 | PC-038 — Pass-the-hash defense |
| 4 | Policy Engine (GPO-equivalent) | 14 | 2 | PC-055 — SYSVOL replication via DFS-R is Windows-only |
| 5 | Cert Service (PKI / CA / Enrollment) | 11 | 1 | PC-057 — AD CS is Windows-only, no open-source MS-WCCE |
| 6 | Federation Gateway (SAML / OIDC / WS-Fed) | 10 | 0 | PC-068 — AD FS is heavy and Windows-bound |
| 7 | File Gateway (SMB / DFS / Print) | 7 | 3 | PC-078 — SMB 3.1.1 with pre-auth integrity + AES-GCM |
| 8 | Client SDK (cross-platform library) | 9 | 2 | PC-085 — No universal AD client SDK exists today |
| 9 | Cross-Platform Parity | 12 | 1 | PC-095 — No unified policy authoring across Win/macOS/Linux |
| 10 | Operations (deploy / monitor / recover) | 10 | 0 | PC-109 — No containerization, no Kubernetes-native deploy |
| 11 | Security & Threat Model | 8 | 3 | PC-116/117/118 — Kerberoasting, DCSync, golden ticket |
| 12 | Migration & Coexistence | 7 | 0 | PC-127 — Password hash migration |

**Core Directory (22 problems, 4 blockers)** is the foundation; every other capability consumes its APIs. The four blockers — DRSUAPI replication ([PC-001](../catalog/01-core-directory.md)), USN/InvocationID/UTD-vector model ([PC-002](../catalog/01-core-directory.md)), `member`/`memberOf` back-link with linkID pairing ([PC-004](../catalog/01-core-directory.md)), and ESE/JET Blue storage engine replacement ([PC-007](../catalog/01-core-directory.md)) — collectively decide whether the framework is wire-compatible with AD or clean-slate. These decisions cascade into every other capability.

**KDC (13 problems, 3 blockers)** is the second-most-critical capability. The MS-KILE profile ([PC-023](../catalog/02-kdc.md)) requires PAC generation, FAST, PKINIT, kpasswd, and cross-realm referral; the only open-source server that emits MS-PAC is Samba's Heimdal fork (GPLv3). The RC4-HMAC default ([PC-024](../catalog/02-kdc.md)) is the Kerberoasting liability. The krbtgt rotation problem ([PC-030](../catalog/02-kdc.md)) is the golden-ticket mitigation. All three are blockers because every downstream service assumes a PAC-bearing TGT.

**Auth Provider (7 problems, 2 blockers)** handles NTLM, SASL, smart-card, SSPI-equivalent. The blockers — NTLM relay ([PC-037](../catalog/03-auth-provider.md)) and pass-the-hash defense ([PC-038](../catalog/03-auth-provider.md)) — are security-blockers: the framework cannot ship if it inherits AD's known NTLM vulnerabilities without mitigation.

**Policy Engine (14 problems, 2 blockers)** replaces GPO. The blockers — GPO Preferences ([PC-045](../catalog/04-policy-engine.md)) and SYSVOL replication via DFS-R ([PC-055](../catalog/04-policy-engine.md)) — are the two places where AD's policy model cannot be replaced by a thin shim. Preferences are Windows-only XML files with no macOS/Linux equivalent; DFS-R has no open-source implementation.

**Cert Service (11 problems, 1 blocker)** replaces AD CS. The blocker — AD CS is Windows-only and no open-source MS-WCCE server exists ([PC-057](../catalog/05-cert-service.md)) — forces a choice between implementing MS-WCCE for interop or adopting ACME/EST with a Windows-side adapter.

**Federation Gateway (10 problems, 0 blockers)** replaces AD FS. No single problem is a blocker because the modern IdP ecosystem (Keycloak, Authentik, Zitadel) already covers most of what AD FS does; the work is choosing and wrapping one. Top problem ([PC-068](../catalog/06-federation-gateway.md)) is operational weight, not feature gap.

**File Gateway (7 problems, 3 blockers)** covers SMB, DFS, print, offline files. Three blockers — SMB 3.1.1 with pre-auth integrity and AES-GCM ([PC-078](../catalog/07-file-gateway.md)), SMB1 must be dropped ([PC-079](../catalog/07-file-gateway.md)), and PrintNightmare ([PC-083](../catalog/07-file-gateway.md)) — are concentrated here because SMB is the protocol with the most dangerous legacy surface.

**Client SDK (9 problems, 2 blockers)** is the cross-platform library. The blockers — no universal SDK exists today ([PC-085](../catalog/08-client-sdk.md)) and ID mapping between SIDs and POSIX UIDs/GIDs is non-deterministic across hosts ([PC-089](../catalog/08-client-sdk.md)) — are both greenfield design decisions.

**Cross-Platform Parity (12 problems, 1 blocker)** tracks platform-specific gaps. The blocker — no unified policy authoring across Windows GPO, macOS Configuration Profiles, Linux SSSD-conf ([PC-095](../catalog/09-cross-platform-parity.md)) — is the meta-problem that the framework exists to solve.

**Operations (10 problems, 0 blockers)** covers deployment, monitoring, backup, recovery, upgrade. No single problem is a blocker because each has an operational workaround; collectively they define the framework's operability gap versus cloud-native systems. Top problem ([PC-109](../catalog/10-operations.md)) — no containerization, no Kubernetes-native deployment — is the most visible.

**Security & Threat Model (8 problems, 3 blockers)** is the explicit threat surface. All three blockers — Kerberoasting ([PC-116](../catalog/11-security-threat-model.md)), DCSync ([PC-117](../catalog/11-security-threat-model.md)), and golden ticket ([PC-118](../catalog/11-security-threat-model.md)) — are attacks the framework must mitigate by default, not opt-in.

**Migration & Coexistence (7 problems, 0 blockers)** is the path from AD to the framework. No single problem is a blocker because the framework can ship without automated migration tooling, but the 7 problems collectively determine whether adoption is feasible. Password hash migration ([PC-127](../catalog/12-migration-and-coexistence.md)) is the most consequential.

## 3. The 23 blocker problems

The 23 blockers define the minimum viable framework. The parity matrix shows 21 uniquely-tagged blocker rows in [`catalog/14-cross-platform-parity-matrix.md`](../catalog/14-cross-platform-parity-matrix.md); the catalog README's headline count of 23 reflects two additional items flagged as blocker-class in per-capability detail entries. Grouped by capability:

**Core Directory (4 blockers)**
- **PC-001** — DRSUAPI replication protocol must be implemented server-side for AD-interop scenarios. The framework's DC must speak MS-DRSR on the wire or accept that AD-interop is lost.
- **PC-002** — USN/InvocationID/UTD-vector replication model is unique to AD; alternatives (CRDT, Raft, OT) must preserve rollback and lingering-object semantics.
- **PC-004** — `member`/`memberOf` back-link requires linkID pairing and DSA-computed construction; without it, group membership queries break.
- **PC-007** — ESE/JET Blue database is Windows-only; the framework must pick a new storage engine (RocksDB, FoundationDB, SQLite, custom) and justify the choice.

**KDC (3 blockers)**
- **PC-023** — KDC must implement MS-KILE profile of RFC 4120 with PAC generation, FAST, PKINIT, kpasswd, cross-realm referral. Samba Heimdal (GPLv3) is the only open-source server that emits MS-PAC.
- **PC-024** — RC4-HMAC default for backwards compat is a Kerberoasting liability. The framework must default to AES and force-migrate service accounts.
- **PC-030** — `krbtgt` account compromise equals golden ticket; rotation is operationally painful and must be HSM-bound and automated.

**Auth Provider (2 blockers)**
- **PC-037** — NTLM relay attacks require LDAP signing + channel binding + EPA enforcement on by default; AD has these opt-in via GPO and most orgs don't enable them.
- **PC-038** — Pass-the-hash defense requires LSASS protection / Credential Guard equivalent; the framework must not store reusable NT hashes in client process memory.

**Policy Engine (2 blockers)**
- **PC-045** — GPO Preferences (XML files) have no macOS/Linux equivalent. Drive mappings, registry changes, file copies, scheduled tasks, local users — all Windows-only.
- **PC-055** — SYSVOL replication via DFS-R is Windows-only; FRS is removed. The framework must provide an equivalent or use a different distribution channel (e.g. Git-backed).

**Cert Service (1 blocker)**
- **PC-057** — AD CS (`certsvc.exe` + ESE CA DB) is Windows-only; no open-source MS-WCCE server exists. Framework must either implement MS-WCCE, wrap Dogtag/Step-CA, or adopt ACME and ship a Windows-side adapter.

**File Gateway (3 blockers)**
- **PC-078** — SMB 3.1.1 with pre-auth integrity + AES-GCM is required for modern Windows interop. Samba implements this; a fresh implementation is high-risk.
- **PC-079** — SMB1 must be dropped (security liability); migration is automatic on modern Windows but legacy NAS appliances may break.
- **PC-083** — PrintNightmare (CVE-2021-34527) exposed MS-RPRN driver install as SYSTEM. The framework must either drop MS-RPRN entirely or implement driverless IPP Everywhere.

**Client SDK (2 blockers)**
- **PC-085** — No universal AD client SDK exists today; Windows uses SSPI+Wldap32, macOS uses OpenDirectory, Linux uses SSSD/Winbind/PAM/NSS. The framework must provide one or document explicit per-platform stacks.
- **PC-089** — ID mapping (SID ↔ POSIX UID/GID) is non-deterministic across hosts without coordination. SSSD's slice algorithm, FreeIPA's range, and AD's RFC2307 are three competing approaches.

**Cross-Platform Parity (1 blocker)**
- **PC-095** — macOS Configuration Profiles vs Windows GPO vs Linux SSSD-conf have no unified authoring. The framework must either pick one format and translate, or define a new DSL that compiles to all three.

**Security & Threat Model (3 blockers)**
- **PC-116** — Kerberoasting (RC4 TGS brute-force) is the dominant AD attack. Mitigation: disable RC4, force AES, alert on etype 0x17 in TGS-REQ events.
- **PC-117** — DCSync (`DRSGetNCChanges` with `EXOP_REPL_SECRETS`) extracts all password hashes. Mitigation: audit `DS-Replication-Get-Changes-All` privilege, break-glass via HSM-bound key.
- **PC-118** — Golden ticket (forged TGT via krbtgt hash) requires krbtgt rotation to invalidate. Mitigation: HSM-bound krbtgt key, automatic rotation, ticket-validation default.

The 23-blocker list spans 9 of 12 capabilities. Federation Gateway, Operations, and Migration have no individual blockers — but each has high-severity problems that gate v1 ship. Solving the 23 blockers is the minimum viable framework; solving the 64 high-severity problems is v1.

## 4. The 8 security threats with STRIDE classification

The catalog dedicates a full capability to security ([`catalog/11-security-threat-model.md`](../catalog/11-security-threat-model.md)) because AD's threat model is implicit and scattered across registry keys, GPOs, and KB articles. The framework must make mitigations explicit and on-by-default. The 8 threats are PC-116 through PC-123:

**PC-116 — Kerberoasting** (STRIDE: Information disclosure, Elevation of privilege). Any authenticated domain user can request a TGS for any SPN-bearing account, then offline brute-force the encrypted ticket. RC4-HMAC tickets fall in seconds to minutes on modern GPUs; AES tickets are computationally infeasible. The known AD mitigation is "disable RC4, require AES" — but this requires migrating every service account's `msDS-SupportedEncryptionTypes` and is rarely completed. The framework must default to AES-only and emit 4769-equivalent events flagged when etype 0x17 appears.

**PC-117 — DCSync** (STRIDE: Information disclosure, Elevation of privilege). Any principal with `DS-Replication-Get-Changes-All` on the domain NC head can call `DRSGetNCChanges` with `EXOP_REPL_SECRETS` and pull every password hash. Domain Admins, Enterprise Admins, and DC machine accounts hold this by default. The known AD mitigation is the audit on 4662 events with the replication GUID; the framework must make this a per-principal audit and require HSM-bound break-glass for full-sync operations.

**PC-118 — Golden ticket** (STRIDE: Spoofing, Elevation of privilege). An attacker who obtains the `krbtgt` account's NT hash can forge arbitrary TGTs with arbitrary PAC contents, persisting even after user password resets. The only AD mitigation is krbtgt rotation (which invalidates all existing TGTs), performed manually and rarely. The framework must HSM-bind the krbtgt key, rotate it automatically (e.g. every 30 days with a 2-version overlap), and accept the operational pain of frequent rotation as a security feature.

**PC-119 — Silver ticket** (STRIDE: Spoofing, Elevation of privilege). An attacker who obtains a service account's hash can forge TGS tickets directly, bypassing the KDC. Server 2016 introduced `PAC_BUFFER_TICKET_CHECKSUM` (signed by the krbtgt key over the whole ticket) which mitigates this — but services must opt in. The framework must default-validate the checksum on every TGS acceptance. High severity because the mitigation is well-understood but rarely deployed.

**PC-120 — SIDHistory abuse** (STRIDE: Elevation of privilege, Spoofing). `sIDHistory` lets a migrated user carry their old SID, enabling cross-domain resource access. An attacker who can inject SIDs into `sIDHistory` (via `DRSAddSidHistory` or direct LDAP modify) gains any group membership. The known AD mitigation is SIDHistory filtering on external trusts; within-forest trusts have it OFF by default. The framework must default to filtering on all trusts and audit `sIDHistory` writes.

**PC-121 — Selective authentication** (STRIDE: Elevation of privilege). The `Allowed to Authenticate` ACE on a resource controls which cross-domain users can access it — but it's per-resource and rarely used. The framework should provide FreeIPA HBAC-style server-side evaluation as the cross-platform equivalent. Medium severity.

**PC-122 — AdminSDHolder + SDPROP** (STRIDE: Tampering, Elevation of privilege). Every 60 minutes, the SDPROP process resets the ACL on protected groups (Domain Admins, Enterprise Admins, etc.) to match the AdminSDHolder container's ACL. This can override intended delegated permissions and is a known operational surprise. The framework should replace AdminSDHolder with declarative RBAC templates. Medium severity.

**PC-123 — Supply-chain risk** (STRIDE: Tampering, Elevation of privilege). AD updates ship via WSUS, which trusts the WSUS server's signing key. A compromised WSUS server can push arbitrary code to every DC. The framework should adopt Sigstore (cosign) and in-toto attestations for framework binaries, independent of the distribution channel. Medium severity.

The 8 threats map cleanly to STRIDE; the most damaging (PC-116, 117, 118) are dual-category (information disclosure + elevation, or spoofing + elevation). The framework must mitigate all 8 by default, not opt-in, and the mitigations must be audit-logged. See [`catalog/11-security-threat-model.md`](../catalog/11-security-threat-model.md) for the per-threat mitigation matrix.

## 5. The 12 cross-platform parity gaps

PC-094 through PC-105 are the cross-platform parity problems catalogued in [`catalog/09-cross-platform-parity.md`](../catalog/09-cross-platform-parity.md). These are the gaps that surface because AD is Windows-only and the framework targets three platforms.

**PC-094 — macOS has no native NTLM support.** macOS SMBX client (macOS 10.14+) dropped NTLMSSP; only Samba or third-party agents (Delinea/Centrify) provide it. ~5–10% of enterprise macOS users have at least one NTLM-requiring app. Framework must provide NTLM via Samba winbind or document legacy apps as out of scope.

**PC-095 — No unified policy authoring across Windows GPO, macOS Configuration Profiles, Linux SSSD-conf.** Three formats, three parsers, three enforcement models. The framework must either pick one format and translate (lossy) or define a new DSL that compiles to all three. This is a blocker (see section 3).

**PC-096 — macOS DDM (Declarative Device Management) is the future but not yet full-coverage.** Apple's DDM replaces imperative MDM commands with declarative state; coverage is partial in macOS 14/15. The framework should adopt DDM-first authoring with auto-fallback to Configuration Profile for unported payloads.

**PC-097 — macOS FileVault recovery key escrow goes to Apple or MDM, not AD.** The framework must either store per-computer recovery keys in the framework directory (with ACL-gated read) or adopt NBDE (Clevis/Tang) for all platforms.

**PC-098 — LAPS (local admin password rotation) has no macOS/Linux native equivalent.** Microsoft LAPS is Windows-only (now built into Windows 11 24H2). The framework must provide per-host local-admin password rotation in the directory with ACL-gated read, or adopt the Windows LAPS schema for compat.

**PC-099 — SSSD/Winbind/PBIS are alternative Linux stacks; migration between them is painful.** Three competing Linux identity stacks with overlapping but inconsistent features. The framework should hard-deprecate Winbind for NSS/PAM (keep for SMB only) and provide migration tooling from PBIS to SSSD.

**PC-100 — macOS OpenDirectory AD plug-in has gaps (GPO, ABE, full DFS-N).** Apple's OpenDirectory AD plug-in handles auth but not policy, access-based enumeration, or full DFS-N referral. The framework must provide a first-party macOS client SDK that fills these gaps, or document third-party tools as required.

**PC-101 — FreeIPA is a separate Linux identity platform with AD cross-forest trust.** FreeIPA is feature-rich but architecturally separate from the framework. The framework must decide: adopt FreeIPA as the Linux tier, or build a native IPA-equivalent. This is a Tier-1 architectural decision (see [`./04-open-research-questions.md`](./04-open-research-questions.md)).

**PC-102 — RODC (Read-Only DC) has no Linux/macOS equivalent.** RODC is for branch offices with physical insecurity. The framework must provide a Kubernetes-style read-replica with no secrets, or an edge-deployed DC with HSM-bound subset, or document RODC as out of scope.

**PC-103 — OpenLDAP + MIT Kerberos (roll-your-own) is high-effort, low-feature.** The classic Linux identity stack is duct-taped together from OpenLDAP, MIT krb5, and a PAM/NSS shim. The framework should provide migration tooling to FreeIPA or document this as deprecated.

**PC-104 — Centrify / PBIS / AdmitMac / DAVE are legacy third-party macOS agents.** These commercial products fill the macOS AD-integration gap but are end-of-life or acquiring. The framework must document migration paths from each to its first-party macOS client.

**PC-105 — Heimdal Kerberos on macOS is a fork tracking upstream ~2014.** Apple's Heimdal fork is a decade behind upstream, missing modern etypes and FAST hardening. The framework should contribute the fork upstream or document PSSO (Platform SSO) as the only modern macOS path.

The 12 parity gaps cluster around three themes: (a) macOS lacks first-party equivalents for NTLM, policy, FileVault, LAPS, and OpenDirectory AD plug-in (PC-094, 095, 097, 098, 100); (b) Linux has three competing stacks with no clear winner (PC-099, 101, 103); (c) cross-platform RODC and Heimdal fork rot are framework-wide gaps (PC-102, 105). The macOS gap is the most acute — Apple has been coasting on a 2014 Heimdal fork and third-party agents for a decade.

## 6. Top 5 most-cited KB files in the catalog

The catalog was mined from a 72-file KB. Five KB files contributed the most problems:

1. **`docs/02-protocols/01-kerberos-internals.md`** — Kerberos protocol internals (AS-REQ/AS-REP, TGS-REQ/TGS-REP, PAC structure, etypes, FAST, PKINIT, cross-realm). Cited by every KDC problem (PC-023 through PC-035), every Security Kerberos-related problem (PC-116, 118, 119), and several Auth Provider problems. Single most-cited KB file. The Kerberos PAC is the foundation of AD's authorization model; getting it wrong breaks every downstream service.

2. **`docs/01-ad-core/01-ad-ds-internals.md`** — AD DS internals (`ntdsa.dll`, ESE database, DRSUAPI replication, USN/UTD vector, schema cache, sdtable, GC). Cited by every Core Directory blocker (PC-001, 002, 004, 007) and most high-severity Core Directory problems. The ESE storage engine and DRSUAPI replication are the two most consequential AD-specific implementation choices.

3. **`docs/01-ad-core/03-replication-internals.md`** — Replication internals (DRSUAPI opnums, `DRSGetNCChanges`, `PROPERTY_META_DATA_EXT`, lingering objects, tombstones, KCC topology). Cited by PC-001, PC-002, PC-009, PC-014, PC-016, PC-019, and the DCSync security problem (PC-117). Replication is where AD-interop and clean-slate tensions are sharpest.

4. **`docs/02-protocols/08-spn-upn-pac.md`** — SPN/UPN/PAC (service principal names, user principal names, PAC buffer types, `PAC_LOGON_INFO`, `PAC_BUFFER_TICKET_CHECKSUM`, NTAuthCertificates). Cited by PC-023, PC-027, PC-031, PC-032, PC-067, PC-116, PC-118, PC-119. The PAC is the cross-cutting data structure that ties KDC, Auth Provider, Cert Service, and Security together.

5. **`docs/02-protocols/06-rpc-dcerpc-ms-drsr.md`** — DCE-RPC and DRSR (MS-DRSR protocol, opnums, DRSUAPI interface UUID, `EXOP_REPL_SECRETS`, `DRSAddSidHistory`). Cited by PC-001, PC-002, PC-117, PC-124. DRSR is the wire protocol the framework must either implement or replace; every AD-interop decision goes through this file.

These five KB files account for roughly 60% of all catalog citations. They define the protocol surface where the framework's hardest decisions live: replication, Kerberos PAC, storage, and the DRSR wire format. An architect who reads only these five KB files will understand 60% of the catalog's blocker problems.

## 7. Cross-cutting design tensions

The catalog README identifies 10 cross-cutting tensions that appear across multiple capabilities and must be resolved at the architecture level. Each tension is a binary-or-ternary choice that cascades into multiple capabilities.

**AD-interop vs. clean-slate.** Every protocol-level decision trades interop with existing AD deployments against the freedom to design something better. The framework must pick a lane per protocol: full compat (speak MS-DRSR), compat-with-shim (speak MS-DRSR + extension), or clean-slate (speak Raft/OT). If DRSUAPI is implemented for interop, the UTD vector model is forced; if a clean-slate CRDT model is chosen, AD-interop is lost. Spans PC-001, PC-002, PC-007, PC-017, PC-023, PC-036, PC-057, PC-068, PC-078, PC-094, PC-099, PC-103, PC-124. No global answer; each protocol must be decided individually.

**Multi-master vs. consensus (Raft).** AD is multi-master with last-writer-wins; modern systems prefer Raft/Paxos for strong consistency. The framework must decide per-NC: stay multi-master (compat) or move to consensus (correctness). If consensus, what is the failure mode when a quorum member is unavailable? Spans PC-002, PC-009, PC-014, PC-016, PC-022, PC-043, PC-074, PC-108. Raft simplifies correctness but breaks AD-interop; multi-master preserves interop but inherits LWW.

**LDAP schema vs. typed schema.** AD's schema is dynamic, attribute-based, LDAP-defined. Modern systems prefer typed schemas (protobuf, SQL DDL, JSON Schema). The choice cascades into the directory API, the replication protocol, and the client SDK. Spans PC-017, PC-021, PC-046, PC-058, PC-107, PC-113. Hybrid (LDAP schema + typed projection) is possible but adds an adapter layer.

**SIDs vs. UUIDs.** AD uses SIDs for security principals; modern systems prefer UUIDs. The framework must decide: SIDs (interop), UUIDs (modern), or both with mapping. `sIDHistory` migration (PC-124) is the immediate pressure point. Spans PC-015, PC-026, PC-089, PC-124, PC-127. "Both with mapping" is operationally expensive; "SIDs only" forecloses future modernisation; "UUIDs only" breaks AD-interop.

**GPO format vs. declarative policy.** AD's GPO is INI/registry.pol-based, fragile, no rollback. Modern alternatives (Salt, Ansible, Kubernetes operators) are declarative, versioned, transactional. Spans PC-043 through PC-056, PC-095, PC-125, PC-130. Hybrid (declarative source-of-truth that compiles to GPO for Windows interop) is most promising but requires a non-trivial ADMX-to-declarative translator.

**NTLM: drop or maintain compat.** NTLM is broken (pass-the-hash, relay) but legacy apps require it. The framework must decide: drop entirely (secure), maintain (compat), or maintain with hard mitigations (channel binding, EPA, signing). Spans PC-036, PC-037, PC-038, PC-039, PC-094. "Drop" eliminates an attack class but breaks ~5–10% of legacy apps; "maintain with mitigations" preserves compat at the cost of complexity.

**AD CS protocols vs. ACME/EST.** AD CS uses MS-WCCE/MS-XCEP for enrollment; modern PKI uses ACME (RFC 8555) or EST (RFC 7030). Spans PC-057 through PC-067, PC-123. ACME is simpler and modern but requires a Windows-side adapter for legacy clients.

**AD FS topology vs. modern IdP.** AD FS is a separate farm with SQL/WID, WAP reverse proxy, MS-ADFSPIP. Modern IdPs (Keycloak, Authentik, Ory, Zitadel) are lighter and cloud-native. Spans PC-068 through PC-077. Wrap-modern-IdP is obvious for new deployments; re-implement is required only for orgs needing AD FS wire-compat.

**Multi-tenancy: native vs. per-instance.** AD has no native multi-tenancy; cloud-native systems expect it. The framework must decide: support multi-tenancy natively (modern) or document why not (interop). Spans PC-022, PC-067, PC-076, PC-101, PC-102. Native adds complexity; per-instance is simpler but doesn't match cloud-native expectations.

**Client SDK: per-platform or unified.** No universal AD client SDK exists today. The framework must decide: provide a unified C/Rust/Go SDK with platform bindings, or wrap existing per-platform libraries (SSSD, OpenDirectory, Wldap32). Spans PC-085 through PC-093, PC-094 through PC-105. Unified is more work but produces consistent developer experience; per-platform is faster but inherits each platform's quirks.

These 10 tensions are not independent. The AD-interop vs. clean-slate choice is the meta-tension; every other tension is a specialisation. An architect who picks "AD-interop" as the global answer resolves most tensions toward the compat end; an architect who picks "clean-slate" resolves them toward the modern end. The realistic answer is mixed: AD-interop for wire protocols (Kerberos, SMB, LDAP), clean-slate for internal mechanics (storage engine, consensus, schema). The 11 Tier-1 architectural questions in [`./04-open-research-questions.md`](./04-open-research-questions.md) are the per-protocol instantiations of these tensions.

## 8. Migration & coexistence considerations

PC-124 through PC-130 (catalogued in [`catalog/12-migration-and-coexistence.md`](../catalog/12-migration-and-coexistence.md)) cover the path from AD to the framework. No individual migration problem is a blocker — the framework can ship without automated migration tooling — but the 7 problems collectively determine whether adoption is feasible. A framework that nobody can migrate to is a research project, not a product.

The migration story has four hard problems and three operational ones. **sidHistory migration (PC-124)** is the first hard problem: ADMT uses `DRSAddSidHistory` (DRSUAPI opnum 20) to inject source-domain SIDs into the target user's `sIDHistory`, preserving ACL continuity across the migration. The framework must either implement this opnum on its DRSUAPI surface, provide an alternative migration tool that writes `sIDHistory` via LDAP modify (operationally equivalent, requires the same `SeEnableDelegationPrivilege`), or document claims-based migration as the only path (which limits interop with pre-2012 functional-level forests). **Password hash migration (PC-127)** is the second hard problem: the framework must either accept `sIDHistory` + ADMT password copy (which requires DCSync-equivalent access to the source domain), deploy a password-sync agent (proprietary or standard protocol — see ORQ-255/256), or require password reset at next login (operationally painful). **GPO translation (PC-125)** is the third: ADMX/ADML/Registry.pol/GptTmpl.inf/Preferences XML must be translated to the framework's native policy format, and most settings will not have a clean 1:1 mapping. **Kerberos cross-realm (PC-129)** is the fourth: during coexistence, users in the framework realm must access resources in the AD realm and vice versa, requiring `trustedDomain` objects in both directions plus `[capaths]` configuration on every client.

The three operational problems are: **DNS namespace sharing (PC-128)** — the framework and AD must coexist in the same DNS namespace during migration, requiring careful zone delegation and SRV-record scoping; **client switchover (PC-126)** — clients must be able to switch from AD to the framework (and back, if rollback is needed), requiring parallel-run support with cross-realm Kerberos trust and LDAP referrals; **SYSVOL migration (PC-130)** — logon scripts and GPO files in SYSVOL must move to the framework's policy distribution channel (SMB share compat or HTTP-based distribution).

The realistic migration timeline is 30–180 days for coexistence, with cutover triggered when 100% of source-domain ACLs have been rewritten (or source resources decommissioned). The framework must support this entire window with parallel-run mode, audit-grade visibility into migration progress, and a documented rollback path. See [`catalog/12-migration-and-coexistence.md`](../catalog/12-migration-and-coexistence.md) for per-problem source-state, target-state, and coexistence-window detail.

## Synthesis

The 130-problem catalog resolves to a small number of architectural decisions. The 23 blockers are concentrated in Core Directory (4), KDC (3), Auth Provider (2), Policy Engine (2), File Gateway (3), Client SDK (2), Security (3), plus one each in Cert Service and Cross-Platform Parity. Federation Gateway, Operations, and Migration have no individual blockers but define the framework's operability and adoption story. The 8 security threats must all be mitigated by default; the 12 parity gaps must all be closed for the framework to claim cross-platform equivalence. The 10 cross-cutting tensions resolve, in practice, to one meta-decision (AD-interop vs. clean-slate) plus 11 per-protocol instantiations that are the Tier-1 architectural questions synthesised in [`./04-open-research-questions.md`](./04-open-research-questions.md).
