---
title: Framework Design Roadmap
audience: architects-and-engineers
tags: [rough-draft, synthesis, roadmap, phased-delivery, mvp, research-spikes, risks, success-criteria]
related:
  - ./README.md
  - ./01-executive-summary.md
  - ./05-cross-platform-parity.md
  - ./06-roadmap.md
  - ../catalog/README.md
  - ../catalog/14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Framework Design Roadmap

## Roadmap philosophy

The framework is large: 130 cataloged problems ([`catalog/README.md`](../catalog/README.md)), 262 open research questions ([`catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md)), 12 framework capabilities, 3 target platforms. A naive "design everything then build everything" sequence would take a decade and produce nothing usable. We sequence instead by *decision leverage* and *deliverable value*. Architectural decisions (Tier-1 ORQs) are made first because they cascade across every capability — getting replication wrong in week 4 means rewriting Core Directory, KDC, Operations, and Migration in year 2. The MVP ships the smallest subset that demonstrates end-to-end value: a Linux host can join the framework as a member, authenticate via Kerberos, apply policy, request a cert, and mount an SMB share. Everything beyond the MVP is a horizontal expansion (more capabilities at production quality) and a vertical expansion (deeper features per capability).

The severity tiers from the catalog drive phase scoping. **23 blocker-class problems** (architecture-spanning, MVP-blocking) are the MVP's scope. **64 high-severity problems** are v1's scope — production-hardening, security mitigations, full cross-platform parity, operational tooling. **33 medium-severity problems** are v2's scope — migration tooling, advanced features, scale-out topologies. **10 low-severity problems** are v3's scope — legacy compat, polish, documentation. Total: 23 + 64 + 33 + 10 = 130 ✓. The phases are sequential, but cross-cutting workstreams (security review, interop testing, documentation, performance) run continuously across all phases. Acknowledged uncertainty: research spike outcomes may shift Phase 2+ scope — if the DRSUAPI spike (Phase 0) concludes "adopt Samba's DRSUAPI code as-is," Phase 2 MVP shrinks by 2-3 months; if it concludes "fresh implementation," Phase 2 grows by 3-6 months.

## Phase 0: Research spikes (4-8 weeks)

Seven research spikes, run in parallel where independent, sequential where dependent. Each spike answers one Tier-1 ORQ cluster and produces a decision document. Spike duration is 1-2 weeks of focused engineering effort per spike; parallelism compresses total Phase 0 to 4-8 weeks. See [`catalog/13-open-research-questions.md`](../catalog/13-open-research-questions.md) §"Tier 1 (must answer before design begins)" for the full Tier-1 ORQ list.

**Spike 1: Replication protocol choice (ORQ-001/002/003/004).** Objective: decide between (a) adopting Samba's DRSUAPI code as-is (GPL, mature, AD-wire-compatible), (b) writing a fresh DRSUAPI implementation (clean IP, full control, multi-month effort), or (c) replacing DRSUAPI with a CRDT/Raft-based replication that speaks DRSUAPI on the wire for AD interop. Duration: 2 weeks. Deliverable: a 30-page decision document covering legal (GPL compatibility), engineering (Samba's `source4/rpc_server/drsuapi/getncchanges.c` reuse vs fresh implementation), wire compatibility (USN/InvocationID/UTD-vector vs Raft log), and migration impact (mixed-mode interop with Windows Server 2022/2025 DCs). This spike answers the most consequential Tier-1 ORQ; its outcome determines whether Phase 2 MVP starts in month 3 (Samba reuse) or month 6 (fresh implementation).

**Spike 2: Storage engine choice (ORQ-011/012/013/014).** Objective: decide between ESE-equivalent (custom JET Blue reimplementation), SQLite (mature, embedded, single-file), FoundationDB (distributed, multi-region, Apple-scale), or a custom storage engine. Duration: 2 weeks. Deliverable: benchmark results (1M-object directory, write throughput, replication latency), operational analysis (backup/restore, schema migration, multi-region), and a recommendation with cost/complexity trade-offs. Dependency: depends on Spike 1's outcome (Samba's DRSUAPI requires a specific storage interface). This spike cascades to Core Directory (PC-007), Operations (PC-106 observability, PC-110 DR), and Migration (PC-127 password hash migration).

**Spike 3: Identity model — SID vs UUID (ORQ-026/027) + schema model — LDAP vs typed (ORQ-030/031).** Combined spike because the two decisions are tightly coupled. Objective: decide whether to keep SIDs (AD-compatible) or migrate to UUIDs (clean slate), and whether to keep LDAP schema (RFC 4512, OID-typed) or move to a typed schema (Protobuf/SQL-style). Duration: 1 week. Deliverable: a decision document covering AD interop (SIDs required for migration sIDHistory — PC-124), ACL evaluation (SIDs in `nTSecurityDescriptor` are intrinsic — PC-013), Client SDK impact (PC-085 wraps SID or UUID), and operational tooling (`dcdiag`-equivalent CLI). Recommendation pending spike: keep SIDs for AD interop, use UUIDs internally with a SID↔UUID bidirectional map (PC-015).

**Spike 4: KDC implementation choice (ORQ-042/043/044).** Objective: decide between Samba's Heimdal fork (GPL, MS-KILE-compatible, mature), MIT krb5 + custom PAC plugin (FreeIPA approach — `ipa_kdb` plugin reads principals from 389-DS), or a fresh KDC implementation. Duration: 2 weeks. Deliverable: PKINIT interop matrix (against Windows Server 2022 AD), FAST armoring behavior test, PAC_FULL_CHECKSUM support test, MS-KILE conformance test results. Recommendation pending spike: Samba's Heimdal fork for v1 (fastest path to MS-KILE compat), evaluate fresh implementation for v3 if Heimdal fork maintenance burden grows.

**Spike 5: NTLM decision (ORQ-072/074/075) + Client SDK architecture (ORQ-169/170/175/176).** Combined spike because the SDK architecture depends on whether NTLM is maintained. Objective: decide NTLM posture (drop entirely vs maintain opt-in vs maintain default) and SDK architecture (Rust core + C bindings vs extend SSSD vs adopt FreeIPA client). Duration: 1 week. Deliverable: a decision document covering NTLM audit-mode migration plan, SDK architecture diagram, per-platform FFI surface (SSPI on Windows, OpenDirectory on macOS, SSSD responders on Linux), and bundled MIT krb5 vs system Heimdal decision. Recommendation pending spike: NTLM opt-in (audit mode by default, drop after migration), Rust core SDK with C bindings.

**Spike 6: PKI enrollment protocol (ORQ-110/111) + Federation layer (ORQ-132/133/134) + SMB server choice (ORQ-154/155).** Three-in-one spike because each is a 2-3 day decision. Objective: decide PKI enrollment protocol (MS-WCCE for AD interop vs ACME for cross-platform native), federation layer (native Rust implementation vs Keycloak wrapper vs cloud IdP federation), and SMB server (Samba `smbd` vs fresh implementation). Duration: 1 week. Deliverable: three short decision documents. Recommendations pending spike: ACME native with MS-WCCE bridge for AD interop; Keycloak federation for v1 (lower effort) with native federation in v2; Samba `smbd` for v1 (mature, MS-SMB2-compatible) with fresh implementation evaluated for v3.

**Spike 7: Linux tier strategy (ORQ-202/203).** Objective: decide whether the framework builds a native Linux DC (the framework's Core Directory runs natively on Linux) or adopts FreeIPA as the Linux identity tier (the framework coordinates above FreeIPA). Duration: 1 week. Deliverable: a decision document covering operator migration paths (AD-to-framework vs AD-to-FreeIPA-to-framework), feature parity (FreeIPA lacks multi-domain-NC, RODC, AD CS-equivalent autoenrollment — PC-101), and engineering effort (native DC: high; FreeIPA wrapper: low). Recommendation pending spike: native Linux DC — the framework's Core Directory must be a peer DC, not a wrapper.

## Phase 1: Architecture decisions (2-4 weeks)

Each of the 11 Tier-1 ORQ clusters gets a decision deadline in Phase 1, with explicit cascading-impact analysis. The spike outcome is the recommended answer; the Phase 1 decision is the locked answer with sponsor sign-off. Phase 1 ends with an Architecture Decision Record (ADR) per ORQ cluster, signed by the framework's principal architect and the sponsor.

| ORQ cluster | Decision deadline | Cascades to | Rationale |
|---|---|---|---|
| ORQ-001/002/003/004 (replication) | Week 1 | Core Directory (PC-001/002), Operations (PC-108/110/111), Migration (PC-126/127/129) | Determines whether Phase 2 starts month 3 (Samba reuse) or month 6 (fresh). |
| ORQ-011/012/013/014 (storage) | Week 2 | Core Directory (PC-007/008/020), Operations (PC-109/110) | Depends on Spike 1's DRSUAPI decision; determines backup/restore and container strategy. |
| ORQ-026/027 (SID vs UUID) | Week 1 | KDC (PC-023/031), Auth Provider (PC-040), Client SDK (PC-089), Migration (PC-124/127) | SID-vs-UUID decision affects every principal reference in the directory; revert cost is total rewrite. |
| ORQ-030/031 (schema model) | Week 1 | Core Directory (PC-017), Client SDK (PC-085), Operations (PC-107/113) | Schema model determines LDAP-vs-typed API surface; affects every directory query path. |
| ORQ-042/043/044 (KDC) | Week 2 | KDC (PC-023/024/026/027), Auth Provider (PC-036/037/038), Client SDK (PC-085/090) | KDC choice determines PAC behavior, FAST support, PKINIT interop — every Kerberos-dependent feature cascades. |
| ORQ-072/074/075 (NTLM) | Week 1 | Auth Provider (PC-036/037/038), Client SDK (PC-085/094), Cross-Platform Parity (PC-094) | NTLM posture affects macOS/Linux parity directly (no native NTLM on macOS — PC-094). |
| ORQ-110/111 (PKI) | Week 3 | Cert Service (PC-057/059), Client SDK (PC-085), Migration (PC-127) | ACME vs MS-WCCE determines whether macOS/Linux clients can enroll natively or require a Windows-side bridge. |
| ORQ-132/133/134 (federation) | Week 3 | Federation Gateway (PC-068/071/073), Client SDK (PC-085) | Native vs Keycloak vs cloud determines operational complexity; Keycloak is lowest-effort for v1. |
| ORQ-154/155 (SMB server) | Week 3 | File Gateway (PC-078/079/080/081/083), Client SDK (PC-085) | Samba `smbd` is the mature choice; fresh implementation is multi-year. |
| ORQ-169/170/175/176 (Client SDK) | Week 2 | Client SDK (PC-085/089/090/091/093), Cross-Platform Parity (PC-094/095) | SDK architecture is the universal client surface; wrong choice means per-platform behavior drift. |
| ORQ-202/203 (Linux tier) | Week 4 | Operations (PC-109), Migration (PC-126), all Linux-side problems | Native Linux DC vs FreeIPA wrapper determines whether the framework is a peer or a coordinator. |

Total Phase 1 duration: 4 weeks of decision-locking, with the spike outcomes (Phase 0) feeding in. The cascade graph is: replication → storage → KDC → Client SDK; SID/UUID + schema → all of the above; NTLM → Client SDK + Cross-Platform Parity; PKI + federation + SMB → Cert Service + Federation Gateway + File Gateway; Linux tier → Operations + Migration. The replication decision is the highest-cascade; it must be locked in Week 1.

## Phase 2: MVP — solve the 23 blockers (6-12 months)

The MVP delivers the smallest subset that demonstrates end-to-end value: a Linux host can join the framework as a member, authenticate via Kerberos, apply policy via SSSD-equivalent, request a cert via ACME, and mount an SMB share — against both a framework DC and a Windows Server 2022 DC in mixed mode. Federation and migration are out of scope for MVP. The 23 blockers are grouped by capability below.

**Core Directory (6 blockers: PC-001, PC-002, PC-004, PC-007, plus 2 high-severity effectively blocker-class: PC-014 FSMO, PC-022 multi-tenancy).** MVP delivers: a working directory service with LDAPv3 read/write, DRSUAPI replication (per Spike 1 outcome — Samba reuse or fresh implementation), USN/InvocationID/UTD-vector replication model, `member`/`memberOf` back-link with linkID pairing, a storage engine (per Spike 2 outcome), FSMO role placement via Raft consensus (or AD-compatible single-master), and a documented multi-tenancy decision (per-tenant NC heads vs single-NC multi-tenant). MVP does *not* deliver: schema extension tooling (Phase 3), Global Catalog (Phase 3), AD-integrated DNS (Phase 3), RODC (Phase 4). See [`catalog/01-core-directory.md`](../catalog/01-core-directory.md).

**KDC (3 blockers: PC-023 MS-KILE, PC-024 RC4 default, PC-030 krbtgt rotation).** MVP delivers: a KDC issuing Kerberos tickets via AS-REQ/TGS-REQ with MS-KILE-conformant PAC generation and signing, AES-256-only default etype with RC4 opt-in (audit-logged), krbtgt account with documented rotation procedure (manual in MVP, automated in Phase 3). MVP does *not* deliver: PKINIT (Phase 3), FAST-required mode (Phase 3), gMSA (Phase 3), cross-realm referral (Phase 3). See [`catalog/02-kdc.md`](../catalog/02-kdc.md).

**Auth Provider (2 blockers: PC-037 NTLM relay, PC-038 PtH defense).** MVP delivers: an auth provider supporting Kerberos (primary) and NTLM (opt-in, audit-logged, channel-binding + EPA enforced), LSASS-equivalent protection on Windows (Credential Guard), PAM-based protection on Linux (`pam_sss.so` with `krb5_store_*`), and OpenDirectory/Authorization-based protection on macOS (PSSO Extension with hardware-bound keys). MVP does *not* deliver: S4U2Self/S4U2Proxy (Phase 3), audit events in structured format (Phase 3), time sync hardening (Phase 3). See [`catalog/03-auth-provider.md`](../catalog/03-auth-provider.md).

**Policy Engine (2 blockers: PC-045 GPO Preferences, PC-055 SYSVOL replication).** MVP delivers: basic policy distribution via a unified DSL that compiles to GPO (Windows), Configuration Profile (macOS), and `sssd.conf`/`pam_access.so` (Linux), covering the ~60% of GPO categories that have direct Configuration Profile equivalents. SYSVOL replication uses the framework's Core Directory replication (per Spike 1 outcome), not DFS-R. MVP does *not* deliver: full GPO Preferences support (Phase 3), ADMX schema (Phase 3), WMI filter replacement (Phase 3), policy rollback (Phase 4). See [`catalog/04-policy-engine.md`](../catalog/04-policy-engine.md).

**Cert Service (1 blocker: PC-057 AD CS).** MVP delivers: a basic CA exposing an ACME endpoint (RFC 8555), with cert enrollment from macOS and Linux clients via the Client SDK's ACME module. Windows clients use MS-WCCE during AD interop via a translation bridge. MVP does *not* deliver: certificate templates (Phase 3), autoenrollment (Phase 3), key archival (Phase 4), OCSP scaling (Phase 4). See [`catalog/05-cert-service.md`](../catalog/05-cert-service.md).

**File Gateway (3 blockers: PC-078 SMB 3.1.1, PC-079 SMB1 drop, PC-083 PrintNightmare).** MVP delivers: a basic file gateway using Samba `smbd` (per Spike 6 outcome) with SMB 3.1.1 enforced (pre-auth integrity + AES-GCM), SMB1 refused, and MS-RPRN driver install refused (PrintNightmare mitigation). MVP does *not* deliver: DFS-N/DFS-R (Phase 4), CA shares (Phase 4), ABE (Phase 4), offline files (Phase 4). See [`catalog/07-file-gateway.md`](../catalog/07-file-gateway.md).

**Client SDK (2 blockers: PC-085 unified SDK, PC-089 ID mapping).** MVP delivers: a Rust core SDK with C bindings on Windows/macOS/Linux, covering authentication (Kerberos via bundled MIT krb5 on macOS/Linux, SSPI on Windows), directory query (LDAP wrapper), policy application (compiles unified DSL to per-platform format), file/print client (SMB client wrapper), and cert enrollment (ACME). ID mapping uses SSSD's slice algorithm with the framework's directory-provided `ldap_idmap_range`. MVP does *not* deliver: federation client (Phase 3), smart-card logon (Phase 3), Swift/Python/Go bindings beyond minimum-viable (Phase 3). See [`catalog/08-client-sdk.md`](../catalog/08-client-sdk.md).

**Cross-Platform Parity (1 blocker: PC-095 unified policy authoring).** MVP delivers: the unified policy DSL described under Policy Engine above, with documented coverage map per platform. MVP does *not* deliver: macOS DDM support (Phase 5), legacy macOS agent compat (Phase 5), RODC (Phase 4), FreeIPA cross-forest trust (Phase 4). See [`catalog/09-cross-platform-parity.md`](../catalog/09-cross-platform-parity.md).

**Security (3 blockers: PC-116 Kerberoasting, PC-117 DCSync, PC-118 golden ticket).** MVP delivers: Kerberoasting mitigation (AES-only etype default, RC4 opt-in audit-logged — PC-024/116), DCSync prevention (DRSGetNCChanges requires `DS-Replication-Get-Changes-All` ACL, enforced by default — PC-117), golden ticket mitigation (krbtgt rotation procedure, manual in MVP — PC-030/118). MVP does *not* deliver: silver ticket mitigation (Phase 3), SIDHistory abuse prevention (Phase 3), AdminSDHolder equivalent (Phase 4), supply-chain hardening (Phase 4). See [`catalog/11-security-threat-model.md`](../catalog/11-security-threat-model.md).

**Operations (0 blockers).** MVP delivers minimum-viable operational tooling: `framework-cli` (a unified CLI for join, query, policy, cert, file ops — PC-115 equivalent of `dcdiag`/`repadmin`/`ntdsutil`), structured JSON logging (PC-111), basic Prometheus exporter (PC-106). MVP does *not* deliver: full observability suite (Phase 3), containerization (Phase 3), DR runbooks (Phase 4), multi-region (Phase 4). See [`catalog/10-operations.md`](../catalog/10-operations.md).

**Migration (0 blockers).** MVP does not deliver migration tooling. Migration is Phase 4 scope. See [`catalog/12-migration-and-coexistence.md`](../catalog/12-migration-and-coexistence.md).

**MVP delivery summary**: working directory service with LDAP + DRSUAPI replication; KDC issuing Kerberos tickets; auth provider supporting Kerberos + opt-in NTLM; basic policy distribution (60% coverage); basic cert enrollment (ACME); basic file gateway (Samba `smbd` with SMB 3.1.1); Rust client SDK on all 3 platforms; minimum-viable operational tooling; security mitigations for the top 3 threats (Kerberoasting, DCSync, golden ticket). No federation, no migration, no PKI templates, no advanced policy, no advanced file features.

## Phase 3: v1 — solve the 64 high-severity problems (12-18 months)

v1 expands the MVP horizontally to production quality and vertically to cover the high-severity problems. Each capability adds features beyond MVP.

**Core Directory adds**: Global Catalog (PC-005), AD-integrated DNS (PC-019), schema extension tooling (PC-017), tombstone/lingering-object cleanup (PC-009), RID pool allocation (PC-015), SPN uniqueness enforcement (PC-031), UPN uniqueness (PC-032), Linked Value Replication (PC-003), `tokenGroups` construction (PC-018), constructed attributes (`memberOf`, `canonicalName` — PC-018).

**KDC adds**: PKINIT smart-card logon (PC-027), FAST-required mode (PC-026), gMSA (PC-035), cross-realm TGT referral (PC-028), AES-SHA384 etype 0x13 (PC-029), automatic krbtgt rotation (PC-030), KDC throughput optimization for million-object scale (PC-033), `kpasswd` (PC-034).

**Auth Provider adds**: S4U2Self/S4U2Proxy constrained delegation (PC-039), Windows Token ↔ Linux PAM ↔ macOS Authorization unified abstraction (PC-040), time sync hardening with chrony/ntpd (PC-041), Kerberos audit events in structured format (PC-042).

**Policy Engine adds**: full GPO Preferences support (Drive Maps, Files, Registry, Scheduled Tasks, Folder Redirection, Environment, Local Users and Groups, Printers — PC-045), ADMX schema (PC-046), CSE model (PC-047), GPO security filtering (PC-054), Registry.pol PReg parser (PC-052), SSSD GPO access control integration (PC-053), WMI filter replacement with declarative host facts (PC-049).

**Cert Service adds**: certificate templates v1/v2/v3 with `msPKI-*` attributes (PC-058), autoenrollment via the Client SDK (PC-059), OCSP responder (PC-061), NTAuthCertificates distribution (PC-067), CA database corruption recovery (PC-062), cert revocation during CA outage (PC-063), NDES/SCEP for network devices (PC-064).

**Federation Gateway adds**: native OIDC provider (PC-071), ADFS WAP equivalent via Envoy + ext-authz (PC-073), ADFS farm topology equivalent (PC-074), OAuth2/OIDC quirks handling (PC-075), external OIDC IdP federation (PC-076), token-signing cert rollover (PC-070), SAML replay detection (PC-072).

**File Gateway adds**: DFS-N (PC-080), Continuously Available shares (PC-081), Access-Based Enumeration (PC-082), offline files / CSC (PC-084, deferred to v2 if engineering effort is too high).

**Client SDK adds**: federation client (token cache, refresh, RP metadata), smart-card logon (PC-027 — PKINIT), full Swift/Python/Go bindings beyond MVP, PSSO Extension integration on macOS 13+ (PC-086), Jamf Connect ROPG fallback on macOS 12 and below (PC-087), SSSD GPO access control integration (PC-088), Heimdal-vs-MIT standardization (PC-090), domain join via `realm join`/`adcli`/`net ads join`/`dsconfigad` unified (PC-091), PAM distro variance handling (PC-092), ticket cache type abstraction (PC-093).

**Operations adds**: full Prometheus exporter + OpenTelemetry (PC-106), containerization via Kubernetes operator (PC-109), structured audit logging (PC-111), REST/gRPC API (PC-112), unified operational CLI (PC-115), trust password rotation (PC-114), `dcdiag`/`repadmin`/`ntdsutil` equivalents (PC-115), multi-region deployment with PDC urgent replication (PC-108).

**Security adds**: silver ticket mitigation via `PAC_BUFFER_TICKET_CHECKSUM` (PC-119), SIDHistory abuse prevention (PC-120), selective authentication (PC-121), AdminSDHolder + SDROP equivalent (PC-122), supply-chain hardening (PC-123).

**Cross-Platform Parity adds**: macOS FileVault recovery key escrow to framework directory (PC-097), LAPS on macOS 14+ via PSSO device password rotation (PC-098), FreeIPA cross-forest trust (PC-101), RODC (PC-102).

## Phase 4: v2 — solve the 33 medium-severity problems (12-18 months)

v2 adds migration tooling, advanced federation, advanced PKI, advanced file gateway, and advanced operations.

**Migration adds (PC-124 through PC-130 — all 7 migration problems)**: sIDHistory migration via `DRSAddSidHistory` + `SeEnableDelegationPrivilege` (PC-124), GPO translation from AD to framework-native (PC-125), client switchover with parallel-run support (PC-126), password hash migration via sIDHistory or password-sync agent (PC-127), DNS namespace sharing during migration (PC-128), Kerberos cross-realm with `capaths` + `trustedDomainObject` (PC-129), SYSVOL migration with SMB share compat (PC-130).

**Federation Gateway adds**: claims rule language migration (PC-069), ADFS CRL-to-Rego/Cedar translation (PC-069), three-tier CA topology (PC-066), key archival KRA (PC-060), CA database corruption recovery procedures (PC-062), OCSP scaling (PC-061).

**File Gateway adds**: DFS-R equivalent (PC-080), Continuously Available shares cluster integration (PC-081), offline files / CSC-equivalent (PC-084).

**Operations adds**: disaster recovery runbooks (PC-110), multi-region AD deployment with replication latency optimization (PC-108), schema upgrade irreversibility documentation (PC-107), functional level upgrade one-way documentation (PC-113), `dcdiag`/`repadmin`/`ntdsutil` full coverage (PC-115).

**Policy Engine adds**: GPO background refresh interval tuning (PC-051), GPO security filtering hardening (PC-054), no native policy versioning/history (PC-056), slow-link detection replacement (PC-050), GPO conflict resolution (PC-044), GPO rollback/transactional semantics (PC-048).

## Phase 5: v3 — solve the 10 low-severity problems + polish (6-12 months)

v3 adds legacy compat and polish. The framework's modern posture (drop NTLM, drop SMB1, AES-only Kerberos) means legacy support is opt-in only — v3 closes the opt-in paths for operators who genuinely need them.

**Legacy compat adds**: NTLM maintenance (if Phase 1 decided maintain — PC-036/094), FRS support for migration scenarios (PC-055 fallback if Windows source DC is pre-2008), legacy macOS agent compat — NoMAD, Enterprise Connect, AdmitMac (PC-104), OpenLDAP + MIT Kerberos roll-your-own stack documentation (PC-103), cross-CA trust via `CrossCertificatePair` (PC-065), AD RMS migration to Azure Information Protection (PC-077), macOS DDM full coverage (PC-096), AES-SHA384 etype 0x13 default (PC-029), SAML replay detection tuning (PC-072).

**Polish adds**: full documentation coverage for every PC and ORQ in the catalog, operator runbooks for every Phase 2-4 feature, performance tuning guides, troubleshooting guides, certification curriculum for partners, customer-facing architecture whitepapers.

## Cross-cutting workstreams

Four workstreams run continuously across all phases. Each has a dedicated lead and a quarterly review cadence.

**Security review (continuous).** STRIDE threat model updates per release, mapped to the catalog's 8 security threats (PC-116 through PC-123). Penetration testing per release, with a focus on the 3 blocker-class threats (Kerberoasting, DCSync, golden ticket). External security audit at MVP, v1, v2. The framework's threat model document is updated quarterly and reviewed against new attack techniques (MITRE ATT&CK T1558 — Steal or Forge Kerberos Tickets, T1003.002 — Security Account Manager, T1558.003 — Kerberoasting).

**Interop testing (continuous).** Maintain a matrix of interop tests against Windows Server 2022, Windows Server 2025 (when released), Samba 4.x, MIT Kerberos 1.20+, Heimdal 7.x, FreeIPA 4.10+, Jamf Pro 11.10+. Tests cover: DRSUAPI replication (mixed framework-DC + Windows-DC topology), Kerberos cross-realm (framework realm + AD realm), LDAP controls (per [`docs/02-protocols/02-ldap-protocol.md`](../docs/02-protocols/02-ldap-protocol.md)), SMB 3.1.1 (framework client + Windows server, framework server + Windows client), GPO interop (framework-emitted GPO consumed by Windows client), Configuration Profile interop (framework-emitted profile consumed by macOS PSSO).

**Documentation (continuous).** Every feature ships with a KB file update. The [`docs/`](../docs/) directory grows with the framework's surface. Every PC in the catalog has a corresponding KB section explaining the framework's resolution. Every ORQ has a decision record in the ADR repository. Documentation is reviewed at MVP, v1, v2, v3 — missing or stale documentation blocks release.

**Performance (continuous).** 1M-object directory benchmark suite, run nightly. Benchmarks: directory write throughput (target: 10,000 writes/sec on a single DC), replication latency (target: <5s p99 for a write to reach all DCs in a 5-DC topology), KDC AS-REQ throughput (target: 5,000 AS-REQ/sec on a single KDC), LDAP search latency (target: <50ms p99 for a subtree search returning 1,000 entries), SMB read throughput (target: 10 Gbps on a single SMB 3.1.1 connection). Performance regressions block release.

## Risks and mitigations

Seven risks identified from the catalog. Each is a Phase 2+ slip risk that requires explicit mitigation in the project plan.

**Risk 1: DRSUAPI implementation complexity may slip Phase 2 by 3-6 months.** DRSUAPI (MS-DRSR) is a complex RPC protocol with 24 opnums, USN/InvocationID/UTD-vector replication semantics, and 30+ years of edge-case compat with Windows DCs. Spike 1 (Phase 0) evaluates Samba's DRSUAPI code as a starting point. *Mitigation*: if Spike 1 concludes Samba's code is reusable (GPL-compatible license, acceptable code quality), Phase 2 starts month 3; if Spike 1 concludes fresh implementation is required, Phase 2 grows to 9-12 months. The decision deadline for this risk is Phase 0 Week 2.

**Risk 2: MIT vs Heimdal Kerberos divergence may break PKINIT interop.** PKINIT (RFC 4556) has subtle differences between MIT krb5 and Heimdal — `pkinit_id` syntax, anonymous PKINIT `anon_reply` semantics, `pkinit_anchors` config. If the framework's KDC (Heimdal fork per Spike 4) and client (MIT krb5 per Spike 5) cannot interop on PKINIT, smart-card logon breaks. *Mitigation*: Spike 4 includes a PKINIT interop matrix against Windows Server 2022 AD; failures block Phase 3 PKINIT delivery (PC-027). Fallback: bundle the same Kerberos implementation on both KDC and client (Heimdal-on-client or MIT-on-KDC), accepting the divergence cost.

**Risk 3: macOS PSSO Extension may not support all framework features.** PSSO is macOS 13+ only and Apple-controlled. If Apple changes PSSO's payload schema in a future macOS release, the framework's macOS client SDK may break. *Mitigation*: maintain a Jamf Connect fallback for macOS 12 and below (PC-087), and monitor Apple's PSSO release notes for breaking changes. The framework's macOS SDK is designed to degrade gracefully (PSSO if available, Jamf Connect if not, basic Kerberos via system Heimdal as last resort).

**Risk 4: SSSD's GPO access control subset may be insufficient for production.** SSSD enforces only 5 of the ~40 User Rights Assignment entries. Operators who depend on full URA enforcement (e.g., `SeServiceLogonRight` for service accounts, `SeDenyNetworkLogonRight` for blocked users) will find the framework's Linux client less restrictive than Windows. *Mitigation*: the framework's client SDK extends SSSD's GPO parser to cover the full URA set in v1 (PC-053 high-severity), and provides a `pam_access.so`-based fallback for any URA SSSD cannot parse.

**Risk 5: ACME-to-MS-WCCE bridge may break Windows autoenroll.** The framework's cert service exposes ACME for cross-platform native enrollment, with an MS-WCCE bridge for Windows AD CS interop. If the bridge has translation gaps (e.g., cert template attributes that don't map cleanly from ACME to MS-WCCE), Windows autoenroll may fail in mixed mode. *Mitigation*: the bridge is tested against a Windows Server 2022 AD CS in mixed mode as part of Phase 2 (MVP) interop testing. Translation gaps are documented and Windows clients fall back to native MS-WCCE during migration.

**Risk 6: ID mapping migration from PBIS/Winbind may break NFS/SMB permissions.** Operators migrating from PBIS or Winbind to the framework's SSSD-baseline ID mapping will see UID changes for the same AD user (different algorithms, different ranges). This breaks NFS file ownership (UIDs in inode metadata) and SMB file ownership (SIDs in `nTSecurityDescriptor` translated to UIDs at the client). *Mitigation*: the framework's migration tooling includes an ID-mapping migration planner that reads the existing PBIS/Winbind `idmap` config and emits an SSSD `ldap_idmap_range` that preserves existing UIDs. Where preservation is impossible (different algorithms), the migration tooling documents the file-ownership re-chown procedure.

**Risk 7: Federation layer choice (Keycloak vs native) may delay Phase 3.** Spike 6 recommends Keycloak wrapper for v1 (lowest effort), with native federation in v2. If Keycloak's operational complexity (JVM, database, scaling) proves unacceptable to operators, the framework may need to bring native federation forward to Phase 3, slipping Phase 3 by 3-6 months. *Mitigation*: Phase 0 spike outcome includes an operator-survey on Keycloak acceptance; if operators reject Keycloak uniformly, native federation is brought forward to Phase 3 and Phase 3 duration extends to 18-24 months.

## Success criteria

Each phase has explicit "done" criteria. A phase is not complete until every criterion is met.

**Phase 0 (research spikes) succeeds when**: 7 spike decision documents are signed by the principal architect and the sponsor; each Tier-1 ORQ cluster has a recommended answer with cascading-impact analysis; the Phase 1 ADR draft is ready for review.

**Phase 1 (architecture decisions) succeeds when**: 11 ADRs are signed and published; the framework's architecture document is ratified; the engineering team is staffed and the Phase 2 sprint plan is committed.

**Phase 2 (MVP) succeeds when**: a Linux host can join the framework as a member via `realm join`-equivalent, authenticate via Kerberos (`kinit` succeeds, `klist` shows a TGT), apply policy via the SSSD-equivalent Client SDK module (policy DSL compiles to `sssd.conf` and is applied), request a cert via ACME (`getcert`-equivalent succeeds and the cert is valid against the framework's CA), mount an SMB share (`mount -t cifs` succeeds against the framework's file gateway with SMB 3.1.1 negotiated), and all of this works against both a framework DC and a Windows Server 2022 DC in mixed mode (mixed-mode interop test passes). Bonus criterion: a macOS 14 host can do the same with PSSO Extension as the auth surface.

**Phase 3 (v1) succeeds when**: all 64 high-severity problems are resolved (per the catalog's severity classification), the 1M-object directory benchmark suite passes nightly, the security audit finds no Critical or High findings, the interop test matrix passes against Windows Server 2022/2025, Samba 4.x, MIT Kerberos 1.20+, Heimdal 7.x, FreeIPA 4.10+, and Jamf Pro 11.10+, and at least 3 design-partner operators have completed a production pilot with 10,000+ users.

**Phase 4 (v2) succeeds when**: all 33 medium-severity problems are resolved, the migration tooling supports AD-to-framework migration for a 100,000-user forest (verified via a design-partner migration), advanced federation (claims rules, custom attribute stores) is in production at 2+ design-partner sites, advanced PKI (key archival, OCSP scaling) is in production at 2+ design-partner sites, and the disaster recovery runbook is tested via a full DC-loss drill at 1+ design-partner site.

**Phase 5 (v3) succeeds when**: all 10 low-severity problems are resolved, legacy compat (NTLM, FRS, legacy macOS agents) is opt-in and documented, the framework's documentation is complete (every PC and ORQ has a corresponding KB section, every Phase 2-4 feature has an operator runbook), and the framework is Generally Available with a published support policy (5-year support per major release, 1-year overlap between major releases).

These criteria are deliberately concrete and testable. A phase that meets its criteria ships; a phase that does not, does not. The framework's reputation depends on this discipline — shipping a phase that does not meet its criteria would compound technical debt and erode operator trust. The catalog's 130 problems and 262 ORQs are the framework's contract with itself; the roadmap is the schedule for delivering that contract.
