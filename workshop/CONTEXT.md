---
title: Tier-1 ORQ Resolution Workshop — Context Briefing
audience: architects-and-engineers
tags: [workshop, orq, tier-1, architecture, context]
related:
  - ./README.md
  - ../adr/TRIAGE.md
  - ../adr/README.md
  - ../catalog/13-open-research-questions.md
  - ../draft/04-open-research-questions.md
  - ../draft/06-roadmap.md
last_updated: 2026-08-13
---

# Tier-1 ORQ Resolution Workshop — Context Briefing

This briefing prepares architects and engineers for the 2-day Tier-1 ORQ Resolution Workshop, whose purpose is to convert the 11 Tier-1 Open Research Questions (ORQ-001 through ORQ-203) into architectural decisions that unblock 61 deferred problems (and the ~61 follow-up ADRs that depend on them) and lock the framework's foundational architecture before capability design begins. Of the 11 Tier-1 ORQs, 9 are fed by 7 research spikes (Spike 1–7, executed in parallel during the prior 4–5 week Phase 0); the remaining 2 (identity model and schema model) are pure architectural design decisions to be made in the workshop with the spike readouts in hand. Each decision will be scored against 7 weighted criteria (§Decision criteria) and recorded by the workshop scribe in `DECISIONS.md`. Wrong answers at Tier-1 cascade across multiple capabilities — replication-protocol choice alone rewrites Core Directory, Operations, Migration, and Security — so the workshop is the highest-leverage 2 days in the framework's design lifecycle.

## The 11 Tier-1 ORQs

### ORQ-001 / ORQ-002 / ORQ-003 / ORQ-004: Replication protocol choice (DRSUAPI vs. CRDT vs. Raft)
- **Theme**: Multi-master replication protocol that determines wire-compat, conflict resolution, and migration story.
- **Source**: `catalog/13-open-research-questions.md` lines 38–41
- **Question**:
  - ORQ-001: Should the framework adopt Samba's DRSUAPI code (GPL) or write a fresh implementation?
  - ORQ-002: Is there a path to CRDT/OT replication that still speaks DRSUAPI on the wire?
  - ORQ-003: Can `PROPERTY_META_DATA_EXT` be expressed as a CRDT tombstone vector?
  - ORQ-004: Does a Raft log naturally subsume the Up-To-Dateness (UTD) vector needs?
- **Why it's Tier-1**: Replication is the foundation of Core Directory; every Operations, Migration, and Security problem depends on it. Picking wrong forces a rewrite of ADR-001 (LVR), ADR-008 (declarative topology), ADR-010 (backup/restore), ADR-058 (container-native DCs), and ADR-061 (REST/gRPC API) — and the entire PC-117 (DCSync) threat model evaporates if a non-DRSUAPI protocol is chosen.
- **Candidate answers**:
  - **Option A — Implement DRSUAPI server-side (full AD wire-compat).** Forces the UTD vector + `PROPERTY_META_DATA_EXT` model + lingering-object detection. No open-source implementation outside Samba (GPLv3); framework must inherit GPLv3, write ~5K-line fresh implementation, or license the Samba code.
  - **Option B — CRDT/OT replication with a DRSUAPI wire-compat shim.** Preserves interop on the wire, adds a translation layer, unproven at AD scale (1M+ objects, 100+ DCs).
  - **Option C — Raft consensus, abandon AD-interop.** Clean-slate, strong consistency, breaks every AD-interop scenario (mixed-forest replication, ADMT-style migration, RODC at branch sites). Simplifies correctness but rewrites the migration story from scratch.
- **Implications of each candidate**:
  - **Option A**: UTD vector + `PROPERTY_META_DATA_EXT` forced. PC-117 DCSync threat applies (the attacker primitive is `EXOP_REPL_SECRETS` opnum, which only exists in DRSUAPI). GPLv3 license risk for commercial framework adoption. Migration from AD is trivial (wire-compatible). Estimated 6 person-months.
  - **Option B**: UTD vector preserved on the wire but CRDT OR-set internally. Conflict resolution switches from LWW to add-wins for tombstones. DCSync threat is partially mitigated (the wire still speaks DRSUAPI but the secret-fetch opnum can be policy-gated). Adds a translation layer in every replication path. ~8 person-months (CRDT engine + shim).
  - **Option C**: No DRSUAPI wire — AD DCs cannot replicate with framework DCs. PC-117 DCSync disappears. Migration must be batch-import (snapshot AD DIT → framework import), not parallel-run. PC-124/126 (sIDHistory migration, parallel-run) become much harder. Raft quorum requirement complicates branch-site deployment (no RODC equivalent; PC-102 redesigns). ~4 person-months for the Raft engine itself.
- **Problems gated by this ORQ**: PC-001 (blocker), PC-002 (blocker), PC-005 (high), PC-009 (high), PC-014 (high), PC-019 (high), PC-043 (high), PC-044 (medium), PC-055 (blocker), PC-102 (medium, also ORQ-026/027), PC-108 (high), PC-117 (blocker), PC-126 (high, also ORQ-026/027). Plus partial-ADR dependents: ADR-001, ADR-003, ADR-004, ADR-044, ADR-062.
- **Research spike feeding this ORQ**: **Spike 1 — DRSUAPI replication interop vs. CRDT-shim** (3 weeks, 1M-object prototype benchmarking pure-DRSUAPI vs. CRDT-shim backends on replication latency, throughput, and AD-interop correctness).
- **Pre-workshop reading**:
  - `adr/ADR-001-linked-value-replication.md` (PARTIAL — defers shim GC strategy)
  - `adr/ADR-008-declarative-replication-topology.md`
  - `adr/ADR-044-dfs-n-via-dns-srv.md` (PARTIAL — defers DFS-R to ORQ-001/002)
  - `adr/ADR-062-trust-password-auto-rotation.md` (PARTIAL — defers to ORQ-001)
  - `docs/03-directory-schema/05-replication-internals.md` (UTD vector, `PROPERTY_META_DATA_EXT`, `REPLVALINF_V3`)
  - `docs/02-protocols/06-rpc-dcerpc-ms-drsr.md` (DRSUAPI opnum table, `EXOP_REPL_SECRETS`)

### ORQ-011 / ORQ-012 / ORQ-013 / ORQ-014: Storage engine choice (ESE vs. SQLite vs. FoundationDB vs. custom)
- **Theme**: On-disk storage engine that determines throughput, transactional semantics, backup/restore model, and replication log structure.
- **Source**: `catalog/13-open-research-questions.md` lines 48–51
- **Question**:
  - ORQ-011: SQLite?
  - ORQ-012: FoundationDB?
  - ORQ-013: Custom?
  - ORQ-014: Each has tradeoffs; pick one and justify?
- **Why it's Tier-1**: The storage engine is the substrate for every Core Directory and Operations decision. It determines backup/restore (PC-020, ADR-010 partial), tombstone lifetime (PC-009), sdtable design (PC-008, ADR-004 partial), DC containerization (PC-109, ADR-058 partial), and PITR runbooks (PC-110, ADR-059 partial). Switching engines post-MVP requires a full data migration.
- **Candidate answers**:
  - **Option A — SQLite WAL.** Mature, embedded, single-node. Mature ecosystem; well-understood operational profile. Limits DC write throughput to ~5K writes/sec (single-writer), which is below modern enterprise DC requirements.
  - **Option B — FoundationDB.** Distributed, ordered key-value. Scales horizontally to 10M+ objects and 100+ DCs. Adds a distributed storage dependency (operationally heavier than embedded). Used in production by Snowflake and Apple.
  - **Option C — RocksDB.** LSM-tree, embedded. Scales to 10M objects on a single node; multi-DC via Raft-replicated logs. Tuning is non-trivial (compaction strategy, bloom filters, block cache). Used by CockroachDB, TiKV, Grafana Mimir.
  - **Option D — Custom.** Full control over transactional semantics, backup model, replication log format. Multi-year engineering investment; high defect risk.
- **Implications of each candidate**:
  - **Option A**: Backup is `sqlite3 .backup` (single file). PITR via WAL replay. Cannot exceed single-node throughput — disqualifies for >10K write/sec workloads. Suitable only for PoC / small deployments.
  - **Option B**: Backup is FDB backup agent (continuous to S3/object store). PITR is native. Multi-DC active-active is FDB-native. Adds FDB cluster as a Tier-0 dependency — must be on the framework's critical-path SLO. Replaces ESE's role most directly.
  - **Option C**: Backup is RocksDB checkpoint + WAL archive. PITR via WAL replay. Multi-DC requires a Raft replication layer on top (the framework would build its own consensus, not FDB's). Operational tuning is the dominant cost.
  - **Option D**: The framework owns everything. Maximum architectural freedom, maximum implementation cost. Not justified unless none of A/B/C meet a hard requirement (e.g., sub-ms commit latency on spinny disks for edge DCs).
- **Problems gated by this ORQ**: PC-007 (blocker). Plus partial-ADR dependents: ADR-010 (backup/restore), ADR-034 (CA transactional DB), ADR-058 (container-native DCs), ADR-059 (PITR runbooks), ADR-066 (AdminSDHolder declarative RBAC), ADR-067 (Sigstore supply chain).
- **Research spike feeding this ORQ**: **Spike 2 — Storage engine evaluation: FoundationDB vs. RocksDB vs. SQLite** (3 weeks; minimal directory store on each engine; benchmark LDAP read/write throughput at 1M/10M/100M objects; backup/restore time; replication log throughput; multi-attribute transactional semantics).
- **Pre-workshop reading**:
  - `adr/ADR-010-backup-restore-snapshots.md` (PARTIAL — defers backup mechanism to ORQ-011)
  - `adr/ADR-034-transactional-db-pitr-reject-repair.md` (PARTIAL — defers CA storage to ORQ-120/121)
  - `adr/ADR-058-container-native-dcs-operator.md` (PARTIAL — defers storage layout to ORQ-011)
  - `adr/ADR-059-pitr-backup-dr-runbooks.md` (PARTIAL — defers PITR mechanism to ORQ-011)
  - `docs/01-ad-core/01-ad-ds-internals.md` (ESE/JET Blue internals, `ntds.dit` schema)

### ORQ-026 / ORQ-027: Identity model (SIDs vs. UUIDs vs. both)
- **Theme**: Primary key for security principals — wire-format currency with AD vs. modern internal representation.
- **Source**: `catalog/13-open-research-questions.md` lines 63–64
- **Question**:
  - ORQ-026: Replace SIDs with UUIDs?
  - ORQ-027: Keep SIDs for AD interop, use UUIDs internally?
- **Why it's Tier-1**: SIDs are the interop currency with AD (ACLs, PACs, audit logs, sIDHistory migration). UUIDs are the modern equivalent. Using both requires a mapping layer that touches every capability that handles a principal reference — KDC PAC builder, Auth Provider token construction, Policy Engine security filtering, File Gateway ACL evaluator, Client SDK ID mapping, Migration sIDHistory flow. Picking wrong forces a re-litigation of the entire identity stack.
- **Candidate answers**:
  - **Option A — SIDs only.** Full AD interop. No mapping layer. Forecloses future modernisation; inherits RID-pool allocation bottleneck (PC-015) and SID/UID mapping complexity on POSIX (PC-089).
  - **Option B — UUIDs only.** Modern, eliminates RID pool. Breaks AD interop entirely (ACLs on migrated objects reference SIDs that no longer exist). sIDHistory migration (PC-124) becomes impossible without a synthetic SID layer.
  - **Option C — Both with cached bidirectional mapping.** SIDs as the wire format for AD interop; UUIDs as the internal primary key. Cached mapping table (`sid_to_uuid`, `uuid_to_sid`) in the directory. Mapping table is itself a Tier-2 design problem (ORQ-177/178: distribution, cache invalidation, GC of orphaned mappings).
- **Implications of each candidate**:
  - **Option A**: PC-015 RID pool problem inherited unchanged. PC-089 POSIX UID mapping still required (SID → UID algorithm). PC-124 sIDHistory migration works as-is. PC-120 sIDHistory abuse threat applies.
  - **Option B**: PC-015 eliminated. PC-089 still required (UUID → UID algorithm). PC-124 must be redesigned as claims-based migration. PC-120 eliminated (no sIDHistory). All AD-interop scenarios (mixed-forest ACLs, cross-trust access) require a SID synthesis layer — defeats the modernisation goal.
  - **Option C**: PC-015 still required (SIDs are kept for AD-interop). PC-089 simplified (UUID is primary key; SID→UID is a cache lookup, not an algorithm). PC-124 works (sIDHistory preserved on the wire). PC-120 mitigated (per-trust filtering policy on the mapping table). Mapping layer adds ~1 KB/principal storage and O(1) lookup; cache miss rate is the dominant operational metric.
- **Problems gated by this ORQ**: PC-010 (medium, also ORQ-030/031), PC-015 (high), PC-022 (high), PC-089 (blocker), PC-102 (medium, also ORQ-001/002), PC-120 (high), PC-124 (high), PC-126 (high, also ORQ-001/002), PC-127 (high). Plus partial-ADR dependents: ADR-002 (memberOf back-link), ADR-053 (key escrow), ADR-054 (LAPS rotation).
- **Research spike feeding this ORQ**: None — this is an architectural design decision, not an empirical question. Resolved in the workshop with Spike 1 (replication) readout in hand.
- **Pre-workshop reading**:
  - `adr/ADR-002-memberof-back-link.md` (PARTIAL — defers to ORQ-026)
  - `adr/ADR-053-key-escrow-and-nbde.md` (PARTIAL — defers principal model to ORQ-026)
  - `adr/ADR-054-per-host-laps-rotation.md` (PARTIAL — defers host principal model to ORQ-026)
  - `docs/03-directory-schema/01-schema-attributes.md` (`objectSid`, `sIDHistory`, `msDS-PrincipalIdentifier` attributes)
  - `docs/09-linux-equivalents/02-sssd-id-mapping.md` (SID → POSIX UID algorithms)

### ORQ-030 / ORQ-031: Schema model (LDAP dynamic vs. typed vs. hybrid)
- **Theme**: Directory schema representation — runtime-extensible LDAP-style vs. compile-time typed.
- **Source**: `catalog/13-open-research-questions.md` lines 67–68
- **Question**:
  - ORQ-030: Hybrid (LDAP schema + typed projection)?
  - ORQ-031: Pure typed with LDAP schema as an adapter?
- **Why it's Tier-1**: Schema choice determines the directory API surface, the replication payload format, and the client SDK type system. Cascades into PC-017 (schema format), PC-021 (bitmask vs. explicit columns), PC-046 (ADMX-equivalent), PC-058 (cert template schema), PC-107 (schema-as-code), PC-113 (functional levels).
- **Candidate answers**:
  - **Option A — LDAP dynamic schema.** Full AD compat; runtime-extensible via `schemaModifyRequest`. No compile-time type safety — every attribute is a string/byte blob. Forces the SDK to expose attributes as generic maps.
  - **Option B — Typed schema.** Protobuf/SQL DDL with versioned migrations. Compile-time safety; tooling generates language-specific types. No runtime extension — adding an attribute requires a schema migration (PC-107 becomes significant).
  - **Option C — Hybrid.** LDAP schema as the wire/storage format; typed projection as the SDK surface. Code generation from the LDAP schema definition (analogous to protobuf-from-IDL). Adapter cost in the SDK and the policy engine.
- **Implications of each candidate**:
  - **Option A**: PC-046 ADMX translation straightforward (ADMX is LDAP-schema-shaped). PC-058 cert templates keep `msPKI-*` attributes. PC-107 schema upgrades reversible (add/remove attributes). SDK is generic (`getattr(name)`); no type safety; every consumer parses attribute values themselves.
  - **Option B**: PC-046 requires an ADMX → typed-schema translator. PC-058 templates become typed structures (mirrors `CertificateTemplate` protobuf). PC-107 schema upgrades are versioned migrations (like SQL migrations). SDK is strongly typed (generated code); consumers get compile-time safety. Adding an attribute requires a PR.
  - **Option C**: PC-046 uses typed projection for the SDK; LDAP wire format preserved for AD-interop. PC-058 templates are typed internally, exposed as LDAP attributes for AD-interop. PC-107 schema-as-code generates both the LDAP schema and the typed projection from a single source. SDK is strongly typed (projection); LDAP wire is generic. Adapter cost in the SDK code generator.
- **Problems gated by this ORQ**: PC-010 (medium, also ORQ-026/027), PC-017 (high), PC-021 (medium), PC-045 (blocker), PC-046 (high), PC-095 (blocker, also ORQ-169/170/175/176), PC-107 (high), PC-113 (medium), PC-125 (high). Plus partial-ADR dependents: ADR-024 (per-platform executors, also ORQ-090/091).
- **Research spike feeding this ORQ**: None — architectural design decision. Resolved in the workshop.
- **Pre-workshop reading**:
  - `adr/ADR-003-schema-cache-cow.md` (PARTIAL — defers cache invalidation to ORQ-001; schema format depends on ORQ-030/031)
  - `adr/ADR-024-per-platform-policy-executors.md` (PARTIAL — defers policy format to ORQ-090/091; schema model is upstream)
  - `docs/03-directory-schema/01-schema-attributes.md` (attribute syntaxes, `objectClassCategory`, `systemFlags`, `lDAPDisplayName`)
  - `docs/04-group-policy/03-admx-templates.md` (ADMX schema, namespace, `policy` element structure)

### ORQ-042 / ORQ-043 / ORQ-044: KDC implementation (Samba Heimdal vs. MIT+plugin vs. fresh)
- **Theme**: KDC codebase — license-permissive MIT vs. MS-PAC-emitting Samba Heimdal fork vs. greenfield.
- **Source**: `catalog/13-open-research-questions.md` lines 82–84
- **Question**:
  - ORQ-042: Reuse Samba's Heimdal fork (GPL)?
  - ORQ-043: MIT krb5 + custom PAC plugin (FreeIPA approach)?
  - ORQ-044: Fresh implementation?
- **Why it's Tier-1**: The KDC is the second-most-critical capability (after the directory itself). PAC generation and signing must match MS-KILE byte-for-byte, or AD-aware services (IIS, SQL Server, Samba SMB) reject framework-issued tickets. The KDC implementation choice gates PC-023 (MS-KILE profile), PC-025 (PAC validation mechanism), PC-119 (silver-ticket mitigation via `PAC_BUFFER_TICKET_CHECKSUM`), and every Kerberos-related Security problem.
- **Candidate answers**:
  - **Option A — Samba Heimdal fork.** GPLv3 (license risk for commercial framework adoption). Only open-source KDC that emits MS-PAC for all principals. Mature PAC generation code in `source4/kdc/`. Inherits Samba's Heimdal fork lag (~5 years behind upstream Heimdal).
  - **Option B — MIT krb5 + custom PAC plugin.** MIT-licensed. Requires re-implementing PAC generation (FreeIPA's `ipa_kdb_mspac.c` is the reference, ~5K lines, generates MS-PAC for trust users only). Framework would extend to all principals. Defect surface in the PAC plugin.
  - **Option C — Fresh implementation.** Full control over KDC internals. Multi-year effort. High defect risk on MS-KILE corner cases (constrained delegation, compound identity, `PAC_REQUESTOR`/`PAC_FULL_CHECKSUM` per Server 2016+). Rejects a decade of upstream MIT krb5 bug fixes.
- **Implications of each candidate**:
  - **Option A**: PAC generation works out of the box. Framework inherits GPLv3 — commercial adoption requires either a dual-license arrangement with the Samba Team or a clean-room reimplementation funded by the framework. KDC codebase is ~5 years behind upstream Heimdal — security fixes lag.
  - **Option B**: Framework is MIT-licensed end-to-end. PAC plugin is ~5K-10K lines of new code; defect surface concentrated in the plugin. FreeIPA's plugin is the reference, but FreeIPA emits MS-PAC only for trust users; framework needs MS-PAC for all principals. License-permissive path is required for most commercial framework adoption.
  - **Option C**: Framework owns the entire KDC. Maximum architectural freedom (e.g., native HSM binding for krbtgt, native KCM protocol). Multi-year investment; defect risk on MS-KILE corner cases. Not viable for v1.
- **Problems gated by this ORQ**: PC-023 (blocker), PC-025 (high), PC-119 (high). Plus partial-ADR dependents: ADR-064 (Kerberoasting mitigation — PAC validation mechanism), ADR-065 (krbtgt HSM rotation — KDC integration), ADR-069 (cross-realm capaths — KDC implementation).
- **Research spike feeding this ORQ**: **Spike 3 — MIT krb5 + custom PAC plugin vs. Samba Heimdal fork** (3 weeks; implement MS-PAC generation in a MIT krb5 KDB plugin mirroring FreeIPA's `ipa_kdb_mspac.c`; validate byte-for-byte against AD-issued tickets; test PAC acceptance by IIS, SQL Server, Samba SMB server; compare defect surface, license implications, ongoing maintenance cost).
- **Pre-workshop reading**:
  - `adr/ADR-011-rc4-deprecation-aes-default.md` (etype negotiation — works on any KDC)
  - `adr/ADR-015-krbtgt-hsm-rotation.md` (HSM binding — implementation cost varies by KDC)
  - `adr/ADR-049-standardize-mit-krb5.md` (client-side MIT choice; KDC decision is orthogonal)
  - `adr/ADR-064-kerberoasting-aes-migration.md` (PARTIAL — PAC validation mechanism depends on KDC)
  - `docs/02-protocols/01-kerberos-internals.md` (MS-KILE profile, PAC buffer types)
  - `docs/02-protocols/08-spn-upn-pac.md` (PAC structure, `PAC_INFO_BUFFER` array)

### ORQ-072 / ORQ-074 / ORQ-075: NTLM decision (drop vs. maintain compat vs. maintain with hardening)
- **Theme**: NTLM support posture — eliminate the protocol entirely, keep it for compat, or keep it hardened.
- **Source**: `catalog/13-open-research-questions.md` lines 115, 117–118
- **Question**:
  - ORQ-072: Drop NTLM entirely (eliminates PtH)?
  - ORQ-074: Replace with OAuth2 client-credentials flow?
  - ORQ-075: Maintain S4U for AD interop?
- **Why it's Tier-1**: NTLM is a security liability (pass-the-hash, relay) but is required by ~5–10% of enterprise apps (pre-2018 SQL Server drivers, legacy IIS apps, old SMB appliances). The decision cascades into PC-036 (NTLM legacy interop), PC-038 (PtH defense / LSASS protection — fundamentally about NT hash storage), PC-039 (S4U2Self/S4U2Proxy constrained delegation), PC-094 (macOS has no native NTLM). If NTLM is dropped, PtH goes away; if maintained, the framework needs LSASS-equivalent protection (Credential Guard, VSM/TEE on Linux).
- **Candidate answers**:
  - **Option A — Drop NTLM entirely.** Eliminates pass-the-hash and relay attack classes. Breaks legacy apps (~5–10% of enterprise workloads per Spike 4 audit). Forces OAuth2/Kerberos migration for every app.
  - **Option B — Maintain NTLM with hard mitigations.** Channel binding (RFC 5929), EPA, signing, LSASS-equivalent protection on Linux (TEE / kernel keyring). Preserves compat. Complexity in the auth provider.
  - **Option C — Maintain NTLM via Samba winbind on a separate daemon.** Preserves compat, isolates risk (NTLM hashes never touch the framework's main auth path). Adds a Samba winbind dependency. Framework's main auth path is NTLM-free.
- **Implications of each candidate**:
  - **Option A**: PC-038 PtH disappears. PC-094 macOS NTLM gap irrelevant. ~5–10% of enterprise apps cannot migrate to the framework until rewritten. Migration timeline is gated on app modernisation, not on the framework.
  - **Option B**: PC-038 PtH defense requires LSASS-equivalent on Linux (TEE / kernel keyring / `keyctl`). PC-094 macOS NTLM needs Samba winbind on macOS (already required for SMB). PC-039 S4U2Self/S4U2Proxy preserved. NTLM hardening is complex (channel binding on every NTLM-using protocol).
  - **Option C**: PC-038 PtH defense applies only to the winbind daemon (isolated). PC-094 macOS NTLM via winbind on macOS (consistent with Linux). PC-039 S4U preserved in the framework's main auth path; NTLM-only flows handled by winbind. Framework main path is NTLM-free; documented deprecation timeline for winbind.
- **Problems gated by this ORQ**: PC-036 (high), PC-038 (blocker), PC-039 (high), PC-094 (high). Plus partial-ADR dependents: ADR-021 (LDAP signing — independent of NTLM decision, but channel-binding posture is affected).
- **Research spike feeding this ORQ**: **Spike 4 — NTLM compat surface audit** (2 weeks; catalog every NTLM-requiring app in 3–5 representative enterprise deployments; quantify the NTLM-requiring workload; assess each app's Kerberos migration path; determine whether Samba winbind as a sidecar (Option C) covers the realistic legacy surface).
- **Pre-workshop reading**:
  - `adr/ADR-021-ldap-signing-channel-binding.md` (channel binding is required regardless of NTLM decision)
  - `docs/02-protocols/04-ntlm-internals.md` (NTLM message flow, NT hash, session security)
  - `docs/09-linux-equivalents/04-winbind-internals.md` (winbind architecture, `winbindd` daemon)

### ORQ-110 / ORQ-111: PKI enrollment protocol (MS-WCCE vs. ACME vs. EST)
- **Theme**: Certificate enrollment protocol — Windows auto-enroll interop vs. modern ACME.
- **Source**: `catalog/13-open-research-questions.md` lines 159–160
- **Question**:
  - ORQ-110: Adopt ACME (RFC 8555) for new clients + MS-WCCE adapter for Windows?
  - ORQ-111: Implement Dogtag-style REST API?
- **Why it's Tier-1**: PKI enrollment protocol determines whether Windows clients can auto-enroll (the dominant PKI automation pattern in enterprises) and whether the framework can interop with AD CS hierarchies. Cascades into PC-057 (AD CS replacement), PC-059 (autoenrollment), PC-064 (NDES/SCEP), PC-067 (NTAuthCertificates), PC-123 (supply chain — signing cert enrollment).
- **Candidate answers**:
  - **Option A — Implement MS-WCCE/MS-XCEP.** Full AD interop; Windows auto-enroll works out of the box. Complex (no open-source implementation; ~10K lines of DCE-RPC). The framework would be the first non-Microsoft MS-WCCE server.
  - **Option B — Adopt ACME (RFC 8555).** Modern, simple, RFC-standard. Requires a Windows-side adapter that translates AD-CS autoenroll-equivalent GPO to ACME account+order flows (Spike 5 deliverable). No NTAuthCertificates model (PC-067 redesigns to per-tenant trust store).
  - **Option C — Adopt EST (RFC 7030).** Simpler than MS-WCCE, less ecosystem support than ACME. Used in some IoT/industrial PKI deployments.
  - **Option D — Single enrollment endpoint speaking all three (MS-WCCE + ACME + EST).** Maximum compat, maximum engineering (~15K lines), maximum maintenance surface.
- **Implications of each candidate**:
  - **Option A**: Windows auto-enroll works as-is (no client-side adapter). PC-067 NTAuthCertificates preserved. PC-058 templates use `msPKI-*` schema. Framework is the first non-Microsoft MS-WCCE server — high defect risk.
  - **Option B**: Windows auto-enroll requires the Spike 5 adapter (translated GPO → ACME order flow). PC-067 redesigns to per-tenant trust store (modernisation win). PC-058 templates use a JSON-schema format (interop with AD CS via adapter). Linux/macOS use a native ACME client (certbot, step-cli).
  - **Option C**: EST is simpler than MS-WCCE; ecosystem support is thinner than ACME. Windows auto-enroll still requires an adapter. PC-067 redesigns as in Option B.
  - **Option D**: All clients get a native-protocol enrollment path. Engineering cost is the dominant factor; ongoing maintenance is 3× single-protocol.
- **Problems gated by this ORQ**: PC-027 (high — PKINIT depends on NTAuthCertificates and Enterprise CA, which depend on enrollment protocol), PC-057 (blocker), PC-058 (high), PC-059 (high), PC-064 (medium), PC-067 (high).
- **Research spike feeding this ORQ**: **Spike 5 — ACME + Windows autoenroll adapter** (2 weeks; build a Windows-side adapter that translates AD-CS autoenroll-equivalent GPO to ACME account+order flows; validate that Windows 10/11 clients can auto-enroll from an ACME server (Step-CA or smallstep) without manual intervention; compare to MS-WCCE implementation effort).
- **Pre-workshop reading**:
  - `adr/ADR-032-hsm-bound-kra-shamir.md` (KRA — independent of enrollment protocol)
  - `adr/ADR-033-ocsp-responder-rfc-6960-nonce-ha.md` (OCSP — independent)
  - `adr/ADR-035-multi-cdp-ocsp-cluster-crl-fallback.md` (CRL distribution — independent)
  - `adr/ADR-036-trust-manager-cross-cert-interop.md` (trust model — depends on PC-067 resolution)
  - `adr/ADR-037-two-tier-ca-hsm-root.md` (CA topology — independent of enrollment protocol)
  - `docs/05-pki-certs/01-ad-cs-architecture.md` (MS-WCCE/MS-XCEP, autoenroll.dll CSE)
  - `docs/05-pki-certs/02-certificate-templates.md` (`msPKI-*` schema)
  - `docs/05-pki-certs/03-autoenrollment.md` (autoenroll flow on Windows)

### ORQ-132 / ORQ-133 / ORQ-134: Federation layer (re-implement AD FS vs. wrap modern IdP vs. cloud-first)
- **Theme**: Federation server — full AD FS wire-compat vs. wrap Keycloak vs. recommend cloud IdP.
- **Source**: `catalog/13-open-research-questions.md` lines 184–186
- **Question**:
  - ORQ-132: Adopt Keycloak as the federation layer?
  - ORQ-133: Build native?
  - ORQ-134: Cloud-first (Entra ID)?
- **Why it's Tier-1**: Federation is the framework's web/HTTP identity surface. The choice determines operational weight, IdP feature set, and migration path for the 10-federation-problem block (PC-068 through PC-077). Cascades into PC-069 (claims-policy language — Rego vs. Cedar vs. plugins, depends on IdP choice), PC-073 (WAP replacement — oauth2-proxy vs. Envoy+ext-authz), PC-074 (farm topology), PC-076 (external IdP federation / identity brokering).
- **Candidate answers**:
  - **Option A — Re-implement AD FS.** Full wire-compat for legacy relying parties (SharePoint on-prem 2013/2016/2019, Office desktop WS-Trust, custom WIF apps). Multi-year effort. Fragile (AD FS has 20+ years of quirks). Required only for orgs that cannot migrate legacy RPs.
  - **Option B — Wrap Keycloak.** Apache-licensed, mature, lighter than AD FS. Requires SAML/OIDC config translation (AD FS relying-party XML → Keycloak JSON). Built-in identity brokering (PC-076 solved natively). WS-Trust-to-OIDC bridge per ADR-039 (partial).
  - **Option C — Wrap Authentik / Ory / Zitadel.** Cloud-native, smaller ecosystem than Keycloak. Lighter operationally; thinner enterprise feature set.
  - **Option D — Cloud-first.** Recommend Entra ID for orgs that want cloud. Framework does not provide a federation server; integrates with Entra ID via OIDC.
- **Implications of each candidate**:
  - **Option A**: PC-068 AD FS replacement is wire-compatible; legacy RPs work without migration. PC-069 claims language is AD FS CRL (proprietary). PC-073 WAP must be re-implemented (AD FS WAP is Windows-only). PC-074 farm topology is AD FS WID/SQL. Multi-year engineering.
  - **Option B**: PC-068 AD FS replaced by Keycloak; legacy RPs migrate via ADR-039's WS-Trust-to-OIDC bridge. PC-069 claims language is Keycloak's native map/reducer or Rego plugin. PC-073 WAP replaced by oauth2-proxy or Envoy+ext-authz. PC-074 topology is Keycloak's Infinispan cluster. PC-076 brokering is Keycloak-native.
  - **Option C**: Same as Option B but with a different IdP. Smaller ecosystem = fewer reference deployments; higher risk for v1.
  - **Option D**: PC-068–077 all defer to the cloud IdP. Framework has no federation surface; loses customers who want on-prem.
- **Problems gated by this ORQ**: PC-068 (high), PC-069 (high), PC-073 (medium), PC-074 (medium), PC-076 (medium). Plus partial-ADR dependent: ADR-041 (strict OIDC — depends on federation layer).
- **Research spike feeding this ORQ**: **Spike 6 — Keycloak as AD FS replacement** (2 weeks; configure Keycloak for SAML 2.0, OIDC, and WS-Federation endpoints; translate an AD FS relying-party configuration (claims rules, RP trust) to Keycloak; test with 3–5 representative SaaS apps (Salesforce, ServiceNow, Workday); identify the WS-Trust-to-OIDC bridge requirement and AD FS-specific quirks like `resource=` parameter and Application Groups).
- **Pre-workshop reading**:
  - `adr/ADR-038-jwks-endpoint-webhook-rollover.md` (JWKS — IdP-independent)
  - `adr/ADR-039-oidc-primary-wstrust-bridge.md` (WS-Trust bridge — assumes Keycloak-class IdP)
  - `adr/ADR-040-saml-replay-clock-skew-policy.md` (SAML replay — IdP-independent)
  - `adr/ADR-041-strict-oidc-default-resource-compat.md` (PARTIAL — defers `resource=` to ORQ-132)
  - `docs/06-federation-sso/01-adfs-architecture.md` (AD FS internals, WID/SQL, WAP)
  - `docs/06-federation-sso/02-saml-ws-fed.md` (WS-Federation passive, `wa=wsignin1.0`)
  - `docs/06-federation-sso/03-claims-rules.md` (AD FS CRL, claim pass-through, transformation)

### ORQ-154 / ORQ-155: SMB server (Samba vs. fresh vs. platform-native)
- **Theme**: SMB server implementation — GPLv3 Samba vs. greenfield vs. per-platform native.
- **Source**: `catalog/13-open-research-questions.md` lines 209–210
- **Question**:
  - ORQ-154: Adopt Samba's `smbd` (GPL)?
  - ORQ-155: Write fresh SMB server?
- **Why it's Tier-1**: SMB is the most dangerous protocol surface (3 blockers in File Gateway: PC-078, PC-079, PC-083). The server choice determines security posture (SMB 3.1.1 pre-auth integrity), CA-share support (PC-081 — persistent handles, cluster quorum), PrintNightmare defense (PC-083 — ADR-046 drops MS-RPRN), and operational model (CTDB-style clustered Samba vs. custom cluster layer). License risk is the dominant commercial concern.
- **Candidate answers**:
  - **Option A — Adopt Samba's `smbd`.** GPLv3 (license risk). Mature, wire-interoperable with Windows back to SMB 2.0.2. Cluster story is CTDB (Samba's cluster layer). Inherits Samba's CVE history.
  - **Option B — Fresh SMB server implementation.** Full control over security posture and cluster design. Multi-year effort. High defect risk on SMB 3.1.1 pre-auth integrity (AES-GCM, dialect negotiation, encryption negotiation). License-clean.
  - **Option C — Reuse macOS SMBX kernel ext.** macOS-only; doesn't help Linux/Windows. Rejected for cross-platform parity.
  - **Option D — Wrap platform-native (Samba on Linux, SMBX on macOS, srv2.sys on Windows).** Windows cannot host framework DCs if the framework's DC runs Linux; this option fragments the deployment story.
- **Implications of each candidate**:
  - **Option A**: PC-078 SMB 3.1.1 supported (Samba 4.5+). PC-079 SMB1 drop is a Samba config (`server min protocol = SMB2_02`, already covered by ADR-043). PC-081 CA shares via CTDB. PC-083 PrintNightmare via ADR-046 (IPP Everywhere, drop MS-RPRN). GPLv3 — commercial adoption requires license strategy.
  - **Option B**: PC-078 SMB 3.1.1 implemented from scratch (high defect risk on pre-auth integrity corner cases). PC-079 SMB1 drop is trivial. PC-081 CA shares require a custom cluster layer (the framework would build its own CTDB equivalent). PC-083 same as Option A. License-clean. Multi-year.
  - **Option C**: macOS-only — rejected.
  - **Option D**: Fragmented. The framework's deployment story becomes per-platform; cross-platform parity fails.
- **Problems gated by this ORQ**: PC-078 (blocker), PC-081 (high), PC-130 (medium). Plus partial-ADR dependents: ADR-043 (SMB1 drop — independent of server choice), ADR-045 (ABE — pre-computed index works on any server), ADR-046 (IPP Everywhere — independent), ADR-047 (Offline Files — independent).
- **Research spike feeding this ORQ**: None of the 7 spikes targets SMB directly. The workshop resolves this ORQ from existing Samba experience + the partial ADRs already written (ADR-043/044/045/046/047) + the File Gateway catalog analysis. Recommendation in draft/04: Samba for v1 (license risk accepted or negotiated), with a fresh-implementation research track for v2.
- **Pre-workshop reading**:
  - `adr/ADR-043-drop-smb1-support.md` (SMB1 drop — works on any server)
  - `adr/ADR-044-dfs-n-via-dns-srv.md` (PARTIAL — DFS-R deferred to ORQ-001/002)
  - `adr/ADR-045-abe-precomputed-index.md` (PARTIAL — ABE index server-agnostic)
  - `adr/ADR-046-drop-msrprn-adopt-ipp-everywhere.md` (drop MS-RPRN — independent)
  - `docs/07-file-print/01-smb-shares-internals.md` (`srv.sys`, SMB 3.1.1 pre-auth integrity)
  - `docs/02-protocols/03-smb-cifs-protocol.md` (dialect history, encryption negotiation)

### ORQ-169 / ORQ-170 / ORQ-175 / ORQ-176: Client SDK architecture (gRPC vs. Rust core vs. per-platform wrappers)
- **Theme**: Client SDK unification — single cross-platform API vs. per-platform wrappers around existing libraries.
- **Source**: `catalog/13-open-research-questions.md` lines 227–228, 233–234
- **Question**:
  - ORQ-169: Adopt gRPC-based SDK with platform-native auth adapters?
  - ORQ-170: Per-language bindings (Rust core)?
  - ORQ-175: Extend SSSD or write a new client?
  - ORQ-176: Adopt FreeIPA client as the base?
- **Why it's Tier-1**: The SDK is the developer-facing surface. The choice determines API consistency across languages, language coverage (Python/Go/Rust/Node/C#), maintenance cost, and the macOS/Linux parity story (PC-100, PC-085). Cascades into PC-085 (no universal SDK), PC-086 (PSSO adapter), PC-089 (ID mapping), PC-091 (domain join), PC-093 (ticket cache), PC-095 (unified policy authoring), PC-100 (macOS first-party SDK).
- **Candidate answers**:
  - **Option A — gRPC-based SDK with platform-native auth adapters.** Consistent API across languages (Python, Go, Rust, Node, C#). gRPC adds a runtime dependency on the client. Auth adapters handle platform-specific credential acquisition (Keychain on macOS, KCM on Linux, CredSSP on Windows).
  - **Option B — Rust core with per-language bindings (C FFI).** No gRPC dependency. Rust core wraps LDAP bind, Kerberos kinit, SMB mount. C FFI bindings for Python (PyO3), Go (cgo), Node (napi-rs), C# (P/Invoke). More binding work per language; lighter runtime.
  - **Option C — Per-platform wrappers around existing libraries.** SSSD on Linux, OpenDirectory on macOS, Wldap32/SSPI on Windows. Fastest to ship. Inherits each platform's quirks (SSSD's config-file-driven model, OpenDirectory's plist APIs, Wldap32's COM heritage). No API consistency across platforms.
  - **Option D — Adopt FreeIPA client as the base.** Linux only — doesn't help macOS/Windows. FreeIPA's `ipa` CLI is Python; the framework would wrap it.
- **Implications of each candidate**:
  - **Option A**: PC-085 solved via gRPC. PC-086 PSSO adapter is a platform-native auth adapter. PC-089 ID mapping is an SDK function. PC-091 domain join is an SDK function (REST/gRPC call to the directory). PC-093 ticket cache is a platform-native auth adapter. PC-095 unified authoring uses the SDK's typed API. PC-100 macOS first-party SDK is the gRPC client + Keychain adapter. Adds gRPC runtime dependency on every client — heavy for edge/embedded use cases.
  - **Option B**: Same as Option A but no gRPC runtime. PC-085 solved via Rust core. PC-086/089/091/093/095/100 same. Each language needs a binding (PyO3/cgo/napi-rs/P-Invoke). Binding maintenance is the dominant cost. Lighter runtime than Option A; suitable for edge/embedded.
  - **Option C**: PC-085 not solved (no universal API). PC-086 PSSO is macOS-only via OpenDirectory. PC-089 ID mapping is per-platform. PC-091 domain join is per-platform. PC-095 unified authoring is impossible (each platform's API is different). PC-100 macOS uses OpenDirectory. Fastest to ship v1; worst long-term.
  - **Option D**: Linux-only. PC-085 not solved. PC-086/100 not addressed. Rejected.
- **Problems gated by this ORQ**: PC-040 (high, also ORQ-202/203), PC-085 (blocker), PC-086 (high), PC-091 (medium), PC-095 (blocker, also ORQ-030/031), PC-100 (medium). Plus partial-ADR dependents: ADR-048 (PSSO migration), ADR-049 (MIT krb5), ADR-051 (KCM/API: cache), ADR-055 (dzdo migration), ADR-063 (unified CLI).
- **Research spike feeding this ORQ**: **Spike 7 — Rust core SDK with C FFI bindings** (3 weeks; build a minimal Rust core that wraps LDAP bind, Kerberos kinit, and SMB mount; expose via C FFI; build Python and Go bindings; measure API consistency vs. native SSSD/OpenDirectory/Wldap32 wrappers; identify the platform-native auth adapters needed — Keychain on macOS, KCM on Linux, CredSSP on Windows).
- **Pre-workshop reading**:
  - `adr/ADR-048-psso-macos-jamf-connect-migration.md` (PARTIAL — defers PSSO adapter to ORQ-169)
  - `adr/ADR-049-standardize-mit-krb5.md` (PARTIAL — defers SDK integration to ORQ-169)
  - `adr/ADR-050-authselect-standard-pam.md` (PARTIAL — defers to ORQ-202)
  - `adr/ADR-051-kcm-linux-api-macos-cache-abstraction.md` (PARTIAL — defers to ORQ-169)
  - `adr/ADR-055-legacy-agent-migration-dzdo-sudoers.md` (PARTIAL — defers to ORQ-169)
  - `adr/ADR-063-unified-cross-platform-cli.md` (PARTIAL — defers implementation language to ORQ-169/231/232)
  - `docs/08-macos-equivalents/05-kerberos-sso-extension.md` (PSSO Extension API surface)
  - `docs/09-linux-equivalents/01-sssd-ad-provider.md` (SSSD architecture, `krb5_child`)

### ORQ-202 / ORQ-203: Linux tier strategy (SSSD only vs. SSSD+Winbind vs. FreeIPA vs. native)
- **Theme**: Linux identity stack — adopt FreeIPA, extend SSSD, or build native.
- **Source**: `catalog/13-open-research-questions.md` lines 263–264
- **Question**:
  - ORQ-202: Adopt FreeIPA as the Linux tier?
  - ORQ-203: Build native IPA-equivalent in the framework?
- **Why it's Tier-1**: Linux identity is fragmented across three stacks (SSSD, Winbind, FreeIPA). The framework must pick one, build a fourth, or document out-of-scope. Cascades into PC-053 (SSSD GPO access control — HBAC vs. URA depends on tier), PC-088 (SSSD GPO gaps — depends on whether SSSD is extended or replaced), PC-099 (SSSD/Winbind/PBIS migration path), PC-101 (FreeIPA as a separate platform), PC-103 (OpenLDAP+MIT Kerberos roll-your-own), PC-121 (selective auth vs. HBAC).
- **Candidate answers**:
  - **Option A — SSSD only.** Modern default for AD-joined Linux. No NTLM (PC-094 requires winbind sidecar). No full GPO CSE (PC-088 — SSSD's `ad_gpo_access` covers only a subset of GPO settings). Lightest operational footprint.
  - **Option B — SSSD + Winbind.** SSSD for NSS/PAM; Winbind for SMB/NTLM. Operational complexity (two stacks to maintain). Required if NTLM is maintained (per ORQ-072 Option B/C).
  - **Option C — FreeIPA.** Full-featured (HBAC, sudo rules, cert automount, ID views). Separate platform with its own schema (FreeIPA's directory). AD cross-forest trust. Heavier operationally than SSSD-only.
  - **Option D — Build native IPA-equivalent in the framework.** Multi-year effort. Full control. The framework's directory becomes the Linux tier directly (no separate FreeIPA directory).
- **Implications of each candidate**:
  - **Option A**: PC-053 limited to SSSD's HBAC emulation (`ad_gpo_access`). PC-088 partial — SSSD's GPO coverage gaps remain. PC-099 migration from Winbind/PBIS to SSSD documented. PC-101 FreeIPA out of scope. PC-103 OpenLDAP+MIT documented as legacy. PC-121 selective auth via SSSD's `ad_gpo_filter_permit`.
  - **Option B**: PC-053 same as Option A. PC-088 same. PC-099 same. PC-101 same. PC-103 same. PC-121 same. NTLM coverage via Winbind (depends on ORQ-072 outcome).
  - **Option C**: PC-053 solved via FreeIPA HBAC (native). PC-088 solved via FreeIPA's full sudo/HBAC rules. PC-099 migration from SSSD-only to FreeIPA documented. PC-101 FreeIPA is the Linux tier. PC-103 documented as out-of-scope (FreeIPA replaces). PC-121 solved via FreeIPA HBAC. Adds FreeIPA as a separate directory; cross-forest trust required for AD-interop.
  - **Option D**: PC-053/088/099/101/103/121 all solved natively in the framework. Multi-year effort. The framework's directory becomes the Linux identity source directly (no SSSD/FreeIPA/Winbind).
- **Problems gated by this ORQ**: PC-040 (high, also ORQ-169/170/175/176), PC-053 (high), PC-088 (high), PC-099 (medium), PC-101 (medium), PC-103 (low), PC-121 (medium). Plus partial-ADR dependent: ADR-050 (authselect — depends on Linux tier).
- **Research spike feeding this ORQ**: None of the 7 spikes targets Linux tier directly. The workshop resolves this ORQ from the existing SSSD/FreeIPA knowledge in `docs/09-linux-equivalents/` + Spike 7 (Rust core SDK) readout (which informs whether the framework can build a native client). Recommendation in draft/04: adopt FreeIPA as the Linux tier for v1 (Option C), with a documented migration path from SSSD-only deployments; building native (Option D) is v2+ work.
- **Pre-workshop reading**:
  - `adr/ADR-050-authselect-standard-pam.md` (PARTIAL — defers to ORQ-202)
  - `docs/09-linux-equivalents/01-sssd-ad-provider.md` (SSSD architecture, `sssd-ad` provider)
  - `docs/09-linux-equivalents/04-winbind-internals.md` (winbind architecture, `winbindd`)
  - `docs/09-linux-equivalents/08-freeipa-trust.md` (FreeIPA AD trust, HBAC, ID views)
  - `docs/09-linux-equivalents/03-sssd-gpo-access.md` (SSSD's `ad_gpo_access` — HBAC emulation)

## The 61 deferred problems

Every deferred problem is gated by one or more of the 11 Tier-1 ORQs. Problems gated by multiple ORQs are resolved when *all* their gating ORQs are resolved. The "Gating ORQ" column uses the Tier-1 ORQ cluster label (e.g., "ORQ-001/002" means the replication cluster).

| PC | Title (short) | Capability | Severity | Gating ORQ |
|----|---------------|-----------|----------|------------|
| PC-001 | DRSUAPI replication protocol | Core Directory | blocker | ORQ-001/002 |
| PC-002 | USN/InvocationID/UTD-vector model | Core Directory | blocker | ORQ-003/004 |
| PC-005 | Global Catalog PAS replication | Core Directory | high | ORQ-001/002 |
| PC-007 | ESE/JET Blue storage engine | Core Directory | blocker | ORQ-011/012/013/014 |
| PC-009 | Tombstone lifetime and lingering objects | Core Directory | high | ORQ-001/002 |
| PC-010 | Cross-domain move | Core Directory | medium | ORQ-026/027 + ORQ-030/031 |
| PC-014 | FSMO roles single-master bottleneck | Core Directory | high | ORQ-001/002 |
| PC-015 | RID pool allocation bottleneck | Core Directory | high | ORQ-026/027 |
| PC-017 | LDAP schema vs typed schema | Core Directory | high | ORQ-030/031 |
| PC-019 | AD-integrated DNS zones | Core Directory | high | ORQ-001/002 |
| PC-021 | instanceType/systemFlags bitmasks | Core Directory | medium | ORQ-030/031 |
| PC-022 | Multi-tenancy not native to AD | Core Directory | high | ORQ-026/027 (tenancy cross-cut) |
| PC-023 | MS-KILE profile + PAC generation | KDC | blocker | ORQ-042/043/044 |
| PC-025 | PAC validation RPC roundtrip | KDC | high | ORQ-042/043/044 |
| PC-027 | PKINIT smart-card logon | KDC | high | ORQ-110/111 |
| PC-036 | NTLM legacy interop | Auth Provider | high | ORQ-072/074/075 |
| PC-038 | Pass-the-hash (LSASS / Credential Guard) | Auth Provider | blocker | ORQ-072/074/075 |
| PC-039 | S4U2Self + S4U2Proxy constrained delegation | Auth Provider | high | ORQ-072/074/075 |
| PC-040 | Windows Token vs Linux PAM stack | Auth Provider | high | ORQ-169/170/175/176 + ORQ-202/203 |
| PC-043 | GPC + GPT split fragile | Policy Engine | high | ORQ-001/002 (also GitOps theme) |
| PC-044 | LSDOU last-writer-wins | Policy Engine | medium | ORQ-001/002 |
| PC-045 | GPO Preferences XML no macOS/Linux equivalent | Policy Engine | blocker | ORQ-030/031 |
| PC-046 | ADMX schema Windows-specific | Policy Engine | high | ORQ-030/031 |
| PC-053 | SSSD GPO access control limited | Policy Engine | high | ORQ-202/203 |
| PC-055 | SYSVOL replication via DFS-R Windows-only | Policy Engine | blocker | ORQ-001/002 (also GitOps theme) |
| PC-057 | AD CS Windows-only (no MS-WCCE server) | Cert Service | blocker | ORQ-110/111 |
| PC-058 | Certificate templates (msPKI-*) complex | Cert Service | high | ORQ-110/111 |
| PC-059 | Autoenrollment Windows-only | Cert Service | high | ORQ-110/111 |
| PC-064 | NDES (SCEP) fragile + IIS dependency | Cert Service | medium | ORQ-110/111 |
| PC-067 | NTAuthCertificates canonical CA list | Cert Service | high | ORQ-110/111 |
| PC-068 | AD FS heavy (WID/SQL + WAP) | Federation Gateway | high | ORQ-132/133/134 |
| PC-069 | ADFS claims rule language proprietary | Federation Gateway | high | ORQ-132/133/134 |
| PC-073 | AD FS WAP Windows-only | Federation Gateway | medium | ORQ-132/133/134 |
| PC-074 | ADFS farm topology fragile | Federation Gateway | medium | ORQ-132/133/134 |
| PC-076 | External OIDC IdP federation | Federation Gateway | medium | ORQ-132/133/134 |
| PC-078 | SMB 3.1.1 with pre-auth integrity | File Gateway | blocker | ORQ-154/155 |
| PC-081 | Continuously Available (CA) shares | File Gateway | high | ORQ-154/155 |
| PC-085 | No universal AD client SDK | Client SDK | blocker | ORQ-169/170/175/176 |
| PC-086 | macOS PSSO Extension Apple-only | Client SDK | high | ORQ-169/170/175/176 |
| PC-088 | SSSD on Linux GPO gaps | Client SDK | high | ORQ-202/203 |
| PC-089 | ID mapping (SID ↔ POSIX UID/GID) | Client SDK | blocker | ORQ-026/027 |
| PC-091 | Domain join fragmented | Client SDK | medium | ORQ-169/170/175/176 |
| PC-094 | macOS no native NTLM | Cross-Platform Parity | high | ORQ-072/074/075 |
| PC-095 | No unified policy authoring | Cross-Platform Parity | blocker | ORQ-030/031 + ORQ-169/170/175/176 |
| PC-099 | SSSD/Winbind/PBIS migration painful | Cross-Platform Parity | medium | ORQ-202/203 |
| PC-100 | macOS OpenDirectory AD plug-in gaps | Cross-Platform Parity | medium | ORQ-169/170/175/176 |
| PC-101 | FreeIPA separate Linux identity platform | Cross-Platform Parity | medium | ORQ-202/203 |
| PC-102 | RODC no Linux/macOS equivalent | Cross-Platform Parity | medium | ORQ-001/002 + ORQ-026/027 |
| PC-103 | OpenLDAP + MIT Kerberos roll-your-own | Cross-Platform Parity | low | ORQ-202/203 |
| PC-107 | Schema upgrades irreversible | Operations | high | ORQ-030/031 |
| PC-108 | Multi-region AD replication latency | Operations | high | ORQ-001/002 |
| PC-113 | Functional level upgrades one-way | Operations | medium | ORQ-030/031 |
| PC-117 | DCSync | Security | blocker | ORQ-001/002 |
| PC-119 | Silver ticket (service-account hash) | Security | high | ORQ-042/043/044 |
| PC-120 | SIDHistory abuse | Security | high | ORQ-026/027 |
| PC-121 | Selective authentication rarely used | Security | medium | ORQ-202/203 |
| PC-124 | sIDHistory migration | Migration | high | ORQ-026/027 |
| PC-125 | GPO translation manual | Migration | high | ORQ-030/031 |
| PC-126 | Client switchover parallel-run | Migration | high | ORQ-026/027 + ORQ-001/002 |
| PC-127 | Password hash migration | Migration | high | ORQ-026/027 |
| PC-130 | SYSVOL migration | Migration | medium | ORQ-154/155 |

**Gating-ORQ summary**: ORQ-001/002/003/004 (replication) gates 13 problems (3 blockers, 7 high, 3 medium); ORQ-011/012/013/014 (storage) gates 1 (blocker) plus 6 partial-ADR dependents; ORQ-026/027 (identity) gates 9 (1 blocker, 6 high, 2 medium); ORQ-030/031 (schema) gates 9 (1 blocker, 5 high, 3 medium); ORQ-042/043/044 (KDC) gates 3 (1 blocker, 2 high); ORQ-072/074/075 (NTLM) gates 4 (1 blocker, 3 high); ORQ-110/111 (PKI) gates 6 (1 blocker, 4 high, 1 medium); ORQ-132/133/134 (federation) gates 5 (5 high/medium); ORQ-154/155 (SMB) gates 3 (1 blocker, 1 high, 1 medium); ORQ-169/170/175/176 (Client SDK) gates 6 (1 blocker, 2 high, 3 medium); ORQ-202/203 (Linux tier) gates 7 (4 high, 3 medium). Several problems are gated by 2 ORQs and are counted in both clusters.

## Workshop agenda (2-day)

The 2-day workshop runs 09:00–17:30 each day with breaks (15 min morning, 1 h lunch, 15 min afternoon). Each ORQ slot produces a Decision, Rationale, Trade-offs accepted, Follow-up ADR list, and Implementation impact (per §Workshop output). The scribe records outputs to `DECISIONS.md` in real time.

### Day 1 — Research spike readouts + replication / storage / identity / schema

The four foundational architectural questions: how data is replicated, where it is stored, how principals are identified, and how the schema is shaped. These four decisions determine the framework's substrate; every other Tier-1 ORQ references one or more of them.

- **09:00–10:30 — Spike 1 readout (DRSUAPI replication interop vs. CRDT-shim)**. Spike owner presents 1M-object benchmark results: pure-DRSUAPI vs. CRDT-shim replication latency, throughput, AD-interop correctness. Q&A on UTD vector preservation, lingering-object detection, GPLv3 license posture.
- **10:45–12:00 — ORQ-001/002/003/004 decision (replication protocol)**. Workshop evaluates Options A/B/C against the 7 decision criteria. The replication choice cascades into 13 deferred problems and 5 partial ADRs — high-leverage slot.
- **13:00–14:30 — Spike 2 readout (storage engine evaluation: FoundationDB vs. RocksDB vs. SQLite)**. Spike owner presents LDAP read/write throughput at 1M/10M/100M objects, backup/restore time, replication log throughput, multi-attribute transactional semantics.
- **14:45–16:00 — ORQ-011/012/013/014 decision (storage engine)**. Workshop evaluates Options A/B/C/D. Affects 1 deferred problem (PC-007, blocker) and 6 partial ADRs (backup/restore, container DCs, PITR, declarative RBAC, Sigstore).
- **16:15–17:30 — ORQ-026/027 + ORQ-030/031 decision (identity model + schema model)**. These two architectural design decisions have no spike feed — resolved by workshop reasoning. Identity model (SIDs-only / UUIDs-only / both) cascades into 9 problems (1 blocker). Schema model (LDAP dynamic / typed / hybrid) cascades into 9 problems (1 blocker). The two are coupled: hybrid schema (ORQ-030 Option C) is the natural fit for "both with mapping" identity (ORQ-026 Option C). Joint discussion recommended.

### Day 2 — KDC / NTLM / policy / PKI / federation / SMB / SDK / Linux tier

The seven protocol-tier architectural questions: each Tier-1 ORQ cluster corresponds to one protocol surface. Day 2 is denser because each cluster has a spike readout (where applicable) followed immediately by the decision.

- **09:00–10:00 — Spike 3 readout + ORQ-042/043/044 decision (KDC implementation)**. Spike owner presents MIT krb5 + custom PAC plugin byte-compat report vs. Samba Heimdal fork; license analysis. Workshop decides Option A/B/C. Affects 3 deferred problems (1 blocker) and 3 partial ADRs (Kerberoasting, krbtgt HSM, cross-realm capaths).
- **10:15–11:15 — Spike 4 readout + ORQ-072/074/075 decision (NTLM)**. Spike owner presents NTLM compat matrix from 3–5 enterprise deployments. Workshop decides Option A/B/C. Affects 4 deferred problems (1 blocker).
- **11:30–12:30 — ORQ-090/091 decision (policy format)**. Although Tier-2, ORQ-090/091 gates ADR-024 (per-platform executors) and feeds PC-045/046/053/095. Workshop evaluates YAML/CRDT/Rego/DSL options. This is the only Tier-2 ORQ on the agenda because it is on the critical path of 4 deferred problems (3 blockers/high).
- **13:30–14:30 — Spike 5 readout + ORQ-110/111 decision (PKI enrollment)**. Spike owner presents ACME + Windows autoenroll adapter prototype. Workshop decides Option A/B/C/D. Affects 6 deferred problems (1 blocker) — the largest single-ORQ block on Day 2.
- **14:45–15:45 — Spike 6 readout + ORQ-132/133/134 decision (federation layer)**. Spike owner presents Keycloak-as-AD-FS-replacement migration playbook (Salesforce, ServiceNow, Workday test). Workshop decides Option A/B/C/D. Affects 5 deferred problems and 1 partial ADR (strict OIDC `resource=`).
- **16:00–16:30 — ORQ-154/155 decision (SMB server)**. No spike — resolved from existing Samba experience + partial ADRs already written. Workshop decides Option A/B/C/D. Affects 3 deferred problems (1 blocker) and 4 partial ADRs.
- **16:30–17:00 — Spike 7 readout + ORQ-169/170/175/176 decision (Client SDK architecture)**. Spike owner presents Rust core SDK prototype with Python/Go bindings. Workshop decides Option A/B/C/D. Affects 6 deferred problems (1 blocker) and 5 partial ADRs (PSSO, MIT krb5, KCM, dzdo, unified CLI).
- **17:00–17:30 — ORQ-202/203 decision (Linux tier strategy) + wrap-up**. No spike — resolved from existing SSSD/FreeIPA knowledge + Spike 7 readout (which informs whether native is viable). Workshop decides Option A/B/C/D. Affects 7 deferred problems. Wrap-up: confirm all 11 Tier-1 ORQs have decisions recorded; assign follow-up ADR owners; schedule Day-3 (if any ORQ is unresolved).

## Decision criteria

For each ORQ, the workshop must score every candidate answer against these 7 criteria. Scoring is 1–5 per criterion (1 = poor, 5 = excellent); the workshop may weight criteria differently per ORQ (e.g., AD-interop is weighting-3 for replication, weighting-1 for storage engine). The scribe records the score matrix per ORQ in `DECISIONS.md`.

1. **AD-interop** — Does the candidate preserve wire-level interop with existing AD deployments? Will existing AD DCs, clients, and tools (ADUC, `Get-ADUser`, impacket, `samba-tool`) work against the framework without modification? Will the framework interop with AD in mixed-forest / cross-trust / parallel-run scenarios?
2. **Cross-platform parity** — Does the candidate work equivalently on Windows, macOS, and Linux? Will the same API produce the same behaviour on every platform? Are platform-specific deviations documented and tested?
3. **Scalability** — Does the candidate scale to 10M objects, 100 DCs, 1M clients? What is the throughput ceiling (writes/sec, reads/sec, replication lag)? What is the failure mode at the ceiling?
4. **Security** — Does the candidate meet modern security baselines? No RC4, no NTLM relay, no MD5 MAC, no pre-2014 crypto. LSASS-equivalent protection on Linux. HSM binding for high-value keys (krbtgt, CA private keys, framework signing keys). STRIDE-classified threat model for the candidate.
5. **Operability** — Does the candidate support modern operations? Containerization (Kubernetes operator), GitOps (Git-backed config), observability (OpenTelemetry, Prometheus), backup/restore (PITR), disaster-recovery runbooks.
6. **Implementation cost** — What is the person-week estimate for v1? For v2? What is the defect risk (high / medium / low)? What is the maintenance burden (annual person-weeks)?
7. **Migration feasibility** — Can existing AD customers migrate to this candidate? What is the migration path (parallel-run, batch-import, swing-migration)? What is the rollback path? What is the operator skill gap (Windows admin → Linux admin, ADUC → CLI, etc.)?

## Pre-workshop deliverables

Each research spike owner must produce a 5–10 page readout covering:

- **Hypothesis** — what the spike set out to validate (1 paragraph).
- **Methodology** — what was built, what was measured, what was compared (1 page).
- **Findings** — benchmark results, compatibility matrix, defect counts, license analysis (3–5 pages). All quantitative claims must cite the measurement methodology and confidence interval.
- **Recommendation** — which candidate the spike owner recommends, with confidence level (high / medium / low) and the reasoning chain (1 page).
- **Open questions for the workshop** — issues the spike could not resolve, decisions that depend on cross-ORQ coupling (e.g., "Spike 1's recommendation assumes ORQ-026/027 chooses 'both with mapping' for the UTD vector to be expressible as a CRDT tombstone vector") (1 page).

Spike readouts are due 48 hours before the workshop (i.e., end of Day −2) to give workshop participants time to read. The workshop does not re-litigate spike findings; it uses them as input to the decision.

## Workshop output

For each ORQ, the workshop produces a 1-page decision record (the scribe writes these to `/home/z/my-project/adrian/workshop/DECISIONS.md` in real time):

1. **Decision** — the chosen candidate (Option A/B/C/D), stated unambiguously in a single sentence.
2. **Rationale** — why this candidate was chosen, citing the spike readout (where applicable) and the score matrix from §Decision criteria. 2–4 paragraphs.
3. **Trade-offs accepted** — what the framework is giving up by choosing this candidate. Explicitly named (e.g., "GPLv3 license risk for Samba smbd", "NTLM compat surface maintained for v1"). 1 paragraph.
4. **Follow-up ADRs** — list of deferred problems (by PC-NNN) that can now have ADRs written, plus the partial ADRs that can now be promoted from PARTIAL to full. Each PC-NNN is annotated with the owner and target date for the follow-up ADR.
5. **Implementation impact** — which capabilities/modules are affected, with person-week estimates per capability. This feeds the Phase 1 (architecture decisions) and Phase 2 (MVP) roadmap in `draft/06-roadmap.md`.

The decision records are the workshop's single deliverable. They supersede any prior recommendations in `draft/04-open-research-questions.md` and become the authoritative input to Phase 1 of the roadmap. The 11 decision records collectively unlock ~61 follow-up ADRs and lock the framework's foundational architecture.

## Reference materials

- [`TRIAGE.md`](../adr/TRIAGE.md) — full triage with PC → ORQ mapping; the source of truth for which problems are ADR-eligible, PARTIAL, or DEFERRED.
- [`ADR README`](../adr/README.md) — master ADR index; the per-capability ADR tables and the partial-ADR table (35 PARTIAL ADRs whose "Open Questions" section cites the gating ORQ by ID).
- [`Catalog ORQs`](../catalog/13-open-research-questions.md) — all 262 ORQs grouped by capability, with Tier-1/Tier-2/Tier-3 prioritisation and 12 cross-cutting themes.
- [`Draft ORQ synthesis`](../draft/04-open-research-questions.md) — distilled view of the 11 Tier-1 architectural questions with candidates, cascades, and recommendations per question; the 7 research spike plan.
- [`Draft roadmap`](../draft/06-roadmap.md) — Phase 0 (research spikes, 4–5 weeks) and Phase 1 (architecture decisions, post-workshop) context; the workshop is the boundary between Phase 0 and Phase 1.
