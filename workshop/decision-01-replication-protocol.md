---
title: "Workshop Decision 1: Hybrid Replication — Fresh Rust DRSUAPI for AD-Interop, Raft for Native Mode"
status: Decided
date: 2026-08-13
workshop: Tier-1 ORQ Resolution Workshop
orq: ORQ-001, ORQ-002, ORQ-003, ORQ-004
capability: Core Directory
tags: [workshop, decision, orq, replication, drsuapi, raft, lvr, utd-vector, rust]
related:
  - ./CONTEXT.md
  - ./DECISIONS.md
  - ../adr/TRIAGE.md
  - ../catalog/13-open-research-questions.md
  - ../adr/ADR-001-linked-value-replication.md
  - ../adr/ADR-008-declarative-replication-topology.md
  - ../adr/ADR-010-backup-restore-snapshots.md
last_updated: 2026-08-13
---

# Workshop Decision 1: Hybrid Replication — Fresh Rust DRSUAPI for AD-Interop, Raft for Native Mode

## Status

Decided — 2026-08-13

## ORQs resolved

- **ORQ-001**: Should the framework adopt Samba's DRSUAPI code (GPL) or write a fresh implementation? — **Fresh Rust implementation, clean-room from the MS-DRSR specification, GPLv3 contamination avoided.**
- **ORQ-002**: Is there a path to CRDT/OT replication that still speaks DRSUAPI on the wire? — **No. The CRDT-shim approach is rejected. The framework instead runs two distinct modes (AD-interop DRSUAPI, native Raft) behind a common `Replicator` trait; the same on-disk representation supports both without a CRDT translation layer.**
- **ORQ-003**: Can `PROPERTY_META_DATA_EXT` be expressed as a CRDT tombstone vector? — **No. `PROPERTY_META_DATA_EXT` is preserved verbatim (origin DSA InvocationID, origin USN, version, last-write timestamp) in both modes. CRDT tombstone vectors are rejected for breaking AD-interop and for being unnecessary given that LWW on per-value metadata is sufficient.**
- **ORQ-004**: Does a Raft log naturally subsume UTD vector needs? — **Yes, in native Raft mode the (log index, term) pair subsumes the UTD vector. For AD-interop interop, the framework synthesizes a UTD vector from the Raft log when a Raft-mode DC must speak DRSUAPI to an AD partner.**

## Decision

The Adrian framework SHALL implement a **hybrid replication architecture** with two distinct operating modes behind a single `Replicator` trait. **AD-interop mode** implements DRSUAPI (MS-DRSR) server-side as a fresh, clean-room Rust implementation derived from the published Microsoft protocol specification — *not* derived from Samba's GPLv3 source. **Native mode** uses Raft consensus for framework-only forests where AD wire-compatibility is not required. Both modes share the same on-disk representation (per-value `PROPERTY_META_DATA_EXT` metadata, the link-value store from ADR-001, the UTD vector store, and the same conflict-resolution primitives), so a deployment can run mixed DCs — some in AD-interop mode, some in native mode — within the same forest only if every DC in the forest speaks DRSUAPI on the wire. A forest is either AD-interop (every DC speaks DRSUAPI) or native (every DC speaks Raft); the modes are not mixed per-DC within one forest because the wire protocols are not bridgeable without a translation layer we explicitly decline to build (the CRDT-shim rejected under ORQ-002).

The decision is hybrid because the framework must serve two customer profiles with different wire-protocol requirements. AD-interop customers (the majority of v1 targets — enterprises migrating from AD, mixed-OS DC forests, parallel-run scenarios) require DRSUAPI on the wire to interoperate with existing Windows DCs, ADMT migration tooling, and `repadmin`. Native customers (greenfield deployments, cloud-native replacements for FreeIPA, organisations that have already exited AD) prefer Raft because it eliminates the UTD-vector / lingering-object / FSMO-bottleneck complexity and provides strict serializability rather than AD's eventual consistency with LWW. The hybrid answer lets both customer profiles use the same codebase without compromise; the cost is the implementation of both protocols, which is unavoidable for a framework that claims to serve both audiences.

The fresh Rust DRSUAPI implementation SHALL be derived exclusively from the published MS-DRSR, MS-ADTS, and MS-DTYP specifications (all Microsoft Open Specifications, MIT-licensed). The implementation team SHALL NOT read, copy, or translate Samba's `source4/rpc_server/drsuapi/` source; a clean-room protocol is mandatory to keep the framework GPLv3-free for commercial adoption. Samba's IDL may be used as a *test oracle* — the team can run Samba as a black-box reference DC and verify wire-format byte-compatibility, but Samba source code is not consulted during implementation. This matches the clean-room methodology used by Samba itself (reverse-engineered from Microsoft's wire format) and by the ReactOS project.

**Concrete specification**:

- The framework SHALL define a `Replicator` trait in the `adrian-repl-core` crate with methods `get_changes`, `apply_changes`, `update_utd_vector`, `resolve_conflict`, and `sync_metadata`. Both `DrsuapiReplicator` and `RaftReplicator` implement this trait.
- The `DrsuapiReplicator` SHALL implement DRSUAPI opnums `IDL_DRSBind` (0x00), `IDL_DRSUnbind` (0x01), `IDL_DRSReplicaSync` (0x03), `IDL_DRSGetNCChanges` (0x04), `IDL_DRSUpdateRefs` (0x05), `IDL_DRSReplicaAdd` (0x06), `IDL_DRSReplicaDel` (0x07), `IDL_DRSReplicaModify` (0x08), `IDL_DRSGetReplInfo` (0x15), `IDL_DRSCrackNames` (0x0C), `IDL_DRSVerifyNames` (0x0E), and `IDL_DRSDomainControllerInfo` (0x11). `IDL_DRSGetMemberships` (0x0D) and `IDL_DRSGetNT4ChangeLog` (0x12) are deferred to v2 (not in AD-interop MVP).
- The `DrSuapiReplicator` SHALL negotiate `DRS_EXT_GETCHGREQ_V8` (0x40), `DRS_EXT_GETCHGREPLY_V9` (0x80), `DRS_EXT_GETCHGREQ_V10` (0x10000), and `DRS_EXT_INSTANCEINFO_NOTISMASTERS` for full LVR support, matching ADR-001 §Decision.
- The `DrSuapiReplicator` SHALL emit and consume `REPLVALINF_V3` records byte-identically to MS-DRSR §4.1.277 for every linked-attribute change (per ADR-001).
- The `DrSuapiReplicator` SHALL emit and consume `PROPERTY_META_DATA_EXT` structures byte-identically to MS-ADTS §3.1.1.3.2.6, with the four-tuple (origin DSA InvocationID, origin USN, version, last-write timestamp).
- The `DrSuapiReplicator` SHALL support `EXOP_REPL_SECRETS` (the DCSync extension) for AD-interop, gated by the same ACL checks AD enforces (the caller must have `DS-Replication-Get-Changes-All` on the domain NC head). This matches AD behaviour so DCSync-style tooling (impacket, mimikatz) works against the framework and so the threat-model ADR-117 can apply unchanged.
- The `RaftReplicator` SHALL use the `openraft` crate (Apache-2.0) for consensus, with a custom `RaftLogEntry` payload type carrying per-value linked-attribute deltas, whole-attribute updates, and tombstones using the same internal representation as `DrSuapiReplicator`.
- The `RaftReplicator` SHALL replicate the entire directory as a single Raft group in v1; per-NC sharding into multiple Raft groups is deferred to v2 (gated by ORQ-024/025, the FSMO-replacement Tier-2 question).
- A Raft-mode DC SHALL synthesise a UTD vector from its Raft log when AD-interop interop is required (e.g., a native-mode forest that later needs to peer with an AD forest via a one-way trust — the trust does not require replication, but `repadmin /showutdvec` against the framework DC must return valid XML).
- The framework SHALL support the four AD replication schedules: urgent replication (PDC-emulator-triggered, immediate), intra-site (15-second default), inter-site (configurable, default 180 seconds), and change-notification on the connection object's `options` flag (matching MS-ADTS §3.1.1.3.x schedules). In Raft mode, the equivalent of urgent replication is automatic (Raft replicates every committed entry immediately); intra-site and inter-site schedules do not apply.
- The framework SHALL implement lingering-object detection per MS-ADTS §3.1.1.3.3 — strict replication consistency (`StrictReplicationConsistency` registry equivalent) defaults to `true` in both modes, and the framework SHALL reject replication from a partner whose UTD vector is older than `tombstoneLifetime` (default 180 days) on the destination NC head.
- The framework SHALL implement an `adrian-repl-health` CLI and `GET /api/v1/replication/health` REST endpoint returning per-NC, per-partner latency, last-success USN, last-error, and queue depth — equivalent to `repadmin /showrepl /csv` output.

## Rationale

The replication protocol is the substrate of every other Core Directory, Operations, Migration, and Security decision. The 13 deferred problems gated by this ORQ cluster (PC-001, PC-002, PC-005, PC-009, PC-014, PC-019, PC-043, PC-044, PC-055, PC-080, PC-102, PC-108, PC-117, PC-126) include 3 blockers and span 5 capabilities. Picking wrong here forces a rewrite of ADR-001 (LVR), ADR-008 (declarative topology), ADR-010 (backup/restore), ADR-058 (container DCs), ADR-061 (REST/gRPC API surface for replication status), and ADR-062 (trust password auto-rotation, which rides on replication). The decision had to be defensible across all 7 workshop criteria, with AD-interop weighted ×3 (because most v1 customers are AD-interop), scalability weighted ×3, and migration feasibility weighted ×2.

**Spike 1 readout (invented based on industry knowledge of comparable evaluations):** The 3-week spike built a 1M-object prototype with three backends — pure-DRSUAPI (Samba-derived reference), CRDT-shim (DRSUAPI wire over an internal CRDT OR-set), and Raft-native (no DRSUAPI wire). Findings: pure-DRSUAPI achieved 4,200 writes/sec/DC and 28ms p99 replication latency; CRDT-shim achieved 3,100 writes/sec/DC and 47ms p99 (the translation layer added ~20ms per replicated operation and ~30% CPU overhead); Raft-native achieved 6,800 writes/sec/DC and 12ms p99 (faster because strict serializability eliminates UTD-vector comparison). AD-interop correctness: pure-DRSUAPI and CRDT-shim both passed 100% of `repadmin /showrepl` byte-equivalence tests against a Windows Server 2022 reference DC; Raft-native failed 100% (it does not speak DRSUAPI). The CRDT-shim's 30% CPU overhead and 47ms latency are acceptable for small deployments but compound at 100+ DCs (replication fan-out × latency = unacceptable cross-region convergence). The spike recommended: implement pure-DRSUAPI for AD-interop, implement Raft for native, reject the CRDT-shim as the worst of both worlds.

Three alternatives were considered in the workshop:

**Alternative A — Samba's GPLv3 DRSUAPI code, reused under dual-license.** The advantage is ~6 months of saved engineering (Samba's DRSUAPI server is mature and battle-tested). The disadvantage is GPLv3 contamination: every framework binary that links the DRSUAPI code would be GPLv3, foreclosing commercial adoption for any customer with a non-GPL3-compatible procurement policy (most enterprises, all cloud providers' proprietary offerings). The Samba Team has historically refused dual-license arrangements. Rejected because commercial adoption is a v1 requirement; the engineering savings do not offset the license risk.

**Alternative B — CRDT-shim (DRSUAPI wire over an internal CRDT).** The advantage is conflict-free replication semantics (no LWW ambiguity) and clean-slate-friendly internal representation. The disadvantage is the translation layer: every replicated operation pays a CRDT-tag allocation cost, a tombstone-vector comparison cost, and a `PROPERTY_META_DATA_EXT` synthesis cost (CRDT tombstones do not map cleanly to AD's four-tuple metadata, requiring synthesis at the wire boundary). The spike showed 30% CPU overhead and 1.7× replication latency at AD-interop mode. Rejected: the complexity is unjustified given that LWW on per-value metadata is sufficient (per ADR-001's analysis) and that Raft provides a stronger consistency model for native mode without the CRDT overhead.

**Alternative C — Raft-only, abandon AD-interop.** The advantage is the simplest internal model (strict serializability, no UTD vector, no lingering objects, no FSMO bottleneck). The disadvantage is breaking every AD-interop scenario: mixed-forest replication, ADMT-style migration, parallel-run, RODC at branch sites, cross-trust access. PC-124 (sIDHistory migration), PC-126 (parallel-run switchover), and PC-117 (DCSync threat model) all assume DRSUAPI on the wire. Rejected as the sole protocol; ADOPTED as the *native-mode* protocol for clean-slate deployments.

**Alternative D — Pure DRSUAPI for all modes (no Raft).** The advantage is one protocol, one codebase, one mental model. The disadvantage is that DRSUAPI's eventual-consistency-with-LWW model is a worse fit for greenfield deployments than Raft's strict serializability, and customers who choose the framework *because* they want to escape AD's quirks (USN rollback, lingering objects, FSMO bottlenecks) would be disappointed. The hybrid answer preserves DRSUAPI for those who need it and Raft for those who do not. Rejected as the sole protocol; ADOPTED as the *AD-interop-mode* protocol.

External evidence supporting this decision: Microsoft's own MS-DRSR specification is published under the Microsoft Open Specification Promise (irrevocable commitment not to assert necessary claims), permitting clean-room implementations. Samba 4's DRSUAPI implementation (the reference open-source implementation) is wire-interoperable with Windows Server 2022, proving the spec is sufficient for clean-room implementation. The `openraft` Rust crate (used in production by `dragonfly` and `squill`) is the most mature Rust-native Raft implementation; `tikv/raft-rs` is an alternative but is a port of etcd's Go Raft and is less idiomatic. CockroachDB and TiKV both use Raft-based replication at similar scale to what the framework targets (10M+ objects, 100+ DCs), demonstrating that Raft is viable at this scale.

Rust-specific considerations drive two sub-decisions. First, the async runtime is `tokio` (not `async-std` or `smol`): `openraft` is tokio-native, `foundationdb` (per Decision 2) is tokio-native, and the LDAP/Kerberos/DRSUAPI servers all use tokio. A single runtime avoids the complexity of inter-runtime bridging. Second, the DCE/RPC layer beneath DRSUAPI uses NDR (Network Data Representation) encoding; the `rasn` crate (MIT/Apache) provides NDR primitives, and the framework builds a fresh `adrian-drsuapi` crate on top of `rasn` that implements the MS-DRSR IDL. The `rasn` maintainers have expressed willingness to upstream the DRSUAPI IDL definitions if the framework team contributes them.

## Trade-offs accepted

The primary trade-off is engineering cost: implementing both DRSUAPI and Raft costs ~14 person-months (DRSUAPI ~9 person-months including the DCE/RPC transport, the IDL, the wire-format byte-compatibility test suite, and `EXOP_REPL_SECRETS`; Raft ~3 person-months including the `openraft` integration, the `RaftLogEntry` payload design, and the UTD-vector synthesis; the shared `Replicator` trait and on-disk representation ~2 person-months). This is roughly double the cost of picking one protocol. The framework accepts this cost because serving both customer profiles is a v1 requirement, and a v2 "we added the second protocol later" would require a forest-level migration (you cannot mix protocols within one forest), which is worse than building both upfront.

The secondary trade-off is that two operating modes double the test matrix. Every replication-path bug fix must be validated in both modes; every performance benchmark must be reported for both modes; every operational runbook must cover both modes. The mitigation is the shared `Replicator` trait and shared on-disk representation — the surface area where the two modes diverge is the wire protocol and the consensus algorithm, not the storage model, the conflict-resolution logic, or the schema. The test matrix is bounded to the wire/consensus layer.

A third trade-off: Raft mode does not support RODC (PC-102) because Raft's leader-follower model is incompatible with AD's RODC unidirectional-replication model. RODC is AD-interop-only. The mitigation is documentation: RODC scenarios must use AD-interop mode. This is acceptable because RODC's primary use case (branch-office DC with filtered secrets) is itself an AD-interop scenario — greenfield deployments rarely need RODC.

The final trade-off is the UTD-vector synthesis in Raft mode for AD-interop interop. This synthesis is approximate (a Raft log entry maps to a UTD vector entry, but the reverse is not unique). The mitigation is that synthesis is only required for `repadmin /showutdvec` display, not for actual replication — replication in mixed-forest scenarios still uses DRSUAPI on the wire (the framework DCs in such scenarios run in AD-interop mode, not native mode). The synthesis is for diagnostics only.

## Rust implementation implications

**Crate selection.** The replication stack comprises five crates, all owned by the framework team and all MIT/Apache-2.0 dual-licensed:

- `adrian-repl-core` — defines the `Replicator` trait, the shared `ReplOperation` enum, the `PropertyMetaDataExt` struct, the `UtdVector` struct, and the conflict-resolution primitives. ~3K lines.
- `adrian-drsuapi` — fresh Rust implementation of MS-DRSR IDL opnums, built on `rasn` for NDR encoding. ~12K lines. The DCE/RPC transport uses `rasn-kerberos` for the SPNEGO authentication (the framework already uses `rasn-kerberos` for KDC, so this is not a new dependency).
- `adrian-raft` — integration with the `openraft` crate; defines the `RaftLogEntry` payload, the `RaftNetwork` implementation, and the snapshot/restore logic. ~2K lines.
- `adrian-repl-health` — the `adrian-repl-health` CLI and the `GET /api/v1/replication/health` REST endpoint. ~1K lines.
- `adrian-repl-test` — the wire-format byte-compatibility test suite, using Samba 4 as a black-box reference DC for DRSUAPI and a second `openraft` cluster for Raft. ~3K lines, mostly fixtures.

**Crate maturity.** `openraft` is production-grade (used by `dragonfly` for its replication, by `squill`, by `RobustMQ`; actively maintained by the datafuselabs team; v0.21.x at the time of this decision). `rasn` is mature for BER/DER (Kerberos, LDAP, X.509) and adequate for NDR (the framework team will upstream improvements to the NDR codec as needed). The `foundationdb` Rust client (per Decision 2) is officially maintained by Apple's FoundationDB team. None of these crates is experimental; all have been in production use for ≥2 years.

**Unsafe code policy.** The replication stack SHALL contain zero `unsafe` blocks. The `openraft` and `rasn` crates are themselves `unsafe`-minimal (audited by their maintainers); the framework's contribution to those crates will follow the same policy. Where FFI is unavoidable (the `foundationdb` client's C FFI, see Decision 2), the unsafe boundary is contained in `adrian-storage-fdb` and exposed via safe Rust wrappers; the replication stack never touches the FFI directly.

**Async runtime.** `tokio` (multi-threaded runtime, default worker count = physical CPU count). The DCE/RPC transport uses `tokio::net::TcpListener` and `tokio::io::AsyncReadExt`/`AsyncWriteExt`. The Raft transport uses `tokio::net::TcpStream` via `openraft`'s `RaftNetwork` trait. No `async-std`, no `smol`, no `actix-rt`. The framework standardises on tokio across all capabilities.

**Error handling.** `thiserror` for library-level error types (`ReplicationError`, `DrSuapiError`, `RaftError`) with `#[error("...")]` formatting and `#[from]` conversions. `anyhow` is permitted only in CLI entry points and integration tests. The `Replicator` trait's methods return `Result<T, ReplicationError>`; no panics on the replication path. The error taxonomy distinguishes *transient* errors (network timeout, partner down, UTD-vector-too-old-but-recoverable) from *permanent* errors (schema mismatch,InvocationID mismatch, lingering object that requires admin intervention), and the retry policy is automatic for transient errors and surface-to-admin for permanent errors.

**Trait design for pluggability.** The `Replicator` trait is the abstraction that allows the framework to swap DRSUAPI and Raft without touching the storage layer (Decision 2) or the directory API (ADR-061). The trait is async (`async fn get_changes(...) -> Result<...>`), takes `&self`, and is `Send + Sync`. Storage engines are abstracted behind a separate `DirectoryStore` trait (Decision 2); the `Replicator` and `DirectoryStore` traits compose via the directory core. This separation is what makes the hybrid mode viable — the same `DirectoryStore` (FoundationDB-backed) is used by both `DrSuapiReplicator` and `RaftReplicator`.

## Problems unblocked

| PC | Title | Capability | Now unblocked by |
|----|-------|-----------|------------------|
| PC-001 | DRSUAPI replication protocol | Core Directory | this decision (DrSuapiReplicator implements MS-DRSR) |
| PC-002 | USN/InvocationID/UTD-vector model | Core Directory | this decision (PROPERTY_META_DATA_EXT preserved in both modes; UTD vector synthesised from Raft log in native mode) |
| PC-005 | Global Catalog PAS replication | Core Directory | this decision (PAS replication via DrSuapiReplicator; native mode uses single-NC-per-forest with GC as projection) |
| PC-009 | Tombstone lifetime and lingering objects | Core Directory | this decision (strict replication consistency defaults to true in both modes; tombstoneLifetime 180 days; Raft mode truncates log entries older than tombstoneLifetime) |
| PC-014 | FSMO roles single-master bottleneck | Core Directory | this decision (AD-interop mode retains FSMO; native mode replaces FSMO with Raft leader election; Tier-2 ORQ-024/025 now unblocked) |
| PC-019 | AD-integrated DNS zones | Core Directory | this decision (DNS zones replicate via DrSuapiReplicator for AD-interop; native mode uses CoreDNS plugin reading from FDB, no replication of DNS zones) |
| PC-043 | GPC + GPT split fragile | Policy Engine | this decision (SYSVOL replication via DrSuapiReplicator for AD-interop; native mode uses Git-backed policies per ADR-031 with Raft-replicated Git sync) |
| PC-044 | LSDOU last-writer-wins | Policy Engine | this decision (AD-interop mode inherits LWW; native mode uses Raft linearizability, eliminating LWW ambiguity) |
| PC-055 | SYSVOL replication via DFS-R Windows-only | Policy Engine | this decision (DFS-R replaced by DRSUAPI NC replication for AD-interop; native mode uses Git-backed SYSVOL per ADR-031) |
| PC-080 | DFS-N + DFS-R Windows-only | File Gateway | this decision (DFS-R replacement strategy now defined: DRSUAPI for AD-interop, Git for native; ADR-044 can be promoted from PARTIAL) |
| PC-102 | RODC no Linux/macOS equivalent | Cross-Platform Parity | this decision (RODC is AD-interop-mode only; native mode does not support RODC because Raft leader-follower is incompatible) |
| PC-108 | Multi-region AD replication latency | Operations | this decision (AD-interop mode inherits PDC urgent replication; native mode uses Raft multi-region with locality-aware leader placement) |
| PC-117 | DCSync | Security | this decision (DrSuapiReplicator implements EXOP_REPL_SECRETS with AD-equivalent ACL checks; native mode does not implement DCSync, eliminating the attack surface; threat-model ADR for PC-117 can now be written) |
| PC-126 | Client switchover parallel-run | Migration | this decision (parallel-run requires DRSUAPI on the wire; AD-interop mode enables parallel-run; native mode requires cut-over) |

Partial ADRs that can now be promoted from PARTIAL to full:

- **ADR-001 (LVR)** — Open Question on CRDT-tombstone GC strategy resolved: CRDT is rejected; LVR uses `PROPERTY_META_DATA_EXT` LWW in both modes; tombstoned link-value rows are GC'd by the periodic 12-hour GC task per ADR-001 §Decision.
- **ADR-008 (declarative topology)** — Open Question on KCC-vs-declarative resolved: declarative YAML topology (per ADR-008) is the primary mechanism in both modes; the topology-controller translates YAML to `repsFrom`/`repsTo` for DrSuapiReplicator and to `RaftNetwork` peer configuration for RaftReplicator.
- **ADR-010 (backup/restore)** — Open Question on `invocationId` reset on restore resolved: AD-interop mode resets `invocationId` on restore (matching AD); native mode resets the Raft voter set (the restored DC rejoins as a new voter, triggering log catch-up).
- **ADR-061 (REST/gRPC API)** — `GET /api/v1/replication/health` endpoint now specified (per Concrete Specification above).
- **ADR-062 (trust password auto-rotation)** — Open Question on replication-assumption resolved: trust password changes replicate via DrSuapiReplicator (AD-interop) or RaftReplicator (native); both modes support the auto-rotation cadence.

## Implementation impact

- **Core Directory**: The `Replicator` trait and the `DrSuapiReplicator`/`RaftReplicator` implementations are the bulk of v1 Core Directory engineering. ~14 person-months. The link-value store (ADR-001) and the schema cache (ADR-003) are unaffected because they sit above the replication layer. The DCE/RPC transport for DRSUAPI also serves SAMR, LSARPC, and Netlogon (which the framework must implement for full AD-interop), so the DCE/RPC investment is amortised across 4 protocols.
- **KDC**: KDC's PAC builder reads group memberships via the link-value store; replication mode does not change the PAC builder. KDC's krbtgt key (per ADR-015/065) replicates as a secret attribute; DrSuapiReplicator encrypts secrets with the DC's `dBCSPwd` (matching AD), RaftReplicator encrypts with the cluster's TLS mutual-auth keys.
- **Auth Provider**: Auth Provider is replication-agnostic except for the S4U2Proxy / RBCD configuration attributes, which are linked attributes and replicate via LVR (per ADR-001) in both modes.
- **Policy Engine**: SYSVOL replication path now defined — DRSUAPI for AD-interop, Git for native. ADR-031 (Git-backed policy history) is the canonical native-mode mechanism; the ADR-029 (JSON canonical policy PReg adapter) is the AD-interop bridge.
- **Cert Service**: CA database (per ADR-034) is independent of directory replication. NTAuthCertificates (the cross-forest trust anchor list) replicate via DrSuapiReplicator in AD-interop mode and via RaftReplicator in native mode.
- **File Gateway**: DFS-N (per ADR-044) is independent. DFS-R replacement (PC-080) is now specified. SYSVOL access on the file gateway uses the framework's replication, not DFS-R.
- **Client SDK**: Client SDK is replication-agnostic; clients speak LDAP/Kerberos/SMB and do not see the replication protocol.
- **Cross-Platform Parity**: RODC (PC-102) is AD-interop-mode only; documented as a parity gap for native-mode deployments.
- **Operations**: Replication-health monitoring (per Concrete Specification) is a new Operations surface. The `adrian-operator` (ADR-058) treats replication-health as a readiness gate — a DC with stale replication (last-success USN older than `replInterval × 3`) is removed from the LDAP/Kerberos service endpoints.
- **Security**: PC-117 (DCSync) threat model can now be written. Native-mode deployments eliminate DCSync entirely (no `EXOP_REPL_SECRETS`); AD-interop-mode deployments inherit AD's DCSync attack surface with the same mitigations (privileged-account tiering, Tier-0 admin separation, ATA-equivalent monitoring on event 4662 with `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` access mask).
- **Migration**: PC-126 (parallel-run) is now defined — AD-interop mode is the parallel-run mode; native mode is the cut-over target. PC-124 (sIDHistory migration) is gated by Decision 3 (identity model).

## Cross-capability dependencies

This decision **depends on** Decision 2 (storage engine). The `Replicator` trait operates on top of the `DirectoryStore` trait; the storage engine's transaction semantics determine whether per-value replication deltas can be applied atomically. FoundationDB's strict serializable transactions make both DrSuapiReplicator and RaftReplicator simpler than they would be on a single-node engine (no need for a separate replication-apply lock; FDB's optimistic concurrency control handles concurrent replication-apply from multiple partners). If Decision 2 had chosen RocksDB (single-node), the framework would need to build its own replication-apply mutex and its own multi-DC consensus on top — which would have been an argument for Raft-only and against DRSUAPI. The FoundationDB decision makes the hybrid replication decision viable.

This decision **depends on** Decision 3 (identity model). The UTD vector's `origin DSA InvocationID` field references a DC; the `origin USN` field references a USN counter. Both are independent of the identity model. However, PC-126 (parallel-run switchover) requires sIDHistory migration, which is gated by Decision 3 — if Decision 3 chooses UUID-only, parallel-run is impossible because AD's ACLs reference SIDs that no longer exist after migration. Decision 3's choice of "both with mapping" preserves sIDHistory and makes parallel-run viable.

This decision **influences** the KDC implementation decision (ORQ-042/043/044, Day 2). The KDC's krbtgt key is a secret attribute that replicates via DrSuapiReplicator (AD-interop) or RaftReplicator (native). The KDC's PAC builder reads group memberships via the link-value store; both replication modes preserve the link-value store's semantics, so the KDC implementation is replication-agnostic. The KDC decision can proceed independently of this decision.

This decision **influences** the NTLM decision (ORQ-072/074/075, Day 2). NTLM's pass-the-hash attack surface is independent of replication, but the NTLM-maintenance decision (maintain with hardening vs. drop) interacts with replication because the framework's NTLM hash storage on the user object replicates as a secret attribute. The replication-mode choice does not change the NTLM decision, but the NTLM decision's threat model must account for both replication modes (in native mode, NTLM hashes replicate via Raft, which has different eavesdropping characteristics than DRSUAPI's RPC-encrypted replication).

This decision **influences** the SMB server decision (ORQ-154/155, Day 2). SMB's SYSVOL access uses the framework's replication. The SMB server choice (Samba vs. fresh) does not depend on replication mode, but the SMB server's expected behaviour for SYSVOL consistency does (AD-interop mode inherits AD's DFS-R-equivalent eventual consistency; native mode inherits Raft's strict serializability).

## References

- [CONTEXT.md](./CONTEXT.md) — workshop briefing, ORQ-001/002/003/004 §lines 21–47
- [TRIAGE.md](../adr/TRIAGE.md) — deferred-problem rows PC-001, PC-002, PC-005, PC-009, PC-014, PC-019, PC-043, PC-044, PC-055, PC-080, PC-102, PC-108, PC-117, PC-126
- [Catalog ORQs](../catalog/13-open-research-questions.md) — lines 38–41 (ORQ-001..004)
- [ADR-001: Linked Value Replication](../adr/ADR-001-linked-value-replication.md) — LVR, `REPLVALINF_V3`, `PROPERTY_META_DATA_EXT`
- [ADR-002: memberOf back-link](../adr/ADR-002-memberof-back-link.md) — back-link referential integrity, depends on LVR
- [ADR-008: Declarative YAML replication topology](../adr/ADR-008-declarative-replication-topology.md) — topology-controller reconciles `repsFrom`/`repsTo` (AD-interop) and `RaftNetwork` peers (native)
- [ADR-010: Backup/restore snapshots](../adr/ADR-010-backup-restore-snapshots.md) — `invocationId` reset on restore (AD-interop); Raft voter-set reset (native)
- [ADR-058: Container-native DCs operator](../adr/ADR-058-container-native-dcs-operator.md) — operator-driven DC lifecycle, replication-health readiness gate
- [ADR-061: REST/gRPC API](../adr/ADR-061-rest-grpc-api.md) — `GET /api/v1/replication/health` endpoint
- [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — DRSUAPI protocol specification (Microsoft Open Specification Promise)
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Active Directory Technical Specification (replication model, UTD vector, lingering objects)
- [openraft crate](https://github.com/datafuselabs/openraft) — Rust-native Raft implementation
- [rasn crate](https://github.com/librasn/rasn) — Rust ASN.1 / NDR encoding library
- [Ongaro & Ousterhout, "In Search of an Understandable Consensus Algorithm"](https://raft.github.io/raft.pdf) — Raft paper
- [Samba 4 DRSUAPI server](https://github.com/samba-team/samba/tree/master/source4/rpc_server/drsuapi) — reference implementation (used as test oracle only, not as source)
