---
title: "ADR-071: Hybrid Replication Model — DrSuapiReplicator + RaftReplicator behind Replicator Trait"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-002
severity: blocker
unblocked_by: Workshop Decision 1 (ORQ-001/002/003/004)
tags: [adr, core-directory, replication, raft, drsuapi, utd-vector, invocation-id, rust]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-01-replication-protocol.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-001-linked-value-replication.md
  - ./ADR-070-drsuapi-replication-protocol.md
  - ./ADR-074-tombstone-lifetime-lingering-objects.md
last_updated: 2026-08-13
---

# ADR-071: Hybrid Replication Model — DrSuapiReplicator + RaftReplicator behind Replicator Trait

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-001/002/003/004. It is now unblocked by [Workshop Decision 1 (Hybrid Replication — Fresh Rust DRSUAPI for AD-Interop, Raft for Native Mode)](../workshop/decision-01-replication-protocol.md).

## Context

AD's replication correctness rests on a four-tuple: per-DC `usnChanged` (monotonic 64-bit counter allocated inside the ESE transaction in `ntdsa.dll!DBUpdateRecUsn`, persisted at `DBHEADER.usnLast` offset 0x118 of `ntds.dit`), per-DC `invocationId` (UUID regenerated on USN-rollback detection or by `repadmin /kcc -resetinvocationid`, persisted on the NTDS Settings object as OID `1.2.840.113556.1.4.124`), per-NC up-to-dateness (UTD) vector (set of `{InvocationID, USN}` tuples encoding the highest-seen USN per originating DSA), and per-NC high-watermark cursor (the `{InvocationID, USN}` pair last pulled from each partner). Together these implement idempotent replication with rollback protection per [PC-002](../catalog/01-core-directory.md#pc-002--usn--invocationid--utd-vector-replication-model-is-unique-to-ad-alternatives-must-preserve-rollback-semantics) and [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

Rollback detection is the subtle part. When a partner DC's `invocationId` differs from what the source remembers, the source discards all state about that partner and re-initializes the UTD vector (treating the partner as a fresh replica). When a partner's advertised high-watermark is *lower* than the stored cursor, `ntdsa.dll!CheckUsnRollback` quarantines the partner and logs event 2095. Recovery requires demote + metadata cleanup + re-promote, or `repadmin /kcc -resetinvocationid` as a last resort, per [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md).

Any new replication protocol (CRDT, OT, Raft) must preserve all three properties: (a) rollback detection — restored DCs must not silently resume from a stale USN; (b) idempotency — re-replication of the same change must be a no-op; (c) per-attribute `PROPERTY_META_DATA_EXT` with `dwVersion`, `uuidLastOriginatingDsa`, `usnOriginatingChange`, `ftimeLastOriginatingChange`. Raft's log truncation gives consistency but loses per-attribute originating metadata; 389-DS MMR uses a vector clock without per-attribute versioning; OpenLDAP SYNCREPL uses a state cookie without rollback detection.

**Unblocking decision.** [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) resolved ORQ-001/002/003/004 by selecting the hybrid model: `DrSuapiReplicator` (per ADR-070) for AD-interop mode, `RaftReplicator` (this ADR) for native mode, behind a shared `Replicator` trait. `PROPERTY_META_DATA_EXT` is preserved verbatim in both modes. UTD vector is synthesised from the Raft log when a native-mode DC must speak DRSUAPI for diagnostics. This ADR specifies the `Replicator` trait, the `RaftReplicator` implementation, and the UTD-vector synthesis.

## Decision

The framework SHALL define a `Replicator` trait in the `adrian-repl-core` crate with methods `get_changes`, `apply_changes`, `update_utd_vector`, `resolve_conflict`, and `sync_metadata`. Both `DrsuapiReplicator` (per ADR-070) and `RaftReplicator` (this ADR) implement this trait. The trait operates on a shared `ReplOperation` enum (`AddObject`, `ModifyAttribute`, `DeleteObject`, `AddLink`, `DeleteLink`, `TombstoneGC`), with per-value `PropertyMetaDataExt` metadata (`origin_invocation_id: Uuid`, `origin_usn: u64`, `version: u32`, `last_write_timestamp: SystemTime`). The same on-disk representation (FDB subspaces per Decision 2) supports both replicators without a translation layer.

The `RaftReplicator` SHALL use the `openraft` crate (Apache-2.0) for consensus, with a custom `RaftLogEntry` payload type carrying per-value linked-attribute deltas, whole-attribute updates, and tombstones using the same internal representation as `DrSuapiReplicator`. In v1, the `RaftReplicator` SHALL replicate the entire directory as a single Raft group; per-NC sharding into multiple Raft groups is deferred to v2 (gated by ORQ-024/025, the FSMO-replacement Tier-2 question, partially resolved by ADR-076).

**Concrete specification**:

- The `Replicator` trait SHALL be `async`, take `&self`, and be `Send + Sync`. The signature:
  ```rust
  #[async_trait]
  pub trait Replicator: Send + Sync {
      async fn get_changes(&self, nc_head: &Dn, cursor: &UtdVector) -> Result<ReplBatch, ReplicationError>;
      async fn apply_changes(&self, batch: ReplBatch) -> Result<ApplyStats, ReplicationError>;
      async fn update_utd_vector(&self, nc_head: &Dn, delta: UtdDelta) -> Result<(), ReplicationError>;
      async fn resolve_conflict(&self, conflict: ConflictRecord) -> Result<Resolution, ReplicationError>;
      async fn sync_metadata(&self, partner: &DsaEndpoint) -> Result<SyncState, ReplicationError>;
  }
  ```
- The `ReplOperation` enum SHALL carry per-value `PropertyMetaDataExt`. Conflict resolution SHALL be: highest `version` wins; tiebreak by latest `last_write_timestamp`; tiebreak by highest `origin_usn`; final tiebreak by lexicographically-highest `origin_invocation_id`. This matches AD's resolver.
- The `RaftReplicator` SHALL use `openraft::Raft<RaftNodeId, RaftNode, RaftLogEntry, RaftStateMachine, RaftNetwork>`. The `RaftLogEntry` payload is `ReplOperation`. The `RaftStateMachine` applies `ReplOperation` to the `FdbDirectoryStore` (per Decision 2).
- The `RaftReplicator` SHALL replicate the entire directory as a single Raft group in v1 (one leader, N followers). The leader is elected by `openraft`'s default leader-election (randomised election timeout, lowest-ID wins on tie). Per-NC sharding is deferred to v2.
- A native-mode DC SHALL maintain an `invocation_id` (UUIDv4, generated at DC promotion, persisted on the NTDS Settings object) — matching AD's `invocationId` for diagnostic compatibility. The Raft log's `(term, index)` pair is the authoritative ordering; the `invocation_id` is a stable DC identifier for `repadmin /showutdvec` display.
- A native-mode DC SHALL synthesise a UTD vector from its Raft log when AD-interop interop is required (e.g., a native-mode forest that later peers with an AD forest via a one-way trust — the trust does not require replication, but `repadmin /showutdvec` against the framework DC must return valid XML). Synthesis maps each Raft log entry to a UTD entry: `origin_invocation_id = entry.leader_id`, `origin_usn = entry.log_index`. Synthesis is for diagnostics only — actual replication in mixed-forest scenarios uses DRSUAPI on the wire (the framework DCs run in AD-interop mode).
- The framework SHALL support urgent replication (PDC-emulator-triggered, immediate in AD-interop), intra-site (15-second default), inter-site (configurable, default 180 seconds), and change-notification on the connection object's `options` flag, matching MS-ADTS §3.1.1.3.x schedules. In Raft mode, urgent replication is automatic (Raft replicates every committed entry immediately); intra-site and inter-site schedules do not apply.
- The framework SHALL implement lingering-object detection per MS-ADTS §3.1.1.3.3 — `StrictReplicationConsistency` defaults to `true` in both modes. The framework SHALL reject replication from a partner whose UTD vector is older than `tombstoneLifetime` (default 180 days) on the destination NC head. In Raft mode, the equivalent is the Raft log truncation policy (entries older than `tombstoneLifetime` are truncated after a snapshot, per ADR-074).
- The framework SHALL expose `GET /api/v1/replication/health` (per ADR-061) returning per-NC, per-partner latency, last-success USN, last-error, and queue depth — equivalent to `repadmin /showrepl /csv` output. The `adrian-repl-health` CLI emits the same data.
- USN rollback detection: a native-mode DC that detects its Raft log index is *lower* than what the cluster remembers (i.e., the DC was restored from a stale snapshot) SHALL self-quarantine, log an event equivalent to AD's event 2095, and refuse to serve writes until an admin runs `adrian-repl reset-invocation-id` (which generates a new `invocation_id` and rejoins the Raft cluster as a fresh voter, triggering log catch-up). This matches AD's `repadmin /kcc -resetinvocationid` recovery path.
- Performance target: the `RaftReplicator` SHALL sustain ≥6,800 writes/sec/DC and <12 ms p99 replication latency (matching the spike-1 prototype benchmark, which is faster than DRSUAPI because strict serializability eliminates UTD-vector comparison).

## Rationale

The hybrid model preserves AD interop (DRSUAPI on the wire for AD-interop forests) while giving clean-slate deployments a stronger consistency model (Raft strict serializability for native forests). Customers who choose the framework *because* they want to escape AD's quirks (USN rollback, lingering objects, FSMO bottlenecks) get the strict-serializable experience; customers who need to coexist with AD get the byte-compatible experience.

`openraft` is production-grade (used by `dragonfly` for its replication, by `squill`, by `RobustMQ`; actively maintained by the datafuselabs team; v0.21.x at the time of this decision). `tikv/raft-rs` is an alternative but is a port of etcd's Go Raft and is less idiomatic. CockroachDB and TiKV both use Raft-based replication at similar scale (10M+ objects, 100+ DCs), demonstrating that Raft is viable at the framework's target scale.

The UTD-vector synthesis in Raft mode is approximate (a Raft log entry maps to a UTD vector entry, but the reverse is not unique). The mitigation is that synthesis is only required for `repadmin /showutdvec` display, not for actual replication. Mixed-forest scenarios always run framework DCs in AD-interop mode (not native), so the synthesis is purely diagnostic.

Raft mode does not support RODC (PC-102) because Raft's leader-follower model is incompatible with AD's RODC unidirectional-replication model. RODC is AD-interop-only. This is acceptable because RODC's primary use case (branch-office DC with filtered secrets) is itself an AD-interop scenario — greenfield deployments rarely need RODC.

## Consequences

**Positive**: Native-mode forests get strict-serializable replication (no USN rollback, no lingering objects, no LWW ambiguity, no FSMO bottleneck). The `Replicator` trait abstraction means the storage layer (Decision 2), the schema cache (ADR-003), the link-value store (ADR-001), and the constructed-attribute engine (ADR-009) are unaware of which replicator is in use. The test matrix is bounded to the wire/consensus layer (the storage model, conflict-resolution logic, and schema are shared).

**Negative**: Two operating modes double the test matrix for replication-path bug fixes and performance benchmarks. The shared `Replicator` trait and shared on-disk representation bound the divergence surface to wire protocol and consensus algorithm — the storage, schema, and link-value layers are tested once, not twice. The UTD-vector synthesis in Raft mode is approximate (diagnostic-only).

**Neutral**: The `Replicator` trait is the v2 seam where a third replicator (e.g., a CRDT-shim for offline-first edge deployments, or a Postgres-L replication adapter) would slot in. None is planned for v1.

**Cost**: ~3 person-months for `RaftReplicator` (the `openraft` integration, the `RaftLogEntry` payload design, the UTD-vector synthesis) + ~2 person-months for the shared `Replicator` trait and on-disk representation (split with ADR-070). Total ~5 person-months for ADR-071's share.

**Operational impact**: AD-interop forests operate with AD's replication semantics (eventual consistency, PDC-urgent, UTD vector). Native-mode forests operate with Raft's strict serializability (immediate replication, leader election on failure, log truncation per ADR-074). The `adrian-repl-health` CLI surfaces both modes uniformly.

## Alternatives Considered

### Alternative 1: Pure DRSUAPI for all modes (no Raft)

One protocol, one codebase, one mental model. But DRSUAPI's eventual-consistency-with-LWW model is a worse fit for greenfield deployments, and customers who want to escape AD's quirks (USN rollback, lingering objects, FSMO bottlenecks) would be disappointed. Rejected as the sole protocol; ADOPTED as the AD-interop-mode protocol per ADR-070.

### Alternative 2: Pure Raft, abandon AD-interop

Simplest internal model. But breaks every AD-interop scenario (mixed-forest replication, ADMT migration, parallel-run, RODC, cross-trust access). PC-124 (sIDHistory migration), PC-126 (parallel-run switchover), PC-117 (DCSync threat model) all assume DRSUAPI on the wire. Rejected as the sole protocol; ADOPTED as the native-mode protocol.

### Alternative 3: CRDT-shim (DRSUAPI wire over internal CRDT OR-set)

Conflict-free replication semantics. But the translation layer adds 30% CPU overhead and 1.7× latency at AD-interop mode (per Spike 1), and CRDT tombstones do not map cleanly to AD's `PROPERTY_META_DATA_EXT` four-tuple. Rejected: complexity is unjustified given LWW on per-value metadata is sufficient (per ADR-001) and Raft provides a stronger model for native mode without CRDT overhead.

## Open Questions

- For v2 per-NC sharding (multiple Raft groups, one per NC), what is the cross-NC transaction boundary? FDB strict serializable transactions span subspaces, but Raft groups are independent. The answer requires a cross-shard transaction protocol (per-NC Raft groups with a two-phase commit across NC heads). Defer to v2.
- For the UTD-vector synthesis in Raft mode, what is the XML format for `repadmin /showutdvec` output? MS-ADTS specifies the format; the framework must match byte-for-byte for AD tooling compatibility. Confirm in implementation.
- Should the `RaftReplicator` support read-only followers (analogous to AD RODC)? No — RODC is AD-interop-mode only because Raft leader-follower is incompatible. Re-confirm in v2 if customer demand materialises.

## Cross-capability impact

- **KDC**: KDC's krbtgt key replicates as a secret attribute via `RaftReplicator` (native) or `DrSuapiReplicator` (AD-interop). KDC's PAC builder reads group memberships via the link-value store; both replicators preserve the link-value store's semantics, so KDC is replication-agnostic.
- **Auth Provider**: NTLM hash storage replicates as a secret attribute. Raft-mode encryption uses the cluster's TLS mutual-auth keys; AD-interop-mode uses the DC's `dBCSPwd`.
- **Policy Engine**: SYSVOL replication — DRSUAPI for AD-interop, Git for native (per ADR-031). The `RaftReplicator` carries the GPC (Group Policy Container) data in native mode.
- **Operations**: `GET /api/v1/replication/health` (per ADR-061) surfaces both modes uniformly. The `adrian-operator` (ADR-058) treats replication-health as a readiness gate — a DC with stale replication (last-success USN older than `replInterval × 3`) is removed from LDAP/Kerberos service endpoints.
- **Migration**: PC-126 (parallel-run) requires DRSUAPI on the wire — AD-interop mode enables parallel-run; native mode requires cut-over.
- **Security**: PC-117 (DCSync) threat model — native-mode deployments eliminate DCSync entirely (no `EXOP_REPL_SECRETS`); AD-interop deployments inherit AD's DCSync attack surface.

## References

- [PC-002](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 1 — Hybrid Replication](../workshop/decision-01-replication-protocol.md) — unblocking decision
- [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md) — UTD vector IDL, USN rollback detection algorithm, strict consistency registry
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — `DBHEADER.usnLast`, `DBUpdateRecUsn`, transaction commit path
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Active Directory Technical Specification (replication model, UTD vector, lingering objects)
- [openraft crate](https://github.com/datafuselabs/openraft) — Rust-native Raft implementation
- [Ongaro & Ousterhout, "In Search of an Understandable Consensus Algorithm"](https://raft.github.io/raft.pdf) — Raft paper
- [ADR-001: Linked Value Replication](./ADR-001-linked-value-replication.md) — `REPLVALINF_V3`, `PROPERTY_META_DATA_EXT`
- [ADR-070: DRSUAPI Replication Protocol](./ADR-070-drsuapi-replication-protocol.md) — `DrSuapiReplicator` AD-interop mode
- [ADR-074: Tombstone Lifetime and Lingering Objects](./ADR-074-tombstone-lifetime-lingering-objects.md) — Raft log truncation policy
