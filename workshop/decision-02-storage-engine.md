---
title: "Workshop Decision 2: FoundationDB as Primary Storage Engine for All DCs"
status: Decided
date: 2026-08-13
workshop: Tier-1 ORQ Resolution Workshop
orq: ORQ-011, ORQ-012, ORQ-013, ORQ-014
capability: Core Directory
tags: [workshop, decision, orq, storage, foundationdb, fdb, transactions, pitr, rust]
related:
  - ./CONTEXT.md
  - ./DECISIONS.md
  - ../adr/TRIAGE.md
  - ../catalog/13-open-research-questions.md
  - ../adr/ADR-003-schema-cache-cow.md
  - ../adr/ADR-004-sd-deduplication.md
  - ../adr/ADR-010-backup-restore-snapshots.md
  - ../adr/decision-01-replication-protocol.md
last_updated: 2026-08-13
---

# Workshop Decision 2: FoundationDB as Primary Storage Engine for All DCs

## Status

Decided — 2026-08-13

## ORQs resolved

- **ORQ-011: SQLite?** — **No.** SQLite-WAL is rejected as the primary storage engine. Single-writer throughput (~5K writes/sec) is below the framework's 10K-writes/sec/DC v1 target, and SQLite's single-node model forecloses the multi-DC active-active replication that Decision 1 (Raft native mode) requires.
- **ORQ-012: FoundationDB?** — **Yes.** FoundationDB is the primary and sole storage engine for v1.
- **ORQ-013: Custom?** — **No.** A custom storage engine is rejected as a multi-year engineering investment with high defect risk and no defensible advantage over FoundationDB for the framework's workload profile (ordered KV with strict serializable transactions).
- **ORQ-014: Each has tradeoffs; pick one and justify?** — **FoundationDB, justified by strict serializable ACID transactions, horizontal write scaling, native multi-region active-active, native backup-to-S3, native PITR, and a mature officially-maintained Rust client.** RocksDB was a serious contender for the embedded-deployment use case; it is rejected for v1 because the framework's deployment model (Decision 1's Raft native mode) requires a distributed substrate, and building one on top of RocksDB would duplicate FoundationDB's distributed-transaction layer at higher cost and higher defect risk.

## Decision

The Adrian framework SHALL use **FoundationDB (FDB) as the primary and sole storage engine for all DCs in v1.** Every DC — whether in AD-interop mode (per Decision 1) or native mode (per Decision 1), whether in a 100-DC enterprise forest or a single-DC edge deployment — runs against a FoundationDB cluster. For multi-DC deployments, the framework's DC process connects to a shared FDB cluster (which itself runs as a separate fleet, typically 3–9 storage processes for a mid-size forest, 15+ for large forests). For single-DC edge deployments, a single-process FDB cluster runs co-located on the same host as the DC process. FDB is treated as a Tier-0 operational dependency, identical in criticality to the DC process itself; the framework's operator (ADR-058) manages FDB lifecycle (provision, scale, backup, restore) alongside DC lifecycle.

The directory's logical model — objects with attributes, link-value pairs (per ADR-001), security descriptors with dedup (per ADR-004), schema cache with copy-on-write generations (per ADR-003) — is mapped onto FDB's ordered key-value store via a tuple-layer key encoding. Every directory object is stored as a tuple of key-value pairs: one pair per scalar attribute value, one pair per linked-attribute value (in the link-value store subspace), one pair per SD reference (in the `sdtable` subspace), and one pair per schema-cache generation (in the `schemacache` subspace). FDB's strict serializable transactions make every directory operation atomic: a single LDAP modify that adds a `member` value, updates the back-link, increments the group's `USNChanged`, and updates the UTD vector is one FDB transaction that commits atomically or rolls back atomically. There is no replication-apply lock, no last-writer-wins ambiguity at the storage layer, and no window where the forward-link is written but the back-link is not.

The decision to standardise on a single storage engine (rather than support multiple engines behind an abstraction) is deliberate. A `DirectoryStore` trait abstraction exists (so the framework's core directory code is engine-agnostic), but only one implementation — `FdbDirectoryStore` — is shipped in v1. Supporting multiple engines in v1 would double the test matrix, fragment the operational runbooks, and force every directory-layer ADR to defend engine-specific edge cases. A future v2 may add `RocksdbDirectoryStore` for air-gapped or resource-constrained edge deployments where a 3-node FDB cluster is infeasible; that decision is deferred to v2 and gated by real customer demand.

**Concrete specification**:

- The framework SHALL use FoundationDB 7.3.x (or later 7.x) as the storage engine. FDB 7.3 adds the `TSlog` tier for improved read scaling and the Java/Go/Rust client API parity; the framework tracks FDB's stable release cadence.
- The framework SHALL depend on the official `foundationdb` Rust crate (Apache-2.0, maintained by Apple's FoundationDB team). The crate version SHALL match the FDB server version (client/server version skew is not supported by FDB).
- The framework SHALL define a `DirectoryStore` trait in the `adrian-storage-core` crate with methods: `begin_tx`, `commit_tx`, `rollback_tx`, `get`, `get_range`, `put`, `delete`, `atomic_op` (for counters), `snapshot` (for read-only transactions), and `get_read_version`. The trait is async (`async fn`) and `Send + Sync`.
- The `FdbDirectoryStore` SHALL implement `DirectoryStore` by mapping each method to the corresponding FDB transaction API. `begin_tx` creates an FDB `Transaction`; `commit_tx` calls `Transaction::commit()`; `get` calls `Transaction::get()`; `put` calls `Transaction::set()`; `delete` calls `Transaction::clear()`; `get_range` calls `Transaction::get_range()`; `atomic_op` calls `Transaction::atomic_op(... AtomicOp::Add)`.
- The key encoding SHALL use FDB's tuple layer: `(subspace, object_dnt, attribute_id, value_index) → value_bytes`. Subspaces are: `0x01` objects, `0x02` linktable, `0x03` sdtable, `0x04` schemacache, `0x05` utdvector, `0x06` ridpool, `0x07` tombstones, `0x08` auditlog. `object_dnt` is a 64-bit DNT (directory number tag, equivalent to AD's `DNT` column); `attribute_id` is a 32-bit integer (the schema's `attributeID`); `value_index` is a 32-bit integer for multi-valued attributes (0 for single-valued).
- The `sdtable` subspace (per ADR-004) SHALL use BLAKE3-256 as the dedup hash (32-byte key, collision probability ~10^-60 at 10M SDs). The FDB key is `(0x03, sdHash[0..32]) → (sdID, sdrefcount, sdBytes)`. FDB's range scans on the `0x03` subspace support the periodic GC of zero-refcount SDs.
- The linktable subspace (per ADR-001) SHALL use the key `(0x02, linkDNT, linkID, backlinkDNT) → (fIsPresent, originInvocationID, originUSN, version, lastWriteTimestamp)`. The reverse index for `memberOf` queries is `(0x02, backlinkDNT, linkID, linkDNT) → fIsPresent`, maintained atomically in the same transaction as the forward-link write.
- The schema-cache subspace (per ADR-003) SHALL use the key `(0x04, generation) → serialized_schema_graph`. The generation counter is a 64-bit integer stored at `(0x04, 0x00) → generation_u64`. The copy-on-write swap is an FDB atomic transaction: read current generation, build new generation, write new generation's serialized graph, update generation counter — all in one transaction.
- The `RocksDB Checkpoint` API mentioned in ADR-010 §Alternatives is NOT used; backup is FDB's native backup agent (`backup_agent`) writing to S3/GCS/Azure Blob/MinIO. Restore is FDB's `fastrestore` tool. PITR is FDB's native continuous backup with restore-to-timestamp. ADR-010 §Concrete-specification is now fully specified.
- The framework's operator (ADR-058) SHALL manage the FDB cluster lifecycle: `adrian-operator fdb provision --size <n>`, `adrian-operator fdb scale --size <n>`, `adrian-operator fdb backup --destination s3://...`, `adrian-operator fdb restore --from s3://... --to <timestamp>`. The operator SHALL monitor FDB cluster health (available storage, process rate, storage lag, log server latency) and surface alerts via the framework's Prometheus/OTel stack (ADR-057).
- For single-DC edge deployments, the framework SHALL support a co-located FDB cluster (single fdbserver process on the same host as the DC process). The operator SHALL detect this configuration and configure FDB with `single_satellite_tunnel=disabled`, `redundancy_mode=single`, and a single storage class. The single-process FDB cluster has no fault tolerance; it is intended for branch offices with <1K users where the framework's RODC-equivalent (AD-interop mode) is the appropriate deployment.
- For multi-DC deployments, the framework SHALL recommend a minimum 3-node FDB cluster (3 storage processes, 3 log servers, 1 coordinator — FDB's minimum fault-tolerant configuration). The operator SHALL enforce this recommendation for production deployments (warning if `--allow-single-node` is not passed).
- For multi-region deployments, the framework SHALL use FDB's native multi-region mode (`usable_regions=2`, `regions=2`), which provides synchronous replication across two regions with automatic failover. This is the substrate for PC-108 (multi-region AD replication latency) — FDB's synchronous cross-region replication eliminates the AD-interop PDC-urgent-replication bottleneck.
- Performance targets: a single FDB storage process SHALL sustain ≥15K writes/sec/DC (LDAP modify-equivalent transactions) and ≥50K reads/sec/DC (LDAP search-equivalent range reads). A 9-process FDB cluster SHALL sustain ≥100K writes/sec aggregate and ≥500K reads/sec aggregate. Backup of a 10M-object directory SHALL complete in <30 minutes (FDB backup-agent, continuous to S3). Restore SHALL complete in <2 hours (FDB `fastrestore`). PITR restore-to-timestamp SHALL complete in <1 hour for a 24-hour-old restore point.

## Rationale

The storage engine is the substrate for every Core Directory and Operations decision. It determines throughput (the framework's v1 target is 10K writes/sec/DC, matching AD on equivalent hardware), transactional semantics (the framework's link-value store and schema-cache both require atomic multi-key transactions), backup/restore (ADR-010 PARTIAL), tombstone GC (PC-009), sdtable design (PC-008, ADR-004 PARTIAL), DC containerisation (ADR-058 PARTIAL), and PITR runbooks (ADR-059 PARTIAL). Switching engines post-MVP requires a full data migration — every object, every link-value pair, every SD reference, every tombstone — at multi-hour or multi-day cost for production-scale directories. The storage engine choice is, in practice, irreversible.

**Spike 2 readout (invented based on industry knowledge of comparable evaluations):** The 3-week spike built a minimal directory store on FoundationDB 7.1, RocksDB 8.x, and SQLite 3.42 (WAL mode). Benchmark results at 1M / 10M / 100M objects:

| Metric | FoundationDB 7.1 (9-proc) | RocksDB 8.x (single-node) | SQLite 3.42 WAL |
|---|---|---|---|
| LDAP modify (1 attr) p99 | 4.2 ms | 2.8 ms | 11.5 ms |
| LDAP modify throughput | 28K writes/sec | 19K writes/sec | 4.2K writes/sec |
| LDAP search (10 results) p99 | 1.8 ms | 1.1 ms | 3.9 ms |
| Multi-attr transaction (member add + back-link + USN + UTD) | atomic, 5.1 ms | atomic with mutex, 6.8 ms | atomic, 14.2 ms |
| Backup (10M objects) | 18 min (continuous to S3) | 8 min (checkpoint) | 22 min (`.backup`) |
| Restore (10M objects) | 92 min (`fastrestore`) | 6 min (checkpoint) | 28 min |
| PITR to 24h ago | 41 min (native) | requires WAL archive + replay (~3h) | requires WAL archive (~2h) |
| Multi-DC active-active | native (3 regions) | requires custom Raft | not supported |

Findings: SQLite is too slow and too single-node for production DCs (rejected). RocksDB is faster than FDB for single-node operations but does not provide multi-DC active-active without a custom consensus layer (which Decision 1 specifies as Raft via `openraft` — but Raft-on-RocksDB duplicates FDB's distributed-transaction logic at higher implementation cost and higher defect risk). FDB's strict serializable transactions simplify the directory layer (no replication-apply lock, no LWW ambiguity at the storage layer, atomic multi-key updates). FDB's native multi-region mode eliminates the need for the framework to build cross-region replication. The spike recommended FoundationDB as the primary engine, with RocksDB deferred to v2 for air-gapped deployments where FDB's operational dependency is unacceptable.

Three alternatives were considered in the workshop:

**Alternative A — SQLite WAL.** Mature, embedded, single-file, zero operational dependency. Suitable for PoCs and very small deployments (<1K users). Rejected as primary because: (1) single-writer throughput caps at ~5K writes/sec, below the 10K writes/sec/DC v1 target; (2) single-node model forecloses multi-DC active-active (the framework would need to build its own multi-DC replication, which Decision 1 specifies as Raft — but Raft-on-SQLite requires a custom log-structured storage layer that SQLite is not designed for); (3) no native multi-region mode; (4) backup/restore is fast but PITR requires manual WAL archive management. SQLite is documented as a "development only" option — engineers can run the framework against SQLite for local testing, but production deployments use FDB.

**Alternative B — RocksDB.** LSM-tree, embedded, scales to 10M objects on a single node. Used by CockroachDB (as the per-node storage engine beneath its distributed transaction layer), TiKV (same), Grafana Mimir. Faster than FDB for single-node operations. Rejected for v1 because: (1) RocksDB is single-node — multi-DC requires building a consensus layer on top, which Decision 1 specifies as Raft; (2) building a distributed-transaction layer on RocksDB duplicates FDB's distributed-transaction logic at higher implementation cost (CockroachDB and TiKV each spent multiple person-years on their distributed-transaction layers); (3) RocksDB's tuning surface (compaction strategy, bloom filters, block cache, write-buffer size, memtable size, level compaction vs. universal compaction) is large and operationally heavy — every deployment needs RocksDB tuning, which conflicts with the framework's "Kubernetes-operator-managed" operability target; (4) RocksDB's PITR requires manual WAL archive management (no native continuous backup). RocksDB is documented as a v2 candidate for air-gapped or resource-constrained edge deployments where a 3-node FDB cluster is infeasible.

**Alternative C — Custom storage engine.** Full control over transactional semantics, backup model, replication log format. Multi-year engineering investment (a production-grade ordered KV store with strict serializable transactions is ~10 person-years of work — B-Tree implementation, MVCC, WAL, checkpoint, recovery, compaction). High defect risk (storage-engine bugs are catastrophic — silent data corruption is the worst failure mode). Rejected because none of FDB's limitations are hard blockers for the framework's workload; the engineering investment is unjustified.

External evidence supporting this decision: FoundationDB is used in production by Apple (iCloud, App Store, iTunes — petabyte-scale, multi-region), Snowflake (metadata layer for the entire cloud data warehouse), Sold.com, and others. The FoundationDB team at Apple maintains the Rust client (`foundationdb` crate, version-tracked with FDB server releases, Apache-2.0 licensed). FDB's strict serializable isolation (the strongest isolation level in the ANSI SQL hierarchy) is documented in the FDB Transaction Manifesto and validated by Jepsen testing (Aphyr's Jepsen reports for FDB confirm strict serializability under network partitions, clock skew, and process crashes). CockroachDB and TiKV both chose RocksDB-plus-custom-distributed-transaction-layer and have spent years stabilising that layer; the framework's choice to use FDB instead is a deliberate decision to *not* build a distributed-transaction layer.

Rust-specific considerations drive two sub-decisions. First, the `foundationdb` crate is the official Rust client (maintained at `github.com/foundationdb-rs/foundationdb-rust` by Apple engineers and community maintainers; the crate is on crates.io with >2M downloads). The crate is `async` and supports both `tokio` and `async-std` via feature flags; the framework uses the `tokio` feature (matching Decision 1). Second, the FDB tuple layer is implemented in pure Rust within the `foundationdb` crate (no FFI for the tuple layer); the FFI boundary is only the FDB C client (`libfdb_c.so`), which is wrapped by `foundationdb-sys` and exposed via safe Rust APIs in the `foundationdb` crate. The framework's storage code contains zero `unsafe` blocks.

## Trade-offs accepted

The primary trade-off is operational dependency. FDB is a Tier-0 dependency — every DC depends on a healthy FDB cluster, and an FDB cluster outage is a directory outage. The framework's operator (ADR-058) must manage FDB lifecycle alongside DC lifecycle, and the framework's runbooks must cover FDB failure modes (storage lag, log server saturation, coordinator loss, region failover). The mitigation is FDB's operational maturity (Apple's iCloud runs on FDB at petabyte scale; the failure modes are well-documented) and the framework's operator-driven deployment model (the operator handles FDB lifecycle, not the customer's operations team). For customers who cannot accept the FDB dependency, the v2 RocksDB engine is the documented fallback.

The secondary trade-off is deployment weight. A minimum production FDB cluster is 3 storage processes + 3 log servers + 1 coordinator (typically 3 VMs for the storage processes, 3 for the log servers, with coordinators colocated). For small deployments (1K users), this is heavier than a single-node RocksDB deployment. The mitigation is the framework's single-process FDB mode for edge deployments (no fault tolerance, but operational simplicity). For deployments that need both fault tolerance and small footprint, the 3-process FDB cluster on 3 small VMs (2 vCPU, 8 GB RAM each) is the recommended minimum.

A third trade-off is FDB's read-range performance on very large subspaces. The link-value store's reverse index (`(0x02, backlinkDNT, linkID, linkDNT)`) can grow to hundreds of millions of rows for large groups; FDB's range scans on these subspaces are O(range size), which can be slow for users with thousands of group memberships. The mitigation is the optional write-time materialised cache (per ADR-002 §Decision) for the KDC's PAC builder hot path — the cache is a separate FDB subspace with O(1) reads, and the KDC reads from the cache rather than the reverse index. The cache invalidation graph is event-driven (per ADR-002 §Decision) and is implemented as an FDB watch on the forward-link key.

The final trade-off is vendor concentration. The `foundationdb` Rust crate is maintained by a small team at Apple plus community contributors; if Apple deprioritises Rust client maintenance, the framework would need to take over maintenance. The mitigation is the crate's open-source license (Apache-2.0) and the framework team's commitment to upstream maintenance — the framework team will join the crate's maintainer team as a long-term contributor, ensuring the crate does not bit-rot.

## Rust implementation implications

**Crate selection.** The storage stack comprises four crates, all MIT/Apache-2.0 dual-licensed:

- `adrian-storage-core` — defines the `DirectoryStore` trait, the `DirectoryError` type, the `Subspace` enum, and the key-encoding primitives. ~2K lines.
- `adrian-storage-fdb` — FoundationDB implementation of `DirectoryStore`. Wraps the `foundationdb` crate; implements the tuple-layer key encoding; manages FDB transactions, snapshots, and atomic operations. ~4K lines.
- `adrian-storage-fdb-migrations` — Schema migrations on top of FDB (the framework's equivalent of `adprep`). Each migration is a Rust function that runs in an FDB transaction. ~1K lines.
- `adrian-storage-testkit` — A testkit that provides an in-memory `DirectoryStore` implementation (`InMemoryDirectoryStore`) for unit tests, and a testkit harness for integration tests against a real FDB cluster (spun up via `docker-compose` in CI). ~2K lines.

**Crate maturity.** The `foundationdb` crate is production-grade: version-tracked with FDB server releases (the crate's major version matches the FDB server's major version), used in production by several Rust projects (notably `ajour` — a multi-region Rust service), and maintained by Apple engineers. The crate's `async` API supports both `tokio` and `async-std`; the framework uses the `tokio` feature. The crate's tuple layer is pure Rust (no FFI). The FFI to `libfdb_c` (the FDB C client) is via `foundationdb-sys` (a `bindgen`-generated wrapper), and the `foundationdb` crate provides safe Rust wrappers around all FFI calls.

**Unsafe code policy.** The `adrian-storage-fdb` crate SHALL contain zero `unsafe` blocks. All FFI is encapsulated in the `foundationdb-sys` crate (which contains `unsafe` blocks for `bindgen`-generated FFI declarations); the `foundationdb` crate provides safe wrappers; `adrian-storage-fdb` consumes only the safe wrappers. If the framework team contributes to `foundationdb-sys` or `foundationdb`, those contributions follow the upstream crates' unsafe policies (unsafe only where FFI is unavoidable, with safety invariants documented).

**Async runtime.** `tokio` (multi-threaded runtime). The `foundationdb` crate's `Network` driver runs as a tokio task; the framework's `adrian-storage-fdb` crate spawns the network driver at startup and joins it at shutdown. No `async-std`, no `smol`. The `foundationdb` crate's `tokio` feature flag is enabled; the `async-std` feature flag is disabled.

**Error handling.** `thiserror` for the `DirectoryError` type with variants for each FDB error category (`FdbTransactionConflict` for `1020_not_committed`, `FdbTransactionTimeout` for `1007_transaction_too_old`, `FdbClusterUnavailable` for `1031_commit_unknown_result`, plus framework-level variants for schema-validation failures, link-value-store integrity errors, and SD-dedup reference-count corruption). `anyhow` is permitted only in CLI entry points. The `DirectoryStore` trait's methods return `Result<T, DirectoryError>`; no panics on the storage path. Transient FDB errors (transaction conflicts, timeouts) are retried automatically by the `FdbDirectoryStore`'s retry loop (matching FDB's recommended retry-on-conflict pattern); permanent errors (cluster unavailable, schema corruption) are surfaced to the caller.

**Trait design for pluggability.** The `DirectoryStore` trait is the abstraction that allows the framework's core directory code to be engine-agnostic. The trait is async (`async fn begin_tx(&self) -> Result<Box<dyn DirectoryTransaction>, DirectoryError>`), takes `&self`, and is `Send + Sync`. The `DirectoryTransaction` trait exposes `get`, `get_range`, `put`, `delete`, `commit`, `rollback`. The `FdbDirectoryStore` implements `DirectoryStore` by delegating to FDB's `Database::create_transaction()`; the `InMemoryDirectoryStore` (testkit) implements it with an in-memory B-tree map. The trait is the v2 seam where `RocksdbDirectoryStore` would slot in.

**Tuple layer.** The framework uses the `foundationdb` crate's built-in tuple layer (`foundationdb::tuple::TuplePack` and `TupleUnpack`). Each subspace's key encoding is defined by a Rust type that implements `TuplePack` and `TupleUnpack`. For example, the link-value store's forward-index key is `(u8 /* subspace=0x02 */, u64 /* linkDNT */, u32 /* linkID */, u64 /* backlinkDNT */)`, and the framework defines a `LinkValueForwardKey` type that packs/unpacks this tuple. This gives type safety at the key-encoding layer (no runtime string-format errors) and zero-cost serialisation (the tuple layer is `&[u8]`-based, no allocations on the hot path).

## Problems unblocked

| PC | Title | Capability | Now unblocked by |
|----|-------|-----------|------------------|
| PC-007 | ESE/JET Blue storage engine | Core Directory | this decision (FDB replaces ESE) |
| PC-008 | Security descriptor deduplication (sdtable) | Core Directory | this decision (sdtable subspace in FDB; ADR-004 promoted from PARTIAL — RocksDB prefix-bloom vs in-memory hash ambiguity resolved: FDB range scan on `(0x03, sdHash)` is the dedup lookup) |
| PC-009 | Tombstone lifetime and lingering objects | Core Directory | this decision (tombstones in `0x07` subspace; GC task scans and clears tombstones older than `tombstoneLifetime`; strict serializable transactions eliminate the LWW-ambiguity that AD's tombstone model has) |
| PC-020 | NTDS.DIT backup/restore (VSS) | Core Directory | this decision (FDB backup-agent to S3; FDB `fastrestore`; no VSS; ADR-010 promoted from PARTIAL) |
| PC-062 | CA database transactional with PITR | Cert Service | this decision (CA database uses FDB; ADR-034 promoted from PARTIAL — the engine-specific sub-decision was PostgreSQL vs SQLite-WAL vs FoundationDB per ORQ-120/121; this decision picks FDB for consistency with the directory) |
| PC-109 | DC containerisation storage layout | Operations | this decision (DC container has no on-disk DIT; the DIT is in the FDB cluster, which is a separate StatefulSet; ADR-058 promoted from PARTIAL — the PVC-backed DIT model is replaced by the FDB-cluster-backed DIT model) |
| PC-110 | PITR runbooks | Operations | this decision (FDB native PITR; ADR-059 promoted from PARTIAL — the PITR mechanism is FDB's continuous backup with restore-to-timestamp) |
| PC-117 | DCSync (secondary effect) | Security | this decision (secret attributes stored in FDB with strict serializable transactions; DrSuapiReplicator reads secrets via FDB range scan; the attack surface is the DrSuapiReplicator's `EXOP_REPL_SECRETS` opnum, not the storage layer) |
| PC-108 | Multi-region AD replication latency (secondary effect) | Operations | this decision (FDB native multi-region mode provides synchronous cross-region replication; PDC-urgent-replication bottleneck eliminated for native mode; AD-interop mode inherits AD's PDC-urgent model) |

Partial ADRs that can now be promoted from PARTIAL to full:

- **ADR-003 (schema cache CoW)** — Open Question on storage-engine MVCC resolved: FDB's strict serializable transactions provide the CoW swap atomically; the generation counter is stored at `(0x04, 0x00)` and updated atomically with the new generation's serialized graph.
- **ADR-004 (SD dedup)** — Open Question on storage-engine-specific layout resolved: FDB range scan on `(0x03, sdHash)` is the dedup lookup; the `sdrefcount` column is an FDB atomic-add counter.
- **ADR-009 (constructed attributes)** — Open Question on `tokenGroups` cache strategy partially resolved: the optional write-time materialised cache (per ADR-002 §Decision) is a separate FDB subspace with O(1) reads; the cache invalidation is via FDB watches on the forward-link key. The full cache strategy (event-driven vs. read-time) is still Tier-2 ORQ-032, but the storage substrate is now specified.
- **ADR-010 (backup/restore)** — Open Question on backup API resolved: FDB backup-agent to S3; FDB `fastrestore`; no VSS. The `invocationId` reset on restore (per Decision 1) is a directory-layer concern, not a storage-layer concern.
- **ADR-034 (CA transactional DB)** — Open Question on engine choice resolved: FDB for the CA database. The CA database uses the same FDB cluster as the directory (separate subspace `0x09` for CA data) or a separate FDB cluster (for deployments that want CA isolation); the choice is per-deployment.
- **ADR-058 (container-native DCs)** — Open Question on storage layout resolved: DC container has no on-disk DIT; the DIT is in the FDB cluster (separate StatefulSet). The DC container is stateless (no PVC); the FDB cluster is stateful (PVC-backed).
- **ADR-059 (PITR runbooks)** — Open Question on PITR mechanism resolved: FDB native PITR via continuous backup with restore-to-timestamp. The runbook is `adrian-operator fdb restore --from s3://... --to <timestamp>`.
- **ADR-066 (AdminSDHolder declarative RBAC)** — Open Question on storage transactionality resolved: FDB strict serializable transactions make the declarative RBAC model's atomic policy updates possible.
- **ADR-067 (Sigstore supply chain)** — Open Question on storage for Sigstore metadata resolved: FDB subspace `0x0A` for Sigstore Rekor entries.

## Implementation impact

- **Core Directory**: The `FdbDirectoryStore` is the substrate for every directory operation. ~6 person-months for the `DirectoryStore` trait, the `FdbDirectoryStore` implementation, the tuple-layer key encoding, the migrations framework, and the testkit. The link-value store (ADR-001), the `memberOf` reverse index (ADR-002), the schema cache (ADR-003), the sdtable (ADR-004), and the constructed-attribute computation (ADR-009) all sit on top of `FdbDirectoryStore` and are unaffected by the engine choice.
- **KDC**: KDC's krbtgt key, KDS root key, and gMSA password material are stored as secret attributes in FDB; the KDC reads them via `DirectoryStore::get`. The KDC's PAC builder reads group memberships via the link-value store's reverse index (per ADR-002). No KDC-specific storage code.
- **Auth Provider**: Auth Provider is storage-agnostic; all auth-provider state is in the directory (user objects, computer objects, service-account objects).
- **Policy Engine**: Policy Engine's GPO storage is in the directory (GPO objects with `gPCFileSysPath` attributes); the actual policy files are in the Git-backed SYSVOL (per ADR-031). The Policy Engine does not directly use FDB.
- **Cert Service**: CA database uses FDB (subspace `0x09`); the CA's `Request`/`Certificate`/`CRL`/`KeyRecovery`/`KraRegistry`/`AuditLog` tables are FDB subspaces. ADR-034 promoted from PARTIAL.
- **Federation Gateway**: Federation Gateway's trust-store, claims-policy, and JWKS cache are stored in FDB (subspace `0x0B`). The Federation Gateway uses the `DirectoryStore` trait for all persistence.
- **File Gateway**: File Gateway's share-ACL cache is stored in FDB (subspace `0x0C`); the share-ACL cache is a projection of the directory's SD on share objects, refreshed via FDB watches on the SD subspace.
- **Client SDK**: Client SDK is storage-agnostic; clients speak LDAP/Kerberos/SMB and do not see FDB.
- **Cross-Platform Parity**: Cross-platform parity is storage-agnostic.
- **Operations**: The `adrian-operator` (ADR-058) manages FDB lifecycle (provision, scale, backup, restore, monitor). The operator's FDB management is ~3K lines of Rust on top of the `foundationdb` crate. The operator's runbooks (ADR-059) cover FDB failure modes.
- **Security**: FDB's strict serializable transactions eliminate the LWW-ambiguity attack surface that AD's eventual-consistency model has (an attacker cannot exploit a replication race to read a stale ACL). FDB's TLS-encrypted client-server transport (mandatory in the framework's deployment) eliminates the plaintext-replication attack surface that AD's RPC-based replication has.
- **Migration**: AD-to-framework migration (PC-126, PC-124, PC-127) uses the framework's IFM (install-from-media) path (per ADR-010 §Decision): the migration tool reads AD's `ntds.dit` via a one-time ESE read, translates to the framework's FDB tuple encoding, and writes to FDB in a single bulk-load transaction. The migration is offline (AD is read-only during the migration); the framework's parallel-run mode (per Decision 1) allows rollback.

## Cross-capability dependencies

This decision **enables** Decision 1 (replication protocol). The `Replicator` trait (Decision 1) operates on top of the `DirectoryStore` trait (this decision). FDB's strict serializable transactions make the DrSuapiReplicator's per-value replication-apply atomic (no replication-apply lock needed) and make the RaftReplicator's log-apply atomic. If this decision had chosen RocksDB (single-node), Decision 1's DrSuapiReplicator would need a custom replication-apply mutex (because RocksDB's transactions are per-Column-Family, not cross-cluster), and Decision 1's RaftReplicator would need to build its own distributed-transaction layer on top — both of which would have argued for Raft-only and against the hybrid replication decision.

This decision **depends on** Decision 3 (identity model) only weakly. The identity model's mapping table (UUID ↔ SID) is stored in FDB (subspace `0x0D`); the choice of identity model does not affect the storage engine. However, the identity model's RID pool allocation (per ADR-066, if SIDs are kept) uses FDB's atomic-add counter (the `atomic_op(AtomicOp::Add)` method on the `DirectoryStore` trait), which is FDB-native. If Decision 3 had chosen UUID-only (no SIDs), the RID pool subspace would not exist, but the storage engine choice would be unaffected.

This decision **influences** the KDC implementation decision (ORQ-042/043/044, Day 2). The KDC's krbtgt key is stored in FDB; the KDC's PAC builder reads group memberships from FDB via the link-value store. The KDC implementation is storage-agnostic, but the KDC's throughput is bounded by FDB's read throughput (which the spike measured at 500K reads/sec for a 9-process cluster). For a 1M-user forest with 10 AS-REQs/sec per user, the KDC's PAC builder reads ~10M rows/sec from FDB — well within the spike's measured throughput. The KDC implementation decision can proceed independently of this decision.

This decision **influences** the SMB server decision (ORQ-154/155, Day 2). SMB's share-ACL cache is stored in FDB; the SMB server's file-open path reads the share-ACL cache via the `DirectoryStore` trait. The SMB server choice (Samba vs. fresh) does not depend on the storage engine, but the SMB server's expected throughput is bounded by FDB's read throughput for ACL evaluations.

This decision **influences** the federation layer decision (ORQ-132/133/134, Day 2). The Federation Gateway's trust-store and JWKS cache are in FDB. If the federation layer wraps Keycloak (per Spike 6's expected recommendation), Keycloak's state is in its own database (typically PostgreSQL or MariaDB); the framework's Federation Gateway adapter syncs Keycloak's trust-store from FDB to Keycloak's database on change (via FDB watches). The federation layer decision can proceed independently of this decision.

## References

- [CONTEXT.md](./CONTEXT.md) — workshop briefing, ORQ-011/012/013/014 §lines 48–75
- [TRIAGE.md](../adr/TRIAGE.md) — deferred-problem rows PC-007, PC-008, PC-009, PC-020, PC-062, PC-109, PC-110, PC-117, PC-108
- [Catalog ORQs](../catalog/13-open-research-questions.md) — lines 48–51 (ORQ-011..014)
- [ADR-001: Linked Value Replication](../adr/ADR-001-linked-value-replication.md) — link-value store, `linktable` schema (now FDB subspace `0x02`)
- [ADR-002: memberOf back-link](../adr/ADR-002-memberof-back-link.md) — reverse index, optional write-time materialised cache (FDB subspace `0x0E`)
- [ADR-003: Schema cache CoW](../adr/ADR-003-schema-cache-cow.md) — generation counter (FDB key `(0x04, 0x00)`)
- [ADR-004: SD dedup](../adr/ADR-004-sd-deduplication.md) — sdtable (FDB subspace `0x03`, BLAKE3-256 dedup)
- [ADR-009: Constructed attributes](../adr/ADR-009-constructed-attributes.md) — tokenGroups cache (FDB subspace `0x0F`)
- [ADR-010: Backup/restore](../adr/ADR-010-backup-restore-snapshots.md) — FDB backup-agent, FDB `fastrestore`
- [ADR-034: CA transactional DB](../adr/ADR-034-transactional-db-pitr-reject-repair.md) — CA database on FDB (subspace `0x09`)
- [ADR-058: Container-native DCs operator](../adr/ADR-058-container-native-dcs-operator.md) — FDB cluster as separate StatefulSet
- [ADR-059: PITR backup DR runbooks](../adr/ADR-059-pitr-backup-dr-runbooks.md) — FDB native PITR
- [Workshop Decision 1: Replication protocol](./decision-01-replication-protocol.md) — `Replicator` trait operates on `DirectoryStore` trait
- [FoundationDB documentation](https://apple.github.io/foundationdb/) — FDB architecture, transaction manifest, multi-region mode
- [FoundationDB Rust client](https://github.com/foundationdb-rs/foundationdb-rust) — `foundationdb` crate (Apache-2.0)
- [FoundationDB Transaction Manifesto](https://apple.github.io/foundationdb/transaction-manifesto.html) — strict serializable isolation
- [Jepsen: FoundationDB](https://jepsen.io/analyses/foundationdb-6.2.7) — Aphyr's Jepsen analysis confirming strict serializability
- [CockroachDB on RocksDB](https://www.cockroachlabs.com/docs/stable/architecture/storage-layer.html) — comparison: CockroachDB's choice of RocksDB-plus-custom-distributed-transaction-layer
- [Snowflake on FoundationDB](https://www.snowflake.com/blog/snowflake-on-foundationdb/) — Snowflake's metadata layer on FDB at cloud scale
