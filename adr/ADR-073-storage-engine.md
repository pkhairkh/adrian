---
title: "ADR-073: FoundationDB as Sole Storage Engine for All DCs"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-007
severity: blocker
unblocked_by: Workshop Decision 2 (ORQ-011/012/013/014)
tags: [adr, core-directory, storage, foundationdb, fdb, transactions, rust]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-02-storage-engine.md
  - ../catalog/01-core-directory.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/00-overview/02-ad-architecture.md
  - ./ADR-010-backup-restore-snapshots.md
last_updated: 2026-08-13
---

# ADR-073: FoundationDB as Sole Storage Engine for All DCs

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-011/012/013/014. It is now unblocked by [Workshop Decision 2 (FoundationDB as Primary Storage Engine for All DCs)](../workshop/decision-02-storage-engine.md). This ADR promotes ADR-010 (Backup/Restore) from PARTIAL to full by specifying the FDB-native backup mechanism.

## Context

AD stores the DIT in `ntds.dit`, an ESE (Extensible Storage Engine, "Jet Blue") database with 32 KB page size (Server 2012+), implemented by `esent.dll`. ESE provides ISAM-style transactional access via `JetInit3`, `JetAttachDatabase`, `JetBeginTransaction`, `JetPrepareUpdate`, `JetSetColumn`, `JetUpdate`, `JetCommitTransaction`. The DIT contains ~50 tables: `datatable` (one row per AD object), `linktable` (linked-value attributes), `sdtable` (security descriptor dedup cache), `cursor` (per-NC UTD vector), `msysobjects` (ESE catalog), per [PC-007](../catalog/01-core-directory.md#pc-007--ese--jet-blue-database-is-windows-only-framework-must-pick-a-new-storage-engine) and [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md).

Open-source alternatives evaluated: Samba uses TDB (hash-file, no transactions); FreeIPA/389-DS uses BerkeleyDB; OpenLDAP uses LMDB (single-writer). Modern LSM-tree stores (RocksDB, LevelDB) are fast for writes but require compaction tuning. None is identical to ESE in transactional semantics, page-level checksums, SD dedup, or replication integration.

The framework must pick a storage engine that supports: (a) transactional writes with `BEGIN/COMMIT/ROLLBACK` and WAL; (b) per-attribute metadata storage (`PROPERTY_META_DATA_EXT` per attribute per object); (c) SD deduplication (`sdtable`); (d) page-level checksums for corruption detection; (e) online backup; (f) crash recovery (WAL replay on boot); (g) horizontal write scaling for multi-DC active-active (per Decision 1's Raft native mode); (g) multi-region synchronous replication for PC-108.

**Unblocking decision.** [Workshop Decision 2](../workshop/decision-02-storage-engine.md) selected FoundationDB 7.3.x as the sole storage engine for all DCs in v1, with the official `foundationdb` Rust crate (Apache-2.0, maintained by Apple's FDB team). A `DirectoryStore` trait abstraction exists, but only one implementation — `FdbDirectoryStore` — ships in v1. The decision rejected SQLite (single-writer ~5K writes/sec), RocksDB (single-node, requires building distributed-transaction layer), and Custom (multi-year investment). This ADR translates Decision 2 into the concrete Core Directory storage implementation.

## Decision

The framework SHALL use FoundationDB 7.3.x as the storage engine for all DCs in v1. Every DC — AD-interop or native, 100-DC enterprise forest or single-DC edge — runs against an FDB cluster. For multi-DC deployments, the DC process connects to a shared FDB cluster (3–9 storage processes for mid-size, 15+ for large). For single-DC edge deployments, a single-process FDB cluster runs co-located. FDB is a Tier-0 operational dependency managed by the framework's operator (ADR-058).

The directory's logical model — objects with attributes, link-value pairs (per ADR-001), security descriptors with dedup (per ADR-004), schema cache with copy-on-write generations (per ADR-003) — is mapped onto FDB's ordered KV store via a tuple-layer key encoding. Every directory object is stored as a tuple of key-value pairs: one pair per scalar attribute value, one pair per linked-attribute value (link-value store subspace), one pair per SD reference (`sdtable` subspace), one pair per schema-cache generation (`schemacache` subspace). FDB's strict serializable transactions make every directory operation atomic: a single LDAP modify that adds a `member` value, updates the back-link, increments the group's `USNChanged`, and updates the UTD vector is one FDB transaction that commits atomically or rolls back atomically. There is no replication-apply lock, no LWW ambiguity at the storage layer, and no window where the forward-link is written but the back-link is not.

**Concrete specification**:

- The framework SHALL depend on the official `foundationdb` Rust crate (Apache-2.0). Crate version SHALL match the FDB server version (client/server version skew is not supported).
- The framework SHALL define a `DirectoryStore` trait in `adrian-storage-core`:
  ```rust
  #[async_trait]
  pub trait DirectoryStore: Send + Sync {
      async fn begin_tx(&self) -> Result<Box<dyn DirectoryTransaction>, DirectoryError>;
      async fn snapshot(&self) -> Result<Box<dyn DirectoryStore>, DirectoryError>;
      async fn get_read_version(&self) -> Result<ReadVersion, DirectoryError>;
  }
  #[async_trait]
  pub trait DirectoryTransaction: Send + Sync {
      async fn get(&self, key: Key) -> Result<Option<Value>, DirectoryError>;
      async fn get_range(&self, range: KeyRange) -> Result<Vec<(Key, Value)>, DirectoryError>;
      async fn put(&self, key: Key, value: Value) -> Result<(), DirectoryError>;
      async fn delete(&self, key: Key) -> Result<(), DirectoryError>;
      async fn atomic_op(&self, key: Key, op: AtomicOp) -> Result<(), DirectoryError>;
      async fn commit(self) -> Result<CommitResult, DirectoryError>;
      async fn rollback(self) -> Result<(), DirectoryError>;
  }
  ```
- The `FdbDirectoryStore` SHALL implement `DirectoryStore` by mapping each method to the corresponding FDB transaction API. `begin_tx` creates an FDB `Transaction`; `commit_tx` calls `Transaction::commit()`; `get` calls `Transaction::get()`; `put` calls `Transaction::set()`; `delete` calls `Transaction::clear()`; `get_range` calls `Transaction::get_range()`; `atomic_op` calls `Transaction::atomic_op(... AtomicOp::Add)`.
- The key encoding SHALL use FDB's tuple layer: `(subspace, object_dnt, attribute_id, value_index) → value_bytes`. Subspaces are: `0x01` objects, `0x02` linktable, `0x03` sdtable, `0x04` schemacache, `0x05` utdvector, `0x06` ridpool, `0x07` tombstones, `0x08` auditlog, `0x09` ca_data, `0x0A` sigstore, `0x0D` identity_mapping (per Decision 3). `object_dnt` is a 64-bit DNT (directory number tag, equivalent to AD's `DNT` column); `attribute_id` is a 32-bit integer; `value_index` is a 32-bit integer for multi-valued attributes.
- The `sdtable` subspace (per ADR-004) SHALL use BLAKE3-256 as the dedup hash. FDB key: `(0x03, sdHash[0..32]) → (sdID, sdrefcount, sdBytes)`. FDB range scans on the `0x03` subspace support periodic GC of zero-refcount SDs.
- The linktable subspace (per ADR-001) SHALL use the key `(0x02, linkDNT, linkID, backlinkDNT) → (fIsPresent, originInvocationID, originUSN, version, lastWriteTimestamp)`. The reverse index for `memberOf` queries is `(0x02, backlinkDNT, linkID, linkDNT) → fIsPresent`, maintained atomically in the same transaction as the forward-link write.
- The schema-cache subspace (per ADR-003) SHALL use the key `(0x04, generation) → serialized_schema_graph`. The generation counter is a 64-bit integer stored at `(0x04, 0x00) → generation_u64`. The copy-on-write swap is an FDB atomic transaction.
- Backup SHALL use FDB's native backup agent (`backup_agent`) writing to S3/GCS/Azure Blob/MinIO. Restore SHALL use FDB's `fastrestore` tool. PITR SHALL use FDB's native continuous backup with restore-to-timestamp. This promotes ADR-010 from PARTIAL to full — the backup API is now FDB-native.
- The framework's operator (ADR-058) SHALL manage the FDB cluster lifecycle: `adrian-operator fdb provision --size <n>`, `adrian-operator fdb scale --size <n>`, `adrian-operator fdb backup --destination s3://...`, `adrian-operator fdb restore --from s3://... --to <timestamp>`. The operator SHALL monitor FDB cluster health (available storage, process rate, storage lag, log server latency) and surface alerts via the framework's Prometheus/OTel stack (ADR-057).
- For single-DC edge deployments, the framework SHALL support a co-located FDB cluster (single fdbserver process on the same host as the DC process). The operator configures `single_satellite_tunnel=disabled`, `redundancy_mode=single`. No fault tolerance; intended for branch offices with <1K users.
- For multi-DC deployments, the framework SHALL recommend a minimum 3-node FDB cluster (3 storage processes, 3 log servers, 1 coordinator — FDB's minimum fault-tolerant configuration). The operator SHALL warn if `--allow-single-node` is not passed for production deployments.
- For multi-region deployments, the framework SHALL use FDB's native multi-region mode (`usable_regions=2`, `regions=2`), providing synchronous replication across two regions with automatic failover. This is the substrate for PC-108 (multi-region AD replication latency).
- Performance targets: a single FDB storage process SHALL sustain ≥15K writes/sec/DC and ≥50K reads/sec/DC. A 9-process FDB cluster SHALL sustain ≥100K writes/sec aggregate and ≥500K reads/sec aggregate. Backup of a 10M-object directory SHALL complete in <30 minutes. Restore SHALL complete in <2 hours. PITR restore-to-timestamp SHALL complete in <1 hour for a 24-hour-old restore point.
- The framework SHALL use the `foundationdb` crate's `tokio` feature flag (not `async-std`). The FDB `Network` driver runs as a tokio task spawned at startup and joined at shutdown.
- The `FdbDirectoryStore`'s retry loop SHALL retry on `1020_not_committed` (transaction conflict) and `1007_transaction_too_old` (timeout) per FDB's recommended retry-on-conflict pattern. Permanent errors (`1031_commit_unknown_result`, cluster unavailable, schema corruption) are surfaced to the caller.

## Rationale

The storage engine is the substrate for every Core Directory and Operations decision. It determines throughput (10K writes/sec/DC v1 target), transactional semantics (link-value store and schema-cache both require atomic multi-key transactions), backup/restore (ADR-010), tombstone GC (PC-009), sdtable design (PC-008, ADR-004), DC containerisation (ADR-058), and PITR runbooks (ADR-059). Switching engines post-MVP requires a full data migration at multi-hour or multi-day cost for production-scale directories. The storage choice is, in practice, irreversible.

Spike 2 benchmarked FDB 7.1, RocksDB 8.x, and SQLite 3.42 WAL. SQLite was too slow (4.2K writes/sec) and too single-node. RocksDB was faster single-node (19K writes/sec) but required building a custom distributed-transaction layer — duplicating FDB's logic at higher cost and higher defect risk. FDB's strict serializable transactions simplify the directory layer (no replication-apply lock, no LWW ambiguity at the storage layer, atomic multi-key updates). FDB's native multi-region mode eliminates the need for the framework to build cross-region replication.

FoundationDB is used in production by Apple (iCloud, App Store, iTunes — petabyte-scale, multi-region), Snowflake (metadata layer), and others. The `foundationdb` Rust crate is officially maintained by Apple engineers, version-tracked with FDB server releases. FDB's strict serializable isolation is documented in the FDB Transaction Manifesto and validated by Jepsen testing (Aphyr's Jepsen reports confirm strict serializability under network partitions, clock skew, and process crashes). CockroachDB and TiKV both chose RocksDB-plus-custom-distributed-transaction-layer and have spent years stabilising that layer; the framework's choice to use FDB instead is a deliberate decision to *not* build a distributed-transaction layer.

## Consequences

**Positive**: FDB strict serializable transactions simplify the directory layer — every multi-key update is atomic. FDB's native multi-region mode eliminates the need to build cross-region replication. FDB's native backup-to-S3 and PITR eliminate the need for VSS or custom backup tooling. FDB's official Rust client is mature and Apple-maintained. The `DirectoryStore` trait abstraction preserves v2 optionality (a future `RocksdbDirectoryStore` for air-gapped deployments).

**Negative**: FDB is a Tier-0 operational dependency — every DC depends on a healthy FDB cluster. An FDB cluster outage is a directory outage. The framework's operator (ADR-058) must manage FDB lifecycle alongside DC lifecycle. Runbooks must cover FDB failure modes (storage lag, log server saturation, coordinator loss, region failover). A minimum production FDB cluster is 3 storage + 3 log + 1 coordinator (typically 6 VMs) — heavier than a single-node RocksDB deployment for small deployments.

**Neutral**: The `DirectoryStore` trait is the v2 seam where `RocksdbDirectoryStore` would slot in for air-gapped or resource-constrained edge deployments where a 3-node FDB cluster is infeasible. None is planned for v1; deferred to v2 gated by real customer demand.

**Cost**: ~6 person-months for the `DirectoryStore` trait, the `FdbDirectoryStore` implementation, the tuple-layer key encoding, the migrations framework, and the testkit. Link-value store (ADR-001), `memberOf` reverse index (ADR-002), schema cache (ADR-003), sdtable (ADR-004), and constructed-attribute computation (ADR-009) all sit on top and are unaffected by the engine choice.

**Operational impact**: FDB cluster lifecycle is operator-managed. Backup/restore is `adrian-operator fdb backup/restore` CLI. PITR is `adrian-operator fdb restore --to <timestamp>`. FDB cluster health is monitored via Prometheus/OTel.

## Alternatives Considered

### Alternative 1: SQLite WAL

Mature, embedded, single-file, zero operational dependency. Suitable for PoCs and very small deployments (<1K users). Rejected as primary: (1) single-writer throughput ~5K writes/sec is below the 10K target; (2) single-node forecloses multi-DC active-active; (3) no native multi-region; (4) PITR requires manual WAL archive. SQLite is documented as a "development only" option — engineers can run the framework against SQLite for local testing via `InMemoryDirectoryStore`.

### Alternative 2: RocksDB

LSM-tree, embedded, scales to 10M objects on a single node. Used by CockroachDB and TiKV as the per-node storage beneath their distributed-transaction layers. Faster than FDB for single-node operations (19K writes/sec in spike). Rejected for v1: (1) single-node requires building a consensus layer on top (which Decision 1 specifies as Raft, but Raft-on-RocksDB duplicates FDB's distributed-transaction logic); (2) RocksDB's tuning surface (compaction, bloom filters, block cache, write-buffer size, level vs. universal compaction) is operationally heavy — conflicts with the framework's "Kubernetes-operator-managed" operability target; (3) PITR requires manual WAL archive. Documented as v2 candidate for air-gapped edge deployments.

### Alternative 3: Custom storage engine

Full control over transactional semantics, backup model, replication log format. Multi-year engineering investment (~10 person-years for production-grade ordered KV store with strict serializable transactions: B-Tree, MVCC, WAL, checkpoint, recovery, compaction). High defect risk (silent data corruption is the worst failure mode). Rejected: none of FDB's limitations are hard blockers for the framework's workload; the investment is unjustified.

## Open Questions

- For FDB tuple-layer key encoding, should the framework use the `foundationdb` crate's built-in `TuplePack`/`TupleUnpack` or a custom encoding? Default: built-in (type-safe, zero-cost). Confirm in implementation.
- For FDB cluster sizing, what is the recommended cluster size for a 10M-object forest? Spike 2 suggests 9 storage processes (3 regions × 3 processes). Confirm with a customer-scale benchmark.
- For the v2 `RocksdbDirectoryStore`, what is the migration path from FDB? LDIF export/import is one option; FDB-to-RocksDB direct copy is another. Defer to v2.

## Cross-capability impact

- **Core Directory**: `FdbDirectoryStore` is the substrate for every directory operation. Link-value store, `memberOf` reverse index, schema cache, sdtable, constructed-attribute computation all sit on top and are unaffected.
- **KDC**: KDC's krbtgt key (per ADR-015) is stored as a secret attribute in FDB; `DrSuapiReplicator` encrypts secrets with the DC's `dBCSPwd` (AD-interop), `RaftReplicator` encrypts with TLS mutual-auth keys (native).
- **Cert Service**: CA database (per ADR-034) uses FDB subspace `0x09` (or a separate FDB cluster for CA isolation; per-deployment choice).
- **File Gateway**: DFS-N (per ADR-044) is independent of storage. SYSVOL access uses the framework's replication.
- **Operations**: FDB cluster lifecycle, backup/restore, PITR runbooks (per ADR-059). FDB cluster health is a readiness gate for the `adrian-operator` (ADR-058).
- **Security**: FDB's strict serializable transactions eliminate the LWW-ambiguity attack surface that AD's tombstone model has. Secret attributes (passwords, krbtgt) are stored encrypted; `DrSuapiReplicator` and `RaftReplicator` both encrypt at rest.

## References

- [PC-007](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 2 — FoundationDB Storage Engine](../workshop/decision-02-storage-engine.md) — unblocking decision
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — ESE table schema, transaction commit path, USN allocation
- [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) — `NTDS.DIT` internal layout, ESE page size, VSS writer GUID
- [FoundationDB](https://www.foundationdb.org/) — FDB project
- [foundationdb Rust crate](https://github.com/foundationdb-rs/foundationdb-rust) — official Rust client
- [FDB Transaction Manifesto](https://apple.github.io/foundationdb/transaction-manifesto.html) — strict serializability
- [Aphyr Jepsen: FoundationDB](https://aphyr.com/posts/354-jepsen-foundationdb) — Jepsen testing results
- [ADR-010: Backup/Restore Snapshots](./ADR-010-backup-restore-snapshots.md) — promoted from PARTIAL; backup API is FDB-native
- [ADR-003: Schema Cache CoW](./ADR-003-schema-cache-cow.md) — schema-cache subspace
- [ADR-004: SD Dedup](./ADR-004-sd-deduplication.md) — sdtable subspace
