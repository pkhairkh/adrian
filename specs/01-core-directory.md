---
title: "Core Directory Service — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Core Directory Service
tags: [spec, core-directory, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Core Directory Service — Technical Specification

## 1. Overview

The Core Directory Service is the substrate of the Adrian framework: it stores every object, attribute, link-value, security descriptor, schema definition, and tombstone; serves LDAP and LDAPS to AD-aware clients; replicates between DCs in either AD-interop (DRSUAPI) or native (Raft) mode; runs the copy-on-write schema cache; eliminates all five FSMO roles in native mode; and exposes the DSA (Directory System Agent) surface that every other capability — KDC, Policy Engine, Cert Service, Federation Gateway, File Gateway, Client SDK, Migration — consumes. It is the "1 of the 1-to-12 dependency graph": every other capability sits on top of the `DirectoryStore` and `Replicator` traits defined here.

This capability carries 22 ADRs: ADR-001 through ADR-010 (linked value replication, memberOf back-link, schema cache CoW, SD deduplication, well-known container GUIDs, AD LDAP controls, password change protocol, declarative replication topology, constructed attributes, backup/restore) and ADR-070 through ADR-081 (DRSUAPI replication server, hybrid Replicator trait, Global Catalog strategy, FoundationDB storage engine, tombstone lifetime, cross-domain move, FSMO replacement, DNS in directory, RID pool, schema model, multi-tenancy, instanceType/systemFlags). It resolves four of the framework's 23 blockers (PC-001 DRSUAPI replication, PC-002 USN/UTD vector, PC-004 member/memberOf back-link, PC-007 ESE storage replacement) plus four high-severity problems and is the longest pole on the v1 critical path.

The capability is implemented as **ten** Rust crates spread across four dependency layers in the framework workspace. Layer 0 holds the storage and schema trait crates (`adrian-storage-core`, `adrian-sid`, `adrian-schema-traits`); Layer 1 holds the replication and identity trait crates (`adrian-repl-core`, `adrian-identity-core`); Layer 2 holds the concrete implementations (`adrian-storage-fdb`, `adrian-repl-core` impls, `adrian-drsuapi`, `adrian-raft`, `adrian-schema-compiler`, `adrian-directory-service`, `adrian-identity-fdb`, `adrian-identity-ridpool`, `adrian-repl-health`). External dependencies include `foundationdb` (the only v1 storage engine), `openraft` (native replication), `rasn`/`rasn-kerberos` (ASN.1/NDR encoding for DRSUAPI), `ldap3` (server mode), and `tokio` (async runtime). The combined codebase is ~60K lines of Rust — larger than any other capability and roughly 30% of the framework total.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-storage-core` | 0 | `DirectoryStore` + `DirectoryTransaction` traits, `Key`/`Value`/`KeyRange` types, `DirectoryError` enum | ADR-073 |
| `adrian-sid` | 0 | `Sid` type (`S-1-5-21-…`), parse/serialize per MS-DTYP §2.4.2, SID↔UUID helpers | ADR-110 |
| `adrian-schema-traits` | 0 | `Projectable` derive macro, `SchemaProjection` type, `AttributeId`/`ClassId` types | ADR-078 |
| `adrian-repl-core` | 1 | `Replicator` trait, `ReplOperation` enum, `PropertyMetaDataExt`, `UtdVector` | ADR-001, ADR-071 |
| `adrian-identity-core` | 1 | `IdentityMapping` trait (`uuid_to_sid`, `sid_to_uuid`, `uuid_to_uid`, `uid_to_uuid`) | ADR-110 |
| `adrian-storage-fdb` | 2 | `FdbDirectoryStore` impl of `DirectoryStore`, FDB 7.3.x client, tuple-layer encoding, retry-on-conflict | ADR-073, ADR-010 |
| `adrian-identity-fdb` | 2 | `FdbIdentityMapping` impl of `IdentityMapping`, stored in FDB subspace `0x06` | ADR-110 |
| `adrian-identity-ridpool` | 2 | RID pool allocator for AD-interop mode; per-DC local counter in native mode | ADR-077 |
| `adrian-drsuapi` | 2 | `DrSuapiReplicator` impl of `Replicator`; fresh Rust MS-DRSR; gated by `ad-interop` feature | ADR-070, ADR-001 |
| `adrian-raft` | 2 | `RaftReplicator` impl of `Replicator`; openraft integration; single Raft group in v1 | ADR-071, ADR-076 |
| `adrian-schema-compiler` | 2 | Walks Schema NC, builds `Arc<SchemaProjection>` at boot, regenerates on `schemaUpdateNow` ≤500 ms | ADR-003, ADR-078 |
| `adrian-directory-service` | 2 | LDAP/LDAPS server (TCP/389, 636), DSA, `schemaModifyRequest` handler, GC listener (TCP/3268, 3269), AD LDAP controls (ADR-006) | ADR-002, ADR-005, ADR-006, ADR-009, ADR-072, ADR-074, ADR-075, ADR-076, ADR-079, ADR-080, ADR-081 |
| `adrian-repl-health` | 2 | Replication health probe, `repadmin /showutdvec` equivalent diagnostics | ADR-071 |

## 3. Key types and traits

```rust
// crates/adrian-storage-core/src/lib.rs

use async_trait::async_trait;
use uuid::Uuid;

/// Core storage abstraction. One implementation ships in v1
/// (`FdbDirectoryStore`); a future `RocksdbDirectoryStore` for
/// air-gapped edge deployments is gated by v2 demand.
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
    async fn commit(self: Box<Self>) -> Result<CommitResult, DirectoryError>;
    async fn rollback(self: Box<Self>) -> Result<(), DirectoryError>;
}

pub enum AtomicOp { Add(i64), BitOr(u64), BitAnd(u64), CompareAndClear(Value) }

pub struct Key(Vec<u8>); // tuple-layer-encoded
pub struct Value(Vec<u8>);
pub struct KeyRange { start: Key, end: Key }
pub struct ReadVersion(u64);
pub struct CommitResult { version: ReadVersion, bytes_written: u64 }
```

```rust
// crates/adrian-repl-core/src/lib.rs

use crate::{PropertyMetaDataExt, UtdVector};
use uuid::Uuid;

#[async_trait]
pub trait Replicator: Send + Sync {
    async fn get_changes(
        &self,
        nc_head: Uuid,
        cursor: ReplCursor,
    ) -> Result<Vec<ReplOperation>, ReplicationError>;
    async fn apply_changes(
        &self,
        batch: Vec<ReplOperation>,
    ) -> Result<ApplySummary, ReplicationError>;
    async fn update_utd_vector(
        &self,
        nc_head: Uuid,
        delta: UtdDelta,
    ) -> Result<(), ReplicationError>;
    async fn resolve_conflict(
        &self,
        conflict: ConflictRecord,
    ) -> Result<Resolution, ReplicationError>;
    async fn sync_metadata(&self, partner: &str) -> Result<MetadataSummary, ReplicationError>;
}

#[derive(Clone, Debug)]
pub enum ReplOperation {
    AddObject       { object: DirectoryObject, metadata: PropertyMetaDataExt },
    ModifyAttribute { object: Uuid, attr: AttributeId,
                      values: Vec<AttributeValueChange>,
                      metadata: PropertyMetaDataExt },
    DeleteObject    { object: Uuid, metadata: PropertyMetaDataExt },
    AddLink         { source: Uuid, link_id: u32, target: Uuid,
                      metadata: PropertyMetaDataExt },
    DeleteLink      { source: Uuid, link_id: u32, target: Uuid,
                      metadata: PropertyMetaDataExt },
    TombstoneGC     { object: Uuid, expired_at: SystemTime },
}

/// Highest `version` wins; tiebreak by latest `last_write_timestamp`;
/// then highest `origin_usn`; then lexicographically-highest
/// `origin_invocation_id`. Matches AD's resolver byte-for-byte.
pub struct PropertyMetaDataExt {
    pub version: u32,
    pub last_write_timestamp: SystemTime,
    pub origin_invocation_id: Uuid,
    pub origin_usn: u64,
    pub attribute_id: u32,
}
```

```rust
// crates/adrian-identity-core/src/lib.rs

use adrian_sid::Sid;
use uuid::Uuid;

#[async_trait]
pub trait IdentityMapping: Send + Sync {
    async fn uuid_to_sid(&self, uuid: Uuid) -> Result<Sid, IdentityError>;
    async fn sid_to_uuid(&self, sid: &Sid) -> Result<Uuid, IdentityError>;
    async fn uuid_to_uid(&self, uuid: Uuid) -> Result<u32, IdentityError>;
    async fn uid_to_uuid(&self, uid: u32) -> Result<Uuid, IdentityError>;
    async fn allocate_rid(&self) -> Result<u32, IdentityError>;
}

/// Greenfield deterministic algorithm:
///   uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536
/// Collisions on rare collisions handled by FDB atomic-add counter
/// re-allocating the colliding UUID's UID into the directory-stored
/// override table.
pub fn uuid_to_uid_deterministic(uuid: Uuid) -> u32 {
    let hi = uuid.as_u128() as u64;
    let lo = (uuid.as_u128() >> 64) as u64;
    let mixed = hi ^ lo;
    ((mixed % (2u64.pow(31) - 65536)) + 65536) as u32
}
```

```rust
// crates/adrian-directory-service/src/dsa.rs

pub struct Dsa {
    store: Arc<dyn DirectoryStore>,
    replicator: Arc<dyn Replicator>,
    identity: Arc<dyn IdentityMapping>,
    schema: Arc<ArcSwap<SchemaProjection>>,
    config: DsaConfig,
}

impl Dsa {
    pub async fn handle_ldap_request(
        &self,
        req: LdapRequest,
        ctx: &AuthContext,
    ) -> Result<LdapResponse, DsaError> {
        // 1. ACL-check against SD on every object touched.
        // 2. If modify, allocate USN, set PropertyMetaDataExt per value.
        // 3. If modify touches linked attr, write forward link (0x02)
        //    and reverse link atomically in same FDB transaction.
        // 4. On schemaModifyRequest, regenerate SchemaProjection
        //    via schema-compiler and ArcSwap-store.
        // 5. If AD-interop, queue DRSUAPI replication-trigger event.
        // 6. If native, Raft log entry already written by Replicator.
    }
}
```

## 4. Data model

The directory's logical model — objects with attributes, link-value pairs, security descriptors with dedup, schema cache with copy-on-write generations — is mapped onto FoundationDB's ordered KV store via a tuple-layer key encoding. Every directory object is stored as multiple key-value pairs: one per scalar attribute value, one per linked-attribute value (link-value subspace), one per SD reference (`sdtable` subspace), one per schema-cache generation (`schemacache` subspace). FDB's strict serializable transactions make every directory operation atomic: a single LDAP modify that adds a `member` value, updates the back-link, increments the group's `USNChanged`, and updates the UTD vector is one FDB transaction that commits atomically or rolls back atomically. There is no replication-apply lock, no LWW ambiguity at the storage layer, and no window where the forward-link is written but the back-link is not.

```
FDB subspace layout (per ADR-073, ADR-071, ADR-074, ADR-077, ADR-110):
  0x01 — objects
         key: (0x01, dnt:u64, attr_id:u32, value_idx:u32)
         val: <value_bytes> + <property_metadata_ext>
  0x02 — linktable
         key: (0x02, source_dnt:u64, link_id:u32, target_dnt:u64)
         val: (fIsPresent:bool, originInvocationID:uuid,
               originUSN:u64, version:u32, lastWriteTimestamp:u64)
         // reverse index for memberOf:
         key: (0x02, target_dnt:u64, link_id:u32, source_dnt:u64)
         val: fIsPresent:bool
         (written atomically with forward-link in same FDB tx)
  0x03 — sdtable (per ADR-004)
         key: (0x03, blake3_hash[0..32])
         val: (sdID:u64, sdRefCount:u32, sdBytes:<self-relative SD>)
         // GC: range scan 0x03, drop entries with sdRefCount == 0
  0x04 — schemacache (per ADR-003)
         key: (0x04, 0x00)             → current_generation:u64
         key: (0x04, generation:u64)   → serialized_schema_graph
         // CoW swap: increment generation atomic-add, write new graph,
         // then atomic-add the current pointer
  0x05 — utdvector
         key: (0x05, nc_head_uuid, origin_invocation_id)
         val: (highest_usn:u64, last_sync:u64)
  0x06 — identity_mapping (per ADR-110)
         key: (0x06, 0x01, uuid) → sid_bytes
         key: (0x06, 0x02, sid)  → uuid_bytes
         key: (0x06, 0x03, uid:u32) → uuid_bytes   // migrated mode only
         key: (0x06, 0x04, uuid) → uid:u32          // migrated mode only
  0x07 — tombstones (per ADR-074)
         key: (0x07, dnt:u64)
         val: <tombstone_record>
         // tombstoneLifetime default 180 days; GC sweeps by
         //    expiration = isDeleted_time + 180d
         // Recycle Bin: two-stage delete, isRecycled flag
  0x08 — auditlog
         key: (0x08, ts:u64, event_id:u32)
         val: <serialized OTel audit event>
  0x09 — ca_data (per ADR-034, used by Cert Service)
         key: (0x09, cert_serial:u64)
         val: <cert_record>
  0x0A — sigstore (per ADR-067, used by Operations)
         key: (0x0A, artifact_hash[0..32])
         val: <sigstore_bundle>
  0x0D — abe_index (per ADR-045, used by File Gateway)
         key: (0x0D, share_uuid, parent_dnt:u64, child_dnt:u64)
         val: (allowed_sids:Vec<Sid>, denied_sids:Vec<Sid>)
         // rebuilt on ACL change with 5-second eventual consistency
```

**Tuple-layer encoding.** Every key uses FDB's built-in `TuplePack`/`TupleUnpack` (type-safe, zero-cost). The `object_dnt` is a 64-bit DNT (directory number tag, equivalent to AD's `DNT` column); `attribute_id` is a 32-bit integer; `value_index` is a 32-bit integer for multi-valued attributes. The DNT counter lives at `(0x01, 0x00) → next_dnt:u64` and is allocated via FDB atomic-add.

**Tombstones** (per ADR-074): a tombstoned object is moved from subspace `0x01` to `0x07` with `isDeleted=true`, `isRecycled=false`, and `deletion_time`. After `tombstoneLifetime` (default 180 days, configurable), the GC sweep physically deletes the tombstone. The Recycle Bin (two-stage delete) sets `isRecycled=true` on first delete and physically deletes on second. Replication strictly preserves tombstones — a tombstone written on DC-A replicates to DC-B as a tombstone with identical metadata, preventing lingering-object divergence.

**SD dedup** (per ADR-004): security descriptors are content-hashed with BLAKE3-256 and stored once in subspace `0x03`; every object that uses the SD references it by hash. FDB range scans on `0x03` support periodic GC of zero-refcount SDs. This matches AD's `sdtable` design but with a modern hash (BLAKE3 vs MD5).

**Multi-tenancy** (per ADR-081): every subspace is prefixed with a 16-byte `tenant_uuid` when `multitenancy = true`. The framework's operator creates a tenant by allocating a UUID and prefixing all of the tenant's subspaces with it. Cross-tenant queries are rejected at the storage layer.

## 5. Protocol surface

```
LDAP/LDAPS wire protocol (per ADR-006):
  TCP/389  — LDAP (plaintext, requires StartTLS for non-anonymous bind)
  TCP/636  — LDAPS (TLS 1.3 mandatory; TLS 1.2 with backward-compat)
  TCP/3268 — Global Catalog (per ADR-072, PAS-filtered read-only view)
  TCP/3269 — Global Catalog over TLS

LDAP controls (AD-specific, per ADR-006):
  LDAP_SERVER_PAGED_OID                "1.2.840.113556.1.4.319"
  LDAP_SERVER_SORT_OID                 "1.2.840.113556.1.4.473"
  LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID "1.2.840.113556.1.4.521"  (ADR-075)
  LDAP_SERVER_TREE_DELETE_OID          "1.2.840.113556.1.4.805"
  LDAP_SERVER_ASQ_OID                  "1.2.840.113556.1.4.1504"
  LDAP_SERVER_DIRSYNC_OID              "1.2.840.113556.1.4.841"
  LDAP_SERVER_VERIFY_NAME_OID          "1.2.840.113556.1.4.1338"
  LDAP_SERVER_QUOTA_CONTROL_OID        "1.2.840.113556.1.4.1852"
  LDAP_SERVER_GET_STATS_OID            "1.2.840.113556.1.4.970"
  LDAP_SERVER_NOTIFICATION_OID         "1.2.840.113556.1.4.528"
  LDAP_SERVER_EXTENDED_DN_OID          "1.2.840.113556.1.4.529"

LDAP extended operations:
  StartTLS                  RFC 4511
  LDAP_SERVER_FAST_BIND_OID "1.2.840.113556.1.4.1781"
  LDAP_PWD_CHANGE_REQ       "1.3.6.1.4.1.4203.1.11.1" (RFC 3062)

DRSUAPI wire protocol (AD-interop mode, per ADR-070):
  TCP/135  — RPC endpoint mapper (epmv2)
  TCP/dyn  — DRSUAPI endpoint (registered with epmapper)
  UUID     — E3514235-4B06-11D1-AB04-00C04FC2DCD2 (DRSUAPI)
  Versions — 4.0 (Windows 2003+), 5.0 (Windows 2008+), 10.0 (Windows 2016+)
  Opnums   — 0x00 (Bind), 0x01 (Unbind), 0x03 (ReplicaSync),
             0x04 (GetNCChanges), 0x05 (ReplicaUpdateRefs),
             0x06 (ReplicaAdd), 0x07 (ReplicaDel), 0x08 (ReplicaModify),
             0x0C (GetMemberships), 0x0E (GetReplInfo),
             0x11 (AddEntry), 0x15 (GetMemberships2), 0x0D (CrackNames),
             0x12 (WriteAccountSpn)
  EXOP_REPL_SECRETS — ACL-gated (DS-Replication-Get-Changes-All
                       extended right required, audited per ADR-122)
  LZExpress compression — per MS-XCA, applied to REPLVALINF_V3 batches
```

## 6. Configuration

```toml
# /etc/adrian/dsa.toml — Core Directory Service configuration

[directory]
realm              = "corp.example.com"
forest_root        = "corp.example.com"
netbios_domain     = "CORP"
site               = "Default-First-Site-Name"
interop_mode       = "ad-interop"   # "ad-interop" | "native"
tombstone_lifetime_days = 180
recycle_bin_enabled     = true
multitenancy            = false

[storage]
engine             = "fdb"           # "fdb" only in v1; "rocksdb" v2
fdb_cluster_file   = "/etc/adrian/fdb.cluster"
fdb_api_version    = 730
fdb_max_retries    = 50
fdb_retry_budget_ms = 5000
backup_destination = "s3://adrian-backups/corp/"
pitr_window_days   = 30

[ldap]
listen_addr        = "0.0.0.0:389"
listen_addr_tls    = "0.0.0.0:636"
gc_listen_addr     = "0.0.0.0:3268"
gc_listen_addr_tls = "0.0.0.0:3269"
tls_cert_file      = "/etc/adrian/ldap.crt"
tls_key_file       = "/etc/adrian/ldap.key"
tls_min_version    = "1.2"
anonymous_bind     = false
signing_required   = true             # per ADR-021
channel_binding_required = true       # per ADR-021
max_connections    = 4096
paged_size_max     = 1000

[replication]
topology_file      = "/etc/adrian/topology.yaml"  # per ADR-008
partners           = ["dc01.corp.example.com", "dc02.corp.example.com"]
kcc_interval_secs  = 900
urgent_replication = true
compression        = "lzexpress"     # for DRSUAPI batches

[raft]                                # native mode only
election_timeout_ms  = 1500
heartbeat_interval_ms = 500
snapshot_threshold    = 100000
log_retention_entries = 1000000
members               = ["dc01", "dc02", "dc03"]

[schema]
schema_nc_dn       = "CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com"
compiler_regen_ms_max = 500           # per ADR-078
typed_projection   = true             # generate Rust accessors at boot
object_version_for_interop = true     # synthesize objectVersion for AD-interop

[fsmo]                                # native mode: all eliminated; ad-interop: emulated
schema_master_emulated      = true    # per ADR-076
domain_naming_master_emulated = true
pdc_emulator_emulated       = true
rid_master_emulated         = true    # native uses per-DC local counter
infrastructure_master_emulated = true

[observability]
prometheus_port    = 9100
otel_endpoint      = "http://otel-collector:4317"
log_level          = "info"
audit_log_path     = "/var/log/adrian/audit.log"
```

Environment variables override TOML: `ADRIAN_DSA__DIRECTORY__REALM`, `ADRIAN_DSA__STORAGE__FDB_CLUSTER_FILE`, etc. Feature flags: `ad-interop` (default-on; gates `adrian-drsuapi` and FSMO emulation), `enterprise-hsm` (default-off; gates PKCS#11 paths for krbtgt).

## 7. Error handling

```rust
// crates/adrian-storage-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("FDB transaction conflict (1020_not_committed); will retry")]
    TransactionConflict,
    #[error("FDB transaction too old (1007_transaction_too_old)")]
    TransactionTooOld,
    #[error("FDB commit unknown result (1031_commit_unknown_result)")]
    CommitUnknown,
    #[error("FDB cluster unavailable: {0}")]
    ClusterUnavailable(String),
    #[error("schema mismatch: object {object_dn} references attr {attr_id} not in projection")]
    SchemaMismatch { object_dn: String, attr_id: u32 },
    #[error("InvocationID mismatch on partner {partner}: expected {expected}, got {actual}")]
    InvocationIdMismatch { partner: String, expected: Uuid, actual: Uuid },
    #[error("lingering object detected: {dn} on partner {partner}; quarantine required")]
    LingeringObject { dn: String, partner: String },
    #[error("USN rollback detected on partner {partner}; self-quarantining")]
    UsnRollback { partner: String },
    #[error("ACL denied: {0}")]
    AclDenied(String),
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// crates/adrian-repl-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    #[error("replication partner {0} unreachable")]
    PartnerUnreachable(String),
    #[error("UTD vector too old on partner {0}; full sync required")]
    UtdTooOld(String),
    #[error("DRSUAPI bind failed to {partner}: {reason}")]
    DrsuapiBindFailed { partner: String, reason: String },
    #[error("EXOP_REPL_SECRETS denied for principal {principal} on {target}")]
    ExopDenied { principal: String, target: String },
    #[error("Raft proposal rejected: {0}")]
    RaftRejected(String),
    #[error("schema conflict on {attr_id}: {detail}")]
    SchemaConflict { attr_id: u32, detail: String },
    #[error("storage layer: {0}")]
    Storage(#[from] DirectoryError),
}
```

**Error propagation strategy.** Library crates use `thiserror` enums; binary entry points (`adrian-operator`, `adrian-cli`) use `anyhow`. The boundary is strict: `anyhow` is permitted only in `main()` and integration tests. Transient errors (transaction conflict, partner unreachable, UTD too old) are retried automatically with exponential backoff via the `backon` crate; permanent errors (schema mismatch, InvocationID mismatch, lingering object) surface to the operator via the audit log and the CLI's `--verbose` flag. The framework's DC self-quarantines on USN rollback detection (per ADR-074) — it stops serving replication but continues serving LDAP read traffic with a degraded-state banner in the audit log.

User-facing error messages are written for senior operators: terse, technical, actionable. Example: `error: USN rollback detected on partner dc03.corp.example.com (last_seen_usn=12345, current_usn=12200). Self-quarantining replication. Run \`adrian-cli fdb restore --from s3://...\` to restore from backup.`

## 8. Testing strategy

```
Unit tests — per-crate, in src/*.rs #[cfg(test)] modules
  Mock DirectoryStore / Replicator / IdentityMapping in adrian-test-harness
  Target: ≥80% line coverage per crate (cargo-tarpaulin enforced in CI)
  Runtime: <60 seconds for entire workspace (parallelized)
  Coverage:
    - tuple-layer key encoding round-trips (proptest, 50 cases per subspace)
    - SD dedup BLAKE3 collision detection
    - schema cache CoW generation pointer atomic swap
    - memberOf back-link atomic write (forward + reverse in same tx)
    - tombstone GC sweep with tombstoneLifetime boundary
    - UTD vector merge semantics

Integration tests — tests/integration/, real FDB (in-process), tokio rt-multi-thread
  Runtime: ~10 minutes for full suite
  Coverage:
    - LDAP bind + search + modify + delete sequence
    - LDAPS with mutual TLS
    - All 11 AD LDAP controls (ADR-006) with real clients (ldapsearch)
    - schemaModifyRequest → SchemaProjection regen ≤500 ms
    - Cross-domain move (ADR-075) preserves UUID-stable identity
    - GC listener (TCP/3268) returns PAS-filtered results
    - Tombstone creation, replication to partner, GC sweep
    - Multi-tenant isolation (tenant-A cannot read tenant-B objects)

Interop tests — tests/interop/, Docker Compose with real third-party services
  Runtime: ~2 hours full matrix
  Matrix:
    - Windows Server 2022 DC ↔ framework DC (DRSUAPI replication both directions)
    - Samba 4.20 smbclient + samba-tool drs against framework DC
    - OpenLDAP ldapsearch/ldapmodify against framework LDAP server
    - FreeIPA 4.10 cross-realm trust establishment
  Critical tests:
    - REPLVALINF_V3 byte-identity (Windows ↔ framework) — captures
      Windows-issued replication batch and framework-issued batch for
      same NC head, asserts byte-identity modulo two documented
      divergences (USN indexing, InvocID encoding)
    - LDAP search-result-reference chain across domain boundaries
    - DCSync from Windows DC ↔ framework DC (audited per ADR-122)
    - Tombstone replication between Windows DC and framework DC

Property-based tests — proptest in src/*.rs #[cfg(test)] modules
  Parsers tested:
    - tuple-layer Key encoding (round-trip)
    - PropertyMetaDataExt serialization
    - REPLVALINF_V3 NDR encoding (rasn)
    - UTD vector serialization
    - SID ↔ UUID mapping (deterministic algorithm)
  Corpus: ~500 property tests across the workspace
```

## 9. Implementation phases

```
MVP (Phase 1) — 23 blockers, this capability contributes 4:
  - ADR-073: FoundationDB storage engine, FdbDirectoryStore, tuple-layer
  - ADR-071: Replicator trait (interface only); DrSuapiReplicator ships first
  - ADR-070: DRSUAPI server, opnums 0x00/01/03/04/05, EXOP_REPL_SECRETS
  - ADR-001: Linked value replication in 0x02 subspace
  - ADR-002: memberOf back-link as DSA-computed reverse index
  - ADR-004: SD deduplication via BLAKE3 in 0x03 subspace
  - ADR-003: Schema cache CoW with generation pointer
  - ADR-078: Hybrid schema; LDAP authoritative; typed projection at boot
  - ADR-006: All 11 AD LDAP controls + extended ops
  - ADR-007: kpasswd primary password-change protocol
  - ADR-074: Tombstones in 0x07, tombstoneLifetime=180d, GC sweep
  - ADR-077: RID pool allocator (AD-interop) / per-DC local counter (native)
  - ADR-010: FDB-native backup_agent + fastrestore (promoted from PARTIAL)

v1 (Phase 2) — 64 high ADRs, this capability contributes ~10:
  - ADR-071: RaftReplicator (openraft), single Raft group, UTD synthesis
  - ADR-076: FSMO elimination in native mode (5 roles); emulation in interop
  - ADR-072: GC as FDB projection (native) or PAS-replicated (interop)
  - ADR-075: Cross-domain move via LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID
  - ADR-079: AD-integrated DNS zones in FDB subspace (per-zone)
  - ADR-080: instanceType / systemFlags bitmasks preserved
  - ADR-081: Multi-tenancy via FDB subspace prefix
  - ADR-008: Declarative YAML replication topology (replaces KCC auto-topology)
  - ADR-009: Constructed attributes via DSA-side computation
  - ADR-005: Well-known container GUIDs (Users, Computers, Domain Controllers)

v2 (Phase 3) — 33 medium ADRs, this capability contributes ~3:
  - Per-NC Raft sharding (Tier-2 ORQ-024/025; not yet a numbered ADR)
  - RocksDB engine for air-gapped edge (`RocksdbDirectoryStore`)
  - Multi-tenancy hardening (cross-tenant query audit, per-tenant FDB tenant)
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `foundationdb` | 0.9 | Official FDB Rust client; `tokio` feature; FDB 7.3.x server |
| `openraft` | 0.9 | Raft consensus for native replication; tokio-native |
| `rasn` | 0.22 | ASN.1 + NDR encoding for DRSUAPI REPLVALINF_V3 |
| `rasn-kerberos` | 0.22 | Kerberos primitives (used by replication security) |
| `ldap3` | 0.11 | LDAP server-mode + client for integration tests |
| `tokio` | 1 | Async runtime; `rt-multi-thread` feature |
| `async-trait` | 0.1 | `#[async_trait]` on `DirectoryStore`, `Replicator`, `IdentityMapping` |
| `uuid` | 1.10 | `Uuid` type with `v7` feature for UUIDv7 primary keys |
| `thiserror` | 1 | Error enums in every library crate |
| `anyhow` | 1 | Top-level error handling in binaries only |
| `backon` | 1 | Retry-with-backoff for transient errors |
| `blake3` | 1 | SD deduplication hash (subspace 0x03) |
| `arc-swap` | 1 | CoW schema cache pointer swap (per ADR-003) |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel instrumentation (per ADR-057) |
| `prometheus` | 0.13 | Metrics exporter |
| `serde` / `serde_json` / `serde_yaml` | 1 | Config + topology parsing |
| `clap` | 4 | CLI parsing for `adrian-cli` (Layer 4) |
| `proptest` | 1 | Property-based tests for parsers |
| `backtrace` | 0.3 | Stack traces on panic (invariant violations) |

## 11. References

- ADRs: [ADR-001](../adr/ADR-001-linked-value-replication.md), [ADR-002](../adr/ADR-002-memberof-back-link.md), [ADR-003](../adr/ADR-003-schema-cache-cow.md), [ADR-004](../adr/ADR-004-sd-deduplication.md), [ADR-005](../adr/ADR-005-well-known-container-guids.md), [ADR-006](../adr/ADR-006-ad-ldap-controls.md), [ADR-007](../adr/ADR-007-password-change-protocol.md), [ADR-008](../adr/ADR-008-declarative-replication-topology.md), [ADR-009](../adr/ADR-009-constructed-attributes.md), [ADR-010](../adr/ADR-010-backup-restore-snapshots.md), [ADR-070](../adr/ADR-070-drsuapi-replication-protocol.md), [ADR-071](../adr/ADR-071-replication-model.md), [ADR-072](../adr/ADR-072-global-catalog-strategy.md), [ADR-073](../adr/ADR-073-storage-engine.md), [ADR-074](../adr/ADR-074-tombstone-lifetime-lingering-objects.md), [ADR-075](../adr/ADR-075-cross-domain-move.md), [ADR-076](../adr/ADR-076-fsmo-role-replacement.md), [ADR-077](../adr/ADR-077-foreign-security-principals-rid-pool.md), [ADR-078](../adr/ADR-078-schema-model.md), [ADR-079](../adr/ADR-079-dns-in-directory.md), [ADR-080](../adr/ADR-080-instancetype-systemflags-bitmasks.md), [ADR-081](../adr/ADR-081-multi-tenancy.md)
- Workshop decisions: [Decision 1 — Replication Protocol](../workshop/decision-01-replication-protocol.md), [Decision 2 — Storage Engine](../workshop/decision-02-storage-engine.md), [Decision 3 — Identity Model](../workshop/decision-03-identity-model.md), [Decision 4 — Schema Model](../workshop/decision-04-schema-model.md)
- KB files: [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md), [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md), [docs/02-protocols/06-rpc-dcerpc-ms-drsr.md](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md), [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md)
- RFCs: RFC 4510-4519 (LDAP), RFC 4511 (LDAP protocol), RFC 3062 (LDAP password modify)
- MS-* specs: MS-ADTS (Active Directory Technical Specification), MS-DRSR (DRSUAPI), MS-DTYP (SID/SD types), MS-XCA (LZExpress compression)
