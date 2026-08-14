//! # adrian-storage-fdb
//!
//! FoundationDB implementation of [`DirectoryStore`] for the Adrian framework.
//!
//! Per ADR-073 and Workshop Decision 2, FoundationDB 7.3.x is the sole
//! storage engine for v1. The FDB tuple-layer key encoding is:
//!
//! ```text
//! (subspace, object_dnt, attribute_id, value_index) → value_bytes
//! ```
//!
//! where `subspace` is one of the values in
//! [`adrian_storage_core::Subspace`], `object_dnt` is a 64-bit DNT, and
//! `attribute_id` is a 32-bit integer from the schema cache.
//!
//! ## Two code paths (gated by the `fdb` feature flag)
//!
//! The crate always compiles, with two distinct code paths:
//!
//! 1. **Default (no `fdb` feature)** — [`FdbDirectoryStore`] wraps an
//!    [`InMemoryDirectoryStore`] from `adrian-storage-testkit` and uses its
//!    low-level [`ReadTxn`] / [`WriteTxn`] interface to store tuple-layer-
//!    encoded rows in an in-process `BTreeMap`. This exercises the *exact
//!    same* tuple-layer key encoding as the real FDB code path, but requires
//!    neither libclang at build time nor a running FDB cluster at runtime.
//!    All crate-level unit tests run against this code path.
//!
//! 2. **`fdb` feature** — a real `foundationdb::Database`-backed code path
//!    is compiled in. [`FdbDirectoryStore::connect`] opens the database,
//!    and [`FdbTxn`] wraps a real `foundationdb::Transaction`. The high-level
//!    `DirectoryStore` methods (`get` / `get_by_dn` / `put` / `delete`) use
//!    the *same* tuple-layer key encoding helpers from
//!    `adrian-storage-core` as the fallback path. Integration tests against
//!    a real FDB cluster are `#[ignore]`-gated; run them with
//!    `cargo test --features fdb -- --ignored` and a running FDB instance
//!    (e.g. `docker run -e FDB_NETWORKING_MODE=host -p 4500:4500/udp
//!    foundationdb/foundationdb:7.3.30`).
//!
//! ## Subspaces (per ADR-073 §Decision and Decision 2 §Decision)
//!
//! | Subspace | Purpose | ADR |
//! |----------|---------|-----|
//! | `0x01`   | directory objects (per-attribute-value rows) | ADR-073 |
//! | `0x02`   | link-value store (forward + reverse indexes) | ADR-001 |
//! | `0x03`   | security-descriptor dedup table (BLAKE3-256) | ADR-004 |
//! | `0x04`   | schema-cache generations (CoW swap) | ADR-003 |
//! | `0x05`   | up-to-dateness vector store | ADR-071 |
//! | `0x06`   | RID pool allocator state | Decision 3 |
//! | `0x07`   | tombstones | ADR-074 |
//! | `0x08`   | audit log | ADR-060 |
//! | `0x09`   | CA database | ADR-034 |
//! | `0x0A`   | Sigstore Rekor entries | ADR-067 |
//! | `0x0B`   | Federation Gateway trust store | ADR-039 |
//! | `0x0C`   | File Gateway share-ACL cache | ADR-105 |
//! | `0x0D`   | identity mapping table (UUID ↔ SID) | Decision 3 |
//! | `0x0E`   | `memberOf` materialised cache | ADR-002 |
//! | `0x0F`   | `tokenGroups` constructed-attribute cache | ADR-009 |
//! | `0x10`   | UUID → DNT index | ADR-073 |
//! | `0x11`   | DN → DNT index | ADR-073 |
//!
//! ## ADRs
//!
//! - ADR-073: FoundationDB as sole storage engine
//! - ADR-001: Linked Value Replication
//! - ADR-002: `memberOf` as DSA-computed back-link
//! - ADR-003: Schema cache with copy-on-write generations
//! - ADR-004: Security descriptor deduplication
//! - ADR-009: Constructed attributes
//! - ADR-074: Tombstone lifetime and lingering objects
//!
//! ## Layer
//!
//! Layer 1 — abstractions (depend on Layer 0). Implements
//! [`DirectoryStore`] from `adrian-storage-core`. The non-`fdb` fallback
//! path depends on `adrian-storage-testkit` (Layer 2) for its
//! snapshot-isolated `BTreeMap` — this is a workspace-internal convenience
//! to avoid duplicating the testkit's transactional KV implementation.

// NOTE (Wave 1 / T-102): The crate was originally `#![forbid(unsafe_code)]`, but
// `foundationdb` 0.9 marks `FdbApiBuilder::boot()` as `unsafe` because the
// returned `NetworkAutoStop` guard MUST be dropped before the program exits.
// We intentionally leak the guard (the FDB network runs for the lifetime of
// the process), which is the documented pattern for long-running services.
// The `unsafe` is confined to a single helper (`ensure_fdb_network_started`)
// which is `#[allow(unsafe_code)]`-gated and contains a SAFETY comment.
//
// All other code paths remain `unsafe`-free. `deny` (not `forbid`) lets us
// grant the single targeted `allow`.
#![deny(unsafe_code)]
#![warn(missing_docs)]

use adrian_storage_core::{
    decode_i64_be, decode_object_key, encode_dn_index_key,
    encode_object_key as encode_object_key_canonical, encode_object_prefix, encode_tombstone_key,
    encode_uuid_index_key, DirectoryStore, DirectoryTransaction, DistinguishedName, KeyRange,
    Object, ReadTxn, StorageError, Subspace, WriteTxn, DNT_ATTR_SENTINEL, DN_ATTR_SENTINEL,
    UUID_ATTR_SENTINEL,
};
use adrian_storage_core::{Attribute, Dnt, ValueIndex};
use async_trait::async_trait;
use uuid::Uuid;

// Re-export the canonical sentinel constants from `adrian-storage-core` so
// callers using `adrian-storage-fdb` do not need to import two crates.
pub use adrian_storage_core::{
    DNT_COUNTER_NAME, DNT_COUNTER_SENTINEL_ATTR, LINK_FORWARD_MARKER, LINK_REVERSE_MARKER,
};

/// Sentinel DNT value indicating "not yet assigned". Objects inserted via
/// `DirectoryStore::put` with `dnt == 0` are assigned a fresh DNT from the
/// `next_dnt` counter (mirroring the FDB atomic-add on `(0x01, 0xFF,
/// "next_dnt")` per ADR-073). Re-exported from `adrian-storage-testkit`
/// for ergonomic access from consumers of this crate.
pub const UNASSIGNED_DNT: Dnt = adrian_storage_testkit::UNASSIGNED_DNT;

/// FoundationDB-backed implementation of [`DirectoryStore`] (per ADR-073).
///
/// Without the `fdb` cargo feature (the default), the store wraps an
/// [`InMemoryDirectoryStore`] from `adrian-storage-testkit` and uses its
/// low-level [`ReadTxn`] / [`WriteTxn`] interface to store tuple-layer-
/// encoded rows. This means the *same* code path that encodes/decodes keys
/// for a real FDB cluster is exercised in unit tests — only the storage
/// substrate (real FDB cluster vs. in-process `BTreeMap`) differs.
///
/// With the `fdb` feature enabled, [`FdbDirectoryStore::connect`] opens a
/// real `foundationdb::Database` and subsequent operations use real FDB
/// transactions. See the crate-level docs for how to run integration tests
/// against a real FDB cluster.
#[derive(Debug, Clone)]
pub struct FdbDirectoryStore {
    /// Cluster connection string (e.g. `docker.cluster:4500`). Stored for
    /// diagnostics; the in-memory fallback code path does not use this
    /// value (it ignores it entirely). With the `fdb` feature, this is
    /// passed to `foundationdb::Database::from_path` (or
    /// `Database::new(cluster_file)`) on [`FdbDirectoryStore::connect`].
    pub cluster_file: Option<String>,
    /// The backend implementation. Always [`Backend::InMemory`] when the
    /// `fdb` feature is disabled; either variant when the feature is
    /// enabled (caller chooses via [`FdbDirectoryStore::new`] vs
    /// [`FdbDirectoryStore::connect`]).
    inner: Backend,
}

/// The active backend for a [`FdbDirectoryStore`] instance.
#[derive(Debug, Clone)]
enum Backend {
    /// In-memory fallback (always available). Wraps an
    /// [`InMemoryDirectoryStore`] from `adrian-storage-testkit` and uses
    /// its low-level `ReadTxn` / `WriteTxn` interface — NOT its
    /// `DirectoryStore` high-level methods — so that the tuple-layer key
    /// encoding is exercised end-to-end in unit tests.
    InMemory(adrian_storage_testkit::InMemoryDirectoryStore),
    /// Real FoundationDB backend (gated by the `fdb` feature flag).
    #[cfg(feature = "fdb")]
    Real(RealFdbBackend),
}

impl FdbDirectoryStore {
    /// Construct a new [`FdbDirectoryStore`] for the given cluster file. The
    /// `cluster_file` is recorded for diagnostics but **not actually
    /// connected to** — the returned store uses the in-memory fallback path.
    ///
    /// To open a real FDB connection (requires the `fdb` feature), use
    /// [`FdbDirectoryStore::connect`].
    ///
    /// If `cluster_file` is `None`, the `FDB_CLUSTER_FILE` env var would be
    /// used by the real backend at connect time (the fallback ignores it).
    pub fn new(cluster_file: Option<&str>) -> Self {
        Self {
            cluster_file: cluster_file.map(str::to_string),
            inner: Backend::InMemory(adrian_storage_testkit::InMemoryDirectoryStore::new()),
        }
    }

    /// Construct an in-memory-only fallback store (no `cluster_file`
    /// recorded). Useful for tests that don't care about the cluster
    /// connection string.
    pub fn in_memory() -> Self {
        Self {
            cluster_file: None,
            inner: Backend::InMemory(adrian_storage_testkit::InMemoryDirectoryStore::new()),
        }
    }

    /// Open a real FDB connection (requires the `fdb` feature flag).
    ///
    /// Without the `fdb` feature, this always returns
    /// [`StorageError::Backend`] — callers should fall back to
    /// [`FdbDirectoryStore::new`] (in-memory).
    #[cfg(feature = "fdb")]
    pub async fn connect(cluster_file: Option<&str>) -> Result<Self, StorageError> {
        let backend = RealFdbBackend::connect(cluster_file).await?;
        Ok(Self {
            cluster_file: cluster_file.map(str::to_string),
            inner: Backend::Real(backend),
        })
    }

    /// Open a real FDB connection (requires the `fdb` feature flag).
    ///
    /// Without the `fdb` feature, this always returns
    /// [`StorageError::Backend`].
    #[cfg(not(feature = "fdb"))]
    pub async fn connect(_cluster_file: Option<&str>) -> Result<Self, StorageError> {
        Err(StorageError::Backend(
            "FdbDirectoryStore::connect requires the `fdb` cargo feature (compile with \
             --features fdb) and a running FDB cluster"
                .into(),
        ))
    }

    /// Returns `true` if this store is the in-memory fallback (no real FDB
    /// cluster is being used). Useful for tests and diagnostics.
    pub fn is_in_memory_fallback(&self) -> bool {
        matches!(self.inner, Backend::InMemory(_))
    }

    /// Begin a write transaction and return it as a concrete [`FdbTxn`] so
    /// the high-level `put` / `delete` methods can use both the
    /// [`WriteTxn`] interface (for `commit` / `rollback`) and the
    /// [`DirectoryTransaction`] extension (for `allocate_dnt`,
    /// `lookup_dnt_by_uuid`, `tombstone`, etc.).
    async fn begin_directory_write(&self) -> Result<FdbTxn, StorageError> {
        // We construct the FdbTxn directly from the backend's own
        // `begin_write()` result. The testkit returns `Box<dyn WriteTxn>`;
        // we wrap that boxed trait object inside `FdbTxn` and delegate all
        // method calls through it. This means we don't need to expose the
        // concrete `InMemoryWriteTxn` type at this layer.
        match &self.inner {
            Backend::InMemory(s) => {
                let txn = s.begin_write().await?;
                Ok(FdbTxn::from_write_boxed(txn))
            }
            #[cfg(feature = "fdb")]
            Backend::Real(s) => {
                let txn = s.begin_write().await?;
                Ok(FdbTxn::from_write_boxed(Box::new(txn)))
            }
        }
    }
}

// ---- High-level DirectoryStore implementation ----
//
// All methods use the tuple-layer key encoding helpers from
// `adrian-storage-core` (`encode_object_key`, `encode_uuid_index_key`,
// `encode_dn_index_key`, `encode_tombstone_key`, `encode_dnt_counter_key`).
// The encoding is identical regardless of whether the backend is the
// in-memory fallback or a real FDB cluster — only the storage substrate
// differs.

#[async_trait]
impl DirectoryStore for FdbDirectoryStore {
    async fn get(&self, uuid: Uuid) -> Result<Option<Object>, StorageError> {
        let txn = self.begin_read().await?;
        // Step 1: lookup UUID → DNT via the 0x10 index.
        let dnt_key = encode_uuid_index_key(uuid);
        let dnt_bytes = match txn.get(&dnt_key).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let dnt_i = decode_i64_be(&dnt_bytes)
            .ok_or_else(|| StorageError::Backend("UUID→DNT value not 8 bytes".into()))?;
        if dnt_i < 0 {
            return Err(StorageError::Backend(format!("DNT is negative: {dnt_i}")));
        }
        let dnt = dnt_i as Dnt;
        // Step 2: range scan over (0x01, dnt, *) prefix.
        read_object_from_range(&*txn, uuid, dnt).await
    }

    async fn get_by_dn(&self, dn: &DistinguishedName) -> Result<Option<Object>, StorageError> {
        let txn = self.begin_read().await?;
        // Step 1: lookup DN → DNT via the 0x11 index.
        let dnt_key = encode_dn_index_key(dn);
        let dnt_bytes = match txn.get(&dnt_key).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let dnt_i = decode_i64_be(&dnt_bytes)
            .ok_or_else(|| StorageError::Backend("DN→DNT value not 8 bytes".into()))?;
        if dnt_i < 0 {
            return Err(StorageError::Backend(format!("DNT is negative: {dnt_i}")));
        }
        let dnt = dnt_i as Dnt;
        // Step 2: read the object rows; recover the UUID from the
        // UUID_ATTR_SENTINEL row (so we don't require the caller to know
        // the UUID when looking up by DN).
        let uuid = match find_uuid_in_object_rows(&*txn, dnt).await? {
            Some(u) => u,
            None => return Ok(None),
        };
        read_object_from_range(&*txn, uuid, dnt).await
    }

    async fn put(&self, obj: &Object) -> Result<(), StorageError> {
        // Use the concrete `FdbTxn` so we can call both `WriteTxn` methods
        // (`commit`) and `DirectoryTransaction` helpers (`allocate_dnt`,
        // `set_indexes`, etc.) on the same transaction.
        let txn = self.begin_directory_write().await?;
        // Determine the DNT: if the caller supplied UNASSIGNED_DNT (0),
        // allocate a fresh one via atomic-add on the counter; otherwise
        // reuse the caller's DNT (this is the "re-put / rename" path).
        let dnt = if obj.dnt == UNASSIGNED_DNT {
            // Check if this UUID already exists (re-put of existing object).
            match txn.lookup_dnt_by_uuid(obj.uuid).await? {
                Some(existing) => existing,
                None => txn.allocate_dnt().await?,
            }
        } else {
            obj.dnt
        };
        // Write the UUID→DNT and DN→DNT indexes + the DNT self-reference row.
        txn.set_indexes(obj.uuid, &obj.dn, dnt).await?;
        // Write the DN as a sentinel-attribute row so it round-trips through
        // `read_object_from_range`. The UUID is also stored (so `get_by_dn`
        // can recover the UUID without the caller supplying it).
        let dn_key = encode_object_key_canonical(Subspace::Objects, dnt, DN_ATTR_SENTINEL, 0);
        txn.put(&dn_key, obj.dn.dn.as_bytes()).await?;
        let uuid_key = encode_object_key_canonical(Subspace::Objects, dnt, UUID_ATTR_SENTINEL, 0);
        txn.put(&uuid_key, obj.uuid.as_bytes()).await?;
        // Write each user-visible attribute as a separate row.
        for (val_idx, attr) in obj.attributes.iter().enumerate() {
            let key = encode_object_key_canonical(
                Subspace::Objects,
                dnt,
                attr.attribute_id,
                val_idx as ValueIndex,
            );
            let value = encode_attr_value(&attr.name, &attr.value);
            txn.put(&key, &value).await?;
        }
        // Commit via the `WriteTxn::commit` method (which takes
        // `self: Box<Self>` — we wrap `txn` in a `Box` to satisfy it).
        WriteTxn::commit(Box::new(txn)).await
    }

    async fn delete(&self, uuid: Uuid) -> Result<(), StorageError> {
        // Per ADR-074 §Decision, delete moves the object to the 0x07
        // Tombstones subspace rather than hard-deleting. The tombstone
        // preserves a minimal attribute set (objectGUID, objectSid,
        // sIDHistory, lastKnownParent, member) — for the fallback path we
        // preserve the object's UUID and DN as the minimal set; the real
        // FDB path will preserve the full AD-compat set once the schema
        // cache is wired up.
        let txn = self.begin_directory_write().await?;
        let dnt = match txn.lookup_dnt_by_uuid(uuid).await? {
            Some(d) => d,
            None => {
                // Idempotent: deleting a non-existent UUID is a no-op
                // (per the testkit's contract).
                WriteTxn::rollback(Box::new(txn)).await?;
                return Ok(());
            }
        };
        // Read the current rows so we can preserve DN + UUID in the
        // tombstone payload. We do this in the same transaction (read-
        // your-writes) so the tombstone reflects the pre-delete state.
        let rows = txn.get_object_rows(dnt).await?;
        let mut preserved_uuid: Option<Uuid> = None;
        let mut dn_str: Option<String> = None;
        for (attr_id, _val_idx, value) in &rows {
            if *attr_id == DN_ATTR_SENTINEL {
                dn_str = String::from_utf8(value.clone()).ok();
            } else if *attr_id == UUID_ATTR_SENTINEL && value.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(value);
                preserved_uuid = Some(Uuid::from_bytes(arr));
            }
        }
        // The preserved payload format is: [uuid (16)][dn_len: u16 BE]
        // [dn_utf8_bytes]. The real FDB implementation will replace this
        // with a serialised AD-compat preserved-attribute set once the
        // schema cache (ADR-003) is wired up.
        let mut payload = Vec::new();
        let preserved_uuid = preserved_uuid.unwrap_or(uuid);
        payload.extend_from_slice(preserved_uuid.as_bytes());
        if let Some(dn) = &dn_str {
            let dn_bytes = dn.as_bytes();
            let len = u16::try_from(dn_bytes.len()).map_err(|_| {
                StorageError::Backend(format!(
                    "DN too long for tombstone payload: {}",
                    dn_bytes.len()
                ))
            })?;
            payload.extend_from_slice(&len.to_be_bytes());
            payload.extend_from_slice(dn_bytes);
        } else {
            payload.extend_from_slice(&0u16.to_be_bytes());
        }
        // The tombstone's NC head DNT defaults to 1 (the schema NC head,
        // which is the first object created). The real implementation will
        // compute the NC head from the object's DN ancestry. For now we
        // use the placeholder 1 (any non-zero DNT, since tombstone GC
        // scans by NC head DNT).
        let nc_head_dnt = 1;
        let when_deleted = 0i64; // The real implementation uses `chrono::Utc::now().timestamp()`.
        txn.tombstone(nc_head_dnt, dnt, &payload, when_deleted)
            .await?;
        // Also delete the DN→DNT index row so the deleted DN can be reused
        // (if AD Recycle Bin semantics are not in effect). We keep the
        // UUID→DNT index row pointing at the now-tombstoned DNT so that
        // a future "revive from tombstone" operation can find the
        // tombstone by UUID. (Note: `tombstone` already deleted the
        // UUID→DNT index row as part of its atomic delete-from-objects-
        // subspace step.)
        if let Some(dn) = &dn_str {
            let dn_idx_key = encode_dn_index_key(&DistinguishedName::new(dn.clone()));
            txn.delete(&dn_idx_key).await?;
        }
        WriteTxn::commit(Box::new(txn)).await
    }

    async fn begin_read(&self) -> Result<Box<dyn ReadTxn>, StorageError> {
        match &self.inner {
            Backend::InMemory(s) => {
                let txn = s.begin_read().await?;
                Ok(Box::new(FdbTxn::from_read_boxed(txn)))
            }
            #[cfg(feature = "fdb")]
            Backend::Real(s) => {
                let txn = s.begin_read().await?;
                Ok(Box::new(FdbTxn::from_read_boxed(Box::new(txn))))
            }
        }
    }

    async fn begin_write(&self) -> Result<Box<dyn WriteTxn>, StorageError> {
        match &self.inner {
            Backend::InMemory(s) => {
                let txn = s.begin_write().await?;
                Ok(Box::new(FdbTxn::from_write_boxed(txn)))
            }
            #[cfg(feature = "fdb")]
            Backend::Real(s) => {
                let txn = s.begin_write().await?;
                Ok(Box::new(FdbTxn::from_write_boxed(Box::new(txn))))
            }
        }
    }

    fn snapshot(&self) -> Box<dyn DirectoryStore> {
        // Both backends are cheaply clonable (Arc-based for the in-memory
        // path; the real FDB `Database` is also internally Arc'd). The
        // returned snapshot shares the underlying storage — callers wanting
        // a frozen point-in-time view should `begin_read()` instead.
        Box::new(self.clone())
    }
}

// ---- Helper: read an Object from the per-DNT row range ----
//
// Used by both `get` and `get_by_dn` after the DNT has been resolved. Reads
// the (0x01, dnt, *) prefix range and decodes the rows into an `Object`.

async fn read_object_from_range(
    txn: &dyn ReadTxn,
    uuid: Uuid,
    dnt: Dnt,
) -> Result<Option<Object>, StorageError> {
    let prefix = encode_object_prefix(Subspace::Objects, dnt);
    let range = KeyRange::prefix(&prefix).ok_or_else(|| {
        StorageError::Backend("object prefix is all-0xFF (impossible for valid DNT)".into())
    })?;
    let rows = txn.get_range(&range.begin, &range.end).await?;
    if rows.is_empty() {
        // The DNT index pointed at a DNT with no rows — the object was
        // deleted (tombstoned) between the index lookup and the range
        // read. Return None to match the caller's expectation.
        return Ok(None);
    }
    let mut dn: Option<DistinguishedName> = None;
    let mut attributes: Vec<Attribute> = Vec::with_capacity(rows.len());
    for (key, value) in rows {
        let Some((_, attr_id, val_idx)) = decode_object_key(&key, Subspace::Objects) else {
            continue;
        };
        if attr_id == DN_ATTR_SENTINEL {
            dn = Some(DistinguishedName::new(
                String::from_utf8_lossy(&value).into_owned(),
            ));
        } else if attr_id == UUID_ATTR_SENTINEL || attr_id == DNT_ATTR_SENTINEL {
            // Skip self-reference rows — the UUID is supplied by the caller
            // (or recovered via `find_uuid_in_object_rows`), and the DNT
            // is already known.
        } else {
            let (name, attr_value) = decode_attr_value(&value).ok_or_else(|| {
                StorageError::Backend(format!(
                    "malformed attribute value row (attr_id={attr_id}, val_idx={val_idx})"
                ))
            })?;
            attributes.push(Attribute {
                attribute_id: attr_id,
                name,
                value: attr_value,
            });
        }
    }
    let dn = dn.unwrap_or_else(|| DistinguishedName::new(String::new()));
    Ok(Some(Object {
        uuid,
        dn,
        attributes,
        dnt,
    }))
}

/// Scan the per-DNT row range for the `UUID_ATTR_SENTINEL` row and return
/// the recovered UUID. Used by `get_by_dn` to recover the UUID without
/// requiring the caller to supply it.
async fn find_uuid_in_object_rows(
    txn: &dyn ReadTxn,
    dnt: Dnt,
) -> Result<Option<Uuid>, StorageError> {
    let prefix = encode_object_prefix(Subspace::Objects, dnt);
    let range = KeyRange::prefix(&prefix).ok_or_else(|| {
        StorageError::Backend("object prefix is all-0xFF (impossible for valid DNT)".into())
    })?;
    let rows = txn.get_range(&range.begin, &range.end).await?;
    for (key, value) in rows {
        if let Some((_, attr_id, _)) = decode_object_key(&key, Subspace::Objects) {
            if attr_id == UUID_ATTR_SENTINEL && value.len() == 16 {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&value);
                return Ok(Some(Uuid::from_bytes(bytes)));
            }
        }
    }
    Ok(None)
}

// ---- Attribute value encoding ----
//
// Each user-visible attribute row's value bytes are encoded as:
//   [name_len: u16 BE][name_bytes (UTF-8)][raw_value_bytes]
//
// This length-prefix encoding allows the attribute *name* to round-trip
// through the KV layer without requiring a schema cache (ADR-003) to map
// `attribute_id` → `name`. When the schema cache is wired up (a future
// wave), this encoding can be replaced with raw value bytes + schema-cache
// lookup, but for now the length-prefix encoding is the simplest way to
// make the fallback code path fully round-trippable.

/// Encode an attribute value row as `[name_len: u16 BE][name_bytes][value_bytes]`.
fn encode_attr_value(name: &str, value: &[u8]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    // u16 saturating check — attribute names in AD/LDAP are <= 64 chars.
    let name_len = u16::try_from(name_bytes.len()).unwrap_or(0xFFFF);
    let mut out = Vec::with_capacity(2 + name_bytes.len() + value.len());
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(value);
    out
}

/// Decode an attribute value row produced by [`encode_attr_value`].
/// Returns `None` if the bytes are malformed (truncated name length,
/// truncated name bytes, or invalid UTF-8).
fn decode_attr_value(bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    if bytes.len() < 2 {
        return None;
    }
    let name_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if bytes.len() < 2 + name_len {
        return None;
    }
    let name = String::from_utf8(bytes[2..2 + name_len].to_vec()).ok()?;
    let value = bytes[2 + name_len..].to_vec();
    Some((name, value))
}

// ---- FdbTxn: the transaction wrapper ----
//
// `FdbTxn` is a single type that wraps *either* an in-memory
// `InMemoryReadTxn` / `InMemoryWriteTxn` (from `adrian-storage-testkit`)
// or a real `foundationdb::Transaction` (gated by the `fdb` feature).
//
// Both backends expose the same `ReadTxn` / `WriteTxn` trait interface, so
// `FdbTxn` wraps them as `Box<dyn ReadTxn>` / `Box<dyn WriteTxn>` trait
// objects. This means we don't need to expose the concrete
// `InMemoryWriteTxn` / `RealFdbWriteTxn` types at this layer.
//
// The wrapper implements `ReadTxn`, `WriteTxn`, and
// `DirectoryTransaction` by delegating to the inner backend. Because the
// type is concrete (not a trait object), the high-level `FdbDirectoryStore`
// methods can call both `WriteTxn::commit` (which takes `self: Box<Self>`)
// and the `DirectoryTransaction` extension methods on the same value.

/// The FDB transaction wrapper used by [`FdbDirectoryStore`].
///
/// Without the `fdb` feature, this is always the in-memory variant
/// (wrapping an `InMemoryReadTxn` or `InMemoryWriteTxn` from
/// `adrian-storage-testkit`). With the `fdb` feature, the `from_write_boxed`
/// / `from_read_boxed` constructors accept any backend that implements
/// [`ReadTxn`] / [`WriteTxn`], including the real FDB backend.
///
/// The wrapper exposes the [`DirectoryTransaction`] trait so callers can
/// use the high-level helpers (`allocate_dnt`, `lookup_dnt_by_uuid`,
/// `tombstone`, etc.) without caring about which backend is active.
pub struct FdbTxn {
    inner: FdbTxnInner,
}

/// Manual `Debug` impl — the underlying `dyn ReadTxn` / `dyn WriteTxn`
/// trait objects are not `Debug`, so we emit a backend-agnostic label
/// instead of trying to print the inner transaction's state.
impl std::fmt::Debug for FdbTxn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner {
            FdbTxnInner::Read(_) => f.debug_struct("FdbTxn").field("mode", &"read").finish(),
            FdbTxnInner::Write(_) => f.debug_struct("FdbTxn").field("mode", &"write").finish(),
        }
    }
}

enum FdbTxnInner {
    /// Read-only transaction (snapshot). Either from the testkit (fallback)
    /// or a real FDB snapshot read.
    Read(Box<dyn ReadTxn>),
    /// Read-write transaction. Either from the testkit (fallback) or a
    /// real FDB transaction.
    Write(Box<dyn WriteTxn>),
}

impl FdbTxn {
    /// Wrap a boxed read txn.
    pub fn from_read_boxed(txn: Box<dyn ReadTxn>) -> Self {
        Self {
            inner: FdbTxnInner::Read(txn),
        }
    }

    /// Wrap a boxed write txn.
    pub fn from_write_boxed(txn: Box<dyn WriteTxn>) -> Self {
        Self {
            inner: FdbTxnInner::Write(txn),
        }
    }

    /// Returns `true` if this is a read-only transaction (no writes allowed).
    fn is_read_only(&self) -> bool {
        matches!(self.inner, FdbTxnInner::Read(_))
    }
}

#[async_trait]
impl ReadTxn for FdbTxn {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        match &self.inner {
            FdbTxnInner::Read(t) => t.get(key).await,
            FdbTxnInner::Write(t) => t.get(key).await,
        }
    }

    async fn get_range(
        &self,
        begin: &[u8],
        end: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        match &self.inner {
            FdbTxnInner::Read(t) => t.get_range(begin, end).await,
            FdbTxnInner::Write(t) => t.get_range(begin, end).await,
        }
    }
}

#[async_trait]
impl WriteTxn for FdbTxn {
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        match &self.inner {
            FdbTxnInner::Write(t) => t.put(key, value).await,
            // Read-only txns cannot write — return a clear error.
            FdbTxnInner::Read(_) => Err(StorageError::Backend(format!(
                "put() called on a read-only transaction (inner = {})",
                if self.is_read_only() {
                    "read-only"
                } else {
                    "write (unreachable)"
                }
            ))),
        }
    }

    async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        match &self.inner {
            FdbTxnInner::Write(t) => t.delete(key).await,
            FdbTxnInner::Read(_) => Err(StorageError::Backend(
                "delete() called on a read-only transaction".into(),
            )),
        }
    }

    async fn atomic_add(&self, key: &[u8], value: i64) -> Result<(), StorageError> {
        match &self.inner {
            FdbTxnInner::Write(t) => t.atomic_add(key, value).await,
            FdbTxnInner::Read(_) => Err(StorageError::Backend(
                "atomic_add() called on a read-only transaction".into(),
            )),
        }
    }

    async fn clear_range(&self, begin: &[u8], end: &[u8]) -> Result<(), StorageError> {
        match &self.inner {
            FdbTxnInner::Write(t) => t.clear_range(begin, end).await,
            FdbTxnInner::Read(_) => Err(StorageError::Backend(
                "clear_range() called on a read-only transaction".into(),
            )),
        }
    }

    async fn commit(self: Box<Self>) -> Result<(), StorageError> {
        // Destructure `self` (the `Box<FdbTxn>`) to extract the inner
        // `Box<dyn WriteTxn>` and call its `commit()`. Read-only txns
        // cannot commit (error).
        let inner = self.inner;
        match inner {
            FdbTxnInner::Write(t) => t.commit().await,
            FdbTxnInner::Read(_) => Err(StorageError::Backend(
                "commit() called on a read-only transaction".into(),
            )),
        }
    }

    async fn rollback(self: Box<Self>) -> Result<(), StorageError> {
        let inner = self.inner;
        match inner {
            FdbTxnInner::Write(t) => t.rollback().await,
            // Read-only txns have nothing to roll back — no-op success.
            FdbTxnInner::Read(_) => Ok(()),
        }
    }
}

#[async_trait]
impl DirectoryTransaction for FdbTxn {
    async fn tombstone(
        &self,
        nc_head_dnt: Dnt,
        deleted_object_dnt: Dnt,
        preserved_attributes: &[u8],
        when_deleted_unix_seconds: i64,
    ) -> Result<(), StorageError> {
        // Encode the tombstone value: [preserved_bytes_len: u32 BE]
        // [preserved_bytes][when_deleted: i64 BE]. The u32 length prefix
        // allows the GC task to skip the variable-length preserved-attrs
        // blob without parsing it.
        let pres_len = u32::try_from(preserved_attributes.len()).map_err(|_| {
            StorageError::Backend(format!(
                "preserved_attributes too long: {}",
                preserved_attributes.len()
            ))
        })?;
        let mut value = Vec::with_capacity(4 + preserved_attributes.len() + 8);
        value.extend_from_slice(&pres_len.to_be_bytes());
        value.extend_from_slice(preserved_attributes);
        value.extend_from_slice(&when_deleted_unix_seconds.to_be_bytes());
        // Write the tombstone row in the 0x07 subspace.
        let tomb_key = encode_tombstone_key(nc_head_dnt, deleted_object_dnt);
        self.put(&tomb_key, &value).await?;
        // Read+delete the object's rows from the 0x01 Objects subspace.
        let prefix = encode_object_prefix(Subspace::Objects, deleted_object_dnt);
        let range = KeyRange::prefix(&prefix).ok_or_else(|| {
            StorageError::Backend("object prefix is all-0xFF (impossible for valid DNT)".into())
        })?;
        let rows = self.get_range(&range.begin, &range.end).await?;
        // First, find the UUID row (so we can delete the UUID→DNT index).
        let mut uuid_to_delete: Option<Uuid> = None;
        for (key, value) in &rows {
            if let Some((_, attr_id, _)) = decode_object_key(key, Subspace::Objects) {
                if attr_id == UUID_ATTR_SENTINEL && value.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(value);
                    uuid_to_delete = Some(Uuid::from_bytes(arr));
                }
            }
        }
        // Delete each object row.
        for (key, _value) in &rows {
            self.delete(key).await?;
        }
        // Delete the UUID→DNT index row (so subsequent `get(uuid)` returns
        // None — the object is logically deleted).
        if let Some(uuid) = uuid_to_delete {
            let uuid_idx_key = encode_uuid_index_key(uuid);
            self.delete(&uuid_idx_key).await?;
        }
        Ok(())
    }
}

// ---- Real FDB backend (gated by `fdb` feature) ----
//
// The real FDB backend wraps a `foundationdb::Database` and spawns
// transactions on demand. Wave 1 (T-102) compiles this code path against
// `foundationdb` 0.9.2 with libclang + the FDB C client installed.

// ---- FDB network startup (gated by `fdb` feature) ----
//
// `foundationdb` 0.9 marks `FdbApiBuilder::boot()` as `unsafe` because the
// returned `NetworkAutoStop` guard MUST be dropped before the program exits.
// For a long-running service we want the FDB network to run for the lifetime
// of the process, so we leak the guard on first use. The leak is intentional
// and matches the documented pattern for servers / long-running services.

#[cfg(feature = "fdb")]
static FDB_NETWORK_STARTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Initialise the FDB network exactly once per process. Subsequent calls are
/// no-ops. The `NetworkAutoStop` guard returned by `boot()` is intentionally
/// leaked (`mem::forget`) so the FDB network thread runs for the lifetime of
/// the process. This matches the recommended pattern for long-running services.
#[cfg(feature = "fdb")]
#[allow(unsafe_code)] // see SAFETY comment below
fn ensure_fdb_network_started() -> Result<(), StorageError> {
    if FDB_NETWORK_STARTED.set(()).is_ok() {
        // First call — actually boot the network.
        let network_builder = foundationdb::api::FdbApiBuilder::default()
            .build()
            .map_err(|e| StorageError::Backend(format!("FdbApiBuilder::build failed: {e}")))?;
        // SAFETY: `NetworkBuilder::boot()` is marked `unsafe` because the
        // returned `NetworkAutoStop` MUST be dropped before the program
        // exits (otherwise the background network thread may race with
        // process teardown). We intentionally `mem::forget` the guard so
        // the network runs for the lifetime of the process. When the
        // process exits, the OS reclaims all resources (including the FDB
        // network thread) — this is the documented pattern for
        // long-running services in the `foundationdb` crate's own
        // examples. There is no soundness hazard to Rust memory.
        let guard = unsafe { network_builder.boot() }
            .map_err(|e| StorageError::Backend(format!("NetworkBuilder::boot failed: {e}")))?;
        std::mem::forget(guard);
    }
    Ok(())
}

#[cfg(feature = "fdb")]
mod real_fdb {
    use super::*;

    /// Real FDB backend.
    #[derive(Clone)]
    pub struct RealFdbBackend {
        /// The `foundationdb::Database` handle. Wrapped in `Arc` so the
        /// backend is cheaply clonable (matching the in-memory fallback's
        /// `Arc<RwLock<...>>` semantics).
        db: std::sync::Arc<foundationdb::Database>,
    }

    impl std::fmt::Debug for RealFdbBackend {
        // `foundationdb::Database` doesn't implement `Debug` in 0.9 (the
        // inner FFI handle is a raw pointer). We provide a stub that
        // prints the backend's static type name + cluster_file hint.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RealFdbBackend")
                .field("db", &"<foundationdb::Database>")
                .finish()
        }
    }

    impl RealFdbBackend {
        /// Open a real FDB connection. The `cluster_file` may be `None`,
        /// in which case the `FDB_CLUSTER_FILE` env var is used by the
        /// `foundationdb` crate.
        pub async fn connect(cluster_file: Option<&str>) -> Result<Self, StorageError> {
            // Initialise the FDB network exactly once per process. The
            // network guard is intentionally leaked (the FDB network runs
            // for the lifetime of the process).
            ensure_fdb_network_started()?;
            let db = match cluster_file {
                Some(path) => foundationdb::Database::from_path(path).map_err(|e| {
                    StorageError::Backend(format!("Database::from_path failed: {e}"))
                })?,
                None => foundationdb::Database::new(None)
                    .map_err(|e| StorageError::Backend(format!("Database::new failed: {e}")))?,
            };
            Ok(Self {
                db: std::sync::Arc::new(db),
            })
        }

        /// Begin a read transaction (FDB snapshot read).
        pub async fn begin_read(&self) -> Result<RealFdbReadTxn, StorageError> {
            let trx = self
                .db
                .create_trx()
                .map_err(|e| StorageError::Backend(format!("create_trx failed: {e}")))?;
            Ok(RealFdbReadTxn { trx })
        }

        /// Begin a read-write transaction.
        pub async fn begin_write(&self) -> Result<RealFdbWriteTxn, StorageError> {
            let trx = self
                .db
                .create_trx()
                .map_err(|e| StorageError::Backend(format!("create_trx failed: {e}")))?;
            Ok(RealFdbWriteTxn { trx })
        }
    }

    /// Real FDB read transaction (snapshot).
    pub struct RealFdbReadTxn {
        trx: foundationdb::Transaction,
    }

    impl std::fmt::Debug for RealFdbReadTxn {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RealFdbReadTxn").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl ReadTxn for RealFdbReadTxn {
        async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            let fut = self.trx.get(key, true /* snapshot */);
            let slice = fut
                .await
                .map_err(|e| StorageError::Backend(format!("FDB get failed: {e}")))?;
            Ok(slice.as_deref().map(|s| s.to_vec()))
        }

        async fn get_range(
            &self,
            begin: &[u8],
            end: &[u8],
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            use foundationdb::RangeOption;
            let opt = RangeOption::from(begin..end);
            // Wave 1 (T-102): in `foundationdb` 0.9, `get_ranges` returns a
            // `Stream` (not a `Future`). For our per-DNT ranges — which
            // are typically <100 rows and well under FDB's 1MB per-chunk
            // default — a single `get_range` (singular) call suffices.
            // `iteration=1` is the documented first-call value.
            let result = self
                .trx
                .get_range(&opt, 1, true /* snapshot */)
                .await
                .map_err(|e| StorageError::Backend(format!("FDB get_range failed: {e}")))?;
            let mut out = Vec::new();
            for kv in result.iter() {
                out.push((kv.key().to_vec(), kv.value().to_vec()));
            }
            Ok(out)
        }
    }

    /// Real FDB read-write transaction.
    pub struct RealFdbWriteTxn {
        trx: foundationdb::Transaction,
    }

    impl std::fmt::Debug for RealFdbWriteTxn {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RealFdbWriteTxn").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl ReadTxn for RealFdbWriteTxn {
        async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            let fut = self.trx.get(key, false /* not snapshot */);
            let slice = fut
                .await
                .map_err(|e| StorageError::Backend(format!("FDB get failed: {e}")))?;
            Ok(slice.as_deref().map(|s| s.to_vec()))
        }

        async fn get_range(
            &self,
            begin: &[u8],
            end: &[u8],
        ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
            use foundationdb::RangeOption;
            let opt = RangeOption::from(begin..end);
            // See RealFdbReadTxn::get_range for rationale on `get_range`
            // (singular) vs `get_ranges` (plural Stream).
            let result = self
                .trx
                .get_range(&opt, 1, false /* not snapshot */)
                .await
                .map_err(|e| StorageError::Backend(format!("FDB get_range failed: {e}")))?;
            let mut out = Vec::new();
            for kv in result.iter() {
                out.push((kv.key().to_vec(), kv.value().to_vec()));
            }
            Ok(out)
        }
    }

    #[async_trait]
    impl WriteTxn for RealFdbWriteTxn {
        async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.trx.set(key, value);
            Ok(())
        }

        async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
            self.trx.clear(key);
            Ok(())
        }

        async fn atomic_add(&self, key: &[u8], value: i64) -> Result<(), StorageError> {
            use foundationdb::options::MutationType;
            // FDB's AtomicOp::Add takes an 8-byte big-endian i64 operand.
            self.trx
                .atomic_op(key, &value.to_be_bytes(), MutationType::Add);
            Ok(())
        }

        async fn clear_range(&self, begin: &[u8], end: &[u8]) -> Result<(), StorageError> {
            // `Transaction::clear_range` is a single atomic op that wipes
            // the half-open range `[begin, end)` in the FDB cluster —
            // equivalent to many `clear()` calls but committed atomically.
            self.trx.clear_range(begin, end);
            Ok(())
        }

        async fn commit(self: Box<Self>) -> Result<(), StorageError> {
            self.trx.commit().await.map_err(|e| {
                // Map FDB error codes to StorageError variants per ADR-073
                // §Decision (retry-on-conflict loop is the caller's
                // responsibility; this method surfaces the underlying
                // error).
                StorageError::Backend(format!("FDB commit failed: {e}"))
            })?;
            Ok(())
        }

        async fn rollback(self: Box<Self>) -> Result<(), StorageError> {
            // FDB transactions are rolled back by simply dropping the
            // `Transaction` object — there is no explicit `rollback()`
            // call. The `Drop` impl in the `foundationdb` crate handles
            // cleanup.
            drop(self);
            Ok(())
        }
    }
}

// Re-export the real-FDB types for the rest of the crate.
#[cfg(feature = "fdb")]
use real_fdb::RealFdbBackend;

// ---- Legacy tuple-layer key-encoding helpers ----
//
// These functions are re-exported from `adrian-storage-core` for backward
// compatibility with the original stub API. New code should call the
// canonical functions in `adrian_storage_core` directly.

/// Re-export of [`adrian_storage_core::encode_object_key`] for callers that
/// historically imported it from `adrian_storage_fdb`. Prefer the
/// `adrian_storage_core` path in new code.
pub fn encode_object_key(subspace: u8, dnt: u64, attribute_id: u32, value_index: u32) -> Vec<u8> {
    let subspace = subspace_from_u8(subspace);
    adrian_storage_core::encode_object_key(subspace, dnt, attribute_id, value_index)
}

/// Re-export of [`adrian_storage_core::encode_link_forward_key`] (legacy
/// API; prefer the `adrian_storage_core` path in new code).
pub fn encode_link_forward_key(link_dnt: u64, link_id: u32, backlink_dnt: u64) -> Vec<u8> {
    adrian_storage_core::encode_link_forward_key(link_dnt, link_id, backlink_dnt)
}

/// Re-export of [`adrian_storage_core::encode_link_reverse_key`] (legacy
/// API; prefer the `adrian_storage_core` path in new code).
pub fn encode_link_reverse_key(backlink_dnt: u64, link_id: u32, link_dnt: u64) -> Vec<u8> {
    adrian_storage_core::encode_link_reverse_key(backlink_dnt, link_id, link_dnt)
}

/// Re-export of [`adrian_storage_core::encode_sd_table_key`] (legacy API;
/// prefer the `adrian_storage_core` path in new code).
pub fn encode_sd_table_key(sd_hash: &[u8]) -> Result<Vec<u8>, StorageError> {
    adrian_storage_core::encode_sd_table_key(sd_hash)
}

/// Convert a raw subspace byte to a `Subspace` enum value. Returns
/// `Subspace::Objects` (0x01) for unknown bytes — callers that need to
/// validate the byte should use the `TryFrom<u8>` impl on `Subspace`
/// (to be added in a future wave alongside the schema cache).
fn subspace_from_u8(b: u8) -> Subspace {
    match b {
        0x01 => Subspace::Objects,
        0x02 => Subspace::LinkTable,
        0x03 => Subspace::SdTable,
        0x04 => Subspace::SchemaCache,
        0x05 => Subspace::UtdVector,
        0x06 => Subspace::RidPool,
        0x07 => Subspace::Tombstones,
        0x08 => Subspace::AuditLog,
        0x09 => Subspace::CaDb,
        0x0A => Subspace::Sigstore,
        0x0B => Subspace::Federation,
        0x0C => Subspace::FileGateway,
        0x0D => Subspace::IdentityMapping,
        0x0E => Subspace::MemberOfCache,
        0x0F => Subspace::TokenGroupsCache,
        0x10 => Subspace::ObjectUuidIndex,
        0x11 => Subspace::ObjectDnIndex,
        _ => Subspace::Objects, // fallback for unknown bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_storage_core::{Attribute, DistinguishedName, Object, Subspace};

    /// Deterministic UUID for tests (avoids depending on the `v4` feature
    /// of the `uuid` crate — only `v7` and `serde` are enabled in the
    /// workspace Cargo.toml).
    fn test_uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    /// Build a minimal `Object` for tests.
    fn make_obj(uuid: Uuid, dn: &str, attrs: Vec<Attribute>) -> Object {
        Object {
            uuid,
            dn: DistinguishedName::new(dn),
            attributes: attrs,
            dnt: UNASSIGNED_DNT, // let the store allocate
        }
    }

    fn make_attr(id: u32, name: &str, value: &[u8]) -> Attribute {
        Attribute {
            attribute_id: id,
            name: name.to_string(),
            value: value.to_vec(),
        }
    }

    // ===== Fallback-path behavioral tests (no `fdb` feature required) =====

    #[tokio::test]
    async fn fallback_get_on_empty_store_returns_none() {
        let store = FdbDirectoryStore::in_memory();
        assert!(store.is_in_memory_fallback());
        let got = store.get(test_uuid(1)).await.unwrap();
        assert!(got.is_none(), "get on empty store must return None");
    }

    #[tokio::test]
    async fn fallback_get_by_dn_on_empty_store_returns_none() {
        let store = FdbDirectoryStore::in_memory();
        let got = store
            .get_by_dn(&DistinguishedName::new("CN=foo,DC=corp,DC=com"))
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn fallback_put_then_get_roundtrip_by_uuid() {
        let store = FdbDirectoryStore::in_memory();
        let uuid = test_uuid(1);
        let obj = make_obj(
            uuid,
            "CN=alice,DC=corp,DC=com",
            vec![
                make_attr(3, "cn", b"alice"),
                make_attr(7, "displayName", b"Alice"),
            ],
        );
        store.put(&obj).await.unwrap();
        let got = store.get(uuid).await.unwrap().expect("object should exist");
        assert_eq!(got.uuid, uuid);
        assert_eq!(got.dn.dn, "CN=alice,DC=corp,DC=com");
        assert_eq!(got.dnt, 1, "first inserted object should get DNT 1");
        assert_eq!(got.attributes.len(), 2);
        // Attributes should round-trip exactly (name + value bytes).
        let by_name: std::collections::HashMap<&str, &[u8]> = got
            .attributes
            .iter()
            .map(|a| (a.name.as_str(), a.value.as_slice()))
            .collect();
        assert_eq!(by_name.get("cn").copied(), Some(&b"alice"[..]));
        assert_eq!(by_name.get("displayName").copied(), Some(&b"Alice"[..]));
    }

    #[tokio::test]
    async fn fallback_put_then_get_by_dn_roundtrip() {
        let store = FdbDirectoryStore::in_memory();
        let uuid = test_uuid(2);
        let dn = DistinguishedName::new("CN=bob,OU=Eng,DC=corp,DC=com");
        let obj = Object {
            uuid,
            dn: dn.clone(),
            attributes: vec![make_attr(3, "cn", b"bob")],
            dnt: UNASSIGNED_DNT,
        };
        store.put(&obj).await.unwrap();
        let got = store
            .get_by_dn(&dn)
            .await
            .unwrap()
            .expect("object should exist");
        assert_eq!(got.uuid, uuid, "get_by_dn must recover the UUID");
        assert_eq!(got.dn.dn, "CN=bob,OU=Eng,DC=corp,DC=com");
        assert_eq!(got.attributes.len(), 1);
    }

    #[tokio::test]
    async fn fallback_put_assigns_sequential_dnts_via_atomic_add() {
        let store = FdbDirectoryStore::in_memory();
        // Insert three objects; their DNTs must be 1, 2, 3.
        for i in 1..=3u128 {
            let uuid = test_uuid(100 + i);
            let obj = make_obj(uuid, &format!("CN=user{i},DC=corp,DC=com"), vec![]);
            store.put(&obj).await.unwrap();
            let got = store.get(uuid).await.unwrap().unwrap();
            assert_eq!(got.dnt, i as u64, "DNT must be sequential starting at 1");
        }
        // Verify the DNT counter is at 3 by reading it directly.
        let txn = store.begin_read().await.unwrap();
        let counter_key = adrian_storage_core::encode_dnt_counter_key();
        let counter_bytes = txn.get(&counter_key).await.unwrap().unwrap();
        let counter = i64::from_be_bytes(counter_bytes[..].try_into().unwrap());
        assert_eq!(counter, 3, "DNT counter must be 3 after 3 inserts");
    }

    #[tokio::test]
    async fn fallback_put_re_put_preserves_dnt() {
        let store = FdbDirectoryStore::in_memory();
        let uuid = test_uuid(5);
        let obj = make_obj(uuid, "CN=carol,DC=corp,DC=com", vec![]);
        store.put(&obj).await.unwrap();
        // Re-put the same UUID with new attributes — the DNT must be
        // preserved (the existing DNT 1 should be reused, not allocated
        // anew).
        let updated = Object {
            uuid,
            dn: DistinguishedName::new("CN=carol-renamed,DC=corp,DC=com"),
            attributes: vec![make_attr(11, "sn", b"Carol-Renamed")],
            dnt: UNASSIGNED_DNT, // should reuse existing DNT
        };
        store.put(&updated).await.unwrap();
        let got = store.get(uuid).await.unwrap().unwrap();
        assert_eq!(got.dnt, 1, "re-put must preserve the existing DNT");
        assert_eq!(got.dn.dn, "CN=carol-renamed,DC=corp,DC=com");
        assert_eq!(got.attributes.len(), 1);
        assert_eq!(got.attributes[0].name, "sn");
    }

    #[tokio::test]
    async fn fallback_delete_creates_tombstone_and_hides_object() {
        let store = FdbDirectoryStore::in_memory();
        let uuid = test_uuid(7);
        let dn = DistinguishedName::new("CN=dave,DC=corp,DC=com");
        store
            .put(&make_obj(
                uuid,
                "CN=dave,DC=corp,DC=com",
                vec![make_attr(3, "cn", b"dave")],
            ))
            .await
            .unwrap();
        // Delete the object — should tombstone it (move to 0x07), not
        // hard-delete.
        store.delete(uuid).await.unwrap();
        // get(uuid) must now return None (the object is logically deleted).
        assert!(store.get(uuid).await.unwrap().is_none());
        // get_by_dn must also return None (the DN index row was cleared).
        assert!(store.get_by_dn(&dn).await.unwrap().is_none());
        // The tombstone row must exist in the 0x07 subspace.
        let txn = store.begin_read().await.unwrap();
        let prefix = vec![Subspace::Tombstones as u8];
        let end = {
            let mut e = prefix.clone();
            e[0] += 1;
            e
        };
        let rows = txn.get_range(&prefix, &end).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "exactly one tombstone row should exist after one delete"
        );
        let (key, value) = &rows[0];
        assert_eq!(key.len(), 17);
        assert_eq!(key[0], Subspace::Tombstones as u8);
        let nc_head = u64::from_be_bytes(key[1..9].try_into().unwrap());
        let deleted = u64::from_be_bytes(key[9..17].try_into().unwrap());
        assert_eq!(nc_head, 1);
        assert_eq!(deleted, 1);
        // Tombstone value: [preserved_len: u32 BE][preserved_bytes][when_deleted: i64 BE]
        // Preserved bytes contain the UUID (16) + DN length prefix (2) + DN bytes.
        assert!(
            value.len() >= 4 + 16 + 2 + 8,
            "tombstone value must contain preserved attrs"
        );
        let pres_len = u32::from_be_bytes(value[0..4].try_into().unwrap()) as usize;
        let preserved = &value[4..4 + pres_len];
        assert_eq!(&preserved[0..16], uuid.as_bytes());
        let dn_len = u16::from_be_bytes(preserved[16..18].try_into().unwrap()) as usize;
        assert_eq!(&preserved[18..18 + dn_len], b"CN=dave,DC=corp,DC=com");
    }

    #[tokio::test]
    async fn fallback_delete_is_idempotent() {
        let store = FdbDirectoryStore::in_memory();
        let uuid = test_uuid(8);
        store
            .put(&make_obj(uuid, "CN=eve,DC=corp,DC=com", vec![]))
            .await
            .unwrap();
        store.delete(uuid).await.unwrap();
        // Second delete must succeed (idempotent — no-op, no error).
        store.delete(uuid).await.unwrap();
        // Still no object.
        assert!(store.get(uuid).await.unwrap().is_none());
        // Still exactly one tombstone (the second delete must not create
        // a duplicate tombstone).
        let txn = store.begin_read().await.unwrap();
        let prefix = vec![Subspace::Tombstones as u8];
        let end = {
            let mut e = prefix.clone();
            e[0] += 1;
            e
        };
        let rows = txn.get_range(&prefix, &end).await.unwrap();
        assert_eq!(rows.len(), 1, "second delete must not duplicate tombstone");
    }

    #[tokio::test]
    async fn fallback_multi_valued_attributes_roundtrip_in_order() {
        let store = FdbDirectoryStore::in_memory();
        let uuid = test_uuid(9);
        // Three values for the same multi-valued attribute (e.g. memberOf).
        let obj = make_obj(
            uuid,
            "CN=frank,DC=corp,DC=com",
            vec![
                make_attr(0x10, "memberOf", b"CN=Group1,DC=corp,DC=com"),
                make_attr(0x10, "memberOf", b"CN=Group2,DC=corp,DC=com"),
                make_attr(0x10, "memberOf", b"CN=Group3,DC=corp,DC=com"),
            ],
        );
        store.put(&obj).await.unwrap();
        let got = store.get(uuid).await.unwrap().unwrap();
        // All three values must round-trip, with the same attribute_id and
        // distinct value_indices (0, 1, 2).
        assert_eq!(got.attributes.len(), 3);
        assert!(got.attributes.iter().all(|a| a.attribute_id == 0x10));
        assert!(got.attributes.iter().all(|a| a.name == "memberOf"));
        let values: Vec<&[u8]> = got.attributes.iter().map(|a| a.value.as_slice()).collect();
        assert_eq!(values[0], b"CN=Group1,DC=corp,DC=com");
        assert_eq!(values[1], b"CN=Group2,DC=corp,DC=com");
        assert_eq!(values[2], b"CN=Group3,DC=corp,DC=com");
    }

    #[tokio::test]
    async fn fallback_raw_write_txn_atomic_add_on_dnt_counter() {
        // Verify the low-level WriteTxn::atomic_add interface works
        // against the in-memory backend, mirroring the real FDB path's
        // use of `Transaction::atomic_op(AtomicOp::Add)` on the DNT
        // counter key.
        let store = FdbDirectoryStore::in_memory();
        let key = adrian_storage_core::encode_dnt_counter_key();
        // atomic_add 5, then 7 — counter should be 12 after commit.
        let txn = store.begin_write().await.unwrap();
        txn.atomic_add(&key, 5).await.unwrap();
        txn.atomic_add(&key, 7).await.unwrap();
        txn.commit().await.unwrap();
        let read = store.begin_read().await.unwrap();
        let bytes = read.get(&key).await.unwrap().unwrap();
        let v = i64::from_be_bytes(bytes[..].try_into().unwrap());
        assert_eq!(v, 12, "two atomic_adds of 5 and 7 must produce 12");
    }

    #[tokio::test]
    async fn fallback_snapshot_shares_underlying_storage() {
        let store = FdbDirectoryStore::in_memory();
        let snap = store.snapshot();
        // Write through the original store; the snapshot (which shares the
        // underlying Arc<RwLock<BTreeMap>>) must observe the write.
        store
            .put(&make_obj(test_uuid(11), "CN=g,DC=corp,DC=com", vec![]))
            .await
            .unwrap();
        let got = snap.get(test_uuid(11)).await.unwrap();
        assert!(
            got.is_some(),
            "snapshot must reflect writes through the original store"
        );
    }

    #[tokio::test]
    async fn fallback_legacy_encode_object_key_compat() {
        // Verify the legacy `encode_object_key(subspace_u8, ...)` API
        // still works (backward-compat with the previous stub).
        let k1 = encode_object_key(0x01, 42, 3, 0);
        let k2 = adrian_storage_core::encode_object_key(Subspace::Objects, 42, 3, 0);
        assert_eq!(k1, k2, "legacy and canonical encoders must agree");
    }

    // ===== Legacy encoding tests (kept from the previous stub) =====

    #[test]
    fn encode_object_key_structure() {
        let key = encode_object_key(0x01, 42, 3, 0);
        assert_eq!(key[0], 0x01);
        assert!(key.len() > 1);
    }

    #[test]
    fn encode_object_key_different_dnts() {
        let k1 = encode_object_key(0x01, 42, 3, 0);
        let k2 = encode_object_key(0x01, 43, 3, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn encode_object_key_different_subspaces() {
        let k1 = encode_object_key(0x01, 42, 3, 0);
        let k2 = encode_object_key(0x02, 42, 3, 0);
        assert_ne!(k1, k2);
    }

    #[test]
    fn encode_link_forward_key_structure() {
        let key = encode_link_forward_key(10, 5, 20);
        assert!(!key.is_empty());
    }

    #[test]
    fn encode_link_forward_key_different_links() {
        let k1 = encode_link_forward_key(10, 5, 20);
        let k2 = encode_link_forward_key(10, 5, 21);
        assert_ne!(k1, k2);
    }

    // ===== Real-FDB integration tests (require `--features fdb` + cluster) =====
    //
    // Wave 1 (T-104): these tests are now un-ignored and run as part of the
    // default `cargo test --features fdb` invocation against a real FDB
    // cluster. Each test calls `clear_all_keys(&store)` at the start to
    // ensure idempotency across repeated test runs (so running the suite
    // twice doesn't fail with stale-state errors).
    //
    // To run them, the build/runtime environment MUST have:
    //   1. libclang (for `foundationdb-sys`'s bindgen step).
    //   2. The FDB C client library (`libfdb_c.so`) on the linker path
    //      (e.g. via `LD_LIBRARY_PATH`).
    //   3. A running FDB cluster reachable at the address in
    //      `FDB_CLUSTER_FILE` (or `docker.cluster:4500` by default).

    /// Wave 1 (T-104): helper that wipes all keys in the cluster so each
    /// integration test starts from a clean slate. Uses the half-open range
    /// `[b"\x00", b"\xff")` which covers the entire FDB keyspace.
    #[cfg(feature = "fdb")]
    async fn clear_all_keys(store: &FdbDirectoryStore) {
        let txn = store.begin_write().await.expect("begin_write");
        txn.clear_range(b"\x00", b"\xff")
            .await
            .expect("clear_range");
        let boxed: Box<dyn WriteTxn> = txn;
        boxed.commit().await.expect("commit");
    }

    /// Wave 1 (T-104): a process-wide Mutex that serializes the real-FDB
    /// integration tests. Without this, cargo's parallel test runner would
    /// execute `real_fdb_*` tests concurrently and one test's
    /// `clear_all_keys` would wipe another test's data mid-flight. Each
    /// real-FDB test acquires this lock at the start and holds it for the
    /// duration of the test body (across all `.await` points).
    #[cfg(feature = "fdb")]
    static REAL_FDB_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[cfg(feature = "fdb")]
    #[tokio::test]
    async fn real_fdb_put_then_get_roundtrip() {
        let _guard = REAL_FDB_TEST_LOCK.lock().await;
        let store = FdbDirectoryStore::connect(None).await.unwrap();
        clear_all_keys(&store).await;
        assert!(!store.is_in_memory_fallback());
        let uuid = test_uuid(1);
        let obj = make_obj(
            uuid,
            "CN=real,DC=corp,DC=com",
            vec![make_attr(3, "cn", b"real")],
        );
        store.put(&obj).await.unwrap();
        let got = store.get(uuid).await.unwrap().expect("object should exist");
        assert_eq!(got.uuid, uuid);
        assert_eq!(got.dn.dn, "CN=real,DC=corp,DC=com");
        store.delete(uuid).await.unwrap();
        assert!(store.get(uuid).await.unwrap().is_none());
    }

    #[cfg(feature = "fdb")]
    #[tokio::test]
    async fn real_fdb_delete_creates_tombstone() {
        let _guard = REAL_FDB_TEST_LOCK.lock().await;
        let store = FdbDirectoryStore::connect(None).await.unwrap();
        clear_all_keys(&store).await;
        let uuid = test_uuid(2);
        store
            .put(&make_obj(uuid, "CN=tomb,DC=corp,DC=com", vec![]))
            .await
            .unwrap();
        store.delete(uuid).await.unwrap();
        assert!(store.get(uuid).await.unwrap().is_none());
        let txn = store.begin_read().await.unwrap();
        let prefix = vec![Subspace::Tombstones as u8];
        let mut end = prefix.clone();
        end[0] += 1;
        let rows = txn.get_range(&prefix, &end).await.unwrap();
        assert!(!rows.is_empty(), "tombstone row must exist after delete");
    }

    #[cfg(feature = "fdb")]
    #[tokio::test]
    async fn real_fdb_atomic_add_dnt_counter() {
        let _guard = REAL_FDB_TEST_LOCK.lock().await;
        let store = FdbDirectoryStore::connect(None).await.unwrap();
        clear_all_keys(&store).await;
        store
            .put(&make_obj(test_uuid(10), "CN=a,DC=corp,DC=com", vec![]))
            .await
            .unwrap();
        store
            .put(&make_obj(test_uuid(11), "CN=b,DC=corp,DC=com", vec![]))
            .await
            .unwrap();
        let read = store.begin_read().await.unwrap();
        let key = adrian_storage_core::encode_dnt_counter_key();
        let bytes = read.get(&key).await.unwrap().unwrap();
        let v = i64::from_be_bytes(bytes[..].try_into().unwrap());
        assert_eq!(v, 2, "DNT counter must be 2 after two inserts");
    }
}
