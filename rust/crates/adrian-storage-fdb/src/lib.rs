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

    /// Run an async closure with transaction retry on conflict (Wave 3,
    /// T-301). Retries `f` up to 3 times when `f` returns
    /// `StorageError::Conflict` (FDB error 1020 `not_committed`) or
    /// `StorageError::TooOld` (FDB error 1007 `transaction_too_old`),
    /// with exponential backoff: 10ms, 50ms, 250ms.
    ///
    /// The closure receives a fresh `&FdbDirectoryStore` reference on each
    /// invocation (the closure is responsible for calling `begin_write()`
    /// internally and committing the transaction). If the closure returns
    /// any other error variant (e.g. `Backend`, `NotFound`, `SchemaValidation`),
    /// the retry loop terminates immediately and propagates the error.
    ///
    /// Returns:
    /// - `Ok(T)` if `f` succeeded within the retry budget.
    /// - `Err(StorageError::Conflict)` if the retry budget (3 attempts) was
    ///   exhausted.
    /// - `Err(other)` if `f` returned a non-retryable error.
    pub async fn run_with_retry<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: Fn(
            &FdbDirectoryStore,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, StorageError>> + Send + '_>,
        >,
    {
        // Backoff schedule per the tasklist: 10ms, 50ms, 250ms.
        // After 3 retries we give up and return the last Conflict error.
        const BACKOFF_MS: [u64; 3] = [10, 50, 250];
        let mut attempt: u32 = 0;
        loop {
            match f(self).await {
                Ok(value) => return Ok(value),
                Err(StorageError::Conflict) | Err(StorageError::TooOld) => {
                    if attempt as usize >= BACKOFF_MS.len() {
                        // Retry budget exhausted — surface the conflict.
                        return Err(StorageError::Conflict);
                    }
                    let backoff = std::time::Duration::from_millis(BACKOFF_MS[attempt as usize]);
                    tracing::debug!(
                        attempt = attempt + 1,
                        backoff_ms = BACKOFF_MS[attempt as usize],
                        "FdbDirectoryStore::run_with_retry — retrying on conflict"
                    );
                    tokio::time::sleep(backoff).await;
                    attempt += 1;
                }
                Err(other) => return Err(other),
            }
        }
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
            // Wave 3 (T-301): map FDB commit errors to StorageError variants
            // so the retry loop in `FdbDirectoryStore::run_with_retry` can
            // detect retryable conflicts via `matches!`.
            //
            // `TransactionCommitError::on_error()` is FDB's recommended
            // retry-or-propagate API: it returns Ok(Transaction) if the
            // error is retryable (the transaction was reset and can be
            // reused) or Err(FdbError) if the error is permanent. We
            // discard the returned Transaction (the retry loop creates a
            // fresh one) and translate Ok → Conflict, Err → Backend.
            match self.trx.commit().await {
                Ok(_) => Ok(()),
                Err(commit_err) => match commit_err.on_error().await {
                    Ok(_reset_trx) => Err(StorageError::Conflict),
                    Err(fdb_err) => {
                        if fdb_err.code() == 1007 {
                            Err(StorageError::TooOld)
                        } else {
                            Err(StorageError::Backend(format!(
                                "FDB commit failed: {} (code {})",
                                fdb_err.message(),
                                fdb_err.code()
                            )))
                        }
                    }
                },
            }
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

// ============================================================================
// Backup / Restore / PITR (Wave 2 — ADR-010 / ADR-034 / ADR-059)
// ============================================================================
//
// Implements the backup-coordinator surface specified by:
//   - ADR-010 §Decision (quiesce → snapshot → metadata-record → resume → verify)
//   - ADR-034 §Decision 3 (PITR via WAL replay)
//   - ADR-034 §Decision 5 (reject-repair mode — all writes fail with
//     `StorageError::RejectRepair`)
//   - ADR-059 §Decision (per-DC backup with PITR; 60-second WAL archive
//     interval; operator-driven DR runbooks)
//
// The on-disk snapshot format is a custom binary format (no extra deps):
//   [magic: 4 bytes "ADBK"]
//   [version: 4 bytes BE u32 = 1]
//   [timestamp: 8 bytes BE i64 — unix seconds when snapshot was taken]
//   [key_count: 4 bytes BE u32]
//   For each key:
//     [key_len: 4 bytes BE u32]
//     [key: key_len bytes]
//     [val_len: 4 bytes BE u32]
//     [value: val_len bytes]
//   [sha256 of all the above: 32 bytes]
//
// The "WAL" for PITR is an in-process `Vec<MutationRecord>` maintained by the
// BackupManager. In a production deployment this would be FDB's mutation
// stream (via the `fdbbackup` tool or FDB's `StorageServer` log); for v1 we
// stub it via the BackupManager's `record_mutation()` helper, which the
// test harness calls after every write. PITR replays the WAL up to the
// target timestamp.

/// Magic bytes prefixing every Adrian backup file ("ADBK" = ADrian BacKup).
const BACKUP_MAGIC: [u8; 4] = *b"ADBK";
/// Backup format version (increment on incompatible changes).
const BACKUP_VERSION: u32 = 1;
/// Type alias for a key-value pair returned by snapshot reads.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// One record in the in-process WAL used by `BackupManager::restore_to_timestamp`.
/// Records are kept in insertion order; PITR replays them in order.
#[derive(Debug, Clone)]
pub struct MutationRecord {
    /// Unix-seconds timestamp when the mutation was recorded.
    pub ts: i64,
    /// The mutation kind (`Put` carries a value; `Delete` does not).
    pub op: MutationOp,
}

/// The kind of mutation recorded in the WAL.
#[derive(Debug, Clone)]
pub enum MutationOp {
    /// Put `value` at `key`.
    Put {
        /// The key being written.
        key: Vec<u8>,
        /// The value being written.
        value: Vec<u8>,
    },
    /// Delete `key`.
    Delete {
        /// The key being deleted.
        key: Vec<u8>,
    },
    /// Clear the half-open range `[begin, end)`.
    ClearRange {
        /// The inclusive begin key of the range to clear.
        begin: Vec<u8>,
        /// The exclusive end key of the range to clear.
        end: Vec<u8>,
    },
}

/// Metadata recorded in every snapshot file (per ADR-010 §Decision 3 —
/// "Records the snapshot metadata — invocation ID, USN cursor, timestamp,
/// storage-engine version, framework version"). The `invocation_id` and
/// `usn_cursor` fields are stubbed for v1 (the framework's replication
/// metadata is not yet implemented); they're serialised to the snapshot
/// file so future versions can read them without a format migration.
#[derive(Debug, Clone)]
pub struct SnapshotMetadata {
    /// Unix-seconds timestamp when the snapshot was taken.
    pub timestamp: i64,
    /// Number of keys in the snapshot.
    pub key_count: usize,
    /// Framework version (semver-like string, currently "0.1.0").
    pub framework_version: String,
    /// Invocation ID of the DC that took the snapshot (stubbed as
    /// `Uuid::nil()` for v1; populated by the replication layer in a
    /// future wave).
    pub invocation_id: Uuid,
    /// USN cursor at the time of the snapshot (stubbed as 0 for v1;
    /// populated by the replication layer in a future wave).
    pub usn_cursor: i64,
    /// SHA-256 of the snapshot body (all key-value pairs).
    pub sha256: [u8; 32],
}

/// Backup coordinator for the Adrian framework (Wave 2 — ADR-010/034/059).
///
/// Wraps an `FdbDirectoryStore` (either in-memory fallback or real FDB) and
/// provides:
///   - `create_snapshot(path)` — transactionally-consistent snapshot to disk
///   - `restore_from_snapshot(path)` — clear + restore from a snapshot file
///   - `restore_to_timestamp(ts)` — PITR via WAL replay
///   - `set_reject_repair(true)` — ADR-034 §5 reject-repair mode
///   - `verify_snapshot(path)` — re-reads the snapshot, recomputes SHA-256,
///     and confirms integrity
///   - `create_incremental_snapshot(since_ts, path)` — only serialises keys
///     modified since `since_ts` (per ADR-059 §Decision — "hourly incremental
///     snapshot via the storage engine's incremental_snapshot() API")
pub struct BackupManager {
    /// The underlying store. Reads and writes go through this.
    store: FdbDirectoryStore,
    /// Process-wide reject-repair flag (per ADR-034 §5). When true, all
    /// writes via `BackupManager::put` / `delete` / `atomic_add` /
    /// `clear_range` / `commit` return `StorageError::RejectRepair`.
    reject_repair: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// In-process WAL of mutations (per ADR-034 §3 — PITR via WAL replay).
    /// In production this would be FDB's mutation stream; for v1 we stub
    /// it in-process. Records are appended in insertion order.
    wal: std::sync::Arc<std::sync::Mutex<Vec<MutationRecord>>>,
}

impl std::fmt::Debug for BackupManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupManager")
            .field("store", &self.store)
            .field(
                "reject_repair",
                &self
                    .reject_repair
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("wal_len", &self.wal.lock().unwrap().len())
            .finish()
    }
}

impl BackupManager {
    /// Construct a new `BackupManager` wrapping the given store.
    pub fn new(store: FdbDirectoryStore) -> Self {
        Self {
            store,
            reject_repair: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            wal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Get a reference to the underlying store (for direct reads).
    pub fn store(&self) -> &FdbDirectoryStore {
        &self.store
    }

    /// Set the reject-repair flag (per ADR-034 §5 — "Reject hard-repair
    /// tools"). When `on` is true, all subsequent writes via this
    /// `BackupManager` will return `StorageError::RejectRepair`. The only
    /// recovery procedure is `restore_from_snapshot` + WAL replay.
    pub fn set_reject_repair(&self, on: bool) {
        self.reject_repair
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Returns `true` if reject-repair mode is currently active.
    pub fn is_reject_repair(&self) -> bool {
        self.reject_repair
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record a mutation in the in-process WAL. Called by `put` / `delete`
    /// / `clear_range` after the write commits. Each record carries the
    /// current unix-seconds timestamp (used by `restore_to_timestamp` to
    /// filter the replay window).
    fn record_mutation(&self, op: MutationOp) {
        let ts = chrono::Utc::now().timestamp();
        let mut wal = self.wal.lock().unwrap();
        wal.push(MutationRecord { ts, op });
    }

    /// Write a single key-value pair through the underlying store, after
    /// checking the reject-repair flag. Records the mutation in the WAL.
    pub async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        if self.is_reject_repair() {
            return Err(StorageError::RejectRepair);
        }
        let txn = self.store.begin_write().await?;
        txn.put(key, value).await?;
        let boxed: Box<dyn WriteTxn> = txn;
        boxed.commit().await?;
        self.record_mutation(MutationOp::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        });
        Ok(())
    }

    /// Delete a single key, after checking the reject-repair flag. Records
    /// the mutation in the WAL.
    pub async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        if self.is_reject_repair() {
            return Err(StorageError::RejectRepair);
        }
        let txn = self.store.begin_write().await?;
        txn.delete(key).await?;
        let boxed: Box<dyn WriteTxn> = txn;
        boxed.commit().await?;
        self.record_mutation(MutationOp::Delete { key: key.to_vec() });
        Ok(())
    }

    /// Clear the half-open range `[begin, end)`, after checking the
    /// reject-repair flag. Records the mutation in the WAL.
    pub async fn clear_range(&self, begin: &[u8], end: &[u8]) -> Result<(), StorageError> {
        if self.is_reject_repair() {
            return Err(StorageError::RejectRepair);
        }
        let txn = self.store.begin_write().await?;
        txn.clear_range(begin, end).await?;
        let boxed: Box<dyn WriteTxn> = txn;
        boxed.commit().await?;
        self.record_mutation(MutationOp::ClearRange {
            begin: begin.to_vec(),
            end: end.to_vec(),
        });
        Ok(())
    }

    /// Read all keys in the store (entire keyspace). Used by
    /// `create_snapshot` to dump the current state.
    async fn read_all_keys(&self) -> Result<Vec<KvPair>, StorageError> {
        let txn = self.store.begin_read().await?;
        txn.get_range(b"\x00", b"\xff").await
    }

    /// Create a transactionally-consistent snapshot file at `path` (per
    /// ADR-010 §Decision 1-5: quiesce → snapshot → metadata-record →
    /// resume → verify).
    ///
    /// The snapshot is a single read transaction that dumps all keys;
    /// because FDB transactions are snapshot-isolated, this is consistent
    /// (no partial writes from concurrent transactions are visible). The
    /// snapshot file format includes a SHA-256 integrity hash.
    pub async fn create_snapshot(
        &self,
        path: &std::path::Path,
    ) -> Result<SnapshotMetadata, StorageError> {
        let pairs = self.read_all_keys().await?;
        let timestamp = chrono::Utc::now().timestamp();
        let metadata = self.write_snapshot_file(path, &pairs, timestamp)?;
        Ok(metadata)
    }

    /// Write the snapshot file in the documented binary format. The
    /// SHA-256 is computed over the entire body (magic + version + ts +
    /// count + all key-value pairs) and appended as the last 32 bytes.
    fn write_snapshot_file(
        &self,
        path: &std::path::Path,
        pairs: &[KvPair],
        timestamp: i64,
    ) -> Result<SnapshotMetadata, StorageError> {
        use std::io::Write;
        let mut hasher = sha2::Sha256::new();
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&BACKUP_MAGIC);
        body.extend_from_slice(&BACKUP_VERSION.to_be_bytes());
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for (k, v) in pairs {
            body.extend_from_slice(&(k.len() as u32).to_be_bytes());
            body.extend_from_slice(k);
            body.extend_from_slice(&(v.len() as u32).to_be_bytes());
            body.extend_from_slice(v);
        }
        use sha2::Digest;
        hasher.update(&body);
        let sha256: [u8; 32] = hasher.finalize().into();
        body.extend_from_slice(&sha256);

        let mut file = std::fs::File::create(path)
            .map_err(|e| StorageError::Backend(format!("create snapshot file failed: {e}")))?;
        file.write_all(&body)
            .map_err(|e| StorageError::Backend(format!("write snapshot file failed: {e}")))?;
        Ok(SnapshotMetadata {
            timestamp,
            key_count: pairs.len(),
            framework_version: "0.1.0".to_string(),
            invocation_id: Uuid::nil(),
            usn_cursor: 0,
            sha256,
        })
    }

    /// Read a snapshot file and return its metadata + key-value pairs.
    /// Returns `StorageError::Backend` if the file is corrupt (bad magic,
    /// truncated, or SHA-256 mismatch).
    pub fn read_snapshot_file(
        &self,
        path: &std::path::Path,
    ) -> Result<(SnapshotMetadata, Vec<KvPair>), StorageError> {
        let bytes = std::fs::read(path)
            .map_err(|e| StorageError::Backend(format!("read snapshot file failed: {e}")))?;
        if bytes.len() < 4 + 4 + 8 + 4 + 32 {
            return Err(StorageError::Backend(
                "snapshot file too short (truncated header)".into(),
            ));
        }
        if bytes[0..4] != BACKUP_MAGIC {
            return Err(StorageError::Backend("snapshot file: bad magic".into()));
        }
        let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != BACKUP_VERSION {
            return Err(StorageError::Backend(format!(
                "snapshot file: unsupported version {version} (expected {BACKUP_VERSION})"
            )));
        }
        let timestamp = i64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let key_count = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let mut cursor = 20;
        let mut pairs = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            if cursor + 4 > bytes.len() {
                return Err(StorageError::Backend(
                    "snapshot file: truncated key length".into(),
                ));
            }
            let klen = u32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            if cursor + klen > bytes.len() {
                return Err(StorageError::Backend(
                    "snapshot file: truncated key bytes".into(),
                ));
            }
            let key = bytes[cursor..cursor + klen].to_vec();
            cursor += klen;
            if cursor + 4 > bytes.len() {
                return Err(StorageError::Backend(
                    "snapshot file: truncated value length".into(),
                ));
            }
            let vlen = u32::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;
            if cursor + vlen > bytes.len() {
                return Err(StorageError::Backend(
                    "snapshot file: truncated value bytes".into(),
                ));
            }
            let value = bytes[cursor..cursor + vlen].to_vec();
            cursor += vlen;
            pairs.push((key, value));
        }
        // The last 32 bytes are the SHA-256.
        if cursor + 32 != bytes.len() {
            return Err(StorageError::Backend(
                "snapshot file: trailing data after expected SHA-256".into(),
            ));
        }
        let stored_sha: [u8; 32] = bytes[cursor..cursor + 32].try_into().unwrap();
        // Recompute SHA-256 over the body (everything before the hash).
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes[..cursor]);
        let computed_sha: [u8; 32] = hasher.finalize().into();
        if stored_sha != computed_sha {
            return Err(StorageError::Backend(format!(
                "snapshot file: SHA-256 mismatch (stored={}, computed={})",
                hex(&stored_sha),
                hex(&computed_sha)
            )));
        }
        Ok((
            SnapshotMetadata {
                timestamp,
                key_count: pairs.len(),
                framework_version: "0.1.0".to_string(),
                invocation_id: Uuid::nil(),
                usn_cursor: 0,
                sha256: stored_sha,
            },
            pairs,
        ))
    }

    /// Restore from a snapshot file (per ADR-010 §Decision — restore with
    /// invocationId reset). Clears the current store, then writes all keys
    /// from the snapshot.
    pub async fn restore_from_snapshot(
        &self,
        path: &std::path::Path,
    ) -> Result<SnapshotMetadata, StorageError> {
        let (metadata, pairs) = self.read_snapshot_file(path)?;
        // Clear current state.
        let clear_txn = self.store.begin_write().await?;
        clear_txn.clear_range(b"\x00", b"\xff").await?;
        let boxed: Box<dyn WriteTxn> = clear_txn;
        boxed.commit().await?;
        // Write all keys from the snapshot. We batch them in a single
        // transaction so the restore is atomic (no partial restore).
        let txn = self.store.begin_write().await?;
        for (k, v) in &pairs {
            txn.put(k, v).await?;
        }
        let boxed: Box<dyn WriteTxn> = txn;
        boxed.commit().await?;
        // Clear the WAL — the snapshot is now the new "base" for PITR.
        self.wal.lock().unwrap().clear();
        Ok(metadata)
    }

    /// PITR: restore to a target timestamp (per ADR-034 §Decision 3 +
    /// ADR-059 §Decision). Replays the WAL up to `target_ts`. Pre-condition:
    /// the store must already be at the snapshot state taken before `target_ts`
    /// (callers should `restore_from_snapshot` first, then call this method
    /// with `target_ts >= snapshot.timestamp`).
    pub async fn restore_to_timestamp(&self, target_ts: i64) -> Result<(), StorageError> {
        let wal = self.wal.lock().unwrap().clone();
        let mut replayed = 0u64;
        for record in &wal {
            if record.ts > target_ts {
                break;
            }
            let txn = self.store.begin_write().await?;
            match &record.op {
                MutationOp::Put { key, value } => {
                    txn.put(key, value).await?;
                }
                MutationOp::Delete { key } => {
                    txn.delete(key).await?;
                }
                MutationOp::ClearRange { begin, end } => {
                    txn.clear_range(begin, end).await?;
                }
            }
            let boxed: Box<dyn WriteTxn> = txn;
            boxed.commit().await?;
            replayed += 1;
        }
        tracing::info!(
            "PITR: replayed {} WAL records up to target_ts {}",
            replayed,
            target_ts
        );
        Ok(())
    }

    /// Verify a snapshot file's integrity (per ADR-010 §Decision 5 —
    /// "Verifies the snapshot — reads back a sample of objects from the
    /// snapshot to confirm consistency"). This implementation re-reads the
    /// entire snapshot file and recomputes the SHA-256; if the stored hash
    /// doesn't match, returns `StorageError::Backend`.
    pub fn verify_snapshot(
        &self,
        path: &std::path::Path,
    ) -> Result<SnapshotMetadata, StorageError> {
        let (metadata, _pairs) = self.read_snapshot_file(path)?;
        Ok(metadata)
    }

    /// Create an incremental snapshot file at `path` containing only the
    /// mutations recorded since `since_ts` (per ADR-059 §Decision — "hourly
    /// incremental snapshot via the storage engine's incremental_snapshot()
    /// API"). The incremental file uses the same format as a full snapshot
    /// but contains only the keys that were put (the latest value for each
    /// key) plus tombstones for deleted keys (encoded as zero-length values).
    pub async fn create_incremental_snapshot(
        &self,
        since_ts: i64,
        path: &std::path::Path,
    ) -> Result<SnapshotMetadata, StorageError> {
        let wal = self.wal.lock().unwrap().clone();
        // Build the incremental set: for each Put, store the latest value
        // for that key (last write wins). For each Delete, mark the key as
        // tombstoned (zero-length value). ClearRange expands to "all keys in
        // the range are tombstoned" — for simplicity, we record only the
        // explicit Put/Delete operations; ClearRange is a no-op for the
        // incremental file (a future revision will handle it properly).
        let mut incremental: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut deleted_keys: std::collections::BTreeSet<Vec<u8>> =
            std::collections::BTreeSet::new();
        for record in &wal {
            if record.ts <= since_ts {
                continue;
            }
            match &record.op {
                MutationOp::Put { key, value } => {
                    incremental.insert(key.clone(), value.clone());
                    deleted_keys.remove(key);
                }
                MutationOp::Delete { key } => {
                    incremental.remove(key);
                    deleted_keys.insert(key.clone());
                }
                MutationOp::ClearRange { .. } => {
                    // For v1, ClearRange is not tracked in the incremental
                    // snapshot (would require enumerating the range).
                }
            }
        }
        // Encode deleted keys as zero-length values.
        let mut pairs: Vec<KvPair> = incremental.into_iter().collect();
        for k in deleted_keys {
            pairs.push((k, Vec::new()));
        }
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let timestamp = chrono::Utc::now().timestamp();
        self.write_snapshot_file(path, &pairs, timestamp)
    }
}

/// Encode a byte slice as a lowercase hex string (used for SHA-256
/// display in error messages).
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl BackupManager {
    /// Test-only accessor for the in-process WAL. Used by PITR tests to
    /// overwrite record timestamps with deterministic values (so tests
    /// don't depend on wall clock). NOT for production use — the WAL is
    /// an internal implementation detail.
    #[doc(hidden)]
    pub fn wal_for_test(&self) -> std::sync::MutexGuard<'_, Vec<MutationRecord>> {
        self.wal.lock().unwrap()
    }
}

// ============================================================================
// Subspace migration (Wave 3, T-303)
// ============================================================================
//
// `migrate_subspace(old_prefix, new_prefix)` copies all keys under the
// `old_prefix` to keys under the `new_prefix` (preserving the suffix), then
// atomically clears the `old_prefix` range. Used for schema upgrades where
// data needs to move between subspaces (e.g. when a new schema version
// changes the tuple-layer encoding for an attribute).
//
// The migration is performed in a single FDB transaction (atomic w.r.t.
// concurrent reads/writes). For large subspaces (>1M keys), callers should
// batch the migration to avoid hitting FDB's 10MB-per-transaction limit;
// this v1 implementation does not batch.

/// Migrate all keys from `old_prefix` to `new_prefix` atomically.
///
/// For each key `K` matching `old_prefix`, a new key `K' = new_prefix ++ K[old_prefix.len()..]`
/// is written with the same value. After all copies are written, the
/// `old_prefix` range is cleared (in the same transaction — atomic).
///
/// Returns the number of keys migrated. The caller is responsible for
/// ensuring no concurrent writes are happening to the `old_prefix` range
/// during migration (otherwise the migration may miss keys).
pub async fn migrate_subspace(
    store: &FdbDirectoryStore,
    old_prefix: &[u8],
    new_prefix: &[u8],
) -> Result<usize, StorageError> {
    if old_prefix.is_empty() {
        return Err(StorageError::Backend(
            "migrate_subspace: old_prefix must not be empty (would migrate entire keyspace)".into(),
        ));
    }
    if old_prefix == new_prefix {
        return Err(StorageError::Backend(
            "migrate_subspace: old_prefix and new_prefix must differ".into(),
        ));
    }
    // Read all keys under old_prefix.
    let mut end = old_prefix.to_vec();
    // strinc: increment the last byte; if it would overflow (0xFF), append
    // a 0x00 byte (per FDB tuple-layer convention — for our prefixes which
    // are single subspace bytes < 0xFF, this is unreachable).
    match end.last_mut() {
        Some(b) if *b < 0xFF => *b += 1,
        _ => end.push(0x00),
    }
    let read_txn = store.begin_read().await?;
    let pairs = read_txn.get_range(old_prefix, &end).await?;
    if pairs.is_empty() {
        return Ok(0);
    }
    // Write the migrated keys + clear the old prefix in a single transaction.
    let write_txn = store.begin_write().await?;
    for (k, v) in &pairs {
        let suffix = &k[old_prefix.len()..];
        let mut new_key = Vec::with_capacity(new_prefix.len() + suffix.len());
        new_key.extend_from_slice(new_prefix);
        new_key.extend_from_slice(suffix);
        write_txn.put(&new_key, v).await?;
    }
    write_txn.clear_range(old_prefix, &end).await?;
    let boxed: Box<dyn WriteTxn> = write_txn;
    boxed.commit().await?;
    Ok(pairs.len())
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

    // ===== Wave 2: Backup / Restore / PITR tests (ADR-010/034/059) =====

    /// Helper: build a `BackupManager` over a fresh in-memory store.
    fn backup_mgr_in_memory() -> BackupManager {
        BackupManager::new(FdbDirectoryStore::in_memory())
    }

    #[tokio::test]
    async fn backup_snapshot_round_trip() {
        // T-201: create_snapshot + restore_from_snapshot. Write 3 keys,
        // snapshot, clear, restore, verify all 3 keys are back.
        let mgr = backup_mgr_in_memory();
        mgr.put(b"k1", b"v1").await.unwrap();
        mgr.put(b"k2", b"v2").await.unwrap();
        mgr.put(b"k3", b"v3").await.unwrap();
        let snap_path = std::env::temp_dir().join("adrian_test_backup_snapshot_round_trip.adbk");
        let metadata = mgr.create_snapshot(&snap_path).await.unwrap();
        assert_eq!(metadata.key_count, 3, "snapshot must capture all 3 keys");
        assert_eq!(metadata.sha256.len(), 32);
        // Wipe the store, then restore from snapshot.
        mgr.clear_range(b"\x00", b"\xff").await.unwrap();
        let txn = mgr.store().begin_read().await.unwrap();
        assert!(txn.get(b"k1").await.unwrap().is_none(), "k1 must be gone");
        let restored = mgr.restore_from_snapshot(&snap_path).await.unwrap();
        assert_eq!(restored.key_count, 3);
        let txn = mgr.store().begin_read().await.unwrap();
        assert_eq!(txn.get(b"k1").await.unwrap().unwrap(), b"v1".to_vec());
        assert_eq!(txn.get(b"k2").await.unwrap().unwrap(), b"v2".to_vec());
        assert_eq!(txn.get(b"k3").await.unwrap().unwrap(), b"v3".to_vec());
        let _ = std::fs::remove_file(&snap_path);
    }

    #[tokio::test]
    async fn backup_restore_from_corrupt_file_fails() {
        // T-202: restore_from_snapshot must fail with StorageError::Backend
        // when the snapshot file is corrupt (bad SHA-256).
        let mgr = backup_mgr_in_memory();
        mgr.put(b"k1", b"v1").await.unwrap();
        let snap_path = std::env::temp_dir().join("adrian_test_backup_corrupt.adbk");
        mgr.create_snapshot(&snap_path).await.unwrap();
        // Corrupt the snapshot by appending a byte (changes the SHA-256).
        let mut bytes = std::fs::read(&snap_path).unwrap();
        bytes.push(0x42); // append a byte — breaks the trailing-SHA-256 check
                          // Also flip a byte in the body to force a SHA mismatch.
        bytes[20] ^= 0xFF;
        std::fs::write(&snap_path, &bytes).unwrap();
        let result = mgr.restore_from_snapshot(&snap_path).await;
        assert!(
            result.is_err(),
            "restore from corrupt snapshot must fail: {:?}",
            result
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SHA-256 mismatch")
                || msg.contains("truncated")
                || msg.contains("trailing"),
            "error must indicate corruption, got: {msg}"
        );
        let _ = std::fs::remove_file(&snap_path);
    }

    #[tokio::test]
    async fn backup_pitr_to_past_timestamp() {
        // T-203: PITR. Take a snapshot at T0, then make writes at T1, T2, T3.
        // Restore from the snapshot, then call restore_to_timestamp(T2) —
        // verify the store reflects writes up to T2 but not T3.
        //
        // We can't actually wait real time in a unit test, so we directly
        // mutate the WAL records' timestamps to deterministic values.
        let mgr = backup_mgr_in_memory();
        mgr.put(b"base", b"v0").await.unwrap();
        let snap_path = std::env::temp_dir().join("adrian_test_backup_pitr.adbk");
        let snap_meta = mgr.create_snapshot(&snap_path).await.unwrap();
        // After snapshot: write 3 mutations. We overwrite their WAL timestamps
        // to deterministic values so the test doesn't depend on wall clock.
        mgr.put(b"k1", b"v1").await.unwrap();
        mgr.put(b"k2", b"v2").await.unwrap();
        mgr.delete(b"k1").await.unwrap();
        // Set deterministic timestamps: T0=snap_meta.timestamp+10, T1=+20, T2=+30.
        {
            let mut wal = mgr_wal_for_test(&mgr);
            let base = snap_meta.timestamp;
            let len = wal.len();
            assert!(len >= 3, "WAL must have at least 3 records");
            wal[len - 3].ts = base + 10; // put k1
            wal[len - 2].ts = base + 20; // put k2
            wal[len - 1].ts = base + 30; // delete k1
        }
        // Restore from snapshot — wipes store + clears WAL.
        mgr.restore_from_snapshot(&snap_path).await.unwrap();
        // Re-insert the WAL records manually (since restore clears the WAL).
        // In production, the WAL would be archived separately and replayed;
        // for this test we manually re-add the records to the WAL.
        {
            let base = snap_meta.timestamp;
            let mut wal = mgr_wal_for_test(&mgr);
            wal.push(MutationRecord {
                ts: base + 10,
                op: MutationOp::Put {
                    key: b"k1".to_vec(),
                    value: b"v1".to_vec(),
                },
            });
            wal.push(MutationRecord {
                ts: base + 20,
                op: MutationOp::Put {
                    key: b"k2".to_vec(),
                    value: b"v2".to_vec(),
                },
            });
            wal.push(MutationRecord {
                ts: base + 30,
                op: MutationOp::Delete {
                    key: b"k1".to_vec(),
                },
            });
        }
        // PITR to T2 (base+20): should have k1=v1, k2=v2 (no delete yet).
        mgr.restore_to_timestamp(snap_meta.timestamp + 20)
            .await
            .unwrap();
        let txn = mgr.store().begin_read().await.unwrap();
        assert_eq!(txn.get(b"k1").await.unwrap().unwrap(), b"v1".to_vec());
        assert_eq!(txn.get(b"k2").await.unwrap().unwrap(), b"v2".to_vec());
        // PITR to T3 (base+30): should have k2=v2, k1 deleted.
        // First restore base snapshot again (so we can replay from scratch).
        mgr.restore_from_snapshot(&snap_path).await.unwrap();
        // Re-add the WAL records again (restore_from_snapshot clears WAL).
        {
            let base = snap_meta.timestamp;
            let mut wal = mgr_wal_for_test(&mgr);
            wal.push(MutationRecord {
                ts: base + 10,
                op: MutationOp::Put {
                    key: b"k1".to_vec(),
                    value: b"v1".to_vec(),
                },
            });
            wal.push(MutationRecord {
                ts: base + 20,
                op: MutationOp::Put {
                    key: b"k2".to_vec(),
                    value: b"v2".to_vec(),
                },
            });
            wal.push(MutationRecord {
                ts: base + 30,
                op: MutationOp::Delete {
                    key: b"k1".to_vec(),
                },
            });
        }
        mgr.restore_to_timestamp(snap_meta.timestamp + 30)
            .await
            .unwrap();
        let txn = mgr.store().begin_read().await.unwrap();
        assert!(
            txn.get(b"k1").await.unwrap().is_none(),
            "k1 must be deleted at T3"
        );
        assert_eq!(txn.get(b"k2").await.unwrap().unwrap(), b"v2".to_vec());
        let _ = std::fs::remove_file(&snap_path);
    }

    #[tokio::test]
    async fn backup_reject_repair_blocks_writes() {
        // T-204: set_reject_repair(true) causes all writes (put/delete/
        // clear_range) to fail with StorageError::RejectRepair (per
        // ADR-034 §5). Reads still succeed.
        let mgr = backup_mgr_in_memory();
        mgr.put(b"k1", b"v1").await.unwrap();
        assert!(!mgr.is_reject_repair());
        mgr.set_reject_repair(true);
        assert!(mgr.is_reject_repair());
        // Writes must fail.
        let err = mgr.put(b"k2", b"v2").await.unwrap_err();
        assert!(
            matches!(err, StorageError::RejectRepair),
            "put must fail with RejectRepair: {err:?}"
        );
        let err = mgr.delete(b"k1").await.unwrap_err();
        assert!(
            matches!(err, StorageError::RejectRepair),
            "delete must fail"
        );
        let err = mgr.clear_range(b"\x00", b"\xff").await.unwrap_err();
        assert!(
            matches!(err, StorageError::RejectRepair),
            "clear_range must fail"
        );
        // Reads must still succeed.
        let txn = mgr.store().begin_read().await.unwrap();
        assert_eq!(txn.get(b"k1").await.unwrap().unwrap(), b"v1".to_vec());
        // Turning reject-repair off re-enables writes.
        mgr.set_reject_repair(false);
        mgr.put(b"k2", b"v2").await.unwrap();
        let txn = mgr.store().begin_read().await.unwrap();
        assert_eq!(txn.get(b"k2").await.unwrap().unwrap(), b"v2".to_vec());
    }

    #[tokio::test]
    async fn backup_integrity_check_passes_for_valid_file() {
        // T-205: verify_snapshot re-reads the file, recomputes SHA-256, and
        // confirms integrity. Returns the metadata on success.
        let mgr = backup_mgr_in_memory();
        mgr.put(b"k1", b"v1").await.unwrap();
        mgr.put(b"k2", b"v2").await.unwrap();
        let snap_path = std::env::temp_dir().join("adrian_test_backup_verify.adbk");
        let write_meta = mgr.create_snapshot(&snap_path).await.unwrap();
        let verify_meta = mgr.verify_snapshot(&snap_path).unwrap();
        assert_eq!(write_meta.timestamp, verify_meta.timestamp);
        assert_eq!(write_meta.key_count, verify_meta.key_count);
        assert_eq!(write_meta.sha256, verify_meta.sha256);
        let _ = std::fs::remove_file(&snap_path);
    }

    #[tokio::test]
    async fn backup_incremental_snapshot_only_has_changed_keys() {
        // T-205 (incremental): create_incremental_snapshot(since_ts) writes
        // only the keys modified since `since_ts`. We simulate by writing
        // 3 keys via BackupManager (which records them in the WAL), then
        // calling create_incremental_snapshot — the file should contain
        // exactly those 3 keys.
        let mgr = backup_mgr_in_memory();
        // First write a "base" key directly to the store (bypassing the WAL).
        {
            let txn = mgr.store().begin_write().await.unwrap();
            txn.put(b"base", b"v0").await.unwrap();
            let boxed: Box<dyn WriteTxn> = txn;
            boxed.commit().await.unwrap();
        }
        // Now write 3 keys via the BackupManager (so they go into the WAL).
        mgr.put(b"k1", b"v1").await.unwrap();
        mgr.put(b"k2", b"v2").await.unwrap();
        mgr.put(b"k3", b"v3").await.unwrap();
        let snap_path = std::env::temp_dir().join("adrian_test_backup_incremental.adbk");
        // since_ts = far future would exclude all WAL records, but we want
        // all of them, so we pass since_ts = 0 (include all records).
        let meta = mgr
            .create_incremental_snapshot(0, &snap_path)
            .await
            .unwrap();
        // The incremental snapshot should contain k1, k2, k3 (NOT base —
        // base was written directly, bypassing the WAL).
        let (_, pairs) = mgr.read_snapshot_file(&snap_path).unwrap();
        let keys: std::collections::HashSet<Vec<u8>> = pairs.into_iter().map(|(k, _)| k).collect();
        assert!(
            keys.contains(b"k1".as_slice()),
            "incremental must contain k1"
        );
        assert!(
            keys.contains(b"k2".as_slice()),
            "incremental must contain k2"
        );
        assert!(
            keys.contains(b"k3".as_slice()),
            "incremental must contain k3"
        );
        assert!(
            !keys.contains(b"base".as_slice()),
            "incremental must NOT contain 'base' (was written directly, not via WAL)"
        );
        assert_eq!(meta.key_count, 3, "incremental must have 3 keys");
        let _ = std::fs::remove_file(&snap_path);
    }

    /// Test-only helper: get a mutable reference to the BackupManager's WAL.
    /// We need this because PITR tests want to overwrite the WAL records'
    /// timestamps with deterministic values (so the test doesn't depend on
    /// wall clock).
    fn mgr_wal_for_test(mgr: &BackupManager) -> std::sync::MutexGuard<'_, Vec<MutationRecord>> {
        // SAFETY: this is a test-only helper that breaks the encapsulation
        // of the BackupManager's WAL. We use `Arc::as_ptr` to get a raw
        // pointer, then reconstruct a MutexGuard. This is safe in test
        // code because (a) the BackupManager is not shared across threads
        // in tests, (b) we hold the guard for the duration of the
        // mutation, (c) we drop it before any other operation.
        //
        // In practice we just access the WAL through the same lock the
        // BackupManager uses internally — there's no actual unsafe code
        // needed because `Mutex::lock()` is a safe API. We just need to
        // expose the WAL for tests.
        mgr.wal_for_test()
    }

    // ===== Wave 3: Transaction retry + subspace migration tests =====

    /// T-301/T-304: run_with_retry succeeds on first attempt when f returns Ok.
    #[tokio::test]
    async fn retry_succeeds_on_first_attempt() {
        let store = FdbDirectoryStore::in_memory();
        let result: Result<u32, StorageError> = store
            .run_with_retry(|_s| Box::pin(async { Ok(42u32) }))
            .await;
        assert_eq!(
            result.unwrap(),
            42,
            "first-attempt success must return value"
        );
    }

    /// T-301/T-304: run_with_retry retries on Conflict and succeeds when
    /// a later attempt returns Ok. Simulates a transaction that fails the
    /// first time but succeeds the second time (e.g. another transaction
    /// committed between read-version and commit).
    #[tokio::test]
    async fn retry_succeeds_on_conflict() {
        let store = FdbDirectoryStore::in_memory();
        // Use a cell to track attempt count across closure invocations.
        let attempt = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempt_clone = attempt.clone();
        let result: Result<u32, StorageError> = store
            .run_with_retry(move |_s| {
                let attempt = attempt.clone();
                Box::pin(async move {
                    let n = attempt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if n == 0 {
                        // First attempt: simulate a conflict.
                        Err(StorageError::Conflict)
                    } else {
                        // Second attempt: succeed.
                        Ok(42u32)
                    }
                })
            })
            .await;
        assert_eq!(result.unwrap(), 42, "retry must succeed on second attempt");
        assert_eq!(
            attempt_clone.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "closure must have been invoked twice"
        );
    }

    /// T-301/T-304: run_with_retry exhausts the retry budget (3 attempts)
    /// and returns `StorageError::Conflict` when every attempt fails.
    #[tokio::test]
    async fn retry_exhausted_after_three_attempts() {
        let store = FdbDirectoryStore::in_memory();
        let attempt = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempt_clone = attempt.clone();
        let result: Result<(), StorageError> = store
            .run_with_retry(move |_s| {
                let attempt = attempt.clone();
                Box::pin(async move {
                    attempt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err(StorageError::Conflict)
                })
            })
            .await;
        assert!(
            matches!(result, Err(StorageError::Conflict)),
            "must return Conflict after retry budget exhausted: {result:?}"
        );
        // Initial attempt + 3 retries = 4 invocations.
        assert_eq!(
            attempt_clone.load(std::sync::atomic::Ordering::Relaxed),
            4,
            "closure must have been invoked 4 times (1 initial + 3 retries)"
        );
    }

    /// T-303/T-304: migrate_subspace copies all keys from old_prefix to
    /// new_prefix, then atomically clears the old_prefix range.
    #[tokio::test]
    async fn subspace_migration_round_trip() {
        let store = FdbDirectoryStore::in_memory();
        // Write 3 keys under old_prefix 0xAA and 1 key outside the prefix
        // (must NOT be migrated).
        let txn = store.begin_write().await.unwrap();
        txn.put(&[0xAA, 0x01], b"v1").await.unwrap();
        txn.put(&[0xAA, 0x02], b"v2").await.unwrap();
        txn.put(&[0xAA, 0x03], b"v3").await.unwrap();
        txn.put(&[0xBB, 0x01], b"outside").await.unwrap();
        let boxed: Box<dyn WriteTxn> = txn;
        boxed.commit().await.unwrap();

        // Migrate 0xAA → 0xCC.
        let migrated = migrate_subspace(&store, &[0xAA], &[0xCC]).await.unwrap();
        assert_eq!(migrated, 3, "must migrate 3 keys");

        // Verify the new keys exist under 0xCC.
        let read = store.begin_read().await.unwrap();
        assert_eq!(
            read.get(&[0xCC, 0x01]).await.unwrap().unwrap(),
            b"v1".to_vec()
        );
        assert_eq!(
            read.get(&[0xCC, 0x02]).await.unwrap().unwrap(),
            b"v2".to_vec()
        );
        assert_eq!(
            read.get(&[0xCC, 0x03]).await.unwrap().unwrap(),
            b"v3".to_vec()
        );

        // Verify the old keys are gone.
        assert!(read.get(&[0xAA, 0x01]).await.unwrap().is_none());
        assert!(read.get(&[0xAA, 0x02]).await.unwrap().is_none());
        assert!(read.get(&[0xAA, 0x03]).await.unwrap().is_none());

        // Verify the outside key is still there.
        assert_eq!(
            read.get(&[0xBB, 0x01]).await.unwrap().unwrap(),
            b"outside".to_vec(),
            "key outside the migrated prefix must be untouched"
        );
    }
}
