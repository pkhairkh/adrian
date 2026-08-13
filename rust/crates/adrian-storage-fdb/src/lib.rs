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
//! [`DirectoryStore`] from `adrian-storage-core`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_storage_core::{
    Attribute, DirectoryStore, DistinguishedName, Object, ReadTxn, StorageError, WriteTxn,
};
use async_trait::async_trait;
use uuid::Uuid;

/// FoundationDB-backed implementation of [`DirectoryStore`].
///
/// Per ADR-073, FoundationDB is the sole storage engine for v1. This struct
/// wraps an FDB `Database` handle and implements the trait by delegating to
/// FDB transactions (per Decision 2 §Decision: `begin_tx` →
/// `Database::create_transaction()`, `commit_tx` →
/// `Transaction::commit()`, etc.).
///
/// The stub below is a placeholder that panics on every call. The real
/// implementation is gated behind the `fdb` feature flag (requires libclang
/// at build time for `foundationdb-sys`'s bindgen step, and the FDB C client
/// library at runtime).
#[derive(Debug, Clone)]
pub struct FdbDirectoryStore {
    /// Cluster connection string (e.g. `docker.cluster:4500`).
    pub cluster_file: Option<String>,
}

impl FdbDirectoryStore {
    /// Construct a new `FdbDirectoryStore` for the given cluster file. If
    /// `cluster_file` is `None`, the `FDB_CLUSTER_FILE` env var is used.
    pub fn new(cluster_file: Option<&str>) -> Self {
        Self {
            cluster_file: cluster_file.map(str::to_string),
        }
    }
}

#[async_trait]
impl DirectoryStore for FdbDirectoryStore {
    async fn get(&self, _uuid: Uuid) -> Result<Option<Object>, StorageError> {
        // TODO: implement per ADR-073 — read range on subspace 0x01 keyed by
        // (0x01, dnt, *) where dnt is looked up from the UUID→DNT index.
        Err(StorageError::Backend(
            "FdbDirectoryStore::get not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn get_by_dn(&self, _dn: &DistinguishedName) -> Result<Option<Object>, StorageError> {
        // TODO: implement per ADR-073 — DN→DNT lookup on subspace 0x01
        // secondary index, then read range as above.
        Err(StorageError::Backend(
            "FdbDirectoryStore::get_by_dn not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn put(&self, _obj: &Object) -> Result<(), StorageError> {
        // TODO: implement per ADR-073 — atomic-add on DNT counter for new
        // objects, write per-attribute-value rows, write link-value rows for
        // linked attributes (per ADR-001), write SD dedup rows (per ADR-004).
        Err(StorageError::Backend(
            "FdbDirectoryStore::put not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn delete(&self, _uuid: Uuid) -> Result<(), StorageError> {
        // TODO: implement per ADR-074 — move object to tombstones subspace
        // (0x07) rather than hard-delete; clear forward and reverse link rows
        // (per ADR-001).
        Err(StorageError::Backend(
            "FdbDirectoryStore::delete not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn begin_read(&self) -> Result<Box<dyn ReadTxn>, StorageError> {
        // TODO: implement per ADR-073 — Database::create_transaction +
        // Transaction::snapshot.
        Err(StorageError::Backend(
            "FdbDirectoryStore::begin_read not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn begin_write(&self) -> Result<Box<dyn WriteTxn>, StorageError> {
        // TODO: implement per ADR-073 — Database::create_transaction.
        Err(StorageError::Backend(
            "FdbDirectoryStore::begin_write not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    fn snapshot(&self) -> Box<dyn DirectoryStore> {
        // TODO: implement per ADR-073 — return a clone that uses snapshot
        // reads by default.
        Box::new(self.clone())
    }
}

/// The FDB transaction wrapper used by `FdbDirectoryStore` (gated by `fdb`
/// feature; the stub below is a no-op placeholder).
#[derive(Debug, Default)]
pub struct FdbTxn {
    _private: (),
}

#[async_trait]
impl ReadTxn for FdbTxn {
    async fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // TODO: implement per ADR-073 — Transaction::get.
        Err(StorageError::Backend(
            "FdbTxn::get not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn get_range(
        &self,
        _begin: &[u8],
        _end: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        // TODO: implement per ADR-073 — Transaction::get_range.
        Err(StorageError::Backend(
            "FdbTxn::get_range not yet implemented (gated by `fdb` feature)".into(),
        ))
    }
}

#[async_trait]
impl WriteTxn for FdbTxn {
    async fn put(&self, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> {
        // TODO: implement per ADR-073 — Transaction::set.
        Err(StorageError::Backend(
            "FdbTxn::put not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn delete(&self, _key: &[u8]) -> Result<(), StorageError> {
        // TODO: implement per ADR-073 — Transaction::clear.
        Err(StorageError::Backend(
            "FdbTxn::delete not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn atomic_add(&self, _key: &[u8], _value: i64) -> Result<(), StorageError> {
        // TODO: implement per ADR-073 — Transaction::atomic_op(AtomicOp::Add).
        // Used for DNT counter (per Decision 2) and RID pool (per Decision 3).
        Err(StorageError::Backend(
            "FdbTxn::atomic_add not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn commit(self: Box<Self>) -> Result<(), StorageError> {
        // TODO: implement per ADR-073 — Transaction::commit with retry-on-
        // conflict loop (1020_not_committed) and retry-on-too-old (1007).
        let _ = self;
        Err(StorageError::Backend(
            "FdbTxn::commit not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn rollback(self: Box<Self>) -> Result<(), StorageError> {
        // TODO: implement per ADR-073 — drop the Transaction without
        // committing.
        let _ = self;
        Ok(())
    }
}

/// Helper: encode an FDB tuple key for a (subspace, dnt, attribute_id,
/// value_index) row in the `0x01` objects subspace.
pub fn encode_object_key(subspace: u8, dnt: u64, attribute_id: u32, value_index: u32) -> Vec<u8> {
    // TODO: implement per ADR-073 using foundationdb::tuple::TuplePack.
    let mut out = Vec::with_capacity(1 + 8 + 4 + 4);
    out.push(subspace);
    out.extend_from_slice(&dnt.to_be_bytes());
    out.extend_from_slice(&attribute_id.to_be_bytes());
    out.extend_from_slice(&value_index.to_be_bytes());
    out
}

/// Helper: encode an FDB tuple key for a forward-link row in the `0x02`
/// link-value subspace, per ADR-001.
pub fn encode_link_forward_key(link_dnt: u64, link_id: u32, backlink_dnt: u64) -> Vec<u8> {
    // TODO: implement per ADR-001 using foundationdb::tuple::TuplePack.
    let mut out = Vec::with_capacity(1 + 8 + 4 + 8);
    out.push(0x02);
    out.extend_from_slice(&link_dnt.to_be_bytes());
    out.extend_from_slice(&link_id.to_be_bytes());
    out.extend_from_slice(&backlink_dnt.to_be_bytes());
    out
}

// Suppress unused-import warnings — `Attribute` and `DistinguishedName` are
// re-exported here for ergonomic access from consumers; they will be used by
// the real implementation (gated by `fdb`).
#[allow(unused_imports)]
use adrian_storage_core::{Attribute as _Attribute, DistinguishedName as _Dn};
