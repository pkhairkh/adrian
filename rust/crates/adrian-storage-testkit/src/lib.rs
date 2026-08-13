//! # adrian-storage-testkit
//!
//! In-memory [`DirectoryStore`] implementation for unit tests in the Adrian
//! framework.
//!
//! Per Decision 2 §Rust implementation implications, the testkit provides
//! an in-memory `DirectoryStore` implementation (`InMemoryDirectoryStore`)
//! for unit tests, plus a testkit harness for integration tests against a
//! real FDB cluster (spun up via `docker-compose` in CI — added in Wave 4b).
//!
//! ## ADRs
//!
//! - ADR-073: FoundationDB as sole storage engine (the testkit is the v2
//!   seam where alternative storage engines would slot in)
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-storage-core`, `tokio`. No internal Layer 1+ dependencies — the
//! testkit is consumed by `adrian-test-harness` (Layer 2) and by every
//! crate's unit tests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_storage_core::{
    DirectoryStore, DistinguishedName, Object, ReadTxn, StorageError, WriteTxn,
};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// An in-memory `DirectoryStore` for unit tests (per Decision 2 §Rust
/// implementation implications).
///
/// Uses a `BTreeMap<Vec<u8>, Vec<u8>>` to mimic FDB's ordered key-value
/// store. Transactions are snapshot-isolated (the testkit takes a clone of
/// the map at `begin_read` / `begin_write` time and writes are applied
/// atomically on `commit`).
#[derive(Debug, Default, Clone)]
pub struct InMemoryDirectoryStore {
    /// The key-value store, shared across clones via `Arc<RwLock<...>>`.
    pub kv: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
    /// The DNT counter (per ADR-073 — atomic-add on first insert).
    pub next_dnt: Arc<RwLock<u64>>,
    /// The UUID → DNT index.
    pub uuid_to_dnt: Arc<RwLock<std::collections::HashMap<Uuid, u64>>>,
    /// The DN → DNT index.
    pub dn_to_dnt: Arc<RwLock<std::collections::HashMap<String, u64>>>,
    /// The DNT → object cache (per ADR-073 — materialised view of the
    /// per-attribute-value rows).
    pub objects: Arc<RwLock<std::collections::HashMap<u64, Object>>>,
}

impl InMemoryDirectoryStore {
    /// Construct a new empty `InMemoryDirectoryStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DirectoryStore for InMemoryDirectoryStore {
    async fn get(&self, _uuid: Uuid) -> Result<Option<Object>, StorageError> {
        // TODO: implement per ADR-073 — read from uuid_to_dnt index, then
        // read object cache.
        Ok(None)
    }

    async fn get_by_dn(&self, _dn: &DistinguishedName) -> Result<Option<Object>, StorageError> {
        // TODO: implement per ADR-073.
        Ok(None)
    }

    async fn put(&self, _obj: &Object) -> Result<(), StorageError> {
        // TODO: implement per ADR-073 — atomic-add on next_dnt counter for
        // new objects, write to objects cache, update uuid_to_dnt and
        // dn_to_dnt indexes.
        Ok(())
    }

    async fn delete(&self, _uuid: Uuid) -> Result<(), StorageError> {
        // TODO: implement per ADR-074 — move to tombstones (in this testkit,
        // just remove from the cache; the real FDB impl uses the 0x07
        // subspace).
        Ok(())
    }

    async fn begin_read(&self) -> Result<Box<dyn ReadTxn>, StorageError> {
        Ok(Box::new(InMemoryReadTxn {
            snapshot: self.kv.read().unwrap().clone(),
        }))
    }

    async fn begin_write(&self) -> Result<Box<dyn WriteTxn>, StorageError> {
        Ok(Box::new(InMemoryWriteTxn {
            snapshot: self.kv.read().unwrap().clone(),
            target: Arc::clone(&self.kv),
        }))
    }

    fn snapshot(&self) -> Box<dyn DirectoryStore> {
        Box::new(self.clone())
    }
}

/// An in-memory read transaction (snapshot of the kv store at
/// `begin_read` time).
#[derive(Debug)]
pub struct InMemoryReadTxn {
    /// The snapshot of the kv store.
    pub snapshot: BTreeMap<Vec<u8>, Vec<u8>>,
}

#[async_trait]
impl ReadTxn for InMemoryReadTxn {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.snapshot.get(key).cloned())
    }

    async fn get_range(
        &self,
        begin: &[u8],
        end: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        Ok(self
            .snapshot
            .range(begin.to_vec()..end.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

/// An in-memory write transaction.
#[derive(Debug)]
pub struct InMemoryWriteTxn {
    /// The snapshot of the kv store at `begin_write` time.
    pub snapshot: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The target kv store (applied on `commit`).
    pub target: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

#[async_trait]
impl ReadTxn for InMemoryWriteTxn {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.snapshot.get(key).cloned())
    }

    async fn get_range(
        &self,
        begin: &[u8],
        end: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        Ok(self
            .snapshot
            .range(begin.to_vec()..end.to_vec())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

#[async_trait]
impl WriteTxn for InMemoryWriteTxn {
    async fn put(&self, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> {
        // TODO: implement — write to self.snapshot (the snapshot is the
        // write-set; applied atomically on commit).
        Ok(())
    }

    async fn delete(&self, _key: &[u8]) -> Result<(), StorageError> {
        // TODO: implement.
        Ok(())
    }

    async fn atomic_add(&self, _key: &[u8], _value: i64) -> Result<(), StorageError> {
        // TODO: implement.
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<(), StorageError> {
        // TODO: implement — apply self.snapshot to self.target atomically.
        let _ = self;
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), StorageError> {
        // TODO: implement — drop self.snapshot without applying to self.target.
        let _ = self;
        Ok(())
    }
}
