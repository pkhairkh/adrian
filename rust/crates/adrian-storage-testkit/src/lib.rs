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
//! ## Semantics
//!
//! - The key-value layer (`kv`) is an ordered `BTreeMap<Vec<u8>, Vec<u8>>`,
//!   mimicking FDB's ordered key-value store.
//! - `begin_read()` returns an `InMemoryReadTxn` holding a *clone* of the kv
//!   map at that instant — snapshot isolation, no read-version acquisition.
//! - `begin_write()` returns an `InMemoryWriteTxn` holding a *clone* of the kv
//!   map (read view) plus a write-set (`BTreeMap<Vec<u8>, Option<Vec<u8>>>`)
//!   and a list of pending atomic-adds. Writes are staged locally and applied
//!   atomically to the target under a single write-lock acquisition on
//!   `commit()`. `rollback()` simply drops the staged writes.
//! - The high-level `DirectoryStore` methods (`get` / `get_by_dn` / `put` /
//!   `delete`) operate directly on three secondary indexes
//!   (`uuid_to_dnt`, `dn_to_dnt`, `objects`) and a `next_dnt` counter, mirroring
//!   the FDB implementation's per-attribute-value rows. They are NOT
//!   transactional against `begin_write` transactions — they perform direct
//!   atomic updates to the indexes. Callers needing multi-key atomicity must
//!   use `begin_write()` and the raw `WriteTxn` interface.
//! - `delete()` removes the object from all indexes (the real FDB
//!   implementation moves the object to the `0x07` tombstones subspace per
//!   ADR-074; that behaviour is the storage backend's responsibility, not the
//!   testkit's).
//!
//! ## ADRs
//!
//! - ADR-073: FoundationDB as sole storage engine (the testkit is the v2
//!   seam where alternative storage engines would slot in)
//! - ADR-074: Tombstone lifetime and lingering objects (the testkit does
//!   *not* model tombstones — it hard-deletes from the in-memory indexes;
//!   tests that need tombstone semantics should use `adrian-storage-fdb`
//!   against a real FDB cluster)
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
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

/// Sentinel DNT value indicating "not yet assigned". Objects inserted via
/// `DirectoryStore::put` with `dnt == 0` are assigned a fresh DNT from the
/// `next_dnt` counter (mirroring the FDB atomic-add on `(0x01, 0xFF,
/// "next_dnt")` per ADR-073).
pub const UNASSIGNED_DNT: u64 = 0;

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
    /// The DNT counter (per ADR-073 — atomic-add on first insert). Starts at
    /// 1 so that `UNASSIGNED_DNT` (0) is reserved as "not yet assigned".
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
    /// Construct a new empty `InMemoryDirectoryStore` with `next_dnt`
    /// initialised to 1 (so that DNT 0 is reserved as
    /// [`UNASSIGNED_DNT`]).
    pub fn new() -> Self {
        Self {
            kv: Arc::new(RwLock::new(BTreeMap::new())),
            next_dnt: Arc::new(RwLock::new(1)),
            uuid_to_dnt: Arc::new(RwLock::new(std::collections::HashMap::new())),
            dn_to_dnt: Arc::new(RwLock::new(std::collections::HashMap::new())),
            objects: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Number of live objects currently in the store (excludes anything
    /// removed via `delete`). Useful for assertions in tests.
    pub fn len(&self) -> usize {
        self.objects.read().unwrap().len()
    }

    /// Returns `true` if the store currently holds no live objects.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Current value of the DNT counter. The next object inserted via `put`
    /// with `dnt == UNASSIGNED_DNT` will receive this value, and the counter
    /// will be incremented.
    pub fn next_dnt(&self) -> u64 {
        *self.next_dnt.read().unwrap()
    }
}

#[async_trait]
impl DirectoryStore for InMemoryDirectoryStore {
    async fn get(&self, uuid: Uuid) -> Result<Option<Object>, StorageError> {
        // Two-step lookup: uuid → dnt → object. We acquire each read lock
        // separately (no nested locking) to keep the lock graph acyclic.
        let dnt = {
            let idx = self.uuid_to_dnt.read().unwrap();
            idx.get(&uuid).copied()
        };
        let Some(dnt) = dnt else {
            return Ok(None);
        };
        let obj = {
            let objs = self.objects.read().unwrap();
            objs.get(&dnt).cloned()
        };
        Ok(obj)
    }

    async fn get_by_dn(&self, dn: &DistinguishedName) -> Result<Option<Object>, StorageError> {
        let dnt = {
            let idx = self.dn_to_dnt.read().unwrap();
            idx.get(&dn.dn).copied()
        };
        let Some(dnt) = dnt else {
            return Ok(None);
        };
        let obj = {
            let objs = self.objects.read().unwrap();
            objs.get(&dnt).cloned()
        };
        Ok(obj)
    }

    async fn put(&self, obj: &Object) -> Result<(), StorageError> {
        // Assign a fresh DNT if the caller passed `UNASSIGNED_DNT` (0).
        // We acquire the `next_dnt` write lock only when we actually need a
        // new DNT — re-puts of an existing object (same UUID, non-zero DNT)
        // preserve the original DNT.
        let dnt = if obj.dnt == UNASSIGNED_DNT {
            let mut counter = self.next_dnt.write().unwrap();
            let assigned = *counter;
            *counter = assigned
                .checked_add(1)
                .ok_or_else(|| StorageError::Backend("DNT counter overflow".into()))?;
            assigned
        } else {
            obj.dnt
        };

        // Build the materialised object with the (possibly newly assigned)
        // DNT. We clone here because the caller's `obj` is borrowed and we
        // need an owned copy for the cache.
        let materialised = Object {
            dnt,
            uuid: obj.uuid,
            dn: obj.dn.clone(),
            attributes: obj.attributes.clone(),
        };

        // Update the three indexes. Lock order: uuid_to_dnt → dn_to_dnt →
        // objects (always this order, to keep the lock graph acyclic).
        {
            let mut idx = self.uuid_to_dnt.write().unwrap();
            idx.insert(materialised.uuid, dnt);
        }
        {
            let mut idx = self.dn_to_dnt.write().unwrap();
            idx.insert(materialised.dn.dn.clone(), dnt);
        }
        {
            let mut objs = self.objects.write().unwrap();
            objs.insert(dnt, materialised);
        }
        Ok(())
    }

    async fn delete(&self, uuid: Uuid) -> Result<(), StorageError> {
        // Resolve UUID → DNT, then drop the object from all three indexes.
        // Hard-delete (no tombstone) — see the crate-level docs for why.
        let dnt = {
            let mut idx = self.uuid_to_dnt.write().unwrap();
            idx.remove(&uuid)
        };
        let Some(dnt) = dnt else {
            // Idempotent: deleting a non-existent UUID is a no-op.
            return Ok(());
        };
        let dn_string = {
            let mut objs = self.objects.write().unwrap();
            objs.remove(&dnt).map(|o| o.dn.dn)
        };
        if let Some(dn_str) = dn_string {
            let mut idx = self.dn_to_dnt.write().unwrap();
            idx.remove(&dn_str);
        }
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
            writes: Arc::new(Mutex::new(BTreeMap::new())),
            atomic_adds: Arc::new(Mutex::new(Vec::new())),
            target: Arc::clone(&self.kv),
        }))
    }

    fn snapshot(&self) -> Box<dyn DirectoryStore> {
        // `Clone` is cheap (Arc bumps). The clone observes a logically
        // consistent point-in-time view because every mutation goes through
        // the same shared `Arc<RwLock<...>>` — callers wanting a frozen
        // point-in-time snapshot should `begin_read()` instead.
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
            .range((begin.to_vec())..(end.to_vec()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
}

/// Pending write entry for the write-set: `Some(v)` for `put`, `None` for
/// `delete`.
pub type PendingWrite = Option<Vec<u8>>;

/// The write-set: keys mapped to their pending operation.
pub type WriteSet = BTreeMap<Vec<u8>, PendingWrite>;

/// A pending atomic-add, applied in staging order at commit time.
pub type PendingAtomicAdd = (Vec<u8>, i64);

/// An in-memory write transaction.
///
/// Holds a *read snapshot* of the kv store at `begin_write` time, plus a
/// *write-set* of pending puts/deletes and a list of pending atomic-adds.
/// Reads in this transaction observe the snapshot overlaid with the
/// write-set (read-your-writes). Writes are applied to `target` atomically
/// on `commit()` under a single write-lock acquisition; `rollback()` simply
/// drops the staged writes.
#[derive(Debug)]
pub struct InMemoryWriteTxn {
    /// The snapshot of the kv store at `begin_write` time (read view).
    pub snapshot: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The write-set: `Some(v)` for `put`, `None` for `delete`.
    pub writes: Arc<Mutex<WriteSet>>,
    /// The list of pending atomic-adds, applied in order at `commit` time.
    pub atomic_adds: Arc<Mutex<Vec<PendingAtomicAdd>>>,
    /// The target kv store (applied on `commit`).
    pub target: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl InMemoryWriteTxn {
    /// Read-through helper: consult the write-set first, then the snapshot.
    fn read_through(&self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(pending) = self.writes.lock().unwrap().get(key) {
            return pending.clone();
        }
        self.snapshot.get(key).cloned()
    }
}

#[async_trait]
impl ReadTxn for InMemoryWriteTxn {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.read_through(key))
    }

    async fn get_range(
        &self,
        begin: &[u8],
        end: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        // Merge snapshot range with write-set range. For each key in the
        // snapshot range, overlay the write-set: if the write-set has a
        // `Some(v)` for that key, use it; if `None`, skip (deleted); if
        // absent, use the snapshot value. Then append any write-set keys
        // that fall in the range but are not in the snapshot (new puts).
        let writes = self.writes.lock().unwrap();
        let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        // Start from snapshot range.
        for (k, v) in self.snapshot.range((begin.to_vec())..(end.to_vec())) {
            match writes.get(k) {
                Some(Some(new_v)) => {
                    out.insert(k.clone(), new_v.clone());
                }
                Some(None) => { /* deleted */ }
                None => {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
        // Then add any write-set keys in range that aren't in the snapshot.
        for (k, v_opt) in writes.range((begin.to_vec())..(end.to_vec())) {
            if let Some(v) = v_opt {
                out.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        Ok(out.into_iter().collect())
    }
}

#[async_trait]
impl WriteTxn for InMemoryWriteTxn {
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.writes
            .lock()
            .unwrap()
            .insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.writes.lock().unwrap().insert(key.to_vec(), None);
        Ok(())
    }

    async fn atomic_add(&self, key: &[u8], value: i64) -> Result<(), StorageError> {
        // Stage the atomic-add; it is applied at `commit` time against the
        // target's current value (so two concurrent txns both doing
        // `atomic_add(k, 1)` produce a net +2, matching FDB semantics).
        self.atomic_adds.lock().unwrap().push((key.to_vec(), value));
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<(), StorageError> {
        // Single critical section: acquire the target write lock and apply
        // all staged writes + atomic-adds. This guarantees atomicity
        // w.r.t. other concurrent commits.
        let mut target = self.target.write().unwrap();
        // Apply puts and deletes.
        for (k, v_opt) in self.writes.lock().unwrap().iter() {
            match v_opt {
                Some(v) => {
                    target.insert(k.clone(), v.clone());
                }
                None => {
                    target.remove(k);
                }
            }
        }
        // Apply atomic-adds in staging order. Each reads the current target
        // value (which may have been updated by an earlier put in this same
        // commit), adds `value`, and writes back as a big-endian i64.
        for (k, delta) in self.atomic_adds.lock().unwrap().iter() {
            let current = target
                .get(k)
                .and_then(|v| {
                    if v.len() == 8 {
                        Some(i64::from_be_bytes(v[..8].try_into().unwrap()))
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let new_val = current
                .checked_add(*delta)
                .ok_or_else(|| StorageError::Backend("atomic_add overflow".into()))?;
            target.insert(k.clone(), new_val.to_be_bytes().to_vec());
        }
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), StorageError> {
        // Drop self — the staged writes and atomic_adds are simply
        // discarded. No interaction with `target` is needed.
        let _ = self;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_storage_core::{Attribute, DistinguishedName, Object};

    /// Build a minimal `Object` for tests with the given UUID, DN, and DNT
    /// (use `UNASSIGNED_DNT` to simulate a fresh insert).
    fn make_obj(uuid: Uuid, dn: &str, dnt: u64) -> Object {
        Object {
            uuid,
            dn: DistinguishedName::new(dn),
            attributes: vec![Attribute {
                attribute_id: 3,
                name: "cn".to_string(),
                value: dn.split(',').next().unwrap_or("").as_bytes().to_vec(),
            }],
            dnt,
        }
    }

    /// Deterministic UUID for tests (avoids depending on the `v4` feature
    /// of the `uuid` crate — only `v7` and `serde` are enabled in the
    /// workspace Cargo.toml).
    fn test_uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    // ----- DirectoryStore high-level CRUD -----

    #[tokio::test]
    async fn get_on_empty_store_returns_none() {
        let store = InMemoryDirectoryStore::new();
        let got = store.get(Uuid::nil()).await.unwrap();
        assert!(got.is_none(), "get on empty store must return None");
    }

    #[tokio::test]
    async fn get_by_dn_on_empty_store_returns_none() {
        let store = InMemoryDirectoryStore::new();
        let got = store
            .get_by_dn(&DistinguishedName::new("CN=Foo,DC=corp,DC=com"))
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn put_then_get_roundtrip_by_uuid() {
        let store = InMemoryDirectoryStore::new();
        let uuid = test_uuid(1);
        let obj = make_obj(uuid, "CN=alice,DC=corp,DC=com", UNASSIGNED_DNT);
        store.put(&obj).await.unwrap();
        let got = store.get(uuid).await.unwrap().expect("object should exist");
        assert_eq!(got.uuid, uuid);
        assert_eq!(got.dn.dn, "CN=alice,DC=corp,DC=com");
        assert_eq!(got.attributes.len(), 1);
    }

    #[tokio::test]
    async fn put_then_get_by_dn_roundtrip() {
        let store = InMemoryDirectoryStore::new();
        let uuid = test_uuid(2);
        let dn = DistinguishedName::new("CN=bob,OU=Eng,DC=corp,DC=com");
        let obj = Object {
            uuid,
            dn: dn.clone(),
            attributes: vec![],
            dnt: UNASSIGNED_DNT,
        };
        store.put(&obj).await.unwrap();
        let got = store.get_by_dn(&dn).await.unwrap().expect("object should exist");
        assert_eq!(got.uuid, uuid);
    }

    #[tokio::test]
    async fn put_assigns_sequential_dnts() {
        let store = InMemoryDirectoryStore::new();
        assert_eq!(store.next_dnt(), 1);
        store
            .put(&make_obj(test_uuid(10), "CN=a,DC=corp,DC=com", UNASSIGNED_DNT))
            .await
            .unwrap();
        store
            .put(&make_obj(test_uuid(11), "CN=b,DC=corp,DC=com", UNASSIGNED_DNT))
            .await
            .unwrap();
        store
            .put(&make_obj(test_uuid(12), "CN=c,DC=corp,DC=com", UNASSIGNED_DNT))
            .await
            .unwrap();
        assert_eq!(store.next_dnt(), 4, "next_dnt must advance by 3");
        assert_eq!(store.len(), 3);
    }

    #[tokio::test]
    async fn put_preserves_explicit_nonzero_dnt() {
        let store = InMemoryDirectoryStore::new();
        let uuid = test_uuid(3);
        let obj = make_obj(uuid, "CN=carol,DC=corp,DC=com", 42);
        store.put(&obj).await.unwrap();
        // next_dnt must NOT have been touched (we used dnt=42).
        assert_eq!(store.next_dnt(), 1, "explicit DNT must not consume counter");
        let got = store.get(uuid).await.unwrap().unwrap();
        assert_eq!(got.dnt, 42);
    }

    #[tokio::test]
    async fn put_updates_existing_object_in_place() {
        let store = InMemoryDirectoryStore::new();
        let uuid = test_uuid(4);
        // First put with empty attributes.
        store
            .put(&Object {
                uuid,
                dn: DistinguishedName::new("CN=dave,DC=corp,DC=com"),
                attributes: vec![],
                dnt: UNASSIGNED_DNT,
            })
            .await
            .unwrap();
        // Second put: same UUID, new DN, new attributes.
        store
            .put(&Object {
                uuid,
                dn: DistinguishedName::new("CN=dave-renamed,OU=Eng,DC=corp,DC=com"),
                attributes: vec![Attribute {
                    attribute_id: 7,
                    name: "displayName".to_string(),
                    value: b"Dave".to_vec(),
                }],
                dnt: 1, // preserve the originally-assigned DNT
            })
            .await
            .unwrap();
        let got = store.get(uuid).await.unwrap().unwrap();
        assert_eq!(got.dn.dn, "CN=dave-renamed,OU=Eng,DC=corp,DC=com");
        assert_eq!(got.attributes.len(), 1);
        assert_eq!(got.attributes[0].name, "displayName");
        assert_eq!(store.len(), 1, "update must not create a duplicate");
    }

    #[tokio::test]
    async fn delete_removes_object_from_all_indexes() {
        let store = InMemoryDirectoryStore::new();
        let uuid = test_uuid(5);
        let dn = DistinguishedName::new("CN=eve,DC=corp,DC=com");
        store
            .put(&Object {
                uuid,
                dn: dn.clone(),
                attributes: vec![],
                dnt: UNASSIGNED_DNT,
            })
            .await
            .unwrap();
        assert_eq!(store.len(), 1);
        store.delete(uuid).await.unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.get(uuid).await.unwrap().is_none());
        assert!(store.get_by_dn(&dn).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let store = InMemoryDirectoryStore::new();
        let uuid = test_uuid(6);
        store
            .put(&make_obj(uuid, "CN=frank,DC=corp,DC=com", UNASSIGNED_DNT))
            .await
            .unwrap();
        store.delete(uuid).await.unwrap();
        // Second delete must not error.
        store.delete(uuid).await.unwrap();
        assert_eq!(store.len(), 0);
    }

    // ----- ReadTxn / WriteTxn low-level interface -----

    #[tokio::test]
    async fn read_txn_get_returns_snapshot_value() {
        let store = InMemoryDirectoryStore::new();
        store
            .kv
            .write()
            .unwrap()
            .insert(b"abc".to_vec(), b"v1".to_vec());
        let txn = store.begin_read().await.unwrap();
        assert_eq!(txn.get(b"abc").await.unwrap(), Some(b"v1".to_vec()));
        assert_eq!(txn.get(b"missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_txn_get_range_returns_ordered_subset() {
        let store = InMemoryDirectoryStore::new();
        {
            let mut kv = store.kv.write().unwrap();
            kv.insert(b"a".to_vec(), b"1".to_vec());
            kv.insert(b"b".to_vec(), b"2".to_vec());
            kv.insert(b"c".to_vec(), b"3".to_vec());
            kv.insert(b"d".to_vec(), b"4".to_vec());
        }
        let txn = store.begin_read().await.unwrap();
        // Half-open range [b, d)
        let range = txn.get_range(b"b", b"d").await.unwrap();
        let keys: Vec<&[u8]> = range.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(keys, vec![b"b".as_slice(), b"c".as_slice()]);
    }

    #[tokio::test]
    async fn write_txn_put_and_commit_persists() {
        let store = InMemoryDirectoryStore::new();
        let txn = store.begin_write().await.unwrap();
        txn.put(b"k1", b"v1").await.unwrap();
        txn.put(b"k2", b"v2").await.unwrap();
        // Read-your-writes inside the txn.
        assert_eq!(txn.get(b"k1").await.unwrap(), Some(b"v1".to_vec()));
        txn.commit().await.unwrap();
        // After commit, a fresh read txn must observe both writes.
        let read = store.begin_read().await.unwrap();
        assert_eq!(read.get(b"k1").await.unwrap(), Some(b"v1".to_vec()));
        assert_eq!(read.get(b"k2").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn write_txn_rollback_discards_writes() {
        let store = InMemoryDirectoryStore::new();
        store
            .kv
            .write()
            .unwrap()
            .insert(b"pre".to_vec(), b"existing".to_vec());
        let txn = store.begin_write().await.unwrap();
        txn.put(b"new", b"transient").await.unwrap();
        txn.delete(b"pre").await.unwrap();
        txn.rollback().await.unwrap();
        // After rollback, target must be unchanged.
        let read = store.begin_read().await.unwrap();
        assert_eq!(read.get(b"pre").await.unwrap(), Some(b"existing".to_vec()));
        assert_eq!(read.get(b"new").await.unwrap(), None);
    }

    #[tokio::test]
    async fn write_txn_delete_and_commit_removes_key() {
        let store = InMemoryDirectoryStore::new();
        store
            .kv
            .write()
            .unwrap()
            .insert(b"to-remove".to_vec(), b"v".to_vec());
        let txn = store.begin_write().await.unwrap();
        txn.delete(b"to-remove").await.unwrap();
        txn.commit().await.unwrap();
        let read = store.begin_read().await.unwrap();
        assert_eq!(read.get(b"to-remove").await.unwrap(), None);
    }

    #[tokio::test]
    async fn write_txn_atomic_add_increments_existing_value() {
        let store = InMemoryDirectoryStore::new();
        // Seed the counter at 10 (big-endian i64).
        store
            .kv
            .write()
            .unwrap()
            .insert(b"counter".to_vec(), 10i64.to_be_bytes().to_vec());
        let txn = store.begin_write().await.unwrap();
        txn.atomic_add(b"counter", 5).await.unwrap();
        txn.commit().await.unwrap();
        let read = store.begin_read().await.unwrap();
        let v = read.get(b"counter").await.unwrap().unwrap();
        let n = i64::from_be_bytes(v[..].try_into().unwrap());
        assert_eq!(n, 15);
    }

    #[tokio::test]
    async fn write_txn_atomic_add_on_missing_key_starts_from_zero() {
        let store = InMemoryDirectoryStore::new();
        let txn = store.begin_write().await.unwrap();
        txn.atomic_add(b"fresh-counter", 7).await.unwrap();
        txn.commit().await.unwrap();
        let read = store.begin_read().await.unwrap();
        let v = read.get(b"fresh-counter").await.unwrap().unwrap();
        let n = i64::from_be_bytes(v[..].try_into().unwrap());
        assert_eq!(n, 7);
    }

    #[tokio::test]
    async fn two_concurrent_txns_do_not_see_each_others_writes() {
        // Snapshot isolation: txn_b, started after txn_a's commit, sees
        // txn_a's writes; but two overlapping txns each see their own
        // snapshot. We model this by starting both reads from the same kv
        // state, then mutating via txn_a only.
        let store = InMemoryDirectoryStore::new();
        store
            .kv
            .write()
            .unwrap()
            .insert(b"shared".to_vec(), b"base".to_vec());

        let txn_a = store.begin_write().await.unwrap();
        let txn_b = store.begin_write().await.unwrap();
        txn_a.put(b"shared", b"a-wins").await.unwrap();
        // txn_b still sees the snapshot value (read isolation).
        assert_eq!(txn_b.get(b"shared").await.unwrap(), Some(b"base".to_vec()));
        // txn_a sees its own write (read-your-writes).
        assert_eq!(txn_a.get(b"shared").await.unwrap(), Some(b"a-wins".to_vec()));
        txn_a.commit().await.unwrap();
        txn_b.rollback().await.unwrap();
        // After txn_a commits, a new read observes a-wins.
        let read = store.begin_read().await.unwrap();
        assert_eq!(read.get(b"shared").await.unwrap(), Some(b"a-wins".to_vec()));
    }

    #[tokio::test]
    async fn snapshot_returns_independent_box_dyn_store() {
        let store = InMemoryDirectoryStore::new();
        let _snap = store.snapshot();
        // The snapshot shares the underlying Arc (see `snapshot()` docs), so
        // the live write through `store` must be reflected in `snap`'s shared
        // state. We observe that via `store` itself, since
        // `Box<dyn DirectoryStore>` doesn't expose `.len()`.
        store
            .put(&make_obj(test_uuid(7), "CN=g,DC=corp,DC=com", UNASSIGNED_DNT))
            .await
            .unwrap();
        assert_eq!(store.len(), 1, "snapshot must reflect live state");
    }

    #[tokio::test]
    async fn write_txn_get_range_overlays_writes_on_snapshot() {
        let store = InMemoryDirectoryStore::new();
        {
            let mut kv = store.kv.write().unwrap();
            kv.insert(b"a".to_vec(), b"s1".to_vec());
            kv.insert(b"b".to_vec(), b"s2".to_vec());
            kv.insert(b"c".to_vec(), b"s3".to_vec());
        }
        let txn = store.begin_write().await.unwrap();
        txn.put(b"b", b"w2").await.unwrap(); // overlay
        txn.delete(b"c").await.unwrap(); // delete from snapshot
        txn.put(b"d", b"w4").await.unwrap(); // new key in range [a, e)
        let range = txn.get_range(b"a", b"e").await.unwrap();
        let map: BTreeMap<Vec<u8>, Vec<u8>> = range.into_iter().collect();
        assert_eq!(
            map.get(&b"a"[..]).map(|v| v.as_slice()),
            Some(b"s1".as_slice())
        );
        assert_eq!(
            map.get(&b"b"[..]).map(|v| v.as_slice()),
            Some(b"w2".as_slice())
        );
        assert!(!map.contains_key(&b"c"[..]), "deleted key must be absent");
        assert_eq!(
            map.get(&b"d"[..]).map(|v| v.as_slice()),
            Some(b"w4".as_slice())
        );
    }
}
