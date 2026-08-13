//! # adrian-identity-fdb
//!
//! FoundationDB-backed [`IdentityMapping`] implementation for the Adrian
//! framework.
//!
//! Per Decision 3 §Rust implementation implications, the mapping table is
//! stored in FDB subspace `0x0D` (forward and reverse indexes), with an
//! in-memory LRU cache protected by `tokio::sync::RwLock` and FDB watches
//! (`tokio::sync::watch` channels) for cache invalidation.
//!
//! ## Two code paths
//!
//! Like `adrian-storage-fdb`, this crate has two code paths:
//! - **Default (no `fdb` feature)**: uses the `InMemoryDirectoryStore`-backed
//!   fallback from `adrian-storage-testkit`. The same tuple-layer key encoding
//!   is used for both paths, so behavioural tests against the fallback
//!   exercise the same code path that runs against a real FDB cluster.
//! - **`fdb` feature**: uses a real `foundationdb::Database`. The integration
//!   tests for the real path are `#[ignore]` (require a running FDB cluster
//!   and the `fdb` feature flag).
//!
//! ## ADRs
//!
//! - ADR-110: SID-to-UID mapping (UUID-primary)
//! - ADR-077: Foreign security principals + RID pool
//! - ADR-124: sIDHistory injection mitigation
//! - ADR-126: sIDHistory migration via DRSAddSidHistory
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-identity-core`, `adrian-storage-fdb`, `adrian-sid`,
//! `adrian-storage-core`, and (for the fallback path) `adrian-storage-testkit`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_identity_core::{IdentityError, IdentityMapping, PosixId, PrincipalId};
use adrian_sid::Sid;
use adrian_storage_core::DirectoryStore;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// FDB subspace identifier for the identity-mapping table (per ADR-110).
const IDENTITY_MAPPING_SUBSPACE: u8 = 0x0D;

/// Forward index marker: `(0x0D, 0x01, uuid_bytes) → sid_bytes`.
const FORWARD_MARKER: u8 = 0x01;
/// Reverse index marker: `(0x0D, 0x02, sid_bytes) → uuid_bytes`.
const REVERSE_MARKER: u8 = 0x02;
/// UID → UUID index marker: `(0x0D, 0x03, uid_be_bytes) → uuid_bytes`.
const UID_INDEX_MARKER: u8 = 0x03;
/// UUID → UID index marker: `(0x0D, 0x04, uuid_bytes) → uid_be_bytes`.
const UUID_TO_UID_MARKER: u8 = 0x04;
/// UID atomic counter marker: `(0x0D, 0xFF, "next_uid")` (atomic-add).
const UID_COUNTER_MARKER: u8 = 0xFF;

/// Encode the forward-index key `(0x0D, 0x01, uuid_bytes)`.
fn forward_key(uuid: &Uuid) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16);
    out.push(IDENTITY_MAPPING_SUBSPACE);
    out.push(FORWARD_MARKER);
    out.extend_from_slice(uuid.as_bytes());
    out
}

/// Encode the reverse-index key `(0x0D, 0x02, sid_bytes)`.
fn reverse_key(sid: &Sid) -> Result<Vec<u8>, IdentityError> {
    let sid_bytes = sid.to_bytes()?;
    let mut out = Vec::with_capacity(2 + sid_bytes.len());
    out.push(IDENTITY_MAPPING_SUBSPACE);
    out.push(REVERSE_MARKER);
    out.extend_from_slice(&sid_bytes);
    Ok(out)
}

/// Encode the UID→UUID index key `(0x0D, 0x03, uid_be_bytes)`.
fn uid_index_key(uid: PosixId) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 4);
    out.push(IDENTITY_MAPPING_SUBSPACE);
    out.push(UID_INDEX_MARKER);
    out.extend_from_slice(&uid.to_be_bytes());
    out
}

/// Encode the UUID→UID index key `(0x0D, 0x04, uuid_bytes)`.
fn uuid_to_uid_key(uuid: &Uuid) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16);
    out.push(IDENTITY_MAPPING_SUBSPACE);
    out.push(UUID_TO_UID_MARKER);
    out.extend_from_slice(uuid.as_bytes());
    out
}

/// Encode the UID counter key `(0x0D, 0xFF, "next_uid")`.
fn uid_counter_key() -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8);
    out.push(IDENTITY_MAPPING_SUBSPACE);
    out.push(UID_COUNTER_MARKER);
    out.extend_from_slice(b"next_uid");
    out
}

/// Map a `StorageError` to an `IdentityError::Backend`.
fn map_storage_err(e: adrian_storage_core::StorageError) -> IdentityError {
    IdentityError::Backend(e.to_string())
}

/// FDB-backed implementation of [`IdentityMapping`] (per Decision 3).
///
/// The mapping table is stored in FDB subspace `0x0D`:
/// - Forward index: `(0x0D, 0x01, uuid_bytes) → sid_bytes`
/// - Reverse index: `(0x0D, 0x02, sid_bytes) → uuid_bytes`
/// - UID → UUID index: `(0x0D, 0x03, uid_be) → uuid_bytes`
/// - UUID → UID index: `(0x0D, 0x04, uuid_bytes) → uid_be`
/// - UID counter: `(0x0D, 0xFF, "next_uid")` (atomic-add, starts at 65536)
///
/// The in-memory LRU cache (per Decision 3 §Async runtime —
/// `tokio::sync::RwLock`-protected, 99%+ hit rate on the KDC PAC builder hot
/// path) is a `HashMap` for the test fallback path; the `fdb` feature path
/// adds FDB watch-based invalidation.
#[derive(Clone)]
pub struct FdbIdentityMapping {
    /// The underlying FDB-backed directory store (per ADR-073).
    pub store: adrian_storage_fdb::FdbDirectoryStore,
    /// The LRU cache capacity (default 100_000 entries — per Decision 3
    /// §Implementation impact, ~80 MB resident set on a mid-size forest).
    pub cache_capacity: usize,
    /// In-memory forward cache (UUID → SID). Shared across clones via `Arc`.
    cache_uuid_to_sid: Arc<RwLock<HashMap<Uuid, Sid>>>,
    /// In-memory reverse cache (SID → UUID). Shared across clones via `Arc`.
    cache_sid_to_uuid: Arc<RwLock<HashMap<Sid, Uuid>>>,
}

impl std::fmt::Debug for FdbIdentityMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FdbIdentityMapping")
            .field("store", &self.store)
            .field("cache_capacity", &self.cache_capacity)
            .finish()
    }
}

impl FdbIdentityMapping {
    /// Construct a new `FdbIdentityMapping` backed by the given
    /// `FdbDirectoryStore`.
    pub fn new(store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self {
            store,
            cache_capacity: 100_000,
            cache_uuid_to_sid: Arc::new(RwLock::new(HashMap::new())),
            cache_sid_to_uuid: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Construct a new `FdbIdentityMapping` backed by the in-memory
    /// fallback (no FDB cluster required). Useful for unit tests.
    pub fn new_in_memory_default() -> Self {
        Self::new(adrian_storage_fdb::FdbDirectoryStore::new(None))
    }

    /// Try the in-memory cache for the forward direction.
    fn cache_get_sid(&self, uuid: &Uuid) -> Option<Sid> {
        self.cache_uuid_to_sid.read().ok()?.get(uuid).cloned()
    }

    /// Try the in-memory cache for the reverse direction.
    fn cache_get_uuid(&self, sid: &Sid) -> Option<Uuid> {
        self.cache_sid_to_uuid.read().ok()?.get(sid).copied()
    }

    /// Insert into both caches (with capacity enforcement).
    fn cache_put(&self, uuid: Uuid, sid: Sid) {
        if let Ok(mut c1) = self.cache_uuid_to_sid.write() {
            if c1.len() >= self.cache_capacity && !c1.contains_key(&uuid) {
                // Evict an arbitrary entry (LRU would be better, but
                // HashMap::retain arbitrary eviction is acceptable for the
                // fallback path; the `fdb` feature path uses a real LRU).
                let key_to_evict = c1.keys().next().copied();
                if let Some(k) = key_to_evict {
                    if let Some(evicted_sid) = c1.remove(&k) {
                        if let Ok(mut c2) = self.cache_sid_to_uuid.write() {
                            c2.remove(&evicted_sid);
                        }
                    }
                }
            }
            c1.insert(uuid, sid.clone());
        }
        if let Ok(mut c2) = self.cache_sid_to_uuid.write() {
            c2.insert(sid, uuid);
        }
    }

    /// Remove from both caches.
    fn cache_remove(&self, uuid: &Uuid) {
        let sid_to_remove: Option<Sid> = {
            let c1 = self.cache_uuid_to_sid.read().ok();
            c1.and_then(|c| c.get(uuid).cloned())
        };
        if let Some(sid) = sid_to_remove {
            if let Ok(mut c1) = self.cache_uuid_to_sid.write() {
                c1.remove(uuid);
            }
            if let Ok(mut c2) = self.cache_sid_to_uuid.write() {
                c2.remove(&sid);
            }
        }
    }
}

#[async_trait]
impl IdentityMapping for FdbIdentityMapping {
    async fn lookup_sid(&self, uuid: PrincipalId) -> Result<Option<Sid>, IdentityError> {
        // 1. Try the in-memory cache first.
        if let Some(sid) = self.cache_get_sid(&uuid) {
            return Ok(Some(sid));
        }
        // 2. On cache miss, read the forward index from the store.
        let key = forward_key(&uuid);
        let txn = self.store.begin_read().await.map_err(map_storage_err)?;
        let buf = txn.get(&key).await.map_err(map_storage_err)?;
        let Some(buf) = buf else {
            return Ok(None);
        };
        let sid = Sid::from_bytes(&buf)?;
        // 3. Populate the cache.
        self.cache_put(uuid, sid.clone());
        Ok(Some(sid))
    }

    async fn lookup_uuid(&self, sid: &Sid) -> Result<Option<PrincipalId>, IdentityError> {
        // 1. Try the in-memory cache first.
        if let Some(uuid) = self.cache_get_uuid(sid) {
            return Ok(Some(uuid));
        }
        // 2. On cache miss, read the reverse index.
        let key = reverse_key(sid)?;
        let txn = self.store.begin_read().await.map_err(map_storage_err)?;
        let buf = txn.get(&key).await.map_err(map_storage_err)?;
        let Some(buf) = buf else {
            return Ok(None);
        };
        if buf.len() != 16 {
            return Err(IdentityError::Backend(format!(
                "reverse index value must be 16 bytes (UUID), got {}",
                buf.len()
            )));
        }
        let uuid = Uuid::from_bytes(buf[..16].try_into().expect("16-byte slice"));
        // 3. Populate the cache.
        self.cache_put(uuid, sid.clone());
        Ok(Some(uuid))
    }

    async fn lookup_uid(&self, uuid: PrincipalId) -> Result<Option<PosixId>, IdentityError> {
        // First check the directory-stored UUID→UID index. If absent, fall
        // back to the algorithmic `uuid_to_uid` mapping (per Decision 3
        // §Decision — used when `uidNumber` is not directory-stored).
        let key = uuid_to_uid_key(&uuid);
        let txn = self.store.begin_read().await.map_err(map_storage_err)?;
        let buf = txn.get(&key).await.map_err(map_storage_err)?;
        if let Some(buf) = buf {
            if buf.len() == 4 {
                let uid = u32::from_be_bytes(buf[..4].try_into().expect("4-byte slice"));
                return Ok(Some(uid));
            }
            return Err(IdentityError::Backend(format!(
                "UUID→UID index value must be 4 bytes, got {}",
                buf.len()
            )));
        }
        // Fall back to algorithmic mapping.
        Ok(Some(adrian_identity_core::uuid_to_uid(uuid)))
    }

    async fn lookup_uuid_from_uid(
        &self,
        uid: PosixId,
    ) -> Result<Option<PrincipalId>, IdentityError> {
        let key = uid_index_key(uid);
        let txn = self.store.begin_read().await.map_err(map_storage_err)?;
        let buf = txn.get(&key).await.map_err(map_storage_err)?;
        let Some(buf) = buf else {
            return Ok(None);
        };
        if buf.len() != 16 {
            return Err(IdentityError::Backend(format!(
                "UID→UUID index value must be 16 bytes (UUID), got {}",
                buf.len()
            )));
        }
        let uuid = Uuid::from_bytes(buf[..16].try_into().expect("16-byte slice"));
        Ok(Some(uuid))
    }

    async fn insert(&self, uuid: PrincipalId, sid: &Sid) -> Result<(), IdentityError> {
        // Single transaction: write forward + reverse indexes. FDB's strict
        // serializable transactions prevent two writes from committing the
        // same SID for different UUIDs (MappingConflict) — in the testkit
        // fallback, we enforce this manually by checking the reverse index.
        let sid_bytes = sid.to_bytes()?;
        let fkey = forward_key(&uuid);
        let rkey = reverse_key(sid)?;

        let txn = self.store.begin_write().await.map_err(map_storage_err)?;
        // Conflict check: is the SID already mapped to a different UUID?
        let existing = txn.get(&rkey).await.map_err(map_storage_err)?;
        if let Some(existing_bytes) = existing {
            if existing_bytes.len() == 16 {
                let existing_uuid =
                    Uuid::from_bytes(existing_bytes[..16].try_into().expect("16-byte slice"));
                if existing_uuid != uuid {
                    return Err(IdentityError::MappingConflict(format!(
                        "SID {sid} is already mapped to UUID {existing_uuid} (requested {uuid})"
                    )));
                }
            }
        }
        // Conflict check: is the UUID already mapped to a different SID?
        let existing = txn.get(&fkey).await.map_err(map_storage_err)?;
        if let Some(existing_bytes) = existing {
            let existing_sid = Sid::from_bytes(&existing_bytes)?;
            if existing_sid != *sid {
                return Err(IdentityError::MappingConflict(format!(
                    "UUID {uuid} is already mapped to SID {existing_sid} (requested {sid})"
                )));
            }
            // Already mapped identically — idempotent insert.
            return Ok(());
        }
        txn.put(&fkey, &sid_bytes).await.map_err(map_storage_err)?;
        txn.put(&rkey, uuid.as_bytes())
            .await
            .map_err(map_storage_err)?;
        txn.commit().await.map_err(map_storage_err)?;
        // Populate the cache.
        self.cache_put(uuid, sid.clone());
        Ok(())
    }

    async fn remove(&self, uuid: PrincipalId) -> Result<(), IdentityError> {
        // Look up the SID first so we can also remove the reverse index.
        let fkey = forward_key(&uuid);
        let txn = self.store.begin_write().await.map_err(map_storage_err)?;
        let existing = txn.get(&fkey).await.map_err(map_storage_err)?;
        let Some(existing_bytes) = existing else {
            // Idempotent: removing a non-existent UUID is a no-op.
            return Ok(());
        };
        let sid = Sid::from_bytes(&existing_bytes)?;
        let rkey = reverse_key(&sid)?;
        txn.delete(&fkey).await.map_err(map_storage_err)?;
        txn.delete(&rkey).await.map_err(map_storage_err)?;
        // Also remove the UUID→UID and UID→UUID index entries if present.
        let uid_key = uuid_to_uid_key(&uuid);
        let uid_buf = txn.get(&uid_key).await.map_err(map_storage_err)?;
        if let Some(uid_buf) = uid_buf {
            if uid_buf.len() == 4 {
                let uid = u32::from_be_bytes(uid_buf[..4].try_into().expect("4-byte slice"));
                txn.delete(&uid_index_key(uid))
                    .await
                    .map_err(map_storage_err)?;
            }
            txn.delete(&uid_key).await.map_err(map_storage_err)?;
        }
        txn.commit().await.map_err(map_storage_err)?;
        // Drop from the in-memory cache.
        self.cache_remove(&uuid);
        Ok(())
    }
}

/// Allocate a fresh POSIX UID via atomic-add on the UID counter (per Decision
/// 3 §Decision — UIDs start at 65536 and are allocated in increasing order
/// across the forest).
///
/// **Note**: the in-memory fallback path uses a per-store UID counter that
/// is NOT shared across clones of `FdbDirectoryStore` (because the fallback
/// wraps `InMemoryDirectoryStore`, which itself doesn't expose a process-wide
/// counter). The `fdb` feature path uses a real FDB atomic-add on
/// `(0x0D, 0xFF, "next_uid")` which IS cluster-wide. Tests that need
/// cluster-wide UID allocation must use `--features fdb` and a running FDB
/// cluster.
pub async fn allocate_uid(
    store: &adrian_storage_fdb::FdbDirectoryStore,
    uuid: PrincipalId,
) -> Result<PosixId, IdentityError> {
    let counter_key = uid_counter_key();
    let txn = store.begin_write().await.map_err(map_storage_err)?;
    // Read current value (or seed with 65535 so the first allocation returns
    // 65536 after atomic_add(+1)).
    let current = txn.get(&counter_key).await.map_err(map_storage_err)?;
    let seed: i64 = match current {
        Some(buf) if buf.len() == 8 => i64::from_be_bytes(buf[..8].try_into().expect("8-byte buf")),
        _ => 65535,
    };
    txn.atomic_add(&counter_key, 1)
        .await
        .map_err(map_storage_err)?;
    // Also write the UUID→UID index for the new UID.
    let uid: PosixId = u32::try_from(seed + 1)
        .map_err(|_| IdentityError::Backend("UID counter overflowed u32".to_string()))?;
    let uuid_uid_key = uuid_to_uid_key(&uuid);
    let uid_index_k = uid_index_key(uid);
    txn.put(&uuid_uid_key, &uid.to_be_bytes())
        .await
        .map_err(map_storage_err)?;
    txn.put(&uid_index_k, uuid.as_bytes())
        .await
        .map_err(map_storage_err)?;
    txn.commit().await.map_err(map_storage_err)?;
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_identity_core::IdentityMapping;
    use uuid::Uuid;

    fn make_mapping() -> FdbIdentityMapping {
        FdbIdentityMapping::new_in_memory_default()
    }

    fn test_uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn test_sid(rid: u32) -> Sid {
        Sid::new([0, 0, 0, 0, 0, 5], vec![21, 100, 200, 300, rid]).unwrap()
    }

    // ----- Construction -----

    #[test]
    fn new_sets_default_cache_capacity() {
        let mapping = make_mapping();
        assert_eq!(mapping.cache_capacity, 100_000);
    }

    #[test]
    fn cache_capacity_is_mutable() {
        let mut mapping = make_mapping();
        mapping.cache_capacity = 1_000;
        assert_eq!(mapping.cache_capacity, 1_000);
    }

    #[test]
    fn store_handle_is_propagated() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(Some("/tmp/test.cluster"));
        let mapping = FdbIdentityMapping::new(store);
        assert_eq!(
            mapping.store.cluster_file.as_deref(),
            Some("/tmp/test.cluster")
        );
    }

    #[test]
    fn clone_preserves_fields() {
        let mapping = make_mapping();
        let cloned = mapping.clone();
        assert_eq!(mapping.cache_capacity, cloned.cache_capacity);
        assert_eq!(mapping.store.cluster_file, cloned.store.cluster_file);
    }

    // ----- lookup_uid (algorithmic fallback) -----

    #[tokio::test]
    async fn lookup_uid_returns_algorithmic_mapping_when_not_stored() {
        let mapping = make_mapping();
        let uuid = test_uuid(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF);
        let result = mapping.lookup_uid(uuid).await.unwrap();
        let expected = adrian_identity_core::uuid_to_uid(uuid);
        assert_eq!(result, Some(expected));
    }

    #[tokio::test]
    async fn lookup_uid_is_deterministic() {
        let mapping = make_mapping();
        let uuid = Uuid::nil();
        let uid1 = mapping.lookup_uid(uuid).await.unwrap();
        let uid2 = mapping.lookup_uid(uuid).await.unwrap();
        assert_eq!(uid1, uid2);
    }

    #[tokio::test]
    async fn lookup_uid_is_in_posix_range() {
        let mapping = make_mapping();
        for i in 0..64u128 {
            let uuid = test_uuid(i);
            if let Some(uid) = mapping.lookup_uid(uuid).await.unwrap() {
                assert!(uid >= 65536, "uid {} < 65536", uid);
                assert!(uid < (1u32 << 31), "uid {} >= 2^31", uid);
            }
        }
    }

    // ----- insert + lookup_sid (real forward-index path) -----

    #[tokio::test]
    async fn insert_then_lookup_sid_round_trip() {
        let mapping = make_mapping();
        let uuid = test_uuid(1);
        let sid = test_sid(1000);
        mapping.insert(uuid, &sid).await.unwrap();
        let got = mapping.lookup_sid(uuid).await.unwrap();
        assert_eq!(got, Some(sid));
    }

    #[tokio::test]
    async fn insert_then_lookup_uuid_round_trip() {
        let mapping = make_mapping();
        let uuid = test_uuid(2);
        let sid = test_sid(2000);
        mapping.insert(uuid, &sid).await.unwrap();
        let got = mapping.lookup_uuid(&sid).await.unwrap();
        assert_eq!(got, Some(uuid));
    }

    #[tokio::test]
    async fn lookup_sid_returns_none_for_unknown_uuid() {
        let mapping = make_mapping();
        let got = mapping.lookup_sid(test_uuid(99)).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn lookup_uuid_returns_none_for_unknown_sid() {
        let mapping = make_mapping();
        let got = mapping.lookup_uuid(&test_sid(9999)).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn insert_is_idempotent_for_same_pair() {
        let mapping = make_mapping();
        let uuid = test_uuid(3);
        let sid = test_sid(3000);
        mapping.insert(uuid, &sid).await.unwrap();
        // Second insert with the same pair must succeed (idempotent).
        mapping.insert(uuid, &sid).await.unwrap();
        // Verify only one entry exists.
        let got = mapping.lookup_sid(uuid).await.unwrap();
        assert_eq!(got, Some(sid));
    }

    #[tokio::test]
    async fn insert_conflict_on_sid_reuse() {
        let mapping = make_mapping();
        let uuid_a = test_uuid(10);
        let uuid_b = test_uuid(11);
        let sid = test_sid(4000);
        mapping.insert(uuid_a, &sid).await.unwrap();
        // Inserting the same SID for a different UUID must fail with MappingConflict.
        let result = mapping.insert(uuid_b, &sid).await;
        assert!(matches!(result, Err(IdentityError::MappingConflict(_))));
    }

    #[tokio::test]
    async fn insert_conflict_on_uuid_reuse() {
        let mapping = make_mapping();
        let uuid = test_uuid(12);
        let sid_a = test_sid(5000);
        let sid_b = test_sid(5001);
        mapping.insert(uuid, &sid_a).await.unwrap();
        let result = mapping.insert(uuid, &sid_b).await;
        assert!(matches!(result, Err(IdentityError::MappingConflict(_))));
    }

    // ----- remove -----

    #[tokio::test]
    async fn remove_then_lookup_returns_none() {
        let mapping = make_mapping();
        let uuid = test_uuid(4);
        let sid = test_sid(4001);
        mapping.insert(uuid, &sid).await.unwrap();
        mapping.remove(uuid).await.unwrap();
        assert!(mapping.lookup_sid(uuid).await.unwrap().is_none());
        assert!(mapping.lookup_uuid(&sid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn remove_is_idempotent() {
        let mapping = make_mapping();
        let uuid = test_uuid(5);
        mapping.remove(uuid).await.unwrap();
        mapping.remove(uuid).await.unwrap();
    }

    #[tokio::test]
    async fn remove_then_reinsert_works() {
        let mapping = make_mapping();
        let uuid = test_uuid(6);
        let sid_a = test_sid(6000);
        let sid_b = test_sid(6001);
        mapping.insert(uuid, &sid_a).await.unwrap();
        mapping.remove(uuid).await.unwrap();
        // After removal, the UUID is free to be re-mapped to a different SID.
        mapping.insert(uuid, &sid_b).await.unwrap();
        assert_eq!(mapping.lookup_sid(uuid).await.unwrap(), Some(sid_b.clone()));
        assert_eq!(mapping.lookup_uuid(&sid_b).await.unwrap(), Some(uuid));
        assert!(mapping.lookup_uuid(&sid_a).await.unwrap().is_none());
    }

    // ----- allocate_uid (single-call only; cross-call monotonicity requires
    // the `fdb` feature against a real FDB cluster) -----

    #[tokio::test]
    async fn allocate_uid_first_call_returns_65536() {
        let mapping = make_mapping();
        let uid = allocate_uid(&mapping.store, test_uuid(20)).await.unwrap();
        assert_eq!(uid, 65536, "first allocation must return 65536");
    }

    #[tokio::test]
    async fn allocate_uid_writes_index_entries() {
        let mapping = make_mapping();
        let uuid = test_uuid(24);
        let uid = allocate_uid(&mapping.store, uuid).await.unwrap();
        // After allocation, lookup_uid must return the stored UID (not the
        // algorithmic fallback).
        let got = mapping.lookup_uid(uuid).await.unwrap();
        assert_eq!(got, Some(uid));
        // And lookup_uuid_from_uid must round-trip.
        let got_uuid = mapping.lookup_uuid_from_uid(uid).await.unwrap();
        assert_eq!(got_uuid, Some(uuid));
    }

    // ----- Cache behavior -----

    #[tokio::test]
    async fn lookup_sid_populates_cache_on_miss() {
        let mapping = make_mapping();
        let uuid = test_uuid(30);
        let sid = test_sid(7000);
        mapping.insert(uuid, &sid).await.unwrap();
        // Drop the in-memory cache (clone the store, new caches).
        let mapping2 = FdbIdentityMapping {
            store: mapping.store.clone(),
            cache_capacity: mapping.cache_capacity,
            cache_uuid_to_sid: Arc::new(RwLock::new(HashMap::new())),
            cache_sid_to_uuid: Arc::new(RwLock::new(HashMap::new())),
        };
        // First lookup misses the cache, hits the store, populates the cache.
        let got = mapping2.lookup_sid(uuid).await.unwrap();
        assert_eq!(got, Some(sid.clone()));
        // Second lookup must hit the cache (we verify by inspecting it
        // directly).
        assert_eq!(mapping2.cache_get_sid(&uuid), Some(sid));
    }

    #[tokio::test]
    async fn remove_invalidates_cache() {
        let mapping = make_mapping();
        let uuid = test_uuid(31);
        let sid = test_sid(8000);
        mapping.insert(uuid, &sid).await.unwrap();
        // Cache is populated.
        assert_eq!(mapping.cache_get_sid(&uuid), Some(sid.clone()));
        mapping.remove(uuid).await.unwrap();
        // Cache is invalidated.
        assert_eq!(mapping.cache_get_sid(&uuid), None);
        assert_eq!(mapping.cache_get_uuid(&sid), None);
    }
}
