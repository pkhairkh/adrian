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
//! `adrian-storage-core`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_identity_core::{IdentityError, IdentityMapping, PosixId, PrincipalId};
use adrian_sid::Sid;
use async_trait::async_trait;

/// FDB-backed implementation of [`IdentityMapping`] (per Decision 3).
///
/// The mapping table is stored in FDB subspace `0x0D`:
/// - Forward index: `(0x0D, 0x01, uuid_bytes) → sid_bytes`
/// - Reverse index: `(0x0D, 0x02, sid_bytes) → uuid_bytes`
/// - POSIX UID index: `(0x0D, 0x03, uid_be_bytes) → uuid_bytes`
///
/// The in-memory LRU cache (per Decision 3 §Async runtime —
/// `tokio::sync::RwLock`-protected, 99%+ hit rate on the KDC PAC builder hot
/// path) is invalidated by FDB watches on the forward-index key.
#[derive(Debug, Clone)]
pub struct FdbIdentityMapping {
    /// The underlying FDB-backed directory store (per ADR-073).
    pub store: adrian_storage_fdb::FdbDirectoryStore,
    /// The LRU cache capacity (default 100_000 entries — per Decision 3
    /// §Implementation impact, ~80 MB resident set on a mid-size forest).
    pub cache_capacity: usize,
}

impl FdbIdentityMapping {
    /// Construct a new `FdbIdentityMapping` backed by the given
    /// `FdbDirectoryStore`.
    pub fn new(store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self {
            store,
            cache_capacity: 100_000,
        }
    }
}

#[async_trait]
impl IdentityMapping for FdbIdentityMapping {
    async fn lookup_sid(&self, _uuid: PrincipalId) -> Result<Option<Sid>, IdentityError> {
        // TODO: implement per Decision 3 — read from LRU cache; on miss, read
        // FDB subspace 0x0D forward index; populate cache; register FDB watch
        // for invalidation.
        Err(IdentityError::Backend(
            "FdbIdentityMapping::lookup_sid not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn lookup_uuid(&self, _sid: &Sid) -> Result<Option<PrincipalId>, IdentityError> {
        // TODO: implement per Decision 3 — read reverse index on FDB subspace
        // 0x0D.
        Err(IdentityError::Backend(
            "FdbIdentityMapping::lookup_uuid not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn lookup_uid(&self, uuid: PrincipalId) -> Result<Option<PosixId>, IdentityError> {
        // TODO: implement per Decision 3 — fall back to
        // adrian_identity_core::uuid_to_uid algorithmic mapping if
        // uidNumber is not directory-stored.
        Ok(Some(adrian_identity_core::uuid_to_uid(uuid)))
    }

    async fn lookup_uuid_from_uid(
        &self,
        _uid: PosixId,
    ) -> Result<Option<PrincipalId>, IdentityError> {
        // TODO: implement per Decision 3 — read POSIX UID index on FDB
        // subspace 0x0D.
        Err(IdentityError::Backend(
            "FdbIdentityMapping::lookup_uuid_from_uid not yet implemented (gated by `fdb` feature)"
                .into(),
        ))
    }

    async fn insert(&self, _uuid: PrincipalId, _sid: &Sid) -> Result<(), IdentityError> {
        // TODO: implement per Decision 3 — write forward + reverse indexes in
        // a single FDB transaction; the unique-index constraint enforced by
        // FDB's strict serializable transactions prevents
        // `IdentityError::MappingConflict`.
        Err(IdentityError::Backend(
            "FdbIdentityMapping::insert not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn remove(&self, _uuid: PrincipalId) -> Result<(), IdentityError> {
        // TODO: implement per Decision 3 — clear forward + reverse indexes in
        // a single FDB transaction.
        Err(IdentityError::Backend(
            "FdbIdentityMapping::remove not yet implemented (gated by `fdb` feature)".into(),
        ))
    }
}

// TODO: implement FDB watches (tokio::sync::watch) for LRU cache invalidation per Decision 3 §Async runtime.
// TODO: implement PosixId collision detection per Decision 3 §Trade-offs accepted.

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_identity_core::IdentityMapping;
    use uuid::Uuid;

    /// Construct a default-backed `FdbIdentityMapping` for tests. The store is
    /// a stub and never reads/writes FDB — it is only used to verify the
    /// struct's public construction surface.
    fn make_mapping() -> FdbIdentityMapping {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        FdbIdentityMapping::new(store)
    }

    #[test]
    fn new_sets_default_cache_capacity() {
        // Per Decision 3 §Implementation impact — default cache capacity is
        // 100_000 entries (~80 MB resident set on a mid-size forest).
        let mapping = make_mapping();
        assert_eq!(mapping.cache_capacity, 100_000);
    }

    #[test]
    fn cache_capacity_is_mutable() {
        // Callers can tune the cache capacity for memory-constrained
        // deployments (e.g. edge DCs).
        let mut mapping = make_mapping();
        mapping.cache_capacity = 1_000;
        assert_eq!(mapping.cache_capacity, 1_000);
    }

    #[test]
    fn store_handle_is_propagated() {
        // The store field is `pub` — verify the construction propagates the
        // cluster file path through to the underlying store.
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

    #[tokio::test]
    async fn lookup_uid_returns_algorithmic_mapping() {
        // Per Decision 3 — `lookup_uid` falls back to the algorithmic
        // `uuid_to_uid` mapping when `uidNumber` is not directory-stored. The
        // stub implementation must return `Some(uuid_to_uid(uuid))`.
        let mapping = make_mapping();
        let uuid = Uuid::from_u128(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF);
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
        // Per Decision 3 §Decision — UID must be in [65536, 2^31-1).
        let mapping = make_mapping();
        for i in 0..64u128 {
            let uuid = Uuid::from_u128(i);
            if let Some(uid) = mapping.lookup_uid(uuid).await.unwrap() {
                assert!(uid >= 65536, "uid {} < 65536", uid);
                assert!(uid < (1u32 << 31), "uid {} >= 2^31", uid);
            }
        }
    }

    #[tokio::test]
    async fn lookup_sid_returns_backend_error_when_fdb_unavailable() {
        // The FDB-backed implementation is gated behind the `fdb` feature.
        // Without the feature, `lookup_sid` must surface a `Backend` error
        // (not panic), so callers can degrade gracefully.
        let mapping = make_mapping();
        let result = mapping.lookup_sid(Uuid::nil()).await;
        assert!(result.is_err(), "expected an error");
        assert!(
            matches!(result, Err(IdentityError::Backend(_))),
            "expected Backend error, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn lookup_uuid_returns_backend_error_when_fdb_unavailable() {
        let mapping = make_mapping();
        let sid: Sid = "S-1-5-21-100-200-300-1000".parse().unwrap();
        let result = mapping.lookup_uuid(&sid).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    #[tokio::test]
    async fn lookup_uuid_from_uid_returns_backend_error_when_fdb_unavailable() {
        let mapping = make_mapping();
        let result = mapping.lookup_uuid_from_uid(65536).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    #[tokio::test]
    async fn insert_returns_backend_error_when_fdb_unavailable() {
        let mapping = make_mapping();
        let sid: Sid = "S-1-5-21-100-200-300-1000".parse().unwrap();
        let result = mapping.insert(Uuid::nil(), &sid).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    #[tokio::test]
    async fn remove_returns_backend_error_when_fdb_unavailable() {
        let mapping = make_mapping();
        let result = mapping.remove(Uuid::nil()).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    // NOTE: FDB-backed integration tests (forward/reverse index reads, LRU
    // cache hit/miss, FDB watch invalidation) require a running FoundationDB
    // cluster and the `fdb` feature flag. They are intentionally omitted from
    // this unit-test module — see `adrian-test-harness` for integration tests
    // that spin up a real FDB cluster via docker-compose.
    #[tokio::test]
    #[ignore = "requires a running FDB cluster and the `fdb` feature flag"]
    async fn fdb_integration_lookup_sid_hits_lru_cache() {
        // Placeholder — will be implemented in `adrian-test-harness` once the
        // FDB integration testkit is added in Wave 4b.
    }
}
