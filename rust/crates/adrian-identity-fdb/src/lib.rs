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
