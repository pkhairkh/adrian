//! # adrian-identity-core
//!
//! Identity mapping trait and principal types for the Adrian framework.
//!
//! Per Workshop Decision 3, the framework's identity model is UUID-primary
//! with SID-as-attribute: every principal has a UUIDv7 as its internal
//! primary key and a SID as a first-class attribute (`objectSid`). The
//! [`IdentityMapping`] trait is the bidirectional cache that translates
//! between the two, and is consumed by the KDC PAC builder, the Auth
//! Provider, the Policy Engine, the File Gateway ACL evaluator, the Client
//! SDK ID-mapping service, and the Migration sIDHistory flow.
//!
//! ## ADRs
//!
//! - ADR-110: SID-to-UID mapping (UUID-primary)
//! - ADR-077: Foreign security principals + RID pool
//! - ADR-126: sIDHistory migration via DRSAddSidHistory
//! - ADR-124: sIDHistory injection mitigation
//! - ADR-066: AdminSDHolder → declarative RBAC
//!
//! ## Layer
//!
//! Layer 1 — abstractions (depend on Layer 0). Depends on `adrian-sid` and
//! `adrian-storage-core`. Implementations:
//! - `FdbIdentityMapping` in `adrian-identity-fdb` (production, FDB-backed,
//!   subspace `0x0D`)
//! - `InMemoryIdentityMapping` in `adrian-identity-testkit` (unit tests)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_sid::Sid;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A principal's internal primary key — a UUIDv7 (per Decision 3 §Decision).
///
/// UUIDv7 is time-ordered, which gives index locality in FDB (per Decision 2
/// §Rationale) and avoids the RID-pool bottleneck (per Decision 3 §Decision).
pub type PrincipalId = Uuid;

/// A POSIX UID/GID (per Decision 3 §Decision, `uuid_to_uid` algorithmic
/// mapping or `uidNumber`/`gidNumber` directory-stored mapping).
pub type PosixId = u32;

/// The type of a security principal (per RFC 4512 / AD's `objectClass`
/// hierarchy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrincipalType {
    /// A user principal (`objectClass: user`).
    User,
    /// A computer / domain-controller principal (`objectClass: computer`).
    Computer,
    /// A group principal (`objectClass: group`).
    Group,
    /// A managed service account (`objectClass: msDS-ManagedServiceAccount`).
    ManagedServiceAccount,
    /// A group managed service account (`objectClass:
    /// msDS-GroupManagedServiceAccount`).
    GroupManagedServiceAccount,
    /// A foreign security principal (per ADR-077).
    ForeignSecurityPrincipal,
    /// A trust account (per-forest trust, per-external trust).
    Trust,
}

/// A security principal (per Decision 3 §Decision Layer 1).
///
/// The principal carries both a UUID (`uuid`) and a SID (`sid`); the SID is
/// stored as a first-class attribute on the principal object. `sid_history`
/// (per ADR-124 / ADR-126) is the list of historical SIDs that the principal
/// was previously known by (used by `sIDHistory` migration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// The principal's UUIDv7 (per Decision 3).
    pub uuid: PrincipalId,
    /// The principal's current SID (the `objectSid` attribute).
    pub sid: Sid,
    /// Historical SIDs (the `sIDHistory` attribute, per ADR-126). Empty for
    /// principals that have never been migrated.
    pub sid_history: Vec<Sid>,
    /// The principal type (per RFC 4512 / AD).
    pub principal_type: PrincipalType,
}

/// Error type for identity operations (per Decision 3 §Error handling).
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The UUID or SID is not in the mapping table — the principal does not
    /// exist.
    #[error("identity mapping not found: {0}")]
    MappingNotFound(String),
    /// Two UUIDs map to the same SID, or two SIDs map to the same UUID — a
    /// corruption that should never happen given FDB's unique-index
    /// constraints.
    #[error("identity mapping conflict: {0}")]
    MappingConflict(String),
    /// The RID pool is exhausted — AD-interop mode only, requires RID-master
    /// intervention (per Decision 3 §Decision).
    #[error("RID pool exhausted for domain {0}")]
    RidPoolExhausted(String),
    /// The POSIX UID/GID collision check failed (per Decision 3 §Trade-offs
    /// accepted — for >10K principal deployments, use directory-stored
    /// `uidNumber`/`gidNumber`).
    #[error("POSIX UID/GID collision on uid={0}")]
    PosixCollision(PosixId),
    /// Backend storage error (per Decision 2 §Error handling).
    #[error("backend error: {0}")]
    Backend(String),
}

/// The SID↔UUID mapping trait (per Decision 3 §Decision).
///
/// Implementations:
/// - `FdbIdentityMapping` in `adrian-identity-fdb` (production, FDB-backed
///   subspace `0x0D` with forward and reverse indexes, per Decision 3)
/// - `InMemoryIdentityMapping` in `adrian-identity-testkit` (unit tests)
///
/// The trait is async (`async fn lookup_sid(&self, uuid: Uuid) -> ...`), takes
/// `&self`, and is `Send + Sync` (per Decision 3 §Async runtime). The
/// in-memory LRU cache is `tokio::sync::RwLock`-protected; FDB watches
/// (`tokio::sync::watch` channels) notify the cache on invalidation.
#[async_trait]
pub trait IdentityMapping: Send + Sync {
    /// Look up the SID for a UUID (forward lookup).
    ///
    /// This is the hottest identity-mapping consumer: the KDC PAC builder
    /// calls this on every AS-REQ (per Decision 3 §Implementation impact).
    async fn lookup_sid(&self, uuid: PrincipalId) -> Result<Option<Sid>, IdentityError>;

    /// Look up the UUID for a SID (reverse lookup).
    ///
    /// Used by the File Gateway ACL evaluator (per Decision 3
    /// §Implementation impact) and the Policy Engine security filter.
    async fn lookup_uuid(&self, sid: &Sid) -> Result<Option<PrincipalId>, IdentityError>;

    /// Look up the POSIX UID for a UUID (per ADR-110).
    ///
    /// Algorithmic mapping (per Decision 3 §Decision):
    /// `uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536`
    ///
    /// For deployments >10K principals, the framework recommends
    /// directory-stored `uidNumber`/`gidNumber` (per Decision 3 §Trade-offs
    /// accepted).
    async fn lookup_uid(&self, uuid: PrincipalId) -> Result<Option<PosixId>, IdentityError>;

    /// Look up the UUID for a POSIX UID (reverse lookup, per ADR-110).
    async fn lookup_uuid_from_uid(
        &self,
        uid: PosixId,
    ) -> Result<Option<PrincipalId>, IdentityError>;

    /// Insert a new (UUID, SID) mapping (per Decision 3 §Decision). Used by
    /// the principal-creation path; the mapping is replicated via the
    /// `Replicator` trait (per Decision 1).
    async fn insert(&self, uuid: PrincipalId, sid: &Sid) -> Result<(), IdentityError>;

    /// Remove a mapping (per Decision 3 §Decision). Used by the principal-
    /// deletion path.
    async fn remove(&self, uuid: PrincipalId) -> Result<(), IdentityError>;
}

/// The default algorithmic UUID → POSIX UID mapping (per Decision 3
/// §Decision).
///
/// `uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536`
///
/// Gives a stable POSIX UID range of 65536..2^31-1 (the same range as Linux
/// `useradd` defaults). For deployments >10K principals, use directory-stored
/// `uidNumber`/`gidNumber` (per Decision 3 §Trade-offs accepted — the
/// collision probability is unacceptable for >10K principals).
pub fn uuid_to_uid(uuid: PrincipalId) -> PosixId {
    // TODO: implement per Decision 3 §Decision and ADR-110.
    let high = (uuid.as_u128() >> 64) as u64;
    let low = uuid.as_u128() as u64;
    let mixed = high ^ low;
    let modulus = (1u64 << 31) - 65536;
    ((mixed % modulus) + 65536) as PosixId
}

// TODO: implement FdbIdentityMapping in adrian-identity-fdb per Decision 3 (FDB subspace 0x0D).
// TODO: implement InMemoryIdentityMapping in adrian-identity-testkit per Decision 3.
// TODO: implement RID pool allocator in adrian-identity-ridpool per Decision 3 (FDB subspace 0x06).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_to_uid_is_deterministic() {
        let uuid = Uuid::nil();
        let uid1 = uuid_to_uid(uuid);
        let uid2 = uuid_to_uid(uuid);
        assert_eq!(uid1, uid2, "same UUID must produce same UID");
    }

    #[test]
    fn uuid_to_uid_in_range() {
        // UID must be in [65536, 2^31-1)
        for i in 0..100u128 {
            let uuid = Uuid::from_u128(i);
            let uid = uuid_to_uid(uuid);
            assert!(uid >= 65536, "uid {} < 65536", uid);
            assert!(uid < (1u32 << 31), "uid {} >= 2^31", uid);
        }
    }

    #[test]
    fn uuid_to_uid_different_uuids_different_uids() {
        let uid1 = uuid_to_uid(Uuid::from_u128(1));
        let uid2 = uuid_to_uid(Uuid::from_u128(2));
        assert_ne!(uid1, uid2, "different UUIDs should produce different UIDs (with high probability)");
    }

    #[test]
    fn principal_type_variants() {
        let user = PrincipalType::User;
        let group = PrincipalType::Group;
        let computer = PrincipalType::Computer;
        // Just verify they exist and can be matched
        match user {
            PrincipalType::User => {}
            _ => panic!(),
        }
        match group {
            PrincipalType::Group => {}
            _ => panic!(),
        }
        match computer {
            PrincipalType::Computer => {}
            _ => panic!(),
        }
    }
}
