//! # adrian-identity-ridpool
//!
//! RID pool allocator for the Adrian framework (AD-interop mode).
//!
//! Per Decision 3 §Decision, in AD-interop mode the RID-pool allocator runs
//! on the framework's "RID master" DC (the framework's replacement for AD's
//! RID Master FSMO role — per ADR-076 §Decision, FSMO roles are eliminated in
//! native mode but preserved in AD-interop mode for wire compatibility).
//!
//! The allocator dispenses RID ranges in **500-RID batches** (matching AD's
//! `RIDAllocationPoolSize`). The allocator state is stored in FDB subspace
//! `0x06` with the key:
//!
//! ```text
//! (0x06, domain_sid_bytes) → (next_rid, last_allocated_rid, pool_exhaustion_warning_threshold)
//! ```
//!
//! The `next_rid` counter uses FDB's atomic-add operation for lock-free
//! allocation (per Decision 2 §Decision). RID pool exhaustion (when
//! `next_rid` exceeds `last_allocated_rid`) triggers a request to the
//! RID-master DC for a new 500-RID batch.
//!
//! ## ADRs
//!
//! - ADR-015: krbtgt HSM rotation (RID-pool implications)
//! - ADR-076: FSMO role replacement (RID Master elimination in native mode)
//! - ADR-077: Foreign security principals + RID pool
//! - ADR-110: SID-to-UID mapping (UUID-primary)
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-identity-core`, `adrian-storage-fdb`, `adrian-sid`,
//! `adrian-storage-core`. Gated by the `ad-interop` feature flag at the
//! workspace level (per finaldraft/04-rust-workspace-design.md §7).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_identity_core::{IdentityError, PrincipalId};
use adrian_sid::Sid;
use async_trait::async_trait;

/// The size of a RID allocation batch (per Decision 3 §Decision — matches
/// AD's `RIDAllocationPoolSize`).
pub const RID_BATCH_SIZE: u32 = 500;

/// The RID-pool exhaustion warning threshold (per Decision 3 §Decision —
/// matches AD's `rIDAllocationPoolRenewThreshold`).
pub const RID_EXHAUSTION_WARNING_THRESHOLD: u32 = RID_BATCH_SIZE / 2;

/// A 32-bit RID (relative identifier, per MS-DTYP §2.4.2).
pub type Rid = u32;

/// The RID-pool allocator trait (per Decision 3 §Decision).
///
/// Implementations:
/// - [`FdbRidPoolAllocator`] — AD-interop mode (FDB subspace `0x06`,
///   500-RID batches dispensed by the RID-master DC)
/// - [`LocalRidAllocator`] — native mode (per-DC local counter, no
///   coordination, per Decision 3 §Decision)
#[async_trait]
pub trait RidPoolAllocator: Send + Sync {
    /// Allocate a single RID for the given domain SID (per Decision 3
    /// §Decision).
    async fn allocate(&self, domain_sid: &Sid) -> Result<Rid, IdentityError>;

    /// Allocate a batch of `n` RIDs for the given domain SID (per Decision 3
    /// §Decision — used by the RID-master DC when dispensing a new 500-RID
    /// batch to a non-RID-master DC).
    async fn allocate_batch(&self, domain_sid: &Sid, n: u32) -> Result<Vec<Rid>, IdentityError>;

    /// Return the current allocator state for the given domain SID (per
    /// Decision 3 §Decision — `next_rid`, `last_allocated_rid`).
    async fn state(&self, domain_sid: &Sid) -> Result<RidPoolState, IdentityError>;
}

/// The RID-pool allocator state for a single domain SID (per Decision 3
/// §Decision, stored at FDB key `(0x06, domain_sid_bytes)`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RidPoolState {
    /// The next RID to allocate (atomic-add counter, per Decision 2).
    pub next_rid: Rid,
    /// The last allocated RID in the current batch (per Decision 3).
    pub last_allocated_rid: Rid,
    /// The pool-exhaustion warning threshold (per Decision 3 — defaults to
    /// `RID_EXHAUSTION_WARNING_THRESHOLD`).
    pub warning_threshold: u32,
}

/// FDB-backed RID-pool allocator for AD-interop mode (per Decision 3
/// §Decision).
///
/// This allocator runs on the RID-master DC and dispenses 500-RID batches to
/// other DCs in the forest. The `next_rid` counter uses FDB's atomic-add
/// operation for lock-free allocation (per Decision 2 §Decision).
#[derive(Debug, Clone)]
pub struct FdbRidPoolAllocator {
    /// The underlying FDB-backed directory store (per ADR-073).
    pub store: adrian_storage_fdb::FdbDirectoryStore,
}

impl FdbRidPoolAllocator {
    /// Construct a new `FdbRidPoolAllocator` backed by the given
    /// `FdbDirectoryStore`.
    pub fn new(store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl RidPoolAllocator for FdbRidPoolAllocator {
    async fn allocate(&self, _domain_sid: &Sid) -> Result<Rid, IdentityError> {
        // TODO: implement per Decision 3 — FDB atomic-add on (0x06,
        // domain_sid, "next_rid") key; if the new value exceeds
        // last_allocated_rid, request a new 500-RID batch from the RID-master
        // DC (this is a no-op if we ARE the RID-master DC).
        Err(IdentityError::Backend(
            "FdbRidPoolAllocator::allocate not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn allocate_batch(&self, _domain_sid: &Sid, _n: u32) -> Result<Vec<Rid>, IdentityError> {
        // TODO: implement per Decision 3 — atomic-add n to (0x06, domain_sid,
        // "next_rid"); if the new value exceeds last_allocated_rid, error
        // with RidPoolExhausted.
        Err(IdentityError::Backend(
            "FdbRidPoolAllocator::allocate_batch not yet implemented (gated by `fdb` feature)"
                .into(),
        ))
    }

    async fn state(&self, _domain_sid: &Sid) -> Result<RidPoolState, IdentityError> {
        // TODO: implement per Decision 3 — read (0x06, domain_sid) key.
        Err(IdentityError::Backend(
            "FdbRidPoolAllocator::state not yet implemented (gated by `fdb` feature)".into(),
        ))
    }
}

/// Per-DC local RID allocator for native mode (per Decision 3 §Decision).
///
/// In native mode, each DC allocates RIDs locally with no coordination (no
/// RID-master DC). Each DC maintains its own RID counter at FDB key
/// `(0x06, local_dc_id, domain_sid) → next_rid`, where `local_dc_id` is the
/// DC's `invocationId` (per Decision 1).
#[derive(Debug, Clone)]
pub struct LocalRidAllocator {
    /// The DC's invocation ID (per Decision 1).
    pub local_dc_id: uuid::Uuid,
    /// The underlying FDB-backed directory store (per ADR-073).
    pub store: adrian_storage_fdb::FdbDirectoryStore,
}

impl LocalRidAllocator {
    /// Construct a new `LocalRidAllocator` for the given DC.
    pub fn new(local_dc_id: uuid::Uuid, store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self { local_dc_id, store }
    }
}

#[async_trait]
impl RidPoolAllocator for LocalRidAllocator {
    async fn allocate(&self, _domain_sid: &Sid) -> Result<Rid, IdentityError> {
        // TODO: implement per Decision 3 — local atomic-add on
        // (0x06, local_dc_id, domain_sid) key; no RID-master coordination.
        Err(IdentityError::Backend(
            "LocalRidAllocator::allocate not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn allocate_batch(&self, _domain_sid: &Sid, _n: u32) -> Result<Vec<Rid>, IdentityError> {
        // TODO: implement per Decision 3 — local atomic-add.
        Err(IdentityError::Backend(
            "LocalRidAllocator::allocate_batch not yet implemented (gated by `fdb` feature)".into(),
        ))
    }

    async fn state(&self, _domain_sid: &Sid) -> Result<RidPoolState, IdentityError> {
        // TODO: implement per Decision 3 — read local RID counter.
        Err(IdentityError::Backend(
            "LocalRidAllocator::state not yet implemented (gated by `fdb` feature)".into(),
        ))
    }
}

/// Helper: assign a SID to a principal using the RID-pool allocator (per
/// Decision 3 — principal-creation path).
pub async fn assign_sid(
    _allocator: &dyn RidPoolAllocator,
    _domain_sid: &Sid,
    _principal_uuid: PrincipalId,
) -> Result<Sid, IdentityError> {
    // TODO: implement per Decision 3 — allocate a RID, construct the SID
    // (domain_sid + RID), insert into IdentityMapping.
    Err(IdentityError::Backend(
        "assign_sid not yet implemented (gated by `fdb` feature)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn rid_batch_size_matches_ad_default() {
        // Per Decision 3 §Decision — must match AD's `RIDAllocationPoolSize`
        // for AD-interop wire compatibility.
        assert_eq!(RID_BATCH_SIZE, 500);
    }

    #[test]
    fn warning_threshold_is_half_batch_size() {
        // Per Decision 3 §Decision — defaults to AD's
        // `rIDAllocationPoolRenewThreshold` (half the batch size). When the
        // remaining pool drops below this threshold, the DC preemptively
        // requests a new batch from the RID-master.
        assert_eq!(RID_EXHAUSTION_WARNING_THRESHOLD, 250);
        assert_eq!(RID_EXHAUSTION_WARNING_THRESHOLD, RID_BATCH_SIZE / 2);
    }

    #[test]
    fn rid_type_alias_is_u32() {
        // RIDs are 32-bit per MS-DTYP §2.4.2 — verify the alias is exactly
        // `u32` so consumers can rely on its width.
        let r: Rid = 0xFFFF_FFFF;
        assert_eq!(r, u32::MAX);
    }

    #[test]
    fn fdb_allocator_new_propagates_store() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(Some("/tmp/rid.cluster"));
        let allocator = FdbRidPoolAllocator::new(store);
        assert_eq!(
            allocator.store.cluster_file.as_deref(),
            Some("/tmp/rid.cluster")
        );
    }

    #[test]
    fn local_allocator_new_propagates_invocation_id_and_store() {
        // Per Decision 3 — in native mode each DC allocates RIDs locally keyed
        // by its `invocationId`. Verify both fields are stored.
        let invocation_id = Uuid::from_u128(0xABCD_1234);
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let allocator = LocalRidAllocator::new(invocation_id, store);
        assert_eq!(allocator.local_dc_id, invocation_id);
        assert!(allocator.store.cluster_file.is_none());
    }

    #[test]
    fn rid_pool_state_serializes_round_trip() {
        // `RidPoolState` is stored at FDB key (0x06, domain_sid_bytes) —
        // serde round-trip must be lossless.
        let state = RidPoolState {
            next_rid: 1000,
            last_allocated_rid: 1500,
            warning_threshold: RID_EXHAUSTION_WARNING_THRESHOLD,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let decoded: RidPoolState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.next_rid, 1000);
        assert_eq!(decoded.last_allocated_rid, 1500);
        assert_eq!(decoded.warning_threshold, 250);
    }

    #[test]
    fn rid_pool_state_default_warning_threshold_is_250() {
        // Verify the documented default — even though `RidPoolState` has no
        // `Default` impl, the canonical initial state uses
        // `RID_EXHAUSTION_WARNING_THRESHOLD` for the warning_threshold field.
        let initial = RidPoolState {
            next_rid: 500,
            last_allocated_rid: 1000,
            warning_threshold: RID_EXHAUSTION_WARNING_THRESHOLD,
        };
        assert_eq!(initial.warning_threshold, 250);
    }

    #[tokio::test]
    async fn fdb_allocator_allocate_returns_backend_error_without_fdb() {
        // The FDB-backed allocator requires the `fdb` feature flag. Without
        // it, `allocate` must surface a `Backend` error rather than panicking.
        let allocator = FdbRidPoolAllocator::new(adrian_storage_fdb::FdbDirectoryStore::new(None));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let result = allocator.allocate(&domain_sid).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    #[tokio::test]
    async fn fdb_allocator_allocate_batch_returns_backend_error_without_fdb() {
        let allocator = FdbRidPoolAllocator::new(adrian_storage_fdb::FdbDirectoryStore::new(None));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let result = allocator.allocate_batch(&domain_sid, 500).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    #[tokio::test]
    async fn fdb_allocator_state_returns_backend_error_without_fdb() {
        let allocator = FdbRidPoolAllocator::new(adrian_storage_fdb::FdbDirectoryStore::new(None));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let result = allocator.state(&domain_sid).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    #[tokio::test]
    async fn local_allocator_returns_backend_error_without_fdb() {
        // LocalRidAllocator is also FDB-backed (per-DC local counter at
        // (0x06, local_dc_id, domain_sid) key). Verify it surfaces
        // `Backend` for every method when the `fdb` feature is off.
        let allocator = LocalRidAllocator::new(
            Uuid::nil(),
            adrian_storage_fdb::FdbDirectoryStore::new(None),
        );
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        assert!(matches!(
            allocator.allocate(&domain_sid).await,
            Err(IdentityError::Backend(_))
        ));
        assert!(matches!(
            allocator.allocate_batch(&domain_sid, 10).await,
            Err(IdentityError::Backend(_))
        ));
        assert!(matches!(
            allocator.state(&domain_sid).await,
            Err(IdentityError::Backend(_))
        ));
    }

    #[tokio::test]
    async fn assign_sid_returns_backend_error_without_fdb() {
        // The `assign_sid` helper composes RID allocation + SID construction +
        // IdentityMapping insertion; all three require FDB. Without `fdb`,
        // it must surface a `Backend` error.
        let allocator: Box<dyn RidPoolAllocator> = Box::new(FdbRidPoolAllocator::new(
            adrian_storage_fdb::FdbDirectoryStore::new(None),
        ));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let result = assign_sid(allocator.as_ref(), &domain_sid, Uuid::nil()).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(IdentityError::Backend(_))));
    }

    // NOTE: FDB-backed integration tests (RID-pool exhaustion, batch
    // dispensation, RID-master coordination, lock-free atomic-add allocation)
    // require a running FoundationDB cluster and the `fdb` feature flag. They
    // are intentionally omitted from this unit-test module — see
    // `adrian-test-harness` for integration tests.
    #[tokio::test]
    #[ignore = "requires a running FDB cluster and the `fdb` feature flag"]
    async fn fdb_integration_rid_pool_exhaustion_triggers_batch_request() {
        // Placeholder — will be implemented in `adrian-test-harness` once the
        // FDB integration testkit is added in Wave 4b.
    }
}
