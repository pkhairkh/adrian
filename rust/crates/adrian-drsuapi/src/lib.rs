//! # adrian-drsuapi
//!
//! DRSUAPI server (MS-DRSR) for the Adrian framework — fresh Rust
//! implementation.
//!
//! Per Workshop Decision 1 §Decision, the framework implements DRSUAPI
//! (MS-DRSR) server-side as a fresh, clean-room Rust implementation derived
//! from the published Microsoft protocol specification — *not* derived from
//! Samba's GPLv3 source. This crate implements the [`Replicator`] trait from
//! `adrian-repl-core` and runs over the DCE/RPC transport from
//! `adrian-dcerpc`.
//!
//! ## DRSUAPI opnums (per Decision 1 §Decision)
//!
//! | Opnum | Method | Status |
//! |-------|--------|--------|
//! | 0x00  | `IDL_DRSBind` | stub |
//! | 0x01  | `IDL_DRSUnbind` | stub |
//! | 0x03  | `IDL_DRSReplicaSync` | stub |
//! | 0x04  | `IDL_DRSGetNCChanges` | stub |
//! | 0x05  | `IDL_DRSUpdateRefs` | stub |
//! | 0x06  | `IDL_DRSReplicaAdd` | stub |
//! | 0x07  | `IDL_DRSReplicaDel` | stub |
//! | 0x08  | `IDL_DRSReplicaModify` | stub |
//! | 0x15  | `IDL_DRSGetReplInfo` | stub |
//! | 0x0C  | `IDL_DRSCrackNames` | stub |
//! | 0x0E  | `IDL_DRSVerifyNames` | stub |
//! | 0x11  | `IDL_DRSDomainControllerInfo` | stub |
//! | —     | `EXOP_REPL_SECRETS` (DCSync) | stub (ACL-gated per ADR-122) |
//!
//! `IDL_DRSGetMemberships` (0x0D) and `IDL_DRSGetNT4ChangeLog` (0x12) are
//! deferred to v2 (per Decision 1 §Decision — not in AD-interop MVP).
//!
//! ## ADRs
//!
//! - ADR-070: DRSUAPI replication protocol
//! - ADR-001: Linked Value Replication (`REPLVALINF_V3` records)
//! - ADR-071: Replication model (UTD vectors, conflict resolution)
//! - ADR-074: Tombstone lifetime and lingering objects
//! - ADR-122: DCSync mitigation (ACL-gated `EXOP_REPL_SECRETS`)
//! - ADR-126: sIDHistory migration via DRSAddSidHistory
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-repl-core`, `adrian-storage-fdb`, `adrian-schema-traits`,
//! `adrian-identity-core`, `adrian-dcerpc`, `rasn`. Gated by the
//! `ad-interop` feature flag at the workspace level.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_repl_core::{
    ConflictRecord, NcHead, ReplicationError, ReplicationPayload, Replicator, Resolution, UtdDelta,
    UtdVector,
};
use async_trait::async_trait;

/// DRSUAPI extension flags (per MS-DRSR §4.1.277 — `DRS_EXTENSIONS`).
///
/// Per Decision 1 §Decision, the framework negotiates
/// `DRS_EXT_GETCHGREQ_V8` (0x40), `DRS_EXT_GETCHGREPLY_V9` (0x80),
/// `DRS_EXT_GETCHGREQ_V10` (0x10000), and
/// `DRS_EXT_INSTANCEINFO_NOTISMASTERS` for full LVR support (per ADR-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrsExtFlag {
    /// `DRS_EXT_BASE` (0x00000001) — base extension.
    Base = 0x0000_0001,
    /// `DRS_EXT_ASYNCREPL` (0x00000002) — async replication.
    AsyncRepl = 0x0000_0002,
    /// `DRS_EXT_GETCHGREQ_V6` (0x00000004) — `IDL_DRSGetNCChanges` V6.
    GetChgReqV6 = 0x0000_0004,
    /// `DRS_EXT_GETCHGREPLY_V5` (0x00000008) — `IDL_DRSGetNCChanges` reply V5.
    GetChgReplyV5 = 0x0000_0008,
    /// `DRS_EXT_GETCHGREQ_V8` (0x00000040) — `IDL_DRSGetNCChanges` V8 (LVR,
    /// per ADR-001).
    GetChgReqV8 = 0x0000_0040,
    /// `DRS_EXT_GETCHGREPLY_V9` (0x00000080) — `IDL_DRSGetNCChanges` reply V9.
    GetChgReplyV9 = 0x0000_0080,
    /// `DRS_EXT_GETCHGREQ_V10` (0x00010000) — `IDL_DRSGetNCChanges` V10.
    GetChgReqV10 = 0x0001_0000,
    /// `DRS_EXT_INSTANCEINFO_NOTISMASTERS` (0x00000010) — see MS-DRSR.
    InstanceInfoNotIsMasters = 0x0000_0010,
}

/// DRSUAPI DSA options (per MS-DRSR, the `dwFlags` field on `IDL_DRSBind`).
///
/// These are bit flags — in MS-DRSR several symbolic names map to the same
/// numeric bit (e.g. `DRS_GETCHG_CHECK` and `DRS_UPDATE_NOTIFICATION` both
/// equal `0x0000_0002`). Rust `enum` variants cannot share discriminant
/// values, so the canonical name is retained here and the alias is documented
/// in the variant's doc comment. Consumers that need to combine flags should
/// use the underlying `u32` representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrsOption {
    /// `DRS_ASYNC_OP` (0x00000001) — async operation.
    AsyncOp = 0x0000_0001,
    /// `DRS_GETCHG_CHECK` (0x00000002) — check for changes. Also the value
    /// of `DRS_UPDATE_NOTIFICATION` (alias in MS-DRSR).
    GetChgCheck = 0x0000_0002,
    /// `DRS_ADD_REF` (0x00000004) — add reference.
    AddRef = 0x0000_0004,
    /// `DRS_SYNC_ALL` (0x00000008) — sync all. Also the value of
    /// `DRS_DEL_REF` (alias in MS-DRSR).
    SyncAll = 0x0000_0008,
    /// `DRS_WRIT_REP` (0x00000010) — writable replication.
    WritRep = 0x0000_0010,
    /// `DRS_INIT_SYNC` (0x00000020) — initial sync.
    InitSync = 0x0000_0020,
    /// `DRS_PER_SYNC` (0x00000040) — periodic sync.
    PerSync = 0x0000_0040,
    /// `DRS_FULL_SYNC_NOW` (0x0000_0080) — full sync now.
    FullSyncNow = 0x0000_0080,
    /// `EXOP_REPL_SECRETS` (0x00000100) — the DCSync extension, per ADR-122
    /// (ACL-gated).
    ExopReplSecrets = 0x0000_0100,
    /// `DRS_GET_ANC` (0x00000800) — get ancestors.
    GetAnc = 0x0000_0800,
    /// `DRS_FULL_SYNC_IN_PROGRESS` (0x00010000) — full sync in progress.
    FullSyncInProgress = 0x0001_0000,
    /// `DRS_GET_ALL_GROUP_MEMBERSHIP` (0x00800000) — get all group
    /// memberships.
    GetAllGroupMembership = 0x0080_0000,
}

/// DRSUAPI replicator implementation (per Decision 1 §Decision).
///
/// Implements [`Replicator`] by speaking MS-DRSR over the DCE/RPC transport
/// from `adrian-dcerpc`. Negotiates `DRS_EXT_GETCHGREQ_V8/V10` for full LVR
/// support (per ADR-001). Emits and consumes `REPLVALINF_V3` records
/// byte-identically to MS-DRSR §4.1.277 (per Decision 1 §Decision) for every
/// linked-attribute change.
pub struct DrSuapiReplicator {
    /// The DSA's invocation ID (per MS-ADTS §3.1.1.3.2.6).
    pub invocation_id: uuid::Uuid,
    /// The underlying FDB-backed directory store.
    pub store: adrian_storage_fdb::FdbDirectoryStore,
}

impl DrSuapiReplicator {
    /// Construct a new `DrSuapiReplicator`.
    pub fn new(invocation_id: uuid::Uuid, store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self {
            invocation_id,
            store,
        }
    }
}

#[async_trait]
impl Replicator for DrSuapiReplicator {
    async fn get_changes(
        &self,
        _nc_head: NcHead,
        _cursor: &UtdVector,
    ) -> Result<ReplicationPayload, ReplicationError> {
        // TODO: implement per ADR-070 — handle IDL_DRSGetNCChanges (opnum
        // 0x04). Walk the FDB subspaces (0x01 objects + 0x02 linktable +
        // 0x07 tombstones) starting at the cursor's highest USN per origin
        // DSA; emit REPLVALINF_V3 records byte-identically to MS-DRSR
        // §4.1.277.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::get_changes not yet implemented".into(),
        ))
    }

    async fn apply_changes(
        &self,
        _batch: ReplicationPayload,
    ) -> Result<Vec<Resolution>, ReplicationError> {
        // TODO: implement per ADR-070 — apply REPLVALINF_V3 records in a
        // single FDB transaction; per-value conflict resolution using
        // adrian_repl_core::resolve_conflict.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::apply_changes not yet implemented".into(),
        ))
    }

    async fn update_utd_vector(
        &self,
        _nc_head: NcHead,
        _delta: UtdDelta,
    ) -> Result<(), ReplicationError> {
        // TODO: implement per ADR-071 — write UTD vector entry to FDB
        // subspace 0x05.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::update_utd_vector not yet implemented".into(),
        ))
    }

    async fn resolve_conflict(
        &self,
        _conflict: ConflictRecord,
    ) -> Result<Resolution, ReplicationError> {
        // TODO: implement per ADR-071 — admin-intervention conflict
        // resolution; the default resolver is
        // adrian_repl_core::resolve_conflict.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::resolve_conflict not yet implemented".into(),
        ))
    }

    async fn sync_metadata(&self, _partner: &str) -> Result<(), ReplicationError> {
        // TODO: implement per ADR-070 — handle IDL_DRSReplicaSync (opnum
        // 0x03) to the partner DSA.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::sync_metadata not yet implemented".into(),
        ))
    }
}

/// `IDL_DRSBind` (opnum 0x00) — bind to the DRSUAPI service (per MS-DRSR
/// §4.1.4).
pub async fn drs_bind(
    _invocation_id: uuid::Uuid,
    _extensions: &[DrsExtFlag],
) -> Result<DrsBindResult, ReplicationError> {
    // TODO: implement per ADR-070 / MS-DRSR §4.1.4.
    Err(ReplicationError::Backend(
        "drs_bind not yet implemented".into(),
    ))
}

/// The result of `IDL_DRSBind` (per MS-DRSR §4.1.4.2 `DRS_BIND_RESULT`).
#[derive(Debug, Clone)]
pub struct DrsBindResult {
    /// The server's DSA invocation ID.
    pub server_invocation_id: uuid::Uuid,
    /// The server's negotiated extension flags (per MS-DRSR §4.1.277).
    pub server_extensions: Vec<DrsExtFlag>,
    /// The server's replication epoch (per MS-DRSR §4.1.4.2).
    pub replication_epoch: u32,
}

/// `IDL_DRSGetNCChanges` (opnum 0x04) — get NC changes (per MS-DRSR §4.1.27).
pub async fn drs_get_nc_changes(
    _nc_head: NcHead,
    _cursor: &UtdVector,
) -> Result<ReplicationPayload, ReplicationError> {
    // TODO: implement per ADR-070 / MS-DRSR §4.1.27 — emit REPLVALINF_V3
    // records byte-identically.
    Err(ReplicationError::Backend(
        "drs_get_nc_changes not yet implemented".into(),
    ))
}

// TODO: implement IDL_DRSUnbind (opnum 0x01) per MS-DRSR §4.1.5.
// TODO: implement IDL_DRSReplicaSync (opnum 0x03) per MS-DRSR §4.1.10.
// TODO: implement IDL_DRSUpdateRefs (opnum 0x05) per MS-DRSR §4.1.21.
// TODO: implement IDL_DRSReplicaAdd (opnum 0x06) per MS-DRSR §4.1.11.
// TODO: implement IDL_DRSReplicaDel (opnum 0x07) per MS-DRSR §4.1.13.
// TODO: implement IDL_DRSReplicaModify (opnum 0x08) per MS-DRSR §4.1.12.
// TODO: implement IDL_DRSGetReplInfo (opnum 0x15) per MS-DRSR §4.1.26.
// TODO: implement IDL_DRSCrackNames (opnum 0x0C) per MS-DRSR §4.1.17.
// TODO: implement IDL_DRSVerifyNames (opnum 0x0E) per MS-DRSR §4.1.19.
// TODO: implement IDL_DRSDomainControllerInfo (opnum 0x11) per MS-DRSR §4.1.16.
// TODO: implement EXOP_REPL_SECRETS (DCSync) per ADR-122 — ACL-gated, caller must have DS-Replication-Get-Changes-All on the domain NC head.
