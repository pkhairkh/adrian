//! # adrian-repl-core
//!
//! Replication trait and shared types for the Adrian framework.
//!
//! Per Workshop Decision 1, the framework implements a hybrid replication
//! architecture with two distinct operating modes behind a single
//! [`Replicator`] trait:
//!
//! - **AD-interop mode** — `DrSuapiReplicator` (in `adrian-drsuapi`) implements
//!   DRSUAPI (MS-DRSR) server-side as a fresh, clean-room Rust implementation.
//! - **Native mode** — `RaftReplicator` (in `adrian-raft`) uses
//!   [`openraft`](https://docs.rs/openraft) for consensus in framework-only
//!   forests.
//!
//! Both modes share the same on-disk representation (per-value
//! [`PropertyMetaDataExt`], the link-value store from ADR-001, the
//! [`UtdVector`] store, and the same conflict-resolution primitives), so the
//! `Replicator` trait operates on the same [`ReplOperation`] enum regardless
//! of the underlying wire protocol.
//!
//! ## ADRs
//!
//! - ADR-001: Linked Value Replication
//! - ADR-071: Replication model (UTD vectors, conflict resolution)
//! - ADR-070: DRSUAPI replication protocol
//! - ADR-074: Tombstone lifetime and lingering objects
//! - ADR-076: FSMO role replacement (native mode)
//! - ADR-008: Declarative replication topology
//! - ADR-122: DCSync mitigation
//!
//! ## Layer
//!
//! Layer 1 — abstractions (depend on Layer 0). Depends on
//! `adrian-storage-core` and `adrian-schema-traits`. Implementations:
//! - `DrSuapiReplicator` in `adrian-drsuapi` (Layer 2, AD-interop)
//! - `RaftReplicator` in `adrian-raft` (Layer 2, native)
//! - `InMemoryReplicator` in `adrian-repl-testkit` (unit tests)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A DSA invocation ID (per MS-ADTS §3.1.1.3.2.6, the `invocationId`
/// attribute on the `nTDSDSA` object). A 128-bit UUID that identifies a DC's
/// current replication identity; changes when the DC's database is restored
/// from backup (per ADR-074 §Decision — strict serializable transactions
/// eliminate the LWW-ambiguity that AD's tombstone model has).
pub type InvocationId = Uuid;

/// A USN (update sequence number, per MS-ADTS §3.1.1.3.2.5). 64-bit
/// monotonically-increasing counter per-DC; the `USNChanged` attribute on
/// each object is the highest USN at the time of the last write.
pub type Usn = u64;

/// A per-value version counter (per MS-ADTS §3.1.1.3.2.6,
/// `PROPERTY_META_DATA_EXT.version`). Incremented on every write to the
/// value.
pub type Version = u32;

/// A directory NC head (per MS-ADTS, the `nCName` attribute on the
/// `crossRef` object). The replication cursor is anchored to the NC head.
pub type NcHead = Uuid;

/// Per-value replication metadata (per MS-ADTS §3.1.1.3.2.6
/// `PROPERTY_META_DATA_EXT`).
///
/// The four-tuple `(origin_invocation_id, origin_usn, version,
/// last_write_timestamp)` is the AD-canonical representation and is emitted
/// byte-identically by `DrSuapiReplicator` (per Decision 1 §Decision).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PropertyMetaDataExt {
    /// The origin DSA's invocation ID (per MS-ADTS §3.1.1.3.2.6).
    pub origin_invocation_id: InvocationId,
    /// The origin USN at the time of the last write (per MS-ADTS
    /// §3.1.1.3.2.6).
    pub origin_usn: Usn,
    /// The per-value version counter (per MS-ADTS §3.1.1.3.2.6).
    pub version: Version,
    /// The last-write timestamp (per MS-ADTS §3.1.1.3.2.6,
    /// `lastWriteTime`). Windows FILETIME (100ns intervals since 1601-01-01).
    pub last_write_timestamp: u64,
}

/// A single up-to-dateness vector entry (per MS-ADTS §3.1.1.3.2.5,
/// `UTD_VECTOR`): `(origin_invocation_id, highest_usn)` pairs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UtdVectorEntry {
    /// The origin DSA's invocation ID.
    pub invocation_id: InvocationId,
    /// The highest USN received from that DSA.
    pub highest_usn: Usn,
}

/// An up-to-dateness vector (per MS-ADTS §3.1.1.3.2.5).
///
/// The UTD vector is the per-DC, per-NC summary of the highest USN received
/// from every other DSA. It is used to skip replication partners that have
/// nothing new to send. Stored in FDB subspace `0x05` (per Decision 2
/// §Decision).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UtdVector {
    /// The vector entries, one per origin DSA.
    pub entries: Vec<UtdVectorEntry>,
}

/// A delta to apply to a UTD vector (per Decision 1 §Decision — the
/// `update_utd_vector` method takes a delta, not a full vector).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtdDelta {
    /// The origin DSA's invocation ID.
    pub invocation_id: InvocationId,
    /// The new highest USN received from that DSA.
    pub new_highest_usn: Usn,
}

/// A replication operation (per Decision 1 §Decision — the `Replicator`
/// trait operates on this enum).
///
/// Each variant carries per-value [`PropertyMetaDataExt`] so conflict
/// resolution can be applied uniformly across DrSuapiReplicator and
/// RaftReplicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplOperation {
    /// Add a new object. Carries the object's UUID, DN, and initial
    /// attribute values.
    AddObject {
        /// The object's UUIDv7 (per Decision 3).
        uuid: Uuid,
        /// The object's DN.
        dn: String,
        /// The initial attribute values, each with per-value metadata.
        attributes: Vec<(String, Vec<u8>, PropertyMetaDataExt)>,
    },
    /// Modify an attribute value (add, replace, or delete a single value).
    ModifyAttribute {
        /// The object's UUID.
        uuid: Uuid,
        /// The attribute LDAP name.
        attribute: String,
        /// The value bytes (empty for delete).
        value: Vec<u8>,
        /// The per-value metadata.
        metadata: PropertyMetaDataExt,
    },
    /// Delete an object (per ADR-074 — moves to tombstones subspace).
    DeleteObject {
        /// The object's UUID.
        uuid: Uuid,
        /// The per-object metadata.
        metadata: PropertyMetaDataExt,
    },
    /// Add a linked-attribute forward link (per ADR-001).
    AddLink {
        /// The forward-link object's UUID (e.g. the group).
        link_uuid: Uuid,
        /// The link ID (per ADR-001 — even for forward, odd for back-link).
        link_id: u32,
        /// The back-link object's UUID (e.g. the member).
        backlink_uuid: Uuid,
        /// The per-value metadata.
        metadata: PropertyMetaDataExt,
    },
    /// Remove a linked-attribute forward link (per ADR-001 — soft-delete via
    /// `fIsPresent=false`, not a hard delete, so the link can be rehydrated
    /// by a lingering-object reconciliation).
    DeleteLink {
        /// The forward-link object's UUID.
        link_uuid: Uuid,
        /// The link ID.
        link_id: u32,
        /// The back-link object's UUID.
        backlink_uuid: Uuid,
        /// The per-value metadata.
        metadata: PropertyMetaDataExt,
    },
    /// Tombstone garbage-collection sweep (per ADR-074 — periodic, not
    /// replicated; runs independently on each DC).
    TombstoneGC {
        /// The cutoff timestamp (Windows FILETIME). Tombstones older than
        /// this are hard-deleted.
        cutoff: u64,
    },
}

/// A batch of replication operations (per Decision 1 §Decision —
/// `get_changes` returns a batch, `apply_changes` takes a batch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPayload {
    /// The NC head this batch applies to.
    pub nc_head: NcHead,
    /// The replication operations in this batch, in apply order.
    pub operations: Vec<ReplOperation>,
    /// The originating DSA's invocation ID.
    pub origin_invocation_id: InvocationId,
    /// The highest USN in this batch (per MS-ADTS §3.1.1.3.2.5).
    pub highest_usn: Usn,
}

/// A replication conflict (per Decision 1 §Decision — conflict resolution is
/// highest-`version`-wins, tiebreak by latest `last_write_timestamp`, then
/// highest `origin_usn`, then lexicographically-highest
/// `origin_invocation_id` — matching AD's resolver).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// The object's UUID.
    pub uuid: Uuid,
    /// The attribute in conflict.
    pub attribute: String,
    /// The local value + metadata.
    pub local: (Vec<u8>, PropertyMetaDataExt),
    /// The incoming value + metadata.
    pub incoming: (Vec<u8>, PropertyMetaDataExt),
}

/// The resolution chosen for a conflict (per Decision 1 §Decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution {
    /// The local value won the conflict.
    LocalWins,
    /// The incoming value won the conflict.
    IncomingWins,
}

/// Error type for replication operations (per Decision 1 §Error handling).
#[derive(Debug, Error)]
pub enum ReplicationError {
    /// A transient error (network timeout, partner down, UTD-vector-too-old
    /// but recoverable). Retried automatically.
    #[error("transient replication error: {0}")]
    Transient(String),
    /// A permanent error (schema mismatch, invocation ID mismatch, lingering
    /// object that requires admin intervention). Surfaced to admin.
    #[error("permanent replication error: {0}")]
    Permanent(String),
    /// The replication partner is not reachable.
    #[error("partner unreachable: {0}")]
    PartnerUnreachable(String),
    /// The replication partner's schema generation is older than the local
    /// schema generation (per ADR-078 — schema mismatch is a permanent
    /// error).
    #[error("schema mismatch: local={local} partner={partner}")]
    SchemaMismatch {
        /// Local schema generation.
        local: u64,
        /// Partner schema generation.
        partner: u64,
    },
    /// The replication partner's invocation ID has changed (per ADR-074 —
    /// indicates a database restore on the partner; requires admin
    /// intervention).
    #[error("invocation ID mismatch: expected={expected} actual={actual}")]
    InvocationIdMismatch {
        /// The expected invocation ID.
        expected: InvocationId,
        /// The actual invocation ID.
        actual: InvocationId,
    },
    /// Backend storage error (per Decision 2 §Error handling).
    #[error("backend error: {0}")]
    Backend(String),
}

/// The replication trait (per Decision 1 §Decision).
///
/// The trait is async (`async fn get_changes(...) -> ...`), takes `&self`,
/// and is `Send + Sync` (per Decision 1 §Async runtime). Both
/// `DrSuapiReplicator` and `RaftReplicator` implement this trait.
///
/// Conflict resolution is highest-`version`-wins, tiebreak by latest
/// `last_write_timestamp`, then highest `origin_usn`, then
/// lexicographically-highest `origin_invocation_id` — matching AD's resolver
/// (per Decision 1 §Decision).
#[async_trait]
pub trait Replicator: Send + Sync {
    /// Get a batch of changes from the local DC starting at the given UTD
    /// cursor (per Decision 1 §Decision — `IDL_DRSGetNCChanges` opnum 0x04
    /// for DrSuapiReplicator; Raft log tail for RaftReplicator).
    async fn get_changes(
        &self,
        nc_head: NcHead,
        cursor: &UtdVector,
    ) -> Result<ReplicationPayload, ReplicationError>;

    /// Apply a batch of changes from a replication partner (per Decision 1
    /// §Decision — conflict resolution is applied per-value).
    async fn apply_changes(
        &self,
        batch: ReplicationPayload,
    ) -> Result<Vec<Resolution>, ReplicationError>;

    /// Update the UTD vector for the given NC head with a delta (per
    /// Decision 1 §Decision).
    async fn update_utd_vector(
        &self,
        nc_head: NcHead,
        delta: UtdDelta,
    ) -> Result<(), ReplicationError>;

    /// Resolve a conflict that `apply_changes` could not resolve
    /// automatically (per Decision 1 §Decision — admin intervention required
    /// for conflicting writes with identical metadata).
    async fn resolve_conflict(
        &self,
        conflict: ConflictRecord,
    ) -> Result<Resolution, ReplicationError>;

    /// Synchronise replication metadata with a partner (per Decision 1
    /// §Decision — `IDL_DRSReplicaSync` opnum 0x03 for DrSuapiReplicator;
    /// Raft snapshot transfer for RaftReplicator).
    async fn sync_metadata(&self, partner: &str) -> Result<(), ReplicationError>;
}

/// Resolve a conflict using AD's resolver (per Decision 1 §Decision).
///
/// Highest `version` wins; tiebreak by latest `last_write_timestamp`; then
/// highest `origin_usn`; then lexicographically-highest
/// `origin_invocation_id`.
pub fn resolve_conflict(local: &PropertyMetaDataExt, incoming: &PropertyMetaDataExt) -> Resolution {
    // TODO: implement per Decision 1 §Decision — verify byte-identical to
    // AD's resolver (per ADR-071).
    if incoming.version > local.version {
        return Resolution::IncomingWins;
    }
    if incoming.version < local.version {
        return Resolution::LocalWins;
    }
    if incoming.last_write_timestamp > local.last_write_timestamp {
        return Resolution::IncomingWins;
    }
    if incoming.last_write_timestamp < local.last_write_timestamp {
        return Resolution::LocalWins;
    }
    if incoming.origin_usn > local.origin_usn {
        return Resolution::IncomingWins;
    }
    if incoming.origin_usn < local.origin_usn {
        return Resolution::LocalWins;
    }
    if incoming.origin_invocation_id > local.origin_invocation_id {
        return Resolution::IncomingWins;
    }
    Resolution::LocalWins
}

// TODO: implement DrSuapiReplicator in adrian-drsuapi per Decision 1 (fresh Rust MS-DRSR via rasn).
// TODO: implement RaftReplicator in adrian-raft per Decision 1 (openraft integration).
// TODO: implement InMemoryReplicator in adrian-repl-testkit per Decision 1.
