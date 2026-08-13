//! # adrian-raft
//!
//! openraft-based native replication for the Adrian framework.
//!
//! Per Workshop Decision 1 §Decision, native mode uses Raft consensus for
//! framework-only forests where AD wire-compatibility is not required. This
//! crate implements the [`Replicator`] trait from `adrian-repl-core` using
//! the [`openraft`](https://docs.rs/openraft) crate (Apache-2.0).
//!
//! The `RaftReplicator` SHALL replicate the entire directory as a single
//! Raft group in v1; per-NC sharding into multiple Raft groups is deferred
//! to v2 (per Decision 1 §Decision, gated by ORQ-024/025).
//!
//! ## ADRs
//!
//! - ADR-071: Replication model (UTD vectors, conflict resolution)
//! - ADR-076: FSMO role replacement (native mode eliminates all 5 FSMO
//!   roles)
//! - ADR-008: Declarative replication topology (YAML → RaftNetwork peer
//!   configuration)
//! - ADR-074: Tombstone lifetime and lingering objects
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-repl-core`, `adrian-storage-fdb`, `openraft`, `tokio`. NOT gated
//! by `ad-interop` — this is the native-mode replication path.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_repl_core::{
    ConflictRecord, NcHead, ReplicationError, ReplicationPayload, Replicator, Resolution, UtdDelta,
    UtdVector,
};
use async_trait::async_trait;

/// A Raft log entry payload (per Decision 1 §Decision — the
/// `RaftLogEntry` payload type carrying per-value linked-attribute deltas,
/// whole-attribute updates, and tombstones using the same internal
/// representation as `DrSuapiReplicator`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaftLogEntry {
    /// The originating DSA's invocation ID (per MS-ADTS §3.1.1.3.2.6).
    pub origin_invocation_id: uuid::Uuid,
    /// The originating USN (per MS-ADTS §3.1.1.3.2.5).
    pub origin_usn: u64,
    /// The replication operation (uses the same `ReplOperation` enum as
    /// `DrSuapiReplicator` so on-disk representation is identical across
    /// modes — per Decision 1 §Decision).
    pub operation: adrian_repl_core::ReplOperation,
}

/// openraft-based `Replicator` implementation (per Decision 1 §Decision).
///
/// Replicates the directory as a single Raft group in v1; per-NC sharding is
/// deferred to v2 (per Decision 1 §Decision). The Raft log is persisted in
/// FDB (per Decision 2 — the storage engine is the same; only the consensus
/// algorithm differs).
pub struct RaftReplicator {
    /// The DSA's invocation ID (per Decision 1).
    pub invocation_id: uuid::Uuid,
    /// The underlying FDB-backed directory store.
    pub store: adrian_storage_fdb::FdbDirectoryStore,
    /// The Raft cluster ID (per ADR-008 — declarative YAML topology).
    pub cluster_id: String,
}

impl RaftReplicator {
    /// Construct a new `RaftReplicator`.
    pub fn new(
        invocation_id: uuid::Uuid,
        store: adrian_storage_fdb::FdbDirectoryStore,
        cluster_id: impl Into<String>,
    ) -> Self {
        Self {
            invocation_id,
            store,
            cluster_id: cluster_id.into(),
        }
    }
}

#[async_trait]
impl Replicator for RaftReplicator {
    async fn get_changes(
        &self,
        _nc_head: NcHead,
        _cursor: &UtdVector,
    ) -> Result<ReplicationPayload, ReplicationError> {
        // TODO: implement per Decision 1 — Raft log tail starting at
        // cursor's highest USN. The Raft log is persisted in FDB subspace
        // 0x05 (UTD vector subspace, reused for the Raft log state machine).
        Err(ReplicationError::Backend(
            "RaftReplicator::get_changes not yet implemented".into(),
        ))
    }

    async fn apply_changes(
        &self,
        _batch: ReplicationPayload,
    ) -> Result<Vec<Resolution>, ReplicationError> {
        // TODO: implement per Decision 1 — apply Raft log entries in commit
        // order via the state machine; FDB's strict serializable
        // transactions make log-apply atomic (no replication-apply lock
        // needed, per Decision 1 §Cross-capability dependencies).
        Err(ReplicationError::Backend(
            "RaftReplicator::apply_changes not yet implemented".into(),
        ))
    }

    async fn update_utd_vector(
        &self,
        _nc_head: NcHead,
        _delta: UtdDelta,
    ) -> Result<(), ReplicationError> {
        // TODO: implement per ADR-071 — synthesise UTD vector from Raft log
        // commit index (per Decision 1 §Decision — UTD-vector synthesis).
        Err(ReplicationError::Backend(
            "RaftReplicator::update_utd_vector not yet implemented".into(),
        ))
    }

    async fn resolve_conflict(
        &self,
        _conflict: ConflictRecord,
    ) -> Result<Resolution, ReplicationError> {
        // TODO: implement per ADR-071 — in native mode, conflicts should
        // never occur because Raft serialises writes; if a conflict is
        // observed, it indicates a bug or a split-brain that requires admin
        // intervention.
        Err(ReplicationError::Permanent(
            "conflict resolution in native mode should never be needed — possible split-brain"
                .into(),
        ))
    }

    async fn sync_metadata(&self, _partner: &str) -> Result<(), ReplicationError> {
        // TODO: implement per Decision 1 — Raft snapshot transfer to a new
        // peer joining the cluster (per ADR-008 — declarative topology).
        Err(ReplicationError::Backend(
            "RaftReplicator::sync_metadata not yet implemented".into(),
        ))
    }
}

/// The Raft network transport (per openraft's `RaftNetwork` trait). Wraps a
/// `tokio::net::TcpStream` for peer-to-peer communication (per Decision 1
/// §Async runtime).
#[derive(Debug)]
pub struct RaftNetworkTransport {
    /// The local DSA's bind address (per ADR-008 — declarative topology).
    pub bind_addr: std::net::SocketAddr,
    /// The list of peer DSA addresses (per ADR-008).
    pub peers: Vec<std::net::SocketAddr>,
}

impl RaftNetworkTransport {
    /// Construct a new `RaftNetworkTransport`.
    pub fn new(bind_addr: std::net::SocketAddr, peers: Vec<std::net::SocketAddr>) -> Self {
        Self { bind_addr, peers }
    }
}

// TODO: implement openraft RaftLogStore / RaftStateMachine backed by FDB per Decision 1.
// TODO: implement openraft RaftNetwork over tokio::net::TcpStream per Decision 1.
// TODO: implement Raft snapshot transfer for new-peer join per ADR-008.
// TODO: implement UTD-vector synthesis from Raft commit index per ADR-071.
