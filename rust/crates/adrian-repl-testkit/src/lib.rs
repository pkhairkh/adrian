//! # adrian-repl-testkit
//!
//! In-memory [`Replicator`] implementation for unit tests in the Adrian
//! framework.
//!
//! Per Decision 1 §Decision, the testkit provides an in-memory `Replicator`
//! implementation (`InMemoryReplicator`) backed by a `Vec<ReplOperation>`,
//! for unit tests that don't need a real DRSUAPI/Raft backend.
//!
//! ## ADRs
//!
//! - ADR-071: Replication model (UTD vectors, conflict resolution)
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-repl-core`, `adrian-storage-core`. Consumed by every crate's
//! unit tests that need replication.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_repl_core::{
    ConflictRecord, NcHead, ReplOperation, ReplicationError, ReplicationPayload, Replicator,
    Resolution, UtdDelta, UtdVector,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

/// An in-memory `Replicator` for unit tests (per Decision 1 §Decision).
#[derive(Debug, Default)]
pub struct InMemoryReplicator {
    /// The replication log, keyed by NC head (per ADR-071).
    pub logs: RwLock<HashMap<NcHead, Vec<ReplOperation>>>,
    /// The UTD vectors, keyed by NC head (per ADR-071).
    pub utd_vectors: RwLock<HashMap<NcHead, UtdVector>>,
    /// The originating DSA's invocation ID (per Decision 1).
    pub invocation_id: uuid::Uuid,
}

impl InMemoryReplicator {
    /// Construct a new `InMemoryReplicator` with the given invocation ID.
    pub fn new(invocation_id: uuid::Uuid) -> Self {
        Self {
            logs: RwLock::new(HashMap::new()),
            utd_vectors: RwLock::new(HashMap::new()),
            invocation_id,
        }
    }
}

#[async_trait]
impl Replicator for InMemoryReplicator {
    async fn get_changes(
        &self,
        nc_head: NcHead,
        _cursor: &UtdVector,
    ) -> Result<ReplicationPayload, ReplicationError> {
        // TODO: implement per ADR-071 — return all operations from the log
        // starting at the cursor's highest USN.
        let logs = self.logs.read().unwrap();
        let ops = logs.get(&nc_head).cloned().unwrap_or_default();
        Ok(ReplicationPayload {
            nc_head,
            operations: ops,
            origin_invocation_id: self.invocation_id,
            highest_usn: 0,
        })
    }

    async fn apply_changes(
        &self,
        batch: ReplicationPayload,
    ) -> Result<Vec<Resolution>, ReplicationError> {
        // TODO: implement per ADR-071 — append batch.operations to
        // self.logs[batch.nc_head], applying conflict resolution per-value.
        let mut logs = self.logs.write().unwrap();
        let log = logs.entry(batch.nc_head).or_default();
        log.extend(batch.operations);
        Ok(vec![])
    }

    async fn update_utd_vector(
        &self,
        nc_head: NcHead,
        delta: UtdDelta,
    ) -> Result<(), ReplicationError> {
        // TODO: implement per ADR-071.
        let mut vectors = self.utd_vectors.write().unwrap();
        let vector = vectors.entry(nc_head).or_default();
        for entry in &mut vector.entries {
            if entry.invocation_id == delta.invocation_id {
                entry.highest_usn = delta.new_highest_usn;
                return Ok(());
            }
        }
        vector.entries.push(adrian_repl_core::UtdVectorEntry {
            invocation_id: delta.invocation_id,
            highest_usn: delta.new_highest_usn,
        });
        Ok(())
    }

    async fn resolve_conflict(
        &self,
        conflict: ConflictRecord,
    ) -> Result<Resolution, ReplicationError> {
        // TODO: implement per ADR-071 — use adrian_repl_core::resolve_conflict.
        Ok(adrian_repl_core::resolve_conflict(
            &conflict.local.1,
            &conflict.incoming.1,
        ))
    }

    async fn sync_metadata(&self, _partner: &str) -> Result<(), ReplicationError> {
        // No-op in the in-memory testkit.
        Ok(())
    }
}
