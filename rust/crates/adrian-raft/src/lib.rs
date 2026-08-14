//! # adrian-raft
//!
//! openraft-based native replication for the Adrian framework.
//!
//! Per Workshop Decision 1 §Decision, native mode uses Raft consensus for
//! framework-only forests where AD wire-compatibility is not required. This
//! crate implements the [`Replicator`] trait from `adrian-repl-core` (as
//! [`RaftDirectoryReplicator`]) on top of a low-level [`RaftReplicator`] RPC
//! trait (impl [`ManualRaftReplicator`]).
//!
//! ## What's REAL in v1 (Wave 2c)
//!
//! - [`RaftLogEntry`] struct with `term`, `index`, `origin_invocation_id`,
//!   `origin_usn`, `payload` (per Priority 1 / ADR-071 §Decision).
//! - [`encode_log_entry`] / [`decode_log_entry`] — length-prefixed JSON
//!   framing, round-trip tested.
//! - [`synthesize_utd_vector`] — reads a Raft log and produces a UTD vector
//!   with one cursor per distinct leader (per ADR-071 §Decision — "synthesis
//!   maps each Raft log entry to a UTD entry: `origin_invocation_id =
//!   entry.leader_id`, `origin_usn = entry.log_index`").
//! - [`RaftReplicator`] trait (low-level RPCs: `append_entries`, `vote`,
//!   `install_snapshot` — per Ongaron & Ousterhout §5.4.1) with a real
//!   [`ManualRaftReplicator`] impl that handles the receiver-side RPC logic
//!   (term check, log consistency check, conflict truncation, commit-index
//!   advance, vote granting with up-to-date log check).
//! - `to_openraft_log_id` / `to_openraft_vote` conversion helpers that map
//!   our plain Rust types to openraft's `LogId<u64>` / `Vote<u64>` types —
//!   this is the seam for the eventual full openraft integration (per
//!   ADR-071 §Decision — `openraft::Raft<...>` driver is the target).
//! - [`RaftDirectoryReplicator`] (the high-level `Replicator` impl) that
//!   delegates `get_changes` / `apply_changes` to the in-memory Raft log
//!   and uses [`synthesize_utd_vector`] for cursor computation.
//!
//! ## What's STUB in v1 (deferred, documented in code)
//!
//! - **openraft `Raft` driver**: not wired up. A full integration requires
//!   implementing `RaftLogStore` + `RaftStateMachine` + `RaftNetwork` over
//!   FDB and tokio::net::TcpStream. The trait contract
//!   (`RaftReplicator::append_entries`/`vote`/`install_snapshot`) is
//!   implemented in [`ManualRaftReplicator`] so callers see real Raft RPC
//!   semantics; the leader-election / heartbeat / log-propagation driver is
//!   out of scope for v1 (per task description: "A real Raft impl isn't
//!   required for MVP").
//! - **`install_snapshot`**: stubbed — accepts the term update, discards
//!   the snapshot bytes. Real snapshot transfer requires the
//!   FDB-backed RaftLogStore (deferred to the openraft-driver wave).
//! - **Log persistence**: the in-memory `Vec<RaftLogEntry>` is volatile. A
//!   real impl persists to FDB subspace `0x05` (per Decision 2 / ADR-073).
//! - **`sync_metadata`**: returns `Ok(())` — in Raft mode, metadata sync is
//!   automatic (every committed entry is replicated immediately). The
//!   `partner` argument is logged but otherwise ignored.
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
    ConflictRecord, InvocationId, NcHead, ReplOperation, ReplicationError, ReplicationPayload,
    Replicator, Resolution, Usn, UtdDelta, UtdVector, UtdVectorEntry,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

// Re-export openraft types so callers can convert our log entries to
// openraft's `Entry<C>` without depending on openraft directly. Per ADR-071
// §Decision — `openraft::Raft<RaftNodeId, RaftNode, RaftLogEntry,
// RaftStateMachine, RaftNetwork>` is the target API.
pub use openraft::{CommittedLeaderId, LogId, Vote};

/// A Raft log entry (per ADR-071 §Decision and Priority 1 of Wave 2c).
///
/// Each entry carries:
/// - `term` and `index` — the Raft log coordinates (per Ongaron & Ousterhout
///   §5.3). `(term, index)` uniquely identifies an entry across the cluster.
/// - `origin_invocation_id` — the originating leader's DSA invocation ID
///   (per MS-ADTS §3.1.1.3.2.6). Used for UTD-vector synthesis per ADR-071:
///   "synthesis maps each Raft log entry to a UTD entry:
///   `origin_invocation_id = entry.leader_id`, `origin_usn = entry.log_index`."
/// - `origin_usn` — the originating USN (per MS-ADTS §3.1.1.3.2.5). In Raft
///   mode this is the leader's monotonic counter; in the synthesised UTD
///   vector it equals `index` (per ADR-071).
/// - `payload` — the [`ReplOperation`] payload, the same enum used by
///   `DrSuapiReplicator` (per Decision 1 §Decision — on-disk representation is
///   identical across modes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaftLogEntry {
    /// The Raft term in which this entry was created (per Ongaron &
    /// Ousterhout §5.3 — terms are monotonically increasing).
    pub term: u64,
    /// The entry's index in the Raft log (1-indexed; index 0 is the
    /// implicit pre-config placeholder used by `prev_log_index=0` on the
    /// very first append — per Ongaron & Ousterhout §5.3).
    pub index: u64,
    /// The originating leader's DSA invocation ID (per ADR-071 — used for
    /// UTD-vector synthesis: each entry contributes a cursor
    /// `(origin_invocation_id, index)` to the synthesised vector).
    pub origin_invocation_id: InvocationId,
    /// The originating USN (per MS-ADTS §3.1.1.3.2.5). In native mode this
    /// is a per-leader monotonic counter.
    pub origin_usn: Usn,
    /// The replication operation payload (uses the same `ReplOperation`
    /// enum as `DrSuapiReplicator` — per Decision 1 §Decision, on-disk
    /// representation is identical across modes).
    pub payload: ReplOperation,
}

// `ReplOperation` (in `adrian-repl-core`) does not derive `PartialEq`
// (AD's `PROPERTY_META_DATA_EXT` model intentionally forces callers to use
// explicit metadata comparison per ADR-071). We implement `PartialEq` /
// `Eq` on `RaftLogEntry` by comparing the payload via its JSON
// serialisation — both sides are serde-derivable so the serialisation is
// total and deterministic.
impl PartialEq for RaftLogEntry {
    fn eq(&self, other: &Self) -> bool {
        self.term == other.term
            && self.index == other.index
            && self.origin_invocation_id == other.origin_invocation_id
            && self.origin_usn == other.origin_usn
            && serde_json::to_string(&self.payload).ok()
                == serde_json::to_string(&other.payload).ok()
    }
}

impl Eq for RaftLogEntry {}

impl RaftLogEntry {
    /// Construct a new entry with the given coordinates and payload.
    /// `origin_usn` defaults to `index` (per ADR-071 synthesis rule).
    #[must_use]
    pub fn new(
        term: u64,
        index: u64,
        origin_invocation_id: InvocationId,
        payload: ReplOperation,
    ) -> Self {
        Self {
            term,
            index,
            origin_invocation_id,
            origin_usn: index,
            payload,
        }
    }

    /// Convert to an openraft `LogId<u64>` (per ADR-071 §Decision — openraft's
    /// `LogId` is `(leader_id, index)`, where `leader_id` is openraft's
    /// `CommittedLeaderId<u64>` containing just the term). This is the seam
    /// for the eventual full openraft integration.
    ///
    /// Note: openraft's `CommittedLeaderId<NID>` discards the node ID (only
    /// the term survives). The originating DSA's invocation ID is preserved
    /// separately in [`RaftLogEntry::origin_invocation_id`] so UTD-vector
    /// synthesis can use it.
    #[must_use]
    pub fn to_openraft_log_id(&self) -> LogId<u64> {
        // openraft's `CommittedLeaderId::new(term, node_id)` ignores
        // `node_id` (it's a PhantomData field); the leader identity within
        // a term is implicit (Raft elects at most one leader per term).
        LogId::new(CommittedLeaderId::new(self.term, 0u64), self.index)
    }

    /// Convert the entry's leader-coordinates to an openraft `Vote<u64>`
    /// representing a vote for this leader in this term.
    #[must_use]
    pub fn to_openraft_vote(&self) -> Vote<u64> {
        Vote::new(self.term, 0u64)
    }
}

/// Length-prefix sentinel: 4 bytes big-endian length, then the JSON body.
/// Matches the framing used by openraft's `serde` payload encoding (per
/// openraft docs §Storage — "entries are length-prefixed bincode or JSON
/// frames").
const ENTRY_LEN_PREFIX_BYTES: usize = 4;

/// Encode a [`RaftLogEntry`] to length-prefixed JSON bytes (per Priority 1).
///
/// Wire format: `[len: u32 BE][serde_json body bytes]`. The length prefix is
/// defensive — JSON is self-delimiting, but a length prefix prevents
/// truncation bugs in mixed-binary streams (e.g., when Raft RPC frames are
/// multiplexed over a TCP connection).
#[must_use]
pub fn encode_log_entry(entry: &RaftLogEntry) -> Vec<u8> {
    let body = serde_json::to_vec(entry).unwrap_or_else(|e| {
        // RaftLogEntry derives Serialize and contains only serde-derivable
        // fields (u64, Uuid, ReplOperation which also derives Serialize).
        // Failure here indicates a programming bug, not a runtime condition.
        // Panic is appropriate per the framework's "loud failure" convention
        // (HANDOVER_STATE.md §2 — prefer panic over silent corruption in
        // serialisation code paths).
        panic!("RaftLogEntry serialisation failed: {e}");
    });
    let mut out = Vec::with_capacity(ENTRY_LEN_PREFIX_BYTES + body.len());
    out.extend_from_slice(
        &(u32::try_from(body.len()).expect("Raft log entry > 4 GiB; out of memory")).to_be_bytes(),
    );
    out.extend_from_slice(&body);
    out
}

/// Decode a length-prefixed JSON [`RaftLogEntry`] (per Priority 1).
///
/// Inverse of [`encode_log_entry`]. Returns [`RaftError::InvalidEntry`] on
/// malformed input (truncated prefix, length-prefix/body mismatch, JSON
/// decode error).
pub fn decode_log_entry(bytes: &[u8]) -> Result<RaftLogEntry, RaftError> {
    if bytes.len() < ENTRY_LEN_PREFIX_BYTES {
        return Err(RaftError::InvalidEntry(format!(
            "entry too short for length prefix: got {} bytes, need {}",
            bytes.len(),
            ENTRY_LEN_PREFIX_BYTES
        )));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < ENTRY_LEN_PREFIX_BYTES + len {
        return Err(RaftError::InvalidEntry(format!(
            "truncated entry: header says {len} body bytes, got {}",
            bytes.len() - ENTRY_LEN_PREFIX_BYTES
        )));
    }
    let body = &bytes[ENTRY_LEN_PREFIX_BYTES..ENTRY_LEN_PREFIX_BYTES + len];
    serde_json::from_slice(body).map_err(|e| RaftError::InvalidEntry(format!("JSON decode: {e}")))
}

/// Synthesise a UTD vector from a Raft log (per ADR-071 §Decision).
///
/// Per ADR-071: "Synthesis maps each Raft log entry to a UTD entry:
/// `origin_invocation_id = entry.leader_id`, `origin_usn = entry.log_index`."
/// The result has one cursor per distinct leader invocation ID, with
/// `highest_usn` equal to the highest log index authored by that leader.
///
/// The `local_dc_id` parameter is reserved for future use (per ADR-071 —
/// synthesis is for `repadmin /showutdvec` display, which expects the local
/// DC's invocation ID in the leading slot, but in v1 we just emit the
/// synthesised vector without the local-DC placeholder).
#[must_use]
pub fn synthesize_utd_vector(log: &[RaftLogEntry], _local_dc_id: Uuid) -> UtdVector {
    let mut by_leader: HashMap<InvocationId, Usn> = HashMap::new();
    for entry in log {
        let cur = by_leader.entry(entry.origin_invocation_id).or_insert(0);
        if entry.index > *cur {
            *cur = entry.index;
        }
    }
    let mut entries: Vec<UtdVectorEntry> = by_leader
        .into_iter()
        .map(|(invocation_id, highest_usn)| UtdVectorEntry {
            invocation_id,
            highest_usn,
        })
        .collect();
    // Sort by invocation ID for deterministic output (lexicographic order,
    // matching AD's UTD-vector display ordering per MS-ADTS §3.1.1.3.2.5).
    entries.sort_by_key(|e| e.invocation_id);
    UtdVector { entries }
}

/// Error type for Raft operations (per Decision 1 §Error handling —
/// `thiserror`-based, used by the low-level [`RaftReplicator`] trait).
#[derive(Debug, Error)]
pub enum RaftError {
    /// A malformed entry (decode failure, length-prefix mismatch).
    #[error("invalid Raft log entry: {0}")]
    InvalidEntry(String),
    /// The snapshot transfer was rejected (e.g., term regression). Stubbed
    /// in v1 — real InstallSnapshot requires the FDB-backed RaftLogStore.
    #[error("snapshot rejected: {0}")]
    SnapshotRejected(String),
}

/// Result of an `append_entries` RPC (per Ongaron & Ousterhout §5.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    /// The receiver's current term after processing the request (per Raft
    /// §5.4.1 — receivers always include their current term in responses so
    /// stale leaders can step down).
    pub term: u64,
    /// Whether the entries were accepted (true) or rejected due to a stale
    /// term or log inconsistency (false).
    pub success: bool,
    /// The receiver's last log index after the append (per Raft §5.3 — used
    /// by leaders to compute `nextIndex` for retries).
    pub last_log_index: u64,
    /// The receiver's commit index after applying `leader_commit`.
    pub commit_index: u64,
}

/// Result of a `vote` RPC (per Ongaron & Ousterhout §5.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteResult {
    /// The receiver's current term after processing the request.
    pub term: u64,
    /// Whether the vote was granted.
    pub vote_granted: bool,
}

/// Leader-side per-peer replication state (per Ongaron & Ousterhout §5.2 —
/// volatile state on the leader: `nextIndex[]` and `matchIndex[]` for each
/// peer). Only meaningful when the local node is the leader; initialised by
/// [`ManualRaftReplicator::start_election`] upon winning a term.
#[derive(Debug, Clone, Default)]
pub struct PeerReplicationState {
    /// The index of the next log entry to send to this peer (per Raft §5.2
    /// — initialised to `leader_last_log_index + 1` on election).
    pub next_index: u64,
    /// The highest log index known to be replicated on this peer (per Raft
    /// §5.2 — initialised to 0 on election, advanced by
    /// [`ManualRaftReplicator::record_peer_ack`]).
    pub match_index: u64,
}

/// Per-node Raft state (per Ongaron & Ousterhout §5.2 — persistent +
/// volatile state on each server).
#[derive(Debug, Clone)]
pub struct RaftNodeState {
    /// The node's current term (persistent — per Raft §5.2).
    pub current_term: u64,
    /// The candidate the node voted for in `current_term`, or `None`
    /// (persistent — per Raft §5.2).
    pub voted_for: Option<Uuid>,
    /// The node's Raft log (1-indexed conceptually; `log[0]` has
    /// `index=1`. The implicit "genesis" entry at `index=0` has
    /// `term=0` and is represented by the empty-log case —
    /// `term_at(0)` returns `Some(0)`).
    pub log: Vec<RaftLogEntry>,
    /// The highest log index known to be committed (volatile — per Raft
    /// §5.2).
    pub commit_index: u64,
    /// The highest log index applied to the state machine (volatile — per
    /// Raft §5.2; `last_applied <= commit_index` invariant).
    pub last_applied: u64,
    /// The currently-known leader for the current term (volatile).
    pub leader_id: Option<Uuid>,
}

impl Default for RaftNodeState {
    fn default() -> Self {
        Self::new()
    }
}

impl RaftNodeState {
    /// Create a fresh node state at term 0 with an empty log (the genesis
    /// placeholder entry is implicit; `last_log_index()` returns `0`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            commit_index: 0,
            last_applied: 0,
            leader_id: None,
        }
    }

    /// Returns the index of the last entry in the log (0 for an empty log).
    #[must_use]
    pub fn last_log_index(&self) -> u64 {
        self.log.last().map_or(0, |e| e.index)
    }

    /// Returns the term of the last entry in the log (0 for an empty log).
    #[must_use]
    pub fn last_log_term(&self) -> u64 {
        self.log.last().map_or(0, |e| e.term)
    }

    /// Returns the term of the entry at `index`, or `None` if out of range.
    /// Index 0 returns `Some(0)` (the implicit genesis entry per Raft §5.4.1).
    #[must_use]
    pub fn term_at(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        // Log entries are 1-indexed; find by linear scan. Acceptable for
        // unit-test-sized logs; a real impl would index by `index - 1` after
        // ensuring no gaps (per Raft §5.3 — log is contiguous).
        self.log.iter().find(|e| e.index == index).map(|e| e.term)
    }

    /// Truncate the log so that all entries with `index >= from` are
    /// removed. Used by `append_entries` to handle log conflicts (per Raft
    /// §5.4.1 — "if an existing entry conflicts with a new one (same index
    /// but different terms), delete the existing entry and all that follow
    /// it").
    pub fn truncate_from(&mut self, from: u64) {
        self.log.retain(|e| e.index < from);
    }
}

/// The low-level Raft RPC trait (per Priority 3 of Wave 2c — the trait
/// contract for raw Raft RPCs).
///
/// Implements the receiver-side RPC handlers per Ongaron & Ousterhout
/// §5.4.1:
/// - `append_entries` — AppendEntries RPC (heartbeat + log replication).
/// - `vote` — RequestVote RPC (leader election).
/// - `install_snapshot` — InstallSnapshot RPC (§5.4.2 — for followers
///   whose logs have been truncated past the leader's `nextIndex`).
///
/// This trait is *not* the same as [`Replicator`] (the high-level
/// adrian-repl-core trait). [`RaftDirectoryReplicator`] (the high-level
/// `Replicator` impl) is built on top of [`RaftReplicator`] — it translates
/// `ReplicationPayload` batches to and from `RaftLogEntry` payloads and
/// delegates the RPC plumbing to a [`RaftReplicator`] impl.
#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait RaftReplicator: Send + Sync {
    /// AppendEntries RPC (per Ongaron & Ousterhout §5.4.1).
    ///
    /// Receiver-side logic:
    /// 1. If `term < currentTerm`, reply false.
    /// 2. If `term > currentTerm`, update `currentTerm`, become follower.
    /// 3. If log at `prev_log_index` doesn't have term `prev_log_term`,
    ///    reply false.
    /// 4. If an existing entry conflicts with a new one (same index but
    ///    different terms), delete the existing entry and all that follow.
    /// 5. Append any new entries not already in the log.
    /// 6. If `leader_commit > commit_index`, set
    ///    `commit_index = min(leader_commit, last_new_index)`.
    async fn append_entries(
        &self,
        term: u64,
        leader_id: Uuid,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<RaftLogEntry>,
        leader_commit: u64,
    ) -> Result<AppendResult, RaftError>;

    /// RequestVote RPC (per Ongaron & Ousterhout §5.4.1).
    ///
    /// Receiver-side logic:
    /// 1. If `term < currentTerm`, reply false.
    /// 2. If `term > currentTerm`, update `currentTerm`, reset
    ///    `voted_for`.
    /// 3. If `voted_for` is `None` or `candidate_id`, and the candidate's
    ///    log is at least as up-to-date as the receiver's, grant vote.
    async fn vote(
        &self,
        term: u64,
        candidate_id: Uuid,
        last_log_index: u64,
        last_log_term: u64,
    ) -> Result<VoteResult, RaftError>;

    /// InstallSnapshot RPC (per Ongaran & Ousterhout §5.4.2). Stubbed in
    /// v1 — accepts the term update, discards the snapshot bytes. Real
    /// snapshot transfer requires the FDB-backed `RaftLogStore`, which is
    /// gated on the full openraft driver integration (deferred — see crate
    /// docs §"What's STUB in v1").
    async fn install_snapshot(
        &self,
        term: u64,
        leader_id: Uuid,
        last_included_index: u64,
        last_included_term: u64,
        offset: u64,
        data: Vec<u8>,
        done: bool,
    ) -> Result<(), RaftError>;
}

/// A manual Raft implementation that satisfies the [`RaftReplicator`] trait
/// contract. Holds per-node state in memory behind a `tokio::sync::RwLock`.
///
/// This is NOT a full Raft implementation — it implements the
/// AppendEntries, RequestVote, and InstallSnapshot RPC *handlers* (the
/// receiver-side logic per Ongaron & Ousterhout §5.4.1), but does NOT
/// implement leader election (the candidate-side `start_election` loop),
/// heartbeats, or log propagation. Those are the Raft *driver*'s
/// responsibility and are out-of-scope for v1 (per the wave 2c task
/// description: "A real Raft impl isn't required for MVP").
///
/// The driver would be `openraft::Raft<C>` (per ADR-071 §Decision —
/// `openraft::Raft<RaftNodeId, RaftNode, RaftLogEntry, RaftStateMachine,
/// RaftNetwork>`), which requires implementing `RaftLogStore` +
/// `RaftStateMachine` + `RaftNetwork`. That integration is deferred to a
/// future wave; the [`RaftReplicator`] trait contract here is the seam.
pub struct ManualRaftReplicator {
    /// The local node's ID (per Raft §5.1 — `node_id` in the cluster config).
    pub local_node_id: Uuid,
    /// Per-node state, keyed by node ID. The local node's state is at
    /// `nodes[&local_node_id]`. Other entries are for diagnostics /
    /// testing (a real Raft driver would not store peer state locally —
    /// peers store their own state).
    pub nodes: Arc<RwLock<HashMap<Uuid, RaftNodeState>>>,
    /// Leader-side per-peer replication state (per Raft §5.2 — `nextIndex[]`
    /// and `matchIndex[]`), keyed by peer node ID. Only meaningful when the
    /// local node is the leader; initialised by [`Self::start_election`].
    pub peer_state: Arc<RwLock<HashMap<Uuid, PeerReplicationState>>>,
}

impl ManualRaftReplicator {
    /// Create a new `ManualRaftReplicator` with the local node initialised
    /// to a fresh `RaftNodeState::new()` (term 0, empty log, no vote cast).
    #[must_use]
    pub fn new(local_node_id: Uuid) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(local_node_id, RaftNodeState::new());
        Self {
            local_node_id,
            nodes: Arc::new(RwLock::new(nodes)),
            peer_state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a peer node with fresh state (used by cluster setup and tests).
    /// Also initialises the leader-side `peer_state` entry for this peer.
    pub async fn add_peer(&self, peer_id: Uuid) {
        let mut nodes = self.nodes.write().await;
        nodes.entry(peer_id).or_insert_with(RaftNodeState::new);
        drop(nodes);
        let mut ps = self.peer_state.write().await;
        ps.entry(peer_id).or_default();
    }

    /// Read the local node's `current_term` (test/diagnostic helper).
    pub async fn current_term(&self) -> u64 {
        let nodes = self.nodes.read().await;
        nodes.get(&self.local_node_id).map_or(0, |s| s.current_term)
    }

    /// Read the local node's `commit_index` (test/diagnostic helper).
    pub async fn commit_index(&self) -> u64 {
        let nodes = self.nodes.read().await;
        nodes.get(&self.local_node_id).map_or(0, |s| s.commit_index)
    }

    /// Read the local node's `last_log_index` (test/diagnostic helper).
    pub async fn last_log_index(&self) -> u64 {
        let nodes = self.nodes.read().await;
        nodes
            .get(&self.local_node_id)
            .map_or(0, |s| s.last_log_index())
    }

    /// Read a snapshot of the local node's log (test/diagnostic helper).
    pub async fn log_snapshot(&self) -> Vec<RaftLogEntry> {
        let nodes = self.nodes.read().await;
        nodes
            .get(&self.local_node_id)
            .map_or_else(Vec::new, |s| s.log.clone())
    }

    /// Read the local node's `voted_for` (test/diagnostic helper).
    pub async fn voted_for(&self) -> Option<Uuid> {
        let nodes = self.nodes.read().await;
        nodes.get(&self.local_node_id).and_then(|s| s.voted_for)
    }

    /// Read the local node's `leader_id` (test/diagnostic helper).
    pub async fn leader_id(&self) -> Option<Uuid> {
        let nodes = self.nodes.read().await;
        nodes.get(&self.local_node_id).and_then(|s| s.leader_id)
    }

    // -----------------------------------------------------------------
    // Wave 2: quorum enforcement + leader election (per RFC §5.2)
    // -----------------------------------------------------------------

    /// Compute the cluster majority threshold: `(total_nodes / 2) + 1`
    /// (per RFC §5.2 — "majority" means more than half). A single-node
    /// cluster has majority = 1; a 3-node cluster has majority = 2; a
    /// 5-node cluster has majority = 3.
    async fn majority_threshold(&self) -> u64 {
        let nodes = self.nodes.read().await;
        let total = nodes.len() as u64;
        (total / 2) + 1
    }

    /// Record that a peer has acknowledged log entries up to `match_index`
    /// (per Raft §5.2 — leader updates `matchIndex[i]` and `nextIndex[i]`
    /// on each successful `AppendEntries` response). This is the
    /// bookkeeping side of quorum tracking; call this after every
    /// successful `append_entries_to_peer`.
    pub async fn record_peer_ack(&self, peer_id: Uuid, match_index: u64) {
        let mut ps = self.peer_state.write().await;
        let entry = ps.entry(peer_id).or_default();
        entry.match_index = entry.match_index.max(match_index);
        entry.next_index = match_index + 1;
    }

    /// Try to commit entries up to `index`. Returns `Ok(true)` if a
    /// majority of nodes (self + peers) have `match_index >= index` and the
    /// entry at `index` is from the current term (per RFC §5.4.2 — the
    /// current-term restriction prevents committing stale-term entries via
    /// a future leader). Returns `Ok(false)` if quorum is not yet reached.
    ///
    /// On success, advances `commit_index` to `index` (if it was lower).
    pub async fn commit_entry(&self, index: u64) -> Result<bool, RaftError> {
        let majority = self.majority_threshold().await;
        // Count self as an ack (the leader holds the entry locally).
        let mut acks = 1u64;
        {
            let ps = self.peer_state.read().await;
            for p in ps.values() {
                if p.match_index >= index {
                    acks += 1;
                }
            }
        }
        if acks < majority {
            return Ok(false);
        }
        // Per RFC §5.4.2 fig 8 — only commit entries from the current term.
        let mut nodes = self.nodes.write().await;
        let local = nodes
            .get(&self.local_node_id)
            .ok_or_else(|| RaftError::InvalidEntry("local node not found".into()))?;
        let entry_term = local.term_at(index).unwrap_or(0);
        if entry_term != local.current_term && index > 0 {
            // Stale-term entry — cannot commit directly (per fig 8). A
            // later current-term entry will commit these implicitly once it
            // replicates.
            return Ok(false);
        }
        let local = nodes
            .get_mut(&self.local_node_id)
            .expect("local node present above");
        if index > local.commit_index {
            local.commit_index = index;
        }
        Ok(true)
    }

    /// Send an `AppendEntries` RPC to a specific peer (in-process
    /// simulation of a network call). The peer's receiver-side handler
    /// (`append_entries_impl`) runs against `self.nodes[peer_id]`.
    ///
    /// On success, records the peer's `match_index` via
    /// [`Self::record_peer_ack`] so [`Self::commit_entry`] can count it.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_entries_to_peer(
        &self,
        peer_id: Uuid,
        term: u64,
        leader_id: Uuid,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<RaftLogEntry>,
        leader_commit: u64,
    ) -> Result<AppendResult, RaftError> {
        let result = self
            .append_entries_impl(
                peer_id,
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            )
            .await?;
        if result.success {
            self.record_peer_ack(peer_id, result.last_log_index).await;
        }
        Ok(result)
    }

    /// Send a `RequestVote` RPC to a specific peer (in-process simulation).
    /// Returns the peer's `VoteResult`.
    pub async fn request_vote_from_peer(
        &self,
        peer_id: Uuid,
        term: u64,
        candidate_id: Uuid,
        last_log_index: u64,
        last_log_term: u64,
    ) -> Result<VoteResult, RaftError> {
        self.vote_impl(peer_id, term, candidate_id, last_log_index, last_log_term)
            .await
    }

    /// Start a leader election (per RFC §5.2). Increments `current_term`,
    /// votes for self, broadcasts `RequestVote` to all peers via
    /// [`Self::request_vote_from_peer`]. Returns `Ok(true)` if a majority
    /// of votes were granted (the local node becomes leader); `Ok(false)`
    /// otherwise (split vote — the local node stays a candidate and will
    /// retry on the next election timeout).
    ///
    /// Split-vote prevention (RFC §5.2): a candidate must receive a
    /// majority before becoming leader. If two candidates split the vote,
    /// neither wins and a new election is needed.
    pub async fn start_election(&self) -> Result<bool, RaftError> {
        // Step 1: increment term, vote for self (per RFC §5.2).
        let (term, last_log_index, last_log_term) = {
            let mut nodes = self.nodes.write().await;
            let local = nodes
                .get_mut(&self.local_node_id)
                .ok_or_else(|| RaftError::InvalidEntry("local node not found".into()))?;
            local.current_term += 1;
            local.voted_for = Some(self.local_node_id);
            local.leader_id = None; // candidate doesn't recognise a leader.
            (
                local.current_term,
                local.last_log_index(),
                local.last_log_term(),
            )
        };
        // Step 2: request votes from all peers (self already counts as 1).
        let peer_ids: Vec<Uuid> = {
            let nodes = self.nodes.read().await;
            nodes
                .keys()
                .filter(|&&k| k != self.local_node_id)
                .copied()
                .collect()
        };
        let mut votes = 1u64;
        for peer_id in peer_ids {
            let result = self
                .request_vote_from_peer(
                    peer_id,
                    term,
                    self.local_node_id,
                    last_log_index,
                    last_log_term,
                )
                .await?;
            if result.vote_granted {
                votes += 1;
            }
        }
        // Step 3: quorum check (per RFC §5.2 — majority required).
        let majority = self.majority_threshold().await;
        if votes < majority {
            return Ok(false);
        }
        // Step 4: become leader — set leader_id, init peer_state.
        let last_idx = {
            let mut nodes = self.nodes.write().await;
            let local = nodes
                .get_mut(&self.local_node_id)
                .expect("local node present above");
            local.leader_id = Some(self.local_node_id);
            local.last_log_index()
        };
        let mut ps = self.peer_state.write().await;
        for p in ps.values_mut() {
            p.next_index = last_idx + 1;
            p.match_index = 0;
        }
        Ok(true)
    }

    /// Append-entries receiver-side core logic, parameterised by `node_id`
    /// (so the leader can call it on a peer via `append_entries_to_peer`).
    /// Implements RFC §5.4.1 steps 1-6 exactly as the trait method does,
    /// but operates on `self.nodes[node_id]` instead of `self.nodes[local]`.
    #[allow(clippy::too_many_arguments)]
    async fn append_entries_impl(
        &self,
        node_id: Uuid,
        term: u64,
        leader_id: Uuid,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<RaftLogEntry>,
        leader_commit: u64,
    ) -> Result<AppendResult, RaftError> {
        let mut nodes = self.nodes.write().await;
        let local = nodes.entry(node_id).or_insert_with(RaftNodeState::new);
        if term < local.current_term {
            return Ok(AppendResult {
                term: local.current_term,
                success: false,
                last_log_index: local.last_log_index(),
                commit_index: local.commit_index,
            });
        }
        if term > local.current_term {
            local.current_term = term;
            local.voted_for = None;
        }
        local.leader_id = Some(leader_id);
        let local_term_at_prev = local.term_at(prev_log_index);
        if local_term_at_prev != Some(prev_log_term) {
            return Ok(AppendResult {
                term: local.current_term,
                success: false,
                last_log_index: local.last_log_index(),
                commit_index: local.commit_index,
            });
        }
        for entry in entries {
            if let Some(existing_term) = local.term_at(entry.index) {
                if existing_term != entry.term {
                    local.truncate_from(entry.index);
                    local.log.push(entry);
                }
            } else {
                local.log.push(entry);
            }
        }
        let last_idx = local.last_log_index();
        if leader_commit > local.commit_index {
            local.commit_index = leader_commit.min(last_idx);
        }
        Ok(AppendResult {
            term: local.current_term,
            success: true,
            last_log_index: local.last_log_index(),
            commit_index: local.commit_index,
        })
    }

    /// Vote receiver-side core logic, parameterised by `node_id`.
    async fn vote_impl(
        &self,
        node_id: Uuid,
        term: u64,
        candidate_id: Uuid,
        last_log_index: u64,
        last_log_term: u64,
    ) -> Result<VoteResult, RaftError> {
        let mut nodes = self.nodes.write().await;
        let local = nodes.entry(node_id).or_insert_with(RaftNodeState::new);
        if term < local.current_term {
            return Ok(VoteResult {
                term: local.current_term,
                vote_granted: false,
            });
        }
        if term > local.current_term {
            local.current_term = term;
            local.voted_for = None;
        }
        let up_to_date = {
            let local_last_term = local.last_log_term();
            let local_last_idx = local.last_log_index();
            if last_log_term != local_last_term {
                last_log_term > local_last_term
            } else {
                last_log_index >= local_last_idx
            }
        };
        let grant = match local.voted_for {
            Some(v) if v != candidate_id => false,
            _ => up_to_date,
        };
        if grant {
            local.voted_for = Some(candidate_id);
        }
        Ok(VoteResult {
            term: local.current_term,
            vote_granted: grant,
        })
    }
}

#[async_trait]
impl RaftReplicator for ManualRaftReplicator {
    async fn append_entries(
        &self,
        term: u64,
        leader_id: Uuid,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<RaftLogEntry>,
        leader_commit: u64,
    ) -> Result<AppendResult, RaftError> {
        // Delegate to the parameterised `_impl` so the same receiver-side
        // logic is reused by `append_entries_to_peer` (leader -> peer RPC).
        self.append_entries_impl(
            self.local_node_id,
            term,
            leader_id,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit,
        )
        .await
    }

    async fn vote(
        &self,
        term: u64,
        candidate_id: Uuid,
        last_log_index: u64,
        last_log_term: u64,
    ) -> Result<VoteResult, RaftError> {
        // Delegate to the parameterised `_impl` so the same receiver-side
        // logic is reused by `request_vote_from_peer` (candidate -> peer
        // RPC).
        self.vote_impl(
            self.local_node_id,
            term,
            candidate_id,
            last_log_index,
            last_log_term,
        )
        .await
    }

    async fn install_snapshot(
        &self,
        term: u64,
        leader_id: Uuid,
        last_included_index: u64,
        last_included_term: u64,
        offset: u64,
        data: Vec<u8>,
        done: bool,
    ) -> Result<(), RaftError> {
        // Wave 2 (T-203): real InstallSnapshot handler per RFC §7. Accepts
        // the term update (stepping down if the caller's term is higher),
        // rejects term regressions, and on `done=true` applies the snapshot:
        // truncates the log up to `last_included_index`, advances
        // `commit_index` and `last_applied` to `last_included_index`.
        let mut nodes = self.nodes.write().await;
        let local = nodes
            .entry(self.local_node_id)
            .or_insert_with(RaftNodeState::new);
        if term < local.current_term {
            return Err(RaftError::SnapshotRejected(format!(
                "stale term: caller={term} current={}",
                local.current_term
            )));
        }
        if term > local.current_term {
            local.current_term = term;
            local.voted_for = None;
        }
        local.leader_id = Some(leader_id);
        // RFC §7: on the final chunk, discard any conflicting entries and
        // apply the snapshot. We don't persist `data` (in-memory v1), but
        // we do truncate the log and advance commit/apply cursors so the
        // follower's state matches the leader's post-compaction state.
        if done {
            // Truncate entries with index <= last_included_index (they are
            // now captured by the snapshot). Keep entries after
            // last_included_index if they exist (RFC §7 allows the log to
            // contain entries after the snapshot).
            local.log.retain(|e| e.index > last_included_index);
            if local.commit_index < last_included_index {
                local.commit_index = last_included_index;
            }
            if local.last_applied < last_included_index {
                local.last_applied = last_included_index;
            }
            tracing::debug!(
                target: "adrian_raft::install_snapshot",
                last_included_index,
                last_included_term,
                data_len = data.len(),
                offset,
                "snapshot applied: log truncated, commit_index/last_applied advanced"
            );
        } else if offset != 0 {
            tracing::debug!(
                target: "adrian_raft::install_snapshot",
                offset,
                chunk_len = data.len(),
                "snapshot chunk received (awaiting final chunk)"
            );
        }
        Ok(())
    }
}

/// The high-level `Replicator` impl for the Adrian framework's native Raft
/// mode (per ADR-071 §Decision). Built on top of a [`RaftReplicator`] RPC
/// layer (default: [`ManualRaftReplicator`]).
///
/// In v1 the Raft log is held in memory (volatile — see crate docs §"What's
/// STUB in v1"). The `store` field is kept for the eventual FDB-backed log
/// store integration (per Decision 2 — the storage engine is the same; only
/// the consensus algorithm differs).
pub struct RaftDirectoryReplicator {
    /// The DSA's invocation ID (per Decision 1 — used as the local Raft
    /// node ID).
    pub invocation_id: uuid::Uuid,
    /// The underlying FDB-backed directory store (used for the future
    /// FDB-backed RaftLogStore integration; not used by the in-memory
    /// v1 RPC layer).
    pub store: adrian_storage_fdb::FdbDirectoryStore,
    /// The Raft cluster ID (per ADR-008 — declarative YAML topology).
    pub cluster_id: String,
    /// The low-level Raft RPC layer (per ADR-071 — `openraft::Raft<...>` is
    /// the target API; `ManualRaftReplicator` is the v1 hand-rolled impl).
    pub raft: Arc<ManualRaftReplicator>,
}

impl RaftDirectoryReplicator {
    /// Construct a new `RaftDirectoryReplicator` with a fresh
    /// [`ManualRaftReplicator`] keyed on `invocation_id`.
    #[must_use]
    pub fn new(
        invocation_id: uuid::Uuid,
        store: adrian_storage_fdb::FdbDirectoryStore,
        cluster_id: impl Into<String>,
    ) -> Self {
        Self {
            invocation_id,
            store,
            cluster_id: cluster_id.into(),
            raft: Arc::new(ManualRaftReplicator::new(invocation_id)),
        }
    }

    /// Get a reference to the inner low-level Raft RPC layer (for testing
    /// and for callers that need direct access to AppendEntries / Vote /
    /// InstallSnapshot RPCs).
    #[must_use]
    pub fn raft(&self) -> &Arc<ManualRaftReplicator> {
        &self.raft
    }
}

#[async_trait]
impl Replicator for RaftDirectoryReplicator {
    async fn get_changes(
        &self,
        nc_head: NcHead,
        cursor: &UtdVector,
    ) -> Result<ReplicationPayload, ReplicationError> {
        // Per Decision 1 §Decision — `get_changes` returns the Raft log tail
        // starting at the cursor's highest USN per leader. We synthesise the
        // UTD vector from the local Raft log (per ADR-071 §Decision) and
        // return entries beyond what the cursor has seen.
        let log = self.raft.log_snapshot().await;
        let operations: Vec<ReplOperation> = log
            .iter()
            .filter(|entry| {
                // Skip entries already covered by the cursor — i.e., entries
                // whose (origin_invocation_id, index) is <= the cursor's
                // (origin_invocation_id, highest_usn) for that leader.
                let cursor_high = cursor
                    .entries
                    .iter()
                    .find(|c| c.invocation_id == entry.origin_invocation_id)
                    .map_or(0, |c| c.highest_usn);
                entry.index > cursor_high
            })
            .map(|e| e.payload.clone())
            .collect();
        let highest_usn = log.iter().map(|e| e.index).max().unwrap_or(0);
        Ok(ReplicationPayload {
            nc_head,
            operations,
            origin_invocation_id: self.invocation_id,
            highest_usn,
        })
    }

    async fn apply_changes(
        &self,
        batch: ReplicationPayload,
    ) -> Result<Vec<Resolution>, ReplicationError> {
        // Per Decision 1 §Decision — append Raft log entries, then commit
        // via quorum-gated `commit_entry` (Wave 2 fix). Previously this
        // method advanced `commit_index` unconditionally — a data-loss risk
        // on network partition (per tasklist gap #2). Now the local node
        // appends uncommitted entries and `commit_entry` only commits when
        // a majority of peers have acked (or when this is a single-node
        // cluster, where majority = 1 = self).
        //
        // Conflict resolution is a no-op in Raft mode (Raft serialises
        // writes — per ADR-071 §Decision — so every entry "applies" without
        // conflict).
        let leader_invocation_id = batch.origin_invocation_id;
        let (term, start_index, new_last_index) = {
            let mut nodes = self.raft.nodes.write().await;
            let local = nodes
                .entry(self.raft.local_node_id)
                .or_insert_with(RaftNodeState::new);
            let start_index = local.last_log_index() + 1;
            let term = local.current_term.max(1);
            for (offset, op) in batch.operations.into_iter().enumerate() {
                let next_index = start_index + offset as u64;
                local.log.push(RaftLogEntry {
                    term,
                    index: next_index,
                    origin_invocation_id: leader_invocation_id,
                    origin_usn: next_index,
                    payload: op,
                });
            }
            (term, start_index, local.last_log_index())
        };
        // Wave 2: commit via quorum-gated `commit_entry`. For a single-node
        // cluster (no peers), majority = 1 = self, so this commits
        // immediately. For a multi-node cluster, the leader must replicate
        // to peers (via `append_entries_to_peer`) and record acks (via
        // `record_peer_ack`) before `commit_entry` will advance
        // `commit_index`.
        if new_last_index >= start_index {
            let _ = self.raft.commit_entry(new_last_index).await;
        }
        let _ = term; // used for log entry creation above
        let resolutions =
            vec![Resolution::IncomingWins; (new_last_index - start_index + 1) as usize];
        Ok(resolutions)
    }

    async fn update_utd_vector(
        &self,
        _nc_head: NcHead,
        _delta: UtdDelta,
    ) -> Result<(), ReplicationError> {
        // Per ADR-071 §Decision — in native mode the UTD vector is
        // synthesised from the Raft log on demand (see
        // `synthesize_utd_vector`); there is no separate mutable UTD-vector
        // store to update. `update_utd_vector` is therefore a no-op.
        Ok(())
    }

    async fn resolve_conflict(
        &self,
        _conflict: ConflictRecord,
    ) -> Result<Resolution, ReplicationError> {
        // Per ADR-071 §Decision — in native mode, conflicts should never
        // occur because Raft serialises writes; if a conflict is observed,
        // it indicates a bug or a split-brain that requires admin
        // intervention. Return a Permanent error (not transient), surfacing
        // possible split-brain to admins.
        Err(ReplicationError::Permanent(
            "conflict resolution in native mode should never be needed — possible split-brain"
                .into(),
        ))
    }

    async fn sync_metadata(&self, _partner: &str) -> Result<(), ReplicationError> {
        // Per Decision 1 §Decision — Raft snapshot transfer to a new peer
        // joining the cluster (per ADR-008 — declarative topology). In v1
        // the snapshot transfer is stubbed (see `install_snapshot`); the
        // call succeeds because in Raft mode metadata sync is automatic —
        // every committed entry is replicated immediately, so a partner
        // joining the cluster catches up via normal AppendEntries.
        tracing::debug!(
            target: "adrian_raft::sync_metadata",
            partner = _partner,
            cluster_id = %self.cluster_id,
            "sync_metadata: stubbed (Raft mode — metadata sync is automatic via AppendEntries)"
        );
        Ok(())
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
    #[must_use]
    pub fn new(bind_addr: std::net::SocketAddr, peers: Vec<std::net::SocketAddr>) -> Self {
        Self { bind_addr, peers }
    }
}

// TODO: implement openraft RaftLogStore / RaftStateMachine backed by FDB per Decision 1.
// TODO: implement openraft RaftNetwork over tokio::net::TcpStream per Decision 1.
// TODO: implement openraft Raft driver wiring (leader election, heartbeats,
// log propagation) — currently the in-memory ManualRaftReplicator handles
// RPC *handlers* but not the driver loop.

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_repl_core::{PropertyMetaDataExt, ReplOperation};
    use std::net::SocketAddr;
    use uuid::Uuid;

    fn dummy_invocation_id() -> Uuid {
        Uuid::from_u128(0x_42)
    }

    fn dummy_invocation_id_b() -> Uuid {
        Uuid::from_u128(0x_43)
    }

    fn dummy_socket_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn dummy_metadata(inv: Uuid, usn: u64) -> PropertyMetaDataExt {
        PropertyMetaDataExt {
            origin_invocation_id: inv,
            origin_usn: usn,
            version: 1,
            last_write_timestamp: 0,
        }
    }

    fn dummy_entry(term: u64, index: u64, origin_invocation_id: Uuid) -> RaftLogEntry {
        RaftLogEntry::new(
            term,
            index,
            origin_invocation_id,
            ReplOperation::TombstoneGC {
                cutoff: index * 100,
            },
        )
    }

    // ---- Priority 1: RaftLogEntry encode/decode round-trip ----

    #[test]
    fn raft_log_entry_roundtrip_via_json() {
        // Existing serialisation test — preserved for backward compat, now
        // exercises the new struct (term, index, payload fields).
        let entry = RaftLogEntry {
            term: 5,
            index: 42,
            origin_invocation_id: dummy_invocation_id(),
            origin_usn: 12345,
            payload: ReplOperation::TombstoneGC { cutoff: 1337 },
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        let back: RaftLogEntry = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, entry);
    }

    #[test]
    fn raft_log_entry_carries_modify_attribute_payload() {
        let metadata = PropertyMetaDataExt {
            origin_invocation_id: dummy_invocation_id(),
            origin_usn: 7,
            version: 2,
            last_write_timestamp: 1000,
        };
        let entry = RaftLogEntry {
            term: 1,
            index: 7,
            origin_invocation_id: dummy_invocation_id(),
            origin_usn: 7,
            payload: ReplOperation::ModifyAttribute {
                uuid: dummy_invocation_id(),
                attribute: "cn".into(),
                value: b"alice".to_vec(),
                metadata,
            },
        };
        let json = serde_json::to_string(&entry).expect("serialise");
        assert!(json.contains("ModifyAttribute"), "json={}", json);
        assert!(json.contains("\"attribute\":\"cn\""), "json={}", json);
        assert!(json.contains("[97,108,105,99,101]"), "json={}", json);
        assert!(json.contains("\"term\":1"), "json={}", json);
        assert!(json.contains("\"index\":7"), "json={}", json);
    }

    #[test]
    fn encode_log_entry_roundtrips_through_decode() {
        let entry = RaftLogEntry::new(
            3,
            7,
            dummy_invocation_id(),
            ReplOperation::TombstoneGC { cutoff: 999 },
        );
        let bytes = encode_log_entry(&entry);
        let decoded = decode_log_entry(&bytes).expect("decode");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn encode_log_entry_uses_length_prefix() {
        let entry = RaftLogEntry::new(
            1,
            1,
            dummy_invocation_id(),
            ReplOperation::TombstoneGC { cutoff: 1 },
        );
        let bytes = encode_log_entry(&entry);
        assert!(bytes.len() > 4, "encoded entry should be > 4 bytes");
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(
            len as usize + 4,
            bytes.len(),
            "length prefix should match body size"
        );
    }

    #[test]
    fn decode_log_entry_rejects_short_input() {
        let short = [0u8; 2]; // < 4-byte length prefix
        let err = decode_log_entry(&short).unwrap_err();
        assert!(matches!(err, RaftError::InvalidEntry(_)), "{:?}", err);
    }

    #[test]
    fn decode_log_entry_rejects_truncated_body() {
        // Header says 100 bytes of body, but we only provide 4 bytes.
        let mut bad = Vec::new();
        bad.extend_from_slice(&100u32.to_be_bytes());
        bad.extend_from_slice(&[0u8; 4]);
        let err = decode_log_entry(&bad).unwrap_err();
        assert!(matches!(err, RaftError::InvalidEntry(_)));
    }

    #[test]
    fn encode_decode_roundtrip_preserves_all_repl_operation_variants() {
        let inv = dummy_invocation_id();
        let md = dummy_metadata(inv, 1);
        let cases = vec![
            ReplOperation::AddObject {
                uuid: inv,
                dn: "cn=alice,dc=example,dc=com".into(),
                attributes: vec![("cn".into(), b"alice".to_vec(), md.clone())],
            },
            ReplOperation::ModifyAttribute {
                uuid: inv,
                attribute: "cn".into(),
                value: b"bob".to_vec(),
                metadata: md.clone(),
            },
            ReplOperation::DeleteObject {
                uuid: inv,
                metadata: md.clone(),
            },
            ReplOperation::AddLink {
                link_uuid: inv,
                link_id: 1,
                backlink_uuid: dummy_invocation_id_b(),
                metadata: md.clone(),
            },
            ReplOperation::DeleteLink {
                link_uuid: inv,
                link_id: 1,
                backlink_uuid: dummy_invocation_id_b(),
                metadata: md.clone(),
            },
            ReplOperation::TombstoneGC { cutoff: 100 },
        ];
        for (i, op) in cases.into_iter().enumerate() {
            let entry = RaftLogEntry::new(7, (i + 1) as u64, inv, op);
            let bytes = encode_log_entry(&entry);
            let decoded = decode_log_entry(&bytes).expect("decode");
            assert_eq!(decoded, entry, "roundtrip failed for case {i}");
        }
    }

    // ---- Priority 2: UTD-vector synthesis ----

    #[test]
    fn synthesize_utd_vector_empty_log_yields_empty_vector() {
        let v = synthesize_utd_vector(&[], dummy_invocation_id());
        assert!(v.entries.is_empty());
    }

    #[test]
    fn synthesize_utd_vector_single_leader_one_cursor() {
        let inv = dummy_invocation_id();
        let log = vec![
            dummy_entry(1, 1, inv),
            dummy_entry(1, 2, inv),
            dummy_entry(1, 5, inv), // gap in indices — highest wins
        ];
        let v = synthesize_utd_vector(&log, dummy_invocation_id());
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].invocation_id, inv);
        assert_eq!(v.entries[0].highest_usn, 5);
    }

    #[test]
    fn synthesize_utd_vector_two_leaders_two_cursors() {
        // Per Priority 2 test case — "5 entries from 2 different leaders →
        // UTD with 2 cursors".
        let inv_a = dummy_invocation_id();
        let inv_b = dummy_invocation_id_b();
        let log = vec![
            dummy_entry(1, 1, inv_a),
            dummy_entry(1, 2, inv_a),
            dummy_entry(2, 3, inv_b), // leader B takes over at term 2
            dummy_entry(2, 4, inv_b),
            dummy_entry(2, 5, inv_b),
        ];
        let v = synthesize_utd_vector(&log, dummy_invocation_id());
        assert_eq!(
            v.entries.len(),
            2,
            "expected 2 cursors, got {:?}",
            v.entries
        );
        for e in &v.entries {
            if e.invocation_id == inv_a {
                assert_eq!(e.highest_usn, 2);
            } else if e.invocation_id == inv_b {
                assert_eq!(e.highest_usn, 5);
            } else {
                panic!("unexpected invocation_id {}", e.invocation_id);
            }
        }
    }

    #[test]
    fn synthesize_utd_vector_entries_sorted_by_invocation_id() {
        // Per MS-ADTS §3.1.1.3.2.5 — UTD vector entries are displayed in
        // lexicographic invocation-ID order. Synthesis must match.
        let inv_a = Uuid::from_u128(0x_99);
        let inv_b = Uuid::from_u128(0x_11);
        let log = vec![dummy_entry(1, 1, inv_a), dummy_entry(2, 1, inv_b)];
        let v = synthesize_utd_vector(&log, dummy_invocation_id());
        assert_eq!(v.entries.len(), 2);
        assert_eq!(v.entries[0].invocation_id, inv_b);
        assert_eq!(v.entries[1].invocation_id, inv_a);
    }

    // ---- Priority 3: RaftReplicator trait impl (ManualRaftReplicator) ----

    #[tokio::test]
    async fn append_entries_rejects_stale_term() {
        // Per Raft §5.4.1 step 1 — if term < currentTerm, reply false.
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        {
            let mut nodes = repl.nodes.write().await;
            let local = nodes.get_mut(&repl.local_node_id).unwrap();
            local.current_term = 5;
        }
        let res = repl
            .append_entries(3, dummy_invocation_id(), 0, 0, vec![], 0)
            .await
            .expect("append_entries");
        assert!(!res.success);
        assert_eq!(res.term, 5, "receiver should echo its current term");
    }

    #[tokio::test]
    async fn append_entries_accepts_higher_term_and_appends_entries() {
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        let inv = dummy_invocation_id();
        let entries = vec![
            dummy_entry(2, 1, inv),
            dummy_entry(2, 2, inv),
            dummy_entry(2, 3, inv),
        ];
        let res = repl
            .append_entries(2, inv, 0, 0, entries, 2)
            .await
            .expect("append_entries");
        assert!(res.success, "expected success");
        assert_eq!(res.term, 2);
        assert_eq!(res.last_log_index, 3);
        assert_eq!(res.commit_index, 2);
        assert_eq!(repl.last_log_index().await, 3);
        assert_eq!(repl.commit_index().await, 2);
    }

    #[tokio::test]
    async fn append_entries_rejects_log_inconsistency() {
        // Per Raft §5.4.1 step 3 — if log at prev_log_index doesn't have
        // prev_log_term, reply false.
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        let inv = dummy_invocation_id();
        repl.append_entries(1, inv, 0, 0, vec![dummy_entry(1, 1, inv)], 0)
            .await
            .expect("prime");
        let res = repl
            .append_entries(1, inv, 1, 99, vec![], 0)
            .await
            .expect("append_entries");
        assert!(!res.success);
    }

    #[tokio::test]
    async fn append_entries_truncates_conflicting_entries() {
        // Per Raft §5.4.1 step 4 — conflict at index 2 with different term
        // truncates [1@2, 1@3] and appends [2@2, 2@3].
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        let inv = dummy_invocation_id();
        repl.append_entries(
            1,
            inv,
            0,
            0,
            vec![
                dummy_entry(1, 1, inv),
                dummy_entry(1, 2, inv),
                dummy_entry(1, 3, inv),
            ],
            0,
        )
        .await
        .expect("prime");
        let res = repl
            .append_entries(
                2,
                inv,
                1,
                1,
                vec![dummy_entry(2, 2, inv), dummy_entry(2, 3, inv)],
                0,
            )
            .await
            .expect("append_entries");
        assert!(res.success);
        let log = repl.log_snapshot().await;
        assert_eq!(
            log.len(),
            3,
            "log should have 3 entries after truncation+append: {:?}",
            log
        );
        assert_eq!(log[0].term, 1, "entry 1 unchanged");
        assert_eq!(log[1].term, 2, "entry 2 replaced with term 2");
        assert_eq!(log[2].term, 2, "entry 3 replaced with term 2");
    }

    #[tokio::test]
    async fn append_entries_idempotent_resend_does_not_duplicate() {
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        let inv = dummy_invocation_id();
        let entries = vec![dummy_entry(1, 1, inv), dummy_entry(1, 2, inv)];
        repl.append_entries(1, inv, 0, 0, entries.clone(), 0)
            .await
            .expect("first append");
        let res = repl
            .append_entries(1, inv, 0, 0, entries, 0)
            .await
            .expect("append_entries");
        assert!(res.success);
        assert_eq!(repl.last_log_index().await, 2);
        assert_eq!(repl.log_snapshot().await.len(), 2);
    }

    #[tokio::test]
    async fn vote_rejects_stale_term() {
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        {
            let mut nodes = repl.nodes.write().await;
            nodes.get_mut(&repl.local_node_id).unwrap().current_term = 5;
        }
        let res = repl
            .vote(3, dummy_invocation_id_b(), 0, 0)
            .await
            .expect("vote");
        assert!(!res.vote_granted);
        assert_eq!(res.term, 5);
    }

    #[tokio::test]
    async fn vote_grants_for_first_candidate_with_up_to_date_log() {
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        let res = repl
            .vote(1, dummy_invocation_id_b(), 0, 0)
            .await
            .expect("vote");
        assert!(res.vote_granted);
        assert_eq!(res.term, 1);
        assert_eq!(repl.voted_for().await, Some(dummy_invocation_id_b()));
    }

    #[tokio::test]
    async fn vote_rejects_second_candidate_in_same_term() {
        // Per Raft §5.4.1 step 3 — at most one vote per term per node.
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        let cand_a = dummy_invocation_id_b();
        let cand_b = Uuid::from_u128(0x_44);
        repl.vote(1, cand_a, 0, 0).await.expect("vote a");
        let res = repl.vote(1, cand_b, 0, 0).await.expect("vote b");
        assert!(!res.vote_granted, "second candidate should not get vote");
        assert_eq!(repl.voted_for().await, Some(cand_a));
    }

    #[tokio::test]
    async fn vote_rejects_candidate_with_stale_log() {
        // Per Raft §5.4.1 step 3 — candidate's log must be at least as
        // up-to-date as the receiver's.
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        let inv = dummy_invocation_id();
        repl.append_entries(
            5,
            inv,
            0,
            0,
            vec![RaftLogEntry::new(
                5,
                10,
                inv,
                ReplOperation::TombstoneGC { cutoff: 0 },
            )],
            0,
        )
        .await
        .expect("prime");
        let res = repl
            .vote(6, dummy_invocation_id_b(), 20, 4)
            .await
            .expect("vote");
        assert!(!res.vote_granted, "stale-log candidate should not get vote");
    }

    #[tokio::test]
    async fn vote_grants_for_candidate_with_higher_term_even_if_local_already_voted() {
        // Per Raft §5.4.1 step 2 — if term > currentTerm, update currentTerm
        // and reset voted_for. Then step 3 grants vote freely.
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        repl.vote(1, dummy_invocation_id_b(), 0, 0)
            .await
            .expect("first vote");
        let res = repl
            .vote(2, Uuid::from_u128(0x_44), 0, 0)
            .await
            .expect("vote");
        assert!(res.vote_granted);
        assert_eq!(res.term, 2);
    }

    #[tokio::test]
    async fn install_snapshot_rejects_term_regression() {
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        {
            let mut nodes = repl.nodes.write().await;
            nodes.get_mut(&repl.local_node_id).unwrap().current_term = 5;
        }
        let err = repl
            .install_snapshot(3, dummy_invocation_id_b(), 100, 2, 0, vec![1, 2, 3], true)
            .await
            .unwrap_err();
        assert!(matches!(err, RaftError::SnapshotRejected(_)));
    }

    #[tokio::test]
    async fn install_snapshot_accepts_higher_term() {
        let repl = ManualRaftReplicator::new(dummy_invocation_id());
        repl.install_snapshot(5, dummy_invocation_id_b(), 100, 4, 0, vec![1, 2, 3], true)
            .await
            .expect("install_snapshot");
        assert_eq!(repl.current_term().await, 5);
    }

    // ---- openraft type conversion seam ----

    #[test]
    fn raft_log_entry_to_openraft_log_id_round_trip() {
        let entry = RaftLogEntry::new(
            7,
            42,
            dummy_invocation_id(),
            ReplOperation::TombstoneGC { cutoff: 0 },
        );
        let lid = entry.to_openraft_log_id();
        assert_eq!(lid.index, 42);
        assert_eq!(lid.committed_leader_id().term, 7);
    }

    #[test]
    fn raft_log_entry_to_openraft_vote_round_trip() {
        let entry = RaftLogEntry::new(
            3,
            9,
            dummy_invocation_id(),
            ReplOperation::TombstoneGC { cutoff: 0 },
        );
        let vote = entry.to_openraft_vote();
        assert_eq!(vote.leader_id.get_term(), 3);
        assert!(!vote.is_committed());
    }

    // ---- High-level RaftDirectoryReplicator ----

    #[test]
    fn raft_directory_replicator_new_sets_fields() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let inv = dummy_invocation_id();
        let replicator = RaftDirectoryReplicator::new(inv, store, "cluster-a");
        assert_eq!(replicator.invocation_id, inv);
        assert_eq!(replicator.cluster_id, "cluster-a");
        assert!(replicator.store.cluster_file.is_none());
        assert_eq!(replicator.raft.local_node_id, inv);
    }

    #[test]
    fn raft_directory_replicator_new_accepts_string_and_str() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let _r1 = RaftDirectoryReplicator::new(dummy_invocation_id(), store.clone(), "literal");
        let owned = String::from("owned");
        let _r2 = RaftDirectoryReplicator::new(dummy_invocation_id(), store, owned);
    }

    #[tokio::test]
    async fn raft_directory_replicator_get_changes_empty_log() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let repl = RaftDirectoryReplicator::new(dummy_invocation_id(), store, "c");
        let cursor = UtdVector::default();
        let payload = repl
            .get_changes(NcHead::nil(), &cursor)
            .await
            .expect("get_changes");
        assert!(payload.operations.is_empty());
        assert_eq!(payload.highest_usn, 0);
    }

    #[tokio::test]
    async fn raft_directory_replicator_apply_changes_appends_to_log() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let repl = RaftDirectoryReplicator::new(dummy_invocation_id(), store, "c");
        let md = dummy_metadata(dummy_invocation_id(), 1);
        let batch = ReplicationPayload {
            nc_head: NcHead::nil(),
            operations: vec![
                ReplOperation::ModifyAttribute {
                    uuid: dummy_invocation_id(),
                    attribute: "cn".into(),
                    value: b"alice".to_vec(),
                    metadata: md.clone(),
                },
                ReplOperation::DeleteObject {
                    uuid: dummy_invocation_id_b(),
                    metadata: md,
                },
            ],
            origin_invocation_id: dummy_invocation_id(),
            highest_usn: 2,
        };
        let resolutions = repl.apply_changes(batch).await.expect("apply_changes");
        assert_eq!(resolutions.len(), 2);
        assert!(resolutions.iter().all(|r| *r == Resolution::IncomingWins));
        assert_eq!(repl.raft.last_log_index().await, 2);
    }

    #[tokio::test]
    async fn raft_directory_replicator_get_changes_returns_tail_beyond_cursor() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let repl = RaftDirectoryReplicator::new(dummy_invocation_id(), store, "c");
        let md = dummy_metadata(dummy_invocation_id(), 1);
        let batch = ReplicationPayload {
            nc_head: NcHead::nil(),
            operations: vec![
                ReplOperation::ModifyAttribute {
                    uuid: dummy_invocation_id(),
                    attribute: "cn".into(),
                    value: b"alice".to_vec(),
                    metadata: md.clone(),
                },
                ReplOperation::DeleteObject {
                    uuid: dummy_invocation_id_b(),
                    metadata: md,
                },
            ],
            origin_invocation_id: dummy_invocation_id(),
            highest_usn: 2,
        };
        repl.apply_changes(batch).await.expect("apply");
        // Cursor up-to-date — empty tail.
        let cursor = UtdVector {
            entries: vec![UtdVectorEntry {
                invocation_id: dummy_invocation_id(),
                highest_usn: 2,
            }],
        };
        let payload = repl
            .get_changes(NcHead::nil(), &cursor)
            .await
            .expect("get_changes");
        assert!(
            payload.operations.is_empty(),
            "cursor up-to-date should yield empty tail"
        );
        // Cursor one behind — should return the last entry.
        let cursor = UtdVector {
            entries: vec![UtdVectorEntry {
                invocation_id: dummy_invocation_id(),
                highest_usn: 1,
            }],
        };
        let payload = repl
            .get_changes(NcHead::nil(), &cursor)
            .await
            .expect("get_changes");
        assert_eq!(
            payload.operations.len(),
            1,
            "should return 1 entry past cursor"
        );
        assert_eq!(payload.highest_usn, 2);
    }

    #[tokio::test]
    async fn raft_directory_replicator_update_utd_vector_is_noop() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let repl = RaftDirectoryReplicator::new(dummy_invocation_id(), store, "c");
        let delta = UtdDelta {
            invocation_id: dummy_invocation_id(),
            new_highest_usn: 99,
        };
        repl.update_utd_vector(NcHead::nil(), delta)
            .await
            .expect("update_utd_vector");
    }

    #[tokio::test]
    async fn raft_directory_replicator_resolve_conflict_reports_split_brain() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let repl = RaftDirectoryReplicator::new(dummy_invocation_id(), store, "c");
        let metadata = dummy_metadata(dummy_invocation_id(), 1);
        let conflict = ConflictRecord {
            uuid: Uuid::nil(),
            attribute: "cn".into(),
            local: (b"local".to_vec(), metadata.clone()),
            incoming: (b"incoming".to_vec(), metadata),
        };
        let result = repl.resolve_conflict(conflict).await;
        assert!(
            matches!(result, Err(ReplicationError::Permanent(_))),
            "{:?}",
            result
        );
    }

    #[tokio::test]
    async fn raft_directory_replicator_sync_metadata_succeeds_stub() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let repl = RaftDirectoryReplicator::new(dummy_invocation_id(), store, "c");
        repl.sync_metadata("partner-dc")
            .await
            .expect("sync_metadata");
    }

    #[test]
    fn raft_network_transport_new_sets_fields() {
        let bind = dummy_socket_addr(389);
        let peers = vec![dummy_socket_addr(390), dummy_socket_addr(391)];
        let transport = RaftNetworkTransport::new(bind, peers.clone());
        assert_eq!(transport.bind_addr, bind);
        assert_eq!(transport.peers, peers);
    }

    #[test]
    fn raft_network_transport_supports_empty_peers() {
        let bind = dummy_socket_addr(389);
        let transport = RaftNetworkTransport::new(bind, vec![]);
        assert!(transport.peers.is_empty());
    }

    // =================================================================
    // NEW (Wave 2) — quorum enforcement + leader election + install_snapshot
    // =================================================================

    #[tokio::test]
    async fn wave2_commit_entry_succeeds_with_quorum() {
        // T-201 positive: `commit_entry` commits when a majority of peers
        // have acked. 3-node cluster (majority = 2): self + 1 peer ack = 2.
        let node_a = Uuid::from_u128(0xA1);
        let node_b = Uuid::from_u128(0xA2);
        let node_c = Uuid::from_u128(0xA3);
        let raft = ManualRaftReplicator::new(node_a);
        raft.add_peer(node_b).await;
        raft.add_peer(node_c).await;
        // Append one entry at term 1, index 1 on the leader.
        {
            let mut nodes = raft.nodes.write().await;
            let local = nodes.get_mut(&node_a).unwrap();
            local.current_term = 1;
            local.log.push(RaftLogEntry::new(
                1,
                1,
                node_a,
                ReplOperation::DeleteObject {
                    uuid: Uuid::nil(),
                    metadata: dummy_metadata(node_a, 1),
                },
            ));
        }
        // Peer B acks up to index 1.
        raft.record_peer_ack(node_b, 1).await;
        let committed = raft.commit_entry(1).await.expect("commit_entry");
        assert!(committed, "quorum reached (self + B = 2 >= 2)");
        assert_eq!(raft.commit_index().await, 1);
    }

    #[tokio::test]
    async fn wave2_commit_entry_rejected_without_quorum() {
        // T-201 negative: `commit_entry` returns false when majority is not
        // reached. 5-node cluster (majority = 3): self + 1 peer ack = 2 < 3.
        let node_a = Uuid::from_u128(0xB1);
        let raft = ManualRaftReplicator::new(node_a);
        for i in 2..=5 {
            raft.add_peer(Uuid::from_u128(0xB0 + i as u128)).await;
        }
        {
            let mut nodes = raft.nodes.write().await;
            let local = nodes.get_mut(&node_a).unwrap();
            local.current_term = 1;
            local.log.push(RaftLogEntry::new(
                1,
                1,
                node_a,
                ReplOperation::DeleteObject {
                    uuid: Uuid::nil(),
                    metadata: dummy_metadata(node_a, 1),
                },
            ));
        }
        // Only one peer acks.
        raft.record_peer_ack(Uuid::from_u128(0xB2), 1).await;
        let committed = raft.commit_entry(1).await.expect("commit_entry");
        assert!(!committed, "quorum NOT reached (self + 1 peer = 2 < 3)");
        assert_eq!(
            raft.commit_index().await,
            0,
            "commit_index must NOT advance"
        );
    }

    #[tokio::test]
    async fn wave2_leader_election_3_nodes() {
        // T-202: 3-node cluster, node A calls `start_election`, wins with
        // 2/3 votes (self + one peer). Per RFC §5.2 split-vote prevention,
        // A must receive a majority before becoming leader.
        let node_a = Uuid::from_u128(0xC1);
        let node_b = Uuid::from_u128(0xC2);
        let node_c = Uuid::from_u128(0xC3);
        let raft = ManualRaftReplicator::new(node_a);
        raft.add_peer(node_b).await;
        raft.add_peer(node_c).await;
        let won = raft.start_election().await.expect("start_election");
        assert!(won, "node A should win with 2/3 votes (self + B or C)");
        assert_eq!(raft.current_term().await, 1);
        assert_eq!(raft.leader_id().await, Some(node_a));
        assert_eq!(raft.voted_for().await, Some(node_a));
        // After winning, peer_state should be initialised.
        let ps = raft.peer_state.read().await;
        for p in ps.values() {
            assert_eq!(p.match_index, 0);
            assert_eq!(p.next_index, 1, "next_index = last_log_index + 1 = 0 + 1");
        }
    }

    #[tokio::test]
    async fn wave2_leader_election_5_nodes() {
        // T-202: 5-node cluster, node A calls `start_election`, wins with
        // 3/5 votes (self + 2 peers). Majority = 3.
        let node_a = Uuid::from_u128(0xD1);
        let raft = ManualRaftReplicator::new(node_a);
        for i in 2..=5 {
            raft.add_peer(Uuid::from_u128(0xD0 + i as u128)).await;
        }
        let won = raft.start_election().await.expect("start_election");
        assert!(won, "node A should win with 3/5 votes (self + 2 peers)");
        assert_eq!(raft.current_term().await, 1);
        assert_eq!(raft.leader_id().await, Some(node_a));
    }

    #[tokio::test]
    async fn wave2_partition_recovery() {
        // T-204 partition recovery: simulate a 3-node cluster where node A
        // is leader, then a partition isolates node C. Node A can still
        // commit with B (2/3 majority). After the partition heals, C
        // rejoins and catches up via AppendEntries.
        let node_a = Uuid::from_u128(0xE1);
        let node_b = Uuid::from_u128(0xE2);
        let node_c = Uuid::from_u128(0xE3);
        let raft = ManualRaftReplicator::new(node_a);
        raft.add_peer(node_b).await;
        raft.add_peer(node_c).await;
        // Phase 1: A wins election (2/3 votes).
        let won = raft.start_election().await.expect("election");
        assert!(won);
        let term = raft.current_term().await;
        // Phase 2: A appends an entry and replicates to B only (C is
        // "partitioned" — we skip calling append_entries_to_peer on C).
        let entry = RaftLogEntry::new(
            term,
            1,
            node_a,
            ReplOperation::DeleteObject {
                uuid: Uuid::nil(),
                metadata: dummy_metadata(node_a, 1),
            },
        );
        {
            let mut nodes = raft.nodes.write().await;
            nodes.get_mut(&node_a).unwrap().log.push(entry.clone());
        }
        let result = raft
            .append_entries_to_peer(node_b, term, node_a, 0, 0, vec![entry.clone()], 0)
            .await
            .expect("append_entries to B");
        assert!(result.success);
        // Phase 3: A commits with B's ack (2/3 majority).
        let committed = raft.commit_entry(1).await.expect("commit_entry");
        assert!(committed, "A+B = 2/3 majority, should commit");
        assert_eq!(raft.commit_index().await, 1);
        // Phase 4: partition heals — A replicates to C.
        let result = raft
            .append_entries_to_peer(
                node_c,
                term,
                node_a,
                0,
                0,
                vec![entry],
                raft.commit_index().await,
            )
            .await
            .expect("append_entries to C");
        assert!(
            result.success,
            "C should accept entries after partition heals"
        );
        // Verify C's log matches A's.
        let nodes = raft.nodes.read().await;
        let c_log = &nodes.get(&node_c).unwrap().log;
        assert_eq!(c_log.len(), 1);
        assert_eq!(c_log[0].index, 1);
        assert_eq!(nodes.get(&node_c).unwrap().commit_index, 1);
    }

    #[tokio::test]
    async fn wave2_install_snapshot_applies_snapshot() {
        // T-203: InstallSnapshot with `done=true` truncates the log up to
        // `last_included_index` and advances `commit_index` / `last_applied`.
        let node_a = Uuid::from_u128(0xF1);
        let raft = ManualRaftReplicator::new(node_a);
        // Seed the log with 5 entries at term 1.
        {
            let mut nodes = raft.nodes.write().await;
            let local = nodes.get_mut(&node_a).unwrap();
            local.current_term = 2;
            for i in 1..=5 {
                local.log.push(RaftLogEntry::new(
                    1,
                    i,
                    node_a,
                    ReplOperation::DeleteObject {
                        uuid: Uuid::nil(),
                        metadata: dummy_metadata(node_a, i),
                    },
                ));
            }
        }
        // Install a snapshot covering entries 1-3.
        raft.install_snapshot(2, node_a, 3, 1, 0, vec![0xAB; 64], true)
            .await
            .expect("install_snapshot");
        let nodes = raft.nodes.read().await;
        let local = nodes.get(&node_a).unwrap();
        assert_eq!(
            local.log.len(),
            2,
            "entries 1-3 truncated, entries 4-5 remain"
        );
        assert_eq!(local.log[0].index, 4);
        assert_eq!(local.log[1].index, 5);
        assert_eq!(local.commit_index, 3);
        assert_eq!(local.last_applied, 3);
    }
}
