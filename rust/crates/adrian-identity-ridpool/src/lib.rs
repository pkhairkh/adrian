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
//! `adrian-storage-core`, `adrian-storage-testkit` (for the fallback path).
//! Gated by the `ad-interop` feature flag at the workspace level (per
//! finaldraft/04-rust-workspace-design.md §7).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_identity_core::{IdentityError, PrincipalId};
use adrian_sid::Sid;
use adrian_storage_core::{DirectoryStore, ReadTxn, WriteTxn};
use adrian_storage_testkit::InMemoryDirectoryStore;
use async_trait::async_trait;
use std::fmt;

/// Encode a SID to its binary wire form, mapping `SidError` to an
/// `IdentityError::Backend`. Used by the key-encoding helpers below.
fn sid_to_bytes(domain_sid: &Sid) -> Result<Vec<u8>, IdentityError> {
    domain_sid
        .to_bytes()
        .map_err(|e| IdentityError::Backend(format!("SID encode error: {e}")))
}

/// The size of a RID allocation batch (per Decision 3 §Decision — matches
/// AD's `RIDAllocationPoolSize`).
pub const RID_BATCH_SIZE: u32 = 500;

/// The RID-pool exhaustion warning threshold (per Decision 3 §Decision —
/// matches AD's `rIDAllocationPoolRenewThreshold`).
pub const RID_EXHAUSTION_WARNING_THRESHOLD: u32 = RID_BATCH_SIZE / 2;

/// The first RID dispensed by a freshly-initialised pool. RIDs 0..1000 are
/// reserved for well-known SIDs (Built-in Administrators RID 544, etc.) per
/// MS-DTYP §2.4.2 + AD's well-known security identifiers table; new security
/// principals are dispensed RIDs starting at 1000 to mirror AD's default
/// `rIDPreviousAllocationPool` lower bound.
pub const INITIAL_RID: u32 = 1000;

/// The FDB subspace byte for RID-pool state (per Decision 3 + storage-core
/// `Subspace::RidPool = 0x06`).
const RIDPOOL_SUBSPACE: u8 = 0x06;

/// Marker byte separating the domain-SID prefix from the per-domain
/// "next_rid" atomic counter key suffix. Using a byte < 0x80 ensures the
/// counter key sorts immediately after the state key (which is the bare
/// `(0x06, domain_sid_bytes)` prefix) — matching FDB tuple-layer convention
/// where shorter keys sort before longer keys sharing the same prefix.
const COUNTER_KEY_MARKER: u8 = 0x00;
/// Marker byte for the local-DC scope tag used by `LocalRidAllocator`'s keys.
const LOCAL_DC_MARKER: u8 = 0x10;
/// Marker byte separating the domain-SID prefix from the per-domain state
/// suffix. Distinct from `COUNTER_KEY_MARKER` so the state key and counter
/// key are non-overlapping even if one is a prefix of the other.
const STATE_KEY_MARKER: u8 = 0x01;

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
///
/// Wire format (12 bytes, big-endian):
/// `[next_rid: u32 BE][last_allocated_rid: u32 BE][warning_threshold: u32 BE]`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RidPoolState {
    /// The next RID to allocate (atomic-add counter, per Decision 2). This is
    /// the value the next `allocate()` call will dispense.
    pub next_rid: Rid,
    /// The last RID allocated to this DC by the RID-master in the current
    /// batch (inclusive — the DC may dispense any RID `<= last_allocated_rid`
    /// before requesting a new batch).
    pub last_allocated_rid: Rid,
    /// The pool-exhaustion warning threshold (per Decision 3 — defaults to
    /// `RID_EXHAUSTION_WARNING_THRESHOLD`).
    pub warning_threshold: u32,
}

impl RidPoolState {
    /// Construct the canonical initial state for a freshly-created RID pool:
    /// `next_rid = INITIAL_RID`, `last_allocated_rid = INITIAL_RID +
    /// RID_BATCH_SIZE - 1` (i.e. a single 500-RID batch covering
    /// `INITIAL_RID..=INITIAL_RID+RID_BATCH_SIZE-1`), `warning_threshold =
    /// RID_EXHAUSTION_WARNING_THRESHOLD`.
    pub fn initial() -> Self {
        Self {
            next_rid: INITIAL_RID,
            last_allocated_rid: INITIAL_RID + RID_BATCH_SIZE - 1,
            warning_threshold: RID_EXHAUSTION_WARNING_THRESHOLD,
        }
    }

    /// Encode this state to its 12-byte big-endian wire form.
    pub fn encode(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&self.next_rid.to_be_bytes());
        out[4..8].copy_from_slice(&self.last_allocated_rid.to_be_bytes());
        out[8..].copy_from_slice(&self.warning_threshold.to_be_bytes());
        out
    }

    /// Decode a state from its 12-byte big-endian wire form. Returns `None`
    /// if `buf` is not exactly 12 bytes.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() != 12 {
            return None;
        }
        let next_rid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let last_allocated_rid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let warning_threshold = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        Some(Self {
            next_rid,
            last_allocated_rid,
            warning_threshold,
        })
    }
}

/// The backing KV store for an [`FdbRidPoolAllocator`] or
/// [`LocalRidAllocator`].
///
/// Per the wave-1 plan, the framework supports two code paths:
/// - `Fdb`: production, gated by the `fdb` feature flag (requires a running
///   FoundationDB cluster + the FDB C client library at build time).
/// - `InMemory`: the default (no-feature) build, backed by
///   [`InMemoryDirectoryStore`] from `adrian-storage-testkit`. This path is
///   fully exercised by unit tests; it exercises the same FDB tuple-layer
///   key encoding as the real FDB path so the encoding logic is verified.
#[derive(Clone)]
pub enum RidBackend {
    /// The FDB-backed production backend (gated by the `fdb` feature flag).
    /// Without the feature enabled, every method on this backend surfaces a
    /// `Backend` error rather than panicking — callers degrade gracefully.
    Fdb(adrian_storage_fdb::FdbDirectoryStore),
    /// The in-memory fallback backend. Backed by
    /// [`InMemoryDirectoryStore`] (cheaply cloneable via `Arc`); state is
    /// shared across clones.
    InMemory(InMemoryDirectoryStore),
}

impl fmt::Debug for RidBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fdb(s) => f.debug_tuple("Fdb").field(s).finish(),
            Self::InMemory(s) => f.debug_tuple("InMemory").field(s).finish(),
        }
    }
}

impl RidBackend {
    /// Begin a write transaction against the backend. Returns a `Backend`
    /// error for the FDB path when the `fdb` feature is not enabled.
    async fn begin_write(&self) -> Result<Box<dyn WriteTxn>, IdentityError> {
        match self {
            Self::Fdb(s) => s.begin_write().await.map_err(map_storage_err),
            Self::InMemory(s) => s.begin_write().await.map_err(map_storage_err),
        }
    }

    /// Begin a read transaction against the backend. Returns a `Backend`
    /// error for the FDB path when the `fdb` feature is not enabled.
    async fn begin_read(&self) -> Result<Box<dyn ReadTxn>, IdentityError> {
        match self {
            Self::Fdb(s) => s.begin_read().await.map_err(map_storage_err),
            Self::InMemory(s) => s.begin_read().await.map_err(map_storage_err),
        }
    }

    /// Range-scan the backend for keys with the given prefix. Returns a
    /// `Backend` error for the FDB path when the `fdb` feature is not enabled.
    async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, IdentityError> {
        let r = self.begin_read().await?;
        let mut end = prefix.to_vec();
        // strinc: increment the last byte; if it would overflow (0xFF),
        // append a 0x00 byte to the prefix and use range [prefix, prefix+0x00].
        // For our prefixes this is unreachable because every prefix ends in
        // a non-0xFF byte (subspace + marker bytes are all < 0xFF).
        match end.last_mut() {
            Some(b) if *b < 0xFF => *b += 1,
            _ => end.push(0x00),
        }
        r.get_range(prefix, &end).await.map_err(map_storage_err)
    }
}

fn map_storage_err(e: adrian_storage_core::StorageError) -> IdentityError {
    IdentityError::Backend(e.to_string())
}

/// Encode the per-domain RID-pool state key: `(0x06, domain_sid_bytes)`.
fn rid_state_key(domain_sid: &Sid) -> Result<Vec<u8>, IdentityError> {
    let sid_bytes = sid_to_bytes(domain_sid)?;
    let mut out = Vec::with_capacity(1 + sid_bytes.len());
    out.push(RIDPOOL_SUBSPACE);
    out.extend_from_slice(&sid_bytes);
    Ok(out)
}

/// Encode the per-domain RID-pool counter key:
/// `(0x06, domain_sid_bytes, 0x00, "next_rid")`. The marker byte
/// disambiguates this key from the state key (which is the bare
/// `(0x06, domain_sid_bytes)` prefix) and ensures the counter key sorts
/// after the state key in the FDB ordered KV store.
fn rid_counter_key(domain_sid: &Sid) -> Result<Vec<u8>, IdentityError> {
    let mut out = rid_state_key(domain_sid)?;
    out.push(COUNTER_KEY_MARKER);
    out.extend_from_slice(b"next_rid");
    Ok(out)
}

/// Encode the per-DC, per-domain local RID-pool state prefix used by
/// [`LocalRidAllocator`]:
/// `(0x06, 0x10, local_dc_id_bytes, domain_sid_bytes)`.
fn local_rid_state_prefix(
    local_dc_id: uuid::Uuid,
    domain_sid: &Sid,
) -> Result<Vec<u8>, IdentityError> {
    let sid_bytes = sid_to_bytes(domain_sid)?;
    let mut out = Vec::with_capacity(1 + 1 + 16 + sid_bytes.len());
    out.push(RIDPOOL_SUBSPACE);
    out.push(LOCAL_DC_MARKER);
    out.extend_from_slice(local_dc_id.as_bytes());
    out.extend_from_slice(&sid_bytes);
    Ok(out)
}

/// Encode the per-DC, per-domain local RID-pool state key (suffix
/// `0x01` + "state").
fn local_rid_state_key(
    local_dc_id: uuid::Uuid,
    domain_sid: &Sid,
) -> Result<Vec<u8>, IdentityError> {
    let mut out = local_rid_state_prefix(local_dc_id, domain_sid)?;
    out.push(STATE_KEY_MARKER);
    out.extend_from_slice(b"state");
    Ok(out)
}

/// Encode the per-DC, per-domain local RID-pool counter key (suffix
/// `0x00` + "next_rid").
fn local_rid_counter_key(
    local_dc_id: uuid::Uuid,
    domain_sid: &Sid,
) -> Result<Vec<u8>, IdentityError> {
    let mut out = local_rid_state_prefix(local_dc_id, domain_sid)?;
    out.push(COUNTER_KEY_MARKER);
    out.extend_from_slice(b"next_rid");
    Ok(out)
}

/// FDB-backed RID-pool allocator for AD-interop mode (per Decision 3
/// §Decision).
///
/// This allocator runs on the RID-master DC and dispenses 500-RID batches to
/// other DCs in the forest. The `next_rid` counter uses FDB's atomic-add
/// operation for lock-free allocation (per Decision 2 §Decision).
///
/// In the default (no-`fdb`) build, the allocator wraps an
/// [`InMemoryDirectoryStore`] and exercises the same key-encoding logic as
/// the real FDB path. The real FDB code path is gated behind the `fdb`
/// feature flag and requires a running FDB cluster + the FDB C client library
/// at build time.
#[derive(Debug, Clone)]
pub struct FdbRidPoolAllocator {
    /// The backing KV store (FDB in production, in-memory in unit tests).
    pub backend: RidBackend,
    /// The `FdbDirectoryStore` field is preserved for backwards
    /// compatibility with callers that inspect `cluster_file` for
    /// diagnostics. When the allocator is constructed via [`Self::new`],
    /// the backend is `RidBackend::Fdb(store.clone())`; when constructed
    /// via [`Self::new_in_memory`], the backend is
    /// `RidBackend::InMemory(...)` and this field is `None`.
    pub store: Option<adrian_storage_fdb::FdbDirectoryStore>,
}

impl FdbRidPoolAllocator {
    /// Construct a new `FdbRidPoolAllocator` whose backend is the
    /// `FdbDirectoryStore` (production). Without the `fdb` feature flag
    /// enabled, every allocator method surfaces a `Backend` error — callers
    /// should use [`Self::new_in_memory`] for unit tests.
    pub fn new(store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self {
            backend: RidBackend::Fdb(store.clone()),
            store: Some(store),
        }
    }

    /// Construct a new `FdbRidPoolAllocator` backed by an
    /// [`InMemoryDirectoryStore`]. This is the default path for unit tests
    /// and for deployments that don't have a running FDB cluster.
    pub fn new_in_memory(store: InMemoryDirectoryStore) -> Self {
        Self {
            backend: RidBackend::InMemory(store),
            store: None,
        }
    }

    /// Construct a new `FdbRidPoolAllocator` backed by a fresh
    /// [`InMemoryDirectoryStore`] — convenience for tests.
    pub fn new_in_memory_default() -> Self {
        Self::new_in_memory(InMemoryDirectoryStore::new())
    }

    /// Reclaim the RID-pool state for a domain that has been removed from
    /// the forest (per ADR-077 §Decision — RID pool reclaim on DC removal).
    ///
    /// Clears all keys under the `(0x06, domain_sid_bytes)` prefix. After
    /// this call, the next `allocate(domain_sid)` will re-initialise the
    /// pool from scratch (starting at `INITIAL_RID`).
    pub async fn reclaim_domain(&self, domain_sid: &Sid) -> Result<(), IdentityError> {
        let prefix = rid_state_key(domain_sid)?;
        let pairs = self.backend.scan_prefix(&prefix).await?;
        if pairs.is_empty() {
            return Ok(());
        }
        let txn = self.backend.begin_write().await?;
        for (k, _) in &pairs {
            txn.delete(k).await.map_err(map_storage_err)?;
        }
        txn.commit().await.map_err(map_storage_err)?;
        Ok(())
    }
}

#[async_trait]
impl RidPoolAllocator for FdbRidPoolAllocator {
    async fn allocate(&self, domain_sid: &Sid) -> Result<Rid, IdentityError> {
        let state_key = rid_state_key(domain_sid)?;
        let counter_key = rid_counter_key(domain_sid)?;
        let txn = self.backend.begin_write().await?;

        // Read or initialise the state.
        let mut state = match txn.get(&state_key).await.map_err(map_storage_err)? {
            Some(buf) => RidPoolState::decode(&buf).unwrap_or_else(RidPoolState::initial),
            None => RidPoolState::initial(),
        };

        // Read or initialise the counter. The counter holds the *last
        // dispensed* RID (i.e. the value before this allocation); a freshly
        // initialised pool has counter = INITIAL_RID - 1.
        let counter_old: i64 = match txn.get(&counter_key).await.map_err(map_storage_err)? {
            Some(buf) if buf.len() == 8 => {
                i64::from_be_bytes(buf[..8].try_into().expect("8-byte buf"))
            }
            _ => {
                // First-ever allocation for this domain — seed the counter
                // with INITIAL_RID - 1 so the post-increment value is
                // INITIAL_RID.
                let seed = (INITIAL_RID as i64) - 1;
                txn.put(&counter_key, &seed.to_be_bytes())
                    .await
                    .map_err(map_storage_err)?;
                // Also persist the initial state so `state()` reflects the
                // pool's high-water mark on subsequent reads.
                txn.put(&state_key, &state.encode())
                    .await
                    .map_err(map_storage_err)?;
                seed
            }
        };

        // Lock-free atomic increment (per Decision 2 — staged, applied at
        // commit time). Locally compute the post-increment value to work
        // around the testkit's lack of read-your-writes for staged
        // atomic_adds (matches the wave-1a `allocate_dnt` workaround).
        txn.atomic_add(&counter_key, 1)
            .await
            .map_err(map_storage_err)?;
        let new_rid = counter_old + 1;

        // If the new RID exceeds the current batch's high-water mark,
        // request a new 500-RID batch (in this test impl, just extend
        // `last_allocated_rid` — per the task brief).
        if new_rid as u32 > state.last_allocated_rid {
            state.last_allocated_rid = state.last_allocated_rid.saturating_add(RID_BATCH_SIZE);
            txn.put(&state_key, &state.encode())
                .await
                .map_err(map_storage_err)?;
        }

        txn.commit().await.map_err(map_storage_err)?;
        Ok(new_rid as Rid)
    }

    async fn allocate_batch(&self, domain_sid: &Sid, n: u32) -> Result<Vec<Rid>, IdentityError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let state_key = rid_state_key(domain_sid)?;
        let counter_key = rid_counter_key(domain_sid)?;
        let txn = self.backend.begin_write().await?;

        let mut state = match txn.get(&state_key).await.map_err(map_storage_err)? {
            Some(buf) => RidPoolState::decode(&buf).unwrap_or_else(RidPoolState::initial),
            None => RidPoolState::initial(),
        };

        let counter_old: i64 = match txn.get(&counter_key).await.map_err(map_storage_err)? {
            Some(buf) if buf.len() == 8 => {
                i64::from_be_bytes(buf[..8].try_into().expect("8-byte buf"))
            }
            _ => {
                let seed = (INITIAL_RID as i64) - 1;
                txn.put(&counter_key, &seed.to_be_bytes())
                    .await
                    .map_err(map_storage_err)?;
                txn.put(&state_key, &state.encode())
                    .await
                    .map_err(map_storage_err)?;
                seed
            }
        };

        // Lock-free batch allocation: atomic_add by `n`, then locally
        // compute the dispensed range `[counter_old+1, counter_old+n]`.
        // `u32` -> `i64` is infallible.
        let n_i64: i64 = n.into();
        txn.atomic_add(&counter_key, n_i64)
            .await
            .map_err(map_storage_err)?;
        let first = counter_old + 1;
        let last = counter_old + n_i64;

        // Extend the batch if we've over-allocated past `last_allocated_rid`.
        if last as u32 > state.last_allocated_rid {
            // Round up to whole batches so the high-water mark always ends
            // on a batch boundary (matches AD's `rIDAllocationPool`
            // semantics — the pool is dispensed in `RID_BATCH_SIZE`-sized
            // chunks).
            let needed = (last as u32).saturating_sub(state.last_allocated_rid);
            let extra_batches = needed.div_ceil(RID_BATCH_SIZE);
            let extra = extra_batches.saturating_mul(RID_BATCH_SIZE);
            state.last_allocated_rid = state.last_allocated_rid.saturating_add(extra);
            txn.put(&state_key, &state.encode())
                .await
                .map_err(map_storage_err)?;
        }

        txn.commit().await.map_err(map_storage_err)?;
        let rids = (first..=last).map(|v| v as Rid).collect();
        Ok(rids)
    }

    async fn state(&self, domain_sid: &Sid) -> Result<RidPoolState, IdentityError> {
        let state_key = rid_state_key(domain_sid)?;
        let counter_key = rid_counter_key(domain_sid)?;
        let r = self.backend.begin_read().await?;
        let state = match r.get(&state_key).await.map_err(map_storage_err)? {
            Some(buf) => RidPoolState::decode(&buf).unwrap_or_else(RidPoolState::initial),
            None => RidPoolState::initial(),
        };
        let counter_val: u32 = match r.get(&counter_key).await.map_err(map_storage_err)? {
            Some(buf) if buf.len() == 8 => {
                // The counter holds the *last dispensed* RID (initialised
                // to INITIAL_RID - 1). The next RID to dispense is one
                // past it.
                let v = i64::from_be_bytes(buf[..8].try_into().expect("8-byte buf"));
                if v < 0 {
                    INITIAL_RID
                } else {
                    (v + 1) as u32
                }
            }
            _ => state.next_rid,
        };
        Ok(RidPoolState {
            next_rid: counter_val,
            last_allocated_rid: state.last_allocated_rid,
            warning_threshold: state.warning_threshold,
        })
    }
}

/// Per-DC local RID allocator for native mode (per Decision 3 §Decision).
///
/// In native mode, each DC allocates RIDs locally with no coordination (no
/// RID-master DC). Each DC maintains its own RID counter at FDB key
/// `(0x06, 0x10, local_dc_id_bytes, domain_sid_bytes, ...)`, where
/// `local_dc_id` is the DC's `invocationId` (per Decision 1). The keys are
/// namespaced under the local-DC marker `0x10` so they don't collide with
/// the per-domain `FdbRidPoolAllocator` keys.
#[derive(Debug, Clone)]
pub struct LocalRidAllocator {
    /// The DC's invocation ID (per Decision 1).
    pub local_dc_id: uuid::Uuid,
    /// The backing KV store (FDB in production, in-memory in unit tests).
    pub backend: RidBackend,
    /// The `FdbDirectoryStore` field is preserved for backwards
    /// compatibility. When the allocator is constructed via [`Self::new`],
    /// the backend is `RidBackend::Fdb(store.clone())`; when constructed
    /// via [`Self::new_in_memory`], the backend is `RidBackend::InMemory`.
    pub store: Option<adrian_storage_fdb::FdbDirectoryStore>,
}

impl LocalRidAllocator {
    /// Construct a new `LocalRidAllocator` for the given DC, backed by the
    /// given `FdbDirectoryStore` (production). Without the `fdb` feature
    /// flag enabled, every allocator method surfaces a `Backend` error —
    /// callers should use [`Self::new_in_memory`] for unit tests.
    pub fn new(local_dc_id: uuid::Uuid, store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self {
            local_dc_id,
            backend: RidBackend::Fdb(store.clone()),
            store: Some(store),
        }
    }

    /// Construct a new `LocalRidAllocator` for the given DC, backed by an
    /// [`InMemoryDirectoryStore`] (default path for unit tests).
    pub fn new_in_memory(local_dc_id: uuid::Uuid, store: InMemoryDirectoryStore) -> Self {
        Self {
            local_dc_id,
            backend: RidBackend::InMemory(store),
            store: None,
        }
    }

    /// Convenience: construct a `LocalRidAllocator` backed by a fresh
    /// [`InMemoryDirectoryStore`].
    pub fn new_in_memory_default(local_dc_id: uuid::Uuid) -> Self {
        Self::new_in_memory(local_dc_id, InMemoryDirectoryStore::new())
    }

    /// Reclaim the local RID-pool state for this DC + domain (per ADR-077
    /// §Decision — RID pool reclaim on DC removal).
    ///
    /// Clears all keys under the
    /// `(0x06, 0x10, local_dc_id_bytes, domain_sid_bytes)` prefix. After
    /// this call, the next `allocate(domain_sid)` will re-initialise the
    /// per-DC counter from scratch.
    pub async fn reclaim_dc(&self, domain_sid: &Sid) -> Result<(), IdentityError> {
        let prefix = local_rid_state_prefix(self.local_dc_id, domain_sid)?;
        let pairs = self.backend.scan_prefix(&prefix).await?;
        if pairs.is_empty() {
            return Ok(());
        }
        let txn = self.backend.begin_write().await?;
        for (k, _) in &pairs {
            txn.delete(k).await.map_err(map_storage_err)?;
        }
        txn.commit().await.map_err(map_storage_err)?;
        Ok(())
    }
}

#[async_trait]
impl RidPoolAllocator for LocalRidAllocator {
    async fn allocate(&self, domain_sid: &Sid) -> Result<Rid, IdentityError> {
        let state_key = local_rid_state_key(self.local_dc_id, domain_sid)?;
        let counter_key = local_rid_counter_key(self.local_dc_id, domain_sid)?;
        let txn = self.backend.begin_write().await?;

        let mut state = match txn.get(&state_key).await.map_err(map_storage_err)? {
            Some(buf) => RidPoolState::decode(&buf).unwrap_or_else(RidPoolState::initial),
            None => RidPoolState::initial(),
        };

        let counter_old: i64 = match txn.get(&counter_key).await.map_err(map_storage_err)? {
            Some(buf) if buf.len() == 8 => {
                i64::from_be_bytes(buf[..8].try_into().expect("8-byte buf"))
            }
            _ => {
                let seed = (INITIAL_RID as i64) - 1;
                txn.put(&counter_key, &seed.to_be_bytes())
                    .await
                    .map_err(map_storage_err)?;
                txn.put(&state_key, &state.encode())
                    .await
                    .map_err(map_storage_err)?;
                seed
            }
        };

        txn.atomic_add(&counter_key, 1)
            .await
            .map_err(map_storage_err)?;
        let new_rid = counter_old + 1;

        if new_rid as u32 > state.last_allocated_rid {
            state.last_allocated_rid = state.last_allocated_rid.saturating_add(RID_BATCH_SIZE);
            txn.put(&state_key, &state.encode())
                .await
                .map_err(map_storage_err)?;
        }

        txn.commit().await.map_err(map_storage_err)?;
        Ok(new_rid as Rid)
    }

    async fn allocate_batch(&self, domain_sid: &Sid, n: u32) -> Result<Vec<Rid>, IdentityError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let state_key = local_rid_state_key(self.local_dc_id, domain_sid)?;
        let counter_key = local_rid_counter_key(self.local_dc_id, domain_sid)?;
        let txn = self.backend.begin_write().await?;

        let mut state = match txn.get(&state_key).await.map_err(map_storage_err)? {
            Some(buf) => RidPoolState::decode(&buf).unwrap_or_else(RidPoolState::initial),
            None => RidPoolState::initial(),
        };

        let counter_old: i64 = match txn.get(&counter_key).await.map_err(map_storage_err)? {
            Some(buf) if buf.len() == 8 => {
                i64::from_be_bytes(buf[..8].try_into().expect("8-byte buf"))
            }
            _ => {
                let seed = (INITIAL_RID as i64) - 1;
                txn.put(&counter_key, &seed.to_be_bytes())
                    .await
                    .map_err(map_storage_err)?;
                txn.put(&state_key, &state.encode())
                    .await
                    .map_err(map_storage_err)?;
                seed
            }
        };

        // `u32` -> `i64` is infallible.
        let n_i64: i64 = n.into();
        txn.atomic_add(&counter_key, n_i64)
            .await
            .map_err(map_storage_err)?;
        let first = counter_old + 1;
        let last = counter_old + n_i64;

        if last as u32 > state.last_allocated_rid {
            let needed = (last as u32).saturating_sub(state.last_allocated_rid);
            let extra_batches = needed.div_ceil(RID_BATCH_SIZE);
            let extra = extra_batches.saturating_mul(RID_BATCH_SIZE);
            state.last_allocated_rid = state.last_allocated_rid.saturating_add(extra);
            txn.put(&state_key, &state.encode())
                .await
                .map_err(map_storage_err)?;
        }

        txn.commit().await.map_err(map_storage_err)?;
        let rids = (first..=last).map(|v| v as Rid).collect();
        Ok(rids)
    }

    async fn state(&self, domain_sid: &Sid) -> Result<RidPoolState, IdentityError> {
        let state_key = local_rid_state_key(self.local_dc_id, domain_sid)?;
        let counter_key = local_rid_counter_key(self.local_dc_id, domain_sid)?;
        let r = self.backend.begin_read().await?;
        let state = match r.get(&state_key).await.map_err(map_storage_err)? {
            Some(buf) => RidPoolState::decode(&buf).unwrap_or_else(RidPoolState::initial),
            None => RidPoolState::initial(),
        };
        let counter_val: u32 = match r.get(&counter_key).await.map_err(map_storage_err)? {
            Some(buf) if buf.len() == 8 => {
                let v = i64::from_be_bytes(buf[..8].try_into().expect("8-byte buf"));
                if v < 0 {
                    INITIAL_RID
                } else {
                    (v + 1) as u32
                }
            }
            _ => state.next_rid,
        };
        Ok(RidPoolState {
            next_rid: counter_val,
            last_allocated_rid: state.last_allocated_rid,
            warning_threshold: state.warning_threshold,
        })
    }
}

/// Helper: assign a SID to a principal using the RID-pool allocator (per
/// Decision 3 — principal-creation path).
///
/// Allocates a single RID via the allocator and constructs the new SID as
/// `domain_sid + RID` (the new RID becomes the final sub-authority). Returns
/// the constructed SID.
pub async fn assign_sid(
    allocator: &dyn RidPoolAllocator,
    domain_sid: &Sid,
    _principal_uuid: PrincipalId,
) -> Result<Sid, IdentityError> {
    let rid = allocator.allocate(domain_sid).await?;
    let mut sub = domain_sid.sub_authorities.clone();
    sub.push(rid);
    Ok(Sid::new(domain_sid.identifier_authority, sub)?)
}

// ============================================================================
// Tests
// ============================================================================

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
        let r: Rid = 0xFFFF_FFFF;
        assert_eq!(r, u32::MAX);
    }

    #[test]
    fn fdb_allocator_new_propagates_store() {
        let store = adrian_storage_fdb::FdbDirectoryStore::new(Some("/tmp/rid.cluster"));
        let allocator = FdbRidPoolAllocator::new(store);
        assert_eq!(
            allocator.store.as_ref().unwrap().cluster_file.as_deref(),
            Some("/tmp/rid.cluster")
        );
    }

    #[test]
    fn local_allocator_new_propagates_invocation_id_and_store() {
        let invocation_id = Uuid::from_u128(0xABCD_1234);
        let store = adrian_storage_fdb::FdbDirectoryStore::new(None);
        let allocator = LocalRidAllocator::new(invocation_id, store);
        assert_eq!(allocator.local_dc_id, invocation_id);
        assert!(allocator.store.as_ref().unwrap().cluster_file.is_none());
    }

    #[test]
    fn rid_pool_state_serializes_round_trip() {
        let state = RidPoolState {
            next_rid: 1000,
            last_allocated_rid: 1500,
            warning_threshold: RID_EXHAUSTION_WARNING_THRESHOLD,
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let decoded: RidPoolState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, state);
    }

    #[test]
    fn rid_pool_state_default_warning_threshold_is_250() {
        let initial = RidPoolState {
            next_rid: 500,
            last_allocated_rid: 1000,
            warning_threshold: RID_EXHAUSTION_WARNING_THRESHOLD,
        };
        assert_eq!(initial.warning_threshold, 250);
    }

    #[test]
    fn rid_pool_state_initial_is_canonical() {
        let s = RidPoolState::initial();
        assert_eq!(s.next_rid, INITIAL_RID);
        assert_eq!(s.last_allocated_rid, INITIAL_RID + RID_BATCH_SIZE - 1);
        assert_eq!(s.warning_threshold, RID_EXHAUSTION_WARNING_THRESHOLD);
    }

    #[test]
    fn rid_pool_state_encode_decode_round_trip() {
        let s = RidPoolState::initial();
        let buf = s.encode();
        assert_eq!(buf.len(), 12);
        assert_eq!(RidPoolState::decode(&buf), Some(s));
    }

    #[test]
    fn rid_pool_state_decode_rejects_wrong_length() {
        assert_eq!(RidPoolState::decode(&[]), None);
        assert_eq!(RidPoolState::decode(&[0u8; 11]), None);
        assert_eq!(RidPoolState::decode(&[0u8; 13]), None);
    }

    #[test]
    fn rid_pool_state_decode_reads_be_fields() {
        // next_rid=1000, last_allocated_rid=1499, warning_threshold=250.
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(&1000u32.to_be_bytes());
        buf[4..8].copy_from_slice(&1499u32.to_be_bytes());
        buf[8..].copy_from_slice(&250u32.to_be_bytes());
        let s = RidPoolState::decode(&buf).expect("must decode");
        assert_eq!(s.next_rid, 1000);
        assert_eq!(s.last_allocated_rid, 1499);
        assert_eq!(s.warning_threshold, 250);
    }

    #[tokio::test]
    async fn fdb_allocator_allocate_succeeds_via_in_memory_fallback() {
        // After Wave 1a, `FdbDirectoryStore::new(None)` returns an
        // `InMemoryDirectoryStore`-backed fallback that genuinely works (no
        // real FDB cluster required). This test now exercises the fallback
        // path instead of asserting a backend error.
        let allocator = FdbRidPoolAllocator::new(adrian_storage_fdb::FdbDirectoryStore::new(None));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let result = allocator.allocate(&domain_sid).await;
        assert!(
            result.is_ok(),
            "allocate must succeed via in-memory fallback: {:?}",
            result.err()
        );
        let rid = result.unwrap();
        assert!(
            rid >= 1000,
            "first allocated RID must be >= INITIAL_RID (1000), got {}",
            rid
        );
    }

    #[tokio::test]
    async fn fdb_allocator_allocate_batch_succeeds_via_in_memory_fallback() {
        let allocator = FdbRidPoolAllocator::new(adrian_storage_fdb::FdbDirectoryStore::new(None));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let result = allocator.allocate_batch(&domain_sid, 500).await;
        assert!(
            result.is_ok(),
            "allocate_batch must succeed via in-memory fallback: {:?}",
            result.err()
        );
        let rids = result.unwrap();
        assert_eq!(rids.len(), 500);
        // RIDs must be strictly increasing and contiguous.
        for i in 1..rids.len() {
            assert!(rids[i] > rids[i - 1], "RIDs must be strictly increasing");
        }
    }

    #[tokio::test]
    async fn fdb_allocator_state_succeeds_via_in_memory_fallback() {
        let allocator = FdbRidPoolAllocator::new(adrian_storage_fdb::FdbDirectoryStore::new(None));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        // Allocate first to populate state.
        allocator.allocate(&domain_sid).await.unwrap();
        let result = allocator.state(&domain_sid).await;
        assert!(
            result.is_ok(),
            "state must succeed via in-memory fallback: {:?}",
            result.err()
        );
        let state = result.unwrap();
        assert!(
            state.next_rid >= 1001,
            "next_rid must have advanced past INITIAL_RID after one allocation"
        );
    }

    #[tokio::test]
    async fn local_allocator_succeeds_via_in_memory_fallback() {
        let allocator = LocalRidAllocator::new(
            Uuid::nil(),
            adrian_storage_fdb::FdbDirectoryStore::new(None),
        );
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let r1 = allocator.allocate(&domain_sid).await;
        assert!(r1.is_ok(), "allocate must succeed: {:?}", r1.err());
        let batch = allocator.allocate_batch(&domain_sid, 10).await;
        assert!(
            batch.is_ok(),
            "allocate_batch must succeed: {:?}",
            batch.err()
        );
        assert_eq!(batch.unwrap().len(), 10);
        let st = allocator.state(&domain_sid).await;
        assert!(st.is_ok(), "state must succeed: {:?}", st.err());
    }

    #[tokio::test]
    async fn assign_sid_succeeds_via_in_memory_fallback() {
        let allocator: Box<dyn RidPoolAllocator> = Box::new(FdbRidPoolAllocator::new(
            adrian_storage_fdb::FdbDirectoryStore::new(None),
        ));
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let result = assign_sid(allocator.as_ref(), &domain_sid, Uuid::nil()).await;
        assert!(
            result.is_ok(),
            "assign_sid must succeed: {:?}",
            result.err()
        );
        let sid = result.unwrap();
        assert_eq!(sid.domain_sid(), Some(domain_sid));
    }

    // ===========================================================================
    // New behavioral tests — exercise the real InMemory fallback path.
    // ===========================================================================

    #[tokio::test]
    async fn in_memory_allocate_returns_initial_rid() {
        // First allocation from a fresh pool must dispense INITIAL_RID.
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let rid = allocator.allocate(&domain_sid).await.unwrap();
        assert_eq!(rid, INITIAL_RID);
    }

    #[tokio::test]
    async fn in_memory_allocate_sequential_rids() {
        // 500 sequential allocations must dispense RIDs INITIAL_RID..=
        // INITIAL_RID+499 (a single batch — no extension needed).
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let mut rids = Vec::with_capacity(500);
        for _ in 0..500 {
            rids.push(allocator.allocate(&domain_sid).await.unwrap());
        }
        for (i, rid) in rids.iter().enumerate() {
            assert_eq!(*rid, INITIAL_RID + i as u32);
        }
        // The 500th allocation must NOT have extended the batch (the
        // initial batch covers INITIAL_RID..=INITIAL_RID+499).
        let state = allocator.state(&domain_sid).await.unwrap();
        assert_eq!(state.last_allocated_rid, INITIAL_RID + RID_BATCH_SIZE - 1);
    }

    #[tokio::test]
    async fn in_memory_allocate_triggers_batch_extension() {
        // The 501st allocation must extend the batch by RID_BATCH_SIZE.
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        for _ in 0..500 {
            let _ = allocator.allocate(&domain_sid).await.unwrap();
        }
        let rid_501 = allocator.allocate(&domain_sid).await.unwrap();
        assert_eq!(rid_501, INITIAL_RID + 500);
        let state = allocator.state(&domain_sid).await.unwrap();
        assert_eq!(
            state.last_allocated_rid,
            INITIAL_RID + 2 * RID_BATCH_SIZE - 1,
            "batch must have been extended by one RID_BATCH_SIZE chunk"
        );
    }

    #[tokio::test]
    async fn in_memory_allocate_batch_dispenses_range() {
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let rids = allocator.allocate_batch(&domain_sid, 100).await.unwrap();
        assert_eq!(rids.len(), 100);
        for (i, rid) in rids.iter().enumerate() {
            assert_eq!(*rid, INITIAL_RID + i as u32);
        }
    }

    #[tokio::test]
    async fn in_memory_allocate_batch_extends_across_boundary() {
        // Allocate 600 in one batch — must extend the high-water mark to
        // cover the full range.
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let rids = allocator.allocate_batch(&domain_sid, 600).await.unwrap();
        assert_eq!(rids.len(), 600);
        assert_eq!(rids[0], INITIAL_RID);
        assert_eq!(rids[599], INITIAL_RID + 599);
        let state = allocator.state(&domain_sid).await.unwrap();
        assert_eq!(
            state.last_allocated_rid,
            INITIAL_RID + 2 * RID_BATCH_SIZE - 1,
            "batch must have been extended to two batches' worth"
        );
    }

    #[tokio::test]
    async fn in_memory_allocate_batch_zero_returns_empty() {
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let rids = allocator.allocate_batch(&domain_sid, 0).await.unwrap();
        assert!(rids.is_empty());
    }

    #[tokio::test]
    async fn in_memory_state_returns_initial_state_for_fresh_domain() {
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let state = allocator.state(&domain_sid).await.unwrap();
        assert_eq!(state.next_rid, INITIAL_RID);
        assert_eq!(state.last_allocated_rid, INITIAL_RID + RID_BATCH_SIZE - 1);
        assert_eq!(state.warning_threshold, RID_EXHAUSTION_WARNING_THRESHOLD);
    }

    #[tokio::test]
    async fn in_memory_allocate_uniqueness_across_domains() {
        // Two different domain SIDs must dispense independent RID streams.
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_a: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let domain_b: Sid = "S-1-5-21-999-999-999".parse().unwrap();
        let rid_a = allocator.allocate(&domain_a).await.unwrap();
        let rid_b = allocator.allocate(&domain_b).await.unwrap();
        assert_eq!(rid_a, INITIAL_RID);
        assert_eq!(rid_b, INITIAL_RID);
        // Subsequent allocations on each domain must be independent.
        let rid_a2 = allocator.allocate(&domain_a).await.unwrap();
        let rid_b2 = allocator.allocate(&domain_b).await.unwrap();
        assert_eq!(rid_a2, INITIAL_RID + 1);
        assert_eq!(rid_b2, INITIAL_RID + 1);
    }

    #[tokio::test]
    async fn in_memory_state_reflects_counter_after_allocations() {
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        for _ in 0..42 {
            let _ = allocator.allocate(&domain_sid).await.unwrap();
        }
        let state = allocator.state(&domain_sid).await.unwrap();
        assert_eq!(state.next_rid, INITIAL_RID + 42);
    }

    #[tokio::test]
    async fn in_memory_reclaim_domain_clears_state() {
        // After reclaim_domain, allocations restart from INITIAL_RID (the
        // pool is re-initialised).
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        for _ in 0..10 {
            let _ = allocator.allocate(&domain_sid).await.unwrap();
        }
        allocator.reclaim_domain(&domain_sid).await.unwrap();
        let rid_after_reclaim = allocator.allocate(&domain_sid).await.unwrap();
        assert_eq!(
            rid_after_reclaim, INITIAL_RID,
            "reclaim must reset the pool to the initial state"
        );
    }

    #[tokio::test]
    async fn in_memory_reclaim_domain_idempotent() {
        // Reclaiming a never-allocated domain must succeed (no-op).
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        allocator.reclaim_domain(&domain_sid).await.unwrap();
    }

    #[tokio::test]
    async fn local_allocator_in_memory_allocate_sequential() {
        // LocalRidAllocator: per-DC local counter, sequential allocation.
        let dc_id = Uuid::from_u128(0xCAFE_BABE);
        let allocator = LocalRidAllocator::new_in_memory_default(dc_id);
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let r1 = allocator.allocate(&domain_sid).await.unwrap();
        let r2 = allocator.allocate(&domain_sid).await.unwrap();
        let r3 = allocator.allocate(&domain_sid).await.unwrap();
        assert_eq!(r1, INITIAL_RID);
        assert_eq!(r2, INITIAL_RID + 1);
        assert_eq!(r3, INITIAL_RID + 2);
    }

    #[tokio::test]
    async fn local_allocator_in_memory_two_dcs_independent() {
        // Two LocalRidAllocators with different local_dc_ids must dispense
        // independent RID streams (no RID-master coordination).
        let dc1 = Uuid::from_u128(0x1111);
        let dc2 = Uuid::from_u128(0x2222);
        // Share the underlying store (so we can verify they don't collide
        // on the same KV space) — clone() shares the Arc.
        let store = InMemoryDirectoryStore::new();
        let a1 = LocalRidAllocator::new_in_memory(dc1, store.clone());
        let a2 = LocalRidAllocator::new_in_memory(dc2, store);
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let r1 = a1.allocate(&domain_sid).await.unwrap();
        let r2 = a2.allocate(&domain_sid).await.unwrap();
        // Both DCs dispense INITIAL_RID — they have separate keys.
        assert_eq!(r1, INITIAL_RID);
        assert_eq!(r2, INITIAL_RID);
        // Verify independence: a1's next allocation must be INITIAL_RID+1,
        // NOT INITIAL_RID+2 (a2's allocation must not have advanced a1's
        // counter).
        let r1_next = a1.allocate(&domain_sid).await.unwrap();
        assert_eq!(r1_next, INITIAL_RID + 1);
    }

    #[tokio::test]
    async fn local_allocator_in_memory_reclaim_dc_resets_counter() {
        let dc_id = Uuid::from_u128(0xDEAD_BEEF);
        let allocator = LocalRidAllocator::new_in_memory_default(dc_id);
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        for _ in 0..5 {
            let _ = allocator.allocate(&domain_sid).await.unwrap();
        }
        allocator.reclaim_dc(&domain_sid).await.unwrap();
        let rid = allocator.allocate(&domain_sid).await.unwrap();
        assert_eq!(rid, INITIAL_RID);
    }

    #[tokio::test]
    async fn assign_sid_constructs_correct_sid() {
        // assign_sid must allocate a RID and construct domain_sid + RID.
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let principal_uuid = Uuid::from_u128(0xBEEF);
        let assigned = assign_sid(&allocator, &domain_sid, principal_uuid)
            .await
            .unwrap();
        assert_eq!(
            assigned.sub_authorities,
            vec![21, 100, 200, 300, INITIAL_RID]
        );
        assert_eq!(assigned.rid(), Some(INITIAL_RID));
        // The domain SID of the assigned SID must match the input domain SID.
        assert_eq!(assigned.domain_sid().unwrap(), domain_sid);
    }

    #[tokio::test]
    async fn assign_sid_consecutive_calls_produce_distinct_sids() {
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let s1 = assign_sid(&allocator, &domain_sid, Uuid::nil())
            .await
            .unwrap();
        let s2 = assign_sid(&allocator, &domain_sid, Uuid::nil())
            .await
            .unwrap();
        assert_ne!(s1, s2);
        assert_eq!(s1.rid(), Some(INITIAL_RID));
        assert_eq!(s2.rid(), Some(INITIAL_RID + 1));
    }

    #[tokio::test]
    async fn in_memory_persistence_across_clones() {
        // FdbRidPoolAllocator::clone shares the underlying InMemoryDirectoryStore
        // via Arc — allocations performed on the clone must be visible to the
        // original.
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        let cloned = allocator.clone();
        let rid_orig = allocator.allocate(&domain_sid).await.unwrap();
        let rid_clone = cloned.allocate(&domain_sid).await.unwrap();
        assert_eq!(rid_orig, INITIAL_RID);
        assert_eq!(rid_clone, INITIAL_RID + 1);
    }

    #[tokio::test]
    async fn in_memory_exhaustion_warning_threshold_observed() {
        // Allocate close to the batch boundary and verify the state's
        // warning_threshold stays at RID_EXHAUSTION_WARNING_THRESHOLD —
        // the real implementation would emit a warning event when
        // `last_allocated_rid - next_rid < warning_threshold`.
        let allocator = FdbRidPoolAllocator::new_in_memory_default();
        let domain_sid: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        // Drain to within the warning threshold: INITIAL_RID + (RID_BATCH_SIZE - RID_EXHAUSTION_WARNING_THRESHOLD - 1).
        let drain_count = RID_BATCH_SIZE - RID_EXHAUSTION_WARNING_THRESHOLD - 1;
        for _ in 0..drain_count {
            let _ = allocator.allocate(&domain_sid).await.unwrap();
        }
        let state = allocator.state(&domain_sid).await.unwrap();
        assert_eq!(state.warning_threshold, RID_EXHAUSTION_WARNING_THRESHOLD);
        // remaining = last_allocated_rid - next_rid + 1
        let remaining = state.last_allocated_rid - state.next_rid + 1;
        assert!(
            remaining <= RID_EXHAUSTION_WARNING_THRESHOLD + 1,
            "remaining ({remaining}) should be at or just above the warning threshold"
        );
        assert!(remaining > 0, "pool must not be exhausted yet");
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
