//! # adrian-storage-core
//!
//! Core directory storage traits and types for the Adrian framework.
//!
//! This crate defines the fundamental abstractions that every storage backend
//! must implement. The primary trait is [`DirectoryStore`], which provides
//! transactional CRUD operations on directory objects backed by an ordered
//! key-value store.
//!
//! ## ADRs
//!
//! - ADR-073: FoundationDB as sole storage engine (Decision 2)
//! - ADR-001: Linked Value Replication (link-value store, `linktable` subspace)
//! - ADR-002: `memberOf` as DSA-computed back-link
//! - ADR-003: Schema cache with copy-on-write generations
//! - ADR-004: Security descriptor deduplication (`sdtable` subspace)
//! - ADR-009: Constructed attributes (`tokenGroups` cache strategy)
//! - ADR-074: Tombstone lifetime and lingering objects
//!
//! ## Layer
//!
//! Layer 0 — foundation (no internal dependencies). Consumed by every layer
//! above. Only one implementation ships in v1 ([`FdbDirectoryStore`] in
//! `adrian-storage-fdb`); a future `RocksdbDirectoryStore` for air-gapped edge
//! deployments is gated by v2 demand (per ADR-073 §Decision).
//!
//! [`FdbDirectoryStore`]: https://docs.rs/adrian-storage-fdb/

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A directory number tag (DNT) — equivalent to AD's `DNT` column. A 64-bit
/// internal identifier used as the FDB tuple-layer primary key for every
/// directory object (per ADR-073 §Decision, key encoding `(subspace, dnt,
/// attribute_id, value_index) → value_bytes`).
pub type Dnt = u64;

/// A 32-bit attribute identifier — the schema's `attributeID` integer (per
/// ADR-003).
pub type AttributeId = u32;

/// A 32-bit value index for multi-valued attributes (0 for single-valued).
pub type ValueIndex = u32;

/// FDB subspace identifiers (per ADR-073 §Decision and Decision 2 §Decision).
///
/// The subspaces 0x01-0x0F are reserved for primary data (per-attribute
/// values, linktable, sdtable, etc.); subspaces 0x10-0x1F are reserved for
/// framework-internal indexes that accelerate lookups but are derivable
/// from the primary subspaces (per ADR-073 §Decision, key encoding
/// `(subspace, dnt, attribute_id, value_index) → value_bytes`). Subspaces
/// 0x20+ are reserved for future expansion.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Subspace {
    /// `0x01` — directory objects (per-attribute-value rows).
    Objects = 0x01,
    /// `0x02` — link-value store (forward and reverse indexes, per ADR-001).
    LinkTable = 0x02,
    /// `0x03` — security-descriptor dedup table (per ADR-004).
    SdTable = 0x03,
    /// `0x04` — schema-cache generations (per ADR-003).
    SchemaCache = 0x04,
    /// `0x05` — up-to-dateness vector store (per ADR-071).
    UtdVector = 0x05,
    /// `0x06` — RID pool allocator state (per Decision 3).
    RidPool = 0x06,
    /// `0x07` — tombstones (per ADR-074).
    Tombstones = 0x07,
    /// `0x08` — audit log (per ADR-060).
    AuditLog = 0x08,
    /// `0x09` — CA database (per ADR-034).
    CaDb = 0x09,
    /// `0x0A` — Sigstore Rekor entries (per ADR-067).
    Sigstore = 0x0A,
    /// `0x0B` — Federation Gateway trust store and JWKS cache.
    Federation = 0x0B,
    /// `0x0C` — File Gateway share-ACL cache.
    FileGateway = 0x0C,
    /// `0x0D` — identity mapping table (UUID ↔ SID, per Decision 3).
    IdentityMapping = 0x0D,
    /// `0x0E` — `memberOf` materialised cache (per ADR-002).
    MemberOfCache = 0x0E,
    /// `0x0F` — `tokenGroups` constructed-attribute cache (per ADR-009).
    TokenGroupsCache = 0x0F,
    /// `0x10` — UUID → DNT index (per ADR-073 — primary-key lookup of the
    /// DNT for a given object UUID).
    ObjectUuidIndex = 0x10,
    /// `0x11` — DN → DNT index (per ADR-073 — secondary lookup of the DNT
    /// for a given distinguished name).
    ObjectDnIndex = 0x11,
}

/// Sentinel attribute ID reserved for the DNT counter row in the `0x01`
/// (Objects) subspace. Per ADR-073, the DNT counter is stored at the key
/// `(0x01, 0xFF, "next_dnt")` and updated via FDB's `AtomicOp::Add`.
///
/// The byte layout of the DNT counter key is:
/// `[0x01][0xFF 0xFF 0xFF 0xFF (attr_id sentinel)][b"next_dnt"]`.
pub const DNT_COUNTER_SENTINEL_ATTR: AttributeId = 0xFFFF_FFFF;

/// The literal name suffix of the DNT counter key, per ADR-073.
pub const DNT_COUNTER_NAME: &[u8] = b"next_dnt";

/// Sentinel attribute ID used to store the object's DN as a row in the
/// `0x01` Objects subspace (so that the DN travels with the object's other
/// attributes and is read back in the same range scan). The DN value is
/// stored UTF-8-encoded in the row's value bytes.
pub const DN_ATTR_SENTINEL: AttributeId = 0xFFFF_FFFE;

/// Sentinel attribute ID used to store the object's UUID as a row in the
/// `0x01` Objects subspace. The UUID value is stored as 16 raw bytes.
pub const UUID_ATTR_SENTINEL: AttributeId = 0xFFFF_FFFD;

/// Sentinel attribute ID used to store the object's DNT as a self-reference
/// row in the `0x01` Objects subspace (so that the range scan returns at
/// least one row even for an object with zero user-visible attributes,
/// guaranteeing that `get(uuid)` returns `Some(obj)` rather than `None`).
pub const DNT_ATTR_SENTINEL: AttributeId = 0xFFFF_FFFC;

/// A half-open byte range `[begin, end)` for FDB range reads (per ADR-073
/// §Decision — `Transaction::get_range(begin, end)`).
///
/// Range reads are the primary mechanism for scanning an entire object's
/// attribute rows: the caller constructs a `KeyRange` from a subspace prefix
/// (via [`KeyRange::prefix`]) and the backend returns all key-value pairs
/// whose keys fall in `[begin, end)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyRange {
    /// The inclusive begin key.
    pub begin: Vec<u8>,
    /// The exclusive end key.
    pub end: Vec<u8>,
}

impl KeyRange {
    /// Construct a new `KeyRange` from explicit begin/end byte slices.
    pub fn new(begin: impl Into<Vec<u8>>, end: impl Into<Vec<u8>>) -> Self {
        Self {
            begin: begin.into(),
            end: end.into(),
        }
    }

    /// Construct a `KeyRange` that covers all keys with the given prefix
    /// (per FDB's `range::Range::strinc` semantics — i.e. the end key is
    /// the prefix with its last byte incremented; if the last byte is
    /// `0xFF`, the algorithm carries into earlier bytes). Returns `None`
    /// when the prefix is all `0xFF` bytes (in which case there is no
    /// finite end key and a full-scan range must be used instead).
    pub fn prefix(prefix: &[u8]) -> Option<Self> {
        let end = strinc(prefix)?;
        Some(Self {
            begin: prefix.to_vec(),
            end,
        })
    }
}

/// FDB `strinc` — compute the smallest byte string strictly greater than
/// all strings beginning with `prefix` (per FDB's tuple-layer range
/// semantics). Returns `None` if `prefix` is empty or all `0xFF` bytes.
fn strinc(prefix: &[u8]) -> Option<Vec<u8>> {
    if prefix.is_empty() {
        return None;
    }
    let mut out = prefix.to_vec();
    // Walk back from the last byte, incrementing. If a byte is 0xFF, set
    // it to 0x00 and carry into the previous byte. If we run off the
    // beginning (all 0xFF), there is no finite end key.
    for i in (0..out.len()).rev() {
        if out[i] != 0xFF {
            out[i] += 1;
            out.truncate(i + 1);
            return Some(out);
        }
    }
    None
}

/// A distinguished name (DN) per RFC 4514 — the human-readable, hierarchical
/// identifier of a directory object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DistinguishedName {
    /// The DN string in RFC 4514 canonical form (e.g.
    /// `CN=Administrator,CN=Users,DC=adrian,DC=example,DC=com`).
    pub dn: String,
}

impl DistinguishedName {
    /// Construct a new DN from a string. Does not validate; validation is the
    /// schema-cache layer's responsibility (per ADR-003).
    pub fn new(dn: impl Into<String>) -> Self {
        Self { dn: dn.into() }
    }

    /// Return the parent DN (the DN with the leftmost RDN stripped), or `None`
    /// if this DN is a domain root (e.g. `DC=com`).
    pub fn parent(&self) -> Option<Self> {
        // TODO: implement per ADR-005 (well-known container GUIDs) — RFC 4514
        // parent computation with case-insensitive RDN parsing.
        let idx = self.dn.find(',')?;
        Some(Self {
            dn: self.dn[idx + 1..].to_string(),
        })
    }
}

impl std::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.dn)
    }
}

impl std::str::FromStr for DistinguishedName {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: validate per RFC 4514 + ADR-005 well-known container GUIDs.
        Ok(Self::new(s))
    }
}

/// A single (attribute, value) pair on a directory object. Multi-valued
/// attributes are represented as multiple `Attribute` entries on the same
/// `Object`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    /// The schema `attributeID` for this attribute (per ADR-003).
    pub attribute_id: AttributeId,
    /// The LDAP attribute name (e.g. `cn`, `member`, `objectSid`).
    pub name: String,
    /// The raw value bytes (FDB tuple-layer encoded for typed values).
    pub value: Vec<u8>,
}

/// A directory object identified by UUIDv7 and DN.
///
/// Per Decision 3, the UUID is the framework's internal primary key; the SID
/// is stored as a first-class attribute (`objectSid`). Per ADR-001, linked
/// attributes (e.g. `member`) are stored in the link-value store (`0x02`
/// subspace) rather than as inline values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    /// UUIDv7 primary key (per Decision 3).
    pub uuid: Uuid,
    /// The object's distinguished name.
    pub dn: DistinguishedName,
    /// The object's scalar attribute values. Linked attributes are stored in
    /// the `linktable` subspace (per ADR-001) and surfaced as constructed
    /// attributes on read.
    pub attributes: Vec<Attribute>,
    /// The object's DNT (directory number tag, per ADR-073). Stable for the
    /// lifetime of the object; assigned by `FdbDirectoryStore::put` via an
    /// atomic-add counter on first insert.
    pub dnt: Dnt,
}

/// Error type for storage operations.
///
/// Per Decision 2 §Error handling, the error taxonomy distinguishes
/// *transient* errors (transaction conflicts, timeouts — retried
/// automatically by `FdbDirectoryStore`) from *permanent* errors (cluster
/// unavailable, schema corruption — surfaced to the caller).
#[derive(Debug, Error)]
pub enum StorageError {
    /// Object not found (read returned no rows for the given UUID/DN).
    #[error("object not found: {0}")]
    NotFound(String),
    /// Transaction conflict (FDB error 1020 `not_committed`). Retried
    /// automatically by `FdbDirectoryStore`'s retry loop; surfaced only if
    /// the retry budget is exhausted.
    #[error("transaction conflict")]
    Conflict,
    /// Transaction too old (FDB error 1007 `transaction_too_old`). Retried
    /// automatically.
    #[error("transaction too old")]
    TooOld,
    /// Schema validation failed (per ADR-003 / ADR-078).
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    /// Link-value-store integrity violation (per ADR-001).
    #[error("link-value-store integrity: {0}")]
    LinkIntegrity(String),
    /// SD-dedup reference-count corruption (per ADR-004).
    #[error("sdtable corruption: {0}")]
    SdCorruption(String),
    /// Backend error (FDB cluster unavailable, network, etc.).
    #[error("backend error: {0}")]
    Backend(String),
}

/// A read-only transaction snapshot (per ADR-073 §Decision, FDB snapshots are
/// read-only transactions that do not acquire read versions).
#[async_trait]
pub trait ReadTxn: Send + Sync {
    /// Read a single key.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;
    /// Read a range of keys.
    async fn get_range(
        &self,
        begin: &[u8],
        end: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;
}

/// A read-write transaction (per ADR-073 §Decision).
#[async_trait]
pub trait WriteTxn: ReadTxn {
    /// Write a single key-value pair.
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    /// Delete a single key.
    async fn delete(&self, key: &[u8]) -> Result<(), StorageError>;
    /// Atomic add (per Decision 2 — used for RID-pool allocation and DNT
    /// counter).
    async fn atomic_add(&self, key: &[u8], value: i64) -> Result<(), StorageError>;
    /// Commit the transaction.
    async fn commit(self: Box<Self>) -> Result<(), StorageError>;
    /// Rollback the transaction (drop all writes).
    async fn rollback(self: Box<Self>) -> Result<(), StorageError>;
}

/// Core storage trait that every backend must implement.
///
/// Implementations:
/// - `FdbDirectoryStore` in `adrian-storage-fdb` (FoundationDB, per ADR-073)
/// - `InMemoryDirectoryStore` in `adrian-storage-testkit` (unit tests)
///
/// Per ADR-073, FoundationDB is the sole storage engine for v1. The trait is
/// the v2 seam where `RocksdbDirectoryStore` would slot in (gated by real
/// customer demand for air-gapped edge deployments).
#[async_trait]
pub trait DirectoryStore: Send + Sync {
    /// Read an object by UUID.
    async fn get(&self, uuid: Uuid) -> Result<Option<Object>, StorageError>;

    /// Read an object by DN.
    async fn get_by_dn(&self, dn: &DistinguishedName) -> Result<Option<Object>, StorageError>;

    /// Create or update an object. Assigns a DNT on first insert via an
    /// atomic-add counter (per ADR-073).
    async fn put(&self, obj: &Object) -> Result<(), StorageError>;

    /// Delete an object. Per ADR-074, the object is moved to the `0x07`
    /// tombstones subspace (not hard-deleted) and is garbage-collected after
    /// `tombstoneLifetime` (default 180 days).
    async fn delete(&self, uuid: Uuid) -> Result<(), StorageError>;

    /// Begin a read transaction (snapshot).
    async fn begin_read(&self) -> Result<Box<dyn ReadTxn>, StorageError>;

    /// Begin a write transaction.
    async fn begin_write(&self) -> Result<Box<dyn WriteTxn>, StorageError>;

    /// Return a snapshot view of the store for read-only transactions (per
    /// ADR-073).
    fn snapshot(&self) -> Box<dyn DirectoryStore>;
}

// ---- Tuple-layer key encoding (per ADR-073 §Decision) ----
//
// The FDB key encoding for directory rows is a fixed-width, big-endian,
// byte-concatenated tuple of `(subspace, dnt, attribute_id, value_index)`.
// Fixed-width encoding is chosen over the `foundationdb` crate's built-in
// `TuplePack` for three reasons:
//   1. The encoding must work in pure Rust (no FDB dependency) for the
//      `adrian-storage-fdb` fallback path that wraps `InMemoryDirectoryStore`
//      from `adrian-storage-testkit`. The `foundationdb::tuple` module is
//      only available behind the `fdb` feature flag.
//   2. Fixed-width big-endian concatenation sorts identically to FDB's
//      tuple-layer encoding for `u64` / `u32` types, so range scans return
//      rows in the same order as a real FDB backend.
//   3. The encoding is deterministic and easy to test in isolation, without
//      needing to bootstrap a full FDB client.
//
// The `foundationdb` crate's `TuplePack` may be adopted in a future wave
// once the schema-cache layer (ADR-003) requires heterogeneous value types
// (strings, nested tuples, etc.) — see ADR-073 §Open Questions.

/// Encode an FDB tuple key for a per-attribute-value row in the `0x01`
/// (Objects) subspace, per ADR-073 §Decision.
///
/// Key layout (17 bytes total, big-endian):
/// `[subspace (1)][dnt (8)][attribute_id (4)][value_index (4)]`
///
/// The corresponding value bytes are the raw attribute value (or, for the
/// sentinel attribute IDs [`UUID_ATTR_SENTINEL`] / [`DN_ATTR_SENTINEL`] /
/// [`DNT_ATTR_SENTINEL`], a self-reference row that ensures the range scan
/// returns at least one row per object).
pub fn encode_object_key(
    subspace: Subspace,
    dnt: Dnt,
    attribute_id: AttributeId,
    value_index: ValueIndex,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 4 + 4);
    out.push(subspace as u8);
    out.extend_from_slice(&dnt.to_be_bytes());
    out.extend_from_slice(&attribute_id.to_be_bytes());
    out.extend_from_slice(&value_index.to_be_bytes());
    out
}

/// Decode an FDB tuple key for a per-attribute-value row in the `0x01`
/// (Objects) subspace. Returns `None` if the key is not exactly 17 bytes
/// long or if the leading subspace byte does not match the expected value.
#[allow(clippy::missing_panics_doc)] // the slice lengths are statically known
pub fn decode_object_key(
    key: &[u8],
    expected_subspace: Subspace,
) -> Option<(Dnt, AttributeId, ValueIndex)> {
    if key.len() != 17 || key[0] != expected_subspace as u8 {
        return None;
    }
    let dnt = u64::from_be_bytes(key[1..9].try_into().ok()?);
    let attribute_id = u32::from_be_bytes(key[9..13].try_into().ok()?);
    let value_index = u32::from_be_bytes(key[13..17].try_into().ok()?);
    Some((dnt, attribute_id, value_index))
}

/// Encode the 9-byte prefix `(subspace, dnt)` used for range scans of all
/// attribute rows belonging to a given object (per ADR-073 §Decision —
/// `Transaction::get_range` over the prefix).
pub fn encode_object_prefix(subspace: Subspace, dnt: Dnt) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(subspace as u8);
    out.extend_from_slice(&dnt.to_be_bytes());
    out
}

/// Encode the DNT counter key `(0x01, 0xFF, "next_dnt")` per ADR-073
/// §Decision. The counter is incremented atomically via
/// `Transaction::atomic_op(AtomicOp::Add)` on first insert of a new object.
///
/// Key layout (13 bytes): `[0x01][0xFF 0xFF 0xFF 0xFF][b"next_dnt" (8)]`
pub fn encode_dnt_counter_key() -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + DNT_COUNTER_NAME.len());
    out.push(Subspace::Objects as u8);
    out.extend_from_slice(&DNT_COUNTER_SENTINEL_ATTR.to_be_bytes());
    out.extend_from_slice(DNT_COUNTER_NAME);
    out
}

/// Encode the UUID→DNT index key in subspace `0x10`, per ADR-073 §Decision.
///
/// Key layout (17 bytes): `[0x10][uuid (16)]` → value: 8-byte big-endian DNT.
pub fn encode_uuid_index_key(uuid: Uuid) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16);
    out.push(Subspace::ObjectUuidIndex as u8);
    out.extend_from_slice(uuid.as_bytes());
    out
}

/// Decode the 16-byte UUID from a UUID→DNT index key. Returns `None` if the
/// key is not exactly 17 bytes long or does not start with the `0x10`
/// subspace byte.
pub fn decode_uuid_index_key(key: &[u8]) -> Option<Uuid> {
    if key.len() != 17 || key[0] != Subspace::ObjectUuidIndex as u8 {
        return None;
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&key[1..17]);
    Some(Uuid::from_bytes(bytes))
}

/// Encode the DN→DNT index key in subspace `0x11`, per ADR-073 §Decision.
///
/// Key layout: `[0x11][dn_utf8_bytes]` → value: 8-byte big-endian DNT.
pub fn encode_dn_index_key(dn: &DistinguishedName) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + dn.dn.len());
    out.push(Subspace::ObjectDnIndex as u8);
    out.extend_from_slice(dn.dn.as_bytes());
    out
}

/// Encode a forward-link row key in the `0x02` (LinkTable) subspace, per
/// ADR-001 §Decision. The forward-link subspace is keyed by the originating
/// (link-holding) object's DNT, so a range scan over `(0x02, link_dnt, *)`
/// returns every outgoing link from `link_dnt`.
///
/// Key layout (22 bytes): `[0x02][0x00 (forward marker)][link_dnt (8)]
/// [link_id (4)][backlink_dnt (8)]`
pub fn encode_link_forward_key(
    link_dnt: Dnt,
    link_id: AttributeId,
    backlink_dnt: Dnt,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8 + 4 + 8);
    out.push(Subspace::LinkTable as u8);
    out.push(LINK_FORWARD_MARKER);
    out.extend_from_slice(&link_dnt.to_be_bytes());
    out.extend_from_slice(&link_id.to_be_bytes());
    out.extend_from_slice(&backlink_dnt.to_be_bytes());
    out
}

/// Encode a reverse-link row key in the `0x02` (LinkTable) subspace, per
/// ADR-001 §Decision. The reverse-link subspace is keyed by the backlink
/// target's DNT, so a range scan over `(0x02, backlink_dnt, 0x01, *)` returns
/// every `memberOf`-style reverse link pointing AT `backlink_dnt` — i.e.
/// the answer to "which groups contain this user as a member?".
///
/// Key layout (22 bytes): `[0x02][0x01 (reverse marker)][backlink_dnt (8)]
/// [link_id (4)][link_dnt (8)]`
pub fn encode_link_reverse_key(
    backlink_dnt: Dnt,
    link_id: AttributeId,
    link_dnt: Dnt,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 8 + 4 + 8);
    out.push(Subspace::LinkTable as u8);
    out.push(LINK_REVERSE_MARKER);
    out.extend_from_slice(&backlink_dnt.to_be_bytes());
    out.extend_from_slice(&link_id.to_be_bytes());
    out.extend_from_slice(&link_dnt.to_be_bytes());
    out
}

/// Marker byte (the second byte of the link-table key) that distinguishes a
/// forward-link row from a reverse-link row. Per ADR-001, both indexes live
/// in the `0x02` subspace; the marker byte ensures forward and reverse rows
/// sort into separate contiguous ranges so each can be scanned independently.
pub const LINK_FORWARD_MARKER: u8 = 0x00;

/// Marker byte for reverse-link rows (see [`LINK_FORWARD_MARKER`]).
pub const LINK_REVERSE_MARKER: u8 = 0x01;

/// Encode an SD-dedup table row key in the `0x03` (SdTable) subspace, per
/// ADR-004 §Decision. The dedup hash is BLAKE3-256 (32 bytes).
///
/// Key layout (33 bytes): `[0x03][sd_hash (32)]` → value:
/// `(sd_id, sd_refcount, sd_bytes)`.
///
/// Returns [`StorageError::SdCorruption`] if `sd_hash` is not exactly 32
/// bytes long.
pub fn encode_sd_table_key(sd_hash: &[u8]) -> Result<Vec<u8>, StorageError> {
    if sd_hash.len() != 32 {
        return Err(StorageError::SdCorruption(format!(
            "sd_hash must be 32 bytes (BLAKE3-256), got {}",
            sd_hash.len()
        )));
    }
    let mut out = Vec::with_capacity(1 + 32);
    out.push(Subspace::SdTable as u8);
    out.extend_from_slice(sd_hash);
    Ok(out)
}

/// Encode a tombstone row key in the `0x07` (Tombstones) subspace, per
/// ADR-074 §Decision. Tombstones are keyed by the NC head DNT (so a range
/// scan over a single NC's tombstones is cheap) followed by the deleted
/// object's own DNT.
///
/// Key layout (17 bytes): `[0x07][nc_head_dnt (8)][deleted_object_dnt (8)]`
/// → value: `(preserved_attributes_bytes, when_deleted_unix_seconds_i64)`.
pub fn encode_tombstone_key(nc_head_dnt: Dnt, deleted_object_dnt: Dnt) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 8);
    out.push(Subspace::Tombstones as u8);
    out.extend_from_slice(&nc_head_dnt.to_be_bytes());
    out.extend_from_slice(&deleted_object_dnt.to_be_bytes());
    out
}

/// Decode a tombstone row key into its `(nc_head_dnt, deleted_object_dnt)`
/// pair. Returns `None` if the key is not exactly 17 bytes long or does not
/// start with the `0x07` subspace byte.
pub fn decode_tombstone_key(key: &[u8]) -> Option<(Dnt, Dnt)> {
    if key.len() != 17 || key[0] != Subspace::Tombstones as u8 {
        return None;
    }
    let nc = u64::from_be_bytes(key[1..9].try_into().ok()?);
    let obj = u64::from_be_bytes(key[9..17].try_into().ok()?);
    Some((nc, obj))
}

/// Decode an 8-byte big-endian i64 (the wire format FDB uses for atomic-add
/// counters, per ADR-073 §Decision). Returns `None` if the slice is not
/// exactly 8 bytes long.
pub fn decode_i64_be(bytes: &[u8]) -> Option<i64> {
    if bytes.len() != 8 {
        return None;
    }
    let arr: [u8; 8] = bytes.try_into().ok()?;
    Some(i64::from_be_bytes(arr))
}

/// A higher-level transaction abstraction than [`ReadTxn`] / [`WriteTxn`]:
/// knows about DNT allocation, the UUID/DN indexes, and tombstone writes
/// (per ADR-073 §Decision and ADR-074 §Decision).
///
/// The trait is implemented by both the real FDB transaction wrapper
/// (`FdbTxn` in `adrian-storage-fdb`, gated by the `fdb` feature) and the
/// in-memory fallback wrapper (used when the `fdb` feature is disabled).
/// Callers that need multi-key atomicity (e.g. "update an object's DN in
/// one transaction") should program against this trait rather than the raw
/// [`WriteTxn`] interface.
#[async_trait]
pub trait DirectoryTransaction: WriteTxn {
    /// Allocate a fresh DNT by atomically incrementing the counter at
    /// [`encode_dnt_counter_key`]. Returns the *new* DNT (i.e. the value
    /// after the increment). Per ADR-073 §Decision, this must be the very
    /// first write in a `put` of a new object so that the DNT is visible
    /// to subsequent reads in the same transaction (read-your-writes).
    ///
    /// Implementation note: in real FDB, an `atomic_add` is visible to
    /// subsequent reads in the same transaction, so the implementation
    /// could simply `atomic_add(1); get(); return get_result`. The
    /// `adrian-storage-testkit`'s `InMemoryWriteTxn` does NOT model
    /// read-your-writes for staged atomic-adds (the staged delta is
    /// applied only at commit time, and `get` in the same transaction
    /// returns the snapshot value). This default impl works around that
    /// by reading the snapshot value first, computing `snapshot + 1`
    /// locally, and then staging the atomic-add. The locally-computed
    /// value matches what FDB's read-your-writes would return (since
    /// `atomic_add(k, 1)` on a snapshot value of `n` produces a read-view
    /// value of `n + 1`). Two concurrent transactions both calling
    /// `allocate_dnt` would conflict at commit time in real FDB (the
    /// second commit fails with `1020_not_committed` and is retried);
    /// the testkit does not model this conflict detection (callers
    /// running concurrent tests against the testkit should serialise
    /// their `allocate_dnt` calls).
    async fn allocate_dnt(&self) -> Result<Dnt, StorageError> {
        let key = encode_dnt_counter_key();
        // Read the current counter value. For real FDB this is the snapshot
        // value (pre-atomic_add); for the testkit this is also the snapshot
        // value (the staged atomic_add is invisible to `get`).
        let snapshot_val: i64 = match self.get(&key).await? {
            None => 0,
            Some(b) => decode_i64_be(&b)
                .ok_or_else(|| StorageError::Backend("DNT counter value not 8 bytes".into()))?,
        };
        if snapshot_val < 0 {
            return Err(StorageError::Backend(format!(
                "DNT counter is negative: {snapshot_val}"
            )));
        }
        // Compute the new DNT locally. This matches what FDB's read-your-
        // writes would return after `atomic_add(k, 1)` on the snapshot
        // value (i.e. `snapshot_val + 1`).
        let new_dnt = snapshot_val.checked_add(1).ok_or_else(|| {
            StorageError::Backend("DNT counter overflow (i64 overflow)".into())
        })?;
        // Stage the atomic-add. In real FDB, this is visible to subsequent
        // reads in this transaction; in the testkit, this is applied at
        // commit time. Either way, the final counter value after commit
        // is `snapshot_val + 1`.
        self.atomic_add(&key, 1).await?;
        Ok(new_dnt as Dnt)
    }

    /// Read the current value of the DNT counter without incrementing it.
    /// Returns 0 if the counter has never been written (i.e. no objects
    /// have ever been inserted).
    async fn read_dnt_counter(&self) -> Result<Dnt, StorageError> {
        let key = encode_dnt_counter_key();
        let bytes = self.get(&key).await?;
        match bytes {
            None => Ok(0),
            Some(b) => {
                let v = decode_i64_be(&b)
                    .ok_or_else(|| StorageError::Backend("DNT counter value not 8 bytes".into()))?;
                if v < 0 {
                    return Err(StorageError::Backend(format!(
                        "DNT counter is negative: {v}"
                    )));
                }
                Ok(v as Dnt)
            }
        }
    }

    /// Look up the DNT for a given object UUID via the `0x10` index. Returns
    /// `Ok(None)` if no object with that UUID exists.
    async fn lookup_dnt_by_uuid(&self, uuid: Uuid) -> Result<Option<Dnt>, StorageError> {
        let key = encode_uuid_index_key(uuid);
        match self.get(&key).await? {
            None => Ok(None),
            Some(bytes) => {
                let v = decode_i64_be(&bytes).ok_or_else(|| {
                    StorageError::Backend("UUID→DNT index value not 8 bytes".into())
                })?;
                Ok(Some(v as Dnt))
            }
        }
    }

    /// Look up the DNT for a given DN via the `0x11` index. Returns
    /// `Ok(None)` if no object with that DN exists.
    async fn lookup_dnt_by_dn(&self, dn: &DistinguishedName) -> Result<Option<Dnt>, StorageError> {
        let key = encode_dn_index_key(dn);
        match self.get(&key).await? {
            None => Ok(None),
            Some(bytes) => {
                let v = decode_i64_be(&bytes).ok_or_else(|| {
                    StorageError::Backend("DN→DNT index value not 8 bytes".into())
                })?;
                Ok(Some(v as Dnt))
            }
        }
    }

    /// Read all attribute rows for a given DNT. Returns a vector of
    /// `(attribute_id, value_index, value_bytes)` tuples, sorted by
    /// `(attribute_id, value_index)` ascending (because the underlying
    /// key-value store is ordered and `get_range` returns keys in order).
    async fn get_object_rows(
        &self,
        dnt: Dnt,
    ) -> Result<Vec<(AttributeId, ValueIndex, Vec<u8>)>, StorageError> {
        let prefix = encode_object_prefix(Subspace::Objects, dnt);
        let range = KeyRange::prefix(&prefix).ok_or_else(|| {
            StorageError::Backend("object prefix is all-0xFF (impossible for valid DNT)".into())
        })?;
        let rows = self.get_range(&range.begin, &range.end).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (key, value) in rows {
            if let Some((_, attr_id, val_idx)) = decode_object_key(&key, Subspace::Objects) {
                out.push((attr_id, val_idx, value));
            }
        }
        Ok(out)
    }

    /// Write the UUID→DNT and DN→DNT index entries for a newly-inserted or
    /// renamed object, plus a self-reference DNT row in the `0x01` Objects
    /// subspace (so that the range scan in [`Self::get_object_rows`] returns
    /// at least one row).
    async fn set_indexes(
        &self,
        uuid: Uuid,
        dn: &DistinguishedName,
        dnt: Dnt,
    ) -> Result<(), StorageError> {
        let uuid_key = encode_uuid_index_key(uuid);
        let dn_key = encode_dn_index_key(dn);
        let dnt_value = (dnt as i64).to_be_bytes().to_vec();
        self.put(&uuid_key, &dnt_value).await?;
        self.put(&dn_key, &dnt_value).await?;
        // Self-reference row: ensures the range scan returns at least one
        // row even for an object with zero user-visible attributes.
        let self_key = encode_object_key(Subspace::Objects, dnt, DNT_ATTR_SENTINEL, 0);
        self.put(&self_key, &dnt_value).await?;
        Ok(())
    }

    /// Move an object to the `0x07` Tombstones subspace (per ADR-074
    /// §Decision). The caller supplies the NC head DNT (used for range
    /// scans during GC), the deleted object's DNT, the preserved attribute
    /// bytes (objectGUID, objectSid, sIDHistory, lastKnownParent, member),
    /// and the deletion timestamp (Unix seconds).
    ///
    /// Implementations MUST delete the object's rows from the `0x01`
    /// (Objects), `0x10` (ObjectUuidIndex), and `0x11` (ObjectDnIndex)
    /// subspaces atomically with the tombstone write, so that the deletion
    /// is consistent from the perspective of any concurrent transaction.
    async fn tombstone(
        &self,
        nc_head_dnt: Dnt,
        deleted_object_dnt: Dnt,
        preserved_attributes: &[u8],
        when_deleted_unix_seconds: i64,
    ) -> Result<(), StorageError>;
}

// `InMemoryDirectoryStore` is implemented in `adrian-storage-testkit` (Wave 0).
// `FdbDirectoryStore` is implemented in `adrian-storage-fdb` (this wave —
// the real FDB code path is gated by the `fdb` feature; the in-memory
// fallback wraps `InMemoryDirectoryStore` and is always available).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_parent() {
        let dn = DistinguishedName::new("CN=Admin,CN=Users,DC=corp,DC=com");
        let parent = dn.parent().unwrap();
        assert_eq!(parent.dn, "CN=Users,DC=corp,DC=com");
    }

    #[test]
    fn dn_parent_domain_root() {
        let dn = DistinguishedName::new("DC=com");
        assert!(dn.parent().is_none());
    }

    #[test]
    fn dn_display() {
        let dn = DistinguishedName::new("CN=Admin,DC=corp,DC=com");
        assert_eq!(dn.to_string(), "CN=Admin,DC=corp,DC=com");
    }

    #[test]
    fn subspace_values() {
        assert_eq!(Subspace::Objects as u8, 0x01);
        assert_eq!(Subspace::LinkTable as u8, 0x02);
        assert_eq!(Subspace::IdentityMapping as u8, 0x0D);
    }

    #[test]
    fn object_serialization() {
        let obj = Object {
            uuid: Uuid::nil(),
            dn: DistinguishedName::new("CN=Test,DC=corp,DC=com"),
            attributes: vec![Attribute {
                attribute_id: 3,
                name: "cn".to_string(),
                value: b"Test".to_vec(),
            }],
            dnt: 42,
        };
        let json = serde_json::to_string(&obj).unwrap();
        let obj2: Object = serde_json::from_str(&json).unwrap();
        assert_eq!(obj.uuid, obj2.uuid);
        assert_eq!(obj.dn, obj2.dn);
        assert_eq!(obj.dnt, obj2.dnt);
    }

    // ----- Tuple-layer key encoding tests (Priority 1) -----

    #[test]
    fn encode_object_key_roundtrip_and_layout() {
        // Key must be exactly 17 bytes: 1 + 8 + 4 + 4.
        let key = encode_object_key(Subspace::Objects, 0x0123_4567_89AB_CDEF, 0x0246_8ACE, 7);
        assert_eq!(key.len(), 17, "object key must be exactly 17 bytes");
        // Subspace byte first.
        assert_eq!(key[0], Subspace::Objects as u8);
        // Big-endian DNT in bytes 1..9.
        assert_eq!(&key[1..9], &0x0123_4567_89AB_CDEFu64.to_be_bytes());
        // Round-trip via decode_object_key.
        let (d, a, v) = decode_object_key(&key, Subspace::Objects)
            .expect("decode_object_key must round-trip encode_object_key output");
        assert_eq!(d, 0x0123_4567_89AB_CDEF);
        assert_eq!(a, 0x0246_8ACE);
        assert_eq!(v, 7);
    }

    #[test]
    fn encode_object_key_sorts_lexicographically_by_dnt() {
        // Big-endian DNT means lexicographic byte ordering == numeric ordering.
        let k_low = encode_object_key(Subspace::Objects, 1, 3, 0);
        let k_mid = encode_object_key(Subspace::Objects, 42, 3, 0);
        let k_high = encode_object_key(Subspace::Objects, 0xFFFF_FFFF_FFFF_FFFF, 3, 0);
        assert!(k_low < k_mid);
        assert!(k_mid < k_high);
        // Different subspaces sort before any same-subspace DNTs (0x01 < 0x02).
        let k_objs = encode_object_key(Subspace::Objects, 999, 3, 0);
        let k_link = encode_object_key(Subspace::LinkTable, 1, 3, 0);
        assert!(k_objs < k_link, "0x01 must sort before 0x02");
    }

    #[test]
    fn encode_dnt_counter_key_matches_adr_073_spec() {
        // Per ADR-073: key is (0x01, 0xFF, "next_dnt"). Our encoding is
        // [0x01][0xFF 0xFF 0xFF 0xFF][b"next_dnt"] = 13 bytes.
        let key = encode_dnt_counter_key();
        assert_eq!(key.len(), 13);
        assert_eq!(key[0], Subspace::Objects as u8);
        assert_eq!(&key[1..5], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(&key[5..13], b"next_dnt");
    }

    #[test]
    fn encode_link_forward_and_reverse_keys_disjoint_ranges() {
        // Forward: [0x02][0x00][link_dnt][link_id][backlink_dnt]
        // Reverse: [0x02][0x01][backlink_dnt][link_id][link_dnt]
        // Both 22 bytes. Forward keys must sort before reverse keys because
        // 0x00 < 0x01 — so a range scan with the forward prefix returns only
        // forward rows, and a scan with the reverse prefix returns only
        // reverse rows (per ADR-001 §Decision).
        let fwd = encode_link_forward_key(10, 5, 20);
        let rev = encode_link_reverse_key(20, 5, 10);
        assert_eq!(fwd.len(), 22);
        assert_eq!(rev.len(), 22);
        assert_eq!(fwd[0], Subspace::LinkTable as u8);
        assert_eq!(fwd[1], LINK_FORWARD_MARKER);
        assert_eq!(rev[0], Subspace::LinkTable as u8);
        assert_eq!(rev[1], LINK_REVERSE_MARKER);
        assert!(fwd < rev, "forward-link keys must sort before reverse-link keys");
        // Forward-link range prefix (everything for link_dnt=10 outgoing).
        let fwd_prefix = {
            let mut p = Vec::with_capacity(10);
            p.push(Subspace::LinkTable as u8);
            p.push(LINK_FORWARD_MARKER);
            p.extend_from_slice(&10u64.to_be_bytes());
            p
        };
        // Forward key matches the prefix; reverse key does not.
        assert!(fwd.starts_with(&fwd_prefix));
        assert!(!rev.starts_with(&fwd_prefix));
    }

    #[test]
    fn encode_sd_table_key_rejects_wrong_hash_length_and_round_trips() {
        // Must reject non-32-byte hashes.
        let short = encode_sd_table_key(&[0u8; 16]);
        assert!(
            matches!(short, Err(StorageError::SdCorruption(_))),
            "16-byte hash must be rejected, got: {short:?}"
        );
        // Must accept exactly 32-byte BLAKE3-256 hashes.
        let mut hash = [0u8; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = encode_sd_table_key(&hash).expect("32-byte hash must be accepted");
        assert_eq!(key.len(), 33);
        assert_eq!(key[0], Subspace::SdTable as u8);
        assert_eq!(&key[1..33], &hash);
        // Tombstone key round-trip.
        let tkey = encode_tombstone_key(7, 42);
        assert_eq!(tkey.len(), 17);
        let (nc, obj) = decode_tombstone_key(&tkey).expect("tombstone key round-trip");
        assert_eq!(nc, 7);
        assert_eq!(obj, 42);
        // Bad tombstone key (wrong subspace byte) returns None.
        let mut bad = tkey.clone();
        bad[0] = 0x01;
        assert!(decode_tombstone_key(&bad).is_none());
    }

    #[test]
    fn key_range_prefix_strinc_increments_last_byte_and_carries() {
        // Simple prefix: last byte incremented.
        let r = KeyRange::prefix(b"abc").expect("strinc on abc");
        assert_eq!(r.begin, b"abc");
        assert_eq!(r.end, b"abd");
        // Last byte 0xFF carries into the previous byte.
        let r2 = KeyRange::prefix(b"ab\xff").expect("strinc on ab\\xff");
        assert_eq!(r2.end, b"ac");
        // All-0xFF prefix has no finite end.
        assert!(KeyRange::prefix(&[0xFFu8; 4]).is_none());
        // UUID→DNT index key range (subspace 0x10 + 16 bytes).
        let uuid = Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
        let idx_key = encode_uuid_index_key(uuid);
        assert_eq!(idx_key.len(), 17);
        assert_eq!(idx_key[0], Subspace::ObjectUuidIndex as u8);
        let decoded = decode_uuid_index_key(&idx_key).expect("uuid index key round-trip");
        assert_eq!(decoded, uuid);
        // DN→DNT index key (variable length).
        let dn = DistinguishedName::new("CN=alice,DC=corp,DC=com");
        let dn_key = encode_dn_index_key(&dn);
        assert_eq!(dn_key[0], Subspace::ObjectDnIndex as u8);
        assert_eq!(&dn_key[1..], b"CN=alice,DC=corp,DC=com");
    }
}
