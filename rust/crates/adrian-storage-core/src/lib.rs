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
/// The subspaces 0x01-0x0F are reserved for framework use; subspaces 0x10+
/// are reserved for future expansion.
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

// TODO: implement FdbDirectoryStore in adrian-storage-fdb per ADR-073.
// TODO: implement InMemoryDirectoryStore in adrian-storage-testkit per Decision 2 §Rust implementation implications.
// TODO: add tuple-layer key encoding types per ADR-073 §Decision (LinkValueForwardKey, SdTableKey, SchemaCacheGenerationKey).
