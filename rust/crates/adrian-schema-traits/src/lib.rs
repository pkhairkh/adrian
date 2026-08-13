//! # adrian-schema-traits
//!
//! Schema trait definitions and the `Projectable` derive macro target for the
//! Adrian framework.
//!
//! Per ADR-078 §Decision and Workshop Decision 4, the framework uses a hybrid
//! schema model: the live directory Schema NC is the source of truth (Layer 0
//! of Decision 4), and at boot a schema compiler (`adrian-schema-compiler`,
//! Layer 2) walks the Schema NC and builds a typed Rust projection
//! (`Arc<SchemaProjection>`). Framework-native classes (e.g. `ServiceAccount`,
//! `ManagedDevice`, `PolicySet`) are declared as Rust traits in this crate
//! with `#[derive(Projectable)]`; the derive macro emits the projection glue
//! (`ldap_class_ids()`, `read_from(&Entry)`, `write_to(&mut EntryBuilder)`).
//!
//! ## ADRs
//!
//! - ADR-003: Schema cache with copy-on-write generations
//! - ADR-078: Hybrid schema model (live directory + typed Rust projection)
//! - ADR-079: DNS in directory
//! - ADR-080: Instance type / systemFlags / bitmasks
//! - ADR-119: Schema-as-code with GitOps
//!
//! ## Layer
//!
//! Layer 0 — foundation (no internal dependencies). Consumed by
//! `adrian-schema-compiler` (Layer 2) and by every crate that reads typed
//! directory objects.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A 32-bit attribute identifier — the schema's `attributeID` (per ADR-003).
pub type AttributeId = u32;

/// A 32-bit class identifier — the schema's `governsID` (per ADR-003).
pub type ClassId = u32;

/// The LDAP attribute syntax enum (per RFC 4512 §4.1.3 and AD's
/// `attributeSyntax` / `oMSyntax` pair, per ADR-078).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttributeSyntax {
    /// DirectoryString (UTF-8 string, LDAP syntax `1.3.6.1.4.1.1466.115.121.1.15`).
    DirectoryString,
    /// IA5String (ASCII, LDAP syntax `1.3.6.1.4.1.1466.115.121.1.26`).
    Ia5String,
    /// Integer (32-bit, LDAP syntax `1.3.6.1.4.1.1466.115.121.1.27`).
    Integer,
    /// LargeInteger (64-bit, AD syntax `2.5.5.16`).
    LargeInteger,
    /// Boolean (LDAP syntax `1.3.6.1.4.1.1466.115.121.1.7`).
    Boolean,
    /// OID (LDAP syntax `1.3.6.1.4.1.1466.115.121.1.38`).
    Oid,
    /// DN (distinguished name, LDAP syntax `1.3.6.1.4.1.1466.115.121.1.12`).
    Dn,
    /// SID (AD syntax `2.5.5.17`).
    Sid,
    /// GUID / UUID (AD syntax `2.5.5.10` for octet-string).
    OctetString,
    /// UTCTime / GeneralizedTime (LDAP syntax `1.3.6.1.4.1.1466.115.121.1.24`).
    GeneralizedTime,
    /// Security descriptor (AD syntax `2.5.5.15`).
    SecurityDescriptor,
    /// Print case string (AD syntax `2.5.5.3`).
    CaseExactString,
}

/// An `attributeSchema` object from the Schema NC (per ADR-003 / ADR-078).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeSchema {
    /// The `attributeID` (per ADR-003).
    pub id: AttributeId,
    /// The LDAP attribute name (e.g. `cn`, `member`, `objectSid`).
    pub ldap_name: String,
    /// The attribute syntax (per RFC 4512 / AD).
    pub syntax: AttributeSyntax,
    /// `rangeLower` (per ADR-078).
    pub range_lower: Option<i64>,
    /// `rangeUpper` (per ADR-078).
    pub range_upper: Option<i64>,
    /// `isSingleValued` (per ADR-003).
    pub is_single_valued: bool,
    /// `searchFlags` (per ADR-009 — controls index / constructed-attribute
    /// behaviour).
    pub search_flags: u32,
    /// Whether this attribute is a linked attribute (per ADR-001 — stored in
    /// the `linktable` subspace rather than inline).
    pub is_linked: bool,
    /// The linked-attribute `linkID` (per ADR-001). Forward links have even
    /// linkIDs; back-links have odd linkIDs paired with the forward link's
    /// linkID + 1.
    pub link_id: Option<u32>,
}

/// A `classSchema` object from the Schema NC (per ADR-003 / ADR-078).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassSchema {
    /// The `governsID` (per ADR-003).
    pub id: ClassId,
    /// The LDAP class name (e.g. `user`, `group`, `computer`).
    pub ldap_name: String,
    /// The superior (parent) class IDs (per ADR-003).
    pub superiors: Vec<ClassId>,
    /// The mandatory (`mustContain`) attribute IDs (per ADR-003).
    pub must_contain: Vec<AttributeId>,
    /// The optional (`mayContain`) attribute IDs (per ADR-003).
    pub may_contain: Vec<AttributeId>,
    /// The `systemFlags` bitmask (per ADR-080).
    pub system_flags: u32,
    /// The `objectClassCategory` (1=structural, 2=auxiliary, 3=abstract,
    /// per ADR-080).
    pub category: u8,
}

/// The in-memory schema projection (per ADR-078 §Decision).
///
/// The projection is built at DSA boot by `adrian-schema-compiler` (Layer 2)
/// and atomically swapped per ADR-003's copy-on-write schema cache. A new
/// schema generation triggers a re-compile and an atomic pointer swap.
#[derive(Debug, Clone)]
pub struct SchemaProjection {
    /// Map of attribute ID → attribute schema.
    pub attributes: std::collections::HashMap<AttributeId, AttributeSchema>,
    /// Map of class ID → class schema.
    pub classes: std::collections::HashMap<ClassId, ClassSchema>,
    /// Map of LDAP attribute name → attribute ID (for case-insensitive lookup
    /// per RFC 4512).
    pub attribute_name_to_id: std::collections::HashMap<String, AttributeId>,
    /// Map of LDAP class name → class ID.
    pub class_name_to_id: std::collections::HashMap<String, ClassId>,
    /// The schema generation counter (per ADR-003; stored at FDB key
    /// `(0x04, 0x00)`).
    pub generation: u64,
}

impl SchemaProjection {
    /// Construct an empty projection at generation 0 (per ADR-003 — boot
    /// before the schema compiler has run).
    pub fn empty() -> Self {
        Self {
            attributes: std::collections::HashMap::new(),
            classes: std::collections::HashMap::new(),
            attribute_name_to_id: std::collections::HashMap::new(),
            class_name_to_id: std::collections::HashMap::new(),
            generation: 0,
        }
    }

    /// Copy-on-write: clone the projection with `generation + 1`, ready for
    /// mutation per ADR-003 §Decision. The previous generation remains
    /// immutable for in-flight readers; the new generation is the only one
    /// that may be mutated.
    ///
    /// Saturates at `u64::MAX` to keep the counter monotonic.
    pub fn next_generation(&self) -> Self {
        let mut next = self.clone();
        next.generation = self.generation.saturating_add(1);
        next
    }
}

/// A trait for cache lookups against the schema projection (per ADR-003).
///
/// Implementations:
/// - `SchemaProjection` itself (direct lookup)
/// - A `SnapshotView` that holds an `Arc<SchemaProjection>` and exposes the
///   same lookups atomically (per ADR-003 §Decision)
pub trait SchemaCache: Send + Sync {
    /// Look up an attribute schema by ID.
    fn attribute(&self, id: AttributeId) -> Option<&AttributeSchema>;
    /// Look up an attribute schema by LDAP name (case-insensitive).
    fn attribute_by_name(&self, name: &str) -> Option<&AttributeSchema>;
    /// Look up a class schema by ID.
    fn class(&self, id: ClassId) -> Option<&ClassSchema>;
    /// Look up a class schema by LDAP name (case-insensitive).
    fn class_by_name(&self, name: &str) -> Option<&ClassSchema>;
    /// Return the schema generation (per ADR-003).
    fn generation(&self) -> u64;
    /// Return the UUID of the schema NC head (per ADR-003).
    fn schema_nc_head(&self) -> Uuid;
}

/// Error type for schema operations (per ADR-078 §Decision, validation
/// failures are surfaced at projection compile time, not silently).
#[derive(Debug, Error)]
pub enum SchemaError {
    /// The attribute ID is not in the schema projection.
    #[error("unknown attribute ID: {0}")]
    UnknownAttributeId(AttributeId),
    /// The attribute name is not in the schema projection.
    #[error("unknown attribute name: {0}")]
    UnknownAttributeName(String),
    /// The class ID is not in the schema projection.
    #[error("unknown class ID: {0}")]
    UnknownClassId(ClassId),
    /// The class name is not in the schema projection.
    #[error("unknown class name: {0}")]
    UnknownClassName(String),
    /// The object violates the class's must-contain constraint (per ADR-078).
    #[error("missing must-contain attribute {0} on class {1}")]
    MissingMustContain(AttributeId, ClassId),
    /// The object has an attribute not allowed by its class (per ADR-078).
    #[error("attribute {0} not allowed on class {1}")]
    DisallowedAttribute(AttributeId, ClassId),
    /// The projection compile failed (per ADR-078 — loud failure at boot).
    #[error("schema projection compile failed: {0}")]
    ProjectionCompile(String),
}

/// A trait that every framework-native class declares via
/// `#[derive(Projectable)]` (per ADR-078 §Decision Layer 2).
///
/// The derive macro emits `ldap_class_ids()`, `read_from(&Entry)`, and
/// `write_to(&mut EntryBuilder)`. Framework-native classes (e.g.
/// `ServiceAccount`, `ManagedDevice`, `PolicySet`) project onto standard LDAP
/// classes (e.g. `msDS-ManagedServiceAccount`) and can be projected back to
/// LDAP at write time.
pub trait Projectable: Send + Sync {
    /// The LDAP class IDs this trait projects onto (per ADR-078).
    fn ldap_class_ids() -> &'static [ClassId];
}

// TODO: implement #[derive(Projectable)] proc-macro in adrian-schema-traits-derive (gated to Wave 4b).
// TODO: implement SchemaProjection::build in adrian-schema-compiler per ADR-078.
// TODO: add native-class trait library (ServiceAccount, ManagedDevice, PolicySet, CertificateTemplate) per ADR-078 §Decision Layer 2.

bitflags::bitflags! {
    /// The `searchFlags` bitmask on `attributeSchema` (per MS-ADTS §3.1.1.3.2.5
    /// and ADR-080).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SearchFlags: u32 {
        /// fANR (0x01) — attribute is included in ANR (ambiguous name resolution).
        const ANR = 0x01;
        /// fATTINDEX (0x02) — an index is created on the attribute.
        const ATTINDEX = 0x02;
        /// fPRESERVEATON (0x04) — preserve on tombstone.
        const PRESERVEATON = 0x04;
        /// fCOPY (0x08) — copy the value when the object is copied.
        const COPY = 0x08;
        /// fTUPLEINDEX (0x10) — a tuple index is created (for substring searches).
        const TUPLEINDEX = 0x10;
        /// fSUBTREEATTRINDEX (0x20) — a subtree index is created.
        const SUBTREEATTRINDEX = 0x20;
        /// fCONFIDENTIAL (0x80) — attribute is confidential (requires
        /// CONTROL_ACCESS right to read, per ADR-066).
        const CONFIDENTIAL = 0x80;
        /// fNEVERVALUEAUDIT (0x100) — do not audit value reads.
        const NEVERVALUEAUDIT = 0x100;
    }

    /// The `systemFlags` bitmask on `attributeSchema` and `classSchema` (per
    /// MS-ADTS §3.1.1.2.4 and ADR-080).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SystemFlags: u32 {
        /// FLAG_ATTR_NOT_REPLICATED (0x01) — attribute is not replicated.
        const ATTR_NOT_REPLICATED = 0x01;
        /// FLAG_ATTR_IS_CONSTRUCTED (0x02) — attribute is constructed (per ADR-009).
        const ATTR_IS_CONSTRUCTED = 0x02;
        /// FLAG_DOMAIN_DISALLOW_RENAME (0x04000000) — domain object cannot be renamed.
        const DOMAIN_DISALLOW_RENAME = 0x0400_0000;
        /// FLAG_DOMAIN_DISALLOW_MOVE (0x08000000) — domain object cannot be moved.
        const DOMAIN_DISALLOW_MOVE = 0x0800_0000;
        /// FLAG_DISALLOW_DELETE (0x80000000) — object cannot be deleted.
        const DISALLOW_DELETE = 0x8000_0000;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_flags_decoding() {
        // fANR = 0x01, fATTINDEX = 0x02, fPRESERVEATON = 0x04
        let flags = SearchFlags::ANR | SearchFlags::ATTINDEX;
        assert!(flags.contains(SearchFlags::ANR));
        assert!(flags.contains(SearchFlags::ATTINDEX));
        assert!(!flags.contains(SearchFlags::CONFIDENTIAL));
    }

    #[test]
    fn system_flags_decoding() {
        let flags = SystemFlags::ATTR_NOT_REPLICATED | SystemFlags::ATTR_IS_CONSTRUCTED;
        assert!(flags.contains(SystemFlags::ATTR_NOT_REPLICATED));
        assert!(flags.contains(SystemFlags::ATTR_IS_CONSTRUCTED));
    }
}
