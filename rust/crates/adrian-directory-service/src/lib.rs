//! # adrian-directory-service
//!
//! LDAP server + DSA (Directory System Agent) for the Adrian framework.
//!
//! Implements LDAPv3 (RFC 4510-4519) server-side on TCP/389 (LDAP) and
//! TCP/636 (LDAPS), with the Global Catalog listener on TCP/3268 / 3269 (per
//! ADR-072). The DSA wires together:
//!
//! - [`DirectoryStore`] (`adrian-storage-fdb::FdbDirectoryStore`)
//! - [`Replicator`] (`adrian-drsuapi::DrSuapiReplicator` or
//!   `adrian-raft::RaftReplicator`)
//! - [`IdentityMapping`] (`adrian-identity-fdb::FdbIdentityMapping`)
//! - [`SchemaProjection`] (`adrian-schema-compiler`)
//!
//! ## AD-interop LDAP controls (per ADR-006)
//!
//! The DSA implements the AD-specific LDAP controls required for AD-aware
//! clients:
//! - `LDAP_SERVER_PAGED_RESULT_OID` (1.2.840.113556.1.4.319)
//! - `LDAP_SERVER_SORT_OID` (1.2.840.113556.1.4.473)
//! - `LDAP_SERVER_SD_FLAGS_OID` (1.2.840.113556.1.4.801)
//! - `LDAP_SERVER_SHOW_DELETED_OID` (1.2.840.113556.1.4.417)
//! - `LDAP_SERVER_EXTENDED_DN_OID` (1.2.840.113556.1.4.529)
//! - `LDAP_SERVER_ASQ_OID` (1.2.840.113556.1.4.1504)
//! - `LDAP_SERVER_DIRSYNC_OID` (1.2.840.113556.1.4.1413)
//! - `LDAP_SERVER_DOMAIN_SCOPE_OID` (1.2.840.113556.1.4.1339)
//! - `LDAP_SERVER_VERIFY_NAME_OID` (1.2.840.113556.1.4.1338)
//! - `LDAP_SERVER_RangedRetrieval` (1.2.840.113556.1.4.1668)
//!
//! ## `schemaModifyRequest` handler (per ADR-078)
//!
//! The DSA implements the LDAP `schemaModifyRequest` extended operation (per
//! RFC 4512 §4.1.2 and ADR-078 §Decision Layer 1). On schema modification,
//! the schema compiler (`adrian-schema-compiler`) regenerates the typed
//! Rust projection and atomically swaps it in (per ADR-003 §Decision).
//!
//! ## ADRs
//!
//! - ADR-006: AD-specific LDAP controls
//! - ADR-009: Constructed attributes (`tokenGroups`, etc.)
//! - ADR-072: Global Catalog strategy
//! - ADR-073: FoundationDB as sole storage engine
//! - ADR-078: Hybrid schema model
//! - ADR-079: DNS in directory (integrated DNS zones)
//! - ADR-080: Instance type / systemFlags / bitmasks
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-storage-fdb`, `adrian-schema-compiler`, `adrian-identity-fdb`,
//! `adrian-repl-core`, `tokio`, `ldap3`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_identity_core::IdentityMapping;
use adrian_repl_core::Replicator;
use adrian_schema_traits::SchemaProjection;
use adrian_storage_core::DirectoryStore;
use std::sync::Arc;

/// The DSA (Directory System Agent) — wires together all the framework's
/// directory subsystems into a running LDAP server (per
/// finaldraft/02-architecture-overview.md §5).
pub struct Dsa {
    /// The directory store (per ADR-073, FDB-backed in v1).
    pub store: Arc<dyn DirectoryStore>,
    /// The replication backend (per Decision 1 — either
    /// `DrSuapiReplicator` for AD-interop or `RaftReplicator` for native).
    pub replicator: Arc<dyn Replicator>,
    /// The identity mapping (per Decision 3).
    pub identity_mapping: Arc<dyn IdentityMapping>,
    /// The schema projection (per ADR-078 — atomically swapped per ADR-003).
    pub schema_projection: Arc<SchemaProjection>,
    /// The DSA's invocation ID (per MS-ADTS §3.1.1.3.2.6).
    pub invocation_id: uuid::Uuid,
    /// The LDAP bind address (TCP/389 or LDAPS TCP/636).
    pub ldap_bind_addr: std::net::SocketAddr,
    /// The Global Catalog bind address (TCP/3268 or GC-SSL TCP/3269, per
    /// ADR-072).
    pub gc_bind_addr: std::net::SocketAddr,
}

impl Dsa {
    /// Construct a new DSA wiring together the given subsystems.
    pub fn new(
        store: Arc<dyn DirectoryStore>,
        replicator: Arc<dyn Replicator>,
        identity_mapping: Arc<dyn IdentityMapping>,
        schema_projection: Arc<SchemaProjection>,
        invocation_id: uuid::Uuid,
        ldap_bind_addr: std::net::SocketAddr,
        gc_bind_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            store,
            replicator,
            identity_mapping,
            schema_projection,
            invocation_id,
            ldap_bind_addr,
            gc_bind_addr,
        }
    }

    /// Run the DSA — start the LDAP listener, GC listener, and replication
    /// loop. Blocks until shutdown.
    pub async fn run(&self) -> Result<(), DsaError> {
        // TODO: implement per ADR-006 / ADR-072 / ADR-078.
        // - Bind LDAP listener on ldap_bind_addr (per ADR-006 — AD controls).
        // - Bind GC listener on gc_bind_addr (per ADR-072).
        // - Start replication loop (per Decision 1).
        // - Start schema-cache watch (per ADR-003).
        Err(DsaError::NotImplemented(
            "Dsa::run not yet implemented".into(),
        ))
    }
}

/// Error type for DSA operations.
#[derive(Debug, thiserror::Error)]
pub enum DsaError {
    /// The operation is not yet implemented.
    #[error("not implemented: {0}")]
    NotImplemented(String),
    /// LDAP protocol error.
    #[error("LDAP error: {0}")]
    Ldap(String),
    /// Schema validation failed (per ADR-078).
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    /// Replication error (per Decision 1).
    #[error("replication error: {0}")]
    Replication(#[from] adrian_repl_core::ReplicationError),
    /// Storage error (per Decision 2).
    #[error("storage error: {0}")]
    Storage(#[from] adrian_storage_core::StorageError),
    /// Backend error.
    #[error("backend error: {0}")]
    Backend(String),
}

/// An LDAP search request (per RFC 4511 §4.5).
#[derive(Debug, Clone)]
pub struct SearchRequest {
    /// The base DN of the search.
    pub base_dn: String,
    /// The search scope (0=base, 1=one-level, 2=subtree, per RFC 4511 §4.5.1).
    pub scope: u8,
    /// The deref-aliases policy (per RFC 4511 §4.5.1).
    pub deref_aliases: u8,
    /// The size limit (0 = no limit, per RFC 4511 §4.5.1).
    pub size_limit: i32,
    /// The time limit (0 = no limit, per RFC 4511 §4.5.1).
    pub time_limit: i32,
    /// The search filter (per RFC 4515 string representation).
    pub filter: String,
    /// The attributes to return (empty = all user attributes; `*` = all;
    /// `1.1` = no attributes; per RFC 4511 §4.5.1).
    pub attributes: Vec<String>,
    /// Whether to return attribute types only (per RFC 4511 §4.5.1).
    pub types_only: bool,
}

/// An LDAP search result entry (per RFC 4511 §4.5.2).
#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    /// The entry's DN.
    pub dn: String,
    /// The entry's attributes.
    pub attributes: Vec<(String, Vec<Vec<u8>>)>,
}

/// Handle an LDAP search request (per RFC 4511 §4.5).
///
/// Implements the AD-specific LDAP controls per ADR-006 (paged results, sort,
/// SD flags, show-deleted, extended-DN, ASQ, DirSync, domain-scope,
/// verify-name, ranged-retrieval).
pub async fn handle_search(
    _dsa: &Dsa,
    _req: SearchRequest,
) -> Result<Vec<SearchResultEntry>, DsaError> {
    // TODO: implement per RFC 4511 §4.5 + ADR-006 (AD controls) + ADR-009
    // (constructed attributes like tokenGroups).
    Err(DsaError::NotImplemented(
        "handle_search not yet implemented".into(),
    ))
}

/// Handle a `schemaModifyRequest` extended operation (per ADR-078 §Decision
/// Layer 1). Triggers a schema re-compile and atomic swap (per ADR-003).
pub async fn handle_schema_modify_request(_dsa: &Dsa, _ldif: &[u8]) -> Result<(), DsaError> {
    // TODO: implement per ADR-078 — apply the LDIF to the Schema NC, then
    // trigger adrian-schema-compiler to regenerate the projection.
    Err(DsaError::NotImplemented(
        "handle_schema_modify_request not yet implemented".into(),
    ))
}

// TODO: implement LDAP bind handler per RFC 4513 + ADR-021 (signing/channel-binding).
// TODO: implement LDAP modify handler per RFC 4511 §4.6 (per-attribute write with SD dedup per ADR-004).
// TODO: implement LDAP add handler per RFC 4511 §4.7 (with link-value writes per ADR-001).
// TODO: implement LDAP delete handler per RFC 4511 §4.8 (tombstone per ADR-074).
// TODO: implement LDAP modifyDN handler per RFC 4511 §4.9 (with cross-domain move per ADR-075).
// TODO: implement LDAP compare handler per RFC 4511 §4.10.
// TODO: implement LDAP extended operations per RFC 4511 §4.12 (startTLS, schemaModifyRequest, whoAmI).
// TODO: implement AD controls per ADR-006.
// TODO: implement constructed attributes per ADR-009 (tokenGroups, memberOf, canonicalName, etc.).

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_identity_testkit::InMemoryIdentityMapping;
    use adrian_repl_testkit::InMemoryReplicator;
    use adrian_storage_testkit::InMemoryDirectoryStore;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn dummy_invocation_id() -> uuid::Uuid {
        uuid::Uuid::from_u128(0x_ABCD)
    }

    fn dummy_socket_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn empty_schema_projection() -> Arc<SchemaProjection> {
        Arc::new(SchemaProjection {
            attributes: Default::default(),
            classes: Default::default(),
            attribute_name_to_id: Default::default(),
            class_name_to_id: Default::default(),
            generation: 0,
        })
    }

    fn build_test_dsa() -> Dsa {
        Dsa::new(
            Arc::new(InMemoryDirectoryStore::new()),
            Arc::new(InMemoryReplicator::new(dummy_invocation_id())),
            Arc::new(InMemoryIdentityMapping::new()),
            empty_schema_projection(),
            dummy_invocation_id(),
            dummy_socket_addr(389),
            dummy_socket_addr(3268),
        )
    }

    #[test]
    fn search_request_construction_defaults() {
        // A subtree search for all user attributes on the domain root (the
        // most common LDAP search in AD-style clients).
        let req = SearchRequest {
            base_dn: "DC=adrian,DC=example,DC=com".into(),
            scope: 2, // subtree
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            filter: "(objectClass=*)".into(),
            attributes: Vec::new(),
            types_only: false,
        };
        assert_eq!(req.base_dn, "DC=adrian,DC=example,DC=com");
        assert_eq!(req.scope, 2);
        assert_eq!(req.filter, "(objectClass=*)");
        assert!(req.attributes.is_empty());
        assert!(!req.types_only);
    }

    #[test]
    fn search_request_no_attributes_marker() {
        // Per RFC 4511 §4.5.1, an attribute list of ["1.1"] means "return
        // no attributes". This is used by AD clients to probe for object
        // existence.
        let req = SearchRequest {
            base_dn: "CN=Users,DC=adrian,DC=example,DC=com".into(),
            scope: 0, // base
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            filter: "(objectClass=user)".into(),
            attributes: vec!["1.1".into()],
            types_only: false,
        };
        assert_eq!(req.attributes, vec!["1.1".to_string()]);
        assert_eq!(req.scope, 0);
    }

    #[test]
    fn search_result_entry_construction() {
        let entry = SearchResultEntry {
            dn: "CN=alice,DC=adrian,DC=example,DC=com".into(),
            attributes: vec![("sAMAccountName".into(), vec![b"alice".to_vec()])],
        };
        assert_eq!(entry.dn, "CN=alice,DC=adrian,DC=example,DC=com");
        assert_eq!(entry.attributes.len(), 1);
        assert_eq!(entry.attributes[0].0, "sAMAccountName");
        assert_eq!(entry.attributes[0].1, vec![b"alice".to_vec()]);
    }

    #[test]
    fn search_result_entry_supports_multi_valued_attribute() {
        // memberOf is multi-valued (per ADR-002 — DSA-computed back-link);
        // a search response must be able to return multiple byte values per
        // attribute.
        let entry = SearchResultEntry {
            dn: "CN=bob,DC=adrian,DC=example,DC=com".into(),
            attributes: vec![(
                "memberOf".into(),
                vec![
                    b"CN=Admins,DC=adrian,DC=example,DC=com".to_vec(),
                    b"CN=Users,DC=adrian,DC=example,DC=com".to_vec(),
                ],
            )],
        };
        assert_eq!(entry.attributes[0].1.len(), 2);
    }

    #[test]
    fn dsa_error_not_implemented_display() {
        let err = DsaError::NotImplemented("Dsa::run not yet implemented".into());
        let msg = format!("{}", err);
        assert!(msg.contains("not implemented"), "msg={}", msg);
        assert!(msg.contains("Dsa::run"), "msg={}", msg);
    }

    #[test]
    fn dsa_error_schema_validation_display() {
        let err = DsaError::SchemaValidation("missing must-contain cn".into());
        let msg = format!("{}", err);
        assert!(msg.contains("schema validation failed"), "msg={}", msg);
        assert!(msg.contains("must-contain"), "msg={}", msg);
    }

    #[test]
    fn dsa_error_storage_wraps_storage_error() {
        // The `#[from]` attribute on the Storage variant must allow `?` to
        // propagate StorageError from `DirectoryStore` calls.
        let inner = adrian_storage_core::StorageError::Backend("disk full".into());
        let err: DsaError = inner.into();
        let msg = format!("{}", err);
        assert!(msg.contains("storage error"), "msg={}", msg);
        assert!(msg.contains("disk full"), "msg={}", msg);
    }

    #[test]
    fn dsa_new_sets_fields() {
        let inv = dummy_invocation_id();
        let ldap_addr = dummy_socket_addr(389);
        let gc_addr = dummy_socket_addr(3268);
        let dsa = build_test_dsa();
        assert_eq!(dsa.invocation_id, inv);
        assert_eq!(dsa.ldap_bind_addr, ldap_addr);
        assert_eq!(dsa.gc_bind_addr, gc_addr);
        // Default schema generation is 0 (per ADR-003 — boot before the
        // schema compiler has run).
        assert_eq!(dsa.schema_projection.generation, 0);
    }

    #[tokio::test]
    async fn dsa_run_returns_not_implemented() {
        // Until the LDAP / GC listeners are wired up (per ADR-006 / ADR-072),
        // Dsa::run MUST return NotImplemented rather than silently exiting.
        let dsa = build_test_dsa();
        let result = dsa.run().await;
        assert!(
            matches!(result, Err(DsaError::NotImplemented(_))),
            "{:?}",
            result
        );
    }

    #[tokio::test]
    async fn handle_search_returns_not_implemented() {
        let dsa = build_test_dsa();
        let req = SearchRequest {
            base_dn: "DC=adrian,DC=example,DC=com".into(),
            scope: 2,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            filter: "(objectClass=*)".into(),
            attributes: Vec::new(),
            types_only: false,
        };
        let result = handle_search(&dsa, req).await;
        assert!(
            matches!(result, Err(DsaError::NotImplemented(_))),
            "{:?}",
            result
        );
    }

    #[tokio::test]
    async fn handle_schema_modify_request_returns_not_implemented() {
        // The schemaModifyRequest extended op (per ADR-078) is not yet
        // wired to the schema compiler; it MUST return NotImplemented so
        // callers don't think a no-op schema change succeeded.
        let dsa = build_test_dsa();
        let ldif = b"dn: CN=Some-New-Attribute,CN=Schema,CN=Configuration,DC=adrian\n";
        let result = handle_schema_modify_request(&dsa, ldif).await;
        assert!(
            matches!(result, Err(DsaError::NotImplemented(_))),
            "{:?}",
            result
        );
    }
}
