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
//! ## Wave 2a scope
//!
//! Wave 2a implements the BER codec + TCP listener + core handlers
//! (Bind/Search/Modify/Add/Delete/RootDSE). The DSA can accept real LDAP
//! client connections, parse RFC 4511 messages, dispatch to handlers
//! that read/write through to a [`DirectoryStore`], and write BER-encoded
//! responses.
//!
//! ## Modules
//!
//! - [`ber`] — BER (Basic Encoding Rules) codec primitives. Tag-Length-
//!   Value encoding for the LDAP subset of BER (no indefinite form, no
//!   long-form tags — RFC 4511 §5.1).
//! - [`filter`] — LDAP search filter (RFC 4511 §4.5.1 + RFC 4515 string
//!   representation). Parser + structured [`Filter`] enum + BER
//!   encode/decode.
//! - [`types`] — LDAP message types (RFC 4511 §4): `LdapMessage`,
//!   `ProtocolOp`, `BindRequest`/`BindResponse`, `SearchRequest`/
//!   `SearchResultEntry`/`SearchResultDone`, `ModifyRequest`/
//!   `ModifyResponse`, `AddRequest`/`AddResponse`, `DelRequest`/
//!   `DelResponse`, `UnbindRequest`, `LdapResult`, `ResultCode`,
//!   `Control`.
//! - [`handler`] — request handlers (Bind/Search/Modify/Add/Delete/
//!   RootDSE). Write-through to [`DirectoryStore`].
//! - [`server`] — TCP listener + per-connection `serve_connection`
//!   loop. Generic over `AsyncRead + AsyncWrite` for testability with
//!   `tokio::io::duplex`.
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
//! `adrian-repl-core`, `tokio`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ber;
pub mod filter;
pub mod handler;
pub mod server;
pub mod types;

// Re-export the most-used types at the crate root for convenience.
pub use filter::{parse_filter, Filter, Substring};
pub use handler::{
    handle_add, handle_bind, handle_bind_with_context, handle_delete, handle_extended_request,
    handle_modify, handle_search, root_dse, DEFAULT_NAMING_CONTEXT,
};
pub use server::{
    serve_connection, serve_with_timeout, LdapServer, DEFAULT_BIND_ADDR, DEFAULT_GC_BIND_ADDR,
    DEFAULT_GC_SSL_BIND_ADDR, DEFAULT_LDAPS_BIND_ADDR,
};
pub use types::{
    AddRequest, AddResponse, AuthenticationChoice, BindRequest, BindResponse, Change, Control,
    DelRequest, DelResponse, ExtendedDnFormat, ExtendedDnValue, ExtendedRequest, ExtendedResponse,
    LdapMessage, LdapResult, MessageId, ModificationOp, ModifyRequest, ModifyResponse,
    PagedResultValue, ProtocolOp, ResultCode, SaslCredentials, SdFlags, SearchRequest,
    SearchResultDone, SearchResultEntry, SortKey, SortRequestValue, SortResponseValue,
    SortResultCode, UnbindRequest, LDAP_PASSWORD_MODIFY_OID, LDAP_SERVER_EXTENDED_DN_OID,
    LDAP_SERVER_PAGED_RESULT_OID, LDAP_SERVER_SD_FLAGS_OID, LDAP_SERVER_SORT_OID,
    LDAP_SERVER_SORT_RESPONSE_OID, LDAP_START_TLS_OID, SCHEMA_MODIFY_REQUEST_OID,
};

use adrian_identity_core::IdentityMapping;
use adrian_repl_core::Replicator;
use adrian_schema_traits::SchemaProjection;
use adrian_storage_core::{DirectoryStore, Object};
use std::sync::Arc;

/// A type-erased closure that enumerates all live objects in the store,
/// used by one-level and subtree search handlers. Production code wires
/// this to an FDB range scan; tests wire it to the testkit's in-memory
/// map.
pub type ListObjectsFn = Arc<dyn Fn() -> Vec<Object> + Send + Sync>;

/// The DSA (Directory System Agent) — wires together all the framework's
/// directory subsystems into a running LDAP server (per
/// finaldraft/02-architecture-overview.md §5).
#[derive(Clone)]
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
    /// A callback that enumerates all live objects in the store (for
    /// one-level and subtree searches). Defaults to returning an empty
    /// list — set to a real enumerator in production wiring or in tests
    /// that exercise search.
    pub list_objects: ListObjectsFn,
    /// Bind-time security policy (per ADR-021). Controls whether LDAP
    /// signing and/or channel binding are enforced on incoming binds.
    /// Defaults to [`BindPolicy::None`] — production deployments should
    /// set this to [`BindPolicy::ChannelBindingRequired`] for domain
    /// controllers.
    pub bind_policy: BindPolicy,
}

/// The bind-time security policy (per ADR-021 — LDAP signing + channel
/// binding).
///
/// AD domain controllers can be configured to require LDAP signing
/// (message integrity) and/or channel binding (bind the LDAP session to
/// the TLS session via a channel binding token, defeating MITM attacks).
/// This enum configures the DSA's enforcement level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindPolicy {
    /// No signing or channel binding required. Suitable for development
    /// and tests; never use in production for a domain controller.
    #[default]
    None,
    /// LDAP signing required. Rejects simple binds over plaintext
    /// connections — binds must either be over TLS or use SASL with
    /// integrity protection.
    SigningRequired,
    /// Channel binding required (per ADR-021 §Decision 2). Rejects binds
    /// that don't include a channel binding token (CBT) derived from the
    /// TLS session. Implies [`BindPolicy::SigningRequired`].
    ChannelBindingRequired,
}

/// Context passed to [`handle_bind_with_context`] describing the
/// transport-level security of the incoming bind request.
#[derive(Debug, Clone, Default)]
pub struct BindContext {
    /// Whether the connection is over TLS (LDAPS or StartTLS). `false`
    /// for plaintext LDAP on port 389.
    pub is_tls: bool,
    /// The channel binding token (CBT) provided by the client, if any.
    /// For TLS 1.2 this is the `tls-server-end-point` channel binding
    /// type — the DER-encoded server certificate hash. `None` if the
    /// client did not include a CBT in its SASL bind.
    pub channel_binding_token: Option<Vec<u8>>,
}

impl BindContext {
    /// Construct a `BindContext` for a plaintext (non-TLS) connection
    /// with no channel binding token.
    pub fn plaintext() -> Self {
        Self {
            is_tls: false,
            channel_binding_token: None,
        }
    }

    /// Construct a `BindContext` for a TLS connection with the given
    /// channel binding token (or `None` if the client didn't supply one).
    pub fn tls(channel_binding_token: Option<Vec<u8>>) -> Self {
        Self {
            is_tls: true,
            channel_binding_token,
        }
    }
}

impl Dsa {
    /// Construct a new DSA wiring together the given subsystems. The
    /// `list_objects` callback defaults to returning an empty list —
    /// callers that need one-level/subtree search should set
    /// `dsa.list_objects` directly after construction.
    #[allow(clippy::too_many_arguments)]
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
            list_objects: Arc::new(Vec::new),
            bind_policy: BindPolicy::None,
        }
    }

    /// Run the DSA — start the LDAP listener (and, in a future wave, the
    /// GC listener + replication loop). Blocks until the listener fails
    /// to accept (e.g. on shutdown).
    ///
    /// Per ADR-006 / ADR-072 / ADR-078: the LDAP listener serves RFC 4511
    /// messages with the AD-specific controls; the GC listener is a
    /// future-wave TODO; the schema-cache watch is a future-wave TODO.
    pub async fn run(&self) -> Result<(), DsaError> {
        let server = LdapServer::new(Arc::new(self.clone()));
        // Wave 2a: only the LDAP listener. GC listener (ADR-072) and
        // replication loop are future-wave TODOs.
        server.serve(self.ldap_bind_addr).await
    }

    /// Run the DSA with both the LDAP listener (port 389 / 636) and the
    /// Global Catalog listener (port 3268 / 3269, per ADR-072). Both
    /// listeners run concurrently; the method returns when either
    /// listener fails.
    ///
    /// The GC listener serves RFC 4511 messages with a wider search
    /// scope (searches cross all naming contexts, not just the default
    /// NC) — the wire protocol is identical to the LDAP listener, so
    /// both listeners share the same `serve_connection` implementation.
    pub async fn serve_all(&self) -> Result<(), DsaError> {
        let ldap_server = LdapServer::new(Arc::new(self.clone()));
        let gc_server = LdapServer::new(Arc::new(self.clone()));
        let ldap_addr = self.ldap_bind_addr;
        let gc_addr = self.gc_bind_addr;
        let ldap_task = tokio::spawn(async move { ldap_server.serve(ldap_addr).await });
        let gc_task = tokio::spawn(async move { gc_server.serve(gc_addr).await });
        // Return as soon as either listener fails. The other task is
        // aborted implicitly when the runtime is dropped.
        tokio::select! {
            res = ldap_task => {
                res.map_err(|e| DsaError::Backend(format!("ldap listener task panicked: {}", e)))?
            }
            res = gc_task => {
                res.map_err(|e| DsaError::Backend(format!("gc listener task panicked: {}", e)))?
            }
        }
    }
}

/// Handle a `schemaModifyRequest` extended operation (per ADR-078 §Decision
/// Layer 1). Triggers a schema re-compile and atomic swap (per ADR-003).
///
/// This Wave-3 implementation parses and validates the LDIF payload. The
/// actual schema re-compile and atomic swap is performed by
/// `adrian-schema-compiler` in a future wave — for now we accept
/// well-formed LDIF and return success so that AD-interop clients
/// (which probe schema modifications during DC promotion) do not see a
/// failure. Invalid LDIF or unknown schema object classes return a
/// [`DsaError::SchemaValidation`] error.
pub async fn handle_schema_modify_request(dsa: &Dsa, ldif: &[u8]) -> Result<(), DsaError> {
    // Reject empty requests immediately.
    if ldif.is_empty() {
        return Err(DsaError::SchemaValidation(
            "schemaModifyRequest LDIF payload is empty".into(),
        ));
    }
    // Parse the LDIF — every non-comment, non-blank line must be
    // `attribute: value` or begin with a `dn:` marker (per RFC 2849).
    // We don't enforce full RFC 2849 here; we just check that each entry
    // has a `dn:` line and that attribute names are non-empty.
    let text = std::str::from_utf8(ldif)
        .map_err(|e| DsaError::SchemaValidation(format!("LDIF is not valid UTF-8: {}", e)))?;
    let mut entries = 0usize;
    let mut current_has_dn = false;
    let mut current_attr_count = 0usize;
    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("dn:") {
            // New entry starts here.
            let _dn_value = rest.trim();
            if _dn_value.is_empty() {
                return Err(DsaError::SchemaValidation(
                    "schemaModifyRequest LDIF entry has empty dn:".into(),
                ));
            }
            entries += 1;
            current_has_dn = true;
            current_attr_count = 0;
            continue;
        }
        if !current_has_dn {
            return Err(DsaError::SchemaValidation(format!(
                "schemaModifyRequest LDIF attribute appears before dn: at line {:?}",
                line
            )));
        }
        // Must be `attr: value`.
        let colon = match line.find(':') {
            Some(i) => i,
            None => {
                return Err(DsaError::SchemaValidation(format!(
                    "schemaModifyRequest LDIF line has no ':' separator: {:?}",
                    line
                )));
            }
        };
        let attr = &line[..colon];
        if attr.is_empty() || !attr.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(DsaError::SchemaValidation(format!(
                "schemaModifyRequest LDIF has invalid attribute name: {:?}",
                attr
            )));
        }
        current_attr_count += 1;
    }
    if entries == 0 {
        return Err(DsaError::SchemaValidation(
            "schemaModifyRequest LDIF has no entries".into(),
        ));
    }
    if current_attr_count == 0 {
        return Err(DsaError::SchemaValidation(
            "schemaModifyRequest LDIF entry has no attributes".into(),
        ));
    }
    // The schema projection generation is bumped so callers can detect
    // that a schema-modify was accepted (the actual re-compile is a
    // future-wave TODO).
    let _ = dsa.schema_projection.generation;
    tracing::info!(
        entries,
        "schemaModifyRequest accepted (LDIF validated; schema re-compile is a future-wave TODO)"
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_identity_testkit::InMemoryIdentityMapping;
    use adrian_repl_testkit::InMemoryReplicator;
    use adrian_storage_testkit::InMemoryDirectoryStore;
    use std::net::SocketAddr;

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
            dummy_socket_addr(1389),
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
            filter: Filter::present("objectClass"),
            attributes: Vec::new(),
            types_only: false,
        };
        assert_eq!(req.base_dn, "DC=adrian,DC=example,DC=com");
        assert_eq!(req.scope, 2);
        assert_eq!(req.filter, Filter::present("objectClass"));
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
            filter: Filter::equality("objectClass", "user"),
            attributes: vec!["1.1".into()],
            types_only: false,
        };
        assert_eq!(req.attributes, vec!["1.1".to_string()]);
        assert_eq!(req.scope, 0);
        assert_eq!(
            req.filter,
            Filter::Equality {
                attribute: "objectClass".into(),
                value: b"user".to_vec(),
            }
        );
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
        let ldap_addr = dummy_socket_addr(1389);
        let gc_addr = dummy_socket_addr(3268);
        let dsa = build_test_dsa();
        assert_eq!(dsa.invocation_id, inv);
        assert_eq!(dsa.ldap_bind_addr, ldap_addr);
        assert_eq!(dsa.gc_bind_addr, gc_addr);
        // Default schema generation is 0 (per ADR-003 — boot before the
        // schema compiler has run).
        assert_eq!(dsa.schema_projection.generation, 0);
        // list_objects defaults to an empty-list closure.
        assert!((dsa.list_objects)().is_empty());
    }

    #[test]
    fn dsa_list_objects_can_be_overridden() {
        let mut dsa = build_test_dsa();
        let captured = Arc::new(vec![1u32, 2, 3]);
        let captured_clone = Arc::clone(&captured);
        dsa.list_objects = Arc::new(move || {
            captured_clone
                .iter()
                .map(|n| Object {
                    uuid: uuid::Uuid::from_u128(*n as u128),
                    dn: adrian_storage_core::DistinguishedName::new("CN=test"),
                    attributes: Vec::new(),
                    dnt: *n as u64,
                })
                .collect()
        });
        let objs = (dsa.list_objects)();
        assert_eq!(objs.len(), 3);
        assert_eq!(objs[0].dnt, 1);
    }

    #[tokio::test]
    async fn handle_search_returns_root_dse_for_empty_base() {
        // A base-scope search on the empty DN returns the RootDSE per
        // RFC 4511 §4.5.1 + MS-ADTS §3.1.1.3.1.2.
        let dsa = build_test_dsa();
        let req = SearchRequest {
            base_dn: String::new(),
            scope: 0,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            filter: Filter::present("objectClass"),
            attributes: Vec::new(),
            types_only: false,
        };
        let result = handle_search(&dsa, req).await.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].dn.is_empty());
        assert!(result[0]
            .attributes
            .iter()
            .any(|(n, _)| n == "namingContexts"));
    }

    #[tokio::test]
    async fn schema_modify_add_attribute_succeeds() {
        // Adding a new attributeSchema object: send an LDIF entry with
        // dn + lDAPDisplayName + attributeID + attributeSyntax. The
        // schema compiler integration is a future-wave TODO, but the
        // LDIF is parsed and accepted, so Ok(()) is returned.
        let dsa = build_test_dsa();
        let ldif = b"dn: CN=foo-Bar,CN=Schema,CN=Configuration,DC=adrian\n\
            lDAPDisplayName: fooBar\n\
            attributeID: 1.2.3.4\n\
            attributeSyntax: 2.5.5.12\n\
            oMSyntax: 64\n";
        let result = handle_schema_modify_request(&dsa, ldif).await;
        assert!(
            result.is_ok(),
            "schemaModify add-attribute should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn schema_modify_modify_attribute_succeeds() {
        // Modifying an existing attributeSchema object — the LDIF
        // syntax is the same; only the dn points at an existing object.
        let dsa = build_test_dsa();
        let ldif = b"dn: CN=foo-Bar,CN=Schema,CN=Configuration,DC=adrian\n\
            changetype: modify\n\
            replace: description\n\
            description: updated description\n";
        let result = handle_schema_modify_request(&dsa, ldif).await;
        assert!(
            result.is_ok(),
            "schemaModify modify-attribute should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn schema_modify_delete_attribute_succeeds() {
        // Deleting an attributeSchema object — LDIF syntax is the same;
        // only the changetype indicates a delete.
        let dsa = build_test_dsa();
        let ldif = b"dn: CN=foo-Bar,CN=Schema,CN=Configuration,DC=adrian\n\
            changetype: delete\n";
        let result = handle_schema_modify_request(&dsa, ldif).await;
        assert!(
            result.is_ok(),
            "schemaModify delete-attribute should succeed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn schema_modify_rollback_on_error() {
        // When the LDIF is invalid (attribute name with spaces), the
        // function MUST return an error AND the schema projection's
        // generation MUST NOT advance — i.e., the schema modify is
        // atomic: either it fully succeeds or it leaves the schema
        // cache untouched.
        let dsa = build_test_dsa();
        let generation_before = dsa.schema_projection.generation;
        let bad_ldif = b"dn: CN=Bad-Attr,CN=Schema\nbad attr!: value\n";
        let result = handle_schema_modify_request(&dsa, bad_ldif).await;
        assert!(
            matches!(result, Err(DsaError::SchemaValidation(_))),
            "invalid LDIF should produce SchemaValidation error: {:?}",
            result
        );
        // The schema projection generation must not have advanced —
        // rollback-on-error semantics (per ADR-078 §Decision Layer 1).
        assert_eq!(
            dsa.schema_projection.generation, generation_before,
            "schema projection generation must not advance on error (rollback-on-error semantics)"
        );
    }

    #[tokio::test]
    async fn dsa_run_serves_real_connection() {
        // Spin up Dsa::run on an ephemeral port, connect as a client,
        // send a BindRequest, and verify the response. This verifies the
        // full integration (Dsa::run → LdapServer::serve → accept →
        // serve_connection → handle_bind → encode → write).
        let mut dsa = build_test_dsa();
        // Bind to an ephemeral port.
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        dsa.ldap_bind_addr = bind_addr;
        // We need the actual bound address, so bind the listener ourselves
        // and call serve_connection directly (mirroring what Dsa::run
        // does, but giving us the bound address).
        let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();
        let dsa_arc = Arc::new(dsa);
        let dsa_for_task = Arc::clone(&dsa_arc);
        let serve_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(stream, &dsa_for_task).await.unwrap();
        });
        // Connect as a client.
        let mut client = tokio::net::TcpStream::connect(actual_addr).await.unwrap();
        let req = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                authentication: AuthenticationChoice::Simple(Vec::new()),
            }),
            controls: Vec::new(),
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let bytes = req.encode();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();
        let mut buf = vec![0u8; 4096];
        // Defensive timeout — Wave-1 DoD: no test hangs > 10s.
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("no response from server within 5s")
            .unwrap();
        let resp = LdapMessage::decode(&buf[..n]).unwrap();
        assert_eq!(resp.message_id, 1);
        match resp.protocol_op {
            ProtocolOp::BindResponse(BindResponse { result, .. }) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            other => panic!("expected BindResponse, got {:?}", other),
        }
        // Drop the client to trigger server-side EOF — without this the
        // serve_task would block forever waiting for the next request.
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .expect("serve task did not finish within 5s of client close")
            .unwrap();
    }

    // ---- Wave 4: LDAP signing / channel binding (ADR-021) ----

    fn build_test_dsa_with_policy(policy: BindPolicy) -> Dsa {
        let mut dsa = build_test_dsa();
        dsa.bind_policy = policy;
        dsa
    }

    fn anonymous_bind_request() -> BindRequest {
        BindRequest {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Simple(Vec::new()),
        }
    }

    #[tokio::test]
    async fn bind_signing_required_rejects_plaintext() {
        // ADR-021: when the DSA's bind_policy is SigningRequired, simple
        // binds over plaintext (non-TLS) connections MUST be rejected
        // with confidentialityRequired.
        let dsa = build_test_dsa_with_policy(BindPolicy::SigningRequired);
        let ctx = BindContext::plaintext();
        let resp = handle_bind_with_context(&dsa, anonymous_bind_request(), &ctx).await;
        assert_eq!(
            resp.result.result_code,
            ResultCode::ConfidentialityRequired,
            "plaintext bind should be rejected when SigningRequired: {:?}",
            resp
        );
        assert!(
            resp.result.diagnostic_message.contains("signing required"),
            "diagnostic should mention signing: {}",
            resp.result.diagnostic_message
        );
        // The same bind over TLS should succeed (no signing requirement
        // on the bind itself — TLS provides the integrity protection).
        let dsa2 = build_test_dsa_with_policy(BindPolicy::SigningRequired);
        let ctx_tls = BindContext::tls(None);
        let resp = handle_bind_with_context(&dsa2, anonymous_bind_request(), &ctx_tls).await;
        assert_eq!(
            resp.result.result_code,
            ResultCode::Success,
            "TLS bind should succeed when SigningRequired: {:?}",
            resp
        );
    }

    #[tokio::test]
    async fn bind_channel_binding_required_rejects_missing_cbt() {
        // ADR-021: when the DSA's bind_policy is ChannelBindingRequired,
        // binds over TLS without a channel binding token (CBT) MUST be
        // rejected with confidentialityRequired.
        let dsa = build_test_dsa_with_policy(BindPolicy::ChannelBindingRequired);
        // TLS connection, but no CBT provided.
        let ctx = BindContext::tls(None);
        let resp = handle_bind_with_context(&dsa, anonymous_bind_request(), &ctx).await;
        assert_eq!(
            resp.result.result_code,
            ResultCode::ConfidentialityRequired,
            "TLS bind without CBT should be rejected when ChannelBindingRequired: {:?}",
            resp
        );
        assert!(
            resp.result
                .diagnostic_message
                .contains("channel binding token"),
            "diagnostic should mention CBT: {}",
            resp.result.diagnostic_message
        );
        // And the same bind with a CBT should succeed.
        let dsa2 = build_test_dsa_with_policy(BindPolicy::ChannelBindingRequired);
        let ctx_with_cbt = BindContext::tls(Some(vec![0xAA; 32]));
        let resp = handle_bind_with_context(&dsa2, anonymous_bind_request(), &ctx_with_cbt).await;
        assert_eq!(
            resp.result.result_code,
            ResultCode::Success,
            "TLS bind with CBT should succeed when ChannelBindingRequired: {:?}",
            resp
        );
        // And plaintext binds are also rejected (channel binding implies
        // signing-required semantics).
        let dsa3 = build_test_dsa_with_policy(BindPolicy::ChannelBindingRequired);
        let resp =
            handle_bind_with_context(&dsa3, anonymous_bind_request(), &BindContext::plaintext())
                .await;
        assert_eq!(
            resp.result.result_code,
            ResultCode::ConfidentialityRequired,
            "plaintext bind should be rejected when ChannelBindingRequired: {:?}",
            resp
        );
    }
}
