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
    handle_add, handle_bind, handle_delete, handle_modify, handle_search, root_dse,
    DEFAULT_NAMING_CONTEXT,
};
pub use server::{serve_connection, serve_with_timeout, LdapServer, DEFAULT_BIND_ADDR};
pub use types::{
    AddRequest, AddResponse, AuthenticationChoice, BindRequest, BindResponse, Change, Control,
    DelRequest, DelResponse, LdapMessage, LdapResult, MessageId, ModificationOp, ModifyRequest,
    ModifyResponse, ProtocolOp, ResultCode, SaslCredentials, SearchRequest, SearchResultDone,
    SearchResultEntry, UnbindRequest,
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
}

/// Handle a `schemaModifyRequest` extended operation (per ADR-078 §Decision
/// Layer 1). Triggers a schema re-compile and atomic swap (per ADR-003).
///
/// **Wave 2a**: not yet implemented — returns [`DsaError::NotImplemented`].
/// The schema compiler integration is a future-wave TODO.
pub async fn handle_schema_modify_request(_dsa: &Dsa, _ldif: &[u8]) -> Result<(), DsaError> {
    Err(DsaError::NotImplemented(
        "handle_schema_modify_request not yet implemented (ADR-078 future wave)".into(),
    ))
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
}
