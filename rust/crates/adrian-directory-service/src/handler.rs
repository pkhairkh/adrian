//! LDAP request handlers (RFC 4511 §4).
//!
//! Each handler takes a [`Dsa`](crate::Dsa) reference and the parsed
//! request type, performs the operation against the directory store, and
//! returns the appropriate response type. The TCP server
//! ([`serve_connection`](crate::serve_connection)) is responsible for
//! wrapping the response in an `LDAPMessage` and writing it to the wire.
//!
//! ## Bind (RFC 4511 §4.2)
//!
//! - **Anonymous** bind (empty DN + empty simple password) → `success`.
//! - **Simple** bind (non-empty DN + non-empty password) → `success` if
//!   the DN exists in the store (Wave 2a accepts any non-empty password;
//!   real password-hash verification arrives in a later wave).
//! - **SASL** bind → `authMethodNotSupported` (Wave 2a does not implement
//!   SASL — see ADR-021 for the signing/channel-binding design).
//! - LDAPv2 (`version != 3`) → `protocolError`.
//!
//! ## Search (RFC 4511 §4.5)
//!
//! - **Base scope** (`scope=0`) → return the single base object (or the
//!   RootDSE if `base_dn` is empty).
//! - **One-level scope** (`scope=1`) → return direct children of the base.
//! - **Subtree scope** (`scope=2`) → return the base + all descendants.
//!
//! Filtering supports `present`, `equalityMatch`, `substrings`, `and`,
//! `or`, `not`, `greaterOrEqual`, `lessOrEqual`, and `approxMatch`.
//!
//! ## Modify / Add / Delete (RFC 4511 §4.6-4.8)
//!
//! Write-through to [`DirectoryStore::put`](adrian_storage_core::DirectoryStore::put)
//! / [`delete`](adrian_storage_core::DirectoryStore::delete) with basic
//! validation (must have `objectClass` for Add; entry must exist for
//! Modify/Delete).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::types::{
    AddRequest, AddResponse, BindRequest, BindResponse, Change, DelRequest, DelResponse,
    LdapResult, ModificationOp, ModifyRequest, ModifyResponse, ResultCode, SearchRequest,
    SearchResultDone, SearchResultEntry, UnbindRequest,
};
use crate::Dsa;
use crate::DsaError;
use adrian_storage_core::{Attribute, DistinguishedName, Object};
use uuid::Uuid;

/// The default naming context returned by the RootDSE. In production this
/// would be configurable per-domain; for Wave 2a it is hard-coded.
pub const DEFAULT_NAMING_CONTEXT: &str = "DC=adrian,DC=example,DC=com";

/// The schema NC's DN (per ADR-078 — the live Schema NC is the source of
/// truth for the schema compiler).
pub const SCHEMA_NC_DN: &str = "CN=Schema,CN=Configuration,DC=adrian,DC=example,DC=com";

/// The configuration NC's DN.
pub const CONFIGURATION_NC_DN: &str = "CN=Configuration,DC=adrian,DC=example,DC=com";

/// Handle a `BindRequest` (RFC 4511 §4.2).
///
/// See the [module docs](self) for the bind semantics.
pub async fn handle_bind(dsa: &Dsa, req: BindRequest) -> BindResponse {
    // LDAPv3 only — reject v1/v2.
    if req.version != 3 {
        return BindResponse::error(
            ResultCode::ProtocolError,
            format!(
                "unsupported LDAP version: {} (only v3 is supported)",
                req.version
            ),
        );
    }
    match &req.authentication {
        crate::types::AuthenticationChoice::Simple(pw) => {
            // Anonymous bind: empty DN + empty password → success.
            if req.name.is_empty() && pw.is_empty() {
                return BindResponse::success();
            }
            // Simple bind: non-empty DN + non-empty password → check the DN.
            if req.name.is_empty() || pw.is_empty() {
                return BindResponse::error(
                    ResultCode::InvalidCredentials,
                    "anonymous bind requires both empty DN and empty password",
                );
            }
            let dn = DistinguishedName::new(&req.name);
            match dsa.store.get_by_dn(&dn).await {
                Ok(Some(_)) => {
                    // Wave 2a: accept any non-empty password for an
                    // existing DN. Real password-hash verification arrives
                    // in a later wave (per ADR-021).
                    BindResponse::success()
                }
                Ok(None) => BindResponse::error(
                    ResultCode::InvalidCredentials,
                    "invalid DN/password combination",
                ),
                Err(e) => BindResponse::error(
                    ResultCode::OperationsError,
                    format!("storage error during bind: {}", e),
                ),
            }
        }
        crate::types::AuthenticationChoice::Sasl(_) => BindResponse::error(
            ResultCode::AuthMethodNotSupported,
            "SASL bind not yet implemented (see ADR-021)",
        ),
    }
}

/// Handle an `UnbindRequest` (RFC 4511 §4.3). The server closes the
/// connection after unbind; this function is a no-op placeholder.
pub async fn handle_unbind(_dsa: &Dsa, _req: UnbindRequest) {
    // No response is sent for unbind — the server simply closes the
    // connection. The actual close happens in `serve_connection`.
}

/// Handle a `SearchRequest` (RFC 4511 §4.5).
///
/// Returns the list of matching entries (which the server sends as
/// individual `SearchResultEntry` messages, followed by a
/// `SearchResultDone`). On error, the server sends a `SearchResultDone`
/// with the error code and no entries.
pub async fn handle_search(
    dsa: &Dsa,
    req: SearchRequest,
) -> Result<Vec<SearchResultEntry>, DsaError> {
    // RootDSE: base_dn="" + scope=base → return the RootDSE entry.
    if req.base_dn.is_empty() && req.scope == 0 {
        return Ok(vec![root_dse()]);
    }
    // Gather candidate objects based on scope.
    let candidates = gather_candidates(dsa, &req.base_dn, req.scope).await?;
    // Apply the filter to each candidate.
    let mut results = Vec::new();
    for obj in candidates {
        if filter_matches(&obj, &req.filter) {
            results.push(object_to_search_entry(&obj, &req.attributes));
        }
    }
    Ok(results)
}

/// Gather the candidate objects for a search, based on scope.
async fn gather_candidates(dsa: &Dsa, base_dn: &str, scope: u8) -> Result<Vec<Object>, DsaError> {
    match scope {
        0 => {
            // Base scope: just the base object.
            let dn = DistinguishedName::new(base_dn);
            match dsa.store.get_by_dn(&dn).await? {
                Some(obj) => Ok(vec![obj]),
                None => Ok(Vec::new()),
            }
        }
        1 | 2 => {
            // One-level / subtree: enumerate via the list_objects callback.
            let all = (dsa.list_objects)();
            let mut out = Vec::new();
            for obj in all {
                let matches = match scope {
                    1 => dn_is_child_of(&obj.dn.dn, base_dn),
                    2 => dn_is_descendant_of(&obj.dn.dn, base_dn),
                    _ => false,
                };
                if matches {
                    out.push(obj);
                }
            }
            // For subtree scope, include the base object itself if it exists.
            if scope == 2 {
                let dn = DistinguishedName::new(base_dn);
                if let Some(obj) = dsa.store.get_by_dn(&dn).await? {
                    out.push(obj);
                }
            }
            Ok(out)
        }
        _ => Err(DsaError::Ldap(format!(
            "unsupported search scope: {}",
            scope
        ))),
    }
}

/// Check if a DN is a direct child of `parent_dn` (case-insensitive,
/// suffix-based — sufficient for Wave 2a; real DN comparison parses RDNs).
fn dn_is_child_of(child_dn: &str, parent_dn: &str) -> bool {
    let child_lc = child_dn.to_ascii_lowercase();
    let parent_lc = parent_dn.to_ascii_lowercase();
    if parent_lc.is_empty() {
        // Root parent: any single-RDN child (e.g. "DC=com" or
        // "DC=adrian"). For Wave 2a, treat top-level DNs as children of
        // the empty root.
        return !child_lc.is_empty() && !child_lc.contains(',');
    }
    // child must end with ", parent" (note the leading comma+space).
    let suffix = format!(", {}", parent_lc);
    if child_lc.ends_with(&suffix) {
        // Ensure there's no further nesting — i.e. the part before the
        // suffix is a single RDN (no comma).
        let prefix = &child_lc[..child_lc.len() - suffix.len()];
        return !prefix.is_empty() && !prefix.contains(',');
    }
    // Also accept ",parent" without space (some clients omit the space).
    let suffix_no_space = format!(",{}", parent_lc);
    if child_lc.ends_with(&suffix_no_space) {
        let prefix = &child_lc[..child_lc.len() - suffix_no_space.len()];
        return !prefix.is_empty() && !prefix.contains(',');
    }
    false
}

/// Check if a DN is a descendant of `ancestor_dn` (case-insensitive,
/// suffix-based). The base DN itself counts as a descendant (subtree
/// scope includes the base).
fn dn_is_descendant_of(child_dn: &str, ancestor_dn: &str) -> bool {
    let child_lc = child_dn.to_ascii_lowercase();
    let ancestor_lc = ancestor_dn.to_ascii_lowercase();
    if ancestor_lc.is_empty() {
        return !child_lc.is_empty();
    }
    if child_lc == ancestor_lc {
        return true;
    }
    child_lc.ends_with(&format!(", {}", ancestor_lc))
        || child_lc.ends_with(&format!(",{}", ancestor_lc))
}

/// Convert a storage [`Object`] to a [`SearchResultEntry`], optionally
/// filtering the attributes returned.
fn object_to_search_entry(obj: &Object, attrs: &[String]) -> SearchResultEntry {
    let return_all = attrs.is_empty()
        || attrs.iter().any(|a| a == "*")
        || attrs.iter().any(|a| a.eq_ignore_ascii_case("*"));
    let no_attrs = attrs.iter().any(|a| a == "1.1");
    let mut entries: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    if no_attrs {
        return SearchResultEntry {
            dn: obj.dn.dn.clone(),
            attributes: Vec::new(),
        };
    }
    // Group attributes by name.
    let mut grouped: std::collections::BTreeMap<String, Vec<Vec<u8>>> =
        std::collections::BTreeMap::new();
    for attr in &obj.attributes {
        if return_all || attrs.iter().any(|a| a.eq_ignore_ascii_case(&attr.name)) {
            grouped
                .entry(attr.name.clone())
                .or_default()
                .push(attr.value.clone());
        }
    }
    for (name, values) in grouped {
        entries.push((name, values));
    }
    SearchResultEntry {
        dn: obj.dn.dn.clone(),
        attributes: entries,
    }
}

/// Check if a storage [`Object`] matches a [`crate::filter::Filter`].
fn filter_matches(obj: &Object, filter: &crate::filter::Filter) -> bool {
    use crate::filter::Filter;
    match filter {
        Filter::And(subs) => subs.iter().all(|s| filter_matches(obj, s)),
        Filter::Or(subs) => subs.iter().any(|s| filter_matches(obj, s)),
        Filter::Not(inner) => !filter_matches(obj, inner),
        Filter::Present(attr) => obj
            .attributes
            .iter()
            .any(|a| a.name.eq_ignore_ascii_case(attr)),
        Filter::Equality { attribute, value } => obj.attributes.iter().any(|a| {
            a.name.eq_ignore_ascii_case(attribute) && a.value.as_slice() == value.as_slice()
        }),
        Filter::Approx { attribute, value } => {
            // approxMatch is case-insensitive equality on string values.
            let value_lc = String::from_utf8_lossy(value).to_ascii_lowercase();
            obj.attributes.iter().any(|a| {
                a.name.eq_ignore_ascii_case(attribute)
                    && String::from_utf8_lossy(&a.value).to_ascii_lowercase() == value_lc
            })
        }
        Filter::GreaterOrEqual { attribute, value } => {
            let v = String::from_utf8_lossy(value);
            obj.attributes.iter().any(|a| {
                a.name.eq_ignore_ascii_case(attribute) && *String::from_utf8_lossy(&a.value) >= *v
            })
        }
        Filter::LessOrEqual { attribute, value } => {
            let v = String::from_utf8_lossy(value);
            obj.attributes.iter().any(|a| {
                a.name.eq_ignore_ascii_case(attribute) && *String::from_utf8_lossy(&a.value) <= *v
            })
        }
        Filter::Substrings {
            attribute,
            substrings,
        } => {
            let mut initial: Option<&[u8]> = None;
            let mut anys: Vec<&[u8]> = Vec::new();
            let mut final_: Option<&[u8]> = None;
            for s in substrings {
                match s {
                    crate::filter::Substring::Initial(v) => initial = Some(v),
                    crate::filter::Substring::Any(v) => anys.push(v),
                    crate::filter::Substring::Final(v) => final_ = Some(v),
                }
            }
            obj.attributes.iter().any(|a| {
                if !a.name.eq_ignore_ascii_case(attribute) {
                    return false;
                }
                substrings_match(&a.value, initial, &anys, final_)
            })
        }
    }
}

/// Check if a byte string matches an `(initial, any*, final?)` substring
/// pattern.
fn substrings_match(
    value: &[u8],
    initial: Option<&[u8]>,
    anys: &[&[u8]],
    final_: Option<&[u8]>,
) -> bool {
    let v = String::from_utf8_lossy(value);
    let v_lc = v.to_ascii_lowercase();
    let initial_lc = initial.map(|b| String::from_utf8_lossy(b).to_ascii_lowercase());
    let anys_lc: Vec<String> = anys
        .iter()
        .map(|b| String::from_utf8_lossy(b).to_ascii_lowercase())
        .collect();
    let final_lc = final_.map(|b| String::from_utf8_lossy(b).to_ascii_lowercase());

    let mut pos = 0usize;
    if let Some(init) = &initial_lc {
        if !v_lc[..].starts_with(init.as_str()) {
            return false;
        }
        pos = init.len();
    }
    for any in &anys_lc {
        if any.is_empty() {
            continue;
        }
        match v_lc[pos..].find(any.as_str()) {
            Some(idx) => pos += idx + any.len(),
            None => return false,
        }
    }
    if let Some(fin) = &final_lc {
        if !v_lc.ends_with(fin.as_str()) {
            return false;
        }
        if v_lc.len() - fin.len() < pos {
            return false;
        }
    }
    true
}

/// Build the RootDSE entry (RFC 4511 §4.5.1 + AD specifics).
///
/// The RootDSE is returned when a client searches with `base_dn=""` and
/// `scope=base`. It advertises:
/// - `namingContexts` — the domain, configuration, and schema NCs.
/// - `defaultNamingContext` — the domain NC.
/// - `supportedLDAPVersion` — `[3]`.
/// - `supportedSASLMechanisms` — `["GSSAPI", "GSS-SPNEGO", "EXTERNAL"]`.
/// - `supportedControl` — the AD control OIDs per ADR-006.
/// - `vendorName` — `"Adrian"`.
pub fn root_dse() -> SearchResultEntry {
    SearchResultEntry {
        dn: String::new(),
        attributes: vec![
            (
                "namingContexts".into(),
                vec![
                    DEFAULT_NAMING_CONTEXT.as_bytes().to_vec(),
                    CONFIGURATION_NC_DN.as_bytes().to_vec(),
                    SCHEMA_NC_DN.as_bytes().to_vec(),
                ],
            ),
            (
                "defaultNamingContext".into(),
                vec![DEFAULT_NAMING_CONTEXT.as_bytes().to_vec()],
            ),
            ("supportedLDAPVersion".into(), vec![b"3".to_vec()]),
            (
                "supportedSASLMechanisms".into(),
                vec![
                    b"GSSAPI".to_vec(),
                    b"GSS-SPNEGO".to_vec(),
                    b"EXTERNAL".to_vec(),
                ],
            ),
            (
                "supportedControl".into(),
                vec![
                    // LDAP_SERVER_PAGED_RESULT_OID (ADR-006).
                    b"1.2.840.113556.1.4.319".to_vec(),
                    // LDAP_SERVER_SORT_OID.
                    b"1.2.840.113556.1.4.473".to_vec(),
                    // LDAP_SERVER_SD_FLAGS_OID.
                    b"1.2.840.113556.1.4.801".to_vec(),
                    // LDAP_SERVER_SHOW_DELETED_OID.
                    b"1.2.840.113556.1.4.417".to_vec(),
                    // LDAP_SERVER_EXTENDED_DN_OID.
                    b"1.2.840.113556.1.4.529".to_vec(),
                ],
            ),
            ("vendorName".into(), vec![b"Adrian".to_vec()]),
            ("objectClass".into(), vec![b"*".to_vec()]),
        ],
    }
}

/// Handle a `ModifyRequest` (RFC 4511 §4.6).
pub async fn handle_modify(dsa: &Dsa, req: ModifyRequest) -> ModifyResponse {
    let dn = DistinguishedName::new(&req.object);
    let mut obj = match dsa.store.get_by_dn(&dn).await {
        Ok(Some(o)) => o,
        Ok(None) => {
            return ModifyResponse {
                result: LdapResult::error(
                    ResultCode::NoSuchObject,
                    format!("entry not found: {}", req.object),
                ),
            };
        }
        Err(e) => {
            return ModifyResponse {
                result: LdapResult::error(
                    ResultCode::OperationsError,
                    format!("storage error during modify: {}", e),
                ),
            };
        }
    };
    // Apply each change to the in-memory copy.
    for change in &req.changes {
        apply_change(&mut obj, change);
    }
    // Write through.
    if let Err(e) = dsa.store.put(&obj).await {
        return ModifyResponse {
            result: LdapResult::error(
                ResultCode::OperationsError,
                format!("storage error during modify put: {}", e),
            ),
        };
    }
    ModifyResponse::success()
}

/// Apply a single [`Change`] to an [`Object`] in place.
fn apply_change(obj: &mut Object, change: &Change) {
    let (name, values) = &change.modification;
    match change.operation {
        ModificationOp::Add => {
            for v in values {
                obj.attributes.push(Attribute {
                    attribute_id: 0, // Wave 2a: schema-attribute-id lookup not implemented.
                    name: name.clone(),
                    value: v.clone(),
                });
            }
        }
        ModificationOp::Delete => {
            // If values is empty, delete all values of the attribute.
            // Otherwise, delete only the matching values.
            if values.is_empty() {
                obj.attributes
                    .retain(|a| !a.name.eq_ignore_ascii_case(name));
            } else {
                obj.attributes.retain(|a| {
                    !a.name.eq_ignore_ascii_case(name)
                        || !values.iter().any(|v| v.as_slice() == a.value.as_slice())
                });
            }
        }
        ModificationOp::Replace => {
            // Remove all existing values, then add the new ones.
            obj.attributes
                .retain(|a| !a.name.eq_ignore_ascii_case(name));
            for v in values {
                obj.attributes.push(Attribute {
                    attribute_id: 0,
                    name: name.clone(),
                    value: v.clone(),
                });
            }
        }
    }
}

/// Handle an `AddRequest` (RFC 4511 §4.7).
pub async fn handle_add(dsa: &Dsa, req: AddRequest) -> AddResponse {
    // Basic validation: must have an objectClass attribute.
    let has_object_class = req
        .attributes
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("objectClass"));
    if !has_object_class {
        return AddResponse {
            result: LdapResult::error(
                ResultCode::ObjectClassViolation,
                "add request must include an objectClass attribute",
            ),
        };
    }
    // Check for existing entry with the same DN.
    let dn = DistinguishedName::new(&req.entry);
    if let Ok(Some(_)) = dsa.store.get_by_dn(&dn).await {
        return AddResponse {
            result: LdapResult::error(
                ResultCode::EntryAlreadyExists,
                format!("entry already exists: {}", req.entry),
            ),
        };
    }
    // Construct the new object. UUIDv7 in tests; production would call
    // the identity-mapping service.
    let obj = Object {
        uuid: Uuid::from_u128(0),
        dn,
        attributes: req
            .attributes
            .iter()
            .flat_map(|(name, vals)| {
                vals.iter().map(move |v| Attribute {
                    attribute_id: 0,
                    name: name.clone(),
                    value: v.clone(),
                })
            })
            .collect(),
        dnt: 0, // Assigned by store on insert.
    };
    // Note: Uuid::from_u128(0) is a placeholder. Real impl would use
    // Uuid::new_v7 or the identity-mapping service. For Wave 2a tests,
    // callers should set their own UUID if uniqueness matters.
    if let Err(e) = dsa.store.put(&obj).await {
        return AddResponse {
            result: LdapResult::error(
                ResultCode::OperationsError,
                format!("storage error during add: {}", e),
            ),
        };
    }
    AddResponse::success()
}

/// Handle a `DelRequest` (RFC 4511 §4.8).
pub async fn handle_delete(dsa: &Dsa, req: DelRequest) -> DelResponse {
    let dn = DistinguishedName::new(&req.entry);
    // Look up the object to get its UUID for delete.
    let obj = match dsa.store.get_by_dn(&dn).await {
        Ok(Some(o)) => o,
        Ok(None) => {
            return DelResponse {
                result: LdapResult::error(
                    ResultCode::NoSuchObject,
                    format!("entry not found: {}", req.entry),
                ),
            };
        }
        Err(e) => {
            return DelResponse {
                result: LdapResult::error(
                    ResultCode::OperationsError,
                    format!("storage error during delete lookup: {}", e),
                ),
            };
        }
    };
    if let Err(e) = dsa.store.delete(obj.uuid).await {
        return DelResponse {
            result: LdapResult::error(
                ResultCode::OperationsError,
                format!("storage error during delete: {}", e),
            ),
        };
    }
    DelResponse::success()
}

/// Build a `SearchResultDone` from a [`DsaError`] (used by the server
/// when `handle_search` returns an error).
pub fn search_done_from_error(err: &DsaError) -> SearchResultDone {
    let (code, msg) = match err {
        DsaError::NotImplemented(msg) => (ResultCode::UnwillingToPerform, msg.clone()),
        DsaError::Ldap(msg) => (ResultCode::ProtocolError, msg.clone()),
        DsaError::SchemaValidation(msg) => (ResultCode::ObjectClassViolation, msg.clone()),
        DsaError::Storage(e) => (ResultCode::OperationsError, e.to_string()),
        DsaError::Replication(e) => (ResultCode::OperationsError, e.to_string()),
        DsaError::Backend(msg) => (ResultCode::OperationsError, msg.clone()),
    };
    SearchResultDone {
        result: LdapResult::error(code, msg),
    }
}

// (No trailing private imports — every imported item is used above.)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{Filter, Substring};
    use crate::types::{AuthenticationChoice, BindRequest as BindReq};
    use crate::types::{Change as Ch, ModificationOp as ModOp};
    use adrian_identity_testkit::InMemoryIdentityMapping;
    use adrian_repl_testkit::InMemoryReplicator;
    use adrian_schema_traits::SchemaProjection;
    use adrian_storage_core::{
        Attribute as Attr, DirectoryStore, DistinguishedName as DN, Object as Obj,
    };
    use adrian_storage_testkit::InMemoryDirectoryStore;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn dummy_invocation_id() -> Uuid {
        Uuid::from_u128(0x_ABCD)
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

    /// Build a test Dsa backed by an InMemoryDirectoryStore, with the
    /// `list_objects` callback wired to enumerate the store's `objects` map.
    fn build_test_dsa_with_store() -> (Dsa, Arc<InMemoryDirectoryStore>) {
        let store = Arc::new(InMemoryDirectoryStore::new());
        let store_clone = Arc::clone(&store);
        let list_objects = Arc::new(move || {
            store_clone
                .objects
                .read()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<_>>()
        });
        let dsa = Dsa {
            store: Arc::clone(&store) as Arc<dyn DirectoryStore>,
            replicator: Arc::new(InMemoryReplicator::new(dummy_invocation_id())),
            identity_mapping: Arc::new(InMemoryIdentityMapping::new()),
            schema_projection: empty_schema_projection(),
            invocation_id: dummy_invocation_id(),
            ldap_bind_addr: dummy_socket_addr(1389),
            gc_bind_addr: dummy_socket_addr(3268),
            list_objects,
        };
        (dsa, store)
    }

    /// Insert a test user object into the store.
    async fn insert_user(store: &InMemoryDirectoryStore, dn: &str, cn: &str) -> Uuid {
        let uuid = Uuid::from_u128(0x_1234);
        let obj = Obj {
            uuid,
            dn: DN::new(dn),
            attributes: vec![
                Attr {
                    attribute_id: 0,
                    name: "objectClass".into(),
                    value: b"user".to_vec(),
                },
                Attr {
                    attribute_id: 0,
                    name: "cn".into(),
                    value: cn.as_bytes().to_vec(),
                },
            ],
            dnt: 0,
        };
        store.put(&obj).await.unwrap();
        uuid
    }

    #[tokio::test]
    async fn bind_anonymous_succeeds() {
        let (dsa, _store) = build_test_dsa_with_store();
        let req = BindReq {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Simple(Vec::new()),
        };
        let resp = handle_bind(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::Success);
    }

    #[tokio::test]
    async fn bind_simple_with_existing_dn_succeeds() {
        let (dsa, store) = build_test_dsa_with_store();
        insert_user(&store, "CN=alice,DC=adrian,DC=example,DC=com", "alice").await;
        let req = BindReq {
            version: 3,
            name: "CN=alice,DC=adrian,DC=example,DC=com".into(),
            authentication: AuthenticationChoice::Simple(b"s3cret".to_vec()),
        };
        let resp = handle_bind(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::Success);
    }

    #[tokio::test]
    async fn bind_simple_with_nonexistent_dn_fails() {
        let (dsa, _store) = build_test_dsa_with_store();
        let req = BindReq {
            version: 3,
            name: "CN=nobody,DC=adrian,DC=example,DC=com".into(),
            authentication: AuthenticationChoice::Simple(b"s3cret".to_vec()),
        };
        let resp = handle_bind(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::InvalidCredentials);
    }

    #[tokio::test]
    async fn bind_wrong_version_rejected() {
        let (dsa, _store) = build_test_dsa_with_store();
        let req = BindReq {
            version: 2,
            name: String::new(),
            authentication: AuthenticationChoice::Simple(Vec::new()),
        };
        let resp = handle_bind(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::ProtocolError);
    }

    #[tokio::test]
    async fn bind_sasl_not_supported() {
        let (dsa, _store) = build_test_dsa_with_store();
        let req = BindReq {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Sasl(crate::types::SaslCredentials {
                mechanism: "GSSAPI".into(),
                credentials: None,
            }),
        };
        let resp = handle_bind(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::AuthMethodNotSupported);
    }

    #[tokio::test]
    async fn search_base_returns_single_entry() {
        let (dsa, store) = build_test_dsa_with_store();
        insert_user(&store, "CN=alice,DC=adrian,DC=example,DC=com", "alice").await;
        let req = SearchRequest {
            base_dn: "CN=alice,DC=adrian,DC=example,DC=com".into(),
            scope: 0,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            filter: Filter::present("objectClass"),
            attributes: Vec::new(),
            types_only: false,
        };
        let results = handle_search(&dsa, req).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "CN=alice,DC=adrian,DC=example,DC=com");
        // Should have objectClass and cn attributes.
        assert!(results[0]
            .attributes
            .iter()
            .any(|(n, _)| n == "objectClass"));
        assert!(results[0].attributes.iter().any(|(n, _)| n == "cn"));
    }

    #[tokio::test]
    async fn search_subtree_returns_all_descendants() {
        let (dsa, store) = build_test_dsa_with_store();
        insert_user(&store, "CN=alice,DC=adrian,DC=example,DC=com", "alice").await;
        insert_user(&store, "CN=bob,OU=Users,DC=adrian,DC=example,DC=com", "bob").await;
        insert_user(
            &store,
            "CN=carol,OU=Users,DC=adrian,DC=example,DC=com",
            "carol",
        )
        .await;
        let req = SearchRequest {
            base_dn: "DC=adrian,DC=example,DC=com".into(),
            scope: 2,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            filter: Filter::present("objectClass"),
            attributes: Vec::new(),
            types_only: false,
        };
        let results = handle_search(&dsa, req).await.unwrap();
        // The base DN doesn't exist as an object, but the three users are
        // descendants — they should all be returned.
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn search_with_equality_filter() {
        let (dsa, store) = build_test_dsa_with_store();
        insert_user(&store, "CN=alice,DC=adrian,DC=example,DC=com", "alice").await;
        insert_user(&store, "CN=bob,DC=adrian,DC=example,DC=com", "bob").await;
        let req = SearchRequest {
            base_dn: "DC=adrian,DC=example,DC=com".into(),
            scope: 2,
            deref_aliases: 0,
            size_limit: 0,
            time_limit: 0,
            filter: Filter::equality("cn", "alice"),
            attributes: Vec::new(),
            types_only: false,
        };
        let results = handle_search(&dsa, req).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].dn, "CN=alice,DC=adrian,DC=example,DC=com");
    }

    #[tokio::test]
    async fn search_root_dse() {
        let (dsa, _store) = build_test_dsa_with_store();
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
        let results = handle_search(&dsa, req).await.unwrap();
        assert_eq!(results.len(), 1);
        let root = &results[0];
        assert!(root.dn.is_empty());
        assert!(root.attributes.iter().any(|(n, _)| n == "namingContexts"));
        assert!(root
            .attributes
            .iter()
            .any(|(n, _)| n == "supportedLDAPVersion"));
    }

    #[tokio::test]
    async fn modify_replace_attribute() {
        let (dsa, store) = build_test_dsa_with_store();
        let uuid = insert_user(&store, "CN=alice,DC=adrian,DC=example,DC=com", "alice").await;
        let req = ModifyRequest {
            object: "CN=alice,DC=adrian,DC=example,DC=com".into(),
            changes: vec![Ch {
                operation: ModOp::Replace,
                modification: ("displayName".into(), vec![b"Alice Liddell".to_vec()]),
            }],
        };
        let resp = handle_modify(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::Success);
        // Verify the attribute was written.
        let obj = store.get(uuid).await.unwrap().unwrap();
        assert!(obj
            .attributes
            .iter()
            .any(|a| { a.name == "displayName" && a.value == b"Alice Liddell" }));
    }

    #[tokio::test]
    async fn modify_nonexistent_returns_no_such_object() {
        let (dsa, _store) = build_test_dsa_with_store();
        let req = ModifyRequest {
            object: "CN=nobody,DC=adrian,DC=example,DC=com".into(),
            changes: vec![Ch {
                operation: ModOp::Replace,
                modification: ("displayName".into(), vec![b"X".to_vec()]),
            }],
        };
        let resp = handle_modify(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::NoSuchObject);
    }

    #[tokio::test]
    async fn add_creates_entry() {
        let (dsa, store) = build_test_dsa_with_store();
        let req = AddRequest {
            entry: "CN=bob,DC=adrian,DC=example,DC=com".into(),
            attributes: vec![
                ("cn".into(), vec![b"bob".to_vec()]),
                ("objectClass".into(), vec![b"user".to_vec()]),
            ],
        };
        let resp = handle_add(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::Success);
        // Verify the entry exists (lookup by DN).
        let obj = store
            .get_by_dn(&DN::new("CN=bob,DC=adrian,DC=example,DC=com"))
            .await
            .unwrap()
            .unwrap();
        assert!(obj.attributes.iter().any(|a| a.name == "cn"));
    }

    #[tokio::test]
    async fn add_without_object_class_rejected() {
        let (dsa, _store) = build_test_dsa_with_store();
        let req = AddRequest {
            entry: "CN=bob,DC=adrian,DC=example,DC=com".into(),
            attributes: vec![("cn".into(), vec![b"bob".to_vec()])],
        };
        let resp = handle_add(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::ObjectClassViolation);
    }

    #[tokio::test]
    async fn add_duplicate_rejected() {
        let (dsa, store) = build_test_dsa_with_store();
        insert_user(&store, "CN=bob,DC=adrian,DC=example,DC=com", "bob").await;
        let req = AddRequest {
            entry: "CN=bob,DC=adrian,DC=example,DC=com".into(),
            attributes: vec![("objectClass".into(), vec![b"user".to_vec()])],
        };
        let resp = handle_add(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::EntryAlreadyExists);
    }

    #[tokio::test]
    async fn delete_removes_entry() {
        let (dsa, store) = build_test_dsa_with_store();
        let uuid = insert_user(&store, "CN=alice,DC=adrian,DC=example,DC=com", "alice").await;
        let req = DelRequest::new("CN=alice,DC=adrian,DC=example,DC=com");
        let resp = handle_delete(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::Success);
        // Verify it's gone.
        assert!(store.get(uuid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_no_such_object() {
        let (dsa, _store) = build_test_dsa_with_store();
        let req = DelRequest::new("CN=nobody,DC=adrian,DC=example,DC=com");
        let resp = handle_delete(&dsa, req).await;
        assert_eq!(resp.result.result_code, ResultCode::NoSuchObject);
    }

    #[test]
    fn root_dse_contains_required_attributes() {
        let root = root_dse();
        let names: Vec<&str> = root.attributes.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"namingContexts"));
        assert!(names.contains(&"defaultNamingContext"));
        assert!(names.contains(&"supportedLDAPVersion"));
        assert!(names.contains(&"supportedSASLMechanisms"));
        assert!(names.contains(&"vendorName"));
        // supportedLDAPVersion should be [3].
        let v = root
            .attributes
            .iter()
            .find(|(n, _)| n == "supportedLDAPVersion")
            .unwrap();
        assert_eq!(v.1, vec![b"3".to_vec()]);
    }

    #[test]
    fn filter_present_matches() {
        let obj = Obj {
            uuid: Uuid::from_u128(1),
            dn: DN::new("CN=alice"),
            attributes: vec![Attr {
                attribute_id: 0,
                name: "cn".into(),
                value: b"alice".to_vec(),
            }],
            dnt: 1,
        };
        assert!(filter_matches(&obj, &Filter::present("cn")));
        assert!(filter_matches(&obj, &Filter::present("CN"))); // case-insensitive
        assert!(!filter_matches(&obj, &Filter::present("sn")));
    }

    #[test]
    fn filter_equality_matches() {
        let obj = Obj {
            uuid: Uuid::from_u128(1),
            dn: DN::new("CN=alice"),
            attributes: vec![Attr {
                attribute_id: 0,
                name: "cn".into(),
                value: b"alice".to_vec(),
            }],
            dnt: 1,
        };
        assert!(filter_matches(
            &obj,
            &Filter::Equality {
                attribute: "cn".into(),
                value: b"alice".to_vec(),
            }
        ));
        assert!(!filter_matches(
            &obj,
            &Filter::Equality {
                attribute: "cn".into(),
                value: b"bob".to_vec(),
            }
        ));
    }

    #[test]
    fn filter_and_or_not() {
        let obj = Obj {
            uuid: Uuid::from_u128(1),
            dn: DN::new("CN=alice"),
            attributes: vec![
                Attr {
                    attribute_id: 0,
                    name: "cn".into(),
                    value: b"alice".to_vec(),
                },
                Attr {
                    attribute_id: 0,
                    name: "objectClass".into(),
                    value: b"user".to_vec(),
                },
            ],
            dnt: 1,
        };
        let and = Filter::and(vec![
            Filter::equality("objectClass", "user"),
            Filter::equality("cn", "alice"),
        ]);
        assert!(filter_matches(&obj, &and));
        let and_fail = Filter::and(vec![
            Filter::equality("objectClass", "user"),
            Filter::equality("cn", "bob"),
        ]);
        assert!(!filter_matches(&obj, &and_fail));
        let or = Filter::or(vec![
            Filter::equality("cn", "bob"),
            Filter::equality("cn", "alice"),
        ]);
        assert!(filter_matches(&obj, &or));
        let not = Filter::not(Filter::equality("cn", "bob"));
        assert!(filter_matches(&obj, &not));
    }

    #[test]
    fn filter_substrings_matches() {
        let obj = Obj {
            uuid: Uuid::from_u128(1),
            dn: DN::new("CN=alice"),
            attributes: vec![Attr {
                attribute_id: 0,
                name: "cn".into(),
                value: b"alice liddell".to_vec(),
            }],
            dnt: 1,
        };
        let f = Filter::Substrings {
            attribute: "cn".into(),
            substrings: vec![
                Substring::Initial(b"al".to_vec()),
                Substring::Any(b"ce".to_vec()),
                Substring::Final(b"ell".to_vec()),
            ],
        };
        assert!(filter_matches(&obj, &f));
        let f_fail = Filter::Substrings {
            attribute: "cn".into(),
            substrings: vec![Substring::Initial(b"bob".to_vec())],
        };
        assert!(!filter_matches(&obj, &f_fail));
    }

    #[test]
    fn dn_is_child_of_basic() {
        assert!(dn_is_child_of(
            "CN=alice,DC=adrian,DC=com",
            "DC=adrian,DC=com"
        ));
        assert!(dn_is_child_of(
            "CN=alice,DC=adrian,DC=com",
            "dc=adrian,dc=com"
        ));
        assert!(!dn_is_child_of(
            "CN=alice,OU=Users,DC=adrian,DC=com",
            "DC=adrian,DC=com"
        ));
        assert!(!dn_is_child_of("DC=adrian,DC=com", "DC=adrian,DC=com"));
    }

    #[test]
    fn dn_is_descendant_of_includes_self() {
        assert!(dn_is_descendant_of("DC=adrian,DC=com", "DC=adrian,DC=com"));
        assert!(dn_is_descendant_of(
            "CN=alice,OU=Users,DC=adrian,DC=com",
            "DC=adrian,DC=com"
        ));
        assert!(!dn_is_descendant_of("DC=other,DC=com", "DC=adrian,DC=com"));
    }
}
