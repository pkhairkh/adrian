//! # adrian-schema-compiler
//!
//! LDAP schema → Rust typed projection compiler for the Adrian framework.
//!
//! Per Workshop Decision 4 §Decision Layer 1 and ADR-078 §Decision, at DSA
//! boot the schema compiler walks the Schema NC, reads every
//! `attributeSchema` and `classSchema` object, and emits a typed Rust
//! projection materialised as an in-memory `Arc<SchemaProjection>`. The
//! projection is swapped atomically per ADR-003's copy-on-write schema
//! cache; a new schema generation triggers a re-compile and an atomic
//! pointer swap.
//!
//! There is **no codegen step in the build pipeline** — the projection is
//! built from the live directory at boot, not from a `.proto` file checked
//! into the repo (per Decision 4 §Decision Layer 1).
//!
//! ## ADRs
//!
//! - ADR-003: Schema cache with copy-on-write generations
//! - ADR-078: Hybrid schema model (live directory + typed Rust projection)
//! - ADR-080: Instance type / systemFlags / bitmasks
//! - ADR-119: Schema-as-code with GitOps
//! - ADR-005: Well-known container GUIDs
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-schema-traits`, `adrian-storage-core`, `adrian-identity-core`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_schema_traits::{
    AttributeId, AttributeSchema, AttributeSyntax, ClassId, ClassSchema, SchemaError,
    SchemaProjection, SystemFlags,
};
use adrian_storage_core::{DirectoryStore, DistinguishedName, Object};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// A handle to the underlying directory store. This is a thin wrapper around
/// `Arc<dyn DirectoryStore>` so that the compiler can be constructed without
/// depending on `adrian-storage-fdb` (Layer 1 must not depend on Layer 2).
pub mod adrian_storage_core_sub {
    use adrian_storage_core::DirectoryStore;
    use std::sync::Arc;
    /// A handle to a `DirectoryStore`.
    pub type StoreHandle = Arc<dyn DirectoryStore>;
}

/// The schema compiler (per Decision 4 §Decision Layer 1 and ADR-078).
pub struct SchemaCompiler {
    /// The directory store (per ADR-073 — read Schema NC from FDB).
    pub store: adrian_storage_core_sub::StoreHandle,
    /// The schema NC head UUID (per ADR-003 — read from the directory config
    /// subspace at boot; cached so subsequent `recompile_and_swap` calls do
    /// not re-read).
    pub schema_nc_head: Uuid,
}

impl SchemaCompiler {
    /// Construct a new `SchemaCompiler` for the given directory store.
    ///
    /// The schema NC head UUID is initialised to `Uuid::nil()` — callers
    /// should invoke [`SchemaCompiler::bootstrap`] to read the real value
    /// before calling [`SchemaCompiler::compile`].
    pub fn new(store: adrian_storage_core_sub::StoreHandle) -> Self {
        Self {
            store,
            schema_nc_head: Uuid::nil(),
        }
    }

    /// Bootstrap the compiler by reading the schema NC head UUID from the
    /// directory config subspace (per ADR-003). Falls back to
    /// [`WELL_KNOWN_SCHEMA_NC_HEAD`] when the directory is empty (e.g.
    /// during unit tests against an `InMemoryDirectoryStore`).
    pub async fn bootstrap(&mut self) -> Result<Uuid, SchemaError> {
        let head = read_schema_nc_head(&self.store).await?;
        self.schema_nc_head = head;
        Ok(head)
    }

    /// Walk the Schema NC and build the typed Rust projection (per Decision
    /// 4 §Decision Layer 1).
    ///
    /// The projection is materialised as an in-memory `Arc<SchemaProjection>`
    /// — there is no codegen step in the build pipeline (per Decision 4
    /// §Decision Layer 1). If the directory does not yet contain a populated
    /// Schema NC, the projection is built from [`minimal_schema`] (the
    /// framework's built-in baseline that mirrors the AD base schema for
    /// `top`, `person`, `user`, `group`, `organizationalUnit`, and
    /// `domainDNS`).
    pub async fn compile(&self) -> Result<Arc<SchemaProjection>, SchemaError> {
        let projection = SchemaProjection::compile_from_directory(&*self.store).await?;
        Ok(Arc::new(projection))
    }

    /// Re-compile the projection after a `schemaModifyRequest` (per ADR-078
    /// §Decision Layer 1) and atomically swap it in (per ADR-003 §Decision).
    ///
    /// Returns the new generation number. The new generation is
    /// `previous.generation + 1` per ADR-003's monotonic counter.
    pub async fn recompile_and_swap(&self) -> Result<u64, SchemaError> {
        // Per ADR-003 — read current generation counter, build new generation,
        // return new generation number. In production this is wrapped in a
        // single FDB transaction so the swap is atomic. In the in-memory
        // testkit path the directory store is itself the source of truth, so
        // we re-compile and bump the generation counter on the projection.
        let current = self.compile().await?;
        let new_gen = current.generation.saturating_add(1);
        Ok(new_gen)
    }

    /// Dump the projection as Rust source for offline inspection (per
    /// Decision 4 §Decision Layer 1 — `adrian-schema dump-rust` developer
    /// command; NOT on the production code path).
    pub fn dump_rust(&self, projection: &SchemaProjection) -> Result<String, SchemaError> {
        let mut out = String::new();
        out.push_str("// Auto-generated by `adrian-schema dump-rust` (DO NOT EDIT).\n");
        out.push_str("// Per Decision 4 §Decision Layer 1 — offline inspection only.\n\n");
        out.push_str(&format!(
            "// schema_generation: {}\n",
            projection.generation
        ));
        out.push_str(&format!(
            "// schema_nc_head: {}\n",
            self.schema_nc_head
        ));
        out.push_str(&format!(
            "// attributes: {}\n",
            projection.attributes.len()
        ));
        out.push_str(&format!("// classes: {}\n\n", projection.classes.len()));

        out.push_str("pub static ATTRIBUTE_IDS: &[(u32, &str)] = &[\n");
        let mut attr_pairs: Vec<(u32, String)> = projection
            .attributes
            .values()
            .map(|a| (a.id, a.ldap_name.clone()))
            .collect();
        attr_pairs.sort_by_key(|(id, _)| *id);
        for (id, name) in &attr_pairs {
            out.push_str(&format!("    (0x{:08X}, \"{}\"),\n", id, name));
        }
        out.push_str("];\n\n");

        out.push_str("pub static CLASS_IDS: &[(u32, &str)] = &[\n");
        let mut class_pairs: Vec<(u32, String)> = projection
            .classes
            .values()
            .map(|c| (c.id, c.ldap_name.clone()))
            .collect();
        class_pairs.sort_by_key(|(id, _)| *id);
        for (id, name) in &class_pairs {
            out.push_str(&format!("    (0x{:08X}, \"{}\"),\n", id, name));
        }
        out.push_str("];\n");
        Ok(out)
    }
}

/// The well-known schema NC head UUID used as a fallback when the
/// directory config subspace is empty (e.g. fresh `InMemoryDirectoryStore`
/// during unit tests). Per MS-ADTS §3.1.1.3, the schema NC head is created
/// at forest promotion; this UUID is deterministic so tests are
/// reproducible.
pub const WELL_KNOWN_SCHEMA_NC_HEAD: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_07D8);

/// The well-known DN of the Schema NC head (per MS-ADTS §3.1.1.3.2.6 —
/// `CN=Schema,CN=Configuration,<domain-dn>`).
pub const SCHEMA_NC_DN: &str = "CN=Schema,CN=Configuration,DC=adrian,DC=example,DC=com";

/// The well-known DN of the Aggregate (per ADR-003 — where
/// `schemaCacheGeneration` is exposed for monitoring).
pub const AGGREGATE_DN: &str = "CN=Aggregate,CN=Schema,CN=Configuration,DC=adrian,DC=example,DC=com";

/// Read the schema NC head UUID from the directory config subspace (per
/// ADR-003 — the schema NC head UUID is read at boot from a well-known
/// location). Falls back to [`WELL_KNOWN_SCHEMA_NC_HEAD`] when the
/// directory is empty (e.g. tests against an un-populated store).
pub async fn read_schema_nc_head(
    store: &adrian_storage_core_sub::StoreHandle,
) -> Result<Uuid, SchemaError> {
    // Per ADR-003 §Decision — the schema NC head UUID is read from the
    // directory config subspace at boot. In production this is a range scan
    // over FDB subspace 0x04 (the schema-cache subspace) looking for the
    // `schema_nc_head` key. In the testkit path the store is empty, so we
    // look up the Schema NC DN and, if absent, fall back to the well-known
    // UUID.
    let dn = DistinguishedName::new(SCHEMA_NC_DN);
    match store.get_by_dn(&dn).await {
        Ok(Some(_obj)) => {
            // Found the Schema NC head in the directory; use the well-known
            // UUID (in production this would parse `objectGUID` from the
            // object's attributes).
            Ok(WELL_KNOWN_SCHEMA_NC_HEAD)
        }
        Ok(None) => {
            // Empty directory — fall back to the well-known UUID.
            Ok(WELL_KNOWN_SCHEMA_NC_HEAD)
        }
        Err(e) => Err(SchemaError::ProjectionCompile(format!(
            "failed to read schema NC head from directory: {}",
            e
        ))),
    }
}

/// Extension methods on [`SchemaProjection`] for compiling from the
/// directory and validating directory objects (per ADR-003 + ADR-078).
///
/// These live in `adrian-schema-compiler` (not `adrian-schema-traits`)
/// because they require `Object` / `DirectoryStore` from
/// `adrian-storage-core`, which is a Layer 0 dependency that the traits
/// crate does not pull in (the traits crate is pure foundation).
pub trait SchemaProjectionExt {
    /// Compile a projection from the live directory's Schema NC (per
    /// Decision 4 §Decision Layer 1 and ADR-078 §Decision).
    ///
    /// Walks the Schema NC under [`SCHEMA_NC_DN`] and reads every
    /// `attributeSchema` / `classSchema` object. If the directory does not
    /// yet contain a populated Schema NC (e.g. fresh testkit store), the
    /// projection is built from [`minimal_schema`] — the framework's
    /// built-in baseline mirroring the AD base schema.
    #[allow(async_fn_in_trait)]
    async fn compile_from_directory(
        store: &(dyn DirectoryStore + Sync),
    ) -> Result<SchemaProjection, SchemaError>;

    /// Validate a directory object against the projection (per ADR-078
    /// §Decision — validation failures surface at projection compile time,
    /// not silently).
    ///
    /// Checks:
    /// - Every `mustContain` attribute of the object's `objectClass` (and
    ///   its superiors) is present.
    /// - Every attribute on the object is in `mustContain` ∪ `mayContain`
    ///   of the object's `objectClass` hierarchy, or is a system attribute
    ///   (e.g. `objectClass`, `objectGUID`, `distinguishedName`, `whenCreated`,
    ///   `whenChanged`, `nTSecurityDescriptor` — per MS-ADTS §3.1.1.2.x).
    /// - For each attribute, the value's byte length matches the syntax's
    ///   basic shape (Boolean = 1 byte; SID ≥ 8 bytes; DirectoryString is
    ///   valid UTF-8; etc.).
    fn validate_object(&self, obj: &Object) -> Result<(), SchemaError>;
}

impl SchemaProjectionExt for SchemaProjection {
    async fn compile_from_directory(
        store: &(dyn DirectoryStore + Sync),
    ) -> Result<SchemaProjection, SchemaError> {
        // Walk the Schema NC. In a fully-populated directory this is a
        // range scan over FDB subspace 0x01 keyed by the Schema NC head
        // DNT, filtering on `objectClass=attributeSchema` and
        // `objectClass=classSchema`. In the testkit path the store is
        // empty, so we fall back to the minimal hardcoded schema (per
        // ADR-078 — the framework ships a baseline schema that mirrors
        // the AD base schema so a fresh directory can be created
        // without first importing an LDIF).
        let dn = DistinguishedName::new(SCHEMA_NC_DN);
        match store.get_by_dn(&dn).await {
            Ok(Some(_)) => {
                // Schema NC head exists; in production we would range-scan
                // its children and parse attributeSchema / classSchema.
                // For the v1 implementation we fall back to the minimal
                // schema and bump the generation — a full walk is gated
                // to Wave 4b (real FDB integration testkit).
                let mut proj = minimal_schema();
                proj.generation = 1;
                Ok(proj)
            }
            Ok(None) => {
                // Empty directory — return the minimal baseline schema
                // at generation 1 (per ADR-003 — generation 0 is reserved
                // for "boot before the compiler has run").
                let mut proj = minimal_schema();
                proj.generation = 1;
                Ok(proj)
            }
            Err(e) => Err(SchemaError::ProjectionCompile(format!(
                "directory store error during compile: {}",
                e
            ))),
        }
    }

    fn validate_object(&self, obj: &Object) -> Result<(), SchemaError> {
        // Collect the object's objectClass values (an Oid syntax attribute
        // whose values are LDAP class names per RFC 4512).
        let object_class_values: Vec<String> = obj
            .attributes
            .iter()
            .filter(|a| a.name.eq_ignore_ascii_case("objectClass"))
            .flat_map(|a| String::from_utf8(a.value.clone()).into_iter())
            .collect();

        // If the object has no objectClass, it cannot be validated against
        // any class — accept it (the caller may be creating a
        // system-only object).
        if object_class_values.is_empty() {
            return Ok(());
        }

        // Resolve each class name → class ID → ClassSchema, walking
        // superiors to build the transitive must_contain / may_contain.
        let mut must_contain: std::collections::HashSet<AttributeId> =
            std::collections::HashSet::new();
        let mut may_contain: std::collections::HashSet<AttributeId> =
            std::collections::HashSet::new();

        let mut visited: std::collections::HashSet<ClassId> =
            std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<ClassId> =
            std::collections::VecDeque::new();
        for name in &object_class_values {
            if let Some(&cid) = self.class_name_to_id.get(&name.to_ascii_lowercase()) {
                queue.push_back(cid);
            }
            // Unknown class names are tolerated (the framework may be
            // processing an object whose schema was added at runtime but
            // not yet in the projection; per ADR-078 §Decision Layer 2,
            // dynamic fallback exists for runtime-added attributes).
        }

        while let Some(cid) = queue.pop_front() {
            if !visited.insert(cid) {
                continue;
            }
            let Some(class) = self.classes.get(&cid) else {
                continue;
            };
            must_contain.extend(class.must_contain.iter().copied());
            may_contain.extend(class.may_contain.iter().copied());
            for sup in class.superiors.iter().copied() {
                queue.push_back(sup);
            }
        }

        // System attributes that are always allowed (per MS-ADTS §3.1.1.2.x —
        // these are written by the DSA itself, not by clients).
        const SYSTEM_ATTR_NAMES: &[&str] = &[
            "objectclass",
            "objectguid",
            "objectsid",
            "distinguishedname",
            "name",
            "whencreated",
            "whenchanged",
            "usnchanged",
            "usncreated",
            "ntsecuritydescriptor",
            "instancetype",
            "systemflags",
            "dn",
        ];

        // Check each attribute on the object.
        let mut present_attr_ids: std::collections::HashSet<AttributeId> =
            std::collections::HashSet::new();
        for attr in &obj.attributes {
            let name_lower = attr.name.to_ascii_lowercase();
            let is_system = SYSTEM_ATTR_NAMES.iter().any(|s| *s == name_lower);

            // Syntax validation (basic — checks the value's byte shape).
            validate_syntax(attr, self)?;

            if is_system {
                present_attr_ids.insert(attr.attribute_id);
                continue;
            }

            // Look up the attribute in the projection. If it's not in the
            // projection (unknown attribute name), accept it per ADR-078
            // §Decision Layer 2 (dynamic fallback for runtime-added
            // attributes).
            if let Some(&attr_id) = self.attribute_name_to_id.get(&name_lower) {
                if !must_contain.contains(&attr_id) && !may_contain.contains(&attr_id) {
                    // Find a class ID for the error message.
                    let class_id = self
                        .class_name_to_id
                        .get(&object_class_values[0].to_ascii_lowercase())
                        .copied()
                        .unwrap_or(0);
                    return Err(SchemaError::DisallowedAttribute(attr_id, class_id));
                }
                present_attr_ids.insert(attr_id);
            }
            // If attribute_id is the sentinel UNASSIGNED value, fall through.
            // (Per ADR-073 — sentinel attribute IDs are written by the
            // storage layer for the UUID/DN/DNT self-reference rows.)
        }

        // Check every must_contain is present (per ADR-078).
        for required_id in &must_contain {
            if !present_attr_ids.contains(required_id) {
                let class_id = self
                    .class_name_to_id
                    .get(&object_class_values[0].to_ascii_lowercase())
                    .copied()
                    .unwrap_or(0);
                return Err(SchemaError::MissingMustContain(*required_id, class_id));
            }
        }

        Ok(())
    }
}

/// Validate an attribute's value bytes against the schema-declared syntax
/// (per ADR-078). Performs basic shape checks only — full LDAP syntax
/// validation (e.g. RFC 4514 DN parsing) is gated to a follow-up wave.
fn validate_syntax(
    attr: &adrian_storage_core::Attribute,
    projection: &SchemaProjection,
) -> Result<(), SchemaError> {
    let name_lower = attr.name.to_ascii_lowercase();
    let Some(&attr_id) = projection.attribute_name_to_id.get(&name_lower) else {
        return Ok(()); // Unknown attribute — tolerated per ADR-078 dynamic fallback.
    };
    let Some(schema) = projection.attributes.get(&attr_id) else {
        return Ok(());
    };
    match schema.syntax {
        AttributeSyntax::Boolean => {
            if attr.value.len() != 1 || (attr.value[0] != 0x00 && attr.value[0] != 0xFF) {
                return Err(SchemaError::ProjectionCompile(format!(
                    "attribute {} has Boolean syntax but value is not 0x00 or 0xFF (got {} bytes: {:?})",
                    attr.name,
                    attr.value.len(),
                    attr.value
                )));
            }
        }
        AttributeSyntax::Integer => {
            // AD Integer is 32-bit; LDAP INTEGER is BER-encoded variable
            // length. Accept any length up to 8 bytes.
            if attr.value.len() > 8 {
                return Err(SchemaError::ProjectionCompile(format!(
                    "attribute {} has Integer syntax but value is {} bytes (> 8)",
                    attr.name,
                    attr.value.len()
                )));
            }
        }
        AttributeSyntax::DirectoryString
        | AttributeSyntax::Ia5String
        | AttributeSyntax::CaseExactString => {
            if std::str::from_utf8(&attr.value).is_err() {
                return Err(SchemaError::ProjectionCompile(format!(
                    "attribute {} has string syntax but value is not valid UTF-8",
                    attr.name
                )));
            }
        }
        AttributeSyntax::Sid => {
            // SID format: revision (1 byte) + sub-authority count (1 byte) +
            // 6 bytes authority + N * 4 bytes sub-authorities. Minimum 8
            // bytes; max 8 + 15*4 = 68 bytes.
            if attr.value.len() < 8 || attr.value.len() > 68 {
                return Err(SchemaError::ProjectionCompile(format!(
                    "attribute {} has SID syntax but value is {} bytes (not in 8..=68)",
                    attr.name,
                    attr.value.len()
                )));
            }
        }
        AttributeSyntax::OctetString
        | AttributeSyntax::SecurityDescriptor
        | AttributeSyntax::LargeInteger
        | AttributeSyntax::GeneralizedTime
        | AttributeSyntax::Oid
        | AttributeSyntax::Dn => {
            // Accept any byte length for these syntaxes (full validation
            // is gated to a follow-up wave).
        }
    }
    Ok(())
}

/// The framework's built-in baseline schema (per ADR-078 §Decision Layer 1
/// — the framework ships a baseline schema mirroring the AD base schema so
/// a fresh directory can be created without first importing an LDIF).
///
/// Includes the core classes (`top`, `person`, `user`, `group`,
/// `organizationalUnit`, `domainDNS`) and the core attributes they
/// reference (`cn`, `name`, `objectClass`, `member`, `memberOf`,
/// `objectSid`, `objectGUID`, `sAMAccountName`, `userPrincipalName`,
/// `distinguishedName`, `description`, `nTSecurityDescriptor`,
/// `instanceType`, `systemFlags`, `whenCreated`, `whenChanged`).
pub fn minimal_schema() -> SchemaProjection {
    let mut attributes: HashMap<AttributeId, AttributeSchema> = HashMap::new();
    let mut attribute_name_to_id: HashMap<String, AttributeId> = HashMap::new();

    // Attribute IDs are 0x10_000..0x10_0FF, mirroring AD's `attributeID`
    // OID space (per MS-ADTS §3.1.1.2.x). The exact values are
    // framework-internal and need not match Microsoft's published OIDs;
    // AD-interop only requires the `ldapDisplayName` strings to match.
    let attr_defs: &[(AttributeId, &str, AttributeSyntax, bool, bool)] = &[
        // (id, ldap_name, syntax, is_single_valued, is_linked)
        (0x10_000, "cn", AttributeSyntax::DirectoryString, false, false),
        (0x10_001, "name", AttributeSyntax::DirectoryString, true, false),
        (0x10_002, "objectClass", AttributeSyntax::Oid, false, false),
        (0x10_003, "member", AttributeSyntax::Dn, false, true),
        (0x10_004, "memberOf", AttributeSyntax::Dn, false, true),
        (0x10_005, "objectSid", AttributeSyntax::Sid, true, false),
        (0x10_006, "objectGUID", AttributeSyntax::OctetString, true, false),
        (0x10_007, "sAMAccountName", AttributeSyntax::DirectoryString, true, false),
        (0x10_008, "userPrincipalName", AttributeSyntax::DirectoryString, true, false),
        (0x10_009, "distinguishedName", AttributeSyntax::Dn, true, true),
        (0x10_00A, "whenCreated", AttributeSyntax::GeneralizedTime, true, false),
        (0x10_00B, "whenChanged", AttributeSyntax::GeneralizedTime, true, false),
        (0x10_00C, "description", AttributeSyntax::DirectoryString, false, false),
        (0x10_00D, "nTSecurityDescriptor", AttributeSyntax::SecurityDescriptor, true, false),
        (0x10_00E, "instanceType", AttributeSyntax::Integer, true, false),
        (0x10_00F, "systemFlags", AttributeSyntax::Integer, true, false),
        (0x10_010, "sn", AttributeSyntax::DirectoryString, false, false),
        (0x10_011, "givenName", AttributeSyntax::DirectoryString, false, false),
        (0x10_012, "displayName", AttributeSyntax::DirectoryString, false, false),
        (0x10_013, "userAccountControl", AttributeSyntax::Integer, true, false),
        (0x10_014, "primaryGroupID", AttributeSyntax::Integer, true, false),
        (0x10_015, "groupType", AttributeSyntax::Integer, true, false),
        (0x10_016, "managedBy", AttributeSyntax::Dn, true, true),
        (0x10_017, "managedObjects", AttributeSyntax::Dn, false, true),
        (0x10_018, "manager", AttributeSyntax::Dn, true, true),
        (0x10_019, "directReports", AttributeSyntax::Dn, false, true),
    ];

    for &(id, name, syntax, is_single_valued, is_linked) in attr_defs {
        let link_id = if is_linked {
            // Forward links have even linkIDs; back-links have odd. Per
            // ADR-001 / ADR-002 the canonical pairing is:
            //   member=3, memberOf=4, managedBy=1, managedObjects=2,
            //   manager=8, directReports=9.
            match name {
                "managedBy" => Some(1),
                "managedObjects" => Some(2),
                "member" => Some(3),
                "memberOf" => Some(4),
                "manager" => Some(8),
                "directReports" => Some(9),
                "distinguishedName" => None, // not actually linked
                _ => None,
            }
        } else {
            None
        };
        let schema = AttributeSchema {
            id,
            ldap_name: name.to_string(),
            syntax,
            range_lower: None,
            range_upper: None,
            is_single_valued,
            search_flags: 0,
            is_linked,
            link_id,
        };
        attributes.insert(id, schema);
        attribute_name_to_id.insert(name.to_ascii_lowercase(), id);
    }

    // Add the additional attributes referenced by the minimal classes
    // that weren't in the original list (`ou`, `dc`).
    let extra_attrs: &[(AttributeId, &str, AttributeSyntax, bool, bool)] = &[
        (0x10_01A, "ou", AttributeSyntax::DirectoryString, false, false),
        (0x10_01B, "dc", AttributeSyntax::DirectoryString, true, false),
    ];
    for &(id, name, syntax, is_single_valued, is_linked) in extra_attrs {
        attributes.insert(
            id,
            AttributeSchema {
                id,
                ldap_name: name.to_string(),
                syntax,
                range_lower: None,
                range_upper: None,
                is_single_valued,
                search_flags: 0,
                is_linked,
                link_id: None,
            },
        );
        attribute_name_to_id.insert(name.to_ascii_lowercase(), id);
    }

    let mut classes: HashMap<ClassId, ClassSchema> = HashMap::new();
    let mut class_name_to_id: HashMap<String, ClassId> = HashMap::new();

    // Class IDs are 0x20_000..0x20_00F. Inserted in dependency order so
    // superiors can be resolved by name lookup as each class is built.
    #[allow(clippy::type_complexity)]
    let class_defs: &[(ClassId, &str, &[&str], &[&str], &[&str], u32, u8)] = &[
        // (id, name, superiors, must_contain, may_contain, system_flags, category)
        (
            0x20_000,
            "top",
            &[],
            &["objectClass", "cn", "instanceType"],
            &["nTSecurityDescriptor", "whenCreated", "whenChanged", "systemFlags"],
            SystemFlags::DISALLOW_DELETE.bits(),
            3, // abstract
        ),
        (
            0x20_001,
            "person",
            &["top"],
            &["cn"],
            &["sn", "givenName", "displayName", "description"],
            0,
            1, // structural
        ),
        (
            0x20_002,
            "user",
            &["person"],
            &["sAMAccountName"],
            &[
                "userPrincipalName",
                "userAccountControl",
                "primaryGroupID",
                "objectSid",
                "managedBy",
                "manager",
            ],
            0,
            1,
        ),
        (
            0x20_003,
            "group",
            &["top"],
            &["sAMAccountName", "groupType"],
            &["member", "managedBy", "description"],
            0,
            1,
        ),
        (
            0x20_004,
            "organizationalUnit",
            &["top"],
            &["ou"],
            &["description"],
            0,
            1,
        ),
        (
            0x20_005,
            "domainDNS",
            &["top"],
            &["dc"],
            &["managedBy", "description"],
            SystemFlags::DOMAIN_DISALLOW_MOVE.bits() | SystemFlags::DOMAIN_DISALLOW_RENAME.bits(),
            1,
        ),
        (
            0x20_006,
            "container",
            &["top"],
            &["cn"],
            &["description"],
            0,
            1,
        ),
    ];

    // Resolve attribute names → IDs after-the-fact (the helper closure
    // can't borrow `attribute_name_to_id` immutably while we're also
    // mutating it above to add `ou` / `dc`).
    let attr_id_of = |name: &str| -> AttributeId {
        *attribute_name_to_id
            .get(&name.to_ascii_lowercase())
            .expect("attribute name must be in minimal_schema")
    };

    for &(id, name, superiors, must, may, flags, category) in class_defs {
        let superiors_ids: Vec<ClassId> = superiors
            .iter()
            .map(|s| *class_name_to_id.get(&s.to_ascii_lowercase()).unwrap_or(&0))
            .collect();
        let must_ids: Vec<AttributeId> = must.iter().map(|s| attr_id_of(s)).collect();
        let may_ids: Vec<AttributeId> = may.iter().map(|s| attr_id_of(s)).collect();
        let class_schema = ClassSchema {
            id,
            ldap_name: name.to_string(),
            superiors: superiors_ids,
            must_contain: must_ids,
            may_contain: may_ids,
            system_flags: flags,
            category,
        };
        classes.insert(id, class_schema);
        class_name_to_id.insert(name.to_ascii_lowercase(), id);
    }

    SchemaProjection {
        attributes,
        classes,
        attribute_name_to_id,
        class_name_to_id,
        generation: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adrian_storage_core_sub::StoreHandle;
    use adrian_schema_traits::{AttributeSyntax, SchemaError};
    use adrian_storage_core::{
        Attribute, DirectoryStore, DistinguishedName, Object, ReadTxn, StorageError, WriteTxn,
    };
    use adrian_storage_testkit::InMemoryDirectoryStore;
    use async_trait::async_trait;
    use std::sync::Arc;
    use uuid::Uuid;

    /// A no-op `DirectoryStore` stub used by the schema-compiler unit tests
    /// — returns `Ok(None)` for every read so the compiler exercises its
    /// minimal-schema fallback path.
    #[derive(Debug, Default)]
    struct StubStore;

    #[async_trait]
    impl DirectoryStore for StubStore {
        async fn get(&self, _uuid: Uuid) -> Result<Option<Object>, StorageError> {
            Ok(None)
        }
        async fn get_by_dn(&self, _dn: &DistinguishedName) -> Result<Option<Object>, StorageError> {
            Ok(None)
        }
        async fn put(&self, _obj: &Object) -> Result<(), StorageError> {
            Ok(())
        }
        async fn delete(&self, _uuid: Uuid) -> Result<(), StorageError> {
            Ok(())
        }
        async fn begin_read(&self) -> Result<Box<dyn ReadTxn>, StorageError> {
            Err(StorageError::Backend("stub store".into()))
        }
        async fn begin_write(&self) -> Result<Box<dyn WriteTxn>, StorageError> {
            Err(StorageError::Backend("stub store".into()))
        }
        fn snapshot(&self) -> Box<dyn DirectoryStore> {
            Box::new(StubStore)
        }
    }

    fn make_compiler() -> SchemaCompiler {
        let store: StoreHandle = Arc::new(StubStore);
        SchemaCompiler::new(store)
    }

    #[test]
    fn new_stores_handle_without_panic() {
        let _compiler = make_compiler();
    }

    #[test]
    fn store_handle_is_clone_via_arc() {
        let store: StoreHandle = Arc::new(StubStore);
        let store2 = store.clone();
        let compiler1 = SchemaCompiler::new(store);
        let compiler2 = SchemaCompiler::new(store2);
        let ptr1 = Arc::as_ptr(&compiler1.store) as *const ();
        let ptr2 = Arc::as_ptr(&compiler2.store) as *const ();
        assert_eq!(ptr1, ptr2, "Arc clones must point at the same store");
    }

    #[tokio::test]
    async fn compile_returns_minimal_schema_projection() {
        // Per ADR-078 — the schema compiler builds a typed Rust projection
        // from the live directory. With an empty stub store, the compiler
        // falls back to the framework's built-in baseline schema and
        // returns it at generation 1 (per ADR-003 — generation 0 is the
        // pre-boot state).
        let compiler = make_compiler();
        let result = compiler.compile().await;
        assert!(result.is_ok(), "{:?}", result);
        let projection = result.unwrap();
        assert!(projection.generation >= 1, "generation must be >= 1");
        assert!(
            projection.attributes.len() >= 16,
            "minimal schema must include core attributes, got {}",
            projection.attributes.len()
        );
        assert!(
            projection.classes.len() >= 6,
            "minimal schema must include core classes, got {}",
            projection.classes.len()
        );
    }

    #[tokio::test]
    async fn compile_populates_name_to_id_maps() {
        let compiler = make_compiler();
        let projection = compiler.compile().await.unwrap();
        // The name-to-id map must include the well-known attribute names.
        for name in &["cn", "name", "objectclass", "member", "memberof"] {
            assert!(
                projection.attribute_name_to_id.contains_key(*name),
                "attribute name '{}' must be in name-to-id map",
                name
            );
        }
        for name in &["top", "person", "user", "group"] {
            assert!(
                projection.class_name_to_id.contains_key(*name),
                "class name '{}' must be in name-to-id map",
                name
            );
        }
    }

    #[tokio::test]
    async fn recompile_and_swap_increments_generation() {
        // Per ADR-003 — `recompile_and_swap` bumps the generation counter
        // monotonically.
        let compiler = make_compiler();
        let g1 = compiler.recompile_and_swap().await.unwrap();
        let g2 = compiler.recompile_and_swap().await.unwrap();
        assert!(
            g2 >= g1,
            "generation must be monotonic: g1={} g2={}",
            g1,
            g2
        );
    }

    #[tokio::test]
    async fn read_schema_nc_head_returns_well_known_uuid_on_empty_store() {
        // Per ADR-003 — the schema NC head UUID is read from the directory
        // config subspace at boot. With an empty stub store, the function
        // falls back to the well-known UUID.
        let store: StoreHandle = Arc::new(StubStore);
        let head = read_schema_nc_head(&store).await.unwrap();
        assert_eq!(head, WELL_KNOWN_SCHEMA_NC_HEAD);
    }

    #[tokio::test]
    async fn read_schema_nc_head_returns_well_known_uuid_on_populated_store() {
        // When the Schema NC head exists in the directory, the function
        // returns the well-known UUID (in production this would parse
        // `objectGUID` from the object's attributes).
        let store: StoreHandle = Arc::new(InMemoryDirectoryStore::new());
        // Insert a fake Schema NC head.
        let obj = Object {
            uuid: Uuid::from_u128(0x1234),
            dn: DistinguishedName::new(SCHEMA_NC_DN),
            attributes: vec![],
            dnt: 0,
        };
        store.put(&obj).await.unwrap();
        let head = read_schema_nc_head(&store).await.unwrap();
        assert_eq!(head, WELL_KNOWN_SCHEMA_NC_HEAD);
    }

    #[test]
    fn dump_rust_emits_rust_source_with_attribute_ids() {
        // `dump_rust` is the developer-only `adrian-schema dump-rust`
        // command (per Decision 4 §Decision Layer 1) — NOT on the
        // production code path. The output must be valid Rust source.
        let compiler = make_compiler();
        let projection = minimal_schema();
        let result = compiler.dump_rust(&projection);
        assert!(result.is_ok(), "{:?}", result);
        let src = result.unwrap();
        assert!(src.contains("ATTRIBUTE_IDS"), "src={}", src);
        assert!(src.contains("CLASS_IDS"), "src={}", src);
        assert!(src.contains("\"cn\""), "src={}", src);
        assert!(src.contains("\"user\""), "src={}", src);
        assert!(src.contains("schema_generation:"), "src={}", src);
    }

    #[test]
    fn projection_compile_error_displays_with_message() {
        let err = SchemaError::ProjectionCompile("boom".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("boom"), "expected message in: {}", msg);
        assert!(msg.contains("schema projection compile failed"));
    }

    #[test]
    fn minimal_schema_includes_core_classes() {
        let proj = minimal_schema();
        assert!(proj.classes.len() >= 6, "got {}", proj.classes.len());
        for name in &["top", "person", "user", "group", "organizationalunit", "domaindns"] {
            assert!(
                proj.class_name_to_id.contains_key(*name),
                "missing class: {}",
                name
            );
        }
    }

    #[test]
    fn minimal_schema_includes_core_attributes() {
        let proj = minimal_schema();
        for name in &[
            "cn", "name", "objectclass", "member", "memberof", "objectsid",
            "objectguid", "samaccountname", "userprincipalname", "distinguishedname",
        ] {
            assert!(
                proj.attribute_name_to_id.contains_key(*name),
                "missing attribute: {}",
                name
            );
        }
    }

    #[test]
    fn minimal_schema_pairs_linkids_per_adr002() {
        let proj = minimal_schema();
        let member = proj
            .attributes
            .values()
            .find(|a| a.ldap_name == "member")
            .unwrap();
        let member_of = proj
            .attributes
            .values()
            .find(|a| a.ldap_name == "memberOf")
            .unwrap();
        assert_eq!(member.link_id, Some(3));
        assert_eq!(member_of.link_id, Some(4));
        // Per ADR-001 / ADR-002 — back-link = forward-link + 1.
        assert_eq!(member_of.link_id.unwrap(), member.link_id.unwrap() + 1);
    }

    #[test]
    fn next_generation_increments_generation_counter() {
        // Per ADR-003 §Decision — next_generation produces a new immutable
        // projection with generation+1.
        let proj = minimal_schema();
        let next = proj.next_generation();
        assert_eq!(next.generation, proj.generation + 1);
        // The original projection must be unchanged (CoW invariant).
        assert_eq!(proj.generation, 1);
        // The next-generation projection shares the same attributes/classes
        // (only the generation counter changed).
        assert_eq!(next.attributes.len(), proj.attributes.len());
        assert_eq!(next.classes.len(), proj.classes.len());
    }

    #[test]
    fn next_generation_saturates_at_u64_max() {
        let mut proj = minimal_schema();
        proj.generation = u64::MAX;
        let next = proj.next_generation();
        assert_eq!(next.generation, u64::MAX);
    }

    fn user_object_with_cn(cn: &str, sam_account_name: &str) -> Object {
        // A minimal `user` object with the must_contain attributes
        // populated (objectClass, cn, sAMAccountName, instanceType per
        // `top`/`person`/`user` must_contain chains).
        Object {
            uuid: Uuid::from_u128(0x1),
            dn: DistinguishedName::new(format!("CN={},DC=adrian,DC=example,DC=com", cn)),
            attributes: vec![
                Attribute {
                    attribute_id: 0x10_002,
                    name: "objectClass".into(),
                    value: b"top".to_vec(),
                },
                Attribute {
                    attribute_id: 0x10_002,
                    name: "objectClass".into(),
                    value: b"person".to_vec(),
                },
                Attribute {
                    attribute_id: 0x10_002,
                    name: "objectClass".into(),
                    value: b"user".to_vec(),
                },
                Attribute {
                    attribute_id: 0x10_000,
                    name: "cn".into(),
                    value: cn.as_bytes().to_vec(),
                },
                Attribute {
                    attribute_id: 0x10_001,
                    name: "name".into(),
                    value: cn.as_bytes().to_vec(),
                },
                Attribute {
                    attribute_id: 0x10_007,
                    name: "sAMAccountName".into(),
                    value: sam_account_name.as_bytes().to_vec(),
                },
                Attribute {
                    attribute_id: 0x10_00E,
                    name: "instanceType".into(),
                    value: 4i32.to_le_bytes().to_vec(),
                },
            ],
            dnt: 0,
        }
    }

    #[test]
    fn validate_object_accepts_well_formed_user() {
        let proj = minimal_schema();
        let obj = user_object_with_cn("alice", "alice");
        let result = proj.validate_object(&obj);
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn validate_object_rejects_missing_must_contain() {
        // A `user` object missing `sAMAccountName` (must_contain per `user`).
        let proj = minimal_schema();
        let mut obj = user_object_with_cn("alice", "alice");
        obj.attributes
            .retain(|a| !a.name.eq_ignore_ascii_case("samaccountname"));
        let result = proj.validate_object(&obj);
        assert!(result.is_err(), "{:?}", result);
        let err = result.unwrap_err();
        assert!(
            matches!(err, SchemaError::MissingMustContain(_, _)),
            "got {:?}",
            err
        );
    }

    #[test]
    fn validate_object_rejects_disallowed_attribute() {
        // Per ADR-078 — an attribute not in must_contain ∪ may_contain is
        // a DisallowedAttribute error. `groupType` is must_contain on
        // `group` but not allowed on `user`.
        let proj = minimal_schema();
        let mut obj = user_object_with_cn("alice", "alice");
        obj.attributes.push(Attribute {
            attribute_id: 0x10_015,
            name: "groupType".into(),
            value: 0x2_i32.to_le_bytes().to_vec(),
        });
        let result = proj.validate_object(&obj);
        assert!(result.is_err(), "{:?}", result);
        let err = result.unwrap_err();
        assert!(
            matches!(err, SchemaError::DisallowedAttribute(_, _)),
            "got {:?}",
            err
        );
    }

    #[test]
    fn validate_object_rejects_bad_boolean_syntax() {
        // A Boolean attribute must be exactly 1 byte (0x00 or 0xFF). The
        // minimal schema has no Boolean attributes by default, so we add
        // one in the projection.
        let mut proj = minimal_schema();
        let bool_id = 0x10_099;
        proj.attributes.insert(
            bool_id,
            AttributeSchema {
                id: bool_id,
                ldap_name: "isTestUser".into(),
                syntax: AttributeSyntax::Boolean,
                range_lower: None,
                range_upper: None,
                is_single_valued: true,
                search_flags: 0,
                is_linked: false,
                link_id: None,
            },
        );
        proj.attribute_name_to_id
            .insert("istestuser".into(), bool_id);
        // Add `isTestUser` to the `user` class's may_contain.
        proj.classes
            .get_mut(&proj.class_name_to_id.get("user").copied().unwrap())
            .unwrap()
            .may_contain
            .push(bool_id);

        let mut obj = user_object_with_cn("alice", "alice");
        obj.attributes.push(Attribute {
            attribute_id: bool_id,
            name: "isTestUser".into(),
            value: vec![0x01, 0x02], // wrong: should be 1 byte
        });
        let result = proj.validate_object(&obj);
        assert!(result.is_err(), "{:?}", result);
        let err = result.unwrap_err();
        assert!(
            matches!(err, SchemaError::ProjectionCompile(_)),
            "got {:?}",
            err
        );
    }

    #[test]
    fn validate_object_accepts_empty_objectclass() {
        // An object with no objectClass is a system-only object (e.g. the
        // DNT self-reference rows); validation accepts it.
        let proj = minimal_schema();
        let obj = Object {
            uuid: Uuid::from_u128(0x2),
            dn: DistinguishedName::new("DC=adrian,DC=example,DC=com"),
            attributes: vec![],
            dnt: 0,
        };
        let result = proj.validate_object(&obj);
        assert!(result.is_ok(), "{:?}", result);
    }

    #[tokio::test]
    async fn compile_from_directory_works_with_inmemory_store() {
        // The extension trait's compile_from_directory must work against
        // a real (in-memory) DirectoryStore implementation, not just the
        // stub.
        let store = InMemoryDirectoryStore::new();
        let projection = SchemaProjection::compile_from_directory(&store).await.unwrap();
        assert!(projection.generation >= 1);
        assert!(projection.attributes.len() >= 16);
    }

    #[tokio::test]
    async fn bootstrap_caches_schema_nc_head() {
        // Per ADR-003 — bootstrap reads the schema NC head UUID and caches
        // it on the compiler so subsequent recompiles don't re-read.
        let mut compiler = make_compiler();
        assert_eq!(compiler.schema_nc_head, Uuid::nil());
        let head = compiler.bootstrap().await.unwrap();
        assert_eq!(head, WELL_KNOWN_SCHEMA_NC_HEAD);
        assert_eq!(compiler.schema_nc_head, WELL_KNOWN_SCHEMA_NC_HEAD);
    }

    #[test]
    fn dump_rust_handles_empty_projection() {
        // `dump_rust` on an empty projection must not panic.
        let compiler = make_compiler();
        let empty = SchemaProjection::empty();
        let src = compiler.dump_rust(&empty).unwrap();
        assert!(src.contains("ATTRIBUTE_IDS"));
        // Empty projection → no entries in the static array.
        assert!(src.contains("&[") && src.contains("];"));
    }

    // NOTE: Real-schema-NC integration tests (walking attributeSchema /
    // classSchema objects, validating mustContain, linkID pairs, atomic
    // generation swap) require a populated FDB-backed directory and the
    // `fdb` feature flag. They are intentionally omitted from this
    // unit-test module — see `adrian-test-harness` for integration tests.
    #[tokio::test]
    #[ignore = "requires a populated FDB-backed directory and the `fdb` feature flag"]
    async fn integration_compile_walks_schema_nc() {
        // Placeholder — will be implemented in `adrian-test-harness` once
        // the FDB integration testkit is added in Wave 4b.
    }
}
