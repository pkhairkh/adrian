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
//! `adrian-schema-traits`, `adrian-storage-core`, `adrian-identity-core`,
//! `rasn`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_schema_traits::{SchemaError, SchemaProjection};
use std::sync::Arc;

/// The schema compiler (per Decision 4 §Decision Layer 1 and ADR-078).
pub struct SchemaCompiler {
    /// The directory store (per ADR-073 — read Schema NC from FDB).
    pub store: adrian_storage_core_sub::StoreHandle,
}

/// A handle to the underlying directory store. This is a thin wrapper around
/// `Arc<dyn DirectoryStore>` so that the compiler can be constructed without
/// depending on `adrian-storage-fdb` (Layer 1 must not depend on Layer 2).
pub mod adrian_storage_core_sub {
    use adrian_storage_core::DirectoryStore;
    use std::sync::Arc;
    /// A handle to a `DirectoryStore`.
    pub type StoreHandle = Arc<dyn DirectoryStore>;
}

impl SchemaCompiler {
    /// Construct a new `SchemaCompiler` for the given directory store.
    pub fn new(store: adrian_storage_core_sub::StoreHandle) -> Self {
        Self { store }
    }

    /// Walk the Schema NC and build the typed Rust projection (per Decision
    /// 4 §Decision Layer 1).
    ///
    /// The projection is materialised as an in-memory `Arc<SchemaProjection>`
    /// — there is no codegen step in the build pipeline (per Decision 4
    /// §Decision Layer 1).
    pub async fn compile(&self) -> Result<Arc<SchemaProjection>, SchemaError> {
        // TODO: implement per ADR-078 / Decision 4:
        // 1. Read Schema NC head UUID from the directory config subspace.
        // 2. Walk every attributeSchema and classSchema object under the
        //    Schema NC (FDB range scan on subspace 0x01 keyed by parent DNT
        //    = Schema NC DNT).
        // 3. Build SchemaProjection (attributes, classes, name-to-id maps).
        // 4. Validate the projection — every mustContain attribute exists,
        //    every superior class exists, every linkID pair is well-formed
        //    (per ADR-001).
        // 5. Return Arc<SchemaProjection>.
        Err(SchemaError::ProjectionCompile(
            "SchemaCompiler::compile not yet implemented".into(),
        ))
    }

    /// Re-compile the projection after a `schemaModifyRequest` (per ADR-078
    /// §Decision Layer 1) and atomically swap it in (per ADR-003 §Decision).
    pub async fn recompile_and_swap(&self) -> Result<u64, SchemaError> {
        // TODO: implement per ADR-003 — read current generation counter at
        // FDB key (0x04, 0x00), build new generation, write new generation's
        // serialized graph, update generation counter — all in one FDB
        // transaction. Return the new generation number.
        Err(SchemaError::ProjectionCompile(
            "SchemaCompiler::recompile_and_swap not yet implemented".into(),
        ))
    }

    /// Dump the projection as Rust source for offline inspection (per
    /// Decision 4 §Decision Layer 1 — `adrian-schema dump-rust` developer
    /// command; NOT on the production code path).
    pub fn dump_rust(&self, _projection: &SchemaProjection) -> Result<String, SchemaError> {
        // TODO: implement per Decision 4 — emit Rust source for offline
        // inspection. Not on the production code path.
        Err(SchemaError::ProjectionCompile(
            "SchemaCompiler::dump_rust not yet implemented".into(),
        ))
    }
}

/// The schema NC head UUID (per ADR-003 — read from the directory config
/// subspace at boot).
pub async fn read_schema_nc_head(
    _store: &adrian_storage_core_sub::StoreHandle,
) -> Result<uuid::Uuid, SchemaError> {
    // TODO: implement per ADR-003.
    Err(SchemaError::ProjectionCompile(
        "read_schema_nc_head not yet implemented".into(),
    ))
}

// TODO: implement framework-native trait library projection (ServiceAccount, ManagedDevice, PolicySet, CertificateTemplate) per ADR-078 §Decision Layer 2.
// TODO: implement #[derive(Projectable)] glue generation per ADR-078 §Decision Layer 2.
// TODO: implement schema-as-code GitOps workflow per ADR-119 (pull LDIF from Git, apply via schemaModifyRequest).
