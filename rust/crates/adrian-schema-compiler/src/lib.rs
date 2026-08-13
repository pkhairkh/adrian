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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adrian_storage_core_sub::StoreHandle;
    use adrian_schema_traits::SchemaError;
    use adrian_storage_core::{
        DirectoryStore, DistinguishedName, Object, ReadTxn, StorageError, WriteTxn,
    };
    use async_trait::async_trait;
    use std::sync::Arc;
    use uuid::Uuid;

    /// A no-op `DirectoryStore` stub used by the schema-compiler unit tests.
    /// The compiler's methods are stubs that never actually read from the
    /// store — the stub exists only so `SchemaCompiler::new` can be called
    /// with a real `StoreHandle`.
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
        // Construction must succeed — even with a stub store, the compiler
        // stores the handle for later use by `compile` / `recompile_and_swap`.
        let _compiler = make_compiler();
    }

    #[test]
    fn store_handle_is_clone_via_arc() {
        // `StoreHandle = Arc<dyn DirectoryStore>` — clones share the same
        // underlying store. Verify the aliasing semantics hold so the
        // compiler can hand the handle off to sub-components (e.g. a future
        // schema-cache snapshot).
        let store: StoreHandle = Arc::new(StubStore);
        let store2 = store.clone();
        // Two clones of an Arc point at the same allocation — a round-trip
        // through `Arc::as_ptr` would confirm pointer equality, but we settle
        // for verifying both are usable.
        let compiler1 = SchemaCompiler::new(store);
        let compiler2 = SchemaCompiler::new(store2);
        // Both compilers should hold the same trait-object pointer.
        let ptr1 = Arc::as_ptr(&compiler1.store) as *const ();
        let ptr2 = Arc::as_ptr(&compiler2.store) as *const ();
        assert_eq!(ptr1, ptr2, "Arc clones must point at the same store");
    }

    #[tokio::test]
    async fn compile_returns_projection_compile_error() {
        // Per ADR-078 / Decision 4 — the schema compiler is a stub in this
        // wave; calling `compile` before implementation must surface a loud
        // `SchemaError::ProjectionCompile` (per ADR-078 §Decision — loud
        // failure at boot, never silent).
        let compiler = make_compiler();
        let result = compiler.compile().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(SchemaError::ProjectionCompile(_))));
    }

    #[tokio::test]
    async fn recompile_and_swap_returns_projection_compile_error() {
        // Per ADR-003 — atomic pointer-swap of a new generation; the stub
        // must surface `ProjectionCompile` until the real implementation
        // lands (Wave 4b).
        let compiler = make_compiler();
        let result = compiler.recompile_and_swap().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(SchemaError::ProjectionCompile(_))));
    }

    #[test]
    fn dump_rust_returns_projection_compile_error() {
        // `dump_rust` is the developer-only `adrian-schema dump-rust` command
        // (per Decision 4 §Decision Layer 1) — NOT on the production code
        // path. The stub returns `ProjectionCompile` until implemented.
        let compiler = make_compiler();
        let projection = SchemaProjection {
            attributes: std::collections::HashMap::new(),
            classes: std::collections::HashMap::new(),
            attribute_name_to_id: std::collections::HashMap::new(),
            class_name_to_id: std::collections::HashMap::new(),
            generation: 1,
        };
        let result = compiler.dump_rust(&projection);
        assert!(result.is_err());
        assert!(matches!(result, Err(SchemaError::ProjectionCompile(_))));
    }

    #[tokio::test]
    async fn read_schema_nc_head_returns_projection_compile_error() {
        // Per ADR-003 — the schema NC head UUID is read from the directory
        // config subspace at boot. The stub surfaces `ProjectionCompile`
        // until implemented.
        let store: StoreHandle = Arc::new(StubStore);
        let result = read_schema_nc_head(&store).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(SchemaError::ProjectionCompile(_))));
    }

    #[test]
    fn projection_compile_error_displays_with_message() {
        // Per ADR-078 §Decision — validation failures must be surfaced at
        // projection compile time, not silently. Verify the error's Display
        // implementation propagates the underlying message.
        let err = SchemaError::ProjectionCompile("boom".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("boom"), "expected message in: {}", msg);
        assert!(msg.contains("schema projection compile failed"));
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
