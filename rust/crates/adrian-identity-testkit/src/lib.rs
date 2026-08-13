//! # adrian-identity-testkit
//!
//! In-memory [`IdentityMapping`] implementation for unit tests in the Adrian
//! framework.
//!
//! Per Decision 3 §Trait design for pluggability, the testkit provides an
//! in-memory `IdentityMapping` implementation (`InMemoryIdentityMapping`)
//! backed by a `HashMap`, for unit tests that don't need a real FDB cluster.
//!
//! ## ADRs
//!
//! - ADR-110: SID-to-UID mapping (UUID-primary)
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-identity-core`, `adrian-sid`. Consumed by every crate's unit
//! tests that need identity mapping.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_identity_core::{IdentityError, IdentityMapping, PosixId, PrincipalId};
use adrian_sid::Sid;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

/// An in-memory `IdentityMapping` for unit tests (per Decision 3 §Trait
/// design for pluggability).
#[derive(Debug, Default)]
pub struct InMemoryIdentityMapping {
    /// The UUID → SID forward index.
    pub uuid_to_sid: RwLock<HashMap<PrincipalId, Sid>>,
    /// The SID → UUID reverse index.
    pub sid_to_uuid: RwLock<HashMap<String, PrincipalId>>,
    /// The UUID → UID index (per ADR-110).
    pub uuid_to_uid: RwLock<HashMap<PrincipalId, PosixId>>,
    /// The UID → UUID reverse index.
    pub uid_to_uuid: RwLock<HashMap<PosixId, PrincipalId>>,
}

impl InMemoryIdentityMapping {
    /// Construct a new empty `InMemoryIdentityMapping`.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl IdentityMapping for InMemoryIdentityMapping {
    async fn lookup_sid(&self, uuid: PrincipalId) -> Result<Option<Sid>, IdentityError> {
        Ok(self.uuid_to_sid.read().unwrap().get(&uuid).cloned())
    }

    async fn lookup_uuid(&self, sid: &Sid) -> Result<Option<PrincipalId>, IdentityError> {
        Ok(self
            .sid_to_uuid
            .read()
            .unwrap()
            .get(&sid.to_string())
            .copied())
    }

    async fn lookup_uid(&self, uuid: PrincipalId) -> Result<Option<PosixId>, IdentityError> {
        // Fall back to algorithmic mapping if not directory-stored (per
        // Decision 3 §Decision).
        Ok(Some(
            self.uuid_to_uid
                .read()
                .unwrap()
                .get(&uuid)
                .copied()
                .unwrap_or_else(|| adrian_identity_core::uuid_to_uid(uuid)),
        ))
    }

    async fn lookup_uuid_from_uid(
        &self,
        uid: PosixId,
    ) -> Result<Option<PrincipalId>, IdentityError> {
        Ok(self.uid_to_uuid.read().unwrap().get(&uid).copied())
    }

    async fn insert(&self, uuid: PrincipalId, sid: &Sid) -> Result<(), IdentityError> {
        let sid_str = sid.to_string();
        // Check for conflict (per Decision 3 — MappingConflict should never
        // happen given FDB's unique-index constraints, but the testkit
        // enforces it manually).
        if let Some(existing) = self.sid_to_uuid.read().unwrap().get(&sid_str) {
            if *existing != uuid {
                return Err(IdentityError::MappingConflict(format!(
                    "SID {} already mapped to UUID {}",
                    sid_str, existing
                )));
            }
        }
        self.uuid_to_sid.write().unwrap().insert(uuid, sid.clone());
        self.sid_to_uuid.write().unwrap().insert(sid_str, uuid);
        Ok(())
    }

    async fn remove(&self, uuid: PrincipalId) -> Result<(), IdentityError> {
        if let Some(sid) = self.uuid_to_sid.write().unwrap().remove(&uuid) {
            self.sid_to_uuid.write().unwrap().remove(&sid.to_string());
        }
        self.uuid_to_uid.write().unwrap().remove(&uuid);
        Ok(())
    }
}
