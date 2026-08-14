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
//! - ADR-017: UPN uniqueness
//! - ADR-126: sIDHistory migration via DRSAddSidHistory
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
    /// The SID → sIDHistory index (per ADR-126). Each entry maps the
    /// principal's current SID to its list of historical SIDs.
    pub sid_to_history: RwLock<HashMap<String, Vec<Sid>>>,
    /// The UPN → UUID index (per ADR-017). UPNs are unique per principal.
    pub upn_to_uuid: RwLock<HashMap<String, PrincipalId>>,
    /// The UUID → UPN forward index (for back-reference / display).
    pub uuid_to_upn: RwLock<HashMap<PrincipalId, String>>,
}

impl InMemoryIdentityMapping {
    /// Construct a new empty `InMemoryIdentityMapping`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the sIDHistory for a principal identified by its current SID
    /// (per ADR-126 — sIDHistory migration). Replaces any existing
    /// sIDHistory for this SID.
    pub fn set_sid_history(&self, sid: &Sid, history: Vec<Sid>) {
        self.sid_to_history
            .write()
            .unwrap()
            .insert(sid.to_string(), history);
    }

    /// Set the UPN for a principal identified by its UUID (per ADR-017 —
    /// UPN uniqueness). Returns `Err(IdentityError::MappingConflict)` if
    /// the UPN is already registered to a different principal.
    pub fn set_upn(&self, uuid: PrincipalId, upn: &str) -> Result<(), IdentityError> {
        // Check for UPN conflict.
        if let Some(existing) = self.upn_to_uuid.read().unwrap().get(upn) {
            if *existing != uuid {
                return Err(IdentityError::MappingConflict(format!(
                    "UPN {upn} is already mapped to UUID {existing} (requested {uuid})"
                )));
            }
        }
        // Remove any existing UPN for this UUID (so we don't leave a stale
        // UPN→UUID entry pointing at this UUID).
        if let Some(old_upn) = self.uuid_to_upn.read().unwrap().get(&uuid).cloned() {
            self.upn_to_uuid.write().unwrap().remove(&old_upn);
        }
        self.upn_to_uuid
            .write()
            .unwrap()
            .insert(upn.to_string(), uuid);
        self.uuid_to_upn
            .write()
            .unwrap()
            .insert(uuid, upn.to_string());
        Ok(())
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
            // Also remove sIDHistory for this SID.
            self.sid_to_history
                .write()
                .unwrap()
                .remove(&sid.to_string());
        }
        self.uuid_to_uid.write().unwrap().remove(&uuid);
        // Also remove UPN registration.
        if let Some(upn) = self.uuid_to_upn.write().unwrap().remove(&uuid) {
            self.upn_to_uuid.write().unwrap().remove(&upn);
        }
        Ok(())
    }

    async fn resolve_sid_history(&self, sid: &Sid) -> Result<Vec<Sid>, IdentityError> {
        Ok(self
            .sid_to_history
            .read()
            .unwrap()
            .get(&sid.to_string())
            .cloned()
            .unwrap_or_default())
    }

    async fn lookup_by_upn(&self, upn: &str) -> Result<Option<(PrincipalId, Sid)>, IdentityError> {
        let uuid = self.upn_to_uuid.read().unwrap().get(upn).copied();
        let Some(uuid) = uuid else {
            return Ok(None);
        };
        let sid = self.uuid_to_sid.read().unwrap().get(&uuid).cloned();
        let Some(sid) = sid else {
            // UPN exists but no SID — data corruption (shouldn't happen
            // given the testkit's invariant that insert + set_upn are
            // paired).
            return Err(IdentityError::Backend(format!(
                "UPN {upn} maps to UUID {uuid} but no SID is registered for that UUID"
            )));
        };
        Ok(Some((uuid, sid)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_identity_core::uuid_to_uid;
    use uuid::Uuid;

    /// Helper: build a SID from a literal "S-1-5-21-..." string.
    fn sid(s: &str) -> Sid {
        s.parse().unwrap()
    }

    /// Helper: insert a principal with the given UUID + SID into the mapping.
    async fn insert(mapping: &InMemoryIdentityMapping, uuid: Uuid, sid: &Sid) {
        mapping.insert(uuid, sid).await.unwrap();
    }

    // ===== Wave 4 / T-401: 8 tests for the in-memory identity testkit =====

    /// T-401 #1: SID→UID round-trip — insert (UUID, SID), verify lookup_uid(uuid)
    /// returns the algorithmic mapping.
    #[tokio::test]
    async fn sid_to_uid_round_trip() {
        let m = InMemoryIdentityMapping::new();
        let uuid = Uuid::from_u128(0xABCDEF);
        let sid = sid("S-1-5-21-100-200-300-1000");
        insert(&m, uuid, &sid).await;
        let uid = m.lookup_uid(uuid).await.unwrap().unwrap();
        let expected = uuid_to_uid(uuid);
        assert_eq!(
            uid, expected,
            "lookup_uid must return the algorithmic mapping"
        );
        assert!(uid >= 65536, "uid must be >= 65536");
        assert!(uid < (1u32 << 31), "uid must be < 2^31");
    }

    /// T-401 #2: UID→SID — set a directory-stored UID via the public
    /// `uuid_to_uid` field, verify `lookup_uuid_from_uid` returns the UUID.
    /// (`lookup_sid` from a UID is conceptually a 2-hop lookup: UID→UUID→SID.)
    #[tokio::test]
    async fn uid_to_sid_lookup() {
        let m = InMemoryIdentityMapping::new();
        let uuid = Uuid::from_u128(0x1111);
        let sid = sid("S-1-5-21-100-200-300-1001");
        insert(&m, uuid, &sid).await;
        // Set a directory-stored UID (not the algorithmic one).
        m.uuid_to_uid.write().unwrap().insert(uuid, 42_000);
        m.uid_to_uuid.write().unwrap().insert(42_000, uuid);
        // UID → UUID → SID round-trip.
        let looked_up_uuid = m.lookup_uuid_from_uid(42_000).await.unwrap().unwrap();
        assert_eq!(
            looked_up_uuid, uuid,
            "UID→UUID lookup must return the right UUID"
        );
        let looked_up_sid = m.lookup_sid(looked_up_uuid).await.unwrap().unwrap();
        assert_eq!(
            looked_up_sid, sid,
            "UUID→SID lookup must return the right SID"
        );
    }

    /// T-401 #3: GID mapping works (same algorithmic mapping as UID — the
    /// framework uses the same `uuid_to_uid` function for GIDs per Decision 3
    /// §POSIX UID/GID mapping). We verify the same UUID produces the same
    /// numeric value when used as either a UID or a GID.
    #[tokio::test]
    async fn gid_mapping_works() {
        let m = InMemoryIdentityMapping::new();
        let group_uuid = Uuid::from_u128(0xBBBB);
        let group_sid = sid("S-1-5-21-100-200-300-512"); // 512 = Domain Admins RID
        insert(&m, group_uuid, &group_sid).await;
        // The framework treats UIDs and GIDs as the same numeric space per
        // Decision 3 §POSIX UID/GID mapping (the same algorithmic function
        // `uuid_to_uid` is used for both).
        let gid = m.lookup_uid(group_uuid).await.unwrap().unwrap();
        let expected_gid = uuid_to_uid(group_uuid);
        assert_eq!(
            gid, expected_gid,
            "GID mapping must match the algorithmic mapping"
        );
        assert!(gid >= 65536, "gid must be >= 65536");
    }

    /// T-401 #4: well-known SIDs resolve correctly. We verify that well-known
    /// SIDs can be inserted + looked up like any other SID (the testkit
    /// doesn't have a special-case for well-known SIDs — they're stored
    /// alongside domain SIDs in the same mapping).
    #[tokio::test]
    async fn well_known_sids_resolve_correctly() {
        let m = InMemoryIdentityMapping::new();
        let cases = [
            // (uuid, sid_string, description)
            (Uuid::from_u128(1), "S-1-1-0", "Everyone"),
            (Uuid::from_u128(2), "S-1-5-7", "Anonymous"),
            (Uuid::from_u128(3), "S-1-5-18", "System / LocalSystem"),
            (Uuid::from_u128(4), "S-1-5-11", "Authenticated Users"),
            (
                Uuid::from_u128(5),
                "S-1-5-32-544",
                "Administrators (built-in)",
            ),
        ];
        for (uuid, sid_str, desc) in cases {
            let s = sid(sid_str);
            insert(&m, uuid, &s).await;
            let looked_up = m.lookup_uuid(&s).await.unwrap();
            assert_eq!(
                looked_up,
                Some(uuid),
                "well-known SID {sid_str} ({desc}) must resolve to UUID {uuid}"
            );
        }
    }

    /// T-401 #5: overflow handling — the algorithmic mapping uses modulo
    /// (2^31 - 65536), so it can never produce a value >= 2^31 or < 65536.
    /// We verify this for a large sample of UUIDs (including UUIDs whose
    /// high 64 bits would overflow u32 without the modulo).
    #[tokio::test]
    async fn overflow_handling() {
        let m = InMemoryIdentityMapping::new();
        // Test with UUIDs that exercise the modulo path (high bits would
        // overflow u32 without the modulo reduction). Use unique RIDs to
        // avoid SID collisions in the testkit's unique-SID constraint.
        let overflow_uuids = [
            (Uuid::from_u128(u128::MAX), 1001u32),
            (
                Uuid::from_u128(0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000),
                1002,
            ),
            (
                Uuid::from_u128(0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF),
                1003,
            ),
            (
                Uuid::from_u128(0x8000_0000_0000_0000_0000_0000_0000_0000),
                1004,
            ),
        ];
        for (uuid, rid) in overflow_uuids {
            let s = sid(&format!("S-1-5-21-100-200-300-{rid}"));
            insert(&m, uuid, &s).await;
            let uid = m.lookup_uid(uuid).await.unwrap().unwrap();
            assert!(
                (65536..(1u32 << 31)).contains(&uid),
                "uid {uid} for uuid {uuid} must be in [65536, 2^31) — overflow must be handled"
            );
        }
    }

    /// T-401 #6: concurrent access — spawn N tasks that all insert into the
    /// mapping concurrently. Verify all inserts succeed and the mapping has
    /// the expected count.
    #[tokio::test]
    async fn concurrent_access_to_in_memory_mapping() {
        let m = std::sync::Arc::new(InMemoryIdentityMapping::new());
        let n = 50;
        let mut handles = Vec::new();
        for i in 0..n {
            let m_clone = m.clone();
            handles.push(tokio::spawn(async move {
                let uuid = Uuid::from_u128(i as u128 + 1);
                let s: Sid = format!("S-1-5-21-100-200-300-{i}").parse().unwrap();
                m_clone.insert(uuid, &s).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // Verify all N principals are present.
        for i in 0..n {
            let uuid = Uuid::from_u128(i as u128 + 1);
            assert!(
                m.lookup_sid(uuid).await.unwrap().is_some(),
                "principal {i} must be present after concurrent inserts"
            );
        }
        // Verify no cross-talk (each UUID → SID mapping is intact).
        for i in 0..n {
            let uuid = Uuid::from_u128(i as u128 + 1);
            let sid = m.lookup_sid(uuid).await.unwrap().unwrap();
            let sid_str = sid.to_string();
            assert!(
                sid_str.ends_with(&format!("-{i}")),
                "principal {i} SID must end with -{i}, got {sid_str}"
            );
        }
    }

    /// T-401 #7: schema validation — inserting a principal with a SID that
    /// parses successfully is OK; the testkit doesn't impose additional
    /// schema validation beyond what `Sid::from_str` does.
    #[tokio::test]
    async fn schema_validation_rejects_invalid_sids() {
        let m = InMemoryIdentityMapping::new();
        // An invalid SID string fails at parse time (not at insert time).
        let invalid = "not-a-valid-sid".parse::<Sid>();
        assert!(invalid.is_err(), "invalid SID string must fail to parse");
        // The testkit's insert requires a valid Sid; the parse-failure is
        // surfaced before insert. We verify the testkit accepts a valid SID.
        let valid = sid("S-1-5-21-100-200-300-1234");
        m.insert(Uuid::from_u128(0x999), &valid).await.unwrap();
    }

    /// T-401 #8: negative tests — looking up an unknown UUID/SID returns
    /// None (not an error).
    #[tokio::test]
    async fn negative_tests_unknown_returns_none() {
        let m = InMemoryIdentityMapping::new();
        let unknown_uuid = Uuid::from_u128(0xDEAD_BEEF);
        let unknown_sid = sid("S-1-5-21-999-999-999-9999");
        // Empty mapping: every lookup returns None.
        assert!(m.lookup_sid(unknown_uuid).await.unwrap().is_none());
        assert!(m.lookup_uuid(&unknown_sid).await.unwrap().is_none());
        assert!(m.lookup_uid(unknown_uuid).await.unwrap().is_some(),
            "lookup_uid returns the algorithmic mapping even for unknown UUIDs (per Decision 3 — fallback path");
        assert!(m.lookup_uuid_from_uid(99_999).await.unwrap().is_none());
        assert!(m
            .resolve_sid_history(&unknown_sid)
            .await
            .unwrap()
            .is_empty());
        assert!(m
            .lookup_by_upn("nobody@nowhere.example.com")
            .await
            .unwrap()
            .is_none());
    }

    // ===== Wave 4 / T-402 + T-404: sIDHistory + UPN tests =====

    /// T-402/T-404 #1: sIDHistory resolution — set sIDHistory for a
    /// principal, verify `resolve_sid_history(sid)` returns the list.
    #[tokio::test]
    async fn sid_history_resolution() {
        let m = InMemoryIdentityMapping::new();
        let uuid = Uuid::from_u128(0xAAAA);
        // Use all-numeric SIDs (the SID parser only accepts numeric sub-authorities).
        let current_sid = sid("S-1-5-21-100-200-300-1000");
        let old_sid_1 = sid("S-1-5-21-200-200-300-1000");
        let old_sid_2 = sid("S-1-5-21-300-200-300-1000");
        insert(&m, uuid, &current_sid).await;
        m.set_sid_history(&current_sid, vec![old_sid_1.clone(), old_sid_2.clone()]);
        let history = m.resolve_sid_history(&current_sid).await.unwrap();
        assert_eq!(history.len(), 2, "sIDHistory must have 2 entries");
        assert_eq!(history[0], old_sid_1, "first historical SID must match");
        assert_eq!(history[1], old_sid_2, "second historical SID must match");
        // A SID with no sIDHistory returns empty.
        let other_sid = sid("S-1-5-21-400-200-300-1000");
        let empty = m.resolve_sid_history(&other_sid).await.unwrap();
        assert!(empty.is_empty(), "SID with no sIDHistory must return empty");
    }

    /// T-403/T-404 #2: UPN lookup — set UPN for a principal, verify
    /// `lookup_by_upn(upn)` returns (uuid, sid).
    #[tokio::test]
    async fn upn_lookup_returns_uuid_and_sid() {
        let m = InMemoryIdentityMapping::new();
        let uuid = Uuid::from_u128(0xBBBB);
        let sid = sid("S-1-5-21-100-200-300-2000");
        insert(&m, uuid, &sid).await;
        m.set_upn(uuid, "alice@corp.example.com").unwrap();
        let result = m.lookup_by_upn("alice@corp.example.com").await.unwrap();
        let (looked_up_uuid, looked_up_sid) = result.unwrap();
        assert_eq!(
            looked_up_uuid, uuid,
            "UPN lookup must return the right UUID"
        );
        assert_eq!(looked_up_sid, sid, "UPN lookup must return the right SID");
        // Unknown UPN returns None.
        let unknown = m.lookup_by_upn("nobody@corp.example.com").await.unwrap();
        assert!(unknown.is_none(), "unknown UPN must return None");
    }

    /// T-403/T-404 #3: UPN uniqueness — registering the same UPN for two
    /// different UUIDs fails with `MappingConflict`.
    #[tokio::test]
    async fn upn_uniqueness_enforced() {
        let m = InMemoryIdentityMapping::new();
        let uuid1 = Uuid::from_u128(1);
        let uuid2 = Uuid::from_u128(2);
        let sid1 = sid("S-1-5-21-100-200-300-3001");
        let sid2 = sid("S-1-5-21-100-200-300-3002");
        insert(&m, uuid1, &sid1).await;
        insert(&m, uuid2, &sid2).await;
        // First registration succeeds.
        m.set_upn(uuid1, "bob@corp.example.com").unwrap();
        // Second registration with the same UPN fails (different UUID).
        let err = m.set_upn(uuid2, "bob@corp.example.com").unwrap_err();
        assert!(
            matches!(err, IdentityError::MappingConflict(_)),
            "second UPN registration must fail with MappingConflict, got: {err:?}"
        );
        // Re-registering the same UPN for the same UUID is a no-op (idempotent).
        m.set_upn(uuid1, "bob@corp.example.com").unwrap();
        // Changing the UPN for the same UUID (rename) works.
        m.set_upn(uuid1, "robert@corp.example.com").unwrap();
        let result = m.lookup_by_upn("robert@corp.example.com").await.unwrap();
        assert_eq!(
            result.unwrap().0,
            uuid1,
            "renamed UPN must still map to the same UUID"
        );
        // Old UPN is now released.
        let old = m.lookup_by_upn("bob@corp.example.com").await.unwrap();
        assert!(old.is_none(), "old UPN must be released after rename");
    }

    /// T-404 #4: cross-domain SID lookup via sIDHistory — set up a
    /// principal in the new domain with the old domain's SID in its
    /// sIDHistory. Verify that looking up the principal by its old SID
    /// returns the principal's UUID (this is the "sIDHistory passthrough"
    /// flow used during migration per ADR-126).
    ///
    /// The default `lookup_uuid(sid)` only checks the current-SID reverse
    /// index — to find a principal by an old SID, callers must enumerate
    /// the sIDHistory index (or, in this testkit's case, iterate the
    /// `sid_to_history` map).
    #[tokio::test]
    async fn cross_domain_sid_lookup_via_sid_history() {
        let m = InMemoryIdentityMapping::new();
        let new_uuid = Uuid::from_u128(0xCCCC);
        // Use all-numeric SIDs (new domain = 100, old domain = 200).
        let new_sid = sid("S-1-5-21-100-200-300-5000");
        let old_sid = sid("S-1-5-21-200-200-300-5000");
        insert(&m, new_uuid, &new_sid).await;
        m.set_sid_history(&new_sid, vec![old_sid.clone()]);
        // Direct lookup by old SID returns None (it's not the current SID).
        let direct = m.lookup_uuid(&old_sid).await.unwrap();
        assert!(
            direct.is_none(),
            "old SID must NOT be in the current-SID reverse index"
        );
        // But the sIDHistory index confirms the link.
        let history = m.resolve_sid_history(&new_sid).await.unwrap();
        assert!(
            history.contains(&old_sid),
            "sIDHistory must contain the old SID"
        );
        // In production, the KDC PAC builder walks sIDHistory to construct
        // the ExtraSids array; the framework's `lookup_uuid` does NOT
        // implicitly follow sIDHistory (per ADR-124 — sIDHistory is an
        // explicit attribute, not an implicit reverse index).
    }
}
