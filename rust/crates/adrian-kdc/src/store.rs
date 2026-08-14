#![forbid(unsafe_code)]
//! # adrian-kdc :: store
//!
//! Principal store abstraction for the KDC. Per Workshop Decision 5
//! (`workshop/decision-05-kdc-implementation.md` §5) the KDC is a stateless
//! pool that reads principals from Core Directory via a typed schema
//! projection, with a 60-second TTL cache and event-driven invalidation
//! (ADR-018).
//!
//! For Wave 3a we ship a minimal in-memory implementation
//! ([`InMemoryPrincipalStore`]) that lets the KDC round-trip AS-REQ/AS-REP
//! and TGS-REQ/TGS-REP without standing up the full directory integration.

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use uuid::Uuid;

use crate::crypto::Aes256Key;

/// A single principal's long-term KDC state.
#[derive(Clone, Debug)]
pub struct PrincipalRecord {
    /// The principal's UUID (objectGUID in AD-speak).
    pub uuid: Uuid,
    /// Realm (uppercase), e.g. `EXAMPLE.COM`.
    pub realm: String,
    /// Principal name components, e.g. `["alice"]` or `["krbtgt", "EXAMPLE.COM"]`.
    pub components: Vec<String>,
    /// AES-256 long-term key (RFC 3962 PBKDF2, 4096 iterations).
    pub key: Aes256Key,
    /// Key version number (kvno) — bumped on every password reset.
    pub kvno: u32,
    /// UAC `TRUSTED_TO_AUTH_FOR_DELEGATION` bit (0x100000) per ADR-087.
    /// Required for S4U2Self — a service with this flag can request a
    /// ticket to itself on behalf of any user.
    pub trusted_to_auth_for_delegation: bool,
    /// `msDS-AllowedToDelegateTo` SPN list per ADR-087 (classic constrained
    /// delegation). The service can S4U2Proxy to any SPN in this list.
    /// Empty = no constrained delegation allowed.
    pub allowed_to_delegate_to: Vec<String>,
}

impl PrincipalRecord {
    /// Construct a principal with the given key, kvno=1, and default
    /// delegation fields (`trusted_to_auth_for_delegation = false`,
    /// `allowed_to_delegate_to = empty`). Use the builder methods
    /// [`with_trusted_to_auth_for_delegation`] and
    /// [`with_allowed_to_delegate_to`] to set the delegation fields.
    pub fn new(
        uuid: Uuid,
        realm: impl Into<String>,
        components: Vec<String>,
        key: Aes256Key,
    ) -> Self {
        Self {
            uuid,
            realm: realm.into(),
            components,
            key,
            kvno: 1,
            trusted_to_auth_for_delegation: false,
            allowed_to_delegate_to: Vec::new(),
        }
    }

    /// Builder: set the `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (ADR-087).
    /// Required for S4U2Self.
    pub fn with_trusted_to_auth_for_delegation(mut self, trusted: bool) -> Self {
        self.trusted_to_auth_for_delegation = trusted;
        self
    }

    /// Builder: set the `msDS-AllowedToDelegateTo` SPN list (ADR-087 classic
    /// constrained delegation). The service can S4U2Proxy to any SPN in
    /// this list.
    pub fn with_allowed_to_delegate_to(mut self, targets: Vec<String>) -> Self {
        self.allowed_to_delegate_to = targets;
        self
    }

    /// The Kerberos salt for this principal per RFC 3962 §4:
    /// `REALM ++ concat(components)`.
    pub fn salt(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(self.realm.len() + 32);
        s.extend_from_slice(self.realm.as_bytes());
        for c in &self.components {
            s.extend_from_slice(c.as_bytes());
        }
        s
    }

    /// True iff this is the `krbtgt/<REALM>` principal.
    pub fn is_krbtgt(&self) -> bool {
        self.components.len() == 2
            && self.components[0].eq_ignore_ascii_case("krbtgt")
            && self.components[1].eq_ignore_ascii_case(&self.realm)
    }

    /// True iff this principal is allowed to S4U2Proxy to the given target
    /// SPN (case-insensitive match against `allowed_to_delegate_to`).
    /// Per ADR-087 §Decision (classic constrained delegation).
    pub fn can_delegate_to(&self, target_spn: &str) -> bool {
        self.allowed_to_delegate_to
            .iter()
            .any(|s| s.eq_ignore_ascii_case(target_spn))
    }
}

/// Async trait abstracting principal lookup.
#[async_trait]
pub trait PrincipalStore: Send + Sync {
    /// Look up a principal by `(realm, components)`. Realm match is
    /// case-insensitive per RFC 4120 §6.1.
    async fn lookup(
        &self,
        realm: &str,
        components: &[String],
    ) -> Result<Option<PrincipalRecord>, StoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store backend unavailable: {0}")]
    Backend(String),
}

/// Simple in-memory principal store, keyed by `(uppercase-realm, components-joined)`.
#[derive(Default)]
pub struct InMemoryPrincipalStore {
    inner: RwLock<HashMap<(String, String), PrincipalRecord>>,
}

impl InMemoryPrincipalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a principal record.
    pub fn insert(&self, rec: PrincipalRecord) {
        let key = normalize_key(&rec.realm, &rec.components);
        let mut w = self.inner.write().expect("principal store poisoned");
        w.insert(key, rec);
    }

    /// Number of principals currently registered.
    pub fn len(&self) -> usize {
        self.inner.read().expect("principal store poisoned").len()
    }

    /// True iff no principals are registered.
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .expect("principal store poisoned")
            .is_empty()
    }
}

fn normalize_key(realm: &str, components: &[String]) -> (String, String) {
    let r = realm.to_ascii_uppercase();
    let c = components
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("/");
    (r, c)
}

#[async_trait]
impl PrincipalStore for InMemoryPrincipalStore {
    async fn lookup(
        &self,
        realm: &str,
        components: &[String],
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        let key = normalize_key(realm, components);
        let r = self.inner.read().expect("principal store poisoned");
        Ok(r.get(&key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_key(seed: u8) -> Aes256Key {
        [seed; 32]
    }

    #[tokio::test]
    async fn lookup_returns_inserted_principal() {
        let store = InMemoryPrincipalStore::new();
        let rec = PrincipalRecord::new(
            Uuid::nil(),
            "EXAMPLE.COM",
            vec!["alice".into()],
            dummy_key(1),
        );
        store.insert(rec.clone());
        let got = store
            .lookup("example.com", &["alice".to_string()])
            .await
            .unwrap()
            .expect("alice must be present");
        assert_eq!(got.uuid, rec.uuid);
    }

    #[tokio::test]
    async fn lookup_is_case_insensitive_on_realm() {
        let store = InMemoryPrincipalStore::new();
        store.insert(PrincipalRecord::new(
            Uuid::nil(),
            "EXAMPLE.COM",
            vec!["bob".into()],
            dummy_key(2),
        ));
        assert!(store
            .lookup("Example.Com", &["bob".to_string()])
            .await
            .unwrap()
            .is_some());
        assert!(store
            .lookup("example.com", &["BOB".to_string()])
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn lookup_missing_principal_returns_none() {
        let store = InMemoryPrincipalStore::new();
        assert!(store
            .lookup("EXAMPLE.COM", &["nobody".to_string()])
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn salt_is_realm_plus_concatenated_components() {
        let rec = PrincipalRecord::new(
            Uuid::nil(),
            "EXAMPLE.COM",
            vec!["host".into(), "web.example.com".into()],
            dummy_key(3),
        );
        assert_eq!(rec.salt(), b"EXAMPLE.COMhostweb.example.com");
    }

    #[test]
    fn is_krbtgt_detects_cross_realm_principal() {
        let krbtgt = PrincipalRecord::new(
            Uuid::nil(),
            "EXAMPLE.COM",
            vec!["krbtgt".into(), "EXAMPLE.COM".into()],
            dummy_key(4),
        );
        assert!(krbtgt.is_krbtgt());
        let not_krbtgt = PrincipalRecord::new(
            Uuid::nil(),
            "EXAMPLE.COM",
            vec!["alice".into()],
            dummy_key(5),
        );
        assert!(!not_krbtgt.is_krbtgt());
    }

    #[tokio::test]
    async fn insert_replaces_existing_principal() {
        let store = InMemoryPrincipalStore::new();
        let uuid = Uuid::nil();
        let mut rec = PrincipalRecord::new(uuid, "EXAMPLE.COM", vec!["alice".into()], dummy_key(1));
        store.insert(rec.clone());
        rec.key = dummy_key(2);
        rec.kvno = 2;
        store.insert(rec);
        let got = store
            .lookup("EXAMPLE.COM", &["alice".to_string()])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.kvno, 2);
        assert_eq!(got.key, dummy_key(2));
    }
}
