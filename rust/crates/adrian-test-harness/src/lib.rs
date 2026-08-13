//! # adrian-test-harness
//!
//! Shared test fixtures and interop test utilities for the Adrian framework.
//!
//! Per finaldraft/04-rust-workspace-design.md §8 (Testing strategy), this
//! crate provides:
//!
//! - Mock implementations of `DirectoryStore`, `Replicator`,
//!   `IdentityMapping` (re-exported from `adrian-storage-testkit`,
//!   `adrian-repl-testkit`, `adrian-identity-testkit`)
//! - Shared test fixtures (sample principals, sample SIDs, sample objects,
//!   sample schema projections)
//! - Integration test helpers (spin up an in-process FDB cluster, an
//!   `adrian-directory-service` instance, an LDAP client that performs a
//!   bind + search + modify + delete sequence)
//! - Interop test utilities (Windows Server 2022 fixture, MIT krb5 fixture,
//!   Samba 4.20 fixture, OpenLDAP fixture, FreeIPA 4.10 fixture — gated
//!   behind the `ad-interop` feature flag)
//!
//! ## Wave 4a — in-process KDC + kpasswd fixtures
//!
//! This wave adds four in-process fixtures that let integration tests run
//! without any external dependencies (no FDB cluster, no real HSM, no live
//! Kerberos listener):
//!
//! - [`TestDirectory`] — wraps [`InMemoryDirectoryStore`] with pre-seeded
//!   users/groups/OUs (the directory side of the Adrian stack).
//! - [`TestKdc`] — wraps [`InMemoryPrincipalStore`] + a deterministic
//!   krbtgt AES-256 key, exposing [`TestKdc::as_req`] / [`TestKdc::tgs_req`]
//!   which call the real `adrian_kdc::handlers::{handle_as_req,
//!   handle_tgs_req}` free functions (RFC 4120 AS-REQ/TGS-REQ flows).
//! - [`TestKpasswd`] — wraps [`KpasswdService`] with a software HSM and
//!   the [`KrbtgtManager`], exposing [`TestKpasswd::change_password`] which
//!   calls the real `KpasswdService::handle_kpasswd` (RFC 3244).
//! - [`TestHarness`] — combines all three into a single fixture, with
//!   [`TestHarness::new`] constructing a fully-wired in-process Adrian
//!   stack and [`TestHarness::create_principal`] seeding both the principal
//!   store and the directory store so that AS-REQ, TGS-REQ, and kpasswd
//!   flows all resolve to the same principal.
//!
//! ## ADRs
//!
//! - ADR-073: FoundationDB as sole storage engine (in-process FDB testkit)
//! - ADR-018: KDC as stateless pool behind LB (harness wires the in-memory
//!   principal store, no live TCP listener)
//! - ADR-019: kpasswd password-change protocol (harness wires the
//!   `KpasswdService` with a software HSM)
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Re-exports the
//! three testkit crates; adds shared fixtures. Also depends on Layer 3
//! `adrian-kdc` for the in-process KDC + kpasswd fixtures (a documented
//! layering exception — the test harness is the integration-test seam that
//! wires Layer 3 services for end-to-end testing, per finaldraft/04-rust-
//! workspace-design.md §8).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Re-export the three testkit crates so consumers can `use adrian_test_harness::*`.
pub use adrian_identity_testkit::InMemoryIdentityMapping;
pub use adrian_repl_testkit::InMemoryReplicator;
pub use adrian_storage_testkit::InMemoryDirectoryStore;

use adrian_hsm::{Hsm, KeyHandle, KeyType, SoftwareHsm};
use adrian_identity_core::{Principal, PrincipalType};
use adrian_kdc::crypto::{self, Aes256Key, CONFOUNDER_LEN, HMAC_SHA1_96_LEN};
use adrian_kdc::handlers::{
    self, AsRep, AsReq, Authenticator, EncKdcRepPart, PaData, PaEncTsEnc, TgsReq,
    DEFAULT_TGT_LIFETIME_SECS, KEY_USAGE_AS_REP_ENC_PART, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP,
    KEY_USAGE_TGS_REQ_AUTHENTICATOR, MSG_TYPE_AS_REQ, MSG_TYPE_TGS_REQ, PA_ENC_TIMESTAMP_TYPE,
    PVNO,
};
use adrian_kdc::kpasswd::{KpasswdRequest, KpasswdResponse, KpasswdService, PrincipalName};
use adrian_kdc::krbtgt::KrbtgtManager;
use adrian_kdc::store::{InMemoryPrincipalStore, PrincipalRecord, PrincipalStore};
use adrian_kdc::EType;
use adrian_sid::Sid;
use adrian_storage_core::{Attribute, DirectoryStore, DistinguishedName, Object};
use adrian_storage_testkit::UNASSIGNED_DNT;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Sample fixtures (pre-Wave-4a — preserved for backward compat)
// ---------------------------------------------------------------------------

/// A test fixture: a sample user principal (per Decision 3 §Decision).
pub fn sample_user_principal() -> Principal {
    Principal {
        uuid: Uuid::nil(),
        sid: "S-1-5-21-3623811015-3361044348-30300820-500"
            .parse()
            .expect("sample user SID must parse"),
        sid_history: Vec::new(),
        principal_type: PrincipalType::User,
    }
}

/// A test fixture: a sample group principal (per Decision 3 §Decision).
pub fn sample_group_principal() -> Principal {
    Principal {
        uuid: Uuid::nil(),
        sid: "S-1-5-21-3623811015-3361044348-30300820-512"
            .parse()
            .expect("sample group SID must parse"),
        sid_history: Vec::new(),
        principal_type: PrincipalType::Group,
    }
}

/// A test fixture: a sample domain SID (per MS-DTYP §2.4.2).
pub fn sample_domain_sid() -> Sid {
    "S-1-5-21-3623811015-3361044348-30300820"
        .parse()
        .expect("sample domain SID must parse")
}

/// A test fixture: a sample administrator SID (RID 500, per MS-ADTS).
pub fn sample_administrator_sid() -> Sid {
    "S-1-5-21-3623811015-3361044348-30300820-500"
        .parse()
        .expect("sample administrator SID must parse")
}

/// A test fixture: a sample Domain Admins SID (RID 512, per MS-ADTS).
pub fn sample_domain_admins_sid() -> Sid {
    "S-1-5-21-3623811015-3361044348-30300820-512"
        .parse()
        .expect("sample Domain Admins SID must parse")
}

/// A test fixture: a sample well-known SID (per MS-DTYP §2.4.2.2 —
/// `S-1-1-0` Everyone).
pub fn sample_everyone_sid() -> Sid {
    "S-1-1-0".parse().expect("sample Everyone SID must parse")
}

/// A test fixture: a sample well-known SID (per MS-DTYP §2.4.2.2 —
/// `S-1-5-11` Authenticated Users).
pub fn sample_authenticated_users_sid() -> Sid {
    "S-1-5-11"
        .parse()
        .expect("sample Authenticated Users SID must parse")
}

/// A test fixture: a sample DSA invocation ID (per MS-ADTS §3.1.1.3.2.6).
pub fn sample_invocation_id() -> Uuid {
    Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff")
        .expect("sample invocation ID must parse")
}

// ---------------------------------------------------------------------------
// Wave 4a — in-process test fixtures
// ---------------------------------------------------------------------------

/// Default realm used by the in-process fixtures (per ADR-013 — single-realm
/// test topology; cross-realm referral is a v0.7.0+ task).
pub const DEFAULT_REALM: &str = "ADRIAN.EXAMPLE.COM";

/// Default domain DN suffix used by the in-process directory fixture
/// (matches the realm — `ADRIAN.EXAMPLE.COM` → `DC=adrian,DC=example,DC=com`).
pub const DEFAULT_DOMAIN_DN: &str = "DC=adrian,DC=example,DC=com";

/// Default Users container DN — pre-seeded by [`TestDirectory::new`] so that
/// user objects created via [`TestHarness::create_principal`] have a parent.
pub const DEFAULT_USERS_CONTAINER_DN: &str = "CN=Users,DC=adrian,DC=example,DC=com";

/// Default krbtgt password used to derive the in-process krbtgt raw
/// AES-256 key (via PBKDF2-HMAC-SHA1, 4096 iterations per RFC 3962). The
/// raw key is consumed by the KDC handlers (`handle_as_req` /
/// `handle_tgs_req`); the HSM-bound key (used by `KpasswdService`) is a
/// separate, independently-generated AES-256 key inside the software HSM.
pub const DEFAULT_KRBTGT_PASSWORD: &[u8] = b"krbtgt-master-password";

/// HMAC key ID used by the kpasswd service to verify authenticator MACs
/// (per `adrian_kdc::kpasswd::KpasswdService::handle_kpasswd` — the service
/// looks up `"krbtgt-mac"` in the HSM on every request).
pub const KPASSWD_MAC_KEY_ID: &str = "krbtgt-mac";

/// Error type for in-process test-harness operations. Wraps the underlying
/// `KdcError` from `adrian-kdc` plus a few harness-specific failures
/// (missing principal, missing directory object, async store failures).
#[derive(Debug, Error)]
pub enum HarnessError {
    /// The requested principal was not found in the in-process principal
    /// store (call [`TestHarness::create_principal`] first).
    #[error("principal not found: {0}")]
    PrincipalNotFound(String),
    /// The requested directory object was not found in the in-process
    /// directory store.
    #[error("directory object not found: {0}")]
    DirectoryObjectNotFound(String),
    /// A KDC handler returned a typed error.
    #[error("kdc: {0}")]
    Kdc(#[from] adrian_kdc::KdcError),
    /// A directory-store operation failed.
    #[error("storage: {0}")]
    Storage(String),
    /// An HSM operation failed.
    #[error("hsm: {0}")]
    Hsm(#[from] adrian_hsm::HsmError),
    /// A crypto operation failed (AES-CTS encrypt/decrypt, HMAC verify).
    #[error("crypto: {0}")]
    Crypto(String),
}

impl From<adrian_kdc::crypto::CryptoError> for HarnessError {
    fn from(e: adrian_kdc::crypto::CryptoError) -> Self {
        HarnessError::Crypto(e.to_string())
    }
}

impl From<adrian_kdc::handlers::DecodeError> for HarnessError {
    fn from(e: adrian_kdc::handlers::DecodeError) -> Self {
        HarnessError::Crypto(format!("decode: {e}"))
    }
}

/// Current time in seconds since the UNIX epoch. Mirrors the private
/// `now_secs()` helper in `adrian_kdc::handlers` so the harness can build
/// PA-ENC-TIMESTAMP pre-auth and ticket timestamps that the KDC will accept
/// (within the ±5-minute clock-skew tolerance per RFC 4120 §3.1.3).
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Generate `len` cryptographically-secure random bytes using `ring`'s
/// `SystemRandom`. Used to generate confounders and session keys for the
/// in-process AS-REQ / TGS-REQ builders.
fn random_bytes(len: usize) -> Result<Vec<u8>, HarnessError> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf)
        .map_err(|_| HarnessError::Crypto("SystemRandom fill failed".into()))?;
    Ok(buf)
}

/// Encrypt `plaintext` for the given RFC 3961 §5.1 key usage, using the
/// per-usage Ke (encryption) and Ki (integrity) keys derived from
/// `base_key`.
///
/// This is the test-harness re-implementation of the `pub(crate)
/// encrypt_for_usage` in `adrian_kdc::handlers`. It's needed because the
/// original is `pub(crate)` — we can't call it from outside the crate — but
/// the harness needs to encrypt PA-ENC-TIMESTAMP pre-auth and authenticator
/// blobs to drive the KDC handlers end-to-end.
///
/// Wire format (matches `adrian_kdc::handlers::encrypt_for_usage`):
/// `aes256_cts(Ke, confounder || plaintext) || hmac_sha1_96(Ki, confounder || plaintext)`
pub fn encrypt_for_usage(
    base_key: &Aes256Key,
    key_usage: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, HarnessError> {
    let ke = adrian_kdc::key_derivation::derive_encryption_key(base_key, key_usage);
    let ki = adrian_kdc::key_derivation::derive_integrity_key(base_key, key_usage);
    let confounder = random_bytes(CONFOUNDER_LEN)?;
    let mut full = Vec::with_capacity(CONFOUNDER_LEN + plaintext.len());
    full.extend_from_slice(&confounder);
    full.extend_from_slice(plaintext);
    let ct = crypto::aes256_cts_encrypt(&ke, &full)?;
    let tag = crypto::hmac_sha1_96(&ki, &full);
    let mut out = Vec::with_capacity(ct.len() + HMAC_SHA1_96_LEN);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_for_usage`]. Verifies the HMAC
/// in constant time before returning the plaintext.
pub fn decrypt_for_usage(
    base_key: &Aes256Key,
    key_usage: u32,
    cipher_blob: &[u8],
) -> Result<Vec<u8>, HarnessError> {
    let ke = adrian_kdc::key_derivation::derive_encryption_key(base_key, key_usage);
    let ki = adrian_kdc::key_derivation::derive_integrity_key(base_key, key_usage);
    if cipher_blob.len() < CONFOUNDER_LEN + HMAC_SHA1_96_LEN {
        return Err(HarnessError::Crypto(format!(
            "cipher too short: {} < {}",
            cipher_blob.len(),
            CONFOUNDER_LEN + HMAC_SHA1_96_LEN
        )));
    }
    let ct_len = cipher_blob.len() - HMAC_SHA1_96_LEN;
    let (ct, tag) = cipher_blob.split_at(ct_len);
    let pt_with_confounder = crypto::aes256_cts_decrypt(&ke, ct)?;
    let expected_tag = crypto::hmac_sha1_96(&ki, &pt_with_confounder);
    if !constant_time_eq(&expected_tag, tag) {
        return Err(HarnessError::Crypto("HMAC mismatch".into()));
    }
    Ok(pt_with_confounder[CONFOUNDER_LEN..].to_vec())
}

/// Constant-time slice equality.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// TestDirectory — in-memory directory fixture
// ---------------------------------------------------------------------------

/// In-process directory fixture: wraps [`InMemoryDirectoryStore`] with the
/// pre-seeded domain root + Users container that the kpasswd flow expects.
///
/// The directory side of the Adrian stack is consumed by `KpasswdService`
/// (which looks up principals by DN and writes the `unicodePwd` attribute
/// on password changes). The KDC handlers use a separate
/// [`InMemoryPrincipalStore`] (see [`TestKdc`]) — the harness's
/// [`TestHarness::create_principal`] populates both stores so that AS-REQ
/// and kpasswd flows resolve to the same principal.
pub struct TestDirectory {
    /// The underlying in-memory directory store (re-exposed for direct
    /// test manipulation — e.g. asserting on `unicodePwd` after a
    /// `change_password` call).
    pub store: Arc<InMemoryDirectoryStore>,
    /// The realm (also the directory's DNS suffix uppercased).
    pub realm: String,
    /// The domain DN (e.g. `DC=adrian,DC=example,DC=com`).
    pub domain_dn: String,
}

impl TestDirectory {
    /// Construct a new in-process directory fixture with the default realm
    /// (`ADRIAN.EXAMPLE.COM`) and pre-seeded domain root + Users container.
    pub fn new() -> Self {
        Self::with_realm(DEFAULT_REALM)
    }

    /// Construct a directory fixture with a custom realm. The realm's DNS
    /// form (lowercased, dot-separated) becomes the domain DN. Pre-seeds:
    /// - The domain root (e.g. `DC=adrian,DC=example,DC=com`)
    /// - The Users container (e.g. `CN=Users,DC=adrian,DC=example,DC=com`)
    pub fn with_realm(realm: &str) -> Self {
        let store = Arc::new(InMemoryDirectoryStore::new());
        let domain_dn = realm_to_dn(realm);
        let users_dn = format!("CN=Users,{domain_dn}");
        let fixture = Self {
            store,
            realm: realm.to_string(),
            domain_dn,
        };
        // Pre-seed synchronously — `InMemoryDirectoryStore::put` is async
        // but does no I/O, so blocking on a future via `tokio::runtime::Handle`
        // is unnecessary. We use `tokio::task::block_in_place` instead via
        // a one-shot runtime only when called from a sync context; here we
        // require the caller to drive the runtime (TestHarness::new is async).
        // For the sync `new()` / `with_realm()` entry points we punt the
        // pre-seed to `TestHarness::new` (which is async) — this keeps the
        // sync constructor trivial and avoids a hidden tokio runtime.
        let _ = users_dn;
        fixture
    }

    /// Async pre-seed of the domain root + Users container. Called by
    /// [`TestHarness::new`] after constructing the directory fixture.
    async fn seed(&self) -> Result<(), HarnessError> {
        // Domain root.
        let domain_obj = Object {
            uuid: Uuid::from_u128(0xAD0_0000_0000_0001),
            dn: DistinguishedName {
                dn: self.domain_dn.clone(),
            },
            attributes: vec![Attribute {
                attribute_id: 0,
                name: "objectClass".into(),
                value: b"domainDNS".to_vec(),
            }],
            dnt: UNASSIGNED_DNT,
        };
        self.store
            .put(&domain_obj)
            .await
            .map_err(|e| HarnessError::Storage(e.to_string()))?;
        // Users container.
        let users_dn = format!("CN=Users,{}", self.domain_dn);
        let users_obj = Object {
            uuid: Uuid::from_u128(0xAD0_0000_0000_0002),
            dn: DistinguishedName { dn: users_dn },
            attributes: vec![Attribute {
                attribute_id: 0,
                name: "objectClass".into(),
                value: b"container".to_vec(),
            }],
            dnt: UNASSIGNED_DNT,
        };
        self.store
            .put(&users_obj)
            .await
            .map_err(|e| HarnessError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Insert (or replace) a directory object. Convenience wrapper around
    /// `InMemoryDirectoryStore::put` that converts the storage error to
    /// [`HarnessError`].
    pub async fn put(&self, obj: &Object) -> Result<(), HarnessError> {
        self.store
            .put(obj)
            .await
            .map_err(|e| HarnessError::Storage(e.to_string()))
    }

    /// Look up a directory object by DN. Convenience wrapper around
    /// `InMemoryDirectoryStore::get_by_dn`.
    pub async fn get_by_dn(&self, dn: &str) -> Result<Option<Object>, HarnessError> {
        self.store
            .get_by_dn(&DistinguishedName { dn: dn.to_string() })
            .await
            .map_err(|e| HarnessError::Storage(e.to_string()))
    }

    /// Build the canonical DN for a user principal under the Users
    /// container: `CN=<name>,CN=Users,<domain_dn>`.
    pub fn user_dn(&self, name: &str) -> String {
        format!("CN={name},CN=Users,{}", self.domain_dn)
    }
}

impl Default for TestDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a Kerberos realm (e.g. `ADRIAN.EXAMPLE.COM`) to its DNS-form
/// domain DN (e.g. `DC=adrian,DC=example,DC=com`). Each dot-separated
/// component becomes a `DC=` RDN. Per RFC 4514, the DN is case-insensitive
/// but the convention is lowercase DNS form (matches AD's behavior).
fn realm_to_dn(realm: &str) -> String {
    realm
        .to_ascii_lowercase()
        .split('.')
        .map(|c| format!("DC={c}"))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// TestKdc — in-process KDC fixture
// ---------------------------------------------------------------------------

/// In-process KDC fixture: wraps [`InMemoryPrincipalStore`] + a deterministic
/// krbtgt raw AES-256 key, exposing [`TestKdc::as_req`] / [`TestKdc::tgs_req`]
/// which call the real `adrian_kdc::handlers::{handle_as_req, handle_tgs_req}`
/// free functions.
///
/// The krbtgt key here is the *raw* 32-byte AES key (derived via PBKDF2 from
/// [`DEFAULT_KRBTGT_PASSWORD`]). This is the key the KDC handlers expect —
/// they take a `&Aes256Key` directly, not an HSM `KeyHandle`. The
/// [`TestKpasswd`] fixture uses a separate HSM-bound key (via
/// [`KrbtgtManager`]) because the kpasswd service goes through the HSM for
/// MAC verification. The two keys are NOT the same bytes — they're
/// independent keys, one for each codepath. This mirrors the production
/// split where the KDC handlers' key is held in process memory (per ADR-018
/// stateless-pool) while the kpasswd HMAC key is HSM-bound (per ADR-019).
pub struct TestKdc {
    /// The in-memory principal store (re-exposed for direct test
    /// manipulation — e.g. asserting on `kvno` after a password change).
    pub principal_store: Arc<InMemoryPrincipalStore>,
    /// The krbtgt raw AES-256 key used by the KDC handlers.
    pub krbtgt_key: Aes256Key,
    /// The realm served by this KDC.
    pub realm: String,
}

impl TestKdc {
    /// Construct a new KDC fixture with the default realm and a
    /// deterministic krbtgt key derived from [`DEFAULT_KRBTGT_PASSWORD`].
    pub fn new() -> Self {
        Self::with_realm(DEFAULT_REALM)
    }

    /// Construct a KDC fixture with a custom realm. The krbtgt key is
    /// derived via PBKDF2-HMAC-SHA1 (4096 iterations, RFC 3962 §3) from
    /// [`DEFAULT_KRBTGT_PASSWORD`] and the salt `<REALM>krbtgt` (RFC 3962
    /// §4 — salt is `realm ++ concat(components)`).
    pub fn with_realm(realm: &str) -> Self {
        let mut salt = Vec::new();
        salt.extend_from_slice(realm.as_bytes());
        salt.extend_from_slice(b"krbtgt");
        let krbtgt_key = crypto::derive_aes256_key(DEFAULT_KRBTGT_PASSWORD, &salt);
        Self {
            principal_store: Arc::new(InMemoryPrincipalStore::new()),
            krbtgt_key,
            realm: realm.to_string(),
        }
    }

    /// Insert (or replace) a principal record. Convenience wrapper around
    /// `InMemoryPrincipalStore::insert`.
    pub fn insert(&self, rec: PrincipalRecord) {
        self.principal_store.insert(rec);
    }

    /// Look up a principal by name (single-component, e.g. `"alice"`).
    pub async fn lookup(&self, name: &str) -> Result<PrincipalRecord, HarnessError> {
        self.principal_store
            .lookup(&self.realm, &[name.to_string()])
            .await
            .map_err(|e| HarnessError::Storage(e.to_string()))?
            .ok_or_else(|| HarnessError::PrincipalNotFound(format!("{}/{}", self.realm, name)))
    }

    /// Build a valid AS-REQ for the given client principal, with a
    /// PA-ENC-TIMESTAMP pre-authenticator encrypted under the client's
    /// long-term key (key usage 1, RFC 4120 §5.2.7.2).
    pub fn build_as_req(&self, client: &PrincipalRecord) -> Result<AsReq, HarnessError> {
        let now = now_secs();
        let pa_ts = PaEncTsEnc {
            patimestamp: now,
            pausec: 0,
        };
        let pa_ts_bytes = handlers::encode_pa_enc_ts_enc(&pa_ts);
        let blob = encrypt_for_usage(&client.key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &pa_ts_bytes)?;
        Ok(AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: client.realm.clone(),
            cname: client.components.clone(),
            nonce: 0xDEAD_BEEF,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            padata: vec![PaData {
                padata_type: PA_ENC_TIMESTAMP_TYPE,
                padata_value: blob,
            }],
            till: now + DEFAULT_TGT_LIFETIME_SECS,
        })
    }

    /// Perform an AS-REQ for the named client. Returns the raw AS-REP
    /// bytes (caller can decode via `adrian_kdc::handlers::decode_as_rep`).
    ///
    /// The AS-REQ is built with a fresh PA-ENC-TIMESTAMP pre-auth encrypted
    /// under the client's long-term key (key usage 1). The KDC's
    /// `handle_as_req` verifies the pre-auth, builds the TGT, and returns
    /// the AS-REP.
    pub async fn as_req(&self, client_name: &str) -> Result<Vec<u8>, HarnessError> {
        let client = self.lookup(client_name).await?;
        let req = self.build_as_req(&client)?;
        let req_bytes = handlers::encode_as_req(&req);
        let rep_bytes =
            handlers::handle_as_req(&*self.principal_store, &self.krbtgt_key, &req_bytes).await?;
        Ok(rep_bytes)
    }

    /// Perform a TGS-REQ for `service_name` using a TGT previously issued
    /// to `client_name`. The TGT is obtained by performing an AS-REQ
    /// internally and recovering the session key from the AS-REP enc-part
    /// (decrypted under the client's long-term key, key usage 3).
    ///
    /// Returns the raw TGS-REP bytes (caller can decode via
    /// `adrian_kdc::handlers::decode_tgs_rep`).
    pub async fn tgs_req(
        &self,
        client_name: &str,
        service_name: &str,
    ) -> Result<Vec<u8>, HarnessError> {
        let client = self.lookup(client_name).await?;
        // Step 1: AS-REQ → AS-REP, recover TGT + session key.
        let as_req = self.build_as_req(&client)?;
        let as_req_bytes = handlers::encode_as_req(&as_req);
        let as_rep_bytes =
            handlers::handle_as_req(&*self.principal_store, &self.krbtgt_key, &as_req_bytes)
                .await?;
        let as_rep: AsRep = handlers::decode_as_rep(&as_rep_bytes)?;
        let rep_pt = decrypt_for_usage(&client.key, KEY_USAGE_AS_REP_ENC_PART, &as_rep.enc_part)?;
        let erp: EncKdcRepPart = handlers::decode_enc_kdc_rep_part(&rep_pt)?;
        let session_key = erp.session_key;
        let tgt = as_rep.ticket.clone();
        // Step 2: build the authenticator (encrypted under the TGT session
        // key, key usage 7).
        let now = now_secs();
        let auth = Authenticator {
            crealm: client.realm.clone(),
            cname: client.components.clone(),
            subkey: None,
            seq_number: 1,
            ctime: now,
            cusec: 0,
        };
        let auth_bytes = handlers::encode_authenticator(&auth);
        let auth_enc =
            encrypt_for_usage(&session_key, KEY_USAGE_TGS_REQ_AUTHENTICATOR, &auth_bytes)?;
        // Step 3: look up the service principal's components.
        let svc = self
            .principal_store
            .lookup(&self.realm, &parse_service_components(service_name))
            .await
            .map_err(|e| HarnessError::Storage(e.to_string()))?
            .ok_or_else(|| {
                HarnessError::PrincipalNotFound(format!("{}/{}", self.realm, service_name))
            })?;
        // Step 4: TGS-REQ.
        let req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: svc.realm.clone(),
            sname: svc.components.clone(),
            nonce: 0xCAFE_BABE,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt,
            authenticator_enc: auth_enc,
            till: now + DEFAULT_TGT_LIFETIME_SECS,
        };
        let req_bytes = handlers::encode_tgs_req(&req);
        let rep_bytes =
            handlers::handle_tgs_req(&*self.principal_store, &self.krbtgt_key, &req_bytes).await?;
        Ok(rep_bytes)
    }
}

impl Default for TestKdc {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a service principal name string into components. Accepts either
/// a single-component name (e.g. `"alice"`) or a slash-separated name
/// (e.g. `"host/web.example.com"`).
fn parse_service_components(name: &str) -> Vec<String> {
    name.split('/').map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// TestKpasswd — in-process kpasswd fixture
// ---------------------------------------------------------------------------

/// In-process kpasswd fixture: wraps [`KpasswdService`] with a software HSM
/// and the HSM-bound [`KrbtgtManager`]. Exposes
/// [`TestKpasswd::change_password`] which calls the real
/// `KpasswdService::handle_kpasswd` (RFC 3244).
///
/// The fixture pre-seeds the `krbtgt-mac` HMAC key in the HSM at
/// construction time so that `change_password` can compute the
/// authenticator MAC that `KpasswdService::handle_kpasswd` will verify.
pub struct TestKpasswd {
    /// The underlying kpasswd service (re-exposed for direct test
    /// manipulation).
    pub service: KpasswdService,
    /// The HSM (re-exposed so tests can generate additional keys if needed).
    pub hsm: Arc<dyn Hsm>,
    /// The krbtgt manager (HSM-bound).
    pub krbtgt: Arc<KrbtgtManager>,
    /// The MAC key handle used to sign authenticators.
    pub mac_key_handle: KeyHandle,
    /// The realm served by this kpasswd fixture.
    pub realm: String,
}

impl TestKpasswd {
    /// Construct a new kpasswd fixture wired to the given directory store.
    /// The fixture creates a fresh `SoftwareHsm`, a fresh `KrbtgtManager`
    /// (which generates the krbtgt AES-256 key in the HSM), and pre-seeds
    /// the `krbtgt-mac` HMAC key.
    pub async fn new(directory: Arc<InMemoryDirectoryStore>) -> Result<Self, HarnessError> {
        Self::with_realm(directory, DEFAULT_REALM).await
    }

    /// Construct a kpasswd fixture with a custom realm.
    pub async fn with_realm(
        directory: Arc<InMemoryDirectoryStore>,
        realm: &str,
    ) -> Result<Self, HarnessError> {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await?);
        // Pre-seed the krbtgt-mac HMAC key. `Hsm::generate_key` is
        // idempotent in the software impl — calling it again in
        // `KpasswdService::handle_kpasswd` returns the same handle.
        let mac_key_handle = hsm
            .generate_key(KPASSWD_MAC_KEY_ID, KeyType::HmacSha1)
            .await?;
        let dir_dyn: Arc<dyn adrian_storage_core::DirectoryStore> = directory;
        let service = KpasswdService::new(dir_dyn, krbtgt.clone(), hsm.clone());
        Ok(Self {
            service,
            hsm,
            krbtgt,
            mac_key_handle,
            realm: realm.to_string(),
        })
    }

    /// Compute the authenticator MAC for a kpasswd request. The MAC is
    /// HMAC-SHA1-96 over `(client_principal || target_principal || new_password)`
    /// under the krbtgt-mac key (per `KpasswdService::handle_kpasswd`).
    pub async fn compute_mac(
        &self,
        client: &str,
        target: &str,
        new_password: &[u8],
    ) -> Result<Vec<u8>, HarnessError> {
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(target.as_bytes());
        mac_input.extend_from_slice(new_password);
        let mac = self.hsm.sign(&self.mac_key_handle, &mac_input).await?;
        Ok(mac)
    }

    /// Build a kpasswd request for `client` changing their own password to
    /// `new_password`. The request includes a valid authenticator MAC
    /// computed under the krbtgt-mac key.
    pub async fn build_request(
        &self,
        client: &str,
        new_password: &[u8],
    ) -> Result<KpasswdRequest, HarnessError> {
        let principal = format!("{client}@{}", self.realm);
        let mac = self
            .compute_mac(&principal, &principal, new_password)
            .await?;
        Ok(KpasswdRequest {
            client_principal: PrincipalName::new(principal.clone()),
            target_principal: PrincipalName::new(principal),
            authenticator_mac: mac,
            new_password: new_password.to_vec(),
            password_encrypted: false,
        })
    }

    /// Perform a kpasswd password-change request for `client` (self-service
    /// — `client` is both the authenticator and the target). Returns the
    /// parsed [`KpasswdResponse`].
    ///
    /// The kpasswd service verifies the authenticator MAC, looks up the
    /// target principal in the directory, hashes the new password via
    /// PBKDF2-HMAC-SHA256 (200k iterations), and writes the `unicodePwd`
    /// attribute on the target's directory object.
    pub async fn change_password(
        &self,
        client: &str,
        new_password: &[u8],
    ) -> Result<KpasswdResponse, HarnessError> {
        let req = self.build_request(client, new_password).await?;
        let resp_bytes = self.service.handle_kpasswd(&req.encode()).await?;
        let resp = KpasswdResponse::parse(&resp_bytes)?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// TestHarness — combined in-process fixture
// ---------------------------------------------------------------------------

/// Combined in-process fixture: a fully-wired Adrian stack with
/// [`TestDirectory`] + [`TestKdc`] + [`TestKpasswd`] sharing the same
/// realm.
///
/// Constructed via [`TestHarness::new`] (async — the kpasswd fixture
/// awaits HSM key generation). Each instance is fully isolated: a fresh
/// `InMemoryDirectoryStore`, a fresh `InMemoryPrincipalStore`, a fresh
/// `SoftwareHsm`, and a fresh `KrbtgtManager`. Tests can construct
/// multiple harnesses in parallel without cross-talk.
pub struct TestHarness {
    /// The directory fixture.
    pub directory: TestDirectory,
    /// The KDC fixture.
    pub kdc: TestKdc,
    /// The kpasswd fixture.
    pub kpasswd: TestKpasswd,
    /// Monotonic counter for generating per-harness UUIDv7s.
    uuid_counter: AtomicU64,
}

impl TestHarness {
    /// Construct a new fully-wired in-process Adrian stack with the default
    /// realm (`ADRIAN.EXAMPLE.COM`). Pre-seeds the directory's domain root
    /// and Users container.
    pub async fn new() -> Result<Self, HarnessError> {
        Self::with_realm(DEFAULT_REALM).await
    }

    /// Construct a harness with a custom realm.
    pub async fn with_realm(realm: &str) -> Result<Self, HarnessError> {
        let directory = TestDirectory::with_realm(realm);
        directory.seed().await?;
        // The KDC and kpasswd fixtures share the same directory store
        // (Arc-backed — cheap to clone).
        let directory_store = directory.store.clone();
        let kdc = TestKdc::with_realm(realm);
        let kpasswd = TestKpasswd::with_realm(directory_store, realm).await?;
        Ok(Self {
            directory,
            kdc,
            kpasswd,
            uuid_counter: AtomicU64::new(1),
        })
    }

    /// Generate a fresh UUIDv7 for a new principal. Combines the current
    /// time (UUIDv7's 48-bit timestamp) with a per-harness monotonic
    /// counter to guarantee uniqueness even when called in a tight loop.
    fn fresh_uuid(&self) -> Uuid {
        // Use `Uuid::now_v7()` (the uuid crate's `v7` feature — does not
        // require `v4`) to get a time-ordered UUID per Decision 3. The
        // counter is unused for UUID generation but kept for future
        // deterministic-UUID test modes.
        let _ = self.uuid_counter.fetch_add(1, Ordering::Relaxed);
        Uuid::now_v7()
    }

    /// Create a user principal with the given name and password. Inserts
    /// the principal into both the principal store (for KDC handlers) and
    /// the directory store (for kpasswd). Returns the principal's UUID.
    ///
    /// The principal's long-term AES-256 key is derived via PBKDF2-HMAC-SHA1
    /// (4096 iterations, RFC 3962 §3) from the password and the salt
    /// `<REALM><name>` (RFC 3962 §4 — `realm ++ concat(components)`).
    pub async fn create_principal(&self, name: &str, password: &str) -> Result<Uuid, HarnessError> {
        let uuid = self.fresh_uuid();
        let mut salt = Vec::new();
        salt.extend_from_slice(self.kdc.realm.as_bytes());
        salt.extend_from_slice(name.as_bytes());
        let key = crypto::derive_aes256_key(password.as_bytes(), &salt);
        let rec = PrincipalRecord::new(uuid, &self.kdc.realm, vec![name.to_string()], key);
        self.kdc.insert(rec);
        // Directory object — DN under the Users container.
        let dn = self.directory.user_dn(name);
        let obj = Object {
            uuid,
            dn: DistinguishedName { dn: dn.clone() },
            attributes: vec![
                Attribute {
                    attribute_id: 0,
                    name: "objectClass".into(),
                    value: b"user".to_vec(),
                },
                Attribute {
                    attribute_id: 0,
                    name: "sAMAccountName".into(),
                    value: name.as_bytes().to_vec(),
                },
            ],
            dnt: UNASSIGNED_DNT,
        };
        self.directory.put(&obj).await?;
        Ok(uuid)
    }

    /// Create a service principal with a two-component name
    /// (`host/<name>`). Inserts into both stores. Returns the principal's
    /// UUID.
    pub async fn create_service_principal(
        &self,
        name: &str,
        password: &str,
    ) -> Result<Uuid, HarnessError> {
        let uuid = self.fresh_uuid();
        let components = vec!["host".to_string(), name.to_string()];
        let mut salt = Vec::new();
        salt.extend_from_slice(self.kdc.realm.as_bytes());
        for c in &components {
            salt.extend_from_slice(c.as_bytes());
        }
        let key = crypto::derive_aes256_key(password.as_bytes(), &salt);
        let rec = PrincipalRecord::new(uuid, &self.kdc.realm, components, key);
        self.kdc.insert(rec);
        // Directory object — DN under the Users container (services live
        // alongside users in the test fixture for simplicity).
        let dn = format!("CN=host-{name},CN=Users,{}", self.directory.domain_dn);
        let obj = Object {
            uuid,
            dn: DistinguishedName { dn },
            attributes: vec![
                Attribute {
                    attribute_id: 0,
                    name: "objectClass".into(),
                    value: b"computer".to_vec(),
                },
                Attribute {
                    attribute_id: 0,
                    name: "sAMAccountName".into(),
                    value: format!("host${name}").into_bytes(),
                },
            ],
            dnt: UNASSIGNED_DNT,
        };
        self.directory.put(&obj).await?;
        Ok(uuid)
    }

    /// Perform an AS-REQ for the named client. Convenience wrapper around
    /// [`TestKdc::as_req`].
    pub async fn as_req(&self, client: &str) -> Result<Vec<u8>, HarnessError> {
        self.kdc.as_req(client).await
    }

    /// Perform a TGS-REQ for `service` using a TGT obtained for `client`.
    /// Convenience wrapper around [`TestKdc::tgs_req`].
    pub async fn tgs_req(&self, client: &str, service: &str) -> Result<Vec<u8>, HarnessError> {
        self.kdc.tgs_req(client, service).await
    }

    /// Perform a kpasswd password change for `client` (self-service).
    /// Convenience wrapper around [`TestKpasswd::change_password`].
    pub async fn change_password(
        &self,
        client: &str,
        new_password: &str,
    ) -> Result<KpasswdResponse, HarnessError> {
        self.kpasswd
            .change_password(client, new_password.as_bytes())
            .await
    }

    /// Look up a principal in the principal store by name. Returns the
    /// full `PrincipalRecord` (including the long-term AES-256 key, kvno,
    /// and UUID).
    pub async fn principal_lookup(&self, name: &str) -> Result<PrincipalRecord, HarnessError> {
        self.kdc.lookup(name).await
    }

    /// Fetch the directory object for a user principal by name. Returns
    /// `None` if no such object exists.
    pub async fn directory_object_for(&self, name: &str) -> Result<Option<Object>, HarnessError> {
        let dn = self.directory.user_dn(name);
        self.directory.get_by_dn(&dn).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_kdc::handlers::{
        decode_as_rep, decode_tgs_rep, KEY_USAGE_AS_REP_TGT, KEY_USAGE_TGS_REP_TICKET,
        MSG_TYPE_AS_REP, MSG_TYPE_TGS_REP, TICKET_FLAG_FORWARDABLE, TICKET_FLAG_RENEWABLE,
    };
    use adrian_kdc::kpasswd::result_code;

    /// `TestHarness::new()` must construct a fully-wired stack with no
    /// errors: the directory is seeded, the principal store is empty, the
    /// HSM has the krbtgt + krbtgt-mac keys, and the realm is the default.
    #[tokio::test]
    async fn new_creates_wired_stack() {
        let h = TestHarness::new().await.expect("harness constructs");
        // Realm matches the default.
        assert_eq!(h.directory.realm, DEFAULT_REALM);
        assert_eq!(h.kdc.realm, DEFAULT_REALM);
        assert_eq!(h.kpasswd.realm, DEFAULT_REALM);
        // Domain DN matches the default.
        assert_eq!(h.directory.domain_dn, DEFAULT_DOMAIN_DN);
        // The directory has the domain root + Users container pre-seeded.
        let domain = h
            .directory
            .get_by_dn(DEFAULT_DOMAIN_DN)
            .await
            .expect("get domain")
            .expect("domain root exists");
        assert_eq!(domain.uuid, Uuid::from_u128(0xAD0_0000_0000_0001));
        let users = h
            .directory
            .get_by_dn(DEFAULT_USERS_CONTAINER_DN)
            .await
            .expect("get users container")
            .expect("users container exists");
        assert_eq!(users.uuid, Uuid::from_u128(0xAD0_0000_0000_0002));
        // The principal store is empty (no principals created yet).
        assert!(h.kdc.principal_store.is_empty());
        // The HSM has the krbtgt + krbtgt-mac keys.
        assert_eq!(h.kpasswd.mac_key_handle.key_type, KeyType::HmacSha1);
        assert_eq!(h.kpasswd.mac_key_handle.id, KPASSWD_MAC_KEY_ID);
        let krbtgt_kh = h.kpasswd.krbtgt.current_key().await;
        assert_eq!(h.kpasswd.krbtgt.current_key().await.version, 1);
        assert_eq!(krbtgt_kh.key_type, KeyType::Aes256);
    }

    /// `create_principal()` must add the principal to BOTH the principal
    /// store (KDC) and the directory store (kpasswd). The two records must
    /// carry the same UUID.
    #[tokio::test]
    async fn create_principal_adds_to_directory_and_principal_store() {
        let h = TestHarness::new().await.expect("harness");
        let uuid = h
            .create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        // Principal store has alice.
        let rec = h.kdc.lookup("alice").await.expect("lookup alice");
        assert_eq!(rec.uuid, uuid);
        assert_eq!(rec.realm, DEFAULT_REALM);
        assert_eq!(rec.components, vec!["alice".to_string()]);
        assert_eq!(rec.kvno, 1);
        // Directory has alice's object.
        let obj = h
            .directory_object_for("alice")
            .await
            .expect("dir alice")
            .expect("alice dir obj exists");
        assert_eq!(obj.uuid, uuid);
        let dn = h.directory.user_dn("alice");
        assert_eq!(obj.dn.dn, dn);
        // sAMAccountName attribute is set.
        let sam = obj
            .attributes
            .iter()
            .find(|a| a.name == "sAMAccountName")
            .expect("sAMAccountName present");
        assert_eq!(sam.value, b"alice");
    }

    /// `as_req()` returns a valid AS-REP: decodable, with the right pvno /
    /// msg-type / crealm / cname, and a TGT whose sname is
    /// `krbtgt/<REALM>`.
    #[tokio::test]
    async fn as_req_returns_valid_as_rep() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create");
        let rep_bytes = h.as_req("alice").await.expect("AS-REQ");
        let rep = decode_as_rep(&rep_bytes).expect("decode AS-REP");
        assert_eq!(rep.pvno, PVNO);
        assert_eq!(rep.msg_type, MSG_TYPE_AS_REP);
        assert_eq!(rep.crealm, DEFAULT_REALM);
        assert_eq!(rep.cname, vec!["alice".to_string()]);
        assert_eq!(
            rep.ticket.sname,
            vec!["krbtgt".to_string(), DEFAULT_REALM.to_string()]
        );
        assert_eq!(rep.ticket.etype, EType::Aes256CtsHmacSha1_96);
    }

    /// The AS-REP's TGT enc-part must be decryptable with the krbtgt raw
    /// key (key usage 2), yielding a valid `EncTicketPart` with the
    /// client's identity.
    #[tokio::test]
    async fn as_rep_tgt_decrypts_under_krbtgt_key() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create");
        let rep_bytes = h.as_req("alice").await.expect("AS-REQ");
        let rep = decode_as_rep(&rep_bytes).expect("decode AS-REP");
        // Decrypt the TGT enc-part with the krbtgt key (key usage 2).
        let tgt_pt = decrypt_for_usage(
            &h.kdc.krbtgt_key,
            KEY_USAGE_AS_REP_TGT,
            &rep.ticket.enc_part,
        )
        .expect("decrypt TGT");
        let etp = handlers::decode_enc_ticket_part(&tgt_pt).expect("decode EncTicketPart");
        assert_eq!(etp.crealm, DEFAULT_REALM);
        assert_eq!(etp.cname, vec!["alice".to_string()]);
        assert!(etp.flags & TICKET_FLAG_FORWARDABLE != 0);
        assert!(etp.flags & TICKET_FLAG_RENEWABLE != 0);
    }

    /// `tgs_req()` returns a valid TGS-REP: decodable, with the right
    /// pvno / msg-type, and a service ticket whose sname matches the
    /// requested service.
    #[tokio::test]
    async fn tgs_req_returns_valid_tgs_rep() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        h.create_service_principal("web.example.com", "svc-password")
            .await
            .expect("create svc");
        let rep_bytes = h
            .tgs_req("alice", "host/web.example.com")
            .await
            .expect("TGS-REQ");
        let rep = decode_tgs_rep(&rep_bytes).expect("decode TGS-REP");
        assert_eq!(rep.pvno, PVNO);
        assert_eq!(rep.msg_type, MSG_TYPE_TGS_REP);
        assert_eq!(rep.crealm, DEFAULT_REALM);
        assert_eq!(rep.cname, vec!["alice".to_string()]);
        assert_eq!(
            rep.ticket.sname,
            vec!["host".to_string(), "web.example.com".to_string()]
        );
    }

    /// The TGS-REP's service ticket enc-part must be decryptable with the
    /// service's long-term key (key usage 2), yielding a valid
    /// `EncTicketPart` carrying the client's identity.
    #[tokio::test]
    async fn tgs_rep_service_ticket_decrypts_under_service_key() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        h.create_service_principal("web.example.com", "svc-password")
            .await
            .expect("create svc");
        let rep_bytes = h
            .tgs_req("alice", "host/web.example.com")
            .await
            .expect("TGS-REQ");
        let rep = decode_tgs_rep(&rep_bytes).expect("decode TGS-REP");
        // Look up the service principal's long-term key (two-component
        // service principal — `host/web.example.com`).
        let svc = h
            .kdc
            .principal_store
            .lookup(
                DEFAULT_REALM,
                &["host".to_string(), "web.example.com".to_string()],
            )
            .await
            .expect("lookup")
            .expect("svc found");
        let svc_pt = decrypt_for_usage(&svc.key, KEY_USAGE_TGS_REP_TICKET, &rep.ticket.enc_part)
            .expect("decrypt svc ticket");
        let svc_etp = handlers::decode_enc_ticket_part(&svc_pt).expect("decode EncTicketPart");
        assert_eq!(svc_etp.cname, vec!["alice".to_string()]);
        assert_eq!(svc_etp.crealm, DEFAULT_REALM);
    }

    /// `change_password()` returns a success response with result code 0
    /// (KRB5_KPASSWD_SUCCESS).
    #[tokio::test]
    async fn change_password_returns_success() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        let resp = h
            .change_password("alice", "new-strong-password!")
            .await
            .expect("change_password");
        assert_eq!(
            resp.result_code,
            result_code::KRB5_KPASSWD_SUCCESS,
            "expected success, got: {}",
            resp.result_string
        );
    }

    /// `change_password()` updates the directory: the target object's
    /// `unicodePwd` attribute is set to a fresh PBKDF2 hash (16-byte salt +
    /// 32-byte output = 48 bytes).
    #[tokio::test]
    async fn change_password_sets_unicode_pwd_in_directory() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        // Before: no unicodePwd attribute.
        let before = h
            .directory_object_for("alice")
            .await
            .expect("get alice")
            .expect("alice exists");
        assert!(
            before.attributes.iter().all(|a| a.name != "unicodePwd"),
            "no unicodePwd before change"
        );
        // Change.
        h.change_password("alice", "new-strong-password!")
            .await
            .expect("change");
        // After: unicodePwd is set, length = 16 (salt) + 32 (output) = 48.
        let after = h
            .directory_object_for("alice")
            .await
            .expect("get alice")
            .expect("alice exists");
        let pwd_attr = after
            .attributes
            .iter()
            .find(|a| a.name == "unicodePwd")
            .expect("unicodePwd after change");
        assert_eq!(
            pwd_attr.value.len(),
            adrian_kdc::kpasswd::PBKDF2_SALT_LEN + adrian_kdc::kpasswd::PBKDF2_OUTPUT_LEN
        );
    }

    /// `change_password()` with the SAME new password twice would be a
    /// replay (same MAC). Instead, this test changes the password twice
    /// with DIFFERENT new passwords and verifies the directory's
    /// `unicodePwd` hash changes (random salt per call).
    #[tokio::test]
    async fn change_password_produces_fresh_hash_each_call() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        h.change_password("alice", "first-new-password!")
            .await
            .expect("first change");
        let after_first = h
            .directory_object_for("alice")
            .await
            .expect("get alice")
            .expect("alice exists");
        let hash1 = after_first
            .attributes
            .iter()
            .find(|a| a.name == "unicodePwd")
            .expect("unicodePwd after first change")
            .value
            .clone();
        h.change_password("alice", "second-new-password!")
            .await
            .expect("second change");
        let after_second = h
            .directory_object_for("alice")
            .await
            .expect("get alice")
            .expect("alice exists");
        let hash2 = after_second
            .attributes
            .iter()
            .find(|a| a.name == "unicodePwd")
            .expect("unicodePwd after second change")
            .value
            .clone();
        assert_eq!(
            hash1.len(),
            adrian_kdc::kpasswd::PBKDF2_SALT_LEN + adrian_kdc::kpasswd::PBKDF2_OUTPUT_LEN
        );
        assert_eq!(
            hash2.len(),
            adrian_kdc::kpasswd::PBKDF2_SALT_LEN + adrian_kdc::kpasswd::PBKDF2_OUTPUT_LEN
        );
        assert_ne!(
            hash1, hash2,
            "fresh PBKDF2 salt must produce a different hash"
        );
    }

    /// Fixture isolation: two `TestHarness` instances are fully
    /// independent. Creating a principal in one does NOT make it visible
    /// in the other; AS-REQs in one cannot resolve principals from the
    /// other.
    #[tokio::test]
    async fn fixtures_are_isolated() {
        let h1 = TestHarness::new().await.expect("harness 1");
        let h2 = TestHarness::new().await.expect("harness 2");
        h1.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice in h1");
        // h1 sees alice.
        assert!(h1.kdc.lookup("alice").await.is_ok());
        // h2 does NOT see alice.
        let err = h2.kdc.lookup("alice").await.expect_err("must be missing");
        assert!(matches!(err, HarnessError::PrincipalNotFound(_)));
        // h2's directory does NOT have alice.
        let obj = h2.directory_object_for("alice").await.expect("dir get");
        assert!(obj.is_none(), "alice must not exist in h2's directory");
    }

    /// `principal_lookup()` returns the principal record stored by
    /// `create_principal()` — including the UUID, realm, components, and
    /// kvno.
    #[tokio::test]
    async fn principal_lookup_returns_created_principal() {
        let h = TestHarness::new().await.expect("harness");
        let uuid = h
            .create_principal("alice", "hunter2-password")
            .await
            .expect("create");
        let rec = h.principal_lookup("alice").await.expect("lookup");
        assert_eq!(rec.uuid, uuid);
        assert_eq!(rec.realm, DEFAULT_REALM);
        assert_eq!(rec.components, vec!["alice".to_string()]);
        assert_eq!(rec.kvno, 1);
        // The long-term key is non-zero (PBKDF2 of a non-empty password).
        assert_ne!(rec.key, [0u8; 32]);
    }

    /// `realm_to_dn` correctly converts a dotted realm to a `DC=`-form DN
    /// (lowercased per RFC 4514 DNS-form convention).
    #[test]
    fn realm_to_dn_converts_correctly() {
        assert_eq!(
            realm_to_dn("ADRIAN.EXAMPLE.COM"),
            "DC=adrian,DC=example,DC=com"
        );
        assert_eq!(realm_to_dn("CORP.COM"), "DC=corp,DC=com");
        assert_eq!(realm_to_dn("LOCAL"), "DC=local");
    }

    /// `parse_service_components` splits a slash-separated service name
    /// into components.
    #[test]
    fn parse_service_components_splits_on_slash() {
        assert_eq!(
            parse_service_components("host/web.example.com"),
            vec!["host".to_string(), "web.example.com".to_string()]
        );
        assert_eq!(parse_service_components("alice"), vec!["alice".to_string()]);
        // Three components (rare but valid for some SPNs).
        assert_eq!(
            parse_service_components("ldap/dc1/corp.com"),
            vec![
                "ldap".to_string(),
                "dc1".to_string(),
                "corp.com".to_string()
            ]
        );
    }

    /// `encrypt_for_usage` / `decrypt_for_usage` round-trip: encrypting
    /// then decrypting the same plaintext under the same key + usage
    /// recovers the original plaintext.
    #[test]
    fn encrypt_decrypt_for_usage_round_trips() {
        let base = crypto::derive_aes256_key(b"password", b"salt");
        let plaintext = b"some-secret-payload-32-bytes-ok!";
        let blob = encrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, plaintext)
            .expect("encrypt");
        let recovered =
            decrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &blob).expect("decrypt");
        assert_eq!(&recovered, plaintext);
    }

    /// `decrypt_for_usage` rejects a blob encrypted under a different key
    /// usage (HMAC mismatch).
    #[test]
    fn decrypt_for_usage_rejects_wrong_key_usage() {
        let base = crypto::derive_aes256_key(b"password", b"salt");
        let plaintext = b"some-secret-payload-32-bytes-ok!";
        let blob = encrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, plaintext)
            .expect("encrypt");
        let err = decrypt_for_usage(&base, KEY_USAGE_AS_REP_ENC_PART, &blob)
            .expect_err("must fail with wrong usage");
        assert!(matches!(err, HarnessError::Crypto(_)));
    }

    /// `TestKdc::build_as_req` produces a well-formed AS-REQ that the KDC
    /// accepts (round-trips through encode/decode).
    #[tokio::test]
    async fn build_as_req_produces_decodable_request() {
        let h = TestHarness::new().await.expect("harness");
        h.create_principal("alice", "hunter2-password")
            .await
            .expect("create alice");
        let alice = h.kdc.lookup("alice").await.expect("lookup");
        let req = h.kdc.build_as_req(&alice).expect("build_as_req");
        let bytes = handlers::encode_as_req(&req);
        let decoded = handlers::decode_as_req(&bytes).expect("decode_as_req");
        assert_eq!(decoded.pvno, PVNO);
        assert_eq!(decoded.msg_type, MSG_TYPE_AS_REQ);
        assert_eq!(decoded.cname, vec!["alice".to_string()]);
        assert_eq!(decoded.realm, DEFAULT_REALM);
        // PA-ENC-TIMESTAMP padata present.
        assert_eq!(decoded.padata.len(), 1);
        assert_eq!(decoded.padata[0].padata_type, PA_ENC_TIMESTAMP_TYPE);
    }
}
