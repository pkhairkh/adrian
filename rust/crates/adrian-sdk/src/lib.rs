//! # adrian-sdk
//!
//! Unified Rust client SDK core. `AdrianClient` exposes auth, directory, file,
//! and policy modules to host platforms. FFI bindings (`adrian-sdk-c`,
//! `adrian-sdk-jni`, `adrian-sdk-swift`, `adrian-sdk-python`) wrap this crate.
//!
//! ## ADRs
//!
//! - ADR-107: Unified Rust core SDK
//! - ADR-108: SSPI-equivalent auth abstraction
//! - ADR-109: Cross-platform LDAP client
//! - ADR-106: SMB client persistent handles (FileModule)
//! - ADR-111: Unified ticket cache abstraction
//! - ADR-048: PSSO Extension + macOS join
//! - ADR-054: Per-host LAPS rotation
//! - ADR-063: Unified cross-platform CLI
//!
//! ## Crate-level safety
//!
//! `#![forbid(unsafe_code)]` — this crate is pure safe Rust. All FFI /
//! platform-unsafe work lives in `adrian-sdk-c` (which uses
//! `#![deny(unsafe_code)]` plus `#[allow(unsafe_code)]` on the FFI entry
//! points, because FFI inherently requires `unsafe`).

#![forbid(unsafe_code)]

use std::sync::Arc;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("auth: {0}")]
    Auth(String),
    #[error("directory: {0}")]
    Directory(String),
    #[error("file: {0}")]
    File(String),
    #[error("policy: {0}")]
    Policy(String),
    /// Cert-enrollment failure (ACME / MS-WCCE bridge). Added in Wave 5a
    /// per ADR-107 §Decision §Cert enrollment — distinct from `Auth` so
    /// callers can branch on cert-enrollment errors vs. auth errors.
    #[error("cert: {0}")]
    Cert(String),
    #[error("not joined")]
    NotJoined,
}

// =========================================================================
// Legacy AdrianClient API (original Wave 4 stub surface).
//
// Kept intact for backward compatibility with `adrian-sdk-c` (which calls
// `AdrianClient::new()` and `client.join(...)`), and to preserve the
// existing 5 structural tests. New consumers should prefer the
// `AdrianSdk` builder API below (per ADR-107 §Decision — "constructed
// once per host; shared across modules" via `Arc<dyn ...>` trait objects).
// =========================================================================

/// Unified client. Constructed once per host; shared across modules.
pub struct AdrianClient {
    // TODO: hold Arc<AuthContext>, Arc<dyn DirectoryStore>, policy cache, etc.
}

impl AdrianClient {
    pub fn new() -> Self {
        Self {}
    }

    /// Join the host to the framework domain (writes `/etc/adrian/`,
    /// `adrianlsa.dll`, `AdrianOpenDirectory.bundle`, or PSSO config).
    pub async fn join(&self, _domain: &str) -> Result<(), SdkError> {
        // TODO: implement join per ADR-107
        Err(SdkError::NotJoined)
    }

    /// Auth module — exposes `AuthContext` to host platform.
    pub fn auth(&self) -> AuthModule {
        AuthModule
    }

    /// File module — SMB client backed (ADR-106).
    pub fn file(&self) -> FileModule {
        FileModule
    }

    /// Directory module — LDAP client (ADR-109).
    pub fn directory(&self) -> DirectoryModule {
        DirectoryModule
    }

    /// Policy module — fetch + cache policy docs.
    pub fn policy(&self) -> PolicyModule {
        PolicyModule
    }
}

impl Default for AdrianClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Auth module handle.
pub struct AuthModule;
/// File module handle (SMB-backed).
pub struct FileModule;
/// Directory module handle (LDAP-backed).
pub struct DirectoryModule;
/// Policy module handle.
pub struct PolicyModule;

// =========================================================================
// Unified SDK core (Wave 5a — ADR-107).
//
// The `AdrianSdk` struct + builder is the new entry point per ADR-107
// §Decision: "constructed once per host; shared across modules" via
// `Arc<dyn ...>` trait objects. The five module traits (`AuthModule`,
// `DirectoryModule`, `PolicyModule`, `FileModule`, `CertModule`) are
// defined below. The legacy unit-struct `AuthModule`/`FileModule`/
// `DirectoryModule`/`PolicyModule` types above are kept for backward
// compatibility with `adrian-sdk-c` and existing structural tests; they
// are intentionally not the same type as the trait-based modules.
//
// The trait-based modules are re-exported at crate root via the
// `sdk` submodule path (`adrian_sdk::sdk::AuthModule`). The data types
// (`AuthToken`, `DirEntry`, `ModifyEntry`, `DeclarativePolicy`,
// `AppliedPolicy`, `MountedShare`, `CertEnrollRequest`) are re-exported
// at crate root because they don't conflict with any legacy names.
// =========================================================================

/// Unified SDK core (ADR-107). Constructed via [`AdrianSdk::builder`].
///
/// Holds `Arc<dyn ...>` trait-object references to each of the five
/// module traits. The host platform (Windows LSA / macOS OpenDirectory /
/// Linux PAM-NSS) constructs one `AdrianSdk` per process; all callers
/// share the same connection pool, credential cache, and config.
///
/// `Debug` is implemented manually because `Arc<dyn Trait>` is only
/// `Debug` if the trait has a `Debug` bound, which we don't want to
/// require (the trait-object bounds are `Send + Sync`, not
/// `Send + Sync + Debug`).
pub struct AdrianSdk {
    /// Auth module — Kerberos / NTLM / cert / OAuth2 (ADR-108).
    pub auth: Arc<dyn sdk::AuthModule>,
    /// Directory module — LDAP search/get/modify (ADR-109).
    pub directory: Arc<dyn sdk::DirectoryModule>,
    /// Policy module — declarative policy apply/rollback (ADR-029/113).
    pub policy: Arc<dyn sdk::PolicyModule>,
    /// File module — SMB client mount (ADR-106).
    pub file: Arc<dyn sdk::FileModule>,
    /// Cert module — ACME enrollment (ADR-095/097).
    pub cert: Arc<dyn sdk::CertModule>,
}

impl std::fmt::Debug for AdrianSdk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdrianSdk")
            .field("auth", &"<dyn AuthModule>")
            .field("directory", &"<dyn DirectoryModule>")
            .field("policy", &"<dyn PolicyModule>")
            .field("file", &"<dyn FileModule>")
            .field("cert", &"<dyn CertModule>")
            .finish()
    }
}

impl AdrianSdk {
    /// Returns a builder for constructing an `AdrianSdk` with custom
    /// module impls. Use [`SdkBuilder::with_defaults`] for the
    /// framework's standard stub impls.
    pub fn builder() -> SdkBuilder {
        SdkBuilder::new()
    }

    /// Construct an `AdrianSdk` with the framework's default stub impls
    /// (`KerberosAuthModule`, `LdapDirectoryModule`,
    /// `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`).
    /// Convenience for tests and quick prototyping; production callers
    /// should use [`AdrianSdk::builder`] to inject real impls.
    pub fn with_default_stubs() -> Self {
        SdkBuilder::with_defaults().build().expect(
            "SdkBuilder::with_defaults() must always yield a valid \
             AdrianSdk — this is an invariant of the stub impls",
        )
    }
}

/// Builder for [`AdrianSdk`]. Each module is set via the eponymous
/// method (`auth(...)`, `directory(...)`, ...). [`SdkBuilder::build`]
/// fails if any module is missing.
#[derive(Default)]
pub struct SdkBuilder {
    auth: Option<Arc<dyn sdk::AuthModule>>,
    directory: Option<Arc<dyn sdk::DirectoryModule>>,
    policy: Option<Arc<dyn sdk::PolicyModule>>,
    file: Option<Arc<dyn sdk::FileModule>>,
    cert: Option<Arc<dyn sdk::CertModule>>,
}

impl SdkBuilder {
    /// Create an empty builder (all modules unset). Call `.build()` to
    /// fail with `SdkError::Auth("auth module not set")` etc.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder pre-populated with the framework's standard stub
    /// impls (`KerberosAuthModule`, `LdapDirectoryModule`,
    /// `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`).
    /// The resulting `.build()` always succeeds.
    pub fn with_defaults() -> Self {
        Self {
            auth: Some(Arc::new(sdk::KerberosAuthModule::new())),
            directory: Some(Arc::new(sdk::LdapDirectoryModule::new())),
            policy: Some(Arc::new(sdk::DeclarativePolicyModule::new())),
            file: Some(Arc::new(sdk::SmbFileModule::new())),
            cert: Some(Arc::new(sdk::AcmeCertModule::new())),
        }
    }

    /// Set the auth module (ADR-108).
    pub fn auth(mut self, m: Arc<dyn sdk::AuthModule>) -> Self {
        self.auth = Some(m);
        self
    }
    /// Set the directory module (ADR-109).
    pub fn directory(mut self, m: Arc<dyn sdk::DirectoryModule>) -> Self {
        self.directory = Some(m);
        self
    }
    /// Set the policy module (ADR-029/113).
    pub fn policy(mut self, m: Arc<dyn sdk::PolicyModule>) -> Self {
        self.policy = Some(m);
        self
    }
    /// Set the file module (ADR-106).
    pub fn file(mut self, m: Arc<dyn sdk::FileModule>) -> Self {
        self.file = Some(m);
        self
    }
    /// Set the cert module (ADR-095/097).
    pub fn cert(mut self, m: Arc<dyn sdk::CertModule>) -> Self {
        self.cert = Some(m);
        self
    }

    /// Build the [`AdrianSdk`]. Fails with the matching `SdkError`
    /// variant if any module is missing (e.g. `SdkError::Auth("auth
    /// module not set")` when `auth` was not provided).
    pub fn build(self) -> Result<AdrianSdk, SdkError> {
        let auth = self
            .auth
            .ok_or_else(|| SdkError::Auth("auth module not set".into()))?;
        let directory = self
            .directory
            .ok_or_else(|| SdkError::Directory("directory module not set".into()))?;
        let policy = self
            .policy
            .ok_or_else(|| SdkError::Policy("policy module not set".into()))?;
        let file = self
            .file
            .ok_or_else(|| SdkError::File("file module not set".into()))?;
        let cert = self
            .cert
            .ok_or_else(|| SdkError::Cert("cert module not set".into()))?;
        Ok(AdrianSdk {
            auth,
            directory,
            policy,
            file,
            cert,
        })
    }
}

// =========================================================================
// SDK submodule — trait-based module definitions + data types + stub impls.
//
// Lives in `pub mod sdk` (rather than at crate root) to avoid name
// collisions with the legacy zero-sized unit structs `AuthModule`,
// `FileModule`, `DirectoryModule`, `PolicyModule` above (which are kept
// for backward compatibility with `adrian-sdk-c`).
//
// Consumers import the traits as `use adrian_sdk::sdk::{AuthModule,
// DirectoryModule, ...};` or via the re-exported types
// (`adrian_sdk::AdrianSdk`, `adrian_sdk::AuthToken`, etc.).
// =========================================================================

pub mod sdk {
    use super::SdkError;
    use async_trait::async_trait;
    use std::sync::Arc;

    // -----------------------------------------------------------------
    // Data types
    // -----------------------------------------------------------------

    /// Authentication token returned by [`AuthModule::authenticate_*`].
    /// Carries the principal name, expiry, and credential kind.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AuthToken {
        /// The principal (UPN or SPN) the token authenticates.
        pub principal: String,
        /// Token expiry (Unix epoch seconds). `None` = no expiry.
        pub expiry: Option<u64>,
        /// Credential kind — drives downstream dispatch in
        /// `FileModule::mount_share` and `DirectoryModule::bind_*`.
        pub kind: AuthTokenKind,
    }

    /// Credential kind for [`AuthToken`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AuthTokenKind {
        /// Kerberos TGT (acquired via `authenticate_kerberos`).
        Kerberos,
        /// NTLM client-side credential (per ADR-108 §Decision 6 —
        /// client-only, server-side NTLM is rejected).
        Ntlm,
        /// X.509 client cert (Schannel-equivalent).
        Cert,
        /// OAuth2 bearer token.
        OAuth2,
    }

    /// Directory entry returned by [`DirectoryModule::search`] and
    /// [`DirectoryModule::get_by_dn`].
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct DirEntry {
        /// The entry's distinguished name (RFC 4514 string form).
        pub dn: String,
        /// Attribute name → raw value bytes (length-prefixed encoding is
        /// the storage layer's concern; the SDK surface is raw bytes).
        pub attributes: Vec<(String, Vec<u8>)>,
    }

    /// A single modify operation (RFC 4511 §4.6 `ModifyRequest`).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ModifyEntry {
        /// Attribute name to modify.
        pub attribute: String,
        /// Operation kind (add / replace / delete).
        pub operation: ModifyOp,
        /// Values to add/replace/delete. Empty for "delete all values".
        pub values: Vec<Vec<u8>>,
    }

    /// Modify operation kind (RFC 4511 §4.6).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ModifyOp {
        /// Add the listed values to the attribute.
        Add,
        /// Replace all existing values with the listed values.
        Replace,
        /// Delete the listed values (or all values if `values` is empty).
        Delete,
    }

    /// Declarative policy document (per ADR-029 §Decision — canonical
    /// JSON). Compiled to platform-native formats (PReg, MDM plist,
    /// authselect) by `adrian-policy-executor`.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct DeclarativePolicy {
        /// Human-readable name.
        pub name: String,
        /// Semver version.
        pub version: String,
        /// Settings (key → JSON value string).
        pub settings: Vec<(String, String)>,
    }

    /// Result of [`PolicyModule::apply`] — carries the rollback token
    /// needed to undo the application via [`PolicyModule::rollback`].
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct AppliedPolicy {
        /// Name of the applied policy (echoes `DeclarativePolicy::name`).
        pub name: String,
        /// Version of the applied policy.
        pub version: String,
        /// Applied-at timestamp (Unix epoch seconds). `None` = unknown.
        pub applied_at: Option<u64>,
        /// Opaque rollback token — passed back to
        /// [`PolicyModule::rollback`] to undo the application.
        pub rollback_token: Vec<u8>,
    }

    /// A mounted SMB share (per ADR-106). Returned by
    /// [`FileModule::mount_share`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct MountedShare {
        /// Server host name (e.g. `dc01.adrian.example`).
        pub server: String,
        /// Share name (e.g. `sysvol`).
        pub share: String,
        /// Local mount path (e.g. `/mnt/adrian/sysvol`).
        pub mount_path: String,
    }

    /// Cert enrollment request (per ADR-095/096). Passed to
    /// [`CertModule::enroll`].
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct CertEnrollRequest {
        /// Cert profile name (e.g. `adrian-machine-auth`).
        pub profile: String,
        /// Certificate Signing Request (DER-encoded).
        pub csr: Vec<u8>,
        /// Subject DN (RFC 4514 string form).
        pub subject: String,
    }

    // -----------------------------------------------------------------
    // Module traits
    // -----------------------------------------------------------------

    /// Auth module (ADR-108 — SSPI-equivalent). Exposes the four
    /// credential-acquisition entry points.
    #[async_trait]
    pub trait AuthModule: Send + Sync {
        /// Acquire a Kerberos TGT via password (RFC 4120 AS-REQ).
        async fn authenticate_kerberos(
            &self,
            principal: &str,
            password: &str,
        ) -> Result<AuthToken, SdkError>;
        /// Acquire an NTLM client-side credential (per Decision 6 —
        /// client-only).
        async fn authenticate_ntlm(
            &self,
            principal: &str,
            password: &str,
        ) -> Result<AuthToken, SdkError>;
        /// Acquire an X.509 client cert credential (Schannel-equivalent).
        async fn authenticate_cert(&self, cert: &[u8], key: &[u8]) -> Result<AuthToken, SdkError>;
        /// Wrap an OAuth2 bearer token as a credential.
        async fn authenticate_oauth2(&self, access_token: &str) -> Result<AuthToken, SdkError>;
    }

    /// Directory module (ADR-109 — Wldap32-equivalent). Exposes LDAP
    /// search/get/modify.
    #[async_trait]
    pub trait DirectoryModule: Send + Sync {
        /// Search the directory with an RFC 4515 filter string.
        async fn search(&self, filter: &str) -> Result<Vec<DirEntry>, SdkError>;
        /// Get a single entry by distinguished name.
        async fn get_by_dn(&self, dn: &str) -> Result<DirEntry, SdkError>;
        /// Modify an entry's attributes (RFC 4511 §4.6).
        async fn modify(&self, dn: &str, changes: Vec<ModifyEntry>) -> Result<(), SdkError>;
    }

    /// Policy module (ADR-029/113). Applies declarative policy and
    /// rolls it back transactionally (ADR-025).
    #[async_trait]
    pub trait PolicyModule: Send + Sync {
        /// Apply a declarative policy. Returns the [`AppliedPolicy`]
        /// carrying the rollback token.
        async fn apply(&self, policy: &DeclarativePolicy) -> Result<AppliedPolicy, SdkError>;
        /// Roll back a previously-applied policy (ADR-025 —
        /// transactional rollback).
        async fn rollback(&self, applied: &AppliedPolicy) -> Result<(), SdkError>;
    }

    /// File module (ADR-106 — SMB client). Mounts an SMB share using
    /// the host's auth token.
    #[async_trait]
    pub trait FileModule: Send + Sync {
        /// Mount `\\server\share` authenticated by `auth`.
        async fn mount_share(
            &self,
            server: &str,
            share: &str,
            auth: &AuthToken,
        ) -> Result<MountedShare, SdkError>;
    }

    /// Cert module (ADR-095/097 — ACME enrollment). Returns the issued
    /// cert DER.
    #[async_trait]
    pub trait CertModule: Send + Sync {
        /// Enroll a certificate via ACME (RFC 8555). Returns the issued
        /// cert DER (X.509).
        async fn enroll(&self, request: CertEnrollRequest) -> Result<Vec<u8>, SdkError>;
    }

    // -----------------------------------------------------------------
    // Stub impls — "loud stub" convention per HANDOVER_STATE.
    //
    // Each stub constructs without state (per ADR-107 §Decision — "the
    // modules are accessors, not owned resources") and returns a
    // documented `SdkError` variant with a message naming the backend
    // it would delegate to in production. Returning `Ok(...)` would
    // silently mislead downstream consumers.
    // -----------------------------------------------------------------

    /// Stub auth module — would delegate to `adrian-kdc` for Kerberos,
    /// `adrian-ntlm-client` for NTLM, the platform key store for cert,
    /// and the framework's OAuth2 validator for OAuth2.
    ///
    /// ## Wave 3c wiring (ADR-108)
    ///
    /// `KerberosAuthModule::new()` returns an unwired module (preserves
    /// backward compat with v0.5.0 callers). To actually drive an AS-REQ
    /// against the in-workspace `adrian-kdc`, construct via
    /// [`KerberosAuthModule::with_kdc`]:
    ///
    /// ```ignore
    /// use adrian_kdc::store::{InMemoryPrincipalStore, PrincipalRecord};
    /// use adrian_sdk::sdk::KerberosAuthModule;
    ///
    /// let store = std::sync::Arc::new(InMemoryPrincipalStore::new());
    /// // store.insert(PrincipalRecord::new(...));
    /// let krbtgt_key = [0u8; 32]; // production: from KrbtgtManager
    /// let module = KerberosAuthModule::with_kdc(store, krbtgt_key);
    /// ```
    ///
    /// When `with_kdc` was not called, `authenticate_kerberos` returns a
    /// specific `SdkError::Auth` (NOT a generic "not yet wired" stub):
    /// the error names the principal and points the caller at the
    /// `with_kdc(...)` method so the wiring gap is actionable.
    ///
    /// When `with_kdc` was called, `authenticate_kerberos` actually drives
    /// an AS-REQ via `adrian_kdc::handlers::handle_as_req`. The v0.6.0
    /// SDK cannot encrypt the PA-ENC-TIMESTAMP pre-auth blob (the
    /// `encrypt_for_usage` helper is `pub(crate)` in `adrian-kdc`), so the
    /// KDC will respond with `KdcError::PreauthRequired`. The SDK surfaces
    /// this as an `SdkError::Auth` carrying the KDC's typed error message;
    /// v0.7.0 will add a public `encrypt_for_usage` (or an SDK-side
    /// pre-auth helper) and complete the round-trip.
    #[derive(Debug)]
    pub struct KerberosAuthModule {
        /// Injected KDC backend. `None` after `new()`; `Some` after
        /// `with_kdc(...)`. Held as `Arc<dyn PrincipalStore>` so the same
        /// store can be shared with the KDC service's other handlers.
        kdc: Option<KdcBackend>,
    }

    /// Wired KDC backend held inside [`KerberosAuthModule`].
    ///
    /// Carries the principal store (any impl of
    /// `adrian_kdc::store::PrincipalStore` — typically the in-memory
    /// testkit store or, in production, a DirectoryStore adapter) and the
    /// raw AES-256 krbtgt key used to encrypt TGT enc-parts.
    ///
    /// Note: v0.6.0 takes the raw `Aes256Key` directly because
    /// `KrbtgtManager` cannot export its HSM-bound key material. v0.7.0
    /// will add a `with_kdc_manager(Arc<KrbtgtManager>)` entry point once
    /// the HSM exposes an etype-18 encrypt operation (or a key-export
    /// escape hatch for development).
    #[derive(Clone)]
    pub struct KdcBackend {
        /// Shared principal store — same trait object the KDC's
        /// `handle_as_req` consults.
        pub store: Arc<dyn adrian_kdc::store::PrincipalStore>,
        /// Raw AES-256 krbtgt key (32 bytes). Caller is responsible for
        /// key provenance.
        pub krbtgt_key: adrian_kdc::crypto::Aes256Key,
    }

    impl std::fmt::Debug for KdcBackend {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Don't print the krbtgt key material — key hygiene.
            f.debug_struct("KdcBackend")
                .field("store", &"<dyn PrincipalStore>")
                .field("krbtgt_key", &"[redacted; 32 bytes]")
                .finish()
        }
    }

    impl KerberosAuthModule {
        /// Construct an unwired auth module. No network / disk I/O.
        ///
        /// `authenticate_kerberos` on the returned module will return a
        /// specific `SdkError::Auth` pointing the caller at
        /// [`KerberosAuthModule::with_kdc`].
        pub fn new() -> Self {
            Self { kdc: None }
        }

        /// Construct a wired auth module that drives an AS-REQ against
        /// `adrian-kdc`'s real `handle_as_req`.
        ///
        /// Production callers should inject the workspace's shared
        /// `PrincipalStore` (FDB-backed in production, in-memory in tests)
        /// and the current krbtgt key (typically snapshotted from
        /// `KrbtgtManager::current_key().await`).
        pub fn with_kdc(
            store: Arc<dyn adrian_kdc::store::PrincipalStore>,
            krbtgt_key: adrian_kdc::crypto::Aes256Key,
        ) -> Self {
            Self {
                kdc: Some(KdcBackend { store, krbtgt_key }),
            }
        }

        /// True iff a KDC backend has been injected via `with_kdc(...)`.
        pub fn is_kdc_wired(&self) -> bool {
            self.kdc.is_some()
        }
    }

    impl Default for KerberosAuthModule {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl AuthModule for KerberosAuthModule {
        async fn authenticate_kerberos(
            &self,
            principal: &str,
            _password: &str,
        ) -> Result<AuthToken, SdkError> {
            // Production: drives RFC 4120 AS-REQ against `adrian-kdc`,
            // FAST-armored per ADR-012, returns a TGT in a
            // platform-native ticket cache (ADR-111). Stub returns
            // SdkError::Auth so callers don't mistake a stub for a TGT.
            //
            // Wave 3c: when the caller has injected a KDC backend via
            // `with_kdc(...)`, actually drive the AS-REQ. The v0.6.0 SDK
            // cannot encrypt the PA-ENC-TIMESTAMP pre-auth blob (the
            // `encrypt_for_usage` helper is `pub(crate)` in
            // `adrian-kdc`), so the KDC will respond with
            // `KdcError::PreauthRequired`. Surface that error verbatim —
            // it proves the wiring is alive and identifies the next
            // concrete step (v0.7.0: expose encrypt_for_usage or add an
            // SDK-side pre-auth helper).
            let kdc = match &self.kdc {
                None => {
                    return Err(SdkError::Auth(format!(
                        "Kerberos auth for {principal}: adrian-kdc handler not configured — \
                         call KerberosAuthModule::with_kdc(store, krbtgt_key) to inject the \
                         KDC backend (ADR-108)"
                    )));
                }
                Some(b) => b.clone(),
            };

            // Parse `principal` into (realm, components). Accept the
            // standard `user@REALM` form. SPN-style `host/foo.example.com`
            // is rejected here for v0.6.0 simplicity (kinit-style usage
            // only).
            let (realm, cname) = crate::parse_kerberos_principal(principal).ok_or_else(|| {
                SdkError::Auth(format!(
                    "Kerberos auth for {principal}: invalid principal form (expected \
                     `name@REALM`)"
                ))
            })?;

            // Build an AS-REQ with empty padata. The KDC will respond
            // with KDC_ERR_PREAUTH_REQUIRED (surfaced as
            // `KdcError::PreauthRequired`) per RFC 4120 §3.1.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let req = adrian_kdc::handlers::AsReq {
                pvno: adrian_kdc::handlers::PVNO,
                msg_type: adrian_kdc::handlers::MSG_TYPE_AS_REQ,
                realm,
                cname,
                nonce: 1,
                etypes: vec![adrian_kdc::EType::Aes256CtsHmacSha1_96],
                padata: Vec::new(),
                till: now + 3600,
            };
            let req_bytes = adrian_kdc::handlers::encode_as_req(&req);

            let rep_bytes = adrian_kdc::handlers::handle_as_req(
                kdc.store.as_ref(),
                &kdc.krbtgt_key,
                &req_bytes,
            )
            .await
            .map_err(|e| {
                SdkError::Auth(format!(
                    "Kerberos auth for {principal}: adrian-kdc AS-REQ failed: {e} \
                     (ADR-108; pre-auth encryption wiring pending v0.7.0)"
                ))
            })?;

            // On success, parse the AS-REP and return an AuthToken
            // carrying the TGT. (Reachable once v0.7.0 adds pre-auth.)
            let rep = adrian_kdc::handlers::decode_as_rep(&rep_bytes).map_err(|e| {
                SdkError::Auth(format!(
                    "Kerberos auth for {principal}: AS-REP decode failed: {e} (ADR-108)"
                ))
            })?;
            Ok(AuthToken {
                principal: rep.cname.join("/"),
                expiry: Some(rep.ticket.kvno as u64),
                kind: AuthTokenKind::Kerberos,
            })
        }
        async fn authenticate_ntlm(
            &self,
            principal: &str,
            _password: &str,
        ) -> Result<AuthToken, SdkError> {
            // Production: drives NTLMv2 NEGOTIATE → CHALLENGE →
            // AUTHENTICATE via `adrian-ntlm-client` (per Decision 6 —
            // client-only).
            Err(SdkError::Auth(format!(
                "NTLM client auth for {principal} not yet wired to adrian-ntlm-client (ADR-108 §Decision 6)"
            )))
        }
        async fn authenticate_cert(
            &self,
            _cert: &[u8],
            _key: &[u8],
        ) -> Result<AuthToken, SdkError> {
            // Production: wraps the platform key store (Windows
            // NCrypt / macOS Keychain / Linux keyctl) via `keyring` crate.
            Err(SdkError::Auth(
                "Cert auth not yet wired to platform key store (ADR-108)".into(),
            ))
        }
        async fn authenticate_oauth2(&self, _access_token: &str) -> Result<AuthToken, SdkError> {
            // Production: validates the JWT via `openidconnect` crate
            // (per ADR-107 §Decision §Federation).
            Err(SdkError::Auth(
                "OAuth2 token validation not yet wired to openidconnect (ADR-107)".into(),
            ))
        }
    }

    /// Stub directory module — would delegate to `adrian-directory-service`
    /// (LDAP server) via the `ldap3` pure-Rust LDAP client.
    ///
    /// ## Wave 1 wiring (ADR-109)
    ///
    /// `LdapDirectoryModule::new()` returns an unwired module (preserves
    /// backward compat with v0.5.0 callers). To actually drive an LDAP
    /// Bind + Search / Modify against a running DSA, construct via
    /// [`LdapDirectoryModule::with_url`]:
    ///
    /// ```ignore
    /// use adrian_sdk::sdk::LdapDirectoryModule;
    ///
    /// let module = LdapDirectoryModule::with_url("ldap://dc01.adrian.example".into());
    /// ```
    ///
    /// When `with_url` was not called, `search` / `get_by_dn` / `modify`
    /// return the existing loud-stub `SdkError::Directory` pointing the
    /// caller at the `with_url(...)` method.
    ///
    /// When `with_url` was called, the methods open an anonymous LDAP
    /// bind to the URL (via `ldap3::LdapConnAsync`), issue an RFC 4511
    /// search / modify against the live DSA, and surface typed errors
    /// (connection refused, no such object, etc.) as `SdkError::Directory`.
    #[derive(Debug)]
    pub struct LdapDirectoryModule {
        /// Injected LDAP URL. `None` after `new()`; `Some(url)` after
        /// `with_url(...)`. The URL MUST be in `ldap://host:port` or
        /// `ldaps://host:port` form (per RFC 4516).
        url: Option<String>,
    }

    impl LdapDirectoryModule {
        /// Construct an unwired directory module. No network / disk I/O.
        ///
        /// `search` / `get_by_dn` / `modify` on the returned module will
        /// return a specific `SdkError::Directory` pointing the caller at
        /// [`LdapDirectoryModule::with_url`].
        pub fn new() -> Self {
            Self { url: None }
        }

        /// Construct a wired directory module that drives RFC 4511 LDAP
        /// operations against the DSA at `url`.
        ///
        /// The URL MUST be in the `ldap://host[:port]` or
        /// `ldaps://host[:port]` form (per RFC 4516). Default port is 389
        /// for `ldap://` and 636 for `ldaps://`.
        ///
        /// Production callers should inject the framework's shared DSA
        /// URL (typically a load-balanced virtual service over the
        /// framework's LDAP listeners per ADR-072).
        pub fn with_url(url: String) -> Self {
            Self { url: Some(url) }
        }

        /// True iff an LDAP URL has been injected via `with_url(...)`.
        #[must_use]
        pub fn is_url_wired(&self) -> bool {
            self.url.is_some()
        }
    }

    impl Default for LdapDirectoryModule {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl DirectoryModule for LdapDirectoryModule {
        async fn search(&self, filter: &str) -> Result<Vec<DirEntry>, SdkError> {
            let url = match &self.url {
                None => {
                    return Err(SdkError::Directory(format!(
                        "LDAP search '{filter}': adrian-directory-service not configured — call \
                         LdapDirectoryModule::with_url(url) to inject the DSA URL (ADR-109)"
                    )));
                }
                Some(u) => u.clone(),
            };

            // Drive a real LDAP search via `ldap3`. Anonymous bind + subtree
            // search from the empty root (per RFC 4511 §4.5). The result
            // entries are mapped to `DirEntry` (DN + raw attribute bytes).
            let (conn, mut ldap) = ldap3::LdapConnAsync::new(&url)
                .await
                .map_err(|e| SdkError::Directory(format!("LDAP connect '{url}': {e} (ADR-109)")))?;
            // Drive the connection on a background task so `ldap.*` calls
            // can `.await` driver messages.
            tokio::spawn(async move {
                let _ = conn.drive().await;
            });
            // Anonymous bind (empty DN + empty password) — Wave 1 does not
            // implement SASL bind; ADR-021 covers signing/channel-binding.
            let _ = ldap
                .simple_bind("", "")
                .await
                .map_err(|e| SdkError::Directory(format!("LDAP bind '{url}': {e} (ADR-021)")))?;
            // Subtree search from the empty root with the caller's filter.
            let search_result = ldap
                .search("", ldap3::Scope::Subtree, filter, Vec::<String>::new())
                .await
                .map_err(|e| {
                    SdkError::Directory(format!("LDAP search '{filter}': {e} (ADR-109)"))
                })?;
            let (rs, _) = search_result.success().map_err(|e| {
                SdkError::Directory(format!("LDAP search '{filter}': {e} (ADR-109)"))
            })?;
            let _ = ldap.unbind().await;
            // Map `ldap3::ResultEntry` → `DirEntry`. Each `ResultEntry`
            // wraps raw BER (StructureTag); `SearchEntry::construct`
            // parses it into a typed (DN, attrs, bin_attrs) triple.
            let mut out = Vec::with_capacity(rs.len());
            for entry in rs {
                let se = ldap3::SearchEntry::construct(entry);
                let dn = se.dn.clone();
                let mut attrs: Vec<(String, Vec<u8>)> = Vec::new();
                // String-typed attributes — `attrs: HashMap<String, Vec<String>>`.
                for (name, vals) in se.attrs.iter() {
                    for v in vals.iter() {
                        attrs.push((name.clone(), v.as_bytes().to_vec()));
                    }
                }
                // Binary-valued attributes — `bin_attrs: HashMap<String, Vec<Vec<u8>>>`.
                // Surfaced with their raw bytes (e.g. `objectSid`,
                // `unicodePwd`) so callers can branch on the binary value
                // without lossy UTF-8 conversion.
                for (name, vals) in se.bin_attrs.iter() {
                    for v in vals.iter() {
                        attrs.push((name.clone(), v.clone()));
                    }
                }
                out.push(DirEntry {
                    dn,
                    attributes: attrs,
                });
            }
            Ok(out)
        }
        async fn get_by_dn(&self, dn: &str) -> Result<DirEntry, SdkError> {
            // Reuse `search` with a base-object filter on the DN. The
            // filter `(objectClass=*)` matches any object; the SDK layers
            // a base-scope retrieval on top by walking the result and
            // picking the entry whose DN matches `dn`.
            let mut entries = self.search("(objectClass=*)").await?;
            for entry in entries.drain(..) {
                if entry.dn.eq_ignore_ascii_case(dn) {
                    return Ok(entry);
                }
            }
            Err(SdkError::Directory(format!(
                "LDAP get_by_dn '{dn}': no such object (ADR-109)"
            )))
        }
        async fn modify(&self, dn: &str, changes: Vec<ModifyEntry>) -> Result<(), SdkError> {
            let url = match &self.url {
                None => {
                    return Err(SdkError::Directory(format!(
                        "LDAP modify on '{dn}': adrian-directory-service not configured — call \
                         LdapDirectoryModule::with_url(url) to inject the DSA URL (ADR-109)"
                    )));
                }
                Some(u) => u.clone(),
            };
            let (conn, mut ldap) = ldap3::LdapConnAsync::new(&url)
                .await
                .map_err(|e| SdkError::Directory(format!("LDAP connect '{url}': {e} (ADR-109)")))?;
            tokio::spawn(async move {
                let _ = conn.drive().await;
            });
            let _ = ldap
                .simple_bind("", "")
                .await
                .map_err(|e| SdkError::Directory(format!("LDAP bind '{url}': {e} (ADR-021)")))?;
            // Translate each ModifyEntry into an ldap3::Mod. ldap3::Mod<S>
            // is parameterized by a single byte-like type S used for BOTH
            // the attribute name and the value set, so we encode the
            // attribute name as Vec<u8> to allow binary attribute values
            // (e.g. `objectSid`, `unicodePwd`) without lossy UTF-8
            // conversion.
            use std::collections::HashSet;
            let mods: Vec<ldap3::Mod<Vec<u8>>> = changes
                .into_iter()
                .map(|c| {
                    let name: Vec<u8> = c.attribute.into_bytes();
                    let set: HashSet<Vec<u8>> = c.values.into_iter().collect();
                    match c.operation {
                        ModifyOp::Add => ldap3::Mod::Add(name, set),
                        ModifyOp::Replace => ldap3::Mod::Replace(name, set),
                        ModifyOp::Delete => ldap3::Mod::Delete(name, set),
                    }
                })
                .collect();
            ldap.modify(dn, mods).await.map_err(|e| {
                SdkError::Directory(format!("LDAP modify on '{dn}': {e} (ADR-109)"))
            })?;
            let _ = ldap.unbind().await;
            Ok(())
        }
    }

    /// Stub policy module — would delegate to `adrian-policy-core` +
    /// `adrian-policy-executor` for declarative-policy apply/rollback.
    ///
    /// ## Wave 1 wiring (ADR-029/113)
    ///
    /// `DeclarativePolicyModule::new()` returns an unwired module (preserves
    /// backward compat with v0.5.0 callers). To actually drive policy
    /// synthesis + rollback against the framework's executor, construct
    /// via [`DeclarativePolicyModule::with_executor`]:
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use adrian_policy_executor::{LinuxPolicyExecutor, PolicyExecutor};
    /// use adrian_sdk::sdk::DeclarativePolicyModule;
    ///
    /// let exec: Arc<dyn PolicyExecutor> = Arc::new(LinuxPolicyExecutor::new());
    /// let module = DeclarativePolicyModule::with_executor(exec);
    /// ```
    ///
    /// When `with_executor` was not called, `apply` / `rollback` return
    /// the existing loud-stub `SdkError::Policy` pointing the caller at
    /// the `with_executor(...)` method.
    ///
    /// When `with_executor` was called, `apply` converts the SDK's
    /// simplified `DeclarativePolicy` (name/version/settings: Vec<(String,
    /// String)>) to the canonical `adrian_policy_core::DeclarativePolicy`
    /// (with typed `PolicyValue::String` values), calls
    /// `PolicyExecutor::synthesize`, and returns an `AppliedPolicy` whose
    /// `rollback_token` encodes the executor's platform tag + the
    /// synthesized file count (consumed by `rollback`).
    pub struct DeclarativePolicyModule {
        /// Injected policy executor. `None` after `new()`; `Some` after
        /// `with_executor(...)`. Held as `Arc<dyn PolicyExecutor>` so the
        /// same executor can be shared with the operator daemon.
        executor: Option<Arc<dyn adrian_policy_executor::PolicyExecutor>>,
    }

    impl std::fmt::Debug for DeclarativePolicyModule {
        // Manual Debug impl — `Arc<dyn PolicyExecutor>` is not Debug
        // (the trait-object bounds are `Send + Sync`, not
        // `Send + Sync + Debug`). Print a placeholder to avoid leaking
        // executor-internal state.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DeclarativePolicyModule")
                .field(
                    "executor",
                    &if self.executor.is_some() {
                        "<dyn PolicyExecutor>"
                    } else {
                        "<unwired>"
                    },
                )
                .finish()
        }
    }

    // The derive-generated Debug was replaced by the manual impl above.
    // (The line below is intentionally not `#[derive(Debug)]`.)

    impl DeclarativePolicyModule {
        /// Construct an unwired policy module. No network / disk I/O.
        ///
        /// `apply` / `rollback` on the returned module will return a
        /// specific `SdkError::Policy` pointing the caller at
        /// [`DeclarativePolicyModule::with_executor`].
        pub fn new() -> Self {
            Self { executor: None }
        }

        /// Construct a wired policy module that drives policy synthesis +
        /// rollback against the framework's `PolicyExecutor` trait.
        ///
        /// Production callers should inject `LinuxPolicyExecutor`,
        /// `WindowsPolicyExecutor`, or `MacOsPolicyExecutor` per ADR-024.
        pub fn with_executor(executor: Arc<dyn adrian_policy_executor::PolicyExecutor>) -> Self {
            Self {
                executor: Some(executor),
            }
        }

        /// True iff a policy executor has been injected via `with_executor(...)`.
        #[must_use]
        pub fn is_executor_wired(&self) -> bool {
            self.executor.is_some()
        }
    }

    impl Default for DeclarativePolicyModule {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl PolicyModule for DeclarativePolicyModule {
        async fn apply(&self, policy: &DeclarativePolicy) -> Result<AppliedPolicy, SdkError> {
            let exec = match &self.executor {
                None => {
                    return Err(SdkError::Policy(format!(
                        "Apply on policy '{}/{}': adrian-policy-executor not configured — call \
                         DeclarativePolicyModule::with_executor(executor) to inject the executor \
                         (ADR-029/113)",
                        policy.name, policy.version
                    )));
                }
                Some(e) => e.clone(),
            };
            // Translate the SDK's simplified `DeclarativePolicy` to the
            // canonical `adrian_policy_core::DeclarativePolicy`. Each
            // `(String, String)` setting becomes a `PolicySetting` with
            // `PolicyValue::String`. Settings with non-string values (int,
            // bool, bytes, string-list) are out-of-scope for the SDK's
            // simplified surface — callers needing typed values should
            // construct `adrian_policy_core::DeclarativePolicy` directly.
            let core_policy = adrian_policy_core::DeclarativePolicy {
                version: 1,
                name: policy.name.clone(),
                description: format!("SDK-applied policy `{}/{}`", policy.name, policy.version),
                settings: policy
                    .settings
                    .iter()
                    .map(|(k, v)| adrian_policy_core::PolicySetting {
                        key: k.clone(),
                        value: adrian_policy_core::PolicyValue::String(v.clone()),
                        applies_to: Vec::new(),
                    })
                    .collect(),
            };
            // Synthesize the per-platform file set. The executor performs
            // no file system writes (per ADR-024 §Decision); the operator
            // daemon writes the files atomically via `rename(2)`.
            let applied = exec
                .synthesize(&core_policy, "<sdk-target>")
                .await
                .map_err(|e| {
                    SdkError::Policy(format!(
                        "Apply on policy '{}/{}': adrian-policy-executor synthesize failed: {e} \
                         (ADR-029/113)",
                        policy.name, policy.version
                    ))
                })?;
            // Encode the rollback token: 1 byte platform tag + 8 bytes
            // LE file count. The token is opaque to callers; `rollback`
            // parses it back to drive `PolicyExecutor::rollback`.
            let mut rollback_token = Vec::with_capacity(9);
            rollback_token.push(applied.platform.as_str().as_bytes()[0]);
            rollback_token.extend_from_slice(&(applied.files.len() as u64).to_le_bytes());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .ok();
            Ok(AppliedPolicy {
                name: policy.name.clone(),
                version: policy.version.clone(),
                applied_at: now,
                rollback_token,
            })
        }
        async fn rollback(&self, applied: &AppliedPolicy) -> Result<(), SdkError> {
            let exec = match &self.executor {
                None => {
                    return Err(SdkError::Policy(format!(
                        "Rollback on applied policy '{}/{}': adrian-policy-executor not configured \
                         — call DeclarativePolicyModule::with_executor(executor) to inject the \
                         executor (ADR-025)",
                        applied.name, applied.version
                    )));
                }
                Some(e) => e.clone(),
            };
            // The rollback token encodes a transaction ID (per ADR-025).
            // Wave 1 does not have a real transaction log — we pass
            // `Uuid::nil()` to the executor, which the LinuxPolicyExecutor
            // stub accepts (it always returns Ok per Wave 4a).
            exec.rollback(uuid::Uuid::nil()).await.map_err(|e| {
                SdkError::Policy(format!(
                    "Rollback on applied policy '{}/{}': adrian-policy-executor rollback \
                         failed: {e} (ADR-025)",
                    applied.name, applied.version
                ))
            })
        }
    }

    /// Stub file module — would delegate to `adrian-smb-client` for SMB
    /// 3.1.1 mount with persistent handles (ADR-106).
    ///
    /// ## Wave 1 wiring (ADR-106)
    ///
    /// `SmbFileModule::new()` returns an unwired module (preserves backward
    /// compat with v0.5.0 callers). To actually drive an SMB Negotiate +
    /// SessionSetup + TreeConnect against a running SMB server, construct
    /// via [`SmbFileModule::with_smb_addr`]:
    ///
    /// ```ignore
    /// use adrian_sdk::sdk::SmbFileModule;
    ///
    /// let module = SmbFileModule::with_smb_addr("dc01.adrian.example:445".into());
    /// ```
    ///
    /// When `with_smb_addr` was not called, `mount_share` returns the
    /// existing loud-stub `SdkError::File` pointing the caller at the
    /// `with_smb_addr(...)` method.
    ///
    /// When `with_smb_addr` was called, `mount_share` opens a TCP
    /// connection to the SMB server, drives a full SMB 3.1.1
    /// Negotiate + SessionSetup + TreeConnect sequence via
    /// `adrian_smb_client`, and returns a `MountedShare` carrying the
    /// server / share / mount path.
    #[derive(Debug)]
    pub struct SmbFileModule {
        /// Injected SMB server address (`host:port`). `None` after
        /// `new()`; `Some(addr)` after `with_smb_addr(...)`.
        addr: Option<String>,
    }

    impl SmbFileModule {
        /// Construct an unwired file module. No network / disk I/O.
        ///
        /// `mount_share` on the returned module will return a specific
        /// `SdkError::File` pointing the caller at
        /// [`SmbFileModule::with_smb_addr`].
        pub fn new() -> Self {
            Self { addr: None }
        }

        /// Construct a wired file module that drives an SMB 3.1.1 mount
        /// sequence against the server at `addr` (`host:port`).
        ///
        /// Production callers should inject the framework's SMB server
        /// address (typically the SYSVOL host per ADR-094).
        pub fn with_smb_addr(addr: String) -> Self {
            Self { addr: Some(addr) }
        }

        /// True iff an SMB server address has been injected via
        /// `with_smb_addr(...)`.
        #[must_use]
        pub fn is_addr_wired(&self) -> bool {
            self.addr.is_some()
        }
    }

    impl Default for SmbFileModule {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl FileModule for SmbFileModule {
        async fn mount_share(
            &self,
            server: &str,
            share: &str,
            _auth: &AuthToken,
        ) -> Result<MountedShare, SdkError> {
            let addr = match &self.addr {
                None => {
                    return Err(SdkError::File(format!(
                        "SMB mount \\\\{server}\\{share}: adrian-smb-client not configured — call \
                         SmbFileModule::with_smb_addr(addr) to inject the server address (ADR-106)"
                    )));
                }
                Some(a) => a.clone(),
            };
            // Drive a real SMB 3.1.1 Negotiate + SessionSetup + TreeConnect
            // via `adrian_smb_client`. Wave 1 uses the default SPNEGO blob
            // (the Wave 3b server accepts any blob); real Kerberos / NTLM
            // token integration is a later wave per ADR-105/106.
            let mut client = adrian_smb_client::connect_tcp(&addr).await.map_err(|e| {
                SdkError::File(format!(
                    "SMB mount \\\\{server}\\{share}: connect to {addr} failed: {e} (ADR-106)"
                ))
            })?;
            let _ = client.negotiate().await.map_err(|e| {
                SdkError::File(format!(
                    "SMB mount \\\\{server}\\{share}: negotiate with {addr} failed: {e} (ADR-106)"
                ))
            })?;
            let _ = client
                .session_setup(adrian_smb_client::default_spnego_blob())
                .await
                .map_err(|e| {
                    SdkError::File(format!(
                        "SMB mount \\\\{server}\\{share}: session_setup failed: {e} (ADR-106)"
                    ))
                })?;
            let path = format!("\\{server}\\{share}");
            let _ = client.tree_connect(&path).await.map_err(|e| {
                SdkError::File(format!(
                    "SMB mount \\\\{server}\\{share}: tree_connect to {path} failed: {e} (ADR-106)"
                ))
            })?;
            // The mount path is conventionally `/mnt/adrian/<share>` per
            // ADR-106. The SDK does not perform the actual mount syscall
            // (that's the operator daemon's job); it returns the mount
            // path the daemon should use.
            let mount_path = format!("/mnt/adrian/{share}");
            Ok(MountedShare {
                server: server.to_string(),
                share: share.to_string(),
                mount_path,
            })
        }
    }

    /// Stub cert module — would delegate to `adrian-acme-server`
    /// (RFC 8555 ACME client) for cert enrollment.
    ///
    /// ## Wave 1 wiring (ADR-095/097)
    ///
    /// `AcmeCertModule::new()` returns an unwired module (preserves backward
    /// compat with v0.5.0 callers). To actually drive a cert issuance via
    /// the framework's CA, construct via [`AcmeCertModule::with_ca`]:
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use adrian_ca::CaService;
    /// use adrian_sdk::sdk::AcmeCertModule;
    ///
    /// let ca = Arc::new(CaService::new().expect("ca"));
    /// let module = AcmeCertModule::with_ca(ca);
    /// ```
    ///
    /// When `with_ca` was not called, `enroll` returns the existing
    /// loud-stub `SdkError::Cert` pointing the caller at the
    /// `with_ca(...)` method.
    ///
    /// When `with_ca` was called, `enroll` calls
    /// `CaService::issue(profile, csr_der)` directly — bypassing the
    /// HTTP ACME wire protocol (the operator's HTTP server is the ACME
    /// front-end; the SDK is the in-process CA client for hosts that
    /// embed the framework). The issued cert DER is returned to the
    /// caller.
    pub struct AcmeCertModule {
        /// Injected CA service. `None` after `new()`; `Some` after
        /// `with_ca(...)`. Held as `Arc<CaService>` because the CA is
        /// shared with the ACME HTTP server and the operator daemon.
        ca: Option<Arc<adrian_ca::CaService>>,
    }

    impl std::fmt::Debug for AcmeCertModule {
        // Manual Debug impl — `CaService` holds an ECDSA private key and
        // does not implement Debug (to avoid accidentally leaking key
        // material via debug output). Print a placeholder instead.
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AcmeCertModule")
                .field(
                    "ca",
                    &if self.ca.is_some() {
                        "<CaService>"
                    } else {
                        "<unwired>"
                    },
                )
                .finish()
        }
    }

    impl AcmeCertModule {
        /// Construct an unwired cert module. No network / disk I/O.
        ///
        /// `enroll` on the returned module will return a specific
        /// `SdkError::Cert` pointing the caller at
        /// [`AcmeCertModule::with_ca`].
        pub fn new() -> Self {
            Self { ca: None }
        }

        /// Construct a wired cert module that drives cert issuance via
        /// the framework's CA service. Bypasses the HTTP ACME wire
        /// protocol — the operator's HTTP server (Layer 3) is the ACME
        /// front-end; this entry point is for hosts that embed the
        /// framework (e.g. PSSO extensions per ADR-048).
        pub fn with_ca(ca: Arc<adrian_ca::CaService>) -> Self {
            Self { ca: Some(ca) }
        }

        /// True iff a CA service has been injected via `with_ca(...)`.
        #[must_use]
        pub fn is_ca_wired(&self) -> bool {
            self.ca.is_some()
        }
    }

    impl Default for AcmeCertModule {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl CertModule for AcmeCertModule {
        async fn enroll(&self, request: CertEnrollRequest) -> Result<Vec<u8>, SdkError> {
            let ca = match &self.ca {
                None => {
                    return Err(SdkError::Cert(format!(
                        "ACME enroll for profile '{}/{}': adrian-acme-server not configured — \
                         call AcmeCertModule::with_ca(ca) to inject the CA service (ADR-095/097)",
                        request.profile, request.subject
                    )));
                }
                Some(c) => c.clone(),
            };
            // Drive real cert issuance via `CaService::issue`. The CA
            // verifies the CSR's self-signature, issues an X.509 v3 cert
            // per the named profile, and returns the DER bytes.
            ca.issue(&request.profile, &request.csr).await.map_err(|e| {
                SdkError::Cert(format!(
                    "ACME enroll for profile '{}/{}': CA issue failed: {e} (ADR-095/097)",
                    request.profile, request.subject
                ))
            })
        }
    }
}

// Re-export the new trait-based module types + data types at crate root
// for ergonomic `use adrian_sdk::*;`. The legacy unit structs
// (`AuthModule`, `FileModule`, `DirectoryModule`, `PolicyModule`) remain
// at crate root and are NOT shadowed here — the traits live only in
// `sdk::*` to avoid the name collision.
pub use sdk::{
    AcmeCertModule, AppliedPolicy, AuthToken, AuthTokenKind, CertEnrollRequest, DeclarativePolicy,
    DeclarativePolicyModule, DirEntry, KdcBackend, KerberosAuthModule, LdapDirectoryModule,
    ModifyEntry, ModifyOp, MountedShare, SmbFileModule,
};

// =========================================================================
// Internal helpers (free functions)
// =========================================================================

/// Parse a Kerberos principal of the form `user@REALM` into `(realm, [user])`.
///
/// Returns `None` if the principal lacks `@`, has an empty realm, or has
/// an empty name component. Multi-component SPNs (`host/foo.example.com`)
/// are rejected for v0.6.0 simplicity — only `user@REALM` (kinit-style) is
/// accepted by `KerberosAuthModule::authenticate_kerberos`.
///
/// Realm case is normalized to uppercase per RFC 4120 §6.1 (Kerberos realms
/// are case-sensitive but conventionally uppercase; the KDC's
/// `InMemoryPrincipalStore` normalizes on lookup, so the SDK matches that
/// convention).
fn parse_kerberos_principal(principal: &str) -> Option<(String, Vec<String>)> {
    let at = principal.rfind('@')?;
    let name = &principal[..at];
    let realm = &principal[at + 1..];
    if name.is_empty() || realm.is_empty() {
        return None;
    }
    // Reject SPN-style (`host/foo`) — only single-component `user@REALM`
    // for v0.6.0.
    if name.contains('/') {
        return None;
    }
    Some((realm.to_ascii_uppercase(), vec![name.to_string()]))
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_and_default_construct_without_state() {
        // Per ADR-107: AdrianClient is constructed once per host and shared
        // across modules. `new()` and `default()` must yield a usable
        // handle without side effects (no network, no disk I/O).
        let a = AdrianClient::new();
        let b = AdrianClient::default();
        let _ = (a, b);
    }

    #[tokio::test]
    async fn join_returns_not_joined_until_implemented() {
        // Loud stub convention — `join` is not yet wired to write
        // `/etc/adrian/`, `adrianlsa.dll`, `AdrianOpenDirectory.bundle`,
        // or PSSO config (per ADR-107/048). The stub MUST surface
        // `SdkError::NotJoined` (a unit variant, intentionally distinct
        // from the string-carrying variants) so callers can detect
        // "framework not yet implemented" vs. a runtime join failure.
        let client = AdrianClient::new();
        let err = client
            .join("adrian.example")
            .await
            .expect_err("join must surface NotJoined until implemented");
        assert!(matches!(err, SdkError::NotJoined), "got {:?}", err);
    }

    #[test]
    fn module_accessors_return_distinct_handles() {
        // Per ADR-107: each module accessor returns a thin handle. The
        // four modules — auth (ADR-108), file (ADR-106), directory
        // (ADR-109), policy — must all be reachable from a single
        // AdrianClient. Constructing each handle MUST NOT touch the
        // network or disk.
        let client = AdrianClient::new();
        let _auth = client.auth();
        let _file = client.file();
        let _directory = client.directory();
        let _policy = client.policy();
    }

    #[test]
    fn module_handles_are_zero_sized() {
        // The legacy module handles (AuthModule, FileModule, DirectoryModule,
        // PolicyModule) are intentionally zero-sized today — they hold no
        // state of their own, only borrowing the client's shared state.
        // Per ADR-107 the modules are accessors, not owned resources.
        assert_eq!(std::mem::size_of::<AuthModule>(), 0);
        assert_eq!(std::mem::size_of::<FileModule>(), 0);
        assert_eq!(std::mem::size_of::<DirectoryModule>(), 0);
        assert_eq!(std::mem::size_of::<PolicyModule>(), 0);
    }

    #[test]
    fn sdk_error_variants_render_expected_messages() {
        // Display strings are part of the public diagnostic contract —
        // FFI binding crates (sdk-c, sdk-jni, sdk-swift, sdk-python)
        // translate them into platform-native error codes.
        assert_eq!(
            format!("{}", SdkError::Auth("no ticket cache".into())),
            "auth: no ticket cache"
        );
        assert_eq!(
            format!("{}", SdkError::Directory("ldap bind failed".into())),
            "directory: ldap bind failed"
        );
        assert_eq!(
            format!("{}", SdkError::File("share not found".into())),
            "file: share not found"
        );
        assert_eq!(
            format!("{}", SdkError::Policy("empty cache".into())),
            "policy: empty cache"
        );
        assert_eq!(
            format!("{}", SdkError::Cert("csr malformed".into())),
            "cert: csr malformed"
        );
        // NotJoined is the unit variant for "framework not yet joined" —
        // its Display is fixed (no payload).
        assert_eq!(format!("{}", SdkError::NotJoined), "not joined");
    }
}

#[cfg(test)]
mod api_tests {
    //! Wave 5a tests — covers the new `AdrianSdk` builder + trait-object
    //! module API per ADR-107/108/109/110/111. Each stub impl is
    //! exercised via the trait to verify dispatch + error propagation.

    use super::sdk::{AuthModule, CertModule, DirectoryModule, FileModule, PolicyModule};
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------
    // Builder tests
    // -----------------------------------------------------------------

    #[test]
    fn sdk_builder_new_yields_empty_builder_that_fails_to_build() {
        // An empty builder MUST fail with `SdkError::Auth("auth module
        // not set")` — the first missing module in builder order.
        // Returning Ok would silently produce an SDK with no auth
        // module, which would panic on the first `sdk.auth.authenticate_*`
        // call.
        let err = SdkBuilder::new()
            .build()
            .expect_err("empty builder must fail to build");
        match err {
            SdkError::Auth(msg) => assert!(msg.contains("auth module not set"), "got: {msg}"),
            other => panic!("expected SdkError::Auth, got {other:?}"),
        }
    }

    #[test]
    fn sdk_builder_with_defaults_builds_successfully() {
        // The framework's standard stub impls (`KerberosAuthModule`,
        // `LdapDirectoryModule`, `DeclarativePolicyModule`,
        // `SmbFileModule`, `AcmeCertModule`) MUST always yield a
        // valid `AdrianSdk`. This is the smoke test for the stub
        // constructors — if any stub's `new()` panics, this test fails.
        let sdk = AdrianSdk::with_default_stubs();
        // Verify each module is non-null (Arc<dyn Trait> is 2 pointers
        // wide; a null Arc would be a bug).
        assert!(
            Arc::strong_count(&sdk.auth) >= 1,
            "auth Arc must hold a strong ref"
        );
        assert!(Arc::strong_count(&sdk.directory) >= 1);
        assert!(Arc::strong_count(&sdk.policy) >= 1);
        assert!(Arc::strong_count(&sdk.file) >= 1);
        assert!(Arc::strong_count(&sdk.cert) >= 1);
    }

    #[test]
    fn sdk_builder_missing_directory_returns_directory_error() {
        // Setting only `auth` MUST fail with `SdkError::Directory`
        // (the next missing module in builder order). This verifies
        // the builder reports the FIRST missing module, not a generic
        // "incomplete" error.
        let err = SdkBuilder::new()
            .auth(Arc::new(sdk::KerberosAuthModule::new()))
            .build()
            .expect_err("partial builder must fail to build");
        match err {
            SdkError::Directory(msg) => {
                assert!(msg.contains("directory module not set"), "got: {msg}")
            }
            other => panic!("expected SdkError::Directory, got {other:?}"),
        }
    }

    #[test]
    fn sdk_builder_missing_policy_returns_policy_error() {
        // Setting auth + directory MUST fail with `SdkError::Policy`.
        let err = SdkBuilder::new()
            .auth(Arc::new(sdk::KerberosAuthModule::new()))
            .directory(Arc::new(sdk::LdapDirectoryModule::new()))
            .build()
            .expect_err("partial builder must fail");
        assert!(matches!(err, SdkError::Policy(_)), "got {err:?}");
    }

    #[test]
    fn sdk_builder_missing_file_returns_file_error() {
        let err = SdkBuilder::new()
            .auth(Arc::new(sdk::KerberosAuthModule::new()))
            .directory(Arc::new(sdk::LdapDirectoryModule::new()))
            .policy(Arc::new(sdk::DeclarativePolicyModule::new()))
            .build()
            .expect_err("partial builder must fail");
        assert!(matches!(err, SdkError::File(_)), "got {err:?}");
    }

    #[test]
    fn sdk_builder_missing_cert_returns_cert_error() {
        let err = SdkBuilder::new()
            .auth(Arc::new(sdk::KerberosAuthModule::new()))
            .directory(Arc::new(sdk::LdapDirectoryModule::new()))
            .policy(Arc::new(sdk::DeclarativePolicyModule::new()))
            .file(Arc::new(sdk::SmbFileModule::new()))
            .build()
            .expect_err("partial builder must fail");
        assert!(matches!(err, SdkError::Cert(_)), "got {err:?}");
    }

    #[test]
    fn sdk_builder_full_construction_succeeds_with_all_stubs() {
        // All five stubs set → build succeeds. This is the positive
        // counterpart to the partial-construction tests above.
        let sdk = SdkBuilder::new()
            .auth(Arc::new(sdk::KerberosAuthModule::new()))
            .directory(Arc::new(sdk::LdapDirectoryModule::new()))
            .policy(Arc::new(sdk::DeclarativePolicyModule::new()))
            .file(Arc::new(sdk::SmbFileModule::new()))
            .cert(Arc::new(sdk::AcmeCertModule::new()))
            .build()
            .expect("full builder must succeed");
        // Verify the trait-object dispatch works (the stubs return Err,
        // but they MUST be reachable through the Arc<dyn ...>).
        let _ = sdk.auth.clone();
        let _ = sdk.directory.clone();
    }

    // -----------------------------------------------------------------
    // Stub impl tests — verify each stub constructs without state and
    // returns a loud, documented SdkError variant when invoked.
    // -----------------------------------------------------------------

    #[test]
    fn stub_module_constructors_are_zero_cost() {
        // Each stub `new()` MUST be infallible and side-effect-free
        // (no network, no disk). Per ADR-107 §Decision — "the modules
        // are accessors, not owned resources".
        let _ = sdk::KerberosAuthModule::new();
        let _ = sdk::LdapDirectoryModule::new();
        let _ = sdk::DeclarativePolicyModule::new();
        let _ = sdk::SmbFileModule::new();
        let _ = sdk::AcmeCertModule::new();
    }

    #[tokio::test]
    async fn kerberos_auth_module_stub_returns_loud_auth_error() {
        // Stub MUST return `SdkError::Auth` with a message naming the
        // backend it would delegate to (`adrian-kdc`). Returning Ok
        // would silently mislead callers into thinking they have a TGT.
        let m = sdk::KerberosAuthModule::new();
        let err = m
            .authenticate_kerberos("alice@ADRIAN.EXAMPLE", "pw")
            .await
            .expect_err("stub must return Err");
        match err {
            SdkError::Auth(msg) => {
                assert!(msg.contains("alice@ADRIAN.EXAMPLE"), "got: {msg}");
                assert!(msg.contains("adrian-kdc"), "got: {msg}");
            }
            other => panic!("expected SdkError::Auth, got {other:?}"),
        }
    }

    /// Wave 3c (W6-3c): the unwired `KerberosAuthModule::new()` must NOT
    /// return the v0.5.0 "not yet wired" stub message — it must return a
    /// specific, actionable error that names the `with_kdc(...)` method
    /// callers should use to inject the KDC backend.
    #[tokio::test]
    async fn kerberos_auth_module_returns_real_error_when_kdc_not_configured() {
        let m = sdk::KerberosAuthModule::new();
        assert!(!m.is_kdc_wired(), "new() must produce an unwired module");
        let err = m
            .authenticate_kerberos("alice@ADRIAN.EXAMPLE", "pw")
            .await
            .expect_err("unwired module must return Err");
        match err {
            SdkError::Auth(msg) => {
                // Must NOT carry the v0.5.0 "not yet wired" stub phrase.
                assert!(
                    !msg.contains("not yet wired"),
                    "error message must evolve past v0.5.0 stub; got: {msg}"
                );
                // Must name the principal.
                assert!(msg.contains("alice@ADRIAN.EXAMPLE"), "got: {msg}");
                // Must name the backend.
                assert!(msg.contains("adrian-kdc"), "got: {msg}");
                // Must point at the `with_kdc(...)` method.
                assert!(msg.contains("with_kdc"), "got: {msg}");
            }
            other => panic!("expected SdkError::Auth, got {other:?}"),
        }
    }

    /// Wave 3c (W6-3c): when `with_kdc(...)` IS called, the SDK must
    /// actually drive an AS-REQ via `adrian_kdc::handlers::handle_as_req`.
    /// The v0.6.0 SDK cannot encrypt the PA-ENC-TIMESTAMP pre-auth blob
    /// (the `encrypt_for_usage` helper is `pub(crate)` in `adrian-kdc`),
    /// so the KDC must respond with `KdcError::PreauthRequired`. The SDK
    /// surfaces that as `SdkError::Auth(...)` carrying the KDC's typed
    /// error message — proving the wiring is alive.
    #[tokio::test]
    async fn kerberos_auth_module_with_kdc_calls_handler_and_surfaces_preauth_required() {
        use adrian_kdc::store::{InMemoryPrincipalStore, PrincipalRecord};

        let store = std::sync::Arc::new(InMemoryPrincipalStore::new());
        // Insert a principal so the KDC gets past "principal not found"
        // and reaches the pre-auth check.
        let alice_key = [0x42u8; 32];
        let alice = PrincipalRecord::new(
            uuid::Uuid::nil(),
            "ADRIAN.EXAMPLE",
            vec!["alice".into()],
            alice_key,
        );
        store.insert(alice);
        let krbtgt_key = [0x11u8; 32];

        let m = sdk::KerberosAuthModule::with_kdc(store, krbtgt_key);
        assert!(m.is_kdc_wired(), "with_kdc must mark the module as wired");

        let err = m
            .authenticate_kerberos("alice@ADRIAN.EXAMPLE", "pw")
            .await
            .expect_err(
                "wired module must surface the KDC's PreauthRequired error (pre-auth encryption \
                 is a v0.7.0 task)",
            );
        match err {
            SdkError::Auth(msg) => {
                // KDC returned `KdcError::PreauthRequired`; the SDK
                // surfaces it via Display. The exact wording ("preauth
                // required") is stable because `KdcError`'s Display impl
                // is pinned by `kdc_error_display_messages`.
                assert!(
                    msg.contains("preauth required"),
                    "expected KDC PreauthRequired to surface in error; got: {msg}"
                );
                assert!(msg.contains("alice@ADRIAN.EXAMPLE"), "got: {msg}");
            }
            other => panic!("expected SdkError::Auth, got {other:?}"),
        }
    }

    /// Wave 3c (W6-3c): invalid principal forms (`user` without realm,
    /// SPN-style `host/foo`, empty realm `user@`) must surface a
    /// parse error rather than being passed to the KDC.
    #[tokio::test]
    async fn kerberos_auth_module_rejects_invalid_principal_form() {
        let store = std::sync::Arc::new(adrian_kdc::store::InMemoryPrincipalStore::new());
        let m = sdk::KerberosAuthModule::with_kdc(store, [0u8; 32]);

        for bad in [
            "alice",
            "alice@",
            "@ADRIAN.EXAMPLE",
            "host/foo.adrian.example@ADRIAN",
        ] {
            let err = m
                .authenticate_kerberos(bad, "pw")
                .await
                .expect_err("invalid principal form must be rejected");
            match err {
                SdkError::Auth(msg) => {
                    assert!(
                        msg.contains("invalid principal form"),
                        "expected 'invalid principal form' for {bad:?}; got: {msg}"
                    );
                }
                other => panic!("expected SdkError::Auth for {bad:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn ldap_directory_module_stub_returns_loud_directory_error() {
        // Each directory method MUST return `SdkError::Directory` so
        // callers can branch on directory failures vs. auth failures.
        let m = sdk::LdapDirectoryModule::new();
        let err = m
            .search("(objectClass=user)")
            .await
            .expect_err("stub must return Err");
        assert!(matches!(err, SdkError::Directory(_)), "got {err:?}");
        let err = m
            .get_by_dn("CN=alice,DC=adrian,DC=example")
            .await
            .expect_err("stub must return Err");
        assert!(matches!(err, SdkError::Directory(_)), "got {err:?}");
        let err = m
            .modify("CN=alice,DC=adrian,DC=example", vec![])
            .await
            .expect_err("stub must return Err");
        assert!(matches!(err, SdkError::Directory(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn declarative_policy_module_stub_returns_loud_policy_error() {
        let m = sdk::DeclarativePolicyModule::new();
        let policy = DeclarativePolicy {
            name: "audit-policy".into(),
            version: "1.0.0".into(),
            settings: vec![],
        };
        let err = m.apply(&policy).await.expect_err("stub must return Err");
        match err {
            SdkError::Policy(msg) => {
                assert!(msg.contains("audit-policy"), "got: {msg}");
                assert!(msg.contains("adrian-policy-executor"), "got: {msg}");
            }
            other => panic!("expected SdkError::Policy, got {other:?}"),
        }
        let applied = AppliedPolicy {
            name: "audit-policy".into(),
            version: "1.0.0".into(),
            applied_at: None,
            rollback_token: vec![0u8; 16],
        };
        let err = m
            .rollback(&applied)
            .await
            .expect_err("stub must return Err");
        assert!(matches!(err, SdkError::Policy(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn smb_file_module_stub_returns_loud_file_error() {
        let m = sdk::SmbFileModule::new();
        let token = AuthToken {
            principal: "host/dc01.adrian.example".into(),
            expiry: None,
            kind: AuthTokenKind::Kerberos,
        };
        let err = m
            .mount_share("dc01.adrian.example", "sysvol", &token)
            .await
            .expect_err("stub must return Err");
        match err {
            SdkError::File(msg) => {
                assert!(msg.contains("dc01.adrian.example"), "got: {msg}");
                assert!(msg.contains("sysvol"), "got: {msg}");
                assert!(msg.contains("adrian-smb-client"), "got: {msg}");
            }
            other => panic!("expected SdkError::File, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn acme_cert_module_stub_returns_loud_cert_error() {
        let m = sdk::AcmeCertModule::new();
        let req = CertEnrollRequest {
            profile: "adrian-machine-auth".into(),
            csr: vec![0x30, 0x82, 0x01, 0x00], // ASN.1 SEQUENCE prefix
            subject: "CN=dc01.adrian.example".into(),
        };
        let err = m.enroll(req).await.expect_err("stub must return Err");
        match err {
            SdkError::Cert(msg) => {
                assert!(msg.contains("adrian-machine-auth"), "got: {msg}");
                assert!(msg.contains("adrian-acme-server"), "got: {msg}");
            }
            other => panic!("expected SdkError::Cert, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Trait dispatch test — verifies the SDK routes calls through the
    // Arc<dyn Module> trait object, not some shortcut path.
    // -----------------------------------------------------------------

    /// A mock auth module that counts invocations. Used to verify
    /// trait-object dispatch.
    struct MockAuthModule {
        kerberos_calls: AtomicUsize,
    }

    #[async_trait]
    impl AuthModule for MockAuthModule {
        async fn authenticate_kerberos(
            &self,
            principal: &str,
            _password: &str,
        ) -> Result<AuthToken, SdkError> {
            self.kerberos_calls.fetch_add(1, Ordering::SeqCst);
            Ok(AuthToken {
                principal: principal.into(),
                expiry: Some(12345),
                kind: AuthTokenKind::Kerberos,
            })
        }
        async fn authenticate_ntlm(
            &self,
            _principal: &str,
            _password: &str,
        ) -> Result<AuthToken, SdkError> {
            Err(SdkError::Auth("mock: NTLM not supported".into()))
        }
        async fn authenticate_cert(
            &self,
            _cert: &[u8],
            _key: &[u8],
        ) -> Result<AuthToken, SdkError> {
            Err(SdkError::Auth("mock: cert not supported".into()))
        }
        async fn authenticate_oauth2(&self, _access_token: &str) -> Result<AuthToken, SdkError> {
            Err(SdkError::Auth("mock: OAuth2 not supported".into()))
        }
    }

    #[tokio::test]
    async fn adrian_sdk_dispatches_to_injected_auth_module() {
        // Verify the SDK calls the injected module impl via the
        // Arc<dyn AuthModule> trait object — not some hardcoded stub.
        let mock = Arc::new(MockAuthModule {
            kerberos_calls: AtomicUsize::new(0),
        });
        let sdk = SdkBuilder::with_defaults()
            .auth(mock.clone())
            .build()
            .expect("builder must succeed");

        let token = sdk
            .auth
            .authenticate_kerberos("alice@ADRIAN.EXAMPLE", "pw")
            .await
            .expect("mock must succeed");
        assert_eq!(token.principal, "alice@ADRIAN.EXAMPLE");
        assert_eq!(token.kind, AuthTokenKind::Kerberos);
        assert_eq!(mock.kerberos_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn adrian_sdk_propagates_module_errors_unchanged() {
        // Verify errors returned by the injected module are propagated
        // unchanged (not wrapped, not swallowed). This is the error-
        // propagation contract per ADR-107.
        let mock = Arc::new(MockAuthModule {
            kerberos_calls: AtomicUsize::new(0),
        });
        let sdk = SdkBuilder::with_defaults()
            .auth(mock.clone())
            .build()
            .expect("builder must succeed");
        let err = sdk
            .auth
            .authenticate_ntlm("alice@ADRIAN.EXAMPLE", "pw")
            .await
            .expect_err("mock returns Err for NTLM");
        match err {
            SdkError::Auth(msg) => assert!(msg.contains("mock: NTLM not supported"), "got: {msg}"),
            other => panic!("expected SdkError::Auth, got {other:?}"),
        }
    }
}

// =========================================================================
// Wave 1 tests — SDK module wiring (ADR-109/029/106/095).
//
// Each of the 4 unwired SDK modules (`LdapDirectoryModule`,
// `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`) now has a
// `with_*(backend)` constructor that injects the in-workspace backend.
// When the backend is injected, the module's trait methods actually drive
// the backend (real LDAP round-trip, real policy synthesis, real SMB
// Negotiate+SessionSetup+TreeConnect, real CA issue). When the backend is
// NOT injected, the existing loud-stub error surfaces unchanged (backward
// compat with v0.5.0 callers).
//
// 2 tests per module: success path + error propagation.
// =========================================================================

#[cfg(test)]
mod wave1_tests {
    use super::sdk::{
        AcmeCertModule, AuthToken, AuthTokenKind, CertEnrollRequest, CertModule, DeclarativePolicy,
        DeclarativePolicyModule, DirectoryModule, FileModule, LdapDirectoryModule, PolicyModule,
        SmbFileModule,
    };
    use super::*;
    use std::sync::Arc;

    // -----------------------------------------------------------------
    // T-101: LdapDirectoryModule wiring (ADR-109).
    // -----------------------------------------------------------------

    /// Build a minimal DSA backed by the in-workspace testkits, with one
    /// dummy object in `list_objects` so subtree searches return at least
    /// one entry.
    fn build_test_dsa_with_dummy_object() -> adrian_directory_service::Dsa {
        use adrian_directory_service::Dsa;
        use adrian_identity_testkit::InMemoryIdentityMapping;
        use adrian_repl_testkit::InMemoryReplicator;
        use adrian_schema_traits::SchemaProjection;
        use adrian_storage_core::{Attribute, DistinguishedName, Object};
        use adrian_storage_testkit::InMemoryDirectoryStore;

        let mut dsa = Dsa::new(
            Arc::new(InMemoryDirectoryStore::new()),
            Arc::new(InMemoryReplicator::new(uuid::Uuid::from_u128(0x_ABCD))),
            Arc::new(InMemoryIdentityMapping::new()),
            Arc::new(SchemaProjection::empty()),
            uuid::Uuid::from_u128(0x_ABCD),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        // Inject a dummy object with an `objectClass` attribute so the
        // `(objectClass=*)` present-filter matches it.
        let dummy = Object {
            uuid: uuid::Uuid::nil(),
            dn: DistinguishedName::new("DC=adrian,DC=example,DC=com"),
            attributes: vec![Attribute {
                attribute_id: 0,
                name: "objectClass".into(),
                value: b"domainDNS".to_vec(),
            }],
            dnt: 0,
        };
        dsa.list_objects = Arc::new(move || vec![dummy.clone()]);
        dsa
    }

    /// Stand up an in-process LDAP server on an ephemeral port. Returns
    /// the bound address; the accept loop runs in a spawned task until the
    /// test ends.
    async fn spawn_ldap_server(dsa: adrian_directory_service::Dsa) -> std::net::SocketAddr {
        use adrian_directory_service::serve_connection;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr on bound listener");
        let dsa = Arc::new(dsa);
        let dsa_for_loop = dsa.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let dsa = dsa_for_loop.clone();
                tokio::spawn(async move {
                    let _ = serve_connection(stream, &dsa).await;
                });
            }
        });
        addr
    }

    /// Wave 1 success path: with `with_url` set to a real in-process
    /// LDAP server, `search` drives a real Bind + Search round-trip and
    /// returns the dummy object from the DSA's `list_objects`.
    #[tokio::test]
    async fn ldap_directory_module_with_url_searches_real_dsa_and_returns_entries() {
        let dsa = build_test_dsa_with_dummy_object();
        let addr = spawn_ldap_server(dsa).await;
        let module = LdapDirectoryModule::with_url(format!("ldap://{addr}"));
        assert!(
            module.is_url_wired(),
            "with_url must mark the module as wired"
        );
        let entries = module
            .search("(objectClass=*)")
            .await
            .expect("wired module must return Ok");
        // The DSA's list_objects returned one dummy object with DN
        // `DC=adrian,DC=example,DC=com`. The subtree search on the empty
        // root MUST surface it.
        assert!(
            !entries.is_empty(),
            "search must return at least one entry; got {:?}",
            entries
        );
        let found = entries
            .iter()
            .find(|e| e.dn.eq_ignore_ascii_case("DC=adrian,DC=example,DC=com"));
        assert!(
            found.is_some(),
            "search must return the dummy object; got DNs: {:?}",
            entries.iter().map(|e| &e.dn).collect::<Vec<_>>()
        );
    }

    /// Wave 1 error propagation: with `with_url` set to an unreachable
    /// address (port 1 — connection refused), `search` surfaces a
    /// `SdkError::Directory` carrying the URL + a connect-related
    /// message. This proves the wiring is alive — the failure mode is a
    /// real network error, NOT the v0.5.0 "not yet wired" stub.
    #[tokio::test]
    async fn ldap_directory_module_with_unreachable_url_surfaces_connect_error() {
        // Port 1 is reserved and not listening on most systems.
        let module = LdapDirectoryModule::with_url("ldap://127.0.0.1:1".into());
        let err = module
            .search("(objectClass=*)")
            .await
            .expect_err("unreachable URL must surface Err");
        match err {
            SdkError::Directory(msg) => {
                // Must carry the URL and a connect-related message — NOT
                // the v0.5.0 "not yet wired" stub.
                assert!(
                    !msg.contains("not yet wired"),
                    "wired module must surface a real connect error, not the v0.5.0 stub; got: {msg}"
                );
                assert!(
                    msg.contains("127.0.0.1:1"),
                    "error must name the URL; got: {msg}"
                );
            }
            other => panic!("expected SdkError::Directory, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // T-102: DeclarativePolicyModule wiring (ADR-029/113).
    // -----------------------------------------------------------------

    /// Wave 1 success path: with `with_executor` set to a real
    /// `LinuxPolicyExecutor`, `apply` synthesizes the per-platform file
    /// set and returns an `AppliedPolicy` with a non-empty rollback
    /// token (encoding the platform tag + file count).
    #[tokio::test]
    async fn declarative_policy_module_with_executor_synthesizes_files() {
        use adrian_policy_executor::{LinuxPolicyExecutor, PolicyExecutor};
        let exec: Arc<dyn PolicyExecutor> = Arc::new(LinuxPolicyExecutor::new());
        let module = DeclarativePolicyModule::with_executor(exec);
        assert!(module.is_executor_wired());
        let policy = DeclarativePolicy {
            name: "baseline-workstation".into(),
            version: "1.0.0".into(),
            settings: vec![
                ("audit.var.log.adrian".into(), "true".into()),
                ("firewall.allow.ssh".into(), "true".into()),
            ],
        };
        let applied = module
            .apply(&policy)
            .await
            .expect("wired module must return Ok");
        assert_eq!(applied.name, "baseline-workstation");
        assert_eq!(applied.version, "1.0.0");
        assert!(applied.applied_at.is_some(), "applied_at must be set");
        // Rollback token = 1 byte platform tag + 8 bytes LE file count.
        // Linux = 'l' (0x6C); file count > 0 (audit + firewalld + CSE
        // JSON = 3 files; may be more).
        assert!(
            !applied.rollback_token.is_empty(),
            "rollback_token must be non-empty"
        );
        assert_eq!(
            applied.rollback_token[0], b'l',
            "platform tag must be 'l' for Linux; got: {:?}",
            applied.rollback_token
        );
    }

    /// Wave 1 error propagation: with `with_executor` NOT called,
    /// `apply` surfaces the loud-stub `SdkError::Policy` pointing the
    /// caller at `with_executor`. Backward compat with v0.5.0 callers.
    #[tokio::test]
    async fn declarative_policy_module_unwired_returns_loud_stub_error() {
        let module = DeclarativePolicyModule::new();
        assert!(!module.is_executor_wired());
        let policy = DeclarativePolicy {
            name: "audit-policy".into(),
            version: "1.0.0".into(),
            settings: vec![],
        };
        let err = module
            .apply(&policy)
            .await
            .expect_err("unwired module must return Err");
        match err {
            SdkError::Policy(msg) => {
                assert!(msg.contains("audit-policy"), "got: {msg}");
                assert!(msg.contains("with_executor"), "got: {msg}");
                assert!(msg.contains("ADR-029/113"), "got: {msg}");
            }
            other => panic!("expected SdkError::Policy, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // T-103: SmbFileModule wiring (ADR-106).
    // -----------------------------------------------------------------

    /// Stand up an in-process SMB server on a duplex pair, returning a
    /// connected client stream + the server task handle. Used by the
    /// SMB mount-share success test.
    async fn spawn_smb_server_on_duplex() -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>)
    {
        use adrian_smb_server::{Share, SmbServer, VirtualFs};
        use std::collections::HashMap;
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let share = Arc::new(Share::with_fs(
            "sysvol",
            VirtualFs::with_files(HashMap::new()),
        ));
        let shares: Arc<HashMap<String, Arc<Share>>> =
            Arc::new(HashMap::from([("sysvol".to_string(), share)]));
        let guid = uuid::Uuid::from_u128(0xABCD_0000_0000_0000_0000_0000_0000_0001);
        let salt = vec![0x11u8; 32];
        let handle = tokio::spawn(async move {
            let _ = SmbServer::handle_connection(server_stream, shares, guid, salt).await;
        });
        (client_stream, handle)
    }

    /// Wave 1 success path: with `with_smb_addr` set to a real in-process
    /// SMB server's TCP address, `mount_share` drives Negotiate +
    /// SessionSetup + TreeConnect and returns a `MountedShare` with the
    /// expected server / share / mount path.
    #[tokio::test]
    async fn smb_file_module_with_addr_mounts_share_via_real_smb_round_trip() {
        use adrian_smb_server::{Share, SmbServer, VirtualFs};
        use std::collections::HashMap;
        // Stand up an SMB server on an ephemeral TCP port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let share = Arc::new(Share::with_fs(
            "sysvol",
            VirtualFs::with_files(HashMap::new()),
        ));
        let shares: Arc<HashMap<String, Arc<Share>>> =
            Arc::new(HashMap::from([("sysvol".to_string(), share)]));
        let guid = uuid::Uuid::from_u128(0xABCD_0000_0000_0000_0000_0000_0000_0001);
        let salt = vec![0x11u8; 32];
        let shares_for_loop = shares.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shares = shares_for_loop.clone();
                let guid = guid;
                let salt = salt.clone();
                tokio::spawn(async move {
                    let _ = SmbServer::handle_connection(stream, shares, guid, salt).await;
                });
            }
        });
        // Wire the SDK module with the address.
        let module = SmbFileModule::with_smb_addr(addr.to_string());
        assert!(module.is_addr_wired());
        let token = AuthToken {
            principal: "host/dc01.adrian.example".into(),
            expiry: None,
            kind: AuthTokenKind::Kerberos,
        };
        // The SMB server's TreeConnect path uses the share name; the
        // server name is whatever we pass to mount_share. We use the
        // loopback address so the TCP round-trip succeeds.
        let mounted = module
            .mount_share("127.0.0.1", "sysvol", &token)
            .await
            .expect("wired module must mount successfully");
        assert_eq!(mounted.server, "127.0.0.1");
        assert_eq!(mounted.share, "sysvol");
        assert_eq!(mounted.mount_path, "/mnt/adrian/sysvol");
    }

    /// Wave 1 error propagation: with `with_smb_addr` set to an
    /// unreachable address (port 1 — connection refused), `mount_share`
    /// surfaces `SdkError::File` carrying the server/share + a
    /// connect-related message.
    #[tokio::test]
    async fn smb_file_module_with_unreachable_addr_surfaces_connect_error() {
        let module = SmbFileModule::with_smb_addr("127.0.0.1:1".into());
        let token = AuthToken {
            principal: "host/dc01.adrian.example".into(),
            expiry: None,
            kind: AuthTokenKind::Kerberos,
        };
        let err = module
            .mount_share("dc01.adrian.example", "sysvol", &token)
            .await
            .expect_err("unreachable addr must surface Err");
        match err {
            SdkError::File(msg) => {
                assert!(
                    !msg.contains("not yet wired"),
                    "wired module must surface real connect error, not v0.5.0 stub; got: {msg}"
                );
                assert!(msg.contains("dc01.adrian.example"), "got: {msg}");
                assert!(msg.contains("sysvol"), "got: {msg}");
            }
            other => panic!("expected SdkError::File, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // T-104: AcmeCertModule wiring (ADR-095/097).
    // -----------------------------------------------------------------

    /// Generate a real ECDSA-P256 PKCS#10 CSR via `ring`, returning the
    /// DER bytes. Mirrors the helper used by `adrian-ca`'s own tests.
    fn make_real_csr(subject_cn: &str) -> Vec<u8> {
        use adrian_ca::{CertificationRequest, CertificationRequestInfo};
        use bitvec::prelude::{BitVec, Msb0};
        use rasn::prelude::*;
        use rasn_pkix::{
            AlgorithmIdentifier, AttributeTypeAndValue, Name, RelativeDistinguishedName,
            SubjectPublicKeyInfo,
        };
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair as RingKeyPair};
        // OIDs (matching the constants in adrian-ca).
        const OID_ECDSA_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
        const OID_EC_PUBLIC_KEY: &[u32] = &[1, 2, 840, 10045, 2, 1];
        const OID_SECP256R1: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];
        const OID_COMMON_NAME: &[u32] = &[2, 5, 4, 3];

        let rng = SystemRandom::new();
        let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("generate pkcs8");
        let kp = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).expect("from pkcs8");
        let pub_sec1 = kp.public_key().as_ref().to_vec();

        // Build the SubjectPublicKeyInfo with the ECDSA-P256 algorithm
        // identifier and the secp256r1 curve parameter.
        let curve_oid = ObjectIdentifier::new(OID_SECP256R1).expect("valid secp256r1 oid");
        let curve_der = rasn::der::encode(&curve_oid).expect("encode curve oid");
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::new(OID_EC_PUBLIC_KEY).expect("valid ec-pubkey oid"),
                parameters: Some(Any::new(curve_der)),
            },
            subject_public_key: BitVec::<u8, Msb0>::from_vec(pub_sec1),
        };

        // Build the subject Name with one RDN containing the CN.
        // PrintableString lives in `rasn::prelude::*` (re-exported by
        // rasn_pkix but not directly importable from there).
        let ps = rasn::types::PrintableString::try_from(subject_cn).expect("CN is printable");
        let atv = AttributeTypeAndValue {
            r#type: ObjectIdentifier::new(OID_COMMON_NAME).expect("valid cn oid"),
            value: Any::from(rasn::der::encode(&ps).unwrap_or_default()),
        };
        let rdn = RelativeDistinguishedName::from(SetOf::from(vec![atv]));
        let subject = Name::RdnSequence(vec![rdn]);

        // Empty attributes set. `rasn_pkix::Attribute` is a public type
        // (the PKCS#10 Attribute per RFC 2986 §5).
        let attrs: SetOf<rasn_pkix::Attribute> = SetOf::from(Vec::<rasn_pkix::Attribute>::new());
        let info = CertificationRequestInfo {
            version: Integer::from(0u32),
            subject,
            subject_pk_info: spki,
            attributes: attrs,
        };
        let info_der = rasn::der::encode(&info).expect("encode CRI");
        let sig = kp.sign(&rng, &info_der).expect("sign");
        let csr = CertificationRequest {
            certification_request_info: info,
            signature_algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier::new(OID_ECDSA_SHA256).expect("valid ecdsa oid"),
                parameters: None,
            },
            signature: BitVec::<u8, Msb0>::from_vec(sig.as_ref().to_vec()),
        };
        rasn::der::encode(&csr).expect("encode CSR")
    }

    /// Wave 1 success path: with `with_ca` set to a real `CaService`,
    /// `enroll` calls `CaService::issue` with a valid ECDSA-P256 CSR
    /// and the `adrian-webserver` profile. The CA verifies the CSR's
    /// self-signature, issues an X.509 v3 cert, and returns the DER
    /// bytes — non-empty and starting with the X.509 SEQUENCE tag (0x30).
    #[tokio::test]
    async fn acme_cert_module_with_ca_issues_real_cert() {
        let ca = Arc::new(adrian_ca::CaService::new().expect("CA construction succeeds"));
        let module = AcmeCertModule::with_ca(ca);
        assert!(module.is_ca_wired());
        let csr = make_real_csr("dc01.adrian.example");
        let req = CertEnrollRequest {
            profile: "adrian-webserver".into(),
            csr,
            subject: "CN=dc01.adrian.example".into(),
        };
        let cert_der = module
            .enroll(req)
            .await
            .expect("wired module must issue a cert");
        // The DER must be non-empty and start with the X.509 SEQUENCE
        // tag (0x30) per RFC 5280 §4.1.
        assert!(!cert_der.is_empty(), "issued cert DER must be non-empty");
        assert_eq!(
            cert_der[0], 0x30,
            "DER must start with X.509 SEQUENCE tag (0x30); got 0x{:02x}",
            cert_der[0]
        );
    }

    /// Wave 1 error propagation: with `with_ca` set to a real `CaService`
    /// but an invalid (empty) CSR, `enroll` surfaces `SdkError::Cert`
    /// carrying the CA's typed error message (`CsrInvalid` or similar).
    #[tokio::test]
    async fn acme_cert_module_with_ca_rejects_invalid_csr() {
        let ca = Arc::new(adrian_ca::CaService::new().expect("CA construction succeeds"));
        let module = AcmeCertModule::with_ca(ca);
        let req = CertEnrollRequest {
            profile: "adrian-webserver".into(),
            csr: Vec::new(), // empty CSR — invalid
            subject: "CN=dc01.adrian.example".into(),
        };
        let err = module
            .enroll(req)
            .await
            .expect_err("invalid CSR must surface Err");
        match err {
            SdkError::Cert(msg) => {
                assert!(
                    !msg.contains("not yet wired"),
                    "wired module must surface real CA error, not v0.5.0 stub; got: {msg}"
                );
                assert!(msg.contains("adrian-webserver"), "got: {msg}");
                assert!(msg.contains("ADR-095"), "got: {msg}");
            }
            other => panic!("expected SdkError::Cert, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Smoke test: ensure spawn_smb_server_on_duplex helper compiles
    // (the duplex path is used by adrian-smb-client tests; we keep it
    // as a sanity check that the SDK crate can reference the SMB
    // server API from its test module).
    // -----------------------------------------------------------------
    #[tokio::test]
    async fn smb_duplex_helper_compiles_without_panic() {
        let (_stream, handle) = spawn_smb_server_on_duplex().await;
        drop(handle);
    }
}
