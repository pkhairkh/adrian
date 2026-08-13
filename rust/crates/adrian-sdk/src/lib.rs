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
        async fn authenticate_cert(
            &self,
            cert: &[u8],
            key: &[u8],
        ) -> Result<AuthToken, SdkError>;
        /// Wrap an OAuth2 bearer token as a credential.
        async fn authenticate_oauth2(
            &self,
            access_token: &str,
        ) -> Result<AuthToken, SdkError>;
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
    #[derive(Debug, Default)]
    pub struct KerberosAuthModule;

    impl KerberosAuthModule {
        /// Construct a stub auth module. No network / disk I/O.
        pub fn new() -> Self {
            Self
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
            Err(SdkError::Auth(format!(
                "Kerberos auth for {principal} not yet wired to adrian-kdc (ADR-108)"
            )))
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
        async fn authenticate_oauth2(
            &self,
            _access_token: &str,
        ) -> Result<AuthToken, SdkError> {
            // Production: validates the JWT via `openidconnect` crate
            // (per ADR-107 §Decision §Federation).
            Err(SdkError::Auth(
                "OAuth2 token validation not yet wired to openidconnect (ADR-107)".into(),
            ))
        }
    }

    /// Stub directory module — would delegate to `adrian-directory-service`
    /// (LDAP server) via the `ldap3` pure-Rust LDAP client.
    #[derive(Debug, Default)]
    pub struct LdapDirectoryModule;

    impl LdapDirectoryModule {
        /// Construct a stub directory module. No network / disk I/O.
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl DirectoryModule for LdapDirectoryModule {
        async fn search(&self, filter: &str) -> Result<Vec<DirEntry>, SdkError> {
            Err(SdkError::Directory(format!(
                "LDAP search '{filter}' not yet wired to adrian-directory-service (ADR-109)"
            )))
        }
        async fn get_by_dn(&self, dn: &str) -> Result<DirEntry, SdkError> {
            Err(SdkError::Directory(format!(
                "LDAP get_by_dn '{dn}' not yet wired to adrian-directory-service (ADR-109)"
            )))
        }
        async fn modify(
            &self,
            dn: &str,
            _changes: Vec<ModifyEntry>,
        ) -> Result<(), SdkError> {
            Err(SdkError::Directory(format!(
                "LDAP modify on '{dn}' not yet wired to adrian-directory-service (ADR-109)"
            )))
        }
    }

    /// Stub policy module — would delegate to `adrian-policy-core` +
    /// `adrian-policy-executor` for declarative-policy apply/rollback.
    #[derive(Debug, Default)]
    pub struct DeclarativePolicyModule;

    impl DeclarativePolicyModule {
        /// Construct a stub policy module. No network / disk I/O.
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl PolicyModule for DeclarativePolicyModule {
        async fn apply(&self, policy: &DeclarativePolicy) -> Result<AppliedPolicy, SdkError> {
            Err(SdkError::Policy(format!(
                "Apply on policy '{}/{}' not yet wired to adrian-policy-executor (ADR-029/113)",
                policy.name, policy.version
            )))
        }
        async fn rollback(&self, applied: &AppliedPolicy) -> Result<(), SdkError> {
            Err(SdkError::Policy(format!(
                "Rollback on applied policy '{}/{}' not yet wired to adrian-policy-executor (ADR-025)",
                applied.name, applied.version
            )))
        }
    }

    /// Stub file module — would delegate to `adrian-smb-client` for SMB
    /// 3.1.1 mount with persistent handles (ADR-106).
    #[derive(Debug, Default)]
    pub struct SmbFileModule;

    impl SmbFileModule {
        /// Construct a stub file module. No network / disk I/O.
        pub fn new() -> Self {
            Self
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
            Err(SdkError::File(format!(
                "SMB mount \\\\{server}\\{share} not yet wired to adrian-smb-client (ADR-106)"
            )))
        }
    }

    /// Stub cert module — would delegate to `adrian-acme-server`
    /// (RFC 8555 ACME client) for cert enrollment.
    #[derive(Debug, Default)]
    pub struct AcmeCertModule;

    impl AcmeCertModule {
        /// Construct a stub cert module. No network / disk I/O.
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl CertModule for AcmeCertModule {
        async fn enroll(&self, request: CertEnrollRequest) -> Result<Vec<u8>, SdkError> {
            Err(SdkError::Cert(format!(
                "ACME enroll for profile '{}/{}' not yet wired to adrian-acme-server (ADR-095/097)",
                request.profile, request.subject
            )))
        }
    }
}

// Re-export the new trait-based module types + data types at crate root
// for ergonomic `use adrian_sdk::*;`. The legacy unit structs
// (`AuthModule`, `FileModule`, `DirectoryModule`, `PolicyModule`) remain
// at crate root and are NOT shadowed here — the traits live only in
// `sdk::*` to avoid the name collision.
pub use sdk::{
    AcmeCertModule, AppliedPolicy, AuthToken, AuthTokenKind, CertEnrollRequest,
    DeclarativePolicy, DeclarativePolicyModule, DirEntry, KerberosAuthModule,
    LdapDirectoryModule, ModifyEntry, ModifyOp, MountedShare, SmbFileModule,
};

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

    use super::*;
    use super::sdk::{AuthModule, CertModule, DirectoryModule, FileModule, PolicyModule};
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
            SdkError::Auth(msg) => assert!(
                msg.contains("auth module not set"),
                "got: {msg}"
            ),
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
            SdkError::Directory(msg) => assert!(
                msg.contains("directory module not set"),
                "got: {msg}"
            ),
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
        let err = m
            .apply(&policy)
            .await
            .expect_err("stub must return Err");
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
        let err = m.rollback(&applied).await.expect_err("stub must return Err");
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
        async fn authenticate_oauth2(
            &self,
            _access_token: &str,
        ) -> Result<AuthToken, SdkError> {
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
