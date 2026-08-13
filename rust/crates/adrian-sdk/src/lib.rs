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
    #[error("not joined")]
    NotJoined,
}

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
        // The module handles (AuthModule, FileModule, DirectoryModule,
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
        // NotJoined is the unit variant for "framework not yet joined" —
        // its Display is fixed (no payload).
        assert_eq!(format!("{}", SdkError::NotJoined), "not joined");
    }
}
