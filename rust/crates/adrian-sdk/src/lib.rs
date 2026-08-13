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
