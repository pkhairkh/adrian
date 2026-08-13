//! # adrian-auth-core
//!
//! Unified authentication context. The `Principal` type carries SID, UPN,
//! group SIDs (recursive `tokenGroups` expansion), privileges, logon type,
//! and a `CredentialHandle` (Kerberos TGT, NTLM hash, X.509 cert, OAuth2 token).
//!
//! Platform adapters (`LsaAuthBackend` Windows, `GssApiAuthBackend` Linux,
//! `PssoHeimdalAuthBackend` macOS) all delegate to the same Rust core.
//!
//! ## ADRs
//!
//! - ADR-088: Unified token abstraction
//! - ADR-108: SSPI-equivalent auth abstraction
//! - ADR-111: Unified ticket cache abstraction (KCM / macOS cache)
//! - ADR-021: LDAP signing & channel binding (auth-protocol coupling)

use adrian_sid::Sid;
use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("auth failed: {0}")]
    AuthFailed(String),
    #[error("credentials unavailable: {0}")]
    CredentialsUnavailable(String),
    #[error("delegation denied: {0}")]
    DelegationDenied(String),
    #[error("privilege not held: {0}")]
    PrivilegeNotHeld(String),
}

/// Windows-style logon type (MS-NLMP / Kerberos PA-LOGON-INFO).
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub enum LogonType {
    Interactive,
    Network,
    Batch,
    Service,
    NetworkCleartext,
    NewCredentials,
}

/// Privilege bitmask (SeAuditPrivilege, SeTcbPrivilege, etc.).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Privilege {
    pub name: String,
    pub attributes: u32,
}

/// Credential handle returned by `authenticate()` / `delegate()`.
#[derive(Clone, Debug)]
pub enum CredentialHandle {
    KerberosTgt { krb5_ccache: Vec<u8> },
    NtlmHash { nt_hash: Vec<u8> },
    Certificate { der: Vec<u8> },
    OAuth2Token { jwt: String },
}

/// Authenticated principal.
#[derive(Clone, Debug)]
pub struct Principal {
    pub uuid: Uuid,
    pub sid: Sid,
    pub upn: String,
    pub group_sids: Vec<Sid>,
    pub primary_group_sid: Sid,
    pub privileges: Vec<Privilege>,
    pub logon_type: LogonType,
    pub logon_time: chrono::DateTime<chrono::Utc>,
    pub logon_server: String,
    pub credential_handle: CredentialHandle,
}

/// Unified authentication context trait.
#[async_trait]
pub trait AuthContext: Send + Sync {
    async fn authenticate(&self, credential: &CredentialHandle) -> Result<Principal, AuthError>;
    async fn whoami(&self) -> Result<Principal, AuthError>;
    async fn delegate(
        &self,
        principal: &Principal,
        target: &str,
    ) -> Result<CredentialHandle, AuthError>;
    async fn has_privilege(
        &self,
        principal: &Principal,
        privilege: &str,
    ) -> Result<bool, AuthError>;
}
