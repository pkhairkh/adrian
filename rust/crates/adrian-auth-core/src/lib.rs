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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper — a canonical AD-style SID (`S-1-5-21-...-1013`) used across
    /// all auth-core tests. Parsed via the `FromStr` impl in `adrian-sid`.
    fn test_sid() -> Sid {
        "S-1-5-21-3623811015-3361044348-30300820-1013"
            .parse()
            .expect("valid SID")
    }

    /// `LogonType` must serialise to its Rust identifier (serde default) and
    /// round-trip — the value is stored on Principal records in FDB and is
    /// echoed back over the SDK FFI, so the JSON shape is part of the
    /// public API (ADR-088).
    #[test]
    fn logon_type_serde_round_trip() {
        for variant in [
            LogonType::Interactive,
            LogonType::Network,
            LogonType::Batch,
            LogonType::Service,
            LogonType::NetworkCleartext,
            LogonType::NewCredentials,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let back: LogonType = serde_json::from_str(&json).expect("deserialize");
            // Debug-compare because LogonType does not derive PartialEq.
            assert_eq!(format!("{variant:?}"), format!("{back:?}"));
        }
    }

    /// `Privilege` derives `Default` — the default carries an empty name and
    /// zero attributes, which is the sentinel used by the privilege-
    /// enumeration code path when a lookup yields no LSA rights entry.
    #[test]
    fn privilege_default_has_zero_attributes() {
        let p = Privilege::default();
        assert_eq!(p.name, "");
        assert_eq!(p.attributes, 0);
    }

    /// `Privilege` must round-trip through JSON — it is embedded in the
    /// serialised Principal token (ADR-088).
    #[test]
    fn privilege_serde_round_trip() {
        let p = Privilege {
            name: "SeTcbPrivilege".into(),
            attributes: 0x00000001, // SE_PRIVILEGE_ENABLED
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let back: Privilege = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name, "SeTcbPrivilege");
        assert_eq!(back.attributes, 0x00000001);
    }

    /// Every `CredentialHandle` variant must construct from its raw fields.
    /// This pins the variant surface so a later wave cannot quietly rename
    /// a field (e.g. `krb5_ccache` → `ccache`) without breaking callers.
    #[test]
    fn credential_handle_variants_construct() {
        let _tgt = CredentialHandle::KerberosTgt {
            krb5_ccache: vec![0x05, 0x04],
        };
        let _ntlm = CredentialHandle::NtlmHash {
            nt_hash: vec![0u8; 16],
        };
        let _cert = CredentialHandle::Certificate { der: vec![0x30] };
        let _oauth = CredentialHandle::OAuth2Token {
            jwt: "eyJhbGciOiJIUzI1NiJ9.e30".into(),
        };
        // The variants must be Clone + Debug for token-cache storage.
        let cloned = _tgt.clone();
        assert!(format!("{cloned:?}").contains("KerberosTgt"));
        assert!(format!("{_ntlm:?}").contains("NtlmHash"));
        assert!(format!("{_cert:?}").contains("Certificate"));
        assert!(format!("{_oauth:?}").contains("OAuth2Token"));
    }

    /// A `Principal` must construct with every field populated — this is
    /// the wire shape returned by `AuthContext::authenticate` /
    /// `whoami`, so any field rename or removal breaks every platform
    /// adapter (Windows LSA, Linux GSSAPI, macOS PSSO) per ADR-108.
    #[test]
    fn principal_construction() {
        let sid = test_sid();
        let primary = sid.clone();
        let principal = Principal {
            uuid: Uuid::nil(),
            sid: sid.clone(),
            upn: "alice@corp.example.com".into(),
            group_sids: vec![sid.clone()],
            primary_group_sid: primary,
            privileges: vec![Privilege {
                name: "SeInteractiveLogonRight".into(),
                attributes: 0,
            }],
            logon_type: LogonType::Interactive,
            logon_time: chrono::Utc::now(),
            logon_server: "\\\\DC01".into(),
            credential_handle: CredentialHandle::KerberosTgt {
                krb5_ccache: vec![],
            },
        };
        assert_eq!(principal.upn, "alice@corp.example.com");
        assert_eq!(principal.group_sids.len(), 1);
        // Principal must be Clone + Debug for SDK FFI marshalling.
        let _cloned = principal.clone();
        assert!(format!("{principal:?}").contains("Principal"));
    }

    /// `AuthError` Display impls are surfaced to the audit log (ADR-023)
    /// and over the SDK FFI as human-readable strings, so the formatting
    /// must be stable across releases.
    #[test]
    fn auth_error_display_messages() {
        assert_eq!(
            AuthError::AuthFailed("bad TGT signature".into()).to_string(),
            "auth failed: bad TGT signature"
        );
        assert_eq!(
            AuthError::CredentialsUnavailable("no krb5 ccache".into()).to_string(),
            "credentials unavailable: no krb5 ccache"
        );
        assert_eq!(
            AuthError::DelegationDenied("no SeTcbPrivilege".into()).to_string(),
            "delegation denied: no SeTcbPrivilege"
        );
        assert_eq!(
            AuthError::PrivilegeNotHeld("SeBackupPrivilege".into()).to_string(),
            "privilege not held: SeBackupPrivilege"
        );
    }

    /// The `AuthContext` trait must be object-safe (ADR-108) — every
    /// platform adapter is stored as a `Box<dyn AuthContext>` behind the
    /// SDK FFI, so a future signature change that breaks object safety
    /// would silently break every binding (C / JNI / Swift / Python).
    #[tokio::test]
    async fn auth_context_trait_is_object_safe() {
        // Minimal stub backend — never actually invoked, but the impl
        // proves that `async_trait` produces a `dyn AuthContext`-compatible
        // vtable. The methods must take `&self`, return `Result`, and be
        // `Send + Sync` (per the trait bound).
        struct StubBackend;
        #[async_trait]
        impl AuthContext for StubBackend {
            async fn authenticate(
                &self,
                _credential: &CredentialHandle,
            ) -> Result<Principal, AuthError> {
                Err(AuthError::AuthFailed("stub".into()))
            }
            async fn whoami(&self) -> Result<Principal, AuthError> {
                Err(AuthError::AuthFailed("stub".into()))
            }
            async fn delegate(
                &self,
                _principal: &Principal,
                _target: &str,
            ) -> Result<CredentialHandle, AuthError> {
                Err(AuthError::DelegationDenied("stub".into()))
            }
            async fn has_privilege(
                &self,
                _principal: &Principal,
                _privilege: &str,
            ) -> Result<bool, AuthError> {
                Ok(false)
            }
        }

        // The crux of object safety: a trait object can be constructed.
        let backend: Box<dyn AuthContext> = Box::new(StubBackend);
        let res = backend
            .has_privilege(
                &Principal {
                    uuid: Uuid::nil(),
                    sid: test_sid(),
                    upn: "stub".into(),
                    group_sids: vec![],
                    primary_group_sid: test_sid(),
                    privileges: vec![],
                    logon_type: LogonType::Network,
                    logon_time: chrono::Utc::now(),
                    logon_server: "\\\\DC01".into(),
                    credential_handle: CredentialHandle::KerberosTgt {
                        krb5_ccache: vec![],
                    },
                },
                "SeTcbPrivilege",
            )
            .await;
        match res {
            Ok(false) => {}
            other => panic!("expected Ok(false), got {other:?}"),
        }
    }
}
