//! # adrian-ca
//!
//! CA service — certificate issuance, revocation, templates as
//! `cert-profiles.yaml`. HSM-bound keys via `adrian-hsm`.
//!
//! ## ADRs
//!
//! - ADR-037: Two-tier CA with HSM-bound root
//! - ADR-096: cert-profile.yaml replaces AD CS templates
//! - ADR-099: NTAUTHCertificates + PKINIT trust
//! - ADR-036: Trust manager cross-cert interop
//! - ADR-053: Key escrow and NBDE
//! - ADR-067: Sigstore supply chain (cert signing)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("profile not found: {0}")]
    ProfileNotFound(String),
    #[error("csr invalid: {0}")]
    CsrInvalid(String),
    #[error("issuance denied: {0}")]
    IssuanceDenied(String),
    #[error("hsm: {0}")]
    Hsm(String),
    #[error("storage: {0}")]
    Storage(String),
}

/// Certificate profile (canonical YAML, ADR-096).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CertProfile {
    pub name: String,
    pub template_oid: String,
    pub key_usages: Vec<String>,
    pub extended_key_usages: Vec<String>,
    pub validity_days: u32,
    pub subject_name_format: String,
    pub san_templates: Vec<String>,
    pub enrollment_auth: EnrollmentAuth,
}

/// Enrollment authorization mode (replaces AD CS template ACLs).
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub enum EnrollmentAuth {
    Anonymous,
    DomainAuth,
    AgentApproval,
}

/// CA service handle.
pub struct CaService {
    // TODO: hold Arc<FdbDirectoryStore>, Signer, profile registry
}

impl CaService {
    pub fn new() -> Self {
        Self {}
    }

    /// Issue a certificate per the named profile.
    pub async fn issue(&self, _profile: &str, _csr_der: &[u8]) -> Result<Vec<u8>, CaError> {
        // TODO: implement issuance
        Err(CaError::IssuanceDenied("not yet implemented".into()))
    }

    /// Revoke a certificate (CRL/OCSP entry).
    pub async fn revoke(&self, _serial: &[u8], _reason: &str) -> Result<(), CaError> {
        // TODO: implement revocation
        Err(CaError::Storage("not yet implemented".into()))
    }

    /// Load `cert-profiles.yaml` (ADR-096).
    pub async fn load_profiles(&self, _path: &str) -> Result<Vec<CertProfile>, CaError> {
        // TODO: parse YAML
        Err(CaError::ProfileNotFound("not yet implemented".into()))
    }
}

impl Default for CaService {
    fn default() -> Self {
        Self::new()
    }
}
