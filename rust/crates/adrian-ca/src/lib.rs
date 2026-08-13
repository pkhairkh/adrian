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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-ca`. Per the task instructions these cover
    //! type construction, enum variants, error types, `cert-profiles.yaml`
    //! configuration parsing (via serde round-trip) and the loud-stub
    //! behaviour of `CaService` methods — no real HSM, FDB, or network.

    use super::*;

    /// Build a representative `CertProfile` (mirrors `cert-profiles.yaml`
    /// per ADR-096) used by several of the tests below.
    fn sample_profile() -> CertProfile {
        CertProfile {
            name: "adrian-kdc".into(),
            template_oid: "1.3.6.1.4.1.5991.1.1".into(),
            key_usages: vec!["digitalSignature".into(), "keyEncipherment".into()],
            extended_key_usages: vec!["1.3.6.1.5.2.3.5".into() /* KRB5 KDC */],
            validity_days: 365,
            subject_name_format: "CN={host}.adrian.dev".into(),
            san_templates: vec!["DNS:{host}.adrian.dev".into()],
            enrollment_auth: EnrollmentAuth::DomainAuth,
        }
    }

    #[test]
    fn cert_profile_constructs_with_expected_fields() {
        let p = sample_profile();
        assert_eq!(p.name, "adrian-kdc");
        assert_eq!(p.validity_days, 365);
        assert_eq!(p.key_usages.len(), 2);
        assert_eq!(p.extended_key_usages, vec!["1.3.6.1.5.2.3.5"]);
    }

    #[test]
    fn cert_profile_serde_round_trip_preserves_fields() {
        // `cert-profiles.yaml` is the canonical template format per
        // ADR-096 — exercising the serde round-trip via JSON guards both
        // the derive macros and the field set against silent drift.
        let p = sample_profile();
        let json = serde_json::to_string(&p).expect("serialize");
        let back: CertProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name, p.name);
        assert_eq!(back.template_oid, p.template_oid);
        assert_eq!(back.key_usages, p.key_usages);
        assert_eq!(back.extended_key_usages, p.extended_key_usages);
        assert_eq!(back.validity_days, p.validity_days);
        assert_eq!(back.subject_name_format, p.subject_name_format);
        assert_eq!(back.san_templates, p.san_templates);
    }

    #[test]
    fn enrollment_auth_variants_serialise_as_expected() {
        // The enum is `Copy + serde::Serialize`. We expect each variant
        // to serialise to its PascalCase identifier (no `#[serde(rename)]`
        // is in use yet), which downstream YAML parsers depend on.
        let cases = [
            (EnrollmentAuth::Anonymous, "\"Anonymous\""),
            (EnrollmentAuth::DomainAuth, "\"DomainAuth\""),
            (EnrollmentAuth::AgentApproval, "\"AgentApproval\""),
        ];
        for (variant, expected) in cases {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, expected);
        }
    }

    #[tokio::test]
    async fn ca_service_stubs_surface_typed_errors() {
        // Loud-stub contract: until the FDB store + HSM signer are wired
        // in (ADR-037 / ADR-096 TODO), every `CaService` method must
        // surface a typed `CaError` variant rather than panic. The exact
        // variant is part of the seam contract so downstream callers
        // can match on it today.
        let ca = CaService::new();

        let issue_err = ca.issue("adrian-kdc", &[]).await.unwrap_err();
        assert!(matches!(issue_err, CaError::IssuanceDenied(_)));
        assert!(issue_err.to_string().contains("not yet implemented"));

        let revoke_err = ca.revoke(&[0u8; 16], "keyCompromise").await.unwrap_err();
        assert!(matches!(revoke_err, CaError::Storage(_)));

        let load_err = ca.load_profiles("cert-profiles.yaml").await.unwrap_err();
        assert!(matches!(load_err, CaError::ProfileNotFound(_)));
    }

    #[test]
    fn ca_error_variants_render_messages() {
        // Verify every `#[error("…")]` template renders — catches
        // regressions in the format strings used by logs and HTTP bodies.
        assert_eq!(
            CaError::ProfileNotFound("foo".into()).to_string(),
            "profile not found: foo"
        );
        assert_eq!(
            CaError::CsrInvalid("bad".into()).to_string(),
            "csr invalid: bad"
        );
        assert_eq!(
            CaError::IssuanceDenied("no".into()).to_string(),
            "issuance denied: no"
        );
        assert_eq!(CaError::Hsm("locked".into()).to_string(), "hsm: locked");
        assert_eq!(CaError::Storage("eof".into()).to_string(), "storage: eof");
    }
}
