//! # adrian-pac-validator
//!
//! Unified PAC validator (`libframework_pac_validator.dylib`). Consumed by
//! `adrian-kdc`, `adrian-smb-server`, and platform auth backends.
//!
//! **Minimal stub — Wave 4b placeholder.** Will be replaced by the full
//! implementation per ADR-082 / ADR-083.
//!
//! ## ADRs
//!
//! - ADR-082: MS-KILE-conformant PAC generation (9 buffer types)
//! - ADR-083: Two-layer PAC validation (KDC + service)
//! - ADR-123: Silver ticket mitigation (validate on every service accept)
//! - ADR-015: krbtgt HSM binding (Ed25519 signature)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// PAC buffer type tags per MS-KILE §2.1.
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum PacBufferType {
    /// Logon info (KERB_VALIDATION_INFO).
    LogonInfo = 0x01,
    /// Credentials type.
    CredentialsType = 0x02,
    /// Server checksum.
    ServerChecksum = 0x06,
    /// KDC checksum (privsvr).
    PrivsvrChecksum = 0x07,
    /// Client info.
    ClientInfoType = 0x0A,
    /// Constrained delegation.
    ConstrainedDelegation = 0x0B,
    /// UPN + DNS info.
    UpnDns = 0x0C,
    /// Client claims.
    ClientClaims = 0x0D,
    /// Device info.
    DeviceInfo = 0x0E,
}

/// PAC validation error.
#[derive(Debug, Error)]
pub enum PacValidationError {
    /// Malformed PAC bytes.
    #[error("malformed PAC: {0}")]
    Malformed(String),
    /// Signature mismatch.
    #[error("signature mismatch: {0}")]
    SignatureMismatch(String),
    /// Expired PAC.
    #[error("expired PAC")]
    Expired,
}

/// Parsed PAC structure.
pub struct Pac {
    // TODO: hold rasn-decoded buffers per ADR-082.
}

impl Pac {
    /// Parse raw PAC bytes.
    pub fn parse(_bytes: &[u8]) -> Result<Self, PacValidationError> {
        // TODO: implement rasn parse per MS-KILE.
        Err(PacValidationError::Malformed(
            "PAC parsing not yet implemented".into(),
        ))
    }

    /// Validate the KDC (privsvr) checksum — Layer 1 of ADR-083.
    pub fn validate_kdc_checksum(&self, _krbtgt_key: &[u8]) -> Result<(), PacValidationError> {
        Err(PacValidationError::SignatureMismatch(
            "KDC checksum validation not yet implemented".into(),
        ))
    }

    /// Validate the service checksum — Layer 2 of ADR-083.
    pub fn validate_service_checksum(&self, _service_key: &[u8]) -> Result<(), PacValidationError> {
        Err(PacValidationError::SignatureMismatch(
            "service checksum validation not yet implemented".into(),
        ))
    }
}
