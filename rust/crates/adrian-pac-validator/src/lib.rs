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
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_buffer_type_logon_info_value() {
        // KERB_VALIDATION_INFO (buffer type 0x01) per MS-KILE §2.1.
        assert_eq!(PacBufferType::LogonInfo as u32, 0x01);
    }

    #[test]
    fn pac_buffer_type_checksum_values() {
        // Server checksum (0x06) + KDC/privsvr checksum (0x07) per MS-KILE.
        // These are the two layers validated by ADR-083's two-layer
        // validation (KDC + service).
        assert_eq!(PacBufferType::ServerChecksum as u32, 0x06);
        assert_eq!(PacBufferType::PrivsvrChecksum as u32, 0x07);
    }

    #[test]
    fn pac_buffer_type_all_variants_match_ms_kile() {
        // Sanity-check all known buffer type tags against MS-KILE §2.1.
        assert_eq!(PacBufferType::CredentialsType as u32, 0x02);
        assert_eq!(PacBufferType::ClientInfoType as u32, 0x0A);
        assert_eq!(PacBufferType::ConstrainedDelegation as u32, 0x0B);
        assert_eq!(PacBufferType::UpnDns as u32, 0x0C);
        assert_eq!(PacBufferType::ClientClaims as u32, 0x0D);
        assert_eq!(PacBufferType::DeviceInfo as u32, 0x0E);
    }

    #[test]
    fn pac_buffer_type_copy_and_debug() {
        // The enum is Copy + Debug — exercise both so a future derive change
        // (e.g. dropping Copy) is caught by the test.
        let buf = PacBufferType::LogonInfo;
        let copied = buf;
        assert_eq!(buf as u32, copied as u32);
        let dbg = format!("{:?}", buf);
        assert!(dbg.contains("LogonInfo"), "dbg={}", dbg);
    }

    #[test]
    fn pac_validation_error_malformed_display() {
        let err = PacValidationError::Malformed("bad header".into());
        let msg = format!("{}", err);
        assert!(msg.contains("malformed PAC"), "msg={}", msg);
        assert!(msg.contains("bad header"), "msg={}", msg);
    }

    #[test]
    fn pac_validation_error_signature_mismatch_display() {
        let err = PacValidationError::SignatureMismatch("privsvr".into());
        let msg = format!("{}", err);
        assert!(msg.contains("signature mismatch"), "msg={}", msg);
        assert!(msg.contains("privsvr"), "msg={}", msg);
    }

    #[test]
    fn pac_validation_error_expired_display() {
        let err = PacValidationError::Expired;
        let msg = format!("{}", err);
        assert_eq!(msg, "expired PAC");
    }

    #[test]
    fn pac_parse_empty_bytes_returns_malformed() {
        // rasn-backed parser is not yet implemented (per ADR-082); until
        // then, parse() MUST surface Malformed rather than panic or Ok.
        let result = Pac::parse(&[]);
        let err = result.expect_err("parse() should return Malformed");
        assert!(matches!(err, PacValidationError::Malformed(_)), "{:?}", err);
    }

    #[test]
    fn pac_parse_arbitrary_bytes_returns_malformed() {
        // Even non-empty bytes can't be parsed yet — the stub rejects all
        // input with Malformed.
        let bytes = [0u8; 64];
        let result = Pac::parse(&bytes);
        let err = result.expect_err("parse() should return Malformed");
        assert!(matches!(err, PacValidationError::Malformed(_)), "{:?}", err);
    }

    // Note: Pac::validate_kdc_checksum / validate_service_checksum cannot be
    // exercised without a successfully-parsed `Pac`, which requires the rasn
    // parser (TODO per ADR-082). They are validated indirectly via the error
    // paths in the integration test suite once the parser lands.
}
