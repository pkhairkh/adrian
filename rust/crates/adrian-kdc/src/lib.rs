//! # adrian-kdc
//!
//! Fresh Rust Kerberos KDC for the Adrian framework.
//!
//! Implements RFC 4120 + MS-KILE profile with PAC generation, FAST (RFC 6806),
//! PKINIT (RFC 4556), and kpasswd (RFC 3244).
//!
//! ## ADRs
//!
//! - ADR-082: MS-KILE-conformant PAC generation (9 buffer types)
//! - ADR-083: Two-layer PAC validation
//! - ADR-084: PKINIT FIDO2/WebAuthn bridge + RFC 4556 smart-card
//! - ADR-011: AES-256 default; RC4 disabled by default
//! - ADR-012: FAST required; PKINIT armor TGT
//! - ADR-015: HSM-bound krbtgt; 30-day rotation
//! - ADR-018: KDC as stateless pool behind LB
//! - ADR-020: gMSA with HSM-bound KDS root key
//! - ADR-019: kpasswd password-change protocol
//! - ADR-013: Cross-realm TGT referral
//! - ADR-014: AES-SHA384 etype 0x13
//! - ADR-023: Kerberos audit events
//! - ADR-087: S4U2Self / S4U2Proxy constrained delegation

use thiserror::Error;
use uuid::Uuid;

/// Kerberos encryption type (RFC 3961).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EType {
    /// RC4-HMAC (disabled by default, ADR-011).
    Rc4Hmac = 23,
    /// AES-128-CTS-HMAC-SHA1-96.
    Aes128CtsHmacSha1_96 = 17,
    /// AES-256-CTS-HMAC-SHA1-96 (default for new tickets, ADR-011).
    Aes256CtsHmacSha1_96 = 18,
    /// AES-128-CTS-HMAC-SHA256-128 (ADR-014).
    Aes128CtsHmacSha256_128 = 19,
    /// AES-256-CTS-HMAC-SHA384-192 (ADR-014).
    Aes256CtsHmacSha384_192 = 20,
}

#[derive(Debug, Error)]
pub enum KdcError {
    #[error("principal not found: {0}")]
    PrincipalNotFound(String),
    #[error("preauth required")]
    PreauthRequired,
    #[error("preauth failed: {0}")]
    PreauthFailed(String),
    #[error("etype unsupported: {0:?}")]
    ETypeUnsupported(EType),
    #[error("kdc policy: {0}")]
    Policy(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("pac: {0}")]
    Pac(String),
    #[error("fast armor required (ADR-012)")]
    FastArmorRequired,
}

/// KDC service. Stateless pool behind a load balancer (ADR-018); all state
/// lives in the FDB-backed directory store.
pub struct KdcService {
    // TODO: hold Arc<FdbDirectoryStore>, Arc<SchemaProjection>, Signer
}

impl KdcService {
    pub fn new() -> Self {
        Self {}
    }

    /// Handle AS-REQ (RFC 4120 §3.1 / §5.4.1).
    ///
    /// FAST armoring required (ADR-012); PKINIT armor TGT accepted when
    /// `pkinit-*` feature is enabled.
    pub async fn handle_as_req(&self, _req: &[u8]) -> Result<Vec<u8>, KdcError> {
        // TODO: implement AS-REQ/AS-REP per RFC 4120
        Err(KdcError::Storage("not yet implemented".into()))
    }

    /// Handle TGS-REQ (RFC 4120 §3.3 / §5.4.2).
    pub async fn handle_tgs_req(&self, _req: &[u8]) -> Result<Vec<u8>, KdcError> {
        // TODO: implement TGS-REQ/TGS-REP; S4U2Self/S4U2Proxy per ADR-087
        Err(KdcError::Storage("not yet implemented".into()))
    }

    /// Handle kpasswd (RFC 3244) — APP-REQ based password change (ADR-019).
    pub async fn handle_kpasswd(&self, _req: &[u8]) -> Result<Vec<u8>, KdcError> {
        // TODO: implement kpasswd
        Err(KdcError::Storage("not yet implemented".into()))
    }
}

impl Default for KdcService {
    fn default() -> Self {
        Self::new()
    }
}

/// PAC builder — emits all 9 MS-KILE buffer types (ADR-082).
pub struct PacBuilder {
    // TODO: hold krbtgt Signer
}

impl PacBuilder {
    pub fn new() -> Self {
        Self {}
    }

    /// Build a PAC for the given principal, signed with the krbtgt key.
    pub fn build(&self, _principal: Uuid) -> Result<Vec<u8>, KdcError> {
        // TODO: build 9 buffers per ADR-082
        Err(KdcError::Pac("not yet implemented".into()))
    }
}

impl Default for PacBuilder {
    fn default() -> Self {
        Self::new()
    }
}
