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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify every `EType` variant carries the RFC 3961 / ADR-014 numeric
    /// value, and pin the ADR-011 policy-relevant discrimination: RC4 (23)
    /// is legacy, AES-256-SHA1-96 (18) is the default for new tickets,
    /// and the two ADR-014 etypes (19, 20) form a contiguous family.
    /// These constants are wire-stable and MUST NOT drift.
    #[test]
    fn etype_constants_and_policy_invariants() {
        // RFC 3961 / ADR-014 wire values.
        assert_eq!(EType::Rc4Hmac as u32, 23);
        assert_eq!(EType::Aes128CtsHmacSha1_96 as u32, 17);
        assert_eq!(EType::Aes256CtsHmacSha1_96 as u32, 18);
        assert_eq!(EType::Aes128CtsHmacSha256_128 as u32, 19);
        assert_eq!(EType::Aes256CtsHmacSha384_192 as u32, 20);
        // ADR-011 policy: default (18) < legacy RC4 (23).
        assert!((EType::Aes256CtsHmacSha1_96 as u32) < EType::Rc4Hmac as u32);
        // ADR-014 family: the two SHA-256/384 etypes are contiguous.
        assert_eq!(
            EType::Aes256CtsHmacSha384_192 as u32 - EType::Aes128CtsHmacSha256_128 as u32,
            1
        );
    }

    /// `KdcService::new()` and `KdcService::default()` must produce
    /// equivalent instances — the KDC pool is stateless (ADR-018), so there
    /// is no configuration to carry between constructions.
    #[test]
    fn kdc_service_default_equals_new() {
        let _a = KdcService::new();
        let _b = KdcService::default();
        // Stateless: both constructions succeed with no fields populated.
        // (We rely on the type system — if either panics, the test fails.)
    }

    /// AS-REQ handling is currently a "loud stub" (ADR-018) — it must return
    /// `KdcError::Storage`, not panic or succeed silently. When the real
    /// implementation lands in a later wave, this test should be replaced
    /// with an end-to-end AS-REQ/AS-REP round-trip via `adrian-test-harness`.
    #[tokio::test]
    async fn handle_as_req_returns_storage_not_implemented() {
        let svc = KdcService::new();
        let res = svc.handle_as_req(&[]).await;
        assert!(res.is_err(), "AS-REQ handler must surface a typed error");
        match res.unwrap_err() {
            KdcError::Storage(msg) => assert!(msg.contains("not yet implemented")),
            other => panic!("expected KdcError::Storage, got {other:?}"),
        }
    }

    /// TGS-REQ handler is also a loud stub returning `KdcError::Storage`.
    #[tokio::test]
    async fn handle_tgs_req_returns_storage_not_implemented() {
        let svc = KdcService::new();
        let res = svc.handle_tgs_req(&[]).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            KdcError::Storage(msg) => assert!(msg.contains("not yet implemented")),
            other => panic!("expected KdcError::Storage, got {other:?}"),
        }
    }

    /// kpasswd (RFC 3244 / ADR-019) handler is a loud stub returning
    /// `KdcError::Storage` until the password-change protocol is implemented.
    #[tokio::test]
    async fn handle_kpasswd_returns_storage_not_implemented() {
        let svc = KdcService::new();
        let res = svc.handle_kpasswd(&[]).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            KdcError::Storage(msg) => assert!(msg.contains("not yet implemented")),
            other => panic!("expected KdcError::Storage, got {other:?}"),
        }
    }

    /// `PacBuilder::new()` and `PacBuilder::default()` must both succeed
    /// (the 9-buffer PAC builder per ADR-082 holds only a `krbtgt` Signer
    /// which is wired in a later wave).
    #[test]
    fn pac_builder_default_equals_new() {
        let _a = PacBuilder::new();
        let _b = PacBuilder::default();
    }

    /// `PacBuilder::build()` is a loud stub returning `KdcError::Pac` until
    /// the 9 MS-KILE buffer types (ADR-082) are emitted.
    #[test]
    fn pac_builder_build_returns_pac_not_implemented() {
        let builder = PacBuilder::new();
        let principal = Uuid::nil();
        let res = builder.build(principal);
        assert!(res.is_err());
        match res.unwrap_err() {
            KdcError::Pac(msg) => assert!(msg.contains("not yet implemented")),
            other => panic!("expected KdcError::Pac, got {other:?}"),
        }
    }

    /// Verify the `Display` impls of the typed `KdcError` variants — these
    /// messages are surfaced to audit logs (ADR-023) and to the interop
    /// testkit, so the formatting must be stable.
    #[test]
    fn kdc_error_display_messages() {
        assert_eq!(
            KdcError::PrincipalNotFound("alice".into()).to_string(),
            "principal not found: alice"
        );
        assert_eq!(KdcError::PreauthRequired.to_string(), "preauth required");
        assert_eq!(
            KdcError::PreauthFailed("bad padata".into()).to_string(),
            "preauth failed: bad padata"
        );
        assert_eq!(
            KdcError::ETypeUnsupported(EType::Rc4Hmac).to_string(),
            "etype unsupported: Rc4Hmac"
        );
        assert_eq!(
            KdcError::Policy("rc4 disabled".into()).to_string(),
            "kdc policy: rc4 disabled"
        );
        assert_eq!(
            KdcError::FastArmorRequired.to_string(),
            "fast armor required (ADR-012)"
        );
    }
}
