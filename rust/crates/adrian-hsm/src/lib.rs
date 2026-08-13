//! # adrian-hsm
//!
//! Uniform `Signer` trait over PKCS#11 (via `cryptoki`) and CNG (via `windows`).
//! Gated by the `enterprise-hsm` feature flag; software-key fallback via `ring`.
//!
//! ## ADRs
//!
//! - ADR-037: Two-tier CA with HSM-bound root
//! - ADR-015: krbtgt HSM binding + 30-day rotation
//! - ADR-083: PAC validation with Ed25519 krbtgt public key

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HsmError {
    #[error("pkcs11: {0}")]
    Pkcs11(String),
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("mechanism unsupported: {0}")]
    Unsupported(String),
}

/// Signature algorithm.
#[derive(Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    RsaSha256,
    EcdsaP256Sha256,
    Ed25519,
}

/// Uniform signer abstraction. Two impls in v1: `Pkcs11Signer` (PKCS#11 module)
/// and `SoftwareSigner` (`ring`-backed, default when `enterprise-hsm` is off).
#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, algo: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, HsmError>;
    async fn public_key(&self) -> Result<Vec<u8>, HsmError>;
}

/// Software-key signer (development, small deployments).
pub struct SoftwareSigner {
    // TODO: hold ring::KeyPair
}

#[async_trait]
impl Signer for SoftwareSigner {
    async fn sign(&self, _algo: SignatureAlgorithm, _data: &[u8]) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::Unsupported("not yet implemented".into()))
    }
    async fn public_key(&self) -> Result<Vec<u8>, HsmError> {
        Err(HsmError::Unsupported("not yet implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsm_error_pkcs11_display() {
        let err = HsmError::Pkcs11("slot 0 not found".into());
        let msg = format!("{}", err);
        assert!(msg.contains("pkcs11"), "msg={}", msg);
        assert!(msg.contains("slot 0 not found"), "msg={}", msg);
    }

    #[test]
    fn hsm_error_not_found_display() {
        let err = HsmError::NotFound("krbtgt key".into());
        let msg = format!("{}", err);
        assert!(msg.contains("key not found"), "msg={}", msg);
        assert!(msg.contains("krbtgt"), "msg={}", msg);
    }

    #[test]
    fn hsm_error_unsupported_display() {
        let err = HsmError::Unsupported("RSA-1024".into());
        let msg = format!("{}", err);
        assert!(msg.contains("mechanism unsupported"), "msg={}", msg);
        assert!(msg.contains("RSA-1024"), "msg={}", msg);
    }

    #[test]
    fn signature_algorithm_variants_are_constructible() {
        // Smoke test — all three advertised algorithms must be constructible
        // by name (per ADR-037/ADR-015). The variants are #[derive(Clone,
        // Copy, Debug)] so copying + Debug formatting must work too.
        let algos = [
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::Ed25519,
        ];
        for a in algos {
            let _copy = a; // exercises Copy
            let _dbg = format!("{:?}", a); // exercises Debug
        }
    }

    #[tokio::test]
    async fn software_signer_sign_returns_unsupported() {
        // The software-key signer is a stub until ring integration lands
        // (per ADR-015). sign() MUST surface Unsupported so callers don't
        // mistake an empty signature for success.
        let signer = SoftwareSigner {};
        let result = signer.sign(SignatureAlgorithm::Ed25519, b"data").await;
        let err = result.expect_err("sign() should return Unsupported");
        assert!(matches!(err, HsmError::Unsupported(_)), "{:?}", err);
    }

    #[tokio::test]
    async fn software_signer_public_key_returns_unsupported() {
        let signer = SoftwareSigner {};
        let result = signer.public_key().await;
        let err = result.expect_err("public_key() should return Unsupported");
        assert!(matches!(err, HsmError::Unsupported(_)), "{:?}", err);
    }

    #[test]
    fn signer_trait_is_send_and_sync() {
        // Per Decision 1 §Async runtime, the Signer trait must be usable
        // from async contexts across threads — verify the trait bound
        // `Send + Sync` holds at compile time.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SoftwareSigner>();
        assert_send_sync::<Box<dyn Signer>>();
    }

    // Note: Pkcs11Signer tests that require a real HSM (per ADR-037 /
    // enterprise-hsm feature) are intentionally not exercised here — they
    // would be `#[ignore]`'d behind a real PKCS#11 module and are out of
    // scope for unit tests.
}
