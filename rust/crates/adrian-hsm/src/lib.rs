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
