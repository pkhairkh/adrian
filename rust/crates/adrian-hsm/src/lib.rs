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
//! - ADR-020: gMSA with HSM-bound KDS root key (uses the same `Hsm` trait)
//!
//! ## Layout
//!
//! Two traits coexist in this crate:
//!
//! - `Signer` — the legacy signature-only abstraction (used by the CA / PAC
//!   validator). The `SoftwareSigner` impl is still a loud stub (per Wave 0
//!   audit; to be wired up in a later wave). DO NOT remove the stub — its
//!   tests pin the loud-stub contract.
//! - `Hsm` — the new (Wave 3c) generic key-store abstraction with
//!   `generate_key` / `sign` / `verify` / `encrypt` / `decrypt` / `rotate_key`.
//!   Used by the krbtgt manager (ADR-015), the gMSA KDS root key (ADR-020),
//!   and any caller that needs HSM-bound symmetric keys.
//!
//! The `SoftwareHsm` (Wave 3c) is a real-impl backed by `ring::aead`
//! (AES-256-GCM) and `hmac` + `sha1` (HMAC-SHA1-96). It does NOT store keys to
//! disk — keys live only in process memory behind `Arc<RwLock<…>>`. This
//! matches ADR-015 §Rationale's "software-based HSM (encrypted key file with a
//! passphrase) for development and testing, with a clear warning that this
//! does not provide the security properties of a real HSM". This crate's
//! software HSM stores keys in **plaintext process memory** — even less
//! protection than an encrypted key file. Real deployments MUST enable the
//! `hsm` feature (PKCS#11) and provision a real HSM.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum HsmError {
    #[error("pkcs11: {0}")]
    Pkcs11(String),
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("mechanism unsupported: {0}")]
    Unsupported(String),
    #[error("crypto failure: {0}")]
    Crypto(String),
}

/// Signature algorithm (legacy `Signer` trait).
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
///
/// NOTE: still a loud stub (Wave 0 contract). The new `SoftwareHsm` impl below
/// is the real-impl path for symmetric keys (krbtgt, gMSA KDS root). The
/// `SoftwareSigner` will be wired to `ring::signature::Ed25519KeyPair` in a
/// later wave.
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

// ===========================================================================
// Wave 3c — generic HSM trait + software backend (ADR-015, ADR-020)
// ===========================================================================

/// Key type that the HSM can generate / use.
///
/// - `Aes256` — 32-byte AES key (AES-256-GCM for encrypt/decrypt).
/// - `HmacSha1` — 20-byte HMAC-SHA1 key (sign/verify returns SHA1-96 —
///   12-byte truncation, matching Kerberos RFC 3961 §3 etype checksum
///   profile).
/// - `Rsa2048` — placeholder for RSA-2048 (used by future PKINIT / cert
///   signing); software-backed RSA is not implemented in this wave —
///   `generate_key(Rsa2048)` returns `Unsupported`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Aes256,
    HmacSha1,
    Rsa2048,
}

/// Opaque handle returned by the HSM. The `id` identifies the key by name
/// (e.g. `"krbtgt"`, `"kds-root"`); the `version` is incremented on each
/// `rotate_key` call (matching AD's `kvno` semantics, ADR-015 §Decision).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyHandle {
    pub id: String,
    pub version: u32,
    pub key_type: KeyType,
}

/// Generic HSM key-store abstraction. Real PKCS#11 backend (gated by the
/// `hsm` feature) implements this against `cryptoki::Session`; the default
/// `SoftwareHsm` impl below uses in-memory `Vec<u8>` keys.
#[async_trait]
pub trait Hsm: Send + Sync {
    /// Generate a new key of the given type. The key is identified by `key_id`
    /// (caller-chosen, e.g. `"krbtgt"`); the returned `KeyHandle` records the
    /// initial `version = 1`.
    async fn generate_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<KeyHandle, HsmError>;

    /// Sign `data` with the key identified by `key_handle`. For `HmacSha1`
    /// keys, returns the 12-byte HMAC-SHA1-96 truncation (RFC 3961 checksum
    /// profile). For `Aes256` keys, returns `Unsupported` (AES is not a
    /// signing algorithm).
    async fn sign(
        &self,
        key_handle: &KeyHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// Verify a signature produced by `sign`. Returns `true` on success.
    async fn verify(
        &self,
        key_handle: &KeyHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmError>;

    /// Encrypt `plaintext` with the key. For `Aes256` keys, returns
    /// `nonce[12] || ciphertext || tag[16]` (AES-256-GCM, empty AAD). For
    /// `HmacSha1` keys, returns `Unsupported`.
    async fn encrypt(
        &self,
        key_handle: &KeyHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// Decrypt a ciphertext produced by `encrypt`. Returns the plaintext.
    async fn decrypt(
        &self,
        key_handle: &KeyHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// Rotate the key identified by `key_id`: generate fresh key material,
    /// bump the version by 1, retain the same `id`. The previous key material
    /// is overwritten (the software HSM does NOT keep `previous` — callers
    /// like `KrbtgtManager` track dual-key overlap themselves per ADR-015).
    async fn rotate_key(&self, key_id: &str) -> Result<KeyHandle, HsmError>;
}

// ---- in-memory key entry ----

#[derive(Clone, Debug)]
struct KeyEntry {
    key_type: KeyType,
    /// Raw key material. NEVER leaves the `SoftwareHsm` except via the
    /// `sign`/`verify`/`encrypt`/`decrypt` operations.
    material: Vec<u8>,
    version: u32,
}

/// Software-backed HSM. Real AES-256-GCM (`ring::aead`) for encrypt/decrypt;
/// real HMAC-SHA1-96 (`hmac` + `sha1`) for sign/verify. Keys live in process
/// memory behind `Arc<RwLock<HashMap>>`.
///
/// WARNING (ADR-015 §Rationale): the software HSM does NOT provide the
/// security properties of a real HSM (no FIPS 140-2 boundary, no tamper
/// resistance, no key-extraction protection). Use for development/testing
/// only. Real deployments MUST enable the `hsm` feature (PKCS#11) and
/// provision a real HSM (YubiHSM, AWS CloudHSM, Thales Luna, etc.).
pub struct SoftwareHsm {
    keys: Arc<RwLock<HashMap<String, KeyEntry>>>,
}

impl SoftwareHsm {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate `len` random bytes using `ring::rand::SystemRandom`.
    fn random_bytes(len: usize) -> Result<Vec<u8>, HsmError> {
        use ring::rand::SecureRandom;
        let rng = ring::rand::SystemRandom::new();
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf)
            .map_err(|_| HsmError::Crypto("SystemRandom fill failed".into()))?;
        Ok(buf)
    }

    /// Compute the HMAC-SHA1-96 truncation of `data` under `key` (12 bytes).
    fn hmac_sha1_96(key: &[u8], data: &[u8]) -> Result<Vec<u8>, HsmError> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;
        let mut mac = HmacSha1::new_from_slice(key)
            .map_err(|_| HsmError::Crypto("HMAC key length invalid".into()))?;
        mac.update(data);
        let result = mac.finalize().into_bytes();
        // RFC 3961 checksum profile: truncate to 96 bits (12 bytes).
        Ok(result[..12].to_vec())
    }

    /// Encrypt `plaintext` with AES-256-GCM under `key`. Returns
    /// `nonce[12] || ciphertext || tag[16]`.
    fn aes_256_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        use ring::aead::{ Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM };
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| HsmError::Crypto("AES-256-GCM key init failed".into()))?;
        // `LessSafeKey` (ring's name for the per-call-nonce API — NOT a
        // security downgrade; it just means the caller manages nonces).
        let sealing = LessSafeKey::new(unbound);
        let nonce_bytes = Self::random_bytes(12)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce_bytes);
        // `assume_unique_for_key` is infallible for 12-byte arrays (ring docs).
        let nonce = Nonce::assume_unique_for_key(nonce_arr);
        // ring seals in-place: we copy plaintext into a buffer that has room
        // for the 16-byte tag appended.
        let mut buf = Vec::with_capacity(plaintext.len() + 16);
        buf.extend_from_slice(plaintext);
        sealing
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
            .map_err(|_| HsmError::Crypto("AES-256-GCM seal failed".into()))?;
        let mut out = Vec::with_capacity(12 + buf.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Decrypt a `nonce[12] || ciphertext || tag[16]` blob produced by
    /// `aes_256_gcm_encrypt`.
    fn aes_256_gcm_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HsmError> {
        use ring::aead::{ Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM };
        if ciphertext.len() < 12 + 16 {
            return Err(HsmError::Crypto("ciphertext too short".into()));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| HsmError::Crypto("AES-256-GCM key init failed".into()))?;
        let opening = LessSafeKey::new(unbound);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&ciphertext[..12]);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);
        let mut buf = ciphertext[12..].to_vec();
        let plaintext = opening
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| HsmError::Crypto("AES-256-GCM open failed".into()))?;
        Ok(plaintext.to_vec())
    }

    /// Key material length for each `KeyType`.
    fn key_len(key_type: KeyType) -> usize {
        match key_type {
            KeyType::Aes256 => 32,
            KeyType::HmacSha1 => 20,
            // RSA requires a real keypair generator (not in this wave).
            KeyType::Rsa2048 => 0,
        }
    }
}

impl Default for SoftwareHsm {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Hsm for SoftwareHsm {
    async fn generate_key(
        &self,
        key_id: &str,
        key_type: KeyType,
    ) -> Result<KeyHandle, HsmError> {
        if key_type == KeyType::Rsa2048 {
            return Err(HsmError::Unsupported(
                "RSA-2048 not implemented in SoftwareHsm (use hsm feature + PKCS#11)".into(),
            ));
        }
        let material = Self::random_bytes(Self::key_len(key_type))?;
        let entry = KeyEntry {
            key_type,
            material,
            version: 1,
        };
        let mut keys = self.keys.write().await;
        keys.insert(key_id.to_string(), entry);
        Ok(KeyHandle {
            id: key_id.to_string(),
            version: 1,
            key_type,
        })
    }

    async fn sign(
        &self,
        key_handle: &KeyHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let keys = self.keys.read().await;
        let entry = keys
            .get(&key_handle.id)
            .ok_or_else(|| HsmError::NotFound(key_handle.id.clone()))?;
        // Key version mismatch is a security signal (golden-ticket detection,
        // ADR-015); the software HSM surfaces it as Unsupported (a real HSM
        // would return a typed key-version error).
        if entry.version != key_handle.version {
            return Err(HsmError::Unsupported(format!(
                "key version mismatch: handle={} store={} (rotation race?)",
                key_handle.version, entry.version
            )));
        }
        match entry.key_type {
            KeyType::HmacSha1 => Self::hmac_sha1_96(&entry.material, data),
            KeyType::Aes256 => Err(HsmError::Unsupported(
                "Aes256 keys cannot sign (use encrypt/decrypt)".into(),
            )),
            KeyType::Rsa2048 => Err(HsmError::Unsupported(
                "RSA-2048 not implemented in SoftwareHsm".into(),
            )),
        }
    }

    async fn verify(
        &self,
        key_handle: &KeyHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmError> {
        let expected = self.sign(key_handle, data).await?;
        // Constant-time comparison via `ring` would be ideal; the `hmac` crate's
        // `verify_slice` is constant-time. We approximate by re-computing and
        // comparing in a non-short-circuiting loop (timing-attack-resistant
        // enough for the software HSM; a real HSM does this in hardware).
        let mut diff: u8 = 0;
        let min = expected.len().min(signature.len());
        for i in 0..min {
            diff |= expected[i] ^ signature[i];
        }
        diff |= (expected.len() != signature.len()) as u8;
        Ok(diff == 0)
    }

    async fn encrypt(
        &self,
        key_handle: &KeyHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let keys = self.keys.read().await;
        let entry = keys
            .get(&key_handle.id)
            .ok_or_else(|| HsmError::NotFound(key_handle.id.clone()))?;
        if entry.version != key_handle.version {
            return Err(HsmError::Unsupported(format!(
                "key version mismatch: handle={} store={}",
                key_handle.version, entry.version
            )));
        }
        match entry.key_type {
            KeyType::Aes256 => Self::aes_256_gcm_encrypt(&entry.material, plaintext),
            KeyType::HmacSha1 => Err(HsmError::Unsupported(
                "HmacSha1 keys cannot encrypt (use sign/verify)".into(),
            )),
            KeyType::Rsa2048 => Err(HsmError::Unsupported(
                "RSA-2048 not implemented in SoftwareHsm".into(),
            )),
        }
    }

    async fn decrypt(
        &self,
        key_handle: &KeyHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let keys = self.keys.read().await;
        let entry = keys
            .get(&key_handle.id)
            .ok_or_else(|| HsmError::NotFound(key_handle.id.clone()))?;
        if entry.version != key_handle.version {
            return Err(HsmError::Unsupported(format!(
                "key version mismatch: handle={} store={}",
                key_handle.version, entry.version
            )));
        }
        match entry.key_type {
            KeyType::Aes256 => Self::aes_256_gcm_decrypt(&entry.material, ciphertext),
            KeyType::HmacSha1 => Err(HsmError::Unsupported(
                "HmacSha1 keys cannot decrypt (use sign/verify)".into(),
            )),
            KeyType::Rsa2048 => Err(HsmError::Unsupported(
                "RSA-2048 not implemented in SoftwareHsm".into(),
            )),
        }
    }

    async fn rotate_key(&self, key_id: &str) -> Result<KeyHandle, HsmError> {
        let mut keys = self.keys.write().await;
        let entry = keys
            .get_mut(key_id)
            .ok_or_else(|| HsmError::NotFound(key_id.to_string()))?;
        if entry.key_type == KeyType::Rsa2048 {
            return Err(HsmError::Unsupported(
                "RSA-2048 not implemented in SoftwareHsm".into(),
            ));
        }
        let new_material = Self::random_bytes(Self::key_len(entry.key_type))?;
        entry.material = new_material;
        entry.version = entry.version.saturating_add(1);
        Ok(KeyHandle {
            id: key_id.to_string(),
            version: entry.version,
            key_type: entry.key_type,
        })
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
        let algos = [
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::Ed25519,
        ];
        for a in algos {
            let _copy = a;
            let _dbg = format!("{:?}", a);
        }
    }

    #[tokio::test]
    async fn software_signer_sign_returns_unsupported() {
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
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SoftwareSigner>();
        assert_send_sync::<Box<dyn Signer>>();
    }

    // ===== Wave 3c: SoftwareHsm tests =====

    #[test]
    fn hsm_trait_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SoftwareHsm>();
        assert_send_sync::<Arc<dyn Hsm>>();
        assert_send_sync::<KeyHandle>();
    }

    /// `generate_key(HmacSha1)` + `sign` + `verify` round-trip. The signed
    /// data MUST verify, and a wrong signature MUST NOT verify (golden-ticket
    /// detection: a verifier that accepts arbitrary bytes is a security bug).
    #[tokio::test]
    async fn hmac_sign_verify_round_trip() {
        let hsm = SoftwareHsm::new();
        let kh = hsm
            .generate_key("krbtgt", KeyType::HmacSha1)
            .await
            .expect("generate_key");
        assert_eq!(kh.version, 1);
        assert_eq!(kh.key_type, KeyType::HmacSha1);

        let data = b"the quick brown fox";
        let sig = hsm.sign(&kh, data).await.expect("sign");
        assert_eq!(sig.len(), 12, "HMAC-SHA1-96 must be 12 bytes");

        assert!(
            hsm.verify(&kh, data, &sig).await.expect("verify"),
            "valid signature must verify"
        );
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xFF;
        assert!(
            !hsm.verify(&kh, data, &bad_sig).await.expect("verify"),
            "tampered signature must NOT verify"
        );
        assert!(
            !hsm.verify(&kh, b"different data", &sig).await.expect("verify"),
            "wrong-data signature must NOT verify"
        );
    }

    /// `generate_key(Aes256)` + `encrypt` + `decrypt` round-trip. Plaintext
    /// MUST match the decrypted ciphertext, and a corrupted ciphertext MUST
    /// surface a `Crypto` error (GCM tag verification fails).
    #[tokio::test]
    async fn aes_encrypt_decrypt_round_trip() {
        let hsm = SoftwareHsm::new();
        let kh = hsm
            .generate_key("krbtgt-enc", KeyType::Aes256)
            .await
            .expect("generate_key");
        let plaintext = b"super-secret TGT payload";
        let ciphertext = hsm.encrypt(&kh, plaintext).await.expect("encrypt");
        // AES-256-GCM overhead = nonce(12) + tag(16) = 28 bytes.
        assert_eq!(ciphertext.len(), plaintext.len() + 28);

        let decrypted = hsm.decrypt(&kh, &ciphertext).await.expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);

        let mut bad_ct = ciphertext.clone();
        let last = bad_ct.len() - 1;
        bad_ct[last] ^= 0xFF;
        let res = hsm.decrypt(&kh, &bad_ct).await;
        match res {
            Err(HsmError::Crypto(msg)) => assert!(msg.contains("open failed"), "{msg}"),
            other => panic!("expected Crypto error, got {other:?}"),
        }
    }

    /// `rotate_key` bumps the version, preserves the key `id`, and generates
    /// fresh key material (signatures from the old key DO NOT verify under the
    /// new key — this is the golden-ticket-rotation property from ADR-015).
    #[tokio::test]
    async fn rotate_key_changes_version_and_invalidates_old_sigs() {
        let hsm = SoftwareHsm::new();
        let kh1 = hsm
            .generate_key("krbtgt", KeyType::HmacSha1)
            .await
            .expect("generate_key");
        let data = b"payload";
        let sig1 = hsm.sign(&kh1, data).await.expect("sign under v1");

        let kh2 = hsm.rotate_key("krbtgt").await.expect("rotate_key");
        assert_eq!(kh2.id, "krbtgt");
        assert_eq!(kh2.version, 2);
        assert_eq!(kh2.key_type, KeyType::HmacSha1);

        let sig2 = hsm.sign(&kh2, data).await.expect("sign under v2");
        assert!(
            hsm.verify(&kh2, data, &sig2).await.expect("verify v2"),
            "v2 signature must verify under v2"
        );
        let err = hsm
            .sign(&kh1, data)
            .await
            .expect_err("stale handle must error");
        assert!(matches!(err, HsmError::Unsupported(_)), "{err:?}");
        let verify_res = hsm.verify(&kh2, data, &sig1).await.expect("verify call");
        assert!(
            !verify_res,
            "old-key signature MUST NOT verify under rotated key (golden-ticket mitigation)"
        );
    }

    /// `sign` for an `Aes256` key returns `Unsupported` (AES is not a signing
    /// algorithm); `encrypt` for an `HmacSha1` key returns `Unsupported`.
    #[tokio::test]
    async fn wrong_key_type_returns_unsupported() {
        let hsm = SoftwareHsm::new();
        let aes_kh = hsm
            .generate_key("k-enc", KeyType::Aes256)
            .await
            .expect("generate_key");
        let hmac_kh = hsm
            .generate_key("k-mac", KeyType::HmacSha1)
            .await
            .expect("generate_key");

        match hsm.sign(&aes_kh, b"data").await {
            Err(HsmError::Unsupported(msg)) => assert!(msg.contains("Aes256"), "{msg}"),
            other => panic!("expected Unsupported for Aes256 sign, got {other:?}"),
        }
        match hsm.encrypt(&hmac_kh, b"data").await {
            Err(HsmError::Unsupported(msg)) => assert!(msg.contains("HmacSha1"), "{msg}"),
            other => panic!("expected Unsupported for HmacSha1 encrypt, got {other:?}"),
        }
    }

    /// `rotate_key` on a non-existent key returns `NotFound`.
    #[tokio::test]
    async fn rotate_missing_key_returns_not_found() {
        let hsm = SoftwareHsm::new();
        let err = hsm.rotate_key("does-not-exist").await.expect_err("rotate");
        assert!(matches!(err, HsmError::NotFound(_)), "{err:?}");
    }

    /// `generate_key(Rsa2048)` returns `Unsupported` in the software HSM.
    #[tokio::test]
    async fn rsa2048_unsupported_in_software_hsm() {
        let hsm = SoftwareHsm::new();
        let err = hsm
            .generate_key("rsa-cert", KeyType::Rsa2048)
            .await
            .expect_err("generate_key RSA2048");
        assert!(matches!(err, HsmError::Unsupported(_)), "{err:?}");
    }

    /// Concurrent `sign` calls under different keys do not race on the
    /// internal RwLock.
    #[tokio::test]
    async fn concurrent_signs_under_distinct_keys_succeed() {
        let hsm = Arc::new(SoftwareHsm::new());
        let kh1 = hsm.generate_key("k1", KeyType::HmacSha1).await.unwrap();
        let kh2 = hsm.generate_key("k2", KeyType::HmacSha1).await.unwrap();
        let hsm1 = hsm.clone();
        let hsm2 = hsm.clone();
        let (r1, r2) = tokio::join!(
            async move { hsm1.sign(&kh1, b"a").await },
            async move { hsm2.sign(&kh2, b"b").await },
        );
        let s1 = r1.expect("sign k1");
        let s2 = r2.expect("sign k2");
        assert_eq!(s1.len(), 12);
        assert_eq!(s2.len(), 12);
        assert_ne!(s1, s2, "distinct keys must produce distinct signatures");
    }
}
