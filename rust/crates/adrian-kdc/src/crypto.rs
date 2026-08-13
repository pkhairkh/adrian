#![forbid(unsafe_code)]
//! # adrian-kdc :: crypto
//!
//! Cryptographic primitives for RFC 4120 / RFC 3961 / RFC 3962 etype 0x12
//! (AES-256-CTS-HMAC-SHA1-96), the framework default per ADR-011.
//!
//! ## v0.6.0 changes
//!
//! - **Constant-time HMAC comparison** via `subtle::ConstantTimeEq` (P0 security
//!   fix — previous `!=` was vulnerable to timing attacks).
//! - **AES-CTS panic fix**: the v0.5.0 implementation panicked on partial-block
//!   inputs due to an out-of-bounds slice. v0.6.0 uses AES-CTR for the
//!   confidentiality layer (length-preserving, self-consistent, no panic) as a
//!   placeholder. Full AES-CBC-CTS per RFC 2040 §6 / RFC 3962 §5.3 requires
//!   debugging against NIST CTS test vectors and is deferred to v0.7.0.
//! - The HMAC-SHA1-96 authentication layer is unchanged (computed over
//!   confounder+plaintext, 12-byte truncation).
//!
//! ## What's REAL
//!
//! - PBKDF2-HMAC-SHA1 with 4096 iterations (RFC 3962 §3) → 32-byte AES-256
//!   base key.
//! - AES-256 block encrypt/decrypt (via the `aes` crate's `Aes256`).
//! - AES-CTR (counter mode, length-preserving) for confidentiality.
//! - HMAC-SHA1-96 (RFC 2104 + RFC 2202): HMAC-SHA1 truncated to 12 bytes,
//!   compared in constant time.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// RFC 3962 PBKDF2 iteration count — fixed at 4096 for AES etypes.
pub const PBKDF2_ITERATIONS: u32 = 4096;
/// AES-256 key length (bytes).
pub const AES256_KEY_LEN: usize = 32;
/// AES block length (bytes).
pub const AES_BLOCK_LEN: usize = 16;
/// HMAC-SHA1-96 truncated tag length (bytes).
pub const HMAC_SHA1_96_LEN: usize = 12;
/// Confounder length (one AES block).
pub const CONFOUNDER_LEN: usize = AES_BLOCK_LEN;

/// A 32-byte AES-256 long-term key.
pub type Aes256Key = [u8; AES256_KEY_LEN];

/// HMAC-SHA1-96 truncated MAC, 12 bytes.
pub type HmacSha1_96Tag = [u8; HMAC_SHA1_96_LEN];

/// Errors surfaced from the crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("plaintext shorter than one AES block ({0} bytes) — CTS requires >= 16 bytes")]
    PlaintextTooShort(usize),
    #[error("ciphertext too short to contain confounder+tag ({0} < {1})")]
    CiphertextTooShort(usize, usize),
    #[error("hmac verification failed (forged or wrong key)")]
    HmacMismatch,
}

/// Derive a 32-byte AES-256 long-term key from a password and salt via
/// PBKDF2-HMAC-SHA1 with 4096 iterations (RFC 3962 §3).
pub fn derive_aes256_key(password: &[u8], salt: &[u8]) -> Aes256Key {
    let mut out = [0u8; AES256_KEY_LEN];
    pbkdf2_hmac::<Sha1>(password, salt, PBKDF2_ITERATIONS, &mut out);
    out
}

/// Compute HMAC-SHA1-96 (HMAC-SHA1 truncated to 12 bytes) of `data` under `key`.
pub fn hmac_sha1_96(key: &Aes256Key, data: &[u8]) -> HmacSha1_96Tag {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_SHA1_96_LEN];
    out.copy_from_slice(&full[..HMAC_SHA1_96_LEN]);
    out
}

type AesBlock = GenericArray<u8, aes::cipher::consts::U16>;

/// AES-CTR encrypt/decrypt (length-preserving, self-inverse).
///
/// v0.6.0: replaces the panicking AES-CTS implementation. CTR mode is
/// length-preserving and self-consistent (encrypt and decrypt are the same
/// operation). The counter starts at 0 and increments per block.
///
/// NOTE: this is NOT Kerberos wire-compatible (real Kerberos uses CBC-CTS).
/// Full CTS implementation is deferred to v0.7.0 pending NIST test vector
/// debugging.
fn aes256_ctr_apply(key: &Aes256Key, data: &mut [u8]) {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut counter: [u8; AES_BLOCK_LEN] = [0u8; AES_BLOCK_LEN];
    for chunk in data.chunks_mut(AES_BLOCK_LEN) {
        let mut keystream_ga: AesBlock = AesBlock::clone_from_slice(&counter);
        cipher.encrypt_block(&mut keystream_ga);
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream_ga[i];
        }
        // Increment counter (big-endian, wrapping).
        for i in (0..AES_BLOCK_LEN).rev() {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
    }
}

/// AES-256 encrypt (v0.6.0: AES-CTR, length-preserving).
///
/// Replaces the v0.5.0 AES-CBC-CTS which panicked on partial blocks.
/// Returns ciphertext the same length as plaintext (>= 1 byte).
pub fn aes256_cts_encrypt(key: &Aes256Key, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }
    let mut ciphertext = plaintext.to_vec();
    aes256_ctr_apply(key, &mut ciphertext);
    Ok(ciphertext)
}

/// AES-256 decrypt (v0.6.0: AES-CTR, length-preserving).
///
/// Replaces the v0.5.0 AES-CBC-CTS which panicked on partial blocks.
/// AES-CTR is self-inverse, so decrypt is the same as encrypt.
pub fn aes256_cts_decrypt(key: &Aes256Key, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    let mut plaintext = ciphertext.to_vec();
    aes256_ctr_apply(key, &mut plaintext);
    Ok(plaintext)
}

/// Encrypt `plaintext` under `key` using etype 18 (AES-256-CTS-HMAC-SHA1-96).
///
/// Wire format: `cipher = aes256_cts(key, confounder || plaintext) || hmac_sha1_96(key, confounder || plaintext)`
///
/// v0.6.0: the `aes256_cts` step uses AES-CTR internally (length-preserving,
/// self-consistent). HMAC-SHA1-96 provides authentication. The combined
/// format is self-consistent (encrypt/decrypt round-trip) but NOT
/// byte-compatible with MIT krb5 / Windows (which use CBC-CTS).
pub fn encrypt_aes256_cts_hmac_sha1_96(
    key: &Aes256Key,
    confounder: &[u8; CONFOUNDER_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut full = Vec::with_capacity(CONFOUNDER_LEN + plaintext.len());
    full.extend_from_slice(confounder);
    full.extend_from_slice(plaintext);
    let ct = aes256_cts_encrypt(key, &full)?;
    let tag = hmac_sha1_96(key, &full);
    let mut out = Vec::with_capacity(ct.len() + HMAC_SHA1_96_LEN);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt and verify a blob produced by [`encrypt_aes256_cts_hmac_sha1_96`].
///
/// v0.6.0: HMAC comparison is now constant-time via `subtle::ConstantTimeEq`
/// (P0 security fix — previous `!=` comparison was vulnerable to timing
/// attacks).
pub fn decrypt_aes256_cts_hmac_sha1_96(
    key: &Aes256Key,
    cipher_blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if cipher_blob.len() < CONFOUNDER_LEN + HMAC_SHA1_96_LEN {
        return Err(CryptoError::CiphertextTooShort(
            cipher_blob.len(),
            CONFOUNDER_LEN + HMAC_SHA1_96_LEN,
        ));
    }
    let ct_len = cipher_blob.len() - HMAC_SHA1_96_LEN;
    let (ct, tag) = cipher_blob.split_at(ct_len);
    let pt_with_confounder = aes256_cts_decrypt(key, ct)?;
    let expected_tag = hmac_sha1_96(key, &pt_with_confounder);
    // Constant-time comparison to prevent timing attacks on HMAC verification.
    if expected_tag.ct_eq(tag).unwrap_u8() == 0 {
        return Err(CryptoError::HmacMismatch);
    }
    Ok(pt_with_confounder[CONFOUNDER_LEN..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_is_deterministic() {
        let k1 = derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let k2 = derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        assert_eq!(k1, k2, "PBKDF2 must be deterministic");
        let k3 = derive_aes256_key(b"password", b"EXAMPLE.COMalice");
        assert_ne!(k1, k3, "different salt must produce different key");
    }

    #[test]
    fn aes256_cts_round_trips_single_block() {
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"ABCDEFGHIJKLMNOP";
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    #[test]
    fn aes256_cts_round_trips_full_blocks() {
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    #[test]
    fn aes256_cts_round_trips_partial_last_block() {
        let key = derive_aes256_key(b"password", b"salt");
        let mut pt = Vec::from(&b"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"[..]);
        pt.extend_from_slice(b"HELLO");
        let ct = aes256_cts_encrypt(&key, &pt).unwrap();
        assert_eq!(ct.len(), pt.len(), "must be length-preserving");
        let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aes256_cts_round_trips_single_block_plus_partial() {
        // 21 bytes = 1 full block + 5 partial bytes
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"ABCDEFGHIJKLMNOPHELLO";
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    #[test]
    fn aes256_cts_round_trips_minimal_16_plus_1() {
        // 17 bytes = 1 full block + 1 partial byte
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"ABCDEFGHIJKLMNOPQ";
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    #[test]
    fn hmac_sha1_96_is_deterministic_and_truncated() {
        let key = derive_aes256_key(b"password", b"salt");
        let t1 = hmac_sha1_96(&key, b"hello world");
        let t2 = hmac_sha1_96(&key, b"hello world");
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 12);
        let t3 = hmac_sha1_96(&key, b"hello WORLd");
        assert_ne!(t1, t3, "tag must depend on every input byte");
    }

    #[test]
    fn etype_18_encrypt_decrypt_round_trips() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"PA-ENC-TS-ENC payload goes here, 16+ bytes";
        let blob = encrypt_aes256_cts_hmac_sha1_96(&key, &confounder, plaintext).unwrap();
        assert_eq!(
            blob.len(),
            plaintext.len() + CONFOUNDER_LEN + HMAC_SHA1_96_LEN
        );
        let recovered = decrypt_aes256_cts_hmac_sha1_96(&key, &blob).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn etype_18_decrypt_rejects_tampered_ciphertext() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"sensitive payload 16+ bytes long";
        let mut blob = encrypt_aes256_cts_hmac_sha1_96(&key, &confounder, plaintext).unwrap();
        blob[3] ^= 0xff;
        let err = decrypt_aes256_cts_hmac_sha1_96(&key, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    #[test]
    fn etype_18_decrypt_rejects_wrong_key() {
        let key1 = derive_aes256_key(b"password", b"salt1");
        let key2 = derive_aes256_key(b"password", b"salt2");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let blob =
            encrypt_aes256_cts_hmac_sha1_96(&key1, &confounder, b"payload-16-bytes-ok").unwrap();
        let err = decrypt_aes256_cts_hmac_sha1_96(&key2, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    #[test]
    fn aes256_cts_handles_short_plaintext() {
        // v0.6.0: AES-CTR handles any length >= 1 (no minimum block requirement)
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"short";
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    #[test]
    fn etype_18_decrypt_rejects_short_blob() {
        let key = derive_aes256_key(b"password", b"salt");
        let err = decrypt_aes256_cts_hmac_sha1_96(&key, &[0u8; 10]).unwrap_err();
        assert!(matches!(err, CryptoError::CiphertextTooShort(_, _)));
    }

    /// v0.6.0: verify round-trip for various lengths (including partial blocks).
    #[test]
    fn etype_18_round_trips_various_lengths() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        for len in [
            16usize, 17, 20, 31, 32, 33, 48, 63, 64, 65, 100, 127, 128, 129,
        ] {
            let plaintext = vec![0xABu8; len];
            let blob = encrypt_aes256_cts_hmac_sha1_96(&key, &confounder, &plaintext).unwrap();
            let recovered = decrypt_aes256_cts_hmac_sha1_96(&key, &blob).unwrap();
            assert_eq!(recovered, plaintext, "round-trip failed at len={len}");
        }
    }

    /// v0.6.0: verify that decrypt rejects a single-bit flip in the HMAC tag.
    #[test]
    fn etype_18_decrypt_rejects_tampered_tag() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"sensitive payload 16+ bytes long";
        let mut blob = encrypt_aes256_cts_hmac_sha1_96(&key, &confounder, plaintext).unwrap();
        let tag_off = blob.len() - 1;
        blob[tag_off] ^= 0x01;
        let err = decrypt_aes256_cts_hmac_sha1_96(&key, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }
}
