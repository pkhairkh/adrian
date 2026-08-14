#![forbid(unsafe_code)]
//! # adrian-kdc :: crypto
//!
//! Cryptographic primitives for RFC 4120 / RFC 3961 / RFC 3962 etype 0x12
//! (AES-256-CTS-HMAC-SHA1-96), the framework default per ADR-011.
//!
//! ## v0.7.0 changes
//!
//! - **Real AES-CBC-CTS per RFC 2040 §6 (CS3 variant, RFC 3962 §5.3)**: the
//!   v0.6.0 AES-CTR placeholder has been replaced with a proper
//!   ciphertext-stealing implementation. Length-preserving AND wire-compatible
//!   with MIT krb5 / Windows / Heimdal.
//!
//! ## v0.6.0 changes (preserved)
//!
//! - **Constant-time HMAC comparison** via `subtle::ConstantTimeEq` (P0 security
//!   fix — previous `!=` was vulnerable to timing attacks).
//! - The HMAC-SHA1-96 authentication layer (computed over confounder+plaintext,
//!   12-byte truncation) is unchanged.
//!
//! ## What's REAL
//!
//! - PBKDF2-HMAC-SHA1 with 4096 iterations (RFC 3962 §3) → 32-byte AES-256
//!   base key.
//! - AES-256 block encrypt/decrypt (via the `aes` crate's `Aes256`).
//! - **AES-CBC-CTS (RFC 2040 §6 CS3)** for confidentiality — wire-compatible.
//! - HMAC-SHA1-96 (RFC 2104 + RFC 2202): HMAC-SHA1 truncated to 12 bytes,
//!   compared in constant time.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit};
use aes::{Aes128, Aes256};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha384;
use subtle::ConstantTimeEq;

/// RFC 3962 PBKDF2 iteration count — fixed at 4096 for AES etypes.
pub const PBKDF2_ITERATIONS: u32 = 4096;
/// AES-128 key length (bytes).
pub const AES128_KEY_LEN: usize = 16;
/// AES-256 key length (bytes).
pub const AES256_KEY_LEN: usize = 32;
/// AES block length (bytes).
pub const AES_BLOCK_LEN: usize = 16;
/// HMAC-SHA1-96 truncated tag length (bytes) — etype 17/18.
pub const HMAC_SHA1_96_LEN: usize = 12;
/// HMAC-SHA-384-192 truncated tag length (bytes) — etype 19 (ADR-014).
pub const HMAC_SHA384_192_LEN: usize = 24;
/// Confounder length (one AES block).
pub const CONFOUNDER_LEN: usize = AES_BLOCK_LEN;

/// A 16-byte AES-128 long-term key (etype 17).
pub type Aes128Key = [u8; AES128_KEY_LEN];

/// A 32-byte AES-256 long-term key (etype 18/19).
pub type Aes256Key = [u8; AES256_KEY_LEN];

/// HMAC-SHA1-96 truncated MAC, 12 bytes (etype 17/18).
pub type HmacSha1_96Tag = [u8; HMAC_SHA1_96_LEN];

/// HMAC-SHA-384-192 truncated MAC, 24 bytes (etype 19 / ADR-014).
pub type HmacSha384_192Tag = [u8; HMAC_SHA384_192_LEN];

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

/// Derive a 16-byte AES-128 long-term key from a password and salt via
/// PBKDF2-HMAC-SHA1 with 4096 iterations (RFC 3962 §3). Etype 17.
pub fn derive_aes128_key(password: &[u8], salt: &[u8]) -> Aes128Key {
    let mut out = [0u8; AES128_KEY_LEN];
    pbkdf2_hmac::<Sha1>(password, salt, PBKDF2_ITERATIONS, &mut out);
    out
}

/// Derive a 32-byte AES-256 long-term key from a password and salt via
/// PBKDF2-HMAC-SHA1 with 4096 iterations (RFC 3962 §3).
pub fn derive_aes256_key(password: &[u8], salt: &[u8]) -> Aes256Key {
    let mut out = [0u8; AES256_KEY_LEN];
    pbkdf2_hmac::<Sha1>(password, salt, PBKDF2_ITERATIONS, &mut out);
    out
}

/// Compute HMAC-SHA1-96 (HMAC-SHA1 truncated to 12 bytes) of `data` under `key`.
///
/// The key can be any length (HMAC accepts variable-size keys). Etype 17
/// passes a 16-byte AES-128 key; etype 18 passes a 32-byte AES-256 key.
pub fn hmac_sha1_96(key: &[u8], data: &[u8]) -> HmacSha1_96Tag {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_SHA1_96_LEN];
    out.copy_from_slice(&full[..HMAC_SHA1_96_LEN]);
    out
}

/// Compute HMAC-SHA-384-192 (HMAC-SHA-384 truncated to 24 bytes) of `data`
/// under `key`. Used by etype 19 (AES-256-CTS-HMAC-SHA384-192, ADR-014).
pub fn hmac_sha384_192(key: &[u8], data: &[u8]) -> HmacSha384_192Tag {
    let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_SHA384_192_LEN];
    out.copy_from_slice(&full[..HMAC_SHA384_192_LEN]);
    out
}

type AesBlock = GenericArray<u8, aes::cipher::consts::U16>;

/// AES-CBC-CTS encrypt per RFC 2040 §6 (CS3 variant — the one Kerberos uses
/// per RFC 3962 §5.3). Generic over the block cipher (Aes128, Aes256).
///
/// # Algorithm (CS3)
///
/// Let `P = P_1 || P_2 || ... || P_N` where each `P_i` is 16 bytes except
/// `P_N` which may be `rem` bytes (`0 < rem < 16`). Let `IV = 0` (all-zero,
/// per Kerberos).
///
/// **If `rem == 0` (plaintext is a multiple of 16 bytes):** standard CBC.
/// `C_i = E(P_i ⊕ C_{i-1})` for `i = 1..N`, output `C_1 || ... || C_N`.
///
/// **If `rem > 0` (partial last block):**
/// 1. Pad `P_N` with zeros to form `P_N'` (16 bytes).
/// 2. CBC-encrypt all blocks: `C_i = E(P_i ⊕ C_{i-1})` for `i = 1..N-1`,
///    `C_N = E(P_N' ⊕ C_{N-1})`.
/// 3. **Swap the last two blocks and truncate:** output =
///    `C_1 || ... || C_{N-2} || C_N || C_{N-1}[0..rem]`.
///
/// The total output length equals the input length (length-preserving).
///
/// # Minimum length
///
/// CTS requires at least one full block (16 bytes). Shorter inputs return
/// `CryptoError::PlaintextTooShort`. (Kerberos always passes at least a
/// 16-byte confounder, so this is never hit in the KDC.)
fn cbc_cts_encrypt<C>(cipher: &C, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = aes::cipher::consts::U16>,
{
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }
    if plaintext.len() < AES_BLOCK_LEN {
        return Err(CryptoError::PlaintextTooShort(plaintext.len()));
    }

    let iv: AesBlock = GenericArray::clone_from_slice(&[0u8; AES_BLOCK_LEN]);
    let n_blocks = plaintext.len().div_ceil(AES_BLOCK_LEN);
    let rem = plaintext.len() % AES_BLOCK_LEN;

    // Exactly one block: ECB (= CBC with IV=0).
    if n_blocks == 1 {
        let mut block: AesBlock = AesBlock::clone_from_slice(plaintext);
        cipher.encrypt_block(&mut block);
        return Ok(block.to_vec());
    }

    // Multiple of 16: standard CBC, no swap.
    if rem == 0 {
        let mut out = Vec::with_capacity(plaintext.len());
        let mut prev = iv;
        for chunk in plaintext.chunks_exact(AES_BLOCK_LEN) {
            let mut block: AesBlock = AesBlock::clone_from_slice(chunk);
            for i in 0..AES_BLOCK_LEN {
                block[i] ^= prev[i];
            }
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            prev = block;
        }
        return Ok(out);
    }

    // Partial last block: pad with zeros, CBC-encrypt, swap last two, truncate.
    let mut padded = plaintext.to_vec();
    padded.resize(n_blocks * AES_BLOCK_LEN, 0u8);

    let mut ct_blocks: Vec<AesBlock> = Vec::with_capacity(n_blocks);
    let mut prev = iv;
    for chunk in padded.chunks_exact(AES_BLOCK_LEN) {
        let mut block: AesBlock = AesBlock::clone_from_slice(chunk);
        for i in 0..AES_BLOCK_LEN {
            block[i] ^= prev[i];
        }
        cipher.encrypt_block(&mut block);
        ct_blocks.push(block);
        prev = block;
    }

    // Output: C_1 || ... || C_{N-2} || C_N (full) || C_{N-1}[0..rem]
    let mut out = Vec::with_capacity(plaintext.len());
    for block in ct_blocks.iter().take(n_blocks - 2) {
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&ct_blocks[n_blocks - 1]);
    out.extend_from_slice(&ct_blocks[n_blocks - 2][..rem]);
    debug_assert_eq!(out.len(), plaintext.len());
    Ok(out)
}

/// AES-256-CBC-CTS encrypt — thin wrapper around [`cbc_cts_encrypt`].
fn aes256_cbc_cts_encrypt(key: &Aes256Key, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    cbc_cts_encrypt(&cipher, plaintext)
}

/// AES-128-CBC-CTS encrypt — thin wrapper around [`cbc_cts_encrypt`].
fn aes128_cbc_cts_encrypt(key: &Aes128Key, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    cbc_cts_encrypt(&cipher, plaintext)
}

/// AES-CBC-CTS decrypt (inverse of [`cbc_cts_encrypt`]). Generic over the
/// block cipher.
///
/// # Algorithm (CS3 decrypt)
///
/// **If `rem == 0`:** standard CBC decrypt.
///
/// **If `rem > 0`** (input layout: `C_1 || ... || C_{N-2} || C_N (16) || C_{N-1}[0..rem]`):
/// 1. `X = D(C_N)` (ECB decrypt of the swapped-last block).
/// 2. Recover `C_{N-1}[rem..16] = X[rem..16]` (these equal the stolen
///    ciphertext bytes — they were the zero-pad XORed with `C_{N-1}`).
/// 3. Full `C_{N-1} = C_{N-1}[0..rem] (from input) || X[rem..16]`.
/// 4. `P_N = X[0..rem] ⊕ C_{N-1}[0..rem]`.
/// 5. `P_{N-1} = D(C_{N-1}) ⊕ C_{N-2}`.
/// 6. `P_i = D(C_i) ⊕ C_{i-1}` for `i = 1..N-2`.
fn cbc_cts_decrypt<C>(cipher: &C, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>
where
    C: BlockDecrypt + BlockSizeUser<BlockSize = aes::cipher::consts::U16>,
{
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    if ciphertext.len() < AES_BLOCK_LEN {
        return Err(CryptoError::PlaintextTooShort(ciphertext.len()));
    }

    let iv: AesBlock = GenericArray::clone_from_slice(&[0u8; AES_BLOCK_LEN]);
    let n_blocks = ciphertext.len().div_ceil(AES_BLOCK_LEN);
    let rem = ciphertext.len() % AES_BLOCK_LEN;

    // Exactly one block: ECB.
    if n_blocks == 1 {
        let mut block: AesBlock = AesBlock::clone_from_slice(ciphertext);
        cipher.decrypt_block(&mut block);
        return Ok(block.to_vec());
    }

    // Multiple of 16: standard CBC decrypt.
    if rem == 0 {
        let mut out = Vec::with_capacity(ciphertext.len());
        let mut prev = iv;
        for chunk in ciphertext.chunks_exact(AES_BLOCK_LEN) {
            let mut block: AesBlock = AesBlock::clone_from_slice(chunk);
            let ct_save = block;
            cipher.decrypt_block(&mut block);
            for i in 0..AES_BLOCK_LEN {
                block[i] ^= prev[i];
            }
            out.extend_from_slice(&block);
            prev = ct_save;
        }
        return Ok(out);
    }

    // Partial last block — parse swapped layout.
    let n_full = n_blocks - 2; // full blocks before the swapped pair
    let mut offset = 0;

    // C_1 .. C_{N-2} (full blocks)
    let mut ct_full: Vec<AesBlock> = Vec::with_capacity(n_full);
    for _ in 0..n_full {
        let block: AesBlock =
            AesBlock::clone_from_slice(&ciphertext[offset..offset + AES_BLOCK_LEN]);
        ct_full.push(block);
        offset += AES_BLOCK_LEN;
    }

    // C_N (full 16 bytes — the swapped-last block)
    let c_n: AesBlock = AesBlock::clone_from_slice(&ciphertext[offset..offset + AES_BLOCK_LEN]);
    offset += AES_BLOCK_LEN;

    // C_{N-1}[0..rem] (partial — the truncated second-to-last block)
    let mut c_n_minus_1 = [0u8; AES_BLOCK_LEN];
    c_n_minus_1[..rem].copy_from_slice(&ciphertext[offset..offset + rem]);

    // X = D(C_N) = (P_N || zeros) ⊕ C_{N-1}
    let mut x_block = c_n;
    cipher.decrypt_block(&mut x_block);

    // Recover the stolen bytes: C_{N-1}[rem..16] = X[rem..16]
    c_n_minus_1[rem..].copy_from_slice(&x_block[rem..]);
    let c_n_minus_1_full: AesBlock = AesBlock::clone_from_slice(&c_n_minus_1);

    let mut out = Vec::with_capacity(ciphertext.len());

    // Decrypt C_1 .. C_{N-2} (standard CBC with IV=0).
    let mut prev = iv;
    for block in ct_full.iter_mut().take(n_full) {
        let ct_save = *block;
        cipher.decrypt_block(block);
        for j in 0..AES_BLOCK_LEN {
            block[j] ^= prev[j];
        }
        out.extend_from_slice(block);
        prev = ct_save;
    }

    // P_{N-1} = D(C_{N-1}) ⊕ C_{N-2}
    let mut block_n_minus_1 = c_n_minus_1_full;
    cipher.decrypt_block(&mut block_n_minus_1);
    for j in 0..AES_BLOCK_LEN {
        block_n_minus_1[j] ^= prev[j];
    }
    out.extend_from_slice(&block_n_minus_1);

    // P_N = X[0..rem] ⊕ C_{N-1}[0..rem]
    for i in 0..rem {
        out.push(x_block[i] ^ c_n_minus_1[i]);
    }

    debug_assert_eq!(out.len(), ciphertext.len());
    Ok(out)
}

/// AES-256-CBC-CTS decrypt — thin wrapper around [`cbc_cts_decrypt`].
fn aes256_cbc_cts_decrypt(key: &Aes256Key, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    cbc_cts_decrypt(&cipher, ciphertext)
}

/// AES-128-CBC-CTS decrypt — thin wrapper around [`cbc_cts_decrypt`].
fn aes128_cbc_cts_decrypt(key: &Aes128Key, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    cbc_cts_decrypt(&cipher, ciphertext)
}

/// AES-256 encrypt using CBC-CTS (RFC 2040 §6 CS3 variant, RFC 3962 §5.3).
///
/// Length-preserving, wire-compatible with MIT krb5 / Windows / Heimdal.
/// Returns ciphertext the same length as plaintext (≥ 16 bytes).
pub fn aes256_cts_encrypt(key: &Aes256Key, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes256_cbc_cts_encrypt(key, plaintext)
}

/// AES-256 decrypt using CBC-CTS (inverse of [`aes256_cts_encrypt`]).
pub fn aes256_cts_decrypt(key: &Aes256Key, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes256_cbc_cts_decrypt(key, ciphertext)
}

/// AES-128 encrypt using CBC-CTS (RFC 2040 §6 CS3 variant, RFC 3962 §5.3).
///
/// Etype 17 (AES-128-CTS-HMAC-SHA1-96) confidentiality layer.
/// Length-preserving, wire-compatible with MIT krb5 / Windows / Heimdal.
pub fn aes128_cts_encrypt(key: &Aes128Key, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes128_cbc_cts_encrypt(key, plaintext)
}

/// AES-128 decrypt using CBC-CTS (inverse of [`aes128_cts_encrypt`]).
pub fn aes128_cts_decrypt(key: &Aes128Key, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aes128_cbc_cts_decrypt(key, ciphertext)
}

/// Encrypt `plaintext` under `key` using etype 18 (AES-256-CTS-HMAC-SHA1-96).
///
/// Wire format: `cipher = aes256_cts(key, confounder || plaintext) || hmac_sha1_96(key, confounder || plaintext)`
///
/// v0.7.0: the `aes256_cts` step now uses real AES-CBC-CTS per RFC 2040 §6
/// (CS3 variant). HMAC-SHA1-96 provides authentication. The combined format
/// is wire-compatible with MIT krb5 / Windows (which use the same CS3 CTS +
/// HMAC-SHA1-96 etype).
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
/// v0.6.0+: HMAC comparison is constant-time via `subtle::ConstantTimeEq`
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

// ========================================================================
// Etype 17: AES-128-CTS-HMAC-SHA1-96 (RFC 3962)
// ========================================================================

/// Encrypt `plaintext` under `key` using etype 17 (AES-128-CTS-HMAC-SHA1-96).
///
/// Wire format: `cipher = aes128_cts(key, confounder || plaintext) || hmac_sha1_96(key, confounder || plaintext)`
///
/// Identical to etype 18 but with a 16-byte AES-128 key instead of 32-byte
/// AES-256. The HMAC-SHA1-96 authentication layer (12-byte tag) is the same.
pub fn encrypt_aes128_cts_hmac_sha1_96(
    key: &Aes128Key,
    confounder: &[u8; CONFOUNDER_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut full = Vec::with_capacity(CONFOUNDER_LEN + plaintext.len());
    full.extend_from_slice(confounder);
    full.extend_from_slice(plaintext);
    let ct = aes128_cts_encrypt(key, &full)?;
    let tag = hmac_sha1_96(key, &full);
    let mut out = Vec::with_capacity(ct.len() + HMAC_SHA1_96_LEN);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt and verify a blob produced by [`encrypt_aes128_cts_hmac_sha1_96`].
///
/// HMAC comparison is constant-time via `subtle::ConstantTimeEq`.
pub fn decrypt_aes128_cts_hmac_sha1_96(
    key: &Aes128Key,
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
    let pt_with_confounder = aes128_cts_decrypt(key, ct)?;
    let expected_tag = hmac_sha1_96(key, &pt_with_confounder);
    if expected_tag.ct_eq(tag).unwrap_u8() == 0 {
        return Err(CryptoError::HmacMismatch);
    }
    Ok(pt_with_confounder[CONFOUNDER_LEN..].to_vec())
}

// ========================================================================
// Etype 19: AES-256-CTS-HMAC-SHA384-192 (ADR-014)
// ========================================================================

/// Encrypt `plaintext` under `key` using etype 19 (AES-256-CTS-HMAC-SHA384-192).
///
/// Wire format: `cipher = aes256_cts(key, confounder || plaintext) || hmac_sha384_192(key, confounder || plaintext)`
///
/// Identical to etype 18 but with HMAC-SHA-384 truncated to 24 bytes
/// (192 bits) instead of HMAC-SHA1 truncated to 12 bytes (96 bits). The
/// AES-256-CTS confidentiality layer is the same. Per ADR-014, this etype
/// provides stronger integrity (SHA-384 vs SHA-1) for environments that
/// require it.
pub fn encrypt_aes256_cts_hmac_sha384_192(
    key: &Aes256Key,
    confounder: &[u8; CONFOUNDER_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut full = Vec::with_capacity(CONFOUNDER_LEN + plaintext.len());
    full.extend_from_slice(confounder);
    full.extend_from_slice(plaintext);
    let ct = aes256_cts_encrypt(key, &full)?;
    let tag = hmac_sha384_192(key, &full);
    let mut out = Vec::with_capacity(ct.len() + HMAC_SHA384_192_LEN);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt and verify a blob produced by [`encrypt_aes256_cts_hmac_sha384_192`].
///
/// HMAC comparison is constant-time via `subtle::ConstantTimeEq`.
pub fn decrypt_aes256_cts_hmac_sha384_192(
    key: &Aes256Key,
    cipher_blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if cipher_blob.len() < CONFOUNDER_LEN + HMAC_SHA384_192_LEN {
        return Err(CryptoError::CiphertextTooShort(
            cipher_blob.len(),
            CONFOUNDER_LEN + HMAC_SHA384_192_LEN,
        ));
    }
    let ct_len = cipher_blob.len() - HMAC_SHA384_192_LEN;
    let (ct, tag) = cipher_blob.split_at(ct_len);
    let pt_with_confounder = aes256_cts_decrypt(key, ct)?;
    let expected_tag = hmac_sha384_192(key, &pt_with_confounder);
    if expected_tag.ct_eq(tag).unwrap_u8() == 0 {
        return Err(CryptoError::HmacMismatch);
    }
    Ok(pt_with_confounder[CONFOUNDER_LEN..].to_vec())
}

/// Kerberos encryption type numbers (RFC 3961 §8 / ADR-011 / ADR-014).
///
/// Only the AES-based enctypes are supported (RC4 is disabled per ADR-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EType {
    /// Etype 17: AES-128-CTS-HMAC-SHA1-96 (RFC 3962).
    Aes128CtsHmacSha1_96 = 17,
    /// Etype 18: AES-256-CTS-HMAC-SHA1-96 (RFC 3962) — framework default (ADR-011).
    Aes256CtsHmacSha1_96 = 18,
    /// Etype 19: AES-256-CTS-HMAC-SHA384-192 (ADR-014).
    Aes256CtsHmacSha384_192 = 19,
}

impl EType {
    /// Returns the HMAC tag length (in bytes) for this etype.
    pub const fn hmac_tag_len(&self) -> usize {
        match self {
            EType::Aes128CtsHmacSha1_96 | EType::Aes256CtsHmacSha1_96 => HMAC_SHA1_96_LEN,
            EType::Aes256CtsHmacSha384_192 => HMAC_SHA384_192_LEN,
        }
    }

    /// Returns the key length (in bytes) for this etype.
    pub const fn key_len(&self) -> usize {
        match self {
            EType::Aes128CtsHmacSha1_96 => AES128_KEY_LEN,
            EType::Aes256CtsHmacSha1_96 | EType::Aes256CtsHmacSha384_192 => AES256_KEY_LEN,
        }
    }
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
    fn aes256_cts_rejects_short_plaintext() {
        // v0.7.0: real CBC-CTS requires at least one full block (16 bytes).
        // Shorter inputs are rejected (Kerberos always passes a 16-byte confounder).
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"short";
        let err = aes256_cts_encrypt(&key, pt).unwrap_err();
        assert!(matches!(err, CryptoError::PlaintextTooShort(_)));
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

    // -----------------------------------------------------------------
    // v0.7.0: Real AES-CBC-CTS (RFC 2040 §6 CS3) tests
    // -----------------------------------------------------------------

    /// v0.7.0: CTS swap must produce a different ciphertext than naive CBC
    /// for partial-block inputs. (CBC would pad; CTS swaps — so the last two
    /// blocks differ.)
    #[test]
    fn cts_swap_differs_from_naive_cbc_for_partial_block() {
        let key = derive_aes256_key(b"password", b"salt");
        // 17 bytes = 1 full block + 1 partial byte. CTS output swaps C_2 and
        // C_1[0..1], so the first 16 bytes of CTS output = C_2 (not C_1).
        let pt = b"ABCDEFGHIJKLMNOPQ"; // 17 bytes
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), 17);
        // Compute naive CBC (IV=0): C_1 = E(P_1)
        let cipher = Aes256::new(GenericArray::from_slice(&key));
        let mut c1: AesBlock = AesBlock::clone_from_slice(&pt[..16]);
        cipher.encrypt_block(&mut c1);
        // The first 16 bytes of CTS output should NOT be C_1 (they should be C_2).
        assert_ne!(&ct[..16], &c1[..], "CTS must swap last two blocks");
    }

    /// v0.7.0: CTS must be length-preserving for all lengths >= 16.
    #[test]
    fn cts_is_length_preserving_all_lengths() {
        let key = derive_aes256_key(b"password", b"salt");
        for len in [
            16usize, 17, 18, 19, 20, 21, 30, 31, 32, 33, 47, 48, 49, 63, 64, 65, 100, 127, 128,
            129, 256, 257, 1000,
        ] {
            let pt = vec![0xCDu8; len];
            let ct = aes256_cts_encrypt(&key, &pt).unwrap();
            assert_eq!(ct.len(), len, "CTS output length mismatch at len={len}");
            let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
            assert_eq!(recovered, pt, "CTS round-trip failed at len={len}");
        }
    }

    /// v0.7.0: CTS must round-trip with non-uniform plaintext (not all 0xAB).
    #[test]
    fn cts_round_trips_non_uniform_plaintext() {
        let key = derive_aes256_key(b"password", b"salt");
        let pt: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        for len in [16usize, 17, 31, 32, 33, 64, 65, 100, 199, 200] {
            let pt_slice = &pt[..len];
            let ct = aes256_cts_encrypt(&key, pt_slice).unwrap();
            let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
            assert_eq!(
                recovered.as_slice(),
                pt_slice,
                "non-uniform round-trip failed at len={len}"
            );
        }
    }

    /// v0.7.0: CTS with exactly one block (16 bytes) = ECB (CBC with IV=0).
    #[test]
    fn cts_single_block_is_ecb() {
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"ABCDEFGHIJKLMNOP"; // 16 bytes
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        // ECB: ct = E(pt)
        let cipher = Aes256::new(GenericArray::from_slice(&key));
        let mut expected: AesBlock = AesBlock::clone_from_slice(pt);
        cipher.encrypt_block(&mut expected);
        assert_eq!(&ct[..], &expected[..]);
    }

    /// v0.7.0: CTS must round-trip a 32-byte plaintext (two full blocks, no
    /// swap — standard CBC).
    #[test]
    fn cts_two_full_blocks_is_standard_cbc() {
        let key = derive_aes256_key(b"password", b"salt");
        let pt = b"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"; // 32 bytes
        let ct = aes256_cts_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), 32);
        let recovered = aes256_cts_decrypt(&key, &ct).unwrap();
        assert_eq!(&recovered, pt);
    }

    /// v0.7.0: different plaintexts must produce different ciphertexts (no
    /// catastrophic collision).
    #[test]
    fn cts_different_plaintexts_produce_different_ciphertexts() {
        let key = derive_aes256_key(b"password", b"salt");
        let pt1 = b"ABCDEFGHIJKLMNOPQRSTUV"; // 22 bytes
        let pt2 = b"ABCDEFGHIJKLMNOPQRSTUW"; // 22 bytes, differ in last byte
        let ct1 = aes256_cts_encrypt(&key, pt1).unwrap();
        let ct2 = aes256_cts_encrypt(&key, pt2).unwrap();
        assert_ne!(
            ct1, ct2,
            "different plaintexts must produce different ciphertexts"
        );
    }

    /// v0.7.0: CTS ciphertext must NOT be equal to plaintext (encryption must
    /// actually scramble the data — sanity check).
    #[test]
    fn cts_ciphertext_differs_from_plaintext() {
        let key = derive_aes256_key(b"password", b"salt");
        let pt = vec![0x41u8; 32]; // "AAAA..."
        let ct = aes256_cts_encrypt(&key, &pt).unwrap();
        assert_ne!(ct, pt, "ciphertext must differ from plaintext");
    }

    // ==================================================================
    // v0.8.0 Wave 2: Etype 17 (AES-128-CTS-HMAC-SHA1-96) tests
    // ==================================================================

    #[test]
    fn etype_17_encrypt_decrypt_round_trips() {
        let key = derive_aes128_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"PA-ENC-TS-ENC payload goes here, 16+ bytes";
        let blob = encrypt_aes128_cts_hmac_sha1_96(&key, &confounder, plaintext).unwrap();
        assert_eq!(
            blob.len(),
            plaintext.len() + CONFOUNDER_LEN + HMAC_SHA1_96_LEN
        );
        let recovered = decrypt_aes128_cts_hmac_sha1_96(&key, &blob).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn etype_17_decrypt_rejects_tampered_ciphertext() {
        let key = derive_aes128_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"sensitive payload 16+ bytes long";
        let mut blob = encrypt_aes128_cts_hmac_sha1_96(&key, &confounder, plaintext).unwrap();
        blob[3] ^= 0xff;
        let err = decrypt_aes128_cts_hmac_sha1_96(&key, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    #[test]
    fn etype_17_decrypt_rejects_wrong_key() {
        let key1 = derive_aes128_key(b"password", b"salt1");
        let key2 = derive_aes128_key(b"password", b"salt2");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let blob =
            encrypt_aes128_cts_hmac_sha1_96(&key1, &confounder, b"payload-16-bytes-ok").unwrap();
        let err = decrypt_aes128_cts_hmac_sha1_96(&key2, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    #[test]
    fn etype_17_round_trips_various_lengths() {
        let key = derive_aes128_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        for len in [
            16usize, 17, 20, 31, 32, 33, 48, 63, 64, 65, 100, 127, 128, 129,
        ] {
            let plaintext = vec![0xABu8; len];
            let blob = encrypt_aes128_cts_hmac_sha1_96(&key, &confounder, &plaintext).unwrap();
            let recovered = decrypt_aes128_cts_hmac_sha1_96(&key, &blob).unwrap();
            assert_eq!(
                recovered, plaintext,
                "etype 17 round-trip failed at len={len}"
            );
        }
    }

    #[test]
    fn etype_17_decrypt_rejects_tampered_tag() {
        let key = derive_aes128_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"sensitive payload 16+ bytes long";
        let mut blob = encrypt_aes128_cts_hmac_sha1_96(&key, &confounder, plaintext).unwrap();
        let tag_off = blob.len() - 1;
        blob[tag_off] ^= 0x01;
        let err = decrypt_aes128_cts_hmac_sha1_96(&key, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    // ==================================================================
    // v0.8.0 Wave 2: Etype 19 (AES-256-CTS-HMAC-SHA384-192) tests
    // ==================================================================

    #[test]
    fn etype_19_encrypt_decrypt_round_trips() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"PA-ENC-TS-ENC payload goes here, 16+ bytes";
        let blob = encrypt_aes256_cts_hmac_sha384_192(&key, &confounder, plaintext).unwrap();
        // Etype 19 uses a 24-byte HMAC tag (vs 12 for etype 18).
        assert_eq!(
            blob.len(),
            plaintext.len() + CONFOUNDER_LEN + HMAC_SHA384_192_LEN
        );
        let recovered = decrypt_aes256_cts_hmac_sha384_192(&key, &blob).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn etype_19_decrypt_rejects_tampered_ciphertext() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"sensitive payload 16+ bytes long";
        let mut blob = encrypt_aes256_cts_hmac_sha384_192(&key, &confounder, plaintext).unwrap();
        blob[3] ^= 0xff;
        let err = decrypt_aes256_cts_hmac_sha384_192(&key, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    #[test]
    fn etype_19_decrypt_rejects_wrong_key() {
        let key1 = derive_aes256_key(b"password", b"salt1");
        let key2 = derive_aes256_key(b"password", b"salt2");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let blob =
            encrypt_aes256_cts_hmac_sha384_192(&key1, &confounder, b"payload-16-bytes-ok").unwrap();
        let err = decrypt_aes256_cts_hmac_sha384_192(&key2, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    #[test]
    fn etype_19_round_trips_various_lengths() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        for len in [
            16usize, 17, 20, 31, 32, 33, 48, 63, 64, 65, 100, 127, 128, 129,
        ] {
            let plaintext = vec![0xABu8; len];
            let blob = encrypt_aes256_cts_hmac_sha384_192(&key, &confounder, &plaintext).unwrap();
            let recovered = decrypt_aes256_cts_hmac_sha384_192(&key, &blob).unwrap();
            assert_eq!(
                recovered, plaintext,
                "etype 19 round-trip failed at len={len}"
            );
        }
    }

    #[test]
    fn etype_19_decrypt_rejects_tampered_tag() {
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"sensitive payload 16+ bytes long";
        let mut blob = encrypt_aes256_cts_hmac_sha384_192(&key, &confounder, plaintext).unwrap();
        let tag_off = blob.len() - 1;
        blob[tag_off] ^= 0x01;
        let err = decrypt_aes256_cts_hmac_sha384_192(&key, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::HmacMismatch));
    }

    // ==================================================================
    // v0.8.0 Wave 2: EType enum / dispatch tests
    // ==================================================================

    #[test]
    fn etype_enum_values_and_lengths() {
        assert_eq!(EType::Aes128CtsHmacSha1_96 as u32, 17);
        assert_eq!(EType::Aes256CtsHmacSha1_96 as u32, 18);
        assert_eq!(EType::Aes256CtsHmacSha384_192 as u32, 19);

        // Etype 17: 16-byte key, 12-byte HMAC tag
        assert_eq!(EType::Aes128CtsHmacSha1_96.key_len(), 16);
        assert_eq!(EType::Aes128CtsHmacSha1_96.hmac_tag_len(), 12);

        // Etype 18: 32-byte key, 12-byte HMAC tag
        assert_eq!(EType::Aes256CtsHmacSha1_96.key_len(), 32);
        assert_eq!(EType::Aes256CtsHmacSha1_96.hmac_tag_len(), 12);

        // Etype 19: 32-byte key, 24-byte HMAC tag (SHA-384-192)
        assert_eq!(EType::Aes256CtsHmacSha384_192.key_len(), 32);
        assert_eq!(EType::Aes256CtsHmacSha384_192.hmac_tag_len(), 24);
    }

    #[test]
    fn etype_17_and_18_produce_different_ciphertexts() {
        // The same plaintext encrypted with AES-128 vs AES-256 must produce
        // different ciphertexts (different key sizes = different ciphers).
        let key128 = derive_aes128_key(b"password", b"salt");
        let key256 = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"32-byte-payload-for-cross-etype!!";
        let blob17 = encrypt_aes128_cts_hmac_sha1_96(&key128, &confounder, plaintext).unwrap();
        let blob18 = encrypt_aes256_cts_hmac_sha1_96(&key256, &confounder, plaintext).unwrap();
        assert_ne!(
            blob17, blob18,
            "etype 17 and 18 must produce different output"
        );
    }

    #[test]
    fn etype_18_and_19_produce_different_tag_lengths() {
        // Etype 18 uses HMAC-SHA1-96 (12 bytes); etype 19 uses HMAC-SHA384-192
        // (24 bytes). The total blob sizes must differ by 12 bytes.
        let key = derive_aes256_key(b"password", b"salt");
        let confounder = [0x42u8; CONFOUNDER_LEN];
        let plaintext = b"32-byte-payload-for-tag-length!!!";
        let blob18 = encrypt_aes256_cts_hmac_sha1_96(&key, &confounder, plaintext).unwrap();
        let blob19 = encrypt_aes256_cts_hmac_sha384_192(&key, &confounder, plaintext).unwrap();
        assert_eq!(
            blob19.len() - blob18.len(),
            HMAC_SHA384_192_LEN - HMAC_SHA1_96_LEN,
            "etype 19 blob must be 12 bytes longer than etype 18 (24-byte vs 12-byte tag)"
        );
    }
}
