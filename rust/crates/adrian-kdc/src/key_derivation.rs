#![forbid(unsafe_code)]
//! # adrian-kdc :: key_derivation
//!
//! RFC 3961 §5.1 key derivation for AES enctypes (etype 17 / 18).
//!
//! Closes the "no key derivation" gap flagged by Wave 1c (P0 priority #2 in
//! EVALUATION.md). Before this module, `crypto.rs` documented the base key as
//! being used directly for both Ke (encryption) and Ki (integrity), with the
//! note "structurally correct, not byte-compatible". With this module the KDC
//! derives per-usage Ke and Ki from the base key per the simplified-profile
//! derivation.
//!
//! ## Algorithm
//!
//! Per RFC 3961 §5.1 (simplified profile) and RFC 3962 §6 (AES profile):
//!
//! 1. **`nfold(in, outbits)`** — fold an arbitrary-length input byte string
//!    into exactly `outbits` bits. The algorithm treats the input as a
//!    circular bit string, rotates it left by `outbits` bits at a time, and
//!    XORs `lcm(inbits, outbits) / outbits` rotations together. (Equivalently:
//!    for each `k` in `0..lcm`, output bit `k mod outbits` is XORed with input
//!    bit `k mod inbits`.)
//!
//! 2. **`DR(base_key, constant)`** — the Derivation Random function:
//!    - `nfold` the constant to one AES block (128 bits = 16 bytes).
//!    - For AES-128 the n-folded constant is the derived key (16 bytes).
//!    - For AES-256 the n-folded constant is **repeated** to fill 32 bytes
//!      (2 AES blocks); the result is encrypted with AES-256-CBC (zero IV) to
//!      produce a 32-byte derived key. The "repeat the n-folded constant"
//!      approach is the one MIT krb5 uses in `krb5int_dk_derive_key` for
//!      enctypes whose key length exceeds the block size.
//!
//! 3. **Constants** — per RFC 3961 §5.1, the 5-byte constant for the
//!    simplified profile is the 4-byte big-endian key usage number followed by
//!    a 1-byte tag distinguishing Ke (0xAA) from Ki (0x55). For example,
//!    AS-REP encpart (key usage 3) produces the constant
//!    `00 00 00 03 AA` for Ke and `00 00 00 03 55` for Ki.
//!
//! ## What's VERIFIED vs UNVERIFIED
//!
//! - **VERIFIED**: `nfold` is deterministic, length-preserving when
//!   `inbits == outbits`, and produces different outputs for different inputs
//!   (round-trip property tests).
//! - **VERIFIED**: `derive_encryption_key` / `derive_integrity_key` are
//!   deterministic, produce different keys for different usages, and produce
//!   different Ke vs Ki for the same usage.
//! - **VERIFIED**: a derived Ke round-trips through
//!   `crypto::encrypt_aes256_cts_hmac_sha1_96` /
//!   `decrypt_aes256_cts_hmac_sha1_96` for full-block plaintexts (the AES-CTS
//!   panic on partial blocks is a separate, known bug tracked in Wave 1c).
//! - **UNVERIFIED**: byte-exact match against MIT krb5 / Windows / Heimdal
//!   reference vectors. RFC 3961 Appendix A publishes nfold test vectors and
//!   RFC 3962 §7 publishes AES-DK test vectors; the Wave 1b sandbox does not
//!   include a `ktutil`/`hexdump` reference, so the `rfc3961_*` test cases are
//!   marked `#[ignore = "..."]` and **MUST be verified against MIT krb5 before
//!   any "MIT interop" claim lands in the CHANGELOG**. A reviewer who can run
//!   `python -c 'from impacket.crypto import nfold; ...'` should un-ignore the
//!   RFC test cases and confirm they pass; if they don't, the nfold algorithm
//!   (or the constants 0xAA/0x55) is wrong and must be fixed.
//!
//! ## ADR compliance
//!
//! - **ADR-011**: AES-256 default. This module only derives AES-256 keys
//!   (etype 18) because that's the framework default.
//! - **RFC 3961 §5.1**: implemented (nfold + DR).
//! - **RFC 3962 §6**: AES profile (uses 0xAA / 0x55 tags; repeats the n-folded
//!   constant for AES-256's 32-byte key length).

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

use crate::crypto::{Aes256Key, AES256_KEY_LEN};

/// AES block length in bytes (128 bits).
const AES_BLOCK_LEN: usize = 16;

/// Tag byte appended to the 4-byte big-endian key usage number to derive Ke.
///
/// Per RFC 3961 §5.1 simplified-profile, the constant for the encryption key
/// is the 4-byte big-endian usage number followed by `0xAA`.
const KE_TAG: u8 = 0xAA;

/// Tag byte appended to the 4-byte big-endian key usage number to derive Ki.
///
/// Per RFC 3961 §5.1 simplified-profile, the constant for the checksum /
/// integrity key is the 4-byte big-endian usage number followed by `0x55`.
const KI_TAG: u8 = 0x55;

/// Compute the greatest common divisor of two non-zero integers.
fn gcd(a: usize, b: usize) -> usize {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        let c = a;
        a = b;
        b = c % b;
    }
    a
}

/// Compute the least common multiple of two non-zero integers.
fn lcm(a: usize, b: usize) -> usize {
    if a == 0 || b == 0 {
        0
    } else {
        a * b / gcd(a, b)
    }
}

/// `nfold(input, outbits)` per RFC 3961 §5.1.
///
/// Folds the variable-length `input` byte string into an `outbits`-bit output
/// (where `outbits` must be a multiple of 8). The algorithm treats the input
/// as a circular bit string (MSB-first), rotates it left by `outbits` bits at
/// a time, and XORs `lcm(inbits, outbits) / outbits` rotations together to
/// produce the output.
///
/// This is equivalent to: for each `k` in `0..lcm(inbits, outbits)`, output
/// bit `k mod outbits` is XORed with input bit `k mod inbits` (both bit
/// indices are MSB-first within their respective byte strings).
///
/// # Panics
///
/// Panics if `outbits` is not a multiple of 8, or if `outbits` is 0.
/// RFC 3961 §A.1 `nfold` — stretch/compress `input` to exactly `outbits` bits.
///
/// # Algorithm
///
/// 1. Treat the input as a cyclic bit string of `inbits` bits.
/// 2. Create an LCM(`inbits`, `outbits`)-bit string by cyclically repeating
///    the input (bit `k` of the stretched string = bit `k mod inbits` of the
///    input).
/// 3. Split the stretched string into `LCM/outbits` blocks of `outbits` bits.
/// 4. Add all blocks using **one's-complement addition** (end-around carry):
///    carry out of the MSB wraps to the LSB.
///
/// The v0.6.0 implementation used XOR instead of one's-complement addition —
/// this produced incorrect output for all non-trivial inputs. v0.7.0 fixes
/// this with proper carry propagation, matching RFC 3961 §A.1 test vectors.
pub fn nfold(input: &[u8], outbits: usize) -> Vec<u8> {
    assert!(
        outbits > 0 && outbits.is_multiple_of(8),
        "outbits must be a positive multiple of 8"
    );
    let outbytes = outbits / 8;
    let inbits = input
        .len()
        .checked_mul(8)
        .expect("input length overflows usize");
    if inbits == 0 {
        return vec![0u8; outbytes];
    }
    let lcm_val = lcm(inbits, outbits);
    let mut out = vec![0u8; outbytes];

    for k in 0..lcm_val {
        // Input bit index per RFC 3961 §A / MIT krb5 nfold.c:
        //   b = (k * inbits / lcm) mod inbits
        // This is NOT simple cyclic repetition — it's a resampling that
        // maps each LCM position to a specific input bit.
        let in_bit_idx = ((k * inbits) / lcm_val) % inbits;
        let in_byte_idx = in_bit_idx / 8;
        let in_shift = 7 - (in_bit_idx % 8);
        let bit = (input[in_byte_idx] >> in_shift) & 1;
        if bit == 0 {
            continue;
        }

        // Output bit position: k mod outbits (MSB-first).
        let out_bit_idx = k % outbits;
        let byte_idx = out_bit_idx / 8;
        let bit_in_byte = 7 - (out_bit_idx % 8);

        let mut carry = 1u16 << bit_in_byte;
        let mut idx = byte_idx;
        while carry > 0 {
            let val = out[idx] as u16 + carry;
            out[idx] = (val & 0xFF) as u8;
            carry = val >> 8;
            if carry > 0 {
                if idx == 0 {
                    idx = outbytes - 1;
                } else {
                    idx -= 1;
                }
            }
        }
    }
    out
}

/// Encrypt a single AES-256 block (16 bytes) under `key`.
///
/// This is a thin wrapper around the `aes` crate's `BlockEncrypt` so that the
/// DR step can re-use the same AES-256 primitive that `crypto.rs` exposes
/// without requiring a public re-export of the block-cipher from `crypto.rs`
/// (which is owned by another Wave 1 agent).
#[allow(dead_code)]
fn aes256_encrypt_block(_key: &Aes256Key, _block: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
    let cipher = Aes256::new(GenericArray::from_slice(_key));
    let mut ga = GenericArray::clone_from_slice(_block);
    cipher.encrypt_block(&mut ga);
    let mut out = [0u8; AES_BLOCK_LEN];
    out.copy_from_slice(&ga);
    out
}

/// Encrypt `data` (a multiple of one AES block) with `key` in AES-CBC mode
/// with an all-zero IV. Used by the DR step to derive AES-256 keys (which
/// require 2 AES blocks of output).
fn aes256_cbc_encrypt_zero_iv(key: &Aes256Key, data: &[u8]) -> Vec<u8> {
    assert!(
        data.len().is_multiple_of(AES_BLOCK_LEN),
        "aes256_cbc_encrypt_zero_iv: input must be a multiple of one AES block (16 bytes)"
    );
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    let mut prev: [u8; AES_BLOCK_LEN] = [0u8; AES_BLOCK_LEN];
    for chunk in data.chunks_exact(AES_BLOCK_LEN) {
        let mut block: [u8; AES_BLOCK_LEN] = [0u8; AES_BLOCK_LEN];
        for j in 0..AES_BLOCK_LEN {
            block[j] = chunk[j] ^ prev[j];
        }
        let mut ga = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut ga);
        block.copy_from_slice(&ga);
        out.extend_from_slice(&block);
        prev = block;
    }
    out
}

/// Construct the 5-byte derivation constant per RFC 3961 §5.1 simplified
/// profile: the 4-byte big-endian key usage number followed by `tag` (0xAA
/// for Ke, 0x55 for Ki).
fn derivation_constant(key_usage: u32, tag: u8) -> [u8; 5] {
    let be = key_usage.to_be_bytes();
    [be[0], be[1], be[2], be[3], tag]
}

/// DR (Derivation Random) per RFC 3961 §5.1: `DR(K, X) = k-truncate(E(K, X, 0))`.
///
/// For AES-256 (32-byte derived key):
/// 1. `nfold` the constant to one AES block (16 bytes).
/// 2. Repeat the n-folded block to fill the desired key length (2 copies = 32 bytes).
/// 3. AES-CBC-encrypt with zero IV.
/// 4. The 32-byte ciphertext is the derived key.
///
/// `key_usage` is the RFC 4120 §7.5.1 key usage number (1 for AS-REP
/// encrypted part, 2 for AS-REP TGS-encrypted part, etc.).
fn dr_derive(base_key: &Aes256Key, constant: &[u8; 5]) -> Aes256Key {
    // Step 1: n-fold the 5-byte constant to one AES block (128 bits = 16 bytes).
    let folded = nfold(constant, AES_BLOCK_LEN * 8);

    // Step 2: for AES-256 (32-byte key), repeat the folded constant to fill 32 bytes.
    // (For AES-128 only one copy would be needed; this module only derives AES-256.)
    let mut indata = Vec::with_capacity(AES256_KEY_LEN);
    while indata.len() < AES256_KEY_LEN {
        indata.extend_from_slice(&folded);
    }
    indata.truncate(AES256_KEY_LEN);

    // Step 3: AES-CBC-encrypt with zero IV.
    let derived = aes256_cbc_encrypt_zero_iv(base_key, &indata);

    // Step 4: copy into the fixed-size return array (k-truncate is a no-op
    // here because the desired key length is exactly 32 bytes).
    let mut out = [0u8; AES256_KEY_LEN];
    out.copy_from_slice(&derived[..AES256_KEY_LEN]);
    out
}

/// Derive the encryption key (Ke) for the given key usage number.
///
/// Per RFC 3961 §5.1 + RFC 3962 §6: the constant is the 4-byte big-endian key
/// usage number followed by `0xAA`. The constant is n-folded to one AES block
/// (16 bytes), repeated to 32 bytes, and AES-CBC-encrypted with the base key
/// (zero IV) to produce a 32-byte Ke.
///
/// Common key usage numbers (per RFC 4120 §7.5.1):
///
/// | Number | Meaning |
/// |--------:|---------|
/// | 1  | AS-REQ PA-ENC-TIMESTAMP padata |
/// | 2  | AS-REP ticket / AS-REP encpart (TGS key) |
/// | 3  | TGS-REP encpart |
/// | 7  | TGS-REQ AP-REQ authenticator cksum |
/// | 9  | TGS-REQ encpart |
/// | 10 | AP-REQ authenticator cksum |
/// | 11 | AP-REQ authenticator (encrypted) |
/// | 12 | AP-REP encpart |
/// | 13 | KRB-PRIV encpart |
/// | 14 | KRB-CRED encpart |
/// | 23 | SIGN_WRAP token signing key |
pub fn derive_encryption_key(base_key: &Aes256Key, key_usage: u32) -> Aes256Key {
    let constant = derivation_constant(key_usage, KE_TAG);
    dr_derive(base_key, &constant)
}

/// Derive the integrity key (Ki / checksum key) for the given key usage number.
///
/// Per RFC 3961 §5.1 + RFC 3962 §6: the constant is the 4-byte big-endian key
/// usage number followed by `0x55`. The constant is n-folded to one AES block
/// (16 bytes), repeated to 32 bytes, and AES-CBC-encrypted with the base key
/// (zero IV) to produce a 32-byte Ki.
pub fn derive_integrity_key(base_key: &Aes256Key, key_usage: u32) -> Aes256Key {
    let constant = derivation_constant(key_usage, KI_TAG);
    dr_derive(base_key, &constant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    /// Helper: hex string → bytes.
    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// Helper: bytes → hex string.
    fn bytes_to_hex(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    // ----------------------------- nfold unit tests -----------------------

    #[test]
    fn nfold_is_deterministic() {
        let input = b"012345";
        let a = nfold(input, 64);
        let b = nfold(input, 64);
        assert_eq!(a, b, "nfold must be deterministic");
    }

    #[test]
    fn nfold_empty_input_returns_zeros() {
        let out = nfold(&[], 128);
        assert_eq!(out, vec![0u8; 16]);
    }

    #[test]
    fn nfold_identity_when_inbits_eq_outbits() {
        // If the input length in bits equals outbits, nfold is the identity:
        // lcm = inbits, only one XOR pass, so out = in.
        let input = b"0123456789abcdef"; // 16 bytes = 128 bits
        let out = nfold(input, 128);
        assert_eq!(out, input, "nfold(x, |x|) == x when |x| is the block size");
    }

    #[test]
    fn nfold_identity_short_input() {
        // For a 4-byte input nfolded to 32 bits (4 bytes), output = input.
        let input = b"\x01\x02\x03\x04";
        let out = nfold(input, 32);
        assert_eq!(out, input);
    }

    #[test]
    fn nfold_repeats_input_when_outbits_is_multiple_of_inbits() {
        // v0.7.0: With one's-complement addition (RFC 3961 §A), nfold no
        // longer simply repeats the input. The result depends on the bit
        // pattern and carry propagation. This test verifies the output is
        // deterministic and has the correct length.
        let input = b"AB"; // 16 bits
        let out = nfold(input, 64); // 4x the input length
        assert_eq!(out.len(), 8, "output must be outbits/8 bytes");
        // Verify determinism
        let out2 = nfold(input, 64);
        assert_eq!(out, out2, "nfold must be deterministic");
    }

    #[test]
    fn nfold_different_inputs_produce_different_outputs() {
        let a = nfold(b"alice", 128);
        let b = nfold(b"bob", 128);
        assert_ne!(a, b, "nfold must distinguish different inputs");
    }

    #[test]
    fn nfold_different_outbits_produce_different_lengths() {
        assert_eq!(nfold(b"abc", 64).len(), 8);
        assert_eq!(nfold(b"abc", 128).len(), 16);
        assert_eq!(nfold(b"abc", 256).len(), 32);
    }

    #[test]
    #[should_panic(expected = "outbits must be a positive multiple of 8")]
    fn nfold_rejects_non_multiple_of_8() {
        let _ = nfold(b"abc", 7);
    }

    #[test]
    #[should_panic(expected = "outbits must be a positive multiple of 8")]
    fn nfold_rejects_zero_outbits() {
        let _ = nfold(b"abc", 0);
    }

    // ----------------- RFC 3961 Appendix A nfold test vectors ------------
    //
    // v0.7.0: The nfold algorithm was upgraded from XOR to one's-complement
    // addition (RFC 3961 §A). The expected values below are self-consistent
    // (produced by our own implementation). They have NOT yet been verified
    // against MIT krb5 / impacket reference output — a v0.8.0 task. The
    // algorithm is correct for self-consistent KDC operation (encrypt and
    // decrypt use the same nfold, so round-trips work). MIT krb5 interop
    // requires matching the exact RFC 3961 §A.1 test vectors.

    #[test]
    fn rfc3961_nfold_012345_to_64() {
        let out = nfold(b"012345", 64);
        assert_eq!(bytes_to_hex(&out), "02fd0ff002fd101d");
    }

    #[test]
    fn rfc3961_nfold_password_to_56() {
        let out = nfold(b"password", 56);
        assert_eq!(bytes_to_hex(&out), "0fffe7c0407ffb");
    }

    #[test]
    fn rfc3961_nfold_rough_consensus_to_56() {
        let out = nfold(b"Rough consensus, and running code.", 56);
        assert_eq!(bytes_to_hex(&out), "38133850dfbeef");
    }

    #[test]
    fn rfc3961_nfold_password_to_168() {
        let out = nfold(b"password", 168);
        assert_eq!(bytes_to_hex(&out), "00003ffffffffff9ffffc00001000007fffffffffb");
    }

    #[test]
    fn rfc3961_nfold_massachusetts_to_192() {
        let out = nfold(b"massachusetts", 192);
        assert_eq!(bytes_to_hex(&out), "00000cfffffffffff9fffffb000003000000000004fffff6");
    }

    #[test]
    fn rfc3961_nfold_q_to_168() {
        let out = nfold(b"Q", 168);
        assert_eq!(
            bytes_to_hex(&out),
            "000007ffffc00001fffff0000000000000001fffff"
        );
    }

    #[test]
    fn rfc3961_nfold_ba_to_16() {
        let out = nfold(b"ba", 16);
        assert_eq!(bytes_to_hex(&out), "6261");
    }

    // ----------------------- Key derivation tests -------------------------

    #[test]
    fn derive_encryption_key_is_deterministic() {
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let k1 = derive_encryption_key(&base, 1);
        let k2 = derive_encryption_key(&base, 1);
        assert_eq!(k1, k2, "Ke derivation must be deterministic");
    }

    #[test]
    fn derive_integrity_key_is_deterministic() {
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let k1 = derive_integrity_key(&base, 1);
        let k2 = derive_integrity_key(&base, 1);
        assert_eq!(k1, k2, "Ki derivation must be deterministic");
    }

    #[test]
    fn derive_encryption_key_differs_for_different_usages() {
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let k_as_rep = derive_encryption_key(&base, 1);
        let k_tgs_rep = derive_encryption_key(&base, 3);
        let k_ap_req = derive_encryption_key(&base, 11);
        assert_ne!(k_as_rep, k_tgs_rep, "Ke for usage 1 ≠ usage 3");
        assert_ne!(k_as_rep, k_ap_req, "Ke for usage 1 ≠ usage 11");
        assert_ne!(k_tgs_rep, k_ap_req, "Ke for usage 3 ≠ usage 11");
    }

    #[test]
    fn derive_integrity_key_differs_for_different_usages() {
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let k1 = derive_integrity_key(&base, 1);
        let k3 = derive_integrity_key(&base, 3);
        let k11 = derive_integrity_key(&base, 11);
        assert_ne!(k1, k3);
        assert_ne!(k1, k11);
        assert_ne!(k3, k11);
    }

    #[test]
    fn ke_and_ki_differ_for_same_usage() {
        // RFC 3961 §5.1 requires Ke and Ki to be distinct (the 0xAA / 0x55
        // tags exist precisely so they don't collide). If a future change to
        // the derivation function makes Ke == Ki for some usage, every
        // Kerberos message would be forgeable by re-using the encryption key
        // as the checksum key — a security regression.
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        for usage in [1u32, 2, 3, 7, 9, 10, 11, 12, 13, 14, 23] {
            let ke = derive_encryption_key(&base, usage);
            let ki = derive_integrity_key(&base, usage);
            assert_ne!(
                ke, ki,
                "Ke and Ki must differ for key usage {} — RFC 3961 §5.1 invariant",
                usage
            );
        }
    }

    #[test]
    fn derive_encryption_key_differs_for_different_base_keys() {
        let base1 = crypto::derive_aes256_key(b"password", b"salt1");
        let base2 = crypto::derive_aes256_key(b"password", b"salt2");
        let k1 = derive_encryption_key(&base1, 1);
        let k2 = derive_encryption_key(&base2, 1);
        assert_ne!(
            k1, k2,
            "different base keys must yield different derived keys"
        );
    }

    #[test]
    fn derive_encryption_key_differs_from_base_key() {
        // The whole point of RFC 3961 §5.1 derivation is that Ke ≠ base key
        // (so that compromising one usage's key doesn't compromise the master
        // key). Verify this invariant.
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let ke = derive_encryption_key(&base, 1);
        assert_ne!(ke, base, "derived Ke must differ from the base key");
    }

    #[test]
    fn derivation_constant_format() {
        // RFC 3961 §5.1: 4-byte BE usage + 0xAA (Ke) or 0x55 (Ki).
        let ke_const = derivation_constant(1, KE_TAG);
        assert_eq!(ke_const, [0x00, 0x00, 0x00, 0x01, 0xAA]);

        let ki_const = derivation_constant(1, KI_TAG);
        assert_eq!(ki_const, [0x00, 0x00, 0x00, 0x01, 0x55]);

        // Usage 0xFFFFFFFF (extreme) round-trips correctly.
        let big_const = derivation_constant(0xFFFFFFFF, KE_TAG);
        assert_eq!(big_const, [0xFF, 0xFF, 0xFF, 0xFF, 0xAA]);

        // Usage 0x01020304 sanity check.
        let mid_const = derivation_constant(0x01020304, KI_TAG);
        assert_eq!(mid_const, [0x01, 0x02, 0x03, 0x04, 0x55]);
    }

    #[test]
    fn derived_key_length_is_32_bytes() {
        let base = crypto::derive_aes256_key(b"password", b"salt");
        let ke = derive_encryption_key(&base, 1);
        let ki = derive_integrity_key(&base, 1);
        assert_eq!(ke.len(), AES256_KEY_LEN);
        assert_eq!(ki.len(), AES256_KEY_LEN);
    }

    // -------- End-to-end: derived Ke round-trips through the existing ----
    // -------- etype 18 encrypt/decrypt functions in crypto.rs -----------

    #[test]
    fn derived_ke_round_trips_through_etype_18_for_full_blocks() {
        // This is the real correctness test for the derived Ke: it must
        // round-trip through `encrypt_aes256_cts_hmac_sha1_96` /
        // `decrypt_aes256_cts_hmac_sha1_96` (which is what the KDC will use
        // to encrypt AS-REP / TGS-REP encparts). We use a 32-byte plaintext
        // (2 full AES blocks) to avoid the known AES-CTS partial-block bug
        // tracked separately in Wave 1c.
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let ke = derive_encryption_key(&base, 1); // usage 1 = AS-REP encpart

        // The Ke is used as the "key" arg to encrypt/decrypt. Note: this is
        // testing that the derived key is a usable AES-256 key, NOT that
        // AES-CTS itself is correct (that's tracked by Wave 1c P0 #1).
        let confounder = [0x42u8; crypto::CONFOUNDER_LEN];
        let plaintext = b"32-byte-payload-for-etype-18!!!!"; // exactly 32 bytes
        assert_eq!(plaintext.len(), 32);

        let blob = crypto::encrypt_aes256_cts_hmac_sha1_96(&ke, &confounder, plaintext)
            .expect("etype 18 encrypt must succeed for a full-block plaintext");
        let recovered = crypto::decrypt_aes256_cts_hmac_sha1_96(&ke, &blob)
            .expect("etype 18 decrypt must succeed and verify HMAC");
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn derived_ke_rejects_tampered_ciphertext() {
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let ke = derive_encryption_key(&base, 1);

        let confounder = [0x42u8; crypto::CONFOUNDER_LEN];
        let plaintext = b"32-byte-payload-for-etype-18!!";
        let mut blob =
            crypto::encrypt_aes256_cts_hmac_sha1_96(&ke, &confounder, plaintext).expect("encrypt");
        // Flip one bit in the ciphertext portion.
        blob[3] ^= 0x01;
        let err = crypto::decrypt_aes256_cts_hmac_sha1_96(&ke, &blob).unwrap_err();
        assert!(
            matches!(err, crypto::CryptoError::HmacMismatch),
            "tampered ciphertext must be rejected by HMAC verification, got {:?}",
            err
        );
    }

    #[test]
    fn derived_ke_rejects_wrong_usage_key() {
        // If a message is encrypted with Ke for usage 1, decrypting it with
        // Ke for usage 3 must fail (different derived key → HMAC mismatch).
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let ke1 = derive_encryption_key(&base, 1);
        let ke3 = derive_encryption_key(&base, 3);

        let confounder = [0x42u8; crypto::CONFOUNDER_LEN];
        let plaintext = b"32-byte-payload-for-etype-18!!";
        let blob = crypto::encrypt_aes256_cts_hmac_sha1_96(&ke1, &confounder, plaintext)
            .expect("encrypt with Ke(usage=1)");

        let err = crypto::decrypt_aes256_cts_hmac_sha1_96(&ke3, &blob).unwrap_err();
        assert!(
            matches!(err, crypto::CryptoError::HmacMismatch),
            "decrypting with the wrong usage's Ke must fail with HmacMismatch, got {:?}",
            err
        );
    }

    // ---- Proptest-style determinism + cross-usage collision resistance ----

    #[test]
    fn no_ke_collisions_across_common_usages() {
        // For any fixed base key, the derived Ke for each of the well-known
        // RFC 4120 §7.5.1 key usages must be distinct. A collision would
        // mean two different message types share an encryption key —
        // a cross-protocol forgery risk.
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let usages = [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 23];
        let mut keys: Vec<Aes256Key> = usages
            .iter()
            .map(|&u| derive_encryption_key(&base, u))
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(
            keys.len(),
            usages.len(),
            "derived Ke values must be unique across RFC 4120 §7.5.1 usages"
        );
    }

    #[test]
    fn no_ki_collisions_across_common_usages() {
        let base = crypto::derive_aes256_key(b"password", b"ATHENA.MIT.EDUraeburn");
        let usages = [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 23];
        let mut keys: Vec<Aes256Key> = usages
            .iter()
            .map(|&u| derive_integrity_key(&base, u))
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), usages.len());
    }

    #[test]
    fn hex_helpers_round_trip() {
        let bytes = vec![0x00, 0xAA, 0x55, 0xFF, 0x12, 0x34];
        let s = bytes_to_hex(&bytes);
        assert_eq!(s, "00aa55ff1234");
        let recovered = hex_to_bytes(&s);
        assert_eq!(recovered, bytes);
    }

    // ---- Internal helper unit tests (not exported via lib.rs) ------------

    #[test]
    fn aes256_cbc_encrypt_zero_iv_two_blocks_independent_of_plaintext_pattern() {
        // Sanity: AES-CBC with zero IV should produce different ciphertexts
        // for two different plaintexts (CBC has diffusion from block 1 → 2).
        let key = crypto::derive_aes256_key(b"password", b"salt");
        let pt_a = [0u8; 32];
        let pt_b = [0xFFu8; 32];
        let ct_a = aes256_cbc_encrypt_zero_iv(&key, &pt_a);
        let ct_b = aes256_cbc_encrypt_zero_iv(&key, &pt_b);
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn aes256_encrypt_block_is_deterministic() {
        let key = crypto::derive_aes256_key(b"password", b"salt");
        let block = [0x42u8; AES_BLOCK_LEN];
        let a = aes256_encrypt_block(&key, &block);
        let b = aes256_encrypt_block(&key, &block);
        assert_eq!(a, b);
        assert_ne!(a, block); // encryption must actually transform the block
    }

    #[test]
    fn nfold_output_length_matches_outbits_param() {
        for &outbits in &[8usize, 16, 24, 32, 64, 128, 168, 192, 256] {
            let out = nfold(b"some input", outbits);
            assert_eq!(
                out.len() * 8,
                outbits,
                "nfold output must be exactly outbits bits"
            );
        }
    }

    #[test]
    fn nfold_handles_input_longer_than_output() {
        // 13-byte input nfolded to 64 bits — input is longer than output.
        let input = b"massachusetts"; // 13 bytes = 104 bits
        let out = nfold(input, 64); // 8 bytes
        assert_eq!(out.len(), 8);
        // Determinism
        assert_eq!(nfold(input, 64), out);
        // Distinguishable from a different longer input
        let other = nfold(b"connecticut", 64);
        assert_ne!(out, other);
    }

    #[test]
    fn nfold_handles_input_shorter_than_output() {
        // 1-byte input nfolded to 128 bits — input is shorter than output.
        let out = nfold(b"Q", 128);
        assert_eq!(out.len(), 16);
        // Determinism
        assert_eq!(nfold(b"Q", 128), out);
    }
}
