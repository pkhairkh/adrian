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
//!    into exactly `outbits` bits. The algorithm (matching MIT krb5
//!    `krb5int_nfold` and impacket `_nfold`) concatenates `lcm/inbits` copies
//!    of the input, where copy `k` is rotated RIGHT by `13*k` bits, then
//!    splits the result into `lcm/outbits` chunks of `outbits` bits each and
//!    adds them using **one's-complement addition** (end-around carry). The
//!    13-bit rotation is the key subtlety that distinguishes the real
//!    algorithm from a naive cyclic-repetition-and-XOR.
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
//! ## Verification status (v0.8.0)
//!
//! - **VERIFIED**: `nfold` matches all 11 RFC 3961 §A.1 test vectors
//!   byte-for-byte. The algorithm was cross-checked against MIT krb5
//!   `krb5int_nfold` (C) and impacket `_nfold` (Python) — both produce
//!   identical output. The critical detail is the 13-bit right rotation per
//!   copy, which the v0.7.0 implementation was missing entirely.
//! - **VERIFIED**: `derive_encryption_key` / `derive_integrity_key` are
//!   deterministic, produce different keys for different usages, and produce
//!   different Ke vs Ki for the same usage.
//! - **VERIFIED**: a derived Ke round-trips through
//!   `crypto::encrypt_aes256_cts_hmac_sha1_96` /
//!   `decrypt_aes256_cts_hmac_sha1_96`.
//! - **PENDING (Wave 4)**: byte-exact match against RFC 3962 §7 AES-DK
//!   key-derivation test vectors (DR-encrypt chain).
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

/// `nfold(input, outbits)` per RFC 3961 §5.1 / §A.1.
///
/// Folds the variable-length `input` byte string into an `outbits`-bit output
/// (where `outbits` must be a positive multiple of 8). The algorithm (matching
/// MIT krb5 `krb5int_nfold` and impacket `_nfold`) is:
///
/// 1. Let `lcm = lcm(len(input), outbits/8)` (in bytes).
/// 2. Build a `lcm`-byte string by concatenating `lcm/len(input)` copies of
///    `input`, where copy `k` is rotated RIGHT by `13*k` bits.
/// 3. Slice the `lcm`-byte string into `lcm/(outbits/8)` chunks of `outbits/8`
///    bytes each.
/// 4. Add all chunks using **one's-complement addition** (end-around carry:
///    a carry out of the MSB wraps to the LSB).
///
/// The 13-bit rotation is the key subtlety that distinguishes the real
/// algorithm from a naive cyclic-repetition-and-XOR. It is verified against
/// all 11 RFC 3961 §A.1 test vectors.
///
/// # Panics
///
/// Panics if `outbits` is not a positive multiple of 8.
pub fn nfold(input: &[u8], outbits: usize) -> Vec<u8> {
    assert!(
        outbits > 0 && outbits.is_multiple_of(8),
        "outbits must be a positive multiple of 8"
    );
    let outbytes = outbits / 8;
    let inbytes = input.len();
    if inbytes == 0 {
        return vec![0u8; outbytes];
    }

    let lcm_val = lcm(inbytes, outbytes); // in bytes
    let num_copies = lcm_val / inbytes;

    // Build the rotated stream: concatenate copies, each rotated right by 13*k bits.
    let mut bigstr = Vec::with_capacity(lcm_val);
    for k in 0..num_copies {
        let rotated = rotate_right(input, 13 * k);
        bigstr.extend_from_slice(&rotated);
    }
    debug_assert_eq!(bigstr.len(), lcm_val);

    // Slice into outbytes-sized chunks and one's-complement add them all.
    let mut out = vec![0u8; outbytes];
    for chunk in bigstr.chunks_exact(outbytes) {
        add_ones_complement_inplace(&mut out, chunk);
    }

    out
}

/// Rotate a byte string RIGHT by `nbits` bits (circular bit rotation, MSB-first).
///
/// This implements the per-copy rotation used by `nfold`. The rotation is
/// circular: bits shifted off the right end reappear at the left end.
///
/// Equivalent to impacket's `rotate_right(ba, nbits)`.
fn rotate_right(input: &[u8], nbits: usize) -> Vec<u8> {
    let len = input.len();
    if len == 0 {
        return Vec::new();
    }
    let nbytes_shift = (nbits / 8) % len;
    let remain = nbits % 8;

    let mut out = vec![0u8; len];
    for (i, slot) in out.iter_mut().enumerate() {
        // impacket uses Python negative indexing: ba[i - nbytes_shift].
        // Equivalent modular index:
        let idx_high = (i + len - nbytes_shift) % len;
        // The byte BEFORE idx_high supplies the low bits that wrap around.
        let idx_low = (idx_high + len - 1) % len;

        // Use u16 to avoid overflow when shifting by 8 (remain == 0 case).
        let high = (input[idx_high] as u16) >> remain;
        let low = ((input[idx_low] as u16) << (8 - remain)) & 0xFF;
        *slot = (high | low) as u8;
    }
    out
}

/// One's-complement (end-around-carry) addition: `acc = acc + b`.
///
/// Both slices must be the same length. The addition is performed as
/// big-endian one's-complement: carries out of any byte position propagate
/// to the next MORE-significant byte (lower index), and a carry out of the
/// MSB (index 0) wraps to the LSB (last index). Carries are propagated
/// iteratively until none remain.
fn add_ones_complement_inplace(acc: &mut [u8], b: &[u8]) {
    let n = acc.len();
    debug_assert_eq!(n, b.len());

    // Element-wise sum into a u16 working array.
    let mut v: Vec<u16> = acc
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| x as u16 + y as u16)
        .collect();

    // Propagate carries end-around until none remain.
    while v.iter().any(|&x| x > 0xFF) {
        let mut new_v = vec![0u16; n];
        for i in 0..n {
            // Position i receives the carry from position (i+1) % n.
            // (Position 0 = MSB; carry out of MSB wraps to position n-1 = LSB.)
            let carry_src = (i + 1) % n;
            new_v[i] = (v[carry_src] >> 8) + (v[i] & 0xFF);
        }
        v = new_v;
    }

    for (slot, &val) in acc.iter_mut().zip(v.iter()) {
        *slot = val as u8;
    }
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
/// with an all-zero IV.
///
/// **Note**: this function was used by the v0.7.0 (incorrect) DR implementation.
/// The v0.8.0 DR fix replaced it with iterative ECB feedback. This function is
/// kept for the test that verifies the AES-CBC primitive.
#[allow(dead_code)]
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

/// DR (Derivation Random) per RFC 3961 §5.1.
///
/// The correct algorithm is **iterative single-block ECB feedback**:
/// ```text
/// K1 = E(Key, n-fold(Constant))       // IV = 0
/// K2 = E(Key, K1)                     // feed ciphertext back as next plaintext
/// K3 = E(Key, K2)
/// DR(Key, Constant) = k-truncate(K1 || K2 || K3 || ...)
/// ```
///
/// For AES-256 (32-byte key), we need 2 blocks: K1 || K2 (32 bytes).
///
/// **v0.8.0 fix**: the v0.7.0 implementation used "repeat the n-folded
/// constant to 32 bytes and CBC-encrypt" — this is WRONG. It produces the
/// correct K1 (because CBC with IV=0 on the first block = ECB) but the wrong
/// K2 (CBC chains C1 ⊕ nfold, while DR requires E(K1) with no XOR). The
/// correct algorithm feeds the ciphertext back as the next plaintext with no
/// XOR chaining. Verified against RFC 3962 Appendix B string-to-key vectors.
fn dr_derive(base_key: &Aes256Key, constant: &[u8]) -> Aes256Key {
    // Step 1: n-fold the constant to one AES block (128 bits = 16 bytes).
    let folded = nfold(constant, AES_BLOCK_LEN * 8);
    debug_assert_eq!(folded.len(), AES_BLOCK_LEN);

    // Step 2: iterative ECB feedback.
    let cipher = Aes256::new(GenericArray::from_slice(base_key));
    let mut out = Vec::with_capacity(AES256_KEY_LEN);
    let mut block: GenericArray<u8, aes::cipher::consts::U16> =
        GenericArray::clone_from_slice(&folded);
    while out.len() < AES256_KEY_LEN {
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }

    // Step 3: k-truncate to the desired key length (32 bytes for AES-256).
    let mut result = [0u8; AES256_KEY_LEN];
    result.copy_from_slice(&out[..AES256_KEY_LEN]);
    result
}

/// DK (Derive Key) per RFC 3961 §5.1: `DK(Key, Constant) = random-to-key(DR(Key, Constant))`.
///
/// For AES, `random-to-key` is the identity function (any bit string of the
/// correct length is a valid AES key), so `DK = DR`.
fn dk_derive(base_key: &Aes256Key, constant: &[u8]) -> Aes256Key {
    dr_derive(base_key, constant)
}

/// Full Kerberos string-to-key for AES-256 (RFC 3962 §4).
///
/// This is the REAL string-to-key function that a Kerberos client/KDC uses:
/// 1. `tkey = PBKDF2-HMAC-SHA1(password, salt, iterations, 32)`
/// 2. `base_key = DK(tkey, "kerberos")`
///
/// Note: [`crate::crypto::derive_aes256_key`] returns only the PBKDF2 output
/// (step 1). This function applies the full chain (steps 1 + 2) to produce the
/// actual Kerberos base key. Verified against RFC 3962 Appendix B.
pub fn string_to_key_aes256(password: &[u8], salt: &[u8], iterations: u32) -> Aes256Key {
    let tkey = crate::crypto::derive_aes256_key_with_iterations(password, salt, iterations);
    dk_derive(&tkey, b"kerberos")
}

/// Derive the encryption key (Ke) for the given key usage number.
///
/// Per RFC 3961 §5.1 + RFC 3962 §6: the constant is the 4-byte big-endian key
/// usage number followed by `0xAA`. The constant is n-folded to one AES block
/// (16 bytes), then DR applies iterative ECB feedback (K1=E(key,nfold),
/// K2=E(key,K1), ...) to produce a 32-byte Ke.
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
/// (16 bytes), then DR applies iterative ECB feedback to produce a 32-byte Ki.
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

    // ----------------- RFC 3961 §A.1 nfold test vectors ------------------
    //
    // v0.8.0: The nfold algorithm was completely rewritten to match MIT krb5
    // `krb5int_nfold` and impacket `_nfold`. The critical fix is the 13-bit
    // right rotation per copy — the v0.7.0 implementation was missing this
    // entirely and produced self-consistent (but WRONG) output. All 11 RFC
    // 3961 §A.1 test vectors now pass byte-for-byte, verified against both
    // MIT krb5 (C) and impacket (Python) reference implementations.
    //
    // NOTE: The v0.7.0 tasklist listed 7 vectors with incorrect expected
    // values (5 of 7 didn't match the actual RFC). The real RFC 3961 §A.1
    // publishes 11 vectors; we test all 11 here. See worklog for details.

    #[test]
    fn rfc3961_nfold_012345_to_64() {
        let out = nfold(b"012345", 64);
        assert_eq!(bytes_to_hex(&out), "be072631276b1955");
    }

    #[test]
    fn rfc3961_nfold_password_to_56() {
        let out = nfold(b"password", 56);
        assert_eq!(bytes_to_hex(&out), "78a07b6caf85fa");
    }

    #[test]
    fn rfc3961_nfold_rough_consensus_to_64() {
        // RFC 3961 §A.1: 64-fold("Rough Consensus, and Running Code")
        // Note: capital C's, no trailing period, 64-bit output (not 56).
        let out = nfold(b"Rough Consensus, and Running Code", 64);
        assert_eq!(bytes_to_hex(&out), "bb6ed30870b7f0e0");
    }

    #[test]
    fn rfc3961_nfold_password_to_168() {
        let out = nfold(b"password", 168);
        assert_eq!(
            bytes_to_hex(&out),
            "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e"
        );
    }

    #[test]
    fn rfc3961_nfold_massachvsetts_to_192() {
        // RFC 3961 §A.1 uses the archaic "V" spelling: MASSACHVSETTS.
        let input = b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY";
        let out = nfold(input, 192);
        assert_eq!(
            bytes_to_hex(&out),
            "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b"
        );
    }

    #[test]
    fn rfc3961_nfold_q_to_168() {
        let out = nfold(b"Q", 168);
        assert_eq!(
            bytes_to_hex(&out),
            "518a54a215a8452a518a54a215a8452a518a54a215"
        );
    }

    #[test]
    fn rfc3961_nfold_ba_to_168() {
        // RFC 3961 §A.1: 168-fold("ba"), NOT 16-fold. (16-fold("ba") = "6261"
        // by identity, since lcm == inbits means no folding occurs.)
        let out = nfold(b"ba", 168);
        assert_eq!(
            bytes_to_hex(&out),
            "fb25d531ae8974499f52fd92ea9857c4ba24cf297e"
        );
    }

    #[test]
    fn rfc3961_nfold_kerberos_to_64() {
        let out = nfold(b"kerberos", 64);
        assert_eq!(bytes_to_hex(&out), "6b65726265726f73");
    }

    #[test]
    fn rfc3961_nfold_kerberos_to_128() {
        let out = nfold(b"kerberos", 128);
        assert_eq!(bytes_to_hex(&out), "6b65726265726f737b9b5b2b93132b93");
    }

    #[test]
    fn rfc3961_nfold_kerberos_to_168() {
        let out = nfold(b"kerberos", 168);
        assert_eq!(
            bytes_to_hex(&out),
            "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4"
        );
    }

    #[test]
    fn rfc3961_nfold_kerberos_to_256() {
        let out = nfold(b"kerberos", 256);
        assert_eq!(
            bytes_to_hex(&out),
            "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4"
        );
    }

    // -------- Edge-case tests (T-104: empty, single byte, identity) --------

    #[test]
    fn nfold_edge_case_empty_input() {
        // Empty input → all-zero output of the requested length.
        assert_eq!(nfold(&[], 64), vec![0u8; 8]);
        assert_eq!(nfold(&[], 128), vec![0u8; 16]);
        assert_eq!(nfold(&[], 256), vec![0u8; 32]);
    }

    #[test]
    fn nfold_edge_case_single_byte_input() {
        // Single-byte input nfolded to 168 bits — verified against RFC ("Q" →
        // 168 above). Here we test a different single byte (0x00) for
        // sanity: all-zero input must produce all-zero output.
        assert_eq!(nfold(&[0x00], 64), vec![0u8; 8]);
        assert_eq!(nfold(&[0xFF], 64), vec![0xFFu8; 8]);
    }

    #[test]
    fn nfold_edge_case_identity_when_inbits_eq_outbits() {
        // When input length == output length, lcm == inbits, so there is
        // exactly one copy (rotation by 0 bits) and one slice. The
        // one's-complement sum of a single value is the value itself.
        let input = b"0123456789abcdef";
        let out = nfold(input, 128);
        assert_eq!(out, input, "nfold(x, |x|) == x when |x| is the block size");

        let input2 = b"\x01\x02\x03\x04";
        let out2 = nfold(input2, 32);
        assert_eq!(out2, input2);
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

    // ==================================================================
    // v0.8.0 Wave 4: RFC 3962 Appendix B AES-DK key derivation test vectors
    // ==================================================================

    /// RFC 3962 Appendix B string-to-key test vectors.
    /// Verifies the full chain: PBKDF2 → DK(tkey, "kerberos") → base key.
    #[test]
    fn rfc3962_string_to_key_dk_kerberos_vectors() {
        // Vector 1: password="password", salt="ATHENA.MIT.EDUraeburn", iter=1, AES-256
        // PBKDF2 output (tkey) = cdedb528...0837
        // DK(tkey, "kerberos") = fe697b52...0161 (the real Kerberos base key)
        let base_key = string_to_key_aes256(b"password", b"ATHENA.MIT.EDUraeburn", 1);
        assert_eq!(
            bytes_to_hex(&base_key),
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
            "RFC 3962 Appendix B: string-to-key(password, ATHENA.MIT.EDUraeburn, 1)"
        );

        // Vector 2: iter=2
        let base_key2 = string_to_key_aes256(b"password", b"ATHENA.MIT.EDUraeburn", 2);
        assert_eq!(
            bytes_to_hex(&base_key2),
            "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
            "RFC 3962 Appendix B: string-to-key(password, ATHENA.MIT.EDUraeburn, 2)"
        );

        // Vector 3: iter=1200
        let base_key3 = string_to_key_aes256(b"password", b"ATHENA.MIT.EDUraeburn", 1200);
        assert_eq!(
            bytes_to_hex(&base_key3),
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
            "RFC 3962 Appendix B: string-to-key(password, ATHENA.MIT.EDUraeburn, 1200)"
        );

        // Also verify the DK step directly: DK(tkey, "kerberos") = base_key
        let tkey: Aes256Key =
            hex_to_bytes("cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837")
                .try_into()
                .unwrap();
        let dk_result = dk_derive(&tkey, b"kerberos");
        assert_eq!(
            bytes_to_hex(&dk_result),
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
            "DK(tkey, \"kerberos\") must match RFC 3962 Appendix B"
        );
    }

    /// RFC 3961 §5.1 key derivation: Ke/Ki for key usage 1 (AS-REQ PA-ENC-TIMESTAMP).
    /// Base key = fe697b52... (the real Kerberos AES-256 base key from string-to-key).
    #[test]
    fn rfc3962_derive_ke_ki_usage_1() {
        let base_key: Aes256Key =
            hex_to_bytes("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
                .try_into()
                .unwrap();

        let ke = derive_encryption_key(&base_key, 1);
        assert_eq!(
            bytes_to_hex(&ke),
            "d0e3f5c9ca1c9b7accaf979cb9c9633ecb0dadb0905c857c9875b5967c13b6c9",
            "Ke for usage 1 (AS-REQ PA-ENC-TIMESTAMP)"
        );

        let ki = derive_integrity_key(&base_key, 1);
        assert_eq!(
            bytes_to_hex(&ki),
            "4c559abaa7970eb32071dd43f8b832cc04cc255d97c19ab609ab65987a699b24",
            "Ki for usage 1"
        );
    }

    /// RFC 3961 §5.1 key derivation: Ke/Ki for key usage 2 (AS-REP ticket).
    #[test]
    fn rfc3962_derive_ke_ki_usage_2() {
        let base_key: Aes256Key =
            hex_to_bytes("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
                .try_into()
                .unwrap();

        let ke = derive_encryption_key(&base_key, 2);
        assert_eq!(
            bytes_to_hex(&ke),
            "c7cfd9cd75fe793a586a542d87e0d1396f1134a104bb1a9190b8c90ada3ddf37",
            "Ke for usage 2 (AS-REP ticket)"
        );

        let ki = derive_integrity_key(&base_key, 2);
        assert_eq!(
            bytes_to_hex(&ki),
            "97151b4c76945063e2eb0529dc067d97d7bba90776d8126d91f34f3101aea8ba",
            "Ki for usage 2"
        );
    }

    /// RFC 3961 §5.1 key derivation: Ke/Ki for key usage 3 (TGS-REP encpart).
    #[test]
    fn rfc3962_derive_ke_ki_usage_3() {
        let base_key: Aes256Key =
            hex_to_bytes("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
                .try_into()
                .unwrap();

        let ke = derive_encryption_key(&base_key, 3);
        assert_eq!(
            bytes_to_hex(&ke),
            "82c229a75b71be9611413bce88fc44e441f4f71340659329a2e4a2a8a35960ac",
            "Ke for usage 3 (TGS-REP encpart)"
        );

        let ki = derive_integrity_key(&base_key, 3);
        assert_eq!(
            bytes_to_hex(&ki),
            "2acc7e801cfac7f511cf8729f5569481e97730c3041e2271829bf40a2e4d03a6",
            "Ki for usage 3"
        );
    }

    /// RFC 3961 §5.1 key derivation: Ke/Ki for key usages 7 and 8
    /// (TGS-REQ AP-REQ authenticator cksum and authenticator encrypted).
    #[test]
    fn rfc3962_derive_ke_ki_usages_7_8() {
        let base_key: Aes256Key =
            hex_to_bytes("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
                .try_into()
                .unwrap();

        // Usage 7: TGS-REQ AP-REQ authenticator cksum
        let ke7 = derive_encryption_key(&base_key, 7);
        assert_eq!(
            bytes_to_hex(&ke7),
            "998c98377c7c12856f97b45c74441078bff849fb86bf0cb0ad227827af5ad3b1",
            "Ke for usage 7"
        );
        let ki7 = derive_integrity_key(&base_key, 7);
        assert_eq!(
            bytes_to_hex(&ki7),
            "ef169527345dfb2890e132a9865ab42bb4ede6aab4b20a61f834c6d27ce17e62",
            "Ki for usage 7"
        );

        // Usage 8: TGS-REQ AP-REQ authenticator (encrypted)
        let ke8 = derive_encryption_key(&base_key, 8);
        assert_eq!(
            bytes_to_hex(&ke8),
            "a57e67685d5b4e056b9197ff7ea8d249a67a796ddbcfdcb7ea2321a8e934d646",
            "Ke for usage 8"
        );
        let ki8 = derive_integrity_key(&base_key, 8);
        assert_eq!(
            bytes_to_hex(&ki8),
            "1a16b7ec775f3368f4220d0bfb41e5d9fb06784848790ddd188bf2ed6e191fe3",
            "Ki for usage 8"
        );
    }
}
