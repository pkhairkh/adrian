# TASKLIST 01 — KDC Crypto & Wire Format

**Domain**: Kerberos cryptographic primitives + ASN.1/DER wire encoding
**Branch**: `domain-01-kdc-crypto`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-kdc/src/crypto.rs`
- `rust/crates/adrian-kdc/src/key_derivation.rs`
- `rust/crates/adrian-kdc/src/wire.rs`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `crypto.rs`: Real AES-CBC-CTS per RFC 2040 §6 CS3 variant (wire-compatible). 21 tests.
- `key_derivation.rs`: nfold uses one's-complement addition but **expected test values are self-consistent, NOT verified against RFC 3961 §A.1 reference vectors**. 7 tests un-ignored but with wrong expected values.
- `wire.rs`: rasn-kerberos ASN.1/DER encoding for AS-REQ/AS-REP/TGS-REQ/TGS-REP. 41 handler tests pass.

## Known Gaps

1. **nfold algorithm produces incorrect output** — the RFC 3961 §A.1 test vectors (e.g. `nfold("012345", 64)` should be `be072631276b1955`) don't match. Our implementation uses a resampling formula `b = (k * inbits / lcm) % inbits` that doesn't match MIT krb5's `k5_nfold`. The correct algorithm is documented in MIT krb5 `src/lib/crypto/krb/nfold.c`.
2. **No AES-CBC-CTS NIST CAVP test vectors** — the CTS implementation round-trips correctly but has not been verified against NIST CAVP CTS test vectors.
3. **No AES-128-CTS support** — only AES-256 is implemented; etype 17 (AES-128-CTS-HMAC-SHA1-96) uses the AES-256 path with truncation (incorrect).
4. **No SHA-384 etype (0x13)** — ADR-014 specifies AES-256-CTS-HMAC-SHA384-192 (etype 19/0x13) but it's not implemented.
5. **No constant-time PBKDF2** — timing side-channel on password verification.

---

## Wave 1: Fix nfold to match RFC 3961 §A.1

**DoD**: All 7 RFC 3961 §A.1 nfold test vectors pass with the CORRECT expected values (not self-consistent values). Verified against MIT krb5 reference.

### Tasks

- T-101: Study MIT krb5 `k5_nfold` source (available at `https://github.com/krb5/krb5/blob/master/src/lib/crypto/krb/nfold.c`). The algorithm processes bits from LCM-1 down to 1 (not 0 to LCM-1), uses a different bit-extraction formula, and carries differently.
- T-102: Rewrite `nfold()` in `key_derivation.rs` to match MIT krb5 byte-for-byte.
- T-103: Update the 7 RFC 3961 §A.1 test vectors with the correct expected values:
  - `nfold("012345", 64)` = `be072631276b1955`
  - `nfold("password", 56)` = `78a07b6caf85fa`
  - `nfold("Rough consensus, and running code.", 56)` = `bb6ed30870b20f`
  - `nfold("password", 168)` = `59e4a8ca7c22a2da58d528f1cf1c2c7c7c22a2da`
  - `nfold("massachusetts", 192)` = `c345bcb7eb9b5b5e5f1d7dca4e8d3c084e8d3c08`
  - `nfold("Q", 168)` = `515153515153515153515153515153515153515153`
  - `nfold("ba", 16)` = `6262`
- T-104: Add 3 new nfold edge-case tests (empty input, single byte, input == output length).
- T-105: Commit `Wave 1: Fix nfold to match RFC 3961 §A.1 / MIT krb5 (+3 tests)`

## Wave 2: AES-128-CTS + SHA-384 etype

**DoD**: Etype 17 (AES-128-CTS-HMAC-SHA1-96) and etype 19 (AES-256-CTS-HMAC-SHA384-192) fully implemented with test vectors.

### Tasks

- T-201: Implement `aes128_cts_encrypt`/`decrypt` using `Aes128` cipher (16-byte key).
- T-202: Implement `hmac_sha384_192` (HMAC-SHA-384 truncated to 24 bytes) for etype 19.
- T-203: Implement `encrypt_aes256_cts_hmac_sha384_192` / `decrypt_aes256_cts_hmac_sha384_192`.
- T-204: Add `EType::Aes128CtsHmacSha1_96` and `EType::Aes256CtsHmacSha384_192` to the crypto dispatch.
- T-205: Add 10 tests (5 per etype: round-trip, tamper detection, wrong key, various lengths, edge cases).
- T-206: Commit `Wave 2: AES-128-CTS + AES-256-CTS-HMAC-SHA384-192 etypes (+10 tests)`

## Wave 3: NIST CAVP test vectors + constant-time hardening

**DoD**: AES-CBC-CTS verified against NIST CAVP CTS test vectors. PBKDF2 is constant-time.

### Tasks

- T-301: Download NIST CAVP CTS test vectors (from NIST CVP project).
- T-302: Add a `cts_nist_cavp_vectors` test that reads the vectors and verifies all pass.
- T-303: Audit PBKDF2 for timing side-channels; use `ring::pbkdf2` if the current `pbkdf2` crate is not constant-time.
- T-304: Add a timing-attack regression test (verify HMAC comparison is constant-time).
- T-305: Commit `Wave 3: NIST CAVP CTS vectors + constant-time hardening (+5 tests)`

## Wave 4: RFC 3962 §7 AES-DK key derivation test vectors

**DoD**: DR-encrypt key derivation verified against RFC 3962 §7 test vectors.

### Tasks

- T-401: Add RFC 3962 §7 AES-DK test vectors (the `string-to-key` → `random-to-key` → `derive` chain).
- T-402: Verify `derive_key` produces the correct Ke/Ki for key usages 1, 2, 3, 7, 8.
- T-403: Add 5 tests covering the full key-derivation chain.
- T-404: Commit `Wave 4: RFC 3962 §7 AES-DK test vectors (+5 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-kdc --lib crypto` — all tests pass, 0 ignored
- `cargo test -p adrian-kdc --lib key_derivation` — all tests pass, 0 ignored (nfold vectors match RFC)
- `cargo clippy -p adrian-kdc -- -D warnings` clean
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
