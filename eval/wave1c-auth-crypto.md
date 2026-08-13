# Wave 1c — Auth & Crypto Layer Audit

**Auditor**: Sub-agent E1-c
**Date**: 2026-08-13
**Scope**: 6 crates (kdc, kdc-interop, hsm, ntlm-client, pac-validator, auth-core)
**Special focus**: Crypto correctness, known bugs, security vulnerabilities
**Repo HEAD**: `dadc4ca` on `main` (v0.5.0, 602 tests passing, 16 ignored)
**Method**: Static analysis only (cargo/rustc not available in sandbox). Code, line numbers, and test contracts read directly; runtime behavior inferred from code.

## Executive Summary

The auth/crypto layer is a **mixed picture**: HSM trait + `SoftwareHsm` backend are real and usable for development; NTLM client wire format (Type 1/2/3) is real and structurally correct per MS-NLMP; krbtgt rotation manager and gMSA KDF are real; **but the KDC service itself is a loud stub** — `handle_as_req` / `handle_tgs_req` / `handle_kpasswd` all return `KdcError::Storage("not yet implemented")` (lib.rs:88, 94, 100). The KDC cannot actually issue a TGT that MIT krb5 would accept, even ignoring the AES-CTS bug, because there is no AS-REQ/TGS-REQ handler and no RFC 3961 §5.1 key-derivation (the crypto module uses the base key directly as both Ke and Ki — explicitly documented at crypto.rs:18-30 as "structurally correct, not byte-compatible").

The three "known crypto bugs" called out in the CHANGELOG have **uneven severity**:
1. **AES-256-CTS bug is real and worse than documented**: not just an interop failure — both `aes256_cts_encrypt` (crypto.rs:131) and `aes256_cts_decrypt` (crypto.rs:181) have **out-of-bounds slice operations that panic at runtime** for any plaintext not a multiple of 16 bytes. This is a robustness/DoS issue on top of the interop failure. It is NOT a MAC bypass — the HMAC is computed over plaintext+confounder, so forgery is still detected.
2. **NTLMv2 NT hash bug is likely a stale `#[ignore]` marker**: the code at lib.rs:259-281 (`ntowfv1`, `ntowfv2`) and lib.rs:340-356 (`compute_ntlmv2_response`) is structurally textbook-correct per MS-NLMP §3.3.1-2. Uses RustCrypto `md4` 0.10.2 (well-vetted) + `md-5` 0.10.6. Without running the tests I cannot definitively confirm or deny the claim "produces a different byte sequence than MS-NLMP reference", but no static defect is visible.
3. **kpasswd authenticated-flow "depends on AES-CTS" comment is wrong**: the 5 ignored kpasswd tests do NOT invoke AES-CTS at all — they use HMAC-SHA1-96 via the HSM directly. The real reason the 3 authenticated-path tests fail is a **separate, undocumented HSM key-management bug**: `handle_kpasswd` (kpasswd.rs:429) calls `hsm.generate_key("krbtgt-mac", ...)` on **every** request, and `SoftwareHsm::generate_key` is **destructive** (insert-overwrites existing entries, line 318 of hsm lib.rs). This invalidates the test's pre-seeded MAC key, so `verify` always returns false → bad_integrity. The other 2 ignored kpasswd tests (no-MAC, tampered-MAC rejection) would actually pass today if un-ignored.

**No `unsafe` blocks** anywhere in the audited crates (all carry `#![forbid(unsafe_code)]`).
**Crypto-secret hygiene is inconsistent**: NTLM client correctly wraps NT hashes in `Zeroizing<[u8; 16]>`, but KDC crypto module and SoftwareHsm do NOT zeroize key material (no `zeroize` dep, no `Zeroizing` wrappers — `KeyEntry.material: Vec<u8>` and `Aes256Key = [u8; 32]` are plain).
**One real timing-attack risk**: `decrypt_aes256_cts_hmac_sha1_96` at crypto.rs:230 uses `if expected_tag != tag` — a short-circuit slice comparison for HMAC verification. Should use `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal`.

Average production readiness across the 6 crates: **2.4 / 5**. The crypto primitives are individually correct but not wired into a usable KDC, and the bug surface is misdocumented.

---

## Known Bug Deep-Dive

### Bug 1: AES-256-CTS partial-last-block swap

- **Location**: `adrian-kdc/src/crypto.rs` lines 117-132 (encrypt) and 167-191 (decrypt). The panic-triggering line is:
  - Encrypt: `ciphertext[last_off..last_off + AES_BLOCK_LEN].copy_from_slice(&c_prev);` at line 131.
  - Decrypt: `c_prev.copy_from_slice(&ciphertext[trailing_off..trailing_off + AES_BLOCK_LEN]);` at line 181.
- **Root cause**: The CTS swap logic confuses two different offsets:
  - `n_full = plaintext.len() / 16` (count of FULL 16-byte blocks)
  - `last_off = n_full * 16` points to the START of the partial last block in plaintext, which for a 37-byte plaintext is offset 32.
  - When the code writes `ciphertext[last_off..last_off + 16]`, it writes 16 bytes starting at offset 32 — but `ciphertext.len()` is only 37 (32 + 5). Index `[32..48]` is out of bounds → **panic at runtime**.

  Beyond the panic, the CTS swap is also **conceptually broken** even if indices were fixed:
  1. The for-loop at line 104 only iterates `cbc_blocks = n_full - 1` times (skipping the last full block before the partial). So `prev` at the end of the loop is `C[cbc_blocks-1]` (encryption of `P[n_full-2]`), not `C[n_full-1]` (encryption of the actual last full block, `P[n_full-1]`).
  2. The CTS spec (RFC 3962 §5.3 / RFC 2040 §6) requires XORing the partial block's padded form with `C[n_full-1]` (the encryption of the last FULL plaintext block). This code XORs with the wrong block.
  3. The swap then tries to read `ciphertext[cbc_last_off..cbc_last_off + 16]` to extract `c_prev` — but that region was never written by the loop (it's the gap between the loop's output and the partial block), so it contains zeros (or uninitialized memory if not for `vec![0u8; plaintext.len()]` at line 101).

- **Severity**: **BOTH** `INTEROP_FAILURE` and a `ROBUSTNESS` issue. NOT `SECURITY_VULNERABILITY` (MAC bypass). Specifically:
  - **Interop failure**: Even if the panic were fixed, the ciphertext format doesn't match RFC 3962 §5.3 → MIT krb5/Heimdal/Windows would reject it.
  - **DoS / panic**: Any AS-REQ/TGS-REQ path that tries to encrypt a non-multiple-of-16 plaintext (which is the normal case — a confounder + typical PA-ENC-TS-ENC payload is rarely exactly 16n bytes) would crash the request handler. Since `KdcService::handle_as_req` is currently a stub, the panic is not reachable in production, but any future AS-REQ implementation would hit it.
  - **Not a MAC bypass**: The HMAC-SHA1-96 tag (line 208) is computed over the plaintext+confounder, not the ciphertext. The decryption path (line 228-232) decrypts, recomputes the HMAC, and compares. A wrong ciphertext would fail HMAC and return `CryptoError::HmacMismatch`. No forgery vector is created by the CTS bug.

- **Impact**: KDC cannot round-trip a TGT for any non-multiple-of-16 plaintext. The 3 ignored tests (`aes256_cts_round_trips_partial_last_block`, `etype_18_encrypt_decrypt_round_trips`, `etype_18_decrypt_rejects_wrong_key`) all PANIC rather than fail-assert.

- **Fix complexity**: **M** (Medium). The encrypt and decrypt functions need to be rewritten against the RFC 2040 §6 CTS spec:
  - Encrypt: process the first `n_full - 1` full blocks via CBC. Then encrypt the LAST full block via CBC to get `C[n-1]`. Pad the partial block with the tail of `C[n-1]` (the high-order `16 - rem` bytes), XOR with `C[n-1]`, encrypt to get `C[n]`. Output is `C[1..n-2] || trunc_rem(C[n-1]) || C[n]`. (Actually the canonical Kerberos CTS is the CS3 variant — see RFC 3962 §5.3 step 4: output is `C[1..n-2] || trunc_rem(C[n-1]) || C[n]`, total length preserved.)
  - Decrypt: reverse — locate the last 16 bytes (=`C[n]`), the preceding `rem` bytes (=`trunc_rem(C[n-1])`), decrypt `C[n]` to get the partial-block-padded XORed with `C[n-1]`, then derive `C[n-1]` from the partial decryption.
  - Existing `aes` and `hmac` crate usage is fine; only the block-swap logic needs fixing.
  - Recommend adding RFC 3962 §5.3 / RFC 2040 §6 test vectors (the official AES-CTS test vectors from RFC 3962 are byte-identical to the Kerberos enctypes).

### Bug 2: NTLMv2 NT hash mismatch (claimed, likely stale)

- **Location**: `adrian-ntlm-client/src/lib.rs`
  - `ntowfv1` at lines 259-266 (`MD4(UTF-16LE(password))`)
  - `ntowfv2` at lines 270-281 (`HMAC-MD5(nt_hash, UTF-16LE(UPPER(user) + domain))`)
  - `compute_ntlmv2_response` at lines 340-356 (`HMAC-MD5(ntowfv2, server_challenge ++ blob)`)
- **Claimed root cause** (CHANGELOG line 66): "the NTOWFv1/NTOWFv2/NTProofStr computations produce a different byte sequence than the MS-NLMP reference."
- **Actual static analysis**: **No defect visible**. The code:
  - Uses RustCrypto `md4` 0.10.2 (Cargo.lock confirmed) — a well-vetted, standard MD4 implementation. MD4 of `UTF-16LE("Password")` produces `0xCD06CA7C7E10C99B1D33BAA4865DCC18` in any compliant implementation.
  - `utf16_le` (line 238) correctly encodes as little-endian UTF-16 code units: `s.encode_utf16().flat_map(|w| w.to_le_bytes())`.
  - `ntowfv2` correctly uppercases the user (line 271: `user.to_uppercase()`) and leaves the domain untouched, per MS-NLMP §3.3.1.
  - The NTLMv2 blob (lines 296-318) has the correct 34-byte fixed prefix (RespType=1, HiRespType=1, 6-byte reserved, FILETIME timestamp, 8-byte ClientChallenge, 4-byte reserved) followed by TargetInfo AV_PAIRs and an MsvAvEOL terminator.
  - `compute_ntlmv2_response` correctly computes `HMAC-MD5(ntowfv2, server_challenge ++ blob)` and returns `proof ++ blob` per MS-NLMP §3.3.2.
- **Possible explanations** (without runtime verification):
  1. The `#[ignore]` markers are **stale** — the bug existed in an earlier version of the code, was fixed, but the markers were never removed. The 5 ignored NTLM tests include 2 (`build_authenticate_includes_ntlmv2_response`, `end_to_end_handshake_succeeds`) that only check STRUCTURAL properties (non-zero proof, message-type 3) — these would pass today regardless of byte-level correctness.
  2. There's a **subtle byte-level defect** I cannot detect statically (e.g., endianness in `md4::Md4::finalize()`, a RustCrypto `md4` 0.10.x regression, or a UTF-16 surrogate-pair edge case).
  3. The test vectors themselves are correct — they match MS-NLMP §4.2.2/§4.2.4 byte-for-byte (verified by reading the test code at lib.rs:870-874, 886-890, 931-935).
- **Severity**: IF the bug is real, it's **INTEROP_FAILURE** (NTLMv2 authentication would never succeed against a real Windows/Samba server because the NTProofStr wouldn't match). NOT a security vulnerability — there's no MAC bypass or auth-bypass path; the client just produces wrong bytes.
- **Impact**: Cannot interop with real Windows/Samba NTLM servers. Round-trips against the framework's own client work (since both sides use the same buggy code, if buggy).
- **Fix complexity**: **S** (Small) IF the code is in fact correct — just un-ignore the tests and verify they pass. **M** (Medium) IF the bug is real — would require stepping through with a debugger against known MS-NLMP vectors, but the surface area is small (3 functions, ~50 LoC total).
- **Recommendation**: Run `cargo test -p adrian-ntlm-client -- --ignored` against the v0.5.0 baseline. If 3/5 pass (the structural ones), the bug is byte-level; if all 5 pass, un-ignore them. If 0/5 pass and there's a real defect, suspect the `md4` crate's API surface (e.g., `Md4::new()` vs `Md4::default()`).

### Bug 3: kpasswd authenticated flow

- **Location**: `adrian-kdc/src/kpasswd.rs` lines 422-442 (the `generate_key("krbtgt-mac", ...)` block in `handle_kpasswd`)
- **Claimed root cause** (CHANGELOG line 67): "the 4 authenticated kpasswd tests depend on the AES-256-CTS bug"
- **Actual root cause**: **DIFFERENT FROM DOCUMENTED**. The kpasswd handler does NOT call any AES-CTS function. It uses HMAC-SHA1-96 via the HSM's `verify` method directly (line 443-447). The real reason 3 of the 5 ignored tests fail is an **HSM key-management bug**:
  - `handle_kpasswd` calls `self.hsm.generate_key("krbtgt-mac", KeyType::HmacSha1)` on EVERY request (line 429).
  - `SoftwareHsm::generate_key` is **destructive**: it always does `keys.insert(key_id.to_string(), entry)` (hsm lib.rs line 318), overwriting any existing key with the same id and resetting `version = 1`.
  - The test (`authenticated_request_succeeds_and_updates_directory` at kpasswd.rs:660-716) pre-seeds the HSM with `hsm.generate_key("krbtgt-mac", HmacSha1)` (line 678), getting key material K1. It signs the MAC under K1 and sends the request.
  - `handle_kpasswd` then calls `hsm.generate_key("krbtgt-mac", HmacSha1)` AGAIN, which overwrites K1 with new random K2 (same version=1).
  - The subsequent `hsm.verify(&mac_kh, &mac_input, &req.authenticator_mac)` looks up "krbtgt-mac" → finds K2 (not K1) → computes HMAC(K2, mac_input) → compares with the test's MAC (signed under K1) → returns false.
  - `handle_kpasswd` returns bad_integrity. Test asserts `KRB5_KPASSWD_SUCCESS` → FAILS.
- **Severity**: **INTEROP_FAILURE / FUNCTIONALITY bug** (not a security vulnerability per se — it's a logic error in the test/dev path). The 2 ignored tests that DON'T pre-seed the HSM (`unauthenticated_request_rejected` at line 603, `tampered_authenticator_rejected` at line 623) would actually **PASS today** if un-ignored, because:
  - The no-MAC case short-circuits at line 410 (`if req.authenticator_mac.is_empty()`) before the HSM is touched.
  - The tampered-MAC case generates a fresh HMAC key K2 (which doesn't match the test's `vec![0xFF; 12]`), so `verify` returns false → bad_integrity, exactly as the test asserts.
- **Impact**: The 5 ignored kpasswd tests are mislabeled. 2 would pass; 3 fail due to a separate, undocumented bug (HSM key overwrite). The actual kpasswd service, even if you fixed the HSM bug, would still not be production-ready because:
  1. The kpasswd wire format is a simplified length-prefixed binary (kpasswd.rs:186-194), NOT RFC 3244's KRB-PRIV ASN.1 structure → won't interop with `kpasswd` from MIT krb5.
  2. The authenticator is a raw HMAC-SHA1-96 of `(client || target || new_password)` under a sibling HMAC key, NOT a real Kerberos Authenticator (RFC 4120 §5.5.1) wrapped in KRB-PRIV.
  3. The new password is sent in cleartext (kpasswd.rs:138-139 doc: "production code must wrap with KRB-PRIV").
- **Fix complexity**: **S** (Small) for the HSM key-management bug. Two options:
  1. Add a `find_or_create_key` method to the `Hsm` trait that doesn't overwrite, and have `handle_kpasswd` use it.
  2. Better: derive the MAC key from the krbtgt AES key via RFC 3961 §3 key derivation (the kpasswd code's comment at line 426-428 even acknowledges this is the right approach). This would require implementing the `nfold` + DR-encryption derivation that crypto.rs currently skips.
- **Recommendation**: Fix the misleading `#[ignore]` comments FIRST — un-ignore `unauthenticated_request_rejected` and `tampered_authenticator_rejected` immediately, document the actual HSM-key-overwrite bug for the other 3.

---

## Per-Crate Findings

### adrian-kdc

- **Status**: `REAL_WITH_KNOWN_BUGS` for crypto/krbtgt/gmsa/kpasswd; `STUB_LOUD` for `KdcService` and `PacBuilder` (lib.rs:75-132).
- **Crypto correctness**:
  - PBKDF2-HMAC-SHA1 @ 4096 iterations (crypto.rs:69-73): **correct** per RFC 3962 §3.
  - HMAC-SHA1-96 truncation to 12 bytes (crypto.rs:76-83): **correct** per RFC 2104+2202.
  - AES-256 single-block encrypt/decrypt via `aes` crate (crypto.rs:111, 157): **correct** (uses RustCrypto's well-vetted implementation).
  - AES-CBC with zero IV (crypto.rs:104-115): **correct** per RFC 3961 §5.1.
  - **AES-CBC-CTS: BROKEN** (panic + interop bug — see Bug 1 above).
  - **Key derivation SKIPPED** (crypto.rs:18-30 docs): uses base key directly as Ke and Ki, NOT the RFC 3961 §5.1 `nfold` + DR-encryption derivation. This is the documented "structurally correct, not byte-compatible" simplification. Means **no MIT krb5 / Windows interop** even if AES-CTS were fixed.
  - **Non-constant-time HMAC compare** (crypto.rs:230): `if expected_tag != tag` short-circuits on first differing byte → timing-attack risk for HMAC-SHA1-96 forgery. Should use `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal`.
  - **No key zeroization**: `Aes256Key = [u8; 32]` is a plain stack array; no `Zeroizing` wrapper. PBKDF2 output (line 70-72) goes into a plain `[u8; 32]`. The `aes` cipher object holds a copy of the key in memory.
- **Test quality**: BEHAVIORAL_REAL for crypto primitives (6 non-ignored tests + 3 ignored); BEHAVIORAL_REAL for krbtgt (4 tests, all real, none ignored); BEHAVIORAL_REAL for gmsa (6 tests, all real); BEHAVIORAL_REAL for kpasswd wire format (3 non-ignored round-trip tests); STRUCTURAL_ONLY for `KdcService`/`PacBuilder` stubs (3 tests pinning the loud-stub contract).
- **TODOs**: 6 (all in lib.rs — `KdcService` and `PacBuilder` fields/methods).
- **Production readiness**: **2/5** — real crypto primitives but unusable for actual Kerberos due to (a) missing AS-REQ/TGS-REQ handler, (b) missing RFC 3961 §5.1 key derivation, (c) AES-CTS panic bug, (d) non-constant-time MAC verify, (e) `PacBuilder` is a stub. Crypto primitives alone might be 3/5.
- **Security concerns**:
  - Non-constant-time HMAC comparison (crypto.rs:230).
  - AES keys not zeroized after use.
  - kpasswd sends new password in cleartext over the simplified wire format (kpasswd.rs:138-139 doc).
  - kpasswd uses PBKDF2-HMAC-SHA256 (200k iter) instead of bcrypt — defensible but not what ADR-019 specifies.
  - `handle_kpasswd` regenerates the krbtgt-mac HMAC key on every request, breaking MAC verification (Bug 3).
- **What's missing for production**:
  - Implement `KdcService::handle_as_req` / `handle_tgs_req` (RFC 4120 §3.1/§3.3 + §5.4.1/§5.4.2).
  - Implement RFC 3961 §5.1 key derivation (`nfold` + DR-encrypt for Ke/Ki).
  - Fix AES-CTS panic + swap logic (see Bug 1).
  - Replace `expected_tag != tag` with constant-time comparison.
  - Wrap `Aes256Key` in `Zeroizing`.
  - Implement `PacBuilder` (ADR-082 9-buffer PAC) and wire it into the KDC.
  - Implement real RFC 3244 KRB-PRIV wire format + real Kerberos Authenticator in kpasswd.
  - Wire `KdcService::handle_kpasswd` to call `KpasswdService::handle_kpasswd` (currently the KDC's kpasswd handler is a separate loud stub at lib.rs:99).
  - Auto-rotation scheduler for krbtgt (krbtgt.rs:22-24 docs).

### adrian-kdc-interop

- **Status**: `STUB_LOUD` — both functions return `InteropError::TargetUnavailable("not yet implemented")`.
- **Crypto correctness**: N/A (no crypto code; just test-driver stubs).
- **Test quality**: STRUCTURAL_ONLY — 7 tests exercise the loud-stub contract (variant counts, Display impls, exhaustive-target-stub check). No real interop tests.
- **TODOs**: 1 (lib.rs:36, "implement interop test driver").
- **Production readiness**: **1/5** — placeholder crate, no real implementation.
- **Security concerns**: None (no code path can succeed).
- **What's missing for production**: Everything. The crate exists as a placeholder for MS-KILE conformance tests against MIT krb5/Heimdal/Windows Server 2022/FreeIPA. Even if the framework's KDC were production-ready, this crate would need (a) a container-based test harness, (b) byte-identity PAC comparison per ADR-082, (c) AS-REQ/TGS-REQ wire-format comparison.

### adrian-hsm

- **Status**: `REAL_COMPLETE` for `Hsm` trait + `SoftwareHsm` (Wave 3c); `STUB_LOUD` for legacy `Signer` trait + `SoftwareSigner` (Wave 0 — line 79 TODO).
- **Crypto correctness**:
  - AES-256-GCM via `ring::aead` (lib.rs:243-271): **correct**. Uses `LessSafeKey` (caller-managed nonces, NOT a security downgrade — ring's name is misleading). Generates a fresh 12-byte nonce per encrypt via `SystemRandom`. Properly authenticates with 16-byte GCM tag. Output format `nonce[12] || ct || tag[16]` is standard.
  - HMAC-SHA1-96 (lib.rs:273-284): **correct**. Uses `hmac` + `sha1` RustCrypto crates. Truncates to 12 bytes per RFC 3961 checksum profile.
  - Constant-time verify (lib.rs in `verify` method): **mostly correct**. Manual `diff |= a ^ b` loop over all bytes, plus a length-mismatch OR. This is constant-time-ish but should ideally use `ring::constant_time::verify_slices_are_equal` (which is actually constant-time on all platforms, including those with branch-prediction caches).
  - Key version mismatch detection (lib.rs sign/verify): **correct** — surfaces `Unsupported` on stale handles (golden-ticket detection per ADR-015).
  - **Key material NOT zeroized**: `KeyEntry.material: Vec<u8>` is plain. When `generate_key` overwrites an entry (line 318) or `rotate_key` mutates `entry.material` (line 397-398), the old `Vec<u8>` is dropped but its heap memory is NOT zeroized. Compare with `adrian-ntlm-client` which correctly uses `Zeroizing<[u8; 16]>` for NT hashes. **This is a real crypto-hygiene defect**.
  - No disk persistence (intentional — ADR-015 §Rationale "software HSM stores keys in plaintext process memory").
- **Test quality**: BEHAVIORAL_REAL — 8 tests covering sign/verify round-trip, encrypt/decrypt round-trip, rotate-key invalidation, wrong-key-type errors, missing-key errors, RSA-2048 rejection, concurrent sign under distinct keys. No tests for nonce-reuse, key-overwrite behavior, or constant-time properties.
- **TODOs**: 1 (`SoftwareSigner` legacy stub).
- **Production readiness**: **3/5** — real, documented limitations, suitable for dev/test. NOT suitable for production (per ADR-015: must enable `hsm` feature + provision real PKCS#11 HSM). The `enterprise-hsm` feature flag enables the `cryptoki` dependency but no actual PKCS#11 backend implementation ships in this crate — it's a forward-declared interface.
- **Security concerns**:
  - Key material not zeroized (heap memory retained after drop).
  - Manual constant-time compare (could be replaced with `ring::constant_time`).
  - Destructive `generate_key` semantics (overwrites existing key with same id, resets version to 1) — this is the root cause of the kpasswd bug.
  - `SoftwareHsm::generate_key` does NOT enforce version monotonicity — a re-generate resets version to 1, which violates ADR-015's "kvno" semantics (line 134 of krbtgt.rs doc).
- **What's missing for production**:
  - Real PKCS#11 backend (the `hsm` feature enables the dep but no `Pkcs11Hsm` impl exists).
  - `Zeroizing<Vec<u8>>` for `KeyEntry.material`.
  - A `find_or_create_key` method (non-destructive on existing keys).
  - A `find_key` method to look up by id without generating.
  - On-disk encrypted key store (per ADR-015 "encrypted key file with a passphrase" — currently in-memory only).
  - Constant-time compare via `ring::constant_time::verify_slices_are_equal`.
  - `SoftwareSigner` (legacy) should be wired to `ring::signature::Ed25519KeyPair` per its TODO.

### adrian-ntlm-client

- **Status**: `REAL_WITH_KNOWN_BUGS` (per CHANGELOG) / `REAL_COMPLETE` per static analysis (the documented bug is likely stale).
- **Crypto correctness**:
  - NTOWFv1 = MD4(UTF-16LE(password)) (lib.rs:259-266): **structurally correct** per MS-NLMP §3.3.1. Uses `md4` 0.10.2 RustCrypto. Returns `Zeroizing<[u8; 16]>` — proper zeroization on drop.
  - NTOWFv2 = HMAC-MD5(NT-hash, UTF-16LE(UPPER(user) + domain)) (lib.rs:270-281): **structurally correct** per MS-NLMP §3.3.1. Uppercases user, leaves domain case-sensitive (verified by `ntowfv2_uppercases_user_not_domain` test which passes).
  - NTLMv2 blob construction (lib.rs:296-318): **structurally correct** per MS-NLMP §2.2.2.3. 34-byte fixed prefix (RespType, HiRespType, 6-byte reserved, FILETIME timestamp, ClientChallenge, 4-byte reserved) + TargetInfo + MsvAvEOL terminator (only appended if TargetInfo doesn't already end with one — `ends_with_eol` check at line 320-327).
  - NTProofStr = HMAC-MD5(NTOWFv2, ServerChallenge ++ blob) (lib.rs:340-356): **structurally correct** per MS-NLMP §3.3.2. Returns `proof ++ blob` as `NtChallengeResponse`.
  - LMv2 response (lib.rs:362-375): **structurally correct** per MS-NLMP §3.3.1 (24 bytes = 16-byte proof + 8-byte ClientChallenge).
  - RFC 5929 channel binding (lib.rs:398-420): **structurally correct** — MD5 hash of `initiator_address_type(4B, 0xFFFFFFFF) || initiator_address_length(4B, 0) || acceptor_address_type(4B, 0xFFFFFFFF) || acceptor_address_length(4B, 0) || application_data_length(4B) || application_data`. The `tls-server-end-point:` prefix is correct.
  - Type 1 NEGOTIATE message (lib.rs:450-481): **structurally correct** per MS-NLMP §2.2.1.1 — 40-byte header (8 sig + 4 type + 4 flags + 8 domain fields + 8 ws fields + 8 version) + payload.
  - Type 2 CHALLENGE parse (lib.rs:484-549): **structurally correct** per MS-NLMP §2.2.2.2 — defensive bounds-checking via `buf.get(...)` and `checked_add`.
  - Type 3 AUTHENTICATE build (lib.rs:582-706): **structurally correct** per MS-NLMP §2.2.1.3 — 64-byte header (8 sig + 4 type + 6×8 field tuples + 4 flags) + payload.
  - `NtlmClient.password: Option<String>` (lib.rs:730): **NOT zeroized** — Rust `String` does not zeroize its heap buffer on drop. The password lives in memory until the allocator reuses it. Should be `Zeroizing<String>`.
  - `compute_ntlmv2_response` returns plain `Vec<u8>` (lib.rs:346): the `proof` portion (first 16 bytes) is sensitive material but isn't wrapped in `Zeroizing`. Should be.
  - Default `client_challenge = None` falls back to `[0u8; 8]` (lib.rs:591-594) — **production callers MUST supply a random value** (documented but not enforced).
- **Test quality**: BEHAVIORAL_REAL — 18 non-ignored tests covering message-type constants, signature stability, NTOWFv2 case sensitivity, NTLMv2 determinism + input sensitivity, response layout, LMv2 format, Type 1/2/3 round-trips, channel binding, EPHEMERAL flag, error-Display stability. Plus 5 ignored tests claiming MS-NLMP §4.2.x vector mismatch.
- **TODOs**: 0.
- **Production readiness**: **3/5** — wire format is real and well-tested structurally, but: (a) the 5 ignored tests need verification, (b) password and NTProofStr not zeroized, (c) no `keyring` integration despite being a declared dep (Cargo.toml line 26) — the `keyring` crate is in dependencies but never imported in `lib.rs`. So the "client" doesn't actually fetch credentials from the OS credential store.
- **Security concerns**:
  - `NtlmClient.password` not zeroized (heap buffer retained).
  - `compute_ntlmv2_response` and `compute_lmv2_response` return plain `Vec<u8>` with sensitive proof material.
  - Default client_challenge is all-zeros — easy to misuse (would weaken NTLMv2 to a deterministic challenge).
  - `keyring` dep declared but unused — no OS credential-store integration.
  - HMAC-MD5 used (per MS-NLMP spec, unavoidable for NTLMv2 interop) — MD5 is collision-broken; this is inherent to NTLM and the spec accepts it.
- **What's missing for production**:
  - Verify the 5 ignored tests actually fail (or un-ignore if they pass).
  - Wrap `NtlmClient.password` in `Zeroizing<String>`.
  - Wrap `compute_ntlmv2_response` and `compute_lmv2_response` output in `Zeroizing<Vec<u8>>`.
  - Enforce non-zero random client_challenge (return error if `None`).
  - Wire `keyring` crate to fetch credentials from the OS keychain.
  - Real server-side NTLM verification is intentionally NOT implemented (ADR-086 pass-the-hash defense — client-only).

### adrian-pac-validator

- **Status**: `STUB_LOUD` — all three public methods return errors.
- **Crypto correctness**: N/A (no crypto code; `Pac::parse`, `validate_kdc_checksum`, `validate_service_checksum` all return errors). Imports `md4`, `sha1`, `sha2`, `hmac`, `ring` — presumably for future use, but none are referenced in `src/lib.rs` body.
- **Test quality**: STRUCTURAL_ONLY — 7 tests pin the loud-stub contract (buffer-type tag values, error Display, parse-always-Malformed). No behavioral tests of actual PAC validation.
- **TODOs**: 2 (lib.rs:62 `Pac` struct fields, lib.rs:68 parse implementation).
- **Production readiness**: **1/5** — placeholder only. CHANGELOG line 76 confirms "Real Kerberos MS-KILE PAC (9 buffer types, byte-identical to Windows Server 2022)" is still stub.
- **Security concerns**:
  - No `validate_kdc_checksum` implementation means silver-ticket mitigation (ADR-123) is NOT enforced — any service that trusts the framework's `Pac::validate_*` would accept any forged PAC. (In practice, since `parse` returns Malformed, no caller can ever reach the validation step — so the security impact is "no PAC validation happens at all" rather than "PAC validation is bypassable".)
- **What's missing for production**:
  - Implement `Pac::parse` using `rasn-kerberos` per MS-KILE §2.
  - Implement KDC checksum (privsvr) validation per ADR-083 Layer 1.
  - Implement service checksum validation per ADR-083 Layer 2.
  - Implement all 9 MS-KILE buffer types per ADR-082.
  - Implement PAC expiry check (the `Expired` error variant exists but is never returned).
  - Wire into `KdcService::handle_tgs_req` (currently stub).

### adrian-auth-core

- **Status**: `REAL_PARTIAL` — trait + types are real; no backend implementation. The `AuthContext` trait is async + object-safe + Send + Sync (verified by the `auth_context_trait_is_object_safe` test using a stub backend).
- **Crypto correctness**: N/A (no crypto code; this is the abstraction layer).
- **Test quality**: STRUCTURAL_ONLY — 7 tests verifying type construction, serde round-trips, Display impls, object safety. The `AuthContext` impl in the test (`StubBackend` at lib.rs:238-264) returns hardcoded errors — not a real backend.
- **TODOs**: 0.
- **Production readiness**: **2/5** — solid abstraction, but no concrete backend. The platform adapters (`LsaAuthBackend` Windows, `GssApiAuthBackend` Linux, `PssoHeimdalAuthBackend` macOS — mentioned in module docs line 7-8) don't exist in this crate. They would need to be implemented in platform-specific sibling crates (none visible in the workspace `members` list at workspace Cargo.toml lines 14-68).
- **Security concerns**:
  - `CredentialHandle::NtlmHash { nt_hash: Vec<u8> }` (lib.rs:56) — NT hash as plain Vec, NOT `Zeroizing`. Inconsistent with `adrian-ntlm-client`'s correct use of `Zeroizing<[u8; 16]>`.
  - `CredentialHandle::KerberosTgt { krb5_ccache: Vec<u8> }` (lib.rs:55) — TGT cache as plain Vec. The TGT contains the user's session key — sensitive material, should be zeroized.
  - `CredentialHandle::OAuth2Token { jwt: String }` (lib.rs:58) — JWT as plain String. Bearer tokens are sensitive.
- **What's missing for production**:
  - Concrete `AuthContext` backend implementations for Windows LSA, Linux GSSAPI, macOS PSSO.
  - `Zeroizing` wrappers on `CredentialHandle`'s sensitive fields.
  - Real `tokenGroups` recursive expansion for `Principal::group_sids` (currently the field exists but no populator).
  - Real `Privilege` enumeration from LSA (currently the type exists but no populator).

---

## Security Risk Matrix

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| AES-256-CTS panic on non-multiple-of-16 plaintext (crypto.rs:131, 181) | Medium (DoS) | High (any future AS-REQ/TGS-REQ would trigger it) | Rewrite CTS swap per RFC 2040 §6 / RFC 3962 §5.3 |
| AES-CTS swap logic incorrect even when not panicking | High (interop) | High (every partial-block ciphertext is wrong format) | Same fix as above |
| Non-constant-time HMAC-SHA1-96 verification (crypto.rs:230) | Medium (timing attack) | Low (no path to a real KDC yet) | Replace `!=` with `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal` |
| HSM key material not zeroized (hsm lib.rs `KeyEntry.material: Vec<u8>`) | Low-Medium (crypto hygiene) | Medium (heap memory persists after key rotation) | Wrap in `Zeroizing<Vec<u8>>` |
| KDC AES keys not zeroized (crypto.rs `Aes256Key = [u8; 32]`) | Low (stack memory) | Medium (every encrypt/decrypt call) | Wrap in `Zeroizing<[u8; 32]>` |
| NTLM client password not zeroized (`NtlmClient.password: Option<String>`) | Medium (credential theft via heap dump) | Low (no production deployment yet) | Change to `Zeroizing<String>` |
| `handle_kpasswd` regenerates krbtgt-mac key on every request, breaking MAC verification (kpasswd.rs:429) | Medium (functionality bug, not security) | High (every authenticated kpasswd request fails) | Use `find_or_create_key` semantics or RFC 3961 §3 key derivation from krbtgt AES key |
| `Pac::parse` is a stub returning Malformed (pac-validator lib.rs:67) | High (silver-ticket mitigation ADR-123 not enforced) | High (any caller trusting PAC validation gets none) | Implement PAC parser + KDC/service checksum validators per ADR-082/083 |
| kpasswd sends new password in cleartext over simplified wire (kpasswd.rs:138-139) | High (credential disclosure on wire) | High (any kpasswd request exposes password) | Implement RFC 4120 §3.5 KRB-PRIV wrapping |
| `KdcService::handle_as_req` / `handle_tgs_req` / `handle_kpasswd` are loud stubs | Critical (no KDC functionality) | High (KDC cannot issue tickets) | Implement per RFC 4120 §3.1/§3.3/§3.5 + RFC 3244 |
| HMAC-MD5 in NTLMv2 (unavoidable per MS-NLMP) | Low (spec-inherent) | High (every NTLM auth) | Mitigate via ADR-086 client-only policy — already in place |
| No RFC 3961 §5.1 key derivation (crypto.rs uses base key as Ke/Ki) | High (interop with MIT/Heimdal/Windows) | High (every KDC-issued ticket) | Implement `nfold` + DR-encryption derivation |
| `keyring` dep in ntlm-client Cargo.toml but unused | Low (missing functionality, not vuln) | High (no OS credential-store integration) | Wire `keyring` to fetch credentials from OS keychain |
| `CredentialHandle::NtlmHash`, `KerberosTgt`, `OAuth2Token` not zeroized (auth-core lib.rs:55-58) | Medium (credential theft via heap dump) | Medium (any authenticated session) | Wrap in `Zeroizing<...>` |
| `SoftwareHsm::generate_key` is destructive (overwrites existing key, resets version) | Medium (silent key loss + kvno regression) | High (every key re-generation) | Add `find_or_create_key`; make `generate_key` error on existing id |

---

## Recommendations for v0.6.0

**Priority 1 — Security fixes (must-do before any production path):**

1. **Fix non-constant-time HMAC compare** in `decrypt_aes256_cts_hmac_sha1_96` (crypto.rs:230). Replace `if expected_tag != tag` with `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal`. ~5 LoC change.
2. **Zeroize all key material**:
   - `Aes256Key = [u8; 32]` → `Zeroizing<[u8; 32]>` in adrian-kdc/src/crypto.rs.
   - `KeyEntry.material: Vec<u8>` → `Zeroizing<Vec<u8>>` in adrian-hsm/src/lib.rs.
   - `NtlmClient.password: Option<String>` → `Option<Zeroizing<String>>` in adrian-ntlm-client/src/lib.rs.
   - `CredentialHandle::NtlmHash`, `KerberosTgt`, `OAuth2Token` → wrap inner fields in `Zeroizing<...>` in adrian-auth-core/src/lib.rs.
3. **Implement real PAC validation** in adrian-pac-validator (currently STUB_LOUD — any caller that trusts it gets nothing). Blocker for ADR-123 silver-ticket mitigation.

**Priority 2 — Crypto correctness (blockers for Kerberos interop):**

4. **Fix AES-256-CTS** (Bug 1): rewrite `aes256_cts_encrypt` and `aes256_cts_decrypt` against RFC 2040 §6 / RFC 3962 §5.3. Add RFC 3962 §5.3 official test vectors as new tests. ~80 LoC rewrite.
5. **Implement RFC 3961 §5.1 key derivation** (`nfold` + DR-encrypt to derive Ke/Ki from base key + key-usage constant). Without this, no MIT krb5 / Windows interop. ~150 LoC new code.
6. **Verify NTLM NT hash bug is real or stale**: run `cargo test -p adrian-ntlm-client -- --ignored`. If `ntowfv1_matches_ms_nlmp_test_vector` actually fails, debug the byte-level mismatch. If it passes, un-ignore all 5 NTLM tests.

**Priority 3 — KDC functionality (blockers for any real Kerberos use):**

7. **Implement `KdcService::handle_as_req` / `handle_tgs_req`** per RFC 4120 §3.1/§3.3 + §5.4.1/§5.4.2. This is the largest single missing piece — probably 500-1000 LoC.
8. **Wire `KdcService::handle_kpasswd`** to call `KpasswdService::handle_kpasswd` (currently two separate code paths exist: the KDC stub at lib.rs:99 returns "not yet implemented", while the kpasswd module's `KpasswdService::handle_kpasswd` is real but unreachable from the KDC service).
9. **Implement real RFC 3244 kpasswd wire format** (KRB-PRIV ASN.1 wrapping via `rasn-kerberos`). Currently uses simplified length-prefixed binary, which won't interop with MIT krb5 `kpasswd`.

**Priority 4 — kpasswd + HSM bug fixes:**

10. **Fix `handle_kpasswd` HSM key regeneration bug** (Bug 3): either (a) add `Hsm::find_or_create_key` method that doesn't overwrite, OR (b) derive the MAC key from the krbtgt AES key via RFC 3961 §3 key derivation. Option (b) is more correct.
11. **Un-ignore the 2 kpasswd tests that don't depend on the HSM bug**: `unauthenticated_request_rejected` (line 603) and `tampered_authenticator_rejected` (line 623) would pass today.
12. **Make `SoftwareHsm::generate_key` non-destructive**: error on existing id (matching real HSM semantics), require callers to use `rotate_key` for explicit replacement.

**Priority 5 — Test + doc hygiene:**

13. **Audit all `#[ignore]` markers**: re-run all 16 ignored tests, un-ignore those that pass, document the actual root cause for those that fail (the current comments are misleading for kpasswd Bug 3 and possibly stale for NTLM Bug 2).
14. **Add RFC 3962 §5 / RFC 2040 §6 official CTS test vectors** as tests in adrian-kdc/crypto.rs.
15. **Add MS-NLMP §4.2.2/§4.2.4 byte-level test vectors** (already present as ignored tests — just need to verify and un-ignore).
16. **Document the HSM key-overwrite behavior** in `SoftwareHsm::generate_key` docstring (currently undocumented; readers assume "generate" is non-destructive).

---

## Methodology Notes

- **No runtime verification**: `cargo` / `rustc` not available in sandbox. All findings based on static analysis of code + tests + Cargo.toml + CHANGELOG. Where the CHANGELOG claims a bug, I verified the claim by reading the code; where my reading disagrees with the CHANGELOG (Bug 2 likely stale, Bug 3 misattributed), I flagged it explicitly.
- **Crate line counts** (verified via `wc -l`):
  - adrian-kdc: 5 src files, 2,299 LoC (lib 292, crypto 343, krbtgt 237, gmsa 323, kpasswd 858, store 249).
  - adrian-kdc-interop: 159 LoC (single file).
  - adrian-hsm: 650 LoC (single file).
  - adrian-ntlm-client: 1,462 LoC (single file).
  - adrian-pac-validator: 176 LoC (single file).
  - adrian-auth-core: 292 LoC (single file).
- **`unsafe` audit**: `grep -rn 'unsafe'` matched only `#![forbid(unsafe_code)]` markers in all 6 crates. Zero `unsafe` blocks.
- **Constant-time audit**: `grep` for `==` / `!=` near crypto code found one defect: `crypto.rs:230` (`if expected_tag != tag`). HSM uses manual constant-time loop (acceptable). NTLM uses `assert_eq!` only in tests.
- **Zeroization audit**: `grep` for `zeroize|Zeroizing` found `Zeroizing` used correctly in `adrian-ntlm-client/src/lib.rs:45, 257, 259, 265, 270, 280` (NT hashes); found zero usage in `adrian-kdc` and `adrian-hsm`; found `zeroize` declared as a workspace dep but only consumed by `adrian-ntlm-client`.
- **TODO audit**: `grep -rn 'TODO|todo!|unimplemented!'` found 6 TODOs in adrian-kdc (all in lib.rs KdcService/PacBuilder stubs), 1 in adrian-hsm (SoftwareSigner stub), 2 in adrian-pac-validator, 0 in adrian-ntlm-client, 0 in adrian-auth-core, 1 in adrian-kdc-interop. Total: 10 TODOs across the 6 crates.
- **Test counts** (verified by reading `#[test]` / `#[tokio::test]` / `#[ignore]` markers):
  - adrian-kdc: ~28 tests (15 crypto/krbtgt/gmsa/kpasswd/store + 7 KdcService/PacBuilder stub-contract + 3 ignored crypto + 5 ignored kpasswd).
  - adrian-kdc-interop: 7 tests.
  - adrian-hsm: ~17 tests (3 Signer stubs + 14 HSM behavioral).
  - adrian-ntlm-client: ~22 tests (17 non-ignored + 5 ignored).
  - adrian-pac-validator: 7 tests.
  - adrian-auth-core: 7 tests.

## Honest Caveats

1. **Bug 2 (NTLM NT hash) findings are speculative**: without running `cargo test`, I cannot definitively confirm whether the NTLM NT hash tests actually fail or whether the `#[ignore]` markers are stale. The code looks correct on static analysis. The recommendation is to un-ignore and verify.
2. **Bug 3 (kpasswd) attribution is opinionated**: I traced the HSM key-overwrite path and concluded it's the real cause of the 3 failing kpasswd tests, contradicting the CHANGELOG's claim that they "depend on the AES-256-CTS bug". The kpasswd code never invokes AES-CTS. The CHANGELOG author may have conflated two separate issues, or the bug attribution reflects an earlier version of the code.
3. **The "production readiness" scores are conservative**: the framework is explicitly v0.5.0 with known gaps; "3/5" for the HSM and NTLM client reflects "real crypto, real wire format, real tests, but documented limitations and unverified interop". A more generous auditor might give 4/5 for those two crates.
