# Wave 2a — Cross-Cutting Security Audit

**Auditor**: Sub-agent E2-a
**Date**: 2026-08-13
**Scope**: All 47 crates, cross-cutting security focus (attack surface, threat model, AD-baseline comparison, crypto correctness, secrets hygiene, supply chain)
**Repo HEAD**: `d4d714e` on `main` (v0.5.0)
**Method**: Static analysis only (no `cargo`/`rustc` in sandbox). Code, line numbers, test contracts, and Cargo manifests read directly; runtime behavior inferred from code. Wave 1a/1b/1c/1d findings consolidated and re-verified.

---

## Executive Summary

**Adrian's v0.5.0 security posture is "scaffolded but not enforced."** Every ADR-documented AD security control (RC4 refusal, LDAP signing/channel binding, SMB1 refusal, DCSync mitigation, silver ticket mitigation, SID history filtering, Kerberoasting mitigation, HSM-bound krbtgt) is *specified* and *referenced in code comments* but **none is actually enforced in code** — because every enforcement point (`KdcService::handle_as_req`, `KdcService::handle_tgs_req`, `Dsa::run` + `handle_search`, `SmbServer::serve`, `drs_get_nc_changes`, `Pac::parse` + `validate_*`, `migrate_sidhistory`) is a loud stub returning `NotImplemented`. The single exception is **pass-the-hash defense (ADR-086)**, which is structurally enforced *by absence* — no server-side NTLM code exists anywhere in the codebase, so there's nothing to pass a hash to.

Crypto correctness is **independently real but not wired**. The HSM (AES-256-GCM + HMAC-SHA1-96 via `ring`/`hmac`/`sha1`) is correct, including fresh random nonces per encrypt. The KDC's AES-256-CTS-HMAC-SHA1-96 etype 18 primitives are individually correct (PBKDF2-HMAC-SHA1@4096, HMAC-SHA1-96 truncation, AES-256 block cipher) but the AES-CTS swap logic panics on non-multiple-of-16 plaintexts (Wave 1c confirmed), and the RFC 3961 §5.1 `nfold`+DR key derivation is intentionally skipped (documented as "structurally correct, not byte-compatible" — meaning **no MIT krb5/Heimdal/Windows interop today**). The NTLMv2 client wire format is structurally correct per MS-NLMP, but 5 ignored tests claim MS-NLMP §4.2 vector mismatch (likely stale per Wave 1c, but unverified).

Three confirmed crypto-hygiene defects (all flagged by Wave 1c): (1) `crypto.rs:230` non-constant-time HMAC compare; (2) HSM `KeyEntry.material: Vec<u8>` not zeroized; (3) `NtlmClient.password: Option<String>` not zeroized. **Two new defects Wave 1c missed**: (4) `compute_ntlmv2_response` returns plain `Vec<u8>` (16-byte proof not zeroized); (5) `gmsa.rs` uses HSM `sign` (which truncates to HMAC-SHA1-96 → 12 bytes per block) for SP800-108 KDF blocks, producing non-standard 12-byte K(i) blocks instead of full 20-byte HMAC-SHA1 output per SP800-108 §5.1 — a subtle deviation from the standard KDF.

**No secrets in the repo** (correcting the Wave 1d insinuation): `HANDOVER_PROMPT.md` references `${ADRIAN_GH_TOKEN}` as an env var (line 27) and explicitly warns "the predecessor token was shared in plaintext — rotate it" (line 461). No actual token value is committed. No hardcoded production credentials in any source file. The `keyring` crate is declared but **never imported** — no OS credential-store integration for TGT/keytab/NT-hash persistence at rest.

**Bottom line**: Adrian v0.5.0 is **not production-ready** and carries no live network attack surface (no TCP listeners bound, no `axum::serve()` calls anywhere). The risk is that v0.6.0 stubs start getting filled in *without* the security controls being wired first. The P0 list below is the order in which security controls MUST land before any "AS-REQ works" claim.

---

## Threat Model

| Threat | AD baseline control | Adrian control status | Gap severity |
|--------|--------------------|-----------------------|--------------|
| **Kerberoasting** (T1558.003) | AES-only default; refuse RC4 TGS; `msDS-SupportedEncryptionTypes` required on SPN | `EType::Rc4Hmac` constant exists (`kdc/src/lib.rs:41`) and comment says "disabled by default (ADR-011)" — but `handle_tgs_req` is a stub (`kdc/src/lib.rs:93-96`). No etype negotiation, no SPN attribute check. | **High** — not enforced |
| **DCSync** (T1003.006) | `EXOP_REPL_SECRETS` ACL-gated to DC machine accounts only; SIEM rule on non-DC caller | `drs_get_nc_changes` returns `Backend("not yet implemented")` (`drsuapi/src/lib.rs:236-245`). `DrsOption::ExopReplSecrets = 0x100` constant exists (line 304) but no ACL check. Audit event `DcSyncAttempt` defined (`monitor/src/lib.rs:67`) but never emitted. TODO at `drsuapi/src/lib.rs:257`. | **Critical** — not enforced |
| **Golden ticket** (T1558.001) | HSM-bound krbtgt; 30-day auto-rotation; kvno check on TGS | `KrbtgtManager` calls `Hsm::generate_key` (`krbtgt.rs:76-79`) and `rotate_key` works (`krbtgt.rs:97-110`). BUT: (a) default HSM is `SoftwareHsm` (plaintext in-memory, ADR-015 §Rationale admits); (b) no auto-rotation scheduler (`krbtgt.rs:22-24`); (c) kvno NOT written to directory's `CN=krbtgt` account (`krbtgt.rs:25-27`); (d) previous key NOT destroyed after 2× TGT lifetime (`krbtgt.rs:28-31`). Real PKCS#11 HSM backend not implemented (only `SoftwareHsm` ships). | **Critical** — partial; production-blocker |
| **Silver ticket** (T1558.004) | `PAC_BUFFER_TICKET_CHECKSUM` validation on every service accept (ADR-123) | `Pac::parse` always returns `Malformed` (`pac-validator/src/lib.rs:67-72`). `validate_kdc_checksum` always returns `SignatureMismatch` (lines 75-78). `validate_service_checksum` always returns `SignatureMismatch` (lines 82-85). The 9 MS-KILE buffer types are constants only (lines 24-43) — no parser. | **Critical** — not implemented |
| **Pass-the-hash** (T1550.001) | Drop server-side NTLM entirely; client-only NTLM (ADR-086) | No `verify_password`/`verify_ntlm` function exists anywhere in the codebase (verified via `grep`). `adrian-ntlm-client` is explicitly client-only (ADR-085; `ntlm-client/src/lib.rs:4`). | **None** — enforced by absence ✓ |
| **LDAP relay** (T1557.001) | LDAP signing required + channel binding (TLS + ECC) per ADR-021 | `handle_search` is a loud stub (`directory-service/src/lib.rs:179-188`). No bind handler. TODO at line 200. Client-side channel binding tokens ARE computed correctly (`ntlm-client/src/lib.rs:398-420`), but no server exists to enforce them. | **High** — not enforced (no server) |
| **SMB1** (CWE-326 outdated protocol) | SMB1 refused; SMB 2.0.2 minimum (ADR-043) | `adrian-smb-core/src/lib.rs:147-156` test confirms `Dialect::Smb202` is the minimum offered. BUT `SmbServer::serve` is a stub (`smb-server/src/lib.rs:41-44`) — no actual dialect negotiation happens. | **Low** — enforced structurally (no server) |
| **sIDHistory injection** (T1178) | Per-trust filtering; only allow sIDHistory during migration window | `Principal::sid_history: Vec<Sid>` field exists (`identity-core/src/lib.rs:83`). `migrate_sidhistory` is a stub (`migrate/src/lib.rs:50-52`). No per-trust filter. No migration-window enforcement. | **High** — not enforced |
| **LAPS / local admin** | Per-host LAPS rotation (ADR-054) | `migrate_passwords` is a stub. No LAPS-style rotation agent. | **Medium** — not implemented |
| **PKINIT/smart card** | PKINIT + FIDO2/WebAuthn bridge (ADR-084) | `webauthn-rs = "0.5"` declared in Cargo.toml but no crate consumes it. `authenticate_cert` in SDK is a loud stub (`sdk/src/lib.rs:533-543`). | **Medium** — deferred |
| **Supply chain** | Sigstore + in-toto (ADR-067) | No `.github/` directory. No CI config. No `cargo audit` workflow. No `audit.toml`. No Dependabot. | **Medium** — gap |
| **Unauthenticated kpasswd** | KRB-PRIV wrapping of password change (RFC 3244) | `kpasswd.rs` uses simplified length-prefixed binary, NOT KRB-PRIV ASN.1 (`kpasswd.rs:27-31`). New password sent in **cleartext** on the wire (`kpasswd.rs:137-139`). | **Critical** — cleartext password disclosure |
| **Replay / freshness** | Authenticator timestamp (RFC 4120 §5.5.1) + replay cache | `kpasswd.rs` uses raw HMAC-SHA1-96 of `(client || target || new_password)` as the authenticator (`kpasswd.rs:417-421`) — no timestamp, no replay cache. A captured request could be replayed. | **High** — no replay defense |

---

## Crypto Correctness Findings

### `adrian-kdc/src/crypto.rs`

- **Algorithm correctness**:
  - `derive_aes256_key` (lines 69-73): PBKDF2-HMAC-SHA1 @ 4096 iterations → 32-byte AES-256 base key. **Correct** per RFC 3962 §3.
  - `hmac_sha1_96` (lines 76-83): HMAC-SHA1 truncated to 12 bytes. **Correct** per RFC 2104+2202.
  - AES-256 single-block encrypt/decrypt via `aes::Aes256` (lines 95, 143). **Correct** (RustCrypto `aes` 0.8).
  - AES-CBC with zero IV (lines 102, 150). **Correct** per RFC 3961 §5.1 — zero IV is mandatory because the confounder supplies freshness.
  - **AES-CBC-CTS: BROKEN** (encrypt lines 117-132; decrypt lines 167-191). Out-of-bounds slice operations panic on non-multiple-of-16 plaintexts. Wave 1c Bug 1 confirmed. Not a MAC bypass — HMAC is computed over plaintext+confounder (line 208), so forgery is still detected.
  - **Key derivation SKIPPED** (lines 18-30 explicit doc). Base key used directly as both Ke and Ki. RFC 3961 §5.1 `nfold`+DR-encrypt derivation NOT implemented. Result: **no MIT krb5/Heimdal/Windows interop**.

- **Constant-time comparison**: ❌ FAIL. `decrypt_aes256_cts_hmac_sha1_96` at line 230: `if expected_tag != tag` — short-circuit slice comparison. Timing-attack risk for HMAC-SHA1-96 forgery. **Fix**: `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal`. ~5 LoC change. (Wave 1c S-001.)

- **Key zeroization**: ❌ FAIL. `pub type Aes256Key = [u8; AES256_KEY_LEN];` (line 51) is a plain stack array. `derive_aes256_key` returns plain `[u8; 32]` (line 69). The `aes::Aes256` cipher object holds an internal copy of the key. None are wrapped in `Zeroizing`. (Wave 1c S-002.)

- **IV uniqueness**: ✓ CORRECT. Zero IV is correct per RFC 3961 §5.1 (the confounder — line 201 — supplies per-message freshness; using a random IV would actually break Kerberos wire-format compatibility).

- **Hardcoded keys**: ✓ NONE. All keys are derived from passwords via PBKDF2 or generated randomly via `ring::rand::SystemRandom` (in HSM).

### `adrian-hsm/src/lib.rs`

- **Algorithm correctness**:
  - `aes_256_gcm_encrypt` (lines 218-241): AES-256-GCM via `ring::aead::LessSafeKey`. **Correct**. `LessSafeKey` is ring's caller-managed-nonce API — NOT a security downgrade (the name is misleading; ring docs explicitly say so).
  - `aes_256_gcm_decrypt` (lines 245-261): **Correct**. Properly checks `ciphertext.len() < 12 + 16` (line 247) before slicing.
  - `hmac_sha1_96` (lines 204-214): HMAC-SHA1 truncated to 12 bytes. **Correct** per RFC 3961 checksum profile.
  - **Manual constant-time verify** (lines 339-345): `diff |= expected[i] ^ signature[i]` over `min` length, plus `diff |= (expected.len() != signature.len()) as u8`. **Acceptable but suboptimal** — should use `ring::constant_time::verify_slices_are_equal`. The `as u8` cast on `bool` is implementation-defined behavior in some C compilers but is well-defined in Rust (true → 1, false → 0).

- **Key zeroization**: ❌ FAIL. `KeyEntry.material: Vec<u8>` (line 169) is plain `Vec<u8>`. When `generate_key` overwrites (line 295) or `rotate_key` reassigns (line 407), the old `Vec<u8>`'s heap memory is NOT zeroized — it goes back to the allocator. (Wave 1c S-003.)

- **IV / nonce uniqueness**: ✓ CORRECT. `aes_256_gcm_encrypt` generates a fresh 12-byte random nonce per call (line 225). No nonce reuse. Nonce is prepended to ciphertext (line 238).

- **Hardcoded keys**: ✓ NONE. All key material comes from `ring::rand::SystemRandom::fill` (line 198).

- **NEW — Destructive `generate_key` semantics**: `SoftwareHsm::generate_key` (lines 282-301) does `keys.insert(key_id.to_string(), entry)` (line 295) which overwrites any existing key with the same id and resets `version = 1`. This is the root cause of the `kpasswd.rs:429` HSM-key-overwrite bug (Wave 1c Bug 3). It also violates ADR-015's kvno monotonicity assumption. Real HSMs error on duplicate key id; the caller must use `rotate_key` for explicit replacement.

- **NEW — No `find_or_create_key`**: There's no way to look up a key by id without generating. This forces callers (like `kpasswd.rs:429`) to call `generate_key` defensively, which triggers the overwrite bug.

- **NEW — No disk persistence**: ADR-015 §Rationale specifies "encrypted key file with a passphrase" for the software HSM, but `SoftwareHsm` is purely in-memory (`Arc<RwLock<HashMap<String, KeyEntry>>>`, line 183). Process restart = total key loss. Production deployments would have to re-derive all krbtgt/gMSA keys, invalidating every issued TGT and every gMSA password simultaneously.

### `adrian-ntlm-client/src/lib.rs`

- **Algorithm correctness**:
  - `ntowfv1` (lines 259-266): `MD4(UTF-16LE(password))` per MS-NLMP §3.3.1. Uses RustCrypto `md4` 0.10.2. **Structurally correct**.
  - `ntowfv2` (lines 270-281): `HMAC-MD5(nt_hash, UTF-16LE(UPPER(user) + domain))` per MS-NLMP §3.3.1. Uppercases user, leaves domain case-sensitive. **Structurally correct**.
  - `compute_ntlmv2_response` (lines 340-356): `HMAC-MD5(NTOWFv2, ServerChallenge ++ blob)` per MS-NLMP §3.3.2. Returns `proof ++ blob` as `NtChallengeResponse`. **Structurally correct**.
  - `compute_lmv2_response` (lines 362-375): `HMAC-MD5(NTOWFv2, ServerChallenge ++ ClientChallenge)` per MS-NLMP §3.3.1. **Structurally correct**.
  - `compute_channel_binding` (lines 398-420): RFC 5929 `tls-server-end-point` binding. MD5 of `initiator_address_type(4B, 0xFFFFFFFF) || initiator_address_length(4B, 0) || acceptor_address_type(4B, 0xFFFFFFFF) || acceptor_address_length(4B, 0) || application_data_length(4B) || application_data` where `application_data = "tls-server-end-point:" ++ cert_hash`. **Structurally correct**.
  - Type 1/2/3 message construction (lines 450-706): **Structurally correct** per MS-NLMP §2.2.1.1/§2.2.2.2/§2.2.1.3. Bounds-checked `read_u16_le`/`read_u32_le` (lines 211-235).

- **Constant-time comparison**: N/A. Client-only — no MAC verification on the client side.

- **Key zeroization**:
  - `ntowfv1` returns `Zeroizing<[u8; 16]>` (line 265). ✓ CORRECT.
  - `ntowfv2` returns `Zeroizing<[u8; 16]>` (line 280). ✓ CORRECT.
  - **NEW — `compute_ntlmv2_response` returns plain `Vec<u8>`** (line 346). The first 16 bytes are `NTProofStr` (sensitive — equivalent to an auth credential). NOT zeroized.
  - **NEW — `compute_lmv2_response` returns plain `Vec<u8>`** (line 367). Same concern (24 bytes = 16 proof + 8 client challenge).
  - **NEW — `NtlmClient.password: Option<String>`** (line 730). Rust `String` does NOT zeroize its heap buffer on drop. The password lives in heap memory until the allocator reuses it. (Wave 1c S-005.)

- **IV / nonce uniqueness**: N/A (NTLM is HMAC-based, not encryption-based; the "nonces" are ServerChallenge and ClientChallenge, both 8 bytes, supplied by the parties).

- **Hardcoded keys**: ✓ NONE. No hardcoded NT hashes or test vectors in production code (test fixtures at line 880-909 use MS-NLMP §4.2 documented vectors, which is correct).

- **NEW — Default `client_challenge = None` falls back to `[0u8; 8]`** (line 593). A deterministic all-zero client challenge weakens NTLMv2 — an attacker who captures one AUTHENTICATE message from a victim client can predict the proof structure for any future authentication by the same client (modulo the server's challenge). Documented at line 579-581 ("production callers MUST supply a random value") but NOT enforced.

- **NEW — HMAC-MD5 used** (per MS-NLMP §3.3.2). MD5 is collision-broken (practical collision attacks since 2008). Spec-inherent — cannot change without breaking NTLM interop. Acceptable because ADR-086 caps NTLM to client-only use.

- **NEW — `keyring` crate declared in Cargo.toml (line 26) but UNUSED.** No `use keyring::` import anywhere in `lib.rs`. The crate is dead weight in the dep graph and ADR-085/ADR-112 promise of OS credential-store integration is unfulfilled.

### `adrian-kdc/src/krbtgt.rs`

- **Algorithm correctness**: N/A — delegates all crypto to HSM via `Hsm::generate_key`/`rotate_key`.

- **Constant-time / zeroize**: N/A — `KeyHandle` (line 116-120) carries only `{id, version, key_type}`, no key material. Material lives in HSM.

- **NEW — No auto-rotation scheduler** (lines 22-24 doc). ADR-015 §Decision mandates 30-day auto-rotation. Currently `rotate()` must be called manually by an operator. If operators forget, golden-ticket mitigation silently degrades.

- **NEW — kvno NOT written to directory's `CN=krbtgt` account** (lines 25-27 doc). The HSM's `version` field and the directory's `kvno` attribute can drift. A client verifying a TGT by reading `kvno` from the directory would get a stale value if rotation happened without directory write-through.

- **NEW — Previous key NOT destroyed after 2× TGT lifetime** (lines 28-31 doc). The manager simply overwrites `previous` on the next rotation. ADR-015's retention window assumes a real clock + scheduling, which doesn't exist.

- **NEW — HSM is SOFTWARE-only by default.** `KrbtgtManager::new` accepts `Arc<dyn Hsm>`, and the only shipped impl is `SoftwareHsm` (plaintext in-memory). The `enterprise-hsm` feature flag enables the `cryptoki` dep but no `Pkcs11Hsm` implementation ships. Production krbtgt HSM-binding is **not deliverable** without writing the PKCS#11 backend.

### `adrian-kdc/src/gmsa.rs`

- **Algorithm correctness**:
  - `compute_gmsa_password` (lines 139-178): SP800-108 KDF in HMAC-SHA1 counter mode. **Structurally correct** per NIST SP800-108 §5.1.
  - **NEW — Non-standard K(i) block size.** The HSM's `sign` returns 12-byte HMAC-SHA1-96 truncations (per `SoftwareHsm::sign`, line 318). So each K(i) is 12 bytes, not the standard 20-byte HMAC-SHA1 output. SP800-108 §5.1 says use the full HMAC output. This means: (a) the KDF deviates from SP800-108; (b) for 32-byte output (line 50), we need 3 iterations of 12 bytes = 36 bytes, truncated to 32 (line 176). Mathematically OK (still uses HMAC-SHA1's full PRF security), but non-standard.
  - **NEW — Does NOT match AD's MS-ADTS §2.2.20 KDS algorithm** (lines 19-24 admit). AD uses the gMSA's SID (not DN), the cycle timestamp (not a counter), and a 32-byte output split into 4 quarters with specific bit-mixing. So **no AD-interop for gMSA password derivation** — an AD domain controller and an Adrian KDC computing the same gMSA's password for the same cycle would get different 32-byte values.

- **Constant-time / zeroize**: ❌ FAIL. `compute_gmsa_password` returns plain `Vec<u8>` (line 177). The gMSA password is a service-account credential — sensitive material. NOT zeroized. Same for `compute_current_password` (line 181).

- **NEW — `EffectiveTime` trick NOT enforced** (lines 26-28 doc). AD requires new KDS root keys to have an `EffectiveTime = now + 10 hours` to prevent race conditions during rotation (an attacker who learns of a new root key immediately could compute future gMSA passwords before the legitimate KDC starts using the key). Adrian accepts new root keys immediately, eliminating this defense.

- **NEW — Host ACL (`msDS-GroupMSAMembership`) NOT enforced** (lines 28-31 doc). Any caller can compute any gMSA password via `compute_gmsa_password`. The directory-service layer is supposed to enforce the ACL on the password-fetch RPC, but that layer is a stub.

- **Hardcoded keys**: ✓ NONE. KDS root key generated via `Hsm::generate_key` (line 81) with `ring::rand::SystemRandom`.

### `adrian-kdc/src/kpasswd.rs`

- **Algorithm correctness**:
  - `hash_password` (lines 355-370): PBKDF2-HMAC-SHA256 @ 200k iterations, 16-byte random salt, 32-byte output. Uses `pbkdf2` 0.12 + `sha2` 0.10 RustCrypto. **Cryptographically correct** for password hashing.
  - **NEW — Uses PBKDF2-SHA256 instead of bcrypt** (lines 37-39 doc). ADR-019 specifies bcrypt. PBKDF2-SHA256 is acceptable (NIST SP800-132) but weaker than bcrypt against GPU-based cracking. Defensible but spec-deviant.

- **Constant-time**: N/A — `hash_password` is one-way (no verify path in this module).

- **NEW — `handle_kpasswd` MAC verification under destructive HSM `generate_key`** (line 429, Wave 1c Bug 3). Each request regenerates the "krbtgt-mac" HMAC key, overwriting any pre-seeded key. The verify path then uses the new key (not the test's pre-seeded key), causing `bad_integrity`. The fallback branch at lines 431-441 calls `rotate_key` then `generate_key` again — making the bug worse.

- **NEW — New password sent in CLEARTEXT** (lines 137-139 doc; line 421 includes `req.new_password` in MAC input but the wire format at lines 196-219 does NOT encrypt the password). RFC 3244 requires KRB-PRIV wrapping. **Any network observer of a kpasswd request learns the new password.** Critical credential disclosure on the wire.

- **NEW — No replay defense**. The authenticator is a raw HMAC-SHA1-96 of `(client || target || new_password)` (lines 417-421). No timestamp, no nonce, no replay cache. A captured request can be replayed to force the same password change repeatedly (or, more perversely, replayed after the user has changed their password to a strong one — resetting it back to the captured value).

- **NEW — No transactional lock on password write**. `handle_kpasswd` does `directory.get_by_dn` (line 459) → modifies in-memory `target_obj` (line 489-504) → `directory.put(&target_obj)` (line 506). Two concurrent kpasswd requests for the same user could race: req A reads state S0, req B reads state S0, A writes S1, B writes S2 (overwriting S1). One password change is silently lost. No FDB transactional compare-and-set.

- **NEW — `PrincipalName::to_dn` falls back to hardcoded realm** (lines 112-121). `format!("CN={user},CN=Users,DC=adrian,DC=example,DC=com")` — the realm `adrian.example.com` is hardcoded. Cross-realm kpasswd requests (or any non-`adrian.example.com` deployment) would map to the wrong DN. Real bug, not just a stub limitation.

- **NEW — Password quality validation only checks length** (lines 472-485). ADR-019 mandates complexity, history, dictionary, and breached-password checks. Only `MIN_PASSWORD_LEN (12)` and `MAX_PASSWORD_LEN (256)` are enforced.

- **NEW — `attribute_id: 0` placeholder** (line 502). When adding a new `unicodePwd` attribute, the code sets `attribute_id: 0` ("placeholder — schema cache will resolve"). Until the schema cache (ADR-003) is wired, the storage layer cannot distinguish `unicodePwd` from any other attribute by ID — only by name. Functional, but a schema-validation gap.

### `adrian-identity-core/src/lib.rs`

- **Algorithm correctness**: `uuid_to_uid` (lines 183-190) is a non-cryptographic mapping. Documented as such (lines 174-182). Returns u32 in range `[65536, 2^31)`.
  - **NEW — `as PosixId` (u32) cast is safe**: `mixed % modulus` where `modulus = (1u64 << 31) - 65536 = 2_147_418_112`. Max after mod = `2_147_418_111`. Plus 65536 = `2_147_483_647 = u32::MAX / 2`. Fits in u32 without truncation. Verified.
  - **NEW — Birthday collision at ~77k principals**: u31-bit space = `2_147_418_112` values. Birthday bound ≈ `sqrt(2.1e9) ≈ 46k`. For >10k principals, ADR-110 §Decision recommends directory-stored `uidNumber`/`gidNumber`. Documented; not a vulnerability per se.

- **NEW — `sid_history: Vec<Sid>` field** (line 83). The field exists but no per-trust filtering (ADR-124) or migration-window enforcement (ADR-126) is implemented. Any caller that constructs a `Principal` with `sid_history` populated can carry arbitrary SIDs (including Domain Admin SIDs from a foreign domain), which would then be honored by any consumer that trusts `Principal::sid_history` (the PAC builder, the file gateway ACL evaluator). Mitigation requires implementing the filtering layer, which is a stub.

---

## Authentication / Authorization Findings

### KDC pre-auth

- `KdcService::handle_as_req` (kdc/src/lib.rs:87-90): **loud stub returning `KdcError::Storage("not yet implemented")`**. Confirmed by Wave 1c. **NO pre-auth verification happens** — no PA-ENC-TS-ENC check, no FAST armor TGT validation, no PKINIT verification.
- ADR-012 (FAST required) is documented (kpasswd.rs:514-534) but NOT enforced — `fast_armor_tgt` returns `Ok(())` whenever `fast_required = false` (the default).
- ADR-011 (RC4 refusal) is documented (kdc/src/lib.rs:40) but NOT enforced — no etype negotiation code path exists.

### LDAP bind

- `Dsa::run` (directory-service/src/lib.rs:108-117): **loud stub returning `DsaError::NotImplemented`**. No TCP listener is bound. No bind handler. No `handle_bind` function exists.
- `handle_search` (lines 179-188): loud stub. TODO at line 200 confirms "implement LDAP bind handler per RFC 4513 + ADR-021 (signing/channel-binding)".
- **NEW — `ldap3` workspace dep is CLIENT-side only** (Cargo.toml line 132). It is consumed by `adrian-sdk` for cross-platform LDAP client module. There is no server-side LDAP stack — Adrian would need to write one (BER codec + RFC 4511 PDU handlers + bind/search/modify/add/delete/modifyDN/compare/extended op handlers). The `rasn-ldap` dep (line 116) provides ASN.1 types but no I/O.
- **Anonymous bind risk**: when a bind handler is eventually written, it MUST reject anonymous binds for sensitive operations (modify, add, delete, modifyDN). Currently no design constraint enforces this.

### SMB session setup

- `SmbServer::serve` (smb-server/src/lib.rs:41-44): **loud stub returning `SmbServerError::Protocol("not yet implemented")`**. Confirmed by Wave 1d.
- ADR-043 (SMB1 refusal): structurally enforced at the dialect-list level (`adrian-smb-core/src/lib.rs:147-156` test pins `Dialect::Smb202` as minimum). But since `serve()` is a stub, no actual negotiation happens.
- ADR-021 (SMB signing required): NOT enforced. No signing key derivation code.
- ADR-123 (PAC validation on every service accept): NOT enforceable — `Pac::parse` is a stub.

### Policy RBAC

- `WindowsPolicyExecutor::synthesize` (policy-executor/src/lib.rs:194+): real synthesis (returns file bytes). **But `apply` is a stub** that wraps `synthesize` (per trait doc, line 130-133). No transactional apply, no rollback, no RBAC check.
- **NEW — No caller authorization anywhere in the policy pipeline.** A `DeclarativePolicy` is a plain JSON document; `synthesize` consumes it without checking who is calling. The operator daemon (also a stub) is supposed to enforce RBAC, but the trait surface doesn't carry a principal identity.
- **NEW — `secret_ref` not yet implemented** (referenced in ADR-091, ADR-113, ADR-091 §6). The `PolicyValue` type in `adrian-policy-core` (not audited here) does not have a `SecretRef` variant — it's a TODO. Without this, secrets cannot be delivered via policy without falling back to the GPP `cPassword` antipattern (MS14-025).

### Auth bypass risks

- `parse_challenge` (ntlm-client/src/lib.rs:484-549): does NOT validate the server's `NegotiateFlags` against what the client requested. A malicious server could send flags the client didn't offer (e.g., dropping `NEGOTIATE_128`, forcing weaker session security). The client uses the server's flags verbatim (line 641: `let mut flags = challenge.negotiate_flags`).
- **NEW — `client_challenge = None` defaults to `[0u8; 8]`** (ntlm-client/src/lib.rs:593). A deterministic client challenge weakens NTLMv2 to a predictable structure. A malicious server that observes one AUTHENTICATE message from a victim can predict the proof for any future authentication (modulo the server's challenge).
- **NEW — No size cap on `target_info`** (ntlm-client/src/lib.rs:531-538). The server can specify `target_info_len = u16::MAX = 65535`. The client then allocates a 64 KB `Vec<u8>` and copies the bytes. Bounded but could amplify (small Type 2 message → 64 KB allocation). Not a real DoS vector but worth noting.

---

## Input Validation Findings

### Panics on untrusted input

- **NEW — All `panic!`/`unreachable!`/`todo!`/`unimplemented!` calls are inside `#[cfg(test)]` modules** (verified via grep). The single exception is `adrian-raft/src/lib.rs:209` which calls `panic!("RaftLogEntry serialisation failed: {e}")` in `encode_log_entry` (production code). Justified by the comment "RaftLogEntry derives Serialize and contains only serde-derivable fields ... Failure here indicates a programming bug". Acceptable but worth flagging — a future field type change could trigger this in production.

- **NEW — `Mutex::lock().unwrap()` / `RwLock::read().unwrap()` / `.expect("poisoned")`** appears in:
  - `adrian-kdc/src/store.rs:105, 111, 118, 141` (`.expect("principal store poisoned")`)
  - `adrian-repl-testkit/src/lib.rs:62, 78, 90` (`.unwrap()`)
  - These would panic on lock poison (a panic in another thread holding the lock). For the testkit, acceptable. For `kdc/store.rs`, a poisoned mutex would crash the KDC — should be converted to `lock().unwrap_or_else(|e| e.into_inner())` to recover, or to a graceful error.

- **NEW — `.expect("16-byte slice")` / `.expect("8-byte buf")` after `buf.len() == N` guards** in `adrian-storage-fdb/src/lib.rs` (per Wave 1a, lines 252, 267, 295, 314, 362, 397) and `adrian-identity-fdb/src/lib.rs` (lines 397, 454, 614, 659, 706). Guard-then-expect pattern: can't panic on well-formed backend data, but a truncated FDB value (e.g., partial write) would crash the process. Defense-in-depth would use `.ok_or(Backend(...))?`.

### Integer overflow risks

- **NEW — `decode_log_entry` in `adrian-raft/src/lib.rs:232`**: `let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;` then check `bytes.len() < ENTRY_LEN_PREFIX_BYTES + len`. On **32-bit platforms**, if `len == u32::MAX`, `4 + u32::MAX` wraps to 3, the check `bytes.len() < 3` is false for any 4-byte+ input, and `&bytes[4..4+u32::MAX]` panics with index out of bounds. On 64-bit (the only realistic target), safe. **Defensive concern only.**
- **NEW — `frag_length as usize` in `dcerpc/transport.rs:114` and `dcerpc/pdu.rs:484, 562, 801`**: `u16` → `usize`, no overflow possible. Allocates `vec![0u8; frag_length]` (max 64 KB). Bounded.
- **NEW — `n_ctx as usize` in `dcerpc/pdu.rs:274`**: `u8` → `usize`, bounded to 255. Allocates `Vec::with_capacity(n_ctx as usize)`. Safe.
- **NEW — `name_len as usize` in `storage-fdb/src/lib.rs:553`**: `u16` → `usize`, bounded to 65535. Safe.
- **NEW — `body_len as usize` in `kpasswd.rs:225, 313`**: `u16` → `usize`, bounded. Safe.
- **NEW — `as PosixId` (u32) cast in `identity-core/src/lib.rs:189`**: verified safe above.

### DoS vectors

- **NEW — No unbounded read loops in production code.** `loop { ... }` only in test code or in XML reader (`admx-compiler/src/lib.rs:228`, terminates on EOF) and PReg UTF-16 string reader (`policy-preg/src/lib.rs:317`, terminates on `;` delimiter). Both are bounded by input size.
- **NEW — `read_utf16_until_semi` (`policy-preg/src/lib.rs:314-336`)**: accumulates `code_units: Vec<u16>` until `;` delimiter. A malicious PReg file with a very long string field (no `;` until EOF) would allocate up to `buf.len() / 2` u16 values. Bounded by input size. Not a DoS vector in practice (PReg files come from SYSVOL, which is trusted).
- **NEW — `DceRpcEndpoint::run` is a stub**: no actual TCP listener exists. No live DoS attack surface.
- **NEW — No TCP listener bound anywhere in the codebase**: `grep` for `TcpListener::bind` returns zero matches. All `axum::Router` instances are constructed but never served (`grep` for `axum::serve` returns zero matches). **Zero live network attack surface in v0.5.0.**

---

## Network Attack Surface

- **NEW — Zero live TCP listeners**. `grep` for `TcpListener::bind` / `axum::serve` / `serve()` (production) returns zero matches. The only `TcpStream::connect` calls are in `adrian-dcerpc/src/transport.rs:34` (DCE/RPC client) and the SMB client (Wave 1d).

- **NEW — `DcerpcTcpTransport::read_pdu`** (transport.rs:111-128): reads 16-byte common header, parses `frag_length` (u16, max 65535), allocates `vec![0u8; frag_length]`, reads remaining body. Allocation bounded to 64 KB per PDU. Safe.

- **NEW — `DceRpcEndpoint::run`** (dcerpc/src/lib.rs:249): documented as deferred — server-side DCE/RPC listener NOT implemented. Wave 1b confirms.

- **NEW — All HTTP routers are inert**: `adrian-print-service/router()`, `adrian-federation-shim/router()`, `adrian-monitor/metrics_router()`, `adrian-acme-server/router()` all construct `axum::Router` instances but never call `axum::serve()` on them. No live HTTP endpoints.

- **NEW — `Dsa::run`** (directory-service/src/lib.rs:108): loud stub. No LDAP listener, no GC listener. TODO at line 109.

- **NEW — `SmbServer::serve`** (smb-server/src/lib.rs:41): loud stub. No TCP/445 listener.

- **NEW — No unbounded `read_to_end` calls**. The only `read_to_string` calls are in CLI / compiler code that reads local files (`adrian-cli/src/lib.rs:219`, `adrian-admx-compiler/src/lib.rs:177`). Bounded by local file size.

---

## Supply Chain Findings

- **NEW — No `.github/` directory, no CI configuration, no `cargo audit` workflow, no `audit.toml`, no Dependabot config.** Zero automated supply-chain defense. ADR-067 (Sigstore + in-toto) is documented but not implemented.

- **NEW — Major dependencies are at recent versions** (workspace Cargo.toml lines 77-187):
  - `tokio = "1"` (latest 1.x)
  - `ring = "0.17"` (latest 0.17.x — well-vetted, used by Google's production crypto)
  - `aes = "0.8"`, `sha1 = "0.10"`, `sha2 = "0.10"`, `hmac = "0.12"`, `pbkdf2 = "0.12"` — RustCrypto family, well-vetted
  - `md4 = "0.10"`, `md-5 = "0.10"` — deliberately included for NTLM (spec-inherent weakness, but correct implementations)
  - `zeroize = "1"` (latest)
  - `axum = "0.8"`, `rustls = "0.23"`, `tokio-rustls = "0.26"` — recent
  - `rasn = "0.22"`, `rasn-kerberos = "0.22"`, `rasn-ldap = "0.22"`, `rasn-pkix = "0.22"` — relatively new ASN.1 library; lower vetting depth than `ring`/`aes`. Used by `adrian-pac-validator` (stub) and `adrian-ntlm-client` (cert parsing only). Acceptable risk.
  - `cryptoki = "0.8"` — PKCS#11 bindings. Declared but no `Pkcs11Hsm` impl ships.
  - `foundationdb = "0.9"` — Apple's FDB Rust bindings. Default-features = false. Not compile-tested in the dev sandbox (no libclang).
  - `openraft = "0.9"` — Raft consensus. Declared but `adrian-raft` uses a hand-rolled `ManualRaftReplicator` (Wave 1b confirmed). The `serde` feature is enabled for future integration.

- **NEW — No `unsafe` blocks anywhere.** Every crate carries `#![forbid(unsafe_code)]`. Verified via grep for `unsafe ` — only matches are the `forbid(unsafe_code)` markers and FFI declarations in `adrian-sdk-c` (which uses `#[no_mangle] pub unsafe extern "C"` — required for C ABI, not a memory-safety hole per se).

- **NEW — Dead dependencies**:
  - `keyring = "3"` (line 185) — declared in `adrian-ntlm-client/Cargo.toml:26` but never imported. ~50 KB of compiled dead code.
  - `git2 = "0.19"` (line 177) — declared as workspace dep but no crate currently consumes it.
  - `webauthn-rs = "0.5"` (line 187) — declared but no crate currently consumes it (federation/PKI deferred).
  - `openidconnect = "3"` (line 186) — declared but no crate currently consumes it.
  - `x509-cert = "0.2"` (line 188) — declared but no crate currently consumes it.
  - `rasn-ldap = "0.22"` (line 116) — declared but no crate currently consumes it (the `adrian-directory-service` stub doesn't import it).

- **NEW — Known-vulnerable dep check**: Without running `cargo audit`, I cannot definitively rule out RUSTSEC advisories. However, the dep versions listed are recent (late 2024 / early 2025) and the major crypto deps (`ring`, `aes`, `sha2`, `hmac`) have strong track records.

---

## Secrets Management Findings

### GitHub PAT (correcting Wave 1d's insinuation)

- **NEW — NO hardcoded GitHub PAT in `HANDOVER_PROMPT.md` or anywhere else in the repo.** Wave 1d claimed the PAT was "still in `HANDOVER_PROMPT.md`" — this is **incorrect**.
- `HANDOVER_PROMPT.md:27`: `**GitHub PAT**: Set the \`ADRIAN_GH_TOKEN\` environment variable to a fresh token from https://github.com/settings/tokens (the predecessor token was shared in plaintext — rotate it)`. This is an instruction to set an env var, not a committed secret.
- `HANDOVER_PROMPT.md:95`: `git clone https://pkhairkh:${ADRIAN_GH_TOKEN}@github.com/pkhairkh/adrian.git`. Uses env-var substitution. No actual token.
- `HANDOVER_PROMPT.md:461`: `**GitHub PAT**: The predecessor token was shared in plaintext in prior sessions. Generate a fresh token at https://github.com/settings/tokens and pass it via the \`ADRIAN_GH_TOKEN\` environment variable. **Never commit tokens to the repo** — GitHub Push Protection will block the push.` Explicit warning.
- Grep for `ghp_[A-Za-z0-9]{36}` and `github_pat_[A-Za-z0-9_]{82}` across the entire repo: **zero matches**. The PAT was not committed.

### Hardcoded passwords / keys

- **NEW — No hardcoded production credentials in any source file.** The `password123` reference at `adrian-sdk-c/src/lib.rs:410` is a C-string test fixture for the FFI integration test (`let password = c"password123".as_ptr();`), not a production credential.
- **NEW — No hardcoded NT hashes, krbtgt keys, or KDS root keys**. All key material is derived from passwords (PBKDF2) or generated randomly (`ring::rand::SystemRandom`).

### `keyring` usage

- **NEW — `keyring = "3"` declared in `adrian-ntlm-client/Cargo.toml:26` but NEVER imported.** No `use keyring::` statement anywhere in `adrian-ntlm-client/src/lib.rs`. ADR-085/ADR-112 promise OS credential-store integration (Windows Credential Manager, macOS Keychain, Linux keyctl) — this promise is **unfulfilled**. The crate is dead weight in the dep graph.
- `adrian-sdk/src/lib.rs:539`: comment mentions `keyring` ("Production: wraps the platform key store (Windows NCrypt / macOS Keychain / Linux keyctl) via `keyring` crate") but the import is absent. Same dead-reference pattern.

### `SoftwareHsm` plaintext storage

- **NEW — `SoftwareHsm` stores keys in plaintext process memory** (`adrian-hsm/src/lib.rs:183` — `Arc<RwLock<HashMap<String, KeyEntry>>>`). ADR-015 §Rationale specifies "encrypted key file with a passphrase" for the software HSM, but no such file is implemented. A process memory dump (e.g., via `gcore`, `/proc/<pid>/mem`, or a container escape) reveals every krbtgt key, KDS root key, and HMAC key.
- **NEW — No on-disk key persistence.** Process restart = total key loss. Every issued TGT becomes unvalidatable, every gMSA password becomes uncomputable. The HSM is purely ephemeral.
- **NEW — Real PKCS#11 HSM backend not implemented.** The `enterprise-hsm` feature flag enables the `cryptoki` dep but no `Pkcs11Hsm` impl ships in this crate. Production HSM-binding for krbtgt (ADR-015) is **not deliverable** without writing the PKCS#11 backend.

### Secrets in transit

- **NEW — kpasswd sends new password in cleartext** (kpasswd.rs:137-139 doc; lines 417-421 MAC input includes plaintext password). Critical credential disclosure on the wire. Mitigation: implement RFC 4120 §3.5 KRB-PRIV wrapping (kpasswd.rs:27-31 doc admits this is deferred).
- **NEW — No TLS on any planned endpoint.** ADR-021 mandates LDAP signing + channel binding; ADR-043 mandates SMB 3.1.1 preauth integrity + AES-128-CCM/GCM encryption. None of this is implemented because the servers are stubs.

---

## Risk Register (Consolidated)

| ID | Risk | Severity | Likelihood | Wave 1 Source | Mitigation |
|----|------|----------|------------|---------------|------------|
| S-001 | Non-constant-time HMAC compare in `decrypt_aes256_cts_hmac_sha1_96` (`crypto.rs:230`) | High | Low (no path to KDC yet) | 1c | Replace `!=` with `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal` |
| S-002 | `Aes256Key = [u8; 32]` not zeroized (`crypto.rs:51`) | Medium | High (every encrypt/decrypt call) | 1c | Wrap in `Zeroizing<[u8; 32]>` |
| S-003 | `KeyEntry.material: Vec<u8>` not zeroized (`hsm/src/lib.rs:169`) | Medium | Medium (heap persists after rotation) | 1c | Wrap in `Zeroizing<Vec<u8>>` |
| S-004 | `NtlmClient.password: Option<String>` not zeroized (`ntlm-client/src/lib.rs:730`) | High | Low (no production deployment) | 1c | Change to `Option<Zeroizing<String>>` |
| S-005 | `CredentialHandle::NtlmHash`/`KerberosTgt`/`OAuth2Token` not zeroized (`auth-core/src/lib.rs:55-58`) | Medium | Medium | 1c | Wrap inner fields in `Zeroizing<...>` |
| S-006 | `compute_ntlmv2_response` returns plain `Vec<u8>` (16-byte proof not zeroized) (`ntlm-client/src/lib.rs:346`) | Medium | Medium | **NEW (2a)** | Wrap in `Zeroizing<Vec<u8>>` |
| S-007 | `compute_lmv2_response` returns plain `Vec<u8>` (`ntlm-client/src/lib.rs:367`) | Low | Medium | **NEW (2a)** | Wrap in `Zeroizing<Vec<u8>>` |
| S-008 | `compute_gmsa_password` returns plain `Vec<u8>` (gMSA password not zeroized) (`gmsa.rs:177`) | High | Medium (any gMSA use) | **NEW (2a)** | Wrap in `Zeroizing<Vec<u8>>` |
| S-009 | `SoftwareHsm::generate_key` is destructive (overwrites existing key, resets version) (`hsm/src/lib.rs:295`) | High | High (every key re-gen) | 1c (Bug 3) | Add `find_or_create_key`; error on existing id |
| S-010 | `handle_kpasswd` regenerates "krbtgt-mac" key on every request (`kpasswd.rs:429`) | High | High (every authenticated kpasswd fails) | 1c (Bug 3) | Use `find_or_create_key` or derive MAC key from krbtgt AES key via RFC 3961 §3 |
| S-011 | kpasswd sends new password in cleartext (`kpasswd.rs:137-139`) | **Critical** | High | 1c | Implement RFC 4120 §3.5 KRB-PRIV wrapping |
| S-012 | kpasswd has no replay defense (no timestamp, no nonce, no replay cache) (`kpasswd.rs:417-421`) | High | High | **NEW (2a)** | Add RFC 4120 §5.5.1 Authenticator with timestamp + replay cache |
| S-013 | kpasswd uses simplified wire format (no KRB-PRIV ASN.1) (`kpasswd.rs:27-31`) | High | High | 1c | Use `rasn-kerberos` for real KRB-PRIV codec |
| S-014 | `Pac::parse` always returns `Malformed` (`pac-validator/src/lib.rs:67-72`) | **Critical** | High | 1c | Implement PAC parser per MS-KILE §2 + ADR-082 (9 buffer types) |
| S-015 | `validate_kdc_checksum` / `validate_service_checksum` always return `SignatureMismatch` (`pac-validator/src/lib.rs:75-85`) | **Critical** | High | 1c | Implement per ADR-083 (two-layer validation) |
| S-016 | AES-256-CTS swap logic panics on non-multiple-of-16 plaintext (`crypto.rs:131, 181`) | Medium (DoS) | High (any future AS-REQ/TGS-REQ) | 1c (Bug 1) | Rewrite per RFC 2040 §6 / RFC 3962 §5.3 |
| S-017 | RFC 3961 §5.1 key derivation (`nfold` + DR-encrypt) NOT implemented (`crypto.rs:18-30`) | High (interop) | High | 1c | Implement `nfold` + DR-encryption for Ke/Ki |
| S-018 | No auto-rotation scheduler for krbtgt (`krbtgt.rs:22-24`) | High | Medium | **NEW (2a)** | Add tokio task that calls `rotate()` every 30 days |
| S-019 | kvno NOT written to directory's `CN=krbtgt` account (`krbtgt.rs:25-27`) | High | Medium | **NEW (2a)** | Wire `KrbtgtManager::rotate()` to `DirectoryStore::put` on the krbtgt account |
| S-020 | Previous krbtgt key NOT destroyed after 2× TGT lifetime (`krbtgt.rs:28-31`) | Medium | Low | **NEW (2a)** | Add timer-based destruction of `previous` after `2 × DEFAULT_TGT_LIFETIME_HOURS` |
| S-021 | Real PKCS#11 HSM backend not implemented (only `SoftwareHsm` ships) | **Critical** | High | **NEW (2a)** | Implement `Pkcs11Hsm` against `cryptoki::Session` |
| S-022 | `SoftwareHsm` stores keys in plaintext memory (`hsm/src/lib.rs:183`) | High | High | **NEW (2a)** | Implement encrypted key file per ADR-015 §Rationale |
| S-023 | No disk persistence for HSM keys (process restart = total key loss) | High | High | **NEW (2a)** | Add encrypted key file persistence |
| S-024 | `handle_as_req` is a loud stub — no pre-auth verification (`kdc/src/lib.rs:87-90`) | **Critical** | High | 1c | Implement per RFC 4120 §3.1 + §5.4.1 + ADR-012 (FAST) |
| S-025 | `handle_tgs_req` is a loud stub — no TGS issuance, no etype enforcement (`kdc/src/lib.rs:93-96`) | **Critical** | High | 1c | Implement per RFC 4120 §3.3 + §5.4.2 + ADR-087 (S4U) |
| S-026 | RC4 refusal NOT enforced in code (constant exists, no check) (`kdc/src/lib.rs:41`) | High | High | **NEW (2a)** | Add etype negotiation handler that rejects RC4-HMAC (etype 23) per ADR-011 |
| S-027 | LDAP bind handler NOT implemented — anonymous bind risk (`directory-service/src/lib.rs:200`) | High | High (when listener ships) | 1b, **NEW (2a)** | Implement per RFC 4513 + ADR-021 (signing/channel-binding); reject anonymous bind for modify/add/delete |
| S-028 | SMB session setup NOT implemented — no Kerberos, no signing (`smb-server/src/lib.rs:41-44`) | High | High (when listener ships) | 1d, **NEW (2a)** | Implement per MS-SMB2 §3.3.5 + ADR-021 (signing) + ADR-123 (PAC validation) |
| S-029 | DCSync ACL gate NOT implemented (`drsuapi/src/lib.rs:257`) | **Critical** | High | **NEW (2a)** | Implement `EXOP_REPL_SECRETS` ACL check per ADR-122 (caller must have DS-Replication-Get-Changes-All on domain NC head) |
| S-030 | SID history injection mitigation NOT implemented (`migrate/src/lib.rs:50-52`) | High | Medium | **NEW (2a)** | Implement per-trust filtering per ADR-124; enforce migration window per ADR-126 |
| S-031 | Silver ticket mitigation (`PAC_BUFFER_TICKET_CHECKSUM`) NOT implemented | **Critical** | High | **NEW (2a)** | Implement in `Pac::validate_*` per ADR-123 |
| S-032 | Policy executor has no RBAC check (`policy-executor/src/lib.rs:115-143`) | High | High | **NEW (2a)** | Add caller principal parameter to `synthesize`/`apply`; enforce RBAC |
| S-033 | `secret_ref` policy type NOT implemented (GPP `cPassword` antipattern risk) | High | High | **NEW (2a)** | Add `PolicyValue::SecretRef` variant per ADR-091 §6; integrate with framework secret service |
| S-034 | gMSA `EffectiveTime` 10-hour delay NOT enforced (`gmsa.rs:26-28`) | Medium | Medium | **NEW (2a)** | Implement `EffectiveTime = now + 10h` per ADR-020 §Decision |
| S-035 | gMSA host ACL (`msDS-GroupMSAMembership`) NOT enforced (`gmsa.rs:28-31`) | High | Medium | **NEW (2a)** | Enforce in directory-service password-fetch RPC |
| S-036 | gMSA KDF uses 12-byte HMAC-SHA1-96 truncation instead of 20-byte full HMAC-SHA1 (`gmsa.rs:164-166`) | Low | Medium | **NEW (2a)** | Add `Hsm::sign_full` method or use full HMAC-SHA1 in gMSA KDF |
| S-037 | gMSA KDF does NOT match AD's MS-ADTS §2.2.20 algorithm (`gmsa.rs:19-24`) | High (interop) | High | **NEW (2a)** | Reverse-engineer AD's algorithm per ADR-020 §Open Questions |
| S-038 | `PrincipalName::to_dn` falls back to hardcoded `adrian.example.com` realm (`kpasswd.rs:119`) | Medium | Medium | **NEW (2a)** | Use the request's actual realm, not a hardcoded fallback |
| S-039 | kpasswd password write not transactional — concurrent race risk (`kpasswd.rs:459-506`) | Medium | Low | **NEW (2a)** | Use FDB transactional compare-and-set |
| S-040 | kpasswd password quality validation only checks length (`kpasswd.rs:472-485`) | Medium | Medium | **NEW (2a)** | Add complexity, history, dictionary, breached-password checks per ADR-019 |
| S-041 | kpasswd uses PBKDF2-SHA256 instead of bcrypt (`kpasswd.rs:37-39`) | Low | High | **NEW (2a)** | Add `bcrypt` to workspace deps; switch `hash_password` |
| S-042 | NTLM client default `client_challenge = None` falls back to `[0u8; 8]` (`ntlm-client/src/lib.rs:593`) | Medium | Medium | **NEW (2a)** | Enforce non-zero random challenge; return error if `None` |
| S-043 | `keyring` crate declared but unused (`ntlm-client/Cargo.toml:26`) | Low (missing functionality) | High | 1c, **NEW (2a)** | Wire `keyring` to fetch credentials from OS keychain, or remove the dep |
| S-044 | No `.github/` directory, no CI, no `cargo audit` workflow | Medium | High | **NEW (2a)** | Add `.github/workflows/ci.yml` with `cargo audit`, `cargo clippy -D warnings`, `cargo test --workspace`; add Dependabot |
| S-045 | No supply-chain signing (ADR-067 Sigstore + in-toto) | Medium | High | **NEW (2a)** | Implement per ADR-067 |
| S-046 | `parse_challenge` doesn't validate server's NegotiateFlags (`ntlm-client/src/lib.rs:484-549`) | Low | Low | **NEW (2a)** | Mask server flags against client's requested flags |
| S-047 | `decode_log_entry` integer overflow on 32-bit platforms if `len == u32::MAX` (`raft/src/lib.rs:232`) | Low | Low (64-bit only target) | **NEW (2a)** | Add `len.checked_add(ENTRY_LEN_PREFIX_BYTES)` and check for overflow |
| S-048 | `encode_log_entry` panics on serialization failure (`raft/src/lib.rs:209`) | Low | Low | **NEW (2a)** | Return `Result` instead of panicking |

---

## Recommendations for v0.6.0 (Security-First)

**P0 — MUST land before any "AS-REQ works" claim:**

1. **Fix non-constant-time HMAC compare** in `decrypt_aes256_cts_hmac_sha1_96` (`crypto.rs:230`). Replace `if expected_tag != tag` with `subtle::ConstantTimeEq` or `ring::constant_time::verify_slices_are_equal`. ~5 LoC. (S-001)

2. **Zeroize all key material**:
   - `Aes256Key = Zeroizing<[u8; 32]>` in `crypto.rs:51`.
   - `KeyEntry.material: Zeroizing<Vec<u8>>` in `hsm/src/lib.rs:169`.
   - `NtlmClient.password: Option<Zeroizing<String>>` in `ntlm-client/src/lib.rs:730`.
   - `compute_ntlmv2_response` and `compute_lmv2_response` return `Zeroizing<Vec<u8>>`.
   - `compute_gmsa_password` returns `Zeroizing<Vec<u8>>`.
   - `CredentialHandle::NtlmHash`, `KerberosTgt`, `OAuth2Token` inner fields wrapped in `Zeroizing<...>` in `auth-core/src/lib.rs:55-58`.
   - Total: ~20 LoC across 4 crates. (S-002 through S-008)

3. **Fix `SoftwareHsm::generate_key` destructive semantics** (S-009): add `find_or_create_key` method; error on existing id; require `rotate_key` for explicit replacement. Also fixes S-010 (kpasswd HSM key bug). ~30 LoC in HSM + ~5 LoC in kpasswd.

4. **Implement real PAC validation** in `adrian-pac-validator` (S-014, S-015, S-031): `Pac::parse` using `rasn-kerberos` per MS-KILE §2; `validate_kdc_checksum` per ADR-083 Layer 1; `validate_service_checksum` per ADR-083 Layer 2; all 9 MS-KILE buffer types per ADR-082. Blocker for ADR-123 silver-ticket mitigation. Estimated 500-800 LoC.

5. **Implement RFC 3961 §5.1 key derivation** (`nfold` + DR-encrypt for Ke/Ki) in `crypto.rs` (S-017). Without this, no MIT krb5/Heimdal/Windows interop. Estimated ~150 LoC.

6. **Fix AES-256-CTS** (S-016): rewrite `aes256_cts_encrypt` and `aes256_cts_decrypt` against RFC 2040 §6 / RFC 3962 §5.3. Add RFC 3962 §5 official test vectors. ~80 LoC rewrite.

7. **Wrap kpasswd new password in KRB-PRIV** (S-011): implement RFC 4120 §3.5 KRB-PRIV wrapping using `rasn-kerberos`. Without this, every kpasswd request leaks the new password on the wire. Estimated ~200 LoC.

8. **Add replay cache to kpasswd** (S-012): implement RFC 4120 §5.5.1 Authenticator with timestamp + replay cache. Estimated ~150 LoC.

**P1 — MUST land before any production deployment:**

9. **Implement real PKCS#11 HSM backend** (S-021, S-022, S-023): `Pkcs11Hsm` against `cryptoki::Session`. Implement encrypted key file persistence per ADR-015 §Rationale. Estimated ~500 LoC.

10. **Implement DCSync ACL gate** (S-029): in `drs_get_nc_changes`, check caller has `DS-Replication-Get-Changes-All` on the domain NC head before honoring `EXOP_REPL_SECRETS`. Emit `DcSyncAttempt` audit event per ADR-122. Estimated ~100 LoC.

11. **Implement SID history per-trust filtering** (S-030): in the directory-service PAC builder and the file gateway ACL evaluator, filter `Principal::sid_history` against the current trust's SID filter list per ADR-124. Estimated ~150 LoC.

12. **Wire `keyring` crate** (S-043): integrate OS credential-store for TGT/keytab/NT-hash persistence. Removes the dead dep and fulfills ADR-085/ADR-112. Estimated ~100 LoC.

13. **Add `.github/workflows/ci.yml`** (S-044): `cargo audit`, `cargo clippy -D warnings`, `cargo test --workspace`, `cargo deny` (license + advisory check). Add Dependabot config. Estimated 1 day.

14. **Add krbtgt auto-rotation scheduler** (S-018): tokio task that calls `KrbtgtManager::rotate()` every `DEFAULT_ROTATION_INTERVAL_DAYS = 30` days, with audit event emission. Wire kvno directory write-through (S-019) and previous-key destruction timer (S-020). Estimated ~200 LoC.

**P2 — SHOULD land before v0.7.0:**

15. **Enforce RC4 refusal** in `handle_tgs_req` (S-026): reject `EType::Rc4Hmac` (23) with `KdcError::Policy("rc4 disabled")` per ADR-011. Add `msDS-SupportedEncryptionTypes` check on the SPN. Estimated ~50 LoC.

16. **Implement LDAP bind handler** (S-027) per RFC 4513 + ADR-021. Reject anonymous bind for modify/add/delete/modifyDN. Enforce signing + channel binding. Estimated ~500 LoC.

17. **Implement SMB session setup** (S-028) per MS-SMB2 §3.3.5. Enforce signing (HMAC-SHA256 over SMB2 header) and PAC validation on every accept (ADR-123). Estimated ~800 LoC.

18. **Add `secret_ref` policy type** (S-033) per ADR-091 §6. Integrate with framework secret service (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault per Decision 11). Estimated ~300 LoC.

19. **Enforce gMSA host ACL** (S-035) and `EffectiveTime` delay (S-034) per ADR-020. Estimated ~100 LoC.

20. **Add password quality validation** (S-040) per ADR-019: complexity, history, dictionary, breached-password checks. Estimated ~200 LoC.

21. **Switch kpasswd to bcrypt** (S-041) per ADR-019. Add `bcrypt = "0.15"` to workspace deps. Estimated ~10 LoC change.

**P3 — NICE to have for v0.7.0+:**

22. **Reverse-engineer AD's MS-ADTS §2.2.20 gMSA KDS algorithm** (S-037) for AD-interop. Estimated 1-2 person-weeks of reverse engineering.

23. **Add supply-chain signing** (S-045) per ADR-067: Sigstore (cosign) + in-toto attestations on container images and binary releases. Estimated 1 person-week.

24. **Fix `PrincipalName::to_dn` hardcoded realm** (S-038) — use the request's actual realm. Estimated ~10 LoC.

25. **Add transactional lock to kpasswd password write** (S-039) — use FDB transactional compare-and-set. Estimated ~30 LoC.

26. **Harden NTLM client**: validate server's NegotiateFlags (S-046), enforce non-zero random client_challenge (S-042). Estimated ~20 LoC.

---

## Honest Caveats

1. **No runtime verification**: `cargo`/`rustc` not available in the sandbox. All findings are based on static analysis of code + tests + Cargo.toml + CHANGELOG + ADRs. Where the CHANGELOG claims a bug (e.g., AES-CTS panic, NTLM hash mismatch), I verified the claim by reading the code; where my reading agrees with the CHANGELOG, I cite it; where my reading disagrees (e.g., Wave 1d's GitHub PAT claim is incorrect — no PAT is committed), I flag it explicitly.

2. **Threat-model severity scores are subjective**: "Critical" means "if a production deployment existed, this would be a critical vulnerability." Since v0.5.0 has zero live network attack surface (no TCP listeners bound, no `axum::serve()` calls), the *effective* exploitability of every finding is zero today. The scores reflect the risk if a stub is filled in without first landing the corresponding security control.

3. **The "enforced by absence" framing for pass-the-hash defense (ADR-086)** is charitable: it's true that no server-side NTLM code exists, so PtH is structurally impossible *today*. But the moment a future wave adds an NTLM verify path (e.g., for legacy compatibility), PtH becomes possible. The structural enforcement needs to be a `#![forbid(unsafe_code)]`-style linter rule or a Cargo feature flag that hard-disables server-side NTLM, not just the absence of code.

4. **The AD-baseline comparison is based on ADR text, not empirical AD testing.** I have not run `secretsdump.py` against Adrian, nor have I run `kinit`/`kpasswd` against a real Adrian KDC (because there is no real Adrian KDC). The "NOT ENFORCED" labels reflect the absence of enforcement code, not the failure of enforcement code in practice.

5. **`cargo audit` was not run**: the supply-chain findings are based on Cargo.lock + workspace Cargo.toml inspection. Without running `cargo audit`, I cannot definitively rule out RUSTSEC advisories on the listed dep versions. The P0 recommendation #13 (add CI) would close this gap.
