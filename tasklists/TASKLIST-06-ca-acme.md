# TASKLIST 06 — CA, ACME & PKI

**Domain**: Certificate Authority + ACME server (RFC 8555) + HSM + WCCE bridge
**Branch**: `domain-06-ca-acme`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-ca/src/lib.rs`
- `rust/crates/adrian-ca/Cargo.toml`
- `rust/crates/adrian-acme-server/src/lib.rs`
- `rust/crates/adrian-acme-server/Cargo.toml`
- `rust/crates/adrian-wcce-bridge/src/lib.rs`
- `rust/crates/adrian-wcce-bridge/Cargo.toml`
- `rust/crates/adrian-hsm/src/lib.rs`
- `rust/crates/adrian-hsm/Cargo.toml`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `adrian-ca` (1331 lines): Real X.509 v3 cert issuance via `rasn-pkix` + `ring::signature`. Self-signed root CA, end-entity certs from CSRs, 4 cert profiles (WebServer, Client, CodeSigning, KerberosKdc), CRL. 24 tests.
- `adrian-acme-server` (1646 lines): RFC 8555 endpoints (directory, newNonce, newAccount, newOrder, authz, challenge, finalize, cert). JWS verification with ECDSA-P256. 15 tests.
- `adrian-wcce-bridge` (165 lines): STUB — MS-WCCE → ACME translation not implemented. 4 TODOs.
- `adrian-hsm` (795 lines): `SoftwareHsm` with AES-256-GCM + HMAC-SHA1. `KeyType::Aes256` + `KeyType::HmacSha1` only. 17 tests.

## Known Gaps

1. **CA uses `ring::signature` directly, not `adrian-hsm`** — the HSM trait doesn't support ECDSA. Need to extend `KeyType` with `EcdsaP256`.
2. **No OCSP responder (RFC 6960)** — ADR-035 specifies OCSP but no code exists.
3. **No real ACME challenge verification** — POST /challenge/{id} auto-marks the challenge `valid` without actually fetching the http-01 URL.
4. **No ARI (RFC 8823)** — ACME Renewal Information endpoint is a placeholder.
5. **WCCE bridge is a stub** — `translate_request` returns `TranslationError` without doing real MS-WCCE → ACME translation.
6. **No PKCS#11 HSM backend (ADR-015)** — only `SoftwareHsm` exists; `enterprise-hsm` feature gates `cryptoki` but the backend is not implemented.
7. **No cert template YAML (ADR-096)** — cert profiles are hardcoded Rust enums, not YAML-driven.

---

## Wave 1: Extend HSM with ECDSA + wire CA through HSM

**DoD**: `KeyType::EcdsaP256` supported in `adrian-hsm`. `adrian-ca` signs certs through the HSM trait, not `ring` directly.

### Tasks

- T-101: Add `KeyType::EcdsaP256` variant to `adrian-hsm`.
- T-102: Implement `SoftwareHsm::generate_key("name", KeyType::EcdsaP256)` using `ring::signature::EcdsaKeyPair`.
- T-103: Implement `Hsm::sign_ecdsa(key_handle, data) -> Result<Vec<u8>>` and `Hsm::verify_ecdsa(key_handle, data, sig) -> Result<bool>`.
- T-104: Refactor `adrian-ca` to use `Hsm::sign_ecdsa` instead of `ring::signature` directly.
- T-105: Add 6 tests (ECDSA key generation, sign/verify round-trip, wrong key rejected, CA signs through HSM, HSM key rotation, key handle persistence).
- T-106: Commit `Wave 1: HSM ECDSA support + CA signs through HSM (+6 tests)`

## Wave 2: OCSP responder (RFC 6960)

**DoD**: OCSP responder serves real RFC 6960 responses. Cert status can be queried.

### Tasks

- T-201: Implement `OcspResponder` — HTTP endpoint that accepts OCSP requests (DER-encoded `OCSPRequest`) and returns `OCSPResponse`.
- T-202: Implement OCSP nonce extension (RFC 8954) — prevents replay attacks.
- T-203: Wire OCSP responder to the CA's revocation list — returns `good`, `revoked`, or `unknown` based on CRL.
- T-204: Implement OCSP signing — responses signed by the CA's OCSP signing key (may be the CA key or a delegated OCSP key per ADR-035).
- T-205: Add 5 tests (OCSP request/response round-trip, good cert, revoked cert, unknown cert, nonce replay rejection).
- T-206: Commit `Wave 2: OCSP responder (RFC 6960) + nonce (+5 tests)`

## Wave 3: Real ACME challenge verification + ARI

**DoD**: ACME http-01 challenge is actually verified (HTTP GET to the challenge URL). ARI endpoint returns renewal info.

### Tasks

- T-301: Implement `verify_http_01_challenge(domain, token, key_auth)` — makes an HTTP GET to `http://{domain}/.well-known/acme-challenge/{token}` and verifies the response matches `{key_auth}`.
- T-302: Implement `verify_dns_01_challenge(domain, txt_record)` — queries DNS for `_acme-challenge.{domain}` TXT record and verifies it matches the expected value.
- T-303: Implement ARI (RFC 8823) endpoint `GET /draft-ietf-acme-ari-03/renewal-info/{certID}` — returns suggested renewal window.
- T-304: Add 5 tests (http-01 success, http-01 failure (wrong response), dns-01 success, ARI returns renewal window, ARI for non-existent cert).
- T-305: Commit `Wave 3: Real ACME challenge verification + ARI (RFC 8823) (+5 tests)`

## Wave 4: WCCE bridge + cert template YAML (ADR-096)

**DoD**: MS-WCCE requests are translated to ACME orders. Cert profiles are YAML-driven.

### Tasks

- T-401: Implement `WcceBridge::translate_request(wcce_request)` — parse MS-WCCE cert request (per MS-WCCE protocol) and create an equivalent ACME order.
- T-402: Implement `WcceBridge::translate_response(acme_cert)` — convert the ACME-issued cert to an MS-WCCE response.
- T-403: Define cert profile YAML schema (ADR-096) — `profiles/webserver.yaml`, `profiles/client.yaml`, etc.
- T-404: Implement `CertProfile::from_yaml(path)` — load cert profile from YAML.
- T-405: Add 6 tests (WCCE→ACME translation, ACME→WCCE translation, YAML profile loading, YAML profile validation, profile override at issuance, unknown profile rejected).
- T-406: Commit `Wave 4: WCCE bridge + cert template YAML (ADR-096) (+6 tests)`

## Wave 5: PKCS#11 HSM backend (ADR-015)

**DoD**: `enterprise-hsm` feature compiles with `cryptoki`. Real PKCS#11 HSM backend (e.g., SoftHSM for testing) works.

### Tasks

- T-501: Implement `Pkcs11Hsm` struct that wraps `cryptoki::Session`.
- T-502: Implement `Hsm` trait for `Pkcs11Hsm` — `generate_key`, `encrypt`, `decrypt`, `sign`, `verify` via PKCS#11 API.
- T-503: Add `Pkcs11Hsm::new(library_path, slot_id, pin)` constructor.
- T-504: Add integration tests using SoftHSM (install `softhsm2` + `softhsm2-module`).
- T-505: Add 4 tests (PKCS#11 key generation, sign/verify via PKCS#11, AES-GCM via PKCS#11, key persistence across sessions).
- T-506: Commit `Wave 5: PKCS#11 HSM backend (ADR-015) (+4 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-ca -p adrian-acme-server -p adrian-wcce-bridge -p adrian-hsm` — all tests pass
- `cargo check --features enterprise-hsm -p adrian-hsm` compiles (if cryptoki available)
- `cargo clippy` clean for all 4 crates
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
