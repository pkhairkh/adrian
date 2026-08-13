# TASKLIST 02 — KDC Handlers & kpasswd

**Domain**: KDC AS-REQ/TGS-REQ handler logic + kpasswd + krbtgt rotation + gMSA
**Branch**: `domain-02-kdc-handlers`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-kdc/src/handlers.rs`
- `rust/crates/adrian-kdc/src/kpasswd.rs`
- `rust/crates/adrian-kdc/src/krbtgt.rs`
- `rust/crates/adrian-kdc/src/gmsa.rs`
- `rust/crates/adrian-kdc/src/store.rs`
- `rust/crates/adrian-kdc/src/lib.rs` (only the `KdcService` struct + handler dispatch, NOT crypto/wire/key_derivation modules)

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `handlers.rs`: Real AS-REQ/TGS-REQ handlers with rasn-kerberos wire encoding. 41 tests.
- `kpasswd.rs`: KRB-PRIV envelope wired (P0 #9 closed). 21 tests. Replay cache real.
- `krbtgt.rs`: HSM-bound krbtgt rotation manager.
- `gmsa.rs`: gMSA KDF (known bug: uses HMAC-SHA1-96 truncation instead of full HMAC-SHA1 per SP800-108 §5.1).
- `store.rs`: `PrincipalStore` trait + `InMemoryPrincipalStore`.

## Known Gaps

1. **No FAST armoring (RFC 6806)** — ADR-012 mandates FAST armor for all AS-REQs but handlers accept unarmored requests.
2. **No PKINIT (RFC 4556)** — `pkinit-smartcard` and `pkinit-fido2` feature flags are stubs.
3. **No cross-realm TGT referral (ADR-013)** — handler always answers from local realm.
4. **No S4U2Self / S4U2Proxy (ADR-087)** — handler requires a real client TGT.
5. **gMSA KDF bug** — uses HMAC-SHA1-96 (12 bytes) instead of full HMAC-SHA1 (20 bytes) per SP800-108 §5.1.
6. **No krbtgt auto-rotation scheduling** — `KrbtgtManager` supports manual rotation but no cron/timer.
7. **No KDC pre-auth plugin framework** — only PA-ENC-TIMESTAMP is supported.

---

## Wave 1: FAST armoring (RFC 6806)

**DoD**: AS-REQ handlers accept and verify FAST armor (TGS-REQ wrapped in armor TGT). Unarmored AS-REQs are rejected when FAST is required (configurable).

### Tasks

- T-101: Define `FastArmorKey` type (derived from armor TGT session key per RFC 6806 §5.4).
- T-102: Implement `unwrap_fast_armor(as_req) -> InnerAsReq` that decrypts the FAST factor.
- T-103: Add `KdcService::handle_as_req_fast` that requires FAST armor.
- T-104: Add 5 tests (FAST-wrapped AS-REQ succeeds, unarmored rejected when required, tampered armor rejected, wrong armor key rejected, FAST factor round-trip).
- T-105: Commit `Wave 1: FAST armoring (RFC 6806) (+5 tests)`

## Wave 2: gMSA KDF fix + SP800-108 compliance

**DoD**: gMSA KDF uses full HMAC-SHA1 (20 bytes) per SP800-108 §5.1. All gMSA tests pass.

### Tasks

- T-201: Fix `gmsa::compute_password_hash` to use full HMAC-SHA1 output (20 bytes), not truncated HMAC-SHA1-96 (12 bytes).
- T-202: Add SP800-108 §5.1 test vectors (counter mode KDF with HMAC-SHA1 PRF).
- T-203: Add 4 tests (gMSA hash round-trip, KDF counter mode, wrong key rejected, domain separation).
- T-204: Commit `Wave 2: gMSA KDF fix — full HMAC-SHA1 per SP800-108 §5.1 (+4 tests)`

## Wave 3: Cross-realm TGT referral (ADR-013)

**DoD**: AS-REQ for a principal in a foreign realm returns a referral TGT to the client's realm KDC.

### Tasks

- T-301: Implement realm lookup (check if requested principal's realm matches local realm).
- T-302: If foreign realm, construct a referral TGT (TGT encrypted with the cross-realm key, `sname = krbtgt/FOREIGN_REALM`).
- T-303: Add `KdcService::handle_cross_realm_referral`.
- T-304: Add 4 tests (referral TGT for foreign realm, local realm no referral, cross-realm key rotation, capath validation per ADR-069).
- T-305: Commit `Wave 3: Cross-realm TGT referral (ADR-013) (+4 tests)`

## Wave 4: S4U2Self + S4U2Proxy (ADR-087)

**DoD**: `handle_tgs_req` supports S4U2Self (service requests a ticket to itself on behalf of a user) and S4U2Proxy (service forwards a user's ticket to another service).

### Tasks

- T-401: Implement S4U2Self — parse PA-FOR-USER padata, construct service ticket with the user's identity.
- T-402: Implement S4U2Proxy — parse the evidence ticket, verify constrained delegation rights, construct forwarded ticket.
- T-403: Add ACL check: verify the service is allowed to delegate for the target user (check `msDS-AllowedToDelegateTo`).
- T-404: Add 5 tests (S4U2Self succeeds, S4U2Proxy succeeds, delegation not allowed, evidence ticket tampered, cross-protocol attack rejected).
- T-405: Commit `Wave 4: S4U2Self + S4U2Proxy constrained delegation (ADR-087) (+5 tests)`

## Wave 5: krbtgt auto-rotation + KDC pre-auth plugin framework

**DoD**: krbtgt key auto-rotates every 30 days (ADR-015). Pre-auth plugins are extensible.

### Tasks

- T-501: Implement `KrbtgtRotationScheduler` that triggers `rotate_key` every 30 days.
- T-502: Define `PreAuthPlugin` trait with `verify_pa_data(&self, padata, client) -> Result<()>`.
- T-503: Implement `PaEncTimestampPlugin` (existing PA-ENC-TIMESTAMP logic refactored into a plugin).
- T-504: Add 4 tests (rotation triggers on schedule, old key still valid during overlap window, plugin registration, unknown padata type rejected).
- T-505: Commit `Wave 5: krbtgt auto-rotation + pre-auth plugin framework (+4 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-kdc --lib handlers` — all tests pass
- `cargo test -p adrian-kdc --lib kpasswd` — all tests pass
- `cargo test -p adrian-kdc --lib gmsa` — all tests pass (gMSA KDF fixed)
- `cargo clippy -p adrian-kdc -- -D warnings` clean
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
