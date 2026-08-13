# TASKLIST 10 — Policy, Schema & Auth

**Domain**: Policy engine + schema compiler + auth (NTLM/PAC/claims/federation) + DCE/RPC + SID
**Branch**: `domain-10-policy-auth`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-policy-core/src/lib.rs`
- `rust/crates/adrian-policy-core/Cargo.toml`
- `rust/crates/adrian-policy-executor/src/lib.rs`
- `rust/crates/adrian-policy-executor/Cargo.toml`
- `rust/crates/adrian-policy-preg/src/lib.rs`
- `rust/crates/adrian-policy-preg/Cargo.toml`
- `rust/crates/adrian-policy-cel/src/lib.rs`
- `rust/crates/adrian-policy-cel/Cargo.toml`
- `rust/crates/adrian-admx-compiler/src/lib.rs`
- `rust/crates/adrian-admx-compiler/Cargo.toml`
- `rust/crates/adrian-schema-compiler/src/lib.rs`
- `rust/crates/adrian-schema-compiler/Cargo.toml`
- `rust/crates/adrian-schema-traits/src/lib.rs`
- `rust/crates/adrian-schema-traits/Cargo.toml`
- `rust/crates/adrian-auth-core/src/lib.rs`
- `rust/crates/adrian-auth-core/Cargo.toml`
- `rust/crates/adrian-ntlm-client/src/lib.rs`
- `rust/crates/adrian-ntlm-client/Cargo.toml`
- `rust/crates/adrian-pac-validator/src/lib.rs`
- `rust/crates/adrian-pac-validator/Cargo.toml`
- `rust/crates/adrian-claims-engine/src/lib.rs`
- `rust/crates/adrian-claims-engine/Cargo.toml`
- `rust/crates/adrian-federation-shim/src/lib.rs`
- `rust/crates/adrian-federation-shim/Cargo.toml`
- `rust/crates/adrian-dcerpc/src/lib.rs`
- `rust/crates/adrian-dcerpc/src/ndr.rs`
- `rust/crates/adrian-dcerpc/src/pdu.rs`
- `rust/crates/adrian-dcerpc/src/transport.rs`
- `rust/crates/adrian-dcerpc/Cargo.toml`
- `rust/crates/adrian-kdc-interop/src/lib.rs`
- `rust/crates/adrian-kdc-interop/Cargo.toml`
- `rust/crates/adrian-sid/src/lib.rs`
- `rust/crates/adrian-sid/Cargo.toml`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `adrian-policy-core` (954 lines): `compile_to_preg` real. 21 tests.
- `adrian-policy-executor` (927 lines): `synthesize` real; `apply`/`rollback` stubs. 20 tests.
- `adrian-policy-preg` (637 lines): Real MS-GPREG codec. 12 tests. 5/5 readiness.
- `adrian-policy-cel` (92 lines): STUB — `eval` returns error. 3 tests.
- `adrian-admx-compiler` (803 lines): Parse real; legacy compile lossy. 15 tests.
- `adrian-schema-compiler` (1283 lines): `validate_object` real; `compile_from_directory` hardcoded. 22 tests. 1 ignored (FDB).
- `adrian-schema-traits` (291 lines): Trait definitions. 2 tests. 3 TODOs.
- `adrian-auth-core` (309 lines): Trait real; no backends. 7 tests.
- `adrian-ntlm-client` (1480 lines): Wire format real; **5 tests ignored** — NTLMv2 NT hash computation has a known bug vs MS-NLMP test vectors.
- `adrian-pac-validator` (722 lines): Real parser + two-layer checksum validation per ADR-083. 7 tests. 2 TODOs.
- `adrian-claims-engine` (107 lines): STUB. 3 tests.
- `adrian-federation-shim` (138 lines): STUB. 4 tests.
- `adrian-dcerpc` (2271 lines): NDR + bind/bind_ack real; no server. 49 tests. 8 TODOs.
- `adrian-kdc-interop` (159 lines): STUB. 7 tests. 1 TODO.
- `adrian-sid` (1015 lines): Real SDDL/binary. 35 tests. 5/5 readiness.

## Known Gaps

1. **NTLMv2 NT hash bug** — 5 tests in `adrian-ntlm-client` are `#[ignore]`'d because the NT hash computation produces different bytes than MS-NLMP reference vectors.
2. **Policy `apply`/`rollback` are stubs** — `LinuxPolicyExecutor::apply` returns Ok(()) without writing files.
3. **CEL policy engine is a stub** — `CelSelector::eval` returns error.
4. **Claims engine is a stub** — `ClaimRule::parse`/`to_cel` return errors.
5. **Federation shim is a stub** — `push_jwks_rollover` returns error.
6. **PAC validator has 2 TODOs** — ticket checksum (ADR-123 silver ticket mitigation) and full MS-NDR for KERB_VALIDATION_INFO.
7. **Schema compiler `compile_from_directory` is hardcoded** — doesn't actually read schema files.
8. **DCE/RPC has no server** — only client-side bind/bind_ack; no `DceRpcServer::serve`.
9. **KDC interop is a stub** — no real MIT krb5 / Windows interop tests.

---

## Wave 1: Fix NTLMv2 NT hash bug

**DoD**: All 5 ignored NTLM tests pass (un-ignored). NT hash matches MS-NLMP §3.3.1 reference vectors.

### Tasks

- T-101: Study MS-NLMP §3.3.1 NTLMv2 hash computation: `NTProofStr = HMAC_MD5(NTLMv2Hash, SERVER_CHALLENGE || BLOB)`.
- T-102: Fix the NT hash computation in `adrian-ntlm-client/src/lib.rs` (lines 259-281, 340-356 — the bug is likely in the blob construction or HMAC-MD5 vs HMAC-MD5 of a different input).
- T-103: Verify against MS-NLMP test vectors in the Microsoft MS-NLMP spec appendix.
- T-104: Un-ignore the 5 NTLM tests and verify they pass.
- T-105: Commit `Wave 1: Fix NTLMv2 NT hash bug (+5 tests un-ignored)`

## Wave 2: Policy apply/rollback + CEL engine

**DoD**: `LinuxPolicyExecutor::apply` writes real files (PReg, authselect, sshd_config). CEL engine evaluates real expressions.

### Tasks

- T-201: Implement `LinuxPolicyExecutor::apply(policy)` — write PReg files to `/var/lib/adrian/policy/`, run `authselect select adrian` to configure PAM, update `sshd_config`.
- T-202: Implement `LinuxPolicyExecutor::rollback(policy)` — restore the previous PReg files, revert authselect, revert sshd_config.
- T-203: Implement `CelSelector::eval(expression, context)` — real CEL expression evaluation (use `cel-interpreter` crate or hand-roll a minimal CEL parser).
- T-204: Add 6 tests (apply writes files, rollback restores files, authselect called, CEL eval true/false, CEL eval with context, CEL eval with complex expression).
- T-205: Commit `Wave 2: Policy apply/rollback + CEL engine (+6 tests)`

## Wave 3: PAC full NDR + ticket checksum (ADR-123)

**DoD**: PAC buffers use full MS-NDR encoding for `KERB_VALIDATION_INFO`. Ticket checksum (ADR-123) is validated.

### Tasks

- T-301: Implement MS-NDR encoding for `KERB_VALIDATION_INFO` (the LOGON_INFO buffer) — use `adrian-dcerpc::ndr::NdrWriter`.
- T-302: Update `PacBuilder` to emit NDR-encoded LOGON_INFO instead of self-defined binary.
- T-303: Implement ticket checksum validation in `PacValidator` — verify `PAC_BUFFER_TICKET_CHECKSUM` (type 0x10) matches the ticket's enc-part (ADR-123 silver ticket mitigation).
- T-304: Add 5 tests (NDR LOGON_INFO round-trip, PAC with NDR buffers parses, ticket checksum valid, ticket checksum invalid (silver ticket attack), ticket checksum missing rejected).
- T-305: Commit `Wave 3: PAC full MS-NDR + ticket checksum (ADR-123) (+5 tests)`

## Wave 4: Claims engine + federation shim + DCE/RPC server

**DoD**: Claims engine parses and evaluates claim rules. Federation shim pushes JWKS. DCE/RPC server accepts connections.

### Tasks

- T-401: Implement `ClaimRule::parse(rule_text)` — parse ADFS-style claim rule language per ADR-101.
- T-402: Implement `ClaimRule::to_cel()` — convert claim rule to CEL expression.
- T-403: Implement `ClaimsEngine::evaluate(claim_rules, input_claims) -> output_claims`.
- T-404: Implement `FederationShim::push_jwks_rollover(jwks)` — POST JWKS to federation partners via webhook (ADR-038).
- T-405: Implement `DceRpcServer::serve(addr, handler)` — TCP listener that accepts DCE/RPC bind requests and dispatches to handlers.
- T-406: Add 7 tests (claim rule parse, claim rule to_cel, claims evaluate, JWKS push success, JWKS push retry, DCE/RPC server bind, DCE/RPC server request/response).
- T-407: Commit `Wave 4: Claims engine + federation shim + DCE/RPC server (+7 tests)`

## Wave 5: Schema compiler + KDC interop fixtures

**DoD**: `compile_from_directory` reads real schema files. KDC interop has real test fixtures.

### Tasks

- T-501: Implement `SchemaCompiler::compile_from_directory(path)` — reads `*.ldif` schema files, parses attributeClass / objectClass definitions, generates `SchemaProjection`.
- T-502: Add a test schema directory with sample LDIF files.
- T-503: Implement `KdcInteropFixture` in `adrian-kdc-interop` — starts an in-process KDC, generates an AS-REQ, verifies the AS-REP can be decoded by `rasn-kerberos`.
- T-504: Add 5 tests (compile from directory, schema projection has expected attributes, KDC interop AS-REQ round-trip, KDC interop TGS-REQ round-trip, KDC interop PAC validation).
- T-505: Commit `Wave 5: Schema compiler + KDC interop fixtures (+5 tests)`

---

## Final DoD (all waves)

- `cargo test` for all 14 crates in this domain — all tests pass, 0 ignored (NTLM tests un-ignored)
- `cargo clippy` clean for all 14 crates
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
