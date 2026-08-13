# Adrian Framework — v0.7.0 Handover State

**Date**: 2026-08-14
**Repo HEAD**: `391f096` on `main` (v0.6.0 — "Wave 4: Final audit — CHANGELOG v0.6.0 (738 tests, 9/10 P0 items closed)")
**Verified by**: v0.7.0 orchestrator (Wave 0)

---

## Baseline Verification (Wave 0 DoD — PASSED)

| Check | Command | Result |
|-------|---------|--------|
| Workspace test count | `cargo test --workspace` | **738 passed / 0 failed / 16 ignored** ✓ |
| Clippy (deny warnings) | `cargo clippy --workspace --all-targets -- -D warnings` | **Finished `dev` profile** (clean) ✓ |
| Format check | `cargo fmt --all --check` | **exit 0** (clean) ✓ |
| Toolchain | `rustc --version` | `1.97.1 (8bab26f4f 2026-07-14)` ✓ |
| Workspace size | `ls rust/crates/ \| wc -l` | 47 crates ✓ |

## v0.6.0 Architecture Recap

47-crate workspace organized in 5 layers:
- **L0 Foundation** (4 crates): storage-core, sid, schema-traits, repl-core — all REAL_COMPLETE.
- **L1 Abstractions** (5 crates): storage-fdb, identity-core/fdb/ridpool/testkit — real with in-memory fallback.
- **L2 Domain** (17 crates): storage-testkit, dcerpc, drsuapi, raft, directory-service, schema-compiler, kdc (+8 submodules), hsm, ntlm-client, pac-validator, auth-core, policy-*, admx-compiler, repl-testkit — mixed real/stub.
- **L3 Services** (10 crates): ca, acme-server, wcce-bridge, smb-{server,client,core}, print-service, federation-shim, policy-cel, claims-engine — **ALL STUBS**.
- **L4 Ops** (11 crates): sdk (+4 bindings), cli, monitor, operator, gpo-translate, migrate, test-harness — mixed.

## What's Missing (v0.7.0 scope)

### P0 (1 remaining)
- **P0 #9**: kpasswd KRB-PRIV wiring — `KrbPrivEnvelope` API exists but not wired into `handle_kpasswd`.

### Wire-compat gaps (from CHANGELOG v0.6.0 "What's still stub")
1. **Kerberos ASN.1/DER** — v0.6.0 uses simplified self-consistent binary (handlers.rs magic bytes 0xA1-0xB5). v0.7.0 must use `rasn-kerberos`.
2. **AES-CBC-CTS per RFC 2040 §6** — v0.6.0 uses AES-CTR placeholder (crypto.rs:93-110). v0.7.0 must implement real CTS.
3. **Real FDB cluster integration tests** — requires libclang + FDB C client (deferred — not in v0.7.0 critical path).
4. **SMB 3.1.1 server** — STUB_SILENT.
5. **ACME server** — STUB_SILENT (empty axum router).
6. **CA service** — STUB_LOUD.
7. **`.github/workflows/`** — PAT lacks `workflow` scope (committed to `ci-templates/` instead).

### P1/P2 items (covered by v0.7.0 waves)
- P1 #19: `adrian-test-harness` in-process fixtures (Wave 4a)
- P1 #20: `cargo bench` with criterion (Wave 4a)
- P2 #21: Real LDAP server (Wave 2a)
- P2 #22: Real DRSUAPI NDR codec (Wave 2b)
- P2 #23: Real SMB 3.1.1 server (Wave 3b)
- P2 #24: Real ACME server (Wave 3a)
- P2 #25: Real CA service (Wave 3a)
- P2 #27: Operator reconcile loop (Wave 4b)

## v0.7.0 Wave Plan

| Wave | Scope | DoD test target |
|------|-------|-----------------|
| 0 | Environment verification + baseline check | 738 (verified) |
| 1 | Wire-format upgrade — ASN.1/DER + AES-CBC-CTS | ≥ 758 |
| 2 | Protocol services — LDAP + DRSUAPI real handlers | ≥ 788 |
| 3 | Cert + SMB services + kpasswd KRB-PRIV | ≥ 828 |
| 4 | Ops + integration + final audit | ≥ 848 |

## Environment Constraints

- **Disk**: 9.9GB total, ~5-7GB available after build. `cargo clean` between waves if needed.
- **Rust**: 1.97.1 (stable, minimal profile + clippy + rustfmt).
- **FDB**: `fdb` feature OFF (no libclang) — tests run against in-memory fallback.
- **PAT**: lacks `workflow` scope — `.github/workflows/` cannot be pushed.
- **Sub-agent timeouts**: ~10 minutes. Check `git log` + file state before re-dispatching.

## Critical Files (Wave 1 targets)

| File | Lines | Owner sub-task | Current state |
|------|-------|---------------|---------------|
| `rust/crates/adrian-kdc/src/crypto.rs` | 347 | 1a | AES-CTR placeholder (lines 93-110). `aes256_cts_encrypt`/`decrypt` use `aes256_ctr_apply`. |
| `rust/crates/adrian-kdc/src/handlers.rs` | 2472 | 1b | Custom length-prefixed binary (magic bytes 0xA1-0xB5). 25 encode/decode fns (lines 454-870). |
| `rust/crates/adrian-kdc/src/pac.rs` | 1694 | 1c | Self-defined binary PAC format. 6 build/parse fns. |

## Workspace Dependency Notes

Already available (no Cargo.toml changes needed for Wave 1):
- `rasn = "0.22"`, `rasn-kerberos = "0.22"` — for ASN.1/DER encoding.
- `rasn-ldap = "0.22"`, `rasn-pkix = "0.22"` — for Wave 2/3.
- `x509-cert = "0.2"` — for Wave 3 CA.
- `aes = "0.8"`, `subtle = "2"`, `zeroize = "1"` — for crypto.
- `axum = "0.8"`, `hyper = "1"`, `tokio-rustls = "0.26"` — for ACME/SMB servers.

## Critical Constraints (from HANDOVER_PROMPT.md)

1. Rust only. No C/Python/Go for framework code (FFI bindings excepted).
2. `#![forbid(unsafe_code)]` in every crate (only `adrian-sdk-c` uses `deny` + per-function `allow`).
3. Async runtime: `tokio` (rt-multi-thread).
4. Errors: `thiserror` for libs, `anyhow` for binaries.
5. License: MIT. No GPLv3.
6. `uuid` crate features: `["v7", "serde"]` only — `Uuid::new_v4()` NOT available.
7. Commits: one per sub-task. Push after each wave. Format: `Wave N: <description> (+M tests)`.
8. Tests: every new function gets a unit test; every protocol handler gets a round-trip test.
9. Sub-agent file ownership: EXCLUSIVE. Use `git add <specific-files>`.
10. Worklog: `/home/z/my-project/worklog.md` — read before, append after.

## Success Criteria (v0.7.0 — all must pass)

- [ ] `cargo test --workspace` ≥ 848 passed, 0 failed
- [ ] `cargo check --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo fmt --all --check` passes
- [ ] Local HEAD = remote HEAD on `main`
- [ ] CHANGELOG.md updated to v0.7.0
- [ ] KDC uses `rasn-kerberos` for ASN.1/DER (not simplified binary)
- [ ] AES-CBC-CTS per RFC 2040 §6 (not AES-CTR placeholder)
- [ ] LDAP server serves RFC 4511 BER over TCP
- [ ] DRSUAPI handlers use real MS-DRSR NDR codec
- [ ] ACME server serves RFC 8555 endpoints
- [ ] CA service issues real X.509 v3 certs
- [ ] SMB 3.1.1 server handles Negotiate/SessionSetup/TreeConnect/Create/Read/Write/Close
- [ ] kpasswd wraps new password in KRB-PRIV (P0 #9 closed)
- [ ] `adrian-test-harness` has in-process fixtures
- [ ] `cargo bench` setup with criterion
- [ ] Operator reconcile loop is real
