# TASKLIST 08 — SDK & CLI

**Domain**: Cross-platform SDK (Rust + C + JNI + Swift + Python) + CLI
**Branch**: `domain-08-sdk-cli`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-sdk/src/lib.rs`
- `rust/crates/adrian-sdk/Cargo.toml`
- `rust/crates/adrian-sdk-c/src/lib.rs`
- `rust/crates/adrian-sdk-c/Cargo.toml`
- `rust/crates/adrian-sdk-jni/src/lib.rs`
- `rust/crates/adrian-sdk-jni/Cargo.toml`
- `rust/crates/adrian-sdk-swift/src/lib.rs`
- `rust/crates/adrian-sdk-swift/Cargo.toml`
- `rust/crates/adrian-sdk-python/src/lib.rs`
- `rust/crates/adrian-sdk-python/Cargo.toml`
- `rust/crates/adrian-cli/src/lib.rs`
- `rust/crates/adrian-cli/src/main.rs`
- `rust/crates/adrian-cli/Cargo.toml`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `adrian-sdk` (1412 lines): `KerberosAuthModule` wired to KDC (Wave 3c v0.6.0). Other 4 modules (`LdapDirectoryModule`, `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`) return "not yet wired" errors. 20 tests.
- `adrian-sdk-c` (419 lines): FFI plumbing real, wraps the SDK stub. 8 tests.
- `adrian-sdk-jni` (128 lines): STUB. 0 tests. 1 TODO.
- `adrian-sdk-swift` (127 lines): STUB. 0 tests.
- `adrian-sdk-python` (119 lines): STUB. 0 tests. 1 TODO.
- `adrian-cli` (1062 lines): `join` + `policy apply` dispatch real. Other subcommands (`klist`, `kinit`, `auth`, `cert`, `file`, `migrate`, `gpo-translate`, `kdc rotate-krbtgt`) either silent-Ok or loud stubs. 6 tests.

## Known Gaps

1. **`LdapDirectoryModule::search`** returns "not yet wired to adrian-directory-service" — needs real LDAP client.
2. **`DeclarativePolicyModule::apply`** returns "not yet wired to adrian-policy-executor".
3. **`SmbFileModule::mount_share`** returns "not yet wired to adrian-smb-client (ADR-106)".
4. **`AcmeCertModule::enroll`** returns "not yet wired to adrian-acme-server (ADR-095/097)".
5. **JNI/Swift/Python SDK bindings are stubs** — no real FFI wrappers.
6. **CLI `klist`/`kinit`/`auth`/`cert`/`file` subcommands are silent-Ok** — they `tracing::info!` and return `Ok(())` without doing work.
7. **No `adrian-cli` integration tests** — only 6 unit tests of argument parsing.

---

## Wave 1: Wire SDK modules to real backends

**DoD**: All 5 SDK modules (`KerberosAuthModule`, `LdapDirectoryModule`, `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`) dispatch to real backends.

### Tasks

- T-101: Wire `LdapDirectoryModule::search` to `adrian-directory-service` (use `ldap3` client to connect to a running DSA).
- T-102: Wire `DeclarativePolicyModule::apply` to `adrian-policy-executor::LinuxPolicyExecutor::apply`.
- T-103: Wire `SmbFileModule::mount_share` to `adrian-smb-client` (open a session + tree connect).
- T-104: Wire `AcmeCertModule::enroll` to `adrian-acme-server` (HTTP POST to the ACME endpoints).
- T-105: Add 8 tests (2 per module: success path + error propagation).
- T-106: Commit `Wave 1: Wire all 5 SDK modules to real backends (+8 tests)`

## Wave 2: Convert CLI silent-Ok subcommands to real dispatch

**DoD**: All CLI subcommands either dispatch to a real backend or return a loud `CliError::NotImplemented`. No silent-Ok.

### Tasks

- T-201: Implement `kinit` — calls `KerberosAuthModule::authenticate_kerberos`, stores TGT in a credential cache file.
- T-202: Implement `klist` — reads the credential cache, prints active tickets.
- T-203: Implement `auth` — calls `KerberosAuthModule::authenticate_kerberos`, verifies success.
- T-204: Implement `cert` — calls `AcmeCertModule::enroll`, saves cert to disk.
- T-205: Implement `file` — calls `SmbFileModule::mount_share`, mounts the share.
- T-206: Implement `kdc rotate-krbtgt` — calls `KrbtgtManager::rotate_key` via a KDC admin RPC.
- T-207: Add 7 tests (one per subcommand: verify it dispatches correctly).
- T-208: Commit `Wave 2: CLI subcommands — real dispatch (no silent-Ok) (+7 tests)`

## Wave 3: JNI binding + Swift binding

**DoD**: JNI and Swift SDK bindings have real FFI wrappers that call into `adrian-sdk-c`.

### Tasks

- T-301: Implement `AdrianSdkJni::joinRealm(env, realm, hostname)` — JNI function that calls `adrian_sdk_c::adrian_join`.
- T-302: Implement `AdrianSdkJni::authenticate(env, principal, password)` — JNI function for Kerberos auth.
- T-303: Implement Swift bindings — `AdrianSdk.swift` with `joinRealm`, `authenticate`, `searchDirectory`, `applyPolicy`, `mountShare`, `enrollCert`.
- T-304: Add 4 tests (JNI join round-trip, JNI auth round-trip, Swift binding compiles, Swift binding calls C FFI).
- T-305: Commit `Wave 3: JNI + Swift SDK bindings (+4 tests)`

## Wave 4: Python binding + CLI integration tests

**DoD**: Python SDK binding works (pyo3). CLI has end-to-end integration tests using `assert_cmd`.

### Tasks

- T-401: Implement `adrian_sdk_python` — pyo3 module with `join_realm`, `authenticate`, `search_directory`, `apply_policy`, `mount_share`, `enroll_cert` functions.
- T-402: Add 3 Python tests (join + auth flow, search directory, enroll cert).
- T-403: Add CLI integration tests using `assert_cmd` — `adrian join`, `adrian kinit`, `adrian klist`, `adrian auth` end-to-end.
- T-404: Add 5 CLI integration tests (join succeeds, kinit creates cache, klist prints ticket, auth succeeds, unknown command fails).
- T-405: Commit `Wave 4: Python binding + CLI integration tests (+8 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-sdk -p adrian-sdk-c -p adrian-sdk-jni -p adrian-sdk-swift -p adrian-sdk-python -p adrian-cli` — all tests pass
- `cargo clippy` clean for all 6 crates
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
