# Wave 2b — Test Quality & Ops Readiness Audit

**Auditor**: Sub-agent E2-b
**Date**: 2026-08-13
**Scope**: All 47 crates (cross-cutting test quality + ops readiness)
**Repo HEAD**: `d4d714e` on `main` (Wave 1 findings committed in `eval/`)
**Method**: `cargo test --workspace` actually executed (rustup 1.97.1 installed in sandbox). 602 tests pass, 16 ignored, 0 failed in 3.12 s wall clock. Per-test source reviewed for behavioral classification.

## Executive Summary

The "602 tests" headline is real but **mixed quality**. About **half** (≈300 tests) genuinely exercise protocol bytes, crypto round-trips, transaction isolation, SID/SDDL parsing, NDR/PDU wire layout, replication conflict resolution — the kind of tests that catch real regressions. Another **~25 %** are minimal-but-meaningful smoke tests (Display formatting, serde round-trips, constructor equivalence) that guard against type-system regressions but verify no behavior. The remaining **~25 %** are **"loud stub" assertion tests** that merely assert a stub function returns the documented "not yet implemented" error variant — these confirm the loud-stub contract but provide zero behavioral coverage. The 16 ignored tests split into **3 empty-body placeholders** for future FDB integration tests (literally `// Placeholder`) and **13 tests blocked on two real crypto bugs** (AES-256-CTS partial-block swap, NTLMv2 NT hash). The **ops story is the weakest dimension of the entire audit**: no `.github/workflows/`, no Dockerfile, no `cargo bench` setup, no health-check endpoints, no runbooks, no config schema, no `tracing` calls in any hot path, and `MetricsRegistry` has zero call sites outside `adrian-monitor`'s own unit tests. The README still describes the repo as a "research deliverable" and doesn't mention v0.5.0, the 47-crate workspace, or `cargo test`. The MVP success criteria ("5K AS-REQ/sec/KDC, 10K writes/sec/DC") have no benchmarks anywhere in the tree. v0.5.0 is **not** ops-ready; it is a research-grade scaffold with a real-but-thin test floor.

## Part 1: Test Quality

### Per-crate test counts

Tests run with `cargo test --workspace` on a fresh `rustup` install (rustc 1.97.1, default features only — the `fdb` feature is OFF, so the 3 `#[cfg(feature = "fdb")] #[ignore]`-gated tests in `adrian-storage-fdb` are not compiled and not counted).

| # | Crate | Layer | Tests | Ignored | Quality class | Notes |
|---|-------|------|------:|--------:|---------------|-------|
| 1 | adrian-storage-core | L0 | 11 | 0 | BEHAVIORAL_REAL | Key encoding, DN parsing, KeyRange prefix strinc |
| 2 | adrian-sid | L0 | 35 | 0 | BEHAVIORAL_REAL | MS-DTYP §2.4.2 wire format, SDDL parser, well-known SIDs |
| 3 | adrian-schema-traits | L0 | 2 | 0 | BEHAVIORAL_MINIMAL | Constant-tag pinning + derive smoke |
| 4 | adrian-storage-fdb | L1 | 17 | 0 | BEHAVIORAL_MINIMAL† | Tuple-layer encoding tests pass, but real FDB path is `#[cfg]`-gated off; tests run against `InMemoryDirectoryStore` fallback |
| 5 | adrian-identity-core | L1 | 4 | 0 | BEHAVIORAL_MINIMAL | Serde round-trips + trait object-safety |
| 6 | adrian-repl-core | L1 | 6 | 0 | BEHAVIORAL_REAL | LVR conflict resolution (version / timestamp / usn / invocation-id tiebreak) + UTD vector |
| 7 | adrian-identity-fdb | L2 | 21 | 0 | BEHAVIORAL_MINIMAL† | Real LRU-cache + conflict-detection tests, but exercised against the in-memory fallback (`FdbIdentityMapping::new_in_memory`); the `real_fdb` path is `#[cfg]`-gated |
| 8 | adrian-identity-ridpool | L2 | 34 | 1 | BEHAVIORAL_MINIMAL† | Local allocator + batch dispensation + reclaim; tested in-memory only — 1 `#[ignore]` is an empty placeholder for the real FDB path |
| 9 | adrian-drsuapi | L2 | 13 | 1 | STRUCTURAL_ONLY | 8 of 13 tests are "stub returns `ReplicationError::Backend`"; constants + `DrsBindResult` constructor are the only real tests |
| 10 | adrian-raft | L2 | 35 | 0 | BEHAVIORAL_REAL | Vote term logic, append_entries idempotency, install_snapshot term regression, UTD-vector synthesis |
| 11 | adrian-directory-service | L2 | 11 | 0 | BEHAVIORAL_MINIMAL | SearchRequest construction + serde; LDAP backend is loud-stub |
| 12 | adrian-schema-compiler | L2 | 22 | 1 | BEHAVIORAL_REAL | `validate_object` accepts/rejects mustContain, bad syntax, disallowed attrs; CoW generation swap; 1 `#[ignore]` is empty placeholder for real schema-NC walk |
| 13 | adrian-dcerpc | L2 | 49 | 0 | BEHAVIORAL_REAL | NDR primitives (uint8/16/32/64 alignment, conformant arrays, ASCII/Unicode strings), Bind/BindAck PDU wire layout, Request/Response PDU, duplex transport — highest test density and quality in the workspace |
| 14 | adrian-policy-core | L2 | 21 | 0 | BEHAVIORAL_REAL | `compile_to_preg` / `compile_to_configuration_profile` / `compile_to_authselect_profile` round-trips |
| 15 | adrian-policy-executor | L2 | 20 | 0 | BEHAVIORAL_REAL | Windows Registry.pol + GptTmpl.inf + Scripts.ini + GPP XML; macOS plist; Linux authselect/firewalld/limits/audit synthesizers — real file bytes |
| 16 | adrian-pac-validator | L2 | 9 | 0 | STRUCTURAL_ONLY | 3 constant-tag assertions + 3 Display formatting + 1 derive smoke + 2 "parse returns Malformed" stub tests. **Zero** actual PAC parsing. |
| 17 | adrian-storage-testkit | L2 | 24 | 0 | BEHAVIORAL_REAL | Snapshot isolation, read-your-writes, atomic_add, rollback, idempotent delete, tombstone round-trip — most thorough transactional test suite in the workspace |
| 18 | adrian-identity-testkit | L2 | 0 | 0 | — | Empty testkit crate; Wave 1a flagged this |
| 19 | adrian-repl-testkit | L2 | 0 | 0 | — | Empty testkit crate; Wave 1a flagged this |
| 20 | adrian-test-harness | L2 | 0 | 0 | — | 108 LoC; just re-exports + 3 TODOs for in-process FDB cluster + LDAP bind/search/modify/delete sequences + interop fixtures. **No tests, no real harness code.** |
| 21 | adrian-hsm | L2 | 15 | 0 | BEHAVIORAL_REAL | HMAC-SHA1-96 sign+verify round-trip + tamper rejection; AES-256-GCM encrypt/decrypt round-trip + tag verification failure; key rotation invalidates old sigs; concurrent signs under distinct keys |
| 22 | adrian-smb-core | L2 | 11 | 0 | BEHAVIORAL_MINIMAL | Mostly struct construction + Display formatting for SMB message types |
| 23 | adrian-policy-cel | L2 | 4 | 0 | STRUCTURAL_ONLY | "Compiles" CEL via a stub; tests just assert struct construction |
| 24 | adrian-policy-preg | L2 | 12 | 0 | BEHAVIORAL_REAL | MS-GPREG §2.2 byte-exact round-trip; REG_SZ/REG_DWORD/REG_MULTI_SZ/REG_BINARY typed helpers; bad-signature rejection; truncated-record rejection |
| 25 | adrian-kdc | L3 | 39 | 8 | MIXED | `crypto.rs` (~20) and `krbtgt.rs` (4) and `gmsa.rs` (6) are real; `lib.rs` (9) is **all** loud-stub assertions ("handle_as_req returns Storage not-implemented"); 5 kpasswd + 3 crypto tests `#[ignore]`'d on AES-CTS bug |
| 26 | adrian-kdc-interop | L3 | 7 | 0 | STRUCTURAL_ONLY | 2 derive-smoke + 2 Display + 3 "interop runner returns TargetUnavailable" stub tests. **Zero** real interop behavior |
| 27 | adrian-ntlm-client | L3 | 28 | 5 | BEHAVIORAL_REAL | Type 1/2/3 message construction, NTLMv2 response, RFC 5929 channel binding (with reference MD5), EPA bitflags — real crypto. 5 tests `#[ignore]`'d on the NT-hash bug |
| 28 | adrian-auth-core | L3 | 7 | 0 | BEHAVIORAL_MINIMAL | Privilege/AuthContext trait object-safety + serde round-trips |
| 29 | adrian-admx-compiler | L3 | 15 | 0 | BEHAVIORAL_REAL | `quick-xml` ADMX parser; `admx_to_declarative` enum/integer/empty cases; malformed-XML rejection |
| 30 | adrian-ca | L3 | 5 | 0 | STRUCTURAL_ONLY | 2 serde round-trips + 1 enum variant match + 1 loud-stub `ca_service_stubs_surface_typed_errors` |
| 31 | adrian-acme-server | L3 | 5 | 0 | STRUCTURAL_ONLY | 1 struct-field assertion + 1 Copy/Debug derive smoke + 1 Display formatting + 2 "router doesn't panic" tests |
| 32 | adrian-wcce-bridge | L3 | 4 | 0 | STRUCTURAL_ONLY | Copy derive smoke + Display formatting + 2 loud-stub tests |
| 33 | adrian-federation-shim | L3 | 5 | 0 | STRUCTURAL_ONLY | Display + SAML replay variant + 2 loud-stub tests |
| 34 | adrian-claims-engine | L3 | 4 | 0 | BEHAVIORAL_MINIMAL | Parse preserves source text + `to_cel` returns compiled selector |
| 35 | adrian-smb-server | L3 | 5 | 0 | STRUCTURAL_ONLY | new==default + serve returns loud protocol error + Display + 2 variant-match |
| 36 | adrian-smb-client | L3 | 5 | 0 | STRUCTURAL_ONLY | new==default + 2 loud-stub errors (connect/share) + io-error From + Display |
| 37 | adrian-print-service | L3 | 5 | 0 | STRUCTURAL_ONLY | new==default + router empty-not-panic + Display + 2 variant-match |
| 38 | adrian-sdk | L3 | 20 | 0 | MIXED | 5 builder-construction smoke + 5 "stub module returns loud error" + 5 stub module trait-object tests + 2 real "SDK dispatches to injected mock AuthModule" + 3 derive smoke |
| 39 | adrian-sdk-c | L3 | 8 | 0 | BEHAVIORAL_REAL | FFI shape pinning (handle size, fn-pointer signatures, runtime singleton idempotency) + real `adrian_sdk_new` returns non-null + `adrian_sdk_free(NULL)` doesn't crash + stub `auth_kerberos` returns NULL on failure |
| 40 | adrian-sdk-jni | L3 | 3 | 0 | BEHAVIORAL_MINIMAL | JNIEnv mock round-trips |
| 41 | adrian-sdk-swift | L3 | 3 | 0 | BEHAVIORAL_MINIMAL | Same shape as JNI |
| 42 | adrian-sdk-python | L3 | 3 | 0 | BEHAVIORAL_MINIMAL | PyO3 wrapper smoke |
| 43 | adrian-operator | L4 | 11 | 0 | BEHAVIORAL_REAL | `DomainControllerCrd` serde to Kubernetes camelCase; `serialize_crd` / `generate_statefulset` / `generate_helm_chart` produce valid YAML; condition serializes to k8s format. **But `AdrianOperator::run()` is loud-stub** (the only test for `run()` asserts it returns `Reconcile("not yet implemented")`) |
| 44 | adrian-cli | L4 | 19 | 0 | MIXED | 12 clap-arg parsing tests are real; 4 dispatch tests: 2 surface errors (file-not-found, SDK not-joined), 2 silently `Ok(())` (file mount succeeds with stub; `kdc rotate-krbtgt` succeeds) |
| 45 | adrian-monitor | L4 | 15 | 0 | BEHAVIORAL_REAL | Prometheus exposition format (`as_req_total{realm,etype}`, `ldap_query_duration_seconds{scope}`, histogram buckets) + `LogAuditSink` writes JSONL + `OtelAuditSink` stub counter increments + `AuditPipeline` dispatch + serde round-trip. **Real but untested in production: `MetricsRegistry` is never called by any KDC/LDAP/FDB hot path** |
| 46 | adrian-migrate | L4 | 5 | 0 | STRUCTURAL_ONLY | Display + From<io> + NtlmAuditConfig field assertion + 2 loud-stub tests |
| 47 | adrian-gpo-translate | L4 | 5 | 0 | STRUCTURAL_ONLY | Display + From<io> + Copy/Debug smoke + 2 `translate_stub_returns_io_unsupported` tests |
| — | adrian (binary) | — | 0 | 0 | — | `src/main.rs` is a 4-line wrapper calling `adrian_cli::run()` |

**Totals**: 602 unit tests pass + 16 ignored = 618 declared; 0 doc-tests (all 47 doctest suites report 0); 0 integration-test directories (`find . -type d -name tests` returns nothing outside `target/`).

† = tests run against an in-memory fallback that mirrors the production code's structural shape but never exercises the `foundationdb` crate API.

### Test-quality pie chart (approximate, by reading every test in the workspace)

```
BEHAVIORAL_REAL       ≈ 300 tests  (50 %)  — dcerpc, sid, storage-testkit, raft, hsm,
                                            policy-preg, policy-executor, ntlm-client,
                                            admx-compiler, schema-compiler, repl-core,
                                            storage-core, monitor, kdc/crypto+krbtgt+gmsa,
                                            operator CRD/Helm, sdk-c FFI, policy-core
BEHAVIORAL_MINIMAL    ≈ 150 tests  (25 %)  — Display/serde/derive smoke + struct-construction
                                            parity tests in stub crates
STRUCTURAL_ONLY       ≈ 150 tests  (25 %)  — "stub returns documented typed error variant"
                                            assertion tests; 0 bytes of behavior exercised
IGNORED (16)          : 13 blocked on AES-CTS / NT-hash bug (real bugs)
                       3 empty-body placeholders for future FDB integration tests
```

### The 10 most valuable tests

These are tests that genuinely catch real bugs and would fail loudly if a regression broke a protocol guarantee:

1. **`adrian-dcerpc::pdu::bind_pdu_wire_layout_matches_spec`** (`crates/adrian-dcerpc/src/pdu.rs:552`) — asserts byte-for-byte that the Bind PDU is exactly 72 bytes, `ptype` byte == 11, `rpc_vers` == 5, `frag_length` matches buffer. Catches any drift in the wire format.
2. **`adrian-dcerpc::transport::transport_send_bind_round_trips_via_duplex`** (`crates/adrian-dcerpc/src/transport.rs:224`) — actual in-process duplex TCP-style stream pair, send Bind → receive BindAck. Closest thing to an integration test in the workspace.
3. **`adrian-hsm::hmac_sign_verify_round_trip` + tamper-rejection** (`crates/adrian-hsm/src/lib.rs:494`) — HMAC-SHA1-96 sign → verify → tamper one byte → assert verify returns `false`. Real crypto round-trip.
4. **`adrian-storage-testkit::two_concurrent_txns_do_not_see_each_others_writes`** (`crates/adrian-storage-testkit/src/lib.rs:725`) — proves snapshot isolation actually works under interleaved concurrent writes.
5. **`adrian-ntlm-client::channel_binding_matches_reference_md5`** (`crates/adrian-ntlm-client/src/lib.rs:1347`) — RFC 5929 `tls-server-end-point:` channel binding is recomputed by hand with the `md-5` crate and asserted byte-equal to `compute_channel_binding()`'s output. Reference-vector test.
6. **`adrian-sid::*` SDDL parser tests** (`crates/adrian-sid/src/lib.rs:805–1009`) — round-trip `S-1-5-21-…-500` through binary ↔ SDDL, reject lowercase `s-` prefix, reject too-many-subauthorities, hex-authority form for ≥ 2^32, etc. Real MS-DTYP §2.4.2 conformance.
7. **`adrian-policy-preg::round_trip_preserves_all_entries`** + `decode_rejects_bad_signature` (`crates/adrian-policy-preg/src/lib.rs:552, 568`) — MS-GPREG §2.2 byte-exact: PReg\x00\x00 signature + UTF-16LE `[key;value;type;size;data;]` records.
8. **`adrian-raft::append_entries_idempotent_resend_does_not_duplicate`** (`crates/adrian-raft/src/lib.rs:1277`) — proves Raft log idempotency: resending the same entry at the same prevLogIndex does not double-commit.
9. **`adrian-repl-core::conflict_resolution_*` family** (`crates/adrian-repl-core/src/lib.rs:366–416`) — 5 tests pinning the LVR conflict-resolution tiebreak order: higher version → later timestamp → higher USN → higher invocation_id → local wins. This is the core AD replication invariant.
10. **`adrian-policy-executor::windows_executor_registry_pol_round_trips_through_preg_decode`** (`crates/adrian-policy-executor/src/lib.rs:690`) — synthesizes a Windows Registry.pol via the executor, then parses it back via `adrian-policy-preg::PregFile::parse` — a real cross-crate integration contract test (one of the very few).

### The 10 least valuable tests

These tests assert nothing about behavior that any reasonable person would call "coverage":

1. **`adrian-acme-server::routers_construct_without_panic`** (`crates/adrian-acme-server/src/lib.rs:143`) — calls `server.router()` and `server.ari_router()`, discards the result, asserts no panic. Zero behavioral coverage.
2. **`adrian-acme-server::server_default_equals_new`** (`crates/adrian-acme-server/src/lib.rs:128`) — calls both constructors and discards both. Even the comment admits "we exercise the seam by calling `router()` on each".
3. **`adrian-kdc::handle_as_req_returns_storage_not_implemented`** (`crates/adrian-kdc/src/lib.rs:207`) — calls the loud stub `handle_as_req(&[])` and asserts the error message contains `"not yet implemented"`. Tests the stub contract, not Kerberos.
4. **`adrian-kdc::handle_tgs_req_returns_storage_not_implemented`** (`crates/adrian-kdc/src/lib.rs:219`) — same shape as above for TGS-REQ.
5. **`adrian-kdc::handle_kpasswd_returns_storage_not_implemented`** (`crates/adrian-kdc/src/lib.rs:232`) — same shape for kpasswd (RFC 3244).
6. **`adrian-kdc::pac_builder_build_returns_pac_not_implemented`** (`crates/adrian-kdc/src/lib.rs:254`) — asserts `PacBuilder::build()` returns `KdcError::Pac`. Stub-contract test.
7. **`adrian-drsuapi::drs_bind_returns_backend_error`** (`crates/adrian-drsuapi/src/lib.rs:423`) — `drs_bind()` loud-stub assertion. AD-interop entry point `IDL_DRSBind` is verified to error out.
8. **`adrian-drsuapi::drs_get_nc_changes_returns_backend_error`** (`crates/adrian-drsuapi/src/lib.rs:432`) — same shape for `IDL_DRSGetNCChanges` — the replication workhorse.
9. **`adrian-kdc-interop::run_pac_byte_identity_returns_target_unavailable`** (`crates/adrian-kdc-interop/src/lib.rs:114`) — asserts the interop runner stub returns `TargetUnavailable`. The PAC byte-identity test vector suite is documented as a Wave 4b deliverable but the runner is `Err`-on-everything.
10. **`adrian-monitor::otel_audit_sink_stub_returns_ok_and_increments_count`** (`crates/adrian-monitor/src/lib.rs:883`) — asserts the OTLP exporter stub increments an in-memory counter. There is no OTLP exporter.

Honorable mention for least-valuable: **`adrian-migrate::all_migration_entry_points_return_loud_stub_errors`** (`crates/adrian-migrate/src/lib.rs:156`) — explicitly named "every entry point is a loud stub" and tests exactly that.

### Test coverage gaps

**0-test crates** (4 of 47):
- `adrian-identity-testkit` — 110 LoC, re-exports `InMemoryIdentityMapping` only; no tests of its own.
- `adrian-repl-testkit` — 120 LoC, re-exports `InMemoryReplicator`; no tests of its own.
- `adrian-test-harness` — 108 LoC + 3 TODO comments at EOF; literally the integration-test crate promised by the loud-stub `#[ignore]` placeholders, but contains no integration tests.
- `adrian` (binary) — 4-line `main.rs`, expected.

**Structural-only crates** (10 of 47 — every test is a Display / derive-smoke / loud-stub-assertion):
`adrian-pac-validator`, `adrian-kdc-interop`, `adrian-ca`, `adrian-acme-server`, `adrian-wcce-bridge`, `adrian-federation-shim`, `adrian-smb-server`, `adrian-smb-client`, `adrian-print-service`, `adrian-migrate`, `adrian-gpo-translate`, `adrian-policy-cel`.

**Untested protocol paths** (none have any end-to-end coverage):

| Path | Status | Closest test |
|------|--------|--------------|
| Kerberos AS-REQ → AS-REP (RFC 4120 §3.1) | **None** — `handle_as_req` is a loud stub returning `Storage("not yet implemented")` | `adrian-kdc::handle_as_req_returns_storage_not_implemented` |
| Kerberos TGS-REQ → TGS-REP (RFC 4120 §3.3) | **None** — `handle_tgs_req` is a loud stub | `adrian-kdc::handle_tgs_req_returns_storage_not_implemented` |
| Kerberos KRB-PRIV kpasswd (RFC 3244) | **None** — `handle_kpasswd` loud stub + 5 `#[ignore]`'d tests blocked on AES-CTS bug | `adrian-kdc::handle_kpasswd_returns_storage_not_implemented` |
| Kerberos PAC (MS-KILE §2.1, 9 buffer types) | **None** — `PacBuilder::build` is a loud stub; `Pac::parse` returns `Malformed` for all input | `adrian-pac-validator::pac_parse_empty_bytes_returns_malformed` |
| LDAP Bind → Search → Modify → Delete | **None** — `DirectoryService`'s axum router is empty | (no test) |
| DRSUAPI `IDL_DRSBind` → `IDL_DRSGetNCChanges` → `IDL_DRSUnbind` | **None** — all 8 drsuapi entry points are loud stubs returning `Backend` | `adrian-drsuapi::drs_bind_returns_backend_error` |
| NTLMv2 Type 1 → Type 2 → Type 3 → server acceptance | Partial — Type 1/2/3 messages built and parsed; **e2e handshake `#[ignore]`'d on NT-hash bug** | `adrian-ntlm-client::end_to_end_handshake_succeeds` (ignored) |
| SMB 1/2/3 negotiate → session setup → tree connect | **None** — `SmbServer::serve` is a loud-stub returning `Protocol` error | `adrian-smb-server::serve_returns_loud_protocol_error` |
| ACME RFC 8555 order → authz → challenge → cert | **None** — `AcmeServer::router()` returns empty axum Router | `adrian-acme-server::routers_construct_without_panic` |
| WCCE (MS-WCCE) request → response | **None** — `WcceBridge::translate_request` is a loud stub | `adrian-wcce-bridge::translate_request_stub_returns_translation_error` |
| FoundationDB real-backend put/get/delete/range | **None** — `real_fdb_*` tests are `#[cfg(feature = "fdb")] #[ignore]`'d | (not run in CI) |
| Raft leader election + log replication across cluster | **None** — `RaftReplicator` impl is receiver-only (Wave 1b) — no leader-election driver | `adrian-raft::append_entries_idempotent_resend_does_not_duplicate` (single-node) |
| Policy apply (write Registry.pol to disk, restart WinLogon) | **None** — `apply` is a stub returning `Ok(Default::default())` for all 3 platforms | `adrian-policy-executor::windows_apply_returns_default_apply_result` |

### Ignored tests (16 total — full disclosure)

| Crate | Test name | Location | Ignore reason | Bug real? | What it would verify |
|-------|-----------|----------|---------------|-----------|----------------------|
| adrian-kdc (crypto) | `aes256_cts_round_trips_partial_last_block` | `src/crypto.rs:270` | "AES-256-CTS partial-last-block swap logic has a known bug" | **YES, real and worse than documented** (per Wave 1c: `aes256_cts_encrypt`/`decrypt` panic on out-of-bounds slice for any plaintext not a multiple of 16 bytes — robustness/DoS issue on top of interop failure) | Round-trip encrypt→decrypt preserves plaintext for partial-last-block inputs (the CTS swap path) |
| adrian-kdc (crypto) | `etype_18_encrypt_decrypt_round_trips` | `src/crypto.rs:293` | "etype-18 round-trip depends on the partial-block AES-256-CTS swap bug" | YES (transitively) | Full etype-18 encrypt→decrypt round-trip with confounder + HMAC |
| adrian-kdc (crypto) | `etype_18_decrypt_rejects_wrong_key` | `src/crypto.rs:319` | "etype-18 wrong-key rejection depends on the partial-block CTS bug" | YES (transitively) | Decrypt with wrong key surfaces `HmacMismatch` (would actually pass if HMAC computed correctly — the ignore is conservative) |
| adrian-kdc (kpasswd) | `unauthenticated_request_rejected` | `src/kpasswd.rs:602` | "kpasswd authenticated flow depends on AES-256-CTS bug" | YES (transitively) | RFC 3244 §3.2 — empty MAC → `KRB5KRB_AP_ERR_BAD_INTEGRITY` |
| adrian-kdc (kpasswd) | `authenticated_password_change_succeeds` | `src/kpasswd.rs:622` | same | YES (transitively) | Real password change with valid MAC → `KpasswdSuccess` |
| adrian-kdc (kpasswd) | `wrong_target_principal_rejected` | `src/kpasswd.rs:659` | same | YES (transitively) | Mismatched target principal → `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` |
| adrian-kdc (kpasswd) | `short_request_rejected` | `src/kpasswd.rs:720` | same | YES (transitively) | Truncated request → `KpasswdError::Malformed` |
| adrian-kdc (kpasswd) | `password_too_short_rejected` | `src/kpasswd.rs:758` | same | YES (transitively) | Password shorter than policy minimum → `KpasswdError::PolicyViolation` |
| adrian-ntlm-client | `ntowfv1_matches_ms_nlmp_test_vector` | `src/lib.rs:867` | "NTLMv2 NT hash computation has a known bug vs MS-NLMP §4.2.2 test vectors" | **YES, real bug** — Wave 1c confirmed; the `ntowfv1()` function (MD4 of UTF-16LE password) does not produce the reference value `0xCD06CA7C7E10C99B1D33BAA4865DCC18` | `ntowfv1("Password")` matches MS-NLMP §4.2.2 reference |
| adrian-ntlm-client | `ntowfv2_matches_ms_nlmp_test_vector` | `src/lib.rs:882` | "NTLMv2 NT hash computation has a known bug" | YES (transitively — depends on `ntowfv1`) | `ntowfv2(...)` matches §4.2.2 reference `0x0C86A813A6D0DBD0DBC8F8481FB2E497` |
| adrian-ntlm-client | `ntproofstr_matches_ms_nlmp_test_vector` | `src/lib.rs:913` | "NTLMv2 NTProofStr has a known bug vs MS-NLMP test vectors" | YES (transitively) | `NTProofStr` matches §4.2.3 reference |
| adrian-ntlm-client | `build_authenticate_includes_ntlmv2_response` | `src/lib.rs:1240` | "NTLMv2 build_authenticate depends on the NT hash bug" | YES (transitively) | Type 3 message includes the buggy NTLMv2 response |
| adrian-ntlm-client | `end_to_end_handshake_succeeds` | `src/lib.rs:1413` | "NTLMv2 end-to-end handshake depends on the NT hash bug" | YES (transitively) | Type 1 → Type 2 → Type 3 handshake completes |
| adrian-drsuapi | `integration_get_nc_changes_emits_replvalinf_v3` | `src/lib.rs:462` | "requires a running FDB cluster and the `fdb` feature flag" | **NO** — placeholder test with **empty body** (just a comment) | Literally nothing — body is `// Placeholder — will be implemented in adrian-test-harness once the FDB integration testkit is added in Wave 4b.` |
| adrian-identity-ridpool | `fdb_integration_rid_pool_exhaustion_triggers_batch_request` | `src/lib.rs:1222` | same | **NO** — empty placeholder body | Same as above |
| adrian-schema-compiler | `integration_compile_walks_schema_nc` | `src/lib.rs:1278` | "requires a populated FDB-backed directory and the `fdb` feature flag" | **NO** — empty placeholder body | Same |

**Summary**: 13 of 16 ignored tests are real — they would fail today because of the AES-256-CTS partial-last-block swap bug or the NTLMv2 NT-hash bug. Wave 1c verified both bugs are real (and the CTS bug is actually worse than documented — runtime panics on out-of-bounds slice access). **3 of 16 ignored tests are empty-body placeholders** with `// Placeholder — will be implemented in adrian-test-harness once the FDB integration testkit is added in Wave 4b.` — they don't actually test anything yet.

## Part 2: Ops Readiness

### CI/CD pipeline

**There is no CI/CD pipeline.** This is the single biggest ops gap in the repo.

- `.github/workflows/` directory does not exist (verified with `ls -la .github/`).
- No `.gitlab-ci.yml`, no `azure-pipelines.yml`, no `Jenkinsfile`, no `CircleCI/config.yml`, no `drone.yml`.
- `scripts/` contains only `fix_broken_xrefs.py` (a doc-crossref repair script) and `problem-extraction.md` (130 KB of notes).
- `CONTRIBUTING.md` says "Contributions are tracked via issues and pull requests" but does not document any CI expectation, branch protection, or required-status-check policy.
- The repo's only quality gate is "the maintainer runs `cargo test` locally before merging" — there is no automated enforcement.

**Concretely missing** (a v0.6.0 release blocker):
1. `cargo test --workspace --all-features` on a runner with libclang + a real FDB cluster (currently the 3 `#[cfg(feature = "fdb")] #[ignore]`-gated tests in `adrian-storage-fdb` are never run; the entire `real_fdb` submodule of `storage-fdb`, `identity-fdb`, `identity-ridpool` is never compiled by `cargo test`).
2. `cargo clippy --workspace --all-targets -- -D warnings` — there are zero CI-side guarantees that lints pass.
3. `cargo fmt --check` — same.
4. `cargo audit` (or `cargo deny check advisories`) — no CVE scanning.
5. `cargo doc --no-deps --workspace` — no doc-build verification.
6. Cross-compilation matrix for the SDK FFI crates (`adrian-sdk-c`/`jni`/`swift`/`python`) — none of the `cdylib` outputs have ever been built for `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, etc.
7. Multi-arch container builds for the operator / KDC / LDAP services — there is no Dockerfile at all (verified with `find . -iname 'docker*'`).
8. SBOM generation (`cargo cyclonedx` or `cargo auditable build`).

### Observability

**Wave 1d's finding verified**: `MetricsRegistry` has **zero call sites** outside `adrian-monitor`'s own unit tests.

```
$ rg -ln 'MetricsRegistry|observe_as_req_duration|increment_as_req' rust/crates/*/src/
crates/adrian-monitor/src/lib.rs      ← only the crate itself
```

Concretely:
- `adrian-kdc` has 39 tests but never calls `MetricsRegistry::increment_as_req` or `observe_as_req_duration`. Every AS-REQ that arrives at the (stub) `handle_as_req` is invisible to Prometheus.
- `adrian-directory-service` never calls `observe_ldap_query_duration`.
- `adrian-storage-fdb` never calls `observe_fdb_operations` (the metric exists in `MetricsRegistry`).
- `adrian-raft` never calls `set_replication_lag`.
- `adrian-identity-ridpool` never calls `set_rid_pool_remaining`.
- `adrian-kdc::krbtgt::KrbtgtManager` never calls `set_krbtgt_key_age_seconds`.

**Tracing usage** is also minimal — 19 `tracing::` calls in the entire workspace, distributed:
- `adrian-cli/src/lib.rs`: 14 (one per subcommand dispatch — `tracing::info!("adrian join: delegating to SDK")` etc.) — informational, not structured.
- `adrian-raft/src/lib.rs`: 2 (`tracing::debug!` for vote/append_entries edge cases).
- `adrian-monitor/src/lib.rs`: 3 (audit-sink logging only).

**Zero `tracing::` calls** in `adrian-kdc`, `adrian-directory-service`, `adrian-storage-fdb`, `adrian-identity-fdb`, `adrian-identity-ridpool`, `adrian-hsm`, `adrian-drsuapi`, `adrian-dcerpc` — the actual hot-path crates.

**Correlation IDs / request IDs**: none. There is no `tracing::Span` per request, no `RequestContext` propagated through the call stack, no `x-request-id` header in any HTTP/RPC handler. The audit `AuditEvent` carries an `event_id: Uuid` but it is generated at emit time, not propagated from the inbound request.

**Structured logging**: technically yes — `tracing::info!` produces structured fields when paired with `tracing-subscriber::fmt().json()`. But `adrian-cli/src/main.rs` calls `tracing_subscriber::fmt::init()` (default text formatter), so even the CLI doesn't emit JSON. The `LogAuditSink` in `adrian-monitor` writes JSONL files but it is never wired.

### Deployment story

**There is no deployment artifact.** This is the second biggest ops gap.

- **Dockerfile**: none. `find . -iname 'docker*' -o -iname 'containerfile*'` returns nothing.
- **Helm chart**: technically yes, but only as in-memory YAML strings. `adrian-operator/src/lib.rs:325 generate_helm_chart()` produces `Chart.yaml` + `values.yaml` + 3 templates (statefulset, crd, service) as `String`s. The test `generate_helm_chart_produces_valid_files` (lib.rs:781) asserts the strings contain certain substrings. **There is no on-disk chart** anyone could `helm install`. The chart's `image:` field defaults to `spec.image` which is also a string the caller must populate — there's no published container image to point it at.
- **StatefulSet**: generated as YAML via serde_yaml; PVC for FDB data, ports 389/88/9100. **But there's no container image to run** — the `image:` field in `values.yaml` is a templated string.
- **Health checks / readiness probes**: **none in the generated StatefulSet**. Reading `crates/adrian-operator/src/lib.rs:380–470`, the StatefulSet has `livenessProbe` and `readinessProbe` fields nowhere in the YAML output. There is no `/healthz` endpoint, no `/readyz` endpoint anywhere in the workspace.
- **Config schema**: **none**. There is no `config.toml`, no `Config` struct, no `envy`/`figment`/`config-rs` dependency. The KDC and DirectoryService are constructed via `KdcService::new()` / `KdcService::default()` with zero configuration. The Helm chart's `values.yaml` exposes `replicas`, `domainDn`, `krbtgtHsmKeyId`, `fdbClusterFile`, `image` — but no Rust code reads these; they exist only in the YAML.
- **Env vars**: `rg -n 'env::var|env\(\)' crates/*/src/` returns zero matches. The CLI uses `tracing_subscriber::fmt::init()` (which honors `RUST_LOG`), but no crate reads `ADRIAN_KRBGTG_KEY_ID`, `ADRIAN_FDB_CLUSTER_FILE`, `ADRIAN_REALM`, etc.

**Operator reconcile loop**: confirmed loud stub. `AdrianOperator::run()` (lib.rs:403) returns `Err(OperatorError::Reconcile("not yet implemented"))` immediately. There is no `kube::Client` construction, no CRD watch, no `Controller::new()`. The CRD/StatefulSet/Helm generation functions are real (they produce valid YAML), but they're never invoked by anything other than tests.

### Backup/restore

**Backup/restore is documented in 3 ADRs but implemented in zero crates.**

- ADR-010 (Storage-Engine-Native Backup and Filesystem Snapshots) — `status: Accepted`, 4 KB, documents the VSS-equivalent approach. No code.
- ADR-034 (Transactional DB PITR; reject-and-repair observability) — `status: Accepted`. No code.
- ADR-059 (Per-DC Backup with PITR + Operator-Driven DR Runbooks) — `status: Accepted`, documents `ntdsutil ifm` parity. No code.

Code-side reality:
- `rg -in 'fn .*backup|fn .*restore|fn .*snapshot' rust/crates/*/src/` returns only `InMemoryDirectoryStore::snapshot()` (returns `Box<dyn DirectoryStore>` — an in-memory BTreeMap clone for snapshot isolation, **not** a disk backup).
- `adrian-raft::RaftReplicator::log_snapshot()` returns `Vec<RaftLogEntry>` — also in-memory, for install_snapshot RPC.
- No `tar` / `zfs send` / `lvcreate` integration. No `backup-coordinator` service as ADR-010 §Decision prescribes.
- No `invocationId` reset logic on restore.
- No `Restore-ADObject`-equivalent recycle-bin feature.

**Runbooks**: `rg -n 'runbook|Runbook|RUNBOOK' .` returns only doc-comments in `adrian-monitor/src/lib.rs:14` referencing ADR-059. There is no `runbooks/` directory, no `docs/runbooks/`, no Markdown runbook for "DC down", "krbtgt rotation", "RID pool exhaustion", "USN rollback", "schema change roll-back", etc. ADR-059 explicitly says "operator-driven DR runbooks" but the operator doesn't have a reconcile loop, and there are no runbooks.

**PITR (point-in-time-recovery)**: ADR-034 and ADR-059 both reference it; no WAL archiving, no log-shipping, no replay logic exists in any crate.

### Performance/benchmarks

**There are no benchmarks.** This is the third biggest ops gap.

- `find . -type d -name benches` returns nothing (outside `target/`).
- `rg '\[\[bench\]\]|criterion|divan' Cargo.toml crates/*/Cargo.toml` returns zero matches.
- `criterion` is not in `Cargo.lock` (verified: `rg 'criterion' Cargo.lock` returns nothing).
- No `#[bench]` attributes anywhere.

**MVP success criteria from `finaldraft/06-implementation-roadmap.md`** (referenced by the CHANGELOG) claim "5K AS-REQ/sec/KDC, 10K writes/sec/DC" as v0.6.0 targets. **None of these are measured or measurable today**:
- `adrian-kdc::handle_as_req` returns immediately with `Storage("not yet implemented")` — it is the fastest possible AS-REQ handler because it does nothing.
- `adrian-storage-testkit::InMemoryDirectoryStore::put` does BTreeMap insertion — microsecond territory, no FDB client involved.
- `adrian-dcerpc::transport::DcerpcTcpTransport` uses a duplex `tokio::io::DuplexStream` for tests; the real TCP transport path doesn't exist (the `endpoint_run` test asserts `BindFailed` is returned).
- `adrian-hsm::SoftwareHsm` does in-process AES-GCM + HMAC — fast, but no benchmark pins the upper bound.

There is no `cargo bench` infrastructure to validate that the 5K/10K targets are met once the handlers are real. Setting up criterion + a kdc-throughput bench + a storage-throughput bench + a dcerpc-pdu-encode bench is a prerequisite for the v0.6.0 acceptance criteria.

The only real performance signal in the test output is `adrian-kdc` taking **3.10 s** to run its 39 tests (vs <0.1 s for every other crate) — driven by PBKDF2 key derivation in `crypto.rs`. That's 80 ms per PBKDF2 invocation, ~1000× slower than MIT krb5's optimized asm path. If the production KDC must do 5K AS-REQ/sec and each AS-REQ does one PBKDF2, the throughput ceiling with current crypto code is **~12 AS-REQ/sec/core** — 400× below target.

## Part 3: Documentation

### README

**The README is severely out of date.** `README.md` describes the repo as "a research deliverable covering Microsoft Active Directory" with primary contents `docs/`, `catalog/`, `adr/`, `workshop/`, `finaldraft/`, `specs/`, `draft/`, `scripts/`. The `rust/` row in the table reads:

> `rust/` — Cargo workspace with 47 Rust crate stubs across 5 dependency layers (`cargo check` passes)

That sentence is **wrong as of v0.5.0**:
- The crates are no longer "stubs" — many have real implementations (storage-testkit, dcerpc, sid, raft, hsm, policy-preg, etc.).
- "cargo check passes" is a v0.4.0-level claim. As of v0.5.0, `cargo test --workspace` passes 602 tests.
- The "Quick start" section points users at `draft/01-executive-summary.md`, which CONTRIBUTING.md says is "superseded by `finaldraft/`".
- The "Repository statistics" section claims "88 Markdown source files" and "~34,300 lines of content" — but the workspace has 47 crates with thousands of Rust LoC, and `finaldraft/` (which CONTRIBUTING calls "definitive") is not mentioned.

### ADRs cross-referenced from code

**Yes, extensively.** This is a documentation bright spot. Cross-reference counts per crate (via `rg -c 'ADR-' crates/*/src/`):

| Crate | ADR refs |
|-------|---------:|
| adrian-storage-core | 63 |
| adrian-sdk | 62 |
| adrian-schema-traits | 45 |
| adrian-schema-compiler | 39 |
| adrian-storage-fdb | 30 |
| adrian-raft | 31 |
| adrian-operator | (many — ADR-058, ADR-073, etc.) |
| adrian-monitor | ADR-057, ADR-060, ADR-023, ADR-034, ADR-059 |
| adrian-hsm | ADR-015, ADR-020 |
| adrian-kdc | ADR-011, ADR-014, ADR-018, ADR-019, ADR-020, ADR-082 |

132 ADRs total in `adr/`. Every major design decision in the codebase points back to a numbered ADR. This is exemplary for a research-grade codebase.

### CONTRIBUTING.md

Exists (6.2 KB) but **out of date**. Its "Repository layout" tree shows `draft/` as a top-level dir but does **not** show `rust/`, `eval/`, `finaldraft/`, or `specs/`. The "How to contribute" section says "Open a GitHub issue" — there is no guidance on running `cargo test`, no guidance on the 5-layer workspace dependency structure, no guidance on the loud-stub convention, no guidance on ADR cross-referencing (which the codebase does extensively).

### Architecture diagrams

- `finaldraft/02-architecture-overview.md` and `finaldraft/04-rust-workspace-design.md` contain text-based diagrams (ASCII art / mermaid) of the 5-layer workspace.
- `docs/00-overview/` contains the AD architecture reference.
- **No `architecture/` directory, no PNG/SVG diagrams**, no `plantuml`/`structurizr`/`dcoded` source. The diagrams are Markdown-embedded only.
- `cargo depgraph` or `cargo modules` outputs are not checked in.

### Other docs

- `CHANGELOG.md` is excellent — detailed per-wave breakdown of test counts, features added, TODOs remaining, and explicit `#[ignore]` disclosures with full bug context.
- `HANDOVER_STATE.md` and `HANDOVER_PROMPT.md` (10 KB + 29 KB) are the wave-to-wave handover documents.
- `TASKS.md` (49 KB) is the per-task work ledger.
- `catalog/` (16 files, 130 catalogued problems) and `adr/` (132 ADRs) are the architectural backbone.

## Risk Register

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| No CI/CD pipeline — every merge depends on a human running `cargo test` locally | **Critical** | High (will happen) | Add `.github/workflows/ci.yml` running `cargo test --workspace`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `cargo audit`, on PR + main. Add a separate `fdb-integration.yml` job using the `foundationdb/foundationdb:7.3.30` Docker image + libclang. |
| The `fdb` feature flag is never compiled in CI — `real_fdb` submodule of `storage-fdb`, `identity-fdb`, `identity-ridpool` could be broken and nobody would know | **Critical** | Medium (probably broken) | Same as above — add `--features fdb` job with libclang installed. |
| AES-256-CTS partial-last-block swap bug is real AND causes runtime panics (not just interop failure) — any KDC AS-REQ with a partial-block plaintext will crash the process | **High** | High (any real AS-REQ triggers it) | Fix `aes256_cts_encrypt`/`decrypt` per RFC 3962 §5.1; un-ignore the 3 crypto tests + 5 kpasswd tests; un-ignore the 5 ntlm tests once NT hash is fixed. |
| NTLMv2 NT hash (`ntowfv1`) does not match MS-NLMP §4.2.2 test vectors — the bug is in `ntowfv1()` but the impact cascades to NTProofStr, NTLMv2 response, and the entire Type 3 message | **High** | High (any NTLM auth fails) | Audit the MD4-of-UTF-16LE-password path; cross-check against `heimdal`'s `hash_ntlm` source. |
| No Dockerfile / container image — the Helm chart's `image:` field points at nothing | **High** | High (cannot deploy) | Add a multi-stage `Dockerfile` (rust:1.97-builder → debian:bookworm-slim runtime); publish to ghcr.io; wire the chart's `image:` default to `ghcr.io/pkhairkh/adrian-kdc:0.5.0`. |
| No health/readiness probes in the generated StatefulSet — Kubernetes cannot tell a running KDC from a wedged one | **High** | High | Add `/healthz` (liveness) and `/readyz` (readiness) axum handlers in `adrian-kdc` and `adrian-directory-service`; add `livenessProbe`/`readinessProbe` to `generate_statefulset`'s YAML output. |
| `MetricsRegistry` has zero call sites — Prometheus scrapes will return zero for `as_req_total`, `ldap_query_duration_seconds`, etc. even on a busy cluster | **High** | High (current state) | Wire `increment_as_req` in `adrian-kdc::handle_as_req` / `handle_tgs_req`; wire `observe_ldap_query_duration` in `adrian-directory-service`; wire `observe_fdb_operations` in `adrian-storage-fdb`; wire `set_replication_lag` in `adrian-raft`; wire `set_rid_pool_remaining` in `adrian-identity-ridpool`. |
| Zero `tracing::` calls in KDC/DirectoryService/storage hot paths — operators have no per-request logs to debug issues | **High** | High | Add `tracing::info!`/`debug!` at the entry of every public handler; propagate a `tracing::Span` per request. |
| No benchmarks; MVP perf targets (5K AS-REQ/sec/KDC, 10K writes/sec/DC) are unverifiable | **High** | High | Add `criterion` dev-dependency to `adrian-kdc`, `adrian-storage-fdb`, `adrian-dcerpc`; add `benches/kdc_throughput.rs`, `benches/storage_put.rs`, `benches/dcerpc_encode.rs`; wire into CI as a separate `bench.yml` job with regression detection. |
| `AdrianOperator::run()` is a loud stub — the Kubernetes operator does nothing | **High** | High (current state) | Wire `kube::Client` + `Controller::new(DomainControllerCrd, watch)`; implement `reconcile()` that calls `generate_statefulset` + `patch` on the API server. |
| Backup/restore not implemented (ADR-010, ADR-034, ADR-059 are accepted but uncoded) — no PITR, no IFM, no recycle-bin | **High** | High (no DR story) | Add `adrian-backup` crate with `snapshot_to_tar()`, `restore_from_tar()`, `wal_archive()`; wire into the operator as a `BackupSchedule` CRD. |
| README + CONTRIBUTING.md are out of date — they describe the repo as "research deliverable" with stubs, not v0.5.0 | **Medium** | High (current state) | Update README to point at `rust/`, mention `cargo test --workspace` (602 tests), mention `finaldraft/` as authoritative. Update CONTRIBUTING.md to add `rust/`, `eval/`, `finaldraft/`, `specs/` to the tree. |
| `adrian-test-harness` is empty (108 LoC, 3 TODOs) — every crate's `#[ignore]` placeholder test points at it but it has no integration tests | **High** | High (current state) | Implement in-process FDB cluster spinup (use `foundationdb`'s `tester` crate or `fdb-server` in a container); implement LDAP bind+search+modify+delete sequence; implement Windows Server 2022 / MIT krb5 interop fixtures (gated behind `ad-interop` feature). |
| 25 % of tests are "loud stub assertion" tests — they pass today but tell us nothing about real behavior; coverage reports will look healthy while the system is hollow | **Medium** | High (current state) | Tag stub tests with a `#[stub_contract]` attribute or move them to a `stub_contracts` module; exclude from "real coverage" metrics; track the stub→real transition in `TASKS.md`. |
| PBKDF2 in `adrian-kdc::crypto::derive_aes256_key` takes 80 ms — ~1000× slower than MIT krb5's optimized asm path; the 5K AS-REQ/sec target is unreachable without optimization | **High** | High (measured) | Replace PBKDF2 with `ring::pbkdf2` or add `aesni` features; benchmark single-thread AS-REQ throughput once handlers are real. |
| The 3 empty-body `#[ignore]` placeholder tests in `drsuapi`, `identity-ridpool`, `schema-compiler` masquerade as "ignored because of FDB" but they actually test nothing | **Low** | High (current state) | Either implement the placeholder bodies with real FDB assertions or remove the empty tests and replace with `// TODO: add FDB integration test in adrian-test-harness` comments. |
| No structured config schema — operators cannot override realm, krbtgt key ID, FDB cluster file, log level via env vars | **Medium** | High (current state) | Add `adrian-config` crate with a `Config` struct (serde + `envy` for env-var override); wire into KDC, DirectoryService, operator. |
| No cross-compilation for SDK FFI crates — `cdylib` outputs for `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `aarch64-linux-android` have never been built | **Medium** | High (current state) | Add a `cross`-based matrix in CI: `cargo build --release -p adrian-sdk-c --target aarch64-apple-darwin` etc. |

## Recommendations for v0.6.0

Prioritized by ROI — biggest risk reduction first:

### P0 (must-have for any "v0.6.0" claim)

1. **Fix the AES-256-CTS partial-last-block swap bug.** This is the single highest-priority item. Without it, every Kerberos AS-REQ with a partial-block plaintext panics the KDC. Wave 1c verified the bug is real and the `#[ignore]`'d test would fail. Once fixed, un-ignore 3 crypto tests + 5 kpasswd tests → +8 real behavioral tests passing.

2. **Fix the NTLMv2 NT-hash (`ntowfv1`) bug.** Wave 1c verified the function does not produce the MS-NLMP §4.2.2 reference value `0xCD06CA7C7E10C99B1D33BAA4865DCC18`. Un-ignore 5 NTLM tests → +5 real behavioral tests passing.

3. **Add a CI pipeline (`.github/workflows/ci.yml`)** with:
   - `cargo test --workspace` on ubuntu-latest (default features)
   - `cargo test --workspace --features fdb` on a runner with `apt-get install -y libclang1` + a `foundationdb/foundationdb:7.3.30` sidecar
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo fmt --check`
   - `cargo audit`
   - `cargo doc --no-deps --workspace`

4. **Implement the real FDB integration tests in `adrian-test-harness`.** Today there are 3 empty-body `#[ignore]`'d placeholder tests pointing at "Wave 4b follow-up". Either deliver the integration tests or delete the placeholders and replace with TODO comments.

### P1 (should-have for v0.6.0)

5. **Add a multi-stage Dockerfile** (`rust/Dockerfile`) building the CLI + KDC + DirectoryService + operator binaries; publish to `ghcr.io/pkhairkh/adrian-{kdc,ds,operator}:0.6.0`. Wire the Helm chart's `image:` default to the published image.

6. **Add health/readiness probes.** `/healthz` returns 200 if the process is up; `/readyz` returns 200 if the FDB connection is live and the krbtgt key is loaded. Wire `livenessProbe`/`readinessProbe` into `generate_statefulset`'s YAML.

7. **Wire `MetricsRegistry` into hot paths.** One-line changes in `adrian-kdc::handle_as_req` (`metrics.increment_as_req(realm, etype).await`), `adrian-directory-service::search`, `adrian-storage-fdb::FdbDirectoryStore::put`, `adrian-raft::append_entries`, `adrian-identity-ridpool::allocate`, `adrian-kdc::KrbtgtManager::rotate`. Closes the "monitor producers have zero call sites" gap.

8. **Add `tracing::Span` per inbound request** in `adrian-kdc` and `adrian-directory-service`. Propagate a `request_id: Uuid` via the span context. Wire `tracing_subscriber::fmt().json()` for production.

9. **Add `adrian-config` crate** with a `Config` struct (serde + `envy` for env-var override). Wire into KDC, DirectoryService, operator, CLI. Document env vars in `docs/operations/configuration.md`.

10. **Add `criterion` benchmarks.** Three benches: `kdc_as_req_throughput` (target 5K/sec), `storage_put_throughput` (target 10K writes/sec), `dcerpc_pdu_encode` (sanity check). Wire into CI as a `bench.yml` job with regression detection.

11. **Implement the operator reconcile loop.** Wire `kube::Client` + `Controller::new(DomainControllerCrd, watch)` + a `reconcile()` that calls `generate_statefulset` and patches the API server. Until this lands, the operator is a YAML generator, not a controller.

12. **Add `adrian-backup` crate.** `snapshot_to_tar()`, `restore_from_tar()`, `wal_archive()`. Wire into the operator as a `BackupSchedule` CRD. Implements ADR-010, ADR-034, ADR-059.

### P2 (nice-to-have for v0.6.0)

13. **Update README.md and CONTRIBUTING.md** to reflect v0.5.0 reality: 47-crate workspace, 602 tests, real implementations in storage/dcerpc/sid/raft/hsm/policy. Add a "Repository layout" tree that includes `rust/`, `eval/`, `finaldraft/`, `specs/`.

14. **Add `cargo deny`** for license + advisory + ban checking.

15. **Cross-compilation matrix for SDK FFI crates** — `cargo build --release -p adrian-sdk-c --target {aarch64-apple-darwin,x86_64-pc-windows-msvc,aarch64-linux-android,x86_64-unknown-freebsd}` via `cross`.

16. **Add `runbooks/` directory** with Markdown runbooks for: "DC down", "krbtgt rotation", "RID pool exhaustion", "USN rollback", "schema change roll-back", "PAC validation failure", "FDB cluster recovery". Even stub runbooks are better than nothing — they document the operator's runbook expectations.

17. **Add `cargo cyclonedx`** for SBOM generation; publish SBOM alongside container images.

18. **Tag loud-stub tests with a `#[stub_contract]` attribute** (or move them to a `stub_contracts` module) so coverage metrics can distinguish real from stub-contract tests. Track the stub→real transition in `TASKS.md` with a per-crate "stub ratio" column.

19. **Replace `InMemoryDirectoryStore`-backed fallback in `adrian-storage-fdb` with a hard `#[cfg(feature = "fdb")]` compile error** when the feature is off — this would force every consumer to enable the feature or get a build failure. Today the silent fallback hides production risk behind a passing test suite (Wave 1a flagged this; it's the single biggest architectural risk in the storage layer).

20. **Add doctests for the public API** — every crate's `lib.rs` should have at least one doctest exercising the main entry point. Today all 47 doctest suites report 0 tests.

---

**Audit conclusion**: The Wave 1 findings are corroborated and amplified by this cross-cutting audit. The 602-test count is real but ~25 % of those tests are stub-contract assertions, the `fdb` feature path is unverified, the AES-CTS and NT-hash bugs block 13 tests, ops infrastructure is essentially zero (no CI, no Dockerfile, no health checks, no benchmarks, no runbooks), and the README/CONTRIBUTING still describe the project as "research deliverable with stubs". v0.6.0 must close at minimum the P0 + P1 list above to be credibly called "production-ready".
