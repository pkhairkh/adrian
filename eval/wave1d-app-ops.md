# Wave 1d — Application & Ops Layer Audit

**Auditor**: Sub-agent E1-d
**Date**: 2026-08-13
**Scope**: 25 crates (sdk*, cli, monitor, operator, policy*, admx-compiler, gpo-translate, ca, acme, wcce, smb*, print, federation, claims, migrate, test-harness)
**Commit**: `dadc4ca` (v0.5.0)

## Executive Summary

The application + ops layer is, with very few exceptions, a **scaffold wave**: types, traits, error enums, and loud-stub implementations are in place, but **no crate in this layer actually calls into a real backend**. Of the 25 audited crates, only 5 are "real" (`adrian-policy-preg`, `adrian-policy-core`, `adrian-policy-executor`'s `synthesize`, `adrian-admx-compiler`'s parser, `adrian-monitor`'s `MetricsRegistry`); the remaining 20 are loud stubs (typed errors) or silent stubs (empty axum routers / Ok-with-zeros). The SDK's `KerberosAuthModule::authenticate_kerberos()` returns `"not yet wired to adrian-kdc (ADR-108)"`; the CLI's `join` surfaces that error, but `gpupdate`, `klist`, `kinit`, `auth`, `cert`, `file`, `migrate`, `gpo-translate`, `kdc rotate-krbtgt` all silently `Ok(())` after parsing args. The Kubernetes operator generates valid CRD/StatefulSet/Helm YAML, but `AdrianOperator::run()` returns `Reconcile("not yet implemented")` — no `kube::Client` is constructed. The Wave 4b/4c deferred crates (`adrian-ca`, `adrian-acme-server`, `adrian-wcce-bridge`, `adrian-smb-server`, `adrian-smb-client`, `adrian-smb-core`, `adrian-print-service`, `adrian-federation-shim`, `adrian-policy-cel`) remain stubs. **v0.5.0 is not production-ready**; the integration gap between the SDK trait surface and the backends it abstracts (KDC, DirectoryStore, PolicyExecutor, SMB client, ACME server) is the single largest delivery risk for v0.6.0.

## Per-Crate Findings

### adrian-sdk
- **Status**: STUB_LOUD (new `AdrianSdk` builder API) + STUB_SILENT (legacy `AdrianClient::join` returns `NotJoined`, which is technically a real error variant, but it's misleading: nothing actually attempts a join)
- **Test quality**: BEHAVIORAL_MINIMAL — 20 tests; cover builder success/failure paths, stub error variants, error Display strings. No test exercises any backend integration because none exists.
- **TODOs**: 2 (`AdrianClient::join`, `AdrianClient` field comment)
- **Production readiness**: 2/5 — the trait surface (`AuthModule`, `DirectoryModule`, `PolicyModule`, `FileModule`, `CertModule`) is well-designed and the `SdkBuilder` enforces all-five-modules invariant; but **all five default impls (`KerberosAuthModule`, `LdapDirectoryModule`, `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`) return `SdkError::{Auth,Directory,Policy,File,Cert}("not yet wired to <crate>")`**. The `Cargo.toml` declares `ldap3`, `rustls`, `adrian-smb-client`, `adrian-auth-core` as deps but the stubs never call into them — dead deps.
- **Integration status**: NONE. The `KerberosAuthModule::authenticate_kerberos` body is literally `Err(SdkError::Auth(format!("Kerberos auth for {principal} not yet wired to adrian-kdc (ADR-108)")))`. Same for the other four modules. The `AdrianClient::join` (legacy surface used by `adrian-sdk-c/jni/swift/python`) returns `Err(SdkError::NotJoined)`.
- **What's missing**: real impl delegating to `adrian-kdc`, `adrian-directory-service` (via `ldap3`), `adrian-policy-executor`, `adrian-smb-client`, `adrian-acme-server`; an actual `join()` that writes `/etc/adrian/`, `adrianlsa.dll`, `AdrianOpenDirectory.bundle`, or PSSO config per ADR-107/048; the `Arc<AuthContext>` field on `AdrianClient` (currently zero-sized).

### adrian-sdk-c
- **Status**: REAL_PARTIAL — the FFI surface (`adrian_client_new/free/join`, `adrian_sdk_new/free/auth_kerberos/...`) is properly `#[no_mangle] pub unsafe extern "C"`, the runtime is a `OnceLock<tokio::runtime::Runtime>` singleton; but the underlying SDK methods are loud stubs.
- **Test quality**: STRUCTURAL_ONLY — 8 tests; they take function pointers to verify symbols/signatures exist, but never invoke them (can't invoke without a real C test harness).
- **TODOs**: 1
- **Production readiness**: 3/5 — FFI plumbing is correct (lifetimes via `Box::into_raw`/`Box::from_raw`, `OnceLock` runtime singleton); would be 5/5 if the underlying SDK did real work.
- **Integration status**: Calls into `adrian-sdk` correctly; SDK is loud-stub, so the C ABI is also loud-stub at runtime.
- **What's missing**: real `cbindgen` header generation in CI; a C test binary to verify the ABI; integration tests that drive `adrian_client_join` against a real `adrian-kdc` instance.

### adrian-sdk-jni
- **Status**: REAL_PARTIAL — three `#[no_mangle] extern "system"` JNI symbols (`newClient`, `join`, `free`); the tokio runtime is a `OnceLock`.
- **Test quality**: STRUCTURAL_ONLY — 3 tests, all pin function-pointer signatures without invoking them.
- **TODOs**: 0
- **Production readiness**: 3/5
- **Integration status**: Wraps `AdrianClient::join` which returns `NotJoined`. The JNI `join` returns `jboolean` 1 on `Ok(())`, 0 on `Err`. Today every call returns 0.
- **What's missing**: no `dev.adrian.sdk.AdrianSdk` (new builder API) — only the legacy `AdrianClient`; no Java-side test (`org.junit` invocation from Maven/Gradle).

### adrian-sdk-swift
- **Status**: REAL_PARTIAL — three C-ABI symbols (`adrian_swift_client_new`, `_release`, `_join`). Hand-rolled C ABI; `swift-bridge` integration is explicitly deferred per the crate doc.
- **Test quality**: STRUCTURAL_ONLY — 3 tests (pointer-size + signature pin + runtime singleton).
- **TODOs**: 0
- **Production readiness**: 3/5
- **Integration status**: Wraps `AdrianClient::join`; today `_join` always returns `-2`.
- **What's missing**: `swift-bridge` integration; an `AdrianSDK.xcframework` target; Swift-side `AdrianSDK` class that wraps the C ABI; the new `AdrianSdk` builder API in Swift.

### adrian-sdk-python
- **Status**: REAL_PARTIAL — `#[pyclass] AdrianPyClient` with `#[new]` + `join` + `from_config`; `#[pymodule] fn adrian` entry point.
- **Test quality**: STRUCTURAL_ONLY — 3 tests (Rust-side constructor + behavior contract that `join` returns `False` until SDK is wired).
- **TODOs**: 1 (`from_config` is a stub returning `Ok(Self::new())`)
- **Production readiness**: 3/5
- **Integration status**: `join` returns `bool` from `result.is_ok()`. Underlying SDK is loud-stub → today `join` always returns `False`.
- **What's missing**: real `from_config` YAML parsing; exposure of the 5 module traits to Python; `maturin` build in CI; a Python-side pytest suite.

### adrian-cli
- **Status**: STUB_LOUD for `join` and `policy apply` (surfaces SDK errors); STUB_SILENT for everything else (`gpupdate`, `klist`, `kinit`, `auth`, `cert enroll`, `file mount`, `migrate *`, `gpo-translate`, `kdc rotate-krbtgt` all log a `tracing::info!` then return `Ok(())` without calling anything). `leave` is a literal no-op.
- **Test quality**: BEHAVIORAL_MINIMAL — 19 tests; clap parsing is well-covered (rejects missing args, validates subcommand enum), and `dispatch_*` tests verify `join` surfaces "not joined" and `policy apply` surfaces missing-file errors. But the 8 silent-Ok subcommands have no behavioral tests because there's no behavior to test.
- **TODOs**: 0
- **Production readiness**: 2/5 — `clap` ergonomics are good; but the CLI cannot actually join, authenticate, apply policy, enroll certs, mount shares, or migrate anything. `adrian join --domain adrian.dev --user admin` prints a `not joined` error and exits non-zero.
- **Integration status**: Calls `adrian-sdk::AdrianClient::new()` + `client.join(&domain)`. The SDK is a loud-stub; therefore the CLI's `join` is a loud-stub. The other subcommands don't even call into the SDK — they call `client.policy()`, `client.auth()`, `client.file()` (which return zero-sized unit structs) and then do nothing.
- **What's missing**: real `dispatch` arms that call `SdkBuilder`-built modules; interactive password prompt for `auth`/`kinit` when `--password` omitted; JSON output mode; a `--config` flag; integration tests that drive `adrian join` against a `adrian-directory-service` + `adrian-kdc` test fixture.

### adrian-monitor
- **Status**: REAL_COMPLETE for `MetricsRegistry` + `LogAuditSink` + `AuditPipeline` + `MonitorService::metrics_router` (axum `/metrics` + `/healthz`); STUB_LOUD for `OtelAuditSink` (counts events, never emits OTLP) and `MonitorService::install_otel` (returns `Err(MonitorError::Otel("not yet implemented"))`).
- **Test quality**: BEHAVIORAL_REAL for metrics + log sink (15 tests; render_prometheus output is asserted byte-by-byte, histogram bucket math verified, audit event serde round-trip tested); BEHAVIORAL_MINIMAL for the OTel stub.
- **TODOs**: 0
- **Production readiness**: 3/5 — the metrics registry + Prometheus exposition is genuinely usable today (someone could `/metrics` scrape it); but **no crate in the workspace calls `inc_as_req`, `observe_as_req_duration`, `inc_fdb_operation`, `set_replication_lag`, `set_krbtgt_key_age`, `set_rid_pool_remaining`**. The metrics surface has zero producers. Searched `adrian-kdc`, `adrian-directory-service`, `adrian-storage-fdb`, `adrian-identity-ridpool`, `adrian-repl-core` source files — none import `MetricsRegistry` or call any increment method.
- **Integration status**: NONE. `adrian-monitor` does not pull metrics from anywhere; backends do not push metrics anywhere. The two sides exist in isolation.
- **What's missing**: (1) KDC hot-path calls to `inc_as_req` / `observe_as_req_duration` after every AS-REQ/TGS-REQ; (2) DirectoryStore calls to `observe_ldap_query_duration`; (3) FDB storage layer calls to `inc_fdb_operation`; (4) replication layer `set_replication_lag`; (5) RID pool `set_rid_pool_remaining`; (6) KDC `set_krbtgt_key_age` after `rotate-krbtgt`; (7) `install_otel` real impl with configurable OTLP endpoint; (8) `OtelAuditSink` actually emitting LogRecords via `opentelemetry-logs` API.

### adrian-operator
- **Status**: REAL_PARTIAL for CRD types + `serialize_crd` + `crd_definition` + `generate_statefulset` + `generate_helm_chart` (all emit valid JSON/YAML); STUB_LOUD for `AdrianOperator::run` (returns `Err(OperatorError::Reconcile("not yet implemented"))`).
- **Test quality**: BEHAVIORAL_REAL for the generation surface (12 tests assert the CRD YAML has expected `apiVersion`, `kind`, container ports, env vars, volume mounts, liveness/readiness probes; serde round-trip of `DomainControllerCrd`); BEHAVIORAL_MINIMAL for the operator controller.
- **TODOs**: 0
- **Production readiness**: 3/5 — `helm template` on the generated chart would produce a deployable StatefulSet today (with caveats: image `ghcr.io/adrian/dc:0.1.0` doesn't exist yet, `fast-ssd` StorageClass is environment-specific). But there is no reconcile loop, no `kube::Client`, no CRD watch, no status-patching.
- **Integration status**: NONE at runtime. `Cargo.toml` declares `kube`, `k8s-openapi` as deps, but `AdrianOperator::new()` returns an empty struct and `run()` returns Err without ever calling `kube::Client::try_default()`. The `kube` dep is currently dead weight.
- **What's missing**: real `kube::Client` construction from in-cluster or kubeconfig; `kube::Api::<DomainControllerCrd>::all` watch loop; reconcile logic that compares `spec` to observed StatefulSet and patches status; leader election; graceful shutdown on SIGTERM; an integration test using `kube`'s test framework against a `kind`/`k3d` cluster.

### adrian-policy-core
- **Status**: REAL_PARTIAL — full type system (`PolicyDoc`, `PolicyArea` enum with 8 variants, `DeclarativePolicy`, `PolicySetting`, `PolicyValue` enum with 5 variants) + real compilation functions: `compile_to_preg`, `compile_to_configuration_profile`, `compile_to_authselect_profile` emit real PReg/plist/authselect bytes.
- **Test quality**: BEHAVIORAL_REAL — 21 tests; serde round-trip of all types, plist escape verified, PReg output asserted.
- **TODOs**: 2
- **Production readiness**: 4/5
- **Integration status**: `compile_to_preg` is consumed by `adrian-policy-executor::WindowsPolicyExecutor::synthesize_sync`; `compile_to_configuration_profile` is consumed by `MacOsPolicyExecutor`. Real integration.
- **What's missing**: more aggressive `PolicyValue` variant coverage (e.g. typed integers in PolicySetting; today everything is JSON-stringified); a JSON Schema for `DeclarativePolicy` so external authors can validate offline.

### adrian-policy-preg
- **Status**: REAL_COMPLETE — full MS-GPREG §2.2 implementation: `PregFile::parse` + `PregFile::serialize` + `encode_preg_file` + `decode_preg_file` + `PregEntry` with all 8 registry value types. UTF-16LE encoding, hex data encoding, record delimiter handling, signature validation, trailing-NUL tolerance.
- **Test quality**: BEHAVIORAL_REAL — 12 tests; deterministic encode/decode round-trip, malformed-input rejection, hex case verification.
- **TODOs**: 0
- **Production readiness**: 5/5 — this is the most production-ready crate in the audited set. Could ship today as a standalone `Registry.pol` parser library.
- **Integration status**: Consumed by `adrian-policy-core::compile_to_preg` (which is consumed by `adrian-policy-executor::WindowsPolicyExecutor`). Real integration.
- **What's missing**: fuzzing (cargo-fuzz) against adversarial PReg byte streams; performance benchmark against `samba-gpupdate` for large policy files.

### adrian-policy-executor
- **Status**: REAL_PARTIAL — `synthesize` is real (Windows: emits PReg + GptTmpl.inf + Scripts.ini + GPP XML + Adrian/policy.json; macOS: emits managed-client plist + firewall plist + manifest JSON; Linux: emits authselect profile + firewalld XML + limits.conf.d per the doc comments I didn't fully read but the file structure matches). `apply`/`rollback`/`verify` are silent stubs returning `Ok(ApplyResult { transaction_id: Uuid::nil(), areas_applied: 0, ... })`.
- **Test quality**: BEHAVIORAL_REAL for `synthesize` (20 tests assert per-platform file paths and content); BEHAVIORAL_MINIMAL for the silent-stub `apply`/`rollback`/`verify`.
- **TODOs**: 0
- **Production readiness**: 3/5 — the synthesised file sets are the input the operator daemon would push to SYSVOL/MDM/systemd; but the apply/rollback/verify half is unimplemented, and no daemon currently consumes the synthesised output.
- **Integration status**: The `synthesize` outputs are real bytes; nobody currently writes them to disk or pushes them to SYSVOL. The SDK's `DeclarativePolicyModule::apply` returns a loud-stub error, so the SDK doesn't call `PolicyExecutor::synthesize` either.
- **What's missing**: real `apply` per ADR-025 transactional-rollback machinery (snapshot/diff/undo); real `verify` (gpresult on Windows, `profiles show` on macOS, `authselect current` on Linux); a daemon that takes `AppliedPolicy` and atomically writes the files; the SDK's `DeclarativePolicyModule` should call `WindowsPolicyExecutor::synthesize`.

### adrian-policy-cel
- **Status**: STUB_SILENT — `CelSelector::compile` returns `Ok` without compiling (stores source string only); `CelSelector::eval` returns `Err(CelError::Eval("not yet implemented: <source>"))`.
- **Test quality**: BEHAVIORAL_MINIMAL — 4 tests assert the loud-stub error message echoes the source.
- **TODOs**: 3
- **Production readiness**: 1/5
- **Integration status**: NONE. No `cel` crate dep; no compilation; no evaluation.
- **What's missing**: actual `cel-rust` (or `cel-interpreter`) integration; CEL → JSON host-facts binding; sandboxing limits (recursion depth, op count).

### adrian-admx-compiler
- **Status**: REAL_PARTIAL — `parse_admx` is a real `quick-xml` streaming parser (events: `Start`, `Empty`, `Text`, `End`) that builds `AdmxPolicy` structs with `AdmxElement::{Boolean, Text, Integer, Enum}`. `admx_to_declarative` compiles to `DeclarativePolicy`. The legacy `compile(admx_path, adml_path)` wraps the output in a `PolicyDoc` with empty `areas` (lossy — see comment at line 184-187).
- **Test quality**: BEHAVIORAL_REAL — 15 tests covering parse of minimal ADMX, element extraction, enum items, declarative compilation, deterministic output.
- **TODOs**: 0
- **Production readiness**: 4/5
- **Integration status**: Consumed by `adrian-gpo-translate` (which is itself a loud stub that doesn't actually call `parse_admx`).
- **What's missing**: ADML string-table substitution (today `display_name` keeps the raw `$(string.<id>)` reference); the legacy `compile` lossy wrapping; `<categories>` parsing for hierarchy; full `<elements>` coverage (the parser handles `boolean`/`text`/`decimal`/`longDecimal`/`enum` but not `list`/`multitext`).

### adrian-gpo-translate
- **Status**: STUB_SILENT — `translate` and `translate_gpo_directory` return `Err(GpoTranslateError::Io(std::io::Error::new(Unsupported, "not yet implemented")))`.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests assert the loud-stub error kind.
- **TODOs**: 1
- **Production readiness**: 1/5
- **Integration status**: NONE. Despite the doc comment saying it dispatches to `adrian-admx-compiler` / `adrian-policy-preg` / inline GptTmpl parser, no dispatch happens.
- **What's missing**: dispatch table for the 4 `InputFormat` variants; SYSVOL GPO directory walker (ADR-130); GptTmpl.inf INI parser; GPP XML parser.

### adrian-migrate
- **Status**: STUB_SILENT — all 5 entry points (`audit_ntlm`, `plan_ntlm`, `migrate_sidhistory`, `migrate_passwords`, `migrate_sysvol`, `migrate_kerberos`) return loud stub errors.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests assert each entry point returns the documented `MigrationError` variant.
- **TODOs**: 1
- **Production readiness**: 1/5
- **Integration status**: NONE. CLI's `adrian migrate *` subcommands don't even call into this crate — they log and return `Ok(())`.
- **What's missing**: every entry point's body.

### adrian-ca
- **Status**: STUB_SILENT — `CaService::issue`/`revoke`/`load_profiles` all return loud stub errors.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests; serde round-trip of `CertProfile`, enum variants, stub error matching.
- **TODOs**: 5 (the entire CA body)
- **Production readiness**: 1/5
- **Integration status**: NONE. No FDB, no HSM, no x509 cert building.
- **What's missing**: real `issue` (build x509 via `rcgen` or `x509-cert`, sign via `adrian-hsm`, store in FDB); real `revoke` (CRL update + OCSP entry); real `load_profiles` (YAML parse via `serde_yaml`); CRL generation; OCSP responder.

### adrian-acme-server
- **Status**: STUB_SILENT — `AcmeServer::router()` and `ari_router()` return empty `axum::Router::new()` with no routes.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests assert router construction doesn't panic.
- **TODOs**: 5
- **Production readiness**: 1/5
- **Integration status**: NONE. No `/directory`, `/new-nonce`, `/new-account`, `/new-order`, `/authz-v3`, `/challenge`, `/finalize`, `/cert` endpoints. No `CaService` delegation.
- **What's missing**: RFC 8555 §7.1 directory; §7.2 nonce; §7.3 account; §7.4 order; §7.5 authorization; §7.6 challenge; §7.7 finalize/cert; RFC 8823 ARI; JWS verification; account key rollover; rate limiting.

### adrian-wcce-bridge
- **Status**: STUB_SILENT — `WcceBridge::translate_request` returns `Err(WcceError::Translation("MS-WCCE → ACME translation not yet implemented"))` for all 4 `WcceRequestType` variants.
- **Test quality**: BEHAVIORAL_MINIMAL — 4 tests assert the loud-stub error.
- **TODOs**: 4
- **Production readiness**: 1/5
- **Integration status**: NONE. No DCOM transport; no ACME upstream.
- **What's missing**: MS-WCCE §3.x DCOM dispatch; `CertServerRequest` Ping/Request/GetCert/GetCACert translation; CA lookup by template OID; ACME order placement; polling.

### adrian-smb-server
- **Status**: STUB_SILENT — `SmbServer::serve()` returns `Err(SmbServerError::Protocol("not yet implemented"))`.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests assert error variants.
- **TODOs**: 2
- **Production readiness**: 1/5
- **Integration status**: NONE. No TCP/445 bind; no negotiate/session-setup/tree-connect.
- **What's missing**: real SMB 3.1.1 server: NEGOTIATE (dialect selection, preauth integrity), SESSION_SETUP (Kerberos via GSSAPI, signing key derivation), TREE_CONNECT, CREATE (with durable handles per ADR-106), READ, WRITE, CLOSE, TRANSFORM (encryption); PAC validation per ADR-123.

### adrian-smb-client
- **Status**: STUB_SILENT — `SmbClient::connect` returns `Connect("not yet implemented")`, `SmbClient::open` returns `Share("not yet implemented")`.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests.
- **TODOs**: 3
- **Production readiness**: 1/5
- **Integration status**: NONE. The SDK's `SmbFileModule::mount_share` is a loud stub that doesn't even import `adrian-smb-client` at runtime.
- **What's missing**: real negotiate/session-setup/tree-connect; persistent handles (durable open, reconnect after network blip); DFS-N referral following per ADR-044.

### adrian-smb-core
- **Status**: STUB_SILENT — type enums (`Dialect`, `Command`, `NegotiateRequest`) are defined; `encode_negotiate`/`decode_negotiate` both return `Err(SmbError::Malformed("not yet implemented"))`.
- **Test quality**: BEHAVIORAL_MINIMAL — 11 tests assert type enums, repr values, error variants.
- **TODOs**: 2
- **Production readiness**: 1/5
- **Integration status**: NONE. The `rasn` dep mentioned in the crate doc is not in `Cargo.toml` — wire codecs are entirely unimplemented.
- **What's missing**: `rasn`-backed SMB2 PDU codecs for every `Command` variant; SMB 3.1.1 preauth integrity (SHA-512); encryption (AES-128-CCM / AES-128-GCM); signing (HMAC-SHA256 over the SMB2 header).

### adrian-print-service
- **Status**: STUB_SILENT — `PrintService::router()` returns empty `axum::Router::new()`.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests.
- **TODOs**: 2
- **Production readiness**: 1/5
- **Integration status**: NONE.
- **What's missing**: RFC 8011 IPP operations (Print-Job, Validate-Job, Get-Jobs, Get-Printer-Attributes, Hold-Job, Release-Job, Cancel-Job); CUPS integration; print queue registry.

### adrian-federation-shim
- **Status**: STUB_SILENT — `FederationShim::router()` returns empty router; `push_jwks_rollover()` returns `Err(JwksRollover("not yet implemented"))`.
- **Test quality**: BEHAVIORAL_MINIMAL — 5 tests.
- **TODOs**: 4
- **Production readiness**: 1/5
- **Integration status**: NONE.
- **What's missing**: WS-Trust `/trust/2005/usernamemixed` endpoint; JWKS rollover webhook; SAML replay cache (moka); Keycloak upstream proxy.

### adrian-claims-engine
- **Status**: STUB_SILENT — `ClaimRule::parse` accepts any string (no grammar); `ClaimRule::to_cel` returns a `CelSelector::compile("true")` (literal `true`).
- **Test quality**: BEHAVIORAL_MINIMAL — 4 tests.
- **TODOs**: 3
- **Production readiness**: 1/5
- **Integration status**: Depends on `adrian-policy-cel` which is itself a stub.
- **What's missing**: AD FS claim rule language grammar parser (the language is small but non-trivial — `=> issue(Type = "...", Value = "...");`); translator to CEL.

### adrian-test-harness
- **Status**: STUB_SILENT — only sample SID/principal fixtures; no in-process FDB cluster; no integration harness; no interop fixtures.
- **Test quality**: NONE — 0 tests.
- **TODOs**: 3
- **Production readiness**: 1/5
- **Integration status**: NONE.
- **What's missing**: in-process FDB cluster spinup (foundationdb-rs has a `testnet` feature, or use `fdb-server` in a container); adrian-directory-service + LDAP client harness; interop fixtures (Windows Server 2022 VM, MIT krb5 container, Samba 4.20 container, OpenLDAP container, FreeIPA 4.10 container).

## Integration Status Matrix

| Edge | Real backend wiring? | Tested end-to-end? | Notes |
|------|---------------------|-------------------|-------|
| `adrian-sdk` → `adrian-kdc` | NO | NO | `KerberosAuthModule::authenticate_kerberos` returns `Err(SdkError::Auth("... not yet wired to adrian-kdc (ADR-108)"))` |
| `adrian-sdk` → `adrian-directory-service` (LDAP) | NO | NO | `LdapDirectoryModule::search` returns `Err(SdkError::Directory("... not yet wired to adrian-directory-service (ADR-109)"))` despite `ldap3` being a declared dep |
| `adrian-sdk` → `adrian-policy-executor` | NO | NO | `DeclarativePolicyModule::apply` returns `Err(SdkError::Policy("... not yet wired to adrian-policy-executor"))` |
| `adrian-sdk` → `adrian-smb-client` | NO | NO | `SmbFileModule::mount_share` returns `Err(SdkError::File("... not yet wired to adrian-smb-client (ADR-106)"))` despite `adrian-smb-client` being a path-dep |
| `adrian-sdk` → `adrian-acme-server` | NO | NO | `AcmeCertModule::enroll` returns `Err(SdkError::Cert("... not yet wired to adrian-acme-server"))` |
| `adrian-sdk` → `join()` writes `/etc/adrian/` | NO | NO | Returns `Err(SdkError::NotJoined)` |
| `adrian-cli` → `adrian-sdk::AdrianClient::join` | YES (loud) | YES (asserts error msg) | Only `join` actually calls into SDK; 8 other subcommands silently `Ok(())` |
| `adrian-cli` → `adrian-migrate` | NO | NO | `migrate *` subcommands log + `Ok(())` |
| `adrian-cli` → `adrian-gpo-translate` | NO | NO | `gpo-translate` subcommand logs + `Ok(())` |
| `adrian-monitor` ← `adrian-kdc` | NO | NO | KDC source files contain zero `inc_as_req` / `observe_as_req_duration` calls |
| `adrian-monitor` ← `adrian-directory-service` | NO | NO | Directory service source contains zero `observe_ldap_query_duration` calls |
| `adrian-monitor` ← `adrian-storage-fdb` | NO | NO | FDB storage source contains zero `inc_fdb_operation` calls |
| `adrian-monitor` ← `adrian-repl-core` | NO | NO | Replication source contains zero `set_replication_lag` calls |
| `adrian-monitor` ← `adrian-identity-ridpool` | NO | NO | RID pool source contains zero `set_rid_pool_remaining` calls |
| `adrian-operator` → k8s API (`kube::Client`) | NO | NO | `AdrianOperator::run()` returns `Err(Reconcile("not yet implemented"))` without constructing a client |
| `adrian-operator` → CRD YAML generation | YES (real) | YES (asserted YAML) | `serialize_crd` / `generate_statefulset` / `generate_helm_chart` / `crd_definition` all produce valid JSON/YAML |
| `adrian-policy-core::compile_to_preg` → `adrian-policy-preg` | YES | YES (round-trip tests) | Real PReg bytes emitted, parsed back |
| `adrian-policy-executor::synthesize` → `adrian-policy-core::compile_to_*` | YES | YES (file-path assertions) | Real bytes for Windows PReg/GptTmpl/Scripts.ini/GPP XML + macOS plist + Linux authselect |
| `adrian-policy-executor::apply` → filesystem / SYSVOL | NO | NO | Returns `ApplyResult { transaction_id: Uuid::nil(), areas_applied: 0, ... }` |
| `adrian-admx-compiler::parse_admx` → `quick-xml` | YES | YES | Real streaming parse |
| `adrian-gpo-translate` → `adrian-admx-compiler` | NO | NO | `translate` returns `Io(Unsupported)` |
| `adrian-wcce-bridge` → `adrian-acme-server` | NO | NO | `translate_request` returns `Translation("not yet implemented")` |
| `adrian-federation-shim` → Keycloak upstream | NO | NO | Empty router + `push_jwks_rollover` returns Err |
| `adrian-claims-engine` → `adrian-policy-cel` | YES (but stub → stub) | YES (stub assertions) | `to_cel` calls `CelSelector::compile("true")`; the resulting selector is itself a loud stub |
| `adrian-test-harness` → in-process FDB | NO | NO | 3 TODOs at end of lib.rs |

## Cross-Cutting Observations

1. **Loud-stub discipline is consistent but the integration gap is total.** Every stub returns a typed `Error` variant with a `"not yet wired to <crate> (ADR-xxx)"` message. This is good engineering hygiene — no silent Ok — but it masks the fact that **zero of the 25 audited crates actually call into a backend**. The framework's 602 passing tests are mostly asserting that stubs return the documented error variant.

2. **Dead dependencies.** `adrian-sdk/Cargo.toml` declares `ldap3`, `rustls`, `adrian-smb-client`, `adrian-auth-core` as path/workspace deps but the `sdk::*` stub impls never `use` them. `adrian-operator/Cargo.toml` declares `kube` and `k8s-openapi` but the operator struct holds no `kube::Client`. These compile but contribute binary bloat for no functionality.

3. **Test quality is bimodal.** The real-implementation crates (`adrian-policy-preg`, `adrian-policy-core`, `adrian-policy-executor::synthesize`, `adrian-admx-compiler`, `adrian-monitor::MetricsRegistry`) have BEHAVIORAL_REAL tests that assert byte-level output. The stub crates have BEHAVIORAL_MINIMAL tests that assert the loud-stub error variant + Display string. The two missing test categories are (a) end-to-end integration tests (none exist — `adrian-test-harness` has 0 tests and 3 TODOs) and (b) fuzzing (none exist).

4. **The SDK is the integration point, and it is not integrating.** ADR-107 §Decision says "the host platform constructs one `AdrianSdk` per process; all callers share the same connection pool, credential cache, and config." The trait surface (`AuthModule`, `DirectoryModule`, `PolicyModule`, `FileModule`, `CertModule`) is well-designed; the `SdkBuilder` enforces the all-five-modules invariant. But the 5 default impls are zero-state stubs that return errors. The host platform (Windows LSA / macOS OpenDirectory / Linux PAM-NSS) cannot integrate until at least one default impl is real.

5. **CLI dispatch is asymmetric.** Only `Join` and `Policy Apply` actually delegate to the SDK (and surface its loud-stub errors). The other 8 subcommands log a `tracing::info!` and return `Ok(())` without calling anything. This means `adrian gpupdate` appears to succeed but does nothing — a UX worse than failing loudly.

6. **Monitor has zero producers.** `MetricsRegistry` is fully implemented with a Prometheus exposition renderer, but no other crate in the workspace calls any of its methods. The `/metrics` endpoint would always return empty (zero counters, zero histograms, zero gauges).

7. **Operator is a YAML generator, not an operator.** `crd_definition()`, `generate_statefulset()`, `generate_helm_chart()` are genuinely useful (and the Helm chart would template correctly). But `AdrianOperator::run()` is the loud-stub. Without a reconcile loop wired to `kube::Client`, this is chart-ware, not an operator.

8. **Wave 4b/4c deferred crates are all still loud stubs.** All 9 deferred crates (`adrian-ca`, `adrian-acme-server`, `adrian-wcce-bridge`, `adrian-smb-server`, `adrian-smb-client`, `adrian-smb-core`, `adrian-print-service`, `adrian-federation-shim`, `adrian-policy-cel`) plus `adrian-claims-engine` and `adrian-test-harness` remain at the same stub state as when they were deferred. None has progressed past error-variant + Display-string tests.

9. **Policy stack is the bright spot.** `adrian-policy-core` + `adrian-policy-preg` + `adrian-policy-executor::synthesize` + `adrian-admx-compiler::parse_admx` form a real, tested, end-to-end pipeline from ADMX XML → `AdmxPolicy` → `DeclarativePolicy` → `PregFile` bytes. The gap is "no daemon writes the bytes to disk," but the compilation path itself works.

## Risk Register

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| SDK stubs never get wired → v0.6.0 ships with same integration gap | High | High | Allocate Wave 6 entirely to one module at a time (start with `KerberosAuthModule` → `adrian-kdc` since both are in-workspace); add integration tests as the acceptance criterion |
| CLI silent-Ok subcommands mislead operators into thinking `adrian gpupdate`/`klist` worked | Medium | High | Convert the 8 silent-Ok arms to loud-stub errors that surface "not yet implemented" until the underlying SDK module is wired |
| Monitor metrics have zero producers → dashboards always show zero | Medium | Certain | Add `inc_as_req`/`observe_as_req_duration` calls to `adrian-kdc` AS-REQ handler in the same wave that wires `KerberosAuthModule`; add `inc_fdb_operation` to `adrian-storage-fdb` transaction path |
| Operator CRD YAML references nonexistent image `ghcr.io/adrian/dc:0.1.0` | Medium | Certain | Either publish a placeholder image, or change the default to `ghcr.io/adrian/dc:0.5.0` matching the workspace version, or surface a validation error in `generate_statefulset` if `image` is empty |
| `kube` + `k8s-openapi` deps in `adrian-operator` are dead weight, increasing compile time | Low | Certain | Either wire `AdrianOperator::run` to a real `kube::Client` (preferred) or move the deps under `[dev-dependencies]` until the reconcile loop lands |
| `adrian-sdk` declares `ldap3`/`rustls`/`adrian-smb-client`/`adrian-auth-core` as deps but doesn't use them | Low | Certain | Either implement `LdapDirectoryModule` against `ldap3` (preferred) or remove the unused deps until the impls land |
| `adrian-test-harness` has 0 tests and 3 TODOs → no integration safety net when modules start getting wired | High | Certain | Build the in-process FDB + directory-service harness as the very first task of Wave 6, before wiring any SDK module |
| `adrian-policy-executor::apply` returns `Ok` with `Uuid::nil()` transaction ID → callers may think apply succeeded | Medium | High | Convert to loud-stub `Err(PolicyError::NotImplemented(...))` until ADR-025 transactional rollback lands |
| `adrian-policy-cel` silently accepts any source string in `compile` → downstream `eval` failure surfaces late | Low | Medium | Make `compile` return `Err(CelError::Compile(...))` for syntactically invalid CEL (or integrate `cel-rust` and let it reject) |
| `adrian-cli` `Leave` is a literal no-op `Ok(())` | Low | High | Convert to loud-stub until SDK has a `leave()` method |

## Recommendations for v0.6.0

Prioritized by leverage (unblocks the most downstream work per unit of effort):

1. **Wire `adrian-sdk::KerberosAuthModule::authenticate_kerberos` → `adrian-kdc` AS-REQ.** This is the single highest-leverage integration: it unblocks the SDK `AuthModule` trait, makes `adrian auth` and `adrian kinit` actually acquire TGTs, and forces the test harness to exist (you can't test AS-REQ without a running KDC). Estimated: 1-2 weeks. Deliverable: an integration test that calls `sdk.auth.authenticate_kerberos("admin@ADRIAN.DEV", "password")` and asserts the returned `AuthToken` has `kind: Kerberos`.

2. **Build `adrian-test-harness` in-process FDB + directory-service + KDC fixtures.** Prerequisite for #1. Without this, every integration test is a manual `docker compose up`. Estimated: 1 week. Deliverable: `adrian_test_harness::spinup_cluster() -> TestCluster` returning handles to a running FDB + DirectoryService + KDC.

3. **Wire `adrian-monitor` producers into `adrian-kdc` + `adrian-storage-fdb`.** Cheap, mechanical work: add `inc_as_req(realm, etype)` calls in the KDC AS-REQ handler, `inc_fdb_operation(op_type)` in the FDB transaction path, `observe_as_req_duration(seconds)` around the handler. Estimated: 2-3 days. Deliverable: `curl /metrics` on a running DC shows non-zero counters.

4. **Convert the 8 silent-Ok CLI subcommands to loud-stub errors.** Trivial change: replace `Ok(())` with `Err(anyhow!("not yet implemented: <subcommand>"))`. Estimated: half a day. Deliverable: `adrian gpupdate` prints "not yet implemented: gpupdate" instead of silently succeeding.

5. **Wire `adrian-sdk::LdapDirectoryModule` → `ldap3` crate → `adrian-directory-service`.** The `ldap3` dep is already in `Cargo.toml`; the directory service already speaks LDAP. Estimated: 1 week. Deliverable: integration test that calls `sdk.directory.search("(sAMAccountName=admin)")` against the test harness and asserts the returned `DirEntry` has the expected DN.

6. **Wire `adrian-operator::AdrianOperator::run` → `kube::Client` watch loop.** Either implement a real reconcile loop or split the crate into `adrian-operator-crds` (YAML generation, usable today) and `adrian-operator-controller` (the reconcile loop, deferred). Estimated: 2-3 weeks for a real reconcile loop; 1 day for the split. Deliverable: `kubectl apply -f <generated-crd.yaml>` then `kubectl get dcs` shows the operator reconciling.

7. **Wire `adrian-policy-executor::apply` to actually write the `synthesize`d files to a target directory** (initially `/tmp/adrian-policy-test/`, later SYSVOL). This is the missing half of the policy pipeline. Estimated: 1 week (without transactional rollback — that's a separate ADR-025 effort). Deliverable: integration test that runs `executor.apply(&doc, "/tmp/foo")` and asserts the files exist on disk.

8. **Implement `adrian-ca::CaService::issue` + `adrian-acme-server` RFC 8555 endpoints.** The cert enrollment path is the longest pole for native-mode deployments. Estimated: 3-4 weeks. Deliverable: `adrian cert enroll --subject dc01.adrian.dev` returns a real DER cert via ACME.

9. **Implement `adrian-smb-core` `rasn`-backed PDU codecs + `adrian-smb-client::SmbClient::connect`.** The SMB client is what the SDK `FileModule` needs. Estimated: 4-6 weeks (SMB 3.1.1 is a large protocol). Deliverable: `sdk.file.mount_share("dc01", "sysvol", &auth)` returns a real `MountedShare`.

10. **Convert `adrian-policy-executor::apply`/`rollback`/`verify` from silent-Ok to loud-stub errors.** Trivial: replace the `Ok(ApplyResult { transaction_id: Uuid::nil(), ... })` body with `Err(PolicyError::NotImplemented(...))`. Estimated: half a day. Prevents callers from thinking apply succeeded.

11. **Remove or feature-gate dead deps** in `adrian-sdk` (`ldap3`, `rustls`, `adrian-smb-client`, `adrian-auth-core`) and `adrian-operator` (`kube`, `k8s-openapi`) until the impls that use them land. Estimated: half a day. Reduces compile time + binary size.

12. **Add `cargo-fuzz` targets for `adrian-policy-preg::decode_preg_file` and `adrian-admx-compiler::parse_admx`.** These are the only crates in this layer that parse untrusted bytes from external sources (SYSVOL `Registry.pol`, ADMX files). Estimated: 1 day to set up + ongoing fuzzing. Deliverable: fuzzer finds no panics in 24h of CPU time.
