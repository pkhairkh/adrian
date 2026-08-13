---
title: Rust Workspace Design — ~30–40 Crates in 5 Dependency Layers
audience: architects-and-engineers
tags: [final-draft, rust, workspace, cargo, crates, traits, error-handling, async, feature-flags, testing, ci-cd]
related:
  - ./README.md
  - ./01-executive-summary.md
  - ./02-foundational-decisions.md
  - ./03-capability-deep-dives.md
  - ../adr/README.md
last_updated: 2026-08-14
---

# Rust Workspace Design — ~30–40 Crates in 5 Dependency Layers

## 1. Workspace overview

The Adrian framework is a single Cargo workspace at `adrian/` containing ~30–40 crates, all dual-licensed MIT/Apache-2.0, all owned by the framework team. The workspace root `Cargo.toml` declares the member list, the shared dependency versions (via `[workspace.dependencies]`), the shared profile settings (`opt-level`, `lto = "thin"` for release, `debug = "line-tables-only"` for release to keep backtraces), and the workspace-level metadata (authors, license, repository, edition = 2021). The crate count is deliberately bounded: each capability contributes 1–5 crates (per the deep dives in [`./03-capability-deep-dives.md`](./03-capability-deep-dives.md)), and cross-cutting concerns (storage, replication, schema, identity, SDK, operator) get their own crates to keep the dependency graph clean.

The workspace uses Cargo features for conditional compilation of the two operating modes (per Workshop Decision 1). The `ad-interop` feature flag, defined at the workspace level and inherited by every crate that needs it, enables the DRSUAPI replication path (`adrian-drsuapi`), the MS-WCCE enrollment bridge (`adrian-wcce-bridge`), the NTLM client (`adrian-ntlm-client`), the ADMX compiler (`adrian-admx-compiler`), and the FSMO emulation code paths. Without `ad-interop`, the framework builds in native-only mode: Raft replication, ACME-only enrollment, no NTLM (neither server nor client), declarative JSON policy authoring only, and FSMO roles eliminated (per ADR-076). The framework's release binaries always enable `ad-interop` (the v1 customer base is overwhelmingly AD-interop); native-only builds are for greenfield deployments and reduce binary size by ~15% by excluding the DRSUAPI and MS-WCCE code paths.

## 2. Workspace layout

```
adrian/
├── Cargo.toml                       (workspace root, [workspace.dependencies] pinning)
├── Cargo.lock                       (committed; reproducible builds)
├── rust-toolchain.toml              (stable channel, pinned)
├── crates/
│   ├── adrian-storage-core/         (DirectoryStore trait, no impl)
│   ├── adrian-storage-fdb/          (FdbDirectoryStore, FDB 7.3.x client)
│   ├── adrian-repl-core/            (Replicator trait, ReplOperation, UtdVector)
│   ├── adrian-drsuapi/              (DrSuapiReplicator, MS-DRSR IDL via rasn)
│   ├── adrian-raft/                 (RaftReplicator, openraft integration)
│   ├── adrian-directory-service/    (LDAP server + DSA, axum + ldap3 server)
│   ├── adrian-sid/                  (SID format, parse/serialize, SID-to-UUID)
│   ├── adrian-identity-core/        (IdentityMapping trait)
│   ├── adrian-identity-fdb/         (FDB-backed identity mapping table)
│   ├── adrian-identity-ridpool/     (RID pool allocator for AD-interop)
│   ├── adrian-schema-compiler/      (LDAP schema → Rust typed projection)
│   ├── adrian-schema-traits/        (Schema trait definitions, #[derive(Projectable)])
│   ├── adrian-kdc/                  (Kerberos KDC, ~30K lines)
│   ├── adrian-kdc-interop/          (MS-KILE conformance tests vs Windows 2022)
│   ├── adrian-pkinit-bridge/        (FIDO2/WebAuthn + RFC 4556 PKINIT)
│   ├── adrian-pac-validator/        (unified PAC validator, libframework_pac_validator)
│   ├── adrian-ntlm-client/          (NTLM client-only, ~3K lines)
│   ├── adrian-auth-core/            (AuthContext trait, Principal type)
│   ├── adrian-policy-core/          (PolicyDoc, PolicyArea, canonical JSON)
│   ├── adrian-policy-executor/      (PolicyExecutor trait + 3 platform impls)
│   ├── adrian-policy-cel/           (CEL selector, role-based binding)
│   ├── adrian-policy-preg/          (PReg adapter, Registry.pol read/write)
│   ├── adrian-policy-distribution/  (WebSocket push + Git pull)
│   ├── adrian-policy-daemon/        (adrian-policyd, runs as SYSTEM/root/launchd)
│   ├── adrian-admx-compiler/        (admx2adrian, ADMX → canonical JSON)
│   ├── adrian-sssd-gpo/             (cdylib, extends SSSD's ad_gpo_access)
│   ├── adrian-ca/                   (CA core, cert issuance, HSM-bound keys)
│   ├── adrian-acme-server/          (RFC 8555 + 8737 + 8823 ARI)
│   ├── adrian-wcce-bridge/          (MS-WCCE → ACME translation)
│   ├── adrian-est-bridge/           (RFC 7030 EST → ACME)
│   ├── adrian-scep-bridge/          (RFC 8894 SCEP → ACME)
│   ├── adrian-ocsp/                 (RFC 6960 OCSP responder, HA cluster)
│   ├── adrian-hsm/                  (uniform Signer trait over PKCS#11/CNG)
│   ├── adrian-federation-shim/      (Keycloak sidecar, Rust axum, WS-Trust bridge)
│   ├── adrian-claims-engine/        (AD FS CRL compatibility layer)
│   ├── adrian-smb-server/           (fresh SMB 3.1.1 server, ~15K lines)
│   ├── adrian-smb-core/             (SMB protocol primitives, shared client/server)
│   ├── adrian-smb-client/           (SMB client for SDK's FileModule)
│   ├── adrian-print-service/        (IPP Everywhere, cups integration)
│   ├── adrian-sdk/                  (Rust core SDK, AdrianClient)
│   ├── adrian-sdk-c/                (C ABI via cbindgen)
│   ├── adrian-sdk-jni/              (JNI bindings)
│   ├── adrian-sdk-swift/            (Swift bindings via swift-bridge)
│   ├── adrian-sdk-python/           (pyo3 + maturin)
│   ├── adrian-operator/             (Kubernetes operator, DomainController CRD)
│   ├── adrian-cli/                  (unified cross-platform CLI, clap)
│   ├── adrian-monitor/              (Prometheus + OpenTelemetry)
│   ├── adrian-audit/                (structured OTel audit logs, MITRE ATT&CK)
│   ├── adrian-migrate/              (migration tooling, audit-ntlm/plan-ntlm)
│   ├── adrian-gpo-translate/        (admx2adrian + preg2adrian wrapper)
│   └── adrian-test-harness/         (shared test fixtures, interop test utils)
├── examples/
│   ├── join-linux/                  (adrian-cli join reference)
│   ├── join-macos/                  (PSSO Extension + join)
│   ├── join-windows/                (adrianlsa.dll + join)
│   ├── migrate-from-ad/             (parallel-run migration example)
│   └── greenfield-deploy/           (native-mode Kubernetes deployment)
├── tests/
│   ├── integration/                 (cross-crate integration tests)
│   ├── interop/                     (vs Windows Server 2022, MIT krb5, Samba)
│   └── property/                    (proptest for protocol parsers)
└── docs/                            (architecture docs, ADRs, catalog)
```

The crate count is 47 in this layout. Of those, 39 are the framework's own crates (the rest are illustrative — `adrian-test-harness` is shared test fixtures, the others are example/test scaffolding). The framework accepts this count because each crate has a clear single responsibility, a public API surface bounded by trait definitions, and a test suite scoped to its own code. Smaller crate counts would couple unrelated capabilities; larger counts would fragment the dependency graph. The 39 framework crates average ~5K lines each (range: ~1K for `adrian-sid` to ~30K for `adrian-kdc`), totaling ~200K lines of Rust — comparable to Samba 4's AD-DC subset (~250K lines of C) and substantially smaller than Windows Server's AD DS codebase (estimated >1M lines of C/C++ across `ntdsa.dll`, `lsass.exe`, `kdcsvc.dll`, and supporting binaries).

## 3. Crate dependency layers

The 39 framework crates are organized in five dependency layers. Lower layers never depend on higher layers; same-layer crates may depend on each other only when the dependency is acyclic. The layering is enforced by a CI check (`cargo-deny` + a custom `adrian-check-layers` script that reads each crate's `Cargo.toml` and rejects forbidden cross-layer deps) — a developer who adds an illegal dependency gets a CI failure before review.

**Layer 0 — Foundation (no internal dependencies).**
- `adrian-storage-core` — the `DirectoryStore` trait, the `DirectoryTransaction` trait, the `Key`/`Value`/`KeyRange` types, the `DirectoryError` enum. No implementation; consumed by every layer above.
- `adrian-sid` — the `Sid` type (`S-1-5-21-...` format), parse/serialize per MS-DTYP §2.4.2, SID-to-UUID conversion helpers. Pure data type, no I/O.
- `adrian-schema-traits` — the `Projectable` derive macro, the `SchemaProjection` type, the `AttributeId`/`ClassId` types. No I/O; consumed by the schema compiler and by every crate that reads typed directory objects.

Layer 0 has zero internal dependencies and depends only on external crates (`foundationdb` types, `uuid`, `rasn` primitives, `thiserror`). Layer 0 crates can be compiled in isolation; they are the framework's stable API surface.

**Layer 1 — Abstractions (depend on Layer 0).**
- `adrian-storage-fdb` — `FdbDirectoryStore` impl of `DirectoryStore`. Depends on `adrian-storage-core`, `foundationdb`, `tokio`.
- `adrian-identity-core` — the `IdentityMapping` trait (`uuid_to_sid`, `sid_to_uuid`, `uuid_to_uid`, `uid_to_uuid`). Depends on `adrian-sid`, `uuid`.
- `adrian-repl-core` — the `Replicator` trait, `ReplOperation` enum, `PropertyMetaDataExt`, `UtdVector`, `UtdDelta`, `ConflictRecord`, `Resolution`. Depends on `adrian-storage-core`, `adrian-schema-traits`, `uuid`.
- `adrian-auth-core` — the `AuthContext` trait, the `Principal` type. Depends on `adrian-sid`, `uuid`.

Layer 1 traits compose Layer 0 types into the framework's primary abstractions. A crate at Layer 1 may depend on multiple Layer 0 crates but never on another Layer 1 crate (the layer is parallel, not stacked). This prevents the trait abstractions from coupling to each other prematurely.

**Layer 2 — Domain implementations (depend on Layers 0–1).**
- `adrian-identity-fdb` — `FdbIdentityMapping` impl of `IdentityMapping`, stored in FDB subspace `0x06`. Depends on `adrian-identity-core`, `adrian-storage-fdb`.
- `adrian-identity-ridpool` — RID pool allocator for AD-interop mode (per-DC local counter in native mode). Depends on `adrian-identity-core`, `adrian-storage-fdb`.
- `adrian-drsuapi` — `DrSuapiReplicator` impl of `Replicator`, fresh Rust MS-DRSR. Depends on `adrian-repl-core`, `adrian-storage-fdb`, `rasn`, `rasn-kerberos`, `tokio`. Gated by `ad-interop` feature.
- `adrian-raft` — `RaftReplicator` impl of `Replicator`, openraft integration. Depends on `adrian-repl-core`, `adrian-storage-fdb`, `openraft`, `tokio`.
- `adrian-schema-compiler` — walks Schema NC, builds `Arc<SchemaProjection>` at boot, regenerates on `schemaUpdateNow`. Depends on `adrian-schema-traits`, `adrian-storage-core`, `adrian-identity-core`, `phf`, `rasn`.
- `adrian-directory-service` — LDAP server (TCP/389, LDAPS/636), DSA, `schemaModifyRequest` handler, AD-interop LDAP controls (per ADR-006), GC listener (TCP/3268, 3269). Depends on `adrian-storage-fdb`, `adrian-schema-compiler`, `adrian-identity-fdb`, `adrian-repl-core`, `tokio`, `ldap3` server mode.
- `adrian-policy-core` — `PolicyDoc`, `PolicyArea` enum, canonical JSON serialization. Depends on `adrian-schema-traits`, `serde`, `serde_json`, `cel`.
- `adrian-policy-executor` — `PolicyExecutor` trait, `WindowsPolicyExecutor`, `MacOsPolicyExecutor`, `LinuxPolicyExecutor`. Depends on `adrian-policy-core`, `quick-xml`, `plist`, `rust-ini`.
- `adrian-pac-validator` — unified PAC validator (`libframework_pac_validator.dylib`). Depends on `adrian-sid`, `rasn`, `rasn-kerberos`, `ring`, `md4`.

Layer 2 implements the Layer 1 traits against concrete backends (FDB, openraft, rasn) and adds domain logic (schema compilation, LDAP server, policy model, PAC validation). Layer 2 crates may depend on each other within the layer (e.g., `adrian-directory-service` depends on `adrian-schema-compiler` and `adrian-identity-fdb`).

**Layer 3 — Services (depend on Layers 0–2).**
- `adrian-kdc` — Kerberos KDC, ~30K lines, all etypes, FAST, PKINIT, kpasswd, S4U2Self/S4U2Proxy. Depends on `adrian-storage-fdb`, `adrian-schema-compiler`, `adrian-identity-fdb`, `adrian-pac-validator`, `rasn`, `rasn-kerberos`, `ring`, `cryptoki`.
- `adrian-kdc-interop` — MS-KILE conformance tests vs Windows Server 2022. Depends on `adrian-kdc`, `tokio`, `rasn-kerberos`. Dev-dependency only.
- `adrian-pkinit-bridge` — FIDO2/WebAuthn + RFC 4556 PKINIT. Depends on `adrian-kdc`, `webauthn-rs`, `x509-cert`.
- `adrian-ntlm-client` — NTLM client-only, ~3K lines. Depends on `adrian-auth-core`, `md4`, `hmac`, `sha2`, `rasn`, `rasn-pkix`, `keyring`. Gated by `ad-interop` feature.
- `adrian-policy-distribution` — WebSocket push + Git pull. Depends on `adrian-policy-core`, `tokio`, `tokio-tungstenite`, `git2`, `rustls`.
- `adrian-policy-daemon` — `adrian-policyd`, runs as SYSTEM/root/launchd. Depends on `adrian-policy-core`, `adrian-policy-executor`, `adrian-policy-distribution`, `tokio`, `clap`.
- `adrian-admx-compiler` — `admx2adrian` binary. Depends on `adrian-policy-core`, `quick-xml`, `serde_json`. Gated by `ad-interop` feature.
- `adrian-sssd-gpo` — cdylib, extends SSSD's `ad_gpo_access`. Depends on `adrian-policy-core`, `libc`.
- `adrian-ca` — CA core, cert issuance, HSM-bound keys. Depends on `adrian-storage-fdb`, `adrian-hsm`, `x509-cert`, `cryptoki`, `tokio`.
- `adrian-acme-server` — RFC 8555 + 8737 + 8823 ARI. Depends on `adrian-ca`, `axum`, `rustls`, `tokio`, `serde_json`.
- `adrian-wcce-bridge` — MS-WCCE → ACME translation. Depends on `adrian-acme-server`, `rasn`, `rustls`, `tokio`. Gated by `ad-interop` feature.
- `adrian-est-bridge` / `adrian-scep-bridge` — RFC 7030 / RFC 8894 bridges. Depend on `adrian-acme-server`.
- `adrian-ocsp` — RFC 6960 OCSP responder. Depends on `adrian-ca`, `axum`, `ring`.
- `adrian-hsm` — uniform `Signer` trait over PKCS#11/CNG. Depends on `cryptoki`, `windows`.
- `adrian-smb-server` — fresh SMB 3.1.1 server, ~15K lines. Depends on `adrian-storage-fdb`, `adrian-identity-fdb`, `adrian-pac-validator`, `tokio`, `rustls`, `aes`, `aes-gcm`, `sha2`, `rasn`, `gss-api`.
- `adrian-smb-core` — SMB protocol primitives, shared by server and client. Depends on `rasn`, `rasn-kerberos`.
- `adrian-smb-client` — SMB client for SDK's `FileModule`. Depends on `adrian-smb-core`, `tokio`.
- `adrian-print-service` — IPP Everywhere (RFC 8011), `cups` integration. Depends on `axum`, `tokio`.
- `adrian-federation-shim` — Keycloak sidecar, Rust `axum`, WS-Trust bridge. Depends on `adrian-claims-engine`, `axum`, `tokio`, `rustls`, `openidconnect`, `saml2`, `moka`, `serde_json`.
- `adrian-claims-engine` — AD FS CRL compatibility. Depends on `adrian-policy-cel`, `serde_json`.
- `adrian-sdk` — Rust core SDK, `AdrianClient`. Depends on `adrian-auth-core`, `adrian-storage-core`, `adrian-policy-core`, `adrian-identity-core`, `ldap3`, `pavao`, `rustls`, `openidconnect`, `saml2`, `tokio`.

Layer 3 crates are the framework's user-facing services. They wire Layer 2 implementations into running servers (`adrian-kdc`, `adrian-smb-server`, `adrian-acme-server`) and composite APIs (`adrian-sdk`). Layer 3 crates may depend on multiple Layer 2 and Layer 3 crates.

**Layer 4 — Operations & tooling (depend on Layers 0–3).**
- `adrian-operator` — Kubernetes operator, `DomainController` CRD. Depends on `adrian-directory-service`, `adrian-kdc`, `kube`, `tokio`, `serde_yaml`.
- `adrian-cli` — unified cross-platform CLI, `clap`. Depends on `adrian-sdk`, `adrian-migrate`, `adrian-policy-core`, `clap`, `tokio`, `serde_json`.
- `adrian-monitor` — Prometheus + OpenTelemetry. Depends on `adrian-storage-fdb`, `adrian-repl-core`, `prometheus`, `opentelemetry`, `opentelemetry-otlp`, `tracing`, `tracing-opentelemetry`.
- `adrian-audit` — structured OTel audit logs, MITRE ATT&CK mapping. Depends on `adrian-storage-fdb`, `opentelemetry`, `tracing`.
- `adrian-migrate` — migration tooling, `audit-ntlm`/`plan-ntlm`/`sidhistory`/`passwords`. Depends on `adrian-sdk`, `adrian-gpo-translate`, `tokio`, `serde_json`, `clap`.
- `adrian-gpo-translate` — `admx2adrian` + `preg2adrian` wrapper. Depends on `adrian-admx-compiler`, `adrian-policy-preg`, `clap`.

Layer 4 crates consume the framework as a library; they do not define new framework abstractions. The `adrian-operator` and `adrian-cli` are the primary operator surfaces; `adrian-migrate` and `adrian-gpo-translate` are the primary migration surfaces.

## 4. Key traits

The framework's trait abstractions are the API surface that makes hybrid mode (AD-interop vs native), pluggable storage (FoundationDB today, RocksDB in v2), per-platform policy executors, and cross-platform authentication viable. Five traits anchor the architecture:

**`DirectoryStore`** (Layer 0, `adrian-storage-core`) — the storage abstraction. The trait is async (`#[async_trait]`), `Send + Sync`, with methods `begin_tx() -> Box<dyn DirectoryTransaction>`, `snapshot() -> Box<dyn DirectoryStore>`, `get_read_version() -> ReadVersion`. The `DirectoryTransaction` sub-trait has `get`, `get_range`, `put`, `delete`, `atomic_op`, `commit`, `rollback`. Only one implementation ships in v1 (`FdbDirectoryStore` in `adrian-storage-fdb`); a future `RocksdbDirectoryStore` for air-gapped edge deployments is gated by v2 demand. The trait is the seam that lets the framework swap storage engines without touching the directory service, replication, or KDC.

**`Replicator`** (Layer 1, `adrian-repl-core`) — the replication abstraction. The trait is `async`, `Send + Sync`, with methods `get_changes(nc_head, cursor)`, `apply_changes(batch)`, `update_utd_vector(nc_head, delta)`, `resolve_conflict(conflict)`, `sync_metadata(partner)`. Two implementations: `DrSuapiReplicator` (AD-interop, fresh Rust MS-DRSR) and `RaftReplicator` (native, openraft). The trait operates on `ReplOperation` enum (`AddObject`, `ModifyAttribute`, `DeleteObject`, `AddLink`, `DeleteLink`, `TombstoneGC`), each carrying per-value `PropertyMetaDataExt`. Conflict resolution is highest-`version`-wins, tiebreak by latest `last_write_timestamp`, then highest `origin_usn`, then lexicographically-highest `origin_invocation_id` — matching AD's resolver.

**`IdentityMapping`** (Layer 1, `adrian-identity-core`) — the SID↔UUID mapping abstraction. Methods: `uuid_to_sid(uuid)`, `sid_to_uuid(sid)`, `uuid_to_uid(uuid)`, `uid_to_uuid(uid)`. The `FdbIdentityMapping` impl (Layer 2) stores mappings in FDB subspace `0x06`. The framework's identity model (Workshop Decision 3) is UUID-primary with SID-as-attribute; the mapping table is the bidirectional cache that makes AD-interop work. `uuid_to_uid` uses the deterministic algorithm `uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536` for greenfield deployments; migrated deployments use directory-stored UIDs (per ADR-110).

**`PolicyExecutor`** (Layer 2, `adrian-policy-executor`) — per-platform policy application. The trait has `apply(policy_doc, target_host) -> ApplyResult`, `rollback(transaction_id)`, `verify(policy_doc) -> VerifyResult`. Three implementations: `WindowsPolicyExecutor` (emits PReg `Registry.pol` + `GptTmpl.inf` + `Scripts.ini` + GPP XML + synthetic CSE JSON), `MacOsPolicyExecutor` (emits MDM Configuration Profile payloads — `com.apple.ManagedClient.preferences`, `com.apple.security.firewall`, `com.apple.passwordpolicy`, `com.apple.configuration.files`), `LinuxPolicyExecutor` (emits `authselect` profile fragments + `/etc/security/limits.conf.d/` + `/etc/audit/rules.d/` + `/etc/login.defs.d/` + `firewalld`/`nftables` + atomic `rename(2)` writes). The trait is the seam that lets one canonical JSON policy doc compile to three platform-native formats (per ADR-113).

**`AuthContext`** (Layer 1, `adrian-auth-core`) — unified authentication context. The `Principal` type carries `sid: Sid`, `upn: String`, `group_sids: Vec<Sid>` (recursive `tokenGroups` expansion), `primary_group_sid: Sid`, `privileges: Vec<Privilege>`, `logon_type: LogonType`, `logon_time: SystemTime`, `logon_server: String`, `credential_handle: CredentialHandle` (enum: `KerberosTgt`, `NtlmHash`, `Certificate`, `OAuth2Token`). The trait has `authenticate(credential) -> Principal`, `whoami() -> Principal`, `delegate(principal, target) -> CredentialHandle`, `has_privilege(principal, privilege) -> bool`. Platform adapters (`LsaAuthBackend` Windows, `GssApiAuthBackend` Linux, `PssoHeimdalAuthBackend` macOS) wrap platform-native auth; `pam_adrian.so`, `adrianlsa.dll`, `AdrianOpenDirectory.bundle` all delegate to the same Rust core (per ADR-088).

These five traits compose: `adrian-directory-service` wires `DirectoryStore` + `Replicator` + `IdentityMapping` + `SchemaProjection` into the LDAP server; `adrian-kdc` wires `DirectoryStore` + `IdentityMapping` + `SchemaProjection` + `AuthContext` into the KDC; `adrian-sdk` wires all five plus `PolicyExecutor` into the unified client API. New implementations (RocksDB storage, custom replicator, alternative policy executor) can be added without touching consumers — the trait is the contract.

## 5. Error handling

Library crates use `thiserror` for error types. Every framework crate defines its own error enum (`DirectoryError`, `ReplicationError`, `DrSuapiError`, `RaftError`, `KdcError`, `AuthError`, `PolicyError`, `SmbError`, `CertError`, `FederationError`, `SdkError`, `MigrationError`) with `#[derive(thiserror::Error)]` and `#[error("...")]` formatting on each variant. `#[from]` conversions are used for upstream errors where the conversion is unambiguous (e.g., `#[from] std::io::Error`). The error taxonomy distinguishes *transient* errors (network timeout, partner down, UTD-vector-too-old-but-recoverable, FDB transaction conflict) from *permanent* errors (schema mismatch, InvocationID mismatch, lingering object requiring admin intervention, certificate expired, ACL denied). Transient errors are retried automatically with exponential backoff (`backon` crate); permanent errors surface to the operator via the audit log and the CLI's `--verbose` flag.

Application-level crates (`adrian-cli`, `adrian-operator`, `adrian-migrate`, `adrian-policy-daemon`) use `anyhow` for top-level error handling — these crates' `main()` functions return `anyhow::Result<()>` and propagate errors with `?`. The boundary is strict: `anyhow` is permitted only in binary entry points and integration tests; library crates must use `thiserror` enums so consumers can match on variants. The `adrian-sdk` crate is the exception — it exposes `SdkError` (thiserror) to consumers because it's the public API surface. Every framework crate's error enum implements `std::error::Error + Send + Sync + 'static`; errors cross thread boundaries via `tokio::spawn` and `tokio::task::JoinHandle`. No `panic!` on the framework's hot paths; panics are reserved for invariant violations (e.g., `SchemaProjection` not loaded when KDC starts) and surface as 500-equivalent errors with a stack trace in the audit log.

## 6. Async runtime

The framework standardizes on `tokio` (`rt-multi-thread` feature, default worker count = physical CPU count, `tokio::runtime::Builder::new_multi_thread().enable_all().build()`). No `async-std`, no `smol`, no `actix-rt`. The decision is forced by dependencies: `openraft` is tokio-native, `foundationdb` is tokio-native, `rasn`'s I/O is tokio-native, `ldap3`'s server mode is tokio-native, `axum` (used by ACME server, federation shim, OCSP responder) is tokio-native, `kube` (operator) is tokio-native. A single runtime avoids inter-runtime bridging and lets the framework share one `tokio::runtime::Runtime` across all crates in a binary. The `adrian-cli` binary creates the runtime in `main()` and passes it down; the `adrian-operator` binary uses `tokio::main` macro; the `adrian-policy-daemon` binary uses `tokio::main`. The framework's FFI bindings (`adrian-sdk-c`, `adrian-sdk-jni`, `adrian-sdk-swift`, `adrian-sdk-python`) internally create a `tokio::runtime::Runtime` and call `block_on` for blocking methods, exposing both `async` (where the host language supports it) and blocking APIs.

## 7. Feature flags

The workspace defines two top-level feature flags inherited by every crate that needs them:

**`ad-interop`** (default-enabled in release builds) — enables DRSUAPI replication (`adrian-drsuapi`), MS-WCCE enrollment bridge (`adrian-wcce-bridge`), NTLM client (`adrian-ntlm-client`), ADMX compiler (`adrian-admx-compiler`), PReg adapter (`adrian-policy-preg`), RID pool allocator (`adrian-identity-ridpool`), FSMO emulation code paths in `adrian-directory-service`, ADR-006 AD-specific LDAP controls, `sIDHistory` migration tooling in `adrian-migrate`. Without `ad-interop`, the framework builds in native-only mode: Raft replication only, ACME-only enrollment, no NTLM (neither server nor client), declarative JSON policy authoring only (no ADMX/PReg), no FSMO emulation (all 5 roles eliminated per ADR-076), no `sIDHistory` migration tooling. Native-only builds are ~15% smaller (DRSUAPI and MS-WCCE are ~30K lines combined) and suitable for greenfield deployments that will never peer with AD.

**`enterprise-hsm`** (default-disabled) — enables HSM-bound key paths in `adrian-hsm` (PKCS#11 via `cryptoki`, CNG KSP via `windows`), `adrian-kdc` (krbtgt HSM binding per ADR-015), `adrian-ca` (CA key HSM binding per ADR-037), `adrian-pac-validator` (Ed25519 krbtgt public key verification per ADR-083). Without `enterprise-hsm`, the framework uses software keys (ring crate) for krbtgt, CA, and PAC validation — suitable for development and small deployments. The `enterprise-hsm` feature is opt-in because PKCS#11 requires runtime library loading (`cryptoki` loads `libsofthsm2.so` or vendor PKCS#11 module at runtime) and CNG is Windows-only — making the feature default-on would force every framework deployment to ship a PKCS#11 module.

Per-crate features are minimal: most crates have only `default` and `ad-interop`. The `adrian-kdc` crate has additional features for `pkinit-smartcard` (RFC 4556, requires `x509-cert`) and `pkinit-fido2` (vendor padata 0xAB, requires `webauthn-rs`). The `adrian-sdk` crate has features per platform binding (`c-abi`, `jni`, `swift`, `python`) that gate the FFI export layer. The `adrian-policy-executor` crate has features per platform (`windows`, `macos`, `linux`) that gate the per-platform `PolicyExecutor` implementation — Linux deployments don't need to compile the macOS executor.

## 8. Testing strategy

The framework uses four test layers:

**Unit tests** — every crate has `#[cfg(test)] mod tests` in each source file, covering the crate's public and `pub(crate)` API. Unit tests run in `cargo test` without external dependencies (no FDB cluster, no KDC, no LDAP server) — they use mock implementations of `DirectoryStore`, `Replicator`, `IdentityMapping` from `adrian-test-harness`. Target: ≥80% line coverage per crate, enforced by `cargo-tarpaulin` in CI. Unit tests run in <60 seconds for the entire workspace (parallelized across crates).

**Integration tests** — in `tests/integration/`, these tests exercise multiple crates together against real (not mocked) FDB and tokio. A typical integration test spins up an in-process FDB cluster (via the `foundationdb` crate's test-utils), an `adrian-directory-service` instance, and an LDAP client (`ldap3`) that performs a bind + search + modify + delete sequence. Integration tests run in `cargo test --test '*'` and take ~10 minutes for the full suite. Each integration test is tagged with its required capabilities (`#[ignore]` if it needs `ad-interop` or `enterprise-hsm` features) so CI can run subsets in parallel.

**Interop tests** — in `tests/interop/`, these tests validate wire-compatibility against real AD and third-party implementations. The interop test matrix includes: Windows Server 2022 (AD DS, AD CS, AD FS) running in an isolated VM, MIT krb5 1.21 (kinit/klist/kadmin client against framework KDC), Samba 4.20 (smbclient and `samba-tool drs` against framework DC), OpenLDAP client (ldapsearch/ldapmodify against framework LDAP server), and FreeIPA 4.10 (cross-realm trust establishment). Interop tests run in a separate CI pipeline (`interop-tests.yml`) triggered on `main` commits and release tags; they require Docker Compose for the third-party services and take ~2 hours for the full matrix. The PAC byte-identity test (per ADR-082) is the highest-signal interop test — it captures a Windows-issued PAC and a framework-issued PAC for the same input principal and verifies byte-identity modulo two documented divergences (LogonServer name, PAC_REQUESTOR machine SID format).

**Property-based tests** — using `proptest`, the framework tests protocol parsers (SID, PAC, SMB, DRSUAPI `REPLVALINF_V3`, X.509, ACME JWS) for round-trip correctness: generate a random valid input, serialize, parse, assert equality. Property tests run in `cargo test` and are particularly valuable for the `rasn`-based parsers where a bug in NDR encoding could silently corrupt replication. Each parser crate has ≥10 property tests; the framework's proptest corpus has ~500 property tests total.

The framework's test coverage target is 80% line coverage for unit + integration tests combined, with interop tests gating releases (not PRs). The CI pipeline runs `cargo test` on every PR (unit + integration subset), `cargo test --all-features` on `main` commits (full integration suite), and `cargo test --test interop` on release tags (full interop matrix).

## 9. CI/CD

The framework uses GitHub Actions with the following pipeline on every PR:

- **`cargo fmt --check`** — formatting check, fails the PR if `cargo fmt` would change any file.
- **`cargo clippy -- -D warnings`** — lint check, fails the PR on any clippy warning. The workspace's `clippy.toml` sets `cognitive-complexity = 50`, `too-many-arguments-threshold = 10`, `type-complexity-threshold = 250` — strict but not pedantic.
- **`cargo test`** — unit + integration tests across the workspace. Runs in a matrix: Ubuntu 22.04, macOS 13, Windows Server 2022; Rust stable and Rust beta. The matrix catches platform-specific regressions (e.g., `windows` crate API differences, `objc2` macOS-only compilation, `tokio` runtime behavior differences).
- **`cargo doc --no-deps`** — documentation build, fails on broken intra-doc links. The workspace's `rustdoc.toml` enables `#[warn(missing_docs)]` — every public item must have a doc comment.
- **`cargo deny check`** — `cargo-deny` checks for license compliance (rejects GPLv3, AGPLv3; permits MIT, Apache-2.0, BSD-2/3, MPL-2.0), security advisories (RUSTSEC), and duplicate dependency versions.
- **`adrian-check-layers`** — custom script that reads each crate's `Cargo.toml` and rejects cross-layer dependency violations (e.g., `adrian-storage-core` depending on `adrian-kdc`).
- **`cargo-tarpaulin`** — coverage measurement, fails if any crate's line coverage drops below 80% compared to the `main` branch baseline.

On `main` commits, the pipeline adds `cargo test --all-features` (full integration suite, ~10 minutes), `cargo build --release` (release binary size regression check), and the interop test matrix (`tests/interop/`, ~2 hours, gated on the integration suite passing).

Release builds use `cargo-dist` (the `axodotdev/cargo-dist` action) for cross-platform binary distribution. `cargo-dist` produces static musl Linux binaries (x86_64 and aarch64), macOS universal binaries (x86_64 + aarch64), and Windows MSVC binaries (x86_64). Each release artifact is signed via `cosign sign --key <kms>` (per ADR-067) with the framework's Sigstore key in a KMS-backed store; build provenance is recorded via in-toto attestations. The release pipeline publishes to GitHub Releases, crates.io (`adrian-sdk`, `adrian-cli`, `adrian-operator` — the user-facing crates), and the framework's Helm chart registry (`adrian-operator` chart for Kubernetes deployment). Container images (`adrian-dc`, `adrian-keycloak-shim`, `adrian-acme-server`, `adrian-smb-server`) are published to `ghcr.io/adrian-framework/` with multi-arch manifests (linux/amd64, linux/arm64) and signed via `cosign sign` with the same Sigstore key.

The framework's release cadence is quarterly minor releases (1.0 → 1.1 → 1.2 → ...) with patch releases as needed for security fixes. The release branch (`release/1.x`) is created from `main` at minor release; security patches are backported to the two most recent minor releases (N and N-1). The framework's deprecation policy is: features are deprecated in minor release N, removed in minor release N+2 (minimum 6 months). The `ad-interop` feature flag is permanent — the framework will support AD-interop mode for the foreseeable future (it's the v1 customer base), with native-only mode as the recommended default for greenfield deployments starting in v2.
