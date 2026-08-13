---
title: "Workshop Decision 11 — Client SDK: unified Rust core + platform-specific bindings (resolves ORQ-169/170/175/176)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Client SDK
orqs_resolved: [ORQ-169, ORQ-170, ORQ-175, ORQ-176]
gates: [PC-040, PC-085, PC-086, PC-091, PC-095, PC-100, PC-115]
tags: [workshop, decision, client-sdk, rust, ffi, c-abi, jni, pyo3, swift-bridge, sssd, freeipa]
related:
  - ./CONTEXT.md
  - ../adr/TRIAGE.md
  - ../adr/ADR-049-standardize-mit-krb5.md
  - ../adr/ADR-051-kcm-linux-api-macos-cache-abstraction.md
  - ../adr/ADR-054-per-host-laps-rotation.md
  - ../adr/ADR-056-psso-modern-macos-kerberos-path.md
  - ../adr/ADR-058-container-native-dcs-operator.md
  - ../adr/ADR-063-unified-cross-platform-cli.md
  - ../catalog/08-client-sdk.md
last_updated: 2026-08-14
---

# Workshop Decision 11 — Client SDK: unified Rust core + platform-specific bindings

## Status

Accepted — 2026-08-14. Tier-1 (architectural) decision made at the Day 2 late-afternoon session of the Tier-1 ORQ Resolution Workshop. Resolves ORQ-169 (gRPC-based SDK with platform-native auth adapters), ORQ-170 (per-language bindings with Rust core), ORQ-175 (extend SSSD or write a new client), and ORQ-176 (adopt FreeIPA client as the base). Supersedes the open SDK-architecture questions in ADR-049 (MIT krb5 standardization), ADR-051 (KCM Linux API + macOS cache abstraction), and ADR-063 (unified cross-platform CLI).

## ORQs resolved

- **ORQ-169** — "Adopt gRPC-based SDK with platform-native auth adapters?" → **No, but with nuance.** The framework's SDK is a Rust core library with platform-specific bindings (C ABI, JNI, Swift bridge, Python via pyo3), not a gRPC-based SDK. gRPC adds a network hop and a protobuf schema that is unnecessary for an in-process SDK; the framework's auth-directory-policy-cert-file-federation operations are all in-process and benefit from direct Rust calls. The framework does ship a gRPC API (per [ADR-061](../adr/ADR-061-rest-grpc-api.md)) for *remote* administration (operators running CLI tools against a remote DC), but the *client SDK* (which runs on every enrolled host) is not gRPC-based.
- **ORQ-170** — "Per-language bindings (Rust core)?" → **Yes.** The framework's SDK is `adrian-sdk`, a Rust core library with platform-specific bindings: C ABI (for Windows C/C++/C# clients, macOS Objective-C clients, and Linux C/C++ clients), JNI (for Java/Kotlin/Android clients), Swift bridge (for macOS/iOS native Swift clients), Python via `pyo3` (for Python automation and Ansible collection), and Go via `cgō` (for Kubernetes operator and Go-based automation). The Rust core is the single source of truth; bindings are thin FFI wrappers.
- **ORQ-175** — "Extend SSSD or write a new client?" → **Write a new client, with SSSD integration where SSSD is the platform-native path (per Decision 12).** The framework's Client SDK is the new client; on Linux, the SDK's PAM/NSS provider integrates with SSSD's `proxy` or `infopipe` mechanism so that SSSD-Consuming Linux software (everything using `getpwnam`, `pam_authenticate`, etc.) sees the framework's directory without SSSD itself being a framework component.
- **ORQ-176** — "Adopt FreeIPA client as the base?" → **No.** FreeIPA's client is a Python-and-C-based toolset tightly coupled to FreeIPA's directory schema and Dogtag CA. Adopting it would import FreeIPA's coupling and its Python dependency. The framework's Client SDK is Rust-native, with FreeIPA supported as an optional alternative Linux tier (per Decision 12), not as the SDK base.

## Decision

The framework's Client SDK is a **unified Rust core library (`adrian-sdk`) with platform-specific bindings**. The core library handles authentication (Kerberos, NTLM fallback), directory (LDAP queries, attribute reads), policy (load, evaluate, apply, rollback per Decision 7), cert enrollment (ACME per Decision 8), file (SMB client for SYSVOL access), and federation (token validation, refresh). Platform bindings expose the Rust core to platform-native consumers via FFI.

### Concrete specification

1. **Rust core library (`adrian-sdk`).** The core is a Rust workspace member, distributed as a Rust crate (`adrian-sdk = "1.0"` on crates.io for Linux/macOS Rust consumers) and as a pre-built static/dynamic library for FFI consumers. The core's public API is:
   ```rust
   pub struct AdrianClient { /* ... */ }
   impl AdrianClient {
       pub fn new(config: ClientConfig) -> Result<Self, ClientError>;
       pub fn auth(&self) -> &AuthModule;       // Kerberos, NTLM, password
       pub fn directory(&self) -> &DirectoryModule;  // LDAP queries, attribute reads
       pub fn policy(&self) -> &PolicyModule;   // load, evaluate, apply, rollback
       pub fn cert(&self) -> &CertModule;       // ACME enrollment, key store
       pub fn file(&self) -> &FileModule;       // SMB client for SYSVOL
       pub fn federation(&self) -> &FederationModule;  // token validation, refresh
   }
   ```
   Each module is an `&'a` reference into the `AdrianClient` (zero-cost; the modules share the underlying connection pool, credential cache, and config). The core uses `tokio = "1"` for async I/O; the public API exposes both `async` methods (for Rust consumers) and blocking methods (for FFI consumers, which typically cannot run a `tokio` runtime). The blocking methods internally use `tokio::runtime::Runtime::block_on`.

2. **C ABI binding (`adrian-sdk-c`).** A C header (`adrian.h`) and a static/dynamic library (`libadrian_sdk.a` / `.so` / `.dylib` / `.dll`). The C ABI uses opaque pointers (`AdrianClient*`, `AdrianAuth*`, etc.) and `int32_t adrian_<module>_<method>(Adrian<Client|Module>* self, ...)` function signatures. Errors are returned as `int32_t` codes; error messages are retrieved via `adrian_error_message(int32_t code, char* buf, size_t len)`. Strings are returned as `const char*` (NUL-terminated UTF-8) owned by the library, valid until the next call to the same module (the caller must copy if longer lifetime is needed). The C ABI is the foundation for all other bindings (JNI, Swift, Python, Go all use the C ABI).

3. **JNI binding (`adrian-sdk-java`).** A Java JAR (`adrian-sdk-java-1.0.jar`) and a JNI native library (`libadrian_sdk_java.so` / `.dylib` / `.dll`). The JAR exposes Java classes (`com.adrian.sdk.AdrianClient`, `com.adrian.sdk.auth.AuthModule`, etc.) with native methods implemented in the JNI library. The JNI library is a thin wrapper over the C ABI; it converts Java types to C types and back, handles Java exceptions, and manages the JVM's reference to the underlying Rust `AdrianClient`. The JAR also includes a Kotlin-friendly API (`suspend` functions for async methods) for Android consumers.

4. **Swift bridge (`adrian-sdk-swift`).** A Swift package (`AdrianSDK`, distributed via Swift Package Manager) that wraps the C ABI. The Swift bridge uses `swift-bridge = "0.2"` to auto-generate Swift types from Rust types where possible; for complex types (e.g., `tokio`'s `Handle`), the bridge provides manual Swift wrappers. The Swift package exposes `AdrianClient`, `AuthModule`, etc. as Swift classes with async methods (`async throws`); the framework's macOS/iOS native consumers use these directly. The Swift bridge is the foundation for the framework's macOS PSSO Extension (per [ADR-056](../adr/ADR-056-psso-modern-macos-kerberos-path.md)) and the framework's iOS app (planned for v1.1).

5. **Python binding (`adrian-sdk-python`).** A Python package (`adrian-sdk`, distributed via PyPI) generated by `pyo3 = "0.21"`. The Python package exposes Python classes (`adrian.Client`, `adrian.AuthModule`, etc.) with Pythonic APIs (snake_case, exceptions for errors, context managers for resource cleanup). The Python binding is the foundation for the framework's Ansible collection (`community.adrian`, distributed via Ansible Galaxy), which provides Ansible modules for framework administration (`adrian_user`, `adrian_group`, `adrian_policy`, `adrian_cert`, etc.).

6. **Go binding (`adrian-sdk-go`).** A Go module (`github.com/adrian/sdk-go`) generated by `cgo` against the C ABI. The Go module exposes Go types (`adrian.Client`, `adrian.AuthModule`, etc.) with idiomatic Go APIs (contexts, errors, goroutines for async). The Go binding is the foundation for the framework's Kubernetes operator (per ADR-058) and the framework's Terraform provider (`adrian/adrian`, distributed via the Terraform Registry).

7. **Platform-native integrations.** The Rust core integrates with platform-native libraries via FFI:
   - **Windows**: `windows = "0.54"` for Win32 APIs (`LsaConnectUntrusted`, `LogonUser`, `AcquireCredentialsHandle`, `InitializeSecurityContext` for Kerberos/NTLM auth; `Wldap32` for LDAP; `Crypt32` / `NCrypt` for cert and key store; `WinHttp` for HTTPS).
   - **macOS**: `core-foundation = "0.10"` and `objc2 = "0.5"` for macOS frameworks (`Kerberos.framework`, `OpenDirectory.framework`, `Security.framework` for keychain, `CFNetwork` for HTTPS). The macOS integration uses the system Heimdal (per [ADR-049](../adr/ADR-049-standardize-mit-krb5.md)) for PSSO Extension compatibility; framework-application Kerberos uses MIT krb5 installed at `/opt/adrian/lib/mit-krb5/`.
   - **Linux**: `gss-api = "0.1"` (via `libgssapi_krb5`), `ldap3 = "0.11"` (pure-Rust LDAP client), `systemd = "0.10"` (for systemd-journald logging and `notify`), `rustls = "0.23"` for HTTPS.

8. **PAM/NSS provider.** On Linux, the SDK ships a PAM module (`pam_adrian.so`) and an NSS module (`nss_adrian.so.2`) that integrate with the system PAM/NSS stack. The PAM module implements `pam_sm_authenticate`, `pam_sm_acct_mgmt`, `pam_sm_chauthtok`, `pam_sm_session_mgmt`, delegating to the Rust core's `AuthModule`. The NSS module implements `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid`, `getspnam`, delegating to the Rust core's `DirectoryModule`. The PAM/NSS modules are loaded via `/etc/pam.d/` and `/etc/nsswitch.conf` configured by `authselect` (per [ADR-050](../adr/ADR-050-authselect-standard-pam.md)).

   On macOS, the SDK ships an OpenDirectory plugin (`AdrianOpenDirectory.bundle`) that integrates with the system OpenDirectory framework, exposing framework-directory users and groups to macOS-native software (`dscl`, `id`, `groups`, loginwindow). The OpenDirectory plugin uses the Rust core via the C ABI.

   On Windows, the SDK ships an LSA Authentication Package (`adrianlsa.dll`) and a Credential Provider (`AdrianCredentialProvider.dll`) that integrate with the Windows logon stack. The LSA Authentication Package delegates to the Rust core's `AuthModule`; the Credential Provider renders the framework's logon UI (for password+MFA logon).

9. **Domain join.** The SDK's `AdrianClient::join_domain(domain, admin_creds)` method performs the domain-join operation: generates a machine keypair (in TPM2 on Windows/Linux, in Secure Enclave on macOS), creates the host object in the framework's directory via LDAP, registers the SPN (`host/<fqdn>`, `cifs/<fqdn>`, `HTTP/<fqdn>`, `ldap/<fqdn>`), writes the machine key to the platform-native key store (Windows LSA, macOS Keychain, Linux `/etc/krb5.keytab`), and triggers the initial policy pull. The SDK exposes this via the `adrian-cli join` command (per [ADR-063](../adr/ADR-063-unified-cross-platform-cli.md)).

10. **Policy enforcement.** The SDK's `PolicyModule` runs the framework's policy daemon (`adrian-policy-daemon` per Decision 7) on every enrolled host. The daemon receives policy updates via WebSocket push (per ADR-028), evaluates the CEL selector against the host's facts (per ADR-026), and dispatches each `PolicyArea` to the registered `PolicyExecutor` (per Decision 7's public plugin trait). The executors run with the daemon's privileges (SYSTEM on Windows, root on Linux, root on macOS via launchd).

11. **Cert enrollment.** The SDK's `CertModule` runs the framework's cert enrollment agent on every enrolled host. The agent reads the host's cert profile assignments from the directory, runs an ACME client against the framework's CA (per Decision 8), fulfills the `adrian-attest-01` challenge via TPM2 quote (Windows/Linux) or Apple Secure Enclave attestation (macOS), stores the issued cert and private key in the platform-native key store (Windows CNG KSP, macOS Keychain, Linux `systemd`-managed keyring or `/etc/adrian/keys/`), and re-enrolls at 2/3 of validity (per RFC 8823 ARI). The agent runs as a Windows Service / launchd daemon / systemd service.

12. **File access.** The SDK's `FileModule` provides an SMB client (using `pavao = "0.10"` or the framework's own SMB client implementation, depending on `pavao`'s maturity) for accessing `\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\`. The client uses the host's machine Kerberos ticket (acquired via the SDK's `AuthModule`) for authentication. The `FileModule` is read-only for the SYSVOL share (policy distribution is read-only on the client side); read-write for shares the host is authorized to write to (e.g., user home shares).

13. **Federation.** The SDK's `FederationModule` provides OIDC token validation (via `openidconnect = "3"`), SAML assertion validation (via `saml2 = "0.20"`), and token refresh for client-side RPs that need to validate framework-issued tokens. The module is used by the framework's own federation-aware services (e.g., the framework's REST API per ADR-061) and by customer RPs that link against the SDK.

14. **Per-host LAPS rotation.** The SDK's `AuthModule` rotates the host's LAPS-equivalent local-admin password per [ADR-054](../adr/ADR-054-per-host-laps-rotation.md). The rotation generates a new random password, writes it to the host's local-admin account, and writes the new password hash to the framework's directory. The rotation runs on a schedule (default 30 days) via the SDK's daemon.

## Rationale

Three candidate architectures were considered.

**Candidate A: gRPC-based SDK with platform-native auth adapters.** A gRPC server runs on each enrolled host; platform-native clients (LSA, PAM, NSS, MDM) call the gRPC server via platform-native adapters. Rejected because (a) gRPC adds a network hop (localhost TCP) and a protobuf schema layer that is unnecessary for in-process operations — every `getpwnam` call would incur a localhost TCP round-trip and protobuf marshal/unmarshal, adding 100-500 µs per call; for NSS-heavy workloads (e.g., `find /` walks `getpwuid` for every file), this is unacceptable. (b) gRPC's `tokio` runtime conflicts with the platform's existing runtime (Windows SCM, macOS launchd, Linux systemd) — the gRPC server becomes another process to supervise, another port to firewall, another log file to rotate. (c) The platform-native auth adapters still need to be written (LSA on Windows, PAM/NSS on Linux, OpenDirectory on macOS) — the gRPC server does not eliminate the platform-native work; it adds an extra layer. (d) gRPC's binary footprint (`grpc-rs` + `protobuf` + `tokio` + `h2` + `tonic` + their transitive deps) is ~15MB, which is excessive for an embedded SDK. The Rust core + C ABI is ~5MB.

**Candidate B: Extend SSSD as the Linux client; wrap platform-native (LSA, OpenDirectory) on Windows/macOS.** Use SSSD's `proxy` provider to delegate to the framework's directory on Linux; use Windows LSA on Windows; use macOS OpenDirectory on macOS. Each platform's client is platform-native. Rejected because (a) SSSD is C, tightly coupled to its own internal architecture (the `data provider` abstraction, the `be_ptask` scheduler, the `responder` IPC), and extending it to support the framework's policy/cert/federation modules requires either (i) extending SSSD with new responders (which the SSSD upstream may not accept) or (ii) running the framework's modules as a separate daemon alongside SSSD (which duplicates the host's identity surface and risks SSSD-vs-framework drift). (b) SSSD's policy support (the `ad_gpo.c` Security CSE subset) does not extend to the framework's full PolicyArea enum (per Decision 7); SSSD would need significant rework to support the framework's policy executor trait. (c) Windows LSA and macOS OpenDirectory are platform-specific and do not provide a unified API; the framework would need three separate codebases for Windows, macOS, and Linux, defeating the cross-platform-parity goal. (d) SSSD's release cadence is controlled by the upstream SSSD project (Red Hat / SUSE), not by the framework; the framework cannot ship SDK fixes without waiting for the next SSSD release. The framework's SDK is Rust-native and ships on the framework's release cadence.

**Candidate C: Adopt FreeIPA client as the base on Linux; wrap platform-native on Windows/macOS.** FreeIPA's client is `ipa-client-install` (Python) + `sssd` (C) + `certmonger` (C). Adopting it as the base means inheriting FreeIPA's directory-schema coupling (the `ipa*` object classes, the `ipaConfigString` attribute, the `cn=etc,<suffix>` configuration container) and FreeIPA's Dogtag CA coupling. Rejected because (a) the framework's directory schema is its own (per Day 1 schema decision), not FreeIPA's; inheriting FreeIPA's schema coupling would force the framework to maintain FreeIPA-specific schema elements in its own directory. (b) FreeIPA's client is Python, requiring a Python interpreter on every Linux host; for embedded / minimal Linux deployments (containers, IoT), this is a non-starter. (c) FreeIPA's `certmonger` is a separate CA-enrollment daemon with its own state machine; the framework's cert enrollment (ACME per Decision 8) is incompatible with `certmonger`'s MS-WCCE-only model. (d) FreeIPA's client does not support Windows or macOS at all, so the framework would still need separate Windows and macOS clients — same three-codebase problem as Candidate B.

The chosen Rust-core-with-bindings model gives the framework: (a) a single source of truth (the Rust core) for all platform behavior, eliminating cross-platform drift; (b) platform-native integration via FFI (LSA, PAM/NSS, OpenDirectory, Kerberos, key stores) where platform-native is required; (c) cross-language support via the C ABI foundation (every language with FFI can call the framework's SDK); (d) memory safety (Rust for the protocol-parsing and credential-handling code); (e) the framework's release cadence (no dependency on upstream SSSD or FreeIPA release cycles). The Rust core's binary footprint (~5MB) is acceptable for modern hosts; the SDK is built once per platform and distributed via the framework's package repositories (MSI on Windows, pkg on macOS, deb/rpm on Linux).

## Trade-offs accepted

- **Rust knowledge required for SDK contributors.** The SDK's core is Rust; contributors must know Rust. The bindings (C ABI, JNI, Swift, Python, Go) are thinner and have lower contribution friction. Acceptable because Rust is increasingly widely-known and the framework's documentation includes a "contributing to the SDK core" guide.
- **No SSSD reuse on Linux.** The framework's PAM/NSS provider is `pam_adrian.so` + `nss_adrian.so.2`, not SSSD. Linux distributions that ship SSSD by default (RHEL, Ubuntu, SUSE) will see the framework's PAM/NSS provider alongside SSSD; operators must disable SSSD's `ad` provider (or use SSSD's `proxy` provider pointing at the framework's NSS module) to avoid double-resolution. The framework's installer handles this via `authselect` (per ADR-050). Acceptable because the framework's NSS module is faster than SSSD's (no `data provider` IPC, no `be_ptask` scheduler, direct LDAP queries from the NSS module).
- **No FreeIPA client reuse on Linux.** FreeIPA users cannot use `ipa-client-install` against the framework; they must use the framework's `adrian-cli join`. FreeIPA-specific tooling (`ipa user-add`, `ipa group-add`) does not work against the framework. Acceptable because FreeIPA is supported as an alternative Linux tier (per Decision 12), not as the SDK base; customers who choose FreeIPA-as-Linux-tier use FreeIPA's own client tooling on FreeIPA-managed hosts.
- **macOS PSSO Extension requires the Swift bridge.** The macOS PSSO Extension (per [ADR-056](../adr/ADR-056-psso-modern-macos-kerberos-path.md)) is written in Swift and uses the SDK's Swift bridge. PSSO Extension bugs may require debugging across the Swift-Rust FFI boundary. Acceptable because PSSO Extension is a macOS-native component (Apple's SSO Kerberos extension) and Swift is its natural implementation language; the Swift bridge provides the Rust core's functionality without forcing PSSO to be Rust-native.
- **JNI native library per platform.** Java consumers must ship the JNI native library (`libadrian_sdk_java.so` / `.dylib` / `.dll`) for their target platform. This is standard JNI practice but adds packaging complexity for Java apps that target multiple platforms. Acceptable because the framework's Maven package (`com.adrian:adrian-sdk-java`) includes native libraries for all supported platforms (Linux x86_64/aarch64, macOS x86_64/arm64, Windows x86_64), auto-selected via `os.detected.classifier`.
- **Go binding via cgo has runtime overhead.** cgo calls are slower than pure-Go calls (~50 ns per call) and break Go's escape analysis. The framework's Go binding is intended for the Kubernetes operator and Terraform provider, where the per-call overhead is negligible compared to the underlying network I/O. Acceptable for the intended use case; pure-Go consumers who need max performance should use the framework's gRPC API (per ADR-061) instead.

## Rust implementation implications

The decision is implementable in pure Rust for the core; bindings are FFI layers. The crate graph:

- **`adrian-sdk`** (workspace member, library) — the Rust core. Crates: `tokio`, `serde`, `serde_json`, `ldap3 = "0.11"` (pure-Rust LDAP), `gss-api = "0.1"` (Kerberos via MIT krb5), `pavao = "0.10"` (SMB client), `rustls = "0.23"`, `reqwest`, `openidconnect = "3"`, `saml2 = "0.20"`, `x509-cert`, `tokio-tungstenite` (WebSocket for policy push per ADR-028), `tracing`, `thiserror`. The core exposes both async and blocking APIs; the blocking APIs internally use `tokio::runtime::Runtime::block_on`.
- **`adrian-sdk-c`** (workspace member, `cdylib` + `staticlib`) — the C ABI binding. Crates: `cbindgen = "0.26"` (auto-generates `adrian.h`). The C ABI is hand-rolled where `cbindgen` cannot auto-generate; ~1K lines of Rust.
- **`adrian-sdk-java`** (workspace member, `cdylib`) — the JNI binding. Crates: `jni = "0.21"`. ~2K lines of Rust mapping Java types to C ABI calls. The Java JAR is built with Maven from generated Java sources.
- **`adrian-sdk-swift`** (workspace member, `cdylib` + `staticlib`) — the Swift bridge. Crates: `swift-bridge = "0.2"`. ~500 lines of Rust config plus auto-generated Swift.
- **`adrian-sdk-python`** (workspace member, `cdylib`) — the Python binding. Crates: `pyo3 = "0.21"`, built with `maturin = "1"`. ~1.5K lines of Rust.
- **`adrian-sdk-go`** (workspace member, `cdylib` + `staticlib`) — the Go binding via `cgo` against the C ABI; ~800 lines of Go wrappers.
- **`pam_adrian`** (workspace member, `cdylib`) — the PAM module. Crates: `pam-bindings = "0.1"`. ~600 lines of Rust implementing `pam_sm_authenticate` etc.
- **`nss_adrian`** (workspace member, `cdylib`) — the NSS module. Crates: `libc = "0.2"`. ~1.2K lines of Rust implementing `getpwnam` etc. via `extern "C"`. Loaded via `/etc/nsswitch.conf` (`passwd: files adrian`).
- **`adrian-lsa`** (workspace member, `cdylib` for Windows) — the Windows LSA Authentication Package. Crates: `windows = "0.54"`. ~1.5K lines of Rust implementing `LsaApInitializePackage`, `LsaApLogonUser`, etc. Compiled only on Windows.
- **`adrian-credential-provider`** (workspace member, `cdylib` for Windows) — the Windows Credential Provider. ~1K lines of C++ (COM-based API) with auth logic delegated to the Rust core via the C ABI.
- **`adrian-opendirectory`** (workspace member, `cdylib` for macOS) — the macOS OpenDirectory plugin. Crates: `objc2 = "0.5"`, `core-foundation = "0.10"`. ~1.2K lines of Rust + Objective-C glue. Compiled only on macOS.
- **`adrian-policy-daemon`** (workspace member, binary) — the policy daemon (per Decision 7). Uses `adrian-sdk` for directory and policy retrieval.
- **`adrian-cert-agent`** (workspace member, binary) — the cert enrollment agent (per Decision 8). Uses `adrian-sdk` and `adrian-attest`.
- **`adrian-cli`** (workspace member, binary) — the unified CLI (per ADR-063). Subcommands: `join`, `unjoin`, `status`, `policy`, `cert`, `auth`, `directory`, `file`, `federation`.

The Rust core's `AdrianClient::new(config)` constructs the client with a `ClientConfig` specifying the framework's directory host, KDC host, CA host, federation host, SMB share, and the host's identity. The config is loaded from `/etc/adrian/client.conf` (Linux), `C:\Program Files\Adrian\client.conf` (Windows), or `/Library/Adrian/client.conf` (macOS); generated by `adrian-cli join` during domain join.

The SDK's container image (per ADR-058) is built on `ubuntu:22.04` (Linux), `mcr.microsoft.com/windows/servercore:ltsc2022` (Windows), or installed via pkg on macOS. Binaries are signed (per [ADR-067](../adr/ADR-067-sigstore-supply-chain.md)) and notarized on macOS.

Estimated effort: ~30 person-weeks for v1. Breakdown: Rust core (8 pw), C ABI + cbindgen (2 pw), JNI + Java codegen (3 pw), Swift bridge (2 pw), Python + Ansible (3 pw), Go + Terraform (2 pw), PAM/NSS (2 pw), Windows LSA + Credential Provider (4 pw, highest-risk), macOS OpenDirectory (2 pw), `adrian-cli` (2 pw). The Windows LSA is the critical-path item (LSA Authentication Package is a complex API with strict timing requirements; bugs can prevent Windows logon).

## Problems unblocked

| Problem | Capability | Severity | Gating ORQ before | Status after |
|---------|-----------|----------|---------------------|--------------|
| PC-085 — No universal AD client SDK | Client SDK | blocker | ORQ-169/170/175/176 | Unblocked — `adrian-sdk` Rust core + C ABI / JNI / Swift / Python / Go bindings provide a universal SDK across all five platforms |
| PC-086 — macOS PSSO Extension Apple-only | Client SDK | high | ORQ-169/170/175/176 | Unblocked — Swift bridge provides Rust core to PSSO Extension (per ADR-056) |
| PC-088 — SSSD on Linux GPO gaps | Client SDK | high | ORQ-202/203 (Linux tier, Decision 12) | Unblocked by this decision — `pam_adrian` + `nss_adrian` provide framework-native PAM/NSS that bypasses SSSD's gaps; SSSD-as-Linux-tier (Decision 12) is supported via SSSD's `proxy` provider |
| PC-091 — Domain join fragmented | Client SDK | medium | ORQ-169/170/175/176 | Unblocked — `adrian-cli join` provides a unified domain-join API across all platforms |
| PC-095 — No unified policy authoring | Cross-Platform Parity | blocker | ORQ-030/031 (Day 1) + ORQ-169/170/175/176 (this decision) + ORQ-090/091 (Decision 7) | Unblocked — `adrian-sdk` `PolicyModule` consumes canonical JSON policy; authoring UI emits canonical JSON; cross-platform compilation per Decision 7 |
| PC-100 — macOS OpenDirectory AD plug-in gaps | Cross-Platform Parity | medium | ORQ-169/170/175/176 | Unblocked — `adrian-opendirectory` plugin replaces the AD plug-in with framework-native OpenDirectory integration |
| PC-115 — dcdiag/repadmin/ntdsutil Windows-only | Operations | medium | ORQ-231/232 (Tier-3, language) + ORQ-169/170/175/176 (this decision) | Unblocked for SDK architecture — `adrian-cli` provides the unified CLI per ADR-063; implementation language is Rust (resolves the language question raised in ADR-063 PARTIAL) |
| PC-040 — Windows Token vs Linux PAM stack | Auth Provider | high | ORQ-169/170/175/176 (this decision) + ORQ-202/203 (Decision 12) | Unblocked — `adrian-sdk` `AuthModule` provides a unified auth abstraction over Windows LSA / Linux PAM / macOS OpenDirectory |

## Implementation impact

The decision locks the Client SDK's v1 architecture. The Rust core's public API is stable for v1 (semver guarantee). The C ABI is stable for v1 (no breaking changes to function signatures or struct layouts); subsequent versions add new functions and fields without removing existing ones. The bindings' public APIs (Java, Swift, Python, Go) are stable for v1.

The Windows LSA Authentication Package is the highest-risk item. The LSA package is loaded into `lsass.exe`; bugs can crash `lsass.exe`, forcing a Windows reboot. The framework's CI runs the LSA package in a Windows Server 2022 VM with `lsass.exe` crash detection.

The macOS OpenDirectory plugin is the second-highest-risk item (bugs can prevent macOS logon). The framework's CI runs the plugin in a macOS 14 VM with `opendirectoryd` crash detection, tested with `dscl` queries and `loginwindow` logon.

The PAM/NSS modules on Linux are well-understood; the implementation risk is lower than Windows LSA or macOS OpenDirectory. The modules are tested in CI against `authselect`'s test suite and against real `login` / `su` / `ssh` invocations.

The Python binding's Ansible collection is the migration-critical path for customers with existing Ansible automation. The collection's modules (`adrian_user`, `adrian_group`, `adrian_policy`) provide the same idioms as Ansible's built-in modules, making migration straightforward.

## Cross-capability dependencies

- **Core Directory.** The SDK's `DirectoryModule` queries the directory via LDAP (`ldap3` crate). The directory's `memberOf` back-link (per ADR-002) is used for group-membership resolution.
- **KDC.** The SDK's `AuthModule` acquires Kerberos tickets via MIT krb5 (per ADR-049) and uses the unified PAC validator for PAC validation.
- **Auth Provider.** The SDK's `AuthModule` delegates password validation to the Auth Provider via LDAP simple bind.
- **Policy Engine (Decision 7).** The SDK's `PolicyModule` is the host-side policy daemon, loading `adrian-policy-executor` and dispatching policy areas to registered executors.
- **Cert Service (Decision 8).** The SDK's `CertModule` is the host-side cert enrollment agent, using `adrian-attest` for TPM2/Secure Enclave attestation.
- **File Gateway (Decision 10).** The SDK's `FileModule` is the host-side SMB client, accessing `\\<domain>\SYSVOL\` for policy distribution.
- **Federation Gateway (Decision 9).** The SDK's `FederationModule` validates framework-issued OIDC and SAML tokens for client-side RPs.
- **Operations (ADR-058).** The SDK runs as a StatefulSet sidecar in container-native deployments; the SDK's container image is the same across all platforms.
- **Migration (PC-127).** The `adrian-cli join` command is the migration entry point. Customers with existing `realm join` (Linux), `dscacheutil` (macOS), or `Add-Computer` (Windows) workflows should migrate to `adrian-cli join`.
- **Security (PC-123 threat model).** The SDK's memory safety (Rust) and audit logging (per ADR-060) are documented. The SDK's credential handling (Kerberos tickets, password hashes, private keys) is the highest-risk code path; the Rust memory-safety guarantee eliminates the buffer-overflow / use-after-free class of bugs.

## References

- [ADR-002](../adr/ADR-002-memberof-back-link.md) — memberOf back-link
- [ADR-004](../adr/ADR-004-sd-deduplication.md) — security descriptor deduplication
- [ADR-028](../adr/ADR-028-push-based-policy-websocket.md) — push-based policy distribution
- [ADR-049](../adr/ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization (this decision provides the SDK architecture that ADR-049 left open)
- [ADR-050](../adr/ADR-050-authselect-standard-pam.md) — authselect standard PAM
- [ADR-051](../adr/ADR-051-kcm-linux-api-macos-cache-abstraction.md) — KCM Linux API + macOS cache abstraction
- [ADR-054](../adr/ADR-054-per-host-laps-rotation.md) — per-host LAPS rotation
- [ADR-056](../adr/ADR-056-psso-modern-macos-kerberos-path.md) — PSSO modern macOS Kerberos path
- [ADR-058](../adr/ADR-058-container-native-dcs-operator.md) — container-native deployment
- [ADR-060](../adr/ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-061](../adr/ADR-061-rest-grpc-api.md) — REST/gRPC API (for remote admin, contrasted with in-process SDK)
- [ADR-063](../adr/ADR-063-unified-cross-platform-cli.md) — unified cross-platform CLI (this decision resolves the implementation-language question raised in ADR-063 PARTIAL)
- [ADR-067](../adr/ADR-067-sigstore-supply-chain.md) — Sigstore supply chain (SDK binary signing)
- [PC-040, PC-085, PC-086, PC-091, PC-095, PC-100, PC-115](../catalog/08-client-sdk.md) — problem statements
- [pyo3](https://pyo3.rs) — Python binding for Rust
- [swift-bridge](https://github.com/chinedufn/swift-bridge) — Swift-Rust FFI
- [jni-rs](https://github.com/jni-rs/jni-rs) — Rust JNI bindings
- [cbindgen](https://github.com/mozilla/cbindgen) — C header generation from Rust
- [maturin](https://www.maturin.rs) — Rust-Python build tool
- [pavao](https://docs.rs/pavao) — Rust SMB client library
