---
title: "ADR-107: Unified Rust Core SDK with Platform-Specific Bindings"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-085
severity: blocker
unblocked_by: [workshop-decision-11]
tags: [adr, client-sdk, rust, ffi, c-abi, jni, swift-bridge, pyo3, cgo, sspi, wldap32]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-051-kcm-linux-api-macos-cache-abstraction.md
  - ./ADR-056-psso-modern-macos-kerberos-path.md
  - ./ADR-061-rest-grpc-api.md
  - ./ADR-063-unified-cross-platform-cli.md
  - ../catalog/08-client-sdk.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/10-comparison-matrices/04-auth-flow-comparison.md
  - ../docs/09-linux-equivalents/10-pam-nss-stack.md
last_updated: 2026-08-14
---

# ADR-107: Unified Rust Core SDK with Platform-Specific Bindings

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (ORQ-169/170/175/176). Resolves the blocker problem [PC-085](../catalog/08-client-sdk.md) ("No universal AD client SDK"). Supersedes the open SDK-architecture questions raised in [ADR-049](./ADR-049-standardize-mit-krb5.md), [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md), and [ADR-063](./ADR-063-unified-cross-platform-cli.md).

## Context

There is no single client SDK that works on all three target platforms. Windows applications use SSPI (`secur32.dll` — `InitializeSecurityContext`, `AcceptSecurityContext`, `EncryptMessage`) for authentication, Wldap32 (`wldap32.dll` — `ldap_bind_s`, `ldap_search_ext_s`) for LDAP directory access, and NetAPI (`netapi32.dll` — `NetJoinDomain`, `NetShareEnum`) for domain-join and share enumeration. macOS applications use the OpenDirectory framework (`ODSessionCreate`, `ODNodeCreate`, `ODRecordSetValues`) plus the Authorization framework (`AuthorizationCopyRight`), with `dscl`/`dsconfigad` as the CLI surface. Linux applications use SSSD (`pam_sss.so` + `libnss_sss.so.2`) for NSS and PAM, plus OpenLDAP client libraries (`libldap`) for direct LDAP access, per [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) and [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md). The four stacks differ in every dimension: authentication primitive (SSPI vs Authorization framework vs PAM), ticket cache location (LSA in-memory on Windows vs keychain `API:` on macOS vs `KEYRING:persistent:<uid>` or KCM on Linux), group resolution protocol (LDAP `tokenGroups` on SSSD vs `NetrSamLogon` MS-NRPC opnum 45 on Winbind vs `LsaLookupSids3` on Windows), and NSS source (none on Windows vs `libnss_sss` on Linux vs OpenDirectory daemon on macOS).

Per [PC-085](../catalog/08-client-sdk.md)'s impact analysis, a typical enterprise app that needs "authenticate the user, query their group memberships, mount their home share, fetch their cert" today requires ~3,000 lines of platform-specific code per OS, totaling ~9,000 lines plus three CI matrices. The constraints require the framework to: support Windows, macOS, Linux from a single API surface with platform-native bindings (C# for Windows, Swift for macOS, Python/Go/Rust for Linux); expose authentication (Kerberos, NTLM, cert, OAuth2 token), directory query (LDAP), policy application, file/print client, cert enrollment, and federation client APIs; hide platform-specific ticket cache types behind a unified cache abstraction; must not break existing platform-native applications — the SDK must be additive, not replacing SSPI/OpenDirectory/SSSD on the host; and must be wire-compatible with MS-KILE, MS-DRSR (read-only client), MS-ADTS (LDAP), MS-SMB2, MS-WCCE/MS-XCEP (cert enrollment).

Workshop Decision 11 ([workshop/decision-11-client-sdk.md](../workshop/decision-11-client-sdk.md)) resolved the gating ORQs ORQ-169/170/175/176 in favor of: NOT a gRPC-based SDK; YES per-language bindings from a Rust core; write a new client (not extend SSSD); do NOT adopt FreeIPA client as the base. This ADR locks the concrete architecture and crate graph for the `adrian-sdk` workspace.

## Decision

The framework's Client SDK is a **unified Rust core library (`adrian-sdk`) with platform-specific bindings**. The core library handles authentication (Kerberos, NTLM fallback per Decision 6), directory (LDAP queries, attribute reads), policy (load, evaluate, apply, rollback per Decision 7), cert enrollment (ACME per Decision 8), file (SMB client for SYSVOL access), and federation (token validation, refresh). Platform bindings expose the Rust core to platform-native consumers via FFI.

**Concrete specification**:

- **Rust core library (`adrian-sdk`)** — distributed as a Rust crate (`adrian-sdk = "1.0"` on crates.io for Linux/macOS Rust consumers) and as a pre-built static/dynamic library for FFI consumers. The core's public API:
  ```rust
  pub struct AdrianClient { /* connection pool, credential cache, config */ }
  impl AdrianClient {
      pub fn new(config: ClientConfig) -> Result<Self, ClientError>;
      pub fn auth(&self) -> &AuthModule;
      pub fn directory(&self) -> &DirectoryModule;
      pub fn policy(&self) -> &PolicyModule;
      pub fn cert(&self) -> &CertModule;
      pub fn file(&self) -> &FileModule;
      pub fn federation(&self) -> &FederationModule;
  }
  ```
  Each module is an `&'a` reference into the `AdrianClient` (zero-cost; modules share the underlying connection pool, credential cache, and config). The core uses `tokio = "1"` for async I/O; the public API exposes both `async` methods (for Rust consumers) and blocking methods (for FFI consumers, which typically cannot run a `tokio` runtime). The blocking methods internally use `tokio::runtime::Runtime::block_on`.

- **C ABI binding (`adrian-sdk-c`)** — A C header (`adrian.h`) and a static/dynamic library (`libadrian_sdk.a` / `.so` / `.dylib` / `.dll`). The C ABI uses opaque pointers (`AdrianClient*`, `AdrianAuth*`, etc.) and `int32_t adrian_<module>_<method>(...)` function signatures. Errors are returned as `int32_t` codes; error messages are retrieved via `adrian_error_message(int32_t code, char* buf, size_t len)`. Strings are returned as `const char*` (NUL-terminated UTF-8) owned by the library, valid until the next call to the same module. The C ABI is the foundation for all other bindings (JNI, Swift, Python, Go all use the C ABI).

- **JNI binding (`adrian-sdk-java`)** — A Java JAR (`adrian-sdk-java-1.0.jar`) and a JNI native library. The JAR exposes Java classes (`com.adrian.sdk.AdrianClient`, `com.adrian.sdk.auth.AuthModule`, etc.) with native methods implemented in the JNI library. The JNI library is a thin wrapper over the C ABI; it converts Java types to C types and back, handles Java exceptions, and manages the JVM's reference to the underlying Rust `AdrianClient`. The JAR also includes a Kotlin-friendly API (`suspend` functions for async methods) for Android consumers.

- **Swift bridge (`adrian-sdk-swift`)** — A Swift package (`AdrianSDK`, distributed via Swift Package Manager) wrapping the C ABI. The Swift bridge uses `swift-bridge = "0.2"` to auto-generate Swift types from Rust types where possible; for complex types (e.g., `tokio`'s `Handle`), the bridge provides manual Swift wrappers. The Swift package exposes `AdrianClient`, `AuthModule`, etc. as Swift classes with `async throws` methods. The Swift bridge is the foundation for the framework's macOS PSSO Extension (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)) and the framework's iOS app (planned for v1.1).

- **Python binding (`adrian-sdk-python`)** — A Python package (`adrian-sdk`, distributed via PyPI) generated by `pyo3 = "0.21"`. The Python package exposes Python classes (`adrian.Client`, `adrian.AuthModule`, etc.) with Pythonic APIs (snake_case, exceptions for errors, context managers for resource cleanup). The Python binding is the foundation for the framework's Ansible collection (`community.adrian`, distributed via Ansible Galaxy).

- **Go binding (`adrian-sdk-go`)** — A Go module (`github.com/adrian/sdk-go`) generated by `cgo` against the C ABI. The Go module exposes Go types (`adrian.Client`, `adrian.AuthModule`, etc.) with idiomatic Go APIs (contexts, errors, goroutines for async). The Go binding is the foundation for the framework's Kubernetes operator (per [ADR-058](./ADR-058-container-native-dcs-operator.md)) and the framework's Terraform provider.

- **Platform-native integrations**. The Rust core integrates with platform-native libraries via FFI:
  - **Windows**: `windows = "0.54"` for Win32 APIs (`LsaConnectUntrusted`, `LogonUser`, `AcquireCredentialsHandle`, `InitializeSecurityContext` for Kerberos/NTLM auth; `Wldap32` for LDAP; `Crypt32` / `NCrypt` for cert and key store; `WinHttp` for HTTPS).
  - **macOS**: `core-foundation = "0.10"` and `objc2 = "0.5"` for macOS frameworks (`Kerberos.framework`, `OpenDirectory.framework`, `Security.framework` for keychain, `CFNetwork` for HTTPS). The macOS integration uses the system Heimdal (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) for PSSO Extension compatibility; framework-application Kerberos uses MIT krb5 installed at `/opt/adrian/lib/mit-krb5/`.
  - **Linux**: `gss-api = "0.1"` (via `libgssapi_krb5`), `ldap3 = "0.11"` (pure-Rust LDAP client), `systemd = "0.10"` (for systemd-journald logging and `notify`), `rustls = "0.23"` for HTTPS.

- **PAM/NSS provider**. On Linux, the SDK ships a PAM module (`pam_adrian.so`) and an NSS module (`nss_adrian.so.2`) that integrate with the system PAM/NSS stack. The PAM module implements `pam_sm_authenticate`, `pam_sm_acct_mgmt`, `pam_sm_chauthtok`, `pam_sm_session_mgmt`, delegating to the Rust core's `AuthModule`. The NSS module implements `getpwnam`, `getpwuid`, `getgrnam`, `getgrgid`, `getspnam`, delegating to the Rust core's `DirectoryModule`. The PAM/NSS modules are loaded via `/etc/pam.d/` and `/etc/nsswitch.conf` configured by `authselect` (per [ADR-050](./ADR-050-authselect-standard-pam.md)). On macOS, the SDK ships an OpenDirectory plugin (`AdrianOpenDirectory.bundle`) that integrates with the system OpenDirectory framework. On Windows, the SDK ships an LSA Authentication Package (`adrianlsa.dll`) and a Credential Provider (`AdrianCredentialProvider.dll`).

- **Domain join**. The SDK's `AdrianClient::join_domain(domain, admin_creds)` method performs the domain-join operation: generates a machine keypair (in TPM2 on Windows/Linux, in Secure Enclave on macOS), creates the host object in the framework's directory via LDAP, registers the SPN (`host/<fqdn>`, `cifs/<fqdn>`, `HTTP/<fqdn>`, `ldap/<fqdn>`), writes the machine key to the platform-native key store (Windows LSA, macOS Keychain, Linux `/etc/krb5.keytab`), and triggers the initial policy pull. The SDK exposes this via the `adrian-cli join` command (per [ADR-063](./ADR-063-unified-cross-platform-cli.md)).

- **Cert enrollment**. The SDK's `CertModule` runs the framework's cert enrollment agent on every enrolled host. The agent reads the host's cert profile assignments from the directory, runs an ACME client against the framework's CA (per Decision 8), fulfills the `adrian-attest-01` challenge via TPM2 quote (Windows/Linux) or Apple Secure Enclave attestation (macOS), stores the issued cert and private key in the platform-native key store, and re-enrolls at 2/3 of validity (per RFC 8823 ARI). The agent runs as a Windows Service / launchd daemon / systemd service.

- **File access**. The SDK's `FileModule` provides an SMB client (using `pavao = "0.10"` or the framework's own SMB client implementation, depending on `pavao`'s maturity) for accessing `\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\`. The client uses the host's machine Kerberos ticket for authentication. The `FileModule` is read-only for the SYSVOL share (policy distribution is read-only on the client side); read-write for shares the host is authorized to write to (e.g., user home shares).

- **Federation**. The SDK's `FederationModule` provides OIDC token validation (via `openidconnect = "3"`), SAML assertion validation (via `saml2 = "0.20"`), and token refresh for client-side RPs that need to validate framework-issued tokens. The module is used by the framework's own federation-aware services (e.g., the framework's REST API per [ADR-061](./ADR-061-rest-grpc-api.md)) and by customer RPs that link against the SDK.

- **Per-host LAPS rotation**. The SDK's `AuthModule` rotates the host's LAPS-equivalent local-admin password per [ADR-054](./ADR-054-per-host-laps-rotation.md). The rotation generates a new random password, writes it to the host's local-admin account, and writes the new password hash to the framework's directory. The rotation runs on a schedule (default 30 days) via the SDK's daemon.

## Rationale

Three candidate architectures were considered before locking the Rust-core-with-bindings model (per Decision 11 §Rationale).

**Candidate A: gRPC-based SDK with platform-native auth adapters.** A gRPC server runs on each enrolled host; platform-native clients call the gRPC server via platform-native adapters. Rejected because gRPC adds a network hop (localhost TCP) and a protobuf schema layer that is unnecessary for in-process operations — every `getpwnam` call would incur a localhost TCP round-trip and protobuf marshal/unmarshal, adding 100-500 µs per call; for NSS-heavy workloads (e.g., `find /` walks `getpwuid` for every file), this is unacceptable. gRPC's `tokio` runtime conflicts with the platform's existing runtime (Windows SCM, macOS launchd, Linux systemd) — the gRPC server becomes another process to supervise, another port to firewall, another log file to rotate. The Rust core + C ABI is ~5MB, vs gRPC's ~15MB binary footprint.

**Candidate B: Extend SSSD as the Linux client; wrap platform-native (LSA, OpenDirectory) on Windows/macOS.** Rejected because SSSD is C, tightly coupled to its `data provider` abstraction, `be_ptask` scheduler, and `responder` IPC. Extending it to support the framework's policy/cert/federation modules requires either (i) extending SSSD with new responders (which the upstream may not accept) or (ii) running the framework's modules as a separate daemon alongside SSSD (which duplicates the host's identity surface and risks SSSD-vs-framework drift). SSSD's release cadence is controlled by the upstream SSSD project (Red Hat / SUSE), not by the framework; the framework cannot ship SDK fixes without waiting for the next SSSD release.

**Candidate C: Adopt FreeIPA client as the base on Linux; wrap platform-native on Windows/macOS.** FreeIPA's client is `ipa-client-install` (Python) + `sssd` (C) + `certmonger` (C). Rejected because (a) the framework's directory schema is its own (per Day 1 schema decision), not FreeIPA's `ipa*` schema; (b) FreeIPA's client is Python, requiring a Python interpreter on every Linux host — non-starter for embedded / minimal Linux deployments; (c) FreeIPA's `certmonger` is a separate CA-enrollment daemon with its own state machine, incompatible with the framework's ACME cert enrollment per Decision 8.

The chosen Rust-core-with-bindings model gives the framework: (a) a single source of truth (the Rust core) for all platform behavior, eliminating cross-platform drift; (b) platform-native integration via FFI (LSA, PAM/NSS, OpenDirectory, Kerberos, key stores) where platform-native is required; (c) cross-language support via the C ABI foundation (every language with FFI can call the framework's SDK); (d) memory safety (Rust for the protocol-parsing and credential-handling code); (e) the framework's release cadence (no dependency on upstream SSSD or FreeIPA release cycles). The Rust core's binary footprint (~5MB) is acceptable for modern hosts.

## Consequences

**Positive**. The framework gains a single SDK across Windows, macOS, and Linux, eliminating the ~9,000-line tri-codebase cost documented in [PC-085](../catalog/08-client-sdk.md). The Rust memory-safety guarantee eliminates the buffer-overflow / use-after-free CWE class in the SDK's protocol-parsing and credential-handling code paths — the highest-risk code surface on every enrolled host. The C ABI foundation gives every FFI-capable language a path to the SDK without per-language reimplementation. The framework's release cadence is independent of upstream SSSD/FreeIPA/Apple PSSO cadence.

**Negative**. Rust knowledge is required for SDK core contributors; the bindings (C ABI, JNI, Swift, Python, Go) are thinner and have lower contribution friction. No SSSD reuse on Linux means Linux distributions that ship SSSD by default (RHEL, Ubuntu, SUSE) will see the framework's PAM/NSS provider alongside SSSD; operators must disable SSSD's `ad` provider (or use SSSD's `proxy` provider pointing at the framework's NSS module) to avoid double-resolution. The Windows LSA Authentication Package (`adrianlsa.dll`) is loaded into `lsass.exe`; bugs can crash `lsass.exe`, forcing a Windows reboot. The macOS OpenDirectory plugin (`AdrianOpenDirectory.bundle`) is the second-highest-risk item (bugs can prevent macOS logon).

**Neutral**. The SDK is invisible to end users (they interact with the platform-native login UI). The SDK is invisible to platform-native applications (SSPI/OpenDirectory/SSSD continue to work alongside the SDK). The SDK is visible to framework-native applications (they link against `adrian-sdk` directly).

**Implementation cost**. ~30 person-weeks for v1. Breakdown: Rust core (8 pw), C ABI + `cbindgen` (2 pw), JNI + Java codegen (3 pw), Swift bridge (2 pw), Python + Ansible (3 pw), Go + Terraform (2 pw), PAM/NSS (2 pw), Windows LSA + Credential Provider (4 pw, highest-risk), macOS OpenDirectory (2 pw), `adrian-cli` (2 pw). The Windows LSA is the critical-path item.

**Operational impact**. Operations teams gain a single SDK version number across the fleet (`adrian-cli version` returns the same version on Windows, macOS, Linux). Operations teams gain a single audit surface for SDK operations (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)). Operations teams must understand the platform-native integrations (LSA, PAM/NSS, OpenDirectory) for troubleshooting — the runbook includes a "SDK troubleshooting" section per platform.

## Alternatives Considered

**Alternative 1: gRPC-based SDK with platform-native adapters.** Rejected per Decision 11 §Rationale (network hop, protobuf overhead, runtime conflict, binary footprint). See §Rationale above.

**Alternative 2: Per-platform-native SDKs sharing only a spec.** Three independent SDKs (Windows C#/C++, macOS Swift, Linux Go/Rust) implementing the same API spec, with shared integration tests. Rejected because (a) three codebases means three defect surfaces, three release cadences, and inevitable cross-platform drift over time; (b) the framework cannot guarantee byte-identical protocol behavior (PAC parsing, ASN.1 marshaling, LDAP filter escaping) across three independent implementations; (c) the maintenance cost is 3× the unified Rust core.

**Alternative 3: Adopt SSSD's NSS/PAM responder protocol as the framework's Linux integration, write fresh SDKs for Windows/macOS.** Rejected because (a) SSSD's responder IPC is a stable internal protocol but not a published API; coupling to it makes the framework dependent on SSSD's internal stability; (b) SSSD does not provide policy/cert/federation modules — the framework would still need a parallel daemon for those modules, duplicating the host's identity surface; (c) Windows and macOS would still need fresh SDKs, defeating the cross-platform-parity goal.

## Open Questions

None. The decision is fully specified by Decision 11. The remaining implementation details (Windows LSA timing requirements, macOS OpenDirectory plugin lifecycle) are operational risks documented in §Consequences, not architectural open questions.

## Cross-capability impact

- **KDC** ([PC-023](../catalog/02-kdc.md)): The SDK's `AuthModule` acquires Kerberos tickets via MIT krb5 (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) and uses the unified PAC validator for PAC validation.
- **Core Directory** ([PC-013](../catalog/01-core-directory.md)): The SDK's `DirectoryModule` queries the directory via LDAP (`ldap3` crate). The directory's `memberOf` back-link (per [ADR-002](./ADR-002-memberof-back-link.md)) is used for group-membership resolution.
- **Auth Provider** ([PC-029](../catalog/03-auth-provider.md)): The SDK's `AuthModule` delegates password validation to the Auth Provider via LDAP simple bind.
- **Policy Engine** (Decision 7): The SDK's `PolicyModule` is the host-side policy daemon, loading `adrian-policy-executor` and dispatching policy areas to registered executors.
- **Cert Service** (Decision 8): The SDK's `CertModule` is the host-side cert enrollment agent, using `adrian-attest` for TPM2/Secure Enclave attestation.
- **File Gateway** (Decision 10): The SDK's `FileModule` is the host-side SMB client, accessing `\\<domain>\SYSVOL\` for policy distribution.
- **Federation Gateway** (Decision 9): The SDK's `FederationModule` validates framework-issued OIDC and SAML tokens for client-side RPs.
- **Operations** ([ADR-058](./ADR-058-container-native-dcs-operator.md)): The SDK runs as a StatefulSet sidecar in container-native deployments; the SDK's container image is the same across all platforms.
- **Migration** ([PC-127](../catalog/12-migration-and-coexistence.md)): The `adrian-cli join` command is the migration entry point. Customers with existing `realm join`, `dscacheutil`, or `Add-Computer` workflows migrate to `adrian-cli join`.
- **Security** ([PC-123](../catalog/11-security-threat-model.md)): The SDK's memory safety (Rust) and audit logging (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)) are documented. The SDK's credential handling (Kerberos tickets, password hashes, private keys) is the highest-risk code path; the Rust memory-safety guarantee eliminates the buffer-overflow / use-after-free CWE class.

## References

- [PC-085](../catalog/08-client-sdk.md) — problem statement
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — unified Rust core + platform-specific bindings
- [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) — 8-phase login flow side-by-side (Windows 11, macOS PSSO, Linux SSSD, Linux Winbind) with ASCII flow diagrams, ticket cache locations, group resolution protocols
- [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md) — Linux PAM/NSS architecture, `libnss_sss.so.2` IPC protocol, `pam_sss.so` parameter surface, distro-specific PAM generators
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization
- [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) — KCM Linux API + macOS cache abstraction
- [ADR-054](./ADR-054-per-host-laps-rotation.md) — per-host LAPS rotation
- [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) — PSSO modern macOS Kerberos path
- [ADR-058](./ADR-058-container-native-dcs-operator.md) — container-native DCs operator
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-061](./ADR-061-rest-grpc-api.md) — REST/gRPC API (for remote admin, contrasted with in-process SDK)
- [ADR-063](./ADR-063-unified-cross-platform-cli.md) — unified cross-platform CLI
- [pyo3](https://pyo3.rs) — Python binding for Rust
- [swift-bridge](https://github.com/chinedufn/swift-bridge) — Swift-Rust FFI
- [jni-rs](https://github.com/jni-rs/jni-rs) — Rust JNI bindings
- [cbindgen](https://github.com/mozilla/cbindgen) — C header generation from Rust
- [maturin](https://www.maturin.rs) — Rust-Python build tool
- [pavao](https://docs.rs/pavao) — Rust SMB client library
