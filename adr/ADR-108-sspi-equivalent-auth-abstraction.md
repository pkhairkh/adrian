---
title: "ADR-108: SSPI-Equivalent Unified Auth Abstraction in adrian-sdk"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Client SDK
problem: PC-086
severity: high
unblocked_by: [workshop-decision-11, workshop-decision-06]
tags: [adr, client-sdk, sspi, gssapi, psso, kerberos, ntlm, abstractions, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-051-kcm-linux-api-macos-cache-abstraction.md
  - ./ADR-056-psso-modern-macos-kerberos-path.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ../catalog/08-client-sdk.md
  - ../workshop/decision-11-client-sdk.md
  - ../workshop/decision-06-ntlm-decision.md
  - ../docs/10-comparison-matrices/04-auth-flow-comparison.md
  - ../docs/08-macos-equivalents/04-platform-sso-extension.md
last_updated: 2026-08-14
---

# ADR-108: SSPI-Equivalent Unified Auth Abstraction in adrian-sdk

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK) and [Workshop Decision 6](../workshop/decision-06-ntlm-decision.md) (NTLM client-only). Resolves the high-severity problem [PC-086](../catalog/08-client-sdk.md) (macOS PSSO Extension is Apple-only; no SSPI-equivalent abstraction across platforms). Implements the `AuthModule` surface specified in [ADR-107](./ADR-107-unified-rust-core-sdk.md) at concrete API level.

## Context

Windows SSPI (Security Support Provider Interface, `secur32.dll` / `sspicli.dll`) is the in-process authentication API used by every Windows network stack: `AcquireCredentialsHandle` allocates a credential handle bound to a principal and package (`Kerberos`, `NTLM`, `Negotiate`, `Schannel`); `InitializeSecurityContext` drives the client-side multi-leg handshake (returning `CONTINUE_NEEDED` until the protocol completes); `AcceptSecurityContext` drives the server-side counterpart; `ApplyControlToken` / `QueryContextAttributes` enable channel binding, session keys, and PAC extraction; `EncryptMessage` / `DecryptMessage` provide per-message confidentiality and integrity (GSS-API `wrap`/`unwrap` equivalent). LSASS (`lsass.exe`) holds the credentials; the SSP packages (`kerberos.dll`, `msv1_0.dll`, `negotiate.dll`, `schannel.dll`) implement the protocols. macOS exposes no equivalent: PSSO Extension provides ticket acquisition and Authorization framework integration but not a generic `InitializeSecurityContext`-style API; the system Heimdal exposes GSS-API but does not unify Kerberos + NTLM + cert + OAuth2 under one handle type. Linux GSS-API (`libgssapi_krb5.so`) is RFC 2743/2744 conformant but covers only Kerberos and (via `gssntlmssp`) NTLM — not cert-based TLS or OAuth2 token bearer.

The result, per [PC-086](../catalog/08-client-sdk.md) and the 8-phase login flow comparison in [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md), is that a framework-native application wanting "acquire a credential, perform a multi-leg auth handshake, get a session key, wrap/unwrap messages" must call SSPI on Windows, GSS-API on Linux, and PSSO + Heimdal GSS-API on macOS — three different APIs with three different handle types, three different error codes, three different channel-binding idioms. Cross-platform framework applications (the framework's own SMB client, the framework's REST API client, the framework's LDAP client) require a unified auth abstraction; without one, every framework-native network protocol implementation forks three times.

Workshop Decision 11 §1 specifies that the Rust core `adrian-sdk` exposes an `AuthModule` (`pub fn auth(&self) -> &AuthModule`); Decision 6 specifies the NTLM posture (client-only, server-side rejected) and S4U2Self/S4U2Proxy preservation. This ADR locks the `AuthModule`'s public Rust API, the FFI mapping to the C ABI, and the per-platform delegation paths.

## Decision

The `adrian-sdk` Rust core ships an SSPI-equivalent `AuthModule` that exposes a single credential-handle and security-context abstraction across Kerberos, NTLM (client-only per Decision 6), X.509 client cert, and OAuth2 bearer token. The abstraction is implemented in pure Rust in the `adrian-sdk` core; platform-native delegation (LSA, PSSO Heimdal, Linux GSS-API) is hidden behind the abstraction. The C ABI exposes the same abstraction as opaque-handle functions, enabling every binding (JNI, Swift, Python, Go) to consume it identically.

**Concrete specification**:

- The `AuthModule` exposes four credential-acquisition entry points, each returning a `CredentialHandle`:
  ```rust
  impl AuthModule {
      pub fn acquire_kerberos(&self, principal: Option<&str>, use_cache: bool)
          -> Result<CredentialHandle, AuthError>;
      pub fn acquire_ntlm_client(&self, target: &str)
          -> Result<CredentialHandle, AuthError>;     // client-only per Decision 6
      pub fn acquire_cert(&self, cert_selector: &CertSelector)
          -> Result<CredentialHandle, AuthError>;     // X.509 client cert via platform key store
      pub fn acquire_oauth2(&self, token: &OAuth2Token)
          -> Result<CredentialHandle, AuthError>;     // bearer token wrapper
  }
  ```
  `CredentialHandle` is an opaque `pub struct CredentialHandle { inner: Arc<Inner> }`. The same `CredentialHandle` type serves all four credential kinds; downstream APIs (security context, message wrap) dispatch on the credential kind internally. This matches the SSPI model where `AcquireCredentialsHandle` accepts a `pszPackageName` parameter (`"Kerberos"`, `"NTLM"`, `"Negotiate"`, `"Schannel"`) and returns the same `CredHandle` type regardless of package.

- The `AuthModule` exposes a single security-context initialization entry point:
  ```rust
  impl AuthModule {
      pub fn init_security_context(
          &self,
          cred: &CredentialHandle,
          target: &Spn,                              // e.g. Spn("cifs/fileserver.corp.example.com")
          input_token: Option<&[u8]>,                 // None for first leg, Some(token) for subsequent
          channel_bindings: Option<&ChannelBindings>, // RFC 5929 tls-server-end-point
          flags: InitFlags,                           // { mutual_auth, delegate, confidentiality, integrity, ... }
      ) -> Result<SecurityContext, AuthError>;
  }
  ```
  `SecurityContext` exposes `is_complete() -> bool`, `output_token() -> &[u8]` (token to send to peer), `session_key() -> Result<SessionKey, AuthError>` (after context completion), `wrap(&[u8]) -> Result<Vec<u8>, AuthError>`, `unwrap(&[u8]) -> Result<Vec<u8>, AuthError>`, `query_attr(Attr) -> Result<AttrValue, AuthError>` (PAC, peer principal, flags). The signature mirrors SSPI's `InitializeSecurityContext` and GSS-API's `gss_init_sec_context`; the framework's choice is to use a single method per direction with `Option<&[u8]>` for input token (matching SSPI), rather than GSS-API's `gss_init_sec_context(..., input_token, ...)` with an empty token for the first leg.

- The server-side counterpart (`accept_security_context`) is implemented for Kerberos (the framework's KDC-issued service tickets) and X.509 client cert (Schannel-equivalent); NTLM accept is **NOT** implemented per Decision 6. The `AuthModule` exposes `accept_security_context(cred, input_token, channel_bindings) -> Result<SecurityContext, AuthError>`; on Windows this wraps `AcceptSecurityContext`; on Linux this wraps `gss_accept_sec_context`; on macOS this wraps Heimdal's `gss_accept_sec_context` via the `gss-api = "0.1"` Rust crate.

- Channel binding follows RFC 5929 `tls-server-end-point`: `ChannelBindings::tls_server_end_point(server_cert_hash: [u8; 32])` is the only channel-binding type accepted by the framework's `AuthModule`. The `tls-unique` and `tls-server-end-point` channel-binding types are evaluated; `tls-server-end-point` is chosen for parity with SSPI's `ASC_REQ_CONNECTION`/`ASC_REQ_MUTUAL_AUTH` and with Samba's `SMB_SIGNING_SHA256` channel binding per [ADR-021](./ADR-021-ldap-signing-channel-binding.md).

- The Rust core delegates to platform-native primitives via a `pub trait AuthBackend`:
  ```rust
  pub trait AuthBackend: Send + Sync {
      fn acquire_kerberos_cred(&self, principal: Option<&str>) -> Result<NativeCred, AuthError>;
      fn init_kerberos_context(&self, cred: &NativeCred, target: &Spn, input: Option<&[u8]>, cb: Option<&ChannelBindings>, flags: InitFlags) -> Result<NativeContext, AuthError>;
      fn accept_kerberos_context(&self, cred: &NativeCred, input: &[u8], cb: Option<&ChannelBindings>) -> Result<NativeContext, AuthError>;
      fn acquire_ntlm_client_cred(&self) -> Result<NativeCred, AuthError>;     // client-only
      // ... (no ntlm_accept per Decision 6)
  }
  ```
  Three backends are shipped: `LsaAuthBackend` (Windows, via `windows = "0.54"` crate's `LsaConnectUntrusted` / `LsaCallAuthenticationPackage` / `InitializeSecurityContext`); `GssApiAuthBackend` (Linux, via `gss-api = "0.1"` Rust crate wrapping `libgssapi_krb5.so`); `PssoHeimdalAuthBackend` (macOS, via `gss-api = "0.1"` Rust crate wrapping `/usr/lib/libkerberos.dylib` for PSSO-acquired credentials, plus `objc2 = "0.5"` for `AuthorizationCopyRight` integration). On macOS, `acquire_kerberos_cred` first checks the PSSO-managed `API:Initialdefaultcache` (via `krb5_cc_resolve("API:Initialdefaultcache")`); if a TGT exists, the backend returns the PSSO credential. If no TGT exists, the backend falls through to the framework's MIT krb5 installation at `/opt/adrian/lib/mit-krb5/` (per [ADR-049](./ADR-049-standardize-mit-krb5.md)).

- NTLM client-side uses the `adrian-ntlm-client` crate (per Decision 6, ~3K lines of Rust), independent of any platform-native NTLM implementation. The `AuthModule::acquire_ntlm_client` method returns a `CredentialHandle` whose `init_security_context` drives the three-message NEGOTIATE → CHALLENGE → AUTHENTICATE handshake via `adrian-ntlm-client`. NTLMv1 is unconditionally disabled (`InitFlags::NTLMV1_PERMITTED` is rejected with `AuthError::Unsupported`). NT hash storage uses the platform's secure credential store (Linux `keyctl` / `systemd-creds`, macOS Keychain, Windows DPAPI / Cred Guard) via the `keyring = "2"` Rust crate's cross-platform API; the framework's `AuthModule` never holds the NT hash in plaintext outside the `keyring` call.

- PAC extraction follows MS-KILE: after `init_security_context` completes for a service-ticket acquisition (or `accept_security_context` completes for a service accepting a client ticket), `SecurityContext::query_attr(Attr::Pac)` returns `Ok(AttrValue::Pac(pac))`. The PAC is parsed via the framework's unified PAC validator (per [ADR-049](./ADR-049-standardize-mit-krb5.md) §Decision §PAC validator) — never via the platform-native Kerberos implementation's bundled parser. This eliminates the macOS system-Heimdal fork's missing `PAC_FULL_CHECKSUM` / `PAC_REQUESTER` / compound-identity gaps (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)).

- S4U2Self / S4U2Proxy are exposed as `AuthModule::s4u2self(&CredentialHandle, user: &Principal) -> Result<SecurityContext, AuthError>` and `AuthModule::s4u2proxy(&CredentialHandle, evidence_ticket: &[u8], target: &Spn) -> Result<SecurityContext, AuthError>`, both delegating to the framework's KDC per Decision 5 `src/mskile/s4u.rs`. The framework's `msDS-AllowedToDelegateTo` policy is enforced by the KDC; the SDK does not duplicate policy enforcement.

- The C ABI exposes the `AuthModule` as:
  ```c
  typedef struct AdrianAuth AdrianAuth;
  typedef struct AdrianCredHandle AdrianCredHandle;
  typedef struct AdrianSecCtx AdrianSecCtx;

  int32_t adrian_auth_acquire_kerberos(AdrianAuth*, const char* principal, int use_cache, AdrianCredHandle** out);
  int32_t adrian_auth_acquire_ntlm_client(AdrianAuth*, const char* target, AdrianCredHandle** out);
  int32_t adrian_auth_acquire_cert(AdrianAuth*, const AdrianCertSelector*, AdrianCredHandle** out);
  int32_t adrian_auth_acquire_oauth2(AdrianAuth*, const char* token_json, AdrianCredHandle** out);
  int32_t adrian_auth_init_sec_ctx(AdrianAuth*, const AdrianCredHandle*, const char* spn, const uint8_t* in_token, size_t in_len, const AdrianChannelBindings*, uint32_t flags, AdrianSecCtx** out);
  int32_t adrian_secctx_is_complete(const AdrianSecCtx*, int* out);
  int32_t adrian_secctx_output_token(const AdrianSecCtx*, const uint8_t** out_tok, size_t* out_len);
  int32_t adrian_secctx_session_key(const AdrianSecCtx*, const uint8_t** out_key, size_t* out_len);
  int32_t adrian_secctx_wrap(AdrianSecCtx*, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
  int32_t adrian_secctx_unwrap(AdrianSecCtx*, const uint8_t* in, size_t in_len, uint8_t** out, size_t* out_len);
  int32_t adrian_secctx_query_attr(AdrianSecCtx*, uint32_t attr, const void** out_value, size_t* out_len);
  int32_t adrian_secctx_free(AdrianSecCtx*);
  int32_t adrian_cred_free(AdrianCredHandle*);
  ```
  The C ABI is the foundation for JNI, Swift, Python, and Go bindings (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §Decision §bindings). The `int32_t` return codes are stable for v1; `adrian_error_message` retrieves the error string.

- Audit logging: every `acquire_*` and `init_security_context` / `accept_security_context` call emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "sdk_auth_op"`, `principal`, `target_spn`, `credential_kind` (`kerberos`/`ntlm_client`/`cert`/`oauth2`), `result`, `source_ip`, `platform`. NTLM client usage additionally emits `event_type = "ntlm_client_auth"` per Decision 6.

## Rationale

The unified-auth-abstraction choice is forced by the framework's cross-platform-parity commitment (per PC-085 / [ADR-107](./ADR-107-unified-rust-core-sdk.md)). A framework-native SMB client written in Rust must call the same `AuthModule::init_security_context` on Windows, macOS, and Linux; the platform-specific delegation (LSA, PSSO Heimdal, Linux GSS-API) is an internal implementation detail. Without the abstraction, every framework-native protocol implementation (SMB, LDAP, HTTP Negotiate, RPC) would fork three times for the auth handshake, defeating the unified-SDK goal.

The choice to model the API after SSPI (rather than GSS-API) is driven by three considerations. First, SSPI is the more expressive API: `ApplyControlToken` allows mid-context operations (reauth, rekey) that GSS-API does not expose cleanly. Second, SSPI's `QueryContextAttributes` exposes a richer attribute surface (PAC, peer token, session key exportability, impersonation level) that the framework needs. Third, the framework's Windows integration must interoperate with native SSPI consumers (the framework's LSA Authentication Package per [ADR-107](./ADR-107-unified-rust-core-sdk.md) is itself an SSPI consumer); modeling the SDK API after SSPI minimizes the impedance mismatch on Windows. On Linux and macOS, the Rust core translates the SSPI-style API to GSS-API calls internally.

The choice to make `CredentialHandle` opaque (rather than typed per credential kind) matches SSPI's `CredHandle` design: downstream APIs (security context, message wrap) dispatch on the credential kind internally. This eliminates the need for framework applications to know whether they hold a Kerberos credential, an NTLM credential, a cert credential, or an OAuth2 token — they hold a `CredentialHandle` and the `AuthModule` figures out the protocol. This is particularly important for the framework's `Negotiate`-style flows (HTTP `WWW-Authenticate: Negotiate`), where the protocol is chosen at runtime based on the server's response.

The choice to delegate Kerberos to platform-native primitives (LSA, PSSO Heimdal, Linux GSS-API) rather than implementing Kerberos in pure Rust in the SDK is forced by the framework's integration commitments. On Windows, LSA holds the user's TGT; the SDK cannot acquire the user's TGT without going through LSA. On macOS, PSSO Extension manages the user's TGT via `API:Initialdefaultcache`; the SDK must read this cache to preserve the PSSO user experience (per [ADR-049](./ADR-049-standardize-mit-krb5.md)). On Linux, the SDK uses MIT krb5's GSS-API (via `libgssapi_krb5.so` and the `gss-api = "0.1"` Rust crate) to interoperate with SSSD's `sssd-kcm` cache (per [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md)). Implementing Kerberos in pure Rust in the SDK would duplicate the framework's KDC effort (per Decision 5) and require a parallel cache type, breaking PSSO and LSA integration.

The choice to implement NTLM client in pure Rust (`adrian-ntlm-client` crate) rather than wrapping platform-native NTLM is forced by Decision 6's posture (NTLM client-only) and by the need for cross-platform parity. Windows' `msv1_0.dll` provides NTLM client and server; macOS has no native NTLM (per PC-094); Linux has Samba's `libnss_winbind` NTLM but only when `winbindd` is running. Wrapping platform-native NTLM would mean (a) on Windows, using `msv1_0.dll` for client-side NTLM (works, but couples the SDK to `msv1_0.dll`'s internals); (b) on macOS, having no native NTLM (broken); (c) on Linux, requiring Samba's `winbindd` (heavy dependency). A pure Rust NTLMv2 client (~3K lines, per Decision 6 §Rust implementation implications) gives the framework a single cross-platform NTLM client with no platform-native coupling. The NT hash is fetched from the platform's secure credential store on every NTLM authentication (per Decision 6); the `keyring = "2"` Rust crate provides the cross-platform API.

The choice to do PAC validation via the unified PAC validator (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) rather than via each platform's native Kerberos implementation is forced by the macOS system-Heimdal fork's missing features (per [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md)). If the SDK relied on macOS's Heimdal to validate `PAC_FULL_CHECKSUM`, macOS would accept tickets that Linux (MIT krb5 1.16+) and Windows (MS-KILE) reject — a cross-platform parity violation. The unified PAC validator (a shared Rust library) closes this gap by parsing and validating the PAC in the SDK's own code, independent of the platform-native Kerberos implementation.

## Consequences

**Positive**. Framework-native network protocols (SMB, LDAP, HTTP Negotiate, RPC) write one auth path that works on all three platforms, eliminating the ~3,000-line tri-codebase cost for auth alone. The unified PAC validator closes the macOS Heimdal fork's `PAC_FULL_CHECKSUM` / `PAC_REQUESTER` / compound-identity gaps without requiring Apple to update system Heimdal. The opaque `CredentialHandle` enables `Negotiate`-style protocol negotiation at runtime. NTLM client usage is uniform across platforms (pure Rust `adrian-ntlm-client`) with consistent audit logging per Decision 6.

**Negative**. The unified abstraction is a new API surface that framework-native applications must learn (not SSPI, not GSS-API, but a synthesis). The Rust core's `AuthBackend` trait adds an indirection layer (3 backends × 1 trait method per operation) that has a small per-call cost (~50ns per `init_security_context` call for the trait dispatch; negligible vs. the underlying network round-trip). The Windows LSA delegation path requires the SDK to run in the user's logon session (LSA credentials are per-logon-session); the SDK cannot acquire LSA credentials on behalf of a different user without `SeTcbPrivilege` (which the SDK does not request). The macOS PSSO delegation path requires the SDK to run in the user's session (PSSO credentials are per-session); the SDK cannot acquire PSSO credentials from a system daemon without an XPC connection to the user's `securityd` (which the framework does not implement in v1).

**Neutral**. The unified abstraction is invisible to platform-native applications (SSPI/OpenDirectory/SSSD continue to work alongside the SDK). The unified abstraction is invisible to end users (they interact with the platform-native login UI). The unified abstraction is visible to framework-native applications (they call `AuthModule::init_security_context` directly).

**Implementation cost**. ~10 person-weeks. Breakdown: `AuthModule` Rust core + `AuthBackend` trait (3 pw), `LsaAuthBackend` Windows implementation (2 pw, highest-risk due to LSA timing requirements), `GssApiAuthBackend` Linux implementation (1 pw), `PssoHeimdalAuthBackend` macOS implementation (2 pw, including `objc2` `AuthorizationCopyRight` integration), C ABI surface (1 pw), unified PAC validator integration (already shared with [ADR-049](./ADR-049-standardize-mit-krb5.md), 0.5 pw), audit logging integration (0.5 pw).

**Operational impact**. Operations teams gain a single audit event type (`sdk_auth_op`) across all platforms, queryable via OpenTelemetry. Operations teams gain a single metrics surface (`adrian_auth_init_sec_ctx_total{platform, credential_kind, result}`). Operations teams must understand the platform-native delegation paths for troubleshooting (LSA on Windows, PSSO Heimdal on macOS, GSS-API on Linux) — the runbook includes a "unified auth abstraction troubleshooting" section.

## Alternatives Considered

**Alternative 1: Adopt GSS-API as the unified abstraction.** The SDK exposes `gss_init_sec_context` / `gss_accept_sec_context` directly, with platform-specific GSS-API implementations (MIT krb5 on Linux, Heimdal on macOS, MITKerberosShim on Windows via a third-party GSS-API implementation). **Rejection rationale**: Windows does not ship a GSS-API implementation; the framework would need to ship a third-party GSS-API library (e.g. `gssntlmssp` + a MIT krb5 Windows port), adding ~5MB to the Windows binary footprint. GSS-API's C-macro-based error handling (`gss_buffer_desc`, `gss_OID_set`, `GSS_S_COMPLETE` major/minor status codes) does not map cleanly to the framework's Rust error types and the C ABI's `int32_t` return codes. GSS-API lacks `ApplyControlToken`-style mid-context operations. SSPI-style API gives the framework a richer surface that translates to GSS-API calls on Linux/macOS and LSA calls on Windows.

**Alternative 2: Per-protocol API (no unified abstraction).** The SDK exposes `acquire_kerberos_ticket`, `acquire_ntlm_token`, `acquire_cert`, `acquire_oauth2_token` as separate methods, each returning a protocol-specific token type. Framework-native applications choose the protocol explicitly. **Rejection rationale**: This eliminates `Negotiate`-style protocol negotiation, requiring framework-native applications to know the protocol in advance. HTTP `WWW-Authenticate: Negotiate` servers expect the client to negotiate the protocol; without a unified abstraction, the SDK cannot drive `Negotiate` flows. SMB, LDAP, and RPC all use `Negotiate`-style auth; the framework cannot ship framework-native SMB/LDAP/RPC clients without a unified abstraction.

**Alternative 3: Wrap platform-native auth APIs without a Rust abstraction.** The SDK exposes `InitializeSecurityContext` on Windows, `gss_init_sec_context` on Linux, and PSSO + Heimdal GSS-API on macOS — no unified Rust API. Framework-native applications call the platform-native API directly. **Rejection rationale**: This perpetuates the tri-codebase problem documented in [PC-085](../catalog/08-client-sdk.md). The framework's own network protocols (SMB, LDAP, HTTP, RPC) would each need three implementations. Cross-platform parity is impossible without a unified abstraction.

## Open Questions

None. The decision is fully specified. The implementation details (Windows LSA timing requirements, macOS `objc2` `AuthorizationCopyRight` XPC integration) are operational risks documented in §Consequences.

## Cross-capability impact

- **KDC** ([PC-023](../catalog/02-kdc.md)): The `AuthModule::acquire_kerberos` path produces Kerberos AS-REQ/TGS-REQ via the platform-native Kerberos implementation; the framework's KDC receives and responds.
- **Auth Provider** ([PC-029](../catalog/03-auth-provider.md)): The `AuthModule::acquire_kerberos` with password pre-auth delegates password validation to the Auth Provider via the KDC's AS-REQ path.
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The `AuthModule` is the auth surface of the unified SDK (per [ADR-107](./ADR-107-unified-rust-core-sdk.md)).
- **Client SDK** ([PC-090](../catalog/08-client-sdk.md)): The platform-native Kerberos delegation (LSA, PSSO Heimdal, GSS-API) inherits the MIT-vs-Heimdal divergence; the unified PAC validator closes the PAC-related gaps.
- **Client SDK** ([PC-093](../catalog/08-client-sdk.md)): The `AuthModule` reads tickets from the platform-native cache (KCM, API:, LSA) per [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md).
- **Cross-Platform Parity** ([PC-094](../catalog/09-cross-platform-parity.md)): The `adrian-ntlm-client` crate provides macOS NTLM client support (closes the macOS NTLM gap).
- **Federation Gateway** (Decision 9): The `AuthModule::acquire_oauth2` returns a bearer-token `CredentialHandle` that the `FederationModule` uses for client-side RP token validation.

## References

- [PC-086](../catalog/08-client-sdk.md) — problem statement (macOS PSSO Extension Apple-only)
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings
- [Workshop Decision 6 — NTLM](../workshop/decision-06-ntlm-decision.md) — NTLM client-only
- [docs/10-comparison-matrices/04-auth-flow-comparison.md](../docs/10-comparison-matrices/04-auth-flow-comparison.md) — 8-phase login flow side-by-side showing SSPI / PSSO / SSSD divergence
- [docs/08-macos-equivalents/04-platform-sso-extension.md](../docs/08-macos-equivalents/04-platform-sso-extension.md) — PSSO Extension architecture, `AuthorizationCopyRightEx`, `kAuthorizationCredentialTypeSSO`
- [ADR-021](./ADR-021-ldap-signing-channel-binding.md) — LDAP signing + channel binding (RFC 5929 `tls-server-end-point`)
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization + unified PAC validator
- [ADR-051](./ADR-051-kcm-linux-api-macos-cache-abstraction.md) — KCM Linux API + macOS API: cache abstraction
- [ADR-056](./ADR-056-psso-modern-macos-kerberos-path.md) — PSSO modern macOS Kerberos path
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [RFC 2743](https://www.rfc-editor.org/rfc/rfc2743) — Generic Security Service API
- [RFC 2744](https://www.rfc-editor.org/rfc/rfc2744) — GSS-API C-bindings
- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) — Kerberos V5
- [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) — Channel Bindings for TLS
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile) — Kerberos Protocol Extensions
- [SSPI Documentation](https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi) — Microsoft SSPI reference
- [gss-api Rust crate](https://docs.rs/gss-api) — Rust bindings to libgssapi_krb5
- [keyring Rust crate](https://docs.rs/keyring) — Cross-platform credential storage
