---
title: "ADR-112: macOS NTLM Client Gap Closed by adrian-ntlm-client Rust Crate"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Cross-Platform Parity
problem: PC-094
severity: high
unblocked_by: [workshop-decision-06, workshop-decision-11]
tags: [adr, cross-platform-parity, macos, ntlm, ntlmv2, channel-binding, sspi, smb, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ./ADR-021-ldap-signing-channel-binding.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-107-unified-rust-core-sdk.md
  - ./ADR-108-sspi-equivalent-auth-abstraction.md
  - ../catalog/09-cross-platform-parity.md
  - ../workshop/decision-06-ntlm-decision.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/02-protocols/04-ntlm-internals.md
  - ../docs/10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-14
---

# ADR-112: macOS NTLM Client Gap Closed by adrian-ntlm-client Rust Crate

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 6](../workshop/decision-06-ntlm-decision.md) (NTLM client-only; server-side rejected) and [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (unified Rust core SDK). Resolves the high-severity problem [PC-094](../catalog/09-cross-platform-parity.md) (macOS has no native NTLM support; legacy apps fail). Implements the NTLM client-side implementation referenced in Decision 6 §2 (`crates/adrian-ntlm-client`, ~3K lines of Rust).

## Context

NTLM is the challenge-response authentication protocol carried inside an SPNEGO- or raw-NTLMSSP-branded GSS-API token, with a fixed three-message handshake (NEGOTIATE → CHALLENGE → AUTHENTICATE) where the server issues an 8-byte server challenge and the client returns an HMAC-MD5-derived 24-byte NTLMv2 response plus a variable-length client blob. The protocol authenticates the user without sending the password over the wire, but is considered deprecated because (a) the NT hash (MD4 of UTF-16-LE password) is the entire secret and is reusable offline (pass-the-hash), (b) the protocol has no mutual authentication, (c) NTLM relay attacks are trivial without channel binding, and (d) LM hash compatibility leaves 14-char passwords crackable, per [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md). The wire signature `NTLMSSP\0` (8 bytes, `0x4E 0x54 0x4C 0x4D 0x53 0x53 0x50 0x00`) is constant across all three messages (Type 1 NEGOTIATE MessageType `0x00000001`, Type 2 CHALLENGE `0x00000002`, Type 3 AUTHENTICATE `0x00000003`).

macOS SMBX client (`smbx.kext`, replacing `smbfs.kext` in macOS 10.14) does not implement NTLMSSP natively. Apple's strategy since macOS 10.14 has been Kerberos-first for SMB 2+ to AD-joined servers, with NTLM fallback only for legacy SMB 1 dialect connections (which are themselves disabled by default). Samba (Homebrew installable) or third-party agents (Centrify DirectControl, now Delinea/CyberArk) provide NTLM on macOS. Apps that hard-require NTLM — legacy SQL Server drivers (pre-ODBC Driver 17), old IIS-integrated apps that haven't been reconfigured for Kerberos, some legacy SMB appliances that don't support Kerberos — fail on macOS without these third-party stacks, per [docs/10-comparison-matrices/01-feature-os-matrix.md](../docs/10-comparison-matrices/01-feature-os-matrix.md). Linux SSSD also does not implement NTLM natively; it relies on Samba's `libsmbclient` and `pam_winbind` for any NTLM need.

Per [PC-094](../catalog/09-cross-platform-parity.md), ~5-10% of enterprise macOS users have at least one NTLM-requiring app; without a workaround, those users must run the app in a Windows VM or use Citrix/RDS. Workshop Decision 6 ([workshop/decision-06-ntlm-decision.md](../workshop/decision-06-ntlm-decision.md)) resolved the gating ORQs ORQ-072/074/075 with the synthesis posture: drop server-side NTLM (no acceptor on any framework-hosted service); maintain NTLM client-side support for connecting to legacy services via a Rust-native `adrian-ntlm-client` crate (~3K lines); preserve S4U2Self/S4U2Proxy via the framework's KDC. Decision 11 §7 specifies the macOS integration uses the system Heimdal for PSSO; this ADR locks the `adrian-ntlm-client` crate's architecture and its integration into the SDK's `AuthModule` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)).

## Decision

The framework ships an NTLM client implementation in `crates/adrian-ntlm-client` (~3K lines of Rust), used by framework-managed clients (Linux SSSD-equivalent, macOS PSSO Extension, Windows framework-joined hosts) to authenticate to legacy services that still require NTLM. The crate implements NTLMv2 with NTLMv1 unconditionally disabled, RFC 5929 channel binding, EPA `EPHEMERAL` flag, and platform-secure-credential-store-backed NT hash storage. The crate is integrated into the SDK's `AuthModule::acquire_ntlm_client` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) §Decision). Server-side NTLM is rejected per Decision 6 §1 — no framework-hosted service accepts NTLM.

**Concrete specification**:

- The `adrian-ntlm-client` crate implements the three-message NTLMSSP handshake per [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp):
  - **Type 1 NEGOTIATE** (`MessageType = 0x00000001`): emitted by the client to the server, containing `DomainName`, `Workstation`, and the `NegotiateFlags` bitmask. The crate sets `NTLMSSP_NEGOTIATE_UNICODE` (0x00000001), `NTLMSSP_NEGOTIATE_OEM` (0x00000002), `NTLMSSP_REQUEST_TARGET` (0x00000004), `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` (0x00080000), `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` (0x00008000), `NTLMSSP_NEGOTIATE_NTLM` (0x00000200), `NTLMSSP_NEGOTIATE_128` (0x20000000), `NTLMSSP_NEGOTIATE_56` (0x80000000). The crate does NOT set `NTLMSSP_NEGOTIATE_LM_KEY` (LM key support disabled), `NTLMSSP_NEGOTIATE_NTLM_V1` (NTLMv1 disabled per Decision 6 §2).
  - **Type 2 CHALLENGE** (`MessageType = 0x00000002`): received from the server, containing `ServerChallenge` (8 random bytes), `TargetName`, `TargetInfo` (AV_PAIRs including `MsvAvNbComputerName`, `MsvAvNbDomainName`, `MsvAvDnsComputerName`, `MsvAvDnsDomainName`, `MsvAvTimestamp`, `MsvAvTargetName`, `MsvAvChannelBindings`), and the negotiated `NegotiateFlags`. The crate validates `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` is set in the server's flags (rejecting the response with `NtlmError::V1Required` if the server does not support NTLMv2).
  - **Type 3 AUTHENTICATE** (`MessageType = 0x00000003`): emitted by the client to the server, containing `LMChallengeResponse` (24-byte zero-filled for NTLMv2 with EXTENDED_SESSIONSECURITY), `NtChallengeResponse` (the NTLMv2 response, ≥24 bytes), `DomainName`, `UserName`, `Workstation`, `SessionKey`, and `NegotiateFlags`. The crate computes `NtChallengeResponse = NTLMv2_RESPONSE = HMAC-MD5(NTOWFv2, ServerChallenge + ClientBlob)` where `NTOWFv2 = HMAC-MD5(NT-hash, UTF-16-LE(UPPER(user) + Domain))` and `ClientBlob` is the variable-length AV_PAIR blob ending with `MsvAvEOL` (0x0000).

- The crate validates `MsvAvChannelBindings` AV_PAIR (ID `0x000A`) per RFC 5929: if the server includes channel bindings, the crate computes `SHA-256(tls-server-end-point)` of the server's TLS certificate's `SubjectPublicKeyInfo` and includes it in the `ClientBlob`'s `MsvAvChannelBindings` value. If the server's `MsvAvChannelBindings` is empty (zero-filled), the crate also sends an empty `MsvAvChannelBindings` (legacy server compatibility — the framework logs an audit event but does not reject). If the server requires channel binding and the client cannot provide it (no TLS), the crate rejects with `NtlmError::ChannelBindingRequired`.

- The crate sets the EPA `EPHEMERAL` flag (`AvFlags & 0x04`) in the `ClientBlob`'s `MsvAvFlags` AV_PAIR (ID `0x0006`), marking the session as non-delegatable per Decision 6 §2. This prevents the NTLM-authenticated session from being used for S4U2Self/S4U2Proxy constrained delegation (S4U2Self/S4U2Proxy require Kerberos, per Decision 6 §3).

- NT hash storage uses the platform's secure credential store: Linux kernel keyring (`keyctl`) / `systemd-creds`; macOS Keychain; Windows DPAPI / Cred Guard. The crate uses the `keyring = "2"` Rust crate's cross-platform API to store and retrieve the NT hash. The NT hash is fetched from the platform secure credential store on every NTLM authentication; the crate does NOT cache the NT hash in plaintext in process memory beyond the duration of the authentication handshake. The NT hash is never written to disk in plaintext; the `keyring` crate's `set_secret()` API uses the platform's secure-storage mechanism (kernel keyring on Linux, Keychain on macOS, DPAPI on Windows).

- The crate's public API:
  ```rust
  pub struct NtlmClient { /* config, credential handle */ }
  impl NtlmClient {
      pub fn new(client: &AdrianClient, target: &str) -> Result<Self, NtlmError>;
      pub fn step(&mut self, server_token: &[u8]) -> Result<Vec<u8>, NtlmError>;     // returns client_token to send to server
      pub fn is_complete(&self) -> bool;
      pub fn session_key(&self) -> Result<SessionKey, NtlmError>;
  }
  ```
  The crate integrates with the SDK's `AuthModule::acquire_ntlm_client` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) §Decision): `acquire_ntlm_client` returns a `CredentialHandle` whose `init_security_context` drives the NTLMSSP handshake via `NtlmClient::step`. The resulting `SecurityContext` exposes `session_key()` (the NTLM session key, derived from the NT hash and server challenge per MS-NLMP §3.4) for downstream message signing/sealing.

- The crate's dependencies: `md4 = "0.1"` (NT hash derivation: `MD4(UTF-16-LE(password))`), `hmac = "0.12"` (HMAC-MD5 for NTOWFv2 and NTLMv2_RESPONSE), `sha2 = "0.10"` (SHA-256 for `MsvAvChannelBindings`), `rasn = "0.10"` (ASN.1 parsing for `SubjectPublicKeyInfo` extraction from the TLS certificate), `rasn-pkix = "0.10"` (X.509 certificate parsing), `keyring = "2"` (cross-platform credential storage), `tokio = "1"` (async I/O for the credential-store lookup, which may block on Linux `keyctl`), `tracing = "0.1"` (structured logging), `thiserror = "1"` (error types). The crate is `no_std`-compatible except for the `keyring` dependency (which requires OS APIs); the protocol implementation is `no_std` for embedded use cases (e.g., the framework's IoT client).

- The crate does NOT implement NTLM message signing/sealing (`MsvAvFlags` NTLMSSP_NEGOTIATE_ALWAYS_SIGN, NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_KEY_EXCH); these are handled by the SDK's `AuthModule::init_security_context` `wrap`/`unwrap` methods (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) §Decision) which use the NTLM session key as input to RC4-HMAC (for legacy servers) or AES-128-CBC (for servers that negotiate `NTLMSSP_NEGOTIATE_128`) per-message confidentiality. The crate exposes `session_key()` to provide the session key to the `AuthModule`.

- Audit logging: every NTLM authentication attempt emits an OpenTelemetry log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with `event_type = "ntlm_client_auth"` (per Decision 6 §2), including `target_service` (the SPN or hostname the client is authenticating to), `source_user` (the framework principal performing the authentication), `source_ip`, `timestamp`, `ntlm_version` (always `NTLMv2` per Decision 6 §2), `channel_binding_flag` (`present`/`absent`/`required-but-missing`), `epa_ephemeral_flag` (always `true`), `result` (`success`/`failure`), `failure_reason` (if applicable, e.g. `V1Required`, `ChannelBindingRequired`, `CredentialNotFound`). SIEM queries for `event_type = "ntlm_client_auth"` provide NTLM-usage monitoring per Decision 6 §5.

- The crate is integrated into the SDK's `AuthModule::acquire_ntlm_client` on every platform (Linux, macOS, Windows). On Windows, the framework's `AuthModule` uses the `adrian-ntlm-client` crate (rather than wrapping `msv1_0.dll`) for cross-platform parity — the Windows native NTLM client (`msv1_0.dll`) is not used by the framework's SDK to ensure consistent behavior across platforms. (Platform-native applications that use SSPI directly continue to use `msv1_0.dll`; the SDK's NTLM client is for framework-native applications only.)

- The crate does NOT implement NTLM server-side (`AcceptSecurityContext` equivalent). Per Decision 6 §1, no framework-hosted service accepts NTLM authentication. Clients presenting NTLM tokens to framework services are rejected with `strongAuthRequired (8)` (LDAP), `401 Unauthorized` with `WWW-Authenticate: Negotiate, Kerberos` (HTTP), or the protocol-equivalent on other surfaces.

## Rationale

The choice to implement NTLM client in pure Rust (`adrian-ntlm-client` crate) rather than wrapping platform-native NTLM is forced by three considerations. First, macOS has no native NTLM (per PC-094) — wrapping platform-native NTLM would mean the macOS SDK has no NTLM client, breaking framework-native applications that need NTLM on macOS. Second, Linux's Samba `libnss_winbind` provides NTLM but requires `winbindd` running, which the framework does not require (per Decision 12 §4, Winbind is deprecated). Third, Windows' `msv1_0.dll` provides NTLM client and server, but using it would couple the SDK to `msv1_0.dll`'s internals (which differ across Windows versions) and would not provide cross-platform parity. A pure Rust NTLMv2 client (~3K lines, per Decision 6 §Rust implementation implications) gives the framework a single cross-platform NTLM client with no platform-native coupling.

The choice to use the `md4 = "0.1"` Rust crate for NT hash derivation is forced by the NTLM protocol's reliance on MD4 (NT hash = `MD4(UTF-16-LE(password))`). MD4 is cryptographically broken for collision resistance but is still required for NTLMv2's NT hash derivation; the framework's `md4` crate is a pure-Rust implementation, MIT/Apache-2.0-licensed, used only for NTLM hash derivation (the framework does not use MD4 for any other purpose). The crate is audited and has no known vulnerabilities.

The choice to use the `keyring = "2"` Rust crate for NT hash storage is forced by the cross-platform credential-storage requirement. The framework's NT hash storage must use the platform's secure credential store (Linux kernel keyring, macOS Keychain, Windows DPAPI / Cred Guard) to prevent plaintext NT hashes from being written to disk. The `keyring` crate provides a unified API across these platform stores; the framework's `adrian-ntlm-client` crate uses `keyring::Entry::new(service, user)` to store and retrieve the NT hash. The NT hash is never held in process memory beyond the duration of the authentication handshake.

The choice to set the EPA `EPHEMERAL` flag (`AvFlags & 0x04`) is forced by Decision 6 §2. The `EPHEMERAL` flag marks the NTLM session as non-delegatable, preventing the session from being used for S4U2Self/S4U2Proxy constrained delegation (which requires Kerberos per Decision 6 §3). This is a defense-in-depth measure: even if a framework-managed service inadvertently exposes the NTLM session to a constrained-delegation flow, the `EPHEMERAL` flag prevents the framework's KDC from issuing a delegated ticket.

The choice to integrate the NTLM client into the SDK's `AuthModule::acquire_ntlm_client` (rather than as a separate `NtlmModule`) is forced by the unified-auth-abstraction commitment (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)). Framework-native applications call `AuthModule::init_security_context` with a `CredentialHandle` returned by `acquire_ntlm_client`; the `AuthModule`'s `init_security_context` dispatches on the credential kind internally (Kerberos via platform-native GSS-API, NTLM via `adrian-ntlm-client`, cert via Schannel-equivalent, OAuth2 via bearer-token wrap). This eliminates the need for framework applications to know whether they hold a Kerberos credential or an NTLM credential.

The choice to not implement NTLM server-side (`AcceptSecurityContext` equivalent) is forced by Decision 6 §1. The framework does not accept NTLM authentication on any framework-hosted service; the framework's KDC, LDAP server, REST API, SMB server (per Decision 10), HTTP services, cert-service endpoint, and federation gateway all reject NTLM. This eliminates the NTLM-relay attack class (PetitPotam, ShadowCoerce, PrinterBug) against framework infrastructure and eliminates pass-the-hash against framework infrastructure.

## Consequences

**Positive**. The framework gains a single NTLM client implementation across Linux, macOS, and Windows, closing the macOS NTLM gap documented in [PC-094](../catalog/09-cross-platform-parity.md). The pure-Rust implementation eliminates the buffer-overflow / use-after-free CWE class in the NTLM protocol-parsing code (the highest-risk code surface for memory-safety bugs in C-based NTLM implementations like `libnss_winbind` and `msv1_0.dll`). The NT hash is stored in the platform's secure credential store (not in plaintext on disk or in process memory), reducing the pass-the-hash attack surface. The `EPHEMERAL` flag prevents NTLM sessions from being used for constrained delegation. The unified audit logging of NTLM usage (per Decision 6 §2 and ADR-060) provides operational visibility that `msv1_0.dll` and `libnss_winbind` do not natively provide. The ~5-10% of enterprise macOS users with NTLM-requiring apps can now use those apps natively on macOS (no Windows VM, no Citrix/RDS).

**Negative**. The framework's NTLM client is a new code surface that must be maintained and patched as MS-NLMP evolves (e.g. future NTLMv3 if Microsoft introduces one). The `adrian-ntlm-client` crate's ~3K lines of Rust is small but the NTLM protocol has subtle edge cases (AV_PAIR ordering, timestamp handling, session key derivation) that require careful testing. The framework's CI runs an NTLM interop test suite against Windows Server 2022 (the reference NTLM implementation) and Samba (the open-source NTLM implementation) on every PR. The NT hash storage in the platform secure credential store requires the user's session to be active (the `keyring` crate cannot retrieve the NT hash from a system daemon without the user's session); the framework's `adrian-cli join` stores the NT hash at join time and the SDK retrieves it at authentication time.

**Neutral**. The framework's NTLM client is invisible to end users (they see the application's authentication dialog, not the NTLM handshake). The framework's NTLM client is invisible to platform-native applications (SSPI/OpenDirectory/SSSD continue to work alongside the SDK). The framework's NTLM client is visible to framework-native applications (they call `AuthModule::acquire_ntlm_client` directly).

**Implementation cost**. ~6 person-weeks. Breakdown: NTLMSSP Type 1/2/3 message marshaling and parsing (2 pw), NTLMv2 response computation (`NTOWFv2`, `NTLMv2_RESPONSE`, `ClientBlob`) (1 pw), channel binding (`MsvAvChannelBindings` AV_PAIR, `tls-server-end-point` SHA-256, `rasn-pkix` certificate parsing) (1 pw), `keyring` integration and platform-specific credential storage (1 pw), audit logging integration (0.5 pw), interop test suite (Windows Server 2022, Samba) (0.5 pw).

**Operational impact**. Operations teams gain a single NTLM audit event type (`ntlm_client_auth`) across all platforms, queryable via OpenTelemetry (per Decision 6 §5). Operations teams gain metrics for NTLM usage (`adrian_ntlm_auth_total{platform, target_service, result}`) — sudden spikes indicate new NTLM-requiring apps, prompting migration to Kerberos. Operations teams must understand that NTLM is client-only (per Decision 6 §1) — the runbook includes a "NTLM client troubleshooting" section explaining the framework's posture and how to migrate NTLM-requiring apps to Kerberos.

## Alternatives Considered

**Alternative 1: Provide NTLM via Samba winbind on macOS (Homebrew dependency, separate `winbindd` process).** The framework bundles Samba's `winbindd` on macOS (via Homebrew) and uses `libnss_winbind` for NTLM client. **Rejection rationale**: Samba is GPLv3, creating the same license conflict that Decision 10 rejected for `smbd`. Bundling `winbindd` adds a separate process to supervise, a separate port to firewall, a separate log file to rotate. Samba's `winbindd` also requires `smb.conf` configuration and a `secrets.tdb` database, adding operational complexity. The pure-Rust `adrian-ntlm-client` crate is simpler, Apache-2.0-licensed, and does not require a separate process.

**Alternative 2: Document legacy NTLM-requiring apps as out of scope and require Kerberos migration.** The framework does not provide an NTLM client; customers with NTLM-requiring apps must migrate those apps to Kerberos (register SPNs via `setspn -S`, configure app for Kerberos) before migrating to the framework. **Rejection rationale**: Decision 6 §2 explicitly states "the framework SHALL provide NTLM client-side support for connecting to legacy services that framework-managed clients must reach." The ~5-10% of enterprise macOS users with NTLM-requiring apps cannot migrate all those apps before migrating to the framework (some apps are unmaintained, vendor-locked, or appliance-based). The pure-Rust `adrian-ntlm-client` crate provides a migration window during which the apps continue to work via NTLM while the customer plans Kerberos migration.

**Alternative 3: Provide NTLM compat only on the server side (framework SMB server accepts NTLM clients) and require Kerberos on framework clients, accepting asymmetric posture.** The framework's SMB server (per Decision 10) accepts NTLM clients (for legacy interop); the framework's clients use only Kerberos. **Rejection rationale**: Decision 6 §1 explicitly states "the framework SHALL NOT implement an NTLM acceptor." Server-side NTLM is the attack surface (relay, PtH); client-side NTLM is compat plumbing. The asymmetric posture would force customers to maintain NTLM on the server side (high-risk) while blocking NTLM on the client side (low-risk), which is the opposite of the security/compat tradeoff.

## Open Questions

None. The decision is fully specified by Decision 6 §2 and Decision 11 §7. The implementation details (NTLMv2 AV_PAIR ordering, `tls-server-end-point` SHA-256 extraction) are protocol-level details documented in MS-NLMP and RFC 5929.

## Cross-capability impact

- **Auth Provider** ([PC-029](../catalog/03-auth-provider.md)): The framework's NTLM client fetches the NT hash from the platform secure credential store; the NT hash is stored at join time by the framework's `adrian-cli join` (which retrieves it from the framework's directory, where it is encrypted with the HSM-bound PEK per Decision 6 §4).
- **Client SDK** ([PC-085](../catalog/08-client-sdk.md)): The `adrian-ntlm-client` crate is part of the unified SDK's `AuthModule` (per [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md)).
- **Cross-Platform Parity** ([PC-094](../catalog/09-cross-platform-parity.md)): The `adrian-ntlm-client` crate closes the macOS NTLM gap.
- **File Gateway** (Decision 10): The framework's SMB client (per [ADR-107](./ADR-107-unified-rust-core-sdk.md) §File access) uses the `AuthModule::acquire_ntlm_client` path for legacy SMB appliances that do not support Kerberos.
- **KDC** ([PC-023](../catalog/02-kdc.md)): S4U2Self/S4U2Proxy (per Decision 6 §3) are preserved via the framework's KDC; the `EPHEMERAL` flag in the NTLM client's `ClientBlob` prevents NTLM sessions from being used for S4U.

## References

- [PC-094](../catalog/09-cross-platform-parity.md) — problem statement
- [Workshop Decision 6 — NTLM](../workshop/decision-06-ntlm-decision.md) — NTLM client-only
- [Workshop Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md) — Rust core + bindings
- [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md) — NTLMSSP three-message handshake, `NTLMv2_RESPONSE` formula, `MsvAvChannelBindings` AV_PAIR, `LmCompatibilityLevel` registry values
- [docs/10-comparison-matrices/01-feature-os-matrix.md](../docs/10-comparison-matrices/01-feature-os-matrix.md) — NTLM fallback row showing macOS Native OD = ✗, macOS Enterprise MDM = ✗, macOS 3rd-party agent = partial (Admit)
- [ADR-021](./ADR-021-ldap-signing-channel-binding.md) — LDAP signing + channel binding (RFC 5929 `tls-server-end-point`)
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization
- [ADR-060](./ADR-060-structured-audit-logs-otel.md) — structured audit logs (NTLM audit events)
- [ADR-107](./ADR-107-unified-rust-core-sdk.md) — unified Rust core SDK architecture
- [ADR-108](./ADR-108-sspi-equivalent-auth-abstraction.md) — SSPI-equivalent auth abstraction (`AuthModule`)
- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp) — NT LAN Manager (NTLM) Authentication Protocol
- [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) — Channel Bindings for TLS
- [md4 Rust crate](https://docs.rs/md4) — MD4 hash (NT hash derivation)
- [hmac Rust crate](https://docs.rs/hmac) — HMAC-MD5 (NTOWFv2, NTLMv2_RESPONSE)
- [sha2 Rust crate](https://docs.rs/sha2) — SHA-256 (channel binding hash)
- [rasn Rust crate](https://docs.rs/rasn) — ASN.1 parsing (SubjectPublicKeyInfo)
- [rasn-pkix Rust crate](https://docs.rs/rasn-pkix) — X.509 certificate parsing
- [keyring Rust crate](https://docs.rs/keyring) — Cross-platform credential storage (Linux keyring, macOS Keychain, Windows DPAPI)
