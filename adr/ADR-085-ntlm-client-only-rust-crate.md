---
title: "ADR-085: Drop NTLM Server-Side; Client-Only NTLM via Rust Crate for Legacy Interop"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Auth Provider
problem: PC-036
severity: high
unblocked_by: Workshop Decision 6 (ORQ-072/074/075)
tags: [adr, auth-provider, ntlm, ntlmv2, channel-binding, epa, legacy-interop, ms-nlmp, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/03-auth-provider.md
  - ../docs/02-protocols/04-ntlm-internals.md
  - ../docs/09-linux-equivalents/04-winbind-internals.md
  - ../workshop/decision-06-ntlm-decision.md
  - ./ADR-011-rc4-deprecation-aes-default.md
  - ./ADR-012-fast-armoring-required.md
  - ./ADR-021-ldap-signing-channel-binding.md
  - ./ADR-023-kerberos-audit-events.md
last_updated: 2026-08-14
---

# ADR-085: Drop NTLM Server-Side; Client-Only NTLM via Rust Crate for Legacy Interop

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 6](../workshop/decision-06-ntlm-decision.md) which resolved Tier-1 ORQ-072 ("Drop NTLM entirely?"), ORQ-074 ("Replace with OAuth2 client-credentials flow?"), and ORQ-075 ("Maintain S4U for AD interop?") in favor of dropping NTLM server-side while maintaining NTLM client-only via a fresh Rust crate for legacy service interop. This ADR translates that decision into a concrete NTLM posture specification: no NTLM acceptor on any framework service; `crates/adrian-ntlm-client` for outbound NTLM to legacy services; S4U2Self/S4U2Proxy preserved via the framework KDC (per [Decision 5](../workshop/decision-05-kdc-implementation.md)); migration tooling (`adrian-migrate audit-ntlm`) to identify NTLM-requiring apps before customer cutover.

## Context

NTLM (MS-NLMP) is a deprecated three-message challenge-response authentication protocol. AD services that hard-require NTLM include legacy SQL drivers (pre-2017), old IIS-integrated apps with `WindowsAuthentication` and `Providers=NTLM`, third-party appliances (network printers, embedded devices, storage controllers), and Windows services that fall back to NTLM when Kerberos fails. The wire format is the NTLMSSP handshake: Type 1 NEGOTIATE (client → server, carries `NegotiateFlags`), Type 2 CHALLENGE (server → client, carries 8-byte `ServerChallenge` + `TargetInfo` AV_PAIRs), Type 3 AUTHENTICATE (client → server, carries NTLMv2 response computed via `HMAC-MD5(NTOWFv2, ServerChallenge + ClientBlob)` where `NTOWFv2 = HMAC-MD5(NT-hash, UPPER(user) + Domain)`).

Microsoft's "Restrict NTLM" GPOs allow audit→enforce migration: audit mode logs events 8001–8004 (NTLM client/server activity) without blocking; enforce mode blocks NTLM by category (Outbound, Inbound, Audit). Most shops stay in audit mode indefinitely because the audit logs are noisy and identifying which apps to fix is a multi-month investigation.

The framework's posture ([Decision 6](../workshop/decision-06-ntlm-decision.md)) is sharper: the framework SHALL NOT host an NTLM acceptor on any framework service (no inbound NTLM). The framework SHALL provide NTLM client-side support for connecting to legacy services that framework-managed clients must reach (NTLM initiator role only). S4U2Self/S4U2Proxy SHALL be preserved via the framework KDC (not replaced by OAuth2 client-credentials). The framework's NTLM client is Rust-native, isolated, and does not touch the framework's main auth path.

Constraints from [PC-036](../catalog/03-auth-provider.md):

- Must support NTLM as opt-in for migration (legacy apps that hard-require NTLM).
- Must support NTLMv2 (NTLMv1 disabled unconditionally).
- Must support RFC 5929 channel binding for NTLM-over-TLS.
- Must support EPA `EPHEMERAL` flag for non-delegatable sessions.
- For AD interop, the framework must accept `NetrLogonSamLogonEx` PAC validation calls from Windows services (per [ADR-083](./ADR-083-pac-validation-rpc.md)).

## Decision

The framework SHALL adopt the following NTLM posture, with five concrete commitments from [Decision 6](../workshop/decision-06-ntlm-decision.md):

### 1. NTLM server-side (acceptor): NOT SUPPORTED

The framework SHALL NOT implement an NTLM acceptor. No framework-hosted service — LDAP server, KDC, REST API, SMB server (per [Decision 7](../workshop/decision-07-smb-implementation.md)), HTTP services, cert-service endpoint, federation gateway — SHALL accept NTLM authentication. Clients presenting NTLM tokens to framework services SHALL be rejected with `strongAuthRequired (8)` (LDAP), `401 Unauthorized` with `WWW-Authenticate: Negotiate, Kerberos` (HTTP), or the protocol-equivalent on other surfaces. This eliminates the entire NTLM-relay attack class (per [ADR-021](./ADR-021-ldap-signing-channel-binding.md)) against framework infrastructure: PetitPotam-style coercion cannot relay to framework DCs because framework DCs do not accept NTLM. Pass-the-hash against framework infrastructure is eliminated because no framework service accepts NTLM tokens.

### 2. NTLM client-side (initiator): SUPPORTED for legacy services, via Rust crate

The framework SHALL provide an NTLM client implementation in `crates/adrian-ntlm-client` (~3K lines of Rust), used by framework-managed clients (Linux SSSD-equivalent, macOS PSSO Extension, Windows framework-joined hosts) to authenticate to legacy services that still require NTLM. The NTLM client SHALL support:

- NTLMv2 (`NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`); NTLMv1 disabled unconditionally (NTLMv1 has known cryptographic breaks since 2010; no migration mode).
- Channel binding per RFC 5929 (`MsvAvChannelBindings` AV_PAIR ID 0x000B, SHA-256 of `tls-server-end-point`) when layered under TLS.
- EPA (`EPHEMERAL` flag `AvFlags & 0x04`) for non-delegatable sessions.
- NT hash storage in the platform's secure credential cache: Linux kernel keyring (`keyctl`) / `systemd-creds`; macOS Keychain; Windows DPAPI / Cred Guard.
- Audit emission per [ADR-023](./ADR-023-kerberos-audit-events.md) for every NTLM client authentication attempt (`event_type = "ntlm_client_auth"`).

The NTLM client SHALL NOT cache NT hashes in plaintext; the NT hash is fetched from the platform secure credential store on every NTLM authentication. The framework's main auth path (Kerberos, OAuth2, OIDC) is completely NTLM-free; the NTLM client is invoked only when a service explicitly requires NTLM and Kerberos is unavailable.

### 3. S4U2Self / S4U2Proxy: PRESERVED via framework KDC

S4U2Self/S4U2Proxy (RFC 4120 §2.6, MS-SFU) SHALL be implemented in the framework's KDC per [Decision 5](../workshop/decision-05-kdc-implementation.md) (in `crates/adrian-kdc/src/mskile/s4u.rs`). S4U is the Kerberos-native constrained-delegation primitive with no NTLM dependency. Constrained-delegation policy is enforced via `msDS-AllowedToDelegateTo` (per AD semantics). Full specification in [ADR-087](./ADR-087-s4u-constrained-delegation.md) (PC-039).

### 4. NT hash storage: HSM-equivalent protection, no plaintext

The framework's directory SHALL NOT store NT hashes in plaintext. NT hashes SHALL be stored encrypted with a key bound to the framework's HSM (the same HSM that holds the krbtgt key per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)) using the same PEK (Password Encryption Key) mechanism AD uses. The framework's PEK SHALL be HSM-bound; the framework SHALL NOT hold the PEK in process memory in plaintext. This matches AD's `ntdsa.dll` PEK handling and is the strongest possible protection short of eliminating the NT hash entirely.

For framework-native users (users created in the framework, not migrated from AD), the framework SHALL NOT derive or store an NT hash at all — only AES Kerberos keys per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md). NT hashes are derived and stored ONLY for users that require AD-interop (users in mixed forests, users that need to authenticate to legacy NTLM-requiring services). Full PtH defense specification in [ADR-086](./ADR-086-pass-the-hash-defense.md) (PC-038).

### 5. Migration path: AD customers using NTLM MUST move to Kerberos before migration

AD customers with NTLM-requiring applications SHALL migrate those applications to Kerberos (or OAuth2/OIDC) BEFORE migrating to the framework. The framework's migration tooling (`adrian-migrate`) SHALL include an `audit-ntlm` command that scans the AD forest for NTLM-requiring applications and produces a remediation plan, identifying: (a) services with NTLM-only SPNs; (b) applications configured for NTLM auth (IIS apps with `WindowsAuthentication` and `Providers=NTLM`, SQL Server with `Integrated Security=SSPI` and NTLM fallback); (c) event-log evidence of NTLM auth (Windows events 4624 with `Authentication Package = NTLM`); (d) Group Policy `Restrict NTLM` audit-mode events (8004–8020 series). Customers with applications that cannot be migrated SHALL run those applications in a parallel AD forest during the migration window.

### Concrete specification

- No framework-hosted service SHALL accept NTLM authentication (rejected with `strongAuthRequired (8)` or protocol equivalent).
- `crates/adrian-ntlm-client` SHALL implement NTLMv2 client with NTLMv1 disabled, RFC 5929 channel binding, EPA `EPHEMERAL` flag, and platform-secure-credential-store-backed NT hash storage (Linux `keyctl` / `systemd-creds`, macOS Keychain, Windows DPAPI / Cred Guard); NT hashes SHALL NOT be cached in plaintext.
- The KDC SHALL implement S4U2Self/S4U2Proxy per [Decision 5](../workshop/decision-05-kdc-implementation.md) and [ADR-087](./ADR-087-s4u-constrained-delegation.md); constrained-delegation policy SHALL be enforced via `msDS-AllowedToDelegateTo`.
- The directory SHALL NOT store NT hashes in plaintext — they SHALL be encrypted with an HSM-bound PEK (same HSM as krbtgt per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)); NT hashes SHALL be derived and stored ONLY for AD-interop users; framework-native users have AES Kerberos keys only per [ADR-011](./ADR-011-rc4-deprecation-aes-default.md).
- The framework SHALL expose `adrian-migrate audit-ntlm`, `adrian-migrate plan-ntlm`, and `adrian-auth audit-ntlm` CLI commands.
- The framework SHALL emit an audit event (per [ADR-023](./ADR-023-kerberos-audit-events.md)) for every NTLM client authentication attempt, including: target service, source user, source IP, timestamp, NTLM version, channel-binding flag, EPA flag. SIEM queries for `(event_type = "ntlm_client_auth")` provide NTLM-usage monitoring.

### Rust crates used

- `adrian-ntlm-client` (framework crate, written from scratch — ~3K lines). NTLMv2 client: NTLMSSP message construction (Type 1 / 2 / 3), NT hash derivation (MD4 of UTF-16LE password), NTLMv2 response computation (HMAC-MD5 of server challenge + client challenge + target info), channel binding (SHA-256 of `tls-server-end-point`), EPA `EPHEMERAL` flag handling, platform-secure-credential-store integration.
- `md4` (v0.10+, MIT/Apache-2.0) for NT hash derivation. Same crate as the KDC's RC4 audit path (per [Decision 5](../workshop/decision-05-kdc-implementation.md)).
- `hmac` (v0.12+, MIT/Apache-2.0) for HMAC-MD5 (NTLMv2 response) and HMAC-SHA256 (channel binding).
- `sha2` (v0.10+, MIT/Apache-2.0) for SHA-256 channel binding.
- `rasn` (v0.10+, MIT/Apache-2.0) for ASN.1 parsing of NTLMSSP AV_PAIR structures (most of NTLMSSP is raw byte-packed).
- `keyring` (v3.0+, MIT/Apache-2.0) for cross-platform secure credential store access: Linux `secret-service` / `keyctl`, macOS Keychain, Windows DPAPI. Platform adapter prefers `keyctl` / `systemd-creds` on Linux for kernel-level protection.
- `tokio` (v1.40+, MIT) for async NTLM authentication flow.
- `tracing` (v0.1+, MIT) + `opentelemetry` (v0.24+, MIT) for audit emission per [ADR-023](./ADR-023-kerberos-audit-events.md).
- `adrian-kdc` (framework crate, per [Decision 5](../workshop/decision-05-kdc-implementation.md)) for S4U2Self/S4U2Proxy. S4U is implemented in the KDC, not in a separate crate.

### Crates NOT used

`ntlm-rs` (v0.7+) — evaluated and rejected per [Decision 6](../workshop/decision-06-ntlm-decision.md): 2+ years old, known correctness bugs in NTLMv2 response computation, no channel binding support. Used only as a comparison-testing reference. `libgssapi` (binding to system GSSAPI) — reintroduces the C dependency. `samba-ntlm` (Samba GPLv3) — GPLv3.

## Rationale

The decision synthesizes Options A (drop NTLM entirely) and C (winbind sidecar) from the [Decision 6](../workshop/decision-06-ntlm-decision.md) candidate set, without the winbind dependency. Five arguments drive the synthesis:

**1. Server-side NTLM is the attack surface; client-side NTLM is the compat surface.** The NTLM attack classes — pass-the-hash (PC-038), relay (PC-037/ADR-021), NTLM spoofing — all require an NTLM acceptor as the target. Without an NTLM acceptor, the attack class has no foothold in framework infrastructure. The NTLM client is not an attack target; it is an attack initiator.

**2. The framework is greenfield; AD-interop customers must migrate.** The framework has no legacy NTLM-dependent codebase. AD-interop customers with NTLM-requiring apps have a binary choice: migrate the apps to Kerberos/OAuth2 OR run those apps in a parallel AD forest during the migration window. Spike 4 found 5–10% of apps hard-require NTLM; the parallel-AD-forest option is the migration path for those.

**3. Samba winbind is unnecessary.** Winbind inherits Samba's GPLv3 license (~5K lines of config) and adds operational burden. The framework's Rust NTLM client (~3K lines) is lighter, license-clean, and achieves the same isolation (NT hashes never touch the framework's main auth path).

**4. S4U2Self/S4U2Proxy is the Kerberos-native constrained delegation primitive.** ORQ-074's OAuth2 client-credentials alternative is reasonable for new services that don't need user-delegation. But for services that need to forward a user's identity (web app authenticating user via cert, then calling backend SQL as the user), S4U2Proxy is the Kerberos-native mechanism. OAuth2 client-credentials cannot express "act on behalf of user X" without RFC 8693 token exchange, which is more complex than S4U2Proxy and lacks AD interop.

**5. PtH defense for AD-interop mode is PEK encryption + HSM, not NT hash elimination.** PC-038 is fundamentally about NT hash storage. In pure-framework mode, the framework derives no NT hashes and PtH is impossible. In AD-interop mode, NT hashes are stored for AD-interop users; PEK encryption with an HSM-bound key is the strongest possible protection (matching AD's `ntdsa.dll` PEK handling, plus HSM binding that AD doesn't have).

External evidence: [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) defines NTLM; [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) defines TLS channel binding; [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) defines S4U2Self/S4U2Proxy; [Microsoft Security Advisory ADV210003 (PetitPotam)](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003); [Microsoft "Restrict NTLM" GPO](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain); [Mandiant M-Trends 2023](https://www.mandiant.com/resources/blog/m-trends-2023) reports NTLM relay used in ~40% of AD compromises involving lateral movement.

## Consequences

**Positive**: NTLM-relay attacks (PC-037, [ADR-021](./ADR-021-ldap-signing-channel-binding.md)) and pass-the-hash attacks (PC-038, [ADR-086](./ADR-086-pass-the-hash-defense.md)) against framework infrastructure are eliminated — no NTLM acceptor exists as a target. PetitPotam-style coercion cannot relay to framework DCs. Framework-native users have no NT hashes (PtH impossible). AD-interop users' NT hashes are HSM-PEK-encrypted. S4U2Self/S4U2Proxy preserved for constrained delegation. Migration tooling identifies NTLM-requiring apps before customer cutover.

**Negative**: NTLM-requiring legacy services cannot authenticate TO framework-managed services. Customers with such services must migrate them to Kerberos/OAuth2 OR run them in a parallel AD forest. <5% of enterprise workloads in modern AD forests are affected (per Spike 4). Hard constraint. The NTLM client is a maintenance surface (~3K lines); committed for v1/v2; v3 may deprecate if NTLM usage drops below 1% (monitor via `adrian-auth audit-ntlm`). S4U2Self/S4U2Proxy adds KDC complexity (per [Decision 5](../workshop/decision-05-kdc-implementation.md)). NT hash storage is required for AD-interop users (smaller attack surface than AD but not zero).

**Neutral**: No Samba-ecosystem fallback. Samba tools that emit NTLM (`smbclient`, `rpcclient` with NTLM fallback) cannot authenticate TO framework services. Framework-managed clients use the framework's Rust SMB client (per [Decision 7](../workshop/decision-07-smb-implementation.md)) which speaks Kerberos natively.

**Implementation cost**: 8 person-weeks for Auth Provider per [Decision 6](../workshop/decision-06-ntlm-decision.md). Breakdown: `crates/adrian-ntlm-client` 4 pw (NTLMv2, channel binding, EPA, credential-store integration); NTLM-server-side rejection 1 pw (across LDAP, HTTP, SMB, KDC services); `adrian-auth audit-ntlm` CLI 1 pw; S4U enforcement in KDC covered by [Decision 5](../workshop/decision-05-kdc-implementation.md); audit-event emission 1 pw. Core Directory 2 pw (NT hash storage with HSM-PEK encryption; PEK binding per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)). Client SDK 2 pw (NTLM client integration into platform auth adapters). Migration 2 pw (`adrian-migrate audit-ntlm` / `plan-ntlm` CLI). Security 1 pw. Total 15 person-weeks.

## Alternatives Considered

### Alternative 1: Drop NTLM entirely (no client-side)

Eliminates PtH and NTLM relay completely. Rejected: framework-managed clients cannot authenticate to legacy NTLM-requiring services (5–10% of enterprise apps per Spike 4). The framework's NTLM client provides a lighter alternative than a parallel-AD-forest sidecar.

### Alternative 2: Maintain NTLM server-side via Samba winbind sidecar

Isolates NTLM in a separate daemon. Rejected per [Decision 6](../workshop/decision-06-ntlm-decision.md): winbind inherits Samba's GPLv3 license, adds operational burden (separate process supervision, separate config); the Rust NTLM client achieves the same isolation without GPLv3 contamination.

### Alternative 3: Replace NTLM with OAuth2 client-credentials flow wholesale

ORQ-074's candidate. Rejected as wholesale replacement: OAuth2 client-credentials is HTTP-only; NTLM is used by SMB, LDAP, RPC, SQL — protocol bridging is non-trivial. OAuth2 client-credentials cannot express "act on behalf of user X" without RFC 8693 token exchange, which lacks AD interop. OAuth2 is adopted for new framework-native service-to-service auth; S4U2Self/S4U2Proxy preserved for Kerberos-native delegation.

### Alternative 4: NTLMv1 with migration mode

NTLMv1 has known cryptographic breaks since 2010. Rejected: NTLMv1 is cryptographically broken; any deployment accepting NTLMv1 is at risk. The framework disables NTLMv1 unconditionally; customers with NTLMv1-only appliances must upgrade the appliances.

## Open Questions

- For the v3 deprecation threshold: the framework commits to deprecating `crates/adrian-ntlm-client` if NTLM usage drops below 1% of authentications (monitor via `adrian-auth audit-ntlm` over a rolling 12-month window). Deferred to a future deprecation ADR.
- For AD-interop NT hash rotation: should the framework rotate AD-interop users' NT hashes on a schedule? No — the NT hash is the user's actual password hash; rotating without user involvement breaks the password. The framework rotates the PEK on the krbtgt rotation schedule per [ADR-015](./ADR-015-krbtgt-hsm-rotation.md).
- Cross-reference [ADR-086](./ADR-086-pass-the-hash-defense.md) (PC-038 PtH) — full PtH defense specification.
- Cross-reference [ADR-087](./ADR-087-s4u-constrained-delegation.md) (PC-039 S4U) — full S4U specification.
- Cross-reference [ADR-021](./ADR-021-ldap-signing-channel-binding.md) (PC-037 NTLM relay) — relay protection scoped to the NTLM client; server-side relay protection is moot (no NTLM acceptor).

## Cross-capability impact

- **KDC** ([Decision 5](../workshop/decision-05-kdc-implementation.md)): S4U2Self/S4U2Proxy implemented in the KDC's `mskile/s4u.rs`; the Auth Provider's Kerberos SSPI-equivalent initiates S4U requests.
- **Core Directory**: NT hash storage in `unicodePwd` with HSM-PEK encryption; `msDS-AllowedToDelegateTo` for S4U2Proxy policy.
- **Client SDK** ([Decision 11](../workshop/decision-11-client-sdk.md)): NTLM client integration into platform auth adapters (Keychain, `keyctl`, DPAPI). The Client SDK exposes `NtlmClient::authenticate(target)` as a platform-agnostic API.
- **File Gateway** ([Decision 7](../workshop/decision-07-smb-implementation.md)): the framework's SMB server SHALL NOT accept NTLM; framework-managed SMB clients use the framework's NTLM client when connecting to legacy NTLM-requiring SMB servers.
- **Federation Gateway** ([Decision 9](../workshop/decision-09-federation-gateway.md)): the Federation Gateway SHALL NOT accept NTLM; federation uses OAuth2/OIDC/SAML.
- **Migration**: `adrian-migrate audit-ntlm` scans AD forests for NTLM-requiring apps; `adrian-migrate plan-ntlm` produces a remediation plan. Migration is gated on remediating NTLM-requiring apps before cutover.
- **Security** ([ADR-023](./ADR-023-kerberos-audit-events.md)): PtH defense (PC-038) is now scoped to AD-interop NT hash storage (HSM-PEK protected); server-side PtH is eliminated. SIEM queries for NTLM client auth events provide ongoing monitoring of NTLM usage.

## References

- [PC-036](../catalog/03-auth-provider.md) — problem statement in the catalog
- [Workshop Decision 6 — NTLM Decision](../workshop/decision-06-ntlm-decision.md) — unblocking decision; drop server-side NTLM, client-only via Rust crate
- [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md) — NTLM message flow, NT hash, session security
- [docs/09-linux-equivalents/04-winbind-internals.md](../docs/09-linux-equivalents/04-winbind-internals.md) — winbind architecture (rejected in favor of Rust NTLM client)
- [ADR-011](./ADR-011-rc4-deprecation-aes-default.md) — framework-native users have AES keys only, no NT hash
- [ADR-012](./ADR-012-fast-armoring-required.md) — framework's Kerberos posture is the modern alternative to NTLM
- [ADR-015](./ADR-015-krbtgt-hsm-rotation.md) — HSM binding for PEK (NT hash encryption key)
- [ADR-021](./ADR-021-ldap-signing-channel-binding.md) — NTLM-relay protections now scoped to the NTLM client
- [ADR-023](./ADR-023-kerberos-audit-events.md) — amended with `event_type = "ntlm_client_auth"`
- [ADR-086](./ADR-086-pass-the-hash-defense.md) — full PtH defense specification (PC-038)
- [ADR-087](./ADR-087-s4u-constrained-delegation.md) — full S4U specification (PC-039)
- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) — NTLM Authentication Protocol
- [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) — S4U2Self/S4U2Proxy
- [RFC 4120 §2.6](https://www.rfc-editor.org/rfc/rfc4120#section-2.6) — S4U2Self semantics
- [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) — Channel Bindings for TLS
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) — OAuth 2.0 Token Exchange (rejected as wholesale replacement)
- [MS Security Advisory ADV210003 (PetitPotam)](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003)
- [Microsoft "Restrict NTLM" GPO](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain)
- [Mandiant M-Trends 2023](https://www.mandiant.com/resources/blog/m-trends-2023)
