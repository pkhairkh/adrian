---
title: "Decision 6 — NTLM Decision: Drop Server-Side NTLM; Maintain Client-Only NTLM for Legacy Services"
status: accepted
date: 2026-08-13
deciders: adrian-architecture-team
orqs_resolved: [ORQ-072, ORQ-074, ORQ-075]
gates: 4 deferred problems (1 blocker, 3 high) + 1 partial ADR dependent
tags: [workshop, decision, tier-1, ntlm, auth-provider, pass-the-hash, s4u, legacy-interop]
related:
  - ./CONTEXT.md
  - ../adr/TRIAGE.md
  - ../adr/ADR-021-ldap-signing-channel-binding.md
  - ../adr/ADR-023-kerberos-audit-events.md
  - ../adr/ADR-011-rc4-deprecation-aes-default.md
  - ../adr/ADR-012-fast-armoring-required.md
last_updated: 2026-08-13
---

# Decision 6 — NTLM Decision: Drop Server-Side NTLM; Maintain Client-Only NTLM for Legacy Services

## Status

Accepted — 2026-08-13. This decision resolves Tier-1 ORQ-072 ("Drop NTLM entirely (eliminates PtH)?"), ORQ-074 ("Replace with OAuth2 client-credentials flow?"), and ORQ-075 ("Maintain S4U for AD interop?"). All three ORQs are answered by a single coherent posture: the framework **SHALL NOT** accept NTLM authentication on any framework-hosted service (no NTLM server-side / acceptor role); the framework **SHALL** provide NTLM client-side support for connecting to legacy services that framework-managed clients must reach (NTLM initiator role only); S4U2Self/S4U2Proxy constrained delegation SHALL be preserved via the framework's KDC (per Decision 5), NOT replaced by OAuth2 client-credentials.

This is a synthesis of Options A and C from the candidate set in `workshop/CONTEXT.md`: framework-native auth is NTLM-free (Option A's security posture), with a small client-side NTLM implementation retained for connecting to legacy services (Option C's compat surface), but **without** the Samba winbind sidecar dependency that Option C proposed. The framework's NTLM client is Rust-native, isolated, and does not touch the framework's main auth path.

Decision is final for v1. Revisit only if customer demand during Phase 2 MVP shows >15% of enterprise workloads require NTLM server-side (Spike 4's upper-bound estimate is 5–10%; revisit if real-world adoption exceeds 15%).

## ORQs resolved

- **ORQ-072** — "Drop NTLM entirely (eliminates PtH)?" → **YES, server-side**. The framework SHALL NOT host an NTLM acceptor on any framework service. PtH against framework infrastructure is eliminated.
- **ORQ-074** — "Replace with OAuth2 client-credentials flow?" → **NO, not as a wholesale replacement**. OAuth2 client-credentials is the modern replacement for service-to-service auth in new framework-native applications. Existing AD-aware services that used NTLM SHALL migrate to Kerberos (preferred, via the framework's KDC per Decision 5) or to OAuth2 client-credentials (for non-Kerberos-capable services). S4U2Self/S4U2Proxy is the Kerberos-native constrained-delegation mechanism and SHALL be preserved.
- **ORQ-075** — "Maintain S4U for AD interop?" → **YES**. S4U2Self/S4U2Proxy (RFC 4120 §2.6, MS-SFU) SHALL be implemented in the framework's KDC per Decision 5, `src/mskile/s4u.rs`. S4U is the Kerberos-native constrained-delegation primitive with no NTLM dependency; preserved for AD interop and for new framework-native services.

## Decision

The framework SHALL adopt the following NTLM posture, with five concrete commitments:

### 1. NTLM server-side (acceptor): NOT SUPPORTED

The framework SHALL NOT implement an NTLM acceptor. No framework-hosted service — LDAP server, KDC, REST API, SMB server (per Decision 7 ORQ-154/155 Day 2 PM), HTTP services, cert-service endpoint, federation gateway — SHALL accept NTLM authentication. Clients presenting NTLM tokens to framework services SHALL be rejected with `strongAuthRequired (8)` (LDAP), `401 Unauthorized` with `WWW-Authenticate: Negotiate, Kerberos` (HTTP), or the protocol-equivalent on other surfaces. This eliminates the entire NTLM-relay attack class (per ADR-021) against framework infrastructure: PetitPotam-style coercion cannot relay to framework DCs because framework DCs do not accept NTLM. Pass-the-hash against framework infrastructure is eliminated because no framework service accepts NTLM tokens.

### 2. NTLM client-side (initiator): SUPPORTED for legacy services, via Rust crate

The framework SHALL provide an NTLM client implementation in `crates/adrian-ntlm-client` (~3K lines of Rust), used by framework-managed clients (Linux SSSD-equivalent, macOS PSSO Extension, Windows framework-joined hosts) to authenticate to legacy services that still require NTLM. The NTLM client SHALL support: NTLMv2 (`NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`); NTLMv1 disabled unconditionally. Channel binding per RFC 5929 (`MsvAvChannelBindings` AV_PAIR ID 0x000B, SHA-256 of `tls-server-end-point`) when layered under TLS. EPA (`EPHEMERAL` flag `AvFlags & 0x04`) for non-delegatable sessions. NT hash storage in the platform's secure credential cache: Linux kernel keyring (`keyctl`) / `systemd-creds`; macOS Keychain; Windows DPAPI / Cred Guard.

The NTLM client SHALL NOT cache NT hashes in plaintext; the NT hash is fetched from the platform secure credential store on every NTLM authentication. The framework's main auth path (Kerberos, OAuth2, OIDC) is completely NTLM-free; the NTLM client is invoked only when a service explicitly requires NTLM and Kerberos is unavailable.

### 3. S4U2Self / S4U2Proxy: PRESERVED via framework KDC

S4U2Self (Service-for-User-to-Self, RFC 4120 §2.6, MS-SFU §3.1) — a service obtains a Kerberos ticket to itself on behalf of a user, without the user's TGT. Used for protocol transition (a service that authenticated the user via non-Kerberos means, e.g. client certificate, obtains a Kerberos ticket to itself on the user's behalf).

S4U2Proxy (Service-for-User-to-Proxy, MS-SFU §3.2) — a service forwards the user's identity to a downstream service, with the framework KDC's authorization (constrained delegation). The KDC issues a service ticket for the downstream service to the user, with the requesting service as the proxy; the downstream service sees the user's identity, not the proxy's.

The framework's KDC SHALL implement S4U2Self and S4U2Proxy (per Decision 5, `src/mskile/s4u.rs`). Constrained-delegation policy: a service can S4U2Proxy only to services in its `msDS-AllowedToDelegateTo` (per AD semantics); the KDC SHALL validate the protocol-transition ticket before issuing a S4U2Proxy ticket. This preserves AD-interop for mixed forests and is the constrained-delegation primitive for new framework-native services.

### 4. NT hash storage: HSM-equivalent protection, no plaintext

The framework's directory SHALL NOT store NT hashes in plaintext. NT hashes SHALL be stored encrypted with a key bound to the framework's HSM (the same HSM that holds the krbtgt key per ADR-015). NT hashes are required for AD-interop mode — PC-038 PtH defense is fundamentally about NT hash storage; if NTLM is dropped, PtH goes away, but if AD-interop requires NT hash presence, the hash must be protected.

The framework's NT hash storage SHALL use the same mechanism AD uses (`unicodePwd` attribute, BER-encoded with `"` quotes, encrypted with the directory's PEK — the Password Encryption Key). The framework's PEK SHALL be HSM-bound; the framework SHALL NOT hold the PEK in process memory in plaintext. This matches AD's `ntdsa.dll` PEK handling and is the strongest possible protection short of eliminating the NT hash entirely.

For framework-native users (users created in the framework, not migrated from AD), the framework SHALL NOT derive or store an NT hash at all — only AES Kerberos keys (per ADR-011). NT hashes are derived and stored ONLY for users that require AD-interop (users in mixed forests, users that need to authenticate to legacy NTLM-requiring services).

### 5. Migration path: AD customers using NTLM MUST move to Kerberos before migration

AD customers with NTLM-requiring applications SHALL migrate those applications to Kerberos (or OAuth2/OIDC) BEFORE migrating to the framework. The framework's migration tooling (`adrian-migrate`) SHALL include an `audit-ntlm` command (per Spike 4's deliverable) that scans the AD forest for NTLM-requiring applications and produces a remediation plan, identifying: (a) services with NTLM-only SPNs; (b) applications configured for NTLM auth (IIS apps with `WindowsAuthentication` and `Providers=NTLM`, SQL Server with `Integrated Security=SSPI` and NTLM fallback); (c) event-log evidence of NTLM auth (Windows events 4624 with `Authentication Package = NTLM`); (d) Group Policy `Restrict NTLM` audit-mode events (8004–8020 series).

Customers with applications that cannot be migrated (no Kerberos support, no OAuth2 support) SHALL run those applications in a parallel AD forest during the migration window. The framework does NOT support NTLM server-side; this is a hard constraint of the framework.

**Concrete specification**: No framework-hosted service SHALL accept NTLM authentication (rejected with `strongAuthRequired (8)` or protocol equivalent). `crates/adrian-ntlm-client` SHALL implement NTLMv2 client with NTLMv1 disabled, RFC 5929 channel binding, EPA `EPHEMERAL` flag, and platform-secure-credential-store-backed NT hash storage (Linux `keyctl` / `systemd-creds`, macOS Keychain, Windows DPAPI / Cred Guard); NT hashes SHALL NOT be cached in plaintext. The KDC SHALL implement S4U2Self/S4U2Proxy per Decision 5; constrained-delegation policy SHALL be enforced via `msDS-AllowedToDelegateTo`. The directory SHALL NOT store NT hashes in plaintext — they SHALL be encrypted with an HSM-bound PEK (same HSM as krbtgt per ADR-015); NT hashes SHALL be derived and stored ONLY for AD-interop users; framework-native users have AES Kerberos keys only (per ADR-011). The framework SHALL expose `adrian-migrate audit-ntlm`, `adrian-migrate plan-ntlm`, and `adrian-auth audit-ntlm` CLI commands. The framework SHALL emit an audit event (per ADR-023) for every NTLM client authentication attempt, including: target service, source user, source IP, timestamp, NTLM version, channel-binding flag, EPA flag. SIEM queries for `(event_type = "ntlm_client_auth")` provide NTLM-usage monitoring.

## Rationale

The decision synthesizes Options A (drop) and C (winbind sidecar) from the candidate set, without the winbind dependency. Five arguments drive the synthesis:

**1. Server-side NTLM is the attack surface; client-side NTLM is the compat surface.** The NTLM attack classes — pass-the-hash, relay (PetitPotam, ShadowCoerce, PrinterBug), NTLM spoofing — all require an NTLM acceptor as the target. Without an NTLM acceptor, the attack class has no foothold in framework infrastructure. The NTLM client is not an attack target; it is an attack initiator. Eliminating the server-side NTLM is the high-leverage security control; the client-side NTLM is compat plumbing.

**2. The framework is greenfield; AD-interop customers must migrate.** The framework has no legacy NTLM-dependent codebase to maintain. AD-interop customers with NTLM-requiring apps have a binary choice: migrate the apps to Kerberos/OAuth2 (preferred) OR run those apps in a parallel AD forest during the migration window. Spike 4's audit of 3–5 enterprise deployments found 5–10% of apps hard-require NTLM; for those apps, the parallel-AD-forest option is the migration path. The framework does NOT accommodate NTLM server-side.

**3. Samba winbind is unnecessary.** Option C's winbind sidecar proposed isolating NTLM in a separate daemon, but winbind is heavy (~5K lines of config + operational burden) and inherits Samba's GPLv3 license. The framework's Rust NTLM client (`crates/adrian-ntlm-client`, ~3K lines) is lighter, license-clean, and achieves the same isolation (NT hashes never touch the framework's main auth path). Winbind is rejected.

**4. S4U2Self/S4U2Proxy is the Kerberos-native constrained delegation primitive.** ORQ-074's OAuth2 client-credentials alternative is reasonable for new framework-native services that don't need user-delegation semantics. But for services that need to forward a user's identity (e.g. a web app authenticating the user via cert, then calling a backend SQL database as the user), S4U2Proxy is the Kerberos-native mechanism. OAuth2 client-credentials cannot express "act on behalf of user X" without RFC 8693 token exchange, which is more complex than S4U2Proxy and lacks AD interop. The framework SHALL preserve S4U2Self/S4U2Proxy and SHALL NOT mandate OAuth2 as a wholesale replacement.

**5. PtH defense for AD-interop mode is PEK encryption + HSM, not NT hash elimination.** PC-038 (PtH defense) is fundamentally about NT hash storage. In pure-framework mode, the framework derives no NT hashes and PtH is impossible. In AD-interop mode, the framework stores NT hashes for AD-interop users; PEK encryption with an HSM-bound key is the strongest possible protection (matching AD's `ntdsa.dll` PEK handling, plus HSM binding that AD doesn't have). This is better than AD's PtH defense (Credential Guard on Windows clients, which doesn't protect DCs).

**Counter-argument acknowledged**: dropping NTLM server-side breaks AD-interop for any service that framework-managed clients need to reach and that hard-requires NTLM. The framework's NTLM client mitigates this for outbound auth; for inbound auth (legacy clients authenticating to framework-managed services), the framework requires those clients to use Kerberos or OAuth2. This is a hard constraint; customers that cannot meet it cannot migrate to the framework. Spike 4 found this is <5% of enterprise workloads in modern (Server 2019+) AD forests; the workshop accepts the constraint.

External evidence: [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) (NTLM protocol — framework implements NTLMv2; NTLMv1 disabled); [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) (TLS channel binding `tls-server-end-point`, used for `MsvAvChannelBindings`); [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) (S4U2Self/S4U2Proxy, implemented in framework KDC per Decision 5); [Microsoft Security Advisory ADV210003 (PetitPotam)](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003) (NTLM-relay attack class — framework's NTLM-server-side elimination is the strongest mitigation); [Microsoft "Restrict NTLM" GPO documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain) (audit→enforce migration path that `adrian-migrate audit-ntlm` automates); [Mandiant M-Trends 2023](https://www.mandiant.com/resources/blog/m-trends-2023) (NTLM relay used in ~40% of AD compromises involving lateral movement).

## Trade-offs accepted

- **NTLM-requiring legacy services cannot authenticate TO framework-managed services.** Customers with such services must migrate them to Kerberos/OAuth2 OR run them in a parallel AD forest. <5% of enterprise workloads in modern AD forests are affected (per Spike 4). Hard constraint.
- **NTLM client is a maintenance surface.** `crates/adrian-ntlm-client` (~3K lines) is small but adds maintenance surface. Committed for v1/v2; v3 may deprecate if NTLM usage drops below 1% of authentications (monitor via `adrian-auth audit-ntlm`).
- **S4U2Self/S4U2Proxy adds KDC complexity.** S4U is a known KDC corner case (per Decision 5). The interop test suite validates against Windows S4U clients.
- **NT hash storage is required for AD-interop users.** Pure-framework users have no NT hash (only AES Kerberos keys); AD-interop users have an NT hash, encrypted with an HSM-bound PEK. Smaller attack surface than AD (which derives NT hashes for all users) but not zero. Customers wanting zero NT hashes must run pure-framework mode.
- **Migration path is gated on app modernization.** Customers with NTLM-requiring apps cannot migrate until those apps are modernized. The framework provides tooling (`adrian-migrate audit-ntlm`) to identify the constraint.
- **No Samba-ecosystem fallback.** Samba tools that emit NTLM (`smbclient`, `rpcclient` with NTLM fallback) cannot authenticate TO framework services. Framework-managed clients use the framework's Rust SMB client (per Decision 7 Day 2 PM) which speaks Kerberos natively.

## Rust implementation implications

**Crates used**:

- `adrian-ntlm-client` (framework crate, written from scratch — ~3K lines). NTLMv2 client implementation: NTLMSSP message construction (Type 1 / Type 2 / Type 3), NT hash derivation (MD4 of UTF-16LE password), NTLMv2 response computation (HMAC-MD5 of server challenge with NT hash + client challenge + target info), channel binding computation (SHA-256 of `tls-server-end-point`), EPA `EPHEMERAL` flag handling, platform-secure-credential-store integration.
- `md4` (v0.10+, MIT/Apache-2.0) for NT hash derivation (MD4 of UTF-16LE password). The same crate used by the KDC's RC4 audit path (per Decision 5).
- `hmac` (v0.12+, MIT/Apache-2.0) for HMAC-MD5 (NTLMv2 response) and HMAC-SHA256 (channel binding hash).
- `sha2` (v0.10+, MIT/Apache-2.0) for SHA-256 (channel binding `tls-server-end-point`).
- `rasn` (v0.10+, MIT/Apache-2.0) for ASN.1 parsing of NTLMSSP AV_PAIR structures (most of NTLMSSP is raw byte-packed, not ASN.1).
- `keyring` (v3.0+, MIT/Apache-2.0) for cross-platform secure credential store access: Linux `secret-service` / `keyctl`, macOS Keychain, Windows DPAPI. Wrapped with a platform-specific adapter that prefers `keyctl` / `systemd-creds` on Linux for kernel-level protection.
- `tokio` (v1.40+, MIT) for async NTLM authentication flow (3-message handshake is a `tokio::task`).
- `tracing` (v0.1+, MIT) + `opentelemetry` (v0.24+, MIT) for audit emission per ADR-023.
- `adrian-kdc` (framework crate, per Decision 5) for S4U2Self/S4U2Proxy. S4U is implemented in the KDC, not in a separate crate.

**Crates NOT used**: `ntlm-rs` (v0.7+, MIT/Apache-2.0) — evaluated and rejected; last release 2+ years old, known correctness bugs in NTLMv2 response computation, no channel binding support. Used only as a reference for comparison testing. `libgssapi` (binding to system GSSAPI / MIT krb5 libgssapi_krb5) — rejected; reintroduces the C dependency. `samba-ntlm` (Samba's NTLM code, GPLv3) — rejected; GPLv3.

**Module layout** (`crates/adrian-ntlm-client/src/`): `lib.rs` (public API: `NtlmClient::new(credential_source) -> NtlmClient; authenticate(target) -> Result<NtlmSession>`); `messages.rs` (Type 1 / Type 2 / Type 3 NTLMSSP message construction and parsing); `crypto.rs` (NT hash derivation, NTLMv2 response computation, session-security key derivation); `channel_binding.rs` (RFC 5929 `tls-server-end-point` computation); `credential_store.rs` (platform-specific NT hash storage: `keyctl` on Linux, Keychain on macOS, DPAPI on Windows); `audit.rs` (ADR-023 audit emission).

**Performance targets**: NTLM authentication (3-message handshake) ≤50 ms p99 (network round-trips excluded); NT hash derivation ≤1 ms (MD4 of UTF-16LE password); channel binding hash ≤0.1 ms (SHA-256 over ~100 bytes).

**Testing strategy**: unit tests for NTLMSSP round-trips; property-based tests against `ntlm-rs` (the rejected crate) for cross-implementation validation; interop tests against Windows (framework-managed client → Windows NTLM service) and Samba SMB server; `cargo fuzz` targets for the NTLMSSP message parsers.

## Problems unblocked

| PC | Title (short) | Capability | Severity | Pre-gating ORQ | Now unblocked by Decision 6? |
|----|---------------|-----------|----------|----------------|------------------------------|
| PC-036 | NTLM legacy interop | Auth Provider | high | ORQ-072/074/075 | YES — NTLM client (`crates/adrian-ntlm-client`) provides legacy-interop for framework-managed clients; server-side NTLM not supported (hard constraint) |
| PC-038 | Pass-the-hash (LSASS / Credential Guard) | Auth Provider | blocker | ORQ-072/074/075 | YES — server-side NTLM eliminated (no PtH target); NT hash storage (for AD-interop users) is HSM-PEK-encrypted |
| PC-039 | S4U2Self + S4U2Proxy constrained delegation | Auth Provider | high | ORQ-072/074/075 | YES — S4U2Self/S4U2Proxy implemented in framework KDC per Decision 5; constrained-delegation policy via `msDS-AllowedToDelegateTo` |
| PC-094 | macOS no native NTLM | Cross-Platform Parity | high | ORQ-072/074/075 | YES — framework's NTLM client is cross-platform; macOS uses Keychain for NT hash storage |
| PC-040 | Windows Token vs Linux PAM stack | Auth Provider | high | ORQ-169/170/175/176 + ORQ-202/203 | PARTIAL — NTLM posture defined; auth-stack integration depends on Client SDK (Decision 7) and Linux tier (Decision 8) |
| PC-119 | Silver ticket (service-account hash) | Security | high | ORQ-042/043/044 | UNAFFECTED — gated by KDC decision (Decision 5), not NTLM. Listed for cross-reference; the silver-ticket mitigation (`PAC_BUFFER_TICKET_CHECKSUM`) is in Decision 5 |

Plus partial-ADR dependents that can now be promoted from PARTIAL to full:

- **ADR-021** (LDAP signing + channel binding) — was PARTIAL on the NTLM decision. NTLM-relay protections are now scoped to the NTLM client (channel binding for outbound NTLM); server-side, ADR-021 reduces to LDAP signing + TLS (no NTLM relay possible because no NTLM acceptor). ADR-021 can be promoted.
- **ADR-023** (Kerberos audit events) — was full; this decision adds `event_type = "ntlm_client_auth"` to the ADR's schema. ADR-023 is amended (not promoted) with the new event type.

## Implementation impact

**Person-week estimates per capability**: Auth Provider 8 pw (`crates/adrian-ntlm-client` 4 pw — NTLMv2, channel binding, EPA, credential-store integration; NTLM-server-side rejection 1 pw; `adrian-auth audit-ntlm` CLI 1 pw; S4U enforcement in KDC covered by Decision 5 but authenticated by Auth Provider 1 pw; audit-event emission 1 pw). KDC: covered by Decision 5. Core Directory: 2 pw (NT hash storage with HSM-PEK encryption; PEK binding per ADR-015; `unicodePwd` handling). Client SDK: 2 pw (NTLM client integration into platform auth adapters — Keychain macOS, `keyctl` Linux, DPAPI Windows). Migration: 2 pw (`adrian-migrate audit-ntlm` / `plan-ntlm` CLI tools). Security: 1 pw (SIEM queries for NTLM client auth events; PtH detection reduced to monitoring AD-interop NT hash access).

**Total: 15 person-weeks.** On the Phase 1 → Phase 2 critical path; the NTLM client (4 pw) and `audit-ntlm` tooling (2 pw) are the long poles.

**Risk items**:

- **NTLM-requiring-app adoption.** If real-world customer adoption shows >15% of enterprise workloads hard-require NTLM server-side (Spike 4's upper-bound estimate is 5–10%), the framework may need to revisit. Mitigation: `audit-ntlm` tooling identifies the constraint early; parallel-AD-forest migration path is documented.
- **NTLMv2 interop with Windows.** The NTLM client must produce NTLMv2 responses byte-identical to Windows' `msv1_0.dll` for Windows-hosted NTLM services to accept them. The interop test suite validates this.
- **S4U2Self/S4U2Proxy interop with AD.** S4U is a known AD interop corner case; the KDC must produce S4U tickets that AD accepts and accept S4U tickets that AD issues. The interop test suite (per Decision 5) validates this.
- **NT hash storage compromise.** If the PEK is compromised (HSM breach), all AD-interop NT hashes are exposed. Mitigation: PEK is HSM-bound (per ADR-015); HSM breach is a separate incident class.
- **macOS Keychain reliability.** macOS Keychain has historical reliability issues (prompting, ACL corruption); the NTLM client must handle Keychain failures gracefully (fall back to memory-only session, log audit event).

## Cross-capability dependencies

- **Auth Provider ↔ KDC.** S4U2Self/S4U2Proxy is implemented in the KDC (per Decision 5); the Auth Provider's Kerberos SSPI-equivalent initiates S4U requests.
- **Auth Provider ↔ Core Directory.** NT hash storage in `unicodePwd` with HSM-PEK encryption; `msDS-AllowedToDelegateTo` for S4U2Proxy policy.
- **Auth Provider ↔ Client SDK.** NTLM client integration into platform auth adapters (Keychain, `keyctl`, DPAPI). The Client SDK exposes `NtlmClient::authenticate(target)` as a platform-agnostic API.
- **Auth Provider ↔ File Gateway.** The framework's SMB server (per Decision 7 ORQ-154/155 Day 2 PM) SHALL NOT accept NTLM; framework-managed SMB clients use the framework's NTLM client when connecting to legacy NTLM-requiring SMB servers.
- **Auth Provider ↔ Federation Gateway.** The Federation Gateway (per Decision 8 ORQ-132/133/134 Day 2 PM) SHALL NOT accept NTLM; federation uses OAuth2/OIDC/SAML.
- **Auth Provider ↔ Migration.** `adrian-migrate audit-ntlm` scans AD forests for NTLM-requiring apps; `adrian-migrate plan-ntlm` produces a remediation plan. Migration is gated on remediating NTLM-requiring apps before cutover.
- **Auth Provider ↔ Security.** PtH defense (PC-038) is now scoped to AD-interop NT hash storage (HSM-PEK protected); server-side PtH is eliminated. SIEM queries for NTLM client auth events provide ongoing monitoring of NTLM usage.

## References

- [`workshop/CONTEXT.md`](./CONTEXT.md) — §ORQ-072/074/075 candidate analysis; §Decision criteria
- [`adr/TRIAGE.md`](../adr/TRIAGE.md) — DEFERRED problems PC-036/038/039/094 gated by ORQ-072/074/075
- [`adr/ADR-021-ldap-signing-channel-binding.md`](../adr/ADR-021-ldap-signing-channel-binding.md) — LDAP signing, TLS channel binding, EPA; NTLM-specific protections now scoped to the NTLM client
- [`adr/ADR-023-kerberos-audit-events.md`](../adr/ADR-023-kerberos-audit-events.md) — amended with `event_type = "ntlm_client_auth"`
- [`adr/ADR-011-rc4-deprecation-aes-default.md`](../adr/ADR-011-rc4-deprecation-aes-default.md) — framework-native users have AES keys only, no NT hash
- [`adr/ADR-012-fast-armoring-required.md`](../adr/ADR-012-fast-armoring-required.md) — framework's Kerberos posture is the modern alternative to NTLM
- [`docs/02-protocols/04-ntlm-internals.md`](../docs/02-protocols/04-ntlm-internals.md) — NTLM message flow, NT hash, session security
- [`docs/09-linux-equivalents/04-winbind-internals.md`](../docs/09-linux-equivalents/04-winbind-internals.md) — winbind architecture (rejected in favor of Rust NTLM client)
- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/); [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/); [RFC 4120 §2.6](https://www.rfc-editor.org/rfc/rfc4120#section-2.6); [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929); [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) (OAuth 2.0 Token Exchange — the OAuth2 alternative to S4U2Proxy; rejected as wholesale replacement)
- [MS Security Advisory ADV210003 (PetitPotam)](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003); [Microsoft "Restrict NTLM" GPO](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain); [Mandiant M-Trends 2023](https://www.mandiant.com/resources/blog/m-trends-2023)
