---
title: "ADR-021: LDAP Signing, TLS Channel Binding (RFC 5929), and EPA Mandatory by Default"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Auth Provider
problem: PC-037
severity: blocker
tags: [adr, auth-provider, ntlm-relay, ldap-signing, channel-binding, epa, rfc-5929]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/03-auth-provider.md
  - ../docs/02-protocols/04-ntlm-internals.md
  - ../docs/02-protocols/02-ldap-protocol.md
  - ./ADR-023-kerberos-audit-events.md
last_updated: 2026-08-13
---

# ADR-021: LDAP Signing, TLS Channel Binding (RFC 5929), and EPA Mandatory by Default

## Status

Accepted — 2026-08-13

## Context

NTLM relay places an attacker in the middle: the attacker opens a connection to a target service, then诱诱 a victim to authenticate to the attacker (e.g. via malicious SMB share, HTTP page, or coerce-auth via PetitPotam / ShadowCoerce / PrinterBug). The attacker forwards the victim's Type 1 / 2 / 3 messages verbatim to the target service. The target service validates against the victim's NT hash (which the attacker doesn't need). End result: the attacker is authenticated to the target as the victim, per [PC-037](../catalog/03-auth-provider.md#pc-037--ntlm-relay-attacks-require-ldap-signing--channel-binding--epa-enforcement), [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md), and [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md).

Mitigations: (a) SMB signing required — relayed SMB traffic fails signature check because the attacker cannot recompute signatures without the session key (the attacker never has the session key — it's derived from the victim's NT hash via `HMAC-MD5(SessionBaseKey, ServerChallenge ++ ClientChallenge)`); (b) LDAP signing + channel binding (EPA) — same mechanism for LDAP; (c) `Restrict NTLM` GPOs (audit→enforce); (d) Extended Protection for Authentication (EPA) — channel binding for HTTP / LDAPS / RPC. The famous AD CS LDAP endpoint relay (PetitPotam) used NTLM relay to coerce DCs to authenticate to the attacker's NTLM relay, then to the AD CS HTTP endpoint, then request a DC certificate — leading to full forest compromise via AD CS.

Channel binding works as follows: when NTLM is layered under TLS (e.g. LDAPS, HTTPS, SMB 3.1.1), the client computes `MsvAvChannelBindings` (AV_PAIR ID 0x000B) as `SHA-256(channel_bindings)` where `channel_bindings` is the `initiator_address_type || initiator_address || acceptor_address_type || acceptor_address || application_data`. For TLS, this is the `tls-server-end-point` channel binding type ([RFC 5929](https://www.rfc-editor.org/rfc/rfc5929)): `SHA-256(server_cert_signature_algorithm_oid || server_cert_signature)`. The server includes `MsvAvChannelBindings` in its Type 2 TargetInfo (with the expected hash precomputed from its TLS cert), and the client includes the same in its Type 3. If the hashes differ (MITM with their own cert), the server rejects.

Constraints from [PC-037](../catalog/03-auth-provider.md#pc-037--ntlm-relay-attacks-require-ldap-signing--channel-binding--epa-enforcement):

- Must support `MsvAvChannelBindings` (SHA-256 of TLS channel bindings) in NTLMSSP Type 2 / Type 3.
- Must support `EPHEMERAL` flag (`AvFlags & 0x04`) for non-delegatable sessions.
- Must support LDAP signing required (server-side enforcement; `LDAPClientIntegrity = 2` registry).
- Must support SMB signing required (server-side enforcement; `srvsigning = mandatory`).
- For AD interop, must implement RFC 5929 channel binding for NTLM-over-TLS.

## Decision

The framework SHALL require LDAP signing and TLS channel binding ([RFC 5929](https://www.rfc-editor.org/rfc/rfc5929)) on all DC LDAP connections. The framework SHALL mandate Extended Protection for Authentication (EPA) on all HTTP, LDAP, and SMB services. The framework SHALL reject clients that do not support these protections.

Specifically:

1. **LDAP signing required.** The framework's LDAP server SHALL require LDAP signing (server-side enforcement) on all LDAP connections (port 389 and 636). Clients that do not support LDAP signing SHALL be rejected with `strongAuthRequired (8)`. This matches AD's `LDAPClientIntegrity = 2` registry setting.

2. **LDAP channel binding required.** The framework's LDAPS server SHALL require TLS channel binding ([RFC 5929](https://www.rfc-editor.org/rfc/rfc5929)) on all LDAPS connections (port 636 and 3269). Clients that do not provide `MsvAvChannelBindings` in their NTLMSSP Type 3 (or whose channel-binding hash does not match the server's TLS cert) SHALL be rejected with `strongAuthRequired (8)`. This matches AD's `LdapEnforceChannelBinding = 2` registry setting (Server 2019+).

3. **SMB signing required.** The framework's SMB server SHALL require SMB signing (server-side enforcement) on all SMB connections. Clients that do not support SMB signing SHALL be rejected at SMB negotiate. This matches AD's `srvsigning = mandatory` setting.

4. **EPA on all HTTP services.** The framework's HTTP services (the REST API, the self-service password-change portal, the AD CS HTTP endpoint if deployed) SHALL require Extended Protection for Authentication (EPA) — channel binding for HTTP-over-TLS. Clients that do not support EPA SHALL be rejected.

5. **`EPHEMERAL` flag for non-delegatable sessions.** The framework's NTLMSSP implementation SHALL set the `EPHEMERAL` flag (`AvFlags & 0x04`) in the Type 2 TargetInfo for sessions that are not delegatable (the default for NTLM relay-vulnerable sessions). This prevents the relayed session from being delegated to a downstream service.

The framework SHALL provide an audit-only mode (`relay_protection = "audit"`) in which clients without LDAP signing / channel binding / EPA are accepted but logged as security events for monitoring. The framework SHALL provide an enforce mode (`relay_protection = "enforce"`, the default) in which such clients are rejected. The framework SHALL provide a grace-period mode (`relay_protection = "grace"`) that accepts such clients for a configurable time window (default 30 days) before flipping to enforce.

For AD-interop mode, the framework SHALL implement RFC 5929 channel binding for NTLM-over-TLS byte-identically to AD's `msv1_0.dll`. The framework SHALL accept `MsvAvChannelBindings` (AV_PAIR ID 0x000B) in NTLMSSP Type 3 and SHALL validate the hash against the server's TLS cert.

The framework SHALL expose a CLI command (`adrian-auth audit-relay`) that scans the audit log for unprotected-client connections (no LDAP signing, no channel binding, no EPA) in the last N days, producing a report (client IP, user, protocol, timestamp, suggested remediation). This report enables operators to identify legacy clients that need upgrading before flipping `relay_protection` from `audit` to `enforce`.

The framework SHALL emit an audit event (cross-reference ADR-023) for every unprotected-client connection received in `audit` or `grace` mode, including: protocol (LDAP, LDAPS, SMB, HTTP), client IP, user (if authenticated), timestamp, missing protection (signing, channel binding, EPA).

**Concrete specification**:

- The framework's LDAP server SHALL require LDAP signing on all connections (ports 389, 636). Clients without LDAP signing SHALL be rejected with `strongAuthRequired (8)`.
- The framework's LDAPS server SHALL require TLS channel binding (RFC 5929) on all connections (ports 636, 3269). Clients without `MsvAvChannelBindings` (or with mismatched hash) SHALL be rejected with `strongAuthRequired (8)`.
- The framework's SMB server SHALL require SMB signing on all connections. Clients without SMB signing SHALL be rejected at SMB negotiate.
- The framework's HTTP services SHALL require EPA (channel binding for HTTP-over-TLS). Clients without EPA SHALL be rejected.
- The framework's NTLMSSP implementation SHALL set the `EPHEMERAL` flag (`AvFlags & 0x04`) for non-delegatable sessions.
- The framework SHALL support `relay_protection` configuration with values: `"audit"` (accept unprotected clients, log), `"enforce"` (default — reject unprotected clients), `"grace"` (accept for configurable window, then enforce).
- For AD-interop mode, the framework SHALL implement RFC 5929 channel binding byte-identically to AD's `msv1_0.dll`.
- The framework SHALL expose `adrian-auth audit-relay` CLI command (scan audit log for unprotected clients).
- The framework SHALL emit an audit event for every unprotected-client connection in `audit` or `grace` mode, per ADR-023.
- The `grace` mode SHALL accept unprotected clients for a configurable time window (default 30 days), after which the framework flips to `enforce` mode automatically. The grace-period expiry SHALL be logged as a security event.

## Rationale

NTLM relay is the dominant lateral-movement technique after initial compromise. Mandiant M-Trends 2023 reports NTLM relay is used in ~40% of AD compromises that involve lateral movement. The PetitPotam attack (2021) used NTLM relay to coerce DCs to authenticate to AD CS, then request DC certificates — leading to full forest compromise in <30 minutes from initial access. Without LDAP signing + channel binding required by default, the framework's DCs are vulnerable to the same attack.

Three alternatives were considered:

**Alternative A — Opt-in relay protection (compat-first).** LDAP signing and channel binding are configurable but off by default. The advantage is zero breakage for legacy clients. The disadvantage is that the framework's default posture is vulnerable to NTLM relay. Rejected as the default; the enforce-then-grace-then-audit migration mode is the primary path.

**Alternative B — Drop NTLM entirely (eliminates relay).** Without NTLM, there is no NTLM relay. The disadvantage is breaking every legacy client that uses NTLM (older Windows, some third-party appliances, some service accounts). This is gated by the NTLM decision (PC-036, DEFERRED per Tier-1 ORQ-072/074/075). Rejected for v1 because the NTLM decision is deferred; the framework SHALL support NTLM (with relay protections) until the NTLM decision is made.

**Alternative C — Token-binding via TLS exporter ([RFC 9266](https://www.rfc-editor.org/rfc/rfc9266)) instead of NTLMSSP channel binding.** TLS exporter binding protects against relay without requiring NTLMSSP-layer changes. The disadvantage is that it requires TLS 1.3+ (TLS exporter is defined for TLS 1.3) and client-side support (which is not universal). Rejected as a replacement for NTLMSSP channel binding; ADOPTED as a complementary control for HTTP-based Kerberos (the framework SHOULD support both NTLMSSP channel binding for NTLM and TLS exporter for Kerberos-over-HTTP).

External evidence: [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) defines TLS channel binding; [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) documents NTLMSSP channel binding (`MsvAvChannelBindings`); Microsoft's [Security Advisory for PetitPotam](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003) documents the attack and recommends LDAP signing + channel binding as the mitigation. The framework's design matches the industry best practice.

The cost of this decision is migration effort for legacy clients. The `audit-relay` CLI and the grace-period mode provide a controlled migration path; the audit mode gives visibility into which clients don't support the protections before enforcing.

## Consequences

**Positive**: NTLM relay is defeated by default. PetitPotam-style attacks against the framework's DCs fail. The audit-then-grace-then-enforce migration path is operator-friendly. The `audit-relay` CLI provides a clear inventory of legacy clients.

**Negative**: Legacy clients that don't support LDAP signing / channel binding / EPA (older Windows, some third-party appliances) cannot connect in `enforce` mode. The audit and grace modes provide a migration window, but ultimately these clients must be upgraded. The HTTP EPA requirement may break legacy web clients that don't send the channel-binding header.

**Neutral**: The default `enforce` mode matches the security-first posture; the `audit` and `grace` modes are available for AD-interop deployments that need to support legacy clients during migration. AD's Server 2019+ defaults to `LdapEnforceChannelBinding = 2` (required); the framework matches this.

**Implementation cost**: ~5 person-weeks for the LDAP signing enforcement, TLS channel binding validation, SMB signing enforcement, HTTP EPA enforcement, `relay_protection` configuration, `audit-relay` CLI, and audit-event emission. The bulk of the work is the channel-binding hash validation and the EPA enforcement on HTTP.

**Operational impact**: New deployments are NTLM-relay-resistant by default. Existing deployments run `audit-relay` to inventory unprotected clients, upgrade clients, then flip `relay_protection` from `audit` to `grace` to `enforce`. SIEM queries for unprotected-client connections (per ADR-023) provide ongoing monitoring.

## Alternatives Considered

### Alternative 1: Opt-in relay protection (compat-first)

Zero breakage for legacy clients; default posture vulnerable to NTLM relay. Rejected as default; enforce-then-grace-then-audit migration mode is primary.

### Alternative 2: Drop NTLM entirely (eliminates relay)

No NTLM relay without NTLM; breaks every legacy client that uses NTLM. Gated by the NTLM decision (PC-036, DEFERRED per Tier-1 ORQ-072/074/075). Rejected for v1; the framework SHALL support NTLM (with relay protections) until the NTLM decision is made.

### Alternative 3: Token-binding via TLS exporter (RFC 9266) instead of NTLMSSP channel binding

No NTLMSSP-layer changes; requires TLS 1.3+ and client-side support. Rejected as replacement for NTLMSSP channel binding; ADOPTED as complementary control for HTTP-based Kerberos.

## Open Questions

- For the `grace` mode, what is the default grace period? 30 days is the Decision section's default; should it be configurable per-deployment? Yes — operators in regulated environments may need longer grace periods.
- For HTTP EPA, what is the exact header format? The `Authorization: Negotiate` header includes the NTLMSSP Type 3 with `MsvAvChannelBindings`; the HTTP server validates the hash against the TLS cert. This is standard RFC 5929 behavior; no framework-specific extension.
- Cross-reference PC-036 (NTLM, DEFERRED) — if NTLM is dropped, this ADR's NTLM-specific protections become moot. The framework's design preserves the protections regardless; if NTLM is dropped, the protections are simply unused.
- Cross-reference ADR-023 (audit events) — the unprotected-client-connection audit event is the NTLM-relay detection signal; the two ADRs are tightly coupled.

## Cross-capability impact

- **KDC**: KDC is not directly affected (Kerberos has its own relay protections via mutual auth). However, the framework's LDAP server (which the KDC may use for principal lookup) benefits from the LDAP signing + channel binding enforcement.
- **Cert Service**: The AD CS HTTP endpoint is the famous relay target (PetitPotam). The framework's Cert Service HTTP endpoint SHALL require EPA, eliminating the PetitPotam attack vector.
- **File Gateway**: SMB signing enforcement on the File Gateway's SMB server is mandatory; clients without SMB signing are rejected.
- **Operations**: `audit-relay` and the grace-period mode are standard ops tasks. SIEM queries for unprotected-client connections are NTLM-relay detection.
- **Security**: NTLM-relay detection (per ADR-023) is the primary security control. The enforce mode is the preventive control.
- **Migration**: AD-to-framework migration requires client-side relay-protection support. Clients that don't support LDAP signing / channel binding / EPA must be upgraded before migration.

## References

- [PC-037](../catalog/03-auth-provider.md) — problem statement in the catalog
- [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md) — Full NTLM relay attack description, MIC mechanism, channel binding computation, `MsvAvChannelBindings` AV_PAIR
- [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md) — LDAP signing, LDAPS channel binding
- [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929) — Channel Bindings for TLS
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266) — GSS-API Channel Bindings
- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) — NTLM Authentication Protocol
- [MS Security Advisory ADV210003 (PetitPotam)](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003)
