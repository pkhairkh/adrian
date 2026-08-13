---
title: "ADR-012: FAST (RFC 6806) Armoring Required by Default"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-026
severity: high
tags: [adr, kdc, kerberos, fast, as-rep-roasting, rfc-6806]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ./ADR-011-rc4-deprecation-aes-default.md
  - ./ADR-023-kerberos-audit-events.md
last_updated: 2026-08-13
---

# ADR-012: FAST (RFC 6806) Armoring Required by Default

## Status

Accepted — 2026-08-13

## Context

FAST (Flexible Authentication Secure Tunneling, [RFC 6806](https://www.rfc-editor.org/rfc/rfc6806)) wraps the inner pre-auth in a TGT-armored tunnel encrypted to a TGT the client already holds (the "armor TGT"). This defeats offline password cracking from AS-REP captures (AS-REP roasting) because the inner pre-auth response is encrypted to the FAST armor key, not the user's long-term key, per [PC-026](../catalog/02-kdc.md#pc-026--fast-rfc-6806-armoring-is-opt-in-via-gpo-rarely-enforced) and [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

AD supports FAST since Server 2012 (KDC) and Windows 8 (client). The GPO `Computer Configuration → Policies → Administrative Templates → System → Kerberos → Configure FAST policy` has values "Supported" (default — KDC accepts FAST but doesn't require it) and "Required" (KDC refuses non-FAST AS-REQs). Most deployments leave it at "Supported" (effectively off) because: (a) legacy clients (Windows 7, older Java, older Python) don't support FAST; (b) `Required` breaks those legacy clients; (c) the operational pain of identifying and upgrading every legacy client is high.

AS-REP roasting attacks accounts with `DO_NOT_REQUIRE_PREAUTH` UAC flag set — the KDC issues an AS-REP without pre-auth, and the attacker offline-cracks the response. With FAST-required, even accounts without pre-auth benefit from armoring (the armor TGT prevents the attacker from capturing a useful AS-REP). Anonymous PKINIT armor TGT (RFC 6112) is the alternative for first-logon FAST — the client obtains an anonymous TGT without a password, then uses it as armor for the real AS-REQ.

Constraints from [PC-026](../catalog/02-kdc.md#pc-026--fast-rfc-6806-armoring-is-opt-in-via-gpo-rarely-enforced):

- Must support anonymous PKINIT armor TGT (RFC 6112) for first-logon FAST.
- Must support FAST-required mode (KDC refuses non-FAST AS-REQs).
- Must support FAST-supported mode (KDC accepts both; default for migration).
- For AD interop, must negotiate FAST via `PA-FX-FAST` (padata-type 143) and `PA-FX-FAST-START` (213).

## Decision

The framework SHALL require FAST (RFC 6806) armoring by default for all Kerberos AS-REQs. The KDC SHALL refuse non-FAST AS-REQs by default, returning `KDC_ERR_PREAUTH_REQUIRED (25)` with a hint that FAST is required. The framework SHALL provide an audit-only mode (`fast_mode = "audit"`) in which non-FAST AS-REQs are accepted but logged as security events for monitoring, and a grace-period mode (`fast_mode = "grace"`) that accepts non-FAST AS-REQs for a configurable time window (default 30 days) before flipping to required.

The framework SHALL support anonymous PKINIT armor TGT ([RFC 6112](https://www.rfc-editor.org/rfc/rfc6112)) for first-logon FAST. Clients without an existing TGT (first logon after boot, after TGT expiry) SHALL obtain an anonymous PKINIT TGT from the KDC, then use it as the FAST armor for the real AS-REQ. This requires PKINIT support on the KDC (cross-reference PC-027, DEFERRED) and an Enterprise CA or anonymous-PKINIT-capable cert on the KDC.

For AD-interop mode, the framework SHALL negotiate FAST via `PA-FX-FAST` (padata-type 143) and `PA-FX-FAST-START` (213), byte-identical to AD's `kdcsvc.dll`. The framework SHALL accept the GPO-equivalent configuration `fast_mode` with values: `"supported"` (KDC accepts both FAST and non-FAST), `"required"` (default — KDC refuses non-FAST), `"audit"` (KDC accepts non-FAST but logs), `"grace"` (KDC accepts non-FAST for a configurable window, then required).

The framework SHALL expose a CLI command (`adrian-krb5 audit-fast`) that scans the audit log for non-FAST AS-REQs in the last N days, producing a report (client IP, principal, timestamp, suggested remediation). This report enables operators to identify legacy clients that need upgrading before flipping `fast_mode` from `audit` to `required`.

The framework SHALL emit an audit event (cross-reference ADR-023) for every non-FAST AS-REQ received in `audit` or `grace` mode, including: principal, source IP, timestamp, client-version (if discoverable from the padata). SIEM queries for `(event_type = "as_req" AND fast = false)` are the AS-REP roasting detection signal.

**Concrete specification**:

- The KDC SHALL require FAST armoring by default for all AS-REQs. Non-FAST AS-REQs SHALL be refused with `KDC_ERR_PREAUTH_REQUIRED (25)` and a padata hint indicating FAST is required.
- The framework SHALL support `fast_mode` configuration with values: `"supported"`, `"required"` (default), `"audit"`, `"grace"`.
- The framework SHALL support anonymous PKINIT armor TGT (RFC 6112) for first-logon FAST.
- For AD-interop mode, the framework SHALL negotiate FAST via `PA-FX-FAST` (padata-type 143) and `PA-FX-FAST-START` (213), byte-identical to AD.
- The framework SHALL expose `adrian-krb5 audit-fast` (scan audit log for non-FAST AS-REQs) CLI command.
- The framework SHALL emit an audit event for every non-FAST AS-REQ received in `audit` or `grace` mode, per ADR-023.
- The `grace` mode SHALL accept non-FAST AS-REQs for a configurable time window (default 30 days), after which the KDC flips to `required` mode automatically. The grace-period expiry SHALL be logged as a security event.
- TGS-REQs SHALL also support FAST armoring (optional); the KDC SHALL accept both FAST-armored and non-FAST-armored TGS-REQs. TGS-REQ FAST is not required by default because TGS-REQs are already encrypted to the TGT session key (not the user's long-term key), so they are not vulnerable to AS-REP-roasting-style attacks.

## Rationale

AS-REP roasting is a reliable attack against accounts with `DO_NOT_REQUIRE_PREAUTH`. While the flag is rare on user accounts (default off), it is sometimes set for service accounts that need to log in from legacy clients without pre-auth support. An attacker with read access to AD can enumerate accounts with the flag (`Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`), request AS-REPs for each, and offline-crack. Without FAST, the response is encrypted to the user's NT hash, which is crackable. With FAST, the response is encrypted to the armor key, which the attacker doesn't have.

Three alternatives were considered:

**Alternative A — Keep FAST opt-in (AD's default).** The advantage is zero breakage for legacy clients. The disadvantage is that AS-REP roasting remains viable. Rejected as the default; the audit-then-enforce migration mode is the primary path.

**Alternative B — Drop the `DO_NOT_REQUIRE_PREAUTH` flag entirely (no accounts without pre-auth).** The advantage is that AS-REP roasting is impossible without pre-auth bypass. The disadvantage is that legacy clients that depend on no-pre-auth (rare but exists) break, and the flag has legitimate uses (some smart-card logon flows). Rejected as the sole mechanism; the framework SHALL deprecate the flag (warn on set) but not remove it.

**Alternative C — Token-binding via TLS exporter ([RFC 9266](https://www.rfc-editor.org/rfc/rfc9266)) instead of FAST.** The advantage is no Kerberos-protocol-layer change — the ticket is bound to the TLS session, defeating relay without DC roundtrip. The disadvantage is that TLS exporter binding protects against relay, not against AS-REP-roasting-style offline cracking. FAST addresses both (offline cracking and relay); TLS exporter addresses only relay. Rejected as a replacement for FAST; ADOPTED as a complementary control for HTTP-based Kerberos (the framework SHOULD support both FAST for AS-REQ and TLS exporter for HTTP-based TGS use).

External evidence: [RFC 6806](https://www.rfc-editor.org/rfc/rfc6806) defines FAST; [RFC 6112](https://www.rfc-editor.org/rfc/rfc6112) defines anonymous PKINIT armor TGT; [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266) defines TLS channel binding for GSS-API; MIT krb5 1.10+ and Heimdal 1.5+ support FAST. Microsoft's [Security Advisory for AS-REP roasting](https://msrc.microsoft.com/update-guide/vulnerability/ADV200011) documents the attack and recommends FAST-required as the mitigation. The framework's design matches the industry trajectory.

The cost of this decision is migration effort for legacy clients. The `audit-fast` CLI and the grace-period mode provide a controlled migration path; the audit mode gives visibility into which clients don't support FAST before enforcing.

## Consequences

**Positive**: AS-REP roasting is defeated by default. Anonymous PKINIT armor TGT enables first-logon FAST without requiring pre-existing TGTs. The audit-then-grace-then-required migration path is operator-friendly.

**Negative**: Legacy clients that don't support FAST (Windows 7, old Java, old Python, some third-party appliances) cannot authenticate in `required` mode. The audit and grace modes provide a migration window, but ultimately these clients must be upgraded. Anonymous PKINIT requires PKINIT support on the KDC (cross-reference PC-027, DEFERRED), which adds a PKI dependency.

**Neutral**: The default `required` mode matches the security-first posture; the `supported` mode is available for AD-interop deployments that need to support legacy clients during migration.

**Implementation cost**: ~4 person-weeks for the FAST-required enforcement, anonymous PKINIT armor TGT, `fast_mode` configuration, `audit-fast` CLI, and audit-event emission. The bulk of the work is anonymous PKINIT armor TGT (depends on PKINIT support, which is gated by PC-027).

**Operational impact**: New deployments are AS-REP-roasting-resistant by default. Existing deployments run `audit-fast` to inventory non-FAST clients, upgrade clients, then flip `fast_mode` from `audit` to `grace` to `required`. SIEM queries for non-FAST AS-REQs (per ADR-023) provide ongoing monitoring.

## Alternatives Considered

### Alternative 1: Keep FAST opt-in (AD's default)

Zero breakage for legacy clients; AS-REP roasting remains viable. Rejected as default; audit-then-enforce migration mode is primary.

### Alternative 2: Drop `DO_NOT_REQUIRE_PREAUTH` flag entirely

AS-REP roasting impossible without pre-auth bypass; breaks legacy clients that depend on no-pre-auth. Rejected as sole mechanism; the framework SHALL deprecate the flag (warn on set) but not remove it.

### Alternative 3: Token-binding via TLS exporter (RFC 9266) instead of FAST

No Kerberos-protocol-layer change; protects against relay but not AS-REP-roasting-style offline cracking. Rejected as replacement for FAST; ADOPTED as complementary control for HTTP-based Kerberos.

## Open Questions

- What is the timeline for anonymous PKINIT armor TGT support? It depends on PKINIT support on the KDC (cross-reference PC-027, DEFERRED). The framework MAY ship with `fast_mode = "supported"` as the default until PKINIT is implemented, then flip to `required`.
- For the `grace` mode, what is the default grace period? 30 days is the Decision section's default; should it be configurable per-deployment? Yes — operators in regulated environments may need longer grace periods.
- Cross-reference ADR-011 (RC4 deprecation) — both ADRs assume the framework's clients support modern Kerberos. The two ADRs are complementary and should be migrated together.
- Cross-reference ADR-023 (audit events) — the non-FAST AS-REQ audit event is the AS-REP-roasting detection signal; the two ADRs are tightly coupled.

## Cross-capability impact

- **Cert Service**: Anonymous PKINIT armor TGT requires an Enterprise CA or anonymous-PKINIT-capable cert on the KDC. This is gated by PC-027 (PKINIT, DEFERRED).
- **Auth Provider**: FAST armoring affects the Auth Provider's Kerberos SSPI-equivalent — the provider MUST support FAST on the client side.
- **Client SDK**: Client SDK MUST support FAST on all platforms (Windows, macOS, Linux). MIT krb5 1.10+, Heimdal 1.5+, and Windows 8+ all support FAST; the SDK must enforce it.
- **Operations**: `audit-fast` and the grace-period mode are standard ops tasks. SIEM queries for non-FAST AS-REQs are AS-REP-roasting detection.
- **Security**: AS-REP-roasting detection (per ADR-023) is the primary security control. FAST-required is the preventive control.

## References

- [PC-026](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — FAST architecture, `PA-FX-FAST` padata type, anonymous PKINIT armor TGT
- [RFC 6806](https://www.rfc-editor.org/rfc/rfc6806) — FAST (Flexible Authentication Secure Tunneling)
- [RFC 6112](https://www.rfc-editor.org/rfc/rfc6112) — Anonymous PKINIT
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266) — GSS-API Channel Binding
- [MS Security Advisory ADV200011](https://msrc.microsoft.com/update-guide/vulnerability/ADV200011) — AS-REP roasting mitigation
