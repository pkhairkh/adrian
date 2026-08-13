---
title: "ADR-014: AES-SHA384 (etype 0x13) Support with Preference over 0x12 (PARTIAL)"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-029
severity: low
tags: [adr, kdc, kerberos, etype, aes, sha384, rfc-8009, partial]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ./ADR-011-rc4-deprecation-aes-default.md
last_updated: 2026-08-13
---

# ADR-014: AES-SHA384 (etype 0x13) Support with Preference over 0x12 (PARTIAL)

## Status

Accepted — 2026-08-13

## Context

[RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) adds `aes256-cts-hmac-sha384-192` (etype 0x13) with stronger HMAC (SHA-384 instead of SHA-1). Server 2022+ KDCs support etype 0x13; older DCs and clients fall back to 0x12 (`aes256-cts-hmac-sha1-96`). PBKDF2 iteration count stays at 4096 for backward compatibility (changing the iteration count would invalidate all existing AES keys), per [PC-029](../catalog/02-kdc.md#pc-029--aes-sha384-etype-0x13-requires-server-2022-kdc-and-clients) and [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Etype 0x13 provides stronger ticket integrity for modern deployments. SHA-1 (used in etype 0x12's HMAC) is considered weak; SHA-384 (used in 0x13) is not. The cryptographic margin matters less than the operational reality: SHA-1 has not been broken for HMAC use (HMAC-SHA1 is still considered secure), so etype 0x12 is not "broken" — 0x13 is forward-looking. However, government / defense deployments with FIPS 140-3 requirements may mandate etype 0x13 (SHA-1 is disallowed in FIPS mode for new deployments).

A framework should default to 0x13 with fallback to 0x12 for legacy clients. The fallback is automatic via [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) etype negotiation (client proposes 0x13 + 0x12; KDC picks the highest mutually-supported). The migration path: update KDC to support 0x13 (one-time), update clients to support 0x13 (gradual), no password reset needed (PBKDF2 derivation is the same for both etypes — the key derivation uses the same password but different HMAC).

This ADR is PARTIAL because two sub-decisions are deferred to Tier-3 ORQ-055/056: (a) the default-etype-change timeline (when does the framework flip from "support both, prefer 0x12" to "support both, prefer 0x13"?); (b) the 0x12 fallback grace period (when does the framework drop 0x12 entirely for clean-slate deployments?). The high-confidence part — support 0x13, prefer it when both endpoints support it — is the Decision.

Constraints from [PC-029](../catalog/02-kdc.md#pc-029--aes-sha384-etype-0x13-requires-server-2022-kdc-and-clients):

- Must support both 0x12 and 0x13.
- PBKDF2 4096 iterations for compatibility (do not change).
- For AD interop, must negotiate 0x13 via RFC 4120 etype negotiation.

## Decision

The framework SHALL support AES-256-CTS-HMAC-SHA384-192 (etype 0x13) per [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009). The framework SHALL prefer etype 0x13 over etype 0x12 when both endpoints (client and KDC) support 0x13. The KDC SHALL negotiate etype per RFC 4120 §3.1.3: the client proposes its supported etypes (in preference order); the KDC picks the highest mutually-supported etype from the principal's `msDS-SupportedEncryptionTypes`.

The framework SHALL derive both 0x12 and 0x13 keys from the same password via PBKDF2-HMAC-SHA1 with 4096 iterations (per RFC 8009 §1). The two etypes use different HMAC algorithms for ticket integrity (SHA-1 for 0x12, SHA-384 for 0x13) but the same PBKDF2 derivation for the base key. No password reset is needed when upgrading from 0x12 to 0x13.

The framework SHALL set the default `msDS-SupportedEncryptionTypes` for new principals to `0x30` (AES128 | AES256) — this is the 0x11/0x12 bitmask; etype 0x13 is not in the bitmask because RFC 8009 reuses the 0x20 (AES256) bit and the etype is negotiated dynamically. The framework's KDC SHALL advertise 0x13 support in the etype negotiation (the KDC's supported etypes list includes 0x13).

For AD-interop mode, the framework SHALL negotiate 0x13 identically to Server 2022+ AD — clients that propose 0x13 (Windows 11+, modern macOS, modern Linux) get 0x13 tickets; clients that propose only 0x12 get 0x12 tickets.

The default-etype-change timeline (when does the framework flip from "support both, prefer 0x12" to "support both, prefer 0x13"?) and the 0x12 fallback grace period (when does the framework drop 0x12 entirely for clean-slate deployments?) are DEFERRED to Tier-3 ORQ-055/056. The v1 default SHALL be "support both, prefer 0x13 when both endpoints support it, fall back to 0x12 otherwise" — this matches Server 2022+ AD behavior.

**Concrete specification**:

- The framework SHALL support etype 0x13 (`aes256-cts-hmac-sha384-192`) per RFC 8009.
- The KDC SHALL prefer 0x13 over 0x12 when both endpoints support 0x13.
- The framework SHALL derive both 0x12 and 0x13 keys via PBKDF2-HMAC-SHA1 with 4096 iterations (per RFC 8009 §1).
- The framework SHALL NOT change the PBKDF2 iteration count (4096) — changing would invalidate existing keys.
- The KDC SHALL negotiate etypes per RFC 4120 §3.1.3: client proposes supported etypes (in preference order); KDC picks highest mutually-supported from principal's `msDS-SupportedEncryptionTypes`.
- The framework SHALL advertise 0x13 support in the KDC's etype negotiation list.
- For AD-interop mode, the framework SHALL negotiate 0x13 identically to Server 2022+ AD.
- The default `msDS-SupportedEncryptionTypes` for new principals SHALL be `0x30` (AES128 | AES256); etype 0x13 is negotiated dynamically (not in the bitmask).
- The framework SHALL NOT disable 0x12 by default — 0x12 is the fallback for clients that don't support 0x13.

## Rationale

Etype 0x13 is the forward-looking Kerberos etype. SHA-1 (used in 0x12's HMAC) is considered weak in general (collision attacks exist for SHA-1 hashes), although HMAC-SHA1 is still considered secure (the collision attacks do not apply to HMAC). Government / defense deployments with FIPS 140-3 requirements may mandate etype 0x13 because SHA-1 is disallowed in FIPS mode for new deployments. Supporting 0x13 with preference over 0x12 future-proofs the framework.

Three alternatives were considered:

**Alternative A — Stay with 0x12 only; do not support 0x13.** The advantage is simpler implementation (one less etype to support). The disadvantage is loss of FIPS 140-3 compliance and loss of forward-looking crypto. Rejected because 0x13 support is straightforward (the PBKDF2 derivation is identical; only the HMAC algorithm differs) and FIPS compliance is a hard requirement for some deployments.

**Alternative B — Default to 0x13 only; drop 0x12.** The advantage is strongest crypto by default. The disadvantage is breaking all clients that don't support 0x13 (older Windows, older macOS, older Linux, some third-party appliances). Rejected for v1; the framework SHALL support both with 0x13 preference. Dropping 0x12 may be considered for a future clean-slate-only deployment mode (deferred to ORQ-056).

**Alternative C — Increase PBKDF2 iteration count beyond 4096 (e.g. 100K).** The advantage is stronger brute-force resistance (PBKDF2 with 100K iterations is 25× more expensive than 4096). The disadvantage is breaking compatibility with AD (which uses 4096) — the framework's KDC could not validate tickets from AD DCs, and AD DCs could not validate tickets from the framework's KDC. Rejected for AD-interop; the framework SHALL match AD's 4096 iteration count. A higher iteration count may be considered for a future clean-slate-only deployment mode.

External evidence: [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) defines etype 0x13; [RFC 4120 §3.1.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3) defines etype negotiation; MIT krb5 1.18+ and Heimdal 7.x+ support 0x13; Server 2022+ AD supports 0x13. The framework's design matches the industry trajectory.

The cost of this decision is implementation effort for 0x13 support (the HMAC-SHA384 code path, the etype negotiation preference, the test matrix). This is a small incremental cost over 0x12 support.

## Consequences

**Positive**: FIPS 140-3 compliance for deployments that mandate it. Forward-looking crypto (SHA-384 instead of SHA-1). No password reset needed when upgrading from 0x12 to 0x13 (PBKDF2 derivation is identical).

**Negative**: Two etypes to support (0x12 and 0x13) means two test surfaces and two security-review surfaces. The 0x13 preference may break clients that propose 0x13 in their supported list but have buggy 0x13 implementations (rare but exists in older MIT krb5 versions).

**Neutral**: The v1 default (support both, prefer 0x13 when both endpoints support it) matches Server 2022+ AD; operators migrating from Server 2022+ see no change. Operators migrating from older AD forests see the etype upgrade on next ticket issuance.

**Implementation cost**: ~2 person-weeks for 0x13 support (HMAC-SHA384 code path, etype negotiation preference, test matrix). This is incremental over 0x12 support.

**Operational impact**: FIPS-required deployments can mandate 0x13 via `msDS-SupportedEncryptionTypes` configuration. Non-FIPS deployments get 0x13 preference automatically with 0x12 fallback. No operator action needed for the upgrade.

## Alternatives Considered

### Alternative 1: Stay with 0x12 only; do not support 0x13

Simpler implementation; loss of FIPS 140-3 compliance and forward-looking crypto. Rejected because 0x13 support is straightforward and FIPS compliance is a hard requirement for some deployments.

### Alternative 2: Default to 0x13 only; drop 0x12

Strongest crypto by default; breaks all clients that don't support 0x13. Rejected for v1; the framework SHALL support both with 0x13 preference. Dropping 0x12 may be considered for a future clean-slate-only deployment mode (deferred to ORQ-056).

### Alternative 3: Increase PBKDF2 iteration count beyond 4096

Stronger brute-force resistance; breaks compatibility with AD (which uses 4096). Rejected for AD-interop; the framework SHALL match AD's 4096 iteration count. A higher iteration count may be considered for a future clean-slate-only deployment mode.

## Open Questions

- **DEFERRED to ORQ-055**: Default-etype-change timeline — when does the framework flip from "support both, prefer 0x12" to "support both, prefer 0x13"? The v1 default is "prefer 0x13 when both endpoints support it"; the timeline for flipping the preference unconditionally is deferred. The gating ORQ is ORQ-055 (per [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md)).
- **DEFERRED to ORQ-056**: 0x12 fallback grace period — when does the framework drop 0x12 entirely for clean-slate deployments? The v1 default is "support 0x12 as fallback"; the timeline for dropping 0x12 is deferred. The gating ORQ is ORQ-056 (per [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md)).
- Should the framework support future etypes (e.g. post-quantum Kerberos per IETF draft)? Defer to a future post-quantum ADR; the framework's etype negotiation is extensible.
- Cross-reference ADR-011 (RC4 deprecation) — the two ADRs are complementary; the framework SHALL support 0x13 + 0x12 by default and disable RC4 by default.

## Cross-capability impact

- **Auth Provider**: Auth Provider's Kerberos SSPI-equivalent MUST support etype 0x13 on the client side.
- **Client SDK**: Client SDK MUST support etype 0x13 on all platforms (Windows 11+, modern macOS, modern Linux). MIT krb5 1.18+ and Heimdal 7.x+ support 0x13.
- **Cert Service**: PKINIT (PC-027, DEFERRED) does not depend on etype 0x13; PKINIT uses cert-based key agreement, not password-derived keys.
- **Operations**: Etype monitoring (per ADR-023 audit events) tracks 0x13 adoption. The audit event for every TGS-REQ includes the etype; SIEM queries can track the 0x13/0x12 ratio.
- **Security**: Etype 0x13 provides stronger ticket integrity (SHA-384 HMAC). This is a security improvement over 0x12.
- **Migration**: AD-to-framework migration preserves `msDS-SupportedEncryptionTypes`; clients that support 0x13 get 0x13 tickets automatically.

## References

- [PC-029](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — Etype table including 0x13, RFC 8009 reference, PBKDF2 iteration count rationale
- [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) — AES Encryption with HMAC-SHA384 for Kerberos
- [RFC 4120 §3.1.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3) — Etype negotiation
- [NIST FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) — FIPS 140-3 (SHA-1 disallowed for new deployments)
