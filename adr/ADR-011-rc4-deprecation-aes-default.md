---
title: "ADR-011: AES-256 Default with RC4-HMAC Disabled by Default"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-024
severity: blocker
tags: [adr, kdc, kerberos, etype, rc4, aes, kerberoasting]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ./ADR-014-aes-sha384-etype-0x13.md
  - ./ADR-023-kerberos-audit-events.md
last_updated: 2026-08-13
---

# ADR-011: AES-256 Default with RC4-HMAC Disabled by Default

## Status

Accepted — 2026-08-13

## Context

RC4-HMAC (etype 0x17) is the default for accounts without `msDS-SupportedEncryptionTypes` set in legacy AD forests. RC4 keys are derived from MD4 of the password (the NT hash) — meaning the long-term key for RC4 is exactly the NT hash, the same value NTLM uses. TGS tickets encrypted with RC4 can be offline-brute-forced: an attacker with a TGS ticket (obtained via a single TGS-REQ with a valid TGT) can attempt to decrypt it by guessing passwords, computing their NT hash, and trying to decrypt. This is the Kerberoasting attack, per [PC-024](../catalog/02-kdc.md#pc-024--rc4-hmac-default-for-backwards-compat-is-a-security-liability-kerberoasting) and [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Server 2022 disables RC4 by default for new accounts (`msDS-SupportedEncryptionTypes` defaults to 0x30 = AES128 | AES256), but legacy service accounts (created before 2022 or migrated from older domains) still have RC4 enabled. AES keys (etype 0x11 / 0x12) are derived via PBKDF2-HMAC-SHA1 with 4096 iterations — offline brute-force is 1000× more expensive than RC4. Cracking a 10-char complex password from an RC4 TGS takes ~8 hours on a single GPU; AES-256 takes years.

A framework that defaults to RC4 inherits the Kerberoasting liability. Mandiant M-Trends 2023 reports Kerberoasting is used in ~60% of AD compromises that involve Kerberos. The attack requires only authenticated-user read access to AD (any authenticated user can request a TGS for any SPN), making it a reliable lateral-movement vector.

Constraints from [PC-024](../catalog/02-kdc.md#pc-024--rc4-hmac-default-for-backwards-compat-is-a-security-liability-kerberoasting):

- Must support RC4 as opt-in for migration (legacy apps that hard-require RC4).
- AES-only default must not break service-account logon for legacy apps (auto-detect AES support on the client; fallback to RC4 with audit-log warning).
- Must support `msDS-SupportedEncryptionTypes` attribute (bitmask: 0x01 DES-CBC-CRC, 0x04 RC4-HMAC, 0x10 AES128, 0x20 AES256).
- For AD interop, the etype negotiation must follow RFC 4120 §3.1.3 (client proposes, KDC picks highest mutually-supported).

## Decision

The framework SHALL default to AES-256-CTS-HMAC-SHA1-96 (etype 0x12) as the primary long-term key derivation algorithm for all principals. The framework SHALL disable RC4-HMAC (etype 0x17) by default — new principals SHALL NOT have RC4 keys derived; the KDC SHALL NOT issue RC4-encrypted TGS tickets for new principals. The framework SHALL provide an audit-logged migration mode (`rc4_compat_mode = "audit"`) in which RC4 is permitted for principals explicitly marked as RC4-required, and every RC4 TGS-REQ is logged as a security event for monitoring.

The default `msDS-SupportedEncryptionTypes` for new principals SHALL be `0x30` (AES128 | AES256), matching Server 2022. Existing principals migrated from legacy AD SHALL retain their existing `msDS-SupportedEncryptionTypes` value (which may include 0x04 RC4-HMAC). The KDC SHALL negotiate the etype per [RFC 4120 §3.1.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3): the client proposes its supported etypes; the KDC picks the highest mutually-supported etype from the principal's `msDS-SupportedEncryptionTypes`.

The framework SHALL provide a CLI command (`adrian-krb5 audit-rc4`) that scans the directory for principals with RC4 enabled and produces a report (principal DN, last-RC4-TGS timestamp, suggested migration action). The framework SHALL provide a migration tool (`adrian-krb5 migrate-rc4 <principal>`) that resets the principal's password (deriving new AES keys) and updates `msDS-SupportedEncryptionTypes` to AES-only, with audit logging.

For AD-interop mode, the framework SHALL honor `msDS-SupportedEncryptionTypes` exactly as AD does — no framework-specific deviations. The framework's KDC SHALL negotiate etypes identically to AD's `kdcsvc.dll`.

The framework SHALL emit an audit event (cross-reference ADR-023) for every RC4 TGS-REQ, including: principal DN, SPN, source IP, timestamp. SIEM queries for `(event_type = "tgs" AND etype = 0x17)` are the Kerberoasting detection signal.

**Concrete specification**:

- The framework SHALL default `msDS-SupportedEncryptionTypes = 0x30` (AES128 | AES256) for all newly-created principals.
- The framework SHALL NOT derive RC4 keys for new principals (no MD4-of-password stored).
- The KDC SHALL refuse to issue RC4-encrypted TGS tickets for principals with `msDS-SupportedEncryptionTypes` not containing `0x04` (RC4).
- The framework SHALL support an `rc4_compat_mode` deployment configuration with values: `"disabled"` (default — RC4 refused for all principals), `"audit"` (RC4 permitted for principals with `0x04` set; every RC4 TGS-REQ logged), `"enforce"` (RC4 permitted for principals with `0x04` set; principals without `0x04` and clients proposing only RC4 are refused with `KDC_ERR_ETYPE_NOTSUPP (18)`).
- The KDC SHALL negotiate etypes per RFC 4120 §3.1.3: client proposes supported etypes; KDC picks highest mutually-supported from principal's `msDS-SupportedEncryptionTypes`.
- For AD-interop mode, the framework SHALL honor `msDS-SupportedEncryptionTypes` exactly as AD does.
- The framework SHALL expose `adrian-krb5 audit-rc4` (scan for RC4-enabled principals) and `adrian-krb5 migrate-rc4 <principal>` (reset password + update etypes) CLI commands.
- The framework SHALL emit an audit event for every RC4 TGS-REQ (principal DN, SPN, source IP, timestamp) per ADR-023.
- DES-CBC-CRC (etype 0x01) and DES-CBC-MD5 (etype 0x02) SHALL be disabled unconditionally; no migration mode. DES is cryptographically broken and has been disabled in AD since Server 2008.

## Rationale

RC4-HMAC's security problem is structural: the long-term key is the NT hash, which is the same value NTLM uses. This means any compromise of the NT hash (LSASS dump, DIT extraction, backup leak) gives the attacker a working Kerberos long-term key for RC4. AES keys, by contrast, are derived via PBKDF2 (4096 iterations) — the NT hash alone does not give the attacker the AES key (they must brute-force the password through PBKDF2, which is 1000× more expensive). Eliminating RC4 by default removes this structural weakness for new deployments.

Three alternatives were considered:

**Alternative A — Hard cut-off date for RC4 (e.g. framework v2.0 removes RC4 entirely).** The advantage is a clean break. The disadvantage is that customers with legacy apps that hard-require RC4 (old Java runtimes, old Python libraries, some third-party appliances) are forced off the framework. Rejected as the sole mechanism; the audit-then-enforce migration mode is the primary path, and a future hard cut-off may be considered for v2.0 based on customer adoption.

**Alternative B — Auto-rotate service accounts to AES on next password change.** The advantage is gradual migration without operator intervention. The disadvantage is silent breakage — if a service account is rotated to AES but a client doesn't support AES, the TGS-REQ fails with `KDC_ERR_ETYPE_NOTSUPP (18)`, and the operator may not correlate the failure to the etype change. Rejected as the sole mechanism; ADOPTED as an option in the `migrate-rc4` CLI tool (operator explicitly chooses which principals to migrate).

**Alternative C — Keep RC4 enabled by default; rely on Kerberoasting detection (audit events).** The advantage is zero migration cost. The disadvantage is that detection is reactive — by the time Kerberoasting is detected, the attacker has the TGS and is offline-cracking. Detection does not prevent the attack; it only shortens the response window. Rejected as the primary mechanism; audit detection is ADOPTED as a complementary control (the audit-then-enforce migration mode).

External evidence: [RFC 4120 §3.1.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3) defines etype negotiation; [RFC 6649](https://www.rfc-editor.org/rfc/rfc6649) deprecates DES; [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) defines AES-CTS-HMAC etypes; Microsoft's [Security Advisory ADV200011](https://msrc.microsoft.com/update-guide/vulnerability/ADV200011) documents the RC4 deprecation trajectory in AD. Mandiant M-Trends 2023 quantifies the Kerberoasting attack frequency. The framework's design matches the industry trajectory.

The cost of this decision is migration effort for customers with legacy apps. The `migrate-rc4` CLI tool and the audit-then-enforce mode provide a controlled migration path; the audit mode gives visibility into which principals still use RC4 before enforcing the disable.

## Consequences

**Positive**: New deployments are Kerberoasting-resistant by default. The PBKDF2 derivation makes offline cracking 1000× more expensive than RC4. The audit-then-enforce migration mode gives operators visibility and control over the migration. The `audit-rc4` CLI provides a clear inventory of RC4-enabled principals.

**Negative**: Customers with legacy apps that hard-require RC4 must migrate the apps before enabling `enforce` mode. The migration may require code/firmware updates (old Java runtimes, old Python libraries, some third-party appliances). The audit mode adds a small per-TGS-REQ overhead (log write).

**Neutral**: The default `0x30` for new principals matches Server 2022, so customers migrating from Server 2022+ AD see no change. Customers migrating from older AD forests see the etype upgrade on first password reset.

**Implementation cost**: ~3 person-weeks for the etype negotiation, `rc4_compat_mode` configuration, `audit-rc4` and `migrate-rc4` CLI tools, and audit-event emission. The bulk of the work is the migration tooling; the etype negotiation itself is straightforward.

**Operational impact**: New deployments are secure by default. Existing deployments run `audit-rc4` to inventory RC4 usage, migrate principals via `migrate-rc4`, then flip `rc4_compat_mode` from `audit` to `enforce`. SIEM queries for RC4 TGS-REQs (per ADR-023) provide ongoing monitoring.

## Alternatives Considered

### Alternative 1: Hard cut-off date for RC4 in framework v2.0

Clean break; forces customers with legacy apps off the framework. Rejected as sole mechanism; audit-then-enforce migration mode is primary. A future hard cut-off may be considered for v2.0 based on customer adoption.

### Alternative 2: Auto-rotate service accounts to AES on next password change

Gradual migration; silent breakage risk. Rejected as sole mechanism; ADOPTED as an option in the `migrate-rc4` CLI tool (operator explicitly chooses which principals to migrate).

### Alternative 3: Keep RC4 enabled by default; rely on Kerberoasting detection

Zero migration cost; detection is reactive (attacker has the TGS by the time detection fires). Rejected as primary; ADOPTED as a complementary control (audit-then-enforce migration mode).

## Open Questions

- What is the timeline for a hard RC4 cut-off in framework v2.0? Defer to a future deprecation ADR based on customer adoption metrics.
- For the `migrate-rc4` CLI tool, should the tool auto-detect AES support on the client side (probe the client's supported etypes) before migrating? Useful but adds complexity; defer to implementation.
- Cross-reference ADR-014 (etype 0x13, AES-SHA384) — the framework should prefer 0x13 over 0x12 when both endpoints support it. The two ADRs are complementary.
- Cross-reference ADR-023 (audit events) — the RC4 TGS-REQ audit event is the Kerberoasting detection signal; the two ADRs are tightly coupled.

## Cross-capability impact

- **Auth Provider**: NTLM uses the same NT hash. RC4 deprecation does not eliminate the NT hash (NTLM still needs it, per PC-036 DEFERRED), but the framework's design preserves the NT hash for AD-interop regardless.
- **Cert Service**: PKINIT (PC-027, DEFERRED) uses cert-based key agreement, not password-derived keys. RC4 deprecation does not affect PKINIT.
- **Operations**: `audit-rc4` and `migrate-rc4` CLI commands are standard ops tasks. SIEM queries for RC4 TGS-REQs are Kerberoasting detection.
- **Security**: Kerberoasting detection (per ADR-023) is the primary security control. The etype upgrade is the preventive control.
- **Migration**: AD-to-framework migration preserves `msDS-SupportedEncryptionTypes`; existing RC4-enabled principals are visible via `audit-rc4` and migrated via `migrate-rc4`.

## References

- [PC-024](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — Etype table, PBKDF2 derivation, `msDS-SupportedEncryptionTypes` bitmask, Kerberoasting attack description
- [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) — AD security posture, RC4 deprecation timeline
- [RFC 4120 §3.1.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3) — Kerberos V5 etype negotiation
- [RFC 6649](https://www.rfc-editor.org/rfc/rfc6649) — DES deprecation
- [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) — AES-CTS-HMAC etypes
- [MS Security Advisory ADV200011](https://msrc.microsoft.com/update-guide/vulnerability/ADV200011) — RC4 deprecation in AD
