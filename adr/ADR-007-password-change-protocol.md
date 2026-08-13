---
title: "ADR-007: kpasswd as Primary Password-Change Protocol; BER-Quote unicodePwd in AD-Compat Mode"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-013
severity: medium
tags: [adr, core-directory, password-change, kpasswd, unicodepwd, ad-interop]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/02-protocols/02-ldap-protocol.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ./ADR-019-kpasswd-password-change.md
last_updated: 2026-08-13
---

# ADR-007: kpasswd as Primary Password-Change Protocol; BER-Quote unicodePwd in AD-Compat Mode

## Status

Accepted — 2026-08-13

## Context

Active Directory password change via LDAP modify on `unicodePwd` requires the value to be the UTF-16LE bytes of a *quoted* password: `"P@ssw0rd!"` becomes 24 bytes including the opening and closing `0x22 0x00` quote characters in UTF-16LE. The quotes are not optional — the DSA rejects unquoted values with `constraintViolation (19)`. TLS is mandatory (the modify must be over LDAPS or after StartTLS); cleartext password modify is rejected. RFC 3062 PasswordModify extended operation is NOT supported by AD — only the modify-on-`unicodePwd` form works, per [PC-013](../catalog/01-core-directory.md#pc-013--unicodepwd-ber-quote-trick-for-password-changes-is-ad-specific), [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md), and [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

This BER-quote trick is unique to AD. OpenLDAP / 389-DS / Samba 4 accept RFC 3062 PasswordModify and also accept unquoted `userPassword`. Existing AD-automation scripts (ldap3 Python library, impacket, custom PowerShell using `System.DirectoryServices.Protocols`, the `Set-ADAccountPassword` cmdlet) all use the BER-quote trick. Switching to RFC 3062 breaks them.

The `unicodePwd` attribute stores the NT hash (MD4 of the UTF-16LE password) — there is no derivation step. The KDC and NTLM SSP both consume the same 16-byte value as the long-term key. A password change is implemented by the DSA computing MD4 of the new UTF-16LE password and storing the result in `unicodePwd`, plus updating `pwdLastSet`, plus urgent-replicating the change to the PDC emulator.

Constraints from [PC-013](../catalog/01-core-directory.md#pc-013--unicodepwd-ber-quote-trick-for-password-changes-is-ad-specific):

- Must support both forms if AD interop is required: BER-quote on `unicodePwd` AND RFC 3062 PasswordModify extended op.
- TLS mandatory in both forms.
- For AD interop, the `unicodePwd` attribute must exist and store the NT hash (so Kerberos / NTLM can use it).
- Must implement urgent replication to PDC emulator on password change (the PDC is the authoritative source for "did the password just change?" lookups).

## Decision

The framework SHALL use kpasswd (RFC 3244) as the primary password-change protocol for all Kerberos-aware clients. The framework SHALL accept the AD BER-quote `unicodePwd` LDAP modify form ONLY in AD-compat mode (an explicit per-deployment configuration flag). The framework SHALL accept RFC 3062 PasswordModify extended operation in both AD-compat and clean-slate modes as a secondary mechanism (useful for non-Kerberos LDAP clients).

In AD-compat mode, the framework SHALL:

1. Accept the BER-quote `unicodePwd` LDAP modify form, validating that the value is UTF-16LE-encoded quoted string of length ≥ 4 bytes (2 quote bytes + ≥ 1 password char + 1 quote byte).
2. Strip the leading and trailing UTF-16LE quote characters (`0x22 0x00`).
3. Compute the NT hash (MD4 of the stripped UTF-16LE password) and store it in `unicodePwd`.
4. Urgent-replicate the password change to the PDC emulator (or the framework's equivalent urgent-replication target).
5. Update `pwdLastSet` to the current time.
6. Enforce TLS (LDAPS or StartTLS) for the modify operation; reject cleartext with `confidentialityRequired (13)`.

In clean-slate mode, the framework SHALL:

1. Reject BER-quote `unicodePwd` LDAP modify with `unwillingToPerform (53)` and a diagnostic message instructing the client to use kpasswd (RFC 3244) or RFC 3062 PasswordModify.
2. Accept RFC 3062 PasswordModify extended operation as the LDAP-side mechanism.
3. Compute and store the NT hash identically to AD-compat mode (the framework's KDC and Auth Provider consume the same `unicodePwd` value).

In both modes, the framework SHALL implement kpasswd (RFC 3244) on TCP/UDP 464 as the primary password-change protocol, per ADR-019. The kpasswd protocol wraps the password-change request in KRB-PRIV encrypted to the user's TGT session key, providing mutual authentication and confidentiality without TLS.

The framework SHALL expose a REST API endpoint (`POST /api/v1/password/change`) for non-Kerberos, non-LDAP clients (web self-service portals, mobile apps). This endpoint requires the caller to authenticate (via existing credentials or MFA) and is implemented as a thin wrapper over the same password-change primitive used by kpasswd and RFC 3062.

**Concrete specification**:

- The framework SHALL implement kpasswd (RFC 3244) on TCP/UDP 464 as the primary password-change protocol (cross-reference ADR-019).
- The framework SHALL accept RFC 3062 PasswordModify extended operation over TLS in both AD-compat and clean-slate modes.
- In AD-compat mode, the framework SHALL accept the BER-quote `unicodePwd` LDAP modify form (UTF-16LE quoted string) over TLS.
- In clean-slate mode, the framework SHALL reject BER-quote `unicodePwd` LDAP modify with `unwillingToPerform (53)`.
- TLS SHALL be mandatory for all LDAP password-change forms; cleartext SHALL be rejected with `confidentialityRequired (13)`.
- The framework SHALL compute the NT hash (MD4 of UTF-16LE password) and store it in `unicodePwd` for AD-interop (so the KDC's RC4 key derivation and NTLM authentication work).
- The framework SHALL urgent-replicate password changes to the PDC emulator (or equivalent urgent-replication target) within 5 seconds.
- The framework SHALL update `pwdLastSet` to the current time on every password change.
- The framework SHALL expose `POST /api/v1/password/change` REST endpoint for non-Kerberos clients, requiring authentication + optional MFA.
- Password-quality validation (length, complexity, history) SHALL be enforced at the DSA layer (not delegated to a client-side filter), in both kpasswd and LDAP paths.

## Rationale

kpasswd (RFC 3244) is the standardized Kerberos password-change protocol, supported by every Kerberos client (Windows `kerberos.dll`, macOS Heimdal, Linux MIT krb5). It provides mutual authentication and confidentiality via KRB-PRIV wrapping, without requiring TLS. It is the natural primary mechanism for any framework that uses Kerberos as its core authentication protocol. AD itself uses kpasswd on TCP/UDP 464 alongside the LDAP BER-quote form — the framework matches this dual-protocol model.

The BER-quote `unicodePwd` form is an AD-specific quirk with no technical merit (the quotes are a defensive measure against LDAP-injection-style attacks where a password starting with a BER structural byte could be misparsed, but this is better handled at the BER layer). Keeping it as the default would propagate an unnecessary wart; rejecting it in clean-slate mode is the right call. Accepting it in AD-compat mode is required for migration scenarios where existing automation scripts use it.

Three alternatives were considered:

**Alternative A — BER-quote `unicodePwd` as the primary form in all modes.** The advantage is byte-identical AD-interop for existing automation scripts. The disadvantage is propagating an AD-specific wart to clean-slate deployments where it has no value. Rejected as the primary form for clean-slate mode; ADOPTED as an AD-compat-only form.

**Alternative B — RFC 3062 PasswordModify as the primary form in all modes; reject BER-quote entirely.** RFC 3062 is the standardized LDAP password-change mechanism. The disadvantage is breaking every existing AD-automation script that uses BER-quote (and there are thousands in large enterprises). Rejected as the *sole* mechanism; ADOPTED as a secondary mechanism in both modes.

**Alternative C — REST API as the primary form; reject both LDAP forms.** Modern, clean, no BER-quote wart, no RFC 3062 complexity. The disadvantage is breaking every existing Kerberos and LDAP client that uses kpasswd or `unicodePwd`. Rejected as the *primary* form; ADOPTED as an *additional* form for non-Kerberos, non-LDAP clients.

External evidence: [RFC 3244](https://www.rfc-editor.org/rfc/rfc3244) defines kpasswd; [RFC 3062](https://www.rfc-editor.org/rfc/rfc3062) defines the LDAP PasswordModify extended operation; [MS-ADTS §3.1.1.3.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents the `unicodePwd` BER-quote form. Samba 4 implements all three; 389-DS / OpenLDAP implement RFC 3062 natively. The framework's design matches the dual-protocol model.

The cost of this decision is implementing three password-change paths (kpasswd, RFC 3062, BER-quote in AD-compat mode) plus the REST wrapper. The bulk of the work is shared: the password-change primitive (hash computation, urgent replication, `pwdLastSet` update, quality validation) is common to all paths. The path-specific work is the protocol-layer wrappers.

## Consequences

**Positive**: Standardized kpasswd works for every Kerberos client without migration. RFC 3062 works for non-Kerberos LDAP clients. BER-quote works in AD-compat mode for existing automation scripts. REST API works for modern non-Kerberos clients. The framework supports all four client populations without forcing migration.

**Negative**: Three protocol paths (kpasswd, RFC 3062, BER-quote) means three test surfaces and three security-review surfaces. The AD-compat mode flag must be clearly documented; operators who enable it without understanding the implications (propagating the BER-quote wart) may create confusion.

**Neutral**: The REST API is additive; deployments that don't use it pay no cost. The clean-slate-mode rejection of BER-quote is a one-line diagnostic in the LDAP modify response.

**Implementation cost**: ~4 person-weeks for kpasswd (cross-reference ADR-019), ~1 person-week for RFC 3062, ~0.5 person-week for BER-quote AD-compat mode, ~1 person-week for REST endpoint. Total ~6 person-weeks; the bulk is shared with ADR-019.

**Operational impact**: Existing AD-automation scripts (ldap3, impacket, `Set-ADAccountPassword`) work in AD-compat mode without modification. New deployments use kpasswd by default, matching modern Kerberos best practice. The REST endpoint enables self-service password-change portals.

## Alternatives Considered

### Alternative 1: BER-quote unicodePwd as primary in all modes

Byte-identical AD-interop; propagates an AD-specific wart to clean-slate deployments. Rejected as primary for clean-slate mode; ADOPTED as AD-compat-only form.

### Alternative 2: RFC 3062 PasswordModify as primary; reject BER-quote entirely

Standardized LDAP mechanism; breaks existing AD-automation scripts. Rejected as sole mechanism; ADOPTED as secondary mechanism in both modes.

### Alternative 3: REST API as primary; reject both LDAP forms

Modern and clean; breaks every existing Kerberos and LDAP client. Rejected as primary; ADOPTED as additional form for non-Kerberos, non-LDAP clients.

## Open Questions

- Should the framework support password-quality validation at the DSA (currently AD delegates this to the LSA filter `pwdmon.dll`)? Yes — the Decision section specifies DSA-layer enforcement. The quality policy (min length, complexity, history) is configurable per-deployment.
- For the REST endpoint, what authentication methods are accepted? Existing password + optional MFA (FIDO2, TOTP) per ADR-018 (KDC horizontal scaling) and future FIDO2 ADR.
- Cross-reference PC-036 (NTLM, DEFERRED) — if NTLM is dropped, the NT hash becomes Kerberos-only and `unicodePwd` is no longer shared with NTLM. The framework's design preserves the NT hash for AD-interop regardless.

## Cross-capability impact

- **KDC**: KDC's long-term key for the user is the NT hash stored in `unicodePwd`. Password change updates the KDC's key immediately via urgent replication.
- **Auth Provider**: NTLM's NT hash is the same value. Password change invalidates existing NTLM sessions on next challenge.
- **Operations**: Password-change monitoring (event 4723 / 4724 equivalent) is emitted on every change. The REST endpoint enables self-service password-reset workflows.
- **Client SDK**: Client SDK exposes kpasswd for password change; the LDAP wrapper exposes RFC 3062 and BER-quote (AD-compat mode).
- **Migration**: Existing AD-automation scripts work in AD-compat mode without modification.

## References

- [PC-013](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md) — `unicodePwd` modify semantics, BER-quote requirement, TLS enforcement
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — kpasswd protocol, KRB-PRIV wrapping, `kadmin/changepw` SPN
- [RFC 3244](https://www.rfc-editor.org/rfc/rfc3244) — Kerberos Change Password and Set Password protocols
- [RFC 3062](https://www.rfc-editor.org/rfc/rfc3062) — LDAP PasswordModify Extended Operation
- [MS-ADTS §3.1.1.3.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — unicodePwd modify semantics
