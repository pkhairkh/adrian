---
title: "ADR-019: kpasswd (RFC 3244) as Primary Password-Change Protocol with REST Wrapper"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-034
severity: medium
tags: [adr, kdc, kpasswd, password-change, rfc-3244, rest-api]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/02-protocols/07-ntp-time-sync.md
  - ./ADR-007-password-change-protocol.md
last_updated: 2026-08-13
---

# ADR-019: kpasswd (RFC 3244) as Primary Password-Change Protocol with REST Wrapper

## Status

Accepted — 2026-08-13

## Context

Active Directory uses kpasswd ([RFC 3244](https://www.rfc-editor.org/rfc/rfc3244)) on TCP/UDP 464 for password changes. The protocol uses KRB-PRIV wrapping: the client encrypts the password-change request to the kpasswd service (`kadmin/changepw` SPN) using a key derived from the user's TGT session key. The kpasswd service (running on the KDC) validates the request, calls the DSA to update `unicodePwd`, urgent-replicates the change to the PDC, and returns a success / failure code, per [PC-034](../catalog/02-kdc.md#pc-034--kpasswd-rfc-3244-is-the-only-standardized-password-change-protocol-ui-integration-varies), [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), and [docs/02-protocols/07-ntp-time-sync.md](../docs/02-protocols/07-ntp-time-sync.md).

All major clients (Windows `kerberos.dll`, macOS Heimdal, Linux MIT krb5) support kpasswd. UI integration varies: Windows uses Ctrl+Alt+Del → Change Password (which calls kpasswd under the hood); macOS uses System Settings → Users & Groups → Change Password; Linux uses `passwd` via PAM (which calls kpasswd via `pam_krb5`). The kpasswd protocol returns `KRB5KDC_ERR_KEY_EXPIRED` for must-change passwords — the client then prompts for a new password.

A framework must support kpasswd (the standard) and consider modern alternatives (self-service portal, OAuth-backed password reset). The self-service portal is a web app that authenticates the user (via existing credentials or MFA) and calls the directory's password-change API directly. OAuth-backed password reset uses OAuth2 / OIDC scopes (e.g. `password:reset`) to authorize a password-reset flow.

Constraints from [PC-034](../catalog/02-kdc.md#pc-034--kpasswd-rfc-3244-is-the-only-standardized-password-change-protocol-ui-integration-varies):

- Must support TCP/UDP 464.
- KRB-PRIV wrapping (the request and response are encrypted to the user's TGT session key).
- Returns `KRB5KDC_ERR_KEY_EXPIRED` for must-change passwords (the client prompts for new password).
- Returns `KRB5KDC_ERR_POLICY` for policy violations (password too short, password in history, etc.).
- For AD interop, must support the `kadmin/changepw` SPN.

## Decision

The framework SHALL implement kpasswd ([RFC 3244](https://www.rfc-editor.org/rfc/rfc3244)) as the primary password-change protocol for all Kerberos-aware clients. The kpasswd service SHALL run on TCP/UDP 464, co-located with the KDC (the same process or a sibling process). The kpasswd service SHALL accept KRB-PRIV-wrapped password-change requests encrypted to the user's TGT session key, validate the request, call the DSA to update `unicodePwd` (computing the NT hash per ADR-007), urgent-replicate the change to the PDC (or the framework's equivalent urgent-replication target), and return the standard RFC 3244 success / failure codes.

The framework SHALL support the standard kpasswd result codes: `KRB5KDC_ERR_KEY_EXPIRED` (must-change password — the client prompts for new password), `KRB5KDC_ERR_POLICY` (policy violation — password too short, password in history, etc., with a diagnostic message), `KRB5KRB_AP_ERR_BAD_INTEGRITY` (KRB-PRIV decryption failed), `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` (principal not found). The framework SHALL return policy-violation details in the RFC 3244 result-text field (e.g. "Password too short (minimum 12 characters)") so the client can display a useful error to the user.

The framework SHALL expose a REST API endpoint (`POST /api/v1/password/change`) as a modern alternative for non-Kerberos clients (web self-service portals, mobile apps). This endpoint requires the caller to authenticate (via existing credentials — current password, TGT, or OIDC access token) and optionally MFA (FIDO2, TOTP). The endpoint calls the same password-change primitive as kpasswd, ensuring consistent policy enforcement and audit logging across both paths.

The framework SHALL expose a CLI command (`adrian-krb5 passwd <principal>`) that calls kpasswd under the hood (for interactive use). The CLI SHALL prompt for the current password and the new password, derive the TGT session key from the current password, and send the kpasswd request.

For AD-interop mode, the framework SHALL support the `kadmin/changepw` SPN (registered on the kpasswd service account) and SHALL negotiate kpasswd identically to AD's `kdcsvc.dll`. The framework's kpasswd service SHALL accept requests from Windows `kerberos.dll`, macOS Heimdal, and Linux MIT krb5 without modification.

The framework SHALL enforce password-quality validation (length, complexity, history) at the kpasswd service layer, matching the validation performed at the DSA layer for LDAP password changes (per ADR-007). The validation SHALL be identical across kpasswd, RFC 3062 PasswordModify, BER-quote `unicodePwd`, and the REST endpoint — all paths use the same validation module.

**Concrete specification**:

- The framework SHALL implement kpasswd (RFC 3244) on TCP/UDP 464, co-located with the KDC.
- The kpasswd service SHALL accept KRB-PRIV-wrapped password-change requests encrypted to the user's TGT session key.
- The kpasswd service SHALL call the DSA to update `unicodePwd` (computing the NT hash per ADR-007) and urgent-replicate to the PDC.
- The kpasswd service SHALL return the standard RFC 3244 result codes: `KRB5KDC_ERR_KEY_EXPIRED`, `KRB5KDC_ERR_POLICY`, `KRB5KRB_AP_ERR_BAD_INTEGRITY`, `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN`.
- The kpasswd service SHALL return policy-violation details in the RFC 3244 result-text field.
- The framework SHALL expose `POST /api/v1/password/change` REST endpoint for non-Kerberos clients, requiring authentication (current password, TGT, or OIDC access token) + optional MFA.
- The REST endpoint SHALL call the same password-change primitive as kpasswd, ensuring consistent policy enforcement and audit logging.
- The framework SHALL expose `adrian-krb5 passwd <principal>` CLI command (interactive, calls kpasswd under the hood).
- For AD-interop mode, the framework SHALL support the `kadmin/changepw` SPN and SHALL negotiate kpasswd identically to AD.
- The framework SHALL enforce password-quality validation (length, complexity, history) identically across kpasswd, RFC 3062, BER-quote `unicodePwd`, and the REST endpoint.
- Performance target: kpasswd SHALL handle ≥1K password changes per second per KDC instance.

## Rationale

kpasswd is the standardized Kerberos password-change protocol, supported by every Kerberos client. It provides mutual authentication and confidentiality via KRB-PRIV wrapping, without requiring TLS. AD itself uses kpasswd on TCP/UDP 464 — the framework matches this. The REST endpoint is an addition for modern non-Kerberos clients (web portals, mobile apps) that do not have a native Kerberos stack.

Three alternatives were considered:

**Alternative A — RFC 3062 PasswordModify as the primary form; reject kpasswd.** RFC 3062 is the standardized LDAP password-change mechanism. The advantage is unified password-change over LDAP (no separate kpasswd service). The disadvantage is breaking every Kerberos client that uses kpasswd (Windows Ctrl+Alt+Del → Change Password, macOS System Settings → Change Password, Linux `passwd` via PAM). Rejected as the primary form; ADOPTED as a secondary mechanism (per ADR-007).

**Alternative B — REST API as the primary form; reject kpasswd.** Modern, clean, no Kerberos dependency. The disadvantage is breaking every Kerberos client. Rejected as the primary form; ADOPTED as an additional form for non-Kerberos clients.

**Alternative C — Self-service portal with MFA as the primary form.** The portal authenticates the user via MFA (FIDO2, TOTP) and calls the directory's password-change API. The advantage is no password-as-authentication-for-password-change (which is a chicken-and-egg problem when the password is expired). The disadvantage is that the portal is a new component, and existing Kerberos clients (Windows, macOS, Linux) cannot use it without a custom client. Rejected as the primary form; ADOPTED as the REST endpoint's MFA option.

External evidence: [RFC 3244](https://www.rfc-editor.org/rfc/rfc3244) defines kpasswd; [RFC 3062](https://www.rfc-editor.org/rfc/rfc3062) defines the LDAP PasswordModify extended operation; Microsoft's [Set-ADAccountPassword](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword) documentation covers AD's password-change paths. MIT krb5's `kpasswd` command, Heimdal's `kpasswd`, and Windows `kerberos.dll` all support kpasswd. The framework's design matches the standard.

The cost of this decision is implementing kpasswd (a new service co-located with the KDC) plus the REST endpoint (a thin wrapper). The bulk of the work is shared with ADR-007 (the password-change primitive is common).

## Consequences

**Positive**: Standard kpasswd works for every Kerberos client (Windows, macOS, Linux) without migration. The REST endpoint enables modern non-Kerberos clients (web portals, mobile apps). The CLI command provides a convenient interactive path. Password-quality validation is identical across all paths.

**Negative**: Two password-change paths (kpasswd + REST) means two test surfaces and two security-review surfaces. The kpasswd service is a new component that must be deployed alongside the KDC.

**Neutral**: The REST endpoint is additive; deployments that don't use it pay no cost. The CLI command is convenient but not required for normal operation.

**Implementation cost**: ~4 person-weeks for kpasswd (co-located with the KDC, KRB-PRIV handling, result-code emission), ~1 person-week for the REST endpoint (thin wrapper), ~0.5 person-week for the CLI command. Total ~5.5 person-weeks; the bulk is shared with ADR-007.

**Operational impact**: Existing Kerberos clients (Windows Ctrl+Alt+Del → Change Password, macOS System Settings → Change Password, Linux `passwd`) work without modification. The REST endpoint enables self-service password-reset portals with MFA. The CLI command is useful for scripted password changes.

## Alternatives Considered

### Alternative 1: RFC 3062 PasswordModify as primary; reject kpasswd

Unified password-change over LDAP; breaks every Kerberos client. Rejected as primary; ADOPTED as secondary mechanism (per ADR-007).

### Alternative 2: REST API as primary; reject kpasswd

Modern, clean; breaks every Kerberos client. Rejected as primary; ADOPTED as additional form for non-Kerberos clients.

### Alternative 3: Self-service portal with MFA as primary

No password-as-authentication-for-password-change; new component, breaks existing Kerberos clients. Rejected as primary; ADOPTED as the REST endpoint's MFA option.

## Open Questions

- For the REST endpoint, what MFA methods are supported? FIDO2 (WebAuthn), TOTP (RFC 6238), push (platform-specific). Defer to a future MFA ADR.
- Should the framework support passwordless-only mode (no passwords, no kpasswd, no NTLM)? Defer to a future passwordless ADR; the framework's design preserves passwords for AD-interop.
- Cross-reference ADR-007 (password change protocol) — the two ADRs share the password-change primitive. ADR-007 specifies the LDAP forms (RFC 3062, BER-quote); this ADR specifies kpasswd and the REST endpoint.
- Cross-reference ADR-030 (krbtgt rotation, ADR-015) — krbtgt rotation uses the same password-change primitive (krbtgt is a principal; rotation is a password change). The framework's kpasswd service handles krbtgt rotation identically to user password changes.

## Cross-capability impact

- **Core Directory**: kpasswd updates `unicodePwd` via the DSA; the DSA's password-change primitive is shared with ADR-007.
- **Auth Provider**: NTLM's NT hash is the same value; password change via kpasswd invalidates existing NTLM sessions on next challenge.
- **Operations**: Password-change monitoring (event 4723 / 4724 equivalent) is emitted on every change. The REST endpoint enables self-service password-reset workflows.
- **Client SDK**: Client SDK exposes `adrian-krb5 passwd` for interactive password change; the SDK's Kerberos client uses kpasswd under the hood for `passwd`-equivalent operations.
- **Migration**: Existing AD-automation scripts that use kpasswd work without modification. The REST endpoint enables modern automation (Ansible, Terraform) to change passwords without LDAP parsing.

## References

- [PC-034](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — kpasswd protocol, KRB-PRIV wrapping, `kadmin/changepw` SPN
- [docs/02-protocols/07-ntp-time-sync.md](../docs/02-protocols/07-ntp-time-sync.md) — password expiration as a time-based event, urgent replication
- [RFC 3244](https://www.rfc-editor.org/rfc/rfc3244) — Kerberos Change Password and Set Password protocols
- [RFC 3062](https://www.rfc-editor.org/rfc/rfc3062) — LDAP PasswordModify Extended Operation
- [Microsoft Set-ADAccountPassword](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword)
