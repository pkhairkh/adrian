---
title: "ADR-087: S4U2Self + S4U2Proxy Constrained Delegation (with RBCD) in Framework KDC"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Auth Provider
problem: PC-039
severity: high
unblocked_by: Workshop Decision 6 (ORQ-072/074/075)
tags: [adr, auth-provider, s4u, s4u2self, s4u2proxy, rbcd, constrained-delegation, ms-sfu, pac, threat-model]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/03-auth-provider.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ../workshop/decision-05-kdc-implementation.md
  - ../workshop/decision-06-ntlm-decision.md
  - ./ADR-011-rc4-deprecation-aes-default.md
  - ./ADR-023-kerberos-audit-events.md
  - ./ADR-082-ms-kile-pac-generation.md
  - ./ADR-085-ntlm-client-only-rust-crate.md
last_updated: 2026-08-14
---

# ADR-087: S4U2Self + S4U2Proxy Constrained Delegation (with RBCD) in Framework KDC

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 6](../workshop/decision-06-ntlm-decision.md) (which resolved ORQ-075 in favor of preserving S4U2Self/S4U2Proxy rather than replacing with OAuth2 client-credentials) and [Workshop Decision 5](../workshop/decision-05-kdc-implementation.md) (which committed to a fresh Rust KDC with S4U implemented in `crates/adrian-kdc/src/mskile/s4u.rs`). This ADR specifies the framework's S4U2Self/S4U2Proxy implementation, including both classic constrained delegation (`msDS-AllowedToDelegateTo`) and resource-based constrained delegation (RBCD, `msDS-AllowedToActOnBehalfOfOtherIdentity`), with abuse-detection audit events and the framework's posture on the known RBCD attack vector.

## Threat model (STRIDE)

| STRIDE category | Attack vector | Framework mitigation |
|---|---|---|
| **Spoofing** | Attacker with `TRUSTED_TO_AUTH_FOR_DELEGATION` on a service account issues S4U2Self impersonating an arbitrary user (e.g. Domain Admin) | KDC validates `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (0x100000); S4U2Self impersonation scope limited to users the service is authorized to act for per `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) or `msDS-AllowedToDelegateTo` (classic) |
| **Tampering** | Attacker with write access to backend service account modifies `msDS-AllowedToActOnBehalfOfOtherIdentity` SD to grant themselves RBCD rights | Directory enforces write-ACL audit (`event_type = "rbcd_acl_modified"`); Security Descriptor is a binary SD that requires `WRITE_DAC` permission on the target; SIEM alert on RBCD ACL changes |
| **Repudiation** | Front-end service performs S4U2Proxy without traceability | `s4u2proxy.success` audit event captures requester service SID, target service SPN, impersonated user SID, source IP — full chain of custody |
| **Information disclosure** | Attacker enumerates service accounts with `TRUSTED_TO_AUTH_FOR_DELEGATION` to identify high-value S4U targets | Standard directory read access (any authenticated user can enumerate UAC flags); mitigation is operational — minimize `TRUSTED_TO_AUTH_FOR_DELEGATION` accounts; `adrian-auth audit-s4u` reports S4U usage patterns |
| **Denial of service** | Attacker floods KDC with S4U2Self requests for non-existent users | KDC validates `PA-FOR-USER` user existence before issuing S4U2Self ticket; rate-limit per caller (default 50 S4U2Self/sec per service principal) |
| **Elevation of privilege** | RBCD abuse: attacker with `WRITE_DAC` on a machine account grants themselves RBCD rights to that machine, then S4U2Self+Proxy as any user to that machine | RBCD ACL changes audited; `WRITE_DAC` on machine accounts restricted to Domain Admins + the machine itself by default; `adrian-auth audit-rbcd` reports recent RBCD ACL changes |

**Primary attack vector (CVE-2020-17049, "Kerberos Bronze Bit")**: S4U2Proxy with `S4U2Proxy` additional-tickets field carries the user's ticket; if the KDC does not validate the `forwardable` flag on the S4U2Self ticket, an attacker who has `TRUSTED_TO_AUTH_FOR_DELEGATION` on a service can elevate from service-account privilege to any user. The framework's KDC enforces strict `forwardable` flag validation per MS-SFU §3.2.1; the `constrained_delegation` KDC option (bit 14) is required for S4U2Proxy; the KDC rejects S4U2Proxy requests with `KDC_ERR_BADOPTION (13)` if the S4U2Self ticket lacks `forwardable`. The framework's interop test suite validates this against Windows S4U clients.

## Context

S4U2Self (Service-for-User-to-Self, PA-FOR-USER, RFC 4120 §2.6 extension) lets a service obtain a TGS for itself on behalf of a user — no user password needed. The service specifies the user (by UPN or SID) in the `PA-FOR-USER` padata; the KDC issues a TGT-like ticket for the service with the user's identity in the `cname` field, marked `TRANSITIVE_POLICY` and `FOR_USER`. The service account must have the `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (0x100000) set per [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md).

S4U2Proxy (Service-for-User-to-Proxy) lets the service exchange the S4U2Self ticket for a TGS to a backend service, constrained by `msDS-AllowedToDelegateTo` on the service account (classic) or `msDS-AllowedToActOnBehalfOfOtherIdentity` on the backend service (RBCD, Server 2012+). The KDC checks the requested SPN against the appropriate list; if present, the KDC issues a TGS for the backend service with the user's identity. The backend service sees the user's identity (in the PAC), not the front-end service's identity — enabling delegation without password forwarding.

RBCD flips the ACL: instead of the front-end service declaring who it can delegate to, the backend service declares who can delegate to it (binary SD on `msDS-AllowedToActOnBehalfOfOtherIdentity`). This is more secure — the backend service controls its own trust list. But it's also more attack-prone: an attacker with `WRITE_DAC` access to the backend service account can add themselves to the SD, then S4U2Self+Proxy as any user to that backend. This is the basis of the well-known RBCD abuse attack against machine accounts (where `WRITE_DAC` is sometimes granted to the machine itself or to "Authenticated Users" by misconfiguration).

Constraints from [PC-039](../catalog/03-auth-provider.md):

- Must support `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (0x100000) on service accounts.
- Must support `msDS-AllowedToDelegateTo` (multi-valued SPN list).
- Must support `msDS-AllowedToActOnBehalfOfOtherIdentity` (binary SD, RBCD).
- Must support PA-FOR-USER padata (S4U2Self) and the S4U2Proxy ticket exchange.
- For AD interop, must implement MS-SFU protocol extensions.

## Decision

The framework's KDC SHALL implement S4U2Self and S4U2Proxy in `crates/adrian-kdc/src/mskile/s4u.rs` (~2K lines of Rust at v1 maturity, included in the 36 person-week KDC budget per [Decision 5](../workshop/decision-05-kdc-implementation.md)). The implementation SHALL support both classic constrained delegation (`msDS-AllowedToDelegateTo`) and resource-based constrained delegation (RBCD, `msDS-AllowedToActOnBehalfOfOtherIdentity`), with strict flag validation per MS-SFU.

### S4U2Self protocol path

1. The KDC SHALL accept `PA-FOR-USER` padata (padata-type 129) in the TGS-REQ. The padata carries the user's identity (`userName`, `userRealm`, `verify`).
2. The KDC SHALL validate that the requesting service account has `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (0x100000) set. If not, the KDC SHALL reject with `KDC_ERR_BADOPTION (13)`.
3. The KDC SHALL validate the user's existence in the directory (via the principal store). If the user does not exist, the KDC SHALL reject with `KDC_ERR_C_PRINCIPAL_UNKNOWN (6)`.
4. The KDC SHALL issue a TGT-like ticket for the requesting service, with the user's identity in the `cname` field, marked `TRANSITIVE_POLICY` and `FOR_USER`. The ticket's `forwardable` flag SHALL be set if the service is configured for S4U2Proxy (per `msDS-AllowedToDelegateTo` or RBCD); otherwise the ticket is non-forwardable.
5. The PAC inside the S4U2Self ticket SHALL contain the user's identity (per [ADR-082](./ADR-082-ms-kile-pac-generation.md)).

### S4U2Proxy protocol path

1. The KDC SHALL accept the S4U2Self ticket in the `additional-tickets` field of the TGS-REQ, with the `constrained_delegation` KDC option (bit 14) set.
2. The KDC SHALL validate the S4U2Self ticket's `forwardable` flag. If the ticket is not forwardable, the KDC SHALL reject with `KDC_ERR_BADOPTION (13)`. This is the Bronze Bit mitigation.
3. The KDC SHALL validate the requested SPN against:
   - Classic: `msDS-AllowedToDelegateTo` on the requesting service account (multi-valued SPN list). If the SPN is not in the list, reject with `KDC_ERR_BADOPTION (13)`.
   - RBCD: `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target service account (binary SD). If the requesting service's SID is not granted `ACTRL_DS_CONTROL_ACCESS` in the SD, reject with `KDC_ERR_BADOPTION (13)`.
4. If both classic and RBCD are configured, RBCD takes precedence (per MS-SFU §3.2.1).
5. The KDC SHALL issue a TGS for the target service, with the user's identity in the `cname` field and the PAC carrying the user's identity (not the front-end service's identity).
6. The KDC SHALL set the `CNAME_IN_ADDL_TKT` flag in the issued TGS to indicate the ticket was issued via S4U2Proxy (per MS-SFU §3.2.6).

### Concrete specification

- The KDC SHALL implement S4U2Self and S4U2Proxy in `crates/adrian-kdc/src/mskile/s4u.rs` (~2K lines), included in the 36 person-week KDC budget per [Decision 5](../workshop/decision-05-kdc-implementation.md).
- The KDC SHALL support `PA-FOR-USER` padata (padata-type 129) per RFC 4120 §2.6 extension.
- The KDC SHALL validate `TRUSTED_TO_AUTH_FOR_DELEGATION` UAC bit (0x100000) on the requesting service account.
- The KDC SHALL validate `msDS-AllowedToDelegateTo` (classic) and `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD, binary SD); RBCD takes precedence when both are present.
- The KDC SHALL enforce strict `forwardable` flag validation on S4U2Self tickets presented in S4U2Proxy (Bronze Bit mitigation per CVE-2020-17049).
- The KDC SHALL set `CNAME_IN_ADDL_TKT` flag on S4U2Proxy-issued TGS tickets.
- The framework's directory SHALL expose `msDS-AllowedToDelegateTo` (multi-valued string, SPN list) and `msDS-AllowedToActOnBehalfOfOtherIdentity` (binary, NT Security Descriptor) on user and machine accounts.
- The framework's directory SHALL audit `WRITE_DAC` access on `msDS-AllowedToActOnBehalfOfOtherIdentity` — emit `event_type = "rbcd_acl_modified"` per [ADR-023](./ADR-023-kerberos-audit-events.md) with: target account SID, modifier SID, old SD hash, new SD hash, source IP, timestamp.
- The framework SHALL emit audit events per [ADR-023](./ADR-023-kerberos-audit-events.md): `s4u2self.success` (requester SID, target user SID, source IP, forwardable flag), `s4u2self.failed` (with reason `not_trusted_for_delegation`, `user_not_found`, `user_invalid`), `s4u2proxy.success` (requester SID, target SPN, impersonated user SID), `s4u2proxy.failed` (with reason `ticket_not_forwardable`, `spn_not_allowed_classic`, `spn_not_allowed_rbcd`, `rbcd_acl_denied`).
- The KDC SHALL rate-limit S4U2Self requests per caller (default 50/sec per service principal); configurable via `s4u_rate_limit` in `adrian.conf`.
- The framework SHALL expose `adrian-auth audit-s4u` (summarize S4U usage patterns: top S4U2Self callers, top impersonated users, top S4U2Proxy targets) and `adrian-auth audit-rbcd` (recent RBCD ACL changes) CLI commands.

### Rust crates used

- `adrian-kdc` (framework crate, per [Decision 5](../workshop/decision-05-kdc-implementation.md)) — S4U2Self/S4U2Proxy logic in `src/mskile/s4u.rs`. The S4U module consumes the PAC builder (`src/pac.rs` per [ADR-082](./ADR-082-ms-kile-pac-generation.md)) for user-identity PAC construction.
- `rasn` (v0.10+) for ASN.1 encoding/decoding of `PA-FOR-USER` and the S4U2Proxy `additional-tickets` field.
- `rasn-kerberos` (v0.10+) for the S4U2Self/S4U2Proxy ASN.1 type definitions; the framework SHALL NOT use it for MS-SFU-specific extensions (those live in `adrian-kdc::mskile`).
- `windows-core` (v0.54+) for the NT Security Descriptor parser used in RBCD `msDS-AllowedToActOnBehalfOfOtherIdentity` validation. The framework SHALL implement a pure-Rust SD parser in `crates/adrian-kdc/src/sd.rs` (because `windows-core` is Windows-only; the framework's KDC runs on Linux/macOS too).
- `ring` (v0.17+) for HMAC operations on the S4U2Self ticket signature (per [ADR-082](./ADR-082-ms-kile-pac-generation.md)).
- `tracing` + `opentelemetry` for audit emission per [ADR-023](./ADR-023-kerberos-audit-events.md).
- `ldap3` (v0.11+) for `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity` reads from Core Directory.

## Rationale

Four arguments drive the decision to preserve S4U2Self/S4U2Proxy (rather than replace with OAuth2 client-credentials per ORQ-074).

**1. S4U is the Kerberos-native constrained-delegation primitive with no protocol bridging cost.** OAuth2 client-credentials (RFC 6749 §4.4) is HTTP-only; S4U works for any Kerberos-aware protocol (SMB, LDAP, RPC, HTTP, SQL). Replacing S4U with OAuth2 would require protocol-bridging for every non-HTTP Kerberos service — non-trivial and breaking for AD-interop. The framework preserves S4U; OAuth2 is adopted for new framework-native services that don't need user-delegation.

**2. S4U2Proxy preserves AD-interop for mixed-forest deployments.** AD-aware services (IIS → SQL Server, SharePoint → Exchange, custom Kerberos apps) use S4U2Proxy for service-to-service delegation. Replacing S4U with OAuth2 would break these services in mixed forests (framework KDC + AD services). The framework's KDC SHALL produce S4U tickets that AD accepts and accept S4U tickets that AD issues (validated by the interop test suite per [Decision 5](../workshop/decision-05-kdc-implementation.md)).

**3. The Bronze Bit attack is mitigated by strict `forwardable` flag validation.** CVE-2020-17049 exposed a flaw in Microsoft's S4U2Proxy implementation where a non-forwardable S4U2Self ticket could be used for S4U2Proxy. The framework's KDC enforces strict validation per MS-SFU §3.2.1: S4U2Proxy requires a forwardable S4U2Self ticket; the KDC SHALL reject with `KDC_ERR_BADOPTION (13)` otherwise. The framework's interop test suite includes a Bronze Bit regression test.

**4. RBCD abuse is mitigated by audit + `WRITE_DAC` restriction.** RBCD's `msDS-AllowedToActOnBehalfOfOtherIdentity` is a binary SD; modifying it requires `WRITE_DAC` on the target account. The framework's directory enforces `WRITE_DAC` on machine accounts restricted to Domain Admins + the machine itself by default; the `rbcd_acl_modified` audit event fires on every modification; `adrian-auth audit-rbcd` reports recent changes. This is a stronger posture than AD's default (where `WRITE_DAC` is sometimes granted to "Authenticated Users" by misconfiguration).

External evidence: [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) defines S4U2Self/S4U2Proxy; [RFC 4120 §2.6](https://www.rfc-editor.org/rfc/rfc4120#section-2.6) defines the `PA-FOR-USER` padata extension; [CVE-2020-17049 (Bronze Bit)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049) documents the `forwardable` flag bypass; [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) and [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) document the framework's reference S4U layouts.

## Consequences

**Positive**: Service-to-service constrained delegation works for AD-aware services (IIS → SQL Server, web app → backend API, SharePoint → Exchange) without protocol bridging. RBCD is supported for the modern backend-controlled trust model. Bronze Bit attack (CVE-2020-17049) is mitigated by strict `forwardable` flag validation. RBCD abuse is mitigated by audit + `WRITE_DAC` restriction. S4U audit events provide full chain-of-custody for delegation flows.

**Negative**: S4U adds KDC complexity (the Bronze Bit interop test is a known regression risk). RBCD abuse remains possible if `WRITE_DAC` is misconfigured on machine accounts (the framework's default restricts `WRITE_DAC` to Domain Admins + the machine itself, but operators can misconfigure). The S4U2Self `PA-FOR-USER` padata is an RFC 4120 extension, not universally supported by all Kerberos clients (MIT krb5 1.10+ supports it; older clients do not). The `s4u_rate_limit` of 50/sec per service principal may be too low for high-throughput services (configurable).

**Neutral**: S4U2Self tickets carry the user's identity in the PAC; the framework's PAC builder ([ADR-082](./ADR-082-ms-kile-pac-generation.md)) handles this identically to password-issued TGTs. The framework's services consuming S4U2Proxy-issued TGS validate the PAC via the paths specified in [ADR-083](./ADR-083-pac-validation-rpc.md).

**Implementation cost**: 4 person-weeks total (included in the 36 person-week KDC budget per [Decision 5](../workshop/decision-05-kdc-implementation.md)). S4U2Self path: 1.5 pw. S4U2Proxy path with classic + RBCD: 1.5 pw. NT SD parser for RBCD (`crates/adrian-kdc/src/sd.rs`): 0.5 pw. Audit events + `audit-s4u`/`audit-rbcd` CLI: 0.5 pw.

## Alternatives Considered

### Alternative 1: Replace S4U with OAuth2 client-credentials flow wholesale

ORQ-074's candidate. Rejected per [Decision 6](../workshop/decision-06-ntlm-decision.md): OAuth2 client-credentials is HTTP-only; S4U works for any Kerberos-aware protocol. OAuth2 client-credentials cannot express "act on behalf of user X" without RFC 8693 token exchange, which is more complex than S4U2Proxy and lacks AD interop. OAuth2 is adopted for new framework-native service-to-service auth; S4U preserved for Kerberos-native delegation.

### Alternative 2: Drop RBCD; classic constrained delegation only

Simpler implementation; eliminates the RBCD abuse attack vector. Rejected: RBCD is the modern best practice (Server 2012+); AD-interop customers using RBCD cannot migrate to a framework that does not support it. The framework's audit + `WRITE_DAC` restriction mitigates RBCD abuse without eliminating RBCD.

### Alternative 3: Drop classic constrained delegation; RBCD only

Forces all customers to migrate to RBCD. Rejected: classic constrained delegation (`msDS-AllowedToDelegateTo`) is widely deployed; customers cannot migrate all services to RBCD during a single cutover. The framework supports both; RBCD takes precedence when both are configured (per MS-SFU §3.2.1).

### Alternative 4: Add OAuth2-on-behalf-of (RFC 8693) as an alternative to S4U2Proxy

Provide both S4U2Proxy (Kerberos-native) and OAuth2 OBO (HTTP-native) for constrained delegation. Rejected for v1: doubles the constrained-delegation surface; customers confused about which to use. The framework SHALL support OAuth2 OBO in a future revision (post-v1) for HTTP-only services that prefer OAuth2; S4U2Proxy remains the primary mechanism.

## Open Questions

- For S4U2Self `PA-FOR-USER` `verify` field: should the KDC require the requesting service to sign the `PA-FOR-USER` with its long-term key? RFC 4120 §2.6 says the `verify` field is optional; AD does not require it. The framework matches AD (optional); services that want the extra assurance can set it.
- For RBCD `WRITE_DAC` defaults: should the framework restrict `WRITE_DAC` on machine accounts to Domain Admins only (excluding the machine itself)? No — the machine itself needs `WRITE_DAC` to manage its own RBCD list (per AD semantics). The framework's default matches AD: Domain Admins + the machine itself.
- Cross-reference [ADR-082](./ADR-082-ms-kile-pac-generation.md) (PC-023) — S4U2Self tickets carry the user's identity in the PAC; the PAC builder handles this.
- Cross-reference [ADR-083](./ADR-083-pac-validation-rpc.md) (PC-025) — S4U2Proxy-issued TGS tickets carry the user's PAC; downstream services validate via the paths specified there.
- Cross-reference [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md) (PC-036) — S4U is the Kerberos-native alternative to NTLM-based delegation.

## Cross-capability impact

- **KDC** ([Decision 5](../workshop/decision-05-kdc-implementation.md), [ADR-082](./ADR-082-ms-kile-pac-generation.md)): S4U implemented in `mskile/s4u.rs`; consumes the PAC builder for user-identity PAC construction.
- **Auth Provider** ([ADR-085](./ADR-085-ntlm-client-only-rust-crate.md)): the Auth Provider's Kerberos SSPI-equivalent initiates S4U2Self/S4U2Proxy requests via the framework's KDC.
- **Core Directory**: `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity` storage with `WRITE_DAC` audit.
- **Federation Gateway** ([ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md)): federation services use S4U2Proxy for OAuth2-on-behalf-of flow (post-v1, see Alternatives).
- **Client SDK** ([Decision 11](../workshop/decision-11-client-sdk.md)): the SDK's `AuthModule` exposes `s4u2self(user) -> Ticket` and `s4u2proxy(target, evidence_ticket) -> Ticket` methods for framework-managed services that need constrained delegation.
- **Operations**: `adrian-auth audit-s4u` and `adrian-auth audit-rbcd` CLI commands. SIEM queries for `s4u2self.success/failed` and `s4u2proxy.success/failed` events provide delegation-flow monitoring.
- **Security** ([ADR-023](./ADR-023-kerberos-audit-events.md)): S4U audit events + `rbcd_acl_modified` events feed delegation-abuse detection (correlate `s4u2self.success` for sensitive impersonated users with `rbcd_acl_modified` for target services).
- **Migration** ([ADR-069](../workshop/decision-06-ntlm-decision.md)): AD customers with S4U-based constrained delegation migrate to the framework with no service-side change (S4U is wire-compatible); `msDS-AllowedToDelegateTo` and `msDS-AllowedToActOnBehalfOfOtherIdentity` are preserved during migration.

## References

- [PC-039](../catalog/03-auth-provider.md) — problem statement in the catalog
- [Workshop Decision 5 — Fresh Rust KDC](../workshop/decision-05-kdc-implementation.md) — unblocking decision; S4U implemented in `crates/adrian-kdc/src/mskile/s4u.rs`
- [Workshop Decision 6 — NTLM Decision](../workshop/decision-06-ntlm-decision.md) — preserves S4U2Self/S4U2Proxy rather than replacing with OAuth2 client-credentials
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — S4U2Self `PA-FOR-USER` padata, S4U2Proxy ticket exchange, KDC option `constrained-delegation` (bit 14)
- [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) — `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity` schema attributes, RBCD SD format
- [ADR-011](./ADR-011-rc4-deprecation-aes-default.md) — S4U tickets use AES etypes per ADR-011 negotiation
- [ADR-023](./ADR-023-kerberos-audit-events.md) — `s4u2self.success/failed`, `s4u2proxy.success/failed`, `rbcd_acl_modified` audit events
- [ADR-082](./ADR-082-ms-kile-pac-generation.md) — PAC builder constructs S4U2Self tickets carrying the user's identity
- [ADR-083](./ADR-083-pac-validation-rpc.md) — downstream services validate S4U2Proxy-issued TGS tickets via these paths
- [ADR-085](./ADR-085-ntlm-client-only-rust-crate.md) — S4U is the Kerberos-native alternative to NTLM-based delegation
- [MS-SFU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/) — S4U2Self/S4U2Proxy specification
- [RFC 4120 §2.6](https://www.rfc-editor.org/rfc/rfc4120#section-2.6) — `PA-FOR-USER` padata extension
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) — OAuth 2.0 Token Exchange (alternative considered for HTTP-only delegation; deferred to post-v1)
- [CVE-2020-17049 (Bronze Bit)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17049) — S4U2Proxy `forwardable` flag bypass
- [MITRE ATT&CK T1558.001 (Kerberoasting)](https://attack.mitre.org/techniques/T1558/001/) — Kerberos attack techniques catalog
