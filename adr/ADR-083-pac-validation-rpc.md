---
title: "ADR-083: PAC Validation via PAC_BUFFER_TICKET_CHECKSUM (Local) + NetrLogonSamLogonEx (Interop)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: KDC
problem: PC-025
severity: high
unblocked_by: Workshop Decision 5 (ORQ-042/043/044)
tags: [adr, kdc, kerberos, pac, pac-validation, silver-ticket, ms-nrpc, ticket-checksum]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ../docs/02-protocols/06-netlogon-ms-nrpc.md
  - ../workshop/decision-05-kdc-implementation.md
  - ./ADR-015-krbtgt-hsm-rotation.md
  - ./ADR-018-kdc-horizontal-scaling.md
  - ./ADR-021-ldap-signing-channel-binding.md
  - ./ADR-023-kerberos-audit-events.md
  - ./ADR-082-ms-kile-pac-generation.md
last_updated: 2026-08-14
---

# ADR-083: PAC Validation via PAC_BUFFER_TICKET_CHECKSUM (Local) + NetrLogonSamLogonEx (Interop)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 5](../workshop/decision-05-kdc-implementation.md) which resolved Tier-1 ORQ-042/043/044 in favor of a fresh Rust KDC in `crates/adrian-kdc`. This ADR specifies how services validate the PAC inside framework-issued tickets: a local, DC-roundtrip-free path leveraging `PAC_BUFFER_TICKET_CHECKSUM` (Server 2012+ silver-ticket mitigation) as the primary mechanism, with the legacy `NetrLogonSamLogonEx` (MS-NRPC) RPC path retained for AD-interop with Windows services that opt in via the `VerifyPacAuthenticators` registry toggle.

## Context

Services that consume Kerberos service tickets face a choice: trust the KDC's signature at issue time (cheap, no DC roundtrip, vulnerable to silver-ticket attacks if the service account's NT hash is compromised) or re-validate the PAC by calling the DC (expensive, one network roundtrip per AP-REQ, defeats silver-ticket by re-checking the KDC signature). AD supports both paths via the registry toggle `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\VerifyPacAuthenticators` (DWORD; 0 = no verify [default], 1 = verify for services that request it, 2 = always verify). Most services run at default 0 because per-AP-REQ DC roundtrips are prohibitively expensive for high-throughput services (IIS serving 10K req/sec would generate 10K Netlogon calls/sec to the DC).

The Server 2012+ ticket signature (`PAC_BUFFER_TICKET_CHECKSUM`, type 0x0E) closes this gap. The KDC computes an HMAC of the entire encrypted `Ticket.enc-part` using the krbtgt key and includes it in the PAC. The service can validate this signature locally — without a DC roundtrip — by recomputing the HMAC. The catch: the service must hold the krbtgt key to recompute. AD solves this by giving every DC the krbtgt key (LSASS-stored) and giving every member server the krbtgt key via the Netlogon secure channel — the service calls `NetrLogonSamLogonEx` which performs the validation on the DC and returns the verdict. This is still a DC roundtrip, but `PAC_BUFFER_TICKET_CHECKSUM` adds defense-in-depth: an attacker with the service's NT hash can forge the ticket plaintext but cannot forge the `PAC_BUFFER_TICKET_CHECKSUM` (which requires the krbtgt key). The forged ticket passes the service's local signature check (using the service's key) but fails the ticket-signature check (which requires the krbtgt key the attacker doesn't have). Whether the service detects this depends on whether it opts into `VerifyPacAuthenticators`.

The framework's posture ([Decision 5](../workshop/decision-05-kdc-implementation.md) §"Problems unblocked") commits to implementing `PAC_BUFFER_TICKET_CHECKSUM` and accepting `NetrLogonSamLogonEx` calls. This ADR specifies how services opt into validation, what the framework's local validation path looks like, and how the legacy Netlogon path is preserved for AD-interop.

Constraints from [PC-025](../catalog/02-kdc.md):

- Must not introduce per-request DC roundtrip for non-validating services (perf).
- Must support `VerifyPacAuthenticators` registry toggle for opt-in (AD-interop).
- Must support Server 2012+ ticket signature (`PAC_BUFFER_TICKET_CHECKSUM`).
- For AD interop, the framework must accept `NetrLogonSamLogonEx` PAC validation calls from Windows services.

## Decision

The framework SHALL provide two PAC validation paths, layered so that the cheap local path runs first and the expensive DC path runs only when explicitly required:

### Path 1 — Local ticket-signature validation (default; mandatory; zero DC roundtrip)

Every framework-managed service (a service using `crates/adrian-sdk`'s `AuthModule` per [Decision 11](../workshop/decision-11-client-sdk.md)) SHALL validate `PAC_BUFFER_TICKET_CHECKSUM` locally on every AP-REQ it accepts. The validation:

1. Extract `PAC_BUFFER_TICKET_CHECKSUM` from the ticket's PAC.
2. Compute HMAC of `Ticket.enc-part` (the encrypted blob, post-encryption) using the krbtgt key.
3. Compare the computed HMAC against the buffer's signature.
4. Reject the AP-REQ with `KRB_AP_ERR_MODIFIED (41)` on mismatch.

The service obtains the krbtgt key from the framework's HSM-backed key-distribution mechanism — NOT from LSASS memory and NOT from a keytab on disk. The framework's KDC SHALL publish a per-realm krbtgt-public-key (a public verification key) to all framework-managed hosts at domain-join time and on each krbtgt rotation; the public key validates `PAC_BUFFER_TICKET_CHECKSUM` signatures without revealing the symmetric krbtgt key. This is a framework extension over AD's model: AD's `PAC_BUFFER_TICKET_CHECKSUM` is a symmetric HMAC (the service holds the krbtgt symmetric key via Netlogon); the framework's is an asymmetric signature (HMAC computed by the KDC with the symmetric krbtgt key, validated by the service with the krbtgt *public* key). The framework's HSM derives an Ed25519 keypair from the krbtgt symmetric key at each rotation and publishes the Ed25519 public half to all hosts.

**Performance**: Ed25519 verification is ≤50 µs per ticket; 10K req/sec adds ≤500 ms of CPU per second across the pool — negligible. The local path is the default for every framework-managed service.

### Path 2 — Netlogon RPC validation (AD-interop; opt-in via registry toggle)

The framework's KDC SHALL accept `NetrLogonSamLogonEx` (MS-NRPC opnum 45) calls from Windows services that opt into `VerifyPacAuthenticators = 1` or `2`. The KDC SHALL validate the inbound PAC by recomputing `PAC_PRIVSVR_CHECKSUM` (and `PAC_BUFFER_TICKET_CHECKSUM` if present) with the HSM-bound krbtgt key. The KDC SHALL return the validation verdict (`STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_LOGON_FAILURE`) per MS-NRPC §3.5.4.5.2.

The framework's `NetrLogonSamLogonEx` implementation lives in `crates/adrian-kdc/src/mskile/nrpc_validation.rs` (~1.5K lines of Rust). It uses `rasn` for NDR encoding of the MS-NRPC structures (`NETLOGON_VALIDATION_INFO_CLASS`, `NETLOGON_LOGON_INFO`, `PAC_VALIDATION_INFO`) and the framework's MS-NRPC secure channel implementation (per the cross-realm trust path in [ADR-069](./ADR-069-cross-realm-capaths.md)).

This path is for AD-interop with Windows services that hard-require `NetrLogonSamLogonEx` (IIS with `VerifyPacAuthenticators = 2`, SQL Server with `LoginPacValidation = 1`, COM+ roles). Framework-managed services use Path 1.

### Concrete specification

- The KDC SHALL emit `PAC_BUFFER_TICKET_CHECKSUM` on every ticket (per [ADR-082](./ADR-082-ms-kile-pac-generation.md)).
- The KDC SHALL derive an Ed25519 keypair from the krbtgt symmetric key at each rotation. The Ed25519 private key stays in the HSM; the Ed25519 public key is published to all framework-managed hosts via the directory's `msDS-KrbTgtLink`-equivalent attribute (the framework's `krbtgtPublicKey` attribute on the realm object).
- Every framework-managed service SHALL validate `PAC_BUFFER_TICKET_CHECKSUM` locally on every AP-REQ using the published Ed25519 public key. The validation SHALL be a no-op when the ticket lacks `PAC_BUFFER_TICKET_CHECKSUM` (legacy clients; the service logs a `pac_validation.skipped` audit event per [ADR-023](./ADR-023-kerberos-audit-events.md)).
- The KDC SHALL accept `NetrLogonSamLogonEx` (MS-NRPC opnum 45) calls from Windows services. The KDC SHALL validate the PAC by recomputing `PAC_PRIVSVR_CHECKSUM` and `PAC_BUFFER_TICKET_CHECKSUM` (if present) with the HSM-bound krbtgt key.
- The KDC SHALL return MS-NRPC-conformant result codes per MS-NRPC §3.5.4.5.2: `STATUS_SUCCESS`, `STATUS_INVALID_PARAMETER`, `STATUS_LOGON_FAILURE`, `STATUS_NO_TRUST_LSA_ACCOUNT` (when the calling service's secure channel cannot be authenticated).
- The KDC SHALL maintain a per-caller rate limit on `NetrLogonSamLogonEx` calls (default 100/sec per service) to prevent a single service from DoS-ing the KDC with validation calls. Configurable via `krb5_validation_rate_limit` in `adrian.conf`.
- The KDC SHALL cache the validation verdict per (ticket hash, caller) for 5 seconds to avoid redundant HSM roundtrips when a single service issues many AP-REQs with the same ticket in a short window.
- The framework's `AuthModule` SHALL expose `validate_pac(ticket) -> Result<PacInfo, ValidationError>` for framework-managed services. The function performs Path 1 (local Ed25519 verification) and returns the parsed `KERB_VALIDATION_INFO` on success.
- The framework SHALL NOT support the older `NetrLogonSamLogon` (opnum 5) or `NetrLogonSamLogonWithFlags` (opnum 45's predecessor); Windows services MUST use `NetrLogonSamLogonEx` (opnum 46). This matches Server 2012+ behavior.

### Audit events

The framework SHALL emit audit events per [ADR-023](./ADR-023-kerberos-audit-events.md):

- `pac_validation.success` (Path 1): service principal, requester SID, source IP, ticket kvno, validation time (µs).
- `pac_validation.failed` (Path 1): service principal, requester SID, source IP, failure reason (`signature_mismatch`, `missing_buffer`, `expired_key`).
- `pac_validation.skipped` (Path 1, ticket lacks `PAC_BUFFER_TICKET_CHECKSUM`): service principal, requester SID, source IP, ticket age (seconds).
- `netlogon_sam_logon_ex` (Path 2): caller SID, caller workstation, target user SID, validation verdict, validation time.

## Rationale

Four arguments drive this decision.

**1. Local validation closes the silver-ticket attack window without DC roundtrips.** The silver-ticket attack (PC-119) requires the attacker to have the service's NT hash; the attacker forges a ticket plaintext and encrypts it with the service's key. Without `PAC_BUFFER_TICKET_CHECKSUM`, the forged ticket is byte-identical to a real one. With the signature, the forged ticket lacks the correct KDC-side signature — but only services that validate it detect this. AD's `VerifyPacAuthenticators = 2` requires a DC roundtrip per AP-REQ, which is prohibitively expensive at high throughput. The framework's local Ed25519 verification path closes the silver-ticket window at ≤50 µs per AP-REQ — negligible overhead even at 10K req/sec.

**2. Ed25519 asymmetric signature allows public-key validation without revealing the krbtgt key.** AD's `PAC_BUFFER_TICKET_CHECKSUM` is symmetric HMAC — the service holds the krbtgt symmetric key (via the Netlogon secure channel) and recomputes the HMAC. This means a service compromise leaks the krbtgt key, enabling golden-ticket attacks. The framework's asymmetric Ed25519 signature — derived per-rotation from the krbtgt symmetric key in the HSM — gives services a *public* verification key that cannot forge signatures. A service compromise leaks only the public key, which is harmless. The asymmetric approach is a framework improvement over AD's model.

**3. The Netlogon RPC path is retained for AD-interop, not as a primary mechanism.** Windows services with `VerifyPacAuthenticators = 2` set call `NetrLogonSamLogonEx` regardless of `PAC_BUFFER_TICKET_CHECKSUM` presence. The framework's KDC SHALL accept these calls to support Windows services that have not yet migrated to the local validation path. The MS-NRPC implementation is ~1.5K lines of Rust, well-scoped, and exercised by the interop test suite against Windows Server 2022+ services.

**4. Caching and rate-limiting protect the KDC from validation-storm DoS.** A single service issuing 10K AP-REQs/sec against the same ticket should not generate 10K HSM roundtrips. The 5-second verdict cache reduces this to one HSM roundtrip per (ticket hash, caller) per 5 seconds. The per-caller rate limit (default 100/sec) caps the worst-case HSM load at 100 roundtrips/sec per service. Both are configurable; deployments with lower-traffic services can disable rate-limiting.

External evidence: [MS-NRPC §3.5.4.5.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/) defines `NetrLogonSamLogonEx`; [MS-KILE §3.4.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) defines the KDC's PAC validation requirements; [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) and [docs/02-protocols/06-netlogon-ms-nrpc.md](../docs/02-protocols/06-netlogon-ms-nrpc.md) document the framework's reference layouts. Microsoft's [Security Advisory ADV210003](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003) and the [Kerberos PAC validation documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/kerberos-policy) document AD's `VerifyPacAuthenticators` semantics.

## Consequences

**Positive**: Silver-ticket attacks (PC-119) are detected at ≤50 µs per AP-REQ — closing the silver-ticket window at high throughput. AD-interop is preserved via the Netlogon RPC path. The asymmetric Ed25519 signature prevents service-compromise → golden-ticket escalation (a service compromise leaks only the public key).

**Negative**: Every framework-managed service must be linked against `crates/adrian-sdk`'s `AuthModule` to benefit from the local validation path. Services linked against legacy GSSAPI-only stacks (Apache `mod_auth_gssapi`, nginx `spnego-http-auth`) without the SDK integration do not validate `PAC_BUFFER_TICKET_CHECKSUM` locally — they fall back to the Netlogon RPC path (which the framework's KDC supports) or skip validation entirely. The framework's installer SHALL detect such services and warn operators during `adrian-cli join`.

**Neutral**: The 5-second verdict cache means a service can be fooled into accepting a forged ticket for up to 5 seconds after the KDC's verdict cache expires — but only if the forged ticket passes the local Ed25519 check (which it cannot without the krbtgt private key). The cache is defense-in-depth, not the primary defense.

**Implementation cost**: 4 person-weeks total. Local Ed25519 verification path: 1 pw (in `crates/adrian-sdk/src/auth/pac.rs`). HSM-derived Ed25519 keypair + directory publication: 1 pw (in `crates/adrian-kdc/src/hsm.rs` and `crates/adrian-kdc/src/pac/signature.rs`). MS-NRPC `NetrLogonSamLogonEx` implementation: 1.5 pw (in `crates/adrian-kdc/src/mskile/nrpc_validation.rs`). Audit events + verdict cache + rate limiting: 0.5 pw.

## Alternatives Considered

### Alternative 1: Always-validate mode at TGS time (KDC validates PAC immediately after issuing)

The KDC validates the PAC immediately after issuing the ticket, eliminating the per-AP-REQ DC roundtrip. Rejected: this validates that the KDC just issued the ticket correctly — a self-validation. It does not protect against silver-ticket attacks (the attacker forges the ticket without going through the KDC). Local service-side validation is the only defense.

### Alternative 2: Token-binding via TLS exporter (RFC 9266) — bind ticket to TLS session

Defeats relay without DC roundtrip. Rejected as the sole mechanism: requires TLS 1.3+ (RFC 9266 channel bindings are defined for TLS 1.3) and client-side support (not universal). Adopted as a complementary control for HTTP-based Kerberos per [ADR-021](./ADR-021-ldap-signing-channel-binding.md); this ADR's local ticket-signature validation is the primary defense.

### Alternative 3: Mandate `VerifyPacAuthenticators = 2` (always-validate via Netlogon) for all framework-managed services

The strongest AD-compat posture. Rejected: every AP-REQ incurs a DC roundtrip — at 10K req/sec, the KDC handles 10K `NetrLogonSamLogonEx` calls/sec per service, which is not feasible. The local Ed25519 path achieves the same defense at ≤50 µs per AP-REQ without DC roundtrips.

### Alternative 4: Drop the Netlogon RPC path; framework-managed services use only Path 1

Simpler implementation. Rejected: Windows services with `VerifyPacAuthenticators = 1` or `2` set (IIS, SQL Server, COM+ roles) hard-require `NetrLogonSamLogonEx`. The framework's KDC MUST accept these calls for AD-interop. Dropping the Netlogon path would force these services to disable `VerifyPacAuthenticators`, weakening security.

## Open Questions

- For the Ed25519 key derivation: should the framework derive the Ed25519 key from the krbtgt symmetric key via HKDF (deterministic, same input → same key), or generate a fresh Ed25519 keypair per rotation (random, but stored alongside the krbtgt key in the HSM)? HKDF is deterministic and simpler; fresh-per-rotation is cryptographically cleaner. Decision: HKDF — the krbtgt key already has high entropy; HKDF expansion to Ed25519 is standard.
- For the 5-second verdict cache: should the cache TTL be configurable per-deployment? Yes — high-security deployments may set TTL = 0 (no cache); high-throughput deployments may set TTL = 30s. Default 5s.
- Cross-reference [ADR-082](./ADR-082-ms-kile-pac-generation.md) (PC-023) — the PAC builder emits `PAC_BUFFER_TICKET_CHECKSUM`; this ADR specifies how services validate it.

## Cross-capability impact

- **KDC** ([ADR-082](./ADR-082-ms-kile-pac-generation.md)): the PAC builder emits the buffers this ADR validates. The KDC's MS-NRPC implementation accepts `NetrLogonSamLogonEx` calls.
- **Auth Provider** ([ADR-087](./ADR-087-s4u-constrained-delegation.md) PC-039): S4U2Self/S4U2Proxy tickets carry PACs that downstream services validate via the paths specified here.
- **Core Directory**: the `krbtgtPublicKey` attribute on the realm object is the publication channel for the Ed25519 public key.
- **Client SDK** ([Decision 11](../workshop/decision-11-client-sdk.md)): the SDK's `AuthModule` exposes `validate_pac(ticket)`; framework-managed services call this on every AP-REQ.
- **Operations**: `adrian-krb5 audit-pac-validation` CLI summarizes validation success/failure/skip counts; `adrian-krb5 pac-cache flush` clears the verdict cache after an emergency krbtgt rotation.
- **Security** ([ADR-023](./ADR-023-kerberos-audit-events.md)): audit events for validation success/failure/skip feed silver-ticket detection (PC-119) and golden-ticket detection (correlate `pac_validation.failed` with `old_kvno` from [ADR-015](./ADR-015-krbtgt-hsm-rotation.md)).
- **Migration** ([ADR-069](./ADR-069-cross-realm-capaths.md)): cross-realm referrals carry PACs from the originating realm; the framework's KDC validates the originating realm's `PAC_BUFFER_TICKET_CHECKSUM` using the cross-realm trust key.

## References

- [PC-025](../catalog/02-kdc.md) — problem statement in the catalog
- [Workshop Decision 5 — Fresh Rust KDC](../workshop/decision-05-kdc-implementation.md) — unblocking decision; specifies `crates/adrian-kdc/src/mskile/` for S4U + PAC validation extensions
- [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) — PAC validation flow, `NetrLogonSamLogonEx` interface, `VerifyPacAuthenticators` toggle
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — PAC buffer types, ticket signature (Server 2016+), silver-ticket attack
- [docs/02-protocols/06-netlogon-ms-nrpc.md](../docs/02-protocols/06-netlogon-ms-nrpc.md) — MS-NRPC secure channel, `NetrLogonSamLogonEx` opnum 45
- [ADR-015](./ADR-015-krbtgt-hsm-rotation.md) — HSM-bound krbtgt key; Ed25519 keypair derivation
- [ADR-018](./ADR-018-kdc-horizontal-scaling.md) — verdict cache coherency across KDC instances (cache is per-instance; safe because the underlying HSM verdict is identical)
- [ADR-021](./ADR-021-ldap-signing-channel-binding.md) — RFC 5929 channel binding (complementary control for NTLM-relay; this ADR's local ticket-signature validation is the Kerberos analog)
- [ADR-023](./ADR-023-kerberos-audit-events.md) — `pac_validation.success/failed/skipped` and `netlogon_sam_logon_ex` events
- [ADR-082](./ADR-082-ms-kile-pac-generation.md) — PAC builder emits `PAC_BUFFER_TICKET_CHECKSUM`; this ADR specifies how services validate it
- [MS-NRPC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/) — Netlogon Remote Protocol
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) — KDC PAC validation requirements
- [MS-PAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) — `PAC_BUFFER_TICKET_CHECKSUM` buffer type
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266) — GSS-API Channel Bindings (complementary control)
- [Microsoft Kerberos PAC validation](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/kerberos-policy) — `VerifyPacAuthenticators` registry semantics
- [Microsoft Security Advisory ADV210003 (PetitPotam)](https://msrc.microsoft.com/update-guide/vulnerability/ADV210003)
