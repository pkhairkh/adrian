---
title: "ADR-038: JWKS endpoint per RFC 8414; webhook notification; 15-day overlap"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-070
severity: medium
tags: [adr, federation-gateway, jwks, cert-rollover, oidc, saml]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../docs/06-federation-sso/01-adfs-architecture.md
  - ../docs/06-federation-sso/02-saml-ws-fed.md
  - ./ADR-039-oidc-primary-wstrust-bridge.md
  - ./ADR-022-ntp-via-chrony.md
last_updated: 2026-08-13
---

# ADR-038: JWKS endpoint per RFC 8414; webhook notification; 15-day overlap

## Status

Accepted — 2026-08-13.

## Context

AD FS auto-rolls the token-signing cert (Server 2012 R2+): a new cert is published alongside the old for 5–15 days (configurable via `Set-AdfsProperties -SigningCertificateRolloverInterval`), then promoted to primary. Per [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md), AD FS publishes both certs (old primary + new secondary) in federation metadata at `/FederationMetadata/2007-06/FederationMetadata.xml` as `<KeyDescriptor use="signing">` entries in the `<IDPSSODescriptor>`. RPs that auto-refresh metadata (most modern SAML SPs do, typically every 24 hours) pick up the new cert before promotion. RPs that cache metadata statically fail with `MSIS1006 — Token signing certificate thumbprint does not match` after promotion.

Per [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), the failure mode is intermittent: some RPs succeed (those that refreshed metadata recently) and some fail (those with stale cache) — making diagnosis harder. The `certutil -dspublish` equivalent for AD FS is automatic — the AD FS service publishes its signing cert to AD at `CN=<ADFS-FS-Name>,CN=Program Data,CN=ADFS,CN=Microsoft,CN=Program Data,DC=...` (a `contact` object with `servicePrincipalName` and `userCertificate` attributes), so domain-joined clients can validate ADFS-issued tokens without prior trust config. But non-domain-joined RPs (SaaS apps, cloud services) must fetch metadata manually, per [PC-070](../catalog/06-federation-gateway.md).

For the framework, the design must: (a) publish both old + new certs in federation metadata during the rollover window, (b) support `validUntil` attribute on metadata for cert transition signaling, (c) for OIDC, use JWKS rotation API (RFC 8414 Authorization Server Metadata, RFC 7517 JSON Web Key) with both `kid`s published during rollover, (d) auto-notify RPs via webhook on cert rollover (a non-standard but practical extension). The framework must publish both old + new certs in federation metadata during the rollover window, must support `validUntil` for cert transition signaling, for OIDC must support JWKS rotation (RFC 8414 + RFC 7517) with both `kid`s published, and should support webhook-based RP notification on cert rollover.

## Decision

The framework shall publish a JWKS endpoint per RFC 8414 with both old and new `kid`s during rollover, shall support `validUntil` for SAML metadata, shall auto-notify registered RPs via webhook on cert rollover, and shall maintain a 15-day overlap window during rollover.

1. **JWKS endpoint per RFC 8414** — the framework's OIDC Authorization Server publishes its metadata at `/.well-known/oauth-authorization-server` (RFC 8414 §3.1) including the `jwks_uri` field pointing to `/.well-known/jwks.json` (RFC 7517 JSON Web Key Set). The JWKS contains the active token-signing key(s) as JWK objects with `kid`, `kty`, `use` (`sig`), `alg` (`RS256`), `n`, `e` (for RSA) or `x`, `y`, `crv` (for ECDSA). RPs fetch the JWKS at discovery time and refresh per the RP's policy (recommended: every 24 hours, or on JWT validation failure).
2. **OIDC Discovery (RFC 8414)** — the framework publishes the full Authorization Server Metadata at `/.well-known/oauth-authorization-server` including `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `response_types_supported`, `grant_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `scopes_supported`, `claims_supported`. RPs use this metadata for auto-configuration (no manual endpoint registration).
3. **JWKS rotation during rollover** — when a token-signing cert rollover begins, the framework publishes both the old and new keys in the JWKS, each with a distinct `kid`. JWTs are signed with the new key (which becomes primary); the old key remains in the JWKS for the overlap window (default 15 days) so RPs can validate JWTs signed before the rollover. After the overlap window, the old key is removed from the JWKS.
4. **SAML metadata `validUntil`** — for SAML RPs, the framework publishes federation metadata at `/metadata` (SAML 2.0 metadata XML) with `validUntil` attribute on the `<EntityDescriptor>` set to the rollover end date. SAML RPs that respect `validUntil` refresh metadata before the date; RPs that do not refresh are alerted via webhook (below).
5. **Webhook notification** — when a cert rollover begins, the framework sends a webhook (HTTP POST) to each registered RP's `metadata_refresh_url` (configured at RP registration time). The webhook payload: `{"event": "cert_rollover_start", "issuer": "<issuer>", "jwks_uri": "<jwks_uri>", "new_kid": "<kid>", "overlap_days": 15}`. The webhook is sent on rollover start, rollover promote (new key becomes primary), and rollover end (old key removed). RPs acknowledge via HTTP 200; non-acknowledged webhooks are retried 3 times with exponential backoff.
6. **15-day overlap window** — the rollover overlap window is 15 days (matching AD FS's default max). During this window: (a) both old and new keys are in the JWKS, (b) JWTs are signed with the new key, (c) old-key-signed JWTs are still valid for RPs that have not refreshed, (d) webhook notifications are sent on rollover start, promote, and end. The 15-day window is configurable per-deployment (operators can extend for slow-refreshing RPs).
7. **Per-RP rollover policy** — each RP can declare a `rollover_overlap_days` override (longer than the default 15 days for RPs with slow metadata refresh). The framework extends the overlap window for that RP's specific old key (the old key remains in the JWKS for the RP's extended window, even after other RPs' 15-day window has expired).
8. **Cert lifecycle** — token-signing certs are issued by the framework's Cert Service (per ADR-037), valid for 1 year (configurable). The framework's federation service auto-enrolls a new cert 30 days before expiry, begins the rollover at expiry-15-days, promotes at expiry-7-days, and removes the old key at expiry. The rollover is fully automated; operator intervention is not required.

**Concrete specification**:

- The JWKS endpoint is `GET /.well-known/jwks.json` returning `{"keys": [{"kid": "<kid>", "kty": "RSA", "use": "sig", "alg": "RS256", "n": "<base64url>", "e": "<base64url>"}]}`.
- The Authorization Server Metadata is `GET /.well-known/oauth-authorization-server` returning the RFC 8414 metadata JSON.
- SAML metadata is `GET /metadata` returning SAML 2.0 metadata XML with `validUntil` and `<KeyDescriptor use="signing">` entries for both old and new keys during rollover.
- Webhook delivery: HTTP POST to the RP's `metadata_refresh_url` with JSON payload, `Content-Type: application/json`, HMAC-SHA256 signature in `X-Adrian-Webhook-Signature` header (keyed by a per-RP secret configured at RP registration). Retry policy: 3 retries with exponential backoff (1s, 2s, 4s); non-delivery after 3 retries raises an alert.
- The federation service exposes `GET /api/v1/cert-rollover/status` for operators: current phase (`idle` | `rollover-start` | `rollover-promote` | `rollover-end`), old kid, new kid, overlap days remaining.
- The framework's `adrian-fed rollover --start` CLI manually triggers a rollover (for testing or for non-scheduled rotations); `adrian-fed rollover --status` shows the current phase.
- Per-RP rollover policy: `PUT /api/v1/rps/<rp-id>/rollover-policy` with `{"overlap_days": 30}` extends the per-RP overlap window.

## Rationale

Three alternatives were considered.

**Alternative 1: SAML metadata only (no JWKS, no webhook).** Publish only SAML metadata at `/metadata`; rely on RPs to refresh metadata on the standard 24-hour cycle. Rejected because (a) OIDC RPs do not consume SAML metadata — they need JWKS per RFC 7517; (b) 24-hour metadata refresh means up to 24 hours of stale-cert failures during rollover, which is operationally unacceptable for production RPs; (c) SAML metadata refresh is RP-dependent and not guaranteed (some RPs cache metadata statically until manual refresh, per the KB citation of `MSIS1006` failures).

**Alternative 2: Email notification only (no webhook).** Send email to RP operators on cert rollover; rely on operators to manually refresh metadata. Rejected because (a) email is asynchronous and may be missed (operators get too much email); (b) manual metadata refresh is error-prone (operators may forget or be unavailable); (c) email does not provide acknowledgement — the framework cannot know whether the RP refreshed. Webhook provides synchronous notification with acknowledgement.

**Alternative 3: No overlap window (immediate key switch).** Switch the token-signing key immediately on rollover; remove the old key from the JWKS at the same time. Rejected because (a) JWTs signed with the old key that are still in flight (in RP caches, in user sessions) become invalid instantly, causing user-facing auth failures; (b) RPs that have not refreshed metadata cannot validate new-key-signed JWTs, causing auth failures until they refresh. The 15-day overlap window ensures both old and new keys are valid simultaneously, eliminating in-flight JWT failures.

The decision aligns with industry practice: Google Identity Platform publishes JWKS with overlap during key rotation; Auth0 publishes JWKS with overlap; Microsoft Entra ID (Azure AD) publishes JWKS with overlap. Webhook notification is less common (Google and Auth0 do not send webhooks) but is a practical extension for enterprises with strict RP-management requirements.

Cost: ~4 person-weeks for the JWKS endpoint, the rollover state machine, the webhook delivery, and the SAML metadata `validUntil` support.

## Consequences

**Positive**. Cert rollover becomes transparent to RPs that respect JWKS rotation and webhook notification. The 15-day overlap window eliminates in-flight JWT failures. Per-RP rollover policy accommodates slow-refreshing RPs. OIDC Discovery (RFC 8414) enables RP auto-configuration. SAML metadata `validUntil` provides transition signaling for SAML RPs.

**Negative**. Webhook delivery requires RP cooperation (RPs must register a `metadata_refresh_url` and validate the HMAC signature). RPs that do not support webhooks (legacy SaaS apps) fall back to 24-hour metadata refresh, with potential for stale-cert failures. The 15-day overlap window means the JWKS contains 2 keys during rollover, slightly increasing JWT validation cost (RP must try both kids).

**Neutral**. The cert lifecycle (1-year certs, 30-day pre-enroll, 15-day overlap, 7-day promote) is fully automated; operators do not need to initiate rollovers manually. The `adrian-fed rollover --start` CLI is provided for testing and non-scheduled rotations.

**Implementation cost**. ~4 person-weeks for the JWKS endpoint, rollover state machine, webhook delivery, and SAML metadata `validUntil`.

**Operational impact**. Operators register RPs with `metadata_refresh_url` at RP registration time. The federation service auto-rolls token-signing certs per the lifecycle. Webhook delivery failures raise alerts. The `adrian-fed rollover --status` CLI provides rollover visibility.

## Alternatives Considered

### Alternative A: SAML metadata only (no JWKS, no webhook)

Publish only SAML metadata at `/metadata` with `<KeyDescriptor use="signing">` entries for both old and new keys during rollover. Rely on RPs to refresh metadata on the standard 24-hour cycle.

Rejected because (a) OIDC RPs do not consume SAML metadata — they need JWKS per RFC 7517, so OIDC RPs would have no way to discover the new key; (b) 24-hour metadata refresh means up to 24 hours of stale-cert failures during rollover — for a production RP serving 100K users, 24 hours of intermittent auth failures is operationally unacceptable; (c) SAML metadata refresh is RP-dependent and not guaranteed — the KB citation of `MSIS1006 — Token signing certificate thumbprint does not match` failures indicates that some RPs cache metadata statically until manual refresh, which can take days or weeks to resolve. The JWKS + webhook + 15-day overlap design addresses all three issues: JWKS for OIDC RPs, webhook for proactive notification, 15-day overlap for stale-cache tolerance.

### Alternative B: Email notification only (no webhook)

Send email to RP operators on cert rollover start, promote, and end. Rely on operators to manually refresh metadata at their RPs.

Rejected because (a) email is asynchronous and may be missed — operators receive too much email, and cert-rollover notifications are low-priority until they cause an outage; (b) manual metadata refresh is error-prone — operators may forget, be unavailable, or refresh incorrectly (e.g., refreshing the wrong RP); (c) email does not provide acknowledgement — the framework cannot know whether the RP refreshed metadata, so it cannot extend the overlap window for RPs that did not refresh. Webhook provides synchronous notification with HTTP-level acknowledgement: the framework knows which RPs acknowledged and can extend the overlap window for non-acknowledging RPs (per the per-RP rollover policy).

### Alternative C: No overlap window (immediate key switch)

Switch the token-signing key immediately on rollover. Remove the old key from the JWKS at the same time. RPs must refresh metadata immediately to validate new-key-signed JWTs.

Rejected because (a) JWTs signed with the old key that are still in flight (in RP caches, in user sessions, in long-running API calls) become invalid instantly, causing user-facing auth failures — for a production RP, this means thousands of users logged out simultaneously; (b) RPs that have not refreshed metadata cannot validate new-key-signed JWTs, causing auth failures until they refresh — for RPs with 24-hour refresh cycles, this is up to 24 hours of failures; (c) the operator cannot predict which RPs have refreshed, so the failure scope is unknown. The 15-day overlap window ensures both old and new keys are valid simultaneously: in-flight old-key JWTs remain valid for their remaining lifetime, and RPs have 15 days to refresh metadata before the old key is removed. The cost (2 keys in the JWKS during rollover) is negligible compared to the operational benefit.

## Open Questions

- The 15-day overlap window: should it be tunable per-deployment or fixed? Current decision: tunable per-deployment (default 15 days); some deployments may want longer (30 days for slow-refreshing RPs) or shorter (7 days for fast-refreshing RPs).
- Webhook delivery: should the framework support multiple webhook URLs per RP (e.g., primary and backup)? Current decision: single webhook URL per RP; RPs that need backup can configure a load-balanced URL.
- The per-RP rollover policy (`overlap_days` override): should there be a maximum (e.g., 90 days) to prevent indefinite old-key retention? Current decision: maximum 90 days; beyond that, the old key is removed and the RP must refresh or fail.
- The cert lifecycle (1-year certs, 30-day pre-enroll): should the cert validity be tunable per-deployment? Current decision: tunable (default 1 year); high-security deployments may want shorter (6 months) for faster rotation.

## Cross-capability impact

- **Federation Gateway (PC-070)**: This ADR. PC-071 (OIDC primary, ADR-039) — JWKS is OIDC-native; SAML metadata is SAML-native; both are supported.
- **Federation Gateway (PC-072)**: ADR-040 (SAML clock skew) — cert rollover interacts with clock skew (the overlap window must be longer than the maximum clock skew); ADR-022 (NTP via chrony) underpins the time-sync prerequisite.
- **Cert Service (PC-057..PC-067)**: ADR-037 (two-tier CA with HSM root) — token-signing certs are issued by the framework's Cert Service; autoenroll renews them.
- **Operations (PC-106..PC-115)**: ADR-057 (OTel instrumentation) — webhook delivery success/failure and rollover phase are OTel metrics. ADR-060 (audit logs) — rollover events are audit-logged.

## References

- [PC-070](../catalog/06-federation-gateway.md) — problem statement in the catalog
- [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md) — Token-signing cert auto-rollover, 5–15 day overlap window, AD publication
- [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md) — Federation metadata XML structure, `MSIS1006` signature validation errors
- [RFC 8414 OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) — OIDC Discovery
- [RFC 7517 JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517) — JWKS format
- [RFC 7519 JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519) — JWT (uses `kid` for key identification)
- [SAML 2.0 Metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf) — SAML metadata `validUntil`
