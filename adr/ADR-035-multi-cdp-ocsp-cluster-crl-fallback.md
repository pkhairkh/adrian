---
title: "ADR-035: Multi-CDP HTTP fallback; HA OCSP cluster; CRL fallback"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-063
severity: high
tags: [adr, cert-service, crl, cdp, ocsp, revocation, ha]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../docs/05-pki-certs/04-ocsp-crl.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ./ADR-033-ocsp-responder-rfc-6960-nonce-ha.md
last_updated: 2026-08-13
---

# ADR-035: Multi-CDP HTTP fallback; HA OCSP cluster; CRL fallback

## Status

Accepted — 2026-08-13.

## Context

If CRL/OCSP is unreachable from a client, the client either fails-closed (TLS reject with `0x80092013 — Revocation offline`) or fails-open (skip revocation check, accept cert) depending on the application's policy. Per [docs/05-pki-certs/04-ocsp-crl.md](../docs/05-pki-certs/04-ocsp-crl.md), AD CS publishes CRLs to AD (`certificateRevocationList` attribute on `CN=<CAName>,CN=...-CDP,CN=Public Key Services,...`) and HTTP (URL encoded in the cert's CRL Distribution Point extension OID 2.5.29.31, e.g., `http://pki.corp.example.com/crl/<CAName>.crl`). The OCSP URL is encoded in the Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1) with accessMethod `ad-ocsp` (1.3.6.1.5.5.7.48.1).

During CA/AD outage, per [PC-063](../catalog/05-cert-service.md): (a) CRL cannot be regenerated (CA service is down, `certutil -crl` fails); (b) existing CRLs may expire (`NextUpdate` passes, clients reject the stale CRL); (c) OCSP responder cannot refresh its CRL cache; (d) LDAP-based CRL fetch fails (AD is down). `CRLOverlapPeriod` (Server 2008+) extends CRL validity — a new CRL is published *before* the old one's `NextUpdate`, so the overlap window covers CA downtime. But this only works if the overlap window is longer than the outage; a multi-day outage exceeds any reasonable overlap.

The framework must support CRL caching on client (per-platform `CryptnetUrlCache` / `cacerts.pem` / `c_rehash`), multiple CDP URLs (HTTP + LDAP + FILE), OCSP stapling (RFC 6066 §8), backup CRL distribution points (CDN-backed HTTP, independent of AD), and per-application fail-closed vs. fail-open policy. The client-side behavior should be per-application configurable, not a global policy.

## Decision

The framework shall publish CRLs to multiple HTTP distribution points (multi-CDP) for resilience, deploy OCSP responders as a highly-available cluster (per ADR-033), and require clients to support CRL fallback when OCSP is unreachable.

1. **Multi-CDP HTTP fallback** — every cert issued by the framework's CA carries 2+ CDP URLs in its CRL Distribution Points extension (OID 2.5.29.31): (a) a primary HTTP URL on the framework's CA distribution host (`http://pki.<domain>/crl/<ca-name>.crl`), (b) a secondary HTTP URL on a CDN-backed distribution independent of AD and the framework's CA host (`http://crl-cdn.<domain>/crl/<ca-name>.crl`, backed by Cloudflare, CloudFront, Akamai, or self-hosted MinIO with CDN front-end). LDAP CDP (`ldap:///CN=<CAName>,CN=...-CDP,CN=Public Key Services,...`) is included as a tertiary for AD-interop clients that prefer LDAP.
2. **CDN-backed CRL distribution** — CRLs are published to the CDN at CRL generation time. The CDN serves the CRL from edge locations, providing low-latency fetch worldwide and independence from the framework's CA host availability. The CDN is configured with a long TTL (matching the CRL's `NextUpdate`) and is purged on CRL regeneration. For air-gapped deployments, the "CDN" is a self-hosted MinIO cluster with multiple replicas.
3. **HA OCSP cluster** — per ADR-033, the OCSP responder is deployed as a stateless horizontally-scalable cluster (minimum 3 instances) behind a load balancer. The OCSP URL in the cert's AIA extension points to the load-balanced URL (`http://ocsp.<domain>`), not to individual instances.
4. **CRL fallback when OCSP unreachable** — clients configured for OCSP must fall back to CRL fetch when OCSP is unreachable. The framework's Client SDK implements this fallback: on OCSP timeout (5 seconds) or OCSP `tryLater` response, the client fetches the CRL from the primary CDP URL (with 5-second timeout), then the secondary CDP URL (with 5-second timeout). If all CDP URLs fail, the client applies the per-application fail-closed/fail-open policy.
5. **OCSP stapling (RFC 6066 §8)** — the framework's TLS servers (HTTPS, LDAPS, RDP, WinRM) request and staple OCSP responses during the TLS handshake. This eliminates the client-side OCSP fetch round-trip and provides revocation status even when the client cannot reach the OCSP responder directly. The stapled response is refreshed every 5 minutes (well within the responder's pre-signed window per ADR-033).
6. **Per-application fail-closed/fail-open policy** — the framework defines a per-application revocation policy: `strict` (fail-closed: if revocation status cannot be determined, reject the cert), `best-effort` (fail-open with warning: if revocation status cannot be determined, accept the cert but log a warning), `disabled` (skip revocation check entirely, for air-gapped test environments only). Default per application type: LDAPS → `strict`, HTTPS → `best-effort`, RDP → `strict`, WinRM → `strict`, SMTP → `best-effort`.
7. **Client-side CRL cache** — the framework's Client SDK maintains a CRL cache per-platform: Windows `CryptnetUrlCache` (via `CryptRetrieveObjectByUrl` API), macOS `ocspd` daemon (which caches CRLs at `/private/var/db/crls/cacerts.pem`), Linux `/etc/ssl/certs/` + `c_rehash` (via OpenSSL `X509_STORE`). Cache TTL is the CRL's `NextUpdate`; on cache miss, the client fetches from the CDP URL.
8. **CRL pre-publication** — the CA publishes the next CRL before the current CRL's `NextUpdate` (matching AD CS's `CRLOverlapPeriod`). Default overlap is 24 hours (configurable). This ensures there is always a valid CRL available even during CA downtime, as long as the downtime is shorter than the overlap window.

**Concrete specification**:

- Certs issued by the framework's CA carry 3 CDP URLs: `http://pki.<domain>/crl/<ca-name>.crl` (primary), `http://crl-cdn.<domain>/crl/<ca-name>.crl` (CDN-backed), `ldap:///CN=<CAName>,CN=...-CDP,CN=Public Key Services,...?certificateRevocationList?base?objectClass=cRLDistributionPoint` (LDAP for AD interop).
- Certs carry 1 OCSP URL in AIA: `http://ocsp.<domain>` (load-balanced).
- The CA publishes CRLs to all 3 CDP URLs at CRL generation time. The CDN upload is via S3 API (Cloudflare R2, AWS S3, MinIO); the LDAP publish is via LDAP `modify` on the `certificateRevocationList` attribute.
- The framework's Client SDK implements OCSP-then-CRL fallback: try OCSP (5s timeout); on failure, try CRL primary CDP (5s timeout); on failure, try CRL CDN CDP (5s timeout); on failure, apply per-application policy.
- The framework's TLS servers (LDAPS, HTTPS, RDP, WinRM) request OCSP stapling via the `status_request` TLS extension (RFC 6066 §8) and refresh the stapled response every 5 minutes.
- The per-application revocation policy is configured in the framework's directory: `application/<app-name>/revocation_policy = strict|best-effort|disabled`. Default per application type is documented in the framework's reference.
- The framework's `adrian-tls check <host:port>` CLI reports: cert chain validity, OCSP status (stapled or fetched), CRL status, and the effective revocation policy.

## Rationale

Three alternatives were considered.

**Alternative 1: OCSP-only (no CRL).** Drop CRL entirely; rely on OCSP for all revocation checks. Rejected because OCSP is a single point of failure — if the OCSP responder cluster is unreachable (network partition, DNS failure, all instances down), clients cannot check revocation. CRL fallback provides resilience: the CDN-backed CRL is independent of the OCSP responder, so a network partition that takes down OCSP does not take down the CRL CDN.

**Alternative 2: CRL-only (no OCSP).** Drop OCSP; rely on CRL for all revocation checks. Rejected because CRLs are large (10K+ revoked certs = multi-MB CRL) and slow to download. OCSP provides per-cert revocation status in a single HTTP request/response, with lower latency for the common case. Modern TLS clients prefer OCSP stapling over CRL fetch. Dropping OCSP breaks OCSP stapling.

**Alternative 3: Single CDP URL (HTTP only, no CDN, no LDAP).** Publish CRL to one HTTP URL on the CA host. Rejected because a single URL is a single point of failure — if the CA host is down, the CRL is unreachable. Multi-CDP (HTTP primary + HTTP CDN + LDAP tertiary) provides resilience across host failure, network partition, and AD outage. The CDN-backed CRL is the critical resilience feature: it is independent of both the CA host and AD, surviving both.

The decision aligns with industry practice: Let's Encrypt publishes CRLs to multiple HTTP CDPs and operates OCSP responders with HA; DigiCert publishes CRLs to multiple CDPs (HTTP + LDAP); Mozilla's PKI policy requires multiple CDP URLs for publicly-trusted CAs. The framework's design is the same shape.

Cost: ~4 person-weeks for the multi-CDP publishing, the CDN integration, the OCSP-then-CRL fallback in the Client SDK, and the OCSP stapling in TLS servers.

## Consequences

**Positive**. Revocation checking becomes resilient: OCSP cluster (per ADR-033) + multi-CDP CRL (HTTP primary + CDN + LDAP) provides three independent paths. CDN-backed CRL survives CA host failure and AD outage. OCSP stapling eliminates client-side OCSP fetch latency. Per-application fail-closed/fail-open policy gives operators control over the security/availability tradeoff. CRL pre-publication ensures there is always a valid CRL during CA downtime.

**Negative**. Multi-CDP publishing adds operational complexity: the CDN must be configured, purged on CRL regeneration, and monitored. The OCSP-then-CRL fallback in the Client SDK adds latency on OCSP failure (5s timeout before falling back to CRL). Per-application revocation policy is a new configuration surface that operators must understand.

**Neutral**. The default per-application policy (LDAPS strict, HTTPS best-effort) is a deliberate trade-off: strict for security-critical protocols, best-effort for user-facing protocols where availability matters. Operators can override per-application. The LDAP CDP is a tertiary for AD-interop clients; framework-native clients prefer HTTP.

**Implementation cost**. ~4 person-weeks for multi-CDP publishing, CDN integration, OCSP-then-CRL fallback, and OCSP stapling.

**Operational impact**. Operators deploy the CDN (or self-hosted MinIO cluster for air-gapped). CRL regeneration publishes to all CDP URLs automatically. The OCSP cluster is monitored via Prometheus metrics (per ADR-033). Per-application revocation policy is configured in the directory.

## Alternatives Considered

### Alternative A: OCSP-only (no CRL)

Drop CRL entirely; rely on OCSP for all revocation checks. The OCSP cluster (per ADR-033) provides HA.

Rejected because OCSP is a single point of failure even with HA clustering. If the OCSP cluster is unreachable (network partition between client and OCSP, DNS failure for `ocsp.<domain>`, all OCSP instances down simultaneously), clients cannot check revocation. CRL fallback provides resilience: the CDN-backed CRL (`crl-cdn.<domain>`) is independent of the OCSP cluster (different host, different DNS, different network path), so a failure that takes down OCSP does not take down the CRL CDN. Defense in depth: OCSP is the primary (low latency, per-cert), CRL is the fallback (high resilience, multi-MB). Both are needed.

### Alternative B: CRL-only (no OCSP)

Drop OCSP; rely on CRL for all revocation checks. The CDN-backed CRL provides HA.

Rejected because CRLs are large (10K+ revoked certs = multi-MB CRL) and slow to download (multi-second over WAN, even from CDN). The common case (cert is not revoked) requires downloading the entire CRL, which is wasteful. OCSP provides per-cert revocation status in a single HTTP request/response (~1 KB), with lower latency for the common case. Modern TLS clients (Chrome, Firefox, Safari, OpenSSL) prefer OCSP stapling over CRL fetch because of the latency and bandwidth advantage. Dropping OCSP breaks OCSP stapling (RFC 6066 §8), which is the dominant revocation-check mechanism in modern TLS.

### Alternative C: Single CDP URL (HTTP only, no CDN, no LDAP)

Publish CRL to one HTTP URL on the CA host (`http://pki.<domain>/crl/<ca-name>.crl`). Simpler than multi-CDP.

Rejected because a single URL is a single point of failure. If the CA host is down (planned maintenance, hardware failure), the CRL is unreachable — clients that fail-closed reject all certs. Multi-CDP (HTTP primary + HTTP CDN + LDAP tertiary) provides resilience across host failure (CDN is independent), network partition (CDN is on a different network), and AD outage (HTTP CDN does not depend on AD). The CDN-backed CRL is the critical resilience feature: it is independent of both the CA host and AD, surviving both. The cost of multi-CDP (one additional HTTP upload to CDN per CRL regeneration, which happens every 24 hours) is negligible compared to the resilience gain.

## Open Questions

- Should the framework support CRLite (Mozilla's Bloom filter cascade) as a fourth revocation path? CRLite compresses the CRL to ~10 KB, eliminating per-cert OCSP lookups for clients that support it. Current decision: defer CRLite to Tier 3 (per ADR-033); the multi-CDP + OCSP design is forward-compatible with CRLite (the CDN could serve CRLite filters in addition to CRLs).
- The default per-application revocation policy: should HTTPS be `strict` instead of `best-effort`? Some security teams prefer strict for all protocols; some availability teams prefer best-effort for all. Current decision: per-protocol default (LDAPS strict, HTTPS best-effort), overridable per-application.
- The CDN purge on CRL regeneration: should it be synchronous (wait for purge before publishing new CRL) or asynchronous (publish new CRL, purge in background)? Synchronous is safer (no stale CRL served from CDN) but slower; asynchronous is faster but may serve stale CRL briefly. Current decision: synchronous purge with 30-second timeout; on timeout, fall back to asynchronous and alert.
- The LDAP CDP: should it be included in framework-native certs (which do not need LDAP) or only in AD-interop certs? Current decision: included in all certs for uniformity; framework-native clients ignore it.

## Cross-capability impact

- **Cert Service (PC-063)**: This ADR. PC-061 (OCSP responder, ADR-033) — the OCSP cluster is one of the three revocation paths; the multi-CDP CRL is the fallback.
- **Client SDK (PC-085..PC-093)**: The OCSP-then-CRL fallback lives in the Client SDK's TLS validation path; ORQ-169/170 (Client SDK architecture) gates the implementation language.
- **Operations (PC-106..PC-115)**: ADR-057 (OTel instrumentation) — CRL fetch latency, OCSP fetch latency, and revocation policy decisions are OTel metrics.
- **Federation Gateway (PC-068..PC-077)**: PC-070 (token-signing cert rollover, ADR-038) — the federation layer's token-signing certs are checked via OCSP + CRL; the multi-CDP design is critical for federation availability.
- **Security (PC-116..PC-123)**: Per-application fail-closed/fail-open policy is a Security concern; the default policy (strict for LDAPS/RDP/WinRM, best-effort for HTTPS/SMTP) is documented in the Security threat model.

## References

- [PC-063](../catalog/05-cert-service.md) — problem statement in the catalog
- [docs/05-pki-certs/04-ocsp-crl.md](../docs/05-pki-certs/04-ocsp-crl.md) — CRL publication URLs, AIA/CDP extension OIDs, `CRLOverlapPeriod`, `0x80092013` error, OCSP stapling
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — CRL/OCSP HTTP endpoint table, `CRLPublicationURLs` registry
- [RFC 5280 X.509](https://www.rfc-editor.org/rfc/rfc5280) — CRL Distribution Points extension (§4.2.1.13), AIA extension (§4.2.2.1)
- [RFC 6960 OCSP](https://www.rfc-editor.org/rfc/rfc6960) — OCSP protocol
- [RFC 6066 TLS Extensions](https://www.rfc-editor.org/rfc/rfc6066) — OCSP stapling (§8)
- [Mozilla PKI Policy](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/) — industry precedent for multi-CDP CRLs
