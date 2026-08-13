---
title: "ADR-033: OCSP responder per RFC 6960 with nonce; HA cluster"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-061
severity: high
tags: [adr, cert-service, ocsp, rfc-6960, nonce, ha]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../docs/05-pki-certs/04-ocsp-crl.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ./ADR-035-multi-cdp-http-ocsp-cluster.md
last_updated: 2026-08-13
---

# ADR-033: OCSP responder per RFC 6960 with nonce; HA cluster

## Status

Accepted — 2026-08-13.

## Context

AD CS Online Responder (`OCSPResp.exe` under `svchost -k NetworkService`) signs `BasicOCSPResponse` blobs (RFC 6960 ASN.1: `OCSPResponse` → `ResponseBytes` → `BasicOCSPResponse` → `ResponseData` → `SingleResponse` per cert) using an OCSP signing cert (EKU `id-kp-OCSPSigning` 1.3.6.1.5.5.7.3.9, carries `ID-PKIX-OCSP-NoCheck` extension OID 1.3.6.1.5.5.7.48.1.5 so clients skip the signing cert's own CRL check), per [docs/05-pki-certs/04-ocsp-crl.md](../docs/05-pki-certs/04-ocsp-crl.md). The responder reads the CA's CRL from `CRLTable` in the CA ESE database. Per-revocation-configuration registry: `HKLM\SYSTEM\CurrentControlSet\Services\OCSP\Responder\<RevocationConfigName>\SigningFlags = 0x31` (bit 0 = use CA cert private key for signing, bit 4 = RESIGN_ON_KEY_WARNING re-sign after CRL update, bit 5 = DISABLE_SSL_CLIENT_CERT_CHECK).

The scaling problems, per [PC-061](../catalog/05-cert-service.md), are: (a) the OCSP responder is a single point of failure during CA outage — if the CA ESE database is unreachable, the responder cannot refresh its CRL cache; (b) CRL generation can fail with `0x80070020` (file in use) when IIS holds the CRL file lock; (c) for large CAs (10K+ revoked certs), the `SerNumDir\0a\0b\...` hash bucket lookup becomes slow (10+ seconds per OCSP response); (d) the responder does not natively support clustering — multiple responder instances must share the same CRL source, which requires file-system or SQL-backed CRL distribution. Per the same KB, `pkiview.msc` shows OCSP "Error: the OCSP response is invalid" when the signing cert expires; renewal via `OCSPResponseSigning<CAName>` template enroll on the OCSP host (`certutil -pulse`) is the recovery.

For the framework, clustered OCSP responders (multiple instances behind a load balancer, each with independent signing cert but shared CRL source) + CRL pre-publication (publish next CRL before current expires — `CRLOverlapPeriod` already does this on the CA) are the baseline. The framework must support `ID-PKIX-OCSP-NoCheck` extension on signing cert, pre-cached CRL (`CRLOverlapPeriod`), nonce extension (OID 1.3.6.1.5.5.7.48.1.2) for replay prevention, and multiple OCSP responder instances (clustering).

## Decision

The framework shall implement an OCSP responder per RFC 6960 with nonce extension support, deployed as a stateless horizontally-scalable cluster with pre-signed frequent responses for cacheability.

1. **RFC 6960 conformance** — the framework's OCSP responder implements `BasicOCSPResponse` per RFC 6960 §4.2.1. The responder accepts OCSP requests over HTTP POST (per RFC 6960 §2.3) and returns `OCSPResponse` per §2.4. The responder supports the `id-pkix-ocsp-nonce` extension (OID 1.3.6.1.5.5.7.48.1.2) per RFC 8954 (nonce length 32 bytes minimum, 128 bytes maximum; the responder reflects the client's nonce in the response to prevent replay).
2. **`ID-PKIX-OCSP-NoCheck` extension** — the OCSP signing cert carries the `ID-PKIX-OCSP-NoCheck` extension (OID 1.3.6.1.5.5.7.48.1.5), so clients skip the signing cert's own CRL check. The signing cert has EKU `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9) and is issued by the same CA as the certs it is checking (direct signing) — delegated signing is supported but not the default.
3. **Stateless cluster** — the responder is stateless: each instance reads the CRL from a shared source (HTTP CRL distribution point per ADR-035, or local replica of the CA database) and signs responses using its own signing cert. Multiple instances are deployed behind a layer-4 load balancer (HAProxy, NGINX, AWS NLB). Any instance can serve any request; there is no session affinity. The cluster scales horizontally by adding instances.
4. **Pre-signed responses** — the responder pre-signs OCSP responses for the next 4 hours (configurable) at CRL refresh time. The pre-signed responses are stored in an in-memory LRU cache keyed by cert serial number. On request, the responder returns the pre-signed response (cache hit) or signs on demand (cache miss). Pre-signing amortizes signing cost (the HSM-bound signing key is the bottleneck) and enables sub-millisecond response times.
5. **Nonce handling** — when the client includes a nonce in the request, the responder cannot return a pre-signed response (the nonce must be reflected in the signed response). The responder signs on demand for nonce-bearing requests. To prevent nonce-driven denial of service (every request with a unique nonce forces an on-demand sign), the responder limits on-demand signing to 10% of capacity; above that, it returns a `tryLater` response (RFC 6960 §2.4 `ocspResponseStatus = 3`).
6. **CRL refresh** — the responder refreshes its CRL cache at `NextUpdate - 1 hour` (1 hour before expiry), per the CA's `CRLOverlapPeriod`. The refresh is atomic: the new CRL is loaded into a new cache, then atomically swapped with the old cache (no in-flight requests see a half-loaded cache). If refresh fails, the responder continues serving from the old cache and raises an alert.
7. **HA deployment** — minimum 3 responder instances behind a load balancer, with health checks every 5 seconds. An instance that fails 3 consecutive health checks is removed from the pool. The signing cert is renewed automatically via the framework's autoenroll CSE (per the Cert Service's enrollment protocol, gated by ORQ-110/111).
8. **Stapling support** — the responder's responses are cacheable by TLS servers (per RFC 6066 §8 OCSP stapling). The `Cache-Control: public, max-age=300` header is set on responses, allowing TLS servers to staple the response for up to 5 minutes.

**Concrete specification**:

- The OCSP responder is a standalone service (not embedded in the CA); it runs as `adrian-ocsp-responder` on Linux, Windows Service on Windows, launchd daemon on macOS.
- The responder listens on `http://0.0.0.0:80/ocsp` (HTTP per RFC 6960; HTTPS is optional and adds TLS overhead without security benefit because the response is signed).
- The responder reads the CRL from `http://<ca-distribution-host>/crl/<ca-name>.crl` (per ADR-035's multi-CDP HTTP fallback). The CRL is refreshed every `CRLNextUpdate - 3600` seconds.
- The responder's signing cert is issued by the CA via the framework's autoenroll mechanism; the cert is stored in the framework's HSM (per ADR-032) and renewed 30 days before expiry.
- The responder exposes Prometheus metrics at `/metrics`: `ocsp_requests_total`, `ocsp_responses_signed_total`, `ocsp_cache_hits_total`, `ocsp_cache_misses_total`, `ocsp_response_duration_seconds`, `ocsp_crl_refresh_failures_total`. These metrics flow into the framework's OTel instrumentation (per ADR-057).
- The responder's configuration is in `/etc/adrian/ocsp-responder.conf` (Linux), `C:\ProgramData\Adrian\ocsp-responder.conf` (Windows), `/Library/Application Support/Adrian/ocsp-responder.conf` (macOS).
- The load balancer health check is `GET /healthz` returning HTTP 200 if the responder has a valid CRL cache and a non-expired signing cert.

## Rationale

Three alternatives were considered.

**Alternative 1: CRLite (Mozilla's compressed CRL via Bloom filter cascade).** Replace OCSP with CRLite — a cascade of Bloom filters that compresses a multi-MB CRL to ~10 KB, eliminating the need for per-cert OCSP lookups. Rejected for v1 because CRLite is research-grade (deployed in Firefox but not widely in enterprise PKI), requires a central CRLite service to generate and distribute the Bloom filter cascade (additional infrastructure), and is not yet an IETF standard. The framework defers CRLite adoption to Tier 3 (per the triage seed decision). OCSP per RFC 6960 is the well-established standard.

**Alternative 2: CRL-only (no OCSP).** Drop OCSP entirely; rely on CRL distribution per ADR-035. Rejected because CRLs are large (10K+ revoked certs = multi-MB CRL), slow to download, and require client-side parsing. OCSP provides per-cert revocation status in a single HTTP request/response, with lower latency for the common case (cert is not revoked). Modern TLS clients (browsers, OpenSSL) prefer OCSP stapling over CRL fetch.

**Alternative 3: Single OCSP responder (no clustering).** One responder instance per CA, with vertical scaling (more CPU, more memory). Rejected because a single responder is a single point of failure — if the responder is down, all TLS clients that fail-closed on revocation check cascade-fail. Clustering (minimum 3 instances behind a load balancer) provides HA and horizontal scalability.

The decision aligns with industry practice: Let's Encrypt operates OCSP responders per RFC 6960 with HA clustering; DigiCert operates clustered OCSP responders; Dogtag PKI's OCSP subsystem supports clustering. The framework's design is the same shape.

Cost: ~5 person-weeks for the responder implementation (RFC 6960 ASN.1, nonce handling, pre-signing, CRL refresh, clustering, metrics). The pre-signed cache is the highest-risk item (cache invalidation on CRL refresh must be atomic).

## Consequences

**Positive**. OCSP becomes highly available: clustered responders behind a load balancer survive instance failure. Pre-signed responses enable sub-millisecond latency for cache hits. Nonce support prevents replay attacks (RFC 8954). HA deployment (3+ instances) eliminates the single-point-of-failure that AD CS's Online Responder has. Prometheus metrics enable operational visibility.

**Negative**. Clustered responders require a load balancer (additional infrastructure). Pre-signed responses consume memory (~1 KB per pre-signed response × 100K certs = 100 MB per instance; manageable but non-trivial). The HSM-bound signing key is the throughput bottleneck — on-demand signing (for nonce-bearing requests) is limited by HSM signing rate (~1000 signatures/second on a Thales Luna; ~100/second on SoftHSM).

**Neutral**. The 10% capacity cap on nonce-bearing requests is a deliberate trade-off: it prevents nonce-driven DoS but means some legitimate nonce requests get `tryLater`. Modern TLS clients retry on `tryLater`, so the user-visible impact is minimal. CRLite is deferred to Tier 3; the framework's OCSP responder design is forward-compatible with CRLite (the responder could serve CRLite filters in addition to OCSP responses).

**Implementation cost**. ~5 person-weeks for the responder, pre-signed cache, CRL refresh, clustering, and metrics.

**Operational impact**. Operators deploy 3+ OCSP responder instances behind a load balancer. The signing cert is auto-renewed. CRL refresh is monitored via Prometheus metrics. The responder's health check is `GET /healthz`.

## Alternatives Considered

### Alternative A: CRLite (Mozilla Bloom filter cascade)

Replace OCSP with CRLite — a cascade of Bloom filters that compresses a multi-MB CRL to ~10 KB. Clients download the CRLite filter and check revocation status locally, eliminating per-cert OCSP lookups.

Rejected for v1 because (a) CRLite is research-grade — deployed in Firefox (Mozilla's central CRLite service generates and distributes the Bloom filter cascade) but not widely deployed in enterprise PKI; (b) CRLite requires a central service to generate the Bloom filter cascade from the CRL and distribute it to clients — additional infrastructure that the framework does not have in v1; (c) CRLite is not yet an IETF standard (it is a Mozilla proposal); (d) client-side CRLite support is limited (Firefox has it; Chrome, Safari, Edge do not). The framework defers CRLite adoption to Tier 3 per the triage seed decision. OCSP per RFC 6960 is the well-established standard with universal client support.

### Alternative B: CRL-only (no OCSP)

Drop OCSP entirely; rely on CRL distribution per ADR-035. Clients fetch the CRL from the CDP URL and check revocation status locally.

Rejected because CRLs are large (10K+ revoked certs = multi-MB CRL), slow to download (multi-second over WAN), and require client-side parsing (CPU cost). The common case (cert is not revoked) requires downloading the entire CRL. OCSP provides per-cert revocation status in a single HTTP request/response (~1 KB), with lower latency for the common case. Modern TLS clients (Chrome, Firefox, Safari, OpenSSL) prefer OCSP stapling over CRL fetch because of the latency and bandwidth advantage. Dropping OCSP would break OCSP stapling, which is the dominant revocation-check mechanism in modern TLS.

### Alternative C: Single OCSP responder (no clustering)

One responder instance per CA, vertically scaled (more CPU, more memory). Simpler to operate than a cluster.

Rejected because a single responder is a single point of failure. If the responder is down, all TLS clients that fail-closed on revocation check (`0x80092013 — Revocation offline`) cascade-fail — TLS connections to LDAPS, HTTPS, RDP, WinRM all fail. This is the exact failure mode of AD CS's Online Responder during CA outage (per PC-061). Clustering (minimum 3 instances behind a load balancer) provides HA: any instance can serve any request, and instance failure does not cause outage. The operational cost of a 3-instance cluster is modest (3 VMs or 3 containers) compared to the availability gain.

## Open Questions

- Should the framework support OCSP over HTTPS (in addition to HTTP)? RFC 6960 permits both; HTTPS adds TLS overhead without security benefit (the response is signed) but may be required by some firewalls that block HTTP. Current decision: HTTP only; revisit if operators report firewall issues.
- The pre-signed response window (4 hours): should it be tunable per-CA? High-volume CAs may want a longer window (8 hours) to amortize signing cost; low-volume CAs may want a shorter window (1 hour) for faster revocation propagation. Current decision: 4 hours default, tunable per-CA.
- The 10% capacity cap on nonce-bearing requests: should it be tunable? High-security deployments may want 0% (no nonces, all pre-signed) or 100% (all nonces, no pre-signing). Current decision: 10% default, tunable per-responder.

## Cross-capability impact

- **Cert Service (PC-061)**: This ADR. PC-063 (revocation during CA outage, ADR-035) — the OCSP responder cluster provides revocation checking during CA outage (the responder continues serving from its CRL cache even if the CA is down).
- **Operations (PC-106..PC-115)**: ADR-057 (OTel instrumentation) — the responder's Prometheus metrics flow into OTel. ADR-060 (audit logs) — OCSP requests and signing events are audit-logged for incident response.
- **Federation Gateway (PC-068..PC-077)**: PC-070 (token-signing cert rollover, ADR-038) — the federation layer's token-signing certs are checked via OCSP; the responder's HA cluster is critical for federation availability.

## References

- [PC-061](../catalog/05-cert-service.md) — problem statement in the catalog
- [docs/05-pki-certs/04-ocsp-crl.md](../docs/05-pki-certs/04-ocsp-crl.md) — OCSP responder architecture, `BasicOCSPResponse` ASN.1, `SigningFlags` registry bitmask
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — `certsvc.exe` service dependencies, `CRLTable` ESE table layout
- [RFC 6960 OCSP](https://www.rfc-editor.org/rfc/rfc6960) — OCSP protocol
- [RFC 8954 OCSP Nonce Extension](https://www.rfc-editor.org/rfc/rfc8954) — Nonce extension (revised)
- [RFC 6066 TLS Extensions](https://www.rfc-editor.org/rfc/rfc6066) — OCSP stapling (§8)
- [Mozilla CRLite](https://blog.mozilla.org/security/2020/01/21/crlite-part-1-technical-details/) — CRLite (deferred to Tier 3)
