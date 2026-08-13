---
title: "ADR-102: Rust shim as cross-platform WAP replacement — no MS-ADFSPIP, no Windows Server in DMZ"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-073
severity: medium
unblocked_by: Workshop Decision 9
tags: [adr, federation-gateway, wap, ms-adfspip, reverse-proxy, oidc-preauth, cross-platform, rust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../workshop/decision-09-federation-layer.md
  - ../docs/01-ad-core/03-ad-fs-federation.md
  - ../docs/06-federation-sso/01-adfs-architecture.md
  - ./ADR-039-oidc-primary-wstrust-bridge.md
  - ./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md
last_updated: 2026-08-14
---

# ADR-102: Rust shim as cross-platform WAP replacement — no MS-ADFSPIP, no Windows Server in DMZ

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 9](../workshop/decision-09-federation-layer.md) (Federation layer: wrap Keycloak with Rust AD-claim-rules shim). This ADR operationalises Decision 9 §1 (deployment topology) and §3 (framework trust-pipeline integration) against the PC-073 problem surface: AD FS's Web Application Proxy (WAP), a Windows-only perimeter reverse proxy that depends on MS-ADFSPIP RPC and HTTP.SYS, which the framework replaces with the Rust shim running as a cross-platform sidecar.

## Context

WAP (`WAPService.exe` under `svchost -k WAPServiceSvchost`) is the perimeter reverse proxy that pre-auths via AD FS using MS-ADFSPIP (RPC interface UUID `e9396806-0e29-4660-b661-f6345c4bcd36`), per [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md). At install, WAP establishes trust with AD FS via `EstablishProxyTrust` — AD FS issues a client cert to WAP stored in `LocalMachine\My` with subject `ADFS Proxy Trust - <WAP-Hostname>`, used for mutual TLS on subsequent RPC calls. WAP registers HTTP URL ACLs (`https://+:443/<app-path>/`) for each published application via `HTTP.SYS`. For pre-authenticated apps, WAP redirects to `/adfs/ls/` on the AD FS server, captures the issued token, validates the signature using the AD FS token-signing cert, then re-encrypts and forwards to the backend over HTTP/HTTPS. WAP also handles relay-state storage (`StoreRelayState`/`RetrieveRelayState` via MS-ADFSPIP) for SAML and WS-Federation passive flows.

Per [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md), WAP is Windows-only by construction — it runs as a Windows service, depends on `HTTP.SYS` (the Windows kernel HTTP listener), MS-ADFSPIP (a Windows-specific RPC), and AD FS-specific RPC endpoint definitions. The DMZ implication is severe: even orgs that have migrated their entire backend to Linux must run Windows Server in the DMZ to host WAP. The licensing cost (Windows Server per-core CALs for DMZ hosts) and operational cost (Windows patching, Windows antivirus, Windows hardening baselines) are disproportionate to the proxy function WAP provides.

The framework's constraints (from [PC-073](../catalog/06-federation-gateway.md)): must support OIDC pre-auth (redirect to `/authorize`, validate JWT, inject claims as headers); must support header injection for backend (`X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`); for AD FS interop, must support MS-ADFSPIP (or document WAP as legacy). The framework must do all of this cross-platform — Linux, Windows, macOS — without a forced Windows Server footprint in the DMZ.

## Decision

The framework's Federation Gateway replaces WAP with the Rust `adrian-federation-shim` running as a cross-platform sidecar in the Keycloak Pod (per [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md)). The shim is the perimeter reverse proxy; the shim runs on Linux, Windows, or macOS. There is no MS-ADFSPIP, no `WAPService.exe`, no `HTTP.SYS` dependency, no Windows-Server-in-DMZ requirement.

### Concrete specification

1. **Reverse-proxy core.** The shim is built on `tokio = "1"` + `axum = "0.7"` + `tower = "0.4"` + `tower-http = "0.5"` (middleware for trace, CORS, compression). The shim's HTTP server listens on `0.0.0.0:443` with `rustls = "0.23"` for TLS termination using a cert from the framework's CA (per Workshop Decision 8). The shim reverse-proxies to Keycloak at `https://127.0.0.1:8443` over loopback mTLS (the shim's client cert is `CN=adrian-federation-shim`, issued by the framework's CA, rotated every 90 days per [ADR-038](./ADR-038-jwks-endpoint-webhook-rollover.md)). All HTTP routes that the shim does not intercept are passed through to Keycloak unchanged.

2. **OIDC pre-auth for backend apps.** The shim implements OIDC pre-auth for backend applications that are not Keycloak clients themselves (the WAP "pre-authenticated app" pattern). Configuration via `adrian-fed preauth add --path /app1 --backend http://backend.app1.svc:8080 --realm corp --client app1-public`: the shim registers a reverse-proxy route at `/app1/*` that, on request: (a) checks for a session cookie (`adrian_session=<opaque>`); (b) if absent, redirects to `https://idp.<domain>/realms/corp/protocol/openid-connect/auth?client_id=app1-public&redirect_uri=https://idp.<domain>/app1/_callback&state=<random>&nonce=<random>`; (c) on `/app1/_callback`, exchanges the authorization code for an ID token + access token via Keycloak's `/token` endpoint, validates the ID token's signature against the JWKS, sets the session cookie (HttpOnly, Secure, SameSite=Lax, 8-hour TTL), and redirects to the original request URL; (d) on subsequent requests, validates the session cookie, extracts the user's identity and groups from the session store, injects HTTP headers (`X-Auth-User: <uuid>`, `X-Auth-Email: <email>`, `X-Auth-Groups: <comma-separated-group-sids>`, `X-Auth-Subject: <upn>`), and forwards to the backend.

3. **Session store.** Sessions are stored in PostgreSQL (`adrian_session` table keyed by an opaque 256-bit random token, value = JSON `{subject, email, groups, issued_at, expires_at, realm}`). The session cookie is the opaque token; the shim looks up the session in PostgreSQL on every request (with a 30-second in-process `moka` cache to coalesce concurrent requests). This replaces WAP's relay-state storage (`StoreRelayState`/`RetrieveRelayState` via MS-ADFSPIP) with a standard SQL-backed session store. The shim's session-cleanup cron deletes expired sessions every 5 minutes.

4. **No MS-ADFSPIP.** The shim does not implement MS-ADFSPIP. The WAP-proxy-trust cert flow (`EstablishProxyTrust`, `GetWebProxyToken`, `StoreRelayState`, `RetrieveRelayState`) is replaced by (a) mTLS between the shim and Keycloak within the Pod (no proxy-trust cert issuance because the shim is in the same trust boundary as Keycloak — the Pod); (b) PostgreSQL-backed relay-state storage (no MS-ADFSPIP RPC calls); (c) direct admin-API calls from the shim to Keycloak (no `GetWebProxyToken` exchange). Customers with existing MS-ADFSPIP-based tooling (e.g., monitoring scripts that call MS-ADFSPIP) must migrate to the framework's CLI (`adrian-fed health`, `adrian-fed session list`) — documented in the migration guide.

5. **Relay-state storage.** For SAML and WS-Federation passive flows, the shim stores relay state in PostgreSQL (`adrian_relay_state` table keyed by an opaque 256-bit token, value = JSON `{request_url, realm, client, issued_at, expires_at}`). The relay-state TTL is 10 minutes (matches AD FS's `MSIS7042` replay-window default). The shim's relay-state endpoint (`/internal/relay-state`) is consumed by the shim's own SAML/WS-Federation handlers; it is not exposed externally.

6. **Header injection.** Headers injected by the shim's OIDC pre-auth (`X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`, `X-Auth-Subject`) are stripped from inbound requests before injection (prevents spoofing by clients sending their own `X-Auth-*` headers). The header names are configurable via `adrian-fed preauth set --header-prefix X-Auth` for customers who want a non-default prefix (e.g., `X-Remote-User`). The shim also supports `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` for downstream backend consumption.

7. **TLS termination.** The shim terminates TLS using `rustls` with the framework's CA-issued cert. The shim supports TLS 1.2 and TLS 1.3 (TLS 1.0/1.1 are disabled per the framework's security posture). The shim's TLS config supports SNI (Server Name Indication) for multi-tenant deployments where the shim serves multiple realms on different FQDNs. The shim's cert rotation is automatic via the operator's `Reconcile` loop (per [ADR-058](./ADR-058-container-native-dcs-operator.md)): when the framework's CA issues a new cert, the operator writes it to the Pod's volume, and the shim reloads its TLS config without dropping active connections (via `rustls`'s `ServerConfig::set_single_cert` with graceful reload).

8. **Per-app pre-auth vs. framework-brokered auth.** The shim's pre-auth is for backend applications that are not Keycloak clients (legacy apps, custom backends). For applications that are Keycloak clients (modern SPAs, mobile apps), the framework-brokered flow is used: the client app talks directly to Keycloak's `/authorize` and `/token` endpoints (proxied unchanged through the shim) and validates the JWT itself. The two flows are complementary — pre-auth for legacy backends, direct OIDC for modern clients.

9. **AD FS interop.** The framework does not implement WAP-to-AD-FS-interop (the framework does not proxy to an existing AD FS server). Customers migrating from AD FS replace WAP with the shim as part of the migration; the shim's pre-auth configuration is generated from AD FS published-application configuration by `adrian-migrate from-adfs` (per Decision 9 §5 and ADR-100). The migration CLI translates each AD FS published application (`Get-WebApplicationProxyApplication -Name <name>`) to a shim pre-auth configuration (`adrian-fed preauth add ...`) with the backend URL, path, realm, and client ID mapped from AD FS configuration.

10. **Cross-platform operation.** The shim runs on Linux (the primary deployment platform), Windows (for customers who run the Federation Gateway on Windows), and macOS (for development and small-office deployments). The shim's binary is built per-platform via the framework's CI; the container image is built on `ubuntu:22.04` for Linux, `mcr.microsoft.com/windows/servercore:ltsc2022` for Windows. The shim's TLS, HTTP, and PostgreSQL dependencies are pure-Rust (`rustls`, `axum`, `tokio-postgres`), so there are no platform-native library dependencies.

11. **Observability.** The shim emits Prometheus metrics (`adrian_fed_proxy_requests_total{path,result}`, `adrian_fed_preauth_redirects_total{client}`, `adrian_fed_preauth_callbacks_total{client,result}`, `adrian_fed_session_active`, `adrian_fed_session_lookup_total{result}`, `adrian_fed_relay_state_active`, `adrian_fed_tls_handshake_total{result,sni}`), OpenTelemetry traces spanning the full proxy path (ingress → shim → Keycloak → backend), and audit logs per [ADR-060](./ADR-060-structured-audit-logs-otel.md) recording every pre-auth redirect, callback, and session-injection.

## Rationale

WAP exists because AD FS in 2003 needed a Windows-service perimeter proxy and the only Windows-service perimeter proxy primitive was `HTTP.SYS` + a custom RPC protocol. In 2026, the perimeter-proxy primitive is `tokio` + `axum` + `rustls` running as a sidecar in the same Pod as the IdP — there is no Windows-Server-in-DMZ requirement, no MS-ADFSPIP RPC, no `HTTP.SYS`. The Rust shim is the modern perimeter proxy: cross-platform, memory-safe, async, and tightly integrated with the framework's directory and cert services.

The framework chose to implement the WAP replacement in the same Rust shim that does claim-rule translation (per [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md)) rather than as a separate component (e.g., nginx + oauth2-proxy) because (a) the shim is already intercepting token responses for claim-rule transformation — adding pre-auth interception to the same component adds no new latency surface; (b) a single Rust component has a single upgrade cycle, a single observability pipeline, and a single audit log — operationally simpler than coordinating nginx + oauth2-proxy + Keycloak; (c) the framework's trust-pipeline integration (the shim is the only component that holds directory credentials) requires the perimeter proxy to be the same component as the directory-integration layer.

The framework chose PostgreSQL for session and relay-state storage because (a) PostgreSQL is already the Federation Gateway's stateful backend (per ADR-100), so no new infrastructure is added; (b) PostgreSQL's strict serializability ensures session-state consistency across multiple shim replicas (the StatefulSet scales horizontally); (c) PostgreSQL's WAL streaming provides DR for session state (per ADR-059). The 30-second in-process `moka` cache coalesces concurrent requests to the same session, keeping the per-request PostgreSQL lookup cost negligible.

## Consequences

**Positive**. The framework eliminates the Windows-Server-in-DMZ requirement that AD FS + WAP imposed. The shim runs on Linux (the primary deployment platform), eliminating Windows Server licensing and patching for the DMZ. The shim's cross-platform support (Linux, Windows, macOS) means the same Federation Gateway runs identically on any platform — no platform-divergent WAP equivalent. The shim's OIDC pre-auth provides header injection for backend apps that cannot be Keycloak clients themselves, preserving the WAP pre-auth pattern in a modern OIDC-native form.

**Negative**. The shim's pre-auth surface is a new code path that handles user sessions, OIDC callbacks, and header injection — a meaningful security surface. The framework's CI runs penetration tests against the shim's pre-auth endpoints (CSRF, session-fixation, header-injection, open-redirect) on every PR. The shim's PostgreSQL session store adds PostgreSQL write load (one write per session creation, one read per request); the 30-second `moka` cache keeps the read load bounded but the write load is proportional to login rate.

**Neutral**. The framework does not support MS-ADFSPIP-based tooling; customers with existing MS-ADFSPIP monitoring scripts must migrate to the framework's CLI. The framework does not implement WAP-to-AD-FS-interop (no proxy-to-legacy-AD-FS mode); customers migrate from AD FS by replacing WAP with the shim in a single cutover (per the migration guide).

**Implementation cost**. ~2 person-weeks for v1 (part of the shim's 5-pw budget per Decision 9): pre-auth handler (0.5 pw), session store + relay-state store (0.5 pw), header injection (0.3 pw), AD FS migration CLI for published applications (0.5 pw), cross-platform testing (0.2 pw).

**Operational impact**. Federation Gateway operators configure pre-auth via `adrian-fed preauth add`; the framework's operator (`FederationGateway` CRD) manages the pre-auth configuration as a Kubernetes resource. The shim's Prometheus metric `adrian_fed_preauth_redirects_total` is the primary SLO for pre-auth performance; the audit log records every pre-auth event.

## Alternatives Considered

### Alternative A: nginx + oauth2-proxy as the WAP replacement

Deploy nginx as the perimeter reverse proxy and oauth2-proxy as the OIDC pre-auth layer, with Keycloak as the IdP. Rejected because (a) this is three components (nginx, oauth2-proxy, Keycloak) instead of the shim + Keycloak — operationally more complex; (b) oauth2-proxy's session store is cookie-based (large cookies, no server-side session invalidation) or Redis-based (a new infrastructure component); (c) oauth2-proxy does not support claim-rule transformation (per ADR-101) — a separate component would be needed for that, adding a fourth component; (d) the framework's trust-pipeline integration (the perimeter proxy is the only component that holds directory credentials) would require either nginx or oauth2-proxy to hold framework-directory credentials, which neither is designed for; (e) the framework's `adrian-fed` CLI would need to manage nginx + oauth2-proxy configuration, adding a non-Rust configuration surface.

### Alternative B: Envoy + ext-authz as the WAP replacement

Deploy Envoy as the perimeter reverse proxy and an external authorization service (ext-authz) that calls the framework's directory for pre-auth decisions. Rejected for the same reasons as Alternative A, plus: Envoy's configuration surface (YAML + dynamic xDS) is significantly more complex than the shim's `axum`-based route configuration; the framework's operators would need to learn Envoy's config model in addition to the framework's CLI; Envoy's ext-authz model assumes a separate authorization service, which is the shim itself — so the architecture collapses to the shim + Envoy, where Envoy is a thin TLS-terminating reverse proxy in front of the shim. That is exactly what the framework's ingress controller already does, so Envoy is not needed inside the Federation Gateway.

### Alternative C: Traefik + forward-auth as the WAP replacement

Same as Alternative A but with Traefik + forward-auth. Rejected for the same reasons. Traefik's forward-auth model is similar to oauth2-proxy but with Traefik-specific configuration; the framework would inherit Traefik's release cadence and configuration quirks.

### Alternative D: Preserve WAP for AD FS interop; deploy the shim only for new deployments

Customers migrating from AD FS keep WAP in front of AD FS during the coexistence period; the shim is deployed only for new deployments. Rejected because (a) this preserves the Windows-Server-in-DMZ requirement during the coexistence period — the very problem PC-073 identifies; (b) WAP cannot proxy to the framework's Keycloak (WAP's MS-ADFSPIP RPC is AD FS-specific), so customers would need WAP-for-AD-FS and shim-for-Keycloak running in parallel during coexistence — operationally untenable; (c) the framework's migration path (per ADR-100) is a single cutover from AD FS + WAP to Keycloak + shim, not a prolonged coexistence.

## Open Questions

- Should the shim support SAML pre-auth (in addition to OIDC pre-auth) for backend apps that consume SAML assertions? Current decision: no — SAML pre-auth is rare, and customers who need SAML for a backend app should make the app a Keycloak SAML client directly. Revisit if customer demand warrants.
- Should the shim's session store support Redis (in addition to PostgreSQL) for customers who prefer Redis for session state? Current decision: no — PostgreSQL is the Federation Gateway's single stateful backend, and adding Redis adds infrastructure. The shim's 30-second `moka` cache keeps the PostgreSQL read load bounded.
- Should the shim's pre-auth support mTLS client-cert authentication (in addition to OIDC redirect)? Current decision: no — mTLS pre-auth is rare; customers who need mTLS should make the app a Keycloak client with mTLS bearer-issuer flow. Revisit if customer demand warrants.

## Cross-capability impact

- **Federation Gateway (PC-068 — AD FS topology).** Addressed in [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md). The shim's WAP-replacement role is a sub-component of the shim.
- **Federation Gateway (PC-069 — claims rule language).** Addressed in [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md). The shim's claim-rule engine and pre-auth handler share the same `axum` route tree.
- **Federation Gateway (PC-071 — WS-Trust bridge).** Addressed in [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md). The WS-Trust bridge is implemented as part of the shim, sharing the same TLS termination and session-store infrastructure.
- **Cert Service (Workshop Decision 8).** The shim's TLS cert is issued by the framework's CA, rotated every 90 days per ADR-038.
- **Operations (ADR-058).** The shim is deployed as a sidecar in the Keycloak StatefulSet; the framework's operator manages the pre-auth configuration via a `FederationGatewayPreAuth` CRD.
- **Migration (PC-124 AD FS-to-framework).** The `adrian-migrate from-adfs` CLI translates AD FS published applications to shim pre-auth configurations.

## References

- [PC-073](../catalog/06-federation-gateway.md) — problem statement
- [Workshop Decision 9](../workshop/decision-09-federation-layer.md) — §1 deployment topology, §3 framework trust-pipeline integration
- [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md) — WAP `WAPService.exe` process model, MS-ADFSPIP RPC UUID, `EstablishProxyTrust` client cert issuance, URL ACL registration
- [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md) — WAP MS-ADFSPIP operations (`GetConfiguration`, `GetWebProxyToken`, `StoreRelayState`/`RetrieveRelayState`), per-app pre-auth flow
- [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md) — Keycloak + Rust shim deployment topology
- [ADR-038](./ADR-038-jwks-endpoint-webhook-rollover.md) — JWKS endpoint + cert rotation
- [MS-ADFSPIP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adfspip) — AD FS Proxy Implementation Protocol (the framework does not implement this)
- [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) — reference OIDC pre-auth proxy (alternative considered and rejected)
- [Envoy ext-authz](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter) — reference external authorization filter (alternative considered and rejected)
