---
title: "ADR-041: Strict OIDC by default; resource= compat opt-in"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-075
severity: medium
tags: [adr, federation-gateway, oidc, rfc-6749, resource-param, adfs-compat]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../docs/06-federation-sso/04-oidc-oauth.md
  - ../docs/06-federation-sso/01-adfs-architecture.md
  - ./ADR-039-oidc-primary-wstrust-bridge.md
last_updated: 2026-08-13
---

# ADR-041: Strict OIDC by default; resource= compat opt-in

## Status

Accepted — 2026-08-13.

## Context

AD FS 2016+ OIDC has several quirks that deviate from RFC 6749/8252 strict OIDC, per [docs/06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md). The `resource=` parameter is a non-standard OAuth2 extension (inherited from Azure AD's first-generation OAuth implementation) — the client must pass `resource=<web-api-identifier>` in both `/authorize` and `/token` requests to specify the audience of the issued JWT. Standard OAuth2 uses `scope` for this; AD FS supports `scope` for OIDC scopes (`openid`, `profile`, `email`, `allatclaims`, `winhttpcert`, `msapoc`, `vpn_cert`) but requires `resource` for audience. Standard OIDC clients (oauth2-proxy, AppAuth, MSAL) need adaptation to pass `resource`.

Application Groups (Server 2016+) bundle related application registrations: a Server Application (web app server-side, has `client_secret`), a Native Client (mobile/desktop, PKCE required), and a Web API (resource server, validates JWTs). Each component is a separate "Client" in the AD FS OAuth store; the Application Group is just a UI/management grouping. The Web API component replaces the legacy "Relying Party Trust" for OAuth flows — its `Identifier` becomes the JWT `aud` claim.

Other quirks: `allatclaims` scope for full AD claim pass-through (issues ALL claims the RP's Issuance Transform Rules would emit); refresh token rotation (Server 2019+ opt-in via `Set-AdfsWebApiApplication -IssueOAuthRefreshTokensTo AllDevices`); `winhttpcert` / `msapoc` / `vpn_cert` scopes for Windows-specific cert issuance (Edge / Windows Hello for Business, Always On VPN). The `apptype` claim in the JWT marks Confidential vs Public clients — non-standard, per [PC-075](../catalog/06-federation-gateway.md).

For the framework, the recommendation is to be RFC 6749/8252 strict by default and document AD FS quirks for migration. The `resource=` parameter should be a compat mode (opt-in via per-client configuration) for AD FS migration; standard `scope` should be the default. Application Groups map to standard OAuth2 client + resource server pairs.

The framework must support RFC 6749 (OAuth 2.0), RFC 8252 (PKCE for native apps), RFC 7636 (PKCE), must support OIDC Discovery (RFC 8414 — Authorization Server Metadata), and should provide `resource=` compat mode for AD FS migration.

## Decision

The framework shall implement strict OIDC (RFC 6749/8252/7636/8414/7519) by default, with `resource=` parameter compat mode as a per-client opt-in for AD FS migration scenarios.

1. **Strict OIDC by default** — the framework's OIDC implementation conforms to RFC 6749 (OAuth 2.0), RFC 8252 (OAuth 2.0 for Native Apps), RFC 7636 (PKCE), RFC 8414 (Authorization Server Metadata), RFC 7519 (JWT), RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK). The framework enforces: PKCE required for public clients (RFC 8252 §4); `client_secret` required for confidential clients; `redirect_uri` exact-match (no wildcard); `scope` for both OIDC scopes (`openid`, `profile`, `email`) and API scopes (per-resource); `aud` claim derived from the `scope` requested; no `resource=` parameter accepted by default.
2. **`resource=` compat mode (per-client opt-in)** — for AD FS migration scenarios, each client can declare `adfs_compat_resource_param = true` at registration time. When enabled, the framework accepts the `resource=` parameter in `/authorize` and `/token` requests, maps it to the JWT `aud` claim, and ignores the `scope` for audience purposes (standard OIDC scopes `openid`/`profile`/`email` are still honored). This allows standard OIDC clients (oauth2-proxy, AppAuth, MSAL) to work with AD FS-configured RPs without modification, and allows AD FS-configured clients to work with the framework during migration.
3. **Application Groups translation** — AD FS Application Groups (Server Application + Native Client + Web API) translate to standard OAuth2 client + resource server pairs in the framework. Each Application Group component becomes a separate OAuth2 client with its own `client_id`, `client_secret` (for Server Application) or PKCE requirement (for Native Client), and redirect URIs. The Web API component becomes a resource server entry with its `Identifier` as the JWT `aud` claim value. The framework's `adrian-fed migrate-apgroup --name <name>` CLI translates AD FS Application Groups to framework OAuth2 clients and resource servers.
4. **AD FS-specific scopes** — the framework does not support AD FS-specific scopes (`allatclaims`, `winhttpcert`, `msapoc`, `vpn_cert`) by default. For AD FS migration, the framework provides translations: `allatclaims` → framework-native claim pass-through (per the framework's claims rule language, gated by ORQ-132/133/134); `winhttpcert` / `msapoc` / `vpn_cert` → not supported (these are Windows-specific cert issuance flows that the framework does not replicate; clients should use the framework's Cert Service directly per ADR-037).
5. **`apptype` claim** — the framework does not emit the AD FS-specific `apptype` claim. Standard OIDC clients use the `token_endpoint_auth_method` client metadata (RFC 7591 §2) to distinguish confidential vs public clients. The framework supports `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` (for public clients).
6. **Refresh token rotation** — the framework supports refresh token rotation per RFC 6749 §6 and RFC 9700 §4.13.2: each refresh token use issues a new refresh token and invalidates the old. This is the default (matching RFC 9700 BCP); AD FS's opt-in rotation (`IssueOAuthRefreshTokensTo AllDevices`) is the non-strict behavior and is not supported.
7. **Discovery conformance** — the framework's `/.well-known/oauth-authorization-server` endpoint publishes RFC 8414 metadata including `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `grant_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `scopes_supported`, `claims_supported`, `code_challenge_methods_supported` (S256), `token_endpoint_auth_methods_supported`. The metadata does not include AD FS-specific fields.

**Concrete specification**:

- The framework's OIDC implementation passes the OAuth 2.0 certification test suite (https://www.certification.openid.net/) for the basic, dynamic, form_post, and FAPI profiles.
- Per-client configuration: `PUT /api/v1/clients/<client-id>` with `{"adfs_compat_resource_param": false}` (default) or `true` (opt-in).
- The `adrian-fed migrate-apgroup` CLI: takes an AD FS Application Group export (JSON), produces framework OAuth2 client registrations (one per Application Group component) and resource server registrations (one per Web API component).
- The framework's `adrian-fed validate-client --id <client-id>` CLI checks the client's OIDC conformance: PKCE requirement, redirect_uri match, scope handling, `resource=` compat mode.
- The framework's documentation includes an "AD FS OIDC migration guide" explaining the `resource=` compat mode, Application Groups translation, and AD FS-specific scope handling.

## Rationale

Three alternatives were considered.

**Alternative 1: AD FS-compatible OIDC (always accept `resource=`).** Make the framework's OIDC implementation AD FS-compatible by default: always accept `resource=`, always emit `apptype`, always support `allatclaims`. Rejected because (a) AD FS's OIDC quirks are non-standard and declining — Microsoft itself recommends OIDC for new applications and has deprecated WS-Federation passive in Entra ID; (b) standard OIDC clients (oauth2-proxy, AppAuth, MSAL) would need adaptation to pass `resource=`, increasing integration friction; (c) the framework's design principle is "standards-compliant by default" — AD FS compat should be opt-in for migration, not the default.

**Alternative 2: No `resource=` compat (drop AD FS OIDC support).** Do not support `resource=` at all; force AD FS OIDC clients to migrate to standard OIDC before adopting the framework. Rejected because AD FS OIDC migration is a multi-year project for enterprises — clients using `resource=` (custom .NET apps, legacy SharePoint) cannot migrate overnight. The `resource=` compat mode provides a transition path: enterprises adopt the framework now, with `resource=` compat supporting legacy clients, and migrate legacy clients to standard OIDC over the transition window.

**Alternative 3: Per-deployment `resource=` compat (global opt-in, not per-client).** Make `resource=` compat a global deployment setting: either the whole deployment accepts `resource=` (AD FS compat mode) or none of it does. Rejected because a global setting forces all clients to use AD FS compat mode, even new clients that should use standard OIDC. Per-client opt-in allows mixed deployments: legacy clients use `resource=` compat, new clients use standard OIDC. This matches the migration pattern (legacy clients migrate one at a time, not all at once).

The decision aligns with industry practice: Auth0, Okta, and Keycloak all implement strict OIDC by default; none accept `resource=` (it is AD FS/Azure AD-specific). Microsoft Entra ID (Azure AD) supports `resource=` for backward compatibility but recommends `scope` (via `api://` URIs) for new applications. The framework's strict-by-default-with-opt-in-compat approach matches the industry direction.

Cost: ~3 person-weeks for the strict OIDC implementation (the core is shared with ADR-039), the `resource=` compat mode, the Application Groups migration CLI, and the OAuth 2.0 certification test suite conformance.

## Consequences

**Positive**. Strict OIDC by default aligns with modern client expectations (oauth2-proxy, AppAuth, MSAL work without adaptation). Per-client `resource=` compat mode supports AD FS migration without forcing a flag day. Application Groups translation automates the AD FS-to-framework migration. OAuth 2.0 certification provides conformance assurance. Refresh token rotation per RFC 9700 BCP is the secure default.

**Negative**. AD FS-specific scopes (`winhttpcert`, `msapoc`, `vpn_cert`) are not supported, breaking Windows Hello for Business and Always On VPN cert issuance flows that depend on AD FS OIDC. Clients using these flows must migrate to the framework's Cert Service directly (per ADR-037), which is a code change. The `resource=` compat mode adds a small amount of code path complexity (the framework must check the per-client flag on every `/authorize` and `/token` request).

**Neutral**. The framework's OIDC implementation is strict; AD FS compat is opt-in per-client. Operators migrating from AD FS enable `resource=` compat for legacy clients and disable it (or never enable it) for new clients. Over the migration window, legacy clients are updated to standard OIDC and `resource=` compat is disabled.

**Implementation cost**. ~3 person-weeks for the strict OIDC, `resource=` compat, Application Groups migration CLI, and certification test conformance.

**Operational impact**. Operators register new clients with strict OIDC (default). Legacy AD FS clients are migrated via `adrian-fed migrate-apgroup` and have `resource=` compat enabled per-client. The OAuth 2.0 certification provides conformance assurance for auditors.

## Alternatives Considered

### Alternative A: AD FS-compatible OIDC (always accept `resource=`)

Make the framework's OIDC implementation AD FS-compatible by default. Always accept the `resource=` parameter, always emit the `apptype` claim, always support `allatclaims` and other AD FS-specific scopes. Standard OIDC clients must adapt to pass `resource=`.

Rejected because (a) AD FS's OIDC quirks are non-standard and declining — Microsoft itself recommends OIDC for new applications and has deprecated WS-Federation passive in Entra ID, signaling that the `resource=` parameter is a legacy extension that should not be propagated to new systems; (b) standard OIDC clients (oauth2-proxy, AppAuth, MSAL) would need adaptation to pass `resource=`, increasing integration friction for the framework's ecosystem — operators adopting the framework would find that their existing OIDC clients do not work without code changes, which is a barrier to adoption; (c) the framework's design principle is "standards-compliant by default" — AD FS compat should be opt-in for migration scenarios, not the default for new deployments. Strict OIDC by default with per-client `resource=` opt-in (the chosen decision) provides both standards compliance for new clients and AD FS migration support for legacy clients.

### Alternative B: No `resource=` compat (drop AD FS OIDC support)

Do not support the `resource=` parameter at all. Force AD FS OIDC clients (custom .NET apps, legacy SharePoint) to migrate to standard OIDC before adopting the framework.

Rejected because AD FS OIDC migration is a multi-year project for enterprises. Custom .NET apps using `Microsoft.IdentityModel.Tokens` from WIF with `resource=` require code changes to switch to `scope`-based audience. Legacy SharePoint 2013/2016/2019 with AD FS OIDC integration requires SharePoint configuration changes and possibly custom providers. Forcing enterprises to complete these migrations before adopting the framework would delay framework adoption by years and reduce the framework's migration value proposition. The `resource=` compat mode provides a transition path: enterprises adopt the framework now, with `resource=` compat supporting legacy clients, and migrate legacy clients to standard OIDC over a multi-year transition window. The per-client opt-in (not global) allows mixed deployments where legacy clients use `resource=` compat and new clients use standard OIDC, matching the incremental migration pattern.

### Alternative C: Per-deployment `resource=` compat (global opt-in, not per-client)

Make `resource=` compat a global deployment setting: either the whole deployment accepts `resource=` (AD FS compat mode) or none of it does. Operators set the deployment-wide flag at install time.

Rejected because a global setting forces all clients in the deployment to use AD FS compat mode, even new clients that should use standard OIDC. This defeats the purpose of strict-by-default: a deployment with any legacy AD FS client would have all clients (including new ones) in compat mode, propagating AD FS quirks to new clients. Per-client opt-in allows mixed deployments: legacy clients use `resource=` compat (per-client flag enabled), new clients use standard OIDC (per-client flag disabled, the default). This matches the migration pattern (legacy clients migrate one at a time, not all at once) and ensures new clients are strict OIDC from day one. The operational cost of per-client configuration (one extra flag at client registration time) is acceptable given the flexibility gain.

## Open Questions

- The `resource=` compat mode: should it have a deprecation timeline (e.g., 5 years, matching the WS-Trust bridge deprecation per ADR-039)? Current decision: no fixed timeline (the compat mode is per-client and removed when the last legacy client migrates); revisit if operators report long-term compat-mode reliance.
- The AD FS-specific scopes (`allatclaims`, `winhttpcert`, `msapoc`, `vpn_cert`): should the framework support `allatclaims` as a framework-native claim pass-through scope (without the AD FS semantics)? Current decision: yes, via the framework's claims rule language (gated by ORQ-132/133/134); `winhttpcert`/`msapoc`/`vpn_cert` are not supported (clients use the Cert Service directly).
- The OAuth 2.0 certification: which profiles should the framework certify (basic, dynamic, form_post, FAPI)? Current decision: basic + dynamic + form_post for v1; FAPI for high-security deployments in v2.
- The refresh token rotation: should the framework support refresh token replay detection (reject a refresh token that has already been used)? Current decision: yes (RFC 9700 §4.13.2 recommends it); the framework maintains a per-client replay cache for refresh tokens.

## Cross-capability impact

- **Federation Gateway (PC-075)**: This ADR. PC-071 (OIDC primary, ADR-039) — this ADR defines the strictness of the OIDC implementation; ADR-039 defines the protocol choice.
- **Federation Gateway (PC-076)**: External OIDC IdP federation (gated by ORQ-132/133/134) — the framework's strict OIDC implementation makes external IdP brokering cleaner (standard OIDC interop).
- **Migration (PC-124..PC-130)**: ADR-055 (migration paths) — the `adrian-fed migrate-apgroup` CLI is part of the AD FS-to-framework migration tooling.
- **Operations (PC-106..PC-115)**: ADR-060 (audit logs) — OAuth token issuance, refresh token rotation, and `resource=` compat mode usage are audit-logged.

## References

- [PC-075](../catalog/06-federation-gateway.md) — problem statement in the catalog
- [docs/06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md) — AD FS OIDC discovery document, `resource=` requirement, Application Groups, AD FS-specific scopes
- [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md) — AD FS endpoint path table, `RelyingPartyTrust` config DB table
- [RFC 6749 OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) — OAuth 2.0 framework
- [RFC 8252 OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252) — PKCE for native apps
- [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636) — Proof Key for Code Exchange
- [RFC 8414 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) — OIDC Discovery
- [RFC 9700 OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) — Security best current practice (refresh token rotation)
- [OpenID Certification](https://www.certification.openid.net/) — OAuth 2.0 certification test suite
