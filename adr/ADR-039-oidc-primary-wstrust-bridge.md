---
title: "ADR-039: OIDC primary; WS-Trust-to-OIDC bridge"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-071
severity: medium
tags: [adr, federation-gateway, oidc, ws-trust, ws-federation, legacy-bridge]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../docs/06-federation-sso/04-oidc-oauth.md
  - ../docs/06-federation-sso/02-saml-ws-fed.md
  - ./ADR-038-jwks-endpoint-webhook-rollover.md
  - ./ADR-041-strict-oidc-default-resource-compat.md
last_updated: 2026-08-13
---

# ADR-039: OIDC primary; WS-Trust-to-OIDC bridge

## Status

Accepted — 2026-08-13.

## Context

AD FS supports WS-Federation (passive, SOAP-based, ~2003) + WS-Trust (active, SOAP-based) + SAML 2.0 (OASIS, 2005) + OIDC (2016+). Per [docs/06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md), AD FS OIDC endpoints include `/adfs/oauth2/authorize`, `/adfs/oauth2/token`, `/adfs/oauth2/userinfo`, `/adfs/oauth2/jwks`, `/.well-known/openid-configuration`. Per [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), WS-Federation passive uses `wa=wsignin1.0` / `wsignout1.0` parameters with `wtrealm` (RP identifier), `wreply` (return URL), `wctx` (state), `wreq` (optional RST XML), `wauth` (auth method URI), `wfresh` (freshness seconds), `whr` (home realm). WS-Trust active uses SOAP endpoints at `/adfs/services/trust/2005/usernamemixed`, `/adfs/services/trust/13/usernamemixed`, `/adfs/services/trust/2005/windowstransport`, `/adfs/services/trust/13/certificatemixed`, `/adfs/services/trust/mex` (WSDL).

WS-* is SOAP-based, declining — modern clients (SPAs, mobile apps) use OIDC. Microsoft itself has deprecated WS-Federation passive in Entra ID (Azure AD) and recommends OIDC for new applications. But enterprises have legacy RPs (SharePoint on-prem 2013/2016/2019, Office desktop client WS-Trust for Exchange/PowerShell, custom .NET apps using `Microsoft.IdentityModel.Tokens` from WIF) that require WS-* support, per [PC-071](../catalog/06-federation-gateway.md).

For the framework, the design must: (a) support OIDC natively as the primary protocol (RFC 6749, RFC 8252 PKCE, RFC 7636); (b) support SAML 2.0 for legacy RPs (OASIS standard, broad enterprise adoption); (c) deprecate WS-* or provide a compat shim. The compat shim could be a WS-Trust-to-OIDC bridge: the legacy RP sends a WS-Trust RST, the bridge translates to an OIDC token exchange, and the RP gets back a SAML assertion wrapped in RSTR. This preserves legacy RP investment while the framework's core is OIDC-native.

The framework must support OIDC (RFC 6749, 8252 PKCE, 7636) as the primary protocol, must support SAML 2.0 (OASIS) for legacy RPs that cannot migrate to OIDC, and should provide a WS-Trust-to-OIDC bridge for legacy RPs (or drop WS-* entirely).

## Decision

The framework shall adopt OIDC as the primary federation protocol, support SAML 2.0 for legacy RPs, and provide a WS-Trust-to-OIDC bridge for legacy RPs that cannot migrate. WS-Federation passive and WS-Trust active are documented as deprecated.

1. **OIDC primary** — the framework's federation service is OIDC-native (RFC 6749 OAuth 2.0, RFC 8252 PKCE for native apps, RFC 7636 PKCE, RFC 7519 JWT, RFC 8414 Authorization Server Metadata per ADR-038, RFC 7515 JWS). The framework supports the standard OIDC flows: authorization_code (with PKCE for public clients), client_credentials, refresh_token, device_code. Implicit and hybrid flows are supported for backward compatibility but deprecated (per OAuth 2.0 Security Best Current Practice, RFC 9700).
2. **SAML 2.0 for legacy RPs** — the framework supports SAML 2.0 (OASIS) for RPs that cannot migrate to OIDC: SP-initiated SSO, IdP-initiated SSO, SLO (Single Logout), signed and encrypted assertions. SAML metadata is published at `/metadata` (per ADR-038). The framework supports the standard SAML bindings: HTTP-Redirect, HTTP-POST, HTTP-Artifact.
3. **WS-Trust-to-OIDC bridge** — the framework provides a WS-Trust endpoint (`/trust/13/usernamemixed`, `/trust/13/certificatemixed`) that accepts WS-Trust RST (Request Security Token) messages, translates them to OIDC token exchanges (using the `password` or `client_credentials` grant), and returns SAML assertions wrapped in RSTR (Request Security Token Response). The bridge is a translation layer: the legacy RP sees a WS-Trust endpoint; the framework's core performs OIDC.
4. **WS-Federation passive deprecation** — the framework does not support WS-Federation passive (`wa=wsignin1.0`) for new RPs. Legacy RPs using WS-Federation passive must migrate to OIDC or SAML 2.0. A migration tool (`adrian-fed migrate-wsfed --rp <name>`) translates WS-Federation passive RPs to OIDC RPs.
5. **Application Groups translation** — AD FS Application Groups (Server Application + Native Client + Web API) translate to standard OAuth2 client + resource server pairs in the framework: each Application Group component becomes a separate OAuth2 client (with its own `client_id`, `client_secret` or PKCE requirement, redirect URIs). The framework's `adrian-fed migrate-apgroup --name <name>` CLI translates AD FS Application Groups to framework OAuth2 clients.
6. **Endpoint surface** — the framework's federation service exposes:
   - OIDC: `/.well-known/oauth-authorization-server` (RFC 8414 metadata), `/.well-known/jwks.json` (JWKS), `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/revoke`, `/oauth2/device`
   - SAML: `/metadata`, `/saml/sso`, `/saml/slo`, `/saml/artifact`
   - WS-Trust (bridge, deprecated): `/trust/13/usernamemixed`, `/trust/13/certificatemixed`, `/trust/mex` (WSDL)
   - WS-Federation passive: not supported (deprecated)
7. **Deprecation timeline** — WS-Trust bridge is supported for the framework's v1 lifecycle (5 years), with deprecation announced in v1.0 and removal planned for v2.0. Legacy RPs have 5 years to migrate to OIDC or SAML 2.0.

**Concrete specification**:

- The federation service is a standalone service (`adrian-federation`) running on Linux, Windows, or macOS.
- OIDC endpoints conform to RFC 6749 (OAuth 2.0), RFC 8252 (PKCE for native apps), RFC 7636 (PKCE), RFC 7519 (JWT), RFC 8414 (Authorization Server Metadata), RFC 7515 (JWS).
- SAML endpoints conform to SAML 2.0 (OASIS) — SP-initiated SSO, IdP-initiated SSO, SLO, signed and encrypted assertions, HTTP-Redirect/POST/Artifact bindings.
- WS-Trust bridge endpoints conform to WS-Trust 1.3 — the bridge accepts RST messages with `RequestType=Issue`, `TokenType=oasis:names:tc:SAML:2.0:assertion`, `KeyType=Bearer` or `PublicKey`, translates to OIDC token exchange, returns RSTR with SAML assertion.
- The bridge supports `UserNameMixed` (username/password in RST → OIDC `password` grant) and `CertificateMixed` (client cert in TLS → OIDC `client_credentials` grant with mutual TLS).
- The framework's `adrian-fed migrate-wsfed` CLI translates WS-Federation passive RPs (from AD FS configuration export) to OIDC RPs (with redirect URIs derived from `wreply` URLs).
- The framework's `adrian-fed migrate-apgroup` CLI translates AD FS Application Groups to framework OAuth2 clients.
- The framework's documentation marks WS-Trust bridge as deprecated; the deprecation timeline is documented in the migration guide (per ADR-055).

## Rationale

Three alternatives were considered.

**Alternative 1: Drop WS-* entirely.** Do not support WS-Trust or WS-Federation. Force enterprises to rewrite legacy RPs before migrating to the framework. Rejected because WS-* migration is a multi-year project for enterprises — SharePoint on-prem, Office desktop, and custom .NET apps all depend on WS-Trust. Dropping WS-* entirely would force enterprises to either rewrite their apps (multi-year, multi-million-dollar effort) or stay on AD FS, defeating the framework's migration value proposition.

**Alternative 2: Full WS-* support (WS-Trust + WS-Federation passive).** Implement WS-Trust and WS-Federation passive as first-class protocols alongside OIDC and SAML. Rejected because (a) WS-* is declining — Microsoft itself has deprecated WS-Federation passive in Entra ID; (b) implementing full WS-* support doubles the federation service's complexity (SOAP, WSDL, WS-Policy, WS-Security) for a declining user base; (c) the bridge approach (WS-Trust-to-OIDC) provides WS-Trust support without making it a first-class protocol — the framework's core remains OIDC-native.

**Alternative 3: SAML-only (no OIDC, no WS-*).** Use SAML 2.0 as the sole federation protocol. Rejected because (a) modern clients (SPAs, mobile apps) prefer OIDC over SAML — OIDC is JSON-based, lighter, and has better tooling (AppAuth, MSAL, oauth2-proxy); (b) SAML is XML-based and SOAP-ish, declining for new applications; (c) OIDC is the modern standard recommended by Microsoft, Google, Auth0, Okta. The framework must support OIDC for modern clients and SAML for legacy enterprise RPs; both are needed.

The decision aligns with industry practice: Auth0, Okta, and Keycloak all support OIDC as primary with SAML for legacy RPs; Microsoft Entra ID recommends OIDC for new applications and supports SAML for legacy; Google Workspace supports OIDC and SAML. None recommend WS-* for new applications. The bridge approach for WS-Trust is less common (most providers dropped WS-Trust entirely), but the framework's enterprise-migration focus justifies the bridge.

Cost: ~6 person-weeks for the OIDC implementation, ~4 person-weeks for the SAML 2.0 implementation, ~3 person-weeks for the WS-Trust bridge, ~2 person-weeks for the migration CLIs. Total: ~15 person-weeks.

## Consequences

**Positive**. OIDC-native core aligns with modern client expectations (SPAs, mobile apps). SAML 2.0 support covers legacy enterprise RPs that cannot migrate. WS-Trust bridge preserves legacy RP investment (SharePoint on-prem, Office desktop, custom .NET apps) during the multi-year migration to OIDC. The deprecation timeline (5 years) gives enterprises a clear deadline for WS-* removal.

**Negative**. WS-Trust bridge adds operational complexity (SOAP, WSDL, WS-Policy, WS-Security) for a declining user base. The bridge must be maintained for 5 years, with security patches for any WS-Trust vulnerabilities discovered. SAML 2.0 support adds XML signature validation complexity (XML Signature Wrapping attacks are a known SAML vulnerability class).

**Neutral**. The framework supports three federation protocols (OIDC, SAML, WS-Trust bridge) but recommends OIDC for all new RPs. The deprecation timeline is documented; operators must plan WS-* migration before v2.0 removal.

**Implementation cost**. ~15 person-weeks for the full federation service (OIDC + SAML + WS-Trust bridge + migration CLIs).

**Operational impact**. Operators register RPs with the appropriate protocol (OIDC for new RPs, SAML for legacy enterprise RPs, WS-Trust for legacy .NET apps). The migration CLIs translate AD FS configurations. The deprecation timeline is communicated to operators at framework adoption.

## Alternatives Considered

### Alternative A: Drop WS-* entirely

Do not support WS-Trust or WS-Federation passive. Force enterprises to rewrite legacy RPs (SharePoint on-prem, Office desktop, custom .NET apps) before migrating to the framework.

Rejected because WS-* migration is a multi-year project for enterprises. SharePoint on-prem 2013/2016/2019 depends on WS-Federation passive for claims-based auth; migrating SharePoint to OIDC requires SharePoint 2019+ with Subscription Edition or third-party OIDC plugins. Office desktop client uses WS-Trust for Exchange autodiscover and PowerShell remoting; migrating to OIDC requires Office 365 client or MSAL-based auth (not available for all Office versions). Custom .NET apps using `Microsoft.IdentityModel.Tokens` from WIF depend on WS-Trust; migrating to OIDC requires rewriting the auth code with MSAL. Forcing enterprises to complete all three migrations before adopting the framework would delay framework adoption by years and reduce the framework's migration value proposition. The WS-Trust bridge provides a transition path: enterprises adopt the framework now, with WS-Trust bridge supporting legacy RPs, and migrate legacy RPs to OIDC over the 5-year deprecation window.

### Alternative B: Full WS-* support (WS-Trust + WS-Federation passive as first-class)

Implement WS-Trust and WS-Federation passive as first-class protocols alongside OIDC and SAML. All four protocols are equally supported, with no deprecation timeline.

Rejected because (a) WS-* is declining — Microsoft itself has deprecated WS-Federation passive in Entra ID (Azure AD) and recommends OIDC for new applications, so the framework should follow the industry direction; (b) implementing full WS-* support doubles the federation service's complexity (SOAP, WSDL, WS-Policy, WS-Security, WS-Trust, WS-Federation) for a declining user base — the engineering effort would be better spent on OIDC and SAML features; (c) without a deprecation timeline, WS-* support becomes a permanent maintenance burden with no exit path. The bridge approach (WS-Trust-to-OIDC) provides WS-Trust support for legacy RPs without making it a first-class protocol — the framework's core remains OIDC-native, and the bridge is deprecated with a 5-year removal timeline. WS-Federation passive is dropped entirely (its use cases are covered by SAML 2.0).

### Alternative C: SAML-only (no OIDC, no WS-*)

Use SAML 2.0 as the sole federation protocol. All RPs (modern and legacy) use SAML.

Rejected because (a) modern clients (SPAs, mobile apps) prefer OIDC over SAML — OIDC is JSON-based (lighter, easier to parse), RESTful (easier to integrate with modern web frameworks), and has better tooling (AppAuth for iOS/Android, MSAL for Microsoft, oauth2-proxy for reverse proxies); SAML is XML-based (heavier, requires XML signature validation), SOAP-ish (older design), and has less modern tooling; (b) SAML is declining for new applications — Auth0, Okta, and Google all recommend OIDC for new RPs; (c) the industry consensus (per OAuth 2.0 Security Best Current Practice, RFC 9700) is OIDC for new applications, SAML for legacy enterprise RPs. The framework must support OIDC for modern clients (the dominant use case for new RPs) and SAML for legacy enterprise RPs (broad enterprise adoption); both are needed. Dropping OIDC would make the framework unattractive for new RP development, limiting adoption.

## Open Questions

- The WS-Trust bridge deprecation timeline (5 years): should it be shorter (3 years) to force faster migration, or longer (7 years) for slow-moving enterprises? Current decision: 5 years (matches typical enterprise migration cycles); revisit based on adoption feedback.
- SAML 2.0 support: should the framework support SAML 1.1 (legacy) in addition to SAML 2.0? Current decision: SAML 2.0 only (SAML 1.1 is obsolete; legacy RPs should migrate to SAML 2.0 or OIDC).
- The WS-Trust bridge: should it support `WindowsMixed` (Windows Integrated Auth via NTLM/Kerberos) in addition to `UserNameMixed` and `CertificateMixed`? Current decision: no — `WindowsMixed` depends on NTLM/Kerberos which the framework is deprecating (per ADR-021 LDAP signing + channel binding); legacy RPs using `WindowsMixed` should migrate to `UserNameMixed` or `CertificateMixed`.
- The OIDC flows: should the framework support the `password` grant (Resource Owner Password Credentials)? RFC 9700 recommends against it for security reasons. Current decision: supported for backward compatibility (the WS-Trust bridge uses it), but deprecated for direct RP use.

## Cross-capability impact

- **Federation Gateway (PC-071)**: This ADR. PC-070 (cert rollover, ADR-038) — JWKS rotation is OIDC-native; SAML metadata `validUntil` is SAML-native; both are supported.
- **Federation Gateway (PC-075)**: ADR-041 (strict OIDC by default) — the framework's OIDC implementation is RFC-strict; AD FS quirks (`resource=` parameter) are opt-in compat.
- **Federation Gateway (PC-072)**: ADR-040 (SAML clock skew) — SAML replay detection and clock skew are SAML-specific; OIDC uses `iat`/`exp` JWT claims.
- **Migration (PC-124..PC-130)**: ADR-055 (migration paths) — the `adrian-fed migrate-wsfed` and `adrian-fed migrate-apgroup` CLIs are part of the AD FS-to-framework migration tooling.

## References

- [PC-071](../catalog/06-federation-gateway.md) — problem statement in the catalog
- [docs/06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md) — AD FS OIDC endpoint paths, discovery document, supported flows, Application Groups
- [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md) — WS-Federation passive flow, RSTR XML structure, WS-Trust active endpoints
- [RFC 6749 OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) — OAuth 2.0 framework
- [RFC 8252 OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252) — PKCE for native apps
- [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636) — Proof Key for Code Exchange
- [RFC 8414 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414) — OIDC Discovery
- [RFC 9700 OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) — Security best current practice
- [SAML 2.0 (OASIS)](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) — SAML 2.0 core specification
- [WS-Trust 1.3 (OASIS)]https://docs.oasis-open.org/ws-sx/ws-trust/v1.3/ws-trust.html) — WS-Trust specification
