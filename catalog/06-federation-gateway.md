---
title: Federation Gateway — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, federation-gateway, framework-design, gap-analysis, adfs, saml, oidc, oauth2]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./02-kdc.md
  - ./04-policy-engine.md
  - ./05-cert-service.md
  - ./07-file-gateway.md
  - ./09-cross-platform-parity.md
  - ./14-cross-platform-parity-matrix.md
  - ./13-open-research-questions.md
last_updated: 2026-08-13
---

# Federation Gateway — Problem Catalog

## Capability definition

**Responsibility**: Identity provider for web/HTTP apps. SAML 2.0, WS-Federation, OAuth2/OIDC. Issues tokens, manages relying-party trusts, exposes metadata, supports home-realm discovery.

**Inherits from AD**: AD FS (`Microsoft.IdentityServer.ServiceHost.exe` + WID/SQL config DB + WAP reverse proxy + MS-ADFSPIP).

**Public interfaces**: SAML 2.0 endpoints (`/saml2/ls/`, `/saml2/slo/`); WS-Federation endpoints (`/wsfed/`); OAuth2/OIDC endpoints (`/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/.well-known/openid-configuration`); Federation metadata (`/FederationMetadata/2007-06/FederationMetadata.xml`); WS-Trust endpoints (active clients, `/trust/2005/usernamemixed`).

**Depends on**: Core Directory (claims source), KDC (Kerberos-constrained delegation), Cert Service (token-signing cert).

**Consumed by**: Web apps, OAuth2/OIDC clients, SaaS apps.

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-068 | AD FS is heavy (WID/SQL config DB, separate farm, WAP proxy) | high | cross-platform |
| PC-069 | ADFS claims rule language (CRL) is proprietary DSL; migration to standard policy is painful | high | cross-platform |
| PC-070 | Token-signing cert rollover requires RP metadata refresh; 15-day overlap window | medium | cross-platform |
| PC-071 | WS-Federation and WS-Trust are legacy; OIDC is the modern path | medium | cross-platform |
| PC-072 | SAML replay detection window (60 min) and clock skew (5 min) need tuning | low | cross-platform |
| PC-073 | AD FS Web Application Proxy (WAP) is Windows-only; modern alternatives exist | medium | cross-platform |
| PC-074 | ADFS farm topology (primary + secondaries in WID mode) is operationally fragile | medium | cross-platform |
| PC-075 | ADFS as OAuth2/OIDC provider has quirks (`resource=` parameter, Application Groups) | medium | cross-platform |
| PC-076 | External OIDC IdP federation (ADFS-as-RP) needs explicit CPT configuration | medium | cross-platform |
| PC-077 | AD RMS (DRM/IRM) has no open-source server; AIP is the migration path | low | cross-platform |

Severity totals: 0 blocker, 2 high, 7 medium, 2 low.

## Detailed problem entries

### PC-068 — AD FS is heavy (WID/SQL config DB, separate farm, WAP proxy)

**Capability**: Federation Gateway
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD FS runs as `Microsoft.IdentityServer.ServiceHost.exe` (a WCF service host) reading configuration from either a Windows Internal Database (`microsoft.identityserver.mdf` at `%SystemRoot%\Windows\WID\Data\`, connection string `Data Source=np:\\.\pipe\MICROSOFT##WID\tsql\query;Initial Catalog=MicrosoftIdentityServer`) or a SQL Server instance (`Data Source=<sql>;Initial Catalog=AdfsConfiguration;Integrated Security=SSPI`), per [06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md). Config DB tables include `ServiceSettings` (federation service name, signing/encryption cert thumbprints), `RelyingPartyTrust` (per-RP identifiers, rules, claim descriptions, signing cert hash, encryption cert hash, token lifetime, endpoints), `ClaimsProviderTrust` (per-CPT, typically only the AD CPT), `ArtifactStore` (SAML artifact resolution), `IdentityServerPolicy` (policy descriptions, claim descriptions, custom attribute store registrations).

WAP (`WAPService.exe` under `svchost -k WAPServiceSvchost`) is the perimeter reverse proxy that pre-auths via AD FS using MS-ADFSPIP (RPC interface UUID `e9396806-0e29-4660-b661-f6345c4bcd36`). Per [01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md), MS-ADFSPIP operations include `EstablishProxyTrust` (WAP gets a client cert from AD FS stored in `LocalMachine\My` with subject `ADFS Proxy Trust - <WAP-Hostname>`), `GetConfiguration` (pull published applications and endpoints), `GetWebProxyToken` (exchange proxy trust cert for per-request access token), `StoreRelayState` / `RetrieveRelayState`.

The weight: a full AD FS deployment is one or more AD FS nodes (each running `Microsoft.IdentityServer.ServiceHost.exe` as a domain service account with SPN `HOST/<adfs-svc-fqdn>`), one or more WAP nodes in the DMZ, a WID or SQL backend, plus an HSM or local cert store for token-signing keys. Per the same KB, WID is primary-DC-style replication (max 5 nodes, single primary writes); SQL farm allows multi-primary at the SQL tier. This is operationally heavy for small/medium orgs that just need SSO to a handful of SaaS apps.

For the framework, the recommendation is to adopt a lighter federation layer (Keycloak, Authentik, Ory, Zitadel) with AD integration, not re-implement the heavy AD FS topology. Keycloak (open-source, RH SSO upstream) runs as a Java app on JBoss/WildFly, uses a relational DB (MariaDB/Postgres) for realm config, supports SAML 2.0 IdP+SP, OIDC provider, LDAP federation, and Kerberos bridge via SPNEGO — significantly lighter than AD FS.

**Impact**:

AD FS deployment is operationally complex; most orgs would prefer cloud IdP (Entra ID, Okta) or a lighter on-prem IdP (Keycloak). The WID 5-node limit forces SQL farm for larger deployments, adding SQL HA complexity.

**Constraints**:

- Must support SAML 2.0 (OASIS), OIDC (RFC 6749, 8252, 7636), OAuth2.
- Must support AD as claims provider (LDAP or Kerberos-constrained delegation).
- For AD FS interop, must expose `/FederationMetadata/2007-06/FederationMetadata.xml` and accept existing RPT configurations.

**Cross-platform considerations**:

- **Windows**: AD FS + WAP; native integration with AD via Kerberos.
- **macOS**: No native IdP; uses Keychain as cert store only. PSSO provides client-side SSO.
- **Linux**: Keycloak (JBoss/WildFly) is the most common IdP replacement; mod_auth_mellon (Apache) for SP.
- **Cross-platform consistency**: a single lightweight federation service (Keycloak-equivalent) running on all platforms is the cross-platform path.

**KB references**:

- [`01-ad-core/03-ad-fs-federation.md`](../docs/01-ad-core/03-ad-fs-federation.md) — AD FS process model (`Microsoft.IdentityServer.ServiceHost.exe`), WID vs SQL config DB topology, WAP perimeter proxy, MS-ADFSPIP RPC UUID.
- [`06-federation-sso/01-adfs-architecture.md`](../docs/06-federation-sso/01-adfs-architecture.md) — Service account + SPN requirements, config DB tables (`ServiceSettings`, `RelyingPartyTrust`, `ClaimsProviderTrust`), WAP MS-ADFSPIP operations.

**Open questions**:

- Adopt Keycloak as the federation layer (lighter, open-source, cross-platform)?
- Build native federation service (re-implement AD FS protocols from scratch)?
- Cloud-first (Entra ID, Okta) for new deployments and on-prem AD FS for legacy?

**Cross-capability impact**:

- Affects: PC-069 (claims rule language — depends on the chosen IdP), PC-073 (WAP replacement — depends on the chosen reverse proxy).
- Affected by: PC-057 (Cert Service — token-signing cert issuance), PC-024 (KDC — Kerberos-constrained delegation for intranet SSO).

---

### PC-069 — ADFS claims rule language (CRL) is proprietary DSL; migration to standard policy is painful

**Capability**: Federation Gateway
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD FS's claims pipeline is driven by a custom DSL expressed in `Microsoft.IdentityServer.ClaimsPolicy`. Per [06-federation-sso/03-claims-rules.md](../docs/06-federation-sso/03-claims-rules.md), each rule uses the syntax `c:[Type == "...", Value == "...", ...] => issue(Type = "...", Value = c.Value);` and is evaluated in one of five phases: (1) Acceptance Transform Rules (per-CPT — filter/map claims from upstream IdP); (2) Issuance Authorization Rules (per-RPT — Permit/Deny decision); (3) Issuance Transform Rules (per-RPT — map claims to RP's expected vocabulary); (4) Delegation Rules (per-RPT — ActAs/OnBehalfOf token issuance); (5) Token Serialization (sign + serialize as SAML/JWT). The pipeline is evaluated by `Microsoft.IdentityServer.dll!PolicyEngine` with rule bodies optionally executing LDAP, SQL, or custom .NET attribute store queries.

Attribute stores: `Active Directory` (built-in `Microsoft.IdentityServer.ClaimsPolicy.AttributeStore.ActiveDirectoryAttributeStore`, query format `;attr1,attr2;{0}`), `LDAP` (any LDAP server via `LdapAttributeStore`), `SQL` (`SqlAttributeStore` with `System.Data.SqlClient`, parameterized queries), `Custom` (.NET class implementing `IAttributeStore`). Rule compilation is cached per (TrustId, RuleHash) as `Func<ClaimSet, IEnumerable<Claim>>` via `System.Linq.Expressions`.

The CRL is a proprietary DSL — it does not port to other IdPs. Keycloak has "mappers" (Hardcoded, User Attribute, Role, Script, Claim to Role) — no DSL. Authentik has expression policies (Python). Ory Oathkeeper has Rego (OPA) for access rules. Migration from AD FS to any other IdP requires manual translation of every CRL rule to the target's policy language — there is no automated CRL-to-mapper or CRL-to-Rego translator. Per the same KB, common patterns (pass-through, regex transform, conditional issuance, group-to-role mapping, authorization permit/deny) each require manual translation.

For the framework, the recommendation is to adopt a standard policy language (Rego/OPA, Cedar from AWS, or XACML) for claims policy. CRL rules can be auto-translated to the standard language as a one-time migration tool, but new policy should be authored in the standard. Rego is the most mature option with broad tooling support; Cedar has a cleaner syntax but narrower adoption.

**Impact**:

CRL rules do not port to other IdPs; migration requires manual translation. For an enterprise with 50+ RPTs each with 5-10 rules, this is a multi-week migration effort with high risk of translation errors.

**Constraints**:

- Must support AD-as-attribute-store (LDAP query).
- Must support custom attribute stores (plug-in interface).
- For AD FS interop, must accept existing CRL rules or provide a translator.

**Cross-platform considerations**:

- **Windows**: AD FS CRL is the native policy language.
- **macOS**: No native policy language; MDM-driven attribute injection in SSO extensions.
- **Linux**: Keycloak mappers (no DSL); mod_auth_mellon attribute maps (static).
- **Cross-platform consistency**: a standard policy language (Rego/Cedar) is the cross-platform path.

**KB references**:

- [`06-federation-sso/03-claims-rules.md`](../docs/06-federation-sso/03-claims-rules.md) — CRL lexical structure, five-phase pipeline, attribute stores (AD/LDAP/SQL/Custom), rule compilation caching, common rule patterns.
- [`01-ad-core/03-ad-fs-federation.md`](../docs/01-ad-core/03-ad-fs-federation.md) — Claims pipeline phases (CPT Acceptance Transform → RPT Issuance Authorization → RPT Issuance Transform → Delegation → Token Serialization), `Microsoft.IdentityServer.PolicyEngine.PolicyEngine` entry point, `IAttributeStore` interface.

**Open questions**:

- Adopt Rego (OPA) as the claims-policy language?
- Cedar (AWS) — cleaner syntax, narrower adoption?
- Per-IdP plugins (CRL for AD FS, mappers for Keycloak, expression policies for Authentik)?
- Auto-translate CRL to Rego as a one-time migration tool?

**Cross-capability impact**:

- Affects: PC-075 (AD FS OIDC quirks — `allatclaims` scope interacts with CRL rules).
- Affected by: PC-068 (IdP choice — Keycloak mappers vs. CRL is an IdP-specific decision).

---

### PC-070 — Token-signing cert rollover requires RP metadata refresh; 15-day overlap window

**Capability**: Federation Gateway
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD FS auto-rolls token-signing cert (Server 2012 R2+): a new cert is published alongside the old for 5–15 days (configurable via `Set-AdfsProperties -SigningCertificateRolloverInterval`), then promoted to primary. Per [06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md), AD FS publishes both certs (old primary + new secondary) in federation metadata at `/FederationMetadata/2007-06/FederationMetadata.xml` as `<KeyDescriptor use="signing">` entries in the `<IDPSSODescriptor>`. RPs that auto-refresh metadata (most modern SAML SPs do, typically every 24 hours) pick up the new cert before promotion. RPs that cache metadata statically fail with `MSIS1006 — Token signing certificate thumbprint does not match` after promotion.

Per [06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), the failure mode is intermittent: some RPs succeed (those that refreshed metadata recently) and some fail (those with stale cache) — making diagnosis harder. The `certutil -dspublish` equivalent for AD FS is automatic — the AD FS service publishes its signing cert to AD at `CN=<ADFS-FS-Name>,CN=Program Data,CN=ADFS,CN=Microsoft,CN=Program Data,DC=...` (a `contact` object with `servicePrincipalName` and `userCertificate` attributes), so domain-joined clients can validate ADFS-issued tokens without prior trust config. But non-domain-joined RPs (SaaS apps, cloud services) must fetch metadata manually.

For the framework, the design should automate cert rollover + RP notification: (a) publish both old + new certs in metadata for the rollover window; (b) support `validUntil` attribute on metadata for cert transition signaling; (c) auto-notify RPs via webhook on cert rollover (a non-standard but practical extension); (d) for OIDC, use JWKS rotation API (RFC 8414 — Authorization Server Metadata, RFC 7517 — JSON Web Key) with both `kid`s published during rollover.

**Impact**:

Cert rollover causes intermittent RP failures. RPs that don't auto-refresh metadata break silently — users see "SAML response signature validation failed" with no obvious cause. Worst case: a critical SaaS app goes down for users in the rollover window.

**Constraints**:

- Must publish both old + new certs in federation metadata during rollover window.
- Must support `validUntil` for cert transition signaling.
- For OIDC, must support JWKS rotation (RFC 8414 + RFC 7517) with both `kid`s published.
- Should support webhook-based RP notification on cert rollover.

**Cross-platform considerations**:

- **Windows**: AD FS auto-rollover via `Microsoft.IdentityServer.ServiceHost.exe`; `Set-AdfsCertificate -CertificateType TokenSigning -PromoteToPrimary` for manual control.
- **macOS**: No native token-signing cert rollover (macOS is a client only).
- **Linux**: Keycloak realm certificate rollover via admin console; both certs published in JWKS during transition.
- **Cross-platform consistency**: JWKS rotation API (RFC 8414) is the cross-platform OIDC standard; SAML metadata refresh is per-RP.

**KB references**:

- [`06-federation-sso/01-adfs-architecture.md`](../docs/06-federation-sso/01-adfs-architecture.md) — Token-signing cert auto-rollover (Server 2012 R2+), 5–15 day overlap window, AD publication at `CN=<ADFS-FS-Name>,CN=Program Data,CN=ADFS,...`, `Get-AdfsCertificate -CertificateType TokenSigning` for status.
- [`06-federation-sso/02-saml-ws-fed.md`](../docs/06-federation-sso/02-saml-ws-fed.md) — Federation metadata XML structure (`<IDPSSODescriptor>`/`<SPSSODescriptor>`, `<KeyDescriptor use="signing">`), `MSIS1006` and `MSIS1135` signature validation errors.

**Open questions**:

- Auto-notify RPs via webhook on cert rollover (non-standard but practical)?
- JWKS rotation API (RFC 8414) for OIDC with both `kid`s published during rollover?
- Per-RP rollover policy (some RPs may need longer overlap)?

**Cross-capability impact**:

- Affects: PC-071 (OIDC vs. WS-* — JWKS rotation is OIDC-native, SAML metadata refresh is per-RP).
- Affected by: PC-057 (Cert Service issues the token-signing cert; autoenroll renews it).

---

### PC-071 — WS-Federation and WS-Trust are legacy; OIDC is the modern path

**Capability**: Federation Gateway
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD FS supports WS-Federation (passive, SOAP-based, ~2003) + WS-Trust (active, SOAP-based) + SAML 2.0 (OASIS, 2005) + OIDC (2016+). Per [06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md), AD FS OIDC endpoints include `/adfs/oauth2/authorize`, `/adfs/oauth2/token`, `/adfs/oauth2/userinfo`, `/adfs/oauth2/jwks`, `/.well-known/openid-configuration`. Per [06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), WS-Federation passive uses `wa=wsignin1.0` / `wsignout1.0` parameters with `wtrealm` (RP identifier), `wreply` (return URL), `wctx` (state), `wreq` (optional RST XML), `wauth` (auth method URI), `wfresh` (freshness seconds), `whr` (home realm). WS-Trust active uses SOAP endpoints at `/adfs/services/trust/2005/usernamemixed`, `/adfs/services/trust/13/usernamemixed`, `/adfs/services/trust/2005/windowstransport`, `/adfs/services/trust/13/certificatemixed`, `/adfs/services/trust/mex` (WSDL).

WS-* is SOAP-based, declining — modern clients (SPAs, mobile apps) use OIDC. Microsoft itself has deprecated WS-Federation passive in Entra ID (Azure AD) and recommends OIDC for new applications. But enterprises have legacy RPs (SharePoint on-prem 2013/2016/2019, Office desktop client WS-Trust for Exchange/PowerShell, custom .NET apps using `Microsoft.IdentityModel.Tokens` from WIF) that require WS-* support.

For the framework, the design should: (a) support OIDC natively as the primary protocol (RFC 6749, RFC 8252 PKCE, RFC 7636); (b) support SAML 2.0 for legacy RPs (OASIS standard, broad enterprise adoption); (c) deprecate WS-* or provide a compat shim. The compat shim could be a WS-Trust-to-OIDC bridge: the legacy RP sends a WS-Trust RST, the bridge translates to an OIDC token exchange, and the RP gets back a SAML assertion wrapped in RSTR. This preserves legacy RP investment while the framework's core is OIDC-native.

**Impact**:

WS-* migration is a multi-year project for enterprises. SharePoint on-prem, Office desktop, and custom .NET apps all depend on WS-Trust. Dropping WS-* entirely would force enterprises to either rewrite their apps or stay on AD FS.

**Constraints**:

- Must support OIDC (RFC 6749, 8252 PKCE, 7636) — primary protocol.
- Must support SAML 2.0 (OASIS) — for legacy RPs that cannot migrate to OIDC.
- Should provide WS-Trust-to-OIDC bridge for legacy RPs (or drop WS-* entirely).

**Cross-platform considerations**:

- **Windows**: AD FS supports all four protocols natively.
- **macOS**: Apps use AppAuth or ASWebAuthenticationSession for OIDC; no native WS-* client.
- **Linux**: Keycloak supports SAML 2.0 + OIDC; WS-Trust via SOAP endpoint (limited). mod_auth_mellon is SAML only.
- **Cross-platform consistency**: OIDC is the universal modern protocol; SAML 2.0 is the legacy-enterprise standard; WS-* is Windows-only legacy.

**KB references**:

- [`06-federation-sso/04-oidc-oauth.md`](../docs/06-federation-sso/04-oidc-oauth.md) — AD FS OIDC endpoint paths, discovery document, supported flows (authorization_code, implicit, hybrid, client_credentials, refresh_token, password, device_code, jwt-bearer), Application Groups.
- [`06-federation-sso/02-saml-ws-fed.md`](../docs/06-federation-sso/02-saml-ws-fed.md) — WS-Federation passive flow (`wa=wsignin1.0`), RSTR XML structure, WS-Trust active endpoints per auth mode (`usernamemixed`, `windowstransport`, `certificatemixed`).

**Open questions**:

- Drop WS-* entirely and require RPs to migrate to OIDC/SAML?
- Provide a WS-Trust-to-OIDC bridge for legacy RPs?
- Support WS-Federation passive as a separate shim (SharePoint on-prem dependency)?

**Cross-capability impact**:

- Affects: PC-075 (AD FS OIDC quirks — `resource=` parameter is a WS-* legacy leak into OIDC).
- Affected by: PC-068 (IdP choice — Keycloak has limited WS-* support; AD FS supports all).

---

### PC-072 — SAML replay detection window (60 min) and clock skew (5 min) need tuning

**Capability**: Federation Gateway
**Severity**: low
**Cross-platform**: cross-platform

**Problem statement**:

Per [06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), AD FS SAML replay detection caches assertion IDs (the `ID` attribute on `<saml2:Assertion>`) for 60 minutes. If the same assertion ID is submitted twice within the window, the second submission is rejected with `MSIS7029 — The SAML message has already been processed`. Clock skew tolerance is 5 minutes either side — if `IssueInstant` is outside `NotBefore`/`NotOnOrAfter` window (with 5-min skew), the response is rejected with `MSIS7042 — The SAML request has expired`. Per-RP skew override is via `Set-AdfsRelyingPartyTrust -TargetName <name> -NotBeforeSkew 5` (minutes).

The 60-min replay window is too short for slow networks or async processing (e.g., a SAML response queued for retry after 70 minutes is rejected as replay). The 5-min clock skew is too tight for environments without NTP discipline (e.g., VMs with clock drift, IoT devices, legacy systems). Per the same KB, the `IssueInstant` outside the `NotBefore`/`NotOnOrAfter` window (default 60 min) is a top-3 SAML support case — typically caused by NTP misconfiguration on either IdP or SP.

For the framework, the design should make both configurable per-RP and document the security/availability tradeoff: longer replay window = more vulnerable to replay attacks; tighter clock skew = more vulnerable to NTP drift. Per-RP skew policy (high-security RP = 0 min skew, legacy RP = 15 min skew) is the right granularity. Auto-sync clocks via NTP before SAML (a pre-SAML NTP check) is a defensive measure.

**Impact**:

SAML auth failures on clock-skewed SPs. Common in mixed environments (Windows + Linux + IoT) where NTP discipline varies.

**Constraints**:

- Must support per-RP skew override (`NotBeforeSkew`).
- Must support configurable replay detection window (default 60 min, per-RP override).
- Must support NTP-based clock sync verification before SAML (defensive).

**Cross-platform considerations**:

- **Windows**: AD FS `NotBeforeSkew` per-RP; W32Time service for NTP.
- **macOS**: `ntpdate` / `sntp` for clock sync; per-app SAML client may have own skew policy.
- **Linux**: `chrony` / `ntpd` for clock sync; Shibboleth SP / mod_auth_mellon per-RP skew.
- **Cross-platform consistency**: per-RP skew policy is the universal solution; NTP discipline is per-host.

**KB references**:

- [`06-federation-sso/02-saml-ws-fed.md`](../docs/06-federation-sso/02-saml-ws-fed.md) — SAML assertion `Conditions/NotBefore`/`NotOnOrAfter`, replay detection 60-min cache, `MSIS7029` / `MSIS7042` errors, `NotBeforeSkew` per-RP override.
- [`06-federation-sso/01-adfs-architecture.md`](../docs/06-federation-sso/01-adfs-architecture.md) — AD FS SAML endpoints (`/adfs/services/trust/saml/sso`, `/adfs/services/trust/saml/slo`, `/adfs/services/trust/saml/artifact`), `Set-AdfsRelyingPartyTrust -NotBeforeSkew 5` per-RP skew config, `SamlMessageSecureChannel.ReplayDetectionWindow` setting.

**Open questions**:

- Auto-sync clocks via NTP before SAML (pre-SAML NTP check)?
- Per-RP skew policy (high-security RP = 0 min, legacy RP = 15 min)?
- Configurable replay detection window per-RP (default 60 min, override up to 24 hours for async flows)?

**Cross-capability impact**:

- Affects: PC-070 (cert rollover — clock skew interacts with cert validity windows).
- Affected by: PC-071 (OIDC uses `iat`/`exp` JWT claims with similar skew concerns).

---

### PC-073 — AD FS Web Application Proxy (WAP) is Windows-only; modern alternatives exist

**Capability**: Federation Gateway
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

WAP (`WAPService.exe` under `svchost -k WAPServiceSvchost`) is the perimeter reverse proxy that pre-auths via AD FS using MS-ADFSPIP (RPC interface UUID `e9396806-0e29-4660-b661-f6345c4bcd36`), per [01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md). At install, WAP establishes trust with AD FS via `EstablishProxyTrust` — AD FS issues a client cert to WAP stored in `LocalMachine\My` with subject `ADFS Proxy Trust - <WAP-Hostname>`, used for mutual TLS on subsequent RPC calls. WAP registers HTTP URL ACLs for each published application (`https://+:443/<app-path>/`). For pre-authenticated apps, WAP redirects to `/adfs/ls/` on the AD FS server, captures the issued token, validates the signature using the AD FS token-signing cert, then re-encrypts and forwards to the backend over HTTP/HTTPS.

Per [06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md), WAP is Windows-only — it runs as a Windows service and depends on `HTTP.SYS`, MS-ADFSPIP, and AD FS-specific RPC. Modern alternatives: nginx + oauth2-proxy (OIDC pre-auth), Traefik + forward-auth, Caddy + auth portal, Envoy + ext-authz. These are lighter, cross-platform, and support OIDC natively without the MS-ADFSPIP dependency.

For the framework, the recommendation is to adopt a cloud-native reverse proxy with OIDC pre-auth: nginx + oauth2-proxy for simplicity, Envoy + ext-authz for high-scale, or Traefik + forward-auth for container-native. The reverse proxy redirects unauthenticated requests to the framework's OIDC `/authorize` endpoint, captures the issued JWT, validates signature against JWKS, and injects the JWT claims as HTTP headers (`X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`) for the backend.

**Impact**:

WAP is a Windows-only dependency; alternatives are lighter, cross-platform, and support modern protocols (OIDC) natively. For orgs migrating off Windows, WAP is a forced dependency on Windows Server.

**Constraints**:

- Must support OIDC pre-auth (redirect to `/authorize`, validate JWT, inject claims as headers).
- Must support header injection for backend (`X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`).
- For AD FS interop, must support MS-ADFSPIP (or document WAP as legacy).

**Cross-platform considerations**:

- **Windows**: WAP via `WAPService.exe` + MS-ADFSPIP RPC.
- **macOS**: No native equivalent; uses third-party reverse proxies (nginx, Caddy).
- **Linux**: nginx + oauth2-proxy, Traefik + forward-auth, Envoy + ext-authz, Caddy + auth portal.
- **Cross-platform consistency**: nginx + oauth2-proxy is the most portable; Envoy is the most scalable.

**KB references**:

- [`01-ad-core/03-ad-fs-federation.md`](../docs/01-ad-core/03-ad-fs-federation.md) — WAP `WAPService.exe` process model, MS-ADFSPIP RPC UUID, `EstablishProxyTrust` client cert issuance, URL ACL registration.
- [`06-federation-sso/01-adfs-architecture.md`](../docs/06-federation-sso/01-adfs-architecture.md) — WAP MS-ADFSPIP operations (`GetConfiguration`, `GetWebProxyToken`, `StoreRelayState`/`RetrieveRelayState`), per-app pre-auth flow.

**Open questions**:

- Adopt oauth2-proxy as the WAP replacement (simplest, most portable)?
- Envoy + ext-authz for high-scale deployments?
- Traefik + forward-auth for container-native?

**Cross-capability impact**:

- Affects: PC-074 (WAP farm topology — modern reverse proxies have their own clustering).
- Affected by: PC-071 (OIDC pre-auth depends on OIDC support in the framework's IdP).

---

### PC-074 — ADFS farm topology (primary + secondaries in WID mode) is operationally fragile

**Capability**: Federation Gateway
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

WID-mode AD FS has one primary node (writes) + N secondaries (read-only, sync every 5 min via `Microsoft.IdentityServer.PolicyModel.dll!PolicyStore.GetSetUpdate`), per [06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md). All admin cmdlets (`Set-AdfsRelyingPartyTrust`, `Add-AdfsClaimsProviderTrust`, etc.) must hit the primary node. If the primary dies, manual promotion is required: `Set-AdfsSyncProperties -Role PrimaryComputer` on a secondary. SQL-mode adds HA at the SQL tier (synchronous replication, multi-primary writes), but adds SQL Server licensing and HA complexity.

Per [01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md), the WID 5-node limit forces SQL farm for larger deployments. The 5-minute sync lag means a secondary node may serve stale config for up to 5 minutes after a primary-side change — including new RPT configurations, certificate rollovers, and claim rule updates. Worst case: admin adds a new RPT to the primary, a user is redirected to a secondary that hasn't synced yet, and the user gets `MSIS7017 — Audience URI is not in the AudienceRestriction collection`.

For the framework, the recommendation is to use consensus-based config (Raft) for the federation layer. etcd-backed config (like Kubernetes) provides strong consistency across all nodes — no primary/secondary distinction, no sync lag. Each federation node reads config from etcd on startup and watches for changes via etcd's watch API. Writes go through the Raft consensus (majority of nodes must acknowledge), ensuring all nodes see the same config at the same logical time.

**Impact**:

WID primary failure is a manual failover. During the failover window (typically 15–30 minutes for admin response), admin cmdlets fail and config changes cannot be made. The 5-minute sync lag causes intermittent "stale config" failures on secondaries.

**Constraints**:

- Must support multi-primary config (no single primary, all nodes accept writes).
- Must support config DB HA (etcd cluster, Raft consensus).
- For AD FS interop, must accept that WID/SQL is the legacy topology.

**Cross-platform considerations**:

- **Windows**: AD FS WID (primary + secondaries) or SQL farm.
- **macOS**: No native federation farm; uses cloud IdP or external Keycloak.
- **Linux**: Keycloak uses relational DB (MariaDB/Postgres) for realm config — multi-primary via DB replication. etcd is the consensus-native option.
- **Cross-platform consistency**: etcd + Raft is the cross-platform consensus option.

**KB references**:

- [`06-federation-sso/01-adfs-architecture.md`](../docs/06-federation-sso/01-adfs-architecture.md) — WID vs SQL topology, primary/secondary model, 5-node WID limit, 5-minute sync lag, `Set-AdfsSyncProperties -Role PrimaryComputer` promotion.
- [`01-ad-core/03-ad-fs-federation.md`](../docs/01-ad-core/03-ad-fs-federation.md) — WID file paths (`microsoft.identityserver.mdf` / `microsoft.identityserver_log.ldf`), config DB tables (`ServiceSettings`, `RelyingPartyTrust`, `ClaimsProviderTrust`), SQL farm connection string.

**Open questions**:

- etcd-backed config (Raft consensus, multi-primary writes)?
- Raft among federation nodes (no external etcd dependency)?
- SQL farm with synchronous replication for SQL-shop orgs?

**Cross-capability impact**:

- Affects: PC-068 (IdP weight — consensus-based config adds complexity but reduces operational fragility).
- Affected by: PC-073 (WAP replacement — modern reverse proxies have their own clustering).

---

### PC-075 — ADFS as OAuth2/OIDC provider has quirks (`resource=` parameter, Application Groups)

**Capability**: Federation Gateway
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD FS 2016+ OIDC has several quirks that deviate from RFC 6749/8252 strict OIDC, per [06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md). The `resource=` parameter is a non-standard OAuth2 extension (inherited from Azure AD's first-generation OAuth implementation) — the client must pass `resource=<web-api-identifier>` in both `/authorize` and `/token` requests to specify the audience of the issued JWT. Standard OAuth2 uses `scope` for this; AD FS supports `scope` for OIDC scopes (`openid`, `profile`, `email`, `allatclaims`, `winhttpcert`, `msapoc`, `vpn_cert`) but requires `resource` for audience. Standard OIDC clients (oauth2-proxy, AppAuth, MSAL) need adaptation to pass `resource`.

Application Groups (Server 2016+) bundle related application registrations: a Server Application (web app server-side, has `client_secret`), a Native Client (mobile/desktop, PKCE required), and a Web API (resource server, validates JWTs). Each component is a separate "Client" in the AD FS OAuth store; the Application Group is just a UI/management grouping. The Web API component replaces the legacy "Relying Party Trust" for OAuth flows — its `Identifier` becomes the JWT `aud` claim.

Other quirks: `allatclaims` scope for full AD claim pass-through (issues ALL claims the RP's Issuance Transform Rules would emit); refresh token rotation (Server 2019+ opt-in via `Set-AdfsWebApiApplication -IssueOAuthRefreshTokensTo AllDevices`); `winhttpcert` / `msapoc` / `vpn_cert` scopes for Windows-specific cert issuance (Edge / Windows Hello for Business, Always On VPN). The `apptype` claim in the JWT marks Confidential vs Public clients — non-standard.

For the framework, the recommendation is to be RFC 6749/8252 strict by default and document AD FS quirks for migration. The `resource=` parameter should be a compat mode (opt-in via per-client configuration) for AD FS migration; standard `scope` should be the default. Application Groups map to standard OAuth2 client + resource server pairs.

**Impact**:

AD FS OIDC is not strictly RFC-conformant; standard OIDC clients need adaptation. Migration to a strict OIDC provider requires updating clients to drop `resource=` and use `scope` for audience.

**Constraints**:

- Must support RFC 6749 (OAuth 2.0), RFC 8252 (PKCE for native apps), RFC 7636 (PKCE).
- Must support OIDC Discovery (RFC 8414 — Authorization Server Metadata).
- Should provide `resource=` compat mode for AD FS migration.

**Cross-platform considerations**:

- **Windows**: AD FS OIDC with `resource=` parameter, Application Groups, `allatclaims`/`winhttpcert`/`msapoc`/`vpn_cert` scopes.
- **macOS**: AppAuth / ASWebAuthenticationSession are RFC-strict; require `resource=` adaptation for AD FS.
- **Linux**: oauth2-proxy, mod_auth_openidc, Keycloak adapters are RFC-strict; require `resource=` adaptation for AD FS.
- **Cross-platform consistency**: RFC-strict OIDC is the cross-platform default; AD FS `resource=` is a compat shim.

**KB references**:

- [`06-federation-sso/04-oidc-oauth.md`](../docs/06-federation-sso/04-oidc-oauth.md) — AD FS OIDC discovery document (including `resource=` requirement), Application Groups (Server Application + Native Client + Web API), `allatclaims`/`winhttpcert`/`msapoc`/`vpn_cert` scopes, `apptype` claim, refresh token rotation.
- [`06-federation-sso/01-adfs-architecture.md`](../docs/06-federation-sso/01-adfs-architecture.md) — AD FS endpoint path table (`/adfs/oauth2/authorize`, `/adfs/oauth2/token`, `/adfs/oauth2/jwks`, `/.well-known/openid-configuration`), `RelyingPartyTrust` config DB table for Application Group storage, `Set-AdfsWebApiApplication` / `Set-AdfsWebApplication` / `Add-AdfsNativeClientApplication` cmdlets.

**Open questions**:

- Provide `resource=` compat mode for AD FS migration (per-client opt-in)?
- Strict OIDC by default (RFC 6749/8252 conformant)?
- Map Application Groups to standard OAuth2 client + resource server pairs?

**Cross-capability impact**:

- Affects: PC-076 (External OIDC IdP federation — `resource=` quirk is AD FS-specific; strict OIDC is portable).
- Affected by: PC-069 (CRL — `allatclaims` scope interacts with Issuance Transform Rules).

---

### PC-076 — External OIDC IdP federation (ADFS-as-RP) needs explicit CPT configuration

**Capability**: Federation Gateway
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

ADFS 2019+ can federate to external OIDC IdPs (Entra ID, Okta, Google, Keycloak), per [06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md). Steps: `Add-AdfsClaimsProviderTrust -Name 'AzureAD-Corp' -OIDCUrl 'https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize' -ClientID <azure-ad-app-id> -ClientSecret (ConvertTo-SecureString ...) -MetadataUrl 'https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration' -IssuanceTransformRules @(...)`. ADFS becomes the RP; the user selects this CPT at the home realm discovery page. The external IdP issues its own JWT; ADFS validates, extracts claims into the pipeline, and re-issues its own JWT/SAML token to the downstream RP.

This is the "federation chain" pattern — the external IdP becomes one of multiple CPTs. Each external IdP requires explicit per-IdP configuration: OIDC URL, ClientID, ClientSecret, MetadataURL, Issuance Transform Rules. There is no auto-discovery of multiple IdPs (the `whr` parameter or home realm discovery page lets the user pick, but the admin must pre-configure each CPT). Per the same KB, ADFS's home realm discovery is an HTML page at `/adfs/ls/idpinitiatedsignon.aspx` (disabled by default since Server 2016) that lists available CPTs; the user clicks one and is redirected.

For the framework, the design should support IdP brokering natively (Keycloak-style): each tenant can configure multiple external IdPs (OIDC, SAML, social), users pick at login via home realm discovery, and the framework brokers the auth flow. Per-tenant IdP routing (e.g., `@corp.example.com` → AD, `@partner.com` → Partner OIDC) is the right granularity. This is native in Keycloak (Identity Brokering) and Authentik (Federation).

**Impact**:

Multi-IdP federation is manual per-IdP configuration. For an enterprise with 10+ partner IdPs, this is significant operational overhead. Home realm discovery UX is poor (manual user click).

**Constraints**:

- Must support OIDC + SAML IdP brokering (framework is RP to external IdP, IdP to downstream RP).
- Must support home realm discovery (HTML page or `whr` parameter).
- Must support per-tenant IdP routing (email domain → IdP).

**Cross-platform considerations**:

- **Windows**: AD FS via `Add-AdfsClaimsProviderTrust` with `-OIDCUrl` / `-ClientID` / `-ClientSecret` / `-MetadataUrl`; home realm discovery via `idpinitiatedsignon.aspx`.
- **macOS**: No native IdP brokering; per-app implementation.
- **Linux**: Keycloak Identity Brokering (OIDC/SAML/social); per-realm IdP configuration; home realm discovery via login page.
- **Cross-platform consistency**: Keycloak-style identity brokering is the cross-platform path.

**KB references**:

- [`06-federation-sso/04-oidc-oauth.md`](../docs/06-federation-sso/04-oidc-oauth.md) — `Add-AdfsClaimsProviderTrust` OIDC parameters (`-OIDCUrl`, `-ClientID`, `-ClientSecret`, `-MetadataUrl`), Issuance Transform Rules for external IdP claims, home realm discovery via `idpinitiatedsignon.aspx`.
- [`06-federation-sso/01-adfs-architecture.md`](../docs/06-federation-sso/01-adfs-architecture.md) — `ClaimsProviderTrust` config DB table (per-CPT row with `Identifier`, `Name`, `AcceptanceTransformRules`), `Get-AdfsClaimsProviderTrust` enumeration, `whr` parameter for CPT selection at `/adfs/ls/`.

**Open questions**:

- Adopt Keycloak-style identity brokering (per-tenant IdP routing)?
- Per-tenant IdP routing (email domain → IdP)?
- Auto-discovery of available IdPs (vs. explicit per-IdP configuration)?

**Cross-capability impact**:

- Affects: PC-069 (CRL — external IdP claims pass through Acceptance Transform Rules).
- Affected by: PC-071 (OIDC is the modern protocol for IdP brokering; SAML for legacy).

---

### PC-077 — AD RMS (DRM/IRM) has no open-source server; AIP is the migration path

**Capability**: Facility: Federation Gateway (related — RMS is a separate AD service but shares the federation trust model)
**Severity**: low
**Cross-platform**: cross-platform

**Problem statement**:

AD RMS (`rmssvc.exe` inside `svchost -k netsvcs`) issues use licenses for protected content, per [01-ad-core/05-ad-rms-rights.md](../docs/01-ad-core/05-ad-rms-rights.md). The Server Licensor Certificate (SLC) private key compromise = all issued ILs compromised — every protected document ever issued by the RMS cluster becomes decryptable by anyone with the SLC private key. RMS uses a multi-stage pipeline: machine activation (client generates RSA keypair), enrollment (RMS server signs public key in RAC — Rights Account Certificate), client licensor cert (CLC — fresh RSA keypair, public key + validity signed with SLC), content encryption (AES-256 content key + per-recipient RSA wrap inside Issuance License IL), use license (recipient decrypts AES key with their RSA private key).

Microsoft's Azure Information Protection (AIP) is the cloud migration target for on-prem AD RMS. The Microsoft Information Protection (MIP) SDK exists for Linux/macOS clients (`mip_sdk` NuGet / pip package), enabling cross-platform protected-content consumption. But there is no open-source RMS server — the SLC issuance, use-license issuance, and revocation machinery is proprietary to Microsoft.

For the framework, the recommendation is to document whether IRM (Information Rights Management) is in scope (likely no — the use cases are narrow: legal, finance, healthcare with strict IRM requirements) and recommend AIP for orgs that need IRM. Implementing a minimal RMS-compatible server (SLC issuance + use-license issuance + revocation) is a significant engineering effort with no open-source reference; the only viable path is AIP or a third-party IRM (Vera, VeraCloud, Seclore).

**Impact**:

IRM-dependent orgs (legal, finance, healthcare) have no open-source alternative to AD RMS. For orgs without IRM needs (most orgs), this is a non-issue.

**Constraints**:

- If in scope, must support use-license issuance + content key encryption (AES-256 content key + per-recipient RSA wrap).
- If in scope, must support SLC private key protection (HSM-backed).
- If out of scope, recommend AIP or third-party IRM (Vera, Seclore).

**Cross-platform considerations**:

- **Windows**: AD RMS (`rmssvc.dll` under `svchost -k netsvcs`); AIP client for cloud.
- **macOS**: MIP SDK for client-side consumption; no native RMS server.
- **Linux**: MIP SDK for client-side consumption; no native RMS server.
- **Cross-platform consistency**: AIP + MIP SDK is the only cross-platform IRM path; no open-source server exists.

**KB references**:

- [`01-ad-core/05-ad-rms-rights.md`](../docs/01-ad-core/05-ad-rms-rights.md) — RMS architecture (`rmssvc.exe` cluster topology), SLC issuance, RAC/CLC pipeline, content encryption (AES-256 content key + per-recipient RSA wrap), use license flow, `DRMS_Config_*` SQL Server database.
- [`05-pki-certs/02-certificate-templates.md`](../docs/05-pki-certs/02-certificate-templates.md) — `pKICertificateTemplate` AD class for RMS server licensor cert templates, `pKIExtendedKeyUsage` OID `1.3.6.1.4.1.311.10.3.6` (Key Recovery) and related RMS EKU OIDs, `msPKI-Private-Key-Flag.REQUIRE_ARCHIVAL` for SLC private key archival.

**Open questions**:

- Out of scope (recommend AIP)?
- Implement minimal RMS-compatible server (SLC + use license + revocation)?
- Adopt third-party IRM (Vera, Seclore) as integration partner?

**Cross-capability impact**:

- Affects: PC-068 (IdP weight — RMS is a separate service from AD FS but shares the federation trust model).
- Affected by: PC-057 (Cert Service — RMS uses AD CS or third-party certs for SLC issuance), PC-066 (CA topology — RMS SLC private key protection benefits from HSM).
