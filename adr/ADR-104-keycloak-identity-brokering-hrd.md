---
title: "ADR-104: Keycloak identity brokering with home realm discovery — per-tenant IdP routing"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-076
severity: medium
unblocked_by: Workshop Decision 9
tags: [adr, federation-gateway, home-realm-discovery, identity-brokering, oidc, saml, entra-id, keycloak]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../workshop/decision-09-federation-layer.md
  - ../docs/06-federation-sso/04-oidc-oauth.md
  - ../docs/06-federation-sso/02-saml-ws-fed.md
  - ./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md
  - ./ADR-101-adfs-claim-rule-language-compat.md
last_updated: 2026-08-14
---

# ADR-104: Keycloak identity brokering with home realm discovery — per-tenant IdP routing

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 9](../workshop/decision-09-federation-layer.md) (Federation layer: wrap Keycloak with Rust AD-claim-rules shim). This ADR operationalises Decision 9 §6 (identity brokering) against the PC-076 problem surface: AD FS's external OIDC IdP federation, which requires explicit per-IdP Claims Provider Trust (CPT) configuration and offers poor home-realm-discovery UX, which the framework replaces with Keycloak's built-in identity brokering plus the framework's per-tenant IdP routing layer in the Rust shim.

## Context

ADFS 2019+ can federate to external OIDC IdPs (Entra ID, Okta, Google, Keycloak), per [docs/06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md). Steps: `Add-AdfsClaimsProviderTrust -Name 'AzureAD-Corp' -OIDCUrl 'https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize' -ClientID <azure-ad-app-id> -ClientSecret (ConvertTo-SecureString ...) -MetadataUrl 'https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration' -IssuanceTransformRules @(...)`. ADFS becomes the RP; the user selects this CPT at the home realm discovery page. The external IdP issues its own JWT; ADFS validates, extracts claims into the pipeline, and re-issues its own JWT/SAML token to the downstream RP.

This is the "federation chain" pattern — the external IdP becomes one of multiple CPTs. Each external IdP requires explicit per-IdP configuration: OIDC URL, ClientID, ClientSecret, MetadataURL, Issuance Transform Rules. There is no auto-discovery of multiple IdPs (the `whr` parameter or home realm discovery page lets the user pick, but the admin must pre-configure each CPT). Per [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), ADFS's home realm discovery is an HTML page at `/adfs/ls/idpinitiatedsignon.aspx` (disabled by default since Server 2016) that lists available CPTs; the user clicks one and is redirected. For an enterprise with 10+ partner IdPs, this is significant operational overhead. Home realm discovery UX is poor (manual user click).

The framework's constraints (from [PC-076](../catalog/06-federation-gateway.md)): must support OIDC + SAML IdP brokering (framework is RP to external IdP, IdP to downstream RP); must support home realm discovery (HTML page or `whr` parameter); must support per-tenant IdP routing (email domain → IdP).

Workshop Decision 9 §6 fixes this by specifying that Keycloak's built-in identity brokering supports federating to external OIDC/SAML IdPs, with the framework's CLI exposing this via `adrian-fed broker add`. The shim adds claim-rule transformation on top of brokered identities (e.g., a brokered Entra ID user mapped to a framework-directory user via email-claim matching, with claim rules adding framework-specific claims like UUID and group SIDs).

## Decision

The framework's Federation Gateway uses **Keycloak's built-in identity brokering** for external IdP federation, with **the Rust shim adding a per-tenant IdP routing layer** that maps email domain → IdP for automatic home realm discovery. There is no `idpinitiatedsignon.aspx` HTML page; home realm discovery is automatic (email domain) or hint-based (`?whr=` parameter or `?login_hint=`). The framework ships pre-built broker configurations for Entra ID, Google, GitHub, and Apple; arbitrary OIDC/SAML IdPs are supported via `adrian-fed broker add`.

### Concrete specification

1. **Keycloak identity brokering.** The framework uses Keycloak's built-in identity brokering (per the [Keycloak Identity Brokering documentation](https://www.keycloak.org/docs/latest/server_admin/#_identity_broker)) to federate to external IdPs. Each external IdP is configured as a Keycloak `IdentityProvider` in the realm's `identityProviders` configuration. The framework's CLI `adrian-fed broker add --provider <oidc|saml> --name <name> --alias <alias> ...` creates a Keycloak `IdentityProvider` via Keycloak's admin API. The CLI accepts the standard OIDC parameters (`authorizationUrl`, `tokenUrl`, `clientId`, `clientSecret`, `jwksUrl`, `logoutUrl`) and the standard SAML parameters (`singleSignOnServiceUrl`, `singleLogoutServiceUrl`, `signingCertificate`, `nameIdPolicyFormat`).

2. **Pre-built broker configurations.** The framework ships pre-built broker configurations for the four most common external IdPs:
   - **Entra ID (Azure AD)** — `adrian-fed broker add-entra --tenant <tenant-id>`: creates an OIDC `IdentityProvider` with `authorizationUrl=https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize`, `tokenUrl=https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token`, `jwksUrl=https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`, `clientId=<prompt>`, `clientSecret=<prompt>`, `defaultScope=openid profile email`. The CLI also generates the Entra ID app registration manifest (display name, redirect URI `https://idp.<domain>/realms/<realm>/broker/entra/login`) for the operator to apply in the Entra ID portal.
   - **Google** — `adrian-fed broker add-google --client-id <id> --client-secret <secret>`: creates an OIDC `IdentityProvider` with Google's well-known endpoints.
   - **GitHub** — `adrian-fed broker add-github --client-id <id> --client-secret <secret>`: creates an OIDC `IdentityProvider` with GitHub's well-known endpoints. Note: GitHub OIDC does not return email in the ID token by default; the framework's `claim-rules.yaml` includes a rule to query GitHub's `/user/emails` API via a custom store (the shim's `StoreContext` extension point).
   - **Apple** — `adrian-fed broker add-apple --service-id <id> --team-id <id> --key-id <id> --key-file <path>`: creates an OIDC `IdentityProvider` with Apple's well-known endpoints and Apple-specific client-secret JWT generation (the shim generates the per-request client-secret JWT using the Apple-issued private key).

3. **Per-tenant IdP routing (email domain → IdP).** The shim's per-tenant IdP routing layer maps email domain → broker alias. Configuration via `adrian-fed broker route add --domain corp.example.com --broker ad-corporate` (the broker `ad-corporate` is the framework's own AD-equivalent directory, accessed via Keycloak's built-in User Federation Provider pointing at the shim's `/internal/userfed` endpoint per Decision 9 §3). When a user arrives at the Federation Gateway's login page (`https://idp.<domain>/realms/<realm>/protocol/openid-connect/auth?client_id=<client>&redirect_uri=<uri>`) without a session, the shim's custom login form (Keycloak theme) prompts for an email address. On submit, the shim looks up the email domain in the routing table; if a matching broker is found, the shim redirects the user to that broker's `/broker/<alias>/login` endpoint. If no match is found, the shim falls back to the framework's own directory (the default broker).

4. **Hint-based home realm discovery.** For programmatic clients (e.g., a SAML SP that knows the user's home realm), the shim supports hint-based home realm discovery:
   - `?whr=<broker-alias>` — SAML/WS-Federation passive convention; the shim redirects to the named broker's `/broker/<alias>/login` endpoint, skipping the email-domain prompt.
   - `?login_hint=<email>` — OIDC convention; the shim extracts the email domain from the hint and applies the per-tenant routing table. If the hint is a full email address, the shim pre-fills the login form's email field and applies the routing table on submit.
   - `?domain_hint=<domain>` — Entra ID convention; the shim applies the routing table to the domain hint directly.

5. **Home realm discovery page.** The shim does not ship an `idpinitiatedsignon.aspx`-equivalent HTML page. Home realm discovery is automatic (email domain) or hint-based (`?whr=`, `?login_hint=`, `?domain_hint=`). Customers who need an explicit "pick your IdP" page (e.g., for a portal that aggregates multiple IdPs) can configure Keycloak's built-in `IdentityProvider`-redirector authenticator, which renders a list of available brokers as HTML links. The framework's default theme renders this list as a styled HTML page; the framework's documentation notes this is the equivalent of AD FS's `idpinitiatedsignon.aspx`.

6. **Claim-rule transformation on brokered identities.** When a brokered user authenticates (e.g., a brokered Entra ID user), the shim applies the framework's claim rules (per [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md)) to the brokered identity's claims. Typical transformations:
   - **Email-to-UUID mapping** — the shim's `StoreContext` queries the framework's directory for a user with `mail=<brokered-claim-email>`; if found, the rule issues a `sub` claim with the framework's UUID. If not found, the rule issues a `sub` claim with a derived synthetic UUID (UUIDv5 from the broker alias + the broker's `sub` claim), and the shim logs the unmapped brokered user for operator review.
   - **Group SID injection** — the shim's `StoreContext` queries the framework's directory for the mapped user's group membership (via `memberOf` back-link per ADR-002) and issues `groups` claim with the user's framework group SIDs.
   - **Broker-source attribution** — the shim issues a `idp` claim with the broker alias (e.g., `entra`, `google`) so downstream RPs can distinguish brokered users from framework-native users.

7. **Just-in-time (JIT) user provisioning.** The framework supports JIT provisioning of brokered users via Keycloak's `IdentityProvider` `firstBrokerLoginFlow` setting. When a brokered user authenticates for the first time and the email-to-UUID mapping fails (no framework user with that email), the JIT flow creates a framework-directory user with the brokered user's email, display name, and a random password (the brokered user never sees the password; they always authenticate via the broker). The JIT-created user is added to a default group (`brokered-users`) with restricted permissions. Operators can configure per-broker JIT behavior: `jit=enabled` (default), `jit=disabled` (brokered users must be pre-created), `jit=link-only` (brokered users must be pre-created and linked manually by an admin).

8. **Multi-tenancy.** Keycloak's one-realm-per-tenant model is preserved (per Decision 9 §7). Each realm has its own set of brokers, routing rules, and claim rules. `adrian-fed realm create --tenant <name>` creates a fully isolated realm with no brokers by default; the tenant admin adds brokers via `adrian-fed broker add` within the realm.

9. **Audit.** Every broker authentication is logged per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with attributes `adrian.fed.realm`, `adrian.fed.broker`, `adrian.fed.broker_subject`, `adrian.fed.framework_subject`, `adrian.fed.jit_provisioned` (bool), `adrian.fed.routing_method` (`email-domain` / `whr-hint` / `login-hint` / `domain-hint` / `default`). The audit log is the primary forensic record for brokered-authentication incidents.

10. **AD FS migration.** The `adrian-migrate from-adfs` CLI (per Decision 9 §5) translates AD FS Claims Provider Trusts to Keycloak `IdentityProvider` configurations. Each AD FS CPT with `-OIDCUrl` becomes an OIDC broker; each CPT with `-MetadataUrl` (SAML) becomes a SAML broker. The CLI emits a per-CPT migration report listing the broker alias, the routing rule (derived from the CPT's `AcceptanceTransformRules` if they include an email-domain check), and any manual configuration required (e.g., client secret rotation).

## Rationale

AD FS's home realm discovery exists because every multi-IdP federation needs to route users to the right IdP, and the simplest 2003-era answer was an HTML page that lists the IdPs. In 2026, the modern answer is automatic routing based on the user's email domain — most users have a stable email domain that maps to their IdP, and the manual-pick page is a UX regression. Keycloak's identity brokering provides the federation-chain primitive (framework is RP to external IdP, IdP to downstream RP), and the shim's per-tenant routing layer adds the automatic-home-realm-discovery layer that Keycloak does not provide out of the box.

The framework chose Keycloak's built-in brokering over re-implementing brokering in the shim because (a) Keycloak's brokering is mature (Red Hat ships it, AWS documents it); (b) the framework's differentiation is the per-tenant routing layer and the claim-rule transformation, not the brokering itself; (c) re-implementing brokering would duplicate Keycloak's OIDC-client and SAML-SP logic, which is the kind of protocol re-implementation Decision 9 explicitly rejects.

The framework chose email-domain-based routing as the default because (a) it is the most common pattern in enterprise federation (Entra ID's `domain_hint`, Okta's `email-domain routing`, Auth0's `HRD`); (b) it requires no user interaction (the email is collected by the login form anyway); (c) it works for programmatic clients via `?login_hint=`. Hint-based routing (`?whr=`, `?domain_hint=`) is the fallback for clients that cannot collect an email (e.g., SAML SPs that initiate auth with a pre-configured IdP).

The framework chose to ship pre-built broker configurations for Entra ID, Google, GitHub, and Apple because these are the four most common external IdPs in enterprise and consumer federation. Pre-built configurations reduce operator error (the Entra ID tenant-id format, the GitHub OIDC email-API quirk, the Apple client-secret JWT generation) and provide a tested baseline. Arbitrary OIDC/SAML IdPs are supported via `adrian-fed broker add` for the long tail.

## Consequences

**Positive**. Home realm discovery is automatic for the common case (email-domain routing) — no manual user pick page. Per-tenant IdP routing supports 10+ partner IdPs without per-IdP user prompts. Pre-built broker configurations for Entra ID, Google, GitHub, and Apple reduce operator error. JIT provisioning supports brokered users who do not have a pre-existing framework-directory account. Claim-rule transformation on brokered identities (per ADR-101) ensures downstream RPs see a consistent claim set regardless of whether the user authenticated via the framework's directory or a brokered IdP.

**Negative**. Email-domain routing requires the email domain to be a stable identifier for the user's IdP. Customers where the email domain does not match the IdP (e.g., a contractor with a `@contractor.com` email who should authenticate via the customer's Entra ID) must configure an explicit override (`adrian-fed broker route add --user <upn> --broker <alias>`) or fall back to hint-based routing. The JIT-provisioning default (`jit=enabled`) creates framework-directory users automatically — operators who want stricter control must set `jit=link-only` per broker.

**Neutral**. The framework does not ship an `idpinitiatedsignon.aspx`-equivalent HTML page by default; customers who need one can configure Keycloak's `IdentityProvider`-redirector authenticator. The framework's default theme provides a styled version of the redirector page for customers who want it.

**Implementation cost**. ~1.5 person-weeks for v1 (part of the shim's 5-pw budget per Decision 9): per-tenant routing layer in the shim (0.5 pw), pre-built broker configurations (0.5 pw), JIT provisioning integration (0.3 pw), AD FS migration CLI for CPTs (0.2 pw).

**Operational impact**. Federation Gateway operators configure brokers via `adrian-fed broker add` and routing rules via `adrian-fed broker route add`. The framework's `FederationGateway` CRD references the broker and routing configuration. The shim's Prometheus metric `adrian_fed_broker_authentications_total{realm,broker,result}` is the primary SLO for broker performance; the audit log records every broker authentication.

## Alternatives Considered

### Alternative A: AD FS-style `idpinitiatedsignon.aspx` HTML page as the default

The shim ships an HTML page at `/realms/<realm>/broker/pick` that lists all configured brokers as clickable links; the user picks an IdP manually. Rejected as the default because (a) manual picking is a UX regression for the common case (email-domain routing is automatic); (b) the manual-pick page is a fallback for customers who need it, not the default; (c) programmatic clients (SAML SPs, OIDC clients with `login_hint`) cannot use the manual-pick page. The manual-pick page is supported as an opt-in via Keycloak's `IdentityProvider`-redirector authenticator.

### Alternative B: Re-implement identity brokering in the Rust shim (no Keycloak brokering)

The shim implements its own OIDC-client and SAML-SP logic for external IdPs; Keycloak is used only for the framework's own directory. Rejected because (a) this is the protocol re-implementation Decision 9 explicitly rejects; (b) Keycloak's brokering is mature and well-tested (Red Hat, AWS); (c) the framework's differentiation is the per-tenant routing layer and claim-rule transformation, not the brokering itself. Re-implementing brokering would add ~10 person-weeks of effort for no benefit.

### Alternative C: Auto-discovery of available IdPs via `.well-known/webfinger` (RFC 7033)

The shim implements WebFinger: given a user's email or URL, the shim queries `https://<domain>/.well-known/webfinger?resource=acct:<email>` to discover the user's IdP. Rejected as the primary routing mechanism because (a) WebFinger requires the email domain's web server to host a `.well-known/webfinger` endpoint, which most IdPs do not do (Entra ID, Okta, Google do not host WebFinger for user emails); (b) WebFinger adds a network round-trip to every login (query the email domain's web server, parse the WebFinger response, redirect to the discovered IdP); (c) the per-tenant routing table (`adrian-fed broker route add`) achieves the same outcome (email domain → IdP) without the network round-trip. WebFinger is supported as an opt-in extension for customers whose IdPs host WebFinger (`adrian-fed broker route add --domain <domain> --webfinger`).

### Alternative D: Cloud-first (Entra ID as the sole external IdP)

The framework federates only to Entra ID; other external IdPs are not supported. Rejected because (a) Decision 9 explicitly rejects cloud-first (ORQ-134 = NO); (b) customers with partner IdPs (Okta, Google, custom SAML IdPs) cannot use Entra ID as a universal broker; (c) the framework's value proposition includes supporting customers with diverse IdP ecosystems. Entra ID is a supported broker (per §2), not the sole broker.

## Open Questions

- Should the framework support SAML IdP brokering in v1 (in addition to OIDC brokering)? Current decision: yes — Keycloak's identity brokering supports SAML natively, and the framework's `adrian-fed broker add --provider saml` exposes it. SAML brokering is less common than OIDC but is required for some legacy partner IdPs.
- Should the framework support social-login brokers (Facebook, Twitter, LinkedIn) in v1? Current decision: no — social-login brokers are rare in enterprise federation; customers who need them can configure them via `adrian-fed broker add` manually.
- Should the framework support multi-broker authentication (a user authenticates to multiple brokers in sequence, with claims merged)? Current decision: no — multi-broker authentication is rare and adds significant complexity; revisit if customer demand warrants.

## Cross-capability impact

- **Federation Gateway (PC-068 — AD FS topology).** Addressed in [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md). Identity brokering is a sub-feature of the Federation Gateway.
- **Federation Gateway (PC-069 — claims rule language).** Addressed in [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md). Claim rules apply to brokered identities (per §6).
- **Core Directory.** The shim's per-tenant routing layer and JIT provisioning query the framework's directory for email-to-UUID mapping and group membership.
- **Auth Provider.** The framework's own directory is exposed as a broker (the `ad-corporate` broker) via Keycloak's User Federation Provider pointing at the shim's `/internal/userfed` endpoint.
- **Policy Engine (Workshop Decision 7).** Broker and routing configuration is stored in Git (per ADR-031) and applied via `adrian-fed apply`, consistent with the framework's Git-backed configuration model.
- **Migration (PC-124 AD FS-to-framework).** The `adrian-migrate from-adfs` CLI translates AD FS Claims Provider Trusts to Keycloak `IdentityProvider` configurations.

## References

- [PC-076](../catalog/06-federation-gateway.md) — problem statement
- [Workshop Decision 9](../workshop/decision-09-federation-layer.md) — §6 identity brokering
- [docs/06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md) — `Add-AdfsClaimsProviderTrust` OIDC parameters, Issuance Transform Rules for external IdP claims, home realm discovery via `idpinitiatedsignon.aspx`
- [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md) — `whr` parameter for CPT selection at `/adfs/ls/`, `ClaimsProviderTrust` config DB table
- [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md) — Keycloak + Rust shim deployment topology
- [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md) — AD FS claim rule language compatibility (applies to brokered identities)
- [Keycloak Identity Brokering](https://www.keycloak.org/docs/latest/server_admin/#_identity_broker) — Keycloak's identity brokering documentation
- [Microsoft Entra ID OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) — Entra ID OIDC endpoints
- [RFC 7033 — WebFinger](https://www.rfc-editor.org/rfc/rfc7033) — alternative considered and rejected as the primary routing mechanism
