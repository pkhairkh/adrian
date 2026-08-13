---
title: "Federation Gateway (SAML / OIDC / WS-Fed) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Federation Gateway
tags: [spec, federation-gateway, saml, oidc, keycloak, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Federation Gateway (SAML / OIDC / WS-Fed) — Technical Specification

## 1. Overview

The Federation Gateway replaces AD FS with Keycloak 26+ (Quarkus distribution) running as a Kubernetes StatefulSet with a Rust `adrian-federation-shim` sidecar that handles WS-Trust-to-OIDC bridging (ADR-039), claim-rule translation (ADR-101), JWKS rollover with webhook notification (ADR-038), strict OIDC by default with `resource=` compat opt-in (ADR-041), SAML replay detection with per-RP clock skew (ADR-040), and identity brokering / HRD (ADR-104). The capability has zero blockers — the modern IdP ecosystem (Keycloak, Auth0, Okta, Azure AD) covers the gap entirely.

Workshop Decision 9 chose wrap-Keycloak over re-implementing AD FS or building native. The Rust shim is stateless — all per-realm, per-client, per-rule configuration lives in Keycloak's PostgreSQL, and the shim loads on demand with a 5-minute `moka` LRU cache. This means the shim can be horizontally scaled independently of Keycloak; in a multi-replica StatefulSet, any shim instance can serve any request. The shim's perimeter-auth functions (pre-auth, relay-state storage, header injection) are implemented natively in Rust; relay state is stored in PostgreSQL (`adrian_relay_state` table keyed by an opaque 256-bit token). The WS-Trust bridge is the only piece that cannot be natively served by Keycloak — Keycloak 25+ dropped WS-Trust server support, so the shim re-implements the WS-Trust `wsignin1.0` flow as a translator to OIDC code-flow.

The capability carries 10 ADRs: ADR-038 (JWKS endpoint + webhook rollover), ADR-039 (OIDC primary + WS-Trust bridge), ADR-040 (SAML replay + per-RP clock skew), ADR-041 (strict OIDC + resource= compat opt-in), ADR-042 (AD RMS out of scope, recommend AIP), ADR-100 (Keycloak StatefulSet + Rust shim sidecar), ADR-101 (AD FS claim-rule language compat), ADR-102 (Rust shim WAP replacement), ADR-103 (Keycloak StatefulSet, no primary/secondary), ADR-104 (identity brokering + HRD). The capability is implemented as **two** Rust crates at Layer 3: `adrian-federation-shim` (the sidecar binary + library, ~5K lines) and `adrian-claims-engine` (AD FS CRL compatibility, ~2K lines). External dependencies include `axum`, `tokio`, `rustls`, `openidconnect`, `saml2`, `moka`, `serde_json`, `reqwest`, `jsonwebtoken`, `tokio-tungstenite`.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-federation-shim` | 3 | Rust `axum` HTTP reverse proxy + WS-Trust bridge + JWKS rollover + SAML replay detection + relay-state storage; Keycloak sidecar; ~5K lines | ADR-038, ADR-039, ADR-040, ADR-041, ADR-100, ADR-102, ADR-103 |
| `adrian-claims-engine` | 2 | AD FS claim-rule language (CRL) compatibility; translates CRL to Keycloak's native map/reducer or Rego plugin; ~2K lines | ADR-101, ADR-104 |
| `adrian-federation-shim` (cont.) | 3 | Per-RP clock skew policy, identity brokering HRD with framework host-identity context | ADR-040, ADR-104 |
| `adrian-federation-shim` (cont.) | 3 | AD RMS out-of-scope banner + AIP redirect for legacy RPs | ADR-042 |

## 3. Key types and traits

```rust
// crates/adrian-federation-shim/src/lib.rs

use axum::{Router, middleware::Next, response::Response};
use moka::future::Cache;
use jsonwebtoken::Algorithm;

pub struct FederationShim {
    keycloak_url: String,                    // http://keycloak:8080
    keycloak_admin_url: String,              // http://keycloak:9990
    http_client: reqwest::Client,
    relay_state_store: Arc<dyn RelayStateStore>,
    jwks_cache: Cache<String, JwkSet>,       // 5-min TTL per realm
    crl_engine: Arc<ClaimsEngine>,
    config: ShimConfig,
}

impl FederationShim {
    /// Main axum router. Every request flows through:
    ///   1. Pre-auth middleware (per-RP rate limit, mTLS check)
    ///   2. Reverse proxy to Keycloak (for OIDC/SAML native endpoints)
    ///   3. Post-auth middleware (header injection, claim enrichment)
    ///   4. WS-Trust bridge (for /adfs/services/trust/2005/windowstransport)
    pub fn router(&self) -> Router;
}

/// WS-Trust bridge: translates wsignin1.0 to OIDC code-flow
/// (per ADR-039). Keycloak 25+ dropped WS-Trust server support.
pub struct WsTrustBridge {
    keycloak_oidc_url: String,
    relay_state_store: Arc<dyn RelayStateStore>,
}

impl WsTrustBridge {
    pub async fn handle_wsignin(
        &self,
        request: WsigninRequest,
    ) -> Result<WsigninResponse, ShimError>;

    pub async fn handle_wsignout(
        &self,
        request: WsignoutRequest,
    ) -> Result<WsignoutResponse, ShimError>;
}

/// Relay state storage — opaque 256-bit token keyed in PostgreSQL.
/// Stateless shim means any instance can serve any relay-state lookup.
#[async_trait]
pub trait RelayStateStore: Send + Sync {
    async fn store(&self, state: &RelayState) -> Result<String, ShimError>;
    async fn retrieve(&self, token: &str) -> Result<RelayState, ShimError>;
    async fn delete(&self, token: &str) -> Result<(), ShimError>;
}

pub struct RelayState {
    pub relying_party: String,
    pub original_url: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub context: serde_json::Value,           // per-RP context
}
```

```rust
// crates/adrian-claims-engine/src/lib.rs (per ADR-101)

/// AD FS claim-rule language (CRL) compatibility. Translates CRL
/// to Keycloak's native map/reducer or Rego plugin. Supports
/// ~95% of common CRL constructs; complex rules require Rego opt-in.
pub struct ClaimsEngine {
    rego_engine: Option<regorus::Engine>,
    keycloak_mapper_api: KeycloakMapperApi,
}

impl ClaimsEngine {
    /// Compile CRL to a Keycloak protocol-mapper configuration.
    pub fn compile_to_keycloak_mapper(
        &self,
        crl: &ClaimRuleList,
    ) -> Result<MapperConfig, ClaimError>;

    /// Compile CRL to a Rego policy (opt-in for advanced rules).
    pub fn compile_to_rego(
        &self,
        crl: &ClaimRuleList,
    ) -> Result<String, ClaimError>;

    /// Evaluate claims at runtime using either mapper or Rego.
    pub async fn evaluate(
        &self,
        principal: &Principal,
        rp_id: &str,
    ) -> Result<Vec<Claim>, ClaimError>;
}

#[derive(Clone, Debug)]
pub struct Claim {
    pub claim_type: String,                   // e.g. "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    pub value: String,
    pub issuer: String,
}

/// Subset of AD FS CRL supported (per ADR-101):
///   => issue(Type = "email", Value = c.Value);
///   => issue(Type = "role", Value = RegExReplace(c.Value, "DOMAIN\\", ""));
///   exists([issuer == "AD AUTHORITY"]) => issue(Type = "authmethod", Value = "windows");
///   NOT exists([Type == "group", Value == "Admins"]) => issue(Type = "deny", Value = "true");
pub struct ClaimRuleList { pub rules: Vec<ClaimRule> }
pub struct ClaimRule {
    pub condition: Option<ClaimCondition>,    // None = unconditional
    pub action: ClaimAction,
}
pub enum ClaimAction { Issue(IssueStmt), Add(AddStmt) }
```

```rust
// crates/adrian-federation-shim/src/jwks.rs (per ADR-038)

/// JWKS rollover with 15-day overlap + webhook notification.
/// RPs subscribed to webhook get POST {oldKid, newKid, rolloverAt}
/// 7 days before rollover completes.
pub struct JwksRolloverManager {
    keycloak_admin: KeycloakAdmin,
    webhook_subscribers: Vec<WebhookEntry>,
    rollover_interval: Duration,              // 90 days default
    overlap_duration: Duration,               // 15 days per ADR-038
}

impl JwksRolloverManager {
    pub async fn schedule_rollover(&self, realm: &str) -> Result<(), ShimError>;
    pub async fn notify_subscribers(&self, event: RolloverEvent) -> Result<(), ShimError>;
    pub async fn verify_rollover(&self, realm: &str) -> Result<(), ShimError>;
}
```

```rust
// crates/adrian-federation-shim/src/saml_replay.rs (per ADR-040)

/// SAML replay detection — 60-minute window per-RP.
/// Each assertion ID is stored with timestamp; assertions older
/// than 60 minutes are pruned. Per-RP clock skew policy adjusts
/// the notBefore/notOnOrAfter tolerance.
pub struct SamlReplayCache {
    seen_assertions: Cache<String, SystemTime>,    // 60-min TTL
    per_rp_clock_skew: DashMap<String, Duration>,
}
```

## 4. Data model

```
PostgreSQL schema (Keycloak's own database, plus framework additions):

  -- Keycloak-managed tables (standard Keycloak 26+ schema):
  --   REALM, CLIENT, CLIENT_ATTRIBUTES, CLIENT_PROTOCOL_MAPPER,
  --   USER_ENTITY, FEDERATION_IDENTITY, IDENTITY_PROVIDER,
  --   USER_SESSION, CLIENT_SESSION, etc.

  -- Framework additions:
  CREATE TABLE adrian_relay_state (                -- per ADR-039, ADR-102
    token CHAR(64) PRIMARY KEY,                   -- 256-bit hex-encoded token
    relying_party TEXT NOT NULL,
    original_url TEXT NOT NULL,
    context JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT expires_check CHECK (expires_at > created_at)
  );
  CREATE INDEX idx_adrian_relay_state_expires ON adrian_relay_state(expires_at);

  CREATE TABLE adrian_saml_replay (                -- per ADR-040
    assertion_id TEXT NOT NULL,
    relying_party TEXT NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (assertion_id, relying_party)
  );
  CREATE INDEX idx_adrian_saml_replay_seen ON adrian_saml_replay(seen_at);

  CREATE TABLE adrian_jwks_rollover (              -- per ADR-038
    realm TEXT NOT NULL,
    rollover_id UUID PRIMARY KEY,
    old_kid TEXT NOT NULL,
    new_kid TEXT NOT NULL,
    scheduled_at TIMESTAMPTZ NOT NULL,
    overlap_ends_at TIMESTAMPTZ NOT NULL,
    webhook_notified BOOLEAN NOT NULL DEFAULT FALSE
  );

  CREATE TABLE adrian_claim_rules (                -- per ADR-101
    realm TEXT NOT NULL,
    relying_party TEXT NOT NULL,
    crl_text TEXT NOT NULL,                       -- original AD FS claim-rule language
    mapper_config JSONB,                          -- compiled to Keycloak mapper
    rego_policy TEXT,                             -- compiled to Rego (opt-in)
    PRIMARY KEY (realm, relying_party)
  );

  CREATE TABLE adrian_webhook_subscribers (        -- per ADR-038
    realm TEXT NOT NULL,
    relying_party TEXT NOT NULL,
    webhook_url TEXT NOT NULL,
    secret TEXT NOT NULL,                         -- HMAC secret for signing webhook payloads
    events TEXT[] NOT NULL,                       -- ['jwks_rollover', 'cert_expiring']
    PRIMARY KEY (realm, relying_party, webhook_url)
  );

FDB cross-references (per ADR-073, subspace 0x08 for audit):
  (0x08, ts, event_id)
    → audit events for SSO logon, SAML response, OIDC token issue, etc.

WS-Trust state machine (per ADR-039):
  State 1: RP POSTs wsignin1.0 to /adfs/services/trust/2005/windowstransport
  State 2: Shim extracts RP identity, creates relay_state in PostgreSQL
  State 3: Shim redirects user to Keycloak /protocol/openid-connect/auth
           with state=relay_state_token
  State 4: User authenticates via Keycloak (Kerberos, password, MFA)
  State 5: Keycloak redirects to shim /oauth2/callback with code
  State 6: Shim exchanges code for tokens at Keycloak token endpoint
  State 7: Shim retrieves relay_state from PostgreSQL
  State 8: Shim constructs SAML assertion (signed by Keycloak IdP signing key)
  State 9: Shim POSTs SAML response back to RP's AssertionConsumerServiceURL
  State 10: PostgreSQL deletes relay_state (one-shot)

Per-RP clock skew policy (per ADR-040):
  Default: ±5 minutes for SAML notBefore/notOnOrAfter
  Per-RP override: stored in adrian_relying_party_config table:
    rp_id | clock_skew_secs | replay_window_secs | strict_oidc
    -------+-----------------+--------------------+------------
    sharepoint2019 | 300 | 3600 | false (resource= compat)
    office365 | 60 | 3600 | true
    custom-wif-app | 600 | 7200 | false
```

## 5. Protocol surface

```
Endpoints exposed by the framework Federation Gateway:

OIDC endpoints (served by Keycloak, proxied through shim):
  GET  /auth/realms/{realm}/.well-known/openid-configuration
  GET  /auth/realms/{realm}/protocol/openid-connect/auth
  POST /auth/realms/{realm}/protocol/openid-connect/token
  GET  /auth/realms/{realm}/protocol/openid-connect/userinfo
  GET  /auth/realms/{realm}/protocol/openid-connect/certs    (JWKS)
  POST /auth/realms/{realm}/protocol/openid-connect/logout
  GET  /auth/realms/{realm}/protocol/openid-connect/login-status-iframe.html

SAML 2.0 endpoints (served by Keycloak, proxied through shim):
  POST /auth/realms/{realm}/protocol/saml                    (SSO redirect)
  GET  /auth/realms/{realm}/protocol/saml                    (SSO redirect)
  POST /auth/realms/{realm}/protocol/saml/logout
  GET  /auth/realms/{realm}/protocol/saml/descriptor         (metadata)

WS-Trust endpoints (served by shim, per ADR-039):
  POST /adfs/services/trust/2005/windowstransport           (wsignin1.0)
  POST /adfs/services/trust/13/windowstransport
  POST /adfs/services/trust/mex                             (metadata exchange)
  POST /adfs/ls/                                            (legacy AD FS path compat)

WS-Federation endpoints (served by shim):
  GET  /adfs/ls/?wa=wsignin1.0&wtrealm=<rp>&wreply=<url>   (signin)
  GET  /adfs/ls/?wa=wsignout1.0&wtrealm=<rp>               (signout)
  GET  /adfs/federationmetadata/2007-06/federationmetadata.xml

Webhook endpoints (per ADR-038):
  POST {rp_webhook_url}                                     (JWKS rollover notification)
  Payload: { "event": "jwks_rollover", "realm": "...", "oldKid": "...",
             "newKid": "...", "overlapEndsAt": "2026-09-13T..." }
  Signed with HMAC-SHA256 using subscriber's secret

HRD endpoints (per ADR-104):
  GET  /auth/realms/{realm}/adrian/hrd?returnUrl=<url>
  Returns HTML with identity-broker options; framework host-identity
  context (Kerberos, machine cert) auto-selects for framework-enrolled clients

Management API (per ADR-101, AD FS management-plane compat):
  POST /api/v1/realms/{realm}/relying-parties              (Set-AdfsRelyingPartyTrust equivalent)
  GET  /api/v1/realms/{realm}/relying-parties
  PUT  /api/v1/realms/{realm}/relying-parties/{rp_id}
  DELETE /api/v1/realms/{realm}/relying-parties/{rp_id}
  POST /api/v1/realms/{realm}/claim-rules                  (Set-AdfsClaimRule equivalent)
  GET  /api/v1/realms/{realm}/claim-rules/{rp_id}
  POST /api/v1/realms/{realm}/jwks/rollover                (operator-triggered)
```

## 6. Configuration

```toml
# /etc/adrian/federation-shim.toml — Federation shim configuration

[shim]
listen_addr            = "0.0.0.0:8443"
tls_cert_file          = "/etc/adrian/federation.crt"
tls_key_file           = "/etc/adrian/federation.key"
tls_min_version        = "1.2"
keycloak_url           = "http://keycloak-svc:8080"
keycloak_admin_url     = "http://keycloak-svc:9990"
keycloak_admin_user    = "adrian-admin"
keycloak_admin_password_file = "/etc/adrian/keycloak-admin.pw"
postgres_url           = "postgres://federation@db-1:5432/keycloak"
max_connections        = 4096
request_timeout_secs   = 30

[cache]
jwks_ttl_secs          = 300                        # 5 min per ADR-104
keycloak_realm_ttl_secs = 300
keycloak_client_ttl_secs = 300
max_cache_size         = 10000                      # moka LRU

[jwks_rollover]                        # ADR-038
rollover_interval_days = 90
overlap_duration_days  = 15                          # per ADR-038
webhook_notification_lead_days = 7
webhook_retry_max       = 5

[saml_replay]                          # ADR-040
window_secs             = 3600                       # 60 minutes
prune_interval_secs     = 300
per_rp_clock_skew_secs  = 300                        # default; per-RP override in DB

[oidc]                                 # ADR-041
strict_default          = true                       # OIDC default
resource_compat_opt_in  = false                      # per-RP opt-in
issue_refresh_token     = true
refresh_token_max_age_secs = 86400

[ws_trust_bridge]                      # ADR-039
enabled                 = true
mex_endpoint_enabled    = true
legacy_adfs_ls_path     = true                       # /adfs/ls/ compat

[hrd]                                  # ADR-104
enabled                 = true
framework_host_auto_select = true                    # Kerberos / machine cert

[claims_engine]                        # ADR-101
default_backend         = "keycloak-mapper"          # or "rego"
rego_opt_in             = true
crl_strict_mode         = true                       # fail on unsupported CRL constructs

[ad_interop]                           # ADR-100, ADR-103
stateful_set_mode       = true
infinispan_owners_sessions = 2
infinispan_owners_auth_sessions = 2
no_primary_secondary    = true                       # ADR-103
synchronous_commit      = "on"                       # PostgreSQL

[rms]                                  # ADR-042
out_of_scope_banner     = true
aip_redirect_url        = "https://aip.microsoft.com/"

[audit]
otel_endpoint           = "http://otel-collector:4317"
emit_sso_logon          = true
emit_saml_response      = true
emit_oidc_token_issue   = true
emit_wsignin            = true
mitre_attack_mapping    = true
```

## 7. Error handling

```rust
// crates/adrian-federation-shim/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum ShimError {
    #[error("Keycloak unreachable: {0}")]
    KeycloakUnreachable(String),
    #[error("Keycloak returned non-2xx: status={status} body={body}")]
    KeycloakError { status: u16, body: String },
    #[error("relay state {0} not found or expired")]
    RelayStateNotFound(String),
    #[error("relay state expired")]
    RelayStateExpired,
    #[error("SAML assertion replay detected: assertion_id={0}")]
    SamlReplay(String),
    #[error("SAML assertion expired: notOnOrAfter={0}")]
    SamlExpired(SystemTime),
    #[error("SAML clock skew exceeded: skew={skew}, tolerance={tolerance}")]
    SamlClockSkew { skew: Duration, tolerance: Duration },
    #[error("WS-Trust request malformed: {0}")]
    WsTrustMalformed(String),
    #[error("OIDC strict mode: client did not send resource= parameter")]
    OidcStrictModeMissingResource,
    #[error("JWKS not found for realm {0}")]
    JwksNotFound(String),
    #[error("JWKS rollover failed: {0}")]
    JwksRolloverFailed(String),
    #[error("PostgreSQL: {0}")]
    Db(#[from] sqlx::Error),
    #[error("claims engine: {0}")]
    Claims(#[from] ClaimError),
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
}

// crates/adrian-claims-engine/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("CRL parse error: {0}")]
    CrlParse(String),
    #[error("unsupported CRL construct: {0}")]
    UnsupportedConstruct(String),
    #[error("CRL refers to unknown claim type: {0}")]
    UnknownClaimType(String),
    #[error("Rego compile failed: {0}")]
    RegoCompile(String),
    #[error("Rego eval failed: {0}")]
    RegoEval(String),
    #[error("Keycloak mapper API error: {0}")]
    KeycloakMapper(String),
}
```

**Error propagation.** HTTP errors map to standard HTTP status codes: Keycloak upstream errors → 502 Bad Gateway, relay state missing → 400 Bad Request, SAML replay → 401 Unauthorized, OIDC strict mode missing resource → 400 Bad Request with RFC 8555-style problem document. WS-Trust errors return SOAP faults with the appropriate `wst:FailedAuthentication` or `wst:InvalidRequest` codes (per WS-Trust 1.3 spec). All SSO failures emit OTel audit events with MITRE ATT&CK mapping (`T1078 Valid Accounts`, `T1606 Forge Web Credentials`).

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - JWKS rollover scheduling + webhook notification
    - RelayState store+retrieve+delete round-trips
    - SAML replay cache: insert + lookup + prune
    - Per-RP clock skew policy lookup
    - WS-Trust wsignin1.0 parsing (XML)
    - WS-Trust SAML assertion construction (signed)
    - OIDC code-flow exchange
    - Claims engine: CRL parsing (50 sample rules)
    - Claims engine: Keycloak mapper config generation
    - Claims engine: Rego policy generation
    - mTLS client cert verification
    - Moka cache TTL behavior

Integration tests — tests/integration/, real Keycloak + PostgreSQL + tokio
  Coverage:
    - End-to-end OIDC code-flow against Keycloak
    - End-to-end SAML 2.0 redirect binding against Keycloak
    - WS-Trust wsignin1.0 → OIDC → SAML assertion full flow
    - JWKS rollover: old kid honored + new kid honored during overlap
    - Webhook notification sent to mock subscriber
    - Relay state lifecycle (create, retrieve, delete, expire)
    - SAML replay detection: same assertion_id rejected second time
    - Claims engine: CRL → Keycloak mapper applied at runtime
    - HRD: framework host with Kerberos TGT auto-selects realm

Interop tests — tests/interop/
  Matrix:
    - Windows Server 2022 AD FS migration tools against framework
      (verify claim-rule translation produces equivalent claims)
    - SharePoint 2019 against framework WS-Trust bridge (wsignin1.0)
    - Office 365 desktop client WS-Trust against framework
    - Custom WIF (.NET) app against framework WS-Fed
    - SAML SPs: Salesforce, Workday, ServiceNow, Tableau
    - OIDC RPs: Grafana, GitLab, Vault, Jenkins
    - Keycloak 26+ raw (no shim) for protocol parity baseline
    - Apache mod_auth_openidc against framework OIDC

Property-based tests — proptest
  Parsers tested:
    - SAML 2.0 assertion round-trips
    - OIDC JWT round-trips
    - WS-Trust XML round-trips
    - CRL parser round-trips
  Corpus: 50+ property tests across federation crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-100: Keycloak StatefulSet with PostgreSQL + Rust shim sidecar
  - ADR-103: no primary/secondary, Infinispan distributed caches
  - ADR-038: JWKS rollover with 15-day overlap + webhook
  - ADR-041: strict OIDC by default
  - SAML 2.0 + OIDC endpoints (native Keycloak, proxied through shim)
  - ADR-101: basic AD FS claim-rule translation (Keycloak mapper backend)
  - Per-RP relay state storage

v1 (Phase 2):
  - ADR-039: full WS-Trust-to-OIDC bridge for legacy RPs (SharePoint,
             Office, WIF apps)
  - ADR-040: SAML replay detection + per-RP clock skew policy
  - ADR-101: full claim-rule compatibility (CRL → mapper or Rego)
  - ADR-104: identity brokering + HRD with framework host-identity
  - ADR-102: shim as WAP replacement (perimeter auth, header injection)
  - ADR-041: resource= compat opt-in per RP
  - ADR-042: AD RMS out-of-scope banner + AIP redirect

v2 (Phase 3):
  - Rego-based claims engine opt-in for advanced rules
  - Multi-region Keycloak clustering with cross-site Infinispan
  - AD FS management-plane compat (`Set-AdfsRelyingPartyTrust` CLI)
  - Predictive JWKS rollover based on RP coverage telemetry
  - SAML 2.0 ECP profile for non-browser clients
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `axum` | 0.7 | HTTP reverse proxy + middleware |
| `tokio` | 1 | Async runtime |
| `rustls` | 0.23 | TLS termination + mTLS client cert |
| `openidconnect` | 3.3 | OIDC client library (for talking to Keycloak) |
| `saml2` | 0.6 | SAML 2.0 assertion construction + signing |
| `moka` | 0.12 | LRU cache for JWKS, realm, client configs |
| `serde_json` | 1 | JSON serialization for relay state |
| `reqwest` | 0.12 | HTTP client for Keycloak + webhook |
| `jsonwebtoken` | 9 | JWT verification (Keycloak tokens) |
| `tokio-tungstenite` | 0.21 | WebSocket for HRD + keycloak admin events |
| `quick-xml` | 0.31 | WS-Trust XML parsing |
| `regorus` | 0.2 | Rego engine (opt-in claims engine backend) |
| `sqlx` | 0.7 | PostgreSQL client |
| `ring` | 0.17 | Crypto for HMAC webhook signatures |
| `sha2` | 0.10 | SHA-256 for relay state tokens |
| `thiserror` | 1 | Error enums |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit events |
| `prometheus` | 0.13 | Metrics |
| `proptest` | 1 | Property-based tests |
| `uuid` | 1.10 | UUIDs for relay state, rollover IDs |

## 11. References

- ADRs: [ADR-038](../adr/ADR-038-jwks-endpoint-webhook-rollover.md), [ADR-039](../adr/ADR-039-oidc-primary-wstrust-bridge.md), [ADR-040](../adr/ADR-040-saml-replay-clock-skew-policy.md), [ADR-041](../adr/ADR-041-strict-oidc-default-resource-compat.md), [ADR-042](../adr/ADR-042-rms-out-of-scope-recommend-aip.md), [ADR-100](../adr/ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md), [ADR-101](../adr/ADR-101-adfs-claim-rule-language-compat.md), [ADR-102](../adr/ADR-102-rust-shim-wap-replacement.md), [ADR-103](../adr/ADR-103-keycloak-statefulset-no-primary-secondary.md), [ADR-104](../adr/ADR-104-keycloak-identity-brokering-hrd.md)
- Workshop decisions: [Decision 9 — Federation Layer](../workshop/decision-09-federation-layer.md)
- KB files: [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md), [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md), [docs/06-federation-sso/02-saml-ws-fed.md](../docs/06-federation-sso/02-saml-ws-fed.md), [docs/06-federation-sso/03-claims-rules.md](../docs/06-federation-sso/03-claims-rules.md), [docs/06-federation-sso/04-oidc-oauth.md](../docs/06-federation-sso/04-oidc-oauth.md)
- RFCs: RFC 6749 (OAuth 2.0), RFC 7519 (JWT), RFC 8414 (OAuth Authorization Server Metadata), RFC 8252 (OAuth Native Apps), RFC 7515 (JWS), RFC 7517 (JWK), RFC 7662 (OAuth Token Introspection), RFC 7516 (JWE), OASIS SAML 2.0 (Assertions, Protocol, Bindings, Profiles, Metadata), WS-Trust 1.3 (OASIS Standard)
- MS-* specs: MS-ADFS (Active Directory Federation Services), MS-ADFSPIP (AD FS Proxy Integration Protocol)
