---
title: "ADR-100: Replace AD FS farm (WID/SQL + WAP) with Keycloak StatefulSet + Rust shim sidecar"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-068
severity: high
unblocked_by: Workshop Decision 9
tags: [adr, federation-gateway, adfs, keycloak, wid, sql, wap, statefulset, rust-shim]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../workshop/decision-09-federation-layer.md
  - ../docs/01-ad-core/03-ad-fs-federation.md
  - ../docs/06-federation-sso/01-adfs-architecture.md
  - ./ADR-038-jwks-endpoint-webhook-rollover.md
  - ./ADR-039-oidc-primary-wstrust-bridge.md
  - ./ADR-058-container-native-dcs-operator.md
  - ./ADR-059-pitr-backup-dr-runbooks.md
last_updated: 2026-08-14
---

# ADR-100: Replace AD FS farm (WID/SQL + WAP) with Keycloak StatefulSet + Rust shim sidecar

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 9](../workshop/decision-09-federation-layer.md) (Federation layer: wrap Keycloak with Rust AD-claim-rules shim). This ADR operationalises Decision 9's deployment-topology specification against the PC-068 problem surface: AD FS's operationally heavy WID/SQL config DB + WAP reverse-proxy model, which the framework replaces with a single Keycloak StatefulSet and a Rust sidecar shim.

## Context

AD FS ships as a four-component stack on every production deployment, per [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md):

1. **`Microsoft.IdentityServer.ServiceHost.exe`** — a WCF service host running as a domain service account with the SPN `HOST/<adfs-svc-fqdn>`. The service host reads configuration from one of two backends.
2. **WID** (Windows Internal Database) — the default config store, an embedded SQL Server Express instance accessible only via the named pipe `\\.\pipe\MICROSOFT##WID\tsql\query` with database file `microsoft.identityserver.mdf` at `%SystemRoot%\Windows\WID\Data\`. WID enforces a single-primary topology: one node accepts writes, up to four secondaries pull via `Microsoft.IdentityServer.PolicyModel.dll!PolicyStore.GetSetUpdate` on a 5-minute sync interval, with a hard 5-node ceiling per farm.
3. **SQL farm** — for deployments exceeding the WID 5-node ceiling, the config DB moves to a SQL Server instance (`AdfsConfiguration` database, `Integrated Security=SSPI` connection string), pushing the HA burden to SQL Server (Always On Availability Groups, synchronous-commit replicas, listener FQDN). This adds SQL Server licensing, SQL HA operations, and a second database team to the federation service's blast radius.
4. **WAP** (`WAPService.exe` under `svchost -k WAPServiceSvchost`) — the perimeter reverse proxy. Per [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md), WAP establishes trust with AD FS via the MS-ADFSPIP RPC interface (UUID `e9396806-0e29-4660-b661-f6345c4bcd36`) at install time: `EstablishProxyTrust` issues a client cert to WAP stored in `LocalMachine\My` with subject `ADFS Proxy Trust - <WAP-Hostname>`. Subsequent calls (`GetConfiguration`, `GetWebProxyToken`, `StoreRelayState`, `RetrieveRelayState`) use that cert for mTLS on the RPC channel. WAP is Windows-only — it depends on `HTTP.SYS`, MS-ADFSPIP, and AD FS-specific RPC.

The operationally heavy reality: a "production" AD FS deployment is N AD FS nodes + N WAP nodes in the DMZ + a WID/SQL backend + HSM or local cert store for token-signing keys + an AD DC for the AD FS service account + DNS records for the AD FS service FQDN. Per the catalog's impact analysis in [PC-068](../catalog/06-federation-gateway.md), this is operationally heavy for small and medium orgs that just need SSO to a handful of SaaS apps. WID's 5-node limit forces SQL farm for larger deployments, adding SQL HA complexity. WAP's Windows-only constraint forces a Windows Server footprint in the DMZ even when the rest of the org has migrated to Linux.

The framework's constraints (from [PC-068](../catalog/06-federation-gateway.md)): must support SAML 2.0 (OASIS), OIDC (RFC 6749/8252/7636), OAuth2; must support AD as a claims provider (LDAP or Kerberos-constrained delegation); for AD FS interop, must expose `/FederationMetadata/2007-06/FederationMetadata.xml` and accept existing RPT configurations. The framework must do all of this without the four-component AD FS topology.

## Decision

The framework's Federation Gateway is **Keycloak 25+ (Quarkus distribution) running as a StatefulSet in Kubernetes, with the Rust `adrian-federation-shim` deployed as a sidecar in the same Pod**. Keycloak replaces the AD FS service host (`Microsoft.IdentityServer.ServiceHost.exe`) and the WID/SQL config DB; the Rust shim replaces WAP as the perimeter reverse proxy and adds the AD-claim-rule translation layer. There is no WID, no SQL Server farm, no WAP, and no MS-ADFSPIP.

### Concrete specification

1. **Deployment topology.** The Federation Gateway is one Kubernetes StatefulSet (per [ADR-058](./ADR-058-container-native-dcs-operator.md)) with two containers in each Pod:
   - **`adrian-keycloak`** (main container) — the upstream Keycloak Quarkus distribution, running on Java 21+, listening on `https://127.0.0.1:8443` (loopback only — never exposed outside the Pod). The container image is `quay.io/keycloak/keycloak:25.0` extended with the framework's theme JAR and event-listener SPI JAR (both built from source via Maven). Keycloak uses its bundled Quarkus HTTP server; no reverse proxy in front of Keycloak within the Pod.
   - **`adrian-federation-shim`** (sidecar container) — the Rust shim (`tokio` + `axum`) listening on `https://0.0.0.0:443` (exposed via the Service). The shim reverse-proxies to `adrian-keycloak:8443` over loopback mTLS, intercepts OIDC `/token` and SAML `/saml/sso` responses for claim-rule transformation, intercepts admin API calls for trust-pipeline enforcement, and exposes the WS-Trust bridge (per [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md)).
   - **`adrian-postgresql`** (separate StatefulSet, same namespace) — a PostgreSQL 16 instance for Keycloak's realm/client/session state. PostgreSQL is the single stateful component of the Federation Gateway; it is the operational equivalent of AD FS's WID/SQL config DB, with one crucial difference: PostgreSQL's synchronous replication (`synchronous_commit = on`, `synchronous_standby_names = ANY 1 (*)`) provides multi-primary-equivalent HA without the WID single-primary ceiling or the SQL Server licensing burden.

2. **No WID, no SQL Server.** The framework does not ship, embed, or depend on the Windows Internal Database or Microsoft SQL Server. PostgreSQL is the only config-DB backend Keycloak uses; the framework's Helm chart deploys PostgreSQL (or accepts an externally-managed PostgreSQL connection string for customers who prefer Cloud SQL / RDS / Aurora). The framework's backup/restore coverage (per [ADR-059](./ADR-059-pitr-backup-dr-runbooks.md)) extends to PostgreSQL via `pgBackRest` point-in-time recovery.

3. **No WAP, no MS-ADFSPIP.** The Rust shim is the perimeter reverse proxy. The shim runs on Linux, Windows, or macOS — there is no Windows-Server-in-DMZ requirement. The shim does not implement MS-ADFSPIP; the WAP-proxy-trust cert flow (`EstablishProxyTrust`, `GetWebProxyToken`) is replaced by mTLS between the shim and Keycloak within the Pod (the shim's client cert is issued by the framework's CA per Workshop Decision 8, with the cert rotated every 90 days per ADR-038). The shim's perimeter-auth functions (pre-auth, relay-state storage, header injection) are implemented natively in Rust; relay state is stored in PostgreSQL (`adrian_relay_state` table keyed by an opaque 256-bit token).

4. **Stateless shim, stateful Keycloak.** The Rust shim is stateless — all per-realm, per-client, per-rule configuration lives in Keycloak's PostgreSQL, and the shim loads it on demand with a 5-minute `moka` LRU cache (per Decision 9 §10). This means the shim can be horizontally scaled independently of Keycloak; in a multi-replica StatefulSet, any shim instance can serve any request. Keycloak itself uses its built-in clustering (Infinispan distributed caches) for session state, with cache owners=`2` for session and `2` for authentication sessions — providing HA without an external cache tier.

5. **Single-FQDN exposure.** The Federation Gateway is exposed on a single FQDN (`idp.<domain>`) on port 443. There is no separate WAP FQDN. The Service is a `ClusterIP` Service fronted by an ingress controller (nginx, Traefik, or the cloud-provider ingress) that terminates TLS using a cert from the framework's CA. The ingress routes `/oauth2/*`, `/saml/*`, `/trust/*`, `/metadata`, `/.well-known/*`, `/realms/*`, `/resources/*`, `/admin/*` to the shim; the shim routes everything to Keycloak over loopback except for the paths it intercepts.

6. **AD FS migration path.** The framework ships `adrian-migrate from-adfs` (Rust CLI, per Decision 9 §5) that reads AD FS configuration via PowerShell over WinRM (`Get-AdfsRelyingPartyTrust`, `Get-AdfsClaimsProviderTrust`, `Get-AdfsApplicationGroup`, `Get-AdfsClaimDescription`) and emits two artifacts: `realm-export.json` (Keycloak import) and `claim-rules.yaml` (shim config). The CLI translates AD FS Relying Party Trusts to Keycloak clients (SAML for claims-aware RPs, OIDC for Application Group web APIs), Claim Descriptions to Keycloak claim definitions, Issuance Transform Rules to the shim's claim-rule configuration, and Application Groups to sets of Keycloak clients. Operators review, commit to Git (per [ADR-031](./ADR-031-git-backed-policy-history.md)), and apply via `adrian-fed apply --realm <file> --rules <file>`.

7. **Sizing guidance.** The framework's default sizing targets the small-to-medium enterprise that PC-068 identifies as underserved by AD FS: one Pod (2 vCPU, 4 GB RAM), one PostgreSQL instance (2 vCPU, 8 GB RAM), 50 GB SSD. This serves up to 50 RPs and 5,000 concurrent SSO sessions. For larger deployments, the StatefulSet scales to 3 Pods (3 × 2 vCPU, 3 × 4 GB RAM) and PostgreSQL moves to a 3-replica HA cluster; this configuration serves up to 500 RPs and 50,000 concurrent sessions. SQL-farm-equivalent scale is achieved without SQL Server.

8. **Observability.** The shim emits Prometheus metrics (`adrian_fed_proxy_requests_total{path,result}`, `adrian_fed_claims_evaluated_total{realm,client}`, `adrian_fed_directory_lookup_total{result}`, `adrian_fed_jwks_rotation_total`, `adrian_fed_keycloak_upstream_latency_seconds`), OpenTelemetry traces spanning the full request path (ingress → shim → Keycloak → directory), and audit logs per [ADR-060](./ADR-060-structured-audit-logs-otel.md). Keycloak's own metrics (`keycloak_metrics` SPI enabled) are scraped via the shim's `/internal/metrics/keycloak` proxy endpoint (mTLS-protected).

9. **Backup and DR.** Federation Gateway backup covers (a) PostgreSQL (via `pgBackRest` full + WAL streaming, 30-day retention per ADR-059), (b) the Git-backed `claim-rules.yaml` and `realm-export.json` (per ADR-031), (c) the HSM-resident token-signing key (escrowed per [ADR-053](./ADR-053-key-escrow-and-nbde.md)). DR runbook: restore PostgreSQL from `pgBackRest`, redeploy the Pod, restore the signing key from HSM escrow. RTO ≤ 1 hour, RPO ≤ 5 minutes (PostgreSQL WAL streaming).

## Rationale

AD FS's four-component topology exists because each component was the simplest available answer to a 2003-era question: where do we store config (SQL Server — Microsoft's flagship DB), how do we expose it to the DMZ (a separate Windows service that proxies via RPC), how do we make it HA (Windows Failover Cluster or SQL Always On). In 2026, each answer is wrong for a clean-slate framework: SQL Server is licensed-DB overhead for a config store that fits in PostgreSQL; WAP's MS-ADFSPIP is a Windows-only RPC protocol in a cross-platform world; Windows Failover Cluster is a Windows-only HA layer in a Kubernetes world. Keycloak's StatefulSet + sidecar-shim model answers each question with the modern primitive: PostgreSQL for config storage (one database, multi-master via synchronous replication, no licensing); Rust reverse proxy for DMZ exposure (cross-platform, no MS-ADFSPIP, native TLS); Kubernetes StatefulSet for HA (3 replicas, pod anti-affinity, rolling upgrades). The shim's 5-minute LRU cache for realm config means the shim's hot path has no PostgreSQL dependency; only first-request-per-realm pays the lookup cost. The framework chose Keycloak over re-implementing federation (Decision 9 ORQ-133 = NO) and over cloud-first (Decision 9 ORQ-134 = NO) because Keycloak is the de facto self-hosted enterprise federation engine. The fresh-Rust shim (~6K lines per Decision 9) is proportional to the framework's differentiation — the framework adds value via claim rules, directory integration, and migration tooling, not via re-implementing OIDC/SAML/OAuth2.

## Consequences

**Positive**. The framework eliminates the WID 5-node ceiling, the SQL Server licensing requirement, the WAP Windows-only constraint, and the MS-ADFSPIP RPC surface. The Federation Gateway's deployment topology is one StatefulSet + one PostgreSQL instance — operationally simpler than AD FS's four-component stack by an order of magnitude. The framework inherits Keycloak's mature protocol implementation (OIDC, SAML, OAuth2, JWKS rotation, multi-tenancy, identity brokering, session management) without re-implementation cost. The framework's customers inherit Keycloak's operator community (Red Hat, AWS) for free.

**Negative**. The Federation Gateway carries a JVM dependency (Java 21+, ~200 MB container image). The framework supports Keycloak LTS upgrades on the framework's release cadence — major upgrades (e.g., 25 → 26) may require shim updates. The shim's claim-rule coverage is ~95% of the AD FS rule-language surface (per Decision 9); the remaining 5% is dropped with `WARN` during migration, requiring manual rewrite. The framework does not expose Keycloak's admin UI — all admin operations go through `adrian-fed` CLI (this is positive for configuration discipline per ADR-031, but operators used to the Keycloak admin UI must learn the CLI).

**Neutral**. PostgreSQL replaces both WID and SQL Server as the config DB. Customers with existing SQL Server investment cannot reuse it for the Federation Gateway; they must deploy PostgreSQL (or use a managed PostgreSQL service). Customers with existing Keycloak experience find the framework's Federation Gateway familiar; customers without Keycloak experience face a learning curve.

**Implementation cost**. ~18 person-weeks for v1 (per Decision 9): shim (5 pw), claims-engine (3 pw, addressed in [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md)), WS-Trust bridge (3 pw), Keycloak client library (2 pw), AD FS migration CLI (3 pw), `adrian-fed` CLI (2 pw).

**Operational impact**. Federation Gateway operators manage one StatefulSet + one PostgreSQL instance via the framework's operator (`FederationGateway` CRD per ADR-058). Sizing is documented; scaling is horizontal (more Pod replicas) up to the PostgreSQL limit. Backup/DR is a documented runbook (per ADR-059). Keycloak upgrades follow the framework's LTS policy (current LTS + previous LTS for one year).

## Alternatives Considered

### Alternative A: Re-implement AD FS topology in Rust (fresh Rust federation engine, native config DB)

Build a fresh Rust federation service that implements OIDC, SAML, WS-Trust bridge, OAuth2 client management, JWKS rotation, multi-tenancy, identity brokering, and session management, backed by the framework's FoundationDB instance (per Workshop Decision 2). Rejected because (a) the engineering effort is conservatively 80+ person-weeks per Decision 9 (Keycloak is ~250K lines of Java accumulated over 12 years; a Rust re-implementation would require equivalent protocol coverage including SAML XML Signature Wrapping mitigations, OIDC RFC 9700 compliance, OAuth2 PKCE edge cases); (b) the federation protocol surface is mature and standardized — there is no architectural innovation to be had by re-implementing it, only engineering risk; (c) re-implementation would require tracking every RFC revision and security advisory for OIDC, SAML, and OAuth2 — a sustained maintenance burden that diverts effort from the framework's differentiating capabilities.

### Alternative B: Cloud-first (Entra ID as the federation engine)

Use Entra ID (Azure AD) as the federation engine. Customers federate to Entra ID instead of running a self-hosted federation service. Rejected because (a) Entra ID requires internet connectivity — incompatible with the framework's on-prem-first posture and with government/defense/regulated industries that require air-gapped operation; (b) Entra ID's per-tenant pricing (per-user, per-month) is incompatible with the framework's "self-host, no per-user licensing" value proposition; (c) Entra ID is itself a Microsoft product, and the framework is explicitly a Microsoft-AD-replacement; (d) Entra ID's protocol support is Microsoft-controlled. Entra ID remains a supported upstream IdP (per Decision 9 §6 and ADR-104), but it is not the engine.

### Alternative C: Wrap a different modern IdP (Authentik, Ory, Zitadel) with the Rust shim

Use a different Rust-native or Go-native modern IdP in place of Keycloak, with the same Rust shim architecture. Rejected because (a) Authentik (Python/Go) has a smaller operator community and partial SAML 2.0 spec compliance; (b) Ory (Go) is API-first and lacks a built-in admin UI (non-starter for enterprise operators); (c) Zitadel (Go) has a smaller community and fewer third-party integrations; (d) Keycloak is the de facto standard for self-hosted enterprise federation (Red Hat ships it in OpenShift, AWS documents it for EKS). The framework's customers are more likely to have prior Keycloak experience. The shim's protocol surface (User Federation SPI + admin API) is small enough that the IdP choice does not materially affect the shim's complexity.

### Alternative D: Preserve the AD FS four-component topology with framework-native components

Keep the WID/SQL + WAP model but replace each component with a framework-native equivalent: framework's FDB replaces WID/SQL, framework's Rust reverse proxy replaces WAP, framework's Rust federation engine replaces `Microsoft.IdentityServer.ServiceHost.exe`. Rejected because this is Alternative A with extra steps — it preserves an architectural pattern that exists only because of 2003-era constraints (separate Windows service for DMZ, SQL Server for config DB) without adding any benefit. The four-component separation creates operational complexity (multiple StatefulSets, multiple upgrade cycles, multiple failure modes) that the single-Pod Keycloak + shim model avoids.

## Open Questions

- Keycloak major upgrade cadence: should the framework support every Keycloak LTS (twice yearly) or only every other LTS (yearly)? Current decision: every LTS, with the previous LTS supported for one year after the new LTS ships.
- PostgreSQL deployment model: should the framework's Helm chart deploy PostgreSQL in-cluster by default, or require an external PostgreSQL connection string? Current decision: in-cluster by default (for simplicity); external supported via `federation.postgresql.external` Helm value (for customers who prefer managed PostgreSQL).
- Multi-region federation: should the framework support cross-region PostgreSQL replication for DR? Current decision: not in v1; multi-region federation is documented as a v1.1 feature.

## Cross-capability impact

- **Cert Service (Workshop Decision 8).** The shim's signing key is a cert issued by the framework's CA (enrolled via ACME with the `federation_signing` profile, stored in the HSM via PKCS#11, rotated every 90 days per ADR-038).
- **Core Directory.** The shim is the only federation component that talks to the directory; LDAP provides user lookup, group membership (via `memberOf` back-link per ADR-002), and attribute resolution. The shim caches results in `moka` to reduce directory load.
- **Operations (ADR-058).** The Federation Gateway is deployed as a StatefulSet (Keycloak + PostgreSQL) with the shim as a sidecar. The framework's operator manages the Federation Gateway lifecycle via a `FederationGateway` CRD.
- **Operations (ADR-059).** Federation Gateway backup covers PostgreSQL (pgBackRest), Git-backed config (ADR-031), and HSM-resident signing keys (ADR-053). DR runbook documented.
- **Migration (PC-124 AD FS-to-framework).** The `adrian-migrate from-adfs` CLI is the migration entry point for AD FS.
- **Federation Gateway (PC-069 — claims rule language).** Addressed in [ADR-101](./ADR-101-adfs-claim-rule-language-compat.md).
- **Federation Gateway (PC-073 — WAP replacement).** Addressed in [ADR-102](./ADR-102-rust-shim-wap-replacement.md).
- **Federation Gateway (PC-074 — farm consensus).** Addressed in [ADR-103](./ADR-103-keycloak-statefulset-no-primary-secondary.md).
- **Federation Gateway (PC-076 — home realm discovery).** Addressed in [ADR-104](./ADR-104-keycloak-identity-brokering-hrd.md).

## References

- [PC-068](../catalog/06-federation-gateway.md) — problem statement
- [Workshop Decision 9](../workshop/decision-09-federation-layer.md) — Federation layer: wrap Keycloak with Rust shim
- [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md) — AD FS process model, WID vs SQL config DB topology, WAP perimeter proxy, MS-ADFSPIP RPC UUID
- [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md) — Service account + SPN requirements, config DB tables (`ServiceSettings`, `RelyingPartyTrust`, `ClaimsProviderTrust`), WAP MS-ADFSPIP operations
- [ADR-038](./ADR-038-jwks-endpoint-webhook-rollover.md) — JWKS endpoint + webhook rollover
- [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md) — OIDC primary; WS-Trust bridge (provided by the shim)
- [ADR-058](./ADR-058-container-native-dcs-operator.md) — container-native deployment
- [ADR-059](./ADR-059-pitr-backup-dr-runbooks.md) — PITR backup DR runbooks
- [Keycloak Documentation](https://www.keycloak.org/documentation) — Keycloak server docs
- [Keycloak Clustering](https://www.keycloak.org/server/configuration-production) — Keycloak production deployment and clustering
- [PostgreSQL Synchronous Replication](https://www.postgresql.org/docs/16/warm-standby.html#SYNCHRONOUS-REPLICATION) — PostgreSQL synchronous replication for HA
