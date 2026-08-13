---
title: "ADR-081: Multi-Tenancy via Per-Tenant FDB Keyspaces with Hard Isolation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-022
severity: high
unblocked_by: Workshop Decision 2 (ORQ-011/012/013/014) and Workshop Decision 3 (ORQ-026/027)
tags: [adr, core-directory, multi-tenancy, foundationdb, keyspaces, per-tenant-isolation, krbgt-per-tenant]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-02-storage-engine.md
  - ../workshop/decision-03-identity-model.md
  - ../catalog/01-core-directory.md
  - ../docs/00-overview/03-domains-forests-trees.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ./ADR-073-storage-engine.md
last_updated: 2026-08-13
---

# ADR-081: Multi-Tenancy via Per-Tenant FDB Keyspaces with Hard Isolation

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-011/012/013/014 (storage) and ORQ-026/027 (identity model). It is now unblocked by [Workshop Decision 2 (FoundationDB Storage Engine)](../workshop/decision-02-storage-engine.md) and [Workshop Decision 3 (UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping)](../workshop/decision-03-identity-model.md).

## Context

AD has no native multi-tenancy. Each tenant needs either a separate forest (heavy — separate schema, separate KDC, separate GC, separate replication topology, separate admin team) or a separate OU within a shared forest (light — same KDC, same GC, same schema, same replication topology, no hard isolation between tenants). The OU-based approach has weak isolation: a Domain Admin in tenant A can read tenant B's user objects; a compromised KDC in tenant A issues tickets for tenant B's users; a schema extension by tenant A affects tenant B, per [PC-022](../catalog/01-core-directory.md#pc-022--multi-tenancy-is-not-native-to-ad-framework-should-decide-whether-to-support-it) and [docs/00-overview/03-domains-forests-trees.md](../docs/00-overview/03-domains-forests-trees.md).

Hard isolation requires: separate `krbtgt` keys per tenant (otherwise one tenant's admin can forge tickets for another tenant); separate GC per tenant (otherwise one tenant's admin can enumerate another tenant's users); separate schema extensions per tenant (otherwise one tenant's schema change affects another); separate audit logs per tenant (otherwise one tenant's admin can read another tenant's auth events); separate replication topology per tenant (otherwise a slow tenant blocks replication for all).

A framework should either (a) support per-tenant NCs with hard isolation, or (b) document why multi-tenancy is out of scope and recommend separate framework instances per tenant. Option (b) is simpler but operationally expensive at scale (one deployment per tenant × 1000 tenants = 1000 deployments). Option (a) is complex but matches cloud-native expectations (Kubernetes-style namespace isolation).

**Unblocking decisions.** [Workshop Decision 2](../workshop/decision-02-storage-engine.md) selected FoundationDB, whose keyspace-subspace model naturally supports per-tenant isolation — each tenant gets its own FDB subspace prefix. [Workshop Decision 3](../workshop/decision-03-identity-model.md) specifies multi-tenancy via per-tenant UUID namespaces — each tenant has its own UUIDv7 namespace prefix; SIDs remain forest-global but the mapping table enforces per-tenant visibility. This ADR translates both decisions into the concrete multi-tenancy implementation.

## Decision

The framework SHALL support multi-tenancy via per-tenant FDB keyspaces with hard isolation. Each tenant has its own FDB subspace prefix (`0x10 + tenant_id`), its own `krbtgt` key, its own schema extensions (per-tenant Schema NC projection), its own GC (per-tenant PAS filter), its own audit logs (per-tenant audit subspace), and its own replication topology (per-tenant Raft group in native mode; per-tenant DRSUAPI NCs in AD-interop mode). Tenant isolation is enforced at the FDB layer (per-tenant subspaces) and at the API layer (per-tenant authentication context).

**Concrete specification**:

- The framework SHALL support a configurable number of tenants per forest (default 1 = single-tenant; configurable up to 10,000 tenants for cloud-scale deployments). Each tenant has a unique `tenant_id` (UUIDv4) assigned at tenant creation.
- Each tenant SHALL have its own FDB subspace prefix. The subspace allocation is: `0x10 + tenant_id_bytes[0..14]` (the tenant_id is a 16-byte UUID; the subspace prefix is `0x10` followed by the tenant_id bytes). All tenant data (objects, linktable, sdtable, schemacache, utdvector, ridpool, tombstones, auditlog, identity_mapping) is stored under the tenant's subspace prefix. The framework's `DirectoryStore` trait (per Decision 2) is parameterised by `tenant_id` — every `begin_tx` call takes a `tenant_id` argument; the `FdbDirectoryStore` enforces per-tenant isolation at the FDB key-prefix level.
- The framework SHALL enforce per-tenant isolation at the API layer. Every LDAP bind, every REST API call, every gRPC call carries a tenant context (derived from the bind DN's tenant prefix or from a `X-Tenant-ID` HTTP header). The framework's authorisation layer (per ADR-066 AdminSDHolder declarative RBAC) rejects cross-tenant access — a request from tenant A's authenticated principal cannot read tenant B's data.
- Each tenant SHALL have its own `krbtgt` account and key. The KDC (per Decision 5) routes AS-REQ to the correct tenant's `krbtgt` based on the request's realm (each tenant has its own realm name `<tenant_id>.<forest-dns>`). Cross-tenant TGT referral (per ADR-013 cross-realm TGT referral) uses per-tenant trust keys.
- Each tenant SHALL have its own Schema NC projection. A schema extension by tenant A (adding an `attributeSchema` to tenant A's Schema NC) does not affect tenant B's Schema NC. The schema cache (per ADR-003) is per-tenant — each tenant has its own generation counter and `Arc<SchemaProjection>`. The `schemaModifyRequest` writes are routed to the correct tenant's Schema NC based on the bind DN's tenant prefix.
- Each tenant SHALL have its own GC. In native mode, the GC PAS filter (per ADR-072) is per-tenant — a GC query from tenant A returns only tenant A's objects. In AD-interop mode, per-tenant GC requires per-tenant PAS replicas (heavier storage cost; recommended only for tenants with significant cross-domain query volume).
- Each tenant SHALL have its own audit log (FDB subspace `0x08` per tenant). Audit log queries are per-tenant — tenant A's admin cannot read tenant B's audit events. The OpenTelemetry audit pipeline (per ADR-060) emits per-tenant events with the `tenant_id` attribute.
- Each tenant SHALL have its own replication topology in native mode (per-tenant Raft group). In AD-interop mode, per-tenant replication topology requires per-tenant NC heads (heavier replication cost; recommended only for tenants with significant write volume).
- The framework SHALL support per-tenant backup/restore. A tenant's data can be restored without affecting other tenants (FDB's per-keyspace backup/restore supports this). The `adrian-operator fdb backup --tenant <tenant_id> --destination s3://...` and `adrian-operator fdb restore --tenant <tenant_id> --from s3://...` commands enable per-tenant backup/restore.
- The framework SHALL expose a per-tenant admin role (`TenantAdmin`) that has full admin rights within the tenant but no rights to other tenants. There SHALL be no super-admin role that can see all tenants (per the constraint "no super-admin who can see all tenants"). The framework's deployment-admin role (managing the FDB cluster and the framework's own infrastructure) is separate from tenant-admin and does not have access to tenant data.
- The framework SHALL expose `adrian-tenant create --name <name>`, `adrian-tenant list`, `adrian-tenant show --id <tenant_id>`, and `adrian-tenant delete --id <tenant_id>` CLI for tenant management. Tenant creation allocates a new `tenant_id`, creates the tenant's FDB subspace, provisions the tenant's Schema NC (cloned from the forest's base schema), provisions the tenant's `krbtgt` account, and configures the tenant's audit log.
- For AD-interop mode, multi-tenancy is documented as out of scope (AD is single-tenant per forest). AD-interop deployments use single-tenant forests; multi-tenant deployments use native mode. The framework SHALL reject tenant-creation requests in AD-interop mode with `unwillingToPerform (53)`.
- For identity mapping (per Decision 3), the per-tenant UUID namespace prefix is the tenant's `tenant_id`. UUIDv7 generation for new principals in tenant A uses `tenant_id_A` as the context (per Decision 3's `Uuid::from_timestamp_and_context()` API). SIDs remain forest-global (the SID's domain component is the forest's domain SID); the RID component is unique per tenant (per-tenant RID pool in AD-interop mode; per-tenant local RID counter in native mode).
- Performance target: per-tenant operations (LDAP search, KDC AS-REQ, GC query) SHALL complete with ≤5% overhead vs single-tenant operations (the FDB subspace prefix adds ~16 bytes per key; range scans are O(range size) regardless of subspace count).

## Rationale

Multi-tenancy is a cloud-native requirement. SaaS-style AD offerings (Azure AD DS, Managed AD) need multi-tenancy; without it, each tenant requires a separate deployment — operationally expensive at scale (1000 tenants × 6 VMs per FDB cluster = 6000 VMs). On-prem enterprises with multiple business units (acquisitions, joint ventures, regulated subsidiaries) also need multi-tenancy. Without hard isolation, a single compromised admin or a single compromised DC compromises all tenants.

FoundationDB's subspace-prefix model is the natural substrate for per-tenant isolation. Each tenant gets its own subspace prefix; FDB's strict serializable transactions span subspaces (per-tenant transactions are atomic); FDB's range scans are O(range size) regardless of subspace count. Apple's iCloud FDB deployment uses a similar per-tenant-prefix model for hundreds of millions of tenants.

Decision 3's per-tenant UUID namespace prefix ensures UUID uniqueness across tenants (two principals in different tenants with the same name have different UUIDs because the UUIDv7 context includes the tenant_id). SIDs remain forest-global (the SID's domain component is the forest's domain SID) — this is required for AD-interop compatibility (in case the framework forest later needs to peer with an AD forest via trust). The RID component is unique per tenant (per-tenant RID pool prevents cross-tenant RID collision).

The "no super-admin" constraint is a hard security requirement — if a super-admin existed, a single compromise would compromise all tenants. The framework's deployment-admin role (managing the FDB cluster) is separate from tenant-admin and does not have access to tenant data (the deployment-admin can manage the FDB cluster but cannot read tenant subspaces — the framework's `FdbDirectoryStore` enforces per-tenant access control at the API layer).

External evidence: Microsoft Entra ID (Azure AD) uses per-tenant isolation (each customer is a tenant with its own data store). HashiCorp Consul uses per-namespace ACL isolation. CockroachDB uses per-database isolation. The pattern is industry-standard for cloud-native multi-tenant systems.

## Consequences

**Positive**: Hard isolation between tenants (a compromised admin in tenant A cannot access tenant B's data). Per-tenant `krbtgt` keys prevent cross-tenant ticket forgery. Per-tenant schema extensions prevent cross-tenant schema conflicts. Per-tenant audit logs prevent cross-tenant audit-log reading. Per-tenant backup/restore enables tenant-level disaster recovery. Cloud-scale deployments (1000+ tenants) are operationally feasible (one FDB cluster serves all tenants).

**Negative**: Per-tenant overhead — each tenant has its own Schema NC projection (~80 MB resident set), its own audit log, its own RID pool. For 1000 tenants, this is ~80 GB of resident set across the FDB cluster — manageable on modern hardware but non-trivial. Per-tenant `krbtgt` keys increase KDC key-management complexity (the KDC must track 1000+ keys).

**Neutral**: AD-interop deployments are single-tenant (AD is single-tenant per forest); multi-tenant deployments use native mode. The framework's documentation clearly distinguishes the two deployment models. The `adrian-tenant` CLI is the modern equivalent of Azure AD's `New-AzureADTenant`.

**Cost**: ~8 person-weeks for the per-tenant FDB keyspace infrastructure, the per-tenant Schema NC projection, the per-tenant KDC key management, the per-tenant audit log, the per-tenant replication topology, the per-tenant backup/restore, the tenant-admin role, and the `adrian-tenant` CLI.

**Operational impact**: Tenant management is `adrian-tenant` CLI. Tenant isolation is monitored via Prometheus/OTel (per-tenant query latency, per-tenant audit-log size, per-tenant RID pool usage). The `adrian-operator` (ADR-058) manages tenant lifecycle (create, delete, backup, restore).

## Alternatives Considered

### Alternative 1: Separate framework instances per tenant (no native multi-tenancy)

Maximum isolation (each tenant has its own FDB cluster, its own framework deployment, its own admin team). Simple implementation (no per-tenant logic in the framework). Operationally expensive at scale (1000 tenants × 6 VMs per FDB cluster = 6000 VMs). Rejected for cloud-scale deployments; documented as the recommended deployment for high-security on-prem deployments (e.g., regulated subsidiaries with strict air-gap requirements).

### Alternative 2: OU-based multi-tenancy (AD's model)

Each tenant is an OU within a shared forest. Light isolation (same KDC, same GC, same schema). Weak isolation — a Domain Admin in tenant A can read tenant B's user objects. Rejected: the framework's customers expect hard isolation (cloud-native expectation); the OU-based model does not meet the security requirement.

### Alternative 3: Hybrid — separate framework instances per tenant for hard isolation, with a federation layer (SAML/OIDC) for cross-tenant SSO

Each tenant has its own framework instance (hard isolation). Cross-tenant SSO uses the framework's Federation Gateway (per ADR for federation) with SAML or OIDC. The advantage is maximum isolation (no shared FDB cluster). The disadvantage is operational overhead (one FDB cluster per tenant) and the federation layer adds complexity. Rejected as the default; documented as a deployment option for high-security multi-tenant scenarios.

## Open Questions

- For per-tenant Schema NC projection, should the framework support schema sharing (multiple tenants sharing a base schema, with per-tenant extensions)? Default: yes — each tenant's Schema NC is initialised from the forest's base schema; per-tenant extensions are added on top. Confirm in implementation.
- For per-tenant `krbtgt` key management, should the framework use per-tenant HSM slots (per ADR-015 krbtgt HSM rotation) or a single HSM with per-tenant keys? Default: single HSM with per-tenant keys (the HSM's key-management API supports per-tenant key derivation). Confirm with HSM vendor.
- For 10,000-tenant cloud-scale deployments, is the per-tenant Schema NC projection overhead (~80 GB resident set) acceptable? Default: yes, on modern hardware (a 64-GB-RAM DC can host ~800 tenants; the framework's operator scales DCs based on tenant count). Confirm with customer-scale benchmark.

## Cross-capability impact

- **KDC**: KDC routes AS-REQ to the correct tenant's `krbtgt` based on the request's realm. KDC's PAC builder reads the principal's current SID and `sIDHistory` via the per-tenant identity mapping table. KDC's krbtgt rotation (per ADR-015) is per-tenant.
- **Auth Provider**: Auth Provider's token construction (S4U2Self, S4U2Proxy, RBCD) is per-tenant — a token for tenant A's principal cannot be used to access tenant B's resources.
- **Policy Engine**: GPO objects are per-tenant — tenant A's GPOs do not affect tenant B's hosts. Policy Engine's security filtering reads the principal's SID via the per-tenant identity mapping table.
- **Cert Service**: Certificate templates are per-tenant — tenant A's templates are not visible to tenant B. CA database (per ADR-034) is per-tenant (separate FDB subspace `0x09 + tenant_id`).
- **File Gateway**: File ACLs are per-tenant — tenant A's file shares are not visible to tenant B. The File Gateway's ACL evaluator consults the per-tenant identity mapping table.
- **Client SDK**: Client SDK's `getpwuid` and `getgrgid` queries are per-tenant (the SDK passes the tenant context via a thread-local or environment variable).
- **Operations**: Per-tenant monitoring (Prometheus/OTel metric: per-tenant query latency, audit-log size, RID pool usage). Per-tenant backup/restore. The `adrian-operator` (ADR-058) manages tenant lifecycle.
- **Migration**: AD-to-framework migration uses single-tenant forests (AD is single-tenant); multi-tenant framework deployments are greenfield or migrated from cloud-native identity providers (Azure AD, Okta).
- **Security**: PC-117 (DCSync) threat model — in native-mode multi-tenant deployments, DCSync is eliminated (no `EXOP_REPL_SECRETS`); in AD-interop single-tenant deployments, the AD DCSync attack surface is inherited. Per-tenant audit logs prevent cross-tenant audit-log reading.

## References

- [PC-022](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 2 — FoundationDB Storage Engine](../workshop/decision-02-storage-engine.md) — FDB keyspaces as substrate for per-tenant isolation
- [Workshop Decision 3 — UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping](../workshop/decision-03-identity-model.md) — per-tenant UUID namespaces; per-tenant identity mapping table
- [docs/00-overview/03-domains-forests-trees.md](../docs/00-overview/03-domains-forests-trees.md) — forest as the security boundary, OU-based weak isolation
- [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) — AD deployment models, multi-forest vs single-forest
- [FoundationDB — Subspaces](https://apple.github.io/foundationdb/developer-guide.html#subspaces) — FDB subspace-prefix model
- [FoundationDB — Layer-Status](https://apple.github.io/foundationdb/developer-guide.html) — FDB multi-tenant patterns
- [Microsoft Entra ID — Multi-Tenant](https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant) — cloud-native multi-tenant pattern
- [ADR-073: Storage Engine](./ADR-073-storage-engine.md) — FDB subspaces; `DirectoryStore` trait
- [ADR-072: Global Catalog Strategy](./ADR-072-global-catalog-strategy.md) — per-tenant GC
- [ADR-015: krbtgt HSM Rotation](./ADR-015-krbtgt-hsm-rotation.md) — per-tenant `krbtgt` keys
- [ADR-066: AdminSDHolder Declarative RBAC](./ADR-066-adminsdholder-declarative-rbac.md) — tenant-admin role
