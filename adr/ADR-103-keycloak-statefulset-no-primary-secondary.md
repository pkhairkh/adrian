---
title: "ADR-103: PostgreSQL multi-primary replaces AD FS WID primary-secondary farm topology"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-074
severity: medium
unblocked_by: Workshop Decision 9
tags: [adr, federation-gateway, adfs, wid, sql-farm, postgresql, raft, multi-primary, sync-replication]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../workshop/decision-09-federation-layer.md
  - ../docs/01-ad-core/03-ad-fs-federation.md
  - ../docs/06-federation-sso/01-adfs-architecture.md
  - ./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md
  - ./ADR-058-container-native-dcs-operator.md
  - ./ADR-059-pitr-backup-dr-runbooks.md
last_updated: 2026-08-14
---

# ADR-103: PostgreSQL multi-primary replaces AD FS WID primary-secondary farm topology

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 9](../workshop/decision-09-federation-layer.md) (Federation layer: wrap Keycloak with Rust AD-claim-rules shim). This ADR operationalises Decision 9 §1 (deployment topology) against the PC-074 problem surface: AD FS's operationally fragile WID-mode farm topology (one primary writes, N secondaries pull every 5 minutes, manual promotion on primary failure) and the SQL-mode farm's HA burden (SQL Server Always On Availability Groups), which the framework replaces with PostgreSQL's synchronous multi-primary replication.

## Context

WID-mode AD FS has one primary node (writes) + N secondaries (read-only, sync every 5 min via `Microsoft.IdentityServer.PolicyModel.dll!PolicyStore.GetSetUpdate`), per [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md). All admin cmdlets (`Set-AdfsRelyingPartyTrust`, `Add-AdfsClaimsProviderTrust`, etc.) must hit the primary node. If the primary dies, manual promotion is required: `Set-AdfsSyncProperties -Role PrimaryComputer` on a secondary. The WID 5-node limit forces SQL farm for larger deployments. The 5-minute sync lag means a secondary node may serve stale config for up to 5 minutes after a primary-side change — including new RPT configurations, certificate rollovers, and claim rule updates. Worst case: admin adds a new RPT to the primary, a user is redirected to a secondary that hasn't synced yet, and the user gets `MSIS7017 — Audience URI is not in the AudienceRestriction collection`.

Per [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md), the WID file paths are `%SystemRoot%\Windows\WID\Data\microsoft.identityserver.mdf` and `microsoft.identityserver_log.ldf`; the config DB tables include `ServiceSettings` (federation service name, signing/encryption cert thumbprints), `RelyingPartyTrust` (per-RP identifiers, rules, claim descriptions, signing cert hash, encryption cert hash, token lifetime, endpoints), `ClaimsProviderTrust` (per-CPT, typically only the AD CPT), `ArtifactStore` (SAML artifact resolution), and `IdentityServerPolicy` (policy descriptions, claim descriptions, custom attribute store registrations). SQL-mode moves the same schema to a SQL Server instance with `Data Source=<sql>;Initial Catalog=AdfsConfiguration;Integrated Security=SSPI`, adding SQL Server licensing and HA complexity (Always On AGs with synchronous-commit replicas, listener FQDN).

The operational fragility is structural: WID's primary-secondary model is single-writer with bounded read replica count, manual failover, and a sync lag that creates windows of inconsistency. SQL-mode fixes the multi-writer problem at the SQL tier but adds SQL Server licensing, SQL HA operations, and a second database team. Neither mode gives the framework a clean, modern, cross-platform consensus-based config store.

The framework's constraints (from [PC-074](../catalog/06-federation-gateway.md)): must support multi-primary config (no single primary, all nodes accept writes); must support config DB HA (etcd cluster, Raft consensus, or equivalent); for AD FS interop, must accept that WID/SQL is the legacy topology. The framework must not inherit WID's primary-secondary fragility or SQL Server's licensing burden.

## Decision

The framework's Federation Gateway config store is **PostgreSQL with synchronous replication**, deployed as a 3-replica StatefulSet (or external managed PostgreSQL). PostgreSQL replaces both WID (single-primary + secondaries) and SQL farm (SQL Server Always On) as the Federation Gateway's config DB. There is no primary-secondary distinction, no 5-minute sync lag, no manual promotion, no SQL Server licensing. All Keycloak instances in the Federation Gateway StatefulSet read and write the same PostgreSQL database; PostgreSQL's synchronous replication (`synchronous_commit = on`, `synchronous_standby_names = ANY 1 (*)`) ensures every write is durable on at least one replica before the client receives a commit acknowledgement.

### Concrete specification

1. **PostgreSQL topology.** The Federation Gateway's PostgreSQL is deployed as a 3-replica StatefulSet (`adrian-postgresql-0`, `-1`, `-2`) in the same namespace as Keycloak. One replica is the primary (`adrian-postgresql-0` by convention); the other two are synchronous-streaming replicas. The primary accepts writes; the replicas accept read queries (Keycloak does not use read-splitting, so all queries hit the primary in v1). If the primary fails, the framework's operator (`FederationGateway` CRD per ADR-058) promotes a replica via `pg_ctl promote` on the highest-priority replica (`adrian-postgresql-1`). Promotion takes 5-15 seconds; the framework's operator updates the Service to point at the new primary. Keycloak reconnects automatically (its JDBC driver has connection-pool retry logic).

2. **Synchronous replication.** PostgreSQL's `synchronous_commit = on` and `synchronous_standby_names = ANY 1 (*)` configure synchronous streaming replication: every write transaction waits for at least one replica to acknowledge WAL reception before the client receives a commit. This guarantees zero data loss on primary failure (the replica has the committed transaction). The trade-off is write latency: every write incurs the round-trip latency to the nearest replica (typically 1-3 ms within a single datacenter; 10-50 ms across availability zones). For the Federation Gateway's write load (one write per session creation, per realm config change, per client config change — typically <100 writes/sec at peak), the synchronous-replication latency is negligible.

3. **Multi-primary-equivalent semantics.** Keycloak is a single-writer application from PostgreSQL's perspective (it sends all writes to the primary), but operationally, all Keycloak instances in the StatefulSet are equivalent: any instance can serve any request, and any instance can issue writes (which PostgreSQL routes to the primary via the JDBC connection string). There is no primary-Keycloak-instance distinction (unlike WID's primary-AD-FS-instance); there is no admin cmdlet that must hit a specific node. The `adrian-fed apply` CLI sends config changes to any Keycloak instance, which writes to PostgreSQL, which replicates synchronously to the replicas. All Keycloak instances see the change on the next read (no 5-minute sync lag — PostgreSQL's replication is sub-second within a datacenter).

4. **Quorum.** The 3-replica PostgreSQL cluster tolerates 1 replica failure without data loss (synchronous replication requires 1 ack from any replica; 2 of 3 replicas are always available with 1 failure). The framework's operator uses Patroni (or Stolon, or CloudNativePG — the framework's default is CloudNativePG, a Kubernetes-native PostgreSQL operator) for cluster management: leader election via Kubernetes leases, automatic failover, WAL archival to S3-compatible object storage. CloudNativePG's default quorum is "any 1 synchronous replica" — matching the framework's `synchronous_standby_names = ANY 1 (*)` setting.

5. **Backup and DR.** PostgreSQL backup is via CloudNativePG's built-in `pgBackRest` integration: continuous WAL archival to S3-compatible object storage (per [ADR-059](./ADR-059-pitr-backup-dr-runbooks.md)), scheduled base backups every 6 hours, 30-day retention. Point-in-time recovery (PITR) restores PostgreSQL to any second within the 30-day window. The DR runbook (per ADR-059): (a) deploy a new PostgreSQL cluster from the latest base backup + WAL replay to the target timestamp; (b) redeploy the Keycloak StatefulSet pointing at the new PostgreSQL; (c) restore the HSM-resident signing key from escrow (per [ADR-053](./ADR-053-key-escrow-and-nbde.md)). RTO ≤ 1 hour, RPO ≤ 5 minutes (WAL streaming lag).

6. **Multi-region federation.** For multi-region deployments (v1.1 target), the framework supports cross-region PostgreSQL asynchronous replication (logical replication via PostgreSQL's `pg_logical` extension, or physical replication via `pg_basebackup` + WAL streaming) to a standby region. The standby region's PostgreSQL is read-only until a planned cross-region failover (operator-initiated) or unplanned failover (disaster-recovery runbook). Cross-region replication is asynchronous (the round-trip latency of synchronous cross-region replication would be unacceptable for the Federation Gateway's write load); the standby region's RPO is bounded by the WAL-shipping lag (typically 1-5 seconds over a dedicated cross-region link).

7. **No WID, no SQL Server.** The framework does not ship, embed, or depend on WID or SQL Server. The framework's Helm chart deploys CloudNativePG (default) or accepts an external PostgreSQL connection string (`federation.postgresql.external` Helm value) for customers who prefer managed PostgreSQL (Cloud SQL, RDS, Aurora). The framework's documentation explicitly notes that AD FS's WID and SQL-farm topologies are legacy and that the framework does not interoperate with them — customers migrating from AD FS replace the config DB with PostgreSQL as part of the migration.

8. **AD FS migration.** The `adrian-migrate from-adfs` CLI (per Decision 9 §5 and ADR-100) reads AD FS configuration from the WID/SQL config DB (via PowerShell over WinRM — `Get-AdfsRelyingPartyTrust`, `Get-AdfsClaimsProviderTrust`, etc.) and writes the translated configuration to PostgreSQL via Keycloak's admin API. The migration is one-way (AD FS → PostgreSQL); the framework does not write back to AD FS. After migration cutover, the AD FS farm is decommissioned; its WID/SQL config DB is preserved (read-only) for forensic reference for 30 days, then deleted.

9. **Operational SLOs.** The Federation Gateway's config DB SLOs: write availability ≥ 99.95% (PostgreSQL primary available, accepting writes); read availability ≥ 99.99% (any replica can serve reads if the primary is briefly unavailable); write latency p99 ≤ 10 ms (synchronous replication within a datacenter); read latency p99 ≤ 5 ms; failover time ≤ 30 seconds (CloudNativePG detects primary failure and promotes a replica). These SLOs are monitored via CloudNativePG's Prometheus exporter (`cnpg_collector_*` metrics) and the framework's standard PostgreSQL Prometheus exporter (`pg_*` metrics).

10. **No etcd, no Raft among federation nodes.** The framework does not run a separate etcd cluster or Raft consensus among the Federation Gateway's Keycloak instances. The Federation Gateway's state lives in PostgreSQL, which uses its own replication protocol (streaming replication + synchronous commit). The framework's Core Directory (per Workshop Decision 2) uses FoundationDB for its own storage; the Federation Gateway's PostgreSQL is operationally independent. Running a separate etcd or Raft cluster for federation config would add infrastructure without benefit — PostgreSQL already provides the multi-primary-equivalent, HA, durable config store that PC-074 requires.

## Rationale

AD FS's WID primary-secondary model exists because Windows Internal Database is a single-writer SQL Server Express instance, and the simplest way to scale AD FS reads was to add read replicas with periodic sync. SQL farm exists because customers outgrew WID's 5-node ceiling and SQL Server was Microsoft's flagship DB. In 2026, neither is the right answer: PostgreSQL's synchronous streaming replication provides multi-primary-equivalent semantics (every Keycloak instance can write; PostgreSQL routes writes to the primary; replicas receive writes synchronously) with no SQL Server licensing, no Windows-Server requirement, and no 5-minute sync lag. CloudNativePG (or Patroni/Stolon) provides automatic failover and Kubernetes-native cluster management.

The framework chose PostgreSQL over etcd-and-Raft because (a) Keycloak's native storage is PostgreSQL — Keycloak does not support etcd as a backend, so running etcd for federation config would require a translation layer between Keycloak and etcd, adding complexity; (b) PostgreSQL's transactional semantics (ACID, MVCC, strict serializability) are required for federation config (a partial write of realm + client + claim rules would leave the Federation Gateway in an inconsistent state); etcd's KV semantics are simpler but lack the transactional guarantees; (c) PostgreSQL's operational tooling (pgBackRest, pg_stat_statements, pg_repack, CloudNativePG's backup/restore) is more mature than etcd's for the Federation Gateway's workload (config writes plus session writes).

The framework chose synchronous replication (`synchronous_commit = on`) over asynchronous replication because federation config (realms, clients, claim rules, signing cert thumbprints) is correctness-critical — losing a config write on primary failure would cause an inconsistent state across Keycloak instances. The 1-3 ms write latency cost is negligible at the Federation Gateway's write load (<100 writes/sec). For multi-region (v1.1), the framework accepts asynchronous cross-region replication because synchronous cross-region replication would add 50-200 ms to every write, which is unacceptable.

## Consequences

**Positive**. The framework eliminates WID's primary-secondary fragility (no manual promotion, no 5-minute sync lag, no `MSIS7017` stale-config errors). The framework eliminates SQL Server licensing and HA complexity (no Always On AGs, no SQL Server per-core CALs). The Federation Gateway's config DB is PostgreSQL — a single, well-understood, cross-platform database with mature operational tooling. The framework inherits CloudNativePG's automatic failover, backup, and DR capabilities.

**Negative**. The Federation Gateway carries a PostgreSQL dependency (one PostgreSQL cluster per Federation Gateway, plus the framework's Core Directory uses FoundationDB per Decision 2 — two databases in the framework's blast radius). PostgreSQL synchronous replication adds 1-3 ms write latency; for write-heavy workloads this would matter, but the Federation Gateway is read-heavy. Multi-region federation (v1.1) requires asynchronous cross-region replication, with an RPO of 1-5 seconds — acceptable for federation config but documented explicitly.

**Neutral**. Customers with existing PostgreSQL investment can reuse their operational practices; customers without PostgreSQL experience face a learning curve. The framework's Helm chart deploys CloudNativePG by default; customers who prefer Patroni or Stolon can substitute them via the Helm chart's `postgresql.operator` value.

**Implementation cost**. ~1 person-week for v1 (part of the ADR-100 budget): CloudNativePG Helm chart integration (0.5 pw), Federation Gateway operator CRD for PostgreSQL lifecycle (0.3 pw), DR runbook documentation (0.2 pw). PostgreSQL itself is upstream software; the framework does not implement PostgreSQL.

**Operational impact**. Federation Gateway operators manage PostgreSQL via CloudNativePG's CRD (`Cluster` resource); the framework's `FederationGateway` CRD references the PostgreSQL cluster. Sizing is documented (3 replicas, 2 vCPU each, 8 GB RAM each, 100 GB SSD). Backup/DR is a documented runbook (per ADR-059). PostgreSQL upgrades follow CloudNativePG's rolling-upgrade process (one replica at a time, with quorum preserved).

## Alternatives Considered

### Alternative A: Raft consensus among federation nodes (no external PostgreSQL)

The Federation Gateway's Keycloak instances form a Raft cluster; the Raft log is the source of truth for federation config. Each Keycloak instance runs an embedded Raft engine (e.g., `openraft`) and replicates config changes via Raft. No external PostgreSQL; Keycloak's session state is in-memory (Infinispan distributed cache). Rejected because (a) Keycloak does not support Raft as a storage backend — Keycloak's storage is JPA-based and expects a relational database; running Raft instead would require forking Keycloak, which the framework explicitly avoids (per Decision 9); (b) Raft's log is a write-ahead log, not a queryable database — the framework would need a state machine that interprets the Raft log and exposes it as a queryable config store, which is what PostgreSQL already is; (c) Raft's quorum requirement (majority of N nodes) means a 3-node Raft cluster tolerates 1 failure, same as 3-replica PostgreSQL with synchronous replication — but Raft does not give the framework PostgreSQL's transactional semantics or operational tooling.

### Alternative B: etcd-backed config (Kubernetes-native KV store)

The Federation Gateway's config lives in etcd (the Kubernetes-native KV store); each Keycloak instance reads config from etcd on startup and watches for changes via etcd's watch API. Rejected because (a) Keycloak does not support etcd as a storage backend (same problem as Alternative A); (b) etcd's KV semantics are simpler than PostgreSQL's — a partial write of realm + client + claim rules would require an etcd transaction (which etcd supports, but the framework would have to map Keycloak's JPA storage to etcd KV operations, which is a non-trivial translation layer); (c) etcd is already running in the Kubernetes cluster (it's the Kubernetes control-plane store), and using it for application config couples application availability to Kubernetes control-plane availability — a federation config write should not fail because the Kubernetes API server is briefly unavailable.

### Alternative C: SQL farm with synchronous replication (preserve the AD FS SQL-mode model)

Use PostgreSQL (or MySQL, or MariaDB) in a SQL-farm topology that mirrors AD FS's SQL-mode: multiple federation nodes writing to a single SQL backend with synchronous replication. Rejected because this is the chosen architecture — PostgreSQL with synchronous replication IS the modern equivalent of AD FS's SQL-mode farm. The alternative is moot. The difference from AD FS's SQL-mode is that the framework uses PostgreSQL (cross-platform, no licensing) instead of SQL Server (Windows-only, per-core licensing), and uses CloudNativePG (Kubernetes-native operator) instead of SQL Server Always On AGs (Windows Failover Cluster-dependent).

### Alternative D: FoundationDB (reuse the Core Directory's storage backend)

Per Workshop Decision 2, the framework's Core Directory uses FoundationDB. Reuse FDB for the Federation Gateway's config store. Rejected because (a) Keycloak does not support FoundationDB as a storage backend — Keycloak's storage is JPA-based and supports PostgreSQL, MySQL, MariaDB, Oracle, SQL Server, but not FDB; (b) even if the framework wrote an FDB-JPA adapter, the engineering effort (~4 person-weeks for the adapter alone, plus ongoing maintenance) is disproportionate to the benefit (one fewer database in the framework's blast radius); (c) the Federation Gateway's workload (config writes + session writes) is well-suited to PostgreSQL's MVCC; FDB's strict serializability is overkill for federation config. The framework accepts two databases (FDB for Core Directory, PostgreSQL for Federation Gateway) as the cost of using best-fit storage for each capability.

## Open Questions

- Should the framework support multi-region federation in v1 (instead of v1.1)? Current decision: defer to v1.1; multi-region adds asynchronous cross-region PostgreSQL replication, which is operationally complex and is not a v1-critical feature.
- Should the framework support read-splitting (Keycloak reads from replicas, writes to primary) to scale read throughput? Current decision: no — Keycloak's read load is modest (the framework's `moka` LRU cache in the shim absorbs most reads), and read-splitting adds configuration complexity (the JDBC connection pool must route reads vs writes).
- Should the framework support external managed PostgreSQL (Cloud SQL, RDS, Aurora) for customers who prefer managed databases? Current decision: yes — the Helm chart accepts an external PostgreSQL connection string; the framework's documentation lists tested managed PostgreSQL providers.

## Cross-capability impact

- **Federation Gateway (PC-068 — AD FS topology).** Addressed in [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md). The PostgreSQL cluster is a sub-component of the Federation Gateway's deployment topology.
- **Federation Gateway (PC-073 — WAP replacement).** Addressed in [ADR-102](./ADR-102-rust-shim-wap-replacement.md). The shim's session and relay-state stores use the same PostgreSQL cluster.
- **Operations (ADR-058).** The PostgreSQL cluster is deployed as a StatefulSet managed by CloudNativePG; the framework's `FederationGateway` CRD references the PostgreSQL `Cluster` CRD.
- **Operations (ADR-059).** PostgreSQL backup (pgBackRest + WAL archival) is part of the framework's PITR backup DR coverage.
- **Core Directory (Workshop Decision 2).** The Core Directory uses FoundationDB; the Federation Gateway's PostgreSQL is operationally independent. Two databases in the framework's blast radius is documented and accepted.
- **Migration (PC-124 AD FS-to-framework).** The `adrian-migrate from-adfs` CLI reads AD FS's WID/SQL config DB and writes the translated configuration to PostgreSQL via Keycloak's admin API.

## References

- [PC-074](../catalog/06-federation-gateway.md) — problem statement
- [Workshop Decision 9](../workshop/decision-09-federation-layer.md) — §1 deployment topology
- [docs/06-federation-sso/01-adfs-architecture.md](../docs/06-federation-sso/01-adfs-architecture.md) — WID vs SQL topology, primary/secondary model, 5-node WID limit, 5-minute sync lag, `Set-AdfsSyncProperties -Role PrimaryComputer` promotion
- [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md) — WID file paths, config DB tables (`ServiceSettings`, `RelyingPartyTrust`, `ClaimsProviderTrust`), SQL farm connection string
- [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md) — Keycloak + Rust shim deployment topology
- [ADR-058](./ADR-058-container-native-dcs-operator.md) — container-native deployment
- [ADR-059](./ADR-059-pitr-backup-dr-runbooks.md) — PITR backup DR runbooks
- [PostgreSQL Synchronous Replication](https://www.postgresql.org/docs/16/warm-standby.html#SYNCHRONOUS-REPLICATION) — PostgreSQL synchronous replication docs
- [CloudNativePG](https://cloudnative-pg.io/) — Kubernetes-native PostgreSQL operator
- [Keycloak Database Configuration](https://www.keycloak.org/server/db) — Keycloak's supported database backends
