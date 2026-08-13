---
title: "ADR-034: Transactional DB with PITR; reject repair tools"
status: Accepted (partial)
date: 2026-08-13
deciders: adrian-architecture-team
capability: Cert Service
problem: PC-062
severity: medium
tags: [adr, cert-service, database, pitr, transactional, eseutil]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/05-cert-service.md
  - ../docs/05-pki-certs/01-ad-cs-architecture.md
  - ../docs/01-ad-core/02-ad-cs-cert-services.md
  - ./ADR-032-hsm-bound-kra-shamir.md
last_updated: 2026-08-13
---

# ADR-034: Transactional DB with PITR; reject repair tools

## Status

Accepted (partial) — 2026-08-13. The confident sub-decision (use a transactional database with WAL/transaction-log replay and PITR; explicitly reject hard-repair tools; document "restore from backup" as the only corruption recovery procedure) is locked. The deferred sub-decision — the specific DB engine choice (PostgreSQL vs. SQLite-WAL vs. FoundationDB) — is gated by Tier-3 ORQ-120/121 and resolved in a future ADR.

## Context

CA ESE database (`%SystemRoot%\System32\CertLog\<CAName>.edb`, page size 32 KB on Server 2016+) corruption is detected via JET errors: `JET_errDbTimeTooNew`, `JET_errDbTimeCorrupted`, `JET_errDiskRead` (-1022), per [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md). The recovery procedure, per [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), is "restore from backup" — running `eseutil /p` (hard repair) on a CA database is explicitly discouraged because it can break cert serial continuity (the `Request.RequestRow` → `Certificate.CertRowId` foreign-key chain) and lose rows that ESE considers "logically deleted" but that are still queryable.

CA database backup uses `certutil.exe -backup` or the `CertSvc VSS Writer` (writer ID `{5425FD7A-0D43-4C59-AA61-D3D2D8E9A9D7}`). Restoration requires `certutil -restoreDB` followed by `-restoreKey` to re-import the CA private key from the `.p12` backup. The CA service must be stopped during restore; the CA is offline for the duration (typically 30 minutes to several hours depending on database size). Per the same KB, ESE transaction-log replay (`edbXXXXX.log` files) can recover from soft crashes; hard crashes require backup restore.

The operational pain: a CA database restore is a multi-hour outage. During the outage, no new certs can be issued, no revocations can be processed (the CRL cannot be regenerated from a stale database), and OCSP responses become stale. For an Enterprise CA serving 10K+ users with autoenroll, this means cert renewal failures cascade, per [PC-062](../catalog/05-cert-service.md).

For the framework, online CA DB repair (while the CA continues to serve reads from a replica) + point-in-time recovery (PITR via WAL replay) is the modern alternative. The framework must support WAL/transaction-log replay for soft crash recovery, PITR for hard crash recovery, online repair (CA continues to serve reads from a replica while a member is repaired), and must NOT break cert serial continuity (the `Request.RequestRow` → `Certificate.CertRowId` chain). The framework should NOT use ESE; the choice of storage backend is a foundational decision.

## Decision

The framework shall use a transactional database with WAL (write-ahead log) and PITR (point-in-time recovery) for CA storage. Hard-repair tools (ESE `eseutil /p` equivalent) are explicitly rejected; "restore from backup" is the only corruption recovery procedure.

1. **Transactional database** — the framework's CA storage uses a transactional database (not ESE) with ACID properties. Every cert issuance, revocation, and CRL generation is a transaction; partial transactions are rolled back. The specific DB engine is deferred to ORQ-120/121 (PostgreSQL vs. SQLite-WAL vs. FoundationDB) — the framework's CA code uses a database abstraction layer that supports all three.
2. **WAL for soft crash recovery** — the database uses write-ahead logging: every transaction is written to the WAL before it is applied to the main database. On soft crash (process kill, power loss), the database replays the WAL on restart and recovers to the last committed transaction. No data loss, no manual intervention.
3. **PITR for hard crash recovery** — the database supports point-in-time recovery via WAL archiving. WAL segments are continuously archived to object storage (S3, GCS, Azure Blob, MinIO). On hard crash (disk corruption, file system damage), the database is restored from the last full backup plus WAL replay to any point in time within the WAL retention window (default 30 days). This replaces ESE's `eseutil /p` hard repair, which is explicitly rejected.
4. **Online repair via replication** — the framework's CA database runs as a primary with one or more read replicas (synchronous replication for the primary, asynchronous for additional replicas). If the primary fails, a replica is promoted (automatic failover within 30 seconds). While a member is repaired (e.g., disk replacement), the CA continues to serve reads from the surviving replicas and writes from the new primary. The CA is never offline during repair.
5. **Reject hard-repair tools** — the framework explicitly rejects the equivalent of `eseutil /p` (hard repair). There is no `adrian-ca-db-repair --hard` command. The only corruption recovery procedure is: (a) failover to a replica if available, or (b) restore from backup + WAL replay if no replica is available. This matches AD CS's documented guidance ("do not eseutil /p") and enforces it as a hard rule.
6. **Cert serial continuity** — the database schema preserves the `Request.RequestRow` → `Certificate.CertRowId` foreign-key chain (the framework's equivalent: `requests` table → `certificates` table, with `certificates.request_id` foreign key). No operation breaks this chain; the framework's CA code enforces referential integrity via database constraints.
7. **Schema** — the database schema includes: `requests` (CSR data, submission time, requesting principal), `certificates` (issued cert DER, serial number, request_id FK, issuance time, expiry time, revocation status, revocation time, revocation reason), `crls` (CRL DER, generation time, next-update time), `key_recovery_table` (archived key shares per ADR-032), `kra_registry` (KRA certs and quorum config per ADR-032), `audit_log` (every issuance, revocation, recovery event).
8. **Backup** — the framework's operator (per ADR-058) schedules daily full backups and continuous WAL archiving. Backup verification (restore to a test CA, issue a test cert) runs weekly.

**Concrete specification**:

- The database abstraction layer is a Go (or Rust, per ORQ-169/170) interface with implementations for PostgreSQL, SQLite-WAL, and FoundationDB. The interface supports: `BeginTx`, `Commit`, `Rollback`, `Query`, `Exec`, `Backup`, `Restore`, `PITR(target_time)`.
- WAL archiving: the database writes WAL segments to `s3://<bucket>/adrian-ca/<ca-name>/wal/<segment-id>` (or equivalent for GCS/Azure Blob/MinIO). WAL segments are 64 MB; rotation is automatic.
- Full backups: the operator schedules daily full backups to `s3://<bucket>/adrian-ca/<ca-name>/backup/<date>/`. Backup format is the database's native backup format (e.g., `pg_basebackup` for PostgreSQL).
- PITR: the `adrian-ca-db restore --to <timestamp>` CLI restores the database to the specified timestamp by combining the last full backup before the timestamp and WAL replay from the backup to the timestamp.
- Replication: the primary writes synchronously to at least 1 replica (configurable; default 2 replicas for production CA). Read replicas serve OCSP responder CRL reads (per ADR-033) and `certutil -view` queries, offloading the primary.
- Failover: the framework's CA operator monitors primary health; on primary failure, it promotes a replica (automatic, within 30 seconds). The CA service reconnects to the new primary.
- The framework's documentation states explicitly: "There is no hard-repair tool. If the database is corrupt, restore from backup. There is no equivalent of `eseutil /p`."

## Rationale

Three alternatives were considered.

**Alternative 1: Keep ESE for AD interop.** Use the same ESE database as AD CS for full binary compatibility. Rejected because ESE is a Windows-only, AD-specific storage engine with no PITR, no online repair, and a documented "do not hard-repair" caveat that the framework cannot enforce. The framework's value proposition is modernization; keeping ESE perpetuates the operational pain that PC-062 describes.

**Alternative 2: Append-only log (event sourcing).** Treat the CA database as an immutable append-only log of issuance/revocation events; rebuild the current state by replaying the log. Rejected because (a) appending is fast but querying (e.g., "is cert serial X revoked?") requires a materialized view, adding complexity; (b) the log grows unboundedly (10K certs/year × 10 years = 100K events, manageable, but compounded by CRL generation events, audit events, KRA recovery events); (c) the framework's CA code must implement event sourcing on top of a database that does not natively support it. A transactional database with WAL provides the same durability guarantee (the WAL is the append-only log) with native query support.

**Alternative 3: Cloud-managed database (AWS RDS, Azure SQL, GCP Cloud SQL).** Use a cloud-managed database that handles backup, PITR, replication, and failover automatically. Rejected because (a) cloud-managed databases introduce a cloud dependency (the framework cannot operate without internet connectivity to the cloud DB), (b) cloud-managed databases do not support air-gapped deployments (government, defense, regulated industries), (c) cloud-managed database cost compounds for high-throughput CAs (per-transaction pricing for some engines). The framework uses a self-hosted database with the same capabilities, deployable on-prem and in-cloud.

The decision aligns with industry practice: HashiCorp Vault uses HA storage backends (Consul, Raft) with WAL; Kubernetes etcd uses Raft with WAL; Dogtag PKI uses 389-DS LDAP with replication. None use ESE. The framework's design is the same shape.

Cost: ~6 person-weeks for the database abstraction layer, the WAL archiving, the PITR CLI, and the replication/failover logic. The DB engine choice (ORQ-120/121) is additional; the abstraction layer ensures the choice is reversible.

## Consequences

**Positive**. Soft crashes recover automatically via WAL replay (no manual intervention). Hard crashes recover via PITR to any point in the WAL retention window (default 30 days). Online repair via replication means the CA is never offline during repair. Cert serial continuity is preserved via database constraints. Hard-repair tools are rejected by design, eliminating the `eseutil /p` footgun.

**Negative**. The database adds operational dependencies: a DB engine (PostgreSQL, SQLite-WAL, or FoundationDB per ORQ-120/121), WAL archiving infrastructure (S3/MinIO), backup verification. The DB engine choice is deferred (PARTIAL ADR), so the framework's CA code must use an abstraction layer that supports all three candidates — adding a small but non-zero performance overhead.

**Neutral**. The replication model (1 primary + N replicas) means the framework's CA is a primary-replica cluster, not a multi-master cluster. Multi-master would allow any CA node to issue certs, but introduces conflict resolution complexity. Primary-replica is simpler and sufficient for CA throughput (cert issuance is not high-frequency; 100 certs/minute is typical peak).

**Implementation cost**. ~6 person-weeks for the abstraction layer, WAL archiving, PITR CLI, and replication/failover. The DB engine choice (ORQ-120/121) is additional effort for the chosen engine's specific integration.

**Operational impact**. Operators deploy the CA database as a primary-replica cluster (minimum 1 replica for HA). WAL archiving and daily backups are scheduled via the framework's operator (per ADR-058). Backup verification runs weekly. PITR is a CLI call (`adrian-ca-db restore --to <timestamp>`). Failover is automatic.

## Alternatives Considered

### Alternative A: Keep ESE for AD interop

Use the same ESE database as AD CS for full binary compatibility with `certutil -backup` / `-restoreDB` / `certsrv.msc`.

Rejected because ESE is a Windows-only, AD-specific storage engine with no PITR (only soft recovery via `eseutil /r`), no online repair (the CA is offline during restore), and a documented "do not hard-repair" caveat that the framework cannot enforce programmatically. The framework's value proposition is modernization; keeping ESE perpetuates the operational pain that PC-062 describes. Additionally, ESE is not cross-platform (no Linux/macOS port), so the framework cannot use ESE on non-Windows CAs.

### Alternative B: Append-only log (event sourcing)

Treat the CA database as an immutable append-only log of issuance/revocation events. The current state (which certs are valid, revoked, expired) is a materialized view rebuilt by replaying the log.

Rejected because (a) appending is fast but querying (e.g., "is cert serial X revoked?" for OCSP responder lookups) requires a materialized view, adding complexity and a second storage system to manage; (b) the log grows unboundedly — 10K certs/year × 10 years = 100K issuance events, compounded by CRL generation events, audit events, KRA recovery events, reaching millions of events over a decade; (c) the framework's CA code must implement event sourcing on top of a database that does not natively support it, adding a custom layer that must be debugged and maintained. A transactional database with WAL provides the same durability guarantee (the WAL is the append-only log) with native query support, native PITR, and native replication — all features the framework would otherwise have to build.

### Alternative C: Cloud-managed database (AWS RDS, Azure SQL, GCP Cloud SQL)

Use a cloud-managed database that handles backup, PITR, replication, and failover automatically. The framework's CA code uses the cloud DB's connection string.

Rejected because (a) cloud-managed databases introduce a cloud dependency — the framework cannot operate without internet connectivity to the cloud DB, breaking air-gapped deployments (government, defense, regulated industries); (b) cloud-managed database cost compounds for high-throughput CAs — AWS RDS for PostgreSQL charges ~$100/month for a small instance but scales to $1000+/month for production-grade, plus storage cost per GB; (c) cloud-managed databases do not support all of the framework's deployment scenarios (on-prem, hybrid, multi-cloud). The framework uses a self-hosted database with the same capabilities (WAL, PITR, replication, failover), deployable on-prem and in-cloud, with no cloud dependency. Operators who prefer a cloud-managed DB can deploy the framework's CA on cloud IaaS (EC2, Azure VM, GCE) with a self-hosted DB.

## Open Questions

- **Deferred sub-decision (PARTIAL)**: the specific DB engine choice (PostgreSQL vs. SQLite-WAL vs. FoundationDB). Gated by Tier-3 ORQ-120 (CA DB engine requirements: transactional, WAL, PITR, replication, cross-platform) and ORQ-121 (DB engine comparison: PostgreSQL maturity vs. SQLite simplicity vs. FoundationDB distributed). The current abstraction layer supports all three; the choice is reversible.
- The replication model: should the framework support multi-master (allow any CA node to issue certs) in addition to primary-replica? Multi-master adds conflict resolution (e.g., two CAs issuing the same serial number). Current decision: primary-replica only; revisit if CA throughput exceeds primary capacity (unlikely for typical enterprise).
- WAL retention: 30 days is the default. Should it be tunable per-deployment? High-security deployments may want 90 days; cost-conscious deployments may want 7 days. Current decision: tunable, default 30 days.

## Cross-capability impact

- **Cert Service (PC-062)**: This ADR. PC-061 (OCSP responder, ADR-033) — the OCSP responder reads CRLs from the CA database; the replication model offloads reads to replicas.
- **Cert Service (PC-060)**: ADR-032 (HSM-bound KRA) — the `key_recovery_table` is part of the CA database; transactional DB with PITR protects archived keys.
- **Core Directory (PC-001..PC-022)**: PC-007 (Core Directory storage engine) — the framework's Core Directory may use the same DB engine as the CA DB (per ORQ-011/012/013/014), but they are separate databases. The CA DB abstraction layer could be shared with Core Directory's storage layer.
- **Operations (PC-106..PC-115)**: ADR-058 (DCs as containers; Kubernetes operator) — the CA DB runs as a StatefulSet with persistent volumes; the operator manages backup, WAL archiving, and failover.
- **Operations (PC-106..PC-115)**: ADR-059 (per-DC backup with PITR) — the CA DB backup is part of the per-DC backup strategy.

## References

- [PC-062](../catalog/05-cert-service.md) — problem statement in the catalog
- [docs/05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md) — ESE database schema, `CircularLogging` registry, `DBSessionCount`/`DBPageSize` tuning
- [docs/01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md) — ESE corruption detection, "do not eseutil /p" warning, `certutil -backup`/`-restoreDB`/`-restoreKey` workflow
- [PostgreSQL WAL](https://www.postgresql.org/docs/current/wal.html) — industry precedent for WAL-based PITR
- [SQLite WAL mode](https://www.sqlite.org/wal.html) — industry precedent for WAL mode
- [FoundationDB](https://www.foundationdb.org/) — distributed transactional database
