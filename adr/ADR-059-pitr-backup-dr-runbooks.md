---
title: "ADR-059: Per-DC Backup with PITR + Operator-Driven DR Runbooks"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-110
severity: high
tags: [adr, operations, backup, dr, pitr, wal-archiving, operator, recovery]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ./ADR-058-container-native-dcs-operator.md
  - ./ADR-063-unified-cross-platform-cli.md
last_updated: 2026-08-13
---

# ADR-059: Per-DC Backup with PITR + Operator-Driven DR Runbooks

## Status

Accepted — 2026-08-13

## Context

AD disaster recovery is a multi-step manual procedure. The canonical runbook for a dead-DC scenario is: (1) `ntdsutil → metadata cleanup → remove selected server <DC>` — removes the NTDS Settings object and the computer account from AD, otherwise the dead DC lingers as a replication partner; (2) `repadmin /removelingeringobjects` — cleans up objects on other DCs that were deleted on the dead DC but not yet replicated (tombstone-lifetime-exceeded scenarios, event 2042); (3) IFM (Install From Media) — `ntdsutil → ifm → create full <path>` produces an offline DIT snapshot used to seed a new DC without pulling the full DIT over the WAN; (4) `Restore-ADObject` (Active Directory Recycle Bin, requires forest functional level ≥ 2008 R2) — restores deleted objects from the recycled-object state; (5) USN rollback recovery — if a DC was restored from a non-VSS-aware snapshot, the partner detects the rollback via `CheckUsnRollback` in `ntdsa.dll`, logs event 2095, and refuses replication; the only safe recovery is `dcpromo /forceremoval` + metadata cleanup + re-promotion.

Every step is interactive. `ntdsutil` is a Windows-only CLI with a nested menu interface (not scriptable without `ntdsutil.exe … < input.txt` hacks). Recovery Time Objective (RTO) for a single-DC failure is typically 2-4 hours with an experienced operator; for a forest-root failure (all DCs in the forest root domain lost), RTO is 8-24 hours because schema restoration from backup + cross-domain trust re-establishment + Group Policy re-link is required. Forest-root recovery without a current backup is forest-rebuild (weeks).

The framework gap: modern systems provide one-command restore. CockroachDB has `cockroach dump` + `cockroach restore`. PostgreSQL has Point-In-Time Recovery (PITR) via WAL archiving. Kubernetes operators (e.g. the Postgres-operator) automate backup, restore, and failover. The framework should provide an operator that handles per-DC backup (PVC snapshot of the DIT + WAL archiving), point-in-time restore, automated metadata cleanup when a DC pod is terminated, Recycle Bin equivalent by default (no forest-functional-level gate), and USN-rollback-equivalent detection via Raft term numbers (a partitioned-then-rejoined node simply rejoins the quorum, no manual cleanup).

The constraint set: support point-in-time restore (PITR) of the DIT; support automated metadata cleanup when a DC is permanently removed (pod deletion triggers NTDS-Settings cleanup); enable Recycle Bin by default (no functional-level gate); detect "USN rollback" automatically (snapshot-restored DC) and refuse to serve; support IFM-equivalent (seed a new DC from an offline DIT snapshot).

## Decision

The framework provides per-DC backup via a layered model: (1) the framework's storage engine writes a Write-Ahead Log (WAL) that is archived to object storage (S3, GCS, Azure Blob, MinIO) every 60 seconds; (2) the operator takes a daily full snapshot of the DIT PVC (via the CSI snapshot API); (3) the operator takes an hourly incremental snapshot (storage-engine-level, faster than PVC snapshot). Point-in-time recovery (PITR) replays the WAL from the most recent full or incremental snapshot to any timestamp within the retention window (default 35 days).

The operator implements all DR runbooks as reconcile loops: `DeadDCRecovery` (detect a non-responsive Pod for >5 minutes, mark for metadata cleanup), `MetadataCleanup` (remove the `nTDSDSA` object, computer account, and any lingering replication metadata), `ForestRootRecovery` (restore the forest root from the most recent backup + re-establish cross-domain trusts), `LingeringObjectCleanup` (the framework detects lingering objects automatically via the replication metadata, no `repadmin /removelingeringobjects` invocation needed), `USNRollbackDetection` (any DC whose Raft term number is older than the quorum's current term refuses to serve; the operator quarantines and re-seeds from a healthy DC). Recycle Bin is enabled by default — deleted objects go to a recycled state for 180 days, then to a tombstone state for 180 days, then are garbage-collected. Restore is a single CLI command or operator invocation.

**Concrete specification**:

- The framework's storage engine MUST write a WAL with sequential, monotonic log sequence numbers (LSNs). Each WAL record MUST contain the modified object DN, the modified attribute, the previous value (for rollback), the new value, the originating DC, the originating USN, and a timestamp.
- WAL records MUST be archived to object storage every 60 seconds (configurable). The archive format is a compressed (zstd) sequence of WAL records in framework-defined protobuf schema.
- The operator MUST take a daily full PVC snapshot at 02:00 cluster-local time (configurable) via the CSI `VolumeSnapshot` API.
- The operator MUST take an hourly incremental snapshot via the storage engine's `incremental_snapshot()` API (which produces a delta against the last full snapshot).
- PITR MUST support restore to any second within the retention window (default 35 days of WAL + 35 daily full snapshots).
- PITR restore MUST complete within 10 minutes for a 100 GB DIT (target RTO 10 min for single-DC restore).
- `Restore-DCObject` (Recycle Bin restore) MUST be a single CLI command: `adrian-cli restore-object --dn "CN=jdoe,OU=Users,DC=corp,DC=example,DC=com" --deleted-within 7d`.
- `Restore-DCObject` MUST be exposed as an operator action: `kubectl apply -f restore-object.yaml` with `spec.dn` and `spec.deletedWithin`.
- The operator MUST detect a dead DC Pod (liveness probe failures for >5 minutes) and automatically invoke `MetadataCleanup` on the domain's other DCs.
- The operator MUST quarantine any DC whose Raft term number is older than the quorum's current term (USN-rollback-equivalent). Quarantined DCs are not allowed to serve LDAP/Kerberos; they are re-seeded from a healthy DC by the operator.
- Lingering object cleanup MUST be automatic: the framework's replication protocol detects lingering objects (objects present on a partner but deleted on the source) and removes them without operator intervention. The replication log MUST record each removal for audit.
- IFM-equivalent (offline DC seeding) MUST be supported: `adrian-cli ifm-export --output /path/to/snapshot` produces a portable snapshot; `adrian-cli ifm-import --input /path/to/snapshot` seeds a new DC from the snapshot without pulling the full DIT over the network.
- The IFM snapshot format MUST be the same as the daily full PVC snapshot format (a single tar of the DIT + a WAL position marker).
- The framework MUST support cross-region backup replication: WAL archives and daily snapshots are replicated to a secondary region within 5 minutes.
- The framework MUST ship a default retention policy: 35 days of WAL, 35 daily snapshots, 12 monthly snapshots, 7 yearly snapshots. Operators can extend via configuration.
- Backup integrity MUST be verified daily: the operator restores the most recent snapshot to a throwaway Pod and runs a consistency check (object count, schema integrity, FSMO presence).

## Rationale

Per-DC backup with WAL archiving is the proven model from Postgres, MySQL, CockroachDB, and FoundationDB. It provides point-in-time recovery (any second within the retention window) which is strictly more powerful than AD's "restore from VSS snapshot" model (only the snapshot timestamps are recoverable). The 60-second WAL archive interval bounds the data loss window (Recovery Point Objective, RPO) to 60 seconds — a 60x improvement over AD's typical "last night's VSS snapshot" RPO of 24 hours.

The operator-driven DR model is necessary because manual DR is the leading cause of prolonged outages. The 2-4 hour single-DC RTO and 8-24 hour forest-root RTO in AD are dominated by human time, not technology time. The framework's target RTOs (10 min single-DC, 60 min forest-root) are achievable only if the operator performs the metadata cleanup, snapshot restore, and replication re-establishment without human intervention.

Recycle Bin by default removes the forest-functional-level gate that makes it opt-in in AD. Most AD deployments do not enable Recycle Bin because it requires forest functional level 2008 R2, and many forests are stuck at lower levels for compat reasons. The framework enables it on day 1.

USN-rollback detection via Raft term numbers is strictly better than AD's `CheckUsnRollback` heuristic. AD's heuristic detects a snapshot-restored DC by comparing USN vectors and refusing replication; it is fragile (certain rollback scenarios are not detected) and requires manual `dcpromo /forceremoval`. The framework's Raft quorum model means a snapshot-restored DC simply has a stale term number and is automatically quarantined and re-seeded.

Lingering object cleanup automation removes the need for `repadmin /removelingeringobjects`. The framework's replication protocol (whatever is chosen per the deferred PC-001/PC-002 decision) can detect lingering objects via the same metadata that AD uses (originating USN + tombstone-lifetime), but the framework can remove them automatically because the replication protocol is framework-controlled. AD cannot do this safely because DRSUAPI replication must interop with arbitrary DSA implementations.

IFM-equivalent is required for offline DC promotion in bandwidth-constrained environments (a 100 GB DIT over a 100 Mbps WAN takes 2.5 hours to seed; an IFM snapshot shipped on physical media or via S3 multi-part upload is faster). The IFM snapshot format being identical to the daily backup format reduces the number of code paths.

## Consequences

**Positive**: RPO drops from 24 hours (AD VSS) to 60 seconds (WAL archiving). RTO for single-DC drops from 2-4 hours to 10 minutes. RTO for forest-root drops from 8-24 hours to 60 minutes. Recycle Bin is on by default; deleted objects are recoverable for 180 days without a forest-functional-level prerequisite. USN-rollback-equivalent detection is automatic and safe. DR runbooks become operator invocations, not wiki pages.

**Negative**: Object storage costs (S3, GCS, Azure Blob) accrue continuously — for a 100 GB DIT with 35 days of WAL + 35 daily snapshots + 12 monthly + 7 yearly, the storage footprint is roughly 1.5 TB per DC, ~$30-50/month per DC at standard S3 pricing. Cross-region replication doubles this. The operator becomes a critical DR component — operator bugs can corrupt backups. PITR restore requires a maintenance window during which the DC is read-only.

**Neutral**: The framework's storage engine choice (deferred per PC-007 / Tier-1 ORQ-011/012/013/014) must support WAL archiving; most candidate engines (RocksDB, FoundationDB, CockroachDB's Pebble) do. ESE does not natively; an ESE-backed framework would need a custom WAL layer. The decision is stable regardless of storage choice.

**Implementation cost**: ~4 person-months for the WAL archiving and PITR replay logic; ~3 person-months for the operator reconcile loops; ~2 person-months for the IFM-equivalent import/export; ~2 person-months for the cross-region replication. Total: ~11 person-months for v1.

**Operational impact**: Operators set a backup retention config once; the operator handles the rest. DR drills become quarterly automated tests (the operator restores to a test cluster, the test framework verifies object counts). The framework's runbook is `kubectl apply -f restore.yaml` rather than a 20-page wiki page.

## Alternatives Considered

**Alternative A: VSS-style snapshots only (no WAL archiving).** AD's model. Rejected because RPO is 24 hours (last nightly snapshot), which is unacceptable for identity data in 2026. Password changes, group membership changes, and ACL changes within the last 24 hours would be lost on restore.

**Alternative B: Logical-export backups (LDIF or JSON dumps) only.** Export the DIT to LDIF nightly. Rejected because (a) restore is all-or-nothing (cannot PITR to a specific second), (b) logical export of a 100 GB DIT takes hours and locks the DIT, (c) logical restore re-imports every object via LDAP, taking 10-100x longer than a snapshot restore.

**Alternative C: Storage-array-level snapshots (EBS snapshots, NetApp snapshots).** Rejected as the primary path because (a) it couples the framework to a specific storage backend, (b) array snapshots do not capture the WAL position (the DIT file alone is not crash-consistent without the WAL), (c) cross-region replication of array snapshots is vendor-specific. Array snapshots are used as the daily full snapshot via CSI when available, but WAL archiving remains the PITR substrate.

## Open Questions

None — this is an ADR-ELIGIBLE decision. The exact storage engine is deferred per PC-007 / Tier-1 ORQ-011/012/013/014, but the WAL-archiving + PITR + operator-driven DR architecture is stable regardless of storage choice.

## Cross-capability impact

- **Core Directory (PC-001 through PC-022)**: DRSUAPI replication (PC-001) must support IFM seeding; the framework's replication protocol must record enough metadata for automatic lingering-object cleanup.
- **Operations (PC-109)**: Container deployment (ADR-058) provides the Pod + PVC substrate that backup uses.
- **Operations (PC-111)**: Audit logs (ADR-060) must be backed up alongside the DIT — audit logs are part of the recovery point.
- **Operations (PC-115)**: Unified CLI (ADR-063) exposes `restore-object`, `ifm-export`, `ifm-import`, `restore-pitr` commands.
- **KDC (PC-030)**: krbtgt rotation is part of the forest-root recovery runbook; the operator must rotate krbtgt as part of `ForestRootRecovery`.
- **Security (PC-118)**: Golden-ticket mitigation (ADR-065) requires krbtgt rotation as part of incident response; the operator's `ForestRootRecovery` reconcile loop includes the krbtgt rotation step.
- **Migration (PC-126)**: Client switchover during migration uses IFM-equivalent to seed framework DCs from AD DIT snapshots.
- **Cert Service (PC-062)**: CA database backup must be a separate but parallel operator-managed flow; CA database corruption (PC-062) is recoverable.

## References

- [PC-110](../catalog/10-operations.md) — problem statement (Disaster recovery is manual)
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — USN rollback detection (`ntdsa.dll!CheckUsnRollback`), tombstone-lifetime handling, ESE -1018/-1022 errors
- [Replication internals](../docs/03-directory-schema/05-replication-internals.md) — Event 2095 (USN rollback), event 2042 (tombstone lifetime exceeded), `repadmin /removelingeringobjects`
- [Kubernetes VolumeSnapshots](https://kubernetes.io/docs/concepts/storage/volume-snapshots/)
- [PostgreSQL Point-In-Time Recovery (PITR)](https://www.postgresql.org/docs/current/continuous-archiving.html)
- [CSI (Container Storage Interface)](https://github.com/container-storage-interface/spec)
- [RFC 4120 — Kerberos (for kpasswd integration with backup verification)](https://datatracker.ietf.org/doc/html/rfc4120)
