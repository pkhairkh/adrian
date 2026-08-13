---
title: "ADR-010: Storage-Engine-Native Backup and Filesystem Snapshots (PARTIAL)"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-020
severity: high
tags: [adr, core-directory, backup, restore, snapshots, vss, partial]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/03-directory-schema/05-replication-internals.md
last_updated: 2026-08-13
---

# ADR-010: Storage-Engine-Native Backup and Filesystem Snapshots (PARTIAL)

## Status

Accepted — 2026-08-13

## Context

Active Directory backup uses VSS (Volume Shadow Copy Service) writer `{5425FD7A-0D43-4C59-AA61-D3D2D9E2B9D7}` to capture a transactionally-consistent DIT snapshot. The VSS writer freezes ESE writes, snapshots the volume, thaws writes — the snapshot is point-in-time consistent. Non-VSS-aware snapshots (VMware/Hyper-V without integration services, manual file copy of `ntds.dit`) cause USN rollback detection on next boot: the DC advertises a stale `invocationId` and `usnLast`, partners quarantine it, event 2095 fires, per [PC-020](../catalog/01-core-directory.md#pc-020--ntdsdit-backup--restore-requires-vss-aware-snapshots), [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md), and [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

The restore procedure is equally critical: after restoring a VSS-aware backup, the DC must reset its `invocationId` (so partners re-seed) or perform an authoritative restore (mark specific objects as authoritative, overriding partners' versions). The `ntdsutil ifm` (install-from-media) feature creates a VSS-aware snapshot suitable for offline DC provisioning — the new DC copies the IFM media and starts replication from the IFM's USN, avoiding a full forest-wide sync.

A framework needs: (a) online backup API (snapshot the storage engine while it's running, transactionally consistent); (b) restore procedure that detects and resets `invocationId` (or equivalent); (c) feature-parity with `ntdsutil ifm` for install-from-media; (d) snapshot retention and rotation. For container-native deployments, the equivalent is CRIU (Checkpoint/Restore In Userspace) for process-level snapshots, or LVM/ZFS/Btrfs snapshots for filesystem-level snapshots.

This ADR is PARTIAL because the specific backup API depends on the framework's storage-engine choice (gated by Tier-1 ORQ-011/012/013/014). Different storage engines have different snapshot APIs: SQLite has the `sqlite3_backup_*` API; RocksDB has `CreateCheckpoint()`; FoundationDB has snapshot transactions; LMDB has `mdb_env_copy2()` with `MDB_NOSYNC`. The high-level decision — use storage-engine-native backup, eliminate VSS dependency, support IFM — is confident; the specific API call depends on the deferred storage-engine choice.

Constraints from [PC-020](../catalog/01-core-directory.md#pc-020--ntdsdit-backup--restore-requires-vss-aware-snapshots):

- Must support point-in-time-consistent snapshot (storage-engine-native or filesystem-level).
- Must support IFM (install-from-media) for offline DC provisioning.
- Must support `invocationId` reset on restore (or equivalent for the framework's replication model).
- Must support authoritative restore (mark specific objects as authoritative).
- For AD interop, the VSS writer must be invokable by Windows Backup (and the equivalent on macOS / Linux must be invokable by `tar` / `rsync` / `zfs send`).

## Decision

The framework SHALL use storage-engine-native backup APIs (snapshot/checkpoint) and filesystem-level snapshots (LVM/ZFS/Btrfs) as the backup mechanism, eliminating the VSS dependency entirely. The framework SHALL register a backup-coordinator service that:

1. **Quiesces writes** — signals the storage engine to flush pending transactions and hold new writes (or use MVCC snapshot isolation if the storage engine supports it, allowing writes to continue during snapshot).
2. **Triggers the snapshot** — calls the storage-engine-native snapshot API (e.g. RocksDB `CreateCheckpoint()`, SQLite `sqlite3_backup_*`, LMDB `mdb_env_copy2()`) OR triggers a filesystem-level snapshot (LVM `lvcreate -s`, ZFS `zfs snapshot`, Btrfs `btrfs subvolume snapshot`).
3. **Records the snapshot metadata** — invocation ID, USN cursor, timestamp, storage-engine version, framework version. This metadata is essential for restore (the framework must know the snapshot's replication state to correctly reset `invocationId`).
4. **Resumes writes** — releases the quiesce.
5. **Verifies the snapshot** — reads back a sample of objects from the snapshot to confirm consistency.

The framework SHALL support restore with `invocationId` reset: when restoring from a snapshot, the framework SHALL generate a new `invocationId` (UUID), persist it to the directory, and signal replication partners that this DC is "fresh" (partners will re-seed from this DC's state). This matches AD's behavior of resetting `invocationId` on restore.

The framework SHALL support authoritative restore: an admin can mark specific objects (or subtrees) as authoritative, overriding partners' versions on next replication. The mechanism is the framework's equivalent of `ntdsutil authoritative restore` — mark objects with a high version counter that supersedes any partner's version.

The framework SHALL support install-from-media (IFM): an admin can take a snapshot, copy it to a new DC, and start the new DC from the snapshot's USN state (avoiding a full forest-wide sync). The IFM snapshot includes the directory data, the schema, the configuration NC, and the replication metadata (UTD vector, invocation IDs of all partners).

The framework SHALL NOT use VSS on Windows. Windows DCs SHALL use the same storage-engine-native / filesystem-level snapshot mechanism as Linux and macOS DCs. This eliminates the VSS dependency and ensures cross-platform backup format compatibility (a backup taken on a Windows DC is restorable on a Linux DC and vice versa).

The framework SHALL support backup retention and rotation via a configurable policy (e.g. "keep 7 daily, 4 weekly, 12 monthly backups"). The retention policy is enforced by the backup-coordinator service.

For AD-interop mode, the framework SHALL expose a VSS-writer-equivalent interface on Windows DCs that invokes the storage-engine-native backup mechanism under the hood — Windows Backup and VSS-aware backup tools (Commvault, Veeam) can invoke this interface and get a transactionally-consistent snapshot. This interface is a Windows-only shim; Linux and macOS DCs use the framework's native CLI/REST backup API directly.

**Concrete specification**:

- The framework SHALL implement a backup-coordinator service that performs: quiesce → snapshot → metadata-record → resume → verify.
- The snapshot mechanism SHALL be storage-engine-native (preferred) or filesystem-level (fallback). The choice is configured at deployment time based on the storage engine and filesystem available.
- Snapshot metadata SHALL include: invocation ID, USN cursor, timestamp, storage-engine version, framework version, NC heads and their UTD vectors.
- Restore SHALL generate a new `invocationId`, persist it, and signal partners to re-seed.
- Authoritative restore SHALL mark specific objects (or subtrees) with a version counter that supersedes partners' versions.
- IFM SHALL produce a portable snapshot (directory data + schema + configuration + replication metadata) that can be copied to a new DC and started without a full forest-wide sync.
- The framework SHALL NOT use VSS for backup; Windows DCs SHALL use the same mechanism as Linux/macOS DCs.
- For AD-interop mode on Windows, the framework SHALL expose a VSS-writer-equivalent shim that invokes the native backup mechanism.
- The framework SHALL expose `adrian-backup create`, `adrian-backup restore`, `adrian-backup ifm-create`, and `adrian-backup list` CLI commands.
- The framework SHALL expose `POST /api/v1/backup/create`, `POST /api/v1/backup/restore`, `POST /api/v1/backup/ifm`, and `GET /api/v1/backup/list` REST endpoints.
- Backup retention policy SHALL be configurable (default: 7 daily, 4 weekly, 12 monthly).
- Performance target: a snapshot of a 10M-object directory SHALL complete in <60 seconds (storage-engine-native) or <10 seconds (filesystem-level).

## Rationale

VSS is Windows-only and tightly coupled to ESE. The framework's storage engine is not ESE (gated by ORQ-011/012/013/014); forcing VSS compatibility would either require emulating ESE's VSS writer interface (fragile, version-dependent) or running the framework on Windows only (unacceptable for cross-platform). The clean-slate approach — storage-engine-native backup + filesystem-level snapshots — is portable, well-supported on all platforms, and matches the operational pattern of modern containerized infrastructure.

Three alternatives were considered:

**Alternative A — VSS-only on Windows; storage-engine-native on Linux/macOS.** The advantage is AD-interop with Windows Backup and existing VSS-aware backup tools (Commvault, Veeam). The disadvantage is two backup mechanisms with different semantics (VSS snapshots are volume-level; storage-engine-native snapshots are database-level), making cross-platform backup-restore fragile (a Windows-taken VSS backup is not restorable on a Linux DC). Rejected as the primary mechanism; ADOPTED as a Windows-only shim for AD-interop.

**Alternative B — CRIU (Checkpoint/Restore In Userspace) for container-native snapshots.** CRIU captures process state, including open file descriptors and memory. The advantage is process-level snapshot (the DC process is checkpointed and can be restored from the checkpoint). The disadvantage is that CRIU does not capture replication state cleanly — restoring a DC from CRIU skips the boot sequence (which is needed to re-register RPC endpoints, re-publish SRV records, etc.), and CRIU's process-state snapshot may include stale network connections that break on restore. Rejected for v1; CRIU is interesting for container-native deployments but the boot sequence is essential for DC correctness.

**Alternative C — Object-store-based backup (S3 with versioning).** The directory state is serialized to an object store (S3, GCS, Azure Blob) with versioning; restore reads the versioned object. The advantage is durability (S3's 11 nines) and portability (any DC can restore from any region). The disadvantage is backup time (serializing 10M objects to S3 takes minutes) and restore time (reading 10M objects from S3 takes minutes). Rejected for v1 as the primary mechanism; may be adopted as an off-site backup tier in addition to local snapshots.

External evidence: [RocksDB Checkpoints](https://github.com/facebook/rocksdb/wiki/Checkpoints) documents the `CreateCheckpoint()` API; [SQLite Online Backup API](https://www.sqlite.org/backup.html) documents `sqlite3_backup_*`; [LMDB `mdb_env_copy2`](https://github.com/LMDB/lmdb/blob/mdb.master/libraries/liblmdb/lmdb.h) documents the LMDB snapshot API; [ZFS Send/Receive](https://openzfs.github.io/openzfs-docs/man/8/zfs-send.8.html) documents the ZFS snapshot replication mechanism. All major storage engines and modern filesystems support snapshot APIs; the framework's design is portable across them.

The cost of this decision is the backup-coordinator service (~3000 lines of code) plus the per-storage-engine adapter (~500 lines each). The Windows VSS shim is an additional ~1000 lines for AD-interop. The bulk of the work is the metadata recording and the restore `invocationId` reset logic.

## Consequences

**Positive**: Cross-platform backup-restore — a Windows-taken backup is restorable on a Linux DC and vice versa. No VSS dependency on Windows. Storage-engine-native snapshots are fast (<60 seconds for 10M objects; <10 seconds with filesystem-level snapshots). IFM enables rapid DC provisioning without full forest-wide sync.

**Negative**: Windows administrators accustomed to VSS-based backup tools (Windows Backup, Veeam, Commvault) must use the framework's native backup CLI/REST API OR the VSS-shim. The shim adds complexity and may have subtle compatibility issues with specific backup tools. The specific snapshot API depends on the storage engine choice (gated by ORQ-011/012/013/014) — until the storage engine is chosen, the implementation cannot be finalized.

**Neutral**: The backup-coordinator service is a new component that must be highly available (a single coordinator failure halts backups). The retention policy is configurable; deployments with strict retention requirements (e.g. financial services with 7-year retention) can configure accordingly.

**Implementation cost**: ~5 person-weeks for the backup-coordinator, per-storage-engine adapter, CLI/REST API, and IFM. The Windows VSS shim is an additional ~2 person-weeks for AD-interop. Total ~7 person-weeks; final implementation depends on ORQ-011/012/013/014 resolution.

**Operational impact**: Backup and restore are CLI/REST-driven, matching modern infrastructure patterns. IFM enables rapid DC provisioning in remote sites without WAN saturation. The VSS shim on Windows enables existing backup-tool integration for AD-interop deployments.

## Alternatives Considered

### Alternative 1: VSS-only on Windows; storage-engine-native on Linux/macOS

AD-interop with Windows Backup; two backup mechanisms with different semantics. Rejected as primary; ADOPTED as a Windows-only shim for AD-interop.

### Alternative 2: CRIU for container-native snapshots

Process-level snapshot; does not capture replication state cleanly. Rejected for v1; interesting for container-native deployments but the boot sequence is essential for DC correctness.

### Alternative 3: Object-store-based backup (S3 with versioning)

Durable and portable; backup and restore times are minutes (too slow for routine operations). Rejected as primary; may be adopted as an off-site backup tier in addition to local snapshots.

## Open Questions

- **DEFERRED to ORQ-011/012/013/014**: The specific backup API depends on the framework's storage-engine choice. RocksDB `CreateCheckpoint()`, SQLite `sqlite3_backup_*`, FoundationDB snapshot transactions, and LMDB `mdb_env_copy2()` are all candidates. The high-level decision (storage-engine-native + filesystem-level, no VSS) is confident; the specific API call is deferred. The gating ORQs are ORQ-011/012/013/014 (per [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md)).
- For the Windows VSS shim, what is the compatibility matrix with major backup tools (Windows Backup, Veeam, Commvault, Datto)? Requires integration testing; defer to a future testing ADR.
- Cross-reference PC-009 (tombstone lifetime, DEFERRED) — restoring a backup older than `tombstoneLifetime` causes quarantine. The framework's restore procedure SHALL detect this and warn the admin.
- Should the framework support cross-engine backup-restore (backup taken with RocksDB, restore to SQLite)? This would require a portable backup format (e.g. LDIF + replication metadata). Defer to a future portability ADR.

## Cross-capability impact

- **Operations**: Backup and restore are core ops tasks; the CLI/REST API replaces `wbadmin start systemstatebackup` and `ntdsutil ifm`. The retention policy is configurable per-deployment.
- **Migration**: AD-to-framework migration uses the framework's IFM to provision the first framework DC from an AD-taken LDIF snapshot.
- **KDC**: KDC key material (krbtgt account) is part of the directory and is included in the backup. Restore brings the KDC back to the snapshot state.
- **Cert Service**: CA database is a separate database (per ADR-062); CA backup is independent of directory backup.
- **File Gateway**: SYSVOL replication (PC-055, DEFERRED) is a separate replication concern; SYSVOL backup is independent of directory backup.
- **Security**: Backup encryption at rest is mandatory; the framework's backup format SHALL encrypt sensitive attributes (`unicodePwd`, KDS root key) with a per-deployment key.

## References

- [PC-020](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — VSS writer GUID, ESE database files, `ntdsutil ifm` procedure
- [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md) — USN rollback detection on restore, event 2095, `repadmin /kcc -resetinvocationid`
- [RocksDB Checkpoints](https://github.com/facebook/rocksdb/wiki/Checkpoints) — `CreateCheckpoint()` API
- [SQLite Online Backup API](https://www.sqlite.org/backup.html) — `sqlite3_backup_*`
- [ZFS Send/Receive](https://openzfs.github.io/openzfs-docs/man/8/zfs-send.8.html) — ZFS snapshot replication
