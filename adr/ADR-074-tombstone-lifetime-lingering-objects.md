---
title: "ADR-074: Tombstone Lifetime, Lingering Object Detection, and Raft Log Truncation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-009
severity: high
unblocked_by: Workshop Decision 1 (ORQ-001/002/003/004) and Workshop Decision 2 (ORQ-011/012/013/014)
tags: [adr, core-directory, tombstones, lingering-objects, garbage-collection, raft-log-truncation, recycle-bin]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-01-replication-protocol.md
  - ../workshop/decision-02-storage-engine.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-071-replication-model.md
  - ./ADR-073-storage-engine.md
last_updated: 2026-08-13
---

# ADR-074: Tombstone Lifetime, Lingering Object Detection, and Raft Log Truncation

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-001/002/003/004 (replication) and ORQ-011/012/013/014 (storage). It is now unblocked by [Workshop Decision 1 (Hybrid Replication)](../workshop/decision-01-replication-protocol.md) and [Workshop Decision 2 (FoundationDB Storage Engine)](../workshop/decision-02-storage-engine.md).

## Context

AD tombstones objects instead of deleting them outright: when an object is deleted, the DSA sets `isDeleted=TRUE`, moves the object to `CN=Deleted Objects,<NC>` (a normally-hidden container), preserves a minimal attribute set (`objectGUID`, `objectSid`, `sIDHistory`, `lastKnownParent`, `member` for tombstoned groups), and strips all other attributes. The tombstone persists for `tombstoneLifetime` days (default 180 days since Server 2003 SP1; older forests defaulted to 60). After `tombstoneLifetime`, the tombstone is garbage-collected (`ntdsa.dll!GarbageCollection` task), per [PC-009](../catalog/01-core-directory.md#pc-009--tombstone-lifetime-and-lingering-object-cleanup-must-be-designed) and [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md).

If a partner DC is offline longer than `tombstoneLifetime`, strict replication consistency refuses to re-sync (event 2042 — "The DC has been offline for too long to be brought up-to-date"). The admin must run `repadmin /removelingeringobjects <src-dc> <dst-dc> <nc-dn> /advisory` to scan for stale objects, then run without `/advisory` to actually remove them. Without strict consistency, the stale DC could reintroduce deleted objects (a "lingering object" — an object deleted on one DC but still present on the stale DC, which then replicates it back to the rest of the forest). Lingering objects are subtle: they may have stale group memberships, stale SPNs, stale passwords — all of which cause intermittent auth failures and security risks.

A new framework needs an equivalent design or accepts eventual-consistency risks. CRDT-based replication handles tombstones natively; Raft-based replication uses log truncation. Both approaches must answer: how long to retain tombstones? how to detect a partner that's been offline longer than the retention period? how to clean up lingering objects?

**Unblocking decisions.** [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) specifies strict replication consistency defaults to `true` in both modes; tombstoneLifetime 180 days; Raft mode truncates log entries older than tombstoneLifetime. [Workshop Decision 2](../workshop/decision-02-storage-engine.md) specifies tombstones in FDB subspace `0x07`; GC task scans and clears tombstones older than `tombstoneLifetime`; strict serializable transactions eliminate the LWW-ambiguity that AD's tombstone model has. This ADR translates both decisions into the concrete tombstone/GC implementation.

## Decision

The framework SHALL implement AD-compatible tombstones with `tombstoneLifetime` defaulting to 180 days, configurable per-NC. Tombstones are stored in FDB subspace `0x07` (per Decision 2). The framework SHALL implement strict replication consistency (lingering-object detection) in both AD-interop and native modes. In native (Raft) mode, the Raft log truncation policy SHALL retain entries for at least `tombstoneLifetime` to support restored-DC catch-up. The framework SHALL support the AD Recycle Bin (two-stage delete) for AD-interop compatibility.

**Concrete specification**:

- Tombstone creation: when an object is deleted, the framework SHALL set `isDeleted=TRUE`, move the object to `CN=Deleted Objects,<NC>`, preserve `objectGUID`, `objectSid`, `sIDHistory`, `lastKnownParent`, `member` (for tombstoned groups), and strip all other attributes. The tombstone is written in the same FDB transaction as the deletion (atomic). The tombstone's `whenChanged` is the deletion timestamp.
- Tombstone storage: tombstones live in FDB subspace `0x07` with key `(0x07, nc_head_dnt, deleted_object_dnt) → (preserved_attributes_bytes, when_deleted)`. The `0x01` (objects) subspace row for the deleted object is removed atomically with the `0x07` row write.
- `tombstoneLifetime`: configurable per-NC via the `tombstoneLifetime` attribute on `CN=Directory Service,CN=Windows NT,CN=Services,...`. Default 180 days. The framework SHALL NOT delete tombstones younger than `tombstoneLifetime`.
- Garbage collection: a periodic GC task (default 12-hour cycle, matching AD's `GarbageCollection` task) SHALL scan the `0x07` subspace and delete tombstones older than `tombstoneLifetime`. The GC task is a single FDB transaction per batch of 1,000 tombstones (batching avoids long-running transactions). The GC task SHALL also delete the corresponding `0x02` (linktable) rows for the deleted object (link-value cleanup).
- Recycle Bin (two-stage delete): if the forest functional level ≥ Windows Server 2008 R2 (AD-interop) or the framework's native recycle-bin flag is enabled, deleted objects go through two stages: deleted (recyclable) → recycled (non-recyclable but still present) → physically deleted. The framework SHALL support `Restore-ADObject`-equivalent to revive a deleted-but-not-recycled object. The recycled stage persists for an additional `deletedObjectLifetime` (default 180 days, configurable). Total tombstone retention is `tombstoneLifetime + deletedObjectLifetime` (default 360 days) when Recycle Bin is enabled.
- Strict replication consistency: defaults to `true` in both AD-interop and native modes. The framework SHALL reject replication from a partner whose UTD vector is older than `tombstoneLifetime` on the destination NC head. The rejection SHALL log an event equivalent to AD's event 2042 ("The DC has been offline for too long to be brought up-to-date") with the partner's DN, NC DN, and the age of the partner's UTD vector.
- Lingering-object detection: the framework SHALL expose `adrian-repl remove-lingering-objects <src-dc> <dst-dc> <nc-dn> [--advisory]` CLI equivalent to `repadmin /removelingeringobjects`. With `--advisory`, the CLI scans and reports; without, the CLI actually removes. The CLI scans the destination DC's NC for objects whose `whenChanged` is older than the source DC's UTD vector for the originating DC — these are lingering objects.
- Raft log truncation (native mode): the `RaftReplicator` SHALL retain Raft log entries for at least `tombstoneLifetime` (default 180 days) before truncation. The truncation policy is: entries older than `tombstoneLifetime` AND already applied to a Raft snapshot are eligible for truncation. This ensures a restored-DC (whose log was lost) can catch up by replaying entries from the last `tombstoneLifetime`. The truncation runs as a periodic task (default 24-hour cycle).
- Raft snapshot: when the Raft log is truncated, the Raft state machine snapshot SHALL be an FDB transaction-consistent read of the entire directory (using FDB's snapshot isolation). The snapshot is stored as a binary blob in FDB subspace `0x0B` (raft_snapshots). New voters catch up by loading the latest snapshot, then replaying log entries after the snapshot's index.
- Restored-DC catch-up: a DC restored from backup (per ADR-010) SHALL rejoin the Raft cluster as a fresh voter (its old `invocationId` is reset; per Decision 1). The Raft leader SHALL ship the latest snapshot to the restored DC, then replicate log entries forward. If the restored DC's lost log entries are still within `tombstoneLifetime`, the cluster's log retains them and catch-up is automatic. If the restored DC's lost entries are older than `tombstoneLifetime`, the cluster's log has truncated them, but the snapshot captures the post-deletion state — the restored DC catches up to the snapshot, missing the intermediate tombstone events but arriving at the correct final state.
- `GET /api/v1/replication/tombstones` (per ADR-061) SHALL return per-NC tombstone count, oldest tombstone age, and next GC run time.
- Performance target: the GC task SHALL process ≥100K tombstones per hour (per FDB transaction batch of 1,000 × 100 batches/hour). A 10M-object forest with 1% tombstone rate generates 100K tombstones per 180 days ≈ 23 tombstones/hour, well within the GC capacity.

## Rationale

Tombstones exist in AD because AD replicates eventually — a partner DC may be offline when an object is deleted, and the deletion must be replicated to that partner when it comes back online. Without tombstones, the deletion would never propagate (the object is gone, so there's nothing to replicate). The tombstone is the "I was deleted" marker that propagates.

The 180-day default `tombstoneLifetime` is a compromise: long enough to cover most DC outage scenarios (DC replacement, branch-office WAN outage, disaster recovery), short enough to limit storage overhead. The framework inherits this default for AD-interop compatibility.

In Raft mode, the Raft log serves the same purpose as tombstones — the log records every operation, including deletes, and is replayed on catch-up. The framework's truncation policy (retain entries for `tombstoneLifetime`) ensures a restored DC can catch up. The Raft snapshot is the compaction mechanism: once entries are captured in a snapshot, they can be truncated.

Strict replication consistency (quarantine long-offline partners) is a defence against lingering objects. Without it, a stale DC that comes back online replicates its stale state forward, reintroducing deleted objects. The framework defaults to strict (matching AD's `StrictReplicationConsistency = 1` registry equivalent) because the cost of lingering objects (intermittent auth failures, security risks) exceeds the cost of admin intervention.

External evidence: AD's tombstone model is documented in [MS-ADTS §3.1.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) and [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md). The Recycle Bin is documented in MS-ADTS §3.1.1.5.3. CockroachDB and TiKV use similar log-truncation-with-snapshot policies for their Raft-based replication. The 180-day default matches AD's Server 2003 SP1+ default; older forests (60 days) are documented as a migration concern.

## Consequences

**Positive**: AD-interop compatibility — the framework produces AD-compatible tombstones on the wire. Strict replication consistency defaults to safe (lingering-object quarantine). Recycle Bin enables `Restore-ADObject` for accidental deletes. Raft log truncation policy ensures restored-DC catch-up.

**Negative**: Tombstone storage overhead — ~200 bytes per tombstone (preserved attributes + metadata). For a 10M-object forest with 1% tombstone rate over 180 days, this is ~10M × 1% × 200 = 20 MB — negligible. The Raft log retention adds storage overhead in native mode (~1 KB per log entry × 10M entries over 180 days = 10 GB — manageable on FDB).

**Neutral**: The GC task runs in the background (12-hour cycle); admins see no impact. The Raft log truncation runs in the background (24-hour cycle). The `adrian-repl remove-lingering-objects` CLI is for manual intervention when strict consistency quarantines a partner.

**Cost**: ~4 person-weeks for tombstone creation, GC task, Recycle Bin, lingering-object detection CLI, and Raft log truncation policy.

**Operational impact**: `tombstoneLifetime` is configurable per-NC (matching AD). The GC task is monitored via Prometheus/OTel (tombstones processed per hour, GC lag). Restored-DC catch-up is automatic in native mode (Raft snapshot + log replay); in AD-interop mode, the restored DC must re-replicate via DRSUAPI (per ADR-070).

## Alternatives Considered

### Alternative 1: No tombstones (immediate physical delete)

Simpler model — deleted objects are gone. But breaks replication: a partner DC offline during the delete never sees the deletion, and on reconnect, the deleted object replicates back as a "new" object (the source DC re-creates it because the partner says "I don't have this object"). This is the lingering-object problem in its worst form. Rejected for both AD-interop (incompatible) and native (Raft log alone would handle deletes, but AD-interop compatibility is required).

### Alternative 2: CRDT tombstones (explicit delete-tokens in the operation log)

CRDTs use explicit delete-tokens that tombstone the value. Conflict-free by construction. But CRDT tombstones do not map cleanly to AD's `PROPERTY_META_DATA_EXT` four-tuple, requiring synthesis at the wire boundary (per Decision 1's rejection of the CRDT-shim). Rejected: complexity is unjustified given LWW on per-value metadata is sufficient and Raft provides a stronger model for native mode.

### Alternative 3: MVCC time-travel queries (no tombstones; deleted objects accessible via time-travel)

Use FDB's MVCC to support time-travel queries — deleted objects are gone from the current view but accessible via historical reads. The advantage is no tombstone storage overhead. The disadvantage is breaking AD-interop (AD tools expect tombstones on the wire, not time-travel queries). Rejected for v1; may be revisited for native-only deployments as a value-add feature.

## Open Questions

- Should the framework support per-NC `tombstoneLifetime` (different lifetimes for different NCs)? AD supports this. Default: yes, per-NC configurable. Confirm in implementation.
- For the Raft log truncation, what is the snapshot frequency? Too frequent → snapshot overhead; too infrequent → restored-DC catch-up reads many log entries. Default: snapshot every 1M log entries or every 7 days, whichever comes first. Confirm with benchmark.
- For the Recycle Bin in native mode, should the framework expose a `Restore-ADObject`-equivalent CLI? Yes, for parity with AD-interop mode. The CLI is `adrian-directory restore --object <dn>`.

## Cross-capability impact

- **KDC**: KDC's krbtgt key (per ADR-015) tombstones on rotation (the old key is tombstoned, not deleted, to allow decryption of existing TGTs until expiry). The tombstone GC must not delete krbtgt tombstones younger than the maximum TGT lifetime (default 10 hours).
- **Auth Provider**: NTLM hash changes tombstone the old hash; same GC consideration.
- **Policy Engine**: GPO deletions tombstone; the GPC (Group Policy Container) tombstone replicates via DRSUAPI (AD-interop) or Raft (native).
- **Cert Service**: Published certificate deletions tombstone; the CA database (separate FDB subspace) handles its own deletion lifecycle.
- **Operations**: GC task is a monitored background job. `tombstoneLifetime` is a deployment-configurable property. Restored-DC catch-up is part of the disaster-recovery runbook (per ADR-010).
- **Migration**: AD-to-framework migration preserves tombstoneLifetime; tombstones from AD are migrated as framework tombstones.
- **Security**: Lingering-object detection is a defence against privilege-escalation via stale group memberships. The `adrian-repl remove-lingering-objects` CLI is the operational mitigation.

## References

- [PC-009](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 1 — Hybrid Replication](../workshop/decision-01-replication-protocol.md) — strict replication consistency, tombstoneLifetime 180 days, Raft log truncation
- [Workshop Decision 2 — FoundationDB Storage Engine](../workshop/decision-02-storage-engine.md) — tombstones in FDB subspace `0x07`, strict serializable transactions eliminate LWW-ambiguity
- [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md) — tombstone lifetime, lingering object detection, event 2042, `repadmin /removelingeringobjects`
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — `GarbageCollection` task, tombstone attribute preservation
- [MS-ADTS §3.1.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — tombstone lifetime, Recycle Bin, lingering objects
- [ADR-071: Replication Model](./ADR-071-replication-model.md) — Raft log truncation policy
- [ADR-073: Storage Engine](./ADR-073-storage-engine.md) — FDB subspaces
- [ADR-010: Backup/Restore Snapshots](./ADR-010-backup-restore-snapshots.md) — restored-DC catch-up via invocationId reset
