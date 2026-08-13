# TASKLIST 04 — DRSUAPI & Replication

**Domain**: DRSUAPI (MS-DRSR) replication protocol + Raft consensus + replication core
**Branch**: `domain-04-drsuapi-repl`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-drsuapi/src/lib.rs`
- `rust/crates/adrian-drsuapi/Cargo.toml`
- `rust/crates/adrian-raft/src/lib.rs`
- `rust/crates/adrian-raft/Cargo.toml`
- `rust/crates/adrian-repl-core/src/lib.rs`
- `rust/crates/adrian-repl-core/Cargo.toml`
- `rust/crates/adrian-repl-testkit/src/lib.rs`
- `rust/crates/adrian-repl-testkit/Cargo.toml`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `adrian-drsuapi` (2059 lines): Real MS-DRSR NDR codec for DRS_EXTENSIONS, UtdVectorExt, ReplEntInfV3. `drs_bind` + `drs_get_nc_changes` handlers real. 37 tests (1 ignored — FDB). 16 TODOs.
- `adrian-raft` (1602 lines): RPC receivers real, but **commits without quorum** (data loss on partition). 35 tests.
- `adrian-repl-core` (430 lines): `Replicator` trait, `UtdVector`, `ConflictRecord`. 6 tests.
- `adrian-repl-testkit` (120 lines): Test fixtures. 0 tests.

## Known Gaps

1. **`DrSuapiReplicator::get_changes`** (the `Replicator` trait impl) is still a documented stub returning `ReplicationError::Backend` — not wired to `drs_get_nc_changes_dispatch`.
2. **Raft commits without quorum** — the `commit_entry` function doesn't verify a quorum of append_entries acknowledgments before committing (data loss risk on network partition).
3. **Only 2 of 12 DRSUAPI opnums are real** — DRSBind (0x00) and DRSGetNCChanges (0x04). DRSUnbind, DRSReplicaSync, DRSCrackNames, DRSVerifyNames, DRSDomainControllerInfo, DRSGetReplInfo, DRSUpdateRefs, DRSReplicaAdd/Del/Modify are all stubs.
4. **No EXOP_REPL_SECRETS (DCSync) ACL gating (ADR-122)** — the DCSync mitigation is documented but not enforced.
5. **No tombstone GC (ADR-074)** — tombstone keys are real but the garbage-collection task that purges expired tombstones is not implemented.
6. **No linked-value replication (ADR-001)** — `REPLVALINF_V3` struct exists but LVR logic is not wired.

---

## Wave 1: Wire DrSuapiReplicator to drs_get_nc_changes_dispatch

**DoD**: `DrSuapiReplicator::get_changes` calls `drs_get_nc_changes_dispatch` and returns real replication data. Integration test with `InMemoryDirectoryStore` passes.

### Tasks

- T-101: Implement `DirectorySource` trait that walks subspace `0x01` with prefix `encode_object_prefix(Subspace::Objects, nc_head_dnt)`.
- T-102: Wire `DrSuapiReplicator::get_changes` to call `drs_get_nc_changes_dispatch(source, nc_head, usn_vector, max_objects)`.
- T-103: Add integration test: seed two `InMemoryDirectoryStore` instances, replicate from A → B, verify B has all objects.
- T-104: Add 3 tests (full replication, incremental replication with UTD vector, replication with no changes).
- T-105: Commit `Wave 1: Wire DrSuapiReplicator to drs_get_nc_changes_dispatch (+4 tests)`

## Wave 2: Raft quorum enforcement + leader election fix

**DoD**: Raft `commit_entry` requires a quorum of append_entries ACKs before committing. Leader election follows RFC §5.2 (split vote prevention).

### Tasks

- T-201: Fix `commit_entry` to count ACKs and only commit when `acks >= (peers / 2) + 1`.
- T-202: Fix leader election: a candidate must receive a quorum of votes before becoming leader.
- T-203: Add `Raft::install_snapshot` for log compaction (RFC §7).
- T-204: Add 5 tests (commit with quorum, commit rejected without quorum, leader election with 3 nodes, leader election with 5 nodes, partition recovery).
- T-205: Commit `Wave 2: Raft quorum enforcement + leader election fix (+5 tests)`

## Wave 3: DRSUAPI opnums — DRSUnbind, DRSReplicaSync, DRSCrackNames

**DoD**: 3 additional DRSUAPI opnums fully implemented with NDR encoding.

### Tasks

- T-301: Implement `IDL_DRSUnbind` (opnum 0x01) — releases the bind handle.
- T-302: Implement `IDL_DRSReplicaSync` (opnum 0x03) — triggers a replication cycle.
- T-303: Implement `IDL_DRSCrackNames` (opnum 0x0C) — converts between DN, SID, UPN, SPN formats.
- T-304: Add 6 tests (2 per opnum: request parsing + response generation, round-trip).
- T-305: Commit `Wave 3: DRSUAPI DRSUnbind + DRSReplicaSync + DRSCrackNames (+6 tests)`

## Wave 4: DCSync mitigation + tombstone GC + LVR

**DoD**: EXOP_REPL_SECRETS is ACL-gated per ADR-122. Tombstone GC runs on a schedule per ADR-074. Linked-value replication works per ADR-001.

### Tasks

- T-401: Implement ACL check on `EXOP_REPL_SECRETS` — only principals with `DS-Replication-Get-Changes-All` right (admin) can sync secrets. Emit audit event on denial (ADR-122).
- T-402: Implement `TombstoneGc` task — runs every 180 days (default tombstone lifetime), purges objects with `isDeleted=true` and `whenChanged < now - tombstone_lifetime`.
- T-403: Wire linked-value replication — `REPLVALINF_V3` records carry linked-attribute values (e.g. `member`), only deltas are replicated.
- T-404: Add 6 tests (DCSync denied for non-admin, DCSync audit event, tombstone GC purges expired, tombstone GC preserves active, LVR delta replication, LVR conflict resolution).
- T-405: Commit `Wave 4: DCSync mitigation + tombstone GC + linked-value replication (+6 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-drsuapi -p adrian-raft -p adrian-repl-core -p adrian-repl-testkit` — all tests pass
- `cargo clippy -p adrian-drsuapi -p adrian-raft -p adrian-repl-core -p adrian-repl-testkit -- -D warnings` clean
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
