# TASKLIST 05 — Storage & Identity

**Domain**: FoundationDB storage layer + identity mapping + RID pool allocation + backup/restore
**Branch**: `domain-05-storage-identity`
**Exclusive files** (DO NOT touch any other files):
- `rust/crates/adrian-storage-core/src/lib.rs`
- `rust/crates/adrian-storage-core/Cargo.toml`
- `rust/crates/adrian-storage-fdb/src/lib.rs`
- `rust/crates/adrian-storage-fdb/Cargo.toml`
- `rust/crates/adrian-storage-testkit/src/lib.rs`
- `rust/crates/adrian-storage-testkit/Cargo.toml`
- `rust/crates/adrian-identity-core/src/lib.rs`
- `rust/crates/adrian-identity-core/Cargo.toml`
- `rust/crates/adrian-identity-fdb/src/lib.rs`
- `rust/crates/adrian-identity-fdb/Cargo.toml`
- `rust/crates/adrian-identity-ridpool/src/lib.rs`
- `rust/crates/adrian-identity-ridpool/Cargo.toml`
- `rust/crates/adrian-identity-testkit/src/lib.rs`
- `rust/crates/adrian-identity-testkit/Cargo.toml`

**Base**: v0.7.0 (commit `7f42127` on `main`, 970 tests passing)

---

## Current State (v0.7.0)

- `adrian-storage-core` (946 lines): `DirectoryStore` trait, `Object`, `Attribute`, `DistinguishedName`, tuple-layer key encoding. 11 tests. 2 TODOs.
- `adrian-storage-fdb` (1419 lines): `FdbDirectoryStore` with `fdb` feature flag (gated by libclang). In-memory fallback real. 17 tests. **3 ignored** (require real FDB cluster).
- `adrian-storage-testkit` (943 lines): `InMemoryDirectoryStore` (snapshot-isolated). 24 tests.
- `adrian-identity-core` (248 lines): `IdentityMapping` trait, SID/UID/GID mapping. 4 tests. 4 TODOs.
- `adrian-identity-fdb` (669 lines): FDB-backed identity mapping. 21 tests.
- `adrian-identity-ridpool` (1227 lines): RID pool allocation per ADR-077. 35 tests. 1 ignored (FDB).
- `adrian-identity-testkit` (110 lines): In-memory identity mapping. 0 tests.

## Known Gaps

1. **Real FDB path never compiled** — the `fdb` feature requires libclang for `foundationdb-sys` bindgen. All tests run against the in-memory fallback. CI has no `cargo check --features fdb` step.
2. **No backup/restore (ADR-010/034/059)** — 3 ADRs specify backup/restore (snapshot, PITR, reject-repair) but no code exists.
3. **No tombstone GC task** — tombstone keys are real but the GC that purges expired tombstones is not scheduled (also referenced in TASKLIST-04).
4. **No transaction retry with backoff** — `FdbTxn` doesn't retry on conflict (`1020` conflict error); just returns the error.
5. **No subspace migration** — can't migrate data between subspaces (needed for schema upgrades).
6. **`adrian-identity-testkit` has 0 tests** — the in-memory identity mapping testkit is untested.

---

## Wave 1: Install FDB client + compile real path

**DoD**: `cargo check --features fdb` passes with libclang + FDB C client installed. Real FDB integration tests are un-ignored and pass against a local FDB cluster.

### Tasks

- T-101: Install libclang-dev and FDB C client 7.3.x (download from https://github.com/apple/foundationdb/releases).
- T-102: Run `cargo check --features fdb -p adrian-storage-fdb` — verify it compiles.
- T-103: Start a local FDB server (single-node) for integration tests.
- T-104: Un-ignore the 3 FDB integration tests in `adrian-storage-fdb` and verify they pass.
- T-105: Un-ignore the 1 FDB test in `adrian-identity-ridpool` and verify it passes.
- T-106: Commit `Wave 1: Real FDB path compiles + integration tests pass (+4 tests un-ignored)`

## Wave 2: Backup/restore (ADR-010/034/059)

**DoD**: Snapshot backup + PITR (point-in-time-recovery) + reject-repair mode implemented.

### Tasks

- T-201: Implement `BackupManager::create_snapshot(path)` — creates a consistent FDB snapshot to disk.
- T-202: Implement `BackupManager::restore_from_snapshot(path)` — restores from a snapshot.
- T-203: Implement PITR — `BackupManager::restore_to_timestamp(ts)` — replays the mutation log up to `ts` (ADR-034).
- T-204: Implement reject-repair mode — `DirectoryStore::set_reject_repair(true)` causes all writes to fail with `StorageError::RejectRepair` (ADR-034).
- T-205: Add 6 tests (snapshot round-trip, restore from snapshot, PITR to past timestamp, reject-repair blocks writes, backup integrity check, incremental backup).
- T-206: Commit `Wave 2: Backup/restore — snapshot + PITR + reject-repair (ADR-010/034/059) (+6 tests)`

## Wave 3: Transaction retry + subspace migration

**DoD**: FDB transactions retry on conflict with exponential backoff. Subspace migration tool exists.

### Tasks

- T-301: Implement `FdbTxn::run_with_retry<F>(f)` — retries `f` up to 3 times on conflict (error 1020), with exponential backoff (10ms, 50ms, 250ms).
- T-302: Add a `retry_on_conflict` integration test that simulates two concurrent transactions.
- T-303: Implement `migrate_subspace(old_prefix, new_prefix)` — copies all keys from old subspace to new, then atomically swaps the prefix pointer.
- T-304: Add 3 tests (retry succeeds on conflict, retry exhausted after 3 attempts, subspace migration round-trip).
- T-305: Commit `Wave 3: Transaction retry with backoff + subspace migration (+4 tests)`

## Wave 4: Identity testkit + SID/UID mapping completeness

**DoD**: `adrian-identity-testkit` has real tests. SID ↔ UID/GID mapping handles all edge cases per ADR-110.

### Tasks

- T-401: Add 8 tests to `adrian-identity-testkit` (SID→UID round-trip, UID→SID, GID mapping, well-known SIDs, overflow handling, concurrent access, schema validation, negative tests).
- T-402: Implement `IdentityMapping::resolve_sid_history(sid)` — follows sIDHistory links per ADR-126.
- T-403: Implement `IdentityMapping::lookup_by_upn(upn)` — UPN → SID/UID resolution.
- T-404: Add 4 tests (sIDHistory resolution, UPN lookup, UPN uniqueness, cross-domain SID lookup).
- T-405: Commit `Wave 4: Identity testkit + sIDHistory/UPN resolution (+12 tests)`

---

## Final DoD (all waves)

- `cargo test -p adrian-storage-core -p adrian-storage-fdb -p adrian-storage-testkit -p adrian-identity-core -p adrian-identity-fdb -p adrian-identity-ridpool -p adrian-identity-testkit` — all tests pass
- `cargo check --features fdb -p adrian-storage-fdb` compiles (if libclang available)
- `cargo clippy` clean for all 7 crates
- `cargo fmt --all --check` clean
- Branch pushed, PR opened against `main`
