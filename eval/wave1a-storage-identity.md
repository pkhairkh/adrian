# Wave 1a — Storage & Identity Layer Audit

**Auditor**: Sub-agent E1-a
**Date**: 2026-08-13
**Scope**: 10 crates (storage-core, storage-fdb, storage-testkit, identity-core, identity-fdb, identity-ridpool, identity-testkit, sid, repl-core, repl-testkit)
**Repo HEAD**: `dadc4ca` on `main` (v0.5.0)
**Total LoC audited**: 7,127 lines across 10 crates

## Executive Summary

The storage + identity layer is a **mixed bag**: foundational types (`adrian-sid`, `adrian-storage-core`, `adrian-repl-core`) are well-engineered and near production-ready, while the FDB-backed implementations (`storage-fdb`, `identity-fdb`, `identity-ridpool`) are functional but carry an **unverifiable production risk** because the real `foundationdb` code path is explicitly not compile-tested (no libclang in the dev sandbox). Two testkit crates (`identity-testkit`, `repl-testkit`) ship with **zero tests**, which is the single biggest test-coverage gap in this wave. No `unsafe` code exists anywhere (every crate carries `#![forbid(unsafe_code)]`). Headline numbers: 14 total TODOs across the layer (most are aspirational pointers to other crates, not actual stubs), 156 tests (heavily concentrated in `sid`, `identity-ridpool`, `storage-testkit`), 0 unsafe blocks. Average production readiness: **3.4 / 5**.

The biggest architectural risk is the **dual code-path pattern**: every "production" crate (storage-fdb, identity-fdb, identity-ridpool) ships a default build that wraps `InMemoryDirectoryStore` from the testkit. This means `cargo test` passes even though the `foundationdb` API calls in the `real_fdb` submodule have never been compiled. A CI step with `--features fdb` + libclang + a real FDB cluster is **mandatory** before any production claim.

## Per-Crate Findings

### adrian-storage-core
- **Status**: REAL_COMPLETE
- **Test quality**: BEHAVIORAL_REAL (11 tests — key layout, sort order, round-trips, strinc carry, error rejection)
- **TODOs**: 2 (both in `DistinguishedName::parent()` / `FromStr` — RFC 4514 + ADR-005 well-known container GUID parsing is simplistic)
- **LoC**: ~946
- **Production readiness**: 4/5 — solid abstraction layer; DN parsing is naive (find first comma, split) but explicitly deferred to the schema-cache layer
- **Security concerns**: None. No unsafe. The `strinc` algorithm correctly handles the all-`0xFF` edge case by returning `None`. Sentinel attribute IDs (`0xFFFF_FFFx`) are well-named constants.
- **What's missing**: RFC 4514 DN validation (acknowledged TODO); ADR-005 well-known container GUID resolution (acknowledged TODO); a `TryFrom<u8>` for `Subspace` (the `subspace_from_u8` helper in `storage-fdb` silently falls back to `Subspace::Objects` for unknown bytes).
- **Notes**: The `DirectoryTransaction` trait's `allocate_dnt` default impl has an explicit workaround for the testkit's lack of read-your-writes on staged atomic-adds (lines 619-645). The workaround is correct but introduces a subtle coupling: any future backend that DOES model read-your-writes for atomic-adds (like real FDB) would still get the locally-computed value, which happens to match — so the workaround is safe but the comment is essential reading.

### adrian-storage-fdb
- **Status**: REAL_PARTIAL (real FDB code path is **not compile-tested** per crate-level docs line 778: *"It is NOT compile-tested in this sandbox (libclang is not available)"*)
- **Test quality**: BEHAVIORAL_REAL for the in-memory fallback path (20 tests — put/get round-trips, DNT allocation, tombstones, multi-valued attrs, atomic-adds, idempotency); NONE for the real FDB path (`#[ignore]`-gated, requires `--features fdb` + running cluster)
- **TODOs**: 0
- **LoC**: ~1419
- **Production readiness**: 3/5 — the fallback path is solid; the real FDB path is best-effort and likely has compile errors
- **Security concerns**: `std::mem::forget(_guard)` in `RealFdbBackend::connect` (line 808) intentionally leaks the FDB network boot guard. This is the recommended pattern per the `foundationdb` crate docs (the network runs forever once booted), but it means the FDB network thread is never cleanly shut down — fine for a long-running service, problematic for short-lived test processes.
- **What's missing**:
  - **Compile-verify the `real_fdb` module** (libclang + `cargo check --features fdb`). This is the single highest-risk item in the audit.
  - **Retry-on-conflict loop**: the `StorageError::Conflict` docstring (line 277) claims "Retried automatically by `FdbDirectoryStore`'s retry loop" but no such loop exists in `put`/`delete` — errors are surfaced directly to the caller.
  - **`get_range` semantics**: `RealFdbReadTxn::get_range` uses `trx.get_ranges()` (plural — paginated) which may behave differently from the in-memory path's single-shot `BTreeMap::range()`. Should use `trx.get_range()` (singular) for byte-for-byte compatibility.
  - **Real FDB path's `tombstone` impl**: hardcoded `nc_head_dnt = 1` (line 386) and `when_deleted = 0` (line 387) — placeholders that need to be replaced with real NC-head computation and `chrono::Utc::now().timestamp()`.
- **Notes**: The legacy `encode_object_key(subspace_u8, ...)` shim (lines 965-968) silently maps unknown bytes to `Subspace::Objects` — this is a defensive fallback but masks caller bugs. The `Backend` enum and `FdbTxn` wrapper are a clean abstraction over the two code paths.

### adrian-storage-testkit
- **Status**: REAL_COMPLETE
- **Test quality**: BEHAVIORAL_REAL (24 tests — CRUD, snapshot isolation, read-your-writes, write-set overlay on range reads, atomic-add aggregation, idempotency, batch of 100 objects, re-put preserving DNT)
- **TODOs**: 0
- **LoC**: ~943
- **Production readiness**: 4/5 — solid for a testkit; the dual-interface design is a known limitation
- **Security concerns**: None. `Mutex::lock().unwrap()` and `RwLock::read().unwrap()` will panic on poison — acceptable for a testkit (poison indicates a panic in another thread holding the lock, which is itself a test failure).
- **What's missing**:
  - **Unified high-level / low-level state**: the `DirectoryStore::put`/`delete`/`get` methods operate on `uuid_to_dnt`/`dn_to_dnt`/`objects` HashMaps and NEVER touch the `kv` BTreeMap. The `begin_read`/`begin_write` low-level interface operates ONLY on `kv`. Writes through one path are invisible to the other. This is acknowledged in the crate docs (lines 22-28) but is a subtle gotcha for any caller that mixes the two interfaces (the `FdbDirectoryStore` fallback path uses only the low-level kv interface, so it doesn't hit this — but other consumers might).
  - **Tombstone semantics**: hard-deletes from indexes (line 200-220); the crate docs explicitly say "tests that need tombstone semantics should use `adrian-storage-fdb` against a real FDB cluster". This is fine but means the testkit cannot be used to test AD Recycle Bin or lingering-object reconciliation.
  - **Conflict detection**: two concurrent `begin_write` transactions can both commit (no conflict detection) — the testkit models snapshot isolation but not strict serializability. Acknowledged in the `allocate_dnt` comment in `storage-core`.
- **Notes**: `InMemoryWriteTxn::commit` (line 376) acquires a single write lock on `target` and applies all staged writes + atomic-adds in one critical section — this gives atomicity but serializes all commits. Acceptable for unit tests, would not scale to production.

### adrian-identity-core
- **Status**: REAL_COMPLETE (trait + types + `uuid_to_uid` algorithm)
- **Test quality**: BEHAVIORAL_MINIMAL (4 tests — uid determinism, uid range, distinct UIDs for distinct UUIDs, PrincipalType variant matching — the last is STRUCTURAL_ONLY)
- **TODOs**: 4 (3 are pointers to "implement in another crate"; 1 is on `uuid_to_uid` but the function IS implemented — leftover TODO from when it was a stub)
- **LoC**: ~248
- **Production readiness**: 3/5 — functional abstraction layer, but tests are thin
- **Security concerns**: None. The `uuid_to_uid` algorithm uses `high ^ low` mixing which is weaker than a real hash but acceptable for a UID-mapping function (collision probability is documented as the trade-off).
- **What's missing**:
  - **Collision probability testing**: no test verifies the documented >10K-principal collision threshold.
  - **`uuid_to_uid` edge cases**: UUID-nil (all zeros) produces `uid = 0 ^ 0 = 0`, then `0 % (2^31 - 65536) + 65536 = 65536`. That's in range but worth a test.
  - **`From<StorageError> for IdentityError`**: missing — only `From<SidError>` is implemented, so storage errors must be stringified via `map_storage_err` (loses type info).
- **Notes**: The leftover TODO on `uuid_to_uid` (line 184) is misleading — the function is fully implemented. Should be removed.

### adrian-identity-fdb
- **Status**: REAL_PARTIAL (real FDB path is gated by `fdb` feature and NOT compile-tested, same as `storage-fdb`)
- **Test quality**: BEHAVIORAL_REAL for in-memory fallback path (21 tests — round-trips, conflict detection on SID/UUID reuse, idempotency, cache populate/invalidate, algorithmic uid fallback, allocate_uid); NONE for real FDB path
- **TODOs**: 0
- **LoC**: ~669
- **Production readiness**: 3/5 — same dual-path risk as `storage-fdb`; cache eviction is "arbitrary" not LRU
- **Security concerns**:
  - **Cache eviction is non-LRU**: `cache_put` (lines 175-195) evicts an arbitrary entry via `c1.keys().next().copied()` when at capacity. The crate docs claim "in-memory LRU cache" but the fallback impl is plain `HashMap` with arbitrary eviction. For the test path this is fine; for any production use of the fallback path it could cause cache thrashing.
  - **`.expect()` on slice lengths**: lines 252, 267, 295, 314, 362, 397 use `.expect("16-byte slice")` / `.expect("4-byte slice")` / `.expect("8-byte buf")`. These are guarded by `buf.len() == N` checks immediately before, so they can't panic on well-formed backend data — but a corrupted FDB value (e.g. truncated by a partial write) would panic the process instead of returning a `Backend` error.
- **What's missing**:
  - **Compile-verify the real FDB path** (same as `storage-fdb`).
  - **Real LRU cache** for the production path (the `lru` crate is a common choice).
  - **FDB watch-based cache invalidation**: the crate docs (line 9) claim "FDB watches (`tokio::sync::watch` channels) notify the cache on invalidation" but no watch logic exists in the code — the cache is only invalidated on local `remove()` calls.
  - **Retry-on-conflict**: same gap as `storage-fdb` — `insert` checks for conflicts in-transaction but doesn't retry on FDB `1020_not_committed`.
- **Notes**: `allocate_uid` (line 387) seeds the counter with 65535 so the first allocation returns 65536 — clever but worth a comment explaining the off-by-one. The `insert` method (line 299) does both forward and reverse conflict checks in a single transaction — this is correct and atomic.

### adrian-identity-ridpool
- **Status**: REAL_COMPLETE (both `FdbRidPoolAllocator` and `LocalRidAllocator` are fully implemented against the in-memory fallback; the real FDB path uses the same code via `RidBackend::Fdb`)
- **Test quality**: BEHAVIORAL_REAL (35 tests — sequential RIDs, batch extension, exhaustion threshold, reclaim, two-DC independence, persistence across clones, batch boundary crossing, assign_sid construction)
- **TODOs**: 0
- **LoC**: ~1227
- **Production readiness**: 4/5 — most thoroughly tested crate in this wave after `adrian-sid`
- **Security concerns**:
  - **`.expect("8-byte buf")`** on lines 397, 454, 614, 659, 706 — same panic-on-corruption risk as `identity-fdb`. Guarded by `buf.len() == 8` checks but could be `.ok_or(IdentityError::Backend(...))` for defense-in-depth.
  - **`scan_prefix` strinc workaround** (lines 227-237): the comment says "for our prefixes this is unreachable because every prefix ends in a non-0xFF byte" — but `domain_sid_bytes` could theoretically end in 0xFF (a SID with sub-authority `0xFFFFFFFF`). The fallback (`end.push(0x00)`) is correct but the "unreachable" claim is wrong. Worth a test.
- **What's missing**:
  - **Real FDB integration tests** for RID-master → non-RID-master batch dispensation (the `fdb_integration_rid_pool_exhaustion_triggers_batch_request` test is `#[ignore]`'d and empty).
  - **RID exhaustion error path**: `allocate` extends `last_allocated_rid` via `saturating_add(RID_BATCH_SIZE)` (line 429) but never returns `RidPoolExhausted` — the pool just keeps growing. The `IdentityError::RidPoolExhausted` variant exists but is never constructed.
  - **Warning threshold emission**: the `in_memory_exhaustion_warning_threshold_observed` test (line 1193) verifies the threshold is in state but no actual warning event is emitted when crossing it.
- **Notes**: The dual-source-of-truth design (state_key has `next_rid`, counter_key has the authoritative counter) is confusing — `state()` (line 498) reads both and uses the counter as authoritative, ignoring the state's `next_rid` field. The state's `next_rid` is essentially dead data after the first allocation. Worth refactoring to either (a) drop `next_rid` from the state struct or (b) keep them in sync.

### adrian-identity-testkit
- **Status**: REAL_COMPLETE (functional `HashMap`-backed impl)
- **Test quality**: NONE (0 tests)
- **TODOs**: 0
- **LoC**: ~110
- **Production readiness**: 3/5 — functional but untested; uses `sid.to_string()` as a HashMap key (perf concern on hot paths)
- **Security concerns**: `Mutex::lock().unwrap()` panics on poison — same as `storage-testkit`, acceptable for a testkit.
- **What's missing**:
  - **Tests** — this is the single biggest test-coverage gap in the audit. Even a basic round-trip test for `insert`/`lookup_sid`/`lookup_uuid`/`remove` would catch regressions.
  - **Algorithmic `lookup_uuid_from_uid` reverse**: the trait suggests `lookup_uid` falls back to `uuid_to_uid` for unstored UIDs, but there's no way to reverse the algorithmic mapping (`lookup_uuid_from_uid` returns `None` for unstored UIDs). This is correct (you can't reverse a hash) but worth documenting.
  - **Per-UUID uid storage**: no `insert_uid`/`allocate_uid` method — the testkit can only store UIDs that are explicitly inserted via the private `uuid_to_uid` HashMap (which has no public setter). Callers that want to test the directory-stored UID path have to use `identity-fdb` instead.
- **Notes**: The `lookup_uuid` impl uses `sid.to_string()` as the HashMap key (line 61) — this works because `Sid` implements `Display`, but it allocates a String on every lookup. Using `Sid` directly as the key (it implements `Hash` + `Eq`) would be faster and avoid the allocation.

### adrian-sid
- **Status**: REAL_COMPLETE
- **Test quality**: BEHAVIORAL_REAL (35 tests — round-trips for string/wire/serde forms, well-known constructors, classification helpers, hex/decimal authority boundary, max sub-authorities, 0 sub-authorities, trailing-bytes rejection, lowercase-s rejection, non-numeric sub-authority rejection, real-world AD SID parsing)
- **TODOs**: 0
- **LoC**: ~1015
- **Production readiness**: 5/5 — the most production-ready crate in this audit
- **Security concerns**: None. The `from_bytes` impl (line 312) rejects trailing bytes with `SidError::TrailingBytes` — explicit defence against SID-blob smuggling (a malformed SID with attacker-controlled appended data). The `from_str` impl rejects lowercase 's' prefix (per MS-DTYP), unsupported revisions, and authorities > 2^48. All edge cases are tested.
- **What's missing**: Nothing critical. Could add:
  - A `Sid::is_account_in_domain(&self, domain: &Sid) -> bool` helper for the `memberOf` back-link evaluation path.
  - A `Sid::to_windows_filetime()` / `from_windows_filetime()` pair (currently `last_write_timestamp` in `repl-core` is a raw `u64` Windows FILETIME with no helper).
- **Notes**: This is the gold standard for the rest of the audit — comprehensive tests, defensive parsing, clear documentation, no `unsafe`, no `unwrap()` in production code paths (only in tests). The `new_unchecked` const constructor (line 227) is correctly scoped to `pub(crate)` and used only by the well-known SID constructors whose sub-authority counts are statically known.

### adrian-repl-core
- **Status**: REAL_COMPLETE (trait + types + `resolve_conflict` algorithm)
- **Test quality**: BEHAVIORAL_MINIMAL (6 tests — conflict resolution paths for version/timestamp/usn/invocation-id tiebreaks + all-equal-local-wins + UtdVector construction)
- **TODOs**: 4 (1 on `resolve_conflict` — function IS implemented, TODO says "verify byte-identical to AD's resolver"; 3 are pointers to other crates: DrSuapiReplicator, RaftReplicator, InMemoryReplicator)
- **LoC**: ~430
- **Production readiness**: 4/5 — solid trait design; conflict resolver is implemented but not validated against AD's actual behavior
- **Security concerns**: None. The `ReplicationError` enum distinguishes transient vs permanent errors, schema mismatch, and invocation-ID mismatch (the latter is critical for ADR-074 lingering-object detection).
- **What's missing**:
  - **Property-based testing** of `resolve_conflict` to verify total ordering (commutativity, associativity, transitivity) — the current tests only cover the four tiebreak dimensions one at a time, not their interactions.
  - **Validation against AD's resolver**: the TODO on line 323 acknowledges this — the algorithm matches the documented AD behavior but hasn't been tested against a real Windows DC's conflict-resolution output.
  - **`ReplOperation` encoding/decoding**: no `to_bytes`/`from_bytes` for the enum — the `Replicator` trait takes owned `ReplicationPayload` values, so serialization is the implementer's responsibility. A canonical encoding would help with cross-DC wire compatibility.
- **Notes**: The `ReplOperation` enum (line 127) is well-designed — it covers AddObject, ModifyAttribute, DeleteObject, AddLink, DeleteLink, and TombstoneGC. The `TombstoneGC` variant is correctly NOT replicated (per ADR-074 — each DC runs GC independently). The leftover TODO on `resolve_conflict` (line 323) is misleading — the function is implemented; the TODO is about validation, not implementation.

### adrian-repl-testkit
- **Status**: REAL_PARTIAL (basic in-memory impl; the 4 TODOs on the methods are aspirational "do this properly per ADR-071" markers, but the methods work)
- **Test quality**: NONE (0 tests)
- **TODOs**: 4 (all on trait method impls — `get_changes` ignores cursor, `apply_changes` skips conflict resolution, `update_utd_vector` works but has TODO, `resolve_conflict` delegates to `repl-core::resolve_conflict`)
- **LoC**: ~120
- **Production readiness**: 2/5 — functional but untested, with acknowledged gaps in conflict resolution
- **Security concerns**: None (no security-sensitive operations).
- **What's missing**:
  - **Tests** — second-biggest test-coverage gap after `identity-testkit`. At minimum: insert via `apply_changes`, retrieve via `get_changes`, verify UTD vector advances.
  - **Cursor-based `get_changes`** (line 60 TODO): currently returns ALL operations ignoring the cursor's `highest_usn` — a real replication partner would only send changes since the cursor.
  - **Conflict resolution in `apply_changes`** (line 76 TODO): currently just `log.extend(batch.operations)` — no per-value conflict resolution against existing log entries. This means the testkit cannot be used to test conflict resolution end-to-end.
  - **`highest_usn` in `ReplicationPayload`** (line 68): hardcoded to 0 — should be the max USN of the returned operations.
- **Notes**: The crate is honest about its limitations — every method has a TODO explaining what's missing. The basic shape (logs keyed by NC head, UTD vectors keyed by NC head, invocation ID stored on the struct) is correct. The gap is in the semantics, not the structure.

## Cross-Cutting Observations

### 1. The "fdb feature flag" pattern is consistent but unverifiable
Every production crate (`storage-fdb`, `identity-fdb`, `identity-ridpool`) uses the same pattern: default build wraps `InMemoryDirectoryStore` and exercises the real tuple-layer key encoding; `--features fdb` enables the real `foundationdb` code path. **The real FDB code path has never been compiled** (no libclang in the dev sandbox — acknowledged in `storage-fdb` line 778). This means:
- All 156 tests in this wave pass against the in-memory fallback.
- The real FDB path likely has compile errors (wrong API signatures, missing trait impls, type mismatches with `foundationdb` 0.9).
- A CI step with `--features fdb` + libclang + a running FDB cluster is **mandatory** before any production deployment claim.

### 2. The dual-interface design of `InMemoryDirectoryStore` is a subtle gotcha
The testkit's `DirectoryStore::put`/`delete`/`get` methods operate on `uuid_to_dnt`/`dn_to_dnt`/`objects` HashMaps, while the low-level `ReadTxn`/`WriteTxn` interface operates on the `kv` BTreeMap. Writes through one path are invisible to the other. The `FdbDirectoryStore` fallback path uses ONLY the low-level kv interface (so it doesn't hit this), but any other consumer that mixes the two interfaces will see inconsistent state. This is documented in the testkit's crate-level docs (lines 22-28) but is easy to miss.

### 3. `.expect()` on slice lengths is a pervasive (minor) risk
The identity crates (`identity-fdb`, `identity-ridpool`) use `.expect("16-byte slice")` / `.expect("8-byte buf")` after `buf.len() == N` guards. These can't panic on well-formed backend data, but a corrupted FDB value (truncated write, partial commit) would panic the process. Defense-in-depth would use `.ok_or(IdentityError::Backend(...))?` instead. Not a security vulnerability per se, but a robustness gap.

### 4. Leftover TODOs on implemented functions are misleading
Three crates have TODO comments on functions that are actually implemented:
- `identity-core::uuid_to_uid` (line 184) — implemented, TODO says "implement per Decision 3"
- `repl-core::resolve_conflict` (line 323) — implemented, TODO says "verify byte-identical to AD's resolver"
- `repl-testkit::update_utd_vector` (line 89) — implemented, TODO says "implement per ADR-071"

These TODOs should either be removed (if the implementation is complete) or rephrased to reflect the actual remaining work (validation, testing, etc.).

### 5. Cache eviction is "arbitrary" not LRU
`identity-fdb`'s `cache_put` (lines 175-195) uses `HashMap::keys().next()` for eviction — explicitly "arbitrary" per the code comment. The crate docs claim "in-memory LRU cache". For the test fallback path this is acceptable; for any production use of the fallback path it could cause cache thrashing under load.

### 6. Two testkits ship with zero tests
`adrian-identity-testkit` (110 LoC) and `adrian-repl-testkit` (120 LoC) both have ZERO `#[test]` or `#[tokio::test]` items. This is the single biggest test-coverage gap in the audit. Even basic round-trip tests would catch regressions.

### 7. No `unsafe` code anywhere
All 10 crates carry `#![forbid(unsafe_code)]`. This is a strong positive signal — the entire storage + identity layer is safe Rust, with no `unsafe` blocks, no `union` types, no raw pointer dereferences.

### 8. Lock ordering is documented and consistent
`storage-testkit` documents its lock ordering (`uuid_to_dnt` → `dn_to_dnt` → `objects`, line 184) to keep the lock graph acyclic. Other crates using multiple locks (`identity-fdb`'s `cache_uuid_to_sid` + `cache_sid_to_uuid`) acquire them sequentially without nested locking — also safe.

## Risk Register

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| Real FDB code path has never been compiled (no libclang in dev sandbox) | **High** | **High** | Add CI step: `cargo check --features fdb` with libclang installed; add `#[cfg(feature = "fdb")]` integration tests against a Docker FDB cluster |
| `identity-testkit` and `repl-testkit` have zero tests — regressions will slip through | **High** | **Medium** | Add minimum-viable test suites (round-trip insert/lookup/remove for each testkit) |
| No retry-on-conflict loop in `FdbDirectoryStore::put`/`delete` despite docstring claiming one exists | **Medium** | **High** | Either implement the retry loop (with bounded retry budget) or fix the docstring on `StorageError::Conflict` |
| `.expect()` on slice lengths panics on corrupted FDB values | **Medium** | **Low** | Replace with `.ok_or(Backend(...))?` for defense-in-depth |
| Cache eviction is "arbitrary" not LRU in `identity-fdb` fallback path | **Low** | **Medium** | Use the `lru` crate for the production path; keep `HashMap` for the test fallback |
| `InMemoryDirectoryStore` dual-interface state divergence (high-level vs low-level kv) | **Low** | **Low** | Document the gotcha more prominently; consider unifying the two interfaces in a future refactor |
| `scan_prefix` strinc workaround in `identity-ridpool` claims "unreachable" but is reachable for SIDs with sub-authority `0xFFFFFFFF` | **Low** | **Low** | Add a test for the 0xFF-prefix case; the fallback (`end.push(0x00)`) is correct but untested |
| `resolve_conflict` in `repl-core` is not validated against AD's actual resolver behavior | **Medium** | **Medium** | Add property-based tests for total ordering; validate against a Windows DC's conflict-resolution output if possible |
| `allocate_uid` in `identity-fdb` uses per-store counter (not cluster-wide) on the fallback path | **Low** | **Medium** | Documented in the function's docstring; tests that need cluster-wide UID allocation must use `--features fdb` |

## Recommendations for v0.6.0

### P0 — Must-do before any production claim

1. **Compile-verify the real FDB code path** (`storage-fdb`, `identity-fdb`, `identity-ridpool`). Add a CI job: `cargo check --features fdb` with libclang installed. Fix any compile errors in the `real_fdb` submodules. This is the single highest-risk item in the audit.
2. **Add tests for `identity-testkit` and `repl-testkit`**. Minimum viable: round-trip insert/lookup/remove for each testkit. Target: 5-10 tests per testkit, bringing the layer's test count from 156 to ~170.
3. **Add real-FDB integration tests** (`#[ignore]`-gated, requiring `--features fdb` + Docker FDB cluster). The existing `#[ignore]`'d tests in `storage-fdb` are a good starting point — extend the pattern to `identity-fdb` and `identity-ridpool`.

### P1 — Should-do for v0.6.0

4. **Implement retry-on-conflict loop** in `FdbDirectoryStore::put`/`delete`/`FdbIdentityMapping::insert`/`FdbRidPoolAllocator::allocate`. Bounded retry budget (e.g. 5 retries with exponential backoff). Either implement it or fix the misleading docstring on `StorageError::Conflict`.
5. **Replace `.expect()` with `.ok_or(Backend(...))?`** in `identity-fdb` (6 sites) and `identity-ridpool` (5 sites) for defense-in-depth against corrupted FDB values.
6. **Use real LRU cache** in `identity-fdb`'s production path (the `lru` crate is a common choice). Keep `HashMap` for the test fallback if eviction behavior doesn't matter there.
7. **Remove or rephrase misleading TODOs** on implemented functions (`uuid_to_uid`, `resolve_conflict`, `update_utd_vector`).
8. **Implement cursor-based `get_changes` and conflict-resolving `apply_changes`** in `repl-testkit`. The current impls are acknowledged stubs — they prevent the testkit from being used to test replication semantics end-to-end.

### P2 — Nice-to-have for v0.7.0+

9. **Add property-based tests** for `resolve_conflict` (total ordering: commutativity, associativity, transitivity) using `proptest`.
10. **Validate `resolve_conflict` against AD's actual resolver** — capture conflict-resolution outputs from a Windows DC and compare byte-for-byte.
11. **Unify `InMemoryDirectoryStore`'s dual interfaces** — either route the high-level `DirectoryStore` methods through the low-level kv interface, or document the divergence more prominently and add a runtime assertion that prevents mixing the two.
12. **Add `From<StorageError> for IdentityError`** in `identity-core` to preserve type info across the storage→identity boundary (currently `map_storage_err` stringifies the error).
13. **Replace `Sid::to_string()` HashMap keys with `Sid` directly** in `identity-testkit` (line 61) — `Sid` implements `Hash` + `Eq`, avoiding the per-lookup String allocation.
14. **Add `RidPoolExhausted` error path** in `identity-ridpool` — the variant exists in `identity-core` but is never constructed; the allocator currently grows the pool unboundedly via `saturating_add`.
15. **Implement FDB watch-based cache invalidation** in `identity-fdb`'s production path (the crate docs claim it but no watch logic exists).

---

**Audit complete.** Total crates audited: 10. Total LoC reviewed: 7,127. Total tests counted: 156. Total TODOs counted: 14 (of which 7 are aspirational pointers to other crates, 3 are on implemented functions, 4 are on `repl-testkit` methods that work but have acknowledged gaps). No `unsafe` code anywhere. Average production readiness: **3.4 / 5**.
