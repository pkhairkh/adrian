---
title: "ADR-003: Copy-on-Write Schema Cache with Monotonic Generation Numbers"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-006
severity: medium
tags: [adr, core-directory, schema-cache, cow, mvcc, lock-free]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/00-overview/02-ad-architecture.md
  - ../docs/03-directory-schema/01-schema-attributes.md
last_updated: 2026-08-13
---

# ADR-003: Copy-on-Write Schema Cache with Monotonic Generation Numbers

## Status

Accepted — 2026-08-13

## Context

Active Directory's `ntdsa.dll` keeps the schema in an in-memory `g_SchemaCache` hash table (`THashTable<SchemaClass>` keyed by `governsID`). The cache is loaded at boot from `CN=Schema,CN=Configuration,<forest-root-dn>` and refreshed whenever the operational attribute `schemaUpdateNow` (a write to `CN=Aggregate,CN=Schema,...`) is invoked. The reload is single-threaded: `ntdsa.dll!SCCacheRefresh` acquires the schema cache lock, walks the entire Schema NC, rebuilds the hash table, swaps it in, and releases the lock. In-flight LDAP requests continue using the previous cache snapshot; new requests block until the reload completes, per [PC-006](../catalog/01-core-directory.md#pc-006--schema-cache-reload-blocks-ldap-writes-for-530-seconds), [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md), and [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

On a mid-size forest (~2,000 schema attributes, ~500 classes), the reload takes 5–30 seconds. During this window, all LDAP writes block (reads continue using the cached schema). Schema extensions during maintenance windows cause noticeable write outages. CI/CD-style schema operations — e.g. an application deployment that adds a new attribute — are unworkable in their natural cadence because each schema modify triggers a reload. Production AD deployments rarely extend schema more than once per quarter precisely because of this cost.

The constraint is transactional consistency: in-flight writes must not see a partial schema (a write that adds a value for a not-yet-cached attribute would fail validation). Concurrent reads during reload must not block — reads vastly outnumber writes in any directory. For AD interop, the framework must accept `schemaUpdateNow` writes and trigger a reload, but the reload mechanism itself is implementation-specific (not on the wire).

The 5–30 second outage is unacceptable for the framework's own evolution. Each new framework feature adds schema attributes; if each addition blocks writes for 30 seconds, the framework's release cadence is constrained by schema-cache reload cost. This is a self-imposed ceiling that the framework should not inherit from AD.

## Decision

The framework SHALL implement a copy-on-write schema cache with monotonic generation numbers. The schema cache SHALL be an immutable data structure identified by a generation counter; readers acquire the current generation's pointer atomically and use it for the duration of their LDAP operation. Writers (schema-modify transactions) construct a new generation of the schema cache from the current one plus the delta, atomically swap the pointer to point at the new generation, and decrement the reference count on the old generation. The old generation is freed when its reference count reaches zero (i.e., when all in-flight readers using it have completed).

Writers SHALL NOT block readers, and readers SHALL NOT block writers. Multiple concurrent writers SHALL serialize via a writer-writer mutex (only one schema-modify transaction may be in flight at a time, matching AD's behavior where `schemaUpdateNow` is single-threaded). The writer-writer mutex is held only for the duration of the cache-rebuild step (typically <100 ms), not for the duration of the schema-modify transaction (which may take seconds for replication).

The generation counter SHALL be monotonic and SHALL be exposed as an operational attribute on `CN=Aggregate,CN=Schema,...` (`schemaCacheGeneration`) for monitoring and debugging. A reader that observes `schemaCacheGeneration = N` is guaranteed to see all schema changes committed in generations ≤ N.

`schemaUpdateNow` writes SHALL trigger a new generation build. The build is incremental where possible: if the schema modify adds one attribute to one class, the new generation shares the unchanged portions of the schema graph with the previous generation (persistent-data-structure sharing, similar to Clojure's persistent vectors). Full rebuilds are required only for changes that affect the schema graph globally (e.g., adding a `mustContain` to a base class affects every subclass).

**Concrete specification**:

- The schema cache SHALL be an immutable, reference-counted data structure. Readers acquire a reference at the start of an LDAP operation and release it at the end.
- The generation counter SHALL be a 64-bit monotonically-increasing integer, persisted to disk on every schema-modify commit (so DCs restored from backup retain the correct generation).
- Writers SHALL construct the new generation by persistent-data-structure sharing: only modified subgraphs (the changed class, its subclasses if `mustContain`/`mayContain` changed, the changed attribute, indexes) are rebuilt; unchanged subgraphs are shared by reference.
- The writer-writer mutex SHALL be held only for the cache-rebuild step (target: <100 ms); schema-modify transaction commit, replication, and audit-log emission SHALL occur outside the mutex.
- `schemaUpdateNow` writes SHALL trigger a new generation build synchronously; the LDAP modify response SHALL return only after the new generation is live (readers may use either generation during the rebuild).
- LDAP writes SHALL validate against the generation active at the start of the write transaction; if the generation changes mid-transaction, the write SHALL re-validate against the new generation and retry if validation fails.
- The schema cache SHALL support concurrent reads at any scale (no read lock; atomic pointer acquisition).
- For AD-interop mode, the framework SHALL accept `schemaUpdateNow` writes and SHALL emit the `schemaCacheGeneration` operational attribute for monitoring; the reload mechanism itself is internal and not exposed on the wire.
- Performance target: a schema-modify that adds one attribute to one class SHALL complete (cache rebuild + transaction commit) in ≤ 200 ms, with zero blocked readers.

## Rationale

The AD behavior is a known operational pain point with no workaround. The fix is well-understood in the database literature: copy-on-write with MVCC (multi-version concurrency control) is the standard solution for read-heavy workloads with occasional writes, used by PostgreSQL, LMDB, CouchDB, and Clojure's persistent data structures. Applying it to the schema cache is straightforward; the only complexity is the persistent-data-structure sharing for incremental rebuilds.

Three alternatives were considered:

**Alternative A — Per-attribute / per-class invalidation (granular invalidation).** Instead of rebuilding the whole cache, invalidate only the affected attribute or class. The 389-DS / OpenLDAP `cn=config` backend uses this approach. Rejected for v1 because schema-graph changes (adding a `mustContain` to a base class) cascade to every subclass, requiring a graph-walk to identify all affected classes — the complexity of computing the affected set exceeds the complexity of copy-on-write, and the bug surface (missing an affected class) is high. Copy-on-write with persistent-data-structure sharing achieves the same incremental cost without the bug surface.

**Alternative B — MVCC at the storage-engine level.** The schema cache reads from the storage engine, which already supports MVCC (per PC-007 / ORQ-011..014). The schema cache could be a thin wrapper that reads the schema NC on every operation. Rejected because the storage-engine-level MVCC provides transactional consistency but not the in-memory performance required for LDAP validation — every LDAP write would pay a storage-engine roundtrip for schema validation, adding 1–5 ms per write. The in-memory copy-on-write cache keeps validation sub-millisecond.

**Alternative C — Two-cache hot-swap (the AD model with a smaller reload window).** Keep AD's two-cache model but optimize the reload to be faster (parallelize the schema walk, pre-compute indexes). Rejected because the fundamental problem is the writer-writer lock, not the reload speed — even a 1-second reload blocks writes for 1 second, which is unacceptable for CI/CD-style schema operations. Copy-on-write eliminates the lock entirely.

External evidence: [PostgreSQL MVCC documentation](https://www.postgresql.org/docs/current/mvcc.html) documents the multi-version concurrency model; LMDB's [Appendix B: MVCC](https://github.com/LMDB/lmdb/blob/mdb.master/libraries/liblmdb/lmdb.h) describes the same pattern for memory-mapped databases; Clojure's [persistent data structures](https://clojure.org/reference/data_structures) demonstrate the persistent-data-structure sharing that makes incremental rebuilds efficient. The pattern is industry-standard for read-heavy workloads.

The cost of this decision is doubled memory during the swap window — both the old generation and the new generation are in memory simultaneously until the old generation's reference count reaches zero. For a 5,000-attribute schema, the cache is ~50 MB; the swap window is bounded by the longest in-flight LDAP operation (typically <1 second), so peak memory is ~100 MB. This is acceptable on any modern DC.

## Consequences

**Positive**: Schema modifications no longer block LDAP writes. CI/CD pipelines that add schema attributes can run at any cadence without maintenance windows. The framework's own schema evolution (each new feature adds attributes) is not constrained by reload cost. Concurrent reads scale linearly with CPU — no read lock, no contention.

**Negative**: Memory overhead during the swap window (~50 MB extra for a typical schema). Persistent-data-structure sharing adds implementation complexity — the schema graph must be represented as a persistent (immutable) data structure, which is unfamiliar to engineers accustomed to mutable hash tables. The generation counter must be persisted to disk on every commit, adding a small write-amplification cost.

**Neutral**: The schema cache's behavior is invisible to LDAP clients — they see identical schema reads before, during, and after a schema modify. Operators see the `schemaCacheGeneration` counter increment, which is useful for debugging "did my schema change take effect?" queries.

**Implementation cost**: ~5 person-weeks for the copy-on-write infrastructure, persistent-data-structure schema graph, generation counter, and AD-interop `schemaUpdateNow` translation. The bulk of the work is the persistent-data-structure representation of the schema graph (attribute definitions, class definitions, inheritance hierarchy, index metadata).

**Operational impact**: Schema modifications complete in <200 ms (target), versus 5–30 seconds in AD. The framework can ship schema-changing features without coordinating maintenance windows. Monitoring: `schemaCacheGeneration` should be tracked as a metric; a non-incrementing generation counter over a multi-day window suggests a stalled schema-modify transaction.

## Alternatives Considered

### Alternative 1: Per-attribute / per-class granular invalidation

Invalidate only the affected attribute or class on schema modify, avoiding a full cache rebuild. Used by 389-DS / OpenLDAP `cn=config`. Rejected for v1 because schema-graph changes cascade to subclasses, requiring a graph-walk to identify affected classes — the complexity exceeds copy-on-write, and the bug surface (missing an affected class) is high. May be revisited if schema-modify frequency becomes high enough to justify the complexity.

### Alternative 2: Storage-engine MVCC for schema validation

Read the schema NC from the storage engine on every LDAP write; rely on storage-engine MVCC for consistency. Rejected because the per-write storage-engine roundtrip adds 1–5 ms, making LDAP validation too slow for high-throughput DCs. The in-memory copy-on-write cache keeps validation sub-millisecond.

### Alternative 3: Optimized two-cache hot-swap (AD model with faster reload)

Keep AD's two-cache model but parallelize the schema walk and pre-compute indexes. Rejected because the fundamental problem is the writer-writer lock, not reload speed — even a 1-second reload blocks writes for 1 second. Copy-on-write eliminates the lock entirely.

## Open Questions

- For schema-graph-wide changes (adding a `mustContain` to a base class with 1000 subclasses), is persistent-data-structure sharing sufficient, or should we fall back to a full rebuild for large cascades? Threshold: if the affected subgraph exceeds 50% of the schema, do a full rebuild.
- Should the generation counter be replicated cross-DC? AD does not replicate the schema cache generation; each DC tracks its own. The framework should match AD for interop. Defer to the replication-protocol ADR (gated by ORQ-001/002).
- Cross-reference PC-017 (LDAP schema vs typed schema, DEFERRED) — the typed-schema alternative would change the cache representation but not the copy-on-write model.

## Cross-capability impact

- **KDC**: KDC reads schema for SPN/UPN attribute definitions; copy-on-write ensures no read blocking during schema changes.
- **Auth Provider**: Auth Provider reads schema for `msDS-AllowedToDelegateTo` and RBCD attribute definitions; same benefit.
- **Policy Engine**: Policy Engine reads schema for GPO attribute definitions; same benefit.
- **Cert Service**: Cert Service reads schema for certificate-template attribute definitions; same benefit.
- **Operations**: Schema-modify operations no longer require maintenance windows; the framework's release cadence is not constrained by reload cost.

## References

- [PC-006](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) — Schema cache reload behavior, single-threaded `gSchemaCache` rebuild
- [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md) — `schemaUpdateNow` operational attribute, `SCCacheRefresh` internals
- [PostgreSQL MVCC](https://www.postgresql.org/docs/current/mvcc.html) — multi-version concurrency control
- [LMDB](https://github.com/LMDB/lmdb) — memory-mapped MVCC database
- [Clojure Persistent Data Structures](https://clojure.org/reference/data_structures) — persistent (immutable) data structure sharing
