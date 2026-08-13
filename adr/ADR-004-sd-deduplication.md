---
title: "ADR-004: Security Descriptor Deduplication via Content-Hash Indexed Table"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-008
severity: medium
tags: [adr, core-directory, security-descriptor, sdtable, dedup, hashing]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/00-overview/02-ad-architecture.md
last_updated: 2026-08-13
---

# ADR-004: Security Descriptor Deduplication via Content-Hash Indexed Table

## Status

Accepted — 2026-08-13

## Context

Active Directory deduplicates security descriptors (SDs) across objects: two objects with identical `nTSecurityDescriptor` share one row in `sdtable`, with the reference count tracked in `sdrefcount`. The DSA computes a 32-bit Murmur hash of the self-relative SD, looks up the hash in `sdtable`, and either reuses the existing row or allocates a new one. Lookup happens in `ntdsa.dll!SCGetSDFromCache` before falling through to allocation, per [PC-008](../catalog/01-core-directory.md#pc-008--security-descriptor-deduplication-sdtable-required-for-large-directories), [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md), and [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md). The `sdtable` columns are `sdID` (PK), `sd` (binary self-relative SD), `sdHash` (32-bit Murmur), `sdrefcount` (number of objects referencing this SD).

SD evaluation is a hot path in authorization. Every LDAP query that returns `nTSecurityDescriptor` (or filters on it) walks the SD's DACL. Every file-open in the File Gateway capability walks the share's SD. Every GPO application walks the GPO's SD. At 10M objects with mostly unique SDs, `sdtable` would be 10M rows × ~2 KB SD = 20 GB; the SD cache miss rate approaches 100%, and every lookup does a disk read. Script-generated OUs with explicit per-OU ACEs (a common pattern in some shops) bloat `sdtable` past 1M rows and slow SD evaluation from ~1 ms to ~50 ms.

AD's 32-bit Murmur hash has a noticeable collision rate at 10M+ SDs — approximately 1% collision rate at 10M entries (birthday paradox: 2^32 = 4.3 billion; sqrt(2^32) ≈ 65K for 50% collision probability, so 10M is well into the collision regime). AD handles collisions by byte-for-byte comparison after hash match, but the comparison cost adds up at scale.

Constraints from [PC-008](../catalog/01-core-directory.md#pc-008--security-descriptor-deduplication-sdtable-required-for-large-directories):

- Must support `nTSecurityDescriptor` self-relative SD storage (the binary format defined in MS-DTYP §2.4.6).
- SD hash collision must be detected — two SDs with the same hash must compare byte-for-byte before dedup.
- Reference count must be transactionally consistent — an SD with `sdrefcount = 0` must be GC'd; an SD with `sdrefcount > 0` must not be GC'd.
- For AD interop, the SD on the wire must be byte-identical (so AD-aware tools that compare SDs work).

## Decision

The framework SHALL implement security descriptor deduplication via a content-hash indexed table (the framework's equivalent of AD's `sdtable`). The hash function SHALL be BLAKE3 with 256-bit output (not Murmur32). The dedup table SHALL be a separate storage-engine table with columns: `sdID` (PK), `sdHash` (32-byte BLAKE3 digest), `sd` (binary self-relative SD), `sdrefcount` (transactional reference count). Objects reference SDs by `sdID` foreign key.

The dedup algorithm on every SD write SHALL be: (1) compute BLAKE3-256 of the self-relative SD; (2) look up `sdHash` in the dedup table; (3) if found, byte-compare the stored `sd` against the new SD; (4) if byte-identical, increment `sdrefcount` on the existing row and return the existing `sdID`; (5) if not byte-identical (hash collision — expected at <2^-64 rate for BLAKE3-256, effectively zero), insert a new row with the same hash and a new `sdID`; (6) if not found, insert a new row. On every SD-write that replaces an existing SD, the framework SHALL decrement `sdrefcount` on the old `sdID` row in the same transaction. Rows with `sdrefcount = 0` SHALL be GC'd by the periodic GC task (same 12-hour cycle as tombstone GC, per PC-009).

BLAKE3 is chosen over Murmur32 for three reasons: (a) 256-bit output eliminates the collision rate at any conceivable directory scale (10M SDs gives ~10^-60 collision probability, effectively zero); (b) BLAKE3 is the fastest modern hash (5x faster than SHA-256, 2x faster than BLAKE2b on modern hardware with SIMD); (c) BLAKE3 is a Merkle tree, allowing future parallelization of SD hashing if SD sizes grow beyond the current ~2 KB average. The 256-bit output also doubles as a content-addressable identifier — the framework can use `sdHash` as a deduplication key across DCs without exchanging the full SD, enabling future cross-DC dedup protocols.

For AD-interop mode, the framework SHALL emit byte-identical self-relative SDs on the LDAP wire (the `nTSecurityDescriptor` attribute). The internal `sdID` reference is invisible to clients; the wire format is always the full SD.

**Concrete specification**:

- The framework SHALL maintain a `sdtable`-equivalent with columns: `sdID` (PK, 64-bit integer), `sdHash` (32-byte BLAKE3 digest), `sd` (binary self-relative SD, MS-DTYP §2.4.6 format), `sdrefcount` (transactional integer).
- Every LDAP write that sets `nTSecurityDescriptor` SHALL: (a) compute BLAKE3-256 of the new SD; (b) look up `sdHash` in the dedup table; (c) byte-compare on hash match; (d) increment `sdrefcount` on existing row or insert new row; (e) decrement `sdrefcount` on the previous `sdID` row if the object previously had a different SD.
- The hash lookup SHALL be O(1) via a unique index on `sdHash`. Byte-comparison on hash match SHALL be O(SD size) — typically <2 KB.
- The reference count SHALL be transactional — increment and decrement SHALL be in the same storage transaction as the object write. Partial commits SHALL roll back the entire transaction.
- Rows with `sdrefcount = 0` SHALL be eligible for GC by the periodic GC task (12-hour cycle). The GC task SHALL NOT delete rows with `sdrefcount > 0`.
- The framework SHALL expose the dedup table via a monitoring API (count of unique SDs, total SD references, distribution of `sdrefcount` values) for capacity planning.
- For AD-interop mode, the LDAP wire format SHALL be the byte-identical self-relative SD (no `sdID` on the wire).
- Performance target: SD-write throughput SHALL be ≥ 10K writes/second per DC at 10M-object scale with 90% SD reuse (typical for OUs that inherit from parent SDs).

## Rationale

SD evaluation is a hot path in every AD-interop system. Without dedup, every object lookup pays an SD hash compare against the in-memory SD cache (typically ~1M entries), then falls through to disk. At 10M objects with mostly unique SDs, the SD cache miss rate approaches 100%, and every lookup does a disk read — authorization latency jumps from ~1 ms to ~50 ms. The dedup table eliminates the per-object SD storage: 10M objects sharing 100K unique SDs (typical for a well-structured forest) store 100K SDs instead of 10M, reducing SD storage from 20 GB to 200 MB and keeping the SD cache entirely in memory.

Three alternatives were considered:

**Alternative A — No dedup; store full SD on every object.** OpenLDAP, 389-DS, and Samba 4 all do this. The advantage is simpler code (no dedup table, no reference counting). The disadvantage is the disk-read cost at scale: 10M unique SDs × 2 KB = 20 GB of SD storage, far exceeding the in-memory cache. Authorization latency at 10M-object scale becomes 50 ms per query, unacceptable for any DC handling >100 queries/second. Rejected for v1 because the framework targets AD-scale deployments.

**Alternative B — 32-bit Murmur hash (AD's choice).** The advantage is wire-compatibility with AD's `sdtable` (though the dedup table is internal and not on the wire). The disadvantage is the collision rate: 1% collision rate at 10M SDs means 100K false-positive byte-comparisons per full-cache scan, adding ~100 ms to the scan. At 100M SDs (cloud-scale), the collision rate exceeds 50%, making the hash useless. Rejected in favor of BLAKE3-256.

**Alternative C — SHA-256 (NIST standard, FIPS 140-3 compliant).** The advantage is FIPS compliance for regulated deployments. The disadvantage is speed: SHA-256 is 5x slower than BLAKE3 on modern hardware, and SD hashing is in the hot path. BLAKE3 is not FIPS-approved but is cryptographically stronger than SHA-256 (no known attacks; BLAKE2 was a SHA-3 finalist). For FIPS-required deployments, the framework SHALL support a configurable hash function (BLAKE3 default; SHA-256 opt-in for FIPS mode). This configurability is implementation detail, not a separate ADR.

External evidence: [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs) documents the algorithm and benchmark; [MS-DTYP §2.4.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/) defines the self-relative SD format; [Samba 4 `source4/dsdb/samdb/ldb_modules/acl.c`](https://github.com/samba-team/samba) is the reference open-source SD handling code. The dedup pattern is identical across AD, Samba, and the framework's design.

## Consequences

**Positive**: SD storage at 10M-object scale with 100K unique SDs is ~200 MB (vs. 20 GB without dedup). The SD cache fits entirely in memory, keeping authorization latency sub-millisecond. The framework matches AD's `sdtable` design and is interoperable.

**Negative**: The dedup table is a separate storage-engine table that must be transactionally consistent with the object table — every SD write involves a dedup-table lookup, an increment or insert, and (if replacing) a decrement on the old row, all in one transaction. This adds write-path CPU cost (~5% of write throughput at typical SD-reuse ratios). The GC task must scan the dedup table periodically to reclaim zero-refcount rows; this is O(unique-SD-count) per GC cycle.

**Neutral**: The dedup table is internal; clients see no difference. The hash function (BLAKE3 vs SHA-256) is configurable for FIPS deployments but invisible to clients.

**Implementation cost**: ~4 person-weeks for the dedup table, hash function, reference-counting logic, GC task, and AD-interop byte-identical SD emission. The bulk of the work is the transactional reference-counting logic.

**Operational impact**: SD-heavy operations (bulk OU creation with explicit ACEs, GPO SD updates) complete faster because the dedup table absorbs the redundancy. Monitoring: the dedup-table stats API exposes unique-SD count, total references, and `sdrefcount` distribution; a high ratio of unique-SDs-to-objects (>10:1) indicates SD sprawl that may benefit from inheritance review.

## Alternatives Considered

### Alternative 1: No dedup (store full SD on every object)

OpenLDAP / 389-DS / Samba 4 model. Simpler code, but 20 GB SD storage at 10M-object scale causes disk-read latency. Rejected for v1 because the framework targets AD-scale deployments where the cost is unacceptable.

### Alternative 2: 32-bit Murmur hash (AD's choice)

Wire-compatible with AD's `sdtable` internal hash. Collision rate at 10M SDs is ~1%, causing false-positive byte-comparisons. At 100M SDs, collision rate exceeds 50%, making the hash useless. Rejected in favor of BLAKE3-256.

### Alternative 3: SHA-256 (FIPS-compliant)

FIPS 140-3 compliant for regulated deployments. 5x slower than BLAKE3, unacceptable in the SD-write hot path. ADOPTED as an opt-in configurable hash for FIPS-required deployments; BLAKE3 remains the default.

## Open Questions

- Should the framework also dedup partial SD components (owner, group, SACL, DACL) separately? AD does not — the entire SD is dedup'd as one unit. Partial dedup would increase the dedup ratio but add per-component reference counting. Defer to a future performance-optimization ADR if SD storage becomes a capacity concern.
- For cross-DC dedup, should the framework exchange `sdHash` (32 bytes) instead of the full SD (2 KB) during replication? This requires the BLAKE3 hash to be deterministic cross-DC (it is — same input, same output) and the dedup table to be replicated or synchronously queried. Defer to the replication-protocol ADR (gated by ORQ-001/002).
- Cross-reference PC-007 (storage engine, DEFERRED) — the dedup table's storage-engine-specific layout (RocksDB prefix-bloom vs in-memory hash) depends on the storage-engine choice.

## Cross-capability impact

- **Policy Engine**: GPO SDs benefit from the same dedup; the dedup table is shared across all SD-bearing objects.
- **File Gateway**: Share ACLs are SDs; dedup reduces per-share SD storage.
- **Cert Service**: Certificate-template SDs (which are complex, multi-ACE structures) benefit from dedup.
- **Operations**: SD-dedup monitoring (unique-SD count, dedup ratio) is a useful capacity-planning metric.
- **Security**: SD-dedup enables fast SD-comparison for "which objects have this exact SD?" queries (useful for security audits).

## References

- [PC-008](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — `sdtable` columns, `SCGetSDFromCache` lookup path, `sdrefcount` reference counting
- [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) — `NTDS.DIT` table inventory, `sdtable` row in table list
- [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs) — BLAKE3 hash algorithm
- [MS-DTYP §2.4.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/) — self-relative security descriptor format
- [Samba 4 acl module](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/acl.c) — reference SD handling
