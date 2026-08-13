---
title: "ADR-001: Linked Value Replication for Multi-Valued Linked Attributes"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-003
severity: high
tags: [adr, core-directory, replication, linked-attributes, lvr]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ../docs/03-directory-schema/01-schema-attributes.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-002-memberof-back-link.md
last_updated: 2026-08-13
---

# ADR-001: Linked Value Replication for Multi-Valued Linked Attributes

## Status

Accepted — 2026-08-13

## Context

Active Directory's replication model has historically treated multi-valued attributes as a single replicable unit. Before Windows Server 2003 SP1, a modification to any single value of a multi-valued linked attribute (for example, adding one user to a 10,000-member distribution group) caused the *entire* attribute set to be serialized and replicated on the wire — 10,000 `member` DNs per change. The practical ceiling for group size was ~5,000 members because each modification saturated replication links, per [PC-003](../catalog/01-core-directory.md#pc-003--linked-value-replication-lvr-required-for-groups-larger-than-5000-members).

Linked Value Replication (LVR), introduced in Server 2003 SP1 (schema `objectVersion` 31+), addresses this by splitting multi-valued linked attributes into per-value `REPLVALINF_V3` records. Each add or delete is one record carrying the value DN, the add/delete flag (`fIsPresent`), and the per-value `PROPERTY_META_DATA_EXT` structure (origin DSA InvocationID, origin USN, version, last-write timestamp), per [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md) and [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md). LVR eligibility is gated by two schema conditions: the attribute's `linkID` must be non-zero (forward links are even; backlinks are forward+1) AND `systemFlags` must have `FLAG_ATTR_IS_LINKED` (bit 8, mask 0x100), per [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

Without LVR-equivalent semantics, the framework inherits the same ~5,000-member ceiling as pre-2003 SP1 AD. At modern enterprise scale (50K-member distribution lists, 100K-member dynamic groups for cloud-synced tenants), the framework would saturate replication links with multi-megabyte payloads per single-value change. Back-link construction (`memberOf` for the added user) is also slow without per-value replication because the destination must recompute the entire back-link set from a full-attribute payload.

The framework's choice of replication protocol is gated by Tier-1 ORQ-001/002 (DRSUAPI vs CRDT vs Raft), which is DEFERRED per the triage. However, the per-value replication concept is independent of the underlying protocol: regardless of whether the framework uses DRSUAPI `REPLVALINF_V3`, a CRDT OR-set, or a Raft log, the on-the-wire delta for a linked attribute change must be per-value, not per-attribute. This makes the decision ADR-ELIGIBLE: the *what* (per-value deltas) is high-confidence; only the *how-on-the-wire* is deferred.

Constraints from [PC-003](../catalog/01-core-directory.md#pc-003--linked-value-replication-lvr-required-for-groups-larger-than-5000-members):

- `linkID` pairing in schema (forward = even, backlink = forward+1) must be preserved — `member` (linkID=3) → `memberOf` (linkID=4), `managedBy` (linkID=1) → `managedObjects` (linkID=2), etc.
- Back-link is computed, never directly writable. LDAP clients that write `memberOf` get `unwillingToPerform (53)`.
- `REPLVALINF_V3` version is negotiated via `DRS_EXT_GETCHGREQ_V8` (0x40) in `DRS_EXTENSIONS_INT.dwFlags`.
- For AD interop, the framework must accept and produce `REPLVALINF_V3` records on the wire.

## Decision

The framework SHALL implement Linked Value Replication for every DN-syntax multi-valued linked attribute — `member`, `memberOf` (computed; see ADR-002), `managedBy`, `managedObjects`, `directReports`, `manager`, `gPLink`, `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, and any custom attribute with a non-zero `linkID` and `FLAG_ATTR_IS_LINKED` set. Every add or delete of a single value SHALL produce a per-value replication delta carrying the value DN, the add/delete flag, and per-value metadata. Whole-attribute replication SHALL NOT be used for any linked attribute, regardless of group size.

Each per-value delta SHALL carry a `PROPERTY_META_DATA_EXT`-equivalent structure containing origin DSA InvocationID, origin USN, version counter, and last-write timestamp. Conflict resolution SHALL be last-writer-wins based on the timestamp in `PROPERTY_META_DATA_EXT`, with USN as the tiebreaker and origin InvocationID as the second tiebreaker. Tombstoned values (delete-with-retain) SHALL be tracked separately from present values so that a re-add after delete correctly resurrects the value rather than treating it as a no-op.

For AD-interop deployments, the framework SHALL accept and produce byte-identical `REPLVALINF_V3` records on the DRSUAPI wire and SHALL negotiate `DRS_EXT_GETCHGREQ_V8` (0x40) in `DRS_EXTENSIONS_INT.dwFlags`. For clean-slate deployments using a non-DRSUAPI replication protocol (CRDT OR-set or Raft log entries), the framework SHALL translate per-value deltas to the chosen protocol's representation at the boundary — the per-value semantics are preserved; only the encoding differs.

**Concrete specification**:

- The framework SHALL implement linked-value replication for all DN-syntax multi-valued attributes with non-zero `linkID` and `FLAG_ATTR_IS_LINKED` set in `systemFlags`.
- Each per-value replication delta SHALL contain: value DN, `fIsPresent` (TRUE=add, FALSE=delete), origin DSA InvocationID, origin USN, version counter, and last-write timestamp.
- The link-value store (the framework's equivalent of AD's `linktable`) SHALL be a separate indexed table from the object store; columns: `linkDNT`, `backlinkDNT`, `linkID`, `fIsPresent`, `originInvocationID`, `originUSN`, `version`, `lastWriteTimestamp`.
- Conflict resolution for the same logical value (same `linkDNT` + `backlinkDNT` + `linkID`) on replication convergence SHALL be: highest `version` wins; tiebreak by latest `lastWriteTimestamp`; final tiebreak by highest `originUSN`; final tiebreak by lexicographically-highest `originInvocationID`.
- The DSA SHALL reject direct LDAP writes to back-link attributes (`memberOf`, `managedObjects`, `directReports`, `isMemberOfPartialAttributeSet`-derived back-links) with `unwillingToPerform (53)` and a diagnostic message naming the corresponding forward link.
- For AD-interop mode, the framework SHALL emit and consume `REPLVALINF_V3` records on the DRSUAPI wire byte-identically to MS-DRSR §4.1.277.
- The framework SHALL support range-retrieval (PC-012 `LDAP_SERVER_RANGE_RETRIEVAL_OID`) on linked attributes via paged reads against the link-value store.
- Performance target: a single `member` add to a 100,000-member group SHALL produce a replication delta ≤ 1 KB and SHALL complete on the origin DSA in ≤ 5 ms.

## Rationale

The fundamental observation is that whole-attribute replication of linked attributes does not scale to modern enterprise group sizes. AD's pre-LVR ceiling of ~5,000 members was an operational constraint, not a protocol limit — the DSA could technically accept 100K-member groups, but each change produced a 10 MB replication payload, saturating WAN links and triggering replication backpressure. LVR eliminates this ceiling by collapsing the replication payload to a single per-value record per change. Per [MS-ADTS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts) and [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr), AD itself adopted LVR in Server 2003 SP1 precisely for this reason; replicating the design choice is the lowest-risk path.

Three alternatives were considered:

**Alternative A — Whole-attribute replication with delta-compression.** The replicator transmits a binary diff of the multi-valued attribute rather than the full set. This reduces payload size on the wire but still requires the destination to deserialize the full attribute to apply the diff. Worse, conflict detection requires per-value metadata, which is lost in a binary diff. Rejected: conflict resolution becomes ambiguous; delta-compression algorithms (bsdiff, xdelta) are O(attribute size) in CPU, making large groups expensive on both sides.

**Alternative B — Graph database (Neo4j, Dgraph, JanusGraph) for membership.** Membership is expressed as graph edges; edge adds and deletes are atomic per-edge operations. This eliminates the per-attribute ceiling entirely and gives O(log n) transitive closure for `tokenGroups` queries. Rejected: a graph database imposes a second storage engine (the framework already needs a relational or KV store for non-linked attributes), introduces a novel operational dependency not present in AD/Samba/389-DS, and complicates backup/restore. The graph model also doesn't map cleanly to AD's linkID pairing (forward+1 backlinks), requiring translation layers. We accept the relational `linktable` model for v1 and defer graph storage to a future evaluation if `tokenGroups` performance becomes the bottleneck (cross-reference ADR-009 constructed attributes).

**Alternative C — CRDT OR-set (add-wins observed-remove set).** Each value carries a unique tag; adds are unioned, deletes tombstone the tag. Conflict-free by construction. Rejected as the *primary* mechanism because it breaks AD-interop: AD-interop requires `REPLVALINF_V3` on the wire with `PROPERTY_META_DATA_EXT`, not CRDT tags. However, CRDT OR-set semantics are ADOPTED INTERNALLY for clean-slate deployments where AD-interop is not required — the per-value metadata structure is the same, but the conflict resolution is add-wins rather than last-writer-wins. This dual-mode is explicitly allowed by the decision.

The cost of this decision is implementation complexity. The link-value store is a second indexed table that must be transactionally consistent with the object store — every forward-link write must atomically write the back-link row, every delete must atomically remove both, every conflict resolution must consider per-value metadata rather than per-attribute metadata. This complexity is unavoidable for any framework that wants to scale beyond ~5,000-member groups; the question is not "whether" but "how," and LVR's `REPLVALINF_V3` is the most interoperable answer.

External evidence: [MS-DRSR §4.1.277 `REPLVALINF_V3`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/20f5f8b3-1f6d-4f4d-a1e6-9c0e7f0f3f6a) defines the wire format; Samba 4 implements LVR in `source4/dsdb/samdb/ldb_modules/repl_meta_data.c` and is wire-interoperable with AD; 389-DS and FreeIPA replicate per-value natively via their MMR protocol. The framework's design matches all three reference implementations.

## Consequences

**Positive**: The framework supports groups of any size (tested target: 1M-member groups) without replication backpressure. Single-value changes produce ≤1 KB replication deltas regardless of group size. Back-link construction at the destination is O(1) per replicated value, not O(group size). The framework is wire-compatible with AD for linked-attribute replication, enabling mixed-OS DC forests.

**Negative**: The link-value store adds storage overhead — approximately 80 bytes per linked value (DN pair + metadata), versus 0 bytes if whole-attribute storage were used. For a directory with 100M linked values (typical for a large enterprise with deep group nesting), this is ~8 GB of link-value storage. Conflict resolution requires per-value metadata comparison, which is more CPU-intensive than per-attribute comparison. The DSA must maintain referential integrity: deleting a user requires walking the link-value store to remove all `member` references to that user, which is O(group count) per deletion.

**Neutral**: The link-value store is the framework's internal representation; on the wire, AD-interop mode emits `REPLVALINF_V3` and clean-slate mode emits whatever the chosen replication protocol uses. Operators see no difference — group expansion in ADUC, `Get-ADGroupMember`, and LDAP `member` queries return identical results regardless of whether the underlying storage is LVR or whole-attribute.

**Implementation cost**: ~8 person-weeks for the link-value store, conflict resolution, range-retrieval support, and AD-interop `REPLVALINF_V3` translation. The bulk of the work is the conflict-resolution logic; the storage schema is straightforward.

**Operational impact**: Large-group operations (add 1K users to a 50K-member group) complete in seconds rather than minutes. Replication latency for group-membership changes drops from minutes to seconds. The `linktable`-equivalent requires periodic compaction to reclaim space from tombstoned values; the framework's GC task (analogous to AD's `GarbageCollection`) handles this on a 12-hour cycle, matching AD.

## Alternatives Considered

### Alternative 1: Whole-attribute replication with delta compression

The replicator transmits a binary diff (bsdiff/xdelta) of the multi-valued attribute rather than the full set. Payload size on the wire is reduced, but the destination must deserialize the full attribute to apply the diff, and conflict resolution becomes ambiguous because per-value metadata is lost in the diff. CPU cost on both sides is O(attribute size), making large groups expensive. Rejected: does not scale, breaks conflict detection, and is not AD-interop-compatible.

### Alternative 2: Graph database for membership

Replace the link-value store with a graph database (Neo4j, Dgraph, JanusGraph) that natively supports edge-add and edge-delete operations and provides O(log n) transitive closure for `tokenGroups`. Rejected for v1 because it introduces a second storage engine, a novel operational dependency, and a translation layer for AD-interop `REPLVALINF_V3`. The graph model may be revisited if `tokenGroups` performance becomes the bottleneck (cross-reference ADR-009).

### Alternative 3: CRDT OR-set (add-wins)

Each value carries a unique tag; adds are unioned, deletes tombstone the tag. Conflict-free by construction; no last-writer-wins needed. Rejected as the *primary* mechanism because AD-interop requires `REPLVALINF_V3` with `PROPERTY_META_DATA_EXT`, not CRDT tags. ADOPTED as an internal optimization for clean-slate deployments where AD-interop is not required; the per-value metadata structure is reused, but conflict resolution is add-wins. This dual-mode is explicit in the Decision section.

## Open Questions

- Should the framework expose a `linktable`-level API for administrators to inspect linked-value metadata (origin DSA, USN, timestamp) per value? AD does not expose this; Samba does via `ldbsearch --show-binary-metadata`. Deferring to a future UX ADR.
- For the clean-slate CRDT OR-set mode, what is the GC strategy for tombstone tags? The CRDT literature (Shapiro et al.) recommends periodic tag compaction, but the interval and trigger are unspecified. Defer to the replication-protocol ADR (gated by ORQ-001/002).
- Cross-reference ADR-009 (constructed attributes) — `tokenGroups` reads the link-value store; the caching strategy for `tokenGroups` is partially deferred to ORQ-032.

## Cross-capability impact

- **KDC**: KDC's PAC builder reads group memberships from the link-value store; per-value metadata enables fast incremental PAC updates on membership change (cross-reference ADR-018 KDC horizontal scaling).
- **Auth Provider**: S4U2Proxy (`msDS-AllowedToDelegateTo`) and RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) are linked attributes and benefit from per-value replication.
- **Policy Engine**: GPO security filtering uses group membership; per-value replication ensures policy-application latency is independent of group size.
- **Cert Service**: `NTAuthCertificates` and published-cert back-links are linked attributes; LVR applies.
- **File Gateway**: Share ACLs reference group SIDs; group membership changes replicate per-value, so access revocation takes effect in seconds, not minutes.
- **Operations**: Replication-health monitoring must include per-value replication latency as a metric, not just per-NC latency.

## References

- [PC-003](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md) — `REPLVALINF_V3` IDL, `PROPERTY_META_DATA_EXT`, LVR schema-version gate
- [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md) — `linkID` pairing, `FLAG_ATTR_IS_LINKED`, `systemFlags` bitmask
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — `linktable` schema, `backlinkDNT` reverse index
- [MS-DRSR §4.1.277 `REPLVALINF_V3`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — DRSUAPI replication protocol
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts) — Active Directory Technical Specification
- [Shapiro et al., "A comprehensive study of Convergent and Commutative Replicated Data Types"](https://hal.inria.fr/inria-00555588/document) — CRDT OR-set theory
