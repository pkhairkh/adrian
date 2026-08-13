---
title: "ADR-009: Constructed Attributes via DSA-Side Computation (PARTIAL)"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-018
severity: high
tags: [adr, core-directory, constructed-attributes, operational, partial, token-groups]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/02-ous-containers.md
  - ../docs/03-directory-schema/03-global-catalog.md
  - ./ADR-002-memberof-back-link.md
  - ./ADR-018-kdc-horizontal-scaling.md
last_updated: 2026-08-13
---

# ADR-009: Constructed Attributes via DSA-Side Computation (PARTIAL)

## Status

Accepted — 2026-08-13

## Context

Active Directory marks certain attributes as constructed (`FLAG_ATTR_IS_CONSTRUCTED` bit 1, mask 0x02 in `systemFlags`). They are not stored; the DSA computes them at read time from underlying data. Examples: `memberOf` (walks `linktable` back-links for the user's group memberships — see ADR-002), `tokenGroups` (recursive group expansion including universal groups across domains, returns SIDs), `tokenGroupsGlobalAndUniversal` (subset for GC-style queries), `canonicalName` (DN-to-domain-path translation, e.g. `CN=jdoe,CN=Users,DC=corp,DC=example,DC=com` → `corp.example.com/Users/jdoe`), `msDS-NCReplCursors` (UTD vector as XML), `msDS-NCReplInboundNeighbors` (inbound partners as XML), `parentGUID` (parent object's GUID), `allowedChildClassesEffective` / `allowedAttributesEffective` (computed from the caller's permissions), per [PC-018](../catalog/01-core-directory.md#pc-018--constructed-attributes-memberof-tokengroups-canonicalname-require-dsa-side-computation), [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md), and [docs/03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md).

Constructed attributes are also marked `FLAG_ATTR_IS_OPERATIONAL` (bit 2, mask 0x04) — they are not returned by default in LDAP searches; the client must explicitly request them in the `attributes` list. This is why a default `ldapsearch (objectClass=user)` does not return `memberOf` — the client must request `attributes=['memberOf', 'tokenGroups']`.

The expensive one is `tokenGroups` — recursive group expansion is O(group count × group size) and can take 100ms+ for users with deep nested memberships. AD computes it at read time. The Kerberos KDC's PAC builder computes the equivalent (`GroupIds` and `ExtraSids` in `KERB_VALIDATION_INFO`) on every TGT issuance, which is why KDC CPU is the bottleneck at million-user scale (cross-reference ADR-018).

This ADR is PARTIAL because the *caching strategy* for `tokenGroups` is uncertain. Two strategies are viable: (a) event-driven write-time cache (update the cache on every group-membership change; read is O(1)) and (b) read-time computation with TTL cache (compute on read, cache for N seconds). The choice depends on the framework's KDC throughput target and the cache-invalidation graph complexity. The triage defers this sub-decision to Tier-2 ORQ-032 (per [PC-018](../catalog/01-core-directory.md#pc-018--constructed-attributes-memberof-tokengroups-canonicalname-require-dsa-side-computation)).

Constraints from [PC-018](../catalog/01-core-directory.md#pc-018--constructed-attributes-memberof-tokengroups-canonicalname-require-dsa-side-computation):

- Must support `FLAG_ATTR_IS_CONSTRUCTED` and `FLAG_ATTR_IS_OPERATIONAL` semantics.
- Clients must explicitly request operational attrs in the LDAP search `attributes` list; default search must not return them.
- `tokenGroups` must include universal groups across domains (requires GC lookup or equivalent).
- `memberOf` must be the same set as what the `linktable` back-link walk would produce (no divergence between constructed and stored).

## Decision

The framework SHALL support constructed attributes via DSA-side computation, marked as operational (not returned by default in LDAP searches). The framework SHALL implement the following constructed attributes for AD-interop:

1. **`memberOf`** — walks the link-value store's reverse index (see ADR-002). Returns the DNs of all groups the user is a direct member of. NOT recursive (use `LDAP_MATCHING_RULE_IN_CHAIN` for recursive queries).
2. **`tokenGroups`** — recursive group expansion including universal groups across domains. Returns an array of SIDs. Requires GC lookup for cross-domain universal groups (or the framework's equivalent cross-NC query).
3. **`tokenGroupsGlobalAndUniversal`** — subset of `tokenGroups` containing only global and universal groups (no domain-local groups). Used for GC-style queries.
4. **`tokenGroupsNoGCAcceptable`** — subset that does not require GC lookup (domain-local + global from the user's domain only).
5. **`canonicalName`** — DN-to-domain-path translation (e.g. `CN=jdoe,CN=Users,DC=corp,DC=example,DC=com` → `corp.example.com/Users/jdoe`).
6. **`parentGUID`** — the `objectGUID` of the parent object.
7. **`allowedChildClassesEffective`** — list of object classes that the caller has permission to create as children of the target object.
8. **`allowedAttributesEffective`** — list of attributes that the caller has permission to read on the target object.
9. **`msDS-NCReplCursors`** — UTD vector as XML (used by `repadmin /showutdvec`).
10. **`msDS-NCReplInboundNeighbors`** — inbound replication partners as XML (used by `repadmin /showrepl`).

All constructed attributes SHALL be marked `FLAG_ATTR_IS_CONSTRUCTED` and `FLAG_ATTR_IS_OPERATIONAL` in the schema. The DSA SHALL NOT return them in LDAP searches unless the client explicitly requests them in the `attributes` list (matching AD behavior).

The `tokenGroups` computation SHALL: (a) walk the link-value store reverse index for direct group memberships; (b) recurse into parent groups (universal, global, domain-local) until closure; (c) for cross-domain universal groups, query the GC (or the framework's equivalent cross-NC query); (d) return the resulting SID array, including the user's primary group SID (from `primaryGroupID`) and any `sIDHistory` entries.

The caching strategy for `tokenGroups` (event-driven write-time cache vs. read-time computation with TTL) is DEFERRED to Tier-2 ORQ-032. The framework SHALL implement read-time computation as the v1 default (matching AD), with a pluggable cache interface that allows future ADR to add write-time caching without changing the API.

**Concrete specification**:

- The framework SHALL implement the 10 constructed attributes listed in the Decision section, with `FLAG_ATTR_IS_CONSTRUCTED` and `FLAG_ATTR_IS_OPERATIONAL` set in `systemFlags`.
- Constructed attributes SHALL NOT be returned in LDAP searches unless the client explicitly requests them by name in the `attributes` list.
- `memberOf` SHALL return direct group memberships (NOT recursive); recursive queries use `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`).
- `tokenGroups` SHALL return a SID array including: direct group SIDs, recursively-expanded group SIDs, primary group SID (from `primaryGroupID`), and `sIDHistory` entries.
- `tokenGroups` SHALL include universal groups from all domains in the forest (requires GC or equivalent cross-NC query).
- `canonicalName` SHALL translate `CN=jdoe,CN=Users,DC=corp,DC=example,DC=com` to `corp.example.com/Users/jdoe` (DNS-name-first, slash-separated path).
- `parentGUID` SHALL return the `objectGUID` of the parent object (the object whose DN is the request DN minus the leftmost RDN).
- `allowedChildClassesEffective` and `allowedAttributesEffective` SHALL compute the effective set based on the caller's permissions (read the SD on the target object, evaluate the caller's token against the ACEs).
- `msDS-NCReplCursors` and `msDS-NCReplInboundNeighbors` SHALL return the framework's UTD vector and inbound replication partners in the AD-compatible XML format (byte-identical to AD for AD-interop).
- For AD-interop mode, all constructed attributes SHALL be byte-identical to AD's output (including BER encoding and value ordering).
- The framework SHALL implement read-time computation as the v1 default for `tokenGroups`; the cache interface SHALL be pluggable to allow future write-time caching without API changes.

## Rationale

Constructed attributes are fundamental to AD's identity model. Every AD-aware application that asks "what groups is this user in?" reads `memberOf` or `tokenGroups`. Every UI that displays a user-friendly path reads `canonicalName`. Every AD management tool reads `allowedChildClassesEffective` to populate "New Object" dialogs. Without constructed attributes, every AD-aware application breaks. The Decision section's 10-attribute set covers the most commonly used constructed attributes; the remaining constructed attributes (e.g. `msDS-PrincipalName`, `dSCorePropagationData`) are deferred to Tier 3.

The caching strategy for `tokenGroups` is deferred because the choice depends on the framework's KDC throughput target (cross-reference ADR-018). If the KDC's PAC builder computes `tokenGroups` on every AS-REQ, a write-time cache is essential to avoid per-request O(group count × group size) cost. If the KDC's PAC builder uses a separate cache (the framework's own `GroupIds` / `ExtraSids` cache, not the LDAP `tokenGroups`), the LDAP `tokenGroups` can be read-time-computed without affecting KDC throughput. The two paths are independent; ORQ-032 resolves the KDC cache question, and the LDAP `tokenGroups` cache follows.

Three alternatives were considered:

**Alternative A — Store all constructed attributes as materialized (write-time cache for everything).** The advantage is O(1) read cost. The disadvantage is write-path cost and cache-invalidation graph complexity — a group rename invalidates every member's `memberOf`, `tokenGroups`, and `canonicalName` cache; a user move invalidates every group's `memberOf` for that user. The invalidation graph is O(group count × group size) on every change. Rejected as the default; may be adopted for `tokenGroups` only if ORQ-032 resolves in favor of write-time caching.

**Alternative B — Compute all constructed attributes at read time, no cache.** The advantage is zero storage cost and zero invalidation complexity. The disadvantage is read-path cost — `tokenGroups` for a user in 500 groups averaging 10K members is 5M link-value rows scanned per query. AD does this and it works because AD deployments rarely query `tokenGroups` at high frequency (the KDC's PAC builder is the hot path, not LDAP `tokenGroups`). Rejected for the KDC's PAC builder path (too expensive); ADOPTED as the v1 default for LDAP `tokenGroups` queries (acceptable cost, matches AD).

**Alternative C — External cache service (Redis, Memcached) for `tokenGroups`.** The advantage is decoupled scaling (cache scales independently of the DSA). The disadvantage is a new operational dependency and cache-consistency challenges (the cache must invalidate on every group-membership change, which requires the DSA to publish invalidation events). Rejected for v1; may be revisited if `tokenGroups` query frequency becomes a bottleneck.

External evidence: [MS-ADTS §3.1.1.3.2.20](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents constructed attributes; [MS-ADTS §3.1.1.3.2.21](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents `tokenGroups` semantics; Samba 4 implements constructed attributes in `source4/dsdb/samdb/ldb_modules/operational.c`. The framework's design matches AD's semantics and defers the caching question to ORQ-032.

The cost of this decision is implementation effort for the 10 constructed attributes (~6 person-weeks total, the bulk being `tokenGroups` with GC cross-NC query). The cache-invalidation graph (if write-time caching is later adopted per ORQ-032) is a future cost not included in v1.

## Consequences

**Positive**: AD-aware applications that read `memberOf`, `tokenGroups`, `canonicalName`, `allowedChildClassesEffective`, and `allowedAttributesEffective` work without modification. ADUC's "Member Of" tab works. The KDC's PAC builder has a clean API to query group memberships. `repadmin /showutdvec` and `repadmin /showrepl` work via `msDS-NCReplCursors` and `msDS-NCReplInboundNeighbors`.

**Negative**: Read-time computation of `tokenGroups` is expensive for users with deep nested memberships (100ms+ per query). The KDC's PAC builder MUST use a separate cache (not the LDAP `tokenGroups`) to avoid per-AS-REQ cost — this is the topic of ORQ-032 and ADR-018.

**Neutral**: The v1 default (read-time computation, no cache) matches AD's behavior; operators see no difference. The pluggable cache interface allows future ADR to add caching without API changes.

**Implementation cost**: ~6 person-weeks for the 10 constructed attributes, the bulk being `tokenGroups` with GC cross-NC query (~3 person-weeks). The remaining 9 attributes are ~0.3 person-weeks each.

**Operational impact**: `tokenGroups` queries for users with deep nested memberships may take 100ms+; this is acceptable for occasional queries (ADUC display) but unacceptable for high-frequency paths (KDC PAC builder). The KDC MUST use a separate cache; LDAP `tokenGroups` is for human-driven queries.

## Alternatives Considered

### Alternative 1: Store all constructed attributes as materialized (write-time cache for everything)

O(1) read cost; O(group count × group size) invalidation cost per change. Rejected as the default; may be adopted for `tokenGroups` only if ORQ-032 resolves in favor of write-time caching.

### Alternative 2: Compute all constructed attributes at read time, no cache

Zero storage cost; O(group count × group size) read cost per query. Rejected for the KDC's PAC builder path (too expensive); ADOPTED as the v1 default for LDAP `tokenGroups` queries.

### Alternative 3: External cache service (Redis, Memcached) for tokenGroups

Decoupled scaling; new operational dependency. Rejected for v1; may be revisited if `tokenGroups` query frequency becomes a bottleneck.

## Open Questions

- **DEFERRED to ORQ-032**: Cache `tokenGroups` on write (event-driven, invalidate on group membership change) vs compute at read? The v1 default is read-time computation; the cache interface is pluggable for future ADR. The gating ORQ is ORQ-032 (per [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md)).
- Can the framework precompute `tokenGroups` for the KDC's PAC builder (avoiding the per-AS-REQ computation)? This is the KDC throughput bottleneck at million-user scale; cross-reference ADR-018.
- Should `memberOf` be stored (materialized) or computed? ADR-002 specifies read-time construction as the default with optional write-time materialized cache. This ADR is consistent with ADR-002.

## Cross-capability impact

- **KDC**: KDC's PAC builder computes the equivalent of `tokenGroups` on every AS-REQ. The KDC SHOULD use a separate cache (not the LDAP `tokenGroups` query path) to avoid per-AS-REQ cost; cross-reference ADR-018.
- **Auth Provider**: S4U2Self uses `tokenGroups`-equivalent computation for the impersonated user's PAC.
- **Policy Engine**: GPO security filtering reads `memberOf` (constructed) to determine which GPOs apply.
- **Federation Gateway**: Claim issuance reads `tokenGroups` for group-based claim rules.
- **Operations**: `repadmin /showutdvec` and `repadmin /showrepl` use `msDS-NCReplCursors` and `msDS-NCReplInboundNeighbors` for replication-health monitoring.
- **Client SDK**: Client LDAP wrapper must expose operational-attribute requests so apps can fetch `memberOf` and `tokenGroups`.

## References

- [PC-018](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md) — `systemFlags` bitmask, `FLAG_ATTR_IS_CONSTRUCTED` / `FLAG_ATTR_IS_OPERATIONAL`
- [docs/03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md) — `tokenGroups` recursive expansion via GC, `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`)
- [MS-ADTS §3.1.1.3.2.20](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Constructed Attributes
- [MS-ADTS §3.1.1.3.2.21](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — tokenGroups semantics
- [Samba 4 `ldb_modules/operational.c`](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/operational.c) — reference implementation
