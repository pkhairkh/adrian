---
title: "ADR-002: memberOf Back-Link as DSA-Computed linkID Pair"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-004
severity: blocker
tags: [adr, core-directory, memberof, back-link, linkid, referential-integrity]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ../docs/03-directory-schema/01-schema-attributes.md
  - ./ADR-001-linked-value-replication.md
  - ./ADR-009-constructed-attributes.md
last_updated: 2026-08-13
---

# ADR-002: memberOf Back-Link as DSA-Computed linkID Pair

## Status

Accepted — 2026-08-13

## Context

Active Directory's identity model is built on bidirectional linked attributes. `member` (OID `2.5.4.31`, linkID=3) is the forward link stored on group objects; `memberOf` (OID `2.5.4.35`, linkID=4) is the corresponding back-link materialized on user, computer, and other security-principal objects. The linkID pairing is hardcoded in the schema: `CN=member,CN=Schema,...,linkID=3` and `CN=memberOf,CN=Schema,...,linkID=4`. Other pairings follow the same pattern: `managedBy` (linkID=1) → `managedObjects` (linkID=2); `manager` (linkID=8) → `directReports` (linkID=9), per [PC-004](../catalog/01-core-directory.md#pc-004--membermemberof-back-link-requires-linkid-pairing-and-dsa-computed-construction) and [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

The DSA — not the client — owns back-link integrity. When a client adds a user DN to a group's `member` attribute, `ntdsa.dll` writes one row to `linktable` (`linkDNT` = group DNT, `backlinkDNT` = user DNT, `linkID` = 3) within the same ESE transaction as the forward-link write. The `memberOf` value for the user is then materialized either at read time (constructed attribute, `FLAG_ATTR_IS_CONSTRUCTED`) by walking the `linktable` reverse index, or pre-computed in `linktable`'s reverse index for performance. Clients cannot write `memberOf` directly; the DSA rejects the operation with `unwillingToPerform (53)`. See [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md).

This bidirectional link is foundational to AD's identity model. Every AD-aware application that asks "what groups is this user in?" reads `memberOf`. Exchange, SharePoint, ADUC, every custom LDAP app that filters `(memberOf=CN=Admins,...)`, and the Kerberos KDC's PAC builder (which walks `memberOf` recursively to compute `GroupIds` and `ExtraSids` in the `KERB_VALIDATION_INFO`) all depend on it. A framework that wants typed/SQL-backed schema must still implement this bidirectional link or break every AD application.

The mechanics are non-trivial. The DSA must update the back-link atomically with the forward-link write (within the same storage transaction). The back-link must be replicated alongside the forward-link via LVR per ADR-001 (`REPLVALINF_V3` for both sides). The back-link must be invalidated when the forward-link is deleted — which can happen via direct `member` value removal, tombstone of the group, tombstone of the user, or cross-domain move (PC-010). The back-link must be invalidated when the *target* object is tombstoned (the user is deleted; the `memberOf` values for that user become dangling references and must be cleaned up).

Constraints from [PC-004](../catalog/01-core-directory.md#pc-004--membermemberof-back-link-requires-linkid-pairing-and-dsa-computed-construction):

- `memberOf` must be transparent to LDAP clients reading it — they must see it as a multi-valued DN-syntax attribute populated by the DSA.
- Must support both constructed-at-read-time (low storage cost, high read cost) and stored-materialized (high storage cost, low read cost) forms. AD uses stored for `memberOf` and constructed for `tokenGroups`.
- Back-link must be transactionally consistent with forward-link — no window where `member` is set but `memberOf` is not.
- For AD interop, the schema must define `member` (`attributeID` `2.5.4.31`) and `memberOf` (`2.5.4.35`) with `linkID` 3 and 4 respectively.

## Decision

The framework SHALL implement `memberOf` as a DSA-computed back-link paired with the forward `member` link via the standard `linkID` mechanism. The DSA SHALL write one row to the link-value store on every forward-link write and one row on every forward-link delete; the back-link value SHALL be derivable from the link-value store's reverse index at read time. Direct LDAP writes to `memberOf` SHALL be rejected with `unwillingToPerform (53)` and a diagnostic message instructing the client to write the corresponding forward link (`member` on the group) instead.

The framework SHALL generalize this mechanism to every `linkID`-paired attribute set in the schema. The link-value store (defined in ADR-001) SHALL carry a `linkID` column that identifies which forward/back-link pair the row belongs to. The DSA SHALL resolve the back-link attribute from the schema's `linkID` table at query time: a search for `memberOf` on a user SHALL translate to a reverse-index scan on `linktable` where `backlinkDNT = user.DNT AND linkID = 4`. Other pairings (`managedBy`/`managedObjects`, `manager`/`directReports`, `msDS-AllowedToDelegateTo`/`msDS-HasMasterNCs`-style back-links) SHALL work identically via the same code path.

The framework SHALL materialize back-links at read time by default (constructed-attribute semantics; cross-reference ADR-009). For performance-critical paths (the KDC's PAC builder, the GC's `memberOf` for cross-domain searches), the framework SHALL support an optional write-time materialized cache keyed on the user DNT, invalidated transactionally on every forward-link write. The cache invalidation graph is the responsibility of the DSA's referential-integrity module — when a forward-link write commits, the DSA SHALL enqueue a cache-invalidation event for every back-link affected by the write.

For AD-interop mode, the schema SHALL define `member` and `memberOf` with OIDs `2.5.4.31` and `2.5.4.35` and linkIDs 3 and 4 respectively, byte-identical to MS-ADTS. The framework SHALL emit `memberOf` as a multi-valued DN-syntax attribute in LDAP search results, with values sorted by group DNT (matching AD's lexicographic ordering for deterministic round-trips).

**Concrete specification**:

- The DSA SHALL reject direct LDAP modify operations on `memberOf`, `managedObjects`, `directReports`, and every other back-link attribute (linkID is odd — back-links are odd; forward links are even) with `unwillingToPerform (53)`.
- The DSA SHALL write a link-value store row (`linkDNT`, `backlinkDNT`, `linkID`, `fIsPresent`, metadata) atomically with every forward-link write, in the same storage transaction. Partial commits SHALL roll back the entire transaction.
- On forward-link delete (direct removal, group tombstone, or target tombstone), the DSA SHALL mark the corresponding link-value store row as `fIsPresent = FALSE` within the same transaction. The tombstoned row SHALL be retained for `tombstoneLifetime` days (cross-reference PC-009) for replication convergence, then GC'd.
- A search for `memberOf` on a user object SHALL return the DNs of all groups for which a `linktable` row with `backlinkDNT = user.DNT AND linkID = 4 AND fIsPresent = TRUE` exists.
- The KDC's PAC builder SHALL read group memberships via the same link-value store API; no separate `tokenGroups` cache is required (cross-reference ADR-009 for `tokenGroups` caching strategy).
- The DSA SHALL support `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`) on `member` and `memberOf` for recursive queries, implemented as a transitive-closure walk over the link-value store with a depth cap (default: 256; configurable).
- For AD-interop mode, the `memberOf` attribute returned in LDAP search results SHALL be byte-identical to AD's output, including the DN-syntax BER encoding and value ordering.

## Rationale

The bidirectional link is non-negotiable for AD interop. Every reference implementation of an AD-compatible directory (Samba 4's `source4/dsdb/samdb/ldb_modules/memberof.c`, OpenLDAP's `slapd-memberof` overlay, 389-DS's `memberOf` plugin) implements this exact pattern: forward-link writes trigger back-link materialization in the same transaction, back-links are read-only for clients, and the link-value store is the source of truth. Repeating this design is the lowest-risk path; deviating would break every AD-aware application.

Three alternatives were considered:

**Alternative A — Store `memberOf` as a regular multi-valued attribute, updated by the DSA on forward-link writes (no reverse-index read).** This is the OpenLDAP `memberof` overlay model: the overlay writes the back-link value to the user object at the same time as the forward-link write. The advantage is faster reads (the value is already materialized). The disadvantage is double-storage (every group membership is stored twice — once as `member` on the group, once as `memberOf` on the user) and the risk of divergence if the overlay fails. Rejected for the *default* mode because of the divergence risk; ADOPTED as an optional write-time materialized cache for performance-critical paths.

**Alternative B — Compute `memberOf` at read time only (no storage, pure construction).** This is the AD model for `tokenGroups`. The advantage is zero storage cost. The disadvantage is O(group count × group size) read cost — for a user in 500 groups averaging 10K members, the reverse-index scan touches 5M link-value rows. Rejected as the *sole* mechanism because of read-path cost; ADOPTED as the default for ordinary LDAP reads (where the cost is acceptable) with the optional materialized cache for the KDC's hot path.

**Alternative C — Graph database with edge traversal.** As in ADR-001, a graph database would give O(log n) transitive closure. Rejected for v1 because of the storage-engine dependency; revisited in ADR-001.

The cost of this decision is referential-integrity complexity. Every forward-link write must propagate to the back-link in the same transaction. Every object tombstone must cascade to link-value store cleanup — deleting a user requires removing all `member` references to that user from every group, which is O(group count) per deletion. Every group tombstone must cascade to `memberOf` invalidation for every member, which is O(group size) per deletion. These cascades are CPU-bound but unavoidable; the DSA's referential-integrity module handles them in a background task for large cascades (>1000 affected rows) and inline for small cascades.

External evidence: [MS-ADTS §3.1.1.3.2.26](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) describes the link-table semantics; Samba 4's `ldb_modules/memberof.c` is the reference open-source implementation; OpenLDAP's `slapd-memberof` overlay (per [RFC 4512](https://www.rfc-editor.org/rfc/rfc4512)) demonstrates the same pattern in a non-AD directory. All three converge on the same design.

## Consequences

**Positive**: AD-aware applications work without modification — Exchange, SharePoint, ADUC, every custom LDAP app that filters on `memberOf`, the Kerberos KDC's PAC builder, and Azure AD Connect's group-sync all see correct `memberOf` values. The framework is wire-compatible with AD for the most queried attribute in the directory.

**Negative**: The referential-integrity module adds write-path CPU cost — every forward-link write triggers a back-link update, and every object tombstone triggers a cascade. For a busy DC handling 10K group-membership changes per second, the referential-integrity module is ~15% of write-path CPU. The link-value store's reverse index adds storage overhead (~80 bytes per back-link row).

**Neutral**: The default read-time construction matches AD's behavior; the optional write-time materialized cache matches OpenLDAP's `memberof` overlay. Deployments choose based on read/write ratio.

**Implementation cost**: ~6 person-weeks for the referential-integrity module, link-value store reverse index, `LDAP_MATCHING_RULE_IN_CHAIN` support, and AD-interop byte-identical output. The bulk of the work is the cascade-on-tombstone logic and the cache-invalidation event graph.

**Operational impact**: Group-membership changes are immediately visible to `memberOf` queries (no cache lag). Deleting a large group (10K+ members) triggers a cascade that may take seconds; the DSA's background-task queue absorbs this without blocking the LDAP write that triggered the delete. Administrators see the same `memberOf` output from `Get-ADUser -Properties memberOf` as they would from AD.

## Alternatives Considered

### Alternative 1: Stored `memberOf` (OpenLDAP `memberof` overlay model)

The overlay writes the back-link value to the user object at the same time as the forward-link write. Reads are fast (value already materialized) but storage is doubled and divergence risk exists if the overlay fails. ADOPTED as an optional write-time materialized cache for performance-critical paths (KDC PAC builder); REJECTED as the default because of the divergence risk.

### Alternative 2: Pure read-time construction (AD `tokenGroups` model)

Zero storage cost; O(group count × group size) read cost. ADOPTED as the default for ordinary LDAP reads; REJECTED as the sole mechanism because of read-path cost for the KDC's hot path.

### Alternative 3: Graph database with edge traversal

O(log n) transitive closure; novel storage-engine dependency. Rejected for v1 (cross-reference ADR-001); revisited if `tokenGroups` performance becomes the bottleneck.

## Open Questions

- What is the cascade threshold for background-task offload? Inline for <1000 affected rows; background for ≥1000 — is this tunable per-deployment?
- For cross-domain move (PC-010, DEFERRED), does the back-link need to be rewritten as a foreign-SID reference, or does the framework's identity model (gated by ORQ-026/027 SIDs vs UUIDs) eliminate this?
- The optional write-time materialized cache: what is the invalidation strategy for cross-DC replication convergence? Event-driven invalidation on replication apply is correct but adds CPU to the replication path.

## Cross-capability impact

- **KDC**: PAC builder reads group memberships via the link-value store; the optional materialized cache (cross-reference ADR-018 KDC horizontal scaling) is the KDC's hot path.
- **Auth Provider**: S4U2Proxy (`msDS-AllowedToDelegateTo`) and RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) are linkID-paired and use the same referential-integrity module.
- **Policy Engine**: GPO security filtering reads `memberOf` to determine which GPOs apply to a user; correctness depends on this ADR.
- **Cert Service**: Published-cert back-links (`userCertificate` / `certPublicationSubject`) follow the same pattern.
- **Federation Gateway**: Claim issuance reads `memberOf` for group-based claim rules.
- **File Gateway**: Share ACLs reference group SIDs; group membership resolution uses the link-value store.

## References

- [PC-004](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — `linktable` schema, `linkDNT` / `backlinkDNT` columns, `linkbase` encoding
- [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md) — `linkID` pairing table
- [MS-ADTS §3.1.1.3.2.26](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — link-table semantics
- [RFC 4512 §4.1.2](https://www.rfc-editor.org/rfc/rfc4512#section-4.1.2) — LDAP schema definitions
- [Samba 4 `ldb_modules/memberof.c`](https://github.com/samba-team/samba/blob/master/source4/dsdb/samdb/ldb_modules/memberof.c) — reference implementation
