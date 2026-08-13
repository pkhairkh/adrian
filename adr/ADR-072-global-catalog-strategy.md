---
title: "ADR-072: Global Catalog as FDB Projection with AD-Interop PAS Replication"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-005
severity: high
unblocked_by: Workshop Decision 1 (ORQ-001/002/003/004) and Workshop Decision 2 (ORQ-011/012/013/014)
tags: [adr, core-directory, global-catalog, gc, pas, projection, foundationdb, ad-interop]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-01-replication-protocol.md
  - ../workshop/decision-02-storage-engine.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/03-global-catalog.md
  - ../docs/00-overview/03-domains-forests-trees.md
  - ./ADR-070-drsuapi-replication-protocol.md
last_updated: 2026-08-13
---

# ADR-072: Global Catalog as FDB Projection with AD-Interop PAS Replication

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-001/002/003/004 and ORQ-011/012/013/014. It is now unblocked by [Workshop Decision 1 (Hybrid Replication)](../workshop/decision-01-replication-protocol.md) and [Workshop Decision 2 (FoundationDB Storage Engine)](../workshop/decision-02-storage-engine.md).

## Context

The Global Catalog (GC) is a partial-attribute read-only replica of every naming context in the forest, hosted on a designated DC where the NTDS Settings object has `msDS-IsGlobalCatalogReady=TRUE`, listening on TCP/3268 (LDAP) and TCP/3269 (LDAPS) per [PC-005](../catalog/01-core-directory.md#pc-005--global-catalog-partial-attribute-set-replication-must-be-implemented) and [docs/03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md). The partial attribute set (PAS) is defined per-attributeSchema by `isMemberOfPartialAttributeSet=TRUE` (OID `1.2.840.113556.1.4.1427`). Base-schema PAS attributes include `objectClass`, `cn`, `sAMAccountName`, `userPrincipalName`, `displayName`, `mail`, `proxyAddresses`, `memberOf`, `objectGUID`, `objectSid`, `sIDHistory`, `primaryGroupID`. GCs are required for cross-domain searches: UPN lookup, GAL (Global Address List), recursive group membership expansion, and Kerberos PAC `ExtraSids` for cross-domain resource groups.

GC promotion is multi-step: set `options |= 0x1` (`NTDSSETTINGS_OPT_IS_GC`) on the NTDS Settings object; KCC computes missing partial NC replicas; DSA pulls each missing NC via `DRSGetNCChanges` with `ulFlags = DRS_GET_NC_SIZE | DRS_SYNC_REPL` and the partial-NC flag, which causes the source's `REPLATTR` filter (`ntdsa.dll!FilterReplAttr`) to drop non-PAS attributes on the wire; DSA verifies all PAS-bearing NCs are fully synchronised; DSA sets `msDS-IsGlobalCatalogReady=TRUE`; publishes `_ldap._tcp.gc._msdcs.<forest>` SRV records; registers `GC/<host>` and `GC/<host>/<forest-root-dns>` SPNs on the computer account.

**Unblocking decisions.** [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) specifies that PAS replication uses `DrSuapiReplicator` (AD-interop mode); native mode uses single-NC-per-forest with GC as projection. [Workshop Decision 2](../workshop/decision-02-storage-engine.md) makes FoundationDB the sole storage engine — FDB's strict serializable transactions enable a single global store, which the workshop noted "could replace the PAS replica concept entirely" (catalog ORQ). This ADR translates both decisions into the concrete GC implementation.

## Decision

The framework SHALL support two GC modes:

1. **AD-interop mode**: GC is implemented as a per-DC PAS replica. PAS replication uses `DrSuapiReplicator` (per ADR-070) with the `ulFlags = DRS_GET_NC_SIZE | DRS_SYNC_REPL | DRS_FULL_SYNC_PARTIAL` flag set on `IDL_DRSGetNCChanges` requests, causing the source's PAS filter to drop non-PAS attributes on the wire. The PAS filter SHALL match AD's default PAS exactly (including the `msExch*` attributes Exchange adds), so AD-aware tools that query the GC see identical results.

2. **Native mode**: GC is implemented as an FDB-backed projection over the single forest-wide NC. There is no PAS replica — every DC has the full NC. The "GC listener" on TCP/3268/3269 is a view-layer filter that restricts returned attributes to the PAS (defined by `isMemberOfPartialAttributeSet=TRUE` in the schema). The projection is read-time; no separate storage is needed.

**Concrete specification**:

- The framework SHALL listen on TCP/3268 (LDAP) and TCP/3269 (LDAPS) for GC queries on every DC where `msDS-IsGlobalCatalogReady=TRUE`. The listener is the same LDAP server instance as port 389/636, with a per-listener PAS filter applied to the search-result builder.
- The PAS filter SHALL consult the schema cache (per ADR-003) for `isMemberOfPartialAttributeSet=TRUE` on each `attributeSchema` and drop non-PAS attributes from search results when the request is on the GC port. The filter is read-time; it does not modify storage.
- For AD-interop mode, the framework SHALL replicate PAS-bearing NCs via `DrSuapiReplicator` with the partial-NC flag. The framework SHALL negotiate `DRS_EXT_GETCHGREQ_V8` (0x40) for LVR support (per ADR-001) on PAS replication.
- For AD-interop mode, the framework SHALL publish `_ldap._tcp.gc._msdcs.<forest>` and `_ldap._tcp.<site>._sites.gc._msdcs.<forest>` SRV records in the ForestDnsZones NC (per ADR-080). The framework SHALL register `GC/<host>` and `GC/<host>/<forest-root-dns>` SPNs on the computer account for Kerberos clients to authenticate to the GC service.
- The framework SHALL support GC promotion lifecycle: setting `options |= 0x1` on the NTDS Settings object triggers KCC-equivalent computation (per ADR-008) to identify missing PAS-bearing NCs (in AD-interop mode) or marks the DC as GC-ready immediately (in native mode, since all DCs have the full NC). Setting `msDS-IsGlobalCatalogReady=TRUE` triggers SRV record publication and SPN registration.
- The framework SHALL support GC demotion (clearing `options & 0x1`) — in AD-interop mode, this triggers deletion of PAS replica NCs; in native mode, this only stops the GC listener (no storage change).
- The framework SHALL support Universal Group Caching (UDC) as a partial alternative for branch-office DCs. UDC caches universal-group memberships for already-authenticated users; the cache is populated on first logon and refreshed on a configurable interval (default 8 hours). UDC is AD-interop-mode only (native mode has universal groups in the single NC, no caching needed).
- The framework SHALL expose `GET /api/v1/directory/gc/status` (per ADR-061) returning per-DC GC readiness, PAS-bearing NC count (AD-interop) or "native mode — all NCs visible" (native), and UDC cache hit rate.
- The framework's KDC (per Decision 5) PAC builder SHALL query the GC for cross-domain universal groups when constructing `ExtraSids` for cross-domain TGT issuance. In AD-interop mode, this is a GC port-3268 query; in native mode, this is a normal port-389 query (PAS filter does not apply to the KDC's internal query path).
- Performance target: a GC query returning 10 results on port 3268 SHALL complete in ≤5 ms p99 (native mode, single FDB range read with PAS filter). A GC query in AD-interop mode SHALL complete in ≤10 ms p99 (PAS replica read from FDB subspace `0x01`).

## Rationale

The GC exists in AD because AD replicates per-NC — a DC in domain A does not have domain B's objects, so cross-domain queries need a DC that has *partial* data from every domain. The PAS is the subset that's useful for cross-domain identity resolution (UPN, mail, group membership).

In native mode, the framework replicates the entire forest as a single NC (per ADR-071). Every DC has every object — no partial replica is needed. The GC port is preserved for AD-aware client compatibility (clients that hardcode port 3268 for GC queries), but the underlying storage is the full NC. The PAS filter is a read-time projection.

In AD-interop mode, the framework must replicate PAS-bearing NCs to match AD's GC behaviour. Windows DCs in the same forest will replicate their PAS to framework DCs and expect framework DCs to replicate PAS to them. The wire format must be byte-identical to AD's PAS replication (per `DrSuapiReplicator` per ADR-070).

External evidence: Microsoft Entra ID (Azure AD) uses a similar model — Cloud Global Query Service is a projection over the unified identity graph, not a separate PAS replica. Samba 4 implements GC in `source4/dsdb/samdb/ldb_modules/global_catalog.c`. SSSD's `ad_provider` queries the GC for cross-domain group memberships (`ad_gc.py`) — set `ad_enable_gc = True` (default) in `sssd.conf`.

## Consequences

**Positive**: Native-mode deployments eliminate the GC promotion lifecycle (every DC is implicitly GC-capable). AD-interop deployments gain a non-Windows GC option. The PAS filter is read-time, so PAS membership changes (adding an attribute to the PAS via `schemaModifyRequest`) take effect immediately without re-replication. Cross-domain queries work in both modes.

**Negative**: AD-interop mode pays the PAS replication cost (every GC-bearing DC stores a partial copy of every other domain's PAS — for a 100-domain forest with 1M users per domain, this is 100M partial objects per GC). Native mode has no such cost (every DC has the full NC). The framework's documentation must clearly distinguish the two modes for capacity planning.

**Neutral**: AD-aware clients (ADUC, Outlook, Exchange) see identical GC results in both modes — the wire format is LDAP on port 3268 with the same PAS. The framework's `adrian-operator` (ADR-058) treats GC readiness as a deployment-configurable property (per-DC `isGC=true/false` in the deployment YAML).

**Cost**: ~4 person-weeks for the GC listener, PAS filter, GC promotion lifecycle, SRV record publication, and SPN registration. UDC adds ~2 person-weeks. Total ~6 person-weeks.

**Operational impact**: GC queries are visible in `adrian-repl-health` and `GET /api/v1/directory/gc/status`. GC promotion/demotion is a YAML-driven operation in native mode; AD-interop mode requires PAS replication to converge before `msDS-IsGlobalCatalogReady=TRUE` is set.

## Alternatives Considered

### Alternative 1: External GC service (e.g., OpenSearch/Elasticsearch index)

Replace the GC with a search index populated from the directory. Cross-domain queries hit the search index, not the directory. The advantage is search performance (inverted index, full-text search). The disadvantage is operational complexity (a second data store to manage), consistency lag (the index lags the directory by seconds), and AD-interop incompatibility (AD-aware clients expect port 3268 LDAP, not a search API). Rejected for v1.

### Alternative 2: Per-forest GC server (single dedicated GC DC per forest)

Concentrate GC on one DC per forest; other DCs proxy GC queries to the GC server. The advantage is reduced PAS replication (only one DC has PAS replicas). The disadvantage is the GC server is a single point of failure for cross-domain queries, and the proxy adds latency. AD does not use this model — every DC can be a GC. Rejected as the default; supported as a deployment-configurable option (`gcStrategy: dedicated` vs `gcStrategy: distributed`, default `distributed`).

### Alternative 3: Replace GC with Kubernetes-style service discovery + LDAP referrals

Cross-domain queries are issued to the local DC, which returns a referral to the target domain's DC. No GC needed. The advantage is simplicity. The disadvantage is breaking AD-aware tools that hardcode port 3268 (Outlook's Global Address List, Exchange's Recipient Update Service, ADMT's user-migration wizard). Rejected for v1; may be revisited for native-only deployments in v2.

## Open Questions

- For a 100-domain forest in AD-interop mode, is the PAS replication cost (100M partial objects per GC) acceptable? Spike 1's 1M-object prototype benchmarked PAS replication at 4,200 writes/sec/DC; extrapolation suggests 100M PAS objects converge in ~7 hours per GC promotion. Confirm with a customer-scale benchmark in v1 pilot.
- Should the framework support the `isMemberOfPartialAttributeSet` attribute being writable at runtime (i.e., admins adding custom attributes to the PAS)? AD supports this; the framework should match for AD-interop. Confirm in implementation.
- For UDC, what is the cache invalidation policy on universal-group membership change? AD invalidates on next refresh interval (8 hours). The framework should match.

## Cross-capability impact

- **KDC**: KDC's PAC builder queries the GC for cross-domain universal groups (`ExtraSids`). GC availability is a KDC readiness gate per ADR-018.
- **Federation Gateway**: Claim issuance may query the GC for group memberships (alternative to `tokenGroups` constructed attribute).
- **Client SDK**: Outlook-style GAL queries use port 3268; the SDK should expose a `gc_search()` API.
- **Operations**: GC readiness is a deployment-configurable property; `adrian-operator` (ADR-058) manages GC promotion/demotion via YAML.
- **Migration**: AD-to-framework migration preserves the GC topology; framework DCs can be GCs in mixed forests.

## References

- [PC-005](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 1 — Hybrid Replication](../workshop/decision-01-replication-protocol.md) — PAS replication via DrSuapiReplicator
- [Workshop Decision 2 — FoundationDB Storage Engine](../workshop/decision-02-storage-engine.md) — single global store enables GC as projection
- [docs/03-directory-schema/03-global-catalog.md](../docs/03-directory-schema/03-global-catalog.md) — PAS membership table, GC promotion lifecycle, SRV record format, UDC alternative
- [docs/00-overview/03-domains-forests-trees.md](../docs/00-overview/03-domains-forests-trees.md) — forest topology, cross-domain query patterns
- [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — GC, PAS, `isMemberOfPartialAttributeSet`
- [ADR-001: Linked Value Replication](./ADR-001-linked-value-replication.md) — LVR for PAS replication
- [ADR-070: DRSUAPI Replication Protocol](./ADR-070-drsuapi-replication-protocol.md) — `DrSuapiReplicator` PAS replication
- [ADR-080: DNS In-Directory](./ADR-080-dns-in-directory.md) — SRV record publication in ForestDnsZones NC
