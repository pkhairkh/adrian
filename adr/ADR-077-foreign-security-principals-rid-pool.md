---
title: "ADR-077: RID Pool Allocation, Foreign Security Principals, and sIDHistory Migration"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-015
severity: high
unblocked_by: Workshop Decision 3 (ORQ-026/027)
tags: [adr, core-directory, rid-pool, foreign-security-principals, sidhistory, sid, uuid, identity-mapping]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-03-identity-model.md
  - ../catalog/01-core-directory.md
  - ../docs/00-overview/04-fsmo-roles.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-075-cross-domain-move.md
  - ./ADR-076-fsmo-role-replacement.md
last_updated: 2026-08-13
---

# ADR-077: RID Pool Allocation, Foreign Security Principals, and sIDHistory Migration

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-026/027 (identity model). It is now unblocked by [Workshop Decision 3 (UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping)](../workshop/decision-03-identity-model.md).

## Context

Each AD DC requests RIDs from the RID Master in batches of 500 (default `msDS-RIDPoolSize`). When the local pool drops below 50% (alert threshold, event 16656), the DC requests a new pool; when the local pool drops below ~20%, the DC alerts urgently. When the pool is exhausted, no new security principals can be created (event 16645). The RID Master itself maintains a forest-wide `rIDAvailablePool` (a 64-bit counter, low 31 bits = next RID, high 33 bits = reserved) on the `CN=RID Manager$,CN=System,<domain-dn>` object, per [PC-015](../catalog/01-core-directory.md#pc-015--rid-pool-allocation-is-a-500-rid-batch-bottleneck) and [docs/00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md).

The RID space per domain is bounded by the 32-bit RID component of the SID (`S-1-5-21-<domain>-<rid>`), giving a theoretical max of 2^30 RIDs (~1 billion) per domain. RID pool collision is a real risk: if a DC is restored from snapshot (USN rollback), its local pool may overlap with RIDs already issued by the restored DC before the snapshot. AD detects this via the `rIDPreviousAllocationPool` / `rIDAllocationPool` attributes and the RID Master's "RID pool cleanup" mechanism. Without detection, two DCs could issue the same RID to different objects — a catastrophic identity collision.

Closely related is the **Foreign Security Principal** concept. When a principal from a trusted forest is granted access to a resource in this forest, AD creates a Foreign Security Principal object in `CN=ForeignSecurityPrincipals,<domain-dn>` (well-known container GUID `221ac1a7-6f24-4c89-8e68-26d2bf7822bb`). The FSP object's `objectSid` is the foreign principal's SID; the FSP is a placeholder that allows AD-aware tools to display the foreign principal by SID. The FSP does not have a UUID primary key in AD (its `objectGUID` is auto-generated); ACLs reference the foreign principal's SID directly. The framework must preserve FSP semantics for AD-interop compatibility.

`sIDHistory` (per Decision 3) is the multi-valued SID set that preserves the principal's previous SIDs across migration. `sIDHistory` is the substrate for parallel-run migration (PC-126) — during parallel-run, the principal exists in both AD and the framework, with the same SID; after cut-over, the AD-side principal is deleted, and the framework's principal retains the SID in `sIDHistory` for backward compatibility with AD-aware tools that reference the old SID.

**Unblocking decision.** [Workshop Decision 3](../workshop/decision-03-identity-model.md) specifies: UUID-primary identity (no RID-pool bottleneck for UUIDs); SID-as-attribute (preserved for AD-interop); RID-pool allocator (500-RID batches for AD-interop mode matching AD's `RIDAllocationPoolSize`); local RID allocation for native mode (each DC maintains its own RID counter); per-trust `sIDHistory` filtering (for PC-120 mitigation); `sIDHistory` preserved on the wire (for PC-124 migration). This ADR translates Decision 3 into the concrete RID-pool, FSP, and `sIDHistory` implementation.

## Decision

The framework SHALL implement a dual-mode RID allocator: a RID-pool allocator (AD-interop mode, 500-RID batches matching AD) and a local RID allocator (native mode, per-DC counter). Foreign Security Principals SHALL be created on-demand when a foreign SID is referenced in an ACL or group membership. `sIDHistory` SHALL be preserved on the wire for AD-interop, with per-trust filtering for security (per PC-120 mitigation).

**Concrete specification**:

### RID Pool Allocation

- For AD-interop mode, the framework SHALL implement a RID-pool allocator (the `adrian-identity-ridpool` crate per Decision 3) that dispenses 500-RID batches (matching AD's `RIDAllocationPoolSize`). The allocator state is stored in FDB subspace `0x06` with the key `(0x06, domain_sid) → (next_rid, last_allocated_rid, pool_exhaustion_warning_threshold)`.
- The `next_rid` counter SHALL use FDB's `atomic_op` (AtomicOp::Add) for lock-free allocation. When `next_rid` exceeds `last_allocated_rid`, the DC requests a new 500-RID batch from the RID Master (per ADR-076). The RID Master updates `(0x06, domain_sid)` atomically (FDB strict serializable transaction) to allocate the next batch.
- RID pool exhaustion detection: when `next_rid` exceeds `last_allocated_rid - 50` (the alert threshold, ~10% remaining), the framework SHALL emit a warning event (equivalent to AD's event 16656). When `next_rid` exceeds `last_allocated_rid` (exhaustion), the framework SHALL emit a critical event (equivalent to AD's event 16645) and reject new security-principal creation with `unwillingToPerform (53)`.
- RID pool collision detection (USN rollback): the framework SHALL store `rIDPreviousAllocationPool` (the previous batch's `[start, end]`) and `rIDAllocationPool` (the current batch's `[start, end]`) in FDB subspace `0x06`. On DC boot, the framework SHALL compare the stored `rIDAllocationPool` with the DC's `invocationId`-keyed RID counter. If a mismatch is detected (the DC's counter is lower than the stored pool, indicating a snapshot restore), the framework SHALL self-quarantine (matching AD's behaviour) and require `adrian-repl reset-invocation-id` (per ADR-071) before resuming RID allocation.
- For native mode, RID allocation is local — each DC maintains its own RID counter at `(0x06, local_dc_id, domain_sid) → next_rid`. The DC's `local_dc_id` is its `invocationId`. No RID-master coordination. The 2^32 RID limit is per-DC (effectively unlimited).
- The framework SHALL expose `adrian-identity rid-pool show --domain <domain-dn>` CLI equivalent to `Get-ADDomain | Select RIDAvailablePool, RIDMaster`.
- The framework SHALL support `msDS-RIDPoolSize` configuration (default 500; can be increased up to 5000 for high-throughput domains).

### Foreign Security Principals

- The framework SHALL create Foreign Security Principal (FSP) objects on-demand when a foreign SID is referenced in an ACL or group membership and no FSP exists for that SID. The FSP object is created in `CN=ForeignSecurityPrincipals,<domain-dn>` (well-known container GUID `221ac1a7-6f24-4c89-8e68-26d2bf7822bb` per PC-011).
- The FSP object's `objectSid` is the foreign principal's SID. The FSP's `objectGUID` is auto-generated (UUIDv7, per Decision 3). The FSP does not have a `sAMAccountName` (foreign principals are not in this domain's account namespace).
- The framework SHALL register the FSP in the identity mapping table (FDB subspace `0x0D) with the foreign SID as the key. The mapping table entry's `principal_type` is `ForeignSecurityPrincipal`.
- The framework SHALL NOT replicate FSPs via DRSUAPI as new objects — the FSP is created on-demand on each DC that references the foreign SID (matching AD's behaviour). The framework's identity mapping table ensures consistency (the mapping table is replicated).
- The framework SHALL expose `adrian-identity fsp show --sid <sid>` and `adrian-identity fsp list` CLI for FSP inspection.

### sIDHistory

- Every security principal object MAY have a `sIDHistory` attribute (multi-valued SID set) for migrated principals. The framework SHALL preserve `sIDHistory` on the wire for AD-interop mode (per PC-124) — the DRSUAPI `REPLENTIN` payload includes `sIDHistory` as a multi-valued attribute.
- For native mode, `sIDHistory` is preserved but not exposed via PAC (the framework's native PAC includes only the current SID). For AD-interop mode, `sIDHistory` is exposed via PAC (matching AD's behaviour).
- Per-trust `sIDHistory` filtering (per PC-120 mitigation): the framework's trust configuration specifies which `sIDHistory` entries are exposed to which trusts. The KDC's PAC builder (per Decision 5) applies the filtering at PAC-issuance time. The default is "expose all `sIDHistory`" (matching AD); deployments can configure `sIDHistoryFiltering = strict` to expose only the current SID and the SIDs from explicitly-trusted forests.
- The framework SHALL expose `adrian-identity sid-history show --uuid <uuid>` and `adrian-identity sid-history add --uuid <uuid> --sid <sid>` CLI for manual `sIDHistory` management (used during migration).
- The framework's migration tool (per ADR for PC-124) reads the source AD's `sIDHistory`, writes the principal's UUID + current SID + `sIDHistory` in the mapping table atomically (single FDB transaction). Downstream ACLs and PACs continue to reference the old SID via `sIDHistory`.

### Performance and Safety

- RID allocation in AD-interop mode SHALL complete in ≤50 ms per 500-RID batch (network round-trip to RID Master). RID allocation in native mode SHALL complete in ≤1 ms (local FDB atomic-add).
- FSP creation SHALL complete in ≤10 ms (single FDB transaction: write FSP object + update mapping table).
- `sIDHistory` add SHALL complete in ≤10 ms (single FDB transaction: update principal's `sIDHistory` attribute + update mapping table).
- The framework SHALL detect and reject RID pool collision (USN rollback) before any new RID is allocated — the detection runs at DC boot and is a readiness gate for the `adrian-operator` (per ADR-058).

## Rationale

The RID-pool bottleneck is inherent to AD's SID-based identity model — SIDs require a unique RID per principal, and RID allocation must be coordinated to prevent collision. The framework inherits this bottleneck for AD-interop mode (required for AD-interop wire compatibility). For native mode, the framework eliminates the bottleneck via local RID allocation (each DC has its own counter; no coordination needed).

Foreign Security Principals are an AD-interop compatibility requirement — AD-aware tools (ADUC, ADSI Edit) expect FSP objects in `CN=ForeignSecurityPrincipals,<domain-dn>` for displaying foreign principals by SID. The framework creates FSPs on-demand to satisfy this expectation without manual admin intervention.

`sIDHistory` is the substrate for parallel-run migration (PC-126) — without `sIDHistory`, cut-over migration breaks AD-aware tools that reference the old SID. The framework preserves `sIDHistory` on the wire (AD-interop) and in storage (both modes) for migration compatibility.

Per-trust `sIDHistory` filtering (per PC-120) is a security mitigation — `sIDHistory` can be abused to escalate privileges across trusts (a principal with `sIDHistory = {Enterprise Admins SID}` gains Enterprise Admin rights). The framework's filtering is configurable per-trust, defaulting to "expose all" for AD-interop compatibility and recommending "strict" for high-security deployments.

External evidence: Microsoft Entra ID (Azure AD) uses a similar model — `onPremisesSecurityIdentifier` is preserved for hybrid scenarios; `sIDHistory` is preserved in on-prem AD for migration. Samba 4 implements RID allocation in `source4/dsdb/common/util.c` `ridalloc` module. FreeIPA uses UUIDs for unique IDs but still allocates SIDs for AD interop. The pattern is industry-standard.

## Consequences

**Positive**: Native-mode deployments eliminate the RID-pool bottleneck (local RID allocation, no RID-master dependency). AD-interop deployments inherit AD's RID-pool model (500-RID batches) for wire compatibility. FSPs are created on-demand (no manual admin intervention). `sIDHistory` is preserved for migration compatibility. Per-trust `sIDHistory` filtering mitigates PC-120.

**Negative**: AD-interop mode inherits AD's 2^32 RID-per-domain limit (~1 billion SIDs). Deployments that anticipate exceeding this limit should use native mode. The RID-pool collision detection (USN rollback) is an operational concern — admins must understand the detection and the `adrian-repl reset-invocation-id` recovery path.

**Neutral**: The identity mapping table (per Decision 3) is the authoritative source of truth for UUID ↔ SID correspondence. RID allocation, FSP creation, and `sIDHistory` management all update the mapping table atomically.

**Cost**: ~5 person-months (per Decision 3) for the `adrian-sid` crate, the `adrian-identity-core` trait, the `adrian-identity-fdb` implementation, the RID-pool allocator, and the in-memory cache. FSP creation and `sIDHistory` management are sub-features within the identity stack.

**Operational impact**: RID-pool monitoring is a deployment concern (Prometheus/OTel metric: `rid_pool_remaining`). FSP creation is automatic (no admin intervention). `sIDHistory` management is a migration concern (the migration tool handles it). Per-trust `sIDHistory` filtering is a deployment-configurable property (`sIDHistoryFiltering = permissive | strict`).

## Alternatives Considered

### Alternative 1: Replace SIDs with UUIDs entirely (eliminate RID allocation)

Drop SIDs — use UUIDs as the sole identifier. Eliminates RID-pool bottleneck, RID-master FSMO role, 2^32 RID limit. But breaks AD-interop (AD-aware tools expect SIDs in ACLs, PACs, audit logs). Rejected: Decision 3 explicitly preserves SIDs as the wire-format currency for AD interop.

### Alternative 2: Consensus-based RID allocation (Raft per-domain for RID pool)

Replace the RID Master with a Raft group per domain that dispenses RIDs. Eliminates the single-master bottleneck. But adds Raft consensus latency (~10 ms per allocation) and complexity. Rejected for v1 — FDB atomic-add counter (per Decision 3) provides the same coordination without a separate Raft group. May be revisited if FDB atomic-add proves insufficient for very-high-throughput domains (>100K principals/sec).

### Alternative 3: No FSP creation (admins create FSPs manually)

Document that admins must create FSPs manually when adding a foreign SID to an ACL. Simpler implementation. But breaks AD-aware tools that expect FSPs to exist automatically (ADUC displays "Account unknown" for foreign SIDs without FSPs). Rejected for AD-interop compatibility.

## Open Questions

- For native mode, should the framework expose `msDS-RIDPoolSize` for compatibility? Default: yes (read-only; the value is ignored in native mode). Confirm in implementation.
- For per-trust `sIDHistory` filtering, what is the default for native-mode forests that later join an AD forest via trust? Default: `permissive` (expose all `sIDHistory`) for AD-interop compatibility. Confirm with security review.
- For the RID-pool collision detection, should the framework auto-recover (reset `invocationId` and re-allocate RIDs from the current pool) or require admin intervention? Default: require admin intervention (`adrian-repl reset-invocation-id`) — auto-recovery risks silent SID collision if the detection is a false positive. Confirm with security review.

## Cross-capability impact

- **KDC**: KDC's PAC builder reads the principal's current SID and `sIDHistory` via the identity mapping table. RID allocation does not affect the KDC (the KDC reads existing principals, not new ones). Per-trust `sIDHistory` filtering is applied at PAC-issuance time.
- **Auth Provider**: NTLM hash storage is on the principal object keyed by UUID. RID allocation does not affect Auth Provider.
- **Policy Engine**: GPO security filtering references principals by SID. The framework's ACL evaluator consults `sIDHistory` to resolve old SIDs (for migration compatibility).
- **Cert Service**: Certificate templates reference principals by UUID (internal) or SID (AD-interop). The framework's mapping table handles translation.
- **File Gateway**: File ACLs reference principals by SID. FSPs are created on-demand when a foreign SID is referenced.
- **Client SDK**: `getpwuid` and `getgrgid` queries use the identity mapping table; RID allocation is transparent.
- **Migration**: AD-to-framework migration uses `sIDHistory` to preserve AD-aware tool compatibility. The migration tool (per PC-124) reads the source AD's `sIDHistory` and writes the principal's UUID + SID + `sIDHistory` in the mapping table atomically.
- **Security**: PC-120 (`sIDHistory` abuse) is mitigated by per-trust `sIDHistory` filtering. PC-117 (DCSync) — RID allocation is not a DCSync attack surface (DCSync reads secrets, not RIDs).

## References

- [PC-015](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 3 — UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping](../workshop/decision-03-identity-model.md) — unblocking decision
- [docs/00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md) — RID Master role, pool allocation algorithm, `rIDAvailablePool` / `rIDAllocationPool` / `rIDPreviousAllocationPool` attributes
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — RID allocation in ESE, RID pool collision detection
- [MS-ADTS §3.1.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — RID Master, RID pool, `sIDHistory`
- [MS-DTYP §2.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/) — SID binary format
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) — UUIDv7
- [ADR-075: Cross-Domain Move](./ADR-075-cross-domain-move.md) — SID rewrite on cross-domain move, `sIDHistory` preservation
- [ADR-076: FSMO Role Replacement](./ADR-076-fsmo-role-replacement.md) — RID Master elimination in native mode
