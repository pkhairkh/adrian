---
title: "ADR-075: Cross-Domain Move via UUID-Stable Identity with Atomic SID Rewrite"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-010
severity: medium
unblocked_by: Workshop Decision 3 (ORQ-026/027) and Workshop Decision 4 (ORQ-030/031)
tags: [adr, core-directory, cross-domain-move, infrastructure-master, sidhistory, uuid, identity-mapping]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-03-identity-model.md
  - ../workshop/decision-04-schema-model.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/02-ous-containers.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-002-memberof-back-link.md
last_updated: 2026-08-13
---

# ADR-075: Cross-Domain Move via UUID-Stable Identity with Atomic SID Rewrite

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-026/027 (identity model) and ORQ-030/031 (schema model). It is now unblocked by [Workshop Decision 3 (UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping)](../workshop/decision-03-identity-model.md) and [Workshop Decision 4 (Hybrid LDAP Schema + Typed Rust Projection)](../workshop/decision-04-schema-model.md).

## Context

Moving an object within an NC is a standard LDAP ModifyDN operation (RFC 4511 §4.9). Moving an object *across* NCs (e.g., user from `corp.example.com` to `child.corp.example.com`) requires the `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` control (`1.2.840.113556.1.4.521`), carrying the target DC's NTDS Settings DN. The source DC reads the object's `nTSecurityDescriptor`, `sIDHistory`, group memberships, then calls DRSUAPI `IDL_DRSAddEntry` (opnum 17) against the target DC's `invocationId` to create the object in the target NC. The source DC then writes a tombstone with `lastKnownParent` set to the original parent DN, per [PC-010](../catalog/01-core-directory.md#pc-010--cross-domain-move-requires-ldap_server_crossdom_move_target_oid-and-pdc--rid-master-coordination) and [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md).

Cross-domain move has hard prerequisites: (1) domain functional level ≥ Windows 2000 native; (2) PDC emulator reachable in both domains; (3) RID master reachable in the target domain — the target DC needs a fresh RID for the moved object's new `objectSid` (the source domain's RID is kept in `sIDHistory`, and a new RID is allocated in the target domain); (4) admin privilege on both source and target OUs; (5) SPN attribute values must be cleared first (`servicePrincipalName` is domain-scoped); (6) group memberships across NC boundaries are rewritten as foreign-SID references in `sIDHistory`.

The Infrastructure Master FSMO role's job is to update cross-domain references when objects are renamed or moved. In forests with GCs on every DC, the Infrastructure Master is largely obsolete (the IM's cross-domain reference update is redundant when every DC has a GC). In a modern framework with a single global store (per Decision 2), the Infrastructure Master concept is entirely obsolete — cross-domain references are resolved at read-time via the identity mapping table (per Decision 3).

**Unblocking decisions.** [Workshop Decision 3](../workshop/decision-03-identity-model.md) specifies UUID-primary identity: every security principal has a UUID primary key (unchanged across moves) plus a SID attribute (rewritten on cross-domain move). The bidirectional mapping table (FDB subspace `0x0D`) is updated atomically. Cross-domain move rewrites the principal's SID; the UUID is unchanged — the move is transparent to internal APIs. [Workshop Decision 4](../workshop/decision-04-schema-model.md) specifies the typed Rust projection that exposes `Sid` and `Uuid` as first-class types, enabling the framework's internal code to operate on UUIDs without SID-translation overhead. This ADR translates both decisions into the concrete cross-domain move implementation.

## Decision

The framework SHALL implement cross-domain move via the `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` control for AD-interop compatibility, with the internal mechanics simplified by UUID-primary identity. The UUID is stable across the move; the SID is rewritten in the target domain (old SID preserved in `sIDHistory`). The Infrastructure Master FSMO role is **obsolete in native mode** (cross-domain references are resolved at read-time via the identity mapping table); in AD-interop mode, the framework emulates the IM for AD-tool compatibility but performs no actual cross-domain reference update work (the GC does this).

**Concrete specification**:

- The framework SHALL accept the `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` (`1.2.840.113556.1.4.521`) control on LDAP ModifyDN operations across NC boundaries. The control value carries the target DC's NTDS Settings DN.
- Cross-domain move SHALL execute atomically in a single FDB transaction (per Decision 2's strict serializable transactions) with the following steps:
  1. Read the source object's attributes (UUID, current SID, `sIDHistory`, group memberships, `nTSecurityDescriptor`).
  2. Allocate a new RID in the target domain (via the RID-pool allocator per Decision 3; for native mode, via the local RID allocator; for AD-interop, via the RID-master FSMO role).
  3. Construct the new SID: `S-1-5-21-<target-domain-sid>-<new-rid>`.
  4. Update the identity mapping table (FDB subspace `0x0D`): the forward index `(0x0D, 0x01, uuid) → (new_sid, sid_history + old_sid, ...)` and the reverse index `(0x0D, 0x02, old_sid) → tombstoned` and `(0x0D, 0x02, new_sid) → uuid`.
  5. Write the new object in the target NC: UUID unchanged, `objectSid = new_sid`, `sIDHistory = old_sIDHistory + old_sid`, all other attributes preserved.
  6. Tombstone the source object (per ADR-074) with `lastKnownParent` set to the original parent DN.
  7. Rewrite group memberships: for each group the user was a member of, if the group is in the source domain, the membership becomes a foreign-SID reference (the group's `member` value is the user's new SID, not the user's DN — because the user is now in a different NC). If the group is in the target domain, the membership is a local DN reference.
  8. Clear `servicePrincipalName` values (SPNs are domain-scoped; cross-domain SPN causes duplicate-SPN conflicts per PC-031). The framework SHALL emit a warning and log the cleared SPNs for admin re-add after move.
  9. Commit the FDB transaction.
- For AD-interop mode, the framework SHALL additionally call `IDL_DRSAddEntry` (opnum 17, per ADR-070) against the target DC's `invocationId` to replicate the new object to the target NC. The source-side tombstone replicates via normal DRSUAPI replication.
- For native mode (single NC per forest), cross-domain "move" is semantically equivalent to a within-NC move (the source and target are in the same NC). The framework SHALL accept the cross-domain control for AD-tool compatibility but execute the move as a within-NC ModifyDN (no SID rewrite, no RID allocation, no `sIDHistory` update — the UUID, SID, and `sIDHistory` are all unchanged). The framework SHALL log a warning that "cross-domain move in native mode is a no-op on identity; only the DN changed".
- The Infrastructure Master FSMO role SHALL be **emulated** in AD-interop mode (the `fSMORoleOwner` attribute on the Infrastructure object is writable and discoverable via LDAP) but SHALL perform **no actual work** — the framework's identity mapping table resolves cross-domain references at read-time. The framework SHALL emit a log message "Infrastructure Master role holder <DC-DN>; role is emulated — cross-domain references resolve via identity mapping table".
- The framework SHALL expose `adrian-directory move --source <dn> --target <dn> [--cross-domain]` CLI equivalent to `movetree.exe` and `Move-ADObject -TargetServer`.
- The framework SHALL support `Move-ADObject -TargetServer` PowerShell equivalent via the LDAP control (the framework's LDAP server accepts the control and executes the move).
- The framework SHALL detect and reject cross-domain move of objects with `systemFlags & FLAG_DOMAIN_DISALLOW_MOVE` (0x100) or `FLAG_DOMAIN_DISALLOW_MOVE_ON_DOMAIN` (0x200) set (per PC-021).
- Performance target: cross-domain move of a user with 100 group memberships SHALL complete in ≤500 ms (single FDB transaction). The bottleneck is RID allocation in AD-interop mode (network round-trip to RID master ~50 ms); in native mode, RID allocation is local (~1 ms).

## Rationale

AD's cross-domain move is complex because AD's primary key is the DN (which changes on move) and the SID (which changes on move). Every reference to the moved object must be updated — group memberships, ACLs, audit logs, SPNs. The Infrastructure Master FSMO role exists to update cross-domain references periodically (every 2 hours by default in AD).

The framework's UUID-primary identity (per Decision 3) eliminates this complexity. The UUID is stable across the move — every internal reference (in the link-value store, in ACLs, in audit logs) uses the UUID, which does not change. Only the SID changes (rewritten in the target domain), and the SID is updated atomically in the identity mapping table. The old SID is preserved in `sIDHistory` for backward compatibility with AD-aware tools that reference the old SID.

The Infrastructure Master FSMO role is obsolete in the framework because cross-domain references resolve at read-time via the identity mapping table — there is no periodic "update references" task to run. The role is emulated in AD-interop mode for AD-tool compatibility (`netdom query fsmo`, `Get-ADDomain | Select InfrastructureMaster`) but performs no work.

The SPN-clear requirement (constraint 5 in the catalog) is preserved because SPNs are domain-scoped in AD — a cross-domain SPN causes duplicate-SPN conflicts (PC-031). The framework matches AD's behaviour for AD-interop compatibility.

External evidence: Microsoft Entra ID (Azure AD) uses a similar model — `objectGUID` is stable across moves, `onPremisesSecurityIdentifier` is rewritten on cross-tenant move. Samba 4 implements cross-domain move in `samba-tool domain move`. The pattern of "stable internal ID, mutable wire-format ID" is industry-standard.

## Consequences

**Positive**: Cross-domain move is atomic (single FDB transaction) — no window where the object exists in both NCs or neither NC. UUID-stable identity means internal references (group memberships, ACLs, audit logs) are unchanged. The Infrastructure Master FSMO role is eliminated (no single-master bottleneck for cross-domain reference updates). `sIDHistory` is preserved for AD-aware tools that reference the old SID.

**Negative**: Cross-domain move still requires RID allocation in AD-interop mode (RID-master FSMO dependency). For native mode, this is not a concern (local RID allocation). The SPN-clear requirement is preserved — admins must re-add SPNs after move, matching AD's behaviour.

**Neutral**: AD-aware tools (`movetree.exe`, `Move-ADObject`) work via the LDAP control. The framework's `adrian-directory move` CLI is the modern equivalent. The Infrastructure Master role is documented as "emulated — no work performed" in AD-interop mode.

**Cost**: ~3 person-weeks for the cross-domain move implementation, the identity-mapping-table update logic, the SPN-clear handling, and the Infrastructure Master emulation. The RID-pool allocator (per Decision 3) is a separate ~1K-line crate.

**Operational impact**: Cross-domain move is `adrian-directory move` CLI or `Move-ADObject` PowerShell. The move is atomic; admins see "success" or "failure" — no intermediate state. The Infrastructure Master role is not a operational concern in native mode (the role is emulated in AD-interop mode for compatibility only).

## Alternatives Considered

### Alternative 1: Eliminate cross-domain move entirely (single-domain forest model)

Modern AD deployments increasingly consolidate into single-domain forests. The framework could collapse to a single domain per forest, eliminating cross-domain move entirely. The advantage is simplicity. The disadvantage is breaking AD-interop with multi-domain forests (common in legacy enterprises, joint ventures, regulated subsidiaries). Rejected for v1; documented as a deployment option (`forestModel: single-domain` vs `forestModel: multi-domain`, default `multi-domain` for AD-interop compatibility).

### Alternative 2: Cross-domain move with SID preservation (no SID rewrite)

Keep the source domain's SID in the target domain — no `sIDHistory` update, no RID allocation. The advantage is simplicity (no RID master dependency). The disadvantage is breaking AD's SID-uniqueness invariant (the SID is now in two domains' SID spaces), which causes AD-interop failures (AD DCs refuse to replicate SIDs that belong to a different domain). Rejected for AD-interop compatibility.

### Alternative 3: Cross-domain move with UUID-only (no SID rewrite)

Drop SIDs entirely — use UUIDs as the sole identifier. The advantage is no SID rewrite, no RID allocation, no `sIDHistory`. The disadvantage is breaking AD-interop (AD-aware tools expect SIDs in ACLs, PACs, audit logs). Rejected: Decision 3 explicitly preserves SIDs as the wire-format currency for AD interop.

## Open Questions

- For native mode (single NC per forest), should the framework accept the cross-domain control at all? Default: yes, for AD-tool compatibility, but execute as a within-NC move with a warning log. Confirm in implementation.
- For the Infrastructure Master emulation in AD-interop mode, what is the `fSMORoleOwner` value? Default: the framework's "schema master" DC (the DC that holds the Schema Master role per ADR-076) — the IM role is co-located with the Schema Master for simplicity. Confirm.
- For SPN-clear, should the framework support an option to preserve SPNs (with a duplicate-SPN check)? Default: no — match AD's behaviour (clear SPNs, log them, admin re-adds). Confirm with customer demand.

## Cross-capability impact

- **KDC**: KDC's PAC builder reads the principal's current SID and `sIDHistory` via the identity mapping table. Cross-domain move updates the mapping table atomically; the KDC sees the new SID on the next AS-REQ. No KDC restart or cache invalidation needed (the in-memory cache invalidates via FDB watches per Decision 3).
- **Auth Provider**: S4U2Proxy / RBCD configurations reference principals by SID. Cross-domain move updates the SID; the configuration's `msDS-AllowedToDelegateTo` value is the principal's DN (not SID), so it is rewritten as a foreign-SID reference automatically (step 7 in the Decision).
- **Policy Engine**: GPO security filtering references principals by SID. Cross-domain move updates the SID; the GPO's `SecurityDescriptor` ACE `Trustee` is the principal's SID — the framework translates to UUID via the mapping table for internal ACL evaluation. The ACE itself is not rewritten (the old SID is preserved in `sIDHistory`, which the framework's ACL evaluator also consults).
- **Cert Service**: Certificate templates reference principals by UUID (internal) or SID (AD-interop). Cross-domain move updates the SID; the certificate's `Subject` field stores the principal's SID — the framework updates the certificate's `Subject` on next renewal (certificates are not re-issued on move).
- **File Gateway**: File ACLs reference principals by SID. Cross-domain move updates the SID; the framework's ACL evaluator consults `sIDHistory` to resolve old SIDs. No file ACL rewrite needed.
- **Client SDK**: `getpwuid` and `getgrgid` queries use the identity mapping table; cross-domain move is transparent (UUID unchanged, UID/GID unchanged if directory-stored).
- **Migration**: AD-to-framework migration uses cross-domain move to consolidate multi-domain AD forests into a single framework forest. The move preserves `sIDHistory` for backward compatibility.

## References

- [PC-010](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 3 — UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping](../workshop/decision-03-identity-model.md) — unblocking decision
- [Workshop Decision 4 — Hybrid LDAP Schema + Typed Rust Projection](../workshop/decision-04-schema-model.md) — typed projection for `Sid` and `Uuid` types
- [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md) — `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` control format, move prerequisites, SPN-clear requirement
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — `DRSAddEntry` opnum 17, `lastKnownParent` tombstone attribute
- [MS-ADTS §3.1.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — tombstone lifetime, `lastKnownParent`
- [ADR-002: memberOf Back-Link](./ADR-002-memberof-back-link.md) — cross-domain move and identity model dependency
- [ADR-076: FSMO Role Replacement](./ADR-076-fsmo-role-replacement.md) — Infrastructure Master role elimination
- [ADR-077: Foreign Security Principals and RID Pool Allocation](./ADR-077-foreign-security-principals-rid-pool.md) — RID allocation, `sIDHistory`
