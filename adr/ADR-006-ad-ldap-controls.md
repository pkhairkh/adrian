---
title: "ADR-006: AD-Specific LDAP Controls for Client Interop"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-012
severity: high
tags: [adr, core-directory, ldap, controls, dirsync, range-retrieval, ad-interop]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/02-protocols/02-ldap-protocol.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
last_updated: 2026-08-13
---

# ADR-006: AD-Specific LDAP Controls for Client Interop

## Status

Accepted — 2026-08-13

## Context

Active Directory implements 25+ LDAP controls not part of [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511), including: `LDAP_SERVER_TREE_DELETE_OID` (`1.2.840.113556.1.4.805`, atomic subtree delete), `LDAP_SERVER_DIRSYNC_OID` (`1.2.840.113556.1.4.841`, directory synchronization with cookie-based cursor), `LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.528`, control which SD parts are returned), `LDAP_SERVER_ASQ_OID` (`1.2.840.113556.1.4.1504`, attribute-scoped query), `LDAP_SERVER_RANGE_RETRIEVAL_OID` (`1.2.840.113556.1.4.802`, range retrieval for large multi-valued attributes), `LDAP_SERVER_NOTIFICATION_OID` (`1.2.840.113556.1.4.528`, persistent search), `LDAP_SERVER_GET_STATS_OID` (`1.2.840.113556.1.4.1338`, query statistics), `LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID` (`1.2.840.113556.1.4.521`, cross-domain move), `LDAP_SERVER_SHOW_DELETED_OID`, `LDAP_SERVER_SHOW_RECYCLED_OID`, `LDAP_SERVER_PERMISSIVE_MODIFY_OID`, `LDAP_SERVER_QUOTA_CONTROL_OID`, and others, per [PC-012](../catalog/01-core-directory.md#pc-012--ad-specific-ldap-controls-required-for-client-interop), [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md), and [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md).

OpenLDAP and 389-DS do not implement most of these controls. Only AD and Samba-AD-DC implement the full set. A new framework must either implement these controls or document which AD features break: DirSync-based sync (used by Azure AD Connect), range-retrieval for large groups (used by every AD-aware app reading a >1,500-member group), subtree delete (used by `Remove-ADObject -Recursive`), notification (used by event-driven AD monitoring tools), permissive modify (used by Exchange to avoid read-modify-write races on multi-valued attributes).

The most impactful control is DirSync — Azure AD Connect uses it to read incremental changes from on-prem AD. Without DirSync, the framework cannot be the source for Azure AD Connect sync. Range-retrieval is the second most impactful — without it, reading a 10,000-member group requires 7 paged queries of 1,500 values each (the default range cap). Permissive modify is third — without it, an `ldap_modify` that adds a value already present fails with `attributeOrValueExists (19)`, breaking Exchange's mailbox-provisioning scripts.

Constraints from [PC-012](../catalog/01-core-directory.md#pc-012--ad-specific-ldap-controls-required-for-client-interop):

- Must remain BER-wire-compatible with the control OIDs (e.g. `1.2.840.113556.1.4.528` for SD_FLAGS).
- Control response values must follow MS-ADTS §3.1.1.3 byte layout.
- For DirSync, the cookie format must be opaque to the client but stable across server restarts (the cookie contains a USN cursor + a per-DC marker).
- For range-retrieval, the framework must honor the `attribute;range=low-high` syntax in LDAP attribute requests.
- For permissive modify, the framework must accept a modify operation that adds a value already present without raising an error.

## Decision

The framework SHALL implement the following core set of AD-specific LDAP controls for client interop:

1. **`LDAP_SERVER_RANGE_RETRIEVAL_OID`** (`1.2.840.113556.1.4.802`) — range retrieval for large multi-valued attributes. The framework SHALL honor `attribute;range=low-high` syntax and return values in the requested range, with `attribute;range=high+1-*` indicating more values available. This is essential for any client reading large groups.
2. **`LDAP_SERVER_DIRSYNC_OID`** (`1.2.840.113556.1.4.841`) — directory synchronization with cookie-based cursor. The framework SHALL support the DirSync control with cookie persistence across server restarts (cookie = USN cursor + DC invocation ID). This is essential for Azure AD Connect sync.
3. **`LDAP_SERVER_TREE_DELETE_OID`** (`1.2.840.113556.1.4.805`) — atomic subtree delete. The framework SHALL delete an entire subtree in one LDAP operation, transactionally.
4. **`LDAP_SERVER_NOTIFICATION_OID`** (`1.2.840.113556.1.4.528`) — persistent search / change notification. The framework SHALL maintain a long-lived LDAP connection that receives async notifications on object changes.
5. **`LDAP_SERVER_PERMISSIVE_MODIFY_OID`** (`1.2.840.113556.1.4.1413`) — permissive modify. The framework SHALL accept modify operations that add values already present without raising `attributeOrValueExists (19)`, and delete values not present without raising `noSuchAttribute (16)`.
6. **`LDAP_SERVER_SD_FLAGS_OID`** (`1.2.840.113556.1.4.801`) — control which SD parts are returned (Owner, Group, DACL, SACL). The framework SHALL honor the bitfield and return only the requested SD parts.
7. **`LDAP_SERVER_PAGED_RESULT_OID`** (`1.2.840.113556.1.4.319`) — paged results (RFC 2696). The framework SHALL support paged LDAP searches with cookie-based pagination.
8. **`LDAP_SERVER_SORT_OID`** (`1.2.840.113556.1.4.473`) — server-side sort (RFC 2891). The framework SHALL support server-side sort with the standard sort key + reverse + rule.
9. **`LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID`** (`1.2.840.113556.1.4.521`) — cross-domain move target (gated by PC-010, DEFERRED; framework SHALL accept the control and reject with `unwillingToPerform (53)` if cross-domain move is unsupported).
10. **`LDAP_SERVER_SHOW_DELETED_OID`** (`1.2.840.113556.1.4.417`) and **`LDAP_SERVER_SHOW_RECYCLED_OID`** (`1.2.840.113556.1.4.2064`) — show deleted / recycled objects in searches. The framework SHALL honor these controls and include tombstoned / recycled objects in the search results.
11. **`LDAP_SERVER_LAZY_COMMIT_OID`** (`1.2.840.113556.1.4.623`) — lazy commit. The framework SHALL acknowledge the control and may defer the fsync to a background flush (acceptable for non-critical writes).
12. **`LDAP_SERVER_DOMAIN_SCOPE_OID`** (`1.2.840.113556.1.4.1339`) — domain scope (no GC referral). The framework SHALL honor the control and suppress cross-domain referrals.

The framework SHALL defer the remaining AD controls (ASQ, GET_STATS, FORCE_UPDATE, VERIFY_NAME, SHUTDOWN_NOTIFY, QUOTA, etc.) to Tier 3 implementation — these are less commonly used and can be added incrementally based on customer demand.

For DirSync, the framework SHALL implement a USN-cursor-based cookie format that is opaque to the client but stable across server restarts. The cookie SHALL encode: (a) the highest USN consumed; (b) the DSA invocation ID; (c) a per-NC marker. The cookie format SHALL be byte-identical to AD's for AD-interop mode; for clean-slate mode, the cookie format is the framework's own (but the client-visible semantics are identical).

For range-retrieval, the framework SHALL honor the `attribute;range=low-high` syntax in LDAP attribute requests and return values in the requested range, with `attribute;range=high+1-*` indicating more values available. The default range cap SHALL be 1,500 values (matching AD's default).

For permissive modify, the framework SHALL accept modify operations that add values already present without raising `attributeOrValueExists (19)`, and delete values not present without raising `noSuchAttribute (16)`. The framework SHALL still raise `attributeOrValueExists (19)` if permissive modify is not requested.

**Concrete specification**:

- The framework SHALL implement the 12 controls listed in the Decision section, BER-wire-compatible with the MS-ADTS §3.1.1.3 control OIDs and response value layouts.
- `LDAP_SERVER_DIRSYNC_OID`: cookie format SHALL be opaque to the client, stable across server restarts, and byte-identical to AD's in AD-interop mode. Cookie SHALL encode USN cursor + invocation ID + per-NC marker.
- `LDAP_SERVER_RANGE_RETRIEVAL_OID`: framework SHALL honor `attribute;range=low-high` syntax; default range cap 1,500 values.
- `LDAP_SERVER_PERMISSIVE_MODIFY_OID`: framework SHALL accept add-already-present and delete-not-present without error; non-permissive modify SHALL raise `attributeOrValueExists (19)` / `noSuchAttribute (16)` per RFC 4511.
- `LDAP_SERVER_TREE_DELETE_OID`: framework SHALL delete an entire subtree in one LDAP operation, transactionally. Failure SHALL roll back the entire operation.
- `LDAP_SERVER_NOTIFICATION_OID`: framework SHALL maintain long-lived LDAP connections with async change notifications; the notification stream SHALL include object adds, modifies, deletes, and moves.
- `LDAP_SERVER_SD_FLAGS_OID`: framework SHALL honor the bitfield (Owner=1, Group=2, DACL=4, SACL=8) and return only the requested SD parts in `nTSecurityDescriptor`.
- `LDAP_SERVER_PAGED_RESULT_OID` and `LDAP_SERVER_SORT_OID`: framework SHALL implement RFC 2696 and RFC 2891 respectively, with the standard cookie / sort-key formats.
- For AD-interop mode, all 12 controls SHALL be byte-identical to AD's wire format.

## Rationale

The 12 controls selected are the minimum set required for "Azure AD Connect compatible" and "Exchange-compatible" deployments. DirSync is required for Azure AD Connect sync; range-retrieval is required for any client reading large groups; permissive modify is required for Exchange mailbox provisioning; tree-delete is required for `Remove-ADObject -Recursive`; notification is required for event-driven monitoring tools (e.g., AD audit tools, IAM sync engines). The remaining 13+ AD controls are less commonly used and can be added incrementally.

Three alternatives were considered:

**Alternative A — Implement all 25+ AD controls.** The advantage is complete AD-interop; the disadvantage is significant implementation cost (each control has its own BER encoding, server-side logic, and test surface). Rejected for v1 because the 12 selected controls cover 99% of real-world AD-interop scenarios. The remaining controls are deferred to Tier 3.

**Alternative B — Implement only RFC 4511 standard controls (paged, sort) and replace AD-specific controls with REST/WebSocket equivalents.** Modern alternative: DirSync via WebSocket stream; range-retrieval via REST pagination; tree-delete via REST `DELETE /api/v1/subtree`; notification via WebSocket. Rejected as the *primary* mechanism because every AD-aware LDAP client uses the AD controls, not REST. ADOPTED as an *additional* mechanism for clean-slate clients — the framework SHALL expose REST equivalents for DirSync, tree-delete, and notification in a future ADR.

**Alternative C — Implement DirSync and range-retrieval only; defer the rest.** DirSync and range-retrieval are the two most impactful controls. Rejected because permissive modify, tree-delete, and notification are also commonly used (Exchange, ADUC, monitoring tools) and the cost of implementing them is incremental once the control-dispatch infrastructure exists.

External evidence: [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents all AD controls; [RFC 2696](https://www.rfc-editor.org/rfc/rfc2696) and [RFC 2891](https://www.rfc-editor.org/rfc/rfc2891) define paged and sort controls; Samba 4 implements the full AD control set in `source4/ldap_server`; 389-DS implements syncrepl (the RFC 4533 equivalent of DirSync) but not AD-DirSync. The framework's design matches AD's wire format for interop.

The cost of this decision is implementation effort — 12 controls × ~1 person-week each = ~12 person-weeks total. The bulk of the work is DirSync (cookie format, USN-cursor management, replication-integration) and notification (long-lived connections, async event delivery).

## Consequences

**Positive**: AD-aware LDAP clients (Azure AD Connect, Exchange, ADUC, third-party tools) work without modification. DirSync enables Azure AD Connect to use the framework as the source for hybrid sync. Range-retrieval enables efficient large-group enumeration. Permissive modify enables Exchange mailbox provisioning. Tree-delete enables `Remove-ADObject -Recursive`. Notification enables event-driven monitoring.

**Negative**: 12 person-weeks of implementation effort for v1. The DirSync cookie format must be stable across server restarts and across framework upgrades — a cookie-format change breaks in-flight sync sessions. The notification control requires long-lived LDAP connections, which complicates load-balancer configuration (sticky sessions or WebSocket-style long-poll).

**Neutral**: The 13 deferred controls can be added incrementally based on customer demand; their absence does not block v1 deployment.

**Implementation cost**: ~12 person-weeks for the 12 controls, the bulk being DirSync (~4 person-weeks) and notification (~2 person-weeks). The remaining 10 controls are ~0.5–1 person-week each.

**Operational impact**: Azure AD Connect sync works against the framework; Exchange mailbox provisioning works; `Remove-ADObject -Recursive` works. Monitoring tools that use LDAP notification work without polling.

## Alternatives Considered

### Alternative 1: Implement all 25+ AD controls

Complete AD-interop; significant implementation cost. Rejected for v1 — the 12 selected controls cover 99% of real-world scenarios. Remaining controls deferred to Tier 3.

### Alternative 2: RFC 4511 standard controls only; replace AD-specific with REST/WebSocket

Modern alternative for clean-slate clients. Rejected as the *primary* mechanism because AD-aware LDAP clients use the AD controls. ADOPTED as an *additional* mechanism for clean-slate clients in a future ADR.

### Alternative 3: DirSync and range-retrieval only

The two most impactful controls. Rejected because permissive modify, tree-delete, and notification are also commonly used and the control-dispatch infrastructure exists once DirSync is implemented.

## Open Questions

- Should the framework expose DirSync via WebSocket for clean-slate clients (modern alternative)? The REST/WebSocket equivalent would emit JSON change events instead of BER-encoded DirSync cookies. Defer to a future ADR.
- For the deferred controls (ASQ, GET_STATS, QUOTA, etc.), what is the priority order for Tier 3 implementation? Customer demand should drive this.
- Cross-reference PC-018 (constructed attributes) — `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`) is technically a matching rule, not a control, but is required for recursive `memberOf` queries. Should this be added to the framework's required LDAP feature set? Yes — it's implicitly required by ADR-002.

## Cross-capability impact

- **Migration**: Azure AD Connect sync depends on DirSync. Without DirSync, the framework cannot be the source for hybrid identity sync.
- **Client SDK**: Client LDAP wrapper must expose the control API so apps can send DirSync, range-retrieval, and permissive-modify controls.
- **Policy Engine**: GPO SDs are read with `LDAP_SERVER_SD_FLAGS_OID` to control which SD parts are returned.
- **Operations**: Tree-delete enables `Remove-ADObject -Recursive`; notification enables event-driven monitoring.

## References

- [PC-012](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md) — AD-specific LDAP controls list, BER encoding of control values, DirSync cookie format
- [docs/01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) — DSA control dispatch, range-retrieval implementation, paged query limit
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — AD LDAP controls
- [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511) — LDAP protocol
- [RFC 2696](https://www.rfc-editor.org/rfc/rfc2696) — paged results control
- [RFC 2891](https://www.rfc-editor.org/rfc/rfc2891) — server-side sort control
