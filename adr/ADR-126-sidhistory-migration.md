---
title: "ADR-126: sIDHistory Migration — DRSAddSidHistory + Time-Limited Passthrough Window + ACL Re-write Plan"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Migration
problem: PC-124
severity: high
tags: [adr, migration, sidhistory, drsaddsidhistory, admt, acl-rewrite, parallel-run, cutover]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/12-migration-and-coexistence.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../docs/11-code-examples/05-python-impacket-examples.md
  - ../workshop/decision-03-identity-model.md
  - ./ADR-124-sidhistory-injection-mitigation.md
  - ./ADR-128-kerberos-cross-realm-migration.md
last_updated: 2026-08-13
---

# ADR-126: sIDHistory Migration — DRSAddSidHistory + Time-Limited Passthrough Window + ACL Re-write Plan

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 3 (identity model)](../workshop/decision-03-identity-model.md) which chose UUID-primary + SID-as-attribute with `sIDHistory` preserved on the wire. This ADR specifies the migration workflow that uses `sIDHistory` for ACL continuity during the coexistence window.

## Context

The Active Directory Migration Tool (ADMT) and equivalent migration workflows use `DRSAddSidHistory` (opnum 20 on the DRSUAPI interface `E3514235-8B63-11D0-A26C-00A0C92B955C`) to inject the source-domain user's old SID into the target-domain user's `sIDHistory` attribute. Per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) and [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md), this opnum is documented in MS-DRSR §4.1.29 and requires `SeEnableDelegationPrivilege` on the source domain (held by Domain Admins by default).

The mechanism: ADMT, running in the target domain, binds to a source-domain DC via DRSUAPI. It calls `DRSAddSidHistory` with the source user's SID and the target user's DN. The source DC verifies the caller has `SeEnableDelegationPrivilege`, retrieves the source user's `objectSid` and `sIDHistory`, packages them, and returns. The target DC then writes the returned SIDs into the target user's `sIDHistory`. The target user now has both their new SID (in the target domain) and the old SID (from the source domain) in `sIDHistory`.

When the target user authenticates across a within-forest trust (`TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20`), the source-domain KDC preserves the `sIDHistory` in the PAC's `ExtraSids` array (per MS-KILE §3.4.5). Resources that have ACLs referencing the source-domain SID continue to grant access — the user's token contains both SIDs, and the SRM checks both against the ACL. This is what makes "user migrated from old.corp to new.corp can still access file shares in old.corp that referenced the user's old SID" work without ACL re-write.

`DRSAddSidHistory` is the only mechanism that preserves both the SID (for ACL continuity) and the password (via ADMT's password-copy, which uses a separate DCSync-like call). The alternative is claims-based migration — the framework issues claims (assertions about the user) that the source domain's resources trust, replacing the SID-based access check. But claims-based access control requires Server 2012+ forest functional level, claim-type definitions published in AD, and resource-side central access policies. Most orgs have not deployed this. sIDHistory remains the practical migration mechanism.

Workshop Decision 3 chose UUID-primary + SID-as-attribute with `sIDHistory` preserved on the wire. The mapping table's per-trust filtering policy (per ADR-124) provides the sIDHistory-abuse mitigation. This ADR specifies the migration workflow that uses `sIDHistory` for ACL continuity during the coexistence window.

## Decision

The framework's sIDHistory migration workflow is **ADMT-compatible** and consists of four stages: (1) pre-migration ACL inventory — the framework scans source-domain resources for ACLs referencing source-domain SIDs and produces an ACL-rewrite plan; (2) sIDHistory injection — the framework implements `DRSAddSidHistory` (opnum 20) for ADMT interop and provides a framework-native equivalent (`adrian-cli migrate sidhistory`) for non-ADMT migrations; (3) time-limited passthrough window — per ADR-124, the framework enables sIDHistory passthrough on the within-forest trust for a configurable window (default 180 days) during which cross-trust access uses the sIDHistory; (4) post-migration ACL rewrite — the framework rewrites source-domain ACLs to reference target-domain SIDs (or migrates the resource to the target domain), then disables sIDHistory passthrough.

The framework's `DRSAddSidHistory` implementation is in `crates/adrian-drsuapi` (per Decision 1) and enforces the same `SeEnableDelegationPrivilege` check AD enforces. Every call is audit-logged per ADR-124's sIDHistory-write audit. The framework's `adrian-cli migrate sidhistory` CLI is the framework-native equivalent for non-ADMT migrations; it uses LDAP `modify` on `sIDHistory` directly (with the same `SeEnableDelegationPrivilege` check) and produces the same audit events.

## Migration state machine

**Source state**: AD forest with users having SIDs in source domain, ACLs on resources referencing those SIDs, ADMT installed in target domain (or framework-native migration tool available). Within-forest trust between source AD forest and framework forest is in place.

**Target state**: Framework-native users with current SIDs (in the framework's domain) and `sIDHistory` containing source-domain SIDs. Framework DCs serve the target domain. Cross-realm trust to source AD forest is in place with sIDHistory passthrough enabled for the migration window. Source-domain ACLs have been rewritten to reference target-domain SIDs (or source resources have been migrated to the target domain). sIDHistory passthrough has been disabled (per ADR-124).

**Coexistence period**: 30–180 days typical (default 180, matching the framework's `tombstoneLifetime`). During this window:
- Target-domain users access source-domain resources via sIDHistory passthrough. The source-domain KDC preserves `sIDHistory` in the PAC's `ExtraSids`; the source-domain resource's ACL evaluator checks both the current SID and the sIDHistory SIDs against the ACL.
- The framework's `adrian-cli migrate acl-rewrite --plan <plan-file>` command rewrites source-domain ACLs in batches (default 1000 ACLs per batch, scheduled during low-activity windows). Each batch: (a) reads the source ACL, (b) translates source-domain SIDs to target-domain SIDs via the framework's `IdentityMapping` (per Decision 3), (c) writes the rewritten ACL back to the source resource, (d) records the rewrite in the migration audit log.
- The framework's `adrian-cli migrate acl-rewrite --status` command tracks per-resource rewrite progress (pending/in-progress/complete/failed).
- The framework's audit pipeline (per ADR-060) emits an event for every ACL rewrite with attributes `adrian.migration.acl.resource`, `adrian.migration.acl.source_sid`, `adrian.migration.acl.target_sid`, `adrian.migration.acl.caller`, `adrian.migration.acl.result`.

**Cutover trigger**: When 100% of source-domain ACLs have been rewritten (verified by `adrian-cli migrate acl-rewrite --status` showing 0 pending) AND the framework's audit pipeline has recorded no sIDHistory-passthrough access for ≥30 days, the within-forest trust is converted to an external trust (sIDHistory filtering ON, per ADR-124's default-on filtering). `sIDHistory` is removed from target users via `adrian-cli migrate sidhistory-cleanup --batch-size 1000`. The cleanup is audit-logged per ADR-124.

**Rollback path**: If migration fails (e.g. ACL rewrite batch fails for a critical resource), the framework's `adrian-cli migrate acl-rewrite --rollback --batch <batch-id>` command restores the previous ACLs from the migration audit log. sIDHistory passthrough remains enabled on the within-forest trust; users continue to access source-domain resources via sIDHistory. Rollback is per-batch (granular) and tested quarterly per the framework's DR drill schedule (per ADR-059).

**Concrete specification**:

- The framework MUST implement `DRSAddSidHistory` (opnum 20 on DRSUAPI) in `crates/adrian-drsuapi` (per Decision 1) for ADMT interop. The implementation MUST enforce `SeEnableDelegationPrivilege` on the source side (matching AD).
- The framework MUST audit every `DRSAddSidHistory` call per ADR-124's sIDHistory-write audit (same audit event as a direct LDAP `modify` on `sIDHistory`).
- The framework MUST expose `adrian-cli migrate sidhistory --source-user <source-dn> --target-user <target-dn> --source-forest <forest-dn>` for non-ADMT migrations. The CLI: (a) binds to the source forest via DRSUAPI with `EXOP_REPL_SECRETS` to read the source user's `objectSid` and `sIDHistory`; (b) writes the source SIDs to the target user's `sIDHistory` via LDAP `modify`; (c) records the operation in the migration audit log.
- The framework MUST expose `adrian-cli migrate acl-inventory --source-forest <forest-dn> --output <plan-file>` for pre-migration ACL inventory. The CLI: (a) walks the source forest's resources (file shares, AD objects with ACLs, registry ACLs on Windows, etc.); (b) for each resource, records the ACL entries that reference source-domain SIDs; (c) produces an ACL-rewrite plan in JSON format listing per-resource: source ACL, target ACL (with source SIDs translated to target SIDs via `IdentityMapping`), rewrite-batch assignment.
- The framework MUST expose `adrian-cli migrate acl-rewrite --plan <plan-file> [--batch <batch-id>] [--dry-run]` for ACL rewrite. The CLI: (a) reads the plan file; (b) for the specified batch (or all pending batches if `--batch` not specified), performs the rewrites; (c) `--dry-run` mode shows the rewrites without applying.
- The framework MUST expose `adrian-cli migrate acl-rewrite --status` returning per-resource: source ACL, target ACL, status (pending/in-progress/complete/failed), last-updated timestamp, batch ID.
- The framework MUST expose `adrian-cli migrate acl-rewrite --rollback --batch <batch-id>` for per-batch rollback. The CLI reads the migration audit log for the specified batch and restores the previous ACLs.
- The framework MUST expose `adrian-cli migrate sidhistory-cleanup --batch-size <N>` for post-cutover sIDHistory removal. The CLI walks target users with `sIDHistory` and clears the attribute via LDAP `modify` in batches.
- The framework's audit pipeline MUST emit an OTel log record for every ACL rewrite and every sIDHistory cleanup with the attributes listed above.
- The framework MUST support the time-limited passthrough window per ADR-124: `adrian-cli trust set-sidhistory-passthrough --trust <trust-dn> --until <timestamp>` (default 180 days).
- The framework MUST ship a default Prometheus alert: `adrian_migration_acl_rewrite_failures_total{batch} > 0 for 5m` triggers warning (ACL rewrite batch failures may stall migration).
- The framework MUST emit a Prometheus metric `adrian_migration_acl_rewrite_progress{status}` (per ADR-057) — count of ACLs in each status (pending/in-progress/complete/failed).

## Rationale

sIDHistory migration is the practical mechanism for ACL continuity. Claims-based migration is the theoretical alternative but is not deployed in most AD forests. The framework cannot refuse `DRSAddSidHistory` without breaking ADMT-based migrations — ADMT is the canonical migration tool, used by virtually every enterprise migrating from one AD forest to another. The framework's value proposition is doing the migration safely (audit-logged, time-limited, with ACL rewrite) rather than refusing it.

The pre-migration ACL inventory is the operational innovation. ADMT does not provide this; organisations discover ACL references the hard way (a user reports they cannot access a resource after migration). The framework's `adrian-cli migrate acl-inventory` scans source-domain resources before migration and produces an ACL-rewrite plan, making the migration's scope visible upfront.

The time-limited passthrough window (per ADR-124) is the sIDHistory-abuse mitigation. The framework enables passthrough for a finite window (default 180 days, matching `tombstoneLifetime`); after expiry, the framework automatically re-enables filtering. This prevents sIDHistory from becoming a permanent security liability (the documented AD problem).

The post-migration ACL rewrite is the cutover path. Once all source-domain ACLs are rewritten to reference target-domain SIDs, sIDHistory is no longer needed and can be removed. The framework's `adrian-cli migrate sidhistory-cleanup` automates the removal in batches, avoiding the operational pain of clearing `sIDHistory` on every user manually.

The per-batch rollback is the safety net. If an ACL rewrite batch fails for a critical resource (e.g. a share ACL that grants access to a critical application), the operator can roll back the specific batch without rolling back the entire migration. The rollback is per-batch (granular) and tested quarterly.

## Consequences

**Positive**: ADMT-interop is preserved (organisations using ADMT can migrate to the framework without changing their workflow). Framework-native migration tool (`adrian-cli migrate sidhistory`) is available for non-ADMT migrations. Pre-migration ACL inventory makes the migration's scope visible upfront. Time-limited passthrough window prevents sIDHistory from becoming a permanent liability. Per-batch rollback provides granular safety. Post-migration ACL rewrite + sIDHistory cleanup completes the migration.

**Negative**: The 180-day default passthrough window is a security exposure (sIDHistory is attackable during this window per ADR-124's threat model). The framework's audit pipeline + SIEM rules (per ADR-124) detect attacks during the window, but the exposure is non-zero. ACL rewrite is a long-running operation (weeks for a 50,000-user / 10,000-server migration); the migration's coexistence period is correspondingly long.

**Neutral**: The framework's `DRSAddSidHistory` implementation is byte-compatible with AD's; ADMT works unchanged. The framework's `adrian-cli migrate sidhistory` is the framework-native alternative for organisations that have moved beyond ADMT (or never used it).

**Implementation cost**: ~4 person-months for the `DRSAddSidHistory` implementation, the `adrian-cli migrate sidhistory` CLI, the `acl-inventory` and `acl-rewrite` CLIs, the `sidhistory-cleanup` CLI, and the audit pipeline integration. Reuses Decision 1's `adrian-drsuapi`, Decision 3's `adrian-identity-fdb` and `IdentityMapping`, ADR-060's audit pipeline.

**Operational impact**: Migration teams use `adrian-cli migrate acl-inventory` before migration, `adrian-cli migrate sidhistory` during migration, `adrian-cli migrate acl-rewrite` during coexistence, and `adrian-cli migrate sidhistory-cleanup` after cutover. SOC analysts monitor sIDHistory writes per ADR-124's SIEM rules. SREs monitor `adrian_migration_acl_rewrite_progress` for migration progress.

## Alternatives Considered

**Alternative A: Claims-based migration as the only supported path (no sIDHistory).** Require claims-based migration (Server 2012+ forest functional level, claim-type definitions, central access policies) as the only supported path; refuse `DRSAddSidHistory`. Rejected because (a) most AD source forests are below 2012 functional level; (b) claims-based access control requires resource-side central access policies that most orgs have not deployed; (c) ADMT and equivalent migration tooling uses `DRSAddSidHistory`; the framework cannot refuse it without breaking migrations.

**Alternative B: LDAP `modify` on `sIDHistory` only (no `DRSAddSidHistory` opnum).** Provide only the framework-native `adrian-cli migrate sidhistory` CLI; do not implement the `DRSAddSidHistory` opnum. Rejected because (a) ADMT cannot use the framework's CLI directly (ADMT expects the opnum); (b) customers with existing ADMT workflows would need to retool; (c) the opnum is the standard interop mechanism — the framework should support it for compatibility.

**Alternative C: Per-resource ACL rewrite only (no sIDHistory).** Skip sIDHistory entirely; rewrite every source-domain ACL to reference target-domain SIDs before user migration. Rejected because (a) the ACL rewrite is the long-pole operation (weeks for a 50,000-user migration); without sIDHistory, users cannot access source-domain resources during the rewrite window; (b) the ACL rewrite may break applications that cache SIDs (the apps see the old SID, fail the ACL check); (c) sIDHistory provides the seamless transition that makes migration viable.

**Alternative D: One-way sIDHistory migration (target users have source SIDs in sIDHistory; source resources are migrated to target domain).** Migrate the source resources to the target domain rather than rewriting source-domain ACLs. Rejected as the sole path because (a) some source resources cannot be migrated (e.g. file shares on appliances that cannot be re-homed); (b) resource migration is itself a multi-week operation; (c) the ACL rewrite is needed in either case (the migrated resource's ACL still references source-domain SIDs until rewritten). Resource migration is supported as a complementary operation; the ACL rewrite is the universal mechanism.

## Open Questions

None. Workshop Decision 3 resolved the identity-model ORQ-026/027 that gated this ADR. The sIDHistory migration workflow is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-001/PC-002)**: Decision 1's `DrSuapiReplicator` implements `DRSAddSidHistory` (opnum 20) for ADMT interop.
- **Core Directory (PC-010)**: Decision 3's `IdentityMapping` translates source SIDs to target SIDs for ACL rewrite.
- **Security (PC-120)**: ADR-124 (sIDHistory injection) — the time-limited passthrough window is the sIDHistory-abuse mitigation; the framework's filter is re-enabled automatically after the window.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_migration_acl_rewrite_progress` is the migration-progress metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — sIDHistory write, ACL rewrite, and ACL cleanup audit events.
- **Migration (PC-126)**: ADR-128 (Kerberos cross-realm during migration) — the within-forest trust with sIDHistory passthrough is the parallel-run Kerberos foundation.
- **Migration (PC-127)**: ADR-129 (password hash migration) — password hash migration is paired with sIDHistory migration in ADMT workflows.
- **File Gateway (PC-078)**: Decision 10's SMB server — file-share ACLs are the primary target of the ACL rewrite.

## References

- [PC-124](../catalog/12-migration-and-coexistence.md) — problem statement (sIDHistory migration requires `DRSAddSidHistory` + SeEnableDelegationPrivilege)
- [Trusts topology KB](../docs/03-directory-schema/04-trusts-topology.md) — `sIDHistory` attribute, within-forest trust sIDHistory passthrough, `TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20`, `TRUST_ATTRIBUTE_QUARANTINED = 0x4` for filtering
- [DCERPC MS-DRSR KB](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI interface UUID, opnum 20 `DRSAddSidHistory`
- [Python impacket examples KB](../docs/11-code-examples/05-python-impacket-examples.md) — DRSUAPI-based hash extraction (same mechanism as ADMT password copy)
- [Workshop Decision 1 — Replication protocol](../workshop/decision-01-replication-protocol.md) — `DrSuapiReplicator` implements `DRSAddSidHistory`
- [Workshop Decision 3 — Identity model](../workshop/decision-03-identity-model.md) — UUID-primary + SID-as-attribute + sIDHistory preserved on wire; `IdentityMapping` for source-to-target SID translation
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — ACL rewrite progress metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — sIDHistory write / ACL rewrite / ACL cleanup audit events
- [ADR-059 — PITR backup + DR runbooks](./ADR-059-pitr-backup-dr-runbooks.md) — quarterly DR drill schedule includes ACL rewrite rollback test
- [ADR-124 — sIDHistory injection mitigation](./ADR-124-sidhistory-injection-mitigation.md) — time-limited passthrough window is the sIDHistory-abuse mitigation
- [ADR-128 — Kerberos cross-realm during migration](./ADR-128-kerberos-cross-realm-migration.md) — within-forest trust with sIDHistory passthrough is the parallel-run foundation
- [ADR-129 — Password hash migration](./ADR-129-password-hash-migration.md) — password hash migration paired with sIDHistory migration
- [MS-DRSR §4.1.29](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — `DRSAddSidHistory` opnum 20
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — `sIDHistory` attribute, within-forest trust passthrough
- [MS-KILE §3.4.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) — sIDHistory in PAC `ExtraSids`
- [ADMT documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008/cc974335(v=ws.10)) — ADMT migration workflow
