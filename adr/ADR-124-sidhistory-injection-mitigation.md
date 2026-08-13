---
title: "ADR-124: sIDHistory Injection Mitigation — Default-On Filtering on All Trusts + Per-Write Audit"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-120
severity: high
tags: [adr, security, sidhistory, sid-filtering, pim-trust, claims-based-migration, mitre-t1178-001, mitre-t1134-005]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ../docs/00-overview/03-domains-forests-trees.md
  - ../workshop/decision-03-identity-model.md
  - ./ADR-122-dcsync-mitigation.md
  - ./ADR-126-sidhistory-migration.md
last_updated: 2026-08-13
---

# ADR-124: sIDHistory Injection Mitigation — Default-On Filtering on All Trusts + Per-Write Audit

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 3 (identity model)](../workshop/decision-03-identity-model.md) which chose UUID-primary + SID-as-attribute with a bidirectional mapping table. The mapping table's per-trust filtering policy is the sIDHistory-abuse mitigation specified here.

## Context

The `sIDHistory` attribute (schema OID `1.2.840.113556.1.4.1369`, multi-valued OctetString) on a user or group object carries SIDs from a previous domain — used during migrations to preserve access to resources that reference the old SID. Per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) and [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md), the behaviour of `sIDHistory` is governed by the trust relationship: within-forest trusts (`TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20`) permit sIDHistory passthrough; external trusts (`TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1` or `TRUST_ATTRIBUTE_QUARANTINED = 0x4`) filter sIDHistory from the PAC's `ExtraSids` array.

The attack: an attacker with Domain Admin in a child domain can inject an arbitrary SID (e.g. `S-1-5-21-<forest-root-domain-sid>-519` = Enterprise Admins in the forest root) into a user's `sIDHistory` via `DRSAddSidHistory` (opnum 20 on DRSUAPI, requires `SeEnableDelegationPrivilege` on the source domain — granted to Domain Admins by default). The next time the user requests a TGT, the KDC includes the injected SID in the PAC's `ExtraSids`. When the user traverses the within-forest trust to the forest root, the target KDC preserves the `ExtraSids` (because the trust is within-forest) and the user's token on a forest-root DC includes Enterprise Admins. Result: a child-domain Domain Admin escalates to forest-root Enterprise Admin without ever compromising a forest-root DC. This is the "SID History injection" attack described in MS-KILE §3.4.5.

The mitigation is sIDHistory filtering, also called SID Filter Quarantine. External trusts and forest trusts filter `sIDHistory` by default since Server 2003 (external) and Server 2008 (forest). Within-forest trusts do not filter (by design — to support migration). The administrator can force filtering on within-forest trusts via `netdom trust <trusting> /d:<trusted> /quarantine:Yes` but this breaks migration scenarios. PIM trusts (Privileged Access Management, Server 2016+, `TRUST_ATTRIBUTE_PIM_TRUST = 0x200`) provide user-level isolation with sIDHistory filtering.

Workshop Decision 3 chose UUID-primary + SID-as-attribute with a bidirectional mapping table in FDB subspace `0x0D`. The mapping table is the canonical source of truth for UUID ↔ SID correspondence; per-trust filtering policy on the mapping table is the sIDHistory-abuse mitigation. The KDC's PAC builder applies the filtering at PAC-issuance time.

## Threat model

**STRIDE classification**: Elevation of privilege, Spoofing (MITRE ATT&CK T1178.001 — SID History: SID History Injection; T1134.005 — Access Token Manipulation: SID History Injection)

**Attack vector** (step-by-step):

1. Attacker compromises a child-domain Domain Admin account (via Kerberoasting ADR-064, phishing, etc.).
2. Attacker creates a new user `pwned` in the child domain.
3. Attacker calls `DRSAddSidHistory` (opnum 20 on DRSUAPI) targeting `pwned` with `sIDHistory = S-1-5-21-<forest-root-domain-sid>-519` (Enterprise Admins of the forest root). This requires `SeEnableDelegationPrivilege` on the source domain (held by child-domain Domain Admins).
4. The child-domain KDC, on the next AS-REQ for `pwned`, includes the Enterprise Admins SID in the PAC's `ExtraSids` array.
5. Attacker requests a cross-realm referral TGT to the forest root via the within-forest trust.
6. The forest-root KDC preserves the `ExtraSids` (within-forest trust does not filter sIDHistory).
7. Attacker accesses any forest-root resource as Enterprise Admin. (e.g. DCSync against a forest-root DC.)

**Known mitigations in AD**: SID Filter Quarantine on external trusts (default since Server 2003); SID Filter Quarantine on forest trusts (default since Server 2008); within-forest trusts do NOT filter by default (to support migration); PIM trusts (Server 2016+, `TRUST_ATTRIBUTE_PIM_TRUST = 0x200`) provide user-level isolation with sIDHistory filtering within-forest; audit Event 4662 with `Properties: sIDHistory` (attribute GUID `5905e5c0-c1bb-11d3-99a7-0000f81a86c8`).

**Residual risk in AD**: Within-forest trusts do not filter by default — the attack surface is wide for any forest with multiple domains. PIM trusts are Server 2016+ only and require explicit configuration. `DRSAddSidHistory` is enabled by default and requires only Domain Admin in the source domain. Audit is noisy and rarely tuned.

## Decision

The framework's sIDHistory mitigation is **default-on filtering on all trusts, including within-forest**. The framework replaces AD's "within-forest trusts do not filter" behaviour with "all trusts filter by default, with explicit opt-out for migration windows". The filter is enforced at three layers: (a) the framework's `IdentityMapping` trait (per Decision 3) applies a per-trust filter policy when translating UUID group memberships to SID `ExtraSids` in the PAC; (b) the framework's KDC PAC builder (per Decision 5) honours the filter at PAC-issuance time, omitting filtered SIDs from `ExtraSids`; (c) the framework's File Gateway ACL evaluator (per Decision 10) honours the filter at ACL-evaluation time, ignoring filtered SIDs in the user's token.

The filter policy is per-trust, stored as a `trustAttributes` extension on the `trustedDomain` object. The framework introduces a new trust attribute `TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER = 0x4000` (in the framework's reserved range, non-conflicting with Microsoft-allocated bits). When this attribute is set on a trust, the framework's IdentityMapping applies filtering: only SIDs in the trusted domain's own SID namespace (matching the trusted domain's `securityIdentifier` prefix) are passed through to `ExtraSids`; all other SIDs (including any `sIDHistory` entries that reference a third-party domain) are filtered. The framework's default trust-creation CLI sets this attribute on every trust, including within-forest.

For migration scenarios that require `sIDHistory` passthrough (per ADR-126), the framework supports a **time-limited opt-out**: `adrian-cli trust set-sidhistory-passthrough --trust <trust-dn> --until <timestamp>` enables passthrough for the specified window (default 180 days, matching the framework's `tombstoneLifetime`). After expiry, the framework automatically re-enables filtering; the audit pipeline emits a "passthrough window expired" event. The opt-out is audit-logged at enable-time with severity "medium" and MITRE T1178.001 tag.

The framework supports PIM trusts (per Server 2016+ `TRUST_ATTRIBUTE_PIM_TRUST = 0x200`) for within-forest privileged-access isolation. PIM trusts apply sIDHistory filtering even within-forest; the framework's PIM-trust model is the modern alternative to the time-limited opt-out for permanent privileged-access scenarios.

**Concrete specification**:

- The framework's `IdentityMapping` trait (per Decision 3) MUST support a per-trust filter policy. The policy is stored as the `TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER = 0x4000` bit on the `trustedDomain` object's `trustAttributes` attribute.
- The framework's KDC PAC builder (per Decision 5) MUST honour the filter at PAC-issuance time: when issuing a cross-realm referral TGT, the KDC consults the trust's `trustAttributes`; if `TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER` is set, the KDC omits any `ExtraSids` that do not match the trusted domain's SID namespace.
- The framework's File Gateway ACL evaluator MUST honour the filter at ACL-evaluation time: when evaluating a user's token for a file-open, the evaluator consults the trust through which the user authenticated; if the trust has `TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER` set, the evaluator ignores any SIDs in the token that do not match the trusted domain's SID namespace.
- The framework's `adrian-cli trust create` CLI MUST set `TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER = 0x4000` by default on every trust, including within-forest trusts. The `--no-sid-filter` flag explicitly disables filtering (audit-logged, requires `--confirm-no-sid-filter` to prevent accidental opt-out).
- The framework MUST support time-limited opt-out for migration: `adrian-cli trust set-sidhistory-passthrough --trust <trust-dn> --until <timestamp>` (default 180 days). The CLI records the expiry timestamp on the `trustedDomain` object's `frameworkSidFilterExpiry` attribute.
- The framework's operator (per ADR-058) MUST run a daily reconcile loop that re-enables filtering on any trust whose `frameworkSidFilterExpiry` has passed. The reconcile loop emits an audit event (severity "medium") when re-enabling.
- The framework MUST support PIM trusts via the `TRUST_ATTRIBUTE_PIM_TRUST = 0x200` attribute. PIM trusts apply sIDHistory filtering unconditionally (the `TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER` is implied). `adrian-cli trust create --pim` creates a PIM trust.
- The framework's audit pipeline MUST emit an OTel log record for every `sIDHistory` write (LDAP modify on the `sIDHistory` attribute), with attributes `adrian.identity.sidhistory.target_dn`, `adrian.identity.sidhistory.added_sids`, `adrian.identity.sidhistory.caller_dn`, `adrian.identity.sidhistory.caller_sid`, `adrian.identity.sidhistory.caller_ip`, `adrian.identity.sidhistory.is_migration_window` (boolean: is the write inside a time-limited opt-out window?). This maps to Windows Event 4662 with `Properties: sIDHistory` (attribute GUID `5905e5c0-c1bb-11d3-99a7-0000f81a86c8`).
- The framework's audit pipeline MUST ship default detection rules:
  - Rule 1: `sIDHistory` write with `is_migration_window = false` → severity "critical", MITRE T1178.001. (sIDHistory write outside a migration window is the attack signature.)
  - Rule 2: `sIDHistory` write adding a SID in the forest-root domain's namespace from a child-domain caller → severity "high", MITRE T1178.001. (The classic child-to-forest-root escalation pattern.)
  - Rule 3: `sIDHistory` write adding more than 5 SIDs in one operation → severity "medium". (Bulk sIDHistory writes are suspicious; legitimate migration writes are usually 1–2 SIDs per user.)
- The framework MUST implement `DRSAddSidHistory` (opnum 20 on DRSUAPI) for AD-interop compatibility (per ADR-126 migration scenarios). The implementation MUST enforce `SeEnableDelegationPrivilege` on the source side (matching AD) and MUST audit every call with the same attributes as a direct `sIDHistory` LDAP write.
- The framework MUST expose `adrian-cli trust audit --sidhistory` returning per-trust: `filter_status` (on/off/expired), `passthrough_expiry` (timestamp if applicable), `sIDHistory_writes_in_window` (count), `sIDHistory_writes_outside_window` (count).
- The framework MUST emit a Prometheus metric `adrian_sidhistory_writes_total{trust,is_migration_window,result}` (per ADR-057).
- The framework MUST ship a default Prometheus alert: `rate(adrian_sidhistory_writes_total{is_migration_window="false"}[5m]) > 0` triggers critical.

## Rationale

Default-on filtering on all trusts is the framework's strict-improvement over AD's "within-forest trusts do not filter" behaviour. AD's behaviour is an artefact of the migration-era design (sIDHistory passthrough is needed for migration; within-forest trusts assume the forest is a single security boundary). The framework's posture is that within-forest is not a sufficient security boundary — a compromised child domain should not automatically grant forest-root privileges via sIDHistory injection. Default-on filtering breaks the attack vector at the trust boundary.

The time-limited opt-out is the migration compat path. Migrations require sIDHistory passthrough for a finite window (typically 30–180 days per ADR-126); the framework's opt-out allows this window with explicit audit logging and automatic re-enablement. The 180-day default matches the framework's `tombstoneLifetime` — after this window, any remaining sIDHistory references are stale and should be cleaned up (per ADR-126's post-migration cleanup procedure).

PIM trusts are the modern alternative for permanent privileged-access scenarios. PIM trusts (Server 2016+) apply sIDHistory filtering even within-forest, providing user-level isolation. The framework's PIM-trust support matches Microsoft's recommended posture for forests with multiple domains and privileged-access isolation requirements.

The three-layer filter (IdentityMapping + KDC PAC builder + File Gateway ACL evaluator) provides defence-in-depth. An attacker who bypasses one layer (e.g. by directly querying the directory's `sIDHistory` attribute) is still blocked at the next layer (the KDC will not include the filtered SID in the PAC; the File Gateway will not honour it in the token). The three layers are independent implementations; bypassing all three requires separate compromises.

The audit pipeline's detection rules are tuned for the attack signature. Rule 1 (sIDHistory write outside a migration window) is the high-signal rule — legitimate sIDHistory writes occur only during migration windows; any other write is the attack. Rule 2 (child-to-forest-root SID) catches the classic escalation pattern even inside a migration window. Rule 3 (bulk writes) catches mass-injection attempts.

`DRSAddSidHistory` is implemented for AD-interop compatibility (per ADR-126 migration scenarios where ADMT is the migration tool). The implementation enforces the same `SeEnableDelegationPrivilege` check AD does, plus the framework's per-write audit. The opnum is the migration-era mechanism; the framework cannot refuse it without breaking ADMT-based migrations.

## Consequences

**Positive**: sIDHistory injection attack is blocked at the trust boundary by default. Time-limited opt-out provides migration compat with automatic re-enablement. PIM trusts provide modern privileged-access isolation. Three-layer filter provides defence-in-depth. Audit pipeline surfaces the attack signature (sIDHistory write outside migration window) with severity "critical". MITRE ATT&CK T1178.001 mapping is automatic.

**Negative**: Default-on filtering breaks AD-interop migration scenarios that expect within-forest sIDHistory passthrough. Migrations must use the time-limited opt-out explicitly. The framework's PIM-trust support requires Server 2016+ AD partners for AD-interop scenarios. The audit pipeline's Rule 1 generates false positives during legitimate migration windows — the SOC team tunes the rule per migration.

**Neutral**: The framework's `TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER = 0x4000` is a new wire-format attribute; AD DCs ignore unknown `trustAttributes` bits (per MS-ADTS §6.1.1). The framework's bit is in a reserved range, avoiding conflicts with Microsoft-allocated bits. The filter policy is the framework's addition; AD DCs in AD-interop mode do not honour the framework's bit (they honour their own `TRUST_ATTRIBUTE_QUARANTINED = 0x4` filtering). The framework's filter applies to framework-managed KDC and File Gateway; AD-managed KDC and File Gateway continue with AD's filtering behaviour.

**Implementation cost**: ~3 person-months for the IdentityMapping filter policy, the KDC PAC builder integration, the File Gateway ACL evaluator integration, the time-limited opt-out and reconcile loop, the PIM-trust support, and the audit pipeline rules. Reuses Decision 3's `adrian-identity-fdb`, Decision 5's `adrian-kdc`, Decision 10's `adrian-smb-server`, ADR-060's audit pipeline.

**Operational impact**: SOC analysts see sIDHistory-injection alerts with MITRE T1178.001 tags. Migration teams use `adrian-cli trust set-sidhistory-passthrough` for migration windows. SREs monitor `adrian_sidhistory_writes_total{is_migration_window="false"}` for attack signal. The security team reviews `adrian-cli trust audit --sidhistory` weekly to track filter status per trust.

## Alternatives Considered

**Alternative A: Drop sIDHistory entirely (use only current SIDs).** Eliminate `sIDHistory` from the framework's directory; ACLs reference only current SIDs. Rejected because (a) it breaks AD-interop migration (PC-124 sidHistory migration, ADR-126) — AD ACLs referencing source-domain SIDs would no longer match framework-managed users; (b) it breaks the parallel-run scenario (PC-126) where users access both AD and framework resources; (c) the framework's identity model (Decision 3) explicitly preserves `sIDHistory` as a first-class attribute for AD-interop wire compatibility.

**Alternative B: Match AD's behaviour (within-forest trusts do not filter).** Inherit AD's "within-forest trusts do not filter" behaviour for AD-interop mode; apply filtering only on external and forest trusts. Rejected because (a) the attack vector is precisely within-forest trusts (child-to-forest-root escalation); (b) the framework's value proposition is doing better than AD's defaults; (c) the time-limited opt-out provides migration compat without permanent exposure.

**Alternative C: Filter only specific high-privilege SIDs (e.g. Enterprise Admins, Domain Admins).** Filter only SIDs ending in well-known RIDs (519, 512, 526, 527, 544) rather than filtering all SIDs outside the trusted domain's namespace. Rejected because (a) it is a denylist approach (must enumerate every high-privilege RID); (b) custom application-defined privileged groups are not in the denylist; (c) the allowlist approach (filter all SIDs outside the trusted domain's namespace) is more robust and matches Microsoft's SID Filter Quarantine behaviour on external trusts.

**Alternative D: Claims-based migration as the only supported migration path (no sIDHistory).** Require claims-based migration (Server 2012+ forest functional level, claim-type definitions, central access policies) as the only supported migration path; refuse `DRSAddSidHistory`. Rejected because (a) most AD source forests are below 2012 functional level; (b) claims-based access control requires resource-side central access policies that most orgs have not deployed; (c) ADMT and equivalent migration tooling uses `DRSAddSidHistory`, not claims; the framework cannot refuse it without breaking migrations.

## Open Questions

None. Workshop Decision 3 resolved the identity-model ORQ-026/027 that gated this ADR. The sIDHistory filtering model is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-010)**: Decision 3's identity mapping table is the substrate for the per-trust filter policy.
- **KDC (PC-023)**: Decision 5's KDC PAC builder applies the filter at PAC-issuance time.
- **File Gateway (PC-078)**: Decision 10's SMB server ACL evaluator applies the filter at ACL-evaluation time.
- **Operations (PC-111)**: ADR-060 (audit logs) — sIDHistory write audit events are part of the audit pipeline.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_sidhistory_writes_total` is the key metric.
- **Security (PC-117)**: ADR-122 (DCSync) — DCSync is the typical path to obtain Domain Admin (the prerequisite for `DRSAddSidHistory`); the audit pipeline detects both.
- **Migration (PC-124)**: ADR-126 (sIDHistory migration) — uses the time-limited opt-out for the migration window.
- **Migration (PC-126)**: ADR-128 (Kerberos cross-realm during migration) — the framework's filter policy applies to cross-realm trusts established during migration.

## References

- [PC-120](../catalog/11-security-threat-model.md) — problem statement (sIDHistory abuse; child-to-forest-root escalation)
- [Trusts topology KB](../docs/03-directory-schema/04-trusts-topology.md) — `trustAttributes` bitmask (`QUARANTINED = 0x4`, `WITHIN_FOREST = 0x20`, `PIM_TRUST = 0x200`); SID filtering rules; `DRSAddSidHistory` (opnum 20)
- [Domains forests trees KB](../docs/00-overview/03-domains-forests-trees.md) — forest root Enterprise Admins SID (`S-1-5-21-<forest-root-domain-sid>-519`); within-forest trust transitivity
- [Workshop Decision 3 — Identity model](../workshop/decision-03-identity-model.md) — UUID-primary + SID-as-attribute + bidirectional mapping table; per-trust filtering policy
- [Workshop Decision 5 — KDC implementation](../workshop/decision-05-kdc-implementation.md) — KDC PAC builder honours per-trust filter at PAC-issuance
- [Workshop Decision 10 — SMB server](../workshop/decision-10-smb-server.md) — File Gateway ACL evaluator honours per-trust filter
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — sIDHistory Prometheus metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — sIDHistory write audit events
- [ADR-122 — DCSync mitigation](./ADR-122-dcsync-mitigation.md) — DCSync is the typical prerequisite for `DRSAddSidHistory`
- [ADR-126 — sIDHistory migration](./ADR-126-sidhistory-migration.md) — uses the time-limited opt-out for the migration window
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — `trustAttributes`, SID filtering
- [MS-KILE §3.4.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) — sIDHistory in PAC `ExtraSids`
- [MS-DRSR §4.1.29](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — `DRSAddSidHistory` opnum 20
- [MITRE ATT&CK T1178.001 — SID History: SID History Injection](https://attack.mitre.org/techniques/T1178/001/)
- [MITRE ATT&CK T1134.005 — Access Token Manipulation: SID History Injection](https://attack.mitre.org/techniques/T1134/005/)
