---
title: "ADR-128: Kerberos Cross-Realm with AD During Migration — Per-SPN/Per-User/Per-Host Granularity"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Migration
problem: PC-126
severity: high
tags: [adr, migration, kerberos, cross-realm, parallel-run, per-spn, per-user, per-host, cutover]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/12-migration-and-coexistence.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../workshop/decision-01-replication-protocol.md
  - ../workshop/decision-05-kdc-implementation.md
  - ./ADR-069-cross-realm-capaths.md
  - ./ADR-126-sidhistory-migration.md
last_updated: 2026-08-13
---

# ADR-128: Kerberos Cross-Realm with AD During Migration — Per-SPN/Per-User/Per-Host Granularity

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 5 (KDC implementation)](../workshop/decision-05-kdc-implementation.md) which chose a fresh Rust KDC with RFC 4120 §3.3.3 cross-realm TGT referral and `Transited` field validation, and [Workshop Decision 1 (replication)](../workshop/decision-01-replication-protocol.md) which preserved `EXOP_REPL_SECRETS` and sIDHistory passthrough for AD-interop parallel-run. This ADR specifies the migration workflow that uses cross-realm trust for parallel-run.

## Context

Migrating clients (Windows workstations, macOS laptops, Linux servers) from AD to the framework requires a parallel-run period during which the client is joined to both AD (for legacy resource access) and the framework (for new resource access). The client's Kerberos ccache contains TGTs for both realms; LDAP queries can be referred between directories; SPN lookups can resolve in either. Per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) and [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md), this is enabled by a cross-realm Kerberos trust between AD and the framework's KDC.

The Kerberos referral flow during parallel run: client (joined to AD) requests a service ticket for `cifs/file01.example.com@CORP.EXAMPLE.COM`. The AD KDC, on TGS-REQ, sees that the SPN is owned by the framework's realm (via `trustedDomain` object) and returns a referral TGT `krbtgt/FRAMEWORK.COM@CORP.EXAMPLE.COM`. The client uses this referral TGT to TGS-REQ the framework's KDC, which issues the service ticket. The client presents the service ticket to file01 (which is framework-joined). Authentication succeeds.

For LDAP, the parallel-run uses LDAP referrals. The AD DC has crossRef objects pointing to the framework's NC head; on a query for an object in the framework's NC, AD returns a referral (`SearchResultReference` with the framework's LDAP URL). The LDAP client follows the referral, rebinds to the framework's DC using Kerberos cross-realm, and retrieves the object.

The migration granularity options: (a) per-SPN migration (move one service at a time), (b) per-user migration (move one user at a time, with sIDHistory), (c) per-host migration (move one workstation at a time). Each has tradeoffs. Per-SPN is the lowest-risk but slowest. Per-user is medium-risk and medium-speed. Per-host is fastest but highest-risk.

Workshop Decision 5 chose a fresh Rust KDC with RFC 4120 §3.3.3 cross-realm TGT referral. Decision 1 chose hybrid replication that preserves AD-interop parallel-run. This ADR specifies the migration workflow that uses cross-realm trust for parallel-run at all three granularities, with explicit tooling for each.

## Decision

The framework's parallel-run migration workflow supports **all three granularities** (per-SPN, per-user, per-host) with explicit tooling. The framework's `adrian-cli migrate` CLI provides subcommands for each granularity. The framework's KDC (per Decision 5) supports the cross-realm referral flow with `Transited` field validation in `"strict"` mode (default for cross-forest trusts) per ADR-013. The framework's `[capaths]` configuration is auto-generated per ADR-069. The framework's `DRSAddSidHistory` (per ADR-126) supports the per-user migration path; the framework's SPN-migration tool supports the per-SPN path; the framework's host-rejoin tool supports the per-host path.

## Migration state machine

**Source state**: AD forest with users, computers, services. Clients are AD-joined. Cross-realm trust between AD and the framework's KDC is in place (per ADR-069). `[capaths]` is auto-generated and distributed to clients.

**Target state**: Framework-native directory with users, computers, services. Clients are framework-joined. Cross-realm trust to AD forest remains in place during the coexistence window but is decommissioned after cutover.

**Coexistence period**: 90–365 days for full migration. Per-SPN/per-user/per-host migration is staged. Both directories serve queries during coexistence.

**Per-SPN migration**:
- The framework's `adrian-cli migrate spn --spn <spn> --from-ad --to-framework` command: (a) creates the SPN on the framework's directory (on the appropriate framework-managed service account); (b) registers the SPN with the framework's KDC; (c) removes the SPN from AD (after a configurable coexistence window, default 7 days, during which both directories can issue tickets for the SPN); (d) updates the framework's `trustedDomain` object's `msDS-TrustForestTrustInfo` to reflect the SPN migration (so AD's KDC returns a referral TGT to the framework for the migrated SPN).
- The framework's audit pipeline emits an event for every SPN migration with attributes `adrian.migration.spn.name`, `adrian.migration.spn.source_realm`, `adrian.migration.spn.target_realm`, `adrian.migration.spn.coexistence_until` (timestamp), `adrian.migration.spn.caller`.

**Per-user migration**:
- The framework's `adrian-cli migrate user --user <source-dn> --source-forest <forest-dn> [--with-password]` command: (a) creates the user in the framework's directory with the same `objectGUID` (preserved as the framework UUID per Decision 3); (b) injects the source-domain SID into the framework user's `sIDHistory` via `DRSAddSidHistory` (per ADR-126); (c) if `--with-password`, copies the source user's password hash via the framework's password-sync agent (per ADR-129); (d) disables the source user in AD (after a configurable coexistence window, default 30 days, during which the user can authenticate to either directory).
- The framework's audit pipeline emits an event for every user migration with the attributes listed in ADR-126 plus `adrian.migration.user.password_copied` (boolean).

**Per-host migration**:
- The framework's `adrian-cli migrate host --host <source-dn> --source-forest <forest-dn>` command: (a) creates the computer object in the framework's directory with the same `objectGUID` (preserved as the framework UUID per Decision 3); (b) injects the source-domain SID into the framework computer's `sIDHistory` via `DRSAddSidHistory`; (c) generates a new machine account key for the framework; (d) un-joins the host from AD (`adrian-cli leave --ad`); (e) joins the host to the framework (`adrian-cli join --framework`); (f) verifies the host can authenticate to the framework and access framework-managed resources; (g) verifies the host can still access AD-managed resources via cross-realm trust.
- The framework's audit pipeline emits an event for every host migration with attributes `adrian.migration.host.source_dn`, `adrian.migration.host.target_dn`, `adrian.migration.host.sIDHistory_injected`, `adrian.migration.host.rejoin_result`.

**Cutover trigger**: When 100% of users, computers, and services have been migrated (or decommissioned) and the cross-realm trust has had no traffic for ≥30 days (verified via `adrian-cli trust traffic-stats --trust <trust-dn>`), the trust is removed (`adrian-cli trust remove --trust <trust-dn>`) and AD is decommissioned.

**Rollback path**: Re-join migrated clients to AD (`adrian-cli leave --framework && adrian-cli join --ad`). Re-create migrated users in AD (with sIDHistory reversed if needed — the framework's `adrian-cli migrate user --rollback --user <framework-dn>` clears the framework user's sIDHistory and re-enables the AD user). Re-register migrated SPNs in AD. The framework's migration tool produces a rollback plan for each migration batch.

**Concrete specification**:

- The framework's KDC (per Decision 5) MUST support RFC 4120 §3.3.3 cross-realm TGT referral with `Transited` field validation in `"strict"` mode (default for cross-forest trusts), `"disabled"` mode (default for intra-forest trusts), and `"shortcut-aware"` mode (per ADR-013).
- The framework MUST auto-generate `[capaths]` configuration from the trust graph (per ADR-069) for MIT krb5 and Heimdal clients; the configuration is written to `/etc/krb5.conf.d/adrian-capaths.conf` on Linux and PSSO Extension profile on macOS.
- The framework's KDC MUST support the SPN-migration referral flow: when a client requests a TGS for an SPN that has been migrated to the framework, the AD KDC (with updated `msDS-TrustForestTrustInfo`) returns a referral TGT to the framework; the framework's KDC issues the service ticket.
- The framework MUST expose `adrian-cli migrate spn --spn <spn> --from-ad --to-framework [--coexistence-days <N>]` for per-SPN migration. Default coexistence is 7 days.
- The framework MUST expose `adrian-cli migrate user --user <source-dn> --source-forest <forest-dn> [--with-password] [--coexistence-days <N>]` for per-user migration. Default coexistence is 30 days.
- The framework MUST expose `adrian-cli migrate host --host <source-dn> --source-forest <forest-dn>` for per-host migration. Host migration is atomic (no coexistence window — the host is un-joined from AD and joined to the framework in one operation).
- The framework MUST expose `adrian-cli migrate status --granularity <spn|user|host>` returning per-granularity: total count, migrated count, pending count, in-progress count, failed count.
- The framework MUST expose `adrian-cli trust traffic-stats --trust <trust-dn>` returning per-trust: total TGS-REQ count, total referral-TGT count, last-traffic timestamp. Used for cutover-trigger detection (no traffic for ≥30 days).
- The framework's audit pipeline MUST emit an OTel log record for every SPN/user/host migration with the attributes listed above and MITRE T1021 (Remote Services) tag for SIEM correlation (cross-realm traffic is a lateral-movement signal).
- The framework's audit pipeline MUST ship default detection rules:
  - Rule 1: cross-realm TGS-REQ storm (>100 cross-realm TGS-REQs in 5 minutes from one client) → severity "medium" (potential lateral movement or migration in progress).
  - Rule 2: cross-realm TGS-REQ for an SPN not in the migration plan → severity "high" (the SPN may have been migrated incorrectly, or an attacker is exploiting the cross-trust).
  - Rule 3: cross-realm TGS-REQ with `Transited` field validation failure → severity "high" (the ticket's transited-realms path does not match the trust graph — potential forgery).
- The framework MUST emit a Prometheus metric `adrian_migration_cross_realm_tgs_total{trust,result}` (per ADR-057).
- The framework MUST ship a default Prometheus alert: `rate(adrian_migration_cross_realm_tgs_total{result="transited_validation_failure"}[5m]) > 0` triggers critical.

## Rationale

Three granularities are supported because no single granularity fits all migration scenarios. Per-SPN is the safest (one service at a time, easy rollback) but slowest (must repeat for every service). Per-user is medium-risk and medium-speed. Per-host is fastest but highest-risk (if cross-trust fails, the host is stranded). The framework's value proposition is providing tooling for all three, letting the customer choose the granularity that fits each phase of the migration.

Per-SPN is the recommended starting point. Migrating one SPN at a time lets the customer validate the cross-realm flow, the sIDHistory passthrough, and the framework's KDC behaviour without committing to a large migration. Once confidence is established, the customer can switch to per-user or per-host for faster progress.

Per-user is the recommended middle phase. Migrating users one at a time (with sIDHistory per ADR-126 and password copy per ADR-129) preserves resource access continuity — the user can access both AD-managed and framework-managed resources via the sIDHistory and the cross-realm trust. The 30-day default coexistence window lets the customer verify the user's access before disabling the AD account.

Per-host is the recommended final phase. Migrating hosts (workstations) one at a time un-joins from AD and joins to the framework. The host's user accounts still in AD continue to authenticate via cross-trust. Per-host migration is fastest because workstations are typically migrated in batches (one OU at a time) with no per-user coordination needed.

The `Transited` field validation in `"strict"` mode (per ADR-013) is the cross-realm security control. A ticket's `Transited` field records the realms the ticket has traversed; the framework's KDC validates the field against the trust graph and rejects tickets with unexpected transit paths. This prevents an attacker from forging a ticket that claims to have transited a realm that is not in the trust graph.

The auto-generated `[capaths]` (per ADR-069) eliminates the manual-configuration pain that causes most cross-realm setup failures. The framework's CLI generates the configuration from the trust graph, validates for cycles, and distributes it to clients.

## Consequences

**Positive**: Three granularities (per-SPN, per-user, per-host) fit all migration scenarios. Per-SPN is the safest starting point. Per-user preserves resource access continuity via sIDHistory and password copy. Per-host is the fastest final phase. `Transited` field validation prevents ticket forgery. Auto-generated `[capaths]` eliminates manual configuration. The audit pipeline surfaces cross-realm traffic for SIEM correlation.

**Negative**: The 90–365-day coexistence period requires dual-identity infrastructure (both AD and framework DCs running, both directories authoritative for their respective objects). Cost: 2× DC infrastructure during coexistence. The per-user migration's 30-day coexistence window is a security exposure (the user can authenticate to either directory); the framework's audit pipeline detects anomalous dual-authentication.

**Neutral**: The framework's cross-realm trust does not preclude other cross-realm scenarios (e.g. trust with FreeIPA per Decision 12). The framework's `[capaths]` configuration is per-client; clients with custom `[capaths]` can override the framework's auto-generated configuration.

**Implementation cost**: ~5 person-months for the three `adrian-cli migrate` subcommands, the SPN-migration referral-flow integration, the `adrian-cli trust traffic-stats` CLI, and the audit pipeline rules. Reuses Decision 5's `adrian-kdc`, ADR-069's `[capaths]` auto-generation, ADR-126's `DRSAddSidHistory`, ADR-129's password-sync agent.

**Operational impact**: Migration teams use the three `adrian-cli migrate` subcommands to stage the migration. SOC analysts monitor cross-realm traffic via the audit pipeline. SREs monitor `adrian_migration_cross_realm_tgs_total` for migration progress and `Transited`-validation failures.

## Alternatives Considered

**Alternative A: Big-bang migration (no parallel-run).** Migrate all users, computers, and services in one operation; no cross-realm trust; no coexistence period. Rejected because (a) big-bang migration is high-risk (any failure strands the entire organisation); (b) the framework's value proposition is de-risking migration via parallel-run; (c) most organisations cannot tolerate the downtime required for a big-bang migration.

**Alternative B: Per-SPN migration only.** Support only per-SPN migration; refuse per-user and per-host. Rejected because (a) per-SPN is the slowest granularity (one service at a time); (b) per-user and per-host are practical necessities for large migrations; (c) the framework's value proposition includes tooling for all three granularities.

**Alternative C: Per-host migration only.** Support only per-host migration; refuse per-SPN and per-user. Rejected because (a) per-host is the highest-risk granularity (if cross-trust fails, the host is stranded); (b) some customers need the slower per-SPN or per-user path for high-confidence migration; (c) the framework's value proposition includes tooling for all three granularities.

**Alternative D: Cross-realm trust with sIDHistory filtering ON (no passthrough).** Apply sIDHistory filtering on the cross-realm trust during migration, preventing sIDHistory passthrough. Rejected because (a) it breaks per-user migration (the user's sIDHistory is filtered, so the user cannot access AD-managed resources that reference the old SID); (b) per ADR-124, the framework supports a time-limited passthrough window for migration scenarios; (c) the framework's audit pipeline + SIEM rules detect attacks during the passthrough window.

## Open Questions

None. Workshop Decision 5 (KDC) and Decision 1 (replication) resolved the ORQ-042/043/044 and ORQ-001/002 that gated this ADR. The parallel-run workflow is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-001/PC-002)**: Decision 1's `DrSuapiReplicator` implements `DRSAddSidHistory` for per-user migration.
- **KDC (PC-023/PC-028)**: Decision 5's KDC supports RFC 4120 §3.3.3 cross-realm TGT referral; ADR-013 specifies `Transited` field validation modes.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_migration_cross_realm_tgs_total` is the migration-progress metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — SPN/user/host migration audit events.
- **Migration (PC-124)**: ADR-126 (sIDHistory migration) — per-user migration uses `DRSAddSidHistory` for sIDHistory injection.
- **Migration (PC-127)**: ADR-129 (password hash migration) — per-user migration uses the password-sync agent for password copy.
- **Migration (PC-128/PC-129)**: ADR-068 (subdomain DNS) and ADR-069 (cross-realm capaths) — the DNS and `[capaths]` foundation for cross-realm trust.
- **Security (PC-120)**: ADR-124 (sIDHistory injection) — the time-limited passthrough window is the sIDHistory-abuse mitigation during migration.

## References

- [PC-126](../catalog/12-migration-and-coexistence.md) — problem statement (client switchover from AD to framework requires parallel-run support)
- [Trusts topology KB](../docs/03-directory-schema/04-trusts-topology.md) — `trustedDomain` object structure, cross-realm TGT referral flow (RFC 4120 §3.3.3), trust password rotation during coexistence
- [Kerberos internals KB](../docs/02-protocols/01-kerberos-internals.md) — Kerberos TGS-REQ/TGS-REP message flow, referral TGT mechanism, `KDC_ERR_S_PRINCIPAL_UNKNOWN (6)` triggering referral
- [Workshop Decision 1 — Replication protocol](../workshop/decision-01-replication-protocol.md) — `DrSuapiReplicator` implements `DRSAddSidHistory` and `EXOP_REPL_SECRETS` for parallel-run
- [Workshop Decision 5 — KDC implementation](../workshop/decision-05-kdc-implementation.md) — fresh Rust KDC with RFC 4120 §3.3.3 cross-realm TGT referral and `Transited` field validation
- [ADR-013 — Cross-realm TGT referral](./ADR-013-cross-realm-tgt-referral.md) — `Transited` field validation modes (strict/disabled/shortcut-aware)
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — cross-realm TGS-REQ metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — SPN/user/host migration audit events
- [ADR-068 — Subdomain DNS strategy](./ADR-068-subdomain-dns-strategy.md) — DNS namespace for parallel-run
- [ADR-069 — Cross-realm capaths](./ADR-069-cross-realm-capaths.md) — auto-generated `[capaths]` configuration
- [ADR-126 — sIDHistory migration](./ADR-126-sidhistory-migration.md) — `DRSAddSidHistory` for per-user migration
- [ADR-129 — Password hash migration](./ADR-129-password-hash-migration.md) — password-sync agent for password copy
- [RFC 4120 §3.3.3 — Kerberos Cross-Realm Operation](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3)
- [RFC 4120 §7 — Naming](https://www.rfc-editor.org/rfc/rfc4120#section-7) (Transited field semantics)
- [MS-KILE — Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (cross-realm referral, `Transited` validation)
- [MITRE ATT&CK T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/)
