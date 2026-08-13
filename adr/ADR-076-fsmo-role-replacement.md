---
title: "ADR-076: FSMO Role Replacement — Raft Consensus for Native Mode, Emulation for AD-Interop"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-014
severity: high
unblocked_by: Workshop Decision 1 (ORQ-001/002/003/004) and Workshop Decision 3 (ORQ-026/027)
tags: [adr, core-directory, fsmo, raft, consensus, schema-master, rid-master, pdc-emulator, domain-naming-master, infrastructure-master]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-01-replication-protocol.md
  - ../workshop/decision-03-identity-model.md
  - ../catalog/01-core-directory.md
  - ../docs/00-overview/04-fsmo-roles.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ./ADR-071-replication-model.md
  - ./ADR-075-cross-domain-move.md
last_updated: 2026-08-13
---

# ADR-076: FSMO Role Replacement — Raft Consensus for Native Mode, Emulation for AD-Interop

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-001/002/003/004 (replication) and ORQ-026/027 (identity model). It is now unblocked by [Workshop Decision 1 (Hybrid Replication)](../workshop/decision-01-replication-protocol.md) and [Workshop Decision 3 (UUID-Primary Identity with SID-as-Attribute and Bidirectional Mapping)](../workshop/decision-03-identity-model.md).

## Context

AD is multi-master for ordinary writes but designates exactly one DC per forest or per domain for five single-master operations: Schema Master (sole writer of the Schema NC), Domain Naming Master (sole arbiter of new domain / application partition creation), PDC Emulator (default preferred DC for password changes; trusted DC for downlevel clients; time master; urgent-replication hub), RID Master (allocates 500-RID batches to other DCs; ensures RID uniqueness), Infrastructure Master (updates cross-domain references when objects are renamed or moved). The role holder is recorded in the `fSMORoleOwner` attribute on the Schema NC head, the Partitions container, the domain NC head, the RID Manager object, and the Infrastructure object, per [PC-014](../catalog/01-core-directory.md#pc-014--fsmo-roles-are-single-master-bottlenecks-seizure-is-destructive) and [docs/00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md).

Transfer is graceful (the current holder demotes itself; the new holder is promoted; the role owner writes its own `fSMORoleOwner` and the change replicates normally). Seizure is forceful (`ntdsutil roles seize <role>` or `Move-ADDirectoryServerOperationMasterRole -Force`) — the current holder is offline or unrecoverable. The original holder **must never come back online** as a DC afterwards; if it does, it will believe it still holds the role, leading to a "torn-write" situation that replicates as a conflict and may corrupt the schema. After seizing the schema master from a DC that came back online, the only safe operation on the original holder is demotion (`dcpromo /forceremoval`).

A framework should consider whether FSMO roles are needed at all. Consensus-based RID allocation (Raft per-domain for RID pool allocation) replaces the RID master. Schema-version vector (multi-master schema with version-vector conflict resolution) replaces the schema master. Time-master-via-chrony (or NTP-with-MS-SNTP) replaces the PDC emulator's time-master role. The Infrastructure Master is largely obsolete in forests with GCs on every DC. The Domain Naming Master is needed only when adding/removing domains — a rare operation that can use a brief consensus round.

**Unblocking decisions.** [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) selects Raft for native-mode consensus, replacing all five FSMO roles with Raft leader election + FDB strict serializable transactions. AD-interop mode retains the FSMO role wire format for AD-tool compatibility. [Workshop Decision 3](../workshop/decision-03-identity-model.md) specifies the RID-pool allocator (replacing RID Master) and the identity mapping table (eliminating Infrastructure Master work). This ADR translates both decisions into the concrete FSMO replacement.

## Decision

The framework SHALL eliminate all five FSMO roles in native mode by replacing each with Raft consensus, FDB strict serializable transactions, or the identity mapping table. In AD-interop mode, the framework SHALL **emulate** all five FSMO roles for AD-tool compatibility (`netdom query fsmo`, `Get-ADForest | Select SchemaMaster, DomainNamingMaster`, `Get-ADDomain | Select PDCEmulator, RIDMaster, InfrastructureMaster`) but the role "holder" performs minimal actual work — the framework's consensus and identity infrastructure does the real work.

**Concrete specification**:

### Schema Master (replaced by multi-master schema writes with FDB OCC)

- In native mode, schema modifications are multi-master — any DC can accept `schemaModifyRequest` (per ADR-003). The schema cache copy-on-write swap (per ADR-003) is an FDB atomic transaction; FDB's optimistic concurrency control (OCC) handles concurrent schema modifies from multiple DCs. If two DCs modify the schema concurrently, one's OCC transaction commits and the other's retries (re-reads the current schema generation, re-applies the modify, re-attempts commit). The retry is transparent to the client.
- In AD-interop mode, the framework SHALL designate one DC as the Schema Master holder (via the `fSMORoleOwner` attribute on the Schema NC head). The DC accepts `schemaModifyRequest` writes from LDAP clients and replicates them via DRSUAPI to other framework DCs and to AD DCs. The role is emulated — the framework's FDB OCC does the actual work; the `fSMORoleOwner` attribute is for AD-tool discovery only.
- Schema "seizure" in native mode is a non-issue — there is no single master to seize. In AD-interop mode, schema seizure is `adrian-directory seize-role --role schema-master [--force]`, which updates the `fSMORoleOwner` attribute via an FDB atomic transaction (no risk of torn-write because FDB strict serializability prevents it).

### Domain Naming Master (replaced by FDB atomic transaction on add-domain)

- In native mode, adding/removing a domain or application partition is an FDB atomic transaction on the Partitions container. Concurrent add-domain operations are serialised by FDB OCC. No single master is needed.
- In AD-interop mode, the framework SHALL designate one DC as the Domain Naming Master holder. The DC accepts add-domain / remove-domain operations and replicates them via DRSUAPI. The role is emulated — FDB does the actual work.

### PDC Emulator (replaced by Raft leader + urgent-replication-per-DC + chrony)

- The PDC Emulator's four jobs in AD:
  1. Default preferred DC for password changes → in native mode, any DC accepts password changes; the Raft leader replicates them immediately (urgent replication is automatic in Raft).
  2. Trusted DC for downlevel clients → in native mode, the framework does not support downlevel clients (NT4, Windows 2000); downlevel-client compatibility is AD-interop-only.
  3. Time master → in native mode, the framework uses chrony with authenticated NTP (RFC 5906) per ADR-022; no PDC-emulator time-master role needed.
  4. Urgent-replication hub → in native mode, Raft replicates every committed entry immediately; no urgent-replication hub needed.
- In AD-interop mode, the framework SHALL designate one DC as the PDC Emulator holder. The DC accepts password changes from downlevel clients, serves as the time master (running chrony with the stratum-1 upstream), and triggers urgent replication via DRSUAPI `IDL_DRSReplicaSync` with the `DRS_ASYNC_OP` flag.

### RID Master (replaced by FDB atomic-add counter + RID-pool allocator per Decision 3)

- In native mode, RID allocation is local per DC (per Decision 3) — each DC maintains its own RID counter at `(0x06, local_dc_id, domain_sid) → next_rid`. The DC's `local_dc_id` is its `invocationId`. No RID-master coordination needed.
- In AD-interop mode, the framework SHALL designate one DC as the RID Master holder. The DC dispenses 500-RID batches to other DCs via the RID-pool allocator (per Decision 3). The role is real (AD-interop requires RID-master coordination for SID uniqueness).

### Infrastructure Master (eliminated — identity mapping table resolves cross-domain references)

- The Infrastructure Master's job (update cross-domain references when objects are renamed or moved) is **eliminated entirely** in both modes. The framework's identity mapping table (per Decision 3) resolves cross-domain references at read-time — there is no periodic "update references" task to run.
- In AD-interop mode, the framework SHALL designate one DC as the Infrastructure Master holder (via the `fSMORoleOwner` attribute on the Infrastructure object) for AD-tool discovery. The role is emulated — no work is performed (per ADR-075).

### Cross-cutting

- The framework SHALL expose `adrian-directory fsmo show` CLI equivalent to `netdom query fsmo` and `Get-ADForest | Select SchemaMaster, DomainNamingMaster; Get-ADDomain | Select PDCEmulator, RIDMaster, InfrastructureMaster`. The CLI outputs the role holders (in AD-interop mode) or "all roles eliminated — native mode" (in native mode).
- The framework SHALL expose `adrian-directory fsmo transfer --role <role> --to <DC-DN>` and `adrian-directory fsmo seize --role <role> [--force]` CLI commands for AD-interop mode. In native mode, these commands are no-ops (logged with a warning).
- The framework SHALL monitor FSMO role holder availability in AD-interop mode (per `adrian-operator` ADR-058). If a role holder is offline, the operator alerts; the admin can transfer or seize via CLI.
- The framework SHALL NOT support the "original holder must never come back online" constraint in AD-interop mode (this is an AD-specific constraint caused by AD's single-master model; the framework's FDB strict serializability prevents torn-writes regardless of which DC holds the role).

## Rationale

FSMO roles exist in AD because AD's replication model is multi-master-with-exceptions — certain operations cannot be multi-mastered safely (schema modifications, RID allocation, domain naming) without a coordination mechanism. AD uses single-master designation (one DC holds the role; if it fails, the role is seized).

The framework's substrate (FDB strict serializable transactions, Raft consensus, identity mapping table) provides the coordination mechanism without single-master designation. Schema modifications are coordinated by FDB OCC. RID allocation is local (native) or by RID-pool allocator (AD-interop). Domain naming is coordinated by FDB atomic transaction. The PDC Emulator's jobs are split among Raft leader, chrony, and urgent-replication-per-DC. The Infrastructure Master is eliminated by the identity mapping table.

The emulation in AD-interop mode is for AD-tool compatibility — `netdom query fsmo`, `Get-ADForest`, `Get-ADDomain`, `ntdsutil roles` all query the `fSMORoleOwner` attribute. The framework sets this attribute to a real DC (for discovery) but the role performs no actual work (FDB/Raft do the work).

External evidence: CockroachDB and TiKV eliminate single-master roles via Raft consensus + distributed transactions. HashiCorp Consul eliminates single-master via Raft. Microsoft Entra ID (Azure AD) eliminates FSMO via cloud-native consensus (the on-prem AD FSMO roles are not present in Entra ID). The pattern is industry-standard for any system that moves beyond AD's multi-master-with-exceptions model.

## Consequences

**Positive**: Native-mode deployments eliminate all five FSMO single-master bottlenecks. No "seizure is destructive" risk — there is no single master to seize. No "original holder must never come back online" constraint. Schema modifications are multi-master (any DC can accept). RID allocation is local (no RID-master dependency). The Infrastructure Master is eliminated (no periodic cross-domain reference update task). PDC Emulator's jobs are distributed among Raft/chrony/urgent-replication.

**Negative**: AD-interop mode retains the FSMO role wire format for compatibility — the framework must maintain the `fSMORoleOwner` attribute on five objects and respond to AD-tool queries. This is emulation overhead, not real work. The framework's documentation must clearly distinguish "role holder" (emulated, for AD-tool discovery) from "role work" (done by FDB/Raft/identity mapping).

**Neutral**: AD admins can continue to use `netdom query fsmo`, `Get-ADForest`, `Get-ADDomain`, `ntdsutil roles` in AD-interop mode. The framework's `adrian-directory fsmo` CLI is the modern equivalent. Native-mode deployments use `adrian-directory fsmo show` which outputs "all roles eliminated".

**Cost**: ~3 person-weeks for the FSMO emulation layer (role-holder designation, `fSMORoleOwner` attribute management, transfer/seize CLI) + ~1 person-week for the schema-master multi-master OCC integration + ~1 person-week for the RID-master RID-pool allocator integration. The Raft leader (per ADR-071) and chrony (per ADR-022) are separate. Total ~5 person-weeks.

**Operational impact**: No more "seize FSMO role" runbooks in native mode. AD-interop mode retains the runbook but the seizure is non-destructive (FDB strict serializability prevents torn-writes). The `adrian-operator` (ADR-058) monitors FSMO role holder availability in AD-interop mode and alerts on role-holder offline.

## Alternatives Considered

### Alternative 1: Keep all five FSMO roles in both modes

Maximum AD-interop compatibility. But preserves the single-master bottlenecks (PC-014's core complaint) and the "seizure is destructive" risk. Rejected for native mode — defeats the purpose of moving beyond AD. ADOPTED for AD-interop mode (emulated, no actual work).

### Alternative 2: Hybrid — keep FSMO on the wire (AD-interop), Raft internally (native)

This is the chosen decision. The framework's `fSMORoleOwner` attribute is the wire-format compatibility shim; the framework's consensus and identity infrastructure does the real work. Both modes benefit from the underlying elimination of single-master bottlenecks.

### Alternative 3: Eliminate FSMO entirely (no emulation in AD-interop mode)

Reject AD-interop compatibility. AD tools (`netdom query fsmo`, `Get-ADForest`, `ntdsutil roles`) would fail with "attribute not found". Rejected — AD-interop is a v1 requirement.

## Open Questions

- For AD-interop mode, should the framework co-locate all five FSMO roles on one DC (the "operations master" DC) or distribute them? Default: co-locate on the "schema master" DC for simplicity (the Schema Master is the most consequential role; co-locating avoids split-role operational complexity). Confirm with customer demand.
- For schema-master multi-master OCC in native mode, what is the retry budget? Default: 3 retries with exponential backoff (1ms, 4ms, 16ms); if all fail, return `unwillingToPerform (53)` to the client. Confirm in implementation.
- For the Domain Naming Master in AD-interop mode, does the framework need to support cross-forest trusts (which require Domain Naming Master coordination)? Yes — cross-forest trust creation is gated by the Domain Naming Master in AD. The framework's emulated Domain Naming Master accepts the trust-creation operation and replicates it via DRSUAPI.

## Cross-capability impact

- **KDC**: KDC's krbtgt rotation (per ADR-015) uses urgent replication via the PDC Emulator (AD-interop) or Raft immediate replication (native). Cross-capability: KDC's PAC builder reads the principal's current SID via the identity mapping table — no FSMO dependency.
- **Auth Provider**: NTLM password validation uses the PDC Emulator as the preferred DC (AD-interop) for "did the password just change?" lookups. In native mode, any DC has the current password (Raft immediate replication).
- **Policy Engine**: GPO creation does not require FSMO roles. GPO SD evaluation uses the identity mapping table for SID-to-UUID translation.
- **Cert Service**: NTAuthCertificates publication does not require FSMO roles. CA database (per ADR-034) uses FDB.
- **Operations**: FSMO role monitoring is an AD-interop-only concern (per `adrian-operator` ADR-058). Native-mode deployments do not monitor FSMO (no roles to monitor).
- **Migration**: AD-to-framework migration can transfer FSMO roles to framework DCs (the framework's emulated roles accept transfer). Migration runbooks document the transfer procedure.
- **Security**: PC-117 (DCSync) threat model — the RID Master is the gatekeeper for SID uniqueness. In native mode, RID allocation is local (no RID-master gatekeeping); SID uniqueness is enforced by the local RID counter (monotonic per DC). The threat model must account for this difference.

## References

- [PC-014](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 1 — Hybrid Replication](../workshop/decision-01-replication-protocol.md) — Raft replaces FSMO in native mode
- [Workshop Decision 3 — UUID-Primary Identity](../workshop/decision-03-identity-model.md) — RID-pool allocator replaces RID Master; identity mapping table eliminates Infrastructure Master
- [docs/00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md) — full FSMO role table, transfer vs seizure semantics, `fSMORoleOwner` attribute locations
- [docs/03-directory-schema/05-replication-internals.md](../docs/03-directory-schema/05-replication-internals.md) — urgent replication, PDC Emulator's urgent-replication hub role
- [MS-ADTS §3.1.1.5](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — FSMO roles, `fSMORoleOwner` attribute
- [ADR-071: Replication Model](./ADR-071-replication-model.md) — Raft leader election
- [ADR-075: Cross-Domain Move](./ADR-075-cross-domain-move.md) — Infrastructure Master elimination
- [ADR-022: NTP / Chrony Time Sync](./ADR-022-ntp-chrony-time-sync.md) — PDC Emulator time-master role replacement
