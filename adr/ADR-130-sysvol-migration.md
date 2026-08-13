---
title: "ADR-130: SYSVOL Migration — SMB-Served Git-Backed Policy Share + HTTPS Distribution + DFS-N Referral"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Migration
problem: PC-130
severity: medium
tags: [adr, migration, sysvol, smb, dfs-n, git-backed-policy, https-distribution, parallel-run]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/12-migration-and-coexistence.md
  - ../docs/04-group-policy/01-gpo-architecture.md
  - ../docs/07-file-print/02-dfs-n-dfs-r.md
  - ../workshop/decision-01-replication-protocol.md
  - ../workshop/decision-10-smb-server.md
  - ./ADR-127-gpo-translation.md
  - ./ADR-128-kerberos-cross-realm-migration.md
last_updated: 2026-08-13
---

# ADR-130: SYSVOL Migration — SMB-Served Git-Backed Policy Share + HTTPS Distribution + DFS-N Referral

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 1 (replication)](../workshop/decision-01-replication-protocol.md) which replaced DFS-R with DRSUAPI NC replication (AD-interop) or Git-backed policies (native) for the SYSVOL-equivalent share, and [Workshop Decision 10 (SMB server)](../workshop/decision-10-smb-server.md) which chose a fresh Rust SMB 3.1.1 server that honours `\\<domain>\SYSVOL\...` UNC paths. This ADR specifies the migration workflow that transitions SYSVOL from AD DFS-R to the framework's Git-backed SMB-served share.

## Context

Clients read SYSVOL via `\\<domain>\SYSVOL\...` SMB share per [`04-group-policy/01-gpo-architecture.md`](../docs/04-group-policy/01-gpo-architecture.md) and [`07-file-print/02-dfs-n-dfs-r.md`](../docs/07-file-print/02-dfs-n-dfs-r.md). The GPT half of every GPO lives at `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\` with `Machine\Registry.pol`, `User\Registry.pol`, `Machine\Scripts\`, `User\Scripts\`, `Machine\Preferences\`, etc. Logon scripts (`*.bat`, `*.ps1`) are stored under `\\<domain>\SYSVOL\<domain>\scripts\` and executed by the Group Policy Scripts CSE at user logon. The `NETLOGON` share (`\\<domain>\NETLOGON\`) holds older logon scripts and is the canonical location for AD-integrated scripts.

SYSVOL is replicated between DCs via DFS-R (`dfsr.exe`), a multi-master replication protocol using RDC (Remote Differential Compression) over the wire and the USN journal for change detection. The replication topology is defined by `msDFSR-ReplicationGroup`, `msDFSR-Member`, `msDFSR-Connection`, and `msDFSR-ContentSet` objects in `CN=DFSR-GlobalSettings,CN=System,DC=...`. Conflict resolution is last-writer-wins by `LastWriteTime`; losers are moved to `ConflictAndDeleted`.

During migration, both AD and the framework must serve SYSVOL (or one must redirect). Options:

(a) **Per-domain SYSVOL with DFS-N referral**: keep AD's SYSVOL on `\\corp.example.com\SYSVOL` and add a DFS-N referral for `\\corp.example.com\NEW-SYSVOL` pointing to the framework's SMB share. Windows clients that need AD GPO access `\\corp\SYSVOL`; framework-enrolled clients access `\\corp\NEW-SYSVOL`. The GPO version mismatch between AD and framework is handled by per-OU staging (one OU at a time, the framework's GPO applies to framework-enrolled clients in that OU; AD GPO is disabled for that OU after cutover).

(b) **Migrate to HTTP-based policy distribution**: replace SMB SYSVOL with an HTTPS endpoint served by the framework. Clients fetch policies via `GET https://policy.framework.com/v1/<machine-id>/`. This eliminates the SMB dependency entirely but requires every client to support HTTP policy fetch (Windows does via the Group Policy Client service with a custom CSE; macOS via the framework's client SDK; Linux via SSSD's `ipa_selinux` equivalent). This is a greenfield approach — does not preserve AD-interop.

Workshop Decision 1 specified that SYSVOL replication uses DRSUAPI NC replication for AD-interop and Git-backed policies per ADR-031 for native mode. Decision 10 specified that the framework's SMB server exposes the Git-backed SYSVOL-equivalent share. This ADR specifies the migration workflow that uses option (a) for AD-interop coexistence and transitions to option (b) for post-cutover modernisation.

## Decision

The framework's SYSVOL migration workflow uses **both options**: option (a) (per-domain SYSVOL with DFS-N referral) for AD-interop coexistence; option (b) (HTTPS-based policy distribution) for post-cutover modernisation. The framework's SMB server (per Decision 10) honours `\\<domain>\SYSVOL\...` UNC paths for AD-interop compatibility, exposing the framework's Git-backed policy repository (per ADR-031) as a read-only share. The framework's `adrian-policy-distribution` service (per Decision 7) provides the HTTPS endpoint for post-cutover modernisation.

The framework's `adrian-cli migrate from-sysvol` CLI walks an existing AD SYSVOL, imports GPOs into the framework's Git-backed policy repository (per Decision 7's PReg reader and ADMX compiler), and emits canonical JSON policies. The framework's SMB server then serves the translated policies at `\\<domain>\NEW-SYSVOL\` for AD-interop coexistence. After cutover, the framework's HTTPS endpoint becomes the primary distribution path, and the SMB share is decommissioned (or retained for legacy Windows clients).

## Migration state machine

**Source state**: AD SYSVOL share at `\\corp.example.com\SYSVOL\corp.example.com\` with GPO files, logon scripts, GPT.INI files. DFS-R replication between AD DCs. Windows clients consume SYSVOL via `gpsvc.dll` SMB read flow.

**Target state**: Framework-native policy distribution. SMB share at `\\corp.example.com\NEW-SYSVOL\` (per-domain with DFS-N referral, for AD-interop coexistence) AND HTTPS endpoint at `https://policy.framework.com/v1/` (for framework-enrolled clients). After cutover, AD SYSVOL is decommissioned; the framework's HTTPS endpoint is the primary distribution path.

**Coexistence period**: 90–180 days. During this window:
- Both AD SYSVOL and the framework's policy distribution are active. Windows clients still receive AD GPO via `gpsvc.dll`; framework-enrolled clients receive framework policies via `adrian-policy-daemon` (HTTPS pull or SMB read from `\\<domain>\NEW-SYSVOL\`).
- The framework's `adrian-cli migrate from-sysvol --source-sysvol \\<domain>\SYSVOL --output <git-repo>` command walks the AD SYSVOL: (a) imports each GPO's `Registry.pol` via `preg2adrian` (per Decision 7); (b) imports each GPO's ADMX templates via `admx2adrian` (per Decision 7); (c) imports each GPO's `GptTmpl.inf` via `gpttmpl2adrian` (per ADR-127); (d) imports each GPO's Preferences XML via `gppref2adrian` (per ADR-127); (e) emits canonical JSON policies per GPO, written to the framework's Git-backed policy repository.
- The framework's `adrian-policy-distribution` service reads canonical JSON from Git, compiles to platform-native forms (calls `adrian-policy-preg` for Windows targets, calls the macOS MDM payload emitter, calls the Linux config-fragment emitter), and pushes via WebSocket per ADR-028. The same compiled forms are also served via the SMB share at `\\<domain>\NEW-SYSVOL\` for Windows clients that consume SYSVOL via `gpsvc.dll`.
- The framework's SMB server (per Decision 10) honours the `\\<domain>\NEW-SYSVOL\<domain>\Policies\{<GUID>}\` path layout for Windows client compat. The share is backed by the framework's Git-backed policy repository (read-only — writes go through the Git workflow per ADR-031, not via SMB).
- The framework's DFS-N referral (per ADR-044) publishes `\\<domain>\NEW-SYSVOL` as a DFS-N referral pointing to the framework's SMB server. Windows clients discover the referral via DNS SRV records.
- The framework's audit pipeline (per ADR-060) emits an event for every SYSVOL-migration operation with attributes `adrian.migration.sysvol.source_gpo_guid`, `adrian.migration.sysvol.target_policy_id`, `adrian.migration.sysvol.translation_status`, `adrian.migration.sysvol.caller`.

**Cutover trigger**: When 100% of clients are framework-enrolled and AD GPO has been disabled for ≥30 days (verified via `adrian-cli migrate from-sysvol --status --ad-gpo-disabled-days 30`), the AD SYSVOL share is decommissioned. The framework's HTTPS endpoint becomes the primary distribution path. The SMB share at `\\<domain>\NEW-SYSVOL\` may be retained for legacy Windows clients that cannot use the HTTPS endpoint, or decommissioned if all clients support HTTPS.

**Rollback path**: Re-enable AD SYSVOL share. Re-link AD GPOs to OUs (`Set-GPLink -LinkEnabled Yes`). Framework policies can be disabled or deleted. The framework's `adrian-cli migrate from-sysvol --rollback --gpo <gpo-guid>` re-enables the AD GPO and disables the framework's translated policy. The framework's policy-migration tool preserves a rollback set of framework policies per ADR-127.

**Concrete specification**:

- The framework's SMB server (per Decision 10) MUST honour the `\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\` UNC path layouts for AD-interop compatibility. The share is backed by the framework's Git-backed policy repository (per ADR-031) on the policy distribution host; the SMB server exposes the Git working tree as a read-only share.
- The framework's SMB server MUST honour the `\\<domain>\NEW-SYSVOL\` UNC path for coexistence. Windows clients that need framework-translated GPO access `\\<domain>\NEW-SYSVOL\`; Windows clients that need AD GPO access `\\<domain>\SYSVOL\`. The DFS-N referral (per ADR-044) publishes `\\<domain>\NEW-SYSVOL`.
- The framework's SMB server MUST emit Windows-compatible `Registry.pol` files at `\\<domain>\NEW-SYSVOL\<domain>\Policies\{<GUID>}\Machine\Registry.pol` and `\\<domain>\NEW-SYSVOL\<domain>\Policies\{<GUID>}\User\Registry.pol` for the Registry PolicyArea (per Decision 7's PReg adapter). Non-Registry PolicyAreas are emitted as framework-JSON at `\\<domain>\NEW-SYSVOL\<domain>\Policies\{<GUID>}\Adrian\policy.json` (per Decision 7's synthetic Windows CSE).
- The framework's `adrian-policy-distribution` service MUST provide an HTTPS endpoint at `https://policy.<forest-root>/v1/<machine-id>/` (per Decision 7) for framework-enrolled clients. The endpoint returns the client's compiled policy in the framework's canonical JSON.
- The framework MUST expose `adrian-cli migrate from-sysvol --source-sysvol \\<domain>\SYSVOL --output <git-repo>` that walks the AD SYSVOL and imports GPOs into the framework's Git-backed policy repository. The CLI runs `preg2adrian`, `admx2adrian`, `gpttmpl2adrian`, `gppref2adrian` (per ADR-127) on each GPO and emits canonical JSON policies.
- The framework MUST expose `adrian-cli migrate from-sysvol --status [--gpo <gpo-guid>]` returning per-GPO: source GPO GUID, target policy ID, translation status (per ADR-127), last-synced timestamp, AD-GPO-disabled status.
- The framework MUST expose `adrian-cli migrate from-sysvol --rollback --gpo <gpo-guid>` for per-GPO rollback. The CLI re-enables the AD GPO and disables the framework's translated policy.
- The framework's audit pipeline MUST emit an OTel log record for every SYSVOL-migration operation with the attributes listed above.
- The framework MUST emit a Prometheus metric `adrian_migration_sysvol_gpo_total{status}` (per ADR-057) — count of GPOs in each translation status.
- The framework MUST ship a default Prometheus alert: `adrian_migration_sysvol_gpo_total{status="failed"} > 0 for 30m` triggers warning (translation failures may stall migration).
- The framework's SMB server MUST enforce Access-Based Enumeration (ABE) per ADR-045 on the `\\<domain>\NEW-SYSVOL\` share — clients see only GPO folders they have read access to (matching AD SYSVOL's ABE behaviour).
- The framework's SMB server MUST support SMB 3.1.1 with SHA-512 preauth integrity and AES-256-GCM encryption (per Decision 10) for the `\\<domain>\NEW-SYSVOL\` share. Windows clients that negotiate SMB 3.1.1 get full encryption; legacy clients negotiate SMB 2.1 (no encryption but Kerberos auth).

## Rationale

Both options (a) and (b) are supported because they fit different phases of the migration. Option (a) (per-domain SYSVOL with DFS-N referral) preserves Windows client compat during coexistence — `gpsvc.dll` continues to read `\\<domain>\NEW-SYSVOL\` via SMB. Option (b) (HTTPS-based policy distribution) is the modern post-cutover path that eliminates the SMB dependency for framework-enrolled clients.

The framework's SMB server (per Decision 10) is the key enabler. A fresh Rust SMB server that honours `\\<domain>\SYSVOL\...` UNC paths is necessary for AD-interop compat; without it, the framework cannot serve Windows clients that expect SYSVOL via SMB. The Git-backed policy repository (per ADR-031) is the source of truth; the SMB server exposes the Git working tree as a read-only share. Writes go through the Git workflow (PR-based review per ADR-119, ADR-031), not via SMB.

The `adrian-cli migrate from-sysvol` CLI is the migration entry point. The CLI walks the AD SYSVOL, runs the four translators (per ADR-127), and emits canonical JSON policies. The CLI is the same workflow described in ADR-127; this ADR specifies the SYSVOL-specific share serving and the cutover/rollback path.

The DFS-N referral (per ADR-044) is the discovery mechanism. Windows clients discover the framework's SMB server via DNS SRV records for `\\<domain>\NEW-SYSVOL`; the SMB server's `IOCTL_FSCTL_DFS_GET_REFERRALS` handler returns the framework's SMB server as the referral target. This eliminates the AD-LDAP DFS namespace dependency (per ADR-044) and works cross-platform.

The HTTPS endpoint is the modern path. Framework-enrolled clients (Windows with the synthetic CSE, macOS with the framework's client SDK, Linux with SSSD or `adrian-policy-daemon`) fetch policies via HTTPS. The HTTPS endpoint is the same `adrian-policy-distribution` service per Decision 7; it compiles canonical JSON to platform-native forms on-demand.

The 90–180-day coexistence period matches the parallel-run window (per ADR-128). During coexistence, both AD SYSVOL and the framework's `\\<domain>\NEW-SYSVOL\` are active; Windows clients may receive both (AD GPO via `gpsvc.dll` native CSEs; framework policies via the synthetic CSE per Decision 7). The two coexist without conflict because they target disjoint registry subtrees (per Decision 7).

## Consequences

**Positive**: Both SMB and HTTPS distribution paths are supported. AD-interop compat is preserved (Windows clients continue to read SYSVOL via SMB). Modern post-cutover path (HTTPS) eliminates the SMB dependency for framework-enrolled clients. The framework's SMB server is fresh Rust (per Decision 10) — no Samba GPLv3 contamination, memory-safe. The Git-backed policy repository provides versioned history, PR-based review, and atomic rollback (per ADR-031).

**Negative**: The 90–180-day coexistence period requires dual-SMB infrastructure (both AD DCs serving `\\<domain>\SYSVOL\` and framework DCs serving `\\<domain>\NEW-SYSVOL\`). Cost: 2× SMB infrastructure during coexistence. Windows clients that do not support the synthetic CSE (per Decision 7) cannot consume non-Registry framework policies via SMB; they must use the HTTPS endpoint (which requires the framework's client SDK on Windows).

**Neutral**: The framework's DFS-N referral (per ADR-044) replaces AD's DFS namespace. AD-managed DFS referrals continue to work on AD-managed hosts; the framework's DFS referrals apply on framework-managed hosts. The two coexist during migration.

**Implementation cost**: ~3 person-months for the `adrian-cli migrate from-sysvol` CLI, the SMB share configuration, the DFS-N referral integration, and the audit pipeline integration. Reuses Decision 10's `adrian-smb-server`, Decision 7's `adrian-policy-distribution` and translators, ADR-031's Git-backed policy repository, ADR-044's DFS-N, ADR-060's audit pipeline.

**Operational impact**: Migration teams use `adrian-cli migrate from-sysvol` to import GPOs, `adrian-cli migrate from-sysvol --status` to track progress, and `adrian-cli migrate from-sysvol --rollback` for per-GPO rollback. SREs monitor `adrian_migration_sysvol_gpo_total` for translation progress. After cutover, the HTTPS endpoint is the primary distribution path; the SMB share may be retained or decommissioned.

## Alternatives Considered

**Alternative A: Per-domain SYSVOL with DFS-N referral only (no HTTPS).** Preserve SMB SYSVOL indefinitely; do not migrate to HTTPS. Rejected because (a) SMB SYSVOL is Windows-implementation-shaped and does not fit macOS MDM or Linux config fragments; (b) HTTPS is the modern cross-platform path; (c) the framework's value proposition includes modernisation, not just AD-interop.

**Alternative B: Migrate to HTTPS only (no SMB SYSVOL).** Decommission SMB SYSVOL on cutover; require all clients to use HTTPS. Rejected because (a) Windows clients that do not support the synthetic CSE cannot consume non-Registry framework policies via HTTPS without the framework's client SDK; (b) some legacy Windows applications hardcode `\\<domain>\SYSVOL\...` paths; (c) the gradual migration path (SMB during coexistence, HTTPS post-cutover) reduces risk.

**Alternative C: AD-interop SYSVOL only (framework uses AD's SYSVOL).** The framework's DCs register their SMB shares in AD's DFS namespace; clients read framework policies from `\\<domain>\SYSVOL\<domain>\Policies\{<framework-guid>}\`. Rejected because (a) it couples the framework to AD's DFS-R replication (the framework cannot migrate away from AD's DFS-R until the framework's own SYSVOL is authoritative); (b) AD's DFS-R has its own limitations (Windows-only, conflict resolution is LWW); (c) it does not provide a clean migration path (the framework must eventually serve its own SYSVOL).

**Alternative D: Cloud-based policy distribution only (no on-prem SMB or HTTPS).** Use a cloud service (e.g. Microsoft Intune) for policy distribution; eliminate on-prem SYSVOL entirely. Rejected because (a) it couples the framework to a specific cloud provider; (b) it does not work for air-gapped or on-premises deployments; (c) the framework's value proposition includes on-prem deployment, not just cloud.

## Open Questions

None. Workshop Decision 1 (replication) and Decision 10 (SMB server) resolved the ORQ-001/002 and ORQ-154/155 that gated this ADR. The SYSVOL migration workflow is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-001)**: Decision 1's `DrSuapiReplicator` — SYSVOL replication uses DRSUAPI NC replication for AD-interop mode (per Decision 1).
- **File Gateway (PC-078/PC-080)**: Decision 10's `adrian-smb-server` — the framework's SMB server honours `\\<domain>\SYSVOL\...` UNC paths; ADR-044 (DFS-N) — the framework's DFS-N referral publishes `\\<domain>\NEW-SYSVOL`.
- **Policy Engine (PC-043/PC-055)**: Decision 7's `adrian-policy-distribution` service — the framework's HTTPS endpoint and SMB share are both backed by the Git-backed policy repository (per ADR-031).
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_migration_sysvol_gpo_total` is the migration-progress metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — SYSVOL-migration audit events.
- **Migration (PC-125)**: ADR-127 (GPO translation) — the four translators (`preg2adrian`, `admx2adrian`, `gpttmpl2adrian`, `gppref2adrian`) are the import path for AD SYSVOL GPOs.
- **Migration (PC-126)**: ADR-128 (Kerberos cross-realm during migration) — the framework's SYSVOL share must be accessible to Windows clients during parallel-run via the cross-realm trust.

## References

- [PC-130](../catalog/12-migration-and-coexistence.md) — problem statement (SYSVOL migration requires SMB share compatibility)
- [GPO architecture KB](../docs/04-group-policy/01-gpo-architecture.md) — GPO two-part structure (GPC in AD + GPT in SYSVOL), `gPCFileSysPath` UNC link, `versionNumber` atomic pairing, `gpsvc.dll` SMB read flow
- [DFS-N and DFS-R KB](../docs/07-file-print/02-dfs-n-dfs-r.md) — DFS-N referral flow, pKT, `msDFS-TargetList`, site-aware referral costing; DFS-R replication, RDC, conflict resolution
- [Workshop Decision 1 — Replication protocol](../workshop/decision-01-replication-protocol.md) — SYSVOL replication via DRSUAPI (AD-interop) or Git (native); DFS-R not implemented
- [Workshop Decision 10 — SMB server](../workshop/decision-10-smb-server.md) — fresh Rust SMB 3.1.1 server; `\\<domain>\SYSVOL\` UNC path support; Git-backed SYSVOL-equivalent share
- [Workshop Decision 7 — Policy format](../workshop/decision-07-policy-format.md) — `adrian-policy-distribution` service; HTTPS endpoint; PReg adapter; synthetic Windows CSE
- [ADR-028 — Push-based policy distribution (WebSocket)](./ADR-028-push-based-policy-websocket.md) — WebSocket push channel
- [ADR-031 — Git-backed policy history](./ADR-031-git-backed-policy-history.md) — Git-backed policy repository (the source of truth for the framework's SYSVOL-equivalent)
- [ADR-044 — DFS-N via DNS SRV](./ADR-044-dfs-n-via-dns-srv.md) — DFS-N referral via DNS SRV records
- [ADR-045 — ABE precomputed index](./ADR-045-abe-precomputed-index.md) — ABE on the framework's SMB share
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — SYSVOL migration progress metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — SYSVOL-migration audit events
- [ADR-127 — GPO translation](./ADR-127-gpo-translation.md) — four translators (`preg2adrian`, `admx2adrian`, `gpttmpl2adrian`, `gppref2adrian`) used by `adrian-cli migrate from-sysvol`
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2) — SMB2 protocol specification (UNC path, share access)
- [MS-GPAC — Group Policy: Core Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — PReg format reference; SYSVOL share structure
- [MS-DFSNM — Distributed File System (DFS): Namespace Management Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/) — DFS-N referral flow
