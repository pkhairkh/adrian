---
title: "ADR-094: SYSVOL-equivalent replication via Git-backed policy repository + SMB read surface (resolves PC-055)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-055
severity: blocker
unblocked_by: Workshop Decision 1
tags: [adr, policy-engine, sysvol, dfs-r, git, smb, replication, distribution, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../workshop/decision-01-replication-protocol.md
  - ../workshop/decision-10-smb-server.md
  - ../docs/07-file-print/02-dfs-n-dfs-r.md
  - ../docs/04-group-policy/01-gpo-architecture.md
  - ./ADR-031-git-backed-policy-history.md
  - ./ADR-089-declarative-policy-gpc-gpt-synthesis.md
last_updated: 2026-08-14
---

# ADR-094: SYSVOL-equivalent replication via Git-backed policy repository + SMB read surface (resolves PC-055)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) (Hybrid Replication — Fresh Rust DRSUAPI for AD-Interop, Raft for Native Mode) and [Workshop Decision 10](../workshop/decision-10-smb-server.md) (Fresh Rust SMB 3.1.1 server with SYSVOL-equivalent share). Decision 1 §Trade-offs explicitly accepts "no DFS-R" with Git-based replication for policy files; Decision 10 §10 specifies the framework's SYSVOL-equivalent share backed by the Git-backed policy repository (per ADR-031). This ADR operationalises those decisions against the PC-055 problem surface: the Windows-only nature of DFS-R SYSVOL replication and the framework's choice between implementing DFS-R, adopting Samba's DRSUAPI SYSVOL, or externalising to Git/object-store with an SMB read surface for legacy clients.

## Context

SYSVOL is the AD shared directory that hosts Group Policy Templates (GPT folders), logon scripts, and the ADMX Central Store. Per [docs/07-file-print/02-dfs-n-dfs-r.md](../docs/07-file-print/02-dfs-n-dfs-r.md), SYSVOL replicates via DFS-R (`dfsr.exe`) using version vectors + RDC (Remote Differential Compression) over the wire and the USN journal (`$Extend\$UsnJrnl:$J`) for change detection. The DFS-R RPC interface is UUID `91b7b931-c75a-4530-8258-1b3eb578c5d8`, version 1.0, with opnums for `EstablishConnection`, `GetVersionVector`, `RequestUpdates`, `AsyncPoll`, `GetStatus`. Server 2008 R2+ uses DFS-R for SYSVOL replication (FRS is deprecated); Server 2019 removed FRS entirely. Migration is via `dfsmig.exe` (`/setglobalstate 0→1→2→3`). SYSVOL is a special Replication Group `CN=SYSVOL Share,CN=DFSR-LocalSettings,CN=<dc>,OU=Domain Controllers,DC=...` linked to the `Domain System Volume` content set in `CN=DFSR-GlobalSettings,CN=System,DC=...`. Each DC hosts a read-write copy of SYSVOL; DFS-R converges changes across all DCs with typical latency of 15 seconds to 15 minutes depending on replication schedule and network bandwidth.

Samba AD-DC replicates SYSVOL via DRSUAPI on the SysVol directory (single-master per attribute) — a different mechanism, not DFS-R. Per the same KB, Samba's `source4/rpc_server/drsuapi/` is the only non-Microsoft implementation that answers DRSGetNCChanges as a server; Samba does NOT implement DFS-R. macOS SMBX does not host DFS-N namespaces or DFS-R. Linux `cifs.ko` and `mount.cifs` are DFS-N clients (referral-aware) but not DFS-R replication members. The matrix in [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md) shows SYSVOL as the GPT distribution channel, with `gPCFileSysPath` UNC linkage from the GPC directory object.

For the framework, SYSVOL is the GPO + logon-script distribution channel; without it, GPO breaks entirely (per PC-055). The framework cannot use DFS-R (no open-source implementation exists; writing one is a multi-year project; the DFS-R protocol is undocumented in places — Microsoft's MS-DFSR specification is incomplete). The framework cannot use Samba's DRSUAPI SYSVOL (per Decision 10's rejection of Samba). The choices are: (a) implement DFS-R-equivalent (write it — significant engineering, no open-source implementation exists), (b) Samba-style DRSUAPI-based SYSVOL (Samba's existing model), or (c) externalize to Git/object-store with auto-sync to DCs and provide SMB-read access for legacy clients.

Workshop Decision 1 §Trade-offs accepts "no DFS-R" with Git-based replication for policy files; the framework's directory replication (DRSUAPI or Raft, per Decision 1) handles directory objects (the GPC-equivalent). Decision 10 §10 specifies the SMB server's SYSVOL-equivalent share backed by the Git-backed policy repository (per ADR-031). This ADR defines the Git-based SYSVOL replication model, the SMB read surface, the convergence semantics, and the migration path from AD's DFS-R SYSVOL.

## Decision

The framework **does not implement DFS-R**. SYSVOL-equivalent replication uses Git for policy files (per ADR-031) and the framework's directory replication (per Decision 1) for directory objects (GPC-equivalents). The SMB server (per Decision 10 §10) exposes the Git-backed policy repository as a read-only `\\<domain>\SYSVOL\` share for legacy Windows clients; framework-SDK-enrolled clients receive policy via WebSocket push (per ADR-028) and do not read SYSVOL via SMB. The model is: Git is the source of truth; the SMB share is a read surface derived from Git; the directory replication handles the GPC-equivalent synthesised objects (per ADR-089).

### Concrete specification

1. **Git as the source of truth.** The framework's policy repository (per ADR-031) is a Git repository hosted by the framework's policy distribution service. Each policy commit produces: (a) a canonical JSON policy document committed to Git (per ADR-031); (b) a synthesised GPT folder written to the SMB-served SYSVOL-equivalent share (per ADR-089 §3); (c) a synthesised GPC directory object written to the framework's directory (per ADR-089 §2). The Git commit is the atomic unit; the synthesised GPT folder and GPC object are derived from the commit and written transactionally (the distribution service writes the GPT folder first via atomic-rename of a staging directory, then writes the GPC object via LDAP `MODIFY`; on failure, the staging directory is rolled back).

2. **SMB-served SYSVOL-equivalent share.** Per Decision 10 §10, the framework's SMB server exposes `\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\` as read-only shares. The shares are backed by the Git working tree on the policy distribution host (per ADR-031); the SMB server exposes the working tree as a read-only share. Writes are not permitted via SMB — policy updates go through the framework's Git workflow (operators commit to Git via the framework's UI or via `git push` to the framework's Git server). The share's directory structure mirrors AD's SYSVOL: `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\` (per-policy GPT folders, synthesised per ADR-089 §3); `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Adrian\policy.json` (the canonical JSON, consumed by the synthetic CSE per ADR-092 §5); `\\<domain>\SYSVOL\<domain>\scripts\` (logon scripts, stored as files in Git); `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\` (the ADMX Central Store, populated by `admx2adrian` per ADR-090).

3. **Multi-DC replication.** Each framework DC hosts a replica of the SYSVOL-equivalent share. The replicas are kept in sync via Git's native replication: each DC's policy distribution service runs `git pull` from the framework's central Git server on every push notification (the Git server's `post-receive` hook sends a webhook to each DC's distribution service, which runs `git pull --ff-only`). On `git pull` success, the DC's SMB server re-exposes the updated working tree. Convergence latency is typically sub-second on a LAN (Git's `git pull` over SSH is fast for small policy repositories; the typical policy repository is <100 MB). On WAN links, convergence latency is bounded by Git's transfer time (seconds for small commits; the framework's Git server uses Git's `protocol.version=2` with partial clone for bandwidth efficiency). This replaces DFS-R's 15-second-to-15-minute convergence window with sub-second-to-seconds convergence.

4. **Conflict resolution.** Git's merge model handles conflicts: if two operators commit conflicting policy changes (e.g., both modify the same policy's `Registry` area), Git's `git merge` produces a conflict that the second operator must resolve manually. The framework's `adrian-policy validate` pre-commit hook (per ADR-031) catches schema-level conflicts at commit time; semantic conflicts (e.g., two policies targeting the same host with different settings) are caught by the framework's `adrian-policy coverage` CLI (per Decision 7 §7) at authoring time. This replaces DFS-R's last-writer-wins conflict resolution (which silently drops the loser's changes) with explicit conflict resolution via Git merge.

5. **Directory replication for GPC-equivalents.** The synthesised GPC directory objects (per ADR-089 §2) replicate via the framework's directory replication (DRSUAPI in AD-interop mode, Raft in native mode, per Decision 1). This is the same replication channel that handles all other directory objects; no separate replication channel is needed for GPC-equivalents. The GPC-equivalent's `versionNumber` is derived from the Git commit SHA (the framework's distribution service computes a 64-bit hash of the commit SHA and packs it into the `(userVersion << 32) | machineVersion` representation); the GPT folder's `GPT.INI Version=` is set to the same value at synthesis time. The version-mismatch invariant (per PC-043) holds by construction.

6. **`NETLOGON` share.** The `\\<domain>\NETLOGON\` share hosts logon scripts (`.bat`, `.cmd`, `.ps1` for Windows; `.sh` for Linux/macOS framework-SDK clients). The scripts are stored as files in Git (under `netlogon/` directory in the policy repository); the SMB server exposes the Git working tree's `netlogon/` directory as the `NETLOGON` share. Legacy Windows clients run their logon scripts from `NETLOGON` via the `Scripts` CSE (per ADR-089 §3); framework-SDK clients receive scripts via WebSocket push and execute them via the framework's `Scripts` executor (per ADR-092 §1).

7. **ADMX Central Store.** The `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\` directory hosts the ADMX Central Store (per [docs/04-group-policy/03-admx-templates.md](../docs/04-group-policy/03-admx-templates.md)). The framework's `admx2adrian` compiler (per ADR-090) populates this directory with the compiled ADMX files (the framework re-emits ADMX from the canonical JSON for AD-interop — `admx2adrian` is one-way JSON→ADMX, but the Central Store's ADMX files are copied verbatim from the source ADMX bundle, not re-emitted). Legacy Windows GPMC reads the Central Store's ADMX files for policy authoring UI; framework's authoring UI reads the canonical JSON templates directly.

8. **Migration from AD's DFS-R SYSVOL.** The `adrian-migrate from-sysvol` CLI walks an AD DC's `\\<domain>\SYSVOL\` share (via SMB, authenticated as the host machine account), copies each GPT folder, logon script, and ADMX file into the framework's Git repository, and commits the result. The CLI runs `preg2adrian` (per ADR-029) on each `Registry.pol` to produce canonical JSON; runs `admx2adrian` (per ADR-090) on each referenced ADMX to produce JSON templates; and emits a single Git commit per migrated GPO. The migration is one-way (AD → framework); the framework does not write back to AD's SYSVOL.

9. **Backup and disaster recovery.** The Git repository is backed up via Git's native backup mechanisms (the framework's Git server is configured with `git push --mirror` to a remote backup Git server; the backup server is in a different data center). On disaster recovery, the framework's Git server is restored from the backup; the DCs' distribution services re-`git pull` from the restored server; the SMB shares re-expose the restored working trees. This replaces AD's SYSVOL backup model (`wbadmin start backup` of the SYSVOL folder + DFS-R's `dfsrdiag` recovery tools) with Git's standard backup model.

## Rationale

Three alternatives were considered.

**Alternative A: Implement DFS-R-equivalent.** Write a fresh DFS-R server and client in Rust, derived from the MS-DFSR specification. Rejected because (a) the MS-DFSR specification is incomplete in places — Microsoft's published spec omits internal details of the version-vector reconciliation algorithm and the RDC signature-computation algorithm; Samba's reverse-engineering notes fill some gaps but are not authoritative; (b) the implementation effort is estimated at ~12 person-months for a production-quality DFS-R server (per Decision 10's SMB-server effort estimate of ~28 person-weeks for a fully-specified protocol; DFS-R is less well-specified and more complex); (c) DFS-R's value proposition (multi-master read-write replication with RDC bandwidth optimization) is not needed for the framework's SYSVOL-equivalent — policy files are written by one authority (the framework's policy distribution service) and read by all DCs; multi-master writes are not required; (d) Git's replication model (single-master write, multi-replica read, with merge-based conflict resolution) is a better fit for the framework's policy-authoring workflow (operators commit via PR; the Git server is the single write authority). Decision 1 §Trade-offs accepts "no DFS-R" explicitly.

**Alternative B: Adopt Samba's DRSUAPI SYSVOL.** Use Samba's DRSUAPI-based SYSVOL replication (single-master per attribute). Rejected because (a) per Decision 10's rejection of Samba, the framework does not adopt Samba (GPLv3 license conflict; Samba's `smbd` is rejected as the SMB server; Samba's DRSUAPI SYSVOL is part of the Samba AD-DC codebase, which is GPLv3); (b) Samba's DRSUAPI SYSVOL is single-master (one DC is the write authority; others replicate read-only), which is the same model as Git but with Samba's RPC-over-DCE/RPC transport instead of Git's SSH transport — Git's transport is simpler and more widely supported; (c) Samba's DRSUAPI SYSVOL does not support RDC bandwidth optimization (no bandwidth savings over WAN links); Git's partial-clone and shallow-clone features provide better bandwidth optimization for the framework's use case.

**Alternative C: Externalize to object-store (S3/GCS) with SMB-read adapter.** Store policy files in S3-compatible object storage; the SMB server reads from S3 on demand. Rejected because (a) object storage has higher per-request latency than Git working tree (S3 GET is ~10-50ms; local filesystem read is <1ms); the SMB server's read latency would be 10-50x worse than AD's DFS-R SYSVOL; (b) object storage does not support atomic multi-file updates (a GPT folder has multiple files that must be updated atomically; S3 has no multi-object transaction); (c) object storage introduces a cloud dependency (the framework cannot operate without internet connectivity to S3), which contradicts the framework's air-gapped-deployment support; (d) Git's local working tree is the natural backing store for the SMB server (the SMB server reads files via standard POSIX I/O, no adapter needed).

The chosen model — Git-backed policy repository + SMB read surface — gives the framework: (a) cross-platform replication (Git runs on all platforms; no Windows-only DFS-R dependency); (b) explicit conflict resolution (Git merge replaces DFS-R's last-writer-wins); (c) fast convergence (sub-second on LAN, seconds on WAN); (d) standard backup model (Git mirror push); (e) no DFS-R implementation burden.

## Consequences

**Positive**. The framework does not need to implement DFS-R (saving ~12 person-months of engineering). Policy replication converges in sub-seconds (vs. DFS-R's 15-second-to-15-minute window). Conflict resolution is explicit (Git merge) rather than silent (DFS-R last-writer-wins). Backup is standard Git mirror push (vs. AD's `wbadmin` + `dfsrdiag` recovery). The SMB read surface provides AD-interop for legacy Windows clients.

**Negative**. The framework's SYSVOL is single-master write (the Git server is the write authority); multiple DCs cannot write to SYSVOL simultaneously (whereas AD's DFS-R allows multi-master writes). For the framework's use case (policy authored via the framework's UI or Git PR), single-master write is not a limitation — operators do not write directly to SYSVOL. The Git server is a single point of failure for policy writes; the framework mitigates this by running the Git server in a highly-available configuration (per Decision 1's Raft-based HA for native mode; per ADR-058's StatefulSet for Kubernetes deployments).

**Neutral**. The framework's SYSVOL is read-only via SMB (writes go through Git); this matches the framework's policy-authoring workflow (operators do not hand-edit SYSVOL files, unlike the AD antipattern). The `adrian-cli policy push` CLI is the only write path to SYSVOL (it commits to Git and triggers the distribution service's synthesis).

**Implementation cost**. ~3 person-weeks for v1 (subsumed in Decision 10's SMB-server effort and ADR-031's Git-backed policy history): Git server setup + post-receive webhook (1 pw), SMB share exposure of Git working tree (1 pw, subsumed in Decision 10's SYSVOL-equivalent share implementation), migration CLI `adrian-migrate from-sysvol` (1 pw). Ongoing maintenance: ~0.5 person-week per year for Git server upgrades.

**Operational impact**. Operators commit policy via the framework's UI or `git push`. The `adrian-policy push` CLI triggers the distribution service's synthesis (GPT folder + GPC object). The `adrian-policy status --host <name>` CLI shows the host's last-applied policy version (Git commit SHA). The framework's audit log records every policy commit and every DC's `git pull` event.

## Alternatives Considered

### Alternative A: Implement DFS-R-equivalent

Write a fresh DFS-R server and client in Rust, derived from the MS-DFSR specification.

Rejected as detailed in §Rationale and Decision 1 §Trade-offs: the MS-DFSR specification is incomplete; the implementation effort is ~12 person-months; DFS-R's multi-master read-write model is not needed for the framework's SYSVOL-equivalent; Git's single-master write model is a better fit. Decision 1 §Trade-offs accepts "no DFS-R" explicitly.

### Alternative B: Adopt Samba's DRSUAPI SYSVOL

Use Samba's DRSUAPI-based SYSVOL replication (single-master per attribute).

Rejected as detailed in §Rationale: Samba is GPLv3 (license conflict per Decision 10); Samba's DRSUAPI SYSVOL is part of the Samba AD-DC codebase; Samba's RPC-over-DCE/RPC transport is more complex than Git's SSH transport; Samba's DRSUAPI SYSVOL does not support RDC bandwidth optimization.

### Alternative C: Externalize to object-store (S3/GCS) with SMB-read adapter

Store policy files in S3-compatible object storage; the SMB server reads from S3 on demand.

Rejected as detailed in §Rationale: object storage has higher per-request latency; object storage does not support atomic multi-file updates; object storage introduces a cloud dependency (contradicting air-gapped-deployment support); Git's local working tree is the natural backing store for the SMB server.

## Open Questions

- **Git repository size growth.** The policy repository grows with every commit (Git stores every version of every policy document). For a 10,000-policy deployment with weekly policy updates over 5 years, the repository could grow to several GB. Current decision: Git's `git gc --aggressive` runs weekly to pack objects; the repository is expected to stay under 5 GB. Revisit if repository growth exceeds 10 GB (consider Git LFS for large binary policy artifacts).
- **Multi-master Git writes for federated deployments.** For federated deployments with multiple framework domains (per ADR-013 cross-realm), each domain has its own Git server; cross-domain policy replication is not needed (each domain's policy is independent). Revisit if customers request cross-domain policy replication (no current demand).
- **SMB share write-back for legacy GPO tooling.** Some legacy Windows GPO tooling (e.g., `GPMC.msc`'s "Edit" action that launches `gpedit.msc` and writes directly to SYSVOL) expects to write to SYSVOL via SMB. The framework's SMB share is read-only; such tooling breaks. Current decision: operators migrate from `GPMC.msc` to the framework's authoring UI before migrating SYSVOL; the `adrian-migrate from-sysvol` CLI is the one-time migration path. Revisit if customers report legacy-GPO-tooling-write demand during migration.

## Cross-capability impact

- **Core Directory (Decision 1)**: The GPC-equivalent directory objects replicate via the framework's directory replication (DRSUAPI or Raft); the Git-backed policy files replicate via Git. The two replication channels are independent (directory replication for GPC; Git for GPT), eliminating AD's two-channel coherence bug (per PC-043).
- **File Gateway (Decision 10)**: The SMB server exposes the Git working tree as the `SYSVOL` and `NETLOGON` shares. The Git-backed policy repository is the backing store for the SMB share.
- **Policy Engine (PC-043 GPC/GPT split)**: ADR-089's GPC/GPT synthesis uses Git as the source of truth; the synthesised GPC and GPT are derived from the same Git commit, eliminating the version-mismatch invariant.
- **Policy Engine (PC-056 no native versioning)**: Git provides native versioning and history (per ADR-031); the framework's `adrian-policy history` CLI shows the commit log per policy.
- **Migration (PC-130 SYSVOL migration)**: The `adrian-migrate from-sysvol` CLI is the migration entry point from AD's DFS-R SYSVOL to the framework's Git-backed SYSVOL.
- **Operations (PC-115 unified CLI)**: The `adrian-policy push`, `adrian-policy status`, and `adrian-policy history` CLI subcommands are part of the framework's unified CLI.

## References

- [PC-055](../catalog/04-policy-engine.md) — problem statement in the catalog
- [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) — Hybrid Replication (DRSUAPI AD-interop, Raft native; "no DFS-R" trade-off)
- [Workshop Decision 10](../workshop/decision-10-smb-server.md) §10 — SYSVOL-equivalent share backed by Git
- [docs/07-file-print/02-dfs-n-dfs-r.md](../docs/07-file-print/02-dfs-n-dfs-r.md) — DFS-R architecture, RPC UUID, USN journal, SYSVOL Replication Group, FRS-to-DFS-R migration
- [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md) — SYSVOL as the GPT distribution channel, `gPCFileSysPath` UNC linkage
- [docs/04-group-policy/03-admx-templates.md](../docs/04-group-policy/03-admx-templates.md) — ADMX Central Store under SYSVOL
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution (WebSocket; SDK-enrolled clients do not read SYSVOL via SMB)
- [ADR-031](./ADR-031-git-backed-policy-history.md) — Git-backed policy history (the source-of-truth repository)
- [ADR-089](./ADR-089-declarative-policy-gpc-gpt-synthesis.md) — GPC/GPT synthesis (the synthesised GPT folder is written to the SYSVOL-equivalent share)
- [MS-DFSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsr) — DFS Replication Protocol (reference for the protocol the framework declines to implement)
