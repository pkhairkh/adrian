---
title: "ADR-025: Transactional policy application with rollback"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-048
severity: medium
tags: [adr, policy-engine, transactional, rollback, snapshot]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/02-gpo-processing-order.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ./ADR-024-per-platform-policy-executors.md
  - ./ADR-031-git-backed-policy-history.md
last_updated: 2026-08-13
---

# ADR-025: Transactional policy application with rollback

## Status

Accepted — 2026-08-13.

## Context

AD GPO apply is best-effort. Per [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md), `gpsvc.dll` invokes each CSE via `ProcessGroupPolicyEx`; on CSE error, `gpsvc` logs Event 1090 (`Windows could not record the resultant set of policy (RSoP) information for Group Policy <CSE>`) in `Applications and Services Logs\Microsoft\Windows\GroupPolicy\Operational` and continues with the next CSE. There is no atomic rollback. The Registry CSE (`userenv.dll!ProcessRegistryPolicy`) writes via `RegCreateKeyExW` / `RegSetValueExW` directly; reverting requires restoring from a `Backup-GPO` archive or a System Restore point. The Security CSE (`scecli.dll!SceProcessReturnedGPOs`) writes via `LsaQueryInformationPolicy`, `SceSetSecurityPolicyInfo`, `LsaCreateAccount` — also non-transactional.

Per [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), `gpsvc` caches the last-applied version per CSE per GPO under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{<CSE-GUID>}\{<GPO-GUID>}\Version`. This cache records what was applied, not a snapshot to revert to. A GPO deployment that breaks hosts — e.g., a typo in `GptTmpl.inf` `SeServiceLogonRight` that denies service logon to every service account — has no recovery path except `Restore-GPO -BackupId <guid>` from a `Backup-GPO -Path <path>` archive, followed by `gpupdate /force` on every affected host. In a 10,000-host enterprise, this is a multi-hour outage.

AD interop imposes a constraint: `gpsvc.dll`'s call model is non-transactional and cannot be changed without breaking Windows. The framework must accept this and provide transactional apply as a wrapper around `gpsvc` on Windows, and as a first-class feature on macOS and Linux where the framework controls the entire apply path, per [PC-048](../catalog/04-policy-engine.md).

Cross-platform semantics differ: Windows `gpsvc.dll` apply is non-atomic; macOS MDM profiles are atomic per-profile (install or fail, but a profile that partially applies is undefined); Linux SSSD/Samba apply is non-atomic (`/etc/krb5.conf` rewritten in place, recovery requires file backup). The framework must define a common contract.

## Decision

The framework shall implement transactional policy application with per-executor snapshot and rollback, per the contract defined in ADR-024. Every per-platform executor (`Snapshot()`, `Apply()`, `Rollback()`, `DryRun()`) is invoked through a transactional wrapper that enforces the following semantics:

1. **Snapshot phase** — before any write, every executor in the apply set calls `Snapshot()` and stores the snapshot in a per-host, per-apply transaction log. The snapshot is opaque to the framework (the executor chooses the format: registry hive export on Windows, `defaults export` plist blob on macOS, file copy on Linux).
2. **Dry-run phase** — every executor calls `DryRun()` to compute the effective policy without applying. The framework compares dry-run output against the snapshot to produce a diff (per-setting add/modify/delete).
3. **Apply phase** — executors call `Apply()` in policy-area order. If any `Apply()` returns an error, the framework immediately halts and invokes `Rollback()` on every executor that has already completed `Apply()` — in reverse order.
4. **Rollback phase** — executors call `Rollback()` with their stored snapshot. Rollback is best-effort: if a rollback itself fails, the framework logs the failure, marks the host as "inconsistent state," and raises an alert.
5. **Commit phase** — if all `Apply()` calls succeed, the framework commits the transaction (deletes the snapshot log, writes the new version number to the per-host state).

The framework shall additionally support explicit rollback to any prior policy version (Git-style revert), per ADR-031. The transaction log is retained for the last N applies (default 10) so an operator can roll back to a specific prior version after a delayed-failure detection.

The framework shall support a `--check` / `--dry-run` CLI mode that runs the dry-run phase only and prints the diff. This is the equivalent of Ansible's `--check` mode.

**Concrete specification**:

- The transaction log is stored at `/var/lib/adrian/policy/transactions/<host>/<transaction-id>/` on Linux, `C:\ProgramData\Adrian\Policy\Transactions\<host>\<transaction-id>\` on Windows, `/Library/Application Support/Adrian/Policy/Transactions/<host>/<transaction-id>/` on macOS.
- Each transaction log entry contains: transaction ID (UUID v4), start time, end time, status (`pending` | `applied` | `rolled-back` | `failed`), per-executor snapshots, per-executor apply results, per-executor rollback results.
- The framework's `adrian-policy apply` command accepts `--check` (dry-run only, no writes), `--rollback <transaction-id>` (revert to snapshot from that transaction), `--rollback-version <version>` (revert to a prior policy version per ADR-031).
- On Windows, the synthetic CSE (ADR-024) wraps `gpsvc.dll` apply: it captures a registry hive snapshot via `RegSaveKeyEx`, calls the framework's transactional apply path for framework-authored policy, and lets native CSEs run their normal `gpsvc` path for legacy AD-authored GPOs. Native CSE errors are logged but do not trigger framework rollback (the framework cannot roll back a CSE it did not snapshot).
- On macOS, the executor snapshots via `defaults export <domain>` per domain before apply, and `defaults import` to rollback.
- On Linux, the executor snapshots via `cp -a` of the affected config file (e.g., `/etc/sssd/sssd.conf`) to the transaction log directory before apply, and `mv` to rollback.
- The framework defines a 30-second timeout for any single `Apply()` call; on timeout, the executor is killed and rollback is triggered.
- The framework exposes `GET /api/v1/hosts/<host>/transactions` (REST, per ADR-061) and `adrian-policy transactions --host <name>` (CLI, per ADR-063) for transaction log inspection.

## Rationale

Three alternatives were considered.

**Alternative 1: System-level snapshot (Windows System Restore, macOS Time Machine, Linux LVM snapshot).** Roll back the entire OS to a pre-apply checkpoint. Rejected because System Restore is per-host, requires VSS, and reverts everything (including unrelated changes). For a 10,000-host fleet, per-host System Restore is operationally infeasible (each host has a 5–10 GB shadow copy). LVM snapshots require root-disk-on-LVM, not universal.

**Alternative 2: All-or-nothing apply (atomic batch).** Either every executor applies or none does; rollback is implicit. Rejected because the per-executor surfaces (registry, plist, files) do not support atomic batch writes — there is no cross-surface transaction primitive. Forcing atomicity would require holding locks across all surfaces for the entire apply window, blocking reads.

**Alternative 3: Defer rollback to Git-style revert (per ADR-031).** Drop the snapshot mechanism entirely; rely on Git-backed policy history to revert. Rejected because Git revert re-applies the old policy through the same apply path — if the apply path itself is broken (e.g., the executor segfaults), Git revert cannot recover the host. Snapshot-based rollback is the safety net for executor-level failures; Git revert is the operator-facing change-management tool. Both are needed.

The decision aligns with industry practice: Ansible's `--check` mode and per-task `changed`/`failed` reporting; Chef's `why-run` mode; Puppet's `--noop` mode; Salt's `test=True` mode. All major config-management tools support dry-run and per-resource rollback. The framework's transactional apply is the same shape.

External evidence: Microsoft's `gpupdate /force` has no rollback — this is a known operational gap acknowledged in Microsoft's GPO troubleshooting documentation. The framework's transactional apply closes this gap.

## Consequences

**Positive**. Bad policy deployments become recoverable without fleet-wide `gpupdate /force`. An operator can roll back a broken policy to the last-known-good version in seconds (per-host `Rollback()` call) or to any prior version (Git-style revert per ADR-031). The `--check` mode lets operators preview changes before applying, reducing the "change goes to production blind" risk. The transaction log provides per-host, per-apply audit trail — useful for incident response.

**Negative**. Snapshot storage cost: each snapshot is a copy of the affected config (registry hive export can be 5–50 MB; plist exports are small; Linux config files are small). For 10 retained transactions per host across 10,000 hosts, this is ~5 GB–5 TB depending on snapshot size. The 30-second `Apply()` timeout may be too tight for large Registry hive imports; tunable per-area.

**Neutral**. The transaction log is per-host, not centralized — this matches the per-host apply model. Centralized transaction aggregation is provided by the Operations capability's audit log (per ADR-060).

**Implementation cost**. ~6 person-weeks for the transactional wrapper, the snapshot/rollback primitives, and the `--check` / `--rollback` CLI. Per-executor snapshot implementations are additional effort (counted in ADR-024's executor work).

**Operational impact**. Operators run `adrian-policy apply --check` before every change. Rollback is a single CLI call (`adrian-policy apply --rollback <transaction-id>`). The transaction log is the primary diagnostic for "what changed on this host" — replaces per-host `gpresult /h` scraping.

## Alternatives Considered

### Alternative A: System-level snapshot (System Restore / Time Machine / LVM)

Roll back the entire OS to a pre-apply checkpoint. Rejected because (a) it reverts unrelated changes (a host that received a security update between the GPO apply and the rollback loses the update), (b) per-host snapshots are storage-expensive (5–10 GB per host for System Restore), and (c) LVM snapshots require root-disk-on-LVM, which is not universal across Linux distros or macOS/Windows. Per-executor snapshots are scoped, smaller, and OS-agnostic.

### Alternative B: All-or-nothing apply with implicit rollback

Either every executor applies or none does; rollback is implicit (no per-executor snapshot needed). Rejected because the per-executor surfaces (registry, plist, files, PAM) have no cross-surface transaction primitive. Windows registry has no `RegCommitTransaction` that spans the Security CSE's LSA writes; macOS defaults has no atomic cross-domain batch; Linux file writes are atomic per-file but not across files. Forcing atomicity would require holding locks across all surfaces for the apply window, blocking reads — unacceptable for a 10,000-host fleet where apply runs continuously.

### Alternative C: Git-style revert only (no per-apply snapshot)

Drop the snapshot mechanism; rely on ADR-031's Git-backed policy history to revert. Rejected because Git revert re-applies the old policy through the same apply path — if an executor is broken (segfault, missing dependency, OOM), Git revert cannot recover the host. Snapshot-based rollback is the safety net for executor-level failures; Git revert is the operator-facing change-management tool. Both are needed; they are complementary, not alternatives.

## Open Questions

- Snapshot retention: 10 transactions per host is the default; should this be configurable per-policy-area (e.g., 50 for `Security`, 3 for `Preferences`)?
- On Windows, the synthetic CSE wraps only framework-authored policy. Native CSEs (Registry, Security, etc.) run their normal `gpsvc` path and are not snapshotted. Should the framework attempt to snapshot native CSE writes by hooking `RegSaveKeyEx` and `LsaQueryInformationPolicy`? This adds complexity and may break native CSEs.
- The 30-second `Apply()` timeout: should it be per-executor or per-transaction? Large Registry hive imports may exceed 30 seconds; per-transaction timeout is more flexible.

## Cross-capability impact

- **Policy Engine (PC-048)**: This ADR. PC-056 (Git-backed policy history, ADR-031) is the complementary change-management layer.
- **Client SDK (PC-085..PC-093)**: The transactional wrapper lives in the Client SDK's policy daemon; per-platform executors (ADR-024) implement `Snapshot` / `Apply` / `Rollback` / `DryRun`.
- **Operations (PC-106..PC-115)**: The transaction log is a first-class audit artifact; ADR-060 (audit logs in OTel format) should include transaction log events.
- **Security (PC-116..PC-123)**: Snapshot files contain a copy of pre-apply configuration — must be access-controlled (root-only on Linux, SYSTEM-only on Windows, root-only on macOS).

## References

- [PC-048](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md) — `gpsvc.dll!ProcessGroupPolicyEx` phases, Event 1090, history registry layout
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — CSE entry-point prototype, error-code propagation
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol
- [Ansible check mode](https://docs.ansible.com/ansible/latest/user_guide/playbooks_checkmode.html) — industry precedent for dry-run
