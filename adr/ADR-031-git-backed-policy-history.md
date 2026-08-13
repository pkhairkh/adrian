---
title: "ADR-031: Git-backed policy history with PR review"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-056
severity: medium
tags: [adr, policy-engine, gitops, versioning, audit]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/01-gpo-architecture.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ./ADR-025-transactional-policy-rollback.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
last_updated: 2026-08-13
---

# ADR-031: Git-backed policy history with PR review

## Status

Accepted — 2026-08-13.

## Context

AD GPO has only `versionNumber` (OID `1.2.840.113556.1.4.1340`, combined machine+user 64-bit integer, per [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md)). There is no history of past versions — only the current `versionNumber` and the previous one cached under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{<CSE-GUID>}\{<GPO-GUID>}\Version`. Reverting to a previous GPO state requires restoring from a `Backup-GPO -Path <path>` archive (which produces a `{<guid>}\GPO.xml` + `GPO_Backup.ini` snapshot) via `Restore-GPO -BackupId <guid>`. There is no Git-style history, no diff between versions, no per-setting change log.

Change management is manual: admins must run `Backup-GPO -All -Path \\backup\GPO-Backups\$(Get-Date)` on a schedule and trust the backup. There is no built-in audit trail of "who changed what when" beyond the AD object's `LastOriginatingChange` and the Group Policy Operational log (which is per-host, not per-GPO). The GPMC UI shows the current state only; comparing two versions requires exporting both and diffing with a third-party tool, per [PC-056](../catalog/04-policy-engine.md).

For the framework, Git-backed policies with full history and PR-based review are a baseline expectation. Atomic rollback (per ADR-025) and per-setting attribution (per PC-044) require versioning as a foundation. Auto-tag on apply (so a "known-good" version is always recoverable) and per-policy TTL for change windows are additional features. The framework must support policy version history (Git-style or equivalent), atomic rollback to any prior version, and for AD interop must emit `versionNumber` increments on each change.

Cross-platform considerations: Windows `Backup-GPO`/`Restore-GPO` has no built-in version history; macOS MDM profiles have no version history (MDM servers like Jamf keep revision history per-profile); Linux SSSD/Samba have no policy version history. Ansible/Puppet/Salt provide versioning for their own configs but not for GPO consumption. Git-backed policies with cross-platform client support is the unified path, per [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

## Decision

The framework shall store policy history in a Git repository with PR-based review, auto-tag each applied version, and provide CLI/UI revert to any tagged version.

1. **Git repository as source of truth** — all framework policies are stored in a Git repository (the "policy repo"). The repo contains one `.policy.json` file per policy (per ADR-029) plus `roleBinding` objects (per ADR-030) and `role` definitions. The repo structure: `policies/<policy-name>.policy.json`, `roles/<role-name>.json`, `roleBindings/<binding-name>.json`.
2. **PR-based review** — every policy change is a pull request (PR) to the policy repo. The framework's CI/CD pipeline validates each PR: schema validation (per ADR-029), target validation (roles exist, facts are valid), and per-policy diff. PRs require at least one reviewer approval before merge. Direct commits to the main branch are rejected by branch protection rules.
3. **Auto-tag on apply** — when a policy is merged to main and applied to clients, the framework's policy distribution service tags the repo with `applied/<policy-name>/<timestamp>-<git-sha>`. This produces a known-good tag for every applied version. Reverting to a prior version is `git checkout <tag>` followed by re-apply.
4. **Atomic rollback to any version** — the framework's `adrian-policy revert --policy <name> --to <tag>` CLI checks out the specified tag, re-applies the policy through the transactional apply path (per ADR-025), and tags the new apply. This is Git-style revert: the policy state is restored to the tagged version, and a new commit records the revert.
5. **Per-policy TTL** — each policy can declare `ttl_seconds` in its metadata (per ADR-029). When the TTL expires, the framework's policy distribution service automatically reverts the policy to the version before the TTL-bearing policy was applied. This supports change-window semantics ("apply this emergency policy for 4 hours, then revert"). The TTL revert is logged as an audit event.
6. **AD interop: `versionNumber` emission** — for legacy Windows hosts running `gpsvc.dll`, the framework's policy distribution service emits a GPC `versionNumber` derived from the Git commit timestamp: `versionNumber = (unix_timestamp << 32) | (commit_counter & 0xFFFFFFFF)`. This satisfies `gpsvc.dll`'s version-check logic without requiring the framework to track a separate counter.
7. **Audit trail** — the Git commit history is the audit trail: "who changed what when" is `git log`. The framework's audit log (per ADR-060) records policy apply events (which version was applied to which host when) for cross-reference with the Git history.
8. **Branching strategy** — the policy repo uses a `main` branch for production and `staging` branch for pre-production testing. Policies are merged to `staging`, applied to a test OU, validated, then merged to `main` for fleet-wide apply. This mirrors the standard GitOps workflow.

**Concrete specification**:

- The policy repo is hosted on the framework's Git provider (GitHub Enterprise, GitLab Self-Managed, or Gitea — all supported via standard Git protocol).
- Branch protection: `main` requires 1 reviewer approval, status checks pass (schema validation, target validation), and linear history (rebase merges only, no merge commits).
- The framework's CI/CD pipeline runs on PR open and PR update: `adrian-policy validate <file>` per changed file, `adrian-policy diff --base main --head PR` for the per-policy diff.
- The framework's policy distribution service watches the `main` branch (via Git webhook or polling); on new commits, it compiles each changed policy to per-platform formats (per ADR-029), publishes to the distribution endpoint, and tags the repo.
- The `adrian-policy revert --policy <name> --to <tag>` CLI: checks out the tag, creates a new branch `revert/<policy-name>-<timestamp>`, opens a PR with the revert, and (optionally) auto-merges if `--auto-merge` is passed.
- The `adrian-policy history --policy <name>` CLI shows the Git log for the policy file: commit SHA, author, date, message.
- The `adrian-policy diff --policy <name> --from <tag1> --to <tag2>` CLI shows the per-setting diff between two versions.
- Per-policy TTL: the framework's policy distribution service runs a TTL expiry watcher; on expiry, it auto-reverts and logs an audit event.

## Rationale

Three alternatives were considered.

**Alternative 1: Database-backed version history.** Store policy versions in a SQL database with a `versions` table. Rejected because databases do not provide native diff, branch, or PR review. The framework would have to build all of these from scratch. Git provides them for free, with mature tooling (GitHub, GitLab, Gitea) and broad operator familiarity.

**Alternative 2: Snapshot-based version history (like AD `Backup-GPO`).** Periodically snapshot the policy state to a backup location. Rejected because snapshots are not point-in-time per-change — they capture the state at snapshot time, not at every change. "What changed between snapshot 3 and snapshot 4?" requires diffing two snapshots, not a single `git log`. Snapshots also require manual scheduling and backup management; Git is automatic on every commit.

**Alternative 3: Object-store versioning (S3 versioning, GCS versioning).** Use S3's or GCS's built-in object versioning. Rejected because object-store versioning does not provide diff, branch, or PR review. It provides point-in-time recovery (restore a prior object version) but not change attribution (who changed what) or change review (PR approval before apply).

The decision aligns with industry practice: Kubernetes manifests are Git-backed (Argo CD, Flux); Terraform state is Git-backed; Ansible playbooks are Git-backed. GitOps is the dominant pattern for infrastructure-as-code versioning. The framework's Git-backed policy history is the same pattern.

Cost: ~4 person-weeks for the Git integration (webhook handling, CI/CD pipeline, auto-tagging, revert CLI), the TTL expiry watcher, and the history/diff CLIs.

## Consequences

**Positive**. Full policy history with per-change attribution — "who changed the LAPS policy last week?" is `git log policies/laps.policy.json`. Atomic rollback to any prior version via `adrian-policy revert`. PR-based review catches authoring errors before apply (combined with schema validation per ADR-029). Per-policy TTL supports change-window semantics without operator intervention. The Git history is the audit trail, replacing per-DC event log scraping.

**Negative**. Git adds operational dependencies: a Git provider (GitHub Enterprise, GitLab, Gitea), CI/CD runners, webhook delivery. The framework's policy distribution service must handle Git provider outages (fallback to last-applied state, alert on webhook delivery failure). The policy repo's main branch is a single point of failure — branch protection rules must prevent force-push and deletion.

**Neutral**. The GitOps workflow (staging → main) adds a step to policy deployment. Operators used to direct GPO editing in GPMC must adapt to PR-based review. The framework's UI provides a "create PR" button that opens a PR with the operator's changes, so the workflow is not raw Git.

**Implementation cost**. ~4 person-weeks for the Git integration, TTL watcher, and CLIs. The Git provider integration (webhook handling, CI/CD pipeline templates) is additional effort (~2 person-weeks per provider).

**Operational impact**. Operators open PRs for policy changes (via the UI or `git` CLI). Reviewers approve PRs. The framework's policy distribution service auto-applies merged PRs. Revert is a CLI call. The Git history is the primary audit trail for policy changes.

## Alternatives Considered

### Alternative A: Database-backed version history

Store policy versions in a SQL database with a `versions` table. Each commit creates a new row with the policy JSON, author, timestamp, and parent version ID.

Rejected because databases do not provide native diff, branch, or PR review. The framework would have to build all of these from scratch: a diff view (computing JSON diffs), a branching model (representing branches as rows with a `branch` column), a PR review workflow (representing PRs as rows with `status` and `reviewers` columns). Git provides all of these for free, with mature tooling (GitHub, GitLab, Gitea) and broad operator familiarity. Building a parallel version-control system in a database would be reinventing Git poorly.

### Alternative B: Snapshot-based version history (like AD `Backup-GPO`)

Periodically snapshot the policy state to a backup location. Each snapshot captures all policies as of the snapshot time. Revert restores a snapshot.

Rejected because snapshots are not point-in-time per-change — they capture the state at snapshot time, not at every change. "What changed between snapshot 3 and snapshot 4?" requires diffing two snapshots (potentially hundreds of policies), not a single `git log policies/laps.policy.json`. Snapshots also require manual scheduling and backup management (where to store, how long to retain, how to verify integrity); Git is automatic on every commit, with retention controlled by the repo's history (effectively infinite unless explicitly GC'd).

### Alternative C: Object-store versioning (S3 versioning, GCS versioning)

Use S3's or GCS's built-in object versioning. Each put to a policy object creates a new version; revert restores a prior version.

Rejected because object-store versioning does not provide diff, branch, or PR review. It provides point-in-time recovery (restore a prior object version) but not change attribution (who changed what — S3 versioning records the object version ID and timestamp, but not the author or change message) or change review (PR approval before apply — S3 has no concept of review). Object-store versioning is also provider-specific (S3 vs. GCS vs. Azure Blob) and not portable; Git is universal.

## Open Questions

- Should the framework support multiple Git providers simultaneously (e.g., GitHub for production, Gitea for air-gapped)? Current decision: one provider per deployment; the provider is configurable at install time.
- The auto-tag format `applied/<policy-name>/<timestamp>-<git-sha>`: should it include the host or OU scope? Current decision: no — tags are per-policy, not per-host. Per-host apply state is in the audit log (per ADR-060).
- Per-policy TTL: should TTL reverts require PR review, or auto-merge? Current decision: auto-merge (the TTL is the operator's pre-approval). Revisit if operators report TTL reverts causing unexpected state changes.
- The `versionNumber` derivation from Git commit timestamp: does this satisfy `gpsvc.dll`'s monotonic-version requirement? Yes — `unix_timestamp << 32` is monotonically increasing as long as commits are not backdated. Git commit timestamps can be backdated via `git commit --date`, but the framework's CI/CD pipeline rejects commits with backdated timestamps.

## Cross-capability impact

- **Policy Engine (PC-056)**: This ADR. PC-048 (transactional apply, ADR-025) — Git-style revert uses the transactional apply path; the per-apply snapshot is the safety net for executor-level failures, Git revert is the operator-facing change-management tool.
- **Policy Engine (PC-052)**: ADR-029 (JSON canonical format) — canonical JSON is Git-diffable; the schema is validated on PR.
- **Operations (PC-106..PC-115)**: ADR-060 (audit logs) — Git history and apply audit events are cross-referenced.
- **Migration (PC-124..PC-130)**: ADR-055 (migration paths) — the migration tooling imports AD GPO backups into the policy repo as initial commits.
- **Security (PC-116..PC-123)**: ADR-067 (Sigstore + in-toto attestations) — policy commits can be signed via Sigstore; PR merges produce in-toto attestations for supply-chain security.

## References

- [PC-056](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md) — `versionNumber` packing, `Backup-GPO`/`Restore-GPO` workflow
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — `History\{CSE-GUID}\{GPO-GUID}\Version` cache
- [Pro Git book](https://git-scm.com/book/en/v2) — Git reference
- [Argo CD](https://argo-cd.readthedocs.io/) — industry precedent for GitOps
- [Flux CD](https://fluxcd.io/) — industry precedent for GitOps
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol (`versionNumber` reference)
