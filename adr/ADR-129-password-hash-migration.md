---
title: "ADR-129: Password Hash Migration — Framework-Side Sync Agent with DRSUAPI Pull + LDAP Modify Push"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Migration
problem: PC-127
severity: high
tags: [adr, migration, password-hash, drsuapi, exop-repl-secrets, sync-agent, ldap-modify, admt-pes]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/12-migration-and-coexistence.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ../docs/11-code-examples/05-python-impacket-examples.md
  - ../workshop/decision-03-identity-model.md
  - ./ADR-122-dcsync-mitigation.md
  - ./ADR-126-sidhistory-migration.md
last_updated: 2026-08-13
---

# ADR-129: Password Hash Migration — Framework-Side Sync Agent with DRSUAPI Pull + LDAP Modify Push

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 3 (identity model)](../workshop/decision-03-identity-model.md) which chose UUID-primary + SID-as-attribute with password hashes stored on the principal object keyed by UUID. This ADR specifies the migration workflow that copies password hashes from AD to the framework during the coexistence window.

## Context

User password migration from AD to the framework has three options, each with tradeoffs:

(a) **sIDHistory + password copy via ADMT**: ADMT's Password Export Server (PES) runs on a source-domain DC, captures password hashes as they are set (via a `dll` hook into LSASS), and pushes them to the target domain. The target domain writes the hash into the user's `unicodePwd` and `supplementalCredentials` (Kerberos AES keys). This preserves both the SID (via sIDHistory, ADR-126) and the password — the user experiences no disruption. ADMT is Windows-only and was deprecated by Microsoft (last release 3.2, supports up to Server 2012 R2 source domains); many orgs still use it.

(b) **Password-sync agent**: Microsoft Identity Manager (MIM) or Entra Connect (Azure AD Connect) runs a sync agent that periodically pulls password hashes from AD (via DCSync-equivalent mechanism) and pushes them to a target directory. The target can be Azure AD, a third-party IdP, or (theoretically) the framework's directory. The sync agent uses a proprietary protocol (Microsoft's `PasswordHashSync` API for Azure AD Connect; MIM uses its own). For non-Microsoft targets, the framework would need to implement a sync-agent protocol or use a standard like LDAP `modify` on `unicodePwd` over TLS.

(c) **Require password reset on migration**: Users are migrated with a temporary password and forced to reset on first login to the framework. Simplest operationally but most disruptive — every user must reset their password on cutover day. For a 50,000-user org, the helpdesk load is enormous.

Per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) and [`11-code-examples/05-python-impacket-examples.md`](../docs/11-code-examples/05-python-impacket-examples.md), the underlying password-hash extraction mechanism is DRSUAPI `DRSGetNCChanges` with `EXOP_REPL_SECRETS` (the same mechanism `secretsdump.py` uses for attack per ADR-122). The migration use case is the same mechanism, used legitimately with audit logging.

Workshop Decision 3 chose UUID-primary + SID-as-attribute with password hashes stored on the principal object keyed by UUID. The framework's directory stores `unicodePwd` (NTLM hash, encrypted with the framework's HSM-bound PEK per Decision 6) and `supplementalCredentials` (Kerberos AES keys, similarly encrypted). This ADR specifies the migration workflow that copies password hashes from AD to the framework during the coexistence window.

## Decision

The framework's password hash migration workflow supports **all three options** with the framework's primary recommendation being **option (b) with a framework-side sync agent**. The framework's sync agent runs on a framework DC, binds to an AD DC via DRSUAPI with `EXOP_REPL_SECRETS` (per Decision 1's `DrSuapiReplicator` implementation), pulls the password hashes for a batch of users, and writes them to the framework's directory via LDAP `modify` on `unicodePwd` and `supplementalCredentials`. The agent runs on a schedule (default 15 minutes) during the migration coexistence period. After cutover, the agent is decommissioned.

The framework's sync agent is the operational innovation. AD-interop customers with existing ADMT workflows can continue to use ADMT (option a); the framework supports ADMT's PES protocol via the framework's `DRSAddSidHistory`-equivalent receive path. Customers without ADMT or who prefer the framework-native path use the framework's sync agent (option b). Customers who prefer the simplest path use option (c) with the framework's `must_change_password_at_next_login` flag.

## Migration state machine

**Source state**: AD with user accounts and password hashes in `unicodePwd` (NTLM hash) and `supplementalCredentials` (Kerberos AES keys). Password complexity policy in AD's `Default Domain Policy`.

**Target state**: Framework-native users with password hashes populated. Users can authenticate to the framework with their AD password (no reset required). Password complexity policy from AD preserved.

**Coexistence period**: 30–90 days. During this window:
- The framework's sync agent runs on a schedule (default 15 minutes), propagating password changes from AD to the framework. Users who change their AD password during this window have the new password automatically synced to the framework within 15 minutes.
- The sync agent binds to an AD DC via DRSUAPI with `EXOP_REPL_SECRETS` (per Decision 1's `DrSuapiReplicator`), pulls the password hashes for users in the migration batch, and writes them to the framework's directory via LDAP `modify` on `unicodePwd` and `supplementalCredentials`.
- The sync agent's DRSUAPI calls are audit-logged per ADR-122 (DCSync mitigation) — the framework's audit pipeline distinguishes sync-agent traffic (DC caller, scheduled window) from attack traffic (non-DC caller, off-hours).
- The framework's `adrian-cli migrate password-sync --status` command tracks per-user sync status: `synced` (hash copied), `pending` (hash not yet copied), `failed` (sync failed — typically because the user's password changed during the sync window and the agent needs to retry).
- The framework's audit pipeline emits an event for every sync-agent run with attributes `adrian.migration.password_sync.batch_id`, `adrian.migration.password_sync.users_synced`, `adrian.migration.password_sync.users_failed`, `adrian.migration.password_sync.source_dc`, `adrian.migration.password_sync.duration_ms`.

**Cutover trigger**: When 100% of users have been migrated (per ADR-128's per-user migration) and the sync agent has run with no new changes for ≥7 days (verified via `adrian-cli migrate password-sync --status --no-changes-days 7`), the agent is decommissioned (`adrian-cli migrate password-sync --decommission`) and AD password authority is revoked (the framework's directory is the sole password authority).

**Rollback path**: If migration fails, the framework's user accounts can be disabled. Users continue to authenticate via AD. The sync agent can be re-started if a re-migration is attempted. No data loss — AD remains the source of truth throughout. The framework's `adrian-cli migrate password-sync --rollback --user <framework-dn>` clears the framework user's password hash (forcing the user to authenticate via AD during the rollback window).

**Concrete specification**:

- The framework MUST ship a sync agent (`adrian-migrate-password-sync`) that runs on a framework DC, binds to an AD DC via DRSUAPI with `EXOP_REPL_SECRETS` (per Decision 1's `DrSuapiReplicator`), pulls the password hashes for users in the migration batch, and writes them to the framework's directory via LDAP `modify` on `unicodePwd` and `supplementalCredentials`.
- The sync agent MUST run on a configurable schedule (default 15 minutes) via the framework's operator (per ADR-058) — a `PasswordSyncJob` CRD with `spec.schedule`, `spec.batchSize` (default 1000 users), `spec.sourceDC` (AD DC DN), `spec.targetOU` (framework OU containing migrated users).
- The sync agent MUST preserve the password hash format byte-identically: `unicodePwd` is the NTLM hash (MD4 of UTF-16LE password, BER-encoded with `"` quotes per MS-SAMR); `supplementalCredentials` is the Kerberos AES keys (PBKDF2-HMAC-SHA1 4096 iterations per RFC 8009, packaged in the `PACKAGE` structure per MS-SAMR).
- The sync agent MUST preserve the password complexity policy from AD: the framework's `Default Domain Policy`-equivalent (per Decision 7's `Security` PolicyArea) is set to match the source AD's `Default Domain Policy` settings (min length, complexity, history, max age, min age).
- The sync agent MUST be audit-logged per ADR-122's DCSync-mitigation audit pipeline. The sync agent's DRSUAPI calls appear in the audit pipeline as `EXOP_REPL_SECRETS` calls with `caller_is_dc = true` (the sync agent runs as a framework DC machine account) and `objects_returned ≤ batchSize` (no full-NC pulls). ADR-122's Rule 1 (non-DC caller) does not fire; Rule 2 (>1000 objects) does not fire if `batchSize ≤ 1000`.
- The sync agent MUST NOT cache password hashes in plaintext — the hashes are written to the framework's directory immediately via LDAP `modify` and not retained in the agent's memory beyond the LDAP round-trip.
- The framework's directory MUST store password hashes encrypted with the framework's HSM-bound PEK (per Decision 6) — even if the sync agent is compromised, the hashes are not readable in plaintext from the agent's memory or from the FDB storage at rest.
- The framework MUST expose `adrian-cli migrate password-sync --status [--user <dn>]` returning per-user sync status: `synced` (hash copied, last-synced timestamp), `pending` (hash not yet copied), `failed` (sync failed, last-failure reason).
- The framework MUST expose `adrian-cli migrate password-sync --decommission` to gracefully shut down the sync agent after cutover. The command: (a) verifies no new changes for ≥7 days; (b) disables the sync agent's `PasswordSyncJob` CRD; (c) revokes the sync agent's DRSUAPI credentials; (d) emits an audit event (severity "medium") recording the decommission.
- The framework MUST expose `adrian-cli migrate password-sync --rollback --user <framework-dn>` to clear the framework user's password hash, forcing the user to authenticate via AD during the rollback window.
- The framework MUST support option (a) (ADMT PES protocol) via the framework's `DRSAddSidHistory`-equivalent receive path. Customers using ADMT can use ADMT's PES to push password hashes directly to the framework's directory via DRSUAPI; the framework's directory accepts the push and writes the hashes to the principal object.
- The framework MUST support option (c) (password reset on migration) via the framework's `must_change_password_at_next_login` flag (per Decision 3). The flag is set on the framework user at migration time; the user is prompted to reset on first login to the framework.
- The framework's audit pipeline MUST emit an OTel log record for every sync-agent run with the attributes listed above and MITRE T1003 (OS Credential Dumping) tag for SIEM correlation (password-hash extraction is a credential-dumping signal even when legitimate).
- The framework MUST emit a Prometheus metric `adrian_migration_password_sync_users_total{status}` (per ADR-057).
- The framework MUST ship a default Prometheus alert: `adrian_migration_password_sync_users_total{status="failed"} > 0 for 30m` triggers warning (sync failures may strand users).

## Rationale

Option (b) with the framework-side sync agent is the recommended path because it is (i) cross-platform (the sync agent runs on any framework DC, not just Windows); (ii) standard-protocol-based (DRSUAPI for pull, LDAP `modify` for push — both documented protocols); (iii) audit-logged (per ADR-122's DCSync mitigation); (iv) reversible (the sync agent can be re-started if migration fails). The sync agent is the framework's value-add — ADMT and MIM are Windows-only and use proprietary protocols; the framework's sync agent is open-source and uses standard protocols.

Option (a) (ADMT PES) is supported for AD-interop compatibility. Customers with existing ADMT workflows can continue to use ADMT; the framework's directory accepts ADMT's PES-pushed hashes via DRSUAPI. This is the migration path for customers who cannot deploy the framework's sync agent (e.g. air-gapped framework DCs that cannot reach AD DCs via DRSUAPI).

Option (c) (password reset on migration) is the simplest path and the fallback for customers who cannot use option (a) or (b). The framework's `must_change_password_at_next_login` flag is a standard LDAP attribute (`pwdLastSet = 0` in AD); the framework honours it.

The sync agent's 15-minute default schedule balances convergence (users who change their AD password see the new password in the framework within 15 minutes) and load (the sync agent pulls batches of 1000 users per run; a 50,000-user migration completes in ~50 runs = ~12.5 hours). For tighter convergence, the schedule can be reduced to 1 minute (the framework's audit pipeline distinguishes sync-agent traffic from attack traffic regardless of schedule).

The DRSUAPI-based pull is the same mechanism impacket's `secretsdump.py` uses for attack (per ADR-122). The framework's audit pipeline distinguishes sync-agent traffic (DC caller, scheduled window, batch size ≤1000) from attack traffic (non-DC caller, off-hours, full-NC pull). The sync agent runs as a framework DC machine account with the necessary `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights; ADR-122's `adrian-cli perms audit` surfaces this principal as a DC machine account (not flagged as suspicious).

Password hash format preservation is critical. The framework's directory stores `unicodePwd` and `supplementalCredentials` byte-identically to AD; users who authenticate to the framework with their AD password (via NTLM client per Decision 6 or via Kerberos cross-realm per ADR-128) see the same authentication result as in AD. The PBKDF2-HMAC-SHA1 4096-iteration Kerberos AES key derivation (per RFC 8009) is preserved exactly; users with AES-capable applications see no etype-negotiation change.

## Consequences

**Positive**: Three options (sync agent, ADMT PES, password reset) fit all migration scenarios. The sync agent is cross-platform and uses standard protocols. ADMT-interop is preserved. Password reset is the simplest fallback. Audit-logging per ADR-122 distinguishes sync-agent traffic from attack traffic. Password hash format is byte-identical to AD.

**Negative**: The sync agent runs as a framework DC machine account with `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights — a privileged principal. The framework's audit pipeline + SIEM rules detect abuse; the framework's `adrian-cli perms audit` surfaces the principal for review. The 15-minute default sync schedule means a user who changes their AD password and immediately authenticates to the framework may see the old password (the sync has not run yet); the framework's KDC falls back to AD via the cross-realm trust (per ADR-128) for the gap window.

**Neutral**: The sync agent is decommissioned after cutover; the framework's directory is the sole password authority. Customers who need ongoing password sync (e.g. for hybrid AD + framework deployment) can keep the sync agent running indefinitely.

**Implementation cost**: ~4 person-months for the sync agent, the `adrian-cli migrate password-sync` CLI, the audit pipeline integration, and the ADMT PES receive-path integration. Reuses Decision 1's `adrian-drsuapi`, Decision 3's `adrian-identity-fdb`, Decision 6's HSM-bound PEK, ADR-060's audit pipeline, ADR-122's DCSync mitigation.

**Operational impact**: Migration teams use `adrian-cli migrate password-sync` to start/stop/monitor the sync agent. SOC analysts monitor the audit pipeline for sync-agent traffic vs. attack traffic. SREs monitor `adrian_migration_password_sync_users_total{status="failed"}` for sync failures.

## Alternatives Considered

**Alternative A: ADMT PES only (no framework sync agent).** Require customers to use ADMT for password hash migration; the framework accepts ADMT-pushed hashes via DRSUAPI but does not provide a framework-side pull agent. Rejected because (a) ADMT is Windows-only and was deprecated by Microsoft (last release 3.2, supports up to Server 2012 R2 source domains); (b) customers without ADMT (or with source domains above Server 2012 R2) cannot migrate; (c) the framework's value proposition includes a framework-native migration path.

**Alternative B: Password reset on migration only (no hash copy).** Require all users to reset their password on cutover day; do not copy password hashes. Rejected because (a) for a 50,000-user org, the helpdesk load is 4,000–8,000 hours over a cutover week; (b) productivity loss is 1–2 days per user; (c) the framework's value proposition includes a non-disruptive migration.

**Alternative C: Plaintext password capture via LSASS hook (ADMT PES approach) only.** Implement an LSASS-equivalent hook on the framework's DC to capture plaintext passwords as users change them, then derive the NTLM hash and Kerberos AES keys from the plaintext. Rejected because (a) the framework's DCs do not run LSASS (the framework is fresh Rust per Decision 5); (b) plaintext password capture is a security-sensitive operation that the framework declines to implement; (c) the DRSUAPI-based sync agent achieves the same result without plaintext capture.

**Alternative D: Per-user on-demand sync (no scheduled agent).** Sync password hashes one user at a time on first authentication to the framework. Rejected because (a) the first-authentication latency would include a DRSUAPI round-trip to AD (5–20 seconds typical — unacceptable UX); (b) the sync would not catch password changes that occur while the user is not authenticating to the framework; (c) the scheduled sync agent provides better convergence and lower per-authentication latency.

## Open Questions

None. Workshop Decision 3 resolved the identity-model ORQ-026/027 that gated this ADR. The password hash migration workflow is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-001)**: Decision 1's `DrSuapiReplicator` implements `EXOP_REPL_SECRETS` for the sync agent's pull.
- **Core Directory (PC-010)**: Decision 3's `IdentityMapping` is the canonical reference for UUID-keyed principal objects; the sync agent writes hashes to the UUID-keyed row.
- **Auth Provider (PC-036/PC-038)**: Decision 6 (NTLM drop) — the framework's NT hash storage is HSM-PEK-encrypted; the sync agent's pulled hashes are written to the encrypted store.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_migration_password_sync_users_total` is the sync-progress metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — sync-agent run audit events.
- **Security (PC-117)**: ADR-122 (DCSync mitigation) — the sync agent's DRSUAPI calls are audit-logged per ADR-122; the audit pipeline distinguishes sync-agent traffic from attack traffic.
- **Migration (PC-124)**: ADR-126 (sIDHistory migration) — password hash migration is paired with sIDHistory migration in ADMT workflows; the framework's sync agent can run alongside the sIDHistory migration tool.
- **Migration (PC-126)**: ADR-128 (Kerberos cross-realm during migration) — per-user migration uses the sync agent for password copy.

## References

- [PC-127](../catalog/12-migration-and-coexistence.md) — problem statement (password hash migration requires either sIDHistory or password-sync agent)
- [Trusts topology KB](../docs/03-directory-schema/04-trusts-topology.md) — `trustAuthBlob` structure, cross-realm trust key, `DRSAddSidHistory` (opnum 20) dependency
- [Python impacket examples KB](../docs/11-code-examples/05-python-impacket-examples.md) — `secretsdump.py -just-dc` recipe demonstrating DRSUAPI-based password hash extraction (the same mechanism a sync agent uses, but for migration rather than attack)
- [Workshop Decision 1 — Replication protocol](../workshop/decision-01-replication-protocol.md) — `DrSuapiReplicator` implements `EXOP_REPL_SECRETS` for the sync agent's pull
- [Workshop Decision 3 — Identity model](../workshop/decision-03-identity-model.md) — UUID-primary; password hashes on principal object keyed by UUID
- [Workshop Decision 6 — NTLM decision](../workshop/decision-06-ntlm-decision.md) — HSM-PEK-encrypted NT hash storage
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — sync-progress metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — sync-agent run audit events
- [ADR-122 — DCSync mitigation](./ADR-122-dcsync-mitigation.md) — sync agent's DRSUAPI calls audit-logged; distinguished from attack traffic
- [ADR-126 — sIDHistory migration](./ADR-126-sidhistory-migration.md) — sIDHistory migration paired with password hash migration
- [ADR-128 — Kerberos cross-realm during migration](./ADR-128-kerberos-cross-realm-migration.md) — per-user migration uses the sync agent for password copy
- [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — `EXOP_REPL_SECRETS`, `DRSGetNCChanges`
- [MS-SAMR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/) — `unicodePwd`, `supplementalCredentials` attribute formats
- [RFC 8009 — AES Encryption for Kerberos 5](https://datatracker.ietf.org/doc/html/rfc8009) — PBKDF2-HMAC-SHA1 4096 iterations
- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [ADMT documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008/cc974335(v=ws.10)) — ADMT PES workflow
