---
title: "ADR-093: SSSD GPO access-control enhancement — full Security area coverage via `adrian-sssd-gpo` (resolves PC-053)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-053
severity: high
unblocked_by: Workshop Decision 7
tags: [adr, policy-engine, sssd, gpo, access-control, logon-rights, ura, hbac, linux, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../workshop/decision-07-policy-format.md
  - ../workshop/decision-12-linux-tier.md
  - ../docs/09-linux-equivalents/03-sssd-gpo-access.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
  - ./ADR-050-authselect-standard-pam.md
  - ./ADR-092-policy-executor-trait-synthetic-windows-cse.md
last_updated: 2026-08-14
---

# ADR-093: SSSD GPO access-control enhancement — full Security area coverage via `adrian-sssd-gpo` (resolves PC-053)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 7](../workshop/decision-07-policy-format.md) (canonical JSON `Security` PolicyArea with `PermitLogonLocally`/`DenyLogonLocally`/`PermitLogonHours`/`PermitHosts`/`PermitGroups` settings) and [Workshop Decision 12](../workshop/decision-12-linux-tier.md) §2 (Rust-based SSSD GPO access-control enhancements via `adrian-sssd-gpo` library loaded as a new SSSD access provider). This ADR operationalises Decision 12 §2's `adrian-sssd-gpo` library specification against the PC-053 problem surface: SSSD's coverage of only the `[Privilege Rights]` logon-rights subset of GPO security policy, with AND-vs-OR semantics divergence from Windows.

## Context

SSSD's GPO access control is a partial re-implementation of the Windows Security CSE (`scecli.dll!SceProcessReturnedGPOs`). Per [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md), SSSD's `ad_gpo_access` module (in `src/providers/ad/ad_gpo.c` and `ad_gpo_child.c`) fetches `\\<sysvol>\<domain>\Policies\{<guid>}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` over SMB (libsmbclient, GSS-SPNEGO as the host machine account), parses only the `[Privilege Rights]` section, and maps the listed SIDs to the requesting PAM service. Supported rights: `SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight`, `SeNetworkLogonRight`, `SeBatchLogonRight`, `SeServiceLogonRight` (plus their `Deny` counterparts) — 10 rights out of the ~50 in Windows User Rights Assignment. The right-to-PAM-service mapping is hard-coded: `SeInteractiveLogonRight` → `login`, `su`, `sudo`; `SeRemoteInteractiveLogonRight` → `sshd`; `SeNetworkLogonRight` → Samba/SSH (overlapping with `SeRemoteInteractiveLogonRight`); `SeBatchLogonRight` → `crond`/`systemd-cron`; `SeServiceLogonRight` → `systemd` service accounts.

All other GPO areas are ignored on Linux: Account Policies (password, lockout, Kerberos), Administrative Templates (Registry.pol), Scripts, Preferences (Drive Maps, Files, etc.), Audit Policy, Restricted Groups, Software Install, AppLocker. Per the matrix in [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md), the only GPO area with SSSD support is User Rights Assignment logon rights.

The semantic mismatch runs deeper than coverage. SSSD's `ad_gpo_evaluate_gpo` applies **AND semantics** across GPOs — the user must be in the Allow list of *every* applicable GPO in the chain. Windows applies **OR semantics** — the user must be in the Allow list of *at least one* GPO that grants the right. The divergence is configurable via `ad_gpo_implicit_deny = false` (default): `NO_APPLICABLE_POLICY` ⇒ allow on Linux (matching Windows's permissive default); with `true`, ⇒ deny. With `ad_gpo_map_interactive = true` (default), the right-to-PAM-service mapping is applied; without it, all PAM services are treated as `SeInteractiveLogonRight`. The Linux default behavior diverges from Windows in subtle ways that produce operational surprises.

Workshop Decision 12 §2 specifies the framework's answer: ship `adrian-sssd-gpo` — a Rust library that extends SSSD's GPO access-control to cover the full `Security` PolicyArea (per Decision 7's PolicyArea enum), loaded by SSSD via the `gpo_access_provider = adrian` configuration directive (a new SSSD access provider that the framework contributes upstream to SSSD). Decision 12 §6 specifies the URA-vs-HBAC model: URA is the default for SSSD-primary tier; HBAC is the default for FreeIPA alternative tier. This ADR defines the `adrian-sssd-gpo` library's API, the access-decision algorithm, the URA-vs-OR-semantics fix, and the FreeIPA HBAC sync.

## Decision

The framework ships `adrian-sssd-gpo` — a Rust library exposed to SSSD via a C ABI (`libadrian_sssd_gpo.so`) that implements a new SSSD access provider (`adrian`). The library replaces SSSD's `ad_gpo_access` for framework-managed hosts, covers the full `Security` PolicyArea (per Decision 7), fixes the AND-vs-OR semantics divergence (matching Windows's OR semantics), and integrates with the framework's Client SDK for real-time policy updates via WebSocket (per ADR-028) instead of SSSD's 90-minute background refresh.

### Concrete specification

1. **SSSD access provider registration.** The framework's `adrian-cli join` configures SSSD's `[domain/<domain>]` section with `access_provider = adrian` (a new value, distinct from SSSD's existing `access_provider = ad` and `access_provider = simple` values). The `adrian` access provider loads `libadrian_sssd_gpo.so` via `dlopen` at SSSD startup; the library implements SSSD's `be_access_handler_t` callback signature (matching SSSD's existing access-provider plugin ABI). The library is contributed upstream to SSSD (per Decision 12 §2) so that future SSSD releases ship the provider in-box; for current SSSD releases, the library is installed by the framework's host-enrollment installer.

2. **`adrian_access_check` API.** The library exposes the primary access-check function:
   ```c
   int adrian_access_check(
       const char *user,           // username (short name, not UPN)
       const char *host,           // host FQDN
       const char *pam_service,    // PAM service name (login, sshd, su, sudo, ...)
       const char *source_host,    // client source IP/hostname (for HostAccessControl)
       AdrianAccessDecision *out   // output: Allow, Deny, PermitWithLogonHours
   );
   ```
   The function returns 0 on success (the `out` decision is set) or a non-zero error code on failure (the library falls back to `Permit` on internal error, matching SSSD's fail-open default; operators can configure `adrian_fail_closed = true` for fail-closed behavior in high-security deployments). The function is called by SSSD's PAM stack during `pam_sm_acct_mgmt` (via the `adrian` access provider's `be_access_handler_t` callback).

3. **Policy fetch via Client SDK (not SSSD's GPO-over-SMB path).** The library does not use SSSD's existing `ad_gpo.c` GPO-fetch-over-SMB path. Instead, the library calls the framework's Client SDK (per Decision 11) to fetch the policy document via the WebSocket push (per ADR-028). This gives the library real-time policy updates (sub-second latency from policy commit to access-check enforcement) instead of SSSD's 90-minute background refresh. The library maintains an in-memory cache of the most-recent policy document; the cache is invalidated on every WebSocket push notification. On cache miss (e.g., during SSSD startup before the WebSocket connection is established), the library falls back to an HTTPS pull (per ADR-028's pull fallback) with a 5-second timeout; on timeout, the library returns the last-known-good cached decision (or `Deny` if no cache exists and `adrian_fail_closed = true`).

4. **URA enforcement (OR semantics, matching Windows).** The library evaluates the policy's `Security` area's User Rights Assignment settings against the user, host, and PAM service:
   - `PermitLogonLocally` / `DenyLogonLocally` → PAM services `login`, `su`, `sudo`, `gdm`, `lightdm`.
   - `PermitRemoteInteractiveLogon` / `DenyRemoteInteractiveLogon` → PAM services `sshd`, `vnc`, `xrdp`.
   - `PermitNetworkLogon` / `DenyNetworkLogon` → Samba, `vsftpd`, `nginx` (client-cert auth).
   - `PermitBatchLogon` / `DenyBatchLogon` → `crond`, `systemd-cron`, `atd`.
   - `PermitServiceLogon` / `DenyServiceLogon` → `systemd` service accounts (matched via the service's `User=` directive).
   
   The evaluation uses Windows's **OR semantics**: the user is allowed if they appear in the `Permit*` list of *any* applicable GPO in the LSDOU chain (per ADR-030's role-based binding). This fixes SSSD's AND-semantics divergence (per PC-053). The `Deny*` list is unioned across all GPOs in the chain (deny wins over allow, matching Windows). If no `Permit*` setting is present in any applicable GPO, the decision is `Allow` (matching Windows's permissive default); operators can configure `adrian_implicit_deny = true` for fail-closed behavior.

5. **`PermitLogonHours` enforcement.** The framework's `Security` area's `PermitLogonHours` setting (a per-day-of-week per-hour bitmap, matching AD's `LogonHours` attribute syntax) is enforced by the library. The library checks the current time (in the host's timezone) against the bitmap; if the current time is outside the permitted hours, the decision is `Deny` with a `LogonHours` reason. This replaces SSSD's lack of logon-hours support (SSSD does not parse the `LogonHours` attribute at all).

6. **`PermitHosts` enforcement (HAC — Host Access Control).** The framework's `Security` area's `PermitHosts` setting (a list of host FQDNs or host patterns like `*.corp.example.com`) is enforced by the library. The library checks the request's `host` parameter (the host the user is logging into) against the `PermitHosts` list; if the host is not in the list, the decision is `Deny` with a `HostAccessControl` reason. This replaces SSSD's lack of host-based access control (other than via `simple` access provider's `simple_allow_hosts`, which does not integrate with GPO).

7. **`PermitGroups` enforcement.** The framework's `Security` area's `PermitGroups` setting (a list of group UUIDs/SIDs) is enforced by the library. The library queries the framework's directory for the user's group memberships (via the Client SDK's directory-query API) and checks if any of the user's groups are in the `PermitGroups` list; if not, the decision is `Deny` with a `GroupAccessControl` reason. This replaces SSSD's `simple_allow_groups` (which is a separate access provider, not integrated with GPO).

8. **PAM-service-to-URA mapping (configurable).** The library's PAM-service-to-URA mapping (per §4) is configurable via `/etc/sssd/sssd.conf`:
   ```ini
   [domain/<domain>]
   access_provider = adrian
   adrian_pam_map_interactive = login,su,sudo,gdm,lightdm
   adrian_pam_map_remote = sshd,vnc,xrdp
   adrian_pam_map_network = smbd,vsftpd,nginx
   adrian_pam_map_batch = crond,systemd-cron,atd
   adrian_pam_map_service = systemd
   adrian_fail_closed = false
   adrian_implicit_deny = false
   ```
   This replaces SSSD's hard-coded `ad_gpo_map_*` options with operator-configurable mappings, addressing a long-standing SSSD operational pain point (operators had to rebuild SSSD from source to change the mapping).

9. **FreeIPA HBAC sync.** Per Decision 12 §6, when a customer deploys FreeIPA alongside the framework, FreeIPA's HBAC rules apply to FreeIPA-managed Linux hosts. The framework's `adrian-cli trust sync-hbac` command syncs the framework's `Security` area's `PermitHosts` and `PermitGroups` settings to FreeIPA's HBAC rules. The sync is one-way (framework → FreeIPA); FreeIPA's HBAC rules are not synced back to the framework. The sync runs on every policy commit (via a Git post-receive hook in the framework's policy repository) and via a scheduled task (default hourly) to catch FreeIPA-side rule changes that need to be re-synced.

10. **Audit logging.** The library logs every access-check decision to the framework's audit log (per ADR-060) via the Client SDK's audit-event API. The log entry includes: the user, host, PAM service, source host, the evaluated policy document version, the decision (`Allow`/`Deny`/`PermitWithLogonHours`), the decision reason (which setting caused the `Deny`, if applicable), and the per-GPO evaluation trace (which GPOs granted/denied the right). The log entry is sent via OpenTelemetry to the framework's audit pipeline.

## Rationale

Three alternatives were considered.

**Alternative A: Extend SSSD's `ad_gpo.c` upstream (patch SSSD directly).** Contribute patches to SSSD upstream that extend `ad_gpo.c` to cover the full `Security` area and fix the AND-vs-OR semantics. Rejected because (a) SSSD's `ad_gpo.c` is ~3K lines of C tightly coupled to SSSD's internal data providers (`be_ctx`, `sdap_id_op`, `ad_id_ctx`); extending it to cover the full `Security` area requires ~2K additional lines of C, all of which must match SSSD's coding conventions, threading model, and memory-management patterns (talloc-based, not malloc/free); (b) the SSSD upstream review cycle is slow (months per patch) and the framework cannot ship fixes on its own cadence; (c) SSSD's GPO-fetch-over-SMB path is fundamentally limited by SMB latency and 90-minute background refresh — real-time policy updates require the framework's WebSocket push, which SSSD's architecture does not support without a major rewrite; (d) the framework's `Security` area (per Decision 7) includes `PermitHosts`, `PermitGroups`, and `PermitLogonHours` settings that have no analogue in SSSD's `ad_gpo.c`; adding them upstream is a multi-quarter project. Decision 12 §2 selects a new Rust-based access provider instead.

**Alternative B: Drop SSSD's `ad_gpo_access` entirely; use the framework's Client SDK PAM module (`pam_adrian.so`) for access control.** Replace SSSD's access-provider stack with the framework's PAM module; SSSD handles only authentication and identity (NSS), not access control. Rejected because (a) per Decision 12 §Rationale Candidate B, SSSD is the de facto standard for Linux-AD integration with a large operator community; forcing operators to use the framework's PAM module exclusively is a non-starter for adoption; (b) SSSD's access provider is integrated with SSSD's PAM stack in ways that the framework's PAM module would need to replicate (e.g., SSSD's `pam_sss.so` calls the access provider during `pam_sm_acct_mgmt`, with the user's Kerberos credentials available for group-membership queries via the KCM cache); (c) operators who want the framework-native experience can use `pam_adrian.so` directly (per Decision 11); the framework does not need to force them on customers who prefer SSSD. Decision 12 §1 selects SSSD as the primary Linux tier with the framework's PAM module as an alternative.

**Alternative C: Adopt FreeIPA HBAC as the framework's primary access-control model; map URA to HBAC at compile time.** Use FreeIPA's HBAC (Host-Based Access Control) as the framework's access-control primitive; the policy compiler translates URA settings to HBAC rules at distribution time. Rejected because (a) HBAC is rule-driven (defined centrally, evaluated per-host), while URA is policy-driven (defined per-GPO, applied to all hosts in the OU) — the two models have different semantics (HBAC is per-host-per-user-per-service; URA is per-user-per-right across all hosts in scope); (b) mapping URA to HBAC loses the LSDOU precedence model (per ADR-030); HBAC has no notion of GPO precedence; (c) FreeIPA HBAC requires a FreeIPA server (the framework's directory is not FreeIPA); requiring FreeIPA alongside the framework contradicts Decision 12 §1 (SSSD primary, FreeIPA alternative). Decision 12 §6 supports both URA and HBAC, with URA as the default for SSSD-primary tier and HBAC as the default for FreeIPA alternative tier (with cross-sync via `adrian-cli trust sync-hbac`).

The chosen model — `adrian-sssd-gpo` Rust library loaded as a new SSSD access provider, with OR-semantics URA evaluation and real-time WebSocket policy fetch — gives the framework: (a) full `Security` area coverage on Linux (replacing SSSD's 1/50th-of-Windows coverage); (b) OR semantics matching Windows (fixing the AND-vs-OR divergence); (c) real-time policy enforcement (replacing SSSD's 90-minute refresh); (d) SSSD compatibility (operators keep SSSD's PAM stack and NSS, with the framework's access provider as a drop-in replacement).

## Consequences

**Positive**. Linux hosts now enforce the full `Security` PolicyArea (URA + LogonHours + HAC + GroupAC) with Windows-matching OR semantics. Policy changes propagate to Linux hosts in sub-second latency (via WebSocket push), replacing SSSD's 90-minute background refresh. Operators configure PAM-service-to-URA mappings via `sssd.conf` instead of rebuilding SSSD from source. The framework's audit log records every access-check decision with a per-GPO evaluation trace.

**Negative**. The `adrian-sssd-gpo` library must be maintained for compatibility with SSSD's access-provider ABI across SSSD releases (SSSD's ABI is not formally versioned; minor SSSD releases can break the access-provider interface). The library is a Rust binary loaded by a C SSSD process — the FFI boundary is a maintenance burden (the framework's CI tests the library against SSSD 2.7, 2.8, 2.9 on each release). The WebSocket push dependency means that if the framework's policy distribution service is unreachable, the library falls back to the last-known-good cached decision — operators must monitor the WebSocket connection health.

**Neutral**. SSSD's existing `ad_gpo_access` is not removed; operators who prefer the existing behavior can keep `access_provider = ad`. The framework's `adrian-cli join` defaults to `access_provider = adrian`; operators can override. The library is contributed upstream to SSSD (per Decision 12 §2) so that future SSSD releases ship the provider in-box.

**Implementation cost**. ~4 person-weeks for v1 (per Decision 12 §Implementation impact, subsumed in the SSSD integration line item): Rust library + C ABI (1.5 pw), URA evaluation + OR-semantics logic (1 pw), WebSocket integration via Client SDK (1 pw), SSSD ABI compatibility testing (0.5 pw). Ongoing maintenance: ~1 person-week per year for SSSD ABI compatibility.

**Operational impact**. Operators configure `access_provider = adrian` in `sssd.conf` (the framework's `adrian-cli join` does this automatically). The `adrian-policy access-check --user <name> --host <host> --service <svc>` CLI previews the access decision for a given user/host/service triple without invoking PAM. The framework's audit log records every access-check decision.

## Alternatives Considered

### Alternative A: Patch SSSD's `ad_gpo.c` upstream

Contribute patches to SSSD upstream that extend `ad_gpo.c` to cover the full `Security` area and fix the AND-vs-OR semantics.

Rejected as detailed in §Rationale: SSSD's `ad_gpo.c` is tightly coupled to SSSD internals; the SSSD upstream review cycle is slow; SSSD's GPO-fetch-over-SMB path is fundamentally limited by SMB latency and 90-minute refresh; the framework's `Security` area includes settings (`PermitHosts`, `PermitGroups`, `PermitLogonHours`) that have no analogue in SSSD.

### Alternative B: Drop SSSD's access provider; use `pam_adrian.so` exclusively

Replace SSSD's access-provider stack with the framework's PAM module; SSSD handles only authentication and identity (NSS), not access control.

Rejected as detailed in §Rationale and Decision 12 §Rationale Candidate B: SSSD is the de facto standard; forcing operators to use the framework's PAM module is a non-starter; SSSD's access provider is integrated with SSSD's PAM stack in ways that `pam_adrian.so` would need to replicate; operators who want the framework-native experience can use `pam_adrian.so` directly (per Decision 11).

### Alternative C: Adopt FreeIPA HBAC as primary; map URA to HBAC at compile time

Use FreeIPA's HBAC as the framework's access-control primitive; the policy compiler translates URA settings to HBAC rules.

Rejected as detailed in §Rationale and Decision 12 §6: HBAC is rule-driven (per-host-per-user-per-service) while URA is policy-driven (per-user-per-right across all hosts in scope); mapping URA to HBAC loses the LSDOU precedence model; FreeIPA HBAC requires a FreeIPA server (contradicting Decision 12 §1's SSSD-primary tier). The chosen model supports both URA and HBAC with cross-sync.

## Open Questions

- **Cache invalidation on policy version change.** The library's in-memory policy cache is invalidated on every WebSocket push. For deployments with high policy-commit frequency (e.g., a CI-driven policy pipeline), the cache invalidation may cause excessive re-evaluation. Current decision: the cache is invalidated but the access-check logic is fast (microseconds); re-evaluation is not a performance concern. Revisit if profiling shows otherwise.
- **SSSD ABI compatibility matrix.** The library is tested against SSSD 2.7, 2.8, 2.9 in CI. SSSD 2.10+ may introduce ABI changes; the framework's CI is extended to test against new SSSD releases within 30 days of upstream release. Revisit if a SSSD release breaks the ABI in a way that requires a major library rewrite.
- **`PermitLogonHours` timezone handling.** The `LogonHours` bitmap is per-day-of-week per-hour in the user's timezone. The library uses the host's timezone (assuming the user is logging into the host's timezone). For remote logon (e.g., SSH from a different timezone), this may produce unexpected results. Current decision: the host's timezone is authoritative (matching Windows's behavior); revisit if customers report timezone-related access surprises.

## Cross-capability impact

- **Policy Engine (PC-044 LSDOU conflict resolution)**: The library's URA evaluation uses ADR-030's role-based binding for LSDOU precedence; the OR-semantics evaluation is layered on top of the per-GPO precedence.
- **Policy Engine (PC-046 ADMX schema)**: ADMX-driven `Security` area settings (via `admx2adrian`, per ADR-090) are consumed by the library.
- **Policy Engine (PC-047 CSE model)**: The library replaces SSSD's `ad_gpo.c` Security CSE subset; on framework-SDK-native Linux hosts (per Decision 11), the framework's `adrian-policy-daemon` (per ADR-092) enforces the same `Security` area.
- **Client SDK (Decision 11)**: The library calls the Client SDK for policy fetch and directory queries.
- **Cross-Platform Parity (PC-099 Linux access-control parity)**: This ADR closes the PC-099 gap by providing full `Security` area coverage on Linux.
- **Migration (PC-127 GPO-to-framework)**: The library's URA evaluation is backward-compatible with existing GPO `[Privilege Rights]` settings; customers migrating from AD can keep their existing URA policies unchanged.

## References

- [PC-053](../catalog/04-policy-engine.md) — problem statement in the catalog
- [Workshop Decision 7](../workshop/decision-07-policy-format.md) — canonical JSON `Security` PolicyArea with `PermitLogonLocally`/`PermitLogonHours`/`PermitHosts`/`PermitGroups` settings
- [Workshop Decision 12](../workshop/decision-12-linux-tier.md) §2 — `adrian-sssd-gpo` library specification; §6 — URA vs HBAC model
- [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md) — SSSD `ad_gpo.c` architecture, `GptTmpl.inf` parsing, AND-vs-OR semantics, `ad_gpo_implicit_deny` default
- [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — GPO area × platform coverage matrix
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution (WebSocket)
- [ADR-030](./ADR-030-role-based-policy-binding.md) — role-based policy binding (LSDOU + per-setting precedence)
- [ADR-050](./ADR-050-authselect-standard-pam.md) — authselect standard PAM (the framework's PAM stack)
- [ADR-092](./ADR-092-policy-executor-trait-synthetic-windows-cse.md) — `PolicyExecutor` trait (the framework's `Security` executor on SDK-native Linux hosts)
- [SSSD `ad_gpo.c` source](https://github.com/SSSD/sssd/blob/master/src/providers/ad/ad_gpo.c) — SSSD GPO access-control implementation
