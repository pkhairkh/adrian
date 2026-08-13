---
title: "ADR-122: DCSync Mitigation — Per-Principal Replication-Get-Changes Audit + HSM-Bound Break-Glass"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-117
severity: blocker
tags: [adr, security, dcsync, drsuapi, exop-repl-secrets, audit, hsm, tier-0, mitre-t1003-006]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ../docs/11-code-examples/05-python-impacket-examples.md
  - ../workshop/decision-01-replication-protocol.md
  - ./ADR-060-structured-audit-logs-otel.md
last_updated: 2026-08-13
---

# ADR-122: DCSync Mitigation — Per-Principal Replication-Get-Changes Audit + HSM-Bound Break-Glass

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 1 (replication)](../workshop/decision-01-replication-protocol.md) which adopted hybrid DRSUAPI + Raft. In native Raft mode, DCSync is *eliminated* (no `EXOP_REPL_SECRETS`); in AD-interop mode, DCSync attack surface is inherited from AD with framework-side mitigations specified here.

## Context

DRSUAPI `DRSGetNCChanges` (opnum 3 on interface `E3514235-8B63-11D0-A26C-00A0C92B955C`) is the workhorse of AD replication. The destination DC issues it to a source DC, providing the NC head DN, the UTD vector, and the high-watermark. The source replies with a `REPLENTINLIST` chain of object updates per the wire format documented in [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) and [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md). The `ulExtendedOp` field on the request can be set to `EXOP_REPL_SECRETS` (0x1) which instructs the source to include the secret attributes (`unicodePwd`, `ntPwdHistory`, `supplementalCredentials`, `lmPwdHistory`) on the returned objects. This is how password hashes replicate between DCs.

The attack, dubbed "DCSync" and disclosed in 2015: any principal holding the `DS-Replication-Get-Changes` (GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) and `DS-Replication-Get-Changes-All` (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) extended rights on the domain NC head can call `DRSGetNCChanges` with `EXOP_REPL_SECRETS` and pull the password hashes for every user in the domain. By default, these rights are granted to Domain Admins, Enterprise Admins, and the DC machine accounts. Per the threat notes in [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md), DCSync is "full domain compromise by any Domain Admin" — and any principal granted the extended rights is functionally a Domain Admin.

`secretsdump.py -just-dc corp.example.com/jsmith:'P@ss!'@dc01.corp.example.com` (impacket, per [`11-code-examples/05-python-impacket-examples.md`](../docs/11-code-examples/05-python-impacket-examples.md)) implements the full attack: `DRSBind`, `DRSCrackNames` to resolve the domain NC head DN, `DRSGetNCChanges` with `EXOP_REPL_SECRETS` and `cMaxObjects = 1000` per page, iterate through the entire Domain NC, extract `unicodePwd` (NTLM hash), `supplementalCredentials` (Kerberos AES keys), `lmPwdHistory`/`ntPwdHistory`. Total extraction time for a 100k-user domain: 5–30 minutes. Result: every password hash offline-crackable.

Workshop Decision 1 adopted hybrid replication: DRSUAPI (fresh Rust) for AD-interop mode and Raft for native mode. In native mode, there is no `EXOP_REPL_SECRETS` (Raft replicates everything via log append) — but Raft replication is encrypted at the transport layer (mTLS between peers), and the framework's FDB storage layer (per Decision 2) encrypts secrets at rest with an HSM-bound PEK (per Decision 6). The DCSync *wire* attack is eliminated in native mode. In AD-interop mode, the framework must accept `EXOP_REPL_SECRETS` calls from AD DCs (otherwise interop breaks); the DCSync attack surface is inherited.

## Threat model

**STRIDE classification**: Information disclosure, Elevation of privilege (MITRE ATT&CK T1003.006 — OS Credential Dumping: DCSync)

**Attack vector** (step-by-step):

1. Attacker obtains Domain Admin credentials (via Kerberoasting ADR-064, phishing a DA, or Pass-the-Hash on a DA session).
2. Attacker runs `secretsdump.py -just-dc corp.example.com/jsmith:'P@ss!'@dc01.corp.example.com` from any host that can reach TCP/135 + dynamic RPC ports on the DC.
3. impacket calls `DRSBind` to establish a DRSUAPI session, exchanging `DRS_EXTENSIONS` capability flags (requesting `DRS_EXT_GETCHG_DEFLATE`, `DRS_EXT_GETCHGREQ_V8`, `DRS_EXT_STRONG_ENCRYPTION`).
4. impacket calls `DRSCrackNames` to resolve `DC=corp,DC=example,DC=com` to a `DSNAME` structure.
5. impacket calls `DRSGetNCChanges` with `ulExtendedOp = EXOP_REPL_SECRETS` (0x1), `cMaxObjects = 1000`, providing an empty UTD vector to force a full sync.
6. The DC responds with `REPLENTIN` entries for every user, computer, and trust account. Secret attributes (`unicodePwd`, `supplementalCredentials`) are populated.
7. impacket extracts and prints hashes ready for `hashcat -m 1000` (NTLM) or `-m 13100` (RC4-HMAC TGS using the krbtgt account).
8. Attacker pivots: `krbtgt` hash to forge golden tickets (PC-118); individual user hashes for Pass-the-Hash; `machine$` hashes for lateral movement.

**Known mitigations in AD**: enable Event 4662 on every DC; SIEM rule for non-DC caller with `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` GUID; remove `DS-Replication-Get-Changes-All` from non-DC principals; Tier-0 administration model (DAs only on PAWs); Microsoft Defender for Identity (MDI) detects DCSync via network behaviour.

**Residual risk in AD**: 4662 events are noisy (every legitimate replication produces one); SIEM rules require careful tuning; non-DC principals with the extended right are not audited by default; MDI is a separate licensed product. Native-mode DCSync (via `EXOP_REPL_SECRETS` to a non-DC caller) is undetectable without explicit 4662 auditing.

## Decision

The framework's DCSync mitigation is **mode-dependent**:

**Native Raft mode (DCSync eliminated at the wire)**:
- No `EXOP_REPL_SECRETS` opnum exists in `RaftReplicator`'s protocol; secrets replicate via Raft log entries (encrypted with mTLS between peers per Decision 1).
- No principal can request "all secrets" via a single RPC; secrets are replicated only as part of the normal Raft log append, which is a leader-to-follower push, not a follower-to-leader pull.
- The framework's audit pipeline (per ADR-060) emits an event for every Raft log entry that includes a secret attribute (`unicodePwd`, `ntPwdHistory`, `supplementalCredentials`, `lmPwdHistory`), with attributes `adrian.repl.entry_type`, `adrian.repl.secret_attrs`, `adrian.repl.leader`, `adrian.repl.follower`. SIEM rules alert on follower-to-leader reverse-fetch patterns (which should never occur in Raft).
- The framework's FDB storage (per Decision 2) encrypts secrets at rest with an HSM-bound PEK (per Decision 6); even a full FDB dump does not reveal plaintext secrets.

**AD-interop mode (DCSync attack surface inherited, framework adds mitigations)**:
- `DrSuapiReplicator` (per Decision 1) implements `EXOP_REPL_SECRETS` for AD-interop compatibility — AD DCs need this to replicate secrets from the framework.
- The framework enforces AD-equivalent ACL checks on `DRSGetNCChanges` with `EXOP_REPL_SECRETS`: the caller must hold `DS-Replication-Get-Changes` (GUID `1131f6aa-...`) AND `DS-Replication-Get-Changes-All` (GUID `1131f6ad-...`) on the domain NC head. This matches AD behaviour so DCSync tooling works (impacket, mimikatz) for legitimate migration scenarios.
- The framework's audit pipeline (per ADR-060) emits an event for *every* `DRSGetNCChanges` call with `EXOP_REPL_SECRETS`, with attributes `adrian.drsuapi.caller_sid`, `adrian.drsuapi.caller_dn`, `adrian.drsuapi.caller_is_dc` (boolean: is the caller a registered `nTDSDSA` object's machine account?), `adrian.drsuapi.nc_head`, `adrian.drsuapi.objects_returned`, `adrian.drsuapi.secrets_returned`, `adrian.drsuapi.source_ip`. This maps to Windows Event 4662 with `Properties: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`.
- The framework ships default SIEM rules (in the audit pipeline): (a) alert severity "critical" on any `EXOP_REPL_SECRETS` call where `caller_is_dc = false` (non-DC caller pulling secrets — the DCSync smoking gun); (b) alert severity "high" on `EXOP_REPL_SECRETS` calls where `objects_returned > 1000` (full-NC pull — even from a legitimate DC, this is suspicious); (c) alert severity "medium" on `EXOP_REPL_SECRETS` calls outside the framework's known replication schedule (off-hours secret pulls warrant investigation).
- The framework restricts `DS-Replication-Get-Changes-All` to DC machine accounts by default. The framework's directory security post-deployment script removes the right from any non-DC principal that has it (matching Microsoft's Tier-0 recommendation). The framework's `adrian-cli perms audit --right ds-replication-get-changes-all` lists all principals with the right; the framework's `adrian-cli perms revoke --right ds-replication-get-changes-all --principal <dn>` revokes it.
- The framework supports an **HSM-bound break-glass replication** mode for disaster-recovery scenarios where the framework's normal replication is broken and a one-time secret extraction is needed (e.g. to seed a new DC from a partner). The break-glass operation requires: (a) an HSM-touch quorum (M-of-N administrators physically present at the HSM, per ADR-065's HSM model); (b) a time-limited single-use token signed by the HSM; (c) the framework's audit pipeline emits a "break-glass DRSync" event with severity "critical" and the HSM quorum's administrator identities. The break-glass token is valid for 5 minutes (configurable); after expiry, the token is revoked and the audit log records the revocation.

**Concrete specification**:

- In native mode, the framework MUST NOT implement `EXOP_REPL_SECRETS`; secrets replicate via Raft log entries only.
- In AD-interop mode, the framework's `DrSuapiReplicator` MUST implement `EXOP_REPL_SECRETS` (opnum 3 with `ulExtendedOp = 0x1`) and MUST enforce the AD-equivalent ACL check (`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`).
- The framework's audit pipeline MUST emit an OTel log record for every `DRSGetNCChanges` call with `EXOP_REPL_SECRETS`, with the attributes listed above and MITRE ATT&CK T1003.006 tag.
- The framework's audit pipeline MUST ship default detection rules:
  - Rule 1: `EXOP_REPL_SECRETS` call with `caller_is_dc = false` → severity "critical", MITRE T1003.006.
  - Rule 2: `EXOP_REPL_SECRETS` call with `objects_returned > 1000` → severity "high".
  - Rule 3: `EXOP_REPL_SECRETS` call outside `[monday 02:00, monday 06:00]` replication window (configurable) → severity "medium".
- The framework MUST expose `adrian-cli perms audit --right ds-replication-get-changes-all` returning every principal with the right and whether the principal is a DC machine account.
- The framework MUST support `adrian-cli perms revoke --right ds-replication-get-changes-all --principal <dn>` for non-DC principal revocation.
- The framework MUST support HSM-bound break-glass replication:
  - `adrian-cli drsync break-glass --target-dc <dn> --nc <nc-dn> --hsm-quorum <quorum-id>` initiates the break-glass flow.
  - The HSM quorum (per ADR-065) must approve; M-of-N administrators touch the HSM.
  - On approval, the framework issues a 5-minute single-use token signed by the HSM.
  - The framework's `DrSuapiReplicator` accepts the token in lieu of the ACL check; the call is audit-logged with severity "critical" and the quorum's administrator identities.
  - On expiry, the token is revoked; the audit log records the revocation.
- The framework MUST emit a Prometheus metric `adrian_dcsync_exop_repl_secrets_total{caller_is_dc,result}` (per ADR-057).
- The framework MUST ship a default Prometheus alert: `rate(adrian_dcsync_exop_repl_secrets_total{caller_is_dc="false"}[5m]) > 0` triggers critical.

## Rationale

Native mode eliminates DCSync at the wire by not implementing the opnum. This is the strongest possible mitigation — an attacker cannot call an RPC that does not exist. Raft's leader-follower push model means secrets flow only from leader to follower; a follower cannot "pull" secrets from the leader. The audit pipeline still emits per-entry events (for defence-in-depth) but the attack surface is structurally eliminated.

AD-interop mode inherits the attack surface because `EXOP_REPL_SECRETS` must be available for AD DCs to replicate. The framework's mitigations are: (a) per-call audit with full caller context (the AD-equivalent of Event 4662 with structured attributes); (b) default SIEM rules that surface the DCSync smoking gun (non-DC caller); (c) default ACL posture that restricts `DS-Replication-Get-Changes-All` to DC machine accounts; (d) HSM-bound break-glass for legitimate one-time secret extractions.

The HSM-bound break-glass is the operational innovation. AD has no equivalent — `secretsdump.py` runs with Domain Admin credentials and there is no audit trail beyond Event 4662. The framework's break-glass requires M-of-N administrators physically present at the HSM (matching ADR-065's krbtgt-rotation model), produces a single-use time-limited token, and emits a critical-severity audit event. The break-glass is for disaster-recovery scenarios (e.g. the framework's replication is broken and a one-time secret extraction is needed to seed a new DC); it is not for routine operations.

The default SIEM rules are tuned to balance false-positive rate and detection coverage. Rule 1 (non-DC caller) is the high-signal rule — legitimate DCSync is always DC-to-DC; a non-DC caller is the attack. Rule 2 (>1000 objects) catches full-NC pulls even from a compromised DC account (an attacker who has compromised a DC machine account still produces a >1000-object pull that warrants investigation). Rule 3 (off-hours) catches the attacker who waits for low-activity periods; the rule is "medium" because legitimate DR operations may occur off-hours.

The `adrian-cli perms audit` and `adrian-cli perms revoke` commands are the operational tools for the Tier-0 administration model. Microsoft's recommendation is to remove `DS-Replication-Get-Changes-All` from any non-DC principal; the framework's CLI automates the audit and revocation. The CLI is run weekly by the framework's operator (per ADR-058) and reports any non-DC principal that has accumulated the right (typically via delegation creep).

## Consequences

**Positive**: Native mode eliminates DCSync at the wire (no `EXOP_REPL_SECRETS` opnum). AD-interop mode has structured per-call audit, default SIEM rules, default ACL posture, and HSM-bound break-glass. The framework's audit pipeline surfaces the DCSync smoking gun (non-DC caller) with severity "critical". MITRE ATT&CK T1003.006 mapping is automatic.

**Negative**: AD-interop mode inherits the DCSync attack surface (the framework must accept `EXOP_REPL_SECRETS` calls from AD DCs). The HSM-bound break-glass requires physical HSM access — air-gapped or remote-HSM deployments must plan for the M-of-N quorum model. The default SIEM rules require tuning for legitimate DR scenarios that produce >1000-object pulls (e.g. seeding a new DC from scratch).

**Neutral**: The framework's `EXOP_REPL_SECRETS` implementation is byte-compatible with AD's; impacket's `secretsdump.py` works unchanged against the framework (which is necessary for AD-interop migration scenarios where ADMT or similar tools use the same RPC).

**Implementation cost**: ~3 person-months for the audit-pipeline integration, the SIEM rules, the `adrian-cli perms audit/revoke` CLI, and the HSM-bound break-glass. Reuses Decision 1's `adrian-drsuapi`, ADR-065's HSM quorum model, and ADR-060's audit pipeline.

**Operational impact**: SOC analysts see DCSync events in their SIEM with MITRE T1003.006 tags. SREs use `adrian-cli perms audit` weekly to detect delegation creep. The HSM quorum model is exercised quarterly (per ADR-065's drill schedule).

## Alternatives Considered

**Alternative A: Drop `EXOP_REPL_SECRETS` entirely in AD-interop mode.** Refuse the opnum even for AD DCs; secrets replicate via LDAP `modify` on `unicodePwd` over TLS. Rejected because (a) AD DCs cannot replicate from the framework without `EXOP_REPL_SECRETS` (the opnum is the only AD-side mechanism for secret replication); (b) LDAP-based secret replication is non-standard and breaks `repadmin /syncall`; (c) ADMT, `secretsdump.py`, and other DRSUAPI-based tooling would fail.

**Alternative B: Per-principal `EXOP_REPL_SECRETS` ACL with default-deny.** Require an explicit per-principal ACL grant before any `DRSGetNCChanges` with `EXOP_REPL_SECRETS` is accepted, even from DC machine accounts. Rejected because (a) it breaks AD-interop (AD DCs expect DC machine accounts to have the right by default); (b) it adds operational burden (every new DC requires an ACL grant); (c) the framework's audit + SIEM rules already surface non-DC callers, which is the actual attack signal.

**Alternative C: Encrypt `unicodePwd` with a per-DC public key (only the target DC can decrypt).** Use the framework's HSM to encrypt each `unicodePwd` with the target DC's public key; the source DC sends ciphertext that only the target can decrypt. Rejected because (a) it breaks AD-interop (AD DCs expect `unicodePwd` in the standard PEK-encrypted format); (b) it requires per-DC key management that AD does not have; (c) the framework's FDB at-rest encryption (per Decision 6) already provides equivalent protection.

**Alternative D: Rate-limit `EXOP_REPL_SECRETS` calls.** Cap the rate of `EXOP_REPL_SECRETS` calls per caller per minute. Rejected because (a) it breaks legitimate full-NC replication (a new DC promotion pulls the entire NC in minutes); (b) it does not prevent the attack (an attacker simply waits out the rate limit); (c) the framework's audit + SIEM rules are a better signal than rate.

## Open Questions

None. Workshop Decision 1 resolved the replication-protocol ORQ-001/002 that gated this ADR. The DCSync mitigation model is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-001)**: Decision 1's `DrSuapiReplicator` implements `EXOP_REPL_SECRETS` for AD-interop; this ADR specifies the audit and ACL-posture mitigations.
- **Operations (PC-111)**: ADR-060 (audit logs) — DCSync audit events are part of the audit pipeline.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_dcsync_exop_repl_secrets_total` is a key metric.
- **Security (PC-118)**: ADR-065 (krbtgt HSM rotation) — the HSM quorum model is shared between DCSync break-glass and krbtgt rotation.
- **Security (PC-116)**: ADR-064 (Kerberoasting) — DCSync is the typical post-Kerberoast escalation; the audit pipeline detects both.
- **Security (PC-119)**: ADR-123 (silver ticket) — DCSync is the typical path to obtain a service-account hash for silver-ticket forgery; the audit pipeline detects both.
- **Migration (PC-127)**: ADR-129 (password hash migration) — uses the same `EXOP_REPL_SECRETS` mechanism legitimately; the audit pipeline distinguishes migration traffic (DC caller, scheduled window) from attack traffic (non-DC caller, off-hours).

## References

- [PC-117](../catalog/11-security-threat-model.md) — problem statement (DCSync; full domain compromise by any Domain Admin)
- [AD overview KB](../docs/00-overview/01-active-directory-overview.md) — DCSync threat-model note
- [DCERPC MS-DRSR KB](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI interface UUID, opnum table, `DRS_EXTENSIONS`, `DRS_MSG_GETCHGREQ_V11`, `ulExtendedOp`
- [Replication internals KB](../docs/03-directory-schema/05-replication-internals.md) — `EXOP_REPL_SECRETS` replication flow, UTD vector
- [Python impacket examples KB](../docs/11-code-examples/05-python-impacket-examples.md) — `secretsdump.py -just-dc` recipe
- [Workshop Decision 1 — Replication protocol](../workshop/decision-01-replication-protocol.md) — hybrid DRSUAPI + Raft; `DrSuapiReplicator` implements `EXOP_REPL_SECRETS`
- [Workshop Decision 2 — Storage engine](../workshop/decision-02-storage-engine.md) — FoundationDB at-rest encryption with HSM-bound PEK
- [Workshop Decision 6 — NTLM decision](../workshop/decision-06-ntlm-decision.md) — HSM-bound PEK model
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — DCSync Prometheus metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — DCSync audit events
- [ADR-065 — krbtgt HSM rotation](./ADR-065-krbtgt-hsm-rotation.md) — HSM quorum model reused for break-glass
- [MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — DRSUAPI protocol specification
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — `EXOP_REPL_SECRETS`, `DS-Replication-Get-Changes-All` extended right
- [MITRE ATT&CK T1003.006 — OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006/)
