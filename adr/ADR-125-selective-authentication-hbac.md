---
title: "ADR-125: Selective Authentication Replaced by HBAC-Equivalent Policy Rules + Per-Host Evaluation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-121
severity: medium
tags: [adr, security, selective-auth, hbac, allowed-to-authenticate, cross-forest, policy-driven, defense-in-depth]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ../docs/09-linux-equivalents/08-freeipa-trust.md
  - ../workshop/decision-12-linux-tier.md
  - ../workshop/decision-06-ntlm-decision.md
  - ./ADR-066-adminsdholder-declarative-rbac.md
last_updated: 2026-08-13
---

# ADR-125: Selective Authentication Replaced by HBAC-Equivalent Policy Rules + Per-Host Evaluation

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 12 (Linux tier)](../workshop/decision-12-linux-tier.md) which adopted SSSD-primary + FreeIPA-as-alternative and specified HBAC-equivalent rules as the framework's selective-authentication replacement. [Workshop Decision 6 (NTLM drop)](../workshop/decision-06-ntlm-decision.md) is a defence-in-depth complement: services that no longer accept NTLM reduce the cross-trust attack surface that selective authentication is designed to mitigate.

## Context

Cross-forest trust with the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION` flag (0x10) enables "selective authentication" mode. In this mode, users from the trusted forest cannot authenticate to any resource in the trusting forest unless explicitly granted the "Allowed to Authenticate" extended right (controlAccessRight GUID `68b1d179-0d15-4d4f-ab71-46152e79a7bc`) on the resource computer object per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md).

Without the ACE, a cross-trust user's TGS-REQ to the resource fails with `KRB_ERR_GENERIC` (or the SMB layer returns `STATUS_ACCESS_DENIED`). The resource server logs `LSA` event 4662 with `Accesses: Allowed to Authenticate` failed. The mechanism is sound — it provides per-resource access control across a forest trust, the most granular possible control.

The problem is operational: the ACE must be set on every resource computer object that should be accessible to the foreign user. For a 1000-server farm, that's 1000 ACE operations. For a dynamic environment where servers are added/removed daily, the ACEs are constantly out of sync. Most organisations either: (a) skip selective authentication entirely and use a full-trust model (which exposes all resources to all foreign users), or (b) deploy selective authentication and then over-grant the ACE to avoid the operational pain (defeating the purpose).

FreeIPA's HBAC (Host-Based Access Control) provides a more usable alternative: server-side evaluation of `(user, host, service)` triples against a rule set, with no per-resource ACE needed. The rule set is managed centrally. HBAC is evaluated by SSSD on each host at login time. A similar model could be applied to AD trusts: a central rule set replaces per-resource ACEs. Workshop Decision 12 chose SSSD-primary + FreeIPA-as-alternative for the Linux tier, with HBAC-equivalent rules as the framework's selective-authentication replacement.

Decision 6 (drop NTLM server-side) is a defence-in-depth complement. Selective authentication is partly a mitigation for the risk that a compromised foreign user can authenticate to any resource that accepts their credentials. By eliminating NTLM server-side (the easiest credential to relay/pass), the framework reduces the attack surface that selective authentication is designed to mitigate — services that no longer accept NTLM require Kerberos (with `PAC_BUFFER_TICKET_CHECKSUM` validation per ADR-123) for cross-trust access.

## Threat model

**STRIDE classification**: Elevation of privilege (cross-trust unauthorised access)

**Attack vector** (step-by-step):

1. Attacker compromises a foreign-forest user account (via phishing the foreign user, Kerberoasting in the foreign forest, or compromise of the foreign forest's DC).
2. The trusting forest has a full-trust model (selective authentication not deployed); any foreign user can authenticate to any resource in the trusting forest.
3. Attacker requests a cross-realm referral TGT to the trusting forest via the cross-forest trust.
4. Attacker requests a TGS for `cifs/file01.trusting.local` from the trusting forest's KDC; the KDC obliges (the user is authenticated via the cross-trust TGT).
5. Attacker connects to `\\file01\c$` via SMB using the cross-trust service ticket.
6. file01's SMB server decrypts the ticket, validates the PAC (per ADR-123), sees the foreign user's identity and group memberships (which may include high-privilege groups in the foreign forest — not in the trusting forest).
7. file01 grants access to `\\file01\c$` based on the foreign user's identity. If the trusting forest has any resource that grants access based on foreign-forest group membership (e.g. a share ACL referencing `FOREIGN\Domain Admins`), the attacker escalates.

**Known mitigations in AD**: selective authentication (`TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10`) with per-resource `Allowed to Authenticate` ACE; SID Filter Quarantine (per ADR-124); claims-based access control (Server 2012+); Microsoft Defender for Identity detects anomalous cross-trust access.

**Residual risk in AD**: selective authentication is rarely deployed due to operational pain; full-trust is the common deployment, exposing all resources to all foreign users. Per-resource ACEs are constantly out of sync in dynamic environments. Claims-based access control is rarely deployed. Compromise of a foreign user → access to all resources in the trusting forest.

## Decision

The framework replaces AD's per-resource `Allowed to Authenticate` ACE model with **HBAC-equivalent policy rules** evaluated at logon time on each resource host. The framework's `Security` PolicyArea (per Decision 7's canonical JSON policy format) defines `PermitHosts` and `PermitGroups` settings that control which users can authenticate to which hosts. The framework's `adrian-policy-daemon` (per Decision 7) evaluates the rules at logon time on each enrolled host; the framework's `adrian-sssd-gpo` library (per Decision 12) does the same on SSSD-primary Linux hosts; the framework's `adrian-cli trust sync-hbac` command syncs the framework-defined rules to FreeIPA's HBAC for FreeIPA-alternative deployments.

The framework preserves AD-interop compatibility by supporting the `Allowed to Authenticate` ACE for AD-managed resources. Framework-managed resources use the HBAC-equivalent model; AD-managed resources continue to use the per-resource ACE model. The two models coexist during the migration window.

**Concrete specification**:

- The framework's `Security` PolicyArea (per Decision 7's canonical JSON policy format) MUST define the following settings:
  - `PermitLogonLocally` (string_list of user/group SIDs permitted to log on locally; default `[]` = deny all, with the framework's bootstrap administrator excluded from the deny).
  - `DenyLogonLocally` (string_list; default `[]`).
  - `PermitLogonThroughNetwork` (string_list; controls SMB/SSH/HTTP network logon).
  - `DenyLogonThroughNetwork` (string_list).
  - `PermitHosts` (string_list of host FQDNs or host-group names that the rule applies to; default `["*"]` = all hosts).
  - `DenyHosts` (string_list).
  - `PermitServices` (string_list of service names — `login`, `ssh`, `smb`, `http`; default `["*"]` = all services).
  - `CrossTrustPermitForeignUsers` (string_list of foreign-forest user/group SIDs permitted to authenticate to the host; default `[]` = no foreign users).
- The framework's `adrian-policy-daemon` MUST evaluate the `Security` PolicyArea at logon time on each framework-SDK-native host. The evaluation: (a) resolve the logon user's SID and group SIDs via `IdentityMapping::lookup_sid` (per Decision 3); (b) check the user against `PermitLogonLocally`/`DenyLogonLocally` for local logon or `PermitLogonThroughNetwork`/`DenyLogonThroughNetwork` for network logon; (c) check the host against `PermitHosts`/`DenyHosts`; (d) check the service against `PermitServices`; (e) for foreign-forest users (SIDs not in the local forest's namespace), check against `CrossTrustPermitForeignUsers`. The daemon caches the evaluation result for 60 seconds (configurable) to avoid re-evaluating on every AP-REQ.
- The framework's `adrian-sssd-gpo` library MUST evaluate the same `Security` PolicyArea on SSSD-primary Linux hosts, integrating with SSSD's `simple_ifp` access-control hook. The library translates the framework's settings to SSSD's `ad_gpo_map` and `ad_access_filter` configuration.
- The framework's `adrian-cli trust sync-hbac` command MUST sync the framework's `Security` PolicyArea's `PermitHosts`/`PermitGroups`/`CrossTrustPermitForeignUsers` settings to FreeIPA's HBAC rules for FreeIPA-alternative deployments. The sync runs on a configurable schedule (default 15 minutes).
- The framework's `adrian-policy-daemon` MUST log every logon evaluation as an OTel audit event (per ADR-060) with attributes `adrian.security.logon.user_sid`, `adrian.security.logon.user_dn`, `adrian.security.logon.host`, `adrian.security.logon.service`, `adrian.security.logon.result` (permit/deny), `adrian.security.logon.matched_rule`. Deny results with `result_reason = "cross_trust_not_permitted"` are tagged MITRE T1021 (Remote Services) for SIEM correlation.
- The framework's audit pipeline MUST ship default detection rules:
  - Rule 1: cross-trust user logon denied with `cross_trust_not_permitted` → severity "medium" (legitimate denied access; flagged for visibility).
  - Rule 2: cross-trust user logon permitted on a host not in any rule's `PermitHosts` → severity "high" (the host may have a permissive rule that should be tightened).
  - Rule 3: cross-trust user logon storm (>20 cross-trust logons in 5 minutes from one user) → severity "high" (potential lateral movement).
- The framework MUST support AD-interop compatibility for the `Allowed to Authenticate` ACE. Framework-managed resources that need to be accessible to AD-managed foreign users (via the cross-trust TGT) MUST have the ACE set on the framework-managed computer object. The framework's `adrian-cli trust set-selective-auth --host <dn> --permit-forest <forest-dn>` command sets the ACE on the framework-managed computer object.
- The framework MUST emit a Prometheus metric `adrian_security_logon_total{forest,host,service,result}` (per ADR-057) — the count of logon evaluations per forest, host, service, and result. The metric is keyed by the user's forest (local or foreign) to enable cross-trust logon-rate monitoring.
- The framework MUST ship a default Prometheus alert: `rate(adrian_security_logon_total{forest!="local",result="permit"}[5m]) > 50` triggers warning (high rate of cross-trust logon — potential lateral movement).
- The framework's `adrian-cli security coverage --selective-auth` MUST return per-host: `policy_source` (framework/AD), `evaluation_daemon` (adrian-policy-daemon/adrian-sssd-gpo/FreeIPA), `cross_trust_users_permitted` (count), `last_evaluation` (timestamp).

## Rationale

HBAC-equivalent rules are the operationally superior alternative to per-resource ACEs. The FreeIPA community has used HBAC for years (per [`09-linux-equivalents/08-freeipa-trust.md`](../docs/09-linux-equivalents/08-freeipa-trust.md)); the model is proven. The framework's `Security` PolicyArea extends HBAC with cross-trust-specific settings (`CrossTrustPermitForeignUsers`) that map directly to AD's selective-authentication use case.

The central rule set is the operational improvement. AD's per-resource ACE requires 1000 ACE operations for a 1000-server farm; the framework's central rule set requires one rule with `PermitHosts = ["farm-group"]`. Adding a new server to the farm adds it to the `farm-group` host group — the rule applies automatically. This is the operational property that makes selective authentication usable in dynamic environments.

The per-host evaluation is the perf-improvement property. AD's selective authentication requires the KDC to check the `Allowed to Authenticate` ACE on the resource computer object during TGS-REQ — a directory read per TGS. The framework's `adrian-policy-daemon` evaluates the rule locally on the resource host with a 60-second cache, avoiding the per-TGS directory read. The perf cost is one local evaluation per logon (≤1 ms typical), vs. AD's one directory read per TGS (5–20 ms typical).

AD-interop compatibility preserves the per-resource ACE model for AD-managed resources. Framework-managed resources use the HBAC-equivalent model; AD-managed resources continue with the per-resource ACE model. The two models coexist during migration; after migration, the framework's model is the sole mechanism.

Decision 6's NTLM-server-side drop is the defence-in-depth complement. Selective authentication is partly a mitigation for the risk that a compromised foreign user can authenticate to any resource that accepts their credentials. By eliminating NTLM server-side, the framework requires Kerberos for cross-trust access (with `PAC_BUFFER_TICKET_CHECKSUM` validation per ADR-123, sIDHistory filtering per ADR-124, and HBAC-equivalent rules per this ADR). The combination provides layered defence: the KDC validates the ticket signature; the framework's filter strips injected SIDs; the host's `adrian-policy-daemon` checks the user against the rule set.

The audit pipeline's detection rules surface both legitimate denied access (Rule 1) and potential misconfiguration (Rule 2). The cross-trust logon-rate alert (Rule 3) catches lateral-movement patterns. The Prometheus metric enables per-forest, per-host, per-service monitoring of cross-trust access.

## Consequences

**Positive**: Selective authentication is operationally usable (central rule set, per-host evaluation, 60-second cache). Cross-trust access is monitored per-forest, per-host, per-service. AD-interop compatibility preserves the per-resource ACE model during migration. Decision 6's NTLM drop provides defence-in-depth. MITRE ATT&CK T1021 mapping is automatic for denied cross-trust logons.

**Negative**: AD-managed resources continue to require the per-resource ACE (the framework's model applies only to framework-managed resources). The framework's HBAC-equivalent model requires the `adrian-policy-daemon` to be installed on every framework-managed host (already required per Decision 7 for policy application, so no additional footprint). The FreeIPA `sync-hbac` command requires FreeIPA to be deployed alongside the framework (per Decision 12's FreeIPA-as-alternative tier).

**Neutral**: The framework's `Security` PolicyArea is a new policy area; AD-interop scenarios where AD-managed GPO defines User Rights Assignment (URA) continue to apply on AD-managed hosts. The framework's `Security` PolicyArea applies on framework-managed hosts only.

**Implementation cost**: ~3 person-months for the `adrian-policy-daemon` logon-evaluation integration, the `adrian-sssd-gpo` HBAC integration, the `adrian-cli trust sync-hbac` command, the audit pipeline rules, and the `adrian-cli security coverage --selective-auth` CLI. Reuses Decision 7's `adrian-policy-core`, Decision 12's `adrian-sssd-gpo`, ADR-060's audit pipeline.

**Operational impact**: Security administrators author `Security` PolicyArea rules (not per-resource ACEs). SREs monitor `adrian_security_logon_total{forest!="local"}` for cross-trust access patterns. SOC analysts see cross-trust logon alerts with MITRE T1021 tags. The FreeIPA-alternative-tier customers use `adrian-cli trust sync-hbac` to keep FreeIPA HBAC in sync.

## Alternatives Considered

**Alternative A: Preserve AD's per-resource `Allowed to Authenticate` ACE model verbatim.** Implement the per-resource ACE as the sole selective-authentication mechanism. Rejected because (a) the operational pain is the documented reason AD deployments skip selective authentication; (b) the framework's value proposition is doing better than AD's defaults; (c) the HBAC-equivalent model is proven (FreeIPA) and operationally superior.

**Alternative B: Per-OU ACE inheritance.** Apply the `Allowed to Authenticate` ACE on an OU; inherit to all child computer objects. Rejected because (a) AD's ACL inheritance is fragile (blocked inheritance, explicit deny precedence); (b) it does not solve the dynamic-environment problem (new OUs require new ACEs); (c) the central-rule-set model is more flexible (rules can target host groups, not just OUs).

**Alternative C: Claims-based access control (Server 2012+).** Replace selective authentication with claims-based access control — the resource evaluates user claims (assertions about the user) rather than SIDs. Rejected as the primary path because (a) claims-based access control requires Server 2012+ forest functional level (per ADR-121, the framework replaces functional levels with capability flags — claims-based access control requires the `claims_based_kerberos` capability bit, which not all forests have); (b) central access policies are resource-side and require Active Directory deployment; (c) the HBAC-equivalent model is simpler and proven. Claims-based access control remains available as an opt-in for forests that have the capability.

**Alternative D: Drop cross-forest trust entirely (no foreign users).** Refuse cross-forest trust; foreign users must authenticate via federation (OAuth2/OIDC per the Federation Gateway). Rejected because (a) cross-forest trust is required for AD-interop migration scenarios (PC-126 parallel-run); (b) federation is a different access model (web-SSO, not network logon); (c) many enterprise scenarios require cross-forest network logon (e.g. shared file servers, shared SQL databases).

## Open Questions

None. Workshop Decision 12 resolved the Linux-tier ORQ-202/203 that gated this ADR. Decision 6 provides the defence-in-depth complement. The HBAC-equivalent model is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-010)**: Decision 3's identity mapping table is used to resolve user SIDs and group SIDs for logon evaluation.
- **Policy Engine (PC-047/PC-052)**: Decision 7's `adrian-policy-daemon` evaluates the `Security` PolicyArea at logon time.
- **Operations (PC-111)**: ADR-060 (audit logs) — logon evaluation audit events are part of the audit pipeline.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_security_logon_total` is the key metric.
- **Cross-Platform Parity (PC-040)**: Decision 12 (Linux tier) — `adrian-sssd-gpo` integrates with SSSD for HBAC-equivalent evaluation on SSSD-primary Linux hosts.
- **Auth Provider (PC-036/PC-038)**: Decision 6 (NTLM drop) — services that no longer accept NTLM reduce the cross-trust attack surface.
- **Security (PC-119)**: ADR-123 (silver ticket) — services that validate `PAC_BUFFER_TICKET_CHECKSUM` provide additional defence-in-depth for cross-trust access.
- **Security (PC-120)**: ADR-124 (sIDHistory injection) — sIDHistory filtering prevents injected SIDs from being honoured in cross-trust access.
- **Migration (PC-126)**: ADR-128 (Kerberos cross-realm during migration) — the framework's HBAC-equivalent model applies to cross-trust Kerberos established during migration.

## References

- [PC-121](../catalog/11-security-threat-model.md) — problem statement (selective authentication rarely used; per-resource ACE is operationally painful)
- [Trusts topology KB](../docs/03-directory-schema/04-trusts-topology.md) — `TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10`, `Allowed to Authenticate` controlAccessRight GUID `68b1d179-0d15-4d4f-ab71-46152e79a7bc`
- [FreeIPA trust KB](../docs/09-linux-equivalents/08-freeipa-trust.md) — FreeIPA HBAC model, `ipa trust-add`, `ipa hbacrule` management
- [Workshop Decision 12 — Linux tier](../workshop/decision-12-linux-tier.md) — SSSD-primary + FreeIPA-as-alternative; HBAC-equivalent rules as selective-auth replacement; §7 selective authentication
- [Workshop Decision 6 — NTLM decision](../workshop/decision-06-ntlm-decision.md) — server-side NTLM eliminated; defence-in-depth complement
- [Workshop Decision 7 — Policy format](../workshop/decision-07-policy-format.md) — `Security` PolicyArea canonical JSON; `adrian-policy-daemon` per-host evaluation
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — logon evaluation Prometheus metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — logon evaluation audit events
- [ADR-066 — AdminSDHolder declarative RBAC](./ADR-066-adminsdholder-declarative-rbac.md) — declarative RBAC model reused for `Security` PolicyArea rule structure
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — `TRUST_ATTRIBUTE_CROSS_ORGANIZATION`, `Allowed to Authenticate` extended right
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) — cross-realm TGS referral, selective authentication enforcement
- [FreeIPA HBAC documentation](https://www.freeipa.org/page/Documentation) — HBAC rule model
- [MITRE ATT&CK T1021 — Remote Services](https://attack.mitre.org/techniques/T1021/)
