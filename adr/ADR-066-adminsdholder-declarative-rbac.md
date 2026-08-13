---
title: "ADR-066: Replace AdminSDHolder with Declarative RBAC"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-122
severity: medium
tags: [adr, security, adminsdholder, sdprop, rbac, declarative-policy, audit, mitre-t1098]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/00-overview/05-glossary.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-060-structured-audit-logs-otel.md
  - ./ADR-061-rest-grpc-api.md
last_updated: 2026-08-13
---

# ADR-066: Replace AdminSDHolder with Declarative RBAC

## Status

Accepted — 2026-08-13

## Context

The `AdminSDHolder` object at `CN=AdminSDHolder,CN=System,DC=<domain>,DC=...` holds a security descriptor template that the Security Descriptor Propagator (SDPROP) thread in LSASS applies to all "protected" objects every 60 minutes by default. Protected objects are members of the privileged groups: Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, Server Operators, Print Operators, DNS Admins, and a handful of others (full list in MS-ADTS §6.1.1.6.1). The propagation sets the object's `nTSecurityDescriptor` to match the AdminSDHolder template, including the DACL and ownership.

The operational consequence: any custom ACE placed on a protected object (e.g. a helpdesk group granted `Write Members` on Domain Admins for a delegated workflow) is silently reverted to the AdminSDHolder template within 60 minutes. The admin who placed the ACE is not notified; the next time the workflow runs, it fails with `Access Denied`. The fix is to modify the AdminSDHolder template itself, not the protected object — a non-obvious procedure.

The security consequence: SDPROP also removes inheritance. Protected objects do not inherit ACEs from their parent OU. This breaks the standard "deny HelpDesk write to Domain Admins" pattern — the deny ACE on the parent OU never reaches the Domain Admins group. The only way to apply a deny to Domain Admins is to add it to the AdminSDHolder template. The template applies uniformly to all protected objects, so a deny on the template denies HelpDesk write to ALL protected groups (Domain Admins, Enterprise Admins, Schema Admins, etc.) which may not be the intent.

The framework gap: AdminSDHolder is an implicit, hard-to-discover mechanism. The framework should either (a) preserve AdminSDHolder semantics for AD-interop (with clear documentation that custom ACEs on protected groups will be reverted), or (b) replace with declarative RBAC — a central policy that defines which principals can modify which protected groups, evaluated at write-time rather than reverted every 60 minutes. The declarative model is more transparent and more testable.

## Threat model

**STRIDE classification**: Tampering, Elevation of privilege

**Attack vector** (step-by-step — primary attack pattern):

1. Admin grants HelpDesk `Write Members` on Domain Admins for a temporary workflow.
2. SDPROP reverts the ACE within 60 minutes. Admin does not notice.
3. Workflow fails. Admin "fixes" by granting HelpDesk a broader right (e.g. `Full Control` on the OU) to work around the revert.
4. HelpDesk now has Full Control on the OU, which inherits to all non-protected objects (workstations, services). HelpDesk member compromises a workstation, escalates to local SYSTEM, harvests cached credentials, escalates to Domain Admin via Pass-the-Hash.

Secondary attack pattern (persistence):

1. Attacker (who has Domain Admin) wants to persist access.
2. Attacker modifies AdminSDHolder template to grant their own account `Full Control` on all protected objects.
3. SDPROP propagates the change to Domain Admins, Enterprise Admins, etc.
4. Attacker's account now has Full Control on all privileged groups. Even if the attacker's Domain Admin membership is removed, the AdminSDHolder-granted Full Control persists.
5. Detection requires auditing AdminSDHolder itself — a rarely-checked object.

**Known mitigations in AD**:
- Document the AdminSDHolder template prominently in admin training.
- Audit AdminSDHolder modifications: `dsacls "CN=AdminSDHolder,CN=System,DC=corp,DC=example,DC=com"` regularly, alert on changes.
- Microsoft's "Get-ADAdminSDHolder" community script dumps the current template.
- Use `dsacls /restore` to revert AdminSDHolder to a known-good baseline.
- Disable SDPROP temporarily (registry `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDProtectMode = 0` — not recommended, breaks protection).

**Residual risk in AD**:
- Custom ACEs on protected objects silently revert; admins are not notified.
- SDPROP removes inheritance on protected objects, breaking deny-ACE patterns on parent OUs.
- AdminSDHolder itself is rarely audited; persistence via AdminSDHolder modification is hard to detect.
- The 60-minute propagation delay means a temporary ACE works for up to 60 minutes, encouraging admins to rely on it.
- Per-protected-group templates are not supported; the AdminSDHolder template applies uniformly.

## Decision

The framework replaces AdminSDHolder + SDPROP with a declarative RBAC policy evaluated at write-time. The policy is a YAML document (or CRD) that defines, per protected group, which principals can perform which operations (read, write-member, write-owner, full-control). On any write to a protected object, the framework's DSA evaluates the policy; if the writer is not authorised, the write is rejected with `Insufficient Rights` (LDAP result code 50) and an audit event is emitted. There is no periodic propagation; the policy is enforced live.

The framework's RBAC policy is per-protected-group (not uniform like AdminSDHolder). Domain Admins, Enterprise Admins, Schema Admins, etc. each have their own policy. Inheritance is preserved: protected objects inherit ACEs from their parent OU; the RBAC policy is an additional check on top of the inherited ACL, not a replacement. This preserves the standard "deny HelpDesk write to Domain Admins via OU-level deny ACE" pattern.

For AD-interop scenarios (the framework's DC participates in an AD forest), the framework preserves AdminSDHolder semantics: the framework's DC runs an SDPROP-equivalent thread that applies the AdminSDHolder template to protected objects every 60 minutes. The framework's RBAC policy is an additional layer of protection on top of AdminSDHolder. organisations that have migrated fully to the framework (no AD DCs) can disable the SDPROP-equivalent and rely solely on the RBAC policy.

The RBAC policy is managed via the REST API (per [ADR-061](./ADR-061-rest-grpc-api.md)): `GET /api/v1/rbac/policies`, `PUT /api/v1/rbac/policies/{groupName}`. Changes to the policy are versioned and audited (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)). The framework ships default policies for the Tier-0 (Domain Admins, Enterprise Admins, Schema Admins), Tier-1 (Server Operators, DNS Admins), and Tier-2 (HelpDesk, Account Operators) protected groups, following the Microsoft Tier Model.

**Concrete specification**:

- The framework MUST implement declarative RBAC policy enforcement on writes to protected objects. Protected objects are: members of Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, Server Operators, Print Operators, DNS Admins, and any group tagged `protected = true` in the framework's RBAC policy.
- The RBAC policy MUST be a YAML document (or CRD) with the following structure:
  ```yaml
  rbac:
    - group: "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"
      tier: 0
      rules:
        - principals: ["CN=DA-Workstations,OU=Groups,DC=corp,DC=example,DC=com"]
          operations: ["read", "write-member"]
          audit: true
        - principals: ["CN=Enterprise Admins,CN=Users,DC=corp,DC=example,DC=com"]
          operations: ["full-control"]
          audit: true
        - principals: ["*"]
          operations: []
          audit: true
  ```
- The framework's DSA MUST evaluate the RBAC policy on every write to a protected object. If the writer is not in a principal group that has the requested operation, the write MUST be rejected with `LDAP_INSUFFICIENT_RIGHTS (50)`.
- The DSA MUST emit an OTel audit event on every RBAC policy evaluation (allow or deny) with attributes `adrian.rbac.group`, `adrian.rbac.principal`, `adrian.rbac.operation`, `adrian.rbac.result`, and MITRE ATT&CK T1098 (Account Manipulation) when the operation is `write-member` and the result is `deny`.
- The framework MUST support per-protected-group policies (different rules for Domain Admins vs Enterprise Admins vs Schema Admins).
- The framework MUST preserve inheritance: protected objects inherit ACEs from their parent OU. The RBAC policy is an additional check on top of the inherited ACL, not a replacement.
- The framework MUST ship default RBAC policies for Tier-0, Tier-1, and Tier-2 protected groups following the Microsoft Tier Model:
  - Tier-0 (Domain Admins, Enterprise Admins, Schema Admins): only Tier-0 admin workstations can `write-member`; only Enterprise Admins can `full-control`.
  - Tier-1 (Server Operators, DNS Admins): only Tier-1 admin workstations can `write-member`; only Domain Admins can `full-control`.
  - Tier-2 (HelpDesk, Account Operators): only Tier-2 admin workstations can `write-member`; only Domain Admins can `full-control`.
- The framework's RBAC policy MUST be managed via the REST API: `GET /api/v1/rbac/policies` (list), `GET /api/v1/rbac/policies/{groupName}` (get one), `PUT /api/v1/rbac/policies/{groupName}` (update).
- Changes to the RBAC policy MUST be versioned (each change gets a monotonically increasing version number) and MUST be audited.
- The framework MUST support a "dry-run" mode: `PUT /api/v1/rbac/policies/{groupName}?dry-run=true` evaluates the proposed policy against the last 30 days of writes and reports which writes would have been denied.
- The framework MUST emit a Prometheus metric `adrian_rbac_evaluations_total{group,operation,result}` (per [ADR-057](./ADR-057-prometheus-otel-observability.md)).
- For AD-interop scenarios, the framework MUST preserve AdminSDHolder semantics: the framework's DC runs an SDPROP-equivalent thread that applies the AdminSDHolder template to protected objects every 60 minutes. The framework's RBAC policy is an additional layer on top.
- The framework MUST support disabling the SDPROP-equivalent when no AD DCs are present in the forest (`spec.adminSDHolder.enabled: false` on the `Realm` CRD).
- The framework MUST ship a CLI command `adrian-cli rbac audit` that dumps the current RBAC policy and the last 30 days of RBAC evaluation events for SOC review.

## Rationale

Declarative RBAC evaluated at write-time is strictly better than AdminSDHolder's periodic propagation. The write-time evaluation provides immediate feedback (the writer sees `Insufficient Rights` immediately, not 60 minutes later); the declarative policy is auditable (it is a YAML document, not a security descriptor on a hidden object); the per-protected-group policies match the real-world need (different groups need different rules).

The Microsoft Tier Model (Tier-0/1/2 admin isolation) is the modern best practice for AD admin segmentation. The framework's default policies codify this model, making it the default rather than an opt-in. AD requires extensive configuration to implement the Tier Model (PAWs, separate admin accounts, RBAC via AGPM or third-party); the framework bakes it in.

Preserving AdminSDHolder for AD-interop is necessary because the framework's DC may participate in an AD forest where AD DCs still apply SDPROP. Disabling AdminSDHolder on the framework's DC would create an inconsistency: protected objects on the framework's DC would have different ACLs than on the AD DCs. The framework's RBAC policy is an additional layer on top of AdminSDHolder, not a replacement.

The dry-run mode is essential for safe policy changes. Operators can propose a new policy, see what writes would have been denied, and adjust before applying. This is the same pattern as Kubernetes' `kubectl apply --dry-run=server`.

The audit trail (every RBAC evaluation is logged) is the detection layer. SOC analysts can query the audit pipeline for `adrian.rbac.result = deny` events to detect attempted privilege escalation. The MITRE ATT&CK T1098 mapping on `write-member` denials is automatic.

## Consequences

**Positive**: Custom ACEs on protected objects are no longer silently reverted (RBAC is enforced live, with immediate feedback). Per-protected-group policies match real-world needs. The Microsoft Tier Model is the default. Dry-run mode enables safe policy changes. The audit trail detects attempted privilege escalation. Inheritance is preserved, restoring the standard deny-ACE-on-parent-OU pattern.

**Negative**: The framework's DSA must evaluate the RBAC policy on every write to a protected object, adding latency (typically <1 ms per evaluation, but high-volume environments may notice). The RBAC policy is a new configuration surface that operators must learn. AD-interop scenarios retain AdminSDHolder (the framework cannot remove it from AD DCs), so the dual-layer model (AdminSDHolder + RBAC) adds complexity.

**Neutral**: The framework's RBAC policy does not preclude additional ACL-based access control; operators can layer OU-level ACEs on top of the RBAC policy. The RBAC policy is the privileged-group-specific layer; OU-level ACEs are the resource-specific layer.

**Implementation cost**: ~3 person-months for the DSA write-time RBAC evaluation; ~2 person-months for the policy CRD and REST API; ~2 person-months for the default Tier-0/1/2 policies; ~1 person-month for the dry-run mode; ~1 person-month for the audit integration. Total: ~9 person-months for v1.

**Operational impact**: Operators define RBAC policy via YAML (GitOps workflow). The dry-run mode reduces policy-change risk. SOC analysts see RBAC denials in the audit pipeline with MITRE T1098 tags. The framework's runbook replaces AdminSDHolder documentation with RBAC policy documentation.

## Alternatives Considered

**Alternative A: Preserve AdminSDHolder as-is (AD-interop only).** Keep AdminSDHolder + SDPROP unchanged; document the behaviour; rely on operator training. Rejected because (a) the 60-minute revert is the root cause of the attack pattern (admins work around it by granting broader rights), (b) AdminSDHolder is rarely audited (the persistence attack via AdminSDHolder modification is hard to detect), (c) the uniform-template model does not match the per-group need.

**Alternative B: SDPROP with per-protected-group templates.** Extend SDPROP to apply different templates to different protected groups. Rejected because (a) it retains the periodic-propagation model (the 60-minute revert is still a problem), (b) it does not address the inheritance-removal issue, (c) the declarative RBAC model is strictly better (immediate feedback, auditable, per-group).

**Alternative C: FreeIPA HBAC-style server-side evaluation.** Use FreeIPA's HBAC (Host-Based Access Control) model: central rule set evaluated at login time on each host. Rejected because (a) HBAC is for login authorisation, not for write authorisation on directory objects, (b) HBAC requires an SSSD client on each host (the framework's RBAC must be enforced by the DSA, not the client), (c) HBAC's rule model (user × host × service) does not map cleanly to (principal × group × operation).

**Alternative D: External PDP (Policy Decision Point) via XACML.** Use an external PDP (e.g. AuthzForce) that evaluates XACML policies. Rejected because (a) it adds a network round-trip on every write (latency budget exceeded), (b) XACML is verbose and operationally complex, (c) the framework's DSA is the natural enforcement point.

## Open Questions

None — this is an ADR-ELIGIBLE decision. The framework's storage engine choice (PC-007 / Tier-1 ORQ-011/012/013/014) does not gate this decision: the RBAC policy evaluation is implemented at the DSA layer, not the storage layer.

## Cross-capability impact

- **Core Directory (PC-001 through PC-022)**: DSA write-path must evaluate the RBAC policy; SD table caching (PC-008) must include the RBAC policy in the cache.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_rbac_evaluations_total{group,operation,result}` is the key Prometheus metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — RBAC evaluation events are part of the audit pipeline.
- **Operations (PC-112)**: ADR-061 (REST/gRPC API) — RBAC policy management is via the REST API.
- **Policy Engine (PC-043 through PC-056)**: PC-054 (per-principal ACL pattern) overlaps with RBAC; ADR writers must align.
- **Migration (PC-125)**: GPO translation (PC-125, deferred) must translate AD AdminSDHolder configuration to the framework's RBAC policy.

## References

- [PC-122](../catalog/11-security-threat-model.md) — problem statement (AdminSDHolder + SDPROP can override intended ACLs)
- [Glossary](../docs/00-overview/05-glossary.md) — AdminSDHolder glossary entry: "Object in the system container that holds the security descriptor template applied to protected groups (every 60 min by SDPROP)."
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — SD table caching (`sdtable` in ESE), `nTSecurityDescriptor` column, `SCGetSDFromCache` lookup path that SDPROP modifies
- [MS-ADTS §6.1.1.6.1 — AdminSDHolder and protected groups](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) (full list of protected groups)
- [Microsoft Tier Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model) (Tier-0/1/2 admin isolation)
- [NIST SP 800-162 — Guide to Attribute Based Access Control (ABAC)](https://csrc.nist.gov/publications/detail/sp/800-162/final) (RBAC/ABAC reference)
- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
