---
title: "ADR-030: Role-based policy binding; deprecate Authenticated Users"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-054
severity: medium
tags: [adr, policy-engine, rbac, security-filtering, authenticated-users]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/02-gpo-processing-order.md
  - ../docs/09-linux-equivalents/03-sssd-gpo-access.md
  - ./ADR-024-per-platform-policy-executors.md
last_updated: 2026-08-13
---

# ADR-030: Role-based policy binding; deprecate Authenticated Users

## Status

Accepted — 2026-08-13.

## Context

Default AD GPOs are ACLed for `Authenticated Users` (S-1-5-11, the well-known group including every authenticated user AND computer in the forest) with `Read` + `Apply Group Policy` (extended-right GUID `edacfd8f-ffb3-11d1-b41d-00a0c968f939`). Per [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), for a user or computer to apply a GPO, both `Read` permission on the GPC object (and GPT folder) AND `Apply Group Policy` ACE on the GPC must be present for the security principal or a group containing it; `Deny` ACEs always win.

A common operational footgun: an admin removes `Authenticated Users` from a GPO's ACL to scope it to a specific group (e.g., "Finance Users") and forgets that the computer account needs `Read` at boot to fetch machine policy. The result: machine-side policy silently fails on every host whose computer account is not in the scoped group. The workaround is to add `Domain Computers` (S-1-5-21-...-515) explicitly with `Read`, but this is frequently missed. The modern PowerShell is `Set-GPPermissions -TargetName "..." -PermissionLevel GpoApply -TargetName "DOMAIN Computers"` — but the GPMC UI does not make the computer-account requirement obvious, per [PC-054](../catalog/04-policy-engine.md).

On macOS and Linux, security filtering is honored differently. SSSD's `ad_gpo_evaluate_gpo` checks the GPC's `nTSecurityDescriptor` for the host's computer account SID and the user's PAC SIDs (`PAC_LOGON_INFO.GroupIds`, `ExtraSids`, `LogonDomainId`). If `Authenticated Users` is removed and the host's group is not added, SSSD silently skips the GPO. macOS AD plugin behaves similarly, per [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md).

The framework must support per-principal ACL on policy objects, must include computer accounts by default (auto-add `Domain Computers`-equivalent with `Read`), and for AD interop must honor existing GPC `nTSecurityDescriptor` ACEs. A role-based policy binding (policy → role → principals) would avoid the per-principal ACL footgun.

## Decision

The framework shall adopt role-based policy binding as the primary scoping mechanism, deprecate `Authenticated Users` as the default filter, and auto-include computer accounts for computer-policy.

1. **Role-based binding** — each policy is bound to one or more roles via the canonical JSON policy's `spec.target.roles` field (per ADR-029). A role is a named collection of principals (users, groups, computers, computer groups). Roles are first-class objects in the framework's directory, stored as `roleBinding` objects.
2. **Role definition** — a role is a JSON object: `{"name": "<role-name>", "members": {"users": ["<user-dn>"], "groups": ["<group-dn>"], "computers": ["<computer-dn>"], "computer_groups": ["<computer-group-dn>"]}}`. Roles can be nested (a role can include another role's members).
3. **Computer-policy auto-include** — when a policy's `spec.target` includes computer-side areas (any area other than user-only areas like `Preferences.Shortcuts`), the framework auto-binds the policy to a `Domain Computers`-equivalent role. Operators do not need to explicitly add computer accounts — the framework does it automatically.
4. **Deprecate `Authenticated Users` as default** — the framework's policy authoring UI does not offer `Authenticated Users` as a default binding. Operators must explicitly choose a role. Existing AD-authored GPOs that use `Authenticated Users` continue to work via the AD interop adapter, but the framework's native policy format does not use `Authenticated Users`.
5. **AD interop** — for AD-authored GPOs consumed by the framework's Windows Client SDK, the framework honors the GPC's `nTSecurityDescriptor` ACEs (existing behavior). For framework-authored policies consumed by legacy Windows hosts running `gpsvc.dll`, the framework's policy distribution service emits a GPC with `nTSecurityDescriptor` derived from the role bindings: each role's members get `Read` + `Apply Group Policy`; the auto-included `Domain Computers` role gets `Read` on computer-side policies.
6. **Deny semantics** — `Deny` ACEs always win (matching AD semantics). The framework's role model supports `deny_roles` in addition to `roles`; a principal in a `deny_role` is excluded even if also in an allow `role`.
7. **Diagnostic tooling** — the framework's `adrian-policy why --host <name> --policy <id>` CLI explains why a policy applies or does not apply to a host: lists the role bindings, the principal's role memberships, the auto-included computer role, and any deny-role matches. This replaces AD's `gpresult /scope computer /h` for policy-scoping diagnostics.

**Concrete specification**:

- Roles are stored as `roleBinding` objects in the framework's directory; the schema is defined in ADR-029's JSON schema family.
- The framework's policy authoring UI exposes role selection via a drop-down (no free-text principal entry for binding).
- The auto-included computer role is named `adrian-auto-computers`; its membership is the set of all enrolled computers in the directory. Operators can override per-policy (e.g., scope to a specific computer group).
- The framework's `adrian-policy compile --target windows <file>` CLI emits a GPC `nTSecurityDescriptor` with ACEs: each role's user/group/computer members get `Read` + `Apply Group Policy` (extended-right GUID `edacfd8f-ffb3-11d1-b41d-00a0c968f939`); the `adrian-auto-computers` role gets `Read` on computer-side policies.
- For SSSD interop, the framework's role bindings are translated to GPC `nTSecurityDescriptor` ACEs that SSSD's `ad_gpo_evaluate_gpo` honors (per [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md)). SSSD's PAC SID check works against the role's group SIDs.
- The `adrian-policy why --host <name> --policy <id>` CLI output: `Policy <id> applies to host <name> because: host is in role <role-name> (via group <group-dn>); computer-policy auto-included via adrian-auto-computers.`

## Rationale

Three alternatives were considered.

**Alternative 1: Preserve per-principal ACL as the primary model.** Rejected because the per-principal ACL footgun (forgetting to add `Domain Computers`) is the bug being fixed. Per-principal ACL is also operationally expensive at scale — a 10,000-host fleet with 1,000 GPOs and 50 security groups produces 50,000 ACL entries to manage, with no abstraction. Roles provide the abstraction.

**Alternative 2: Use RBAC with `Authenticated Users` as implicit default.** Keep `Authenticated Users` as the implicit default role; operators opt into more specific roles. Rejected because `Authenticated Users` is over-broad — it includes every user and computer in the forest, which is exactly the wrong default for security-sensitive policies. The framework's design principle is "secure by default"; requiring operators to explicitly choose a role forces them to think about scope.

**Alternative 3: Attribute-based access control (ABAC) with policy-time evaluation.** Use ABAC (e.g., OPA Rego, Cedar) to evaluate policy binding at apply time based on principal attributes. Rejected because ABAC evaluation at every policy refresh is expensive (10,000 hosts × 1,000 policies × ABAC evaluation per refresh), and ABAC policies are harder to audit than role memberships ("why did this policy apply to this host?" requires replaying the ABAC evaluation). RBAC with explicit role bindings is auditable by direct lookup.

The decision aligns with industry practice: Kubernetes uses RoleBinding/ClusterRoleBinding (RBAC); AWS IAM uses role-based policies; HashiCorp Vault uses role-based secret access. None use `Authenticated Users` as a default. The framework's role-based binding is the same shape.

Cost: ~3 person-weeks for the role model, the auto-include logic, the `adrian-policy why` diagnostic, and the AD interop ACE emission.

## Consequences

**Positive**. The "forgot to add `Domain Computers`" footgun is eliminated — the framework auto-includes computer accounts for computer-policy. Role-based binding is auditable ("why did this policy apply to this host?" is a direct lookup). The `adrian-policy why` CLI provides per-host per-policy diagnostics that AD's `gpresult /h` does not. Deprecating `Authenticated Users` as default forces operators to think about scope, reducing over-broad ACL attack surface (per the Security capability).

**Negative**. Operators migrating from AD must re-author their GPO security filtering as role bindings. The migration tooling (per ADR-055) translates AD GPO ACLs to role bindings, but complex ACL setups (multiple groups with `Read` but not `Apply Group Policy`, deny-only ACEs) may not translate cleanly. The auto-included `adrian-auto-computers` role is a new concept that operators must understand.

**Neutral**. Roles are first-class objects, adding to the directory schema. Role nesting is supported but limited to 5 levels (to prevent infinite loops and audit complexity). The deny-role mechanism is symmetric with AD's `Deny` ACE semantics.

**Implementation cost**. ~3 person-weeks for the role model, auto-include logic, `adrian-policy why` diagnostic, and AD interop ACE emission.

**Operational impact**. Operators author role bindings via the UI drop-down. The `adrian-policy why` CLI replaces `gpresult /h` for policy-scoping diagnostics. Role management is a new operational task (creating, populating, and auditing roles).

## Alternatives Considered

### Alternative A: Preserve per-principal ACL as primary model

Keep AD's per-principal ACL model as the framework's primary scoping mechanism. Operators add individual users, groups, and computers to each policy's ACL.

Rejected because the per-principal ACL footgun (forgetting to add `Domain Computers`) is the bug being fixed. Per-principal ACL is also operationally expensive at scale — a 10,000-host fleet with 1,000 policies and 50 security groups produces 50,000 ACL entries to manage, with no abstraction. Roles provide the abstraction: a policy is bound to a role, the role is populated with principals, and changes to role membership propagate to all bound policies automatically. Per-principal ACL requires updating every policy's ACL when a principal is added or removed.

### Alternative B: RBAC with `Authenticated Users` as implicit default

Use RBAC as the primary model but keep `Authenticated Users` as the implicit default role. Operators opt into more specific roles when they want to scope a policy.

Rejected because `Authenticated Users` is over-broad — it includes every user and computer in the forest, which is exactly the wrong default for security-sensitive policies (e.g., a "disable SMBv1" policy should not apply to every authenticated user; it should apply to every computer, which is a different set if there are user-only principals in the forest). The framework's design principle is "secure by default"; requiring operators to explicitly choose a role forces them to think about scope, reducing over-broad ACL attack surface.

### Alternative C: Attribute-based access control (ABAC)

Use ABAC (e.g., OPA Rego, Cedar, XACML) to evaluate policy binding at apply time based on principal attributes (department, location, job title, etc.).

Rejected because (a) ABAC evaluation at every policy refresh is expensive — 10,000 hosts × 1,000 policies × ABAC evaluation per refresh = 10 million evaluations per refresh cycle, adding CPU cost on every host; (b) ABAC policies are harder to audit than role memberships — "why did this policy apply to this host?" requires replaying the ABAC evaluation with the principal's attributes at the time of evaluation, which may have changed since; (c) ABAC policy authoring is a specialist skill (Rego, Cedar, XACML syntax), while role membership management is a basic directory operation. RBAC with explicit role bindings is auditable by direct lookup and manageable by generalist operators. ABAC may be added as a future layer for advanced use cases (e.g., "apply this policy to all hosts in the finance department located in the EU"), but it is not the primary model.

## Open Questions

- Should the framework support attribute-based access control (ABAC) as an additional layer for advanced use cases (e.g., OPA Rego policies for dynamic scoping)? Current decision: RBAC-only for v1; revisit if operator demand for ABAC emerges.
- The `adrian-auto-computers` role: should it be a real role object in the directory (auditable, editable) or a virtual role (computed at evaluation time)? Current decision: real role object (auditable), auto-populated by the framework.
- Role nesting depth limit: 5 levels is the current decision. Should it be tunable? Deep nesting complicates audit; shallow nesting limits expressiveness.

## Cross-capability impact

- **Policy Engine (PC-054)**: This ADR. PC-053 (SSSD GPO access control) — the role model is the cross-platform access-control target, but PC-053 is gated by ORQ-202/203 (Linux tier strategy).
- **Security (PC-116..PC-123)**: ADR-066 (replace AdminSDHolder with declarative RBAC) — the role model is shared between Policy Engine and Security; the same `roleBinding` objects are used for both policy scoping and privileged-access management.
- **Migration (PC-124..PC-130)**: ADR-055 (migration paths) — the migration tooling translates AD GPO ACLs to framework role bindings.
- **Operations (PC-106..PC-115)**: ADR-060 (audit logs) — role binding changes and policy apply decisions are audit events.

## References

- [PC-054](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md) — Security filtering mechanics, `Apply Group Policy` extended-right GUID, `Authenticated Users` default
- [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md) — SSSD's `nTSecurityDescriptor` check and PAC SID evaluation
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol (security filtering reference)
- [RFC 4120 Kerberos](https://www.rfc-editor.org/rfc/rfc4120) — Kerberos PAC (used for SID evaluation)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) — industry precedent for role-based binding
