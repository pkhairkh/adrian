---
title: "ADR-026: Declarative host facts; WMI filter adapter for interop"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-049
severity: medium
tags: [adr, policy-engine, wmi, host-facts, targeting]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/02-gpo-processing-order.md
  - ../docs/04-group-policy/01-gpo-architecture.md
  - ./ADR-024-per-platform-policy-executors.md
last_updated: 2026-08-13
---

# ADR-026: Declarative host facts; WMI filter adapter for interop

## Status

Accepted — 2026-08-13.

## Context

AD GPO WMI filters are `msFTSI` objects under `CN=SOM,CN=WMIPolicy,CN=System,<domain-dn>` (SOM = Scope of Management). Each filter has one or more `msFTSI_Query` entries (WQL queries) ANDed together, attached to a GPO via `gPCWQLFilter` (LDAP URL). Per [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md), at GP processing time the client queries `root\cimv2` for each `msFTSI_Query`; if any query returns zero rows, the filter FAILS and the GPO is not applied (fail-closed). If the WMI service (`winmgmt`) is unavailable or the WMI repository is corrupted, the GPO is not applied. WMI filter results are cached on the client for 60 minutes under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\WMIFilterCache`.

WMI repository corruption is a well-known Windows operational pain point: symptoms include `WMI service is unavailable`, `0x80041006` (WMI out of memory), and partial CIM schema loss. Recovery is `rundll32 wbemdisp.dll,RepairWMISchema` or `winmgmt /salvagerepository` — both require admin rights and a service restart. A cache miss during repository outage means GPOs silently stop applying. The fail-closed behavior compounds the damage: a host with corrupted WMI may silently stop applying security policy (lockout threshold, LAPS rotation) without any visible error in `gpresult`, per [PC-049](../catalog/04-policy-engine.md).

The WMI filter model has no cross-platform equivalent. macOS has no WMI; Linux has `udevadm`/`hostnamectl`/`facter` (Ansible-style facts) but no WQL query language. SSSD's `ad_gpo_filter` does not honor WMI filters at all — they are silently ignored on Linux. The framework must define what "WMI filter on non-Windows" means: a GPO with a WMI filter applies on Windows but is silently skipped on macOS/Linux because the filter cannot be evaluated, per [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md).

For the framework, the design must: (a) preserve WMI filter evaluation for AD interop (existing `msFTSI_Query` WQL queries on Windows), (b) replace WMI filters with declarative host facts evaluated by the framework client as the cross-platform default, (c) translate WQL to host-fact predicates for legacy GPOs imported into the framework, and (d) decide the fail-closed vs. fail-open policy when a fact is unavailable.

## Decision

The framework shall adopt declarative host facts as the primary policy targeting mechanism, with a WMI filter adapter for Windows AD-interop only. The fact model is:

1. **Fact schema** — the framework defines a fixed set of host facts, evaluated by the framework's Client SDK at policy refresh time:
   - `os.name` (`windows` | `macos` | `linux`)
   - `os.version` (semver)
   - `os.arch` (`x86_64` | `arm64`)
   - `host.role` (string, set by enrollment: `workstation` | `server` | `dc` | `container-host`)
   - `host.site` (string, set by enrollment: AD site or framework equivalent)
   - `host.hostname` (string)
   - `host.domain` (string)
   - `host.groups` (list of strings, the host's group memberships)
   - `network.ip_ranges` (list of CIDRs the host has an interface in)
   - `user.name` (string, only for user-policy evaluation)
   - `user.groups` (list of strings, only for user-policy evaluation)
   - `user.site` (string, only for user-policy evaluation)
2. **Fact predicate expression** — the framework uses a simple predicate language: `<fact> <op> <value>` where `<op>` is `==`, `!=`, `in`, `not in`, `matches` (regex), `contains` (for lists). Predicates combine with `and` / `or` / `not`. Example: `host.role == "server" and os.name == "linux" and network.ip_ranges contains "10.0.0.0/8"`.
3. **Fail-open with warning** — if a fact is unavailable (e.g., `host.site` cannot be determined because the host is offline from the site database), the framework logs a warning and evaluates the predicate as `false` (the GPO does not apply). This is fail-closed for the GPO but fail-open for the host (the host continues to function with the last-applied policy). This is safer than AD's fail-closed behavior, which silently drops policy.
4. **WMI filter adapter (Windows-only)** — for legacy AD-authored GPOs that carry `gPCWQLFilter`, the framework's Windows executor evaluates the WQL query via `IWbemServices::ExecQuery` against `root\cimv2`. If WMI is unavailable, the framework logs an error and treats the filter as fail-open (the GPO applies with a warning), opposite to AD's fail-closed. This is a deliberate divergence: the framework prefers applying policy with a warning over silently dropping it.
5. **WQL-to-fact translation** — for legacy GPOs imported into the framework via the migration tooling (per ADR-055), the framework provides a translator that maps common WQL patterns to fact predicates. Example: `SELECT * FROM Win32_OperatingSystem WHERE ProductType = 2` (domain controller) → `host.role == "dc"`. WQL queries that cannot be translated are preserved as Windows-only WMI filters (the framework does not silently drop them).
6. **Fact evaluation cache** — facts are cached for 5 minutes (vs. AD's 60 minutes) to reduce evaluation cost while staying responsive to role/site changes.

**Concrete specification**:

- The fact schema is defined in the framework's Client SDK as a typed struct; new facts are added via framework releases (not user-extensible).
- The predicate language is parsed by a small PEG parser; the grammar is documented in the framework's reference.
- The framework's policy authoring UI exposes fact predicates as a structured form (drop-down for fact, drop-down for operator, value field) — no raw WQL.
- The Windows WMI adapter is implemented in the framework's Windows Client SDK; it uses `IWbemLocator::ConnectServer` with a 5-second timeout, and on failure logs `framework.wmi.unavailable` (OTel event) and applies the GPO with a warning.
- The WQL-to-fact translator covers the top 20 WMI filter patterns observed in production (per a Microsoft field survey cited in [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md)): OS product type, OS version, hostname pattern, IP range, AD site, computer group membership, registry key existence, file existence, service state. Patterns outside this set are preserved as Windows-only.
- The framework's migration tooling (per ADR-055) emits a report listing WMI filters that were translated vs. preserved-as-Windows-only.

## Rationale

Three alternatives were considered.

**Alternative 1: Preserve WMI filter evaluation as the cross-platform default.** Implement a WMI-equivalent on macOS and Linux. Rejected because WMI is a Windows-implementation-shaped abstraction (CIM schema, `root\cimv2` namespace, WQL query language). Porting it to macOS (which uses `system_profiler` and `ioreg`) and Linux (which uses `udevadm` and `hostnamectl`) would require emulating the CIM schema — exactly the SSSD-style emulation trap. The fact that no cross-platform tool (Ansible, Puppet, Chef) has adopted WMI is strong evidence.

**Alternative 2: Keep WMI for Windows-only and use facts for macOS/Linux.** A hybrid: Windows GPOs use WMI filters; framework policies use facts. Rejected because it forces operators to author two targeting mechanisms — WMI for Windows, facts for everything else — which is the current fragmented state of AD+SSSD, the very problem the framework is solving.

**Alternative 3: Fail-closed on fact unavailability (match AD's WMI behavior).** Rejected because AD's fail-closed-on-WMI-outage behavior is the bug being fixed. A host that loses the ability to evaluate facts should not silently drop all security policy. Fail-open-with-warning ensures the host keeps its last-applied policy and surfaces the problem for operator intervention.

The decision aligns with industry practice: Ansible's `facts` (gathered per-host), Puppet's `facter`, Chef's `ohai` — all use declarative host facts as the targeting mechanism. None use WQL. The framework's fact model is the same shape, with a smaller fixed schema (Ansible/Puppet/Chef expose hundreds of facts; the framework exposes ~12) for simplicity and auditability.

Cost: ~4 person-weeks for the fact evaluation engine, the predicate parser, the WMI adapter, and the WQL-to-fact translator. The translator is the highest-risk item (WQL is a complex query language; full translation is infeasible; the top-20-pattern approach is a pragmatic compromise).

## Consequences

**Positive**. Cross-platform policy targeting works: the same predicate (`host.role == "server" and os.name == "linux"`) applies on all three platforms. WMI repository corruption on Windows no longer silently drops security policy — the framework's fail-open-with-warning behavior surfaces the problem. The fact schema is small and documented, making policy authoring approachable for operators (vs. WQL, which requires CIM schema knowledge).

**Negative**. The fact schema is fixed — operators who relied on WMI queries against less-common CIM classes (e.g., `Win32_BIOS` for hardware inventory) must either migrate to framework-native inventory or accept that those policies remain Windows-only via the WMI adapter. The WQL-to-fact translator covers only the top 20 patterns; complex WQL queries are preserved as Windows-only, fragmenting the policy.

**Neutral**. The 5-minute fact cache (vs. AD's 60-minute WMI cache) increases evaluation cost but reduces targeting lag — a host that changes site is correctly targeted within 5 minutes. The fail-open-with-warning behavior diverges from AD; operators migrating from AD must be trained on the new behavior.

**Implementation cost**. ~4 person-weeks for the fact engine, predicate parser, WMI adapter, and WQL-to-fact translator.

**Operational impact**. Operators author predicates in a structured form, not WQL. The migration tooling reports which WMI filters were translated vs. preserved-as-Windows-only. Per-host fact evaluation is observable via `adrian-policy facts --host <name>` (CLI per ADR-063) — replaces `wmic` for policy-targeting diagnostics.

## Alternatives Considered

### Alternative A: Preserve WMI as cross-platform default

Implement a WMI-equivalent on macOS and Linux by porting the CIM schema and WQL parser. Rejected because WMI is Windows-implementation-shaped; porting it to macOS (which uses `system_profiler`/`ioreg`) and Linux (which uses `udevadm`/`hostnamectl`) would require emulating the CIM schema — a SSSD-style emulation trap. No cross-platform config-management tool (Ansible, Puppet, Chef) has adopted WMI; the framework should follow industry consensus.

### Alternative B: Hybrid (WMI on Windows, facts on macOS/Linux)

Keep WMI filter evaluation as the Windows targeting mechanism; use facts only on macOS and Linux. Rejected because it forces operators to author two targeting mechanisms — WMI for Windows, facts for everything else. This is the current fragmented state of AD+SSSD that the framework is explicitly solving. The framework's value proposition is "author once, apply everywhere"; a hybrid breaks that.

### Alternative C: Fail-closed on fact unavailability (match AD)

Match AD's WMI fail-closed behavior: if a fact is unavailable, the GPO does not apply. Rejected because AD's fail-closed-on-WMI-outage is the bug being fixed. A host that loses the ability to evaluate facts (e.g., temporary loss of connectivity to the site database) should not silently drop all security policy. Fail-open-with-warning ensures the host keeps its last-applied policy and surfaces the problem for operator intervention. The warning is critical: operators must know that fact evaluation failed, not silently inherit stale policy.

## Open Questions

- Should the fact schema be user-extensible (allow custom facts via plugin), or fixed to the framework-defined set? Custom facts add flexibility but complicate auditing (an operator must understand the custom fact to interpret a policy). The current decision is fixed schema; revisit if operator demand emerges.
- The WQL-to-fact translator covers the top 20 patterns. Should the framework publish a survey tool that scans existing AD WMI filters and reports the translation coverage before migration? This would help operators predict migration effort.
- The 5-minute fact cache: should it be per-fact (e.g., `host.site` cached for 60 min, `network.ip_ranges` cached for 5 min) or uniform? Per-fact caching is more efficient but adds complexity.

## Cross-capability impact

- **Policy Engine (PC-049)**: This ADR. PC-050 (slow-link detection, ADR-027) is a parallel client-side evaluation problem; the fact engine and the slow-link probe share the "client-side evaluation" pattern.
- **Migration (PC-124..PC-130)**: The WQL-to-fact translator is part of the GPO-to-declarative-policy migration tooling (per ADR-055).
- **Operations (PC-106..PC-115)**: Per-host fact evaluation is observable via the unified CLI (per ADR-063); fact-evaluation-failed warnings flow into the audit log (per ADR-060).
- **Security (PC-116..PC-123)**: Fact predicates are part of the policy audit trail — operators can answer "why did this policy apply to this host?" by inspecting the fact evaluation log.

## References

- [PC-049](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/02-gpo-processing-order.md](../docs/04-group-policy/02-gpo-processing-order.md) — `msFTSI` object class, `msFTSI_Query` attribute, fail-closed behavior, `WMIFilterCache` 60-minute cache
- [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md) — `gPCWQLFilter` LDAP URL format
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol
- [Ansible facts](https://docs.ansible.com/ansible/latest/user_guide/playbooks_vars_facts.html) — industry precedent for declarative host facts
- [Puppet Facter](https://puppet.com/docs/puppet/latest/facter.html) — industry precedent for declarative host facts
