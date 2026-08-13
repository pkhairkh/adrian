---
title: "ADR-008: Declarative YAML Replication Topology as Primary Mechanism"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-016
severity: medium
tags: [adr, core-directory, kcc, topology, declarative, yaml, ad-interop]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/01-core-directory.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ../docs/00-overview/02-ad-architecture.md
last_updated: 2026-08-13
---

# ADR-008: Declarative YAML Replication Topology as Primary Mechanism

## Status

Accepted — 2026-08-13

## Context

Active Directory's Knowledge Consistency Checker (`ntdskcc.dll!KCCDoTask`) runs every 15 minutes by default on every DC, computes a least-cost spanning tree for intra-site replication, and the Inter-Site Topology Generator (ISTG) for each site computes inter-site topology. The KCC walks the sites/subnets/site-links cost matrix in `CN=Sites,CN=Configuration,...` and updates `repsFrom` / `repsTo` on each NC head, per [PC-016](../catalog/01-core-directory.md#pc-016--kcc-topology-generation-every-15-minutes-has-scaling-limits), [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md), and [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md).

At 100+ sites, KCC execution time grows non-linearly (the spanning-tree computation is O(sites × links), and the ISTG bridgehead selection is O(bridgeheads × sites)). At 200+ sites, KCC becomes a bottleneck — single-threaded execution blocks replication topology updates for minutes. ISTG bridgehead selection can fail when sites have asymmetric link costs (the algorithm picks the wrong bridgehead, causing replication to flow over a high-cost link). KCC failures are silent — the topology just doesn't update, and replication continues with stale `repsFrom`. The silent failure mode is the worst: admins assume replication is healthy because no errors are logged, but the topology is stale.

For modern infrastructure, declarative topology (Kubernetes-style YAML) is the dominant pattern. Sites, subnets, site-links, and bridgeheads are declared in a version-controlled YAML file; a controller applies the YAML to the directory, updating `repsFrom` / `repsTo` accordingly. The advantages over auto-computed KCC: human-reviewable topology (PR-based review of topology changes), version-controlled history (git log shows every topology change), no silent failures (the controller surfaces apply errors), no scaling ceiling (the controller handles 10K+ sites without KCC's O(sites × links) bottleneck).

Constraints from [PC-016](../catalog/01-core-directory.md#pc-016--kcc-topology-generation-every-15-minutes-has-scaling-limits):

- Must support site-link cost matrix (`CN=Sites,CN=Configuration,...` `CN=IP,CN=Inter-Site Transports,...` siteLink objects with `cost`, `replInterval`, `schedule`).
- Must support ISTG failover (if the ISTG for a site fails, another DC takes over).
- For AD interop, the KCC must run and update `repsFrom` / `repsTo` on schedule (Windows DCs assume the partner's KCC is healthy).

## Decision

The framework SHALL use declarative YAML topology configuration as the primary mechanism for replication topology. The YAML file SHALL describe: sites (with subnets), site-links (with cost, replication interval, schedule), bridgeheads (per-site, per-site-link), and ISTG assignments (per-site). A topology-controller service SHALL apply the YAML to the directory, updating `repsFrom` / `repsTo` on each NC head. The controller SHALL run continuously, reconciling the directory's topology with the YAML declaration (Kubernetes-style reconciliation loop).

The framework SHALL provide an AD-compat adapter that reads AD-style site objects from `cn=Sites,cn=Configuration` and translates them to the internal YAML representation. This adapter enables mixed-OS DC forests where Windows DCs use KCC and framework DCs use declarative topology — the adapter ensures both sides see the same `repsFrom` / `repsTo` state.

The framework SHALL support KCC-equivalent auto-computation as a fallback for sites where the YAML does not specify bridgeheads or ISTG explicitly. The fallback is a simplified spanning-tree computation (no ISTG bridgehead selection complexity; the controller picks the lowest-cost path) that runs only when the YAML is incomplete. The fallback is intended for bootstrapping (initial deployment before YAML is written) and for emergency topology repair (admin deletes a bridgehead from YAML; the controller computes a temporary replacement).

The framework SHALL expose a CLI command (`adrian-topology apply topology.yaml`) and a REST API endpoint (`POST /api/v1/topology/apply`) for applying YAML topology. The framework SHALL expose a `diff` command (`adrian-topology diff topology.yaml`) that shows the difference between the YAML declaration and the current directory topology before applying.

The YAML schema SHALL support: sites (with `subnets`, `description`), site-links (with `cost`, `replInterval`, `schedule`, `bridgeheads`), ISTG assignments (`istg: <DC-DN>` per site), and explicit `repsFrom` / `repsTo` overrides (for advanced scenarios where the admin wants to bypass auto-computation entirely).

**Concrete specification**:

- The framework SHALL accept a YAML topology file with the schema: `sites` (list of `{name, subnets, description}`), `siteLinks` (list of `{name, sites, cost, replInterval, schedule, bridgeheads}`), `istgAssignments` (map of `site → DC-DN`).
- The topology-controller SHALL reconcile the directory's `repsFrom` / `repsTo` state with the YAML declaration every 60 seconds (configurable).
- The controller SHALL surface apply errors as Kubernetes-style events (visible via `adrian-topology events` and the REST API).
- The framework SHALL provide an AD-compat adapter that reads AD-style `site`, `subnet`, `siteLink` objects from `cn=Sites,cn=Configuration` and translates them to the internal YAML representation. The adapter runs continuously (every 5 minutes) and updates the YAML cache.
- For AD-interop mode, the framework SHALL write `repsFrom` / `repsTo` to the directory in the AD-compatible format (so Windows DCs replicate with framework DCs).
- The framework SHALL support KCC-equivalent auto-computation as a fallback when the YAML is incomplete (no explicit bridgeheads for a siteLink). The fallback SHALL use a simplified spanning-tree algorithm (no ISTG complexity).
- The framework SHALL expose `adrian-topology apply`, `adrian-topology diff`, and `adrian-topology events` CLI commands.
- The framework SHALL expose `POST /api/v1/topology/apply`, `GET /api/v1/topology/diff`, and `GET /api/v1/topology/events` REST endpoints.
- ISTG failover: if the assigned ISTG for a site is unreachable, the controller SHALL elect a new ISTG from the site's DCs (lowest GUID wins, deterministic). The failover SHALL complete within 60 seconds.
- Performance target: topology reconciliation for a 1,000-site forest SHALL complete in <30 seconds (vs KCC's 5+ minutes).

## Rationale

Declarative topology is the modern pattern. Kubernetes, HashiCorp Consul, and Istio all use declarative YAML topology with reconciliation loops. The advantages over KCC's auto-computation: human-reviewable changes (PR-based review), version-controlled history (git log), no silent failures (controller surfaces errors), no scaling ceiling (controller handles 10K+ sites). The KCC's O(sites × links) bottleneck is a fundamental limit of the auto-computation approach; declarative topology sidesteps it.

Three alternatives were considered:

**Alternative A — Keep KCC as primary; add monitoring for silent failures.** The advantage is AD-interop compatibility (Windows DCs assume KCC is running on partners). The disadvantage is the scaling ceiling — KCC at 200+ sites is unworkable, and monitoring does not fix the underlying scaling issue. Rejected as the primary mechanism; KCC is supported only as the AD-compat adapter's source of truth.

**Alternative B — Hybrid: declarative YAML for inter-site, auto-KCC for intra-site.** The advantage is reduced YAML complexity (intra-site topology is auto-computed; only inter-site needs YAML). The disadvantage is the silent-failure mode for intra-site auto-KCC — the same problem as full KCC. Rejected for v1; the framework's default is full declarative topology. The hybrid model is supported via the "KCC-equivalent fallback" for sites without explicit YAML, but it's not the primary mechanism.

**Alternative C — External topology controller (Kubernetes operator pattern).** The topology controller runs as a separate Kubernetes deployment, watches a YAML file in a ConfigMap, and applies it to the directory. The advantage is Kubernetes-native operation. The disadvantage is the framework becomes coupled to Kubernetes — deployments without Kubernetes (bare-metal, macOS DC, traditional Linux) lose the topology controller. Rejected as the *sole* mechanism; the topology controller SHALL be framework-internal (not Kubernetes-dependent) but SHALL support Kubernetes-native deployment as an option.

External evidence: [Kubernetes reconciliation pattern](https://kubernetes.io/docs/concepts/architecture/controller/) documents the reconciliation-loop model; [HashiCorp Consul topology](https://developer.hashicorp.com/consul/docs/architecture) uses declarative YAML for datacenter topology; [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents AD's KCC and ISTG. The framework's design matches the modern declarative pattern while preserving AD-interop via the adapter.

The cost of this decision is the topology-controller service (a new component) plus the YAML schema design plus the AD-compat adapter. The controller is ~3000 lines of code; the adapter is ~1000 lines; the YAML schema is straightforward.

## Consequences

**Positive**: Topology changes are version-controlled (git history), human-reviewed (PR-based), and auditable (controller events). No scaling ceiling — the controller handles 10K+ sites. No silent failures — apply errors are surfaced. Mixed-OS DC forests work via the AD-compat adapter.

**Negative**: Operators accustomed to KCC must learn the YAML schema. The topology-controller is a new service that must be highly available (a single controller failure halts topology updates). The AD-compat adapter adds complexity (continuous translation between AD site objects and YAML).

**Neutral**: KCC-compatible behavior is preserved via the adapter for AD-interop. Operators can choose to use the adapter exclusively (effectively running KCC-equivalent on framework DCs) or migrate to full declarative YAML.

**Implementation cost**: ~6 person-weeks for the topology-controller, YAML schema, CLI/REST API, AD-compat adapter, and KCC-equivalent fallback. The bulk of the work is the controller's reconciliation loop and the adapter's translation logic.

**Operational impact**: Topology changes are PR-reviewed (no more surprise KCC decisions). Topology failures are visible (no more silent stale `repsFrom`). Large-forest deployments (200+ sites) work without KCC's scaling ceiling. Mixed-OS DC forests work via the adapter.

## Alternatives Considered

### Alternative 1: Keep KCC as primary; add monitoring for silent failures

AD-interop compatible; does not fix the scaling ceiling. Rejected as primary; KCC supported only as the AD-compat adapter's source of truth.

### Alternative 2: Hybrid — declarative YAML for inter-site, auto-KCC for intra-site

Reduced YAML complexity; preserves the silent-failure mode for intra-site. Rejected for v1; the framework's default is full declarative topology. The KCC-equivalent fallback supports hybrid operation but is not the primary mechanism.

### Alternative 3: External Kubernetes operator as sole mechanism

Kubernetes-native; couples the framework to Kubernetes. Rejected as sole mechanism; the topology controller SHALL be framework-internal (not Kubernetes-dependent) but SHALL support Kubernetes-native deployment as an option.

## Open Questions

- Should the YAML schema support multi-cluster topologies (the framework deployed across multiple Kubernetes clusters with cross-cluster replication)? Defer to a future multi-cluster ADR.
- For the AD-compat adapter, what is the conflict-resolution policy when the YAML and the AD site objects disagree? Default: YAML wins (declarative is source of truth); AD site objects are read-only in adapter mode. Confirm in implementation.
- Cross-reference PC-001 (DRSUAPI, DEFERRED) — the replication protocol determines whether `repsFrom` / `repsTo` are even the right abstraction. If the framework uses CRDT or Raft, the topology is a membership list, not a `repsFrom` graph. The adapter translates between the two representations.

## Cross-capability impact

- **Operations**: Topology monitoring is now YAML-diff-based rather than KCC-event-based. The `adrian-topology events` CLI replaces `repadmin /showrepl` for topology debugging.
- **Migration**: AD-to-framework migration preserves the site topology via the adapter; no manual YAML authoring required for the initial migration.
- **Client SDK**: Client discovery (`_ldap._tcp.dc._msdcs.<domain>` SRV records) is unaffected — the framework's DNS continues to publish DC locator records based on the topology.
- **Security**: Topology changes are auditable via git history and controller events; no more silent KCC decisions that may have inadvertently routed replication over an untrusted link.

## References

- [PC-016](../catalog/01-core-directory.md) — problem statement in the catalog
- [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) — KCC role in replication topology, ISTG concept
- [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) — Sites, subnets, site-links, KCC execution model
- [Kubernetes Controller Pattern](https://kubernetes.io/docs/concepts/architecture/controller/) — reconciliation loop model
- [HashiCorp Consul Architecture](https://developer.hashicorp.com/consul/docs/architecture) — declarative topology
- [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — AD sites, subnets, site-links
