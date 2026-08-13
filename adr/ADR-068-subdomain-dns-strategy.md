---
title: "ADR-068: Subdomain-per-Directory DNS Strategy for Migration"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Migration
problem: PC-128
severity: medium
tags: [adr, migration, dns, zone-delegation, split-brain, gss-tsig, coexistence]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/12-migration-and-coexistence.md
  - ../docs/02-protocols/05-dns-dynamic-updates.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ./ADR-069-cross-realm-capaths.md
last_updated: 2026-08-13
---

# ADR-068: Subdomain-per-Directory DNS Strategy for Migration

## Status

Accepted — 2026-08-13

## Context

During AD→framework migration, both directories may serve the same DNS namespace (e.g. `corp.example.com`). AD-integrated DNS zones replicate via DRSUAPI as `dnsNode` objects in the `DomainDnsZones` and `ForestDnsZones` application partitions. The framework's DNS may use CoreDNS, BIND, or a cloud DNS service. Two directories serving the same zone = split-brain DNS, with no inherent conflict resolution.

The conflict scenarios: (a) both directories claim to be authoritative for `_ldap._tcp.dc._msdcs.corp.example.com` SRV records — clients resolve to whichever DNS server they query first, leading to inconsistent DC discovery; (b) host A records created by AD dynamic updates (RFC 2136) may conflict with framework-managed A records — last-writer-wins, but the writer is non-deterministic; (c) GSS-TSIG authenticated dynamic updates (RFC 3645) require the client to have a TGT for the DNS server's realm — during parallel-run, a client may have TGTs for both AD and the framework, but each DNS server only accepts GSS-TSIG from its own realm.

The standard solution is zone delegation: split the namespace into `ad.corp.example.com` (served by AD) and `new.corp.example.com` (served by the framework) during the coexistence period. Clients that need to find AD DCs query `_ldap._tcp.dc._msdcs.ad.corp.example.com`; clients that need to find framework DCs query `_ldap._tcp.dc._msdcs.new.corp.example.com`. The forest-root zone `corp.example.com` is served by a neutral DNS that delegates each subdomain to the appropriate directory. After migration, the `ad.corp.example.com` subdomain is decommissioned and `corp.example.com` is fully managed by the framework.

The alternative is per-record migration: keep the same namespace but migrate records one at a time from AD-managed to framework-managed. Each A/SRV record migration requires: (a) stop AD dynamic updates for the record, (b) delete the record from AD DNS, (c) create the record in framework DNS, (d) verify resolution. This is operationally tedious for large namespaces (10,000+ records) but allows gradual migration without changing the namespace.

The framework must support both zone delegation and per-record migration. The framework's DNS server must support GSS-TSIG authenticated dynamic updates for AD-interop scenarios. The framework must provide a DNS-migration tool that automates per-record migration with conflict detection.

## Decision

The framework adopts subdomain-per-directory DNS as the primary migration strategy and per-record migration as the secondary strategy for organisations that cannot change the namespace. The subdomain-per-directory strategy splits the namespace into `ad.<forest-root>` (served by AD) and `fwk.<forest-root>` (served by the framework) during the coexistence period; after migration, the framework's DNS becomes authoritative for the forest-root zone and the AD subdomain is decommissioned. Per-record migration is supported via a tool (`adrian-cli dns migrate`) that automates the stop-update-delete-create-verify cycle for each record.

The framework's DNS server (CoreDNS or BIND, depending on the deferred PC-019 decision) supports RFC 2136 dynamic updates, RFC 3645 GSS-TSIG authentication, and RFC 2782 SRV records for service discovery. The framework ships a CoreDNS plugin (or BIND zone configuration) that exposes the framework's DC-discovery SRV records (`_ldap._tcp.dc._msdcs.fwk.<forest-root>`, `_kerberos._tcp.fwk.<forest-root>`, `_kpasswd._tcp.fwk.<forest-root>`, `_gc._tcp.fwk.<forest-root>`).

The framework's neutral DNS (the one that delegates to AD and the framework subdomains) is a CoreDNS or BIND instance managed by the framework's operator. It serves the forest-root zone (`corp.example.com`) and delegates `ad.corp.example.com` to the AD DCs' DNS and `fwk.corp.example.com` to the framework DCs' DNS. The neutral DNS is the configured DNS server for all client machines during the migration.

For GSS-TSIG authenticated dynamic updates during the coexistence period, the framework's DNS server accepts updates from both AD-realm clients (with a cross-realm trust per ADR-069) and framework-realm clients. The framework's DNS server uses the framework's KDC to validate the GSS-TSIG tokens for framework-realm clients and uses the cross-realm trust to validate AD-realm clients.

**Concrete specification**:

- The framework MUST deploy a "neutral DNS" instance (CoreDNS or BIND) that serves the forest-root zone (`<forest-root>`) and delegates `ad.<forest-root>` to the AD DCs' DNS and `fwk.<forest-root>` to the framework DCs' DNS.
- The neutral DNS MUST be the configured DNS server for all client machines during the migration (`/etc/resolv.conf` on Linux, Network Settings on macOS, DNS Client on Windows).
- The framework's DNS server MUST expose the following SRV records under `fwk.<forest-root>`:
  - `_ldap._tcp.fwk.<forest-root> SRV 0 100 389 <framework-dc>.fwk.<forest-root>`
  - `_ldap._tcp.dc._msdcs.fwk.<forest-root> SRV 0 100 389 <framework-dc>.fwk.<forest-root>`
  - `_kerberos._tcp.fwk.<forest-root> SRV 0 100 88 <framework-dc>.fwk.<forest-root>`
  - `_kerberos._udp.fwk.<forest-root> SRV 0 100 88 <framework-dc>.fwk.<forest-root>`
  - `_kpasswd._tcp.fwk.<forest-root> SRV 0 100 464 <framework-dc>.fwk.<forest-root>`
  - `_gc._tcp.fwk.<forest-root> SRV 0 100 3268 <framework-dc>.fwk.<forest-root>`
- The framework's DNS server MUST support RFC 2136 dynamic updates and RFC 3645 GSS-TSIG authentication for AD-interop scenarios.
- The framework's DNS server MUST accept GSS-TSIG-authenticated dynamic updates from both framework-realm clients and AD-realm clients (via the cross-realm trust per [ADR-069](./ADR-069-cross-realm-capaths.md)).
- The framework MUST ship a DNS-migration tool `adrian-cli dns migrate` that supports per-record migration:
  - `adrian-cli dns migrate --record <name> --type <type> --from ad --to fwk`: stops AD dynamic updates for the record, deletes from AD DNS, creates in framework DNS, verifies resolution.
  - The tool MUST detect conflicts (e.g. the record exists in both AD and framework DNS with different values) and prompt for resolution.
  - The tool MUST preserve a rollback record-set for each migrated record (the previous AD DNS value) for 30 days.
- The framework MUST ship a DNS-rollback tool `adrian-cli dns rollback --record <name>` that restores the previous AD DNS value.
- The framework's DNS server MUST log every dynamic update (success or failure) as an OTel audit event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with attributes `adrian.dns.record`, `adrian.dns.type`, `adrian.dns.operation`, `adrian.dns.client.realm`, `adrian.dns.client.principal`, `adrian.dns.result`.
- The framework MUST ship a default Prometheus alert: `rate(adrian_dns_update_failures_total[5m]) > 10` triggers a warning alert (DNS update failures indicate GSS-TSIG misconfiguration or replication issues).
- The framework MUST document the post-migration DNS cutover procedure: (a) verify all clients are using `fwk.<forest-root>` SRV records, (b) delete the `ad.<forest-root>` delegation from the neutral DNS, (c) update the neutral DNS to serve the `<forest-root>` zone directly from the framework's DNS (the `fwk.` prefix is removed), (d) update all client configurations to use the framework's DNS as the authoritative server for `<forest-root>`.
- For air-gapped or single-forest deployments where subdomain-per-directory is not feasible, the framework MUST support per-record migration as the primary strategy.

## Migration state machine

**Source state**: AD-integrated DNS zone `corp.example.com` with `_ldap._tcp.dc._msdcs` SRV records pointing to AD DCs. AD clients query this zone for DC discovery.

**Target state**: Framework-managed DNS zone `corp.example.com` (after cutover) with `_ldap._tcp.dc._msdcs` SRV records pointing to framework DCs. The `ad.` and `fwk.` subdomains are decommissioned.

**Coexistence period**: 90–365 days. During this window:
- Neutral DNS serves `corp.example.com` and delegates `ad.corp.example.com` (to AD DCs) and `fwk.corp.example.com` (to framework DCs).
- AD-enrolled clients query `ad.corp.example.com` for DC discovery.
- Framework-enrolled clients query `fwk.corp.example.com` for DC discovery.
- Per-record migration tool is used for records that must be in both zones (e.g. host A records for applications that must resolve from both AD and framework clients).

**Cutover trigger**: When 100% of DNS records have been migrated (per-record migration path) or when the AD subdomain has had no queries for ≥30 days (subdomain-per-directory path), the AD DNS zone is decommissioned and the framework's DNS becomes authoritative for `corp.example.com`.

**Rollback path**: Re-delegate the zone back to AD DNS (`ad.corp.example.com` becomes `corp.example.com` again). Re-create any migrated records in AD DNS. The framework's DNS-migration tool preserves a rollback record-set for each migrated record (30 days). Rollback is documented and tested quarterly.

## Rationale

Subdomain-per-directory is the safest migration strategy because it provides clean isolation: AD clients see only AD DCs; framework clients see only framework DCs. There is no split-brain; there is no record conflict; GSS-TSIG works because each DNS server only accepts updates from its own realm. The downside is that clients must be reconfigured to query the correct subdomain — but this is a one-time change that the framework's enrollment process handles automatically.

Per-record migration is the alternative for organisations that cannot change the namespace (e.g. applications hardcoded to `corp.example.com`). The per-record migration tool automates the tedious stop-update-delete-create-verify cycle, with conflict detection and rollback. The tool is slower than subdomain-per-directory (one record at a time) but does not require namespace changes.

The neutral DNS is necessary to provide a single DNS server that all clients query, regardless of whether they are AD-enrolled or framework-enrolled. The neutral DNS delegates to the appropriate subdomain based on the query. Without a neutral DNS, clients would need to be reconfigured to query different DNS servers based on their enrollment — a non-starter for large fleets.

GSS-TSIG cross-realm support is necessary because during the coexistence period, some clients may need to update DNS records in both AD and the framework (e.g. a client that is being migrated and needs to update its host A record in both directories). The cross-realm trust (per ADR-069) enables the framework's DNS to validate AD-realm GSS-TSIG tokens.

The 30-day rollback record-set retention is the safety net. If a per-record migration breaks an application (e.g. the application hardcoded to the old IP), the operator can roll back the specific record without rolling back the entire migration.

## Consequences

**Positive**: Split-brain DNS is eliminated during coexistence. AD clients and framework clients can coexist without DNS conflicts. Per-record migration enables gradual migration for organisations that cannot change the namespace. The DNS-migration tool automates the tedious manual process. Rollback is per-record (granular) and tested quarterly.

**Negative**: Clients must be reconfigured to query the correct subdomain during coexistence (subdomain-per-directory path). The neutral DNS is a new infrastructure component that must be deployed and managed. GSS-TSIG cross-realm support adds complexity to the framework's DNS server. The 30-day rollback record-set retention consumes storage (minor).

**Neutral**: The framework's DNS strategy does not preclude other DNS architectures (e.g. cloud DNS services, enterprise DNS appliances) — the neutral DNS can be any RFC 1035-compliant DNS server that supports zone delegation.

**Implementation cost**: ~3 person-months for the CoreDNS/BIND plugin (SRV record exposure, GSS-TSIG validation); ~2 person-months for the neutral DNS deployment and the operator integration; ~3 person-months for the DNS-migration tool (per-record migration, conflict detection, rollback); ~1 person-month for the audit integration and Prometheus alerts. Total: ~9 person-months for v1.

**Operational impact**: DNS administrators manage the neutral DNS via the framework's operator (CRD-based configuration). Migration teams use `adrian-cli dns migrate` for per-record migration. SOC analysts see DNS update events in the audit pipeline. The post-migration cutover is a documented runbook.

## Alternatives Considered

**Alternative A: Per-record migration only (no subdomain-per-directory).** Keep the same namespace throughout migration; migrate records one at a time. Rejected as the primary path because (a) it does not solve the split-brain problem for SRV records (both AD and the framework would claim to be authoritative for `_ldap._tcp.dc._msdcs.corp.example.com`), (b) it is operationally tedious for large namespaces, (c) it does not provide clean isolation during coexistence. Per-record migration is the secondary path for organisations that cannot change the namespace.

**Alternative B: AD-integrated DNS only (framework uses AD DNS).** The framework's DCs register their SRV records in AD-integrated DNS (via RFC 2136 dynamic updates with GSS-TSIG). Rejected because (a) it couples the framework to AD DNS (the framework cannot migrate away from AD DNS until the framework's own DNS is authoritative), (b) AD-integrated DNS has its own limitations (replication via DRSUAPI, no native multi-region support), (c) it does not provide a clean migration path (the framework must eventually serve its own DNS).

**Alternative C: Cloud DNS (AWS Route53, Google Cloud DNS, Azure DNS) only.** Use a cloud DNS service for the framework's DNS. Rejected as the primary path because (a) it couples the framework to a specific cloud provider, (b) it does not support GSS-TSIG authenticated dynamic updates (cloud DNS services typically use API-key auth), (c) it does not work for air-gapped or on-premises deployments. Cloud DNS may be used as the neutral DNS in cloud deployments.

**Alternative D: mDNS (multicast DNS) for service discovery.** Use mDNS (RFC 6762) for DC discovery instead of unicast DNS. Rejected because (a) mDNS is for local-network service discovery only (it does not scale beyond a single subnet), (b) mDNS does not support authenticated dynamic updates, (c) mDNS is not interoperable with AD's DNS-based DC discovery.

## Open Questions

None — this is an ADR-ELIGIBLE decision. The DNS server choice (PC-019, deferred) does not gate this decision: the subdomain-per-directory strategy and the per-record migration tool work with any RFC 1035-compliant DNS server that supports RFC 2136 and RFC 3645.

## Cross-capability impact

- **Core Directory (PC-019)**: DNS in-directory vs external CoreDNS (PC-019, deferred) — this ADR works with either; the framework's DNS server is the same component regardless of whether it is in-directory or external.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — DNS update failures are a Prometheus metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — DNS update events are part of the audit pipeline.
- **Operations (PC-115)**: ADR-063 (unified CLI) — the `dns` subcommand exposes `migrate`, `rollback`, `zone list`, `record add`, `record delete`.
- **Migration (PC-126)**: Client switchover (PC-126, deferred) — clients are reconfigured to query `fwk.<forest-root>` for DC discovery during the switchover.
- **Migration (PC-129)**: ADR-069 (cross-realm capaths) — KDC discovery via DNS SRV (`_kerberos._tcp.fwk.<forest-root>`) is part of the cross-realm setup.
- **Security (PC-117)**: DCSync detection (PC-117, deferred) — DNS update events can indicate DCSync attempts (a non-DC principal updating DNS records is suspicious).

## References

- [PC-128](../catalog/12-migration-and-coexistence.md) — problem statement (DNS namespace sharing during migration requires careful zone delegation)
- [DNS dynamic updates](../docs/02-protocols/05-dns-dynamic-updates.md) — AD-integrated DNS zone storage (`DomainDnsZones` and `ForestDnsZones` application partitions), `dnsNode` object schema, RFC 2136 dynamic update protocol, RFC 3645 GSS-TSIG authentication
- [Trusts topology](../docs/03-directory-schema/04-trusts-topology.md) — `trustedDomain` object that the framework's DCs and AD DCs use to discover each other; DNS SRV records drive DC-discovery which the trust depends on
- [RFC 1035 — Domain Names Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 2136 — Dynamic Updates in the Domain Name System (DNS UPDATE)](https://datatracker.ietf.org/doc/html/rfc2136)
- [RFC 2782 — DNS SRV Records](https://datatracker.ietf.org/doc/html/rfc2782)
- [RFC 3645 — Generic Security Service Algorithm for Secret Key Transaction Authentication for DNS (GSS-TSIG)](https://datatracker.ietf.org/doc/html/rfc3645)
- [MS-DNSP — Domain Name Service (DNS) Server Management Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/)
