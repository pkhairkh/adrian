---
title: "ADR-018: KDC as Horizontally-Scalable Stateless Pool Behind Load Balancer"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-033
severity: high
tags: [adr, kdc, kerberos, horizontal-scaling, stateless, hsm, cache]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/00-overview/02-ad-architecture.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ./ADR-009-constructed-attributes.md
  - ./ADR-015-krbtgt-hsm-rotation.md
last_updated: 2026-08-13
---

# ADR-018: KDC as Horizontally-Scalable Stateless Pool Behind Load Balancer

## Status

Accepted — 2026-08-13

## Context

Active Directory's KDC (`kdcsvc.dll`) runs in LSASS thread pool. Per-DC throughput is bounded by LSASS CPU — typically 1,000–5,000 AS-REQ/TGS-REQ per second on modern hardware. The 5-minute Kerberos skew window and PAC signing cost per AS-REQ/TGS-REQ add overhead: every AS-REQ requires a `PA-ENC-TIMESTAMP` decryption (PBKDF2 key derivation if AES, MD4 if RC4); every TGS-REQ requires a PAC construction (recursive group membership expansion, signing). At million-user forests, the KDC becomes the bottleneck, per [PC-033](../catalog/02-kdc.md#pc-033--kdc-throughput-at-million-object-scale-is-a-known-bottleneck), [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md), and [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Large enterprises (50K+ users with frequent auth — Exchange ActiveSync, file share access, web app logon) often require dedicated KDC DCs (without GC, without RID master) — DCs whose only role is to handle AS-REQ/TGS-REQ. The dedicated KDC DCs scale horizontally (one per N users), but each DC maintains its own krbtgt key share and PAC generation logic.

A framework should horizontally scale the KDC (stateless, share krbtgt key across N KDCs) and benchmark at scale. The stateless model requires: (a) shared krbtgt key (via Core Directory replication or a shared secret store — per ADR-015, this is the HSM); (b) shared service-account long-term keys (via Core Directory); (c) shared user long-term keys (via Core Directory). The KDC becomes a stateless service that reads from Core Directory on every AS-REQ/TGS-REQ — caching is critical (cache the user's NT hash, group memberships, SPN-to-account mapping).

Constraints from [PC-033](../catalog/02-kdc.md#pc-033--kdc-throughput-at-million-object-scale-is-a-known-bottleneck):

- KDC must share krbtgt key across instances (via Core Directory replication).
- KDC must share service-account long-term keys via directory.
- KDC must share user long-term keys via directory.
- KDC must cache aggressively (user NT hash, group memberships, SPN-to-account mapping) — but cache invalidation on password change / group membership change is critical.
- Must scale to 100K+ AS-REQ/sec at cloud scale.

## Decision

The framework SHALL deploy the KDC as a horizontally-scalable stateless pool behind a load balancer. Each KDC instance SHALL be stateless — no per-instance persistent state; all state is fetched from Core Directory (for principal data) and the HSM (for the krbtgt key, per ADR-015). Any KDC instance SHALL be able to service any AS-REQ or TGS-REQ; the load balancer SHALL distribute requests round-robin (or by least-connections).

The KDC pool SHALL share the krbtgt key via the HSM (per ADR-015). Every KDC instance fetches the krbtgt key from the HSM at boot and uses the HSM for all krbtgt-key cryptographic operations (TGT signing, TGT validation). The KDC instances do not exchange the krbtgt key directly — the HSM is the single source of truth.

The KDC pool SHALL share principal data via Core Directory. Every KDC instance caches principal data (user NT hash, group memberships, SPN-to-account mapping) with a configurable TTL (default 60 seconds). Cache invalidation SHALL be event-driven: when Core Directory applies a replication change that affects principal data (password change, group membership change, SPN change), Core Directory SHALL publish an invalidation event that all KDC instances subscribe to. The KDC instances SHALL evict the affected cache entries on receiving the event.

The KDC pool SHALL scale to 100K+ AS-REQ/sec at cloud scale. The pool size SHALL be configurable (default: 3 KDC instances; cloud-scale: 50+ instances). The load balancer SHALL perform health checks (KDC responds to a `GET /health` HTTP request) and remove unhealthy instances from the pool.

The framework SHALL expose a CLI command (`adrian-krb5 kdc-pool scale <N>`) that adjusts the pool size (manual scaling). The framework SHALL support autoscaling (the pool size adjusts automatically based on CPU utilization and request latency; default target: 60% CPU, <100 ms p99 latency).

The KDC instances SHALL produce identical PACs for the same principal — the PAC is a deterministic function of the principal's group memberships (fetched from Core Directory), the principal's SID (from Core Directory), and the krbtgt key (from the HSM). The framework's PAC construction code SHALL be deterministic; any KDC instance produces the same PAC for the same principal at the same point in time (modulo replication lag).

For AD-interop mode, the framework SHALL expose KDC instances via `_ldap._tcp.dc._msdcs.<domain>` SRV records (one SRV record per KDC instance), matching AD's DC locator mechanism. The framework's SRV records SHALL include KDC instances that are NOT GCs (dedicated KDC-only instances), matching AD's ability to deploy dedicated KDC DCs.

**Concrete specification**:

- The KDC SHALL be deployed as a horizontally-scalable stateless pool behind a load balancer. Each instance SHALL be stateless.
- The pool SHALL share the krbtgt key via the HSM (per ADR-015).
- The pool SHALL share principal data via Core Directory. Each instance caches principal data with configurable TTL (default 60 seconds).
- Cache invalidation SHALL be event-driven: Core Directory publishes invalidation events on password change, group membership change, SPN change; KDC instances subscribe and evict affected cache entries.
- The pool SHALL scale to 100K+ AS-REQ/sec at cloud scale. Pool size configurable (default 3; cloud-scale 50+).
- The load balancer SHALL perform health checks (`GET /health`) and remove unhealthy instances.
- The framework SHALL expose `adrian-krb5 kdc-pool scale <N>` CLI command for manual scaling.
- The framework SHALL support autoscaling based on CPU utilization (target 60%) and request latency (target <100 ms p99).
- KDC instances SHALL produce identical PACs for the same principal (deterministic PAC construction).
- For AD-interop mode, KDC instances SHALL be advertised via `_ldap._tcp.dc._msdcs.<domain>` SRV records.
- Performance target: a single KDC instance SHALL handle ≥5K AS-REQ/sec; a 10-instance pool SHALL handle ≥50K AS-REQ/sec.

## Rationale

The stateless-pool model is the standard horizontal-scaling pattern for read-heavy services. The KDC's per-request work is CPU-bound (PAC construction, encryption, signing); scaling horizontally adds linear throughput. The stateless model eliminates per-instance state management — any instance can service any request, and failed instances are replaced by the load balancer.

Three alternatives were considered:

**Alternative A — Sticky sessions (per-user KDC affinity).** The load balancer routes a user's AS-REQs to the same KDC instance (by source IP or by user DN). The advantage is better cache hit rate (the same instance caches the user's data). The disadvantage is hot-spot risk (a high-activity user overloads their assigned instance) and complexity (the load balancer must track affinity). Rejected as the primary mechanism; the event-driven cache invalidation makes the cache hit rate acceptable without affinity.

**Alternative B — Per-realm KDC pool (one pool per realm, no cross-realm sharing).** Each realm has its own KDC pool; cross-realm TGS-REQs are routed to the target realm's pool. The advantage is isolation (a busy realm does not affect other realms). The disadvantage is operational complexity (one pool per realm × N realms = N pools to manage). Rejected as the primary mechanism; the framework SHALL support per-realm pools as a deployment option, but the default is a per-forest pool shared across realms (with per-realm KDC configuration).

**Alternative C — Embedded KDC in Core Directory (single-process).** The KDC runs in the same process as the Core Directory DSA, sharing memory and avoiding the cross-process cache-invalidation overhead. The advantage is simplicity (no separate KDC service). The disadvantage is the AD model — KDC throughput is bounded by LSASS CPU (which also handles LDAP, replication, GC). Rejected because the framework's design separates KDC from Core Directory for independent scaling.

External evidence: [MIT krb5 `krb5kdc`](https://web.mit.edu/kerberos/krb5-1.21/doc/admin/admin_commands/krb5kdc.html) is a single-process-per-host KDC; Samba 4's KDC has the same model; Microsoft's [Azure AD DS](https://learn.microsoft.com/en-us/azure/active-directory-domain-services/) uses a sharded KDC pool for cloud-scale. The framework's design matches the cloud-native pattern.

The cost of this decision is the event-driven cache-invalidation infrastructure (Core Directory must publish invalidation events; KDC instances must subscribe). This is a small incremental cost over the existing Core Directory replication infrastructure — invalidation events piggyback on the replication apply path.

## Consequences

**Positive**: The KDC scales horizontally to 100K+ AS-REQ/sec at cloud scale. Any KDC instance can service any request; failed instances are replaced by the load balancer. Cache hit rate is high (event-driven invalidation keeps the cache fresh). PAC construction is deterministic across instances.

**Negative**: The event-driven cache-invalidation infrastructure adds complexity (Core Directory must publish events; KDC instances must subscribe). Cache staleness window is the event-propagation latency (typically <1 second within a DC, longer cross-DC). The HSM is a shared dependency — if the HSM fails, all KDC instances fail.

**Neutral**: The stateless model is invisible to clients — they see the same Kerberos protocol regardless of which KDC instance services their request. Operators see the pool size and per-instance metrics via `adrian-krb5 kdc-pool status`.

**Implementation cost**: ~8 person-weeks for the stateless KDC, the event-driven cache-invalidation infrastructure, the load-balancer integration, the autoscaler, and the CLI commands. The bulk of the work is the cache-invalidation event infrastructure.

**Operational impact**: KDC throughput scales linearly with pool size. Dedicated KDC instances (no GC, no RID master) are supported. Autoscaling reduces operational burden. SIEM queries for AS-REQ / TGS-REQ per instance (per ADR-023) provide per-instance monitoring.

## Alternatives Considered

### Alternative 1: Sticky sessions (per-user KDC affinity)

Better cache hit rate; hot-spot risk and load-balancer complexity. Rejected as primary; the event-driven cache invalidation makes the cache hit rate acceptable without affinity.

### Alternative 2: Per-realm KDC pool (one pool per realm)

Isolation; operational complexity (N pools to manage). Rejected as primary; the framework SHALL support per-realm pools as a deployment option, but the default is a per-forest pool shared across realms.

### Alternative 3: Embedded KDC in Core Directory (single-process)

Simplicity; KDC throughput bounded by LSASS CPU. Rejected because the framework's design separates KDC from Core Directory for independent scaling.

## Open Questions

- For the event-driven cache invalidation, what is the propagation latency cross-DC? The framework's replication latency is typically <30 seconds; the cache-invalidation event should propagate faster (urgent replication path, <5 seconds). Confirm in implementation.
- For the autoscaler, what are the scaling thresholds? Default: scale-up at 60% CPU or p99 latency >100 ms; scale-down at 30% CPU and p99 latency <50 ms. Configurable per-deployment.
- Cross-reference ADR-009 (constructed attributes) — `tokenGroups` caching strategy is deferred to ORQ-032. The KDC's PAC builder uses the same cache as `tokenGroups`; ORQ-032 resolution affects this ADR.
- Cross-reference ADR-015 (krbtgt HSM) — the HSM is the shared dependency for the krbtgt key. HSM failover is critical; the framework SHALL support HSM high-availability (multiple HSM instances with key replication).

## Cross-capability impact

- **Core Directory**: Core Directory must publish invalidation events on password change, group membership change, SPN change. This is a small extension to the existing replication-apply path.
- **Auth Provider**: Auth Provider's Kerberos SSPI-equivalent benefits from the KDC pool's horizontal scaling — auth latency is bounded by the pool's p99 latency, not by a single KDC's CPU.
- **Operations**: KDC pool monitoring (`adrian-krb5 kdc-pool status`), autoscaling, and per-instance metrics are standard ops tasks.
- **Migration**: AD-to-framework migration replaces AD's per-DC KDC with the framework's KDC pool. Clients discover KDC instances via SRV records (no client-side change).
- **Security**: Per-instance audit events (per ADR-023) enable SIEM detection of Kerberoasting, AS-REP roasting, golden ticket across the pool. The deterministic PAC construction ensures no instance-specific anomalies.

## References

- [PC-033](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) — LSASS thread pool, KDC scaling ceiling, dedicated KDC DCs
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — KDC PAC construction cost, etype negotiation overhead
- [MIT krb5 `krb5kdc`](https://web.mit.edu/kerberos/krb5-1.21/doc/admin/admin_commands/krb5kdc.html) — single-process KDC
- [Azure AD DS](https://learn.microsoft.com/en-us/azure/active-directory-domain-services/) — cloud-scale sharded KDC pool
- [RFC 4120 §3](https://www.rfc-editor.org/rfc/rfc4120#section-3) — Kerberos V5 KDC requirements
