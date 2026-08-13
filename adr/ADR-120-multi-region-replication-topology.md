---
title: "ADR-120: Multi-Region Replication — Hybrid DRSUAPI + Raft with Locality-Aware Leader Placement"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-108
severity: high
tags: [adr, operations, multi-region, replication, raft, drsuapi, pdc-urgent, locality-aware]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/00-overview/04-fsmo-roles.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ../workshop/decision-01-replication-protocol.md
  - ./ADR-001-linked-value-replication.md
  - ./ADR-058-container-native-dcs-operator.md
last_updated: 2026-08-13
---

# ADR-120: Multi-Region Replication — Hybrid DRSUAPI + Raft with Locality-Aware Leader Placement

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 1 (replication)](../workshop/decision-01-replication-protocol.md) and [Decision 2 (FoundationDB)](../workshop/decision-02-storage-engine.md). This ADR specifies the multi-region topology for both AD-interop and native replication modes.

## Context

AD replication topology is computed by the KCC every 15 minutes (`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\KCC Idle Duration Between Runs = 1800` sec). Intra-site replication is change-notification-driven (15-second default). Inter-site replication is scheduled, LZ77+Huffman-compressed via `ntdsa.dll!MDSCompressionCompress`, and bounded by the site-link cost and schedule window — defaults to 15–180 seconds per hop. For a 3-region deployment (US-East, US-West, EU), an originating write at US-East propagates to EU in 30–360 seconds depending on schedule and link utilisation, per the analysis in [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) and [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md).

Password changes are special: they trigger urgent replication. The DC that accepted the change immediately single-replicates the new `unicodePwd` to the PDC emulator FSMO holder (within 15 seconds). Every DC, on a failed logon with the old password, falls back to the PDC before rejecting. This mechanism is what makes "user changed password 30 seconds ago in EU; user is now in US and logs in" work — but it only works for password changes, not for general attribute writes. A new group membership added in EU takes the normal replication interval to reach US; a user in US logging in immediately after will not see the new group in their PAC.

Modern multi-region systems expect active-active with sub-second convergence. CRDTs (last-writer-wins with vector clocks, or operation-based CRDTs) can converge in milliseconds. AD's pull-based state replication with UTD vectors converges in tens of seconds to minutes. Workshop Decision 1 chose a **hybrid**: DRSUAPI (fresh Rust implementation) for AD-interop mode (inherits AD's convergence semantics), Raft for native mode (strict serializability with sub-second convergence). Decision 2 chose FoundationDB as the storage engine, whose strict-serializable transactions and native multi-region deployment topology are the substrate for fast convergence.

## Decision

The framework's multi-region topology is **mode-dependent** and **driven by a declarative YAML site model** (per ADR-008's declarative topology). In AD-interop mode, the framework inherits AD's site-link topology with one operational improvement: the framework's `DrSuapiReplicator` compresses inter-site replication payloads with zstd (matching AD's LZ77+Huffman compression ratio at lower CPU) and supports a configurable `replInterval` floor of 5 seconds (vs. AD's 15-second KCC floor) for urgent inter-site replication. In native mode, the framework uses `openraft` with **locality-aware leader placement**: the Raft leader is pinned to a configurable "primary region" by default, but the framework's `RaftNetwork` implementation routes follower-append requests over the lowest-latency path between regions, and committed entries are visible to followers in all regions within the Raft log-replication round-trip (typically 50–200 ms cross-region).

For password changes in native mode, the framework does **not** replicate urgent-style — Raft replicates every committed entry immediately, so password changes are visible to all DCs in all regions within one Raft round-trip (≤200 ms typical). For AD-interop mode, the framework inherits AD's PDC-urgent-replication behaviour: the DC that accepted the password change single-replicates to the PDC emulator (which is one of the framework's AD-interop DCs) within 5 seconds (the framework's reduced floor), and other DCs pull from the PDC on the next intra-site cycle (≤5 s) or inter-site cycle (≤30 s default).

The framework exposes a **multi-region health dashboard** with per-region, per-NC, per-partner latency, queue depth, and last-success-USN (or Raft log-index in native mode). The dashboard is the framework's `adrian-repl-health` CLI and the `GET /api/v1/replication/health?region=<region>` REST endpoint, equivalent to `repadmin /showrepl /csv` but with multi-region aggregation.

**Concrete specification**:

- The framework MUST accept a declarative site model in `adrian-topology.yaml` containing: `sites` (name, region, lat/long for cost computation), `links` (from-site, to-site, cost, schedule, `replInterval` floor), `primary_region` (native-mode Raft leader placement), `pdc_site` (AD-interop-mode PDC emulator placement).
- The framework's topology-controller (per ADR-008) MUST reconcile the site model into: (a) DrSuapiReplicator's `repsFrom`/`repsTo` connection objects in AD-interop mode; (b) `openraft`'s `RaftNetwork` peer configuration in native mode.
- In AD-interop mode, the framework's DrSuapiReplicator MUST support a configurable `replInterval` floor of 5 seconds (default; range 5–180 s) for both intra-site and inter-site change-notification. The framework MUST log a warning if the configured floor is below 5 seconds (sub-5-second replication causes KCC instability on AD partners).
- In AD-interop mode, the framework's DrSuapiReplicator MUST implement PDC urgent replication: on a `unicodePwd` write, the receiving DC MUST single-replicate to the PDC emulator within 5 seconds (vs. AD's 15 seconds). The PDC emulator is identified via the framework's FSMO-lease mechanism (per Decision 1's FSMO-lease-replaces-FSMO-role model in native mode, or the AD-interop FSMO holder in AD-interop mode).
- In native mode, the framework's `RaftReplicator` MUST replicate every committed entry to all followers within one Raft round-trip. The `openraft` configuration MUST set `heartbeat_interval = 100ms` and `election_timeout_min = 800ms`, `election_timeout_max = 1200ms` (matching `openraft` defaults but tuned for cross-region deployments where 200 ms RTT is typical).
- In native mode, the framework's `RaftReplicator` MUST support locality-aware leader placement: the leader is pinned to the `primary_region` configured in the site model. If the primary region loses quorum (e.g. regional outage), the leader fails over to a configurable `secondary_region`. Leader-pinning is implemented via `openraft`'s `RaftLeader` custom-election hook that prefers voters in the primary region.
- The framework MUST expose `adrian-repl-health status --region <region>` returning per-NC, per-partner {latency_p50, latency_p99, last_success_usn, last_error, queue_depth, convergence_lag_seconds} for AD-interop mode, and {leader_region, follower_lag_entries, follower_lag_seconds, commit_index, applied_index} for native mode.
- The framework MUST expose `GET /api/v1/replication/health?region=<region>` (REST, per ADR-061) returning the same data as the CLI in JSON.
- The framework MUST emit a Prometheus metric `adrian_repl_convergence_lag_seconds{mode,nc,region}` (per ADR-057) — the time from originating-write to all-DCs-applied. In native mode this is bounded by Raft round-trip (≤200 ms typical); in AD-interop mode this is bounded by the KCC cycle + site-link cost (5–180 s typical).
- The framework MUST ship default Prometheus alerts: (a) `adrian_repl_convergence_lag_seconds > 30 for 5m` triggers warning; (b) `adrian_repl_convergence_lag_seconds > 300 for 5m` triggers critical (the framework's lingering-object threshold); (c) in native mode, `raft_leader_changes_total > 5 for 10m` triggers warning (leader instability).
- The framework's operator (per ADR-058) MUST treat a DC with `convergence_lag_seconds > 900` (15 minutes) as not-ready and remove it from the LDAP/Kerberos service endpoints. The DC rejoins the endpoints when convergence catches up.
- The framework MUST support cross-region FDB deployment in native mode: FDB's built-in multi-region replication (satellite redundancy + remote replicas) provides the storage-layer convergence; the Raft layer on top provides the directory-layer consensus. FDB's `redacted` configuration option keeps secrets (NT hashes, krbtgt key) in the primary region only, with hash-only replication to remote regions.
- For AD-interop mode, the framework's DrSuapiReplicator MUST support change-notification on inter-site connection objects (the `options` flag `NTDSCONN_OPT_USE_NOTIFY = 0x1`), reducing inter-site convergence to ≤5 seconds when both endpoints support it (the framework always does; AD does by default intra-site, opt-in inter-site).

## Rationale

The hybrid model (Decision 1) gives the framework two operating points: AD-interop mode inherits AD's convergence characteristics (with the framework's reduced 5-second floor and zstd compression), native mode achieves sub-second convergence via Raft. The framework's value proposition is offering both — AD-interop customers get a like-for-like replacement that they can later upgrade to native; native customers get modern convergence without AD's UTD-vector baggage.

Locality-aware leader placement in native mode is the key operational property. A naive Raft deployment puts the leader wherever the election happens to land — typically the region with the lowest-latency voters, which may not be the region with the most users. The framework's site model lets the operator pin the leader to the primary user region, minimising write latency for the majority of users. Cross-region follower lag (typically 50–200 ms) is acceptable for reads because the framework's read-your-writes consistency is enforced at the FDB layer (per Decision 2), not at the Raft layer.

The 5-second `replInterval` floor in AD-interop mode is the framework's improvement over AD's 15-second floor. The framework's DrSuapiReplicator is fresh Rust (per Decision 1) and is not bound by AD's KCC cadence; the framework can issue change-notifications as fast as the network allows. The 5-second floor is conservative because sub-5-second notifications cause KCC topology recomputation on AD partners (the KCC sees the rapid notifications as a sign of instability and recomputes the topology). 5 seconds is the empirical sweet spot.

PDC urgent replication in AD-interop mode preserves AD's password-change behaviour. Users who change their password in one region and immediately authenticate in another region expect the new password to work. AD achieves this via PDC-urgent-replication; the framework inherits the mechanism. In native mode, the framework does not need urgent-replication because Raft replicates every committed entry immediately — password changes are visible to all DCs within one Raft round-trip, which is faster than AD's PDC-urgent mechanism.

The convergence-lag Prometheus metric is the single most important operational signal. AD's `repadmin /showrepl` is reactive (admin runs it when something breaks); the framework's Prometheus metric is proactive (alerting fires before users notice). The 30-second warning threshold catches transient lag; the 300-second critical threshold catches lingering-object-class lag. The 900-second (15-minute) not-ready threshold prevents a lagging DC from serving stale data to clients.

## Consequences

**Positive**: Native-mode deployments achieve sub-second convergence (vs. AD's 30–360 seconds). AD-interop mode inherits AD's behaviour with a 3× improvement (5-second vs. 15-second floor). Multi-region health is observable via Prometheus + the framework's CLI/REST. Cross-region FDB deployment provides storage-layer redundancy independent of the directory layer.

**Negative**: Native mode does not support RODC (per Decision 1's trade-off) — branch-office scenarios must use AD-interop mode. The locality-aware leader placement introduces a "primary region" concept that operators must manage (a regional outage requires manual or automated leader failover to the secondary region). The 5-second floor in AD-interop mode may stress AD partners on slow WAN links (the framework logs a warning).

**Neutral**: The hybrid model means the framework ships two replication implementations; the test matrix is doubled (per Decision 1's trade-off). The site model is a new operational artefact (per ADR-008) but it is also the substrate for FSMO-lease placement, KCC-equivalent topology computation, and DNS SRV record publication.

**Implementation cost**: ~4 person-months for the multi-region topology-controller integration, the `adrian-repl-health` CLI/REST, the Prometheus metric, and the locality-aware leader-placement hook. Reuses Decision 1's `adrian-repl-core`, `adrian-drsuapi`, `adrian-raft` crates.

**Operational impact**: SREs monitor `adrian_repl_convergence_lag_seconds` per region; the operator auto-removes lagging DCs from service endpoints. Migration teams use the multi-region dashboard during parallel-run to verify cross-region convergence before cutover.

## Alternatives Considered

**Alternative A: Raft-only, abandon AD-interop.** Use Raft for all forests, refusing to interop with AD's DRSUAPI. Rejected by Decision 1 because it breaks every AD-interop scenario — mixed-forest replication, ADMT migration, parallel-run, RODC at branch sites, cross-trust access. PC-126 (parallel-run switchover) requires DRSUAPI on the wire. The hybrid model preserves DRSUAPI for AD-interop and Raft for native.

**Alternative B: AD-interop only, abandon Raft.** Use DRSUAPI for all forests, accepting AD's convergence characteristics even for greenfield deployments. Rejected by Decision 1 because customers who choose the framework to escape AD's quirks (USN rollback, lingering objects, FSMO bottlenecks, 30–360-second convergence) would be disappointed. Native mode's Raft provides strict serializability and sub-second convergence.

**Alternative C: CRDT-shim (DRSUAPI wire over an internal CRDT OR-set).** Translate between DRSUAPI and an internal CRDT representation at the wire boundary. Rejected by Decision 1 because the translation layer adds 30% CPU overhead and 1.7× replication latency (per Spike 1's measurements). The CRDT's tombstone vectors do not map cleanly to AD's `PROPERTY_META_DATA_EXT` four-tuple, requiring lossy synthesis.

**Alternative D: Multi-master without consensus (last-writer-wins on wall-clock).** Use AD's LWW model in native mode, abandoning Raft's strict serializability. Rejected because (a) LWW on wall-clock is unsafe under clock skew (a 500 ms skew can flip the winner); (b) Raft's strict serializability is a selling point of native mode; (c) FDB's strict-serializable transactions (per Decision 2) make Raft simpler to implement than LWW-with-vector-clocks would be.

## Open Questions

None. Workshop Decision 1 resolved the replication-protocol ORQ-001/002/003/004 that gated this ADR. The multi-region topology is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-001/PC-002)**: This ADR is the Operations-side realisation of Decision 1's `Replicator` trait; no new replication surface.
- **Core Directory (PC-009)**: Lingering-object detection (per Decision 1) is enforced at the framework's `StrictReplicationConsistency` boundary — a DC whose `convergence_lag_seconds > tombstoneLifetime` is quarantined.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_repl_convergence_lag_seconds` is a key Prometheus metric.
- **Operations (PC-110)**: ADR-059 (PITR backup/DR) — multi-region FDB deployment provides cross-region backup redundancy; the operator's DR runbook covers regional-outage scenarios.
- **Operations (PC-115)**: ADR-063 (unified CLI) — `adrian-repl-health` is a subcommand.
- **Security (PC-117)**: ADR-122 (DCSync) — multi-region replication does not change the DCSync attack surface; the same ACL checks apply in both modes.
- **Migration (PC-126)**: Parallel-run requires cross-realm trust; the framework's multi-region topology must include both AD-interop DCs (for AD-interop traffic) and native DCs (for native traffic) during the parallel-run window.

## References

- [PC-108](../catalog/10-operations.md) — problem statement (multi-region AD replication latency; PDC urgent replication)
- [FSMO roles KB](../docs/00-overview/04-fsmo-roles.md) — PDC emulator, urgent replication, inter-site topology
- [Replication internals KB](../docs/03-directory-schema/05-replication-internals.md) — USN/UTD vector, inter-site compression, event 2095/2042
- [Workshop Decision 1 — Replication protocol](../workshop/decision-01-replication-protocol.md) — hybrid DRSUAPI + Raft; `Replicator` trait; FSMO-lease in native mode
- [Workshop Decision 2 — Storage engine](../workshop/decision-02-storage-engine.md) — FoundationDB strict-serializable transactions; multi-region FDB deployment
- [ADR-001 — Linked Value Replication](./ADR-001-linked-value-replication.md) — per-value `PROPERTY_META_DATA_EXT` metadata shared by both modes
- [ADR-008 — Declarative YAML replication topology](./ADR-008-declarative-replication-topology.md) — topology-controller reconciles site model
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — `adrian_repl_convergence_lag_seconds` metric
- [ADR-058 — Container-native DCs operator](./ADR-058-container-native-dcs-operator.md) — readiness gate based on convergence lag
- [ADR-061 — REST/gRPC API](./ADR-061-rest-grpc-api.md) — `GET /api/v1/replication/health` endpoint
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Active Directory replication model, inter-site scheduling
- [openraft](https://github.com/datafuselabs/openraft) — Rust-native Raft implementation
- [FoundationDB multi-region deployment](https://apple.github.io/foundationdb/configuration.html#multi-region) — FDB multi-region replication topology
