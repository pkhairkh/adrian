---
title: "ADR-057: Prometheus Exporter + OpenTelemetry Instrumentation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-106
severity: high
tags: [adr, operations, observability, prometheus, opentelemetry, otlp, metrics, tracing]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-060-structured-audit-logs-otel.md
last_updated: 2026-08-13
---

# ADR-057: Prometheus Exporter + OpenTelemetry Instrumentation

## Status

Accepted — 2026-08-13

## Context

AD emits two streams of operational signal: Windows Event Log XML records (security events 4768/4769 for AS-REQ/TGS-REQ, 5136 for Directory Service Access modifies, 4662 for object access, 4624 for logon) and Performance Monitor counters exposed via the `NTDS` and `LDAP` perfmon objects. Neither is wire-compatible with Prometheus' text-exposition format nor with the OpenTelemetry (OTel) OTLP span/metric data model. The gap forces every modern monitoring stack (Prometheus + Grafana + Alertmanager, Datadog, Chronicle, ELK) to deploy bespoke adapters — `windows_exporter` for metrics, WinLogBeat for logs — that bridge the surface but lose fidelity and add latency.

The deeper gap is per-request distributed tracing. An LDAP bind on an AD DC traverses LSASS, `ntdsa.dll`, the ESE layer, the schema cache, and the SD table; a Kerberos TGS-REQ traverses the KDC, the PAC builder, the SD table, and the krbtgt-key crypto path; a replication cycle traverses the DRSUAPI server, the replication metadata builder, the ESE cursor, and the wire compressor. None of these emit a span. There is no equivalent of an HTTP `X-Request-ID` propagated through the stack. A latency spike on "LDAP bind slow" cannot be attributed to schema-cache miss vs. SD-cache miss vs. ESE I/O wait without manual `perfmon` sampling.

For the framework, this gap is fundamental: the framework must be observable by default. SIEM-first architectures expect JSON or OTLP. Kubernetes operators expect Prometheus metrics with `_total` counter suffixes and histogram buckets for latency. Prometheus' text-exposition model (https://prometheus.io/docs/instrumenting/exposition_formats/) and the OTel protocol (https://opentelemetry.io/docs/specs/otel/protocol/) are the two industry-standard wire formats; any framework that does not emit them natively is, in 2026, unmonitorable without bespoke glue code.

The constraint set is tight: the framework must emit Prometheus metrics (auth rate, replication lag, KDC errors, ESE-equivalent cache hit ratio, FSMO holder changes), must emit OTel traces (per LDAP request, per Kerberos exchange, per replication cycle), must keep the perfmon counter path (`\\<DC>\NTDS\...`) intact for AD-interop scenarios, and must not introduce measurable latency on the request path (<1% overhead at 10k req/s). The framework cannot regress on raw throughput to achieve observability — the LDAP bind path is the hottest path in any identity system.

## Decision

Adopt OpenTelemetry as the in-process instrumentation standard and Prometheus as the external metrics-exposition standard. Every framework component (KDC, DSA, Auth Provider, Policy Engine, Cert Service, File Gateway, Client SDK, operator) links the OTel SDK and emits spans, metrics, and logs via the OTLP/gRPC export path. A per-DC sidecar (the `adrian-observability-sidecar`) terminates OTLP from the framework processes, fans out to (a) a Prometheus scrape endpoint in text-exposition 0.0.4 format, (b) a configurable OTLP upstream (collector), and (c) a local structured-log file in JSON Lines for the audit pipeline (see [ADR-060](./ADR-060-structured-audit-logs-otel.md)). Per-DC metrics granularity is the baseline; per-realm aggregation is delegated to the downstream collector (Prometheus federation or OTel collector pipeline), not the framework itself.

The framework adopts OTel semantic conventions verbatim where they exist (`http`, `rpc`, `db`, `messaging`, `network`, `enduser`, `process`, `host`, `os`) and extends them with a framework-specific namespace `adrian.directory.*`, `adrian.kdc.*`, `adrian.replication.*`, `adrian.policy.*`, `adrian.pki.*` documented in a single semantic-convention spec shipped with the framework. The Windows Event ID → framework-event-name mapping is published as a stable table so SIEM rules can key on either.

**Concrete specification**:

- Every framework binary MUST link `opentelemetry-sdk` (or the language-equivalent) and initialise a tracer, meter, and logger at startup with a `service.name` equal to the binary name (`adrian-kdc`, `adrian-dsa`, `adrian-policy`, etc.).
- Every LDAP request MUST emit one server span named `ldap.request` with attributes `ldap.operation` (bind/search/modify/add/del/...), `ldap.base_dn`, `ldap.scope`, `ldap.filter.length` (not the filter itself, to avoid PII), `ldap.result_code`, and `ldap.client.ip` (truncated to /24 for IPv4 to reduce PII exposure).
- Every Kerberos exchange MUST emit one server span: `kerberos.as_req` or `kerberos.tgs_req`, with attributes `kerberos.etype`, `kerberos.preauth_type`, `kerberos.client_realm`, `kerberos.server_principal` (SPN), `kerberos.result_code`, and `kerberos.source.ip`.
- Every replication cycle MUST emit one span `replication.cycle` with attributes `replication.partner`, `replication.nc_dn`, `replication.objects_sent`, `replication.bytes_sent`, `replication.duration_ms`, and child spans per `DRSGetNCChanges` call.
- Prometheus exposition MUST expose the following minimum metric set under the `adrian_` prefix:
  - `adrian_ldap_requests_total{operation,result}` (counter)
  - `adrian_ldap_request_duration_seconds{operation}` (histogram, buckets `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5]`)
  - `adrian_kerberos_as_req_total{etype,result}` (counter)
  - `adrian_kerberos_tgs_req_total{etype,result}` (counter)
  - `adrian_replication_lag_seconds{partner,nc}` (gauge)
  - `adrian_replication_objects_total{partner,nc,direction}` (counter)
  - `adrian_db_cache_hit_ratio{cache}` (gauge, labels `schema`, `sd`, `object`)
  - `adrian_fsmo_holder{role,domain}` (gauge, value = 1 for the current holder)
  - `adrian_krbtgt_key_version{domain}` (gauge)
  - `adrian_active_ldap_connections` (gauge)
- The `adrian-observability-sidecar` MUST expose Prometheus metrics on `:9100/metrics` and accept OTLP/gRPC on `:4317` and OTLP/HTTP on `:4318`.
- Total telemetry overhead on the LDAP bind path MUST be measured at <1% at 10k req/s in the framework's CI performance gate (publish a benchmark dashboard).
- Span context (trace ID, span ID) MUST be propagated to clients via the LDAP `controlOID 1.2.840.113556.1.4.2211` (framework-defined, registered with IANA) and via the Kerberos `AD-LOGON-HOUR`-equivalent authenticator field repurposed as `AD-FW-TRACE` (authorization-data type 0x80, framework-private), so a client-side trace and the DC-side trace join.
- For AD-interop scenarios, the framework MUST run a `windows_exporter`-equivalent compatibility shim that exposes the perfmon-equivalent counter paths (`\\<DC>\NTDS\DRA Inbound Bytes Total/sec`, etc.) on the same Prometheus endpoint under a `perfmon_*` metric prefix.

## Rationale

OpenTelemetry is the CNCF graduated, vendor-neutral standard for telemetry; Prometheus is the CNCF graduated standard for metrics exposition. Choosing anything else in 2026 — StatsD, InfluxDB, proprietary vendor SDKs — would be choosing a niche. The OTel SDK has stable releases for Go, Rust, C++, Python, Java, .NET; the framework's expected implementation languages are covered.

Per-DC granularity is the right baseline because (a) it matches AD's operational mental model (one DC = one perfmon source), (b) it allows Prometheus' native instance label to do the heavy lifting, (c) per-realm aggregation requires either a federation layer or a distributed metric pipeline which is the operator's choice, not the framework's. Forcing per-realm aggregation in-process would couple the framework to a specific multi-tenant topology.

The framework-specific `adrian.*` semantic-convention namespace is required because OTel's semantic conventions cover HTTP/RPC/db/messaging but not directory or Kerberos operations. Defining these in a single spec, versioned with the framework, is preferable to letting each component invent its own attribute names.

Span context propagation through LDAP controls and Kerberos authorization-data is non-trivial but necessary: without it, a "Mac client → framework DC → Linux file share" auth path cannot be joined into a single trace. The LDAP control and the Kerberos authenticator field are the two natural carrier slots because they survive through the entire request path. Both are framework-private extensions (the LDAP control is registered with IANA under the framework's PEN; the Kerberos auth-data type is in the private range 0x80–0xFF).

The Windows-perfmon compatibility shim is required for AD-interop scenarios where the operator's existing dashboards expect `\\<DC>\NTDS\...` paths. Without it, the framework forces the operator to rebuild every dashboard simultaneously with the migration — a non-starter.

The <1% overhead target is achievable: OTel SDKs in 2026 are batch-and-async by default; the hot LDAP path emits one span per request and a fixed number of metric increments; no per-attribute string allocation is performed on the hot path (attribute keys are interned, attribute values are pre-allocated buffers).

## Consequences

**Positive**: The framework becomes observable by default in any modern stack. SIEM integration is one OTLP collector stanza. Prometheus scrape is one ServiceMonitor YAML. Per-request tracing across the KDC + DSA + Auth-Provider boundary is possible for the first time. Performance regression detection becomes a CI gate. Cross-platform correlation of a single user's auth path (Mac → DC → file share on Linux) is achievable via shared trace IDs.

**Negative**: The framework acquires a runtime dependency on the OTel SDK in every binary, adding ~5 MB to the container image and ~30 MB resident memory per process for the SDK's batch buffers. Span context propagation via LDAP controls adds 16 bytes per request (trace ID + span ID). The Windows-perfmon compatibility shim is a maintenance burden — every AD schema-level perfmon counter must be mirrored. Operator teams that have standardised on Splunk UF or Datadog Agent need to reconfigure to scrape OTLP, not a huge burden but a one-time migration cost.

**Neutral**: The choice of OTel + Prometheus does not preclude emitting other formats (StatsD, fluentd) via collector pipelines. The framework's sidecar is the only mandatory component; the upstream collector, storage, and dashboard layers are the operator's choice.

**Implementation cost**: ~3 person-months to instrument the KDC + DSA + Auth Provider hot paths; ~1 person-month to write the sidecar; ~1 person-month to write the perfmon compat shim; ~1 person-month for the semantic-convention spec and the perf CI gate. Total: ~6 person-months for v1.

**Operational impact**: Operators get a `ServiceMonitor` and a `PodMonitor` YAML out of the box; a default Grafana dashboard JSON ships with the framework; alert rules (Kerberoast storm, replication lag > 15 min, FSMO holder flapping, krbtgt key version stale) ship as a Prometheus rule file. The framework's runbook references these dashboards and alerts by name.

## Alternatives Considered

**Alternative A: StatsD + Zipkin.** StatsD is the older UDP-based metrics standard; Zipkin is the older distributed-tracing standard. Both predate OTel and are widely deployed. Rejected because StatsD's UDP model drops packets under load (exactly when you need metrics most) and Zipkin's instrumentation libraries are being deprecated in favour of OTel. Choosing StatsD + Zipkin would mean inheriting two legacy stacks and bridging to OTel eventually anyway.

**Alternative B: Vendor-native SDKs (Datadog, Splunk, New Relic).** Each APM vendor has its own agent and instrumentation SDK. Some organisations have standardised on one. Rejected because the framework cannot pick a vendor; embedding a vendor SDK couples the framework to that vendor's pricing model and release cadence. OTel's vendor-neutral SDK with a configurable exporter (Datadog exporter, Splunk exporter, etc. available in the OTel collector) achieves the same outcome without coupling.

**Alternative C: Emit only structured logs, derive metrics and traces downstream.** Some systems (e.g. Vector's logs-to-metrics transform) derive metrics from log streams. Rejected because (a) the latency budget for an alert on "Kerberoast storm in progress" is 30 seconds; deriving from logs adds 1–5 minutes; (b) per-request tracing fundamentally requires in-process span context, not log-derived pseudo-traces; (c) the structured-log path is separate (see ADR-060) and must not be overloaded.

## Open Questions

None — this is an ADR-ELIGIBLE decision. Open research questions remain about the exact metric taxonomy (per-realm aggregation in sidecar vs. downstream collector; histogram bucket boundaries for replication lag), but these are Tier-2 ORQs that do not gate the decision.

## Cross-capability impact

- **KDC (PC-023 through PC-035)**: KDC must emit per-AS-REQ and per-TGS-REQ spans; krbtgt key version (PC-030) becomes a Prometheus gauge.
- **Auth Provider (PC-036 through PC-042)**: NTLM and W32Time events (PC-041) emit OTel log records; ADR-023 (PC-042 Kerberos audit events in OTel) shares the OTel semantic conventions — ADR writers must align.
- **Operations (PC-111)**: Structured audit logs (ADR-060) share the same OTel SDK and the same sidecar; the log path and the trace path must agree on trace ID propagation.
- **Operations (PC-112)**: REST/gRPC API (ADR-061) naturally emits OTel server spans per request — the framework's API gateway uses the same SDK.
- **Operations (PC-115)**: Unified CLI (ADR-063) must propagate trace context to the DC when invoking management operations, so CLI invocations appear in traces.
- **Security (PC-117)**: DCSync detection (PC-117, deferred) needs the Event 4662 stream which the audit-log path emits; OTel metrics on `adrian_drs_get_nc_changes_total{caller_type}` would also surface non-DC callers.
- **Security (PC-118)**: Golden-ticket detection needs `adrian_kerberos_tgs_req_total` with a `key_version` label to alert on old-key TGT usage.
- **Migration (PC-129)**: Cross-realm trust (ADR-069) must propagate trace context across realm boundaries so a cross-realm referral is one trace, not two.

## References

- [PC-106](../catalog/10-operations.md) — problem statement (no native Prometheus exporter / OpenTelemetry for AD)
- [Kerberos internals](../docs/02-protocols/01-kerberos-internals.md) — Kerberos event IDs 4768/4769/4771; the etype field on Event 4769 is the Kerberoasting detection signal
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — ESE transaction commit path, event 5136 raise, registry keys (`Strict Replication Consistency`, `LDAPClientIntegrity`) that should be metrics
- [OpenTelemetry Protocol (OTLP) specification](https://opentelemetry.io/docs/specs/otel/protocol/)
- [Prometheus exposition formats](https://prometheus.io/docs/instrumenting/exposition_formats/)
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)
- [RFC 4120 — Kerberos Network Authentication Service](https://datatracker.ietf.org/doc/html/rfc4120) (§5.3 Authorization-Data for the framework-private `AD-FW-TRACE` type)
