---
title: "ADR-060: Structured Audit Logs in OTel Format + MITRE ATT&CK Mapping"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-111
severity: high
tags: [adr, operations, audit, logging, otel, otlp, siem, mitre-attack, security-monitoring]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/01-ad-core/01-ad-ds-internals.md
  - ./ADR-057-prometheus-otel-observability.md
  - ./ADR-064-kerberoasting-aes-migration.md
  - ./ADR-065-krbtgt-hsm-rotation.md
last_updated: 2026-08-13
---

# ADR-060: Structured Audit Logs in OTel Format + MITRE ATT&CK Mapping

## Status

Accepted — 2026-08-13

## Context

AD audit events are emitted via `LSASS!AuthzReportSecurityEvent` into the Windows Event Log, specifically the `Security` log (events 4624 logon, 4625 failed logon, 4662 object access, 4768 AS-REQ, 4769 TGS-REQ, 4771 pre-auth failed, 5136 Directory Service Access modify, 5137 directory object created, 5138 directory object modified, 5139 directory object moved, 5141 directory object deleted) and the `Directory Service` log (events 2095 USN rollback, 2042 tombstone lifetime exceeded, 1425 schema cache reload failure). Each event is XML-serialised per the Windows Event Log schema (`http://schemas.microsoft.com/win/2004/08/events/event`), with the audit data buried in `EventData` fields that are integer-indexed (`Data Name="AuthenticationPackageName"`) rather than keyed by semantic name.

Event 4768 (AS-REQ) carries the target user, the etype used for pre-auth, the source IP, and the result code; Event 4769 (TGS-REQ) carries the requested SPN, the service ticket etype, and the source IP. These are the primary signals for Kerberoasting detection (4769 with etype 0x17 = RC4) and AS-REP roasting detection (4768 with `0x0` pre-auth type). But the XML structure makes them painful to query: SIEM analysts must write XPATH or Regex over the `EventData` block to extract fields.

Windows Event Forwarding (WEF) is the canonical aggregation mechanism: a collector DC subscribes to all DCs' Security logs, re-emits them as `ForwardedEvents`. Third-party agents (`WinLogBeat`, `Splunk_TA_windows`, `nxlog`) parse the XML and re-emit as JSON/CEF. The pipeline adds 5-30 seconds of latency and breaks under event bursts (a 10k-user login storm can overflow WEF queues). MITRE ATT&CK mapping is manual: an analyst reads 4769, looks up T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) in ATT&CK navigator.

The framework gap is fundamental: modern systems emit structured JSON logs by default (Postgres JSON logs, Envoy access logs, OpenTelemetry log records). The framework should emit per-event JSON with full context (user, source, action, result, etype, SPN, IP, MITRE ATT&CK technique ID) directly to an OTel collector. SIEM integration should be one config stanza, not a custom XML parser.

## Decision

The framework emits every audit-worthy event as a structured OpenTelemetry log record (per the OTel logs data model, https://opentelemetry.io/docs/specs/otel/logs/data-model/) via OTLP/HTTP or OTLP/gRPC to the `adrian-observability-sidecar` (introduced in [ADR-057](./ADR-057-prometheus-otel-observability.md)). Each log record carries: (a) the framework event name (e.g. `adrian.kerberos.tgs.request`), (b) the equivalent Windows Event ID for AD-interop (e.g. `4769`), (c) the MITRE ATT&CK technique ID(s) when applicable (e.g. `T1558.003`), (d) the structured attributes (user, source IP, SPN, etype, result code), (e) the trace ID and span ID (joining the per-request trace from ADR-057), and (f) a timestamp with nanosecond precision.

A sidecar also exposes a Windows Event Log forwarder for AD-interop scenarios: when the framework is deployed in mixed mode with AD DCs, the sidecar translates the framework's OTel log records back into Windows Event Log XML format and writes them to the Windows Event Log via the `EvtExportLog` API, so existing SIEM rules that consume Windows Event Log continue to work. The mapping is bidirectional and documented in a stable table.

The framework defines a stable event taxonomy: every audit event has a unique name, a stable set of attributes, a documented MITRE ATT&CK mapping, and a stable Windows Event ID mapping. The taxonomy is versioned with the framework and shipped as a JSON schema file (`adrian-audit-events.json`) that SIEM vendors and operators can consume.

**Concrete specification**:

- Every framework audit event MUST be emitted as an OTel log record with `severity_number` ≥ 9 (INFO) for routine events, ≥ 17 (ERROR) for failures, and `severity_number = 1` (TRACE) for debug-only events.
- Every OTel log record MUST include the following top-level fields: `Timestamp` (ns precision), `ObservedTimestamp`, `TraceId`, `SpanId`, `SeverityText`, `SeverityNumber`, `Body` (the framework event name), and `Attributes`.
- Every audit event MUST include these standard attributes: `adrian.event.name`, `adrian.event.windows_id` (e.g. `4769`), `adrian.event.mitre_attack` (array of technique IDs, empty if N/A), `adrian.dc.host`, `adrian.dc.realm`, `adrian.client.ip`, `adrian.client.port`, `adrian.principal.dn` (when applicable), `adrian.result.code` (Kerberos result code, LDAP result code, etc.), `adrian.result.success` (boolean).
- Kerberos events MUST additionally include: `adrian.kerberos.etype`, `adrian.kerberos.preauth_type`, `adrian.kerberos.spn` (for TGS-REQ), `adrian.kerberos.key_version` (for krbtgt-key-version mismatch detection per ADR-065).
- LDAP events MUST additionally include: `adrian.ldap.operation` (bind/search/modify/add/del), `adrian.ldap.base_dn`, `adrian.ldap.scope`, `adrian.ldap.result_code`.
- Replication events MUST additionally include: `adrian.replication.partner`, `adrian.replication.nc_dn`, `adrian.replication.ulExtendedOp` (DRSGetNCChanges operation, for DCSync detection per PC-117), `adrian.replication.caller_sid` (to detect non-DC callers).
- Directory Service Access events MUST additionally include: `adrian.dsa.object_dn`, `adrian.dsa.attribute`, `adrian.dsa.operation` (read/write/delete), `adrian.dsa.access_mask`.
- The MITRE ATT&CK mapping MUST be sourced from a stable, versioned table maintained in the framework's source tree. The mapping for the top 30 audit events (4768, 4769, 4771, 4624, 4625, 4662, 5136, 5137, 5141, etc.) MUST be documented.
- The Windows Event Log forwarder MUST translate OTel log records to Windows Event Log XML with the exact `EventData` field names that AD uses, so SIEM rules written for AD continue to work.
- The Windows Event Log forwarder MUST preserve the Windows Event ID (e.g. 4769) in the `<EventID>` element.
- The audit pipeline MUST NOT add more than 100 ms of latency to any request (event is emitted asynchronously via a batched OTLP exporter).
- The audit pipeline MUST survive event bursts of 100k events/sec per DC (10x the typical 10k events/sec peak).
- The framework MUST ship default SIEM integration stanzas for Splunk, Elastic, Datadog, Chronicle, and Sentinel.
- The framework MUST ship default detection rules for the top 10 AD attack patterns: Kerberoasting (4769 etype 0x17 storm), AS-REP roasting (4768 preauth type 0), Pass-the-Hash (4624 logon type 3 with NTLM), DCSync (4662 with `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`), Golden ticket (4769 with key version mismatch), Silver ticket (4769 followed by AP-REQ with no preceding TGS), sIDHistory injection (4662 with sIDHistory attribute GUID), AdminSDHolder modification (4662 on the AdminSDHolder object), trust password desync (per ADR-062), and replication from non-DC source (4662 with caller SID not a `nTDSDSA`).

## Rationale

OpenTelemetry's logs data model is the industry standard for structured log records. It supports the same attribute model as OTel traces and metrics, allowing a single collector pipeline to handle all three signals. Emitting audit events as OTel log records (rather than JSON to a file, or syslog, or Windows Event Log) gives the framework one pipeline, one schema, one export protocol.

The MITRE ATT&CK mapping baked into the event attributes is the key improvement over AD. SIEM rules currently require an analyst to look up the technique ID for each Windows Event ID; the framework bakes the mapping in. This makes SIEM rules trivial (`adrian.event.mitre_attack contains "T1558.003"` → Kerberoast alert). The mapping is versioned with MITRE ATT&CK itself; the framework tracks the ATT&CK version it was built against.

The Windows Event Log forwarder for AD-interop is necessary because existing SIEM rules written for AD use Windows Event IDs and `EventData` field names. Without the forwarder, organisations migrating from AD to the framework would have to rewrite every SIEM rule simultaneously with the migration — a non-starter. The forwarder is a translation layer, not a parallel pipeline.

The 100 ms latency budget is achievable: the OTel SDK's batched exporter is asynchronous by default. The hot path (LDAP bind, Kerberos AS-REQ) does one event-record allocation and one batched-send call; the actual OTLP export happens on a separate goroutine.

The 100k events/sec burst tolerance is necessary because login storms (e.g. Monday 9am, after a weekend patch reboot) generate 10x typical peak. The sidecar uses a bounded in-memory queue with backpressure to the framework; if the queue overflows, the framework falls back to writing events to a local JSONL file that the sidecar drains later (audit events must never be dropped silently).

## Consequences

**Positive**: SIEM integration is one OTLP collector stanza, not a custom XML parser. MITRE ATT&CK mapping is automatic. Real-time Kerberoasting detection (4769 etype 0x17 storm) is gated by network latency (typically <1 sec), not WEF latency (5-30 sec). Cross-platform correlation of a single user's auth path is possible via shared trace IDs. Default detection rules ship out of the box for the top 10 AD attack patterns.

**Negative**: The framework's audit pipeline is a hard dependency on the OTel SDK and the sidecar. If the sidecar is down, the framework must fall back to local JSONL files (which require manual drainage). The Windows Event Log forwarder adds maintenance burden — every new audit event must be added to both the OTel schema and the Windows Event Log translation table. SIEM vendors that have built AD-specific parsers may need to update their parsers to handle the framework's event names (though the Windows Event Log forwarder mitigates this).

**Neutral**: The framework's audit pipeline does not preclude other log destinations (syslog, journald, file-based) via the OTel collector's exporter pipeline. The OTLP-first approach is the reference; other destinations are configured downstream.

**Implementation cost**: ~3 person-months for the OTel log emission in every framework component; ~2 person-months for the Windows Event Log forwarder; ~2 person-months for the MITRE ATT&CK mapping table and the default detection rules; ~1 person-month for the SIEM integration stanzas. Total: ~8 person-months for v1.

**Operational impact**: SIEM teams get a documented event taxonomy and default detection rules on day 1. SOC analysts query by MITRE ATT&CK technique ID, not by Windows Event ID. AD-interop scenarios preserve existing SIEM rules via the forwarder.

## Alternatives Considered

**Alternative A: Windows Event Log only (preserve AD semantics).** Emit all events as Windows Event Log XML, even on Linux/macOS DCs. Rejected because (a) Windows Event Log is a Windows-only API; replicating it on Linux requires a custom daemon that itself needs SIEM integration, (b) the XML format is painful to query (XPATH over `EventData`), (c) MITRE ATT&CK mapping would still be manual, (d) the framework cannot regress to a Windows-only audit pipeline in 2026.

**Alternative B: Syslog (RFC 5424) only.** Emit all events as structured syslog messages. Rejected because (a) syslog's structured-data format (RFC 5424 §6.3) is not widely adopted; most syslog messages are unstructured, (b) syslog does not natively support trace ID propagation, (c) syslog lacks the OTel attribute model's typed attributes (string/int/bool/array), (d) SIEM integration via syslog requires the same custom parsing that we are trying to eliminate.

**Alternative C: CEF (Common Event Format) only.** ArcSight's CEF is a popular SIEM event format. Rejected because (a) CEF is a proprietary format (Micro Focus / OpenText), not an open standard, (b) CEF is a flat key=value format, not a structured attribute model, (c) the OTel collector can translate OTLP to CEF downstream via the hec or splunk_hec exporter — operators who need CEF get it via the collector, not the framework.

## Open Questions

None — this is an ADR-ELIGIBLE decision. Tier-2 ORQs remain about the exact attribute taxonomy (whether to align with Sigma rules, with MITRE CAR, or with the OTel security semantic conventions), but these do not gate the decision.

## Cross-capability impact

- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) shares the same OTel SDK and sidecar; the log path and the metric path must agree on attribute names.
- **Operations (PC-112)**: REST/gRPC API (ADR-061) emits OTel log records for every API call; the audit pipeline consumes them.
- **KDC (PC-042)**: ADR-023 (PC-042 Kerberos audit events in OTel) shares the same OTel semantic conventions; ADR writers must align.
- **Auth Provider (PC-036 through PC-042)**: NTLM events emit OTel log records with MITRE ATT&CK T1550 (Use Alternate Authentication Material) mapping.
- **Security (PC-116)**: Kerberoasting detection (ADR-064) consumes the 4769 etype stream from this pipeline.
- **Security (PC-117)**: DCSync detection (PC-117, deferred) consumes the 4662 stream with `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` from this pipeline.
- **Security (PC-118)**: Golden-ticket detection (ADR-065) consumes the 4769 stream with key-version mismatch from this pipeline.
- **Security (PC-122)**: AdminSDHolder audit (ADR-066) consumes the 4662 stream on the AdminSDHolder object from this pipeline.
- **Migration (PC-126)**: Client switchover during migration produces mixed audit streams (AD Event Log + framework OTel); the Windows Event Log forwarder unifies them in the SIEM.

## References

- [PC-111](../catalog/10-operations.md) — problem statement (AD audit logs are Windows Event Log only; no structured logging)
- [Kerberos internals](../docs/02-protocols/01-kerberos-internals.md) — Kerberos event IDs 4768/4769/4771 and the etype field used for Kerberoasting detection
- [AD DS internals](../docs/01-ad-core/01-ad-ds-internals.md) — Event 5136 raised inside the ESE transaction commit path via `LSASS!AuthzReportSecurityEvent`
- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
- [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otel/protocol/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows Event Log schema](https://schemas.microsoft.com/win/2004/08/events/event)
- [RFC 5424 — The Syslog Protocol](https://datatracker.ietf.org/doc/html/rfc5424) (for reference; not chosen)
