---
title: "ADR-023: Structured Kerberos Audit Events in OpenTelemetry Log Format"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Auth Provider
problem: PC-042
severity: high
tags: [adr, auth-provider, audit, kerberos, opentelemetry, siem, 4768-4769-4771]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/03-auth-provider.md
  - ../docs/11-code-examples/05-python-impacket-examples.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ./ADR-011-rc4-deprecation-aes-default.md
  - ./ADR-012-fast-armoring-required.md
  - ./ADR-015-krbtgt-hsm-rotation.md
last_updated: 2026-08-13
---

# ADR-023: Structured Kerberos Audit Events in OpenTelemetry Log Format

## Status

Accepted — 2026-08-13

## Context

Active Directory logs Kerberos events to Windows Event Log: 4768 (TGT issued), 4769 (TGS issued), 4771 (pre-auth failed), 4770 (TGT renewed). Events 4768/4769 with `Ticket Encryption Type: 0x17` (RC4) are the Kerberoasting signal — an attacker is requesting RC4 TGS tickets for offline cracking. The events include: etype (RC4 vs AES — RC4 is the Kerberoast signal), SPN (the requested service principal), requester SID (the user), source IP (the client), request ID (for correlation). SIEM queries (Splunk, QRadar, Sentinel) assume Windows event IDs, per [PC-042](../catalog/03-auth-provider.md#pc-042--kerberos-audit-events-476847694771-need-framework-equivalent), [docs/11-code-examples/05-python-impacket-examples.md](../docs/11-code-examples/05-python-impacket-examples.md), and [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Kerberoasting detection: query for events 4769 where `Ticket Encryption Type = 0x17` (RC4) AND `ServiceName` matches a service account (not `krbtgt` or a computer account). A high count of RC4 TGS-REQs for a single service account in a short window is a strong Kerberoasting signal. Microsoft's Advanced Threat Analytics (ATA) and Defender for Identity both use this pattern.

Golden ticket detection: query for events 4768 where the requesting user's SID is in `Enterprise Admins` but the source IP is unusual, or where the TGT was issued by a DC that's not the user's home DC. Both are weak signals (false positives from legitimate admin activity). Old-key TGT usage (per ADR-015) — a TGT signed by the previous krbtgt key after rotation — is a strong golden-ticket signal.

AS-REP roasting detection: query for events 4768 where `Pre-Authentication Type = 0` (no pre-auth) — accounts with `DO_NOT_REQUIRE_PREAUTH` issue AS-REPs without pre-auth, which can be offline-cracked. With FAST-required (per ADR-012), AS-REP roasting is defeated, but the audit event is still emitted for monitoring.

Constraints from [PC-042](../catalog/03-auth-provider.md#pc-042--kerberos-audit-events-476847694771-need-framework-equivalent):

- Must include etype (RC4 vs AES — Kerberoast signal), SPN (the requested service), requester SID (the user), source IP (the client), request ID (for correlation).
- Must emit events in real-time (not batched — Kerberoasting can complete in minutes).
- Must support OpenTelemetry / CEF / JSON output formats.
- For AD interop, must support Windows Event Log format (so Windows SIEM agents can ingest).

## Decision

The framework SHALL emit structured audit events for all Kerberos operations (TGT issued, TGS issued, pre-auth failed, TGT renewed, old-key TGT used, AS-REP without pre-auth, RC4 TGS-REQ) in OpenTelemetry log format with the equivalent fields of Windows events 4768/4769/4771/4770. The framework SHALL emit events in real-time (not batched) — Kerberoasting can complete in minutes, and batched events delay detection.

The framework SHALL define a Kerberos audit event schema with the following fields (cross-reference OpenTelemetry semantic conventions where applicable):

- `event.type` — `kerberos_as_req`, `kerberos_as_rep`, `kerberos_tgs_req`, `kerberos_tgs_rep`, `kerberos_preauth_failed`, `kerberos_tgt_renewed`, `kerberos_old_key_used`, `kerberos_as_rep_no_preauth`
- `event.id` — UUIDv7 (for correlation)
- `event.timestamp` — RFC 3339 timestamp
- `event.windows_event_id` — `4768` (TGT issued), `4769` (TGS issued), `4771` (pre-auth failed), `4770` (TGT renewed) — for SIEM-compatibility mapping
- `kerberos.etype` — `0x11`, `0x12`, `0x13`, `0x17` (RC4 — Kerberoast signal per ADR-011), `0x18`
- `kerberos.spn` — the requested service principal name (for TGS-REQ) or the principal name (for AS-REQ)
- `kerberos.requester_sid` — the SID of the requesting user
- `kerberos.requester_dn` — the DN of the requesting user
- `kerberos.source.ip` — the client's source IP
- `kerberos.source.port` — the client's source port
- `kerberos.kdc.hostname` — the KDC instance that handled the request (per ADR-018)
- `kerberos.fast` — `true` / `false` (whether FAST armoring was used; `false` is the AS-REP-roasting signal per ADR-012)
- `kerberos.kvno` — the krbtgt key version number (for old-key detection per ADR-015; a TGT signed by a previous kvno after rotation is the golden-ticket signal)
- `kerberos.preauth_type` — `0` (no pre-auth — AS-REP-roasting signal), `2` (PA-ENC-TIMESTAMP), `16` (PA-PK-AS-REQ — PKINIT), `143` (PA-FX-FAST)
- `kerberos.result_code` — `SUCCESS`, `KDC_ERR_C_PRINCIPAL_UNKNOWN (6)`, `KDC_ERR_PREAUTH_FAILED (24)`, `KRB_AP_ERR_SKEW (37)`, `KRB_AP_ERR_MODIFIED (41)`, etc.
- `mitre.attack.technique_id` — (DEFERRED to Tier 3) — `T1558.003` (Kerberoasting), `T1558.001` (Golden Ticket), `T1003.006` (DCSync)

The framework SHALL emit events to multiple sinks simultaneously: (a) local log (journald on Linux, Unified Log on macOS, Windows Event Log on Windows); (b) remote SIEM via OpenTelemetry Collector (the framework's recommended path); (c) optional CEF / Syslog output for legacy SIEMs.

For AD-interop mode on Windows, the framework SHALL emit Windows Event Log events with the standard IDs (4768, 4769, 4771, 4770) so existing Windows SIEM agents (Windows Event Forwarding, Splunk Universal Forwarder, Winlogbeat) can ingest without modification. The Windows Event Log events SHALL include the same fields as the OpenTelemetry events (mapped to Windows event fields).

The framework SHALL emit real-time alerts (not just logs) for high-confidence attack patterns: (a) high count of RC4 TGS-REQs for a single service account in a short window (default: ≥10 RC4 TGS-REQs for the same SPN in 5 minutes — Kerberoasting signal); (b) old-key TGT usage after krbtgt rotation (golden-ticket signal per ADR-015); (c) AS-REP without pre-auth (AS-REP-roasting signal per ADR-012); (d) TGT for an Enterprise Admins SID from an unusual source IP (weak golden-ticket signal).

The framework SHALL expose a CLI command (`adrian-auth audit-kerberos`) that queries the local audit log for Kerberos events with optional filters (event type, etype, SPN, source IP, time range). The framework SHALL expose a REST API endpoint (`GET /api/v1/audit/kerberos`) for the same query.

The MITRE ATT&CK technique ID mapping is DEFERRED to Tier 3. The v1 implementation SHALL emit the `kerberos.*` fields; the `mitre.attack.technique_id` field is reserved for future use.

**Concrete specification**:

- The framework SHALL emit structured audit events for all Kerberos operations (AS-REQ, AS-REP, TGS-REQ, TGS-REP, pre-auth failed, TGT renewed, old-key TGT used, AS-REP without pre-auth, RC4 TGS-REQ) in OpenTelemetry log format.
- The audit event schema SHALL include the fields listed in the Decision section.
- Events SHALL be emitted in real-time (not batched); the framework SHALL NOT buffer events for more than 1 second.
- The framework SHALL emit events to multiple sinks: local log (journald / Unified Log / Windows Event Log), remote SIEM via OpenTelemetry Collector, optional CEF / Syslog.
- For AD-interop mode on Windows, the framework SHALL emit Windows Event Log events with IDs 4768, 4769, 4771, 4770 (byte-identical field layout to AD).
- The framework SHALL emit real-time alerts for: (a) ≥10 RC4 TGS-REQs for the same SPN in 5 minutes (Kerberoasting); (b) old-key TGT usage after krbtgt rotation (golden ticket); (c) AS-REP without pre-auth (AS-REP roasting); (d) TGT for Enterprise Admins SID from unusual source IP (weak golden ticket).
- The framework SHALL expose `adrian-auth audit-kerberos` CLI command (query local audit log with filters).
- The framework SHALL expose `GET /api/v1/audit/kerberos` REST endpoint (same query).
- The MITRE ATT&CK technique ID mapping is DEFERRED to Tier 3; the `mitre.attack.technique_id` field is reserved for future use.

## Rationale

Kerberoasting / DCSync / golden-ticket detection depend on these events. SIEM queries assume Windows event IDs — without equivalent events, the framework's KDC is invisible to existing SIEM deployments. Security teams cannot detect Kerberoasting, golden ticket, AS-REP roasting, or DCSync attacks without these events. Compliance mandates (PCI DSS, HIPAA, SOC 2) require Kerberos audit logging — without it, the framework cannot be deployed in regulated environments.

Three alternatives were considered:

**Alternative A — Map to Windows event IDs only (no OpenTelemetry).** The framework emits Windows Event Log events on Windows, journald on Linux, Unified Log on macOS. SIEM queries use platform-specific parsers. The advantage is byte-identical AD-interop on Windows. The disadvantage is that cross-platform SIEM queries require per-platform parsers, which is a maintenance burden. Rejected as the sole mechanism; ADOPTED as one of multiple sinks (Windows Event Log on Windows for AD-interop).

**Alternative B — OpenTelemetry semantic conventions only (no Windows event ID mapping).** The framework emits OpenTelemetry log events with Kerberos-specific semantic conventions. SIEM queries use OpenTelemetry parsers. The advantage is cross-platform consistency. The disadvantage is breaking existing Windows SIEM agents that expect Windows event IDs. Rejected as the sole mechanism; ADOPTED as the primary mechanism (with Windows event ID mapping for AD-interop).

**Alternative C — CEF (Common Event Format) only.** The framework emits CEF events for SIEM ingestion. CEF is widely supported by SIEMs (Splunk, QRadar, ArcSight). The advantage is SIEM-native format. The disadvantage is that CEF is a legacy format (originally from ArcSight) and lacks the structured-field richness of OpenTelemetry. Rejected as the primary mechanism; ADOPTED as an optional output for legacy SIEMs.

External evidence: [OpenTelemetry Logs specification](https://opentelemetry.io/docs/specs/otel/logs/) defines the log data model; [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/) documents Kerberos-related attack techniques; Microsoft's [Audit Policy Recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) documents the Windows event IDs (4768, 4769, 4771, 4770) and their fields. The framework's design matches the modern OpenTelemetry pattern while preserving AD-interop via Windows Event Log.

The cost of this decision is implementation effort for the audit event emission (instrumentation in the KDC's AS-REQ / TGS-REQ paths), the OpenTelemetry Collector integration, the Windows Event Log mapping (for AD-interop), and the real-time alerting rules. The bulk of the work is the KDC instrumentation; the rest is configuration.

## Consequences

**Positive**: SIEM integration works out-of-the-box via OpenTelemetry Collector. Windows SIEM agents work via Windows Event Log mapping (AD-interop). Real-time alerts detect Kerberoasting, golden ticket, AS-REP roasting, and weak golden-ticket signals. Compliance mandates (PCI DSS, HIPAA, SOC 2) are satisfied.

**Negative**: Real-time event emission adds KDC overhead (one log write per AS-REQ / TGS-REQ). At 100K AS-REQ/sec, this is 100K log writes/sec — non-trivial but manageable with asynchronous logging. The OpenTelemetry Collector is a new operational dependency.

**Neutral**: The MITRE ATT&CK technique ID mapping is deferred to Tier 3; the `mitre.attack.technique_id` field is reserved. Deployments that don't use SIEM integration pay only the local-log cost.

**Implementation cost**: ~5 person-weeks for the KDC instrumentation, the OpenTelemetry Collector integration, the Windows Event Log mapping, the real-time alerting rules, and the CLI/REST query API. The bulk of the work is the KDC instrumentation (every AS-REQ / TGS-REQ path needs audit event emission).

**Operational impact**: SIEM integration works out-of-the-box. The `adrian-auth audit-kerberos` CLI is useful for incident response. Real-time alerts enable rapid detection of Kerberoasting / golden-ticket attacks. Compliance audits are satisfied by the audit log.

## Alternatives Considered

### Alternative 1: Map to Windows event IDs only (no OpenTelemetry)

Byte-identical AD-interop on Windows; cross-platform SIEM queries require per-platform parsers. Rejected as sole mechanism; ADOPTED as one of multiple sinks (Windows Event Log on Windows for AD-interop).

### Alternative 2: OpenTelemetry semantic conventions only (no Windows event ID mapping)

Cross-platform consistency; breaks existing Windows SIEM agents. Rejected as sole mechanism; ADOPTED as primary mechanism (with Windows event ID mapping for AD-interop).

### Alternative 3: CEF (Common Event Format) only

SIEM-native format; legacy, lacks structured-field richness of OpenTelemetry. Rejected as primary; ADOPTED as optional output for legacy SIEMs.

## Open Questions

- **DEFERRED to Tier 3**: MITRE ATT&CK technique ID mapping in the event metadata. The v1 implementation SHALL emit the `kerberos.*` fields; the `mitre.attack.technique_id` field is reserved for future use. The mapping (T1558.003 Kerberoasting, T1558.001 Golden Ticket, T1003.006 DCSync, etc.) is straightforward but the framework's detection rules should be configurable per-deployment.
- OpenTelemetry semantic conventions for Kerberos events? Currently no standard conventions exist. The framework SHALL define its own `kerberos.*` namespace and contribute it to the OpenTelemetry semantic conventions repository.
- Should the framework emit events to a local log (journald / Unified Log / Windows Event Log) AND a remote SIEM (via OTel / Syslog / CEF), or just one? The Decision section specifies both — local log for forensics, remote SIEM for real-time detection.
- For real-time alerting, what are the default thresholds? Kerberoasting: ≥10 RC4 TGS-REQs for the same SPN in 5 minutes (per the Decision section). Golden ticket: any old-key TGT usage after rotation. AS-REP roasting: any AS-REP without pre-auth. These should be configurable per-deployment.
- Cross-reference ADR-011 (RC4 deprecation) — the RC4 TGS-REQ audit event is the Kerberoasting detection signal; the two ADRs are tightly coupled.
- Cross-reference ADR-012 (FAST armoring) — the non-FAST AS-REQ audit event is the AS-REP-roasting detection signal.
- Cross-reference ADR-015 (krbtgt HSM rotation) — the old-key TGT usage audit event is the golden-ticket detection signal.

## Cross-capability impact

- **KDC**: The KDC's AS-REQ / TGS-REQ paths are instrumented for audit event emission. This is a per-request overhead (one log write per request).
- **Operations**: SIEM integration is a core ops task. The `adrian-auth audit-kerberos` CLI is a standard incident-response tool. Real-time alerts enable rapid detection.
- **Security**: Kerberoasting / golden-ticket / AS-REP-roasting detection depends on these events. The audit log satisfies compliance mandates (PCI DSS, HIPAA, SOC 2).
- **Migration**: AD-to-framework migration preserves Windows event IDs (4768, 4769, 4771, 4770) on Windows DCs for SIEM-compatibility. OpenTelemetry output enables cross-platform SIEM integration.
- **Client SDK**: Client SDK exposes `adrian-auth audit-kerberos` for incident-response queries.

## References

- [PC-042](../catalog/03-auth-provider.md) — problem statement in the catalog
- [docs/11-code-examples/05-python-impacket-examples.md](../docs/11-code-examples/05-python-impacket-examples.md) — Impacket Kerberoasting examples, DCSync via `secretsdump.py`, detection patterns
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — Kerberos message types, etypes, Wireshark display filters for Kerberoasting detection
- [OpenTelemetry Logs specification](https://opentelemetry.io/docs/specs/otel/logs/) — log data model
- [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/) — Kerberos-related attack techniques
- [Microsoft Audit Policy Recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) — Windows event IDs (4768, 4769, 4771, 4770)
