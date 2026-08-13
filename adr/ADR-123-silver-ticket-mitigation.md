---
title: "ADR-123: Silver Ticket Mitigation — Mandatory PAC_BUFFER_TICKET_CHECKSUM + Default Service-Side Validation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-119
severity: high
tags: [adr, security, silver-ticket, pac, ticket-checksum, krbtgt, mitre-t1558-001, ms-kile]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ../workshop/decision-05-kdc-implementation.md
  - ../workshop/decision-06-ntlm-decision.md
  - ./ADR-064-kerberoasting-aes-migration.md
  - ./ADR-065-krbtgt-hsm-rotation.md
last_updated: 2026-08-13
---

# ADR-123: Silver Ticket Mitigation — Mandatory PAC_BUFFER_TICKET_CHECKSUM + Default Service-Side Validation

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 5 (KDC implementation)](../workshop/decision-05-kdc-implementation.md) which chose a fresh Rust KDC and confirmed `PAC_BUFFER_TICKET_CHECKSUM` is implemented in `crates/adrian-kdc/src/mskile/ticket_checksum.rs`. Decision 6 (drop NTLM server-side) is a defence-in-depth complement: services that no longer accept NTLM cannot be silver-ticket-attacked via the NTLM acceptor path.

## Context

A silver ticket is a forged service ticket. Where a golden ticket forges a TGT (encrypted with the krbtgt key), a silver ticket forges a TGS service ticket (encrypted with the service account's long-term key). Per [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md), the service ticket's `Ticket.enc-part` is encrypted with the service account's NTLM hash (RC4) or AES key — derived from the service account's password. An attacker who has the service account's hash (obtained via Kerberoasting ADR-064, or via DCSync ADR-122) can forge a service ticket locally using `ticketer.py -nthash <service_hash> -spn cifs/file01.example.com -user-id 500 Administrator` (impacket, per [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md)).

The forged silver ticket is presented directly to the target service (`AP-REQ` containing the forged ticket). The service decrypts the ticket with its own long-term key — succeeds, because the attacker used the correct key. The service extracts the PAC from the ticket's `authorization-data`, sees the user identity and group memberships (forged to be Administrator), and grants access. No KDC interaction occurs — the attack is entirely offline from the KDC's perspective, making detection very hard.

The mitigation introduced in Windows Server 2016 is `PAC_BUFFER_TICKET_CHECKSUM` (PAC buffer type 0x0E). The KDC, when issuing a service ticket, computes an HMAC over the entire `Ticket.enc-part` using the krbtgt key (separate from the encryption) and embeds this signature in the PAC. A service that opts in to ticket-signature validation (registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\VerifyPacAuthenticators = 1`) re-verifies this signature by calling the KDC's PAC validation RPC (`NetrLogonSamLogonEx` with `MSV1_0_PAC` flag). The KDC, holding the krbtgt key, recomputes the signature and returns success or failure. A forged silver ticket lacks the correct ticket signature (attacker does not have the krbtgt key) → verification fails.

The problem: most services do not opt in to PAC validation. IIS with Windows Auth, SQL Server with Kerberos, and COM+ with Kerberos perform PAC validation by default; SMB file services, HTTP services, and most custom applications do not. The performance cost is one RPC roundtrip to the DC per AP-REQ. Silver tickets against non-validating services persist undetected.

Workshop Decision 5 chose a fresh Rust KDC with `PAC_BUFFER_TICKET_CHECKSUM` implemented in `src/mskile/ticket_checksum.rs`. Decision 6 dropped NTLM server-side — services that no longer accept NTLM cannot be silver-ticket-attacked via the NTLM-acceptor path (which would otherwise bypass PAC validation entirely). This ADR specifies the framework's silver-ticket mitigation: mandatory KDC-side generation, default service-side validation, per-service opt-out, and audit logging.

## Threat model

**STRIDE classification**: Spoofing, Elevation of privilege (MITRE ATT&CK T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket; silver ticket is the related T1558.001 sub-technique)

**Attack vector** (step-by-step):

1. Attacker obtains a service account's hash via Kerberoasting (ADR-064) or DCSync (ADR-122).
2. Attacker runs `ticketer.py -nthash <service_account_hash> -domain-sid S-1-5-21-... -domain CORP.EXAMPLE.COM -user-id 500 -spn cifs/file01.example.com Administrator`.
3. `ticketer.py` constructs a `Ticket` ASN.1 with `sname = cifs/file01.example.com`, `cname = Administrator`, forged PAC with Domain Admins group SID, and the standard `PAC_SIGNATURE_DATA` (type 0x06) server signature computed with the service key.
4. The Ticket's `enc-part` is encrypted with the service account's hash. The forged ticket is placed in a ccache.
5. Attacker connects to `\\file01\c$` via SMB using the forged ticket (`smbclient.py --kerberos -k`).
6. file01's SMB server decrypts the ticket with its machine account key — succeeds. Extracts the PAC, sees Administrator + Domain Admins.
7. file01 grants access to `\\file01\c$` as if the attacker were genuinely Administrator.

If file01 has `VerifyPacAuthenticators = 1` (Server 2016+ PAC validation opt-in), step 6 includes a sub-step where the server calls `NetrLogonSamLogonEx` on the DC to verify the `PAC_BUFFER_TICKET_CHECKSUM`. The DC recomputes the signature with the krbtgt key and returns failure (the attacker's forged ticket lacks the correct signature). The AP-REQ fails with `KRB_AP_ERR_MODIFIED (41)`.

**Known mitigations in AD**: Server 2016+ KDC generates `PAC_BUFFER_TICKET_CHECKSUM` automatically; service-side validation requires registry opt-in (default off); Microsoft Defender for Identity detects silver ticket via behavioural anomalies; channel binding (TLS exporter) for IIS 10+ with `Extended Protection = Required`.

**Residual risk in AD**: Service-side validation is off by default (perf cost — one RPC per AP-REQ). Most services skip validation. Silver tickets persist undetected. MITM-able services without channel binding are vulnerable to ticket replay across sessions.

## Decision

The framework's KDC (per Decision 5) generates `PAC_BUFFER_TICKET_CHECKSUM` on **every** service ticket issuance — no opt-out on the KDC side. The framework's service-side Kerberos library (the `adrian-kdc-interop` acceptor library, used by every framework-managed service) validates `PAC_BUFFER_TICKET_CHECKSUM` on **every** AP-REQ by default — per-service opt-out is available for perf-critical services that opt in to a documented residual-risk acceptance.

Validation uses the framework's KDC PAC-validation RPC (`NetrLogonSamLogonEx`-equivalent) — the service sends the ticket signature to the KDC, which recomputes it with the HSM-bound krbtgt key (per ADR-065) and returns success/failure. The RPC is over the framework's mTLS-encrypted internal network; the perf cost is one round-trip per AP-REQ (≤5 ms typical intra-region).

Decision 6's NTLM-server-side drop is the defence-in-depth complement. Services that no longer accept NTLM cannot be silver-ticket-attacked via the NTLM-acceptor path (which would otherwise bypass PAC validation). For framework-managed services, the silver-ticket attack surface is: (a) services that accept Kerberos and validate `PAC_BUFFER_TICKET_CHECKSUM` (default) — protected; (b) services that accept Kerberos but opt out of validation (perf-critical, documented residual risk) — protected only if the service account's hash is not compromised; (c) services that accept neither Kerberos nor NTLM (e.g. OAuth2-only) — not vulnerable to silver ticket (different attack class).

**Concrete specification**:

- The framework's KDC (per Decision 5) MUST emit `PAC_BUFFER_TICKET_CHECKSUM` (PAC buffer type 0x0E) on every service ticket. The checksum is HMAC over the entire `Ticket.enc-part` using the krbtgt key, computed via the HSM (per ADR-065).
- The KDC MUST NOT support an opt-out of `PAC_BUFFER_TICKET_CHECKSUM` generation. Even AD-interop scenarios where the framework's KDC services AD-managed clients must emit the checksum.
- The framework's `adrian-kdc-interop` acceptor library MUST validate `PAC_BUFFER_TICKET_CHECKSUM` on every AP-REQ by default. Validation: extract the PAC buffer from the ticket's `authorization-data`, send the ticket signature to the framework's KDC via `NetrLogonSamLogonEx`-equivalent RPC, receive success/failure.
- The acceptor library MUST support a per-service opt-out via the service's configuration: `kerberos.pac_validation = "off"`. The opt-out MUST be audit-logged at service start (severity "medium", MITRE T1558.001 tag) and surfaced in the framework's coverage report (`adrian-cli security coverage`).
- On validation failure, the acceptor library MUST reject the AP-REQ with `KRB_AP_ERR_MODIFIED (41)` and emit an audit event (severity "high", MITRE T1558.001 tag) with attributes `adrian.kerberos.service.spn`, `adrian.kerberos.client.dn`, `adrian.kerberos.client.ip`, `adrian.kerberos.result.code`, `adrian.kerberos.result.reason = "pac_buffer_ticket_checksum_mismatch"`.
- The framework's audit pipeline MUST emit an OTel log record for every AP-REQ with attributes `adrian.kerberos.service.spn`, `adrian.kerberos.client.dn`, `adrian.kerberos.pac_validation` (boolean), `adrian.kerberos.result.code`, and MITRE T1558.001 tag when validation fails.
- The framework's audit pipeline MUST ship default detection rules:
  - Rule 1: AP-REQ with `pac_buffer_ticket_checksum_mismatch` → severity "high", MITRE T1558.001.
  - Rule 2: AP-REQ to a service with `kerberos.pac_validation = "off"` and `result = success` → severity "medium" (the service is operating with reduced security; a successful auth is not an attack but is flagged for visibility).
  - Rule 3: AP-REQ storm (>50 AP-REQs to one service in 5 minutes from one client) → severity "medium" (potential ticket-replay attack).
- The framework MUST support an alternative validation mechanism: **TLS channel binding** (RFC 5929 `tls-server-end-point`) for services that terminate TLS. The channel binding binds the Kerberos ticket to the TLS session; a ticket replayed across TLS sessions fails. Services that enable channel binding can disable PAC validation (`kerberos.pac_validation = "off"`, `kerberos.channel_binding = "required"`) without accepting the residual risk of forged silver tickets — channel binding provides equivalent protection without the per-AP-REQ RPC. Channel binding requires the framework's TLS termination library to expose `tls-server-end-point` to the Kerberos acceptor library.
- The framework MUST expose `adrian-cli security coverage --silver-ticket` returning per-service: `pac_validation` (on/off), `channel_binding` (required/optional/off), `krbtgt_key_version` (current kvno), and `last_validation_failure` (timestamp of the most recent `pac_buffer_ticket_checksum_mismatch`).
- The framework MUST emit a Prometheus metric `adrian_kerberos_ap_req_total{service,pac_validation,result}` (per ADR-057).
- The framework MUST ship a default Prometheus alert: `rate(adrian_kerberos_ap_req_total{result="pac_buffer_ticket_checksum_mismatch"}[5m]) > 0` triggers critical.

## Rationale

Mandatory KDC-side generation is non-negotiable. The KDC's cost of generating `PAC_BUFFER_TICKET_CHECKSUM` is one HMAC over the ticket's `enc-part` (≤0.5 ms with HSM, ≤0.05 ms without HSM in test environments) — negligible compared to the rest of the TGS-REQ path. There is no perf-based argument for making generation opt-out. The KDC always emits the checksum; whether the service validates it is the per-service decision.

Default service-side validation is the operational change. AD's default is `VerifyPacAuthenticators = 0` (off) because of the perf cost (one RPC per AP-REQ); the framework's default is `on` because the perf cost is acceptable (≤5 ms intra-region via mTLS RPC, vs. AD's Netlogon RPC over TCP/445 which is 10–20 ms typical). Framework-managed services are deployed in data centres with low-latency KDC access; the perf cost is bounded. Per-service opt-out is the escape hatch for perf-critical services that need to disable validation; the opt-out is audit-logged and surfaced in the coverage report so the security team can track which services are operating with reduced security.

Channel binding as an alternative is the perf optimisation for services that terminate TLS. Channel binding does not require a per-AP-REQ RPC — the binding is computed locally from the TLS session. The trade-off is that channel binding requires the service to terminate TLS (it does not work for non-TLS services like raw SMB) and requires the framework's TLS library to expose `tls-server-end-point`. For services that meet these requirements, channel binding is equivalent protection at lower perf cost.

Decision 6's NTLM-server-side drop eliminates the silver-ticket-via-NTLM-acceptor path. In AD, a service that accepts NTLM is silver-ticket-vulnerable if the attacker has the service's NT hash (because NTLM does not have a ticket signature mechanism). The framework's services do not accept NTLM (per Decision 6); this attack path is eliminated. The framework's services are silver-ticket-vulnerable only via the Kerberos-acceptor path, which is mitigated by `PAC_BUFFER_TICKET_CHECKSUM` validation.

The audit pipeline's detection rules surface both the attack (validation mismatch) and the residual-risk exposure (services with validation off). The coverage report is the operational tool for tracking which services have which posture; the security team reviews it weekly.

## Consequences

**Positive**: Silver tickets are detected on validation failure (default-on). Services that opt out are surfaced in the coverage report. Channel binding provides an alternative for TLS-terminating services. Decision 6's NTLM drop eliminates the silver-ticket-via-NTLM-acceptor path. MITRE ATT&CK T1558.001 mapping is automatic.

**Negative**: Default-on validation adds ≤5 ms per AP-REQ (one mTLS RPC to the KDC). Perf-critical services may need to opt out (audit-logged) or use channel binding (requires TLS termination). The audit pipeline's "validation off + success" rule generates noise on services that have legitimately opted out — the security team tunes the rule per service.

**Neutral**: The framework's `PAC_BUFFER_TICKET_CHECKSUM` is byte-compatible with Windows Server 2016+; Windows-managed services that validate the checksum accept framework-issued tickets and vice versa. The framework's `NetrLogonSamLogonEx`-equivalent RPC is compatible with AD's `NetrLogonSamLogonEx` for AD-interop scenarios where framework-managed services validate AD-issued tickets.

**Implementation cost**: ~2 person-months for the KDC-side checksum generation (in Decision 5's `src/mskile/ticket_checksum.rs`), ~2 person-months for the service-side validation library, ~1 person-month for the channel binding integration, ~1 person-month for the audit pipeline rules and the `adrian-cli security coverage` CLI. Reuses Decision 5's `adrian-kdc` and `adrian-kdc-interop`, ADR-065's HSM-bound krbtgt.

**Operational impact**: SOC analysts see silver-ticket alerts with MITRE T1558.001 tags. SREs monitor `adrian_kerberos_ap_req_total{result="pac_buffer_ticket_checksum_mismatch"}` for attack signal. The security team reviews `adrian-cli security coverage --silver-ticket` weekly to track opt-out services.

## Alternatives Considered

**Alternative A: Default-off validation, audit-only (match AD's default).** Make validation opt-in (matching AD's `VerifyPacAuthenticators = 0` default); rely on audit to detect attacks. Rejected because (a) the framework's value proposition is doing better than AD's defaults; (b) audit-only means the attack succeeds (the service grants access to the forged ticket) before the SOC sees the alert; (c) the perf cost of default-on is acceptable (≤5 ms intra-region).

**Alternative B: Eliminate silver-ticket-vulnerable services entirely (Kerberos-only with no opt-out).** Require every framework-managed service to validate `PAC_BUFFER_TICKET_CHECKSUM` with no opt-out. Rejected because (a) some services have legitimate perf requirements that the per-AP-REQ RPC cannot meet (e.g. high-throughput file servers with 10K+ AP-REQs/sec); (b) channel binding is an equivalent-protection alternative that does not require the per-AP-REQ RPC; (c) the audit-logged opt-out plus coverage report provides visibility without forcing a one-size-fits-all posture.

**Alternative C: Replace Kerberos service tickets with PKINIT service tickets.** Use public-key-based service tickets (per ADR-064 Alternative B discussion). Rejected for v1 because PKINIT for service tickets is not standardised (PKINIT is for AS-REQ), it requires a PKI for every service account, and it breaks AD-interop.

**Alternative D: Per-SPN service-account key rotation.** Rotate the service account's key frequently (e.g. daily) so a stolen key is short-lived. Rejected because (a) gMSA already rotates every 30 days (per ADR-064) and daily rotation adds operational overhead without eliminating the attack window; (b) the attacker who has the current key can forge tickets for the rotation interval; (c) `PAC_BUFFER_TICKET_CHECKSUM` validation is the comprehensive mitigation that does not depend on key rotation cadence.

## Open Questions

None. Workshop Decision 5 resolved the KDC-implementation ORQ-042/043/044 that gated this ADR. Decision 6's NTLM-server-side drop provides the defence-in-depth complement. The silver-ticket mitigation model is an implementation choice that does not gate further work.

## Cross-capability impact

- **KDC (PC-023/PC-025)**: Decision 5's `adrian-kdc` emits `PAC_BUFFER_TICKET_CHECKSUM`; this ADR specifies the service-side validation.
- **KDC (PC-030)**: ADR-065 (krbtgt HSM rotation) — the krbtgt key used for checksum generation is HSM-bound; rotation is automatic.
- **Auth Provider (PC-038)**: Decision 6 (NTLM drop) — services that do not accept NTLM cannot be silver-ticket-attacked via the NTLM-acceptor path.
- **Security (PC-116)**: ADR-064 (Kerberoasting) — Kerberoasting is the typical path to obtain the service-account hash needed for silver-ticket forgery; AES-only migration (ADR-064) makes the hash harder to obtain.
- **Security (PC-117)**: ADR-122 (DCSync) — DCSync is the other typical path to obtain the service-account hash; the audit pipeline detects both.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_kerberos_ap_req_total` is the key metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — AP-REQ audit events are part of the audit pipeline.
- **File Gateway (PC-078)**: ADR-040 (SMB server) — the framework's SMB server uses the `adrian-kdc-interop` acceptor library and validates `PAC_BUFFER_TICKET_CHECKSUM` by default; SMB is the canonical silver-ticket target so this is the highest-priority integration.

## References

- [PC-119](../catalog/11-security-threat-model.md) — problem statement (silver ticket; forged TGS via service-account hash; requires PAC_BUFFER_TICKET_CHECKSUM)
- [Kerberos internals KB](../docs/02-protocols/01-kerberos-internals.md) — Ticket structure, AP-REQ flow, `KRB_AP_ERR_MODIFIED (41)` error code
- [SPN/UPN/PAC KB](../docs/02-protocols/08-spn-upn-pac.md) — `PAC_BUFFER_TICKET_CHECKSUM` (type 0x0E) Server 2016+ ticket signature
- [Workshop Decision 5 — KDC implementation](../workshop/decision-05-kdc-implementation.md) — fresh Rust KDC; `PAC_BUFFER_TICKET_CHECKSUM` in `src/mskile/ticket_checksum.rs`
- [Workshop Decision 6 — NTLM decision](../workshop/decision-06-ntlm-decision.md) — server-side NTLM eliminated; defence-in-depth complement
- [ADR-064 — Kerberoasting AES migration](./ADR-064-kerberoasting-aes-migration.md) — service-account hash hardening (the typical silver-ticket precursor)
- [ADR-065 — krbtgt HSM rotation](./ADR-065-krbtgt-hsm-rotation.md) — HSM-bound krbtgt key used for checksum generation
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — AP-REQ Prometheus metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — AP-REQ audit events
- [RFC 4120 — Kerberos V5](https://datatracker.ietf.org/doc/html/rfc4120) (§5.3 for Ticket encryption; §3.2 for AP-REQ flow)
- [RFC 5929 — TLS Channel Bindings](https://datatracker.ietf.org/doc/html/rfc5929) (`tls-server-end-point` for channel binding)
- [MS-KILE — Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (`PAC_BUFFER_TICKET_CHECKSUM`, `VerifyPacAuthenticators`)
- [MS-PAC — Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/) (PAC buffer type 0x0E)
- [MITRE ATT&CK T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
