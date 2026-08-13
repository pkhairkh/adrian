---
title: "ADR-022: Standard NTP via chrony; Drop MS-SNTP; Alert on Clock Skew"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Auth Provider
problem: PC-041
severity: high
tags: [adr, auth-provider, ntp, chrony, ms-sntp, time-sync, kerberos-skew]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/03-auth-provider.md
  - ../docs/02-protocols/07-ntp-time-sync.md
  - ./ADR-012-fast-armoring-required.md
last_updated: 2026-08-13
---

# ADR-022: Standard NTP via chrony; Drop MS-SNTP; Alert on Clock Skew

## Status

Accepted — 2026-08-13

## Context

Kerberos requires clocks within 5 minutes (`clockskew` parameter, [RFC 4120 §5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3)). PA-ENC-TIMESTAMP pre-auth fails with `KRB_AP_ERR_SKEW (37)` if outside the window. AD uses W32Time + MS-SNTP (Microsoft's authenticated NTP extension) — the Netlogon secure channel key signs NTP responses, so DCs can authenticate time to clients. chrony / ntpd do not support MS-SNTP, per [PC-041](../catalog/03-auth-provider.md#pc-041--time-sync-w32time--ms-sntp-is-fragile-5-minute-kerberos-skew-window-breaks-auth) and [docs/02-protocols/07-ntp-time-sync.md](../docs/02-protocols/07-ntp-time-sync.md).

VM time drift via Hyper-V / VMware integration services is a common cause of skew. When a VM is paused / resumed / live-migrated, its clock jumps; if the jump exceeds 5 minutes, Kerberos auth fails until W32Time catches up (typically 5–15 minutes). Linux VMs without `pti` (Page Table Isolation) mitigation can drift faster; macOS VMs on Apple Silicon drift due to TSC differences.

The MS-SNTP authentication extension uses the Netlogon secure channel key to sign NTP packets: the Key ID field in the NTP packet (offset 48) is set to the security context ID; the MAC (offset 52+) is an MD5 HMAC of the NTP packet keyed with the session key derived from the Netlogon secure channel. The client validates the MAC to ensure the time came from a trusted DC. Without MS-SNTP, an attacker could MITM the NTP response and force clock skew, causing auth failures or replay attacks. In practice, the MS-SNTP authentication is rarely attacked — the threat model is theoretical, and modern NTP deployments use authenticated NTP (RFC 5906) or NTS (RFC 8915) instead.

Constraints from [PC-041](../catalog/03-auth-provider.md#pc-041--time-sync-w32time--ms-sntp-is-fragile-5-minute-kerberos-skew-window-breaks-auth):

- Must support RFC 5905 NTP.
- Consider MS-SNTP only for legacy AD interop (chrony/ntpd do not support MS-SNTP).
- Must monitor skew and alert on >2 minute drift.
- For AD interop, must accept MS-SNTP-signed NTP responses from Windows DCs.

## Decision

The framework SHALL use standard NTP ([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)) via chrony as the time sync protocol on all DCs and clients. The framework SHALL drop MS-SNTP entirely — the framework's DCs SHALL NOT send MS-SNTP-signed NTP responses, and the framework's clients SHALL NOT validate MS-SNTP signatures. The framework SHALL alert on clock skew >2 minutes (the Kerberos 5-minute window's safety margin).

The framework's DCs SHALL run chrony in a stratum hierarchy: the forest-root PDC emulator (or the framework's equivalent time-master DC) SHALL be stratum-2 (synced from an external stratum-1 NTP server); other DCs SHALL be stratum-3 (synced from the time-master DC); clients SHALL be stratum-4 (synced from their nearest DC). The framework SHALL expose a CLI command (`adrian-time status`) that shows the current sync source, stratum, offset, and drift.

The framework SHALL alert on clock skew >2 minutes. The alert SHALL be emitted via the framework's monitoring system (Prometheus metric + Alertmanager rule; or equivalent) and SHALL include: DC hostname, current offset, sync source, last-successful-sync timestamp. The framework SHALL also alert on sync failure (chrony unable to reach its upstream server for >5 minutes).

For AD-interop mode, the framework SHALL accept MS-SNTP-signed NTP responses from Windows DCs for read-only interop (the framework's clients can sync from Windows DCs that send MS-SNTP-signed responses). The framework's DCs SHALL NOT send MS-SNTP-signed responses — Windows clients syncing from the framework's DCs use plain NTP (no MS-SNTP). This is a one-way interop: framework → Windows (framework accepts MS-SNTP from Windows); Windows → framework (Windows uses plain NTP from framework).

The framework SHALL expose a CLI command (`adrian-time skew-check`) that checks the clock skew between the local host and a specified DC (or all DCs). This is useful for diagnosing Kerberos auth failures caused by skew.

The framework SHALL document the time-sync prerequisite for Kerberos: all DCs and clients MUST sync from a common NTP source; skew >5 minutes causes `KRB_AP_ERR_SKEW (37)` auth failures. The framework's installation guide SHALL include chrony configuration as a mandatory step.

The framework SHALL support NTS (Network Time Security, [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915)) as an optional authenticated-NTP mechanism for high-security deployments. NTS provides cryptographic authentication of NTP responses without the Netlogon-secure-channel dependency. The framework SHALL expose a CLI command (`adrian-time enable-nts <nts-server>`) that configures chrony to use NTS.

**Concrete specification**:

- The framework SHALL use standard NTP (RFC 5905) via chrony as the time sync protocol on all DCs and clients.
- The framework SHALL drop MS-SNTP entirely — DCs SHALL NOT send MS-SNTP-signed responses; clients SHALL NOT validate MS-SNTP signatures.
- The forest-root PDC emulator (or equivalent time-master DC) SHALL be stratum-2 (synced from external stratum-1 NTP server); other DCs stratum-3 (from time-master); clients stratum-4 (from nearest DC).
- The framework SHALL alert on clock skew >2 minutes (Prometheus metric + Alertmanager rule; or equivalent).
- The framework SHALL alert on sync failure (chrony unable to reach upstream for >5 minutes).
- For AD-interop mode, the framework SHALL accept MS-SNTP-signed NTP responses from Windows DCs (one-way interop: framework → Windows).
- The framework SHALL expose `adrian-time status` (current sync source, stratum, offset, drift), `adrian-time skew-check` (check skew between local host and DC(s)), and `adrian-time enable-nts <nts-server>` (configure NTS) CLI commands.
- The framework SHALL support NTS (RFC 8915) as an optional authenticated-NTP mechanism for high-security deployments.
- The framework's installation guide SHALL include chrony configuration as a mandatory step.

## Rationale

MS-SNTP is a Microsoft-specific NTP authentication extension that requires the Netlogon secure channel. chrony (the modern NTP implementation) and ntpd (the legacy NTP implementation) do not support MS-SNTP. The result is that mixed-OS forests (Windows DCs + Linux DCs) have asymmetric time sync — Windows DCs send MS-SNTP-signed responses that Linux clients ignore; Linux DCs send plain NTP that Windows clients accept but without the MS-SNTP authentication. The MS-SNTP authentication is rarely attacked in practice, and modern alternatives (NTS, RFC 8915) provide cryptographic authentication without the Netlogon dependency.

Three alternatives were considered:

**Alternative A — Keep MS-SNTP for AD-interop.** The framework's DCs send MS-SNTP-signed responses; Windows clients validate. The advantage is byte-identical AD-interop. The disadvantage is requiring the Netlogon secure channel on the framework's DCs (a non-trivial dependency) and the MS-SNTP cryptographic code (which is Microsoft-specific and not in chrony / ntpd). Rejected as the primary mechanism; ADOPTED as a one-way interop (framework accepts MS-SNTP from Windows for read-only sync).

**Alternative B — Use NTS (RFC 8915) as the primary authenticated-NTP mechanism.** NTS provides cryptographic authentication of NTP responses without the Netlogon dependency. The advantage is modern, standardized authentication. The disadvantage is that NTS is not yet widely deployed (chrony supports it since 4.0; ntpd does not support it as of 2024). Rejected as the primary mechanism for v1; ADOPTED as an optional mechanism for high-security deployments. The framework's default is plain NTP (no authentication) with skew monitoring; NTS is opt-in.

**Alternative C — Use authenticated NTP per RFC 5906 (Autokey successor).** RFC 5906 defines authenticated NTP using symmetric keys or Autokey. The advantage is standardized authentication. The disadvantage is that Autokey has known security vulnerabilities (RFC 5906 is informational, not standards-track) and is deprecated in chrony. Rejected in favor of NTS (RFC 8915) for high-security deployments.

External evidence: [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905) defines NTPv4; [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915) defines NTS; [RFC 4120 §5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3) defines the Kerberos clockskew parameter; [chrony documentation](https://chrony-project.org/documentation.html) covers chrony configuration including NTS. Microsoft's [W32Time documentation](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-topology) covers AD's time-sync architecture. The framework's design matches the modern pattern (chrony + NTS opt-in) while preserving AD-interop via one-way MS-SNTP acceptance.

The cost of this decision is implementation effort for the skew-monitoring alert and the CLI commands. The chrony integration itself is configuration-only (no framework code change); the framework's installation guide includes the chrony config. The MS-SNTP one-way acceptance requires a small MS-SNTP parser in the framework's NTP client (for AD-interop mode).

## Consequences

**Positive**: Cross-platform time sync works without the MS-SNTP dependency. chrony is the modern NTP implementation with better drift tracking and faster convergence than ntpd. Skew monitoring provides early warning before the 5-minute Kerberos window is exceeded. NTS opt-in provides cryptographic authentication for high-security deployments.

**Negative**: Windows clients syncing from the framework's DCs use plain NTP (no MS-SNTP authentication). This is a security regression for Windows-only deployments that relied on MS-SNTP authentication. The framework mitigates this by recommending NTS for high-security deployments.

**Neutral**: The MS-SNTP one-way acceptance (framework accepts MS-SNTP from Windows DCs) is invisible to operators — the framework's clients sync from Windows DCs without configuration changes. The skew monitoring is additive; deployments that don't use it pay no cost.

**Implementation cost**: ~3 person-weeks for the skew-monitoring alert, the CLI commands, the MS-SNTP one-way parser, and the installation-guide documentation. The chrony integration is configuration-only.

**Operational impact**: Time sync works cross-platform without MS-SNTP. Skew monitoring provides early warning. The `adrian-time status` and `adrian-time skew-check` CLI commands are useful for diagnosing Kerberos auth failures. The NTS opt-in enables high-security deployments.

## Alternatives Considered

### Alternative 1: Keep MS-SNTP for AD-interop

Byte-identical AD-interop; requires Netlogon secure channel and MS-SNTP cryptographic code. Rejected as primary; ADOPTED as one-way interop (framework accepts MS-SNTP from Windows for read-only sync).

### Alternative 2: Use NTS (RFC 8915) as primary authenticated-NTP mechanism

Modern, standardized authentication; not yet widely deployed. Rejected as primary for v1; ADOPTED as optional mechanism for high-security deployments.

### Alternative 3: Use authenticated NTP per RFC 5906 (Autokey)

Standardized authentication; Autokey has known vulnerabilities, deprecated in chrony. Rejected in favor of NTS (RFC 8915).

## Open Questions

- For the skew-monitoring alert, what is the alert threshold? The Decision section specifies >2 minutes (the 5-minute Kerberos window's safety margin). Should this be configurable per-deployment? Yes — operators in high-security environments may want a tighter threshold (e.g. 1 minute).
- For NTS, what is the recommended NTS server? The framework's installation guide SHALL recommend a public NTS-capable NTP server (e.g. Cloudflare's `time.cloudflare.com:1234`, Netnod's `nts.netnod.se`). For on-prem deployments, the framework SHALL support running a local NTS server.
- Cross-reference ADR-012 (FAST armoring) — FAST depends on time sync (the armor TGT's `authtime` must be within skew). The two ADRs are complementary.
- Cross-reference PC-022 (multi-tenancy, DEFERRED) — multi-tenancy may require per-tenant time-master DCs; the framework's chrony configuration must support per-tenant time-master hierarchy. Defer until multi-tenancy is resolved.

## Cross-capability impact

- **KDC**: KDC's 5-minute skew window is the protocol-level constraint. The framework's skew monitoring provides early warning before the window is exceeded.
- **Operations**: Time-sync monitoring is a core ops task. The `adrian-time status` and `adrian-time skew-check` CLI commands are standard ops tools.
- **Migration**: AD-to-framework migration replaces W32Time with chrony on the framework's DCs. Windows clients syncing from the framework's DCs use plain NTP (no MS-SNTP); this is a behavior change for Windows-only deployments.
- **Security**: Skew monitoring detects replay-attack attempts (an attacker attempting to replay an old authenticator may cause skew alerts). NTS opt-in provides cryptographic authentication for high-security deployments.
- **Client SDK**: Client SDK exposes `adrian-time status` and `adrian-time skew-check` for client-side time-sync diagnostics.

## References

- [PC-041](../catalog/03-auth-provider.md) — problem statement in the catalog
- [docs/02-protocols/07-ntp-time-sync.md](../docs/02-protocols/07-ntp-time-sync.md) — W32Time architecture, MS-SNTP authentication extension, NTP packet structure, Kerberos 5-minute skew window
- [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905) — NTPv4
- [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915) — Network Time Security (NTS)
- [RFC 4120 §5.3](https://www.rfc-editor.org/rfc/rfc4120#section-5.3) — Kerberos clockskew
- [chrony documentation](https://chrony-project.org/documentation.html)
- [Microsoft W32Time documentation](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-topology)
