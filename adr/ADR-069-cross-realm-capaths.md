---
title: "ADR-069: Auto-Generate Kerberos capaths + DNS SRV KDC Discovery"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Migration
problem: PC-129
severity: medium
tags: [adr, migration, kerberos, cross-realm, capaths, dns-srv, trust, automation]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/12-migration-and-coexistence.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ../docs/09-linux-equivalents/08-freeipa-trust.md
  - ./ADR-062-trust-password-auto-rotation.md
  - ./ADR-068-subdomain-dns-strategy.md
last_updated: 2026-08-13
---

# ADR-069: Auto-Generate Kerberos capaths + DNS SRV KDC Discovery

## Status

Accepted — 2026-08-13

## Context

Cross-realm Kerberos trust between AD and the framework requires three components: (a) a `trustedDomain` object on both sides (AD has one for the framework's realm; the framework's directory has one for AD's realm), (b) a `krbtgt/<other-realm>@<this-realm>` cross-realm principal on both sides, with the same password (the cross-realm key), (c) `[capaths]` configuration in `krb5.conf` on KDCs and clients, encoding the trust graph so the KDC knows the referral path.

The `trustedDomain` object carries `trustDirection`, `trustType`, `trustAttributes`, `flatName`, `securityIdentifier`, and `trustAuthBlob` (containing the encrypted cross-realm key). Setting this up requires admin intervention on both sides: `netdom trust <framework-realm> /d:<ad-realm> /add /twoway /password:<cross-realm-password>` on the AD side; equivalent on the framework side.

The `[capaths]` section in `krb5.conf` encodes the realm-trust graph. For a direct trust between AD (`CORP.EXAMPLE.COM`) and the framework (`FRAMEWORK.COM`):

```
[capaths]
  CORP.EXAMPLE.COM = {
    FRAMEWORK.COM = .
  }
  FRAMEWORK.COM = {
    CORP.EXAMPLE.COM = .
  }
```

The `.` means "direct trust exists". For indirect trusts (e.g. framework trusts an intermediate realm that trusts AD), the path must be listed explicitly:

```
[capaths]
  FRAMEWORK.COM = {
    CORP.EXAMPLE.COM = INTERMEDIATE.COM
  }
```

Manual `capaths` configuration is error-prone. A typo or missing entry causes referral failures (`KDC_ERR_S_PRINCIPAL_UNKNOWN (6)` with no clear root cause). The Kerberos client libraries do not auto-discover the trust graph — they require explicit configuration. For a 10-realm migration (multiple child domains + framework realm), the `[capaths]` matrix is 90 entries.

The framework should automate cross-realm setup end-to-end. The framework's trust-management CLI should: (a) create the `trustedDomain` object on the framework side, (b) prompt the admin to run the equivalent `netdom` command on the AD side (or, if the admin has credentials, run it remotely via PowerShell remoting), (c) verify both sides have the trust, (d) auto-generate `[capaths]` for both MIT krb5 and Heimdal clients, (e) publish the trust graph via DNS TXT records so clients can auto-discover (similar to `Realms` DNS SRV per RFC 4120 §7.2.1, but for trust paths).

## Decision

The framework's trust-management CLI (`adrian-cli trust add`) automates the entire cross-realm setup end-to-end. The CLI: (1) creates the `trustedDomain` object on the framework side with the specified trust direction, type, and attributes; (2) generates a 256-bit random cross-realm key and writes it to the `trustAuthBlob`; (3) prompts the admin to run the equivalent `netdom` command on the AD side (or, if the admin provides AD credentials, runs it remotely via PowerShell remoting over WinRM); (4) verifies both sides have the trust by querying both KDCs for the `krbtgt/<other-realm>@<this-realm>` principal; (5) auto-generates `[capaths]` configuration for MIT krb5 and Heimdal clients, written to a framework-managed config file (`/etc/krb5.conf.d/adrian-capaths.conf` on Linux, PSSO Extension profile on macOS); (6) publishes the trust graph via DNS TXT records under `_kerberos._trust.<realm>` so clients can auto-discover the trust paths.

The framework's KDC supports the auto-discovery mechanism: when a client requests a cross-realm referral for a realm not in its local `[capaths]`, the KDC queries the DNS TXT records for the trust graph and dynamically computes the referral path. This eliminates the need for manual `[capaths]` configuration on KDCs (clients still need it if they want to compute the path locally for performance).

The trust graph is stored in the framework's directory as `trustedDomain` objects. The CLI reads the trust graph, computes the shortest path between any two realms (BFS algorithm), and generates the `[capaths]` configuration. The CLI also validates the trust graph for cycles (which would cause infinite referral loops) and warns the admin.

For AD-interop scenarios, the framework's CLI generates a Windows-compatible configuration: a PowerShell script that runs `netdom trust` on the AD side, a `krb5.conf` snippet for Linux/macOS clients (with the framework's auto-generated `[capaths]`), and a Windows registry import file that sets the `[capaths]`-equivalent registry keys on Windows clients (Windows does not use `krb5.conf` but stores the trust graph in the `Lsa` registry hive).

**Concrete specification**:

- The framework MUST ship a CLI command `adrian-cli trust add` that automates cross-realm trust setup:
  - Inputs: `--partner-realm <REALM>`, `--direction [incoming | outgoing | bidirectional]`, `--type [forest | external | realm]`, `--password <cross-realm-password>` (or `--generate-password` to generate a 256-bit random password), `--ad-admin-credentials <pscredential>` (optional, for remote netdom invocation).
  - Outputs: a `trustedDomain` object on the framework side, a PowerShell script for the AD side, a `krb5.conf` snippet for Linux/macOS clients, a Windows registry import file for Windows clients.
- The CLI MUST verify both sides have the trust by querying both KDCs for the `krbtgt/<other-realm>@<this-realm>` principal.
- The CLI MUST support automatic remote invocation on the AD side if `--ad-admin-credentials` is provided (via PowerShell remoting over WinRM).
- The framework MUST auto-generate `[capaths]` configuration from the trust graph:
  - For direct trusts: `<partner-realm> = .` (the `.` means direct trust).
  - For indirect trusts: `<partner-realm> = <intermediate-realm-1>, <intermediate-realm-2>, ...` (the comma-separated path through intermediate realms).
- The CLI MUST validate the trust graph for cycles and warn the admin if a cycle is detected.
- The CLI MUST compute the shortest path between any two realms using BFS.
- The framework's KDC MUST support DNS-based trust-path discovery: when a client requests a cross-realm referral for a realm not in its local `[capaths]`, the KDC queries DNS TXT records under `_kerberos._trust.<target-realm>` for the trust graph and dynamically computes the referral path.
- The framework's DNS server MUST expose the trust graph as DNS TXT records:
  - `_kerberos._trust.<realm> TXT "trusted=<partner-realm-1>,<partner-realm-2>,..."` — lists direct trusts.
  - `_kerberos._trust.<realm> TXT "transitive=yes|no"` — indicates whether the realm's trusts are transitive.
- The framework's DNS server MUST expose per-realm KDC discovery via DNS SRV records (per RFC 4120 §7.2.1 and ADR-068):
  - `_kerberos._tcp.<realm> SRV 0 100 88 <kdc-host>.<realm>`
  - `_kerberos._udp.<realm> SRV 0 100 88 <kdc-host>.<realm>`
  - `_kpasswd._tcp.<realm> SRV 0 100 464 <kdc-host>.<realm>`
- The framework MUST support bidirectional, transitive, and external trust types (per AD's `trustAttributes` bitmask).
- The framework MUST support the `TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20` (within-forest, transitive), `TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1` (external, non-transitive), `TRUST_ATTRIBUTE_QUARANTINED = 0x4` (sIDHistory-filtered), `TRUST_ATTRIBUTE_PIM_TRUST = 0x200` (PIM, Server 2016+) trust attributes.
- For AD-interop scenarios, the framework MUST participate in AD's `I_NetServerPasswordSet2` trust-password rotation (per [ADR-062](./ADR-062-trust-password-auto-rotation.md)).
- The framework MUST ship a CLI command `adrian-cli trust list` that dumps the trust graph in human-readable and JSON formats.
- The framework MUST ship a CLI command `adrian-cli trust verify --partner-realm <REALM>` that verifies the trust is healthy (both sides have the trust object, the cross-realm key matches, the `[capaths]` is correct).
- The framework MUST log every trust-management operation as an OTel audit event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with attributes `adrian.trust.partner`, `adrian.trust.direction`, `adrian.trust.type`, `adrian.trust.operation`, `adrian.trust.result`, and MITRE ATT&CK T1486 (Resource Hijacking) when the operation is `add` and the trust type is `external` (external trusts are a higher risk for abuse).

## Migration state machine

**Source state**: AD forest at `CORP.EXAMPLE.COM` with no trust to the framework. AD clients query `_kerberos._tcp.corp.example.com` for KDC discovery and have no `[capaths]` configuration for the framework's realm.

**Target state**: Framework realm at `FRAMEWORK.COM` (or `FWK.CORP.EXAMPLE.COM` per ADR-068) with bidirectional cross-realm trust to AD. `[capaths]` configured on all KDCs and clients (auto-generated by the framework's CLI). Referral TGTs flow between realms. The trust graph is published via DNS TXT records for auto-discovery.

**Coexistence period**: 90–365 days. During this window:
- The framework's `adrian-cli trust add` has been run; the trust is established.
- `[capaths]` configuration is auto-generated and distributed to clients (via MDM on macOS, via configuration-management on Linux, via registry import on Windows).
- Users in either realm can access resources in the other realm via cross-realm referral.
- The trust is managed by the framework's `TrustHealthController` (per ADR-062) — auto-rotation, desync detection, auto-reset.

**Cutover trigger**: When 100% of users, computers, and services have been migrated to the framework (per PC-126, deferred), the cross-realm trust can be removed. AD's `trustedDomain` object for the framework is deleted; the framework's `trustedDomain` object for AD is deleted; `[capaths]` entries are removed from client configs; DNS TXT records for the trust graph are deleted.

**Rollback path**: Re-establish the cross-realm trust via `adrian-cli trust add` (or `netdom trust /add` on the AD side). Re-add `[capaths]` entries to client configs. The framework's trust-management tool preserves a rollback configuration for each trust (the previous trust object, the previous cross-realm key, the previous `[capaths]` config) for 30 days.

## Rationale

Automating cross-realm setup end-to-end is the only way to make cross-realm trust operationally tractable. Manual setup involves: (a) running `netdom` on the AD side, (b) running the equivalent on the framework side, (c) editing `krb5.conf` on every Linux/macOS client, (d) editing the registry on every Windows client, (e) verifying the trust. For a 10-realm migration, this is hundreds of manual operations, each of which can fail silently. The framework's CLI eliminates all of these manual operations.

DNS-based trust-path discovery is the modern alternative to manual `[capaths]` configuration. RFC 4120 §7.2.1 specifies DNS SRV records for KDC discovery; the framework extends this with DNS TXT records for trust-graph discovery. Clients (and KDCs) can auto-discover the trust graph by querying DNS, eliminating the need for local `[capaths]` configuration. This is the same model as DANE (RFC 6698) for TLS — DNS-based discovery of cryptographic material.

The BFS shortest-path algorithm is the standard for trust-graph traversal. The algorithm is O(V + E) for a trust graph with V realms and E trusts, which is fast enough for any realistic trust graph (10s of realms). Cycle detection prevents infinite referral loops (which would otherwise cause a KDC to refer a request back to itself forever).

The PowerShell-remoting integration for AD-side `netdom` invocation is a usability improvement: the admin does not need to log into the AD DC separately. The integration uses WinRM (Windows Remote Management) and the standard PowerShell `Enter-PSSession` cmdlet. The admin's credentials are passed via `--ad-admin-credentials` (a PowerShell `PSCredential` object); the framework's CLI uses the credentials to invoke `netdom` on the AD DC.

Preserving the trust object, the cross-realm key, and the `[capaths]` config for 30 days for rollback is the safety net. If a trust setup breaks something (e.g. an application that does not handle cross-realm referrals correctly), the operator can roll back the trust to its previous state. The 30-day retention matches ADR-068's rollback retention.

## Consequences

**Positive**: Cross-realm setup is one CLI command (`adrian-cli trust add`). `[capaths]` configuration is auto-generated and distributed. DNS-based trust-path discovery eliminates the need for manual `[capaths]` on KDCs. Cycle detection prevents infinite referral loops. AD-interop is supported via PowerShell-remoting integration. Rollback is one CLI command (`adrian-cli trust rollback`).

**Negative**: The framework's CLI requires AD admin credentials for automatic remote `netdom` invocation (or the admin must run `netdom` manually on the AD side). DNS-based trust-path discovery adds DNS TXT records that must be replicated to all DNS servers (the neutral DNS per ADR-068). The auto-generated `[capaths]` config must be distributed to clients (via MDM, configuration management, or registry import), which requires client-side tooling.

**Neutral**: The framework's cross-realm automation does not preclude manual setup — operators can still run `netdom` and edit `krb5.conf` manually if needed. The CLI's auto-generated config is the default; manual config is opt-in.

**Implementation cost**: ~3 person-months for the trust-management CLI (trust object creation, netdom invocation, verification, capaths generation); ~2 person-months for the KDC DNS-based discovery (TXT record parsing, BFS path computation); ~2 person-months for the client-side distribution tooling (MDM profile, krb5.conf snippet, Windows registry import); ~1 person-month for the audit integration. Total: ~8 person-months for v1.

**Operational impact**: Migration teams use `adrian-cli trust add` for cross-realm setup (one command per trust). Client-side tooling distributes the `[capaths]` config automatically. SOC analysts see trust-management operations in the audit pipeline. The cutover (trust removal) is a documented runbook.

## Alternatives Considered

**Alternative A: Manual setup only (preserve AD's model).** Provide documentation for manual `netdom` and `krb5.conf` configuration; rely on operators. Rejected because (a) manual setup is error-prone (typos in `[capaths]` cause cryptic failures), (b) for a 10-realm migration, the `[capaths]` matrix is 90 entries — manual configuration is intractable, (c) manual setup does not provide rollback, (d) the framework's value proposition is to eliminate manual operations.

**Alternative B: FreeIPA's `ipa trust-add` model only.** FreeIPA's `ipa trust-add` automates cross-realm setup for AD trusts. Rejected as the only path because (a) FreeIPA's automation is IPA-specific (it assumes the framework is FreeIPA), (b) it does not support the full range of trust types (forest, external, realm, PIM), (c) it does not auto-generate `[capaths]` for non-FreeIPA clients (MIT krb5, Heimdal), (d) it does not publish the trust graph via DNS TXT records. FreeIPA's model is a reference; the framework's CLI generalises it.

**Alternative C: DNS-only trust discovery (no `krb5.conf` `[capaths]` ever).** Eliminate `[capaths]` entirely; rely on DNS TXT records for all trust-path discovery. Rejected for v1 because (a) MIT krb5 and Heimdal do not natively support DNS-based trust-path discovery (they require local `[capaths]`), (b) DNS-based discovery adds latency (one DNS query per referral decision), (c) DNS is not always available (air-gapped environments). DNS-based discovery is the KDC-side mechanism; clients still need local `[capaths]` for performance.

**Alternative D: X.509-based cross-realm (PKINIT cross-certification).** Replace shared-password cross-realm trust with X.509 cross-certification (PKINIT, RFC 4556). Rejected for v1 because (a) it requires a PKI for every realm, adding a dependency on the deferred federation layer (ORQ-132/133/134) and the Cert Service (ORQ-110/111), (b) PKINIT cross-certification is not widely deployed (most Kerberos deployments use shared-password cross-realm), (c) it breaks AD-interop entirely (AD does not support PKINIT cross-certification). PKINIT cross-certification may be added in v2 for framework-to-framework trusts.

## Open Questions

None — this is an ADR-ELIGIBLE decision. The KDC implementation choice (PC-023 / Tier-1 ORQ-042/043/044) does not gate this decision: the cross-realm referral protocol is RFC 4120 §3.3.3 (standardised) and MS-KILE (AD-interop); both are supported by any KDC implementation that the framework may choose.

## Cross-capability impact

- **KDC (PC-023 through PC-035)**: KDC must implement RFC 4120 §3.3.3 cross-realm referral; PC-028 (cross-realm TGT referral) is the KDC capability.
- **KDC (PC-030)**: krbtgt rotation (ADR-065 for golden-ticket mitigation) is coordinated with cross-realm trust setup — the cross-realm key is rotated by the `TrustHealthController` (per ADR-062).
- **Core Directory (PC-014)**: FSMO roles (PC-014) — the PDC emulator is often the trust-management DC; the framework's operator must coordinate trust setup with FSMO placement.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — trust-health and trust-password-age are Prometheus metrics (per ADR-062).
- **Operations (PC-111)**: ADR-060 (audit logs) — trust-management operations are part of the audit pipeline.
- **Operations (PC-115)**: ADR-063 (unified CLI) — the `trust` subcommand (`add`, `verify`, `list`, `rollback`) is part of the unified CLI.
- **Migration (PC-126)**: Client switchover (PC-126, deferred) depends on cross-realm trust for parallel-run mode.
- **Migration (PC-128)**: ADR-068 (subdomain-per-directory DNS) — KDC discovery via DNS SRV (`_kerberos._tcp.fwk.<forest-root>`) is part of this ADR.
- **Security (PC-120)**: sIDHistory abuse (PC-120, deferred) — within-forest trusts (which preserve sIDHistory) are a trust type supported by this ADR; the framework defaults to sIDHistory filtering on all trusts.

## References

- [PC-129](../catalog/12-migration-and-coexistence.md) — problem statement (Kerberos cross-realm with AD during migration requires capaths + trust object)
- [Kerberos internals](../docs/02-protocols/01-kerberos-internals.md) — Kerberos cross-realm referral flow (RFC 4120 §3.3.3), TGT referral TGS-REQ/TGS-REP message exchange
- [Trusts topology](../docs/03-directory-schema/04-trusts-topology.md) — `trustedDomain` object, `trustAuthBlob` structure containing the cross-realm key, `trustDirection`/`trustType`/`trustAttributes` semantics
- [FreeIPA trust](../docs/09-linux-equivalents/08-freeipa-trust.md) — FreeIPA's `ipa trust-add` flow that automates cross-realm setup, including the `[capaths]` configuration written to `/var/kerberos/krb5kdc/kdc.conf` and `/etc/krb5.conf`
- [RFC 4120 — Kerberos Network Authentication Service](https://datatracker.ietf.org/doc/html/rfc4120) (§3.3.3 for cross-realm referral; §7.2.1 for DNS SRV KDC discovery)
- [RFC 4556 — PKINIT (Public Key Cryptography for Initial Authentication in Kerberos)](https://datatracker.ietf.org/doc/html/rfc4556) (for reference; not chosen for v1)
- [RFC 2782 — DNS SRV Records](https://datatracker.ietf.org/doc/html/rfc2782)
- [MS-KILE — Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (cross-realm referral profile)
- [MS-LSAD — Local Security Authority (Domain Policy) Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/) (for `trustedDomain` object semantics)
- [MIT Kerberos Documentation — capaths](https://web.mit.edu/kerberos/krb5-1.21/doc/admin/conf_files/krb5_conf.html) (for `[capaths]` configuration format)
