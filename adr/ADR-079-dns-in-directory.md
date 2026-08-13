---
title: "ADR-079: AD-Integrated DNS Zones via DRSUAPI Replication with Native-Mode CoreDNS+FDB Plugin"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-019
severity: high
unblocked_by: Workshop Decision 1 (ORQ-001/002/003/004) and Workshop Decision 2 (ORQ-011/012/013/014)
tags: [adr, core-directory, dns, ad-integrated-dns, drsuapi, coredns, foundationdb, gss-tsig, ddns]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-01-replication-protocol.md
  - ../workshop/decision-02-storage-engine.md
  - ../catalog/01-core-directory.md
  - ../docs/02-protocols/05-dns-dynamic-updates.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ./ADR-070-drsuapi-replication-protocol.md
  - ./ADR-073-storage-engine.md
last_updated: 2026-08-13
---

# ADR-079: AD-Integrated DNS Zones via DRSUAPI Replication with Native-Mode CoreDNS+FDB Plugin

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-001/002/003/004 (replication) and ORQ-011/012/013/014 (storage). It is now unblocked by [Workshop Decision 1 (Hybrid Replication)](../workshop/decision-01-replication-protocol.md) and [Workshop Decision 2 (FoundationDB Storage Engine)](../workshop/decision-02-storage-engine.md).

## Context

AD-integrated DNS stores zones as `dnsNode` objects in two application partitions (NDNCs — Naming Context Definition Naming Contexts): `DomainDnsZones.<domain>` (per-domain DNS data, replicates to all DCs in the domain) and `ForestDnsZones.<forest>` (forest-wide DNS data, replicates to all DCs in the forest). Each `dnsNode` object's `dnsRecord` attribute is a multi-valued binary blob, where each value is a `DNS_RECORD` structure (type, TTL, data) per the DNS wire format. The zones replicate via the same DRSUAPI `IDL_DRSGetNCChanges` mechanism as Domain NCs, per [PC-019](../catalog/01-core-directory.md#pc-019--ad-integrated-dns-zones-replicate-via-drsuapi-in-domaindnszones--forestdnszones-ncs) and [docs/02-protocols/05-dns-dynamic-updates.md](../docs/02-protocols/05-dns-dynamic-updates.md).

AD-integrated DNS features: per-DC DNS (each DC serves its own copy of the zone, accepting dynamic updates), secure DDNS via GSS-TSIG keyed to machine accounts (the machine account's password is the GSS-TSIG key), scavenging (aging-based record cleanup), and forest-wide single source of truth for `_msdcs.<forest>` records (DC locator SRV records). The alternative — file-based DNS zones (BIND, PowerDNS, CoreDNS) — lacks directory replication (each server has its own copy) and lacks secure DDNS tied to machine accounts (would need a separate key distribution mechanism).

BIND with the `dlz_bind` Samba plugin is the closest open-source analog: BIND reads zone data from Samba's LDB store, which replicates via DRSUAPI. FreeIPA stores DNS in 389-DS (its own LDAP), replicating via 389-DS's MMR — not DRSUAPI-compatible. A framework must decide whether to keep DNS in the directory (AD-interop) or externalize (BIND/PowerDNS/CoreDNS) and lose AD DNS features (scavenging, secure DDNS via GSS-TSIG keyed to machine accounts).

**Unblocking decisions.** [Workshop Decision 1](../workshop/decision-01-replication-protocol.md) specifies: DNS zones replicate via `DrSuapiReplicator` for AD-interop; native mode uses CoreDNS plugin reading from FDB, no replication of DNS zones (FDB is the substrate). [Workshop Decision 2](../workshop/decision-02-storage-engine.md) specifies FDB as the storage engine — `dnsNode` objects are stored in FDB subspace `0x01` (objects), and the CoreDNS plugin reads directly from FDB. This ADR translates both decisions into the concrete DNS implementation.

## Decision

The framework SHALL support two DNS modes:

1. **AD-interop mode**: DNS zones are stored as `dnsNode` objects in `DomainDnsZones.<domain>` and `ForestDnsZones.<forest>` NDNCs. Replication uses `DrSuapiReplicator` (per ADR-070) — the NDNCs replicate via DRSUAPI byte-identically to AD. A CoreDNS plugin (`adrian-dns-coredns`) reads zone data from the directory (via the framework's LDAP server, or directly from FDB subspace `0x01`); the plugin serves DNS on port 53. Secure DDNS via GSS-TSIG (RFC 3645) is keyed to machine accounts (the machine account's password is the GSS-TSIG key, retrieved from the directory).

2. **Native mode**: DNS zones are stored as `dnsNode` objects in FDB subspace `0x01` (no separate NDNCs — the framework's single NC contains DNS data). There is no replication of DNS zones (FDB's multi-region synchronous replication provides the substrate). The CoreDNS plugin reads directly from FDB. Secure DDNS via GSS-TSIG is keyed to machine accounts (same as AD-interop mode).

**Concrete specification**:

- The framework SHALL store DNS zones as `dnsNode` objects with `dnsRecord` multi-valued binary attribute (each value is a `DNS_RECORD` structure per the DNS wire format). The `dnsZone` container object holds the zone's SOA, NS, and configuration attributes.
- The framework SHALL support the two AD NDNCs in AD-interop mode: `DomainDnsZones.<domain>` (per-domain) and `ForestDnsZones.<forest>` (forest-wide). The `_msdcs.<forest>` zone is stored in `ForestDnsZones.<forest>` for forest-wide DC-locator SRV record publication.
- The framework SHALL use the `adrian-dns-coredns` plugin (a CoreDNS plugin written in Go, communicating with the framework's Rust directory via gRPC) to serve DNS on port 53. The plugin's backend is FDB-direct (native mode) or LDAP-via-loopback (AD-interop mode for AD-tool compatibility with `dnsmgmt.msc`).
- For AD-interop mode, the framework SHALL replicate `DomainDnsZones.<domain>` and `ForestDnsZones.<forest>` via `DrSuapiReplicator` with the same NDR encoding as AD (per ADR-070). The framework's NDNC replication SHALL be byte-identical to AD's — Windows DCs replicate DNS zones with framework DCs unmodified.
- The framework SHALL support secure DDNS via GSS-TSIG (RFC 3645) keyed to machine accounts. The machine account's password (stored in the directory's `unicodePwd` attribute) is the GSS-TSIG key. The `adrian-dns-coredns` plugin retrieves the key via an authenticated LDAP bind to the directory (using its own machine account credentials) and uses it to verify GSS-TSIG-signed dynamic updates.
- The framework SHALL support DNS scavenging (aging-based record cleanup) per the AD model: each `dnsRecord` has a `timestamp` field; records with `timestamp = 0` are static (no scavenging); records with `timestamp > 0` are dynamic and eligible for scavenging after the no-refresh interval (default 7 days) + refresh interval (default 7 days) = 14 days. The scavenging task runs every 7 days (default) and removes stale dynamic records.
- The framework SHALL publish DC locator SRV records in `_ldap._tcp.dc._msdcs.<domain>`, `_ldap._tcp.<site>._sites.dc._msdcs.<domain>`, `_kerberos._tcp.dc._msdcs.<domain>`, `_ldap._tcp.gc._msdcs.<forest>` (per ADR-072), `_ldap._tcp.pdc._msdcs.<domain>` (per ADR-076 PDC Emulator), and the domain controller's `_ldap._tcp.<domain>` and `_kerberos._tcp.<domain>` records. Publication is automatic on DC promotion; removal is automatic on DC demotion.
- The framework SHALL support the `dnsNode` object's `dNSTombstoned` attribute (set to TRUE when a DNS record is deleted; the tombstone persists for `tombstoneLifetime` days per ADR-074 before physical deletion). DNS tombstones replicate via DRSUAPI (AD-interop) or Raft (native).
- The framework SHALL expose `adrian-dns zone list`, `adrian-dns zone show --zone <zone>`, `adrian-dns record add --zone <zone> --name <name> --type <type> --data <data>`, and `adrian-dns record delete --zone <zone> --name <name> --type <type>` CLI for DNS management (equivalent to `dnscmd` and `Add-DnsServerResourceRecord`).
- The framework SHALL expose `GET /api/v1/dns/zones`, `GET /api/v1/dns/zones/<zone>/records`, `POST /api/v1/dns/zones/<zone>/records`, and `DELETE /api/v1/dns/zones/<zone>/records/<id>` REST endpoints (per ADR-061) for DNS management.
- Performance target: DNS query latency ≤1 ms p99 for cached records (in-memory cache in the CoreDNS plugin), ≤5 ms p99 for uncached records (FDB range read). Dynamic update latency ≤50 ms p99 (single FDB transaction: write `dnsNode` + update `dnsRecord` + replicate via DRSUAPI/Raft).
- The framework SHALL support zone transfers (AXFR/IXFR) for secondary DNS servers (BIND, PowerDNS) that consume the framework's zones. Zone transfers are read-only; the framework is always the primary.

## Rationale

AD-integrated DNS exists because DNS data is closely coupled to directory data — DC locator SRV records, machine-account A/AAAA records, _msdcs forest-wide records. Externalising DNS to a separate store (BIND files, CoreDNS file backend) breaks the coupling: machine accounts cannot securely update their own A records via GSS-TSIG, DC locator records must be manually maintained, and _msdcs records are not forest-wide.

The framework's hybrid model preserves the AD-interop path (DNS in directory, replicates via DRSUAPI, secure DDNS via GSS-TSIG) while giving native-mode deployments a modern CoreDNS-based DNS server (no DRSUAPI overhead, no NDNC replication, just FDB-direct reads). The CoreDNS plugin is the same in both modes — only the backend (LDAP-via-loopback vs FDB-direct) differs.

External evidence: BIND with `dlz_bind` Samba plugin reads from LDB (the Samba equivalent of FDB-direct). FreeIPA uses BIND reading from 389-DS. CoreDNS is the modern alternative (CNCF project, used in Kubernetes for cluster DNS). The `adrian-dns-coredns` plugin is the framework's contribution — a CoreDNS plugin that reads from FDB or LDAP, with GSS-TSIG support for secure DDNS.

## Consequences

**Positive**: AD-interop deployments gain a non-Windows DNS server that participates in AD-integrated DNS replication. Native-mode deployments get a modern CoreDNS-based DNS server with FDB-direct reads (no replication overhead). Secure DDNS via GSS-TSIG works in both modes (machine accounts update their own A records). DC locator SRV records are published automatically. Zone transfers (AXFR/IXFR) support secondary DNS servers.

**Negative**: The `adrian-dns-coredns` plugin is a Go binary (CoreDNS is Go); the framework's other components are Rust. The plugin communicates with the Rust directory via gRPC. This adds a language-boundary complexity (the framework must build and ship a Go binary alongside the Rust binaries). The mitigation is the gRPC API (well-defined, versioned); the plugin is a thin read/Write layer.

**Neutral**: AD-aware DNS tools (`dnsmgmt.msc`, `Resolve-DnsName`, `nslookup`) work against the framework's DNS server. The framework's `adrian-dns` CLI is the modern equivalent. Zone transfers enable BIND/PowerDNS secondaries.

**Cost**: ~6 person-weeks for the `adrian-dns-coredns` plugin (~2K lines Go), the FDB-direct backend, the LDAP-via-loopback backend, the GSS-TSIG support, the scavenging task, the SRV record publication, and the CLI/REST API.

**Operational impact**: DNS is served on port 53 by the `adrian-dns-coredns` plugin (deployed as a sidecar or a separate deployment). DNS management is via `adrian-dns` CLI or REST API. DNS scavenging is a background task. DNS replication health is monitored via `adrian-repl-health` (AD-interop) or FDB cluster health (native).

## Alternatives Considered

### Alternative 1: Externalise DNS entirely (CoreDNS with file/etcd backend)

Drop AD-integrated DNS — use CoreDNS with a file backend or etcd backend. The advantage is simplicity (no directory coupling). The disadvantage is losing secure DDNS via GSS-TSIG (machine accounts cannot update their own A records), losing DC locator SRV record publication (must be manual), losing _msdcs forest-wide records (must be per-server). Rejected for AD-interop compatibility.

### Alternative 2: BIND with `dlz_bind` Samba-equivalent plugin

Use BIND (the legacy DNS server) with a plugin that reads from the framework's directory. The advantage is BIND's maturity and feature completeness (DNSSEC, zone transfers, dynamic updates). The disadvantage is BIND's operational complexity (configuration file format, security exposure, memory footprint). CoreDNS is the modern alternative with simpler configuration and smaller footprint. Rejected; CoreDNS is the chosen DNS server.

### Alternative 3: PowerDNS with LDAP backend

Use PowerDNS (the modern alternative to BIND) with its LDAP backend. The advantage is PowerDNS's modern API and database-backed design. The disadvantage is PowerDNS's LDAP backend is not AD-aware (does not support `dnsNode` / `dnsRecord` schema); the framework would need to write a custom backend. The custom backend would be equivalent to the `adrian-dns-coredns` plugin. Rejected; CoreDNS is simpler and more aligned with cloud-native infrastructure.

## Open Questions

- For the `adrian-dns-coredns` plugin, should the FDB-direct backend use the `foundationdb` Go client or the Rust client via gRPC? Default: Rust client via gRPC (the framework's other components are Rust; the gRPC API is the language boundary). Confirm in implementation.
- For DNSSEC, should the framework sign DNS zones? AD supports DNSSEC (Server 2012+); the framework should match for AD-interop. Default: yes, DNSSEC signing is supported (the `adrian-dns-coredns` plugin signs zones on update). Confirm with customer demand.
- For multi-region DNS, should the framework use anycast for DNS queries? Default: yes, anycast is supported (the framework's operator configures BGP anycast for port 53). Confirm with network architecture.

## Cross-capability impact

- **KDC**: KDC discovery via `_ldap._tcp.dc._msdcs.<domain>` SRV records. DNS availability is a KDC readiness gate.
- **Auth Provider**: NTLM discovery via the same SRV records.
- **Policy Engine**: GPO distribution via SYSVOL (per ADR-031); SYSVOL access uses DFS-N (per ADR-044), which uses DNS for namespace discovery.
- **Cert Service**: CRL distribution via HTTP (no DNS dependency); AIA via HTTP or LDAP (LDAP depends on DNS for DC discovery).
- **File Gateway**: DFS-N namespace discovery via DNS.
- **Client SDK**: Client DC discovery via `_ldap._tcp.dc._msdcs.<domain>` SRV records. DNS availability is a client-side readiness gate.
- **Operations**: DNS monitoring is a deployment concern (Prometheus/OTel metric: DNS query latency, dynamic update rate, scavenging lag). The `adrian-operator` (ADR-058) treats DNS availability as a readiness gate.
- **Migration**: AD-to-framework migration preserves DNS zones (the framework's `dnsNode` schema is AD-compatible). DNS zone migration is a one-step `adrian-dns zone import --from-ad <source-dc>` operation.

## References

- [PC-019](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 1 — Hybrid Replication](../workshop/decision-01-replication-protocol.md) — DNS zones replicate via DrSuapiReplicator (AD-interop); native mode uses CoreDNS+FDB
- [Workshop Decision 2 — FoundationDB Storage Engine](../workshop/decision-02-storage-engine.md) — FDB as substrate for `dnsNode` storage
- [docs/02-protocols/05-dns-dynamic-updates.md](../docs/02-protocols/05-dns-dynamic-updates.md) — GSS-TSIG dynamic updates, `dnsNode` schema, secure DDNS
- [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) — AD-integrated DNS role, `_msdcs` zone, DC locator
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — DNS protocol
- [RFC 3645](https://www.rfc-editor.org/rfc/rfc3645) — GSS-TSIG for DNS dynamic updates
- [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) — DNS dynamic updates
- [CoreDNS](https://coredns.io/) — CNCF DNS server
- [MS-DNSP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/) — AD DNS administration protocol
- [ADR-070: DRSUAPI Replication Protocol](./ADR-070-drsuapi-replication-protocol.md) — NDNC replication
- [ADR-073: Storage Engine](./ADR-073-storage-engine.md) — FDB subspaces
