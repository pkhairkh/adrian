---
title: DNS Dynamic Updates — RFC 2136, GSS-TSIG, AD-Integrated Zones, Scavenging
audience: senior-engineers
tags: [dns, rfc-2136, rfc-3645, gss-tsig, ad-integrated, srv-records, scavenging, tombstone]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-13
---

AD-integrated DNS zones are DNS zone data stored not as flat files but as `dnsNode` objects in the directory, replicated via DRSUAPI just like other AD state, written by client machines (and DCs themselves) using RFC 2136 dynamic update messages authenticated by RFC 3645 GSS-TSIG (a Kerberos-signed TSIG record). The DNS server (`dns.exe`) runs inside a `svchost -k NetworkService` host, listening on TCP/53 and UDP/53, plus a per-zone LDAP session to the local DC's DSA.

## Architecture

```
services.msc: "DNS Server" (DNS)
 ├── process: %SystemRoot%\System32\svchost.exe -k NetworkService
 │    └── dns.exe (loaded as a service DLL; entry point ServiceMain)
 │           ├── dns.dll     (the actual server; resolves queries, dynamic updates)
 │           ├── adsi.dll    (ADSI LDAP wrapper for AD-integrated zones)
 │           ├── xpsp2res.dll (resources)
 │           ├── ws2_32.dll  (Winsock listener)
 │           └── crypt32.dll (TSIG verification)
 │
 ├── Service account: NT AUTHORITY\NETWORK SERVICE (uses machine account for AD writes)
 ├── Files:
 │      %SystemRoot%\System32\dns\
 │        ├── <zone>.dns             (file-backed zones, if any; AD-integrated zones do NOT use these)
 │        ├── CACHE.DNS               (root hints)
 │        ├── BOOT                    (legacy boot file, normally not used)
 │        └── log\dns.log             (debug log)
 │
 ├── Registry:
 │      HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
 │        ├── ZoneDefaults
 │        │     ├── AgingInterval   = 7 days (REG_DWORD)
 │        │     ├── RefreshInterval = 7 days
 │        │     └── NoRefreshInterval = 7 days
 │        ├── LogLevel             = 0x00000100 (REG_DWORD bitmask)
 │        └── RpcProtocol          = 0x05 (REG_DWORD; 0x01=TCP, 0x04=NAMED_PIPE)
 │
 └── AD-integrated zones stored in two application partitions:
        DomainDnsZones.<domain>            ← domain-replicated DNS zones
        ForestDnsZones.<forest>            ← forest-replicated DNS zones (e.g. _msdcs.<forest>)
```

## AD-integrated zone storage

An AD-integrated primary zone (`zoneType = 0` in the `dnsZone` object) is stored as a hierarchy of `dnsNode` objects, one per unique name in the zone. The partition is one of:

| Partition | DN | Replication scope |
|---|---|---|
| Domain partition | `DC=DomainDnsZones,DC=<domain>,DC=<...>` | All DCs in the domain that are DNS servers |
| Forest partition | `DC=ForestDnsZones,DC=<forest>,DC=<...>` | All DCs in the forest that are DNS servers |
| Legacy domain partition | `CN=MicrosoftDNS,DC=<domain>,DC=<...>` (Server 2000 style) | All DCs in the domain (whether or not DNS server) |

The default for Server 2003+ is the `DomainDnsZones` / `ForestDnsZones` application partitions. The forest-level `_msdcs.<forest>` zone (which holds the DC locator records) is always in `ForestDnsZones`.

### dnsNode object schema

```
CN=<relative-name>,DC=<zone-name>,DC=DomainDnsZones,DC=<domain>,DC=<...>
objectClass        = dnsNode
objectCategory     = CN=Dns-Node,CN=Schema,CN=Configuration,...
dnsRecord          = <binary blob — one or more DNS_RECORD structs>
dNSTombstoned      = TRUE/FALSE                            (set when name is in tombstone state)
distinguishedName  = <DN>
instanceType       = 4 (WRITE)
name               = <relative name (e.g. "dc01")>
```

### `dnsRecord` attribute binary format

The `dnsRecord` attribute is a multi-valued binary attribute. Each value is one `DNS_RECORD` (a.k.a. `DNRRTYPE_NODE` struct). The structure is documented in `dnsperf.h` and MS-DNSP:

```
DNS_RECORD (Windows DNS server format) — 28 bytes header + variable data:
Offset  Size  Field
0x00    4     wDataLength       Length of the data portion that follows
0x02    2     (split: 2 bytes of wDataLength, then 2 bytes of wType — but the layout
              is one DWORD where high WORD = wType, low WORD = wDataLength)
0x04    4     dwFlags           Bitfield: section, delete, charset, etc.
0x08    4     dwTtl             TTL in seconds
0x0C    8     dwReserved        Reserved (time stamp / version)
0x14    4     dwTimeStamp       For dynamic records: hours since 1601-01-01 (scavenging)
0x18    var   Data              RDATA specific to the wType (e.g., 4 bytes for A, 16 for AAAA)
```

Multiple records per name → multiple `dnsRecord` values on the same `dnsNode`. Sorted by wType, then by Data.

### dnsZone container object

The zone root:

```
CN=<zone-name>,DC=DomainDnsZones,DC=<domain>,DC=<...>
objectClass           = dnsZone
dc                    = <zone-name>
dNSTTSL               = 1 (REG equivalent: scavenging enabled)
zoneType              = 0   (AD-integrated primary)
secureSecondaries     = 3   (allow zone transfer to: 0=any, 1=NS only, 2=list, 3=none)
secondaryServers      = (list)
zoneTransferPartners  = (list)
dsIntegrated          = TRUE
allowUpdate           = 1   (0=none, 1=secure+unsecure, 2=secure only)
audioEnable           = FALSE (autoscavenge: false by default per zone)
```

## Dynamic Update protocol (RFC 2136)

A dynamic update is a DNS message with `opcode = 5 (UPDATE)`. The message has the standard 12-byte header, followed by four sections:

1. **Zone section** — the zone being updated (SOA MNAME typically).
2. **Prerequisite section** — conditions that must be true (RR exists, RR doesn't exist, RR equals X). Each prerequisite is one RR-like record with class `IN`, `NONE`, or `ANY`.
3. **Update section** — operations to apply (RRSET add, RRSET delete, name delete, etc.). Delete by class `NONE`, delete all by class `ANY`.
4. **Additional section** — TSIG record (if GSS-TSIG).

```
DNS Header:
0x00  2     Transaction ID
0x02  2     Flags        0x2800 = QR=0, Opcode=5 (UPDATE), RD=0
0x04  2     ZOCOUNT      = 1
0x06  2     PRCOUNT      prerequisites
0x08  2     UPCOUNT      updates
0x0A  2     ADCOUNT      additional (TSIG = 1)

Zone Section (1 RR):
  Name (dn-encoded)  + Type=SOA(6) + Class=IN(1) + TTL=0 + RDLENGTH=0

Prerequisite Section (each):
  Name + Type + Class + TTL + RDLENGTH + RDATA
  Class ANY + TTL 0 + RDLENGTH 0 = "name in use" / "name not in use"
  Class NONE = "RRset exists (value given) / does not exist"
  Class IN  = "RRset exists (value must match)"

Update Section (each):
  Class ANY + TTL 0 + RDLENGTH 0 = "delete all RRsets from a name"
  Class NONE + TTL 0 + RDATA     = "delete an RR from an RRset"
  Class IN  + TTL > 0 + RDATA    = "add an RR to an RRset"
```

Server processes prerequisites atomically: if any fails, the entire update is rejected with RCODE. Common RCODEs:

| RCODE | Name | Meaning |
|---|---|---|
| 0 | NOERROR | Updated. |
| 1 | FORMERR | Malformed update. |
| 5 | REFUSED | Update not allowed (zone is not dynamic). |
| 6 | YXDOMAIN | Prerequisite "name should not exist" failed. |
| 7 | YXRRSET | Prerequisite "RRset should not exist" failed. |
| 8 | NXRRSET | Prerequisite "RRset should exist" failed. |
| 9 | NOTAUTH | Not authorized (TSIG missing or invalid). |
| 10 | NOTZONE | Name in update is outside the zone. |

## GSS-TSIG (RFC 3645)

TSIG (Transaction SIGnature, RFC 2845) is a pseudo-RR in the Additional section with name = "the TSIG key name" and type = 250. GSS-TSIG replaces the static shared secret of plain TSIG with a Kerberos-derived session key.

### TSIG RR wire format

```
NAME          = key name (e.g. "dc01.example.com")
TYPE          = 250 (TSIG)
CLASS         = ANY (255)
TTL           = 0
RDLENGTH      = var
RDATA:
   0x00  2    Algorithm Name Length
   0x02  var  Algorithm Name    ("gss-tsig." for Kerberos)
   0x..  8    Time Signed       (48-bit seconds + 16-bit fraction)
   0x..  2    Fudge             (allowed clock skew, seconds)
   0x..  2    MAC Size
   0x..  var  MAC               (the GSS-API MIC token over the DNS message)
   0x..  2    Original ID       (the transaction ID being signed)
   0x..  2    Error             (0 = no error)
   0x..  2    Other Data Length
   0x..  var  Other Data        (present if Error != 0)
```

The MAC field is a Kerberos `GSS_GetMIC()` output over the canonical-form DNS message (with the TSIG RR's MAC field zeroed and ARCOUNT decremented). The signature algorithm is `gss-tsig.` — there is no choice of etype here; the GSS-API negotiates the underlying Kerberos etype.

### GSS-TSIG handshake

The client first does a TGS-REQ for the DNS server's SPN (`DNS/<dns-server-fqdn>`), gets a service ticket, then calls `GSS_Init_sec_context()` with the `mutual_req_flag = FALSE` (no AP-REP needed) but the `replay_det_req_flag = TRUE`. The resulting context has a session key, used for `GSS_GetMIC()` on each dynamic update packet. The context is cached on the client and reused for subsequent updates (typically ~10 hours, matching ticket lifetime).

When the Kerberos context expires, the client does a new TGS-REQ and re-establishes. The DNS server (running as `dns.exe` in NetworkService) calls `GSS_Accept_sec_context()` on each TSIG'd update — typically the context token exchange happens in the first update packet; subsequent packets contain only the MIC.

### SPN and ACL requirements

The DNS service runs as `NT AUTHORITY\NETWORK SERVICE`, which impersonates the local machine account (`<DOMAIN>\<hostname>$`). The SPN `DNS/<dns-server-fqdn>` is registered on the machine account (it's auto-registered by `dnscmd /Config /RpcAuthLevel` or implicit).

For a non-machine account (e.g., a non-DC DNS server) to receive dynamic updates, it must have a `DNS/<fqdn>` SPN on its own service account.

Secure-only updates (`zone.allowUpdate = 2`) require:
- Client auth via GSS-TSIG.
- The authenticated principal must have "Write" on the `dnsNode` object (or its parent) — DNS administers this via `zoneACL` (a security descriptor on the zone's `dnsZone` object). By default, "Authenticated Users" can create child `dnsNode` objects.

## Scavenging and aging

DNS records created via dynamic update carry a `dwTimeStamp` (the `dnsRecord` field, hours since 1601). Static (admin-created) records have `dwTimeStamp = 0` and are never scavenged.

Each zone has three scavenging-related properties:

| Property | Default | Meaning |
|---|---|---|
| NoRefreshInterval | 7 days | Updates to existing records within this window do NOT refresh the timestamp. Prevents AD-replication churn. |
| RefreshInterval | 7 days | Window during which a client may refresh the timestamp. |
| AgingInterval (= RefreshInterval + NoRefreshInterval) | 14 days | Records older than this are eligible for scavenging. |

Scavenging runs every 7 days by default on the server (`HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ScavengingInterval`). When a record is scavenged, the `dnsNode` is tombstoned (`dNSTombstoned = TRUE`) and the `dnsRecord` value is replaced with a tombstone record (wType = 0x0001 with timestamp). The tombstone lives for the DNS tombstone lifetime (default 7 days) before actual deletion.

```
Scavenging timestamp comparison:
  if (dwTimeStamp == 0) return;          // static record
  current_hours = (GetSystemTime() - 1601-01-01) / 3600
  if (current_hours - dwTimeStamp > (NoRefreshInterval + RefreshInterval) / 3600)
      scavenging candidates += 1
```

## SRV records for AD

The DC locator records live in `_msdcs.<forest>` (forest-replicated). Each DC registers:

| Record | Format | Example |
|---|---|---|
| `_ldap._tcp.<domain>` | SRV | priority/weight/port/`<dc-fqdn>` — generic LDAP |
| `_ldap._tcp.<site>._sites.<domain>` | SRV | site-specific LDAP |
| `_ldap._tcp.dc._msdcs.<domain>` | SRV | DC for the domain |
| `_ldap._tcp.<site>._sites.dc._msdcs.<domain>` | SRV | site-specific DC |
| `_ldap._tcp.pdc._msdcs.<domain>` | SRV | PDC emulator |
| `_ldap._tcp.gc._msdcs.<forest-root>` | SRV | Global Catalog servers |
| `_ldap._tcp.<site>._sites.gc._msdcs.<forest-root>` | SRV | site-specific GC |
| `_kerberos._tcp.<domain>` | SRV | KDC for the domain |
| `_kerberos._tcp.dc._msdcs.<domain>` | SRV | DC for Kerberos |
| `_kerberos._udp.<domain>` | SRV | KDC for UDP (small packets) |
| `_kpasswd._tcp.<domain>` | SRV | Password change service (TCP 464) |
| `_kpasswd._udp.<domain>` | SRV | Password change service (UDP 464) |
| `gc._msdcs.<forest-root>` | A/AAAA | GC IP addresses |
| `<dc-guid>._msdcs.<forest-root>` | CNAME | DSA GUID → DC hostname (used by replication partners) |

The DC locator also uses LDAP to query `CN=<site-name>,CN=Sites,CN=Configuration,...` for subnets to map IP → site. The Netlogon service (`netlogon.dll`) registers these records via dynamic update every 60 minutes (configurable via `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DcBackoff`).

## DNS tombstones

When a `dnsNode` is deleted (manually or via scavenging), the DNS server sets `dNSTombstoned = TRUE` and replaces the `dnsRecord` value with a single "tombstone" record. The actual `dnsNode` AD object is deleted after the DNS tombstone lifetime.

This two-phase deletion is needed because AD replication is async — partner DCs may not have seen the original delete. The tombstone (an explicit "this name is gone") replicates ahead of the actual AD delete, preventing the deleted name from "reappearing" when a partner replicates an older version of the `dnsNode`.

## Zone transfer

AD-integrated zones do not use zone transfer (`AXFR` / `IXFR`) between DCs — they replicate via DRSUAPI. To non-DC secondary DNS servers, however, zone transfer is used. `zone.secureSecondaries` controls which secondaries are allowed:

- 0 — any secondary
- 1 — listed in the zone's NS records
- 2 — explicit list (`secondaryServers`)
- 3 — no transfer (default for new zones since Server 2016)

Best practice: 1 or 3, since unrestricted zone transfer leaks the entire zone (including hostnames and IPs).

## Wireshark display filters

```
dns                              # all DNS
dns.flags.opcode == 5            # Dynamic Update
dns.flags.response == 0          # Queries only
dns.count.zones == 1 && dns.count.prerequisites >= 1
dns.type == TSIG                 # TSIG records
dns.tsig.algorithm == "gss-tsig."  # GSS-TSIG specifically
dns.zone.name == "example.com"
dns.update.name                  # name being updated
dns.update.type                  # type being updated

# Capture all DC locator traffic
dns.qry.name contains "_msdcs" and dns.qry.type == 33   # SRV queries for _msdcs

# Capture DNS dynamic updates
dns.flags.opcode == 5
```

## Configuration / code examples

### PowerShell — zone config and scavenging

```powershell
# Show all zones and key properties
Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, AgingEnabled, NoRefreshInterval, RefreshInterval

# Enable scavenging on a zone
Set-DnsServerZoneAging -Name "example.com" -Aging $true `
    -NoRefreshInterval 7.00:00:00 -RefreshInterval 7.00:00:00

# Set server-wide scavenging (every 7 days)
Set-DnsServerScavenging -ScavengingInterval 7.00:00:00 `
    -ScavengingState $true -RefreshInterval 7.00:00:00 `
    -NoRefreshInterval 7.00:00:00

# Enable secure-only updates
Set-DnsServerPrimaryZone -Name "example.com" -DynamicUpdate "Secure"

# Show aging state of records
Get-DnsServerResourceRecord -ZoneName "example.com" -RRType A | `
    Select-Object HostName, RecordType, Timestamp, @{n='HostName';e={$_.HostName}}

# Trigger a manual scavenging cycle
Start-DnsServerScavenging

# Inspect the AD-side dnsNode object directly
Get-ADObject -Filter "objectClass -eq 'dnsNode'" `
    -SearchBase "DC=example.com,DC=DomainDnsZones,DC=example,DC=com" `
    -Properties dnsRecord, dNSTombstoned, whenChanged | Select-Object Name, dNSTombstoned, whenChanged
```

### Python — register an SRV record via GSS-TSIG using `dnspython`

```python
import dns.update, dns.query, dns.tsig, dns.tsigkeyring
import gssapi

# 1. Acquire a Kerberos service ticket for DNS/dc01.example.com@EXAMPLE.COM
name = gssapi.Name("DNS/dc01.example.com@EXAMPLE.COM", name_type=gssapi.NameType.hostbased_service)
ctx = gssapi.SecurityContext(name=name, usage="initiate", flags=[gssapi.RequirementFlag.mutual_authentication])
# GSS_Init_sec_context; ticket pulled from cache (must run kinit first)
init_token = ctx.step()

# 2. Build the dynamic update
update = dns.update.Update("example.com")
update.replace("dc01.example.com.", 3600, "A", "10.0.0.5")

# 3. dnspython does not natively support GSS-TSIG; you must manually build the TSIG RR
#    using the gssapi MIC. Alternative: use the python-dns-module-with-gss-tsig fork,
#    or shell out to `nsupdate -g` (which uses MIT krb5 GSSAPI under the hood):
import subprocess
nsu = subprocess.run(["nsupdate", "-g"], input="""
server dc01.example.com
zone example.com
update delete dc01.example.com. A
update add dc01.example.com. 3600 A 10.0.0.5
show
send
""".encode(), capture_output=True)
print(nsu.stdout.decode())
print(nsu.stderr.decode())
```

### Linux — `nsupdate -g` with Kerberos

```bash
# Acquire a Kerberos ticket first
kinit jdoe@EXAMPLE.COM

# Submit dynamic update signed with GSS-TSIG
nsupdate -g <<EOF
server dc01.example.com
zone example.com
update add web01.example.com 3600 A 10.0.0.10
update add web01.example.com 3600 TXT "host:web01;os:linux"
send
EOF

# Reverse zone update for 10.0.0.10 (zone = 0.0.10.in-addr.arpa)
nsupdate -g <<EOF
server dc01.example.com
zone 0.0.10.in-addr.arpa
update add 10.0.0.10.in-addr.arpa 3600 PTR web01.example.com.
send
EOF
```

### Registry — server-wide scavenging

```
HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
 ├── AgingInterval        = 168  (hours, default 7 days = 168)        (REG_DWORD)
 ├── RefreshInterval      = 168  (hours)                              (REG_DWORD)
 ├── NoRefreshInterval    = 168  (hours)                              (REG_DWORD)
 ├── ScavengingState      = 1    (1=enabled server-wide)              (REG_DWORD)
 ├── AutoCacheUpdate      = 0                                          (REG_DWORD)
 ├── RpcProtocol          = 0x05 (TCP + Named Pipe)                    (REG_DWORD)
 ├── LogLevel             = 0x00000100 (LMODS1) — packet logging       (REG_DWORD)
 └── LogFilePath          = %SystemRoot%\System32\dns\dns.log          (REG_SZ)
```

## Troubleshooting

- **`Dynamic update refused (REFUSED)`** — zone is not dynamic. `Set-DnsServerPrimaryZone -Name X -DynamicUpdate "Secure"` (or NonsecureAndSecure for migration).
- **`TSIG failure (BADSIG / BADKEY)`** — client Kerberos ticket expired or wrong SPN. Verify with `klist get DNS/<dns-server-fqdn>`; SPN must be on the server's machine account.
- **Records not replicating between DCs** — check that the zone's replication scope matches across all DNS servers. `Get-DnsServerZone` on each DC should show `ReplicationScope` consistent.
- **Scavenging deletes records that should be static** — admin-created A records have `dwTimeStamp = 0` (static). If the records are auto-registered (e.g., DHCP), they carry a timestamp and are eligible. Use `Set-DnsServerResourceRecord -Aging` to mark records as static after import.
- **DHCP server registering on behalf of clients** — set the DHCP server to use a dedicated domain account (`dhcpdnsuser`) with permissions to update `dnsNode` objects, and enable "Dynamically update DNS A and PTR records only if requested by DHCP clients" + "Always dynamically update DNS A and PTR records" + "Discard A and PTR records when lease is deleted". Otherwise stale entries proliferate.
- **`Event 4013 (DNS server could not open AD)`** — DNS server started before the DC was ready. Wait for AD to be ready (`netdom query fsmo` succeeds) and restart DNS: `Restart-Service DNS`.
- **`_msdcs` records missing after DC demotion** — demotion should clean up, but sometimes doesn't. Manually: `nltest /dsderegdns:dc01` on the demoted DC, or use `dnscmd /recorddelete` per stale record.

## Cross-platform equivalents

- **Linux**: BIND (`named`) supports both RFC 2136 dynamic updates and GSS-TSIG (built-in `dynb`/`gsstsig` since 9.5). Configuration: `update-policy { grant EXAMPLE.COM krb5-self * A; };`. For AD integration, BIND can host an AD-integrated zone via the `ldap` backend (with Samba's `bind-dns` plug-in, `samba_dnsupdate`). See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux**: Samba 4 as an AD DC ships its own internal DNS server (`samba.source4/dns_server/`) that reads from the same LDAP/DNS partitions as Windows DNS. Alternative: BIND9 with the `dlz` (dynamically loaded zones) plugin pointing at Samba's LDAP. See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux**: `nsupdate -g` (from BIND9 utils) is the canonical GSS-TSIG client tool.
- **macOS**: macOS Server used to ship BIND (`named`) for DNS service; deprecated in macOS Server 5.8. For client dynamic update from macOS, use `nsupdate -g` shipped with the base system (in `/usr/bin/nsupdate`). See `../08-macos-equivalents/07-dns-mdns-bonjour.md` (when present).

## References

- RFC 2136 — Dynamic Updates in the Domain Name System (DNS UPDATE).
- RFC 3007 — Secure Domain Name System (DNS) Dynamic Update.
- RFC 2845 — Secret Key Transaction Authentication for DNS (TSIG).
- RFC 3645 — Generic Security Service Algorithm for TSIG (GSS-TSIG).
- RFC 2782 — A DNS RR for specifying the location of services (DNS SRV).
- MS-DNSP — DNS Server Management Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-dnsp>
- "DNS in AD DS" — MS Learn. <https://learn.microsoft.com/windows-server/networking/dns/dns-top>
- BIND 9 Administrator Reference Manual — `update-policy`.
