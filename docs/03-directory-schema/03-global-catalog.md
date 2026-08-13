---
title: Global Catalog — PAS Replication, GC Locator DNS, GCSPN, UDC, Promotion
audience: senior-engineers
tags: [global-catalog, partial-attribute-set, gcspn, udc, isglobalcatalogready, port-3268]
related:
  - ./01-schema-attributes.md
  - ./02-ous-containers.md
  - ./04-trusts-topology.md
  - ./05-replication-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/05-dns-dynamic-updates.md
last_updated: 2026-08-13
---

The Global Catalog is a partial read-only replica of every naming context in the forest, hosted on a designated DC where the NTDS Settings object has `msDS-IsGlobalCatalogReady=TRUE`, listening on TCP/3268 (LDAP) and TCP/3269 (LDAPS) for forest-wide searches across OUs in different domains — the partial attribute set (PAS) is defined per-attributeSchema by `isMemberOfPartialAttributeSet=TRUE` and replicated as sparse `REPLENTIN` payloads via the standard DRSUAPI `DRSGetNCChanges` mechanism.

## Architecture

```
Forest root: corp.example.com
 ├── DC1.corp.example.com    GC=TRUE   (writes NC=corp.example.com + read-only replicas of child.corp + NDNCs)
 ├── DC2.corp.example.com    GC=FALSE  (only writes corp.example.com)
 └── child.corp.example.com
      └── DC3.child.corp.example.com   GC=TRUE (writes child.corp + read-only corp.example.com partial replica)

GC ports:
  TCP/3268  LDAP  (GC service — anonymous refused, requires at least SASL bind)
  TCP/3269  LDAPS (GC over TLS — requires server cert with EKU=Server Authentication and SPN "GC/...")
  UDP/3268  not used (CLDAP is unicast on 389/UDP only; no GC-CLDAP)

Attribute set:
  PAS = { attributeSchema objects where isMemberOfPartialAttributeSet=TRUE }
       ∪ base-schema attribute set (objectClass, cn, objectGUID, objectSid, displayName,
         sAMAccountName, userPrincipalName, memberOf, primaryGroupID, ...)
```

The GC is implemented as additional naming-context replicas on the DC, each marked `instanceType=0x4` (IT_NC, not writable). The DSA's KCC (`ntdskcc.dll!KRCCGCVerifyGCs`) computes which GCs hold which partial replicas; in a multi-domain forest each GC ends up with one writable NC (its own domain) and N-1 read-only partial NCs (one per other domain).

## Partial Attribute Set (PAS)

Defined by `isMemberOfPartialAttributeSet` (Boolean, OID `1.2.840.113556.1.4.1427`) on each `attributeSchema` object. Base-schema attributes that are in the PAS by default (Server 2022 schema):

| Attribute                | Why in PAS                                  |
|--------------------------|---------------------------------------------|
| `objectClass`            | Required for LDAP filter `(objectClass=*)`. |
| `cn`, `sn`, `givenName`  | ANR search targets.                         |
| `displayName`            | Outlook GAL display.                        |
| `sAMAccountName`         | Downlevel logon name.                       |
| `userPrincipalName`      | UPN logon.                                  |
| `proxyAddresses`         | Exchange routing.                           |
| `mail`                   | Mail query target.                          |
| `memberOf`               | Reverse link (constructed).                 |
| `objectGUID`             | Stable identifier.                          |
| `objectSid`, `sIDHistory` | Security identity.                          |
| `primaryGroupID`         | Group membership expansion.                 |
| `msExch*` selected       | Exchange-managed PAS extensions.            |

Adding an attribute to the PAS:

```ldif
dn: CN=myCustomAttribute,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com
changetype: modify
replace: isMemberOfPartialAttributeSet
isMemberOfPartialAttributeSet: TRUE
-
```

Schema modification triggers a `schemaUpdateNow`. The DSA then replicates the new attribute value to all GCs in the forest; depending on forest size this can take hours. To track: `repadmin /showreps /csv | findstr /i "partial"`.

To **remove** an attribute from the PAS, set `isMemberOfPartialAttributeSet=FALSE`. The DSA will *not* immediately delete existing values from GC replicas — they are removed lazily as objects are touched. For immediate cleanup, run `ldifde -r "(<attr>=*)" -f cleanup.ldif` against each GC's read-only NC.

## GC locator — DNS SRV records

GCs publish their location via three SRV record types under the `_msdcs.<forest-root>` zone:

```
_ldap._tcp.gc._msdcs.corp.example.com.        SRV 0 100 3268 dc1.corp.example.com.
_ldap._tcp.gc._msdcs.corp.example.com.        SRV 0 100 3268 dc3.child.corp.example.com.

# Site-scoped:
_ldap._tcp.<site-name>._sites.gc._msdcs.corp.example.com. SRV 0 100 3268 dc1.corp.example.com.

# When GC is also a PDC (rare):
_ldap._tcp.pdc._msdcs.corp.example.com.       SRV 0 100 389  dc1.corp.example.com.
```

A client (Windows `DCLocator` in `netlogon.dll!DsGetDcName`) resolves `_ldap._tcp.gc._msdcs.<forest>` and selects a GC at random weighted by priority/weight. The CLDAP ping (`LDAP_SERVER_NOTIFICATION_OID`) follows on UDP/389 to confirm the GC accepts the client's site.

GC-specific LDAP ping attribute: `1.2.840.113556.1.4.1340` (`isGlobalCatalogReady`) returned in the `supportedCapabilities` response from a GC port bind:

```
# netlogon-style LDAP ping over UDP/389 (not GC port)
> ldapsearch -H ldap://dc01 -s base -b "" "(objectClass=*)" isGlobalCatalogReady
dn:
isGlobalCatalogReady: TRUE
```

## GCSPN — SPN registration

A GC must register the `GC/<host>` and `GC/<host>/<forest-root-dns>` SPNs to allow Kerberos clients to authenticate to the GC service. These are written on the NTDS Settings object's parent computer account:

```
GC/dc01.corp.example.com
GC/dc01.corp.example.com/corp.example.com
HOST/dc01.corp.example.com/corp.example.com      (existing HOST SPN reused for GC as well)
ldap/dc01.corp.example.com
ldap/dc01.corp.example.com/corp.example.com
GC/..                                           (only on GCs)
```

`setspn -L DC01$` lists these. Missing `GC/..` SPNs cause Kerberos clients to fall back to the `HOST/..` SPN, which still works but logs event 3 (KDC) warnings.

When the DSA starts as a GC, `netlogon.dll!NlpAddServicePrincipalName` registers `GC/<host>` and `GC/<host>/<forest>`. When demoted from GC, the SPNs are removed.

## Universal group caching (UDC) — alternative

Sites with no local GC and a slow WAN can use **Universal Group Caching** instead of placing a GC. UDC caches universal-group memberships for users who have authenticated in the site, refreshed every 8 hours (default) by a GC.

Enabling UDC on a site (per `CN=<site>,CN=Sites,CN=Configuration,...`):

```
msDS-HasMasterNCs            (not modified)
msDS-IsGeneratedGCK          = FALSE    (this DC is not a GC)
msDS-NCReplCursors           (cached)
options                      bit 0x4 not set (IS_GC not set)

Site-level attribute:
msDS-DCPromoteBehaviorVersion = 0
msDS-UniversalGroupCacheRefreshTime = 02:00   (Time-of-day refresh)
msDS-UniversalGroupCacheSiteSettings = 1
```

When a user authenticates in a UDC site, the local DC contacts a GC (`DsGetDcName(GC_REQUIRED)`) and asks for universal group memberships. The result is cached locally. The next logon within 8 hours serves from cache, no WAN round-trip.

UDC is **not** a replacement for a GC in scenarios that require:

- Forest-wide searches (`GC://` queries).
- Cross-domain user object lookups by UPN.
- Exchange address book queries.

UDC is sufficient for ordinary Kerberos PAC building and ACL evaluation (universal group SIDs included in the PAC).

## `isGlobalCatalogReady` — promotion lifecycle

GC promotion is a multi-step process controlled by the DSA:

1. **Admin triggers** via one of:
   - AD Sites and Services → NTDS Settings → Properties → "Global Catalog" checkbox.
   - PowerShell: `Set-ADObject -Identity "CN=NTDS Settings,CN=DC01,CN=Servers,CN=<site>,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com" -Replace @{options=1}`. (Bit 0x1 of `options` = `NTDSSETTINGS_OPT_IS_GC`.)
   - `ntdsutil.exe → roles → connections → connect to server DC01 → quit → "set GC on"`.

2. **DSA sets `msDS-IsGlobalCatalogReady=FALSE`** (it's not yet ready) and `options |= 0x1`.

3. **DSA triggers `KCCDoTask`** to add the GC partial NC replicas. KCC computes which NCs are missing and queues inbound replication from a partner DC for each.

4. **Replication in** — for each non-host domain NC, the DSA performs `DRSGetNCChanges` with `HCTL_ALIGN_HIGHSITE` flags, requesting only PAS attributes (`ulFlags = DRS_GET_NC_SIZE | DRS_SYNC_REPL` and the partial-NC flag). The DSA's `REPLENTIN` filter (`ntdsa.dll!FilterReplAttr`) drops non-PAS attributes on the wire, reducing payload.

5. **DSA verifies `isGlobalCatalogReady`** — checks that all PAS-bearing NCs are fully synchronized (UTD vector caught up). Once verified, sets `msDS-IsGlobalCatalogReady=TRUE`.

6. **Publishes SRV records** for `_ldap._tcp.gc._msdcs.<forest>`.

7. **Registers `GC/..` SPNs** on the computer account.

The whole process can take minutes (small forest) to hours (multi-domain forest with slow WANs). Event 1869 (`NTDS General`): "Global catalog is now ready" — at this point the GC accepts queries on port 3268.

## Universal group membership enumeration

The GC is the authoritative source for universal group membership across the forest. Two mechanisms:

1. **LDAP query against GC port**:
   ```ldap
   ldapsearch -H ldap://dc01:3268 -b "" -s sub \
     "(member:1.2.840.113556.1.4.1941:=CN=jdoe,DC=corp,DC=example,DC=com)" \
     cn member
   ```
   `1.2.840.113556.1.4.1941` is `LDAP_MATCHING_RULE_IN_CHAIN` — recursive DN evaluation. Must be queried against the GC (port 3268) or the user's home DC; cross-domain queries against port 389 return only local-domain results.

2. **Token Groups via LDAP** — `tokenGroups` (constructed, OID `1.2.840.113556.1.4.141`) and `tokenGroupsGlobalAndUniversal`. The DSA walks group memberships, including universal groups across domains, by consulting the GC replica.

```python
from ldap3 import Server, Connection, ALL

# Connect to GC port
srv = Server('dc01.corp.example.com', port=3268, get_info=ALL)
conn = Connection(srv, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

# Recursive group lookup using LDAP_MATCHING_RULE_IN_CHAIN
conn.search('DC=corp,DC=example,DC=com',
            '(member:1.2.840.113556.1.4.1941:=CN=jdoe,DC=corp,DC=example,DC=com)',
            attributes=['cn', 'groupType', 'objectSid'])

for entry in conn.entries:
    print(entry.cn.value, hex(entry.groupType.value))
```

## Wireshark display filter

GC service traffic (LDAP on port 3268):

```
tcp.dstport == 3268 || tcp.srcport == 3268 || tcp.dstport == 3269 || tcp.srcport == 3269
```

Or the equivalent with ldap.dissector:

```
tcp.port == 3268 && ldap
```

For replication of the PAS into a newly promoted GC, filter DRSUAPI traffic carrying the schema-replica flag:

```
dcerpc.opnum == 3   # DRSGetNCChanges
&& frame contains "_ldap._tcp.gc._msdcs"
```

## PowerShell — GC promotion + status

```powershell
# 1. Enumerate all GCs in the forest
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest.GlobalCatalogs | Select-Object Name, SiteName, OSVersion

# 2. Check isGlobalCatalogReady on a specific DC
$ntds = Get-ADObject -Identity "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com" -Properties options, msDS-IsGlobalCatalogReady
"isGC option bit: {0}" -f (($ntds.options -band 0x1) -ne 0)
"isGlobalCatalogReady: {0}" -f $ntds.'msDS-IsGlobalCatalogReady'

# 3. Promote to GC (set the bit)
Set-ADObject -Identity $ntds.DistinguishedName -Replace @{options=1}

# 4. Demote from GC (clear the bit)
Set-ADObject -Identity $ntds.DistinguishedName -Replace @{options=0}
```

## Registry / NTDS Settings attribute table

NTDS Settings object (`CN=NTDS Settings,CN=<DC>,CN=Servers,CN=<site>,CN=Sites,CN=Configuration,...`) attributes:

| Attribute                       | Type      | Purpose                                                            |
|---------------------------------|-----------|--------------------------------------------------------------------|
| `options`                       | Integer   | Bit 0x1 = IS_GC. Bit 0x4 = IS_GLOBAL_CATALOG_DISABLE_SITE_BOUNDARY.|
| `msDS-IsGlobalCatalogReady`     | Boolean   | Readiness flag set by DSA after sync completes.                    |
| `msDS-HasMasterNCs`             | DN-String | NCs for which this DC is a full replica (writable).                |
| `msDS-HasFullReplicaNCs`        | DN-String | NCs for which this DC has a partial read-only replica (GC content).|
| `msDS-NCReplCursors`            | Constructed| Per-NC UTD vector.                                                |
| `msDS-IsRODC`                   | Boolean   | Read-only DC.                                                      |
| `invocationId`                  | OctetString | Per-boot UUID; changes on USN rollback. See `./05-replication-internals.md`. |
| `msDS-BehaviorVersion`          | Integer   | DC functional level (4=2012, 5=2012R2, 6=2016, 7=2019, 8=2022).    |
| `hasMasterNCs`                  | DN-String | Legacy form of `msDS-HasMasterNCs`.                                |

Registry:

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  └── Options                       (REG_DWORD)  Bit 1 = IS_GC (legacy; NTDS Settings is authoritative)
  └── Global Catalog Promotion Complete (REG_DWORD) = 1   (mirrors msDS-IsGlobalCatalogReady)
  └── Mapi Disable GC Promotion    (REG_DWORD)  = 0       (Exchange-aware GC promotion)
```

## Troubleshooting

- **GC queries failing on port 3268 with `operationsError`** — DC is mid-promotion. Wait for `isGlobalCatalogReady=TRUE`. Check event 1869.
- **`_ldap._tcp.gc._msdcs` SRV records missing** — DC is GC but DNS not updated. Restart netlogon: `Restart-Service Netlogon`. Verify dynamic update permissions on `_msdcs.<forest>`.
- **Slow GC query** — GC replica missing PAS attribute. Confirm via `repadmin /showreps` against all NCs. Force re-sync: `repadmin /syncall /A /d /e`.
- **`tokenGroups` returns incomplete list** — Universal group from a child domain not present in GC. Check `msDS-HasFullReplicaNCs` includes the child domain NC.
- **UDC users seeing "no global catalog available"** — `msDS-UniversalGroupCacheRefreshTime` site attribute mis-set. Verify via ADSI Edit on the site object.
- **Exchange cannot route mail** — `proxyAddresses` is in PAS by default, but custom routing attributes may not be. Verify with `Get-ADObject -SearchBase "CN=Schema,CN=Configuration,..." -LDAPFilter "(lDAPDisplayName=proxyAddresses)" -Properties isMemberOfPartialAttributeSet`.

## Cross-platform equivalents

- **Linux — Samba 4 AD DC**: GC is implemented in `source4/dsdb/samdb/ldb_modules/global_catalog.c`. PAS computed from `isMemberOfPartialAttributeSet`. Supports GC port 3268. See `../09-linux-equivalents/04-winbind-internals.md` (placeholder path; Samba 4 also covered in `../09-linux-equivalents/01-sssd-ad-provider.md`).
- **Linux — FreeIPA**: No GC concept. Cross-domain trust relies on the trusted domain's IPA master answering for its own users. FreeIPA masters are full replicas of their own domain only. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — SSSD client**: SSSD's `ad_provider` queries the GC for cross-domain group memberships (`ad_gc.py`). Set `ad_enable_gc = True` (default) in `sssd.conf`. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **macOS — OpenDirectory**: No GC. Each OpenDirectory master serves its own domain. See `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.

## References

- MS-ADTS §3.1.1 — The Global Catalog. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/847a16df-8ab4-49f3-8f5a-9e80e6bef83c>
- MS-ADTS §6.1.1.1 — GC DNS SRV record format. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/b6459df2-c57e-4700-8f00-e1c8c1f6e4c0>
- MS-DRSR §4.1.27 — `DRSGetNCChanges` partial-NC flag. <https://learn.microsoft.com/openspecs/windows_protocols/ms-drsr>
- MS-KILE §3.4.5 — PAC universal group enumeration via GC. <https://learn.microsoft.com/openspecs/windows_protocols/ms-kile>
- Samba `source4/dsdb/samdb/ldb_modules/global_catalog.c` and `source4/rpc_server/drsuapi/getncchanges.c`.
- "Universal Group Caching" — MS Learn Windows Server docs. <https://learn.microsoft.com/windows-server/identity/ad-ds/plan/universal-group-caching>
