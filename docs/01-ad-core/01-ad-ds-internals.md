---
title: AD DS Internals — DSA, ESE/JET Blue, and the DRSUAPI Surface
audience: senior-engineers
tags: [ad-ds, ntdsa-dll, ese, jet-blue, drsuapi, replication, usn, lsass]
related:
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/08-spn-upn-pac.md
  - ./02-ad-cs-cert-services.md
  - ./04-ad-lds-adam.md
last_updated: 2026-08-13
---

The Active Directory Domain Service is a transactional object store implemented by the Directory System Agent (DSA), an in-process module inside LSASS (`lsass.exe`) backed by an Extensible Storage Engine (ESE, "Jet Blue") database file (`ntds.dit`) and exposed over three RPC interfaces — DRSUAPI for replication, LDAP for query/modify, and SAMR/LSA for legacy identity — all sharing one schema cache and one USN allocator per NC.

## Architecture

### Process model

```
lsass.exe
 ├── LSAIso.exe (LSA isolation, optional, runs under LSAIsoSid)
 ├── lsass.exe!LsaApLogonUser* (authentication packages)
 ├── lsass.exe!SamISet* (SAM RPC, samr interface UUID 12345778-1234-ABCD-EF00-0123456789AC)
 ├── lsass.exe!KdcSvc (kdcsvc.dll — Kerberos KDC, RFC 4120 + MS-KILE)
 └── lsass.exe!DSA (ntdsa.dll — Directory System Agent)
       ├── JET blue client (esent.dll — JetInit, JetAttachDatabase, JetBeginTransaction)
       ├── ntdsai.dll (DSA implementation: LDAP request dispatcher, replication engine)
       ├── dsamain.dll (LDAP server front-end, controls handler)
       ├── ntdskcc.dll (Knowledge Consistency Checker — runs every 30 min by default)
       ├── ntdsbsrv.dll (backup server — backup RPC interface)
       ├── ntdsa.dll!DSAInitialize (boot sequence)
       └── ntdsa.dll!MIDL_USER_ALLOCATE (NDR stub allocator for DRSUAPI)
```

The DSA is not a standalone process. It is loaded as a DLL inside `lsass.exe` via the `LSA` notification packages mechanism. `ntdsa.dll` exports `DSAInitialize` which is invoked by `lsass.exe!LsaIUpdateBootStatus` during service startup. Once initialized, the DSA spawns its own worker thread pool (default 4 threads per logical processor, capped at 64), separate from the LSA thread pool.

### Boot sequence

`DSAInitialize` (in `ntdsa.dll`, exported as ordinal #2):

1. Load schema cache from `cn=Schema,cn=Configuration,<NC>` into the in-memory `g_SchemaCache` (a `THashTable<SchemaClass>` keyed by `governsID`).
2. Call `JetInit3` with `JET_paramLogFilePath` pointing to `%SystemRoot%\NTDS\` and `JET_paramSystemPath` to the same.
3. `JetAttachDatabase("%SystemRoot%\NTDS\ntds.dit", JET_bitDbReadOnly)` → recovery (redoes log records from `edb.log`, `edbxxxxx.log`).
4. `JetOpenDatabase` returning `SDB_HANDLE` (`dbid` 1).
5. Open system tables: `datatable` (the actual objects), `linktable` (linked-value attributes), `sdtable` (security descriptor cache), `msysobjects` (ESE catalog).
6. Read `DsaOptions` from registry `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`.
7. Register DRSUAPI endpoint on the dynamic RPC port (or 135-derived ephemeral) and publish to the Endpoint Mapper.
8. Run KCC (`KCCDoTask`), then enable inbound replication.
9. Begin accepting LDAP requests on TCP/389 (LDAP), TCP/636 (LDAPS), TCP/3268/3269 (GC/GC-SSL), UDP/389 (CLDAP — Connectionless LDAP per RFC 1798).

Registry keys of note:

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
 ├── DSA Database File           = %SystemRoot%\NTDS\ntds.dit   (REG_SZ)
 ├── Database log files path     = %SystemRoot%\NTDS              (REG_SZ)
 ├── DSAWorkingThreadCount       = 0  (0 = autotune)              (REG_DWORD)
 ├── Strict Replication Consistency = 1                           (REG_DWORD)
 ├── LDAPClientIntegrity         = 2  (require signing)           (REG_DWORD)
 ├── Repl Perform Initial Synchronizations = 1                    (REG_DWORD)
 ├── Source domain controller    = <former DC if restored>       (REG_SZ)
 └── Options                     = 0  (bit 1 = IS_GC, bit 8 = ALLOW_REPL_MOVE)  (REG_DWORD)
```

### ESE / JET Blue internals

ESE (Extensible Storage Engine) — internally "Jet Blue", distinct from the "Jet Red" engine used by Access. Implementation: `esent.dll`. The AD schema is enforced in code by `ntdsa.dll`, not by ESE — ESE only enforces column types. Tables:

- **`datatable`** — One row per AD object. Columns include `DNT` (Distinguished Name Tag, internal surrogate key, monotonically increasing), `PDNT` (parent DNT), `RDN` (relative distinguished name, Unicode), `RDNType` (attribute ID of RDN), `InstanceType` (bitmask: IT_NC_ABOVE, IT_NC_HEAD, IT_WRITE, IT_UNINSTANTIATED), `ObjDel` (tombstone flag), `NCDNT` (NC head DNT), `Cn` (USN changed), `NcAccCnt<...>` etc.
- **`linktable`** — Multi-valued linked attributes (members of a group, direct reports, SPNs). One row per link value. Columns: `linkDNT` (target object), `backlinkDNT` (computed by KCC reverse index), `del` (deleted link flag), `linkbase` (source DNT encoded). Linked attributes are defined in schema with `linkID` ≠ 0; the `linkID` pairing (e.g., `member` → `memberOf` backlink) is hardcoded in `CN=member,CN=Schema,...,linkID=3` and `CN=memberOf,...,linkID=4` (backlink = forward+1).
- **`sdtable`** — Cached security descriptors, deduplicated by SD hash. Columns: `sdID` (PK), `sd` (binary self-relative SD), `sdHash` (32-bit Murmur hash). Lookup happens in `ntdsa.dll!SCGetSDFromCache` before falling through to allocation. This is why bulk-loading users with identical SDs is cheap.
- **`msysobjects`** — ESE system catalog (column definitions, indices).

Each table uses Long-Value (LV) trees for oversized columns (>= 256 bytes by default) — `dnsRecord`, `nTSecurityDescriptor` (when large), `userParameters`, etc. The LV tree is keyed by `(DNT, columnID, chunkOffset)`.

### Transaction commit path

AD writes are wrapped in a single ESE transaction:

```
JetBeginTransaction()         → returns transaction ID
  JetPrepareUpdate(JET_prepInsert) → row cursor allocated
  JetSetColumn("DNT", newDNT)      → DNT allocated atomically via counter table
  JetSetColumn("PDNT", parentDNT)
  JetSetColumn("RDN", L"jdoe")
  JetSetColumn("objectClass", [top, person, organizationalPerson, user])
  ...
  JetUpdate()                       → writes to version store (in-memory)
  USN allocation:                   → DSA!DBUpdateRecUsn increments DSA_USN, persisted in header
  JetCommitTransaction(JET_bitCommitLazyFlush)
    → writes dirty pages to edb.log (force flush)
    → if log file ≥ 10 MB, rotates to edbXXXXX.log
    → checkpoint (edb.chk) advances
  After commit: queue USN notification to outbound replication partners
  ⇒ raise event 5136 (Directory Service Access modify) via LSASS!AuthzReportSecurityEvent
```

The USN (Update Sequence Number) is a per-DC monotonically increasing 64-bit counter persisted in the database header (`DBHEADER.usnLast`). It is allocated **inside the transaction** before commit, so a USN is never reused even on rollback of the row (rollback decrements the cached last-USN but does not remove the gap). On the wire, the USN appears in `REPLENTIN.pParentObj^-1` (the `usnChanged` stamp) and in `USN_VECTOR.usnHighObjUpdate` for the replication vector.

### Schema cache (`ntdsa.dll`)

In-memory structure: `SchemaCache` (one per DSA), populated at boot, refreshed via `SCCacheRefresh` on schema-class change. Cached per class:

- `governsID` (e.g., `1.2.840.113556.1.5.6` = user)
- `rDNAttID` (default `cn`)
- `mustContain`, `mayContain`, `systemMustContain`, `systemMayContain` (attribute list)
- `possSuperiors`, `systemPossSuperiors` (allowed parent classes)
- `subClassOf` (chain walked at write time)
- `defaultObjectCategory`
- `defaultSecurityDescriptor`
- `schemaFlagsEx` (bit 0x1 = schema-only-object)

The cache is critical to write performance: schema-class validation walks `mustContain` lists in O(1) using the hash table. Reload is triggered by `SchemaUpdateNow` (LDAP modify on `CN=Aggregate,CN=Schema,...`).

## DRSUAPI Interface

The DRSUAPI IDL is published in MS-DRSR §4. The interface UUID is:

```
[e3514235-8b63-11d0-a26c-00a0c92b955c]   // version 4.0
```

Note the prompt's `[uuid(2)]` reference is wrong: that's the version number of the IDL annotation syntax in OpenGroup DCE 1.1. The actual DRSUAPI UUID is the GUID above. Samba's IDL is in `librpc/idl/drsuapi.idl`. Endpoints:

- Dynamic TCP (Server 2008+) — published in Endpoint Mapper (`ncacn_ip_tcp`)
- Named pipe `\pipe\drsuapi` over SMB (Server 2003 fallback)
- Static port 135 → epm lookup → bound session

Key methods (MS-DRSR §4.1, all on `DRS_EXTENSIONS_INT`-aware handles):

| Method | Opnum | Purpose |
|---|---|---|
| `DRSBind` | 0 | Establish session, exchange `DRS_EXTENSIONS` (cap flags: `BASE`, `ASYNCREPL`, `REMOVEAPI`, `MOVEREQ_V2`, `GETCHG_DEFLATE`, `GETCHG_REQ_V6`, `GETCHG_REQ_V8`, `GETCHG_REQ_V10`, `INSTANCE_TYPE_NOT_REQ`, `CRYPTO_BIND`, `GETCHGREQ_V8`, `GETCHGREPLY_V6`, `GETCHGREPLY_V9`, `GETCHGREQ_V10`, `GET_TOPHC`). |
| `DRSUnbind` | 1 | Tear down. |
| `DRSReplicaSync` | 2 | Force inbound replication for a given NC. |
| `DRSGetNCChanges` | 3 | The workhorse — pull a replica update. Returns `REPLENTINLIST` chain. |
| `DRSUpdateRefs` | 4 | Modify a replica's reps-from / reps-to list. |
| `DRSReplicaAdd` | 5 | Add a new source for an NC. |
| `DRSReplicaDel` | 6 | Remove a source. |
| `DRSReplicaModify` | 7 | Modify source flags. |
| `DRSVerifyNames` | 8 | Resolve a list of DNs against the DSA. |
| `DRSGetMemberships` | 9 | Group membership expansion (recursive, transitive). |
| `DRSInterDomainMove` | 10 | Cross-NC move. |
| `DRSGetNT4ChangeLog` | 11 | NT4 SAM replication (legacy, used by Samba). |
| `DRSCrackNames` | 12 | Name-format translation (see below). |
| `DRSWriteSPN` | 13 | SPN multi-master write (atomic duplicate check). |
| `DRSRemoveDsServer` | 14 | Demote self. |
| `DRSRemoveDsDomain` | 15 | Delete a domain from a forest (rare). |
| `DRSGetDomainControllerInfo` | 16 | DC info enumeration (sites, options, GUID). |
| `DRSAddEntry` | 17 | Bulk LDAP-less create (used by `dcpromo`). |
| `DRSExecuteKCC` | 18 | Run KCC now. |
| `DRSGetReplInfo` | 19 | Replication metadata queries (USN vectors, pending links). |
| `DRSAddSidHistory` | 20 | SID history injection (sIDHistory migration, requires SeEnableDelegationPrivilege on the source). |
| `DRSGetMemberships2` | 21 | Newer membership expansion. |
| `DRSReplicaVerifyObjects` | 22 | Existence check of objects on a source. |
| `DRSGetObjectExistence` | 23 | Phantom-cleanup handshake. |
| `DRSQuerySitesByCost` | 24 | Inter-site cost matrix query. |

### `DRSCrackNames` — name-format translation

Format GUIDs (from MS-DRSR §4.1.4 `DS_NAME_FORMAT`):

```
DS_UNKNOWN_NAME                    = 0
DS_DISTINGUISHED_NAME              = 1   cn=jdoe,ou=corp,dc=example,dc=com
DS_NT4_ACCOUNT_NAME                = 2   EXAMPLE\jdoe
DS_DISPLAY_NAME                    = 3   John Doe
DS_GUID_ID                         = 4   {b4d2e...}
DS_CANONICAL_NAME                  = 5   example.com/Corp/jdoe
DS_USER_PRINCIPAL_NAME             = 6   jdoe@example.com
DS_CANONICAL_NAME_EX               = 7
DS_SERVICE_PRINCIPAL_NAME          = 8   cifs/dc01.example.com
DS_SID_OR_SID_HISTORY_NAME         = 9   S-1-5-21-...
DS_DN_WITH_BINARY                  = 10
DS_DN_WITH_STRING                  = 11
DS_FQDN_1779_NAME                  = 12  DC=example,DC=com
DS_NAME_FORMAT_SYNTACTICAL_ONLY    = 13
DS_NT4_ACCOUNT_NAME_SANS_DOMAIN    = 14
DS_ALT_SECURITY_IDENTIFIERS_NAME   = 15
DS_STRING_SID_NAME                 = 16
```

### `DRSGetNCChanges` replication packet

The wire payload (NDR-encoded `DRS_MSG_GETCHGREPLY_V11`):

```
REPLENTINLIST {
    DWORD                cNumEntries;
    REPLENTIN[]          pEntInfList;   // chain of entries
    BOOLEAN              fMoreData;     // more to pull?
    DWORD                dwReturnCode;
    DWORD                dwStreamFlags;
    UUID                 uuidDsaObjSrc; // source DSA invocationID
    USN_VECTOR           usnvecFrom;    // new highwatermark
    UPTODATE_VECTOR*     pUpdtdVec;     // new UTD vector
    FILETIME             ftimeSync;     // last sync time
}
REPLENTIN {
    DWORD                ulFlags;        // ENTINF_FROM_MASTER, etc.
    UUID                 guidParentObj;  // parent GUID (or NULL for NC head)
    DSNAME               pName;          // target DN + SID + GUID
    DWORD                ulFlags2;
    PROPERTY_META_DATA_EXT[] pMetadata;  // per-attribute version/USN/originatingDSA
    PROPENT[]            pEntInf;        // changed attributes
    BOOL                 fIsNTHidden;    // phantom
}
PROPENT {
    ATTRTYP   attrType;   // attributeID (numeric, resolved via schema)
    ATTRVAL[] vals;       // one or more values
}
PROPERTY_META_DATA_EXT {
    DWORD    dwVersion;        // incremented per originating write
    FILETIME ftimeLastOriginatingChange;
    UUID     uuidLastOriginatingDsa;   // invocationID of originator
    USN      usnOriginatingChange;
    USN      usnLocalChange;           // local USN at which we received it
}
```

The invocation ID (`uuidDsaObjSrc`) is the key for replication conflict resolution. It is regenerated by `dcpromo` if the DC is restored from backup (this is the "USN rollback" protection mechanism — restored DCs advertise a new invocation ID, so partners do not treat their old USN vector as still valid).

## LSASS-side threads

LSASS has multiple thread pools:

- **Authentication pool** — services `LsaApLogonUserEx` for Kerberos / NTLM / Negotiate.
- **KDC pool** — `kdcsvc.dll` threads handling AS-REQ / TGS-REQ.
- **DSA pool** — `ntdsa.dll` threads handling LDAP requests and DRSUAPI RPCs. Each thread is bound to a `THSTATE` (thread state) struct containing the schema cache pointer, transaction handle, and quota state.
- **KCC thread** — single-threaded, runs `KCCDoTask` on a 30-minute timer (`HKLM\...\NTDS\Parameters\KCCSchedule`).
- **Repl-in thread** — pulls replication from one source per `nTDSDSA` object.
- **Repl-out thread** — pushes when a partner pulls (always pull-initiated).
- **Notification thread** — pushes async change notification to LDAP clients (`LDAP_SERVER_NOTIFICATION_OID`).

## Configuration / code examples

### Wireshark — replication traffic

```
tcp.port == <dynamic-rpc-port> && dcerpc.pkt_type == 0 && dcerpc.cn_call_id == <call_id>
# or filter by interface
dcerpc.if_id == e3514235-8b63-11d0-a26c-00a0c92b955c
```

### PowerShell — force replication and inspect invocation ID

```powershell
# Show DSA invocation ID, current USN vector
Get-ADDomainController -Filter * | ForEach-Object {
    $dc = $_.HostName
    $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $dc)
    $dsa = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctx)
    [PSCustomObject]@{
        DC = $dc
        InvocationID = $dsa.Site
        OSVersion     = $dsa.OSVersion
        CurrentTime   = $dsa.CurrentTime
    }
}

# Force replication via repadmin /showrepl
repadmin /showrepl /csv > C:\repl.csv
repadmin /syncall /A /e /d /q    # all partitions, error out, q suppress output
repadmin /kcc                   # force KCC on all DCs in the site
```

### Python — DRSCrackNames via impacket

```python
from impacket.dcerpc.v5 import drsuapi, transport
from impacket.dcerpc.v5.dtypes import NULL

def crack(upn, dc_ip, username, password, domain):
    rpctransport = transport.DCERPCTransportFactory(f'ncacn_ip_tcp:{dc_ip}')
    rpctransport.set_credentials(username, password, domain)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

    request = drsuapi.DRSBind()
    request['puuidClientDsa'] = drsuapi.NULLGUID
    request['pextClient']['cb'] = 4
    request['pextClient']['dwFlags'] = drsuapi.DRS_EXT_BASE | drsuapi.DRS_EXT_GETCHG_DEFLATE | drsuapi.DRS_EXT_GETCHGREQ_V8
    resp = dce.request(request)

    hDrs = resp['phDrs']
    invokeId = resp['pextServer']['pid']['uuidDsa']  # source invocation ID

    crack = drsuapi.DRSCrackNames()
    crack['hDrs'] = hDrs
    crack['dwInVersion'] = 1
    crack['pmsgIn']['tag'] = 1
    crack['pmsgIn']['V1']['cNames'] = 1
    crack['pmsgIn']['V1']['rpNames'][0]['StringName'] = upn
    crack['pmsgIn']['V1']['rpNames'][0]['dwFormat'] = drsuapi.DS_USER_PRINCIPAL_NAME
    out = dce.request(crack)
    print(out['pmsgOut']['V1']['pResult']['rItems'][0]['pName'])

    dce.request(drsuapi.DRSUnbind(hDrs))
    dce.disconnect()
```

### ESE database files on disk

```
C:\Windows\NTDS\
 ├── ntds.dit              # main database (~ Jet Blue format, 8K page size)
 ├── edb.log               # current transaction log
 ├── edb00001.log ... edbXXXXX.log   # rotated logs (5 hex digits)
 ├── edb.chk               # checkpoint file (last flushed state pointer)
 ├── edbres00001.jrs       # reserved log (preallocated for emergency space)
 ├── edbres00002.jrs
 ├── temp.edb              # offline defrag working file
 └── EDB0000A.LOG          # bytewise-log naming after integer overflow
```

Page size: 32 KB (Server 2012+). Earlier versions: 8 KB. Cache size (`JET_paramCacheSizeMax`): default = physical RAM / 8, capped at 1 GB for non-EE SKU. Forcing a clean shutdown: `ntdsutil.exe → files → compact to %TEMP%`.

## Troubleshooting

- **USN rollback** — DC restored from snapshot. Symptom: replication inbound stops, event 2095 in Directory Service log. Detection: compare `hostName` invocationID in `CN=NTDS Settings,CN=<DC>,...` against the one advertised on `repadmin /showrepl`. Fix: demote, metadata cleanup, re-promote.
- **Tombstone lifetime exceeded** — `repadmin /showutdvec` shows a partner whose vector is older than `tombstoneLifetime` (default 180 days). Strict replication consistency (`Strict Replication Consistency = 1`) quarantines the stale DC.
- **ESE -1018 / -1022 errors** — database page checksum mismatch. Usually a storage layer fault. Recovery: restore from backup; do not `eseutil /p` on a live AD DB except in break-glass scenarios (and immediately demote afterward).
- **LDAP query performance** — `set objrs=objcmd.execute` taking >5 s usually indicates a missing indexed attribute. Indices are defined by `searchFlags` bit 1 in the schema. Inspect with `Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=..." -Filter * -Properties searchFlags | ?{$_.searchFlags -band 1}`.
- **SD cache bloat** — `sdtable` row count > 1M usually indicates too many unique SDs (often caused by script-generated OUs with explicit per-OU ACEs). Counter: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\SDTableSize` (read-only, monitor via perfmon `NTDS\Database %^Current SD Cache Hits`).

## Cross-platform equivalents

AD DS is the canonical implementation; equivalents are partial:

- **Linux**: Samba 4 as an AD DC (`samba.source4/smbd` and `samba.source4/dsdb/samdb/ldb_modules/`) re-implements the DSA in C, using TDB (Trivial Database) instead of ESE, and ships a re-implementation of DRSUAPI in `source4/rpc_server/drsuapi/`. Schema is in `setup/AD/` templates. See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux**: FreeIPA uses a 389-DS LDAP server (`dirsrv`) with its own replication (fractal-tree index), not DRSUAPI-compatible. AD trusts work but cross-forest replication does not. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **macOS**: No native equivalent. Apple Open Directory uses a tiny LDAP-based directory with slapd-derived code; no DRSUAPI, no GC, no multimaster replication. See `../08-macos-equivalents/06-open-directory.md` (when available).

## References

- MS-ADTS §3 — Active Directory Technical Specification. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts>
- MS-DRSR §4 — DRSUAPI IDL. <https://learn.microsoft.com/openspecs/windows_protocols/ms-drsr>
- [MS-ESWESE] — ESE database engine reference (extensible storage engine). <https://learn.microsoft.com/openspecs/windows_protocols/ms-eses>
- Samba `librpc/idl/drsuapi.idl` and `source4/dsdb/samdb/ldb_modules/repl_meta_data.c`.
- Kenner, R., "Inside Active Directory" 2/e — chapters 6 (database) and 10 (replication).
- `ntdsutil.exe` documentation, MS Learn.
