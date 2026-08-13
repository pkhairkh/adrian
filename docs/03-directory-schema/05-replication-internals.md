---
title: Replication Internals — USN, InvocationID, High-Watermark, UTD Vector, DRSGetNCChanges, LVR, Strict Consistency, Rollback Detection
audience: senior-engineers
tags: [replication, usn, invocationid, utd-vector, drsgetncchanges, lvr, strict-consistency, usn-rollback]
related:
  - ./01-schema-attributes.md
  - ./03-global-catalog.md
  - ./04-trusts-topology.md
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
last_updated: 2026-08-13
---

AD replication is a state-based pull protocol layered on DRSUAPI's `DRSGetNCChanges` (opnum 3): each DC tracks per-NC a 64-bit per-database `USN` monotonic counter (the origin-writing DC's USN stamped on every change), its partner's `InvocationID` so it can detect a partner reset (USN rollback), a per-NC high-watermark of the last-seen `{InvocationID, USN}` pair, and a per-NC up-to-dateness (UTD) vector enumerating the highest-seen USN per-originating-DC — the partner replies with `REPLENTIN`/`ENTINF`/`PROPENT` payloads containing all objects whose originating USN exceeds any vector entry, with linked multi-valued attributes (member/memberOf) replicated individually as `REPLVALINF_V3` records since Server 2003 SP1's Linked Value Replication.

## USN — Update Sequence Number

Per-DC, per-database 64-bit counter. Persisted in `DBHEADER.usnLast` (8 bytes at offset 0x118 of the `ntds.dit` database header). Allocated inside the ESE transaction (`ntdsa.dll!DBUpdateRecUsn`) before `JetUpdate` writes the row to the version store.

Two flavors per object:

- `usnCreated` (column `Cn` in `datatable`, OID 1.2.840.113556.1.4.138) — set once when the object is created. Never changes.
- `usnChanged` (column `UsnChanged` in `datatable`, OID 1.2.840.113556.1.4.140) — bumped on every write to the object (or any of its attributes).

The `usnChanged` column is the index replication walks. The query the DSA issues against its own `datatable` for a replication partner:

```sql
-- pseudocode for ntdsa.dll!GetReplicationEvents
SELECT DNT, NCDNT, UsnChanged
FROM datatable
WHERE NCDNT = <nc-head-dnt>
  AND UsnChanged > <partner-usn-high-watermark>
ORDER BY UsnChanged ASC
```

### Originating vs replicated write

When a DC originates a write (LDAP modify, system update), it stamps `usnChanged` with a fresh USN from its own allocator. When a DC receives a replicated write, it stamps `usnChanged` with its own *local* allocator (the replicated object's USN on the origin DC is preserved in `PROPERTY_META_DATA_EXT.usnOriginating` and `usnProperty`).

Each attribute carries its own per-attribute metadata blob (stored in `linktable`/`sdtable`/special columns):

```c
typedef struct _PROPERTY_META_DATA_EXT {
    ULONG   dwVersion;                  // incremented on each write to this attribute
    UUID    szDistinguishedName;        // actually the originating DSA invocationID (misnamed)
    USN     usnOriginatingChange;       // USN on the originating DC
    FILETIME ftLastOriginatingChange;   // when the change was made on the origin DC
} PROPERTY_META_DATA_EXT;
```

Stored in the `datatable` column `ReplPropertyMetaData` (binary blob, length-prefixed array of `PROPERTY_META_DATA_EXT` entries keyed by attribute ID).

## InvocationID

UUID per DC boot-generation. Stored on the NTDS Settings object as `invocationId` (OID 1.2.840.113556.1.4.124) — OctetString (16 bytes).

The `InvocationID` changes when the DSA detects a USN rollback (see below) or when an admin forces it via `repadmin /kcc -resetinvocationid`. It does NOT change across normal reboots.

When DC A replicates from DC B, A sends B its `InvocationID` in the `DRSGetNCChanges` request. B uses this to look up its cached UTD vector for A — if B's stored `InvocationID` for A differs from A's advertisement, B discards all state about A and re-initializes the UTD vector (effectively treating A as a new replica partner).

## High-watermark

Per-NC per-partner pair: `{InvocationID, usnHighWatermark}`.

- The destination DC sends its current high-watermark to the source.
- The source replies with all objects whose `usnChanged > usnHighWatermark`.
- The destination updates its stored high-watermark to the highest `usnChanged` in the response.

When a destination DC's `InvocationID` differs from what the source remembers (rollback), the source refuses to send updates and returns `ERROR_REPL_ENCRYPTION_REQUIRED` (8453) or `ERROR_DS_DRA_INVALID_PARAMETER` (8410), forcing the destination to be re-seeded.

## Up-to-dateness (UTD) vector

Per-NC per-DC: a set of `{InvocationID, USN}` tuples, one per originating DC. The vector encodes "the highest USN I have seen from each originating DC." Format:

```c
typedef struct _UTDVECTOR {
    ULONG   cNumCursors;
    ULONG   dwVersion;
    [size_is(cNumCursors)] USN_VECTOR_CURSOR rgCursors[];
} UTDVECTOR;

typedef struct _USN_VECTOR_CURSOR {
    UUID    uuidDsa;                 // originating DSA's InvocationID
    USN     usnHighPropUpdate;       // highest originating USN seen from this DSA
} USN_VECTOR_CURSOR;
```

Encoded as a binary attribute on the NTDS Settings object: `msDS-NCReplCursors` (constructed). Visible via:

```powershell
Get-ADObject -Identity "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com" -Properties msDS-NCReplCursors
```

The UTD vector is sent in every `DRSGetNCChanges` request. The source uses it to filter which updates to send:

- An update is **not sent** if its `{originating-InvocationID, originating-USN}` is ≤ the corresponding cursor entry in the destination's UTD vector.
- An update **is sent** if its originating-USN exceeds the destination's cursor entry (or there's no entry for this originator).

This implements idempotent replication: a re-replication of the same change is skipped because the UTD vector already shows it.

## `DRSGetNCChanges` — the wire format

Opnum 3 of DRSUAPI (`E3514235-8B63-11D0-A26C-00A0C92B955C`). The destination DC issues this call to its partner for each NC where it lags.

Request (NDR-encoded `DRS_MSG_GETCHGREQ_V11`):

```c
typedef struct _DRS_MSG_GETCHGREQ_V11 {
    UUID        uuidDsaObjDest;          // destination DC's NTDS Settings object GUID
    UUID        uuidInvocIdSrc;          // source DC's InvocationID (cached)
    ENCODING    *pNcOrPrefix;            // DSNAME of NC head (full DN)
    ULONG       ulFlags;                 // DRS_ASYNC_OP, DRS_GET_ALL_GROUP_MEMBERSHIP,
                                         // DRS_INSTANCE_TYPE_IS_FRS_TARGET, ...
    ULONG       cMaxObjects;             // max objects per reply (default 1000)
    ULONG       cMaxBytes;               // max bytes per reply (default ~10 MB)
    ULONG       ulExtendedOp;            // 0 = normal, EXOP_FSMO_GETCHG_DEMAND, EXOP_REPL_SECRETS, ...
    USN         liFsmoInfo;              // FSMO info
    UTDVECTOR   *pUpToDateVecDest;       // destination UTD vector
    ULONG       cNumMsgs;
    REPLENTIN_V1 *pMsgs;                 // previous partially-processed messages
    ULONG       cNumBytes;
    [size_is(cNumBytes)] UCHAR *pBytes;
    ULONG       ulMoreFlags;
    DRS_EXTENSIONS *pExtOp;              // new flags: DRS_GET_TGT, DRS_GET_NC_SIZE, ...
} DRS_MSG_GETCHGREQ_V11;
```

Reply (`DRS_MSG_GETCHGREPLY_V11`):

```c
typedef struct _DRS_MSG_GETCHGREPLY_V11 {
    UUID        uuidDsaObjSrc;
    UUID        uuidInvocIdSrc;
    DSNAME     *pNcOrPrefix;
    ULONG       cNumObjects;
    ULONG       cNumBytes;
    REPLENTIN_V1 *pObjects;              // array of object updates
    BOOL        fMoreData;               // TRUE if more to fetch
    ULONG       cNumNcSizeObject;
    ULONG       cNumNcSizeValue;
    ULONG       cNumBytesNcSize;
    REPLENTIN_V3 *pObjectsV3;
    DRS_EXTENSIONS *pExtOp;
} DRS_MSG_GETCHGREPLY_V11;
```

### REPLENTIN_V3 — replicated object

```c
typedef struct _REPLENTIN_V3 {
    ULONG       fIsNcPrefix;             // 1 = NC head, 0 = ordinary object
    ULONG       cb;                      // total byte size
    DSNAME     *pName;                   // full DN
    ULONG       cNumAttrs;
    ATTRVAL     *pAttr;                  // array of {attrType, values}
    BOOL        fIsPresent;
    ULONG       cNumValues;
    REPLVALINF_V3 *pValues;              // LVR linked values (see below)
    BOOL        fHasParent;              // parent info present?
    DSNAME     *pParent;                 // parent DN
    USN         usnParent;               // parent's usnChanged
    PROPERTY_META_DATA_EXT *pMetaData;   // per-attribute originating metadata
} REPLENTIN_V3;
```

The ATTRVAL structure for each replicated attribute is the raw BER-encoded value. For multi-valued attributes pre-LVR (Server 2000) the entire set of values is sent; with LVR only the changed values are sent (delta replication).

### PROPENT — linked value payload

```c
typedef struct _REPLVALINF_V3 {
    DSNAME     *pNameObject;             // object DN
    ATTRVAL     attrVal;                 // the linked value (DN of the linked object)
    BOOL        fIsPresent;              // TRUE = add, FALSE = delete
    ULONG       cb;
    PROPERTY_META_DATA_EXT MetaData;     // originating DC + USN + version
} REPLVALINF_V3;
```

Each `member` add/remove is one `REPLVALINF_V3` entry. A change to a 10,000-member group on the origin DC replicates as 1 entry on partners (only the new member), not 10,000.

## Linked Value Replication (LVR)

Pre-Server 2003 SP1: a change to any value in a linked multi-valued attribute (e.g. adding one user to a 10,000-member group) caused the **entire attribute** to replicate — 10,000 values on the wire. This severely limited group size (practical ceiling ~5,000 members).

LVR (introduced Server 2003 SP1, schema version 31+) splits the attribute into individual value-replicable units. The schema attribute's `linkID` being non-zero AND a special flag `FLAG_ATTR_IS_LINKED` in `systemFlags` (bit 8, mask 0x100) determines LVR eligibility. Both conditions met for: `member`/`memberOf`, `managedBy`/`managedObjects`, `directReports`/`manager`, `msDS-AllowedToActOnBehalfOfOtherIdentity` (resource-based constrained delegation).

Enabling LVR was a schema-version bump; an AD forest with schema < 31 cannot use LVR. Forests at Server 2003 SP1+ functional level or higher have LVR enabled by default.

## Strict replication consistency

Registry on each DC:

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  └── Strict Replication Consistency        (REG_DWORD) = 1
```

When set to 1 (recommended; default since Server 2012 R2), the DSA enforces:

- If a partner DC's `InvocationID` is unknown or differs from cached, refuse replication (don't auto-reseed).
- If a partner DC's USN vector indicates USN rollback (see below), quarantine the partner.
- Replicate changes only after the strict consistency check passes.

Setting 0 ("loose") allows re-replication as if the partner is a fresh replica — useful in lab/restore scenarios but risks re-introducing stale data. Check:

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "Strict Replication Consistency"
```

## USN rollback detection

A USN rollback occurs when a DC is restored from a snapshot or imaging tool that does NOT notify the DSA (i.e. not using a VSS-aware AD backup). The DC boots with `usnLast` lower than what its partners remember; subsequent inbound replication is silently skipped because the partners' UTD vector already shows the rolled-back USNs as "seen."

Detection algorithm (in `ntdsa.dll!CheckUsnRollback`):

1. Partner DC receives a `DRSGetNCChanges` request from destination DC D.
2. Partner's stored cursor for D: `{D_invocationID, D_usnHighPropUpdate}`.
3. D's request advertises a high-watermark `{D_invocationID, D_usn_current}`.
4. If `D_usn_current < D_usnHighPropUpdate` — i.e. D regressed — **USN ROLLBACK DETECTED**.
5. Partner sets `fStrictConsistency = TRUE` (if not already), returns `ERROR_DS_DRA_USN_ALREADY_EXISTS` or just refuses to send.
6. Partner logs event 2095 in Directory Service log.
7. Partner also updates a sentinel attribute on D's NTDS Settings object: `msDS-IsLastUsnRecycled` (if present in schema).

Recovery:

```cmd
# On the rolled-back DC:
# Option A (preferred): demote, metadata cleanup, re-promote.
dcpromo /forceremoval
# Then in ADUC/ADSI Edit, delete the DC's NTDS Settings object and computer account.
# Re-promote with dcpromo (Server 2008 R2) or Install-ADDSDomainController (2012+).

# Option B (last resort, NOT recommended): reset invocationId
repadmin /kcc -resetinvocationid
# This forces D to advertise a new InvocationID; partners treat it as fresh and re-seed.
# Risk: lingering objects (objects deleted on partners but still present on D).
```

## Wireshark display filter

DRSUAPI `DRSGetNCChanges` (opnum 3):

```
dcerpc.opnum == 3 && dcerpc.if_id == e3514235-8b63-11d0-a26c-00a0c92b955c
```

For replication containing a specific object's DN (string match on the wire):

```
dcerpc && frame contains "CN=DC01,OU=Domain Controllers"
```

For USN rollback event in NTDS event log:

```
# Event log filter (XML):
<QueryList>
  <Query Id="0" Path="Directory Service">
    <Select Path="Directory Service">*[System[(EventID=2095)]]</Select>
  </Query>
</QueryList>
```

## PowerShell — replication health

```powershell
# 1. Show all replication partners and last-sync status
Get-ADReplicationPartnerMetadata -Target corp.example.com -Scope Domain |
  Format-Table Server, Partner, Partition, LastReplicationSuccess,
               LastReplicationAttempt, LastReplicationResult -Auto

# 2. Show UTD vector per DC per partition
Get-ADReplicationUpToDatenessVectorTable -Target corp.example.com -Scope Domain |
  Format-Table Server, Partition, LastUsn, Partner -Auto

# 3. Show replication failures
Get-ADReplicationFailure -Target corp.example.com -Scope Domain

# 4. Force replication
Sync-ADObject -object "CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com" `
              -source dc01 -destination dc02 -PassThru

# 5. repadmin equivalents
repadmin /showrepl dc01 /reperror
repadmin /replsummary
repadmin /showutdvec dc01 corp.example.com
```

## Python ldap3 — read UTD vector via constructed attribute

```python
from ldap3 import Server, Connection, ALL
import struct, uuid

server = Server('dc01.corp.example.com', get_info=ALL)
conn = Connection(server, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

ntds_dn = "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com"
conn.search(ntds_dn, '(objectClass=*)',
            attributes=['invocationId', 'msDS-NCReplCursors', 'msDS-HasMasterNCs'])

inv_id = uuid.UUID(bytes_le=conn.entries[0].invocationId.value)
print(f"InvocationID: {inv_id}")

# msDS-NCReplCursors is constructed and XML-encoded
cursors_xml = conn.entries[0]['msDS-NCReplCursors'].value
print(cursors_xml)  # <DS_REPL_CURSORS>...</DS_REPL_CURSORS>
```

## Registry / schema attribute table

```
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  ├── Strict Replication Consistency          = 1   (REG_DWORD)
  ├── Repl Perform Initial Synchronizations   = 1   (REG_DWORD) — initial sync on boot
  ├── Replication Giop Timeout (secs)         = 60  (REG_DWORD)
  ├── Update Notif Lifetime (secs)            = 300 (REG_DWORD) — outbound USN notif batch window
  ├── KCC Site Generator Bridge All Site Links= 0   (REG_DWORD) — bridgehead optimization
  ├── KCC Idle Duration Between Runs          = 1800 (REG_DWORD) — KCC run interval (sec)
  └── Allow Replication With DNS Suffix SearchList = 0   (REG_DWORD)
```

Replication-related schema attributes on NTDS Settings object:

| Attribute                       | OID / Syntax              | Purpose                                             |
|---------------------------------|---------------------------|-----------------------------------------------------|
| `invocationId`                  | 1.2.840.113556.1.4.124 / OctetString | Per-boot UUID of the DSA.                          |
| `msDS-NCReplCursors`            | Constructed               | XML-encoded UTD vector per NC.                       |
| `msDS-NCReplInboundNeighbors`   | Constructed               | Inbound replication partners.                       |
| `msDS-NCReplOutboundNeighbors`  | Constructed               | Outbound replication partners.                      |
| `msDS-HasMasterNCs`             | DN-String                 | Writable NCs hosted.                                |
| `msDS-HasFullReplicaNCs`        | DN-String                 | Read-only NCs hosted (GC partial replicas).         |
| `msDS-IsLastUsnRecycled`        | Boolean                   | Set after USN rollback detection.                   |
| `msDS-ReplicationEpoch`         | Integer                   | Incremented on forest reset (forces re-repl).       |
| `options`                       | Integer                   | Bit 0x1 IS_GC; bit 0x4 IS_GLOBAL_CATALOG_DISABLE; bit 0x8 DISABLE_INBOUND_REPL. |

## Troubleshooting

- **Event 2095 — USN rollback detected** — Partner DC was restored from non-VSS snapshot. Demote, metadata-cleanup, re-promote. Do NOT run `repadmin /kcc -resetinvocationid` in production unless explicitly directed.
- **Event 2042 — Tombstone lifetime exceeded** — Partner has been offline longer than `tombstoneLifetime` (default 180 days). Strict consistency refuses re-sync. To allow: `repadmin /removelingeringobjects <src-dc> <dst-dc> <nc-dn> /advisory`. Then remove the stale DC manually.
- **Replication stuck on one DC** — Check `Get-ADReplicationFailure`; common cause is KCC cannot compute topology (sites/subnets mis-configured). Run `repadmin /kcc` on the ISTG bridgehead.
- **`member` attribute replication slow for large group** — Verify LVR enabled (`schemaVersion ≥ 31` AND forest functional level ≥ 2003). Pre-LVR, all values replicate on each change.
- **Strict replication consistency blocking legitimate re-seed** — After metadata cleanup, set `Strict Replication Consistency = 0` temporarily, reseed with `repadmin /replicate`, then re-enable.
- **Outbound replication queue growing** — Increase `HKLM\...\NTDS\Parameters\Replicator concurrent thread count` from default 4 (max 10) on busy bridgeheads.

## Cross-platform equivalents

- **Linux — Samba 4 AD DC**: re-implements `DRSGetNCChanges` and the UTD vector in `source4/rpc_server/drsuapi/getncchanges.c`. Schema/syntax compatible with AD; Samba 4 is the only non-Microsoft DC that can replicate with AD DCs natively. See `../09-linux-equivalents/04-winbind-internals.md` and `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — 389-DS / FreeIPA**: uses its own replication (Multi-Master Replication over LDAP, RFC-draft). Not wire-compatible with AD. See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **Linux — OpenLDAP**: SYNCREPL (RFC 4533) — content synchronization. RefreshAndPersist mode. Not compatible with AD's DRSUAPI. See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **macOS — OpenDirectory**: master-replica via custom `slapd` overlays; no multi-master; no DRSUAPI. See `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.

## References

- MS-ADTS §3 — Replication model. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/4e60634f-0e9f-4f6b-96d3-fb3962f5e2c0>
- MS-ADTS §3.1.1.2.3.1 — `usnChanged`, `usnCreated`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts>
- MS-ADTS §3.1.1.3.2.13 — USN rollback detection algorithm. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/70339f4a-9d24-404b-a3f8-79364677c4a0>
- MS-DRSR §4.1.27 — `DRSGetNCChanges` IDL. <https://learn.microsoft.com/openspecs/windows_protocols/ms-drsr/42c5bffd-8167-4c61-88ae-644676b9c1cd>
- MS-DRSR §5.78 — `DRS_MSG_GETCHGREQ_V11`. <https://learn.microsoft.com/openspecs/windows_protocols/ms-drsr>
- "How the Active Directory Replication Model Works" — MS Learn Windows Server. <https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc781622(v=ws.10)>
- Samba `source4/rpc_server/drsuapi/getncchanges.c` and `librpc/idl/drsuapi.idl`.
