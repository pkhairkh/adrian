---
title: DCE/RPC and MS-DRSR — DRSUAPI Interface, NDR Encoding, Replication Packets
audience: senior-engineers
tags: [dce-rpc, ms-drsr, drsuapi, ndr, idl, epmapper, replication, samba]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/02-ldap-protocol.md
  - ../09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-13
---

DCE/RPC is a connection-oriented RPC protocol running over TCP (`ncacn_ip_tcp`), SMB named pipes (`ncacn_np`), or HTTP (`ncacn_http`), with a 16-byte connection-oriented common header per PDU, NDR (Network Data Representation) wire encoding of typed arguments, and an Interface UUID + version tuple identifying the contract; AD's replication protocol is one such interface — DRSUAPI (`[uuid(E3514235-8B63-11D0-A26C-00A0C92B955C), version(4.0)]`) — whose IDL is published in MS-DRSR §4 and re-implemented in Samba (`librpc/idl/drsuapi.idl`).

## Architecture

```
Application (e.g., ntdsa.dll!DRSGetNCChanges)
   │
   │── MIDL-generated stub (drsuapi_c.c, drsuapi_s.c)
   │       ntdsa.dll exports the server stub; client stub linked into
   │       ntdsapi.dll (and impacket's drsuapi.py reimplements it).
   │
   │── NDR encoder (rpcrt4.dll!NdrClientCall2 / NdrServerCall2)
   │       For type encoding: NDR20 (little-endian) — used by all Microsoft RPC since NT.
   │
   │── RPC runtime (rpcrt4.dll!RpcBindingFromStringBinding, etc.)
   │       Maps to transport: TCP / SMB pipe / HTTP.
   │
   │── Transport:
   │       ncacn_ip_tcp → ws2_32.dll (raw TCP)
   │       ncacn_np → mrxsmb.sys (named pipe over SMB)
   │       ncacn_http → RPC proxy (RPC over HTTP v2)
   │
   │── Auth:
   │       RPC_C_AUTHN_GSS_NEGOTIATE → SPNEGO → Kerberos or NTLM
   │       RPC_C_AUTHN_LEVEL_PKT_PRIVACY → entire stub payload encrypted
   │       RPC_C_AUTHN_LEVEL_PKT_INTEGRITY → signed only
   │
   └── Listener (server side):
          rpcss.dll listens on TCP 135 (epmapper), returns dynamic port for the
          actual interface. The dynamic port is registered by the server via
          RpcEpRegister().
```

## DCE/RPC PDU structure (connection-oriented)

Common header (16 bytes, MS-RPCE §2.1):

```
Offset  Size  Field
0x00    1     RPC_VERS         = 5
0x01    1     RPC_VERS_MINOR   = 0  (DCERPC 1.0 with NDR; 1.0 with NDR20)
0x02    1     PTYPE            PDU type (see below)
0x03    1     PFC_FLAGS        packet flags (first, last, conc-mpx, ...)
0x04    2     DataRep          NDR data representation (byte order, int size, char rep)
                              Little-endian, ASCII, IEEE float → 0x10 0x00 0x00 0x00 (first byte)
0x06    2     FragLength       Total length of this fragment (header + body)
0x08    2     AuthLength       Length of auth trailer (0 if no auth)
0x0A    4     CallId           Request identifier; responses echo it

PTYPE values:
0x00  Request
0x01  Ping
0x02  Response
0x03  Fault
0x04  Working
0x05  Nocall
0x06  Reject
0x07  Ack
0x08  Cl_cancel
0x09  Fack
0x0A  Cancel_ack
0x0B  Bind
0x0C  Bind_ack
0x0D  Bind_nak
0x0E  Alter_context
0x0F  Alter_context_resp
0x11  Auth3 (Microsoft extension for third-leg auth)
0x12  Shutdown
0x13  Co_cancel
0x14  Orphaned
```

For `Request` (PTYPE 0x00) and `Response` (PTYPE 0x02), the header continues (additional 8 bytes for Request, 8 for Response):

```
Request body header (after common header):
0x10  4     AllocHint       Upper bound on stub data size
0x14  2     CtxtId          Context ID (negotiated in Bind)
0x16    1     CancelCount    Number of pending cancels
0x17  1     Reserved
0x18  var   Stub data (NDR-encoded arguments)

Response body header:
0x10  4     AllocHint
0x14  2     CtxtId
0x16  1     CancelCount
0x17  1     Reserved
0x18  4     Reserved (padding to 8-byte boundary)
0x1C  var   Stub data

Auth trailer (after stub data, if AuthLength > 0):
   AuthType      1 byte  (0x0A=NTLM, 0x09=SPNEGO, 0x0E=SCHANNEL, 0x10=Kerberos)
   AuthLevel     1 byte  (1=none, 2=connect, 3=call, 4=PKT, 5=PKT_INTEGRITY, 6=PKT_PRIVACY)
   AuthPadLength 1 byte
   AuthReserved  1 byte
   AuthContextId 4 bytes
   AuthValue     var    (NTLMSSP token / Kerberos AP-REQ / etc.)
```

### Bind negotiation

A Bind (PTYPE 0x0B) carries one or more `p_cont_elem` blocks (context elements), each specifying:

```
p_cont_elem_t {
    p_cont_id         2 bytes       // assigned by client
    n_transfer_syn    1 byte        // number of transfer syntaxes
    reserved          1 byte
    abstract_syntax {
        InterfaceUuid  16 bytes     // e.g. E3514235-8B63-11D0-A26C-00A0C92B955C
        InterfaceVer   4 bytes      // e.g. 4.0 (high 16 = major, low 16 = minor)
    }
    transfer_syntax[] {
        SyntaxUuid     16 bytes     // 8A885D04-1CEB-11C9-9FE8-08002B104860 = NDR 2.0
        SyntaxVer      4 bytes      // 2.0
    }
}
```

Server returns `Bind_ack` with `p_result = 0 (acceptance)` for each accepted context. If interface/version doesn't match, `p_result = 1 (provider rejection)` with `p_reason = 1 (abstract syntax not supported)`. The first Bind on a connection negotiates the security context; subsequent `Alter_context` PDUs can add auth.

## Endpoint Mapper

TCP 135 — `epmapper.exe` (Windows) / `rpcbind` (UNIX). Two RPC interfaces:

| Interface UUID | Version | Purpose |
|---|---|---|
| `E1AF8308-5D1F-11C9-91A4-08002B14A0FA` | 3.0 | `ept_map` — client asks "where is interface X?" |
| `E1AF8308-5D1F-11C9-91A4-08002B14A0FA` | 3.0 | `ept_lookup` — management |
| `0D72FCE7-CB47-4B5C-99A2-1A8D3A0B1B5E` | 1.0 | `epm_v3` (management) |

DCERPC over SMB does not use the Endpoint Mapper — the client connects to a well-known named pipe (`\\<host>\pipe\drsuapi`, `\\<host>\pipe\samr`, `\\<host>\pipe\lsarpc`, etc.).

## NDR (Network Data Representation)

NDR is a typed wire format defined in OpenGroup DCE 1.1. Two flavors:

- **NDR20** — classic, little-endian. UUID `8A885D04-1CEB-11C9-9FE8-08002B104860`. Default for all MS-RPC.
- **NDR64** — optimized 64-bit-friendly. UUID `71710533-BEBA-4937-8319-B5DBEF9CCC36`. Optional, negotiated via Bind.

### NDR type categories

| Type | Tag (in stub data) | Notes |
|---|---|---|
| Conformant array | length prefix 4 bytes | The size is the first field, in elements. |
| Varying array | offset + length | `offset_low, offset_high` |
| Pointer | dereferenced inline | `0x00000000` = NULL pointer, otherwise data follows |
| String | conformant-varying array of chars | NUL-terminated for non-DCE-conformant; explicit length for conformant |
| Struct | in-line fields | Padding to natural alignment (but no padding at struct end) |
| Union | discriminator-first | The `switch_is` value precedes the arm |
| Context handle | 20 bytes | UUID + (zero) — opaque to client |

Pointers are tricky in NDR: a pointer field is preceded by a 4-byte pointer ID (with the high bit set if non-NULL). The actual data is emitted in a separate "pointee" area at the end of the structure. This is why a deep NDR parser is required to read DRSUAPI packets — Samba's `librpc/ndr/ndr.c` and Microsoft's `rpcrt4.dll!NdrpPointerBufferSize` are the canonical implementations.

## DRSUAPI interface

### Interface UUID and opnums

```
Interface: DRSUAPI
UUID:     E3514235-8B63-11D0-A26C-00A0C92B955C
Version:  4.0 (Server 2003+); older DCs may accept 3.0 (Server 2000).
Transfer syntax: NDR 2.0 (and NDR64 in modern builds).
Endpoint: dynamic TCP via epmapper, OR ncacn_np:\\<dc>\pipe\drsuapi
Authentication: Kerberos (preferred), NTLM (legacy).
Auth level: PKT_PRIVACY required by default since Server 2008.

Samba IDL: librpc/idl/drsuapi.idl
Microsoft IDL: MS-DRSR §4.
```

The user prompt mentions `[uuid(2)]` — that's incorrect; the actual interface UUID is `E3514235-...` as above. The "uuid(2)" annotation form in MIDL refers to the version of the IDL syntax, not the interface UUID.

### Methods (opnums and signatures)

| Opnum | Method | Purpose |
|---|---|---|
| 0 | `DRSBind` | Establish session; exchange `DRS_EXTENSIONS` (capability flags). |
| 1 | `DRSUnbind` | Tear down. |
| 2 | `DRSReplicaSync` | Pull-replicate from a specified source DSA. |
| 3 | `DRSGetNCChanges` | The replication workhorse — returns a delta of changes since the supplied USN vector. |
| 4 | `DRSUpdateRefs` | Modify a replica's `repsFrom` / `repsTo` entries (used by KCC). |
| 5 | `DRSReplicaAdd` | Add a new source DSA for an NC. |
| 6 | `DRSReplicaDel` | Remove a source DSA. |
| 7 | `DRSReplicaModify` | Modify source DSA flags. |
| 8 | `DRSVerifyNames` | Verify existence of named objects. |
| 9 | `DRSGetMemberships` | Group membership expansion (transitive, recursive). |
| 10 | `DRSInterDomainMove` | Cross-NC move (rare). |
| 11 | `DRSGetNT4ChangeLog` | NT4 SAM change log (legacy, used by Samba to talk to NT4 BDCs). |
| 12 | `DRSCrackNames` | Name-format translation (see below). |
| 13 | `DRSWriteSPN` | SPN write with duplicate detection. |
| 14 | `DRSRemoveDsServer` | Demote self. |
| 15 | `DRSRemoveDsDomain` | Remove a domain from the forest (rare, irreversibly). |
| 16 | `DRSGetDomainControllerInfo` | Enumerate DC info across the forest. |
| 17 | `DRSAddEntry` | Bulk LDAP-less object creation (used by dcpromo). |
| 18 | `DRSExecuteKCC` | Run KCC immediately. |
| 19 | `DRSGetReplInfo` | Repl metadata queries (USN vectors, pending links, failure info). |
| 20 | `DRSAddSidHistory` | sIDHistory migration (requires SeEnableDelegationPrivilege on source). |
| 21 | `DRSGetMemberships2` | Newer membership expansion. |
| 22 | `DRSReplicaVerifyObjects` | Verify existence of all objects on a source DSA. |
| 23 | `DRSGetObjectExistence` | Phantom cleanup handshake. |
| 24 | `DRSQuerySitesByCost` | Inter-site cost matrix query. |

### `DRSBind` capability flags (`DRS_EXTENSIONS`)

```
DRS_EXTENSIONS_INT {
    DWORD cb;                          // size of the rest
    DWORD dwFlags;                     // capability bitmask:
                                       //   0x00000001 BASE
                                       //   0x00000002 ASYNCREPL
                                       //   0x00000004 REMOVEAPI
                                       //   0x00000008 MOVEREQ_V2
                                       //   0x00000010 GETCHG_DEFLATE (compressed replication)
                                       //   0x00000020 GETCHG_REQ_V6
                                       //   0x00000040 GETCHG_REQ_V8  (Server 2008)
                                       //   0x00000080 GETCHG_REQ_V10 (Server 2012 R2)
                                       //   0x00000100 INSTANCE_TYPE_NOT_REQ
                                       //   0x00000200 CRYPTO_BIND (RPC cert seal)
                                       //   0x00000400 GETCHGREQ_V8 (reused)
                                       //   0x00000800 GETCHGREPLY_V6
                                       //   0x00001000 GETCHGREPLY_V9 (Server 2012)
                                       //   0x00002000 GETCHGREQ_V10 (Server 2012 R2)
                                       //   0x00004000 GET_TOPHC (topology hints)
                                       //   0x00008000 NEED_5TH_COMPRESSION
                                       //   0x00010000 NEED_FULL_DN
                                       //   0x00020000 STRONG_ENCRYPTION
                                       //   0x00040000 GETCHGREPLY_V11
                                       //   0x00080000 EXPECTS_FULL_OID
                                       //   0x00100000 EXPECTS_FULL_GUID_DN
                                       //   0x00200000 INSTANCE_TYPE_NOT_REQ17
                                       //   0x00400000 RECYCLE_BIN
                                       //   0x00800000 EXPECTS_NEVER_EXPIRED
                                       //   0x01000000 GETCHGREQ_V11
    GUID   siteObjGuid;                // site object GUID of the local DSA
    GUID   pid;                        // includes invocationId,Reserved objectGuid
    DWORD  dwFlagsExt;                 // additional flags (Server 2008+)
    // ... additional fields per Server version
}
```

### `DRSGetNCChanges` request and response

```
DRS_MSG_GETCHGREQ_V11 {                  // request, opnum=3
    UUID     hDrs;
    DWORD    dwInVersion;
    DWORD    dwDrsFlags;
    DSNAME   pNC;                         // Naming Context DN
    UUID     uuidDsaObjDest;             // destination DSA's invocationId
    UUID     uuidInvocIdSrc;             // source's invocationId
    USN_VECTOR usnvecFrom;               // highwatermark cursor
    USN_VECTOR usnvecTo;
    ULONG    ulFlags;                    // DRS_SYNC_BYFLAGS, DRS_GET_ALL_GROUP_MEMBERSHIP, ...
    UUID     uuidUpdDsa;                 // for DRS_SYNC_BYFLAGS
    PREFIX_TABLE pPrefixTableDest;       // schema-attribute prefix → attrID mapping
    ULONG    ulMoreFlags;
    ULONG    cMaxObjects;                // page size; server caps at 1000 default
    ULONG    cMaxBytes;
    ULONG    ulExtendedOp;               // 0 = NORMAL_SYNC, 1 = FULL_SYNC_NOW, etc.
}

DRS_MSG_GETCHGREPLY_V11 {                 // response, opnum=3
    UUID     uuidDsaObjSrc;               // source's invocationId
    USN_VECTOR usnvecFrom;                // new highwatermark cursor
    UPTODATE_VECTOR* pUpdtdVec;           // up-to-date-ness vector
    DWORD    cNumEntries;                 // number of REPLENTIN entries
    REPLENTINLIST[] pEntInfList;          // the actual replicated objects
    BOOL     fMoreData;                   // more changes pending?
    DWORD    dwReturnCode;
    DWORD    dwStreamFlags;
    ULONG    cNumNcSizeObject;
    DWORD    cNumNcSizeValues;
    PREFIX_TABLE* pPrefixTableSrc;        // source's prefix table
    // ... (more fields in V11)
}
```

### Replication packet — REPLENTIN

```
REPLENTINLIST {
    REPLENTIN* pEntInfList;              // linked list of REPLENTINs
    BOOL       fIsNTHidden;
}

REPLENTIN {
    DWORD                ulFlags;        // ENTINF_FROM_MASTER, ENTINF_REMOVABLE, ...
    GUID*                guidParentObj;  // parent object GUID
    DSNAME               pName;          // full DN + GUID + SID of the object
    DWORD                ulFlags2;
    PROPERTY_META_DATA_EXT[] pMetadata;  // per-attribute version/USN/originatingDSA
    PROPENT[]            pEntInf;        // changed attributes (or all attrs for full sync)
    BOOL                 fIsNTHidden;
}

DSNAME {
    DWORD       structLen;
    SID*        Sid;
    GUID        Guid;
    GUID        GuidLastKnownParent;     // for deleted objects during a move
    DWORD       NameLen;
    [string]    WCHAR* StringName;       // the DN
}

PROPENT {
    ATTRTYP    attrType;                 // attribute ID (numeric, via prefix table)
    ATTRVAL[]  AttrVal;                  // one or more values
}

PROPERTY_META_DATA_EXT {
    DWORD       dwVersion;               // incremented per originating write
    FILETIME    ftimeLastOriginatingChange;
    UUID        uuidLastOriginatingDsa;  // invocationID of the originating DSA
    USN         usnOriginatingChange;
    USN         usnLocalChange;          // local USN at which this replica received it
}
```

### Compression

When `DRS_EXT_GETCHG_DEFLATE` is negotiated, the reply payload (the `pEntInfList` and friends) is compressed with NT-style LZ77 + Huffman (the same algorithm used by `lznt1`). The compressed blob is preceded by a 4-byte length prefix. Decompression is in `ntdsa.dll!MDSCompressionUncompress` on the destination, `librpc/ndr/ndr_compression.c` in Samba.

### `DRSCrackNames` — name-format translation

Already documented in `01-ad-ds-internals.md` — see there for the `DS_NAME_FORMAT` table.

## Wireshark display filters

```
dcerpc                                  # all DCE/RPC
dcerpc.pkt_type == 0                    # Request
dcerpc.pkt_type == 2                    # Response
dcerpc.pkt_type == 11                   # Bind
dcerpc.pkt_type == 12                   # Bind_ack
dcerpc.cn_call_id == <id>               # specific call ID
dcerpc.if_id == e3514235-8b63-11d0-a26c-00a0c92b955c   # DRSUAPI
dcerpc.if_id == 12345778-1234-abcd-ef00-0123456789ac   # SAMR
dcerpc.if_id == 12345778-1234-abcd-ef00-0123456789ab   # LSARPC
dcerpc.if_id == 12345677-1234-abcd-ef00-01234567cffb   # EPMAPPER
dcerpc.auth_type == 9                   # SPNEGO (negotiate Kerberos or NTLM)
dcerpc.auth_type == 10                  # NTLMSSP
dcerpc.auth_type == 16                  # Kerberos (GSS-API)
dcerpc.auth_level == 6                  # PKT_PRIVACY (encrypted)
dcerpc.auth_level == 5                  # PKT_INTEGRITY (signed)
dcerpc.dg_if_id                         # datagram (UDP) RPC interface
drsuapi                                 # parsed DRSUAPI payload
drsuapi.DRSBind                         # Bind call
drsuapi.DRSGetNCChanges                 # replication
drsuapi.DRSCrackNames
```

## Configuration / code examples

### PowerShell — view replication metadata via WMI

```powershell
# Show all replication partners for this DC
Get-ADReplicationPartnerMetadata -Target "dc01.example.com" -Scope Server | `
    Format-Table Partner, Partition, LastReplicationSuccess, LastReplicationAttempt,
                 ReplicationInterval, PartnerType

# Force a replication event
Sync-ADObject -object "CN=jdoe,CN=Users,DC=example,DC=com" `
              -source "dc01.example.com" -destination "dc02.example.com"

# View raw replication metadata for an object
Get-ADReplicationAttributeMetadata -Object "CN=jdoe,CN=Users,DC=example,DC=com" `
                                   -Server "dc01.example.com" -ShowAllLinkedValues | `
    Format-Table AttributeName, LastOriginatingChangeTime, Version, LastOriginatingChangeDirectoryServerInvocationId
```

### Python — DRSUAPI `DRSBind` + `DRSGetNCChanges` via impacket

```python
from impacket.dcerpc.v5 import drsuapi, transport
from impacket.dcerpc.v5.dtypes import NULL

def pull_replication(dc_ip, username, password, domain, nc_dn):
    rpctransport = transport.DCERPCTransportFactory(f'ncacn_ip_tcp:{dc_ip}')
    rpctransport.set_credentials(username, password, domain)
    rpctransport.set_dport(135)         # epmapper
    dce = rpctransport.get_dce_rpc()
    dce.set_auth_level(6)               # PKT_PRIVACY required
    dce.connect()
    dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

    # DRSBind
    bind = drsuapi.DRSBind()
    bind['puuidClientDsa'] = drsuapi.NULLGUID
    bind['pextClient']['cb'] = 4
    bind['pextClient']['dwFlags'] = (drsuapi.DRS_EXT_BASE |
                                     drsuapi.DRS_EXT_GETCHG_DEFLATE |
                                     drsuapi.DRS_EXT_GETCHGREQ_V8 |
                                     drsuapi.DRS_EXT_STRONG_ENCRYPTION)
    resp = dce.request(bind)
    hDrs = resp['phDrs']

    # DRSCrackNames: DN → GUID
    crack = drsuapi.DRSCrackNames()
    crack['hDrs'] = hDrs
    crack['dwInVersion'] = 1
    crack['pmsgIn']['tag'] = 1
    crack['pmsgIn']['V1']['cNames'] = 1
    crack['pmsgIn']['V1']['rpNames'][0]['StringName'] = nc_dn
    crack['pmsgIn']['V1']['rpNames'][0]['dwFormat'] = drsuapi.DS_FQDN_1779_NAME
    out = dce.request(crack)
    print(out['pmsgOut']['V1']['pResult']['rItems'][0]['pName'])

    # DRSGetNCChanges — request first page
    get_changes = drsuapi.DRSGetNCChanges()
    get_changes['hDrs'] = hDrs
    get_changes['dwInVersion'] = 8       # request v8
    get_changes['pmsgIn']['tag'] = 8
    get_changes['pmsgIn']['V8']['pNC']['StringName'] = nc_dn
    get_changes['pmsgIn']['V8']['uuidDsaObjDest'] = drsuapi.NULLGUID
    get_changes['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_ASYNC_OP
    get_changes['pmsgIn']['V8']['cMaxObjects'] = 100
    get_changes['pmsgIn']['V8']['cMaxBytes'] = 0
    get_changes['pmsgIn']['V8']['ulExtendedOp'] = 0
    # ... (set usnvecFrom, prefix table)

    resp = dce.request(get_changes)
    print(f"Entries: {resp['pmsgOut']['V6']['cNumEntries']}")
    for entry in resp['pmsgOut']['V6']['pEntInfList']:
        print(entry['pName']['StringName'])

    dce.request(drsuapi.DRSUnbind(hDrs))
    dce.disconnect()

pull_replication("dc01.example.com", "admin", "P@ssw0rd!", "EXAMPLE",
                 "DC=example,DC=com")
```

### Linux (Samba source code paths)

```
source4/rpc_server/drsuapi/dcesrv_drsuapi.c       — DRSUAPI server entry points
source4/rpc_server/drsuapi/addentry.c             — DRSAddEntry impl
source4/rpc_server/drsuapi/getncchanges.c         — DRSGetNCChanges impl
source4/rpc_server/drsuapi/uptodateness_vector.c  — UTD vector handling
source4/dsdb/repl/replicated_object.c             — REPLENTIN decoder
librpc/idl/drsuapi.idl                            — IDL definition
librpc/ndr/ndr_drsuapi.c                          — NDR helpers for DRSUAPI
source4/torture/rpc/drsuapi.c                     — DRSUAPI torture tests
source4/libcli/compression/lzxpress.c             — the LZ compression used by DRSUAPI deflate
```

### Registry — RPC dynamic port range

```
HKLM\Software\Microsoft\Rpc\Internet
 ├── Ports             REG_MULTI_SZ   5000-5100   (the dynamic port range)
 ├── PortsInternetAvailable  REG_SZ   "Y"
 └── UseInternetPorts  REG_SZ   "Y"
```

Default dynamic port range (since Windows Server 2008): 49152–65535. AD replication uses this range. Firewall config must permit it for inbound replication, or you pin a static port via `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\TCP/IP Port` (REG_DWORD).

## Troubleshooting

- **`DCE/RPC fault: DCERPC_FAULT_ACCESS_DENIED (5)` on DRSBind** — caller lacks "Replicating Directory Changes" right on the NC. Check via `dsacls "DC=example,DC=com"` for "Replicating Directory Changes" / "Replicating Directory Changes All" / "Replicating Directory Changes In Filtered Set" — the last is for fine-grained-PAG (FGPP) replication.
- **`NT_STATUS_RPC_PROTOCOL_ERROR` from Samba** — usually a version mismatch. Samba's DRSUAPI implementation lags Microsoft; check that the client sets compatible `DRS_EXTENSIONS` flags (don't request V11 if the source is Server 2012 R2 without the right patches).
- **Bind fails with `provider_rejection (1)`** — interface version mismatch. DRSUAPI version 4.0 (modern); if the client requests 5.0 (non-existent), server returns rejection.
- **Replication fails immediately after a USN-rollback scenario** — the destination's `usnvecFrom` for the source is higher than the source's current USN. Server logs event 2095. Fix: demote and re-promote the source.
- **`Event 1722 (RPC server unavailable)`** — network path to source DC broken. Test with `nltest /sc_query:EXAMPLE` and `repadmin /showconn dc01`.
- **`RPC_S_SEC_PKG_ERROR`** — Kerberos context negotiation failed. Usually a duplicate SPN: `setspn -X` should reveal `ldap/<dc-name>` registered to multiple accounts.

## Cross-platform equivalents

- **Linux**: Samba 4's `samba.source4/rpc_server/drsuapi/` is the only open-source DRSUAPI implementation. It speaks the same wire protocol and can both serve (as a Samba DC) and consume (as a Samba domain member replicating from a Windows DC). For full bidirectional interop, Samba must run in DC mode (`samba-tool domain provision --use-rfc2307`).
- **Linux**: FreeIPA does NOT speak DRSUAPI — it uses 389-DS's own replication protocol (fractal-tree-index-based, similar in spirit but not on the wire). FreeIPA ↔ AD integration is via forest trust + Kerberos cross-realm, not via replication. See `../09-linux-equivalents/01-sssd-ad-provider.md` and `../09-linux-equivalents/08-freeipa-trust.md`.
- **Linux**: DCE/RPC client libraries — `samba.source4/librpc/` (Samba), `dcerpc.py` in impacket (pure-Python), `pyrpc` (rare). For Kerberos auth over DCE/RPC: `gssapi` Python bindings + `mit-krb5`.
- **macOS**: Apple has no native DCE/RPC. Samba builds for macOS (via Homebrew or the obsolete `samba` port) provide `rpcclient` and `samba-tool`.

## References

- MS-DRSR — Directory Replication Service (DRSUAPI) Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-drsr>
- MS-RPCE — Remote Procedure Call Protocol Extensions. <https://learn.microsoft.com/openspecs/windows_protocols/ms-rpce>
- OpenGroup DCE 1.1 — Remote Procedure Call (canonical DCE/RPC spec).
- OpenGroup C706 — DCE/RPC over SMB binding.
- MS-LSAD / MS-LSAR — LSA Domain (LSARPC interface).
- MS-SAMR — Security Account Manager (SAMR).
- Samba DRSUAPI source: `source4/rpc_server/drsuapi/` and `librpc/idl/drsuapi.idl`.
- impacket DRSUAPI implementation: `impacket/dcerpc/v5/drsuapi.py`.
- "Understanding DRSUAPI" — Microsoft AD Team Blog (historical).
