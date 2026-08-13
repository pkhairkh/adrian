---
title: AD Architecture — LSASS, NTDS.DIT, and the Driver Stack
audience: senior-engineers
tags: [architecture, lsass, ntds-dit, ese, jet, rpc]
related:
  - ./01-active-directory-overview.md
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
last_updated: 2026-08-13
---

# AD Architecture — Process and Storage Model

This file describes the **implementation of the AD DS service on Windows**: which process owns the database, which modules implement which protocol, where the registry keys live, and how a client LDAP query actually traverses the stack. Subsequent files in `02-protocols/` and `01-ad-core/` drill into specific protocols and roles.

## Process ownership

AD DS is implemented entirely inside `lsass.exe` (the Local Security Authority Subsystem). LSASS hosts the following relevant DLLs:

| DLL | Responsibility |
|-----|----------------|
| `ntdsa.dll` | The Directory System Agent (DSA). Implements LDAP request dispatch, schema enforcement, replication (DRSUAPI), GC, KCC, FSMO logic. |
| `kdcsvc.dll` | The Kerberos KDC service. Handles AS-REQ and TGS-REQ via UDP/TCP 88. |
| `msapsspc.dll` | MS-NLMP / NTLMSSP provider. |
| `netlogon.dll` | Netlogon service (MS-NRPC). Manages secure channel to DC, machine-account password rotation, domain controller location. |
| `lsasrv.dll` | LSA core: token building, security package dispatch, LSA secrets, audit. |
| `kerberos.dll` | The Kerberos security package (client + server-side `AcceptSecurityContext`). Distinct from `kdcsvc.dll`; the latter is the KDC, the former is the SSPI provider. |
| `esent.dll` | ESE database engine. Provides the ISAM API used by `ntdsa.dll` to read/write `ntds.dit`. |
| `dnsrv.dll` | AD-integrated DNS server (loaded only if the DNS Server role is installed on the DC). |

The `ntds.exe` binary is a tiny shim used by `dcpromo` and the boot-time DSA bootstrap; it is not a long-running service. The actual DSA worker is a thread inside LSASS.

### Loading sequence at boot

1. `services.exe` starts `DsaSvc` (`HKLM\SYSTEM\CurrentControlSet\Services\NTDS`).
2. `DsaSvc` triggers LSASS to load `ntdsa.dll` via `DSAInitialize()` (private function exported by ordinals).
3. ESE opens `C:\Windows\NTDS\ntds.dit` exclusively; transaction log files `edb.log`, `edbres00001.jrs` … `edbres00010.jrs`, and `edb.chk` checkpoint file are opened for write.
4. Schema cache is built by reading the Schema NC. Cached in LSASS process memory at `gSchemaCacheAddr` (visible via `!schema` in `ntdsexts.dll` debugger extension).
5. The KCC spawns. KDC starts listening on TCP/UDP 88. Netlogon publishes DC locator DNS records under `_ldap._tcp.dc._msdcs.<domain>` via dynamic update to the AD-integrated DNS zone.
6. RPC endpoints `ldap` (TCP 389), `gc` (TCP 3268), `DRSUAPI` (dynamic, registered with RPCSS), `samr` (dynamic), `netlogon` (dynamic) are published.

## NTDS.DIT internal layout

The DIT is an ESE database with a 16 KB page size (since Server 2008 R2; previously 8 KB). It contains ~50 tables; the most important:

| Table | What it stores |
|-------|----------------|
| `datatable` | The main object table. Every object is one row; every attribute is a separate column. Multi-valued attributes use the linked-value (`LV` table) indirection introduced in Server 2003 SP1 with linked-value replication. |
| `linktable` | DN-syntax attributes (member, memberOf, managedBy, gPLink) — stored as `<object-dsa-guid>:<target-dsa-guid>` pairs for replication efficiency. |
| `sdtable` | De-duplicated security descriptors. Two objects with identical SD share one row; reference count is in `sdrefcount`. |
| `cursor` | Per-NC up-to-dateness vector; `cursor` rows store `<DSA InvocationID, USN>` pairs. |
| `msysobjects` | Internal bookkeeping. |

Page-level checksums are SHA-1 (post-Server 2012; previously a 32-bit checksum). Corruption detection is via `esentutl /g` (offline) or the `JET_errDbTimeTooNew`/`JET_errDbTimeCorrupted` runtime detection.

### Schema cache

`ntdsa.dll` maintains a schema cache in LSASS process memory. The cache is invalidated and rebuilt when:
- The `schemaUpdateNow` operational attribute is written via LDAP.
- The `objectVersion` attribute on the Schema NC head is incremented.
- `repadmin /syncall /A /e /d /q` triggers a schema update replication.

Schema reload is single-threaded and blocks LDAP writes for ~5–30 seconds on a typical mid-size forest. Plan schema extensions during maintenance windows.

## The driver stack on a member server

For non-DC clients (workstations, member servers), AD is consumed through:

```
Application (e.g. Explorer)
    │
    ├─ SSPI (secur32.dll / sspicli.dll)
    │     ├─ Kerberos package (kerberos.dll)
    │     ├─ Negotiate package
    │     ├─ NTLM package (msv1_0.dll)
    │     └─ Pku2u package (pku2u.dll, peer-to-peer)
    │
    ├─ Wldap32 (wldap32.dll) ─ LDAP client
    │     └─ TCP/SSL to DC 389/636/3268/3269
    │
    ├─ Netlogon (netlogon.dll)
    │     └─ MS-NRPC over TCP 445 (named pipe \pipe\netlogon)
    │
    ├─ SMB redirector (rdrmgr.sys / mrxsmb.sys / mrxsmb20.sys)
    │     └─ TCP 445 to DC SYSVOL share
    │
    └─ DCOM / RPC (rpcrt4.dll)
          └─ TCP 135 + dynamic, or named pipe binding
```

Group Policy Client (`gpsvc.dll`) consumes all of these: LDAP to read the GPC, SMB to read the GPT, Kerberos to authenticate to the DC, Netlogon for DC location.

## Registry locations

Key registry paths under `HKLM\SYSTEM\CurrentControlSet\Services\`:

| Path | Purpose |
|------|---------|
| `NTDS\Parameters` | DSA tuning: `DSA Other Writeable`, `Database location`, `Replicator concurrency`, `Strict Replication Consistency`, `TCP/IP Port` (static RPC port for DRSR), `Kerberos Port`, `LDAP Port` |
| `Netlogon\Parameters` | `AvoidPdcOnWan`, `DisablePasswordChange`, `MaximumPasswordAge`, `ScavengeInterval`, `DBFlag` (Netlogon debug log level) |
| `Kdc\Parameters` | `KdcUseClientAddresses`, `SPNMappings`, `MaxPacketSize`, `MaxTokenSize` (Kerberos ticket size cap, default 65535 bytes since Server 2012) |
| `Lsa\Kerberos\Parameters` | `SkewTime`, `MaxTokenSize`, `LogLevel` |

And under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`:

| Path | Purpose |
|------|---------|
| `Group Policy\CSEs\{GUID}` | One subkey per CSE; values `DllName`, `DllNameEx`, `Enabled`, `NoUserPolicy`, `NoMachinePolicy`, `NoSlowLink` |
| `Policies\System\Kerberos` | Client-side Kerberos policy override |
| `Policies\System\GroupPolicy` | GPO debug switch |

## The DC Locator algorithm

`DsGetDcName()` (`netlogon.dll`) is called by virtually every AD-aware application. Algorithm (simplified; see MS-ADTS §6.3.6 for full):

1. If the caller specified a DC name, skip to step 5.
2. Compute the **site name** for the client by looking up the subnet-to-site mapping in `CN=Subnets,CN=Sites,CN=Configuration,...`. Cache in `Netlogon\DcBackoff` registry.
3. Issue DNS queries, in order:
   - `_ldap._tcp.<sitename>._sites.dc._msdcs.<domain>` SRV — preferred in-site DCs.
   - `_ldap._tcp.dc._msdcs.<domain>` SRV — any DC.
4. For each returned host, attempt an LDAP ping (RootDSE query with `NtVerifier` and `Netlogon` attributes) on UDP 389 (`netlogon.dll` implements this as `CLDAP` — Connectionless LDAP, RFC 1798). The DC returns a `NETLOGON_SAM_LOGON_RESPONSE` with the DC's roles (`PDC`, `GC`, `DS`, `KDC`, `Timeserv`, `Closest`).
5. Cache the result in the `DcLocateInfo` in-memory cache and in `Netlogon\Parameters\DynamicObjectNamedPipeWaitHint`. Backoff if the DC is unreachable.

### Wireshark filter

```
ldap.filter == "(&(NtVer=\06\00\00\00)(AAC=\00\00\00\00))" || dns.qry.name contains "_ldap._tcp.dc._msdcs"
```

## Replication trigger flow

A write to a DC causes:

1. ESE begins a transaction.
2. The `datatable` row is updated.
3. The `USN` column for that row is set to the next `USN` from the local DC's monotonic counter (`dsaLocalUSN`).
4. The change is appended to the `hCache` (history cache) keyed by `<object-DNT, attribute-ID, USN>`.
5. On transaction commit, the ESE log is flushed and the change is durable.
6. Replication partners poll (or are notified via RPC `DRSUAPIAsyncReplicaSync`) and call `DRSGetNCChanges` with their **high-watermark** (`{InvId: <partner-inv-id>, usnHighWatermark: <last-seen-usn>}`) and **up-to-dateness vector** for the NC. The DSA returns a `REPLENTIN` list of objects changed since.

See [`../03-directory-schema/05-replication-internals.md`](../03-directory-schema/05-replication-internals.md) for the per-message detail.

## Key binaries, by role

| Role | Binary | Notes |
|------|--------|-------|
| DSA | `lsass.exe` loading `ntdsa.dll` | The DC; runs as `NT AUTHORITY\SYSTEM`. |
| KDC | `lsass.exe` loading `kdcsvc.dll` | Bound to the DSA; uses `krbtgt` account long-term key. |
| Netlogon | `lsass.exe` loading `netlogon.dll` | MS-NRPC server. |
| SAM | `lsass.exe` loading `samsrv.dll` | Only local SAM; AD users are served by `ntdsa.dll` via the AD samsrv shim. |
| DNS Server | `dns.exe` under `svchost -k NetworkService` | Only if DNS role installed. |
| AD CS | `certsvc.exe` under `svchost -k certsvc` | One process per CA. |
| AD FS | `Microsoft.IdentityServer.ServiceHost.exe` | The ADFS service. |
| AD LDS | `instance.exe` per instance | Each instance under `NTDS$<name>` service name. |

## Diagnostic tools

| Tool | Source | Use |
|------|--------|-----|
| `repadmin /showrepl /all` | Windows Server | Show replication metadata, last-success, errors per NC per partner |
| `dcdiag /v /e /c` | Windows Server | DC health (FRS, DFSR, replication, KCC, advertising) |
| `ntdsutil` | Windows Server | Database maintenance, metadata cleanup, IFM, snapshot |
| `ldp.exe` | Windows Server | LDAP browser; bind, search, modify with full controls |
| `esentutl /g ntds.dit` | Windows | Offline integrity check |
| `nltest /dsgetdc:domain /force` | Windows Server | Force DC rediscovery |
| `klist` | Windows | List cached Kerberos tickets |
| `pktmon` | Windows | Packet capture (built-in; ships since Server 1809) |

## References

- [MS-ADTS] §3 „Active Directory Data Model”, §6 „Directory Service Specification”
- Microsoft — *How the Active Directory Database Works* — <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc785926(v=ws.10)>
- Russinovich, Solomon, Ionescu — *Windows Internals, 7th ed.*, Part 1, ch. 7 (Security), Part 2 ch. 9 (AD)
- `ntdsexts.dll` debugger extension shipped with Windows SDK
