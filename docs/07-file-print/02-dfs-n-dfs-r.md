---
title: DFS Namespaces and DFS Replication — dfssvc, pKT referral, DFSR-GlobalSettings, RDC, USN journal, SYSVOL
audience: senior-engineers
tags: [dfs-n, dfs-r, dfssvc, dfsr-exe, pkt, referral, rdc, usn-journal, sysvol, frs-deprecated]
related:
  - ./01-smb-shares-internals.md
  - ./04-offline-files.md
  - ../01-ad-core/01-ad-ds-internals.md
  - ../03-directory-schema/05-replication-internals.md
  - ../08-macos-equivalents/07-third-party-agents-mac.md
  - ../09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-13
---

DFS Namespaces (DFS-N) is the `dfssvc.exe` service (under `svchost`) that resolves `\\domain\share\path` UNC paths into per-site target referrals using the Path Knowledge Table (pKT) cached in registry and stored authoritatively as `fTDfs` / `msDFS-Link` objects in `CN=Dfs-Configuration,CN=System,DC=...`; DFS Replication (DFS-R) is the `dfsr.exe` service that multi-master replicates folder contents across members of a Replication Group using RDC (Remote Differential Compression) over the wire and the USN journal (`$Extend\$UsnJrnl:$J`) for change detection.

## DFS Namespaces (DFS-N)

### Architecture

```
services.msc: DFS Namespace (dfssvc — Windows service name "Dfs")
  ImagePath   : %SystemRoot%\System32\svchost.exe -k netsvcs
  ServiceDll  : %SystemRoot%\System32\dfssvc.dll
  ServiceType : 0x20 (SHARE_PROCESS)
  ObjectName  : LocalSystem
  Dependencies: LanmanServer, RpcSS

User-mode:
  dfssvc.dll          Service entry, RPC handlers, pKT cache
  dfscore.dll         Core DFS logic
  dfshost.dll         Service host
  dfscli.dll          Client-side referral API (NetDfsGetDcAddress / NetDfsGetInfo)

Kernel-mode:
  mup.sys             Multiple UNC Provider — routes \\domain\... to DFS
  mrxsmb.sys          SMB redirector (used by DFS client for non-domain paths)
  mrxsmb20.sys        SMB2 redirector
  mrxdfsc.sys         DFS client mini-redirector — handles \\domain\... path knowledge requests
```

### Namespace types

| Type | Storage | Site-aware? | Notes |
|---|---|---|---|
| Standalone | Registry only (`HKLM\SOFTWARE\Microsoft\Dfs\...`) on hosting server | No | Single server; no AD dependency |
| Domain-based (v1) | `fTDfs` object in `CN=<domain-ns>,CN=Dfs-Configuration,CN=System,DC=...` | Yes (Server 2003 mode) | Legacy; limited to ~5,000 links |
| Domain-based (v2 / Windows Server 2008 mode) | `msDFSR-Root` and `msDFS-NamespaceRoot` objects; access-based enumeration supported | Yes | Required for >5,000 targets, ABE, root scalability |

Domain-based v2 requires forest functional level ≥ Windows Server 2003 and domain functional level ≥ 2008.

### pKT (Path Knowledge Table)

The pKT is the in-memory cache of namespace topology on the DFS server. Built at service start by:
1. Reading the `pKT` and `pKTGuid` registry values from `HKLM\SOFTWARE\Microsoft\Dfs\Roots\Domain\<YourDomain>\<Namespace>`.
2. Querying AD for `CN=<namespace>,CN=Dfs-Configuration,CN=System,DC=...` to refresh topology.

pKT contains entries per link with: list of targets, target priority class, site-cost, last-replica-set state.

### AD storage (domain-based namespace)

```
CN=<namespace-name>, CN=Dfs-Configuration, CN=System, DC=corp, DC=example, DC=com
  objectClass: top, msDFS-NamespaceRoot
  msDFS-GenerationGUID          = <GUID>
  msDFS-SchemaMajorVersion      = 2
  msDFS-NamespaceAlias          = <name>
  msDFS-RootSecurity            = <SD binary>
  msDFS-RootPath                = \\corp.example.com\<namespace>

  CN=<link-name> (e.g., CN=engineering)
    objectClass: top, msDFS-Link
    msDFS-TargetList           = <binary blob: ordered target list>
    msDFS-LinkPath             = \engineering
    msDFS-Comment              = ""
    msDFS-LastModified         = <FILETIME>
    msDFS-Ttl                  = 300   (seconds — referral cache TTL on client)
```

The `msDFS-TargetList` binary blob format (documented in MS-DFSC):

```
typedef struct _DFS_TARGET_LIST {
    unsigned long TargetCount;
    DFS_TARGET_INFO Targets[TargetCount];
} DFS_TARGET_LIST;

typedef struct _DFS_TARGET_INFO {
    unsigned short EntryType;     // 1 = root target, 2 = link target
    unsigned short State;         // 1 = online, 2 = offline
    unsigned long  TargetType;
    wchar_t* ServerName;          // e.g., L"file01.corp.example.com"
    wchar_t* ShareName;           // e.g., L"Engineering$"
    wchar_t* FilePath;            // subpath under share, e.g., L""
} DFS_TARGET_INFO;
```

### Referral flow

1. Client opens `\\corp.example.com\Engineering\docs\file.txt`.
2. `mup.sys` intercepts `\\corp.example.com\...` and routes to `mrxdfsc.sys` (DFS client).
3. DFS client checks local referral cache (`HKLM\SYSTEM\CurrentControlSet\Services\Mup\Parameters\DfsClient`).
4. If cache miss, DFS client sends referral request to DC:
   - `NetrDfsGetReferral` (legacy) or `DfsGetReferrals` (modern) via the `NETDFS` RPC interface `[uuid(4FC742E0-4A10-11CF-8273-00AA004AE673)]` opnum 0/1/2.
5. DC consults pKT, computes site-costs for each target relative to the client's site (`DsGetSiteName`), orders by target priority then site-cost.
6. DC returns `DFS_REFERRAL_V3` (or V4) structure with target list.
7. Client caches referral for `msDFS-Ttl` seconds (default 300).
8. Client picks first target, attempts `TreeConnect` to `\\<server>\<share>`. On failure, falls back to next target in order.

### Site-aware referral

Site-costing uses `NLAPI_INSTANCE` and the subnet map (`CN=Subnets,CN=Sites,CN=Configuration,...`) to compute the cost from client site to each target's site. Lower cost = preferred. Costs are 0 (same site) → increasing by link cost.

### Target priority

| Class | Behavior |
|---|---|
| `site-cost-normal` (default) | Ordered by site cost; ties broken randomly |
| `global-high` | Always first regardless of site |
| `site-cost-high` | First among site-cost peers |
| `site-cost-low` | Last among site-cost peers |
| `global-low` | Always last |

Set via `Set-DfsnRootTarget -TargetPath \\server\ns -ReferralPriorityClass GlobalHigh -ReferralPriorityRank 0`.

## DFS Replication (DFS-R)

### Architecture

```
services.msc: DFS Replication (DFSR)
  ImagePath   : %SystemRoot%\System32\DFSR.exe
  ServiceType : 0x10 (OWN_PROCESS)
  ObjectName  : LocalSystem
  Dependencies: RpcSS, LanmanServer, NtFrs (deprecated; SYSVOL only)

DFSR.exe  (single process)
  dfsr.exe                       main service
  dfsrmig.exe                    SYSVOL migration (FRS → DFSR) tool
  dfsmig.exe                     (alias)
  esent.dll                      JET database engine
  ifs.dll                        Installable File System filter (NTFS change tracking)
  Microsoft.Isam.Interop.dll     managed wrapper

Database:
  %SystemRoot%\System32\DFSR\<GUID>\dfsr.db   (JET Blue, ~50 MB-1 GB typical)
  *.log, *.chk, FileManifest.xml, ConfigDb
```

### AD storage

```
CN=DFSR-GlobalSettings, CN=System, DC=corp, DC=example, DC=com
  CN=Replication Groups (container)
    CN=<RG-name>
      objectClass: msDFSR-ReplicationGroup
      msDFSR-ReplicationGroupType = 1 (1=fullmesh/normal; 2=hubspoke; 4=custom)
      CN=Topology
        CN=<member1>, CN=<member2>, ...    (msDFSR-Member objects)
        CN=<connection1>, ...              (msDFSR-Connection objects, directed)
      CN=Content
        CN=<folder1>                       (msDFSR-ContentSet / folder)
          objectClass: msDFSR-ContentSet
          msDFSR-FileFilter               = "*.tmp,*.bak"
          msDFSR-DirectoryFilter          = "~*"
          msDFSR-Enabled                  = TRUE
          msDFSR-ReadOnly                 = FALSE
          msDFSR-ConflictPath             = <path>
          msDFSR-DfsPath                  = \\corp.example.com\<ns>\<link>
      CN=Subscribers
        CN=<member1>                      (msDFSR-Subscriber; links member to content set + local path)
```

`msDFSR-Topology` defines the replication topology (full mesh, hub-and-spoke, custom) by enumerating connections. A `msDFSR-Connection` is a directed edge from source member to destination member; the replication topology is the union of all connections.

### Replication flow

1. **Change detection**: DFSR registers a USN journal reader on the volume. When NTFS writes a file, the journal entry triggers a `ReadUsnJournal` call in DFSR; DFSR enqueues the changed file for processing.
2. **Version vector**: Each file has a version vector `{OriginatingGuid, OriginatingVsn, Version}`; DFSR maintains a per-content-set vector clock.
3. **Replication**: DFSR connects to the partner's RPC endpoint (`[uuid] 91b7b931-c75a-4530-8258-1b3eb578c5d8`, version 1.0) and submits an `EstablishConnection` followed by `GetVersionVector` + `RequestUpdates`.
4. **RDC**: For files >64 KB by default, DFSR uses Remote Differential Compression (`rdparty.dll`): the source and destination compute rolling hashes over the file and exchange signature lists; only differing chunks are sent.
5. **Conflict resolution**: Two members update the same file concurrently → on next sync, both versions are received. DFSR picks "last writer wins" based on the most recent `LastWriteTime`; the loser is moved to `ConflictAndDeleted` folder under the local replicated folder.
6. **Tombstones**: Deleted files are tracked as tombstones in the DFSR database; tombstones propagate to partners so the delete is replicated.

### RDC (Remote Differential Compression)

RDC is a chunked-diff algorithm similar to rsync. Steps:

1. Source divides file into chunks (size 4-32 KB based on file size).
2. Source computes a hash per chunk (`SHA-1` default).
3. Source sends hash list to destination.
4. Destination compares hashes against its local copy; identifies which chunks it lacks.
5. Destination requests only the missing chunks.
6. Source sends those chunks; destination assembles the new file via a temp file, then atomic rename.

RDC reduces bandwidth dramatically for files with small modifications (e.g., 10 GB PST files with daily email additions).

### `ConflictAndDeleted` folder

Path: `<ReplicatedFolder>\DfsrPrivate\ConflictAndDeleted\`

When DFSR detects a conflict (same file modified on two members), the losing copy is moved here with its original name + suffix. By default the folder grows unbounded; quota management via `dfsradmin quota set` (Server 2012+).

### USN journal

The USN journal is `$Extend\$UsnJrnl:$J` on each NTFS volume. DFSR reads it via `FSCTL_READ_USN_JOURNAL`. Each entry is:

```
typedef struct _USN_RECORD {
    DWORD RecordLength;
    WORD  MajorVersion;    // 2 for V2 records, 3 for V3 (V3 adds FileReferenceNumber as 16-byte GUID-like)
    WORD  MinorVersion;
    DWORDLONG FileReferenceNumber;  // 64-bit MFT record # + sequence (V2); 128-byte GUID (V3)
    DWORDLONG ParentFileReferenceNumber;
    DWORDLONG Usn;                  // monotonically increasing within journal
    LARGE_INTEGER TimeStamp;        // FILETIME
    DWORD Reason;                   // bitmask: USN_REASON_DATA_OVERWRITE (0x1),
                                    //   USN_REASON_DATA_EXTEND (0x2),
                                    //   USN_REASON_DATA_TRUNCATION (0x4),
                                    //   USN_REASON_NAMED_DATA_OVERWRITE (0x10), ...
    DWORD SourceInfo;
    DWORD SecurityId;
    FILE_ATTRIBUTE_INFO FileAttributes;
    WORD  FileNameLength;
    WORD  FileNameOffset;
    WCHAR FileName[1];
} USN_RECORD;
```

Common reasons DFSR cares about:
- `USN_REASON_FILE_CREATE` (0x100) — new file
- `USN_REASON_FILE_DELETE` (0x200) — delete
- `USN_REASON_DATA_EXTEND` / `DATA_OVERWRITE` / `DATA_TRUNCATION` — content change
- `USN_REASON_RENAME_NEW_NAME` (0x2000) — rename

DFSR filters via `FSCTL_READ_USN_JOURNAL` with `MinMajorVersion=3` (Server 2008+) and `UsnJournalStart` from its last committed cursor.

### SYSVOL replication

Server 2008 R2+ uses DFSR for SYSVOL replication (FRS is deprecated, removed in Server 2019). Migration via `dfsmig.exe`:

```
dfsmig /setglobalstate 0   # Start (FRS only)
dfsmig /setglobalstate 1   # Prepare (DFSR replicates SYSVOL alongside FRS)
dfsmig /setglobalstate 2   # Redirect (clients use DFSR copy)
dfsmig /setglobalstate 3   # Eliminate (FRS no longer used; FRS service stopped)
```

SYSVOL is a special Replication Group `CN=SYSVOL Share,CN=DFSR-LocalSettings,CN=<dc>,OU=Domain Controllers,DC=...` linked to the `Domain System Volume` content set in `CN=DFSR-GlobalSettings,CN=System,DC=...`.

## Configuration / code examples

### PowerShell: create a domain-based DFS namespace

```powershell
# On a namespace server
Install-WindowsFeature FS-DFS-Namespace, FS-DFS-Replication -IncludeManagementTools

# Create namespace in v2 (Windows Server 2008 mode)
New-DfsnRoot -Path \\corp.example.com\Public `
             -TargetPath \\file01.corp.example.com\Public `
             -Type DomainV2 `
             -EnableSiteCosting $true

# Add a second root target for fault tolerance
New-DfsnRootTarget -Path \\corp.example.com\Public `
                   -TargetPath \\file02.corp.example.com\Public

# Add a link with two targets, ordered
New-DfsnFolder -Path \\corp.example.com\Public\Engineering `
               -TargetPath \\file01.corp.example.com\Engineering, \\file02.corp.example.com\Engineering

# Set target priority
Set-DfsnFolderTarget -Path \\corp.example.com\Public\Engineering `
                     -TargetPath \\file02.corp.example.com\Engineering `
                     -ReferralPriorityClass SiteCostNormal `
                     -ReferralPriorityRank 0
```

### PowerShell: create a DFS-R Replication Group (full mesh)

```powershell
$rg = New-DfsReplicationGroup -GroupName 'Engineering-Replication' `
        -DomainName corp.example.com -Description 'Engineering data replication'
New-DfsReplicatedFolder -GroupName 'Engineering-Replication' -FolderName 'Engineering'

Add-DfsrMember -GroupName 'Engineering-Replication' -ComputerName file01, file02, file03

# Full mesh topology
New-DfsrTopology -GroupName 'Engineering-Replication' `
  -MemberList file01, file02, file03

# Set the local path on each member
Set-DfsrMembership -GroupName 'Engineering-Replication' -FolderName 'Engineering' `
  -ComputerName file01 -ContentPath 'C:\Shares\Engineering' -PrimaryMember $true
Set-DfsrMembership -GroupName 'Engineering-Replication' -FolderName 'Engineering' `
  -ComputerName file02 -ContentPath 'D:\Shares\Engineering' -PrimaryMember $false
Set-DfsrMembership -GroupName 'Engineering-Replication' -FolderName 'Engineering' `
  -ComputerName file03 -ContentPath 'E:\Shares\Engineering' -PrimaryMember $false

# Force AD replication then poll
repadmin /syncall /A /e /d
dfsrdiag pollad

# Verify
Get-DfsrMember -GroupName 'Engineering-Replication'
Get-DfsrConnection -GroupName 'Engineering-Replication'
```

### Python: query DFS referrals via impacket

```python
from impacket.dcerpc.v5 import transport, netdfs
from impacket.dcerpc.v5.rpcrt import DCERPCException

# Bind to NETDFS interface on a DC
string_binding = r'ncacn_np:\\dc01.corp.example.com[\PIPE\netdfs]'
rpc = transport.DCERPCTransportFactory(string_binding)
rpc.set_credentials('corp\\jdoe', 'password', 'corp.example.com')
dce = rpc.get_dce_rpc()
dce.connect()
dce.bind(netdfs.MSRPC_UUID_DFS)

# NetrDfsGetReferral
req = netdfs.NetrDfsGetReferral()
req['ServerName']   = 'dc01'
req['DFSPath']      = '\\corp.example.com\\Public\\Engineering'
req['Level']        = 3   # DFS_REFERRAL_V3
try:
    resp = dce.request(req)
    print(f"Referral response:")
    for t in resp['ResponseBuffer']['ReferralEntries']:
        print(f"  Server: {t['ServerName']!r}  Share: {t['ShareName']!r}  State: {t['State']}")
except DCERPCException as e:
    print(f"Referral failed: {e}")
dce.disconnect()
```

### Diagnostic commands

```
# Referral cache (client-side)
dfsutil /pktinfo
dfsutil /cache
dfsutil /spcinfo                  # site path cache
dfsutil /pktinfo /p:\\corp.example.com\Public\Engineering

# DFS-N
Get-DfsnRoot
Get-DfsnFolder -Path \\corp.example.com\Public
Get-DfsnFolderTarget -Path \\corp.example.com\Public\Engineering
dfsutil /root:\\corp.example.com\Public /view

# DFS-R
dfsrdiag replstate                 # current replication state per partner
dfsrdiag idrecord                  # version vector
dfsrdiag backlog /rgname:Engineering-Replication /rfname:Engineering /smem:file01 /rmem:file02
Get-DfsrBacklogFileCount -GroupName Engineering-Replication -FolderName Engineering -ReferenceComputerName file01 -MemberComputerName file02

# USN journal
fsutil usn readjournal C:          # dump journal (admin)
fsutil usn queryjournal C:         # journal metadata
```

## Troubleshooting

### Wireshark / network diagnostics

```
# NETDFS RPC referral request/response
dcerpc.if_id == "4FC742E0-4A10-11CF-8273-00AA004AE673"

# DFS-R replication traffic (TCP 445 + dynamic RPC over SMB)
smb2 && smb2.tree.path contains "DFSR" or smb2.tree.path contains "IPC$"
dcerpc.if_id == "91b7b931-c75a-4530-8258-1b3eb578c5d8"

# SYSVOL access during GPO processing
smb2.tree.path == "\\\\corp.example.com\\SYSVOL" or smb2.tree.path contains "SYSVOL"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `\\domain\share` resolves to wrong site | Referral cache TTL too long; site info stale | `dfsutil /pktinfo`; `dfsutil /purge:dfs` to clear client cache; verify `NLTEST /dsgetsite` |
| DFS-R backlog growing unbounded | Network bandwidth saturated; one member offline; RDC disabled on large files | `dfsrdiag backlog`; verify `Set-DfsrConnection -RDCEnabled $true`; check `Get-DfsrConnectionSchedule` |
| ConflictAndDeleted folder growing | Frequent concurrent updates on same file across members | Increase quota: `dfsrdiag quota set`; clean old conflicts via `Remove-DfsrConflictAndDeleted` |
| `Event 4412 — DFSR detected the NTFS USN journal has been reset` | USN journal wrapped or was reset | DFSR auto-recovers via `Journalwrap` non-authoritative sync; force resync: `wbadmin` restore or `dfsrdiag reinitmem` |
| SYSVOL not replicating after DCPROMO | DFSR member not joined to SYSVOL RG | `dfsrdiag pollad`; check `CN=SYSVOL Share,CN=DFSR-LocalSettings` on new DC |
| `Access denied` to namespace root | Permission on `CN=<namespace>,CN=Dfs-Configuration,CN=System,DC=...` | Add read right for Authenticated Users |
| DFS-R service crashes | DFSR database (JET) corruption | Stop DFSR; rename `%SystemRoot%\System32\DFSR\<GUID>\dfsr.db*`; restart DFSR (non-authoritative rebuild) |
| Referral returns wrong target after server outage | Stale referral cache on client | Default TTL 300 s; client will refresh |

### Diagnostic event logs

```
DFS Replication               — Admin and Operational
Microsoft-Windows-DFSN-Server/Operational
Microsoft-Windows-DFSR/Debug (verbose; enable via wevtutil or logman)
```

### Database rebuild (non-authoritative)

```powershell
# Stop DFSR
Stop-Service DFSR

# Move database aside
Move-Item C:\Windows\System32\DFSR\<guid>\* D:\DFSR-backup\

# Set non-authoritative sync for one folder
Set-DfsrMembership -GroupName 'Engineering-Replication' -FolderName 'Engineering' `
   -ComputerName file03 -Force

# Trigger AD poll to rebuild
Start-Service DFSR
dfsrdiag pollad
```

## Cross-platform equivalents

| Windows feature | macOS | Linux |
|---|---|---|
| DFS-N client | macOS SMB client supports DFS referrals via `mount_smbfs`; cached per-session — see `../08-macos-equivalents/08-samba-heimdal-mac.md` | `cifs.ko` kernel module + `mount -t cifs //domain/share /mnt` supports DFS referrals; Samba `smbclient` also handles DFS |
| DFS-N server | (none — Apple SMBX does not host DFS-N) | Samba does NOT host DFS-N namespaces (only acts as a leaf target) — see `../09-linux-equivalents/04-winbind-internals.md` |
| DFS-R replication | (none — no equivalent on macOS) | `lsyncd` / `rsync` / `syncthing` (point-to-point, no multi-master); no DFS-R equivalent |
| RDC | (none) | `librsync` / `rdiff` (similar algorithm; no Samba integration) |
| USN journal | `fs_events` API (per-volume, per-process; not byte-level) | `inotify` (per-directory) + `fanotify` (per-mount; no journaling) |
| SYSVOL replication | (n/a) | Samba 4 AD DC uses DRSUAPI for SYSVOL replication (no DFSR); SysVol is on each DC separately — see `../09-linux-equivalents/05-samba-tool-net-ads.md` |

Samba-as-AD-DC (Samba 4) replicates SYSVOL via DRSUAPI on the SysVol directory (single-master per attribute), NOT via DFS-R — this is a key architectural difference from Windows AD DCs.

## References

- MS-DFSC — Distributed File System (DFS): Namespace Referral Protocol (`[uuid(4FC742E0-4A10-11CF-8273-00AA004AE673)]`)
- MS-DFSR — DFS Replication Protocol (`[uuid(91b7b931-c75a-4530-8258-1b3eb578c5d8)]`)
- MS-ADTS §7.4.1 — `msDFSR-*` classSchema definitions
- MS-ADTS §7.5 — DFS Namespace Configuration Objects
- MS-FRS2 — DFS Replication Protocol (full spec) (`[MS-FRS2]`)
- `dfssvc.dll!DfsManagerInitialize` (service start; loads pKT from registry + AD)
- `mrxdfsc.sys!MRxSmbDfsGetReferral` (kernel referral query)
- `dfsr.exe!Main` (service entry); `dfsr.exe!CReplicationEngine::ProcessUsnJournal` (USN consumer)
- `rdparty.dll!RdcGenerate` (RDC signature computation)
- Microsoft Docs — `https://learn.microsoft.com/windows-server/storage/dfs-namespaces/dfs-overview`
- `https://learn.microsoft.com/windows-server/storage/dfs-replication/dfsr-overview`
- `https://learn.microsoft.com/troubleshoot/windows-server/networking/sysvol-replication-migrates-to-dfsr`
