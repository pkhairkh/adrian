---
title: SMB Shares Internals — lanmanserver, srv2.sys, Share ACLs, ABE, Signing, Encryption, Continuously Available
audience: senior-engineers
tags: [smb, lanmanserver, srv2-sys, srvnet-sys, share-acl, abe, smb-signing, smb-encryption, continuously-available, vss]
related:
  - ./02-dfs-n-dfs-r.md
  - ./04-offline-files.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../08-macos-equivalents/07-third-party-agents-mac.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../09-linux-equivalents/05-samba-tool-net-ads.md
last_updated: 2026-08-13
---

The SMB server runs as the `lanmanserver` service (`svchost -k netsvcs` hosting `srvsvc.dll`) backed by kernel-mode drivers `srv2.sys` (SMB2/3) and `srv.sys` (legacy SMB1), exposing shares enumerated via MS-SRVS RPC `NetShareEnum`, with per-share access controlled by a security descriptor stored under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\Security` and feature flags (AccessBasedEnumeration, EncryptData, ContinuouslyAvailable) stored per-share under `HKLM\...\LanmanServer\Shares\<ShareName>`.

## Architecture

### Service model

```
services.msc: Server (lanmanserver)
  ImagePath   : %SystemRoot%\System32\svchost.exe -k netsvcs
  ServiceDll  : %SystemRoot%\System32\srvsvc.dll
  ServiceType : 0x20 (SHARE_PROCESS)
  StartType   : Automatic
  ObjectName  : LocalSystem
  Dependencies: SamSS, Srv2, LanmanWorkstation, NSI

User-mode:
  srvsvc.dll          Service entry point (NetShareEnum, NetShareAdd, NetShareDel RPC)
  netapi32.dll        Wrappers for NetShare* APIs
  sscore.dll          Share SC core
  srvcli.dll          Client-side for some NetShare callbacks

Kernel-mode:
  srv2.sys            SMB2/3 server (Server 2008+); processes Negotiate/SessionSetup/TreeConnect/Create/Read/Write/Close/...
  srv.sys             Legacy SMB1 server (deprecated; removed by default Server 2016+)
  srvnet.sys          Network-facing layer (TCP listener, TDI on older systems; WSK on Server 2012+)
  rdbss.sys           Redirected Drive Buffering Subsystem (client-side; not for server)
  mrxsmb.sys          SMB client mini-redirector
  mrxsmb20.sys        SMB2/3 client
```

`srvsvc.dll` is the user-mode RPC dispatcher for management operations (`NetShareEnum`, `NetShareAdd`, `NetServerGetInfo` etc.). `srv2.sys` is the kernel-mode packet processor for actual SMB2/3 traffic. The two communicate via IOCTLs.

### Listening ports

| Port | Protocol | Use |
|---|---|---|
| 445 | TCP | SMB direct (modern) |
| 139 | TCP | SMB over NetBIOS (legacy; disabled by default Server 2019+) |
| 137, 138 | UDP | NetBIOS name/datagram (legacy; disabled by default) |

Direct-hosted SMB on TCP 445 is the only supported path on Server 2016+.

### MS-SRVS RPC interface

The `[uuid(4B324FC8-1670-01D3-1278-5A47BF6EE188)]` SRVSVC interface exposes share management:

| Opnum | Method | Notes |
|---|---|---|
| 14 | `NetrShareEnum` | Enumerate shares on server |
| 15 | `NetrShareGetInfo` | Get info on a share (level 0/1/2/501/502/503) |
| 16 | `NetrShareSetInfo` | Set share info |
| 21 | `NetrShareAdd` | Add a share |
| 22 | `NetrShareDel` | Delete a share |
| 28 | `NetrServerGetInfo` | Server info |
| 32 | `NetrServerTransportEnum` | Network transports |
| 56 | `NetrServerAliasAdd` / etc. | (Server 2012+) |

`SHARE_INFO_502` struct (level 502, NDR-encoded):

```
typedef struct _SHARE_INFO_502 {
    [string] wchar_t* shi502_netname;
    DWORD shi502_type;          // STYPE_DISKTREE=0x00, STYPE_PRINTQ=0x01, STYPE_DEVICE=0x02, STYPE_IPC=0x03
    [string] wchar_t* shi502_remark;
    DWORD shi502_permissions;   // legacy; not used by SMB2
    DWORD shi502_max_uses;
    DWORD shi502_current_uses;
    [string] wchar_t* shi502_path;
    [string] wchar_t* shi502_passwd;
    DWORD shi502_reserved;
    PSECURITY_DESCRIPTOR shi502_security_descriptor;  // self-relative SD
} SHARE_INFO_502;
```

### Registry layout

```
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\
  ├─ <ShareName>                         (key per share)
  │    ├─ Path                            = <REG_SZ, e.g. C:\Shares\Engineering>
  │    ├─ Type                            = 0x00000000  (REG_DWORD)  // STYPE_DISKTREE
  │    ├─ Remark                          = ""           (REG_SZ)
  │    ├─ Permissions                     = 0x00000000   (REG_DWORD)  // legacy, unused
  │    ├─ MaxUses                         = 0xFFFFFFFF   (REG_DWORD)  // unlimited
  │    ├─ Security                        = <self-relative SD binary>  (REG_BINARY)
  │    ├─ AccessBasedEnumeration         = 1            (REG_DWORD)  // 0=off (default), 1=on
  │    ├─ CacheFlags                      = 0x00000040   (REG_DWORD)  // CSC caching
  │    │     bit 0x00 = manual caching of documents
  │    │     bit 0x10 = automatic caching of documents
  │    │     bit 0x20 = automatic caching of programs
  │    │     bit 0x40 = no caching (default for new Server 2012+ shares)
  │    │     bit 0x30 = branchcache
  │    ├─ EncryptData                     = 1            (REG_DWORD)  // 0=off (default), 1=SMB3 encryption
  │    ├─ ContinuouslyAvailable          = 1            (REG_DWORD)  // 1=CA (SMB3 CA, requires cluster)
  │    └─ Description                     = ""           (REG_SZ)
  │
  ├─ Security                            = <default SD binary>   (REG_BINARY)  // applied to new shares if not set
  ├─ AutoShareServer                    = 0                     (REG_DWORD)   // 1 = auto-create C$, ADMIN$, IPC$
  └─ AutoShareWks                       = 0                     (REG_DWORD)

HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
  ├─ EnableSMB1Protocol                  = 0                     (REG_DWORD)  // disable SMB1
  ├─ EnableSMB2Protocol                  = 1                     (REG_DWORD)
  ├─ RequireSecuritySignature            = 0                     (REG_DWORD)  // 1 = require signing
  ├─ EnableSecuritySignature             = 1                     (REG_DWORD)  // 1 = enable (not require)
  ├─ EncryptShare                        = 0                     (REG_DWORD)  // global default
  ├─ SrvComment                          = "Engineering file server"  (REG_SZ)
  ├─ NullSessionShares                   = <list>                (REG_MULTI_SZ)  // shares allowing null session
  ├─ AutoDisconnect                      = 15                    (REG_DWORD)  // idle session disconnect (minutes)
  ├─ EnableOplockTimeout                 = 25                    (REG_DWORD)
  ├─ EnableMultiAccept                   = 1                     (REG_DWORD)
  ├─ EnableLeasing                       = 1                     (REG_DWORD)  // SMB2 leasing
  ├─ EnableLargeMtu                      = 1                     (REG_DWORD)  // SMB3 multi-credit
  ├─ EnableMultiChannel                  = 1                     (REG_DWORD)  // SMB3 multichannel
  ├─ AnnounceServer                      = 0                     (REG_DWORD)  // browser announce
  └─ Hidden                              = 0                     (REG_DWORD)  // hide from browse list
```

### Share-level vs NTFS permissions

Share ACL (the `Security` binary) is evaluated first when a client connects via `TreeConnect`. If access is denied at the share level, the client never sees NTFS. If access is granted, NTFS ACL on the file system is evaluated per `Create` / `Read` / `Write`.

The effective permission is the **intersection** (most restrictive) of share ACL and NTFS ACL.

### AccessBasedEnumeration (ABE)

When `AccessBasedEnumeration = 1` on a share, `srv2.sys` filters directory enumeration responses (`FILE_DIRECTORY_INFORMATION` etc.) to only return entries the caller has `FILE_ListDirectory` (read) access to via NTFS. Implemented in `srv2.sys!SrvSmbQueryDirectoryInformation` post-filter.

ABE adds CPU overhead per directory listing — for shares with many entries, disable ABE in deep, performance-critical read paths.

### SMB signing

| Setting | Registry | Effect |
|---|---|---|
| Enabled (not required) | `EnableSecuritySignature=1`, `RequireSecuritySignature=0` | Sign if client requests; otherwise plain |
| Required | `RequireSecuritySignature=1` | Reject unsigned sessions |
| Disabled | `EnableSecuritySignature=0` | Never sign (insecure; not recommended) |

SMB3 dialects (2.1, 3.0, 3.0.2, 3.1.1) sign all messages by default during session setup unless encryption is negotiated (in which case signing is implicit because encryption includes an integrity check).

Signing algorithm per dialect (see also `../02-protocols/03-smb-cifs-protocol.md`):

| Dialect | Algorithm |
|---|---|
| SMB1 | HMAC-MD5 over the SMB message using session key |
| SMB 2.0 - 2.1 | HMAC-SHA-256 over the message, first 16 bytes used |
| SMB 3.0 - 3.0.2 | AES-CMAC-128 over the message |
| SMB 3.1.1 | AES-GMAC-128 with preauth integrity hash as AAD |

### SMB encryption (SMB 3.0+)

Per-share `EncryptData = 1` forces encryption on that share. The `EncryptShare` registry value under `Parameters` is the global default.

SMB 3.0/3.0.2 use AES-CCM-128; SMB 3.1.1 negotiates AES-CCM-128 or AES-GCM-128 (GCM preferred for performance). Key derivation uses HKDF-SHA512 with the SMB session key as input key material and dialect-specific labels (see MS-SMB2 §3.2.5.3).

### Continuously Available shares

`ContinuouslyAvailable = 1` requires:
1. The SMB server to be a clustered role (Failover Cluster).
2. The share's underlying disk to be a Cluster Shared Volume (CSV) or clustered disk.
3. The share flag `CA` set so that `srv2.sys` returns `SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE` in `TreeConnect.GetResponse`.

CA shares support transparent failover: when a cluster node fails, the share's SMB session state (open files, leases, handles) is migrated to another node, and clients see only a brief TCP retransmit. Requires persistent handles (`DH2Q`/`DH2C` create contexts) at create time.

### Shadow copies (VSS) integration

`srv2.sys` exposes previous versions via the `SHI1005_FLAGS_ENCRYPT_NAMESPACE` and the `TimeWarp` SRVSVC opnum (legacy). The "Previous Versions" client-side shell extension reads VSS snapshots via `IOCTL_VOLSNAP_QUERY_ORIGINAL_VOLUMENAME` on the underlying NTFS volume.

Shadow copy schedules are configured via `vssadmin` or the "Previous Versions" GP; copies are stored in the `System Volume Information` folder as VSS diff-area files.

### `srvnet.sys`

The network-facing layer underneath `srv2.sys`. Handles:
- TCP connection acceptance (via WSK on Server 2012+; TDI on older)
- Pre-negotiate buffering
- Sizing of receive buffers
- Compounded request handling

Vulnerabilities in `srvnet.sys` were at the root of EternalBlue (MS17-010) — `srvnet.sys!SrvNetWskReceiveComplete` buffer overflow.

## Configuration / code examples

### PowerShell: create a share with full ABE + encryption + CA flag

```powershell
$shareParams = @{
  Name        = 'Engineering'
  Path        = 'C:\Shares\Engineering'
  FullAccess  = 'CORP\Domain Admins'
  ChangeAccess = 'CORP\Engineering'
  ReadAccess  = 'CORP\Engineering-Ro'
  Description = 'Engineering share'
  EncryptData = $true   # SMB3 encryption
  ConcurrentUserLimit = 0
}
New-SmbShare @shareParams

# Enable ABE
Set-SmbShare -Name 'Engineering' -FolderEnumerationMode AccessBased -Force

# Enable Continuously Available (only on cluster nodes)
Set-SmbShare -Name 'Engineering' -ContinuouslyAvailable $true -Force

# Verify
Get-SmbShare -Name 'Engineering' | Format-List Name, Path, EncryptData, FolderEnumerationMode, ContinuouslyAvailable, Description
Get-SmbShareAccess -Name 'Engineering'
```

### PowerShell: enumerate all shares, decode SD, show flags

```powershell
Get-SmbShare | ForEach-Object {
  $share = $_
  # Read the Security binary from registry
  $sdBytes = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\$($share.Name)" -Name Security -ErrorAction SilentlyContinue).Security
  $sd = $null
  if ($sdBytes) {
    $sd = New-Object System.Security.AccessControl.FileSecurity
    $sd.SetSecurityDescriptorBinaryForm($sdBytes)
  }
  [PSCustomObject]@{
    Name                 = $share.Name
    Path                 = $share.Path
    ABE                  = if ($share.FolderEnumerationMode -eq 'AccessBased') {'Y'} else {'N'}
    EncryptData          = $share.EncryptData
    ContinuouslyAvailable= $share.ContinuouslyAvailable
    CacheMode            = (Get-ItemProperty "HKLM:\...\LanmanServer\Shares\$($share.Name)" -Name CacheFlags -ErrorAction SilentlyContinue).CacheFlags
    SDDL                 = if ($sd) { $sd.Sddl } else { '(inherit)' }
  }
} | Format-Table -AutoSize
```

### PowerShell: require SMB signing on all clients (GPO registry)

```powershell
# Domain-wide GPO targeting servers
$gpo = New-GPO -Name "SMB Security - Servers" -Domain corp.example.com
$gpo | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -ValueName "RequireSecuritySignature" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -ValueName "EnableSMB1Protocol" -Type DWord -Value 0
$gpo | Set-GPRegistryValue -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -ValueName "RequireSecuritySignature" -Type DWord -Value 1

# Client-side audit
Get-SmbClientConfiguration | Select EnableSecuritySignature, RequireSecuritySignature, EnableInsecureGuestLogons
Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature
```

### Python: enumerate shares via impacket (anonymous)

```python
from impacket.smbconnection import SMBConnection

c = SMBConnection('file01.corp.example.com', 'file01.corp.example.com', sess_port=445)
c.login('', '')   # anonymous / null session (may be refused)

# List shares
shares = c.listShares()
for s in shares:
    name = s['shi1_netname'][:-1]
    typ  = s['shi1_type']
    print(f"{name:20s} type=0x{typ:x}")
    # 0 = DISKTREE, 1 = PRINTQ, 2 = DEVICE, 3 = IPC, 0x80000000 = SPECIAL, 0x40000000 = TEMPORARY

# Walk the share's tree (with auth)
c.logoff()
c = SMBConnection('file01.corp.example.com', 'file01.corp.example.com')
c.login('corp\\jdoe', 'password')
files = c.listPath('Engineering', '*')
for f in files:
    print(f"  {f.get_longname():30s} {f.get_filesize():>12d} bytes")
```

### Diagnostic commands

```
Get-SmbShare
Get-SmbShareAccess -Name <share>
Get-SmbConnection
Get-SmbOpenFile
Get-SmbSession
Get-SmbMapping
Get-SmbClientConfiguration
Get-SmbServerConfiguration
Get-SmbMultichannelConnection

# Disable SMB1 server-side
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Performance counters
(Get-Counter -Counter '\TCPv4\Connections Established').CounterSamples
(Get-Counter -Counter '\Server\File Open Connections Total').CounterSamples
```

## Troubleshooting

### Wireshark filters

```
# SMB2 traffic to/from a specific server
smb2 && ip.addr == 192.0.2.10

# TreeConnect to a specific share
smb2.cmd == 3 && smb2.tree.path == "\\Engineering"

# Negotiate (SMB2 dialect selection)
smb2.cmd == 0

# Signing / encryption failures (STATUS_ACCESS_DENIED with SMB2 signature)
smb2.cmd == 1 && smb2.nt_status == 0xC0000022

# Persistent handles (CA shares)
smb2.flags.durable_handle_v2 == 1

# Encryption negotiation
smb2.cmd == 0 && smb2.dialect == 0x0311

# MS-SRVS NetShareEnum
dcerpc.if_id == "4B324FC8-1670-01D3-1278-5A47BF6EE188" && dcerpc.opnum == 14
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `Access is denied. 0x5` on share access | Share ACL or NTFS ACL denies caller | `Get-SmbShareAccess -Name <share>`; `icacls <path>`; verify effective access via `whoami /groups` |
| ABE shows files caller can't read | ABE requires `AccessBasedEnumeration=1` per share | `Set-SmbShare -Name <share> -FolderEnumerationMode AccessBased` |
| `The network name cannot be found. 0x80070035` | Share doesn't exist; or DNS wrong; or SMB1 forced | `Get-SmbShare -Name <share>`; verify `EnableSMB1Protocol=0` not required by client |
| `A required privilege is not held by the client. 0x1311` | SMB signing required by server, client refuses | Set client `RequireSecuritySignature=0` or enable signing on client |
| Session drops every 15 min | `AutoDisconnect = 15` default idle timeout | `Set-SmbServerConfiguration -AutoDisconnect 0` (or large value) |
| `STATUS_FILE_CLOSED` after cluster failover | CA share but client didn't request persistent handles | Client must negotiate SMB 3.0+ and request DH2Q context |
| Slow enumeration on ABE share | ABE post-filters all directory entries; share has thousands | Disable ABE on deep read paths; add per-subfolder index |
| Encryption `STATUS_ACCESS_DENIED` | Server `EncryptData=1`, client doesn't support SMB3 | Upgrade client; or set `EncryptData=0` (downgrade risk) |
| `srv2` event 2017 — server rejected connection | `SrvMaxSessionsPerUser` exceeded | Increase via registry `HKLM\...\LanmanServer\Parameters\MaxSessionsPerUser` |

### Diagnostic event logs

```
Microsoft-Windows-SmbServer/Operational   — server-side errors
Microsoft-Windows-SmbServer/Security      — security-related events (signing, auth failures)
Microsoft-Windows-SmbClient/Operational
Microsoft-Windows-SmbClient/Security
```

## Cross-platform equivalents

| Windows feature | macOS | Linux |
|---|---|---|
| SMB server (srv2.sys) | `smbd` via Samba (`/usr/sbin/smbd`) — see `../08-macos-equivalents/08-samba-heimdal-mac.md` | `smbd` (Samba) — see `../09-linux-equivalents/04-winbind-internals.md` and `../09-linux-equivalents/05-samba-tool-net-ads.md` |
| Share ACL | `smb.conf` per-share `valid users =` / `write list =`; POSIX mode bits | Same as macOS Samba; or POSIX ACLs |
| AccessBasedEnumeration | Samba `hide unreadable = yes` | Same Samba directive |
| SMB signing | `smb.conf: server signing = mandatory` | Same |
| SMB encryption | `smb.conf: server smb encrypt = required` | Same |
| Continuously Available | CTDB clustered Samba (limited; no transparent failover) | CTDB cluster Samba (limited) |
| Shadow copies / VSS | Time Machine snapshots (client-side; not exposed to SMB clients) | LVM snapshots exposed via Samba `shadow_copy2` VFS module |
| MS-SRVS RPC | `rpcclient -U <user> //server -c 'enumshare'` | Same (`rpcclient` from Samba) |

macOS ships a forked Samba (was removed in 10.7 then re-added as a separately installed component) — Apple's native SMBX server (`/usr/sbin/smbd` Apple fork) replaces Samba for default file serving; Samba can be installed via Homebrew for full feature parity. See `../08-macos-equivalents/08-samba-heimdal-mac.md`.

Linux Samba `smbd` is the canonical SMB server and supports all SMB3 dialects including 3.1.1 with encryption. Active Directory integration via `winbind` or `sssd` (see `../09-linux-equivalents/04-winbind-internals.md`).

## References

- MS-SMB2 — Server Message Block (SMB) Protocol Versions 2 and 3
- MS-SRVS — Server Service Remote Protocol (`[uuid(4B324FC8-1670-01D3-1278-5A47BF6EE188)]`, version 3.0)
- MS-SRVS §3.1.4.7 — NetrShareEnum / SHARE_INFO_502 NDR
- MS-SRVS §3.1.4.12 — NetrServerGetInfo
- RFC 7858 — SMB 3.1.1 preauth integrity
- Windows Internals 7th Ed., Part 1, Chapter 7 (Networking) — SMB server kernel architecture
- `srv2.sys!SrvSmbTreeConnect` (TreeConnect handler; reverse-engineered via WinDbg public symbols)
- `srvsvc.dll!NetrShareEnum` dispatch
- `srvnet.sys!SrvNetWskReceiveComplete` (network receive; site of MS17-010 EternalBlue)
- Microsoft Docs — `https://learn.microsoft.com/windows-server/storage/file-server/file-server-smb-overview`
