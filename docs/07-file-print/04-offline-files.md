---
title: Offline Files Internals — cscsvc.dll, CSC v2 Cache, Transparent Caching, Always Offline, Win32_OfflineFiles
audience: senior-engineers
tags: [offline-files, csc, cscsvc-dll, cscdll-dll, transparent-caching, always-offline, syncsvc, win32-offlinefiles, netcache]
related:
  - ./01-smb-shares-internals.md
  - ./02-dfs-n-dfs-r.md
  - ../01-ad-core/01-ad-ds-internals.md
  - ../08-macos-equivalents/07-third-party-agents-mac.md
  - ../09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-13
---

Offline Files (Client-Side Cache, CSC) is implemented by `cscsvc.dll` (service) + `cscdll.dll` (Win32 API) + `cscapi.dll` (UI helpers) backed by an encrypted, proprietary-format cache at `%SystemRoot%\CSC\` (or `CSC-v2` for Server 2012+); sync is triggered at logon/logoff/Task Scheduler, conflict resolution follows a per-share policy (server-wins / client-wins / ask-user), and the WMI provider `root\cimv2:Win32_OfflineFiles*` exposes cache state to PowerShell and Group Policy via registry under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache`.

## Architecture

### Service model

```
services.msc: Offline Files (CscService)
  ImagePath   : %SystemRoot%\System32\svchost.exe -k LocalServiceAndNoImpersonation
  ServiceDll  : %SystemRoot%\System32\cscsvc.dll
  ServiceType : 0x20 (SHARE_PROCESS)
  ObjectName  : NT AUTHORITY\LocalService
  Dependencies: RpcSS, MUP, LanmanWorkstation

User-mode:
  cscsvc.dll          Service entry, RPC handlers, sync engine
  cscdll.dll          Public API (OfflineFiles APIs)
  cscapi.dll          UI helpers (folder icons, sync center)
  SyncCenter.dll      Sync Center integration (Control Panel)
  cscobj.dll          COM objects for Sync Center

Kernel-mode:
  csc.sys             CSC mini-redirector — intercepts SMB Create/Read/Write when offline
  rdbss.sys           Redirected Drive Buffering Subsystem (parent of all mini-redirectors)

Background sync service:
  services.msc: Workstation (syncsvc — Sync Host)
    ImagePath : svchost.exe -k netsvcs
    ServiceDll: %SystemRoot%\System32\SyncHost.dll
    Purpose: runs user-mode sync jobs for Offline Files, Sync Center
```

### Cache format

```
%SystemRoot%\CSC\                   (Server 2008 R2 and earlier)
%SystemRoot%\CSC\v2.0.6\           (Server 2012+ — CSC v2 cache)
  ├─ Cache0001.dat                 (binary; metadata + content; encrypted with SYSTEM-only ACL)
  ├─ Cache0002.dat
  ├─ ...
  ├─ RdpCache0001.dat              (RDP offline cache, if RDP offline mode used)
  └─ Win32_OfflineFiles (used by WMI provider)
```

The cache is encrypted at the file-system level using a 256-bit AES key tied to the machine's DPAPI master key (stored under `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys\` + `Microsoft\Protect\S-1-5-18\`).

CSC v2 (Server 2012+) changes:
- 256-bit encryption (was 128-bit)
- Stream-optimized format (sparse files; faster sync)
- Larger default cache size (10% of disk, was 5%)
- Better compression via `lznt1` for cache pages

Cache size limit set via registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache\Size` (REG_DWORD, in MB; default 0 = auto = 10% of disk).

### CSC mini-redirector (`csc.sys`)

`csc.sys` registers as a mini-redirector with `rdbss.sys`. When a user opens `\\server\share\file.txt`:
1. `mup.sys` routes the UNC to `rdbsx.sys` → `mrxsmb20.sys` (SMB2 client).
2. If `\\server\share` is configured for caching (share `CacheFlags` ≠ 0), `mrxsmb20.sys` calls into `csc.sys` to register the path as cacheable.
3. On `Create`, `csc.sys` checks cache state:
   - **Online** — passthrough to network; optionally also write to cache (transparent caching mode)
   - **Slow-link** — serve from cache (if available); sync in background
   - **Offline** — serve from cache; mark file for sync when back online
4. On `Write`, `csc.sys` writes to cache (synchronously) and queues a sync write to the server.

`csc.sys` exposes IOCTLs to user-mode for cache management (purge, pin, get state). The service `cscsvc.dll` issues these via `DeviceIoControl` on the device `\\.\CSC`.

### Sync triggers

| Trigger | Source | Default behavior |
|---|---|---|
| Logon | `winlogon.exe` fires `SyncServiceProvider.LogonSync` | Sync all pinned shares for the user |
| Logoff | `winlogon.exe` fires `SyncServiceProvider.LogoffSync` | Sync all dirty files; prompt if conflicts |
| Manual | Sync Center (`mobsync.exe` or `SyncCenter.dll`) | User-selected shares only |
| Scheduled | Task Scheduler `\Microsoft\Windows\OfflineFiles\BackgroundSync` | Periodic (default 60 min) |
| Network change | `NLM` (Network List Manager) fires `INetworkListManagerEvents` | Auto-sync on reconnect |
| Slow-link transition | `cscsvc.dll` SlowLinkDetect (ping round-trip) | Switch to "Always Offline" mode |

### Slow-link detection

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache\SlowLinkSpeed
  Default: 64000 (bps) — if measured throughput < this for the share, treat as slow link
```

`cscsvc.dll!SlowLinkDetector` opens an SMB session to the share, transfers a 16 KB block, and measures round-trip time. Three consecutive slow samples (< SlowLinkSpeed) → transition share to offline mode. Faster sample → transition back to online.

### Transparent caching (Server 2008 R2+)

When enabled per-share, files are read through the cache even when online — the client caches a copy after the first read, subsequent reads are served from local cache (verified with the server via a quick SMB CHANGE_NOTIFY or by checking `LastWriteTime` per-open).

This reduces WAN bandwidth but requires the cache to validate staleness per access. Configured via Group Policy:
- Computer Config / Admin Templates / Network / Offline Files / "Transparent Caching Enabled" → `HKLM\SOFTWARE\...\NetCache\TransparentCachingEnabled = 1` (REG_DWORD)
- Per-share: `HKLM\SOFTWARE\...\NetCache\Shares\<ShareName>\TransparentCaching = 1`

### Always Offline mode

Introduced Server 2012. Forces the share into offline mode even when network is fast — provides consistent fast access at the cost of background sync.

GP: Computer Config / Admin Templates / Network / Offline Files / "Configure slow-link mode" → `HKLM\SOFTWARE\...\NetCache\SlowLinkPolicy = 1` (REG_DWORD).

When Always Offline is enabled, the share behaves as offline always; sync runs in background every (default) 120 minutes.

### Conflict resolution

When a file is modified both locally and on the server between syncs:

| Policy | Behavior | Registry |
|---|---|---|
| Server-wins | Server copy overwrites local | `NetCache\ConflictResolution = 1` |
| Client-wins | Local copy overwrites server | `NetCache\ConflictResolution = 2` |
| Ask user | Sync Center prompts user | `NetCache\ConflictResolution = 0` (default) |

Conflict resolution can also be configured per-share via `NetCache\Shares\<ShareName>\ConflictResolution`.

### Background sync

```
services.msc: Sync Host (syncsvc)
  ImagePath   : %SystemRoot%\System32\svchost.exe -k netsvcs
  ServiceDll  : %SystemRoot%\System32\SyncHost.dll
  ServiceType : 0x20
  ObjectName  : LocalService
  Dependencies: RpcSS, ScheduledTasks

SyncHost.dll  (per-user session)
  ↑
  Task Scheduler runs \Microsoft\Windows\OfflineFiles\BackgroundSync
  Trigger: every 120 min (default) when network is up
```

Each user has their own `SyncHost.exe` (or `SyncHost.dll` loaded into a host process) running under that user's identity. Background sync only syncs files the user has cached.

## WMI provider

```
Namespace: root\cimv2
Classes: Win32_OfflineFiles*, defined in cscobj.dll via WMI provider registration

Key classes:
  Win32_OfflineFilesCache           — overall cache state, size, encryption status
  Win32_OfflineFilesFile            — one cached file
  Win32_OfflineFilesDirectory       — one cached directory
  Win32_OfflineFilesShare           — one cached share
  Win32_OfflineFilesItem            — base class for File/Directory/Share
  Win32_OfflineFilesPinInfo         — pin status (pinned = always cached)
  Win32_OfflineFilesDirtyInfo       — uncommitted changes
  Win32_OfflineFilesSyncInfo        — last sync state
  Win32_OfflineFilesChangeInfo      — change list since last sync
  Win32_OfflineFilesConnectionInfo  — online/offline state
```

Methods on `Win32_OfflineFilesCache`:
- `Enable()` / `Disable()` — enable/disable CSC (requires reboot)
- `Encrypt()` / `Decrypt()` — toggle cache encryption
- `GetActiveItemCount()` — count active items
- `Pin()` / `Unpin()` — make item always-cached or not
- `Synchronize()` — force sync
- `PurgeUnpinned()` — purge non-pinned items

## Registry layout

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache\
  ├─ Enabled                                   = 1                (REG_DWORD)  // master switch
  ├─ Size                                      = 0                (REG_DWORD)  // 0 = auto (10% disk)
  ├─ Encrypted                                 = 1                (REG_DWORD)  // encrypt cache
  ├─ AlwaysOfflineEnabled                     = 0                (REG_DWORD)
  ├─ SlowLinkSpeed                             = 64000            (REG_DWORD)  // bps
  ├─ SlowLinkPolicy                            = 0                (REG_DWORD)  // 1 = force slow-link
  ├─ TransparentCachingEnabled                = 0                (REG_DWORD)
  ├─ ConflictResolution                        = 0                (REG_DWORD)  // 0=ask, 1=server, 2=client
  ├─ SyncAtLogon                               = 1                (REG_DWORD)
  ├─ SyncAtLogoff                              = 1                (REG_DWORD)
  ├─ SyncAtSuspend                             = 0                (REG_DWORD)
  ├─ EventLoggingFlags                         = 0x1              (REG_DWORD)
  ├─ BackgroundSyncEnabled                     = 1                (REG_DWORD)
  ├─ BackgroundSyncParams\Interval            = 120              (REG_DWORD)  // minutes
  │
  ├─ Shares\
  │    └─ <ShareName>                          (key per share)
  │         ├─ TransparentCaching             = 0                (REG_DWORD)
  │         ├─ PinPolicy                       = 0                (REG_DWORD)
  │         ├─ SlowLinkSpeed                  = 64000            (REG_DWORD)
  │         ├─ ConflictResolution              = 0                (REG_DWORD)
  │         └─ ExcludeExtensions               = ".tmp;.bak"     (REG_SZ)
  │
  ├─ ExcludeExtensions                         = ".pst;.ost"      (REG_SZ)
  └─ PurgeInterval                             = 1440             (REG_DWORD)  // minutes; purge unpinned older than this

GP path: Computer Configuration / Administrative Templates / Network / Offline Files
```

## Configuration / code examples

### PowerShell: configure Offline Files via GPO

```powershell
$gpo = New-GPO -Name "Offline Files - Workstations" -Domain corp.example.com
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" `
        -ValueName "Enabled" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" `
        -ValueName "Encrypted" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" `
        -ValueName "TransparentCachingEnabled" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" `
        -ValueName "AlwaysOfflineEnabled" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" `
        -ValueName "SlowLinkSpeed" -Type DWord -Value 64000
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" `
        -ValueName "ConflictResolution" -Type DWord -Value 2  # client-wins

# Per-share: pin and enable transparent caching on Engineering share
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache\Shares\Engineering" `
        -ValueName "TransparentCaching" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache\Shares\Engineering" `
        -ValueName "PinPolicy" -Type DWord -Value 1

New-GPLink -Guid $gpo.Id -Target "OU=Workstations,DC=corp,DC=example,DC=com" -LinkEnabled Yes
```

### PowerShell: query WMI cache state and pin a folder

```powershell
# Cache state
$cache = Get-CimInstance -ClassName Win32_OfflineFilesCache -Namespace root/cimv2
[PSCustomObject]@{
  Enabled         = $cache.Enabled
  Encrypted       = $cache.Encrypted
  SizeBytes       = $cache.SizeBytes
  UsedBytes       = $cache.UsedBytes
  FreeBytes       = $cache.FreeBytes
  ActiveItemCount = $cache.ActiveItemCount
} | Format-List

# All cached shares with online/offline state
Get-CimInstance -ClassName Win32_OfflineFilesShare -Namespace root/cimv2 |
  Select-Object Name, Online, Pinned, Dirty, LastSyncTime

# Pin a folder (always-cache)
$cache = Get-CimInstance Win32_OfflineFilesCache -Namespace root/cimv2
Invoke-CimMethod -InputObject $cache -MethodName Pin -Arguments @{
  ItemPath = '\\corp.example.com\Engineering\docs'
  Flags    = 0x00000001  # PIN_FLAG_FILL
}

# Force sync now
Invoke-CimMethod -InputObject $cache -MethodName Synchronize -Arguments @{
  ItemPaths = @('\\corp.example.com\Engineering\docs')
  Flags     = 0x00000002  # SYNC_FLAG_FILLSPARSE
}
```

### Python: enumerate Offline Files cache via WMI

```python
import win32com.client

wmi = win32com.client.Dispatch('WbemScripting.SWbemLocator').ConnectServer('.', 'root\\cimv2')

# All offline items grouped by share
shares = wmi.ExecQuery("SELECT * FROM Win32_OfflineFilesShare")
for s in shares:
    print(f"\nShare: {s.Name}")
    print(f"  Online: {bool(s.Online)}")
    print(f"  Pinned: {bool(s.Pinned)}")
    print(f"  Dirty:  {bool(s.Dirty)}")
    if hasattr(s, 'LastSyncTime') and s.LastSyncTime:
        print(f"  Last sync: {s.LastSyncTime}")

# Files modified but not synced
dirty = wmi.ExecQuery("SELECT * FROM Win32_OfflineFilesFile WHERE Dirty = TRUE")
print(f"\nDirty files ({len(dirty)}):")
for f in dirty:
    print(f"  {f.Path}  modified={f.LastWriteTime}")
```

### Diagnostic commands

```
# Offline Files state
offline /?
offline /status                                  # current online/offline state
offline /share:\\corp.example.com\Engineering    # show per-share state
offline /server:\\file01                          # online/offline per server

# Sync via mobsync (Sync Center)
mobsync /logon                                   # sync at logon time
mobsync /logoff
mobsync /schedule

# Cache management
vssadmin list writers | findstr Offline          # check CSC VSS writer
wmic path Win32_OfflineFilesCache get /value
wmic path Win32_OfflineFilesShare get /value

# Restart CSC service (will close all cached file handles)
Restart-Service CscService

# Disable CSC (requires reboot)
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache' -Name Enabled -Value 0
```

## Troubleshooting

### Wireshark filters

```
# SMB traffic to a share with CSC enabled — look for oplock breaks (server tells client file changed)
smb2.tree.path == "\\\\corp.example.com\\Engineering"
smb2.cmd == 0x12  # OPLOCK_BREAK notification

# Server CHANGE_NOTIFY for transparent caching staleness check
smb2.cmd == 0x05  # CHANGE_DIRECTORY_NOTIFY

# Background sync (scheduled at 120-min intervals)
smb2 && frame.time_relative > 7000 && frame.time_relative < 7500

# Slow-link transition probe (16 KB read)
smb2.cmd == 0x08 and smb2.length == 0x4000   # READ 16 KB
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| Files offline even when network is up | Slow-link triggered; Always Offline enabled; CSC stuck offline | `offline /share:\\server\share /online` to force online; check `SlowLinkSpeed` and `AlwaysOfflineEnabled` |
| `Access denied` when syncing | User changed password; Kerberos ticket stale | `klist purge; gpupdate /force` then sync |
| Conflict dialog on every sync | `ConflictResolution = 0` (ask); user has unsaved local edits | Set `ConflictResolution = 2` (client-wins) or `1` (server-wins); train users |
| Cache fills disk | `Size = 0` (auto = 10%); user pinned too many files | `Set-ItemProperty ... Size -Value <MB>`; `Invoke-CimMethod PurgeUnpinned` |
| Sync fails with `0x80070005` | Server share ACL changed; user lost access | Verify `Get-SmbShareAccess`; re-pin with new credentials |
| `csc.sys` BSOD on slow WAN | Oplock handling bug (older Windows) | Apply latest cumulative update; disable transparent caching as workaround |
| Cache not encrypted after upgrade | `Encrypted = 0` from before Server 2012 | `Invoke-CimMethod Encrypt` on `Win32_OfflineFilesCache` (requires admin; runs in background) |
| `Event 1004 — Cannot initialize the offline files cache` | Cache corruption | Disable CSC (`Enabled = 0`), reboot, delete `%SystemRoot%\CSC\`, enable, reboot |
| Transparent caching not reducing WAN | File last-write-time check still requires SMB round-trip | Disable oplock break filter (registry `DisableOplockBreakFilter`); verify share has CSC enabled |
| Background sync not running | Task Scheduler disabled; user never logged on interactively | `Get-ScheduledTask -TaskName \Microsoft\Windows\OfflineFiles\BackgroundSync`; enable `Run whether user is logged on or not` |

### Diagnostic event logs

```
Microsoft-Windows-OfflineFiles/Operational   — sync events
Microsoft-Windows-OfflineFiles/Analytic      — verbose (enable via wevtutil sl)
Microsoft-Windows-SyncCenter/Operational
```

### Cache reset (last-resort)

```powershell
# 1. Disable CSC
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache' -Name Enabled -Value 0

# 2. Reboot
Restart-Computer -Force

# 3. Delete cache directory
Remove-Item -Recurse -Force C:\Windows\CSC\

# 4. Re-enable
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache' -Name Enabled -Value 1

# 5. Reboot again
Restart-Computer -Force
```

## Cross-platform equivalents

| Windows feature | macOS | Linux |
|---|---|---|
| CSC offline cache | (no native equivalent) — third-party `Expandrive` or `Mountainduck` cache to local disk | `ccachefs` / `OfflineFS` (experimental); mostly absent |
| Sync at logon/logoff | `loginhooks` / `logouthooks` (manual scripts) | `pam_exec` or systemd user units |
| Transparent caching | (none native; macOS SMB client caches file metadata but not content) | (none; kernel caching is page-cache, not offline) |
| Always Offline | (none native) | (none native) |
| Conflict resolution | (none) | (none) |
| WMI Win32_OfflineFiles | (none) | (none) |

macOS does not ship an Offline Files equivalent. Third-party solutions like ExpanDrive or Mountain Duck cache remote SMB/WebDAV shares locally and sync on reconnect; no native integration with Apple's SMBX client. Apple's approach is "always online" — assumes connectivity. For mobile scenarios, mobile accounts + portable home directories (deprecated) used file sync (rsync-based) but are not actively developed — see `../08-macos-equivalents/08-samba-heimdal-mac.md`.

Linux has no native Offline Files feature. Approximations:
- `ccachefs` (FUSE-based) — caches remote FS to local disk; experimental
- `OfflineFS` (FUSE) — similar; unmaintained
- `rsync` cron jobs — manual sync
- Samba `cifs.ko` with `cache=loose` option — page-cache only, not offline
- For full offline support, the closest Linux pattern is local SyncThing/Nextcloud-client — see `../09-linux-equivalents/04-winbind-internals.md`

For Linux domain-joined scenarios, SSSD provides offline Kerberos ticket cache and AD logon cache (offline credentials), which is a partial equivalent for **identity** offline use (not file caching) — see `../09-linux-equivalents/01-sssd-ad-provider.md`.

## References

- MS-CSCMP — Client-Side Caching Maintenance Protocol (CSC) (`[uuid(3FAE6E4F-2E1A-4D9F-8B9F-F39A0F8AB1B8]`)
- MS-CSCCD — Client Side Caching Configuration Data (registry format)
- MS-SMB2 §3.3.5.6 — `TreeConnect.GetResponse` `Capabilities` field bit `SMB2_SHARE_CAP_CONTINUOUSLY_AVAILABLE` and caching flags
- MS-SRVS `SHARE_INFO_1005` `CSCFlags` field (caching policy)
- `cscsvc.dll!CscServiceMain` (service entry); `cscsvc.dll!CscSync` (sync engine)
- `csc.sys!MRxCscFcbInitialization` (mini-redirector FCB creation)
- `cscobj.dll` — WMI provider for `Win32_OfflineFiles*` classes
- `cscdll.dll!OfflineFilesEnable` (enable/disable)
- Microsoft Docs — `https://learn.microsoft.com/windows-server/storage/folder-redirection/deploy-offline-files`
- `https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn645455(v=ws.11)` — Always Offline mode
- Windows Internals 7th Ed., Part 1, Chapter 7 (Networking) — CSC mini-redirector architecture
