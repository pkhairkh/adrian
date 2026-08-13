---
title: Print Services — spoolsv.exe, MS-RPRN RPC, printQueue AD Objects, Driver Isolation, PrintNightmare
audience: senior-engineers
tags: [print-services, spoolsv, ms-rprn, ms-par, printqueue, driver-isolation, printnightmare, pointandprint]
related:
  - ./01-smb-shares-internals.md
  - ./02-dfs-n-dfs-r.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../08-macos-equivalents/07-third-party-agents-mac.md
  - ../09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-13
---

The Print Spooler (`spoolsv.exe`) runs under `svchost -k NetworkService` and exposes the MS-RPRN RPC interface `[uuid(0F30C728-D1DA-11D2-AE4F-00A0C92B955C)]` plus MS-PAR (asynchronous) for print queue management, publishes each shared printer as a `printQueue` object in AD under `CN=<server>,CN=<server-name>,CN=PrintQueues,CN=...`, and was the surface for PrintNightmare (CVE-2021-34527) where `RpcAddPrinterDriverEx` allowed SYSTEM code execution via user-supplied driver paths.

## Architecture

### Service model

```
services.msc: Print Spooler (Spooler)
  ImagePath   : %SystemRoot%\System32\svchost.exe -k NetworkService
  ServiceDll  : %SystemRoot%\System32\spoolsv.exe  (ServiceDll dispatcher, owns ProcessId)
  ServiceType : 0x10 (OWN_PROCESS — spoolsv.exe is its own process, not a hosted DLL)
  ObjectName  : NT AUTHORITY\NetworkService  (Server 2003+; was LocalSystem before)
  Dependencies: RPCSS, LanmanServer, TCP/IP

spoolsv.exe  (single process, 64-bit by default on x64)
  spoolss.dll         Service control + dispatcher
  win32spl.dll        Win32 print provider (default)
  inetpp.dll          Internet Print Provider (IPP)
  localspl.dll        Local print provider
  spoolss.exe         (legacy; redirect)
  printcom.dll        COM interfaces (IXPSDocumentConsumer etc.)
  ntprint.dll         PrintUI / printer install helpers
  prntvpt.dll         XPS to GDI conversion
  puiapi.dll          Printer UI helpers
  printui.dll         PrintUI entry (rundll32 printui.dll,PrintUIEntry ...)
  unidrv.dll / pscript.dll / mxdwdrv.dll  Universal / PostScript / XPS renderers
```

The spooler runs as `NetworkService` (not LocalSystem) since Server 2003, limiting exposure of the SYSTEM token — but PrintNightmare bypassed this because the driver-load path runs in SYSTEM context within the spooler.

### Print provider chain

```
Application → winspool.drv (client API) → spoolss.dll (router) →
  ↓
  Print Provider chain (spoolss.dll enumerates providers):
    localspl.dll         Local spooler (always present)
    win32spl.dll         Remote (\\server\printer) via RPC
    inetpp.dll           IPP (http://server/printers/printer/.printer)
    Custom providers     (loaded from registry HKLM\SYSTEM\...\Print\Providers)
```

The router picks the provider based on printer path prefix: `\\<server>` → win32spl, `http://` → inetpp, no prefix → localspl.

### Print router (`spoolss.dll`)

`spoolss.dll` is the user-mode router. It implements `OpenPrinter`, `StartDocPrinter`, `WritePrinter`, etc. by looking up the print provider by name and calling the matching `OpenPrinter` etc. on that provider.

Print provider registry:
```
HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\
  ├─ LanMan Print Services   (REG_SZ: win32spl.dll)
  ├─ Internet Print Provider (REG_SZ: inetpp.dll)
  └─ <Custom>                (REG_SZ: custom.dll)
```

### MS-RPRN RPC interface

Print System Remote Protocol, `[uuid(0F30C728-D1DA-11D2-AE4F-00A0C92B955C)]`, version 1.0. Exposed on the spooler's named pipe `\PIPE\SPOOLSS` (SMB) or dynamic TCP via the endpoint mapper.

Key opnums (subset):

| Opnum | Method | Notes |
|---|---|---|
| 3 | `RpcEnumPrinters` | List printers (local or remote) |
| 4 | `RpcAddPrinter` | Create a printer (admin) |
| 5 | `RpcDeletePrinter` | Delete |
| 17 | `RpcAddPrinterDriver` | Install a print driver |
| 29 | `RpcEnumPrinterDrivers` | List installed drivers |
| 89 | `RpcRemoteFindFirstPrinterChangeNotificationEx` | Change notification |
| 109 | `RpcAddPrinterDriverEx` | Add driver with flags (was PrintNightmare vector) |
| 29 | `RpcGetPrinterDriverDirectory` | Where drivers live |

`RpcAddPrinterDriverEx` opnum 109 takes a `DRIVER_CONTAINER` (driver name, file paths, version) and a `dwFlags` bitmask including `APD_INSTALL_WARNED_DRIVER` (0x8000) and `APD_COPY_ALL_FILES` (0x4). PrintNightmare exploited this with `dwFlags = APD_INSTALL_WARNED_DRIVER` and a user-writable UNC path: the spooler copied the user-supplied DLL into `C:\Windows\System32\spool\drivers\x64\3\` (as the SYSTEM account) and then loaded it via `LoadLibrary`, achieving SYSTEM code execution.

### MS-PAR (Print System Asynchronous RPC)

`[uuid(76F03F96-CDFD-44FC-A22A-736C8FDCFE7F)]`, version 1.0. Asynchronous variant for high-volume operations; used by Windows Update / IPP clients.

### Print driver isolation

Server 2008 R2+ can run print drivers in isolated processes:

| Isolation mode | Behavior |
|---|---|
| Shared (default) | All drivers share the spoolsv.exe process |
| Isolated | Driver runs in `PrintIsolationHost.exe` (separate process, low-integrity) |
| None | Driver runs in spoolsv.exe (legacy) |

Isolation mode is set per-driver via `PrinterDriverData: PrintIsolationHost` (REG_DWORD) or globally via `HKLM\SYSTEM\CurrentControlSet\Control\Print\PrintIsolationHost`.

`PrintIsolationHost.exe` runs as `LowIntegrity` and has restricted token — if it crashes, only that driver is affected, not the spooler.

### Print driver packages

| Type | Run mode | Notes |
|---|---|---|
| Type 2 (user-mode) | User-mode | Server 2000+; default since Vista |
| Type 3 (kernel-mode) | Kernel-mode | Deprecated; not supported on x64 since Vista |
| Type 4 (XPS-only) | User-mode + spooler integrated | Server 2012+; no driver DLL loaded into spooler — uses spooler's built-in render pipeline |

Type 4 drivers (`*.inf` with `PrinterDriverClass=v4`) don't load third-party code into the spooler at all — they use config XML and the spooler's built-in XPS renderer. This was Microsoft's architectural response to PrintNightmare: a Type 4 driver cannot execute arbitrary code in spooler context.

### Driver install paths

```
HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\
  Windows x64\  (or Windows NT x86\ for 32-bit)
    Drivers\
      Version-3\
        <DriverName>\
          Driver             = <path>   (REG_SZ, e.g., C:\Windows\System32\spool\drivers\x64\3\OldDriver.dll)
          DataFile           = <path>   (REG_SZ, e.g., .ppd or .gpd)
          ConfigFile         = <path>   (REG_SZ, UI DLL)
          HelpFile           = <path>   (REG_SZ)
          DependentFiles     = <list>   (REG_MULTI_SZ)
          PreviousNames      = <list>   (REG_MULTI_SZ)
          DriverVersion      = <int>    (REG_DWORD)
          PrinterAttributes  = 0x8      (REG_DWORD)   // 0x8 = Type 4 (v4 driver)

      Version-4\
        <DriverName>\
          ...
```

### Printer ACLs

Printer security descriptor stored in `HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers\<printer>\Security` (REG_BINARY, self-relative SD). Standard permissions:

| Right | Permission |
|---|---|
| `Print` | Submit jobs (low-privileged user) |
| `ManageDocuments` | Pause/resume/cancel any user's jobs (operator) |
| `ManagePrinters` | Change share name, port, driver; pause/resume the queue |
| `ReadPermissions` | Read SD |
| `ChangePermissions` | Modify SD |
| `TakeOwnership` | Take ownership |

Mapped to printer-specific access masks (`PRINTER_ACCESS_ADMINISTER=0x000F000C`, `PRINTER_ACCESS_USE=0x00020808`, etc.).

### `printQueue` AD objects

Each shared printer can be published to AD as a `printQueue` object (classSchema OID 1.2.840.113556.1.5.22). Default location: `CN=<server>,CN=<server-name>,CN=PrintServices,CN=...` or auto-created under the computer's OU.

Key attributes:

| Attribute | OID | Notes |
|---|---|---|
| `cn` | 2.5.4.3 | Printer share name |
| `serverName` | 1.2.840.113556.1.4.1215 | `\\<server>` |
| `uNCName` | 1.2.840.113556.1.4.137 | `\\<server>\<share>` |
| `printShareName` | 1.2.840.113556.1.4.1432 | Share name |
| `printColor` | 1.2.840.113556.1.4.1339 | Boolean |
| `printDuplexSupported` | 1.2.840.113556.1.4.1354 | Boolean |
| `printStaplingSupported` | 1.2.840.113556.1.4.1368 | Boolean |
| `printMaxResolutionSupported` | 1.2.840.113556.1.4.1357 | DPI |
| `printMemory` | 1.2.840.113556.1.4.1358 | KB |
| `printRate` | 1.2.840.113556.1.4.1362 | Pages per minute |
| `portName` | 1.2.840.113556.1.4.118 | Print port (e.g., IP_192.0.2.10) |
| `driverName` | 1.2.840.113556.1.4.1376 | Driver |
| `location` | 1.2.840.113556.1.4.382 | Free-form location string |

Published via `prncnfg.vbs -t -p <printer> +published` or PowerShell `Set-PrintConfiguration -Published $true`. Clients can search AD for printers by attribute via LDAP filter `(objectCategory=printQueue)`.

### PrintNightmare mitigations

```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
  RestrictDriverInstallationToAdministrators = 1   (REG_DWORD)   # CVE-2021-34527 mitigation
  NoWarningNoElevationOnInstall              = 0   (REG_DWORD)   # 1 = old (insecure) behavior
  UpdatePromptSettings                       = 0   (REG_DWORD)

HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers
  \RestrictAnonymousShareAccess              = 1   (REG_DWORD)   # block null-session \\server\print$
```

Out-of-band patches (KB5004945 / KB5004948) added `RpcAddPrinterDriverEx` validation: server must reject drivers whose file paths point to non-local paths or to UNC paths the requesting user cannot read directly.

### `RpcPacketPrivacy` enforcement

Group Policy: Computer Configuration → Administrative Templates → Printers → "RPC Packet Privacy" (`AlwaysUseRpcPacketPrivacy = 1`). Forces RPC authentication level `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (6) on all MS-RPRN calls — the spooler rejects lower levels (default level was `PKT_INTEGRITY` (5) before Server 2019).

## Configuration / code examples

### PowerShell: install Print and Document Services, add a printer

```powershell
Install-WindowsFeature Print-Services, Print-Server -IncludeManagementTools

# Add TCP/IP printer port
$portName = 'IP_192.0.2.10'
Add-PrinterPort -Name $portName -PrinterHostAddress '192.0.2.10' -SNMPEnabled $true -SNMPCommunity 'public'

# Install a Type 3 driver from INF
Add-PrinterDriver -Name 'HP Universal Printing PCL 6' -InfPath 'C:\Drivers\HP\hpcu250u.inf'

# Add the printer
Add-Printer -Name 'Engineering-LJ-01' -DriverName 'HP Universal Printing PCL 6' -PortName $portName -Shared -ShareName 'Eng-LJ-01' -Published -Location 'HQ/Floor3/CopierRoom'

# Set ACL — only Engineers can print, Admins manage
$sd = Get-Printer -FullName 'Engineering-LJ-01' | Select -ExpandProperty PermissionSDDL
$newSddl = $sd -replace 'A;.*', ''  # strip existing ACEs
$newSddl += '(A;OI;SWRC;;;CORP\Engineering)'   # Print
$newSddl += '(A;OI;FA;;;CORP\PrintAdmins)'     # Full Control (Manage Printers)
Set-Printer -Name 'Engineering-LJ-01' -PermissionSDDL $newSddl

# Verify
Get-Printer -Name 'Engineering-LJ-01' | Format-List Name, ShareName, DriverName, PortName, Published, Location
Get-Printer -Name 'Engineering-LJ-01' -Full | Select -ExpandProperty PermissionSDDL
```

### PowerShell: enforce PrintNightmare mitigations via GPO

```powershell
$gpo = New-GPO -Name "Print Server Hardening" -Domain corp.example.com
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        -ValueName "RestrictDriverInstallationToAdministrators" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        -ValueName "NoWarningNoElevationOnInstall" -Type DWord -Value 0
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" `
        -ValueName "UpdatePromptSettings" -Type DWord -Value 0
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        -ValueName "AlwaysUseRpcPacketPrivacy" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" `
        -ValueName "DisableWebPnPDownload" -Type DWord -Value 1

New-GPLink -Guid $gpo.Id -Target "OU=PrintServers,DC=corp,DC=example,DC=com" -LinkEnabled Yes
```

### PowerShell: enumerate every `printQueue` in AD

```powershell
$root = (Get-ADRootDSE).defaultNamingContext
Get-ADObject -Filter 'objectClass -eq "printQueue"' -SearchBase $root -Properties * |
  Select-Object Name, serverName, uNCName, driverName, printColor, printMaxResolutionSupported, location |
  Format-Table -AutoSize
```

### Python: MS-RPRN RpcEnumPrinters via impacket

```python
from impacket.dcerpc.v5 import transport, rprn
from impacket.dcerpc.v5.rpcrt import DCERPCException

string_binding = r'ncacn_np:\\print01.corp.example.com[\PIPE\SPOOLSS]'
rpc = transport.DCERPCTransportFactory(string_binding)
rpc.set_credentials('corp\\jdoe', 'password', 'corp.example.com')
dce = rpc.get_dce_rpc()
dce.connect()
dce.bind(rprn.MSRPC_UUID_RPRN)

# RpcEnumPrinters (opnum 3), level=2 (PRINTER_INFO_2)
req = rprn.RpcEnumPrinters()
req['Flags']     = rprn.PRINTER_ENUM_LOCAL | rprn.PRINTER_ENUM_SHARED  # 0x0 | 0x7
req['Level']     = 2
req['Buffer']    = b''
resp = dce.request(req)
for p in resp['pPrinterEnum']:
    print(f"{p['pPrinterName']:30s}  share={p['pShareName']:20s}  driver={p['pDriverName']}")

# RpcAddPrinterDriverEx (opnum 109) — admin only; this is the PrintNightmare vector
# (Do not run in production without explicit authorization.)
dce.disconnect()
```

### Diagnostic commands

```
Get-Printer | Format-Table Name, DriverName, PortName, Shared, Published
Get-PrinterDriver | Format-Table Name, InfPath, PrinterEnvironment
Get-PrinterPort | Format-Table Name, PrinterHostAddress, Description
Get-PrintConfiguration -PrinterName 'Engineering-LJ-01'

# PointAndPrint registry
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# Restart spooler
Restart-Service Spooler

# Spooler event log
wevtutil qe "Microsoft-Windows-PrintService/Operational" /c:50 /rd:true /f:text

# PrintUI (legacy)
rundll32 printui.dll,PrintUIEntry /?

# Manual driver isolation host process check
Get-Process PrintIsolationHost -ErrorAction SilentlyContinue
```

## Troubleshooting

### Wireshark filters

```
# MS-RPRN RPC traffic (named pipe \PIPE\SPOOLSS over SMB)
smb2.tree.path == "\\print01\\IPC$" and dcerpc.if_id == "0F30C728-D1DA-11D2-AE4F-00A0C92B955C"
dcerpc.opnum == 109  # RpcAddPrinterDriverEx (PrintNightmare)

# Driver file copy via SMB
smb2.tree.path == "\\print01\\print$" and smb2.filename contains ".dll"

# Printer driver load (event-only; not in packet capture)

# MS-PAR async RPC
dcerpc.if_id == "76F03F96-CDFD-44FC-A22A-736C8FDCFE7F"

# LDAP publication of printQueue
ldap.filter contains "(objectCategory=printQueue)"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `0x0000007e — The specified module could not be found` when adding driver | INF references missing DLL | Use `pnputil /add-driver <inf> /install`; verify `DependentFiles` list |
| `0x00000005 — Access Denied` on `Add-PrinterDriver` | Caller not admin; PrintNightmare mitigation blocking | Add caller to local Administrators; verify `RestrictDriverInstallationToAdministrators=0` only for trusted scenarios |
| PrintNightmare — spooler executes malicious DLL | Driver DLL loaded by spooler (SYSTEM) | Patch to KB5004945+; set `RestrictDriverInstallationToAdministrators=1` |
| Print job stuck in queue | Driver crashed; port unreachable; spooler paused | `Restart-Service Spooler`; `Get-PrintJob | Remove-PrintJob` |
| `PrintIsolationHost` crashes repeatedly | Driver DLL incompatible with isolated host | Set isolation mode back to Shared for that driver: `Set-PrinterDriver -Name <name> -IsolationMode None` |
| `printQueue` not appearing in AD | Spooler service not running; `Published` flag not set | `Set-Printer -Name <name> -Published $true`; restart spooler; verify `CN=printQueue` ACLs |
| Client can't browse printers in AD | Network discovery off; AD query filter wrong; `Print Services` role not installed | Enable Network Discovery; verify `Get-ADObject -Filter 'objectClass -eq "printQueue"'` |
| `RPC_S_SEC_PKG_ERROR` on remote printer install | `RpcPacketPrivacy` enforced but client is old | Upgrade client; or set `AlwaysUseRpcPacketPrivacy=0` (insecure) |
| Slow print spooling over WAN | Driver rendering on server, not client | Enable client-side rendering (CSR): `Set-Printer -RenderMode ClientSide` |
| Printer auto-maps to all users | Group Policy Preference or AD `printQueue` published with auto-install | Remove GPO Prefs; set `printQueue` `Location` carefully |

### Diagnostic event logs

```
Microsoft-Windows-PrintService/Admin         — service errors
Microsoft-Windows-PrintService/Operational   — operational (add/remove printer)
Microsoft-Windows-PrintService/Debug         — verbose (enable via wevtutil)
System                                        — spooler source events
```

### PrintNightmare detection

```powershell
# Detect attempts at driver install that bypass ACL
Get-WinEvent -LogName 'Microsoft-Windows-PrintService/Operational' |
  Where-Object { $_.Id -in 808, 811, 812, 813 } |   # driver install events
  Format-Table TimeCreated, Id, Message -AutoSize

# Detect RpcAddPrinterDriverEx calls
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
# Then watch for \\*\print$ access from non-admin clients
```

## Cross-platform equivalents

| Windows feature | macOS | Linux |
|---|---|---|
| Print spooler (`spoolsv`) | `cupsd` (CUPS) — `/usr/sbin/cupsd` | `cupsd` (CUPS) — `/usr/sbin/cupsd` |
| MS-RPRN RPC | IPP (`http://server:631/printers/...`) — macOS shares printers via CUPS IPP | IPP / LPD / Samba `cups` backend |
| `printQueue` AD objects | Bonjour mDNS advertisement (`_ipp._tcp`) | Avahi mDNS, IPP Everywhere advertisements |
| Driver isolation | (no equivalent; CUPS runs filters as `lp` user) | CUPS runs filters as `lp` user (low-priv) |
| Type 4 v4 drivers | CUPS uses PPD files / IPP Everywhere (no driver code) | IPP Everywhere (driverless printing) |
| PrintNightmare-like | (no equivalent — CUPS doesn't auto-install code via RPC) | (no equivalent — CUPS filters are server-local) |

macOS uses CUPS as its print stack (Apple acquired CUPS in 2007); CUPS exposes IPP on TCP 631, with driver filters stored in `/Library/Printers/`. Printers advertised via Bonjour `_ipp._tcp` mDNS — no LDAP/AD integration. See `../08-macos-equivalents/08-samba-heimdal-mac.md` for Samba-based print sharing.

Linux CUPS (`cupsd`) is identical to macOS CUPS; AD integration for printer discovery is non-native but can be implemented by querying `printQueue` objects via LDAP and publishing them via the CUPS `lpadmin` command. See `../09-linux-equivalents/04-winbind-internals.md` for Samba-based `smbd` print sharing (mimics Windows `PointAndPrint` less securely).

## References

- MS-RPRN — Print System Remote Protocol (`[uuid(0F30C728-D1DA-11D2-AE4F-00A0C92B955C)]`, version 1.0)
- MS-PAR — Print System Asynchronous RPC (`[uuid(76F03F96-CDFD-44FC-A22A-736C8FDCFE7F)]`, version 1.0)
- MS-ADTS §7.5.2 — `printQueue` classSchema (`governsID 1.2.840.113556.1.5.22`)
- CVE-2021-34527 — PrintNightmare (`https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527`)
- CVE-2021-36958 — MS-RPRN `RpcAddPrinterDriverEx` follow-up
- `spoolsv.exe!main` (service entry); `spoolss.dll!OpenPrinterRPC` (router)
- `localspl.dll!SplAddPrinterDriver` (driver install path; site of PrintNightmare fix)
- Microsoft Docs — `https://learn.microsoft.com/windows-server/administration/windows-commands/print-command-reference`
- `https://learn.microsoft.com/windows/security/threat-protection/windows-firewall/known-issues-with-printnightmare-mitigations`
