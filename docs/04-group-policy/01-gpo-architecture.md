---
title: GPO Architecture — GPC, GPT, gPLink, gPOptions, gpsvc.dll in svchost
audience: senior-engineers
tags: [gpo, gpc, gpt, gplink, gpoptions, gpsvc, group-policy-container]
related:
  - ./02-gpo-processing-order.md
  - ./03-admx-templates.md
  - ./04-cse-client-side-extensions.md
  - ./05-gpt-gpc-structure.md
  - ../03-directory-schema/02-ous-containers.md
last_updated: 2026-08-13
---

A Group Policy Object is a two-part entity: the Group Policy Container (GPC), a `groupPolicyContainer` object stored in AD at `CN=Policies,CN=System,<domain-dn>`, and the Group Policy Template (GPT), a folder under `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\` carrying the actual `Registry.pol`, scripts, and XML preference files — both halves are linked by the GPC's `gPCFileSysPath` UNC and version-stamped together via the combined machine/user `versionNumber` attribute that the Group Policy Client Service (`gpsvc.dll` hosted in `svchost -k netsvcs`) reads to detect changes on every refresh.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ AD (LDAP)                                                                       │
│  CN=Policies,CN=System,DC=corp,DC=example,DC=com                                │
│   └─ CN={31B2F340-016D-11D2-945F-00C04FB984F9}  (Default Domain Policy)        │
│         objectClass           : groupPolicyContainer                            │
│         displayName           : "Default Domain Policy"                         │
│         gPCFileSysPath        : \\corp.example.com\SYSVOL\corp.example.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9} │
│         gPCMachineExtensionNames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]          │
│         gPCUserExtensionNames    : [{42B5FAAE-6536-11d1-AE59-0000FED75982}{...}] │
│         versionNumber        : 9007471 (0x0089BFFF)                              │
│                                   ↑ high 32 bits = user (0x0089), low 32 = machine (0xBFFF) │
│         gPCWQLFilter         : LDAP://CN={guid},CN=WMI Filters,CN=SOM,...
│         gPCFunctionalityVersion : 2                                             │
│                                                                                  │
│  CN=Sales,OU=...,DC=corp,DC=example,DC=com                                       │
│         gPLink                : [LDAP://CN={guid},CN=Policies,CN=System,...;0]   │
│         gPOptions             : 0   (0=inherit, 1=block inheritance)             │
└─────────────────────────────────────────────────────────────────────────────────┘
                                  ▲ linked by UNC
                                  │
┌─────────────────────────────────────────────────────────────────────────────────┐
│ SYSVOL (SMB share, DFS-R replicated)                                            │
│  \\<domain>\SYSVOL\<domain>\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\    │
│   ├─ GPT.INI                          [General] Version=9007471                  │
│   ├─ Machine\                                                                      │
│   │    ├─ Registry.pol                (PReg binary, processed by Registry CSE)    │
│   │    ├─ Scripts\Startup\            (startup scripts)                           │
│   │    ├─ Scripts\Shutdown\                                                         │
│   │    ├─ Microsoft\Windows NT\SecEdit\GptTmpl.inf  (security template)          │
│   │    └─ Preferences\                (XML preference files)                      │
│   │         ├─ Registry\Registry.xml                                                │
│   │         ├─ Files\Files.xml                                                      │
│   │         ├─ Services\Services.xml                                                │
│   │         ├─ ScheduledTasks\ScheduledTasks.xml                                    │
│   │         └─ ...                                                                  │
│   └─ User\                                                                         │
│        └─ ... (mirror of Machine\ for user-side policy)                            │
└─────────────────────────────────────────────────────────────────────────────────┘
                                  ▲ read by
                                  │
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Client (Win10/11) gpsvc.dll in svchost -k netsvcs                               │
│  - Bind to LDAP, fetch gPLink chain                                              │
│  - Fetch each GPC object's attributes                                            │
│  - Compare versionNumber to locally cached value                                 │
│  - SMB-read GPT files via the gPCFileSysPath UNC                                 │
│  - For each CSE listed in gPCMachineExtensionNames, invoke the CSE              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## `groupPolicyContainer` class (GPC)

Class: `groupPolicyContainer` (governsID `1.2.840.113556.1.5.108`).

| Attribute                  | OID                              | Type             | Purpose                                                                                    |
|----------------------------|----------------------------------|------------------|--------------------------------------------------------------------------------------------|
| `cn`                       | 2.5.4.3                          | DirectoryString  | RDN — the GPO GUID in `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` form, braces included.       |
| `displayName`              | 1.2.840.113556.1.4.1352          | DirectoryString  | Friendly name shown in GPMC.                                                                |
| `gPCFileSysPath`           | 1.2.840.113556.1.4.1357          | DirectoryString  | UNC path to the GPT folder (e.g. `\\corp.example.com\SYSVOL\corp.example.com\Policies\{GUID}`). |
| `gPCMachineExtensionNames` | 1.2.840.113556.1.4.1360          | DirectoryString  | Bracketed list of CSE-GUID + snap-in-GUID pairs that process the Machine half.              |
| `gPCUserExtensionNames`    | 1.2.840.113556.1.4.1359          | DirectoryString  | Same for User half.                                                                          |
| `versionNumber`            | 1.2.840.113556.1.4.1340          | Integer          | Combined: high 32 bits = user version, low 32 bits = machine version.                       |
| `gPCWQLFilter`             | 1.2.840.113556.1.4.1388          | DirectoryString  | LDAP URL pointing at the WMI filter object under `CN=WMI Filters,CN=SOM,...`. Empty = no filter. |
| `gPCFunctionalityVersion`  | 1.2.840.113556.1.4.1351          | Integer          | Schema version (2 = current; affects ADMX parsing).                                          |
| `msDS-ObjectReference`     | (derived)                        | DN-String        | DN of GPO (computed).                                                                        |
| `showInAdvancedViewOnly`   |                                  | Boolean          | TRUE for default policy.                                                                     |
| `objectCategory`           | 2.5.6.5                          | DN               | `CN=Group-Policy-Container,CN=Schema,CN=Configuration,...`.                                 |

The `versionNumber` packing — high 32 = user, low 32 = machine — is computed as:

```
versionNumber = (userVersion << 32) | (machineVersion & 0xFFFFFFFF)
```

PowerShell decode:

```powershell
$gpc = Get-ADObject -Identity "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=example,DC=com" -Properties versionNumber
$v   = [uint64]$gpc.versionNumber
"Machine version: {0}" -f ($v -band 0xFFFFFFFF)
"User version   : {0}" -f ($v -shr 32)
```

When the GPMC saves a GPO, it bumps the appropriate half (machine or user, depending on what was edited), recomputes `versionNumber`, writes it to the GPC, AND writes the same value into `GPT.INI`'s `Version=` field. The two are an atomic unit — if they disagree, `gpsvc` re-reads both and re-applies.

## `gPLink` and `gPOptions` — linking GPOs to containers

The `gPLink` attribute (OID `1.2.840.113556.1.4.1361`, DirectoryString) lives on `site`, `domainDNS`, and `organizationalUnit` objects (NOT on `container` — see `../03-directory-schema/02-ous-containers.md`).

Format:

```
[LDAP://CN={GUID},CN=Policies,CN=System,DC=corp,DC=example,DC=com;Options][LDAP://CN={GUID2},...;Options2]...
```

Each `[<DN>;<Options>]` segment is one GPO link. Order matters — left to right is highest-priority (LSDOU; see `./02-gpo-processing-order.md`).

`<Options>` bitmask:

| Bit | Mask    | Name                          | Effect                                                       |
|-----|---------|-------------------------------|--------------------------------------------------------------|
| 0   | 0x0001  | GPO_LINK_DISABLED             | Link present but disabled (GPMC greys it out).                |
| 1   | 0x0002  | GPO_LINK_ENFORCED             | "Enforced" (formerly "No Override") — overrides child blocks. |
| (other bits reserved)            |                                                              |

Example decoded:

```
[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=example,DC=com;0]   ; default policy, normal
[LDAP://CN={A1B2C3D4-...},CN=Policies,...;1]                                                            ; disabled
[LDAP://CN={E5F6G7H8-...},CN=Policies,...;2]                                                            ; enforced
```

`gPOptions` (OID `1.2.840.113556.1.4.1360`) on the container:

| Bit | Mask    | Name                          | Effect                                                        |
|-----|---------|-------------------------------|---------------------------------------------------------------|
| 0   | 0x0001  | GPO_BLOCK_INHERITANCE         | Block inheritance from parent OUs / domain. Enforced links still apply. |

## `gPCMachineExtensionNames` / `gPCUserExtensionNames` — CSE list

These attributes encode which Client-Side Extensions must be invoked for the GPO. Format:

```
[{<CSE-GUID>}{<SnapIn-GUID>}][{<CSE-GUID2>}{<SnapIn-GUID2>}]...
```

Each bracketed pair is one extension. The first GUID is the CSE (registered under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{GUID}`). The second GUID is the snap-in that authors settings for that CSE (so GPMC knows which extension tab to show).

Example (Default Domain Policy `gPCMachineExtensionNames`):

```
[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
[{42B5FAAE-6536-11D1-AE59-0000FED75982}{40B66650-4972-11D1-A7CA-0000F87571E53}]
```

CSE GUIDs:

- `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` — Registry CSE (most common)
- `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` — Security CSE
- `{42B5FAAE-6536-11D1-AE59-0000FED75982}` — Scripts CSE
- (full list — see `./04-cse-client-side-extensions.md`)

When `gpsvc` processes a GPO, it iterates the extension list and calls each registered CSE's `ProcessGroupPolicy` entry point. CSEs not listed are NOT invoked, even if the GPT contains their files (e.g. if `Machine\Registry.pol` exists but the Registry CSE GUID is missing from `gPCMachineExtensionNames`, the file is ignored).

## The Group Policy Client Service — `gpsvc.dll`

Service: `gpsvc` (Group Policy Client). Display name: "Group Policy Client". Host process: `svchost.exe -k netsvcs`. DLL: `gpsvc.dll`.

Service registry:

```
HKLM\SYSTEM\CurrentControlSet\Services\gpsvc
  ├── Type              = 0x20        (REG_DWORD, SERVICE_WIN32_SHARE_PROCESS)
  ├── Start             = 2           (REG_DWORD, Automatic)
  ├── ErrorControl      = 1           (REG_DWORD, Normal)
  ├── ImagePath         = %SystemRoot%\system32\svchost.exe -k netsvcs
  ├── ObjectName        = LocalSystem
  ├── Group             = ProfSvc_Group   (depends on ProfSvc for user-side policy)
  └── Parameters
       ├── ServiceDll   = %SystemRoot%\system32\gpsvc.dll  (REG_EXPAND_SZ)
       └── ServiceDllUnloadOnStop = 1
```

`gpsvc.dll` exports `ServiceMain` (called by `svchost` when the service starts). It then:

1. Loads `gptext.dll` (Group Policy Text Extension — parses .inf security templates).
2. Loads `gpcse.dll` etc. — each registered CSE DLL.
3. Registers for `WM_WININICHANGE` and `WM_SETTINGCHANGE` notifications.
4. Sets up a notification timer (default 90-min interval + 0-30 min jitter).
5. Spawns a worker thread for computer-policy refresh and one per logged-on user for user-policy refresh.

`gpsvc` entry points (called by `gpupdate.exe`):

- `RefreshPolicyEx` — synchronous or asynchronous refresh
- `ProcessGroupPolicyEx` — explicit CSE invocation
- `RegisterGroupPolicyChangedNotification` — callback registration for notifications

## Diagnostic — LDAP filter

Find all GPOs with WMI filters attached:

```ldap
(&(objectClass=groupPolicyContainer)(gPCWQLFilter=*))
```

Find OUs with blocked inheritance:

```ldap
(&(objectClass=organizationalUnit)(gPOptions:1.2.840.113556.1.4.803:=1))
```

Find all GPO links where the link is Enforced (Options bit 1 = 0x2):

```ldap
(objectClass=*) — must parse gPLink attribute values; no direct LDAP filter
```

## Wireshark display filter

GP processing on the wire = LDAP queries to fetch GPC + SMB reads to fetch GPT files:

```
# LDAP queries against the Policies container:
ldap && ldap.baseObject contains "CN=Policies,CN=System"

# SMB reads of GPT files:
smb2 && smb2.filename contains "Policies" && (smb2.filename contains "Registry.pol" || smb2.filename contains "GPT.INI")
```

For SYSVOL access over SMB1 (legacy):

```
smb && (smb.cmd == 0x05) && (smb.path contains "SYSVOL") && (smb.path contains "Policies")
```

## PowerShell — enumerate GPO architecture

```powershell
# 1. All GPOs in the domain with their version split
Import-Module GroupPolicy
Get-GPO -All | ForEach-Object {
    $gpc = Get-ADObject -Identity "CN=$($_.Id),CN=Policies,CN=System,DC=corp,DC=example,DC=com" `
                        -Properties versionNumber, gPCFileSysPath, gPCMachineExtensionNames,
                                   gPCUserExtensionNames, gPCWQLFilter
    [PSCustomObject]@{
        DisplayName       = $_.DisplayName
        GPOId             = $_.Id
        GPCVersion        = $gpc.versionNumber
        MachineVersion    = $gpc.versionNumber -band 0xFFFFFFFF
        UserVersion       = [uint64]$gpc.versionNumber -shr 32
        GPTPath           = $gpc.gPCFileSysPath
        WmiFilter         = $gpc.gPCWQLFilter
        MachineCSEs       = $gpc.gPCMachineExtensionNames
        UserCSEs          = $gpc.gPCUserExtensionNames
    }
} | Format-Table -Auto

# 2. All GPO links (gPLink) in the domain tree
Get-ADObject -Filter '(objectClass -eq "organizationalUnit") -or (objectClass -eq "domainDNS")' `
             -Properties gPLink, gPOptions, distinguishedName |
  Where-Object { $_.gPLink } |
  ForEach-Object {
    # Parse gPLink: [LDAP://<DN>;<Options>][LDAP://<DN2>;<Options2>]
    $links = [regex]::Matches($_.gPLink, '\[LDAP://([^;]+);(\d+)\]')
    foreach ($l in $links) {
      [PSCustomObject]@{
        ContainerDN = $_.distinguishedName
        GPODN       = $l.Groups[1].Value
        Options     = [int]$l.Groups[2].Value
        Disabled    = [bool]([int]$l.Groups[2].Value -band 1)
        Enforced    = [bool]([int]$l.Groups[2].Value -band 2)
      }
    }
  }
```

## Python ldap3 — read GPC object

```python
from ldap3 import Server, Connection, ALL
import re

server = Server('dc01.corp.example.com', get_info=ALL)
conn = Connection(server, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

# Read the Default Domain Policy GPC
gpc_dn = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=example,DC=com"
conn.search(gpc_dn, '(objectClass=groupPolicyContainer)',
            attributes=['displayName', 'gPCFileSysPath',
                        'gPCMachineExtensionNames', 'gPCUserExtensionNames',
                        'versionNumber', 'gPCWQLFilter'])

e = conn.entries[0]
ver = int(e.versionNumber.value)
print(f"DisplayName  : {e.displayName.value}")
print(f"GPT UNC      : {e.gPCFileSysPath.value}")
print(f"Machine ver  : {ver & 0xFFFFFFFF}")
print(f"User ver     : {ver >> 32}")

# Parse gPCMachineExtensionNames — list of CSE GUIDs
ext_str = e.gPCMachineExtensionNames.value
pairs = re.findall(r'\{([0-9A-Fa-f-]{36})\}\{([0-9A-Fa-f-]{36})\}', ext_str)
for cse_guid, snapin_guid in pairs:
    print(f"  CSE={cse_guid}  SnapIn={snapin_guid}")
```

## Registry / attribute table

### Group Policy client registry

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy
  ├── History                         (subkeys per CSE per GPO, version tracking)
  ├── State\S-1-5-21-...\Machine      (last-applied machine policy)
  └── State\S-1-5-21-...\User         (last-applied user policy)

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Reporting
  └── (report cache)

HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
  ├── SlowLink                        (REG_DWORD) = 500 (kbps threshold for slow link)
  ├── SlowLinkDetectEnabled           (REG_DWORD) = 1
  ├── GPRefreshDisable                (REG_DWORD) = 0
  ├── GPRefreshRate                   (REG_DWORD) = 90  (background refresh, minutes)
  ├── GPRefreshRateRand               (REG_DWORD) = 30  (jitter, minutes)
  └── NoBackgroundPolicy              (REG_DWORD) = 0   (1 = disable background refresh)

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{GUID}
  ├── DllName                         (REG_EXPAND_SZ) = %SystemRoot%\system32\userenv.dll
  └── (CSE-specific flags)
```

### GPC attribute reference

(See `groupPolicyContainer` class table above.)

## Troubleshooting

- **GPO not applying** — Check `gpresult /h report.html` on the target. Look for "Denied (Security)" (ACL) or "Denied (WMI Filter)" or "Disabled" (link). For machine policy, run `gpresult /h report.html /scope computer` as admin.
- **GPC version != GPT version** — Sysvol replication lag. `gpupdate /force` will re-read both and pick the higher. Check DFS-R health: `dfsrdiag replstate` and `dfsrdiag backlog`.
- **CSE not invoked** — The CSE GUID is missing from `gPCMachineExtensionNames` / `gPCUserExtensionNames`. Manually re-add in GPMC, or check `Get-GPO -Name X | Select Extensions`.
- **GPO present in AD but missing from SYSVOL** — SYSVOL replication failed (FRS to DFS-R migration residue). Run `dfsrdiag pollad` and verify `CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalConfig,...`.
- **`gpsvc` fails to start** — Event 1053 (GroupPolicy). Usually caused by network connectivity to DC, DNS resolution, or broken `WinRM` dependencies. Run `nltest /sc_query:corp` to verify secure channel.
- **User policy not applying for non-admin user** — `gpsvc` runs as LocalSystem; it needs to read the user's profile (`ntuser.pol`). Verify the user has READ on the GPO and the GPO is linked to a parent of the user's OU.

## Cross-platform equivalents

- **Linux — SSSD GPO access control**: SSSD's `ad_gpo_access` module reads GPOs and enforces simple GPO security-filtering for login control. See `../09-linux-equivalents/03-sssd-gpo-access.md` and `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — Samba `samba-gpupdate`**: applies GPOs on Linux VDI images (machine-side Registry.pol equivalent via `/etc/krb5.conf` etc.). See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux — FreeIPA `ipa-pwpolicy` + HBAC**: equivalent capability for password policy and login access control. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **macOS — Jamf Connect / MDM**: GPO equivalent is configuration profiles (`.mobileconfig`). AD-bound Macs use `gpupdate` via the AD plugin. See `../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md` (fallback `../08-macos-equivalents/03-jamf-connect-pro.md`).
- **Comparison matrix**: see `../10-comparison-matrices/05-gpo-equivalents-matrix.md`.

## References

- MS-GPOL §3.1 — Group Policy Protocol Overview. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol>
- MS-GPOD — Group Policy: Directory Access. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpod>
- MS-GPSI — Group Policy: Security Extension. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpsi>
- MS-GPFR — Group Policy: Folder Redirection. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpfr>
- Group Policy Team Blog — "Inside the Group Policy Client Service." <https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/>
- Samba `source4/torture/gpo/` — GP test suite.
- `gpsvc.dll` source path referenced in Windows SDK `policy.h` (`ProcessGroupPolicy` prototype).
