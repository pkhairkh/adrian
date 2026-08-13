---
title: Client-Side Extensions (CSEs) — GUIDs, Registry, ProcessGroupPolicy, Scripts/Registry/Security CSE Internals
audience: senior-engineers
tags: [cse, processgrouppolicy, registry-cse, security-cse, scripts-cse, gpsvc]
related:
  - ./01-gpo-architecture.md
  - ./02-gpo-processing-order.md
  - ./03-admx-templates.md
  - ./05-gpt-gpc-structure.md
last_updated: 2026-08-13
---

A Client-Side Extension (CSE) is a DLL registered under `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<GUID>}` exporting `ProcessGroupPolicy` and `ProcessGroupPolicyEx` entry points, invoked in CSE-list order by `gpsvc.dll` for each applicable GPO — with each CSE GUID appearing in the GPC's `gPCMachineExtensionNames` or `gPCUserExtensionNames` string for the GPO to be processed by that CSE — and the Scripts CSE specifically loading `Scripts.ini` and `psscripts.ini` from the GPT's `Machine\Scripts\` or `User\Scripts\` folder for execution at next boot/logon.

## CSE registry

Each CSE registers under:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<CSE-GUID>}
  ├── (Default)              = <CSE friendly name>      (REG_SZ)
  ├── DllName                = %SystemRoot%\system32\<dll>.dll   (REG_EXPAND_SZ)
  ├── EnableAsynchronousProcessing   = 0/1   (REG_DWORD)
  ├── NoBackgroundProcessing         = 0/1   (REG_DWORD)
  ├── NoGPOListChanges               = 0/1   (REG_DWORD)  -- CSE doesn't need re-run when GPO list unchanged
  ├── NoMachinePolicy                = 0/1   (REG_DWORD)
  ├── NoUserPolicy                   = 0/1   (REG_DWORD)
  ├── PerUserLocalSettings           = 0/1   (REG_DWORD)
  ├── RequiresSuccessfulRegistry     = 0/1   (REG_DWORD)  -- run only if Registry CSE succeeded
  └── ProcessGroupPolicy            = <function name>  (REG_SZ)  -- exported entry point
```

`gpsvc.dll` enumerates these subkeys at service start and loads each `DllName`. When a GPO is processed, `gpsvc` looks up each CSE GUID in the `gPCMachineExtensionNames`/`gPCUserExtensionNames` list, fetches the matching CSE from its in-memory cache, and calls `ProcessGroupPolicy` via `GetProcAddress`.

The CSE entry-point prototype:

```c
typedef UINT (*PFNPROCESSGROUPPOLICY)(
    DWORD dwFlags,                       // PIPL_GPO_INFO_FLAG
    HANDLE hToken,                       // user/computer token
    HKEY hKeyRoot,                       // HKLM or HKU\<user-SID>
    PGROUP_POLICY_OBJECT pDeletedGPOList,// GPOs that have been removed since last refresh
    PGROUP_POLICY_OBJECT pChangedGPOList,// GPOs that have changed
    ULONG nGPOList,                      // count
    PGROUP_POLICY_OBJECT pGPOList,       // all applicable GPOs
    PVOID pLocalRegistrySettings,        // rsop cache
    PFNGENERATEGROUPPOLICY pGenerateGroupPolicy,  // callback for logging
    PVOID pEnvironment                   // additional context
);

typedef UINT (*PFNPROCESSGROUPPOLICYEX)(
    DWORD dwFlags,
    HANDLE hToken,
    HKEY hKeyRoot,
    PGROUP_POLICY_OBJECT pDeletedGPOList,
    PGROUP_POLICY_OBJECT pChangedGPOList,
    ULONG nGPOList,
    PGROUP_POLICY_OBJECT pGPOList,
    PVOID pLocalRegistrySettings,
    PFNGENERATEGROUPPOLICY pGenerateGroupPolicy,
    PVOID pEnvironment,
    PFNSTATUSMESSAGECALLBACK pStatusCallback   // NEW: callback for status messages
);
```

The `GROUP_POLICY_OBJECT` struct (defined in `<userenv.h>`):

```c
typedef struct _GROUP_POLICY_OBJECT {
    DWORD dwOptions;
    DWORD dwVersion;
    LPWSTR lpDSPath;            // LDAP path to GPC
    LPWSTR lpFileSysPath;       // UNC path to GPT
    LPWSTR lpDisplayName;
    LPGUID lpGPOName;           // GPO GUID
    DWORD dwGPOOptions;         // 1=disabled, 2=enforced
    LPWSTR lpExtensions;        // NULL-terminated list of CSE GUIDs (each surrounded by {})
    struct _GROUP_POLICY_OBJECT *pNext;
    struct _GROUP_POLICY_OBJECT *pPrev;
    LPARAM lParam;              // CSE-specific context
    PWCHAR lpLink;              // DN of the container linking the GPO
    LPARAM lParam2;
} GROUP_POLICY_OBJECT, *PGROUP_POLICY_OBJECT;
```

## Major CSEs — GUID table

| CSE GUID                                            | Name                            | DLL                      | Files in GPT consumed                                            |
|-----------------------------------------------------|---------------------------------|--------------------------|------------------------------------------------------------------|
| `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`            | Registry                        | `userenv.dll`            | `Machine\Registry.pol`, `User\Registry.pol`                      |
| `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`            | Security                        | `scecli.dll`             | `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`               |
| `{42B5FAAE-6536-11d1-AE59-0000FED75982}`            | Scripts                         | `gptext.dll`             | `Machine\Scripts\scripts.ini`, `Machine\Scripts\psscripts.ini`, `User\Scripts\scripts.ini`, `User\Scripts\psscripts.ini`, `Machine\Scripts\<Startup\|Shutdown>\*.cmd` |
| `{426031c0-0b47-4852-b0ca-ac3d37bfcb39}`            | Folder Redirection              | `fdeploy.dll`            | `User\Documents & Settings\*.xml` (redirection XML)              |
| `{D02B1F72-3407-48AE-BA88-E8213C6761F1}`            | Group Policy Environment        | `gpsvc.dll`              | (no file; sets environment variables from policy)                |
| `{C631DF4C-088F-4156-B058-4375F4640E84}`            | QoS (Quality of Service)        | `gptext.dll`             | (no file; reads registry policy)                                 |
| `{16be69fa-4209-4250-9b8c-6539af50c92b}`            | AppLocker                       | `appidsvc.dll`           | `Machine\AppLocker\*.xml` (AppLocker rule XMLs)                  |
| `{B087BE9D-ED37-45e5-A8D7-5EB7B0998AA7}`            | Internet Explorer (legacy)      | `iedkcs32.dll`           | `Machine\Microsoft\IEAK\*.ins`, `User\Microsoft\IEAK\*.ins`      |
| `{E47248BA-94CC-45d2-9A41-2D4672C43B16}`            | EFS Recovery                    | `efsadu.dll`             | `Machine\Microsoft\Windows NT\EFS\*.cer`                         |
| `{A3F3E397-3240-4252-9BFA-2744A6C7E8C6}`            | Audit Policy Configuration (Advanced) | `auditpolcore.exe` | `Machine\Microsoft\Windows NT\Audit\Audit.csv`                   |
| `{E437BC1C-AA7F-4c80-B9F1-9D4C0EE1BDDB}`            | Folder Options                  | `gptext.dll`             | (no file; sets folder view policy via registry)                  |
| `{c6dc5466-785a-11d2-84ed-00c04fb1692f}`            | Software Installation           | `appmgmts.dll`           | `Machine\Applications\<package>.aas` (Windows Installer ads)     |
| `{0E28E245-9368-4853-AD84-6DA3BA35BB75}`            | Disk Quota                      | `gptext.dll`             | (no file; sets quota policy via registry)                        |
| `{4CFB60C1-FAA6-47f1-89AA-0B18730C9FD3}`            | Microsoft Surface Hub           | `aceleshook.dll`         | (no file; Surface Hub-specific)                                  |
| `{B587E2B1-4D59-40e7-AD7f-A5C8F6A8E0A2}`            | Enterprise Printers (Preferences)| `gppref.dll`           | `User\Preferences\Printers\Printers.xml`                         |
| `{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}`            | Deployed Printers (Print Mgmt) | `printmanagement.msc`     | `Machine\DeployedPrinters\*.xml`                                 |

### Group Policy Preferences CSEs (separate set)

These CSEs are all hosted in `gppref.dll` and consume XML files from `Machine\Preferences\<...>` or `User\Preferences\<...>`:

| CSE GUID                                            | Area                  | XML file                                           |
|-----------------------------------------------------|-----------------------|----------------------------------------------------|
| `{F9C8B683-6E85-4e7b-AE55-E62B08F2DB60}`            | Applications          | `Applications.xml`                                 |
| `{0ACDD40C-75AC-47ab-BAA0-BF6DE7E7FE63}`            | Drive Maps           | `Drives\Drives.xml`                                |
| `{9426A8C6-E3B5-4d24-A3AA-1E0E0B5F82AE}`            | Environment Variables| `Environment\Environment.xml`                      |
| `{4C03C6E6-C5D0-4a96-9777-A85B87E0A2DA}`            | Files                | `Files\Files.xml`                                  |
| `{79F6A7F6-A60F-4e0d-A3C5-CD7F8AB1E69D}`            | Folders              | `Folders\Folders.xml`                              |
| `{62BE2208-7919-4e74-8F47-3C0F2B5D32F4}`            | Ini Files            | `IniFiles\IniFiles.xml`                            |
| `{4C03C6E6-C5D0-4a96-9777-A85B87E0A2DA}`            | Internet Settings    | `InternetSettings\InternetSettings.xml`            |
| `{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}`            | Local Users and Groups| `LocalUsersAndGroups\LocalUsersAndGroups.xml`     |
| `{0E28E245-9368-4853-AD84-6DA3BA35BB75}`            | Network Options      | `NetworkOptions\NetworkOptions.xml`                |
| `{0F1CE84F-9E6C-4cbf-8FBC-83C13E66D1C3}`            | Power Options        | `PowerOptions\PowerOptions.xml`                    |
| `{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}`            | Printers             | `Printers\Printers.xml`                            |
| `{2BD6E3E7-0F31-46d6-8F53-EE6DDB6F3A8A}`            | Registry (Preferences)| `Registry\Registry.xml`                           |
| `{BFC9EC5F-9AD4-4c4c-9F47-9B82F59F0D9F}`            | Scheduled Tasks      | `ScheduledTasks\ScheduledTasks.xml`                |
| `{D02B1F73-3407-48AE-BA88-E8213C6761F1}`            | Services             | `Services\Services.xml`                            |
| `{30579F96-7AD3-4e0e-9F6F-1E5F0F5F0F5F}`            | Shortcuts            | `Shortcuts\Shortcuts.xml`                          |

## Registry CSE — `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`

The most-used CSE. Reads `Machine\Registry.pol` or `User\Registry.pol` from the GPT, parses the PReg format (see `./05-gpt-gpc-structure.md`), and writes the values to the registry under `HKLM\Software\Policies\` or `HKCU\Software\Policies\` (or `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\` for legacy).

Implementation: `userenv.dll!ProcessRegistryPolicy`. The CSE is one of the few that:

- Runs synchronously.
- Runs in background refresh.
- Runs at every boot (machine) and every logon (user) regardless of version change (because some registry values can be deleted by the user).

Per-policy refresh state stored under:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\<GPO-GUID>\
  ├── Version       (REG_DWORD)   (last-applied version of the GPO)
  ├── FileSysPath   (REG_SZ)
  ├── DisplayName   (REG_SZ)
  └── GPO DN        (REG_SZ)
```

## Security CSE — `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`

Reads `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` from the GPT — an INF-format file containing security settings:

```ini
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 8
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
[Event Audit]
AuditSystemEvents = 0
AuditLogonEvents = 3
AuditObjectAccess = 2
AuditPrivilegeUse = 0
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 0
AuditDSAccess = 2
AuditAccountLogon = 3
[Registry Values]
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning = 4,14
[Privilege Rights]
SeSecurityPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-20
[Version]
signature="$CHICAGO$"
Revision=1
```

Implementation: `scecli.dll!SceProcessReturnedGPOs`. The CSE applies the settings via `LsaQueryInformationPolicy` (for password policy), `SceSetSecurityPolicyInfo` (for registry and audit), and `LsaCreateAccount` (for user rights).

Audit policy on Server 2008+ uses Advanced Audit Policy (`/enable:Advanced_Audit`), stored as `Machine\Microsoft\Windows NT\Audit\Audit.csv`. CSE GUID `{A3F3E397-3240-4252-9BFA-2744A6C7E8C6}` (`auditpolcore.exe`).

## Scripts CSE — `{42B5FAAE-6536-11D1-AE59-0000FED75982}`

Reads:

- `Machine\Scripts\scripts.ini` — Startup/Shutdown scripts (machine)
- `Machine\Scripts\psscripts.ini` — PowerShell Startup/Shutdown scripts (machine)
- `User\Scripts\scripts.ini` — Logon/Logoff scripts (user)
- `User\Scripts\psscripts.ini` — PowerShell Logon/Logoff scripts (user)

INI format (`scripts.ini`):

```ini
[Startup]
0CmdLine=\\corp.example.com\SYSVOL\corp.example.com\scripts\startup.cmd
0Parameters=
1CmdLine=\\corp.example.com\SYSVOL\...install-app.cmd
1Parameters=/silent

[Shutdown]
0CmdLine=%SystemRoot%\system32\shutdown-cleanup.cmd
0Parameters=
```

INI format (`psscripts.ini`):

```ini
[Startup]
0CmdLine=\\corp.example.com\SYSVOL\...\startup.ps1
0Parameters=-ExecutionPolicy Bypass -NoProfile

[Shutdown]
0CmdLine=\\corp.example.com\SYSVOL\...\shutdown.ps1
0Parameters=
```

Scripts are executed synchronously at next boot/logon (not during background refresh). Implementation: `gptext.dll!ProcessScriptsEx`. The CSE builds a `ScriptList` and queues it for the Group Policy Scripts service (`gpsvc.exe` worker) which runs them.

PowerShell script parameters are passed as a single string; `gpsvc` invokes `powershell.exe -ExecutionPolicy Bypass -NoProfile -File <script> <Parameters>`.

Script files are read directly from the GPT at run time — clients do not copy them locally. Slow-link machines can fail to execute scripts if SYSVOL is unreachable.

## Folder Redirection CSE — `{426031c0-0b47-4852-b0ca-ac3d37bfcb39}`

Reads `User\Documents & Settings\FolderRedirection.xml` (or other XML files per-folder). Moves the user's profile folders (Documents, Desktop, Start Menu, etc.) to a UNC path.

DLL: `fdeploy.dll`. Entry point: `ProcessFolderRedirection`. The CSE:

1. Parses the XML.
2. Checks current location of the folder.
3. If different from target and the "Move the contents of <folder> to the new location" option is set, copies the files.
4. Updates `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` to point to the new UNC.
5. Logs the user off (if `Redirect on first logon` policy isn't set) so the change takes effect.

By default, Folder Redirection is NOT applied on slow links. Override via "Configure Folder Redirection policy processing → Process even if GPO has not changed."

## Diagnostic — CSE-specific event log

Per-CSE failures are logged in:

```
Applications and Services Logs \ Microsoft \ Windows \ GroupPolicy \ Operational
  Event 4116   "Group Policy succeeded."  (success, lists applied CSEs)
  Event 5312   "Failed to apply policy and redirect folder <X>."
  Event 7016   "The processing of Group Policy failed. Windows could not evaluate the Windows Management Instrumentation (WMI) filter ..."
  Event 1090   "Windows could not record the resultant set of policy (RSoP) information for Group Policy <CSE>."
  Event 1500   "The Group Policy settings for the computer could not be processed successfully."
  Event 1501   "The Group Policy settings for the user could not be processed successfully."
  Event 1502   "The Group Policy settings for the computer were processed but some components failed."
  Event 1503   "The Group Policy settings for the user were processed but some components failed."
```

## Wireshark display filter

CSE-related file reads from SYSVOL:

```
# Registry.pol reads (Registry CSE):
smb2.filename contains "\\Machine\\Registry.pol" || smb2.filename contains "\\User\\Registry.pol"

# GptTmpl.inf reads (Security CSE):
smb2.filename contains "\\SecEdit\\GptTmpl.inf"

# Scripts.ini reads (Scripts CSE):
smb2.filename contains "scripts.ini"

# AppLocker XML:
smb2.filename contains "\\AppLocker\\"
```

## PowerShell — enumerate registered CSEs

```powershell
# List all CSEs registered on this machine
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\CSEs' |
  ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{
      GUID         = $_.PSChildName
      Name         = $props.'(default)'
      DllName      = $props.DllName
      NoMachinePol = $props.NoMachinePolicy
      NoUserPol    = $props.NoUserPolicy
      NoBgProc     = $props.NoBackgroundProcessing
      AsyncProc    = $props.EnableAsynchronousProcessing
    }
  } | Format-Table -Auto

# List which CSEs are referenced by each GPO
Get-GPO -All | ForEach-Object {
    $gpc = Get-ADObject -Identity "CN=$($_.Id),CN=Policies,CN=System,DC=corp,DC=example,DC=com" `
                        -Properties gPCMachineExtensionNames, gPCUserExtensionNames
    $machineCSEs = [regex]::Matches($gpc.gPCMachineExtensionNames, '\{([0-9A-Fa-f-]{36})\}') |
                   ForEach-Object { $_.Groups[1].Value }
    $userCSEs    = [regex]::Matches($gpc.gPCUserExtensionNames, '\{([0-9A-Fa-f-]{36})\}') |
                   ForEach-Object { $_.Groups[1].Value }
    [PSCustomObject]@{
        GPO          = $_.DisplayName
        MachineCSEs  = $machineCSEs -join ','
        UserCSEs     = $userCSEs -join ','
    }
} | Format-Table -Auto
```

## Python ldap3 — fetch GPC and extract CSE list

```python
from ldap3 import Server, Connection, ALL
import re

server = Server('dc01.corp.example.com', get_info=ALL)
conn = Connection(server, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

cse_names = {
    '35378eac-683f-11d2-a89a-00c04fbbcfa2': 'Registry',
    '827d319e-6eac-11d2-a4ea-00c04f79f83a': 'Security',
    '42b5faae-6536-11d1-ae59-0000fed75982': 'Scripts',
    '426031c0-0b47-4852-b0ca-ac3d37bfcb39': 'Folder Redirection',
    'd02b1f72-3407-48ae-ba88-e8213c6761f1': 'Group Policy Environment',
    'c631df4c-088f-4156-b058-4375f4640e84': 'QoS',
    '16be69fa-4209-4250-9b8c-6539af50c92b': 'AppLocker',
    'b087be9d-ed37-45e5-a8d7-5eb7b0998aa7': 'Internet Explorer (legacy)',
    'e47248ba-94cc-45d2-9a41-2d4672c43b16': 'EFS Recovery',
    'a3f3e397-3240-4252-9bfa-2744a6c7e8c6': 'Audit Policy (Advanced)',
    'e437bc1c-aa7f-4c80-b9f1-9d4c0ee1bddb': 'Folder Options',
    'c6dc5466-785a-11d2-84ed-00c04fb1692f': 'Software Installation',
}

gpc_dn = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=example,DC=com"
conn.search(gpc_dn, '(objectClass=groupPolicyContainer)',
            attributes=['displayName', 'gPCMachineExtensionNames', 'gPCUserExtensionNames'])

e = conn.entries[0]
print(f"GPO: {e.displayName.value}")

for attr_label, attr in [('Machine', 'gPCMachineExtensionNames'),
                         ('User',     'gPCUserExtensionNames')]:
    val = e[attr].value if e[attr] else ''
    cses = re.findall(r'\{([0-9A-Fa-f-]{36})\}', val)
    # Pairs: CSE GUID, snap-in GUID. Take every other.
    for i in range(0, len(cses), 2):
        cse_guid = cses[i].lower()
        snapin   = cses[i+1] if i+1 < len(cses) else ''
        name = cse_names.get(cse_guid, '(unknown)')
        print(f"  [{attr_label}] CSE={cse_guid}  ({name})  SnapIn={snapin}")
```

## Registry / attribute table

### Per-CSE registry (under CSE GUID key)

| Value name                       | Type        | Effect                                                                                          |
|----------------------------------|-------------|------------------------------------------------------------------------------------------------|
| `(Default)`                      | REG_SZ      | CSE friendly name.                                                                              |
| `DllName`                        | REG_EXPAND_SZ | Path to CSE DLL.                                                                              |
| `ProcessGroupPolicy`             | REG_SZ      | Function name (usually `"ProcessGroupPolicy"`).                                                 |
| `EnableAsynchronousProcessing`   | REG_DWORD   | 1 = CSE can return ERROR_PENDING and report completion asynchronously.                          |
| `NoBackgroundProcessing`         | REG_DWORD   | 1 = CSE runs only at boot/logon, not in background refresh.                                     |
| `NoGPOListChanges`               | REG_DWORD   | 1 = CSE skips refresh if the GPO list hasn't changed (no new/removed GPOs).                    |
| `NoMachinePolicy`                | REG_DWORD   | 1 = CSE ignores machine policy.                                                                 |
| `NoUserPolicy`                   | REG_DWORD   | 1 = CSE ignores user policy.                                                                    |
| `PerUserLocalSettings`           | REG_DWORD   | 1 = CSE writes per-user state to `HKU\<SID>\...` instead of `HKLM\...`.                         |
| `RequiresSuccessfulRegistry`     | REG_DWORD   | 1 = CSE skips if Registry CSE failed.                                                           |

### Per-CSE history (per GPO)

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{<CSE-GUID>}\{<GPO-GUID>}\
  ├── DisplayName  (REG_SZ)
  ├── GPO DN       (REG_SZ)         — DN of the GPC object
  ├── FileSysPath  (REG_SZ)         — UNC to GPT
  ├── Version      (REG_DWORD)      — version of this GPO last applied
  ├── Options      (REG_DWORD)      — link options
  ├── User         (REG_SZ)         — SID of the user (or machine SID for computer policy)
  └── Link         (REG_SZ)         — DN of the linking container
```

## Troubleshooting

- **CSE returns error code** — Check Event 1090 in GroupPolicy/Operational log. The error code's HRESULT maps to a specific failure (e.g. 0x80070005 = Access Denied).
- **Registry CSE not writing values** — Check `Registry.pol` exists in the GPT and is well-formed (signature `PReg\0`). Verify GPO version matches `versionNumber`. Test with `gpupdate /force` and `reg query`.
- **Scripts not running at boot** — Check `scripts.ini` exists in `Machine\Scripts\`. Verify `gPCMachineExtensionNames` includes the Scripts CSE GUID `{42B5FAAE-6536-11D1-AE59-0000FED75982}`. Test the script by running it manually as SYSTEM (`psexec -s -i cmd.exe`).
- **Security CSE applies at boot but reverts later** — Local admin changed the setting manually; CSE re-applies on next refresh. To allow local override, set "Apply once and do not re-apply" via `CSE\{827D319E-...}\NoGPOListChanges = 1`.
- **Folder redirection fails for users on slow links** — Override slow-link behavior in "Configure Folder Redirection policy processing" policy (enable "Process even if the Group Policy objects have not changed").
- **AppLocker rules don't apply** — Verify `AppIDSvc` service is running. Check `Machine\AppLocker\*.xml` exists in the GPT. Force refresh: `gpupdate /force`, then `auditpol /get /category:*` to verify.
- **Audit Policy (Advanced) shows "Not Configured"** — Verify `Machine\Microsoft\Windows NT\Audit\Audit.csv` exists in the GPT. If empty, the CSE has nothing to apply. Auditpol must be enabled via "Advanced audit policy configuration" in the GPO.
- **Multiple CSEs with same GUID in `gPCMachineExtensionNames`** — This is normal; pairs are `[CSE][SnapIn]` and a single GPO can have multiple pairs. `gpsvc` de-duplicates by CSE GUID when invoking.

## Cross-platform equivalents

- **Linux — SSSD `ad_gpo_access`**: implements an equivalent of the Security CSE's "Restrict logon" sub-feature. No Registry CSE, Scripts CSE, etc. SSSD reads the GPO ACLs but does not parse `Registry.pol`. See `../09-linux-equivalents/03-sssd-gpo-access.md` and `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — Samba `samba-gpupdate`**: implements a partial Registry CSE equivalent — reads `Registry.pol` from SYSVOL and writes to `/etc/krb5.conf`, `/etc/security/limits.conf`, `/etc/sudoers.d/`, etc. based on a fixed key→file mapping table. See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux — FreeIPA**: no CSE concept; uses native LDAP attributes per-policy-area. See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **macOS — Configuration Profiles**: payloads are equivalent to CSE outputs (each payload type = one "CSE-equivalent" — `com.apple.applicationaccess`, `com.apple.security.FDEFileVault`, etc.). Profiles are not split into separate CSEs — each `.mobileconfig` is a monolithic payload. See `../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md` (fallback `../08-macos-equivalents/03-jamf-connect-pro.md`).
- **Comparison matrix**: see `../10-comparison-matrices/05-gpo-equivalents-matrix.md`.

## References

- MS-GPSI — Group Policy: Security Extension (`{827D319E-...}`). <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpsi>
- MS-GPFR — Group Policy: Folder Redirection (`{426031c0-...}`). <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpfr>
- MS-GPSC — Group Policy: Scripts Extension (`{42B5FAAE-...}`). <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpsc>
- MS-GPRP — Group Policy: Registry Policy Extension (`{35378EAC-...}`). <https://learn.microsoft.com/openspecs/windows_protocols/ms-gprp>
- `<userenv.h>` — `GROUP_POLICY_OBJECT` struct and `PFNPROCESSGROUPPOLICYEX` prototype (Windows SDK).
- `gpsvc.dll` source paths referenced in Windows SDK `gpedit.h`, `userenv.h`.
- Samba `source4/torture/gpo/` for CSE-equivalent tests.
