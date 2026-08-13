---
title: GPT and GPC Structure — GPT.INI, Registry.pol PReg Format, Preferences XML, gPCMachineExtensionNames Encoding
audience: senior-engineers
tags: [gpt, gpc, gptini, registrypol, preg, preferences-xml, group-policy-container]
related:
  - ./01-gpo-architecture.md
  - ./02-gpo-processing-order.md
  - ./03-admx-templates.md
  - ./04-cse-client-side-extensions.md
last_updated: 2026-08-13
---

The Group Policy Template (GPT) on SYSVOL is structured as `GPT.INI` (version marker) plus `Machine\` and `User\` subtrees containing `Registry.pol` — a binary PReg file with a `PReg\0` signature followed by UTF-16LE `[key;value;type;size;data;]` records decoded by `gpsvc.dll!ProcessRegistryPolicy` — alongside `SecEdit\GptTmpl.inf` for the Security CSE, `Scripts\` INI files for the Scripts CSE, and `Preferences\` XML files (`Registry.xml`, `Files.xml`, `Services.xml`, `ScheduledTasks.xml`, `Printers.xml`, `Drives.xml`, `Folders.xml`, `Environment.xml`, `IniFiles.xml`, `Shortcuts.xml`, `InternetSettings.xml`) consumed by `gppref.dll` — all mirrored against the GPC object's `gPCMachineExtensionNames` string format `[{CSE-GUID}{SnapIn-GUID}]...` that tells `gpsvc` which CSEs to invoke.

## GPT folder structure

```
\\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\
  ├── GPT.INI                            (version + display info)
  ├── Machine\
  │    ├── Registry.pol                  (binary PReg file — see below)
  │    ├── Scripts\
  │    │    ├── scripts.ini              (Startup/Shutdown .cmd/.bat/.exe)
  │    │    ├── psscripts.ini            (Startup/Shutdown .ps1)
  │    │    ├── Shutdown\<script>.cmd    (script files referenced in INI)
  │    │    └── Startup\<script>.cmd
  │    ├── Microsoft\
  │    │    └── Windows NT\
  │    │         ├── SecEdit\
  │    │         │    └── GptTmpl.inf     (Security CSE — INF format)
  │    │         ├── EFS\
  │    │         │    └── <cert>.cer      (EFS recovery certs)
  │    │         └── Audit\
  │    │              └── Audit.csv       (Advanced audit policy — AuditPol CSE)
  │    ├── AppLocker\
  │    │    └── AppLocker.xml             (AppLocker rules)
  │    ├── Applications\                   (Software Installation — .aas/.msi packages)
  │    └── Preferences\
  │         ├── Registry\Registry.xml
  │         ├── Files\Files.xml
  │         ├── Folders\Folders.xml
  │         ├── IniFiles\IniFiles.xml
  │         ├── Drives\Drives.xml
  │         ├── Environment\Environment.xml
  │         ├── LocalUsersAndGroups\LocalUsersAndGroups.xml
  │         ├── NetworkOptions\NetworkOptions.xml
  │         ├── PowerOptions\PowerOptions.xml
  │         ├── Printers\Printers.xml
  │         ├── ScheduledTasks\ScheduledTasks.xml
  │         ├── Services\Services.xml
  │         ├── Shortcuts\Shortcuts.xml
  │         └── InternetSettings\InternetSettings.xml
  └── User\
       ├── Registry.pol
       ├── Scripts\...                    (Logon/Logoff scripts — mirror of Machine\Scripts)
       └── Preferences\...                (mirror of Machine\Preferences for user-side)
```

## GPT.INI file

INI format, must be readable by SMB clients. Required entries:

```ini
[General]
Version=9007471                  (REG_DWORD; combined machine+user version, MUST match GPC versionNumber)
DisplayName={31B2F340-016D-11D2-945F-00C04FB984F9}   (the GPO GUID)

[GPC]                            (optional, for legacy GPMC versions)
ExtensionNames={35378EAC-683F-11D2-A89A-00C04FBBCFA2}    (subset of extension GUIDs)
```

`Version` packing matches `GPC.versionNumber`:

```
Version = (userVersion << 32) | (machineVersion & 0xFFFFFFFF)
```

`gpsvc.dll` reads `GPT.INI` at every refresh, compares `Version` against the cached `versionNumber` from the GPC, and if they disagree, falls back to the GPC value and re-reads the GPT files. They should always match — the GPMC writes them together; mismatch is a sign of partial-write failure or SYSVOL replication lag.

## Registry.pol — PReg file format

Binary format with a 6-byte signature `PReg\0` (literal bytes: `0x50 0x52 0x65 0x67 0x00 0x00`) followed by UTF-16LE-encoded records. Each record:

```
[key;value;type;size;data;]
```

Field-by-field (semicolon-delimited, square-bracket-wrapped, UTF-16LE per character including the delimiters):

| Field    | Encoding             | Meaning                                                            |
|----------|----------------------|--------------------------------------------------------------------|
| `key`    | UTF-16LE string      | Registry key path (e.g. `Software\Policies\Contoso\App`).          |
| `value`  | UTF-16LE string      | Registry value name (e.g. `Enabled`). Empty for default value.     |
| `type`   | decimal, ASCII digits| Registry value type: 1=SZ, 2=EXPAND_SZ, 3=BINARY, 4=DWORD, 7=MULTI_SZ. |
| `size`   | decimal, ASCII digits| Byte length of `data` (NOT character count).                       |
| `data`   | Hex-encoded ASCII string | `data` is rendered as ASCII hex chars (`0`-`9`, `a`-`f`, `A`-`F`). Bytes are little-endian for DWORD. |

Example — encoded `[Software\Policies\Contoso\App;Enabled;4;4;01000000;]`:

```
Bytes:
50 00 52 00 65 00 67 00 00 00            "PReg\0"
5B 00 53 00 6F 00 66 00 74 00 77 00 ...  "[Software\Policies\Contoso\App;"
45 00 6E 00 61 00 62 00 6C 00 65 00 64 00 "Enabled"
3B 00                                     ";"
34 00 3B 00 34 00 3B 00                  "4;4;"
30 00 31 00 30 00 30 00 30 00 30 00 30 00 30 00  "01000000"
3B 00 5D 00                              ";]"
```

For REG_SZ, the data is the UTF-16LE byte sequence hex-encoded. For REG_MULTI_SZ, multiple null-terminated UTF-16LE strings concatenated with double-null terminator. For REG_BINARY, raw bytes hex-encoded.

The Registry CSE (`userenv.dll!ProcessRegistryPolicy`) calls `PReg_ReadFile` (exported by `userenv.dll`) which:

1. Verifies the `PReg\0` signature.
2. Reads the entire file as UTF-16LE into a buffer.
3. Iterates, splitting on `[` and `;` delimiters.
4. For each record, writes to the registry via `RegCreateKeyExW` / `RegSetValueExW` under `HKLM\Software\...` (machine) or `HKU\<SID>\Software\...` (user).

### Python decoder

```python
import struct

def parse_preg(path):
    with open(path, 'rb') as f:
        raw = f.read()
    sig = raw[:6]
    assert sig == b'PReg\x00\x00', f"Bad signature: {sig!r}"
    body = raw[6:].decode('utf-16-le')
    records = []
    for record_str in body.split(']'):
        record_str = record_str.strip().lstrip('[')
        if not record_str:
            continue
        parts = record_str.split(';')
        if len(parts) < 5:
            continue
        key, value, rtype, size, data_hex = parts[0], parts[1], int(parts[2]), int(parts[3]), parts[4]
        data = bytes.fromhex(data_hex)
        # Decode based on type
        if rtype == 1:    # REG_SZ
            decoded = data.decode('utf-16-le').rstrip('\x00')
        elif rtype == 4:  # REG_DWORD
            decoded = struct.unpack('<I', data)[0]
        elif rtype == 7:  # REG_MULTI_SZ
            decoded = [s for s in data.decode('utf-16-le').split('\x00') if s]
        elif rtype == 2:  # REG_EXPAND_SZ
            decoded = data.decode('utf-16-le').rstrip('\x00')
        else:
            decoded = data
        records.append({'key': key, 'value': value, 'type': rtype,
                        'size': size, 'data': decoded})
    return records

# Usage:
recs = parse_preg(r'\\corp.example.com\SYSVOL\corp.example.com\Policies\{GUID}\Machine\Registry.pol')
for r in recs:
    print(f"[{r['key']}\\{r['value']}] type={r['type']} value={r['data']}")
```

### PowerShell decoder

```powershell
function Read-RegistryPol {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $sig   = [System.Text.Encoding]::ASCII.GetString($bytes[0..4])
    if ($sig -ne "PReg") { throw "Not a PReg file" }
    $text  = [System.Text.Encoding]::Unicode.GetString($bytes, 6, $bytes.Length - 6)
    $records = $text -split '\[' | Where-Object { $_ -match '^[^;]+;' }
    foreach ($r in $records) {
        $r = $r.TrimEnd(']')
        $parts = $r -split ';'
        if ($parts.Count -ge 5) {
            $key  = $parts[0]
            $val  = $parts[1]
            $type = [int]$parts[2]
            $size = [int]$parts[3]
            $data = $parts[4]
            [PSCustomObject]@{
                Key   = $key
                Value = $val
                Type  = $type
                Size  = $size
                Data  = $data   # hex string; decode based on $type
            }
        }
    }
}

Read-RegistryPol "\\corp.example.com\SYSVOL\corp.example.com\Policies\{GUID}\Machine\Registry.pol"
```

## GptTmpl.inf — Security CSE file

INF format, ANSI encoding (NOT UTF-16 despite being under the GPT). Read by `scecli.dll!SceSetupSecurityByINF`. Sections:

```ini
[Unicode]
Unicode=yes
[System Access]            ; password and lockout policy
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 8
PasswordComplexity = 1     ; 0 = disabled, 1 = require complex
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
[Event Audit]              ; basic audit categories
AuditLogonEvents = 3       ; 0 = none, 1 = success, 2 = failure, 3 = both
AuditObjectAccess = 2
AuditPrivilegeUse = 0
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 0
AuditDSAccess = 2
AuditAccountLogon = 3
[Registry Values]          ; arbitrary registry settings (REG_DWORD = 4, REG_SZ = 1, REG_MULTI_SZ = 7)
MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning = 4,14
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature = 4,1
[Registry ACLs]            ; registry key ACLs (SDDL)
MACHINE\Software\Contoso,2,"D:P(A;CI;RP;;;AU)"
[File Security]            ; file system ACLs
"%SystemRoot%\system32\drivers\etc\hosts",2,"D:P(A;CI;RP;;;AU)"
[Privilege Rights]         ; user rights assignment
SeSecurityPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-20
SeShutdownPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
[Group Membership]         ; local group membership
*Administrators = *S-1-5-32-544,corp\domain-admins
[Service General Setting]  ; service start mode and ACL
MACHINE\System\CurrentControlSet\Services\WinDefend,4,"D:P(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)"
[Version]
signature="$CHICAGO$"
Revision=1
```

Format constants in `[Registry Values]`: `1` = REG_SZ, `3` = REG_BINARY, `4` = REG_DWORD, `7` = REG_MULTI_SZ.

The SDDL strings in `[Registry ACLs]` and `[File Security]` follow the Security Descriptor Definition Language (MS-DTYP §2.5.1).

## Preferences XML — schema overview

Each Preferences XML file has a root element `<Collections>` or `<Shares>` (area-specific). One `<Collection>` per "action group." Per-item actions (`<File>`, `<Folder>`, `<Service>`, etc.) carry an `action` attribute (`C`=Create, `U`=Update, `R`=Replace, `D`=Delete).

Example — `Preferences\Registry\Registry.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Collection clsid="{A3CCF763-4447-4a24-BD24-0F8B6A5D4E8D}"
            name="Contoso Registry Settings">
  <Registry clsid="{9CD4B2F4-923B-4656-A47A-9A3559ACEEC9}"
            name="SetThreshold"
            status="Sets the Contoso application threshold"
            changed="2026-08-13 10:00:00"
            uid="{GUID}"
            userContext="0"
            removePolicy="0">
    <Properties action="U"
                displayDecimal="0"
                default="0"
                hive="HKEY_LOCAL_MACHINE"
                key="SOFTWARE\Contoso\App"
                name="Threshold"
                type="REG_DWORD"
                value="100"/>
  </Registry>
</Collection>
```

`action` attribute values: `C` (Create), `U` (Update), `R` (Replace), `D` (Delete). The CSE (`gppref.dll`) processes them in document order.

### Preferences areas and file names

| Area                  | File                                           | Root element     | Item element     |
|-----------------------|------------------------------------------------|------------------|------------------|
| Drive Maps           | `Preferences\Drives\Drives.xml`                | `<DrivesCls>`    | `<Drive>`        |
| Environment Variables| `Preferences\Environment\Environment.xml`      | `<Environment>`  | `<EnvironmentVariable>` |
| Files                | `Preferences\Files\Files.xml`                  | `<Files>`        | `<File>`         |
| Folders              | `Preferences\Folders\Folders.xml`              | `<Folders>`      | `<Folder>`       |
| Ini Files            | `Preferences\IniFiles\IniFiles.xml`            | `<IniFiles>`     | `<IniFile>`      |
| Internet Settings    | `Preferences\InternetSettings\InternetSettings.xml`| `<InternetSettings>` | `<InternetSettings>` |
| Local Users & Groups | `Preferences\LocalUsersAndGroups\LocalUsersAndGroups.xml`| `<LocalUsersGroups>` | `<User>` or `<Group>` |
| Network Options      | `Preferences\NetworkOptions\NetworkOptions.xml`| `<DUN>`          | `<DUN>`          |
| Power Options        | `Preferences\PowerOptions\PowerOptions.xml`    | `<PowerOptions>` | `<PowerScheme>`  |
| Printers             | `Preferences\Printers\Printers.xml`            | `<Printers>`     | `<Printer>`      |
| Registry (Prefs)     | `Preferences\Registry\Registry.xml`            | `<Collection>`   | `<Registry>`     |
| Scheduled Tasks      | `Preferences\ScheduledTasks\ScheduledTasks.xml`| `<ScheduledTasks>`| `<TaskV2>`      |
| Services             | `Preferences\Services\Services.xml`            | `<NTServices>`   | `<NTService>`    |
| Shortcuts            | `Preferences\Shortcuts\Shortcuts.xml`          | `<Shortcuts>`    | `<Shortcut>`     |

XML schema files (`.xsd`) ship in `%ProgramFiles%\Microsoft Group Policy\PolicyDefinitions\` and document each Preferences area's schema.

### CSE linkage — `gPCMachineExtensionNames` / `gPCUserExtensionNames`

Format:

```
[{<CSE-GUID>}{<SnapIn-GUID>}][{<CSE-GUID2>}{<SnapIn-GUID2>}]...
```

Each bracket pair is one CSE invocation. The first GUID (`{<CSE-GUID>}`) identifies the CSE — the same GUID appears in `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{<CSE-GUID>}`. The second GUID (`{<SnapIn-GUID>}`) identifies the MMC snap-in extension that authors settings for this CSE (so GPMC knows which UI tab to render).

Example — Default Domain Policy `gPCMachineExtensionNames`:

```
[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]
[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
[{42B5FAAE-6536-11D1-AE59-0000FED75982}{40B66650-4972-11D1-A7CA-0000F87571E53}]
```

Decoded:

| CSE GUID                                            | SnapIn GUID                                  | CSE                     | SnapIn                    |
|-----------------------------------------------------|----------------------------------------------|-------------------------|---------------------------|
| `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`            | `{D02B1F72-3407-48AE-BA88-E8213C6761F1}`     | Registry                | Environment Variables     |
| `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`            | `{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}`     | Security                | Security Settings         |
| `{42B5FAAE-6536-11D1-AE59-0000FED75982}`            | `{40B66650-4972-11D1-A7CA-0000F87571E53}`    | Scripts                 | Scripts                   |

When the GPMC saves an edit to a GPO, it updates `gPCMachineExtensionNames` to reflect which CSEs have content. If an admin manually creates a `Registry.pol` file in the GPT but forgets to add the Registry CSE GUID to `gPCMachineExtensionNames`, `gpsvc` will not invoke the Registry CSE for that GPO and the settings will silently fail to apply.

### Decoding example

```python
import re

ext_str = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"

pairs = re.findall(r'\{([0-9A-Fa-f-]{36})\}\{([0-9A-Fa-f-]{36})\}', ext_str)
for cse, snapin in pairs:
    print(f"CSE={cse}  SnapIn={snapin}")
```

## Diagnostic — `gpresult` / LDAP filter

Verify GPT and GPC consistency:

```cmd
:: On the client:
gpresult /h report.html
:: In the report:
::   - Check "Applied Group Policy Objects" list
::   - For each GPO, look for "Last Applied" timestamp and "Version" (GPC and GPT must match)
```

LDAP filter — find GPOs whose `gPCMachineExtensionNames` includes the Registry CSE:

```ldap
(&(objectClass=groupPolicyContainer)(gPCMachineExtensionNames=*35378EAC-683F-11D2-A89A-00C04FBBCFA2*))
```

LDAP filter — find GPOs WITHOUT any CSE extensions (likely broken):

```ldap
(&(objectClass=groupPolicyContainer)(!(gPCMachineExtensionNames=*)))
```

## Wireshark display filter

SMB read of `GPT.INI`:

```
smb2.cmd == 5 && smb2.filename contains "\\GPT.INI"
```

SMB read of `Registry.pol`:

```
smb2.filename contains "\\Machine\\Registry.pol" || smb2.filename contains "\\User\\Registry.pol"
```

SMB read of Preferences XML:

```
smb2.filename contains "\\Preferences\\" && (smb2.filename contains ".xml")
```

## PowerShell — enumerate GPC/GPT consistency

```powershell
Import-Module GroupPolicy

# 1. For each GPO, verify GPC.versionNumber == GPT.INI Version
Get-GPO -All | ForEach-Object {
    $gpc = Get-ADObject -Identity "CN=$($_.Id),CN=Policies,CN=System,DC=corp,DC=example,DC=com" `
                        -Properties versionNumber, gPCFileSysPath
    $gptIni = Join-Path $gpc.gPCFileSysPath "GPT.INI"
    if (Test-Path $gptIni) {
        $gpt = Get-Content $gptIni | Where-Object { $_ -match "^Version=" }
        $gptVer = [int64]($gpt -replace "Version=", "")
        $gpcVer = [int64]$gpc.versionNumber
        [PSCustomObject]@{
            GPO        = $_.DisplayName
            GPCVersion = $gpcVer
            GPTVersion = $gptVer
            Match      = ($gpcVer -eq $gptVer)
        }
    } else {
        [PSCustomObject]@{
            GPO        = $_.DisplayName
            GPCVersion = $gpc.versionNumber
            GPTVersion = "MISSING GPT.INI"
            Match      = $false
        }
    }
} | Format-Table -Auto

# 2. Decode gPCMachineExtensionNames and list CSEs
$cseNames = @{
    '35378eac-683f-11d2-a89a-00c04fbbcfa2' = 'Registry'
    '827d319e-6eac-11d2-a4ea-00c04f79f83a' = 'Security'
    '42b5faae-6536-11d1-ae59-0000fed75982' = 'Scripts'
    '426031c0-0b47-4852-b0ca-ac3d37bfcb39' = 'Folder Redirection'
    '16be69fa-4209-4250-9b8c-6539af50c92b' = 'AppLocker'
}

Get-GPO -All | ForEach-Object {
    $gpc = Get-ADObject -Identity "CN=$($_.Id),CN=Policies,CN=System,DC=corp,DC=example,DC=com" `
                        -Properties gPCMachineExtensionNames
    $cses = [regex]::Matches($gpc.gPCMachineExtensionNames, '\{([0-9A-Fa-f-]{36})\}\{([0-9A-Fa-f-]{36})\}')
    foreach ($m in $cses) {
        $cse   = $m.Groups[1].Value.ToLower()
        $snap  = $m.Groups[2].Value
        [PSCustomObject]@{
            GPO   = $_.DisplayName
            CSE   = $cseNames[$cse]
            GUID  = $m.Groups[1].Value
            SnapIn = $snap
        }
    }
} | Format-Table -Auto

# 3. Decode Registry.pol from a GPO
function Read-PReg {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ([System.Text.Encoding]::ASCII.GetString($bytes[0..3]) -ne "PReg") { return }
    $text = [System.Text.Encoding]::Unicode.GetString($bytes, 6, $bytes.Length - 6)
    foreach ($rec in ($text -split '\[' | Where-Object { $_ -match '^[^;]+;' })) {
        $parts = $rec.TrimEnd(']') -split ';'
        if ($parts.Count -ge 5) {
            [PSCustomObject]@{
                Key   = $parts[0]
                Value = $parts[1]
                Type  = [int]$parts[2]
                Size  = [int]$parts[3]
                Data  = $parts[4]
            }
        }
    }
}

Read-PReg "\\corp.example.com\SYSVOL\corp.example.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Registry.pol"
```

## Registry / attribute table

### GPC object attributes (recap)

| Attribute                       | OID                              | Purpose                                            |
|---------------------------------|----------------------------------|----------------------------------------------------|
| `cn`                            | 2.5.4.3                          | GPO GUID RDN.                                      |
| `displayName`                   | 1.2.840.113556.1.4.1352          | Friendly name.                                     |
| `gPCFileSysPath`                | 1.2.840.113556.1.4.1357          | UNC to GPT.                                        |
| `gPCMachineExtensionNames`      | 1.2.840.113556.1.4.1360          | `[{CSE}{SnapIn}]` pairs for machine.              |
| `gPCUserExtensionNames`         | 1.2.840.113556.1.4.1359          | Same for user.                                     |
| `versionNumber`                 | 1.2.840.113556.1.4.1340          | Combined machine+user version.                    |
| `gPCWQLFilter`                  | 1.2.840.113556.1.4.1388          | WMI filter LDAP URL.                               |
| `gPCFunctionalityVersion`       | 1.2.840.113556.1.4.1351          | ADMX schema version.                               |

### GPT.INI entries

| Entry           | Section     | Purpose                                                       |
|-----------------|-------------|---------------------------------------------------------------|
| `Version`       | `[General]` | Combined version (must match GPC `versionNumber`).            |
| `DisplayName`   | `[General]` | GPO GUID (optional).                                          |
| `ExtensionNames`| `[GPC]`     | Optional extension list (legacy).                             |

### Registry.pol record fields

| Field   | Encoding                | Meaning                            |
|---------|-------------------------|------------------------------------|
| `key`   | UTF-16LE string         | Registry key path.                 |
| `value` | UTF-16LE string         | Value name (empty for default).    |
| `type`  | decimal ASCII digits    | REG_SZ=1, EXPAND_SZ=2, BINARY=3, DWORD=4, MULTI_SZ=7. |
| `size`  | decimal ASCII digits    | Byte length of decoded `data`.     |
| `data`  | hex-encoded ASCII       | Raw bytes (hex).                   |

## Troubleshooting

- **GPT.INI `Version` != GPC `versionNumber`** — SYSVOL replication lag (FRS or DFS-R). Force sync: `dfsrdiag pollad`, then `gpupdate /force` on a client. `gpsvc` will pick the higher value.
- **`Registry.pol` not applying** — Verify PReg signature `PReg\0`. Corrupt file → CSE logs error in event log (Event 1090). Recreate via GPMC.
- **Security settings reverting** — `GptTmpl.inf` applies at boot but is overwritten by user action between refreshes. Set `NoGPOListChanges = 1` for the Security CSE if you want one-shot application.
- **Preferences XML syntax error** — `gppref.dll` fails to parse; logs `Event 4098 Group Policy Files` ("The client-side extension could not parse the XML..."). Validate XML via `xmllint` or VS Code XML extension. Common cause: unescaped `&` in UNC paths (`\\server\share\Q&A\file`).
- **GPO linked but no CSE invoked** — `gPCMachineExtensionNames` doesn't list the required CSE GUID. Re-edit and save in GPMC to fix.
- **Empty `Registry.pol` (just `PReg\0`)** — Normal for newly created GPOs with no settings configured. CSE skips application.
- **AppLocker XML missing** — AppLocker rules not configured in the GPO. Open GPMC → Computer Config → Policies → Windows Settings → Security Settings → Application Control Policies → AppLocker, then add rules.
- **Slow SYSVOL reads** — Each Preferences area = one XML file read = one SMB round trip. Many GPOs × many Preferences areas = high SMB chattiness on slow WANs. Use DFS-R replication health check (`dfsrdiag replstate`) and pre-stage files.
- **Character encoding issues in GptTmpl.inf** — Must be ANSI (CP1252) NOT UTF-16. Editing with Notepad and saving as "Unicode" breaks `scecli.dll` parsing.

## Cross-platform equivalents

- **Linux — SSSD `ad_gpo_access`**: parses GPO Security extension only; no Registry.pol, no Preferences XML. See `../09-linux-equivalents/03-sssd-gpo-access.md` and `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — Samba `samba-gpupdate`**: reads `Registry.pol` from SYSVOL via SMB and translates a fixed set of known policy keys to Linux config files (`/etc/krb5.conf`, `/etc/security/limits.conf`, etc.). No Preferences XML support. See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux — FreeIPA**: no GPT/GPC concept. Policies are LDAP attributes per-area. See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **macOS — Configuration Profiles (`.mobileconfig`)**: equivalent to GPT+GPC combined into a single plist-formatted XML payload. Profiles are pushed via MDM, not via SYSVOL/SMB. See `../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md` (fallback `../08-macos-equivalents/03-jamf-connect-pro.md`).
- **Comparison matrix**: see `../10-comparison-matrices/05-gpo-equivalents-matrix.md`.

## References

- MS-GPreg §2.2 — `Registry.pol` (PReg) File Format. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpreg>
- MS-GPSI §2.2 — `GptTmpl.inf` Format. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpsi>
- MS-GPPREF — Group Policy Preferences XML schema. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gppref>
- MS-GPOD §3.1.1.4 — `gPCMachineExtensionNames` and `gPCUserExtensionNames` format. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpod>
- "PReg File Format" — Microsoft Open Specifications. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpreg/4e9724d8-57d8-42c4-bf0c-2c1bb6a8a3f5>
- `userenv.dll!PReg_ReadFile` and `ProcessRegistryPolicy` — Windows SDK `userenv.h`.
- `scecli.dll!SceProcessReturnedGPOs` — Windows SDK `scesvc.h`.
