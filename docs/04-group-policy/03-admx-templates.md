---
title: ADMX vs ADM Templates — Central Store, policyElements, supportedOn, ADML, Registry Value Types
audience: senior-engineers
tags: [admx, adm, central-store, policyelements, supportedon, adml, registry-value-types]
related:
  - ./01-gpo-architecture.md
  - ./02-gpo-processing-order.md
  - ./04-cse-client-side-extensions.md
  - ./05-gpt-gpc-structure.md
last_updated: 2026-08-13
---

ADMX (Administrative Template XML, since Vista/Server 2008) replaced the legacy ADM format (UTF-16 INI, locale-specific) with a language-neutral XML schema where ADMX files hold the policy definitions and a sibling ADML file per-locale holds the localized display strings — loaded from either the local `%SystemRoot%\PolicyDefinitions\` directory or the SYSVOL Central Store at `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\`, with the `<policyElements>` schema defining the registry payload type (`text`, `decimal`, `boolean`, `enum`, `list`, `longDecimal`, `multilineText`) and the `<supportedOn>` element gating policy applicability by Windows product version.

## ADM (legacy) — file format

Pre-Vista format. Single INI-style file:

```
CLASS MACHINE
CATEGORY !!MyCategory
  KEYNAME "Software\Contoso\App"
  POLICY !!EnableFeature
    EXPLAIN !!EnableFeature_Help
    VALUENAME "Enabled"
    VALUEON  NUMERIC 1
    VALUEOFF NUMERIC 0
    PART !!Threshold EDITTEXT
      VALUENAME "Threshold"
      DEFAULT "100"
    END PART
  END POLICY
END CATEGORY

[strings]
MyCategory="Contoso Application"
EnableFeature="Enable feature X"
EnableFeature_Help="Enables the foo bar feature."
Threshold="Threshold"
```

Drawbacks:

- Embedded localized strings (`[strings]` section); each language = separate ADM file.
- Hard-coded registry paths in the template — every change requires shipping a new ADM.
- GPMC stores the ADM inside the GPO (`\\SYSVOL\<domain>\Policies\{GUID}\ADM\<file>.adm`), eating SYSVOL storage.
- Maximum ADM size: ~3 MB per file (text-quoting limits).

ADMs are still parsed by GPMC for backward compatibility but new templates should be ADMX.

## ADMX — XML schema

XML root:

```xml
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns="http://www.microsoft.com/GroupPolicy/PolicyDefinitions"
                   revision="1.0"
                   schemaVersion="1.0">
  <policyNamespaces>
    <target prefix="contoso" namespace="Contoso.Policies.App" />
    <using prefix="windows" namespace="Microsoft.Policies.Windows" />
  </policyNamespaces>
  <supersededAdm fileName="contoso.adm" />
  <resources minRequiredRevision="1.0" />
  <supportedOn>
    <definitions>
      <definition name="SUPPORTED_Windows7" displayName="$(string.SUPPORTED_Windows7)"/>
    </definitions>
  </supportedOn>
  <categories>
    <category name="CAT_Contoso" displayName="$(string.CAT_Contoso)" explainText="$(string.CAT_Contoso_Help)"/>
  </categories>
  <policies>
    <policy name="POL_EnableFeature" class="Machine"
            displayName="$(string.POL_EnableFeature)"
            explainText="$(string.POL_EnableFeature_Help)"
            key="Software\Contoso\App"
            valueName="Enabled">
      <parentCategory ref="CAT_Contoso" />
      <supportedOn ref="SUPPORTED_Windows7" />
      <enabledValue><decimal value="1" /></enabledValue>
      <disabledValue><decimal value="0" /></disabledValue>
      <elements>
        <text id="PART_Threshold" valueName="Threshold" required="true" />
        <decimal id="PART_MaxConn" valueName="MaxConnections" minValue="1" maxValue="100" />
        <boolean id="PART_Log" valueName="Logging" />
        <enum id="PART_LogLevel" valueName="LogLevel" required="true">
          <item displayName="$(string.LOG_LOW)">
            <value><decimal value="1" /></value>
          </item>
          <item displayName="$(string.LOG_HIGH)">
            <value><decimal value="2" /></value>
          </item>
        </enum>
      </elements>
    </policy>
  </policies>
</policyDefinitions>
```

Schema file: `policyDefinitions.xsd` (ships in the Windows SDK at `%ProgramFiles%\Microsoft Group Policy\Windows 10 and Windows Server 2016 PolicyDefinitions\`).

## ADMX schema elements

| Element              | Purpose                                                                              |
|----------------------|--------------------------------------------------------------------------------------|
| `<policyNamespaces>` | Declares the XML namespace prefix mapping for this file and any referenced namespaces.|
| `<using>`            | Imports another namespace (e.g. `windows` from Microsoft.Policies.Windows).          |
| `<supersededAdm>`    | Lists legacy ADM files this ADMX replaces (GPMC hides the ADM in the editor).        |
| `<resources>`        | Min ADML revision needed (`minRequiredRevision`).                                    |
| `<supportedOn>`      | Defines the platform-eligibility rules (see below).                                  |
| `<categories>`       | Hierarchical categories shown in GPMC's tree.                                        |
| `<policies>`         | The actual policy settings.                                                          |

### `<policy>` element

Attributes:

| Attribute       | Required | Purpose                                                              |
|-----------------|:--------:|----------------------------------------------------------------------|
| `name`          | ✔        | Internal ID. Must be unique within the namespace.                    |
| `class`         | ✔        | `Machine`, `User`, or `Both`.                                        |
| `displayName`   | ✔        | `$(string.NAME)` reference into the ADML.                            |
| `explainText`   | ✔        | Help text reference.                                                  |
| `key`           | ✔        | Registry key path (relative to `HKLM\Software\Policies\` or `HKCU\Software\Policies\` depending on class). |
| `valueName`     | ✘        | Registry value name. Required if `<enabledValue>`/`<disabledValue>` used. |
| `presentation`  | ✘        | Reference to a `<presentation>` ID in ADML (defines the UI layout).  |

Sub-elements:

| Sub-element                | Purpose                                                              |
|----------------------------|----------------------------------------------------------------------|
| `<parentCategory ref="">`  | Place this policy in a category tree.                                |
| `<supportedOn ref="">`     | Platform eligibility.                                                |
| `<enabledValue>`           | Value written when policy is "Enabled."                              |
| `<disabledValue>`          | Value written when policy is "Disabled."                             |
| `<elements>`               | Sub-elements (parameters within the policy dialog).                  |

### `<elements>` schema — `<policyElements>`

The `<elements>` block defines the policy's parameters:

| Element         | Registry type         | Description                                                                 |
|-----------------|-----------------------|-----------------------------------------------------------------------------|
| `<text>`        | `REG_SZ`              | Single-line string.                                                         |
| `<longDecimal>` | `REG_DWORD` (32-bit)  | Unsigned 32-bit integer.                                                    |
| `<decimal>`     | `REG_DWORD`           | Same as longDecimal (alias).                                                |
| `<boolean>`     | `REG_DWORD`           | 0 or 1.                                                                     |
| `<enum>`        | `REG_DWORD` or `REG_SZ` | Drop-down list of `<item>` values.                                       |
| `<list>`        | `REG_MULTI_SZ`        | Multi-valued list (one row per registry value).                            |
| `<multilineText>` | `REG_MULTI_SZ` (or `REG_SZ` if single-line) | Multi-line text box.                              |
| `<textbox>`     | `REG_SZ` or `REG_EXPAND_SZ` | Text box with optional expansion (`expandable="true"` → REG_EXPAND_SZ). |

Sub-attributes of each element:

- `id` — unique within the policy; links to ADML `<presentation>` element.
- `valueName` — registry value name.
- `required` — must be populated for the policy to be valid.
- `minValue`/`maxValue` (for `<decimal>`/`<longDecimal>`) — input validation.
- `soft` — soft policy (doesn't delete registry value when set to "Not Configured").

### `<supportedOn>` definitions

Built-in supportedOn definitions (in `Windows.admx`):

| `name`                       | Platform                                        |
|------------------------------|--------------------------------------------------|
| `SUPPORTED_Win2k`            | Windows 2000                                     |
| `SUPPORTED_WinXP`            | Windows XP                                       |
| `SUPPORTED_Win2003`          | Windows Server 2003                              |
| `SUPPORTED_WinVista`         | Windows Vista                                    |
| `SUPPORTED_Win2008`          | Windows Server 2008                              |
| `SUPPORTED_Win7`             | Windows 7                                        |
| `SUPPORTED_Win2008R2`        | Windows Server 2008 R2                           |
| `SUPPORTED_Win8`             | Windows 8                                        |
| `SUPPORTED_Win2012`          | Windows Server 2012                              |
| `SUPPORTED_Win8_1`           | Windows 8.1                                      |
| `SUPPORTED_Win2012R2`        | Windows Server 2012 R2                           |
| `SUPPORTED_Win10_1607`       | Windows 10 Anniversary Update                    |
| `SUPPORTED_Win10_1709`       | Windows 10 Fall Creators Update                  |
| `SUPPORTED_Win10_1809`       | Windows 10 October 2018 Update                   |
| `SUPPORTED_Win11`            | Windows 11                                       |
| `SUPPORTED_WinServer2022`    | Windows Server 2022                              |

Custom supportedOn definitions can be added by appending to the `<supportedOn><definitions>` block in your own ADMX (referenced via `ref`).

## Registry value types — full table

| Type             | ID | Win API constant | ADMX element            | Notes                                          |
|------------------|:--:|------------------|-------------------------|------------------------------------------------|
| `REG_NONE`       | 0  | `REG_NONE`       | —                       | No value type.                                 |
| `REG_SZ`         | 1  | `REG_SZ`         | `<text>`                | Null-terminated Unicode string.                |
| `REG_EXPAND_SZ`  | 2  | `REG_EXPAND_SZ`  | `<text expandable="true">` | String with `%VAR%` expanded at read time. |
| `REG_BINARY`     | 3  | `REG_BINARY`     | (no ADMX direct element) | Raw binary.                                   |
| `REG_DWORD`      | 4  | `REG_DWORD`      | `<decimal>`, `<longDecimal>`, `<boolean>` | 32-bit little-endian unsigned int. |
| `REG_DWORD_BIG_ENDIAN` | 5 | —              | —                       | Big-endian (rare).                             |
| `REG_LINK`       | 6  | `REG_LINK`       | —                       | Symbolic link to another registry key.         |
| `REG_MULTI_SZ`   | 7  | `REG_MULTI_SZ`   | `<list>`, `<multilineText>` | Sequence of null-terminated strings, double-null-terminated. |
| `REG_RESOURCE_LIST` | 8 | —              | —                       | Resource list (driver).                        |
| `REG_FULL_RESOURCE_DESCRIPTOR` | 9 | —           | —                       | Hardware resource.                             |
| `REG_RESOURCE_REQUIREMENTS_LIST` | 10 | —          | —                       | Resource requirements.                         |
| `REG_QWORD`      | 11 | `REG_QWORD`      | (no direct ADMX element) | 64-bit little-endian.                          |

ADMX cannot directly emit `REG_BINARY` or `REG_QWORD`; admins must use Preferences (XML files) or scripts for these.

## Central Store — SYSVOL

Default local store: `%SystemRoot%\PolicyDefinitions\` (~5,000 files, ~50 MB on Win11).

Central Store location: `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\`

Structure:

```
\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\
  ├── *.admx                  (all template files: Windows.admx, WindowsDefender.admx, etc.)
  ├── en-US\*.adml            (English string resources)
  ├── de-DE\*.adml            (German)
  ├── fr-FR\*.adml            (French)
  ├── ja-JP\*.adml
  └── ... (per LCID)
```

ADMX files live at the root; ADML files live in `<locale>` subdirectories. GPMC auto-loads the locale matching the admin's UI language; falls back to en-US if absent.

### Setting up Central Store

```cmd
:: On a DC or admin workstation with the latest ADMX pack:
xcopy /s /e "C:\Windows\PolicyDefinitions" "\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\"
:: Verify replication:
dfsrdiag replstate
```

Once the Central Store exists, GPMC automatically uses it (it has priority over local `%SystemRoot%\PolicyDefinitions\`). No registry edit needed. The decision is made in `gpedit.dll!FindPolicyDefinitions` which checks the SYSVOL path before the local path.

### Per-locale fallback

GPMC tries `<locale>` (e.g. `de-DE`). If a string is missing, it falls back to `en-US`. If still missing, GPMC shows the raw `$(string.NAME)` reference as the display text — a common debugging hint that ADML deployment is incomplete.

## Built-in ADMX files (Server 2022)

Selected important ADMXs in the Microsoft base set:

| File                       | Purpose                                                       |
|----------------------------|---------------------------------------------------------------|
| `Windows.admx`             | Core Windows policies (~5,000 settings). Includes supportedOn.|
| `ControlPanel.admx`        | Control Panel restrictions.                                   |
| `WindowsDefender.admx`     | Microsoft Defender AV policies.                              |
| `Krb5.admx`                | Kerberos client policies (etypelist,FAST, etc.).             |
| `Srvadmin.admx`            | Server manager policies.                                     |
| `TermSrv.admx`             | Remote Desktop Services.                                     |
| `W32Time.admx`             | Windows Time service.                                        |
| `DNSClient.admx`           | DNS client policies.                                          |
| `Netlogon.admx`            | Netlogon secure channel policies.                            |
| `NTFS.admx`                | NTFS policies (8.3 names, etc.).                             |
| `PrintKrb5.admx`           | Kerberos for print services.                                 |
| `LAPS.admx`                | Local Administrator Password Solution (Windows LAPS).        |
| `CredSSP.admx`             | Credential Security Support Provider.                        |
| `AppLocker.admx`           | AppLocker rules.                                             |
| `Bitlocker.admx`           | BitLocker Drive Encryption.                                  |
| `tls.admx`                 | TLS/SSL configuration.                                        |
| `Cosmic.admx`              | Cortana / Search.                                            |
| `Edge.admx`                | Microsoft Edge browser (separate download).                  |
| `Office16.admx`            | Microsoft 365 Apps for enterprise (separate download).       |

## ADMX authoring example — custom policy

```xml
<!-- contoso.admx -->
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns="http://www.microsoft.com/GroupPolicy/PolicyDefinitions" revision="1.0">
  <policyNamespaces>
    <target prefix="contoso" namespace="Contoso.Policies.App" />
    <using prefix="windows" namespace="Microsoft.Policies.Windows" />
  </policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <categories>
    <category name="CAT_Contoso" displayName="$(string.CAT_Contoso)" />
  </categories>
  <policies>
    <policy name="POL_SetThreshold" class="Both"
            displayName="$(string.POL_SetThreshold)"
            explainText="$(string.POL_SetThreshold_Help)"
            key="Software\Policies\Contoso\App"
            valueName="Threshold">
      <parentCategory ref="CAT_Contoso" />
      <supportedOn ref="windows:SUPPORTED_Win10_1607" />
      <enabledValue><decimal value="100" /></enabledValue>
      <disabledValue><decimal value="0" /></disabledValue>
      <elements>
        <decimal id="PART_Threshold" valueName="Threshold"
                 minValue="1" maxValue="1000" required="true" />
      </elements>
    </policy>
  </policies>
</policyDefinitions>
```

```xml
<!-- contoso.adml (en-US) -->
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitionResources xmlns="http://www.microsoft.com/GroupPolicy/PolicyDefinitions"
                           revision="1.0" schemaVersion="1.0">
  <displayName>Contoso Policies</displayName>
  <description>Policy definitions for Contoso application.</description>
  <resources>
    <stringTable>
      <string id="CAT_Contoso">Contoso Application</string>
      <string id="POL_SetThreshold">Set threshold value</string>
      <string id="POL_SetThreshold_Help">Configures the Contoso application processing threshold.</string>
      <string id="PART_Threshold">Threshold:</string>
    </stringTable>
    <presentationTable>
      <presentation id="POL_SetThreshold">
        <textBox refId="PART_Threshold">
          <label>Threshold value (1-1000):</label>
        </textBox>
      </presentation>
    </presentationTable>
  </resources>
</policyDefinitionResources>
```

The ADML `<presentationTable>` defines the UI layout; each element ID matches the `id` in the ADMX `<elements>` block.

## Diagnostic — ADMX loading verification

GPMC diagnostic in Event Viewer:

```
Applications and Services Logs \ Microsoft \ Windows \ GroupPolicy \ Operational
  Event 4116 — "Group Policy successfully applied ADMX files from Central Store"
  Event 5312 — "Failed to load ADMX <filename>: <reason>"
```

PowerShell:

```powershell
# Verify Central Store exists
Test-Path "\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\Windows.admx"

# List ADMX files in Central Store
Get-ChildItem "\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\*.admx" |
  Select-Object Name, Length, LastWriteTime

# Verify ADML for current locale
$locale = (Get-Culture).Name     # e.g. "en-US"
Test-Path "\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\$locale\Windows.adml"
```

## Wireshark display filter

ADMX loading is SMB read traffic to SYSVOL:

```
smb2 && smb2.filename contains "PolicyDefinitions" && (smb2.filename contains ".admx" || smb2.filename contains ".adml")
```

## PowerShell — bulk ADMX inspection

```powershell
# Parse all ADMX files in Central Store and list policy names
[xml]$admx = Get-Content "\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\WindowsDefender.admx"
$ns = New-Object System.Xml.XmlNamespaceManager $admx.NameTable
$ns.AddNamespace("p", "http://www.microsoft.com/GroupPolicy/PolicyDefinitions")

$admx.SelectNodes("//p:policies/p:policy", $ns) | ForEach-Object {
    [PSCustomObject]@{
        Name      = $_.GetAttribute("name")
        Class     = $_.GetAttribute("class")
        Key       = $_.GetAttribute("key")
        ValueName = $_.GetAttribute("valueName")
    }
} | Format-Table -Auto
```

## Python — parse ADMX/ADML

```python
import xml.etree.ElementTree as ET
import os

ADMX_NS = "{http://www.microsoft.com/GroupPolicy/PolicyDefinitions}"

def parse_admx(path):
    tree = ET.parse(path)
    root = tree.getroot()
    policies = []
    for policy in root.findall(f".//{ADMX_NS}policy"):
        policies.append({
            'name':      policy.get('name'),
            'class':     policy.get('class'),
            'key':       policy.get('key'),
            'valueName': policy.get('valueName'),
            'supportedOn': policy.findtext(f"{ADMX_NS}supportedOn/{ADMX_NS}ref"),
        })
    return policies

def load_adml_strings(adml_path):
    tree = ET.parse(adml_path)
    root = tree.getroot()
    strings = {}
    for s in root.findall(f".//{ADMX_NS}string"):
        strings[s.get('id')] = s.text
    return strings

admx_path = r"\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\WindowsDefender.admx"
adml_path = r"\\corp.example.com\SYSVOL\corp.example.com\Policies\PolicyDefinitions\en-US\WindowsDefender.adml"

policies = parse_admx(admx_path)
strings  = load_adml_strings(adml_path)

for p in policies[:10]:
    display = strings.get(p['name'].replace('POL_', '') + '_Display', '?')
    print(f"{p['name']:50}  {p['class']:8}  {p['key']}\\{p['valueName']}")
```

## Registry / attribute table — GP Editor settings

```
HKLM\SOFTWARE\Microsoft\GroupPolicy\Client
  └── (no per-ADMX keys; ADMXs are loaded at GPMC open time)

HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Editor
  ├── ShowPoliciesOnly            (REG_DWORD) = 0   (show all settings; 1 = hide non-policy settings)
  ├── ShowADMTree                 (REG_DWORD) = 0
  └── ADMFiles                    (subkeys for legacy ADMs)
```

## Troubleshooting

- **GPMC shows `$(string.X)` instead of text** — ADML missing for current locale. Verify `\<locale>\` folder exists. Fall-back to en-US.
- **Policy missing from GPMC** — Check `<supportedOn>` references; if the target OS doesn't match, the policy won't show. Use the `Filter` options to "show all."
- **ADMX not loading from Central Store** — Check share permissions on `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\` — Authenticated Users need Read. Check DFS-R replication: `dfsrdiag backlog /rgname:<RG> /rfname:<RF> /smem:<src> /rmem:<dst>`.
- **Two ADMX files with same namespace conflict** — `<policyNamespaces><target namespace="">` must be unique. Rename one.
- **ADMX policy applies but registry not set** — Check `key` path is correct (no leading backslash; relative to `HKLM\Software\Policies\`). Verify `<enabledValue>`/`<disabledValue>` are populated. Test by `gpupdate /force` then `reg query`.
- **Central Store huge** — Each locale ~30 MB. Trim to needed locales only. Move to a separate DFS-R replicated folder if SYSVOL is space-constrained.
- **Conflicting policies from two ADMXs** — Last-writer-wins in registry. Use GPMC precedence view (`Advanced View → Filtering → Filter On: conflicts`).

## Cross-platform equivalents

- **Linux — SSSD GPO access**: no ADMX-equivalent. SSSD reads GPOs but only honors the `Security` settings subset (security filtering). No ADMX parser. See `../09-linux-equivalents/03-sssd-gpo-access.md` and `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — FreeIPA**: uses `ipa-pwpolicy` for password policies and `ipa-hbacrule` for access control — separate LDAP attributes per policy area. No XML template concept. See `../09-linux-equivalents/09-openldap-mit-kerberos.md`.
- **Linux — Samba `samba-gpupdate`**: applies Registry.pol-style settings to Linux config files (`/etc/krb5.conf`, etc.) — no ADMX parser; the CSE-equivalent knows how to translate a fixed set of policy keys to Linux files. See `../09-linux-equivalents/04-winbind-internals.md`.
- **macOS — Configuration Profiles (`.mobileconfig`)**: Apple's equivalent — XML plist payloads. No ADMX. MDM servers (Jamf, Intune) author profiles. See `../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md` (fallback `../08-macos-equivalents/03-jamf-connect-pro.md`).
- **Comparison matrix**: see `../10-comparison-matrices/05-gpo-equivalents-matrix.md`.

## References

- MS-GPFR / MS-GPSI — Group Policy Preferences and Security extension specs. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpfr>
- "Administrative Templates in Group Policy" — MS Learn. <https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2008/Cc766402(v=ws.10)>
- ADMX schema: `%ProgramFiles%\Microsoft Group Policy\PolicyDefinitions\policyDefinitions.xsd`.
- "How to create a Central Store for Administrative Template files" — MS Learn. <https://learn.microsoft.com/troubleshoot/windows-server/group-policy/create-central-store-administrative-template>
- ADMX Syntax Reference: <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpod/cc224265-0c7e-4d27-8fbc-22b4a06b8a6e>
