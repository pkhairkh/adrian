---
title: GPO Processing Order — LSDOU, WMI Filters, Security Filtering, Slow-Link, Refresh, Async vs Sync
audience: senior-engineers
tags: [gpo-processing, lsdou, wmi-filter, security-filtering, slow-link, async-sync]
related:
  - ./01-gpo-architecture.md
  - ./04-cse-client-side-extensions.md
  - ./05-gpt-gpc-structure.md
  - ../03-directory-schema/02-ous-containers.md
last_updated: 2026-08-13
---

GPO processing order is fixed at LSDOU (Local, Site, Domain, OU — parent-to-child within OU), with each container's `gPLink` list evaluated left-to-right (highest priority first), modified by `gPOptions=1` (block inheritance from below), `gPLink Options=0x2` (enforced / "No Override" from above), WMI filter evaluation at the client, and security filtering that requires both `Apply Group Policy` (`Read` + `Apply`) ACEs present and `Deny` ACEs absent — with slow-link detection (default 500 kbps) switching the CSE set and the sync/async mode based on whether the GP back-end is reachable within the threshold.

## LSDOU — the linear order

The full processing order, last-applied-wins (later overrides earlier in the same scope):

```
1. Local Group Policy
     └── %SystemRoot%\System32\GroupPolicy\Machine\ and \User\
         (always present, lowest priority, ignored by Domain-joined machines if "Always Wait for Network")

2. Site Policy
     └── AD site of the client's current subnet
     └── gPLink on CN=<site>,CN=Sites,CN=Configuration,...
     └── Multiple GPOs: left-to-right, leftmost = highest priority

3. Domain Policy
     └── gPLink on the domainDNS object (DC=corp,DC=example,DC=com)
     └── Includes the Default Domain Policy {31B2F340-016D-11D2-945F-00C04FB984F9}

4. OU Policy (top → bottom of the user's/computer's OU path)
     └── Walk the DN parent chain from domain root to the object's OU
     └── For each ancestor OU, process its gPLink list left-to-right
     └── The OU directly containing the object is processed LAST → highest priority
```

### Order modifier — `gPOptions` block inheritance

If an OU has `gPOptions = 1` (`GPO_BLOCK_INHERITANCE`), GPOs from parent OUs and the domain are NOT processed for objects within this OU. Only GPOs linked to the OU itself and Local/Site GPOs apply.

### Order modifier — `gPLink Options` Enforced

If a GPO link has `Options = 0x2` (`GPO_LINK_ENFORCED`, formerly "No Override"), the GPO is applied at the point in the order it would normally be applied, AND no later GPO in the chain can override its settings. The "enforced" flag propagates downward: every setting in the enforced GPO becomes the final setting for that policy area.

Conflict resolution with block inheritance: Enforced wins. An enforced link at the domain level bypasses a child OU's block-inheritance flag.

## WMI filters

Evaluated at GP processing time on the client. Each GPO can have at most one WMI filter attached (via `gPCWQLFilter`). Stored as `msFTSI` objects under `CN=SOM,CN=WMIPolicy,CN=System,<domain-dn>` (SOM = Scope of Management).

WMI filter object class: `msFTSI` (WMI Filter). Each filter has one or more `msFTSI_Query` entries (WQL queries) ANDed together.

```wql
-- Example: Windows Server 2022 only
SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.0.20348%" AND ProductType = 3

-- Example: member of the Finance OU and laptop
SELECT * FROM Win32_ComputerSystem WHERE DomainRole = 1
```

Evaluation flow:

1. Client queries WMI (`root\cimv2`) for each `msFTSI_Query` in the filter.
2. If any query returns zero rows, the filter FAILS — the GPO is not applied.
3. If all queries return ≥1 row, the filter PASSES — the GPO is evaluated normally.

WMI filter results are cached on the client for 60 minutes (registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\WMIFilterCache`).

If the WMI service is unavailable, the GPO is **NOT applied** (fail-closed) for safety.

### Slow-link impact on WMI

WMI filters are evaluated locally (they query the local WMI provider), so slow-link detection does NOT disable WMI filtering. Slow link DOES disable CSEs that require network access (see below).

## Security filtering

Each GPO has an ACL on its GPC object (`groupPolicyContainer`). For a user/computer to apply the GPO, both:

- `READ` permission on the GPC object (and the GPT folder)
- `Apply Group Policy` (a specific extended-right, GUID `edacfd8f-ffb3-11d1-b41d-00a0c968f939`) ACE on the GPC

must be present for the security principal OR a group containing it. AND:

- `Deny` ACE for `Apply Group Policy` on the principal → GPO NOT applied (Deny always wins).

Default: GPOs are ACLed for `Authenticated Users` (Read + Apply). This is the S-1-5-11 well-known group, which includes every authenticated user AND computer in the forest. Removing Authenticated Users from a GPO is a common breakage point: the computer account needs to read the GPC at boot to fetch machine policy; if Authenticated Users is removed and the computer's group is not added, machine-side policy fails silently.

PowerShell `Set-GPPermissions -TargetName "..." -PermissionLevel GpoApply -TargetName "DOMAIN Computers"` is the modern way to scope.

### Security filtering exceptions

- Local System: always applies (separate code path).
- Read-only domain controllers (RODCs): machine policy applied normally; user policy denied by default.

## Slow-link detection

Algorithm (`gpsvc.dll!DetectSlowLink`):

1. On policy refresh, ping the PDC emulator via ICMP three times.
2. Compute average round-trip time.
3. Estimate link speed = `packet_size / avg_rtt`. Default packet size = 64 KB.
4. If estimated speed < `SlowLink` threshold (default 500 kbps) → SLOW LINK.

Registry:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
  ├── SlowLink             (REG_DWORD) = 500      (kbps; 0 = always fast)
  ├── SlowLinkDetectEnabled (REG_DWORD) = 1
  ├── SlowLinkTimeOut      (REG_DWORD) = 60       (seconds for ping timeout before declaring slow)
  └── GPNetworkName        (REG_SZ)    = <PDC-DC-name>
```

Slow-link impact:

| CSE                       | Slow-link behavior                                                                                          |
|---------------------------|-------------------------------------------------------------------------------------------------------------|
| Registry (`{35378EAC-...}`) | Always applied (registry settings are local).                                                              |
| Security (`{827D319E-...}`)| Always applied.                                                                                            |
| Scripts (`{42B5FAAE-...}`)| Applied only at next boot/logon (not during background refresh).                                          |
| Folder Redirection (`{426031c0-...}`) | NOT applied by default on slow link (set "Follow" policy to override).                       |
| Software Installation (`{c6dc5466-785a-11d2-84ed-00c04fb1692f}`) | NOT applied on slow link.                                                |
| Group Policy Preferences — `Files`, `Printers`, `Drives`, `Shortcuts` | NOT applied on slow link (configurable per-extension).        |

Override slow-link for specific CSEs:

```
User Configuration \ Administrative Templates \ System \ Group Policy \
  Configure Folder Redirection policy processing
    Process even if Group Policy objects have not changed    (enable)
    Do not apply during periodic background processing       (disable)
```

## Background refresh interval

Default: 90 minutes + 0-30 minute jitter. So actual interval is between 90 and 120 minutes.

Computer Configuration \ Administrative Templates \ System \ Group Policy:

- "Group Policy refresh interval for computers" — 90 minutes default
- "Group Policy refresh interval for domain controllers" — same default; can override for DCs

Registry:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\System
  └── GroupPolicyRefreshRate        (REG_DWORD) = 90    (minutes)
  └── GroupPolicyRefreshRateRand    (REG_DWORD) = 30    (jitter)

# For DCs:
HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\System
  └── GroupPolicyRefreshRateDC      (REG_DWORD) = 90
  └── GroupPolicyRefreshRateDCRand  (REG_DWORD) = 30
```

Background refresh is **disabled by default for some CSEs** even when the timer fires:

- Folder Redirection — refresh at logon only.
- Software Installation — refresh at logon only.
- Scripts — refresh at boot/logon only.
- Disk Quota — periodic refresh OK.

This can be overridden per-CSE with "Process even if the Group Policy objects have not changed" but it has a CPU/network cost.

## Async vs sync processing

### Sync (default for fast link)

- Boot: `gpsvc` waits for network initialization before logon UI appears.
- Logon: `gpsvc` waits for user GP processing before shell starts.
- Result: logon takes longer but policy is always consistent at first user action.

Registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SyncForegroundPolicy = 1` (default since Vista).

### Async (default for slow link)

- Boot: logon UI appears before network is up; GP applied in background after logon.
- Logon: user gets desktop before GP processing completes; policy applies ~30 sec later.
- Risk: first 30 sec of session may have stale policy.

Registry: `SyncForegroundPolicy = 0`.

Always Wait for Network at Startup and Logon — Computer Config \ Admin Templates \ System \ Logon:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon
  └── WaitForNetwork = 1   (force sync; ~30 sec logon delay)
```

For fast logon in VDI, set this to 0 — but logon-only policy (folder redirection, drive maps) won't apply on first logon.

## GP processing phases

Per `gpsvc.dll!ProcessGroupPolicyEx`:

```
1. CSE Enumeration
   ├── Read gPCMachineExtensionNames / gPCUserExtensionNames from each GPC.
   ├── Look up each CSE GUID under HKLM\...\Group Policy\CSEs\{GUID}.
   └── Build ordered list of CSEs (ordered by registry Order value if present, else by GUID).

2. For each CSE (in order):
   ├── Check if the GPO version for this CSE has changed since last refresh.
   │   (Cached in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\{CSE-GUID}\{GPO-GUID}\Version)
   ├── If no change and CSE supports no-change-skip, skip.
   ├── If slow link and CSE disabled for slow link, skip.
   ├── If WMI filter attached to GPO and filter FAILS, skip.
   ├── If security filter DENIES the user/computer, skip.
   ├── Otherwise: call CSE ProcessGroupPolicy entry point.
   │   ├── CSE reads its files from GPT (Registry.pol, Scripts.ini, Registry.xml, etc.)
   │   ├── CSE applies settings (writes to registry, files, etc.)
   │   └── CSE returns ERROR_SUCCESS or error code.
   └── On error, log Event 1090 (GroupPolicy) and continue with next CSE.

3. Asynchronous policy refresh (for slow CSEs)
   ├── Some CSEs return ERROR_PENDING — async work queued.
   ├── gpsvc keeps the policy "in progress" until CSE reports completion.
   └── User sees "Applying Group Policy" toast until done.
```

## Diagnostic — `gpresult` and LDAP filter

`gpresult` is the GP client's diagnostic tool. Most useful invocations:

```cmd
:: HTML report — most readable
gpresult /h C:\gpresult.html /f

:: Specific scope
gpresult /scope computer /v
gpresult /scope user /v

:: Specific user
gpresult /user corp\jdoe /v

:: RSOP — Resultant Set of Policy (deprecated since Win10)
gpresult /r
```

For programmatic analysis, query AD for the gPLink chain:

```ldap
# Find all gPLinks on the chain from domain root to a specific OU
ldapsearch -b "OU=Sales,DC=corp,DC=example,DC=com" -s base "(objectClass=*)" gPLink gPOptions
ldapsearch -b "DC=corp,DC=example,DC=com" -s base "(objectClass=*)" gPLink gPOptions
ldapsearch -b "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com" -s base "(objectClass=*)" gPLink
```

## Wireshark display filter

GP processing on the wire = LDAP queries + SMB file reads:

```
# LDAP queries for the GPO objects:
ldap && (ldap.baseObject contains "CN=Policies,CN=System" || ldap.baseObject contains "CN=Sites,CN=Configuration")

# ICMP slow-link detection (3 pings):
icmp && (ip.dst == <pdc-ip-address>)

# SMB reads of GPT files:
smb2.cmd == 5 && smb2.filename contains "\\Policies\\"   # READ responses
```

## PowerShell — RSoP analysis

```powershell
# 1. Get applied GPOs for the current computer
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\rsop.html

# 2. List GPOs that would apply to a specific user, in LSDOU order
$dn = (Get-ADUser -Identity jdoe).DistinguishedName
$ancestors = $dn -split ',' | ForEach-Object {
    $parts = $dn -split ','
    for ($i = $parts.Count - 1; $i -ge 0; $i--) {
        ($parts[0..$i] -join ',')
    }
} | Select-Object -Unique

# Walk the chain bottom-up, collect gPLinks
$gpoList = foreach ($ancestor in $ancestors) {
    $obj = Get-ADObject -Identity $ancestor -Properties gPLink, gPOptions -ErrorAction SilentlyContinue
    if ($obj.gPLink) {
        [PSCustomObject]@{
            Container = $ancestor
            BlockInh  = [bool]($obj.gPOptions -band 1)
            Links     = [regex]::Matches($obj.gPLink, '\[LDAP://([^;]+);(\d+)\]') |
                        ForEach-Object {
                          [PSCustomObject]@{
                            GPO = $_.Groups[1].Value
                            Opt = [int]$_.Groups[2].Value
                          }
                        }
        }
    }
}
$gpoList | Format-List
```

## Python ldap3 — fetch gPLink chain

```python
from ldap3 import Server, Connection, ALL
import re

server = Server('dc01.corp.example.com', get_info=ALL)
conn = Connection(server, user='corp\\admin', password='...', auto_bind=True,
                  authentication='NTLM')

# User DN
user_dn = 'CN=jdoe,OU=Sales,DC=corp,DC=example,DC=com'
ancestors = []
parts = user_dn.split(',')
for i in range(len(parts), 0, -1):
    ancestors.append(','.join(parts[i-1:]))
ancestors.append('CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com')
ancestors.append('DC=corp,DC=example,DC=com')

gplink_re = re.compile(r'\[LDAP://([^;]+);(\d+)\]')
chain = []
for ancestor in ancestors:
    conn.search(ancestor, '(objectClass=*)', search_scope='BASE',
                attributes=['gPLink', 'gPOptions'])
    if conn.entries:
        e = conn.entries[0]
        gplink = e.gPLink.value if 'gPLink' in e else None
        gpopt  = int(e.gPOptions.value) if 'gPOptions' in e and e.gPOptions.value else 0
        if gplink:
            for m in gplink_re.finditer(gplink):
                chain.append({
                    'container': ancestor,
                    'gpo_dn':    m.group(1),
                    'options':   int(m.group(2)),
                    'disabled':  bool(int(m.group(2)) & 1),
                    'enforced':  bool(int(m.group(2)) & 2),
                    'block_inheritance': bool(gpopt & 1),
                })

# LSDOU: Site, Domain, OU (parent -> child). chain is reverse-sorted (user's OU first).
chain.reverse()
for entry in chain:
    print(entry)
```

## Registry / policy attribute table

### GP-related registry values

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\
  └── {<CSE-GUID>}
       └── {<GPO-GUID>}
            ├── DisplayName      (REG_SZ)
            ├── GPO DN           (REG_SZ)
            ├── FileSysPath      (REG_SZ)
            ├── Version          (REG_DWORD)  (last applied version)
            ├── Options          (REG_DWORD)
            ├── User             (REG_SZ) — SID of user/computer
            └── Link             (REG_SZ) — DN of container

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
  ├── SyncForegroundPolicy      (REG_DWORD) = 1   (sync mode default)
  ├── WaitForNetwork            (REG_DWORD) = 0
  └── GroupPolicyRefreshRate    (REG_DWORD) = 90
```

### WMI filter attribute table

| Attribute          | Class              | Purpose                                             |
|--------------------|--------------------|----------------------------------------------------|
| `msFTSI_Name`      | `msFTSI`           | Filter friendly name.                              |
| `msFTSI_Description`| `msFTSI`          | Free-text description.                             |
| `msFTSI_Query`     | `msFTSI`           | WQL query (multi-valued — ANDed).                  |
| `msFTSI_ID`        | `msFTSI`           | Filter GUID (referenced by GPC's `gPCWQLFilter`). |
| `msFTSI_WMIIID`    | `msFTSI`           | WMI namespace identifier.                          |

## Troubleshooting

- **GPO applied to some OUs but not others** — Check `gPOptions` on intermediate OUs (block inheritance), and `gPLink Options` on parent links (enforced). Use `gpresult /r` to see "Applied Group Policy Objects" vs "Denied Group Policy Objects" lists.
- **WMI filter incorrectly excludes computers** — Run the WQL query manually with `wmic` or PowerShell `Get-CimInstance` against the local WMI to verify. WMI repository corruption: `rundll32 wbemdisp.dll, RepairWMISchema`.
- **GPO applies at boot but not at logon** — User-side security filtering denies the user. Verify `Apply Group Policy` ACE on the GPC for the user's group. Use `Get-GPPermission -All` to inspect.
- **Slow logon due to slow-link detection** — ICMP ping blocked. Set `SlowLinkDetectEnabled = 0` in the registry or via "Turn off background refresh of Group Policy" policy.
- **Async processing causes policy inconsistency** — Set `SyncForegroundPolicy = 1` and "Always Wait for Network at Startup and Logon" enabled. Trade-off: 30-60 sec longer logon.
- **GP not refreshing in background** — Verify `gpsvc` running, no `GPRefreshDisable = 1`. Check event log for 1090 (CSE error) and 1053 (GroupPolicy).
- **Enforced GPO not winning** — `gPLink Options` bit 0x2 must be set on the link, not on the GPO itself. Re-check via `Get-GPInheritance -Target <DN>`.

## Cross-platform equivalents

- **Linux — SSSD GPO access**: applies a subset of GPO (security filtering for login). No CSE-equivalent; no `Registry.pol` enforcement. See `../09-linux-equivalents/03-sssd-gpo-access.md` and `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux — Samba `samba-gpupdate`**: applies GP settings to `/etc/krb5.conf`, `/etc/security/limits.conf`, etc. See `../09-linux-equivalents/04-winbind-internals.md`.
- **Linux — FreeIPA HBAC + sudo rules**: equivalent capability (login control, sudo). Different mechanism (LDAP-based, no GP). See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **macOS — Configuration Profiles**: equivalent is `.mobileconfig` payloads delivered via MDM. AD-bound Macs use the AD plugin's `gpupdate` for a subset. See `../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md` (fallback `../08-macos-equivalents/03-jamf-connect-pro.md`).
- **Comparison matrix**: see `../10-comparison-matrices/05-gpo-equivalents-matrix.md`.

## References

- MS-GPOL §3.2.2 — Group Policy Application Order (LSDOU). <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpol/7d3f0f0a-8c1f-4f3a-9f47-0a3b0b8b0a3b>
- MS-GPOD §3.1.1 — `gPLink` format and options. <https://learn.microsoft.com/openspecs/windows_protocols/ms-gpod>
- "Group Policy Processing" — MS Learn Windows Server. <https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing>
- "How Group Policy Processing Works" — TechNet archive. <https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc782655(v=ws.10)>
- WMI Filtering — MS Learn. <https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/wmi-filtering-for-the-group-policy-management-console>
