---
title: PowerShell Active Directory Cmdlets Cookbook
audience: senior-engineers
tags: [powershell, activedirectory, rsat, gpo, replication, fsmo, trust]
related:
  - ../02-protocols/02-ldap-protocol.md
  - ../03-directory-schema/01-schema-attributes.md
  - ../03-directory-schema/04-trusts-topology.md
  - ../03-directory-schema/05-replication-internals.md
  - ../04-group-policy/01-gpo-architecture.md
  - ../04-group-policy/05-gpt-gpc-structure.md
  - ../00-overview/04-fsmo-roles.md
  - ../10-comparison-matrices/03-tool-function-matrix.md
  - ./04-wireshark-tshark-filters.md
  - ./05-python-impacket-examples.md
last_updated: 2026-08-13
---

# PowerShell Active Directory Cmdlets Cookbook

Reference recipes for the `ActiveDirectory`, `GroupPolicy`, `Adfs`, and replication PowerShell modules. Each entry: **command → explanation → expected output snippet**.

## Prerequisites

```powershell
# Install RSAT AD + GPO modules (Windows Server)
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GroupPolicy -IncludeManagementTools

# On Windows 10/11 — Settings → Optional Features → add "RSAT: Active Directory..."
Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools*" -Online |
  Add-WindowsCapability -Online

# Verify
Get-Module -ListAvailable ActiveDirectory, GroupPolicy |
  Select-Object Name, Version
```

Expected:
```
Name              Version
----              -------
ActiveDirectory   1.0.2.0
GroupPolicy       1.0.0.0
```

## Basic queries

### List all users with display name and email

```powershell
Get-ADUser -Filter * -Properties displayName, mail |
  Select-Object SamAccountName, displayName, mail |
  Format-Table -AutoSize
```

Output:
```
SamAccountName displayName      mail
-------------- -----------      ----
jsmith         John Smith       jsmith@corp.example.com
adavis         Alice Davis      adavis@corp.example.com
```

### List computers with last logon date

```powershell
Get-ADComputer -Filter * -Properties lastLogonDate, operatingSystem |
  Select-Object Name, DNSHostName, operatingSystem, lastLogonDate |
  Sort-Object lastLogonDate |
  Format-Table -AutoSize
```

### Resolve `lastLogon` (not replicated) per-DC

```powershell
Get-ADDomainController -Filter * |
  ForEach-Object {
    Get-ADUser -Identity jsmith -Server $_.HostName -Properties lastLogon |
      Select-Object @{n='DC';e={$_.HostName}}, @{n='lastLogon';e={[datetime]::FromFileTime($_.lastLogon)}}
  } | Sort-Object lastLogon -Descending | Select-Object -First 1
```

`lastLogon` is **not replicated** — it's per-DC. To find the actual last logon, query every DC and take the max. `lastLogonTimestamp` is replicated (14-day skew).

## Advanced LDAP filters

### Find enabled user accounts

```powershell
# UAC bit 0x2 = ACCOUNTDISABLE; negate via bitwise match rule 1.2.840.113556.1.4.803
Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
```

### Find users with password never expires

```powershell
# UAC bit 0x10000 = DONT_EXPIRE_PASSWORD
Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=65536)" -Properties displayName
```

### Find service accounts (SPN set)

```powershell
Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties servicePrincipalName |
  Select-Object SamAccountName, servicePrincipalName
```

Output:
```
SamAccountName  servicePrincipalName
--------------  -------------------
svc-sql         {MSSQLSvc/sql01.corp.example.com:1433, MSSQLSvc/sql01:SQLEXPRESS}
svc-iis         {HTTP/web01.corp.example.com, HTTP/web01}
```

### Find users in nested group (recursive)

```powershell
# LDAP_MATCHING_RULE_IN_CHAIN = 1.2.840.113556.1.4.1941
Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=CN=HelpDesk,OU=Groups,DC=corp,DC=example,DC=com)"
```

Equivalent via `Get-ADGroupMember -Recursive`:

```powershell
Get-ADGroupMember -Identity "HelpDesk" -Recursive |
  Where-Object { $_.objectClass -eq 'user' }
```

### Find accounts with badPwdCount > 0

```powershell
Get-ADUser -LDAPFilter "(badPwdCount>=1)" -Properties badPwdCount, badPasswordTime |
  Select-Object SamAccountName, badPwdCount, @{n='badPasswordTime';e={[datetime]::FromFileTime($_.badPasswordTime)}}
```

## Group operations

### List members with type info

```powershell
Get-ADGroupMember -Identity "Domain Admins" |
  Select-Object Name, objectClass, distinguishedName
```

### Add/remove members

```powershell
Add-ADGroupMember -Identity "HelpDesk" -Members jsmith, adavis
Remove-ADGroupMember -Identity "HelpDesk" -Members jsmith -Confirm:$false
```

### Find empty groups

```powershell
Get-ADGroup -Filter * -Properties member |
  Where-Object { -not $_.member } |
  Select-Object Name, GroupCategory, GroupScope
```

### Convert group scope

```powershell
# DomainLocal → Global must go through Universal first (per MS-ADTS)
Set-ADGroup -Identity "ProjectX" -GroupScope Universal
Set-ADGroup -Identity "ProjectX" -GroupScope Global
```

## Password management

### Reset user password

```powershell
$secure = ConvertTo-SecureString -String 'N3wP@ss!2026' -AsPlainText -Force
Set-ADAccountPassword -Identity jsmith -NewPassword $secure -Reset
Set-ADUser -Identity jsmith -ChangePasswordAtLogon $true
```

### Force user to change password at next logon

```powershell
Set-ADUser -Identity jsmith -ChangePasswordAtLogon $true
```

### Service-account managed-password rotation

```powershell
# Group MSA — rotate by clearing and re-resolving
Reset-ADServiceAccountPassword -Identity svc-sql-gmsa

# Per-machine, also rotate the root key (KDS):
Add-KdsRootKey -EffectiveImmediately
# (Use -EffectiveTime (Get-Date).AddHours(-10) for immediate test environments)
```

## Computer management

### Join computer (remote)

```powershell
Add-Computer -DomainName "corp.example.com" -Server "dc01.corp.example.com" `
  -Credential (Get-Credential corp\admin) -OUPath "OU=Workstations,DC=corp,DC=example,DC=com" `
  -NewName "WS-0042" -Restart -Force
```

### Move computer to new OU

```powershell
Get-ADComputer -Identity "WS-0042" |
  Move-ADObject -TargetPath "OU=Decommissioned,DC=corp,DC=example,DC=com"
```

### Disable stale computer accounts (>90 days)

```powershell
$cutoff = (Get-Date).AddDays(-90)
Get-ADComputer -Filter { LastLogonDate -lt $cutoff } -Properties LastLogonDate |
  ForEach-Object {
    Disable-ADAccount -Identity $_
    Set-ADComputer -Identity $_ -Description "Disabled $(Get-Date -f yyyy-MM-dd) - stale"
  }
```

## Replication

### Show replication partners

```powershell
repadmin /showrepl /repsto

# Cmdlet equivalent
Get-ADReplicationPartnerMetadata -Target corp.example.com -Partition * |
  Select-Object Server, Partner, Partition, LastReplicationSuccess, ConsecutiveFailureCount
```

Output:
```
Server           Partner          Partition                       LastReplicationSuccess
------           -------          ---------                       ----------------------
dc01.corp...     dc02.corp...     DC=corp,DC=example,DC=com       8/13/2026 9:42:11 AM
dc01.corp...     dc02.corp...     CN=Schema,CN=Configuration,...  8/13/2026 9:42:08 AM
dc01.corp...     dc02.corp...     DC=ForestDnsZones,DC=corp,...   8/13/2026 9:42:15 AM
```

### Show replication failures

```powershell
Get-ADReplicationFailure -Target corp.example.com -Scope Domain |
  Select-Object Server, Partner, FailureType, ErrorCount, FirstFailureTime
```

### Force replication

```powershell
# All partitions, all partners
repadmin /syncall /A /d /e

# Single object
Sync-ADObject -Object "CN=jsmith,OU=Users,DC=corp,DC=example,DC=com" `
  -Source dc01 -Destination dc02
```

### Up-to-dateness vector

```powershell
Get-ADReplicationUpToDatenessVectorTable -Target dc01 -Scope Domain |
  Select-Object Server, Partner, UsnFilter
```

## GPO operations

### List all GPOs

```powershell
Get-GPO -All | Select-Object DisplayName, Id, GpoStatus, ModificationTime
```

### Create new GPO and link

```powershell
$gpo = New-GPO -Name "Workstation Lockdown" -Comment "CIS benchmark baseline"
$gpo | New-GPLink -Target "OU=Workstations,DC=corp,DC=example,DC=com" -LinkEnabled Yes -Enforced No
```

### Set a registry value

```powershell
Set-GPRegistryValue -Name "Workstation Lockdown" `
  -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
  -ValueName "NoAutoUpdate" -Type DWord -Value 1
```

### Read all registry settings in a GPO

```powershell
Get-GPRegistryValue -Name "Workstation Lockdown" -All |
  Select-Object Key, ValueName, Value, Type
```

### Backup and restore

```powershell
Backup-GPO -All -Path "\\fileserver\GPO-Backups\$(Get-Date -f yyyyMMdd)"
Restore-GPO -Name "Workstation Lockdown" -Path "\\fileserver\GPO-Backups\20260813" -CreateIfNeeded
```

### Import GPO from one domain to another

```powershell
# Backup source
Backup-GPO -Guid 7ab3b2c1-1234-5678-9abc-def012345678 -Path C:\temp\gpo
# Restore as new in target (Import-GPO creates new GUID)
Import-GPO -BackupId <guid> -Path C:\temp\gpo -TargetName "Workstation Lockdown - Prod" -CreateIfNeeded
```

### Inheritance / blocking

```powershell
# Block inheritance on OU
Set-GPInheritance -Target "OU=Staging,DC=corp,DC=example,DC=com" -IsBlocked Yes

# Enforce a specific link
Set-GPLink -Name "Workstation Lockdown" -Target "OU=Workstations,DC=corp,DC=example,DC=com" -Enforced Yes
```

### WMI filter

```powershell
$wmi = New-GPOWmiFilter -Name "Is-Server" `
  -Expression "SELECT * FROM Win32_OperatingSystem WHERE ProductType = 2"
Set-GPWmiFilter -Name "Workstation Lockdown" -WmiFilter $wmi
```

## FSMO operations

### Query FSMO roles

```powershell
# Per-domain (PDC, RID, Infrastructure)
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster

# Per-forest (Schema, Domain Naming)
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster
```

Or the legacy:

```powershell
netdom query fsmo
```

### Transfer PDC emulator role

```powershell
Move-ADDirectoryServerOperationMasterRole -Identity dc02 `
  -OperationMasterRole PDCEmulator
```

### Seize (forceful — only if current holder is offline permanently)

```powershell
Move-ADDirectoryServerOperationMasterRole -Identity dc02 `
  -OperationMasterRole PDCEmulator, RIDMaster, InfrastructureMaster `
  -Force
```

> ⚠ Seizing is destructive — the old holder must never come back online. Seize only if the original FSMO holder is unrecoverable. See [../00-overview/04-fsmo-roles.md](../00-overview/04-fsmo-roles.md).

## Domain trust operations

### List trusts

```powershell
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, TrustAttributes
```

Output:
```
Name       Direction TrustType  TrustAttributes
----       --------- ---------  ---------------
corp.com   Bidirectional UpLevel {FOREST_TRANSITIVE, WITHIN_FOREST}
child.corp Bidirectional UpLevel {WITHIN_FOREST}
```

### Create external trust

```powershell
$cred = Get-Credential partner\admin
New-ADTrust -Name "partner.example.com" `
  -Target "partner.example.com" `
  -TrustType External `
  -Direction Inbound `
  -TrustAttributes 'TreatAsExternal' `
  -Confirm:$false
```

### Verify trust

```powershell
nltest /verify:partner.example.com
Test-ComputerSecureChannel -Server dc01 -Verbose
```

### Reset secure channel

```powershell
# Reset machine account password with DC
Test-ComputerSecureChannel -Repair -Credential (Get-Credential corp\admin)
```

## Schema operations

### Read schema version

```powershell
Get-ADObject -Identity "CN=ActiveDirectory,CN=Schema,CN=Configuration,DC=corp,DC=example,DC=com" `
  -Properties objectVersion, rangeUpper
```

Output:
```
objectVersion rangeUpper
-------------- -----------
88             19 (Server 2022)
```

### Find all GCs

```powershell
Get-ADDomainController -Filter { IsGlobalCatalog -eq $true } |
  Select-Object HostName, Site, OperatingSystem
```

### Promote to GC

```powershell
# Set the NTDS Settings options bit 0x1 (IS_GC)
Set-ADObject -Identity "CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=com" `
  -Replace @{ options = 1 }
# Restart the DC's NTDS service is not required — promotion is online.
```

## Diagnostic shortcuts

### Find locked accounts

```powershell
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LastLogonDate
```

### Unlock

```powershell
Unlock-ADAccount -Identity jsmith
```

### Find disabled accounts

```powershell
Search-ADAccount -AccountDisabled | Select-Object Name, SamAccountName
```

### Find expired passwords

```powershell
Search-ADAccount -PasswordExpired | Select-Object Name, SamAccountName
```

### Check replication metadata for one attribute (last writer)

```powershell
Get-ADReplicationAttributeMetadata -Object "CN=jsmith,OU=Users,DC=corp,DC=example,DC=com" `
  -Server dc01 -Properties memberOf |
  Select-Object AttributeName, LastOriginatingChangeTime, LastOriginatingInvocationId, Version
```

## See also

- [../10-comparison-matrices/03-tool-function-matrix.md](../10-comparison-matrices/03-tool-function-matrix.md) — cross-platform equivalents.
- [../04-group-policy/01-gpo-architecture.md](../04-group-policy/01-gpo-architecture.md) — GPC/GPT internals.
- [../03-directory-schema/05-replication-internals.md](../03-directory-schema/05-replication-internals.md) — USN vectors, `DRSGetNCChanges` mechanics.
- [./05-python-impacket-examples.md](./05-python-impacket-examples.md) — Python LDAP/impacket equivalents (for cross-platform automation).
