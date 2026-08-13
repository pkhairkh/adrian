---
title: macOS CLI Recipes — dscl, dsconfigad, profiles, sso_util, plutil, Kerberos
audience: senior-engineers
tags: [macos, dscl, dsconfigad, profiles, sso_util, kerberos, plist]
related:
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../08-macos-equivalents/01-opendirectory-internals.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../08-macos-equivalents/05-kerberos-sso-extension.md
  - ../08-macos-equivalents/01-opendirectory-internals.md
  - ../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md
  - ../10-comparison-matrices/03-tool-function-matrix.md
  - ./01-powershell-ad-cmdlets.md
last_updated: 2026-08-13
---

# macOS CLI Recipes

Cookbook for AD binding, OpenDirectory inspection, MDM profile management, plist manipulation, Kerberos, and `sso_util` (Platform SSO Extension). Targets macOS 13+ unless noted.

## AD binding via `dsconfigad`

### Bind

```bash
sudo dsconfigad -a host01 \
  -domain corp.example.com \
  -u admin \
  -p 'P@ss!' \
  -ou "CN=Computers,DC=corp,DC=example,DC=com" \
  -status
```

Flags:
| Flag | Purpose |
|---|---|
| `-a <name>` | Computer name to bind as |
| `-domain <FQDN>` | AD domain |
| `-u <user>` | Privileged AD user with join rights |
| `-p <pass>` | Password (avoid on cmdline; use `-p ''` then prompt) |
| `-ou <DN>` | Target OU for the computer object |
| `-status` | Print join status after |
| `-localuser <admin>` | Local admin to authorize the change |
| `-localpass <pass>` | Local admin password |
| `-mobile enable` | Create mobile account at first login |
| `-mobileconfirm disable` | Don't prompt user at mobile account creation |
| `-useuncdisable` | Don't derive UNC from AD homeDirectory |
| `-groups "CORP\Domain Admins"` | AD groups added to local admin |

### Enable SSO (Enterprise Connect / PSSO Extension precursor)

```bash
sudo dsconfigad -enablesso
```

> On macOS 13+, `dsconfigad -enablesso` configures the **Platform SSO Extension** (if installed via MDM profile) rather than the legacy Enterprise Connect. The flag is a no-op if no PSSO Extension is enrolled. See [../08-macos-equivalents/04-platform-sso-extension.md](../08-macos-equivalents/04-platform-sso-extension.md).

### Configure mobile accounts / options

```bash
sudo dsconfigad -mobile enable
sudo dsconfigad -mobileconfirm disable
sudo dsconfigad -localhome enable
sudo dsconfigad -useuncdisable
sudo dsconfigad -groups "CORP\Domain Admins,CORP\HelpDesk"
sudo dsconfigad -namespace domain
```

### Show current config

```bash
sudo dsconfigad -show
```

Output:
```
Active Directory                  = corp.example.com
Active Directory Machine Account  = host01$
Advanced Options - User Experience
  Create mobile account at login  = Enabled
  Require confirmation             = Disabled
  Force home to local disk         = Enabled
  Use Windows UNC path from Active Directory = Disabled
  Network protocol to be used      = smb
  Default user Shell               = /bin/bash
Advanced Options - Mappings
  Mapping UID to attribute         = not set
  Mapping user GID to attribute    = not set
  Mapping group GID to attribute   = not set
  Generate Kerberos auth authority = Enabled
Advanced Options - Administrative
  Preferred Domain controller      = not set
  Allowed admin groups             = CORP\Domain Admins, CORP\HelpDesk
  Authentication from any domain   = Enabled
  Packet signing                   = Allow
  Packet encryption                = Allow
  Password change interval         = 14
  Restrict Dynamic DNS updates     = not set
  Namespace mode                   = domain
```

### Unbind

```bash
sudo dsconfigad -remove -u admin -p 'P@ss!'
```

## OpenDirectory inspection via `dscl`

### List all OD nodes

```bash
dscl -list /
```

Output:
```
Active Directory
BSD
Local
Search
Contact
```

### List users in AD

```bash
dscl /Active\ Directory/CORP -list /Users
```

### Read one user

```bash
dscl /Active\ Directory/CORP -read /Users/jsmith
```

Output (truncated):
```
dsAttrTypeNative:accountExpires: 0
dsAttrTypeNative:badPwdCount: 0
dsAttrTypeNative:badPasswordTime: 0
dsAttrTypeNative:cn: John Smith
dsAttrTypeNative:codePage: 0
dsAttrTypeNative:displayName: John Smith
dsAttrTypeNative:distinguishedName: CN=John Smith,OU=Users,DC=corp,DC=example,DC=com
dsAttrTypeNative:givenName: John
dsAttrTypeNative:lastLogon: 133961634990000000
dsAttrTypeNative:memberOf: CN=HelpDesk,OU=Groups,DC=corp,DC=example,DC=com CN=Domain Users,CN=Users,DC=corp,DC=example,DC=com
dsAttrTypeNative:name: jsmith
dsAttrTypeNative:objectClass: top person organizationalPerson user
dsAttrTypeNative:objectGUID: 11223344-5566-7788-99aa-bbccddeeff00
dsAttrTypeNative:primaryGroupID: 513
dsAttrTypeNative:pwdLastSet: 133901400000000000
dsAttrTypeNative:sAMAccountName: jsmith
dsAttrTypeNative:userAccountControl: 512
dsAttrTypeNative:userPrincipalName: jsmith@corp.example.com
AppleMetaNodeLocation: /Active Directory/CORP
GeneratedUID: 11223344-5566-7788-99aa-bbccddeeff00
NFSHomeDirectory: /Network/Servers/dc01/Users/jsmith
RecordName: jsmith
RecordType: dsRecTypeStandard:Users
```

### Search AD

```bash
dscl /Active\ Directory/CORP -search /Users displayName Smith
dscl /Active\ Directory/CORP -search /Groups memberOf "Domain Admins"
```

### Modify a local attribute (only for local node)

```bash
sudo dscl . -create /Users/jsmith NFSHomeDirectory /Users/jsmith
sudo dscl . -append /Users/jsmith RecordName jsmith.corp
sudo dscl . -delete /Users/jsmith
```

> `.` is the local node (`/Local/Default`). Modifications to AD-backed nodes (`/Active Directory/CORP`) require read-write access to the AD via the bound account's credentials — typically not granted. Use `ldapsearch`/`ldapmodify` for AD writes from macOS.

### List group members

```bash
dscl /Active\ Directory/CORP -read /Groups/"Domain Admins" GroupMembership
dscl /Active\ Directory/CORP -read /Groups/"Domain Admins" memberUid
dscl /Active\ Directory/CORP -read /Groups/"Domain Admins" dsAttrTypeNative:member
```

### Check effective group membership

```bash
dsmemberutil checkmembership -U jsmith -G "CORP\\Domain Admins"
```

Output:
```
user is a member of the group
```

### Resolve GID from group name

```bash
dsmemberutil getgid -G "CORP\\Domain Admins"
```

### Resolve UID from user name

```bash
dsmemberutil getuid -U jsmith
```

### Get all memberships for a UID

```bash
dsmemberutil getmembership -q -u 501
```

Output (UUIDs of all groups the user belongs to, including nested):
```
...
 ABCDEF01-2345-6789-ABCD-EF0123456789
 11223344-5566-7788-99AA-BBCCDDEEFF00
```

## MDM profile management (`profiles`)

### List installed profiles

```bash
profiles list
profiles show -type configuration
profiles show -type provisioning
```

Output:
```
There are 4 configuration profiles installed:

com.example.ssh          (installed 2026-08-13 09:14:33 +0000)
com.example.firewall     (installed 2026-08-13 09:14:33 +0000)
com.example.passwordpolicy (installed 2026-08-13 09:14:33 +0000)
com.example.kerberos     (installed 2026-08-13 09:14:33 +0000)
```

### Install a profile

```bash
sudo profiles install -path ~/Desktop/payload.mobileconfig
```

### Remove a profile

```bash
sudo profiles remove -identifier com.example.ssh
```

### Show profile detail

```bash
profiles show -identifier com.example.kerberos -expand
```

### Show device enrollment status (DEP/ABM)

```bash
profiles status -type enrollment
```

Output:
```
Enrolled via DEP: Yes
MDM enrollment: Yes
MDM server URL: https://mdm.corp.example.com/mdm
```

### Renew MDM enrollment (after OS upgrade)

```bash
sudo profiles renew -type enrollment
```

## Plist manipulation (`plutil` / `defaults`)

### Inspect OpenDirectory config

```bash
plutil -p /Library/Preferences/com.apple.OpenDirectory.plist
```

Output:
```
{
  "ODConfigSatisfiesPolicy" => 1
  "ModuleOptions" => {
    "Active Directory" => {
      "ffUIDCheck" => 0
      "ffUseUNCPath" => 0
      ...
    }
  }
}
```

### Read AD binding config

```bash
sudo defaults read /Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/Domains
```

Or:
```bash
sudo plutil -p /Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/Domains.plist
```

### Edit a value

```bash
sudo defaults write /Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/Domains \
  "Preferred DC" -string "dc01.corp.example.com"
```

### Convert plist formats

```bash
plutil -convert binary1 Info.plist       # XML → binary
plutil -convert xml1 Info.plist          # binary → XML
plutil -convert json Info.plist          # → JSON
```

### Validate a plist

```bash
plutil -lint ~/Desktop/payload.mobileconfig
```

### Read all key-value pairs

```bash
defaults read com.apple.screensaver
```

### Write a complex value

```bash
defaults write com.example.app.plist ServerList -array-add \
  -dict-add hostname "dc01.corp.example.com" \
  -dict-add port 389 \
  -dict-add useTLS true
```

### Watch a plist for changes

```bash
sudo fs_usage -w -f filesys | grep plist
```

## Kerberos management

### Get TGT

```bash
kinit jsmith@CORP.EXAMPLE.COM
```

### List tickets

```bash
klist -v
```

Output:
```
Credentials cache: API:1A2B3C4D-...
        Principal: jsmith@CORP.EXAMPLE.COM

  Issued                Expires               Principal
  Aug 13 09:14:33 2026  Aug 13 19:14:33 2026  krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM
        Flags: 0x40 (F)
        Etype: aes256-cts-hmac-sha1-96
        Addresses: ...
        Ticket: [...]
  Aug 13 09:14:45 2026  Aug 13 19:14:33 2026  cifs/file01.corp.example.com@CORP.EXAMPLE.COM
        Flags: 0x00
        Etype: aes256-cts-hmac-sha1-96
```

### Get a service ticket

```bash
kvno cifs/file01.corp.example.com@CORP.EXAMPLE.COM
kvno -S cifs file01.corp.example.com
```

### Renew

```bash
kinit -R
```

### Destroy

```bash
kdestroy
kdestroy -A   # all caches
```

### Change password (kpasswd, RFC 3244)

```bash
kpasswd jsmith@CORP.EXAMPLE.COM
```

### Switch CCACHE types (file vs API vs KCM)

macOS default is `API:` (in-memory, per-session). To use a file CCACHE for compatibility with scripts:

```bash
export KRB5CCNAME=FILE:/tmp/krb5cc_$(id -u)
kinit jsmith@CORP.EXAMPLE.COM
```

### Inspect CCACHE type

```bash
klist -c        # shows CCACHE name and type
```

## `sso_util` recipes (Platform SSO Extension)

macOS 13+ ships `sso_util` for PSSO Extension configuration. The Extension is installed via MDM profile; `sso_util` then configures it per-realm.

### Configure PSSO for AD

```bash
sudo sso_util configure -a active_directory \
  -r corp.example.com \
  -u admin \
  -p 'P@ss!'
```

Flags:
| Flag | Purpose |
|---|---|
| `-a <type>` | Authority type: `active_directory`, `azure`, `google`, `radius`, `saml` |
| `-r <realm>` | Kerberos realm (uppercase for AD) |
| `-u <user>` | AD user with join rights |
| `-p <pass>` | Password |
| `-f` | Force reconfigure |
| `-s` | Silent (no prompts) |

### Configure PSSO for Azure AD (Entra ID)

```bash
sudo sso_util configure -a azure -r corp.onmicrosoft.com
```

### List configured authorities

```bash
sso_util list
```

Output:
```
Authority: active_directory
Realm: CORP.EXAMPLE.COM
Status: configured
SSO Extension: com.apple.applesso
```

### Show current ticket cache state

```bash
sso_util cache -l
```

Output:
```
realm: CORP.EXAMPLE.COM
principal: jsmith@CORP.EXAMPLE.COM
expiry: 2026-08-13 19:14:33 +0000
flags: F (forwardable)
```

### Force re-authentication

```bash
sso_util cache -d            # purge current
sso_util cache -r            # re-auth (prompts for password)
```

### Remove PSSO configuration

```bash
sudo sso_util remove -r corp.example.com
```

## `dsimport` / `dsexport` — bulk user operations

### Export users from local node

```bash
dsexport /tmp/users.txt /Local/Default dsRecTypeStandard:Users
```

### Inspect export format

```bash
head -3 /tmp/users.txt
```

```
dsRecTypeStandard:Users 4
dsAttrTypeStandard:RecordName dsAttrTypeStandard:UniqueID dsAttrTypeStandard:NFSHomeDirectory dsAttrTypeStandard:UserShell
root:0:/var/root:/bin/sh
daemon:1:/var/root:/usr/bin/false
```

### Import users from CSV → dsimport format

```bash
dsimport /tmp/newusers.txt /Local/Default O
```

Import modes (`O` = append/overwrite, `I` = append if not exist, `A` = replace all):

```
dsimport <file> <node> <mode> [-u <user>] [-p <pass>] [-o <opts>]
```

### Bulk-create local users from a script

```bash
cat > /tmp/users.txt << 'EOF'
dsRecTypeStandard:Users 5
dsAttrTypeStandard:RecordName dsAttrTypeStandard:UniqueID dsAttrTypeStandard:PrimaryGroupID dsAttrTypeStandard:NFSHomeDirectory dsAttrTypeStandard:UserShell
alice:501:20:/Users/alice:/bin/bash
bob:502:20:/Users/bob:/bin/bash
EOF

sudo dsimport /tmp/users.txt /Local/Default I
```

## Network / connection troubleshooting

### List AD-related connections

```bash
lsof -i :88        # Kerberos
lsof -i :389       # LDAP
lsof -i :445       # SMB
lsof -i :3268      # Global Catalog
lsof -i :135       # RPC EPM
lsof -i :53        # DNS
lsof -i :123       # NTP
```

Output (sample):
```
COMMAND   PID   USER  FD  TYPE  DEVICE  SIZE/OFF  NODE NAME
ntpd     234   root  20u  IPv4  0x...   0t0  UDP dc01.corp.example.com:ntp
DirectoryService 887 root 30u IPv4 0x... 0t0  TCP host01.corp.example.com:54321→dc01.corp.example.com:ldap (ESTABLISHED)
```

### Established AD sessions

```bash
netstat -an | grep ESTABLISHED | grep -E '\.(389|88|445|3268|135)$'
```

### DNS lookup of AD SRV records

```bash
dig SRV _ldap._tcp.dc._msdcs.corp.example.com +short
dig SRV _kerberos._tcp.dc._msdcs.corp.example.com +short
dig SRV _ldap._tcp.gc._msdcs.corp.example.com +short
dig SRV _ldap._tcp.HQ._sites.dc._msdcs.corp.example.com +short
```

### Test LDAP bind with GSSAPI

```bash
ldapsearch -H ldap://dc01.corp.example.com -Y GSSAPI \
  -b "DC=corp,DC=example,DC=com" \
  "(sAMAccountName=jsmith)" displayName
```

### Verify Kerberos auth to SMB share

```bash
smbutil view //dc01.corp.example.com/jsmith
mount_smbfs //jsmith@file01/share /mnt/share
```

### Unified log streaming for AD/Kerberos

```bash
# All Kerberos-related
log show --predicate 'subsystem == "com.apple.Kerberos"' --last 1h --info --debug

# OpenDirectory
log show --predicate 'subsystem == "com.apple.opendirectoryd"' --last 1h

# PSSO Extension
log show --predicate 'process == "sso_extension"' --last 1h

# Live streaming
log stream --predicate 'subsystem CONTAINS "Kerberos" OR subsystem CONTAINS "opendirectory"'
```

### Force OpenDirectory to reload AD binding

```bash
sudo killall -HUP opendirectoryd
sudo dscacheutil -flushcache
```

## See also

- [../08-macos-equivalents/02-dscl-dsconfigad.md](../08-macos-equivalents/02-dscl-dsconfigad.md) — `dscl`/`dsconfigad` deep-dive.
- [../08-macos-equivalents/04-platform-sso-extension.md](../08-macos-equivalents/04-platform-sso-extension.md) — PSSO Extension architecture.
- [../08-macos-equivalents/05-kerberos-sso-extension.md](../08-macos-equivalents/05-kerberos-sso-extension.md) — Kerberos SSO Extension.
- [../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md](../08-macos-equivalents/09-mac-mdm-gpo-equivalents.md) — MDM payloads as GPO equivalents.
- [../10-comparison-matrices/03-tool-function-matrix.md](../10-comparison-matrices/03-tool-function-matrix.md) — cross-platform tool matrix.
- [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) — Kerberos wire protocol.
