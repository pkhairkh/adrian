---
title: dscl & dsconfigad — Local-Node Inspector and the AD Binding CLI
audience: senior-engineers
tags: [dscl, dsconfigad, dsmemberutil, ad-binding, opendirectory, macos]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ./01-opendirectory-internals.md
  - ./03-jamf-connect-pro.md
  - ./04-platform-sso-extension.md
  - ./05-kerberos-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

`dscl` is a single binary (`/usr/bin/dscl`) that wraps every `ODNode*` and `ODRecord*` call in `OpenDirectory.framework` behind an interactive or scripted verb-noun syntax; `dsconfigad` (`/usr/sbin/dsconfigad`) is the supported CLI for binding a Mac to an Active Directory domain, persisting its configuration in `/Library/Preferences/DirectoryService/ActiveDirectoryDomains.plist` and the OD plug-in config plists, and toggling post-bind options (SSO, mobile accounts, custom AD site).

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ /usr/bin/dscl    (CLI)        /usr/sbin/dsconfigad   (CLI)   │
│  Interactive + scripted        Wraps dsconfigad framework     │
└──────────────┬─────────────────────────────┬─────────────────┘
               │ ODNode* / ODRecord*         │ CFPropertyList +
               │ via OpenDirectory.framework │ ODConfiguration APIs
               ▼                             ▼
        ┌──────────────────────────────────────────┐
        │ OpenDirectory.framework (client stub)    │
        │  - ODNodeCopyDetails, ODRecordCopyValues │
        │  - ODConfigurationAddLDAPServer,         │
        │    ODConfigurationSetActiveDirectoryInfo │
        └──────────────────────┬───────────────────┘
                               │ XPC
                               ▼
                      ┌────────────────────────┐
                      │   opendirectoryd       │
                      │ (DSP.ActiveDirectory   │
                      │  + DSP.local plug-ins) │
                      └─────────┬──────────────┘
                                │
                ┌───────────────┼────────────────┐
                ▼               ▼                ▼
        /var/db/dslocal    AD DC (LDAP 389,   Local KDC
        (local records)    Kerberos 88,
                            SMB 445, CLDAP 389)
```

- `dscl` is implemented in the Apple sources as a thin wrapper around `ODNode`/`ODRecord` C functions; verbs (`read`, `list`, `create`, `append`, `delete`, `search`, `auth`) map one-to-one to framework entry points.
- `dsconfigad` exists historically in two halves: the CLI binary and the `OpenDirectory.framework` private `ODConfiguration` API (declared in the public `ODConfiguration.h` since 10.9). The CLI serialises its inputs into an `ODConfigurationRef`, calls `ODConfigurationSetActiveDirectoryInfo`, then commits the change via `ODConfigurationCommit`, which writes the relevant plist and tells `opendirectoryd` to refresh the AD plug-in.

## Node selection — the first argument

The first non-flag argument to `dscl` selects the node. Three forms cover 99% of real usage:

| Argument | Resolves to | Plug-in | Typical use |
|---|---|---|---|
| `.` (dot) | `/Local/Default` | local | Reading and editing local user/group plists. |
| `/Local/Default` | `/Local/Default` | local | Same as `.`; explicit form. |
| `/Active Directory` | aggregator | AD | List all bound AD domains. |
| `/Active Directory/CORP` | one AD domain | AD | Read/search AD objects via LDAP on the DC. |
| `/LDAPv3/127.0.0.1` | LDAP server node | LDAPv3 | Read an OpenLDAP/389-DS instance. |
| `/Search` | meta search path | (composite) | Cross-node lookup; the path the OS uses by default for `id`. |
| `/Contacts` | contacts-only path | (composite) | Only Contacts.app consults this. |
| `localhost` | enumeration root | (special) | `dscl localhost -list .` lists all available nodes. Equivalent to `dscl / -list .`. |

## Verbs — what they map to

```
dscl <node> -list   <record-path> [<attr>]                  # ODNodeCopyRecords
dscl <node> -read   <record-path> [<attr>...]               # ODRecordCopyValues
dscl <node> -search <record-path> <key> <value>             # ODNodeCopyRecords with query
dscl <node> -create <record-path> [<key> <value>...]        # ODNodeCreateRecord + ODRecordAddValue
dscl <node> -append <record-path> <key> <value>             # ODRecordAddValue (multi-valued)
dscl <node> -merge  <record-path> <key> <value>             # same as -append
dscl <node> -change <record-path> <key> <old> <new>         # ODRecordRemoveValue + ODRecordAddValue
dscl <node> -delete <record-path> [<key> [<value>]]         # ODRecordRemoveValue or ODRecordDelete
dscl <node> -auth   <record-path> <password>                # ODRecordVerifyPassword
dscl <node> -authonly <user> <password>                     # ODSessionVerifyCredentials
dscl <node> -passwd <record-path> <newpassword>             # ODRecordSetPassword
```

All paths under a node are typed: `/Users`, `/Groups`, `/Computers`, `/ComputerGroups`, `/Aliases`, `/SharedServices`, `/PresetUsers`, `/PresetGroups`, `/Config`, `/Machines`, `/Networks`, `/Servers`, `/Printers`, `/PrintService`, `/NFS`, `/Mounts`, `/Hosts`. Each is an OD record type.

## dsconfigad — binding

The bare-minimum bind command on a stock macOS:

```sh
sudo dsconfigad -a "MAC01" \
   -domain "corp.example.com" \
   -ou "CN=Computers,DC=corp,DC=example,DC=com" \
   -u "domainjoin-svc" \
   -p "<password>" \
   -mobile enable \
   -mobileconfirm disable \
   -localhome enable \
   -useuncpath enable \
   -shell "/bin/zsh" \
   -preferred "CORP-DC-01" \
   -groups "CORP\Mac-Admins"
```

What this does, step by step:

1. **DC locator** — `dsconfigad` calls `dscl /Active Directory -create ...` indirectly via the AD plug-in, which performs a CLDAP netlogon query (`cldap` filter for `DsaGetName` of the domain) against the domain DNS name. If a preferred DC is supplied, the locator skips DNS and uses that host.
2. **Kerberos init** — obtains a TGT for the joining user using `kinit`-equivalent Heimdal calls inside the AD plug-in.
3. **Computer-object create or reset** — uses LDAP over GSSAPI to the DC against the supplied `-ou`. If the computer object already exists (leftover from a previous bind), the join sets `userAccountControl` back to `WORKSTATION_TRUST_ACCOUNT` and rotates the trust password (`unicodePwd`) using the existing account's credentials.
4. **Keytab write** — the new machine-account password is written to `/etc/krb5.keytab` (system keytab) and into the system keychain item `/Library/Keychains/System.keychain` under the account name `mac01$@CORP.EXAMPLE.COM`.
5. **Plist persistence** — `/Library/Preferences/DirectoryService/ActiveDirectoryDomains.plist` is updated with the new domain entry; `/Library/Preferences/OpenDirectory/Configurations/Active Directory/CORP.plist` is written with the per-domain config (AD site, preferred DC, mobile account policy, GPO fetch flags).
6. **Node refresh** — `opendirectoryd` is signalled to reload AD plug-in state. `/Active Directory/CORP` becomes queryable immediately.

## dsconfigad flags (canonical table)

| Flag | Effect |
|---|---|
| `-a <computer-name>` | Bind with this computer name (used as `sAMAccountName` on the new computer object). |
| `-domain <fqdn>` | Target AD domain. |
| `-ou <dn>` | OU/container in which to create the computer object. Default `CN=Computers,...`. |
| `-u <user>` | Domain account with rights to join computers. |
| `-p <password>` | Password for `-u`. Use `-p -` to read from stdin. |
| `-mobile <enable\|disable>` | Allow mobile accounts (cached AD credentials, portable home dir). |
| `-mobileconfirm <enable\|disable>` | Prompt the user at first login to create a mobile account. |
| `-localhome <enable\|disable>` | Force home directory onto local `/Users/<user>`. |
| `-useuncpath <enable\|disable>` | Derive `NFSHomeDirectory` from the AD `homeDirectory` UNC (`\\server\share\user`). |
| `-homeprotocol <smb\|afp\|nfs>` | URL scheme to prepend when converting UNC to home URL. |
| `-home <mount>` | Explicit home share. |
| `-shell <path>` | Default shell for AD users (default `/bin/zsh` on 14.x). |
| `-preferred <dc-fqdn>` | Pin to a single DC. Bypasses locator after first bind. |
| `-groups <group-list>` | Comma-separated list of AD groups the local admin tools treat as local admins (sets `dsAttrTypeStandard:ADGroupCache`). |
| `-namespace <domain\|forest>` | UID/GID uniqueness scope: per-domain or forest. |
| `-enablesso` | Enable Single Sign-On (Kerberos + NTLM SSO) for SMB/AFP and the Authorization framework. |
| `-packetsign <allow\|disable\|require>` | SMB signing policy. |
| `-packetencrypt <allow\|disable\|require>` | SMB encryption policy. |
| `-passinterval <days>` | Machine-account password rotation interval in days (default 30, matching AD). |
| `-passchange <enable\|disable>` | Allow the Mac to rotate its own machine-account password. |
| `-show` | Print current binding configuration. |
| `-remove <domain> -u <user> -p <password>` | Unbind and (optionally) delete the computer object. |

## Post-bind inspection

```sh
# one-shot view of the current binding
sudo dsconfigad -show

# plists on disk backing the binding
sudo plutil -p /Library/Preferences/DirectoryService/ActiveDirectoryDomains.plist
sudo plutil -p /Library/Preferences/DirectoryService/DSNODNSPlugInConfig.plist
sudo plutil -p "/Library/Preferences/OpenDirectory/Configurations/Active Directory/CORP.plist"

# equivalent via defaults (defaults cannot deal with some nested arrays; plutil -p is safer)
sudo defaults read /Library/Preferences/DirectoryService/ActiveDirectoryDomains
sudo defaults read /Library/Preferences/DirectoryService/DSNODNSPlugInConfig

# computer-account status on the AD side (via dscl)
dscl /Active Directory/CORP -read /Computers/MAC01$ \
   objectClass userAccountControl operatingSystem operatingSystemVersion \
   servicePrincipalName lastLogonTimestamp pwdLastSet

# ticket cache status — Heimdal kinit on macOS uses the API:... type by default
klist -v
sudo klist -v                              # host TGT / machine-account key in system keychain
sudo klist -k /etc/krb5.keytab             # system keytab
```

`DSNODNSPlugInConfig.plist` is shared by the AD and LDAPv3 plug-ins: it controls how OD resolves SRV records when the standard `/etc/resolv.conf` resolver is insufficient. Each entry maps a DNS suffix to a preferred KDC/LDAP server, used to override what `_ldap._tcp.dc._msdcs.<domain>` returns.

`ActiveDirectoryDomains.plist` is the master list of bound domains. Its root is a dictionary keyed by domain FQDN; each value is a dict with `AD Domain Controller`, `AD Domain Name`, `AD Site`, `Kerberos Domain`, and `Trust Account` (machine-account short name).

## `/Active Directory` magic node

The AD plug-in synthesises the `/Active Directory` aggregator node at daemon start. Querying it returns one entry per bound domain:

```sh
dscl /Active Directory -list .
# CORP
# SUB.CORP.EXAMPLE.COM
```

Sub-nodes are auto-created:

```
/Active Directory/CORP                      # one domain
/Active Directory/CORP/All Domains          # forest-GC aggregate (queries LDAP port 3268)
/Active Directory/CORP/GlobalAddressList    # Exchange GAL subset
/Active Directory/CORP/Domain Contacts      # mail-enabled contacts only
```

## Membership checks — dsmemberutil, id, groups

`dsmemberutil` (`/usr/bin/dsmemberutil`) is the supported way to test group membership without writing it yourself. It bypasses NSS caching and queries `opendirectoryd` directly through `ODNodeCopyRecords`.

```sh
# does UID 502 belong to GID 20?
sudo dsmemberutil checkmembership -u 502 -g 20

# does the user with GeneratedUID AB12CD34-… belong to group with GUID …?
sudo dsmemberutil checkmembership -x AB12CD34-...-... -X EF567890-...-...

# enumerate all groups for a user
sudo dsmemberutil getgroups -u 502

# flush the membership cache (held inside opendirectoryd)
sudo dsmemberutil flushcache
```

The plain `id` and `groups` commands resolve through `getpwuid`/`getgrgid` via `libsystem_info.dylib`, which consults the `passwd`/`group` nsswitch sources — on macOS the only nsswitch source is `opendirectoryd`. So `id alice` is equivalent to `dscl /Search -read /Users/alice UniqueID PrimaryGroupID` followed by `dscl /Search -search /Groups GeneratedUID <user-guid>` and group-enumeration lookups.

## Examples — common admin tasks

```sh
# Local: create a local service account with a fixed UID and home directory
sudo dscl . -create /Users/buildbot
sudo dscl . -create /Users/buildbot UserShell /bin/zsh
sudo dscl . -create /Users/buildbot NFSHomeDirectory /Users/buildbot
sudo dscl . -create /Users/buildbot UniqueID 510
sudo dscl . -create /Users/buildbot PrimaryGroupID 20
sudo dscl . -create /Users/buildbot RealName "Build Bot"
sudo dscl . -passwd /Users/buildbot '<password>'

# Local: add alice to the admin group
sudo dscl . -append /Groups/admin GroupMembership alice
sudo dscl . -append /Groups/admin GroupMembers <alice-GeneratedUID>

# AD: list all bound users (cached mobile accounts + live AD users via /Search)
dscl /Search -list /Users UniqueID

# AD: search for a user by surname
dscl /Active Directory/CORP -search /Users RealName "*Smith*"

# AD: read the user's group membership (memberOf + primaryGroupID)
dscl /Active Directory/CORP -read /Users/asmith memberOf primaryGroupID

# AD: change AD password from the Mac (requires 'Reset Password' right on asmith)
dscl /Active Directory/CORP -passwd /Users/asmith '<new-password>'

# Confirm the host still has a valid machine-account TGT
sudo klist -v | grep -E 'krbtgt|host/'
```

## Troubleshooting

- **`dsconfigad` errors "Authentication server could not be contacted"** — the CLDAP locator failed. Test with `dig +short _ldap._tcp.dc._msdcs.corp.example.com SRV` and `ldapsearch -LLL -H ldap://corp-dc-01.corp.example.com -Y GSSAPI -b "" -s base -n`. If DNS is right but CLDAP fails, the AD plug-in may be cached on a dead DC — `sudo killall -HUP opendirectoryd`.
- **Binding succeeds but `/Active Directory/CORP` is empty** — daemon did not reload. `sudo killall -HUP opendirectoryd` then `dscl /Active Directory -list .`. If still empty, check `/var/log/opendirectoryd.log` (`sudo log show --predicate 'process == "opendirectoryd"' --info`).
- **`id <ad-user>` returns `no such user`** — `/Search` policy excludes the AD node. Inspect `Search.plist`:
  ```sh
  sudo plutil -p /Library/Preferences/OpenDirectory/Configurations/Search.plist
  ```
  If `/Active Directory/CORP` is missing from `Search Policy`, re-add via `dscl /Search -create / CSPSearchPath /Active Directory/CORP` (or re-run `dsconfigad` with `-enablesso`).
- **Mobile account login fails after password change in AD** — the cached credential hash is stale. Delete the local cached credentials with `sudo dscl . -delete /Users/<user> AuthenticationAuthority` (carefully) and re-login to rebuild, or use `fdesetup authrestart` if FileVault is on.
- **`klist` shows expired TGT for the host** — machine-account password rotation may have desynced. Reset the computer account in AD (`Reset-ADAccountPassword -Identity MAC01$`), then `sudo dsconfigad -force -remove "corp.example.com"` and rebind.
- **`dsmemberutil checkmembership` returns "user is not a member of group" but `id` shows the group** — cache desync. Run `sudo dsmemberutil flushcache && sudo dscacheutil -flushcache`.

## Wire-protocol diagnostics

When a bind is failing, the most diagnostic capture is CLDAP (UDP 389) and Kerberos (TCP 88) from the Mac to the DC:

```
# CLDAP netlogon for the domain
cldap && cldap.filter.domain == "corp.example.com"

# Kerberos AS-REQ the joining user issues to obtain a TGT
kerberos.msg_type == 10 && kerberos.CNameString == "domainjoin-svc"

# LDAP simple bind for the computer-object create/modify
ldap.messageType == 0 && ldap.bind_mechanism == "simple"

# the LDAP search the AD plug-in does to enumerate user objects
ldap.messageType == 3 && ldap.filter contains "sAMAccountName"
```

## Cross-platform comparison

- **AD counterpart** — `dscl /Active Directory/CORP` is the macOS analogue of `Get-ADUser`/`Get-ADComputer` ([`../01-ad-core/01-ad-ds-internals.md`](../01-ad-core/01-ad-ds-internals.md)) but operating from a member machine rather than from a management host with RSAT. `dsconfigad` is the macOS analogue of Windows' `Add-Computer -DomainName corp.example.com -Credential (Get-Credential)` plus the per-machine registry policy under `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`. The CLDAP and Kerberos traffic is identical to what a Windows member server emits, as documented in [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md) and [`../02-protocols/02-ldap-protocol.md`](../02-protocols/02-ldap-protocol.md).
- **Linux counterpart** — `realm join` (from `realmd`) is the rough analogue of `dsconfigad`; it produces `sssd.conf` entries and a `/etc/krb5.keytab`. The local-node side of `dscl .` has no real Linux equivalent — `useradd`/`usermod` operate on `/etc/passwd`/`/etc/shadow` directly. See [`../09-linux-equivalents/01-sssd-ad-provider.md`](../09-linux-equivalents/01-sssd-ad-provider.md) and [`../09-linux-equivalents/09-openldap-mit-kerberos.md`](../09-linux-equivalents/09-openldap-mit-kerberos.md).
- **High-level side-by-side** — [`../10-comparison-matrices/01-feature-os-matrix.md`](../10-comparison-matrices/01-feature-os-matrix.md).

## References

- `dscl` manpage — `man dscl` (macOS 14+, documents the full verb set and node selection syntax).
- `dsconfigad` manpage — `man dsconfigad`.
- `dsmemberutil` manpage — `man dsmemberutil`.
- `OpenDirectory.framework` public header `ODConfiguration.h` — `/System/Library/Frameworks/OpenDirectory.framework/Headers/ODConfiguration.h`.
- Apple Developer doc — "Active Directory integration on Mac" (administrative guide, current through macOS 14).
- Microsoft doc — "Join a computer to a domain" (`Add-Computer`) for the Windows-side analogue.
- `realmd` project — `realm(8)` and `/etc/realmd.conf` for the Linux-side binding workflow.
