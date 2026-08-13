---
title: samba-tool and net ads — Domain Management CLI for Linux Members and Samba DCs
audience: senior-engineers
tags: [samba-tool, net-ads, libads, ms-drsr, keytab, smb-conf, machine-account]
related:
  - ./01-sssd-ad-provider.md
  - ./04-winbind-internals.md
  - ./06-realmd-join-flow.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
last_updated: 2026-08-13
---

`samba-tool` is the Samba4-era Python/C management CLI for Samba AD DCs and members, while `net ads` (built on `libads` in `source3/libads/`) is the older Samba3-era family of commands targeting AD member operations — both share `secrets.tdb` and `/etc/krb5.keytab` as the machine-account state and both speak LDAP+Kerberos+MS-DRSR (`samba-tool drs`) + MSRPC (`net ads`) to the DC, with `samba-tool domain exportkeytab` being the canonical way to extract TDO/machine keys from a Samba DC.

## Two CLIs, two lineages

| Tool | Origin | Target | Implementation |
|---|---|---|---|
| `samba-tool` | Samba4 (Lattice/AD-compatible DC) | Samba AD DC, but most subcommands work against a Windows DC too | Python (`python/samba/`), calls into `libpython-samba` which wraps the Samba C libraries |
| `net ads` | Samba3 (NT4-style member + AD member) | Windows AD or Samba AD DC | C, `source3/utils/net_ads.c`, `source3/libads/` |
| `net rpc` | Samba3 | NT4 / older Samba | C, MSRPC over ncacn_np |
| `net sam` | Samba3 | Local SAM (passdb) | C, `source3/utils/net_sam.c` |

Both ultimately rely on `smb.conf` `[global]` for `realm`, `workgroup`, `security`, `kerberos method`. `samba-tool` additionally reads from `smb.conf` `private dir =` for `secrets.tdb` and `sam.ldb` (DC mode).

## `samba-tool` subcommand map

| Subcommand | Purpose | Backend protocol |
|---|---|---|
| `samba-tool domain provision` | Provision a new Samba AD DC (creates `sam.ldb`, `secrets.tdb`, DNS zones, etc.) | Local only |
| `samba-tool domain join` | Join as a DC to an existing AD forest | MS-DRSR (replicate NCs from a source DC) — see `source4/libnet/libnet_vampire.cc:libnet_vampire_cb_pull_check` |
| `samba-tool domain demote` | Demote a Samba DC | MS-DRSR `DSARecv`/`DSABind` |
| `samba-tool domain level show` / `set` | Domain/forest functional level | LDAP `msDS-Behavior-Version` |
| `samba-tool domain passwordsettings set` | Password policy (PdP) | LDAP on `CN=Default Domain Policy,CN=System,<domain>` |
| `samba-tool domain exportkeytab` | Export all KDC keys to a keytab (DC-only) | Reads from `secrets.tdb` + `hklm.ldb` |
| `samba-tool user add` / `delete` / `list` / `setpassword` / `disable` / `enable` | User lifecycle | LDAP / SAMR |
| `samba-tool user setexpiry` / `setpassword` / `getpassword` | Account flags | LDAP on `userAccountControl`, `unicodePwd`, `pwdLastSet` |
| `samba-tool user create <user> <password> --given-name=… --surname=… --userou=…` | Create with attributes | LDAP Add |
| `samba-tool group add` / `delete` / `list` / `addmembers` / `removemembers` / `listmembers` | Group lifecycle | LDAP |
| `samba-tool dns add` / `delete` / `query` / `update` / `zonelist` / `serverinfo` | Manage AD-integrated DNS | MS-DRSR `DNSServer` interface — `source4/torture/drs/rpc/dnsserver.py` — see `../02-protocols/05-dns-dynamic-updates.md` |
| `samba-tool drs showrepl` / `replicate` / `kcc` / `bindinfo` / `options` | Replication diagnostics | MS-DRSR DRSUAPI (UUID E3514235-8B63-11D0-A26C-00A0C92B955C) — see `../02-protocols/06-rpc-dcerpc-ms-drsr.md` |
| `samba-tool fsmo show` / `transfer` / `seize` | FSMO role management | LDAP modify on `fSMORole` attribute + MS-DRSR |
| `samba-tool ntacl get` / `set` / `sysvolreset` / `sysvolcheck` | POSIX ACL ↔ NT ACL mapping on SYSVOL | Local only (XATTR `security.NTACL`) |
| `samba-tool gpo list` / `fetch` / `create` / `link` / `unlink` / `setinheritance` | Group Policy Objects | LDAP on `CN=Policies,CN=System,<domain>` + SMB fetch |
| `samba-tool spn add` / `delete` / `list` | ServicePrincipalName management | LDAP modify `servicePrincipalName` — see `../02-protocols/08-spn-upn-pac.md` |
| `samba-tool computer create` / `delete` / `list` | Computer objects | LDAP |
| `samba-tool sites create` / `list` / `subnet create` | AD sites & subnets | LDAP on `CN=Sites,CN=Configuration,<forest>` |
| `samba-tool ou create` / `delete` / `list` | Organizational units | LDAP |
| `samba-tool rodc preload` | RODC password replication | MS-DRSR + LDAP `msDS-RevealedUsers` |
| `samba-tool ldapcmp <dc1> <dc2>` | Compare NC contents between two DCs | LDAP |
| `samba-tool processes` (DC only) | List open LDAP sessions / SAM connections | LDB query |

### Key source paths (Samba)

- `source4/scripting/python/samba/netcmd/__init__.py` — `samba-tool` entry, dispatches subcommands.
- `source4/scripting/python/samba/netcmd/domain.py:cmd_domain_join` — `samba-tool domain join`.
- `source4/scripting/python/samba/netcmd/drs.py:cmd_drs_showrepl` — DRS diagnostics.
- `source4/scripting/python/samba/netcmd/dns.py` — DNS management via `source4/librpc/rpc/dnsserver.py`.
- `source4/libnet/libnet_vampire.cc:libnet_vampire_cb_pull_check` — MS-DRSR replication engine.
- `source4/rpc_server/drsuapi/` — DRSUAPI server (Samba DC side).
- `librpc/idl/drsuapi.idl` — DRSUAPI IDL definitions.
- `source3/utils/net_ads.c:net_ads_join` — `net ads join` C implementation.
- `source3/libads/ldap.c:ads_add_machine_acct` — create computer object via LDAP.
- `source3/libads/kerb_util.c:ads_keytab_add_entry` — write `krb5.keytab` entries.
- `source3/libads/util.c:ads_find_dc` — DC locator (DNS SRV + CLDAP ping).

## `net ads` subcommand map

| Subcommand | Purpose | Wire protocol |
|---|---|---|
| `net ads join` | Join the host as a computer object | LDAP Add + `setMachinePassword` + keytab write |
| `net ads testjoin` | Verify the machine account secret works | LDAP bind as `HOSTNAME$` |
| `net ads leave` | Delete the computer object (or just stop using it with `--keep-account`) | LDAP Del |
| `net ads info` | Print DC info (forest, domain, site) | CLDAP ping (`ldap_ping` in `source3/libads/ldap.c:ads_cldap_ping`) |
| `net ads status` | Dump the computer object LDAP attributes | LDAP Search |
| `net ads user` / `net ads group` | List users / groups via SAMR | MSRPC SAMR |
| `net ads password <user>` | Reset a user's password (admin) | LDAP modify `unicodePwd` |
| `net ads changetrustpw` | Rotate the machine account password (refresh trust) | `NetrServerPasswordSet2` over NETLOGON — `source3/libads/ldap.c:ads_change_trust_account_password` |
| `net ads keytab create` | Regenerate `/etc/krb5.keytab` from `secrets.tdb` | Local |
| `net ads keytab add <SPN>` | Add an SPN and its key to the keytab | LDAP modify + keytab write |
| `net ads kerberos pac <user>` | Decode a PAC for a service ticket obtained for `<user>` | Kerberos TGS-REQ + PAC decode |
| `net ads lookup` | DC locator (CLDAP) | CLDAP ping |
| `net ads dns register` | Dynamically register host A/AAAA records in AD-integrated DNS | RFC 3645 GSS-TSIG dynamic update — see `../02-protocols/05-dns-dynamic-updates.md` |
| `net ads dns unregister` | Remove the host's A records | DNS dynamic update (delete) |
| `net ads search <filter> <attr>` | One-shot LDAP search as the machine account | LDAP Search |
| `net ads samcreate` / `samdelete` | Create/delete machine account only (no keytab) | LDAP Add/Del |
| `net ads setspn` | SPN management (alias for `samba-tool spn` style ops) | LDAP modify |
| `net ads workgroup` / `net ads dn` / `net ads dnldap` | Domain info queries | LDAP |

## Configuration — `/etc/samba/smb.conf` (member)

```
[global]
   workgroup = CORP
   realm = CORP.EXAMPLE.COM
   security = ads
   client use spnego = yes
   client ntlmv2 auth = yes

   kerberos method = secrets and keytab
   dedicated keytab file = /etc/krb5.keytab

   # DC locator
   password server = dc01.corp.example.com, dc02.corp.example.com
   # OR leave blank to use DNS SRV discovery

   log level = 3 ads:5
   log file = /var/log/samba/log.%m
```

For a Samba AD DC `smb.conf` looks different (no `security = ads` — it IS the DC) and includes `server role = active directory domain controller`, `dns forwarder = …`, `idmap_ldb:use rfc2307 = yes`, plus `[sysvol]` and `[netlogon]` shares.

## Commands / examples

### Join and keytab lifecycle

```bash
# 1. Join as a member server (creates computer object + writes /etc/krb5.keytab)
sudo net ads join -U admin
# Output: Joined 'HOST01' to dns domain 'corp.example.com'
#         Using short domain name -- CORP
#         Set 'msDS-SupportedEncryptionTypes' to (0x1F) for HOST01$

# 2. Join to a specific OU and advertise OS info
sudo net ads join -U admin \
  createcomputer="OU=LinuxServers,DC=corp,DC=example,DC=com" \
  osName='Ubuntu 22.04 LTS' osVer=22.04

# 3. Verify the secret
sudo net ads testjoin
# Output: Join is OK

# 4. Inspect the machine account object
sudo net ads status -P | less

# 5. Rotate machine-account password (Windows DCs do this every 30 days by default)
sudo net ads changetrustpw
# Output: Password for principal HOST01$@CORP.EXAMPLE.COM changed.

# 6. Regenerate the keytab from the local secret
sudo net ads keytab create -U admin
# Creates /etc/krb5.keytab with: HOST01$@CORP.EXAMPLE.COM (des,rc4,aes128,aes256),
#                                  HOST/host01.corp.example.com@CORP.EXAMPLE.COM,
#                                  HOST/HOST01@CORP.EXAMPLE.COM,
#                                  RestrictedKrbHost/HOST01@...,RestrictedKrbHost/host01.corp.example.com@...

# 7. Add a custom SPN and its key
sudo net ads keytab add HTTP/web01.corp.example.com -U admin
sudo net ads keytab add nfs/web01.corp.example.com -U admin

# 8. Inspect the keytab
klist -k /etc/krb5.keytab
sudo ktutil -k /etc/krb5.keytab list

# 9. Leave the domain
sudo net ads leave -U admin              # also deletes the computer object
sudo net ads leave --keep-account -U admin   # leave keytab/local secret, keep AD object
```

### `samba-tool` on a Samba AD DC

```bash
# Provision a new forest root
sudo samba-tool domain provision --use-rfc2307 --interactive \
  --realm=CORP.EXAMPLE.COM --domain=CORP --adminpass='P@ssw0rd!' \
  --server-role=dc --dns-backend=SAMBA_INTERNAL

# Show replication status
sudo samba-tool drs showrepl
sudo samba-tool drs replicate dc02 dc01 DC=corp,DC=example,DC=com
sudo samba-tool drs kcc dc01                          # trigger KCC

# FSMO
sudo samba-tool fsmo show
sudo samba-tool fsmo transfer --role=pdc-emulator -H ldap://dc02 -U admin

# Export all domain-account keys to a keytab (DC-only — useful for service accounts)
sudo samba-tool domain exportkeytab --principal=HTTP/web01.corp.example.com \
  /etc/krb5.keytab.http
# Full keytab of all principals (very large):
sudo samba-tool domain exportkeytab /tmp/all.keytab

# User lifecycle
sudo samba-tool user create jsmith 'P@ssw0rd!' \
  --given-name=John --surname=Smith \
  --userou='OU=Staff,DC=corp,DC=example,DC=com' \
  --mail-address=john.smith@example.com
sudo samba-tool user setexpiry jsmith --noexpiry
sudo samba-tool user disable jsmith
sudo samba-tool user setpassword jsmith --newpassword='NewP@ss!'

# Groups
sudo samba-tool group add LinuxAdmins --groupou='OU=Groups,DC=corp,DC=example,DC=com'
sudo samba-tool group addmembers LinuxAdmins jsmith,bsmith

# SPN management (compare with setspn on Windows)
sudo samba-tool spn add HTTP/web01.corp.example.com web01$
sudo samba-tool spn list web01$
sudo samba-tool spn delete HTTP/web01.corp.example.com web01$

# DNS management via MS-DRSR DNSServer RPC interface
sudo samba-tool dns add dc01 corp.example.com host01 A 10.0.0.10 -U admin
sudo samba-tool dns add dc01 corp.example.com host01 AAAA 2001:db8::10 -U admin
sudo samba-tool dns query dc01 corp.example.com @ ALL -U admin
sudo samba-tool dns zonelist dc01 -U admin

# GPO
sudo samba-tool gpo list --username=jsmith@corp.example.com
sudo samba-tool gpo fetch {31B2F340-016D-11D2-945F-00C04FB984F9} -o /tmp/gpo.zip
sudo samba-tool gpo link "OU=Servers,DC=corp,DC=example,DC=com" \
  {31B2F340-016D-11D2-945F-00C04FB984F9} 1

# SYSVOL NTACL reset (after restoring from backup)
sudo samba-tool ntacl sysvolreset
sudo samba-tool ntacl sysvolcheck
```

### PAC decoding

```bash
# Decode the PAC embedded in a service ticket obtained for user1
sudo net ads kerberos pac user1 -U user1%password
# Prints: KERB_VALIDATION_INFO fields, group SIDs, UPN/DNS info, signature types
# Useful to verify that the user's group memberships flow into the PAC for SSSD/Winbind access checks
# Full PAC structure documented in ../02-protocols/08-spn-upn-pac.md
```

### Computer password reset from AD (when host has lost sync)

```bash
# On a Windows admin host or from Linux with admin creds
# Reset the computer password to a known value:
sudo net ads password -U admin 'HOST01$' 'NewMachineP@ss!'
# Then on the Linux host, rejoin (which sets a new random password):
sudo net ads join -U admin
```

## Wireshark / tshark

```
# DCE/RPC over SMB for net ads user/group (SAMR)
smb2.filename contains "samr" && dcerpc

# CLDAP ping (net ads info, net ads lookup)
cldap

# LDAP Add (net ads join — computer account creation)
ldap.messageCode == 8

# LDAP modify (net ads keytab add, spn add)
ldap.messageCode == 6

# Kerberos TGS-REQ for the host's own machine account (during changetrustpw)
kerberos.msg_type == 12 && kerberos.SName contains "HOST01$"

# DNS dynamic update (net ads dns register)
dns.flags.response == 0 && dns.count.queries == 1 && dns.qry.name contains "corp.example.com"

# MS-DRSR DRSBind / DRSGetNCChanges (samba-tool drs replicate, samba-tool domain join)
dcerpc.pkt_type == 11 && dcerpc.drsuapi           # bind
dcerpc.drsuapi.opnum == 0                          # DRSBind
dcerpc.drsuapi.opnum == 3                          # DRSGetNCChanges
```

Capture everything:

```bash
sudo tshark -i eth0 -f 'host dc01.corp.example.com and (tcp port 88 or tcp port 389 or tcp port 445 or tcp port 53 or udp port 53 or udp port 389)' \
  -Y 'kerberos || ldap || dcerpc || dns || cldap' -V
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `net ads join` fails with `Failed to set password for machine account (NT_STATUS_LOGON_FAILURE)` | Hostname contains invalid chars (lowercase vs uppercase mismatch) | Use `--computer-name=HOST01` (uppercase) or edit `hostnamectl set-hostname host01.corp.example.com` |
| `net ads testjoin` fails after 30 days | Machine-account password rotation mismatch | `net ads changetrustpw` or rejoin |
| `net ads keytab create` produces empty keytab | `secrets.tdb` doesn't have the machine account password (e.g. host was never joined, or `secrets.tdb` was deleted) | `net ads join -U admin` first |
| `samba-tool drs showrepl` shows `Last attempt @ <date> was successful` but `Last success @ <old date>` | Replication in progress but last full success was earlier — usually transient | Re-run; if persistent, `samba-tool drs replicate` the failing NC |
| `samba-tool domain exportkeytab` writes `0 bytes` | Wrong principal case or `--principal` doesn't exist on the DC | `samba-tool spn list <account>` to verify |
| `net ads dns register` fails with `WERR_DNS_ERROR_RCODE` | Dynamic DNS update refused (zone is AD-integrated and host not authorized; or record exists with different owner) | Pre-create the A record or grant the machine account `Write` permission on its A record |
| `net ads kerberos pac` fails with `kinit: Preauthentication failed` | User password has expired or account locked out | `net ads user info <user>` or check ADUC |
| `samba-tool user create` fails with `LDAP error 53 (WILL_NOT_PERFORM)` | Password doesn't meet AD complexity policy | Use 3-of-4 character classes, ≥7 chars, no sAMAccountName substring |

Logs: `/var/log/samba/log.net`, `log.samba-tool`, `log.ads`, plus the general `log.smbd`/`log.winbindd` if those are running. With `log level = 10 ads:10`, `libads` LDAP messages are fully decoded.

## Cross-platform comparison

- **AD-side counterpart:** `net ads join` mirrors the Windows `Add-Computer -DomainName corp.example.com -Credential admin` PowerShell cmdlet (which internally calls `NetJoinDomain` API in `netapi32.dll`). `samba-tool drs replicate` mirrors `repadmin /sync` and `repadmin /replicate`. `samba-tool fsmo transfer` mirrors `ntdsutil roles transfer`. `samba-tool user create` mirrors `New-ADUser`. `samba-tool dns add` mirrors `Add-DnsServerResourceRecord` against AD-integrated DNS (which itself uses MS-DRSR DNSServer RPC). The MS-DRSR wire protocol is fully covered in `../02-protocols/06-rpc-dcerpc-ms-drsr.md`; Kerberos PAC decoding references `../02-protocols/08-spn-upn-pac.md`.
- **SSSD alternative:** `net ads join` is the Samba-only join path. SSSD users typically join via `realm join` → `adcli join` (`./06-realmd-join-flow.md`) which writes the same `/etc/krb5.keytab` but does not need `smb.conf` to be configured for member operation.
- **macOS counterpart:** `dsconfigad -add corp.example.com -username admin -password pass` performs the equivalent join from macOS — see `../08-macos-equivalents/02-dscl-dsconfigad.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- Samba source — https://github.com/samba-team/samba:
  - `source4/scripting/python/samba/netcmd/` — `samba-tool` Python sources.
  - `source3/utils/net_ads.c` — `net ads` C implementation.
  - `source3/libads/ldap.c`, `source3/libads/kerb_util.c`, `source3/libads/util.c` — `libads` library.
  - `source4/libnet/libnet_vampire.cc` — MS-DRSR replication engine.
  - `source4/rpc_server/drsuapi/` — DRSUAPI server (Samba DC).
  - `librpc/idl/drsuapi.idl` — DRSUAPI IDL definitions.
- `samba-tool(8)`, `net(8)`, `smb.conf(5)`, `kerberos method` documentation in `smb.conf(5)`.
- MS-DRSR, MS-SAMR, MS-LSAR, MS-NRPC, MS-DNSP protocol documentation.
- Samba Wiki — "Joining a Samba DC to an Existing Active Directory" and "Setting up Samba as a Domain Member".
