---
title: Administrative Function × Tool Matrix
audience: senior-engineers
tags: [matrix, tooling, commands, powershell, dscl, sssd, winbind, freeipa]
related:
  - ./01-feature-os-matrix.md
  - ./02-protocol-implementation-matrix.md
  - ../11-code-examples/01-powershell-ad-cmdlets.md
  - ../11-code-examples/02-sssd-conf-recipes.md
  - ../11-code-examples/03-macos-cli-recipes.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../09-linux-equivalents/08-freeipa-trust.md
last_updated: 2026-08-13
---

# Administrative Function × Tool Matrix

For each administrative function, the canonical command on Windows, macOS, SSSD-backed Linux, Winbind-backed Linux, and FreeIPA. Use this as a quick "how do I do X here?" lookup. Sibling: [01-powershell-ad-cmdlets.md](../11-code-examples/01-powershell-ad-cmdlets.md) for expanded PowerShell recipes; [03-macos-cli-recipes.md](../11-code-examples/03-macos-cli-recipes.md) for expanded macOS recipes.

## Function × Tool matrix

| Function | Windows (PowerShell + native) | macOS (dscl / dsconfigad / profiles) | Linux SSSD (realm / adcli / getent / kinit) | Linux Winbind (net ads / wbinfo) | Linux FreeIPA (ipa) |
|---|---|---|---|---|---|
| Find user | `Get-ADUser -Identity jsmith -Properties *` | `dscl /Active Directory/CORP -read /Users/jsmith` | `getent passwd jsmith` | `wbinfo -i CORP\\jsmith` | `ipa user-show jsmith` |
| List all users | `Get-ADUser -Filter * -Properties displayName` | `dscl /Active Directory/CORP -list /Users` | `getent passwd \| grep -i corp` | `wbinfo -u` | `ipa user-find` |
| Reset password | `Set-ADAccountPassword -Identity jsmith -NewPassword (ConvertTo-SecureString 'P@ss!' -AsPlainText -Force)` | `dscl /Active Directory/CORP -passwd /Users/jsmith 'P@ss!'` (requires diradmin) | `adcli reset-computer` (machine only; user pw via `kpasswd jsmith@REALM`) | `smbpasswd -r dc01 -U jsmith` (if available) | `ipa passwd jsmith` |
| List group members | `Get-ADGroupMember -Identity "Domain Admins"` | `dscl /Active Directory/CORP -read /Groups/"Domain Admins" GroupMembership` | `getent group "domain admins"` | `wbinfo -g` then `wbinfo --group-info "Domain Admins"` | `ipa group-show "Domain Admins"` |
| Add user to group | `Add-ADGroupMember -Identity "Domain Admins" -Members jsmith` | `dscl /Active Directory/CORP -append /Groups/"Domain Admins" GroupMembership jsmith` | n/a (read-only client) | n/a | `ipa group-add-member "Domain Admins" --users=jsmith` |
| Join computer to domain | `Add-Computer -DomainName corp.example.com -Credential corp\admin` | `dsconfigad -a host01 -domain corp.example.com -u admin -p pass` | `realm join corp.example.com -U admin` (or `adcli join corp.example.com`) | `net ads join -U admin` | `ipa-client-install --domain example.com --realm EXAMPLE.COM` |
| Leave domain | `Remove-Computer -UnjoinDomainCredential corp\admin -Force` | `dsconfigad -remove -u admin -p pass` | `realm leave corp.example.com` | `net ads leave -U admin` | `ipa-client-install --uninstall` |
| Get service ticket | `klist get cifs/dc01.corp.example.com` (kerb client built-in) | `kvno cifs/dc01.corp.example.com@CORP.EXAMPLE.COM` | `kvno cifs/dc01.corp.example.com@CORP.EXAMPLE.COM` | `kvno cifs/dc01.corp.example.com@CORP.EXAMPLE.COM` | `kvno cifs/dc01.corp.example.com@CORP.EXAMPLE.COM` |
| List cached tickets | `klist` (built-in) | `klist` (Heimdal) | `klist` (MIT) | `klist` | `klist` |
| Purge tickets | `klist purge` | `kdestroy` | `kdestroy` | `kdestroy` | `kdestroy` |
| Configure GPO access (per-user/group) | `Set-GPPermission -Name "Lockdown" -PermissionLevel GpoApply -TargetName "JS-Users" -TargetType Group` | `profiles show` (MDM-scope equivalent; no native GPO) | `sssd.conf: ad_gpo_access_control = enforcing` + `ad_gpo_default_right = deny` | n/a (no GPO engine) | HBAC rule: `ipa hbacrule-add allow-js --hostcat=all --servicecat=all; ipa hbacrule-add-user allow-js --groups=js-users` |
| Push cert to machine | `certreq -enroll -machine -q My CustomMachine` | `profiles install -path ~/Desktop/machine.mobileconfig` | `certmonger + IPA getcert request -I machinename -f /etc/pki/tls/certs/host.crt -k /etc/pki/tls/private/host.key -T caserver` | `certmonger + SCEP` (same as SSSD path) | `ipa cert-request --principal=host/host01.example.com host01.crt` |
| Set SPN | `setspn -S cifs/host01.corp.example.com host01` or `Set-ADComputer -Identity host01 -ServicePrincipalNames @{Add="cifs/host01.corp.example.com"}` | n/a (no SPN on macOS) | `adcli set-attr --computer=host01 servicePrincipalName cifs/host01.corp.example.com` | `net ads keytab add cifs/host01.corp.example.com -U admin` | `ipa service-add cifs/host01.example.com@EXAMPLE.COM` |
| Query domain functional level | `Get-ADDomain | Select-Object -ExpandProperty DomainMode` | `dscl /Active Directory/CORP -read / dsServiceConfig` (limited) | `ldapsearch -Y GSSAPI -b "DC=corp,DC=example,DC=com" -s base msDS-Behavior-Version` | `net ads domain info` | `ipa domaininfo` |
| Check replication status | `repadmin /showrepl /repsto` or `Get-ADReplicationPartnerMetadata -Target corp.example.com -Partition *` | n/a | n/a (no DC role) | `samba-tool drs showrepl` (if Samba is AD-DC) | `ipa-csreplica-manage status` + `ipa-replica-manage status` |
| Query FSMO roles | `netdom query fsmo` or `Get-ADDomain | Select PDCEmulator,RIDMaster,InfrastructureMaster; Get-ADForest | Select SchemaMaster,DomainNamingMaster` | n/a | n/a | `samba-tool fsmo show` (if Samba is AD-DC) | `ipa-csreplica-manage status` (IPA has no direct FSMO concept; CA replication roles differ) |
| Query GC | `Get-ADForest | Select GlobalCatalogs` or `nltest /dsgetdc:corp /gc` | `dscl /Active Directory/CORP/GlobalCatalog -list /Users` | `ldapsearch -H ldap://dc01:3268 -Y GSSAPI -b "" -s base namingContexts` | `wbinfo --online-status` (indirect) | n/a (IPA has no GC) |
| List DCs in site | `nltest /dcgetsite:site-name` then `Get-ADDomainController -Filter * -Site site-name` | `dscl /Active Directory/CORP -read /Locations/site-name` (limited) | `dnsutils: dig SRV _ldap._tcp.site-name._sites.dc._msdcs.corp.example.com` | `net ads dnsserver` or `host -t SRV _ldap._tcp.site-name._sites.dc._msdcs.corp.example.com` | n/a (IPA doesn't expose DC site list) |
| Force replication | `repadmin /syncall /A /d /e` or `Sync-ADObject -Object "CN=jsmith,..." -Source dc01 -Destination dc02` | n/a | n/a | `samba-tool drs replicate dc02 dc01 DC=corp,DC=example,DC=com` (if Samba is AD-DC) | `ipa-replica-manage force-sync dc02.example.com` |
| Query AD-integrated DNS zone | `Get-DnsServerResourceRecord -ZoneName corp.example.com` or `dnscmd dc01 /enumrecords corp.example.com @` | n/a | `dig @dc01 corp.example.com AXFR` (if zone transfer enabled; usually disabled) | `dig @dc01 corp.example.com AXFR` or `samba-tool dns query dc01 corp.example.com @ ALL -U admin` | `ipa dnsrecord-show corp.example.com host01` |
| Enable BitLocker with AD recovery | `Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector` (must have schema + GPO configured) | n/a (FileVault recovery key escrows to Apple or MDM, not AD) | n/a (LUKS has no AD recovery; Clevis/Tang is the alternative) | n/a | partial: Clevis + Tang network-bound disk encryption (no AD) |
| Change AD user password via CLI | `Set-ADAccountPassword -Identity jsmith -OldPassword (ConvertTo-SecureString 'old' -AsPlainText -Force) -NewPassword (ConvertTo-SecureString 'new' -AsPlainText -Force` | `kpasswd jsmith@CORP.EXAMPLE.COM` | `kpasswd jsmith@CORP.EXAMPLE.COM` | `kpasswd jsmith@CORP.EXAMPLE.COM` | `ipa passwd jsmith` |
| Query AD via LDAP | `ldapsearch` (Windows Server ships AD LDS instance) or via PowerShell `[ADSISearcher]` | `ldapsearch -H ldap://dc01 -Y GSSAPI -b "DC=corp,DC=example,DC=com" "(sAMAccountName=jsmith)"` | `ldapsearch -Y GSSAPI -b "DC=corp,DC=example,DC=com" "(sAMAccountName=jsmith)"` | `ldapsearch -Y GSSAPI -b "DC=corp,DC=example,DC=com" "(sAMAccountName=jsmith)"` | `ldapsearch -Y GSSAPI -b "DC=corp,DC=example,DC=com" "(sAMAccountName=jsmith)"` (cross-forest trust) |
| Troubleshoot Kerberos auth | `klist; nltest /sc_query:corp; ksetup /dumpstate; Get-EventLog -LogName Security -InstanceId 4768,4769,4771` | `klist -v; sso_util cache -l; log show --predicate 'subsystem == "com.apple.Kerberos"'` | `klist -vef; SSSD_DEBUG=10 sssctl analyze; journalctl -u sssd -p debug` | `wbinfo -t; klist -vef; pdbedit -Lv; testparm -v` | `klist -vef; ipa hbactest --user=jsmith --service=sshd --host=host01; journalctl -u sssd` |

## Cross-platform equivalencies to remember

- **Password reset on Linux clients only works for the user themselves** (via `kpasswd`) — SSSD/Winbind don't expose privileged password reset the way `Set-ADAccountPassword` does. For admin resets from Linux, use `ldap3` with `modify_operation` on `unicodePwd` (TLS-only).
- **`getent passwd` and `getent group` are the universal UNIX check** regardless of whether NSS is backed by SSSD, Winbind, or FreeIPA — the cell shows SSSD-style invocation only.
- **`realm` is a wrapper** around `adcli` and `ipa-client-install`. It autodetects AD vs IPA and dispatches accordingly. `adcli join` directly is fine if you need flags `realm` doesn't expose.
- **`klist` works on all five platforms** — Windows ships a `klist.exe` (since Win7), macOS/Linux/FreeIPA use the upstream MIT or Heimdal `klist`. Flags differ (`-e` shows etypes everywhere; `-v` works everywhere; Windows `klist purge` ≈ Unix `kdestroy`).
- **`nltest` and `repadmin` are Windows-only**. For Samba AD-DC use `samba-tool drs`. For FreeIPA use `ipa-replica-manage` and `ipa-csreplica-manage`. There is no DC-side admin CLI on a non-DC Linux box.
- **SPN uniqueness**: `setspn -X` is unique to Windows. On Linux, use `ldapsearch` against `servicePrincipalName` to detect duplicates.

## Detailed recipes

See:
- [../11-code-examples/01-powershell-ad-cmdlets.md](../11-code-examples/01-powershell-ad-cmdlets.md) — full PowerShell cookbook.
- [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) — `sssd.conf`, `krb5.conf`, `smb.conf`, `realmd.conf`, PAM.
- [../11-code-examples/03-macos-cli-recipes.md](../11-code-examples/03-macos-cli-recipes.md) — `dscl`, `dsconfigad`, `profiles`, `sso_util`, `plutil`, Kerberos.
- [../11-code-examples/04-wireshark-tshark-filters.md](../11-code-examples/04-wireshark-tshark-filters.md) — wire-level diagnostics.
- [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) — Python automation / security research.

## Per-OS command equivalence (most-used operations)

### Reset a user's password (privileged)

| OS | Command | Notes |
|---|---|---|
| Windows | `Set-ADAccountPassword -Identity jsmith -Reset -NewPassword (ConvertTo-SecureString 'P@ss!' -AsPlainText -Force)` | Requires Account Operator / Domain Admin equivalent. |
| Windows (legacy net.exe) | `net user jsmith P@ss! /domain` | Works but no PowerShell object model. |
| macOS | `dscl /Active Directory/CORP -passwd /Users/jsmith 'P@ss!'` | Requires OD admin; AD-bound diradmin typically. |
| macOS (via kpasswd) | `kpasswd jsmith@CORP.EXAMPLE.COM` | Self-change only — requires user's current TGT. |
| Linux SSSD | `kpasswd jsmith@CORP.EXAMPLE.COM` | Self-change only. Admin resets via `ldap3 modify` on `unicodePwd` over TLS. |
| Linux Winbind | `smbpasswd -r dc01 -U jsmith` | Self-change; admin resets require LDAP modify on `unicodePwd`. |
| Linux FreeIPA | `ipa passwd jsmith` | Admin reset (requires `Password Administrators` privilege). |

### Find which DC the client is currently talking to

| OS | Command |
|---|---|
| Windows | `nltest /dsgetdc:corp.example.com` |
| Windows (PowerShell) | `Get-ADDomainController -Discover -Service ADWS \| Select HostName, Site` |
| macOS | `dscl /Active Directory/CORP -read / Config authAuthority` (parsing; not pretty) |
| macOS (Kerberos) | `klist` — the TGT's issuing KDC is in the ticket |
| Linux SSSD | `sssctl domain-status corp.example.com` (shows active server) |
| Linux Winbind | `wbinfo --getdcname=corp` |
| Linux (DNS approach) | `dig SRV _ldap._tcp.dc._msdcs.corp.example.com +short` |

### Show all service tickets currently cached

| OS | Command | CCACHE location |
|---|---|---|
| Windows | `klist` | LSA in-memory (`lsass.exe`) — no disk file |
| macOS | `klist -v` | `/tmp/krb5cc_<uid>` (default) or `API:` (in-memory) |
| Linux SSSD | `klist -vef` | `KEYRING:persistent:<uid>` (default) or `/var/lib/sss/db/ccache_<DOMAIN>` |
| Linux Winbind | `klist -vef` | `/var/cache/samba/krb5cc_<uid>` |
| Linux FreeIPA | `klist -vef` | Same as SSSD path (IPA clients use SSSD) |

### Force a Kerberos cache purge

| OS | Command |
|---|---|
| Windows | `klist purge` |
| Windows (specific SPN) | `klist purge cifs/dc01.corp.example.com` |
| macOS | `kdestroy` (current principal); `kdestroy -A` (all) |
| Linux SSSD | `kdestroy -A`; restart `sssd-kcm` to clear KCM-managed caches |
| Linux Winbind | `kdestroy -A`; restart `winbind` to clear `winbindd_cache.tdb` |

## Gotchas by platform

### Windows
- `Get-ADUser -Identity jsmith` does NOT return all attributes — must add `-Properties *` or specify properties by name. Default returns only ~10 attributes for performance.
- `Set-ADAccountPassword` requires both `-NewPassword` (SecureString) and either `-Reset` (admin reset, no old pw) or `-OldPassword` (user self-change with old pw).
- `repadmin /syncall /A /d /e` forces full sync across all partitions and DCs — can saturate WAN links; use `repadmin /syncall /A /d` for one-way inbound only.

### macOS
- `dscl /Active Directory/CORP -read /Users/jsmith` may return stale cached data. Force refresh: `sudo killall -HUP opendirectoryd`.
- `dsconfigad -enablesso` is a no-op on macOS 12 and earlier (no PSSO Extension). On macOS 13+ requires the Extension be installed via MDM profile first.
- `profiles install` requires the profile be signed (or `sudo` and `IgnoreTrust` flag).
- `plutil` defaults to binary output; use `-convert xml1` for human-readable.

### Linux SSSD
- `realm join` requires DNS SRV records to be discoverable — won't work if `/etc/resolv.conf` points to a non-AD DNS server.
- `adcli join` writes the keytab to `/etc/krb5.keytab` by default — ensure mode 600 and ownership root:root.
- SSSD config file must be mode 600 (`chmod 600 /etc/sssd/sssd.conf`) or SSSD refuses to start.
- After `realm leave`, the host object remains in AD — clean up via `Get-ADComputer -Identity host01 | Remove-ADObject` on Windows.

### Linux Winbind
- `idmap config * : range` MUST be set explicitly; the default range is too narrow for large directories.
- `winbind enum users = yes` on a domain with 100k+ users will hang `getent passwd` for several minutes. Disable on large domains.
- After `net ads leave`, Samba may retain cached SIDs — restart `winbind` to flush.

### Linux FreeIPA
- `ipa-client-install` requires DNS to resolve the IPA domain — set `/etc/resolv.conf` to point to IPA-managed DNS first.
- `ipa passwd jsmith` resets password and forces change at next logon (PAM `pam_sss.so` enforces).
- After `ipa-client-install --uninstall`, the host object remains in IPA — clean up via `ipa host-del host01.example.com` on IPA server.

## Cross-platform scriptable auth flows

For automation, the typical pattern is:

1. **Windows**: `Import-Module ActiveDirectory; $cred = Get-Credential; ...` — uses current user's TGT via Kerberos SSP.
2. **macOS**: `kinit svc-account@CORP.EXAMPLE.COM` then call `ldapsearch -Y GSSAPI` — explicit Kerberos login.
3. **Linux SSSD/Winbind**: `kinit svc-account@CORP.EXAMPLE.COM` then `ldapsearch -Y GSSAPI` — same as macOS.
4. **Linux FreeIPA**: `kinit admin@EXAMPLE.COM` then `ipa user-show jsmith` — IPA CLI auto-uses the CCACHE.
5. **Python (any platform)**: `gssapi.Credentials(usage='initiate', name=gssapi.Name('svc-account@REALM'))` — then pass to `ldap3` SASL GSSAPI or `impacket` SMB.

For passwordless automation, use a keytab:
- Generate on Windows: `ktpass -princ svc-account@CORP.EXAMPLE.COM -mapuser svc-account -pass * -out svc.keytab -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL`
- Generate on Linux: `ktutil` → `addent -password -p svc-account@REALM -k 1 -e aes256-cts-hmac-sha1-96` → `wkt svc.keytab`
- Use: `kinit -k -t svc.keytab svc-account@CORP.EXAMPLE.COM`

## See also

- [01-feature-os-matrix.md](01-feature-os-matrix.md) — feature × OS matrix.
- [02-protocol-implementation-matrix.md](02-protocol-implementation-matrix.md) — protocol × implementation matrix.
- [04-auth-flow-comparison.md](04-auth-flow-comparison.md) — side-by-side auth flow comparison.
- [05-gpo-equivalents-matrix.md](05-gpo-equivalents-matrix.md) — ADMX setting × cross-platform equivalents.

## Function-to-tool quick lookup (alphabetical by function)

| Function | Windows | macOS | SSSD/Winbind/IPA |
|---|---|---|---|
| Add user to group | `Add-ADGroupMember` | `dscl -append` | `ipa group-add-member` |
| Bind computer | `Add-Computer` | `dsconfigad -a` | `realm join` / `net ads join` / `ipa-client-install` |
| Check replication | `Get-ADReplicationPartnerMetadata` | n/a | `samba-tool drs showrepl` / `ipa-replica-manage status` |
| Configure GPO | `Set-GPPermission` | `profiles` | `sssd.conf: ad_gpo_*` / HBAC rule |
| Disable account | `Disable-ADAccount` | (not natively) | `ldapmodify userAccountControl` |
| Enable BitLocker | `Enable-BitLocker` | FileVault | LUKS / Clevis |
| Find user | `Get-ADUser` | `dscl -read /Users/` | `getent passwd` / `wbinfo -i` / `ipa user-show` |
| Force replication | `repadmin /syncall` | n/a | `samba-tool drs replicate` / `ipa-replica-manage force-sync` |
| Get TGT | (auto at logon) | `kinit` | `kinit` |
| Get service ticket | `klist get` | `kvno` | `kvno` |
| Join computer | `Add-Computer` | `dsconfigad -a` | `realm join` / `net ads join` |
| Leave domain | `Remove-Computer` | `dsconfigad -remove` | `realm leave` / `net ads leave` |
| List cached tickets | `klist` | `klist` | `klist` |
| List DCs in site | `nltest /dcgetsite` | `dscl /Locations` | `dig SRV _ldap._tcp.<site>._sites.dc._msdcs` |
| List group members | `Get-ADGroupMember` | `dscl -read /Groups` | `getent group` / `ipa group-show` |
| List users | `Get-ADUser -Filter *` | `dscl -list /Users` | `ipa user-find` |
| Lock out | (server-side) | (server-side) | (server-side) |
| Modify attribute | `Set-ADUser` | `dscl -change` | `ldapmodify` |
| Move computer | `Move-ADObject` | n/a | n/a |
| Purge tickets | `klist purge` | `kdestroy` | `kdestroy` |
| Push cert | `certreq -enroll` | `profiles install` | `getcert request` (certmonger) |
| Query AD via LDAP | `[ADSISearcher]` | `ldapsearch -Y GSSAPI` | `ldapsearch -Y GSSAPI` |
| Query domain functional level | `Get-ADDomain \| Select DomainMode` | `dscl read` | `ldapsearch msDS-Behavior-Version` |
| Query FSMO | `netdom query fsmo` | n/a | `samba-tool fsmo show` |
| Query GC | `nltest /dsgetdc:corp /gc` | `dscl /GlobalCatalog` | `ldapsearch -H ldap://dc01:3268` |
| Query replication metadata | `Get-ADReplicationAttributeMetadata` | n/a | n/a |
| Reset password | `Set-ADAccountPassword -Reset` | `dscl -passwd` / `kpasswd` | `kpasswd` / `ipa passwd` |
| Search AD | `Get-ADUser -LDAPFilter` | `dscl -search` | `ldapsearch` |
| Set SPN | `setspn -S` | n/a | `net ads keytab add` / `ipa service-add` |
| Test secure channel | `Test-ComputerSecureChannel` | `dsconfigad -show` | `net ads testjoin` / `wbinfo -t` |
| Troubleshoot Kerberos | `klist` + Event 4768/4769/4771 | `klist -v` + `log show` | `klist -vef` + `journalctl -u sssd` |

## Sample sessions

### Windows: Reset password and force change

```powershell
$secure = ConvertTo-SecureString -String 'TempP@ss!' -AsPlainText -Force
Set-ADAccountPassword -Identity jsmith -NewPassword $secure -Reset
Set-ADUser -Identity jsmith -ChangePasswordAtLogon $true
Get-ADUser -Identity jsmith -Properties pwdLastSet, ChangePasswordAtLogon
```

### macOS: Show user's group memberships

```bash
# Method 1: via dscl
dscl /Active\ Directory/CORP -read /Users/jsmith dsAttrTypeNative:memberOf

# Method 2: via dsmemberutil
UID=$(dsmemberutil getuid -U jsmith)
dsmemberutil getmembership -q -u $UID
```

### Linux SSSD: Verify GPO enforcement

```bash
# Show active GPO state
sssctl domain-status corp.example.com
sssctl user-checks jsmith

# Test SSH access for a user
sssctl access-check corp.example.com jsmith sshd

# Show GPO cache
ls -la /var/lib/sss/gpo_cache/
```

### Linux Winbind: Verify join and UID map

```bash
net ads testjoin
wbinfo -t                  # test machine secure channel
wbinfo -u                  # list AD users
wbinfo -g                  # list AD groups
wbinfo -i CORP\\jsmith     # show user info
wbinfo --user-domgroups=CORP\\jsmith   # show domain group memberships
getent passwd CORP\\jsmith  # verify NSS resolution
```

### Linux FreeIPA: HBAC test

```bash
# Verify a user's access to a service on a host
ipa hbactest --user=jsmith --service=sshd --host=host01.example.com

# Show HBAC rules
ipa hbacrule-find

# Show sudo rules
ipa sudorule-find --group=linux-admins
```

## See also (extended)

- [../11-code-examples/01-powershell-ad-cmdlets.md](../11-code-examples/01-powershell-ad-cmdlets.md) — PowerShell cookbook.
- [../11-code-examples/02-sssd-conf-recipes.md](../11-code-examples/02-sssd-conf-recipes.md) — SSSD config recipes.
- [../11-code-examples/03-macos-cli-recipes.md](../11-code-examples/03-macos-cli-recipes.md) — macOS CLI cookbook.
- [../11-code-examples/04-wireshark-tshark-filters.md](../11-code-examples/04-wireshark-tshark-filters.md) — Wireshark / tshark filters.
- [../11-code-examples/05-python-impacket-examples.md](../11-code-examples/05-python-impacket-examples.md) — Python / impacket recipes.
