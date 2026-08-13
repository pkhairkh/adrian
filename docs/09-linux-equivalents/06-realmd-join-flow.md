---
title: realmd DBus Service and realm CLI — Discover, Join, Configure
audience: senior-engineers
tags: [realmd, dbus, adcli, ipa, sssd, pam-auth-update, authselect, nsswitch, realm]
related:
  - ./01-sssd-ad-provider.md
  - ./05-samba-tool-net-ads.md
  - ./07-pbis-powerbroker.md
  - ./10-pam-nss-stack.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ../02-protocols/02-ldap-protocol.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
last_updated: 2026-08-13
---

`realmd` is a system D-Bus service (`org.freedesktop.realmd`) and the `realm` CLI is its thin client, both shipped from https://gitlab.freedesktop.org/realmd/realmd, that discover an AD/IPA domain via DNS SRV records, dispatch the actual join operation to a provider-specific helper (`adcli join` for `ad`, `ipa-client-install` for `ipa`, `samba-tool domain join` for `samba-member`), then write `/etc/sssd/sssd.conf`, `/etc/krb5.conf`, `/etc/samba/smb.conf`, `/etc/nsswitch.conf`, and the PAM stack via `pam-auth-update` (Debian/Ubuntu) or `authselect` (RHEL/Fedora) — a wrapper that abstracts the per-distro glue and is now deprecated in newer distributions in favor of direct `adcli` invocation.

## Architecture

```
                ┌────────────────────────────┐
                │  realm CLI (/usr/bin/realm)│
                └────────────┬───────────────┘
                             │ D-Bus system bus
                             ▼
                ┌────────────────────────────┐
                │  realmd (/usr/sbin/realmd) │
                │  systemd: dbus-org.freedesktop.Realmd.service
                │  src/daemon.c:realmd_daemon_start
                └─┬────────┬────────┬────────┘
                  │        │        │
       ┌──────────┘        │        └───────────┐
       ▼                    ▼                     ▼
┌──────────────┐   ┌──────────────────┐  ┌─────────────────────┐
│ adcli helper │   │ ipa-client-install│  │ samba-tool domain join│
│ /usr/sbin/   │   │ /sbin/ipa-client- │  │ /usr/bin/samba-tool  │
│  adcli       │   │  install          │  │ (samba-member mode)  │
└──────┬───────┘   └────────┬──────────┘  └──────────┬───────────┘
       │                    │                        │
       ▼                    ▼                        ▼
  /etc/sssd/sssd.conf   /etc/sssd/sssd.conf   /etc/samba/smb.conf
  /etc/krb5.conf        /etc/krb5.conf        /etc/krb5.keytab
  /etc/krb5.keytab      /etc/krb5.keytab      /etc/nsswitch.conf (winbind)
```

### realmd daemon

- **systemd unit:** `dbus-org.freedesktop.Realmd.service` (alias of `realmd.service`), D-Bus activatable, `Type=dbus`, runs as root.
- **D-Bus interface:** `org.freedesktop.realmd.Service` (object path `/org/freedesktop/realmd`), `org.freedesktop.realmd.Provider`, `org.freedesktop.realmd.Realm`, `org.freedesktop.realmd.KerberosMembership`.
- **Source:** `src/daemon.c:realmd_daemon_start`, `src/realm.c:realm_handle_discover`, `src/realm.c:realm_handle_join`, `src/realm.c:realm_handle_leave`.

The daemon stays dormant until a D-Bus client invokes `Discover` on `org.freedesktop.realmd.Service`; systemd starts it on demand and stops it after the `IdleTimeout` (default 30 s).

### Discovery

`realm discover <domain>` triggers `src/realm.c:realm_discover_start` which:

1. **DNS discovery** — `res_query` for SRV records:
   - `_ldap._tcp.<domain>` — LDAP server
   - `_kerberos._tcp.<domain>` and `_kerberos._tcp.dc._msdcs.<domain>` — KDC
   - `_kpasswd._tcp.<domain>` — password change server
   - `_ldap._tcp.gc._msdcs.<forest-root>` — Global Catalog (only if `_ldap._tcp.<domain>` returns a DC whose `rootDomainNamingContext` differs from `<domain>`'s own NC)
   - See `../02-protocols/05-dns-dynamic-updates.md` for the SRV record catalog.
2. **CLDAP ping** to each discovered DC to obtain `Netlogon` SAMLOGON response containing `DnsForestName`, `DomainGuid`, `DomainControllerName`, `DomainControllerAddress`, `ServerGuid`, `NtVersion`, `LmNtToken`. (CLDAP = LDAP over UDP/389, RFC 1798.)
3. **LDAP anonymous bind** to read `rootDomainNamingContext`, `defaultNamingContext`, `configurationNamingContext`, `schemaNamingContext`, `ldapServiceName`, `supportedCapabilities`, `supportedSASLMechanisms` — see `../02-protocols/02-ldap-protocol.md`.
4. **DNS TXT `_kerberos.<domain>`** — to confirm the canonical Kerberos realm name (uppercased).

### Provider selection

Based on what the discovery finds, realmd chooses a provider:

| Discovery result | Provider | Join command |
|---|---|---|
| AD DS or AD LDS reachable; `supportedCapabilities` includes AD DS OID | `ad` (default) or `sssd-ad` | `adcli join --domain <domain> --domain-realm <REALM> --host-fqdn <fqdn> --computer-name <NETBIOS> --login-user <admin>` |
| User explicitly passes `--membership-software=samba` or `smb.conf` already configured | `samba-member` | `net ads join -U <admin>` (or `samba-tool domain join`) |
| FreeIPA — DNS TXT `_kerberos.<domain>` returns the IPA realm and LDAP `supportedCapabilities` includes `1.3.6.1.4.1.311.21.36.1.4.1` (IPA) | `ipa` | `ipa-client-install --domain <domain> --realm <REALM> --principal <admin> --password` |
| Generic Kerberos v5 (no AD/IPA signatures) | `kerberos-member` | `adcli join` with `--login-type=user` |

The chosen provider's join command is run in a child process via `g_spawn_async` (`src/realm-invocation.c:realm_invocation_run`). Output is streamed to syslog.

### Post-join configuration

After a successful join, `realm join` runs the provider-specific post-join hooks (in `src/realm-sssd-ad.c:realm_sssd_ad_configure`, `src/realm-sssd-ipa.c:realm_sssd_ipa_configure`, `src/realm-samba.c:realm_samba_configure`):

1. **`/etc/sssd/sssd.conf`** (for `ad` and `ipa` providers) — `realmd` writes a new `[domain/<domain>]` section and adds `<domain>` to `[sssd] domains =`. Sample minimal section written by realmd:

   ```
   [sssd]
   domains = corp.example.com
   config_file_version = 2
   services = nss, pam

   [domain/corp.example.com]
   default_shell = /bin/bash
   krb5_store_password_if_offline = True
   cache_credentials = True
   krb5_realm = CORP.EXAMPLE.COM
   realmd_tags = manages-system joined-with-adcli
   id_provider = ad
   fallback_homedir = /home/%u@%d
   ad_domain = corp.example.com
   use_fully_qualified_names = True
   ldap_id_mapping = True
   ```

2. **`/etc/krb5.conf`** — append `[realms]` and `[domain_realm]` sections (or `include /var/lib/sss/pubconf/krb5.include.d/*`).
3. **`/etc/samba/smb.conf`** (for `samba-member` provider) — writes `[global]` `workgroup`, `realm`, `security = ads`, `kerberos method = secrets and keytab`.
4. **`/etc/nsswitch.conf`** — prepend `sss` to `passwd:`, `group:`, `shadow:` (for SSSD) or `winbind` (for samba-member). `realm` uses `libnss-resume` patching via the distro's NSS config tool, never direct file editing.
5. **PAM stack:**
   - Debian/Ubuntu: `pam-auth-update --enable sss --enable mkhomedir` (writes `/etc/pam.d/common-{auth,account,password,session}`).
   - RHEL/Fedora/Rocky: `authselect select sssd with-mkhomedir with-sudo --force` (writes `/etc/pam.d/system-auth` and `/etc/pam.d/password-auth`, symlinks them from `systemd-auth`, etc.).
   - SUSE: `pam-config --add --sss --mkhomedir` (writes `/etc/pam.d/common-{auth,account,password,session}-pc`).
6. **`/etc/ssh/sshd_config`** — `UsePAM yes` and `KerberosAuthentication yes` (the latter optional; `realm` does not always modify sshd config — depends on `realmd` version and distro policy).
7. **`oddjobd` activation** — `systemctl enable --now oddjobd` so `pam_oddjob_mkhomedir.so` can create home directories on first login. On systems without `oddjobd`, falls back to `pam_mkhomedir.so`.
8. **`/etc/hosts`** — realmd verifies the host's FQDN resolves to itself; if not, adds a line `192.0.2.10 host01.corp.example.com host01`.

## Commands / examples

```bash
# Discover what realmd finds for a domain
realm discover -v corp.example.com
# Output: type: kerberos-membership
#         realm-name: CORP.EXAMPLE.COM
#         domain-name: corp.example.com
#         configured: no
#         server-software: active-directory
#         client-software: sssd
#         required-package: sssd
#         required-package: adcli
#         required-package: samba-common-tools
#         login-formats: %U@%D
#         ...

# Discover and prefer Winbind over SSSD
realm discover --client-software=winbind corp.example.com

# Join (will prompt for admin password)
realm join -U admin corp.example.com

# Join with explicit OU placement and OS info
realm join -U admin \
  --computer-ou='OU=LinuxServers,DC=corp,DC=example,DC=com' \
  --os-name='Ubuntu 22.04 LTS' --os-version=22.04 \
  --user-principal=host/host01.corp.example.com@CORP.EXAMPLE.COM \
  corp.example.com

# Join using samba (winbind) instead of SSSD
realm join -U admin --client-software=winbind --membership-software=samba corp.example.com

# Join an IPA domain (calls ipa-client-install)
realm join -U admin --client-software=sssd ipa.example.com

# List currently joined realms
realm list
# Output: corp.example.com
#           type: kerberos
#           realm-name: CORP.EXAMPLE.COM
#           domain-name: corp.example.com
#           configured: kerberos-member
#           server-software: active-directory
#           client-software: sssd
#           required-package: sssd
#           required-package: adcli
#           login-formats: %U@%D
#           ...

# Restrict who can log in (writes simple_allow_users in sssd.conf)
realm permit user1@corp.example.com user2@corp.example.com
realm permit -g 'LinuxAdmins@corp.example.com'        # by group
realm deny --all                                       # deny everyone (then add back via permit)
realm permit --all                                     # revert to allow all (default)

# Leave the domain (deletes computer object if --remove)
realm leave corp.example.com
realm leave --remove -U admin corp.example.com          # also remove computer object from AD

# Re-discover (after AD topology changes)
realm discover --force corp.example.com
```

### Configuration — `/etc/realmd.conf`

```
[active-directory]
default-client-software = sssd         # or winbind
os-name = Ubuntu 22.04 LTS             # passed to adcli --os-name
os-version = 22.04                     # passed to adcli --os-version

[users]
default-home = /home/%U@%D
default-shell = /bin/bash

[corp.example.com]
computer-ou = OU=LinuxServers,DC=corp,DC=example,DC=com
user-principal = yes                   # set HOST/ principal
automatic-id-mapping = yes             # ldap_id_mapping = true (default)

[service]
automatic-install = yes                # install missing packages via PackageKit
```

## Wireshark / tshark

`realmd` itself doesn't generate wire traffic directly — it spawns `adcli` / `net ads` / `ipa-client-install` which do. The discovery phase makes the most characteristic traffic:

```
# DNS SRV queries
dns.qry.name contains "_ldap._tcp.dc._msdcs.corp.example.com"
dns.qry.name contains "_kerberos._tcp.dc._msdcs.corp.example.com"
dns.qry.name contains "_kpasswd._tcp.corp.example.com"

# DNS TXT for realm name
dns.qry.type == 16 && dns.qry.name == "_kerberos.corp.example.com"

# CLDAP ping (Netlogon SAMLOGON request, RFC 1798 + MS-NRPC §3.4.5)
cldap && cldap.netlogon

# LDAP anonymous bind during discovery
ldap.messageCode == 0 && ldap.authentication.mechanism == "simple" && ldap.bound_server == "anonymous"

# Kerberos AS-REQ from adcli (admin's TGT acquisition)
kerberos.msg_type == 10 && kerberos.cname == "admin"

# LDAP Add (computer account creation, the join itself)
ldap.messageCode == 8 && ldap.attribute.name == "sAMAccountName"
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `realm: Couldn't join realm: Necessary packages not installed` | `adcli` or `sssd` missing | `apt install adcli sssd sssd-ad` (Debian) / `dnf install adcli sssd realmd oddjob-mkhomedir` (RHEL) |
| `realm: Couldn't discover the realm: No such domain` | DNS not pointing at AD DCs; or `_ldap._tcp` SRV missing | `dig SRV _ldap._tcp.dc._msdcs.corp.example.com +short` |
| `realm: Couldn't join realm: Not authorized to perform this session` | Admin password wrong / account locked | Verify with `ldapwhoami -x -D admin@corp.example.com -W` |
| `realm: Couldn't join realm: Operations error` (LDAP) | Trying to join as non-admin without `Add computer objects to the domain` user right; or computer-name collision | Pre-create computer object in correct OU, or `--computer-name` to a free name; `realm join -U admin --computer-ou='OU=…,DC=…'` |
| After `realm join`, `id user@domain` returns nothing | `nscd` caching stale NSS data, or `sssd.service` not started | `systemctl restart sssd nscd; getent passwd user@corp.example.com` |
| `realm permit` did not change login access | `simple_allow_users` already overridden in `/etc/sssd/conf.d/*.conf` | Edit drop-in directly or `realm deny --all && realm permit user@domain` |
| `realm leave` fails | Computer object already deleted from AD, but `secrets.tdb` / `krb5.keytab` still hold secret | `realm leave --no-remove` (just local cleanup) |
| `/etc/pam.d/common-auth` not updated | `pam-auth-update` profile debconf not set; or hand-edited file marked as local | `pam-auth-update --force` |
| `authselect` complains `Existing configuration is not valid` | Hand-edited PAM files conflict | `authselect select sssd with-mkhomedir --force` |

Logs: `journalctl -u realmd` and `journalctl -t realmd` (realmd logs via syslog). `realmd` daemon debug: `REALMD_DEBUG=1` environment in `/etc/sysconfig/realmd` or `/etc/default/realmd`. Provider logs: `/var/log/sssd/sssd_ad.log`, `/var/log/samba/log.net`.

## Cross-platform comparison

- **AD-side counterpart:** `realm join` is conceptually `Add-Computer -DomainName corp.example.com -Credential (Get-Credential) -OUPath 'OU=LinuxServers,DC=corp,DC=example,DC=com' -PassThru` plus `Restart-Service Netlogon`. The Windows-side discovery uses DsGetDcName API in `netapi32.dll` (CLDAP ping + DNS SRV — same algorithms realmd performs); see `../02-protocols/02-ldap-protocol.md` and `../02-protocols/05-dns-dynamic-updates.md` for the discovery wire details.
- **SSSD alternative:** `realm join` simply orchestrates `adcli join` + writes SSSD config. Direct `adcli join` (see `./01-sssd-ad-provider.md`) followed by manual `sssd.conf` editing is what `realm join` does behind the scenes; newer distros (RHEL 9, Ubuntu 22.04+) increasingly document direct `adcli` paths because realmd is in maintenance mode upstream.
- **Samba alternative:** `realm join --membership-software=samba` calls `net ads join` (`./05-samba-tool-net-ads.md`).
- **PBIS alternative:** `domainjoin-cli join` (PBIS) is the closest proprietary analog — see `./07-pbis-powerbroker.md`.
- **macOS counterpart:** `dsconfigad -add corp.example.com -username admin -password … -ou 'OU=MacServers,…' -preferredserver dc01.corp.example.com` plus Directory Utility.app — see `../08-macos-equivalents/02-dscl-dsconfigad.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- realmd source — https://gitlab.freedesktop.org/realmd/realmd (see `src/daemon.c`, `src/realm.c`, `src/realm-sssd-ad.c`, `src/realm-samba.c`).
- adcli source — https://gitlab.freedesktop.org/realmd/adcli (the `ad` provider's join helper).
- `realm(8)`, `realmd.conf(5)`, `realmd(8)` man pages.
- Red Hat documentation — "Joining RHEL to AD using SSSD via realmd".
- MS-NRPC §3.4.5 — CLDAP Netlogon SAMLOGON response structure used by discovery.
- RFC 1798 — CLDAP (LDAP over UDP).
- RFC 2782 — DNS SRV resource record format.
