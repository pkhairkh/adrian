---
title: SSSD ad Provider — Architecture, Responders, and AD Integration
audience: senior-engineers
tags: [sssd, ad-provider, krb5, ldap, systemd, realmd, adcli, pam, nss]
related:
  - ./02-sssd-id-mapping.md
  - ./03-sssd-gpo-access.md
  - ./04-winbind-internals.md
  - ./06-realmd-join-flow.md
  - ./10-pam-nss-stack.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
last_updated: 2026-08-13
---

SSSD's `ad` provider is a thin aggregation layer that pre-binds the `ldap` identity provider, the `krb5` authentication provider, and an AD-specific access checker (`ad_access.c`) behind a single `[domain/<name>]` configuration block, with the daemon itself running as one monitor process plus per-responder (`sssd_nss`, `sssd_pam`, `sssd_sudo`, `sssd_ifp`, `sssd_pac`) and per-domain backend (`sssd_be --domain <name>`) children coordinated over private D-Bus sockets.

## Architecture / process model

`/usr/sbin/sssd` is launched by `sssd.service` (systemd unit `/usr/lib/systemd/system/sssd.service`, `Type=notify`, `ExecStart=/usr/sbin/sssd -c /etc/sssd/sssd.conf`, `EnvironmentFile=-/etc/sysconfig/sssd`). The first process is the **monitor** (`src/monitor/monitor.c:main`), which:

1. Parses `/etc/sssd/sssd.conf` and the `sssd.conf.d/*.conf` drop-ins (`src/confdb/confdb.c:confdb_init`).
2. Forks one **responder** per enabled service in the `[sssd] services =` line — typically `nss`, `pam`, `sudo`, `ifp`, `pac`, `ssh` — each a separate binary in `/usr/libexec/sssd/` (`sssd_nss`, `sssd_pam`, `sssd_sudo`, `sssd_ifp`, `sssd_pac`, `sssd_ssh`).
3. Forks one **backend** per domain: `/usr/libexec/sssd/sssd_be --domain <name>`. The backend embeds all provider modules as shared objects in `/usr/libexec/sssd/libsss_ad.so`, `libsss_ldap.so`, `libsss_krb5.so`, `libsss_ipa.so`, `libsss_simple.so`.

| Process | Binary | IPC socket | Role |
|---|---|---|---|
| Monitor | `sssd` (pid 1 of cgroup) | `/var/run/sssd.pid` | Watches responders/backends; restarts on crash (`src/monitor/monitor.c:ssd_sigchld`) |
| NSS responder | `sssd_nss` | `/var/lib/sss/pipes/nss` | `getpwnam`/`getpwuid`/`getgrnam`/`getgrgid`/`initgroups` from `libnss_sss.so.2` |
| PAM responder | `sssd_pam` | `/var/lib/sss/pipes/pam` | `pam_sss.so` auth/account/password/session |
| SUDO responder | `sssd_sudo` | `/var/lib/sss/pipes/sudo` | `sudoers` LDAP rule lookup |
| IFP responder | `sssd_ifp` | D-Bus `org.freedesktop.sssd.infopipe` (system bus) | Programmatic user/group enumeration |
| PAC responder | `sssd_pac` | `/var/lib/sss/pipes/pac` | Validates PAC in Kerberos service tickets (offloaded by `pam_sss.so`) |
| SSH responder | `sssd_ssh` | `/var/lib/sss/pipes/ssh` | Returns `authorizedKeys` (from `sshPublicKey` AD attribute or `ipaSshPubKey`) |
| Backend (`sssd_be`) | `sssd_be --domain <name>` | private pipe to monitor | Runs the provider modules; performs LDAP queries, Kerberos auth, ID mapping |

The backend owns the TDB/LDB cache at `/var/lib/sss/db/cache_<domain>.ldb` (LDB — Samba's LDAP-on-TDB format), `/var/lib/sss/db/timestamps_<domain>.ldb`, `/var/lib/sss/db/ccache_<domain>` (Kerberos ccache for the machine account), and `/var/lib/sss/pubconf/krb5.include.d/<domain>` (auto-included by `/etc/krb5.conf`).

### The `ad` provider as wrapper

`src/providers/ad/ad_id.c:ad_domain_init` calls `sdap_id_setup_tasks` (LDAP) and `ad_setup_auth()` (Kerberos) — it sets sensible defaults and then delegates:

| Provider key | Underlying module | Defaults injected by `ad` |
|---|---|---|
| `id_provider = ad` | `libsss_ldap.so` via `src/providers/ldap/ldap_id.c:sdap_id_setup_tasks` | `ldap_schema = ad`, `ldap_referrals = true`, `ldap_sasl_mech = GSS-SPNEGO`, `ldap_krb5_init_creds = true`, `ldap_id_mapping = true` |
| `auth_provider = ad` | `libsss_krb5.so` via `src/providers/krb5/krb5_auth.c:krb5_pam_handler` | `krb5_realm = <ad_domain uppercased>`, `krb5_use_kdc_info = true`, `krb5_canonicalize = true` |
| `access_provider = ad` | `libsss_ad.so` via `src/providers/ad/ad_access.c:ad_access_handler` | Chain of `ad_provider=ad_simple` (if `simple_allow_users` set) → `ad_gpo` (if `ad_gpo_access_control != disabled`) → `ad` always-allow |
| `chpass_provider = ad` | `libsss_krb5.so` via `src/providers/krb5/krb5_child.c:krb5_child_process` | Uses `kpasswd` SRV records (`_kpasswd._tcp.<domain>`) |

Key source paths (SSSD upstream https://github.com/SSSD/sssd):

- `src/providers/ad/ad_id.c` — backend initialization, `ad_id_connect` (`ad_id.c:ad_id_connect`), `ad_account_can_short_name`.
- `src/providers/ad/ad_access.c:ad_access_handler` — runs the access-check chain.
- `src/providers/ad/ad_gpo.c` and `src/providers/ad/ad_gpo_child.c` — GPO retrieval (see `../03-sssd-gpo-access.md`).
- `src/providers/ad/ad_subdomains.c:ad_subdomains_refresh` — refreshes trusted-domain info from AD via LDAP (`CN=Configuration,...,CN=Partitions`) plus `netr_GetDcName` discovery.
- `src/providers/ldap/ldap_id.c:ldap_id_setup_tasks` — periodic `sdap_id_enum_users`/`_groups` tasks.
- `src/providers/ldap/sdap.c:sdap_create_search_base` — builds `LDAPMessage` search bases from `cn=Users,<domain DN>` or your `ldap_user_search_base`.
- `src/providers/krb5/krb5_auth.c:krb5_pam_handler` — bridges PAM `auth` phase to `krb5_child`.
- `src/providers/krb5/krb5_child.c:krb5_child_process` — `krb5_get_init_creds_password` / `krb5_get_init_creds_keytab` (machine-account refresh).
- `src/responder/nss/nsssrv.c:nss_cmd_getpwnam` — entry point for NSS lookups.
- `src/responder/pam/pamsrv.c:pam_cmd_authenticate` — PAM `auth` entry.
- `src/util/sss_krb5.c:sss_krb5_get_init_creds` — Kerberos glue.

## Configuration — `/etc/sssd/sssd.conf`

```
[sssd]
services = nss, pam, sudo, ifp, ssh, pac
config_file_version = 2
domains = corp.example.com

[nss]
filter_groups = root
filter_users = root
enum_cache_timeout = 300
entry_negative_timeout = 15
memcache_timeout = 5400

[pam]
offline_credentials_expiration = 60
offline_failed_login_attempts = 5
offline_failed_login_delay = 5
pam_verbosity = 2
pam_id_timeout = 10

[sudo]
sudo_timed = true

[ifp]
allowed_uids = 0, 1000
user_attributes = +mail, + telephoneNumber

[domain/corp.example.com]
id_provider = ad
auth_provider = ad
access_provider = ad
chpass_provider = ad

ad_domain = corp.example.com
ad_server = dc01.corp.example.com
ad_backup_server = dc02.corp.example.com, dc03.corp.example.com
ad_hostname = host01.corp.example.com
ad_enabled_domains = corp.example.com, child.corp.example.com

# Kerberos
krb5_realm = CORP.EXAMPLE.COM
krb5_renewable_lifetime = 7d
krb5_lifetime = 10h
krb5_renew_interval = 1h
krb5_use_fast = try
krb5_store_password_if_offline = true
krb5_ccachedir = /run/user/%u/krb5cc

# LDAP specifics (overridden by 'ad' defaults)
ldap_schema = ad
ldap_id_mapping = true
ldap_sasl_mech = GSS-SPNEGO
ldap_sasl_authid = HOST01$@CORP.EXAMPLE.COM
ldap_referrals = true
ldap_account_expire_policy = ad
ldap_pwd_policy = mit
ldap_tls_reqcert = demand
ldap_id_use_start_tls = true

# AD-specific timeouts
ldap_connection_timeout = 5
ldap_search_timeout = 10
ldap_network_timeout = 5
ldap_opt_timeout = 6

# Cache
entry_cache_timeout = 5400
entry_cache_user_timeout = 5400
entry_cache_group_timeout = 5400
entry_cache_netgroup_timeout = 5400
entry_cache_service_timeout = 21600
entry_cache_sudo_timeout = 1800
refresh_expired_interval = 60

# Offline auth
cache_credentials = true
account_cache_factor = 1
use_fully_qualified_names = true
ignore_group_members = false

# Access control (see ../03-sssd-gpo-access.md)
ad_gpo_access_control = enforcing
ad_gpo_implicit_deny = false
ad_gpo_map_interactive = +allow_logon_locally
ad_gpo_map_remote_interactive = +allow_logon_remote_interactive

# Subdomain (trust) inheritance
subdomain_inherit = ignore_group_members, use_fully_qualified_names
subdomain_homedir = /home/%d/%u
override_homedir = /home/%d/%u
default_shell = /bin/bash

dyndns_update = true
dyndns_ttl = 3600
dyndns_update_ptr = true
dyndns_refresh_interval = 43200
```

File mode must be `0600` owned by `root:root`; SSSD refuses to start if mode is more permissive (`src/util/util_files.c:check_file`). Drop-in overrides live in `/etc/sssd/conf.d/*.conf` merged after the main file (`src/confdb/confdb.c:confdb_read_ini`).

### Joining via `realm`/`adcli`

`realmd` invokes `adcli join` (`/usr/sbin/adcli`, source https://gitlab.freedesktop.org/realmd/adcli) which:

1. Discovers the domain via DNS SRV `_ldap._tcp.dc._msdcs.<domain>` queries (`adcli` `tools/computer.c:adcli_tool_join`).
2. Performs an anonymous LDAP bind to a discovered DC and reads `rootDomainNamingContext`, `dnsHostName`, `ldapServiceName`, `supportedCapabilities` (1.2.840.113556.1.4.2237 = AD LDS; 1.2.840.113556.1.4.1851 = AD DS with RODC; 1.2.840.113556.1.4.800 = AD DS) — see `../02-protocols/02-ldap-protocol.md`.
3. Builds the machine account DN under `CN=<NETBIOS>$,CN=Computers,<domain DN>` (or your redacted `wellKnownObjects` Computers container) and uses `userAccountControl = 4096` (WORKSTATION_TRUST_ACCOUNT) plus `unicodePwd` (the quoted-UTF-16 BER trick documented in `../02-protocols/02-ldap-protocol.md`).
4. Uses the resulting machine-account password to build `/etc/krb5.keytab` with `HOSTNAME$@REALM`, `HOSTNAME$@REALM` (aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96, arcfour-hmac-md5), `HOST/hostname@REALM`, `RestrictedKrbHost/HOSTNAME@REALM`.

```bash
realm discover corp.example.com
realm join -U admin --computer-name=host01 --os-name='Ubuntu 22.04' --os-version=22.04 corp.example.com
# Behind the scenes:
#   adcli join --domain corp.example.com --domain-realm CORP.EXAMPLE.COM \
#     --host-fqdn host01.corp.example.com --computer-name HOST01 \
#     --os-name 'Ubuntu 22.04' --os-version 22.04 \
#     --login-type user --login-user admin --no-password
#   realm writes /etc/sssd/sssd.conf, /etc/krb5.conf, /etc/samba/smb.conf
#   realm calls: pam-auth-update (Debian) or authselect select sssd with-mkhomedir --force (RHEL)

realm permit user1@corp.example.com user2@corp.example.com
realm deny --all
realm leave --remove --user=admin corp.example.com
```

### Manual adcli / net ads equivalents

```bash
# Inspect discovered DCs without joining
adcli info corp.example.com

# Force re-join without leaving first (resets machine password)
adcli join --domain corp.example.com --host-fqdn=host01.corp.example.com \
  --login-user=admin --show-details

# Rotate the machine account password (refuse if DC unreachable)
adcli update --domain corp.example.com

# Reset the host's password from AD and write new keytab
net ads password -U admin%pass -S dc01.corp.example.com HOST01$
net ads keytab create -U admin%pass
klist -k /etc/krb5.keytab
```

### Inspecting the cache and live state

```bash
# TDB/LDB cache contents ( ldbsearch from samba/ldb-tools )
ldbsearch -H /var/lib/sss/db/cache_corp.example.com.ldb -b cn=sysdb '(objectClass=user)' name uid uidNumber gidNumber

# Active TGT for the host account
klist -k /etc/krb5.keytab
klist /var/lib/sss/db/ccache_CORP.EXAMPLE.COM

# What the NSS responder actually returns
getent passwd user1@corp.example.com
getent group 'domain admins@corp.example.com'
id user1@corp.example.com

# Invalidate cache after config change
sss_cache -E                          # everything
sss_cache -u user1                    # one user
sss_cache -g 'domain admins@corp.example.com'
sss_cache -d corp.example.com -E      # one domain only

# Increase verbosity on the fly (no restart)
sudo sssctl logs --level=9 --until=15min
# Or edit [domain/...] debug_level = 9 in sssd.conf and systemctl restart sssd
```

### `sssctl` operational commands

```bash
sssctl domain-status corp.example.com
sssctl user-checks user1@corp.example.com
sssctl user-checks user1@corp.example.com --action=auth
sssctl access-report corp.example.com user1@corp.example.com   # GPO access result
sssctl config-check
```

## Wireshark / tshark

SSSD drives three distinct protocol stacks. Useful display filters:

```
# Kerberos AS-EXCHANGE / TGS-EXCHANGE from sssd_be / krb5_child
kerberos && (kerberos.msg_type == 10 || kerberos.msg_type == 12 || kerberos.msg_type == 14)

# LDAP search from sssd_be (GSS-SPNEGO bound)
ldap && (ldap.messageCode == 3 || ldap.messageCode == 4 || ldap.messageCode == 5)

# LDAP bind using SASL GSS-SPNEGO
ldap.messageCode == 0 && ldap.authentication.mechanism == "GSS-SPNEGO"

# SASL bind first round (negotiateToken), second round (authToken)
ldap.authentication.SASL.mechanism == "GSS-SPNEGO"

# CLDAP (UDP 389) — only used by netlogon discovery from samba, not SSSD directly
cldap

# DNS SRV query for KDC / LDAP / kpasswd locator (sssd_be uses krb5 plugin sssd_krb5_locator.so)
dns.qry.name contains "_ldap._tcp.dc._msdcs.corp.example.com" or
dns.qry.name contains "_kerberos._tcp.dc._msdcs.corp.example.com" or
dns.qry.name contains "_kpasswd._tcp.corp.example.com"
```

Live capture:

```bash
sudo tshark -i eth0 -f 'tcp port 389 or tcp port 636 or tcp port 88 or udp port 88 or udp port 464' \
  -Y 'kerberos || ldap' -V
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `id user@domain` returns nothing, but `ldapsearch -Y GSSAPI` works | NSS cache poisoned, or `use_fully_qualified_names=true` and lookup missed the domain suffix | `sss_cache -E` then `id user@corp.example.com` |
| `Permission denied` in PAM despite correct password | Time skew > 5 min against DC (KRB_AP_ERR_SKEW = 37) | `chronyc sources` / `timedatectl set-ntp true` — see `../02-protocols/07-ntp-time-sync.md` |
| `Server not found in Kerberos database (7)` on `kinit` | Host principal missing (stale machine account) | `adcli join --domain corp.example.com` to recreate |
| `Preauthentication failed` after DC replacement | Keytab still holds old AES keys | `net ads keytab create -U admin` or `adcli update` |
| ` ldbsearch: Unable to open tdb` | sssd_be crashed leaving LDB lock | `systemctl stop sssd; rm /var/lib/sss/db/cache_*.ldb-lock; systemctl start sssd` |
| Enormous `sssd_nss` CPU | LDAP paged search hitting `ldap_paged_size` against a DC with thousands of disabled accounts | Set `ldap_search_timeout = 30`, `enumerate = false`, `ignore_group_members = true` |
| GPO denies all logins even for allowed users | `ad_gpo_implicit_deny = true` and no applicable GPO, or wrong `ad_gpo_map_*` mapping | Set `ad_gpo_access_control = permissive`, inspect `/var/log/sssd/sssd_ad.log`, see `../03-sssd-gpo-access.md` |
| `krb5_child failed: Key version is not yet available` | Stale kvno in keytab after machine password rotation | `adcli update` or `net ads keytab create` |

Logs are at `/var/log/sssd/sssd_<service>.log` — the most useful are `sssd_ad.log` (backend AD provider), `sssd_nss.log`, `sssd_pam.log`, and `sssd_pac.log`. With `debug_level = 9` you get full LDAP request/response dumps and Kerberos KRB5_TRACE output.

## Cross-platform comparison

- **AD-side counterpart:** SSSD's `ad` provider makes the Linux host behave like a Windows member server (computer object in `CN=Computers`, machine-account keytab, secure-channel-equivalent via LDAP GSS-SPNEGO + Kerberos service tickets). The Netlogon secure channel itself is not used — see `../01-ad-core/01-ad-ds-internals.md` for the AD-side computer-account lifecycle and `../02-protocols/01-kerberos-internals.md` for the Kerberos exchange SSSD's `krb5_child` performs. LDAP details in `../02-protocols/02-ldap-protocol.md`; SPN/PAC handling in `../02-protocols/08-spn-upn-pac.md`.
- **Winbind alternative:** Samba's `winbindd` performs the same job via Netlogon secure channel + MS-DRSR-style SAMR queries — see `./04-winbind-internals.md` and `./05-samba-tool-net-ads.md`. SSSD is preferred in modern distros; Winbind remains relevant for file servers (SMB share ACLs via `smbd`).
- **macOS counterpart:** macOS uses `opendirectoryd` plus an AD plugin (configured via `dsconfigad`) rather than SSSD — see `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- SSSD source — https://github.com/SSSD/sssd (main branch); see `src/providers/ad/` and `src/responder/`.
- `adcli` source — https://gitlab.freedesktop.org/realmd/adcli (see `library/` and `tools/computer.c`).
- `realmd` source — https://gitlab.freedesktop.org/realmd/realmd.
- SSSD man pages: `sssd-ad(5)`, `sssd.conf(5)`, `sssd-ldap(5)`, `sssd-krb5(5)`, `sss_cache(8)`, `sssctl(8)`.
- Red Hat documentation — "SSSD AD Provider" chapter in the *Windows Integration Guide*.
- MS-ADTS §3.1.1 (LDAP behavior), MS-KILE (Kerberos profile) — see `../02-protocols/01-kerberos-internals.md` and `../02-protocols/02-ldap-protocol.md`.
