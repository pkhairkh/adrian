---
title: SSSD / Winbind / Kerberos / Samba / PAM Configuration Recipes
audience: senior-engineers
tags: [sssd, winbind, samba, krb5, realmd, pam, authselect, nsswitch]
related:
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../09-linux-equivalents/03-sssd-gpo-access.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../10-comparison-matrices/05-gpo-equivalents-matrix.md
  - ./01-powershell-ad-cmdlets.md
last_updated: 2026-08-13
---

# SSSD / Winbind / Kerberos / Samba / PAM Configuration Recipes

Line-by-line commented configs for AD-joined Linux. Each recipe is self-contained: copy + edit + restart `sssd` / `winbind` / `krb5`.

## Recipe 1 — Basic SSSD-AD join

`/etc/sssd/sssd.conf`:

```ini
[sssd]
# Active responders enabled. NSS + PAM minimum; add 'autofs', 'sudo', 'ssh', 'pac' as needed.
services = nss, pam
# Domains SSSD will manage. Must match [domain/<name>] below.
domains = corp.example.com
# Per-responder idle timeout (seconds). Default 60; raise on busy hosts.
config_file_version = 2
# Separators in fully-qualified names. '\\' for AD-style CORP\user, '@' for user@CORP.
default_domain_suffix = corp.example.com

[nss]
# Filter: hide system users from AD lookups (root, daemon, etc.)
filter_users = root, daemon, bin, sys, nobody
filter_groups = root, daemon, bin, sys, nobody
# Reconnection timeout (sec) before falling back to local-only.
reconnection_retries = 3
# Override shell/home defaults if AD attribute missing.
default_shell = /bin/bash
fallback_homedir = /home/%u

[pam]
# Offline auth cache. Sets how many prior successful hashes to keep.
offline_credentials_expiration = 7
# Days before cached password expiry forces re-auth.
offline_failed_login_attempts = 5
# Account lockout for offline auth failures.
offline_failed_login_delay = 5

[domain/corp.example.com]
# AD provider is the SSSD built-in AD backend (combines LDAP + Kerberos).
id_provider = ad
auth_provider = ad
access_provider = ad
chpass_provider = ad
# Realm (uppercase) — must match AD Kerberos realm.
ad_domain = corp.example.com
ad_server = dc01.corp.example.com, dc02.corp.example.com
# Optionally pin to a site (AD site-aware DC selection).
# ad_site = HQ
# Use dedicated service account for LDAP lookups (recommended).
# ad_enable_dns_sites = true
# Use the machine's Kerberos keytab (/etc/krb5.keytab) for SASL GSSAPI.
krb5_realm = CORP.EXAMPLE.COM
# Use the system keytab created by `adcli join`.
krb5_keytab = /etc/krb5.keytab
# Renew TGT in background near 50% lifetime.
krb5_renew_interval = 1h
# Whether to forward to KDC over TCP (more reliable through firewalls).
krb5_use_tcp = true
# Force canonicalization of principal to match AD UPN.
krb5_canonicalize = false
# LDAP search base autodetection (if not specified, SSSD queries rootDSE).
# ldap_search_base = DC=corp,DC=example,DC=com
# Require LDAP signing (matches "Domain controller: LDAP server signing requirements").
ldap_sasl_mech = GSSAPI
ldap_sasl_minssf = 56
# TLS — required for simple bind, encouraged for SASL too.
ldap_id_use_start_tls = true
# Cache lifetime in seconds.
entry_cache_timeout = 5400
```

Permissions:

```bash
chown root:root /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
systemctl enable --now sssd
```

Join:

```bash
realm join corp.example.com -U admin
# equivalent: adcli join corp.example.com -U admin
```

## Recipe 2 — SSSD with GPO enforcement

Add to `[domain/corp.example.com]`:

```ini
# GPO access control: enforcing (default on RHEL 8+), permissive, disabled.
ad_gpo_access_control = enforcing
# Default right when no GPO applies (allow / deny).
ad_gpo_default_right = deny
# Map AD User Rights Assignment -> SSSD service name.
# Format: right = [+|-]group1,[+|-]group2
ad_gpo_map_interactive = +corp-interactive-users
ad_gpo_map_remote_interactive = +corp-ssh-users
ad_gpo_map_network = +corp-network-users
ad_gpo_map_batch = +corp-batch-users
ad_gpo_map_service = +corp-service-users
ad_gpo_map_permit = +corp-allow-all
# GPO cache timeout (default 5 sec — short to detect policy changes quickly).
ad_gpo_cache_timeout = 30
```

The 5 URA rights SSSD understands (per [../10-comparison-matrices/05-gpo-equivalents-matrix.md](../10-comparison-matrices/05-gpo-equivalents-matrix.md)):

| SSSD key | Windows URA |
|---|---|
| `ad_gpo_map_interactive` | SeInteractiveLogonRight |
| `ad_gpo_map_remote_interactive` | SeRemoteInteractiveLogonRight |
| `ad_gpo_map_network` | SeNetworkLogonRight |
| `ad_gpo_map_batch` | SeBatchLogonRight |
| `ad_gpo_map_service` | SeServiceLogonRight |

## Recipe 3 — SSSD with algorithmic ID mapping (default)

SSSD's `ad_id_mapping = true` (default) derives UID/GID from the AD SID via a configurable slice algorithm. Avoids storing Unix attrs in AD.

```ini
[domain/corp.example.com]
# Enable algorithmic mapping (default).
ldap_id_mapping = true
# Slice size — each domain gets a contiguous block of this many IDs.
ldap_idmap_range_size = 200000
# Range low — SSSD allocates from here upward.
ldap_idmap_range_min = 200000
# Range high — SSSD allocates up to here.
ldap_idmap_range_max = 2000200000
# Number of slices available (default 10000; raise if many domains).
ldap_idmap_range_size = 200000
# Per-domain overrides (default uses auto-discovery; pin if needed).
ldap_idmap_default_domain_sid = S-1-5-21-1234567890-123456789-123456789
ldap_idmap_default_domain = corp
# Autorid-style mapping (alternative — uses one slice per domain found).
# ldap_idmap_autorid_compat = true
```

Algorithm: `uid = range_min + (domain_slice_index * range_size) + (sid_rid % range_size)`.

For deterministic cross-host IDs, ensure `ldap_idmap_default_domain_sid` is identical on every SSSD host.

## Recipe 4 — SSSD with RFC 2307 (Unix attrs in AD)

When AD has `uidNumber`, `gidNumber`, `unixHomeDirectory`, `loginShell` populated:

```ini
[domain/corp.example.com]
ldap_id_mapping = false
# Where to find RFC 2307 attrs:
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_user_home_directory = unixHomeDirectory
ldap_user_shell = loginShell
ldap_user_object_class = user
ldap_group_object_class = group
ldap_group_gid_number = gidNumber
ldap_group_member = memberUid
```

Caveat: AD's default group has `member` (DN-list) not `memberUid`. Set:
```ini
ldap_group_member = member
ldap_group_nesting_level = 2
```

## Recipe 5 — SSSD with sudo rules

SSSD can consume sudoers from AD via the `sudo` responder. Requires schema extension (or LDIF sudoRole objects in AD).

`/etc/sssd/sssd.conf`:

```ini
[sssd]
services = nss, pam, sudo
domains = corp.example.com

[sudo]
# Cache timeout for sudo rules (default 5 min).
sudo_cache_timeout = 300
# Hide log details for sudoers (security).
sudo_timed = true

[domain/corp.example.com]
sudo_provider = ad
# Search base where sudoRole objects live.
ldap_sudo_search_base = OU=Sudoers,DC=corp,DC=example,DC=com
# Refresh rules: smart refresh every 5 min, full refresh every 6 hours.
ldap_sudo_full_refresh_interval = 21600
ldap_sudo_smart_refresh_interval = 300
```

`/etc/nsswitch.conf` line:

```
sudoers: files sss
```

## Recipe 6 — SSSD with autofs

`/etc/sssd/sssd.conf`:

```ini
[sssd]
services = nss, pam, autofs
domains = corp.example.com

[autofs]
# Cache timeout.
autofs_negative_timeout = 15

[domain/corp.example.com]
autofs_provider = ad
# Where automount maps live in AD.
ldap_autofs_search_base = OU=Automounts,DC=corp,DC=example,DC=com
ldap_autofs_map_object_class = nisMap
ldap_autofs_map_name = nisMapName
ldap_autofs_entry_object_class = nisObject
ldap_autofs_entry_key = cn
ldap_autofs_entry_value = nisMapEntry
```

`/etc/nsswitch.conf`:

```
automount: files sss
```

## Recipe 7 — Winbind config (`/etc/samba/smb.conf`)

```ini
[global]
   # Domain member; uses AD DCs for auth.
   security = ads
   # Realm (uppercase) — Kerberos realm.
   realm = CORP.EXAMPLE.COM
   workgroup = CORP
   # Disable NetBIOS lookups (we use DNS).
   disable netbios = yes
   # SMB2 minimum (disable SMB1 — modern security).
   client min protocol = SMB2_10
   server min protocol = SMB2_10
   # Kerberos ticket verification on by default.
   use kerberos keytab = true

   # IDMAP: default (*) backend = tdb (local-only for system accounts)
   idmap config * : backend = tdb
   idmap config * : range = 3000000-3999999

   # Per-domain RID mapping (deterministic from SID).
   idmap config CORP : backend = rid
   idmap config CORP : range = 10000-99999
   idmap config CORP : base_rid = 0

   # Allow nested group resolution (default = 0; bump for deep nesting).
   winbind nested groups = yes
   # Use domain-qualified names: CORP\user
   winbind use default domain = no
   winbind separator = \\
   # Offline logon cache.
   winbind offline logon = yes
   winbind cache time = 300
   # Enumerate users/groups — only on small domains; disable on large.
   winbind enum users = no
   winbind enum groups = no

   # SSSD-compatible shell/home.
   template shell = /bin/bash
   template homedir = /home/%U
```

Join:

```bash
net ads join -U admin
net ads testjoin
systemctl enable --now winbind smb nmb
```

`/etc/nsswitch.conf` for Winbind:

```
passwd: files winbind
group:  files winbind
shadow: files winbind
```

## Recipe 8 — `realmd.conf`

`/etc/realmd.conf`:

```ini
[active-directory]
# Default OU for new computer objects.
default-computer-ou = OU=LinuxHosts,DC=corp,DC=example,DC=com
# Don't touch OS-side config (let realmd manage it).
os-id = linux
# Custom attributes to set on the machine account.
computer-ou = OU=LinuxHosts,DC=corp,DC=example,DC=com
# Whether to install required packages automatically.
automatic-install = yes

[corp.example.com]
# Pin a specific DC for the join.
computer-name = host01
user-principal = host01/admin
# Override default sssd config tweaks realmd applies.
realmd-tags = manages-systemd
```

`realm` commands:

```bash
realm discover corp.example.com
realm join corp.example.com -U admin --computer-ou='OU=LinuxHosts,DC=corp,DC=example,DC=com'
realm leave corp.example.com
realm permit -g corp-linux-users
realm deny --all
```

## Recipe 9 — `/etc/nsswitch.conf` for SSSD vs Winbind

### SSSD
```
passwd:     files sss
shadow:     files sss
group:      files sss
sudoers:    files sss
automount:  files sss
services:   files sss
netgroup:   files sss
```

### Winbind
```
passwd:     files winbind
shadow:     files winbind
group:      files winbind
sudoers:    files
automount:  files
```

### Mixed (don't — but documented for completeness)
```
passwd:     files sss winbind
group:      files sss winbind
```

> ⚠ Running SSSD and Winbind simultaneously is supported but discouraged. NSS lookups will return whichever source answers first; group memberships can diverge. Use one or the other.

## Recipe 10 — PAM stack via `authselect`

RHEL/CentOS 8+ use `authselect` to manage PAM. Don't edit `/etc/pam.d/system-auth` directly — regenerate via `authselect`.

### Enable SSSD profile with offline auth + mkhomedir

```bash
authselect select sssd with-mkhomedir with-sudo with-pamaccess --force
authselect apply-changes
```

This generates `/etc/pam.d/system-auth` and `/etc/pam.d/password-auth` with:

```
# /etc/pam.d/system-auth (excerpt)
auth        required                                     pam_env.so
auth        required                                     pam_faildelay.so delay=2000000
auth        [default=1 ignore=ignore success=ok]         pam_usertype.so isregular
auth        [default=1 ignore=ignore success=ok]         pam_localuser.so
auth        sufficient                                   pam_unix.so nullok try_first_pass
auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success
auth        sufficient                                   pam_sss.so use_first_pass
auth        required                                     pam_deny.so

account     required                                     pam_unix.so
account     sufficient                                   pam_localuser.so
account     sufficient                                   pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                     pam_permit.so

password    requisite                                    pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    required                                     pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient                                   pam_sss.so use_authtok
password    required                                     pam_deny.so

session     optional                                     pam_keyinit.so revoke
session     required                                     pam_limits.so
-session    optional                                     pam_systemd.so
session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid
session     required                                     pam_unix.so
session     optional                                     pam_sss.so
session     optional                                     pam_mkhomedir.so umask=0077
```

### Winbind PAM stack (via authselect)

```bash
authselect select winbind with-mkhomedir with-pamaccess --force
```

Or hand-edit `/etc/pam.d/system-auth`:

```
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        sufficient    pam_winbind.so use_first_pass
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_winbind.so
account     required      pam_permit.so

password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass
password    sufficient    pam_winbind.so use_authtok
password    required      pam_deny.so

session     required      pam_limits.so
session     required      pam_unix.so
session     optional      pam_winbind.so
session     optional      pam_mkhomedir.so umask=0077
```

## Recipe 11 — `/etc/krb5.conf` with SSSD include

```ini
[libdefaults]
    default_realm = CORP.EXAMPLE.COM
    # Allowed enctypes — prefer AES, allow RC4 for legacy DCs.
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes   = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    # UDP vs TCP: TCP for large tickets (PAC-heavy).
    udp_preference_limit = 1
    # Forwardable tickets (needed for some services).
    forwardable = true
    # Proxiable tickets.
    proxiable = true
    # FAST armoring (Server 2012+).
    canonicalize = true
    # Don't try PKINIT by default.
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt

[realms]
    CORP.EXAMPLE.COM = {
        kdc = dc01.corp.example.com
        kdc = dc02.corp.example.com
        admin_server = dc01.corp.example.com
        # Password change endpoint (RFC 3244).
        kpasswd_server = dc01.corp.example.com
        # Use DNS for KDC discovery if explicit list fails.
    }

[domain_realm]
    .corp.example.com = CORP.EXAMPLE.COM
    corp.example.com = CORP.EXAMPLE.COM

[capaths]
    # Cross-realm path: CORP → PARTNER via forest root
    CORP.EXAMPLE.COM = {
        PARTNER.EXAMPLE.COM = .
    }
    PARTNER.EXAMPLE.COM = {
        CORP.EXAMPLE.COM = .
    }

# SSSD injects additional config (domain-realm mappings for the joined domain,
# dynamic KDC discovery via SRV records, etc.) into this directory:
includedir /var/lib/sss/pubconf/krb5.include.d/
```

The `includedir` directive is critical — without it, SSSD's dynamic KDC discovery won't kick in. SSSD writes `/var/lib/sss/pubconf/krb5.include.d/krb5_libdefaults`, `/var/lib/sss/pubconf/krb5.include.d/domain_realm_*, and `/var/lib/sss/pubconf/krb5.include.d/kdc_info_*` files.

## Recipe 12 — `kinit` recipes

```bash
# Initial TGT
kinit jsmith@CORP.EXAMPLE.COM

# TGT for service principal (for svc account)
kinit -k -t /etc/krb5.keytab host/host01.corp.example.com@CORP.EXAMPLE.COM

# Forwardable TGT (default in krb5.conf above, but flag for one-off)
kinit -f jsmith@CORP.EXAMPLE.COM

# Renew existing TGT (if renewable lifetime remains)
kinit -R

# FAST-armored AS-REQ (using a host keytab as armor)
kinit -T /var/lib/sss/db/ccache_CORP.EXAMPLE.COM jsmith@CORP.EXAMPLE.COM

# List tickets
klist -vef

# Service ticket acquisition
kvno cifs/file01.corp.example.com@CORP.EXAMPLE.COM

# Purge
kdestroy
kdestroy -A  # all caches including the default
```

## Recipe 13 — `smb.conf` for SMB client mounting

```ini
[global]
   # Client-only config; no server role.
   security = ads
   realm = CORP.EXAMPLE.COM
   workgroup = CORP
   # Kerberos credentials for SMB Session Setup.
   use kerberos keytab = true
   # Client-side SMB encryption (require SMB3.1.1).
   client min protocol = SMB3_11
   client max protocol = SMB3_11
   client smb encrypt = required
   # Disable NTLMSSP downgrade (force Kerberos).
   client use spnego = yes
   # Multichannel for high-throughput (requires multiple NICs).
   # multichannel = yes
```

`/etc/fstab` for persistent Kerberos-mounted share:

```
//file01.corp.example.com/share  /mnt/share  cifs  sec=krb5i,cruid=1000,multiuser,uid=0,gid=0,dir_mode=0770,file_mode=0660,noserverino,vers=3.1.1  0  0
```

| Mount option | Meaning |
|---|---|
| `sec=krb5i` | Kerberos with integrity (signing) |
| `sec=krb5p` | Kerberos with privacy (encryption) |
| `cruid=1000` | UID to use for credential lookup (for `cifs.upcall`) |
| `multiuser` | Per-user credentials (each user gets their own SMB session) |
| `vers=3.1.1` | Force SMB dialect |

## See also

- [../09-linux-equivalents/01-sssd-ad-provider.md](../09-linux-equivalents/01-sssd-ad-provider.md) — SSSD AD provider internals.
- [../09-linux-equivalents/03-sssd-gpo-access.md](../09-linux-equivalents/03-sssd-gpo-access.md) — GPO access control deep-dive.
- [../09-linux-equivalents/04-winbind-internals.md](../09-linux-equivalents/04-winbind-internals.md) — Winbind internal architecture.
- [../02-protocols/01-kerberos-internals.md](../02-protocols/01-kerberos-internals.md) — Kerberos wire protocol.
- [../02-protocols/02-ldap-protocol.md](../02-protocols/02-ldap-protocol.md) — LDAP protocol.
- [../10-comparison-matrices/05-gpo-equivalents-matrix.md](../10-comparison-matrices/05-gpo-equivalents-matrix.md) — GPO equivalents matrix.
