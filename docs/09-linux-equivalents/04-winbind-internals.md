---
title: Samba Winbind Internals — winbindd, NSS/PAM Modules, idmap Backends
audience: senior-engineers
tags: [winbind, samba, nss, pam, idmap, libads, net-ads, wbinfo, msrpc]
related:
  - ./01-sssd-ad-provider.md
  - ./05-samba-tool-net-ads.md
  - ./02-sssd-id-mapping.md
  - ./10-pam-nss-stack.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
last_updated: 2026-08-13
---

Samba Winbind is the `winbindd` daemon (`/usr/sbin/winbindd`) plus the `libnss_winbind.so.2` NSS module and `pam_winbind.so` PAM module, communicating with the daemon over Unix-domain sockets at `/run/samba/winbindd/pipe` (unprivileged lookups) and `/run/samba/winbindd_privileged/pipe` (auth, password change, machine-account operations), with the daemon itself multiplexing requests across per-domain child processes and the `idmap` subsystem that maps SIDs to POSIX UIDs/GIDs via one of the `idmap_rid` / `idmap_autorid` / `idmap_ad` / `idmap_tdb2` backends.

## Architecture / process model

`winbindd` is started by systemd (`winbind.service`) or by `smbd` itself when `winbindd` is not running. Source: Samba https://github.com/samba-team/samba, `source3/winbindd/winbindd.c:main`.

```
                  ┌───────────────────────────────────────────┐
                  │  winbindd parent (source3/winbindd/winbindd.c) │
                  │  - listen on /run/samba/winbindd/pipe        │
                  │  - listen on /run/samba/winbindd_privileged/pipe │
                  │  - fork per-domain children                 │
                  └──────────┬─────────────────────────┬────────┘
                             │                         │
                ┌────────────┴───────────┐   ┌──────────┴────────────┐
                │  winbindd CORP child   │   │  winbindd CHILD child │
                │  libads-based MSRPC    │   │  (trusted domain)     │
                │  to DC01 (LSA/SAMR/NETLOGON) │                       │
                └────────────────────────┘   └───────────────────────┘
```

| Component | Binary / file | Role |
|---|---|---|
| Daemon | `/usr/sbin/winbindd` | Parent listens; forks per-domain children |
| NSS module | `/lib/x86_64-linux-gnu/libnss_winbind.so.2` (Debian) or `/usr/lib64/libnss_winbind.so.2` (RHEL) | `getpwnam`/`getpwuid`/`getgrnam`/`getgrgid`/`initgroups`/`setgrent`/`getgrent`/`endgrent` calls into `winbindd` over `/run/samba/winbindd/pipe` |
| PAM module | `/lib/x86_64-linux-gnu/security/pam_winbind.so` | `auth`, `account`, `password`, `session` PAM phases via `/run/samba/winbindd_privileged/pipe` (needs root or `wbpriv` group membership) |
| CLI | `/usr/bin/wbinfo` | Tests winbindd operations (`-u`, `-g`, `-t`, `-a`, `-K`, `--allocate-uid`) |
| CLI | `/usr/bin/ntlm_auth` | Helper for proxy-style NTLM auth (Squid, etc.) |
| Cache | `/var/lib/samba/winbindd_cache.tdb` (per-domain cache) and `/var/lib/samba/winbindd_idmap.tdb` (idmap allocation, if `idmap_tdb`) | TDB databases |
| Privileged pipe group | `wbpriv` (Debian) or `wbpriv` (RHEL) — `pam_winbind.so` must be setuid or its consumers must be in this group | See `/etc/group` |

### NSS / PAM request wire format

The winbindd wire protocol is a custom (not DCE/RPC) request/response over the Unix socket. Request struct (`source3/nsswitch/libwbclient/wbclient.h` and `source3/winbindd/winbindd.h:winbindd_request`):

```c
struct winbindd_request {
    uint32_t length;                 // sizeof(request) + extra data
    uint32_t cmd;                    // WINBINDD_GETPWNAM, _GETPWUID, _GETGRNAM, _PAM_AUTH, ...
    uint32_t flags;
    uint32_t pid;
    uint32_t domain_name_len; ...;   // various fixed fields per cmd
    char data[1024];                 // ASCII arguments
    char extra_data[0];              // optional variable-length data
};
```

Major `cmd` values (`source3/nsswitch/wb_common.c` and `source3/winbindd/winbindd_misc.c`):

| `cmd` constant | Numeric | Used by |
|---|---|---|
| `WINBINDD_WINS_BYNAME` | 1 | `nss_wins` |
| `WINBINDD_GETPWNAM` | 6 | `libnss_winbind.getpwnam` |
| `WINBINDD_GETPWUID` | 7 | `libnss_winbind.getpwuid` |
| `WINBINDD_GETGRNAM` | 9 | `libnss_winbind.getgrnam` |
| `WINBINDD_GETGRGID` | 10 | `libnss_winbind.getgrgid` |
| `WINBINDD_SETGRENT` / `_GETGRENT` / `_ENDGRENT` | 13/14/15 | enumeration |
| `WINBINDD_INITGROUPS` | 17 | `libnss_winbind.initgroups` |
| `WINBINDD_PAM_AUTH` | 32 | `pam_winbind auth` |
| `WINBINDD_PAM_ACCT_MGMT` | 33 | `pam_winbind account` |
| `WINBINDD_PAM_CHAUTHTOK` | 34 | `pam_winbind password` |
| `WINBINDD_PAM_CHNG_PSWD_AUTH_CRAP` | 40 | NTLM challenge/response auth (ntlm_auth helper) |
| `WINBINDD_INFO` | 28 | `wbinfo -t` (secret status) |
| `WINBINDD_LIST_USERS` / `_LIST_GROUPS` | 18/19 | `wbinfo -u` / `-g` |
| `WINBINDD_SHOW_SEQUENCE` | 22 | `wbinfo --sequence` |
| `WINBINDD_ALLOCATE_UID` / `_ALLOCATE_GID` | 41/42 | `idmap_tdb` allocation |

### Per-domain child

For each AD domain `winbindd` knows about (configured in `smb.conf [domains]` or discovered via trust), a child process is forked (`source3/winbindd/winbindd.c:domain_init`). The child holds the long-lived MSRPC connections to that domain's DCs:

- `LSARPC` over `\pipe\lsarpc` — `LsaOpenPolicy`, `LsaQueryInfoPolicy2` (for domain info), `LsaLookupSids`, `LsaLookupNames` (SID/name resolution)
- `SAMRPC` over `\pipe\samr` — `SamrConnect`, `SamrOpenDomain`, `SamrEnumerateUsersInDomain`, `SamrQueryInformationUser` (`rid` → user info)
- `NETLOGON` over `\pipe\netlogon` — `NetrServerReqChallenge`, `NetrServerAuthenticate3`, `NetrServerPasswordSet2` (machine account password rotation), `NetrLogonSamLogonEx` (NTLM pass-through auth, PAC validation)
- `DSSETUP` over `\pipe\DSSETUP` — domain controller info
- `SRVSVC` over `\pipe\srvsvc` — share enumeration (for `smbd`, not for NSS)

The MSRPC bindings use `ncacn_np:server[\pipe\lsarpc]` (SMB transport) or `ncacn_ip_tcp:server[135]` (TCP direct, rare). Wire format details in `../02-protocols/06-rpc-dcerpc-ms-drsr.md`.

## Source paths (Samba)

- `source3/winbindd/winbindd.c:main` — daemon entry, `winbindd_setup_listeners`.
- `source3/winbindd/winbindd_dual.c:fork_domain_child` — per-domain child.
- `source3/winbindd/winbindd_misc.c` — info, sequence, getdcname commands.
- `source3/winbindd/winbindd_pam.c:winbindd_dual_pam_auth` — PAM auth handler.
- `source3/winbindd/winbindd_cache.c:wcache_get_pwname` — TDB cache layer.
- `source3/nsswitch/libnss_winbind.c:_nss_winbind_getpwnam_r` — NSS entry.
- `source3/nsswitch/pam_winbind.c:pam_sm_authenticate` — PAM entry.
- `source3/lib/idmap/idmap_rid.c` / `idmap_autorid.c` / `idmap_ad.c` / `idmap_tdb2.c` — idmap backends.
- `source3/libads/ldap.c:ads_simple_bind` / `ads_sasl_bind` — LDAP via libads.
- `source3/libads/krb5_utils.c:ads_krb5_mk_req` — Kerberos service ticket acquisition.
- `source3/libsmb/passchange.c:remote_password_change` — SAMR `SamrChangePasswordUser` flow.
- `source4/torture/rpc/samr.c` — reference SAMR client (testing).

## Configuration — `/etc/samba/smb.conf`

```
[global]
   workgroup = CORP
   realm = CORP.EXAMPLE.COM
   security = ads                              # AD member mode (vs user/domain)
   encrypt passwords = yes

   # Kerberos
   kerberos method = secrets and keytab        # system keytab = /etc/krb5.keytab
   dedicated keytab file = /etc/krb5.keytab

   # Winbind core
   winbind enum users = yes                    # set 'no' for >5k users (perf)
   winbind enum groups = yes
   winbind use default domain = no             # yes = strip CORP\ prefix
   winbind offline logon = yes
   winbind cache time = 300                    # seconds
   winbind reconnect delay = 5
   winbind max clients = 200
   winbind expand groups = 1                   # nested group depth
   winbind nested groups = yes
   winbind refresh tickets = yes               # renew TGTs via kinit
   winbind rpc only = no                       # yes = force MSRPC, no = prefer SAMR/CLDAP locator
   winbind normalize names = yes
   winbind scan trusted domains = yes

   # ID mapping — equivalent to SSSD's ldap_id_mapping (see ./02-sssd-id-mapping.md)
   # Default range for the joined domain
   idmap config * : backend = tdb
   idmap config * : range = 3000-7999          # catch-all for well-known / unmapped SIDs

   # Joined domain: algorithmic RID-based (like SSSD ldap_id_mapping=true)
   idmap config CORP : backend = rid
   idmap config CORP : range = 10000-999999

   # Trusted domain: read AD uidNumber/gidNumber (RFC 2307, like SSSD ldap_id_mapping=false)
   idmap config CHILD : backend = ad
   idmap config CHILD : range = 1000000-1999999
   idmap config CHILD : schema_mode = rfc2307

   # OR for autoranging across many trusted domains:
   # idmap config * : backend = autorid
   # idmap config * : range = 10000-9999999
   # idmap config * : rangesize = 200000
   # idmap config * : read only = no

   # NSS template
   template homedir = /home/%D/%U              # %D = domain, %U = user
   template shell = /bin/bash
   template primary group = "domain users"

   # SMB / smbd specific (irrelevant for pure NSS/PAM use)
   client use spnego = yes
   client ntlmv2 auth = yes
   restrict anonymous = 2
   server signing = mandatory
   smb ports = 445

   # Logging
   log level = 3 winbind:5
   log file = /var/log/samba/log.%m
   max log size = 50
```

### Join flow

```bash
# Initial join (writes /etc/krb5.keytab + /var/lib/samba/secrets.tdb)
net ads join -U admin
# Equivalent verbose:
net ads join -U admin createcomputer="OU=LinuxServers,DC=corp,DC=example,DC=com" \
   osName='Ubuntu 22.04' osVer=22.04 -S dc01.corp.example.com

# Verify
net ads testjoin
net ads info
net ads status -U admin | less                  # machine-account LDAP object dump

# Enumerate
wbinfo -u                                        # all users
wbinfo -g                                        # all groups
wbinfo --user-domgroups='S-1-5-21-...-1107'      # user's domain groups
wbinfo --user-sids='S-1-5-21-...-1107'           # expanded with extraSids

# Auth test
wbinfo -a 'CORP\user1%password'                  # plaintext
wbinfo -K 'CORP\user1%password'                  # kinit + service ticket
wbinfo --krb5auth='CORP\user1%password'          # same

# Trust verification
wbinfo -t                                        # check machine account secret
wbinfo --trusted-domains --verbose
wbinfo -n CORP\\user1                            # name -> SID
wbinfo -s S-1-5-21-1004382210-1580850776-2749628208-1107   # SID -> name

# Allocate UID (idmap_tdb2)
wbinfo --allocate-uid
wbinfo --allocate-gid

# Leave
net ads leave -U admin
```

### NSS / PAM wiring

```
# /etc/nsswitch.conf (manual or via authconfig/authselect)
passwd:     files winbind sss
shadow:     files winbind
group:      files winbind sss
gshadow:    files

# /etc/pam.d/common-auth (Debian) — pam-auth-update generates this
auth sufficient pam_winbind.so try_first_pass
auth required   pam_unix.so nullok_secure

# /etc/pam.d/common-account
account sufficient pam_winbind.so
account required   pam_unix.so

# /etc/pam.d/common-password
password sufficient pam_winbind.so use_authtok try_first_pass
password required   pam_unix.so obscure sha512

# /etc/pam.d/common-session
session required pam_mkhomedir.so umask=0022 skel=/etc/skel
session required pam_winbind.so
session required pam_unix.so
```

`pam_winbind.so` parameters of note (full list in `pam_winbind.conf(5)` and `source3/nsswitch/pam_winbind.c`):

| Parameter | Effect |
|---|---|
| `try_first_pass` | Try the password already prompted by a prior module before prompting again |
| `use_first_pass` | Never prompt; use the prior module's password (fails if none) |
| `use_authtok` | Use the new password from the prior `password` module (e.g. `pam_cracklib`) |
| `require_membership_of = CORP\\LinuxAdmins` | Allow only members of the named group; multiple groups comma-separated |
| `require_membership_of = S-1-5-21-...-1234` | Same, by SID |
| `krb5_auth` | Acquire a Kerberos TGT during `auth` phase and store in `krb5cc_%u` |
| `krb5_ccache_type = FILE:/run/user/%u/krb5cc` | Ccache type and location |
| `cached_login` | Try local cache first if DC unreachable |
| `silent` | Don't log to syslog on auth failure |
| `debug = 100` | Verbose logging |

### idmap backend comparison

| Backend | Algorithm | Use case | SSSD analog |
|---|---|---|---|
| `idmap_rid` (`source3/lib/idmap/idmap_rid.c:idmap_rid_sid_to_id`) | `UID = range_min + RID` (no hashing) | Single domain with a known RID range | SSSD `ldap_id_mapping=true` with a single domain, but SSSD hashes the domain SID for collision resistance |
| `idmap_autorid` (`idmap_autorid.c`) | Hash domain SID → slice; `UID = range_min + slice*rangesize + RID`; next free slice on collision | Many trusted domains; emulates SSSD's algorithm closely | SSSD `ldap_id_mapping=true` with `ldap_idmap_autorid_compat=true` |
| `idmap_ad` (`idmap_ad.c`) | Read `uidNumber`/`gidNumber` from AD | RFC 2307 mode; AD admins populate Unix attributes | SSSD `ldap_id_mapping=false` |
| `idmap_tdb` / `idmap_tdb2` (`idmap_tdb2.c`) | Allocate next free UID on first lookup | Ad-hoc allocation; not stable across hosts unless TDB is replicated | No SSSD equivalent (SSSD always uses algorithmic or authoritative) |
| `idmap_hash` | Deprecated predecessor of `idmap_autorid` | Do not use | — |
| `idmap_nss` | Resolve against already-existing local users | Legacy; rarely used | — |
| `idmap_passdb` | Use Samba passdb | Local Samba DC mode | — |

Switching idmap backends requires `net cache flush` (clears `winbindd_cache.tdb`) and `systemctl restart winbind`, plus a `chown -R --from=<olduid> <newuid>` sweep over file systems — same caveat as SSSD's `sss_cache -E` (see `./02-sssd-id-mapping.md`).

## Wireshark / tshark

```
# DCE/RPC over SMB (ncacn_np) — the SAMR/LSA/NETLOGON traffic from winbindd
smb2.filename contains "samr" || smb2.filename contains "lsarpc" || smb2.filename contains "netlogon"

# DCE/RPC bind and request frames
dcerpc.pkt_type == 11                           # BIND
dcerpc.pkt_type == 0                            # REQUEST
dcerpc.opnum == 5 && dcerpc.cn_call_id == 1     # specific opnum

# SAMR EnumUsers
dcerpc.samr.opnum == 16

# LsaLookupSids
dcerpc.lsa.opnum == 15

# Netlogon NetrServerAuthenticate3
dcerpc.netlogon.opnum == 26

# LDAP from libads (winbindd also does some LDAP — domain controller location)
ldap.messageCode == 0 && ldap.authentication.mechanism == "GSS-SPNEGO"
```

Capture:

```bash
sudo tshark -i eth0 -f 'host dc01.corp.example.com and (tcp port 445 or tcp port 389 or tcp port 88)' \
  -Y 'dcerpc || ldap || kerberos' -V
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `wbinfo -t` returns `checking the trust secret for domain CORP via RPC calls failed: WERR_ACCESS_DENIED` | Machine account password out of sync (typical after AD restore or stale secrets.tdb) | `net ads join -U admin` (rejoin) or `net rpc changetrustpw` (rotate without rejoin) |
| `id CORP\\user1` returns nothing but `wbinfo -u` lists the user | NSS not configured (`/etc/nsswitch.conf` missing `winbind`) | Edit `nsswitch.conf`, run `nscd -i passwd` if `nscd` is running |
| `pam_winbind(sshd:auth): request failed: No such user` | `winbind enum users = no` and NSS has not yet cached the user | Trigger a lookup with `getent passwd CORP\\user1`, or set `winbind enum users = yes` |
| Two hosts show different UIDs for the same user | `idmap_tdb2` allocating independently per host | Switch to `idmap_rid` or `idmap_autorid` (algorithmic) or `idmap_ad` (RFC 2307) |
| `wbinfo -K` works but `kinit` does not | `kerberos method = secrets and keytab` not set, keytab not generated | `net ads keytab create -U admin` |
| Auth slow for first login of each user | `winbind enum users = yes` causing full enumeration at startup | Set `winbind enum users = no`, `winbind enum groups = no` (recommended for >5k users) |
| `winbindd` segfault on trusted-domain lookup | `winbind scan trusted domains = yes` discovering a domain where DC is unreachable | Set `winbind scan trusted domains = no`; declare trusted domains explicitly in `smb.conf` |

Logs: `/var/log/samba/log.winbindd`, `log.winbindd_privileged`, per-domain `log.wb-CORP`. Increase `log level = 5 winbind:10`.

## Cross-platform comparison

- **AD-side counterpart:** Winbind's Netlogon secure-channel (`NetrServerAuthenticate3` + `NetrLogonSamLogonEx`) is the same protocol Windows member servers use against their DC — see `../02-protocols/06-rpc-dcerpc-ms-drsr.md` for the DCE/RPC bind / opnum tables, and `../02-protocols/01-kerberos-internals.md` for the Kerberos exchange `pam_winbind.so krb5_auth` performs. The SMB transport is documented in `../02-protocols/03-smb-cifs-protocol.md`. Compared to SSSD, Winbind hews closer to the Windows member-server wire protocol (Netlogon secure channel + SAMR/LSA); SSSD uses pure LDAP + Kerberos and skips Netlogon.
- **SSSD alternative:** See `./01-sssd-ad-provider.md` for the modern preferred stack. Most distros recommend SSSD for NSS/PAM and Winbind only when SMB shares are served (`smbd` uses `winbindd` for SID/name resolution on share ACLs).
- **macOS counterpart:** macOS uses `opendirectoryd` with an AD plugin (configured via `dsconfigad`) that also speaks LDAP+Kerberos but does NOT use Netlogon for normal NSS/auth — see `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- Samba source — https://github.com/samba-team/samba (see `source3/winbindd/`, `source3/nsswitch/`, `source3/lib/idmap/`, `source3/libads/`).
- `wbinfo(1)`, `pam_winbind(8)`, `pam_winbind.conf(5)`, `idmap_rid(8)`, `idmap_autorid(8)`, `idmap_ad(8)`, `idmap_tdb2(8)`, `net(8)` man pages.
- Samba Wiki — "Active Directory Membership" and "idmap config" pages.
- MS-SAMR, MS-LSAD, MS-LSAR, MS-NRPC protocol documentation (referenced from `../02-protocols/06-rpc-dcerpc-ms-drsr.md`).
