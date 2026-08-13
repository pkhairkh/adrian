---
title: PAM and NSS Stacks on Linux — Name Service and Pluggable Authentication
audience: senior-engineers
tags: [pam, nss, nsswitch, pam_sss, pam_winbind, pam_krb5, pam_ldap, authselect, pam-auth-update, mkhomedir]
related:
  - ./01-sssd-ad-provider.md
  - ./04-winbind-internals.md
  - ./07-pbis-powerbroker.md
  - ./09-openldap-mit-kerberos.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/04-ntlm-internals.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
last_updated: 2026-08-13
---

The Linux identity stack is split between NSS (Name Service Switch, configured in `/etc/nsswitch.conf`) which resolves `passwd`/`group`/`shadow`/`hosts`/`services` lookups to one or more backend modules (`libnss_sss.so.2` for SSSD, `libnss_winbind.so.2` for Winbind, `libnss_ldap.so.2` or `libnss_lsass.so.2` for the others) and PAM (Pluggable Authentication Modules, configured in `/etc/pam.d/<service>` or `/etc/pam.conf`) which runs four phases — `auth`, `account`, `password`, `session` — across a stack of modules (`pam_sss.so`, `pam_winbind.so`, `pam_krb5.so`, `pam_ldap.so`, `pam_unix.so`, `pam_mkhomedir.so` / `pam_oddjob_mkhomedir.so`); each distro family generates these stacks via a different tool (`pam-auth-update` on Debian/Ubuntu, `authselect` on RHEL/Fedora, `pam-config` on SUSE) so direct hand-editing is fragile.

## NSS — `/etc/nsswitch.conf`

```
# /etc/nsswitch.conf — modern AD-joined Linux host running SSSD
passwd:     files sss systemd
shadow:     files sss
group:      files sss systemd

# Hosts — SSSD's `ipasudorule` resolver uses the `sss` module for ipa_hostname lookups too
hosts:      files dns myhostname

# Sudoers — SSSD sudo responder can serve /etc/sudoers rules from IPA/AD
sudoers:    files sss

# Services / netgroup / automount — SSSD can serve all of these too
services:   files sss
netgroup:   files sss
automount:  files sss

# Aliases / ethers / protocols / rpc / publickey — typically files only
aliases:    files
ethers:     files
protocols:  files
rpc:        files
publickey:  files
```

### NSS module chain semantics

For each lookup, glibc iterates the listed sources left-to-right:

- `files` — read `/etc/passwd`, `/etc/group`, `/etc/shadow`
- `sss` — `dlopen("libnss_sss.so.2")`, call `_nss_sss_getpwnam_r` → opens `/var/lib/sss/pipes/nss` and sends a `SSS_NSS_GETPWNAM` request to `sssd_nss` responder
- `winbind` — `libnss_winbind.so.2` → `/run/samba/winbindd/pipe` to `winbindd`
- `ldap` / `ldapd` — `libnss_ldap.so.2` (legacy) or `libnss_ldapd.so.2` → `nslcd`
- `lsass` — PBIS only — `libnss_lsass.so.2` → `lsassd`
- `systemd` — `libnss_systemd.so.2` — resolves `*_dynamic` users created by systemd units (`DynamicUser=yes`)
- `myhostname` — `libnss_myhostname.so.2` — always returns the local hostname to `gethostbyname`
- `mdns4_minimal` — Avahi/Bonjour mDNS — see `../08-macos-equivalents/07-dns-mdns-bonjour.md`

Status codes: `SUCCESS` continues to the next module if `action=continue`; `NOTFOUND` typically continues; `UNAVAIL` and `TRYAGAIN` typically continue unless `[UNAVAIL=return]` is set. The default action is `continue` for all status codes — i.e. next module is tried.

### NSS lookup request wire (SSSD)

`libnss_sss.so.2` sends a fixed binary structure over `/var/lib/sss/pipes/nss`:

```c
// source: src/sss_client/nss_mc.h (SSSD)
struct sss_nss_req {
    uint32_t type;          // SSS_NSS_GETPWNAM=1, SSS_NSS_GETPWUID=2,
                            // SSS_NSS_GETGRNAM=3, SSS_NSS_GETGRGID=4,
                            // SSS_NSS_INITGR=5 (initgroups), ...
    uint32_t reserved;
    uint32_t data_len;
    uint8_t  data[];        // argument (e.g. username, uid as 4-byte LE)
};
```

Responses come back as `sss_nss_rep` followed by the marshalled user/group struct. The `sss_nss` client library also maintains an mmap cache (`/var/lib/sss/mc/passwd`, `/var/lib/sss/mc/group`) so the responder is bypassed for hot lookups — see `src/sss_client/nss_mc.c:nss_mc_getpwuid`.

## PAM — `/etc/pam.d/`

Each service (`login`, `sshd`, `su`, `sudo`, `cron`, `gdm-password`, `cockpit`, etc.) has its own file `/etc/pam.d/<service>`. Generic files like `system-auth`, `password-auth`, `common-auth`, `common-account`, `common-password`, `common-session` are included via `@include` (Debian) or symlinked (RHEL `authselect`).

### PAM phases and module types

| Phase | Purpose | Module type |
|---|---|---|
| `auth` | Verify the user is who they claim (prompt for password, validate against KDC/LDAP/etc.) | `auth` |
| `account` | Check account validity (not expired, allowed by HBAC/GPO, etc.) | `account` |
| `password` | Update the password (writes to AD `unicodePwd`, LDAP `userPassword`, Kerberos KDB) | `password` |
| `session` | Pre/post-login setup (mount home, log session start, create home dir, set up ccache) | `session` |

### Control values

| Syntax | Meaning |
|---|---|
| `required` | Failure: log, continue stack, ultimate failure |
| `requisite` | Failure: log, immediately fail (no further modules) |
| `sufficient` | Success: if no prior `required` failed, immediately succeed (skip rest) |
| `optional` | Success or failure logged; result ignored unless it's the only module |
| `[default=N success=M ...]` | Per-return-code action; e.g. `[default=bad success=ok user_unknown=ignore]` |
| `substack` | Run a separate stack (`@include`-like) and aggregate results |

### Debian/Ubuntu — `pam-auth-update` (writes `/etc/pam.d/common-*`)

`/usr/sbin/pam-auth-update` reads profile metadata from `/usr/share/pam-configs/*` and writes `/etc/pam.d/common-auth`, `common-account`, `common-password`, `common-session`. Each profile (e.g. `sssd`, `winbind`, `ldap`, `krb5`, `mkhomedir`) ships a small debconf-driven file:

```
# /usr/share/pam-configs/sssd
Name: SSS authentication
Default: yes
Priority: 254
Auth-Type: Primary
Auth:
    [success=ok default=ignore]    pam_sss.so use_first_pass
Auth-Initial:
    [success=ok default=ignore]    pam_sss.so
Account-Type: Primary
Account:
    [success=ok new_authtok_reqd=done default=ignore]    pam_sss.so
Password-Type: Primary
Password:
    [success=ok default=ignore]    pam_sss.so use_authtok
Password-Initial:
    [success=ok default=ignore]    pam_sss.so
Session-Type: Additional
Session:
    required    pam_sss.so
Session-Initial:
    required    pam_sss.so
```

Enable / disable:

```bash
pam-auth-update --enable sss mkhomedir
pam-auth-update --disable winbind
pam-auth-update --force          # re-run without prompting
```

The resulting `/etc/pam.d/common-auth` (Debian):

```
auth    [success=2 default=ignore]      pam_unix.so nullok
auth    [success=1 default=ignore]      pam_sss.so use_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
```

### RHEL/Fedora/Rocky — `authselect` (writes `/etc/pam.d/system-auth`, `password-auth`)

`/usr/bin/authselect` ships profiles in `/usr/share/authselect/default/` (`sssd`, `winbind`, `nis`, `minimal`, `local`). Each profile has `system-auth`, `password-auth`, `postlogin`, `fingerprint-auth`, `smartcard-auth`, `nsswitch.conf` templates. Apply:

```bash
authselect select sssd with-mkhomedir with-sudo with-silent-lastlog --force
# writes /etc/pam.d/system-auth and /etc/pam.d/password-auth (NOT symlinked under /etc/pam.d/common-*)

authselect select winbind with-mkhomedir --force
authselect select sssd with-smartcard with-smartcard-required --force   # enforce smartcard
authselect apply-changes        # re-render after manual config edit
```

Profile features (after `with-`):

| Feature | Effect |
|---|---|
| `with-mkhomedir` | Enable `pam_oddjob_mkhomedir.so` in `session` |
| `with-sudo` | Add `sss` to `sudoers` in `nsswitch.conf`, enable `pam_sss.so` in `sudo` |
| `with-fingerprint` | Enable `pam_fprintd.so` |
| `with-smartcard` | Enable `pam_sss.so` smartcard-aware |
| `with-smartcard-required` | Require smartcard (password auth disabled) |
| `with-silent-lastlog` | Suppress `last login` message |
| `with-faillock` | Enable `pam_faillock.so` (account lockout) |
| `with-pamaccess` | Enable `pam_access.so` (consults `/etc/security/access.conf`) |
| `with-nullok` | Allow empty passwords (NOT recommended) |

The resulting `/etc/pam.d/system-auth` (RHEL, `authselect select sssd`):

```
auth        required                                    pam_env.so
auth        required                                    pam_faildelay.so delay=2000000
auth        sufficient                                  pam_unix.so nullok try_first_pass
auth        requisite                                   pam_succeed_if.so uid >= 1000 quiet
auth        sufficient                                  pam_sss.so use_first_pass
auth        required                                    pam_deny.so

account     required                                    pam_unix.so
account     sufficient                                  pam_succeed_if.so uid < 1000 quiet
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required                                    pam_permit.so

password    requisite                                   pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient                                  pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient                                  pam_sss.so use_authtok
password    required                                    pam_deny.so

session     optional                                    pam_keyinit.so revoke
session     required                                    pam_limits.so
-session    optional                                    pam_systemd.so
session     [success=1 default=ignore]                  pam_succeed_if.so service in crond quiet use_uid
session     required                                    pam_unix.so
session     optional                                    pam_sss.so
session     optional                                    pam_oddjob_mkhomedir.so umask=0077
```

### SUSE/openSUSE — `pam-config`

```bash
pam-config --add --sss --mkhomedir --mkhomedir-umask=0022
pam-config --add --krb5 --krb5-debug
pam-config --list
pam-config --write-all
```

Writes `/etc/pam.d/common-{auth,account,password,session}-pc` (the `-pc` suffix is the auto-generated file; the bare `common-*` files `@include common-*-pc`).

## PAM modules reference

### `pam_sss.so`

Source: SSSD `src/sss_client/pam_sss.c:pam_sm_authenticate` (built and installed as `/lib/x86_64-linux-gnu/security/pam_sss.so` or `/usr/lib64/security/pam_sss.so`).

| Parameter | Effect |
|---|---|
| `use_first_pass` | Use the password from a prior module's `pam_get_item(PAM_AUTHTOK)`; do not prompt |
| `try_first_pass` | Try the prior password first; prompt if it fails |
| `forward_pass` | Forward the entered password to subsequent modules via `pam_set_item(PAM_AUTHTOK)` (so `pam_unix` doesn't re-prompt) |
| `use_authtok` | In `password` phase, use the new password from a prior module (e.g. `pam_pwquality`) |
| `ignore_unknown_user` | Return `PAM_IGNORE` (not `PAM_USER_UNKNOWN`) if user not in SSSD domain — lets the stack fall through to local |
| `ignore_authinfo_unavail` | Return `PAM_IGNORE` if SSSD daemon unreachable |
| `domains=<domain1,domain2>` | Restrict this PAM invocation to the named SSSD domains |
| `renew_context=` | Renew the user's Kerberos context on each session open |
| `quiet` | Don't log to syslog |
| `debug` | Verbose logging |

`pam_sss.so` opens `/var/lib/sss/pipes/pam` and sends a `SSS_PAM_AUTHENTICATE` (or `_ACCT_MGMT` / `_CHAUTHTOK` / `_OPEN_SESSION` / `_CLOSE_SESSION`) request to `sssd_pam`. The response carries `PAM_AUTHINFO_UNAVAIL`, `PAM_SUCCESS`, `PAM_AUTH_ERR`, `PAM_NEW_AUTHTOK_REQD` (password must change), `PAM_PERM_DENIED` (access provider denied — e.g. GPO).

### `pam_winbind.so`

Source: Samba `source3/nsswitch/pam_winbind.c:pam_sm_authenticate`.

| Parameter | Effect |
|---|---|
| `try_first_pass` / `use_first_pass` / `use_authtok` / `forward_pass` | As for `pam_sss.so` |
| `require_membership_of = CORP\\LinuxAdmins` | Group-based access (analog of SSSD's `simple_allow_users`) |
| `require_membership_of = S-1-5-21-...-1234` | Same, by SID |
| `krb5_auth` | Acquire a TGT during `auth` phase and store in `krb5cc_%u` |
| `krb5_ccache_type = FILE:/run/user/%u/krb5cc` | Ccache type and location |
| `cached_login` | Try local cache first if DC unreachable |
| `debug = 100` | Verbose logging |
| `silent` | No syslog on auth failure |
| `show_stale_password_prompt` | Hint users when their password is expired |
| `unknown_ok` | Don't log unknown users |

### `pam_krb5.so`

Source: MIT Kerberos `src/plugins/kadm5` / `src/lib/krb5/pam/pam_krb5.c` (also shipped as a separate `pam_krb5` package from Russ Allbery's https://www.eyrie.org/~eagle/software/pam-krb5/). Used in pure-MIT stacks (see `./09-openldap-mit-kerberos.md`).

| Parameter | Effect |
|---|---|
| `try_first_pass` / `use_first_pass` / `forward_pass` | Standard PAM semantics |
| `use_authtok` | Use new password from prior module in `password` phase |
| `renew_lifetime = 7d` | Renewable lifetime for acquired TGT |
| `ticket_lifetime = 10h` | TGT lifetime |
| `minimum_uid = 1000` | Skip for system accounts |
| `debug` | Verbose logging |
| `ignore_root` | Don't try Kerberos for `root` |
| `no_ccache` | Don't write a ccache (just authenticate) |
| `ccache = FILE:/run/user/%u/krb5cc` | Ccache type and location |
| `tokens` | Run AFS/KFW token acquisition after TGT |
| `alt_auth_remote` | Use remote kadmin for password changes instead of local kpasswdd |

### `pam_ldap.so` / `pam_ldd.so`

`pam_ldap.so` (legacy, https://github.com/PADL/pam_ldap) and `pam_ldapd.so` (paired with `nslcd`, https://github.com/arthurdejong/nss-pam-ldapd) handle password changes via LDAP modify `userPassword` (the LDAP RFC 2256/4519 syntax) and simple bind for auth.

### `pam_oddjob_mkhomedir.so` and `pam_mkhomedir.so`

| Module | Source | When to use |
|---|---|---|
| `pam_mkhomedir.so` | glibc-shipped `Linux-PAM` `modules/pam_mkhomedir/pam_mkhomedir.c` | Static `/etc/skel`; simple; runs in the user's session |
| `pam_oddjob_mkhomedir.so` | `oddjob` daemon (`/usr/sbin/oddjobd`), `pam_oddjob_mkhomedir.c` | The D-Bus `oddjob` interface allows running mkhomedir as root with SELinux policy; required on RHEL with SELinux enforcing |

Configure via `authselect select sssd with-mkhomedir` (RHEL) or `pam-auth-update --enable mkhomedir` (Debian). The skel directory is `/etc/skel`; umask typically `0077` (RHEL) or `0022` (Debian).

### `pam_faillock.so` (account lockout)

Source: `Linux-PAM` `modules/pam_faillock/pam_faillock.c`. Implements AD-like account lockout after N failed attempts. Configured in `/etc/security/faillock.conf`:

```
deny             = 5
fail_interval    = 900
unlock_time      = 900
root_unlock_time = 60
audit
```

Equivalent of AD's "Account lockout threshold" GPO setting.

### `pam_access.so` (host-based access control)

Source: `Linux-PAM` `modules/pam_access/pam_access.c`. Consults `/etc/security/access.conf`:

```
# /etc/security/access.conf
+ : ALL : cron crond
+ : root : ALL
- : ALL : 127.0.0.0/8
+ : (admin) (root) : ALL
- : ALL : ALL
```

Powerful alternative to SSSD's `simple_allow_users` for static access control without modifying the directory.

### `systemd-homed`

`systemd-homed` (`systemd-homed.service`, `homectl` CLI; source: `src/home/homed.c` in systemd) is a systemd-native alternative to PAM `session` for user home directory lifecycle. Each user has a `*.home` LUKS image mounted on demand, with the user identity stored in a JSON record (not `/etc/passwd`). Activated by `pam_systemd_home.so`. Seldom deployed in enterprise AD-integrated environments because the user record is local (no directory sync), but supported as a per-user home-encryption option.

## Common PAM stacks side-by-side

### SSSD (`ad` provider) — RHEL

```
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        sufficient    pam_sss.so use_first_pass
auth        required      pam_deny.so

account     required      pam_unix.so
account     [default=bad success=ok user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient    pam_sss.so use_authtok
password    required      pam_deny.so

session     required      pam_limits.so
session     required      pam_unix.so
session     optional      pam_sss.so
session     optional      pam_oddjob_mkhomedir.so umask=0077
```

### Winbind — Debian

```
auth    [success=2 default=ignore]    pam_unix.so nullok
auth    [success=1 default=ignore]    pam_winbind.so krb5_auth try_first_pass
auth    requisite                     pam_deny.so
auth    required                      pam_permit.so

account [success=2 default=ignore]    pam_unix.so
account [success=1 default=ignore]    pam_winbind.so
account requisite                     pam_deny.so
account required                      pam_permit.so

password [success=2 default=ignore]   pam_unix.so obscure sha512
password [success=1 default=ignore]   pam_winbind.so use_authtok try_first_pass
password requisite                    pam_deny.so
password required                     pam_permit.so

session required                      pam_unix.so
session optional                      pam_mkhomedir.so umask=0022 skel=/etc/skel
session optional                      pam_winbind.so
```

### OpenLDAP + MIT Kerberos — RHEL

```
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        sufficient    pam_krb5.so try_first_pass
auth        sufficient    pam_ldap.so use_first_pass
auth        required      pam_deny.so

account     required      pam_unix.so broken_shadow
account     [default=bad success=ok user_unknown=ignore] pam_krb5.so
account     [default=bad success=ok user_unknown=ignore] pam_ldap.so
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass retry=3
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    sufficient    pam_krb5.so use_authtok
password    sufficient    pam_ldap.so use_authtok
password    required      pam_deny.so

session     required      pam_limits.so
session     required      pam_unix.so
session     optional      pam_mkhomedir.so umask=0022 skel=/etc/skel
```

## Wireshark / tshark

PAM/NSS traffic is mostly local (Unix sockets). The wire-visible signals are downstream of NSS/PAM — i.e. the actual LDAP/Kerberos/SMB/DCE-RPC traffic from the daemon:

```
# Kerberos AS-EXCHANGE from pam_sss.so / pam_krb5.so / pam_winbind.so
kerberos.msg_type == 10 || kerberos.msg_type == 11

# LDAP from sssd_be / nslcd / lsassd
ldap.messageCode == 0 && (ldap.authentication.mechanism == "GSS-SPNEGO" || ldap.authentication.mechanism == "simple")

# LDAP bind failure (auth phase failure visible as BindResponse with resultCode != 0)
ldap.messageCode == 1 && ldap.result_code != 0

# MSRPC NetrLogonSamLogonEx from lsassd / winbindd (auth phase)
dcerpc.netlogon.opnum == 39

# SSSD PAC responder validating a service ticket's PAC
kerberos.pac.logon_info

# DNS SRV for KDC discovery (the first thing each auth does on cold start)
dns.qry.name contains "_kerberos._tcp.dc._msdcs" or dns.qry.name contains "_kpasswd._tcp"
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `su - user@domain` fails with `Permission denied` but `id` works | `pam_sss.so` not in `account` phase | `authselect select sssd with-mkhomedir --force` (RHEL) or `pam-auth-update --enable sss` (Debian) |
| SSH login slow (5-10 s) | `pam_krb5.so` retrying unreachable KDC; or DNS SRV lookup failing | Add `krb5.conf dns_lookup_kdc = false` and hardcode KDC; or fix DNS |
| Login works but `~` is empty | `pam_mkhomedir` not in session; or `oddjobd` not running | `systemctl enable --now oddjobd`; check `authselect current` shows `with-mkhomedir` |
| Password change fails with `User not known to the underlying authentication module` | `pam_sss.so use_authtok` failed to receive new password from `pam_pwquality` | Ensure `pam_pwquality` is *before* `pam_sss.so use_authtok` in `password` stack |
| `User not allowed to log in` despite correct password | SSSD access provider denied (GPO or simple) | Check `/var/log/sssd/sssd_pam.log` for `Access denied by ...`; see `./03-sssd-gpo-access.md` |
| Local users (root, etc.) can't log in | `pam_sss.so ignore_unknown_user` missing, and `pam_sss` returns `PAM_USER_UNKNOWN` which `pam_deny` interprets as failure | Add `ignore_unknown_user` to `pam_sss.so` lines |
| Two password prompts on SSH | `pam_unix.so try_first_pass` not set, or `forward_pass` missing on `pam_sss.so` | Add `forward_pass` to `pam_sss.so` and `use_first_pass` to `pam_unix.so` |
| `nslcd` returning stale data after AD group membership change | `nslcd` cache TTL too long; or AD replication not converged | `nscd -i passwd -i group` (if `nscd` running); reduce `cache` in `/etc/nslcd.conf` |
| `pam_winbind` fails intermittently with `NT_STATUS_PIPE_NOT_AVAILABLE` | `winbindd` not running, or out of file descriptors | `systemctl status winbind`; raise `ulimit -n` in `/etc/systemd/system/winbind.service` |
| Login works for AD user but `sudo` doesn't | `pam_sss.so` not in `/etc/pam.d/sudo`; or `sudoers: files sss` missing in `nsswitch.conf` | `authselect select sssd with-sudo --force` (RHEL); or add `session optional pam_sss.so` to `/etc/pam.d/sudo` |

Logs: `/var/log/secure` (RHEL) or `/var/log/auth.log` (Debian) for PAM-level events; `/var/log/sssd/sssd_pam.log` and `sssd_nss.log` for SSSD side; `/var/log/samba/log.pam_winbind` for `pam_winbind`. PAM debug: append `debug` to the offending module line; full PAM debug requires building `Linux-PAM` with `--enable-debug`.

## Cross-platform comparison

- **AD-side counterpart:** Windows has no PAM/NSS distinction — `lsass.exe` is the single LSA server handling both name resolution (`LsaLookupSids`/`LsaLookupNames`) and authentication (`LsaLogonUser`); the equivalent of `nsswitch.conf` is the `LsaLookup*` well-known-SID table plus any installed Security Support Providers (SSPs — see `../02-protocols/04-ntlm-internals.md` for NTLM SSP and `../02-protocols/01-kerberos-internals.md` for Kerberos SSP). The Kerberos PAC validation flow (`NetrLogonSamLogonEx` over Netlogon) is conceptually similar to PAM's `account` phase calling back to a directory for authorization checks — see `../02-protocols/08-spn-upn-pac.md`.
- **macOS counterpart:** macOS uses PAM (the same Linux-PAM source compiled for Darwin) but its PAM stack is much simpler and the backend is `opendirectoryd` via `pam_odl.so` (the OpenDirectory PAM module). `/etc/pam.d/authorization`, `/etc/pam.d/login`, `/etc/pam.d/sudo` etc. each have a handful of lines: `auth sufficient pam_odl.so`, `account required pam_odl.so`, plus `pam_deny.so` and `pam_permit.so`. macOS has no `nsswitch.conf` — OpenDirectory is consulted directly via the `DirectoryService` framework. See `../08-macos-equivalents/01-opendirectory-internals.md` and `../08-macos-equivalents/02-dscl-dsconfigad.md`.
- **Linux-stacks comparison:** See `./01-sssd-ad-provider.md` (SSSD), `./04-winbind-internals.md` (Winbind), `./07-pbis-powerbroker.md` (PBIS), `./09-openldap-mit-kerberos.md` (OpenLDAP+MIT) for the PAM/NSS modules each stack installs.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- Linux-PAM source — https://github.com/linux-pam/linux-pam (modules in `modules/`).
- glibc NSS source — `glibc/nis/nss_files/`, `glibc/nss/nss_database.c`.
- SSSD `pam_sss.so` source — `src/sss_client/pam_sss.c` in https://github.com/SSSD/sssd.
- Samba `pam_winbind.so` source — `source3/nsswitch/pam_winbind.c` in https://github.com/samba-team/samba.
- `pam-krb5` (Russ Allbery) — https://www.eyrie.org/~eagle/software/pam-krb5/.
- `nss-pam-ldapd` (`nslcd`) — https://github.com/arthurdejong/nss-pam-ldapd.
- `authselect` source — https://github.com/authselect/authselect.
- `pam-auth-update` (Debian `libpam-runtime`) — https://salsa.debian.org/pkg-pam-team/pam/-/tree/main/debian/local/pam-auth-update.
- `oddjob` source — https://pagure.io/oddjob.
- `pam(8)`, `pam.conf(5)`, `nsswitch.conf(5)`, `pam_sss(8)`, `pam_winbind(8)`, `pam_krb5(5)`, `pam_ldap(8)`, `pam_mkhomedir(8)`, `pam_oddjob_mkhomedir(8)`, `pam_faillock(8)`, `pam_access(8)`, `authselect(8)`, `pam-auth-update(8)`, `pam-config(8)`, `homectl(1)`.
