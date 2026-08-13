---
title: Authentication Flow Comparison (Windows / macOS / Linux SSSD / Linux Winbind)
audience: senior-engineers
tags: [auth-flow, lsa, pam, kerberos, sssd, winbind, platform-sso]
related:
  - ./01-feature-os-matrix.md
  - ./02-protocol-implementation-matrix.md
  - ./03-tool-function-matrix.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/04-ntlm-internals.md
  - ../02-protocols/08-spn-upn-pac.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../08-macos-equivalents/05-kerberos-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../09-linux-equivalents/04-winbind-internals.md
last_updated: 2026-08-13
---

# Authentication Flow Comparison

Side-by-side login flow for a domain-joined workstation: **user enters password** at the lock screen. Four columns: Windows 11, macOS 13+ (PSSO Extension), Linux with SSSD, Linux with Winbind. Each row is a phase of the flow. ASCII diagrams inline.

## Scenario

- User `jsmith@CORP.EXAMPLE.COM` unlocks their domain-joined workstation with password `P@ss!`.
- DC: `dc01.corp.example.com` (10.10.0.10).
- Time T0 = logon initiated.

## Flow table

| # | Phase | Windows 11 | macOS 13+ (PSSO Extension) | Linux SSSD | Linux Winbind |
|---|---|---|---|---|---|
| 1 | Initial user input | LogonUI.exe captures credential into LSA. Securable `Winlogon.exe → msgina → LogonUI` pipeline. | loginwindow.app passes credential to `authorizationhost`/`SecurityAgent` → PSSO Extension (`com.apple.applesso`). | `gdm` (or `sddm`/`lightdm`) calls PAM via `pam_authenticate`. | Same as SSSD — `gdm`/`sddm` invokes PAM. |
| 2 | PAM / LSA path | LSA (`lsass.exe`) `LsaLogonUser()` → Kerberos SSP (`kerberos.dll`) selected. No PAM. | OpenDirectory `odagentd` + `securityd` route to PSSO Extension (`CredentialProvider`). Extension performs Kerberos via Heimdal libs. | PAM stack `/etc/pam.d/system-auth` (managed by `authselect`) → `pam_sss.so` → SSSD `pam_sss` responder → `sssd_pam` → `sssd_be` (AD provider). | PAM stack → `pam_winbind.so` → `winbindd` (`winbind pam_creds` pipe) → Samba `libnetjoin`/`netlogon` code. |
| 3 | DC location | Netlogon service discovery (`DcGetDcName` RPC) → DNS SRV `_ldap._tcp.dc._msdcs.corp.example.com` → ping. | `dsconfigad`-configured DC list (cached at `/Library/Preferences/OpenDirectory/Configurations/ActiveDirectory/Domains.plist`); PSSO may query SRV. | SSSD's `ad_dns_lookup` (forks `nsupdate`/`resolv.conf`) → SRV `_ldap._tcp.dc._msdcs.corp.example.com` → ping `ldap_ping`. | `winbindd` `get_dc_name()` → DNS SRV `_ldap._tcp.dc._msdcs` → `ldap_ping` over MS-NRPC `NetrServerReqChallenge`. |
| 4 | LDAP bind or Kerberos AS exchange | Kerberos SSP sends AS-REQ to dc01:88. Pre-auth via PA-ENC-TIMESTAMP (AES-256 key derived from password). KDC returns AS-REP with TGT (PAC included, signed). No LDAP bind at logon. | PSSO Extension sends AS-REQ via Heimdal `krb5_get_init_creds`. Same pre-auth. AS-REP returns TGT. PSSO stores in CCACHE (`/tmp/krb5cc_<uid>` via `KCM`/`API:`). | SSSD sends AS-REQ via MIT krb5 (`krb5_get_init_creds_password`). Pre-auth same. TGT cached at `/var/lib/sss/db/ccache_CORP.EXAMPLE.COM` (KEYRING-backed). After AS-REP, SSSD does a SASL GSSAPI bind to LDAP (port 389 + StartTLS or 636) to fetch user entry + group memberships + `tokenGroups`. | Winbind sends AS-REQ via Heimdal (or MIT if built with it). TGT cached at `/var/cache/samba/krb5cc_<uid>` (or `KEYRING:`). Winbind then does `NetrSamLogon` (MS-NRPC opnum 45) over the machine secure channel — DC validates and returns user info + groups. No LDAP bind typically. |
| 5 | Ticket / cache storage | LSA holds TGT in `lsass.exe` process memory (kernel-pinned). Service tickets cached in LSA, accessed via `klist`. User-mode apps get tickets via `LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage)`. | CCACHE at `/tmp/krb5cc_<uid>` (default type `API:` — Heimdal's in-memory store). `klist -v` reads it. PSSO Extension also pushes the TGT to the kernel keyring for SMB client use. | CCACHE at `/var/lib/sss/db/ccache_CORP.EXAMPLE.COM` (or `KEYRING:persistent:%{uid}`). SSSD holds an additional "renewal daemon" — `sssd_kcm` renews TGTs near 50% lifetime. | CCACHE at `/var/cache/samba/krb5cc_<uid>`. Winbind caches group/SID map in `winbindd_cache.tdb`. |
| 6 | Home directory creation | `Winlogon` loads `userenv.dll` → `CreateProfile()` → `%USERPROFILE%\Documents`, etc. Roaming profile pulled from `\\dc01\Profiles\jsmith` if configured. | `System.framework` `CFPreferences` + `createhomedir -c` for mobile accounts; `dscl . -create /Users/jsmith NFSHomeDirectory /Users/jsmith`. | `pam_mkhomedir.so` (or `oddjobd` + `pam_oddjob_mkhomedir.so`) creates `/home/jsmith` from `/etc/skel`. Configured in `system-auth` via `authselect`. | Same as SSSD path — `pam_mkhomedir.so` creates `/home/jsmith`. Winbind doesn't provide home creation directly; relies on PAM module. |
| 7 | Subsequent service ticket acquisition | On access to `cifs/file01.corp.example.com`, workstation's SMB redirector requests TGS-REQ from KDC for `cifs/file01@CORP.EXAMPLE.COM`. PAC included. SMB2 Session Setup carries the service ticket as `AP-REQ` (GSS-SPNEGO). | On `smb://file01.corp.example.com` access, SMB client (`smbx`/`smbd`) calls `krb5_get_credentials()` for `cifs/file01@CORP.EXAMPLE.COM`. TGS-REP cached in CCACHE. SMB2 Session Setup uses `AP-REQ`. | On `mount -t cifs //file01/share`, kernel CIFS VFS calls `getkrb5ccname` via `keyctl` → userspace `cifs.upcall` runs `kinit -S cifs/file01@CORP` → TGS-REQ. Ticket stored in kernel keyring, referenced by SMB Session Setup. | On `mount -t cifs`, `cifs.upcall` calls `nmblookup` → `kinit` (Heimdal) → TGS-REQ. Alternatively, winbind's `multimount` flow can use its own credentials cache. |
| 8 | Logoff | `Winlogon` calls `ExitWindowsEx()`. LSA `LsaDeregisterLogonProcess()`. TGT and service tickets purged from LSA. Profile unloaded (if no handles open). Roaming profile uploaded to `\\dc01\Profiles\jsmith`. | `loginwindow.app` invokes `logout` → `securityd` purges CCACHE (`kdestroy`). Profile sync if mobile account. `sso_util cache -d` purges PSSO cache. | PAM `pam_close_session` invoked → `pam_sss.so` notifies `sssd_pam` → SSSD marks session closed. CCACHE *not* auto-purged (TGT renewal daemon may keep it). `kdestroy` for explicit purge. | `pam_winbind.so` `pam_close_session` notifies `winbindd`. CCACHE typically retained until reboot or `kdestroy`. |

## ASCII flow diagrams

### Windows 11

```
   User
     │ password
     ▼
 LogonUI.exe ──► LSA (lsass.exe)
                    │
                    │ LsaLogonUser()
                    ▼
              Kerberos SSP (kerberos.dll)
                    │
                    │ DNS SRV _ldap._tcp.dc._msdcs
                    ▼
              dc01.corp.example.com:88
                    │
                    │ AS-REQ (PA-ENC-TIMESTAMP, AES-256)
                    ▼
              AS-REP (TGT + PAC, signed)
                    │
                    ▼
              LSA caches TGT in-process
                    │
                    │ User opens \\file01\share
                    ▼
              TGS-REQ cifs/file01@CORP
                    │
                    ▼
              TGS-REP (service ticket + PAC)
                    │
                    ▼
              SMB2 Session Setup (AP-REQ in SPNEGO)
                    │
                    ▼
              file01:445 authenticates session
```

### macOS 13+ (PSSO Extension)

```
   User
     │ password (at loginwindow)
     ▼
 SecurityAgent ──► authorizationhost
                    │
                    │ AuthorizationRight: system.login.console
                    ▼
              OpenDirectory (odagentd, securityd)
                    │
                    │ routes to PSSO Extension
                    ▼
              com.apple.applesso (PSSO Extension)
                    │
                    │ Heimdal krb5_get_init_creds_password()
                    ▼
              dc01.corp.example.com:88
                    │
                    │ AS-REQ (PA-ENC-TIMESTAMP)
                    ▼
              AS-REP (TGT + PAC)
                    │
                    ▼
              CCACHE /tmp/krb5cc_<uid>  (type API:)
                    │
                    │ Kernel keyring sync for smbx
                    ▼
              smbx ─► TGS-REQ cifs/file01@CORP
                    │
                    ▼
              SMB2 Session Setup (AP-REQ)
```

### Linux SSSD

```
   User
     │ password (at gdm)
     ▼
 gdm ──► PAM stack /etc/pam.d/system-auth
          │
          │ pam_authenticate
          ▼
       pam_sss.so ──► /var/run/.sss_pam_socket
                       │
                       ▼
                    sssd_pam (responder)
                       │
                       ▼
                    sssd_be (AD provider)
                       │
                       │ (1) DNS SRV _ldap._tcp.dc._msdcs
                       ▼
                    dc01.corp.example.com
                       │
                       │ (2) MIT krb5 AS-REQ:88
                       ▼
                    AS-REP (TGT)
                       │
                       │ (3) LDAP SASL GSSAPI bind :389 (StartTLS) or :636
                       ▼
                    user entry + tokenGroups retrieved
                       │
                       ▼
                    CCACHE /var/lib/sss/db/ccache_CORP.EXAMPLE.COM
                    (KEYRING:persistent:<uid>)
                       │
                       │ TGT renewed by sssd_kcm near 50% lifetime
                       ▼
                    (User mounts //file01/share)
                       │
                       ▼
                    cifs.upcall ──► kinit -S cifs/file01@CORP
                       │
                       ▼
                    TGS-REP → kernel keyring → SMB2 Session Setup
```

### Linux Winbind

```
   User
     │ password (at gdm)
     ▼
 gdm ──► PAM stack
          │
          │ pam_authenticate
          ▼
       pam_winbind.so ──► winbindd privileged pipe
                            │
                            │ winbindd_pam_auth()
                            ▼
                         get_dc_name() → DNS SRV _ldap._tcp.dc._msdcs
                            │
                            ▼
                         dc01.corp.example.com
                            │
                            │ (1) AS-REQ:88 (Heimdal) for user TGT
                            ▼
                         AS-REP (TGT)
                            │
                            │ (2) NetrServerReqChallenge + NetrServerAuthenticate3
                            │     over machine secure channel
                            ▼
                         NetrSamLogon (MS-NRPC opnum 45)
                            │
                            ▼
                         DC returns user info + groups (PAC inside)
                            │
                            ▼
                         CCACHE /var/cache/samba/krb5cc_<uid>
                         winbindd_cache.tdb (SID↔uid map)
                            │
                            │ (User mounts //file01/share)
                            ▼
                         cifs.upcall ──► kinit -S cifs/file01@CORP
                            │
                            ▼
                         TGS-REP → SMB2 Session Setup
```

## Diagnostic checkpoints per stage

| Stage | Windows | macOS | SSSD | Winbind |
|---|---|---|---|---|
| 1 (input) | Event 4624 (logon success) / 4625 (failure) | `log show --predicate 'subsystem == "com.apple.Authorization"'` | `journalctl -u sssd-pam` | `journalctl -t winbindd` |
| 2 (PAM/LSA) | `wevtutil qe Security` for Logon events | `log show --predicate 'senderImagePath CONTAINS "SecurityAgent"'` | `pamtester login jsmith authenticate` | `wbinfo -a CORP\\jsmith%pass` |
| 3 (DC loc) | `nltest /dsgetdc:corp` | `dig SRV _ldap._tcp.dc._msdcs.corp.example.com` | `sssctl domain-status corp.example.com` | `wbinfo --getdcname=corp` |
| 4 (AS) | Event 4768 (TGT success) / 4771 (pre-auth fail) | `klist -v` (shows AS-REP times) | `journalctl -u sssd-krb5` + `klist -vef` | `wbinfo -a` + `klist -vef` |
| 5 (cache) | `klist` (LSA tickets) | `klist` (`/tmp/krb5cc_<uid>`) | `klist` (KEYRING or FILE) | `klist` (`/var/cache/samba/krb5cc_<uid>`) |
| 6 (home) | `gpresult /h` (Folder Redirection) | `ls -la /Users/jsmith` | `ls -la /home/jsmith` | `ls -la /home/jsmith` |
| 7 (TGS) | Event 4769 (service ticket) | `klist -v` (shows service tickets) | `klist -vef` | `klist -vef` |
| 8 (logoff) | Event 4647 | `log show --predicate 'eventMessage CONTAINS "logout"'` | `journalctl -u sssd-pam` (session close) | `journalctl -t winbindd` |

## Key behavioral differences

- **Windows** keeps the TGT in kernel/LSA memory and never writes it to disk. Even `klist` is reading from LSA via RPC. Privilege escalation attacks on LSA (`lsass.exe` memory) are why Microsoft introduced LSA Protected Mode (`RunAsPPL`) and Credential Guard.
- **macOS** stores CCACHE on disk by default (`/tmp/krb5cc_<uid>`), though PSSO Extension can use `API:` (in-memory) or the kernel keyring. Files are mode 600 by default.
- **SSSD** keeps the TGT in a per-user KEYRING (preferred) or in `/var/lib/sss/db/ccache_<DOMAIN>` with mode 600. The renewal daemon (`sssd_kcm`) auto-renews near 50% of lifetime — Windows does the same automatically; macOS does not (re-prompts for password on expiry).
- **Winbind** keeps the TGT in `/var/cache/samba/krb5cc_<uid>` and additionally caches the SID↔uid map in `winbindd_cache.tdb`. Group resolution goes through `NetrSamLogon` (MS-NRPC) which is fundamentally different from SSSD's LDAP+SASL approach — same end data, different wire path.
- **MS-NRPC vs LDAP for group lookup**: Winbind prefers NRPC (machine secure channel, no additional Kerberos ticket). SSSD prefers LDAP (uses the user's TGT to get a service ticket for `ldap/dc01`). Both are valid; SSSD's approach gives finer ACL control but requires the user to have read rights to the directory.
- **Home directory creation**: Windows uses `userenv.dll!CreateProfile`. macOS uses `createhomedir` or `dscl . -create` for mobile accounts. Linux (both SSSD and Winbind) uses `pam_mkhomedir.so` or `oddjobd`. Behaviorally identical; mechanism differs.
- **Ticket purge on logoff**: Windows purges. macOS purges (PSSO calls `kdestroy`). SSSD does NOT auto-purge — the renewal daemon keeps the TGT across sessions if `krb5_renew_interval` is set. Winbind typically does NOT auto-purge either. This is a security-vs-usability tradeoff: keep TGT = fast re-auth, but a compromised session retains Kerberos creds.
