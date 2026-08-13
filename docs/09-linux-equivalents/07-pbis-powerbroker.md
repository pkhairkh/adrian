---
title: PBIS / PowerBroker Open — BeyondTrust's Legacy AD Integration Stack
audience: senior-engineers
tags: [pbis, powerbroker, beyondtrust, likewise, lwsmd, lsass, registry, domainjoin-cli]
related:
  - ./01-sssd-ad-provider.md
  - ./04-winbind-internals.md
  - ./06-realmd-join-flow.md
  - ./10-pam-nss-stack.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/01-kerberos-internals.md
  - ../08-macos-equivalents/02-dscl-dsconfigad.md
last_updated: 2026-08-13
---

PBIS (PowerBroker Identity Services, Open Edition — formerly Likewise Open, acquired by BeyondTrust from Likewise Software in 2012) is an alternative AD-integration stack consisting of the `lwsmd` service broker daemon plus its own PAM module (`pam_lsass.so`), NSS module (`libnss_lsass.so.2`), and machine-account/registry tooling, all bundled under `/opt/pbis/`, with its own proprietary registry at `/opt/pbis/lwidata/` storing all configuration; PBIS Open's last release was 8.5.x in 2014 and BeyondTrust discontinued the open-source edition, leaving commercial-only "PowerBroker Identity Services AD Bridge" as the successor.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  /opt/pbis/                                                       │
│    ├── bin/                                                       │
│    │   ├── domainjoin-cli         # join/leave                    │
│    │   ├── config                 # registry read/write           │
│    │   ├── enum-users  enum-groups                                │
│    │   ├── lwsm                   # service manager (like svcs)   │
│    │   ├── lwreg                  # registry shell                │
│    │   ├── lwmachine              # machine account ops           │
│    │   ├── pbis                   # umbrella command              │
│    │   ├── pbis-status            # health check                  │
│    │   ├── ad-cache --flush       # NSS cache flush               │
│    │   ├── krb5-keytab            # keytab manager                │
│    │   └── find-user                                              │
│    ├── sbin/                                                      │
│    │   ├── lwsmd                  # PBIS daemon (init by systemd)  │
│    │   ├── netlogond              # NETLOGON secure channel       │
│    │   ├── lsassd                 # Local Security Authority Subsystem (auth+NSS) │
│    │   ├── eventlogd              # event log forwarder           │
│    │   ├── lwregd                 # registry daemon               │
│    │   ├── dcerpcd                # DCE/RPC endpoint mapper       │
│    │   └── reapsysl               # syslog reaper                 │
│    ├── lib/                                                       │
│    │   ├── libnss_lsass.so.2      # NSS module                    │
│    │   ├── security/pam_lsass.so  # PAM module                    │
│    │   └── liblwbase.so, liblwiauth.so, libdsmodule.so, …         │
│    ├── config/                                                    │
│    │   ├── reg.dat                # main registry hive (LWI binary format) │
│    │   └── registry.db            # alternative (older versions)  │
│    ├── lwidata/                                                   │
│    │   ├── db/                    # per-service state              │
│    │   └── cache/                 # NSS cache (TDB-like)           │
│    └── share/                                                     │
└─────────────────────────────────────────────────────────────────┘
```

### `lwsmd` service broker

`/opt/pbis/sbin/lwsmd` (Likewise Service Manager, the PBIS equivalent of systemd or SMF) is launched at boot via `/etc/systemd/system/lwsmd.service` (`Type=forking`, `ExecStart=/opt/pbis/sbin/lwsmd start`, `PIDFile=/var/run/lwsmd.pid`). It reads `/opt/pbis/config/reg.dat` (the registry hive, an LWI-format binary), then starts the per-service child daemons:

| Service | Binary | Role |
|---|---|---|
| `lwreg` | `/opt/pbis/sbin/lwregd` | Registry daemon (serves registry reads/writes from other PBIS components) |
| `dcerpc` | `/opt/pbis/sbin/dcerpcd` | Endpoint mapper ( listens on TCP 135 + dynamic ports for DCE/RPC, like Windows `rpclss.dll` in svchost) |
| `netlogon` | `/opt/pbis/sbin/netlogond` | Netlogon secure-channel client (NetrServerAuthenticate3, NetrLogonSamLogonEx) |
| `lsass` | `/opt/pbis/sbin/lsassd` | Local Security Authority Subsystem — handles authentication (PAM), NSS lookups, ID mapping, group enumeration, password changes |
| `eventlog` | `/opt/pbis/sbin/eventlogd` | Event log forwarder to Windows event log (legacy) |

Each service is started/stopped via `/opt/pbis/bin/lwsm`:

```bash
/opt/pbis/bin/lwsm list                  # all services and status
/opt/pbis/bin/lwsm info lsass
/opt/pbis/bin/lwsm restart lsass
/opt/pbis/bin/lwsm set-autostart lsass yes
```

### Authentication flow

1. PAM `auth` phase calls `pam_lsass.so pam_sm_authenticate` (`/opt/pbis/lib/security/pam_lsass.so`).
2. `pam_lsass.so` opens a UNIX socket connection to `lsassd` at `/var/lib/pbis/lsassd/lsassd.sock` and sends a `LsaAuthenticateUser` IPC request.
3. `lsassd` (`source/lsass/server/lsassd.c:main` in Likewise/PBIS source — note: the open-source drop was on a BeyondTrust SVN server that is now offline; reverse-engineered format from 8.x binaries) decides:
   - For local user: hash-compare against `/etc/shadow` (via `pam_unix` integration).
   - For AD user: ask `netlogond` to perform `NetrLogonSamLogonEx` against the DC with NTLM pass-through or Kerberos.
4. `netlogond` maintains the Netlogon secure channel (`NetrServerAuthenticate3` with the machine-account password stored in registry `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SecureChannel`-equivalent).
5. On success, `lsassd` returns the user's PAC to `pam_lsass.so`; `pam_lsass.so` opens a ccache and writes the TGT acquired via `kinit` against the KDC.

### NSS flow

`libnss_lsass.so.2` (`/opt/pbis/lib/libnss_lsass.so.2`) implements `_nss_lsass_getpwnam_r`, `_nss_lsass_getpwuid_r`, `_nss_lsass_getgrnam_r`, `_nss_lsass_getgrgid_r`, `_nss_lsass_initgroups_dyn`. Each calls into `lsassd` over the same UNIX socket. `lsassd` consults its in-memory cache (refreshed by `LsaEnumerateUsers`/`LsaEnumerateGroups` polling tasks) and falls back to LDAP queries against the GC for cross-domain SIDs.

ID mapping is fixed by `LsaSetIdMapConfiguration` (configurable via `config` CLI): PBIS uses an algorithmic scheme similar to Winbind's `idmap_rid` with the `RangeMin`/`RangeMax`/`RangeSize` registry keys, OR reads `uidNumber`/`gidNumber` from AD in "RFC 2307 mode" (`AssumeDefaultDomain = true` + `DomainManager:DomainSeparator = +`).

## Configuration

PBIS does not use traditional text config files. All configuration lives in the LWI registry at `/opt/pbis/config/reg.dat` (binary format), accessed via `/opt/pbis/bin/config` (read) and `/opt/pbis/bin/config --set <path> <value>` (write).

### Key registry paths

| Registry key | Default | Purpose |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\DomainName` | (empty) | Joined domain DNS name |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\MachineAccount` | (empty) | NetBIOS computer name (HOST01$) |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\Cell` | (empty) | Cell DN for cell-based ID overrides (PBIS-specific feature) |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\AssumeDefaultDomain` | 0 | 1 = strip domain prefix in NSS lookups (like Samba's `winbind use default domain = yes`) |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\RequireMembershipOf` | (empty) | List of S-1-5-21-…/groups that can log in (analog of `simple_allow_users`) |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\DomainManager\UseMachinePassword` | 1 | Use machine account creds for LDAP binds (vs. user creds) |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\DomainManager\DomainSeparator` | `\` | Separator for domain-qualified names (some sites use `+` or `@`) |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\LdapServer` | (auto) | Comma-separated DC list (auto-discovered if empty) |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\SiteName` | (auto) | AD site to prefer |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\UseLdap98` | 0 | Legacy LDAPv2 |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\IdMap\Algorithm` | `LsaIdMapAlgorithmRFC2307` or `LsaIdMapAlgorithmBySid` | ID mapping mode |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\IdMap\RangeMin` | 10000000 | Lowest UID PBIS will allocate |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\IdMap\RangeMax` | 19999999 | Highest |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\IdMap\RangeSize` | 1000000 | Slice size per domain |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Pam\EnableOfflineLogon` | 1 | Cache credentials for offline auth |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Pam\PasswordPrompt` | `Password:` | PAM prompt override |
| `HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Kerberos\CCacheDir` | `/tmp` | TGT storage location |
| `HKLM\SYSTEM\CurrentControlSet\Services\netlogon\Parameters\RequireStrongKey` | 1 | Reject weak Netlogon crypto (CVE-2020-1472 mitigation) |
| `HKLM\SYSTEM\CurrentControlSet\Services\eventlog\Parameters\Server` | (empty) | Syslog/event log forwarder target |

### Reading the registry

```bash
# Dump everything (readable text)
/opt/pbis/bin/config --dump

# Read a single key
/opt/pbis/bin/config RequireMembershipOf
/opt/pbis/bin/config --key 'HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\AssumeDefaultDomain'

# Read with full key path
/opt/pbis/bin/config 'HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\Cell'

# Compare to Windows registry:
# Windows: reg query "HKLM\SOFTWARE\BeyondTrust\PBIS\..." /s
# (PBIS exposes its registry as a Windows-compatible hive when installed on Windows,
#  via the LWI Registry provider service)
```

### Writing the registry

```bash
# Restrict logon to members of CORP\LinuxAdmins and CORP\LinuxUsers
/opt/pbis/bin/config RequireMembershipOf "CORP\\LinuxAdmins" "CORP\\LinuxUsers"

# Strip domain prefix from usernames
/opt/pbis/bin/config --set AssumeDefaultDomain 1

# Set AD site preference
/opt/pbis/bin/config --set 'HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\SiteName' "HQ"

# Use RFC 2307 mode
/opt/pbis/bin/config --set 'HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\IdMap\Algorithm' LsaIdMapAlgorithmRFC2307

# Restart lsassd to apply
/opt/pbis/bin/lwsm restart lsass
```

### `/etc/krb5.conf` (PBIS auto-writes during join)

PBIS writes a minimal `/etc/krb5.conf`:

```ini
[libdefaults]
 default_realm = CORP.EXAMPLE.COM
 dns_lookup_realm = true
 dns_lookup_kdc = true
 ticket_lifetime = 24h
 forwardable = yes
 renew_lifetime = 7d

[realms]
 CORP.EXAMPLE.COM = {
  kdc = dc01.corp.example.com
  kdc = dc02.corp.example.com
  admin_server = dc01.corp.example.com
 }

[domain_realm]
 .corp.example.com = CORP.EXAMPLE.COM
 corp.example.com = CORP.EXAMPLE.COM

[appdefaults]
 pam = {
   debug = false
   ticket_lifetime = 36000
   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
```

PBIS also drops a `/etc/krb5.conf.d/pbis-krb5.conf` include on some distros, and writes the machine-account keytab at `/etc/krb5.keytab`.

### `/etc/nsswitch.conf` (PBIS-modified)

```
passwd:     files lsass
shadow:     files lsass
group:      files lsass
```

Note the module name `lsass` (not `sss` or `winbind`).

## Commands / examples

```bash
# Join
/opt/pbis/bin/domainjoin-cli join corp.example.com admin
# Output: Joining to AD Domain:   corp.example.com
#         With Computer DNS Name: host01.corp.example.com
#         admin@CORP.EXAMPLE.COM's password: ...
#         SUCCESS

# Join with explicit OU
/opt/pbis/bin/domainjoin-cli join --ou "OU=LinuxServers,DC=corp,DC=example,DC=com" \
  corp.example.com admin

# Leave
/opt/pbis/bin/domainjoin-cli leave
# Output: Leaving domain: corp.example.com ... SUCCESS

# Query join state
/opt/pbis/bin/domainjoin-cli query
# Output: Name:      host01
#         Domain:    CORP.EXAMPLE.COM
#         DN:        CN=HOST01,OU=LinuxServers,DC=corp,DC=example,DC=com

# Refresh machine account password (NetrServerPasswordSet2)
/opt/pbis/bin/domainjoin-cli --adv machine-password refresh

# Set OS info on the computer object
/opt/pbis/bin/domainjoin-cli setosname 'Ubuntu 22.04 LTS'

# Enumerate users / groups
/opt/pbis/bin/enum-users
/opt/pbis/bin/enum-groups

# Show user details (PAC + groups)
/opt/pbis/bin/find-user-by-name user1
/opt/pbis/bin/find-user-by-id 10000042

# Status / health
/opt/pbis/bin/pbis-status
/opt/pbis/bin/pbis diagnostics
/opt/pbis/bin/pbis list-features
/opt/pbis/bin/pbis update-ad-integration 8.5.x   # patch registry template

# Cache flush (after AD group membership change)
/opt/pbis/bin/ad-cache --flush
# Or restart lsass entirely:
/opt/pbis/bin/lwsm restart lsass

# Verify authentication
/opt/pbis/bin/pbis test-user --user user1@corp.example.com --pass 'Password!'

# Inspect the keytab
/opt/pbis/bin/krb5-keytab --list
/opt/pbis/bin/krb5-keytab --create   # regenerate from local secret
```

### Cell-based ID overrides (PBIS Enterprise feature)

PBIS Enterprise introduced "cells" — AD-stored per-host overrides for `uidNumber`, `gidNumber`, `homeDirectory`, `shell`, group memberships. The cell is an AD container (typically `CN=<hostname>,CN=Centrify...` or under the host's OU) with `posixAccount`-style attributes for the host's users. To enable:

```bash
/opt/pbis/bin/config --set 'HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\Providers\ActiveDirectory\Cell' \
  'CN=host01,CN=LinuxCells,DC=corp,DC=example,DC=com'
/opt/pbis/bin/lwsm restart lsass
```

Open-source PBIS does not support cells; you must use the commercial product.

## Wireshark / tshark

```
# Netlogon secure channel setup (NetrServerReqChallenge / NetrServerAuthenticate3)
dcerpc.netlogon.opnum == 4 || dcerpc.netlogon.opnum == 26

# NetrLogonSamLogonEx (pass-through auth)
dcerpc.netlogon.opnum == 39

# LSA lookups (for SID/name resolution from lsassd)
dcerpc.lsa.opnum == 15 || dcerpc.lsa.opnum == 14

# SAMR queries (enum-users / enum-groups)
dcerpc.samr.opnum == 16 || dcerpc.samr.opnum == 6

# Kerberos AS-EXCHANGE from lsassd's TGT acquisition on first login
kerberos.msg_type == 10 && kerberos.cname contains "user1"

# LDAP from lsassd (user/group cache refresh)
ldap.messageCode == 3 && (ldap.filter contains "sAMAccountName" || ldap.filter contains "objectSid")
```

## Comparison to SSSD

| Feature | PBIS 8.5 | SSSD |
|---|---|---|
| License | Open-source PBIS Open 8.5.x (GPL/LGPL mix); commercial PBIS Enterprise / AD Bridge | GPLv3+ |
| Active development | No (last open-source release 2014) | Yes (Red Hat + upstream) |
| AD provider | Native (`lsassd` + `netlogond`) | `ad` (LDAP + Kerberos) |
| Netlogon secure channel | Yes (`netlogond`) | No — uses LDAP GSS-SPNEGO |
| ID mapping | Algorithmic or RFC 2307 (registry-driven) | Algorithmic (`ldap_id_mapping=true`) or RFC 2307 (`=false`) — see `./02-sssd-id-mapping.md` |
| GPO access control | No (commercial PBIS has limited support) | Yes (`ad_gpo_access_control` — see `./03-sssd-gpo-access.md`) |
| Offline auth | Yes (`EnableOfflineLogon = 1`) | Yes (`cache_credentials = true` + `krb5_store_password_if_offline = true`) |
| FreeIPA support | No | Yes |
| Cell-based overrides | Yes (Enterprise only) | Yes via FreeIPA ID views, or `sss_override` |
| Auto home creation | `pam_lsass.so mkhomedir` | `pam_oddjob_mkhomedir.so` |
| Configuration | Registry hive (`reg.dat`) | Text (`sssd.conf`) |
| Distro packaging | Vendor installer (tarball) | Native packages everywhere |
| Modern recommendation | Migrate to SSSD | Use directly |

### Migration PBIS → SSSD

1. Note the algorithmic ID mapping range (`RangeMin`, `RangeMax`, `RangeSize`) from PBIS registry.
2. Mirror the range in SSSD `ldap_idmap_range` to preserve UID stability (or do a `chown -R --from=<old> <new>` sweep).
3. `domainjoin-cli leave` to remove the PBIS machine account secret.
4. `apt remove pbis-open` (or rpm equivalent) — leaves `/opt/pbis` for inspection.
5. `realm join corp.example.com -U admin` — joins via `adcli` + configures SSSD.
6. Verify: `id user1@corp.example.com` should return the same UID as before.
7. `find /home -uid <old> -print0 | xargs -0 chown --from=<old> <new>` if UID changed.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `pbis-status` shows `lsass: Stopped` | `lwregd` not running, or registry hive corrupt | `/opt/pbis/bin/lwsm restart lwreg` then `lwsm restart lsass`; if registry corrupt, restore `/opt/pbis/config/reg.dat` from backup |
| All logins `Permission denied` | `RequireMembershipOf` empty + `AssumeDefaultDomain=0` with username format mismatch | `/opt/pbis/bin/config RequireMembershipOf "CORP\\Domain Users"` or `config --set AssumeDefaultDomain 1` |
| UID changes after reboot | Algorithmic ID mapping range was modified but `lsassd` cache not cleared | `/opt/pbis/bin/ad-cache --flush; /opt/pbis/bin/lwsm restart lsass` |
| `domainjoin-cli join` fails with `ERROR_NO_LOGON_SERVERS` | DNS not pointing at AD; or DC unreachable | `/etc/resolv.conf` → AD DNS; `nslookup -type=srv _ldap._tcp.dc._msdcs.corp.example.com` |
| `domainjoin-cli leave` fails | Machine account already deleted from AD | `domainjoin-cli leave --noDisable` (just local cleanup) |
| Cannot resolve well-known SIDs (e.g. `BUILTIN\Administrators`) | Old `lsassd` cache, registry hive missing built-in providers | `/opt/pbis/bin/lwsm restart lsass` after `/opt/pbis/bin/ad-cache --flush` |
| TGT not acquired after password auth | `Kerberos\CCacheDir` not writable by user | `chmod 1777 /tmp` (default ccache dir); or change `CCacheDir` to `/run/user/%u` |
| Cross-domain logins (trusted forest) fail | `DomainManager\TrustedDomains` not configured | Use `/opt/pbis/bin/config --set DomainManager\TrustedDomains "child.corp.example.com"` per trusted domain |

Logs: `/var/log/pbis/lsassd.log`, `netlogond.log`, `lwregd.log`, `eventlogd.log`, `lwsmd.log`. Enable debug: `/opt/pbis/bin/config --set 'HKLM\SYSTEM\CurrentControlSet\Services\lsass\Parameters\LogLevel' 5` then `lwsm restart lsass`.

## Cross-platform comparison

- **AD-side counterpart:** PBIS's `lsassd` is a Linux reimplementation of the Windows `lsass.exe` architecture (LSA server + Netlogon service). The Netlogon secure-channel protocol (`NetrServerAuthenticate3`, `NetrLogonSamLogonEx`, `NetrServerPasswordSet2`) is identical to what Windows member servers use — see `../02-protocols/06-rpc-dcerpc-ms-drsr.md` for the DCE/RPC framing. The Kerberos exchanges against the AD KDC follow MS-KILE — see `../02-protocols/01-kerberos-internals.md`. LDAP queries against AD use the same protocol documented in `../02-protocols/02-ldap-protocol.md`.
- **SSSD alternative:** Modern replacement, with broader feature set (GPO access, FreeIPA, SUDO rules, IFP). See `./01-sssd-ad-provider.md`.
- **Winbind alternative:** `./04-winbind-internals.md` — Samba's stack also uses Netlogon secure channel; PBIS and Winbind are the two Netlogon-based options vs SSSD's LDAP/Kerberos-only approach.
- **macOS counterpart:** PBIS was actually ported to macOS too (now superseded by Apple's native AD plugin in `opendirectoryd`); see `../08-macos-equivalents/02-dscl-dsconfigad.md`.
- **High-level matrix:** `../10-comparison-matrices/01-feature-os-matrix.md`.

## References

- BeyondTrust documentation (commercial product) — https://www.beyondtrust.com/docs/ad-bridge/
- PBIS Open 8.5 archived downloads and documentation (BeyondTrust historically hosted these; archive.org snapshots exist for `www.beyondtrust.com/Support/Downloads/PowerBroker-Identity-Services-Open/`.
- Likewise Open source (pre-acquisition by BeyondTrust) — historical SVN at `https://likewisesoftware.com/svn/` (offline); GitHub mirrors of `likewise-open` exist with the same `lsass/server/lsassd.c:main`, `netlogon/server/netlogond.c:main`, `registry/server/lwregd.c:main` source structure.
- MS-NRPC, MS-LSAD, MS-LSAR, MS-SAMR protocol documentation.
- `domainjoin-cli(1)`, `pbis(1)`, `pbis-status(1)`, `config(1)`, `lwsm(1)`, `lwreg(1)` man pages.
