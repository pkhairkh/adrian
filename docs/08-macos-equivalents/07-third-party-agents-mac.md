---
title: Third-Party AD Agents on macOS — Centrify, PBIS/Likewise, AdmitMac, DAVE, Samba, Heimdal, OpenLDAP
audience: senior-engineers
tags: [centrify, pbis, likewise, admitmac, dave, samba, heimdal, openldap, macos]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/03-smb-cifs-protocol.md
  - ./01-opendirectory-internals.md
  - ./02-dscl-dsconfigad.md
  - ./03-jamf-connect-pro.md
  - ./04-platform-sso-extension.md
  - ./05-kerberos-sso-extension.md
  - ../09-linux-equivalents/04-winbind-internals.md
  - ../09-linux-equivalents/07-pbis-powerbroker.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

Third-party AD agents on macOS predate Apple's first-party Kerberos SSO Extension and Platform SSO, and survive in legacy/regulated deployments where the Apple-bundled OD AD plug-in is insufficient: Centrify DirectControl ships its own Kerberos implementation and a hardened `adclient` daemon; BeyondTrust PBIS (formerly Likewise) ports the same `lwreg`/`lwsmd`/`domainjoin-cli` stack from Linux; Thursby's AdmitMac and DAVE predate OD's AD support and provide alternative SMB/Kerberos stacks; Homebrew ships Samba, Heimdal, and OpenLDAP client tools that can coexist with the OS-bundled equivalents — sometimes at the cost of conflicting with the built-in `smbx` SMB server and Heimdal-based `/usr/bin/kinit`.

## Architecture summary

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Stock macOS (Apple-provided):                                           │
│   /usr/libexec/opendirectoryd        ─── OD daemon, AD plug-in          │
│   /usr/bin/kinit / klist / kdestroy  ─── Heimdal Kerberos client        │
│   /usr/sbin/smbd-equivalent (smbx)   ─── Apple SMBX server (kernel ext) │
│   /System/Library/Frameworks/        ─── Apple SSO Extensions (PSSO)    │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ Third-party overlays (each installs its own binaries + daemons):        │
│                                                                         │
│  Centrify DirectControl     BeyondTrust PBIS           AdmitMac / DAVE  │
│   ├─ adclient (daemon)       ├─ lwsmd (daemon)          ├─ AdmitMac.kext│
│   ├─ adjoin / adleave        ├─ domainjoin-cli          ├─ DAVE.kext    │
│   ├─ dzdo (Centrify sudo)    ├─ lwreg / lwsm            └─ AdmitMac.app│
│   ├─ cinfo                    └─ /opt/pbis/...                           │
│   └─ /usr/local/share/centrifydc/                                        │
│                                                                         │
│  Samba (Homebrew)            Heimdal (Homebrew)         OpenLDAP (HB)   │
│   ├─ /opt/homebrew/sbin/smbd  ├─ /opt/homebrew/bin/kinit ├─ ldapsearch  │
│   ├─ /opt/homebrew/sbin/nmbd  ├─ /opt/homebrew/bin/klist ├─ ldapadd     │
│   └─ /opt/homebrew/etc/samba/ └─ Heimdal kdc daemon      └─ ldapmodify  │
└─────────────────────────────────────────────────────────────────────────┘
```

## 1. Centrify DirectControl for Mac

Centrify (now CyberArk since the 2024 acquisition) DirectControl for Mac is the most invasive third-party AD client on macOS. It ships:

| Path | Purpose |
|---|---|
| `/usr/local/share/centrifydc/bin/adjoin` | Bind to AD. Creates a computer object via LDAP, writes `/etc/krb5.keytab`, drops config into `/etc/centrifydc/`. |
| `/usr/local/share/centrifydc/bin/adleave` | Unbind. Deletes computer object if `-r` flag given. |
| `/usr/local/share/centrifydc/bin/adinfo` | Status: domain, site, DC, GPO cache, license. |
| `/usr/local/share/centrifydc/bin/adquery` | LDAP-like record query (e.g. `adquery user alice`). |
| `/usr/local/share/centrifydc/bin/cinfo` | Cache + connection info; diagnostic dump. |
| `/usr/local/share/centrifydc/bin/dzdo` | Centrify's sudo replacement — enforces Centrify RBAC (dzdo roles) instead of `/etc/sudoers`. |
| `/usr/local/share/centrifydc/bin/dzinfo` | Show the user's dzdo authorizations. |
| `/usr/local/share/centrifydc/sbin/adclient` | The daemon (Centrify's equivalent of `sssd` + `winbind` combined). |
| `/etc/centrifydc/centrifydc.conf` | Main config file (INI format). |
| `/etc/centrifydc/user.ignore` `/etc/centrifydc/group.ignore` | Local users/groups that Centrify must not touch. |
| `/var/centrifycc/` `/var/log/centrifycc/` | Runtime + logs. |

LaunchDaemons:

```
/Library/LaunchDaemons/com.centrify.cdcfsd.plist     # file-system filter (kernel extension)
/Library/LaunchDaemons/com.centrify.adclient.plist   # the adclient daemon
```

Centrify's `adclient` uses its **own Kerberos implementation** (a fork of Heimdal with Centrify's audit hooks) instead of the OS-bundled `/usr/lib/libkerberos.dylib`. This is by design — Centrify wants deterministic behaviour across macOS, Linux, AIX, HP-UX, and Solaris. The downside is that the OS-bundled `klist`/`kinit` do not see Centrify-acquired tickets; use `adinfo --tickets` or Centrify's bundled `klist` at `/usr/local/share/centrifydc/bin/klist`.

`dzdo` (Centrify's sudo) reads its rules from AD computer objects' `centrifydc` attributes — specifically the `dzdoCommandRights` and `dzdoRole` auxiliary classes attached to AD user/group objects. The rules are pushed by the Centrify Access Manager Console (Windows MMC snap-in) which extends the AD schema.

Inspect:

```sh
# Centrify config + state
sudo defaults read /Library/Preferences/com.centrifydc.adclient 2>/dev/null
sudo plutil -p /Library/Preferences/com.centrifydc.adclient.plist 2>/dev/null
sudo cat /etc/centrifydc/centrifydc.conf | head -100
sudo adinfo
sudo adinfo --dns
sudo adinfo --tickets
sudo cinfo
sudo dzinfo <user>

# Confirm the kernel extension is loaded
kextstat | grep -i centrify

# Confirm adclient is running
sudo launchctl print system/com.centrify.adclient
ps aux | grep -i adclient

# Centrify-acquired tickets (separate from OS klist)
sudo /usr/local/share/centrifydc/bin/klist -v

# Diagnostic packet capture of Centrify traffic
sudo tcpdump -i any -w /tmp/cen.pcap 'host <dc-ip> and (port 88 or port 389 or port 445 or port 135)'
```

## 2. BeyondTrust PBIS (formerly Likewise) for Mac

PBIS (PowerBroker Identity Services, formerly Likewise) is the same product on macOS as on Linux — see [`../09-linux-equivalents/07-pbis-powerbroker.md`](../09-linux-equivalents/07-pbis-powerbroker.md) for the full internals. On macOS specifically:

| Path | Purpose |
|---|---|
| `/opt/pbis/bin/domainjoin-cli` | Bind / unbind CLI (identical interface on Linux and macOS). |
| `/opt/pbis/bin/lwreg` | LWREG registry shell — PBIS stores all config in a private registry at `/var/lib/pbis/db/registry.tdb` (TDB = Samba's Trivial Database). |
| `/opt/pbis/bin/lwsm` | LW-SM service manager — list / start / stop PBIS internal services (`lsass`, `eventlog`, `netlogon`, `lwreg`). |
| `/opt/pbis/sbin/lwsmd` | The PBIS daemon. LaunchDaemon `com.beyondtrust.lwsmd`. |
| `/opt/pbis/bin/enum-users` `enum-groups` | List AD users/groups as seen by PBIS. |
| `/opt/pbis/bin/find-user` `find-by-sid` | Look up by name or SID. |
| `/opt/pbis/config/` | Per-host config shell scripts (`hostname.sh`, `domain.sh`, etc.). |
| `/etc/krb5.conf` | PBIS writes a system-wide `krb5.conf` (overrides the macOS default empty file). |
| `/etc/opt/pbis/lsassd.conf` | The LSASS daemon config (PAM/NSS source). |

PBIS replaces the NSS resolver for `passwd`, `group`, `shadow`, `hosts` by hooking into `/etc/pam.d/authorization` and via a `libnss_pbis.dylib` shim loaded into `libsystem_info.dylib` through DYLD insert.

The macOS variant of PBIS was officially deprecated in 2022; BeyondTrust recommends migration to the Apple Kerberos SSO Extension + Jamf Connect. The Linux variant (`../09-linux-equivalents/07-pbis-powerbroker.md`) is still supported.

Inspect:

```sh
# PBIS status
sudo /opt/pbis/bin/domainjoin-cli query
sudo /opt/pbis/bin/lwsm list
sudo /opt/pbis/bin/lwsm info lsass
sudo /opt/pbis/bin/enum-users --level 2
sudo /opt/pbis/bin/find-by-sid S-1-5-21-...

# PBIS config (registry.tdb dump)
sudo /opt/pbis/bin/lwreg export --root HKEY_THIS_MACHINE\\Services\\lsass /tmp/lsass.reg
sudo plutil -p /Library/Preferences/com.beyondtrust.pbis.plist 2>/dev/null

# Confirm lwsmd is running
sudo launchctl print system/com.beyondtrust.lwsmd
ps aux | grep -i lwsmd

# macOS /etc/krb5.conf has been overwritten by PBIS
sudo cat /etc/krb5.conf

# Confirm Heimdal kinit still works (PBIS uses MIT Kerberos, NOT Heimdal)
sudo /usr/bin/kinit <user>@<REALM>      # might fail; PBIS uses MIT
sudo /opt/pbis/bin/kinit <user>@<REALM>  # MIT kinit from PBIS
```

## 3. AdmitMac (Thursby)

AdmitMac is Thursby Software's commercial AD integration product, dating back to the Mac OS X 10.4 era. It predates Apple's AD plug-in. Key components:

| Path | Purpose |
|---|---|
| `/Library/Filesystems/AdmitMac.fs/` | The AdmitMac file-system kernel extension (alternative SMB stack). |
| `/Library/LaunchDaemons/com.thursby.admitmac.plist` | The DAVE daemon. |
| `/Library/Preferences/Thursby AdmitMac Settings.plist` | Main preferences. |
| `/Library/Preferences/Thursby/*` | Per-domain config. |
| `/Applications/AdmitMac/` | User-facing config app. |

AdmitMac provides its own SMB client (a port of Thursby's DAVE SMB stack — see §4) plus AD authentication. It hooks into the macOS Authorization framework via a PAM module at `/usr/lib/pam/pam_admitmac.so` and replaces the standard `mount_smbfs` flow with Thursby's `DAVEmount`.

AdmitMac is largely deprecated in favour of Apple's built-in SMBX client and AD plug-in. Thursby still ships it for compatibility with DAVE-managed deployments, but no new features since ~macOS 11.

Inspect:

```sh
sudo plutil -p "/Library/Preferences/Thursby AdmitMac Settings.plist"
sudo defaults read "/Library/Preferences/Thursby AdmitMac Settings"
kextstat | grep -i thursby            # confirm the .fs kext is loaded
sudo launchctl print system/com.thursby.admitmac
```

## 4. Thursby DAVE

DAVE is Thursby's SMB-client-only product (no AD authentication). It was popular in the Mac OS 9 / early OS X era when Apple's built-in SMB support was weak. Modern macOS (10.9+) ships a fully capable SMBX client; DAVE's value-add today is limited to:

- Better DFS-R referral support than SMBX.
- Older SMB 1.0 dialect compatibility for legacy NAS appliances.
- SPN-aware Kerberos authentication against non-Microsoft SMB servers (Synology, QNAP, NetApp ONTAP 7-mode).

DAVE does not bind to AD; it relies on the OS-bundled Kerberos stack. The DAVE kernel extension lives at `/Library/Filesystems/DAVE.fs/`. AdmitMac is effectively "DAVE + AD auth in one box".

Inspect:

```sh
sudo plutil -p "/Library/Preferences/Thursby DAVE Settings.plist"
kextstat | grep -i DAVE
```

## 5. Samba on macOS (Homebrew)

`brew install samba` builds Samba 4.x from source. This is **rarely a good idea** on macOS because the OS already ships an SMBX server (Apple's user-space SMB implementation, exposed via `launchd` as `com.apple.smbd`). Running Homebrew Samba's `smbd` alongside SMBX causes:

- TCP 445 port conflict (only one process can bind 445). Homebrew Samba must either be configured to listen on a different port or SMBX must be disabled (`sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist`).
- Two separate Kerberos stacks: SMBX uses Apple's Heimdal; Homebrew Samba uses MIT Kerberos against `/opt/homebrew/etc/krb5.conf`.
- Two separate keytabs: SMBX uses `/etc/krb5.keytab`; Homebrew Samba uses `/opt/homebrew/etc/krb5.keytab`.

Samba on macOS is useful in two niche scenarios:

1. **You want to host a non-Microsoft SMB share** with full Samba feature set (DFS-R, custom VFS modules, full ACL semantics). Disable SMBX first.
2. **You want `smbclient`/`rpcclient`/`smbcacls` CLIs** without installing a full Samba server. `brew install samba` puts them in `/opt/homebrew/bin/`; the server daemons (`smbd`, `nmbd`) do not auto-start.

Inspect:

```sh
# Confirm SMBX is the active server (stock macOS)
sudo launchctl print system/com.apple.smbd
sudo plutil -p /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist

# Confirm Homebrew Samba is installed (not running)
brew list samba 2>/dev/null
ls /opt/homebrew/sbin/smbd /opt/homebrew/sbin/nmbd 2>/dev/null
ls /opt/homebrew/etc/samba/smb.conf 2>/dev/null

# Use smbclient against an AD-joined share
/opt/homebrew/bin/smbclient -k -L //fileserver.corp.example.com/
# -k = use Kerberos (consults Heimdal cache via GSSAPI)

# Confirm two separate keytabs
sudo klist -k /etc/krb5.keytab
sudo /opt/homebrew/bin/ktutil -k /opt/homebrew/etc/krb5.keytab list
```

## 6. Heimdal on macOS (Homebrew)

The OS-bundled `/usr/bin/kinit`, `/usr/bin/klist`, `/usr/bin/kdestroy`, `/usr/bin/kpasswd` on macOS are **Heimdal**, not MIT. `kinit --version` confirms:

```
heimdal "Heimdal 1.21" (Apple MITKerberosShim-1.21)
```

Apple ships both Heimdal (`/usr/lib/libkerberos.dylib`, `/usr/lib/libheimdal-asn1.dylib`) and an MIT-compatible shim (`/usr/lib/libMITKerberosShim.dylib`) that redirects MIT-style GSSAPI calls to Heimdal. This is what allows MIT-kerberos-compiled code (Homebrew packages) to work against the system keychain.

Installing Homebrew Heimdal:

```sh
brew install heimdal
# installs /opt/homebrew/bin/kinit (Heimdal), /opt/homebrew/bin/klist, etc.
# also /opt/homebrew/sbin/kdc — Heimdal KDC daemon (you don't want this on a client)
```

Path conflicts:

- `/usr/bin/kinit` (system Heimdal, default in `PATH`)
- `/opt/homebrew/bin/kinit` (Homebrew Heimdal, only used if you prepend `/opt/homebrew/bin`)

In practice, you do not need Homebrew Heimdal on macOS unless you want a newer Heimdal version than Apple ships, or you want to run a Heimdal KDC for testing. The OS-bundled Heimdal is sufficient for AD-joined client behaviour.

Inspect:

```sh
# Confirm system Heimdal
kinit --version
otool -L /usr/bin/kinit
# /usr/lib/libkerberos.5.dylib
# /usr/lib/libheimdal-asn1.dylib
# /usr/lib/libresolv.9.dylib
# ...

# Confirm Apple's MIT shim (for MIT-compiled Homebrew binaries)
otool -L /usr/lib/libMITKerberosShim.dylib
ls /usr/lib/libgssapi_krb5.dylib        # → symlink to libMITKerberosShim.dylib

# Heimdal kinit against AD (system binaries)
sudo kinit <user>@CORP.EXAMPLE.COM
klist -v

# If you installed Homebrew Heimdal, confirm version delta
/opt/homebrew/bin/kinit --version
```

## 7. OpenLDAP client (`ldapsearch` etc.) on macOS

macOS does **not** ship `ldapsearch`, `ldapadd`, `ldapmodify`, or any of the OpenLDAP client CLIs. The OS-bundled LDAP support is library-only: `libldap.dylib` in `/usr/lib/` (OpenLDAP client lib, version typically lags upstream), used by `opendirectoryd`'s LDAPv3 plug-in and by `Directory Utility.app`.

For CLI access:

```sh
brew install openldap            # installs the OpenLDAP client tools
# binaries land in /opt/homebrew/bin/
# ldapsearch, ldapadd, ldapmodify, ldapdelete, ldapwhoami, ldappasswd
# config: /opt/homebrew/etc/openldap/ldap.conf

# Use GSSAPI (Kerberos) auth against an AD DC
/opt/homebrew/bin/ldapsearch -LLL \
  -H ldap://corp-dc-01.corp.example.com \
  -Y GSSAPI -b 'DC=corp,DC=example,DC=com' \
  '(sAMAccountName=alice)' \
  cn memberOf userPrincipalName

# Use simple bind
/opt/homebrew/bin/ldapsearch -LLL \
  -H ldaps://corp-dc-01.corp.example.com \
  -D 'corp\svc-ldap' -W \
  -b 'DC=corp,DC=example,DC=com' \
  '(sAMAccountName=alice)'
```

The Homebrew OpenLDAP links against Homebrew's MIT Kerberos (`brew install krb5`) by default, which uses a separate `krb5.conf` at `/opt/homebrew/etc/krb5.conf` and a separate credential cache (`KRB5CCNAME=FILE:/tmp/mycc`). To interoperate with the macOS system Heimdal cache, set:

```sh
export KRB5CCNAME=API:Initialdefaultcache   # macOS system keychain cache
export KRB5_CONFIG=/dev/null                # ignore Homebrew's krb5.conf
```

…or simply use `kinit` from the system to populate the `API:` cache, then `ldapsearch -Y GSSAPI` will pick it up via the system GSSAPI library.

## Comparison summary table

| Product | Bundled? | AD bind? | Kerberos stack | SMB stack | PAM / NSS hook | Maintained? |
|---|---|---|---|---|---|---|
| **Apple OD AD plug-in** (stock) | Yes | Yes (`dsconfigad`) | Heimdal (system) | SMBX (system) | Yes (via `opendirectoryd`) | Active (Apple) |
| **Kerberos SSO Extension** (stock) | Yes (10.15+) | No (Kerberos only) | Heimdal (system) | n/a | No (Authorization framework) | Active (Apple) |
| **Platform SSO** (stock) | Yes (13+) | No | Heimdal (system) | n/a | Yes (Authorization framework) | Active (Apple) |
| **Centrify DirectControl** | No | Yes (`adjoin`) | Centrify Heimdal fork | SMBX (system) | Yes (`adclient` + `dzdo`) | Active (CyberArk) |
| **BeyondTrust PBIS** | No | Yes (`domainjoin-cli`) | MIT Kerberos (bundled) | SMBX (system) | Yes (`lwsmd` + nss_pbis) | macOS EOL; Linux active |
| **Thursby AdmitMac** | No | Yes (Thursby) | Thursby Kerberos | Thursby DAVE | Yes (`pam_admitmac.so`) | Maintenance only |
| **Thursby DAVE** | No | No | Heimdal (system) | Thursby DAVE | No | Maintenance only |
| **Homebrew Samba** | No | Optional (`net ads join`) | MIT Kerberos (bundled) | Samba `smbd` (conflicts with SMBX) | No | Active (Samba team) |
| **Homebrew Heimdal** | No | Optional (you write the bind) | Heimdal (Homebrew) | n/a | No | Active (Heimdal team) |
| **Homebrew OpenLDAP client** | No | n/a (CLI only) | Heimdal (system) or MIT (Homebrew) | n/a | No | Active (OpenLDAP team) |
| **Jamf Connect** | No | No (cloud-first) | Heimdal (system) via Kerberos SSO Extension | SMBX (system) | Yes (`pam_jamfconnect`) | Active (Jamf) |
| **NoMAD / NoLoAD** | No | No (Kerberos only) | Heimdal (system) | SMBX (system) | Yes (PAM hook) | EOL (Jamf acquired 2021) |
| **Enterprise Connect** (legacy) | No | No (Kerberos only) | Heimdal (system) | n/a | Yes (PAM hook) | Deprecated by Apple |

## Wire-protocol diagnostics

All third-party agents ultimately speak the same Kerberos (TCP/UDP 88), LDAP (TCP 389/636), SMB (TCP 445), and CLDAP (UDP 389) protocols as the stock macOS stack. The same Wireshark filters apply across them:

```
# All Kerberos (Centrify, PBIS-MIT, system-Heimdal — all use the same port)
kerberos && ip.addr == 10.0.0.5

# All LDAP simple bind / search
ldap && ip.addr == 10.0.0.5

# All SMB (Centrify uses SMBX like the OS; DAVE/AdmitMac use their own stack; Samba uses its own)
smb2 && ip.addr == 10.0.0.5

# CLDAP DC-locator
cldap && cldap.filter.domain == "corp.example.com"

# kpasswd (Centrify and PBIS both implement kpasswd on TCP/UDP 464)
tcp.port == 464 || udp.port == 464
```

Centrify's diagnostics include `adinfo --network` which prints a self-collected pcap-style summary of recent AD traffic.

## Cross-platform comparison

- **AD counterpart** — Centrify's `adclient` is the macOS/Linux/AIX/Solaris analogue of Windows' `Netlogon` service (`netlogon.dll` in `lsass.exe`). PBIS is conceptually identical on macOS and Linux (see [`../09-linux-equivalents/07-pbis-powerbroker.md`](../09-linux-equivalents/07-pbis-powerbroker.md)) and is the closest non-Windows analogue of a domain-joined Windows member server's full Netlogon + Kerberos + LDAP stack. AdmitMac and DAVE are commercial analogues of Windows' `lanmanworkstation` (redirector) plus Kerberos client. See [`../01-ad-core/01-ad-ds-internals.md`](../01-ad-core/01-ad-ds-internals.md) for the DC-side view.
- **Linux counterpart** — Centrify DirectControl for Linux is functionally identical to the macOS build (same `adclient`, same `adjoin`, same `centrifydc.conf`); PBIS for Linux is documented at [`../09-linux-equivalents/07-pbis-powerbroker.md`](../09-linux-equivalents/07-pbis-powerbroker.md). Samba, Heimdal, and OpenLDAP on macOS use the same source code as on Linux — see [`../09-linux-equivalents/04-winbind-internals.md`](../09-linux-equivalents/04-winbind-internals.md) and [`../09-linux-equivalents/09-openldap-mit-kerberos.md`](../09-linux-equivalents/09-openldap-mit-kerberos.md). The macOS `opendirectoryd` analogue on Linux is `sssd` ([`../09-linux-equivalents/01-sssd-ad-provider.md`](../09-linux-equivalents/01-sssd-ad-provider.md)).
- **High-level side-by-side** — [`../10-comparison-matrices/01-feature-os-matrix.md`](../10-comparison-matrices/01-feature-os-matrix.md).

## References

- Centrify doc — "DirectControl for Mac Administrator's Guide" (CyberArk, current through macOS 14).
- Centrify CLI reference — `man adjoin`, `man adinfo`, `man dzdo`, `man adclient` (install adds these to `/usr/local/share/man/`).
- BeyondTrust doc — "PBIS for Mac Installation Guide" (legacy; macOS deprecation notice 2022).
- PBIS CLI reference — `domainjoin-cli --help`, `lwsm --help`, `lwreg --help`.
- Thursby Software doc — "AdmitMac User Guide" and "DAVE User Guide" (proprietary, current through macOS 14).
- Samba on Homebrew — `brew info samba` (formula maintained by Homebrew core).
- Heimdal on Homebrew — `brew info heimdal`.
- OpenLDAP on Homebrew — `brew info openldap`.
- Apple doc — "Use the SMBX server" and "Replace the SMB server with Samba" (Apple Support, archived).
- RFC 4120 / MS-KILE — for Kerberos, see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md).
- MS-SMB2 — for SMB, see [`../02-protocols/03-smb-cifs-protocol.md`](../02-protocols/03-smb-cifs-protocol.md).
- RFC 4511 — for LDAP, see [`../02-protocols/02-ldap-protocol.md`](../02-protocols/02-ldap-protocol.md).
