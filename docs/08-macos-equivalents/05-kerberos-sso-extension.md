---
title: Kerberos SSO Extension — Apple's First-Party Kerberos Ticket Manager for macOS
audience: senior-engineers
tags: [kerberos, sso-extension, heimdal, keychain, mdm, macos, ad-binding]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/02-ldap-protocol.md
  - ../02-protocols/05-dns-dynamic-updates.md
  - ./01-opendirectory-internals.md
  - ./02-dscl-dsconfigad.md
  - ./03-jamf-connect-pro.md
  - ./04-platform-sso-extension.md
  - ./06-enterprise-connect-nomad.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

The Kerberos SSO Extension is the bundled macOS 10.15+ Endpoint Security `Authentication_SSO` extension (`com.apple.KerberosSSO.appex`) that runs inside `securityd`'s `authentication-extension` XPC child process, integrates with the Heimdal-based `/usr/bin/kinit` and `/usr/bin/klist` already shipped with the OS, and replaces the older "Kerberos via SSO" path used by Jamf Connect, NoMAD, and Enterprise Connect with a first-party ticket manager whose MDM payload (`com.apple.KerberosSSO`) carries `Realm`, `Domains`, `SiteCode`, `UseSiteAutoDiscovery`, and `ManagementPrincipal`, and whose ticket cache lives in the user's keychain rather than the historical `/tmp/krb5cc_*` file cache.

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  MDM profile (PayloadType: com.apple.KerberosSSO)                    │
 │   ├─ Realm: CORP.EXAMPLE.COM                                          │
 │   ├─ Domains: [corp.example.com, child.corp.example.com]              │
 │   ├─ SiteCode: HQ (optional)                                          │
 │   ├─ UseSiteAutoDiscovery: true                                       │
 │   └─ ManagementPrincipal: macOS-Admin (optional)                      │
 └───────────────────────────────────┬──────────────────────────────────┘
                                     │ profile install
                                     ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  /System/Library/ExtensionKit/Extensions/                            │
 │  com.apple.KerberosSSO.appex   (Authentication_SSO extension)        │
 │  loaded by: securityd  →  authentication-extension XPC service       │
 │  uses: Kerberos.framework  (/System/Library/Frameworks/Kerberos.framework)
 └──────────────────────────────────────────────────────────────────────┘
                │
                │ kinit-equivalent calls via Heimdal libs
                ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Heimdal Kerberos client  (in-process inside authentication-extension)│
 │   /usr/lib/lib Heimdal / libgssapi_glue.dylib                        │
 │   kinit / klist / kdestroy share the same libs                       │
 └──────────────────────────────────────────────────────────────────────┘
                │
                │ TCP 88 (AS-REQ/TGS-REQ), UDP 88, TCP 464 (kpasswd), UDP 389 (CLDAP)
                ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  AD Domain Controller (KDC + kpasswd + DC locator)                   │
 └──────────────────────────────────────────────────────────────────────┘
                │
                │ Ticket cache stored in user keychain
                ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  ~/Library/Keychains/login.keychain-db                               │
 │   item: krbtgt:CORP.EXAMPLE.COM@CORP.EXAMPLE.COM                     │
 │   type: kSecClassGenericPassword, account=<user>@<REALM>             │
 │   accessible via: klist -v (uses ccaches API → keychain backend)     │
 └──────────────────────────────────────────────────────────────────────┘
```

- The extension is **bundled with macOS**. It is *not* a third-party app. On 10.15 through 12.x it had a more limited surface (just TGT acquisition + renewal). In macOS 13+ (when Platform SSO landed), it was promoted to a sub-type of the PSSO `Authentication_SSO` extension family and shares `sso_util` as the CLI surface (see [`04-platform-sso-extension.md`](./04-platform-sso-extension.md)).
- The `/usr/bin/kinit`, `/usr/bin/klist`, `/usr/bin/kdestroy` binaries on macOS are **Heimdal** (not MIT) — they share `libkrb5.dylib` and `libgssapi.dylib` with the rest of the OS, including the SSO Extension. You can confirm with `kinit --version` (Heimdal banner).
- The ticket cache type on a stock macOS 13+ install is `API:<ccache-name>`, which is the in-process Heimdal credential-cache type backed by the keychain. `klist` shows `Default principal: <user>@<REALM>` and `Cache: API:Initialdefaultcache` rather than `FILE:/tmp/krb5cc_502`.

## MDM payload schema

PayloadType: `com.apple.KerberosSSO`

```
PayloadType: com.apple.KerberosSSO
PayloadIdentifier: com.mycompany.kerberos-sso
PayloadUUID: <random UUID>
PayloadVersion: 1
PayloadDisplayName: Kerberos SSO — CORP Realm

# Extension-specific keys
Realm: CORP.EXAMPLE.COM                     # uppercase Kerberos realm; required
Domains:                                     # array of DNS domains; required
    - corp.example.com
    - child.corp.example.com
    - east.corp.example.com
SiteCode: HQ                                 # optional; AD site pin
UseSiteAutoDiscovery: true                   # bool; if true, ignore SiteCode and use CLDAP
ManagementPrincipal: macOS-Admin             # optional; principal allowed to switch users
                                              #   (used by sso_util to re-issue TGTs on
                                              #    behalf of a different user without
                                              #    requiring that user to type a password)
UserName: <user>                             # optional; pre-fills the sso_util login prompt
UserPassword: <password>                     # optional; auto-configures the extension
                                              #   WITHOUT prompting the user. Use with care.
                                              #   Insecure in plaintext MDM payloads;
                                              #   prefer enrollment-time entry.
```

Key enumeration:

| Key | Type | Notes |
|---|---|---|
| `Realm` | string (uppercase) | The Kerberos realm. Must match `userPrincipalName` suffix on the user object in AD. |
| `Domains` | array of strings | DNS domains that map to this realm. The extension uses this to do SPN-to-realm mapping: a service ticket request for `cifs/fileserver.corp.example.com` resolves to realm `CORP.EXAMPLE.COM` because `corp.example.com` is in the list. |
| `SiteCode` | string | AD site name (matches `CN=Sites,CN=Configuration,...` site `cn`). Pins the CLDAP query to that site's DCs. |
| `UseSiteAutoDiscovery` | bool | If `true` (default), the extension queries `_ldap._tcp.<site>._sites.dc._msdcs.<domain>` based on the Mac's subnet-to-site assignment. If `false`, uses `SiteCode` as a fixed pin. |
| `ManagementPrincipal` | string | Service principal with the right to obtain TGTs on behalf of users (S4U2Self-style flow). Used by helpdesk scripts and the Jamf Connect `sso_util configure` path. |
| `UserName` | string | Optional; pre-fills the login prompt. |
| `UserPassword` | string | Optional; auto-enrolls without prompting. **Security-sensitive.** Only use with device encryption + ephemeral MDM payload delivery. |

Inspect:

```sh
sudo profiles show -output stdout-xml | grep -A40 KerberosSSO
sudo profiles list -output stdout
sudo plutil -p /var/db/ConfigurationProfiles/Settings/com.apple.KerberosSSO.plist 2>/dev/null
```

## SPN-to-realm mapping

The `Domains` array drives realm lookup. Heimdal's `krb5.conf` equivalent — but the SSO Extension does not consult `/etc/krb5.conf` on macOS; it builds the realm map from the MDM payload. The lookup is:

```
For service principal cifs/fileserver.east.corp.example.com@<REALM>:
  1. Find longest suffix match in Domains[].
  2. "east.corp.example.com" is in Domains → realm = CORP.EXAMPLE.COM.
  3. If no match, fall back to DNS TXT record lookup on the domain (`_kerberos.<domain>` TXT = `<REALM>`).
  4. If still no match, error out with KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN.
```

This mirrors the Windows `DomainRealmMap` registry key under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains`. The macOS equivalent lives in the MDM payload, not in the registry.

## Ticket cache location

| Cache type | Where | Use case |
|---|---|---|
| `API:Initialdefaultcache` (keychain) | `~/Library/Keychains/login.keychain-db` | Default for macOS 13+ with SSO Extension. Persisted across reboot. Visible to `klist -v`. |
| `FILE:/tmp/krb5cc_<uid>` | `/tmp/krb5cc_502` | File-based cache. Used by Homebrew tools, MIT Kerberos, and any explicit `KRB5CCNAME=FILE:...` override. |
| `MEMORY:` | in-process | Used by short-lived scripts; never persists. |
| `KCM:` | Daemon-backed | Not used on macOS by default. |

To explicitly choose the cache:

```sh
export KRB5CCNAME=FILE:/tmp/mycache
kinit alice@CORP.EXAMPLE.COM
klist -v
```

When the SSO Extension is installed, the **default cache is always `API:`** so that tickets are persisted in the keychain. File-based caches still work but bypass the extension's auto-renew logic.

## Auto-renew

The extension renews the TGT before it expires. Renewal is Heimdal's `krb5_get_renewed_creds` — the equivalent of MIT's `kinit -R`. The renewal cadence:

```
TGT lifetime (typical):     10 hours
TGT renewable lifetime:     7 days
Renewal trigger:            75% of lifetime elapsed (i.e. 7.5h after issuance)
Renewal retries:            every 15 minutes if renewal fails
Final expiry:               7 days after original issuance → re-auth required
```

If renewal fails (e.g. Mac was offline at the renewal window), the extension surfaces a notification via `UserNotifications` framework ("Kerberos credentials will expire in N hours"). At expiry, the user must re-enter the password; the extension calls `krb5_get_init_creds_password` to obtain a fresh TGT, then writes it back to the keychain.

## sso_util CLI

The `sso_util` binary (`/usr/bin/sso_util`) is the supported interface for both Platform SSO (see [`04-platform-sso-extension.md`](./04-platform-sso-extension.md)) and the Kerberos SSO Extension. Kerberos-specific verbs:

```sh
# Install the SSO Extension for the given realm (interactive: prompts for password)
sso_util configure -r CORP.EXAMPLE.COM -u alice
#   -r / --realm:    Kerberos realm (uppercase)
#   -u / --user:     user principal name (without @REALM)
#   -p / --password: supply password non-interactively (insecure; for scripts)
#   --mobile-keychain: store TGT in login keychain (default)
#   --file-cache:    store in FILE:/tmp/krb5cc_<uid> instead (non-default)

# List configured Kerberos SSO Extensions
sso_util extensions -l

# Show currently cached credentials (across all configured SSO Extensions)
sso_util cache -l
# output:
#   Realm: CORP.EXAMPLE.COM
#   Principal: alice@CORP.EXAMPLE.COM
#   Expires: 2026-08-13 22:00:00 UTC
#   RenewUntil: 2026-08-20 12:00:00 UTC

# Force a refresh / renewal
sso_util cache -r -r CORP.EXAMPLE.COM

# Destroy cached credentials (per principal)
sso_util cache -d -r CORP.EXAMPLE.COM

# Change the user's password at the AD KDC (kpasswd protocol on TCP/UDP 464)
sso_util password -r CORP.EXAMPLE.COM -u alice
#   prompts for old + new password, then issues KPASSWD AP-REQ to the KDC
```

The native Heimdal binaries remain usable alongside:

```sh
# Native Heimdal kinit (writes to default cache, same as sso_util configure)
sudo kinit alice@CORP.EXAMPLE.COM
klist -v
klist -k /etc/krb5.keytab             # system keytab (host machine-account)

# Native Heimdal kdestroy (per-principal)
kdestroy -p alice@CORP.EXAMPLE.COM

# Native Heimdal kpasswd
kpasswd alice@CORP.EXAMPLE.COM

# Verify machine-account TGT (system context, not user)
sudo klist -v
```

## Configuration / commands

```sh
# Confirm the SSO Extension is loaded
systemextensionsctl list | grep -i KerberosSSO

# Confirm running process
ps aux | grep authentication-extension
sudo log show --predicate 'process == "authentication-extension"' --last 10m --info

# Verify MDM payload installed
sudo profiles show -output stdout
sudo profiles list -output stdout

# Verify ticket cache
klist -v
klist -e                          # show enctypes per ticket

# Verify Heimdal libraries in use
otool -L /usr/bin/kinit           # should show libkerberos.dylib, libheimdal-asn1.dylib
kinit --version                   # Heimdal banner

# Decrypt /etc/krb5.conf (if present; usually empty on stock macOS)
sudo plutil -p /etc/krb5.conf 2>/dev/null || true
cat /etc/krb5.conf 2>/dev/null

# Inspect system keychain for the machine-account key (host/MAC01$@CORP)
sudo security find-generic-password -s 'com.apple.kerberos.keytab' -g /Library/Keychains/System.keychain
sudo klist -k /etc/krb5.keytab
```

## Troubleshooting

- **`sso_util configure` errors "No Kerberos SSO payload found"** — the MDM payload was not delivered. `sudo profiles list` should show a `com.apple.KerberosSSO` payload. Re-push from MDM.
- **`klist -v` shows no tickets but `sso_util configure` succeeded** — the extension installed the cache in the user keychain, but you ran `klist` from a different UID (e.g. via `sudo`). Use `klist -v` without `sudo`, or `sudo -u <user> klist -v`.
- **`kinit alice@CORP.EXAMPLE.COM` works but `sso_util configure` fails** — Heimdal can reach the KDC, but the SSO Extension cannot because `Domains` does not contain the realm's DNS suffix. Add `corp.example.com` to the `Domains` array in the MDM payload and re-push.
- **Tickets acquired but SMB mount still prompts for password** — SMBX (the macOS SMB client) consults the cache by SPN `cifs/<server>@<REALM>`. Verify `Domains` covers the SMB server's DNS suffix. If the server is `fileserver.east.corp.example.com` and only `corp.example.com` is in `Domains`, the suffix match still works (longest suffix wins). If the server is `fileserver.other.com`, add it.
- **`kpasswd` / `sso_util password` errors `KDC_ERR_S_OLD_MUST_KNOW`** — the user typed the wrong old password. Re-try.
- **Renewal stopped working after Mac was offline for 7+ days** — renewable lifetime exceeded. The user must re-authenticate. Run `sso_util configure -r <REALM> -u <user>` to obtain a fresh TGT.
- **`ManagementPrincipal` flow fails with `KDC_ERR_BADOPTION`** — the management principal does not have the "Trusted for delegation" / "Allowed to authenticate" right on the user object in AD. Set `msDS-AllowedToActOnBehalfOfOtherIdentity` on the user (or grant the management principal `S4U2Self`).
- **Tickets to `host/<server>` SPN fail with `Server not found in Kerberos database`** — the SPN is missing on the target service account in AD. Use `setspn -S host/<server> <server-account>` on a DC (or PowerShell `Set-ADUser -ServicePrincipalNames @{Add='host/<server>'}`).

## Wire-protocol diagnostics

The Kerberos SSO Extension drives the standard Kerberos wire protocols described in [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md). Wireshark display filters for the most common investigations:

```
# All Kerberos traffic from this Mac to the DC
kerberos && ip.addr == 10.0.0.5

# AS-REQ (initial TGT)
kerberos.msg_type == 10

# AS-REP (TGT returned by KDC)
kerberos.msg_type == 11

# TGS-REQ (service ticket request)
kerberos.msg_type == 12

# TGS-REP (service ticket returned)
kerberos.msg_type == 13

# Specific user's AS-REQ
kerberos.msg_type == 10 && kerberos.CNameString == "alice"

# Specific SPN's TGS-REQ
kerberos.msg_type == 12 && kerberos.SNameString == "cifs"

# kpasswd (TCP/UDP 464)
tcp.port == 464 || udp.port == 464

# CLDAP DC-locator queries (UDP 389)
cldap && cldap.filter.domain == "corp.example.com"

# DNS SRV lookups for the KDC
dns.qry.name contains "_kerberos._tcp.dc._msdcs.corp.example.com"
```

## Cross-platform comparison

- **AD counterpart** — A Windows domain-joined client has no separate "Kerberos SSO Extension": the Kerberos client is built into `lsass.exe!kerberos.dll` and the ticket cache is an in-memory kernel object exposed via `Kerberos` API (`LsaCallAuthenticationPackage` with `KerbQueryTicketCacheMessage`). The closest functional analogue is the **Group Policy setting "Kerberos SSO"** that configures client-side realm mapping via `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains` registry. The wire protocols are identical — see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md) and [`../02-protocols/05-dns-dynamic-updates.md`](../02-protocols/05-dns-dynamic-updates.md) (for SRV / CLDAP).
- **Linux counterpart** — `sssd` with the `ad` provider manages the same Kerberos lifecycle (TGT acquisition via `kinit`, automatic renewal via `sssd-kcm` or `kcm` daemon, keytab rotation via `adcli`). The KCM (`/run/.krb5_cc_uid_*` over D-Bus) is the Linux analogue of the macOS keychain-backed `API:` cache. See [`../09-linux-equivalents/01-sssd-ad-provider.md`](../09-linux-equivalents/01-sssd-ad-provider.md).
- **High-level side-by-side** — [`../10-comparison-matrices/01-feature-os-matrix.md`](../10-comparison-matrices/01-feature-os-matrix.md).

## References

- Apple Developer doc — "Kerberos SSO Extension" (current through macOS 14).
- Apple Developer doc — "Set up Kerberos SSO on Mac" (administrative guide).
- WWDC19 session 301 — "Introducing the Kerberos SSO Extension".
- WWDC22 session 1009 — "Meet Platform SSO" (announces PSSO as superset).
- `sso_util` manpage — `man sso_util`.
- `kinit`, `klist`, `kdestroy`, `kpasswd` manpages (Heimdal variants).
- Heimdal source — `/usr/lib/libkerberos.dylib` ships as Heimdal; `kinit --version` confirms.
- RFC 4120 — Kerberos 5.
- RFC 6806 — FAST.
- MS-KILE — Microsoft Kerberos protocol extension doc (the SSO Extension speaks MS-KILE profile).
- See [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md) for the full ASN.1 and PAC breakdown.
