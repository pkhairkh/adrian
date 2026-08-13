---
title: Enterprise Connect & NoMAD — Legacy Apple and Open-Source PSSO Precursors
audience: senior-engineers
tags: [enterprise-connect, nomad, noload, kerberos, password-sync, eol, macos]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../02-protocols/01-kerberos-internals.md
  - ./01-opendirectory-internals.md
  - ./02-dscl-dsconfigad.md
  - ./03-jamf-connect-pro.md
  - ./04-platform-sso-extension.md
  - ./05-kerberos-sso-extension.md
  - ./07-third-party-agents-mac.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

Enterprise Connect was Apple's per-user Kerberos-and-password-sync application (a `.app` plus an MDM-driven config payload of type `com.apple.Enterprise-Connect`) that shipped in limited macOS releases from ~10.12 through ~10.15 as a stopgap before Apple shipped the Kerberos SSO Extension; NoMAD (No AD) was Orchard & Grove's open-source, MIT-licensed replacement that maintained Kerberos tickets and synced local passwords from a menu-bar item, with its companion NoMAD Login Window (NoLoAD) replacing the macOS loginwindow to allow AD authentication at boot — both NoMAD projects were acquired by Jamf in 2021 and their functionality folded into Jamf Connect, leaving both as EOL.

## Architecture — Enterprise Connect

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Apple MDM payload                                                   │
 │   PayloadType: com.apple.Enterprise-Connect                          │
 │   Keys: realm, domain, kerberosRealms, changePasswordURL, etc.       │
 └───────────────────────────────────┬──────────────────────────────────┘
                                     │ profile install
                                     ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Enterprise Connect.app                                              │
 │  /System/Applications/Utilities/Enterprise Connect.app  (some OS)    │
 │  /Applications/Enterprise Connect.app                    (other OS)  │
 │  /Applications/Utilities/Enterprise Connect.app          (other OS)  │
 │  Run as user LaunchAgent: com.apple.enterpriseconnect                │
 └──────────────────────────────────────────────────────────────────────┘
                │
                │ Direct Heimdal kinit calls
                ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Heimdal Kerberos client libs (same as /usr/bin/kinit)               │
 │  /usr/lib/libkerberos.dylib                                          │
 └──────────────────────────────────────────────────────────────────────┘
                │
                │ Ticket cache: FILE:/tmp/krb5cc_<uid>
                ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  AD DC (KDC + kpasswd + DC locator)                                  │
 └──────────────────────────────────────────────────────────────────────┘
```

- Enterprise Connect was **never universally shipped**. It was downloadable from Apple's support site for AppleSeed for IT / enterprise customers and bundled in some macOS point releases for education deployments. The binary location varied; the most common install path was `/Applications/Utilities/Enterprise Connect.app`. The MDM payload type `com.apple.Enterprise-Connect` was always the config vector.
- Enterprise Connect was per-user (LaunchAgent, not LaunchDaemon). It did **not** manage the host's machine-account TGT — only the user's TGT.
- Ticket cache was the Heimdal default `FILE:/tmp/krb5cc_<uid>`. Enterprise Connect predated the keychain-backed `API:` cache type used by the SSO Extension.
- Password sync worked by intercepting `passwd` via PAM (`pam_ec_pwd_sync.so`) or by hooking the SystemKeychain; the mechanism varied across releases.

## Enterprise Connect MDM payload schema

PayloadType: `com.apple.Enterprise-Connect`

```
PayloadType: com.apple.Enterprise-Connect
PayloadIdentifier: com.apple.enterpriseconnect
PayloadUUID: <random UUID>
PayloadVersion: 1
PayloadDisplayName: Enterprise Connect — CORP Realm

# Extension-specific keys
realm: CORP.EXAMPLE.COM
domain: corp.example.com
kerberosRealms:
    - CORP.EXAMPLE.COM
    - CHILD.CORP.EXAMPLE.COM
changePasswordURL: https://passwordreset.corp.example.com/
useKeychain: true                          # store TGT in user keychain
autoRenew: true                            # renew TGT before expiry
changePasswordCommand: /usr/local/bin/ec-changed-pw.sh
signInCommand: /usr/local/bin/ec-signed-in.sh
signOutCommand: /usr/local/bin/ec-signed-out.sh
showSignInAlert: true
displaySignInWindow: true
```

Apple deprecated the `com.apple.Enterprise-Connect` payload type in macOS 10.15 alongside the Kerberos SSO Extension introduction; the payload still parses (silent no-op) on macOS 13+ but the binary is not shipped.

## Configuration / inspection (legacy)

```sh
# Confirm Enterprise Connect binary presence
ls -la /Applications/Utilities/Enterprise\ Connect.app 2>/dev/null
ls -la /System/Applications/Utilities/Enterprise\ Connect.app 2>/dev/null
ls -la /Applications/Enterprise\ Connect.app 2>/dev/null

# Confirm MDM payload installed (legacy)
sudo profiles show -output stdout | grep -i enterprise
sudo plutil -p /Library/Preferences/com.apple.enterpriseconnect.plist 2>/dev/null
sudo defaults read /Library/Preferences/com.apple.enterpriseconnect 2>/dev/null

# Confirm LaunchAgent running
launchctl print gui/$(id -u)/com.apple.enterpriseconnect 2>/dev/null

# Inspect tickets acquired by EC (legacy file cache)
klist -v
sudo klist -v
```

## Architecture — NoMAD and NoMAD Login (NoLoAD)

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  MDM / Jamf Pro / Workspace ONE                                      │
 │   └─ com.trusourcelabs.NoMAD.plist (user prefs)                      │
 │   └─ com.trusourcelabs.NoMADLoginAD.plist (login window prefs)       │
 └───────────────────────────────────┬──────────────────────────────────┘
                                     │ profile install
                                     ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  NoMAD.app  (menu-bar agent, user LaunchAgent)                       │
 │  /Applications/NoMAD.app                                             │
 │  LaunchAgent: com.trusourcelabs.NoMAD.user                            │
 │  - Menu-bar ticket + password-sync UI                                │
 │  - Direct Heimdal kinit/kdestroy calls                               │
 │  - Custom SignInCommand / ChangePasswordCommand shell hooks          │
 └──────────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────────┐
 │  NoMAD Login Window (a.k.a. NoLoAD, separate binary)                 │
 │  /Applications/NoMAD Login.app                                       │
 │  - Replaces the loginwindow:login mechanism in AuthorizationDB       │
 │  - Carbon HIWindow UI prompting for AD username + password           │
 │  - On success: creates local account via dscl if missing             │
 │  - PAM module: pam_nomadlogin.so                                     │
 │  - Optional DEPNotify integration for first-run scripted setup       │
 └──────────────────────────────────────────────────────────────────────┘
```

- NoMAD was started by Joel Rennert and Tom Bridge at Orchard & Grove in 2016. The MIT-licensed source is at `https://gitlab.com/orchardandgrove-oss/no-mad` and `https://gitlab.com/orchardandgrove-oss/no-mad-login`. The last upstream NoMAD release was 1.22; NoLoAD's last release was around 1.4.
- Jamf acquired Orchard & Grove in May 2021, hired the engineers, and re-released NoMAD + NoLoAD as Jamf Connect (binary incompatible; the new product reimplements the same UX).
- NoMAD's ticket cache is `FILE:/tmp/krb5cc_<uid>` by default, configurable to keychain via `UseKeychain = true`. The menu-bar app polls `klist` every 60 seconds and refreshes the icon.

## NoMAD preference schema — `com.trusourcelabs.NoMAD.plist`

Key keys (documented in NoMAD's `Preferences.md`):

| Key | Type | Meaning |
|---|---|---|
| `UseKeychain` | bool | Store TGT in user keychain (`API:` cache) instead of `FILE:`. Default `false`. |
| `AutoRenew` | bool | Renew TGT before expiry. Default `true`. |
| `AutoFederate` | bool | Auto-federate to AD FS for OAuth-style federated auth. |
| `Realm` | string | Kerberos realm (uppercase). |
| `Domains` | array | DNS domains to map to the realm. |
| `SiteCode` | string | AD site pin (optional). |
| `PreferredDC` | string | Pin to a specific DC (optional). |
| `SignInCommand` | string | Shell command run after successful sign-in. |
| `SignOutCommand` | string | Shell command run after sign-out. |
| `ChangePasswordCommand` | string | Shell command run after password change at the KDC. |
| `PasswordExpirationDays` | int | Show "expire in N days" notification. Default 7. |
| `ShowHome` | bool | Show home dir menu item. |
| `ShowTickets` | bool | Show `klist` output in menu. |
| `ShowHelp` | bool | Show Help menu item. |
| `MenuIcon` | string | Path to custom menu-bar icon. |
| `CaribouTime` | bool | Run NoLoAD preflight before sign-in (DEPNotify chain). |
| `ExcludeUsers` | array | Local users that NoMAD should never sign in. |
| `LocalPasswordSync` | bool | Sync local password with AD password on change. Default `true`. |
| `LocalPasswordSyncOnMatchOnly` | bool | Only sync if the current local password equals the AD password. |

## NoMAD Login Window preference schema — `com.trusourcelabs.NoMADLoginAD.plist`

| Key | Type | Meaning |
|---|---|---|
| `ADDomain` | string | AD domain FQDN. |
| `CreateAdminUser` | bool | Make first local user a member of `admin`. |
| `CreateMobileAccount` | bool | Create a mobile account on first login. |
| `LocalAdminUsers` | array | Local users to always treat as admins. |
| `DenyLocal` | bool | Force network authentication even for local users. |
| `DenyLocalExcluded` | array | Local users exempt from `DenyLocal`. |
| `LoginScript` | string | Path to script run after first login. |
| `LogoutScript` | string | Path to script run on logout. |
| `KeychainAdd` | bool | Add the AD password to the user keychain as `NoMAD Login`. |
| `NotifyUsers` | bool | Use DEPNotify-style progress UI. |
| `BackgroundImage` | string | Path to login background. |
| `DisplayName` | string | Display string in the login window title. |
| `LoadLoginScriptsAsRoot` | bool | Run login scripts as root instead of the user. |
| `EULA` | dict | Show an EULA on first login. |
| `CustomFields` | dict | Extra fields to prompt for at login (added to user record). |

## AuthorizationDB — how NoLoAD replaces loginwindow

The NoLoAD installer modifies `system.login.console` in `AuthorizationDB`:

```
system.login.console = {
    builtin:prelogin,
    builtin:policy-banner,
    NomadLogin:login,            ← replaces loginwindow:login
    builtin:login-begin,
    builtin:reset-password,
    builtin:forward-login,
    NomadLogin:login-success,    ← post-auth account provisioning
    builtin:login-success
};
```

The `NomadLogin:login` mechanism is implemented by the `NoMAD Login.app`'s `SecurityAgentPlugin` bundle, located at `/Applications/NoMAD Login.app/Contents/PlugIns/NoLoADLoginPlugin.bundle`. The installer copies this bundle to `/Library/Security/SecurityAgentPlugins/NoLoADLoginPlugin.bundle` and updates `AuthorizationDB`.

Inspect (on a legacy install):

```sh
sudo security authorizationdb read system.login.console | grep -i nomad
ls -la /Library/Security/SecurityAgentPlugins/NoLoADLoginPlugin.bundle 2>/dev/null
```

## Configuration / inspection (legacy)

```sh
# NoMAD.app menu-bar prefs
defaults read com.trusourcelabs.NoMAD
plutil -p ~/Library/Preferences/com.trusourcelabs.NoMAD.plist

# NoLoAD login-window prefs
sudo defaults read com.trusourcelabs.NoMADLoginAD
sudo plutil -p /Library/Preferences/com.trusourcelabs.NoMADLoginAD.plist

# Confirm LaunchAgent / LaunchDaemon
launchctl print gui/$(id -u)/com.trusourcelabs.NoMAD.user 2>/dev/null
launchctl print system/com.trusourcelabs.NoMADLoginAD 2>/dev/null

# Confirm AuthorizationDB contains the NomadLogin mechanism
sudo security authorizationdb read system.login.console | grep -i nomad

# Inspect tickets (legacy file cache by default)
klist -v

# Confirm Heimdal libraries used by NoMAD.app
otool -L /Applications/NoMAD.app/Contents/MacOS/NoMAD | grep -i kerberos
```

## NoMAD ticket lifecycle

1. **First run / menu-bar Sign In** — user clicks the NoMAD menu-bar icon, chooses Sign In, types AD credentials.
2. NoMAD.app calls `kinit <user>@<REALM>` via NSTask. Heimdal `kinit` writes to `FILE:/tmp/krb5cc_<uid>` (or `API:` keychain cache if `UseKeychain = true`).
3. Menu-bar icon updates to "Signed in" with a green checkmark.
4. **Auto-renew** — if `AutoRenew = true`, a `NSTimer` fires every 5 minutes. At 75% of TGT lifetime, NoMAD runs `kinit -R` to renew. Renewal re-prompts only if the original `kinit` used a keytab (which NoMAD's interactive flow does not), so renewal is silent.
5. **Password change** — user clicks Change Password in the menu. NoMAD prompts for old + new password, runs `kpasswd <user>@<REALM>`. On success, if `LocalPasswordSync = true`, NoMAD calls PAM `passwd` against the local account to set the new local password.
6. **Sign out** — `kdestroy -a` clears the cache. Menu icon reverts to "Signed out".

## Why NoMAD is EOL

- Jamf acquired Orchard & Grove in May 2021. The team was moved to Jamf Connect development. No new NoMAD releases after 1.22.
- The MIT-licensed source is still on GitLab but receives only community PRs. Security fixes are not backported.
- Apple's Kerberos SSO Extension (macOS 10.15+) and Platform SSO (macOS 13+) supersede NoMAD's functionality with a first-party, MDM-configured, keychain-backed equivalent.
- The Apple Silicon transition made NoMAD's PAM-based password sync fragile in some edge cases (Apple tightened PAM policies in macOS 11+); Jamf Connect was rewritten to use a different sync approach that survives the new policies.
- For all greenfield deployments, use either Jamf Connect ([`03-jamf-connect-pro.md`](./03-jamf-connect-pro.md)) or Platform SSO + Kerberos SSO Extension ([`04-platform-sso-extension.md`](./04-platform-sso-extension.md) + [`05-kerberos-sso-extension.md`](./05-kerberos-sso-extension.md)).

## Troubleshooting (legacy)

- **NoMAD menu icon missing** — LaunchAgent not loaded. `launchctl load ~/Library/LaunchAgents/com.trusourcelabs.NoMAD.user.plist` (or `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.trusourcelabs.NoMAD.user.plist` on 11+).
- **NoLoAD login window not appearing at boot** — `NomadLogin:login` mechanism missing from AuthorizationDB. Re-run the NoLoAD installer, or manually:
  ```sh
  sudo security authorizationdb read system.login.console > /tmp/console.plist
  # edit /tmp/console.plist to replace loginwindow:login with NomadLogin:login
  sudo security authorizationdb write system.login.console < /tmp/console.plist
  ```
  Always back up the original AuthorizationDB first — a corrupted mechanism bricks login.
- **`kinit` from NoMAD fails but `kinit` from terminal succeeds** — NoMAD passes realm argument with mixed case (e.g. `corp.example.com`). Kerberos realms are case-sensitive; the realm must be uppercase. Fix the `Realm` key in `com.trusourcelabs.NoMAD.plist`.
- **Password sync leaves local password out of sync** — `LocalPasswordSync = false`, or the user changed the AD password at a Windows machine and NoMAD has not detected the change yet. NoMAD detects divergence when `kinit` fails with `KDC_ERR_PREAUTH_FAILED`; on that failure it prompts for the new password, then syncs.
- **FileVault unlock fails after AD password change** — same root cause as Jamf Connect. FileVault uses the cached local password at boot; the sync runs after the user session starts. The user must unlock with the OLD password once, then NoMAD syncs.

## Wire-protocol diagnostics

Enterprise Connect and NoMAD both drive standard Kerberos wire protocols. Same Wireshark filters apply:

```
# All Kerberos from this Mac to a DC
kerberos && ip.addr == 10.0.0.5

# AS-REQ from NoMAD's kinit
kerberos.msg_type == 10 && kerberos.CNameString == "<user>"

# kpasswd (TCP/UDP 464) for password change
tcp.port == 464 || udp.port == 464

# CLDAP DC-locator (NoMAD uses the same netlogon query as the AD plug-in)
cldap && cldap.filter.domain == "corp.example.com"
```

## Cross-platform comparison

- **AD counterpart** — Enterprise Connect was Apple's attempt to ship the equivalent of Windows' built-in `klist` / `ksetup` / `cmdkey` user-mode tooling. NoMAD was an open-source functional analogue of the **Credentials Manager** UI on Windows (`rundll32.exe keymgr.dll,KRShowKeyMgr`). The Kerberos wire protocols are identical to a Windows client — see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md).
- **Linux counterpart** — `klist` / `kinit` / `kdestroy` on Linux (MIT Kerberos) are the closest functional analogues. For the menu-bar UX, the GNOME Shell Kerberos credential extension (`gnome-extensions`) and KDE's `kwalletmanager` offer similar functionality. See [`../09-linux-equivalents/01-sssd-ad-provider.md`](../09-linux-equivalents/01-sssd-ad-provider.md).
- **High-level side-by-side** — [`../10-comparison-matrices/01-feature-os-matrix.md`](../10-comparison-matrices/01-feature-os-matrix.md).

## References

- Orchard & Grove NoMAD source — `https://gitlab.com/orchardandgrove-oss/no-mad` (last release 1.22).
- Orchard & Grove NoMAD Login source — `https://gitlab.com/orchardandgrove-oss/no-mad-login` (last release ~1.4).
- NoMAD User Guide PDF (archived) — documents every key in `com.trusourcelabs.NoMAD.plist`.
- NoMAD Login Admin Guide PDF (archived) — documents every key in `com.trusourcelabs.NoMADLoginAD.plist`.
- Jamf acquisition announcement (May 2021) — Jamf press release; NoMAD team transitioned to Jamf Connect.
- Apple Support doc HT208020 (legacy) — "Use Enterprise Connect" (now redirects to Kerberos SSO Extension doc).
- `security authorizationdb` manpage — `man security`.
- RFC 4120 / MS-KILE — see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md).
