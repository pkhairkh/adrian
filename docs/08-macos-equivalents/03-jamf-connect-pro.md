---
title: Jamf Connect — OIDC Login Window + Menu Bar Agent, Kerberos via SSO Extension, Password Sync
audience: senior-engineers
tags: [jamf-connect, oidc, loginwindow, sso-extension, kerberos, macos]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../02-protocols/01-kerberos-internals.md
  - ./01-opendirectory-internals.md
  - ./02-dscl-dsconfigad.md
  - ./04-platform-sso-extension.md
  - ./05-kerberos-sso-extension.md
  - ./06-enterprise-connect-nomad.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

Jamf Connect is two cooperating binaries that replace traditional AD binding with cloud-IdP-driven identity: `Jamf Connect Login` is a loginwindow `AuthorizationDB` mechanism plus a `SecurityAgentPlugins` bundle that authenticates the user against an OIDC IdP (Entra ID, Okta, Ping, Google Workspace) at the login screen, creates a local macOS account on first login, and continues to enforce password sync at unlock; `Jamf Connect Menu Bar` is a user-agent LaunchAgent that maintains an OIDC refresh token, optionally drives the Apple Kerberos SSO Extension for on-prem AD Kerberos, and surfaces password expiry / sign-out / file-share mounting in the menu bar.

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │ Pre-login (bootstrap token required for these to run as system)       │
 │                                                                      │
 │  loginwindow.app  ──► AuthorizationDB  ──► Jamf Connect Login        │
 │  /System/Library/        /System/Library/     mechanism:              │
 │  CoreServices/loginwindow  Authorization/      jamf_connect_login     │
 │                            Rights/system.login.console                │
 │                                                                      │
 │                              │                                       │
 │                              ▼                                       │
 │                  /Library/Security/SecurityAgentPlugins/             │
 │                  JamfConnectLogin.bundle                             │
 │                  (Carbon HIWindow + WKWebView for OIDC)              │
 │                                                                      │
 │                              │  OIDC Authorization Code + PKCE        │
 │                              ▼                                       │
 │                  IdP (Entra ID / Okta / Ping / Google)               │
 │                  https://login.microsoftonline.com/<tenant>/oauth2/  │
 │                                                                      │
 │                              │  id_token + access_token              │
 │                              ▼                                       │
 │  Local account create (dscl . -create /Users/<short>)                │
 │  + ShadowHash derived from ROPG password grant                       │
 │  + PAM `pam_jamfconnect` (or local password sync)                    │
 └──────────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────────┐
 │ Post-login (user session, LaunchAgent)                               │
 │                                                                      │
 │  com.jamf.connect.menubar (LaunchAgent)                              │
 │   ├─ Jamf Connect Menu Bar.app                                       │
 │   ├─ OIDC refresh token stored in user keychain (JamfConnect)        │
 │   ├─ Calls Kerberos SSO Extension via sso_util / authwright          │
 │   │  (Realm + PreferredDomain from com.jamf.connect.login.plist)     │
 │   └─ Local password sync agent (com.jamf.connect.sync)               │
 │      compares OIDC-provided password hash with local ShadowHash;     │
 │      if divergent, prompts user → PAM passwd → opendirectoryd.       │
 └──────────────────────────────────────────────────────────────────────┘
```

Three binaries / bundles are in play:

| Path | Type | Purpose |
|---|---|---|
| `/Library/Security/SecurityAgentPlugins/JamfConnectLogin.bundle` | SecurityAgent plug-in | The login-window UI. Loaded by `SecurityAgent` when `AuthorizationDB` reaches the `jamf_connect_login` mechanism. Hosts a WKWebView for the OIDC flow. |
| `/Applications/Jamf Connect Menu Bar.app` | User agent | Menu-bar item + background sync agent. Runs as the user via LaunchAgent `com.jamf.connect` (or `com.jamf.connect.menubar`). |
| `/usr/local/bin/authrights` (helper) | CLI | Used by the Jamf Connect deployer (`Jamf Connect Configuration` app) to install/uninstall the `AuthorizationDB` mechanism and `SecurityAgentPlugins` entry. |

## AuthorizationDB — how loginwindow is replaced

macOS login auth is governed by an in-memory policy database held by `securityd`, persisted at `/var/db/auth.db` (a.k.a. `/System/Library/Security/Authorization.plist` as the seed). The right `system.login.console` is a sequence of mechanisms; the default on stock macOS is roughly:

```
system.login.console = {
    builtin:prelogin,
    builtin:policy-banner,
    loginwindow:login,
    builtin:login-begin,
    builtin:reset-password,
    builtin:forward-login,
    builtin:login-success,
    loginwindow:login-success
};
```

Jamf Connect modifies this to insert `jamf_connect_login:login` and `jamf_connect_login:login-success` in place of `loginwindow:login`. The result:

```
system.login.console = {
    builtin:prelogin,
    builtin:policy-banner,
    jamf_connect_login:login,          ← replaces loginwindow:login
    builtin:login-begin,
    builtin:reset-password,
    builtin:forward-login,
    jamf_connect_login:login-success,  ← post-auth account provisioning
    builtin:login-success
};
```

Inspect with:

```sh
sudo security authorizationdb read system.login.console
# or dump the whole DB:
sudo security authorizationdb read system.login.console > /tmp/console.plist
plutil -p /tmp/console.plist
```

The `authrights` helper does the read-modify-write atomically. The Jamf Connect installer runs:

```sh
/usr/local/bin/authrights -set /Library/Security/SecurityAgentPlugins/JamfConnectLogin.bundle
```

Uninstall restores the original `loginwindow:login` mechanism.

## Configuration plists

Two plists drive the deployment:

```
/Library/Preferences/com.jamf.connect.login.plist       (root, for the login mechanism)
~/Library/Preferences/com.jamf.connect.menubar.plist     (per-user, for the menu-bar agent)
```

The login plist is the bigger one. Key keys:

| Key | Type | Meaning |
|---|---|---|
| `OIDCProvider` | string | IdP identifier. `Azure`, `Okta`, `Ping`, `Google`, `Custom`. Drives the discovery-URL template. |
| `OIDCClientID` | string | OAuth client_id registered at the IdP. |
| `OIDCClientSecret` | string | Optional. Required for confidential clients. Public PKCE clients omit this. |
| `OIDCRedirectURI` | string | Must match what's registered at the IdP. Default `com.jamf.connect://callback/auth`. |
| `OIDCIDPPath` | string | Custom path appended to the IdP issuer (Okta tenant path etc.). |
| `OIDCIDPTenant` | string | Entra ID tenant GUID or name. |
| `OIDCDiscoveryURL` | string | When `OIDCProvider = Custom`, the full `/.well-known/openid-configuration` URL. |
| `OIDCScopes` | array | Scopes requested. Defaults to `openid profile email`. |
| `ROPGToken` | bool | Enable Resource Owner Password Grant for offline login. If true, Jamf Connect can obtain tokens from the local cached password when no network is available. |
| `ROPGUsername` | string | Optional override of the username field name sent in ROPG. |
| `LoginType` | string | `OIDC` (default) or `Standard` (fall back to local login if IdP unreachable). |
| `CreateAdminUser` | bool | Make the first local user a member of group `admin`. |
| `CreateCustomAdminUser` | bool | Create a separate local admin account specified by `AdminUser`/`AdminPassword`. |
| `AllowNetworkUsers` | bool | Allow login by any user who can authenticate at the IdP (no allow-list). |
| `DenyLocal` | bool | If true, network users must always authenticate via IdP even if a cached mobile account exists. |
| `DenyLocalExcluded` | array | Users in this list always fall back to local auth. |
| `LocalFallback` | bool | If IdP unreachable, fall back to cached local credentials. |
| `LicenseFile` | string | Path to a Jamf Connect license file pushed via MDM (XML, base64-embedded). |
| `LicenseEmail` | string | Jamf account email for license auto-fetch from `https://licensing.jamfcloud.com`. |
| `Kerberos` | dict | Kerberos sub-config; drives `sso_util configure -r <realm>` on first login. |
| `Kerberos.Realms` | array | Kerberos realms to acquire. e.g. `["CORP.EXAMPLE.COM"]`. |
| `Kerberos.PreferredDomain` | string | The realm used by default for `kinit`. |
| `Kerberos.UseKeychain` | bool | Store ticket-granting-ticket in the user keychain (default true; matches Kerberos SSO Extension behaviour). |
| `Kerberos.AutoRenew` | bool | Renew TGT automatically before expiry. |
| `Kerberos.SiteCode` | string | AD site for DC locator. |
| `PasswordPolicy` | dict | Local password sync rules: minimum length, expiry, complexity. |
| `BackgroundImage` | string | Path to a login-background image. |
| `BannerImage` | string | Path to a banner shown above the OIDC webview. |
| `MenuBackgroundColor` | dict | Visual theming for the login window. |
| `HelpURL` | string | URL opened by the "Help" button at login. |

Menu-bar plist key keys:

| Key | Type | Meaning |
|---|---|---|
| `SignInCommand` | string | Shell command run on sign-in. |
| `SignOutCommand` | string | Shell command run on sign-out. |
| `ChangePasswordCommand` | string | Shell command run on password change. |
| `Kerberos` | dict | Same shape as login plist; controls menu-bar Kerberos item. |
| `MenuIcon` | string | Path to a custom menu-bar icon. |
| `ShowHome` | bool | Show Home Directory menu item. |
| `ShowTickets` | bool | Show `klist` output in menu. |
| `ShowSignInButton` | bool | Show Sign-In menu item. |
| `AutoRenew` | bool | Renew OIDC refresh token in the background. |
| `ExpiresInThreshold` | int | Minutes before token expiry to renew. Default 15. |
| `Shares` | array | List of dicts `{Name, Home, LocalMount, SMBServer, SMBShare, AFP…, Kerberos}` for menu-bar mount actions. |
| `FileSystemAccess` | array | TCC privacy-cached file shares. |
| `SelfServicePath` | string | Path to Jamf Self Service.app for the menu item. |

Inspect:

```sh
sudo defaults read /Library/Preferences/com.jamf.connect.login
sudo plutil -p /Library/Preferences/com.jamf.connect.login.plist
defaults read com.jamf.connect.menubar
plutil -p ~/Library/Preferences/com.jamf.connect.menubar.plist
```

## OIDC flow on the login screen

1. The login mechanism loads `JamfConnectLogin.bundle`. It opens a WKWebView pointed at the IdP `authorize` endpoint with `response_type=code`, `scope=openid profile email offline_access`, `code_challenge=<S256>`, `code_challenge_method=S256`, `redirect_uri=com.jamf.connect://callback/auth`, and `client_id=<OIDCClientID>`.
2. The user authenticates. The IdP redirects back to the custom-scheme URI; WKWebView intercepts it (`WKURLSchemeHandler`).
3. Jamf Connect Login exchanges the authorization code for tokens at the IdP `token` endpoint. Receives `access_token`, `id_token`, `refresh_token`.
4. The `id_token` JWT is decoded; the `sub`/`email`/`preferred_username` claim determines the local account name.
5. ROPG (Resource Owner Password Grant) is run against the IdP's token endpoint with the user's typed password (if `ROPGToken = true`). The returned `access_token` becomes a password-equivalent secret for offline re-auth.
6. Jamf Connect Login calls `opendirectoryd` via `dscl`/OpenDirectory APIs to create a local user (`dscl . -create /Users/<short> ...`) with `ShadowHashData` derived from the typed password (PBKDF2-SHA512).
7. `jamf_connect_login:login-success` mechanism runs `securityd` session create, sets the user's loginwindow session, and hands off to the user session.
8. The user-session LaunchAgent starts `Jamf Connect Menu Bar`, which stores the OIDC refresh token in the user's keychain (account: `JamfConnect`, service: `com.jamf.connect.tokens`).

## Kerberos — piggyback on the Kerberos SSO Extension

Jamf Connect does **not** ship its own Kerberos implementation. It drives the Apple Kerberos SSO Extension (`com.apple.KerberosSSO` MDM payload — see [`05-kerberos-sso-extension.md`](./05-kerberos-sso-extension.md)). On first login:

1. Menu-bar agent reads `Kerberos.Realms` and `Kerberos.PreferredDomain` from the login plist.
2. Runs `sso_util configure -r <REALM> -u <user> --password '<password>'` to install the Kerberos SSO Extension profile for the user.
3. Subsequent TGT acquisitions and renewals happen inside `securityd`'s SSO extension process; the ticket cache lives in the user keychain, visible via `klist -v`.

For deployments that want **only** Kerberos without the OIDC login (drop-in NoMAD replacement), the menu-bar agent can run in "Kerberos-only" mode with `OIDCProvider` unset.

## License mechanism

Jamf Connect is a paid commercial product. Two license delivery mechanisms:

- **License file** — an XML file `JCPLicense.xml` pushed to `/Library/Preferences/com.jamf.connect.license.plist` via MDM. Contains a `Signature` (RSA-2048 over SHA-256) and a `Payload` dict with `LicenseType` (`Subscription` or `Perpetual`), `LicenseSeats`, `LicenseExpirationDate`, `CustomerName`.
- **Cloud license** — the login mechanism and menu-bar agent POST `LicenseEmail` to `https://licensing.jamfcloud.com/api/v1/licenses/validate`, which returns the license XML. Requires outbound HTTPS to Jamf's licensing host.

Verify the active license:

```sh
sudo plutil -p /Library/Preferences/com.jamf.connect.license.plist
sudo defaults read /Library/Preferences/com.jamf.connect.license
```

## Sync agent — local password stays in lockstep with the cloud password

The sync agent (`/usr/local/libexec/JamfConnectSync` or equivalent, launched by `com.jamf.connect.sync` LaunchAgent) runs every 15 minutes by default. It:

1. Calls `PAM` with the user's current password against `pam_jamfconnect` (a custom PAM module installed into `/usr/lib/pam/`).
2. `pam_jamfconnect` checks the password against the local ShadowHash.
3. The agent issues an OIDC ROPG token request with the same password at the IdP.
4. If the IdP rejects (password changed at the IdP), the agent surfaces a "Password Sync Required" notification and prompts the user to enter the new password. The agent then writes the new ShadowHash via `opendirectoryd` (the same code path as `passwd`).

Result: the local Mac password matches the IdP password, which (in federated Entra ID setups) in turn matches the on-prem AD password via Entra Connect. So FileVault unlock, screen unlock, and local sudo all use the same password the user types at cloud apps.

## MDM payload

Jamf Connect is typically deployed as a set of configuration profiles via Jamf Pro, Workspace ONE, Intune, Kandji, or Mosyle. The relevant payload types:

| PayloadType | Purpose |
|---|---|
| `com.jamf.connect.login` | Drops the login plist (the keys above). |
| `com.jamf.connect.menubar` | Drops the menu-bar plist. |
| `com.jamf.connect.license` | Drops the license plist. |
| `com.apple.KerberosSSO` | Drives the Kerberos SSO Extension (see [`05-kerberos-sso-extension.md`](./05-kerberos-sso-extension.md)). |

Inspect delivered profiles:

```sh
sudo profiles show -output stdout
sudo profiles list -output stdout
sudo profiles validate -output stdout
```

## Configuration / commands

```sh
# Install the login-window mechanism and SecurityAgentPlugin
sudo /usr/local/bin/authrights -set /Library/Security/SecurityAgentPlugins/JamfConnectLogin.bundle

# Verify AuthorizationDB has the jamf_connect_login mechanisms
sudo security authorizationdb read system.login.console | grep jamf_connect

# Inspect the OIDC IdP discovery doc fetched at login
curl -s https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration | jq

# Inspect what's in the user's keychain (refresh token + Kerberos tickets)
security find-generic-password -s 'com.jamf.connect.tokens' -g ~/Library/Keychains/login.keychain-db
klist -v                                    # TGT in user keychain via SSO Extension

# Run the menu-bar agent in verbose mode for one cycle
/Applications/Jamf\ Connect\ Menu\ Bar.app/Contents/MacOS/Jamf\ Connect\ Menu\ Bar --verbose

# Tail Jamf Connect logs (unified logging)
sudo log show --predicate 'process == "Jamf Connect Menu Bar" OR process == "SecurityAgent"' --info --last 10m
log show --predicate 'subsystem == "com.jamf.connect"' --info --last 10m

# Force a password sync cycle
launchctl kickstart -k gui/$(id -u)/com.jamf.connect.sync
```

## Troubleshooting

- **Login screen stuck at "Connecting…"** — the WKWebView cannot reach the IdP discovery URL. Verify DNS, TLS chain to `login.microsoftonline.com` (or your IdP), and that `OIDCDiscoveryURL` / `OIDCIDPTenant` are correct. `sudo log show --predicate 'process == "SecurityAgent"' --info --last 5m` shows the WKWebView network failures.
- **Login succeeds but local account not created** — `CreateAdminUser` / `AllowNetworkUsers` may be misconfigured. Or the `id_token` `sub` claim does not pass the username regex (`OIDCUsernameClaim` defaults to `preferred_username` or `email`). Decode the JWT to inspect: `echo '<id-token-jwt>' | cut -d. -f2 | base64 -d | jq`.
- **Password sync never triggers** — confirm the LaunchAgent is loaded: `launchctl print gui/$(id -u)/com.jamf.connect.sync`. Check `~/Library/Logs/JamfConnectSync.log` if you're on a version that still writes there; otherwise `log show --predicate 'subsystem == "com.jamf.connect.sync"'`.
- **Kerberos menu item missing** — the SSO Extension profile was not delivered via MDM. Check `sudo profiles list` for a `com.apple.KerberosSSO` payload, then `sso_util configure -r <REALM> -u <user>` manually to verify.
- **`klist -v` shows no TGT but Jamf Connect menu says "Signed In"** — OIDC is healthy but Kerberos SSO Extension is not. Run `sso_util cache -l` and `sso_util configure -r <REALM> -u <user> --password '<password>'` to re-install.
- **FileVault unlock fails after IdP password change** — the sync agent hasn't run yet. The user must sign in with the **old** password once to unlock FileVault, then the agent will prompt to sync.

## Wire-protocol diagnostics

OIDC is HTTPS-only; Kerberos is the only wire protocol Jamf Connect drives indirectly. Capture both:

```
# HTTPS to the IdP (Entra ID)
tls && http.host contains "login.microsoftonline.com"

# OIDC authorize redirect
http.request.uri contains "/oauth2/v2.0/authorize"

# OIDC token endpoint (POST)
http.request.method == "POST" && http.request.uri contains "/oauth2/v2.0/token"

# Kerberos AS-REQ from the SSO Extension to the AD DC
kerberos.msg_type == 10 && kerberos.CNameString == "<user>"
```

## Cross-platform comparison

- **AD counterpart** — Jamf Connect deliberately replaces AD binding with cloud-IdP-driven identity, so its closest AD-side analogue is the combination of AD FS + Entra Connect + Entra ID for federated cloud auth ([`../01-ad-core/03-ad-fs-federation.md`](../01-ad-core/03-ad-fs-federation.md)), plus GPO-driven password sync on Windows clients. The Kerberos SSO Extension half of Jamf Connect produces the same Kerberos wire traffic a domain-joined Windows client would emit — see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md).
- **Linux counterpart** — `sssd` with the `ad` provider and `realmd` does the equivalent of `dsconfigad` (AD join). For cloud-first login without AD binding, the closest Linux equivalent is **Google Credentials for SSO + GNOME Online Accounts** or **Azure AD join in Ubuntu Pro** — neither has feature parity with Jamf Connect. See [`../09-linux-equivalents/01-sssd-ad-provider.md`](../09-linux-equivalents/01-sssd-ad-provider.md).
- **High-level side-by-side** — [`../10-comparison-matrices/01-feature-os-matrix.md`](../10-comparison-matrices/01-feature-os-matrix.md).

## References

- Jamf official doc — "Jamf Connect Administrator's Guide" (current version 2.x).
- Jamf blog / release notes — historical changes from NoMAD lineage (post-2021 Orchard & Grove acquisition).
- Apple Developer doc — "Customizing the Login Window" (AuthorizationDB mechanism reference).
- `security authorizationdb` manpage — `man security`.
- `sso_util` manpage — `man sso_util` (covers the `configure` and `cache` verbs).
- OIDC spec — RFC 6749 (OAuth 2.0), RFC 8252 (Native Apps, PKCE), OpenID Connect Core 1.0.
- RFC 4120 / MS-KILE — for the Kerberos side, see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md).
