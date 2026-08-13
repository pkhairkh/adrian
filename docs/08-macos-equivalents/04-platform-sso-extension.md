---
title: Apple Platform SSO Extension — macOS 13+ IdP-Driven Authentication with Secure Enclave Hardware Binding
audience: senior-engineers
tags: [platform-sso, psso, sso-extension, secure-enclave, sep, mdm, identity, macos]
related:
  - ../01-ad-core/01-ad-ds-internals.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../02-protocols/01-kerberos-internals.md
  - ./01-opendirectory-internals.md
  - ./03-jamf-connect-pro.md
  - ./05-kerberos-sso-extension.md
  - ./06-enterprise-connect-nomad.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
  - ../10-comparison-matrices/01-feature-os-matrix.md
last_updated: 2026-08-13
---

Apple Platform SSO (PSSO) is a macOS 13+ Endpoint Security `Authentication_SSO` extension that runs inside `securityd`'s `authentication-extension` XPC child process, registers as a `CredentialProvider` with the Authorization framework, and uses a hardware-bound (Secure Enclave / SEP) or password-derived key to silently mint IdP tokens (OAuth 2.0, SAML, or Kerberos — the latter via the bundled Kerberos SSO Extension sub-payload) on behalf of the user, replacing the older Enterprise Connect app and supplanting third-party tools like NoMAD and Jamf Connect's ROPG path for shops that want first-party SSO.

## Architecture

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │  MDM (Jamf, Intune, Workspace ONE, Kandji, Mosyle)                   │
 │   └─ PayloadType: com.apple.configuration-ext.platform-sso           │
 └───────────────────────────────────┬──────────────────────────────────┘
                                     │ profile install
                                     ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  /System/Library/ExtensionKit/Extensions/...                          │
 │  Authentication_SSO.appex  (Endpoint Security SSO extension)         │
 │  loaded into: securityd  →  authentication-extension XPC service     │
 │  (process name in `ps`: authentication-extension)                    │
 └──────────────────────────────────────────────────────────────────────┘
                │                                    │
                │ Authorization C API                │ SSOExtension protocol
                │ (AuthorizationCopyCredential)      │ (CredentialProvider)
                ▼                                    ▼
 ┌────────────────────────────────────┐   ┌────────────────────────────┐
 │  Authorization.framework           │   │  IdP Integration           │
 │  /System/Library/Frameworks/        │   │   ├─ OAuth 2.0 + PKCE      │
 │  Security.framework                 │   │   ├─ SAML 2.0              │
 │  - AuthorizationCopyRightEx         │   │   └─ Kerberos sub-payload  │
 │  - AuthorizationCopyCredential      │   │      (com.apple.KerberosSSO│
 │  - AuthorizationSetCredential       │   │       — see 05-…)          │
 └────────────────────────────────────┘   └────────────────────────────┘
                │
                │ Device registration + silent token mint
                ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  IdP (Azure AD / Entra ID, Okta, Ping, Google Workspace)             │
 │   ├─ Device object registered with public key                        │
 │   ├─ Refresh token (RT) stored in System or User keychain            │
 │   └─ Silent token exchange on subsequent SSO                         │
 └──────────────────────────────────────────────────────────────────────┘
                │
                │ Private key for token signing
                ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │  Secure Enclave Processor (SEP) on T2 / Apple Silicon                │
 │   ├─ Hardware-bound ECDSA P-256 key, per-user or per-device          │
 │   ├─ Key creation via Secure Enclave's kSecAttrTokenIDSecureEnclave  │
 │   └─ Key never leaves SEP; only signatures come out                  │
 └──────────────────────────────────────────────────────────────────────┘
```

- The extension is **first-party** — it ships with the OS as `Authentication_SSO.appex` (a system ExtensionKit app extension). MDM does not deliver the binary; it only delivers the configuration payload. The MDM install triggers the extension to register a `CredentialProvider` for one or more IdPs.
- The extension is hosted by `securityd`. In `ps aux | grep authentication-extension` you see the XPC child process spawn on demand when an app calls `AuthorizationCopyCredential` (or when `sso_util` runs).
- The extension can use two classes of keys:
  - **Hardware-bound (SEP)** — ECDSA P-256, generated via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclaveTokenID`. The private key never leaves the SEP. This is the "passwordless" / phishing-resistant mode.
  - **Password-derived** — a key derived from the user's login password via PBKDF2, used when the deployment cannot rely on SEP (older Intel Macs without T2). Falls back to the user typing the password on each silent mint, defeating much of the point.

## MDM payload schema

PayloadType: `com.apple.configuration-ext.platform-sso`

```
PayloadType: com.apple.configuration-ext.platform-sso
PayloadIdentifier: com.mycompany.sso.platform
PayloadUUID: <random UUID>
PayloadVersion: 1
PayloadDisplayName: Platform SSO — Entra ID

# PSSO-specific keys (PayloadContent dict)
AuthenticationMethod: Hardware_Bound        # or "Password"
PlatformSSOProfile: Device                   # or "User"
                                              #   Device = device-wide, keys in System keychain,
                                              #   User   = per-user, keys in user keychain
TokenToUserSharing: Enable                   # or "Disable"
                                              #   Enable = extension can share the IdP token with
                                              #            calling apps (e.g. Safari, Mail)
                                              #   Disable = extension only authenticates the user;
                                              #            no token sharing
UseSharedDeviceKey: true                     # bool
                                              #   true = share one device key across all users
                                              #   false = one key per user
                                              #   ignored when PlatformSSOProfile = User

# IdP registration payloads (extension-specific sub-dicts)
AuthenticationClient:
    Type: OAuth                              # or "SAML", "Kerberos"
    AuthorizationURL: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
    TokenURL: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
    ClientID: <client-id>
    Scopes:
        - openid
        - profile
        - offline_access
    RedirectURI: com.apple.sso://callback

# Optional Kerberos sub-payload (drives the Kerberos SSO Extension — see 05-…)
Kerberos:
    Realm: CORP.EXAMPLE.COM
    Domains:
        - corp.example.com
        - child.corp.example.com
    UseSiteAutoDiscovery: true

# Optional list of application bundle IDs allowed to request tokens
AllowedApplications:
    - com.microsoft.Outlook
    - com.microsoft.rdc.macos
    - com.apple.Safari
```

Key enumeration:

| Key | Type | Values / Notes |
|---|---|---|
| `AuthenticationMethod` | string | `Password` — password-derived key, no SEP. `Hardware_Bound` — SEP ECDSA P-256 key. Hardware_Bound requires T2 or Apple Silicon. |
| `PlatformSSOProfile` | string | `Device` — single device identity in system keychain. `User` — per-user identity in user keychain. Device profile is typical for shared/lab Macs; User profile for 1:1 Macs. |
| `TokenToUserSharing` | string | `Enable` — calling apps receive a bearer token. `Disable` — only authentication result returned; no token. |
| `UseSharedDeviceKey` | bool | When `PlatformSSOProfile = Device`, multiple users share one device key. When `User`, ignored. |
| `AuthenticationClient` | dict | IdP-specific config. `Type` = `OAuth`/`SAML`/`Kerberos`. |
| `AllowedApplications` | array | Bundle IDs of apps that may invoke `AuthorizationCopyCredential` against this extension. |
| `UserEnrollment` | dict | Optional. Controls whether user must enroll on first login. |

Inspect the installed profile:

```sh
sudo profiles show -output stdout-xml | grep -A50 platform-sso
sudo profiles list
sudo profiles validate -p <profile-identifier>
```

## Device registration flow

PSSO implements a device-registration protocol conceptually identical to Windows Hello for Business / Entra ID device registration:

1. **MDM install triggers extension activation.** `securityd` loads `Authentication_SSO.appex`, registers the `CredentialProvider`.
2. **First-run enrollment.** The user is prompted (via a SecurityAgent alert) to authenticate at the IdP. The extension uses a WKWebView via SecurityAgent's plug-in surface; the user types cloud credentials.
3. **Key generation.** The extension calls `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclaveTokenID`, `kSecAttrKeyType = kSecAttrKeyTypeECSECPrimeRandom`, `kSecAttrKeySizeInBits = 256`, `kSecPrivateKeyAttrs = { kSecAttrIsPermanent = true, kSecAttrApplicationTag = "com.apple.sso.<user-or-device>" }`. The public key is exported.
4. **Device object creation at the IdP.** The extension POSTs the public key + device metadata (serial number, OS version, hardware model) to the IdP's device-registration endpoint. Entra ID: `/devices/<device-id>/register`. The IdP stores the public key against a new device object and returns a refresh token (RT) encrypted to a key only the extension can derive (typically the SEP-protected key, used as a key-encryption-key).
5. **Refresh-token persistence.** The RT is stored in the keychain:
   - `PlatformSSOProfile = Device` → `/Library/Keychains/System.keychain`, account = `PlatformSSO-Device`.
   - `PlatformSSOProfile = User` → `~/Library/Keychains/login.keychain-db`, account = `PlatformSSO-User`.
6. **Silent token mint.** Subsequent `AuthorizationCopyCredential` calls (e.g. from Safari accessing `*.sharepoint.com`) invoke the extension, which:
   a. Loads the RT from the keychain.
   b. Constructs a JWT or signed assertion, signed by the SEP key.
   c. POSTs to the IdP `token` endpoint with `grant_type=refresh_token` and the signed assertion as proof-of-possession.
   d. Receives a new `access_token`, returns it to the calling app.
7. **Re-authentication.** If the RT expires or the user is required to reauthenticate, the extension surfaces a SecurityAgent prompt and the cycle restarts at step 2.

## sso_util CLI

`sso_util` (`/usr/bin/sso_util`) is the supported user-facing CLI for the Platform SSO and Kerberos SSO Extension subsystems. Key verbs:

```sh
# Configure Platform SSO against an IdP (interactive)
sso_util configure -a <IdP-type> -r <RelyingParty-URL> -k <ClientID>
#   -a / --idp-type:    Azure, Okta, Ping, Google, Custom
#   -r / --relying-party: the IdP issuer URL
#   -k / --client-id:   OAuth client_id

# List configured SSO extensions
sso_util extensions -l

# Show currently cached credentials
sso_util cache -l

# Force a token refresh
sso_util cache -r -i <idp-issuer>

# Remove a credential / sign out
sso_util cache -d -i <idp-issuer>

# Change the user's password at the IdP (PSSO password mode)
sso_util password -i <idp-issuer> -u <user>

# Diagnostics
sso_util diagnose -i <idp-issuer>
```

For the Kerberos-specific sub-commands (`configure -r <REALM>`, `password -r <REALM> -u <user>`), see [`05-kerberos-sso-extension.md`](./05-kerberos-sso-extension.md). Both share the same `sso_util` binary because the Kerberos SSO Extension is technically a sub-type of the Platform SSO `Authentication_SSO` extension family.

## Authorization framework integration

The `Security` framework's `Authorization` API surface was extended in macOS 13 to surface PSSO credentials:

```c
// AuthorizationCopyRightEx — surfaces SSO credential if the right is bound to PSSO
OSStatus AuthorizationCopyRightEx(
    AuthorizationRef   authRef,
    const char        *rightName,           // e.g. "com.mycompany.sso.token"
    AuthorizationFlags flags,
    AuthorizationItemSet *environment,
    AuthorizationItemSet *result);          // ← kAuthorizationCredentialTypeSSO comes back here

// The new credential type tag
#define kAuthorizationCredentialTypeSSO   "sso"

// AuthorizationItem for SSO has:
//   name        = the IdP issuer URL
//   value       = opaque token blob (often a JWT access_token)
//   valueLength = strlen(token)
```

Apps like Microsoft Outlook, Edge, Safari, and RDC call this API to silently obtain IdP tokens rather than running their own interactive OAuth flows. The `TokenToUserSharing` payload key gates whether this sharing is allowed per-profile.

## Configuration / commands

```sh
# Verify PSSO extension is loaded
systemextensionsctl list | grep -i sso
# Expect: com.apple.sso.Authentication_SSO in the list

# Inspect running authentication-extension process
ps aux | grep authentication-extension
sudo log show --predicate 'process == "authentication-extension"' --last 10m --info

# Inspect installed MDM payloads
sudo profiles show -output stdout
sudo profiles list -output stdout
sudo plutil -p /var/db/ConfigurationProfiles/Settings/com.apple.configuration-ext.platform-sso.plist 2>/dev/null

# Confirm a credential is cached
sso_util cache -l

# Confirm the SEP key exists in the keychain
sudo security find-key -k /Library/Keychains/System.keychain | grep -i 'ApplicationTag.*com.apple.sso'
security find-key -k ~/Library/Keychains/login.keychain-db | grep -i 'com.apple.sso'

# Force a fresh silent token mint (after rotating IdP secrets)
sso_util cache -r -i https://login.microsoftonline.com/<tenant>/

# When the Kerberos sub-payload is installed, the ticket cache is in the
# user keychain (API:Initialdefaultcache) and visible via klist — same
# surface the bundled Kerberos SSO Extension uses (see 05-…)
klist -v
sudo klist -v                                   # host machine-account TGT (system context)

# If the local account was created by an earlier Jamf Connect / dsconfigad
# workflow, inspect the OD-side state directly:
dscl /Search -read /Users/<user> GeneratedUID AuthenticationAuthority
dscl /Active Directory/CORP -read /Users/<user> userPrincipalName
```

## Troubleshooting

- **`sso_util configure` fails with "extension not available"** — the MDM payload was not delivered, or the Mac is on macOS < 13. Check `sudo profiles list` for `com.apple.configuration-ext.platform-sso`. If missing, re-push the profile from the MDM. Also confirm `sw_vers -productVersion` ≥ 13.0.
- **`AuthenticationMethod = Hardware_Bound` rejected on Intel Mac without T2** — the SEP is required for hardware-bound keys. The Mac must be T2 (2018+) or Apple Silicon. On older Intel Macs, fall back to `Password`.
- **Silent mint fails with `NSURLErrorServerCertificateUntrusted`** — the IdP endpoint cert chain is not trusted by the system root store. Add the issuing CA to System keychain and trust it: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <ca.pem>`.
- **Token returned to calling app is empty** — `TokenToUserSharing = Disable` in the profile. Re-enable, or have the calling app use `AuthorizationCopyRight` (not `AuthorizationCopyCredential`) and re-issue.
- **After password change at the IdP, PSSO still tries the old RT** — RT rotation failed. Run `sso_util cache -d -i <issuer>` then `sso_util configure -a <IdP-type> -r <RelyingParty> -k <ClientID>` to re-enroll.
- **`authentication-extension` process high CPU** — known issue with stale keychain entries. Kill the process: `sudo killall authentication-extension`; `securityd` respawns it.
- **Kerberos sub-payload did not install** — verify the `Kerberos` dict inside the PSSO payload is well-formed, then check `sso_util extensions -l` for both `Authentication_SSO` (PSSO) and `KerberosSSO` (sub-payload). See [`05-kerberos-sso-extension.md`](./05-kerberos-sso-extension.md).

## Wire-protocol diagnostics

PSSO primarily drives HTTPS to the IdP. The Kerberos sub-payload drives Kerberos and CLDAP. Wireshark display filters:

```
# HTTPS to Entra ID
tls && (http.host contains "login.microsoftonline.com" || http.host contains "graph.microsoft.com")

# OAuth token endpoint POSTs (silent mint)
http.request.method == "POST" && http.request.uri contains "/oauth2/v2.0/token"

# SAML POST bindings (Okta / Ping)
http.request.method == "POST" && http.request.uri contains "/SAML2/POST"

# Kerberos AS-REQ from the SSO Extension process (when sub-payload is installed)
kerberos.msg_type == 10

# CLDAP for AD site auto-discovery
cldap && cldap.filter.domain == "corp.example.com"
```

## Cross-platform comparison

- **AD counterpart** — PSSO is the macOS analogue of **Windows Hello for Business** with Entra ID device registration: a hardware-bound key in a TPM (Windows) or SEP (Mac), a device object at the IdP, and a refresh-token-based silent mint. The closest AD-side on-prem counterpart is the AD FS device registration service + Workplace Join, documented in [`../01-ad-core/03-ad-fs-federation.md`](../01-ad-core/03-ad-fs-federation.md). The Kerberos sub-payload produces wire traffic identical to a Windows Kerberos client — see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md).
- **Linux counterpart** — there is no first-party Linux equivalent to PSSO. The closest analogues are `sssd` with `ad` provider for the Kerberos/LDAP side ([`../09-linux-equivalents/01-sssd-ad-provider.md`](../09-linux-equivalents/01-sssd-ad-provider.md)) and the GNOME Online Accounts / `gnome-keyring` token-store for the OAuth side. Systemd's `systemd-homed` with FIDO2 keys is conceptually similar but does not register a device object at an IdP.
- **High-level side-by-side** — [`../10-comparison-matrices/01-feature-os-matrix.md`](../10-comparison-matrices/01-feature-os-matrix.md).

## References

- Apple Developer doc — "Platform SSO" (current through macOS 14 developer library, WWDC22 session 1009 "Meet Platform SSO", WWDC23 session 10291 "Explore the modern Enterprise SSO experience").
- Apple Developer doc — "Authentication Services framework" (`ASAuthorizationProvider`).
- `sso_util` manpage — `man sso_util`.
- `systemextensionsctl` manpage — `man systemextensionsctl`.
- `profiles` manpage — `man profiles`.
- Microsoft Entra ID doc — "Configure Platform SSO for macOS devices in Microsoft Entra ID".
- RFC 6749 / RFC 8252 — OAuth 2.0 and Native Apps (PKCE).
- RFC 4120 / MS-KILE — Kerberos, see [`../02-protocols/01-kerberos-internals.md`](../02-protocols/01-kerberos-internals.md).
- Internal headers — `/System/Library/Frameworks/Security.framework/Headers/Authorization.h` (note: `kAuthorizationCredentialTypeSSO` is in the private `AuthorizationDB.h` on stock installs).
