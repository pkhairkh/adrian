---
title: ADFS OIDC and OAuth 2.0 — Endpoints, Discovery, Application Groups, Scope Mapping, Refresh Tokens, External OIDC IdP
audience: senior-engineers
tags: [ad-fs, oidc, oauth2, jwt, jwks, application-groups, refresh-tokens, msapoc, scope-mapping]
related:
  - ./01-adfs-architecture.md
  - ./02-saml-ws-fed.md
  - ./03-claims-rules.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

ADFS 2016+ exposes an OpenID Connect (OIDC) Provider on `/adfs/oauth2/` with `/authorize`, `/token`, `/userinfo`, `/jwks`, and `/.well-known/openid-configuration` endpoints, supports authorization_code, implicit, hybrid, client_credentials, refresh_token, and (deprecated) resource_owner_password_credentials flows, scopes mapped to AD claims via per-RP issuance transform rules, and groups RP/native-client/web-API bundles as "Application Groups" (Server 2016+) replacing the older per-RP trust model.

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/adfs/oauth2/authorize` | GET / POST | Authorization endpoint (interactive flows) |
| `/adfs/oauth2/token` | POST | Token endpoint (all flows except implicit) |
| `/adfs/oauth2/userinfo` | GET / POST | UserInfo endpoint (OIDC; returns claims for the authenticated user) |
| `/adfs/oauth2/jwks` | GET | JWKS — set of ADFS public signing keys |
| `/adfs/.well-known/openid-configuration` | GET | Discovery document |
| `/adfs/oauth2/logout` | GET | End-session endpoint |
| `/adfs/oauth2/revoke` | POST | Token revocation |
| `/adfs/oauth2/devicecode` | POST | Device code flow (Server 2019+) |
| `/adfs/oauth2/token/device` | POST | Device code token exchange |

Endpoint URLs are advertised in the discovery document and signed with the ADFS token-signing key.

### Discovery document example

```json
{
  "issuer": "https://adfs.corp.example.com/adfs",
  "authorization_endpoint": "https://adfs.corp.example.com/adfs/oauth2/authorize/",
  "token_endpoint": "https://adfs.corp.example.com/adfs/oauth2/token/",
  "userinfo_endpoint": "https://adfs.corp.example.com/adfs/oauth2/userinfo/",
  "jwks_uri": "https://adfs.corp.example.com/adfs/discovery/keys",
  "end_session_endpoint": "https://adfs.corp.example.com/adfs/oauth2/logout",
  "revocation_endpoint": "https://adfs.corp.example.com/adfs/oauth2/revoke",
  "device_authorization_endpoint": "https://adfs.corp.example.com/adfs/oauth2/devicecode",
  "scopes_supported": ["openid","profile","email","allatclaims","winhttpcert","msapoc","vpn_cert"],
  "response_types_supported": ["code","id_token","token","id_token token","code id_token","code token","code id_token token"],
  "response_modes_supported": ["query","fragment","form_post"],
  "grant_types_supported": ["authorization_code","implicit","refresh_token","client_credentials","password","device_code","urn:ietf:params:oauth:grant-type:jwt-bearer"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post","client_secret_basic","private_key_jwt","tls_client_auth"],
  "claims_supported": ["sub","aud","iss","iat","exp","auth_time","nonce","name","email","upn","unique_name","sid"],
  "code_challenge_methods_supported": ["S256","plain"]
}
```

## Supported flows

| Flow | OAuth grant_type | Use case |
|---|---|---|
| Authorization Code | `authorization_code` | Server-side web app (recommended) |
| Implicit | `implicit` | SPA (deprecated in OIDC best practice, but still supported) |
| Hybrid | `code id_token`, `code token`, `code id_token token` | SPA wanting code + nonce in front-channel |
| Client Credentials | `client_credentials` | Server-to-server (no user); client authenticates with secret or cert |
| Refresh Token | `refresh_token` | Renew access token without re-prompting user |
| Resource Owner Password Credentials (ROPC) | `password` | Deprecated; supported but discouraged |
| Device Code | `device_code` | Server 2019+; for IoT / TV / CLI |
| JWT Bearer | `urn:ietf:params:oauth:grant-type:jwt-bearer` | Token exchange (ActAs / OnBehalfOf) |

ADFS enforces PKCE (RFC 7636) on public clients if `UsePkce = $true` is set on the client. S256 is the required code challenge method.

## Scopes

| Scope | Result |
|---|---|
| `openid` | Issues `id_token` JWT; required for OIDC |
| `profile` | Adds `name`, `unique_name`, `sub` claims |
| `email` | Adds `email` claim (from `mail` AD attribute) |
| `allatclaims` | Adds ALL claims the RP's Issuance Transform Rules would emit (full AD claims pass-through) |
| `winhttpcert` | Issues a short-lived certificate (for WinHTTP client cert auth scenarios — Edge / Windows Hello for Business) |
| `msapoc` | Microsoft Account Proof-of-Possession (PoP) — issues a PoP token bound to the client's TLS cert |
| `vpn_cert` | Issues a remote-access VPN client cert (used by Always On VPN integration) |

Custom scope-to-claim mapping: scopes are translated by the ADFS claims pipeline into "claim descriptions" — each scope maps to a set of claim types via `Set-AdfsClaimDescription -Name <scope> -ClaimType <URI>`. When the `allatclaims` scope is not requested, only the `openid`/`profile`/`email` claim types are added.

## Application Groups (Server 2016+)

A new management abstraction that bundles related application registrations:

```
Application Group: "CorpExpenseApp"
  ├── Server Application (web app server-side, has client_secret)
  │     ClientID:        <guid1>
  │     RedirectURI:     https://app.corp.example.com/auth/callback
  │     Secret/Cert:     <confidential>
  │     Allowed Flows:   authorization_code, refresh_token
  ├── Native Client (mobile/desktop app, no secret; PKCE required)
  │     ClientID:        <guid2>
  │     RedirectURI:     ms-appx-web://... or https://...
  │     Allowed Flows:   authorization_code (PKCE), device_code
  └── Web API (resource server; validates JWTs)
        Identifier:      https://api.corp.example.com/
        Audience:        <guid3>
        Allowed Clients: <guid1>, <guid2>
        Per-RP Rules:    Issuance Transform Rules
```

Each component is a separate "Client" in the ADFS OAuth store; the Application Group is just a UI / management grouping. The Web API component replaces the legacy "Relying Party Trust" for OAuth flows — its `Identifier` becomes the JWT `aud` claim.

## JWT token format

ADFS issues JWTs (RFC 7519) signed with RS256 (RSA-SHA256 using the token-signing private key). Header and payload:

```json
// Header
{ "typ": "JWT", "alg": "RS256", "kid": "<key-id>", "x5t": "<cert-thumbprint-b64>" }

// Payload (id_token)
{
  "aud": "<web-api-resource-id>",
  "iss": "https://adfs.corp.example.com/adfs",
  "iat": 1723561931,
  "nbf": 1723561931,
  "exp": 1723565531,
  "sub": "Jq3bT0dSe9KXlX-U6LsrU9b3K5sUXa8Shnj",
  "upn": "jdoe@corp.example.com",
  "unique_name": "CORP\\jdoe",
  "sid": "<session-id>",
  "auth_time": 1723561931,
  "nonce": "<nonce-from-authorize>",
  "amr": ["pwd","wia"],     // auth method references
  "apptype": "Confidential",
  "appid": "<client-id>",
  "ver": "1.0"
}
```

The `kid` header matches a `kid` in the JWKS document; clients fetch JWKS at startup and refresh periodically (default 24 h) or on key-not-found.

ADFS uses an additional claim `apptype` to mark Confidential vs Public clients, and `ver` for token version (1.0 for legacy ADFS, 2.0 not used in ADFS — that's Azure AD).

## Refresh tokens

| Setting | Default | Configurable via |
|---|---|---|
| Sliding lifetime | 8 hours | `Set-AdfsRelyingPartyTrust -TokenLifetime` (and SsoLifetime) |
| Absolute lifetime | 24 hours | `Set-AdfsProperties -SsoLifetime` |
| Sliding refresh enabled | Yes | `Set-AdfsProperties -EnablePersistentSso $true` |
| Single-logout invalidates refresh tokens | Yes | `Set-AdfsProperties -PersistentSsoSsoTokenLifetime` |

When the access token expires, the client POSTs to `/adfs/oauth2/token` with `grant_type=refresh_token&refresh_token=<rt>`; ADFS issues a new access_token (and rotates the refresh_token if `refresh_token_rotation` is enabled — Server 2019+ opt-in).

## External OIDC IdP (ADFS as RP)

ADFS 2019+ can be configured as a Relying Party to an external OIDC IdP (Azure AD, Google, Okta, Keycloak). Steps:

1. `Add-AdfsClaimsProviderTrust` with `-OIDCUrl <external-issuer>/authorize`, `-ClientID <id>`, `-ClientSecret <secret>`, `-MetadataUrl <external-issuer>/.well-known/openid-configuration`
2. ADFS becomes the RP; user selecting this CPT is redirected to the external IdP
3. External IdP issues its own JWT; ADFS validates, extracts claims into the pipeline
4. ADFS re-issues its own JWT/SAML token to the downstream RP

This is the "federation chain" pattern; the external IdP becomes one of multiple CPTs.

## Configuration / code examples

### PowerShell: create an Application Group with server app + native client + web API

```powershell
# 1. Web API (resource)
$api = Add-AdfsWebApiApplication -Name 'CorpExpenseAPI' `
  -Identifier 'https://api.corp.example.com/' `
  -AccessControlPolicyName 'Permit everyone' `
  -IssuanceTransformRules @(
    '@RuleName = "Pass UPN"
     c:[Type == "http://schemas.xmlsoap.org/claims/UPN"]
     => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
              Value = c.Value);'
  )

# 2. Server application (confidential client)
$serverApp = Add-AdfsWebApplication -Name 'CorpExpense-Web' `
  -ApplicationGroupIdentifier 'CorpExpenseApp' `
  -WebApiApplication $api `
  -RedirectUri 'https://app.corp.example.com/auth/callback' `
  -ClientSecret (ConvertTo-SecureString -String '...' -AsPlainText -Force) `
  -AllowedAuthenticationClassReferences @('urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport')

# 3. Native client (public, PKCE)
$native = Add-AdfsNativeClientApplication -Name 'CorpExpense-Mobile' `
  -ApplicationGroupIdentifier 'CorpExpenseApp' `
  -RedirectUri 'ms-appx-web://corp.mobileapp' `
  -WebApiApplication $api

# 4. Enable refresh tokens
Set-AdfsWebApiApplication -TargetName 'CorpExpenseAPI' -IssueOAuthRefreshTokensTo AllDevices
```

### PowerShell: register ADFS as RP to external OIDC IdP (Azure AD)

```powershell
Add-AdfsClaimsProviderTrust -Name 'AzureAD-Corp' `
  -OIDCUrl 'https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize' `
  -ClientID '<azure-ad-app-id>' `
  -ClientSecret (ConvertTo-SecureString '...' -AsPlainText -Force) `
  -MetadataUrl 'https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration' `
  -IssuanceTransformRules @(
    '@RuleName = "Pass through email"
     c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
     => issue(claim = c);'
  )
```

### Python: authorization_code flow against ADFS

```python
import requests, base64, hashlib, secrets, json
from urllib.parse import urlencode, urlparse, parse_qs

CLIENT_ID     = "<server-app-guid>"
CLIENT_SECRET = "<secret>"
REDIRECT_URI  = "https://app.corp.example.com/auth/callback"
ADFS_BASE     = "https://adfs.corp.example.com/adfs"
SCOPE         = "openid profile email allatclaims"
RESOURCE      = "https://api.corp.example.com/"   # Web API identifier (audience)

# --- Step 1: redirect user to /authorize ---
state = secrets.token_urlsafe(16)
nonce = secrets.token_urlsafe(16)
auth_url = f"{ADFS_BASE}/oauth2/authorize?" + urlencode({
    "response_type": "code",
    "client_id":     CLIENT_ID,
    "redirect_uri":  REDIRECT_URI,
    "resource":      RESOURCE,
    "scope":         SCOPE,
    "state":         state,
    "nonce":         nonce,
})
print(f"Open in browser: {auth_url}")

# --- Step 2: exchange code for tokens ---
code = input("Paste 'code' from redirect: ")
token_resp = requests.post(
    f"{ADFS_BASE}/oauth2/token",
    data={
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  REDIRECT_URI,
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    },
    verify="corp-ca-bundle.pem"
)
tokens = token_resp.json()
print(json.dumps(tokens, indent=2))   # access_token, id_token, refresh_token, expires_in

# --- Step 3: validate id_token signature ---
import jwt
jwks = requests.get(f"{ADFS_BASE}/discovery/keys", verify="corp-ca-bundle.pem").json()
header = jwt.get_unverified_header(tokens["id_token"])
key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
id_token = jwt.decode(tokens["id_token"], public_key,
                      algorithms=["RS256"],
                      audience=CLIENT_ID,
                      issuer=ADFS_BASE,
                      options={"verify_nonce": True}, nonce=nonce)
print(json.dumps(id_token, indent=2))

# --- Step 4: call UserInfo ---
ui = requests.get(f"{ADFS_BASE}/oauth2/userinfo",
                  headers={"Authorization": f"Bearer {tokens['access_token']}"},
                  verify="corp-ca-bundle.pem")
print(ui.json())

# --- Step 5: refresh ---
refresh_resp = requests.post(
    f"{ADFS_BASE}/oauth2/token",
    data={
        "grant_type":    "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "resource":      RESOURCE,
    },
    verify="corp-ca-bundle.pem"
)
new_tokens = refresh_resp.json()
print("Refreshed:", new_tokens["access_token"][:20], "...")
```

### Python: client_credentials flow (server-to-server)

```python
import requests, json

resp = requests.post(
    "https://adfs.corp.example.com/adfs/oauth2/token",
    data={
        "grant_type":    "client_credentials",
        "client_id":     "<server-app-guid>",
        "client_secret": "<secret>",
        "resource":      "https://api.corp.example.com/",
    },
    verify="corp-ca-bundle.pem"
)
print(resp.json())   # {"access_token":"<JWT>","token_type":"bearer","expires_in":3600}
```

## Troubleshooting

### Wireshark / network diagnostics

```
# Authorization request (browser → ADFS)
http.request.uri contains "/adfs/oauth2/authorize" and http.request.uri contains "client_id="

# Token endpoint (server app → ADFS)
http.request.uri contains "/adfs/oauth2/token"
http.request.method == "POST" and http.content_type == "application/x-www-form-urlencoded"

# JWKS fetch
http.request.uri contains "/adfs/discovery/keys" or http.request.uri contains "/adfs/oauth2/jwks"

# Discovery
http.request.uri contains ".well-known/openid-configuration"

# Refresh token issuance
http.file_data contains "refresh_token" and http.file_data contains "grant_type=refresh_token"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `invalid_grant` on token exchange | `redirect_uri` mismatch between /authorize and /token | Must be byte-identical (incl. trailing slash, query string) |
| `invalid_client` | Wrong client_secret or client cert | `Set-AdfsWebApplication -TargetName <name> -ClientSecret (ConvertTo-SecureString ...) ` |
| `AADSTS50120 — Invalid JWT signature` (downstream RP) | RP using stale JWKS | RP refreshes JWKS at 24h; force refresh or extend TTL |
| `Unauthorized audience` | `resource=` not provided, or value doesn't match Web API `Identifier` | `resource=https://api.corp.example.com/` (exact match) |
| `AADSTS70000 — Invalid refresh token` | Refresh token expired (24h absolute lifetime by default) | `Set-AdfsProperties -SsoLifetime 168` for 7-day sliding |
| `MSIS9648 — The scope 'allatclaims' is not allowed` | Scope not enabled on RP / web API | `Set-AdfsWebApiApplication -TargetName <name> -AlwaysRequireAuthentication $false -IssueOAuthRefreshTokensTo AllDevices` and verify claim descriptions |
| `redirect_uri_mismatch` | URI registered with extra `/` or different scheme | Compare `Get-AdfsWebApplication | Select -Expand RedirectUri` against what client sent |
| `invalid_pkce_verifier` | PKCE verifier doesn't match challenge | Use S256 only; re-generate verifier per request |
| `unsupported_grant_type` | ROPC disabled by policy | `Set-AdfsAdditionalAuthenticationRule` to allow password grant, or migrate to authorization_code |
| Token signing cert rolled over, clients failing | JWKS still cached old `kid` | ADFS publishes both old + new keys during rollover window (15 days); client should refresh JWKS on key-not-found |

### Diagnostic commands

```
Get-AdfsApplicationGroup | Format-List Name, Id, ApplicationGroupIdentifier
Get-AdfsWebApplication | Format-List Name, ClientId, RedirectUri, AllowedAuthenticationClassReferences
Get-AdfsNativeClientApplication | Format-List Name, ClientId, RedirectUri
Get-AdfsWebApiApplication | Format-List Name, Identifier, TokenLifetime, AllowedClientTypes
Get-AdfsClient | Format-List Name, ClientId, RedirectUri
Get-AdfsClaimsProviderTrust | Where OIDCUrl -ne $null

# Discovery + JWKS via curl
curl -sk https://adfs.corp.example.com/adfs/.well-known/openid-configuration | jq .
curl -sk https://adfs.corp.example.com/adfs/discovery/keys | jq '.keys[].kid'

# Decode a JWT (offline)
echo "<jwt>" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

### Diagnostic event logs

```
AD FS/Admin             — operational events
AD FS/Tracing           — verbose per-request traces
AD FS Auditing          — logon audit (token issuance events)
```

## Cross-platform equivalents

| ADFS OIDC feature | macOS | Linux |
|---|---|---|
| OIDC Provider | (no native) | Keycloak OIDC provider (full support); mod_auth_openidc (Apache) for RP-only |
| OAuth client (public/confidential) | Apps use AppAuth or ASWebAuthenticationSession; MDM may install client certs — see `../08-macos-equivalents/04-platform-sso-extension.md` | Any OIDC client library; Keycloak client adapters (Java/Node/Python) |
| Application Groups | (no native equivalent; app-group concept is iOS/macOS app groups for shared keychain — different) | Keycloak realm + client grouping |
| External OIDC IdP federation | (no native — apps implement per-provider) | Keycloak Identity Brokering (OIDC / SAML / social) |
| Refresh token rotation | (limited) | Keycloak refresh token rotation (offline session idle + max) |

Linux has no native SAML/OIDC client. Common stacks:
- Keycloak (RH SSO): full OIDC provider + IdP brokering + JWT issuance
- mod_auth_openidc (Apache): RP-only OIDC; reads ADFS discovery doc automatically
- nginx-plus-auth-idp: commercial OIDC RP
- For Kerberos-only flows, SSSD is sufficient — see `../09-linux-equivalents/01-sssd-ad-provider.md`

For macOS, PSSO supports OIDC via the Enterprise SSO extension (limited); most macOS OIDC RP implementations are in-app or via ASWebAuthenticationSession — see `../08-macos-equivalents/04-platform-sso-extension.md` and `../08-macos-equivalents/03-jamf-connect-pro.md`.

## References

- RFC 6749 — OAuth 2.0 Authorization Framework
- RFC 7519 — JSON Web Token (JWT)
- RFC 7515 — JSON Web Signature (JWS)
- RFC 7517 — JSON Web Key (JWK)
- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 8252 — OAuth 2.0 for Native Apps (PKCE)
- OpenID Connect Core 1.0 — `https://openid.net/specs/openid-connect-core-1_0.html`
- OpenID Connect Discovery 1.0
- MS-ADFS — AD FS Protocols (`https://learn.microsoft.com/openspecs/windows_protocols/ms-adfs`)
- MS-OAPX — OAuth 2.0 Protocol Extensions
- `System.IdentityModel.Tokens.Jwt.dll` — JWT encode/decode (open-source)
- `Microsoft.IdentityServer.dll!Microsoft.IdentityServer.Web.Protocols.OAuth` (ADFS OAuth handler)
- `https://learn.microsoft.com/windows-server/identity/ad-fs/overview/ad-fs-scenarios-for-developers`
- `https://learn.microsoft.com/windows-server/identity/ad-fs/operations/access-control-policies-in-ad-fs`
