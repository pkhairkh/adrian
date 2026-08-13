---
title: AD FS — Federation Service Internals (ServiceHost, claim pipeline, MS-ADFSPIP)
audience: senior-engineers
tags: [ad-fs, federation, claims, servicehost, wid, ms-adfspip, saml, ws-federation, openid-connect]
related:
  - ./01-ad-ds-internals.md
  - ./02-ad-cs-cert-services.md
  - ../02-protocols/01-kerberos-internals.md
  - ../02-protocols/04-ntlm-internals.md
  - ../06-federation-sso/02-saml-ws-fed.md
last_updated: 2026-08-13
---

AD FS is a Windows service that hosts a Security Token Service (STS) inside `Microsoft.IdentityServer.Servicehost.exe`, persisting configuration in either a Windows Internal Database (WID) instance or a SQL Server database, and issuing SAML 2.0, WS-Federation, and OpenID Connect / OAuth2 tokens via the Microsoft.IdentityModel.Claims protocol pipeline: Claims Provider Trust (CPT) → Acceptance Transform Rules → Relying Party Trust (RPT) Issuance Authorization → RPT Issuance Transform → token serialization. Web Application Proxy (WAP) on the perimeter publishes endpoints via MS-ADFSPIP.

## Architecture

### Process model

```
services.msc: "Active Directory Federation Services" (adfssrv)
 ├── process: %SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\Microsoft.IdentityServer.ServiceHost.exe
 │    │           (a topshelf WCF service host wrapping System.ServiceModel.ServiceHost)
 │    ├── Microsoft.IdentityServer.dll                (core: STS pipeline, claim evaluation)
 │    ├── Microsoft.IdentityServer.Compression.dll    (deflate for SAML artifacts)
 │    ├── Microsoft.IdentityServer.Requestor.dll      (front-door HTTP listener)
 │    ├── Microsoft.IdentityServer.PolicyModel.dll    (CRUD on the config DB)
 │    ├── Microsoft.IdentityServer.PassiveClient.dll  (passive (browser) profile)
 │    ├── Microsoft.IdentityServer.ServiceCore.dll    (service host, perf counters)
 │    ├── Microsoft.IdentityModel.Clients.ActiveDirectory.dll  (ADAL — legacy client)
 │    ├── MSXML6.dll                                  (XML canonicalization for SAML)
 │    └── System.IdentityModel.Tokens.Jwt.dll         (JWT encoder/decoder)
 │
 ├── service account: <DOMAIN>\adfssvc  (managed service account or gMSA recommended)
 ├── SPN: HOST/<adfs-svc-fqdn>   ← MUST be set on the service account; KDC uses it for the STS's
 │        intranet Kerberos auth (clients authenticate to adfs-svc via Negotiate).
 ├── Service dependencies: HTTP (HTTP.SYS), NetTcpPortSharing, RpcSs, Cryptographic Services
 ├── HTTP.SYS URL reservations (run `netsh http show urlacl`):
 │       https://+:443/FederationMetadata/2007-06/
 │       https://+:443/adfs/
 │       https://+:443/adfs/services/
 │       net.tcp:1501/adfs/services/trust/         (WCF metadata, optional)
 └── Self-signed or AD CS-issued TLS cert (CN=adfs.example.com) bound to 0.0.0.0:443 with SNI
```

The service uses `HTTP.SYS` kernel-mode listener (shared with IIS — but AD FS Server 2012 R2+ does NOT require IIS on the same host). TLS termination happens in HTTP.SYS. The `ServiceHost.exe` process is 64-bit, targets .NET Framework 4.x (not .NET Core).

### Topology

| Mode | Config DB | Multi-server sync | Notes |
|---|---|---|---|
| Standalone (single node) | WID | — | Dev / POC only. |
| WID farm | WID, primary DC-style | Primary-Node replication to secondaries (pull model) | Up to 5 servers. Admin cmdlets must hit the primary node. |
| SQL farm | SQL Server | Synchronous via SQL (you pick sync level) | Any number of nodes. Adds HA at the SQL tier. |
| SAML artifact DB | WID (default) / SQL | — | Stores artifact resolution state. |

WID is the same `sqlservr.exe` binary used by WSUS, but a dedicated instance named `\\.\pipe\MICROSOFT##WID\tsql\query`. The AD FS databases are `AdfsConfiguration` and `AdfsArtifactStore`. Their schema is owned by Microsoft; do not modify directly. All writes go through the Microsoft.IdentityServer.PowerShell snap-in, which calls `Microsoft.IdentityServer.PolicyModel.dll!PolicyStore.GetSetUpdate`.

### Config DB tables (selected)

| Table | Key columns | Notes |
|---|---|---|
| `IdentityServerPolicy.ServiceHostSettings` | HostName, ServiceHostName, Id | Top-level service config. |
| `IdentityServerPolicy.CertificateStoreItems` | Id, CertificateBlob, IsPrimary, Use | Token-signing and token-decrypting certs. |
| `IdentityServerPolicy.ClaimSet` | Id, Name | Wraps a list of claims (input or output). |
| `IdentityServerPolicy.TrustGroupEntry` | Uri, TrustRole | One row per Claims Provider Trust or Relying Party Trust. |
| `IdentityServerPolicy.RelyingPartyTrusts` | Id, Identifier, Name, AllowedAuthenticationClassReferences | One row per RP. |
| `IdentityServerPolicy.RelyingPartyClaimDescriptions` | RelyingPartyTrustId, ClaimType | Claims expected by the RP. |
| `IdentityServerPolicy.IssuanceTransformRules` | RelyingPartyTrustId, RuleXml | Issuance Transform rule list (XML serialized). |
| `IdentityServerPolicy.Endpoints` | Address, BindingType, SecurityMode | One row per federation endpoint. |
| `AdfsArtifactStore.ArtifactEntry` | ArtifactId, ResultData, ExpiresAt | Artifact resolution (SAML artifact profile). |
| `AdfsArtifactStore.DeviceRegistration` | DeviceId, DeviceCertificate, UserPrincipalName | Workplace Join / Azure AD-joined devices. |

## Trust pipeline

### Phase 1 — Claims Provider Trust (CPT)

The incoming identity, no matter the protocol, enters the pipeline as a `ClaimsIdentity` from one of:

- AD DS via Kerberos / NTLM (the default intranet CPT — `Active Directory`).
- External CPT — SAML 2.0 IdP, WS-Federation IdP, or another AD FS farm.
- LDAP attribute store (custom — `Add-ADFSAttributeStore`).
- Custom claims provider (rare; requires implementing `IClaimsProvider`).

The CPT's Acceptance Transform rules map the inbound identity's claim set to the farm's normalized claim set (the "claim type schema"). E.g., `c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"] => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", Value = c.Value);`

### Phase 2 — RPT selection

Match against the `Identifier` (an array of URIs — typically the RP's WTrealm or SAML Audience). If multiple RPTs match, AD FS picks the most specific; if none, HTTP 503.13.

### Phase 3 — RPT Issuance Authorization Rules

Decision: `Permit` or `Deny`. Evaluated in order; first matching Permit (no preceding Deny) grants access. Default rule: `=> Permit(Value = "Permit", ...)` for all authenticated users. Common patterns:

- `exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-12345-...-1107"]) => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "Permit");`
- `c:[Type == "http://schemas.auth0.com/..."] => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "Deny");`

### Phase 4 — RPT Issuance Transform Rules

Build the outbound claim set that goes into the token. Common patterns:

- Pass through UPN: `c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"] => issue(claim = c);`
- Map group → role: `c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-12345-1108"] => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "Admin");`
- Custom attribute store lookup: `c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"] => issue(store = "SqlAttributeStore", types = ("role"), query = "SELECT role FROM users WHERE name = {0}", param = c.Value);`

### Phase 5 — Token serialization

Per protocol:

| Protocol | Token format | Endpoint |
|---|---|---|
| WS-Federation passive | SAML 1.1 assertion, base64 in `wresult` POST | `/adfs/ls/` |
| SAML 2.0 passive | SAML 2.0 Response, signed SAML 2.0 assertion | `/adfs/ls/` |
| SAML 2.0 active (SOAP) | SAML 2.0 over SOAP 1.1 (`RequestSecurityToken`) | `/adfs/services/trust/2005/.../` |
| OAuth2 / OIDC | JWT (signed, optional encrypted) | `/adfs/oauth2/authorize`, `/adfs/oauth2/token` |
| WS-Trust | SAML 1.1 / 2.0 inside `RequestSecurityTokenResponse` | `/adfs/services/trust/13/.../` |

Token signing uses the farm's token-signing cert (RSA-2048+ by default, SHA-256). The cert's private key is held in the local machine certificate store (`Cert:\LocalMachine\My`); the cert (with public key) is published to the federation metadata endpoint at `/FederationMetadata/2007-06/FederationMetadata.xml`.

### Service account and SPN

The AD FS service account (`<DOMAIN>\adfssvc`) must own an SPN `HOST/<adfs-fqdn>`. When a client browser hits the intranet endpoint with Windows Integrated Auth, HTTP.SYS performs a `Negotiate` challenge → Kerberos. The browser requests a service ticket for `HTTP/<adfs-fqdn>` (HTTP/ is added by default by HTTP.SYS, even though the literal SPN is HOST/). Set with:

```powershell
Set-ADUser -Identity adfssvc -ServicePrincipalNames @{Add="HOST/adfs.example.com"}
# Optionally HTTP/ as well — Kerberos will try HTTP/ first because the browser prepends it
Set-ADUser -Identity adfssvc -ServicePrincipalNames @{Add="HTTP/adfs.example.com"}
```

A common failure mode: farm servers in a Network Load Balancing cluster, all using the same `adfssvc` account, but only one SPN set. Detection: `setspn -L adfssvc` shows the SPN, but `setspn -X` finds a duplicate because it is also on a computer account for the NLB virtual name.

## Web Application Proxy (WAP) and MS-ADFSPIP

WAP is the perimeter service (`WAPService` running inside `wsaprovhost.exe`) that publishes AD FS endpoints to the internet without exposing the corporate AD FS farm directly. It also publishes HTTP applications (pass-through, pre-auth via AD FS).

MS-ADFSPIP — AD FS Proxy Implementation Protocol. The WAP↔ADFS RPC contract includes:

1. **`GetFederationMetadata`** — WAP fetches the metadata XML from the AD FS farm on first connection.
2. **`GetProxyTrustConfiguration`** — AD FS provides the proxy trust cert (a self-signed cert the WAP uses to authenticate itself to ADFS).
3. **`EstablishProxyTrust`** — WAP presents its cert, AD FS registers it as a trusted proxy. Subsequent requests from the WAP carry an extra HTTP header `X-Proxy-Trust` (signed JWT, signed by the WAP proxy-trust cert).
4. **`RequestToken`** — pass-through for passive SAML requests.
5. **`ReissueProxyTrustCertificate`** — rotate the proxy trust cert.

The trust relationship is asymmetric: AD FS does not trust incoming user requests from the WAP directly; it trusts the WAP-as-a-proxy to have authenticated the user (via forms auth on the WAP itself, or via the pre-auth flow).

Registry under WAP host:
```
HKLM\SOFTWARE\Microsoft\AdfsProxy
 ├── ProxyTrustCertificate     (REG_BINARY, the proxy trust cert with private key)
 ├── FederationServiceName     (REG_SZ, e.g. adfs.example.com)
 ├── FederationServiceUrl      (REG_SZ)
 └── ProxyConfigurationRefreshInterval (REG_DWORD, seconds)
```

## Configuration / code examples

### Wireshark filter — SAML passive flow

```
http.request.uri contains "/adfs/ls/" && http.request.method == "POST"
# JWT issuance
http.request.uri contains "/adfs/oauth2/token" && http.request.method == "POST"
# Federation metadata
http.request.uri contains "FederationMetadata"
# WAP → AD FS proxy trust RPC
dcerpc.if_id == aeff122d-5335-11d4-9b40-00c04f8835ac   # the MS-ADFSPIP interface UUID
```

### PowerShell — list relying parties and their issuance rules

```powershell
# Show all RPTs and key properties
Get-AdfsRelyingPartyTrust | Format-Table Name, Identifier, TokenLifetime, Enabled -AutoSize

# Dump the Issuance Transform rules of a specific RP
(Get-AdfsRelyingPartyTrust -Name "SharePoint-Claims").IssuanceTransformRules

# Add a custom claim rule (LDAP lookup)
$rule = @'
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]
 => issue(store = "Active Directory",
          types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"),
          query = ";mail,sn;{0}", param = c.Value);
'@
Set-AdfsRelyingPartyTrust -TargetName "SharePoint-Claims" -IssuanceTransformRules $rule

# Rotate token-signing cert (auto-cert rollover — but you can also force it)
Update-AdfsCertificate -CertificateType Token-Signing -Urgent
```

### Python — validate a JWT issued by AD FS

```python
import jwt
from jwt import PyJWKClient
import requests

# Pull federation metadata → JWKS URL
metadata = requests.get("https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml",
                        verify=True).text
# AD FS exposes a /adfs/discovery/keys endpoint containing signing keys as JWK
jwks_client = PyJWKClient("https://adfs.example.com/adfs/discovery/keys")
signing_key = jwks_client.get_signing_key_from_jwt(token)

claims = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience="microsoft:identityserver:SharePoint-Claims",
    issuer="https://adfs.example.com/adfs",
    options={"require": ["exp", "iat", "iss", "aud", "sub"]},
)
print(claims["upn"], claims.get("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"))
```

### PowerShell — register a custom attribute store (SQL)

```powershell
Add-AdfsAttributeStore -Name "SqlAttributeStore" -StoreType "SQL" `
    -Configuration @{"Connection" = "Server=sql01;Database=IdStore;Integrated Security=True"}
# Reference from a rule:
#   issue(store = "SqlAttributeStore", types = ("role"),
#         query = "SELECT role FROM users WHERE upn = {0}", param = c.Value);
```

## Troubleshooting

- **Event 364 — "MSIS10001" / Federation Service could not process the request** — typically a token-signing cert mismatch. The RP has cached an old cert. Fix: re-pull federation metadata on the RP side. Diagnostic: `Get-AdfsCertificate -CertificateType Token-Signing`.
- **MSIS8014 — Duplicate SPN** — run `setspn -X` across the forest. The `HOST/<adfs-fqdn>` SPN should be on the AD FS service account exactly once.
- **MSIS7065 — "The SAML authentication request was rejected because the protocol binding is not supported."** — typically SAML 2.0 POST binding sent to the `/adfs/ls/` (passive) endpoint. Check the SP's `ProtocolBinding` attribute.
- **Infinite loop after sign-in** — usually missing Audience URI in the RPT. Add the WTRealm as `Identifier` and the SP's `Audience` value to `SAMLEndpoint` collection: `Set-AdfsRelyingPartyTrust -TargetName X -SamlEndpoint @{...}`.
- **No claims in token** — Issuance Transform rules did not match any inbound claim. Enable AD FS debug logging: `Set-AdfsProperties -LogLevel Information,Verbose,Errors,Warnings` and watch event 1000 series in the AD FS Admin log.
- **WAP trust lost after ADFS cert rotation** — on each WAP host, run `Install-WebApplicationProxy -CertificateThumbprint <tls-cert> -FederationServiceName adfs.example.com` again. The MS-ADFSPIP `EstablishProxyTrust` re-stamps the proxy trust cert.

## Cross-platform equivalents

- **Linux**: Shibboleth IdP (Java, runs under Tomcat / Jetty) — full SAML 2.0 IdP, no WS-* support, no built-in claim-pipeline DSL but uses attribute-filter.xml and attribute-resolver.xml. Keycloak (Java, WildFly) — supports SAML 2.0, OIDC, OAuth2, WS-Federation (passive only). See `../09-linux-equivalents/05-keycloak-saml.md` (when present).
- **Linux**: mod_auth_openidc (Apache / NGINX module) for relying-party side against AD FS. See `../09-linux-equivalents/01-sssd-ad-provider.md` for client-side Kerberos integration.
- **macOS**: Apple Platform SSO (the SSO Extension profile payload) — supports OIDC, SAML, Kerberos. AD FS as an OIDC IdP is the typical macOS integration. See `../08-macos-equivalents/04-platform-sso-extension.md`.
- **macOS**: Safari's native SAML passive via the SSO extension. Pre-13.0 macOS required Safari to handle SAML POST itself; with Platform SSO, the extension intercepts.

## References

- MS-ADFSPIP — AD FS Proxy Implementation Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-adfspip>
- MS-OAPX — OAuth 2.0 Protocol Extensions. <https://learn.microsoft.com/openspecs/windows_protocols/ms-oapx>
- MS-OIDC — OpenID Connect 1.0 profile on AD FS.
- AD FS Architecture, MS Learn. <https://learn.microsoft.com/windows-server/identity/ad-fs/ad-fs-architecture>
- SAML 2.0 Core — RFC 6244 family of OASIS specs.
- WS-Federation 1.2 — OASIS standard.
- OpenID Connect Core 1.0 — openid.net/specs.
