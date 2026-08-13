---
title: AD FS Architecture — Microsoft.IdentityServer.ServiceHost.exe, WID vs SQL Config DB, Service Account SPN, Token-Signing/Decryption Certs, WAP
audience: senior-engineers
tags: [ad-fs, federation, identityserver-servicehost, wid, mssql, ms-adfspip, wap, token-signing-cert]
related:
  - ./02-saml-ws-fed.md
  - ./03-claims-rules.md
  - ./04-oidc-oauth.md
  - ../01-ad-core/03-ad-fs-federation.md
  - ../02-protocols/01-kerberos-internals.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

AD FS runs as `Microsoft.IdentityServer.ServiceHost.exe` (a WCF service host) reading its configuration from either a Windows Internal Database (`microsoft.identityserver.mdf` in `%SystemRoot%\Windows\WID\Data\`) or a SQL Server instance, exposing WS-Federation/SAML/OIDC endpoints on `/adfs/ls/`, `/adfs/services/trust/`, `/adfs/oauth2/`, and fronted by Web Application Proxy (`WAPService.exe` under `svchost -k WAPServiceSvchost`) which performs MS-ADFSPIP-based pre-authentication for external clients.

## Architecture

### Process model

```
services.msc: Active Directory Federation Services (ADFSSrv)
  ImagePath   : C:\Program Files\Active Directory Federation Services\Microsoft.IdentityServer.ServiceHost.exe
  ServiceType : 0x10 (OWN_PROCESS)
  StartType   : Automatic
  ObjectName  : <domain>\adfs-svc$ (the ADFS service account, gMSA or regular)
  Dependencies: HTTP, RPCSS, SamSS, CryptSvc

Microsoft.IdentityServer.ServiceHost.exe  (single instance)
  Microsoft.IdentityServer.dll           core policy engine
  Microsoft.IdentityServer.Compression.dll  token serialization
  Microsoft.IdentityServer.RequestCoordinator.dll  HTTP pipeline
  Microsoft.IdentityServer.ServiceHost.exe.config  WCF bindings
  System.IdentityModel.Tokens.Jwt.dll    JWT issuance for OIDC
  Microsoft.IdentityModel.Tokens.dll
  System.IdentityModel.Services.dll      WsFederation passive module
```

The service is a self-hosted WCF service that registers itself with `HTTP.SYS` for kernel-mode HTTP request routing (URL ACLs: `https://+:443/adfs/`, `http://+:80/adfs/`).

### Service account

| Property | Value | Notes |
|---|---|---|
| Format | Domain account or gMSA (`<domain>\adfs-svc$`) | gMSA recommended (Server 2012+) — password managed by KDC, no operator password knowledge |
| SPN | `HOST/<adfs-svc-fqdn>` (e.g., `HOST/adfs.corp.example.com`) | Required for Kerberos on intranet access; ADFS install registers automatically |
| Group membership | Domain Admins (install only, then removed); local Administrators on each ADFS node; backup operators on WID host (for snapshot) | Service account does NOT need Domain Admin at runtime |
| Logon right | `Logon as a service` (auto-granted) | |
| Additional | `Generate security audits` (for ADFS audit log) | |

The SPN must be on the ADFS service account, NOT on a machine account. The federation service name (FQDN such as `adfs.corp.example.com`) must NOT also be a machine name in DNS — the ADFS proxy/server nodes use distinct host names (e.g., `adfs01.corp.example.com`) but the federation service identifier published in metadata is `adfs.corp.example.com`.

### Configuration database

| Deployment | DB | Connection string | Use case |
|---|---|---|---|
| WID (default) | Windows Internal Database (WYukon / SQL Server Express fork) | `Data Source=np:\\.\pipe\MICROSOFT##WID\tsql\query;Initial Catalog=MicrosoftIdentityServer` | <5 nodes, single-primary write model |
| SQL Server | External SQL | `Data Source=<sql>;Initial Catalog=AdfsConfiguration;Integrated Security=SSPI` | 5+ nodes, multi-primary writes, disaster recovery across sites |

WID file paths:
```
%SystemRoot%\Windows\WID\Data\
  microsoft.identityserver.mdf    (config DB; ~50-200 MB typical)
  microsoft.identityserver_log.ldf
```

### Config DB tables (key)

| Table | Purpose |
|---|---|
| `ServiceSettings` | One row: federation service name, signing/encryption cert thumbprints, audit flags, host name |
| `RelyingPartyTrust` | One row per RP: identifiers, rules, claim descriptions, signing cert hash, encryption cert hash, token lifetime, endpoints |
| `ClaimsProviderTrust` | One row per CPT: typically only the AD CPT; includes AD forest DNS, domain controllers list |
| `ArtifactStore` | SAML artifact resolution store (for HTTP-Artifact binding) |
| `IdentityServerPolicy` | Policy descriptions, claim descriptions, custom attribute store registrations |

All tables are accessible via SQL Server Management Studio connecting to `\\.\pipe\MICROSOFT##WID\tsql\query` with Windows auth as the ADFS service account (or local admin on the WID host). ADFS reads these tables at service start into `Microsoft.IdentityServer.PolicyStorage.PolicyServer` in-memory cache; changes via PowerShell (`Set-AdfsRelyingPartyTrust`) flush to DB then invalidate the cache.

### DC communication

The ADFS service account authenticates end users via LDAP against AD DCs. Two paths:
- **Intranet** — Windows Integrated (Kerberos / NTLM) on the `/adfs/ls/` endpoint, with `WindowsIntegratedAuthentication = $true` (the default).
- **Extranet** — form-based or basic auth (no Kerberos).

The Claims Provider Trust for AD is a built-in non-removable trust; the ADFS service account reads the local forest DNS to find DCs (`DsGetDcName` with `DS_DIRECTORY_SERVICE_REQUIRED`). LDAP queries run under the service account context; the bind is via SSPI Negotiate (Kerberos preferred).

For LDAPS (rare in ADFS), set `Set-AdfsDomainController -DomainController <fqdn> -LdapPort 636`. Otherwise plain LDAP/TCP/389.

### Certificates

| Cert | Subject / SAN | Source | Stored |
|---|---|---|---|
| SSL (Service Communications) | `adfs.corp.example.com` (SAN includes this name) | Enterprise PKI (recommended) or public CA | `LocalMachine\My` store |
| Token-signing | Self-signed by default; can be enterprise CA-issued | Auto-generated at install (self-signed 1 year) | `LocalMachine\My` + ADFS DB (thumbprint) |
| Token-decryption | Self-signed by default | Auto-generated at install | `LocalMachine\My` + ADFS DB |
| Federation metadata signing | Same key as token-signing | Automatic | Same cert |
| OCSP signing (if CRL checking enabled) | EKU OCSPSigning | Auto-enrolled | `LocalMachine\My` |

Token-signing cert is auto-published to AD via the ADFS service: `CN=<ADFS-FS-Name>,CN=Program Data,CN=ADFS,CN=Microsoft,CN=Program Data,DC=...` (a `contact` object with `servicePrincipalName` and `userCertificate` attributes), so domain-joined clients can validate ADFS-issued tokens without prior trust config.

Token-signing cert rollover: ADFS supports automatic rollover (Server 2012 R2+) — the new cert is published alongside the old for 5-15 days before being promoted to primary, allowing RPs to refresh their metadata.

## Endpoints

| Path | Protocol | Purpose |
|---|---|---|
| `/adfs/ls/` | WS-Federation passive, SAML 2.0 passive | Browser SSO redirect target |
| `/adfs/ls/idpinitiatedsignon.aspx` | HTML | IdP-initiated SSO page (disabled by default since Server 2016) |
| `/adfs/services/trust/` | WS-Trust active | SOAP token issuance (active clients — Office, ADFS-aware apps) |
| `/adfs/services/trust/2005/usernamemixed` | WS-Trust 2005 (username) | Active client auth via username/password |
| `/adfs/services/trust/13/usernamemixed` | WS-Trust 1.3 | Same, WS-Trust 1.3 envelope |
| `/adfs/services/trust/2005/windowstransport` | WS-Trust 2005 (Windows) | Kerberos/NTLM active |
| `/adfs/services/trust/13/certificatemixed` | WS-Trust 1.3 (cert) | Mutual TLS client cert auth |
| `/adfs/oauth2/authorize` | OAuth 2.0 | Authorization endpoint |
| `/adfs/oauth2/token` | OAuth 2.0 | Token endpoint |
| `/adfs/oauth2/userinfo` | OAuth 2.0 | UserInfo endpoint (OIDC) |
| `/adfs/oauth2/jwks` | OIDC | JWKS (public keys) |
| `/adfs/.well-known/openid-configuration` | OIDC | Discovery document |
| `/FederationMetadata/2007-06/FederationMetadata.xml` | SAML / WS-Fed | Federation metadata (XML signed with token-signing key) |
| `/adfs/ls/?client_request_id=...` | SAML | SAML SSO endpoint (with idp-initiated support) |
| `/adfs/services/trust/saml/sso` | SAML 2.0 | SAML SSO POST/Redirect target |
| `/adfs/ls/saml/logout` | SAML | Single logout endpoint |

Endpoint state can be `Enabled` / `Disabled` and `Proxy Enabled` / `Proxy Disabled` (whether WAP exposes it).

## Web Application Proxy

```
services.msc: Web Application Proxy (WAPService)
  ImagePath   : %SystemRoot%\System32\svchost.exe -k WAPServiceSvchost
  ServiceDll  : %SystemRoot%\System32\WAPService.dll
  ObjectName  : NT AUTHORITY\NetworkService
  Dependencies: HTTP, RPCSS, CryptSvc

WAPService.dll  (proxy service)
  WspRpcClient.dll            (proxy <-> ADFS RPC client: MS-ADFSPIP)
  WebApplicationProxy.exe     (admin CLI)
```

WAP registers HTTP URL ACLs for each published application (`https://+:443/<app-path>/`). For pre-authenticated apps, WAP redirects to `/adfs/ls/` on the ADFS server, captures the issued token, validates the signature using the ADFS token-signing cert, then re-encrypts and forwards to the backend over HTTP/HTTPS.

### MS-ADFSPIP

MS-ADFSPIP is the RPC protocol between WAP and ADFS, used for:
1. `EstablishProxyTrust` — at install, WAP establishes trust with ADFS; ADFS issues a client cert to WAP stored in `LocalMachine\My` with subject `ADFS Proxy Trust - <WAP-Hostname>`. This cert is used for mutual TLS on subsequent RPC calls.
2. `GetConfiguration` — pulls published applications and ADFS endpoints list.
3. `GetWebProxyToken` — exchanges the proxy trust cert for a per-request access token.
4. `StoreRelayState` / `RetrieveRelayState` — for OAuth/SAML flows that need server-side relay state.

RPC interface UUID: `e9396806-0e29-4660-b661-f6345c4bcd36` (MS-ADFSPIP).

## Configuration / code examples

### PowerShell: create a 3-node ADFS farm with WID

```powershell
# On node 1 — create config + primary
$cred = Get-Credential  # adfs-svc account creds
$firstNodeParams = @{
  ServiceCredential             = $cred
  FederationServiceName         = 'adfs.corp.example.com'
  FederationServiceDisplayName  = 'Corp ADFS'
  CertificateType               = 'SSL'
  PrimaryComputer               = 'adfs01.corp.example.com'
  PrimaryComputerPort           = 80
  SSLSubject                    = 'CN=adfs.corp.example.com'
  SigningCertificateThumbprint  = '<sha1 thumb>'   # optional; auto-generated if omitted
  DecryptionCertificateThumbprint = '<sha1 thumb>' # optional
  AdminConfiguration            = $true
}
Install-AdfsFarm @firstNodeParams

# On nodes 2 and 3 — join farm
$joinParams = @{
  ServiceCredential   = $cred
  PrimaryComputer     = 'adfs01.corp.example.com'
  PrimaryComputerPort = 80
  CertificateType     = 'SSL'
}
Add-AdfsFarmNode @joinParams

# Verify SPN
setspn -L corp\adfs-svc
# Should include: HOST/adfs.corp.example.com
```

### PowerShell: list endpoints, RP trusts, and signing cert

```powershell
Get-AdfsEndpoint | Where-Enabled | Format-Table AddressPath, Protocol, Proxy
Get-AdfsRelyingPartyTrust | Format-Table Name, Identifier, TokenLifetime
Get-AdfsCertificate -CertificateType TokenSigning | Format-List Thumbprint, IsPrimary, NotAfter
Get-AdfsCertificate -CertificateType TokenDecryption
Get-AdfsCertificate -CertificateType ServiceCommunications

# ADFS service account info
$adfs = Get-CimInstance -ClassName Win32_Service -Filter "Name='ADFSSRV'"
$adfs.StartName
```

### SQL: query WID directly for all RPs and their rule text

```sql
-- Connect to \\.\pipe\MICROSOFT##WID\tsql\query as <domain>\adfs-svc or local admin
USE MicrosoftIdentityServer;
GO

SELECT rp.Name,
       rp.Identifier,
       rp.TokenLifetime,
       rp.IssuanceTransformRules,
       rp.IssuanceAuthorizationRules,
       rp.AcceptanceTransformRules,
       rp.AutoUpdateEnabled
  FROM RelyingPartyTrust rp;

SELECT s.SettingID, s.SerializedValue
  FROM ServiceSettings s;   -- Token-signing / encryption cert thumbprints
```

### Python: fetch and parse federation metadata

```python
import requests, xml.etree.ElementTree as ET, base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

md = requests.get('https://adfs.corp.example.com/FederationMetadata/2007-06/FederationMetadata.xml', verify=True).content
root = ET.fromstring(md)

ns = {
    'md':'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds':'http://www.w3.org/2000/09/xmldsig#',
}
# EntityDescriptor -> RoleDescriptor -> KeyDescriptor (signing)
for kd in root.findall('.//md:IDPSSODescriptor/md:KeyDescriptor', ns):
    use = kd.get('use')   # 'signing' or 'encryption'
    cert_b64 = kd.find('ds:KeyInfo/ds:X509Data/ds:X509Certificate', ns).text
    cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
    print(use, cert.subject.rfc4514_string(), cert.fingerprint(hashes.SHA256()).hex())
```

## Troubleshooting

### Wireshark / network diagnostics

```
# ADFS passive SSO browser redirect
http.host == "adfs.corp.example.com" and (http.request.uri contains "/adfs/ls/" or
                                          http.request.uri contains "wa=wsignin1.0" or
                                          http.request.uri contains "wa=wsignout1.0")

# SAML POST (form-encoded SAMLRequest / SAMLResponse)
http.request.method == "POST" and http.content_type == "application/x-www-form-urlencoded"

# WAP <-> ADFS MS-ADFSPIP RPC (after TLS termination)
tls.handshake.type == 1 and tls.handshake.extensions_server_name == "adfs.corp.example.com"

# DC LDAP lookup by ADFS service account
ldap.filter contains "(sAMAccountName=" and ldap.opcode == 0x03  # SearchRequest

# ADFS auto-published signing cert in AD
ldap.filter contains "servicePrincipalName=HOST/adfs" and ldap.attributes contains "userCertificate"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `Event 364 — MSIS1005: The certificate specified...was not found` | SSL cert thumbprint in DB doesn't match store | `Set-AdfsCertificate -CertificateType ServiceCommunications -Thumbprint <thp>` then `Restart-Service adfssrv` |
| `Event 102 — There was an error during enabling the federation service` | SPN missing or duplicate | `setspn -X` to detect duplicates; `setspn -S HOST/adfs.corp.example.com corp\adfs-svc` |
| `MSIS7065 — There was an error accessing the federation service proxy trust` | WAP cert expired or revoked | Re-establish: `Install-WebApplicationProxy -FederationServiceTrustCredential (Get-Credential)` |
| Intranet users prompted for credentials | ADFS service URL not in IE/Edge Intranet zone; or `ExtendedProtectionTokenCheck = Always` blocking NTLM | Add `https://*.corp.example.com` to Intranet zone via GPO; check `Get-AdfsProperties | Select ExtendedProtectionProtectionPolicy` |
| `MSIS8017 — The service account does not have read access to the ADFS DB` | Service account change without ACL update | `Set-AdfsServiceAccount -ServiceAccount <account>` |
| Token signing cert rolled over, RPs failing | RPs not refreshing metadata | Push metadata refresh; or pin both old + new cert during rollover window |
| `MSIS9602 — Key distribution center (KDC) communication failed` | Service account cannot reach DC for Kerberos; LDAPS port blocked | Verify DNS SRV `_ldap._tcp.dc._msdcs.corp.example.com`; allow TCP/389 and TCP/88 |
| WAP proxy fails with `0x80075c29` | ADFS endpoint disabled or proxy-disabled | `Enable-AdfsEndpoint -TargetAddressPath "/adfs/ls/" -Proxy` |

### Diagnostic event logs

```
AD FS/Admin                     — ADFS service operational errors
AD FS/Tracing                   — Detailed request tracing (enable via Set-AdfsProperties -LogLevel)
AD FS Auditing                  — Security audit logon events (requires 'Generate security audits' right)

Microsoft-Windows-WebApplicationProxy/Admin
Microsoft-Windows-WebApplicationProxy/Operational
```

### Diagnostic commands

```
# Test adfs service health
Test-AdfsFarmBehavior -NodeName <host>  # (Server 2019+)
Get-AdfsProperties | Select FederationServiceName, FederationServiceDisplayName, HostName, Identifier
Get-AdfsSyncProperties   # WID sync status (primary vs secondary)

# ADFS metadata inspection
Invoke-WebRequest -Uri https://adfs.corp.example.com/FederationMetadata/2007-06/FederationMetadata.xml -OutFile metadata.xml

# SPN validation
setspn -L corp\adfs-svc
setspn -X            # detect duplicates
setspn -Q HOST/adfs.corp.example.com

# Token-signing cert rollover status
Get-AdfsCertificate -CertificateType TokenSigning
Get-AdfsProperties | Select SigningCertificateRolloverStatus, RolloverStatus

# ADFS service health via HTTP
Invoke-WebRequest https://adfs.corp.example.com/adfs/ls/idpinitiatedsignon.aspx
```

## Cross-platform equivalents

| AD FS feature | macOS | Linux |
|---|---|---|
| Federation service / IdP | (macOS has no native IdP; uses Keychain as cert store only) — PSSO for client-side — see `../08-macos-equivalents/04-platform-sso-extension.md`; Jamf Connect for Kerberos bridging — see `../08-macos-equivalents/03-jamf-connect-pro.md` | Keycloak (JBoss/WildFly) is the most common IdP replacement; mod_auth_mellon (Apache) for SP; nginx-plus-auth-idp for OAuth/OIDC RP |
| SAML/OIDC client (RP / SP) | Platform SSO + Enterprise SSO Extensions — see `../08-macos-equivalents/04-platform-sso-extension.md` | Linux has no native SAML/OIDC client. Use mod_auth_mellon + Mellon (Apache), Shibboleth SP, or Keycloak client libraries; SSSD's role is Kerberos-only — see `../09-linux-equivalents/01-sssd-ad-provider.md` |
| Kerberos auth to ADFS (intranet) | PSSO Kerberos extension — see `../08-macos-equivalents/04-platform-sso-extension.md` | SSSD + krb5 — see `../09-linux-equivalents/01-sssd-ad-provider.md` |
| WAP pre-auth | (macOS doesn't run a reverse proxy with pre-auth natively) | mod_auth_mellon + Apache reverse proxy; or Keycloak gatekeeper |
| Config DB | (no equivalent on macOS) | Keycloak uses relational DB (MariaDB/Postgres) for realm config |

For Linux, Keycloak (open-source, RH SSO upstream) is the closest ADFS replacement: it supports SAML 2.0 IdP+SP, OIDC provider, WS-Federation (limited), LDAP federation, and Kerberos bridge via SPNEGO.

## References

- MS-ADFS — Active Directory Federation Services Protocols
- MS-ADFSPIP — AD FS Proxy Integration Protocol (`[uuid e9396806-0e29-4660-b661-f6345c4bcd36]`)
- MS-OAPX — OAuth 2.0 Protocol Extensions
- MS-OIDCE — OpenID Connect Extensions for ADFS
- OASIS SAML 2.0 Core, Protocol, Bindings, Profiles
- WS-Trust 1.3 / WS-Federation 1.2 (OASIS standards)
- `Microsoft.IdentityServer.dll` — `Microsoft.IdentityServer.PolicyEngine.PolicyEngine` (policy evaluation entry point)
- `Microsoft.IdentityServer.Compression.dll!SamlMessageSerializer`
- Windows Internals 7th Ed., Part 1 — Chapter 9 (ADFS service account + SPN requirements)
- Microsoft Docs — `https://learn.microsoft.com/windows-server/identity/ad-fs/ad-fs-overview`
- `https://learn.microsoft.com/windows-server/identity/ad-fs/technical-reference/understanding-key-ad-fs-concepts`
