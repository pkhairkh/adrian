---
title: SAML 2.0 and WS-Federation — Assertion XML, Bindings, Passive Profile, RSTR, FederationMetadata
audience: senior-engineers
tags: [saml, ws-federation, ws-trust, federation, adfs, assertion, bindings, rstr, metadata]
related:
  - ./01-adfs-architecture.md
  - ./03-claims-rules.md
  - ./04-oidc-oauth.md
  - ../02-protocols/01-kerberos-internals.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

AD FS speaks SAML 2.0 (OASIS Core/Protocol/Bindings/Profiles) and WS-Federation Passive Profile (Microsoft's pre-OAuth IdP protocol); both end with a signed XML `<saml:Assertion>` (or `<saml2:Assertion>`) embedded either directly into the browser response (HTTP-POST) or wrapped in a WS-Trust `RequestSecurityTokenResponse` for active clients, and both are advertised via `/FederationMetadata/2007-06/FederationMetadata.xml` whose `<EntityDescriptor>` carries `<IDPSSODescriptor>` / `<SPSSODescriptor>` role elements.

## SAML 2.0 architecture

### Assertions, Protocols, Bindings, Profiles (4 docs)

| OASIS spec | Defines |
|---|---|
| SAML Core (Assertions) | The `<saml:Assertion>` XML structure, `<saml:Statement>` (Authn / Attribute / AuthzDecision) |
| SAML Protocol | `<samlp:AuthnRequest>`, `<samlp:Response>`, `<samlp:LogoutRequest>`, `<samlp:LogoutResponse>`, `<samlp:NameIDPolicy>` |
| SAML Bindings | HTTP-Redirect, HTTP-POST, HTTP-Artifact, SAML SOAP, PAOS, URI |
| SAML Profiles | Web Browser SSO, IdP-initiated SSO, SP-initiated SSO, Single Logout, NameID Management |

### SAML assertion XML structure

```xml
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
                 ID="_abc123" Version="2.0"
                 IssueInstant="2026-08-13T14:32:11Z">
  <saml2:Issuer>https://adfs.corp.example.com/adfs/services/trust</saml2:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_abc123">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>...</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>...</ds:X509Certificate>  <!-- Token-signing cert -->
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <saml2:Subject>
    <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">jdoe@corp.example.com</saml2:NameID>
    <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml2:SubjectConfirmationData NotOnOrAfter="2026-08-13T14:37:11Z"
                                     Recipient="https://app.corp.example.com/"
                                     InResponseTo="_id-12345"/>
    </saml2:SubjectConfirmation>
  </saml2:Subject>
  <saml2:Conditions NotBefore="2026-08-13T14:32:11Z" NotOnOrAfter="2026-08-13T14:37:11Z">
    <saml2:AudienceRestriction>
      <saml2:Audience>https://app.corp.example.com/</saml2:Audience>
    </saml2:AudienceRestriction>
  </saml2:Conditions>
  <saml2:AuthnStatement AuthnInstant="2026-08-13T14:32:11Z" SessionIndex="_sid-9876">
    <saml2:AuthnContext>
      <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
    </saml2:AuthnContext>
  </saml2:AuthnStatement>
  <saml2:AttributeStatement>
    <saml2:Attribute Name="http://schemas.xmlsoap.org/claims/UPN">
      <saml2:AttributeValue>jdoe@corp.example.com</saml2:AttributeValue>
    </saml2:Attribute>
    <saml2:Attribute Name="http://schemas.xmlsoap.org/claims/Role">
      <saml2:AttributeValue>Engineers</saml2:AttributeValue>
      <saml2:AttributeValue>Domain Users</saml2:AttributeValue>
    </saml2:Attribute>
  </saml2:AttributeStatement>
</saml2:Assertion>
```

Key elements:

| Element | Notes |
|---|---|
| `ID` | Unique per assertion; `_` prefix is conventional but not required |
| `IssueInstant` | UTC xsd:dateTime |
| `Issuer` | URI of IdP; ADFS uses `https://<adfs>/adfs/services/trust` |
| `ds:Signature` | Enveloped signature (XMLDSig); canonicalization is Exclusive C14N |
| `Subject/NameID` | User identifier; format dictates syntax (`unspecified`, `emailAddress`, `persistent`, `transient`, `entity`) |
| `SubjectConfirmation` | `cm:bearer` (default), `cm:holder-of-key` (HoK — client proves possession of key), `cm:sender-vouches` |
| `Conditions/NotBefore` & `NotOnOrAfter` | Validity window; ADFS default 60 min |
| `AudienceRestriction` | RP identifier that the assertion is valid for; MUST match the SP's `EntityID` |
| `AuthnStatement/AuthnContextClassRef` | Authentication method: `PasswordProtectedTransport` (form/Password), `Kerberos` (`urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos`), `TLSClient` (mutual TLS), `SmartCard` (`urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard`), `SmartCard-PKI` |
| `AttributeStatement` | Claim attributes; ADFS uses URN-style names from `http://schemas.xmlsoap.org/claims/*` and `http://schemas.microsoft.com/ws/2008/06/identity/claims/*` |

### Bindings

| Binding | Method | Encoding | Use |
|---|---|---|---|
| HTTP-Redirect | GET | SAML message deflated (zlib) + base64 + URL-safe in query param `SAMLRequest=` / `SAMLResponse=` | AuthnRequest (SP→IdP), LogoutRequest |
| HTTP-POST | POST | SAML message base64 in form field `SAMLRequest=` / `SAMLResponse=` | Assertion (IdP→SP); cannot use Redirect because the signed XML is too large for URL |
| HTTP-Artifact | GET or POST | Sends a small `SAMLart` artifact; SP resolves artifact over SOAP back-channel | Used when assertion is too large or must not pass through browser |
| SAML SOAP | SOAP 1.1 over HTTP | Direct request/response | Artifact resolution, attribute query, name ID mapping |
| PAOS | HTTP `Accept: application/vnd.paos+xml` | Reverse-SOAP; SP embeds PAOS header, IdP returns SOAP body | Used by ECP (Enhanced Client Profile) for non-browser clients |
| URI | (none) | SAML in HTTP header | Less common |

### Profiles

| Profile | Use |
|---|---|
| Web Browser SSO (SP-initiated) | Browser → SP → redirect to IdP → user authenticates → IdP returns Assertion → SP validates, sets session |
| Web Browser SSO (IdP-initiated) | Browser → IdP (user authenticates) → IdP POSTs Assertion to SP |
| Single Logout (SLO) | Either SP or IdP initiates; propagates logout to all sessions |
| NameID Management | Change NameID format mid-session (rare) |
| Enhanced Client Profile (ECP) | Non-browser (SOAP) client; uses PAOS binding |
| Artifact Resolution | Back-channel SOAP to resolve artifact |

### ADFS SAML endpoints

```
/adfs/ls/                          WS-Federation Passive + SAML 2.0 Passive
/adfs/services/trust/saml/sso      SAML 2.0 SSO POST/Redirect
/adfs/services/trust/saml/slo      SAML 2.0 Single Logout
/adfs/services/trust/saml/artifact SAML 2.0 Artifact Resolution (SOAP)
/adfs/ls/idpinitiatedsignon.aspx   IdP-initiated SSO (disabled by default Server 2016+)
```

## WS-Federation Passive Profile

Older Microsoft-protocol (SOAP-based, ~2003) that uses the same `<saml:Assertion>` inside a WS-Trust `RequestSecurityTokenResponse` element, transported via simple HTTP form POST.

### Message flow

```
1. Browser → SP: GET https://app.corp.example.com/
2. SP detects no session → 302 to:
   https://adfs.corp.example.com/adfs/ls/?wa=wsignin1.0
     &wtrealm=https://app.corp.example.com/
     &wctx=<state>
3. Browser → ADFS: GET (above URL)
4. ADFS prompts for creds (if no SSO session), authenticates, builds RSTR
5. ADFS → Browser: 200 OK with HTML form auto-POSTing to SP:
   <form method="POST" action="https://app.corp.example.com/">
     <input type="hidden" name="wa" value="wsignin1.0">
     <input type="hidden" name="wresult" value="<RSTR XML escaped>">
     <input type="hidden" name="wctx" value="<state>">
   </form>
6. Browser → SP: POST (form-encoded)
7. SP validates signature, extracts Assertion, sets session
```

### RSTR XML (RequestSecurityTokenResponse)

```xml
<trust:RequestSecurityTokenResponse xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <trust:Lifetime>
    <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2026-08-13T14:32:11Z</wsu:Created>
    <wsu:Expires xmlns:wsu="...">2026-08-13T14:37:11Z</wsu:Expires>
  </trust:Lifetime>
  <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
    <wsa:EndpointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
      <wsa:Address>https://app.corp.example.com/</wsa:Address>
    </wsa:EndpointReference>
  </wsp:AppliesTo>
  <trust:RequestedSecurityToken>
    <saml2:Assertion ...>  <!-- Same as the SAML 2.0 assertion above -->
      ...
    </saml2:Assertion>
  </trust:RequestedSecurityToken>
  <trust:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</trust:TokenType>
  <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
  <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
</trust:RequestSecurityTokenResponse>
```

The RSTR wraps the SAML assertion. The `wa` parameter is the WS-Federation action:
- `wsignin1.0` — sign-in request
- `wsignout1.0` — sign-out request
- `wsignoutcleanup1.0` — sign-out cleanup request (SP asks IdP to clear session)

Other WS-Federation params:
- `wtrealm` — RP identifier (the SP's `EntityID`)
- `wreply` — return URL after auth (optional)
- `wctx` — opaque state passed through
- `wreq` — optional WS-Trust `RequestSecurityToken` XML
- `wauth` — requested authentication method URI
- `wfresh` — freshness requirement (in seconds; `0` = re-auth required)
- `wct` — client timestamp
- `whr` — home realm (forces a specific Claims Provider Trust) — used for federated IdP selection

## WS-Trust (active clients)

Active (non-browser) clients — Office, Exchange, SharePoint CSOM, ADFS-aware thick apps — use WS-Trust over SOAP to obtain tokens directly. ADFS exposes multiple endpoints:

```
/adfs/services/trust/2005/usernamemixed       WS-Trust Feb 2005 (RSTR wraps SAML 1.1)
/adfs/services/trust/13/usernamemixed         WS-Trust 1.3      (RSTR wraps SAML 2.0)
/adfs/services/trust/2005/windowstransport    WS-Trust Feb 2005 + Windows transport auth (Kerberos/NTLM)
/adfs/services/trust/13/windowstransport      WS-Trust 1.3 + Windows transport
/adfs/services/trust/2005/certificatemixed    WS-Trust Feb 2005 + client cert
/adfs/services/trust/13/certificatemixed      WS-Trust 1.3 + client cert
/adfs/services/trust/issue                    Generic issue (auto-negotiated)
/adfs/services/trust/renew                    Token renewal
/adfs/services/trust/mex                      WS-MetadataExchange (WSDL for the above)
```

### WS-Trust RST (RequestSecurityToken)

```xml
<trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
    <wsa:EndpointReference xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
      <wsa:Address>https://app.corp.example.com/</wsa:Address>
    </wsa:EndpointReference>
  </wsp:AppliesTo>
  <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
  <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
</trust:RequestSecurityToken>
```

WS-Security header carries `<wsse:UsernameToken>` (for `usernamemixed`) or `<wsse:BinarySecurityToken>` (for `certificatemixed`) or Kerberos token (`windowstransport`).

## Federation Metadata

```
URL: https://<adfs>/FederationMetadata/2007-06/FederationMetadata.xml
Signed with: ADFS token-signing key
Content-Type: application/xml
```

```xml
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://adfs.corp.example.com/adfs/services/trust">
  <ds:Signature>...</ds:Signature>
  <RoleDescriptor xsi:type="IDPSSODescriptorType" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>...</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">...</KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="https://adfs.corp.example.com/adfs/ls/"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="https://adfs.corp.example.com/adfs/ls/"/>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
  </RoleDescriptor>
  <!-- Plus SP descriptor for ADFS-as-SP (Claims Provider Trust to other IdPs) -->
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://adfs.corp.example.com/adfs/ls/"
                              index="0" isDefault="true"/>
  </SPSSODescriptor>
  <!-- ADFS-specific extensions: ApplicationService (for WS-Fed passive) -->
</EntityDescriptor>
```

ADFS publishes both an `IDPSSODescriptor` (when acting as IdP) and `SPSSODescriptor` (when acting as SP for federated CPTs).

## Configuration / code examples

### PowerShell: add a SAML 2.0 RP trust from metadata

```powershell
Add-AdfsRelyingPartyTrust -Name 'App-CorpApp' `
  -MetadataUrl 'https://app.corp.example.com/FederationMetadata/2007-06/FederationMetadata.xml'

# Or manually without metadata
Add-AdfsRelyingPartyTrust -Name 'App-CorpApp' `
  -Identifier 'https://app.corp.example.com/' `
  -WSFedEndpoint 'https://app.corp.example.com/' `
  -IssuanceTransformRules @(
    '@RuleTemplate = "LdapClaims"
     @RuleName = "UPN"
     c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
     => issue(Type = "http://schemas.xmlsoap.org/claims/UPN",
              Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value);'
  )

# Add a SAML logout endpoint
Set-AdfsRelyingPartyTrust -TargetName 'App-CorpApp' `
  -SamlEndpoints @{
    SLORedirect = 'https://app.corp.example.com/logout'
    SLOPost     = 'https://app.corp.example.com/logout'
  }
```

### PowerShell: enable SAML 2.0 endpoint and disable WS-Fed passive

```powershell
# Disable WS-Fed passive endpoint (only SAML 2.0)
$ep = Get-AdfsEndpoint -AddressPath '/adfs/ls/'
$ep | Set-AdfsEndpoint -Enabled $true   # leave ls/ on for SAML
Get-AdfsEndpoint -AddressPath '/adfs/services/trust/mex' | Set-AdfsEndpoint -Enabled $true

# Confirm
Get-AdfsEndpoint | Where-Enabled | Select AddressPath, Protocol
```

### Python: SP-initiated SAML AuthnRequest (HTTP-Redirect)

```python
import base64, zlib, urllib.parse, secrets, datetime
from lxml import etree

# 1. Build AuthnRequest XML
NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
NS_SAML  = 'urn:oasis:names:tc:SAML:2.0:assertion'

req_id    = f"_{secrets.token_hex(16)}"
issue_instant = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

authn_req = f"""<samlp:AuthnRequest xmlns:samlp="{NS_SAMLP}"
                   xmlns:saml="{NS_SAML}"
                   ID="{req_id}" Version="2.0"
                   IssueInstant="{issue_instant}"
                   ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                   AssertionConsumerServiceURL="https://app.corp.example.com/saml/acs">
  <saml:Issuer>https://app.corp.example.com/</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="true"
                      Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
  <samlp:RequestedAuthnContext Comparison="minimum">
    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>"""

# 2. Deflate (raw, no zlib header) + base64 + URL-encode
deflated = zlib.compress(authn_req.encode('utf-8'))[2:-4]  # strip header (2B) + adler32 (4B)
encoded  = base64.b64encode(deflated).decode('ascii')

# 3. Build redirect URL
params = {
  'SAMLRequest': encoded,
  'RelayState':  secrets.token_urlsafe(16),
  'SigAlg':      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
}
# SigAlg triggers signing — ADFS supports unsigned AuthnRequest if SP doesn't sign
qs = urllib.parse.urlencode(params)
redirect_url = f"https://adfs.corp.example.com/adfs/ls/?{qs}"
print(redirect_url)
```

### Python: validate SAML Response signature

```python
from lxml import etree
from signxml import XMLVerifier
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Load ADFS token-signing cert (from metadata or PEM)
adfs_signing_cert = x509.load_pem_x509_certificate(open('adfs-signing.pem','rb').read())

# Parse SAMLResponse (POST body, base64-encoded XML)
import base64
xml = base64.b64decode(form_data['SAMLResponse'])
tree = etree.fromstring(xml)

# Verify signature (signxml handles enveloped signature + exc-c14n)
XMLVerifier().verify(tree, x509_cert=adfs_signing_cert.public_bytes(),
                     expect_references=False)

# Extract attributes
NS = {'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'}
for attr in tree.findall('.//saml2:AttributeStatement/saml2:Attribute', NS):
    name = attr.get('Name')
    values = [v.text for v in attr.findall('saml2:AttributeValue', NS)]
    print(f"{name}: {values}")
```

## Troubleshooting

### Wireshark filters

```
# SP-initiated SAML redirect (GET with SAMLRequest)
http.request.uri contains "SAMLRequest="
http.request.uri contains "wa=wsignin1.0"

# IdP → SP assertion POST
http.request.method == "POST" and
  (http.content_type == "application/x-www-form-urlencoded" or
   http.content_type contains "multipart/form-data") and
  (http.file_data contains "SAMLResponse" or http.file_data contains "wresult")

# ADFS metadata fetch
http.request.uri contains "FederationMetadata"

# Active client (Office) WS-Trust
http.request.uri contains "/adfs/services/trust/"

# WAP pre-auth (HTTP redirect to ADFS)
http.response.code == 302 and http.location contains "/adfs/ls/"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `MSIS7012 — An error occurred while processing the SAML response` | Audience restriction mismatch | RP `Identifier` in ADFS must exactly match `<saml:Audience>` in assertion; `Set-AdfsRelyingPartyTrust -TargetName <name> -Identifier <uri>` |
| `MSIS1006 — Token signing certificate thumbprint does not match` | ADFS rolled signing cert, SP has stale metadata | SP refreshes metadata (most modern SPs auto-refresh); ADFS keeps old cert non-primary during 15-day rollover window |
| `MSIS7017 — Audience URI is not in the AudienceRestriction collection` | Multiple `Identifier`s on RP, but SP sends a different one | `Get-AdfsRelyingPartyTrust -TargetName <name> | Select -ExpandProperty Identifier` and add missing identifier |
| Assertion replay — `MSIS7029 — The SAML message has already been processed` | Replay detection (default cache 60 min); clock skew causing re-send | Verify SP clock vs IdP; check ADFS `SamlMessageSecureChannel.ReplayDetectionWindow` |
| `MSIS7042 — The SAML request has expired` | `IssueInstant` outside `NotBefore`/`NotOnOrAfter` window | Verify clock sync on SP and IdP; default tolerance 5 minutes either side |
| `MSIS8012 — The SAML token is invalid because the NotBefore time is in the future` | IdP clock ahead of SP | Allow clock skew: `Set-AdfsRelyingPartyTrust -TargetName <name> -NotBeforeSkew 5` |
| `MSIS1135 — The signature on the SAML message cannot be verified` | SP's trusted cert store doesn't include ADFS signing cert | Re-import metadata or manually add the ADFS signing cert to SP trust store |
| `whr` parameter ignored | Multi-CPT enabled but `whr` doesn't match a CPT identifier | `Get-AdfsClaimsProviderTrust` and use the matching `Identifier` |

### Diagnostic event logs

```
AD FS/Admin                    — Operational errors (events 100-999)
AD FS/Tracing                  — Per-request trace (must enable via Set-AdfsProperties -LogLevel verbose)
AD FS Auditing                 — Security audit logon events
```

### Diagnostic commands

```
Get-AdfsRelyingPartyTrust | Format-List Name, Identifier, TokenLifetime, SamlEndpoints
Get-AdfsClaimsProviderTrust | Format-List Identifier, Name, AcceptanceTransformRules
Get-AdfsProperties | Select SsoLifetime, SamlMessageDeliveryWindow, PersistentSsoEnabled
Get-AdfsEndpoint -AddressPath "/adfs/services/trust/saml/sso" | Format-List
Set-AdfsProperties -LogLevel {Information, Verbose, Warnings, Errors}  # enable verbose

# Fetch metadata manually:
Invoke-WebRequest https://adfs.corp.example.com/FederationMetadata/2007-06/FederationMetadata.xml -OutFile md.xml

# Decode a SAMLRequest (form-POST) from a capture:
# base64-decode the SAMLRequest form value, then deflate (raw deflate, no header)
```

## Cross-platform equivalents

| AD FS feature | macOS | Linux |
|---|---|---|
| SAML IdP | (no native IdP on macOS — uses Keychain only as cert store) — see `../08-macos-equivalents/04-platform-sso-extension.md` for client-side SSO | Keycloak as IdP; Shibboleth IdP; SimpleSAMLphp |
| SAML SP (RP) | Platform SSO + Enterprise SSO Extensions (limited); MDM-driven | mod_auth_mellon (Apache), Shibboleth SP, django-saml-toolkit |
| WS-Federation passive | (none — Windows-only protocol) | (none — Keycloak has limited support; mod_auth_mellon is SAML only) |
| WS-Trust active | (none) | Keycloak supports WS-Trust via SOAP endpoint (limited) |
| Federation metadata | Keychain import; no metadata publishing | Keycloak publishes `/auth/realms/<realm>/protocol/saml/descriptor` |

Linux has no native SAML/OIDC client. Common stacks:
- Keycloak (RH SSO upstream): SAML 2.0 IdP + SP, OIDC provider, can federate to AD via LDAP
- mod_auth_mellon: Apache module, SAML 2.0 SP only
- Shibboleth SP: C-based SAML SP, multi-platform
- nginx-plus-auth-idp: commercial OIDC RP
- For Kerberos-only flows, SSSD is sufficient — see `../09-linux-equivalents/01-sssd-ad-provider.md`

For macOS, the Enterprise SSO / Platform SSO extensions provide Kerberos-only flows; SAML/OIDC RP must be implemented in-app or via MDM-driven browser session injection — see `../08-macos-equivalents/04-platform-sso-extension.md` and `../08-macos-equivalents/03-jamf-connect-pro.md`.

## References

- OASIS SAML 2.0 Core — `https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf`
- OASIS SAML 2.0 Protocol — `saml-protocol-2.0-os`
- OASIS SAML 2.0 Bindings — `saml-bindings-2.0-os`
- OASIS SAML 2.0 Profiles — `saml-profiles-2.0-os`
- OASIS WS-Federation 1.2 — `ws-fed-1.2-spec-os`
- OASIS WS-Trust 1.3 — `ws-trust-1.3-spec-os`
- RFC 7515 — JSON Web Signature (for OIDC, sibling spec)
- W3C XML Signature Syntax and Processing (2nd Ed.) — xmldsig-core
- W3C Exclusive XML Canonicalization — xml-exc-c14n
- MS-ADFS — AD FS Protocols spec (`https://learn.microsoft.com/openspecs/windows_protocols/ms-adfs`)
- `Microsoft.IdentityServer.dll!Microsoft.IdentityServer.Web.Tokens.SamlMessageSerializer`
- `Microsoft.IdentityModel.Tokens.Saml2.dll` (open-source, on GitHub)
- `https://learn.microsoft.com/windows-server/identity/ad-fs/technical-reference/understanding-key-ad-fs-concepts`
