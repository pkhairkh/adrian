---
title: OCSP and CRL Internals — CRLPublicationURLs, OCSPResp.exe, BasicOCSPResponse ASN.1, AIA/CDP, ID-PKIX-OCSP-NoCheck
audience: senior-engineers
tags: [ad-cs, pki, ocsp, crl, ocspreSp, basicOcspResponse, aia, cdp, ms-ocsp]
related:
  - ./01-ad-cs-architecture.md
  - ./02-certificate-templates.md
  - ./03-autoenrollment.md
  - ../01-ad-core/02-ad-cs-cert-services.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/08-freeipa-trust.md
last_updated: 2026-08-13
---

AD CS publishes CRLs on a CA-configured schedule via the `certxmod.dll` Exit module to URLs in the registry multi-string `CRLPublicationURLs`, and an Online Responder service (`OCSPResp.exe` under `svchost -k NetworkService`) signs `BasicOCSPResponse` (RFC 6960) blobs using an OCSP Response Signing cert (EKU 1.3.6.1.5.5.7.3.9, carries `ID-PKIX-OCSP-NoCheck` OID 1.3.6.1.5.5.7.48.1.5 so that clients skip the OCSP signing cert's own CRL check).

## Architecture

### CRL publication

The CA's Exit module fires `EXITEVENT_CRLISSUED` after each `certutil -crl` or scheduled publish. For each entry in `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\CRLPublicationURLs` (REG_MULTI_SZ), the module:

1. Expands `%windir%`, `%3` (CA name), `%8` (delta marker `_` if delta CRL), `%9` (suffix like `(1)`).
2. Writes the DER-encoded `CertificateList` ASN.1 structure.
3. For LDAP URLs, performs `ldap_modify_s` to the `certificateRevocationList` attribute of `CN=<CAName>,CN=<CA-ShortName>,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,<NC>`.
4. For HTTP URLs, `WinHttpSendRequest` PUT — typically a virtual directory mapped to `%windir%\system32\CertSrv\CertEnroll\`.

A CRL entry URL is encoded as:

```
<flags>:<url-template>
  flags (decimal): 1 = file system
                   2 = LDAP
                   4 = HTTP
                   8 = OCSP (only for AIA, not CDP)
                  16 = file system (force)
                  64 = include in CDP extension of issued certs
                 128 = include in CDP extension of issued certs (alternate form)

Example:
1:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl\n2:ldap:///CN=%7%2,CN=%7,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,%6?certificateRevocationList?base?objectClass=cRLDistributionPoint\n64:http://pki.corp.example.com/crl/%3%8%9.crl
```

### CRL types

| Type | File suffix | CRL extension | Registry | Default lifetime |
|---|---|---|---|---|
| Full CRL | `.crl` | `CRLNumber` (2.5.29.20) increments; `NextUpdate` per `CRLPeriod` | `CRLPeriod` + `CRLPeriodUnits` (days) | 7 days typical; 6-12 months for offline root |
| Delta CRL | `.crl` with `%8=_` substituted → `_<suffix>.crl` | `DeltaCRLIndicator` (2.5.29.27) | `CRLDeltaPeriod` + `CRLDeltaPeriodUnits` (hours) | 1 hour typical |

CRL overlap (Server 2008+) — `CRLOverlapPeriod` extends validity: a new CRL is published *before* the old one's `NextUpdate`, so the overlap window covers CA downtime.

### OCSP responder

```
services.msc: "Online Responder" (OCSP)
  ImagePath  : %SystemRoot%\System32\svchost.exe -k NetworkService
  ServiceDll : %SystemRoot%\System32\OCSPSvc.dll  (registered as ServiceDll)
  ServiceType: 0x20 (SHARE_PROCESS)
  ObjectName : NT AUTHORITY\NetworkService
  Dependencies: RpcSs, HTTP, CryptSvc

Process: %SystemRoot%\System32\OCSPResp.exe  (launched by svchost)
  OCSPSvc.dll    Service control + RPC endpoint
  ocsp.dll       OCSP engine, signing, caching
  Microsoft.IdentityModel.dll  (claims, optional)
```

OCSP RPC interface is `OCSPResponder` (`[uuid] 87E25E6B-1322-4F87-B4E1-62ECD9F0A3B6`) but the primary client-facing interface is HTTP. The service registers HTTP URLs via `HttpSetServiceConfiguration` (driver `HTTP.SYS`):

```
http.sys URL ACL:
  https://+:80/ocsp          (default)
  https://+:443/ocsp
  http://+:80/ocsp           (less common)
```

### Revocation configuration

Each Online Responder can host multiple Revocation Configurations, each linking one CA to a signing cert. Stored in registry:

```
HKLM\SYSTEM\CurrentControlSet\Services\OCSP\Responder\<RevocationConfigName>\
  ├─ Provider.ClsId                  = {<CLSID of the OCSP provider>}
  ├─ Provider.Flags                  = 0x0  (REG_DWORD)
  ├─ CACertificates                  = <DER blob of CA cert>  (REG_MULTI_SZ)
  ├─ SigningCertTemplate             = OCSPResponseSigning<CAName>
  ├─ SigningFlags                    = 0x31  (REG_DWORD)
  │     bit 0  = CA cert private key for signing (else use OCSP-specific cert)
  │     bit 4  = RESIGN_ON_KEY_WARNING (re-sign after CRL is updated)
  │     bit 5  = DISABLE_SSL_CLIENT_CERT_CHECK
  ├─ CACertificateHash               = <sha1>  (REG_SZ)
  ├─ RefreshTimeOut                  = 1  (REG_DWORD, hours)
  ├─ BaseCrlUrls\Url_0               = http://pki.corp.example.com/crl/<CAName>.crl
  ├─ DeltaCrlUrls\Url_0              = http://pki.corp.example.com/crl/<CAName>_<delta>.crl
  └─ SerNumDir\0a\0b\...             = hash bucket lookup for fast serial number → status
```

### OCSP signing certificate

The OCSP signing cert must:
- Be issued by the CA it answers for (or chain to it).
- Have EKU `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9).
- Carry `ID-PKIX-OCSP-NoCheck` extension (OID 1.3.6.1.5.5.7.48.1.5) — clients MUST NOT check the OCSP signing cert's own revocation status.
- Have a short lifetime (typically 7-14 days) — auto-renewed by an OCSPResponseSigning template enrolled by the OCSP service account via autoenroll.

The `SigningFlags` bit 0 lets the OCSP responder use the CA's own signing key (when the OCSP service runs ON the CA) — saves cert issuance but increases CA key exposure.

## Protocol/message formats

### CRL structure (RFC 5280 §5)

```asn1
CertificateList ::= SEQUENCE {
    tbsCertList          TBSCertList,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}

TBSCertList ::= SEQUENCE {
    version              Version OPTIONAL,        -- v2 (1)
    signature            AlgorithmIdentifier,     -- sha256WithRSAEncryption (1.2.840.113549.1.1.11)
    issuer               Name,
    thisUpdate           Time,
    nextUpdate           Time OPTIONAL,
    revokedCertificates  SEQUENCE OF SEQUENCE {
        userCertificate      CertificateSerialNumber,
        revocationDate       Time,
        crlEntryExtensions   Extensions OPTIONAL
    } OPTIONAL,
    crlExtensions        [0] EXPLICIT Extensions OPTIONAL
}
```

CRL extensions on the `crlExtensions` field:

| OID | Name | Notes |
|---|---|---|
| 2.5.29.20 | CRLNumber | Monotonically increasing integer |
| 2.5.29.27 | DeltaCRLIndicator | Base CRL number this delta builds on |
| 2.5.29.28 | IssuingDistributionPoint | Critical; `onlyContainsUserCerts`, `onlyContainsCACerts`, `indirectCRL`, `onlyContainsAttributeCerts` |
| 2.5.29.21 | CRLReason | Per-entry; 0=unspecified, 1=keyCompromise, 2=cACompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation, 6=certificateHold, 8=removeFromCRL, 9=privilegeWithdrawn, 10=aACompromise |
| 2.5.29.24 | InvalidityDate | Per-entry |

### OCSP request (RFC 6960)

```asn1
OCSPRequest ::= SEQUENCE {
    tbsRequest      TBSRequest,
    optionalSignature [0] EXPLICIT Signature OPTIONAL
}

TBSRequest ::= SEQUENCE {
    version            [0] EXPLICIT Version DEFAULT v1,
    requestorName      [1] EXPLICIT GeneralName OPTIONAL,
    requestList        SEQUENCE OF Request,
    requestExtensions  [2] EXPLICIT Extensions OPTIONAL
}

Request ::= SEQUENCE {
    reqCert                    CertID,
    singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL
}

CertID ::= SEQUENCE {
    hashAlgorithm    AlgorithmIdentifier,    -- sha256 (2.16.840.1.101.3.4.2.1) preferred
    issuerNameHash   OCTET STRING,           -- hash of DER-encoded issuer Name
    issuerKeyHash    OCTET STRING,           -- hash of issuer's subjectPublicKey BIT STRING contents
    serialNumber     CertificateSerialNumber
}
```

Nonce extension (OID 1.3.6.1.5.5.7.48.1.2) is in `requestExtensions` — 16-32 random bytes; responder echoes back in response. Prevents replay of cached signed responses.

HTTP wire format: base64-encoded DER `OCSPRequest` in body of POST to OCSP URL (Content-Type: `application/ocsp-request`). Some clients support GET with URL-encoded `OCSPRequest` in path (`?/<base64>`).

### OCSP response (RFC 6960)

```asn1
OCSPResponse ::= SEQUENCE {
    responseStatus       OCSPResponseStatus,         -- 0=successful
    responseBytes        [0] EXPLICIT ResponseBytes OPTIONAL
}

ResponseBytes ::= SEQUENCE {
    responseType   OBJECT IDENTIFIER,                -- id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1)
    response       OCTET STRING                      -- DER BasicOCSPResponse
}

BasicOCSPResponse ::= SEQUENCE {
    tbsResponseData       ResponseData,
    signatureAlgorithm    AlgorithmIdentifier,
    signature             BIT STRING,
    certs                 [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
}

ResponseData ::= SEQUENCE {
    version              [0] EXPLICIT Version DEFAULT v1,
    responderID          ResponderID,
    producedAt           GeneralizedTime,
    responses            SEQUENCE OF SingleResponse,
    responseExtensions   [1] EXPLICIT Extensions OPTIONAL
}

SingleResponse ::= SEQUENCE {
    certID                  CertID,
    certStatus              CertStatus,
    thisUpdate              GeneralizedTime,
    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
    singleExtensions        [1] EXPLICIT Extensions OPTIONAL
}

CertStatus ::= CHOICE {
    good        [0] IMPLICIT NULL,
    revoked     [1] IMPLICIT RevokedInfo,
    unknown     [2] IMPLICIT UnknownInfo
}
```

`certs` field carries the OCSP signing cert (so the client can verify chain to CA without separately fetching). `nextUpdate` is optional but SHOULD be present; if absent, client falls back to a local freshness window (typically 1 hour for Windows).

`producedAt` and `thisUpdate` use UTC seconds. Windows OCSP client tolerates `producedAt ± 5 min` of local time.

### AIA and CDP extensions in certificates

Issued certificates carry:

| Extension | OID | Critical | Contains |
|---|---|---|---|
| Authority Information Access (AIA) | 1.3.6.1.5.5.7.1.1 | No | One or more `AccessDescription`s: `accessMethod=1.3.6.1.5.5.7.48.2 (ad-caIssuers)` → URL of issuer CA cert (HTTP or LDAP); `accessMethod=1.3.6.1.5.5.7.48.1 (ad-ocsp)` → URL of OCSP responder |
| CRL Distribution Point (CDP) | 2.5.29.31 | No | One or more `DistributionPoint`s with `fullName` GeneralName URLs (HTTP, LDAP, or FILE) |

Registry-driven URL encoding (CA's `certxmod.dll!FormatCertEnrollURL`):

```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\
  CRLPublicationURLs   : flags:url  (multi-string)
  CACertPublicationURLs: flags:url  (multi-string)

AIA flag for CACertPublicationURLs:
  1 = file system
  2 = LDAP
  4 = HTTP
 11 = include in AIA extension of issued certs (0xb)
```

## Configuration / code examples

### PowerShell: install and configure Online Responder

```powershell
# Install role + feature
Install-WindowsFeature -Name ADCS-Online-Cert-Authority -IncludeManagementTools
Install-AdcsOnlineResponder -Force

# Configure a revocation configuration (link to existing CA)
$caConfig = "corp-issue-01.corp.example.com\CORP-ISSUE-CA-01"
$caCert = Get-CACert $caConfig
$revConfig = @{
  Name = 'CORP-ISSUE-CA-01'
  CACert = $caCert
  CDPUrl = 'http://pki.corp.example.com/crl/CORP-ISSUE-CA-01.crl'
  DeltaCdpUrl = 'http://pki.corp.example.com/crl/CORP-ISSUE-CA-01_*.crl'
  SigningCertTemplate = 'OCSPResponseSigning'
  AutoUpdate = $true
  RefreshTimeoutHours = 1
}
Add-OcspRevocationConfiguration @revConfig

# Force refresh of cached CRLs
Restart-Service OCSPSvc
Get-OCSPRevocationConfiguration | Format-List
```

### PowerShell: include OCSP URL in AIA, force CA re-issue

```powershell
certutil -setreg CA\CACertPublicationURLs "1:%windir%\system32\CertSrv\CertEnroll\%1%3%4.crt\n11:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,%6?cACertificate?base?objectClass=certificationAuthority\n11:http://pki.corp.example.com/certs/%3%4.crt\n2:http://ocsp.corp.example.com/ocsp"
Restart-Service CertSvc
certutil -crl  # Force publish new CRL
# Renew the CA cert (or any leaf) to refresh the AIA extension:
Get-CACertificate | Renew-CACertificate -Force
```

The `2:` prefix on the OCSP URL is interpreted by `certxmod.dll` as "include this URL in AIA extension with accessMethod=ad-ocsp" (reg value `2` = OCSP flag, also includes in AIA).

### Python: parse a CRL and dump revoked serials

```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

with open('CORP-ISSUE-CA-01.crl','rb') as f:
    crl = x509.load_der_x509_crl(f.read())

print(f"Issuer: {crl.issuer.rfc4514_string()}")
print(f"This update: {crl.last_update.isoformat()}")
print(f"Next update: {crl.next_update.isoformat()}")
print(f"CRLNumber: {crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number}")

for r in crl:
    reason = r.extensions.get_extension_for_class(x509.CRLReason).value.reason \
             if r.extensions else None
    print(f"  serial={r.serial_number:#x} revoked={r.revocation_date.isoformat()} reason={reason}")
```

### Python: build and verify an OCSP request

```python
import secrets, requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

cert = x509.load_pem_x509_certificate(open('user.crt','rb').read())
issuer = x509.load_pem_x509_certificate(open('ca.crt','rb').read())

builder = ocsp.OCSPRequestBuilder()
builder = builder.add_certificate(cert, issuer, hashes.SHA256())
builder = builder.add_extension(x509.OCSPNonce(secrets.token_bytes(16)), critical=False)
req = builder.build()
der = req.public_bytes(serialization.Encoding.DER)

r = requests.post('http://ocsp.corp.example.com/ocsp',
                  data=der,
                  headers={'Content-Type':'application/ocsp-request'})

ocsp_resp = ocsp.load_der_ocsp_response(r.content)
print(ocsp_resp.response_status)         # SUCCESSFUL
print(ocsp_resp.certificate_status)      # GOOD / REVOKED / UNKNOWN
print(ocsp_resp.revocation_reason) if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
print(ocsp_resp.this_update, ocsp_resp.next_update)
```

## Troubleshooting

### Wireshark filters

```
# OCSP HTTP traffic
http.request.uri contains "/ocsp" or http.host == "ocsp.corp.example.com"
http.content_type == "application/ocsp-request"
http.content_type == "application/ocsp-response"

# CRL fetch
http.request.uri contains ".crl"

# AIA fetch (CA cert by URL)
http.request.uri contains ".crt" or http.request.uri contains ".cer"

# CA-side LDAP publication of CRL
ldap.opcode == 0x06 and ldap.mod_attr == "certificateRevocationList"
ldap.filter contains "CDP"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `pkiview.msc` shows OCSP "Error: the OCSP response is invalid` | OCSP signing cert expired | Renew `OCSPResponseSigning<CAName>` template enroll on the OCSP host: `certutil -pulse` |
| `pkiview.msc` shows AIA/CDP "HTTP 404` | URL ACL misconfigured or virtual directory missing | `netsh http show urlacl` to confirm `http://+:80/ocsp`; ensure IIS CertEnroll virtual dir is mapped to `%windir%\system32\CertSrv\CertEnroll` |
| Cert revocation check fails — `0x80092013 — Revocation offline` | CRL/OCSP unreachable from client; AIA/CDP URL has internal-only host | Publish external AIA/CDP; add OCSP URL with public host |
| OCSP responses accepted even when stale | `nextUpdate` is in future but CRL is stale | Verify `RefreshTimeOut` registry value; check OCSP service is running |
| `Bad OCSP signing cert` | Signing cert missing `ID-PKIX-OCSP-NoCheck` extension (OID 1.3.6.1.5.5.7.48.1.5) | Re-issue OCSPResponseSigning template with the extension enabled |
| Delta CRL never published | `CRLDeltaPeriod = 0` or `CRLDeltaPeriodUnits = 0` | `certutil -setreg CA\CRLDeltaPeriod 1` + `-setreg CA\CRLDeltaPeriodUnits 0` (1 hour) |
| CRL publication fails with `0x80070020` (file in use) | IIS worker process holds the file | Stop IIS app pool, run `certutil -crl`, restart |
| OCSP responses slow (10+ s) | CRL is huge (10K+ entries); hash bucket lookup slow | Enable delta CRLs; consider splitting the CA |

### Diagnostic commands

```
certutil -crl                       # Force-publish full + delta CRL
certutil -getreg CA\CRLPublicationURLs
certutil -getreg CA\CACertPublicationURLs
certutil -urlfetch -verify <cert.cer>  # Walks AIA/CDP/OCSP URLs
pkiview.msc                          # Enterprise PKI health console
Get-OCSPRevocationConfiguration
Get-OCSPCAConfiguration

# Send an OCSP request manually via openssl:
openssl ocsp -issuer ca.crt -cert user.crt \
  -url http://ocsp.corp.example.com/ocsp \
  -CAfile ca-bundle.crt -resp_text -nonce
```

## Cross-platform equivalents

| AD CS feature | macOS | Linux |
|---|---|---|
| CRL fetch + cache | `ocspd` daemon caches CRLs at `/private/var/db/crls/cacerts.pem`; CLI `security` tool | `/etc/ssl/certs/` + `c_rehash`; OpenSSL `X509_STORE` cache |
| OCSP client | `ocspd` (built-in) — configurable via `com.apple.security.ocsp` preference pane | `openssl ocsp -url ... -issuer ... -cert ...` |
| OCSP responder | (no native; third-party EJBCA or `ruby-r509-ca-ocsp`) | Dogtag OCSP subsystem (`pki-tomcat` instance) — see `../09-linux-equivalents/08-freeipa-trust.md` |
| CRL distribution via LDAP/HTTP | HTTP only (LDAP rare on macOS) | OpenLDAP `slapd` + Apache / nginx HTTP |
| Trust store (root CAs) | `/System/Library/Keychains/SystemRootCertificates.keychain` (read-only); admin roots in `/Library/Keychains/System.keychain` | `/etc/pki/ca-trust/source/anchors/` + `update-ca-trust` (RHEL); `/usr/local/share/ca-certificates/` + `update-ca-certificates` (Debian) |

For macOS Platform SSO / smart-card cert trust, see `../08-macos-equivalents/04-platform-sso-extension.md`; for SSSD smart-card cert trust (Linux), see `../09-linux-equivalents/01-sssd-ad-provider.md`.

## References

- RFC 5280 §5 — Certificate and CRL Profile
- RFC 6960 — X.509 Internet PKI Online Certificate Status Protocol (OCSP)
- RFC 5019 — Lightweight OCSP Profile for HTTP
- RFC 6961 — Multiple OCSP request extension (less common)
- MS-OCSP — Online Certificate Status Protocol (OCSP) Responder Protocol
- `ocsp.h`, `certca.h`, `certenroll.h` (Windows SDK)
- `OCSPSvc.dll!COcspServer::Initialize` and `ocsp.dll!CResponderServer::ProcessRequest` (internal; documented behavior matches RFC 6960)
- `https://learn.microsoft.com/windows-server/identity/ad-cs/active-directory-certificate-services-overview`
- `https://learn.microsoft.com/troubleshoot/windows-server/windows-security/online-responder-service-ocsp`
