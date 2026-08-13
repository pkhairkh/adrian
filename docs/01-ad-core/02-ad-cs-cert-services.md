---
title: AD CS — Certificate Services Internals (certsvc.exe, policy/exit modules, ICertPassage)
audience: senior-engineers
tags: [ad-cs, pki, certsvc, certpmod, certxmod, icertpassage, ms-wcce, ms-xcep]
related:
  - ./01-ad-ds-internals.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../02-protocols/01-kerberos-internals.md
  - ../05-pki-certs/01-ad-cs-architecture.md
last_updated: 2026-08-13
---

Active Directory Certificate Services (AD CS) is a Windows service (`certsvc.exe`) hosting one or more Certificate Authority instances, each backed by an ESE (Jet Blue) database (`*.edb`) and exposed via three interfaces: the ICertPassage DCE/RPC interface for legacy enrollment, the MS-WCCE DCOM interface for policy-based enrollment, and the MS-WSTEP / MS-XCEP HTTP endpoints for modern client enrollment. AD-integrated Enterprise CAs additionally use DRSUAPI to publish issued certificates and CRLs to the `NTAuthCertificates` object in the Configuration NC.

## CA Topology

### Enterprise vs Standalone

| Property | Enterprise CA | Standalone CA |
|---|---|---|
| Required | AD DS domain | None |
| Auth | Integrated Windows (Kerberos / NTLM) | Anonymous or Basic (configurable) |
| Certificate templates (`pKICertificateTemplate`) | Yes — published to `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...` | No — uses static request disposition |
| Subject name | Auto from AD attribute (e.g., `CN=%displayName%` or `dnsHostName` for machine certs) | Manual or from CSR |
| Policy module default | `certpmod.dll!EnterprisePolicy` | `certpmod.dll!StandAlonePolicy` |
| Exit module default | `certxmod.dll!EnterpriseExit` (publishes to AD) | `certxmod.dll!StandAloneExit` |
| Approval model | Auto-issue, manager-approve, or per-template | Per-request manager-approve |
| Typical use | Internal PKI, machine auto-enrollment, SCOM/SQL cert automation | Web-facing CA, offline root, third-party enrollment |

### CA hierarchy classes

- **Root CA** — Self-signed, offline by convention. Subject == Issuer. KeyUsage includes `keyCertSign, cRLSign` (OID 2.5.29.15 bitmask `0x06`).
- **Subordinate CA** — Issued by parent. Same KeyUsage. Two variants: **policy CA** (separates issuance policy boundary) and **issuing CA** (issues end-entity certs directly).
- **Cross-certification** — A root signs another PKI's root via a cross-cert; `CrossCertificatePair` attribute (OID 2.5.4.41) on the AD `NTAuthCertificates` object.

## Service architecture

```
services.msc: "Active Directory Certificate Services" (CertSvc)
 ├── process: %SystemRoot%\System32\certsvc.exe
 │    ├── certpmod.dll   (Policy module — decides whether to issue/deny/pending)
 │    ├── certxmod.dll   (Exit module — fires on issue/revoke, can call AD, SMTP, file)
 │    ├── certadm.dll    (COM administration: ICertAdmin2)
 │    ├── certenc.dll    (CertEnroll server-side helpers)
 │    ├── certca.dll     (CA engine, request handler, key archival, X.509 builder)
 │    ├── certcors.dll   (Crypto CORE, calls CNG: bcrypt.dll, ncrypt.dll)
 │    ├── certcmp.dll    (COM dispatch)
 │    └── mscat32.dll    (catalog file utilities — for exiting to SCCM)
 │
 ├── service account: NT AUTHORITY\SYSTEM (default)
 ├── service dependencies: RPCSS, Cryptographic Services (CryptSvc)
 └── service type: Own Process, Interactive (for console UI)

Per-CA registry hive:
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\
 ├── CAServerName          = <hostname>                     (REG_SZ)
 ├── CRLPublicationURLs    = 1:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl\n2:ldap:///CN=...
 ├── CACertPublicationURLs = ... similar ...
 ├── PolicyModules         = certpmod.dll                   (REG_SZ)
 ├── ExitModules           = certxmod.dll                   (REG_SZ)
 ├── Policy\<CAName>\RequestDisposition    = 0  (issue)     (REG_DWORD)
 ├── Exit\<CAName>\...
 ├── EnrollmentEndpoints   = ... (HTTPS URLs, see MS-XCEP)
 ├── Active               = 1                              (REG_DWORD)  // 0 = paused
 ├── CA Certificate (raw) = <DER-encoded CA cert>          (REG_BINARY)
 └── SubjectName          = CN=...                          (REG_SZ)
```

The `certsvc.exe` binary is a thin dispatcher. Each CA instance runs in its own thread inside the service; multiple CAs share one process. The CA database is opened via ESE inside `certca.dll!caOpenDatabase`.

### `certpmod.dll` — Policy module

Exports `ICertPolicy2` COM interface (`{8691B64C-A8D5-4FAD-A40D-7DC81CABF1CC}`). Lifecycle:

1. `CCertPolicy::Initialize(strConfig)` — called at service start. Loads template definitions from `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,...` into in-memory template table.
2. `CCertPolicy::VerifyRequest(strConfig, Flags, pRequest, pDisposition)` — called per request. Steps:
   - Look up caller SID via `WTSQuerySessionToken` (DCOM caller context).
   - Resolve caller's `objectSid`, `userCertificate`, `dNSHostName` (for machine certs) from AD.
   - Find template by `msPKI-Certificate-Name-Flag` / `msPKI-Enrollment-Flag` match. ACL check: caller must have `Write` on `pKIExtendedKeyUsage` of the template's `nTSecurityDescriptor` — actually, "Enroll" right via ACE on the template's `pKIEnrollmentAccess` ACE.
   - Validate request against template constraints: subject name (auto vs supplied), key usage, EKU (OIDs e.g. 1.3.6.1.5.5.7.3.2 = client auth, 1.3.6.1.5.5.7.3.1 = server auth, 1.3.6.1.4.1.311.20.2.1 = smart-card logon).
   - Subject name building: `%displayName%`, `%dnsHostName%`, `%msDS-...%` substitution tokens.
   - Returns disposition: 1=issue, 2=deny, 3=pending (manager approval queue).
3. `CCertPolicy::GenerateCertificate(...)` — adds extensions: Basic Constraints, Authority Key Identifier (from issuer), Subject Key Identifier (SHA-1 of public key), CRL Distribution Points, Authority Info Access (OCSP / AIA).

### `certxmod.dll` — Exit module

Exports `ICertExit2` (`{3DF5FB6E-FC25-11D1-9EAA-00C04FC30BFA}`). Lifecycle:

1. `CCertExit::Initialize(strConfig, Flags)` — registers event filter mask.
2. `CCertExit::Notify(strConfig, Event, Context)` — called when CA issues (event 1), revokes (event 2), or shuts down (event 4). Default Enterprise exit:
   - Calls `DSCrackNames` to get the DN of the certificate subject (if machine, look up by `dNSHostName`).
   - Calls `IDirectoryObject::CreateDSObject` to publish to the `userCertificate` attribute (machine) or `caCertificate` (CA object) in AD.
   - Publishes CRL via LDAP modify to the `certificateRevocationList` attribute of the appropriate `NTAuthCertificates` / `CertificationAuthority` object.

Custom exit modules (sample in Windows SDK under `%SDK%\Samples\Security\ADCS\Exit\`) allow sending webhooks, pushing to a CMDB, or calling an HSM audit API.

## CA database

ESE database, page size 4 KB (Server 2008+) or 32 KB (Server 2016+). Default path:

```
%SystemRoot%\System32\CertLog\
 ├── <CAName>.edb              # main database
 ├── edb.log                   # transaction log (current)
 ├── edb00001.log .. edbXXXXX.log
 ├── edb.chk                   # checkpoint
 ├── edbres00001.jrs           # reserved logs
 └── <CAName>.pat              # patched-database backup marker
```

Schema (well-known tables, see `certdb.h`):

| Table | Columns (selected) | Notes |
|---|---|---|
| `RequestTable` | RequestId (PK, INT), RequestRow (LONG), StatusCode, Disposition, DispositionMsg, RequesterName, SubmittedWhen, resolvedWhen, Certificate (BLOB), SerialNumber | One row per request, even denied. Certificate column populated on issue. |
| `CertificateTable` | CertRowId, SerialNumber, IssuerNameId, NotBefore, NotAfter, PubKeyHash, CertHash (SHA1) | One row per issued cert. FK to RequestRow via `Request.CertRowId`. |
| `CRLTable` | CRLRowId, IssuerNameId, ThisUpdate, NextUpdate, CRL (BLOB) | Latest published CRL per issuer. |
| `ExtensionTable` | ExtensionRowId, Name, Flags, Value | Extensions for issued certs. |
| `KeyRecoveryTable` | KeyRowId, ArchivedKey (BLOB, encrypted) | Key archival (optional, requires KRA certs). |

The DB is queried via `certutil.exe -view` (which translates to ODBC over ESE) or `ICertView2` COM interface (`{B7F3AF66-0DB5-11D1-9E97-00C04FC30BFA}`). The `Certificate` column in `RequestTable` stores the raw DER X.509 binary. `SerialNumber` is a hex string; in ESE it is stored as text, not binary.

Database backup uses `certutil.exe -backup` or `certsrv.exe` VSS writer (`CertSvc VSS Writer`, writer ID `{5425FD7A-0D43-4C59-AA61-D3D2D8E9A9D7}`). Restoring a CA requires `certutil -restoreDB` followed by `-restoreKey` to re-import the CA private key from the `.p12` backup.

## RPC interfaces

### ICertPassage — legacy request interface

The original MS-WCCE RPC interface for `certreq.exe` and `certcli.dll` enrollment. Interface UUID:

```
[91b9b93a-57b4-11d0-8f16-00a0484d6c9c]  v1.0
```

Endpoint: dynamic TCP via RPC Endpoint Mapper (TCP 135). IDL published in `MS-WCCE` §4 (the DCOM dispinterface `ICertRequestD` is built on top of this for the modern `CCertRequest` COM class).

Key methods (opnums):

| Method | Purpose |
|---|---|
| `Request` | Submit a CSR; returns request ID + disposition. |
| `GetRequestProperty` | Read request attribute (subject, key usage, etc.). |
| `GetCertificateProperty` | Read issued cert attribute (serial, thumbprint). |
| `GetCACertificate` | Retrieve CA cert chain. |
| `GetCertificateRow` | Get the row in `CertificateTable`. |
| `EnumExtensions` / `GetExtension` | Enumerate per-request extensions. |
| `SetAttributes` | Set request attributes mid-flow (e.g., subject alt name). |
| `Ping` | Service liveness check. |

Modern enrollment (Server 2008+) uses the DCOM-class `ICertRequest2` (`{D65E8A2E-26F2-46B3-9F8C-9D7D6FAB68D5}`), also implemented by `certcli.dll`, layered on the same RPC pipe.

### MS-WCCE — Windows Client Certificate Enrollment

The full protocol stack: `ICertRequest2` (DCOM) over `ICertPassage` RPC over DCE/RPC. Defined in MS-WCCE; covers request submission, certificate retrieval, CRL fetch, key recovery (via KRA certs), and template enumeration (Enterprise only). Client-side implementation: `certcli.dll` (loaded by `certreq.exe`, `mmc.exe` PKI snap-in, Auto-enrollment COM object `CLSID_CERTENROLLUI`).

### MS-XCEP — XML Certificate Enrollment Protocol

Modern transport: HTTPS. Schema in MS-XCEP. Endpoints under IIS on the CA host:

```
https://<ca-host>/<CAName>_CES_Kerberos/service.svc     # Certificate Enrollment Web Service (CES)
https://<ca-host>/<CAName>_CES_UsernamePassword/service.svc
https://<ca-host>/<CAName>_CES_Certificate/service.svc
https://<ca-host>/<CAName>_CES_KeyBasedRenewal/service.svc

https://<ca-host>/<CAName>_CES/service.svc/CES           # legacy
https://<ca-host>/ADPolicyProvider/CertificatePolicy.asmx  # CEP — Certificate Enrollment Policy
```

- **CEP (Certificate Enrollment Policy)** — MS-XCEP. Returns a list of available templates filtered by caller permissions. SOAP over HTTPS. WSDL: `%SystemRoot%\System32\certenroll\cepmgr.wsdl`.
- **CES (Certificate Enrollment Web Service)** — MS-WSTEP. Translates SOAP requests into the same ICertPassage RPCs. Permits enrollment across forests / DMZ without file shares or RPC port exposure.

The combination of CEP + CES enables **key-based renewal** (`msPKI-Certificate-Name-Flag` bit 0x4000000 set on the template), where a client with an expiring cert renews using the old cert's private key for authentication (not the user password). Useful for unattended hosts.

## HTTP / DCOM endpoints

| Purpose | Protocol | Default port | Notes |
|---|---|---|---|
| Legacy enrollment | DCOM/RPC (ICertPassage) | Ephemeral via TCP 135 epmapper | Requires RPC dynamic port range. |
| Web enrollment UI | HTTP/HTTPS | 80 / 443 | `certsrv` virtual directory under IIS. |
| CEP | SOAP/HTTPS | 443 | MS-XCEP. |
| CES | SOAP/HTTPS | 443 | MS-WSTEP. One endpoint per auth mode. |
| OCSP responder | HTTP | 80 | Online Responder service (`ocsp.exe`), separate from CertSvc. |

## Configuration / code examples

### Wireshark filter — capture enrollment

```
# ICertPassage (legacy)
dcerpc.if_id == 91b9b93a-57b4-11d0-8f16-00a0484d6c9c
# or via dispinterface — capture all dcerpc to the CA host
ip.addr == <ca_ip> && (dcerpc.pkt_type == 0 || dcerpc.pkt_type == 2)
# CES via SOAP
http.request.uri contains "CES" && http.request.method == "POST"
```

### PowerShell — enumerate templates and request

```powershell
# List templates visible to current user
Get-CATemplate | Sort-Object Name

# Show template ACLs (who can enroll)
$tmpl = Get-ADObject -Filter * -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com" -Properties nTSecurityDescriptor
$tmpl | ForEach-Object {
    $acl = $_.nTSecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
    $acl | Where-Object { $_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight `
                          -and $_.ObjectType -eq "0e10c968-78fb-11d2-90d4-00c04f79dc55" }  # "Enroll" right GUID
} | Format-Table IdentityReference, AccessControlType

# Submit request via certreq
certreq -new -config "CA01.example.com\Example-Enterprise-CA" request.inf newcert.cer
# Or via CMP (Certificate Management Protocol over CMS, RFC 4210) — AD CS does NOT natively speak CMP.
```

### Python — issue a cert request via `certenc` COM

```python
import win32com.client

# Connect to ICertRequest2 via pywin32
CERTADMIN = win32com.client.Dispatch("CertificateAuthority.Request")
# strConfig form: "<server>\<CAName>"
strConfig = "CA01.example.com\\Example-Enterprise-CA"
# Submit a PKCS#10 CSR (DER-encoded base64)
csr_b64 = open("request.b64").read().strip()
disposition = CERTADMIN.Submit(
    0,                       # Flags: 0 = no CR_IN_BASE64HEADER, raw base64
    csr_b64,                 # Request
    "",                      # Attributes string ("CertificateTemplate:Machine")
    strConfig
)
print(f"Disposition: {disposition}")  # 3 = issued, 5 = denied, 5 = under submission
if disposition == 3:
    cert_b64 = CERTADMIN.GetCertificate()
    open("issued.cer","w").write(f"-----BEGIN CERTIFICATE-----\n{cert_b64}\n-----END CERTIFICATE-----\n")
```

For Linux clients enrolling against AD CS: `certmonger` with the `cepces` plugin (SOAP over HTTPS to CES + CEP). See `../09-linux-equivalents/08-freeipa-trust.md` for FreeIPA's own CA (Dogtag).

### Registry — disable weak algorithm

```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\CSP\
 ├── Provider Type  = 24  (PROV_RSA_AES, 24 = KSP via CNG)
 └── HashAlgorithm  = SHA256
```

For an existing CA, rotate the CA cert + key with `certutil -renewCAcert` after algorithm change.

## Troubleshooting

- **`CERTSRV_E_UNSUPPORTED_CERT_TYPE` (0x80094800)** — caller lacks Enroll ACE on template. Inspect template ACL via `Get-ADObject` + `nTSecurityDescriptor`. The Enroll right's ObjectType GUID is `0e10c968-78fb-11d2-90d4-00c04f79dc55`; Auto-Enroll is `a05b8cc2-17bc-4802-a710-e7c15ab866a2`.
- **CRL not publishing to AD** — exit module blocked by firewall on TCP/389 outbound, or CA service account lacks Write to `CN=<CAName>,CN=AIA,CN=Public Key Services,...`. Symptom: `certutil -view -restrict "RevocationDate>now" -out "*"` succeeds but `dsquery * "CN=Example-CA,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=..." -attr certificateRevocationList` returns empty.
- **Database -1022 (JET_errDiskRead)** — SAN path failure; restore from backup. Do not run `eseutil /p` on the CA DB — ESE corruption on a CA almost always means restoring from backup, not patching.
- **Key recovery** — If the KRA (Key Recovery Agent) certs were never issued, you cannot recover archived private keys. Detection: `certutil -getreg CA\KeyRecovery`; if `KeyRecoveryAgents` count is 0, archival never happened.
- **OCSP responder not publishing revocations** — OCSP provider reads from the CA's `CRLTable`. Verify the OCSP service is reading the right CA: `Get-OCSPCAConfig | Format-List CAConfigString, SignCert, SignProviderCNG`.

## Cross-platform equivalents

- **Linux**: FreeIPA ships Dogtag PKI (`pki-tomcatd`) as its CA. Dogtag uses an LDAP directory (389-DS) as its cert DB, supports CMP, SCEP, and a REST API. See `../09-linux-equivalents/08-freeipa-trust.md`.
- **Linux**: `certmonger` daemon + `cepces` plug-in enrolls Linux hosts against AD CS via CES/CEP. See `../09-linux-equivalents/01-sssd-ad-provider.md`.
- **Linux**: HashiCorp Vault PKI secrets engine — stateless CA, no DB, issues via PKCS#8 / PKCS#10 API. Not a full AD CS replacement but commonly used as issuing CA tier under an offline HSM-protected root.
- **macOS**: Apple no longer ships a CA in macOS Server (deprecated in 5.x). For device-cert enrollment against AD CS, use Microsoft Intune push (`Microsoft.CompanyPortal` in Mac App Store) or Profile Manager with SCEP → AD CS NDES server role. See `../08-macos-equivalents/04-platform-sso-extension.md` for Platform SSO device-cert flow.

## References

- MS-WCCE — Windows Client Certificate Enrollment Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-wcce>
- MS-XCEP — X.509 Certificate Enrollment Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-xcep>
- MS-WSTEP — WS-Trust Enrollment Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-wstep>
- MS-CERSOD — Certificate Services Domain. <https://learn.microsoft.com/openspecs/windows_protocols/ms-cersod>
- PKI Administrative tools, `certutil.exe` reference, MS Learn.
- RFC 5280 — X.509 Internet PKI Certificate and CRL Profile.
- RFC 6960 — OCSP.
