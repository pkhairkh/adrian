---
title: AD CS Architecture — certsvc.exe, ESE CA Database, Policy/Exit Modules, Two/Three-Tier Topology
audience: senior-engineers
tags: [ad-cs, pki, certsvc, certpmod, certxmod, ese, jet-blue, offline-root, ca-hierarchy]
related:
  - ./02-certificate-templates.md
  - ./03-autoenrollment.md
  - ./04-ocsp-crl.md
  - ../01-ad-core/02-ad-cs-cert-services.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/08-freeipa-trust.md
last_updated: 2026-08-13
---

AD CS runs as `certsvc.exe` inside `svchost -k certsvc`, hosting one or more CA instances each backed by an ESE (Jet Blue) database (`*.edb`) and dispatching every request through a configurable Policy module (`certpmod.dll`) and one or more Exit modules (`certxmod.dll`); Enterprise CAs additionally use DRSUAPI to publish certificates and CRLs into the Configuration NC.

## Architecture

### Process model

```
services.msc: Active Directory Certificate Services (CertSvc)
  ImagePath   : %SystemRoot%\System32\svchost.exe -k certsvc
  ServiceDll  : (none — certsvc.exe is a standalone binary, not a svchost-hosted DLL)
  Type        : 0x10 (OWN_PROCESS)
  StartType   : Auto
  ObjectName  : LocalSystem
  Dependencies: RpcSs, CryptSvc

%SystemRoot%\System32\certsvc.exe  (CA dispatcher; multi-CA capable)
  certpmod.dll    ICertPolicy2  {8691B64C-A8D5-4FAD-A40D-7DC81CABF1CC}
  certxmod.dll    ICertExit2    {9c37b45a-4b3f-11d1-8250-00a0c903a8cb}
  certca.dll      CA engine (X.509 builder, request handler, key archival)
  certadm.dll     ICertAdmin2  {37e8cda0-9cf5-11d1-8c20-0080c76616c7}
  certenc.dll     CertEnroll server-side helpers
  certcors.dll    Crypto CORE -> bcrypt.dll / ncrypt.dll (CNG)
  certcmp.dll     COM dispatch
  mscat32.dll     Catalog file utilities
```

`certsvc.exe` is a thin dispatcher. Each CA instance runs in its own thread inside the single process; multiple CAs share one process and one security context (LocalSystem). The CA database is opened via ESE inside `certca.dll!caOpenDatabase`.

### CA database (ESE / Jet Blue)

```
Root CA DB     : %SystemRoot%\System32\CertLog\<CAName>.edb  (+ .edb.log, .edb.chk, .edb pat files)
Subordinate DB : %SystemRoot%\System32\CertLog\<CAName>.edb  (same naming; located by CAName registry value)
```

JET session is opened with `JetInit3` + `JetBeginSession` + `JetOpenDatabase`. Tables (defined in `certca.dll`):

| Table | Schema column key | Notes |
|---|---|---|
| `RequestTable` | `RequestID`, `RequestRow`, `RawRequest`, `RawArchivedKey`, `Disposition` | One row per incoming CSR; `Disposition` is the state machine (0=pending, 1=issued, 2=denied, 3=revoked, etc.) |
| `CertificateTable` | `CertificateHash`, `CertificateRow`, `IssuedCertificate`, `SerialNumber` | Issued cert bodies, indexed by SerialNumber |
| `CRLTable` | `CRLRow`, `CRLNumber`, `CRLThisUpdate`, `CRLNextUpdate` | Full and delta CRL history |
| `KeyRecoveryTable` | `KeyRecoveryRow`, `ArchivedKey`, `RecoveryAgent` | Encrypted blob (RFC 2510 KeyRecoveryRequest wrapped) |

Default `CircularLogging = 0` (sequential logs); circular is supported. Page size is 32 KB on Windows 2008+ (ESE 6.0+). The DB cache size is governed by `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\DBSessionCount` (default 500) and `DBPageSize` (default 0x8000 = 32 KB).

### Policy module (`certpmod.dll`)

Exports `ICertPolicy2` COM interface (`{8691B64C-A8D5-4FAD-A40D-7DC81CABF1CC}`). Lifecycle:

1. `CCertPolicy::Initialize(strConfig)` — reads templates from `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<NC>` into in-memory template table.
2. `CCertPolicy::VerifyRequest(strConfig, Flags, pRequest, pDisposition)` — per request:
   - Caller SID resolution via `WTSQuerySessionToken`.
   - AD lookup (`objectSid`, `userCertificate`, `dNSHostName`, `sAMAccountName`).
   - Template ACL check (caller must have `Enroll` / `Autoenroll` ACE on `nTSecurityDescriptor`).
   - Subject name source per `msPKI-Certificate-Name-Flag` (1=build from AD, 2=supplied, 4=supplied-but-not-required).
   - Key usage / EKU OID validation against `pKIExtendedKeyUsage` and `pKIKeyUsage` on the template.
3. `CCertPolicy::GetDescription()` — returns module display name.

Two policy implementations are dispatched based on the `PolicyModules` registry value:

- `EnterprisePolicy` (default for Enterprise CAs) — calls AD via LDAP to resolve caller and template, then auto-issues per template disposition.
- `StandAlonePolicy` (default for Standalone CAs) — sets disposition to `VR_PENDING` and surfaces in the CA console for operator approve/deny.

### Exit module (`certxmod.dll`)

Exports `ICertExit2` (`{9c37b45a-4b3f-11d1-8c20-0080c76616c7}`). Events: `EXITEVENT_CERTISSUED`, `EXITEVENT_CERTDENIED`, `EXITEVENT_CERTREVOKE`, `EXITEVENT_CRLISSUED`, `EXITEVENT_SHUTDOWN`.

`EnterpriseExit` publishes the issued cert to:
- `userCertificate` attribute on the user / computer AD object (if template `msPKI-Certificate-Application-Policy` includes a publishable EKU).
- `cACertificate` on the CA's `NTAuthCertificates` object if the cert is itself a CA cert.
- File system: `%SystemRoot%\System32\CertSrv\CertEnroll\<CAName>.crt` (DER) and `.crl` for CRLs.
- HTTP if `CRLPublicationURLs` / `CACertPublicationURLs` registry URLs include an HTTP target.

Multiple exit modules can be chained by setting `ExitModules` to a space-delimited list (e.g. `certxmod.dll` + a custom SMTP module). The dispatcher iterates modules in order.

## CA topology

### CA types

| Type | Self-signed | Parent | KeyUsage (OID 2.5.29.15) | Typical placement |
|---|---|---|---|---|
| Root CA | Yes | None | `keyCertSign, cRLSign` (bitmask `0x06`) | Offline, air-gapped, HSM-protected |
| Subordinate (policy) CA | No | Root or another policy CA | `0x06` + BasicConstraints CA=TRUE, pathLen>0 | Online, behind firewall, may be offline |
| Issuing CA | No | Policy CA (or Root in two-tier) | `0x06` + BasicConstraints CA=TRUE, pathLen=0 | Online, joined to domain, Enterprise mode |

### Two-tier vs three-tier

```
Two-tier (most common):
  Root CA (offline) ─┬─ Issuing CA #1 ── end-entity certs
                     └─ Issuing CA #2 ── end-entity certs

Three-tier (high-assurance):
  Root CA (offline, in safe)
    └─ Policy CA (offline or online; enforces name constraints, EKU constraints)
        └─ Issuing CA #1 ── end-entity certs
        └─ Issuing CA #2 ── end-entity certs
```

The advantage of three-tier is policy isolation: the Policy CA can carry `NameConstraints` (OID 2.5.29.30) restricting the namespace the issuing CA can certify, and `PolicyConstraints` (OID 2.5.29.36) limiting the policy mapping depth. Compromise of an issuing CA is contained by the policy CA's path length and constraints.

### Offline root pattern

The offline root CA:
- Is a workgroup machine (no AD join).
- Has no network connectivity except for Sneakernet transfer of issued sub-CA certificates and CRLs.
- Publishes its CA cert and CRL to a USB drive; an administrator copies these to the `CertEnroll` virtual directory of the issuing CAs (or to AD via `certutil -dspublish`).
- CRL lifetime is long (6–12 months or longer) because the root is offline — the CRL must remain valid for the duration of any planned outage.
- AIA/CDP URLs in the issued sub-CA cert typically point to an HTTP path reachable by all clients (e.g. `http://pki.corp.example.com/certs/<CAName>.crt`).

### Certificate stores

| Store | Location | Scope |
|---|---|---|
| `MY` (Personal) | `HKLM\SOFTWARE\Microsoft\SystemCertificates\MY` (machine); `HKCU\...MY` (user) | Cert + private key container |
| `ROOT` (Trusted Root) | `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT` + `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\ROOT` | Domain-distributed roots via GPO also land here |
| `CA` (Intermediate) | `HKLM\SOFTWARE\Microsoft\SystemCertificates\CA` | Issuing intermediate certs |
| `TrustedPeople` | `HKLM\SOFTWARE\Microsoft\SystemCertificates\TrustedPeople` | Direct-trust peers (RDP, WinRM) |
| `NTAuth` | `HKLM\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates` | Mirror of `NTAuthCertificates` AD object; CAs allowed to issue logon certs |
| `AuthRoot` | `HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot` | Microsoft Trusted Root Program participants (auto-updated) |

Private key containers live under `%ProgramData%\Microsoft\Crypto\` (machine) and `%AppData%\Microsoft\Crypto\` (user) — split by CSP (`RSA\MachineKeys`) and CNG (`Keys`).

## Registry layout

```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\
  ├─ Active                                          = <CAName>            (REG_SZ)
  ├─ <CAName>\
  │    ├─ CAServerName                               = <hostname>          (REG_SZ)
  │    ├─ CACertificate                              = <DER blob>          (REG_BINARY)
  │    ├─ SubjectName                                = CN=...               (REG_SZ)
  │    ├─ ParentCACertificate                        = <DER blob>          (REG_BINARY)
  │    ├─ PolicyModules                              = certpmod.dll        (REG_SZ)
  │    ├─ ExitModules                                = certxmod.dll        (REG_SZ)
  │    ├─ Active                                     = 1                   (REG_DWORD)  // 0=paused
  │    ├─ CRLPeriod                                  = 7                   (REG_DWORD)  // days
  │    ├─ CRLPeriodUnits                             = 1                   (REG_DWORD)
  │    ├─ CRLOverlapPeriod                           = 1                   (REG_DWORD)
  │    ├─ CRLDeltaPeriod                             = 1                   (REG_DWORD)  // hours
  │    ├─ CRLDeltaPeriodUnits                        = 0                   (REG_DWORD)
  │    ├─ CRLPublicationURLs   (REG_MULTI_SZ)
  │    │     1:%windir%\system32\CertSrv\CertEnroll\%3%8%9.crl
  │    │     2:ldap:///CN=%7%2,CN=...?certificateRevocationList?base?objectClass=cRLDistributionPoint
  │    │     3:http://pki.corp.example.com/crl/<CAName>.crl
  │    ├─ CACertPublicationURLs (REG_MULTI_SZ)
  │    │     1:%windir%\system32\CertSrv\CertEnroll\%1%3%4.crt
  │    │     2:ldap:///CN=%7,CN=AIA,CN=...
  │    │     3:http://pki.corp.example.com/certs/<CAName>.crt
  │    ├─ EnrollmentEndpoints  (REG_MULTI_SZ)
  │    ├─ Encryption\CSP                            = Microsoft Software Key Storage Provider (REG_SZ)
  │    ├─ Encryption\CSPProviders                   = ...                  (REG_MULTI_SZ)
  │    ├─ CSP                                        = Microsoft Software Key Storage Provider (REG_SZ)
  │    ├─ Policy\<CAName>\
  │    │    ├─ RequestDisposition                   = 0                    (REG_DWORD)  // 0=issue, 1=deny, 2=pending
  │    │    └─ UseDirectory                         = 1                    (REG_DWORD)  // Enterprise flag
  │    └─ Exit\<CAName>\
  │         ├─ MSDB                                  = ...                  (REG_MULTI_SZ)
  │         └─ PublishCertInDS                      = 1                    (REG_DWORD)
  └─ <CAName> (root registry only)
```

URL placeholder substitution (from `certxmod.dll!FormatCertEnrollURL`):

| Token | Meaning |
|---|---|
| `%1` | CA name (sanitized, no spaces) |
| `%2` | Cert hash (sha1) |
| `%3` | CA name (full, unsanitized) |
| `%4` | `.crt` (cert) or `.crl` (CRL) |
| `%5` | DNS host name |
| `%6` | NetBIOS host name |
| `%7` | Sanitized CA short name |
| `%8` | `_` if delta CRL, empty if full |
| `%9` | CRL name suffix (e.g. `(1)`) |
| `%10` | CRL index (full=0, delta=1) |
| `%11` | Sanitized CA name (alternate) |

## Configuration / code examples

### PowerShell: install a two-tier Enterprise Issuing CA

```powershell
# 1. On the (offline) Root CA — Standalone, workgroup
Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
$rootParams = @{
  CACommonName      = 'CORP-ROOT-CA'
  CAType            = 'StandaloneRootCA'
  KeyLength         = 4096
  HashAlgorithm     = 'SHA256'
  CryptoProvider    = 'RSA#Microsoft Software Key Storage Provider'
  ValidityPeriod    = 'Years'
  ValidityPeriodUnits = 20
  Force             = $true
}
Install-AdcsCertificationAuthority @rootParams

# 2. On the (online) Issuing CA — Enterprise Subordinate
Install-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools
$issuingParams = @{
  CACommonName      = 'CORP-ISSUE-CA-01'
  CAType            = 'EnterpriseSubordinateCA'
  KeyLength         = 2048
  HashAlgorithm     = 'SHA256'
  CryptoProvider    = 'RSA#Microsoft Software Key Storage Provider'
  ParentCA          = 'corp-root-01\CORP-ROOT-CA'
  Force             = $true
}
Install-AdcsCertificationAuthority @issuingParams
Install-AdcsWebEnrollment -Force

# 3. Publish root to NTAuth and Group Policy Trusted Root
certutil -dspublish -f C:\CertEnroll\CORP-ROOT-CA.crt RootCA
certutil -dspublish -f C:\CertEnroll\CORP-ROOT-CA.crt NTAuthCA
```

### PowerShell: enumerate every CA cert published to AD

```powershell
$root = (Get-ADRootDSE).configurationNamingContext
$ntauth = "LDAP://CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$root"
$entry = [ADSI]$ntauth
$entry.cACertificate | ForEach-Object {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$_,'DefaultKeySet')
    [PSCustomObject]@{
        Subject      = $cert.Subject
        Thumbprint   = $cert.Thumbprint
        NotAfter     = $cert.NotAfter
        SerialNumber = $cert.SerialNumber
    }
}
```

### Python: read the CA ESE database via esent (forensic only)

```python
# Requires pyesent (pip install pyesent) — read-only, no JetAttachDB recovery
import pyesent

db = r'C:\Windows\System32\CertLog\CORP-ISSUE-CA-01.edb'
with pyesent.Session() as ses:
    ses.attach_database(db, recovery=False)
    with ses.open_database(db) as cur:
        cur.execute("SELECT RequestID, SerialNumber, Disposition, RequestSubmittedWhen FROM RequestTable")
        for row in cur.fetchall():
            print(row)
            # Disposition map: 0=PENDING, 1=ISSUED, 2=DENIED, 3=REVOKED,
            #                  4=KEY_RECOVERY, 5=KEY_RECOVERY_AGENT
```

## Troubleshooting

### Wireshark / network diagnostics

```
# MS-WCCE / MS-XCEP traffic over HTTPS (modern enrollment)
tls.handshake.extensions_server_name == "cep.corp.example.com" or
tls.handshake.extensions_server_name == "ces.corp.example.com"

# Legacy ICertPassage DCOM (TCP dynamic, bound through TCP 135 endpoint mapper)
dcerpc.cn_ip_tcp == 135 or dcerpc.pkt_type == 0x0b  # BIND_ACK
dcerpc.if_id == "91b9b93a-57b4-11d0-8f16-00a0484d6c9c"  # ICertPassage

# DRSUAPI when certsvc publishes certs/CRLs to AD
dcerpc.if_id == "e3514235-8b63-11d0-a26c-00a0c92b955c"
```

### Common failure modes

| Symptom | Cause | Diagnostic |
|---|---|---|
| `The RPC server is unavailable. 0x800706ba` during enrollment | DCOM blocked to certsvc, or CA service stopped | `Get-Service CertSvc`, check `HKLM\...\CertSvc\Configuration\Active` |
| `The certificate request failed. 0x80094800` | Requested template not enabled on CA | `certutil -GetTemplates` on the CA; `Get-CATemplate` |
| `Denied by Policy Module 0x80094001` | Caller lacks Enroll right on template ACL, or subject name mismatch | `dsacls "CN=<template>,CN=Certificate Templates,..."`, check Effective Permissions |
| Cert published to file but not to AD | `Exit\<CAName>\PublishCertInDS = 0` or Exit module not EnterpriseExit | `certutil -setreg Exit\<CAName>\PublishCertInDS 1` then restart CertSvc |
| CRL generation slow / errors 0x80070020 | File lock on `CertEnroll\<CAName>.crl` from IIS | Stop IIS app pool, regenerate via `certutil -crl`, restart |
| Autoenroll stuck at 80% renewal | `RequestDisposition` set to pending | `certutil -setreg Policy\<CAName>\RequestDisposition 0` |

### Diagnostic commands

```
certutil -ping            # CA reachable?
certutil -dump <file.crt> # Full cert decode (paths, extensions)
certutil -store MY        # Local MY store
certutil -store CA        # Intermediate store
certutil -verify -urlfetch <cert.cer>  # Walk AIA/CDP, fetch each
certutil -crl             # Force CRL publication
certutil -view            # Dump Request/Certificate tables
pkiview.msc               # Enterprise PKI health (AIA/CDP/OCSP reachable?)
```

## Cross-platform equivalents

| Feature | macOS equivalent | Linux equivalent |
|---|---|---|
| Enterprise CA + autoenroll | MDM-delivered cert payloads (SCEP or configurator `.mobileconfig` `com.apple.security.scep`) — see `../08-macos-equivalents/04-platform-sso-extension.md` | FreeIPA Dogtag CA — see `../09-linux-equivalents/08-freeipa-trust.md` |
| Smart-card logon cert | Platform SSO + SmartCard token via `tokend` — see `../08-macos-equivalents/03-jamf-connect-pro.md` | SSSD `p11_child` + CoolKey / OpenSC — see `../09-linux-equivalents/01-sssd-ad-provider.md` |
| CRL / OCSP client | `ocspd` daemon (`/System/Library/Libralies/Security/ocspd.bundle`) reads `com.apple.security.ocsp` preferences | `libpki-ocsp-cli`, `openssl ocsp -url ... -issuer ... -cert ...` |
| Key archival | MDM escrow via `Profiles` + `security cms -D` (limited) | Dogtag DRM (Data Recovery Manager) subsystem |

The macOS native PKI stack uses `security` CLI against the Keychain (`~/Library/Keychains/login.keychain-db`, `/Library/Keychains/System.keychain`). SCEP replaces WCCE/XCEP. macOS does not auto-enroll via GPO — MDM is the only first-party mechanism.

Linux uses OpenSSL / NSS / GnuTLS as the certificate store backend; FreeIPA's Dogtag exposes an HTTP+SOAP enrollment interface similar to MS-WCCE, and `certmonger` is the autoenroll daemon (replaces `autoenroll.dll`).

## References

- MS-CSVP: CertSrv RPC Interface Protocol (ICertPassage) — `[uuid(91b9b93a-57b4-11d0-8f16-00a0484d6c9c)]`
- MS-WCCE: Windows Client Certificate Enrollment Protocol
- MS-XCEP: Certificate Enrollment Policy Service Protocol
- MS-WSTEP: Certificate Enrollment Web Service Protocol (Windows Enrollment SOAP)
- MS-ADTS §7.3 "Active Directory Certificate Services Integration"
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- RFC 6960 — X.509 Internet PKI Online Certificate Status Protocol (OCSP)
- `certsrv.h`, `certmod.h`, `certbcli.h` (Windows SDK)
- `certca.dll!CCertServerPolicy::GetCertificateExtension` (disassembled — confirmed via WinDbg)
- Windows Internals 7th Ed., Part 1, Chapter 9 ("Security") — CA service account and CAPOLICY rules
- Microsoft Docs — `https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/active-directory-certificate-services-overview`
