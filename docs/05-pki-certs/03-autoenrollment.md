---
title: Autoenrollment Internals — autoenroll.dll, XCEP/WCCE Policy Discovery, Key Archival, AD Publication, certutil -pulse
audience: senior-engineers
tags: [ad-cs, pki, autoenrollment, autoenroll-dll, ms-xcep, ms-wcce, key-archival, cng, certutil-pulse]
related:
  - ./01-ad-cs-architecture.md
  - ./02-certificate-templates.md
  - ./04-ocsp-crl.md
  - ../01-ad-core/02-ad-cs-cert-services.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/01-sssd-ad-provider.md
last_updated: 2026-08-13
---

Autoenrollment is the client-side `autoenroll.dll` invoked by Group Policy (User/Machine Config → Windows Settings → Security Settings → Public Key Policies → Certificate Services Client - Auto-Enrollment) which performs XCEP (MS-XCEP) policy discovery against a CEP endpoint, submits CSRs over WCCE (MS-WCCE) DCOM or WSTEP (MS-WSTEP) HTTPS to a CES endpoint, and publishes the resulting certificate into the requester's `userCertificate` AD attribute via the CA Exit module.

## Architecture

### Trigger sources

| Trigger | Mechanism | Notes |
|---|---|---|
| Group Policy refresh | `gpsvc.dll` calls CSE `{71587597-1207-11D2-8250-00A0C903A8CB}` (Autoenroll CSE) → `autoenroll.dll!PingAutoEnroll` | Default 90-min + 0-30 min jitter; explicit `gpupdate /target:user /force` runs immediately |
| Logon / startup | `winlogon` fires GPO refresh → triggers CSE | First-time enroll typically happens here |
| Task Scheduler | `\Microsoft\Windows\CertificateServicesClient\AutoEnroll` task triggers on event log or schedule | Created by GPO; runs even if user not logged in |
| Manual | `certutil -pulse` or `certutil -pulse -user` | Wraps `ICertConfig::Reset` + `autoenroll.dll!EnrollTrigger` |
| Renewal timer | `autoenroll.dll` schedules `Win32_CreateTimerQueueTimer` at 80% of cert lifetime | Default; per-template `pKIOverlapPeriod` overrides |

The CSE GUID `{71587597-1207-11D2-8250-00A0C903A8CB}` is registered at `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{71587597-...}` with `DllName = %SystemRoot%\system32\autoenroll.dll`.

### Process model

`autoenroll.dll` is in-process to the GPO refresh host:
- User policy: `svchost -k netsvcs` (Group Policy service `gpsvc`) running as the user via impersonation; also `logonui` / `explorer` for logon-triggered runs.
- Computer policy: `gpsvc` running as LocalSystem.

The DLL exports `ProcessGroupPolicy` and `ProcessGroupPolicyEx` (per `userenv.h` GROUP_POLICY_OBJECT struct).

### GPO configuration

```
Computer Configuration / Windows Settings / Security Settings / Public Key Policies /
  Certificate Services Client - Auto-Enrollment

Registry (per CSE scope):
HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment
  ├─ AEPolicy                                 = 0x7  (REG_DWORD)
  │      bit 0 = enabled
  │      bit 1 = renew expired
  │      bit 2 = update certs (manage superseded)
  │      bit 3 = remove revoked
  ├─ ProcessRecoveryAgentEntries             = 1   (REG_DWORD)
  ├─ EnabledRenewals                          = 1   (REG_DWORD)
  └─ CheckExistingDeltaCRLsPeriod            = 8   (REG_DWORD) hours
```

User-side mirror under `HKCU\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment`.

## Enrollment flow

### Phase 1: policy discovery (MS-XCEP)

```
Client → CEP server (HTTPS POST, SOAP 1.1):
  POST /ADPolicyProvider/CertificateEnrollment/Service.svc/CEP HTTP/1.1
  SOAPAction: "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
  Content-Type: application/soap+xml; charset=utf-8

  <wstep:GetPolicies xmlns="...">
    <client:Client lastUpdate="..." preferredLanguage="en-US">
      <client:NotBefore>2026-01-01T00:00:00Z</client:NotBefore>
      <client:NotAfter>2027-01-01T00:00:00Z</client:NotAfter>
    </client:Client>
    <request:Request targetFilter="..." />
  </wstep:GetPolicies>
```

Response: one `<policy:Policy>` element per template the client can see (ACL-filtered). Each contains `policy:PolicyOIDReference`, `policy:Attributes.PrivateKeyAttributes` (algorithm, key length, exportable, attestation flags), and `policy:Extensions` (EKU list).

Client filters policies by:
1. Calling user's domain (cross-forest enrollment requires explicit CEP/CES configuration).
2. EKU vs context (e.g., client auth templates for `User` scope, server auth for `Machine`).
3. `msPKI-Template-Schema-Version` ≥ 1 (v2/v3 templates only — v1 cannot be auto-enrolled).

### Phase 2: request submission (MS-WCCE or MS-WSTEP)

If CES is configured for the template (`EnrollmentEndpoints` registry on the client), client uses WSTEP over HTTPS:

```
POST /CertEnroll/<CAName>_CES_Kerberos/service.svc/CES HTTP/1.1
Content-Type: application/soap+xml; charset=utf-8

<wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <wst:TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/Reference</wst:TokenType>
  <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
  <wst:BinaryExchange>  <!-- PKCS#10 CSR, base64 -->
    MIICzDCCAbSgAwIBAg...
  </wst:BinaryExchange>
</wst:RequestSecurityToken>
```

Otherwise (same-domain, DCOM open), client uses MS-WCCE opnum 36 (`Request`) on ICertPassage:

```python
# NDR-encode the request (simplified — see MS-WCCE §2.2.3.1)
request_attrs  = b"CertificateTemplate:User\x00"
request_attrs += b"RequesterName:CORP\\jdoe\x00"
csr_pkcs10 = ... # DER-encoded

# DCOM call to ICertPassage.Request
disposition, cert_blob = icert.Request(0, request_attrs, csr_pkcs10)
```

### Phase 3: key generation

Client picks crypto provider based on template:

| Template `msPKI-Template-Schema-Version` | `msPKI-Private-Key-Flag` USE_LEGACY_PROVIDER bit | Provider |
|---|---|---|
| 2 (v2) | 0 or 1 | Legacy CSP via `rsaenh.dll` (RSA) or `dssenh.dll` (DSA); default `Microsoft Enhanced Cryptographic Provider v1.0` |
| 2 (v3/CNG) | 0 | CNG KSP via `ncrypt.dll`; default `Microsoft Software Key Storage Provider` |
| 2 (v3/CNG + TPM) | 0 + attestation bit | `Microsoft Platform Crypto Provider` (TPM-bound) |

Private key container paths:
- Legacy CSP, machine: `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys\<GUID>`
- Legacy CSP, user: `%AppData%\Microsoft\Crypto\RSA\<SID>\<GUID>`
- CNG KSP, machine: `%ProgramData%\Microsoft\Crypto\Keys\<GUID>\<filename>`
- CNG KSP, user: `%AppData%\Microsoft\Crypto\Keys\<GUID>\<filename>`
- TPM KSP: TPM-internal handle (no filesystem path)

### Phase 4: key archival (if template requires)

When `msPKI-Private-Key-Flag` bit `REQUIRE_PRIVATE_KEY_ARCHIVAL` (0x8) is set, the CSR is wrapped using the CA's published Key Recovery Agent (KRA) certificate(s) per RFC 2511 (CMS `EnvelopedData`):

```
PKCS#10 CSR augmented with attribute id-aa-kRAKeyInformation (1.3.6.1.4.1.311.21.21):
  The request body is encrypted to the KRA cert's RSA public key
  (PKCS#7 EnvelopedData, AES-256 content key, RSA-OAEP wrap)
```

The CA's `certca.dll!KRAArchiveRequest` decrypts the envelope using the KRA private key (only after operator-initiated recovery), then stores the original private key in the `KeyRecoveryTable` row linked to the issued certificate's `CertificateHash`.

KRA certificates are published to AD `CN=KRAContainer,CN=Public Key Services,CN=Services,CN=Configuration,...`. The CA reads them at service start; the registry value `HKLM\...\CertSvc\Configuration\<CA>\KeyRecoveryAgentCount` (default 1) controls how many KRAs are needed for quorum.

### Phase 5: certificate publication

The CA's Exit module publishes the issued certificate to AD by calling `certxmod.dll!PublishToDS`:

- User certs → `userCertificate` attribute (multivalued binary) on the user object (`CN=<user>,CN=Users,DC=...`).
- Computer certs → `userCertificate` attribute on the computer object (`CN=<computer>,CN=Computers,DC=...`).
- DC certs → `userCertificate` on the DC's NTDS Settings parent (`CN=<dc>,OU=Domain Controllers,DC=...`).
- CA certs → `cACertificate` on the `NTAuthCertificates` object (`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,...`) — published by `certutil -dspublish` on the CA.

The exit module's LDAP call is `ldap_modify_s` with `LDAP_MOD_REPLACE` on the `userCertificate` attribute; multiple values are appended, and the value set is bounded by the schema attribute `rangeUpper` (10240 bytes per cert, no count limit).

Client-side, the cert is also written to the local `MY` store via `CertAddCertificateContextToStore(HCERTSTORE, ..., CERT_STORE_ADD_REPLACE_EXISTING, ...)`.

### Phase 6: renewal logic

Default renewal trigger: at 80% of cert lifetime, the autoenroll timer fires and a renewal CSR is submitted. The new CSR is signed with the existing cert's private key (`CERT_KEY_CONTEXT` reused), and the new cert is written to MY store; the old cert is purged if `REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE` (0x100 in `msPKI-Enrollment-Flag`) is set.

Template-supplied `pKIOverlapPeriod` (FILETIME) overrides the 80% default — the renewal trigger fires at `expiry - overlapPeriod`.

Cross-cert renewal: if the cert's chain crosses a CA cert renewal boundary, the client may need to enroll via the renewed CA cert (published under new serial but same subject + `AuthorityKeyIdentifier` matches).

## Configuration / code examples

### PowerShell: enable user + machine autoenroll via GPO registry

```powershell
# New GPO linked to an OU
$gpo = New-GPO -Name "PKI AutoEnrollment" -Domain "corp.example.com"

# Computer-side policy
$gpo | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment" `
        -ValueName "AEPolicy" -Type DWord -Value 0x7
$gpo | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment" `
        -ValueName "EnabledRenewals" -Type DWord -Value 1
$gpo | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment" `
        -ValueName "ProcessRecoveryAgentEntries" -Type DWord -Value 1

# User-side policy
$gpo | Set-GPRegistryValue -Key "HKCU\Software\Policies\Microsoft\Cryptography\AutoEnrollment" `
        -ValueName "AEPolicy" -Type DWord -Value 0x7

New-GPLink -Guid $gpo.Id -Target "OU=Workstations,DC=corp,DC=example,DC=com" -LinkEnabled Yes

# Force on a single client:
gpupdate /target:computer /force
certutil -pulse
```

### PowerShell: configure CEP and CES endpoints via GPO

```powershell
# Computer-side CEP/CES endpoint registration
$gpo = Get-GPO -Name "PKI AutoEnrollment"
$gpo | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Cryptography\PolicyServers" `
        -ValueName "1" -Type String `
        -Value "0:<ldap>ldap:///CN=CEP,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=com?1?cert enrollment?...?%"
# Or via the Enrollment Policy Server LDAP URL:
$gpo | Set-GPRegistryValue -Key "HKLM\Software\Policies\Microsoft\Cryptography\PolicyServers" `
        -ValueName "Flags" -Type DWord -Value 0x6  # allow flag bits

# Use EnrollmentPolicyServer cmdlets (Windows 8+):
$v = @{
    Url       = 'https://cep.corp.example.com/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP'
    Auth      = 'Kerberos'
    Priority  = 1
    AutoDiscover = $false
}
Add-CertificateEnrollmentPolicyServer @v -NoClobber -Context Machine
```

### Python: simulate a minimal XCEP GetPolicies request

```python
import requests, base64
from datetime import datetime, timezone

cep_url = "https://cep.corp.example.com/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP"

envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:cep="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
    <a:To>{cep_url}</a:To>
  </s:Header>
  <s:Body>
    <cep:GetPolicies>
      <cep:client lastUpdate="2026-08-13T00:00:00Z" preferredLanguage="en-US">
        <cep:notBefore>2026-08-13T00:00:00Z</cep:notBefore>
        <cep:notAfter>2027-08-13T00:00:00Z</cep:notAfter>
      </cep:client>
      <cep:request targetFilter="" />
    </cep:GetPolicies>
  </s:Body>
</s:Envelope>"""

r = requests.post(cep_url, data=envelope,
                  headers={'Content-Type':'application/soap+xml; charset=utf-8'},
                  auth=requests.auth.HttpNtlmAuth('corp\\jdoe','password'),
                  verify='corp-ca-bundle.pem')
print(r.status_code)
print(r.text[:2000])  # Parse policy:Policy elements
```

### Manual trigger and inspection

```
certutil -pulse                        # Trigger machine autoenroll
certutil -pulse -user                  # Trigger user autoenroll
certutil -store MY                     # Show MY store certs after enroll
certutil -store -user MY               # User MY store

# Show scheduled task:
schtasks /query /tn "\Microsoft\Windows\CertificateServicesClient\AutoEnroll" /v /fo LIST

# Show last autoenroll errors in event log:
wevtutil qe Microsoft-Windows-CertificateServicesClient-CertEnroll/Operational /c:50 /rd:true /f:text
```

## Troubleshooting

### Wireshark filters

```
# XCEP policy discovery (CEP)
http.host == "cep.corp.example.com" and http.request.uri contains "CEP"

# WSTEP enrollment (CES)
http.host == "ces.corp.example.com" and http.request.uri contains "_CES_"
tls.handshake.type == 1   # TLS handshake for SOAP+HTTPS

# DCOM MS-WCCE fallback
dcerpc.if_id == "91b9b93a-57b4-11d0-8f16-00a0484d6c9c" and dcerpc.opnum == 36

# Key archival LDAP read of KRAContainer
ldap.filter contains "KRAContainer" or ldap.message_id == 0x01

# Publication to userCertificate attribute (ldap_modify)
ldap.opcode == 0x06 and ldap.mod_attr == "userCertificate"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `Event 6 (autoenroll): 0x80094800 — template not found` | Template not enabled on CA, or template ACL lacks caller | `Add-CATemplate -Name <name>`; verify `dsacls` includes caller's group with Enroll right |
| `Event 64 — KRA cert not found` | Template requires archival but no KRA cert published | `certutil -recoverkey` to verify KRA; `certutil -csca` to publish |
| `0x80072F8A — certificate validation failed` for CEP/CES | CEP/CES SSL cert chain not trusted | Publish CA chain to NTAuth + Root stores; restart `CertEnroll` web site |
| Renewal not happening at 80% | `pKIOverlapPeriod` too large or `AEPolicy` bit 1 (renew) clear | Verify `certutil -template <name>`; verify `AEPolicy & 0x2` |
| `0x80070005 — Access Denied` on DCOM | ICertPassage DCOM launch permission not granted to caller | `dcomcnfg` → Component Services → Computers → My Computer → DCOM Config → CertSrv Request → Security → Launch Permissions |
| Cert issued but not in AD `userCertificate` | Exit module `PublishCertInDS = 0`, or `RequesterName` attribute malformed | `certutil -setreg Exit\<CAName>\PublishCertInDS 1`; restart CertSvc |
| Key archival fails — `0x80093005` | KRA cert expired or KRA KSP not reachable by CA service account | Renew KRA cert; verify KRA private key ACL grants SYSTEM read |
| `0x801901F4 — Forbidden` on CES | Authentication mode mismatch (URL suffix vs caller auth) | Use `_CES_Kerberos` for Kerberos, `_CES_Username` for basic, `_CES_Certificate` for client cert |

### Diagnostic event logs

```
Microsoft-Windows-CertificateServicesClient-CertEnroll/Operational   # client-side enroll flow
Microsoft-Windows-CertificateServicesClient-CertificateEnrollment/Operational
Microsoft-Windows-CertificationAuthority-CertEnroll/Operational       # CA-side CES/CEP
Microsoft-Windows-CertificateServicesClient-AutoEnrollment/Operational
```

### Diagnostic commands

```
certutil -ping    # CA reachable
certutil -template  # Templates visible to current caller
certutil -dspublish -f <cert.cer> NTAuthCA  # Publish CA cert to NTAuth
certutil -pulse -user  # Force autoenroll

gpresult /h gp.html   # Verify AutoEnroll CSE ran; check for AEPolicy value
```

## Cross-platform equivalents

| AD CS feature | macOS | Linux |
|---|---|---|
| Autoenroll via GPO + CSE | MDM-driven `com.apple.security.scep` payload (per-network / per-user) — see `../08-macos-equivalents/04-platform-sso-extension.md`; Jamf Connect adds device cert flows — see `../08-macos-equivalents/03-jamf-connect-pro.md` | `certmonger` daemon: `getcert request -c dogtag -T <profile> -f <file> -k <file>` polls and renews; see `../09-linux-equivalents/01-sssd-ad-provider.md` and `../09-linux-equivalents/08-freeipa-trust.md` |
| Template ACL-driven authorization | MDM profile scope (per-user/per-device group) | FreeIPA `certprofile-show` + `caacl` (CA Access Control List) governs who can request which profile |
| Key archival | (limited — MDM key escrow) | Dogtag DRM subsystem + `pki key-archive` / `pki key-retrieve` |
| Renewal at lifetime threshold | MDM profile triggers re-enroll on expiry | `certmonger` `meta.plugin跟踪` scheduling + `getcert resubmit` |

macOS lacks a GPO-equivalent autoenroll trigger; the MDM profile encodes the SCEP URL + challenge, and `ManagedClient.app` re-enrolls on expiry. Linux `certmonger` runs as a systemd service with per-cert timers.

## References

- MS-XCEP — Certificate Enrollment Policy Service Protocol
- MS-WSTEP — Certificate Enrollment Web Service (CES) Protocol
- MS-WCCE — Windows Client Certificate Enrollment Protocol
- MS-ADTS §7.3 — Autoenrollment Configuration
- RFC 2511 — PKCS#9 + CMS `EnvelopedData` for key archival
- RFC 2985 — PKCS#9 attribute `id-aa-kRAKeyInformation` (1.3.6.1.4.1.311.21.21)
- `autoenroll.h`, `certbcli.h` (Windows SDK)
- `autoenroll.dll!EnrollThread` and `autoenroll.dll!ProcessAutoEnroll` (export-less internal; see disassembly in Windows Internals 7th Ed. Part 1)
- Microsoft Docs — `https://learn.microsoft.com/windows-server/identity/ad-cs/certificate-enrollment-policy-web-service`
