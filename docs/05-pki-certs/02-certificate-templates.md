---
title: Certificate Templates — pKICertificateTemplate AD Class, v1/v2/v3 Schema, msPKI-* Attributes, ACL Model, MS-WCCE/MS-XCEP
audience: senior-engineers
tags: [ad-cs, pki, certificate-templates, pkiCertTemplate, ms-wcce, ms-xcep, cng, suite-b]
related:
  - ./01-ad-cs-architecture.md
  - ./03-autoenrollment.md
  - ./04-ocsp-crl.md
  - ../01-ad-core/02-ad-cs-cert-services.md
  - ../08-macos-equivalents/04-platform-sso-extension.md
  - ../09-linux-equivalents/08-freeipa-trust.md
last_updated: 2026-08-13
---

A certificate template is an instance of the `pKICertificateTemplate` AD class (`CN=<Template>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<NC>`) whose `msPKI-*` attributes drive subject name construction, key generation, EKU enforcement, and ACL-gated enrollment on Enterprise CAs; the on-wire enrollment protocols MS-WCCE (DCOM) and MS-XCEP (HTTPS SOAP) carry template OIDs and request blobs between client and CA.

## Template versions

| Version | Introduced | Schema | Key features |
|---|---|---|---|
| v1 | NT4 / Win2000 | `msPKI-Certificate-Name-Flag` only | No ACLs, no per-template customization beyond enable/disable on a CA. Defined in `CN=Certificate Templates,CN=...`. Stored as `pKICertificateTemplate` with `templateVersion = 1`. |
| v2 | Win2003 | Adds `nTSecurityDescriptor` (ACL), full customization, crypto via CryptoAPI (legacy CSP) | The canonical "template" experience. ACL controls Read / Enroll / Autoenroll / Write / Full Control. |
| v3 | Win2008 | CNG-based (`msPKI-Private-Key-Flag` for key isolation, KSP, Suite B algorithms) | CNG key storage providers, AES/SHA-2 by default, key attestation, renewable accepts, delta CRL templating. Template object's `msPKI-Template-Schema-Version = 2` (note: schema version, not template version) |

`msPKI-Template-Schema-Version` (`attributeID` 1.2.840.113556.1.4.1499) maps: `1` = v2 template, `2` = v3 template. v1 templates do not set this attribute.

## AD object class

```
CN=User, CN=Certificate Templates, CN=Public Key Services, CN=Services, CN=Configuration, DC=corp, DC=example, DC=com

objectClass: top, pKICertificateTemplate

Mandatory attributes (from classSchema pKICertificateTemplate, governsID 1.2.840.113556.1.5.119):
  cn, displayName, msPKI-Certificate-Name-Flag, msPKI-Minimal-Key-Size,
  pKIMaxIssuingDepth, pKIKeyUsage, pKIExtendedKeyUsage, pKICriticalExtensions,
  msPKI-Enrollment-Flag, msPKI-Private-Key-Flag, msPKI-Hash-Algorithm,
  msPKI-Symmetric-Algorithm, msPKI-Symmetric-Key-Length, msPKI-Template-Schema-Version,
  revision, nTSecurityDescriptor

Optional: msPKI-Certificate-Application-Policy, msPKI-Certificate-Policy,
  msPKI-RA-Application-Policies, msPKI-Cert-Template-OID, msPKI-Supersede-Templates,
  msPKI-RA-Signature, pKIOverlapPeriod, pKIExpirationPeriod, msPKI-Enrollment-Agent,
  msPKI-Require-Directory-Path, msPKI-Key-Usage-Property, msDS-ManagedPasswordInterval
```

The `pKICertificateTemplate` classSchema is defined in the base schema (Windows 2000 schema, `objectVersion = 13`).

## Key template attributes

### Subject name construction

`msPKI-Certificate-Name-Flag` (`attributeID` 1.2.840.113556.1.4.1422), a bitmask:

| Bit | Value | Meaning |
|---|---|---|
| 0 | 0x1 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (subject name supplied in request — required for `Computer` template variant where `CN=<dNSHostName>`) |
| 1 | 0x2 | (reserved) |
| 2 | 0x4 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` (SAN supplied in request) |
| 3 | 0x8 | `CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS` (auto-add DNS domain to SAN) |
| 4 | 0x10 | `CT_FLAG_SUBJECT_ALT_REQUIRE_SPN` (auto-add SPN to SAN, e.g. `HOST/<host>`) |
| 5 | 0x20 | `CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID` (auto-add objectGUID) |
| 6 | 0x40 | `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` (auto-add UPN) |
| 7 | 0x80 | `CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL` (auto-add mail) |
| 8 | 0x100 | `CT_FLAG_SUBJECT_ALT_REQUIRE_DNS_AS_CN` (CN built from DNS host name) |
| 9 | 0x200 | `CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN` |
| 10 | 0x400 | `CT_FLAG_SUBJECT_REQUIRE_EMAIL` |
| 11 | 0x800 | `CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME` |
| 12 | 0x1000 | `CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH` |

When neither `0x1` nor any `0x100+` flag is set, the subject is built from the enrollment context (typically `CN=<displayName>` for user, `CN=<dNSHostName>` for computer).

### Enrollment flags

`msPKI-Enrollment-Flag` (`attributeID` 1.2.840.113556.1.4.1372):

| Bit | Value | Flag | Behavior |
|---|---|---|---|
| 0 | 0x1 | INCLUDE_SYMMETRIC_ALGORITHMS | Include symmetric alg in CSR |
| 1 | 0x2 | PEND_ALL_REQUESTS | Force pending state |
| 2 | 0x4 | PUBLISH_TO_KRA_CONTAINER | Publish KRA cert to AD |
| 3 | 0x8 | DONT_USE_TEMPLATES | (Standalone) ignore template |
| 4 | 0x10 | AUTO_ENROLLMENT | Eligible for autoenroll |
| 5 | 0x20 | PREVIOUS_APPROVAL_VALIDATE | Auto-approve if previously approved |
| 6 | 0x40 | PREVIOUS_APPROVAL_VALIDATE_EQUIV | Same but for template equivalency |
| 7 | 0x80 | HYGIENE_ONLY | (No enrollment, hygiene check) |
| 8 | 0x100 | REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE | Auto-purge superseded |
| 9 | 0x200 | ALLOW_ENROLL_ONLINE_BEHALF_OF | Acting as enrollment agent |
| 10 | 0x400 | ADD_EMAIL | (subject) |
| 11 | 0x800 | ADD_OBJ_GUID | (subject) |
| 12 | 0x1000 | ENABLE_MODULUS_NEGOTIATION | CNG modulus negotiation |
| 13 | 0x2000 | DEFAULT_CERT | (mark as default for EKU) |
| 14 | 0x4000 | REQUIRE_USER_INTERACTION | UI prompt before key gen |
| 17 | 0x20000 | IGNORE_ENROLL_ON_BEHALF | Skip enrollment agent check |

### Private key flags

`msPKI-Private-Key-Flag` (`attributeID` 1.2.840.113556.1.4.1390):

| Bit | Value | Flag | Behavior |
|---|---|---|---|
| 0 | 0x1 | EXPORTABLE_KEY | Mark key exportable (`CryptExportKey` allowed) |
| 1 | 0x2 | STRONG_KEY_PROTECTION_REQUIRED | UI prompt on key use |
| 2 | 0x4 | REQUIRE_ARCHIVAL | Key archival with CA KRA cert (template sets `pKIKeyUsage` archival bit) |
| 3 | 0x8 | REQUIRE_PRIVATE_KEY_ARCHIVAL | Same, explicit |
| 4 | 0x10 | REQUIRE_CERT_CHAIN_TYPE | Restrict chain type |
| 7 | 0x80 | REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM | CNG RSASSA-PSS required |
| 8 | 0x100 | REQUIRE_ATTESTATION | Windows 8+ / TPM attestation |
| 9 | 0x200 | ATTESTATION_REQUIRED | Strict — non-attested requests denied |
| 10 | 0x400 | CERTIFICATE_BASED_REQUEST | Cert-based renewal only |
| 11 | 0x800 | USE_LEGACY_PROVIDER | Force legacy CSP (not CNG KSP) |
| 12 | 0x1000 | ATTACH_PUBLIC_KEY_TO_ATTESTATION | Public key in attestation blob |

### Application / Extended Key Usage

`pKIExtendedKeyUsage` (`attributeID` 1.2.840.113556.1.4.144) — array of OIDs that go into the certificate's Extended Key Usage extension (OID 2.5.29.37). Common OIDs:

| OID | Name | Use |
|---|---|---|
| 1.3.6.1.5.5.7.3.1 | serverAuth | TLS server |
| 1.3.6.1.5.5.7.3.2 | clientAuth | TLS client, smart card |
| 1.3.6.1.5.5.7.3.3 | codeSigning | Authenticode |
| 1.3.6.1.5.5.7.3.4 | emailProtection | S/MIME |
| 1.3.6.1.5.5.7.3.8 | timeStamping | TS trust |
| 1.3.6.1.5.5.8.2.2 | IPsecEndSystem / IPsecIKE | IPsec |
| 1.3.6.1.4.1.311.20.2.1 | smartCardLogon | Smart card login (also requires Kerberos) |
| 1.3.6.1.4.1.311.20.2.2 | KerberosClientAuth | PKINIT client |
| 1.3.6.1.4.1.311.21.6 | Key Recovery Agent | KRA |
| 1.3.6.1.4.1.311.21.19 | Directory Service Email Replication | DC mail-rep |
| 1.3.6.1.4.1.311.21.7 | Certificate Request Agent | Enrollment agent |
| 1.3.6.1.4.1.311.10.3.11 | Key Recovery | KRA-v2 |
| 1.3.6.1.4.1.311.10.3.25 | Document Encryption | DRA / EFS-equivalent |
| 1.3.6.1.4.1.311.10.3.4 | EFS | Encrypting File System |
| 1.3.6.1.4.1.311.10.3.4.1 | EFS Recovery | Recovery agent |
| 1.3.6.1.4.1.311.21.10 | Application Certification Authority | Application CA |

`msPKI-Certificate-Application-Policy` (`attributeID` 1.2.840.113556.1.4.1377) — same OID list, used for **issuance policy** constraints (chain `Application Policies` extension, OID 1.3.6.1.4.1.311.21.10). Distinct from `pKIExtendedKeyUsage`: the latter lists EKUs in the issued cert; the former constrains what policies the issued cert is valid for in a chain context.

`msPKI-Certificate-Policy` — array of policy OIDs that go into the Certificate Policies extension (OID 2.5.29.32).

### Key usage

`pKIKeyUsage` (`attributeID` 1.2.840.113556.1.4.1443) — a 2-byte bitmask DER-encoded as OCTET STRING (4-byte length prefix when read over LDAP). RFC 5280 §4.2.1.3 bits:

| Bit | Name | Hex |
|---|---|---|
| 0 | digitalSignature | 0x80 |
| 1 | nonRepudiation (contentCommitment) | 0x40 |
| 2 | keyEncipherment | 0x20 |
| 3 | dataEncipherment | 0x10 |
| 4 | keyAgreement | 0x08 |
| 5 | keyCertSign | 0x04 |
| 6 | cRLSign | 0x02 |
| 7 | encipherOnly | 0x01 |
| 8 | decipherOnly | 0x8000 |

So a typical server auth template stores `0xA0` (digitalSignature + keyEncipherment), CA template stores `0x06` (keyCertSign + cRLSign), KRA template stores `0x80` (digitalSignature).

### Path length / Basic Constraints

`pKIMaxIssuingDepth` (`attributeID` 1.2.840.113556.1.4.1462) — integer; goes into the `pathLenConstraint` field of the BasicConstraints extension (OID 2.5.29.19). Sub-CA templates typically set 0 (cannot issue sub-CAs); the root's pathLen is unconstrained.

### Validity and renewal

| Attribute | OID | Meaning |
|---|---|---|
| `pKIExpirationPeriod` | 1.2.840.113556.1.4.1444 | 8-byte FILETIME, expiry after issuance |
| `pKIOverlapPeriod` | 1.2.840.113556.1.4.1445 | 8-byte FILETIME, renewal window before expiry (default 80% of lifetime) |

Default template: 1 year expiry, 6 week overlap.

### ACLs

`nTSecurityDescriptor` on the template object carries ACEs. Extended rights (defined in `CN=Extended-Rights,CN=Configuration,...`):

| Right | displayName | rightGuid |
|---|---|---|
| Read | (no extended right; standard READ) | — |
| Enroll | `Enroll` | `0e10c968-78d0-11d2-af90-00c04f990c33` |
| Autoenroll | `Autoenroll` | `a05b8cc2-17bc-4802-a710-e7c15ab866a2` |

Effective ACE on `Domain Computers` for a machine template:

```
(A;;RPWPCR;;;S-1-5-21-...-515)  // Domain Computers: Read + Enroll
(A;;RPWPCCRLC;;;S-1-5-11)        // Authenticated Users: Read + Enroll + Autoenroll
```

Autoenroll requires both Enroll + Autoenroll rights. Write permission is granted to PKI admins only (`CN=PKI Admins,CN=Users,...`).

## Template supersession

`msPKI-Supersede-Templates` (`attributeID` 1.2.840.113556.1.4.1461) — multi-valued list of template `cn` values that this template supersedes. At autoenroll, the client checks all enrolled certs; if a cert was issued from a superseded template and is within the overlap window, the client enrolls in the new template and the old cert is purged (if `REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE` is set).

## CA template enablement

Templates defined in AD are visible to all Enterprise CAs, but a CA only *issues* from a template after it is added to the CA's `templates` registry multi-string:

```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\Templates
  REG_MULTI_SZ: "User" "Machine" "DomainController" "KerberosAuthentication" "SmartcardUser"
```

Equivalently via `certutil -SetTemplate -<CAName> +User +Machine`. The CA's `certpmod.dll!GetTemplate` enumerates this list at request time.

## MS-WCCE / MS-XCEP enrollment protocols

### MS-WCCE (DCOM, [MS-WCCE])

Interface UUID `91b9b93a-57b4-11d0-8f16-00a0484d6c9c`, version 0.0. (Same UUID as ICertPassage; MS-WCCE is the spec'd subset.)

Key opnums:

| Opnum | Method | Notes |
|---|---|---|
| 0 | Request | Submit CSR + template name + attributes; returns `Disposition` + `Cert` |
| 1 | GetCACert | Returns CA cert chain |
| 2 | Ping | CA reachable |
| 36 | Request | With template OID and attribute blob — modern path |
| 4 | EnumerateExtensions / GetCertificate | Poll for issued cert after pending disposition |

Request attribute payload (raw binary, see `[MS-WCCE] §2.2.3.1`): `AttributeName\0AttributeValue\0` pairs, including `CertificateTemplate:<cn>` and `RequesterName:<domain\user>` (set by the CA, not the client).

### MS-XCEP (CEP, HTTPS SOAP)

Endpoint: `https://<cep-server>/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP` (SOAP 1.1, WS-Addressing).

Wire format: `GetPolicies` request with `<client:>Client` filter; response contains `<policy:Policies>` with one `<policy:Policy>` per template, including:

- `policy:PolicyOIDReference` (matches the `msPKI-Cert-Template-OID` value)
- `policy:Attributes` (Private Key Attributes: minimal key length, hash algorithm, exportable flag)
- `policy:PrivateKeyFlags`
- `policy:Extensions` (EKU list, key usage, basic constraints)

CEP responses are signed (transport SSL) and may also be signed at the SOAP layer.

### MS-WSTEP (CES, HTTPS SOAP)

Endpoint: `https://<ces-server>/CertEnroll/<CAName>_CES_Kerberos/service.svc/CES` (or `_CES_Username` for username/password, `_CES_Certificate` for cert auth).

Wire format: wraps the PKCS#10 CSR in `<wstep:RequestSecurityToken>` (WS-Trust), the response wraps the issued PKCS#7 chain in `<wstep:RequestSecurityTokenResponse>`.

CES is the protocol-level replacement for DCOM ICertPassage enrollment when the client is not on the same domain or firewall restricts DCOM. Authentication mode is encoded in the URL suffix.

## Configuration / code examples

### PowerShell: create a v3 (CNG) certificate template from scratch

```powershell
$root = (Get-ADRootDSE).configurationNamingContext
$tplContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$root"

# Build the template object
$tpl = New-Object -ComObject X509Enrollment.CX509CertificateTemplateAD
$tpl.Name = "CorpWebServer"
$tpl.DisplayName = "Corp Web Server (CNG)"
$tpl.OID.FriendlyName = "Certificate Template: CorpWebServer"
$tpl.OID.Value = "1.3.6.1.4.1.311.21.8.<forest-oid-arc>.<unique-id>"

# Subject name: built from DNS host name
$tpl.NameFlags = 0x200  # CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN | 0x100 SAN_REQUIRE_DOMAIN_DNS
$tpl.EnrollmentFlags = 0x200  # AUTO_ENROLLMENT
$tpl.PrivateKeyFlags = 0x10   # REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM (CNG)
$tpl.KeyUsage = 0xA0          # digitalSignature | keyEncipherment
$tpl.ExtendedKeyUsage.Add(1, "1.3.6.1.5.5.7.3.1")  # serverAuth
$tpl.MaximumIssuingDepth = 0
$tpl.ExpirationPeriod = (New-TimeSpan -Days 395)
$tpl.OverlapPeriod     = (New-TimeSpan -Days 30)
$tpl.MinimumKeyLength = 2048
$tpl.HashAlgorithm = "SHA256"
$tpl.TemplateSchemaVersion = 2  # v3 (CNG)

$tpl.Save(0, $tplContainer)

# ACL: grant Domain Computers Enroll+Autoenroll
$acl = Get-Acl "AD:\CN=CorpWebServer,$tplContainer"
$domComputers = New-Object System.Security.Principal.NTAccount("CORP\Domain Computers")
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $domComputers,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [Guid]"0e10c968-78d0-11d2-af90-00c04f990c33")))  # Enroll
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [Guid]"a05b8cc2-17bc-4802-a710-e7c15ab866a2")))  # Autoenroll
Set-Acl "AD:\CN=CorpWebServer,$tplContainer" $acl

# Enable on CA
Add-CATemplate -Name CorpWebServer
```

### PowerShell: dump every template with EKU and ACL summary

```powershell
$root = (Get-ADRootDSE).configurationNamingContext
Get-ADObject -Filter 'objectClass -eq "pKICertificateTemplate"' -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$root" -Properties * |
  Select-Object Name, displayName, msPKI-Template-Schema-Version,
    @{n='EKUs';e={$_.pKIExtendedKeyUsage -join ';'}},
    @{n='KeyUsage';e={'0x{0:X4}' -f [BitConverter]::ToUInt16($_.pKIKeyUsage,0)}},
    @{n='EnrollAces';e={
        $acl = Get-Acl "AD:\$($_.DistinguishedName)"
        ($acl.Access | Where-Object { $_.ActiveDirectoryRights -band 0x100 -or $_.ObjectType -eq '0e10c968-78d0-11d2-af90-00c04f990c33' } |
            Select-Object -ExpandProperty IdentityReference) -join ','
    }} |
  Format-Table -AutoSize
```

### Python: parse a template via ldap3 with full attribute decode

```python
from ldap3 import Server, Connection, ALL
from ldap3.protocol.formatters.formatters import format_sid

srv = Server('dc01.corp.example.com', use_ssl=True)
conn = Connection(srv, user='corp\\svc-ldap', password='...', auto_bind=True)

base = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=com'
conn.search(base, '(objectClass=pKICertificateTemplate)', attributes=[
    'cn', 'displayName', 'msPKI-Template-Schema-Version',
    'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
    'msPKI-Private-Key-Flag', 'pKIKeyUsage', 'pKIExtendedKeyUsage',
    'pKIMaxIssuingDepth', 'nTSecurityDescriptor', 'msPKI-Cert-Template-OID'
])

EKU_NAMES = {
    '1.3.6.1.5.5.7.3.1': 'serverAuth', '1.3.6.1.5.5.7.3.2': 'clientAuth',
    '1.3.6.1.4.1.311.20.2.1': 'smartCardLogon', '1.3.6.1.4.1.311.21.6': 'KRA',
    '1.3.6.1.4.1.311.10.3.4': 'EFS', '1.3.6.1.4.1.311.10.3.4.1': 'EFSRecovery',
}

def decode_ku(b: bytes) -> str:
    if len(b) < 2: b = b + b'\x00'*(2-len(b))
    bits = []
    if b[0] & 0x80: bits.append('digitalSignature')
    if b[0] & 0x40: bits.append('nonRepudiation')
    if b[0] & 0x20: bits.append('keyEncipherment')
    if b[0] & 0x10: bits.append('dataEncipherment')
    if b[0] & 0x04: bits.append('keyCertSign')
    if b[0] & 0x02: bits.append('cRLSign')
    return '|'.join(bits) or '(none)'

for entry in conn.entries:
    eku = entry.pKIExtendedKeyUsage.value or []
    print(f"{entry.cn.value:30s} v{entry['msPKI-Template-Schema-Version'].value or '1'} "
          f"KU={decode_ku(entry.pKIKeyUsage.value):40s} "
          f"EKU={','.join(EKU_NAMES.get(x,x) for x in eku)}")
```

## Troubleshooting

### Wireshark filters

```
# MS-WCCE DCOM enrollment
dcerpc.if_id == "91b9b93a-57b4-11d0-8f16-00a0484d6c9c"
dcerpc.opnum == 36                # Request (modern path)

# MS-XCEP SOAP over HTTPS
tls.handshake.extensions_server_name == "cep.corp.example.com"
http.request.uri contains "ADPolicyProvider"

# MS-WSTEP (CES)
tls.handshake.extensions_server_name == "ces.corp.example.com"
http.request.uri contains "_CES_"
```

### Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `The requested certificate template could not be found. 0x80094800` | Template not enabled on CA, or caller is in a different forest without cross-forest enrollment | `Add-CATemplate -Name <name>`; for cross-forest, set `msPKI-Cert-Template-OID` and use CEP/CES |
| `The permissions on the certificate template do not allow the current user to enroll. 0x80094012` | Missing Enroll ACE | `dsacls` on template, add `Enroll` extended right to group |
| `The certificate request was denied. 0x80094801` | Subject name flag conflict (caller supplied name not allowed) | Match `msPKI-Certificate-Name-Flag` to expected subject source |
| Autoenroll issues certs even when caller not in security group | Cached `krbtgt`/computer account in `Authenticated Users` ACE | Remove Authenticated Users; add explicit group |
| Superseded cert not purged | `REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE` (0x100) not set on new template | Set the bit and re-publish; client will purge next cycle |
| v3 (CNG) template issues v2 (legacy CSP) cert | `msPKI-Template-Schema-Version=1` and `msPKI-Private-Key-Flag` lacks CNG bit | Set schema version to 2; ensure KSP specified |
| CEP returns 0 policy entries | CEP server cannot read template container (LDAP perms) or filter mismatch | Check CEP service account has `Read` on `CN=Certificate Templates,...`; verify `<client:>Client` filter |

### Diagnostic commands

```
certutil -template | clip        # Dump all visible templates + ACLs
certutil -template <TemplateName> # Detailed dump of one template
certutil -GetTemplates           # Templates enabled on this CA
dsaccls "CN=<tpl>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=com"
Get-CATemplate                   # Same as certutil -GetTemplates
```

## Cross-platform equivalents

| AD CS feature | macOS | Linux |
|---|---|---|
| Template ACL-driven enrollment | MDM profile + SCEP payload `com.apple.security.scep` with `SubjectName`, `KeyUsage`, `ExtendedKeyUsage` fields — see `../08-macos-equivalents/04-platform-sso-extension.md` | Dogtag cert profile (`/var/lib/pki/<instance>/profiles/ca/<name>.cfg`) — see `../09-linux-equivalents/08-freeipa-trust.md` |
| Autoenroll | MDM push (no autoenroll on bare macOS) — Jamf Connect wraps this — see `../08-macos-equivalents/03-jamf-connect-pro.md` | `certmonger` `getcert request -T <profile>` — see `../09-linux-equivalents/01-sssd-ad-provider.md` |
| Per-template EKU enforcement | MDM profile policy enforcement (`com.apple.security.certificate.eku` style) | Dogtag profile `policyset.<n>.<m>.default.params.extKeyUsageOIDs=N` |
| Key archival | (limited — escrow via MDM) | Dogtag DRM / Key Recovery Authority subsystem |

The FreeIPA / Dogtag certificate profile format roughly maps to a v2/v3 template: each profile is a `.cfg` file under `/var/lib/pki/pki-tomcat/ca/profiles/ca/` with `policyset` stanzas replacing the AD `msPKI-*` attributes, and `auth.class_id` replacing the template ACL.

## References

- MS-WCCE — Windows Client Certificate Enrollment Protocol (`[MS-WCCE]`)
- MS-XCEP — Certificate Enrollment Policy Service Protocol
- MS-WSTEP — Certificate Enrollment Web Service (CES) Protocol
- MS-ADTS §7.3 — Certificate Templates
- RFC 5280 §4.2 — Certificate Extensions (KeyUsage, EKU, BasicConstraints, etc.)
- `certpol.h`, `certcli.h`, `certenc.h` (Windows SDK) — `CX509CertificateTemplateAD` COM class
- `clschema.hxx` in `adprep/schema/` — base `pKICertificateTemplate` classSchema definition
- Windows Internals 7th Ed., Part 1, Chapter 9 — Template version history
- Microsoft Docs — `https://learn.microsoft.com/windows-server/identity/ad-cs/certificate-templates`
