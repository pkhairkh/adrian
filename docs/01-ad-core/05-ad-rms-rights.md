---
title: AD RMS — Rights Management Services Internals (rmssvc.exe, RAC/CLC/IL pipeline)
audience: senior-engineers
tags: [ad-rms, drm, rmssvc, rac, clc, il, ms-drm, ms-rmp, scp, aes-256, rsa-2048]
related:
  - ./01-ad-ds-internals.md
  - ./02-ad-cs-cert-services.md
  - ../02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ../05-pki-certs/02-certificate-templates.md
last_updated: 2026-08-13
---

AD RMS is a Windows service (`rmssvc.exe` inside a `svchost -k netsvcs` host) operating one or more Root or Licensing-only clusters of cert-issuing servers that implement Microsoft's DRM protocol family (MS-DRM, MS-RMP, MS-RM): a client enlists via a machine certificate (RAC), acquires a Client Licensor Certificate (CLC) from its RMS server, encrypts content with a fresh AES-256 content key, embeds that key inside an Issuance License (IL) signed by the CLC, and recipients obtain a Use License decrypting the AES key with the recipient's RSA private key (whose public counterpart was placed in the IL by the licensor).

## Architecture

### Cluster topology

| Cluster type | Purpose | Required |
|---|---|---|
| Root cluster | Houses the Server Licensor Certificate (SLC), issues RACs to clients, issues CLCs to clients, serves use licenses. | Exactly one per RMS deployment. |
| Licensing-only cluster | Issues use licenses only; trusts a root cluster's SLC. | Optional, deployed for scale-out. |

Both cluster types are fronted by a Network Load Balancing VIP and share a configuration database (SQL Server) plus a logging database. State is partitioned: the SLC private key is held in the RMS service's DPAPI-encrypted store, optionally HSM-protected.

### Service and process model

```
services.msc: "Active Directory Rights Management Services" (rmssvc)
 ├── process: %SystemRoot%\System32\svchost.exe -k netsvcs
 │    └── rmssvc.dll loaded as a hosted service (not standalone exe)
 │         (the binary is %SystemRoot%\System32\rmssvc.dll; service ImagePath
 │          is "%SystemRoot%\system32\svchost.exe -k netsvcs")
 │
 │    Modules:
 │      ├── rmssvc.dll           (core service: HTTP listener, request dispatcher)
 │      ├── msdrm.dll            (DRM client — used by the server itself for SLC operations)
 │      ├── certenroll.dll       (CA integration — RMS uses AD CS or third-party certs)
 │      ├── microsoftrmcommandlet.dll  (PowerShell: ADRMS module)
 │      ├── crypt32.dll, bcrypt.dll, ncrypt.dll  (CNG: AES-256, RSA-2048, SHA-256)
 │      └── System.Data.dll      (SQL Server client for config/logging DB)
 │
 ├── IIS virtual directory: /_wmcs (per cluster URL)
 │     ├── /_wmcs/Certification/   (RAC issuance — enrollment.asmx)
 │     ├── /_wmcs/Licensing/       (CLC issuance, use-license.asmx)
 │     ├── /_wmcs/Activation/      (RAC activation for pre-Vista clients)
 │     ├── /_wmcs/admin/           (administration.asmx)
 │     └── /_wmcs/Servicing/       (subservicing.asmx)
 │
 ├── Service account: NT AUTHORITY\NETWORK SERVICE (default), or DOMAIN\RMSService
 ├── Service dependencies: IISADMIN, W3SVC, HTTP, Cryptographic Services, RpcSs
 └── SCP: CN=Configuration,DC=... → CN=Services → CN=RightsManagementServices
                              → CN=Cluster → msPKI-Cert-Template-OID = <cluster URL>
```

### Configuration databases (SQL Server)

| DB | Purpose |
|---|---|
| `DRMS_Config_<cluster>_<port>` | Cluster configuration: SLC public cert, key archive metadata, SCP URL, trusted publishing domains, security policies. |
| `DRMS_Logging_<cluster>_<port>` | Per-license issuance log: timestamp, license GUID, requesting user, content ID, rights granted. |

Key tables in `DRMS_Config_*`:

| Table | Purpose |
|---|---|
| `ClusterPolicies` | Key-value cluster-wide config (SLC fingerprint, enrollment expiry). |
| `ServerPolicies` | Per-server config (URLs, cert chain). |
| `TrustedPublishingDomain` | External RMS cluster SLCs trusted to issue ILs honored here. |
| `ServiceLocatorPoint` | SCP configuration. |
| `Certificate` | Issued cert chain (RACs, CLCs). |
| `Principal` | User/group principals for licensing policy. |
| `RoleAssignment` | Role memberships (RMS Admin, RMS Auditor). |

## Licensing pipeline

### Enrollment (machine → RMS server → user)

```
1. Machine activation: the RMS client (msdrm.dll, loaded by the Office or the
   Windows RMS-aware application) generates a 2048-bit RSA keypair locally,
   persists the private key in C:\ProgramData\Microsoft\DRM\Server\<SID>\
   MachineKeys\*.bin (encrypted by DPAPI in user-context — the SID-tied path
   isolates users on the same machine).
2. Enrollment request: the client POSTs a SOAP request to
   <ServerURL>/_wmcs/Certification/ServerCertification.asmx
   containing the public key + user SID (auth via Windows Integrated).
3. The server signs the public key inside a Server Licensor Certificate (SLC).
   The SLC asserts: "this server holds the SLC private key identified by
   fingerprint X".
4. The user obtains a Rights Account Certificate (RAC):
   <ServerURL>/_wmcs/Certification/Certification.asmx
   Server-side flow:
     a. Server validates the user (via Kerberos / NTLM token over HTTP).
     b. Server builds the RAC payload:
         - User public key (from a freshly generated 2048-bit RSA key, sent by client)
         - User SID, UPN
         - Validity period (default 365 days)
         - Security policy hash
     c. Server signs the RAC with the SLC private key.
     d. Server returns the RAC (XML, base64 inside SOAP).
5. The user obtains a Client Licensor Certificate (CLC):
   <ServerURL>/_wmcs/Licensing/Licensor.asmx
   - Server generates a fresh 2048-bit RSA keypair (the CLC key).
   - Server embeds the CLC public key + CLC validity + signed-with-SLC.
   - Server returns the CLC; the private key is wrapped with the user's RAC
     public key (so only the holder of the RAC private key can decrypt it).
```

### Content encryption (publishing)

```
Author opens document, applies IRM policy (e.g., "View but not print, expires 2026-12-31")
  in Office → Office calls msdrm.dll!CreateLicense:
    1. Generate a fresh AES-256 content key (random 256-bit).
    2. Encrypt the document with AES-256-CBC.
    3. Build an Issuance License (IL) — an XML document containing:
        - Rights expression (rights, conditions, valid-until, revocation)
        - For each authorized principal: their public key (from AD or RAC) + the
          AES-256 content key wrapped with that principal's RSA public key
        - The author's CLC public key fingerprint
    4. Sign the IL with the CLC private key (RSA-2048 over SHA-256).
    5. Embed the signed IL as a header in the encrypted file (Office's
       .docx / .xlsx / .pptx format uses a custom "IRM" part in the OPC zip).
```

### Use license acquisition (consumer)

```
Recipient opens the IRM-protected file
  → Office extracts the IL from the OPC
  → Office POSTs the IL + the recipient's RAC to:
       <ServerURL>/_wmcs/Licensing/License.asmx
  → Server flow:
       a. Verify the IL signature using the CLC public key (chain → SLC).
       b. Verify the recipient's RAC is valid (signature, not revoked).
       c. Check revocation list (issued by the cluster's revocation endpoint).
       d. Apply policy: re-evaluate rights based on:
            - Time (e.g., "expires 2026-12-31" — re-check at use-license time)
            - Group membership (user added/removed since publish)
            - Revocation
       e. Build a Use License (UL) — XML containing:
            - A copy of the IL
            - The recipient's RSA private key wrapped version of the AES key
              (taken from the original IL's encrypted-key entry)
            - The newly-computed rights expression specific to the recipient
       f. Sign the UL with the CLC private key.
       g. Return the UL.
  → Office decrypts the AES content key using the recipient's RAC private key,
    then decrypts the document with the AES key.
```

### Cryptographic envelope

```
Document payload:    AES-256-CBC, random IV per file
Content key (CEK):   256-bit random, generated fresh per document
KEK per recipient:   RSA-2048-OAEP(SHA-256) wraps CEK → embedded in IL <ENCRYPTEDKEY>
SLC signing:         RSA-2048 PKCS#1 v1.5 over SHA-256
CLC signing:         RSA-2048 PKCS#1 v1.5 over SHA-256
IL signing:          RSA-2048 PKCS#1 v1.5 over SHA-256 (CLC private key)
UL signing:          RSA-2048 PKCS#1 v1.5 over SHA-256 (CLC private key)
Manifest hashes:     SHA-256
```

The SLC private key is the trust root for the entire cluster. Compromise of the SLC private key compromises every IL issued under it. Mitigation: deploy an HSM (CNG/KSP), enforce key archival (the SLC can be escrowed to a second server for break-glass revocation), and enforce the cluster revocation list.

### SCP — Service Connection Point

Published automatically by `Set-RmsSvcProperty` (during provisioning):

```
CN=Cluster,CN=RightsManagementServices,CN=Services,CN=Configuration,DC=example,DC=com
 ├── cn                      = Cluster
 ├── objectClass             = serviceConnectionPoint
 ├── msPKI-Cert-Template-OID = http://rms01.example.com/_wmcs/certification   (REG_SZ)
 ├── serviceBindingInformation = <cluster URL>
 ├── keywords                = "MSRMSSCPv2"  (multi-valued)
 └── displayName             = "RMS Cluster"
```

Clients discover their RMS cluster by performing an LDAP query for `objectCategory=serviceConnectionPoint AND keywords=MSRMSSCPv2` against the Configuration NC. Forest-trusts allow clients in another forest to discover a root cluster by querying the trusted forest's Configuration NC.

## RMS client cache

```
%LocalAppData%\Microsoft\MSDRM\          ← per-user
 ├──  Server\                         ← server URLs discovered via SCP
 │     ├── <cluster URL hash>\        ← directory per discovered cluster
 │           Certification.asmx       ← cached cert chain
 │           Licensor.asmx            ← cached CLC
 ├──  Machine\                        ← machine cert + key (encrypted)
 │      cert.bin
 ├──  RAC\                            ← RACs, one per user per cluster
 │      <sid-hash>.bin
 └──  Licenses\                       ← Use License cache, keyed by content ID GUID
        <content-id-guid>.bin

%ProgramData%\Microsoft\Windows\DRM\   ← machine-wide (Office 2013+ uses this)
 ├── Cache\                           ← shared cert cache (IRMCerts)
 ├── Templates\                       ← AD RMS templates distributed via GPO
 │      <guid>.xml
 └── Server\                          ← alternate cache for non-user services
```

Templates (Office's rights policy templates) are distributed by GPO (`Computer Configuration → Policies → Administrative Templates → AD RMS Rights Policy Template Management`). They are XML files with a GUID; Office references them when the user picks "Restrict Permission → <template name>".

## Configuration / code examples

### Wireshark filter — RMS SOAP traffic

```
http.request.uri contains "_wmcs/Certification" && http.request.method == "POST"
http.request.uri contains "_wmcs/Licensing"
# Custom RPC over DCE/RPC — internal-only (e.g., for cluster replicating config):
dcerpc.if_id == c68380b4-9b95-46d9-9aff-d6a3e5e0c6b7   # placeholder for cluster RPC
```

### PowerShell — RMS provisioning and template management

```powershell
# Show the RMS cluster configuration
Get-RmsSvcProperty -Path "Microsoft.Identity.ADRMS\cluster" -Property ServiceAccount

# Re-publish the SCP (in case of cluster URL change)
Set-RmsSvcProperty -Path "Microsoft.Identity.ADRMS\cluster" -ServiceConnectionPoint "http://rms01.example.com/_wmcs/certification"

# Distribute templates
$export = "C:\templates\*.xml"
Export-RmsTPD -Path "Microsoft.Identity.ADRMS\cluster" -ExportedTPLsFile $export

# Add a trusted publishing domain (federate with a partner RMS)
$tpdFile = "C:\partner-tpd.xml"
$tpdPass = (Read-Host -AsSecureString)
Import-RmsTPD -Path "Microsoft.Identity.ADRMS\cluster" -TPDFile $tpdFile -Password $tpdPass
```

### Python — decrypt an RMS-protected file via Azure Information Protection SDK (Python bindings)

```python
# Note: pure-Python RMS clients do not exist for AD RMS — use the
# RMS SDK for C++ / .NET, or the MIP SDK (Microsoft Information Protection).
# Below: pseudo-flow using MIP SDK's Python wrapper (mip-sdk-python).

import mip

# Set up MIP file handler
mip_settings = mip.FileSettings(profile_name="corp-rms",
                                app_data_path="/var/lib/mip")
profile = mip.FileProfile(mip_settings)
handler = profile.create_file_handler("/path/to/protected.docx")

# Auth via AD FS (or Azure AD). For on-prem AD RMS:
# - Service principal registered against AD FS via OAuth2 client_credentials
# - Token issued with scope "https://rms.example.com/.default"
handler.decrypt(access_token="<jwt-from-adfs>")
print(handler.get_label())   # Show sensitivity label if mapped
```

### Registry — RMS client config

```
HKLM\SOFTWARE\Microsoft\MSDRM\ServiceLocation\
 ├── EnterpriseCertification = http://rms01.example.com/_wmcs/Certification   (REG_SZ)
 └── EnterprisePublishing    = http://rms01.example.com/_wmcs/Licensing       (REG_SZ)

HKLM\SOFTWARE\Microsoft\MSDRM\Templates\
 └── (template GUIDs) → REG_SZ = UNC path to the distributed template XML

HKLM\SOFTWARE\Microsoft\MSIPC\Server\<cluster-url-hash>\
 └── ExcludedApps REG_MULTI_SZ = (apps to block from using the SDK)
```

## Troubleshooting

- **`IRM failed to grant the license` (Office)** — client cannot reach the RMS server. Verify SCP via `Get-ADObject -Filter "objectClass -eq 'serviceConnectionPoint' AND keywords -eq 'MSRMSSCPv2'" -SearchBase "CN=Configuration,DC=example,DC=com" -Properties msPKI-Cert-Template-OID`. If empty, re-publish: `Set-RmsSvcProperty -ServiceConnectionPoint "<URL>"`.
- **`The certificate is not trusted`** — server's SLC cert has expired or is not in the client's Trusted Publishing Domain. Re-import via `Import-RmsTPD` or `Set-RmsSvcProperty -TrustedPublishingDomain`.
- **Slow use-license issuance** — DB bottleneck. Check the `DRMS_Logging_*` database — purging records older than N days via the RMS Admin tool (logging retention) usually helps.
- **RAC expired** — re-enroll the user (delete the user's RAC folder under `%LocalAppData%\Microsoft\MSDRM\`, then re-open a protected document; the client re-requests a RAC).
- **Templates not appearing in Office** — GPO not applied; verify `gpresult /h` shows the RMS template policy; check `%LocalAppData%\Microsoft\MSDRM\Templates\` for XML files.
- **Cross-forest RMS** — the trusting forest must have a Trusted User Domain (`Set-RmsSvcProperty -TrustedUserDomain`) AND a Trusted Publishing Domain pointing at the partner's SLC cert.

## Cross-platform equivalents

- **Linux**: Microsoft ships the MIP SDK for Linux (C++) — usable for AD RMS decryption in custom apps. No native RMS server on Linux. The Azure Information Protection client (AIP UL) supports Linux for labeling, but the underlying RMS still points back at Azure Information Protection or AD RMS via the MIP SDK.
- **Linux**: Free software equivalents (no RMS-compatible): `ccrypt` (AES-256 file encryption), `gocryptfs`, `cryptmount` — but none implement rights expression / license issuance.
- **Linux**: Nextcloud / ownCloud offer per-file access control and expiry, but use per-app cryptography, not a license-server model.
- **macOS**: Office for Mac uses the MIP SDK on macOS (`.dylib`) to decrypt RMS-protected files. Native macOS apps do not implement RMS. See `../08-macos-equivalents/04-platform-sso-extension.md` for the auth side.

## References

- MS-DRM — Active Directory Rights Management Services Protocol. <https://learn.microsoft.com/openspecs/windows_protocols/ms-drm>
- MS-RMP — Rights Management Services Client-Server Protocol (the SOAP envelope variant used by Office).
- MS-RM — RMS Protocol 1.0 (legacy, used by Office 2003-2007).
- AD RMS Cryptographic Modes — MS Learn. (Mode 1 = RSA-1024 / SHA-1; Mode 2 = RSA-2048 / SHA-256.)
- Microsoft Information Protection SDK, MS Learn.
- "Active Directory Rights Management Services — Deployment Guide."
