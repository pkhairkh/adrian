---
title: Cert Service — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, cert-service, framework-design, gap-analysis, pki, ad-cs, x509]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./02-kdc.md
  - ./04-policy-engine.md
  - ./06-federation-gateway.md
  - ./07-file-gateway.md
  - ./09-cross-platform-parity.md
  - ./14-cross-platform-parity-matrix.md
  - ./13-open-research-questions.md
last_updated: 2026-08-13
---

# Cert Service — Problem Catalog

## Capability definition

**Responsibility**: X.509 PKI. Issues, revokes, publishes certificates. Supports autoenrollment, key archival, OCSP, CRL, multi-tier CA hierarchy.

**Inherits from AD**: AD CS (`certsvc.exe` + policy/exit modules + CA database + MS-WCCE/MS-XCEP enrollment endpoints + NDES for SCEP).

**Public interfaces**: Certificate enrollment — MS-WCCE/MS-XCEP (interop) or ACME (RFC 8555) or EST (RFC 7030) or SCEP (RFC 8894); CRL distribution — HTTP / LDAP; OCSP responder — RFC 6960; CA admin — certificate templates, revocation, key archival; NDES-equivalent for network devices.

**Depends on**: Core Directory (publishes certs, templates, CRLs).

**Consumed by**: KDC (PKINIT), Auth Provider (smart-card logon, TLS client cert), Federation Gateway (token signing), File Gateway (SMB encryption).

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-057 | AD CS (certsvc.exe + ESE CA DB) is Windows-only; no open-source MS-WCCE server | blocker | Windows, Linux |
| PC-058 | Certificate templates (v1/v2/v3) with `msPKI-*` attributes are complex | high | cross-platform |
| PC-059 | Autoenrollment via `autoenroll.dll` CSE + GPO is Windows-only | high | Windows, macOS, Linux |
| PC-060 | Key archival (KRA) is risky; losing KRA keys loses all archived keys | high | cross-platform |
| PC-061 | OCSP responder scaling; CA database corruption during outage | high | cross-platform |
| PC-062 | CA database corruption recovery is "restore from backup, do not eseutil /p" | medium | cross-platform |
| PC-063 | Certificate revocation during CA outage (CRL/OCSP unreachable) breaks TLS | high | cross-platform |
| PC-064 | NDES (SCEP for network devices) is fragile; IIS dependency | medium | cross-platform |
| PC-065 | Cross-CA trust (cross-cert) via `CrossCertificatePair` is rarely used | low | cross-platform |
| PC-066 | Two-tier vs three-tier CA topology is a greenfield design decision | medium | cross-platform |
| PC-067 | `NTAuthCertificates` AD object is the canonical list of logon-authorized CAs | high | cross-platform |

Severity totals: 1 blocker, 4 high, 5 medium, 1 low.

## Detailed problem entries

### PC-057 — AD CS (certsvc.exe + ESE CA DB) is Windows-only; no open-source MS-WCCE server

**Capability**: Cert Service
**Severity**: blocker
**Cross-platform**: Windows, Linux

**Problem statement**:

AD CS runs as `certsvc.exe` inside `svchost -k certsvc`, hosting one or more CA instances each backed by an ESE (Jet Blue) database (`*.edb`) at `%SystemRoot%\System32\CertLog\<CAName>.edb`, per [05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md). The CA database is opened via `JetInit3` + `JetBeginSession` + `JetOpenDatabase` in `certca.dll!caOpenDatabase` with tables `RequestTable`, `CertificateTable`, `CRLTable`, `KeyRecoveryTable`. Policy module `certpmod.dll` exports `ICertPolicy2` (`{8691B64C-A8D5-4FAD-A40D-7DC81CABF1CC}`); exit module `certxmod.dll` exports `ICertExit2` (`{9c37b45a-4b3f-11d1-8250-00a0c903a8cb}`).

The enrollment protocol is MS-WCCE (Windows Client Certificate Enrollment) — DCE/RPC interface ICertPassage UUID `91b9b93a-57b4-11d0-8f16-00a0484d6c9c`, version 0.0. Key opnums: 0 (`Request`), 1 (`GetCACert`), 2 (`Ping`), 36 (`Request` modern path with template OID + attribute blob). MS-XCEP (CEP, HTTPS SOAP) provides policy discovery at `/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP`. MS-WSTEP (CES, HTTPS SOAP) wraps PKCS#10 CSR in `<wstep:RequestSecurityToken>` for enrollment across forests/DMZ. Per the matrix in [10-comparison-matrices/02-protocol-implementation-matrix.md](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md), Samba does NOT implement MS-WCCE server; FreeIPA's Dogtag uses a different RA protocol; certmonger with the `cepces` plugin is the only Linux client of MS-WCCE/MS-XCEP.

The blocker: there is no open-source MS-WCCE server. Customers who need Windows autoenrollment (the most common AD CS use case) cannot run a non-Windows CA without losing `autoenroll.dll` integration. FreeIPA's Dogtag CA is the closest functional equivalent — supports SCEP, EST, cert autoenrollment via `certmonger`, but does NOT speak MS-WCCE/MS-XCEP/MS-WSTEP.

For the framework, the choice is binary: (a) implement MS-WCCE/MS-XCEP/MS-WSTEP server-side for AD interop with Windows `autoenroll.dll`, or (b) adopt a modern protocol (ACME RFC 8555, EST RFC 7030) and lose Windows autoenroll interop. Option (a) preserves the existing Windows client; option (b) requires a new autoenroll agent on Windows.

**Impact**:

Windows autoenrollment breaks without MS-WCCE; `certmonger` cannot enroll against AD CS without `cepces`. Windows machines that depend on autoenroll for computer certs (IPsec, 802.1X, S/MIME, Kerberos PKINIT) cannot be served by a non-Windows CA.

**Constraints**:

- Must support MS-WCCE/MS-XCEP/MS-WSTEP for Windows interop (existing `autoenroll.dll` clients).
- ACME (RFC 8555) is the modern alternative for new clients.
- EST (RFC 7030) for IoT / network devices.
- SCEP (RFC 8894) for routers/switches (NDES-equivalent).

**Cross-platform considerations**:

- **Windows**: `certsvc.exe` + `autoenroll.dll` CSE + `certreq.exe` are the native stack; MS-WCCE/MS-XCEP/MS-WSTEP are required.
- **macOS**: MDM SCEP profile (`com.apple.security.scep`) is the native enrollment mechanism; no MS-WCCE client.
- **Linux**: `certmonger` with `cepces` plugin speaks MS-WCCE/MS-XCEP; without `cepces`, falls back to Dogtag/SCEP/EST.
- **Cross-platform consistency**: ACME is the only protocol with cross-platform client support; MS-WCCE is Windows-only; SCEP is universal but limited (no key archival, no template ACLs).

**KB references**:

- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — `certsvc.exe` process model, ICertPassage RPC UUID, MS-WCCE/MS-XCEP/MS-WSTEP endpoint URLs.
- [`05-pki-certs/01-ad-cs-architecture.md`](../docs/05-pki-certs/01-ad-cs-architecture.md) — ESE CA database tables, `certpmod.dll`/`certxmod.dll` module lifecycle, per-CA registry layout.
- [`10-comparison-matrices/02-protocol-implementation-matrix.md`](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md) — MS-WCCE row showing only Windows Server implements the server side; Dogtag has its own RA protocol.

**Open questions**:

- Adopt ACME (RFC 8555) for new clients + MS-WCCE adapter for Windows `autoenroll.dll`?
- Implement Dogtag-style REST API and lose Windows autoenroll interop?
- Implement MS-WCCE server-side as a translation layer over a modern CA backend (ACME-style internal API)?

**Cross-capability impact**:

- Affects: PC-059 (autoenrollment via `autoenroll.dll`), PC-067 (NTAuthCertificates distribution).
- Affected by: PC-058 (cert templates are the policy surface that MS-WCCE carries).

---

### PC-058 — Certificate templates (v1/v2/v3) with `msPKI-*` attributes are complex

**Capability**: Cert Service
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD CS templates are `pKICertificateTemplate` AD objects (governsID `1.2.840.113556.1.5.119`) at `CN=<Template>,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<NC>`, per [05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md). The template drives subject name construction (`msPKI-Certificate-Name-Flag` bitmask — `0x1` ENROLLEE_SUPPLIES_SUBJECT, `0x10` SUBJECT_ALT_REQUIRE_SPN, `0x40` SUBJECT_ALT_REQUIRE_UPN, `0x100` SUBJECT_ALT_REQUIRE_DNS_AS_CN, etc.), key generation (`msPKI-Private-Key-Flag` — `0x1` EXPORTABLE_KEY, `0x4` REQUIRE_ARCHIVAL, `0x80` REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM for CNG RSASSA-PSS, `0x100` REQUIRE_ATTESTATION for TPM), EKU enforcement (`pKIExtendedKeyUsage` OID array — `1.3.6.1.5.5.7.3.1` serverAuth, `1.3.6.1.4.1.311.20.2.1` smartCardLogon, `1.3.6.1.4.1.311.21.6` KRA, etc.), key usage (`pKIKeyUsage` 2-byte bitmask), Basic Constraints (`pKIMaxIssuingDepth` → `pathLenConstraint`), validity (`pKIExpirationPeriod` / `pKIOverlapPeriod` 8-byte FILETIME), and ACL (`nTSecurityDescriptor` with `Enroll` right GUID `0e10c968-78d0-11d2-af90-00c04f990c33` and `Autoenroll` right GUID `a05b8cc2-17bc-4802-a710-e7c15ab866a2`).

Template versions: v1 (NT4/Win2000, no ACLs), v2 (Win2003, adds `nTSecurityDescriptor` ACL, full customization via CryptoAPI legacy CSP), v3 (Win2008, CNG-based `msPKI-Private-Key-Flag` for key isolation, KSP, Suite B algorithms, key attestation). `msPKI-Template-Schema-Version` (`1.2.840.113556.1.4.1499`) maps `1` = v2 template, `2` = v3 template. Per the same KB, supersession via `msPKI-Supersede-Templates` (multi-valued list of template `cn` values) drives autoenroll to purge superseded certs when `REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE` (0x100 in `msPKI-Enrollment-Flag`) is set.

The complexity is operator-hostile: a single template misconfiguration (e.g., `msPKI-Certificate-Name-Flag` set to `0x1` ENROLLEE_SUPPLIES_SUBJECT on a smart-card template) can allow a user to request a cert with arbitrary subject, escalating privileges. The ACL model is fragile: removing `Authenticated Users` from a template's ACL is the most common cause of `0x80094012 — The permissions on the certificate template do not allow the current user to enroll`. macOS MDM SCEP profiles encode a subset of this (SubjectName, KeyUsage, ExtendedKeyUsage) but no ACL model; FreeIPA Dogtag profiles use `.cfg` files with `policyset` stanzas replacing `msPKI-*` attributes and `auth.class_id` replacing the template ACL.

For the framework, the choice is between (a) a single JSON template schema with ACL projection to AD (and a translation layer for Dogtag profile format), (b) adopting Dogtag's `.cfg` profile format directly, or (c) preserving `msPKI-*` attributes for AD interop and adding a higher-level JSON wrapper.

**Impact**:

Template authoring is expert-only; the ACL model is fragile. A misconfigured template can allow privilege escalation (ENROLLEE_SUPPLIES_SUBJECT on a sensitive template) or break autoenroll entirely (`Authenticated Users` removed without a replacement group).

**Constraints**:

- Must support per-template ACL (Enroll, Autoenroll, Write, Read) with the two extended-right GUIDs.
- Must support EKU enforcement (the `pKIExtendedKeyUsage` OID array).
- For AD interop, must preserve `msPKI-*` attributes on the AD object.

**Cross-platform considerations**:

- **Windows**: AD CS consumes templates via `certpmod.dll!GetTemplate` at request time; ACL check via `nTSecurityDescriptor`.
- **macOS**: MDM SCEP profile encodes subject/key-usage/EKU but no ACL model. Per-device profile scoping replaces ACL.
- **Linux**: FreeIPA Dogtag uses `certprofile` with `policyset` stanzas and `caacl` (CA Access Control List) for ACL-equivalent. `certmonger` requests via `-T <profile>`.
- **Cross-platform consistency**: a single JSON template schema that compiles to AD template / MDM profile / Dogtag profile is the cross-platform path.

**KB references**:

- [`05-pki-certs/02-certificate-templates.md`](../docs/05-pki-certs/02-certificate-templates.md) — Full `msPKI-*` attribute table, v1/v2/v3 schema differences, ACL extended-right GUIDs, supersession model.
- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — `certpmod.dll` policy module lifecycle, `VerifyRequest` template lookup and ACL check, common error codes `0x80094800` / `0x80094012`.

**Open questions**:

- Single JSON template schema with ACL projection to AD `msPKI-*` attributes?
- Adopt Dogtag profile format (`.cfg` with `policyset` stanzas) for cross-platform?
- Treat `msPKI-*` as legacy read-only and require new templates to use JSON?

**Cross-capability impact**:

- Affects: PC-057 (MS-WCCE carries template OIDs), PC-059 (autoenroll honors template ACLs).
- Affected by: PC-067 (NTAuthCertificates constrains which CAs can issue logon certs; templates add the per-CA constraint layer).

---

### PC-059 — Autoenrollment via `autoenroll.dll` CSE + GPO is Windows-only

**Capability**: Cert Service
**Severity**: high
**Cross-platform**: Windows, macOS, Linux

**Problem statement**:

Autoenrollment is the client-side `autoenroll.dll` invoked by Group Policy CSE `{71587597-1207-11D2-8250-00A0C903A8CB}` (registered at `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\CSEs\{71587597-...}` with `DllName = %SystemRoot%\system32\autoenroll.dll`), per [05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md). The CSE is triggered by `gpsvc.dll` at every GP refresh (default 90 min + jitter), at logon/startup via `winlogon`, by Task Scheduler `\Microsoft\Windows\CertificateServicesClient\AutoEnroll`, or manually via `certutil -pulse`. Per [04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md), the CSE exports `ProcessGroupPolicy`/`ProcessGroupPolicyEx`.

The flow: `autoenroll.dll` performs MS-XCEP policy discovery (CEP HTTPS POST to `/ADPolicyProvider/CertificateEnrollment/Service.svc/CEP` with `<cep:GetPolicies>` SOAP envelope), filters policies by caller domain and EKU context, then submits CSRs over MS-WCCE (DCOM ICertPassage opnum 36) or MS-WSTEP (CES HTTPS SOAP wrapping PKCS#10 in `<wst:RequestSecurityToken>`). The CA's exit module publishes the issued cert to the requester's `userCertificate` AD attribute via `ldap_modify_s` with `LDAP_MOD_REPLACE`. Renewal triggers at 80% of cert lifetime (or per-template `pKIOverlapPeriod`).

macOS has no equivalent — MDM SCEP profile is per-device with no autoenroll trigger; re-enrollment on expiry requires MDM push or a `launchd` daemon. Linux uses `certmonger` with the `cepces` plugin (MS-WCCE/MS-XCEP client) or Dogtag/SCEP/EST. `certmonger` runs as a systemd service with per-cert timers; `getcert request -c dogtag -T <profile> -f <file> -k <file>` polls and renews.

For the framework, a unified autoenroll daemon (cross-platform) that pulls policy from a unified endpoint and submits CSRs over ACME/MS-WCCE/SCEP would be the right design. Key-based renewal (MS-WSTEP, `msPKI-Certificate-Name-Flag` bit `0x4000000`) is essential for unattended hosts — the client renews using the old cert's private key for authentication, not a user password. macOS uses Keychain; Linux uses KRA (Dogtag DRM) or NSS DB; Windows uses CNG KSP — the daemon must support all three platform-native key stores.

**Impact**:

Cross-platform autoenroll requires per-OS agents today. macOS re-enrollment on cert expiry is fragile (relies on MDM push); Linux `certmonger` works against Dogtag but not against AD CS without `cepces`.

**Constraints**:

- Must support key-based renewal (MS-WSTEP) for unattended hosts.
- Must support key archival (template `REQUIRE_PRIVATE_KEY_ARCHIVAL` bit `0x8`).
- Must support platform-native key stores (Keychain on macOS, KRA/CNG on Windows, NSS/KRA on Linux).
- For AD interop, must preserve `autoenroll.dll` CSE invocation model.

**Cross-platform considerations**:

- **Windows**: `autoenroll.dll` CSE + GPO registry `HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment\AEPolicy = 0x7`.
- **macOS**: MDM SCEP profile (`com.apple.security.scep`); no GPO-equivalent trigger. `ManagedClient.app` re-enrolls on expiry.
- **Linux**: `certmonger` systemd service with per-cert timers; `cepces` plugin for MS-WCCE/MS-XCEP.
- **Cross-platform consistency**: a single certmonger-style daemon with platform-native key store adapters is the unified path.

**KB references**:

- [`05-pki-certs/03-autoenrollment.md`](../docs/05-pki-certs/03-autoenrollment.md) — `autoenroll.dll` CSE architecture, MS-XCEP/MS-WCCE/MS-WSTEP flow, key archival via KRA cert, publication to `userCertificate` AD attribute.
- [`04-group-policy/04-cse-client-side-extensions.md`](../docs/04-group-policy/04-cse-client-side-extensions.md) — CSE GUID `{71587597-...}` registry layout, `ProcessGroupPolicy`/`ProcessGroupPolicyEx` prototype.

**Open questions**:

- Single `certmonger`-style daemon with platform-native key store adapters (Keychain, KRA, CNG)?
- ACME + SCEP dual-protocol (ACME for new clients, SCEP for network devices)?
- MS-WSTEP client for non-Windows to enable key-based renewal?

**Cross-capability impact**:

- Affects: PC-060 (key archival is invoked by autoenroll for templates with `REQUIRE_PRIVATE_KEY_ARCHIVAL`).
- Affected by: PC-057 (MS-WCCE/MS-XCEP/MS-WSTEP are the protocols autoenroll speaks), PC-058 (templates drive autoenroll behavior).

---

### PC-060 — Key archival (KRA) is risky; losing KRA keys loses all archived keys

**Capability**: Cert Service
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

When `msPKI-Private-Key-Flag.REQUIRE_PRIVATE_KEY_ARCHIVAL` (bit `0x8`) is set on a template, the CSR is wrapped with the CA's Key Recovery Agent (KRA) certificate(s) per RFC 2511 (CMS `EnvelopedData`): AES-256 content key + RSA-OAEP wrap with the KRA cert's RSA public key, per [05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md). The CA's `certca.dll!KRAArchiveRequest` decrypts the envelope using the KRA private key (only after operator-initiated recovery via `certutil -recoverkey`), then stores the original private key in the `KeyRecoveryTable` row linked to the issued certificate's `CertificateHash`. KRA certificates are published to AD `CN=KRAContainer,CN=Public Key Services,CN=Services,CN=Configuration,...`. The CA reads them at service start; the registry value `HKLM\...\CertSvc\Configuration\<CA>\KeyRecoveryAgentCount` (default 1) controls how many KRAs are needed for quorum.

Per [01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), the failure mode is binary: if KRA private keys are lost, all archived keys are unrecoverable. The recovery flow requires `certutil -recoverkey` with the KRA cert + private key, then operator approval via the CA console (`certsrv.msc` → "Key Recovery Agent" → "Recover Key"). If the KRA cert expires or its private key is destroyed (e.g., HSM failure without backup), every cert issued under the archival-required template becomes unrecoverable.

The single-KRA default (`KeyRecoveryAgentCount = 1`) is operationally risky: there is no quorum, no redundancy, no rotation procedure baked in. Multi-KRA with quorum (N-of-M) requires the CA to use multiple KRA certs and require N to recover — but the CA does not natively support Shamir secret sharing or multi-party recovery. KRA cert rotation requires re-issuing all archived keys (or keeping old KRA certs valid forever, defeating rotation).

For the framework, HSM-backed KRA private keys + multi-KRA quorum (N-of-M via Shamir secret sharing) is the right design. KRA cert rotation should be transparent (re-wrap archived keys under new KRA without re-enrolling users). FreeIPA's Dogtag DRM (Data Recovery Manager) subsystem provides similar functionality but with a different session-key wrapping model.

**Impact**:

KRA key loss = unrecoverable user keys. EFS-encrypted files, S/MIME-encrypted email, and any cert with archival-required become permanently inaccessible. This is a break-glass scenario with no recovery path.

**Constraints**:

- Must support multiple KRAs with quorum (N-of-M).
- Must support KRA cert rotation (re-wrap archived keys under new KRA without re-enrolling users).
- Must support HSM-backed KRA private keys (CNG KSP / PKCS#11).
- For AD interop, must honor `REQUIRE_PRIVATE_KEY_ARCHIVAL` template flag and `KeyRecoveryAgentCount` registry.

**Cross-platform considerations**:

- **Windows**: AD CS KRA via `certca.dll!KRAArchiveRequest`; `CN=KRAContainer` AD publication; `certutil -recoverkey` CLI. Single-KRA default.
- **macOS**: MDM key escrow via Profiles + `security cms -D` (limited); no multi-KRA quorum.
- **Linux**: Dogtag DRM subsystem + `pki key-archive` / `pki key-retrieve`; session-key wrapping model differs from AD CS.
- **Cross-platform consistency**: HSM-backed KRA with multi-party recovery (Shamir) is the cross-platform secure default.

**KB references**:

- [`05-pki-certs/03-autoenrollment.md`](../docs/05-pki-certs/03-autoenrollment.md) — Key archival flow (Phase 4), KRA cert publication to AD, `KeyRecoveryAgentCount` registry, `certca.dll!KRAArchiveRequest`.
- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — KRA recovery procedure via `certutil -recoverkey`, `KeyRecoveryTable` schema, single-KRA default risk.

**Open questions**:

- HSM-backed KRA private keys (CNG KSP / PKCS#11) with threshold cryptography?
- Multi-party KRA recovery via Shamir secret sharing (N-of-M KRA privates required to unwrap)?
- Transparent KRA cert rotation (re-wrap archived keys under new KRA without re-enrolling users)?

**Cross-capability impact**:

- Affects: PC-059 (autoenroll triggers archival for templates with `REQUIRE_PRIVATE_KEY_ARCHIVAL`).
- Affected by: PC-058 (templates drive the archival requirement), PC-066 (CA topology affects KRA placement).

---

### PC-061 — OCSP responder scaling; CA database corruption during outage

**Capability**: Cert Service
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD CS Online Responder (`OCSPResp.exe` under `svchost -k NetworkService`) signs `BasicOCSPResponse` blobs (RFC 6960 ASN.1: `OCSPResponse` → `ResponseBytes` → `BasicOCSPResponse` → `ResponseData` → `SingleResponse` per cert) using an OCSP signing cert (EKU `id-kp-OCSPSigning` 1.3.6.1.5.5.7.3.9, carries `ID-PKIX-OCSP-NoCheck` extension OID 1.3.6.1.5.5.7.48.1.5 so clients skip the signing cert's own CRL check), per [05-pki-certs/04-ocsp-crl.md](../docs/05-pki-certs/04-ocsp-crl.md). The responder reads the CA's CRL from `CRLTable` in the CA ESE database. Per-revocation-configuration registry: `HKLM\SYSTEM\CurrentControlSet\Services\OCSP\Responder\<RevocationConfigName>\SigningFlags = 0x31` (bit 0 = use CA cert private key for signing, bit 4 = RESIGN_ON_KEY_WARNING re-sign after CRL update, bit 5 = DISABLE_SSL_CLIENT_CERT_CHECK).

The scaling problems: (a) the OCSP responder is a single point of failure during CA outage — if the CA ESE database is unreachable, the responder cannot refresh its CRL cache; (b) CRL generation can fail with `0x80070020` (file in use) when IIS holds the CRL file lock; (c) for large CAs (10K+ revoked certs), the `SerNumDir\0a\0b\...` hash bucket lookup becomes slow (10+ seconds per OCSP response); (d) the responder does not natively support clustering — multiple responder instances must share the same CRL source, which requires file-system or SQL-backed CRL distribution. Per the same KB, `pkiview.msc` shows OCSP "Error: the OCSP response is invalid" when the signing cert expires; renewal via `OCSPResponseSigning<CAName>` template enroll on the OCSP host (`certutil -pulse`) is the recovery.

For the framework, clustered OCSP responders (multiple instances behind a load balancer, each with independent signing cert but shared CRL source) + CRL pre-publication (publish next CRL before current expires — `CRLOverlapPeriod` already does this on the CA) are the baseline. CRLite (Mozilla's compressed CRL format) is a research-grade optimization for massive forests (millions of certs); it compresses the CRL to a few KB via Bloom filter cascades, eliminating the need for per-cert OCSP lookups.

**Impact**:

OCSP responder is a single point of failure during CA outage. TLS clients that fail-closed on revocation check (`0x80092013 — Revocation offline`) cannot establish TLS connections to cert-backed services. Worst case: an entire forest's TLS infrastructure cascades down during CA outage.

**Constraints**:

- Must support `ID-PKIX-OCSP-NoCheck` extension on signing cert.
- Must support pre-cached CRL (`CRLOverlapPeriod`).
- Must support nonce extension (OID 1.3.6.1.5.5.7.48.1.2) for replay prevention.
- Must support multiple OCSP responder instances (clustering).

**Cross-platform considerations**:

- **Windows**: `OCSPResp.exe` under `svchost -k NetworkService`; HTTP via `http.sys` URL ACL `https://+:80/ocsp` / `https://+:443/ocsp`.
- **macOS**: `ocspd` daemon (built-in) caches CRLs at `/private/var/db/crls/cacerts.pem`; no native OCSP responder.
- **Linux**: Dogtag OCSP subsystem (`pki-tomcat` instance) for server-side; `openssl ocsp -url ...` for client-side. No native clustered OCSP.
- **Cross-platform consistency**: HTTP-based OCSP (RFC 6960) is universal; clustering and CRLite are framework concerns.

**KB references**:

- [`05-pki-certs/04-ocsp-crl.md`](../docs/05-pki-certs/04-ocsp-crl.md) — OCSP responder architecture, `BasicOCSPResponse` ASN.1, `SigningFlags` registry bitmask, `SerNumDir` hash bucket lookup, common failures including `0x80070020` and stale-CRL.
- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — `certsvc.exe` service dependencies (RPCSS, CryptSvc), `CRLTable` ESE table layout, `certutil -crl` CRL publication command, `pkiview.msc` health console.

**Open questions**:

- Adopt CRLite (Mozilla) for massive-CRL compression (Bloom filter cascade, ~10 KB instead of multi-MB CRL)?
- Multi-responder OCSP clustering with shared CRL source (SQL-backed or distributed KV)?
- Pre-cached OCSP responses (sign next N hours of responses in advance)?

**Cross-capability impact**:

- Affects: PC-063 (revocation during CA outage — OCSP responder scaling directly affects this).
- Affected by: PC-062 (CA DB corruption — OCSP responder depends on CA DB for CRL).

---

### PC-062 — CA database corruption recovery is "restore from backup, do not eseutil /p"

**Capability**: Cert Service
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

CA ESE database (`%SystemRoot%\System32\CertLog\<CAName>.edb`, page size 32 KB on Server 2016+) corruption is detected via JET errors: `JET_errDbTimeTooNew`, `JET_errDbTimeCorrupted`, `JET_errDiskRead` (-1022), per [05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md). The recovery procedure, per [01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), is "restore from backup" — running `eseutil /p` (hard repair) on a CA database is explicitly discouraged because it can break cert serial continuity (the `Request.RequestRow` → `Certificate.CertRowId` foreign-key chain) and lose rows that ESE considers "logically deleted" but that are still queryable.

CA database backup uses `certutil.exe -backup` or the `CertSvc VSS Writer` (writer ID `{5425FD7A-0D43-4C59-AA61-D3D2D8E9A9D7}`). Restoration requires `certutil -restoreDB` followed by `-restoreKey` to re-import the CA private key from the `.p12` backup. The CA service must be stopped during restore; the CA is offline for the duration (typically 30 minutes to several hours depending on database size). Per the same KB, ESE transaction-log replay (`edbXXXXX.log` files) can recover from soft crashes; hard crashes require backup restore.

The operational pain: a CA database restore is a multi-hour outage. During the outage, no new certs can be issued, no revocations can be processed (the CRL cannot be regenerated from a stale database), and OCSP responses become stale. For an Enterprise CA serving 10K+ users with autoenroll, this means cert renewal failures cascade.

For the framework, online CA DB repair (while the CA continues to serve reads from a replica) + point-in-time recovery (PITR via WAL replay) is the modern alternative. FoundationDB, CockroachDB, or SQLite WAL mode are candidate storage backends. The framework should NOT use ESE; the choice of storage backend is a foundational decision.

**Impact**:

CA DB corruption is a multi-hour outage. During the outage, no new certs can be issued and no revocations can be processed. OCSP responses become stale. TLS clients that fail-closed on revocation check cascade-fail.

**Constraints**:

- Must support WAL/transaction-log replay for soft crash recovery.
- Must support point-in-time recovery (PITR) for hard crash recovery.
- Must support online repair (CA continues to serve reads from a replica while a member is repaired).
- Must NOT break cert serial continuity (the `Request.RequestRow` → `Certificate.CertRowId` chain).

**Cross-platform considerations**:

- **Windows**: ESE (Jet Blue) with `eseutil /r` (soft recovery) and `eseutil /p` (hard repair — discouraged for CA DB). `CertSvc VSS Writer` for backup.
- **macOS**: No CA database on macOS; Apple deprecated macOS Server CA in 5.x.
- **Linux**: Dogtag uses 389-DS LDAP as its cert DB; backup via `ns-slapd` LDIF export + restoration via `ns-slapd` LDIF import. Different failure mode (LDAP corruption vs. ESE corruption).
- **Cross-platform consistency**: the framework should pick a storage backend (FoundationDB / CockroachDB / SQLite WAL) and use it on all platforms.

**KB references**:

- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — ESE database corruption detection (`JET_errDbTimeTooNew`, `JET_errDiskRead` -1022), "do not eseutil /p" warning, `certutil -backup`/`-restoreDB`/`-restoreKey` workflow, `CertSvc VSS Writer` ID.
- [`05-pki-certs/01-ad-cs-architecture.md`](../docs/05-pki-certs/01-ad-cs-architecture.md) — ESE database schema (`RequestTable`, `CertificateTable`, `CRLTable`, `KeyRecoveryTable`), `CircularLogging` registry, `DBSessionCount`/`DBPageSize` tuning.

**Open questions**:

- Adopt FoundationDB or CockroachDB for CA storage (multi-master replication, online repair, PITR)?
- SQLite WAL mode for single-CA deployments (simpler, no replication)?
- Treat the CA DB as immutable append-only (issued certs never deleted, revocations as tombstones) and use a log-structured store?

**Cross-capability impact**:

- Affects: PC-061 (OCSP responder depends on CA DB for CRL), PC-063 (revocation during CA outage — CA DB corruption IS a CA outage).
- Affected by: PC-007 (Core Directory storage engine choice — same decision applies to CA DB if shared).

---

### PC-063 — Certificate revocation during CA outage (CRL/OCSP unreachable) breaks TLS

**Capability**: Cert Service
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

If CRL/OCSP is unreachable from a client, the client either fails-closed (TLS reject with `0x80092013 — Revocation offline`) or fails-open (skip revocation check, accept cert) depending on the application's policy. Per [05-pki-certs/04-ocsp-crl.md](../docs/05-pki-certs/04-ocsp-crl.md), AD CS publishes CRLs to AD (`certificateRevocationList` attribute on `CN=<CAName>,CN=...-CDP,CN=Public Key Services,...`) and HTTP (URL encoded in the cert's CRL Distribution Point extension OID 2.5.29.31, e.g., `http://pki.corp.example.com/crl/<CAName>.crl`). The OCSP URL is encoded in the Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1) with accessMethod `ad-ocsp` (1.3.6.1.5.5.7.48.1).

During CA/AD outage: (a) CRL cannot be regenerated (CA service is down, `certutil -crl` fails); (b) existing CRLs may expire (`NextUpdate` passes, clients reject the stale CRL); (c) OCSP responder cannot refresh its CRL cache; (d) LDAP-based CRL fetch fails (AD is down). Per the same KB, `CRLOverlapPeriod` (Server 2008+) extends CRL validity — a new CRL is published *before* the old one's `NextUpdate`, so the overlap window covers CA downtime. But this only works if the overlap window is longer than the outage; a multi-day outage exceeds any reasonable overlap.

For the framework, the design must include: (a) cached CRL on client (Windows: `CryptnetUrlCache`, macOS: `/private/var/db/crls/cacerts.pem`, Linux: `/etc/ssl/certs/` + `c_rehash`); (b) multiple CDP URLs (HTTP + LDAP + FILE); (c) OCSP stapling (server sends pre-fetched OCSP response in TLS handshake, per RFC 6066 §8); (d) backup CRL distribution points (CDN-backed HTTP, independent of AD); (e) CRLite for massive forests (Bloom filter cascade, eliminates per-cert OCSP lookups). The client-side behavior (fail-closed vs. fail-open) should be per-application configurable, not a global policy.

**Impact**:

TLS outages cascade during CA/AD outage. A revoked cert cannot be detected by clients; worse, a valid cert cannot be validated by clients that fail-closed. Worst case: an entire forest's TLS infrastructure (LDAPS, HTTPS, RDP, WinRM) cascade-fails.

**Constraints**:

- Must support CRL caching on client (per-platform `CryptnetUrlCache` / `cacerts.pem` / `c_rehash`).
- Must support multiple CDP URLs (HTTP primary, LDAP secondary, FILE tertiary).
- Must support OCSP stapling (RFC 6066 §8).
- Must support backup CRL distribution points (CDN-backed HTTP, independent of AD).

**Cross-platform considerations**:

- **Windows**: `CryptnetUrlCache` CRL cache at `%SystemRoot%\System32\CertSrv\CertEnroll\`; `certutil -urlfetch -verify` walks AIA/CDP/OCSP URLs. Fail-closed default for `WinHttpSetOption(SECURITY_FLAG_IGNORE_REVOCATION)` callers.
- **macOS**: `ocspd` daemon caches CRLs at `/private/var/db/crls/cacerts.pem`; `security` CLI for trust store. Configurable via `com.apple.security.ocsp` preference pane.
- **Linux**: OpenSSL `X509_STORE` cache; `/etc/ssl/certs/` + `c_rehash`. Per-application policy (e.g., `curl --crlfile`, `openssl -crl_check`).
- **Cross-platform consistency**: fail-closed vs. fail-open policy should be per-application and consistent across platforms.

**KB references**:

- [`05-pki-certs/04-ocsp-crl.md`](../docs/05-pki-certs/04-ocsp-crl.md) — CRL publication URLs and flags, AIA/CDP extension OIDs, `CRLOverlapPeriod`, `0x80092013 — Revocation offline` error, OCSP stapling.
- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — CRL/OCSP HTTP endpoint table, `CRLPublicationURLs` registry multi-string format, `certutil -urlfetch -verify` chain-walk diagnostic.

**Open questions**:

- CRLite for massive forests (Bloom filter cascade, eliminates per-cert OCSP lookups)?
- Multi-CDP HTTP fallback with CDN-backed distribution independent of AD?
- Per-application fail-closed vs. fail-open policy (e.g., LDAPS fail-closed, HTTPS fail-open with warning)?

**Cross-capability impact**:

- Affects: PC-061 (OCSP responder scaling — clustering directly affects availability during CA outage).
- Affected by: PC-062 (CA DB corruption is one cause of CA outage).

---

### PC-064 — NDES (SCEP for network devices) is fragile; IIS dependency

**Capability**: Cert Service
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

NDES (Network Device Enrollment Service) is the AD CS role that provides SCEP (Simple Certificate Enrollment Protocol, RFC 8894) enrollment for routers, switches, IoT devices, and other non-domain-joined devices. Per [01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), NDES runs as `SCEP.exe` service under IIS + ASP.NET + dynamic RPC. Configuration is multi-step: install the NDES role, configure the RA (Registration Authority) cert, configure the SCEP URL (`https://<server>/certsrv/mscep/`), set the challenge password, configure the CA template (an NDES-specific copy of an existing template with `msPKI-Certificate-Name-Flag = 0x1` ENROLLEE_SUPPLIES_SUBJECT and the RA's ACL), and verify the IIS application pool identity has `Enroll` on the template.

Per [05-pki-certs/03-autoenrollment.md](../docs/05-pki-certs/03-autoenrollment.md), the NDES flow: (1) device fetches the RA cert + CA cert via `GET /certsrv/mscep/mscep.dll?operation=GetCACert&message=<ra-name>`; (2) device obtains a one-time challenge password from the NDES admin (via `https://<server>/certsrv/mscep/`); (3) device submits a PKCS#10 CSR wrapped in a PKCS#7 envelope signed by the RA, encrypted to the RA, via `POST /certsrv/mscep/mscep.dll?operation=PKIOperation`; (4) NDES unwraps, submits to the CA via DCOM ICertPassage, returns the issued cert. The challenge password is single-use (regenerated every 60 minutes by default).

The fragility: NDES depends on IIS + ASP.NET, which adds a heavy Windows-only stack. The challenge password distribution is manual (admin copies from the NDES web page to the device). The RA cert must be renewed before expiry (a separate autoenroll task on the NDES host). Configuration errors are common: mis-scoped template ACL, IIS app pool identity mismatch, expired RA cert. There is no native Linux/macOS NDES server.

For the framework, a modern SCEP/EST/ACME endpoint without IIS dependency is the design. EST (RFC 7030) is the IETF-standardized successor to SCEP — HTTPS-based, no challenge password (uses TLS client cert auth instead). ACME (RFC 8555) is the modern standard for automated enrollment (Let's Encrypt model). A single enrollment endpoint that speaks all three protocols (SCEP for legacy network devices, EST for IoT, ACME for modern clients) with per-protocol adapters is the right design.

**Impact**:

NDES is the only AD-native SCEP; the alternative is third-party (Gatekeeper, certNanny, xCA SCEP). NDES configuration errors are a top-5 AD CS support case. The IIS dependency adds attack surface (IIS vulnerabilities, ASP.NET deserialization).

**Constraints**:

- Must support SCEP (RFC 8894) for legacy network devices (routers, switches).
- Should support EST (RFC 7030) for IoT.
- Should support ACME (RFC 8555) for modern clients.
- No IIS dependency — HTTPS endpoint should be a self-contained service.

**Cross-platform considerations**:

- **Windows**: NDES via `SCEP.exe` + IIS + ASP.NET. RA cert autoenroll via `autoenroll.dll` CSE.
- **macOS**: No native SCEP server; MDM SCEP profile is a client only.
- **Linux**: No native NDES-equivalent; third-party (Gatekeeper, certNanny, xCA SCEP) or Dogtag SCEP interface.
- **Cross-platform consistency**: a single HTTPS endpoint speaking SCEP+EST+ACME with per-protocol adapters is the cross-platform path.

**KB references**:

- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — NDES role, IIS + ASP.NET dependency, SCEP URL `/certsrv/mscep/`, RA cert lifecycle.
- [`05-pki-certs/03-autoenrollment.md`](../docs/05-pki-certs/03-autoenrollment.md) — NDES enrollment flow (GetCACert → challenge → PKIOperation), challenge password single-use 60-minute rotation.

**Open questions**:

- Single enrollment endpoint that speaks SCEP + EST + ACME?
- Per-protocol adapters (SCEP for legacy, EST for IoT, ACME for modern)?
- Drop SCEP support and require EST/ACME (forces network device upgrade)?

**Cross-capability impact**:

- Affects: PC-057 (MS-WCCE / ACME choice — NDES is the SCEP corner of the same enrollment-protocol decision).
- Affected by: PC-058 (NDES uses a template — an NDES-specific copy with `ENROLLEE_SUPPLIES_SUBJECT`).

---

### PC-065 — Cross-CA trust (cross-cert) via `CrossCertificatePair` is rarely used

**Capability**: Cert Service
**Severity**: low
**Cross-platform**: cross-platform

**Problem statement**:

Cross-certification is the PKI mechanism where root A signs root B's cert (and vice versa, or one-way), creating a bridge. Per [05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md), AD stores cross-certs in the `CrossCertificatePair` attribute (OID 2.5.4.41) on the `NTAuthCertificates` object at `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,...`. Path validation must then walk both native and cross-cert chains, applying `NameConstraints` (OID 2.5.29.30), `PolicyConstraints` (OID 2.5.29.36), and `PolicyMappings` (OID 2.5.29.33) extensions to constrain the cross-certified namespace.

Per [01-ad-core/02-ad-cs-cert-services.md](../docs/01-ad-core/02-ad-cs-cert-services.md), cross-cert is rarely deployed in practice due to path-validation complexity. Windows CryptoAPI (`CryptFindCertificateInCRL` / `CertGetCertificateChain`) supports cross-cert chains but the `CertGetCertificateChain` `CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT` flag is frequently needed to avoid rejecting cross-certs with non-standard extensions. Browsers (Chrome, Firefox) often do not honor cross-certs at all — they use their own root store (Mozilla CA Program, Chrome Root Store) rather than the OS trust store.

For the framework, the question is whether to support cross-cert for partner-PKI scenarios. The alternative is a trust-manager model (like browser CA bundles) where each application has its own trust store, and partner PKI trust is established by importing the partner root directly. This is operationally simpler but loses the chain-walking benefits of cross-cert (e.g., NameConstraints to restrict what the partner CA can certify).

**Impact**:

Cross-org PKI trust is operationally complex. Most enterprises avoid cross-cert and instead exchange root certs directly (trust-manager model). The `CrossCertificatePair` attribute and chain-walking logic exist but are rarely exercised.

**Constraints**:

- Must support `CrossCertificatePair` attribute on `NTAuthCertificates` for AD interop.
- Must support `pathLenConstraint` in BasicConstraints (OID 2.5.29.19).
- Must support `NameConstraints` (OID 2.5.29.30) for namespace restriction.

**Cross-platform considerations**:

- **Windows**: CryptoAPI `CertGetCertificateChain` supports cross-cert chains; `certutil -viewstore` shows cross-certs.
- **macOS**: Security framework `SecTrustEvaluate` supports cross-cert chains; Keychain Access shows cross-certs.
- **Linux**: OpenSSL `X509_STORE` supports cross-cert chains; per-application trust store.
- **Cross-platform consistency**: cross-cert chain-walking is universally supported but rarely tested; the trust-manager model (per-app trust store) is the operational default.

**KB references**:

- [`05-pki-certs/02-certificate-templates.md`](../docs/05-pki-certs/02-certificate-templates.md) — `CrossCertificatePair` attribute (OID 2.5.4.41), `NameConstraints`/`PolicyConstraints`/`PolicyMappings` extension OIDs.
- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — Cross-cert topology (Root A signs Root B), `NTAuthCertificates` storage, rare deployment.

**Open questions**:

- Adopt trust-manager model (like browser CA bundles) instead of cross-cert?
- Per-application trust stores (each app defines its own trusted roots)?
- Document cross-cert as deprecated and require partner-PKI trust via direct root import?

**Cross-capability impact**:

- Affects: PC-067 (NTAuthCertificates — cross-certs are stored on the same AD object).
- Affected by: PC-066 (CA topology — cross-cert is a topology decision for partner PKI).

---

### PC-066 — Two-tier vs three-tier CA topology is a greenfield design decision

**Capability**: Cert Service
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

Two-tier CA topology (offline root + online issuing) is most common: the root CA is air-gapped, signs the issuing CA's cert, and the issuing CA issues end-entity certs. Per [05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md), the offline root has a long CRL lifetime (6–12 months or longer) because the root is offline — the CRL must remain valid for the duration of any planned outage. AIA/CDP URLs in the issued sub-CA cert point to an HTTP path reachable by all clients (e.g., `http://pki.corp.example.com/certs/<CAName>.crt`). The issuing CA is online, joined to the domain, Enterprise mode, with templates enabled.

Three-tier topology adds a policy CA between root and issuing: `Root CA (offline, in safe) → Policy CA (offline or online; enforces name constraints, EKU constraints) → Issuing CA → end-entity certs`. The advantage is policy isolation: the Policy CA can carry `NameConstraints` (OID 2.5.29.30) restricting the namespace the issuing CA can certify, and `PolicyConstraints` (OID 2.5.29.36) limiting the policy mapping depth. Compromise of an issuing CA is contained by the policy CA's path length and constraints. The disadvantage is operational complexity — three CAs to back up, three keys to protect, three CRLs to publish.

For the framework, two-tier with HSM-protected root is the recommended default for most enterprises. Three-tier is for high-assurance (government, finance, healthcare) where compromise containment outweighs operational complexity. Cloud-based root CA (AWS Private CA, GCP CA Service, Azure Key Vault CA) is an alternative for organizations that want managed root — but introduces a cloud dependency and cost-per-cert pricing.

**Impact**:

CA topology choice affects security posture and operational complexity. A two-tier deployment with software-backed root keys is a single point of catastrophic failure (root key compromise → all issued certs untrustworthy). A three-tier deployment with HSM-backed root and policy CAs is expensive but limits blast radius.

**Constraints**:

- Must support offline root (air-gapped, sneakernet CRL/cert transfer).
- Must support HSM-protected CA keys (CNG KSP / PKCS#11).
- Must support `NameConstraints` and `PolicyConstraints` for three-tier.
- Should support cloud-based root CA (AWS Private CA, GCP CA Service) as an alternative.

**Cross-platform considerations**:

- **Windows**: AD CS two-tier or three-tier via `Install-AdcsCertificationAuthority`; HSM via CNG KSP (nCipher, Thales, Utimaco).
- **macOS**: No native CA; uses AD CS or cloud CA (AWS Private CA, GCP CA Service) for issuance.
- **Linux**: Dogtag two-tier or three-tier via `pkispawn`; HSM via PKCS#11 (SoftHSM, nCipher, Thales).
- **Cross-platform consistency**: HSM-backed root with two-tier default is the cross-platform recommendation.

**KB references**:

- [`05-pki-certs/01-ad-cs-architecture.md`](../docs/05-pki-certs/01-ad-cs-architecture.md) — Two-tier vs three-tier topology diagram, offline root pattern (long CRL lifetime, AIA/CDP URLs), `NameConstraints`/`PolicyConstraints` for three-tier, certificate store layout.
- [`01-ad-core/02-ad-cs-cert-services.md`](../docs/01-ad-core/02-ad-cs-cert-services.md) — CA hierarchy classes (Root / Subordinate policy CA / Issuing CA), KeyUsage bitmask `0x06` for `keyCertSign + cRLSign`, BasicConstraints `pathLenConstraint` per tier.

**Open questions**:

- Default to two-tier with HSM root?
- Cloud-based root CA (AWS Private CA, GCP CA Service) as an alternative?
- Three-tier for high-assurance (government, finance, healthcare) only?

**Cross-capability impact**:

- Affects: PC-060 (KRA placement depends on CA topology), PC-065 (cross-cert is a topology decision for partner PKI).
- Affected by: PC-062 (CA DB corruption — multi-tier adds DB count, increasing failure surface).

---

### PC-067 — `NTAuthCertificates` AD object is the canonical list of logon-authorized CAs

**Capability**: Cert Service
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD publishes the `NTAuthCertificates` object at `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<NC>` listing CAs allowed to issue logon certs. Per [05-pki-certs/01-ad-cs-architecture.md](../docs/05-pki-certs/01-ad-cs-architecture.md), PKINIT KDC validates user certs against this list — a smart-card logon cert issued by a CA not in `NTAuthCertificates` is rejected by the KDC with `KDC_ERR_CLIENT_REVOKED` (or `KDC_ERR_C_PRINCIPAL_UNKNOWN`). Publication is via `certutil -dspublish -f <cert.cer> NTAuthCA`, which appends the cert DER to the `cACertificate` attribute (multivalued binary). Per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), the KDC's PKINIT verification path: client signs a nonce with smart-card private key → KDC verifies signature against user cert → KDC validates cert chain to a root in `NTAuthCertificates` → KDC issues TGT with PAC.

The mirror on the client side is `HKLM\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates` — a registry hive that the Group Policy Public Key Policies / Certificate Path Validation Settings GPO syncs from the AD object. If the client's `NTAuth` registry hive is stale (e.g., GPO not refreshed), smart-card logon fails with `0x800B010A — A certificate chain could not be built to a trusted root authority`. The diagnostic flow is `certutil -viewstore -enterprise NTAuth` (shows the AD-published list) vs. `certutil -viewstore NTAuth` (shows the local registry mirror).

For the framework, the equivalent PKI-trust distribution is required for PKINIT smart-card logon. The framework's KDC must validate user certs against the framework's `NTAuthCertificates`-equivalent. The choice is between (a) preserving the `NTAuthCertificates` AD object for AD interop, (b) replacing it with a per-tenant trust store (each tenant defines its own trusted CAs), or (c) a web-of-trust model (each application defines its own trust roots). Option (b) is more cloud-native but loses the centralized PKI-trust model; option (c) is operationally complex and incompatible with PKINIT.

**Impact**:

Smart-card logon depends on `NTAuthCertificates`. If the list is stale or missing the issuing CA, all smart-card logons fail. PKINIT-dependent features (WHfB, smart-card RDP, Kerberos PKINIT) cascade-fail.

**Constraints**:

- Must support `NTAuthCertificates` for AD interop (PKINIT KDC validation).
- Per-application trust stores (browser, RDP, S/MIME) is a separate concern from PKINIT.
- Per-tenant trust store is a cloud-native alternative but breaks PKINIT centralization.

**Cross-platform considerations**:

- **Windows**: `NTAuthCertificates` AD object + `HKLM\SOFTWARE\Microsoft\SystemCertificates\NTAuth\Certificates` registry mirror; sync via GPO Public Key Policies.
- **macOS**: No `NTAuthCertificates`-equivalent; PSSO smart-card trust uses Keychain System Roots + per-app trust policies. PKINIT is via Heimdal on macOS.
- **Linux**: No `NTAuthCertificates`-equivalent; PKINIT trust uses `/etc/ssl/certs/` + per-app trust policies. SSSD `p11_child` does the cert validation.
- **Cross-platform consistency**: PKINIT trust model should be consistent across platforms; the framework must define a canonical trust list that the KDC and clients honor.

**KB references**:

- [`05-pki-certs/01-ad-cs-architecture.md`](../docs/05-pki-certs/01-ad-cs-architecture.md) — `NTAuthCertificates` AD object location, `cACertificate` attribute, `certutil -dspublish NTAuthCA` publication, registry mirror `HKLM\...\SystemCertificates\NTAuth\Certificates`.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — PKINIT verification path: client signs nonce → KDC verifies signature → KDC validates chain against `NTAuthCertificates` → TGT issued with PAC.

**Open questions**:

- Replace `NTAuthCertificates` with per-tenant trust store (cloud-native)?
- Web-of-trust model (each application defines its own trust roots)?
- Preserve `NTAuthCertificates` for AD interop and add a per-tenant trust store as a new layer?

**Cross-capability impact**:

- Affects: PC-023 (KDC must implement PKINIT — `NTAuthCertificates` is the trust source for PKINIT), PC-024 (smart-card logon via PKINIT).
- Affected by: PC-058 (templates add the per-CA constraint layer; `NTAuthCertificates` is the per-forest constraint), PC-066 (CA topology affects which CAs are in `NTAuthCertificates`).

---

## Cross-capability impact

Problems in this capability affect and are affected by problems in other capabilities:

- **KDC (PC-023..PC-035)**: PKINIT smart-card logon depends on `NTAuthCertificates` (PC-067). The KDC validates user certs against this list.
- **Auth Provider (PC-036..PC-042)**: Smart-card logon and TLS client cert auth depend on the Cert Service for issuance and validation.
- **Policy Engine (PC-043..PC-056)**: Autoenroll CSE `{71587597-...}` is invoked by `gpsvc.dll` at GP refresh (PC-059). GPO policy `AEPolicy = 0x7` enables autoenroll.
- **Federation Gateway (PC-068..PC-077)**: Token-signing certs are issued by the Cert Service. AD FS token-signing cert rollover (PC-070) is a Cert Service concern.
- **File Gateway (PC-078..PC-084)**: SMB 3.1.1 encryption certs are issued by the Cert Service.
- **Operations (PC-106..PC-115)**: CA backup/restore (PC-062) is an Operations concern; `certutil -backup`/`-restoreDB`/`-restoreKey` workflow.
- **Security & Threat Model (PC-116..PC-123)**: CA key compromise (PC-066), KRA key loss (PC-060), and cert template misconfiguration (PC-058) are security concerns.
- **Migration & Coexistence (PC-124..PC-130)**: Migrating from AD CS to a modern CA (ACME/EST) is a Migration concern; cert template translation is required.

## Open research questions specific to this capability

1. **Enrollment protocol choice**: Implement MS-WCCE server-side for AD interop, or adopt ACME (RFC 8555) and lose Windows autoenroll? Or both with a translation layer?

2. **Template schema**: Single JSON template schema that compiles to AD `msPKI-*` / MDM SCEP profile / Dogtag `.cfg` profile? Or preserve `msPKI-*` as legacy?

3. **Key archival model**: HSM-backed KRA with multi-party recovery (Shamir secret sharing, N-of-M)? Transparent KRA cert rotation without re-enrolling users?

4. **CA storage backend**: FoundationDB / CockroachDB / SQLite WAL? Replace ESE entirely with a log-structured append-only store?

5. **OCSP scaling**: CRLite (Mozilla) for massive forests? Multi-responder clustering with shared CRL source?

6. **Revocation availability**: Multi-CDP HTTP fallback with CDN-backed distribution? Per-application fail-closed vs. fail-open policy?

7. **NDES replacement**: Single enrollment endpoint speaking SCEP + EST + ACME? Drop SCEP and require EST/ACME?

8. **Cross-CA trust**: Trust-manager model (per-app trust store) vs. cross-cert with `CrossCertificatePair`? Document cross-cert as deprecated?

9. **CA topology default**: Two-tier with HSM root as default? Three-tier for high-assurance only? Cloud-based root CA as alternative?

10. **NTAuthCertificates replacement**: Per-tenant trust store (cloud-native) vs. preserve `NTAuthCertificates` for AD interop? Web-of-trust model?
