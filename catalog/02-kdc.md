---
title: KDC (Kerberos Key Distribution Center) — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, kdc, kerberos, framework-design, gap-analysis]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./01-core-directory.md
  - ./03-auth-provider.md
  - ./05-cert-service.md
  - ./13-open-research-questions.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# KDC (Kerberos Key Distribution Center) — Problem Catalog

**Capability definition**: Issues Kerberos tickets. Implements AS-REQ/AS-REP, TGS-REQ/TGS-REP, kpasswd, cross-realm referral, PAC generation/signing, PKINIT for smart-card logon, FAST for pre-auth hardening. Inherits from AD's `kdcsvc.dll` running in LSASS on every DC. Depends on Core Directory (reads principal data, krbtgt account, service principals). Consumed by Auth Provider (Kerberos SSPI-equivalent), Federation Gateway (for Kerberos-constrained delegation), and Client SDK (kinit-equivalent).

## Summary of problems

| PC | Title | Severity | Cross-platform |
|----|-------|----------|----------------|
| PC-023 | KDC must implement MS-KILE profile of RFC 4120 with PAC generation and signing | blocker | cross-platform |
| PC-024 | RC4-HMAC default for backwards compat is a security liability (Kerberoasting) | blocker | cross-platform |
| PC-025 | PAC validation RPC requires service-to-DC roundtrip; most services skip it | high | Windows |
| PC-026 | FAST (RFC 6806) armoring is opt-in via GPO; rarely enforced | high | cross-platform |
| PC-027 | PKINIT smart-card logon requires NTAuthCertificates AD object + Enterprise CA | high | cross-platform |
| PC-028 | Cross-realm TGT referral chain is rigid; transited field validation is fragile | medium | cross-platform |
| PC-029 | AES-SHA384 (etype 0x13) requires Server 2022+ KDC and clients | low | cross-platform |
| PC-030 | `krbtgt` account compromise = golden ticket; rotation is operationally painful | blocker | cross-platform |
| PC-031 | SPN uniqueness requires KDC-side `DRSWriteSPN` pre-commit check | high | cross-platform |
| PC-032 | UPN uniqueness is forest-wide but enforced inconsistently | high | cross-platform |
| PC-033 | KDC throughput at million-object scale is a known bottleneck | high | cross-platform |
| PC-034 | `kpasswd` (RFC 3244) is the only standardized password-change protocol; UI integration varies | medium | cross-platform |
| PC-035 | Group Managed Service Accounts (gMSA) require KDS root key + automatic password rotation | high | cross-platform |

---

## Detailed problem entries

### PC-023 — KDC must implement MS-KILE profile of RFC 4120 with PAC generation and signing

**Capability**: KDC
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

AD's KDC (`lsass.exe!kdcsvc.dll`) extends RFC 4120 with MS-KILE: PAC buffer generation in TGT (`PAC_LOGON_INFO` 0x01 carrying `KERB_VALIDATION_INFO` with user RID, `GroupIds[]`, `ExtraSids`, `UserAccountControl`, `LogonServer`, `LogonDomainId`; `PAC_SIGNATURE_DATA` 0x06 for server signature and 0x07 for KDC signature; `PAC_UPN_DNS_INFO` 0x0C; `PAC_CLIENT_INFO` 0x0A; Server 2016+ `PAC_BUFFER_TICKET_CHECKSUM` 0x0E and `PAC_FULL_CHECKSUM` 0x13; Server 2019+ `PAC_REQUESTER` 0x12 carrying requester SID + machine SID) per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md). The KDC signs the PAC with the `krbtgt` account's long-term key (NT hash of the `krbtgt` account password). The KDC also signs the entire `Ticket.enc-part` with the krbtgt key as of Server 2016 (`PAC_BUFFER_TICKET_CHECKSUM`) — defending against silver-ticket attacks.

Samba's Heimdal fork in `source4/kdc/samba_kdc.c` is the only open-source server implementation that generates MS-PAC. MIT krb5 KDC does NOT generate PACs by default (only verifies via `lib/krb5/krb/pac.c`); the FreeIPA `ipa_kdb` plugin (`ipa_kdb_mspac.c`) generates MS-PAC for cross-forest trust users. None of the three is a drop-in replacement for `kdcsvc.dll`: Samba's Heimdal fork is GPLv3; MIT's PAC support is verification-only; FreeIPA's plugin is FreeIPA-specific (depends on 389-DS).

A framework that wants to issue tickets acceptable to AD-joined services must generate a PAC with the full buffer set, sign it with the krbtgt key, and emit the Server 2016+ ticket signature. Services (IIS, SQL Server, SMB server, custom Kerberos-aware apps) validate the PAC's KDC signature by calling `NetrLogonSamLogonEx` over Netlogon to their DC (PC-025). The framework's KDC must accept these validation calls and re-validate the PAC.

**Impact**:

Without MS-KILE-compliant KDC, AD-aware services cannot validate PACs. Cross-forest trusts break (the trusted forest's KDC must produce a PAC that the trusting forest's services accept). S4U2Self/S4U2Proxy (constrained delegation, PC-039) break — these protocols rely on PAC contents. The Kerberos PAC is the foundation of AD's authorization model; without it, every service that does group-membership-based authorization fails.

**Constraints**:

- Must generate PAC with the full buffer set: `PAC_LOGON_INFO`, `PAC_SIGNATURE_DATA` (server + KDC), `PAC_CLIENT_INFO`, `PAC_UPN_DNS_INFO`, and Server 2016+ `PAC_BUFFER_TICKET_CHECKSUM` / `PAC_FULL_CHECKSUM`.
- Must support Server 2016+ ticket signature (silver-ticket defense) — without it, anyone with a service account's NT hash can forge service tickets.
- Must sign PAC with krbtgt long-term key (the NT hash of the krbtgt account's password).
- Must support `NetrLogonSamLogonEx` for PAC validation by services (PC-025).
- For AD interop, the PAC byte layout must be MS-PAC-compliant (NDR-encoded, 8-byte aligned, buffer order matters).

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` native; loaded into LSASS on every DC. Listens on TCP/UDP 88.
- **macOS**: macOS ships an ancient Heimdal fork (`/usr/libexec/kdc`); pre-13.0 only. Modern macOS uses the Kerberos SSO Extension (`/System/Library/PrivateFrameworks/EnterpriseSSO.framework`) for client-side only — no server KDC. The framework's macOS DC must ship its own KDC.
- **Linux**: Samba 4's Heimdal fork in `source4/kdc/` (GPLv3). MIT krb5's `krb5kdc` (the reference open-source KDC) does not generate PACs by default. Heimdal upstream (not Samba's fork) does not generate MS-PAC.
- **Cross-platform consistency**: Wire-level PAC byte layout must be MS-PAC-compliant for interop. Internal KDC architecture can differ.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Full ASN.1 message structures, PAC buffer type table, `KERB_VALIDATION_INFO` layout, ticket signature.
- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — PAC top-level layout, `PAC_INFO_BUFFER`, NDR encoding, signature computation.
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — `kdcsvc.dll` loading into LSASS, KDC thread pool, krbtgt account storage.

**Open questions**:

- Reuse Samba's Heimdal fork (GPLv3 — forces framework to GPL)?
- MIT krb5 + custom PAC plugin (FreeIPA approach — non-GPL but more work)?
- Fresh implementation (full control, no license entanglement, but ~5K lines of code)?
- Can the framework split KDC into a "PAC-generating core" (which must be MS-KILE-compliant) and a "ticket-issuing layer" (which can be more modern)?

**Cross-capability impact**:

- Affects: PC-030 (krbtgt rotation) — KDC must support dual-krbtgt mode and old-key TGT detection.
- Affects: PC-031 (SPN uniqueness) — KDC's TGS-REQ resolution depends on SPN uniqueness.
- Affects: Auth Provider PC-039 (S4U2Self/S4U2Proxy) — constrained delegation uses PAC.
- Affected by: Core Directory PC-013 (`unicodePwd` storage) — krbtgt key is in `unicodePwd`.
- Affected by: Cert Service (PC-055, not in this catalog) — PKINIT requires Enterprise CA.

---

### PC-024 — RC4-HMAC default for backwards compat is a security liability (Kerberoasting)

**Capability**: KDC
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

RC4-HMAC (etype 0x17) is still default for accounts without `msDS-SupportedEncryptionTypes` set. RC4 keys are derived from MD4 of the password (the NT hash) — meaning the long-term key for RC4 is exactly the NT hash, the same value NTLM uses. TGS tickets encrypted with RC4 can be offline-brute-forced: an attacker with a TGS ticket (obtained via a single TGS-REQ with a valid TGT) can attempt to decrypt it by guessing passwords, computing their NT hash, and trying to decrypt. This is the Kerberoasting attack per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Server 2022 disables RC4 by default for new accounts (`msDS-SupportedEncryptionTypes` defaults to 0x30 = AES128 | AES256), but legacy service accounts (created before 2022 or migrated from older domains) still have RC4 enabled. AES keys (etype 0x11 / 0x12) are derived via PBKDF2-HMAC-SHA1 with 4096 iterations — offline brute-force is 1000× more expensive than RC4 per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

A framework should default to AES-only (etype 0x12 + 0x11) and provide explicit RC4-compat mode for migration. The migration path is non-trivial: every service account with RC4-only keys must be reset to a new password (which derives new AES keys), and every client that uses the service must support AES (Windows 7+, modern macOS, modern Linux). Legacy apps that hard-require RC4 (old Java runtimes, old Python libraries, some third-party appliances) cannot be migrated without code/firmware updates.

**Impact**:

Kerberoasting remains the most common AD attack vector. Mandiant M-Trends 2023 reports Kerberoasting is used in ~60% of AD compromises that involve Kerberos. Without AES default, every service account is at risk: an attacker with read access to AD (any authenticated user) can request TGS tickets for every SPN, then offline-crack the service account password at leisure. Cracking a 10-char complex password from an RC4 TGS takes ~8 hours on a single GPU; AES-256 takes ~years.

**Constraints**:

- Must support RC4 as opt-in for migration (legacy apps that hard-require RC4).
- AES-only default must not break service-account logon for legacy apps (auto-detect AES support on the client; fallback to RC4 with audit-log warning).
- Must support `msDS-SupportedEncryptionTypes` attribute (bitmask: 0x01 DES-CBC-CRC, 0x04 RC4-HMAC, 0x10 AES128, 0x20 AES256).
- For AD interop, the etype negotiation must follow RFC 4120 §3.1.3 (client proposes, KDC picks highest mutually-supported).

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` enforces etype policy; `Set-ADUser -Replace @{msDS-SupportedEncryptionTypes=0x30}` enables AES-only.
- **macOS**: Heimdal (legacy) supports RC4; the SSO Extension supports AES. The framework's macOS client must default to AES.
- **Linux**: MIT krb5 supports both RC4 and AES; default `default_tkt_enctypes` in `krb5.conf`. SSSD's `krb5` provider honors `krb5_supported_enctypes`.
- **Cross-platform consistency**: Etype negotiation must be consistent — a service account with AES-only must reject RC4 tickets regardless of client OS.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Etype table, PBKDF2 derivation, `msDS-SupportedEncryptionTypes` bitmask, Kerberoasting attack description.
- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — AD security posture, RC4 deprecation timeline.

**Open questions**:

- Provide a "migration mode" that issues RC4 TGS with audit-log warnings (so admins can find legacy apps)?
- Auto-rotate service accounts to AES on next password change (so the migration happens gradually)?
- Hard cut-off date for RC4 (e.g. framework v2.0 removes RC4 entirely)?

**Cross-capability impact**:

- Affects: Auth Provider PC-036 (NTLM) — same NT hash, same Kerberoasting risk for NTLMv2 responses.
- Affects: Security (PC-110, not in this catalog) — Kerberoasting detection via event 4769 with etype 0x17.

---

### PC-025 — PAC validation RPC requires service-to-DC roundtrip; most services skip it

**Capability**: KDC
**Severity**: high
**Cross-platform**: Windows

**Problem statement**:

Services that need PAC validation (IIS, SQL Server, COM+ services that use role-based authorization) call `NetrLogonSamLogonEx` over Netlogon (MS-NRPC) to the DC, passing the ticket + PAC. The DC validates the KDC signature inside the PAC by recomputing it with the krbtgt key per [02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) and [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md). This is a per-AP-REQ roundtrip for high-security services — every service ticket validation requires a network call to the DC.

Most services skip PAC validation (perf) — they trust the KDC's signature at issue time and rely on the absence of silver-ticket attacks. The Server 2016+ ticket signature (`PAC_BUFFER_TICKET_CHECKSUM`, type 0x0E) mitigates silver-ticket attacks: even if an attacker has the service account's NT hash, they can forge the ticket plaintext but cannot forge the KDC-side ticket signature (which uses the krbtgt key). However, only services that opt in to PAC validation benefit from the ticket signature check; services that skip PAC validation never re-validate.

The opt-in mechanism is the registry toggle `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\VerifyPacAuthenticators` (DWORD; 0 = no verify, 1 = verify for services that request it, 2 = always verify). Default is 0. Services that want PAC validation call `QueryContextAttributes` with `SECPKG_ATTR_PACKAGE_INFO` and check `KERB_WRAP_TOKEN.validatePac`.

A framework could push PAC validation to the KDC at TGS time (always-validate mode — the KDC validates the PAC immediately after issuing the ticket) or implement a token-binding approach (TLS exporter binds the ticket to the TLS session, defeating relay). The trade-off: always-validate adds latency to every TGS-REQ (~10ms per DC roundtrip from the KDC's perspective); token-binding adds complexity to the client and service.

**Impact**:

Silver-ticket attacks succeed against services that skip PAC validation. An attacker with a service account's NT hash (e.g. from a single LSASS dump) can forge arbitrary service tickets for that service. Without ticket signature (Server 2016+), the forged ticket is byte-identical to a real one. With ticket signature, the forged ticket lacks the correct KDC signature — but only services that opt in to PAC validation detect this.

**Constraints**:

- Must not introduce per-request DC roundtrip for non-validating services (perf).
- Must support `VerifyPacAuthenticators` registry toggle for opt-in.
- Must support Server 2016+ ticket signature (`PAC_BUFFER_TICKET_CHECKSUM`).
- For AD interop, the framework must accept `NetrLogonSamLogonEx` PAC validation calls from Windows services.

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` accepts PAC validation via Netlogon; `lsasrv.dll` enforces `VerifyPacAuthenticators` policy. IIS, SQL Server, COM+ all support PAC validation opt-in.
- **macOS**: No native PAC validation mechanism. The framework's macOS services would need a custom validation path.
- **Linux**: MIT krb5 / Heimdal support PAC verification via `krb5_pac_verify()`. Samba 4's `smbd` does PAC validation when `kerberos method = system keytab` and `pac check = true`. Most Linux services (Apache mod_auth_gssapi, nginx spnego-http-auth) skip PAC validation.
- **Cross-platform consistency**: The validation API must be consistent across platforms. The framework's Client SDK should expose a "validate PAC" call that works on all platforms.

**KB references**:

- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — PAC validation flow, `NetrLogonSamLogonEx` interface, `VerifyPacAuthenticators` toggle.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — PAC buffer types, ticket signature (Server 2016+), silver-ticket attack.

**Open questions**:

- Always-validate mode with cached krbtgt keys per service? The KDC shares the krbtgt key with all DCs, but pushing validation to the KDC at TGS time adds latency.
- Token-binding via TLS exporter (RFC 9266) — bind the ticket to the TLS session, defeating relay without DC roundtrip.
- Should the framework mandate PAC validation for all services by default (security-first) or keep it opt-in (perf-first)?

**Cross-capability impact**:

- Affects: Auth Provider PC-039 (S4U2Self/S4U2Proxy) — constrained delegation relies on PAC validation.
- Affects: Security (PC-110, not in this catalog) — silver-ticket detection.

---

### PC-026 — FAST (RFC 6806) armoring is opt-in via GPO; rarely enforced

**Capability**: KDC
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

FAST (Flexible Authentication Secure Tunneling, RFC 6806) wraps the inner pre-auth in a TGT-armored tunnel encrypted to a TGT the client already holds (the "armor TGT"). This defeats offline password cracking from AS-REP captures (AS-REP roasting) because the inner pre-auth response is encrypted to the FAST armor key, not the user's long-term key per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

AD supports FAST since Server 2012 (KDC) and Windows 8 (client). The GPO `Computer Configuration → Policies → Administrative Templates → System → Kerberos → Configure FAST policy` has values "Supported" (default — KDC accepts FAST but doesn't require it) and "Required" (KDC refuses non-FAST AS-REQs). Most deployments leave it at "Supported" (effectively off) because: (a) legacy clients (Windows 7, older Java, older Python) don't support FAST; (b) `Required` breaks those legacy clients; (c) the operational pain of identifying and upgrading every legacy client is high.

AS-REP roasting attacks accounts with `DO_NOT_REQUIRE_PREAUTH` UAC flag set — the KDC issues an AS-REP without pre-auth, and the attacker offline-cracks the response. With FAST-required, even accounts without pre-auth benefit from armoring (the armor TGT prevents the attacker from capturing a useful AS-REP).

A framework should default to FAST-required and document the migration path. The migration path requires: (a) identifying all clients and their FAST support; (b) upgrading non-FAST clients; (c) flipping the policy from Supported to Required in a maintenance window. Anonymous PKINIT armor TGT (RFC 6112) is the alternative for first-logon FAST — the client obtains an anonymous TGT without a password, then uses it as armor for the real AS-REQ.

**Impact**:

AS-REP roasting remains viable for accounts with `DO_NOT_REQUIRE_PREAUTH`. While the flag is rare on user accounts (default off), it's sometimes set for service accounts that need to log in from legacy clients without pre-auth support. An attacker with read access to AD can enumerate accounts with the flag (`Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`), request AS-REPs for each, and offline-crack. Without FAST, the response is encrypted to the user's NT hash, which is crackable. With FAST, the response is encrypted to the armor key, which the attacker doesn't have.

**Constraints**:

- Must support anonymous PKINIT armor TGT (RFC 6112) for first-logon FAST.
- Must support FAST-required mode (KDC refuses non-FAST AS-REQs).
- Must support FAST-supported mode (KDC accepts both; default for migration).
- For AD interop, must negotiate FAST via `PA-FX-FAST` (padata-type 143) and `PA-FX-FAST-START` (213).

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` (Server 2012+) and `kerberos.dll` (Windows 8+) support FAST. GPO `Configure FAST policy` controls.
- **macOS**: SSO Extension supports FAST (Heimdal-derived). Legacy `/usr/libexec/kdc` does not.
- **Linux**: MIT krb5 1.10+ supports FAST; Heimdal 1.5+ supports FAST. SSSD's `krb5` provider honors FAST via `krb5_fast_use_anonymous_pkinit`.
- **Cross-platform consistency**: All clients in a FAST-required realm must support FAST.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — FAST architecture, `PA-FX-FAST` padata type, anonymous PKINIT armor TGT.

**Open questions**:

- Is FAST-required compatible with all legacy clients (Java, old Python, old Samba)? Java 8+ supports FAST; older Python libraries (python-krbV) do not.
- Provide a fallback grace period (FAST-supported with audit-log, then FAST-required after N days)?
- Anonymous PKINIT requires no password — what is the threat model for the anonymous TGT? (The anonymous TGT is only useful as armor; it cannot be used to authenticate to services.)

**Cross-capability impact**:

- Affects: Cert Service (PC-055, not in this catalog) — anonymous PKINIT requires a CA.
- Affects: Security (PC-110, not in this catalog) — AS-REP roasting detection.

---

### PC-027 — PKINIT smart-card logon requires NTAuthCertificates AD object + Enterprise CA

**Capability**: KDC
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

PKINIT (RFC 4556) is the smart-card logon mechanism for Kerberos. The client signs a nonce with its smart-card private key (the smart card holds the user's certificate + private key). The KDC verifies the signature against the user's certificate, which must chain to a CA in the `NTAuthCertificates` AD object (`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,<forest-root-dn>`). The user cert SAN must contain the user's UPN, or map via `altSecurityIdentities` attribute on the user object per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [05-pki-certs/02-certificate-templates.md](../docs/05-pki-certs/02-certificate-templates.md).

The Enterprise CA must be configured to issue certificates with the Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2) and the certificate template must publish issued certs to AD (`NTAuthCA` attribute). The KDC reads `NTAuthCertificates` at boot and caches the cert chain; new CA certs require a KDC restart or `ksetup /domain`-equivalent refresh.

A framework needs equivalent PKI integration or must design a modern passwordless alternative. FIDO2 / WebAuthn is the modern passwordless alternative (Windows Hello for Business, YubiKey, Touch ID). FIDO2 does not require an Enterprise CA — the user registers a FIDO2 authenticator with the IdP, and the IdP issues assertions that the service verifies. The trade-off: FIDO2 is not Kerberos-native; bridging FIDO2 to Kerberos requires a "FIDO2 to Kerberos" gateway (the KDC accepts FIDO2 assertions instead of PKINIT signatures).

**Impact**:

Smart-card logon (PIV/CAC cards used by US government / defense, smart cards used by European enterprises) depends on this integration. Government / defense deployments require PIV/CAC smart-card logon by policy (HSPD-12, DoD CAC mandates). Without PKINIT, smart-card logon fails — users cannot authenticate to AD-joined workstations with their PIV card.

**Constraints**:

- Must support `NTAuthCertificates` AD object for AD interop (KDC reads this object at boot).
- Must support PKINIT (RFC 4556) — `PA-PK-AS-REQ` (padata-type 16) and `PA-PK-AS-REP` (17).
- Must support UPN-in-SAN cert mapping (subjectAltName `otherName = 1.3.6.1.4.1.311.20.2.3` carrying the UPN).
- Must support `altSecurityIdentities` mapping (alternative cert-to-account mapping for cross-forest certs).
- Consider FIDO2 as modern alternative — but FIDO2 is not Kerberos-native.

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` PKINIT support; `certutil -viewstore -enterprise NTAuth` for inspection; Smart Card service (`scardsvr.exe`) for card access.
- **macOS**: `CryptoTokenKit` framework for smart-card access (PIV/CAC via CCID class). The framework's macOS KDC must integrate with `CryptoTokenKit` for client-side smart-card operations.
- **Linux**: MIT krb5 has PKINIT support (`pkinit_libs`); Heimdal has PKINIT support. Smart card access via `pcsc-lite` and `opensc`.
- **Cross-platform consistency**: PKINIT is RFC 4556 — wire format is platform-independent. Smart-card access (the client side) is platform-specific.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — PKINIT ASN.1 structures (`PA-PK-AS-REQ`, `AuthPack`, `PKAuthenticator`), DH key exchange.
- [`05-pki-certs/02-certificate-templates.md`](../docs/05-pki-certs/02-certificate-templates.md) — `NTAuthCertificates` object, smart-card logon EKU, certificate template configuration.

**Open questions**:

- Adopt FIDO2 + PKINIT-anonymous for passwordless (Windows Hello for Business model)? FIDO2 is more user-friendly; PKINIT is more standard.
- Maintain smart-card path for compliance (HSPD-12, DoD CAC, EU eIDAS)?
- Hybrid: FIDO2 for ordinary users, PKINIT for compliance-mandated users?

**Cross-capability impact**:

- Affects: Cert Service (PC-055, not in this catalog) — Enterprise CA must issue smart-card certs.
- Affects: Auth Provider PC-040 (token construction) — PKINIT-issued tickets differ from password-issued.

---

### PC-028 — Cross-realm TGT referral chain is rigid; transited field validation is fragile

**Capability**: KDC
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

When a user in domain A requests a service ticket for a service in domain B, the KDCs walk the trust graph via referral TGTs. The KDC in domain A returns a TGT for `krbtgt/B` (a referral ticket encrypted to B's inter-realm key). The client submits the referral TGT to KDC B, which decrypts it (B has the inter-realm key), issues a service ticket if the service is in B, or another referral if the service is in domain C per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md).

The `Transited` field of the resulting ticket encodes the realm chain (`TrustedRealms` in the `TransitedEncoding`). The target KDC validates the `Transited` field against its trust graph — if the chain includes a realm that the target doesn't trust, the ticket is rejected with `KRB_AP_ERR_TGS_NOREALM`. In forests with many domains and shortcut trusts, the chain can be non-trivial: A → B → C → D, with shortcut trusts A → D and B → D. The KDC at D must validate the chain and decide whether to accept the shortcut or require the full chain.

In practice, AD disables `Transited` field validation by default (`disable-transited` KDC option) because the validation is fragile and the trust graph is implicit (the forest is one administrative unit). Cross-forest trusts (separate forests) do validate, but the validation is often bypassed in mixed-vendor environments where one side uses MIT and the other uses AD.

A framework should consider a flatter trust model (any-to-any via forest root — every domain in a forest trusts every other domain implicitly, no referrals needed) or document the chain semantics. The flatter model eliminates the referral chain but loses the cross-forest trust's transitive closure (forest A trusts forest B; forest B trusts forest C; does forest A trust forest C? — yes, transitively, but only with `Transited` validation).

**Impact**:

Cross-domain auth latency in multi-domain forests. Each hop in the referral chain adds a network roundtrip (client → KDC A → client → KDC B → client → KDC C → client → service). In a 5-domain forest with no shortcut trusts, a cross-domain auth takes 5 roundtrips — 50–500ms depending on WAN latency. Trust-graph misconfig (a missing shortcut trust or a broken trust) breaks auth with `KRB_AP_ERR_MODIFIED` or `KDC_ERR_S_PRINCIPAL_UNKNOWN`.

**Constraints**:

- Must preserve RFC 4120 §3.3.3 referral semantics for AD interop.
- Must support `Transited` field validation (configurable per-trust).
- Must support shortcut trusts (direct trust between non-adjacent domains).
- For AD interop, must support forest trusts (transitive, organization-wide).

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` referral logic; `nltest /domain_trusts` for inspection; `ksetup /addkdc` for cross-realm config.
- **macOS**: SSO Extension supports cross-realm; legacy `/usr/libexec/kdc` does not handle forest trusts.
- **Linux**: MIT krb5 / Heimdal support cross-realm via `[capaths]` and `[domain_realm]` in `krb5.conf`. SSSD's `ad` provider handles cross-domain referrals natively.
- **Cross-platform consistency**: Referral chain must be consistent across KDC implementations.

**KB references**:

- [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md) — Forest / tree / domain topology, trust transitivity.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — `Transited` field in `EncTicketPart`, referral TGT mechanism.
- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — Trust objects, `trustedDomain` class, `msDS-TrustForestTrustInfo`.

**Open questions**:

- Replace `Transited` field with signed assertions from each hop? Each KDC in the chain signs an assertion "I referred this ticket to <next-realm>"; the target KDC verifies the chain.
- Trust-on-first-use model (no validation; trust whatever realm referred the ticket)? Reduces complexity but increases risk.
- Collapse to a single-domain forest (eliminate cross-domain referrals entirely)?

**Cross-capability impact**:

- Affects: Federation Gateway (PC-070, not in this catalog) — cross-forest federation uses similar referral patterns.

---

### PC-029 — AES-SHA384 (etype 0x13) requires Server 2022+ KDC and clients

**Capability**: KDC
**Severity**: low
**Cross-platform**: cross-platform

**Problem statement**:

RFC 8009 adds `aes256-cts-hmac-sha384-192` (etype 0x13) with stronger HMAC (SHA-384 instead of SHA-1). Server 2022+ KDCs support etype 0x13; older DCs and clients fall back to 0x12 (`aes256-cts-hmac-sha1-96`). PBKDF2 iteration count stays at 4096 for backward compatibility (changing the iteration count would invalidate all existing AES keys) per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Etype 0x13 provides stronger ticket integrity for modern deployments. SHA-1 (used in etype 0x12's HMAC) is considered weak; SHA-384 (used in 0x13) is not. The cryptographic margin matters less than the operational reality: SHA-1 has not been broken for HMAC use (HMAC-SHA1 is still considered secure), so etype 0x12 is not "broken" — 0x13 is forward-looking.

A framework should default to 0x13 with fallback to 0x12 for legacy clients. The fallback is automatic via RFC 4120 etype negotiation (client proposes 0x13 + 0x12; KDC picks the highest mutually-supported). The migration path: update KDC to support 0x13 (one-time), update clients to support 0x13 (gradual), no password reset needed (PBKDF2 derivation is the same for both etypes — the key derivation uses the same password but different HMAC).

**Impact**:

Stronger ticket integrity for modern deployments. Etype 0x13 is not a security emergency — etype 0x12 is still secure for HMAC use. The impact of not supporting 0x13 is "missed opportunity for stronger crypto" rather than "security hole." However, government / defense deployments with FIPS 140-3 requirements may mandate etype 0x13 (SHA-1 is disallowed in FIPS mode for new deployments).

**Constraints**:

- Must support both 0x12 and 0x13.
- PBKDF2 4096 iterations for compatibility (do not change).
- For AD interop, must negotiate 0x13 via RFC 4120 etype negotiation.

**Cross-platform considerations**:

- **Windows**: Server 2022+ KDC supports 0x13; Windows 11+ client supports 0x13.
- **macOS**: SSO Extension (Heimdal 7.x+) supports 0x13; legacy does not.
- **Linux**: MIT krb5 1.18+ supports 0x13; Heimdal 7.x+ supports 0x13.
- **Cross-platform consistency**: Etype negotiation must be consistent across all KDCs in the realm.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Etype table including 0x13, RFC 8009 reference, PBKDF2 iteration count rationale.

**Open questions**:

- Adopt 0x13 default with 0x12 fallback grace period?
- When to drop 0x12? Probably never for AD interop; possibly for clean-slate deployments.
- Should the framework support future etypes (e.g. post-quantum Kerberos per IETF draft)?

**Cross-capability impact**:

- Affects: PC-024 (RC4 deprecation) — same etype negotiation framework.

---

### PC-030 — `krbtgt` account compromise = golden ticket; rotation is operationally painful

**Capability**: KDC
**Severity**: blocker
**Cross-platform**: cross-platform

**Problem statement**:

Anyone with the krbtgt account's NT hash can forge TGTs (golden ticket attack). The krbtgt account is a special account in AD (`CN=krbtgt,CN=Users,<domain-dn>`) whose NT hash is the long-term key for the KDC. A forged TGT encrypted with the krbtgt hash is indistinguishable from a real TGT — the KDC cannot detect forgery. With a forged TGT, an attacker can request service tickets for any service in the domain, impersonating any user (including Domain Admins) per [00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) and [02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md).

Mitigation: rotate the krbtgt password (which changes the NT hash, invalidating forged TGTs). The catch: existing TGTs encrypted with the old hash must continue to work until they expire (default 10 hours). Microsoft's solution is dual-krbtgt mode (Server 2012+): the KDC maintains two krbtgt keys — the current key (used to issue new TGTs) and the previous key (used to validate existing TGTs). Rotating the krbtgt password twice within a TGT lifetime (the second rotation invalidates the old key) is the recommended procedure.

The procedure is operationally painful: (1) rotate krbtgt password (KDC starts using new key, keeps old key for validation); (2) wait for TGT lifetime (default 10 hours) — all old TGTs expire; (3) rotate krbtgt password again (KDC drops the now-unused old key) — forged TGTs from before step 1 are now invalid. During the 10-hour window, both keys are valid; an attacker who extracted the old key during this window can still forge TGTs until step 3.

A framework should (a) make krbtgt rotation a one-click operation (not a multi-step manual procedure); (b) support dual-krbtgt mode (overlap window); (c) monitor for tickets signed by old keys post-rotation (security signal — anyone presenting a TGT signed by the old key after rotation is suspicious).

**Impact**:

Compromised krbtgt = full forest compromise. An attacker with the krbtgt hash can forge TGTs for any user (including the Enterprise Admins group) and access any service. Rotation is rarely done in practice — Microsoft recommends annual rotation but most shops rotate only after a known compromise, when it's too late. The operational pain (multi-step procedure, 10-hour window, requires DC restart in older versions) discourages preventive rotation.

**Constraints**:

- Must support dual-krbtgt mode (Server 2012+ feature) — KDC maintains current + previous key.
- Must log old-key TGT usage as a security signal (event 4769 with the krbtgt kvno indicating old key).
- Must support one-click rotation (atomic: rotate current → previous, generate new current).
- For AD interop, must expose `krbtgt` account via standard LDAP and must use the `unicodePwd` attribute as the key source.

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` supports dual-krbtgt mode; `Set-ADAccountPassword -Identity krbtgt` performs rotation; `kvno` attribute tracks key version.
- **macOS**: No native KDC; no krbtgt concept. The framework's macOS DC must implement krbtgt rotation.
- **Linux**: MIT krb5 uses a keytab file (not a directory attribute); rotation is `kadmin -q "change_password krbtgt/REALM"`. Samba 4 supports AD-style krbtgt rotation.
- **Cross-platform consistency**: All KDCs in a realm must use the same krbtgt key — keys must replicate via Core Directory (PC-001, PC-002).

**KB references**:

- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — krbtgt account role, golden ticket attack, rotation procedure.
- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — krbtgt key signing, PAC signature, ticket signature.

**Open questions**:

- HSM-bound krbtgt key? The KDC fetches the key from an HSM at boot; the key never resides in process memory or in the directory. Mitigates LSASS-dump attacks but adds HSM dependency.
- Automatic rotation every N days (e.g. 30)? Reduces the attack window but increases operational complexity (every rotation is a 10-hour window of dual-key operation).
- Should the framework support multiple krbgtgs per realm (e.g. one per DC) — eliminating the single point of compromise but breaking AD interop?

**Cross-capability impact**:

- Affects: Core Directory PC-001 (DRSUAPI) — krbtgt account replication must be atomic and urgent.
- Affects: Operations (PC-096, not in this catalog) — krbtgt rotation is a security operation.
- Affects: Security (PC-110, not in this catalog) — golden ticket detection via old-key TGT usage.
- Affected by: Core Directory PC-013 (`unicodePwd`) — krbtgt key is in `unicodePwd`.

---

### PC-031 — SPN uniqueness requires KDC-side `DRSWriteSPN` pre-commit check

**Capability**: KDC
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD enforces SPN uniqueness forest-wide via `DRSWriteSPN` (opnum 13 of DRSUAPI). When the KDC (or any LDAP modify on `servicePrincipalName`) registers an SPN, the DSA calls `DRSWriteSPN` with `DRS_ADD_SPN`. The DSA on the schema master checks the GC for any existing account with the same SPN. If exactly one existing account has the SPN, return `ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST (8647)`. If zero existing accounts have it, the write succeeds and is replicated per [02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) and [02-protocols/06-rpc-dcerpc-ms-drsr.md](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md).

`setspn -X` finds duplicates post-hoc (forest-wide LDAP paged search, hash, and report). Duplicate SPNs cause the KDC to issue tickets encrypted to the wrong account — when a client requests a TGS for `HTTP/web01.example.com`, the KDC finds two accounts with that SPN, picks one at random (or by some internal ordering), and issues a ticket encrypted to that account's key. The client presents the ticket to the service, which cannot decrypt it (wrong key) — `KRB_AP_ERR_MODIFIED (41)` per [02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md).

A framework must implement SPN uniqueness at write time (pre-commit check) or accept intermittent `KRB_AP_ERR_MODIFIED` failures. The uniqueness scope is forest-wide (across all domains) because SPNs are used by the KDC for cross-domain TGS resolution — a duplicate in domain A and domain B causes the KDC at domain A to issue a ticket for the SPN, but the service is actually in domain B.

**Impact**:

Duplicate SPNs cause intermittent auth failures (`KRB_AP_ERR_MODIFIED`) that are difficult to diagnose. The client sees a "Kerberos ticket decryption failed" error; the admin sees event 4 (KDC) with the wrong account name; the user sees "access denied" intermittently (50% of the time, depending on which DC handles the TGS-REQ). Diagnosing requires running `setspn -X` and resolving every duplicate, which is a multi-hour operation in large forests.

**Constraints**:

- Uniqueness scope is forest-wide (across all domains). Must support GC-based uniqueness check.
- Must support `DRSWriteSPN` for AD interop (opnum 13 of DRSUAPI).
- Must support `setspn -X`-equivalent API for duplicate detection.
- Must support `DRS_ADD_SPN`, `DRS_REMOVE_SPN`, `DRS_CHECK_SPN` operations.

**Cross-platform considerations**:

- **Windows**: `ntdsa.dll` implements `DRSWriteSPN`; `setspn.exe` is the management tool; `Get-ADUser -Filter {servicePrincipalName -eq "..."}` for LDAP-based lookup.
- **macOS**: No native equivalent. The framework's macOS DC must implement SPN uniqueness.
- **Linux**: Samba 4 implements `DRSWriteSPN`; 389-DS / OpenLDAP use a uniqueness plugin (`uiduniqueness` plugin adapted for SPN); FreeIPA has built-in SPN uniqueness via 389-DS plugin.
- **Cross-platform consistency**: Uniqueness check must be identical across all DCs in the forest.

**KB references**:

- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — SPN format, `servicePrincipalName` attribute, `DRSWriteSPN` opnum 13, duplicate detection.
- [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — `DRSWriteSPN` IDL, `DRS_ADD_SPN` / `DRS_REMOVE_SPN` / `DRS_CHECK_SPN` operations.

**Open questions**:

- Per-forest unique index on SPN? A persistent index on `servicePrincipalName` across all NCs would give O(log n) uniqueness check.
- Per-domain uniqueness with cross-domain conflict detection? Lighter-weight (per-NC index) but requires cross-NC coordination.
- Replace SPN with a different service-identity mechanism (e.g. URN, UUID)? Breaks AD interop.

**Cross-capability impact**:

- Affects: Core Directory PC-001 (DRSUAPI) — `DRSWriteSPN` is opnum 13.
- Affects: Auth Provider (PC-080, not in this catalog) — SPN-based service authentication.

---

### PC-032 — UPN uniqueness is forest-wide but enforced inconsistently

**Capability**: KDC
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

UPN (`userPrincipalName`) must be unique within the forest. AD does NOT enforce this at the LDAP-modify level (unlike SPNs) — duplicate UPNs are technically creatable. The KDC enforces uniqueness at AS-REQ time: when a user submits an AS-REQ with a UPN, the KDC resolves the UPN to a `DSNAME` via `DRSCrackNames` (`DS_USER_PRINCIPAL_NAME` → `DS_UNIQUE_ID_NAME`). If multiple accounts match, `DRSCrackNames` returns `DS_NAME_ERROR_NOT_UNIQUE (8649)`; the KDC then refuses the AS-REQ with `KDC_ERR_C_PRINCIPAL_UNKNOWN (6)` per [02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md).

The result: UPN-duplicate users get intermittent login failures depending on which DC handles the AS-REQ and which `DRSCrackNames` result the DC picks. The KDC does not consistently pick one of the duplicates — different DCs may pick different accounts, causing one DC to issue TGTs for user A and another DC to issue TGTs for user B, both with the same UPN. The user sees intermittent "wrong password" errors (because the password is for user A but the KDC is checking against user B's hash).

The UPN suffix list (`uPNSuffixes` on `CN=Partitions,CN=Configuration,...`) restricts which suffixes are valid. A UPN with an unlisted suffix is rejected at AS-REQ time. However, the suffix check is per-forest — a UPN like `jdoe@branch.example.com` is valid only if `branch.example.com` is in `uPNSuffixes` or is a child domain's DNS name.

A framework must enforce UPN uniqueness at write time (pre-commit check) and validate the suffix. The uniqueness scope is forest-wide — same as SPN. The framework's KDC must reject AS-REQs for duplicate UPNs with a clear error code (not the cryptic `KDC_ERR_C_PRINCIPAL_UNKNOWN`).

**Impact**:

UPN-duplicate users get intermittent login failures depending on which DC handles the AS-REQ. Diagnosing is difficult — the user reports "sometimes login works, sometimes it doesn't" — and admins may not realize the root cause is UPN duplication. `Get-ADUser -Filter {userPrincipalName -eq "..."}` returns multiple results; the admin must merge or rename the duplicates. In large forests (100K+ users), UPN duplication is common after mergers / acquisitions (two companies both have `jdoe@corp.example.com`).

**Constraints**:

- Must support `uPNSuffixes` and `msDS-UPNSuffixes` for custom suffixes.
- Uniqueness scope is forest (across all domains).
- Must enforce uniqueness at write time (pre-commit check) — not at AS-REQ time.
- Must validate suffix at write time.

**Cross-platform considerations**:

- **Windows**: `DRSCrackNames` resolves UPN at AS-REQ; `Get-ADUser -Properties userPrincipalName` for inspection; `Set-ADUser -UserPrincipalName` for modify.
- **macOS**: No native UPN concept. The framework's macOS DC must implement UPN.
- **Linux**: Samba 4 implements UPN uniqueness via LDB module; 389-DS / OpenLDAP use a uniqueness plugin.
- **Cross-platform consistency**: UPN uniqueness check must be identical across all DCs in the forest.

**KB references**:

- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — UPN format, `userPrincipalName` attribute, `uPNSuffixes` on Partitions container, `DRSCrackNames` resolution.
- [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md) — UPN as forest-wide identifier, UPN suffix allocation.

**Open questions**:

- Strict write-time uniqueness vs soft enforcement (warn but allow)? Soft allows temporary duplicates during mergers.
- Auto-rename on conflict (append `-2`, `-3`) or refuse the write?
- Replace UPN with email-as-identity (modern IdP model)? Email is more user-friendly but not RFC 4120-native.

**Cross-capability impact**:

- Affects: Core Directory PC-001 (DRSUAPI) — `DRSCrackNames` is opnum 12.
- Affects: Federation Gateway (PC-070, not in this catalog) — UPN is the standard SAML/OIDC subject.

---

### PC-033 — KDC throughput at million-object scale is a known bottleneck

**Capability**: KDC
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

AD's KDC (`kdcsvc.dll`) runs in LSASS thread pool. Per-DC throughput is bounded by LSASS CPU — typically 1,000–5,000 AS-REQ/TGS-REQ per second on modern hardware. The 5-minute Kerberos skew window and PAC signing cost per AS-REQ/TGS-REQ add overhead: every AS-REQ requires a `PA-ENC-TIMESTAMP` decryption (PBKDF2 key derivation if AES, MD4 if RC4); every TGS-REQ requires a PAC construction (recursive group membership expansion, signing). At million-user forests, the KDC becomes the bottleneck per [00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) and [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md).

Large enterprises (50K+ users with frequent auth — Exchange ActiveSync, file share access, web app logon) often require dedicated KDC DCs (without GC, without RID master) — DCs whose only role is to handle AS-REQ/TGS-REQ. The dedicated KDC DCs scale horizontally (one per N users), but each DC maintains its own krbtgt key share and PAC generation logic.

A framework should horizontally scale the KDC (stateless, share krbtgt key across N KDCs) and benchmark at scale. The stateless model requires: (a) shared krbtgt key (via Core Directory replication or a shared secret store); (b) shared service-account long-term keys (via Core Directory); (c) shared user long-term keys (via Core Directory). The KDC becomes a stateless service that reads from Core Directory on every AS-REQ/TGS-REQ — caching is critical (cache the user's NT hash, group memberships, SPN-to-account mapping).

**Impact**:

Large enterprises need dedicated KDC DCs — operationally expensive (one DC per ~10K users). Auth latency in worst-case scenarios (peak morning logon, all users authenticating within 30 minutes) can spike to seconds. Without horizontal scaling, the framework's KDC throughput caps at ~5K AS-REQ/sec per DC — fine for small deployments, inadequate for cloud-scale (Microsoft's Azure AD DS handles millions of auth requests per second via sharding).

**Constraints**:

- KDC must share krbtgt key across instances (via Core Directory replication).
- KDC must share service-account long-term keys via directory.
- KDC must share user long-term keys via directory.
- KDC must cache aggressively (user NT hash, group memberships, SPN-to-account mapping) — but cache invalidation on password change / group membership change is critical.
- Must scale to 100K+ AS-REQ/sec at cloud scale.

**Cross-platform considerations**:

- **Windows**: `kdcsvc.dll` runs in LSASS; one KDC per DC; horizontal scaling = more DCs.
- **macOS**: No native KDC scaling. The framework's macOS KDC must support horizontal scaling.
- **Linux**: MIT krb5's `krb5kdc` is single-process per host; horizontal scaling = more hosts. Samba 4's KDC has the same model.
- **Cross-platform consistency**: All KDCs in a realm must produce identical PACs (same group memberships, same signatures).

**KB references**:

- [`00-overview/02-ad-architecture.md`](../docs/00-overview/02-ad-architecture.md) — LSASS thread pool, KDC scaling ceiling, dedicated KDC DCs.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — KDC PAC construction cost, etype negotiation overhead.

**Open questions**:

- Stateless KDC with shared key in HSM? Each KDC instance fetches the krbtgt key from the HSM at boot; the key never resides in process memory.
- Per-realm KDC pool (one pool per realm) or per-forest KDC pool (shared across realms)?
- Cache invalidation strategy on password change / group membership change? Cache TTL is the simple approach; event-driven invalidation is the correct approach.

**Cross-capability impact**:

- Affects: PC-018 (`tokenGroups` constructed attribute) — KDC's PAC builder computes the equivalent on every AS-REQ.
- Affects: Operations (PC-094, not in this catalog) — KDC monitoring, scaling.
- Affected by: Core Directory PC-002 (UTD vector) — KDC cache must invalidate on replication.

---

### PC-034 — `kpasswd` (RFC 3244) is the only standardized password-change protocol; UI integration varies

**Capability**: KDC
**Severity**: medium
**Cross-platform**: cross-platform

**Problem statement**:

AD uses kpasswd (RFC 3244) on TCP/UDP 464 for password changes. The protocol uses KRB-PRIV wrapping: the client encrypts the password-change request to the kpasswd service (`kadmin/changepw` SPN) using a key derived from the user's TGT session key. The kpasswd service (running on the KDC) validates the request, calls the DSA to update `unicodePwd`, urgent-replicates the change to the PDC, and returns a success / failure code per [02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) and [02-protocols/07-ntp-time-sync.md](../docs/02-protocols/07-ntp-time-sync.md).

All major clients (Windows `kerberos.dll`, macOS Heimdal, Linux MIT krb5) support kpasswd. UI integration varies: Windows uses Ctrl+Alt+Del → Change Password (which calls kpasswd under the hood); macOS uses System Settings → Users & Groups → Change Password; Linux uses `passwd` via PAM (which calls kpasswd via `pam_krb5`). The kpasswd protocol returns `KRB5KDC_ERR_KEY_EXPIRED` for must-change passwords — the client then prompts for a new password.

A framework must support kpasswd (the standard) and consider modern alternatives (self-service portal, OAuth-backed password reset). The self-service portal is a web app that authenticates the user (via existing credentials or MFA) and calls the directory's password-change API directly. OAuth-backed password reset uses OAuth2 / OIDC scopes (e.g. `password:reset`) to authorize a password-reset flow.

**Impact**:

Standard kpasswd is required for client interop. Without it, every client must use a custom password-change mechanism (the framework's API), breaking existing client tools (`passwd`, `kpasswd`, `Set-ADAccountPassword`). The UI integration varies — a framework that wants consistent UX across platforms needs a unified self-service portal.

**Constraints**:

- Must support TCP/UDP 464.
- KRB-PRIV wrapping (the request and response are encrypted to the user's TGT session key).
- Returns `KRB5KDC_ERR_KEY_EXPIRED` for must-change passwords (the client prompts for new password).
- Returns `KRB5KDC_ERR_POLICY` for policy violations (password too short, password in history, etc.).
- For AD interop, must support the `kadmin/changepw` SPN.

**Cross-platform considerations**:

- **Windows**: `kerberos.dll` includes kpasswd client; `ksetup /mapuser` for account mapping.
- **macOS**: SSO Extension supports kpasswd; legacy `/usr/libexec/kdc` includes a kpasswd client.
- **Linux**: MIT krb5's `kpasswd` command; Heimdal's `kpasswd`; SSSD's `krb5` provider handles kpasswd via PAM.
- **Cross-platform consistency**: Wire format is RFC 3244 — platform-independent.

**KB references**:

- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — kpasswd protocol, KRB-PRIV wrapping, `kadmin/changepw` SPN.
- [`02-protocols/07-ntp-time-sync.md`](../docs/02-protocols/07-ntp-time-sync.md) — password expiration as a time-based event, urgent replication.

**Open questions**:

- Add OAuth2 password-reset endpoint as modern alternative? Scope `password:reset` authorizes a reset flow; the user authenticates via MFA.
- Self-service portal with MFA (FIDO2 / TOTP / push)?
- Should the framework support passwordless-only mode (no passwords, no kpasswd)?

**Cross-capability impact**:

- Affects: Core Directory PC-013 (`unicodePwd`) — kpasswd updates `unicodePwd` via DSA.
- Affects: PC-030 (krbtgt rotation) — krbtgt is also a password change via the same mechanism.

---

### PC-035 — Group Managed Service Accounts (gMSA) require KDS root key + automatic password rotation

**Capability**: KDC
**Severity**: high
**Cross-platform**: cross-platform

**Problem statement**:

Group Managed Service Accounts (gMSAs) are a special account type (`msDS-GroupMSAMembership` ACL on the gMSA object) with automatic 30-day password rotation computed by KDS (Key Distribution Service) using a forest-wide root key. The KDS root key is created via `Add-KdsRootKey` and must be created 10+ hours before use (the effective-time trick — KDS refuses to use a root key whose `EffectiveTime` is in the future, preventing key-recovery attacks where an admin creates a root key with a past EffectiveTime and computes historical gMSA passwords) per [01-ad-core/01-ad-ds-internals.md](../docs/01-ad-core/01-ad-ds-internals.md) and [00-overview/04-fsmo-roles.md](../docs/00-overview/04-fsmo-roles.md).

Service hosts fetch the gMSA password via `NetrServerAuthenticate3` + `NetrServerRetrieveBaseDelta` (MS-NRPC) or via `Get-ADServiceAccount` (PowerShell, which calls the same RPC). The host must be a member of the gMSA's `msDS-GroupMSAMembership` group. The host caches the gMSA password for 30 days (until the next rotation); on cache expiry, the host fetches the new password from a DC.

The KDS root key is stored in `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,<forest-root-dn>` as `msKds-ProvRootKey` objects. The KDS uses the root key + the gMSA's SID + the current time (rounded to 30-day intervals) to derive the gMSA password via a PBKDF2-like derivation. All DCs compute the same password (same root key, same SID, same time interval) — no replication of the gMSA password itself, only of the root key.

A framework must implement KDS-equivalent or use a different mechanism (Vault-backed service-account secrets). Vault (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) is a more modern alternative — the framework's KDC issues short-lived tokens to service hosts, who use the tokens to fetch secrets from Vault. The trade-off: Vault is an external dependency; KDS is built-in.

**Impact**:

Without gMSA-equivalent, service-account passwords are static (Kerberoast risk — see PC-024) or operator-managed (ops burden — rotate every N days manually). gMSA solves both: passwords rotate automatically every 30 days; the service host fetches the password without operator intervention; the password is never visible to operators. The 30-day rotation limits the Kerberoast window — an attacker who captures a TGS for the gMSA has 30 days to crack it before the password changes.

**Constraints**:

- Must support automatic rotation (default 30 days, configurable).
- Must support host ACL (`msDS-GroupMSAMembership`).
- Must support the KDS root key (forest-wide secret used for password derivation).
- For AD interop, must implement the MS-NRPC password-fetch protocol (`NetrServerRetrieveBaseDelta`).
- The KDS root key derivation must be deterministic (all DCs compute the same password).

**Cross-platform considerations**:

- **Windows**: `kdssvc.dll` (KDS service in LSASS); `Add-KdsRootKey`, `Get-ADServiceAccount`, `Install-ADServiceAccount` for management. Windows service hosts use `msDS-GroupMSAMembership` natively.
- **macOS**: No native gMSA support. The framework's macOS service hosts would need a custom gMSA client (fetch password via the framework's API).
- **Linux**: Samba 4 supports gMSA (since 4.15); 389-DS / FreeIPA have their own service-account management but not gMSA-compatible. SSSD's `ad` provider supports gMSA password fetch since SSSD 2.5.
- **Cross-platform consistency**: The KDS root key derivation algorithm must be identical across all DCs; the password-fetch protocol must be MS-NRPC for AD interop.

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — gMSA schema attributes, KDS root key storage, password derivation algorithm.
- [`00-overview/04-fsmo-roles.md`](../docs/00-overview/04-fsmo-roles.md) — KDS as a forest-wide service, root key creation, `Add-KdsRootKey` effective-time trick.

**Open questions**:

- HashiCorp Vault integration for service-account secrets? Vault handles secret rotation, access control, audit logging — but adds an external dependency.
- KDS-equivalent per-forest root key? The framework's KDS would be its own service, with its own root key management.
- Hybrid: KDS for AD interop, Vault for new services?
- Should the framework support shorter rotation intervals (e.g. 1 hour, like Kubernetes service-account tokens)?

**Cross-capability impact**:

- Affects: Auth Provider PC-036 (NTLM) — gMSAs use Kerberos only (no NTLM fallback).
- Affects: PC-024 (Kerberoasting) — gMSA rotation limits the crack window.
- Affected by: Core Directory PC-014 (FSMO) — KDS is forest-wide; the root key is replicated.

---

## Cross-capability impact

Problems in this capability affect and are affected by problems in other capabilities:

- **Core Directory** is the foundation. KDC reads principal data, krbtgt account, service principals, and group memberships from Core Directory. PC-023 (KDC MS-KILE) is blocked if Core Directory cannot store `unicodePwd` (PC-013), `servicePrincipalName` (PC-031 uniqueness), `userPrincipalName` (PC-032 uniqueness), or compute `tokenGroups` (PC-018 constructed attribute). PC-030 (krbtgt rotation) requires atomic replication of the krbtgt account's `unicodePwd` via DRSUAPI (PC-001).
- **Auth Provider** consumes KDC for Kerberos SSPI-equivalent. PC-039 (S4U2Self/S4U2Proxy) relies on the KDC's PAC generation. PC-040 (token construction) on Windows uses the KDC-issued TGT to build the user's token. PC-041 (time sync) affects the KDC's 5-minute skew window.
- **Cert Service** is required for PKINIT (PC-027). The Enterprise CA must issue smart-card certs with the Smart Card Logon EKU and publish to `NTAuthCertificates`.
- **Federation Gateway** uses Kerberos-constrained delegation (S4U2Proxy) for service-to-service auth. PC-028 (cross-realm referral) affects cross-forest federation.
- **Client SDK** provides the kinit-equivalent for cross-platform clients. PC-026 (FAST) and PC-029 (etype 0x13) require client-side support.
- **Operations** depends on KDC monitoring (throughput, AS-REQ/TGS-REQ latency, krbtgt rotation scheduling).
- **Security & Threat Model** covers Kerberoasting (PC-024), golden ticket (PC-030), silver ticket (PC-025), AS-REP roasting (PC-026). The KDC's audit events (4768/4769/4771) feed SIEM detection.
- **Migration & Coexistence** depends on KDC interop during cross-realm migration. PC-028 (cross-realm referral) is critical for forest-trust migration.

## Open research questions specific to this capability

1. **KDC implementation strategy**: Reuse Samba's Heimdal fork (GPLv3), MIT krb5 + custom PAC plugin (FreeIPA approach), or fresh implementation? Each has trade-offs in license, MS-KILE compliance, and maintenance burden.

2. **RC4 deprecation path**: Hard cut-off date, migration mode with audit warnings, or auto-rotate to AES? The choice affects every legacy app that hard-requires RC4.

3. **PAC validation default**: Always-validate (security-first, +10ms per TGS), opt-in (perf-first, silver-ticket risk), or token-binding via TLS exporter (modern, no DC roundtrip)?

4. **FAST-required compatibility**: Is FAST-required compatible with all legacy clients? What is the migration path for organizations with old Java / Python / Samba clients?

5. **PKINIT vs FIDO2**: Adopt FIDO2 + PKINIT-anonymous for passwordless, maintain smart-card path for compliance, or hybrid? FIDO2 is modern but not Kerberos-native.

6. **krbtgt key management**: HSM-bound (eliminates LSASS-dump risk, adds HSM dependency), automatic rotation every 30 days (reduces attack window, increases operational complexity), or multiple krbgtgs per realm (eliminates single point, breaks AD interop)?

7. **KDC horizontal scaling**: Stateless KDC with shared key in HSM, per-realm KDC pool, or per-forest KDC pool? Cache invalidation strategy on password change / group membership change is critical.

8. **gMSA alternative**: KDS-equivalent per-forest root key (AD-interop), HashiCorp Vault integration (modern, external dependency), or hybrid?

9. **Cross-realm referral model**: Replace `Transited` field with signed assertions, trust-on-first-use, or collapse to a single-domain forest?

10. **Passwordless future**: When does the framework drop password support entirely (no `unicodePwd`, no kpasswd, no NTLM)? The trade-off is breaking every legacy client.
