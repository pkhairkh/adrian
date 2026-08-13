---
title: Security & Threat Model — Problem Catalog
audience: architects-and-engineers
tags: [problem-catalog, security, threat-model, stride, framework-design, kerberoasting, dcsync, golden-ticket]
related:
  - ./README.md
  - ./00-framework-capabilities.md
  - ./02-kdc.md
  - ./03-auth-provider.md
  - ./10-operations.md
  - ./12-migration-and-coexistence.md
  - ./13-open-research-questions.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Security & Threat Model — Problem Catalog

**Capability definition.** Security & Threat Model is the cross-cutting capability that defines the threat surface, enumerates attacks against the framework, specifies mitigations, and audits the framework's compliance with those mitigations. AD's threat model is implicit and scattered: mitigations for Kerberoasting live in etype policy (`Network security: Configure encryption types allowed for Kerberos`), mitigations for DCSync live in the `DS-Replication-Get-Changes-All` ACL on the domain NC head, mitigations for golden ticket live in the krbtgt rotation procedure, mitigations for silver ticket live in `PAC_BUFFER_TICKET_CHECKSUM`. The framework must make the threat model explicit, define a STRIDE classification per threat, and ensure every mitigation is on by default.

## STRIDE classification reference

Each threat in this catalog is classified by STRIDE category:

- **S**poofing — attacker impersonates a legitimate principal.
- **T**ampering — attacker modifies data in flight or at rest.
- **R**epudiation — attacker denies an action and logs are insufficient.
- **I**nformation disclosure — attacker extracts secrets or sensitive data.
- **D**enial of service — attacker disrupts service availability.
- **E**levation of privilege — attacker gains access beyond their authorisation.

## Summary of problems

| PC | Title | Severity | STRIDE | Cross-platform |
|----|-------|----------|--------|----------------|
| PC-116 | Kerberoasting (RC4 TGS brute-force) is the dominant AD attack | blocker | Information disclosure, Elevation of privilege | cross-platform |
| PC-117 | DCSync (DRSGetNCChanges with EXOP_REPL_SECRETS) extracts all password hashes | blocker | Information disclosure, Elevation of privilege | cross-platform |
| PC-118 | Golden ticket (forged TGT via krbtgt hash) requires krbtgt rotation to invalidate | blocker | Spoofing, Elevation of privilege | cross-platform |
| PC-119 | Silver ticket (forged TGS via service-account hash) requires PAC_BUFFER_TICKET_CHECKSUM | high | Spoofing, Elevation of privilege | cross-platform |
| PC-120 | SIDHistory abuse allows privilege escalation across migrations | high | Elevation of privilege, Spoofing | cross-platform |
| PC-121 | Selective authentication (`Allowed to Authenticate` ACE) is per-resource; rarely used | medium | Elevation of privilege | cross-platform |
| PC-122 | AdminSDHolder + SDPROP (every 60 min) can override intended ACLs | medium | Tampering, Elevation of privilege | cross-platform |
| PC-123 | Supply-chain risk: signed AD updates require WSUS trust | medium | Tampering, Elevation of privilege | cross-platform |

---

## Detailed problem entries

### PC-116 — Kerberoasting (RC4 TGS brute-force) is the dominant AD attack

**Capability**: Security
**Severity**: blocker
**STRIDE**: Information disclosure, Elevation of privilege
**Cross-platform**: cross-platform

**Problem statement**:

Any authenticated domain user can request a TGS service ticket for any SPN-registered service account in the domain. The KDC, on receiving a TGS-REQ for `cifs/file01.example.com@EXAMPLE.COM`, looks up the SPN, finds the owning service account, retrieves the account's long-term key (NTLM hash for RC4, AES key for AES etypes), and encrypts the resulting Ticket's `enc-part` (the `EncTicketPart` structure containing the session key, client identity, PAC, and validity window) with that long-term key per RFC 4120 §5.3 and MS-KILE, as documented in [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md).

The attack: an attacker who has any domain user account (often obtained via phishing or spray) runs `GetUserSPNs.py -request` (impacket) or `Rubeus kerberoast` to enumerate all SPN-bearing accounts in the domain via an LDAP query for `(servicePrincipalName=*)`, then requests a TGS for each SPN. The returned tickets are saved. For accounts whose `msDS-SupportedEncryptionTypes` permits RC4-HMAC (etype 0x17) — or, more commonly, accounts where the KDC falls back to RC4 because the attribute is unset — the Ticket's `enc-part` is encrypted with the NTLM hash (MD4 of the password) as the key. The attacker then performs offline brute-force or dictionary attack on the encrypted ticket using `hashcat -m 13100` (RC4-HMAC TGS) — modern GPUs compute 10⁸-10⁹ guesses/sec against RC4-HMAC. A weak service-account password (`Summer2024!`, `Welcome1`) cracks in seconds to minutes.

AES-encrypted tickets (etype 0x12, AES-256-CTS-HMAC-SHA1-96) are also brute-forceable but the PBKDF2 key derivation (4096 iterations of HMAC-SHA1 per RFC 3962) slows the attack by ~10⁵×, making AES-encrypted tickets with 25+ char random passwords effectively uncrackable. The mitigation hierarchy: (1) gMSA (Group Managed Service Accounts) with 240-char random passwords managed by the KDS root key, (2) AES-only etypes enforced via `msDS-SupportedEncryptionTypes = 0x30` (AES128|AES256) and domain policy `Network security: Configure encryption types allowed for Kerberos` set to disable RC4, (3) long random service-account passwords (>25 chars). Most AD deployments have legacy service accounts with weak passwords and RC4 still enabled — Kerberoasting is the #1 AD attack vector per the threat notes in [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md).

**Impact**:

Kerberoasting is the #1 AD attack vector. Any domain user can pull all SPN-bearing accounts' TGS tickets in minutes. Weak service-account passwords crack offline in seconds. Result: service-account compromise → lateral movement → Domain Admin via token impersonation or kerberoasting of a high-privilege SPN.

**Constraints**:

- Must default to AES-only etypes (no RC4 fallback).
- Must enforce long service-account passwords (>= 25 chars) or mandate gMSA.
- Must support gMSA with KDS root key rotation.
- Must audit every TGS-REQ (Event 4769) with etype field for detection.
- Must alert on TGS-REQ storms (many SPNs requested by one user in short window).

**Attack vector**:

1. Attacker obtains any domain user credentials (phishing, password spray, OSINT).
2. Attacker runs `GetUserSPNs.py corp.example.com/jsmith:'P@ss!' -dc-ip dc01 -request` to enumerate SPN-bearing accounts and request TGS for each.
3. impacket issues an LDAP query `(servicePrincipalName=*)` to enumerate SPNs.
4. For each SPN, impacket issues a TGS-REQ to the KDC with `sname = <SPN>@REALM`. The KDC obliges — no SPN-ownership check on the requester.
5. The TGS-REP contains a `Ticket` encrypted with the service account's long-term key. The attacker saves each ticket.
6. Offline: attacker runs `hashcat -m 13100 hashes.txt rockyou.txt` — RC4-HMAC TGS hashes crack at 10⁸/sec on a modern GPU.
7. Cracked password gives the attacker the service account's credentials. Attacker impersonates the service account, escalates via the account's group memberships (often Domain Admins or local admin on multiple hosts).

**Known mitigations in AD**:

- `Network security: Configure encryption types allowed for Kerberos` GPO → set to "AES128_HMAC_SHA1 + AES256_HMAC_SHA1 + Future" (no RC4). Requires all service accounts to support AES (`msDS-SupportedEncryptionTypes` bitmask including 0x10 or 0x20).
- gMSA (Group Managed Service Account): `New-ADServiceAccount -Name svc-web -DNSHostName web.example.com -KerberosEncryptionType AES256`. The KDS root key (`Add-KdsRootKey -EffectiveImmediately`) generates a 240-char random password rotated every 30 days.
- Service-account password length enforcement: AD has no built-in per-OU password policy for service accounts; must use Fine-Grained Password Policy (`New-ADFineGrainedPasswordPolicy`) targeting the service-accounts OU.
- Detection: Event 4769 (TGS-REQ) with `Ticket Encryption Type: 0x17` (RC4-HMAC) is the smoking gun. SIEM rule: alert on >5 unique SPNs requested by one user in 5 minutes.

**Cross-platform considerations**:

- **Windows**: AD DCs are the reference implementation; mitigation via GPO is canonical.
- **macOS**: Mac clients can also Kerberoast via `kvno <SPN>@REALM` + `hashcat` on the resulting ccache; PSSO Extension does not change this.
- **Linux**: `GetUserSPNs.py` runs identically against an AD-joined Linux host; Samba `samba-tool` does not expose this attack but `impacket` does.
- **Cross-platform consistency**: The framework's KDC must enforce etype policy uniformly regardless of the client OS. Detection signals (Event 4769 equivalent) must be available to all SIEMs.

**KB references**:

- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — Threat-model notes section listing Kerberoasting as the #1 AD attack with the gMSA + AES mitigation.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Kerberos enctype table (etype 0x17 RC4-HMAC vs 0x12 AES-256), PA-ENC-TIMESTAMP pre-auth, TGS-REQ/TGS-REP message structure.
- [`11-code-examples/05-python-impacket-examples.md`](../docs/11-code-examples/05-python-impacket-examples.md) — `GetUserSPNs.py` programmatic recipe.

**Open questions**:

- Auto-detect Kerberoast attempts via 4769 events with etype 0x17? Force-migrate service accounts to AES on next rotation?

**Cross-capability impact**:

- Affects: PC-024 (KDC etype policy), PC-035 (gMSA key distribution), PC-111 (audit pipeline must capture 4769), PC-117 (DCSync attack is often the post-Kerberoast escalation).
- Affected by: PC-023 (KDC must enforce etype policy), PC-030 (krbtgt rotation protects against golden ticket post-Kerberoast).

---

### PC-117 — DCSync (DRSGetNCChanges with EXOP_REPL_SECRETS) extracts all password hashes

**Capability**: Security
**Severity**: blocker
**STRIDE**: Information disclosure, Elevation of privilege
**Cross-platform**: cross-platform

**Problem statement**:

DRSUAPI `DRSGetNCChanges` (opnum 3 on interface `E3514235-8B63-11D0-A26C-00A0C92B955C`) is the workhorse of AD replication. The destination DC issues it to a source DC, providing the NC head DN, the UTD vector, and the high-watermark. The source replies with a `REPLENTINLIST` chain of object updates per the wire format documented in [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) and [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md). The `ulExtendedOp` field on the request can be set to `EXOP_REPL_SECRETS` (0x1) which instructs the source to include the secret attributes (`unicodePwd`, `ntPwdHistory`, `supplementalCredentials`, `lmPwdHistory`) on the returned objects. This is how password hashes replicate between DCs.

The attack, dubbed "DCSync" and disclosed in 2015 by Microsoft / DCLDrsync researchers: any principal holding the `DS-Replication-Get-Changes` (GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) and `DS-Replication-Get-Changes-All` (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) extended rights on the domain NC head can call `DRSGetNCChanges` with `EXOP_REPL_SECRETS` and pull the password hashes for every user in the domain. By default, these rights are granted to Domain Admins, Enterprise Admins, and the DC machine accounts (`BUILTIN\Server Operators` on each DC). Members of `Account Operators` and `Backup Operators` do not have them by default but can sometimes escalate to obtain them.

`secretsdump.py -just-dc corp.example.com/jsmith:'P@ss!'@dc01.corp.example.com` (impacket) implements the full DRSync attack: DRSBind, DRSCrackNames to resolve the domain NC head DN, DRSGetNCChanges with `EXOP_REPL_SECRETS` and `cMaxObjects = 1000` per page, iterate through the entire Domain NC, extract `unicodePwd` (NTLM hash), `supplementalCredentials` (Kerberos AES keys, cached credentials), and `lmPwdHistory`/`ntPwdHistory`. Total extraction time for a 100k-user domain: 5-30 minutes. Result: every password hash offline-crackable at attacker leisure. Per the threat notes in [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md), DCSync is "full domain compromise by any Domain Admin" — and any principal granted the extended rights is functionally a Domain Admin.

**Impact**:

DCSync = full domain compromise. Any Domain Admin (or delegated principal with the two extended rights) can extract all password hashes including the `krbtgt` hash, enabling golden-ticket attacks (PC-118). Detection is hard because the call looks identical to legitimate replication; the only signal is the source (non-DC caller) and the scope (full NC pull).

**Constraints**:

- Must audit all `DRSGetNCChanges` calls with caller identity.
- Must alert on non-DC callers (any principal that is not a registered `nTDSDSA` object).
- Must alert on `EXOP_REPL_SECRETS` scope (full NC pull vs. single-object).
- Must restrict `DS-Replication-Get-Changes-All` to DC machine accounts only by default.
- Must log Event 4662 (Object Access) with the `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` GUID.

**Attack vector**:

1. Attacker obtains Domain Admin credentials (via Kerberoasting PC-116, phishing a DA, or Pass-the-Hash on a DA session).
2. Attacker runs `secretsdump.py -just-dc corp.example.com/jsmith:'P@ss!'@dc01.corp.example.com` from any host that can reach TCP/135 + dynamic RPC ports on the DC.
3. impacket calls `DRSBind` to establish a DRSUAPI session, exchanging `DRS_EXTENSIONS` capability flags (requesting `DRS_EXT_GETCHG_DEFLATE`, `DRS_EXT_GETCHGREQ_V8`, `DRS_EXT_STRONG_ENCRYPTION`).
4. impacket calls `DRSCrackNames` to resolve `DC=corp,DC=example,DC=com` to a `DSNAME` structure.
5. impacket calls `DRSGetNCChanges` with `ulExtendedOp = EXOP_REPL_SECRETS` (0x1), `cMaxObjects = 1000`, providing an empty UTD vector to force a full sync.
6. The DC responds with `REPLENTIN` entries for every user, computer, and trust account. Secret attributes (`unicodePwd`, `supplementalCredentials`) are populated.
7. impacket extracts and prints hashes in a format ready for `hashcat -m 1000` (NTLM) or `-m 13100` (RC4-HMAC TGS using the krbtgt account).
8. Attacker pivots: use `krbtgt` hash to forge golden tickets (PC-118), use individual user hashes for Pass-the-Hash, use `machine$` hashes for lateral movement.

**Known mitigations in AD**:

- Audit: enable Event 4662 on every DC. Filter for `Properties: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All).
- Alert: SIEM rule — any 4662 event where the caller is not a `nTDSDSA` object (i.e. not a registered DC) and the operation is on the Domain NC head.
- Restrict: remove `DS-Replication-Get-Changes-All` from any non-DC principal. Audit ACLs via `dsacls "DC=corp,DC=example,DC=com"` and look for non-default grantees.
- Tier-0 administration model: Domain Admins exist only on DCs and dedicated admin workstations (PAWs); never log into user workstations with DA credentials. Reduces exposure to Pass-the-Hash.
- Microsoft Defender for Identity (MDI) detects DCSync via network behaviour (DRSUAPI RPC from a non-DC source).

**Cross-platform considerations**:

- **Windows**: AD DCs are the reference target; mitigation via ACL audit + Event 4662.
- **macOS**: Mac cannot be a DCSync target (no DC role) but can run `secretsdump.py` against an AD DC.
- **Linux**: Samba AD-DC is also vulnerable (same DRSUAPI surface). FreeIPA is not vulnerable (uses 389-DS replication, not DRSUAPI).
- **Cross-platform consistency**: The framework's KDC + DSA must enforce the same ACL check on `DRSGetNCChanges` regardless of which platform hosts the DC.

**KB references**:

- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — DCSync threat-model note: "any principal with DS-Replication-Get-Changes + DS-Replication-Get-Changes-All can issue DRSGetNCChanges and pull the password hashes."
- [`11-code-examples/05-python-impacket-examples.md`](../docs/11-code-examples/05-python-impacket-examples.md) — `secretsdump.py -just-dc` programmatic recipe with `DRSBind` + `DRSCrackNames` + `DRSGetNCChanges` flow.
- [`02-protocols/06-rpc-dcerpc-ms-drsr.md`](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — DRSUAPI interface UUID, opnum table, `DRS_EXTENSIONS` capability flags, `DRS_MSG_GETCHGREQ_V11` request structure including `ulExtendedOp`.

**Open questions**:

- Per-principal `DS-Replication-Get-Changes-All` audit? Break-glass replication via HSM-bound key?

**Cross-capability impact**:

- Affects: PC-118 (golden ticket is the post-DCSync escalation), PC-111 (audit pipeline must capture 4662 with replication GUID), PC-035 (gMSA password distribution uses a similar DRSUAPI mechanism — must be audited separately).
- Affected by: PC-001 (DRSUAPI implementation), PC-014 (FSMO roles — PDC emulator is often the DRSync target).

---

### PC-118 — Golden ticket (forged TGT via krbtgt hash) requires krbtgt rotation to invalidate

**Capability**: Security
**Severity**: blocker
**STRIDE**: Spoofing, Elevation of privilege
**Cross-platform**: cross-platform

**Problem statement**:

The `krbtgt` account in every AD domain holds the long-term key used to sign and encrypt TGTs (Ticket-Granting Tickets). The KDC, on receiving an AS-REQ, retrieves the `krbtgt` account's NTLM hash (for RC4) or AES key (for AES) and uses it to encrypt the `EncTicketPart` of the returned TGT per [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md). The KDC also signs the PAC inside the TGT with the krbtgt key (`PAC_SIGNATURE_DATA` type 0x07). Every TGS-REQ that follows uses the TGT as the credential; the KDC decrypts the TGT with the krbtgt key, validates the PAC signature, and issues a service ticket. Per [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md), the krbtgt key is also used to sign the `PAC_BUFFER_TICKET_CHECKSUM` (Server 2016+) over the entire Ticket.enc-part.

The attack: an attacker who has the krbtgt hash (typically obtained via DCSync, PC-117) can forge TGTs locally without contacting the KDC. `ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-... -domain CORP.EXAMPLE.COM -user-id 500 Administrator` (impacket) produces a forged TGT claiming to be `Administrator` with arbitrary group memberships, arbitrary validity period (up to 10 years by default), and the correct PAC signatures. The attacker injects the forged TGT into their Kerberos ccache (`KRB5CCNAME`) and uses it to request service tickets via TGS-REQ. The KDC, decrypting the TGT with the krbtgt key, validates everything and issues service tickets as if the attacker were genuinely Administrator.

Detection is hard because the forged TGT is cryptographically valid — the KDC cannot distinguish it from a real one. The only mitigation is krbtgt password rotation: when the krbtgt password is changed, the KDC's krbtgt key changes. Old TGTs (encrypted with the old key) fail decryption. AD keeps the previous krbtgt key for a grace period (typically the TGT lifetime, 10 hours) so in-flight TGTs continue to work; after the grace period, all old TGTs are invalid. Microsoft's incident-response guidance (KB 3011620) recommends rotating krbtgt **twice** with a gap equal to the maximum TGT lifetime — this ensures any old-key TGT has expired before the second rotation removes the old key entirely.

The framework gap: krbtgt rotation in AD is a manual `Set-ADAccountPassword krbtgt` operation that requires careful sequencing (rotate, wait, rotate again). The framework should make this a one-click operation with built-in grace-period management, automatic monitoring for old-key TGT usage (a strong indicator of golden ticket activity), and HSM-bound krbtgt key option to make extraction impossible.

**Impact**:

Compromised krbtgt hash = persistent forest compromise. Attacker retains Domain Admin access for as long as the krbtgt key is unchanged. Microsoft IR guidance: rotate krbtgt twice with 10-hour gap — during that gap, the forest is in a vulnerable state (old key still accepted). Recovery without detection: impossible.

**Constraints**:

- Must support dual-krbtgt mode (current + previous key, grace period = TGT lifetime).
- Must log old-key TGT usage as a security signal (Event 4769 with key-version mismatch).
- Must support one-click krbtgt rotation (operator action, no manual sequencing).
- Must support HSM-bound krbtgt key (key never leaves the HSM, only the KDC sees it via PKCS#11).
- Must support automatic rotation every N days (recommended 180 days; high-security: 30 days).

**Attack vector**:

1. Attacker obtains the krbtgt hash via DCSync (PC-117) — needs Domain Admin or DC compromise.
2. Attacker runs `ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-... -domain CORP.EXAMPLE.COM -user-id 500 Administrator` from any host.
3. `ticketer.py` constructs a `Ticket` ASN.1 structure with `sname = krbtgt/CORP.EXAMPLE.COM`, `cname = Administrator`, `flags = forwardable, renewable, pre-authenticated`, `endtime = 2035-01-01` (10 years out), and a forged PAC containing `GroupIds = [513 Domain Users, 512 Domain Admins, 519 Enterprise Admins]`.
4. The `EncTicketPart` is encrypted with the krbtgt NTLM hash → produces a valid-looking TGT.
5. Attacker exports the TGT to `KRB5CCNAME=/tmp/forged.ccache` and runs any impacket tool (`psexec.py`, `wmiexec.py`, `smbclient.py`) with `KRB5CCNAME` set.
6. The KDC, on receiving a TGS-REQ with the forged TGT, decrypts the TGT using its current krbtgt key, validates the PAC signature, and issues a service ticket for any requested SPN — apparently on behalf of `Administrator`.
7. The attacker uses the service ticket to access any service (SMB, LDAP, HTTP, MSSQL) as Administrator.

**Known mitigations in AD**:

- krbtgt password rotation: `Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString 'NewLongRandomPassword!' -AsPlainText -Force)`. Repeat after the TGT lifetime (10 hours default).
- Detection: Event 4769 with `Key Version` mismatch (the TGT was encrypted with an older krbtgt key version than current). SIEM alert on any 4769 where the TGT key version is < current key version - 1.
- PAC validation (Server 2016+): `PAC_BUFFER_TICKET_CHECKSUM` (type 0x0E) signs the entire Ticket.enc-part with the krbtgt key. Forged TGTs without this signature fail validation by services that opt in. Most services do not opt in (see PC-119).
- HSM-bound krbtgt: not natively supported in AD; requires third-party KSP (Key Storage Provider) integration. The framework should support this natively.
- Automatic rotation: AD has no built-in auto-rotation; orgs use scheduled tasks or Microsoft's `Reset-KrbtgtAccountPassword.ps1` script.

**Cross-platform considerations**:

- **Windows**: AD DCs are the reference target; mitigation via krbtgt rotation + Event 4769 key-version audit.
- **macOS**: Mac clients can consume forged TGTs via `KRB5CCNAME`; no native mitigation.
- **Linux**: Samba AD-DC has the same krbtgt-key model; MIT krb5 KDC supports similar via `kadmin change_password krbtgt/REALM`. FreeIPA's `ipa-replica-manage` does not auto-rotate krbtgt.
- **Cross-platform consistency**: krbtgt rotation must be uniform across all DCs in the realm; replication lag means old-key TGTs may be accepted on lagged DCs even after rotation.

**KB references**:

- [`00-overview/01-active-directory-overview.md`](../docs/00-overview/01-active-directory-overview.md) — Golden ticket threat note: "attacker who has the krbtgt hash can forge TGTs. Detection: monitor for TGS-REQs whose TGT was issued by a non-current krbtgt."
- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — PAC structure, `PAC_SIGNATURE_DATA` (type 0x07) KDC signature keyed with krbtgt, `PAC_BUFFER_TICKET_CHECKSUM` (type 0x0E) introduced Server 2016.

**Open questions**:

- HSM-bound krbtgt key? Automatic rotation every N days?

**Cross-capability impact**:

- Affects: PC-119 (silver ticket uses service-account key, not krbtgt, but similar forgery), PC-030 (krbtgt rotation is the KDC capability), PC-110 (DR procedures must include krbtgt rotation as a recovery step).
- Affected by: PC-117 (DCSync is the typical path to obtain the krbtgt hash), PC-023 (KDC must support key version management).

---

### PC-119 — Silver ticket (forged TGS via service-account hash) requires PAC_BUFFER_TICKET_CHECKSUM

**Capability**: Security
**Severity**: high
**STRIDE**: Spoofing, Elevation of privilege
**Cross-platform**: cross-platform

**Problem statement**:

A silver ticket is a forged service ticket. Where a golden ticket forges a TGT (encrypted with the krbtgt key), a silver ticket forges a TGS service ticket (encrypted with the service account's long-term key). Per [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md), the service ticket's `Ticket.enc-part` is encrypted with the service account's NTLM hash (RC4) or AES key — derived from the service account's password. An attacker who has the service account's hash (obtained via Kerberoasting PC-116, or via DCSync PC-117) can forge a service ticket locally using `ticketer.py -nthash <service_hash> -spn cifs/file01.example.com -user-id 500 Administrator` (impacket).

The forged silver ticket is presented directly to the target service (`AP-REQ` containing the forged ticket). The service decrypts the ticket with its own long-term key — succeeds, because the attacker used the correct key. The service extracts the PAC from the ticket's `authorization-data`, sees the user identity and group memberships (forged to be Administrator), and grants access. No KDC interaction occurs — the attack is entirely offline from the KDC's perspective, making detection very hard.

The mitigation introduced in Windows Server 2016 is `PAC_BUFFER_TICKET_CHECKSUM` (PAC buffer type 0x0E). The KDC, when issuing a service ticket, computes an HMAC over the entire `Ticket.enc-part` using the krbtgt key (separate from the encryption) and embeds this signature in the PAC. A service that opts in to ticket-signature validation (registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\VerifyPacAuthenticators = 1`) re-verifies this signature by calling the KDC's PAC validation RPC (`NetrLogonSamLogonEx` with `MSV1_0_PAC` flag). The KDC, holding the krbtgt key, recomputes the signature and returns success or failure. A forged silver ticket lacks the correct ticket signature (attacker does not have the krbtgt key) → verification fails.

The problem: most services do not opt in to PAC validation. IIS with Windows Auth, SQL Server with Kerberos, and COM+ with Kerberos perform PAC validation by default; SMB file services, HTTP services, and most custom applications do not. The performance cost is one RPC roundtrip to the DC per AP-REQ. Silver tickets against non-validating services persist undetected.

The framework gap: `PAC_BUFFER_TICKET_CHECKSUM` should be generated by default (the framework's KDC must always emit it). Services should default-validate (the framework's service-side Kerberos library should always verify). For perf-critical services, an opt-out should exist but require explicit configuration. Modern alternatives (token binding via TLS exporter, channel binding) should also be considered — they bind the ticket to the TLS channel, preventing replay across sessions.

**Impact**:

Silver tickets persist undetected without PAC validation. Attacker who has a single service-account hash can forge service tickets for that service indefinitely. Detection requires the service to validate the ticket signature (Server 2016+) — most services skip this.

**Constraints**:

- Must generate `PAC_BUFFER_TICKET_CHECKSUM` on every service ticket (KDC-side default).
- Must support per-service opt-in to validation (default: validate).
- Must support opt-out for perf-critical services (explicit configuration, audit-logged).
- Must log validation failures (Event 4769-equivalent with `Failure Code: 0x1F` = KRB_AP_ERR_MODIFIED).

**Attack vector**:

1. Attacker obtains a service account's hash via Kerberoasting (PC-116) or DCSync (PC-117).
2. Attacker runs `ticketer.py -nthash <service_account_hash> -domain-sid S-1-5-21-... -domain CORP.EXAMPLE.COM -user-id 500 -spn cifs/file01.example.com Administrator`.
3. `ticketer.py` constructs a `Ticket` ASN.1 with `sname = cifs/file01.example.com`, `cname = Administrator`, forged PAC with Domain Admins group SID, and the standard PAC_SIGNATURE_DATA (type 0x06) server signature computed with the service key.
4. The Ticket's `enc-part` is encrypted with the service account's hash. The forged ticket is placed in a ccache.
5. Attacker connects to `\\file01\c$` via SMB using the forged ticket (`smbclient.py --kerberos -k`).
6. file01's `srv2.sys` (SMB server) decrypts the ticket with its machine account key — succeeds. Extracts the PAC, sees Administrator + Domain Admins.
7. file01 grants access to `\\file01\c$` as if the attacker were genuinely Administrator.

If file01 has `VerifyPacAuthenticators = 1` (the Server 2016+ PAC validation opt-in), step 6 includes a sub-step where the server calls `NetrLogonSamLogonEx` on the DC to verify the `PAC_BUFFER_TICKET_CHECKSUM`. The DC recomputes the signature with the krbtgt key and returns failure (because the attacker's forged ticket lacks the correct signature). The AP-REQ fails with `KRB_AP_ERR_MODIFIED (41)`.

**Known mitigations in AD**:

- Server 2016+ KDC generates `PAC_BUFFER_TICKET_CHECKSUM` automatically (no opt-in needed on KDC side).
- Service-side validation: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\VerifyPacAuthenticators = 1` (default 0 = off). Significant perf cost (one RPC per AP-REQ).
- Microsoft Defender for Identity detects silver ticket via behavioural anomalies (unusual SPN access patterns, ticket encryption type mismatch).
- Channel binding (TLS exporter): binds the Kerberos ticket to the TLS session, preventing replay across sessions. Supported in IIS 10+ with `Extended Protection = Required`.

**Cross-platform considerations**:

- **Windows**: Server 2016+ generates the ticket signature; service-side validation requires registry opt-in.
- **macOS**: Heimdal Kerberos on macOS does not generate or verify `PAC_BUFFER_TICKET_CHECKSUM` (fork from ~2014, predates Server 2016). PSSO Extension inherits this gap.
- **Linux**: MIT krb5 1.15+ parses the ticket signature; verification requires `[libdefaults] verify_pac = true` and a KDC-side validation RPC.
- **Cross-platform consistency**: The framework's KDC must always generate the ticket signature; the framework's service-side Kerberos library must always verify (with per-service opt-out for perf).

**KB references**:

- [`02-protocols/08-spn-upn-pac.md`](../docs/02-protocols/08-spn-upn-pac.md) — `PAC_BUFFER_TICKET_CHECKSUM` (type 0x0E) Server 2016+ ticket signature, computed over the entire Ticket.enc-part with the krbtgt key.
- [`02-protocols/01-kerberos-internals.md`](../docs/02-protocols/01-kerberos-internals.md) — Ticket structure, AP-REQ flow, `KRB_AP_ERR_MODIFIED (41)` error code.

**Open questions**:

- Default-validate by services (perf cost)? Token-binding alternative?

**Cross-capability impact**:

- Affects: PC-118 (golden ticket uses krbtgt key; silver ticket uses service key — both mitigated by ticket signature), PC-116 (Kerberoasting is the typical path to obtain a service-account hash).
- Affected by: PC-023 (KDC must generate ticket signature), PC-025 (PAC validation RPC).

---

### PC-120 — SIDHistory abuse allows privilege escalation across migrations

**Capability**: Security
**Severity**: high
**STRIDE**: Elevation of privilege, Spoofing
**Cross-platform**: cross-platform

**Problem statement**:

The `sIDHistory` attribute (schema OID `1.2.840.113556.1.4.1369`, multi-valued OctetString) on a user or group object carries SIDs from a previous domain — used during migrations to preserve access to resources that reference the old SID. Per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) and [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md), the behaviour of `sIDHistory` is governed by the trust relationship: within-forest trusts (`TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20`) permit sIDHistory passthrough; external trusts (`TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x1` or `TRUST_ATTRIBUTE_QUARANTINED = 0x4`) filter sIDHistory from the PAC's `ExtraSids` array.

The attack: an attacker with Domain Admin in a child domain can inject an arbitrary SID (e.g. `S-1-5-21-<forest-root-domain-sid>-519` = Enterprise Admins in the forest root) into a user's `sIDHistory` via `DRSAddSidHistory` (opnum 20 on DRSUAPI, requires `SeEnableDelegationPrivilege` on the source domain — granted to Domain Admins by default). The next time the user requests a TGT, the KDC includes the injected SID in the PAC's `ExtraSids`. When the user traverses the within-forest trust to the forest root, the target KDC preserves the `ExtraSids` (because the trust is within-forest) and the user's token on a forest-root DC includes Enterprise Admins. Result: a child-domain Domain Admin escalates to forest-root Enterprise Admin without ever compromising a forest-root DC. This is the "SID History injection" attack described in MS-KILE §3.4.5 and the "Golden SAML"-adjacent research.

The mitigation is sIDHistory filtering, also called SID Filter Quarantine. External trusts and forest trusts filter `sIDHistory` by default since Server 2003 (external) and Server 2008 (forest). Within-forest trusts do not filter (by design — to support migration). The administrator can force filtering on within-forest trusts via `netdom trust <trusting> /d:<trusted> /quarantine:Yes` but this breaks migration scenarios. PIM trusts (Privileged Access Management, Server 2016+, `TRUST_ATTRIBUTE_PIM_TRUST = 0x200`) provide user-level isolation with sIDHistory filtering.

The framework gap: sIDHistory is a migration-era feature that has become a permanent security liability. The framework should (a) default to sIDHistory filtering on ALL trusts including within-forest (use a different mechanism for migration — claims-based migration or per-object ACL re-write), (b) audit every `sIDHistory` write (Event 4662 with the sIDHistory attribute GUID), and (c) alert on non-migration sIDHistory additions. The framework should also support PIM trust semantics (Server 2016+) as a more usable alternative to within-forest sIDHistory passthrough.

**Impact**:

sIDHistory injection = forest-admin escalation from child-domain Domain Admin. Detection is hard because the injected SID looks legitimate in the PAC. Recovery requires removing the injected SID + auditing all access since injection.

**Constraints**:

- Must support sIDHistory filtering (QUARANTINED trust attribute, default ON for all trusts).
- Must audit sIDHistory writes (Event 4662-equivalent with sIDHistory attribute GUID).
- Must alert on non-migration sIDHistory additions.
- Must support PIM trust semantics (Server 2016+ `TRUST_ATTRIBUTE_PIM_TRUST = 0x200`).
- Must support claims-based migration as an alternative to sIDHistory.

**Attack vector**:

1. Attacker compromises a child-domain Domain Admin account (via Kerberoasting PC-116, phishing, etc.).
2. Attacker creates a new user `pwned` in the child domain.
3. Attacker calls `DRSAddSidHistory` (opnum 20 on DRSUAPI) targeting `pwned` with `sIDHistory = S-1-5-21-<forest-root-domain-sid>-519` (Enterprise Admins of the forest root). This requires `SeEnableDelegationPrivilege` on the source domain (held by child-domain Domain Admins).
4. The child-domain KDC, on the next AS-REQ for `pwned`, includes the Enterprise Admins SID in the PAC's `ExtraSids` array.
5. Attacker requests a cross-realm referral TGT to the forest root via the within-forest trust.
6. The forest-root KDC preserves the `ExtraSids` (within-forest trust does not filter sIDHistory).
7. Attacker accesses any forest-root resource as Enterprise Admin. (e.g. DCSync against a forest-root DC.)

**Known mitigations in AD**:

- SID Filter Quarantine on external trusts (default since Server 2003): `netdom trust <trusting> /d:<trusted> /quarantine:Yes`.
- SID Filter Quarantine on forest trusts (default since Server 2008): same command.
- Within-forest trusts do NOT filter by default (to support migration).
- PIM trusts (Server 2016+, `TRUST_ATTRIBUTE_PIM_TRUST = 0x200`): provide user-level isolation with sIDHistory filtering within-forest.
- Audit: Event 4662 (Object Access) with `Properties: sIDHistory` (attribute GUID `5905e5c0-c1bb-11d3-99a7-0000f81a86c8`). SIEM alert on any sIDHistory write outside a designated migration window.

**Cross-platform considerations**:

- **Windows**: AD-interop requires preserving within-forest sIDHistory passthrough for migration scenarios; the framework must support filtering on by default with explicit opt-out for migration.
- **macOS**: Mac clients cannot inject sIDHistory (no DRSUAPI client capability) but consume the PAC's `ExtraSids` via Kerberos.
- **Linux**: Samba AD-DC implements sIDHistory but the filtering behaviour is per-trust, same as AD. FreeIPA trusts AD with sIDHistory filtering on by default.
- **Cross-platform consistency**: The framework's trust model must apply sIDHistory filtering uniformly regardless of which platform hosts the trusting DC.

**KB references**:

- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `trustAttributes` bitmask including `QUARANTINED = 0x4`, `WITHIN_FOREST = 0x20`, `PIM_TRUST = 0x200`; SID filtering rules per trust type; `DRSAddSidHistory` (opnum 20).
- [`00-overview/03-domains-forests-trees.md`](../docs/00-overview/03-domains-forests-trees.md) — Forest root Enterprise Admins SID (`S-1-5-21-<forest-root-domain-sid>-519`); within-forest trust transitivity and sIDHistory passthrough.

**Open questions**:

- Drop sIDHistory entirely (use only current SIDs)? Per-trust filtering policy?

**Cross-capability impact**:

- Affects: PC-124 (sIDHistory migration via `DRSAddSidHistory`), PC-126 (client switchover depends on sIDHistory for resource access continuity), PC-028 (cross-realm TGT referral preserves sIDHistory in PAC).
- Affected by: PC-117 (DCSync is the typical path to obtain Domain Admin), PC-014 (FSMO roles — Infrastructure Master updates cross-domain references including sIDHistory).

---

### PC-121 — Selective authentication (`Allowed to Authenticate` ACE) is per-resource; rarely used

**Capability**: Security
**Severity**: medium
**STRIDE**: Elevation of privilege
**Cross-platform**: cross-platform

**Problem statement**:

Cross-forest trust with the `TRUST_ATTRIBUTE_CROSS_ORGANIZATION` flag (0x10) enables "selective authentication" mode. In this mode, users from the trusted forest cannot authenticate to any resource in the trusting forest unless explicitly granted the "Allowed to Authenticate" extended right (controlAccessRight GUID `68b1d179-0d15-4d4f-ab71-46152e79a7bc`) on the resource computer object per [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md).

Without the ACE, a cross-trust user's TGS-REQ to the resource fails with `KRB_ERR_GENERIC` (or the SMB layer returns `STATUS_ACCESS_DENIED`). The resource server logs `LSA` event 4662 with `Accesses: Allowed to Authenticate` failed. The mechanism is sound — it provides per-resource access control across a forest trust, the most granular possible control.

The problem is operational: the ACE must be set on every resource computer object that should be accessible to the foreign user. For a 1000-server farm, that's 1000 ACE operations. For a dynamic environment where servers are added/removed daily, the ACEs are constantly out of sync. Most organisations either: (a) skip selective authentication entirely and use a full-trust model (which exposes all resources to all foreign users), or (b) deploy selective authentication and then over-grant the ACE to avoid the operational pain (defeating the purpose).

FreeIPA's HBAC (Host-Based Access Control) provides a more usable alternative: server-side evaluation of `(user, host, service)` triples against a rule set, with no per-resource ACE needed. The rule set is managed centrally. HBAC is evaluated by SSSD on each host at login time. A similar model could be applied to AD trusts: a central rule set replaces per-resource ACEs.

The framework gap: the framework should provide a more usable selective-auth model. Options: (a) per-OU selective auth (apply the ACE to an OU, inherit to all child computer objects — requires framework-level ACL inheritance, which AD supports but is fragile), (b) per-host-group selective auth (apply the ACE to a group of computers — requires the framework to materialise the ACE on each member), (c) HBAC-style server-side evaluation (the framework's client SDK on each resource host evaluates a central rule set at AP-REQ time).

**Impact**:

Selective auth is operationally painful; orgs use full-trust instead, exposing all resources to all foreign users. Compromise of a foreign user → access to all resources in the trusting forest.

**Constraints**:

- Must support `Allowed to Authenticate` ACE for AD-interop.
- Must consider HBAC-style server-side evaluation as a modern alternative.
- Must support per-OU and per-host-group ACE inheritance.
- Must audit cross-trust authentication failures (Event 4662 with `Allowed to Authenticate` failed).

**Attack vector**:

(This threat is a usability gap, not a direct attack. The attack enabled by the gap is:)

1. Organisation sets up a cross-forest trust without selective authentication (because the ACE burden is too high).
2. All resources in the trusting forest are accessible to all users in the trusted forest.
3. Attacker compromises a user in the trusted forest (via Kerberoasting PC-116, phishing, etc.).
4. Attacker accesses any resource in the trusting forest — file shares, databases, administrative interfaces — using the compromised user's cross-trust TGT.

**Known mitigations in AD**:

- `TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10` on the trust object enables selective authentication.
- Per-resource ACE: `dsacls \\corp.example.com\CN=SERVER01,OU=Servers,DC=corp,DC=example,DC=com /G "CORP\jdoe:CA;Allowed to Authenticate"`.
- OU-level inheritance: set the ACE on the OU with inheritance; child computer objects inherit. Requires the OU's SD to permit inheritance (default).
- Microsoft Defender for Identity flags cross-trust authentication anomalies.

**Cross-platform considerations**:

- **Windows**: AD-interop requires preserving the per-resource ACE model. The framework's DC must honour the ACE check on every TGS-REQ for cross-trust users.
- **macOS**: Mac clients cannot evaluate the ACE locally; the framework's DC must enforce.
- **Linux**: Samba AD-DC honours the ACE; FreeIPA uses HBAC (different model, more usable).
- **Cross-platform consistency**: The framework should support both models (per-resource ACE for AD-interop; HBAC-style for new deployments) with a clear migration path.

**KB references**:

- [`03-directory-schema/04-trusts-topology.md`](../docs/03-directory-schema/04-trusts-topology.md) — `TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10`, `Allowed to Authenticate` extended-right GUID, per-resource ACE example via `dsacls`.

**Open questions**:

- Per-OU selective auth? FreeIPA HBAC-style server-side evaluation?

**Cross-capability impact**:

- Affects: PC-053 (Policy Engine's access-control model overlaps with selective auth), PC-126 (client switchover during migration may need selective auth for partial migration).
- Affected by: PC-028 (cross-realm TGT referral is the mechanism that brings foreign users into the resource domain).

---

### PC-122 — AdminSDHolder + SDPROP (every 60 min) can override intended ACLs

**Capability**: Security
**Severity**: medium
**STRIDE**: Tampering, Elevation of privilege
**Cross-platform**: cross-platform

**Problem statement**:

The `AdminSDHolder` object at `CN=AdminSDHolder,CN=System,DC=<domain>,DC=...` holds a security descriptor template that the Security Descriptor Propagator (SDPROP) thread in LSASS applies to all "protected" objects every 60 minutes by default per [`00-overview/05-glossary.md`](../docs/00-overview/05-glossary.md) and [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md). Protected objects are members of the privileged groups: Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, Server Operators, Print Operators, DNS Admins, and a handful of others (full list in MS-ADTS §6.1.1.6.1). The propagation sets the object's `nTSecurityDescriptor` to match the AdminSDHolder template, including the DACL and ownership.

The operational consequence: any custom ACE placed on a protected object (e.g. a helpdesk group granted `Write Members` on Domain Admins for a delegated workflow) is silently reverted to the AdminSDHolder template within 60 minutes. The admin who placed the ACE is not notified; the next time the workflow runs, it fails with `Access Denied`. The fix is to modify the AdminSDHolder template itself, not the protected object — a non-obvious procedure (`dsacls "CN=AdminSDHolder,CN=System,DC=corp,DC=example,DC=com" /G "CORP\helpdesk:WP;member"`).

The security consequence: SDPROP also removes inheritance. Protected objects do not inherit ACEs from their parent OU. This breaks the standard "deny HelpDesk write to Domain Admins" pattern — the deny ACE on the parent OU never reaches the Domain Admins group. The only way to apply a deny to Domain Admins is to add it to the AdminSDHolder template. The template applies uniformly to all protected objects, so a deny on the template denies HelpDesk write to ALL protected groups (Domain Admins, Enterprise Admins, Schema Admins, etc.) which may not be the intent.

The framework gap: AdminSDHolder is an implicit, hard-to-discover mechanism. The framework should either (a) preserve AdminSDHolder semantics for AD-interop (with clear documentation that custom ACEs on protected groups will be reverted), or (b) replace with declarative RBAC — a central policy that defines which principals can modify which protected groups, evaluated at write-time rather than reverted every 60 minutes. The declarative model is more transparent and more testable.

**Impact**:

Custom ACEs on protected groups silently revert within 60 minutes. Admins who placed the ACE are not notified. Workflows that depend on the ACE fail mysteriously. Security: inheritance breaks on protected objects, making deny-ACE patterns ineffective.

**Constraints**:

- Must support AdminSDHolder template for AD-interop.
- Must support SDPROP-equivalent (periodic ACL propagation to protected objects).
- Must audit SDPROP reverts (Event 4662-equivalent with `Properties: nTSecurityDescriptor` and reason `AdminSDHolder revert`).
- Must log a warning when an admin places a custom ACE on a protected object (indicating it will be reverted).
- Must consider declarative RBAC as a modern alternative.

**Attack vector**:

(This threat is primarily a usability and audit gap. The indirect attack is:)

1. Admin grants HelpDesk `Write Members` on Domain Admins for a temporary workflow.
2. SDPROP reverts the ACE within 60 minutes. Admin does not notice.
3. Workflow fails. Admin "fixes" by granting HelpDesk a broader right (e.g. `Full Control` on the OU) to work around the revert.
4. HelpDesk now has Full Control on the OU, which inherits to all non-protected objects (workstations, services). HelpDesk member compromises a workstation, escalates to local SYSTEM, harvests cached credentials, escalates to Domain Admin via Pass-the-Hash.

OR:

1. Attacker (who has Domain Admin) wants to persist access.
2. Attacker modifies AdminSDHolder template to grant their own account `Full Control` on all protected objects.
3. SDPROP propagates the change to Domain Admins, Enterprise Admins, etc.
4. Attacker's account now has Full Control on all privileged groups. Even if the attacker's Domain Admin membership is removed, the AdminSDHolder-granted Full Control persists.
5. Detection requires auditing AdminSDHolder itself — a rarely-checked object.

**Known mitigations in AD**:

- Document the AdminSDHolder template prominently in admin training.
- Audit AdminSDHolder modifications: `dsacls "CN=AdminSDHolder,CN=System,DC=corp,DC=example,DC=com"` regularly, alert on changes.
- Microsoft's "Get-ADAdminSDHolder" community script dumps the current template.
- Use `dsacls /restore` to revert AdminSDHolder to a known-good baseline.
- Disable SDPROP temporarily (registry `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDProtectMode = 0` — not recommended, breaks protection).

**Cross-platform considerations**:

- **Windows**: AD-interop requires preserving AdminSDHolder semantics. The framework's DC must run SDPROP every 60 minutes.
- **macOS**: Not a DC platform; Mac clients are unaffected.
- **Linux**: Samba AD-DC implements SDPROP in `source4/dsdb/samdb/ldb_modules/samldb.c` (partial). FreeIPA does not have an equivalent — uses HBAC + sudo rules.
- **Cross-platform consistency**: The framework's AdminSDHolder equivalent must apply uniformly regardless of which platform hosts the DC.

**KB references**:

- [`00-overview/05-glossary.md`](../docs/00-overview/05-glossary.md) — AdminSDHolder glossary entry: "Object in the system container that holds the security descriptor template applied to protected groups (every 60 min by SDPROP)."
- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — SD table caching (`sdtable` in ESE), `nTSecurityDescriptor` column, `SCGetSDFromCache` lookup path that SDPROP modifies.

**Open questions**:

- Replace AdminSDHolder with declarative RBAC? Per-protected-group templates?

**Cross-capability impact**:

- Affects: PC-054 (Policy Engine's per-principal ACL pattern is undermined by AdminSDHolder reverts).
- Affected by: PC-008 (SD table caching is the storage layer AdminSDHolder modifies).

---

### PC-123 — Supply-chain risk: signed AD updates require WSUS trust

**Capability**: Security
**Severity**: medium
**STRIDE**: Tampering, Elevation of privilege
**Cross-platform**: cross-platform

**Problem statement**:

AD DCs receive security updates and feature updates via WSUS (Windows Server Update Services) or Microsoft Update. WSUS signs update packages with the Microsoft root certificate; the DC's Windows Update client (`wuaueng.dll`) verifies the signature before installing. The trust chain is: Microsoft root CA → Microsoft Update signing cert → update package signature. Compromise of WSUS = malicious updates pushed to all DCs in the org.

The threat is not theoretical. In 2021, the SolarWinds Sunburst attack demonstrated a software supply-chain compromise where the vendor's build pipeline was compromised, malicious code was signed with the vendor's legitimate signing cert, and the update was pushed to ~18,000 customers including US government agencies. The same attack pattern against Microsoft's update pipeline (or against a self-hosted WSUS server) would compromise every DC in the org.

The framework gap: the framework's binary distribution must support stronger supply-chain verification than AD's WSUS model. Options: (a) Sigstore (cosign) signing of framework binaries with ephemeral keys whose certificates are recorded in a transparency log (Rekor), (b) in-toto attestations documenting the build pipeline from source to binary, (c) reproducible builds allowing third-party verification that the published binary matches the source. The framework should also support a "deny-by-default" update policy: an update is installed only if its signature is in the configured allowlist AND the transparency log contains the signing event.

The cross-platform angle: WSUS is Windows-only. macOS DCs (theoretical) would receive updates via Apple Software Update, signed with Apple's root. Linux DCs would receive updates via the distro's package manager (apt, dnf, zypper), signed with the distro's GPG key. Each platform has its own supply-chain trust model. The framework must define a unified update-verification policy that applies across platforms, with per-platform signing roots but a single framework-level verification step.

**Impact**:

WSUS compromise = DC supply-chain attack = full forest compromise via malicious code execution on every DC. SolarWinds-scale incident. Detection is hard because the malicious code is signed with a legitimate cert.

**Constraints**:

- Must support signed updates (binary signature verification before install).
- Must support reproducible builds (third-party can verify binary matches source).
- Must support a transparency log (Rekor-style) for signing events.
- Must support a deny-by-default update policy (only allowlisted signatures install).
- Must work cross-platform (Windows: Authenticode; macOS: codesign; Linux: package-manager GPG).

**Attack vector**:

1. Attacker compromises the WSUS infrastructure (either Microsoft's WSUS upstream, or the org's self-hosted WSUS server).
2. Attacker packages a malicious update (e.g. a Trojaned `lsass.exe` patch that exfiltrates password hashes) and signs it with the compromised WSUS signing cert.
3. The DC's Windows Update client receives the malicious update, verifies the signature (passes — attacker's cert is valid), and installs.
4. The Trojaned `lsass.exe` runs on every DC. On each password-change event, it exfiltrates the new hash to attacker C2.
5. Attacker collects hashes passively for weeks/months. Detects Domain Admin password change → DCSync using the harvested DA hash → full forest compromise.

OR (SolarWinds pattern):

1. Attacker compromises the framework's build pipeline (CI/CD).
2. Attacker injects malicious code into a framework release.
3. The malicious release is signed with the framework's legitimate signing cert (because the CI/CD pipeline has signing access).
4. Customers install the signed release via the framework's update mechanism. Signature verification passes (cert is valid).
5. Malicious code runs on every framework DC. (See step 4 above for impact.)

**Known mitigations in AD**:

- WSUS signing cert is Microsoft-controlled; trust model is "trust Microsoft". No transparency log.
- Microsoft's Source Code Integrity (since 2023) requires code-signing transparency for some Windows components, but not all.
- Windows Defender Application Control (WDAC) can restrict which binaries run on a DC, but the policy is hard to author and DCs typically run with permissive WDAC.
- Microsoft's Secure Supply Chain (S2C2F) framework recommends: dependency verification, build-pipeline isolation, signing-key HSM storage, reproducible builds. Most orgs do not implement S2C2F.

**Cross-platform considerations**:

- **Windows**: Authenticode signing; WSUS distribution.
- **macOS**: `codesign` with Apple Developer ID; notarisation service; Gatekeeper enforcement.
- **Linux**: GPG-signed packages via apt/dnf/zypper; reproducible-builds project for Debian; Fedora CoreOS uses container-image signing.
- **Cross-platform consistency**: The framework's update policy must verify signatures using the platform-native mechanism (Authenticode/codesign/GPG) AND apply a framework-level allowlist (Sigstore + Rekor) on top.

**KB references**:

- [`01-ad-core/01-ad-ds-internals.md`](../docs/01-ad-core/01-ad-ds-internals.md) — LSASS process model, DLL loading (`ntdsa.dll`, `kdcsvc.dll`, `esent.dll`), boot sequence — these are the binaries that must be supply-chain-verified.

**Open questions**:

- Sigstore (cosign) for framework binaries? In-toto attestations?

**Cross-capability impact**:

- Affects: PC-109 (containerised deployment must include image-signing verification), PC-110 (DR restores must verify binary signatures).
- Affected by: PC-007 (storage engine choice — RocksDB/FoundationDB are open-source and reproducible-build-friendly; ESE is closed-source).

---

## Cross-capability impact

Security is the most cross-cutting capability: every other capability's design must be reviewed against the threat model. Key cross-capability impacts:

- **Core Directory (PC-001 through PC-022)**: DRSUAPI surface is the DCSync vector (PC-117); SD table is the AdminSDHolder storage (PC-122); schema extensions can introduce new attack surfaces.
- **KDC (PC-023 through PC-035)**: krbtgt rotation is the golden-ticket mitigation (PC-118); etype policy is the Kerberoasting mitigation (PC-116); PAC generation is the silver-ticket mitigation (PC-119); gMSA key distribution is the service-account hardening path (PC-035).
- **Auth Provider (PC-036 through PC-042)**: NTLM relay and Pass-the-Hash threats overlap with the security catalog (PC-038 NTLM PtH).
- **Policy Engine (PC-043 through PC-056)**: GPO itself is a tampering vector if SYSVOL is writable by attackers; AdminSDHolder interactions (PC-122).
- **Cert Service (PC-057 through PC-067)**: CA key compromise = forest compromise; `NTAuthCertificates` is a high-value target.
- **Federation Gateway (PC-068 through PC-077)**: Token-signing cert compromise = federation-wide impersonation.
- **File Gateway (PC-078 through PC-084)**: SYSVOL tampering = GPO tampering = DC compromise; PrintNightmare (CVE-2021-34527) is a known SMB-print-spooler attack.
- **Client SDK (PC-085 through PC-093)**: Client-side credential caching (ccache, keytab) is a PtH vector if not protected.
- **Cross-Platform Parity (PC-094 through PC-105)**: Heimdal macOS fork lacks Server 2016 PAC features (PC-119 mitigation gap); SSSD lacks per-event audit (PC-111).
- **Operations (PC-106 through PC-115)**: Audit pipeline (PC-111) is the detection layer for every security threat.
- **Migration (PC-124 through PC-130)**: sIDHistory migration (PC-124) directly enables the sIDHistory abuse attack (PC-120); parallel-run trust (PC-126) is a temporary attack surface.

## Open research questions specific to Security

- Should the framework auto-detect Kerberoast attempts via 4769 events with etype 0x17, or rely on SIEM rules?
- Should the framework force-migrate service accounts to AES on next password rotation, or allow RC4 indefinitely for compat?
- Should `DS-Replication-Get-Changes-All` be audited per-principal or aggregate?
- Should the framework offer a break-glass replication mechanism via HSM-bound key (replication cannot occur without HSM presence)?
- Should the krbtgt key be HSM-bound by default?
- Should the framework auto-rotate krbtgt every N days, or require explicit operator action?
- Should the framework default-validate `PAC_BUFFER_TICKET_CHECKSUM` on every service (perf cost), or opt-in per service?
- Is token-binding (TLS exporter) a viable alternative to PAC validation?
- Should the framework drop `sIDHistory` entirely and use only current SIDs (claims-based migration)?
- Should sIDHistory filtering policy be per-trust or forest-wide?
- Should the framework support per-OU selective auth, or adopt HBAC-style server-side evaluation?
- Should AdminSDHolder be replaced with declarative RBAC, or preserved for AD-interop?
- Should the framework support per-protected-group templates (different SD for Domain Admins vs Enterprise Admins)?
- Should the framework adopt Sigstore (cosign) for binary signing, or stick with platform-native Authenticode/codesign/GPG?
- Should the framework adopt in-toto attestations for build-pipeline verification?
