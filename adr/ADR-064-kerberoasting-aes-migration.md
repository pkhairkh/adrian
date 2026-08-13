---
title: "ADR-064: Kerberoasting Mitigation — AES-Only Migration + Detection"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-116
severity: blocker
tags: [adr, security, kerberoasting, aes, gmsa, detection, mitre-t1558-003]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/11-code-examples/05-python-impacket-examples.md
  - ./ADR-060-structured-audit-logs-otel.md
  - ./ADR-065-krbtgt-hsm-rotation.md
last_updated: 2026-08-13
---

# ADR-064: Kerberoasting Mitigation — AES-Only Migration + Detection

## Status

Accepted — 2026-08-13

## Context

Any authenticated domain user can request a TGS service ticket for any SPN-registered service account in the domain. The KDC, on receiving a TGS-REQ for `cifs/file01.example.com@EXAMPLE.COM`, looks up the SPN, finds the owning service account, retrieves the account's long-term key (NTLM hash for RC4, AES key for AES etypes), and encrypts the resulting Ticket's `enc-part` (the `EncTicketPart` structure containing the session key, client identity, PAC, and validity window) with that long-term key per RFC 4120 §5.3 and MS-KILE.

The attack: an attacker who has any domain user account (often obtained via phishing or spray) runs `GetUserSPNs.py -request` (impacket) or `Rubeus kerberoast` to enumerate all SPN-bearing accounts in the domain via an LDAP query for `(servicePrincipalName=*)`, then requests a TGS for each SPN. The returned tickets are saved. For accounts whose `msDS-SupportedEncryptionTypes` permits RC4-HMAC (etype 0x17) — or, more commonly, accounts where the KDC falls back to RC4 because the attribute is unset — the Ticket's `enc-part` is encrypted with the NTLM hash (MD4 of the password) as the key. The attacker then performs offline brute-force or dictionary attack on the encrypted ticket using `hashcat -m 13100` (RC4-HMAC TGS) — modern GPUs compute 10⁸-10⁹ guesses/sec against RC4-HMAC. A weak service-account password (`Summer2024!`, `Welcome1`) cracks in seconds to minutes.

AES-encrypted tickets (etype 0x12, AES-256-CTS-HMAC-SHA1-96) are also brute-forceable but the PBKDF2 key derivation (4096 iterations of HMAC-SHA1 per RFC 3962) slows the attack by ~10⁵×, making AES-encrypted tickets with 25+ char random passwords effectively uncrackable. The mitigation hierarchy in AD: (1) gMSA (Group Managed Service Accounts) with 240-char random passwords managed by the KDS root key, (2) AES-only etypes enforced via `msDS-SupportedEncryptionTypes = 0x30` (AES128|AES256) and domain policy `Network security: Configure encryption types allowed for Kerberos` set to disable RC4, (3) long random service-account passwords (>25 chars). Most AD deployments have legacy service accounts with weak passwords and RC4 still enabled — Kerberoasting is the #1 AD attack vector.

The framework's KDC must enforce AES-only etypes by default, must support gMSA with KDS root key rotation, must detect Kerberoast attempts (TGS-REQ storm or RC4-etype usage), and must force-migrate legacy service accounts to AES on next password rotation.

## Threat model

**STRIDE classification**: Information disclosure, Elevation of privilege

**Attack vector** (step-by-step):
1. Attacker obtains any domain user credentials (phishing, password spray, OSINT, OS credential dumping on a workstation).
2. Attacker runs `GetUserSPNs.py corp.example.com/jsmith:'P@ss!' -dc-ip dc01 -request` to enumerate SPN-bearing accounts and request TGS for each.
3. impacket issues an LDAP query `(servicePrincipalName=*)` to enumerate SPNs.
4. For each SPN, impacket issues a TGS-REQ to the KDC with `sname = <SPN>@REALM`. The KDC obliges — no SPN-ownership check on the requester.
5. The TGS-REP contains a `Ticket` encrypted with the service account's long-term key. The attacker saves each ticket.
6. Offline: attacker runs `hashcat -m 13100 hashes.txt rockyou.txt` — RC4-HMAC TGS hashes crack at 10⁸/sec on a modern GPU; AES-256-HMAC TGS hashes crack at ~10³/sec.
7. Cracked password gives the attacker the service account's credentials. Attacker impersonates the service account, escalates via the account's group memberships (often Domain Admins or local admin on multiple hosts).

**Known mitigations in AD**:
- `Network security: Configure encryption types allowed for Kerberos` GPO → set to "AES128_HMAC_SHA1 + AES256_HMAC_SHA1 + Future" (no RC4). Requires all service accounts to support AES (`msDS-SupportedEncryptionTypes` bitmask including 0x10 or 0x20).
- gMSA (Group Managed Service Account): `New-ADServiceAccount -Name svc-web -DNSHostName web.example.com -KerberosEncryptionType AES256`. The KDS root key (`Add-KdsRootKey -EffectiveImmediately`) generates a 240-char random password rotated every 30 days.
- Service-account password length enforcement: AD has no built-in per-OU password policy for service accounts; must use Fine-Grained Password Policy (`New-ADFineGrainedPasswordPolicy`) targeting the service-accounts OU.
- Detection: Event 4769 (TGS-REQ) with `Ticket Encryption Type: 0x17` (RC4-HMAC) is the smoking gun. SIEM rule: alert on >5 unique SPNs requested by one user in 5 minutes.

**Residual risk in AD**:
- RC4 fallback when `msDS-SupportedEncryptionTypes` is unset on a service account — KDC defaults to RC4-HMAC for backward compat.
- Legacy applications that do not support AES (e.g. older Java apps with JCE unlimited-strength not installed) force operators to keep RC4 enabled.
- gMSA requires Server 2012+ DCs and Server 2012+ member servers; pre-2012 servers cannot use gMSA.
- No automatic detection of Kerberoast attempts — relies on SIEM rules that most orgs do not configure.
- No automatic migration of legacy service accounts to AES — operators must manually rotate passwords and update `msDS-SupportedEncryptionTypes`.

## Decision

The framework's KDC defaults to AES-only etypes (no RC4 fallback) for all service-ticket issuance. Every service account must declare `msDS-SupportedEncryptionTypes`; if the attribute is unset, the KDC refuses to issue a TGS for that SPN and emits an audit event flagging the account for migration. The framework provides a one-shot migration tool (`adrian-cli migrate-aes`) that rotates the service-account password to a 256-bit random value, sets `msDS-SupportedEncryptionTypes = 0x30` (AES128 | AES256), and updates the service's keytab. gMSA is the recommended service-account type for new deployments; the framework's KDS root key auto-rotates every 30 days and generates 240-char random passwords.

Detection: the audit pipeline (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)) emits an OTel log record for every TGS-REQ with attributes `adrian.kerberos.etype`, `adrian.kerberos.spn`, `adrian.kerberos.client.dn`. The framework ships default detection rules in the audit pipeline: (a) alert on any TGS-REQ with etype 0x17 (RC4-HMAC) — this is a strong signal that a legacy account is being targeted or that an attacker is forcing RC4 fallback; (b) alert on >5 unique SPNs requested by one user in 5 minutes (Kerberoast storm); (c) alert on TGS-REQ for an SPN whose owning account has a password older than 365 days (stale service account).

The framework's KDC also supports an opt-in "strict AES" mode where any TGS-REQ that cannot be satisfied with AES (because the service account does not support AES) is rejected with `KDC_ERR_ETYPE_NOTSUPP (18)`. This is the default for new deployments; AD-interop scenarios may disable strict mode to allow RC4 fallback during migration.

**Concrete specification**:

- The framework's KDC MUST default to AES-only etypes for service-ticket issuance: `aes256-cts-hmac-sha1-96` (etype 0x12) preferred, `aes128-cts-hmac-sha1-96` (etype 0x11) as fallback. RC4-HMAC (etype 0x17) MUST NOT be used by default.
- The KDC MUST refuse to issue a TGS for an SPN whose owning account has `msDS-SupportedEncryptionTypes` unset; the KDC MUST return `KDC_ERR_ETYPE_NOTSUPP (18)` and emit an audit event `adrian.kerberos.tgs.req.etype_unsupported` with MITRE ATT&CK T1558.003.
- The KDC MUST support an opt-in `strictAes` mode (configurable per realm) where RC4 etype is rejected even if the service account requests it.
- The KDC MUST support gMSA: `New-ADServiceAccount`-equivalent CLI (`adrian-cli service-account create --gmsa`) creates a gMSA with a 240-char random password generated by the KDS root key.
- The KDS root key MUST auto-rotate every 30 days (configurable); the rotation is logged as an audit event.
- The framework MUST ship a migration tool `adrian-cli migrate-aes` that:
  1. Enumerates all service accounts with SPNs (`ldapsearch "(servicePrincipalName=*)"`).
  2. For each account, checks `msDS-SupportedEncryptionTypes`; if unset or RC4-only, flags for migration.
  3. For each flagged account, generates a 256-bit random password, sets it via `set-password` operation, sets `msDS-SupportedEncryptionTypes = 0x30`, exports a new keytab to a configurable path.
  4. Emits an audit event `adrian.migration.aes.account_migrated` per account.
- The audit pipeline MUST emit an OTel log record for every TGS-REQ with attributes `adrian.kerberos.etype`, `adrian.kerberos.spn`, `adrian.kerberos.client.dn`, `adrian.kerberos.client.ip`, `adrian.kerberos.result.code`, and MITRE ATT&CK T1558.003 when etype is RC4.
- The audit pipeline MUST ship default detection rules:
  - Rule 1: TGS-REQ with etype 0x17 (RC4-HMAC) → alert severity "high".
  - Rule 2: >5 unique SPNs requested by one user in 5 minutes → alert severity "high" with MITRE T1558.003.
  - Rule 3: TGS-REQ for an SPN whose owning account has a password older than 365 days → alert severity "medium".
- The audit pipeline MUST emit a Prometheus metric `adrian_kerberos_tgs_req_total{etype,result,spn_class}` (per [ADR-057](./ADR-057-prometheus-otel-observability.md)) where `spn_class` is `gmsa`, `user`, `machine`, or `legacy`.
- For AD-interop scenarios, the framework's KDC MAY issue RC4 TGS for service accounts that explicitly request RC4 (via `msDS-SupportedEncryptionTypes` bitmask including 0x04); this requires per-account opt-in.
- The framework MUST document the RC4 deprecation timeline: RC4 is deprecated as of framework v1, RC4 support is removed in framework v2 (1 year after v1 release).

## Rationale

AES-only is the modern Kerberos standard. RFC 6649 (deprecated RC4 in Kerberos) and RFC 8429 (deprecated RC4 and DES) establish that RC4 must not be used. AD's continued RC4 support is a backward-compat artefact; the framework does not need to repeat this mistake. The PBKDF2 key derivation in AES (RFC 3962, 4096 iterations) slows offline brute-force by 10⁵× compared to RC4's direct MD4 hash — making AES-encrypted tickets effectively uncrackable with 25+ char random passwords.

gMSA as the default for new service accounts eliminates the password-management problem entirely. The KDS root key generates and rotates the password; the service account never knows the password (it retrieves the password via a DRSUAPI call at startup, encrypted with the machine account's key). The framework cannot improve on gMSA's design; it can only make it the default and automate the migration from legacy service accounts.

Detection is the second layer of defense. Even with AES-only enforced, an attacker may attempt Kerberoasting against any account they suspect has a weak password (gMSA accounts are immune because their passwords are 240 chars of random data, but legacy accounts with AES-set but weak passwords may still be vulnerable). The audit pipeline's TGS-REQ stream with etype attribute enables detection of Kerberoast storms and individual RC4 attempts.

The migration tool is necessary because operators cannot manually migrate hundreds of service accounts. The tool automates password rotation, etype update, and keytab export. The migration is reversible (the tool records the previous password hash for rollback) but the rollback path is intentionally difficult (requires explicit `--force-rollback` flag and an audit event) to discourage permanent RC4 usage.

The RC4 deprecation timeline (1 year from v1 to v2) is aggressive but necessary. organisations need a deadline to migrate; without one, RC4 lingers for years. The framework's audit pipeline alerts on RC4 usage, providing visibility into the migration progress.

## Consequences

**Positive**: Kerberoasting against RC4-encrypted tickets is eliminated by default. Kerberoasting against AES-encrypted tickets is computationally infeasible for 25+ char random passwords (gMSA's 240-char passwords are immune). Detection of Kerberoast attempts is automatic via the audit pipeline. Migration of legacy service accounts is one CLI command. MITRE ATT&CK T1558.003 mapping is automatic in audit events.

**Negative**: Legacy applications that do not support AES (older Java apps, legacy appliances) break in strict-AES mode. organisations must migrate these applications before deploying the framework. The migration tool's password rotation may break services that cache the old password (e.g. services that read the password from a config file rather than using a keytab). The RC4 deprecation timeline (1 year) is aggressive for some organisations.

**Neutral**: The framework's strict-AES mode does not preclude AD-interop scenarios where the framework's DC participates in an AD forest with RC4-enabled service accounts; the framework's DC issues RC4 TGS for those accounts if explicitly opted in per-account. The default is no RC4, but the framework can interop with RC4-using AD forests.

**Implementation cost**: ~2 person-months for the KDC etype policy and strict-AES mode; ~2 person-months for the gMSA implementation (KDS root key rotation, password generation, DRSUAPI distribution); ~2 person-months for the migration tool; ~1 person-month for the audit detection rules. Total: ~7 person-months for v1.

**Operational impact**: Operators run `adrian-cli migrate-aes` once during AD-to-framework migration; the tool flags accounts that cannot be migrated (e.g. applications with hardcoded passwords). SOC analysts see Kerberoast alerts in their SIEM with MITRE ATT&CK T1558.003 tags. SREs monitor `adrian_kerberos_tgs_req_total{etype="0x17"}` for residual RC4 usage (should trend to zero).

## Alternatives Considered

**Alternative A: Keep RC4 enabled, rely on long passwords.** Allow RC4 etype but require 25+ char passwords for all service accounts. Rejected because (a) RC4 password brute-force at 10⁸/sec means even 25-char passwords are vulnerable if not truly random (dictionary attacks with mutation rules succeed against human-chosen 25-char passwords), (b) RC4 is deprecated by RFC 6649 and RFC 8429; supporting it indefinitely is technically untenable, (c) operators cannot enforce 25+ char passwords reliably (Fine-Grained Password Policy is hard to configure in AD; the framework can do better but the underlying problem of human-chosen passwords remains).

**Alternative B: Eliminate SPN-based Kerberos entirely; use only PKINIT.** Replace long-term-key-based service tickets with public-key-based service tickets (PKINIT, RFC 4556). Rejected for v1 because (a) PKINIT for service tickets is not standardised (PKINIT is for AS-REQ, not TGS-REQ), (b) it requires a PKI for every service account, adding a dependency on the deferred federation layer (ORQ-132/133/134) and the Cert Service (ORQ-110/111), (c) it breaks AD-interop entirely. PKINIT for AS-REQ is supported as an optional pre-auth method (per the deferred KDC implementation decision, ORQ-042/043/044).

**Alternative C: Per-SPN ownership check.** Require the TGS-REQ requester to be the owner of the SPN (or a delegated principal). Rejected because (a) this breaks legitimate use cases (any user can legitimately request a TGS for any SPN — that is how Kerberos works), (b) it does not prevent Kerberoasting (the attacker is the requester; the check would have to be "is the requester a known bad actor?" which is a different problem), (c) it would require a major protocol change that breaks AD-interop.

## Open Questions

None — this is an ADR-ELIGIBLE decision. The KDC implementation choice (PC-023 / Tier-1 ORQ-042/043/044) does not gate this decision: the etype policy and the gMSA support are stable regardless of whether the KDC is MIT krb5-based, Heimdal-based, or fresh implementation.

## Cross-capability impact

- **KDC (PC-023 through PC-035)**: KDC etype policy (PC-024) is enforced by this ADR; gMSA key distribution (PC-035) is implemented.
- **KDC (PC-030)**: krbtgt rotation (ADR-065 for golden-ticket mitigation) uses the same auto-rotation mechanism as the KDS root key.
- **Auth Provider (PC-036 through PC-042)**: NTLM relay (PC-038) and Pass-the-Hash (PC-039) are related attacks on the auth provider; the audit pipeline detection rules in this ADR are extended by ADR-060 to cover those.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_kerberos_tgs_req_total{etype}` is the key Prometheus metric for Kerberoast detection.
- **Operations (PC-111)**: ADR-060 (audit logs) — the TGS-REQ audit events are emitted via the audit pipeline.
- **Security (PC-117)**: DCSync (PC-117, deferred) is often the post-Kerberoast escalation; the audit pipeline detection rules in this ADR are complemented by DCSync detection rules in PC-117.
- **Security (PC-118)**: Golden ticket (ADR-065) is mitigated by krbtgt rotation; Kerberoasting is the typical path to obtain a service-account hash that may be the krbtgt hash (via DCSync).
- **Migration (PC-127)**: Password hash migration (PC-127, deferred) must preserve the etype policy — migrated service accounts must have AES etypes set.

## References

- [PC-116](../catalog/11-security-threat-model.md) — problem statement (Kerberoasting is the dominant AD attack)
- [AD overview](../docs/00-overview/01-active-directory-overview.md) — Threat-model notes listing Kerberoasting as the #1 AD attack with the gMSA + AES mitigation
- [Kerberos internals](../docs/02-protocols/01-kerberos-internals.md) — Kerberos enctype table (etype 0x17 RC4-HMAC vs 0x12 AES-256), PA-ENC-TIMESTAMP pre-auth, TGS-REQ/TGS-REP message structure
- [Python impacket examples](../docs/11-code-examples/05-python-impacket-examples.md) — `GetUserSPNs.py` programmatic recipe
- [RFC 4120 — Kerberos Network Authentication Service](https://datatracker.ietf.org/doc/html/rfc4120) (§5.3 for Ticket encryption; §7.5 for etype selection)
- [RFC 3962 — AES Encryption for Kerberos 5](https://datatracker.ietf.org/doc/html/rfc3962) (PBKDF2 key derivation)
- [RFC 6649 — Deprecate DES, RC4-HMAC-EXP, and Other Weak Cryptographic Algorithms in Kerberos](https://datatracker.ietf.org/doc/html/rfc6649)
- [RFC 8429 — Deprecate Triple-DES (3DES) and RC4 in Kerberos](https://datatracker.ietf.org/doc/html/rfc8429)
- [MS-KILE — Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/) (`msDS-SupportedEncryptionTypes` semantics)
- [MITRE ATT&CK T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
