---
title: "ADR-065: HSM-Bound krbtgt + Auto-Rotation for Golden-Ticket Mitigation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Security
problem: PC-118
severity: blocker
tags: [adr, security, golden-ticket, krbtgt, hsm, rotation, mitre-t1558-001, defense-in-depth]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/11-security-threat-model.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ./ADR-060-structured-audit-logs-otel.md
  - ./ADR-064-kerberoasting-aes-migration.md
last_updated: 2026-08-13
---

# ADR-065: HSM-Bound krbtgt + Auto-Rotation for Golden-Ticket Mitigation

## Status

Accepted — 2026-08-13

## Context

The `krbtgt` account in every AD domain holds the long-term key used to sign and encrypt TGTs (Ticket-Granting Tickets). The KDC, on receiving an AS-REQ, retrieves the `krbtgt` account's NTLM hash (for RC4) or AES key (for AES) and uses it to encrypt the `EncTicketPart` of the returned TGT per RFC 4120 §5.3. The KDC also signs the PAC inside the TGT with the krbtgt key (`PAC_SIGNATURE_DATA` type 0x07). Every TGS-REQ that follows uses the TGT as the credential; the KDC decrypts the TGT with the krbtgt key, validates the PAC signature, and issues a service ticket. The krbtgt key is also used to sign the `PAC_BUFFER_TICKET_CHECKSUM` (Server 2016+) over the entire Ticket.enc-part.

The attack: an attacker who has the krbtgt hash (typically obtained via DCSync, PC-117) can forge TGTs locally without contacting the KDC. `ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-... -domain CORP.EXAMPLE.COM -user-id 500 Administrator` (impacket) produces a forged TGT claiming to be `Administrator` with arbitrary group memberships, arbitrary validity period (up to 10 years by default), and the correct PAC signatures. The attacker injects the forged TGT into their Kerberos ccache and uses it to request service tickets via TGS-REQ. The KDC, decrypting the TGT with the krbtgt key, validates everything and issues service tickets as if the attacker were genuinely Administrator.

Detection is hard because the forged TGT is cryptographically valid — the KDC cannot distinguish it from a real one. The only mitigation is krbtgt password rotation: when the krbtgt password is changed, the KDC's krbtgt key changes. Old TGTs (encrypted with the old key) fail decryption. AD keeps the previous krbtgt key for a grace period (typically the TGT lifetime, 10 hours) so in-flight TGTs continue to work; after the grace period, all old TGTs are invalid. Microsoft's incident-response guidance (KB 3011620) recommends rotating krbtgt **twice** with a gap equal to the maximum TGT lifetime — this ensures any old-key TGT has expired before the second rotation removes the old key entirely.

The framework gap: krbtgt rotation in AD is a manual `Set-ADAccountPassword krbtgt` operation that requires careful sequencing (rotate, wait, rotate again). The framework should make this a one-click operation with built-in grace-period management, automatic monitoring for old-key TGT usage (a strong indicator of golden ticket activity), and HSM-bound krbtgt key option to make extraction impossible. This decision is the same as ADR-015 (PC-030) from a different problem framing; this ADR encodes the security-impact angle.

## Threat model

**STRIDE classification**: Spoofing, Elevation of privilege

**Attack vector** (step-by-step):
1. Attacker obtains the krbtgt hash via DCSync (PC-117) — needs Domain Admin or DC compromise (or a principal granted `DS-Replication-Get-Changes-All`).
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
- HSM-bound krbtgt: not natively supported in AD; requires third-party KSP (Key Storage Provider) integration.
- Automatic rotation: AD has no built-in auto-rotation; orgs use scheduled tasks or Microsoft's `Reset-KrbtgtAccountPassword.ps1` script.

**Residual risk in AD**:
- Manual rotation is operator-dependent; orgs rotate krbtgt once a year at best, leaving the window for golden-ticket attacks at 365+ days.
- HSM-bound krbtgt is not native; the krbtgt key is in `ntds.dit` and can be extracted via DCSync.
- No automatic monitoring for old-key TGT usage; relies on SIEM rules that most orgs do not configure.
- No graceful dual-krbtgt mode; rotation is disruptive (in-flight TGTs fail during the grace period if the operator does not sequence correctly).

## Decision

The framework binds the krbtgt account's key material to an HSM (Hardware Security Module) by default. The krbtgt key is generated inside the HSM via PKCS#11 `C_GenerateKeyPair` or `C_GenerateRandom` and never leaves the HSM in plaintext. The KDC, on AS-REQ, calls PKCS#11 `C_EncryptInit` / `C_Encrypt` / `C_SignInit` / `C_Sign` to perform TGT encryption and PAC signature — the key is used in the HSM, never exposed to the KDC process memory. This makes the krbtgt key extraction impossible via DCSync or memory dumping (the key is not in `ntds.dit` or LSASS memory; only the HSM's key reference is stored, and that reference is useless without the HSM).

The framework's operator auto-rotates the krbtgt key every 30 days (configurable; high-security: 7 days) with a 2-key overlap window during rollover: the new key is generated in the HSM, the KDC is configured to accept both the old and new keys for TGT decryption for one TGT-lifetime (default 10 hours), after which the old key is destroyed. The rotation is one operator invocation (`adrian-cli operator rotate-krbtgt`) or fully automatic per the configured schedule. Old-key TGT usage during the overlap window is logged as an audit event; old-key TGT usage after the overlap window is a strong indicator of golden-ticket activity and triggers a critical alert.

For AD-interop scenarios where the framework's DC participates in an AD forest, the krbtgt key must be shared with AD DCs (which do not have HSM support). In this case, the framework's DC exports the krbtgt key to a one-time-use encrypted blob (encrypted with the AD DC's machine account key) and sends it via DRSUAPI `EXOP_REPL_SECRETS`. The framework's DC retains the HSM-bound key as the master; the AD DC holds a derived key (the framework re-encrypts the key with the AD DC's machine account key as a wrapper).

**Concrete specification**:

- The framework's KDC MUST use an HSM for all krbtgt key operations: encryption of `EncTicketPart`, signing of `PAC_SIGNATURE_DATA` (type 0x07), signing of `PAC_BUFFER_TICKET_CHECKSUM` (type 0x0E, per PC-119).
- The HSM MUST be accessed via PKCS#11 (v3.0+) or KMIP 1.4 (interoperability standards). SoftHSM2 is acceptable for development; production deployments must use a FIPS 140-2 Level 2 (or higher) HSM (YubiHSM2, Thales Luna, AWS CloudHSM, Azure Managed HSM).
- The krbtgt key MUST be generated inside the HSM via `C_GenerateRandom` (AES-256 key) and MUST NOT be extractable (`CKA_EXTRACTABLE = false`, `CKA_SENSITIVE = true`).
- The KDC MUST call `C_EncryptInit` / `C_Encrypt` to encrypt `EncTicketPart` (for AES-256-CTS-HMAC-SHA1-96 etype 0x12).
- The KDC MUST call `C_SignInit` / `C_Sign` to compute the PAC signature (HMAC-SHA1-96 for AES etype).
- The HSM's key reference (PKCS#11 `CK_OBJECT_HANDLE`) MUST be stored in the framework's `krbtgt` account object (replacing the `unicodePwd` and `supplementalCredentials` attributes that AD uses for the krbtgt key material).
- The framework's operator MUST auto-rotate the krbtgt key every 30 days (configurable via `spec.krbtgtRotationIntervalDays` on the `Realm` CRD; range 1–365).
- The rotation MUST use the 2-key overlap protocol:
  1. Generate a new key in the HSM (new `CK_OBJECT_HANDLE`).
  2. Update the KDC config to accept both the old and new keys for TGT decryption.
  3. Replicate the new key reference to all DCs in the realm (via DRSUAPI `EXOP_REPL_SECRETS` for AD-interop, or the framework's replication protocol for framework-to-framework).
  4. Wait one TGT-lifetime (default 10 hours).
  5. Destroy the old key in the HSM (`C_DestroyObject`).
  6. Update the KDC config to accept only the new key.
- The audit pipeline MUST emit an OTel log record for every TGS-REQ where the TGT was encrypted with a non-current krbtgt key version, with attributes `adrian.kerberos.krbtgt_key_version_used`, `adrian.kerberos.krbtgt_key_version_current`, `adrian.kerberos.client.dn`, and MITRE ATT&CK T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket).
- The audit pipeline MUST ship a default detection rule: any TGS-REQ with `krbtgt_key_version_used < krbtgt_key_version_current - 1` after the overlap window has expired → critical alert with MITRE T1558.001.
- The framework MUST support a "panic rotation" operator action: `adrian-cli operator rotate-krbtgt --panic` rotates the krbtgt key immediately, destroys the old key without overlap window, and forces all in-flight TGTs to be re-issued. This is the incident-response action when golden-ticket activity is detected.
- For AD-interop scenarios, the framework's DC MUST export the krbtgt key to AD DCs via DRSUAPI `EXOP_REPL_SECRETS` on rotation; the AD DC's `krbtgt` account `unicodePwd` and `supplementalCredentials` are updated.
- The framework's KDC MUST emit `PAC_BUFFER_TICKET_CHECKSUM` on every service ticket (per PC-119 mitigation; not deferred here because the krbtgt-key signing of the ticket checksum is part of this ADR's HSM-bound key).
- The framework MUST ship a default Prometheus alert: `rate(adrian_kerberos_tgs_req_total{krbtgt_key_stale="true"}[5m]) > 0` triggers a critical alert.

## Rationale

HSM-bound krbtgt is the strongest possible mitigation against golden-ticket attacks. The attack chain requires the attacker to obtain the krbtgt hash; if the hash is never outside the HSM, the attack is impossible (the attacker cannot DCSync the key, cannot dump LSASS memory for the key, cannot read `ntds.dit` for the key). The remaining attack surface (HSM compromise, KDC process compromise with the HSM's PIN) is much smaller and is addressed by standard HSM operational practices (HSM in a secure location, KDC process running with minimal privileges, HSM access logged).

Auto-rotation every 30 days (vs AD's typical 365+ days) bounds the window of golden-ticket vulnerability to 30 days. If the attacker obtains the krbtgt key via a transient compromise (e.g. a brief DCSync attempt that is detected and blocked), the key is rotated within 30 days, invalidating the attacker's TGTs. With HSM binding, even this 30-day window is closed because the key cannot be extracted.

The 2-key overlap window is necessary to avoid disruption during rotation: in-flight TGTs encrypted with the old key continue to work for one TGT-lifetime (10 hours), giving clients time to obtain new TGTs. Without the overlap, every client would experience auth failures for the duration of the TGT-lifetime after rotation.

Old-key TGT usage detection is the audit-side defense. Even with HSM-bound keys and 30-day rotation, an attacker who obtains the krbtgt key (e.g. via an HSM firmware compromise, or by extracting the key from the HSM via a sophisticated attack) can forge TGTs. The detection rule (`krbtgt_key_version_used < current - 1` after overlap expiry) catches this: any TGT encrypted with an old key version is a forged TGT (the framework's KDC would never issue such a TGT after rotation).

The panic-rotation operator action is the incident-response button. When golden-ticket activity is detected (via the audit rule, or via external threat intelligence), the operator runs `adrian-cli operator rotate-krbtgt --panic` and all in-flight TGTs are immediately invalidated. This is disruptive (every client must re-authenticate) but is the correct response to a confirmed golden-ticket compromise.

For AD-interop scenarios, the HSM-bound key must be exported to AD DCs (which cannot use the HSM directly). This is a security regression for the AD-interop path: AD DCs hold the krbtgt key in `ntds.dit` and can be DCSynced. The framework mitigates this by (a) limiting the export to one-time per rotation (the key is re-encrypted with the AD DC's machine account key as a wrapper, so passive capture of the DRSUAPI traffic does not reveal the key), (b) encouraging migration off AD DCs to framework DCs (which use the HSM). The framework's audit pipeline detects DCSync against AD DCs (per PC-117, deferred) and alerts.

This decision is the same as ADR-015 (PC-030) from a different problem framing; this ADR encodes the security-impact angle and adds the HSM binding, which is the security-relevant addition.

## Consequences

**Positive**: Golden-ticket attacks are eliminated by default (HSM-bound key cannot be extracted). Auto-rotation bounds the vulnerability window to 30 days (configurable down to 7). Old-key TGT detection provides audit-side defense. Panic rotation is the incident-response button. The framework's krbtgt key management is fully automated — no operator sequencing required.

**Negative**: HSM is a hard dependency; organisations without an HSM must deploy one (YubiHSM2 ~$500/DC, AWS CloudHSM ~$1.50/hour, Azure Managed HSM ~$1.50/hour). The HSM becomes a single point of failure: if the HSM is down, the KDC cannot issue TGTs. The framework mitigates this via HSM clustering (Thales Luna, AWS CloudHSM) or dual-HSM configurations. AD-interop scenarios lose the HSM protection (the key is exported to AD DCs). The 2-key overlap window requires careful KDC config management.

**Neutral**: The framework's HSM-bound krbtgt does not preclude non-HSM deployments for development or low-security scenarios; `SoftHSM2` is acceptable for development. The HSM-binding is the default; non-HSM is opt-in via configuration.

**Implementation cost**: ~3 person-months for the PKCS#11 integration in the KDC; ~2 person-months for the operator rotation logic; ~2 person-months for the AD-interop key export; ~1 person-month for the audit detection rules. Total: ~8 person-months for v1.

**Operational impact**: HSM provisioning is a one-time setup per realm (the HSM is shared across all DCs in the realm). HSM key rotation is automatic. SOC analysts see old-key-TGT-usage alerts with MITRE T1558.001 tags. The panic-rotation runbook is documented and tested quarterly.

## Alternatives Considered

**Alternative A: Manual rotation only (AD's model), with detection.** Keep krbtgt in `ntds.dit`, rotate manually per Microsoft's KB 3011620 guidance (twice with 10-hour gap), rely on the audit pipeline for old-key TGT detection. Rejected because (a) manual rotation is operator-dependent and rarely performed (most orgs rotate krbtgt annually at best), (b) the key is extractable via DCSync, the dominant attack path, (c) HSM-bound keys are technically straightforward in 2026 and eliminate the entire class of attack.

**Alternative B: Frequent rotation (every 24 hours) without HSM.** Rotate the krbtgt key daily to minimise the vulnerability window. Rejected because (a) daily rotation is disruptive (every client must re-authenticate daily; in-flight TGTs fail), (b) the 2-key overlap window means the key is exposed during the overlap, (c) the key remains extractable via DCSync; rotation does not prevent extraction, only bounds the validity of extracted keys.

**Alternative C: TPM-bound krbtgt (instead of HSM).** Use the DC's TPM (Trusted Platform Module) to bind the krbtgt key to the DC's hardware. Rejected because (a) TPM is per-DC, not per-realm — each DC would have its own krbtgt key, breaking TGT validation across DCs, (b) TPM 2.0 key derivation is slower than HSM (TPM is designed for low-frequency operations like disk encryption), (c) TPM cannot be shared across DCs (the krbtgt key must be the same on all DCs in the realm).

**Alternative D: Public-key Kerberos (PKINIT for TGT issuance).** Replace the krbtgt long-term key with a public-key pair; clients use PKINIT (RFC 4556) to obtain TGTs. Rejected as the primary path because (a) PKINIT requires every client to have a certificate (PKI deployment cost), (b) PKINIT is for AS-REQ, not for TGT issuance — the TGT itself is still encrypted with a KDC key, (c) the krbtgt-equivalent key (the KDC's private key) still needs to be protected, so HSM binding is still required, (d) PKINIT is supported as an optional pre-auth method (per the deferred KDC implementation decision, ORQ-042/043/044).

## Open Questions

None — this is an ADR-ELIGIBLE decision. The KDC implementation choice (PC-023 / Tier-1 ORQ-042/043/044) does not gate this decision: the HSM integration and the rotation logic are stable regardless of whether the KDC is MIT krb5-based, Heimdal-based, or fresh implementation. The PKCS#11 interface is standardised and supported by all candidate KDC implementations.

## Cross-capability impact

- **KDC (PC-023 through PC-035)**: KDC must implement PKCS#11 integration for krbtgt key operations. PC-030 (krbtgt rotation) is the KDC capability; ADR-015 (PC-030) and this ADR encode the same decision from different problem framings.
- **KDC (PC-024)**: Etype policy (PC-024, addressed in ADR-064) requires AES; the krbtgt key is AES-256.
- **Security (PC-117)**: DCSync (PC-117, deferred) is the typical path to obtain the krbtgt hash; HSM binding makes DCSync of the krbtgt key impossible. PC-117 detection (deferred) is complemented by this ADR's old-key TGT detection.
- **Security (PC-119)**: Silver ticket (PC-119, deferred) uses the service-account key; `PAC_BUFFER_TICKET_CHECKSUM` (signed with the krbtgt key) is part of this ADR's HSM-bound key operations.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_kerberos_tgs_req_total{krbtgt_key_stale="true"}` is the key Prometheus metric for golden-ticket detection.
- **Operations (PC-110)**: ADR-059 (PITR backup + DR) — DR runbooks include krbtgt rotation as a recovery step; the operator's `ForestRootRecovery` reconcile loop includes the krbtgt rotation step.
- **Operations (PC-111)**: ADR-060 (audit logs) — the old-key TGT detection rule is part of the audit pipeline.
- **Migration (PC-126)**: Client switchover (PC-126, deferred) — the cross-realm trust setup (ADR-069) must coordinate krbtgt rotation between AD and the framework during the migration window.

## References

- [PC-118](../catalog/11-security-threat-model.md) — problem statement (Golden ticket requires krbtgt rotation to invalidate)
- [AD overview](../docs/00-overview/01-active-directory-overview.md) — Golden ticket threat note
- [SPN/UPN/PAC](../docs/02-protocols/08-spn-upn-pac.md) — PAC structure, `PAC_SIGNATURE_DATA` (type 0x07) KDC signature keyed with krbtgt, `PAC_BUFFER_TICKET_CHECKSUM` (type 0x0E) introduced Server 2016
- [Kerberos internals](../docs/02-protocols/01-kerberos-internals.md) — TGT structure, AS-REQ/AS-REP flow, etype selection
- [RFC 4120 — Kerberos Network Authentication Service](https://datatracker.ietf.org/doc/html/rfc4120) (§5.3 for Ticket encryption)
- [PKCS#11 v3.0 — Cryptographic Token Interface Standard](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)
- [KMIP 1.4 — Key Management Interoperability Protocol](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip)
- [FIPS 140-2 — Security Requirements for Cryptographic Modules](https://csrc.nist.gov/publications/detail/fips/140/2/final)
- [Microsoft KB 3011620 — krbtgt rotation guidance](https://support.microsoft.com/en-us/topic/2012-forest-recovery-steps-for-restoring-the-krbtgt-account-password-2cf1b8f6-b0e4-4b8f-a6b6-6e6c92d28af6)
- [MITRE ATT&CK T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
