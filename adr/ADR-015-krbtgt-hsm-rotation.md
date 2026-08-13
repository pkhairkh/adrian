---
title: "ADR-015: HSM-Bound krbtgt Key with 30-Day Auto-Rotation and 2-Key Overlap"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-030
severity: blocker
tags: [adr, kdc, kerberos, krbtgt, hsm, golden-ticket, rotation]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/00-overview/01-active-directory-overview.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ./ADR-018-kdc-horizontal-scaling.md
  - ./ADR-023-kerberos-audit-events.md
last_updated: 2026-08-13
---

# ADR-015: HSM-Bound krbtgt Key with 30-Day Auto-Rotation and 2-Key Overlap

## Status

Accepted — 2026-08-13

## Context

Anyone with the krbtgt account's NT hash can forge TGTs (golden ticket attack). The krbtgt account is a special account in AD (`CN=krbtgt,CN=Users,<domain-dn>`) whose NT hash is the long-term key for the KDC. A forged TGT encrypted with the krbtgt hash is indistinguishable from a real TGT — the KDC cannot detect forgery. With a forged TGT, an attacker can request service tickets for any service in the domain, impersonating any user (including Domain Admins), per [PC-030](../catalog/02-kdc.md#pc-030--krbtgt-account-compromise--golden-ticket-rotation-is-operationally-painful), [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md), and [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md).

Mitigation: rotate the krbtgt password (which changes the NT hash, invalidating forged TGTs). The catch: existing TGTs encrypted with the old hash must continue to work until they expire (default 10 hours). Microsoft's solution is dual-krbtgt mode (Server 2012+): the KDC maintains two krbtgt keys — the current key (used to issue new TGTs) and the previous key (used to validate existing TGTs). Rotating the krbtgt password twice within a TGT lifetime (the second rotation invalidates the old key) is the recommended procedure.

The procedure is operationally painful: (1) rotate krbtgt password (KDC starts using new key, keeps old key for validation); (2) wait for TGT lifetime (default 10 hours) — all old TGTs expire; (3) rotate krbtgt password again (KDC drops the now-unused old key) — forged TGTs from before step 1 are now invalid. During the 10-hour window, both keys are valid; an attacker who extracted the old key during this window can still forge TGTs until step 3. Microsoft recommends annual rotation but most shops rotate only after a known compromise, when it's too late.

Constraints from [PC-030](../catalog/02-kdc.md#pc-030--krbtgt-account-compromise--golden-ticket-rotation-is-operationally-painful):

- Must support dual-krbtgt mode (Server 2012+ feature) — KDC maintains current + previous key.
- Must log old-key TGT usage as a security signal (event 4769 with the krbtgt kvno indicating old key).
- Must support one-click rotation (atomic: rotate current → previous, generate new current).
- For AD interop, must expose `krbtgt` account via standard LDAP and must use the `unicodePwd` attribute as the key source.

## Decision

The framework SHALL bind the krbtgt account's key material to an HSM (Hardware Security Module). The krbtgt key SHALL NEVER leave the HSM in plaintext — the KDC fetches the key from the HSM at boot and holds it in HSM-protected memory (HSM session key wraps the krbtgt key; the KDC uses the HSM to perform cryptographic operations, never decrypting the key in process memory). The krbtgt key SHALL NOT be stored in the directory's `unicodePwd` attribute (or any other directory attribute) in plaintext; the directory SHALL store only an HSM key reference (key handle / key ID).

The framework SHALL auto-rotate the krbtgt key on a 30-day interval by default (configurable per-deployment: minimum 7 days, maximum 90 days). The rotation SHALL be atomic and one-click (or fully automated): the KDC generates a new krbtgt key in the HSM, atomically promotes the new key to "current" and demotes the previous current key to "previous" (dual-key overlap). The previous key SHALL be retained for 2× the TGT lifetime (default 20 hours) to validate existing TGTs; after the retention window, the previous key SHALL be destroyed in the HSM.

The framework SHALL maintain exactly 2 krbtgt keys at any time (current + previous), matching AD's dual-krbtgt mode. The KDC SHALL issue new TGTs with the current key; the KDC SHALL validate TGTs presented in TGS-REQs against either the current or the previous key (if the previous key is still in the retention window). Old-key TGT usage SHALL be logged as a security event (cross-reference ADR-023) with the krbtgt kvno indicating which key was used.

The framework SHALL expose a CLI command (`adrian-krb5 rotate-krbtgt`) that performs the one-click rotation manually (useful for emergency rotation after a suspected compromise). The framework SHALL expose a monitoring API (`adrian-krb5 krbtgt-status`) that shows: current key ID, previous key ID, current key generation time, previous key destruction time, next scheduled rotation time.

For AD-interop mode, the framework SHALL expose the krbtgt account via standard LDAP at `CN=krbtgt,CN=Users,<domain-dn>` with the `unicodePwd` attribute populated (the framework SHALL write a placeholder value to `unicodePwd` for AD-compat — the actual key is in the HSM; the directory's `unicodePwd` is not used by the framework's KDC but is required for AD-interop tools that inspect the krbtgt account). The `kvno` attribute SHALL track the key version (incremented on each rotation).

The framework SHALL NOT support multiple krbtgt accounts per realm (one per DC) — this would break AD interop (AD has one krbtgt account per domain). The framework's KDC horizontal scaling (cross-reference ADR-018) uses a shared krbtgt key across all KDC instances in the realm, fetched from the HSM.

**Concrete specification**:

- The krbtgt key SHALL be generated, stored, and used inside an HSM. The key SHALL NEVER leave the HSM in plaintext.
- The directory SHALL store only an HSM key reference (key handle / key ID) for the krbtgt account; the `unicodePwd` attribute SHALL contain a placeholder value for AD-compat.
- The framework SHALL auto-rotate the krbtgt key on a 30-day interval (configurable: 7–90 days).
- Rotation SHALL be atomic: generate new key in HSM → promote to "current" → demote previous "current" to "previous" → schedule destruction of "previous" after 2× TGT lifetime (default 20 hours).
- The framework SHALL maintain exactly 2 krbtgt keys at any time (current + previous).
- The KDC SHALL issue new TGTs with the current key; SHALL validate TGTs against either current or previous key (if previous is in retention window).
- Old-key TGT usage SHALL be logged as a security event (principal, source IP, krbtgt kvno, timestamp) per ADR-023.
- The framework SHALL expose `adrian-krb5 rotate-krbtgt` (manual one-click rotation) and `adrian-krb5 krbtgt-status` (monitoring) CLI commands.
- For AD-interop mode, the framework SHALL expose the krbtgt account at `CN=krbtgt,CN=Users,<domain-dn>` with `unicodePwd` placeholder and `kvno` tracking key version.
- The framework SHALL NOT support multiple krbtgt accounts per realm.
- The HSM SHALL support the framework's standard HSM API (PKCS#11 or vendor-specific); the framework SHALL support multiple HSM backends (YubiHSM, AWS CloudHSM, Azure Managed HSM, Thales Luna, Utimaco SecurityServer) via a pluggable HSM interface.

## Rationale

The krbtgt key is the keys to the kingdom — anyone with the key can forge TGTs for any user, including Domain Admins. Binding the key to an HSM eliminates the LSASS-dump attack vector (the key is never in LSASS memory in plaintext) and the DIT-extraction attack vector (the key is never in the DIT in plaintext). The 30-day auto-rotation limits the attack window — an attacker who extracts the key (somehow — HSM compromise, KDC process compromise via the HSM session) has at most 30 days before the key is rotated.

Three alternatives were considered:

**Alternative A — File-backed krbtgt key (MIT krb5 model).** The krbtgt key is stored in a keytab file on the KDC host. The advantage is simplicity (no HSM dependency). The disadvantage is that the key is on disk — any root compromise of the KDC host leaks the key. Rejected because the krbtgt key is too sensitive for disk storage.

**Alternative B — Directory-stored krbtgt key (AD's model).** The krbtgt key is stored in the `unicodePwd` attribute of the `CN=krbtgt` account, replicated to all DCs. The advantage is AD-interop (the krbtgt account is a normal directory object). The disadvantage is that the key is in the DIT — any DIT backup leak, any LSASS dump, any DIT-extraction attack leaks the key. AD has this vulnerability; the framework should not inherit it. Rejected as the primary mechanism; ADOPTED as an AD-compat shim (the directory stores a placeholder `unicodePwd`, not the actual key).

**Alternative C — Multiple krbtgt accounts per realm (one per DC).** Each KDC instance has its own krbtgt key; TGTs issued by one KDC cannot be validated by another KDC. The advantage is eliminating the single point of compromise (compromising one KDC does not leak the realm-wide krbtgt key). The disadvantage is breaking AD interop (AD has one krbtgt account per domain) and breaking cross-KDC TGT validation (a TGT issued by KDC A must be re-issued by KDC B if the client's next TGS-REQ goes to KDC B). Rejected because the framework's KDC horizontal scaling (ADR-018) requires a shared krbtgt key across all KDC instances in the realm.

External evidence: [RFC 4120 §5](https://www.rfc-editor.org/rfc/rfc4120#section-5) defines the krbtgt principal and TGT semantics; [PKCS#11](https://docs.oasis.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html) defines the HSM API; Microsoft's [Credentials Roaming and krbtgt Rotation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-domain-services) documentation covers AD's dual-krbtgt mode. The framework's design extends AD's model with HSM binding and automatic rotation.

The cost of this decision is the HSM dependency — deployments without an HSM cannot use the framework's KDC. This is an acceptable trade-off for the security improvement; the framework SHALL support multiple HSM backends (YubiHSM for small deployments, AWS CloudHSM / Azure Managed HSM for cloud deployments, Thales Luna / Utimaco for on-prem enterprise deployments). The framework SHALL also support a software-based "HSM" (encrypted key file with a passphrase) for development and testing, with a clear warning that this does not provide the security properties of a real HSM.

## Consequences

**Positive**: The krbtgt key is never on disk, never in LSASS memory in plaintext, never in the DIT. LSASS-dump attacks do not leak the key. DIT-extraction attacks do not leak the key. The 30-day auto-rotation limits the attack window. The one-click rotation (manual or automatic) eliminates the operational pain that discourages preventive rotation in AD.

**Negative**: HSM dependency — deployments without an HSM cannot use the framework's KDC. HSM integration adds operational complexity (HSM provisioning, HSM backup, HSM failover). The 30-day rotation window means a 20-hour dual-key overlap every 30 days — operators must monitor for old-key TGT usage during the overlap (legitimate clients with long-lived TGTs may present old-key TGTs; this is normal but should be monitored).

**Neutral**: The AD-compat shim (placeholder `unicodePwd`) is invisible to AD-interop tools — they see a normal krbtgt account. The `kvno` attribute tracks key version identically to AD.

**Implementation cost**: ~6 person-weeks for the HSM integration (PKCS#11 interface, pluggable backends, key generation, key destruction), the auto-rotation scheduler, the dual-key overlap logic, the CLI commands, and the AD-compat shim. The bulk of the work is the HSM integration and the pluggable backend interface.

**Operational impact**: krbtgt rotation is no longer a multi-step manual procedure — it's a one-click CLI command or fully automated. The 30-day rotation is a significant improvement over AD's recommended annual rotation (and the common practice of never rotating). Monitoring: `adrian-krb5 krbtgt-status` shows the current rotation state; SIEM queries for old-key TGT usage (per ADR-023) detect potential golden-ticket attacks.

## Alternatives Considered

### Alternative 1: File-backed krbtgt key (MIT krb5 model)

Simplicity (no HSM); key is on disk — any root compromise leaks the key. Rejected because the krbtgt key is too sensitive for disk storage.

### Alternative 2: Directory-stored krbtgt key (AD's model)

AD-interop (krbtgt account is a normal directory object); key is in the DIT — any DIT leak or LSASS dump leaks the key. Rejected as primary; ADOPTED as an AD-compat shim (placeholder `unicodePwd`, actual key in HSM).

### Alternative 3: Multiple krbtgt accounts per realm (one per DC)

Eliminates single point of compromise; breaks AD interop and cross-KDC TGT validation. Rejected because the framework's KDC horizontal scaling (ADR-018) requires a shared krbtgt key across all KDC instances in the realm.

## Open Questions

- For the HSM pluggable interface, what is the minimum HSM feature set required? Key generation, key storage, key destruction, AES encryption/decryption, HMAC signing. Most HSMs support these via PKCS#11.
- For cloud-native deployments (AWS, Azure, GCP), should the framework use the cloud provider's managed HSM (AWS CloudHSM, Azure Managed HSM, Google Cloud HSM) or a portable HSM (YubiHSM)? Both — the framework's pluggable interface supports both.
- Should the framework support krbtgt key escrow (a backup of the krbtgt key in a separate HSM, for disaster recovery)? Yes — the framework SHALL support HSM key backup via the HSM's native key-wrapping mechanism. The escrow HSM is a separate deployment.
- Cross-reference ADR-018 (KDC horizontal scaling) — the shared krbtgt key across all KDC instances is fetched from the HSM. The two ADRs are tightly coupled.
- Cross-reference PC-022 (multi-tenancy, DEFERRED) — multi-tenancy may require per-tenant krbtgt keys; the framework's HSM integration must support per-tenant key isolation. Defer until multi-tenancy is resolved.

## Cross-capability impact

- **Core Directory**: The krbtgt account is a normal directory object (for AD-interop), but the actual key is in the HSM, not in `unicodePwd`. The directory stores only an HSM key reference.
- **Operations**: krbtgt rotation is a one-click CLI command or fully automated (30-day schedule). Monitoring: `adrian-krb5 krbtgt-status` and SIEM queries for old-key TGT usage.
- **Security**: Golden-ticket detection (per ADR-023) — old-key TGT usage after rotation is a strong signal. The 30-day rotation limits the attack window.
- **Cert Service**: The HSM used for krbtgt may also be used for CA private keys (cross-reference Cert Service ADRs). The framework's HSM interface is shared.
- **Migration**: AD-to-framework migration requires generating a new krbtgt key in the HSM (the AD krbtgt key is not migrated — it's not HSM-bound). Existing AD-issued TGTs become invalid after migration; clients must re-authenticate.

## References

- [PC-030](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/00-overview/01-active-directory-overview.md](../docs/00-overview/01-active-directory-overview.md) — krbtgt account role, golden ticket attack, rotation procedure
- [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) — krbtgt key signing, PAC signature, ticket signature
- [RFC 4120 §5](https://www.rfc-editor.org/rfc/rfc4120#section-5) — Kerberos V5 message definitions (krbtgt principal)
- [PKCS#11 v3.0](https://docs.oasis.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html) — HSM API
- [Microsoft krbtgt rotation documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-domain-services)
