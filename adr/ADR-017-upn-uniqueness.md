---
title: "ADR-017: Forest-Wide UPN Uniqueness Enforced at Write Time"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-032
severity: high
tags: [adr, kdc, upn, uniqueness, write-time, forest-wide]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ../docs/00-overview/03-domains-forests-trees.md
  - ./ADR-016-spn-uniqueness.md
last_updated: 2026-08-13
---

# ADR-017: Forest-Wide UPN Uniqueness Enforced at Write Time

## Status

Accepted — 2026-08-13

## Context

UPN (`userPrincipalName`) must be unique within the forest. AD does NOT enforce this at the LDAP-modify level (unlike SPNs) — duplicate UPNs are technically creatable. The KDC enforces uniqueness at AS-REQ time: when a user submits an AS-REQ with a UPN, the KDC resolves the UPN to a `DSNAME` via `DRSCrackNames` (`DS_USER_PRINCIPAL_NAME` → `DS_UNIQUE_ID_NAME`). If multiple accounts match, `DRSCrackNames` returns `DS_NAME_ERROR_NOT_UNIQUE (8649)`; the KDC then refuses the AS-REQ with `KDC_ERR_C_PRINCIPAL_UNKNOWN (6)`, per [PC-032](../catalog/02-kdc.md#pc-032--upn-uniqueness-is-forest-wide-but-enforced-inconsistently) and [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md).

The result: UPN-duplicate users get intermittent login failures depending on which DC handles the AS-REQ and which `DRSCrackNames` result the DC picks. The KDC does not consistently pick one of the duplicates — different DCs may pick different accounts, causing one DC to issue TGTs for user A and another DC to issue TGTs for user B, both with the same UPN. The user sees intermittent "wrong password" errors (because the password is for user A but the KDC is checking against user B's hash).

The UPN suffix list (`uPNSuffixes` on `CN=Partitions,CN=Configuration,...`) restricts which suffixes are valid. A UPN with an unlisted suffix is rejected at AS-REQ time. However, the suffix check is per-forest — a UPN like `jdoe@branch.example.com` is valid only if `branch.example.com` is in `uPNSuffixes` or is a child domain's DNS name.

Constraints from [PC-032](../catalog/02-kdc.md#pc-032--upn-uniqueness-is-forest-wide-but-enforced-inconsistently):

- Must support `uPNSuffixes` and `msDS-UPNSuffixes` for custom suffixes.
- Uniqueness scope is forest (across all domains).
- Must enforce uniqueness at write time (pre-commit check) — not at AS-REQ time.
- Must validate suffix at write time.

## Decision

The framework SHALL enforce UPN uniqueness strictly at write time (pre-commit check), forest-wide. When the DSA receives an LDAP modify that sets or changes `userPrincipalName` on any object, the DSA SHALL: (1) parse the UPN; (2) validate the suffix against `uPNSuffixes` and `msDS-UPNSuffixes` on `CN=Partitions,CN=Configuration,...` (and against child domain DNS names); (3) query the per-forest global UPN index for any existing object with the same UPN; (4) if exactly one existing object has the UPN and it's the same object being modified, allow the write; (5) if exactly one existing object has the UPN and it's a different object, reject the write with `constraintViolation (19)` and a diagnostic message naming the conflicting object's DN (NOT the cryptic `KDC_ERR_C_PRINCIPAL_UNKNOWN (6)` that AD returns at AS-REQ time); (6) if zero existing objects have the UPN, allow the write and update the index atomically.

The framework SHALL validate the UPN suffix at write time. The framework SHALL maintain `uPNSuffixes` and `msDS-UPNSuffixes` on `CN=Partitions,CN=Configuration,...` (the framework's equivalent of AD's Partitions container). The framework SHALL accept UPNs with suffixes that are either: (a) in `uPNSuffixes`; (b) in `msDS-UPNSuffixes`; (c) a child domain's DNS name (matches an NC head's DNS name). UPNs with unlisted suffixes SHALL be rejected with `constraintViolation (19)`.

The framework SHALL maintain a per-forest global UPN index (one entry per UPN value, mapping to the object DNT that holds it), analogous to the SPN index in ADR-016. The index SHALL be computed locally per-DC from the `userPrincipalName` attribute values (which are replicated).

The framework SHALL expose a CLI command (`adrian-krb5 upn-duplicates`) that scans the directory for duplicate UPNs (useful for detecting pre-existing duplicates from AD migration where AD did not enforce uniqueness at write time). The framework SHALL expose `adrian-krb5 upn-check <UPN>` (check if a UPN is registered and to which object) and `adrian-krb5 upn-suffixes` (list valid UPN suffixes).

The framework SHALL NOT auto-rename on conflict (e.g., appending `-2`, `-3`) — the write is rejected and the admin must resolve the conflict explicitly. Auto-rename creates confusing identities (a user expecting `jdoe@corp.example.com` may get `jdoe-2@corp.example.com` without realizing it).

For AD-interop mode, the framework SHALL expose `userPrincipalName` as a normal LDAP attribute (writable, indexed) and SHALL accept `DRSCrackNames` (opnum 12 of DRSUAPI) for UPN-to-DN resolution. The framework's KDC SHALL resolve UPN at AS-REQ time via the per-forest global UPN index (O(log n) lookup, not the `DRSCrackNames` RPC) for performance.

**Concrete specification**:

- The DSA SHALL enforce UPN uniqueness at write time via a pre-commit check on every LDAP modify that sets or changes `userPrincipalName`.
- The pre-commit check SHALL: (1) parse the UPN; (2) validate the suffix against `uPNSuffixes`, `msDS-UPNSuffixes`, and child domain DNS names; (3) reject with `constraintViolation (19)` if the suffix is invalid; (4) query the global UPN index for existing objects with the same UPN; (5) reject with `constraintViolation (19)` if a different object holds the UPN; (6) allow and update the index atomically if no other object holds the UPN.
- The framework SHALL maintain a per-forest global UPN index (one entry per UPN value, mapping to the object DNT).
- The framework SHALL validate UPN suffix at write time against `uPNSuffixes`, `msDS-UPNSuffixes`, and child domain DNS names.
- The framework SHALL expose `adrian-krb5 upn-duplicates`, `adrian-krb5 upn-check <UPN>`, and `adrian-krb5 upn-suffixes` CLI commands.
- The framework SHALL NOT auto-rename on conflict — the write is rejected and the admin resolves explicitly.
- For AD-interop mode, the framework SHALL expose `userPrincipalName` as a normal LDAP attribute and SHALL accept `DRSCrackNames` for UPN-to-DN resolution.
- The KDC SHALL resolve UPN at AS-REQ time via the per-forest global UPN index (O(log n), not the `DRSCrackNames` RPC).
- Performance target: UPN uniqueness check SHALL complete in <10 ms for a forest with 10M users (via the per-forest global index).

## Rationale

AD's AS-REQ-time enforcement is a known operational pain point. Duplicate UPNs are creatable (no pre-commit check), and the failure mode is intermittent and difficult to diagnose. The user reports "sometimes login works, sometimes it doesn't" — admins may not realize the root cause is UPN duplication until they run `Get-ADUser -Filter {userPrincipalName -eq "..."}` and see multiple results. The framework's pre-commit enforcement eliminates the duplicate-creation vector entirely.

Three alternatives were considered:

**Alternative A — Soft enforcement (warn but allow).** The DSA logs a warning when a duplicate UPN is created but allows the write. The advantage is flexibility during mergers / acquisitions (two companies both have `jdoe@corp.example.com`; the admin can create both and resolve later). The disadvantage is that duplicates are created silently and the intermittent login failures persist until the admin resolves them. Rejected as the primary mechanism; the strict pre-commit check is the v1 default. Soft enforcement may be considered as an opt-in mode for migration scenarios (deferred to ORQ-061).

**Alternative B — Auto-rename on conflict (append `-2`, `-3`).** The DSA automatically appends a suffix to make the UPN unique. The advantage is no write failures. The disadvantage is confusing identities — a user expecting `jdoe@corp.example.com` may get `jdoe-2@corp.example.com` without realizing it, and the user's email / login credentials may not match. Rejected because the confusion cost exceeds the convenience.

**Alternative C — Replace UPN with email-as-identity (modern IdP model).** Email is more user-friendly and modern IdPs (Okta, Auth0, Azure AD) use email as the primary identity. The disadvantage is that UPN is RFC 4120-native (the KDC's AS-REQ processing depends on UPN-to-account resolution), and email is not. Rejected for v1; the framework SHALL support UPN as the Kerberos-native identity. Email-as-identity may be supported as an additional mechanism in the Federation Gateway (cross-reference Federation Gateway ADRs).

External evidence: [MS-ADTS §3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents UPN format and `uPNSuffixes`; [MS-DRSR §4.1.12](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) documents `DRSCrackNames`; Samba 4 implements UPN uniqueness via an LDB module; 389-DS / OpenLDAP use a uniqueness plugin (`uiduniqueness` adapted for UPN). The framework's design matches AD's behavior and is interoperable.

The cost of this decision is the per-forest global UPN index (one entry per UPN value) and the pre-commit check. The index storage is ~80 bytes per UPN; for 10M users, this is ~800 MB. The pre-commit check is O(log n) via the index, <10 ms per check.

## Consequences

**Positive**: Duplicate UPNs cannot be created in the first place. The intermittent login failure mode (cryptic `KDC_ERR_C_PRINCIPAL_UNKNOWN`) is eliminated. The pre-commit check returns a clear error message naming the conflicting object. `adrian-krb5 upn-duplicates` detects pre-existing duplicates from AD migration.

**Negative**: The per-forest global UPN index adds storage (~800 MB for 10M users). The pre-commit check adds write-path latency (<10 ms per UPN-set, acceptable). The strict enforcement may require workflow changes for mergers / acquisitions (admins must resolve duplicate UPNs before migration, not after).

**Neutral**: The AD-compat behavior is stricter than AD's (AD allows duplicates at write time; the framework does not). Operators migrating from AD must run `adrian-krb5 upn-duplicates` and resolve pre-existing duplicates before migration.

**Implementation cost**: ~3 person-weeks for the per-forest global UPN index, pre-commit check, suffix validation, `upn-duplicates` / `upn-check` / `upn-suffixes` CLI commands. The bulk of the work is shared with ADR-016 (the same uniqueness-enforcement infrastructure).

**Operational impact**: UPN creation failures (duplicate) are caught at write time with a clear error message. `adrian-krb5 upn-duplicates` detects pre-existing duplicates from AD migration. Mergers / acquisitions require upfront UPN deduplication before migration.

## Alternatives Considered

### Alternative 1: Soft enforcement (warn but allow)

Flexibility during mergers; duplicates are created silently and intermittent failures persist. Rejected as primary; strict pre-commit check is the v1 default. Soft enforcement may be considered as opt-in for migration scenarios (deferred to ORQ-061).

### Alternative 2: Auto-rename on conflict (append `-2`, `-3`)

No write failures; confusing identities (user expecting `jdoe@corp` may get `jdoe-2@corp`). Rejected because the confusion cost exceeds the convenience.

### Alternative 3: Replace UPN with email-as-identity (modern IdP model)

User-friendly and modern; not RFC 4120-native. Rejected for v1; the framework SHALL support UPN as the Kerberos-native identity. Email-as-identity may be supported as an additional mechanism in the Federation Gateway.

## Open Questions

- Should the framework support soft enforcement as an opt-in mode for migration scenarios? The Decision section rejects this for v1; defer to ORQ-061 (per [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md)).
- Should the framework support auto-rename as an opt-in mode? The Decision section rejects this for v1; defer to ORQ-062.
- Cross-reference ADR-016 (SPN uniqueness) — the two ADRs share the uniqueness-enforcement infrastructure. The framework's global index API is reusable for any unique-attribute enforcement.
- For the UPN suffix validation, should the framework support regex-based suffix validation (e.g. `*.corp.example.com`)? Useful for delegating suffix namespaces to child domains. Defer to a future enhancement.

## Cross-capability impact

- **Core Directory**: The per-forest global UPN index is a Core Directory concern. The KDC's pre-commit check calls into the Core Directory's index API.
- **Federation Gateway**: UPN is the standard SAML / OIDC subject. Federation claims issuance reads UPN; uniqueness is critical for correct claim mapping.
- **Client SDK**: Client SDK exposes `upn-check`, `upn-duplicates`, `upn-suffixes` CLI commands for user-management workflows.
- **Operations**: `adrian-krb5 upn-duplicates` is a standard ops task (especially after AD migration). The pre-commit check eliminates the duplicate-creation vector.
- **Migration**: AD-to-framework migration requires upfront UPN deduplication. `adrian-krb5 upn-duplicates` detects pre-existing duplicates; admins must resolve them before migration.
- **Security**: UPN uniqueness prevents the intermittent-login-failure attack where an attacker creates a duplicate UPN to intercept authentication (rare but possible).

## References

- [PC-032](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) — UPN format, `userPrincipalName` attribute, `uPNSuffixes` on Partitions container, `DRSCrackNames` resolution
- [docs/00-overview/03-domains-forests-trees.md](../docs/00-overview/03-domains-forests-trees.md) — UPN as forest-wide identifier, UPN suffix allocation
- [MS-ADTS §3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — UPN format and `uPNSuffixes`
- [MS-DRSR §4.1.12](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — `DRSCrackNames`
