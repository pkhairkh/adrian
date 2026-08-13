---
title: "ADR-016: SPN Uniqueness via Pre-Commit KDC/DSA Check (PARTIAL)"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-031
severity: high
tags: [adr, kdc, spn, uniqueness, drswritespn, partial]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/08-spn-upn-pac.md
  - ../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md
  - ./ADR-017-upn-uniqueness.md
last_updated: 2026-08-13
---

# ADR-016: SPN Uniqueness via Pre-Commit KDC/DSA Check (PARTIAL)

## Status

Accepted — 2026-08-13

## Context

Active Directory enforces SPN uniqueness forest-wide via `DRSWriteSPN` (opnum 13 of DRSUAPI). When the KDC (or any LDAP modify on `servicePrincipalName`) registers an SPN, the DSA calls `DRSWriteSPN` with `DRS_ADD_SPN`. The DSA on the schema master checks the GC for any existing account with the same SPN. If exactly one existing account has the SPN, return `ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST (8647)`. If zero existing accounts have it, the write succeeds and is replicated, per [PC-031](../catalog/02-kdc.md#pc-031--spn-uniqueness-requires-kdc-side-drswritespn-pre-commit-check), [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md), and [docs/02-protocols/06-rpc-dcerpc-ms-drsr.md](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md).

`setspn -X` finds duplicates post-hoc (forest-wide LDAP paged search, hash, and report). Duplicate SPNs cause the KDC to issue tickets encrypted to the wrong account — when a client requests a TGS for `HTTP/web01.example.com`, the KDC finds two accounts with that SPN, picks one at random (or by some internal ordering), and issues a ticket encrypted to that account's key. The client presents the ticket to the service, which cannot decrypt it (wrong key) — `KRB_AP_ERR_MODIFIED (41)`. The client sees a "Kerberos ticket decryption failed" error; the admin sees event 4 (KDC) with the wrong account name; the user sees "access denied" intermittently (50% of the time, depending on which DC handles the TGS-REQ). Diagnosing requires running `setspn -X` and resolving every duplicate, which is a multi-hour operation in large forests.

This ADR is PARTIAL because the *uniqueness scope* — per-forest (single global index) vs per-domain with cross-domain conflict detection — is deferred to Tier-2 ORQ-059/060. The high-confidence part — enforce SPN uniqueness at write time via pre-commit check, support `DRSWriteSPN` for AD-interop — is the Decision. The scope question affects implementation (one global index vs N per-NC indexes with cross-NC coordination) but not the API.

Constraints from [PC-031](../catalog/02-kdc.md#pc-031--spn-uniqueness-requires-kdc-side-drswritespn-pre-commit-check):

- Uniqueness scope is forest-wide (across all domains). Must support GC-based uniqueness check.
- Must support `DRSWriteSPN` for AD interop (opnum 13 of DRSUAPI).
- Must support `setspn -X`-equivalent API for duplicate detection.
- Must support `DRS_ADD_SPN`, `DRS_REMOVE_SPN`, `DRS_CHECK_SPN` operations.

## Decision

The framework SHALL enforce SPN uniqueness at write time via a pre-commit check (the framework's equivalent of `DRSWriteSPN`). When the DSA receives an LDAP modify that adds a value to `servicePrincipalName` on any object, the DSA SHALL: (1) parse the SPN value; (2) query the GC (or the framework's equivalent cross-NC index) for any existing object with the same SPN; (3) if exactly one existing object has the SPN and it's the same object being modified (i.e., the SPN is already registered to this object), allow the write as a no-op; (4) if exactly one existing object has the SPN and it's a different object, reject the write with `ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST (8647)`; (5) if zero existing objects have the SPN, allow the write and update the index atomically.

The framework SHALL support `DRSWriteSPN` (opnum 13 of DRSUAPI) for AD-interop mode, byte-identical to AD's implementation. The framework SHALL support `DRS_ADD_SPN`, `DRS_REMOVE_SPN`, `DRS_CHECK_SPN` operations. The `DRS_REMOVE_SPN` operation SHALL remove the SPN from the index; `DRS_CHECK_SPN` SHALL return whether the SPN is currently registered and to which object.

The framework SHALL expose a `setspn -X`-equivalent CLI command (`adrian-krb5 spn-duplicates`) that scans the directory for duplicate SPNs and produces a report (SPN, list of objects holding it, suggested remediation). The framework SHALL expose `adrian-krb5 spn-check <SPN>` (check if an SPN is registered), `adrian-krb5 spn-add <object-DN> <SPN>`, and `adrian-krb5 spn-remove <object-DN> <SPN>` CLI commands.

The uniqueness scope (per-forest single global index vs per-domain with cross-domain conflict detection) is DEFERRED to Tier-2 ORQ-059/060. The v1 implementation SHALL use a per-forest single global index on `servicePrincipalName` (the simplest and most AD-compatible option); the per-domain alternative may be adopted later if performance testing reveals that the per-forest index is a bottleneck (unlikely for typical deployments — the SPN count per forest is typically <1M).

The framework SHALL validate the SPN format at write time per [MS-ADTS §3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/): `<service-class>/<host>:<port>/<service-name>`. The DSA SHALL reject malformed SPNs with `invalidAttributeSyntax (21)`.

**Concrete specification**:

- The DSA SHALL enforce SPN uniqueness at write time via a pre-commit check on every LDAP modify that adds a value to `servicePrincipalName`.
- The pre-commit check SHALL: (1) parse the SPN; (2) query the global SPN index for existing objects with the same SPN; (3) reject with `ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST (8647)` if a different object holds the SPN; (4) allow and update the index atomically if no other object holds the SPN.
- The framework SHALL maintain a per-forest global index on `servicePrincipalName` (one entry per SPN value, mapping to the object DNT that holds it).
- The framework SHALL support `DRSWriteSPN` (opnum 13 of DRSUAPI) for AD-interop, byte-identical to AD.
- The framework SHALL support `DRS_ADD_SPN`, `DRS_REMOVE_SPN`, `DRS_CHECK_SPN` operations.
- The framework SHALL expose `adrian-krb5 spn-duplicates`, `adrian-krb5 spn-check <SPN>`, `adrian-krb5 spn-add <object-DN> <SPN>`, and `adrian-krb5 spn-remove <object-DN> <SPN>` CLI commands.
- The DSA SHALL validate SPN format per MS-ADTS §3.1.1.2: `<service-class>/<host>:<port>/<service-name>`. Malformed SPNs SHALL be rejected with `invalidAttributeSyntax (21)`.
- Performance target: SPN uniqueness check SHALL complete in <10 ms for a forest with 1M registered SPNs (via the per-forest global index).

## Rationale

Duplicate SPNs cause intermittent auth failures that are difficult to diagnose. The `KRB_AP_ERR_MODIFIED (41)` error is opaque to end users and admins; the diagnosis requires running `setspn -X` and resolving every duplicate, which is a multi-hour operation in large forests. Pre-commit enforcement eliminates the duplicate-creation vector entirely — duplicates cannot be created in the first place.

Three alternatives were considered:

**Alternative A — Post-hoc duplicate detection only (no pre-commit check).** The framework allows duplicate SPNs to be created but provides `setspn -X`-equivalent for detection. The advantage is simpler implementation (no global index, no pre-commit check). The disadvantage is that duplicates are created silently and only detected when an admin runs the scan — by which time the intermittent `KRB_AP_ERR_MODIFIED` failures are already causing user impact. Rejected as the primary mechanism; the pre-commit check is the primary, and `setspn -X`-equivalent is the secondary (for detecting pre-existing duplicates from AD migration).

**Alternative B — Per-domain uniqueness (no cross-domain check).** Each domain enforces SPN uniqueness within itself but does not check other domains. The advantage is simpler implementation (per-NC index, no cross-NC coordination). The disadvantage is that duplicate SPNs across domains (e.g., `HTTP/web01.example.com` registered to a service in both `corp.example.com` and `branch.corp.example.com`) cause the KDC at domain A to issue a ticket for the SPN, but the service is actually in domain B. This is exactly the failure mode that AD's forest-wide uniqueness prevents. Rejected as the primary mechanism; the per-forest global index is the v1 default. The per-domain alternative is deferred to ORQ-060.

**Alternative C — Replace SPN with a different service-identity mechanism (e.g. URN, UUID).** The advantage is eliminating the SPN format constraints and the uniqueness check (UUIDs are inherently unique). The disadvantage is breaking AD interop (AD uses SPNs for service-identity lookup; the KDC's TGS-REQ processing depends on SPN-to-account resolution). Rejected because the framework targets AD-interop deployments; SPNs are the AD-native mechanism.

External evidence: [MS-DRSR §4.1.13](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) documents `DRSWriteSPN`; [MS-ADTS §3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents SPN format; Samba 4 implements `DRSWriteSPN` in `source4/dsdb/repl/replication.c`; 389-DS / FreeIPA use a uniqueness plugin (`uiduniqueness` adapted for SPN). The framework's design matches AD's behavior and is interoperable.

The cost of this decision is the per-forest global SPN index (one entry per SPN value) and the pre-commit check (one index lookup per SPN-add LDAP modify). The index storage is ~80 bytes per SPN; for 1M SPNs, this is ~80 MB. The pre-commit check is O(log n) via the index, <10 ms per check.

## Consequences

**Positive**: Duplicate SPNs cannot be created in the first place. The intermittent `KRB_AP_ERR_MODIFIED` failure mode is eliminated. `setspn -X`-equivalent CLI detects pre-existing duplicates from AD migration. AD-interop is preserved via `DRSWriteSPN` support.

**Negative**: The per-forest global SPN index adds storage (~80 MB for 1M SPNs). The pre-commit check adds write-path latency (<10 ms per SPN-add, acceptable). The per-domain alternative (deferred to ORQ-060) is not supported in v1.

**Neutral**: The AD-compat behavior is identical to AD's `DRSWriteSPN` — AD-interop tools (`setspn`, `Get-ADUser -Filter {servicePrincipalName -eq "..."}`) work without modification.

**Implementation cost**: ~3 person-weeks for the per-forest global SPN index, pre-commit check, `DRSWriteSPN` AD-interop, `setspn`-equivalent CLI commands. The bulk of the work is the index and the pre-commit integration with the LDAP modify path.

**Operational impact**: SPN registration failures (duplicate) are caught at write time with a clear error message naming the conflicting object. `adrian-krb5 spn-duplicates` detects pre-existing duplicates from AD migration. AD-interop tools work without modification.

## Alternatives Considered

### Alternative 1: Post-hoc duplicate detection only (no pre-commit check)

Simpler implementation; duplicates are created silently and only detected by admin scan. Rejected as primary; the pre-commit check is primary, and `setspn -X`-equivalent is secondary for detecting pre-existing duplicates.

### Alternative 2: Per-domain uniqueness (no cross-domain check)

Simpler implementation (per-NC index); duplicate SPNs across domains cause `KRB_AP_ERR_MODIFIED` failures. Rejected as primary; the per-forest global index is the v1 default. The per-domain alternative is deferred to ORQ-060.

### Alternative 3: Replace SPN with a different service-identity mechanism (URN, UUID)

Eliminates SPN format constraints and uniqueness check; breaks AD interop. Rejected because the framework targets AD-interop deployments; SPNs are the AD-native mechanism.

## Open Questions

- **DEFERRED to ORQ-059**: Per-forest unique index on SPN? The Decision section adopts this as the v1 default. The gating ORQ is ORQ-059 (per [catalog/13-open-research-questions.md](../catalog/13-open-research-questions.md)). The high-confidence part (pre-commit check, `DRSWriteSPN` support) is implemented in v1; the per-forest index is the chosen implementation.
- **DEFERRED to ORQ-060**: Per-domain uniqueness with cross-domain conflict detection? The Decision section defers this to ORQ-060. The v1 implementation uses per-forest; per-domain may be adopted later if performance testing reveals a bottleneck.
- For the global SPN index, should the index be replicated cross-DC (like other directory data) or computed locally per-DC? The index SHALL be computed locally per-DC from the `servicePrincipalName` attribute values (which are replicated). This avoids a separate replication concern.
- Cross-reference ADR-017 (UPN uniqueness) — UPN uniqueness uses a similar pre-commit check; the two ADRs share the uniqueness-enforcement infrastructure.

## Cross-capability impact

- **Core Directory**: The per-forest global SPN index is a Core Directory concern (storage, indexing, replication of `servicePrincipalName`). The KDC's pre-commit check calls into the Core Directory's index API.
- **Auth Provider**: SPN-based service authentication depends on SPN uniqueness. Without uniqueness, the KDC may issue tickets to the wrong account.
- **Client SDK**: Client SDK exposes `spn-add`, `spn-remove`, `spn-check`, `spn-duplicates` CLI commands for service-account management.
- **Operations**: `adrian-krb5 spn-duplicates` is a standard ops task (especially after AD migration). The pre-commit check eliminates the duplicate-creation vector.
- **Migration**: AD-to-framework migration preserves SPNs; `adrian-krb5 spn-duplicates` detects any pre-existing duplicates in the migrated data.
- **Security**: SPN uniqueness prevents the `KRB_AP_ERR_MODIFIED` failure mode, which can be exploited by an attacker who registers a duplicate SPN to intercept authentication (rare but possible).

## References

- [PC-031](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md) — SPN format, `servicePrincipalName` attribute, `DRSWriteSPN` opnum 13, duplicate detection
- [docs/02-protocols/06-rpc-dcerpc-ms-drsr.md](../docs/02-protocols/06-rpc-dcerpc-ms-drsr.md) — `DRSWriteSPN` IDL, `DRS_ADD_SPN` / `DRS_REMOVE_SPN` / `DRS_CHECK_SPN` operations
- [MS-DRSR §4.1.13](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — `DRSWriteSPN`
- [MS-ADTS §3.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — SPN format
