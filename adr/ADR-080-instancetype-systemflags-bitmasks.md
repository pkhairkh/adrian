---
title: "ADR-080: instanceType and systemFlags Bitmasks via Typed Projection with Bitflags Macros"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-021
severity: medium
unblocked_by: Workshop Decision 4 (ORQ-030/031)
tags: [adr, core-directory, bitmasks, instance-type, system-flags, typed-projection, bitflags, ldap-matching-rule]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-04-schema-model.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/02-ous-containers.md
  - ../docs/03-directory-schema/01-schema-attributes.md
  - ./ADR-078-schema-model.md
last_updated: 2026-08-13
---

# ADR-080: instanceType and systemFlags Bitmasks via Typed Projection with Bitflags Macros

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-030/031 (schema model). It is now unblocked by [Workshop Decision 4 (Hybrid LDAP Schema + Typed Rust Projection)](../workshop/decision-04-schema-model.md).

## Context

AD uses two interlocking bitmasks to gate object behavior: `instanceType` (32-bit, OID `2.5.21.1`, written by the DSA on create, `systemOnly`) and `systemFlags` (32-bit, OID `1.2.840.113556.1.4.378`). `instanceType` bits: `IT_WRITE` (0x01, object is writable on this DC; FALSE on RODC copies), `IT_NC_ABOVE` (0x02, NC head is above this object; i.e. this object is NOT the NC head), `IT_NC` (0x04, object IS the NC head), `IT_NC_BASE` (0x08, base of an NDNC). Common values: 0x03 (writable object below NC head — most user/computer/group objects), 0x04 (NC head replica, NOT writable — GC partial replica), 0x05 (writable NC head — domain NC on a DC in that domain), 0x07 (writable NC head with IT_NC_BASE — NDNC heads on home server), per [PC-021](../catalog/01-core-directory.md#pc-021--instancetype-and-systemflags-are-complex-bitmasks-that-gate-object-behavior) and [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md).

`systemFlags` bits include: `FLAG_ATTR_NOT_REPLICATED` (0x01, attribute value not replicated; e.g. `badPwdCount`, `lastLogon` — per-DC), `FLAG_ATTR_IS_CONSTRUCTED` (0x02), `FLAG_ATTR_IS_OPERATIONAL` (0x04), `FLAG_SCHEMA_BASE_OBJECT` (0x08), `FLAG_ATTR_IS_RDN` (0x10), `FLAG_DOMAIN_DISALLOW_MOVE` (0x100, set on `CN=Builtin`, `CN=Users`, `CN=Computers`, `CN=System`), `FLAG_DOMAIN_DISALLOW_MOVE_ON_DOMAIN` (0x200), `FLAG_DOMAIN_DISALLOW_RENAME` (0x400), `FLAG_DOMAIN_DISALLOW_DELETE` (0x800), and config-NC variants (`FLAG_CONFIG_ALLOW_MOVE` 0x01000000, `FLAG_CONFIG_ALLOW_RENAME` 0x02000000, etc.). Well-known containers have `systemFlags = 0x00080000` (DISALLOW_MOVE | DISALLOW_RENAME | DISALLOW_DELETE).

Direct LDAP clients that filter on these flags (e.g. `(systemFlags:1.2.840.113556.1.4.803:=256)` to find non-movable objects) break if the framework replaces the bitmask with explicit attributes. The trade-off: bitmasks are compact (one attribute) but opaque (no schema enforcement, no indexing on individual bits); explicit attributes are clear (`is_nc_head BOOLEAN`, `is_replicated BOOLEAN`, `is_movable BOOLEAN`) but verbose (one attribute per flag).

**Unblocking decision.** [Workshop Decision 4](../workshop/decision-04-schema-model.md) selected the hybrid schema model with a Rust typed projection. The typed projection exposes bitmasks via `bitflags!` macros and explicit accessor methods, replacing raw bitmask reads for internal framework code while preserving the bitmask wire format for AD-interop. This ADR translates Decision 4's typed projection into the concrete `instanceType` / `systemFlags` implementation.

## Decision

The framework SHALL preserve the `instanceType` and `systemFlags` bitmasks on the wire (AD-interop compatibility) and in storage (FDB subspace `0x01`). The framework's typed Rust projection (per ADR-078) SHALL expose the bitmasks via the `bitflags!` macro from the `bitflags` crate, with explicit accessor methods (`obj.is_nc_head()`, `obj.is_writable()`, `obj.is_movable()`, `obj.is_replicated()`) for internal framework code. LDAP clients continue to filter on the raw bitmask via `LDAP_MATCHING_RULE_BIT_AND` (`1.2.840.113556.1.4.803`) and `LDAP_MATCHING_RULE_BIT_OR` (`1.2.840.113556.1.4.804`).

**Concrete specification**:

- The framework SHALL store `instanceType` and `systemFlags` as 32-bit integers in FDB subspace `0x01` (objects), one row per object per attribute (single-valued). The wire format is BER-encoded INTEGER (per RFC 4511).
- The framework's typed projection (per ADR-078) SHALL expose `instanceType` as a `bitflags!`-generated `InstanceType` type:
  ```rust
  bitflags! {
      #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
      pub struct InstanceType: u32 {
          const WRITE       = 0x01;
          const NC_ABOVE    = 0x02;
          const NC          = 0x04;
          const NC_BASE     = 0x08;
      }
  }
  impl InstanceType {
      pub fn is_nc_head(&self) -> bool { self.contains(Self::NC) }
      pub fn is_writable(&self) -> bool { self.contains(Self::WRITE) }
      pub fn is_nc_base(&self) -> bool { self.contains(Self::NC_BASE) }
  }
  ```
- The framework's typed projection SHALL expose `systemFlags` as a `bitflags!`-generated `SystemFlags` type with all 24 documented flags (`FLAG_ATTR_NOT_REPLICATED`, `FLAG_ATTR_IS_CONSTRUCTED`, `FLAG_ATTR_IS_OPERATIONAL`, `FLAG_SCHEMA_BASE_OBJECT`, `FLAG_ATTR_IS_RDN`, `FLAG_DOMAIN_DISALLOW_MOVE`, `FLAG_DOMAIN_DISALLOW_MOVE_ON_DOMAIN`, `FLAG_DOMAIN_DISALLOW_RENAME`, `FLAG_DOMAIN_DISALLOW_DELETE`, `FLAG_CONFIG_ALLOW_MOVE`, `FLAG_CONFIG_ALLOW_RENAME`, `FLAG_CONFIG_ALLOW_DELETE`, `FLAG_CONFIG_ALLOW_LIMITED_MOVE`, `FLAG_DISALLOW_DELETE_ON_DOMAIN`, plus the less-common flags). Each flag has an explicit accessor method (`obj.is_movable()`, `obj.is_renameable()`, `obj.is_deletable()`, `obj.is_replicated()`).
- The typed accessors SHALL be the framework's internal API for object-behaviour gating. The DSA's write validator (per ADR-078) uses `obj.is_movable()` to reject move operations on objects with `FLAG_DOMAIN_DISALLOW_MOVE`; the replication engine uses `obj.is_replicated()` to skip per-DC attributes (`badPwdCount`, `lastLogon`); the GC PAS filter uses `obj.is_constructed()` to drop constructed attributes from PAS replicas.
- For AD-interop mode, the framework SHALL accept and emit `instanceType` and `systemFlags` byte-identically to MS-ADTS §3.1.1.3. The framework SHALL preserve the bitmask values exactly — `instanceType` 0x03 for ordinary objects, 0x05 for writable NC heads, 0x04 for read-only NC heads (GC partial replicas), 0x07 for NDNC heads on the home server. The framework SHALL NOT replace the bitmask with explicit attributes on the wire.
- The framework SHALL support `LDAP_MATCHING_RULE_BIT_AND` (`1.2.840.113556.1.4.803`) and `LDAP_MATCHING_RULE_BIT_OR` (`1.2.840.113556.1.4.804`) on both `instanceType` and `systemFlags`. The LDAP server's filter evaluator SHALL translate these rules to FDB range scans on the bitmask value (FDB's tuple-layer encoding supports bitwise comparison via range scans — the filter `(systemFlags:1.2.840.113556.1.4.803:=256)` translates to a range scan on `(0x01, *, attribute_id=systemFlags, *)` filtered by `value & 0x100 == 0x100`).
- The framework SHALL enforce `instanceType` and `systemFlags` invariants at write time:
  - `instanceType` is `systemOnly` — clients cannot write it directly; the DSA sets it based on the object's NC and the DC's role.
  - `systemFlags` for well-known containers (`CN=Builtin`, `CN=Users`, `CN=Computers`, `CN=System`, `CN=Deleted Objects`, `CN=ForeignSecurityPrincipals`, `CN=Infrastructure`, `CN=LostAndFound`, `CN=NTDS Quotas`, `CN=Managed Service Accounts`, `CN=Program Data`) is `systemOnly` — the framework sets `FLAG_DOMAIN_DISALLOW_MOVE | FLAG_DOMAIN_DISALLOW_RENAME | FLAG_DOMAIN_DISALLOW_DELETE` (0x800) at object creation and rejects client modifications.
  - The framework SHALL reject LDAP Modify operations that attempt to set `systemFlags & FLAG_DOMAIN_DISALLOW_MOVE` to 0 on well-known containers (per PC-011 — well-known containers are forest-wide constants).
- The framework SHALL expose `adrian-directory inspect --dn <dn> --bitmasks` CLI for bitmask inspection (outputs the decoded bitmask flags for `instanceType` and `systemFlags`).
- The framework's framework-native traits (per ADR-078) SHALL NOT re-declare `instanceType` / `systemFlags` — these are AD-schema attributes projected via the typed projection's standard bitmask handling. Framework-native traits may add typed accessor methods (`obj.is_managed_service_account()` etc.) but the underlying bitmask is the AD-schema `systemFlags`.

## Rationale

The bitmasks are opaque but compact. AD uses them because (a) one attribute covers many boolean properties (storage efficiency); (b) LDAP matching rules support bitwise filtering (query efficiency); (c) the bitmask is `systemOnly` for well-known containers (operational safety). The framework inherits these benefits by preserving the bitmask on the wire and in storage.

The framework's typed projection (per Decision 4) gives internal code the readability of explicit accessor methods (`obj.is_movable()`) without sacrificing the bitmask's compactness. The `bitflags!` macro is the standard Rust pattern for typed bitmask handling — used by `std::os::unix::fs::MetadataExt`, `tokio::io::Interest`, and many other Rust libraries. The `bitflags` crate (MIT/Apache-2.0, maintained by the Rust community) is the de facto standard.

External evidence: AD's bitmask model is documented in [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) and [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md). Samba 4 implements both bitmasks in `source4/dsdb/samdb/ldb_modules/objectclass.c`. 389-DS / OpenLDAP do not have `instanceType` / `systemFlags` equivalents — the framework must implement them for AD-interop. The `bitflags` crate is used by `std`, `tokio`, `rustix`, and most Rust libraries that handle bitmasks.

## Consequences

**Positive**: Internal framework code uses readable accessor methods (`obj.is_movable()`) instead of raw bitmask reads (`obj.system_flags() & 0x100 == 0x100`). The `bitflags!` macro provides type safety — invalid flag combinations are compile-time errors. LDAP clients continue to filter on the raw bitmask via `LDAP_MATCHING_RULE_BIT_AND` / `BIT_OR` (AD-interop compatible). The bitmask wire format is preserved byte-identically.

**Negative**: The bitmask is opaque to humans reading LDAP directly — admins must decode the bitmask manually (`0x800` = DISALLOW_MOVE | DISALLOW_RENAME | DISALLOW_DELETE). The `adrian-directory inspect --bitmasks` CLI is the mitigation. The bitmask is not indexed per-bit (one FDB range scan per bitwise filter) — performance is acceptable for typical filter sizes (the range scan returns ~1000 objects per scan for a 1M-object directory).

**Neutral**: AD-aware tools (ADUC, ADSI Edit, `Get-ADObject -Properties instanceType,systemFlags`) see identical bitmask values. The framework's typed projection is internal; the wire format is unchanged.

**Cost**: ~1 person-week for the `bitflags!` definitions, the typed accessor methods, the write-validator integration, the LDAP matching-rule support, and the `adrian-directory inspect --bitmasks` CLI. The bulk of the work is the typed projection infrastructure (per ADR-078).

**Operational impact**: Admins use `adrian-directory inspect --bitmasks` for bitmask decoding. LDAP clients use `LDAP_MATCHING_RULE_BIT_AND` / `BIT_OR` for filtering. The framework's write validator rejects invalid bitmask modifications on `systemOnly` attributes.

## Alternatives Considered

### Alternative 1: Replace bitmask with explicit attributes (`is_nc_head BOOLEAN`, `is_replicated BOOLEAN`, `is_movable BOOLEAN`)

Readable but verbose (one attribute per flag — ~24 attributes for `systemFlags`). Breaks LDAP clients that filter on the raw bitmask (`(systemFlags:1.2.840.113556.1.4.803:=256)`). Requires translation layer for AD-interop. Rejected: AD-interop compatibility is a v1 requirement.

### Alternative 2: Hybrid — bitmask on the wire (LDAP), explicit attributes internally (storage)

The framework stores explicit attributes (`is_nc_head BOOLEAN`) in FDB and synthesises the bitmask at the LDAP boundary. The advantage is internal readability. The disadvantage is the translation layer (bitmask ↔ explicit attributes) and the storage overhead (24 attributes vs 1 bitmask). The framework's typed projection (per Decision 4) achieves the same internal readability without the translation layer or storage overhead — the bitmask is stored as-is, and the typed projection decodes it at read time. Rejected: the typed projection is the better solution.

### Alternative 3: Pure bitmask (no typed projection) — internal code reads raw bitmask

AD's model. Simple but error-prone — `obj.system_flags() & 0x100 == 0x100` is opaque. Forces every framework engineer to memorise the bitmask constants. Rejected: the typed projection (per Decision 4) is the framework's standard for readable internal code.

## Open Questions

- For bitwise LDAP matching rules (`LDAP_MATCHING_RULE_BIT_AND`), should the framework build a per-bit index (24 indexes for `systemFlags`) for faster filtering? Default: no — FDB range scans are fast enough for typical filter sizes (1000 objects per scan). Confirm with customer-scale benchmark.
- For framework-native classes (`ServiceAccount`, `ManagedDevice`), should the framework define additional `systemFlags` bits (e.g., `FLAG_FRAMEWORK_MANAGED`) to distinguish framework-native objects from AD-schema objects? Default: no — the framework uses `objectClass` for type discrimination, not `systemFlags`. Confirm in implementation.
- For the `adrian-directory inspect --bitmasks` CLI, should the output be JSON or human-readable text? Default: human-readable text (with `--json` flag for machine consumption). Confirm with UX review.

## Cross-capability impact

- **KDC**: KDC's PAC builder does not directly use `instanceType` / `systemFlags`; the PAC builder uses the typed projection's `user` / `computer` / `group` accessors. The KDC's krbtgt account has `systemFlags = FLAG_DOMAIN_DISALLOW_DELETE` (cannot be deleted, only rotated per ADR-015).
- **Auth Provider**: S4U2Proxy / RBCD configurations do not directly use the bitmasks; the framework's typed projection handles the underlying `msDS-*` attributes.
- **Policy Engine**: GPO objects have `systemFlags = FLAG_DOMAIN_DISALLOW_MOVE` (GPOs cannot be moved between domains). The framework's write validator enforces this.
- **Cert Service**: Certificate templates (`pKICertificateTemplate` class) have `systemFlags` indicating whether the template is `FLAG_SCHEMA_BASE_OBJECT` (built-in) or a custom template.
- **File Gateway**: File ACLs do not use `instanceType` / `systemFlags`; the framework's ACL evaluator consults the typed projection's `is_movable()` accessor for move operations.
- **Client SDK**: The SDK exposes the bitmask via the typed projection's accessor methods (`obj.is_movable()`) for framework-native clients and via the raw `instanceType` / `systemFlags` attributes for AD-aware LDAP clients.
- **Operations**: Well-known containers (`CN=Users`, `CN=Computers`, `CN=System`) cannot be moved, renamed, or deleted (per `systemFlags`). The framework's write validator enforces this; the `adrian-operator` (ADR-058) monitors for attempted violations.
- **Migration**: AD-to-framework migration preserves `instanceType` and `systemFlags` byte-identically (the framework's schema is AD-compatible). Migration tools that filter on `systemFlags` (e.g., to find non-movable objects) work unmodified.

## References

- [PC-021](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 4 — Hybrid LDAP Schema + Typed Rust Projection](../workshop/decision-04-schema-model.md) — unblocking decision
- [docs/03-directory-schema/02-ous-containers.md](../docs/03-directory-schema/02-ous-containers.md) — `instanceType` flag table, `systemFlags` bitmask table, well-known container `systemFlags` values
- [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md) — `systemFlags` bitmask on `attributeSchema` (FLAG_ATTR_IS_CONSTRUCTED, FLAG_ATTR_IS_OPERATIONAL, etc.)
- [MS-ADTS §3.1.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — `instanceType` and `systemFlags` definitions
- [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — well-known container `systemFlags` values
- [RFC 4515 §3](https://www.rfc-editor.org/rfc/rfc4515) — LDAP filter syntax, extensible matching rules
- [bitflags crate](https://github.com/bitflags/bitflags) — Rust bitmask macro
- [ADR-078: Schema Model](./ADR-078-schema-model.md) — typed projection infrastructure
- [ADR-011: Well-Known Container GUIDs](./ADR-005-well-known-container-guids.md) — well-known container `systemFlags` enforcement
