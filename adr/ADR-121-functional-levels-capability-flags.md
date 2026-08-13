---
title: "ADR-121: Replace Functional Levels with Per-Feature Capability Flags + DC Capabilities Exchange"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-113
severity: medium
tags: [adr, operations, functional-levels, capability-flags, drsbind, msds-behavior-version, mixed-version]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/03-directory-schema/01-schema-attributes.md
  - ../docs/00-overview/03-domains-forests-trees.md
  - ../workshop/decision-04-schema-model.md
  - ./ADR-119-schema-as-code-gitops.md
last_updated: 2026-08-13
---

# ADR-121: Replace Functional Levels with Per-Feature Capability Flags + DC Capabilities Exchange

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 4 (schema model)](../workshop/decision-04-schema-model.md) which adopted the hybrid LDAP schema + typed Rust projection. This ADR specifies the framework's replacement for AD's domain/forest functional levels.

## Context

AD domain and forest functional levels gate feature availability. Domain modes: Windows 2000 mixed, Windows 2000 native, Windows Server 2003 interim, Windows Server 2003, 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022. Forest modes mirror the Windows Server release version. `Set-ADDomainMode -Identity <domain> -DomainMode <year>` raises the domain functional level; `Set-ADForestMode -Identity <forest> -ForestMode <year>` raises the forest functional level. Both operations are one-way: once raised, they cannot be lowered.

Functional levels gate features by (a) requiring all DCs to be at-or-above that version (so a 2012-functional-level domain cannot host a 2008 R2 DC), (b) enabling or disabling legacy protocols (2008 R2 forest functional level disables NTLM fallback on trusts with `TRUST_ATTRIBUTE_UPLEVEL_ONLY`), and (c) gating schema features (claims-based Kerberos requires 2012 forest functional level + `objectVersion = 56+`). Mixed-version forests (e.g. 2012 + 2022 DCs) work but with feature constraints — the 2012 DCs do not understand `msDS-AllowedToActOnBehalfOfOtherIdentity` (resource-based constrained delegation, 2012 R2+), so writes to that attribute replicate but are silently ignored on 2012 DCs.

Per [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md), `objectVersion` on the Schema NC head must match the forest functional level. A 2012 forest functional level requires `objectVersion >= 56`; a 2022 forest functional level requires `objectVersion = 88`. The forest functional level is the lowest-common-denominator across all DCs in the forest; raising it requires demoting any DC below the new level.

The framework gap: functional levels are an artefact of Microsoft's release cadence (one schema bump per Windows Server release every 3 years). A modern framework with continuous deployment (CD) should not have "levels" — it should have feature flags. Newer DCs should advertise new capabilities via a capabilities-exchange (similar to `DRS_EXTENSIONS` in `DRSBind`); older DCs should gracefully degrade. Workshop Decision 4 resolved the schema model (hybrid LDAP + typed projection); this ADR specifies how the framework gates features without functional levels.

## Decision

The framework replaces AD's domain/forest functional levels with **per-feature capability flags** stored as `attributeSchema` extensions to the `dSConfiguration` directory object. Every framework DC advertises its capabilities via a `DC_CAPABILITIES` extension in `DRSBind` (AD-interop mode) or via the `RaftNetwork` peer-metadata exchange (native mode). Feature availability is computed at runtime as the intersection of all DCs' advertised capabilities — a feature is "forest-enabled" only if every DC in the forest advertises it.

The framework preserves AD-interop compatibility by setting `msDS-Behavior-Version` on the domain NC head to the value AD expects for the highest functional level the framework supports (`7` for Server 2016, `8` for Server 2019, `9` for Server 2022). For AD-interop mode, this integer is a wire-compat artefact (AD DCs check it during `DRSBind`); for native mode, the framework elides the integer entirely and uses only the capability-flags model.

**Concrete specification**:

- The framework MUST define a `DC_CAPABILITIES` bitmask (uint64) with one bit per feature. Initial v1 bits:
  - `0x0000_0001` — `claims_based_kerberos` (compound identity, `msDS-CompoundIdentity`)
  - `0x0000_0002` — `rbcd` (resource-based constrained delegation, `msDS-AllowedToActOnBehalfOfOtherIdentity`)
  - `0x0000_0004` — `aes_only_kerberos` (no RC4 fallback)
  - `0x0000_0008` — `pac_buffer_ticket_checksum` (silver-ticket mitigation per ADR-123)
  - `0x0000_0010` — `fast_required` (PA-FX-FAST armoring required)
  - `0x0000_0020` — `pim_trusts` (`TRUST_ATTRIBUTE_PIM_TRUST = 0x200`)
  - `0x0000_0040` — `gmsa` (Group Managed Service Accounts)
  - `0x0000_0080` — `recycle_bin` (deleted-object recycling, on by default)
  - `0x0000_0100` — `pid_history_filtering` (sIDHistory filtering per ADR-124)
  - `0x0000_0200` — `lsa_protection` (LSASS-equivalent protected process)
  - `0x0000_0400` — `hsm_krbtgt` (HSM-bound krbtgt per ADR-065)
  - `0x0000_0800` — `ntlm_server_disabled` (Decision 6's NTLM-server-side drop)
- Each framework DC MUST advertise its `DC_CAPABILITIES` bitmask in `DRSBind`'s `DRS_EXTENSIONS_V8` extension (AD-interop mode) or in the `RaftNetwork` peer-metadata exchange (native mode).
- The framework MUST compute `forest_capabilities` as the bitwise-AND of all DCs' advertised `DC_CAPABILITIES`. A feature is "forest-enabled" only if every DC advertises it.
- The framework MUST expose `adrian-cli capabilities list --forest` returning the current `forest_capabilities`, per-DC capabilities, and a list of features blocked by a specific DC (e.g. "claims_based_kerberos blocked by DC03 — missing capability bit").
- The framework MUST expose `GET /api/v1/capabilities` (REST, per ADR-061) returning the same data as the CLI in JSON.
- The framework MUST refuse writes that require a feature not in `forest_capabilities`. For example, a write to `msDS-AllowedToActOnBehalfOfOtherIdentity` is rejected with `unwillingToPerform (53)` if `rbcd` is not in `forest_capabilities`. The error message names the blocking DC.
- The framework MUST support `adrian-cli capabilities enable --feature <name> --require-all-dcs-at-version <version>` for staged feature rollout. The CLI verifies every DC in the forest is at-or-above the required version (via the `RaftNetwork` peer-metadata `dc_version` field) and then sets the capability bit in the `dSConfiguration` object (which replicates to all DCs).
- The framework MUST support `adrian-cli capabilities disable --feature <name>` for synthetic rollback (the inverse of enable). Disabling a feature does not roll back data already written using the feature; it only prevents new writes.
- For AD-interop mode, the framework MUST set `msDS-Behavior-Version` on the domain NC head to the value AD expects for the framework's advertised feature set (e.g. `9` for Server 2022). The integer is computed from the `DC_CAPABILITIES` bitmask — a feature-set that includes `aes_only_kerberos`, `pac_buffer_ticket_checksum`, `fast_required`, `pim_trusts`, `gmsa`, `recycle_bin`, `pid_history_filtering`, `lsa_protection`, `hsm_krbtgt` maps to `9` (Server 2022). A feature-set missing `pim_trusts` maps to `7` (Server 2016).
- For AD-interop mode, the framework MUST set the Schema NC head's `objectVersion` to match `msDS-Behavior-Version` (e.g. `objectVersion = 88` for Server 2022). This is the wire-compat artefact AD DCs check during `DRSBind`.
- For native mode, the framework MUST elide `msDS-Behavior-Version` (set to `0` or absent) and use only the `DC_CAPABILITIES` bitmask. Native-mode forests do not interop with AD DCs and therefore do not need the integer.
- The framework MUST emit an audit event per ADR-060 for every capability enable/disable operation, including the feature name, the actor, the previous bitmask, and the new bitmask.
- The framework MUST ship a default Prometheus alert: `adrian_capabilities_blocked_writes_total{feature} > 0 for 5m` triggers warning (a DC is blocking feature-gated writes).

## Rationale

Functional levels are an artefact of Microsoft's release cadence (one schema bump per Windows Server release every 3 years). The framework's continuous-deployment model ships weekly; per-release functional levels do not fit. The capability-flags model is the modern equivalent: each feature is a bit, each DC advertises its bits, the forest's feature set is the intersection. This is how Kubernetes does feature gates, how Linux does kernel `prctl` capabilities, and how the framework's `DRSBind` already works (the `DRS_EXTENSIONS_V8` bitmask is a coarse capability exchange).

The intersection model preserves the safety property of functional levels: a feature is forest-enabled only when every DC can handle it. This prevents the "2012 DC silently ignores `msDS-AllowedToActOnBehalfOfOtherIdentity`" problem — the framework's `rbcd` bit is `0` on the 2012-equivalent DC, the forest's `forest_capabilities` does not include `rbcd`, and writes to the attribute are rejected with a clear error message naming the blocking DC. The operator's remediation is to upgrade the blocking DC; the framework's `adrian-cli capabilities list` shows which DCs need upgrading.

The wire-compat `msDS-Behavior-Version` integer is preserved for AD-interop mode because AD DCs check it during `DRSBind`. The framework computes the integer from the capability bitmask — a feature set that maps to Server 2022 produces `9`; a feature set missing `pim_trusts` produces `7`. The integer is a derived value, not a source of truth; the source of truth is the capability bitmask. This means the framework's `msDS-Behavior-Version` always reflects the framework's actual capabilities, not an arbitrary release-year integer.

The staged rollout (`adrian-cli capabilities enable --require-all-dcs-at-version <version>`) is the operational improvement over AD. In AD, raising the functional level is a one-way `Set-ADForestMode` invocation that fails if any DC is below the new level. The framework's CLI verifies the version requirement first, then sets the bit in `dSConfiguration`, which replicates to all DCs. The bit is set atomically (per FDB strict-serializable transactions, Decision 2); there is no "some DCs have the bit, some don't" window.

The synthetic-rollback model (per ADR-119) applies here too. Disabling a feature does not roll back data already written using the feature; it only prevents new writes. The framework's documentation explicitly notes this limitation: an operator who enables `rbcd`, writes some `msDS-AllowedToActOnBehalfOfOtherIdentity` values, and then disables `rbcd` has those values stranded in the directory (readable but not writable until `rbcd` is re-enabled). This is the same operational semantics as AD's `isDefunct = TRUE` on an attribute — the attribute remains, but new writes are rejected.

## Consequences

**Positive**: Functional levels are eliminated in native mode; replaced with per-feature capability flags. Staged rollout is safer than AD's `Set-ADForestMode` (verify-then-set instead of set-then-pray). Mixed-version forests work cleanly — older DCs degrade gracefully, newer DCs advertise their bits. Wire-compat with AD is preserved via the derived `msDS-Behavior-Version` integer.

**Negative**: The capability bitmask is a fixed-size uint64 — extending beyond 64 features requires a more complex encoding (multi-uint, or a JSON document). The intersection model means a single legacy DC blocks features for the entire forest; the framework's CLI surfaces this, but operators must still upgrade the blocking DC. The `msDS-Behavior-Version` derivation is lossy (multiple capability bitmasks may map to the same integer) — the framework picks the highest integer that the bitmask implies.

**Neutral**: The framework's `DC_CAPABILITIES` bitmask is a new wire-format field; AD DCs ignore unknown bits in `DRS_EXTENSIONS_V8` (per MS-DRSR §5.39). The framework's bitmask is in a reserved range, avoiding conflicts with Microsoft's allocated bits.

**Implementation cost**: ~3 person-months for the capability-flags model, the `adrian-cli capabilities` CLI, the `DRS_EXTENSIONS_V8` integration, and the `msDS-Behavior-Version` derivation logic. Reuses Decision 4's `adrian-schema-compiler` (the `DC_CAPABILITIES` bitmask is a typed projection field on the `dSConfiguration` object).

**Operational impact**: Operators manage capability flags via CLI instead of `Set-ADForestMode`. SREs monitor `adrian_capabilities_blocked_writes_total` for legacy-DC blocking. Migration teams use `adrian-cli capabilities list` to verify the forest is ready for a feature-gated migration (e.g. claims-based Kerberos requires `claims_based_kerberos` in `forest_capabilities`).

## Alternatives Considered

**Alternative A: Preserve AD's functional-level model verbatim.** Implement `msDS-Behavior-Version` and `objectVersion` as the source of truth, with `Set-ADDomainMode`/`Set-ADForestMode`-equivalent CLI commands. Rejected because (a) it inherits the one-way irreversibility that organisations flee; (b) it ties feature gating to the framework's release cadence rather than per-feature rollout; (c) the framework's continuous-deployment model does not fit the "raise the level every 3 years" cadence.

**Alternative B: Drop feature gating entirely (always-latest schema, always-all-features).** Every DC supports every feature; no intersection computation needed. Rejected because (a) it prevents mixed-version forests during upgrades — a new DC running v1.1 cannot coexist with a v1.0 DC if v1.1 introduces a feature v1.0 cannot parse; (b) it forces big-bang upgrades (every DC must be upgraded simultaneously); (c) it breaks AD-interop (AD DCs need a `msDS-Behavior-Version` integer to gate their own behaviour).

**Alternative C: Per-DC feature flags without forest-intersection.** Each DC advertises its capabilities; clients pick a DC that supports the feature they need. Rejected because (a) it breaks replication — a write to `msDS-AllowedToActOnBehalfOfOtherIdentity` accepted by a v1.1 DC replicates to a v1.0 DC that cannot parse the attribute, causing replication failure; (b) it shifts the burden to clients (the client must query DC capabilities before every operation); (c) AD's functional-level model exists precisely to avoid this complexity.

**Alternative D: JSON document instead of bitmask.** Replace the uint64 bitmask with a JSON document enumerating capabilities. Rejected because (a) `DRS_EXTENSIONS_V8` is a fixed-size binary structure; a JSON document requires a new extension type; (b) the bitmask is sufficient for 64 features (the framework's v1 has 12); (c) bitmasks are cheaper to intersect (bitwise-AND) than JSON documents (set intersection).

## Open Questions

None. Workshop Decision 4 resolved the schema-model ORQ-030/031 that gated this ADR. The capability-flags model is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-017)**: This ADR resolves the schema half of PC-017 (the typed-projection half is resolved by Decision 4 and ADR-119).
- **Operations (PC-107)**: ADR-119 (schema-as-code) — `msDS-Behavior-Version` and `objectVersion` are derived from `DC_CAPABILITIES`; schema changes that add new features add new capability bits.
- **Operations (PC-110)**: ADR-059 (PITR backup/DR) — a PITR restore rolls back `DC_CAPABILITIES` to the chosen timestamp's bitmask.
- **KDC (PC-023)**: ADR-123 (silver ticket) gates `pac_buffer_ticket_checksum` capability; ADR-012 (FAST-required) gates `fast_required`.
- **Auth Provider (PC-036)**: Decision 6 (NTLM drop) maps to the `ntlm_server_disabled` capability bit.
- **Security (PC-118/PC-119/PC-120)**: Golden/silver ticket mitigations and sIDHistory filtering are gated by their respective capability bits.
- **Migration (PC-126)**: Parallel-run requires feature-set equivalence between AD and the framework; `adrian-cli capabilities list` verifies this before cutover.

## References

- [PC-113](../catalog/10-operations.md) — problem statement (functional level upgrades are one-way; mixed-version forests are fragile)
- [Schema attributes KB](../docs/03-directory-schema/01-schema-attributes.md) — `objectVersion` table, schema update procedure, `msDS-Behavior-Version` semantics
- [Domains forests trees KB](../docs/00-overview/03-domains-forests-trees.md) — forest-wide replication, forest root, schema master FSMO role
- [Workshop Decision 4 — Schema model](../workshop/decision-04-schema-model.md) — hybrid LDAP schema + typed Rust projection; the substrate for capability-flags extensions
- [ADR-003 — Schema cache COW](./ADR-003-schema-cache-cow.md) — copy-on-write schema cache; the `DC_CAPABILITIES` bitmask is a typed projection field
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — capability-enable/disable audit events
- [ADR-061 — REST/gRPC API](./ADR-061-rest-grpc-api.md) — `GET /api/v1/capabilities` endpoint
- [ADR-119 — Schema-as-code](./ADR-119-schema-as-code-gitops.md) — schema changes add new capability bits
- [MS-ADTS §3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — `msDS-Behavior-Version`, `objectVersion`, functional level gating
- [MS-DRSR §5.39](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/) — `DRS_EXTENSIONS_V8` structure (the wire-format capability exchange)
