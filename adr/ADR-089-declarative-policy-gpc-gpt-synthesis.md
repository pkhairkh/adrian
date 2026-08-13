---
title: "ADR-089: Declarative canonical policy format with INI/Registry.pol AD-interop adapter (resolves PC-043)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-043
severity: high
unblocked_by: Workshop Decision 7
tags: [adr, policy-engine, gpo, declarative, json, preg, ini, gpt, gpc, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../workshop/decision-07-policy-format.md
  - ../docs/04-group-policy/01-gpo-architecture.md
  - ../docs/04-group-policy/05-gpt-gpc-structure.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
  - ./ADR-031-git-backed-policy-history.md
  - ./ADR-094-sysvol-replication-git-backed.md
last_updated: 2026-08-14
---

# ADR-089: Declarative canonical policy format with INI/Registry.pol AD-interop adapter (resolves PC-043)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 7](../workshop/decision-07-policy-format.md) (Policy format: hybrid declarative JSON + ADMX compiler + PReg adapter). This ADR operationalises Decision 7's canonical-format and adapter specifications against the PC-043 problem surface: the GPC/GPT split that AD's Group Policy Container/Template model imposes, and the framework's choice between preserving that split, abandoning it for a single source of truth, or externalising policy to Git/object-store with GPC/GPT views as a compat shim.

## Context

AD represents each Group Policy Object as two halves that must stay in sync:

- The **Group Policy Container (GPC)** — a `groupPolicyContainer` directory object (governsID `1.2.840.113556.1.5.108`) at `CN=Policies,CN=System,<domain-dn>`. It carries `gPCFileSysPath` (UNC into SYSVOL), `gPCMachineExtensionNames`/`gPCUserExtensionNames` (the CSE-GUID ordering list), `versionNumber` (OID `1.2.840.113556.1.4.1340` — a 64-bit integer packed as `(userVersion << 32) | (machineVersion & 0xFFFFFFFF)`), `gPLink`-inherited binding from SOM containers, and `gPCWQLFilter` for WMI filters.
- The **Group Policy Template (GPT)** — a folder under `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\` containing `GPT.INI` (with the matching `Version=` line and `DisplayName=`), `Machine/Registry.pol`, `User/Registry.pol`, `Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf` (INI syntax: `[Unicode]`, `[Version]`, `[Privilege Rights]`, `[System Access]`), `Machine/Scripts/Startup/Scripts.ini`, `Machine/Preferences/*` (14+ XML files consumed by `gppref.dll`), and the ADMX Central Store under `PolicyDefinitions/`.

The split is fragile by construction, per [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md). The GPC replicates via DRSUAPI inside the Configuration NC; the GPT replicates via DFS-R (`dfsr.exe`, RPC UUID `91b7b931-c75a-4530-8258-1b3eb578c5d8`) over the SYSVOL Replication Group. Two independent replication channels with independent schedules, backlogs, and failure modes — and the only coherence invariant is `gpsvc.dll`'s client-side version reconciliation at refresh time. When DFS-R lags (the `dfsrdiag backlog` reveals this), or when admins hand-edit the GPT folder under SYSVOL (a long-standing antipattern), `GPC.versionNumber` and `GPT.INI Version` diverge. Per the analysis in [docs/04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md), `gpsvc.dll` reads `GPT.INI` at every refresh, compares `Version` to the cached `versionNumber` from the GPC, and on mismatch falls back to the GPC value and re-reads the GPT files — but clients may briefly apply stale policy or skip the refresh entirely. Samba AD-DC's SYSVOL replication via DRSUAPI on the SysVol directory is a different mechanism with different failure modes (no RDC, no conflict-and-deleted folder, no `dfsrdiag` tooling). The split is incompatible with the framework's goal of transactional policy apply (ADR-025) and Git-backed policy history (ADR-031).

Workshop Decision 7 (§1, §4, §6) fixes the framework's policy authoring and distribution surface: the canonical policy document is a JSON object (`apiVersion: adrian/v1`, `kind: Policy`, `metadata.{name,version,priority,ttl_seconds}`, `spec.{target,areas[]}`), versioned in Git, distributed via the framework's WebSocket push (ADR-028) with HTTPS pull fallback, and compiled to platform-native forms on the distribution host. For Windows-interop, the distribution host additionally emits `Registry.pol` (PReg), `GptTmpl.inf`, `Scripts.ini`, `Audit.csv`, and GPP XML files into the SMB-served SYSVOL-equivalent share (per Decision 10 §10) so legacy `gpsvc.dll` + native CSEs continue to function. The synthetic Windows CSE (per ADR-024 + Decision 7 §6) consumes `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Adrian\policy.json` for non-Registry areas.

This ADR resolves the GPC/GPT-split problem (PC-043) by defining how the framework replaces the split with a single source of truth (canonical JSON in Git) while still presenting a GPC + GPT view to legacy Windows clients.

## Decision

The framework **abandons the GPC/GPT split for framework-authored policy** and uses canonical JSON in Git as the single source of truth. For AD-interop with existing Windows `gpsvc.dll`, the framework's policy distribution service synthesises a GPC-equivalent directory object and a GPT-equivalent SMB folder structure on demand, both derived from the canonical JSON. The synthesis is one-way (JSON → GPC/GPT view); the framework never reads the synthesised GPC/GPT back into canonical form. The split's coherence invariant (`versionNumber` ↔ `Version=`) is enforced by construction because both values are derived from the same JSON document's `metadata.version` field at synthesis time.

### Concrete specification

1. **Single source of truth.** The canonical JSON policy document (per Decision 7 §1 and ADR-029) is the authoritative policy representation. The document is committed to the framework's Git-backed policy repository (per ADR-031); Git is the system of record. There is no GPC directory object authored directly, no GPT folder edited by operators, no `Version=` line maintained by hand. The framework's `adrian-policy validate` CLI runs on every commit (pre-commit hook + CI), rejecting documents that fail schema validation or CEL-selector compilation.

2. **GPC-equivalent directory object (synthesised).** The framework's policy distribution service (`adrian-policy-distribution`, a Rust service per Decision 7 §11) reads canonical JSON from Git and synthesises a `groupPolicyContainer`-equivalent object in the framework's directory at `CN=Policies,CN=System,<domain-dn>`. The synthesised object carries: `cn` = the framework's policy GUID; `gPCFileSysPath` = `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\`; `gPCMachineExtensionNames` = the CSE-GUID ordering list derived from the policy's `areas[]` (Registry CSE GUID for `Registry` area, framework-synthetic-CSE GUID for non-Registry areas, plus the appropriate native CSE GUIDs for `Security`, `Scripts`, `AuditPolicy`, `Preferences` — see Decision 7 §4); `versionNumber` = the JSON document's `metadata.version` field truncated/reinterpreted as the 64-bit packed `(userVersion << 32) | machineVersion` representation (the framework derives `userVersion` and `machineVersion` from the policy's `target.scope` field — `machine` only, `user` only, or both). The synthesised object is replicated to all framework DCs via the framework's directory replication (DRSUAPI in AD-interop mode, Raft in native mode, per Decision 1).

3. **GPT-equivalent SMB folder (synthesised).** The distribution service writes the GPT folder to the framework's SMB-served SYSVOL-equivalent share (per Decision 10 §10) at `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\`. The folder contains: `GPT.INI` (with `Version=` derived from `metadata.version`, `DisplayName=` derived from `metadata.name`); `Machine/Registry.pol` and `User/Registry.pol` (PReg-encoded per ADR-029 from `area == "Registry"` settings); `Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf` (INI-encoded from `area == "Security"` settings, with `[Privilege Rights]` populated from URA settings and `[System Access]` from account-policy settings); `Machine/Scripts/Startup/Scripts.ini` and `Shutdown/Scripts.ini` (INI-encoded from `area == "Scripts"` settings); `Machine/Microsoft/Windows NT/Audit/audit.csv` (from `area == "AuditPolicy"` settings); `Machine/Preferences/<area>.xml` (GPP-XML-encoded from `area == "Preferences.<area>"` settings — see ADR-091 for the GPP compilation); and `Adrian/policy.json` (the canonical JSON document itself, consumed by the framework's synthetic CSE per Decision 7 §6).

4. **Atomicity by construction.** Because the synthesised GPC object and GPT folder are both derived from the same JSON document at synthesis time, the version-mismatch invariant (`GPC.versionNumber == GPT.INI Version`) holds by construction. The distribution service writes the GPT folder first (atomic rename of a staging directory into the final path), then writes the GPC object via an LDAP `MODIFY` operation; on failure, the staging directory is rolled back. The framework's transactional-policy-rollback trait (per ADR-025) provides the snapshot/rollback contract that the distribution service uses for the GPT write.

5. **`gPLink` and `gPOptions` semantics.** The framework preserves AD's `gPLink` (OID `1.2.840.113556.1.4.1361`) and `gPOptions` (block inheritance) on SOM containers (Site, Domain, OU) for LSDOU processing (per PC-044, resolved separately). Operators bind framework policies to SOM containers via `adrian-policy bind --policy <name> --som <dn> --priority <n>`; the CLI writes the `gPLink` attribute on the SOM container in the framework's directory. The framework's LSDOU evaluation (per ADR-030's role-based binding) honours `gPLink` ordering and `gPOptions` flags.

6. **WMI filter replacement.** The framework does not preserve AD's `msFTSI` WMI filter objects (per ADR-026). Framework policies use CEL selectors (per Decision 7 §10) targeting the declarative host-facts document (per ADR-026). For AD-interop, the framework's distribution service emits an empty `gPCWQLFilter` on the synthesised GPC (no WMI filter); the framework's synthetic CSE on Windows ignores WMI filters for framework-authored GPOs (the CEL selector is evaluated against host facts before policy is pushed, so the GPO is only delivered to hosts that match).

7. **Version reconciliation on Windows clients.** Legacy Windows clients running `gpsvc.dll` see the synthesised GPC and GPT and process them as native GPOs. The `versionNumber` reconciliation logic in `gpsvc.dll` works unchanged: `gpsvc` reads `GPT.INI Version=`, compares to the cached `versionNumber`, and re-applies on mismatch. Because both values are derived from `metadata.version`, the reconciliation succeeds on the first refresh after a policy update; there is no DFS-R lag window.

8. **Decommissioning.** When all Windows clients in a forest are migrated to the framework's Client SDK (per Decision 11), the framework's distribution service stops synthesising GPC/GPT objects (the synthesis is gated by a `policy.legacy_compat = true|false` per-forest setting). Once `legacy_compat = false`, the GPC directory container `CN=Policies,CN=System,<domain-dn>` is preserved for migration audit purposes but no new objects are written; the SYSVOL-equivalent share retains the `Adrian/policy.json` files for SDK-enrolled clients only.

## Rationale

Three alternatives were considered.

**Alternative A: Preserve the GPC/GPT split natively.** Maintain GPC as a first-class directory object and GPT as a first-class SMB folder, both written by the framework's authoring UI directly. Rejected because (a) the split's coherence invariant (`versionNumber == Version`) is enforced by nothing in AD itself — it's a client-side reconciliation that tolerates divergence; preserving the split in the framework inherits the divergence bug; (b) two replication channels (DRSUAPI for GPC, DFS-R for GPT) doubles the failure surface, and the framework has explicitly declined to implement DFS-R (per Decision 10 trade-off §"No DFS-R" and ADR-094); (c) operators hand-editing GPT files under SYSVOL is the most common cause of GPO drift in AD; preserving the GPT as a writable surface preserves the antipattern.

**Alternative B: Drop the GPC/GPT split entirely; framework-SDK-only clients.** Author policy as canonical JSON in Git, distribute via WebSocket (ADR-028), require all clients to run the framework's Client SDK. Rejected because (a) during migration, Windows hosts are in a mixed state (some SDK-enrolled, some still AD-enrolled with native `gpsvc.dll`); the framework cannot serve policy to AD-enrolled Windows hosts without the GPC/GPT view; (b) third-party Windows software that hooks `IGroupPolicy` COM APIs (e.g., `gpresult`, GPO backup/restore tools, audit tools) cannot operate without the GPC/GPT; (c) the framework's migration value proposition (drop-in AD replacement) requires that existing Windows GPO tooling continues to work during the multi-year migration window. The hybrid synthesis approach (canonical JSON source-of-truth + synthesised GPC/GPT view) provides interop without making the split a first-class concept.

**Alternative C: Externalise to Git/object-store with GPC/GPT views as a compat shim — but synchronise GPC/GPT back into Git.** Allow operators to edit GPC attributes or GPT files directly, then sync those changes back into the canonical JSON. Rejected because (a) round-tripping through the GPC/GPT format loses the canonical JSON's typed value model (PReg's REG_SZ/REG_DWORD ambiguity, INI's lack of nested types, GPP XML's per-area schemas); (b) the ADMX-to-JSON compiler (per Decision 7 §3 and ADR-090) is one-way by design; reverse-compilation from GPC/GPT back to canonical JSON is not supported; (c) bidirectional sync creates merge-conflict scenarios that the framework's Git workflow cannot resolve (a Git-side change to a JSON setting conflicts with a GPT-side change to the same setting's `Registry.pol` representation).

The chosen model — canonical JSON in Git as single source of truth, synthesised one-way GPC/GPT view for AD-interop — eliminates the split's coherence bug while preserving AD-interop. The synthesis cost is one-time per policy update (the distribution service regenerates the GPC/GPT on every commit); the runtime cost is zero (Windows clients read the synthesised GPC/GPT as native GPOs).

## Consequences

**Positive**. The GPC/GPT version-mismatch class of bugs is eliminated by construction: both values derive from the same JSON `metadata.version`. The framework's Git workflow (per ADR-031) provides policy versioning, history, and rollback — replacing `Backup-GPO`/`Restore-GPO` and the manual GPO-version-tracker spreadsheets that operators maintain in AD environments. Transactional apply (ADR-025) becomes possible because the framework's `PolicyExecutor::snapshot`/`rollback` contract operates on the canonical JSON, not on the GPC/GPT pair.

**Negative**. The framework's distribution service must implement and maintain the GPC-synthesis (LDAP writes) and GPT-synthesis (PReg/INI/XML emission) code paths for the duration of Windows-mixed-mode operation (potentially 5-7 years, per Decision 8's MS-WCCE bridge deprecation timeline). The synthesis is non-trivial: PReg's UTF-16LE edge cases (per ADR-029), GPP XML's per-area schemas (per ADR-091), and `GptTmpl.inf`'s INI quirks (e.g., the `[Privilege Rights]` SDDL-with-`*S-1-5-32-544` syntax that `scecli.dll` parses) must be reproduced exactly.

**Neutral**. The framework's directory container `CN=Policies,CN=System,<domain-dn>` is preserved for AD-interop; it holds synthesised `groupPolicyContainer` objects during legacy-compat mode and is empty (or holds archived objects) after `legacy_compat = false`. The framework's `adrian-policy unbind` CLI removes both the `gPLink` attribute on the SOM container and the synthesised GPC/GPT entries atomically.

**Implementation cost**. ~5 person-weeks for v1: GPC synthesis (1 pw), GPT synthesis reusing ADR-029's PReg adapter and ADR-091's GPP compiler (2 pw), `gPLink`/`gPOptions` binding CLI (1 pw), integration tests against Windows Server 2022 `gpsvc.dll` (1 pw). Ongoing maintenance: ~1 person-week per year for AD-format edge cases (rare Microsoft-format revisions).

**Operational impact**. Operators author policy via the framework's UI (which emits canonical JSON) or via Git PR (JSON committed directly). Operators bind policies to SOM containers via `adrian-policy bind`. The `adrian-policy compile --target windows` CLI previews the synthesised GPC/GPT without writing it. The framework's audit log records every policy commit, bind, and distribution push.

## Alternatives Considered

### Alternative A: Preserve GPC/GPT split natively

Maintain GPC and GPT as first-class framework objects, written directly by the framework's authoring UI. The framework's directory stores `groupPolicyContainer` objects as native directory entries (not synthesised from JSON); the framework's SYSVOL-equivalent share stores the GPT folder as a native filesystem layout (not synthesised).

Rejected as detailed in §Rationale: the split's coherence invariant is enforced by nothing; two replication channels double the failure surface; preserving the GPT as a writable surface preserves the hand-edit antipattern. The synthesis approach (chosen) provides the same AD-interop surface while making the framework's source-of-truth a single object.

### Alternative B: Framework-SDK-only clients (no GPC/GPT view)

Drop the GPC/GPT view entirely; require all Windows clients to run the framework's Client SDK and consume canonical JSON directly via WebSocket push.

Rejected as detailed in §Rationale: migration-period Windows hosts in mixed state cannot be served; third-party Windows GPO tooling breaks; the framework's drop-in-AD-replacement value proposition requires the GPC/GPT view. The synthesis approach provides AD-interop without forcing an SDK-enrollment migration gate.

### Alternative C: Bidirectional GPC/GPT ↔ JSON sync

Allow operators to edit GPC attributes or GPT files directly via existing AD tooling (`GPMC.msc`, `Set-GPRegistryValue`, hand-edits to `Registry.pol`); the framework's distribution service watches for GPC/GPT changes and reverse-syncs them into the canonical JSON.

Rejected as detailed in §Rationale: round-tripping through GPC/GPT loses the canonical JSON's typed value model; the ADMX-to-JSON compiler (ADR-090) is one-way by design; bidirectional sync creates merge-conflict scenarios that Git cannot resolve. The synthesis approach is one-way (JSON → GPC/GPT) and unambiguous.

## Open Questions

- **GPC `versionNumber` packing for user-only or machine-only policies.** AD packs `versionNumber` as `(userVersion << 32) | machineVersion`; a user-only policy has `machineVersion = 0`, a machine-only policy has `userVersion = 0`. The framework's `target.scope` field (`user`, `machine`, `both`) maps cleanly to the packing — `user` → `(v << 32) | 0`, `machine` → `0 | v`, `both` → `(v << 32) | v` (same version on both halves). This is implemented as documented; revisit if Windows `gpsvc` shows refresh-skew between user and machine halves.
- **Decommissioning audit.** When `legacy_compat = false` is set, should the framework retain the `CN=Policies,CN=System,<domain-dn>` container with synthesised objects (read-only, archived) or delete it? Current decision: retain for 1 year post-decommission for migration audit, then delete via `adrian-policy purge-legacy-gpc`. Revisit if directory-size constraints require earlier deletion.
- **`gPCUserExtensionNames` and the synthetic CSE ordering.** The CSE-GUID ordering list in `gPCMachineExtensionNames`/`gPCUserExtensionNames` controls CSE invocation order on Windows. The framework's synthetic CSE GUID is appended last (highest priority) so framework areas apply after native CSEs; revisit if a policy needs framework-area application before a native CSE (none currently identified).

## Cross-capability impact

- **Policy Engine (PC-044 LSDOU conflict resolution)**: The synthesised GPC's `gPLink` ordering is consumed by the framework's LSDOU evaluator (per ADR-030 role-based binding). The framework's per-setting precedence model (per ADR-030) is layered on top of the synthesised GPC's LSDOU ordering.
- **Policy Engine (PC-052 PReg format)**: ADR-029's PReg adapter is reused by the distribution service's GPT synthesis for `Registry.pol` emission.
- **Policy Engine (PC-046 ADMX schema)**: ADR-090's ADMX-to-JSON compiler imports existing ADMX-defined policies into canonical JSON; the synthesised GPC/GPT view emits them back as native GPOs for legacy Windows clients.
- **File Gateway (Decision 10)**: The SMB server exposes the synthesised GPT folder via the SYSVOL-equivalent share. The Git-backed policy repository (per ADR-031) is the backing store for the `Adrian/policy.json` files in the GPT.
- **Migration (PC-127 GPO-to-framework)**: The `adrian-migrate from-gpo` CLI ingests an AD GPO backup, runs `preg2adrian` on `Registry.pol` and `admx2adrian` on the ADMX templates, and emits canonical JSON; the framework's distribution service then re-synthesises the GPC/GPT view for AD-interop. Migration is a round-trip through canonical JSON, not a direct GPO-to-GPO copy.
- **Operations (PC-115 unified CLI)**: The `adrian-policy` CLI subcommands (`bind`, `unbind`, `compile --target windows`, `purge-legacy-gpc`) are part of the framework's unified CLI per ADR-063.

## References

- [PC-043](../catalog/04-policy-engine.md) — problem statement in the catalog
- [Workshop Decision 7](../workshop/decision-07-policy-format.md) — Policy format: hybrid declarative JSON + ADMX compiler + PReg adapter
- [docs/04-group-policy/01-gpo-architecture.md](../docs/04-group-policy/01-gpo-architecture.md) — GPC/GPT split, `gPCFileSysPath` UNC linkage, version-stamp coupling
- [docs/04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md) — `GPT.INI` format, `versionNumber` packing, `gpsvc.dll` reconciliation
- [ADR-029](./ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy format; PReg adapter (reused by the GPT synthesis)
- [ADR-024](./ADR-024-per-platform-policy-executors.md) — per-platform policy executors (the synthetic Windows CSE)
- [ADR-025](./ADR-025-transactional-policy-rollback.md) — transactional policy application (snapshot/rollback contract)
- [ADR-026](./ADR-026-declarative-host-facts-wmi-adapter.md) — declarative host facts (replaces WMI filters)
- [ADR-028](./ADR-028-push-based-policy-websocket.md) — push-based policy distribution (WebSocket)
- [ADR-030](./ADR-030-role-based-policy-binding.md) — role-based policy binding (LSDOU + per-setting precedence)
- [ADR-031](./ADR-031-git-backed-policy-history.md) — Git-backed policy history
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol (GPC/GPT reference)
