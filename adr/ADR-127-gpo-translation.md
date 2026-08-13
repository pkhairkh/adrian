---
title: "ADR-127: GPO Translation — ADMX-to-Canonical-JSON Compiler + Per-Setting Review Workflow"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Migration
problem: PC-125
severity: high
tags: [adr, migration, gpo, admx, preg, canonical-json, coverage-report, per-setting-review]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/12-migration-and-coexistence.md
  - ../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md
  - ../docs/04-group-policy/03-admx-templates.md
  - ../workshop/decision-04-schema-model.md
  - ../workshop/decision-07-policy-format.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
  - ./ADR-130-sysvol-migration.md
last_updated: 2026-08-13
---

# ADR-127: GPO Translation — ADMX-to-Canonical-JSON Compiler + Per-Setting Review Workflow

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 4 (schema model)](../workshop/decision-04-schema-model.md) which adopted the hybrid LDAP schema + typed Rust projection (the substrate for ADMX-to-typed-projection translation) and [Workshop Decision 7 (policy format)](../workshop/decision-07-policy-format.md) which adopted the canonical JSON policy format with the `admx2adrian` ADMX-to-JSON compiler. This ADR specifies the migration workflow that uses `admx2adrian` and `preg2adrian` for GPO translation.

## Context

AD GPOs are a multi-format assemblage per [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) and [`04-group-policy/03-admx-templates.md`](../docs/04-group-policy/03-admx-templates.md): (a) ADMX/ADML files (XML) defining policy schema and localised strings; (b) `Registry.pol` (PReg binary format) holding the actual registry value settings; (c) `GptTmpl.inf` (INI-style) holding the Security CSE settings (User Rights Assignment, Restricted Groups, Security Options); (d) Preferences XML files (Files.xml, Services.xml, ScheduledTasks.xml, Registry.xml, DriveMaps.xml, etc.) for Preferences CSE; (e) `Scripts` directories containing logon/logoff/startup/shutdown batch/PowerShell scripts; (f) `GPT.INI` with the version number. Each GPO is split into GPC (in AD) and GPT (in SYSVOL).

The framework's native policy format (per Decision 7) is canonical JSON, compiled to platform-native forms (PReg for Windows, MDM payloads for macOS, config fragments for Linux). Migration requires translating each AD format into the framework's canonical JSON. The translation surface: a typical enterprise has 100–500 GPOs, each containing 10–100 settings. Total: 1,000–50,000 settings to translate. Each translation requires: (1) read the ADMX to understand the policy intent, (2) read the Registry.pol to get the current value, (3) find the equivalent framework policy key, (4) translate the value (some values map 1:1, others require semantic translation — e.g. Windows `SeInteractiveLogonRight` → FreeIPA HBAC rule with `--services=login`), (5) review manually for fit (some Windows policies have no Linux/macOS equivalent — e.g. BitLocker PIN enforcement has no macOS equivalent).

Workshop Decision 7 specified the `admx2adrian` compiler (ADMX → JSON template) and `preg2adrian` reader (Registry.pol → JSON values). Decision 4 specified the typed Rust projection that the ADMX-to-JSON compiler consumes. This ADR specifies the migration workflow that uses these tools for GPO translation, including the per-setting review UI and the rollback path.

## Decision

The framework's GPO translation workflow uses Decision 7's `admx2adrian` and `preg2adrian` tools, plus a new `gpttmpl2adrian` (Security CSE) and `gppref2adrian` (Preferences CSE) translator, wrapped in a `adrian-cli migrate from-gpo` CLI that walks an AD GPO backup and produces canonical JSON policies per GPO. The CLI produces a per-setting review report that flags unknown or no-equivalent settings for manual review. The framework provides a per-setting review UI (web app) for operators to accept/modify/reject each translation.

The translation is **lossy on round-trip** (ADMX → JSON is one-way per Decision 7); the framework does not attempt to regenerate ADMX from JSON. The translation is **non-blocking** — settings with no framework equivalent are dropped with `WARN` and surfaced in the coverage report; the migration can proceed with the partial translation.

## Migration state machine

**Source state**: AD with 100–500 GPOs in ADMX/Registry.pol/GptTmpl.inf/Preferences XML format. SYSVOL replication active. GPOs are linked to OUs; clients receive GPOs via `gpsvc.dll`.

**Target state**: Framework-native canonical JSON policies per GPO. Framework's Policy Engine serves the translated policies to enrolled clients. Windows clients receive the framework's PReg-emitted `Registry.pol` via the synthetic CSE (per Decision 7); macOS clients receive MDM payloads; Linux clients receive config fragments.

**Coexistence period**: 90–180 days. During this window:
- Both AD GPO and framework policies may apply to clients (Windows clients still receive AD GPO via `gpsvc.dll`; framework-enrolled clients receive framework policies via `adrian-policy-daemon`).
- Per-setting translation is staged: high-priority GPOs (Security, AccountPolicy, AuditPolicy) are translated first; lower-priority GPOs (Preferences, Scripts) are translated later.
- The framework's `adrian-cli migrate from-gpo --gpo <gpo-guid>` command produces a per-GPO translation report. The report lists each setting's translation status: `translated` (1:1 mapping), `translated_with_semantic_shift` (mapping requires value translation), `no_framework_equivalent` (dropped with `WARN`), `manual_review_required` (ambiguous mapping).
- The framework's per-setting review UI (web app) lets operators review each translation: accept (apply as-is), modify (edit the translated value), or reject (skip the setting). Rejected settings are recorded in the migration audit log.
- The framework's audit pipeline (per ADR-060) emits an event for every translation accept/modify/reject with attributes `adrian.migration.gpo.source_guid`, `adrian.migration.gpo.setting_name`, `adrian.migration.gpo.translation_status`, `adrian.migration.gpo.review_action`, `adrian.migration.gpo.reviewer`.

**Cutover trigger**: When 100% of GPOs have been translated and validated on a pilot group of framework-enrolled clients for ≥30 days, the AD GPOs are disabled (`Set-GPLink -LinkEnabled No`). The framework's policies are the sole source of policy for framework-enrolled clients.

**Rollback path**: Re-enable AD GPOs (`Set-GPLink -LinkEnabled Yes`) on the affected OUs. Framework policies can be disabled or deleted. The translation table (per-GPO source-to-target mapping) is preserved for re-translation if needed. The framework's `adrian-cli migrate from-gpo --rollback --gpo <gpo-guid>` command re-enables the AD GPO and disables the framework's translated policy.

**Concrete specification**:

- The framework MUST ship the `admx2adrian` compiler (per Decision 7) that ingests an ADMX file pair (`.admx` + `.adml`) and emits a canonical JSON **policy template** plus a JSON Schema fragment. The compiler parses ADMX XML via `quick-xml`, walks the `policyDefinition` elements, and translates each `policy` element into a `PolicyArea`-typed setting skeleton.
- The framework MUST ship the `preg2adrian` reader (per Decision 7) that reads existing `Registry.pol` from an AD GPO backup and emits canonical JSON values for the `Registry` PolicyArea.
- The framework MUST ship a `gpttmpl2adrian` translator that reads `GptTmpl.inf` (Security CSE) and emits canonical JSON values for the `Security` PolicyArea (User Rights Assignment, Restricted Groups, Security Options). The translator parses the INI format via `rust-ini`.
- The framework MUST ship a `gppref2adrian` translator that reads Preferences XML files (Files.xml, Services.xml, ScheduledTasks.xml, Registry.xml, DriveMaps.xml) and emits canonical JSON values for the `Preferences.Files`, `Preferences.Services`, `Preferences.ScheduledTasks`, `Preferences.Registry`, `Preferences.DriveMaps` PolicyAreas. The translator parses the XML via `quick-xml`.
- The framework MUST expose `adrian-cli migrate from-gpo --gpo-backup <path> [--output <output-dir>]` that: (a) walks the GPO backup directory; (b) identifies the ADMX files referenced by the GPO; (c) runs `admx2adrian` on each ADMX; (d) runs `preg2adrian` on `Registry.pol`; (e) runs `gpttmpl2adrian` on `GptTmpl.inf`; (f) runs `gppref2adrian` on each Preferences XML; (g) emits a per-GPO translation report and a canonical JSON policy file.
- The translation report MUST classify each setting as: `translated` (1:1 mapping exists in the framework's curated mapping table), `translated_with_semantic_shift` (mapping requires value translation, e.g. Windows `SeInteractiveLogonRight` → framework `Security.PermitLogonLocally`), `no_framework_equivalent` (no mapping exists; setting is dropped with `WARN`), `manual_review_required` (mapping is ambiguous; operator must review).
- The framework MUST ship a per-setting review UI (web app) that displays the translation report and lets operators accept/modify/reject each setting. The UI is implemented as a React/TypeScript single-page app (per Decision 7's authoring UI); it calls the `adrian-policy-validate` library via WebAssembly for client-side schema validation.
- The framework's curated mapping table MUST cover the top 20 ADMX categories per [`10-comparison-matrices/05-gpo-equivalents-matrix.md`](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md): Password policy, Account lockout, User Rights Assignment, Security Options, Firewall, AppLocker, Drive Maps, File preference, Registry preference, Scheduled Tasks, Folder Redirection, Scripts, Printers, BitLocker, LAPS, Audit Policy, Kerberos Policy, NTP, Power Management, Defender.
- The framework MUST support rollback per-GPO: `adrian-cli migrate from-gpo --rollback --gpo <gpo-guid>` re-enables the AD GPO and disables the framework's translated policy. The rollback is audit-logged.
- The framework MUST expose `adrian-cli migrate from-gpo --coverage --gpo <gpo-guid>` returning per-GPO: `total_settings`, `translated`, `translated_with_semantic_shift`, `no_framework_equivalent`, `manual_review_required`, `coverage_percentage` (translated + translated_with_semantic_shift / total).
- The framework's audit pipeline MUST emit an OTel log record for every translation accept/modify/reject with the attributes listed above.
- The framework MUST emit a Prometheus metric `adrian_migration_gpo_translation_total{gpo,status}` (per ADR-057) — count of settings in each translation status per GPO.
- The framework MUST ship a default Prometheus alert: `adrian_migration_gpo_translation_total{status="no_framework_equivalent"} > 50 for 5m` triggers warning (high number of unmapped settings — migration may need manual rework).

## Rationale

The `admx2adrian` compiler is the one-time investment that pays for itself the first time a customer imports the Chrome ADMX and gets 200 managed-preferences keys for free (per Decision 7's rationale). The compiler is single-pass: stream-parse the ADMX, build the JSON template in memory, emit on completion. The `adml` (language resource) file is parsed alongside to provide human-readable display strings, emitted as a `_display` annotation on each setting.

The `gpttmpl2adrian` and `gppref2adrian` translators extend the coverage to the Security CSE and Preferences CSE, which `admx2adrian` does not cover (ADMX defines Registry-policy settings only; Security and Preferences have their own formats). The four translators together cover the full GPO format surface.

The per-setting review UI is the operational innovation. ADMT does not provide this; organisations discover translation gaps the hard way (a setting is silently dropped, a behaviour changes unexpectedly). The framework's UI surfaces every translation with status and lets operators accept/modify/reject. Rejected settings are recorded in the audit log, providing a complete record of what was migrated and what was deliberately skipped.

The curated mapping table is the framework's value-add. The top 20 ADMX categories cover the majority of enterprise GPOs (the long tail is vendor-specific ADMX that the framework cannot pre-map). The framework's mapping table is open-source and community-extensible — customers with vendor-specific ADMX can contribute mappings.

The non-blocking translation is the operational practicality. Settings with no framework equivalent are dropped with `WARN` and surfaced in the coverage report; the migration can proceed with the partial translation. This is the same posture as Decision 7's macOS/Linux compilation target (where settings with no MDM/Linux equivalent are dropped with `WARN`).

## Consequences

**Positive**: GPO translation is automated (per-GPO translation report + per-setting review UI). The four translators (admx2adrian, preg2adrian, gpttmpl2adrian, gppref2adrian) cover the full GPO format surface. The curated mapping table covers the top 20 ADMX categories. Rollback is per-GPO (granular). The coverage report makes translation gaps visible.

**Negative**: The translation is lossy (ADMX → JSON is one-way per Decision 7). Settings with no framework equivalent are dropped; organisations must accept the gap or write a framework-native policy from scratch. The curated mapping table is incomplete for vendor-specific ADMX; customers must extend the table or accept the gap. The per-setting review UI requires operator time (1–5 minutes per setting for `manual_review_required` items).

**Neutral**: The framework's translation does not preclude AD-interop scenarios where AD GPO continues to apply on AD-managed Windows hosts during the coexistence window. Framework-enrolled Windows hosts receive both AD GPO (via `gpsvc.dll` native CSEs) and framework policies (via the synthetic CSE per Decision 7); the two coexist without conflict because they target disjoint registry subtrees.

**Implementation cost**: ~5 person-months for the `gpttmpl2adrian` and `gppref2adrian` translators, the `adrian-cli migrate from-gpo` CLI, the per-setting review UI, the curated mapping table (top 20 ADMX categories), and the audit pipeline integration. Reuses Decision 7's `admx2adrian`, `preg2adrian`, `adrian-policy-core`, `adrian-policy-validate`, and the authoring UI's React/TypeScript stack.

**Operational impact**: Migration teams use `adrian-cli migrate from-gpo` to translate GPOs, the per-setting review UI to review translations, and `adrian-cli migrate from-gpo --coverage` to track migration progress. SOC analysts monitor the audit pipeline for translation accept/modify/reject events. SREs monitor `adrian_migration_gpo_translation_total` for migration progress.

## Alternatives Considered

**Alternative A: Manual translation only (no automation).** Operators manually translate each AD GPO setting to the framework's canonical JSON, reading the ADMX and writing the JSON by hand. Rejected because (a) a 50,000-user org with 300 GPOs averaging 50 settings each = 15,000 settings to translate; at 5–10 minutes per setting, that's 1,250–2,500 person-hours = 8–16 person-months of work; (b) manual translation is error-prone (typos in JSON keys, wrong value types); (c) the framework's value proposition is automating the tedious parts of migration.

**Alternative B: Pure ADMX preservation (no translation).** Preserve ADMX as the framework's policy format and ship a `gpsvc.dll`-equivalent on macOS and Linux that emulates the CSE dispatch loop (per Decision 7's Alternative A). Rejected by Decision 7 because ADMX is Windows-implementation-shaped (registry-path-centric, `enabledValue`/`disabledValue` bitmask) and forcing it onto macOS MDM and Linux config fragments produces the lowest-common-denominator leak that ADR-024 Alternative B rejected.

**Alternative C: Per-platform translation only (no canonical JSON).** Translate each AD GPO directly to platform-native forms (PReg for Windows, MDM for macOS, config fragments for Linux) without a canonical JSON intermediate. Rejected because (a) it triples the translation surface (one translator per platform); (b) the canonical JSON is the single authoring surface for new framework-native policies (per Decision 7); (c) the canonical JSON enables cross-platform parity (one policy applies to all three platforms).

**Alternative D: Cloud-based GPO translation service (SaaS).** Outsource GPO translation to a cloud service that ingests AD GPOs and emits framework-native policies. Rejected because (a) it couples the framework to a specific cloud service; (b) it does not work for air-gapped or on-premises deployments; (c) the framework's value proposition includes the translation tooling itself, not just the translated output.

## Open Questions

None. Workshop Decision 4 (schema model) and Decision 7 (policy format) resolved the ORQ-030/031 and ORQ-090/091 that gated this ADR. The GPO translation workflow is an implementation choice that does not gate further work.

## Cross-capability impact

- **Policy Engine (PC-046/PC-047/PC-052)**: Decision 7's `admx2adrian`, `preg2adrian`, `adrian-policy-core`, `adrian-policy-validate` are the substrate for this ADR's translators.
- **Operations (PC-106)**: ADR-057 (Prometheus + OTel) — `adrian_migration_gpo_translation_total` is the migration-progress metric.
- **Operations (PC-111)**: ADR-060 (audit logs) — translation accept/modify/reject audit events.
- **Migration (PC-107)**: ADR-119 (schema-as-code) — schema changes that add new ADMX-backed attributes are immediately available to the `admx2adrian` compiler via the typed projection.
- **Migration (PC-126)**: ADR-128 (Kerberos cross-realm during migration) — Kerberos Policy GPO translation is part of the migration workflow.
- **Migration (PC-130)**: ADR-130 (SYSVOL migration) — the framework's translated policies are served via the framework's SMB-served SYSVOL-equivalent share during coexistence.

## References

- [PC-125](../catalog/12-migration-and-coexistence.md) — problem statement (GPO translation from AD to framework-native requires manual mapping)
- [GPO equivalents matrix KB](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) — full ADMX setting × cross-platform equivalent matrix
- [ADMX templates KB](../docs/04-group-policy/03-admx-templates.md) — ADMX XML schema, `<policyElements>`, `<supportedOn>`, registry value types
- [Workshop Decision 4 — Schema model](../workshop/decision-04-schema-model.md) — hybrid LDAP schema + typed Rust projection; the substrate for ADMX-to-typed-projection translation
- [Workshop Decision 7 — Policy format](../workshop/decision-07-policy-format.md) — canonical JSON policy format; `admx2adrian` and `preg2adrian` tools; synthetic Windows CSE; per-platform compilation targets
- [ADR-029 — JSON canonical policy + PReg adapter](./ADR-029-json-canonical-policy-preg-adapter.md) — canonical JSON policy format; PReg adapter (output side) and reader (input side)
- [ADR-057 — Prometheus + OTel observability](./ADR-057-prometheus-otel-observability.md) — GPO translation progress metric
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — translation accept/modify/reject audit events
- [ADR-119 — Schema-as-code](./ADR-119-schema-as-code-gitops.md) — schema changes add new ADMX-backed attributes
- [ADR-130 — SYSVOL migration](./ADR-130-sysvol-migration.md) — framework's translated policies served via SMB-served SYSVOL-equivalent
- [MS-GPAC — Group Policy: Core Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — PReg format reference
- [ADMX schema reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/admx-backed-policy) — ADMX policy configuration
- [quick-xml crate](https://docs.rs/quick-xml) — streaming XML parser used by `admx2adrian` and `gppref2adrian`
- [rust-ini crate](https://docs.rs/rust-ini) — INI parser used by `gpttmpl2adrian`
