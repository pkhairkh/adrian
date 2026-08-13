---
title: "ADR-090: ADMX-to-declarative-JSON compiler `admx2adrian` (resolves PC-046)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-046
severity: high
unblocked_by: Workshop Decision 7
tags: [adr, policy-engine, admx, adml, compiler, json, migration, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../workshop/decision-07-policy-format.md
  - ../docs/04-group-policy/03-admx-templates.md
  - ../docs/04-group-policy/05-gpt-gpc-structure.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
  - ./ADR-089-declarative-policy-gpc-gpt-synthesis.md
  - ./ADR-031-git-backed-policy-history.md
last_updated: 2026-08-14
---

# ADR-090: ADMX-to-declarative-JSON compiler `admx2adrian` (resolves PC-046)

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 7](../workshop/decision-07-policy-format.md) §3, which specifies that the framework ships `admx2adrian` — a Rust binary that ingests an ADMX file pair (`.admx` + `.adml`) and emits a canonical JSON policy template plus a JSON Schema fragment. This ADR operationalises Decision 7's compiler specification against the PC-046 problem surface: the Windows-specificity of ADMX and the fragmentation of cross-platform policy-definition formats.

## Context

ADMX (Administrative Template XML, since Vista/Server 2008) is the policy-definition format for AD Group Policy's Registry-policy surface. Per [docs/04-group-policy/03-admx-templates.md](../docs/04-group-policy/03-admx-templates.md), ADMX files live either in the local `%SystemRoot%\PolicyDefinitions\` directory or the SYSVOL Central Store at `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\`, with language-specific ADML files in `<locale>\` subdirectories (`en-US\`, `de-DE\`, `fr-FR\`, etc.). The schema is `policyDefinitions.xsd` (shipped in the Windows SDK); the root element is `<policyDefinitions>` with `<revision>`, `<schemaVersion>`, `<policyNamespaces>` (declaring the `target` namespace prefix and `using` references to other ADMX namespaces), `<supersededAdm>`, `<categories>` (a tree of `<category>` elements with `name`, `displayName`, `parentCategory`, `explainText`), `<policies>` (the actual `<policy>` elements), and `<supportedOn>` (a `<definitions>` block of `<definition>` elements naming Windows version SKUs).

Each `<policy>` element has: `name` (a stable ID like `Pol_Ciphers_AES128`, used as the canonical key in the framework's JSON output), `class` (`Machine` or `User`), `displayName` (an ADML resource reference like `$(string.Pol_Ciphers_AES128)`), `explainText` (also ADML-referenced), `key` (the registry key path, e.g., `SOFTWARE\Policies\Microsoft\Cryptography\AES128`), `valueName` (the registry value name, e.g., `Enabled`), `parentCategory` (a reference to a `<category>` `ref`), `supportedOn` (a reference to a `<supportedOn>` `ref`, e.g., `SUPPORTED_Win10_1809`), and one of three value models: (a) `<boolean>` with `<enabledValue>` and `<disabledValue>` `<decimal>`/`<string>` children, plus optional `<enableKey>` for delete-on-disable; (b) `<elements>` containing one or more of `<boolean>`, `<decimal>`, `<text>`, `<enum>`, `<multitext>`, `<list>`, `<longDecimal>` — each with a `valueName` and type-specific child elements; or (c) a no-value policy (just the registry key presence toggle). ADMX's `presentation` element (a sibling of `<policy>` in `<policies>` or inline) defines the UI form layout via `<textBox>`, `<checkBox>`, `<comboBox>`, `<dropdownList>`, `<listBox>`, `<text>` labels — referenced from the policy's `presentation` attribute.

ADMX is Windows-implementation-shaped: the value model is registry-path-centric (`key`/`valueName`), the typed-value system is REG_SZ/REG_DWORD/REG_MULTI_SZ (with `enabledValue`/`disabledValue` bitmask semantics that have no analogue in macOS MDM or Linux config), the supportedOn predicate is `windows:versions`-only (no macOS/Linux version constraints), and the presentation model assumes a Windows-GPMC-style form. macOS MDM uses per-payload schemas (no unified ADMX-equivalent); SSSD has no ADMX parser (it consumes only the `[Privilege Rights]` subset of `GptTmpl.inf`, per [docs/09-linux-equivalents/03-sssd-gpo-access.md](../docs/09-linux-equivalents/03-sssd-gpo-access.md)); Samba's `samba-gpupdate` reads `Registry.pol` and translates a fixed set of known policy keys to Linux config files (`/etc/krb5.conf`, `/etc/security/limits.conf`, `/etc/sudoers.d/`) but does not parse ADMX. FreeIPA uses native LDAP attributes per-policy-area (`ipaPwpolicy`, `ipaHbacrule`, `ipaSudorule`) — no XML template concept. The matrix in [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md) shows the fragmentation.

Workshop Decision 7 §3 fixes the framework's answer: ship `admx2adrian`, a one-way ADMX-to-JSON compiler that emits canonical JSON policy templates plus JSON Schema fragments. The compiler handles Microsoft's built-in ADMX set (~3,500 policies across 75 ADMX files for Windows 11 23H2) plus customer-specific ADMX (Chrome, Office, Zoom, Edge — typically 500-2,000 additional policies). This ADR defines the compiler's parsing model, the ADMX-to-JSON type mapping, the lossiness contract, and the migration CLI.

## Decision

The framework ships `admx2adrian` as a Rust binary in the `admx2adrian` workspace crate. The compiler ingests one ADMX file and its companion ADML file(s) and emits a canonical JSON policy template per `<policy>` element plus a JSON Schema fragment per ADMX file. The compiler is single-pass (stream-parse ADMX via `quick-xml`, build the JSON output in memory, emit on completion), deterministic (same ADMX input → byte-identical JSON output, for reproducible builds and Git diffs), and one-way (no JSON-to-ADMX reverse compiler).

### Concrete specification

1. **Input contract.** `admx2adrian` accepts a single `.admx` file path (required) and one or more `.adml` file paths (one per locale; `--adml en-US` is the default; `--adml en-US,de-DE,fr-FR` produces a multi-locale output). The compiler refuses to run without at least one ADML file (the ADMX's `displayName` and `explainText` references are unresolved without it). The compiler accepts a `--namespace-mapping <file>` flag for cross-namespace references (e.g., a vendor ADMX that uses `Microsoft.Policies.Windows` via `<using prefix="windows" namespace="Microsoft.Policies.Windows">` requires the Microsoft Windows ADMX on the search path; the namespace-mapping file records `windows → /usr/share/adrian/admx/windows.admx`).

2. **Output contract.** The compiler emits, per ADMX file:
   - A `<admx-file-name>.policies.json` file containing an array of canonical JSON `PolicyTemplate` objects (one per `<policy>` element). Each template is the framework's `PolicyDoc` schema (per ADR-029) with `apiVersion: adrian/v1`, `kind: PolicyTemplate`, `metadata.{name, source_admx, source_adml_locales}`, `spec.target.facts.os.windows_version` (from `supportedOn`), `spec.areas[]` (a single `Registry` area per ADMX policy), and `spec.areas[0].settings{}` (one setting per ADMX `<elements>` element, plus the policy-level boolean toggle).
   - A `<admx-file-name>.schema.json` file containing a JSON Schema fragment defining the policy-template's structure, suitable for inclusion in the framework's authoring UI's schema catalogue.
   - A `<admx-file-name>.catalog.json` file containing the category tree (`<categories>` → `categories[]` with `name`, `display_name`, `parent`, `explain_text`), consumed by the authoring UI's category navigation.
   - A `<admx-file-name>.pres.json` file containing the presentation form-layout per policy (the ADMX `<presentation>` element translated to a UI-layout descriptor), consumed by the authoring UI's form renderer.

3. **Type mapping (ADMX element → framework TypeEnum).** Per Decision 7 §3:
   - ADMX `<boolean>` → framework `TypeEnum::Boolean`. ADMX's `<enabledValue>` and `<disabledValue>` children (each a `<decimal>` or `<string>`) are preserved as `value_when_enabled` and `value_when_disabled` annotations on the setting (not flattened into the boolean value, because the framework's `Boolean` type is a pure true/false — the registry-write semantics are handled by the PReg adapter at compile-to-Windows time).
   - ADMX `<decimal>` and `<longDecimal>` → framework `TypeEnum::Integer`. The `min`/`max` constraints (ADMX `<decimal>` attributes) are preserved as a `range` annotation.
   - ADMX `<text>` → framework `TypeEnum::String`. ADMX's `maxLength` attribute is preserved as a `max_length` annotation.
   - ADMX `<enum>` → framework `TypeEnum::String` with a `enum_values` annotation listing the supported values (the enum's `<item>` children, each with a `displayName` ADML reference and a `<value>`). The framework's `TypeEnum::String` is used instead of a dedicated `TypeEnum::Enum` because the enum semantics are authoring-UI concerns (a dropdown), not type-system concerns.
   - ADMX `<multitext>` → framework `TypeEnum::StringList`.
   - ADMX `<list>` → framework `TypeEnum::StringList` with a `registry_value_suffix` annotation preserving the per-row registry value naming convention ADMX uses (e.g., `1`, `2`, `3` suffix or `*` wildcard).
   - ADMX `key`/`valueName` → preserved as an `admx.registry.{key, value_name}` annotation on the setting, consumed by the PReg adapter (per ADR-029) when emitting `Registry.pol`.
   - ADMX `supportedOn` → translated to a `target.facts.os.windows_version` predicate in CEL (`os.name == "windows" && os.version >= "10.0.17763"` for `SUPPORTED_WinServer2019`). The mapping table from Microsoft's `SUPPORTED_*` mnemonics to Windows build numbers is bundled with the compiler (sourced from `MSFT_SupportedOn` definitions in Microsoft's ADMX).
   - ADMX `parentCategory` → preserved as a `category` annotation referencing the category tree in the `.catalog.json` output.

4. **ADML localization.** ADML files are JSON-formatted (per the ADMX schema, ADML uses `<stringTable>` and `<presentationTable>` elements). The compiler extracts each `<string>` element by `id` and substitutes the `$(string.<id>)` references in the ADMX's `displayName`, `explainText`, and enum-item `displayName` fields. For multi-locale output, the compiler emits a `_display` object per setting with `display_name` and `explain_text` keyed by locale (`en-US`, `de-DE`, `fr-FR`). The authoring UI renders the user's preferred locale from `_display`.

5. **Lossiness contract (one-way compilation).** Per Decision 7 §3, the compiler is **lossy on round-trip** — the following ADMX features are flattened and cannot be reconstructed by a hypothetical JSON-to-ADMX reverse compiler:
   - ADMX's `boolean` inverted-value semantics (where `<enabledValue>` is `0` and `<disabledValue>` is `1` for inverted policies) are flattened to `value_when_enabled` / `value_when_disabled` annotations; the framework's `Boolean` type carries true/false, and the inversion is recorded as a `registry_inverted: true` annotation.
   - ADMX's `<enableKey>` deletion-on-disable (where the registry key is deleted when the policy is disabled) is flattened to a `delete_on_disable: true` annotation; the synthetic Windows CSE handles the deletion at apply time.
   - ADMX's `range` constraints on `<decimal>` elements (the `min`/`max` attributes) are preserved as a `range` annotation but not enforced by the framework's `TypeEnum::Integer` (enforcement is at authoring-UI time via the schema; runtime enforcement is the executor's responsibility).
   - ADMX's `<supportedOn>` reference (a single `windows:versions` mnemonic) is translated to a CEL predicate; the framework's `target.facts.os` schema supports additional predicates (macOS version, Linux distro) that ADMX cannot express, so the round-trip would lose the framework's richer targeting.
   
   The compiler documents the lossiness in the output JSON's `_lossy_from_admx` field, listing the specific ADMX features flattened. This is the framework's explicit authoring contract: ADMX is the migration entry point, not a long-term authoring surface.

6. **`<using>` namespace resolution.** ADMX files reference other ADMX namespaces via `<using prefix="<prefix>" namespace="<namespace>">`. The most common is `windows` → `Microsoft.Policies.Windows` (the Microsoft built-in ADMX). The compiler resolves `<using>` references by looking up the namespace in the `--namespace-mapping` file, loading the referenced ADMX, and resolving any cross-namespace `<category>` or `<supportedOn>` references. Cross-namespace `<category>` references (a vendor ADMX placing its policy under a Microsoft-defined category) are resolved by emitting the vendor policy's `category` annotation with the fully-qualified path (`windows:WindowsComponents/MyVendor:MyCategory`).

7. **Migration CLI.** The framework's `adrian-migrate from-gpo` CLI (per Decision 7 §Migration cross-capability and ADR-089) walks an AD GPO backup directory, identifies the ADMX files referenced by the GPO's `gPCMachineExtensionNames` (or, for hand-authored GPOs without ADMX backing, infers the ADMX from the `Registry.pol`'s registry key paths via a reverse-lookup table bundled with the compiler), runs `admx2adrian` on each referenced ADMX, and emits canonical JSON policy templates plus the GPO's instance values (the actual `Registry.pol` settings, decoded by `preg2adrian` per ADR-029 and merged into the templates' `settings` blocks).

8. **Continuous integration.** The framework's CI runs `admx2adrian` against Microsoft's complete built-in ADMX set (downloaded from the Windows 11 23H2 ADMX bundle on each CI run) plus a curated set of vendor ADMX files (Chrome, Edge, Office, Zoom, Adobe Reader, MS Defender for Endpoint). The CI asserts: (a) zero compiler errors across all ADMX files; (b) the emitted JSON passes schema validation; (c) the JSON-to-PReg round-trip (via the PReg adapter, per ADR-029) produces a `Registry.pol` byte-identical to the original AD-emitted `Registry.pol` for the same settings (regression test against hand-crafted GPOs with known-good `Registry.pol` outputs).

## Rationale

Three alternatives were considered.

**Alternative A: Hand-translate ADMX to framework JSON.** Hire a team of policy authors to translate each ADMX policy into canonical JSON by hand. Rejected because (a) the Microsoft built-in ADMX set alone is ~3,500 policies; hand-translation at 30 minutes per policy is ~1,750 person-hours (≈ 1 person-year), with no guarantee of accuracy; (b) Microsoft ships new ADMX with each Windows feature update (semi-annual), so the hand-translation must be repeated continuously; (c) customer-specific ADMX (Chrome, Office, vendor LOB apps) adds another 500-2,000 policies per customer that the framework cannot hand-translate. The compiler is a one-time ~3 person-week investment (per Decision 7 §Implementation impact) that automates the translation forever.

**Alternative B: ADMX-as-canonical (skip the compiler).** Use ADMX as the framework's canonical policy-definition format; ship an ADMX parser on macOS and Linux that interprets ADMX directly. Rejected because (a) ADMX is registry-path-centric — forcing ADMX onto macOS MDM payloads and Linux config fragments produces the same lowest-common-denominator leak that ADR-024 Alternative B rejected; (b) ADMX's typed-value system (REG_SZ/REG_DWORD/REG_MULTI_SZ) is insufficient for the framework's `secret_ref`, `nested`, and `bytes` types (per Decision 7 §2); (c) ADMX's `supportedOn` predicate is Windows-versions-only, blocking the framework's richer targeting (macOS version, Linux distro, host role, host site); (d) ADMX's `presentation` element assumes a Windows-GPMC form layout that does not map to the framework's React/TypeScript authoring UI; (e) the framework would inherit ADMX's 30-year XML-schema baggage with no migration path to a modern format. Decision 7's §Rationale rejects this candidate (Candidate A) explicitly.

**Alternative C: External ADMX-to-OPA/Rego translator.** Use an existing OPA/Rego policy engine and write an ADMX-to-Rego translator (Rego replaces JSON as the canonical format). Rejected because (a) Rego is rule-oriented, not value-oriented — a Rego policy says "the registry value X should be Y if condition Z", which is a different model than the framework's "set the registry value X to Y" — and translating ADMX's declarative value settings into Rego rules produces verbose, hard-to-audit Rego; (b) Rego's evaluation model assumes a query-and-response pattern (the client asks "what is the value of X?" and Rego evaluates the rules), whereas the framework's policy model is push-based (the distribution service pushes the canonical JSON to the client, which applies it); (c) the framework's CEL selector (per Decision 7 §10) is for targeting (which hosts does this policy apply to?), not for value definition; using Rego for both would conflate the two concerns. Decision 7 §10 selects CEL for targeting and JSON for value definition; Rego is opt-in for targeting only (per Decision 7 §10 last paragraph).

The chosen model — `admx2adrian` one-way compiler — gives the framework: (a) a migration path for the entire Microsoft built-in ADMX set plus customer-specific ADMX; (b) a canonical JSON format that's modern, typed, and Git-diffable; (c) a clean separation between targeting (CEL) and value definition (JSON); (d) a documented lossiness contract that operators can audit (the `_lossy_from_admx` field).

## Consequences

**Positive**. The framework inherits the entire ADMX ecosystem (Microsoft built-in, vendor, customer-specific) without re-authoring. The canonical JSON is modern, typed, and Git-diffable (per ADR-031). The compiler's determinism enables reproducible builds and Git-diff-based policy review. The `_lossy_from_admx` field documents exactly which ADMX features are flattened, making the migration auditable.

**Negative**. The compiler is a maintenance burden: ADMX schema revisions (rare — Microsoft has shipped only minor revisions since 2008) require compiler updates; vendor ADMX files with non-standard schemas (e.g., ADMX files that use `<extension>` elements outside the standard schema) may require per-vendor patches. The lossiness contract means some ADMX semantics (inverted booleans, `enableKey` deletion-on-disable) are handled differently in the framework's runtime than in AD's runtime — the framework's synthetic Windows CSE must reproduce the `delete_on_disable` semantics that AD's native Registry CSE provides implicitly.

**Neutral**. The compiler is one-way; customers who maintain ADMX authoring for legacy AD-only environments must keep their ADMX source-of-truth in existing GPO tooling and re-run the compiler on each ADMX revision. The framework's documentation recommends migrating authoring to canonical JSON after the initial ADMX import.

**Implementation cost**. ~3 person-weeks for v1 (per Decision 7 §Implementation impact): ADMX XML parsing via `quick-xml` (1 pw), type mapping + annotation emission (1 pw), ADML localization + multi-locale output (0.5 pw), CI integration with Microsoft's ADMX bundle + vendor ADMX set (0.5 pw). Ongoing maintenance: ~0.5 person-weeks per year for ADMX schema revisions and vendor ADMX patches.

**Operational impact**. Operators run `admx2adrian` during migration (one-time per ADMX file) and on ADMX revisions (rare). The framework's authoring UI imports the compiled JSON templates into its template catalogue, where operators author policy instances by selecting a template and providing values. The `adrian-policy validate` CLI catches template-instance mismatches at commit time.

## Alternatives Considered

### Alternative A: Hand-translate ADMX to framework JSON

Manually translate each ADMX policy into canonical JSON by hand. Suitable for a small curated set of common policies; infeasible for the full Microsoft built-in set (~3,500 policies) plus customer-specific ADMX (500-2,000 per customer).

Rejected as detailed in §Rationale: ~1 person-year for the initial Microsoft set, repeated semi-annually for new ADMX, and infeasible for customer-specific ADMX. The compiler automates the translation.

### Alternative B: ADMX-as-canonical (skip the compiler)

Use ADMX directly as the framework's canonical policy-definition format. Ship an ADMX parser on macOS and Linux. Avoids the compiler entirely.

Rejected as detailed in §Rationale and Decision 7 §Rationale Candidate A: ADMX is registry-path-centric and Windows-implementation-shaped; forcing it onto macOS/Linux produces the lowest-common-denominator leak; ADMX's typed-value system is insufficient for the framework's `secret_ref`/`nested`/`bytes` types; ADMX's `supportedOn` is Windows-versions-only.

### Alternative C: External ADMX-to-OPA/Rego translator

Use OPA/Rego as the canonical policy format; write an ADMX-to-Rego translator. Rego is a mature policy engine with broad adoption.

Rejected as detailed in §Rationale: Rego is rule-oriented, not value-oriented; Rego's evaluation model is query-response, not push; using Rego for both targeting and value definition conflates two concerns. Decision 7 §10 selects CEL for targeting and JSON for value definition; Rego is opt-in for targeting only.

## Open Questions

- **Vendor ADMX with non-standard schema extensions.** Some vendor ADMX files use `<extension>` elements outside the standard `policyDefinitions.xsd` schema (e.g., Adobe Reader's ADMX uses a non-standard `<pol:AdobCustomElement>` extension). The compiler logs a `WARN` and skips the extension; revisit if a major vendor's extension is widely used and worth supporting.
- **ADMX `revision` and `schemaVersion` tracking.** The compiler emits the ADMX `revision` and `schemaVersion` as `_source.{revision, schema_version}` annotations. Revisit if the framework needs to gate policy application on ADMX schema version (no current use case identified).
- **Multi-locale `_display` object size.** For ADMX files with many policies and many locales, the `_display` object can be large (e.g., Windows 11 23H2 ADMX in 20 locales × 3,500 policies × 200-byte display strings ≈ 14 MB per locale). The compiler supports `--locales en-US` (single-locale output) for size-constrained deployments; revisit if multi-locale output becomes a performance issue.

## Cross-capability impact

- **Policy Engine (PC-043 GPC/GPT split)**: ADR-089's GPC/GPT synthesis uses the compiled JSON templates' `admx.registry` annotations when emitting `Registry.pol` for legacy Windows clients.
- **Policy Engine (PC-047 CSE model)**: ADMX-driven settings invoke the Registry CSE on Windows; the framework's synthetic CSE (per Decision 7 §6) consumes the same compiled JSON for non-Registry areas.
- **Migration (PC-127 GPO-to-framework)**: The `adrian-migrate from-gpo` CLI uses `admx2adrian` as the primary migration entry point for ADMX-defined policies.
- **Cross-Platform Parity (PC-095 unified authoring)**: The compiled JSON templates are the foundation of the framework's unified authoring surface — operators author against the same template regardless of target platform.
- **Operations (PC-115 unified CLI)**: The `admx2adrian` binary is invoked by the `adrian-migrate` CLI; it is not a user-facing command in the unified CLI (per ADR-063).

## References

- [PC-046](../catalog/04-policy-engine.md) — problem statement in the catalog
- [Workshop Decision 7](../workshop/decision-07-policy-format.md) §3 — ADMX-to-JSON compiler specification
- [docs/04-group-policy/03-admx-templates.md](../docs/04-group-policy/03-admx-templates.md) — ADMX schema, ADML localization, Central Store, `<policy>` element structure
- [docs/04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md) — `Registry.pol` PReg format (the target of the PReg adapter that consumes `admx.registry` annotations)
- [ADR-029](./ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy format; PReg adapter (the consumer of `admx.registry` annotations)
- [ADR-089](./ADR-089-declarative-policy-gpc-gpt-synthesis.md) — Declarative policy + GPC/GPT synthesis (uses `admx2adrian` output for migration)
- [ADR-031](./ADR-031-git-backed-policy-history.md) — Git-backed policy history (compiled templates are committed to Git)
- [ADMX schema reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/admx-backed-policy) — Microsoft ADMX documentation
- [`quick-xml` crate](https://docs.rs/quick-xml) — Rust streaming XML parser used by `admx2adrian`
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol
