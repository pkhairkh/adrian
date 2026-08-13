---
title: "ADR-029: JSON canonical policy format; PReg adapter"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Policy Engine
problem: PC-052
severity: medium
tags: [adr, policy-engine, json, preg, format, cross-platform]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/04-policy-engine.md
  - ../docs/04-group-policy/05-gpt-gpc-structure.md
  - ../docs/04-group-policy/04-cse-client-side-extensions.md
  - ./ADR-024-per-platform-policy-executors.md
  - ./ADR-031-git-backed-policy-history.md
last_updated: 2026-08-13
---

# ADR-029: JSON canonical policy format; PReg adapter

## Status

Accepted — 2026-08-13.

## Context

AD `Registry.pol` is a binary file with a 6-byte signature `PReg\0` (literal bytes `0x50 0x52 0x65 0x67 0x00 0x00`) followed by UTF-16LE-encoded records, per [docs/04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md). Each record is `[key;value;type;size;data;]` where `key` and `value` are UTF-16LE strings, `type` is decimal ASCII digits (1=REG_SZ, 2=REG_EXPAND_SZ, 3=REG_BINARY, 4=REG_DWORD, 7=REG_MULTI_SZ), `size` is decimal ASCII digits (byte length of decoded `data`), and `data` is hex-encoded ASCII. The Registry CSE (`userenv.dll!ProcessRegistryPolicy`) calls `PReg_ReadFile` to parse this format and writes to the registry via `RegCreateKeyExW` / `RegSetValueExW`.

The PReg format is opaque to non-Windows clients. SSSD does not parse `Registry.pol` at all — it only reads `GptTmpl.inf` for `[Privilege Rights]`. Samba's `samba-gpupdate` parses PReg via `libndr` and translates a fixed set of known policy keys (`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\...` → `/etc/krb5.conf`, `/etc/security/limits.conf`, `/etc/sudoers.d/`) — but the mapping is hard-coded in `samba-gpupdate` source, not schema-driven. macOS has no PReg concept; MDM payloads are plist XML, per [docs/10-comparison-matrices/05-gpo-equivalents-matrix.md](../docs/10-comparison-matrices/05-gpo-equivalents-matrix.md). The same GPO applied to Windows/macOS/Linux produces different effective configuration because only Windows consumes the `Registry.pol` settings.

For the framework, the choice is between: (a) keeping PReg for Windows interop and adding a PReg reader to the macOS/Linux client, (b) adopting a portable format (JSON) for new policies and providing a PReg compat reader for legacy, or (c) using per-platform native formats (Registry.pol on Windows, plist on macOS, YAML/INI on Linux). Per [PC-052](../catalog/04-policy-engine.md), the framework must support PReg for Windows interop (existing `userenv.dll!PReg_ReadFile`) while new framework policies should use a portable format with a PReg adapter.

The framework's policy authoring surface must emit both PReg (for legacy `gpsvc.dll`) and the new format. The new format must be: (a) human-readable (for Git diffs per ADR-031), (b) typed (so executors know whether a value is a string, integer, boolean, list, or nested structure), (c) schema-validatable (so authoring errors are caught before apply), and (d) cross-platform (no Windows-isms like registry paths in the canonical form).

## Decision

The framework shall adopt JSON as the canonical policy format, with a PReg adapter for Windows AD-interop. The format is:

1. **Canonical JSON schema** — each policy is a JSON document with a fixed top-level structure:
   ```json
   {
     "apiVersion": "adrian/v1",
     "kind": "Policy",
     "metadata": {
       "name": "<policy-name>",
       "version": "<git-sha>",
       "priority": "urgent"|"normal",
       "ttl_seconds": <int|null>
     },
     "spec": {
       "target": {
         "facts": { "<fact-name>": "<predicate>" },
         "roles": ["<role-name>"],
         "groups": ["<group-name>"]
       },
       "areas": [
         {
           "area": "<PolicyArea-enum>",
           "settings": {
             "<setting-key>": { "type": "<type>", "value": <value> }
           },
           "slow_link_policy": "always_apply"|"skip_on_slow_link"|"warn_on_slow_link"
         }
       ]
     }
   }
   ```
2. **Type system** — the framework defines a typed value system: `string`, `integer`, `boolean`, `string_list`, `bytes`, `nested` (a nested JSON object). Each setting carries its type explicitly so executors can validate before apply. This avoids PReg's ambiguity (REG_SZ vs. REG_EXPAND_SZ vs. REG_MULTI_SZ) and plist's implicit typing.
3. **PReg adapter (Windows-only)** — for legacy Windows hosts running `gpsvc.dll`, the framework's policy distribution endpoint emits a `Registry.pol` file derived from the canonical JSON. The translation: `area == "Registry"` settings → PReg records with the registry path from the setting key, type mapping (string → REG_SZ, integer → REG_DWORD, string_list → REG_MULTI_SZ, bytes → REG_BINARY). Non-`Registry` areas are not translatable to PReg and are emitted as separate GPT files (`GptTmpl.inf` for `Security`, `Scripts.ini` for `Scripts`, etc.) using AD-compatible formats.
4. **PReg reader (legacy import)** — the framework's migration tooling (per ADR-055) reads existing `Registry.pol` files and emits canonical JSON. The translation: PReg records → `area == "Registry"` settings with type mapping (REG_SZ → string, REG_DWORD → integer, etc.).
5. **Schema validation** — the framework provides a JSON Schema for the canonical format; the policy authoring UI and CI/CD pipeline validate every policy against the schema before commit (per ADR-031's PR review).
6. **MDM plist adapter (macOS)** — the macOS executor (per ADR-024) translates `area == "Registry"` settings to `com.apple.managedpreferences` payload keys; other areas translate to their respective MDM payload types.
7. **Linux config adapter (Linux)** — the Linux executor translates settings to native config formats: `area == "Security"` → PAM/sudoers/limits.conf; `area == "AuditPolicy"` → auditd rules; `area == "AccountPolicy"` → login.defs; etc.

**Concrete specification**:

- The canonical JSON schema is published at `https://adrian.dev/schemas/policy/v1.json` and bundled with the framework's CLI.
- Every policy file has extension `.policy.json` and is validated on commit by a pre-commit hook (per ADR-031).
- The PReg adapter is implemented in the framework's policy distribution service (Windows-only component); it reads canonical JSON and writes `Registry.pol` to the SMB share served to legacy Windows clients.
- The PReg reader is implemented in the framework's migration tooling (per ADR-055); it reads `Registry.pol` from an existing GPO backup and emits canonical JSON.
- The framework's `adrian-policy validate <file>` CLI validates a policy against the schema and reports errors with line/column.
- The framework's `adrian-policy compile --target windows <file>` CLI emits the PReg/`GptTmpl.inf`/`Scripts.ini` files for a Windows target; `--target macos` emits the MDM plist; `--target linux` emits the native config files.
- The framework's policy authoring UI generates canonical JSON via a structured form (no raw JSON authoring for operators).

## Rationale

Three alternatives were considered.

**Alternative 1: YAML.** Rejected because YAML's type inference is dangerous (e.g., `version: 1.0` is a float, `version: 1.0.0` is a string; `yes`/`no`/`on`/`off` are booleans in some parsers). JSON has no type inference — every value is explicitly typed. YAML's anchor/alias feature is powerful but produces non-obvious diffs (a change to an anchor affects all aliases). JSON's lack of comments is a disadvantage for human authoring, but the framework's policy authoring UI provides documentation inline.

**Alternative 2: TOML.** Rejected because TOML's nested-table syntax is verbose for deeply-nested structures (the framework's policy schema is 3-4 levels deep). TOML is well-suited for flat config files (Rust's `Cargo.toml`, Python's `pyproject.toml`) but not for the framework's structured policy documents. JSON's nesting via objects is more natural for the framework's schema.

**Alternative 3: Per-platform native formats (PReg on Windows, plist on macOS, YAML on Linux).** Rejected because it forces operators to author three versions of every policy — the same fragmentation problem as the current AD+SSSD+MDM state. A single canonical format with platform adapters is the cross-platform path.

The decision aligns with industry practice: Kubernetes uses YAML (with explicit typing via `apiVersion`/`kind`); Terraform uses HCL; CloudFormation uses JSON or YAML; Ansible uses YAML for playbooks but JSON for variable files. JSON is the lowest-common-denominator format with universal parser support across all three platforms and all major programming languages.

Cost: ~4 person-weeks for the JSON schema, the PReg adapter, the PReg reader (migration), and the per-platform adapters. The PReg adapter is the highest-risk item (PReg binary format edge cases: UTF-16LE BOM, multi-string null terminator, registry path case sensitivity).

## Consequences

**Positive**. Cross-platform policy authoring works: operators author once in JSON, the framework compiles to PReg/plist/Linux config. JSON is human-readable and Git-diffable (per ADR-031). Schema validation catches authoring errors before commit. The typed value system eliminates PReg's ambiguity (REG_SZ vs. REG_EXPAND_SZ). Migration from AD is supported via the PReg reader.

**Negative**. JSON's lack of comments is a real disadvantage for human authoring — operators must use the UI or accept inline documentation via `_comment` fields (non-ideal). The PReg adapter must be maintained for as long as legacy Windows clients exist (potentially a decade). The PReg format has edge cases (UTF-16LE BOM, multi-string null terminator) that the adapter must handle exactly.

**Neutral**. The canonical format is JSON; the framework does not support YAML or TOML for policy authoring. Operators who prefer YAML can use a YAML-to-JSON converter in their editor (VS Code, JetBrains), but the canonical form is JSON.

**Implementation cost**. ~4 person-weeks for the schema, PReg adapter, PReg reader, and per-platform adapters. Ongoing maintenance: ~0.5 person-weeks per year for PReg edge cases and schema evolution.

**Operational impact**. Operators author policies via the UI (which emits JSON) or via Git PRs (which contain JSON). The `adrian-policy validate` CLI catches authoring errors before commit. The `adrian-policy compile --target <platform>` CLI previews the per-platform output without applying.

## Alternatives Considered

### Alternative A: YAML

Use YAML as the canonical format. YAML is human-readable, supports comments, and is widely used in infrastructure-as-code (Kubernetes, Ansible).

Rejected because YAML's type inference is dangerous. The classic example: `version: 1.0` parses as a float (1.0), but `version: 1.0.0` parses as a string because `1.0.0` is not a valid float. Similarly, `yes`/`no`/`on`/`off` parse as booleans in some YAML parsers (YAML 1.1) but as strings in others (YAML 1.2). For a typed policy format, this ambiguity is unacceptable — a registry value `1.0` (REG_SZ) and a registry value `1.0` (REG_DWORD) are different settings, and YAML cannot distinguish them without explicit typing (which defeats the purpose of YAML's brevity). JSON has no type inference; every value is explicitly typed (string in quotes, number without quotes, boolean as `true`/`false`).

### Alternative B: TOML

Use TOML as the canonical format. TOML has explicit typing (strings in quotes, numbers without, booleans as `true`/`false`) and supports comments via `#`.

Rejected because TOML's nested-table syntax (`[section.subsection.subsubsection]`) is verbose for deeply-nested structures. The framework's policy schema is 3-4 levels deep (policy → spec → areas → settings → type/value), and TOML's table syntax produces files that are harder to read than the equivalent JSON. TOML is well-suited for flat config files (Rust's `Cargo.toml`, Python's `pyproject.toml`) but not for the framework's structured policy documents. JSON's nesting via objects is more natural for the framework's schema.

### Alternative C: Per-platform native formats

Use PReg on Windows, plist on macOS, YAML on Linux. Each platform's client consumes its native format; the framework's authoring surface emits all three.

Rejected because it forces operators to author three versions of every policy — the same fragmentation problem as the current AD+SSSD+MDM state that the framework is solving. A single canonical format with platform adapters is the cross-platform path. Additionally, syncing changes across three formats is error-prone (a change to the Windows PReg must be manually replicated to the macOS plist and Linux YAML), and auditing "what is the effective policy on this host?" requires reading three formats. The canonical JSON with adapters solves all three problems.

## Open Questions

- Should the framework support YAML as an authoring format (with YAML-to-JSON conversion on commit)? Some operators prefer YAML for human authoring. Current decision: JSON-only canonical; revisit if operator demand emerges.
- The PReg adapter: should it support all PReg edge cases (UTF-16LE BOM, multi-string null terminator, registry path case sensitivity)? Yes — the framework must produce PReg files that `userenv.dll!PReg_ReadFile` accepts without error. Edge cases must be tested against real Windows hosts.
- Schema evolution: how does the framework handle schema versioning? The `apiVersion: adrian/v1` field allows future `adrian/v2` schemas with migration tooling. The framework's CLI refuses to apply a policy with an unknown `apiVersion`.

## Cross-capability impact

- **Policy Engine (PC-052)**: This ADR. PC-046 (ADMX-to-unified-schema translation) produces canonical JSON from ADMX templates. PC-047 (CSE model, ADR-024) — the per-platform executors consume canonical JSON.
- **Migration (PC-124..PC-130)**: ADR-055 (migration paths) — the PReg reader is part of the GPO-to-declarative-policy migration tooling.
- **Operations (PC-106..PC-115)**: ADR-031 (Git-backed policy history) — canonical JSON is Git-diffable; PR review validates against the schema.
- **Cross-Platform Parity (PC-094..PC-105)**: PC-094 (Windows-only Preferences XML) — the canonical JSON format is the cross-platform target.

## References

- [PC-052](../catalog/04-policy-engine.md) — problem statement in the catalog
- [docs/04-group-policy/05-gpt-gpc-structure.md](../docs/04-group-policy/05-gpt-gpc-structure.md) — PReg binary format, `PReg\0` signature, record field encoding
- [docs/04-group-policy/04-cse-client-side-extensions.md](../docs/04-group-policy/04-cse-client-side-extensions.md) — Registry CSE `userenv.dll!ProcessRegistryPolicy` and `PReg_ReadFile`
- [RFC 8259 JSON](https://www.rfc-editor.org/rfc/rfc8259) — JSON specification
- [JSON Schema](https://json-schema.org/) — JSON Schema specification
- [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac) — Group Policy: Core Protocol (PReg format reference)
