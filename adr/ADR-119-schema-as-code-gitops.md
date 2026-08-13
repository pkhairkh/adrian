---
title: "ADR-119: Schema-as-Code with GitOps — Reversible Migrations, Typed Projection Regeneration"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Operations
problem: PC-107
severity: high
tags: [adr, operations, schema, gitops, migration, drsuapi, typed-projection, reversible]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/10-operations.md
  - ../docs/03-directory-schema/01-schema-attributes.md
  - ../docs/03-directory-schema/05-replication-internals.md
  - ../workshop/decision-04-schema-model.md
  - ./ADR-003-schema-cache-cow.md
  - ./ADR-029-json-canonical-policy-preg-adapter.md
last_updated: 2026-08-13
---

# ADR-119: Schema-as-Code with GitOps — Reversible Migrations, Typed Projection Regeneration

## Status

Accepted — 2026-08-13. Unblocked by [Workshop Decision 4 (schema model)](../workshop/decision-04-schema-model.md) which adopted the hybrid LDAP-schema + typed Rust projection. This ADR operationalises that decision for day-2 schema changes.

## Context

AD's schema version is encoded as a single integer `objectVersion` on the Schema NC head (`CN=Aggregate,CN=Schema,CN=Configuration,...`). The progression is monotonic and effectively one-way: 13 (Windows 2000), 30 (Server 2003), 44 (2008), 47 (2008 R2), 56 (2012), 61 (2012 R2), 69 (2016), 72 (2019), 88 (2022). Each release ships an `adprep /forestprep` action that adds new `attributeSchema` and `classSchema` objects, increments `objectVersion`, and triggers a `schemaUpdateNow = 1` cache reload per [`03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md).

Once extended, the schema cannot be rolled back. Attributes and classes can be marked `isDefunct = TRUE` (effectively tombstoned), but the OID arc and `governsID` are burned forever — the schema cache still walks them, `repadmin /showrepl` still reports them, and a re-promotion of a fresh DC will re-import them from the Schema NC. There is no `adprep /forestrollback`. A failed `adprep` that died mid-extension leaves the schema in a partial state that Microsoft support can sometimes clean up by hand but the operation is unsupported.

Real-world consequence: organisations stage schema upgrades in a separate lab forest, run them in prod during maintenance windows, and delay upgrades by 2–3 years. The Windows Server 2022 schema upgrade (`objectVersion = 88`) was rolled out to many enterprises 2–3 years after release because of this risk. Schema upgrades are the single most operationally risky AD change — failed upgrades leave the forest in an unrecoverable state.

The framework gap is that any schema-as-code (Git-backed typed-schema with versioned migrations) approach must contend with: (a) AD-interop requires the literal `objectVersion = 88` schema; (b) the framework must replicate the exact `attributeSchema` set so AD DCs that consume the framework's schema via DRSUAPI do not see missing attributes per [`03-directory-schema/05-replication-internals.md`](../docs/03-directory-schema/05-replication-internals.md); (c) migration from a typed schema back to AD's LDAP schema (for rollback) is lossy.

Workshop Decision 4 chose the **hybrid LDAP schema + typed Rust projection** model: the Schema NC is the authoritative source of truth at the wire and storage layers, and `adrian-schema-compiler` produces a typed Rust projection at boot time from the live directory (not from a checked-in IDL). That decision resolved *what* the schema is; this ADR resolves *how* operators change it safely.

## Decision

The framework treats schema changes as **first-class GitOps-managed migrations** with the following model: schema changes are authored as PRs against a dedicated `adrian-schema` Git repository; each PR contains an LDIF delta (`add attributeSchema`/`classSchema` or `modify isDefunct`) plus a Rust trait field declaration (for the typed projection); the PR review pipeline runs `adrian-schema validate`, `adrian-schema plan`, and `adrian-schema-compiler check`; merge triggers a framework-side apply that writes the LDIF to the Schema NC inside an FDB strict-serializable transaction, increments a framework-local `schemaGeneration` counter, and triggers a copy-on-write cache swap (per [ADR-003](./ADR-003-schema-cache-cow.md)) followed by a typed-projection recompile.

**Reversibility** is the core property. The framework supports **synthetic rollback**: every schema migration PR records a reverse-LDIF that, when applied, marks the added attributes as `isDefunct = TRUE` and removes the typed-projection accessor. True OID-arc reclamation is impossible (matching AD's behaviour) but `isDefunct = TRUE` removes the attribute from the typed projection, from the schema cache walk, and from replication-visible changes. For framework-native-mode forests (no AD-interop), the framework also supports true attribute removal (the LDIF delta records `delete attributeSchema` and the FDB row is deleted) — this is the *only* mode in which the framework deviates from AD's irreversibility.

**Concrete specification**:

- The framework MUST maintain a dedicated Git repository `adrian-schema` (per organisation) containing: (a) `base/schema.ldif` — the canonical Schema NC export at last applied generation; (b) `migrations/NNNN-description.ldif` — numbered migration deltas; (c) `migrations/NNNN-description.reverse.ldif` — reverse deltas for synthetic rollback; (d) `traits/<area>.rs` — Rust trait declarations for typed projection; (e) `adrian-schema.toml` — generation counter, AD-interop flag, last-applied timestamp.
- The framework MUST refuse to apply any schema change that is not in a reviewed-and-merged PR. Direct LDAP writes to `CN=Schema,CN=Configuration,...` are rejected with `unwillingToPerform (53)` unless the connection is the framework-internal schema-apply service.
- The framework MUST expose `adrian-cli schema plan --from <git-ref> --to <git-ref>` that shows the LDIF diff, the projected typed-projection diff, the AD-interop impact (any attribute AD DCs would see as missing), and an estimated apply time.
- The framework MUST expose `adrian-cli schema apply --migration <NNNN>` that: (1) acquires the schema-master lease (per Decision 1's Raft leader election in native mode, or the AD-interop schema-master FSMO in AD-interop mode); (2) opens an FDB transaction; (3) writes the LDIF delta to the Schema NC; (4) writes the typed-projection trait declaration to the framework's schema-trait registry; (5) increments `schemaGeneration`; (6) triggers a copy-on-write cache rebuild (per ADR-003); (7) triggers a typed-projection recompile; (8) commits the FDB transaction; (9) emits an audit event per ADR-060.
- The framework MUST complete the cache rebuild + projection recompile in ≤500 ms for a 10K-attribute / 2K-class schema (per Decision 4's performance target). Apply is synchronous from the operator's perspective — the CLI returns only after the projection is live.
- The framework MUST expose `adrian-cli schema rollback --to <NNNN>` that walks the reverse-LDIF chain from the current generation down to N. Rollback is synthetic by default (`isDefunct = TRUE`); `--hard` flag enables true attribute removal for native-mode-only forests.
- The framework MUST support `adrian-cli schema import-adprep --admx-bundle <path>` for AD-interop scenarios — this ingests a Microsoft `adprep` LDIF (e.g. the Server 2022 schema extension), translates it to the framework's migration format, and applies it. The framework's Schema NC after import is byte-equivalent to a fresh Server 2022 forest.
- The framework MUST audit every schema change (apply, rollback, defunct) as an OTel log event per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with attributes `adrian.schema.generation`, `adrian.schema.operation`, `adrian.schema.migration_id`, `adrian.schema.actor`, `adrian.schema.attributes_added`, `adrian.schema.attributes_defunct`. The event maps to Windows Event 4662 with the schema-NC-head object GUID.
- The framework MUST expose `GET /api/v1/schema/generation` (REST, per ADR-061) returning the current `schemaGeneration`, last-applied migration, last-applied timestamp, and replication status across DCs. The operator's readiness gate (per ADR-058) considers a DC "ready" only when its local `schemaGeneration` matches the forest's.
- The framework MUST ship a default Prometheus alert: `max(adrian_schema_generation) - min(adrian_schema_generation) > 0 for 5m` triggers a warning (schema replication lag).
- The framework's schema-apply service MUST be HA: the schema-master lease (per Decision 1) is held by exactly one DC at a time; if that DC fails, the lease fails over to another DC within 5 seconds. Apply operations in flight are aborted and retried by the CLI.
- For framework-native mode, the framework MAY elide the `objectVersion` integer entirely (per ADR-121). For AD-interop mode, the framework MUST set `objectVersion = 88` to match Server 2022; the integer is a wire-compat artefact, not a feature gate.

## Rationale

Schema-as-code is the modern operational pattern. Kubernetes CRDs, Terraform schemas, and OpenAPI specs are all GitOps-managed with review pipelines. AD's `adprep` model is an artefact of the 1999 release cadence (one schema bump per Windows Server release every 3 years); it does not fit a continuous-deployment framework that ships weekly. The framework's GitOps model treats schema changes the same as any other infrastructure change — reviewable, reversible, audited, and automated.

Reversibility is the core gap. AD's irreversibility is not a property of the schema's data model (the schema is just directory objects with `isDefunct`); it is a property of AD's operational model (no reverse-LDIF chain, no `adprep /forestrollback`). The framework's synthetic-rollback model preserves the OID arc (matching AD's behaviour) while giving operators the operational equivalent of rollback (`isDefunct` removes the attribute from the typed projection and from the cache walk). True attribute removal (native-mode-only) is the strict-superset behaviour for greenfield deployments that do not need AD-interop.

The typed-projection regeneration is the second key property. Workshop Decision 4 specified that the projection is regenerated from the live Schema NC at every `schemaGeneration` swap. This ADR operationalises that: every schema PR includes the Rust trait field declaration, the `adrian-schema-compiler check` step verifies the trait compiles against the LDIF delta, and apply triggers the recompile synchronously. The result is that a schema change and its typed-projection consumer are always in lockstep — there is no "schema changed but the SDK still uses the old projection" window.

The `adrian-schema import-adprep` command is the AD-interop bridge. Customers migrating from AD bring their existing schema (potentially extended with LOB-app attributes beyond the base Server 2022 set). The command ingests the AD Schema NC export (LDIF), translates to the framework's migration format, and applies as a single migration. After import, the framework's Schema NC is byte-equivalent to the source AD forest's, enabling parallel-run (PC-126) without attribute-missing replication errors.

The GitOps model enables staged rollouts. A schema PR can be merged to a `staging` branch and applied to a lab forest; the same PR can then be promoted to `main` and applied to prod. The framework's CLI distinguishes branches by the `adrian-schema.toml`'s `forest` field — a migration applied to the lab forest does not affect prod. This matches the lab-then-prod pattern organisations already use for `adprep`, but with reproducible automation instead of manual `ldifde` invocations.

## Consequences

**Positive**: Schema changes are reviewable (PR-based), reversible (synthetic rollback by default; true removal for native mode), audited (OTel events), and reproducible (GitOps). The typed projection is always in lockstep with the LDAP schema (no drift window). The framework's `schemaGeneration` counter gives the operator a single metric for replication-lag monitoring. AD-interop customers can import their existing schema with one CLI command.

**Negative**: Schema changes are slower than AD's `adprep /forestprep` (PR review + CI validation + apply ≈ hours vs. AD's minutes). The framework's GitOps model assumes Git is the source of truth — customers without a Git infrastructure (rare but possible) must adopt one. The synthetic-rollback model leaves `isDefunct` attributes in the Schema NC forever (matching AD); the OID arc is burned forever (matching AD); organisations that want true rollback must use native mode.

**Neutral**: The `objectVersion` integer is preserved as a wire-compat artefact for AD-interop mode (`= 88` for Server 2022); it is elided in native mode (per ADR-121). Framework-native forests that later need to peer with an AD forest must run `adrian-cli schema import-adprep` to add the missing attributes; this is a one-time operation.

**Implementation cost**: ~6 person-months for the schema-apply service, the GitOps pipeline integration, the `plan`/`apply`/`rollback` CLI, and the `import-adprep` translator. Reuses Decision 4's `adrian-schema-compiler` and `adrian-schema-traits` crates.

**Operational impact**: Schema administrators author PRs (not `adprep` invocations); the framework's CI validates; the schema-master DC applies. SOC analysts see schema-change events in the audit pipeline. The framework's default Prometheus alert catches schema-replication lag.

## Alternatives Considered

**Alternative A: Direct `ldapmodify` against the Schema NC (no GitOps).** Allow operators to write LDIF directly against the Schema NC, matching AD's `ldifde -i -f schema.ldif` workflow. Rejected because (a) it is irreversible with no audit trail beyond the directory's own metadata; (b) it provides no review pipeline — a typo in the LDIF propagates immediately; (c) the typed projection (per Decision 4) cannot be kept in lockstep without a Rust trait field declaration, which `ldapmodify` does not provide; (d) AD-interop customers have lived with this pain for 25 years; the framework's value proposition is doing better.

**Alternative B: Pure typed-schema with checked-in Rust source as source of truth (Option B from Decision 4).** Make the Rust trait declarations the source of truth and generate the LDAP schema from them at boot. Rejected by Decision 4 because it breaks AD-interop (AD expects the LDAP schema to be authoritative on the wire; the framework cannot round-trip a typed-source-of-truth schema back to LDAP without lossy translation). The hybrid model (LDAP authoritative, Rust projected) is what Decision 4 chose; this ADR operationalises it.

**Alternative C: Adopt `adprep`-style release-bundled schema bumps (no per-attribute PRs).** Ship framework releases with bundled schema migrations (one per release), applied at upgrade time. Rejected because (a) it ties schema changes to the framework's release cadence — customers needing an attribute for a LOB app cannot add it without a framework release; (b) it does not provide reviewability or reversibility; (c) it inherits AD's operational model that organisations are fleeing.

**Alternative D: External schema-management tool (e.g. `ldap3`-based script).** Provide a Python or Go script that operators use to author and apply schema changes. Rejected because (a) the typed-projection integration (Decision 4) requires Rust trait declarations; a non-Rust tool cannot author them; (b) the framework's operational model is Rust-native; introducing a Python/Go dependency for schema management breaks the "single binary, single runtime" property; (c) GitOps integration is harder in a script than in a Rust CLI.

## Open Questions

None. Workshop Decision 4 resolved the schema-model ORQ-030/031 that gated this ADR. The GitOps operational model is an implementation choice that does not gate further work.

## Cross-capability impact

- **Core Directory (PC-001/PC-002)**: Schema NC replication via DrSuapiReplicator (AD-interop) or RaftReplicator (native) carries the schema changes — no new replication surface; the schema is just another NC.
- **Core Directory (PC-017)**: Resolved directly — typed-schema vs LDAP-schema is the Decision 4 question; this ADR is the Operations-side realisation.
- **Operations (PC-113)**: Functional levels (ADR-121) are subsumed by the schema-as-code model; the framework replaces functional-level gating with per-feature `schemaGeneration` checks.
- **Operations (PC-110)**: ADR-059 (PITR backup/DR) covers schema-NC restore — a PITR restore rolls back the schema to the chosen timestamp's `schemaGeneration`.
- **Policy Engine (PC-125)**: GPO translation (ADR-127) consumes the typed projection; schema changes that add new ADMX-backed attributes are immediately available to the GPO translator without a redeploy.
- **Migration (PC-126)**: Parallel-run requires schema equivalence between AD and the framework; `adrian-cli schema import-adprep` provides this.
- **Security (PC-117)**: DCSync (ADR-122) is unaffected; the schema-apply service is not a DRSUAPI caller.

## References

- [PC-107](../catalog/10-operations.md) — problem statement (schema upgrades are irreversible; `objectVersion` bump is one-way)
- [Schema attributes KB](../docs/03-directory-schema/01-schema-attributes.md) — `objectVersion` table, schema update procedure, `schemaUpdateNow` semantics, OID allocation arcs
- [Replication internals KB](../docs/03-directory-schema/05-replication-internals.md) — Schema NC replication; the schema is the first NC replicated on a fresh DC
- [Workshop Decision 4 — Schema model](../workshop/decision-04-schema-model.md) — hybrid LDAP schema + typed Rust projection; the source-of-truth model this ADR operationalises
- [ADR-003 — Schema cache COW](./ADR-003-schema-cache-cow.md) — copy-on-write schema cache with monotonic generation numbers; the substrate for the `schemaGeneration` counter
- [ADR-029 — JSON canonical policy + PReg adapter](./ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy derived from the typed projection
- [ADR-058 — Container-native DCs operator](./ADR-058-container-native-dcs-operator.md) — operator-managed DC lifecycle, schema-generation readiness gate
- [ADR-060 — Structured audit logs (OTel)](./ADR-060-structured-audit-logs-otel.md) — schema-change audit events
- [ADR-061 — REST/gRPC API](./ADR-061-rest-grpc-api.md) — `GET /api/v1/schema/generation` endpoint
- [MS-ADTS §3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Active Directory Technical Specification (schema model, `schemaUpdateNow`)
- [RFC 4512](https://www.rfc-editor.org/rfc/rfc4512) — LDAP directory information models (schema definitions)
