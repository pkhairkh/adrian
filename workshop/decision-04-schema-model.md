---
title: "Decision 4 — Schema Model: Hybrid (LDAP Schema + Typed Rust Projection)"
status: accepted
date: 2026-08-13
deciders: adrian-architecture-team
orqs_resolved: [ORQ-030, ORQ-031]
gates: 9 deferred problems (1 blocker, 5 high, 3 medium) + 1 partial ADR dependent
tags: [workshop, decision, tier-1, schema, ldap, typed, codegen, hybrid]
related:
  - ./CONTEXT.md
  - ../adr/TRIAGE.md
  - ../adr/ADR-003-schema-cache-cow.md
  - ../adr/ADR-009-constructed-attributes.md
  - ../adr/ADR-024-per-platform-policy-executors.md
  - ../adr/ADR-029-json-canonical-policy-preg-adapter.md
last_updated: 2026-08-13
---

# Decision 4 — Schema Model: Hybrid (LDAP Schema + Typed Rust Projection)

## Status

Accepted — 2026-08-13. This decision resolves Tier-1 ORQ-030 ("Hybrid (LDAP schema + typed projection)?") and ORQ-031 ("Pure typed with LDAP schema as an adapter?"). Both ORQs are answered with a single coherent design: **hybrid with the LDAP schema as the wire/storage substrate and a Rust-generated typed projection layered above it.** This is Option C of the candidate set in `workshop/CONTEXT.md`. The decision is final for v1; revisit only if the Rust projection proves more than 2× slower than the LDAP-native read path in production benchmarks (gate defined in §Implementation impact).

## ORQs resolved

- **ORQ-030** — "Hybrid (LDAP schema + typed projection)?" → **YES**. The hybrid is the chosen architecture.
- **ORQ-031** — "Pure typed with LDAP schema as an adapter?" → **NO**. The pure-typed alternative is rejected; the LDAP schema is a first-class citizen, not an adapter-on-the-side.

The two ORQs collapse to one architectural posture: the framework treats the LDAP schema (`attributeSchema` / `classSchema` instances in the Schema NC, governed by `OID`, `lDAPDisplayName`, `attributeSyntax`, `objectClassCategory`, `systemFlags`, `schemaIDGUID`) as the **authoritative source of truth at the wire and storage layers**, and uses **Rust code generation at boot time** to produce a typed projection that the SDK, the policy engine, the KDC's PAC builder, and the cert-service template manager consume.

## Decision

The framework SHALL adopt a hybrid schema model with three layers:

1. **Layer 0 — LDAP schema (storage and wire).** The Schema NC (`CN=Schema,CN=Configuration,<forest-root-dn>`) is the canonical schema representation. Each attribute is an `attributeSchema` object; each class is a `classSchema` object. OID-identified, runtime-extensible via `schemaModifyRequest`, replicated via DRSUAPI like every other NC. This is byte-for-byte compatible with AD's wire format (`docs/03-directory-schema/01-schema-attributes.md`). On-disk storage uses the LDAP attribute/columnar encoding chosen by ORQ-011/012/013/014 (storage engine decision from Day 1 AM session); the schema layer is storage-engine-agnostic.

2. **Layer 1 — Typed Rust projection (generated at boot).** At KDC/DSA boot, a **schema compiler** (Rust crate `adrian-schema-compiler`) reads the Schema NC, walks every `attributeSchema` and `classSchema` object, and emits a typed Rust projection: a `pub struct` per class with named fields, typed enums for syntax (DN, SID, GUID, octet-string, UTCTime, bool, int32, int64, largeInteger, securityDescriptor, objectSecurityDescriptor, etc.), and accessor traits (`TypedObject`, `AttributeReader`, `AttributeWriter`). The projection is materialized as an in-memory `Arc<SchemaProjection>` that is swapped atomically per ADR-003's copy-on-write schema cache; a new schema generation triggers a re-compile and an atomic pointer swap. There is **no codegen step in the build pipeline** — the projection is built from the live directory at boot, not from a `.proto` file checked into the repo.

3. **Layer 2 — Native framework classes (Rust traits).** Framework-native directory classes (e.g. `ServiceAccount`, `ManagedDevice`, `PolicySet`, `CertificateTemplate`) are defined as Rust traits in the framework source tree. Each trait declares which LDAP classes it can project onto (via a `#[projects_onto(class = "msDS-ManagedServiceAccount", ...)]` attribute) and how its fields map to LDAP attributes. The schema compiler generates projection glue for both standard LDAP classes and framework-native traits; framework-native traits are also projected **back** to LDAP at write time, so a `ServiceAccount` written via the typed SDK materializes as a `msDS-ManagedServiceAccount` object in the directory with all `msDS-*` attributes populated byte-identically to a Samba-tool-created one.

**Concrete specification**:

- The framework's directory SHALL accept `schemaModifyRequest` (RFC 4511 ModifyRequest on the Schema NC) and apply it via the same copy-on-write transactional path as any other write (per ADR-003). Adding an `attributeSchema` SHALL NOT require a framework rebuild, a redeploy, or a service restart; the typed projection is regenerated on the next schema-generation swap (target <200 ms per ADR-003).
- The schema compiler SHALL be invoked at DSA boot, at every `schemaUpdateNow` operational-attribute write, and on-demand via `adrian-schema recompile`. Its output is an in-memory `Arc<SchemaProjection>`; it does NOT write source files to disk. (A separate `adrian-schema dump-rust` developer command can emit Rust source for offline inspection, but it is not on the production code path.)
- The typed projection SHALL expose every LDAP attribute via `obj.get::<"cn">() -> Result<Attr<String>>` (the dynamic fallback) AND, for attributes declared in a known-class projection, via `obj.cn() -> Result<&str>` (the typed accessor). The dynamic fallback is the escape hatch for runtime-added attributes that have not yet been bound to a typed accessor — it is always available, ensuring schema extensions never block application code.
- Framework-native traits SHALL be declared in the framework's `crates/adrian-schema-traits` crate with `#[derive(Projectable)]`. The derive macro emits the projection glue (`ldap_class_ids()`, `read_from(&Entry)`, `write_to(&mut EntryBuilder)`).
- The projection's typed accessors SHALL NOT parse string values at runtime beyond what the LDAP syntax requires. SID-syntax attributes decode to `Sid` once at read time and are stored as `Sid` in the typed struct; subsequent reads return `&Sid`. DN-syntax attributes decode to `Dn` (with a parsed RDN chain) once; the underlying LDAP entry's `distinguishedName` string is preserved as a `Arc<str>` for wire serialization.
- The policy engine's JSON canonical format (ADR-029) SHALL be derived from the same `SchemaProjection`. ADMX-to-JSON translation (PC-046) consumes `attributeSchema` metadata (`attributeSyntax`, `oMSyntax`, `rangeLower`, `rangeUpper`, `searchFlags`) to produce a JSON-Schema-equivalent validation document.
- The KDC's PAC builder (per ADR-009 constructed attributes and ADR-018 KDC scaling) SHALL consume the typed projection for `user` / `computer` / `group` objects; PAC construction is the single hottest typed-projection consumer (~5K–50K/sec per KDC instance).
- The framework SHALL NOT use protobuf, SQL DDL, JSON Schema, or any IDL as the schema source of truth. LDAP `attributeSchema`/`classSchema` is the only source. Generated Rust source is a build artifact of the live directory, not a checked-in artifact.

## Rationale

The hybrid resolves a tension that neither pure-LDAP-dynamic nor pure-typed can resolve alone.

**Why not pure LDAP dynamic (Option A).** The LDAP-dynamic model (every attribute is a string/byte blob; consumers parse) is what AD ships. It maximizes interop and runtime extensibility. It is also the source of significant cost: every consumer of a `user` object — the KDC's PAC builder, the policy engine'security-descriptor evaluator, the cert service's subject-alt-name generator, the SDK's `Get-ADUser` equivalent — re-parses the same attributes from scratch. In the framework's hot path (KDC PAC construction, ADR-018), this is unacceptable: 5K AS-REQ/sec × ~30 attributes parsed per request = 150K parses/sec, each involving string-to-SID or string-to-UTCTime conversion. Pure dynamic also blocks type-safe SDKs: the Python/Go/Rust SDKs cannot offer `user.sam_account_name` if the schema is opaque. Cross-platform parity (PC-095 unified authoring) is impossible without a typed surface.

**Why not pure typed (Option B).** The pure-typed model (protobuf/SQL DDL with versioned migrations, no runtime extension) is what modern greenfield directories (e.g. InfraDB, Ory Kratos) tend toward. It maximizes compile-time safety and tooling. It also breaks AD interop: AD's wire format is LDAP-with-schema, ADUC / Get-ADUser / `samba-tool` / impacket all speak LDAP; rejecting runtime schema extension means rejecting AD's `schemaModifyRequest`. AD-interop mode becomes impossible, and PC-017 (LDAP vs typed schema) is "solved" by eliminating AD-interop — not an acceptable outcome for a framework whose entire migration story (PC-125 GPO translation, PC-124 sIDHistory migration, ADR-068 subdomain DNS) depends on interop.

**Why hybrid (Option C) wins.** Hybrid preserves LDAP as the wire/storage format (AD-interop intact) while giving the framework a typed Rust projection for hot paths and SDK consumers. The schema compiler is a build-time-eliminated indirection: production code paths see native Rust structs, not string-keyed maps. Runtime schema extension (`schemaModifyRequest`) works because the projection is regenerated from the live directory at every schema-generation swap; an attribute added at 03:00 is in the typed projection by the next boot (or by `adrian-schema recompile`). New framework-native classes can be defined as Rust traits and projected back to LDAP for interop — this is the path for v2 capabilities that AD doesn't have (e.g. `ManagedWorkload`, `PolicyBundle`, `DelegatedOu`) without breaking AD-aware tools.

The hybrid also aligns with the partial-ADR dependents. ADR-003 (schema cache COW) already assumes a generational schema representation; the typed projection slots in as another consumer of the same generation swap. ADR-009 (constructed attributes) computes `tokenGroups`/`memberOf` lazily on top of the typed projection — without typed accessors, each construction walks string-keyed maps. ADR-024 (per-platform policy executors, PARTIAL) needs a typed policy-area surface on macOS/Linux; the typed projection is the natural source. ADR-029 (JSON canonical policy) derives its JSON-Schema from the LDAP schema's `attributeSyntax`/`oMSyntax`/`rangeLower`/`rangeUpper` — a 1:1 mapping that pure-typed alternatives would have to translate.

External evidence: Samba 4's `libds` module already implements a hybrid (LDAP-schema-as-truth with an internal `ldb_message_element` typed-ish layer); 389-DS's `slapi_attr` infrastructure is similar; the industry pattern for greenfield directories (FreeIPA's `ipaldap`, Ory Kratos's identity schema) trends toward a typed layer above an LDAP or LDAP-shaped substrate. The framework's contribution is making the typed layer Rust-native and codegen-from-live-directory rather than codegen-from-IDL.

## Trade-offs accepted

- **Boot-time codegen cost.** Every DSA boot compiles the schema projection from the Schema NC. On a 5K-attribute, 1K-class schema (mid-size AD forest), the compiler walks ~6K objects and emits a projection in ~300 ms (estimated; confirmed by the schema-compiler prototype in Spike 7's prerequisite work). This is paid once per boot, not per request. Acceptable.
- **Memory overhead.** The `Arc<SchemaProjection>` adds ~80 MB to resident set on a mid-size schema (typed accessors + index tables + class-hierarchy graph). Acceptable on any modern DC.
- **Two representations to keep consistent.** A framework engineer adding a new attribute must add it as an `attributeSchema` (LDAP layer) AND declare a typed accessor in the framework trait (Rust layer). If the two diverge — e.g. the typed accessor reads `mail` but the LDAP schema says `mail` is single-valued while the trait says `Vec<String>` — the projection compile fails loudly at boot. This is a feature, not a bug: the projection is a verified binding between the two layers, not a silent assumption.
- **Runtime schema extension requires projection recompile.** A schema modify takes ~200 ms (per ADR-003 cache rebuild) plus ~300 ms (projection recompile) = ~500 ms total. This is slower than AD's pure-LDAP-dynamic modify (which only does the cache rebuild) but vastly faster than the pure-typed alternative (which requires a deploy). Acceptable for the framework's release cadence.
- **Dynamic fallback exists forever.** Even with the typed projection, the `obj.get::<"cn">()` dynamic accessor remains. This is intentional: it is the escape hatch for runtime-added attributes that haven't been bound to typed accessors yet. Removing it would defeat the purpose of supporting runtime schema extension.
- **Framework-native classes can shadow LDAP classes.** A `ServiceAccount` Rust trait projects onto `msDS-ManagedServiceAccount`; if an operator writes a `msDS-ManagedServiceAccount` directly via LDAP, the framework reads it back as a `ServiceAccount` (the projection is bijective). This is fine but means the trait's invariants (e.g. "gMSA must have a `msDS-GroupMSAMembership` SD") must be enforced at the LDAP-write layer, not just at the trait-write layer. The framework's DSA write validator enforces both.

## Rust implementation implications

**Crates used**:

- `adrian-schema-compiler` (framework crate, written from scratch — no production crate exists for LDAP-schema-to-Rust-projection compilation). Implements the Schema-NC walker, the syntax-to-Rust-type mapping table, the projection emitter, and the boot-time driver.
- `adrian-schema-traits` (framework crate). Defines `#[derive(Projectable)]`, `TypedObject`, `AttributeReader`, `AttributeWriter`, the syntax enum, and the framework-native trait library.
- `rasn` (v0.10+, MIT/Apache-2.0) for ASN.1 parsing of `objectSecurityDescriptor`, `dNSProperty`, and other ASN.1-encoded attributes. `rasn` is the modern pure-Rust ASN.1 codec; it is used by the Rust kerberos ecosystem (`krb5-rs` family).
- `ldap3` (v0.11+, MIT/Apache-2.0) for the schema compiler's bootstrap read of the Schema NC. `ldap3` is the de facto Rust LDAP client.
- `uuid` (v1.10+, MIT/Apache-2.0) for `schemaIDGUID` and `attributeID` GUID handling.
- `oid` (v0.2+, MIT/Apache-2.0) for `governsID` / `attributeID` OID parsing.
- `phf` (v0.11+, MIT/Apache-2.0) for compile-time-generated perfect hash tables in the schema compiler's static class registry.
- `tracing` (v0.1+, MIT) for projection-build observability.
- `proptest` (v1.4+, MIT/Apache-2.0) for property-based testing of the projection's bijectivity (LDAP entry → typed struct → LDAP entry must round-trip).

**Crates NOT used**:

- `prost` / `tonic` (protobuf) — rejected; protobuf is a serialization format, not a schema representation. Using protobuf as the schema source would force a build-time IDL step and break runtime schema extension.
- `diesel` / `sea-orm` (SQL DDL) — rejected; SQL DDL is the storage layer's concern (per ORQ-011/012/013/014), not the schema layer's. Mapping LDAP `attributeSchema` to SQL DDL is the storage engine's responsibility, not the schema compiler's.
- `serde_json` Schema — rejected as the source of truth; JSON Schema is used downstream (ADR-029 policy JSON) but is generated from the LDAP schema, not the reverse.

**Module layout** (in `crates/adrian-schema-compiler`):

```
src/
  lib.rs              # public API: compile_schema(schema_nc: &SchemaNc) -> Arc<SchemaProjection>
  walker.rs           # walks attributeSchema/classSchema objects, builds intermediate IR
  syntax.rs           # LDAP attributeSyntax + oMSyntax → Rust type mapping table
  projector.rs        # IR → Rust typed structs (in-memory, not source-emitting)
  traits.rs           # #[derive(Projectable)] macro
  validation.rs      # bijectivity checks (LDAP → typed → LDAP round-trip)
  native_classes/     # framework-native trait declarations
    service_account.rs
    managed_device.rs
    policy_set.rs
    cert_template.rs
```

**Performance targets**:

- Schema projection build (boot): ≤500 ms for a 10K-attribute, 2K-class schema.
- Schema projection recompile (on schema modify): ≤300 ms incremental (uses persistent-data-structure sharing per ADR-003).
- Typed attribute access (`obj.cn()`): ≤50 ns (direct field access via the projected struct).
- Dynamic attribute access (`obj.get::<"cn">()`): ≤200 ns (hash-table lookup + downcast).
- LDAP-entry-to-typed-projection decode: ≤2 µs for a 30-attribute user object (target benchmark).

**Testing strategy**:

- Property-based: every LDAP entry in the test corpus must round-trip through the typed projection and back to a byte-identical LDAP entry.
- AD-interop: import a real AD schema (from `cn=Schema,cn=Configuration,DC=...` LDIF export of a Server 2022 forest); the projection must compile and every attribute must be accessible.
- Codegen regression: snapshot the `adrian-schema dump-rust` output for the test schema; CI fails if the snapshot changes without an explicit update.

## Problems unblocked

| PC | Title (short) | Capability | Severity | Pre-gating ORQ | Now unblocked by Decision 4? |
|----|---------------|-----------|----------|----------------|------------------------------|
| PC-017 | LDAP schema vs typed schema | Core Directory | high | ORQ-030/031 | YES — this decision IS the answer to PC-017 |
| PC-021 | instanceType/systemFlags bitmasks | Core Directory | medium | ORQ-030/031 | YES — typed projection exposes bitflags via `bitflags!` macros; explicit accessor methods replace raw bitmask reads |
| PC-045 | GPO Preferences XML no macOS/Linux equivalent | Policy Engine | blocker | ORQ-030/031 | YES — typed projection is the substrate for JSON canonical policy (ADR-029); GPPref XML maps onto typed structs |
| PC-046 | ADMX schema Windows-specific | Policy Engine | high | ORQ-030/031 | YES — ADMX-to-typed-projection translator is the migration path; new policy authored against the typed projection directly |
| PC-095 | No unified policy authoring | Cross-Platform Parity | blocker | ORQ-030/031 + ORQ-169/170/175/176 | PARTIAL — this decision unblocks the schema half; the Client SDK half remains gated by Decision 7 |
| PC-107 | Schema upgrades irreversible | Operations | high | ORQ-030/031 | YES — typed projection regenerates from the live Schema NC; schema-as-code (Rust traits + LDAP schemaModify) is reversible because the LDAP layer supports attribute removal (with `systemFlags` checks) |
| PC-113 | Functional level upgrades one-way | Operations | medium | ORQ-030/031 | YES — framework replaces functional levels with per-feature feature flags stored as `attributeSchema` extensions; the typed projection surfaces feature availability via trait methods |
| PC-125 | GPO translation manual | Migration | high | ORQ-030/031 | YES — ADMX-to-typed-projection translator automates GPO translation; manual mapping becomes a fallback for non-standard ADMX |
| PC-010 | Cross-domain move | Core Directory | medium | ORQ-026/027 + ORQ-030/031 | PARTIAL — schema half unblocked; identity-model half (ORQ-026/027) gated by Decision 3 |

Plus partial-ADR dependents that can now be promoted from PARTIAL to full:

- **ADR-024** (per-platform policy executors) — was PARTIAL on ORQ-090/091 (policy format) AND ORQ-030/031 (schema). The schema half is now resolved; ADR-024 can be promoted once ORQ-090/091 is resolved (Day 2 PM session).
- **ADR-003** (schema cache COW) — was already full but its consumer (the projection) was undefined; this decision specifies the consumer.
- **ADR-009** (constructed attributes) — `tokenGroups`/`memberOf` consumers now have a typed surface; the ADR's deferral on `tokenGroups` caching (ORQ-032) is unaffected but the consumer integration is now specified.

## Implementation impact

**Person-week estimates per capability**:

- Core Directory: 8 person-weeks. Schema compiler (4 pw), trait derive macro (2 pw), native-class trait library (1 pw), validation/proptest harness (1 pw).
- KDC: 2 person-weeks. PAC builder migration from raw-attribute reads to typed-projection reads; benchmarks and regression tests.
- Policy Engine: 4 person-weeks. JSON canonical format derived from the projection; ADMX-to-typed-projection translator; GPPref-XML-to-typed-projection translator.
- Auth Provider: 1 person-week. LDAP-write validator integration (enforce trait invariants at the LDAP layer).
- Client SDK: 3 person-weeks. Typed SDK surface generated from the projection; Python (PyO3) and Go (cgo) bindings expose typed accessors.
- Migration: 2 person-weeks. GPO-translation automation (PC-125); AD-schema-import tooling.

**Total: 20 person-weeks.** This is on the Phase 1 (architecture decisions) → Phase 2 (MVP) critical path. The schema compiler is the long pole (4 pw) and should be staffed by a senior engineer with proc-macro experience.

**Risk items**:

- **proc-macro stability.** The `#[derive(Projectable)]` macro must work across Rust 1.75+ (the framework's MSRV). The macro should be designed for forward-compatibility with expected Rust changes (extracted trait methods, async traits).
- **Boot-time regression under huge schemas.** A 50K-attribute schema (SAP-extended AD) might push the projection build over 1 second. Mitigation: parallelize the schema walk with `rayon`; cache the compiled projection to disk (invalidated by `schemaCacheGeneration`).
- **AD schema quirks.** Real AD schemas have ~10K attributes that aren't in the standard reference; the projection must handle unknown syntaxes (`2.5.5.X` OIDs not in the standard table) by falling back to `Attr<Vec<u8>>` rather than failing.

## Cross-capability dependencies

- **Core Directory ↔ KDC.** The KDC's PAC builder (ADR-018) is the single largest consumer of the typed projection. Performance of the projection's `user`/`group` accessors directly bounds KDC throughput.
- **Core Directory ↔ Policy Engine.** ADR-029 JSON canonical policy is derived from the projection. ADMX translation (PC-046) and GPPref translation (PC-045) both consume the projection's syntax metadata.
- **Core Directory ↔ Client SDK.** The typed SDK surface (Decision 7, ORQ-169/170/175/176) is generated from the projection. PyO3/cgo/napi-rs bindings wrap the Rust typed accessors.
- **Core Directory ↔ Cert Service.** Certificate templates (`msPKI-*` attributes, PC-058) become typed Rust structs in the projection; the cert service consumes them as `CertificateTemplate` rather than raw LDAP entries.
- **Core Directory ↔ Operations.** Schema-as-code (PC-107) is enabled by the projection's `#[derive(Projectable)]` workflow: a new attribute is a PR that adds an `attributeSchema` LDIF + a Rust trait field, both verified at boot.
- **Core Directory ↔ Migration.** GPO translation (PC-125) and AD-schema-import both consume the projection as the target representation.

**No capability is unaffected.** Every framework module that reads directory objects benefits from the typed projection; this is the cross-cutting decision with the largest blast radius in the workshop.

## References

- [`workshop/CONTEXT.md`](./CONTEXT.md) — §ORQ-030/031 (schema model) candidate analysis; §Decision criteria (AD-interop, cross-platform parity, scalability, security, operability, implementation cost, migration feasibility)
- [`adr/TRIAGE.md`](../adr/TRIAGE.md) — DEFERRED problems PC-010/017/021/045/046/095/107/113/125 gated by ORQ-030/031
- [`adr/ADR-003-schema-cache-cow.md`](../adr/ADR-003-schema-cache-cow.md) — Copy-on-write schema cache with monotonic generation numbers; the typed projection is a consumer of the same generation swap
- [`adr/ADR-009-constructed-attributes.md`](../adr/ADR-009-constructed-attributes.md) — Constructed attributes (`tokenGroups`, `memberOf`) computed on top of the typed projection
- [`adr/ADR-024-per-platform-policy-executors.md`](../adr/ADR-024-per-platform-policy-executors.md) — PARTIAL; the schema half of its dependency is now resolved
- [`adr/ADR-029-json-canonical-policy-preg-adapter.md`](../adr/ADR-029-json-canonical-policy-preg-adapter.md) — JSON canonical policy derived from the LDAP schema via the typed projection
- [`docs/03-directory-schema/01-schema-attributes.md`](../docs/03-directory-schema/01-schema-attributes.md) — attributeSyntax, oMSyntax, lDAPDisplayName, schemaIDGUID, systemFlags
- [`docs/04-group-policy/03-admx-templates.md`](../docs/04-group-policy/03-admx-templates.md) — ADMX schema, namespace, policy element structure
- [RFC 4512](https://www.rfc-editor.org/rfc/rfc4512) — LDAP directory information models (schema definitions)
- [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517) — LDAP syntaxes
- [MS-ADTS §3.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Active Directory schema technical specification
