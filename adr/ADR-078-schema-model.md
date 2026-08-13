---
title: "ADR-078: Hybrid Schema Model — LDAP Schema as Source of Truth with Rust Typed Projection"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: Core Directory
problem: PC-017
severity: high
unblocked_by: Workshop Decision 4 (ORQ-030/031)
tags: [adr, core-directory, schema, ldap, typed-projection, codegen, hybrid, foundationdb-keyspaces]
related:
  - ./README.md
  - ./TRIAGE.md
  - ../workshop/decision-04-schema-model.md
  - ../workshop/decision-02-storage-engine.md
  - ../catalog/01-core-directory.md
  - ../docs/03-directory-schema/01-schema-attributes.md
  - ../docs/00-overview/02-ad-architecture.md
  - ./ADR-003-schema-cache-cow.md
  - ./ADR-079-schema-cache-reload-behavior.md
last_updated: 2026-08-13
---

# ADR-078: Hybrid Schema Model — LDAP Schema as Source of Truth with Rust Typed Projection

## Status

Accepted — 2026-08-13. This ADR was DEFERRED during the initial triage pending resolution of Tier-1 ORQ-030/031 (schema model). It is now unblocked by [Workshop Decision 4 (Hybrid LDAP Schema + Typed Rust Projection)](../workshop/decision-04-schema-model.md). Decision 2 (FoundationDB keyspaces) provides the storage substrate for the schema NC, but the architectural unblocking is Decision 4.

## Context

AD schema uses `attributeSchema` (governsID `1.2.840.113556.1.5.18`) and `classSchema` (governsID `1.2.840.113556.1.5.4`) LDAP objects in `CN=Schema,CN=Configuration,<forest-root-dn>`. Each attribute has an X.500 OID from the Microsoft arc `1.2.840.113556.1.x` (or from a private enterprise arc `1.3.6.1.4.1.<PEN>` for custom attributes), an `attributeSyntax` (X.500 abstract syntax like `2.5.5.12` DirectoryString), an `oMSyntax` (X.520 concrete syntax like 64 caseExactString), a `searchFlags` bitmask (indexing, ANR, confidential, RODC-filtered), `linkID` pairing (forward + backlink), `isMemberOfPartialAttributeSet` (GC membership), `isSingleValued`, `systemOnly`, `rangeLower` / `rangeUpper`. Each class has `subClassOf`, `systemMayContain` / `systemMustContain`, `mayContain` / `mustContain`, `possSuperiors` / `systemPossSuperiors`, `defaultSecurityDescriptor`, `schemaIDGUID`, per [PC-017](../catalog/01-core-directory.md#pc-017--schema-is-ldap-schema-with-oids-typed-schema-alternative-requires-migration-tooling) and [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md).

OpenLDAP and 389-DS use RFC 4512 `attributeType` / `objectClass` definitions in `cn=schema`. The schema is still LDAP-schema with OIDs, just a slightly different representation. A typed-schema alternative (protobuf, SQL DDL, JSON Schema, Cap'n Proto) would require a complete migration path from LDAP schema, plus runtime translation for AD-aware clients that read schema via LDAP. The benefit of typed schema is compile-time type checking, code generation, and structured access; the cost is loss of LDAP-schema compatibility and a non-trivial migration.

The schema choice cascades into the directory API (LDAP queries vs typed queries), the replication protocol (LDAP-schema attributes replicate as BER-encoded values; typed schema would replicate differently), and the client SDK (LDAP wrapper vs typed client). A hybrid approach (LDAP schema + typed projection) is possible but doubles the maintenance surface.

**Unblocking decision.** [Workshop Decision 4](../workshop/decision-04-schema-model.md) selected the hybrid model: the LDAP schema (`attributeSchema` / `classSchema` instances in the Schema NC) is the authoritative source of truth at the wire and storage layers, and Rust code generation at boot time produces a typed projection that the SDK, the policy engine, the KDC's PAC builder, and the cert-service template manager consume. [Workshop Decision 2](../workshop/decision-02-storage-engine.md) provides the FDB substrate — the schema NC is stored in FDB subspace `0x01` (objects), with the schema cache generation swap (per ADR-003) in subspace `0x04`. This ADR translates Decision 4 into the concrete schema implementation.

## Decision

The framework SHALL treat the LDAP schema as the authoritative source of truth at the wire and storage layers, and SHALL use Rust code generation at boot time to produce a typed projection that the framework's internal code (KDC's PAC builder, policy engine, cert-service template manager, SDK) consumes. The schema compiler (`adrian-schema-compiler` crate) SHALL be invoked at DSA boot, at every `schemaUpdateNow` operational-attribute write, and on-demand via `adrian-schema recompile`. The typed projection SHALL be an in-memory `Arc<SchemaProjection>`; the compiler does NOT write source files to disk in production (a separate `adrian-schema dump-rust` developer command can emit Rust source for offline inspection).

**Concrete specification**:

- The framework's directory SHALL accept `schemaModifyRequest` (RFC 4511 ModifyRequest on the Schema NC) and apply it via the same copy-on-write transactional path as any other write (per ADR-003). Adding an `attributeSchema` SHALL NOT require a framework rebuild, a redeploy, or a service restart; the typed projection is regenerated on the next schema-generation swap (target <200 ms per ADR-003, plus ~300 ms projection recompile = ~500 ms total).
- The schema compiler SHALL walk the Schema NC, parse each `attributeSchema` and `classSchema` object, build an intermediate representation (IR), and emit an in-memory `Arc<SchemaProjection>`. The projection includes: typed Rust structs for each class, typed accessors for each attribute, the class-hierarchy graph, the linkID pairing map, and the index metadata (searchFlags).
- The typed projection SHALL expose every LDAP attribute via `obj.get::<"cn">() -> Result<Attr<String>>` (the dynamic fallback) AND, for attributes declared in a known-class projection, via `obj.cn() -> Result<&str>` (the typed accessor). The dynamic fallback is the escape hatch for runtime-added attributes that have not yet been bound to a typed accessor — it is always available, ensuring schema extensions never block application code.
- Framework-native traits SHALL be declared in the framework's `crates/adrian-schema-traits` crate with `#[derive(Projectable)]`. The derive macro emits the projection glue (`ldap_class_ids()`, `read_from(&Entry)`, `write_to(&mut EntryBuilder)`). Framework-native classes (`ServiceAccount`, `ManagedDevice`, `PolicySet`, `CertificateTemplate`) project onto LDAP classes (`msDS-ManagedServiceAccount`, `computer`, `group`, `pKICertificateTemplate`) and are projected **back** to LDAP at write time, so a `ServiceAccount` written via the typed SDK materialises as a `msDS-ManagedServiceAccount` object in the directory with all `msDS-*` attributes populated byte-identically to a Samba-tool-created one.
- The projection's typed accessors SHALL NOT parse string values at runtime beyond what the LDAP syntax requires. SID-syntax attributes decode to `Sid` once at read time and are stored as `Sid` in the typed struct; subsequent reads return `&Sid`. DN-syntax attributes decode to `Dn` (with a parsed RDN chain) once; the underlying LDAP entry's `distinguishedName` string is preserved as a `Arc<str>` for wire serialisation.
- The framework SHALL support the `schemaUpdateNow` operational attribute (write to `CN=Aggregate,CN=Schema,...`) for AD-interop compatibility. The write triggers the schema cache generation swap (per ADR-003) and the typed projection recompile (this ADR). The combined latency is ~500 ms (target).
- The framework SHALL NOT use protobuf, SQL DDL, JSON Schema, or any IDL as the schema source of truth. LDAP `attributeSchema` / `classSchema` is the only source. Generated Rust source is a build artifact of the live directory, not a checked-in artifact.
- The schema NC SHALL be stored in FDB subspace `0x01` (objects), with one row per `attributeSchema` / `classSchema` object. The schema cache generation swap (per ADR-003) lives in subspace `0x04`. The schema projection is in-memory only (not persisted).
- For AD-interop mode, the framework SHALL replicate the Schema NC via DRSUAPI (per ADR-070). For native mode, the framework SHALL replicate the Schema NC via Raft (per ADR-071). The schema compiler reads the Schema NC from FDB regardless of replication mode.
- The policy engine's JSON canonical format (per ADR-029) SHALL be derived from the same `SchemaProjection`. ADMX-to-JSON translation (PC-046) consumes `attributeSchema` metadata (`attributeSyntax`, `oMSyntax`, `rangeLower`, `rangeUpper`, `searchFlags`) to produce a JSON-Schema-equivalent validation document.
- The KDC's PAC builder (per Decision 5) SHALL consume the typed projection for `user` / `computer` / `group` objects. PAC construction is the single hottest typed-projection consumer (~5K–50K/sec per KDC instance).
- Performance targets: schema projection build (boot) ≤500 ms for a 10K-attribute, 2K-class schema; schema projection recompile (on schema modify) ≤300 ms incremental; typed attribute access (`obj.cn()`) ≤50 ns; dynamic attribute access (`obj.get::<"cn">()`) ≤200 ns; LDAP-entry-to-typed-projection decode ≤2 µs for a 30-attribute user object.

## Rationale

The hybrid resolves a tension that neither pure-LDAP-dynamic nor pure-typed can resolve alone.

**Why not pure LDAP dynamic (Option A).** The LDAP-dynamic model (every attribute is a string/byte blob; consumers parse) is what AD ships. It maximises interop and runtime extensibility. It is also the source of significant cost: every consumer of a `user` object — the KDC's PAC builder, the policy engine's security-descriptor evaluator, the cert service's subject-alt-name generator, the SDK's `Get-ADUser` equivalent — re-parses the same attributes from scratch. In the framework's hot path (KDC PAC construction, ADR-018), this is unacceptable: 5K AS-REQ/sec × ~30 attributes parsed per request = 150K parses/sec, each involving string-to-SID or string-to-UTCTime conversion. Pure dynamic also blocks type-safe SDKs.

**Why not pure typed (Option B).** The pure-typed model (protobuf/SQL DDL with versioned migrations, no runtime extension) is what modern greenfield directories tend toward. It maximises compile-time safety and tooling. It also breaks AD interop: AD's wire format is LDAP-with-schema, ADUC / Get-ADUser / `samba-tool` / impacket all speak LDAP; rejecting runtime schema extension means rejecting AD's `schemaModifyRequest`. AD-interop mode becomes impossible.

**Why hybrid (Option C) wins.** Hybrid preserves LDAP as the wire/storage format (AD-interop intact) while giving the framework a typed Rust projection for hot paths and SDK consumers. The schema compiler is a build-time-eliminated indirection: production code paths see native Rust structs, not string-keyed maps. Runtime schema extension (`schemaModifyRequest`) works because the projection is regenerated from the live directory at every schema-generation swap; an attribute added at 03:00 is in the typed projection by the next boot (or by `adrian-schema recompile`).

External evidence: Samba 4's `libds` module already implements a hybrid (LDAP-schema-as-truth with an internal `ldb_message_element` typed-ish layer); 389-DS's `slapi_attr` infrastructure is similar; the industry pattern for greenfield directories (FreeIPA's `ipaldap`, Ory Kratos's identity schema) trends toward a typed layer above an LDAP or LDAP-shaped substrate. The framework's contribution is making the typed layer Rust-native and codegen-from-live-directory rather than codegen-from-IDL.

## Consequences

**Positive**: AD-interop is preserved (LDAP schema on the wire). Type-safe SDKs and hot-path code (KDC PAC builder) consume native Rust structs. Runtime schema extension works without redeploy. Framework-native classes (`ServiceAccount`, `ManagedDevice`) project onto LDAP classes for AD-interop while giving the framework typed access. The policy engine's JSON canonical format (per ADR-029) derives from the same projection.

**Negative**: Boot-time codegen cost (~500 ms per boot for a 10K-attribute schema — paid once per boot, not per request). Memory overhead (~80 MB resident set for the `Arc<SchemaProjection>` on a mid-size schema). Two representations to keep consistent (LDAP schema + typed trait) — the projection's bijectivity check fails loudly at boot if they diverge. Runtime schema extension requires projection recompile (~300 ms incremental). Dynamic fallback exists forever (the escape hatch for runtime-added attributes that haven't been bound to typed accessors).

**Neutral**: AD-aware tools (ADUC, ADSI Edit, ADSI Edit) see identical schema reads before, during, and after a schema modify. Framework engineers use the typed projection; LDAP clients use the LDAP schema. The boundary is the `SchemaProjection` compile step.

**Cost**: ~20 person-weeks total (per Decision 4) for the `adrian-schema-compiler` crate, the `adrian-schema-traits` crate, the syntax-to-Rust-type mapping table, the projection emitter, the boot-time driver, the bijectivity validation, the framework-native trait library, and the property-based testing infrastructure.

**Operational impact**: Schema modifications complete in <500 ms (target), versus 5–30 seconds in AD (per ADR-003 + this ADR). The framework can ship schema-changing features without coordinating maintenance windows. `adrian-schema recompile` is the manual trigger; `schemaUpdateNow` write is the automatic trigger.

## Alternatives Considered

### Alternative 1: Pure LDAP dynamic (no typed projection)

Maximum interop and runtime extensibility. Every consumer re-parses attributes from scratch — unacceptable in the KDC PAC hot path (150K parses/sec). Blocks type-safe SDKs. Rejected: performance and SDK ergonomics are v1 requirements.

### Alternative 2: Pure typed (protobuf/SQL DDL, no runtime extension)

Maximum compile-time safety and tooling. Breaks AD-interop: AD's wire format is LDAP-with-schema; rejecting runtime schema extension rejects `schemaModifyRequest`. AD-interop mode becomes impossible. Rejected: AD-interop is a v1 requirement.

### Alternative 3: Hybrid with checked-in generated Rust source (codegen-from-IDL)

The schema source is an IDL (protobuf, Cap'n Proto); the LDAP schema is generated from the IDL at build time; the typed projection is generated from the IDL at compile time. The advantage is build-time safety. The disadvantage is losing runtime schema extension (`schemaModifyRequest` requires an IDL change and a rebuild). Rejected: runtime schema extension is required for AD-interop and for the framework's own schema evolution.

## Open Questions

- For framework-native classes (`ServiceAccount`, `ManagedDevice`), should the framework enforce trait invariants at the LDAP-write layer or only at the trait-write layer? Default: both — the LDAP-write validator enforces structural invariants (e.g., `msDS-GroupMSAMembership` is required on `msDS-ManagedServiceAccount`); the trait-write layer enforces semantic invariants (e.g., `ServiceAccount` must have a `managedBy` reference). Confirm in implementation.
- For the dynamic fallback (`obj.get::<"cn">()`), should the framework deprecate it over time as more attributes are bound to typed accessors? Default: no — the dynamic fallback is the permanent escape hatch for runtime-added attributes. Document in the SDK guidelines.
- For very large schemas (50K+ attributes, e.g., Exchange-extended schemas), is the 500 ms boot-time codegen cost acceptable? Default: yes, paid once per boot. Confirm with customer-scale benchmark.

## Cross-capability impact

- **KDC**: KDC's PAC builder consumes the typed projection for `user` / `computer` / `group` objects — the hottest typed-projection consumer. Typed accessors eliminate per-AS-REQ string parsing.
- **Auth Provider**: S4U2Proxy / RBCD configurations (`msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`) consume the typed projection for linked-attribute access.
- **Policy Engine**: GPO attribute definitions consume the typed projection; the JSON canonical format (per ADR-029) derives from the same projection. ADMX-to-JSON translation (PC-046) consumes `attributeSchema` metadata.
- **Cert Service**: Certificate templates reference principals by UUID (internal) or SID (AD-interop); the typed projection handles translation.
- **File Gateway**: File ACLs reference principals by SID; the typed projection decodes SID-syntax attributes to `Sid` once at read time.
- **Client SDK**: The SDK exposes typed accessors (`user.sam_account_name()`) for known classes and dynamic accessors (`user.get::<"extensionAttribute">()`) for runtime-added attributes.
- **Operations**: Schema modifications complete in <500 ms (no maintenance windows). `adrian-schema recompile` is the manual trigger.
- **Migration**: AD-to-framework migration imports the AD schema (LDIF export of `cn=Schema,cn=Configuration`); the projection compiles from the imported schema. ADMX-to-typed-projection translator (per PC-125) automates GPO translation.

## References

- [PC-017](../catalog/01-core-directory.md) — problem statement in the catalog
- [Workshop Decision 4 — Hybrid LDAP Schema + Typed Rust Projection](../workshop/decision-04-schema-model.md) — unblocking decision
- [Workshop Decision 2 — FoundationDB Storage Engine](../workshop/decision-02-storage-engine.md) — FDB substrate for Schema NC
- [docs/03-directory-schema/01-schema-attributes.md](../docs/03-directory-schema/01-schema-attributes.md) — `attributeSchema` / `classSchema` attribute tables, OID allocation, `searchFlags` bitmask, `schemaUpdateNow`
- [docs/00-overview/02-ad-architecture.md](../docs/00-overview/02-ad-architecture.md) — schema cache reload behavior, `gSchemaCache` rebuild
- [MS-ADTS §3.1.1.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — schema model, `attributeSchema`, `classSchema`
- [RFC 4512](https://www.rfc-editor.org/rfc/rfc4512) — LDAP schema model (comparison reference)
- [rasn crate](https://github.com/librasn/rasn) — Rust ASN.1 / NDR encoding (used for ASN.1-encoded attributes)
- [ldap3 crate](https://github.com/inejge/ldap3) — Rust LDAP client (used by schema compiler's bootstrap read)
- [ADR-003: Schema Cache CoW](./ADR-003-schema-cache-cow.md) — schema cache generation swap substrate
- [ADR-029: JSON Canonical Policy PReg Adapter](./ADR-029-json-canonical-policy-preg-adapter.md) — JSON-Schema derived from LDAP schema
- [ADR-079: Schema Cache Reload Behavior](./ADR-079-schema-cache-reload-behavior.md) — reload mechanism details
