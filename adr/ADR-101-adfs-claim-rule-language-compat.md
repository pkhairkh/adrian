---
title: "ADR-101: AD FS claim rule language compatibility via Rust PEG-based engine"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: Federation Gateway
problem: PC-069
severity: high
unblocked_by: Workshop Decision 9
tags: [adr, federation-gateway, adfs, claims, crl, pest, peg, rust, migration]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/06-federation-gateway.md
  - ../workshop/decision-09-federation-layer.md
  - ../docs/06-federation-sso/03-claims-rules.md
  - ../docs/01-ad-core/03-ad-fs-federation.md
  - ./ADR-039-oidc-primary-wstrust-bridge.md
  - ./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md
last_updated: 2026-08-14
---

# ADR-101: AD FS claim rule language compatibility via Rust PEG-based engine

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 9](../workshop/decision-09-federation-layer.md) (Federation layer: wrap Keycloak with Rust AD-claim-rules shim). This ADR operationalises Decision 9 §2 (AD FS claim-rule language compatibility) against the PC-069 problem surface: AD FS's proprietary Claims Rule Language (CRL) DSL, which does not port to other IdPs and forces enterprises to manually translate every CRL rule during migration.

## Context

AD FS's claims pipeline is driven by a custom DSL expressed in `Microsoft.IdentityServer.ClaimsPolicy`. Per [docs/06-federation-sso/03-claims-rules.md](../docs/06-federation-sso/03-claims-rules.md), each rule uses the syntax `c:[Type == "...", Value == "...", ...] => issue(Type = "...", Value = c.Value);` and is evaluated in one of five phases: (1) Acceptance Transform Rules (per-CPT — filter/map claims from upstream IdP); (2) Issuance Authorization Rules (per-RPT — Permit/Deny decision); (3) Issuance Transform Rules (per-RPT — map claims to RP's expected vocabulary); (4) Delegation Rules (per-RPT — ActAs/OnBehalfOf token issuance); (5) Token Serialization (sign + serialize as SAML/JWT). The pipeline is evaluated by `Microsoft.IdentityServer.dll!PolicyEngine` with rule bodies optionally executing LDAP, SQL, or custom .NET attribute store queries.

Per [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md), AD FS attribute stores include `Active Directory` (built-in `Microsoft.IdentityServer.ClaimsPolicy.AttributeStore.ActiveDirectoryAttributeStore`, query format `;attr1,attr2;{0}`), `LDAP` (any LDAP server via `LdapAttributeStore`), `SQL` (`SqlAttributeStore` with `System.Data.SqlClient`, parameterized queries), and `Custom` (.NET class implementing `IAttributeStore`). Rule compilation is cached per `(TrustId, RuleHash)` as `Func<ClaimSet, IEnumerable<Claim>>` via `System.Linq.Expressions`.

The CRL is a proprietary DSL — it does not port to other IdPs. Keycloak has "mappers" (Hardcoded, User Attribute, Role, Script, Claim to Role) — no DSL. Authentik has expression policies (Python). Ory Oathkeeper has Rego (OPA) for access rules. Migration from AD FS to any other IdP requires manual translation of every CRL rule to the target's policy language — there is no automated CRL-to-mapper or CRL-to-Rego translator. Common patterns (pass-through, regex transform, conditional issuance, group-to-role mapping, authorization permit/deny) each require manual translation. For an enterprise with 50+ RPTs each with 5-10 rules, this is a multi-week migration effort with high risk of translation errors.

Workshop Decision 9 §2 fixes this by specifying that the framework's Rust shim ships `adrian-claims-engine`, a Rust library that parses and evaluates the AD FS claim rule language. The engine is the framework's answer to PC-069: instead of translating CRL rules to a different policy language, the framework runs CRL rules natively in the Rust shim, preserving the customer's claim-rule investment.

## Decision

The framework's Federation Gateway ships `adrian-claims-engine`, a Rust library that parses and evaluates the AD FS claim rule language natively. The engine is implemented via `pest = "2"` (PEG parser generator) for the grammar and `serde_json` for the claim-set representation. The engine is invoked by the Rust shim on every token issuance to apply per-RP claim-rule transformations to Keycloak-issued tokens.

### Concrete specification

1. **Grammar.** The `adrian-claims-engine` grammar is defined in `claims.pest` (~150 lines, per Decision 9). The grammar covers the canonical forms documented in [docs/06-federation-sso/03-claims-rules.md](../docs/06-federation-sso/03-claims-rules.md):
   - Issuance Transform Rules: `c:[Type == "email"] => issue(Type = "upn", Value = c.Value + "@corp.example.com");`
   - Pass-through: `c:[Type == "email"] => issue(claim = c);`
   - Conditional issuance: `c:[Type == "group", Value == "Sales"] && c2:[Type == "role", Value == "manager"] => issue(Type = "permission", Value = "approve");`
   - Suppression: `c:[Type == "temp"] => suppress(claim = c);`
   - Store-based: `c:[Type == "upn"] => issue(store = "Active Directory", query = "tokenGroups", param = c.Value);`
   - Regex match: `c:[Type == "email", Value =~ ".*@corp\\.example\\.com"] => issue(claim = c);`
   - Aggregate: `c:[Type == "group"] => issue(Type = "groupCount", Value = count(c));`

2. **Public API.** The library exposes:
   ```rust
   pub struct ClaimRuleSet { rules: Vec<Rule> }
   pub struct Claim { pub claim_type: String, pub value: String, pub issuer: String, pub original_issuer: String, pub properties: HashMap<String, String> }
   pub trait StoreContext {
       fn query(&self, store: &str, query: &str, params: &[String]) -> Result<Vec<Claim>, StoreError>;
   }
   pub fn parse(input: &str) -> Result<ClaimRuleSet, ParseError>;
   pub fn ClaimRuleSet::evaluate(&self, input_claims: &[Claim], ctx: &dyn StoreContext) -> Vec<Claim>;
   ```
   The `StoreContext` trait is implemented by the shim to provide AD-store-equivalent queries (e.g., `tokenGroups` for a user — translated to a framework-directory LDAP query for the user's group membership, including nested groups via the `memberOf` back-link per [ADR-002](./ADR-002-memberof-back-link.md)).

3. **Five-phase pipeline.** The engine evaluates claims through the same five phases as AD FS:
   - Acceptance Transform Rules (per Claims Provider Trust) — the shim evaluates these when Keycloak authenticates a user, before the user's claims enter the per-RP pipeline.
   - Issuance Authorization Rules (per Relying Party Trust) — the shim evaluates these before issuing a token to the RP; a `Permit` rule allows issuance, a `Deny` rule blocks it.
   - Issuance Transform Rules (per RPT) — the shim evaluates these to map claims to the RP's expected vocabulary.
   - Delegation Rules (per RPT, for ActAs/OnBehalfOf flows) — the shim evaluates these when the WS-Trust bridge (per [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md)) issues an ActAs token.
   - Token Serialization — the shim re-signs the JWT (or SAML assertion) with the framework's signing key after claim transformation.

4. **Store implementations.** The shim implements `StoreContext` for three stores:
   - `Active Directory` — translates `tokenGroups` queries to framework-directory LDAP queries via the shim's directory-integration layer; `mail`/`displayName`/`userPrincipalName` queries to LDAP attribute reads.
   - `LDAP` — translates arbitrary LDAP queries (the CRL `LDAP` store format `;attr1,attr2;{0}` is parsed and executed as an LDAP search against the framework directory).
   - `SQL` — not implemented in v1; SQL-store rules are dropped during migration with `WARN` (operators must rewrite as Keycloak protocol mappers or framework claim rules).
   - `Custom` — not implemented; custom attribute store .NET classes cannot run in Rust. Dropped with `WARN`.

5. **Token response interception.** When the shim intercepts a Keycloak token response (OIDC `/token` or SAML `/saml/sso`), it: (a) parses the JWT (or SAML assertion) and extracts the claim set Keycloak produced from Keycloak's protocol mappers; (b) loads the RP's claim-rule set (configured per-client via `adrian-fed client set --claim-rules <file>`); (c) evaluates the rule set against the claim set using `adrian-claims-engine`, producing a transformed claim set; (d) re-signs the JWT (or SAML assertion) with the framework's signing key (issued by the framework's CA per Decision 8, rotated per [ADR-038](./ADR-038-jwks-endpoint-webhook-rollover.md)) and returns the transformed token to the RP.

6. **Coverage.** The engine covers ~95% of the AD FS claim rule language used in practice (per Decision 9's analysis of ~10,000 AD FS rule sets from public migration case studies). The supported subset includes: issuance transform rules, pass-through, conditional issuance (`&&`, `||`), suppression, store-based queries (Active Directory, LDAP), regex match (`=~`), aggregate (`count`, `aggregate`), and claim-type/issuer/value conditions. The remaining 5% — rare constructs including `IssueStore` (multi-step store query with intermediate variables), custom-claim-store with arbitrary LDAP queries, and multi-valued claim aggregation with custom collation — are dropped with `WARN` during migration; operators must rewrite them as Keycloak protocol mappers or framework claim rules in the supported subset. The `adrian-migrate from-adfs` CLI emits a per-rule migration report listing supported and dropped rules.

7. **Migration tooling.** The `adrian-migrate from-adfs` CLI (per Decision 9 §5 and ADR-100) translates each AD FS Issuance Transform Rule to the shim's claim-rule configuration, parsed by `adrian-claims-engine` and stored as-is in `claim-rules.yaml` (the shim is rule-language-compatible, so no translation is needed for the ~95% supported subset). For dropped rules (the 5%), the CLI emits `WARN` with the rule text and a recommendation to rewrite as a Keycloak protocol mapper or a Rust-native custom evaluator (the shim's `StoreContext` trait extension point).

8. **Performance.** The engine's parse step is amortised: parsed rule sets are cached in the shim's in-process `moka` LRU (5-minute TTL, 1000 entries) keyed by `(client_id, rule_hash)`. The evaluate step targets ≤ 1 ms per rule for the supported subset (measured on a 10-rule set with 50 input claims). The store-query step (for `Active Directory` and `LDAP` store rules) is the slow path; the shim caches directory-query results in the same `moka` LRU (5-minute TTL) keyed by `(store, query, params_hash)`.

9. **Audit.** Every claim-rule evaluation is logged per [ADR-060](./ADR-060-structured-audit-logs-otel.md) with attributes `adrian.fed.realm`, `adrian.fed.client`, `adrian.fed.rule_count`, `adrian.fed.input_claims_count`, `adrian.fed.output_claims_count`, `adrian.fed.dropped_rules_count`, `adrian.fed.evaluate_duration_us`. The audit log is the primary forensic record for claim-issuance incidents.

## Rationale

The framework chose to support CRL natively rather than translate to a standard policy language (Rego, Cedar, XACML) for three reasons. First, translation is lossy and error-prone: the ~10,000 AD FS rule sets Decision 9 analysed exhibit dozens of edge-case patterns (multi-store queries, regex-based conditional suppression, aggregate-then-issue flows) that no automated translator can map cleanly to Rego or Cedar without semantic loss. The framework would ship a translator that "works for 80% of rules" — and the 20% that fail would be the hard ones that customers actually depend on. Second, native CRL support preserves the customer's existing claim-rule investment: the rule set a customer wrote for AD FS in 2018 works unchanged in the framework in 2026, modulo the 5% dropped subset. This is the same value proposition that drives ADR-100's AD FS migration CLI — keep the customer's investment intact. Third, the Rust shim is the natural place to host a claim-rule engine because the shim is already intercepting token responses for trust-pipeline enforcement (per Decision 9 §3); adding claim-rule evaluation to the same interception point adds no new latency surface.

The framework chose `pest` (PEG) over `nom` (parser combinators) and `lalrpop` (LR) because the CRL grammar is small (~150 lines of PEG), the language is regular enough that PEG's ordered-choice semantics work cleanly, and `pest`'s derive macro produces ergonomic AST types from the grammar. `nom` would require hand-rolling the AST construction; `lalrpop` would require maintaining a separate `.lalrpop` grammar file and a build-script step. The PEG choice trades a small runtime cost (PEG is slower than LR for very large inputs) for development simplicity and grammar readability.

The framework chose ~95% coverage rather than 100% because the remaining 5% (`IssueStore`, custom-claim-store with arbitrary LDAP queries, multi-valued claim aggregation with custom collation) is rare in practice (<5% of rule sets per Decision 9's analysis) and expensive to implement (each requires either a sub-DSL or a Rust extension point). The framework surfaces the 5% explicitly during migration (per §6 and §7) so customers can rewrite before cutover.

## Consequences

**Positive**. Customers migrating from AD FS keep their claim-rule investment — the ~95% supported subset runs unchanged in the framework. The `adrian-migrate from-adfs` CLI provides a per-rule migration report that surfaces the 5% dropped subset before cutover, giving customers a clear list of rules to rewrite. The Rust implementation eliminates the .NET dependency that AD FS's CRL evaluator carried; the engine runs in the same Pod as the rest of the Federation Gateway with no JVM/CLR overhead for claim evaluation.

**Negative**. The 5% dropped subset is a migration risk for customers whose rule sets fall in it. The framework's documentation must clearly call out the dropped constructs and recommend rewrites. The PEG grammar is a maintenance surface: AD FS rule-language edge cases (e.g., operator precedence in compound conditions, string-escape sequences in regex matchers) must be reflected in the grammar as customers encounter them. The engine is a trusted-code boundary — claim rules can produce arbitrary claims, so rules are authored by federation admins and reviewed via PR per ADR-031.

**Neutral**. The framework does not adopt a standard policy language (Rego, Cedar, XACML) for claim rules in v1; the CRL compatibility layer is the primary claim-rule surface. Customers who want Rego or Cedar for new claim rules can use Keycloak's built-in `Script` mapper (JavaScript) for new RPs; the framework may add Rego/Cedar support in v1.1 if customer demand warrants.

**Implementation cost**. ~3 person-weeks for v1 (per Decision 9): grammar definition (0.5 pw), parser (1 pw), evaluator (1 pw), store implementations (0.3 pw), migration CLI integration (0.2 pw). The grammar is the highest-risk item (PEG correctness across the full AD FS rule-language surface).

**Operational impact**. Federation admins author claim rules in CRL (familiar from AD FS), commit to Git via `claim-rules.yaml`, and apply via `adrian-fed apply`. The shim's Prometheus metric `adrian_fed_claims_evaluated_total{realm,client}` is the primary SLO for claim-rule performance; the audit log is the primary forensic record.

## Alternatives Considered

### Alternative A: Translate CRL to Rego (OPA) at migration time

`adrian-migrate from-adfs` translates each CRL rule to a Rego policy; the shim embeds OPA (`rego-rs` Rust crate) and evaluates Rego policies at token-issuance time. Rejected because (a) translation is lossy — the ~5% dropped subset of CRL has no clean Rego equivalent (multi-store queries require Rego's `http.send` to call back to the directory, which is a new network hop and a new failure mode); (b) Rego's evaluation model (declarative, no ordering) does not match CRL's evaluation model (sequential rule application with claim-set mutation), forcing the translator to introduce explicit ordering that Rego does not naturally support; (c) customers who learn Rego for the framework cannot reuse that knowledge against AD FS (the framework's value proposition is AD FS replacement, not Rego adoption); (d) the framework would inherit OPA's release cadence and Rego's evolving semantics for what is, fundamentally, a translation of a 2003-era DSL.

### Alternative B: Translate CRL to Cedar (AWS) at migration time

Same as Alternative A but with Cedar. Rejected for the same reasons, plus: Cedar has narrower adoption than Rego (no operator community in self-hosted enterprise); Cedar's schema validation is stricter than CRL's, forcing the translator to emit a Cedar schema per RP that the customer must maintain; Cedar's permit/deny model does not map cleanly to CRL's issue/suppress model.

### Alternative C: Per-IdP plugins (CRL for AD FS, mappers for Keycloak, expression policies for Authentik)

The framework's federation engine supports multiple policy backends; migration chooses the backend based on the source IdP. Rejected because (a) the framework chose Keycloak as the single engine (per Decision 9), so there is no "Authentik backend"; (b) Keycloak's mappers are not a DSL — they are individual Java classes with config forms, so a "CRL to mappers" translator must emit Java code or Keycloak-JSON mapper configs that are awkward to maintain; (c) customers migrating from AD FS would face a different policy model than customers writing new policy from scratch, creating a two-tier experience.

### Alternative D: Hand-write the parser with `nom` instead of `pest`

Use `nom = "7"` (parser combinators) instead of `pest` (PEG). Rejected because (a) the CRL grammar is small and regular — PEG's ordered-choice works cleanly; (b) `pest`'s derive macro produces ergonomic AST types from the grammar, reducing boilerplate; (c) `nom`'s error messages are notoriously hard to debug (the parser-combinator pattern produces deeply-nested error contexts); `pest` produces line/column errors directly from the grammar source. The runtime cost (PEG is ~2x slower than `nom` for the same grammar) is negligible for a 10-rule set evaluated ≤1 ms.

## Open Questions

- Should the framework add Rego or Cedar support for new claim rules in v1.1? Current decision: defer to v1.1; the CRL compatibility layer covers AD FS migration, and Keycloak's `Script` mapper (JavaScript) covers new RPs in v1.
- Should the engine support the `IssueStore` construct (multi-step store query with intermediate variables) in v1.1? Current decision: defer; the ~5% of rule sets that use `IssueStore` must rewrite as `Active Directory` or `LDAP` store rules in the supported subset.
- Should the engine expose a Rust-native extension point for custom evaluators (replacing AD FS's `Custom` attribute store .NET classes)? Current decision: yes, the `StoreContext` trait is the extension point; the framework's documentation includes a "custom store implementation" guide for v1.1.

## Cross-capability impact

- **Federation Gateway (PC-068 — AD FS topology).** Addressed in [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md). The claims-engine is a sub-component of the Rust shim.
- **Federation Gateway (PC-071 — WS-Trust bridge).** Addressed in ADR-039. The claims-engine evaluates Delegation Rules for ActAs/OnBehalfOf token issuance.
- **Federation Gateway (PC-075 — `resource=` compat).** Addressed in [ADR-041](./ADR-041-strict-oidc-default-resource-compat.md). The claims-engine does not interact with the `resource=` parameter (it operates on already-issued tokens).
- **Core Directory.** The shim's `StoreContext` implementation queries the directory for `Active Directory` and `LDAP` store rules; the directory's `memberOf` back-link (per ADR-002) is used for `tokenGroups` resolution.
- **Policy Engine (Workshop Decision 7).** Claim-rule configuration (`claim-rules.yaml`) is stored in Git (per ADR-031) and applied via `adrian-fed apply`, consistent with the framework's Git-backed configuration model.
- **Migration (PC-124 AD FS-to-framework).** The `adrian-migrate from-adfs` CLI is the migration entry point; the per-rule migration report is the customer's primary migration-planning artifact.

## References

- [PC-069](../catalog/06-federation-gateway.md) — problem statement
- [Workshop Decision 9](../workshop/decision-09-federation-layer.md) — §2 AD FS claim-rule language compatibility
- [docs/06-federation-sso/03-claims-rules.md](../docs/06-federation-sso/03-claims-rules.md) — CRL lexical structure, five-phase pipeline, attribute stores, rule compilation caching, common rule patterns
- [docs/01-ad-core/03-ad-fs-federation.md](../docs/01-ad-core/03-ad-fs-federation.md) — Claims pipeline phases, `Microsoft.IdentityServer.PolicyEngine.PolicyEngine` entry point, `IAttributeStore` interface
- [ADR-039](./ADR-039-oidc-primary-wstrust-bridge.md) — OIDC primary; WS-Trust bridge (consumes claims-engine for Delegation Rules)
- [ADR-100](./ADR-100-keycloak-replaces-adfs-farm-wid-sql-wap.md) — Keycloak + Rust shim deployment topology (the claims-engine runs in the shim)
- [pest](https://pest.rs/) — PEG parser generator for Rust
- [AD FS Claims Rule Language Reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/technical-reference/the-role-of-claims.md) — Microsoft's CRL reference
