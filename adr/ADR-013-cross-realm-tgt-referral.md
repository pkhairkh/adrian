---
title: "ADR-013: RFC 4120 Cross-Realm TGT Referral and Transited-Field Validation"
status: Accepted
date: 2026-08-13
deciders: adrian-architecture-team
capability: KDC
problem: PC-028
severity: medium
tags: [adr, kdc, kerberos, cross-realm, referral, transited-field, trust]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/02-kdc.md
  - ../docs/02-protocols/01-kerberos-internals.md
  - ../docs/03-directory-schema/04-trusts-topology.md
  - ../docs/00-overview/03-domains-forests-trees.md
last_updated: 2026-08-13
---

# ADR-013: RFC 4120 Cross-Realm TGT Referral and Transited-Field Validation

## Status

Accepted — 2026-08-13

## Context

When a user in domain A requests a service ticket for a service in domain B, the KDCs walk the trust graph via referral TGTs. The KDC in domain A returns a TGT for `krbtgt/B` (a referral ticket encrypted to B's inter-realm key). The client submits the referral TGT to KDC B, which decrypts it (B has the inter-realm key), issues a service ticket if the service is in B, or another referral if the service is in domain C, per [PC-028](../catalog/02-kdc.md#pc-028--cross-realm-tgt-referral-chain-is-rigid-transited-field-validation-is-fragile), [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), and [docs/03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md).

The `Transited` field of the resulting ticket encodes the realm chain (`TrustedRealms` in the `TransitedEncoding`). The target KDC validates the `Transited` field against its trust graph — if the chain includes a realm that the target doesn't trust, the ticket is rejected with `KRB_AP_ERR_TGS_NOREALM`. In forests with many domains and shortcut trusts, the chain can be non-trivial: A → B → C → D, with shortcut trusts A → D and B → D. The KDC at D must validate the chain and decide whether to accept the shortcut or require the full chain.

In practice, AD disables `Transited` field validation by default (`disable-transited` KDC option) because the validation is fragile and the trust graph is implicit (the forest is one administrative unit). Cross-forest trusts (separate forests) do validate, but the validation is often bypassed in mixed-vendor environments where one side uses MIT and the other uses AD. Cross-domain auth latency in multi-domain forests: each hop in the referral chain adds a network roundtrip (client → KDC A → client → KDC B → client → KDC C → client → service). In a 5-domain forest with no shortcut trusts, a cross-domain auth takes 5 roundtrips — 50–500 ms depending on WAN latency.

Constraints from [PC-028](../catalog/02-kdc.md#pc-028--cross-realm-tgt-referral-chain-is-rigid-transited-field-validation-is-fragile):

- Must preserve RFC 4120 §3.3.3 referral semantics for AD interop.
- Must support `Transited` field validation (configurable per-trust).
- Must support shortcut trusts (direct trust between non-adjacent domains).
- For AD interop, must support forest trusts (transitive, organization-wide).

## Decision

The framework SHALL implement RFC 4120 §3.3.3 cross-realm TGT referral semantics correctly per spec. When a client requests a TGS for a service in a different realm, the KDC SHALL return a referral TGT for the next hop in the trust graph (encrypted to the inter-realm key for that hop). The client SHALL submit the referral TGT to the next KDC, which SHALL either issue a service ticket (if the service is in its realm) or another referral (if the service is in a further realm).

The framework SHALL implement `Transited` field validation correctly per [RFC 4120 §3.3.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3). The `Transited` field SHALL encode the realm chain (`TransitedEncoding` with `tr-type = 1` DOMAIN-X500-COMPRESS). The target KDC SHALL validate the `Transited` field against its trust graph: if the chain includes a realm that the target doesn't trust (directly or transitively), the ticket SHALL be rejected with `KRB_AP_ERR_TGS_NOREALM (12)`. The framework SHALL support per-trust configuration of `Transited` validation: `"strict"` (validate per spec), `"disabled"` (AD's default — skip validation; useful for intra-forest trusts where the forest is one administrative unit), `"shortcut-aware"` (validate but accept shortcut trusts as valid chains).

The framework SHALL document `capaths` configuration (the `[capaths]` section of `krb5.conf`) as the modern mechanism for explicit cross-realm policy. The `capaths` section SHALL specify, for each (client-realm, service-realm) pair, the explicit referral chain to follow. This eliminates the KDC's trust-graph walk and makes the referral path deterministic. The framework SHALL expose a CLI command (`adrian-krb5 capaths generate`) that generates a `capaths` configuration from the directory's trust objects.

The framework SHALL support shortcut trusts (direct trust between non-adjacent domains). When the KDC computes the referral path, it SHALL prefer shortcut trusts over multi-hop paths (shorter chain = fewer roundtrips). The framework SHALL support forest trusts (transitive, organization-wide): a trust between two forest roots implies transitive trust between all domains in the two forests.

For AD-interop mode, the framework SHALL implement forest trusts identically to AD's `kdcsvc.dll`, including the `msDS-TrustForestTrustInfo` attribute on the `trustedDomain` object. The framework SHALL support `nltest /domain_trusts`-equivalent CLI for trust inspection.

**Concrete specification**:

- The KDC SHALL implement RFC 4120 §3.3.3 cross-realm TGT referral: on TGS-REQ for a service in a different realm, return a referral TGT for the next hop (encrypted to the inter-realm key).
- The KDC SHALL encode the realm chain in the `Transited` field (`tr-type = 1` DOMAIN-X500-COMPRESS) of the resulting service ticket.
- The KDC SHALL support per-trust `Transited` validation modes: `"strict"`, `"disabled"`, `"shortcut-aware"`.
- The framework SHALL expose `adrian-krb5 capaths generate` CLI command that generates a `krb5.conf` `[capaths]` section from the directory's trust objects.
- The framework SHALL support shortcut trusts (direct trust between non-adjacent domains) and SHALL prefer shortcuts over multi-hop paths in the referral computation.
- The framework SHALL support forest trusts (transitive, organization-wide) with `msDS-TrustForestTrustInfo` attribute on `trustedDomain` objects.
- For AD-interop mode, the framework SHALL implement forest trusts identically to AD's `kdcsvc.dll`.
- The framework SHALL expose `adrian-krb5 trusts list` (equivalent to `nltest /domain_trusts`) and `adrian-krb5 trusts show <trust-name>` CLI commands.
- Performance target: cross-realm auth in a 5-domain forest with shortcut trusts SHALL complete in ≤ 2 roundtrips (client → home KDC → shortcut KDC → service).

## Rationale

The framework's choice is to implement the spec correctly rather than follow AD's "disable validation by default" pattern. The spec-correct implementation has two advantages: (a) it interoperates correctly with MIT krb5 and Heimdal, which validate by default; (b) it provides defense-in-depth against malicious referral chains (an attacker who compromises one realm cannot forge a chain through untrusted realms). The cost is configuration complexity — operators must understand `Transited` validation and `capaths` configuration, which AD deployments typically ignore.

Three alternatives were considered:

**Alternative A — Disable `Transited` validation by default (AD's pattern).** The advantage is operational simplicity — operators don't need to understand `Transited` validation. The disadvantage is interoperability issues with MIT krb5 / Heimdal (which validate by default) and loss of defense-in-depth. Rejected as the default; the framework SHALL validate by default with per-trust configuration to disable for intra-forest trusts.

**Alternative B — Replace `Transited` field with signed assertions from each hop.** Each KDC in the chain signs an assertion "I referred this ticket to <next-realm>"; the target KDC verifies the chain. The advantage is cryptographic verifiability — the target KDC can prove the chain rather than trusting the `Transited` field. The disadvantage is protocol incompatibility with AD and MIT krb5 — the framework would not interoperate with existing Kerberos deployments. Rejected for v1; the framework SHALL use the standard `Transited` field. Signed assertions may be considered for a future framework-specific extension.

**Alternative C — Collapse to a single-domain forest (eliminate cross-domain referrals entirely).** Modern AD deployments consolidate into single-domain forests; cross-domain referrals are rare. The advantage is simplicity — no referral logic, no `Transited` field. The disadvantage is breaking multi-domain forest deployments (which still exist in large enterprises, government, and regulated industries). Rejected for v1; the framework SHALL support multi-domain forests. Single-domain forests are a deployment choice, not a framework constraint.

External evidence: [RFC 4120 §3.3.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3) defines cross-realm TGT referral and `Transited` field; [RFC 4120 §5.3.3.1](https://www.rfc-editor.org/rfc/rfc4120#section-5.3.3.1) defines `DOMAIN-X500-COMPRESS` encoding; [MIT krb5 documentation](https://web.mit.edu/kerberos/krb5-1.21/doc/admin/capaths.html) documents `capaths` configuration; [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) documents forest trusts. The framework's design matches the spec and the MIT krb5 pattern, with AD-interop preserved.

The cost of this decision is implementation effort for the `Transited` validation logic and the `capaths` generation tool. The referral logic itself is straightforward (walk the trust graph); the `Transited` validation is the complex part (must handle `DOMAIN-X500-COMPRESS` encoding correctly).

## Consequences

**Positive**: Spec-correct interoperability with MIT krb5 and Heimdal. Defense-in-depth against malicious referral chains. `capaths` generation tool makes cross-realm configuration deterministic and reviewable. Shortcut trusts reduce cross-domain auth latency.

**Negative**: Operators must understand `Transited` validation modes and configure them per-trust. The default `"strict"` mode may break intra-forest trusts where AD's `"disabled"` mode was assumed; operators migrating from AD must explicitly set intra-forest trusts to `"disabled"`.

**Neutral**: The `capaths` generation tool is additive; deployments that don't use it pay no cost. Single-domain forest deployments are unaffected (no cross-realm referrals).

**Implementation cost**: ~4 person-weeks for the referral logic, `Transited` validation, `capaths` generation, forest-trust support, and CLI commands. The bulk of the work is the `Transited` validation and `DOMAIN-X500-COMPRESS` encoding.

**Operational impact**: Cross-domain auth in multi-domain forests works correctly with spec-compliant validation. `adrian-krb5 capaths generate` produces a deterministic `krb5.conf` configuration for clients. `adrian-krb5 trusts list` and `trusts show` provide trust inspection equivalent to `nltest /domain_trusts`.

## Alternatives Considered

### Alternative 1: Disable Transited validation by default (AD's pattern)

Operational simplicity; interoperability issues with MIT krb5 / Heimdal; loss of defense-in-depth. Rejected as default; the framework SHALL validate by default with per-trust configuration to disable for intra-forest trusts.

### Alternative 2: Replace Transited field with signed assertions from each hop

Cryptographic verifiability; protocol incompatibility with AD and MIT krb5. Rejected for v1; the framework SHALL use the standard `Transited` field. Signed assertions may be considered for a future framework-specific extension.

### Alternative 3: Collapse to a single-domain forest (eliminate cross-domain referrals)

Simplicity; breaks multi-domain forest deployments. Rejected for v1; the framework SHALL support multi-domain forests. Single-domain forests are a deployment choice, not a framework constraint.

## Open Questions

- For the `capaths` generation tool, should the tool also generate client-side `krb5.conf` for non-Windows clients (Linux, macOS)? Yes — the tool SHOULD output both the server-side trust objects and the client-side `krb5.conf` configuration.
- Should the framework support cross-forest federation via OIDC / SAML as an alternative to cross-forest Kerberos trusts? Yes, but that is the Federation Gateway capability (PC-070, not in this catalog), not the KDC.
- Cross-reference PC-022 (multi-tenancy, DEFERRED) — multi-tenancy may require per-tenant trust graphs; the framework's `Transited` validation must handle this correctly. Defer until multi-tenancy is resolved.

## Cross-capability impact

- **Federation Gateway**: Cross-forest federation uses similar referral patterns. The framework's `Transited` validation provides defense-in-depth for cross-forest Kerberos trusts; the Federation Gateway may use OIDC / SAML for cross-forest federation instead (simpler, more modern).
- **Client SDK**: Client SDK MUST support `capaths` configuration on Linux and macOS (MIT krb5 / Heimdal native). Windows clients use the framework's trust objects directly.
- **Operations**: `adrian-krb5 trusts list`, `trusts show`, and `capaths generate` are standard ops tasks. Cross-domain auth latency monitoring is a useful metric.
- **Migration**: AD-to-framework migration preserves trust objects; the framework's `Transited` validation may be stricter than AD's default, so operators must explicitly set intra-forest trusts to `"disabled"` mode if they want AD-equivalent behavior.
- **Security**: Spec-correct `Transited` validation provides defense-in-depth against malicious referral chains. This is a security improvement over AD's default.

## References

- [PC-028](../catalog/02-kdc.md) — problem statement in the catalog
- [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md) — `Transited` field in `EncTicketPart`, referral TGT mechanism
- [docs/03-directory-schema/04-trusts-topology.md](../docs/03-directory-schema/04-trusts-topology.md) — Trust objects, `trustedDomain` class, `msDS-TrustForestTrustInfo`
- [docs/00-overview/03-domains-forests-trees.md](../docs/00-overview/03-domains-forests-trees.md) — Forest / tree / domain topology, trust transitivity
- [RFC 4120 §3.3.3](https://www.rfc-editor.org/rfc/rfc4120#section-3.3.3) — Cross-Realm Operation
- [RFC 4120 §5.3.3.1](https://www.rfc-editor.org/rfc/rfc4120#section-5.3.3.1) — `TransitedEncoding`
- [MIT krb5 `capaths` documentation](https://web.mit.edu/kerberos/krb5-1.21/doc/admin/capaths.html)
- [MS-ADTS §6.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/) — Forest trusts
