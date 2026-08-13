---
title: "Adrian Framework — Per-Capability Technical Specifications"
audience: rust-engineers
status: Draft
version: 0.1.0
tags: [specs, index, rust, implementation, adrian-framework]
related:
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Adrian Framework — Per-Capability Technical Specifications

This directory contains 12 per-capability technical specifications for the Adrian framework. Each spec is a detailed implementation-level specification for one capability, derived from the framework's 130 ADRs and 12 workshop decisions.

## How to use this directory

- **Implementing a capability?** Read the corresponding spec front-to-back, then drill into the cited ADRs for full rationale.
- **Looking for cross-capability contracts?** Spec sections "Key types and traits" define the trait surfaces that span capability boundaries.
- **Looking for storage layout?** Each spec's "Data model" section shows the FDB subspaces or PostgreSQL schema it owns or cross-references.
- **Looking for protocol surface?** Each spec's "Protocol surface" section enumerates the wire protocols (RFCs, MS-* specs) it implements.

## Spec inventory

| # | Spec | Capability | Crates | ADRs |
|---|------|-----------|--------|------|
| 01 | [01-core-directory.md](./01-core-directory.md) | Core Directory Service | 10 | ADR-001–010, ADR-070–081 (22) |
| 02 | [02-kdc.md](./02-kdc.md) | KDC (Kerberos Key Distribution Center) | 4 | ADR-011–020, ADR-082–084 (13) |
| 03 | [03-auth-provider.md](./03-auth-provider.md) | Auth Provider (NTLM, SASL, SSPI-equivalent) | 2 | ADR-021–023, ADR-085–088 (7) |
| 04 | [04-policy-engine.md](./04-policy-engine.md) | Policy Engine (GPO-equivalent) | 9 | ADR-024–031, ADR-089–094 (14) |
| 05 | [05-cert-service.md](./05-cert-service.md) | Cert Service (PKI / CA / Enrollment) | 9 | ADR-032–037, ADR-095–099 (11) |
| 06 | [06-federation-gateway.md](./06-federation-gateway.md) | Federation Gateway (SAML / OIDC / WS-Fed) | 2 | ADR-038–042, ADR-100–104 (10) |
| 07 | [07-file-gateway.md](./07-file-gateway.md) | File Gateway (SMB / DFS / Print) | 4 | ADR-043–047, ADR-105–106 (7) |
| 08 | [08-client-sdk.md](./08-client-sdk.md) | Client SDK (cross-platform library) | 7 | ADR-048–051, ADR-107–111 (9) |
| 09 | [09-cross-platform-parity.md](./09-cross-platform-parity.md) | Cross-Platform Parity | 5 | ADR-052–056, ADR-112–118 (12) |
| 10 | [10-operations.md](./10-operations.md) | Operations (deploy / monitor / recover) | 6 | ADR-057–063, ADR-119–121 (10) |
| 11 | [11-security.md](./11-security.md) | Security & Threat Model | 3 | ADR-064–067, ADR-122–125 (8) |
| 12 | [12-migration.md](./12-migration.md) | Migration & Coexistence | 3 | ADR-068–069, ADR-126–130 (7) |

**Totals.** 12 specs covering 130 ADRs across 12 capabilities; ~64 framework Rust crates at Layer 0–4; ~38,700 words total spec content.

## Spec document format

Every spec follows the same 11-section structure:

1. **Overview** — 2–3 paragraphs: what the capability does, which ADRs it implements, which Rust crates it comprises.
2. **Crate structure** — table of crates with layer, role, and ADRs implemented.
3. **Key types and traits** — copy-paste-ready Rust trait + struct definitions.
4. **Data model** — FDB subspace layout, PostgreSQL schema, or per-host state.
5. **Protocol surface** — wire protocol for protocol-facing capabilities, API surface for internal ones.
6. **Configuration** — TOML config example + environment variables + feature flags.
7. **Error handling** — `thiserror` enum definitions + propagation strategy.
8. **Testing strategy** — unit, integration, interop, property-based test plan.
9. **Implementation phases** — MVP / v1 / v2 breakdown.
10. **Dependencies** — external crate dependencies with version + rationale.
11. **References** — ADRs, workshop decisions, KB files, RFCs, MS-* specs.

## Quality bar

- Every spec cites ≥5 ADRs by number (most cite 10–20).
- Every spec includes Rust code blocks (trait definitions, struct definitions, config examples).
- Every spec includes the FDB subspace layout or equivalent data model.
- Every spec includes a configuration example (TOML).
- Every spec includes a testing strategy covering unit + integration + interop + property tests.
- Length: 3,000–5,000 words per spec.

## Relationship to other framework documents

- **ADRs** ([../adr/README.md](../adr/README.md)) — authoritative architectural decisions; specs translate ADRs into implementation-level detail.
- **Workshop decisions** ([../workshop/CONTEXT.md](../workshop/CONTEXT.md)) — canonical design synthesis; specs cite decisions where they unblock ADRs.
- **Final draft** ([../finaldraft/README.md](../finaldraft/README.md)) — executive summary + architecture overview; specs drill deeper into individual capabilities.
- **Catalog** ([../catalog/README.md](../catalog/README.md)) — problem catalog; specs trace ADRs back to the problems they resolve.

## Maintenance

Specs are versioned (`version: 0.1.0` in frontmatter) and evolve with the framework. To update a spec:

1. Bump `version` (e.g. 0.1.0 → 0.2.0 for additions, 1.0.0 for stable).
2. Update `last_updated` date.
3. Add a changelog entry at the bottom of the spec.
4. Submit PR for review by the framework's architecture team.

To add a new capability (hypothetical #13+):

1. Create `specs/13-<capability-slug>.md` following the 11-section format.
2. Add a row to the spec inventory table above.
3. Update the spec total count in this README.
