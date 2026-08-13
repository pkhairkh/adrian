---
title: Final Draft — Adrian Framework Synthesis
audience: architects-and-engineers
tags: [final-draft, synthesis, architecture, rust, framework-design, ad-equivalent]
related:
  - ./01-executive-summary.md
  - ./02-architecture-overview.md
  - ../adr/README.md
  - ../workshop/CONTEXT.md
  - ../catalog/README.md
  - ../draft/README.md
last_updated: 2026-08-14
---

# Final Draft — Adrian Framework Synthesis

This directory is the **definitive synthesis** of the Adrian framework. It supersedes
the earlier `draft/` directory, which was written before the 12 Tier-1 architectural
decisions were locked. The final draft is written for a **Rust-only implementation**:
every component called out in this draft — KDC, DRSUAPI server, SMB 3.1.1 server, schema
compiler, policy executor, ACME CA, federation shim, client SDK, operator, CLI — is a
Rust crate, with no GPL contamination, no C FFI on the hot path, and no Samba/Heimdal/MIT
codebase inheritance.

The final draft draws on three upstream bodies of work:

- **130 ADRs** in [`adr/`](../adr/README.md) (ADR-001 through ADR-130, ~320K words total,
  averaging ~2,500 words per ADR), each resolving one of the 130 problems in
  [`catalog/`](../catalog/README.md). The first 69 ADRs (ADR-001..ADR-069) were written
  during the initial triage; the remaining 61 (ADR-070..ADR-130) were written after the
  Tier-1 ORQ Resolution Workshop unblocked the deferred problem set.
- **12 Tier-1 workshop decisions** in [`workshop/`](../workshop/CONTEXT.md), each resolving
  one or more of the 11 Tier-1 Open Research Questions (ORQ-001 through ORQ-203) and
  gating the architecture of one or more capabilities. The workshop took place over two
  days (2026-08-13 / 2026-08-14) and locked the foundational architecture before the
  follow-up ADRs were written.
- **A 72-file implementation-level knowledge base** in [`docs/`](../docs/README.md),
  ~25,200 lines, covering AD DS, AD CS, AD FS, AD LDS, AD RMS, Kerberos, LDAP, SMB, NTLM,
  DNS, DRSR, NTP, SPN/UPN/PAC, schema, GPO, PKI, federation, file/print, and the
  macOS/Linux equivalents.

The final draft is organised into 7 sections. Each section is a self-contained narrative
written for senior engineers and architects; together they form the engineering brief for
the framework's v1 implementation.

## Sections

| # | File | Status | Contents |
|---|------|--------|----------|
| 01 | [01-executive-summary.md](./01-executive-summary.md) | ✅ written (Wave 3a) | What Adrian is, headline numbers, the 12 architectural decisions, what Adrian delivers by capability, person-week estimates, next steps |
| 02 | [02-architecture-overview.md](./02-architecture-overview.md) | ✅ written (Wave 3a) | Architecture principles, the 12 capabilities and their Rust crates, dependency graph, storage layer (FDB), replication layer (hybrid DRSUAPI + openraft), identity layer (UUIDv7 + SID), KDC, Client SDK, deployment model, observability |
| 03 | [03-capability-deep-dives.md](./03-capability-deep-dives.md) | ✅ written (Wave 3b parallel) | Per-capability deep dive: each of the 12 capabilities documented in ~400 words, covering ADR citations, crate graph, public API, hot paths, operational surface |
| 04 | `04-rust-workspace-design.md` | pending | Workspace layout, crate dependency DAG, feature flags, async runtime, error model, `tracing`/OpenTelemetry integration, `cargo` profile strategy, build/release pipeline |
| 05 | [05-security-architecture.md](./05-security-architecture.md) | ✅ written (Wave 3b parallel) | Threat model (STRIDE per capability), golden/silver ticket mitigation, DCSync mitigation, sIDHistory injection, Kerberoasting, NTLM relay, supply chain (Sigstore + in-toto), key custody (HSM-bound krbtgt, KRA Shamir) |
| 06 | [06-implementation-roadmap.md](./06-implementation-roadmap.md) | ✅ written (Wave 3b parallel) | 6-phase roadmap (Phase 0 research spikes through Phase 5 GA), staffing plan, critical path (KDC is the long pole), interop test lab, customer pilot plan |
| 07 | `07-appendices.md` | pending | ADR-to-capability matrix, workshop-decision-to-ORQ matrix, FDB subspace map, well-known GUID registry, etype table, ADR cross-reference clusters, glossary |

## How to read this draft

- **You are an executive or hiring manager**: read `01-executive-summary.md` only.
- **You are an architect joining the project**: read `01` and `02`, then the
  per-capability deep dive (`03`) for your assigned capability.
- **You are an engineer implementing a crate**: read `02` for the crate's place in the
  graph, `03` for the crate's API surface, `04` for the workspace conventions, and the
  cited ADRs for the concrete specification.
- **You are a security reviewer**: read `02` and `05`, plus the threat-model sections of
  the cited ADRs (every Security-capability ADR includes a STRIDE threat model).
- **You are a customer evaluating the framework**: read `01` for the headline value, `06`
  for the roadmap and pilot plan, and the migration ADRs (`ADR-126` through `ADR-130`) for
  the migration story.

## Relationship to upstream artifacts

The final draft is **authoritative** where it differs from `draft/`. The `draft/`
directory is preserved for historical reference but is no longer maintained. The ADRs
remain the **canonical, immutable** record of every architectural decision; the final
draft synthesises them into a narrative but does not override them. Where the final draft
and an ADR disagree, the ADR wins (and the disagreement is a bug to be filed against the
final draft).

The workshop decisions remain the **canonical record** of the Tier-1 architectural
posture; the final draft cites them inline as "Decision N" and consolidates their
concrete-specification bullets into the per-capability deep dives.

## Maintenance

The final draft is a living document. When an ADR is superseded or a new workshop
decision is made, the corresponding section of the final draft is updated and the
`last_updated` field is bumped. The final draft is version-controlled in the same
repository as the ADRs and workshop decisions, on the `main` branch.
