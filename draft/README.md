---
title: Rough Draft Synthesis — Master Index
audience: architects-and-engineers
tags: [rough-draft, synthesis, master-index, framework-design]
related:
  - ./01-executive-summary.md
  - ./02-kb-synthesis.md
  - ./03-problem-catalog-synthesis.md
  - ./04-open-research-questions.md
  - ./05-cross-platform-parity.md
  - ./06-roadmap.md
  - ../README.md
  - ../catalog/README.md
  - ../docs/README.md
last_updated: 2026-08-13
---

# Rough Draft Synthesis — Master Index

This directory holds the **rough draft synthesis** of the Adrian research deliverable — a curated narrative distilled from the 72-file implementation-level knowledge base under [`../docs/`](../docs/) and the 130-problem framework catalog under [`../catalog/`](../catalog/). It is written for architects and sponsors who need the headline findings in a few hours, not the few days required to read the underlying 88 files.

The draft is **not a replacement** for `docs/` or `catalog/`. Every claim is sourced; specific numbers, OID identifiers, source-file paths, and protocol opnums are cited back to the implementation-level file that documents them.

## Document map

| # | File | One-line description | Audience |
|---|------|---------------------|----------|
| 01 | [`01-executive-summary.md`](./01-executive-summary.md) | Headline findings, top-5 blocker problems, 10 cross-cutting design tensions, recommended next steps. | Sponsors, senior architects (5 min) |
| 02 | [`02-kb-synthesis.md`](./02-kb-synthesis.md) | Distilled synthesis of the 72-file KB: AD roles, 8 protocols, schema/replication/GPO, PKI/federation/file/print, macOS and Linux equivalents, comparison matrices, code and references. | Senior engineers, architects (1 hr) |
| 03 | [`03-problem-catalog-synthesis.md`](./03-problem-catalog-synthesis.md) | Distilled synthesis of the 130-problem catalog: capability-by-capability walkthrough, 23 blockers, 8 security threats, 12 cross-cutting tensions. | Architects (1 hr) |
| 04 | [`04-open-research-questions.md`](./04-open-research-questions.md) | 262 open research questions reorganized by 3-tier prioritization and capability dependency. | Architects, capability leads |
| 05 | [`05-cross-platform-parity.md`](./05-cross-platform-parity.md) | Cross-platform parity analysis: Windows/macOS/Linux gaps, per-capability parity scorecard, remediation strategy. | Architects, capability leads |
| 06 | [`06-roadmap.md`](./06-roadmap.md) | Multi-phase roadmap: Tier-1 spikes → MVP (23 blockers) → v1 (64 high) → v2 (33 medium + 10 low). | Sponsors, program managers |

Files 03–06 are produced by parallel / downstream subagents. Files 01 and 02 are the entry point and may be read standalone.

## How the draft relates to `docs/` and `catalog/`

The three layers are complementary, not redundant:

- **[`docs/`](../docs/)** — 72-file implementation-level KB. Dense, reference-style, written for senior engineers. Protocol messages with hex offsets, source-file paths, registry keys, IDL fragments, OID numbers. Use this when implementing or debugging a specific component.
- **[`catalog/`](../catalog/)** — 16-file problem catalog. 130 problems across 12 framework capabilities, 262 open research questions, 130-row cross-platform parity matrix. Use this when designing the framework or scoping a feature.
- **[`draft/`](./)** — Synthesis. Distilled narrative for sponsors and architects. Use this when you need the headline view, onboarding a new stakeholder, or prioritizing work.

The implementation-level files under `docs/` and `catalog/` are always the source of truth; the draft cites them inline with relative markdown links. If the draft and the source disagree, the source is correct.

## Repository-level statistics

Accurate as of 2026-08-13: **88 Markdown source files** (72 KB + 16 catalog), **~34,300 lines**, **130 catalogued problems** across 12 framework capabilities (23 blocker / 64 high / 33 medium / 10 low), **262 open research questions** in 3-tier prioritization (11 Tier-1 architectural decisions), **130-row cross-platform parity matrix**.

## Reading order

1. [`01-executive-summary.md`](./01-executive-summary.md) — 5 minutes, headline.
2. [`02-kb-synthesis.md`](./02-kb-synthesis.md) — 1 hour, technical narrative.
3. [`03-problem-catalog-synthesis.md`](./03-problem-catalog-synthesis.md) — 1 hour, problem-space narrative.
4. [`04-open-research-questions.md`](./04-open-research-questions.md) — for design spikes.
5. [`05-cross-platform-parity.md`](./05-cross-platform-parity.md) — for parity-gap remediation planning.
6. [`06-roadmap.md`](./06-roadmap.md) — for program planning.

Sponsors and senior architects can stop after 01–02. Capability leads should read 02–05. Program managers should read 01, 04, and 06.

## Status

This is a **rough draft**, intended for internal review and feedback. The synthesis may evolve as the underlying KB and catalog are updated. Each file's `last_updated` frontmatter field tracks the snapshot date.
