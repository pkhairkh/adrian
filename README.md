# Adrian

**Active Directory Knowledge Base and Framework Problem Catalog**

A research deliverable covering Microsoft Active Directory — its services, protocols, schema, GPO, PKI, federation, and file/print stacks — and the equivalent stacks on macOS and Linux/UNIX, with a comprehensive problem catalog (130 problems across 12 framework capabilities) for designing a new cross-platform AD-equivalent framework.

## What's in this repo

| Path | Contents |
|------|----------|
| [`docs/`](./docs/) | 72-file implementation-level knowledge base (AD overview, protocols, schema, GPO, PKI, federation, file/print, macOS/Linux equivalents, comparison matrices, code examples, references) |
| [`catalog/`](./catalog/) | 16-file problem catalog (130 problems across 12 framework capabilities, 262 open research questions, cross-platform parity matrix) |
| [`draft/`](./draft/) | Rough draft synthesis document (executive summary, KB findings, problem catalog synthesis, prioritized research questions, roadmap) |
| [`scripts/`](./scripts/) | Working scripts and extraction artifacts |

## Audience

- **Senior engineers** — the `docs/` directory is implementation-level: protocol messages with hex offsets, source-file paths, registry keys, IDL fragments, OID numbers
- **Architects and engineers** — the `catalog/` directory is for those designing a new framework that supports all AD features and protocols across Windows, macOS, and Linux
- **Project sponsors** — the `draft/` directory provides a synthesized executive view

## Quick start

- New to this repo? Read the [`draft/01-executive-summary.md`](./draft/01-executive-summary.md) first.
- Need an AD reference? Start at [`docs/00-overview/01-active-directory-overview.md`](./docs/00-overview/01-active-directory-overview.md).
- Designing the framework? Start at [`catalog/README.md`](./catalog/README.md).
- Looking for cross-platform parity gaps? See [`catalog/14-cross-platform-parity-matrix.md`](./catalog/14-cross-platform-parity-matrix.md).

## Repository statistics

- 88 Markdown source files
- ~34,300 lines of content
- 130 catalogued problems across 12 framework capabilities
- 262 open research questions
- 130-row cross-platform parity matrix

## License

MIT — see [`LICENSE`](./LICENSE).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). This is a research deliverable; contributions are tracked via issues and pull requests.
