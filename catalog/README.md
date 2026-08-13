---
title: Problem Catalog — Framework for AD-Equivalent Capabilities
audience: architects-and-engineers
tags: [problem-catalog, framework-design, architecture, gap-analysis, threat-model, cross-platform]
related:
  - ./00-framework-capabilities.md
  - ./01-core-directory.md
  - ./02-kdc.md
  - ./03-auth-provider.md
  - ./04-policy-engine.md
  - ./05-cert-service.md
  - ./06-federation-gateway.md
  - ./07-file-gateway.md
  - ./08-client-sdk.md
  - ./09-cross-platform-parity.md
  - ./10-operations.md
  - ./11-security-threat-model.md
  - ./12-migration-and-coexistence.md
  - ./13-open-research-questions.md
  - ./14-cross-platform-parity-matrix.md
last_updated: 2026-08-13
---

# Problem Catalog — Framework for AD-Equivalent Capabilities

A research-grade catalog of **every problem, gap, design tension, and open question** that must be solved to build a new framework supporting all Active Directory features and protocols across Windows, macOS, and Linux/UNIX. Built by systematically mining the 72-file AD knowledge base for protocol gaps, cross-platform inconsistencies, scalability bottlenecks, security threats, operational footguns, and greenfield design tensions.

## What this catalog is — and is not

**Is**:
- A problem inventory. 130 problems across 12 framework capabilities.
- A reference for architects and engineers designing the framework.
- A basis for design decisions, threat modeling, and roadmap sequencing.
- Cross-linked to the source KB files for every claim.

**Is not**:
- A design proposal. No architecture is proposed here.
- A solution catalog. Solutions are a downstream deliverable.
- An implementation guide. No code is provided.

The catalog stops at "here is the problem, here is its impact, here are the constraints, here are the open questions." Picking a solution is the next phase.

## How the catalog was built

1. **Read every file** in the existing KB (`/home/z/my-project/download/ad-kb/`) — 72 files, ~25,200 lines.
2. **Extracted 130 problems** using a structured rubric covering protocol-level gaps, cross-platform parity, scalability, security, operations, greenfield design tensions, and standards-compliance trade-offs.
3. **Grouped problems by framework capability** — 12 capabilities, listed below.
4. **Wrote one catalog file per capability** with detailed analysis per problem (target 500-1000 words per problem, KB citations, impact, constraints, open questions).
5. **Cross-linked problems** that span capabilities (e.g., krbtgt rotation touches KDC, Security, and Operations).
6. **Produced a cross-platform parity matrix** showing which problems affect which platforms.

## Framework capabilities (taxonomy)

The framework is decomposed into 12 capabilities. Each gets its own catalog file:

| # | Capability | File | Problems | Severity (B/H/M/L) |
|---|------------|------|----------|---------------------|
| 1 | Core Directory Service | [01-core-directory.md](./01-core-directory.md) | 22 | TBD |
| 2 | KDC (Kerberos Key Distribution Center) | [02-kdc.md](./02-kdc.md) | 13 | TBD |
| 3 | Auth Provider (NTLM, SASL, SSPI-equivalent) | [03-auth-provider.md](./03-auth-provider.md) | 7 | TBD |
| 4 | Policy Engine (GPO-equivalent) | [04-policy-engine.md](./04-policy-engine.md) | 14 | TBD |
| 5 | Cert Service (PKI / CA / Enrollment) | [05-cert-service.md](./05-cert-service.md) | 11 | TBD |
| 6 | Federation Gateway (SAML / OIDC / WS-Fed) | [06-federation-gateway.md](./06-federation-gateway.md) | 10 | TBD |
| 7 | File Gateway (SMB / DFS / Print) | [07-file-gateway.md](./07-file-gateway.md) | 7 | TBD |
| 8 | Client SDK (cross-platform library) | [08-client-sdk.md](./08-client-sdk.md) | 9 | TBD |
| 9 | Cross-Platform Parity | [09-cross-platform-parity.md](./09-cross-platform-parity.md) | 12 | TBD |
| 10 | Operations (deploy / monitor / recover) | [10-operations.md](./10-operations.md) | 10 | TBD |
| 11 | Security & Threat Model | [11-security-threat-model.md](./11-security-threat-model.md) | 8 | TBD |
| 12 | Migration & Coexistence | [12-migration-and-coexistence.md](./12-migration-and-coexistence.md) | 7 | TBD |

Plus three cross-cutting reference files:

| # | Reference | File | Purpose |
|---|-----------|------|---------|
| 0 | Framework Capabilities Taxonomy | [00-framework-capabilities.md](./00-framework-capabilities.md) | Definitions, responsibilities, dependencies between capabilities |
| 13 | Open Research Questions | [13-open-research-questions.md](./13-open-research-questions.md) | Questions needing further investigation before solutions can be designed |
| 14 | Cross-Platform Parity Matrix | [14-cross-platform-parity-matrix.md](./14-cross-platform-parity-matrix.md) | Problem × platform matrix showing where each problem bites |

## Statistics

**Total problems: 130**

By severity:
- **Blocker** (23): framework cannot ship without solving
- **High** (64): significant gap or security risk
- **Medium** (33): workaround exists but gap should be acknowledged
- **Low** (10): nuisance or future-compatibility item

By capability:

```
Core Directory       22  ████████████████████████
KDC                  13  ███████████████
Auth Provider         7  ████████
Policy Engine        14  █████████████████
Cert Service         11  █████████████
Federation Gateway   10  ████████████
File Gateway          7  ████████
Client SDK            9  ██████████
Cross-Platform Parity 12  ██████████████
Operations           10  ████████████
Security              8  █████████
Migration             7  ████████
                    ───
Total               130
```

By cross-platform dimension (problems that affect each platform):
- Windows: 95 problems (the reference platform)
- macOS: 78 problems (parity gaps, missing equivalents)
- Linux: 82 problems (parity gaps, integration complexity)
- Cross-platform consistency: 67 problems (interop between platforms)

## Problem entry format

Every problem in the catalog follows this structure:

```markdown
### PC-NNN — <Title>

**Capability**: <primary capability>
**Severity**: blocker | high | medium | low
**Cross-platform**: Windows / macOS / Linux / cross-platform

**Problem statement** (2-4 paragraphs):
The technical description of the problem, including what AD does, what the open-source alternatives do, and where the gap lies. Includes protocol-level detail (message types, opnums, registry keys, source-file paths).

**Impact**:
What breaks if unsolved. Quantified where possible (e.g., "breaks AD interop entirely", "limits scale to ~100K objects", "exposes pass-the-hash attack").

**Constraints**:
Technical or business constraints on any solution. E.g., "must remain wire-compatible with MS-DRSR for AD interop", "must scale to 10M objects", "must support offline operation".

**Cross-platform considerations**:
How this problem manifests on each platform. Windows-specific, macOS-specific, Linux-specific aspects.

**KB references**:
- `02-protocols/01-kerberos-internals.md` — section on PAC structure
- `09-linux-equivalents/01-sssd-ad-provider.md` — SSSD's handling

**Open questions**:
- Should the framework adopt X approach or invent Y?
- What does Z imply for compatibility?
```

## Top 5 blocker problems (preview)

These are the highest-priority problems — solving them unlocks the rest:

1. **PC-001** — DRSUAPI replication protocol must be implemented server-side for AD-interop scenarios. *Blocker.*
2. **PC-002** — Replication model choice: state-based pull (DRSR) vs. operation-based push vs. CRDT/OT vs. Raft consensus. *Blocker.*
3. **PC-007** — Storage engine: ESE/JET (legacy) vs. modern LSM-tree (RocksDB) vs. SQL vs. document store. *Blocker.*
4. **PC-023** — Kerberos KDC must implement MS-KILE profile with PAC, FAST, PKINIT, kpasswd, cross-realm referral. *Blocker.*
5. **PC-030** — krbtgt account rotation and key version management for golden-ticket mitigation. *Blocker.*

## Cross-cutting design tensions

These tensions appear across multiple capabilities and must be resolved at the architecture level:

1. **AD-interop vs. clean-slate**. Every protocol-level decision trades interop with existing AD deployments against the freedom to design something better. The framework must pick a lane per protocol: full compat (speak MS-DRSR), compat-with-shim (speak MS-DRSR + extension), or clean-slate (speak Raft/OT).

2. **Multi-master vs. consensus**. AD is multi-master with last-writer-wins conflict resolution. Modern systems prefer Raft/Paxos for strong consistency. The framework must decide: stay multi-master (compat) or move to consensus (correctness)?

3. **LDAP schema vs. typed schema**. AD's schema is dynamic, attribute-based, LDAP-defined. Modern systems prefer typed schemas (protobuf, SQL DDL, JSON Schema). The framework must choose, and the choice cascades into the directory API, the replication protocol, and the client SDK.

4. **SIDs vs. UUIDs**. AD uses SIDs for security principals. Modern systems prefer UUIDs. The framework must decide whether to use SIDs (interop), UUIDs (modern), or both (with mapping).

5. **GPO format vs. declarative policy**. AD's GPO is INI/registry.pol-based, fragile, no rollback. Modern alternatives (Salt, Ansible, Kubernetes operators) are declarative, versioned, transactional. The framework must decide: keep GPO format (interop), adopt declarative (modern), or hybrid?

6. **NTLM: drop or maintain compat**. NTLM is broken (pass-the-hash, relay). But many legacy apps require it. The framework must decide: drop NTLM entirely (secure), maintain NTLM (compat), or maintain NTLM with hard mitigations (channel binding, EPA, signing).

7. **PKI: AD CS protocols vs. ACME/EST**. AD CS uses MS-WCCE/MS-XCEP for enrollment. Modern PKI uses ACME (RFC 8555) or EST (RFC 7030). The framework must decide: implement MS-WCCE (interop) or adopt ACME (modern)?

8. **Federation: AD FS topology vs. modern IdP**. AD FS is a separate farm with SQL/WID. Modern IdPs (Keycloak, Authentik, Ory, Zitadel) are lighter and cloud-native. The framework must decide: re-implement AD FS (interop) or wrap a modern IdP?

9. **Multi-tenancy: native vs. per-instance**. AD has no native multi-tenancy. Cloud-native systems expect multi-tenancy. The framework must decide: support multi-tenancy natively (modern) or document why not (interop with AD's single-tenant model)?

10. **Client SDK: per-platform or unified**. There is no universal AD client SDK today. The framework must decide: provide a unified C/Rust/Go SDK with platform bindings, or wrap existing per-platform libraries (SSSD, OpenDirectory, Wldap32)?

These tensions are referenced from the relevant per-capability catalog files.

## How to use this catalog

### For architects
- Read [00-framework-capabilities.md](./00-framework-capabilities.md) first to understand the capability decomposition.
- Skim every per-capability file's "Summary of problems" section.
- Use [14-cross-platform-parity-matrix.md](./14-cross-platform-parity-matrix.md) to spot parity gaps.
- Use [13-open-research-questions.md](./13-open-research-questions.md) to identify items needing more investigation before design can begin.

### For engineers
- Start with the per-capability file for your area of work.
- Each problem entry cites the source KB files — read those for implementation-level detail.
- Use the open-questions section to drive research spikes.

### For project sponsors
- The statistics above give a sense of scope.
- The 23 blocker problems define the minimum viable framework.
- The 64 high-severity problems define v1.

## Related KB files

This catalog is built on top of the existing 72-file AD knowledge base:

- [KB master index](../README.md)
- [Active Directory overview](../docs/00-overview/01-active-directory-overview.md)
- [Feature × OS matrix](../docs/10-comparison-matrices/01-feature-os-matrix.md)
- [Protocol × implementation matrix](../docs/10-comparison-matrices/02-protocol-implementation-matrix.md)

## Maintenance

This catalog is a snapshot of the KB at the time of writing. If the KB is updated, the catalog should be re-mined. New problems discovered during framework design should be added to the catalog with a new PC-NNN identifier.

The problem-extraction working document is preserved at `/home/z/my-project/scripts/problem-extraction.md` for traceability.
