# Changelog

All notable changes to the Adrian repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for its deliverable structure (each "version" is a research milestone, not a software release).

## [Unreleased]

### Planned
- Resolution of the 11 Tier-1 open research questions (see `catalog/13-open-research-questions.md` and `draft/04-open-research-questions.md`)
- Framework architecture proposal (successor deliverable to the problem catalog)
- Per-capability design recommendations

## [0.1.0] — 2026-08-13

### Added — Initial research deliverable

This is the first versioned release of the Adrian repository. It contains the complete research deliverable: an implementation-level Active Directory knowledge base, a framework problem catalog, and a rough draft synthesis.

#### Knowledge base (`docs/`, 72 files)

- **`00-overview/` (5 files)**: AD overview, architecture (LSASS/ESE/DRSUAPI), domains/forests/trees topology, FSMO roles, glossary
- **`01-ad-core/` (5 files)**: AD DS, AD CS, AD FS, AD LDS, AD RMS internals — service binaries, RPC interfaces, registry paths
- **`02-protocols/` (8 files)**: Kerberos (RFC 4120 + MS-KILE + PAC + FAST + PKINIT), LDAP (RFC 4511 + AD controls), SMB (1.0 → 3.1.1), NTLM (NTLMv1/v2 + NTLMSSP), DNS dynamic updates (RFC 2136 + GSS-TSIG), DCE/RPC + MS-DRSR (DRSUAPI), NTP/W32Time (MS-SNTP), SPN/UPN/PAC structures
- **`03-directory-schema/` (5 files)**: attributeSchema/classSchema OIDs and searchFlags, OUs/containers, Global Catalog, trusts topology (`trustedDomain` objects + `trustAuthBlob`), replication internals (USN/InvocationID/UTD vector + `DRSGetNCChanges`)
- **`04-group-policy/` (5 files)**: GPO architecture (GPC + GPT + `gPLink`), LSDOU processing order, ADMX templates + Central Store, CSEs (per-GUID table), GPT/GPC structure (PReg binary format)
- **`05-pki-certs/` (4 files)**: AD CS architecture (`certsvc.exe` + ESE CA DB), certificate templates (v1/v2/v3 + `msPKI-*` attributes), autoenrollment (MS-WCCE + MS-XCEP), OCSP/CRL (RFC 6960 + `ID-PKIX-OCSP-NoCheck`)
- **`06-federation-sso/` (4 files)**: AD FS architecture (`Microsoft.IdentityServer.ServiceHost.exe` + WID/SQL), SAML 2.0 + WS-Federation (passive + active profiles), claims rule language, OAuth2/OIDC (ADFS 2016+)
- **`07-file-print/` (4 files)**: SMB shares (`lanmanserver` + `srv2.sys`), DFS-N/DFS-R (pKT + RDC + USN journal), print services (MS-RPRN + PrintNightmare CVE-2021-34527), offline files (CSC v2)
- **`08-macos-equivalents/` (8 files)**: OpenDirectory internals, `dscl`/`dsconfigad`, Jamf Connect, Platform SSO Extension (macOS 13+), Kerberos SSO Extension, Enterprise Connect/NoMAD, third-party agents (Centrify/PBIS/AdmitMac/DAVE), MDM-as-GPO (Configuration Profiles + MCX + DDM)
- **`09-linux-equivalents/` (10 files)**: SSSD `ad` provider, ID mapping algorithm, SSSD GPO access control, Winbind internals, `samba-tool`/`net ads`, realmd, PBIS/PowerBroker, FreeIPA-AD cross-forest trust, OpenLDAP+MIT Kerberos, PAM/NSS stacks
- **`10-comparison-matrices/` (5 files)**: feature × OS matrix, protocol × implementation matrix, tool × function matrix, auth flow side-by-side (Win/Mac/Linux), GPO equivalents matrix
- **`11-code-examples/` (5 files)**: PowerShell AD cmdlets, SSSD/krb5/samba configs, macOS CLI recipes, Wireshark/tshark filters, Python+impacket (ldap3, GetUserSPNs, secretsdump, wmiexec, psexec, ticketer, getST)
- **`12-references/` (3 files)**: MS-* protocols (26 entries), RFCs/standards (40+ entries), source code repos (Samba, SSSD, Heimdal, MIT, FreeIPA, OpenLDAP, impacket, realmd, Apple OD)

#### Problem catalog (`catalog/`, 16 files)

- **`README.md`**: Master index — 130 problems across 12 capabilities, severity breakdown (23 blocker / 64 high / 33 medium / 10 low)
- **`00-framework-capabilities.md`**: Capability taxonomy, dependency graph, problem-to-capability assignment rules
- **`01-core-directory.md` through `12-migration-and-coexistence.md`**: 12 per-capability problem files, each ~500-1000 words per problem
- **`13-open-research-questions.md`**: 262 ORQs consolidated across all 130 problems, 3-tier prioritization (11 Tier-1 architectural / ~50 Tier-2 per-capability / ~200 Tier-3 per-feature)
- **`14-cross-platform-parity-matrix.md`**: 130-row × 4-platform matrix (Windows 117 ✓ / macOS 118 ✓ / Linux 118 ✓ / cross-platform consistency 114 ✓)

#### Rough draft synthesis (`draft/`, 7 files, ~23,179 words)

- **`README.md`**: Master index for the draft
- **`01-executive-summary.md`** (1,572 words): Headline findings, top 5 blockers, 10 cross-cutting tensions, recommended next steps
- **`02-kb-synthesis.md`** (3,355 words): 8-section synthesis of the 72 KB files
- **`03-problem-catalog-synthesis.md`** (4,609 words): 12 capabilities, 23 blockers, 8 STRIDE threats, 12 parity gaps, 10 tensions, migration synthesis
- **`04-open-research-questions.md`** (3,720 words): 11 Tier-1 architectural questions with candidate answers, 12 cross-cutting themes, 7 research spikes
- **`05-cross-platform-parity.md`** (4,729 words): Windows reference platform, 10 macOS gaps, 10 Linux gaps, 5 consistency axes, 10 concrete recommendations
- **`06-roadmap.md`** (4,583 words): 6-phase roadmap (research spikes → architecture → MVP → v1 → v2 → v3), cross-cutting workstreams, 7 risks, 6 success criteria

#### Repository metadata

- **`README.md`**: Top-level project overview
- **`LICENSE`**: MIT
- **`CONTRIBUTING.md`**: Contribution guidelines, file conventions, cross-reference verification
- **`CHANGELOG.md`**: This file
- **`.gitignore`**: Editor artifacts, build outputs, secrets

#### Working artifacts (`scripts/`, 2 files)

- **`problem-extraction.md`**: The 130-problem extraction working document (preserved for traceability)
- **`fix_broken_xrefs.py`**: Cross-reference fixer used during KB construction

### Statistics

- 95 tracked files
- ~34,300 lines of Markdown content (excluding scripts)
- 130 catalogued problems across 12 framework capabilities
- 262 open research questions
- 130-row cross-platform parity matrix
- ~23,179 words of rough draft synthesis

### Known issues

- The catalog's README reports 23 blocker problems; the parity matrix shows 21 strictly-tagged blocker rows. The 2-problem delta is documented in `draft/06-roadmap.md` as "2 high-severity effectively blocker-class" (PC-014 FSMO replacement, PC-022 multi-tenancy).
- Several draft files slightly exceed their target word counts (e.g., `03-problem-catalog-synthesis.md` is 4,609 words vs. 4,000 target). Content is dense and citation-heavy; no filler was added.
- The `scripts/` directory contains working artifacts from the research process; these are not production code and should not be executed without review.

### Migration notes

This repository was assembled by:
1. Constructing the 72-file KB at `download/ad-kb/` in a working directory
2. Systematically extracting 130 problems from the KB into `scripts/problem-extraction.md`
3. Writing 16 per-capability catalog files from the extraction
4. Synthesizing the 7-file rough draft from the KB + catalog
5. Migrating all content into the `adrian/` repository with cross-reference fixups

The cross-reference fixup script (`scripts/fix_broken_xrefs.py` and the inline fix in `scripts/fix_catalog_xrefs_for_repo.py` pattern) was applied to update `../02-protocols/foo.md` references in catalog files to `../docs/02-protocols/foo.md` after the directory restructure.
