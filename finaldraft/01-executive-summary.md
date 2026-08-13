---
title: Executive Summary — Adrian Framework
audience: architects-and-engineers
tags: [final-draft, executive-summary, adrian, rust, ad-equivalent, cross-platform]
related:
  - ./README.md
  - ./02-architecture-overview.md
  - ../adr/README.md
  - ../workshop/CONTEXT.md
  - ../catalog/README.md
last_updated: 2026-08-14
---

# Executive Summary — Adrian Framework

## What Adrian is

Adrian is a Rust-native, cross-platform, AD-equivalent identity and directory framework. It supports every feature and protocol cataloged in the 130-problem catalog ([`catalog/`](../catalog/README.md)) — directory, replication, Kerberos KDC, NTLM, GPO-equivalent policy, PKI, federation, SMB file/print, and migration from existing AD forests — implemented across 12 framework capabilities and shipped as a single Rust workspace. The framework is designed to **interoperate with existing Active Directory deployments** during migration (DRSUAPI replication, MS-KILE-conformant KDC, MS-WCCE cert enrollment bridge, AD FS claim-rule compatibility) while providing a **clean-slate path for greenfield deployments** that do not need AD-interop (Raft-native replication, declarative JSON policy, ACME-primary PKI, OIDC-primary federation). Every component is memory-safe Rust on the hot path; the only C dependencies are platform system libraries (LSA on Windows, OpenDirectory on macOS, glibc/PAM on Linux), FoundationDB's C client (`libfdb_c.so`, wrapped by `foundationdb-sys` and exposed via safe Rust APIs in the `foundationdb` crate), and the PKCS#11 HSM client (`libpkcs11.so` via the `cryptoki` crate). No GPL code is linked, shipped, or distributed; no Samba, Heimdal, or MIT krb5 codebase is inherited.

The framework's deployment target is Kubernetes-native (StatefulSet + operator per ADR-058), with a single-container edge deployment for branch offices and a 3-node FDB cluster as the minimum production footprint. The framework targets Windows, macOS, and Linux as both server and client platforms; the client SDK is a unified Rust core (`adrian-sdk`) with platform bindings (C ABI, JNI, Swift bridge, pyo3, cgo) so that Windows C# apps, macOS Swift apps, and Linux Python/Go automation all consume the same Rust core via FFI. Adrian is dual-licensed Apache-2.0 / MIT for the core with a commercial option for enterprise; the ADRs and workshop decisions are written for this licensing posture and explicitly reject GPLv3 dependencies (Samba's Heimdal fork, Samba's `smbd`, FreeIPA's `ipa_kdb_mspac.c`).

## Headline numbers

- **130 problems solved**, every problem cross-linked to ≥2 KB source files in [`catalog/`](../catalog/README.md).
- **130 ADRs written** (ADR-001 through ADR-130), covering every problem in the catalog; 69 ADRs were written before the workshop and 61 follow-up ADRs were written after the 12 Tier-1 decisions unblocked the deferred problem set.
- **12 Tier-1 architectural decisions** made at the 2-day Tier-1 ORQ Resolution Workshop (2026-08-13 / 2026-08-14), recorded in [`workshop/`](../workshop/CONTEXT.md).
- **12 framework capabilities** — Core Directory, KDC, Auth Provider, Policy Engine, Cert Service, Federation Gateway, File Gateway, Client SDK, Cross-Platform Parity, Operations, Security, Migration.
- **3 platforms** — Windows, macOS, Linux/UNIX — as both server and client.
- **~320K words of ADRs** across the 130 ADR files (averaging ~2,460 words per ADR); ~49K words across the 12 workshop decisions; ~25K words in the rough draft (now superseded); ~25K lines in the 72-file KB.
- **Rust-only implementation** — every framework crate is Rust; no GPL code, no C on the hot path, no Samba/Heimdal/MIT inheritance.
- **~314 person-weeks** of v1 implementation effort estimated across the 12 workshop decisions; ~24 person-weeks of KDC MVP-preview on the critical path.

## The 12 architectural decisions

The 12 Tier-1 workshop decisions (cited inline below as "Decision N") are:

1. **Replication** — Hybrid: fresh Rust DRSUAPI server (`adrian-drsuapi` crate) for AD-interop mode + `openraft` for native mode, behind a shared async `Replicator` trait. Resolves ORQ-001/002/003/004; cited by ADR-070, ADR-071, ADR-076, ADR-120.
2. **Storage** — FoundationDB 7.3.x as the sole storage engine for all DCs in v1, accessed via the official `foundationdb` Rust crate; single `FdbDirectoryStore` implementation of the `DirectoryStore` trait. Resolves ORQ-011/012/013/014; cited by ADR-073, ADR-074, ADR-010.
3. **Identity** — UUIDv7 primary key for every security principal + SID as a first-class attribute + bidirectional mapping table in FDB subspace `0x0D`. Resolves ORQ-026/027; cited by ADR-075, ADR-076, ADR-110, ADR-126.
4. **Schema** — Hybrid: LDAP `attributeSchema`/`classSchema` as the authoritative source of truth + Rust typed projection generated at boot by `adrian-schema-compiler`. Resolves ORQ-030/031; cited by ADR-078, ADR-003, ADR-119.
5. **KDC** — Fresh Rust KDC in `adrian-kdc` crate (~30K lines at v1 maturity), MS-KILE-conformant, byte-identical PACs vs. Windows Server 2022+. Resolves ORQ-042/043/044; cited by ADR-082, ADR-083, ADR-084.
6. **NTLM** — Drop server-side NTLM entirely; NTLM client-only via `adrian-ntlm-client` for connecting to legacy services; S4U2Self/S4U2Proxy preserved via the framework KDC. Resolves ORQ-072/074/075; cited by ADR-085, ADR-086, ADR-087.
7. **Policy** — Hybrid: declarative JSON/YAML canonical policy + ADMX-to-JSON compiler (`admx2adrian`) + PReg adapter for Windows `Registry.pol` + public `PolicyExecutor` Rust trait. Resolves ORQ-090/091; cited by ADR-089, ADR-090, ADR-091, ADR-092.
8. **PKI** — ACME (RFC 8555) primary enrollment for all platforms + `adrian-wcce-bridge` for Windows `autoenroll.dll`/`certreq.exe` + EST/SCEP bridges for IoT. Resolves ORQ-110/111; cited by ADR-095, ADR-096, ADR-097, ADR-098.
9. **Federation** — Wrap Keycloak 25+ (Quarkus) with a Rust shim (`adrian-federation-shim`) that adds AD FS claim-rule compatibility, framework trust-pipeline integration, and AD FS migration tooling. Resolves ORQ-132/133/134; cited by ADR-100, ADR-101, ADR-102, ADR-103, ADR-104.
10. **SMB** — Fresh Rust SMB 3.1.1 server in `adrian-smb-server` (SMB 2.0.2–3.1.1 dialect range, SHA-512 preauth integrity, AES-256-GCM encryption, no Samba). Resolves ORQ-154/155; cited by ADR-105, ADR-106, ADR-043.
11. **Client SDK** — Unified Rust core library (`adrian-sdk`) with platform-specific bindings (C ABI, JNI, Swift bridge, pyo3, cgo); not gRPC-based. Resolves ORQ-169/170/175/176; cited by ADR-107, ADR-108, ADR-109, ADR-111.
12. **Linux tier** — SSSD primary + FreeIPA alternative + Winbind deprecated + PBIS unsupported; `adrian-sssd-gpo` library extends SSSD's GPO access-control coverage. Resolves ORQ-202/203; cited by ADR-114, ADR-115, ADR-116, ADR-117.

## What Adrian delivers

By capability (every capability has at least one cited ADR; see `03-capability-deep-dives.md` for the per-capability deep dive):

- **Core Directory Service** — Multi-master directory on FoundationDB with FDB subspaces `0x01` (objects) through `0x0D` (identity mapping); linked-value replication (ADR-001), `memberOf` back-link (ADR-002), copy-on-write schema cache (ADR-003), SD deduplication (ADR-004), well-known container GUIDs (ADR-005), AD LDAP controls (ADR-006), `kpasswd` password change (ADR-007), declarative replication topology (ADR-008), constructed attributes (ADR-009), FDB-native backup/PITR (ADR-010 / ADR-073), tombstones (ADR-074), FSMO replacement (ADR-076), DNS-in-directory (ADR-079), multi-tenancy (ADR-081). Hybrid replication: DRSUAPI server for AD-interop (ADR-070), openraft for native (ADR-071), Global Catalog as FDB projection (ADR-072). Fresh Rust DCE/RPC stack amortised across DRSUAPI/SAMR/LSARPC/Netlogon.
- **KDC** — Fresh Rust KDC (`adrian-kdc`, ~30K lines v1) with MS-KILE-conformant PAC generation (ADR-082), PAC validation RPC (ADR-083), PKINIT/FIDO2/WebAuthn bridge (ADR-084), AES-256 default with RC4 audit-then-enforce (ADR-011), FAST-required armoring (ADR-012), cross-realm TGT referral (ADR-013), AES-SHA384 etype 0x13 (ADR-014), HSM-bound krbtgt with 30-day auto-rotation and 2-key overlap (ADR-015), SPN uniqueness (ADR-016), UPN uniqueness (ADR-017), horizontally-scalable stateless KDC pool (ADR-018), `kpasswd` (ADR-019), gMSA with HSM-bound KDS root key (ADR-020), S4U2Self/S4U2Proxy (ADR-087).
- **Auth Provider** — LDAP signing + TLS channel binding (RFC 5929) + EPA mandatory (ADR-021); chrony NTP, drop MS-SNTP (ADR-022); structured Kerberos audit in OpenTelemetry (ADR-023); NTLM client-only (ADR-085); PtH defense (ADR-086); unified token abstraction (ADR-088).
- **Policy Engine** — Per-platform executors (CSE/MDM/SSSD-conf, ADR-024); transactional rollback (ADR-025); declarative host facts with WMI adapter (ADR-026); HTTP HEAD slow-link detection (ADR-027); push via WebSocket (ADR-028); JSON canonical + PReg adapter (ADR-029); role-based binding (ADR-030); Git-backed history with PR review (ADR-031); ADMX-to-JSON compiler (ADR-090); synthetic Windows CSE (ADR-092); SYSVOL replication via Git-backed store (ADR-094); GPO translation for migration (ADR-127).
- **Cert Service** — Two-tier CA with HSM-bound root (ADR-037); HSM-bound KRA with Shamir M-of-N (ADR-032); OCSP responder RFC 6960 with nonce + HA cluster (ADR-033); transactional DB with PITR (ADR-034); multi-CDP HTTP fallback + CRL fallback (ADR-035); trust manager with cross-cert interop (ADR-036); ACME primary + MS-WCCE bridge (ADR-095); declarative `cert-profiles.yaml` (ADR-096); cross-platform autoenroll (ADR-097); NDES/SCEP replacement bridge (ADR-098); NTAuth certificates + PKINIT trust (ADR-099).
- **Federation Gateway** — Keycloak StatefulSet + Rust shim sidecar (ADR-100); AD FS claim-rule language compatibility (ADR-101); Rust shim as WAP replacement (ADR-102); Keycloak identity brokering + HRD (ADR-104); JWKS endpoint + webhook rollover (ADR-038); OIDC primary + WS-Trust-to-OIDC bridge (ADR-039); SAML replay detection (ADR-040); strict OIDC by default (ADR-041); AD RMS out of scope, recommend AIP (ADR-042).
- **File Gateway** — Fresh Rust SMB 3.1.1 server with SHA-512 preauth integrity + AES-256-GCM (ADR-105); SMB client + persistent handles via SDK FileModule (ADR-106); drop SMB1 (ADR-043); DFS-N-equivalent via DNS SRV (ADR-044); ABE pre-computed per-share index (ADR-045); drop MS-RPRN, adopt IPP Everywhere (ADR-046); Offline Files out of scope (ADR-047); SYSVOL migration (ADR-130).
- **Client SDK** — Unified Rust core `adrian-sdk` (ADR-107); SSPI-equivalent auth abstraction (ADR-108); cross-platform LDAP client (ADR-109); SID-to-UID mapping via identity mapping table (ADR-110); unified ticket-cache abstraction (ADR-111); macOS NTLM client (ADR-112); PSSO modern macOS Kerberos path (ADR-056); MIT krb5 standardisation (ADR-049); authselect PAM profile (ADR-050); KCM on Linux / API: on macOS (ADR-051); unified cross-platform CLI (ADR-063).
- **Cross-Platform Parity** — DDM-first authoring with Configuration Profile fallback (ADR-052); key escrow + NBDE (ADR-053); per-host LAPS rotation (ADR-054); legacy agent migration (ADR-055); MCX legacy → MDM/DDM migration (ADR-118); functional-levels as capability bitmask (ADR-121); SSSD-primary Linux tier (ADR-114); FreeIPA alternative (ADR-115); legacy macOS agents EOL (ADR-116); Apple Heimdal fork staleness mitigated (ADR-117).
- **Operations** — Prometheus + OpenTelemetry (ADR-057); container-native DCs + Kubernetes operator (ADR-058); per-DC backup with PITR + DR runbooks (ADR-059); structured audit logs in OTel + MITRE ATT&CK mapping (ADR-060); REST API for CRUD + gRPC for streaming (ADR-061); trust password auto-rotation (ADR-062); unified cross-platform CLI (ADR-063); GitOps schema (ADR-119); multi-region replication topology (ADR-120); DC capabilities bitmask (ADR-121).
- **Security** — Kerberoasting mitigation (ADR-064); HSM-bound krbtgt + golden ticket mitigation (ADR-065); AdminSDHolder → declarative RBAC (ADR-066); Sigstore + in-toto supply chain (ADR-067); DCSync mitigation (ADR-122); silver ticket mitigation (ADR-123); sIDHistory injection mitigation (ADR-124); selective authentication HBAC (ADR-125); PAC_BUFFER_TICKET_CHECKSUM default-on (ADR-082/ADR-123); TRUST_ATTRIBUTE_FRAMEWORK_SID_FILTER default-on (ADR-124).
- **Migration** — Subdomain-per-directory DNS (ADR-068); cross-realm capaths auto-generation (ADR-069); sIDHistory migration via DRSAddSidHistory (ADR-126); GPO translation (ADR-127); Kerberos cross-realm migration (ADR-128); password hash migration (ADR-129); SYSVOL migration (ADR-130).

## Implementation scope

The 12 workshop decisions' person-week estimates sum to the following v1 effort:

| Decision | Capability | Person-weeks |
|----------|-----------|--------------|
| 1 | Replication | ~60 pw (14 person-months) |
| 2 | Storage | ~26 pw (6 person-months) |
| 3 | Identity | ~22 pw (5 person-months) |
| 4 | Schema | ~20 pw |
| 5 | KDC (full v1) | ~42 pw (~24 pw for MVP preview) |
| 6 | NTLM | ~15 pw |
| 7 | Policy | ~14 pw |
| 8 | PKI | ~22 pw |
| 9 | Federation | ~18 pw |
| 10 | SMB | ~28 pw |
| 11 | Client SDK | ~30 pw |
| 12 | Linux tier | ~12 pw |
| **Total** | | **~309 pw** (~310 pw for v1 MVP, ~327 pw for full v1) |

This is the **direct** engineering cost captured in the workshop decisions; it excludes Phase 0 research spikes (~10 pw already incurred), the operator and CLI (covered by ADR-058 and ADR-063 but not in any workshop decision's estimate, ~10 pw), the observability stack (ADR-057, ~6 pw), and the migration tooling (ADRs 126–130, ~12 pw). Including these brings the **v1 MVP total to ~340 person-weeks** (~8.5 engineer-years) and the **full v1 GA total to ~360 person-weeks** (~9 engineer-years). At a staffing level of 6 senior engineers plus 2 mid-level engineers working full-time on v1, this is approximately **14–18 months calendar time** for MVP and **18–22 months** for full v1 GA — matching the 9-month MVP preview + 12-month full v1 estimate from Decision 5's KDC critical path.

The KDC is the **long pole** on the critical path: 24 person-weeks for MVP preview blocks Phase 2 MVP signoff, and 42 person-weeks for full v1 blocks Phase 3 GA (per Decision 5). The MS-WCCE bridge (Decision 8, 6 pw) is the critical-path item for Windows autoenroll migration; the synthetic Windows CSE (Decision 7, 3 pw) is the critical-path item for policy distribution; the SMB2/3 protocol core (Decision 10, 8 pw) is the critical-path item for file gateway. Each of these blocks a specific customer-visible capability and is staffed accordingly.

## Next steps

1. **Staffing** — Recruit 6 senior Rust engineers (3 for the KDC team per Decision 5's explicit recommendation, 1 for the DRSUAPI/DCE-RPC team, 1 for the SMB team, 1 for the operator/observability team) and 2 mid-level engineers (1 for the Client SDK bindings, 1 for the migration tooling). The schema compiler (Decision 4, 4 pw) needs a senior engineer with proc-macro experience; the federation shim (Decision 9, 5 pw) needs a senior engineer with PEG parser experience. Target: team in place by Phase 1 kickoff (T+0).

2. **Phase 0 research spike readouts** — The 7 Phase 0 research spikes (Spike 1: replication, Spike 2: storage, Spike 3: KDC, Spike 4: NTLM prevalence, Spike 5: PKI, Spike 6: federation, Spike 7: SMB) were synthesised into the workshop decisions but their detailed readouts should be reviewed by the implementing teams during Phase 1 week 1 to surface any deferred sub-questions. Spike 4's NTLM-prevalence upper bound (5–10% of enterprise workloads) is the gate for Decision 6's revisit clause; if real-world adoption during Phase 2 MVP exceeds 15%, the NTLM decision must be revisited.

3. **Phase 1 implementation kickoff** — Phase 1 begins with the foundational crates (`adrian-storage-core`, `adrian-storage-fdb`, `adrian-repl-core`, `adrian-sid`, `adrian-identity-core`, `adrian-identity-fdb`, `adrian-schema-compiler`) because every other capability depends on them. The KDC team starts in parallel on `adrian-kdc`'s AS-REQ/TGS-REQ path. Phase 1 target: foundational crates passing their conformance test suites by T+12 weeks; KDC preview passing MIT/Heimdal/Windows interop tests by T+24 weeks.

4. **Interop test lab setup** — Stand up an AD-interop test forest (Windows Server 2022, two-DC forest, separate domain for cross-forest trust testing) before Phase 1 week 4. The lab is the gate for every interop claim: DRSUAPI replication against a real Windows DC (ADR-070), MS-KILE PAC acceptance by Windows `klist`/IIS/SQL Server (ADR-082), MS-WCCE bridge accepting `autoenroll.dll` traffic (ADR-095), SMB 3.1.1 server accepting Windows 11 client connections (ADR-105), AD FS claim-rule compatibility against a migrated AD FS farm (ADR-101). Lab cost: ~$15K/year in Windows Server licensing + ~$5K/year in hardware.

5. **Pilot customer recruitment** — Recruit 3 pilot customers during Phase 2 MVP for the first production deployments in Phase 3. Target profiles: (a) one mid-size enterprise (~5K users) currently on AD with a clean-slate greenfield target (validates native-mode Raft replication, declarative policy, ACME PKI); (b) one enterprise (~25K users) currently on AD with a parallel-run migration target (validates AD-interop DRSUAPI, MS-WCCE bridge, AD FS migration, sIDHistory migration); (c) one regulated industry customer (government, defense, or finance) with an air-gapped requirement (validates no-cloud-deployment posture, FDB multi-region active-active, HSM-bound krbtgt). Each pilot customer commits to a 6-month engagement with weekly status reviews and full access to the engineering team.
