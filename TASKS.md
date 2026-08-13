---
title: TASKS.md — Adrian Framework Master Task List
audience: rust-engineers, architects, project-managers
status: Active
version: 0.1.0
tags: [tasks, roadmap, implementation, tracking, master-list]
related:
  - ./finaldraft/06-implementation-roadmap.md
  - ./finaldraft/04-rust-workspace-design.md
  - ./adr/README.md
  - ./specs/README.md
  - ./workshop/CONTEXT.md
last_updated: 2026-08-13
---

# TASKS.md — Adrian Framework Master Task List

This file is the **single source of truth** for all implementation work on the Adrian framework. Every task is derived from the 130 ADRs, 12 workshop decisions, 12 per-capability specs, and the 7-section final draft. An engineer should be able to pick a task, read its ADR citations, read the corresponding spec, and start implementing.

## How to use this file

1. **Find a task** by phase (Phase 1 MVP → Phase 4 v3) or by capability (Core Directory → Migration).
2. **Read the ADRs** cited in the task — they contain the concrete specification and rationale.
3. **Read the spec** cited in the task — it contains the crate structure, data model, and protocol surface.
4. **Check dependencies** — the "Depends on" field lists tasks that must complete first.
5. **Update status** — when you start a task, change `[ ]` to `[~]`; when done, change to `[x]`.

## Task numbering

- **T-001 through T-099**: Phase 1 MVP (blocker-severity ADRs + foundational crates)
- **T-100 through T-199**: Phase 2 v1 (high-severity ADRs)
- **T-200 through T-299**: Phase 3 v2 (medium-severity ADRs + migration)
- **T-300 through T-399**: Phase 4 v3 (low-severity ADRs + polish)
- **T-400 through T-499**: Cross-cutting workstreams (continuous)
- **T-500 through T-599**: Infrastructure & tooling

## Severity / priority legend

- **P0** (blocker): framework cannot ship without this — gates Phase 1 MVP
- **P1** (high): significant functional gap — gates Phase 2 v1 GA
- **P2** (medium): important but workaround exists — gates Phase 3 v2
- **P3** (low): polish or future-compat — gates Phase 4 v3

---

## Phase 1: MVP (6-12 months, ~13 engineers)

**Goal**: A Linux host can join the framework, authenticate via Kerberos, apply policy, request a cert via ACME, mount an SMB share — against both a framework DC and a Windows Server 2022 DC in mixed mode.

**MVP does NOT deliver**: federation, migration, PKI templates, advanced policy, PKINIT, S4U, DFS-N, offline files, multi-region, DR runbooks.

### Layer 0: Foundation crates (no internal deps — start here)

- [x] **T-001** [P0] Implement `adrian-storage-core` — `DirectoryStore` trait, `DirectoryTransaction` trait, `Key`/`Value`/`KeyRange` types, `DirectoryError` enum
  - **ADRs**: ADR-073
  - **Spec**: `specs/01-core-directory.md` §3
  - **Crates**: `adrian-storage-core`
  - **Depends on**: nothing (this is the root)
  - **Effort**: 1 person-week
  - **DoD**: trait compiles, doc tests pass, `cargo doc` generates clean API docs

- [x] **T-002** [P0] Implement `adrian-sid` — `Sid` type, parse/serialize per MS-DTYP §2.4.2, SID-to-UUID conversion helpers
  - **ADRs**: ADR-077 (RID pool + foreign security principals)
  - **Spec**: `specs/01-core-directory.md` §3
  - **Crates**: `adrian-sid`
  - **Depends on**: nothing
  - **Effort**: 1 person-week
  - **DoD**: round-trip parse/format for all well-known SIDs, `proptest` bijectivity passes, `S-1-5-21-<domain>-<rid>` format validated

- [x] **T-003** [P0] Implement `adrian-schema-traits` — `AttributeSchema`, `ClassSchema`, `SchemaCache` trait
  - **ADRs**: ADR-078 (hybrid schema model), ADR-003 (schema cache CoW)
  - **Spec**: `specs/01-core-directory.md` §3
  - **Crates**: `adrian-schema-traits`
  - **Depends on**: T-002 (uses `Sid` type for SID-syntax attributes)
  - **Effort**: 1.5 person-weeks
  - **DoD**: trait compiles, `searchFlags` bitmask decoded, `systemFlags` bitmask decoded, `lDAPDisplayName` ↔ `cn` mapping implemented

### Layer 1: Abstraction crates (depend on Layer 0)

- [x] **T-004** [P0] Implement `adrian-storage-fdb` — `FdbDirectoryStore` impl of `DirectoryStore`, FDB subspace layout (0x01 objects, 0x02 linktable, 0x03 sdtable, 0x04 schemacache, 0x0D identity mapping)
  - **ADRs**: ADR-073 (FoundationDB as sole storage engine)
  - **Spec**: `specs/01-core-directory.md` §4
  - **Crates**: `adrian-storage-fdb`
  - **Depends on**: T-001
  - **Effort**: 4 person-weeks
  - **DoD**: `get`/`put`/`delete`/`get_range` work against FDB 7.3+, 10K writes/sec on single node, transaction isolation validated, PITR via FDB `backup_agent` tested

- [x] **T-005** [P0] Implement `adrian-identity-core` — `IdentityMapping` trait (`uuid_to_sid`, `sid_to_uuid`, `uuid_to_uid`, `uid_to_uuid`), `PrincipalId` (UUIDv7)
  - **ADRs**: ADR-110 (SID-to-UID mapping via UUID-primary)
  - **Spec**: `specs/01-core-directory.md` §3, `specs/08-client-sdk.md` §3
  - **Crates**: `adrian-identity-core`
  - **Depends on**: T-002
  - **Effort**: 1 person-week
  - **DoD**: trait compiles, `uuid_to_uid` algorithm implemented `(uuid_to_u64(uuid) % (2^31 - 65536)) + 65536`, `proptest` validates determinism

- [x] **T-006** [P0] Implement `adrian-repl-core` — `Replicator` trait, `ReplicationPayload`, `UtdVector`, `InvocationId`, `ReplOperation` enum
  - **ADRs**: ADR-070 (DRSUAPI server), ADR-071 (hybrid replication model)
  - **Spec**: `specs/01-core-directory.md` §3, §5
  - **Crates**: `adrian-repl-core`
  - **Depends on**: T-001
  - **Effort**: 2 person-weeks
  - **DoD**: trait compiles, conflict resolution (highest-version-wins → latest-timestamp → highest-USN → lexicographic InvocationID) implemented, `PropertyMetaDataExt` struct defined

### Layer 2: Domain implementation crates (depend on Layers 0-1)

- [x] **T-007** [P0] Implement `adrian-identity-fdb` — `FdbIdentityMapping` impl of `IdentityMapping`, stored in FDB subspace 0x0D
  - **ADRs**: ADR-110, ADR-077
  - **Spec**: `specs/01-core-directory.md` §4
  - **Crates**: `adrian-identity-fdb`
  - **Depends on**: T-004, T-005
  - **Effort**: 2 person-weeks
  - **DoD**: bidirectional mapping stored, 99%+ cache hit rate, atomic `add_mapping` via FDB atomic-add, unique-index constraint enforced

- [x] **T-008** [P0] Implement `adrian-identity-ridpool` — RID pool allocator (500-RID batches for AD-interop mode, per-DC local counter for native mode)
  - **ADRs**: ADR-077 (RID pool + foreign security principals)
  - **Spec**: `specs/01-core-directory.md` §4
  - **Crates**: `adrian-identity-ridpool`
  - **Depends on**: T-004, T-005
  - **Effort**: 1.5 person-weeks
  - **DoD**: 500-RID batch allocation works, RID pool reclaim on DC removal works, RID uniqueness validated across 100K allocations

- [x] **T-009** [P0] Implement `adrian-drsuapi` — Fresh Rust DRSUAPI server (DRSBind, DRSUnbind, DRSGetNCChanges, DRSReplicaSync, DRSUpdateRefs)
  - **ADRs**: ADR-070
  - **Spec**: `specs/01-core-directory.md` §5
  - **Crates**: `adrian-drsuapi`
  - **Depends on**: T-004, T-006
  - **Effort**: 6 person-weeks
  - **DoD**: DRSUAPI interface UUID `E3514235-8B63-11D0-A26C-00A0C92B955C` registered, opnum 3 (`DRSGetNCChanges`) returns valid `REPLENTIN_V3` packets, interop test against Windows Server 2022 DCDiag passes, `rasn` NDR encoding validated byte-identical

- [x] **T-010** [P0] Implement `adrian-raft` — openraft-based native replication (`RaftReplicator` impl of `Replicator`)
  - **ADRs**: ADR-071 (hybrid replication model), ADR-076 (FSMO replacement via Raft)
  - **Spec**: `specs/01-core-directory.md` §5
  - **Crates**: `adrian-raft`
  - **Depends on**: T-006
  - **Effort**: 4 person-weeks
  - **DoD**: 5-node Raft cluster forms, leader election <5s, log replication <1s p99, UTD vector synthesized from Raft log, `openraft` 0.9+ integrated

- [x] **T-011** [P0] Implement `adrian-schema-compiler` — LDAP schema → typed Rust projection at boot
  - **ADRs**: ADR-078 (hybrid schema model)
  - **Spec**: `specs/01-core-directory.md` §3, §4
  - **Crates**: `adrian-schema-compiler`
  - **Depends on**: T-003, T-004
  - **Effort**: 3 person-weeks
  - **DoD**: reads Schema NC from FDB, generates Rust type stubs, `SchemaCache` populated at boot in <5s for a 1K-class schema, CoW invalidation via `schemaUpdateNow` works

- [x] **T-012** [P0] Implement `adrian-directory-service` — LDAP server + DSA (LDAPv3 read/write, RootDSE, schema validation, `member`/`memberOf` back-link)
  - **ADRs**: ADR-002 (memberOf as DSA-computed back-link), ADR-073, ADR-074 (tombstones + Recycle Bin), ADR-076 (FSMO replacement)
  - **Spec**: `specs/01-core-directory.md` §5
  - **Crates**: `adrian-directory-service`
  - **Depends on**: T-004, T-007, T-009, T-010, T-011
  - **Effort**: 5 person-weeks
  - **DoD**: LDAP bind + search + modify + add + delete work, `memberOf` computed on read, tombstones with 180-day lifetime, Recycle Bin (restore deleted object), FSMO roles emulated (Schema Master via FDB OCC, PDC Emulator via Raft leader, RID Master via per-DC counter, Infrastructure Master eliminated by identity mapping)

- [x] **T-013** [P0] Implement `adrian-dcerpc` — DCE/RPC transport layer (shared by DRSUAPI, SAMR, LSARPC, Netlogon, WCCE)
  - **ADRs**: ADR-070, ADR-083 (PAC validation RPC)
  - **Spec**: `specs/01-core-directory.md` §5
  - **Crates**: `adrian-dcerpc`
  - **Depends on**: T-001
  - **Effort**: 3 person-weeks
  - **DoD**: DCE/RPC over TCP + named pipe transport, NDR encoding/decoding via `rasn`, RPC Endpoint Mapper (port 135) registration, MS-RPCE extensions (security context, pfc_flags)

### Layer 3: KDC + Auth (MVP preview mode)

- [x] **T-014** [P0] Implement `adrian-kdc` MVP preview — AS-REQ/TGS-REQ path, MS-KILE PAC generation (9 buffer types), AES-only etype, kpasswd, HSM-bound krbtgt
  - **ADRs**: ADR-011 (AES-256 default, RC4 disabled), ADR-015 (krbtgt HSM rotation), ADR-082 (MS-KILE PAC), ADR-019 (kpasswd), ADR-020 (gMSA KDS root key)
  - **Spec**: `specs/02-kdc.md` §3, §4, §5
  - **Crates**: `adrian-kdc`, `adrian-pac-validator`, `adrian-hsm`
  - **Depends on**: T-007, T-011, T-013
  - **Effort**: 42 person-weeks (3 engineers × 14 weeks) — **the long pole**
  - **DoD**: AS-REQ/AS-REP + TGS-REQ/TGS-REP work, PAC with 9 buffer types (`PAC_LOGON_INFO`, `PAC_CREDENTIAL_TYPE`, `PAC_SIGNATURE_DATA` ×2, `PAC_CLIENT_INFO`, `UPN_DNS_INFO`, `PAC_REQUESTOR`, `PAC_BUFFER_TICKET_CHECKSUM`, `PAC_FULL_CHECKSUM`), AES-256-CTS-HMAC-SHA1-96 (etype 0x12) enforced, RC4-HMAC (0x17) refused, krbtgt key in HSM via `cryptoki`, 30-day auto-rotation with 2-key overlap, kpasswd (RFC 3244) on port 464, 5K AS-REQ/sec per instance, PAC byte-identity validated against Windows Server 2022

- [x] **T-015** [P0] Implement `adrian-kdc-interop` — MS-KILE conformance tests
  - **ADRs**: ADR-082, ADR-083 (PAC validation)
  - **Spec**: `specs/02-kdc.md` §8
  - **Crates**: `adrian-kdc-interop`
  - **Depends on**: T-014
  - **Effort**: 3 person-weeks (parallel with T-014)
  - **DoD**: test suite runs against MIT krb5 1.21+, Heimdal 7.x, Windows Server 2022; PAC byte-identity proptest passes; AS-REQ/TGS-REQ cross-realm with AD works; fuzzing via `cargo fuzz` (100M iterations nightly)

- [x] **T-016** [P0] Implement `adrian-ntlm-client` — NTLMv2 client-only with channel binding + EPA
  - **ADRs**: ADR-085 (drop NTLM server), ADR-086 (PtH defense)
  - **Spec**: `specs/03-auth-provider.md` §3, §4
  - **Crates**: `adrian-ntlm-client`
  - **Depends on**: T-002, T-005
  - **Effort**: 3 person-weeks
  - **DoD**: NTLMv2 challenge-response (Type 1/2/3 messages), RFC 5929 `tls-server-end-point` channel binding, EPA EPHEMERAL flag set, platform secure-credential-store via `keyring` crate, NTLM server-side rejected with `strongAuthRequired (8)`, NT hashes stored with `Zeroizing<Vec<u8>>` via `zeroize` crate, HSM-bound PEK for AD-interop NT hashes

- [x] **T-017** [P0] Implement `adrian-auth-core` — Unified `AuthContext` trait (Kerberos + NTLM + cert + OAuth2)
  - **ADRs**: ADR-021 (LDAP signing + channel binding), ADR-088 (unified token abstraction)
  - **Spec**: `specs/03-auth-provider.md` §3
  - **Crates**: `adrian-auth-core`
  - **Depends on**: T-014, T-016
  - **Effort**: 2 person-weeks
  - **DoD**: trait compiles, LDAP signing required, TLS channel binding (RFC 5929) required, EPA required, `rustls` for TLS, audit event emitted on auth success/failure

### Layer 3: Policy Engine (MVP)

- [x] **T-018** [P0] Implement `adrian-policy-core` — Declarative JSON policy format + ADMX compiler + PReg adapter
  - **ADRs**: ADR-029 (JSON canonical + PReg adapter), ADR-089 (declarative GPC/GPT synthesis), ADR-090 (ADMX-to-declarative compiler), ADR-094 (git-backed SYSVOL replication)
  - **Spec**: `specs/04-policy-engine.md` §3, §4
  - **Crates**: `adrian-policy-core`, `adrian-policy-preg`, `adrian-admx-compiler`
  - **Depends on**: T-004, T-012
  - **Effort**: 4 person-weeks
  - **DoD**: canonical JSON policy format defined, ADMX XML parsed via `quick-xml`, PReg `Registry.pol` binary format written, GPC/GPT synthesized, SYSVOL as git repository (push/pull replication), ~60% GPO category coverage

- [x] **T-019** [P0] Implement `adrian-policy-executor` — Per-platform `PolicyExecutor` trait + Windows/macOS/Linux implementations
  - **ADRs**: ADR-024 (per-platform executors), ADR-092 (PolicyExecutor trait + synthetic Windows CSE)
  - **Spec**: `specs/04-policy-engine.md` §3
  - **Crates**: `adrian-policy-executor`
  - **Depends on**: T-018
  - **Effort**: 4 person-weeks
  - **DoD**: `WindowsPolicyExecutor` (emits PReg + GptTmpl + Scripts.ini + GPP XML), `MacOsPolicyExecutor` (emits MDM Configuration Profile payloads), `LinuxPolicyExecutor` (emits `authselect` profile + `firewalld`/`nftables` + `/etc/security/limits.conf.d/`), atomic `rename(2)` writes, rollback supported

### Layer 3: Cert Service (MVP)

- [x] **T-020** [P0] Implement `adrian-acme-server` + `adrian-wcce-bridge` — ACME endpoint (RFC 8555) + MS-WCCE bridge for Windows autoenroll
  - **ADRs**: ADR-095 (ACME primary + MS-WCCE bridge)
  - **Spec**: `specs/05-cert-service.md` §3, §5
  - **Crates**: `adrian-acme-server`, `adrian-wcce-bridge`, `adrian-ca`
  - **Depends on**: T-004, T-012, T-014 (for PKINIT trust via NTAuthCertificates)
  - **Effort**: 4 person-weeks
  - **DoD**: ACME directory endpoint, account creation, order placement, challenge validation, cert issuance, MS-WCCE SOAP bridge for Windows clients, cert published to AD `userCertificate` attribute, X.509 v3 cert via `x509-cert` crate

### Layer 3: File Gateway (MVP)

- [x] **T-021** [P0] Implement `adrian-smb-server` — Fresh Rust SMB 3.1.1 server (pre-auth integrity + AES-GCM, no SMB1)
  - **ADRs**: ADR-043 (drop SMB1), ADR-105 (fresh Rust SMB 3.1.1)
  - **Spec**: `specs/07-file-gateway.md` §3, §4, §5
  - **Crates**: `adrian-smb-server`, `adrian-smb-core`
  - **Depends on**: T-014 (Kerberos auth), T-017 (auth abstraction)
  - **Effort**: 8 person-weeks (~15K lines) — **second-longest pole**
  - **DoD**: SMB 3.1.1 Negotiate + Session Setup + Tree Connect + Create + Read + Write + Close, SHA-512 pre-auth integrity, AES-256-GCM encryption, SMB1 Negotiate refused, signing required on all DC connections, MS-SRVS `NetShareEnum` RPC, share ACLs in registry, 10 Gbps read throughput

- [x] **T-022** [P0] Implement `adrian-print-service` — IPP Everywhere (RFC 8011), drop MS-RPRN
  - **ADRs**: ADR-046 (drop MS-RPRN, adopt IPP Everywhere)
  - **Spec**: `specs/07-file-gateway.md` §5
  - **Crates**: `adrian-print-service`
  - **Depends on**: T-021
  - **Effort**: 2 person-weeks
  - **DoD**: IPP Everywhere server (RFC 8011 + PWG 5100.18), no MS-RPRN opnum 109 (PrintNightmare mitigation), `printQueue` objects published to directory

### Layer 3: Client SDK (MVP)

- [x] **T-023** [P0] Implement `adrian-sdk` core + `adrian-sdk-c` (C ABI binding)
  - **ADRs**: ADR-107 (unified Rust core SDK), ADR-108 (SSPI-equivalent), ADR-109 (LDAP client), ADR-110 (SID-to-UID mapping), ADR-111 (ticket cache), ADR-049 (MIT krb5 client)
  - **Spec**: `specs/08-client-sdk.md` §3, §4
  - **Crates**: `adrian-sdk`, `adrian-sdk-c`
  - **Depends on**: T-014, T-016, T-017, T-018, T-020, T-021
  - **Effort**: 6 person-weeks (2 engineers × 3 weeks)
  - **DoD**: `AuthModule` (Kerberos via MIT krb5, NTLM client, cert, OAuth2), `DirectoryModule` (LDAP via `ldap3`), `PolicyModule` (compiles unified DSL to per-platform), `FileModule` (SMB client via `pavao`), `CertModule` (ACME enrollment), C ABI via `cbindgen`, static binary for Linux/macOS/Windows (amd64 + arm64)

### Layer 3: Security (MVP blockers)

- [x] **T-024** [P0] Implement Kerberoasting mitigation — AES-only default + gMSA + detection rules
  - **ADRs**: ADR-064 (Kerberoasting AES migration), ADR-011 (AES-256 default), ADR-020 (gMSA KDS root key)
  - **Spec**: `specs/11-security.md` §3
  - **Crates**: `adrian-kdc`, `adrian-hsm`
  - **Depends on**: T-014
  - **Effort**: included in T-014
  - **DoD**: RC4-HMAC refused by default, gMSA with HSM-bound KDS root key, 30-day gMSA password rotation, audit event on RC4 attempt, MITRE T1558.003 detection rule

- [x] **T-025** [P0] Implement golden ticket mitigation — HSM-bound krbtgt + 30-day rotation + 2-key overlap
  - **ADRs**: ADR-065 (golden ticket krbtgt HSM), ADR-015 (krbtgt HSM rotation)
  - **Spec**: `specs/11-security.md` §3
  - **Crates**: `adrian-kdc`, `adrian-hsm`
  - **Depends on**: T-014
  - **Effort**: included in T-014
  - **DoD**: krbtgt key in HSM via PKCS#11 (`cryptoki`), 30-day auto-rotation, 2-key overlap (old key valid for 30 days), `rotate-krbtgt` CLI command, audit event on old-key TGT use (MITRE T1558.001 detection)

- [x] **T-026** [P0] Implement DCSync mitigation — native Raft mode eliminates EXOP_REPL_SECRETS; AD-interop per-call audit + HSM break-glass
  - **ADRs**: ADR-122 (DCSync mitigation)
  - **Spec**: `specs/11-security.md` §3
  - **Crates**: `adrian-drsuapi`, `adrian-raft`, `adrian-hsm`
  - **Depends on**: T-009, T-010
  - **Effort**: 2 person-weeks
  - **DoD**: native Raft mode has no `EXOP_REPL_SECRETS` opnum, AD-interop mode per-call audit log, HSM-bound break-glass (M-of-N quorum, 5-minute token), 3 default SIEM rules for DCSync detection

### Layer 4: Operations (MVP minimum-viable)

- [x] **T-027** [P0] Implement `adrian-cli` — Unified cross-platform CLI
  - **ADRs**: ADR-063 (unified CLI)
  - **Spec**: `specs/10-operations.md` §3
  - **Crates**: `adrian-cli`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks
  - **DoD**: `adrian-cli join`, `adrian-cli auth`, `adrian-cli policy apply`, `adrian-cli cert enroll`, `adrian-cli file mount`, `adrian-cli kdc rotate-krbtgt`, static binary, `clap` for CLI parsing

- [x] **T-028** [P0] Implement `adrian-monitor` — Prometheus exporter + OpenTelemetry audit
  - **ADRs**: ADR-057 (Prometheus + OTel), ADR-060 (structured audit OTel)
  - **Spec**: `specs/10-operations.md` §3
  - **Crates**: `adrian-monitor`
  - **Depends on**: T-012, T-014
  - **Effort**: 2 person-weeks
  - **DoD**: per-DC Prometheus sidecar (AS-REQ rate, TGS-REQ rate, LDAP latency, FDB op rate, replication lag), OTel log records for all audit events, MITRE ATT&CK mapping in audit schema

- [x] **T-029** [P0] Implement `adrian-operator` — Kubernetes operator + `DomainController` CRD
  - **ADRs**: ADR-058 (container-native DCs + operator)
  - **Spec**: `specs/10-operations.md` §3
  - **Crates**: `adrian-operator`
  - **Depends on**: T-012, T-014
  - **Effort**: 3 person-weeks
  - **DoD**: `DomainController` CRD, StatefulSet deployment, rolling updates, PVC for FDB data, `kube` crate, Helm chart, distroless container image

### MVP integration & testing

- [ ] **T-030** [P0] Set up interop test lab — Windows Server 2022 DC + MIT krb5 + Samba
  - **Spec**: `specs/02-kdc.md` §8
  - **Depends on**: T-015
  - **Effort**: 1 person-week
  - **DoD**: Windows Server 2022 VM, MIT krb5 1.21, Samba 4.20, cross-realm trust between framework realm and AD realm, DRSUAPI replication in mixed topology, automated test suite runs nightly

- [ ] **T-031** [P0] MVP integration test — end-to-end scenario
  - **Spec**: `specs/10-operations.md` §8
  - **Depends on**: T-014, T-017, T-018, T-020, T-021, T-023, T-027
  - **Effort**: 2 person-weeks
  - **DoD**: Linux host joins framework DC, authenticates via Kerberos, applies policy via `authselect`, requests cert via ACME, mounts SMB share — against both framework DC and Windows Server 2022 DC in mixed mode. Test suite in `tests/integration/`.

---

## Phase 2: v1 (12-18 months, ~28 engineers)

**Goal**: First Generally Available release. Adds federation, full policy engine, full cert service, full Client SDK on all 3 platforms, all security hardening, monitoring/operations.

### Core Directory (12 high-severity ADRs)

- [ ] **T-100** [P1] Implement Linked Value Replication (LVR) — per-value `PropertyMetaDataExt` for multi-valued DN-syntax attributes
  - **ADRs**: ADR-001
  - **Crates**: `adrian-repl-core`, `adrian-storage-fdb`, `adrian-drsuapi`
  - **Depends on**: T-009, T-010
  - **Effort**: 2 person-weeks

- [ ] **T-101** [P1] Implement AD-specific LDAP controls (DirSync, ASQ, cross-domain move, tree-delete-ex, get-stats, verify-name, quota-control)
  - **ADRs**: ADR-006
  - **Crates**: `adrian-directory-service`
  - **Depends on**: T-012
  - **Effort**: 3 person-weeks

- [ ] **T-102** [P1] Implement constructed attributes — `memberOf`, `canonicalName`, `tokenGroups` via DSA-side computation
  - **ADRs**: ADR-009
  - **Crates**: `adrian-directory-service`
  - **Depends on**: T-012
  - **Effort**: 2 person-weeks

- [ ] **T-103** [P1] Implement storage-engine-native backup with PITR
  - **ADRs**: ADR-010, ADR-034
  - **Crates**: `adrian-storage-fdb`
  - **Depends on**: T-004
  - **Effort**: 2 person-weeks

- [ ] **T-104** [P1] Implement Global Catalog as FDB projection
  - **ADRs**: ADR-072
  - **Crates**: `adrian-directory-service`, `adrian-storage-fdb`
  - **Depends on**: T-012
  - **Effort**: 2 person-weeks

- [ ] **T-105** [P1] Implement cross-domain move with UUID-stable identity
  - **ADRs**: ADR-075
  - **Crates**: `adrian-directory-service`, `adrian-identity-fdb`
  - **Depends on**: T-012, T-007
  - **Effort**: 1.5 person-weeks

- [ ] **T-106** [P1] Implement foreign security principals + RID pool interop
  - **ADRs**: ADR-077
  - **Crates**: `adrian-identity-ridpool`, `adrian-identity-fdb`
  - **Depends on**: T-008
  - **Effort**: 2 person-weeks

- [ ] **T-107** [P1] Implement schema-as-code GitOps
  - **ADRs**: ADR-119
  - **Crates**: `adrian-schema-compiler`, `adrian-cli`
  - **Depends on**: T-011, T-027
  - **Effort**: 2 person-weeks

- [ ] **T-108** [P1] Implement well-known container GUIDs
  - **ADRs**: ADR-005
  - **Crates**: `adrian-directory-service`
  - **Depends on**: T-012
  - **Effort**: 1 person-week

- [ ] **T-109** [P1] Implement instanceType/systemFlags bitmasks
  - **ADRs**: ADR-080
  - **Crates**: `adrian-schema-traits`
  - **Depends on**: T-003
  - **Effort**: 0.5 person-weeks

- [ ] **T-110** [P1] Implement tombstone-lifetime + lingering-object cleanup
  - **ADRs**: ADR-074
  - **Crates**: `adrian-directory-service`
  - **Depends on**: T-012
  - **Effort**: 1 person-week

- [ ] **T-111** [P1] Implement declarative replication topology
  - **ADRs**: ADR-008
  - **Crates**: `adrian-raft`, `adrian-cli`
  - **Depends on**: T-010, T-027
  - **Effort**: 1.5 person-weeks

### KDC (8 high-severity ADRs)

- [ ] **T-112** [P1] Implement FAST-required mode flip (gated on PKINIT)
  - **ADRs**: ADR-012
  - **Crates**: `adrian-kdc`
  - **Depends on**: T-114 (PKINIT)
  - **Effort**: 2 person-weeks

- [ ] **T-113** [P1] Implement SPN uniqueness + UPN uniqueness
  - **ADRs**: ADR-016, ADR-017
  - **Crates**: `adrian-directory-service`, `adrian-kdc`
  - **Depends on**: T-012, T-014
  - **Effort**: 1.5 person-weeks

- [ ] **T-114** [P1] Implement PKINIT (RFC 4556) + FIDO2/WebAuthn bridge
  - **ADRs**: ADR-084
  - **Crates**: `adrian-kdc`
  - **Depends on**: T-014
  - **Effort**: 4 person-weeks

- [ ] **T-115** [P1] Implement KDC horizontal scaling — stateless pool behind LB
  - **ADRs**: ADR-018
  - **Crates**: `adrian-kdc`
  - **Depends on**: T-014
  - **Effort**: 2 person-weeks

- [ ] **T-116** [P1] Implement gMSA with HSM-bound KDS root key (promote from PARTIAL)
  - **ADRs**: ADR-020
  - **Crates**: `adrian-kdc`, `adrian-hsm`
  - **Depends on**: T-014
  - **Effort**: 2 person-weeks

- [ ] **T-117** [P1] Implement PAC validation RPC — local Ed25519 + NetrLogonSamLogonEx
  - **ADRs**: ADR-083
  - **Crates**: `adrian-kdc`, `adrian-dcerpc`
  - **Depends on**: T-014, T-013
  - **Effort**: 2 person-weeks

- [ ] **T-118** [P1] Implement S4U2Self/S4U2Proxy constrained delegation
  - **ADRs**: ADR-087
  - **Crates**: `adrian-kdc`
  - **Depends on**: T-014, T-117
  - **Effort**: 3 person-weeks

- [ ] **T-119** [P1] Implement cross-realm TGT referral + capaths
  - **ADRs**: ADR-013, ADR-069
  - **Crates**: `adrian-kdc`
  - **Depends on**: T-014
  - **Effort**: 2 person-weeks

### Auth Provider (3 high-severity ADRs)

- [ ] **T-120** [P1] Implement NTP time sync via chrony (drop MS-SNTP)
  - **ADRs**: ADR-022
  - **Crates**: `adrian-cli`
  - **Depends on**: T-027
  - **Effort**: 1 person-week

- [ ] **T-121** [P1] Implement Kerberos audit events in OpenTelemetry
  - **ADRs**: ADR-023
  - **Crates**: `adrian-kdc`, `adrian-monitor`
  - **Depends on**: T-014, T-028
  - **Effort**: 1.5 person-weeks

- [ ] **T-122** [P1] Implement unified token abstraction — `Principal` type in `adrian-sdk`
  - **ADRs**: ADR-088
  - **Crates**: `adrian-sdk`, `adrian-auth-core`
  - **Depends on**: T-023, T-017
  - **Effort**: 2 person-weeks

### Policy Engine (6 high-severity ADRs)

- [ ] **T-123** [P1] Implement full GPO Preferences cross-platform compilation
  - **ADRs**: ADR-091, ADR-113
  - **Crates**: `adrian-policy-core`, `adrian-policy-executor`
  - **Depends on**: T-018, T-019
  - **Effort**: 4 person-weeks

- [ ] **T-124** [P1] Implement push-based policy updates via WebSocket
  - **ADRs**: ADR-028
  - **Crates**: `adrian-policy-core`
  - **Depends on**: T-018
  - **Effort**: 2 person-weeks

- [ ] **T-125** [P1] Implement SSSD GPO access control enhancement
  - **ADRs**: ADR-093, ADR-114
  - **Crates**: `adrian-policy-executor` (new cdylib: `libadrian_sssd_gpo.so`)
  - **Depends on**: T-019
  - **Effort**: 2 person-weeks

### Cert Service (5 high-severity ADRs)

- [ ] **T-126** [P1] Implement HSM-bound KRA keys with Shamir M-of-N
  - **ADRs**: ADR-032
  - **Crates**: `adrian-ca`, `adrian-hsm`
  - **Depends on**: T-020
  - **Effort**: 2 person-weeks

- [ ] **T-127** [P1] Implement OCSP responder per RFC 6960 + HA cluster
  - **ADRs**: ADR-033, ADR-035
  - **Crates**: `adrian-ca`
  - **Depends on**: T-020
  - **Effort**: 3 person-weeks

- [ ] **T-128** [P1] Implement cert profile YAML replaces templates
  - **ADRs**: ADR-096
  - **Crates**: `adrian-ca`
  - **Depends on**: T-020
  - **Effort**: 2 person-weeks

- [ ] **T-129** [P1] Implement cross-platform autoenroll via ACME
  - **ADRs**: ADR-097
  - **Crates**: `adrian-sdk`, `adrian-acme-server`
  - **Depends on**: T-023, T-020
  - **Effort**: 2 person-weeks

### Federation Gateway (5 high-severity ADRs)

- [ ] **T-130** [P1] Implement Keycloak-wrapped federation gateway
  - **ADRs**: ADR-100
  - **Crates**: `adrian-federation-shim`
  - **Depends on**: T-012, T-014
  - **Effort**: 3 person-weeks

- [ ] **T-131** [P1] Implement AD FS claim rule language compat
  - **ADRs**: ADR-101
  - **Crates**: `adrian-claims-engine`
  - **Depends on**: T-130
  - **Effort**: 3 person-weeks

- [ ] **T-132** [P1] Implement Rust shim WAP replacement (Envoy + ext-authz)
  - **ADRs**: ADR-102
  - **Crates**: `adrian-federation-shim`
  - **Depends on**: T-130
  - **Effort**: 2 person-weeks

- [ ] **T-133** [P1] Implement Keycloak identity brokering + home realm discovery
  - **ADRs**: ADR-104
  - **Crates**: `adrian-federation-shim`
  - **Depends on**: T-130
  - **Effort**: 2 person-weeks

### File Gateway (2 high-severity ADRs)

- [ ] **T-134** [P1] Implement DFS-N via DNS SRV
  - **ADRs**: ADR-044
  - **Crates**: `adrian-smb-server`
  - **Depends on**: T-021
  - **Effort**: 2 person-weeks

- [ ] **T-135** [P1] Implement Access-Based Enumeration with pre-computed index
  - **ADRs**: ADR-045
  - **Crates**: `adrian-smb-server`
  - **Depends on**: T-021
  - **Effort**: 2 person-weeks

### Client SDK (5 high-severity ADRs)

- [ ] **T-136** [P1] Implement SSPI-equivalent unified auth abstraction
  - **ADRs**: ADR-108
  - **Crates**: `adrian-sdk`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

- [ ] **T-137** [P1] Implement cross-platform LDAP client (Wldap32-equivalent)
  - **ADRs**: ADR-109
  - **Crates**: `adrian-sdk`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

- [ ] **T-138** [P1] Implement unified ticket cache abstraction (KCM/API:/LSA)
  - **ADRs**: ADR-111
  - **Crates**: `adrian-sdk`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

- [ ] **T-139** [P1] Implement macOS NTLM client gap closure
  - **ADRs**: ADR-112
  - **Crates**: `adrian-ntlm-client`, `adrian-sdk`
  - **Depends on**: T-016, T-023
  - **Effort**: 1.5 person-weeks

- [ ] **T-140** [P1] Implement PSSO as modern macOS Kerberos path
  - **ADRs**: ADR-056
  - **Crates**: `adrian-sdk-swift`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

### Cross-Platform Parity (4 high-severity ADRs)

- [ ] **T-141** [P1] Implement key escrow + NBDE
  - **ADRs**: ADR-053
  - **Crates**: `adrian-sdk`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

- [ ] **T-142** [P1] Implement per-host LAPS rotation
  - **ADRs**: ADR-054
  - **Crates**: `adrian-cli`, `adrian-sdk`
  - **Depends on**: T-027
  - **Effort**: 2 person-weeks

- [ ] **T-143** [P1] Implement FreeIPA as alternative Linux tier
  - **ADRs**: ADR-115
  - **Crates**: `adrian-cli`
  - **Depends on**: T-027
  - **Effort**: 2 person-weeks

- [ ] **T-144** [P1] Implement Apple Heimdal fork staleness mitigation
  - **ADRs**: ADR-117
  - **Crates**: `adrian-pac-validator`
  - **Depends on**: T-014
  - **Effort**: 1.5 person-weeks

### Operations (6 high-severity ADRs)

- [ ] **T-145** [P1] Implement per-DC backup with PITR + DR runbooks
  - **ADRs**: ADR-059
  - **Crates**: `adrian-operator`, `adrian-storage-fdb`
  - **Depends on**: T-029, T-103
  - **Effort**: 3 person-weeks

- [ ] **T-146** [P1] Implement REST API + gRPC API
  - **ADRs**: ADR-061
  - **Crates**: `adrian-directory-service`
  - **Depends on**: T-012
  - **Effort**: 3 person-weeks

### Security (5 high-severity ADRs)

- [ ] **T-147** [P1] Implement silver ticket mitigation — PAC_BUFFER_TICKET_CHECKSUM mandatory
  - **ADRs**: ADR-123
  - **Crates**: `adrian-kdc`, `adrian-pac-validator`
  - **Depends on**: T-014
  - **Effort**: 2 person-weeks

- [ ] **T-148** [P1] Implement sIDHistory injection mitigation — framework SID filtering
  - **ADRs**: ADR-124
  - **Crates**: `adrian-kdc`, `adrian-identity-fdb`
  - **Depends on**: T-014, T-007
  - **Effort**: 2 person-weeks

- [ ] **T-149** [P1] Implement selective authentication HBAC
  - **ADRs**: ADR-125
  - **Crates**: `adrian-policy-executor`
  - **Depends on**: T-019
  - **Effort**: 2 person-weeks

- [ ] **T-150** [P1] Implement AdminSDHolder replacement — declarative RBAC
  - **ADRs**: ADR-066
  - **Crates**: `adrian-policy-core`, `adrian-directory-service`
  - **Depends on**: T-018, T-012
  - **Effort**: 2 person-weeks

- [ ] **T-151** [P1] Implement supply-chain hardening — Sigstore keyless + SLSA L3
  - **ADRs**: ADR-067
  - **Crates**: CI/CD pipeline (not a Rust crate)
  - **Depends on**: T-029
  - **Effort**: 2 person-weeks

### SDK language bindings (Phase 2)

- [ ] **T-152** [P1] Implement `adrian-sdk-jni` — JNI bindings for Java/Kotlin
  - **Crates**: `adrian-sdk-jni`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

- [ ] **T-153** [P1] Implement `adrian-sdk-swift` — Swift bindings
  - **Crates**: `adrian-sdk-swift`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

- [ ] **T-154** [P1] Implement `adrian-sdk-python` — Python bindings (pyo3)
  - **Crates**: `adrian-sdk-python`
  - **Depends on**: T-023
  - **Effort**: 2 person-weeks

---

## Phase 3: v2 (12-18 months, ~28 engineers sustained)

**Goal**: Migration tools, advanced federation, advanced PKI, advanced file gateway, advanced operations.

### Migration (7 ADRs)

- [ ] **T-200** [P2] Implement sIDHistory migration with time-limited passthrough window
  - **ADRs**: ADR-126
  - **Crates**: `adrian-migrate`, `adrian-identity-fdb`
  - **Depends on**: T-007, T-148
  - **Effort**: 3 person-weeks

- [ ] **T-201** [P2] Implement password hash migration — `unicodePwd` HSM-PEK-encrypted transfer
  - **ADRs**: ADR-129
  - **Crates**: `adrian-migrate`, `adrian-hsm`
  - **Depends on**: T-200
  - **Effort**: 2 person-weeks

- [ ] **T-202** [P2] Implement Kerberos cross-realm migration — capaths auto-generation + DNS SRV KDC discovery
  - **ADRs**: ADR-128
  - **Crates**: `adrian-migrate`, `adrian-kdc`
  - **Depends on**: T-119
  - **Effort**: 2 person-weeks

- [ ] **T-203** [P2] Implement GPO translation tool — AD-to-framework-native policy translation
  - **ADRs**: ADR-127
  - **Crates**: `adrian-gpo-translate`, `adrian-admx-compiler`
  - **Depends on**: T-018
  - **Effort**: 4 person-weeks

- [ ] **T-204** [P2] Implement SYSVOL migration — SMB share compat
  - **ADRs**: ADR-130
  - **Crates**: `adrian-migrate`, `adrian-smb-server`
  - **Depends on**: T-021
  - **Effort**: 2 person-weeks

- [ ] **T-205** [P2] Implement subdomain-per-directory DNS strategy
  - **ADRs**: ADR-068
  - **Crates**: `adrian-cli`
  - **Depends on**: T-027
  - **Effort**: 1.5 person-weeks

- [ ] **T-206** [P2] Implement cross-realm capaths auto-generation CLI
  - **ADRs**: ADR-069
  - **Crates**: `adrian-cli`
  - **Depends on**: T-119, T-027
  - **Effort**: 1 person-week

### Federation (4 ADRs)

- [ ] **T-207** [P2] Implement JWKS endpoint + webhook rollover
  - **ADRs**: ADR-038
  - **Crates**: `adrian-federation-shim`
  - **Depends on**: T-130
  - **Effort**: 1.5 person-weeks

- [ ] **T-208** [P2] Implement OIDC primary + WS-Trust-to-OIDC bridge
  - **ADRs**: ADR-039
  - **Crates**: `adrian-federation-shim`
  - **Depends on**: T-130
  - **Effort**: 2 person-weeks

- [ ] **T-209** [P2] Implement SAML replay detection + clock-skew policy
  - **ADRs**: ADR-040
  - **Crates**: `adrian-federation-shim`
  - **Depends on**: T-130, T-120
  - **Effort**: 2 person-weeks

- [ ] **T-210** [P2] Implement strict OIDC by default + `resource=` compat opt-in
  - **ADRs**: ADR-041
  - **Crates**: `adrian-federation-shim`
  - **Depends on**: T-130
  - **Effort**: 1.5 person-weeks

### PKI (4 ADRs)

- [ ] **T-211** [P2] Implement transactional CA DB with PITR
  - **ADRs**: ADR-034
  - **Crates**: `adrian-ca`
  - **Depends on**: T-020, T-103
  - **Effort**: 2 person-weeks

- [ ] **T-212** [P2] Implement trust manager + cross-cert interop
  - **ADRs**: ADR-036
  - **Crates**: `adrian-ca`
  - **Depends on**: T-020
  - **Effort**: 2 person-weeks

- [ ] **T-213** [P2] Implement two-tier CA with HSM-bound root
  - **ADRs**: ADR-037
  - **Crates**: `adrian-ca`, `adrian-hsm`
  - **Depends on**: T-020
  - **Effort**: 3 person-weeks

- [ ] **T-214** [P2] Implement NDES/SCEP replacement bridge
  - **ADRs**: ADR-098
  - **Crates**: `adrian-wcce-bridge`
  - **Depends on**: T-020
  - **Effort**: 2 person-weeks

### Operations (3 ADRs)

- [ ] **T-215** [P2] Implement trust password auto-rotation
  - **ADRs**: ADR-062
  - **Crates**: `adrian-cli`
  - **Depends on**: T-027
  - **Effort**: 1.5 person-weeks

- [ ] **T-216** [P2] Implement multi-region replication topology
  - **ADRs**: ADR-120
  - **Crates**: `adrian-raft`, `adrian-operator`
  - **Depends on**: T-010, T-029
  - **Effort**: 3 person-weeks

- [ ] **T-217** [P2] Implement functional levels → capability flags
  - **ADRs**: ADR-121
  - **Crates**: `adrian-directory-service`
  - **Depends on**: T-012
  - **Effort**: 1.5 person-weeks

### Policy Engine (5 ADRs)

- [ ] **T-218** [P2] Implement transactional policy rollback
  - **ADRs**: ADR-025
  - **Crates**: `adrian-policy-core`
  - **Depends on**: T-018
  - **Effort**: 2 person-weeks

- [ ] **T-219** [P2] Implement declarative host facts + WMI filter adapter
  - **ADRs**: ADR-026
  - **Crates**: `adrian-policy-core`
  - **Depends on**: T-018
  - **Effort**: 2 person-weeks

- [ ] **T-220** [P2] Implement HTTP HEAD slow-link detection
  - **ADRs**: ADR-027
  - **Crates**: `adrian-policy-core`
  - **Depends on**: T-018
  - **Effort**: 1 person-week

- [ ] **T-221** [P2] Implement role-based policy binding
  - **ADRs**: ADR-030
  - **Crates**: `adrian-policy-core`
  - **Depends on**: T-018
  - **Effort**: 1.5 person-weeks

- [ ] **T-222** [P2] Implement git-backed policy history with PR review
  - **ADRs**: ADR-031
  - **Crates**: `adrian-policy-core`
  - **Depends on**: T-018
  - **Effort**: 2 person-weeks

### Core Directory (3 ADRs)

- [ ] **T-223** [P2] Implement copy-on-write schema cache with generation numbers
  - **ADRs**: ADR-003
  - **Crates**: `adrian-schema-compiler`
  - **Depends on**: T-011
  - **Effort**: 2 person-weeks

- [ ] **T-224** [P2] Implement security descriptor deduplication
  - **ADRs**: ADR-004
  - **Crates**: `adrian-storage-fdb`
  - **Depends on**: T-004
  - **Effort**: 1.5 person-weeks

- [ ] **T-225** [P2] Implement kpasswd as primary password-change protocol
  - **ADRs**: ADR-007
  - **Crates**: `adrian-kdc`
  - **Depends on**: T-014
  - **Effort**: 1 person-week

### Cross-Platform Parity (1 ADR)

- [ ] **T-226** [P2] Implement legacy agent migration — dzdo→sudoers
  - **ADRs**: ADR-055
  - **Crates**: `adrian-migrate`
  - **Depends on**: T-027
  - **Effort**: 2 person-weeks

---

## Phase 4: v3 (6-12 months, ~28 engineers sustained)

**Goal**: Legacy compat + polish + documentation maturity.

### Legacy compat + polish (10 ADRs)

- [ ] **T-300** [P3] Implement AES-SHA384 etype 0x13 default preference
  - **ADRs**: ADR-014
  - **Crates**: `adrian-kdc`
  - **Depends on**: T-014
  - **Effort**: 1 person-week

- [ ] **T-301** [P3] Document AD RMS out of scope + recommend Azure Information Protection
  - **ADRs**: ADR-042
  - **Crates**: n/a (documentation)
  - **Depends on**: nothing
  - **Effort**: 0.5 person-weeks

- [ ] **T-302** [P3] Implement DDM-first authoring on macOS with fallback
  - **ADRs**: ADR-052
  - **Crates**: `adrian-sdk-swift`
  - **Depends on**: T-140
  - **Effort**: 2 person-weeks

- [ ] **T-303** [P3] Implement MCX legacy → MDM Configuration Profiles migration
  - **ADRs**: ADR-118
  - **Crates**: `adrian-migrate`, `adrian-sdk-swift`
  - **Depends on**: T-140
  - **Effort**: 1.5 person-weeks

- [ ] **T-304** [P3] Complete documentation coverage for every PC and ORQ
  - **Crates**: n/a (documentation)
  - **Depends on**: all Phase 1-3 tasks
  - **Effort**: 4 person-weeks

- [ ] **T-305** [P3] Write operator runbooks for every Phase 1-3 feature
  - **Crates**: n/a (documentation)
  - **Depends on**: all Phase 1-3 tasks
  - **Effort**: 3 person-weeks

- [ ] **T-306** [P3] Write performance tuning guides
  - **Crates**: n/a (documentation)
  - **Depends on**: T-400 (perf benchmark suite)
  - **Effort**: 2 person-weeks

- [ ] **T-307** [P3] Write troubleshooting guides
  - **Crates**: n/a (documentation)
  - **Depends on**: all Phase 1-3 tasks
  - **Effort**: 2 person-weeks

- [ ] **T-308** [P3] Write certification curriculum for partners
  - **Crates**: n/a (documentation)
  - **Depends on**: T-304, T-305
  - **Effort**: 3 person-weeks

- [ ] **T-309** [P3] Write customer-facing architecture whitepapers
  - **Crates**: n/a (documentation)
  - **Depends on**: T-304
  - **Effort**: 2 person-weeks

---

## Cross-cutting workstreams (continuous)

### Security review

- [ ] **T-400** [P0] Set up performance benchmark suite — 1M-object directory, nightly runs
  - **Targets**: 10K writes/sec single-DC, <5s p99 replication lag (5-DC topology), 5K AS-REQ/sec/KDC, <50ms p99 LDAP subtree search (1K entries), 10 Gbps SMB read
  - **Depends on**: T-014, T-021
  - **Effort**: 2 person-weeks initial + continuous

- [ ] **T-401** [P0] STRIDE threat model updates per release
  - **Covers**: PC-116 through PC-123 (8 security threats)
  - **MITRE ATT&CK**: T1558, T1003.002, T1558.003, T1558.004, T1550.001, T1178
  - **Depends on**: T-024, T-025, T-026, T-147, T-148, T-149, T-150, T-151
  - **Cadence**: quarterly

- [ ] **T-402** [P0] Penetration testing per release
  - **Focus**: 3 blocker threats (Kerberoasting, DCSync, golden ticket) + high-severity threats
  - **External audit**: at MVP, v1, v2
  - **Depends on**: T-031 (MVP), T-154 (v1), Phase 3 completion (v2)
  - **Cadence**: per release

### Interop testing

- [ ] **T-403** [P0] Maintain interop test matrix
  - **Targets**: Windows Server 2022, Windows Server 2025 (when released), Samba 4.x, MIT krb5 1.21+, Heimdal 7.x, FreeIPA 4.10+, Jamf Pro 11.10+
  - **Covers**: DRSUAPI replication, Kerberos cross-realm, LDAP controls, SMB 3.1.1, GPO interop, Configuration Profile interop
  - **Depends on**: T-030, T-015
  - **Cadence**: nightly CI

- [ ] **T-404** [P0] Fuzzing via `cargo fuzz`
  - **Targets**: AS-REQ, TGS-REQ, PAC, NTLMSSP, SMB parsers
  - **Volume**: 100M iterations nightly
  - **Depends on**: T-014, T-016, T-021
  - **Cadence**: nightly

### Documentation

- [ ] **T-405** [P1] KB file updates per feature
  - **Rule**: every feature ships with a KB file update in `docs/`
  - **Cadence**: per PR

- [ ] **T-406** [P1] Documentation review at MVP, v1, v2, v3
  - **Rule**: missing or stale documentation blocks release
  - **Cadence**: per release

---

## Critical path

The critical path through Phase 1 MVP is:

```
T-001 (storage-core)  ─┐
T-002 (sid)            ─┼─→ T-004 (storage-fdb) ──→ T-007 (identity-fdb) ──┐
T-003 (schema-traits)  ─┘   T-005 (identity-core) ──→ T-008 (ridpool)    ──┤
                                                                        ├──→ T-012 (directory-service) ──→ T-014 (KDC) ──→ T-023 (SDK) ──→ T-027 (CLI) ──→ T-031 (integration test)
T-006 (repl-core) ──→ T-009 (drsuapi) ────────────────────────────────────┤
                  └──→ T-010 (raft) ──────────────────────────────────────┘
T-013 (dcerpc) ────────────────────────────────────────────────────────────┘
T-011 (schema-compiler) ───────────────────────────────────────────────────┘
```

**T-014 (KDC) is the longest pole** at 42 person-weeks (3 engineers × 14 weeks). Start it immediately after T-007 and T-011 land. All other Phase 1 tasks can be parallelized around it.

---

## Risk register

| # | Risk | Impact | Probability | Mitigation |
|---|------|--------|-------------|------------|
| R1 | Fresh Rust KDC is the long pole (~9 months to preview) | MVP slip | High | Phase 1 ships KDC preview; full v1 in Phase 2. MIT krb5 fallback during preview. |
| R2 | FoundationDB operational maturity in enterprise | Adoption | Medium | `DirectoryStore` trait abstracts storage; PostgreSQL/CockroachDB backend feasible in v2. Containerized deployment via operator. |
| R3 | MS-KILE corner-case interop with Windows Server 2022 | KDC gaps | Medium | `adrian-kdc-interop` test suite catches gaps pre-GA. Conservative PAC builder. Monitor MS-KILE spec updates. |
| R4 | macOS PSSO Extension may not support all features | macOS gap | Low | Jamf Connect fallback (ADR-048). Graceful degradation. Unified PAC validator bypasses system Heimdal. |
| R5 | SSSD's GPO access control subset insufficient | Linux gap | Medium | `adrian-sssd-gpo` Rust library extends coverage in v1. `pam_access.so` fallback. |
| R6 | ACME-to-MS-WCCE bridge may break Windows autoenroll | Cert interop | Low | Tested against Windows Server 2022 AD CS in Phase 1. Translation gaps documented. Native MS-WCCE fallback during migration. |
| R7 | ID mapping migration from PBIS/Winbind breaks NFS/SMB | Migration | Medium | `adrian-cli migrate from-{sssd,winbind,pbis}` preserves existing UIDs via directory attributes. `find -uid` re-chown automation. |

---

## Staffing plan

### Phase 1 (MVP, 6-12 months) — ~13 engineers

| Role | Count | Focus | Key tasks |
|------|-------|-------|-----------|
| Storage engineer | 1 | FoundationDB backend | T-001, T-004, T-007, T-008 |
| KDC engineers | 3 | Fresh Rust KDC (long pole) | T-014, T-015, T-024, T-025 |
| Replication engineer | 1 | DRSUAPI + Raft | T-006, T-009, T-010, T-026 |
| SMB engineer | 1 | Fresh Rust SMB 3.1.1 | T-021, T-022 |
| SDK engineers | 2 | Unified Rust core + C ABI | T-002, T-003, T-005, T-023, T-027 |
| Policy engineer | 1 | Declarative + ADMX compiler | T-018, T-019 |
| Cert engineer | 1 | ACME + MS-WCCE bridge | T-020 |
| Security engineer | 1 | Kerberoasting/DCSync/golden ticket | T-024, T-025, T-026 |
| Operator engineer | 1 | Operator + CLI + OTel | T-028, T-029 |
| Test engineer | 1 | Interop + fuzzing + integration | T-015, T-030, T-031, T-403, T-404 |

### Phase 2 (v1, 12-18 months) — ~28 engineers

Phase 1 team continues. Additions:

| Role | Count | Focus |
|------|-------|-------|
| Federation engineer | 1 | Keycloak wrapper + claims engine |
| KDC engineers (additional) | 2 | PKINIT, S4U, FAST-required |
| SMB engineer (additional) | 1 | DFS-N, ABE |
| SDK engineers (additional) | 2 | Swift/Python/Go bindings, PSSO |
| Policy engineer (additional) | 1 | Full GPP cross-platform |
| Cert engineer (additional) | 1 | OCSP, key archival, autoenroll |
| Security engineers (additional) | 2 | Silver ticket, sIDHistory, AdminSDHolder, supply chain |
| Operator engineers (additional) | 2 | REST/gRPC, structured audit, multi-region |
| Migration engineer | 1 | Start of Phase 2 scoping |
| Documentation engineer | 1 | KB files, operator runbooks |
| DevOps/SRE engineer | 1 | CI/CD, Sigstore, reproducible builds |

---

## Success criteria

### Phase 1 MVP — Done when:

- [ ] A Linux host can join the framework as a member (`adrian-cli join`)
- [ ] The host authenticates via Kerberos (AS-REQ/TGS-REQ against framework KDC)
- [ ] The host applies policy via `authselect` (declarative JSON → authselect profile)
- [ ] The host requests a cert via ACME (`adrian-cli cert enroll`)
- [ ] The host mounts an SMB share (`adrian-cli file mount`)
- [ ] All of the above works against both a framework DC and a Windows Server 2022 DC in mixed mode
- [ ] PAC byte-identity validated against Windows Server 2022 in `adrian-kdc-interop`
- [ ] Performance targets met: 5K AS-REQ/sec/KDC, 10K writes/sec/DC, <5s replication lag
- [ ] Security mitigations active: RC4 refused, krbtgt HSM-bound, DCSync audited

### Phase 2 v1 — Done when:

- [ ] Federation gateway live (Keycloak-wrapped, SAML + OIDC + WS-Fed)
- [ ] Full GPO Preferences cross-platform compilation (Drive Maps, Files, Registry, Scheduled Tasks, etc.)
- [ ] Full cert service (OCSP, key archival, autoenroll, cert profiles)
- [ ] Client SDK on all 3 platforms with all 5 language bindings (C, JNI, Swift, Python, Go)
- [ ] All security hardening (silver ticket, sIDHistory, AdminSDHolder, supply chain)
- [ ] REST/gRPC API live
- [ ] External security audit passed

### Phase 3 v2 — Done when:

- [ ] Migration tools verified end-to-end against a 100K-user AD forest at a design-partner site
- [ ] Advanced federation (JWKS rollover, SAML replay, strict OIDC)
- [ ] Two-tier CA with HSM-bound root
- [ ] Multi-region replication topology
- [ ] Trust password auto-rotation

### Phase 4 v3 — Done when:

- [ ] All 130 ADRs implemented
- [ ] Documentation complete for every PC and ORQ
- [ ] Operator runbooks for every feature
- [ | Certification curriculum published
- [ ] 5-year support policy per major release with 1-year overlap

---

## How to update this file

1. **Starting a task**: Change `[ ]` to `[~]` and add your name as assignee.
2. **Completing a task**: Change `[~]` to `[x]` and add the PR/commit hash.
3. **Adding a task**: Use the next available T-NNN number in the appropriate phase section.
4. **Blocking a task**: Add `⚠️ BLOCKED` and a note explaining the blocker.
5. **Discovered new work**: Add to the appropriate phase section with a new T-NNN.

Commit message convention for task updates:
```
tasks: T-014 in progress — KDC AS-REQ path implemented, PAC builder next
tasks: T-014 done — KDC preview complete, PAC byte-identity validated (PR #42)
```
