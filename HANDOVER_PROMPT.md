---
title: HANDOVER PROMPT — Adrian Framework Implementation (Phase 1 MVP → v3)
audience: incoming-agent
version: 1.0.0
date: 2026-08-13
predecessor: orchestrator-v1 (waves 0-5 complete)
tags: [handover, implementation, mvp, rust, adrian-framework]
---

# HANDOVER PROMPT — Adrian Framework Implementation

## TO: Incoming Agent

You are taking over implementation of the **Adrian framework** — a Rust-native, cross-platform, Active Directory–equivalent identity and directory framework. Your predecessor completed the scaffolding phase (47 crates, 268 unit tests, all trait definitions and types in place). Your job is to **replace stub implementations with real protocol-handling code** and deliver the Phase 1 MVP.

---

## EXECUTIVE INSTRUCTIONS

Construct a formal, wave-centric, sub-agent-based prompt to ensure comprehensive coverage of all requirements. Design a sufficient number of waves, decomposing the work into granular agent and sub-agent tasks to prevent the orchestrator, agents, and sub-agents from exceeding their respective context window limits. Execute version control commits following each individual task or subtask, and perform repository pushes after the completion of each wave. Upon concluding each wave, conduct rigorous testing against the explicit Definition of Done (DoD) criteria assigned to that wave. The orchestrator is permitted to return only upon the fulfillment of all DoDs. Provision the environment by retrieving and installing all required binaries, strictly adhering to the latest stable versions for all dependencies.

---

## REPOSITORY STATE

**Repository**: https://github.com/pkhairkh/adrian
**GitHub PAT**: Set the `ADRIAN_GH_TOKEN` environment variable to a fresh token from https://github.com/settings/tokens (the predecessor token was shared in plaintext — rotate it)
**Latest commit**: `75f8f0b` — "Wave 5: Final DoD audit — CHANGELOG v0.4.0 with 268 tests across 47 crates"
**Local path after clone**: `/home/z/my-project/adrian/`

### What exists (DO NOT recreate)

| Artifact | Count | Status |
|----------|-------|--------|
| KB files (`docs/`) | 72 | Complete — implementation-level AD reference |
| Problem catalog (`catalog/`) | 16 files, 130 problems | Complete — all 130 problems catalogued |
| ADRs (`adr/`) | 130 | Complete — one ADR per problem (ADR-001 to ADR-130) |
| Workshop decisions (`workshop/`) | 12 | Complete — all 11 Tier-1 ORQ clusters resolved |
| Final draft (`finaldraft/`) | 7 sections, ~32K words | Complete — definitive synthesis |
| Per-capability specs (`specs/`) | 12 | Complete — crate structure, data models, protocol surfaces |
| TASKS.md | 155 tasks (T-001 to T-406) | Complete — master task list with dependencies, effort estimates, DoDs |
| Rust workspace (`rust/`) | 47 crates | Scaffolded — all crates compile, 268 tests pass |
| CHANGELOG.md | v0.4.0 | Current |

### What's missing (YOUR job)

The 47 Rust crates have **trait definitions, types, error enums, and unit tests** — but the actual protocol handlers are **stubs** returning `NotImplemented` or `todo!()`. There are **~220 TODO markers** across 42 files. The critical stubs are:

| Crate | TODOs | What needs implementing |
|-------|-------|----------------------|
| `adrian-drsuapi` | 18 | DRSBind, DRSGetNCChanges, DRSReplicaSync (MS-DRSR §4) |
| `adrian-storage-fdb` | 16 | FDB-backed DirectoryStore (real FDB transactions, not stubs) |
| `adrian-policy-executor` | 16 | Windows/macOS/Linux policy application (PReg, Configuration Profile, authselect) |
| `adrian-directory-service` | 14 | LDAP server (Bind, Search, Modify, Add, Delete, RootDSE) |
| `adrian-dcerpc` | 14 | DCE/RPC transport (NDR encoding, endpoint mapper, bind/negotiate) |
| `adrian-raft` | 10 | openraft integration (RaftReplicator impl) |
| `adrian-storage-testkit` | 9 | InMemoryDirectoryStore for integration tests |
| `adrian-identity-fdb` | 8 | FDB-backed IdentityMapping (subspace 0x0D) |
| `adrian-schema-compiler` | 7 | LDAP schema → Rust typed projection at boot |
| `adrian-identity-ridpool` | 7 | RID pool allocator (500-RID batches) |
| `adrian-kdc` | 6 | AS-REQ/AS-REP, TGS-REQ/TGS-REP, PAC builder, kpasswd |
| `adrian-ca` | 5 | CA service (cert issuance, revocation, profiles) |
| `adrian-acme-server` | 5 | ACME endpoint (RFC 8555: account, order, challenge, finalize) |
| `adrian-monitor` | 5 | Prometheus exporter + OTel audit pipeline |
| `adrian-storage-core` | 5 | DirectoryTransaction trait, KeyRange types |

---

## ENVIRONMENT PROVISIONING

### Required binaries (install latest stable)

```bash
# Rust toolchain (already installed in predecessor env — verify or reinstall)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile default
. $HOME/.cargo/env
rustc --version  # must be ≥ 1.97.0

# GitHub CLI (for repo operations)
GH_VERSION="2.74.0"
curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" -o /tmp/gh.tar.gz
tar xzf /tmp/gh.tar.gz -C /tmp
mkdir -p /home/z/.local/bin
cp /tmp/gh_${GH_VERSION}_linux_amd64/bin/gh /home/z/.local/bin/gh
chmod +x /home/z/.local/bin/gh
export PATH=/home/z/.local/bin:$PATH

# FoundationDB client library (for adrian-storage-fdb real backend)
# NOTE: FDB 7.3+ requires libclang at build time for foundationdb-sys bindgen
# Install via: apt-get install -y libclang-dev clang
# FDB C client: download from https://github.com/apple/foundationdb/releases (7.3.x)

# Clone repo
cd /home/z/my-project
git clone https://pkhairkh:${ADRIAN_GH_TOKEN}@github.com/pkhairkh/adrian.git
cd adrian
git config user.name "pkhairkh"
git config user.email "31141379+pkhairkh@users.noreply.github.com"

# Verify state
. $HOME/.cargo/env
cd rust && cargo check --workspace && cargo test --workspace 2>&1 | grep 'test result'
# Expected: 268 passed, 0 failed, 4 ignored
```

### Environment constraints

- **Disk**: Workspace `target/` directory can grow to 7+ GB. Run `cargo clean` between waves if disk fills.
- **Context window**: Sub-agents must not exceed ~200K tokens. Limit each sub-agent to 5-8 crates.
- **Parallelism**: Dispatch 3-4 sub-agents in parallel per wave. Each sub-agent commits and pushes independently.
- **Timeouts**: Sub-agents may time out at ~10 minutes. They often complete the work before the timeout — check `git log` and file state before re-dispatching.

---

## WAVE PLAN

### Wave 0: Environment verification + stub audit (YOU ARE HERE)

**DoD**: Repo cloned, `cargo check --workspace` passes, `cargo test --workspace` shows 268 passed / 0 failed, TODO inventory documented.

**Tasks**:
1. Clone repo, install Rust + gh CLI
2. Run `cargo check --workspace` — must pass
3. Run `cargo test --workspace` — must show 268 passed
4. Run `grep -r 'TODO\|todo!\|unimplemented!' crates/ --include='*.rs' -l | wc -l` — document TODO count
5. Commit a `HANDOVER_STATE.md` file to the repo documenting the TODO inventory

---

### Wave 1: Storage layer real implementation (T-004, T-007, T-008)

**DoD**: `adrian-storage-fdb` has a real FDB-backed `DirectoryStore` (not stubs), `adrian-identity-fdb` has real FDB-backed `IdentityMapping`, `adrian-identity-ridpool` has real RID allocation. Integration tests pass against a real or simulated FDB instance. Target: +50 tests (318 total).

**Critical path dependency**: This wave unblocks T-012 (directory-service) and T-014 (KDC).

**Sub-tasks** (dispatch as parallel sub-agents):

#### Sub-task 1a: `adrian-storage-fdb` real FDB backend
- Implement `FdbDirectoryStore::get` / `get_by_dn` / `put` / `delete` using real FDB transactions
- Implement `FdbTxn` (ReadTxn + WriteTxn) wrapping `foundationdb::Transaction`
- Implement `encode_object_key` / `encode_link_forward_key` with real tuple-layer encoding (use `foundationdb::tuple` module)
- Implement DNT counter via FDB atomic-add on key `(0x01, 0xFF, "next_dnt")`
- Implement tombstone move-to-subspace-0x07 on delete (per ADR-074)
- **Tests**: Integration tests against `foundationdb-simulation` or a real FDB instance (mark as `#[ignore]` if FDB unavailable in CI)
- **ADRs**: ADR-073 (FoundationDB as sole storage engine)
- **KB ref**: `docs/01-ad-core/01-ad-ds-internals.md` — ESE/JET internals (analogous patterns)
- **Effort**: 4 person-weeks → compress to 1 wave with focused sub-agent

#### Sub-task 1b: `adrian-identity-fdb` + `adrian-identity-ridpool`
- Implement `FdbIdentityMapping::uuid_to_sid` / `sid_to_uuid` / `uuid_to_uid` / `uid_to_uuid` using FDB subspace 0x0D
- Implement bidirectional mapping table (UUID → SID, SID → UUID) with FDB atomic transactions
- Implement RID pool allocator: 500-RID batches via FDB atomic-add on `(0x06, "next_rid")`, per-DC local cache
- Implement RID pool reclaim on DC removal
- **Tests**: 10+ integration tests for mapping round-trips, RID allocation, RID uniqueness
- **ADRs**: ADR-110 (SID-to-UID mapping), ADR-077 (RID pool + foreign security principals)
- **Workshop ref**: `workshop/decision-03-identity-model.md`
- **Effort**: 3 person-weeks

#### Sub-task 1c: `adrian-storage-testkit` (InMemoryDirectoryStore)
- Implement `InMemoryDirectoryStore` using `std::collections::BTreeMap` for testing without FDB
- Implement `InMemoryTxn` (ReadTxn + WriteTxn)
- This unblocks integration tests for all higher layers
- **Tests**: 15+ tests (CRUD, range scans, transactions, conflict simulation)
- **Effort**: 2 person-weeks

**Wave 1 commit message**: `Wave 1: Real storage layer — FDB backend, identity mapping, RID pool, testkit (T-004, T-007, T-008, +50 tests)`

---

### Wave 2: Replication + directory service (T-009, T-010, T-011, T-012, T-013)

**DoD**: `adrian-drsuapi` handles DRSBind/DRSGetNCChanges, `adrian-raft` has real openraft integration, `adrian-directory-service` serves LDAP Bind/Search/Modify, `adrian-dcerpc` handles NDR encoding. Target: +60 tests (378 total).

**Critical path dependency**: This wave unblocks T-014 (KDC) and T-023 (SDK).

**Sub-tasks**:

#### Sub-task 2a: `adrian-dcerpc` real NDR + transport
- Implement NDR encoding/decoding using `rasn` crate (DCE/RPC bind, bind_ack, request, response)
- Implement TCP transport (port 135 endpoint mapper + dynamic ports)
- Implement named pipe transport (SMB `\pipe\lsass`, `\pipe\netlogon`)
- Implement interface UUID registration (DRSUAPI `E3514235-...`, SAMR `12345778-...`, LSARPC `12345778-...`, Netlogon `12345678-...`, WCCE `910b6e5a-...`)
- **Tests**: 15+ tests for NDR encode/decode round-trips, bind negotiation
- **ADRs**: ADR-070 (DRSUAPI server), ADR-083 (PAC validation RPC)
- **KB ref**: `docs/02-protocols/06-rpc-dcerpc-ms-drsr.md`
- **Effort**: 4 person-weeks

#### Sub-task 2b: `adrian-drsuapi` real DRSUAPI server
- Implement `DRSBind` (opnum 0) — establishes replication context
- Implement `DRSUnbind` (opnum 1)
- Implement `DRSReplicaSync` (opnum 2) — triggers replication
- Implement `DRSGetNCChanges` (opnum 3) — returns REPLENTIN_V3 packets
- Implement `DRSUpdateRefs` (opnum 6) — updates replication topology
- Implement `DRSCrackNames` (opnum 12) — name resolution
- Implement `DRSWriteSPN` (opnum 13) — SPN uniqueness check
- **Tests**: 20+ tests for REPLENTIN encoding, UTD vector handling, conflict resolution
- **ADRs**: ADR-070, ADR-071 (hybrid replication)
- **KB ref**: `docs/02-protocols/06-rpc-dcerpc-ms-drsr.md` (full DRSUAPI opnum table)
- **Workshop ref**: `workshop/decision-01-replication-protocol.md`
- **Effort**: 6 person-weeks

#### Sub-task 2c: `adrian-raft` real openraft integration
- Implement `RaftReplicator` impl of `Replicator` trait using `openraft` 0.9+
- Implement Raft log entry format (`RaftLogEntry` with `ReplOperation` payload)
- Implement UTD vector synthesis from Raft log
- Implement 5-node cluster formation, leader election, log replication
- **Tests**: 10+ tests (cluster formation, leader election, log replication, conflict resolution)
- **ADRs**: ADR-071, ADR-076 (FSMO replacement via Raft)
- **Effort**: 4 person-weeks

#### Sub-task 2d: `adrian-schema-compiler` + `adrian-directory-service`
- Implement schema projection at boot (read Schema NC, build `SchemaProjection`)
- Implement copy-on-write schema cache with generation numbers (per ADR-003)
- Implement LDAP server: Bind (anonymous, simple, GSSAPI), Search (base/one/subtree), Modify, Add, Delete, RootDSE
- Implement `memberOf` back-link computation (per ADR-002)
- Implement tombstone lifecycle (per ADR-074)
- **Tests**: 15+ tests (LDAP bind, search, modify, schema validation, memberOf computation)
- **ADRs**: ADR-002, ADR-003, ADR-012, ADR-074, ADR-078
- **KB ref**: `docs/02-protocols/02-ldap-protocol.md`, `docs/03-directory-schema/`
- **Effort**: 5 person-weeks

**Wave 2 commit message**: `Wave 2: Replication + directory service — DRSUAPI, Raft, LDAP, schema compiler (T-009 to T-013, +60 tests)`

---

### Wave 3: KDC MVP preview (T-014, T-015, T-016, T-017) — THE LONG POLE

**DoD**: `adrian-kdc` handles AS-REQ/AS-REP + TGS-REQ/TGS-REP with MS-KILE PAC (9 buffer types), AES-256-CTS-HMAC-SHA1-96 only (RC4 refused), kpasswd on port 464, HSM-bound krbtgt. `adrian-kdc-interop` validates PAC byte-identity against Windows Server 2022. Target: +80 tests (458 total).

**This is the critical path.** T-014 is estimated at 42 person-weeks (3 engineers × 14 weeks). Compress by dispatching 3 parallel sub-agents on KDC components.

**Sub-tasks**:

#### Sub-task 3a: KDC core — AS-REQ/AS-REP + TGS-REQ/TGS-REP
- Implement AS-REQ parsing (RFC 4120 §5.4.1) using `rasn-kerberos`
- Implement AS-REP generation (TGT encrypted with krbtgt key)
- Implement TGS-REQ parsing (RFC 4120 §5.5.1)
- Implement TGS-REP generation (service ticket encrypted with service account key)
- Implement etype negotiation: AES-256-CTS-HMAC-SHA1-96 (0x12) only; RC4-HMAC (0x17) refused
- Implement pre-auth: PA-ENC-TIMESTAMP (encrypted timestamp)
- **Tests**: 20+ tests (AS-REQ/TGS-REQ parsing, etype negotiation, pre-auth validation)
- **ADRs**: ADR-011 (AES-256 default, RC4 disabled), ADR-082 (MS-KILE PAC)
- **KB ref**: `docs/02-protocols/01-kerberos-internals.md` (full ASN.1 + etype table)
- **Workshop ref**: `workshop/decision-05-kdc-implementation.md`
- **Effort**: 15 person-weeks

#### Sub-task 3b: PAC builder + validator
- Implement PAC generation with 9 buffer types: `PAC_LOGON_INFO`, `PAC_CREDENTIAL_TYPE`, `PAC_SIGNATURE_DATA` (×2, one per etype), `PAC_CLIENT_INFO`, `UPN_DNS_INFO`, `PAC_REQUESTOR`, `PAC_BUFFER_TICKET_CHECKSUM`, `PAC_FULL_CHECKSUM`
- Implement PAC signing (krbtgt key, AES-256 HMAC)
- Implement PAC validation in `adrian-pac-validator`
- Implement `PAC_BUFFER_TICKET_CHECKSUM` (silver ticket mitigation, per ADR-123)
- **Tests**: 15+ tests (PAC construction, signing, validation, byte-identity against known-good Windows PAC)
- **ADRs**: ADR-082, ADR-083 (PAC validation), ADR-123 (silver ticket)
- **KB ref**: `docs/02-protocols/08-spn-upn-pac.md` (full PAC structure)
- **Effort**: 10 person-weeks

#### Sub-task 3c: kpasswd + HSM krbtgt + gMSA
- Implement kpasswd (RFC 3244) on port 464 — password change + set
- Implement HSM-bound krbtgt via `cryptoki` (PKCS#11)
- Implement 30-day krbtgt auto-rotation with 2-key overlap (per ADR-015)
- Implement gMSA with HSM-bound KDS root key (per ADR-020)
- Implement FAST (RFC 6806) in `supported` mode (NOT `required` — gated on PKINIT in v1)
- **Tests**: 15+ tests (kpasswd, HSM binding, rotation, gMSA, FAST armoring)
- **ADRs**: ADR-015, ADR-019 (kpasswd), ADR-020 (gMSA), ADR-012 (FAST)
- **Effort**: 10 person-weeks

#### Sub-task 3d: NTLM client + auth abstraction
- Implement NTLMv2 client (Type 1/2/3 messages) in `adrian-ntlm-client`
- Implement RFC 5929 channel binding (`tls-server-end-point`)
- Implement EPA EPHEMERAL flag
- Implement `AuthContext` trait in `adrian-auth-core` (Kerberos + NTLM + cert + OAuth2)
- Implement platform secure-credential-store via `keyring` crate
- **Tests**: 15+ tests (NTLM message construction, channel binding, auth context)
- **ADRs**: ADR-085 (drop NTLM server), ADR-086 (PtH defense), ADR-088 (unified token)
- **KB ref**: `docs/02-protocols/04-ntlm-internals.md`
- **Effort**: 5 person-weeks

#### Sub-task 3e: KDC interop test suite
- Implement `adrian-kdc-interop` test suite
- Test against MIT krb5 1.21+ (install `krb5-user` package)
- Test PAC byte-identity (construct PAC, send to Windows Server 2022, verify acceptance — or simulate with known-good PAC fixtures)
- Fuzzing targets: AS-REQ, TGS-REQ, PAC parsers via `cargo fuzz`
- **Tests**: 15+ interop tests (MIT cross-realm, PAC byte-identity, fuzzing)
- **ADRs**: ADR-082, ADR-083
- **Effort**: 3 person-weeks

**Wave 3 commit message**: `Wave 3: KDC MVP preview — AS-REQ/TGS-REQ, PAC, kpasswd, HSM, NTLM client, interop (T-014 to T-017, +80 tests)`

---

### Wave 4: Policy + Cert + File services (T-018, T-019, T-020, T-021, T-022)

**DoD**: Policy engine compiles declarative JSON to Windows PReg + macOS Configuration Profile + Linux authselect. ACME server issues real X.509 certs. SMB 3.1.1 server handles Negotiate + Session Setup + Tree Connect + Create + Read + Write + Close. Target: +70 tests (528 total).

**Sub-tasks**:

#### Sub-task 4a: Policy engine
- Implement declarative JSON policy format in `adrian-policy-core` (serde structs, validation)
- Implement `PolicyExecutor` trait in `adrian-policy-executor`:
  - `WindowsPolicyExecutor`: emits PReg `Registry.pol` + `GptTmpl.inf` + `Scripts.ini` + GPP XML
  - `MacOsPolicyExecutor`: emits MDM Configuration Profile payloads (`com.apple.ManagedClient.preferences`, `com.apple.security.firewall`, etc.)
  - `LinuxPolicyExecutor`: emits `authselect` profile + `firewalld`/`nftables` + `/etc/security/limits.conf.d/`
- Implement ADMX-to-declarative compiler in `adrian-admx-compiler` (XML parsing via `quick-xml`)
- Implement PReg binary format in `adrian-policy-preg` (PReg signature + UTF-16LE records)
- **Tests**: 20+ tests (policy compilation, PReg encoding, Configuration Profile generation, authselect profile)
- **ADRs**: ADR-024, ADR-029, ADR-089, ADR-090, ADR-091, ADR-092
- **KB ref**: `docs/04-group-policy/` (full GPO architecture)
- **Workshop ref**: `workshop/decision-07-policy-format.md`
- **Effort**: 4 person-weeks

#### Sub-task 4b: Cert service
- Implement ACME server (RFC 8555) in `adrian-acme-server`: directory, new-account, new-order, authz, challenge, finalize, cert
- Implement CA service in `adrian-ca`: cert issuance (X.509 v3 via `x509-cert`), revocation, CRL
- Implement cert profile YAML in `adrian-ca` (replaces AD CS templates)
- Implement MS-WCCE bridge in `adrian-wcce-bridge` (translates MS-WCCE SOAP → ACME)
- **Tests**: 15+ tests (ACME flow, cert issuance, CRL, MS-WCCE translation)
- **ADRs**: ADR-095, ADR-096, ADR-097, ADR-098
- **KB ref**: `docs/05-pki-certs/`, `docs/02-protocols/02-ldap-protocol.md` (OCSP)
- **Workshop ref**: `workshop/decision-08-pki-enrollment.md`
- **Effort**: 4 person-weeks

#### Sub-task 4c: SMB server + print
- Implement SMB 3.1.1 server in `adrian-smb-server`:
  - Negotiate (dialect 0x311, pre-auth integrity SHA-512)
  - Session Setup (Kerberos via GSS-API, NTLM refused)
  - Tree Connect, Create, Read, Write, Close
  - AES-256-GCM encryption
  - SMB1 refused (per ADR-043)
- Implement SMB client in `adrian-smb-client` (for SDK FileModule)
- Implement IPP Everywhere print service in `adrian-print-service` (RFC 8011)
- **Tests**: 20+ tests (Negotiate, Session Setup, Create/Read/Write, IPP operations)
- **ADRs**: ADR-043, ADR-046, ADR-105, ADR-106
- **KB ref**: `docs/02-protocols/03-smb-cifs-protocol.md`, `docs/07-file-print/`
- **Workshop ref**: `workshop/decision-10-smb-server.md`
- **Effort**: 8 person-weeks

**Wave 4 commit message**: `Wave 4: Policy + cert + file services — declarative policy, ACME, SMB 3.1.1, IPP (T-018 to T-022, +70 tests)`

---

### Wave 5: SDK + ops + integration test (T-023, T-027, T-028, T-029, T-031)

**DoD**: Unified SDK core compiles and passes integration tests. `adrian-cli` has working `join`/`auth`/`policy`/`cert`/`file` commands. `adrian-operator` deploys a DC to Kubernetes. MVP integration test (T-031) passes. Target: +50 tests (578 total).

**Sub-tasks**:

#### Sub-task 5a: Unified SDK
- Implement `adrian-sdk` core:
  - `AuthModule`: Kerberos (via MIT krb5), NTLM client, cert, OAuth2
  - `DirectoryModule`: LDAP via `ldap3` crate
  - `PolicyModule`: compiles unified DSL to per-platform format
  - `FileModule`: SMB client via `pavao` or fresh implementation
  - `CertModule`: ACME enrollment
- Implement `adrian-sdk-c` C ABI via `cbindgen`
- **Tests**: 15+ tests (module construction, auth flow, LDAP query, policy compilation)
- **ADRs**: ADR-107, ADR-108, ADR-109, ADR-110, ADR-111
- **KB ref**: `docs/09-linux-equivalents/` (SSSD patterns), `docs/08-macos-equivalents/`
- **Workshop ref**: `workshop/decision-11-client-sdk.md`
- **Effort**: 4 person-weeks

#### Sub-task 5b: CLI + monitor + operator
- Implement `adrian-cli` commands: `join`, `auth`, `policy apply`, `cert enroll`, `file mount`, `kdc rotate-krbtgt`
- Implement `adrian-monitor`: Prometheus exporter (AS-REQ rate, LDAP latency, FDB op rate, replication lag), OTel audit pipeline
- Implement `adrian-operator`: `DomainController` CRD, StatefulSet, rolling updates, Helm chart
- **Tests**: 15+ tests (CLI parsing, Prometheus metrics, CRD serialization)
- **ADRs**: ADR-057, ADR-058, ADR-060, ADR-063
- **Effort**: 3 person-weeks

#### Sub-task 5c: MVP integration test (T-031)
- Implement end-to-end integration test in `tests/integration/`:
  1. Linux host joins framework DC (`adrian-cli join`)
  2. Authenticates via Kerberos (AS-REQ/TGS-REQ)
  3. Applies policy via `authselect`
  4. Requests cert via ACME
  5. Mounts SMB share
- Test against both framework DC and Windows Server 2022 DC in mixed mode
- **Tests**: 1 comprehensive integration test (may be `#[ignore]` if Windows Server VM unavailable)
- **DoD**: The integration test passes end-to-end
- **Effort**: 2 person-weeks

**Wave 5 commit message**: `Wave 5: SDK + ops + MVP integration test (T-023, T-027 to T-029, T-031, +50 tests)`

---

### Wave 6: Final DoD audit + CHANGELOG v0.5.0

**DoD**: `cargo check --workspace` passes, `cargo test --workspace` shows 578+ passed / 0 failed, `cargo clippy --workspace -- -D warnings` clean, `cargo fmt --all --check` clean, CHANGELOG updated to v0.5.0, TASKS.md updated with completed task markers.

**Tasks**:
1. Run full workspace audit
2. Fix any clippy warnings or test failures
3. Update CHANGELOG.md with v0.5.0 entry
4. Update TASKS.md: mark T-001 to T-031 as `[x]`
5. Commit and push final state
6. Verify local HEAD = remote HEAD

---

## KEY REFERENCES (read these first)

### Architecture documents
- `TASKS.md` — master task list with dependencies, effort estimates, DoDs
- `finaldraft/01-executive-summary.md` — what Adrian is, headline numbers
- `finaldraft/02-architecture-overview.md` — 12 capabilities, Rust crate map, dependency graph
- `finaldraft/04-rust-workspace-design.md` — 47-crate layout, 5-layer dependency hierarchy, key traits
- `finaldraft/06-implementation-roadmap.md` — 4-phase roadmap (MVP/v1/v2/v3), risks, success criteria

### Workshop decisions (architectural choices already made)
- `workshop/decision-01-replication-protocol.md` — Hybrid: fresh Rust DRSUAPI (AD-interop) + openraft (native)
- `workshop/decision-02-storage-engine.md` — FoundationDB 7.3.x as sole storage engine
- `workshop/decision-03-identity-model.md` — UUIDv7 primary + SID-as-attribute + mapping table
- `workshop/decision-04-schema-model.md` — Hybrid: LDAP schema substrate + typed Rust projection
- `workshop/decision-05-kdc-implementation.md` — Fresh Rust KDC (NOT MIT, NOT Samba)
- `workshop/decision-06-ntlm-decision.md` — Drop NTLM server-side; client-only for legacy
- `workshop/decision-07-policy-format.md` — Hybrid: declarative JSON + ADMX compiler
- `workshop/decision-08-pki-enrollment.md` — ACME primary + MS-WCCE bridge
- `workshop/decision-09-federation-layer.md` — Wrap Keycloak
- `workshop/decision-10-smb-server.md` — Fresh Rust SMB 3.1.1
- `workshop/decision-11-client-sdk.md` — Unified Rust core + platform bindings
- `workshop/decision-12-linux-tier.md` — SSSD primary + FreeIPA alternative

### ADRs (130 total — one per problem)
- `adr/README.md` — master index
- Key MVP ADRs: ADR-011 (AES-256 default), ADR-015 (krbtgt HSM), ADR-070 (DRSUAPI), ADR-073 (FoundationDB), ADR-082 (PAC), ADR-105 (SMB 3.1.1)

### Per-capability specs
- `specs/01-core-directory.md` through `specs/12-migration.md`
- Each spec has: crate structure, key types/traits, FDB subspace layout, protocol surface, configuration, testing strategy

### KB files (implementation-level protocol reference)
- `docs/02-protocols/01-kerberos-internals.md` — RFC 4120 + MS-KILE, PAC, FAST, PKINIT
- `docs/02-protocols/02-ldap-protocol.md` — RFC 4511 + AD controls
- `docs/02-protocols/03-smb-cifs-protocol.md` — SMB 1/2/3 dialects
- `docs/02-protocols/06-rpc-dcerpc-ms-drsr.md` — DCE/RPC + DRSUAPI opnum table
- `docs/02-protocols/08-spn-upn-pac.md` — PAC buffer structure

---

## CRITICAL CONSTRAINTS

1. **Rust only.** No C, no Python, no Go for framework code. FFI bindings (C ABI, JNI, Swift, pyo3) are the only exception.
2. **`#![forbid(unsafe_code)]`** in every crate. No `unsafe` blocks.
3. **Async runtime**: `tokio` (rt-multi-thread). No async-std, no smol.
4. **Error handling**: `thiserror` for library errors, `anyhow` for application-level.
5. **License**: MIT. No GPLv3 contamination (this is why we're NOT using Samba's DRSUAPI code — fresh Rust implementation required).
6. **MS-KILE conformance**: PAC must be byte-identical to Windows Server 2022. Validate with `adrian-kdc-interop`.
7. **Security**: RC4 disabled by default. NTLM server-side dropped. HSM-bound krbtgt. Sigstore-signed releases.
8. **AD-interop by default**: The `ad-interop` feature flag is ON by default. DRSUAPI + MS-WCCE + NTLM client + ADMX compiler are all enabled.
9. **Commits**: One commit per sub-task. Push after each wave. Commit messages follow `Wave N: <description> (T-NNN, +M tests)` format.
10. **Tests**: Every new function gets a unit test. Every protocol handler gets a round-trip test. Target ≥ 578 tests by end of Wave 5.

---

## KNOWN ISSUES FROM PREDECESSOR

1. **Disk pressure**: The `target/` directory grows to 7+ GB. Run `cargo clean` between waves if the sandbox fills.
2. **Sub-agent timeouts**: Sub-agents may time out at ~10 minutes but often complete the work first. Always check `git log` and file state before re-dispatching.
3. **FDB build dependency**: `adrian-storage-fdb` real backend requires `libclang-dev` for `foundationdb-sys` bindgen. Install via `apt-get install -y libclang-dev clang` (requires sudo — if no sudo, use the `fdb` feature flag gated approach already in the Cargo.toml).
4. **Parallel agent conflicts**: When 3+ agents work in the same repo simultaneously, `git add` may stage files from other agents. Use `git add <specific-files>` not `git add .`.
5. **Worklog**: `/home/z/my-project/worklog.md` is the shared worklog. Read it before starting; append after each wave.
6. **GitHub PAT**: The predecessor token was shared in plaintext in prior sessions. Generate a fresh token at https://github.com/settings/tokens and pass it via the `ADRIAN_GH_TOKEN` environment variable. **Never commit tokens to the repo** — GitHub Push Protection will block the push.

---

## SUCCESS CRITERIA (Phase 1 MVP — from TASKS.md)

The MVP is done when ALL of these pass:

- [ ] A Linux host can join the framework as a member (`adrian-cli join`)
- [ ] The host authenticates via Kerberos (AS-REQ/TGS-REQ against framework KDC)
- [ ] The host applies policy via `authselect` (declarative JSON → authselect profile)
- [ ] The host requests a cert via ACME (`adrian-cli cert enroll`)
- [ ] The host mounts an SMB share (`adrian-cli file mount`)
- [ ] All of the above works against both a framework DC and a Windows Server 2022 DC in mixed mode
- [ ] PAC byte-identity validated against Windows Server 2022 in `adrian-kdc-interop`
- [ ] Performance targets met: 5K AS-REQ/sec/KDC, 10K writes/sec/DC, <5s replication lag
- [ ] Security mitigations active: RC4 refused, krbtgt HSM-bound, DCSync audited
- [ ] `cargo test --workspace` shows 578+ passed, 0 failed
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] `cargo fmt --all --check` clean

---

## ORCHESTRATOR RETURN CONDITION

The orchestrator (you) is permitted to return only when ALL of the following are true:

1. All 6 waves complete with DoD passing
2. `cargo test --workspace` shows ≥ 578 passed, 0 failed
3. `cargo check --workspace` passes
4. `cargo clippy --workspace -- -D warnings` passes
5. `cargo fmt --all --check` passes
6. Local HEAD = remote HEAD on `main` branch
7. CHANGELOG.md updated to v0.5.0
8. TASKS.md updated with T-001 to T-031 marked `[x]`
9. `HANDOVER_STATE.md` committed documenting final state

**Go.**
