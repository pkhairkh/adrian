---
title: Architecture Overview — Adrian Framework
audience: architects-and-engineers
tags: [final-draft, architecture, adrian, rust, crates, fdb, replication, kdc, sdk, kubernetes, observability]
related:
  - ./README.md
  - ./01-executive-summary.md
  - ../adr/README.md
  - ../workshop/CONTEXT.md
last_updated: 2026-08-14
---

# Architecture Overview — Adrian Framework

## Architecture principles

The Adrian framework is built on seven principles, each of which is enforced by at least one ADR and reflected in the crate graph below.

1. **Memory safety via Rust.** Every framework crate is Rust. The only `unsafe` blocks in the framework are in `foundationdb-sys` (wrapping `libfdb_c.so`) and `cryptoki-sys` (wrapping `libpkcs11.so`); both expose safe Rust APIs at the next layer up. No GPL code is linked, shipped, or distributed; Samba (GPLv3), Heimdal (Samba's fork is GPLv3), MIT krb5 (rejected for embedding reasons in Decision 5), and FreeIPA's `ipa_kdb_mspac.c` (GPLv3) are explicitly excluded. This principle is the basis for Decision 5 (fresh Rust KDC, not MIT) and Decision 10 (fresh Rust SMB server, not Samba), and is cited by every ADR that rejects a C-based alternative.

2. **AD-interop by default.** Every wire protocol the framework speaks is byte-compatible with a real Windows Server 2022+ forest. DRSUAPI replication (ADR-070) speaks MS-DRSR §4 with `DRSGetNCChanges` opnum 3 and `EXOP_REPL_SECRETS`; the KDC (ADR-082) emits PACs byte-identical to Windows; the SMB server (ADR-105) negotiates SMB 3.1.1 with SHA-512 preauth integrity; the MS-WCCE bridge (ADR-095) accepts `autoenroll.dll` traffic; the federation shim (ADR-101) accepts AD FS claim-rule language. Greenfield native-mode deployments exist as a *mode* of the same framework, not a separate product; the same FDB representation, the same `DirectoryStore` trait, the same KDC, the same SDK — only the replication protocol (DRSUAPI vs. Raft per Decision 1) and the policy distribution path (SYSVOL via SMB vs. Git-backed per ADR-094) differ.

3. **Cross-platform parity.** The same framework runs as a DC on Windows, macOS, and Linux; the same Client SDK runs on all three platforms plus Android and iOS. The crate graph (below) has zero platform-conditional compilation in the core; platform-specific code is isolated to binding crates (`adrian-sdk-c`, `adrian-sdk-java`, `adrian-sdk-swift`, `adrian-sdk-python`, `adrian-sdk-go`) and to platform-LSA integration crates (`adrian-lsa-windows`, `adrian-opendirectory-macos`, `adrian-pam-linux`).

4. **Modern crypto only.** AES-256-CTS-HMAC-SHA1-96 (etype 0x12) is the Kerberos default (ADR-011); AES-256-CTS-HMAC-SHA384-192 (etype 0x13) is preferred when both endpoints support it (ADR-014); RC4-HMAC (etype 0x17) is audit-then-enforce; DES is unconditionally disabled. SMB 3.1.1 mandates AES-256-GCM encryption with SHA-512 preauth integrity (ADR-105). LDAP signing + TLS channel binding (RFC 5929) + EPA are mandatory by default (ADR-021). NTLMv1 is unconditionally disabled; NTLMv2 is supported only as a client-side initiator (Decision 6).

5. **Container-native operations.** DCs are StatefulSet pods, not VMs (ADR-058). The framework ships a Kubernetes operator (`adrian-operator`) that manages DC lifecycle, FDB cluster lifecycle (Decision 2), backup/PITR (ADR-059), and policy distribution. Helm charts are the primary deployment artifact; the framework's reference deployment is a single Helm chart that installs the operator, the FDB cluster, the DC StatefulSet, the KDC pool, the SMB server, the federation gateway, and the cert service.

6. **Observable by design.** Every crate emits OpenTelemetry traces, metrics, and structured logs via the `tracing`/`tracing-opentelemetry` crates (ADR-057, ADR-060, ADR-023). The framework ships a Prometheus exporter (`adrian-monitor`) and a pre-built Grafana dashboard. Audit events are structured OTel log records with MITRE ATT&CK technique IDs in the `threat.tactic` and `threat.technique` attributes (ADR-060). The KDC emits an OTel log event for every AS-REQ/TGS-REQ/pre-auth-failure/TGT-renewal/old-key-TGT-usage (ADR-023).

7. **GitOps-friendly.** Schema is GitOps-managed (ADR-119, with reverse-LDIF synthetic rollback); policy is Git-backed with PR review (ADR-031); cert profiles are declarative YAML in Git (ADR-096); replication topology is declarative YAML (ADR-008); the framework's configuration is a single `adrian.toml` checked into the customer's GitOps repo. The operator reconciles Git state to cluster state; `adrian-cli` provides `plan`/`apply`/`rollback` commands that map 1:1 to Git operations.

## The 12 capabilities and their Rust crates

Each capability maps to one or more Rust crates in the `adrian/` workspace. The crate naming convention is `adrian-<capability>-<subsystem>`; the workspace is a single Cargo workspace with ~40 crates at v1 maturity.

| # | Capability | Primary Rust crate(s) | Cited ADRs |
|---|-----------|------------------------|------------|
| 1 | Core Directory | `adrian-storage-core` (trait), `adrian-storage-fdb` (FDB impl), `adrian-repl-core` (trait), `adrian-drsuapi` (AD-interop), `adrian-raft` (native mode, wraps `openraft`), `adrian-directory-service` (LDAP server + DSA), `adrian-sid`, `adrian-identity-core`, `adrian-identity-fdb`, `adrian-schema-compiler`, `adrian-schema-traits`, `adrian-dcerpc` (shared DCE/RPC stack) | ADR-001..010, ADR-070..081, ADR-119..121 |
| 2 | KDC | `adrian-kdc` (AS-REQ/TGS-REQ/PAC/etype/HSM/kpasswd/audit), `adrian-kdc-interop` (MIT/Heimdal/Windows conformance tests) | ADR-011..020, ADR-082..084, ADR-087 |
| 3 | Auth Provider | `adrian-ntlm-client` (NTLMv2 client-only, no acceptor), `adrian-auth-core` (token abstraction, channel binding) | ADR-021, ADR-022, ADR-023, ADR-085, ADR-086, ADR-088 |
| 4 | Policy Engine | `adrian-policy-core` (canonical JSON, validation, CEL/Rego selector), `adrian-policy-executor` (public Rust trait + inventory registration), `adrian-admx-compiler` (`admx2adrian` binary), `adrian-policy-distribution` (PReg adapter, synthetic Windows CSE glue, macOS MDM payload compiler, Linux config-fragment compiler), `adrian-policy-daemon` (per-host evaluation, 60s cache) | ADR-024..031, ADR-089..094 |
| 5 | Cert Service | `adrian-ca` (CA core, two-tier, HSM-bound root), `adrian-acme-server` (RFC 8555 + RFC 8737 + RFC 8823 ARI), `adrian-wcce-bridge` (MS-WCCE/MS-XCEP/MS-WSTEP), `adrian-est-bridge` (RFC 7030), `adrian-scep-bridge` (RFC 8894), `adrian-ocsp` (RFC 6960, HA cluster), `adrian-kra` (HSM-bound KRA with Shamir M-of-N) | ADR-032..037, ADR-095..099 |
| 6 | Federation Gateway | `adrian-federation-shim` (Rust sidecar: AD FS claim-rule engine, trust-pipeline integration, WS-Trust bridge), `adrian-keycloak-config` (Keycloak realm config generator) | ADR-038..042, ADR-100..104 |
| 7 | File Gateway | `adrian-smb-server` (SMB 2.0.2–3.1.1 server, fresh Rust, no Samba), `adrian-smb-client` (SDK FileModule), `adrian-print-service` (IPP Everywhere, no MS-RPRN), `adrian-dfs-n` (DNS SRV-based) | ADR-043..047, ADR-105, ADR-106, ADR-130 |
| 8 | Client SDK | `adrian-sdk` (Rust core), `adrian-sdk-c` (C ABI + `cbindgen`), `adrian-sdk-java` (JNI + JAR + Kotlin), `adrian-sdk-swift` (Swift bridge), `adrian-sdk-python` (pyo3 + Ansible collection), `adrian-sdk-go` (cgo + Terraform provider), `adrian-cli` (unified CLI), `adrian-lsa-windows`, `adrian-opendirectory-macos`, `adrian-pam-linux` | ADR-048..056, ADR-063, ADR-107..113, ADR-118 |
| 9 | Cross-Platform Parity | (cross-cutting; the per-platform crates above are the parity surface) | ADR-052..056, ADR-114..118, ADR-121 |
| 10 | Operations | `adrian-operator` (Kubernetes operator, manages DC + FDB lifecycle), `adrian-cli` (unified CLI), `adrian-monitor` (Prometheus exporter + OTel collector config), `adrian-backup` (FDB backup agent wrapper), `adrian-restore` (FDB `fastrestore` wrapper + DR runbook executor) | ADR-057..063, ADR-119..121 |
| 11 | Security | (cross-cutting; no separate crate. Security controls live in each capability: HSM-bound krbtgt in `adrian-kdc`, PAC_BUFFER_TICKET_CHECKSUM in `adrian-kdc`, SID filtering in `adrian-drsuapi` and `adrian-kdc` and `adrian-smb-server`, Kerberoasting detection in `adrian-kdc` audit, Sigstore signing in the build pipeline per ADR-067) | ADR-064..067, ADR-122..125 |
| 12 | Migration | `adrian-migrate` (umbrella binary: `from-ad`, `from-adfs`, `from-{winbind,pbis}`), `adrian-gpo-translate` (GPO → JSON policy), `adrian-sidhistory` (DRSAddSidHistory opnum 20 wrapper), `adrian-crossrealm-migrate` (Kerberos cross-realm migration), `adrian-pwhash-migrate` (password hash migration) | ADR-068, ADR-069, ADR-126..130 |

The crate count at v1 maturity is approximately **40 crates** (15 in Core Directory, 2 in KDC, 2 in Auth, 5 in Policy, 7 in Cert, 2 in Federation, 4 in File, 10 in Client SDK, 5 in Operations, 5 in Migration). The workspace uses a single `Cargo.toml` at the root with all crates as path dependencies; release builds produce a single Docker image per DC, KDC, SMB, Federation, Cert, and Operator role.

## Dependency graph

The crate dependency DAG (simplified; cross-cutting `tracing`, `tokio`, `serde`, `uuid`, `foundationdb`, `cryptoki` dependencies omitted):

```
                          adrian-storage-core  (trait)
                                   │
                          adrian-storage-fdb   (FDB impl)
                                   │
              ┌────────────────────┼─────────────────────┐
              │                    │                     │
       adrian-identity-fdb   adrian-repl-core   adrian-schema-compiler
              │                    │                     │
       adrian-identity-core  ┌─────┴─────┐       adrian-schema-traits
              │              │           │              │
              │       adrian-drsuapi  adrian-raft       │
              │              │           │              │
              │              └─────┬─────┘              │
              │                    │                    │
              │           adrian-directory-service      │
              │                    │                    │
              │              adrian-dcerpc              │
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
                          adrian-kdc  ──────► adrian-kdc-interop
                                   │
                          adrian-auth-core
                                   │
              ┌────────────────────┼─────────────────────┐
              │                    │                     │
       adrian-ntlm-client   adrian-policy-core    adrian-ca
                                   │              │
                          adrian-policy-executor  ├─► adrian-acme-server
                                   │              ├─► adrian-wcce-bridge
                          adrian-admx-compiler    ├─► adrian-est-bridge
                                   │              ├─► adrian-scep-bridge
                          adrian-policy-distribution ├─► adrian-ocsp
                                   │              └─► adrian-kra
                          adrian-policy-daemon
                                   │
                          adrian-smb-server  ────► adrian-smb-client
                                   │
                          adrian-dfs-n  ────────► adrian-print-service
                                   │
                          adrian-federation-shim  ──► (Keycloak JVM)
                                   │
                          adrian-sdk  ───────────► adrian-cli
                                   │
              ┌─────────┬──────────┼──────────┬─────────────┐
              │         │          │          │             │
       adrian-sdk-c  adrian-sdk-java  adrian-sdk-swift  adrian-sdk-python  adrian-sdk-go
                                   │
                          adrian-operator  ──► adrian-monitor
                                   │
                          adrian-backup  ──► adrian-restore
                                   │
                          adrian-migrate  ──► adrian-gpo-translate
                                   │                │
                                                   ▼
                                           adrian-sidhistory
                                           adrian-crossrealm-migrate
                                           adrian-pwhash-migrate
```

Key DAG properties: (1) `adrian-storage-core` is the root; every other crate depends (transitively) on it. (2) `adrian-dcerpc` is the shared DCE/RPC stack used by `adrian-drsuapi`, `adrian-wcce-bridge`, and (for AD-interop) `adrian-smb-server` (SPNEGO over DCE/RPC for some legacy auth); the DCE/RPC investment is amortised across 3+ protocols. (3) `adrian-sdk` depends on `adrian-kdc` (for Kerberos client), `adrian-auth-core` (for NTLM client), `adrian-directory-service` (for LDAP client), `adrian-policy-daemon` (for policy application), `adrian-ca` (for ACME client), `adrian-smb-client` (for SYSVOL access), and `adrian-federation-shim`'s public API (for token validation). (4) The migration crates depend on the source-format parsers (independent of the framework's own storage layer) and the target-format emulators (which depend on the framework's storage layer).

## Storage layer

FoundationDB 7.3.x is the sole storage engine for all DCs in v1 (Decision 2, ADR-073). Every DC — AD-interop or native, 100-DC enterprise forest or single-DC edge — runs against an FDB cluster. For multi-DC deployments, the DC process connects to a shared FDB cluster (3–9 storage processes for mid-size forests, 15+ for large); for single-DC edge deployments, a single-process FDB cluster runs co-located. FDB is a Tier-0 operational dependency managed by the framework's operator (ADR-058).

The directory's logical model — objects with attributes, link-value pairs (ADR-001), security descriptors with dedup (ADR-004), schema cache with copy-on-write generations (ADR-003) — is mapped onto FDB's ordered KV store via the tuple-layer key encoding: `(subspace, object_dnt, attribute_id, value_index) → value_bytes`. The subspaces are: `0x01` objects, `0x02` linktable, `0x03` sdtable, `0x04` schemacache, `0x05` utdvector, `0x06` ridpool, `0x07` tombstones, `0x08` auditlog, `0x09` dnszone, `0x0A` quota, `0x0B` secretcache, `0x0C` replmetadata, `0x0D` identitymapping (per Decision 3, the bidirectional UUID↔SID mapping table). The `sdtable` (per ADR-004) uses BLAKE3-256 as the dedup hash with key `(0x03, sdHash[0..32]) → (sdID, sdrefcount, sdBytes)`; FDB range scans on the `0x03` subspace support periodic GC of zero-refcount SDs. The linktable (per ADR-001) uses `(0x02, linkDNT, linkID, backlinkDNT) → (fIsPresent, originInvocationID, originUSN, version, lastWriteTimestamp)` with a reverse index `(0x02, backlinkDNT, linkID, linkDNT) → fIsPresent` maintained atomically in the same transaction as the forward-link write — `memberOf` queries are O(group membership count), not O(database size).

FDB's strict serializable transactions make every directory operation atomic: a single LDAP modify that adds a `member` value, updates the back-link, increments the group's `USNChanged`, and updates the UTD vector is one FDB transaction that commits atomically or rolls back atomically. There is no replication-apply lock, no last-writer-wins ambiguity at the storage layer, and no window where the forward-link is written but the back-link is not. Performance targets (per Decision 2 §Concrete-specification): a single FDB storage process sustains ≥15K writes/sec/DC and ≥50K reads/sec/DC; a 9-process FDB cluster sustains ≥100K writes/sec aggregate and ≥500K reads/sec aggregate; backup of a 10M-object directory completes in <30 minutes via FDB `backup_agent` to S3; restore via `fastrestore` completes in <2 hours; PITR to a 24-hour-old restore point completes in <1 hour. The `DirectoryStore` trait abstraction exists (so the framework's core directory code is engine-agnostic), but only one implementation — `FdbDirectoryStore` — ships in v1; a future v2 `RocksdbDirectoryStore` is deferred for air-gapped edge deployments where a 3-node FDB cluster is infeasible.

## Replication layer

The replication layer is **hybrid** (Decision 1, ADR-070, ADR-071): a fresh Rust DRSUAPI server (`adrian-drsuapi` crate, ~12K lines) for AD-interop mode, and `openraft` (the `openraft` Rust crate, MIT/Apache-2.0) for native mode, behind a shared async `Replicator` trait. The same on-disk FDB representation supports both modes — the choice of mode is per-forest, set at forest creation time, and cannot be mixed within a forest. AD-interop mode is required for any forest that needs to peer-replicate with an existing AD forest; native mode is for greenfield deployments that do not need AD-interop.

The `Replicator` trait (`async fn replicate(...) -> Result<ReplicationStats, ReplError>`, `Send + Sync`) has two implementations: `DrSuapiReplicator` (which speaks MS-DRSR §4 wire protocol with `DRSGetNCChanges` opnum 3, `EXOP_REPL_SECRETS` opnum 0x0E, `DRSAddEntry` opnum 0x0D, LZ-Express compression per MS-XCA, NDR encoding via the `rasn` crate, full `DRS_EXTENSIONS_INT` capability negotiation) and `RaftReplicator` (which uses `openraft` with a single Raft group in v1, multi-group sharding deferred to v2). Both implementations preserve `PROPERTY_META_DATA_EXT` verbatim (origin DSA InvocationID, origin USN, version, last-write timestamp) — this is the metadata that makes AD replication idempotent and protects against USN rollback (ADR-074). The UTD vector is the primary replication cursor in both modes; in Raft mode, the UTD vector is synthesised from the Raft log for diagnostic visibility (so `repadmin /showutdvec` works against a native-mode forest). USN rollback self-quarantine is enforced in both modes (ADR-074).

The DCE/RPC transport layer is shared between `adrian-drsuapi`, the future SAMR/LSARPC/Netlogon implementations (required for full AD-interop), and the MS-WCCE bridge (Decision 8). This amortises the DCE/RPC investment across 4 protocols. The fresh DRSUAPI server implementation is ~9.5 person-months (per Decision 1's breakdown), including the DCE/RPC transport, the IDL, the wire-format byte-compatibility test suite, and `EXOP_REPL_SECRETS`. The openraft integration is ~3 person-months (the `openraft` integration, the `RaftLogEntry` payload design, the UTD-vector synthesis). The shared `Replicator` trait and on-disk representation is ~2 person-months. The fresh DRSUAPI implementation is the second-largest engineering investment in the framework after the KDC; it is the price of AD-interop without GPLv3 contamination. The hybrid cost (~14 person-months total) is accepted because serving both customer profiles is a v1 requirement, and a v2 "we added the second protocol later" would require a forest-level migration.

FSMO roles (ADR-076) are **eliminated in native mode**: Schema Master is replaced by FDB optimistic concurrency control on the schema generation counter; Domain Naming Master is replaced by FDB atomic transactions on the domain-naming namespace; PDC Emulator is replaced by the Raft leader + chrony NTP + urgent-replication for password changes; RID Master is replaced by per-DC local RID allocation (no RID-pool bottleneck per Decision 3); Infrastructure Master is eliminated entirely by the bidirectional UUID↔SID mapping table (Decision 3 — there are no "phantom" objects requiring cross-reference resolution). In AD-interop mode, all 5 FSMO roles are **emulated** for AD-tool compatibility (`netdom`, `ntdsutil`, `repadmin /seize` work as expected against a framework DC), but the framework's internal operation does not depend on any single-master role.

## Identity layer

Every security principal (user, computer, group, service account, gMSA, trust identity) has a **UUIDv7 as its internal primary key** and a **SID as a first-class attribute** (Decision 3, ADR-110). The UUID is the primary key in every internal index, every foreign-key reference, every audit log entry, and every replication operation. The SID is the wire-format currency for AD-interop scenarios (LDAP `objectSid`, Kerberos PAC `GroupIds`/`ExtraSids`, SACL/DACL ACE `Trustee`, sIDHistory migration, cross-trust access). UUIDv7 (RFC 9562, September 2024) is chosen over UUIDv4 because its time-ordered first 48 bits give index locality in FDB (improving range-scan performance for time-windowed queries like audit logs and recently-created-principal listings) and natural sort order (UUIDv7 lexical sort matches chronological order, simplifying `ORDER BY createdAt`). UUIDv4 remains supported for imported principals (AD principals migrated via sIDHistory that already have a UUIDv4 `objectGUID` — the framework preserves the AD-assigned `objectGUID` rather than re-issuing a UUIDv7).

A first-class **bidirectional mapping table** in FDB subspace `0x0D` provides O(1) lookup in both directions: forward `(0x0D, 0x01, uuid[0..16]) → (sid_bytes, sid_history_bytes, principal_type, tombstoned_at)` and reverse `(0x0D, 0x02, sid_bytes) → (uuid[0..16], tombstoned_at)`. Every principal-creation operation writes the mapping row in the same FDB transaction as the principal object; every principal-deletion operation tombstones the mapping row in the same transaction as the principal tombstone; every sIDHistory-add operation (during migration) writes the additional `sid_history` entries atomically. FDB's strict serializable transactions enforce the invariant: there is never a window where a principal exists without a mapping row, and there is never a window where a SID is mapped to two UUIDs. The mapping table is cached in-memory on each DC (LRU cache, default 100K entries, configurable) with cache invalidation via FDB watches on the mapping-row keys; a 99%+ cache hit rate is expected for typical deployments, keeping lookup cost at <100µs per call.

The `adrian-sid` crate (fresh Rust, ~800 lines, MIT/Apache-2.0, pure Rust with no FFI) parses and emits the MS-DTYP §2.4.2 SID binary format and provides `Sid`, `SidDomain`, `SidRid` types with `Display`/`FromStr` for the SDDL string form, `AsRef<[u8]>` for the binary form, and `Hash`/`Eq`/`Ord` for use as FDB tuple-layer keys. The crate is independent of the `windows` crate (which is Windows-focused and pulls in a ~50MB dependency tree). The RID-pool allocator (AD-interop mode only) dispenses RID ranges in 500-RID batches (matching AD's `RIDAllocationPoolSize`), with state stored in FDB subspace `0x06` and `next_rid` using FDB's atomic-add operation for lock-free allocation. For native mode, RID allocation is local per-DC (no RID-master DC); each DC maintains its own RID counter at `(0x06, local_dc_id, domain_sid) → next_rid`. The SID format is identical in both modes; only the provisioning mechanism differs. POSIX UID/GID mapping uses the mapping table (PC-089) with the framework's default algorithmic mapping `uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536`, eliminating the SID→UID collision problems that AD/Samba's algorithm has.

## KDC

The KDC is a **fresh Rust implementation** in `adrian-kdc` (~30K lines at v1 maturity), MS-KILE-conformant, RFC 4120-conformant, and wire-compatible with MIT krb5 1.21+, Heimdal 7.x+, and Windows Server 2022+ (Decision 5, ADR-082). The KDC is the **second-largest engineering investment** in the framework (~42 person-weeks for full v1, ~24 person-weeks for v1 MVP preview) and the **long pole on the critical path**: the preview blocks Phase 2 MVP signoff, the full KDC blocks Phase 3 GA. The decision overrides Spike 3's recommendation (Option B, MIT krb5 + custom PAC plugin) on five grounds: license posture (FreeIPA's `ipa_kdb_mspac.c` is GPLv3), memory-safety story (MIT krb5 has 60+ CVEs since 2014, ~30 memory-safety bugs), embedding cost (MIT's `krb5kdc` is a single-process-per-host daemon incompatible with the framework's `tokio` runtime), PAC defect surface (extending `ipa_kdb_mspac.c` to all principals is a 5K-line C extension on the highest-risk code path), and unified operations story (a Rust KDC integrates natively with `tracing`/OpenTelemetry).

The KDC produces PACs byte-identical to Windows Server 2022+ for the same principal at the same replication point-in-time (ADR-082). The full PAC buffer set per MS-KILE: `PAC_LOGON_INFO` (0x01, NDR-encoded `KERB_VALIDATION_INFO`), `PAC_CREDENTIAL_TYPE` (0x02), `PAC_SERVER_CHECKSUM` (0x06), `PAC_PRIVSVR_CHECKSUM` (0x07), `PAC_CLIENT_INFO_TYPE` (0x0A), `PAC_UPN_DNS_INFO` (0x0C), `PAC_BUFFER_TICKET_CHECKSUM` (0x0E, Server 2012+, default-on per ADR-082/ADR-123 for silver-ticket mitigation), `PAC_REQUESTOR` (0x12, Server 2019+), `PAC_FULL_CHECKSUM` (0x13, Server 2016+). The PAC builder is deterministic across KDC instances (per ADR-018): the same principal at the same replication point-in-time produces byte-identical PACs on any KDC instance, which is the precondition for the KDC to be a horizontally-scalable stateless pool. The krbtgt key is HSM-bound (ADR-015, ADR-065) — all krbtgt-key cryptographic operations (TGT signing, TGT validation, `PAC_PRIVSVR_CHECKSUM`) go through the HSM via the `cryptoki` Rust crate (PKCS#11 v3.0); the KDC never holds the krbtgt key in process memory in plaintext. Krbtgt rotation is one-click with 30-day auto-rotation and 2-key overlap (per ADR-015); old-key TGT usage is audit-logged (per ADR-023) and alerted on (per ADR-060's MITRE ATT&CK mapping).

The KDC supports FAST-required mode by default (ADR-012, RFC 6806); `fast_mode = "supported"` / `"audit"` / `"grace"` modes available for migration. Anonymous PKINIT armor TGT (RFC 6112) is supported; full PKINIT (PC-027) is deferred to ORQ-110/111 but the protocol path is stubbed in v1, with PKINIT/FIDO2/WebAuthn bridge specified in ADR-084. Etype negotiation (RFC 4120 §3.1.3 + RFC 8009): AES-256-CTS-HMAC-SHA1-96 (etype 0x12) default (ADR-011); AES-256-CTS-HMAC-SHA384-192 (etype 0x13) preferred when both endpoints support (ADR-014); RC4-HMAC (etype 0x17) audit-then-enforce (ADR-011); DES unconditionally disabled. Cross-realm TGT referral per RFC 4120 §3.3.3 (ADR-013) with `Transited` field validation in per-trust modes `"strict"` (default for cross-forest), `"disabled"` (default for intra-forest), `"shortcut-aware"`. S4U2Self/S4U2Proxy constrained delegation per MS-SFU (ADR-087), preserving AD-interop for mixed forests and the constrained-delegation primitive for new framework-native services (Decision 6). The KDC scales to ≥5K AS-REQ/sec per instance; a 10-instance pool handles ≥50K AS-REQ/sec (ADR-018).

## Client SDK architecture

The Client SDK is a **unified Rust core library** (`adrian-sdk`) with platform-specific bindings (Decision 11, ADR-107). The core handles authentication (Kerberos via the framework KDC, NTLM fallback per Decision 6 — client-only), directory (LDAP queries, attribute reads via the typed schema projection from Decision 4), policy (load, evaluate, apply, rollback per Decision 7), cert enrollment (ACME per Decision 8), file (SMB client for SYSVOL access per ADR-106), and federation (token validation, refresh). The core uses `tokio = "1"` for async I/O; the public API exposes both `async` methods (for Rust consumers) and blocking methods (for FFI consumers, which typically cannot run a `tokio` runtime — the blocking methods internally use `tokio::runtime::Runtime::block_on`). The Rust core is distributed as a Rust crate (`adrian-sdk = "1.0"` on crates.io for Linux/macOS Rust consumers) and as pre-built static/dynamic libraries for FFI consumers.

Platform bindings: **C ABI** (`adrian-sdk-c`, using `cbindgen` to generate `adrian.h` and producing `libadrian_sdk.a/.so/.dylib/.dll`) — opaque pointers, `int32_t` error codes, `const char*` strings (UTF-8, NUL-terminated, owned by the library); this is the foundation for all other bindings. **JNI** (`adrian-sdk-java`, JAR + native library) — Java/Kotlin classes with native methods, thin wrapper over the C ABI, Kotlin `suspend` functions for async methods for Android. **Swift bridge** (`adrian-sdk-swift`, using `swift-bridge`) — Swift Package with `.swift` and `.rs` source pairs, native Swift types, async via Swift's `async/await`. **Python** (`adrian-sdk-python`, using `pyo3`) — Python wheel with native extension module, plus an Ansible collection that wraps the Python API. **Go** (`adrian-sdk-go`, using `cgo`) — Go package plus a Terraform provider. Each binding is a thin FFI wrapper; the Rust core is the single source of truth for behaviour.

The SDK integrates with platform-native auth stacks: on Windows, an LSA Authentication Package (`adrian-lsa-windows`, 4 person-weeks per Decision 11, the critical-path item — LSA bugs can prevent Windows logon) integrates the Rust core with the Windows logon flow; on macOS, an OpenDirectory plugin (`adrian-opendirectory-macos`) integrates with the Authorization framework and the PSSO Extension (ADR-056); on Linux, a PAM/NSS provider (`adrian-pam-linux`) integrates with `authselect` (ADR-050) and SSSD's `infopipe` (per Decision 12 — SSSD-primary Linux tier). The SDK is **additive**: it does not replace SSPI on Windows, OpenDirectory on macOS, or SSSD on Linux — it coexists and augments. The unified ticket-cache abstraction (ADR-111) hides platform-specific cache types (LSA in-memory on Windows, keychain `API:` on macOS, `KEYRING:persistent:<uid>` or KCM on Linux) behind a single `TicketCache` Rust trait. The SSPI-equivalent auth abstraction (ADR-108) provides a single `AuthContext` Rust trait that wraps Kerberos and NTLM under the same API, so Windows applications porting from SSPI have a familiar `InitializeSecurityContext`/`AcceptSecurityContext`-style API.

## Deployment model

The framework is **Kubernetes-native** (ADR-058). DCs are StatefulSet pods (not VMs); the framework ships a Kubernetes operator (`adrian-operator`) that manages DC lifecycle, FDB cluster lifecycle (Decision 2), backup/PITR (ADR-059), and policy distribution. The reference deployment is a single Helm chart that installs the operator, the FDB cluster, the DC StatefulSet, the KDC pool (a separate Deployment with horizontal pod autoscaling on AS-REQ/sec), the SMB server (a StatefulSet with persistent volumes for shares), the federation gateway (a StatefulSet for Keycloak + a Deployment for the Rust shim sidecar), the cert service (a Deployment for the CA + a Deployment for the ACME server + a Deployment for the OCSP responder + a Deployment for the MS-WCCE bridge), and the operator itself.

Container images are distroless (gcr.io/distroless/cc-debian12 base); each role (DC, KDC, SMB, Fed, Cert, Operator) is a separate image built from the same workspace with different `--bin` flags. Images are signed with Sigstore (`cosign sign`) and attested with in-toto (`in-toto-attest`) per ADR-067; the framework's CI runs SLSA Level 3 build provenance. The `adrian-base-container` image (per Decision 12) provides the base Linux image with the framework's CA trust, Kerberos configuration, and SSSD pre-installed; customer workloads that need framework integration derive from this image. Multi-architecture images (amd64, arm64) are built for both x86_64 server hardware and Apple Silicon / Ampere / AWS Graviton; the framework's compile-time detection of platform features (`target_arch`, `target_os`) is limited to the binding crates and the LSA/OpenDirectory/PAM integration crates.

For air-gapped or non-Kubernetes deployments, the framework ships a `systemd`-based deployment that runs each role as a `systemd` service on a single host or across a small fleet. The `adrian-cli` deployment command (`adrian-cli deploy --mode systemd --hosts <list>`) generates the `systemd` unit files, the FDB cluster configuration, and the framework's `adrian.toml` configuration file. This mode is supported for customers who cannot run Kubernetes (regulated industries with restrictive OS baselines, edge deployments with no Kubernetes cluster) but is not the primary deployment path.

## Observability

The framework is **observable by design** (ADR-057, ADR-060, ADR-023). Every crate emits OpenTelemetry traces (via `tracing`/`tracing-opentelemetry`), metrics (via `opentelemetry-prometheus`), and structured logs (via `tracing`/`tracing-subscriber` with JSON formatter). The framework ships a Prometheus exporter (`adrian-monitor`) that exposes the standard Prometheus `/metrics` endpoint with framework-specific metrics: `adrian_kdc_asreq_total{result,etype,fast}`, `adrian_kdc_tgsreq_total{result,spn}`, `adrian_ldap_modify_duration_seconds{op,attrs}`, `adrian_repl_lag_seconds{peer,nc}`, `adrian_fdb_transaction_duration_seconds{op}`, `adrian_smb_open_total{share,user}`, `adrian_acme_orders_total{result,template}`, `adrian_policy_apply_duration_seconds{area,host}`. The pre-built Grafana dashboard (shipped as a ConfigMap in the Helm chart) visualises these metrics with panels for KDC throughput, LDAP latency, replication lag, FDB cluster health, SMB share activity, ACME order rate, and policy apply latency.

Audit events are structured OTel log records with MITRE ATT&CK technique IDs in the `threat.tactic` and `threat.technique` attributes (ADR-060). The KDC emits an OTel log event for every AS-REQ, TGS-REQ, pre-auth failure, TGT renewal, old-key TGT usage, AS-REP-without-preauth, and RC4 TGS-REQ (ADR-023). Windows Event Log IDs 4768/4769/4771/4770 are emulated on Windows for SIEM compatibility. The audit log is stored in FDB subspace `0x08` (per Decision 2's subspace allocation) with a 180-day retention by default (matching AD's default `DefaultAuditingPolicy`); the audit log is replicated with the directory (in AD-interop mode) or via the Raft log (in native mode). The operator surfaces audit-log alerts via the standard alertmanager integration: golden-ticket detection (old-key TGT usage exceeding threshold), Kerberoasting detection (RC4 TGS-REQ for SPN with sensitive account), DCSync detection (DRSGetNCChanges with EXOP_REPL_SECRETS from non-DC account), sIDHistory injection detection (sIDHistory add on a non-migration-window principal). Each alert maps to a MITRE ATT&CK technique ID for downstream SIEM correlation.
