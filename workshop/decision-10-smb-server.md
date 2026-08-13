---
title: "Workshop Decision 10 — SMB server: fresh Rust SMB 3.1.1 server (resolves ORQ-154/155)"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: File Gateway
orqs_resolved: [ORQ-154, ORQ-155]
gates: [PC-078, PC-081, PC-130]
tags: [workshop, decision, file-gateway, smb, smb3, rust, async, memory-safe]
related:
  - ./CONTEXT.md
  - ../adr/TRIAGE.md
  - ../adr/ADR-043-drop-smb1-support.md
  - ../adr/ADR-044-dfs-n-via-dns-srv.md
  - ../adr/ADR-045-abe-precomputed-index.md
  - ../adr/ADR-058-container-native-dcs-operator.md
  - ../catalog/07-file-gateway.md
last_updated: 2026-08-14
---

# Workshop Decision 10 — SMB server: fresh Rust SMB 3.1.1 server

## Status

Accepted — 2026-08-14. Tier-1 (architectural) decision made at the Day 2 early-afternoon session of the Tier-1 ORQ Resolution Workshop. Resolves ORQ-154 (adopt Samba's `smbd`, GPL) and ORQ-155 (write fresh SMB server). Supersedes the open server-implementation question in [ADR-043](../adr/ADR-043-drop-smb1-support.md) (Drop SMB1 Support Entirely) by fixing the SMB server implementation choice.

## ORQs resolved

- **ORQ-154** — "Adopt Samba's smbd (GPL)?" → **No.** Samba is rejected for three independent reasons: (a) license conflict — Samba is GPLv3, the framework is Apache-2.0, and GPLv3's copyleft would force the framework's entire source tree to GPLv3 if Samba were statically linked or shipped as a single work; (b) embedding difficulty — Samba is C, designed as a monolithic daemon, with no stable embedding API, and the `smbd` process model (fork-per-connection historically, threads in modern Samba) is incompatible with the framework's async `tokio` runtime; (c) memory-safety posture — Samba has had 90+ CVEs since 2010 (per the Samba security advisory archive), most in the SMB1/SMB2 parsing layers, and the framework's security posture (memory-safe Rust) is incompatible with shipping a C SMB parser.
- **ORQ-155** — "Write fresh SMB server?" → **Yes.** A fresh Rust SMB 3.1.1 server, written from scratch, targeting SMB 3.1.1 only (per ADR-043's floor of SMB 2.0.2 negotiation and the framework's commitment to SMB 3.1.1 as the modern dialect). The implementation uses `pavao` (a Rust SMB client library) and the emerging `smb-rs` work as reference, but the framework's server is implemented from scratch because no mature Rust SMB server exists.

## Decision

The framework's File Gateway ships a **fresh Rust SMB 3.1.1 server** (`adrian-smb-server`) targeting only SMB 3.1.1 (with SMB 2.0.2 and 2.1 negotiation as the lower bound for client compatibility, but with SMB 3.0 and 3.0.2 and 3.1.1 as the recommended dialects). The server is async (`tokio`), memory-safe (Rust), and integrates with the framework's directory service for authentication and access control.

### Concrete specification

1. **Dialect support.** Per [ADR-043](../adr/ADR-043-drop-smb1-support.md), the server refuses SMB1 negotiation entirely. The server negotiates:
   - **SMB 2.0.2** (`0x0202`) — supported for legacy clients (Windows Server 2008, old Linux `cifs.ko`). No preauth integrity, no encryption, no persistent handles. Used only when the client offers no higher dialect.
   - **SMB 2.1** (`0x0210`) — supported for Windows 7 / Server 2008 R2 clients. Adds leasing, large MTU, multi-credit. No encryption.
   - **SMB 3.0** (`0x0300`) — supported for Windows 8 / Server 2012 clients. Adds encryption (AES-128-CCM), persistent handles, SMB Direct (RDMA, optional), multi-channel.
   - **SMB 3.0.2** (`0x0302`) — supported for Windows 8.1 / Server 2012 R2 clients. Adds AES-128-GCM signing.
   - **SMB 3.1.1** (`0x0311`) — the default and recommended dialect for Windows 10+ / Server 2016+ / macOS 11+ / Linux `cifs.ko` 4.x+ clients. Adds preauth integrity (SHA-512), encryption (AES-128-GCM or AES-256-GCM), and dialect negotiation downgrade protection.
   The server's Negotiate response lists all five dialects (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1) by default. Operators can restrict the dialect list via configuration (`smb.dialects.min = "3.0"`, `smb.dialects.max = "3.1.1"`) to enforce a higher security floor; the framework's default policy template (per Decision 7) sets `smb.dialects.min = "3.0"` for high-security deployments.

2. **Transport.** The server listens exclusively on TCP/445 (direct-hosted), per ADR-043. No NetBIOS-over-TCP (TCP/139, UDP/137/138). The server also supports (opt-in) SMB Direct (RDMA via InfiniBand or RoCE) using the `rust-rdma` crate family (`rdma-sr = "0.1"` if mature, otherwise hand-rolled `ibverbs` FFI). SMB Direct is disabled by default; it is enabled via `smb.direct.enabled = true` with a configured RDMA device.

3. **Authentication.** The server supports two authentication mechanisms:
   - **Kerberos (SPNEGO via GSSAPI)** — the preferred mechanism. The server uses the framework's MIT krb5 (per [ADR-049](../adr/ADR-049-standardize-mit-krb5.md)) for Kerberos acceptor logic. The server's service principal name (SPN) is `cifs/<host-fqdn>@<realm>`, registered automatically during host enrollment. The server validates the Kerberos ticket via the framework's KDC and extracts the client's identity (user SID-equivalent UUID, group SIDs) from the ticket's PAC (validated via the framework's unified PAC validator per ADR-049).
   - **NTLM (SPNEGO via NTLMSSP)** — supported only for clients that cannot use Kerberos (legacy appliances, workgroup clients). NTLM is disabled by default per the framework's NTLM decision (Day 2 afternoon); operators can enable it explicitly via `smb.auth.ntlm = "allowed"` for compatibility with stranded clients. When NTLM is enabled, the server enforces LDAP signing + channel binding (per [ADR-021](../adr/ADR-021-ldap-signing-channel-binding.md)) and NTLMv2 only (no LM, no NTLMv1).

4. **Authorization.** Access-Based Enumeration (ABE) is enforced per [ADR-045](../adr/ADR-045-abe-precomputed-index.md). The server consults the framework's precomputed ABE index for every directory enumeration call, filtering the result list to entries the client has `READ` access to. Share-level ACLs are stored in the framework's directory (per Decision 7's `FileGatewayShare` directory object); file-system ACLs are stored in the file system's extended attributes (`user.adrian.acl` for POSIX-backed shares, NTFS ACLs for Windows-backed shares).

5. **Share backends.** The server supports three share backends:
   - **POSIX filesystem** (default for Linux deployments) — files stored on a local filesystem (ext4, XFS, Btrfs). ACLs mapped from NTFS ACLs via a translation layer; POSIX `getfacl`/`setfacl` semantics for the underlying storage. File locking via `fcntl(F_SETLK)` + `flock(LOCK_EX)`; oplocks via the framework's oplock manager (in-process).
   - **NTFS** (Windows deployments) — files stored on a Windows NTFS volume. ACLs via Windows `GetFileSecurity`/`SetFileSecurity`. File locking via Windows `LockFileEx`; oplocks via `CreateFile(FILE_FLAG_OVERLAPPED)` + `DeviceIoControl(FSCTL_REQUEST_OPLOCK)`.
   - **Object store** (cloud deployments) — files stored in S3-compatible object storage (AWS S3, GCP GCS, MinIO). Each file is an object; each directory is a prefix. ACLs stored as object metadata. No file locking (object stores are not POSIX); the server returns `STATUS_SHARING_VIOLATION` for conflicting opens, falling back to a per-key distributed lock via Redis (optional). Object-store-backed shares do not support persistent handles, durable opens, or oplocks; clients detect the lack via the `FILE_PERSISTENT_HANDLES` capability flag and fall back to non-durable opens.

6. **Preauth integrity.** Per SMB 3.1.1, the server supports SHA-512 preauth integrity (the only algorithm defined in MS-SMB2 §3.2.5.1.1). The server selects SHA-512 in the Negotiate response's `NegotiateContextList` (context type `SMB2_PREAUTH_INTEGRITY_CAPABILITIES`, value `0x0001`). The server validates the preauth integrity hash on every subsequent packet in the session setup; mismatched hashes trigger `STATUS_ACCESS_DENIED` and session teardown.

7. **Encryption.** Per SMB 3.1.1, the server supports AES-128-GCM and AES-256-GCM encryption (the two algorithms defined in MS-SMB2 §3.1.4.3). The server selects AES-256-GCM by default (stronger cipher); operators can downgrade to AES-128-GCM via `smb.encryption.algorithm = "aes-128-gcm"` for performance on clients without AES-NI. Encryption is mandatory for SMB 3.1.1 sessions (the server's Negotiate response sets the `SMB2_GLOBAL_CAP_ENCRYPTION` flag and refuses unencrypted sessions at the 3.1.1 dialect); for SMB 3.0 and 3.0.2, encryption is optional per-share (the share's `encrypt = true|false` flag).

8. **Persistent handles and continuously available (CA) shares.** Per [PC-081](../catalog/07-file-gateway.md), the framework supports CA shares via persistent handles. The server implements persistent handles per MS-SMB2 §3.3.5.2.11 (SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 with `SMB2_DHANDLE_FLAG_PERSISTENT`). Persistent handles are stored in a shared handle table (etcd, Redis, or PostgreSQL) so that a client can reconnect to a different server in the cluster (per ADR-058 StatefulSet with multiple replicas) and resume the open. The handle table key is `(share_id, file_id, client_guid, persistent_id)`; the value is the open's state (current byte offset, oplock state, lease state, brl state). The handle table is replicated to all servers in the cluster; on server failover, the new server resolves the persistent handle from the table and resumes the open (re-opening the file at the OS level and replaying the saved state). CA shares require either a POSIX filesystem with a cluster-wide lock manager (e.g., GFS2, OCFS2) or the object-store backend (where "open" state is purely metadata). NTFS-backed shares do not support CA (NTFS is single-node).

9. **DFS-N (Distributed File System Namespaces).** Per [ADR-044](../adr/ADR-044-dfs-n-via-dns-srv.md), the framework implements DFS-N via DNS SRV records instead of the AD-LDAP-stored DFS namespace. The SMB server's `IOCTL_FSCTL_DFS_GET_REFERRALS` handler queries the framework's DNS server (via `trust-dns-resolver = "0.23"`) for `_<share-name>._dfs._tcp.<domain>` SRV records and returns them as DFS referral responses. This eliminates the AD-LDAP DFS namespace dependency and works cross-platform.

10. **SYSVOL-equivalent share.** The framework's SYSVOL-equivalent share (`\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\`) is served by the SMB server. The share is backed by the framework's Git-backed policy repository (per ADR-031) on the policy distribution host; the SMB server exposes the Git working tree as a read-only share. Writes are not permitted via SMB; policy updates go through the framework's Git workflow. Legacy Windows clients that expect to read `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Registry.pol` see the framework's PReg-emitted `Registry.pol` files (per Decision 7's PReg adapter); the framework's `gpsvc.dll`-equivalent synthetic CSE reads `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Adrian\policy.json` for non-Registry areas.

11. **Performance.** The server targets:
   - Single-connection throughput: ≥ 800 MB/s read, ≥ 600 MB/s write on a 10 GbE link with SMB Direct disabled, AES-256-GCM encryption enabled, against an NVMe-backed POSIX share.
   - Concurrent connections: ≥ 5,000 active sessions per server instance (tested with `smbtorture`'s `--num-ops=5000 --num-clients=5000`).
   - Latency: p99 ≤ 5 ms for `SMB2_CREATE`, `SMB2_READ`, `SMB2_WRITE` on a hot cache.
   The server uses `tokio`'s multi-threaded runtime with one task per connection; the SMB message dispatcher is a per-session state machine (no global lock). File I/O is `tokio-epoll-uring` on Linux 5.1+ (via `tokio-uring = "0.4"`), `IOCP` on Windows (via `tokio = "1"`'s IOCP backend), `kqueue` on macOS.

12. **Observability.** The server emits Prometheus metrics (`prometheus = "0.13"`): `adrian_smb_negotiated_dialect_total{dialect}`, `adrian_smb_session_total{auth_method}`, `adrian_smb_tree_connect_total{share,backend}`, `adrian_smb_create_total{result}`, `adrian_smb_read_bytes_total`, `adrian_smb_write_bytes_total`, `adrian_smb_oplock_break_total`, `adrian_smb_durable_reconnect_total{result}`. OpenTelemetry traces (`opentelemetry = "0.21"`) cover the per-request path (Negotiate → Session Setup → Tree Connect → Create → Read/Write → Close). Audit logs (per ADR-060) record every tree connect, file create, and file delete with the subject, share, file path, and timestamp.

## Rationale

Three candidate architectures were considered.

**Candidate A: Samba `smbd` as the SMB server.** Rejected because (a) GPLv3 license — the framework is Apache-2.0; linking Samba (even dynamically) into a single distributed binary creates a derivative work under GPLv3 §5, forcing the entire framework to GPLv3. The framework's commercial-use posture (enterprises embedding the framework in proprietary products) is incompatible with GPLv3. (b) Embedding difficulty — Samba's `smbd` is a monolithic daemon with its own process model (fork-per-connection historically, thread-per-connection in modern Samba), its own TDB/LSA/PASSDB infrastructure, and its own `smb.conf` configuration. Embedding into the framework's `tokio` runtime requires either running `smbd` as a subprocess (high latency, no native `tokio` integration) or calling Samba's libraries via FFI (loss of memory safety, complex build). (c) Memory-safety posture — Samba has had 90+ CVEs since 2010, most in the SMB1/SMB2 parsing layers, and many are memory-corruption bugs. The framework's security posture (memory-safe Rust for all protocol-parsing code) is incompatible with shipping a C SMB parser. (d) Code reuse cost — Samba's `smbd` is ~250K lines of C accumulated over 30 years; the framework needs ~15K lines of Rust for an SMB 3.1.1 server. Inheriting 250K lines of C to get 15K lines of functionality is a bad trade.

**Candidate B: Platform-native SMB servers (Windows `srv2.sys`, macOS SMBX).** Rejected because (a) Windows `srv2.sys` is a kernel-mode driver that cannot be embedded in a user-mode framework; (b) macOS SMBX is a closed-source Apple daemon not redistributable on Linux or Windows; (c) platform-native servers do not exist on Linux (the only Linux SMB server is Samba, rejected per §A); (d) using platform-native servers would mean three different SMB server implementations with different feature sets, bugs, and configuration models — defeating cross-platform parity.

**Candidate C: Reuse an emerging Rust SMB server crate (`pavao`, `smb-rs`).** Rejected as the primary path because (a) `pavao` is an SMB *client* library, not a server; (b) `smb-rs` is at an early stage (pre-0.1, no server implementation, no encryption, no persistent handles) and is not production-ready; (c) the framework's SMB server needs CA-share support, SMB Direct, DFS-N integration, ABE integration, framework-specific SPN handling, and audit logging — none of which are in any existing Rust crate. The framework's server is implemented from scratch, using `pavao` and `smb-rs` as reference for ASN.1/SPNEGO/Negotiate packet structure where helpful.

The chosen fresh-Rust-implementation model gives the framework: (a) license compatibility (Apache-2.0, no GPLv3 conflict); (b) memory safety (Rust, no buffer overflows in the SMB parser); (c) async integration with the framework's `tokio` runtime (single runtime for all framework components); (d) cross-platform parity (one implementation, three platforms); (e) feature control (the framework implements exactly the features it needs, with the integrations it needs, without inheriting Samba's 30-year tail).

The fresh implementation is a significant engineering investment (~28 person-weeks for v1, see Implementation impact), but it is a one-time cost. The alternative — Samba maintenance + GPLv3 + cross-platform divergence — is a recurring cost that exceeds the one-time implementation cost within 2-3 years.

## Trade-offs accepted

- **SMB 2.0.2 lower bound.** The server negotiates SMB 2.0.2 for legacy-client compatibility (no preauth integrity, no encryption, no persistent handles on this dialect). Operators wanting a higher floor can configure `smb.dialects.min = "3.0"`. Acceptable because some customers have Windows Server 2008 / old Linux `cifs.ko` clients.
- **NTLM as an opt-in fallback.** NTLM is supported when explicitly enabled; the framework's NTLM decision (Day 2 afternoon) controls whether it's enabled by default. Acceptable because some customers have stranded appliances that cannot use Kerberos.
- **No DFS-R.** The framework does not implement DFS-R. SYSVOL-equivalent replication uses Git (per ADR-031) for policy files and the framework's directory replication for directory objects. Acceptable because DFS-R is Windows-only; the framework's Git-based replication is cross-platform.
- **Object-store backend has reduced feature set.** Object-store-backed shares do not support persistent handles, durable opens, or oplocks. Acceptable because object stores are not POSIX; the framework's documentation explicitly lists the feature gap.
- **No SMB Direct on Windows or macOS.** SMB Direct (RDMA) is Linux-only in v1 (via `ibverbs`). Acceptable because SMB Direct is rare in enterprise deployments and Linux is the primary deployment platform.
- **No BranchCache.** The framework does not implement BranchCache (MS-PCCRC). Acceptable because BranchCache is rarely used and has a complex protocol surface.

## Rust implementation implications

The decision is implementable in pure Rust with the following crate graph:

- **`adrian-smb-core`** (workspace member) — SMB2/3 protocol data structures, packet parsers, serializers. Crates: `serde = "1"`, `bytes = "1"`, `nom = "7"` (binary parsing — used for SMB2 header, NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, READ, WRITE, CLOSE, IOCTL, LOCK, ECHO, CANCEL, LOGOFF, FSCTL, INFO), `bitflags = "2"`. The SMB2 packet structure is hand-rolled (no published Rust SMB2 server crate); the implementation is ~5K lines of Rust for the full SMB2 opnum table.
- **`adrian-smb-server`** (workspace member, binary) — the SMB server. Crates: `tokio = "1"` (multi-threaded runtime), `tokio-util = "0.7"` (codec for length-delimited SMB2 frames), `rustls = "0.23"` (TLS for SMB Direct, optional), `aes-gcm = "0.10"` (AES-128-GCM, AES-256-GCM encryption), `sha2 = "0.10"` (SHA-512 preauth integrity), `hmac = "0.12"` (HMAC for SMB 2.x signing), `rand = "0.8"`, `tracing = "0.1"`, `prometheus = "0.13"`, `opentelemetry = "0.21"`. The server's per-session state machine is implemented as a `tokio` task with `tokio::sync::mpsc` for inter-task communication.
- **`adrian-smb-auth`** (workspace member, library) — SPNEGO authentication. Crates: `gss-api = "0.1"` (Rust GSSAPI bindings, via `libgssapi` FFI), `kerberos = "0.1"` (MIT krb5 bindings via `krb5-sys = "0.1"` if mature, otherwise hand-rolled FFI to `libkrb5`), `ntlm = "0.1"` (NTLMSSP — hand-rolled; ~800 lines of Rust). The auth library exposes a `SpnegoAcceptor` trait that the SMB server calls during SESSION_SETUP.
- **`adrian-smb-share-posix`** (workspace member, library) — POSIX share backend. Crates: `tokio = "1"` (async file I/O), `tokio-uring = "0.4"` (Linux 5.1+ io_uring), `nix = "0.27"` (POSIX `fcntl`, `flock`, `getfacl`, `setfacl`), `xattr = "1"` (extended attributes for NTFS ACL storage). The POSIX backend translates NTFS ACLs to POSIX ACLs via the framework's ACL translation library (`adrian-acl-translate`).
- **`adrian-smb-share-ntfs`** (workspace member, library) — NTFS share backend (Windows only). Crates: `windows = "0.54"` (`CreateFileW`, `ReadFile`, `WriteFile`, `GetFileSecurity`, `SetFileSecurity`, `LockFileEx`, `DeviceIoControl(FSCTL_REQUEST_OPLOCK)`). Compiled only on Windows.
- **`adrian-smb-share-s3`** (workspace member, library) — S3-compatible object-store share backend. Crates: `aws-sdk-s3 = "1"` (AWS S3 SDK), `tokio`, `redis = "0.24"` (per-key distributed lock). The S3 backend maps each file to an object; each directory to a prefix.
- **`adrian-smb-handle-table`** (workspace member, library) — cluster-wide persistent-handle table. Crates: `etcd-client = "0.12"` (etcd backend, default), `redis = "0.24"` (Redis backend, opt-in), `sqlx = "0.7"` (PostgreSQL backend, opt-in). The handle table is a `kv`-store with `(share_id, file_id, client_guid, persistent_id)` keys and serialized open-state values.
- **`adrian-smb-dfsn`** (workspace member, library) — DFS-N referral handler. Crates: `trust-dns-resolver = "0.23"` (DNS SRV resolution). The DFS-N handler queries `_<share-name>._dfs._tcp.<domain>` SRV records and returns them as DFS referrals per ADR-044.
- **`adrian-acl-translate`** (workspace member, library) — NTFS ACL ↔ POSIX ACL translation. Crates: `serde`, `bitflags`. Pure Rust, ~600 lines. Translation follows the Microsoft SFU (Services for UNIX) mapping: SID → UID/GID via the framework's id-mapping (per Day 1 identity-model decision); NTFS ACE → POSIX ACE with the standard caveats (POSIX does not have explicit Deny; Deny ACEs are dropped with WARN).
- **`adrian-smb-cli`** (workspace member, binary) — the `adrian-smb` CLI for share management. Crates: `clap = "4"`, `tokio`, `serde_json`. Subcommands: `share create`, `share set`, `share delete`, `share list`, `session list`, `session close`, `tree list`, `tree disconnect`, `dfs-referral add`, `dfs-referral list`.

The SMB server's container image (per ADR-058) is built on `ubuntu:22.04` (or `redhat/ubi9:latest`); the server runs as `non-root` user `adrian` (UID 10001) with `CAP_NET_BIND_SERVICE` for TCP/445 binding. The server's StatefulSet has `volumeClaimTemplates` for the share backend storage (POSIX-backed shares); object-store-backed shares have no PVC.

Estimated effort: ~28 person-weeks for v1. Breakdown: SMB2/3 protocol core (8 pw, highest-risk), POSIX share backend (4 pw), NTFS share backend (3 pw, Windows-only), S3 share backend (3 pw), persistent-handle table + CA share support (4 pw), SPNEGO + Kerberos + NTLMSSP (3 pw), DFS-N (1 pw), ACL translation (2 pw). The SMB2/3 protocol core is the critical-path item; the framework's CI runs `smbtorture` (Samba's SMB conformance suite) against the framework's server on every PR.

## Problems unblocked

| Problem | Capability | Severity | Gating ORQ before | Status after |
|---------|-----------|----------|---------------------|--------------|
| PC-078 — SMB 3.1.1 with preauth integrity + AES-GCM required for modern Windows interop | File Gateway | blocker | ORQ-154/155 | Unblocked — fresh Rust SMB 3.1.1 server with SHA-512 preauth integrity, AES-256-GCM encryption, SMB 3.1.1 default |
| PC-081 — Continuously Available (CA) shares require cluster + persistent handles | File Gateway | high | ORQ-154/155 | Unblocked — persistent handles stored in cluster-wide handle table (etcd/Redis/PostgreSQL); CA shares supported on POSIX and S3 backends |
| PC-130 — SYSVOL migration | Migration | medium | ORQ-154/155 | Unblocked — SMB server exposes Git-backed SYSVOL-equivalent share; legacy Windows clients read `Registry.pol` from `\\<domain>\SYSVOL\` via SMB |
| PC-079 — SMB1 must be dropped | File Gateway | blocker | (ADR-043 covers policy; this decision provides the implementation) | Implementation locked — fresh server refuses SMB1 negotiation per ADR-043 |
| PC-080 — DFS-N/DFS-R Windows-only | File Gateway | blocker | (ADR-044 covers DFS-N policy; this decision provides the implementation) | Implementation locked — DFS-N via DNS SRV per ADR-044; DFS-R not implemented (Git-based replication instead) |
| PC-082 — ABE precomputed index | File Gateway | medium | (ADR-045 covers ABE mechanism; this decision provides the implementation) | Implementation locked — SMB server consults ABE index for every directory enumeration per ADR-045 |
| PC-084 — File-access audit logging | File Gateway | medium | (ADR-060 covers audit policy; this decision provides the implementation) | Implementation locked — SMB server emits OpenTelemetry audit events per ADR-060 |

## Implementation impact

The decision locks the File Gateway's v1 SMB server architecture. The `adrian-smb-server` binary is the sole SMB server; no Samba, no platform-native servers. The container image (~80MB) is built once per release; the StatefulSet deploys 1-N replicas depending on the share-backend choice (POSIX and NTFS backends use 1 replica per node with PVC affinity; S3 backend can scale to many replicas since storage is shared).

The SMB2/3 protocol core is the highest-risk implementation item. The framework's CI runs Samba's `smbtorture` conformance suite against the framework's server on every PR, validating that the server correctly implements every SMB2 opnum. The CI also runs Microsoft's SMB2 SUT test cases, validating wire-level compatibility with Windows clients. The CI includes Windows 11, macOS 14, and Ubuntu 22.04 client VMs that mount shares from the framework's server and run read/write/lock/oplock workloads.

The persistent-handle table is the second-highest-risk item. The framework's CI runs a failover test: a client opens a file with a persistent handle on server A; server A is killed; the client reconnects to server B; the test verifies that server B resumes the open via the handle table. The failover test runs against all three handle-table backends (etcd, Redis, PostgreSQL).

The S3 share backend's lack of file locking is a known limitation, documented explicitly. Operators choosing S3 for cost reasons must accept these limitations or use POSIX backend with NVMe storage instead.

## Cross-capability dependencies

- **Core Directory.** The SMB server queries the directory for share-level ACLs (`FileGatewayShare` directory object) and for user/group identity resolution (during SPNEGO authentication, to map the Kerberos-authenticated identity to a directory user). The directory's `memberOf` back-link (per ADR-002) is used for group-membership-based access control.
- **KDC.** The SMB server validates incoming Kerberos tickets via the framework's KDC. The server's SPN (`cifs/<host-fqdn>`) is registered during host enrollment. The server uses the framework's unified PAC validator (per ADR-049) for PAC parsing.
- **Cert Service (Decision 8).** SMB 3.1.1 encryption does not use certificates (it uses session keys derived from the Kerberos auth); however, SMB Direct (RDMA) TLS uses certs issued by the framework's CA when TLS-over-RDMA is configured.
- **Policy Engine (Decision 7).** The framework's policy defines the SMB server's configuration: `smb.dialects.min`, `smb.encryption.algorithm`, `smb.auth.ntlm`, share definitions. Policy changes are pushed to the SMB server via the framework's WebSocket push (per ADR-028); the server reloads configuration without dropping active sessions.
- **Federation Gateway (Decision 9).** Not a direct dependency; the SMB server does not interact with the federation gateway.
- **Operations (ADR-058).** The SMB server is deployed as a StatefulSet (POSIX/NTFS backends) or Deployment (S3 backend). The framework's operator manages the SMB server lifecycle (deploy, upgrade, backup share backend, restore) via an `SmbServer` CRD.
- **Migration (PC-130 SYSVOL migration).** The SMB server exposes the Git-backed SYSVOL-equivalent share; legacy Windows clients continue to read `\\<domain>\SYSVOL\` via SMB during migration. The framework's `adrian-migrate from-sysvol` CLI walks an existing AD SYSVOL, imports GPOs into the framework's Git-backed policy repository (per Decision 7's PReg reader), and emits canonical JSON policies.
- **Security (PC-123 threat model).** SMB server compromise is a top Security threat; the Rust memory-safety guarantee and the audit logging (per ADR-060) are documented in the Security threat model. The server's non-root execution (UID 10001) and capability-based privilege model (`CAP_NET_BIND_SERVICE` only) limit the blast radius of any future vulnerability.

## References

- [ADR-002](../adr/ADR-002-memberof-back-link.md) — memberOf back-link (for group-membership-based access control)
- [ADR-021](../adr/ADR-021-ldap-signing-channel-binding.md) — LDAP signing + channel binding (NTLM enforcement)
- [ADR-028](../adr/ADR-028-push-based-policy-websocket.md) — push-based policy distribution
- [ADR-031](../adr/ADR-031-git-backed-policy-history.md) — Git-backed SYSVOL-equivalent
- [ADR-043](../adr/ADR-043-drop-smb1-support.md) — Drop SMB1 support (this decision provides the server implementation that ADR-043 left open)
- [ADR-044](../adr/ADR-044-dfs-n-via-dns-srv.md) — DFS-N via DNS SRV
- [ADR-045](../adr/ADR-045-abe-precomputed-index.md) — ABE precomputed index
- [ADR-049](../adr/ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization (for SPNEGO acceptor)
- [ADR-058](../adr/ADR-058-container-native-dcs-operator.md) — container-native deployment
- [ADR-060](../adr/ADR-060-structured-audit-logs-otel.md) — structured audit logs
- [PC-078, PC-081, PC-130](../catalog/07-file-gateway.md) — problem statements
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2) — SMB2 protocol specification
- [Samba security advisories](https://www.samba.org/samba/security/) — historical CVE record (justification for fresh Rust implementation)
- [pavao](https://docs.rs/pavao) — Rust SMB client library (reference)
- [smb-rs](https://github.com/Avira/smb-rs) — emerging Rust SMB library (reference)
- [smbtorture](https://wiki.samba.org/index.php/Smbtorture) — Samba's SMB conformance suite (used in CI)
- [Microsoft Open Specifications SMB2 SUT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fcfde2d3-1b48-4db5-8d57-e0b8f8c6f6e1) — Microsoft's SMB2 test cases
