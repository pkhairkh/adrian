---
title: "ADR-105: Fresh Rust SMB 3.1.1 server — SHA-512 preauth integrity, AES-256-GCM, no Samba"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: File Gateway
problem: PC-078
severity: blocker
unblocked_by: Workshop Decision 10
tags: [adr, file-gateway, smb, smb3, rust, preauth-integrity, aes-gcm, memory-safe, fresh-impl]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/07-file-gateway.md
  - ../workshop/decision-10-smb-server.md
  - ../docs/02-protocols/03-smb-cifs-protocol.md
  - ../docs/07-file-print/01-smb-shares-internals.md
  - ./ADR-043-drop-smb1-support.md
  - ./ADR-044-dfs-n-via-dns-srv.md
  - ./ADR-045-abe-precomputed-index.md
  - ./ADR-049-standardize-mit-krb5.md
last_updated: 2026-08-14
---

# ADR-105: Fresh Rust SMB 3.1.1 server — SHA-512 preauth integrity, AES-256-GCM, no Samba

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 10](../workshop/decision-10-smb-server.md) (SMB server: fresh Rust SMB 3.1.1 server). This ADR operationalises Decision 10 against the PC-078 problem surface: the requirement for SMB 3.1.1 with SHA-512 preauth integrity and AES-GCM encryption for modern Windows interop, which the framework implements as a fresh Rust SMB server (no Samba, no platform-native `srv2.sys`).

## Context

SMB 3.1.1 (dialect `0x0311`, introduced with Server 2016 / Windows 10) layers three security primitives onto the SMB session that earlier dialects lack: SHA-512 pre-auth integrity, AES-GCM (and AES-GMAC) as the encryption and signing cipher, and a `NegotiateContextList` that binds the entire Negotiate exchange into the session-key derivation. Per [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md), the pre-auth integrity hash (Negotiate Context type `0x0001`, `SMB2_PREAUTH_INTEGRITY_CAPABILITIES`) is computed over the entire Negotiate request and response per MS-SMB2 §3.2.5.1, and is then mixed into the HKDF-SHA512 key-derivation labeled `"SMBSigningKey\x00" / "ServerIn\x00" / "ServerOut\x00"`. Without pre-auth integrity, a MITM can downgrade dialect negotiation between a 3.1.1-capable client and an SMB 2.1 server, defeating the AES-GCM signing that 3.1.1 enables. AES-128-GCM and AES-256-GCM are advertised via Negotiate Context type `0x0002` (`SMB2_ENCRYPTION_CAPABILITIES`) and the cipher selection appears in the `SMB2_TRANSFORM_HEADER` (`EncryptionAlgorithm` field at offset `0x14`, values `0x0002`/`0x0004`). Signing via AES-GMAC is advertised via the `SMB2_SIGNING_CAPABILITIES` context (type `0x0008`).

A new framework cannot ship an SMB server that negotiates below SMB 3.0.2 for production use against Windows 10 1709+ clients. Per [PC-078](../catalog/07-file-gateway.md), Windows refuses SMB 2.x to non-domain-joined servers under several GPO-enforced configurations (`EnableInsecureGuestLogons = 0`, Microsoft network client: Digitally sign communications policy). Microsoft telemetry as of 2024 shows >95% of file-server traffic in enterprise AD deployments uses SMB 3.x dialects, with SMB 3.1.1 the majority dialect on Windows 11 + Server 2022. The framework's SMB server MUST negotiate SMB 3.1.1 by default and MUST NOT negotiate below SMB 2.0.2 (per [ADR-043](./ADR-043-drop-smb1-support.md)).

Per [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md), the Windows reference implementation is `srv2.sys` (server) and `mrxsmb20.sys` (client), with the per-share `EncryptData` flag and the per-server `RequireSecuritySignature` registry key under `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` controlling the security posture. Samba added SMB 3.1.1 dialect support in 4.3 (2015), with AES-GCM encryption in 4.4 and pre-auth integrity in 4.4; production stability arrived with Samba 4.7. Apple's SMBX gained SMB 3.1.1 client support in macOS 11 Big Sur; server-side SMB 3.1.1 came later. The Linux CIFS kernel module (`cifs.ko`) supports SMB 3.1.1 with `vers=3.1.1,seal` mount options since kernel 5.x.

Workshop Decision 10 fixes the framework's SMB server choice: a fresh Rust SMB 3.1.1 server (`adrian-smb-server`), written from scratch, targeting SMB 3.1.1 with SMB 2.0.2/2.1/3.0/3.0.2 as fallback dialects. Samba is rejected (GPLv3 license conflict, embedding difficulty, memory-safety posture); platform-native servers are rejected (Windows-only `srv2.sys`, closed-source macOS SMBX, no Linux equivalent); emerging Rust SMB crates (`pavao`, `smb-rs`) are rejected as the primary path (no production server implementation).

## Decision

The framework's File Gateway ships a **fresh Rust SMB 3.1.1 server** (`adrian-smb-server`) targeting only SMB 3.1.1 (with SMB 2.0.2, 2.1, 3.0, 3.0.2 as the lower-bound dialects for client compatibility). The server is async (`tokio`), memory-safe (Rust), and integrates with the framework's directory service for authentication and access control. There is no Samba, no `srv2.sys`, no SMBX, no MS-RPRN, no NetBIOS-over-TCP.

### Concrete specification

1. **Dialect support.** Per Decision 10 §1 and ADR-043, the server refuses SMB1 negotiation entirely. The server's Negotiate response lists five dialects by default: SMB 2.0.2 (`0x0202`), 2.1 (`0x0210`), 3.0 (`0x0300`), 3.0.2 (`0x0302`), and 3.1.1 (`0x0311`). Operators can restrict the dialect list via configuration (`smb.dialects.min = "3.0"`, `smb.dialects.max = "3.1.1"`) to enforce a higher security floor; the framework's default policy template (per Workshop Decision 7) sets `smb.dialects.min = "3.0"` for high-security deployments. SMB 3.1.1 is the recommended dialect for Windows 10+ / Server 2016+ / macOS 11+ / Linux `cifs.ko` 4.x+ clients.

2. **Transport.** The server listens exclusively on TCP/445 (direct-hosted), per ADR-043. No NetBIOS-over-TCP (TCP/139, UDP/137/138). The server also supports (opt-in) SMB Direct (RDMA via InfiniBand or RoCE) using the `rust-rdma` crate family (`rdma-sr = "0.1"` if mature, otherwise hand-rolled `ibverbs` FFI). SMB Direct is disabled by default; it is enabled via `smb.direct.enabled = true` with a configured RDMA device. SMB Direct is Linux-only in v1.

3. **Preauth integrity.** Per SMB 3.1.1, the server supports SHA-512 preauth integrity (the only algorithm defined in MS-SMB2 §3.2.5.1.1). The server selects SHA-512 in the Negotiate response's `NegotiateContextList` (context type `SMB2_PREAUTH_INTEGRITY_CAPABILITIES`, value `0x0001`). The server validates the preauth integrity hash on every subsequent packet in the session setup; mismatched hashes trigger `STATUS_ACCESS_DENIED` and session teardown. The preauth integrity hash is mixed into the HKDF-SHA512 key derivation labeled `"SMBSigningKey"`, `"ServerIn"`, `"ServerOut"` per MS-SMB2 §3.2.5.2.

4. **Encryption.** Per SMB 3.1.1, the server supports AES-128-GCM and AES-256-GCM encryption (the two algorithms defined in MS-SMB2 §3.1.4.3). The server selects AES-256-GCM by default (stronger cipher); operators can downgrade to AES-128-GCM via `smb.encryption.algorithm = "aes-128-gcm"` for performance on clients without AES-NI. Encryption is mandatory for SMB 3.1.1 sessions (the server's Negotiate response sets the `SMB2_GLOBAL_CAP_ENCRYPTION` flag and refuses unencrypted sessions at the 3.1.1 dialect); for SMB 3.0 and 3.0.2, encryption is optional per-share (the share's `encrypt = true|false` flag). SMB 2.0.2 and 2.1 do not support encryption; clients requesting those dialects must accept unencrypted sessions (operators can disable SMB 2.x via `smb.dialects.min = "3.0"`).

5. **Signing.** Per SMB 3.1.1, the server supports AES-GMAC signing (Negotiate Context type `0x0008`, `SMB2_SIGNING_CAPABILITIES`). Signing is required for all sessions (the server refuses unsigned messages on sessions where signing is negotiated). For SMB 2.x and 3.0/3.0.2, the server uses HMAC-SHA256 signing (the dialect-default signing algorithm).

6. **Authentication.** The server supports two authentication mechanisms per Decision 10 §3:
   - **Kerberos (SPNEGO via GSSAPI)** — the preferred mechanism. The server uses the framework's MIT krb5 (per [ADR-049](./ADR-049-standardize-mit-krb5.md)) for Kerberos acceptor logic. The server's service principal name (SPN) is `cifs/<host-fqdn>@<realm>`, registered automatically during host enrollment. The server validates the Kerberos ticket via the framework's KDC and extracts the client's identity (user SID-equivalent UUID, group SIDs) from the ticket's PAC (validated via the framework's unified PAC validator per ADR-049).
   - **NTLM (SPNEGO via NTLMSSP)** — supported only for clients that cannot use Kerberos (legacy appliances, workgroup clients). NTLM is disabled by default per the framework's NTLM decision (Workshop Decision 6); operators can enable it explicitly via `smb.auth.ntlm = "allowed"` for compatibility with stranded clients. When NTLM is enabled, the server enforces LDAP signing + channel binding (per [ADR-021](./ADR-021-ldap-signing-channel-binding.md)) and NTLMv2 only (no LM, no NTLMv1).

7. **Authorization.** Access-Based Enumeration (ABE) is enforced per [ADR-045](./ADR-045-abe-precomputed-index.md). The server consults the framework's precomputed ABE index for every directory enumeration call, filtering the result list to entries the client has `READ` access to. Share-level ACLs are stored in the framework's directory (per Decision 7's `FileGatewayShare` directory object); file-system ACLs are stored in the file system's extended attributes (`user.adrian.acl` for POSIX-backed shares, NTFS ACLs for Windows-backed shares).

8. **Share backends.** The server supports three share backends per Decision 10 §5: POSIX filesystem (default for Linux deployments; files on ext4/XFS/Btrfs with NTFS ACL → POSIX ACL translation via `adrian-acl-translate`), NTFS (Windows deployments; `windows = "0.54"` for Win32 APIs), and object store (cloud deployments; S3-compatible via `aws-sdk-s3 = "1"`; per-key distributed locking via Redis for sharing-violation semantics). Object-store-backed shares do not support persistent handles, durable opens, or oplocks — clients detect the lack via the `FILE_PERSISTENT_HANDLES` capability flag and fall back to non-durable opens.

9. **Persistent handles and continuously available (CA) shares.** Per Decision 10 §8 and the persistent-handle table specification, the server implements persistent handles per MS-SMB2 §3.3.5.2.11 (`SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` with `SMB2_DHANDLE_FLAG_PERSISTENT`). Persistent handles are stored in a shared handle table (etcd, Redis, or PostgreSQL — default etcd) so that a client can reconnect to a different server in the cluster and resume the open. CA shares advertise `SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE` in `TreeConnect.GetResponse` only when the share is genuinely backed by cluster storage. CA shares require either a POSIX filesystem with a cluster-wide lock manager (GFS2, OCFS2) or the object-store backend. NTFS-backed shares do not support CA. (PC-081's persistent-handle table is fully specified in [ADR-106](./ADR-106-smb-client-persistent-handles-sdk-filemodule.md).)

10. **DFS-N.** Per [ADR-044](./ADR-044-dfs-n-via-dns-srv.md), the framework implements DFS-N via DNS SRV records instead of the AD-LDAP-stored DFS namespace. The SMB server's `IOCTL_FSCTL_DFS_GET_REFERRALS` handler queries the framework's DNS server (via `trust-dns-resolver = "0.23"`) for `_<share-name>._dfs._tcp.<domain>` SRV records and returns them as DFS referral responses. No DFS-R (SYSVOL replication uses Git per ADR-031; cross-site file replication is documented as out of scope for v1).

11. **SYSVOL-equivalent share.** The framework's SYSVOL-equivalent share (`\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\`) is served by the SMB server. The share is backed by the framework's Git-backed policy repository (per ADR-031) on the policy distribution host; the SMB server exposes the Git working tree as a read-only share. Writes are not permitted via SMB; policy updates go through the framework's Git workflow. Legacy Windows clients that expect to read `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Registry.pol` see the framework's PReg-emitted `Registry.pol` files (per Decision 7's PReg adapter).

12. **Performance.** Per Decision 10 §11, the server targets: single-connection throughput ≥ 800 MB/s read, ≥ 600 MB/s write on a 10 GbE link with SMB Direct disabled, AES-256-GCM encryption enabled, against an NVMe-backed POSIX share; concurrent connections ≥ 5,000 active sessions per server instance; latency p99 ≤ 5 ms for `SMB2_CREATE`, `SMB2_READ`, `SMB2_WRITE` on a hot cache. The server uses `tokio`'s multi-threaded runtime with one task per connection; the SMB message dispatcher is a per-session state machine (no global lock). File I/O is `tokio-epoll-uring` on Linux 5.1+ (via `tokio-uring = "0.4"`), `IOCP` on Windows (via `tokio = "1"`'s IOCP backend), `kqueue` on macOS.

13. **Observability.** Per Decision 10 §12, the server emits Prometheus metrics (`adrian_smb_negotiated_dialect_total{dialect}`, `adrian_smb_session_total{auth_method}`, `adrian_smb_tree_connect_total{share,backend}`, `adrian_smb_create_total{result}`, `adrian_smb_read_bytes_total`, `adrian_smb_write_bytes_total`, `adrian_smb_oplock_break_total`, `adrian_smb_durable_reconnect_total{result}`). OpenTelemetry traces cover the per-request path (Negotiate → Session Setup → Tree Connect → Create → Read/Write → Close). Audit logs (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)) record every tree connect, file create, and file delete with the subject, share, file path, and timestamp.

## Rationale

The framework chose a fresh Rust implementation over Samba (Decision 10 ORQ-154 = NO) for three independent reasons: (a) license conflict — Samba is GPLv3, the framework is Apache-2.0, and GPLv3's copyleft would force the framework's entire source tree to GPLv3; (b) embedding difficulty — Samba is C, designed as a monolithic daemon, with no stable embedding API, and the `smbd` process model is incompatible with the framework's async `tokio` runtime; (c) memory-safety posture — Samba has had 90+ CVEs since 2010, most in the SMB1/SMB2 parsing layers, and the framework's security posture (memory-safe Rust for all protocol-parsing code) is incompatible with shipping a C SMB parser.

The framework chose fresh Rust over platform-native servers (Decision 10 Alternative B rejected) because Windows `srv2.sys` is a kernel-mode driver that cannot be embedded in a user-mode framework; macOS SMBX is closed-source and not redistributable on Linux or Windows; platform-native servers do not exist on Linux; using platform-native servers would mean three different SMB server implementations with different feature sets, bugs, and configuration models — defeating cross-platform parity.

The framework chose fresh Rust over emerging Rust SMB crates (`pavao`, `smb-rs`) as the primary path (Decision 10 Alternative C rejected) because `pavao` is an SMB *client* library, not a server; `smb-rs` is at an early stage (pre-0.1, no server implementation, no encryption, no persistent handles); the framework's SMB server needs CA-share support, SMB Direct, DFS-N integration, ABE integration, framework-specific SPN handling, and audit logging — none of which are in any existing Rust crate. The framework's server is implemented from scratch, using `pavao` and `smb-rs` as reference for ASN.1/SPNEGO/Negotiate packet structure where helpful.

The fresh implementation is a significant engineering investment (~28 person-weeks for v1 per Decision 10), but it is a one-time cost. The alternative — Samba maintenance + GPLv3 + cross-platform divergence — is a recurring cost that exceeds the one-time implementation cost within 2-3 years.

## Consequences

**Positive**. The framework ships a memory-safe SMB server (Rust eliminates the buffer-overflow/use-after-free class of bugs that have plagued Samba and `srv2.sys`). The framework's SMB server is cross-platform (one Rust implementation, three platforms) — no platform-divergent feature sets. The framework's SMB server is license-compatible (Apache-2.0, no GPLv3 conflict). The framework implements exactly the features it needs (CA shares, SMB Direct, DFS-N, ABE, framework-specific SPN handling, audit logging) without inheriting Samba's 30-year tail of legacy code paths.

**Negative**. The fresh implementation is a ~28 person-weeks engineering investment (per Decision 10). The SMB2/3 protocol core is the highest-risk implementation item; the framework's CI runs `smbtorture` (Samba's SMB conformance suite) and Microsoft's SMB2 SUT test cases against the framework's server on every PR. The persistent-handle table is the second-highest-risk item; the framework's CI runs a failover test (kill server A, reconnect to server B, verify the open resumes via the handle table). The framework does not implement DFS-R (cross-site file replication); customers needing cross-site file replication must use an external solution (rsync, syncthing) or wait for v1.1.

**Neutral**. The framework's SMB server's wire-compatibility posture is identical to Windows Server 2019+ and Samba 4.7+ (per ADR-043), so customer expectations are already aligned. Customers with SMB1-only NAS appliances must deploy a Samba 4.7+ proxy in front of the legacy NAS (per ADR-043's out-of-scope documentation).

**Implementation cost**. ~28 person-weeks for v1 (per Decision 10): SMB2/3 protocol core (8 pw, highest-risk), POSIX share backend (4 pw), NTFS share backend (3 pw, Windows-only), S3 share backend (3 pw), persistent-handle table + CA share support (4 pw), SPNEGO + Kerberos + NTLMSSP (3 pw), DFS-N (1 pw), ACL translation (2 pw).

**Operational impact**. File Gateway operators manage the SMB server via `adrian-smb` CLI (share create/list, session list/close, tree list/disconnect, dfs-referral add/list). The framework's `SmbServer` CRD (per [ADR-058](./ADR-058-container-native-dcs-operator.md)) manages the SMB server lifecycle (deploy, upgrade, backup share backend, restore). The server runs as `non-root` user `adrian` (UID 10001) with `CAP_NET_BIND_SERVICE` for TCP/445 binding.

## Alternatives Considered

### Alternative A: Samba `smbd` as the SMB server

Per Decision 10 Alternative A. Rejected because (a) GPLv3 license — the framework is Apache-2.0; linking Samba (even dynamically) into a single distributed binary creates a derivative work under GPLv3 §5, forcing the entire framework to GPLv3. The framework's commercial-use posture is incompatible with GPLv3. (b) Embedding difficulty — Samba's `smbd` is a monolithic daemon with its own process model and its own TDB/LSA/PASSDB infrastructure; embedding into the framework's `tokio` runtime requires either running `smbd` as a subprocess (high latency, no native `tokio` integration) or calling Samba's libraries via FFI (loss of memory safety, complex build). (c) Memory-safety posture — Samba has had 90+ CVEs since 2010, most in the SMB1/SMB2 parsing layers, and many are memory-corruption bugs. The framework's security posture (memory-safe Rust for all protocol-parsing code) is incompatible with shipping a C SMB parser. (d) Code reuse cost — Samba's `smbd` is ~250K lines of C accumulated over 30 years; the framework needs ~15K lines of Rust for an SMB 3.1.1 server. Inheriting 250K lines of C to get 15K lines of functionality is a bad trade.

### Alternative B: Platform-native SMB servers (Windows `srv2.sys`, macOS SMBX, Samba on Linux)

Per Decision 10 Alternative B. Rejected because (a) Windows `srv2.sys` is a kernel-mode driver that cannot be embedded in a user-mode framework; (b) macOS SMBX is a closed-source Apple daemon not redistributable on Linux or Windows; (c) platform-native servers do not exist on Linux (the only Linux SMB server is Samba, rejected per Alternative A); (d) using platform-native servers would mean three different SMB server implementations with different feature sets, bugs, and configuration models — defeating cross-platform parity.

### Alternative C: Reuse an emerging Rust SMB server crate (`pavao`, `smb-rs`)

Per Decision 10 Alternative C. Rejected as the primary path because (a) `pavao` is an SMB *client* library, not a server; (b) `smb-rs` is at an early stage (pre-0.1, no server implementation, no encryption, no persistent handles) and is not production-ready; (c) the framework's SMB server needs CA-share support, SMB Direct, DFS-N integration, ABE integration, framework-specific SPN handling, and audit logging — none of which are in any existing Rust crate. The framework's server is implemented from scratch, using `pavao` and `smb-rs` as reference for ASN.1/SPNEGO/Negotiate packet structure where helpful.

### Alternative D: Defer SMB server implementation to v1.1; recommend Samba proxy in v1

The framework's v1 documentation recommends a Samba 4.7+ proxy in front of the framework's directory for SMB file serving; the framework's fresh Rust SMB server ships in v1.1. Rejected because (a) the framework's Policy Engine requires SMB access to the SYSVOL-equivalent share (per Decision 7 and ADR-089) — without an SMB server, the framework's policy distribution does not work; (b) the framework's value proposition includes replacing Windows file servers, not deferring file serving to Samba; (c) deferring the fresh implementation to v1.1 means the framework's v1 customers inherit Samba's GPLv3 + memory-safety posture, which the framework explicitly rejects. The 28-person-week investment is on the v1 critical path.

## Open Questions

- Should the framework support SMB multichannel (multiple TCP connections per session for aggregate throughput) in v1? Current decision: yes — multichannel is required for production performance on 10 GbE+ links; the server's `tokio` runtime supports multiple connections per session natively.
- Should the framework support SMB Direct (RDMA) on Windows or macOS in v1.1? Current decision: defer — SMB Direct is Linux-only in v1 (via `ibverbs`); Windows and macOS support is documented as v1.1.
- Should the framework implement BranchCache (MS-PCCRC) in v1? Current decision: no — BranchCache is rarely used and has a complex protocol surface. Revisit if customer demand warrants.
- Should the framework support the SMB `IOCTL_FSCTL_SRV_ENUMERATE_SNAPSHOTS` for VSS-equivalent shadow copies? Current decision: no in v1 — the framework's snapshot story (per Workshop Decision 2's FoundationDB) is at the storage layer, not the SMB layer. Revisit in v1.1.

## Cross-capability impact

- **File Gateway (PC-079 — SMB1 removal).** Addressed in [ADR-043](./ADR-043-drop-smb1-support.md). The fresh server refuses SMB1 negotiation per ADR-043.
- **File Gateway (PC-080 — DFS-N/DFS-R).** Addressed in [ADR-044](./ADR-044-dfs-n-via-dns-srv.md). DFS-N via DNS SRV; no DFS-R.
- **File Gateway (PC-081 — CA shares).** Addressed in [ADR-106](./ADR-106-smb-client-persistent-handles-sdk-filemodule.md). Persistent handles + cluster-wide handle table.
- **File Gateway (PC-082 — ABE).** Addressed in [ADR-045](./ADR-045-abe-precomputed-index.md). The SMB server consults the ABE index for every directory enumeration.
- **Core Directory.** The SMB server queries the directory for share-level ACLs (`FileGatewayShare` directory object) and for user/group identity resolution during SPNEGO authentication.
- **KDC.** The SMB server validates incoming Kerberos tickets via the framework's KDC. The server's SPN (`cifs/<host-fqdn>`) is registered during host enrollment.
- **Policy Engine (Workshop Decision 7).** The framework's policy defines the SMB server's configuration: `smb.dialects.min`, `smb.encryption.algorithm`, `smb.auth.ntlm`, share definitions. Policy changes are pushed to the SMB server via the framework's WebSocket push (per [ADR-028](./ADR-028-push-based-policy-websocket.md)).
- **Operations (ADR-058).** The SMB server is deployed as a StatefulSet (POSIX/NTFS backends) or Deployment (S3 backend).
- **Migration (PC-130 SYSVOL migration).** The SMB server exposes the Git-backed SYSVOL-equivalent share; legacy Windows clients continue to read `\\<domain>\SYSVOL\` via SMB during migration.

## References

- [PC-078](../catalog/07-file-gateway.md) — problem statement
- [Workshop Decision 10](../workshop/decision-10-smb-server.md) — SMB server: fresh Rust SMB 3.1.1 server
- [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md) — SMB 3.1.1 Negotiate context list, AES-GCM transform header, signing algorithm table per dialect
- [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md) — `srv2.sys` driver architecture, per-share `EncryptData` / `ContinuouslyAvailable` registry flags, signing algorithm progression
- [ADR-043](./ADR-043-drop-smb1-support.md) — Drop SMB1 support (this decision provides the server implementation)
- [ADR-044](./ADR-044-dfs-n-via-dns-srv.md) — DFS-N via DNS SRV
- [ADR-045](./ADR-045-abe-precomputed-index.md) — ABE precomputed index
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization (for SPNEGO acceptor)
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2) — SMB2 protocol specification
- [Samba security advisories](https://www.samba.org/samba/security/) — historical CVE record (justification for fresh Rust implementation)
- [pavao](https://docs.rs/pavao) — Rust SMB client library (reference)
- [smb-rs](https://github.com/Avira/smb-rs) — emerging Rust SMB library (reference)
- [smbtorture](https://wiki.samba.org/index.php/Smbtorture) — Samba's SMB conformance suite (used in CI)
