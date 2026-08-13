---
title: "ADR-106: SMB client as Rust SDK FileModule — fresh implementation with persistent-handle reconnect for CA shares"
status: Accepted
date: 2026-08-14
deciders: adrian-architecture-team
capability: File Gateway
problem: PC-081
severity: high
unblocked_by: [Workshop Decision 10, Workshop Decision 11]
tags: [adr, file-gateway, client-sdk, smb, smb-client, persistent-handles, dh2c, ca-shares, rust, pavao]
related:
  - ./TRIAGE.md
  - ./README.md
  - ../catalog/07-file-gateway.md
  - ../workshop/decision-10-smb-server.md
  - ../workshop/decision-11-client-sdk.md
  - ../docs/02-protocols/03-smb-cifs-protocol.md
  - ../docs/07-file-print/01-smb-shares-internals.md
  - ./ADR-043-drop-smb1-support.md
  - ./ADR-049-standardize-mit-krb5.md
  - ./ADR-063-unified-cross-platform-cli.md
  - ./ADR-105-fresh-rust-smb3-server.md
last_updated: 2026-08-14
---

# ADR-106: SMB client as Rust SDK FileModule — fresh implementation with persistent-handle reconnect for CA shares

## Status

Accepted — 2026-08-14. Unblocked by [Workshop Decision 10](../workshop/decision-10-smb-server.md) (SMB server: fresh Rust SMB 3.1.1 server) and [Workshop Decision 11](../workshop/decision-11-client-sdk.md) (Client SDK: unified Rust core + platform-specific bindings). This ADR operationalises Decision 11 §12 (FileModule) against the PC-081 problem surface: the Continuously Available (CA) share requirement — which couples the server-side persistent-handle table (Decision 10) with the client-side DH2C reconnect behavior — and the underlying client-library choice (platform-native `mrxsmb20.sys` / SMBX / `cifs.ko` vs Samba `libsmbclient` vs fresh Rust).

## Context

A Continuously Available (CA) share in Windows is one whose `TreeConnect.GetResponse` returns the `SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE` (0x0002) capability bit, signaling that the share is backed by a Failover Cluster role on top of a Cluster Shared Volume (CSV) and that the server will honor persistent handle create contexts (`DH2Q` — Durable Handle v2 Request, `0x44483251`; and `DH2C` — Durable Handle v2 Reconnect, `0x44483243`). When the cluster node hosting the SMB server role fails, the CSV moves to another node and the SMB client reconnects via `DH2C`, presenting its original `ClientGuid` (negotiated in the SMB2 Negotiate response at offset `0x0C`), the durable handle's `PersistentFileId`, and the session's `SessionId`. The client observes a brief TCP retransmit (typically 1-3 seconds) and then resumes I/O without losing open file handles, oplock state, or SMB leases, per the analysis in [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md) and [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md).

PC-081's open questions (from [catalog/07-file-gateway.md](../catalog/07-file-gateway.md)) include: build a clustered SMB server in a container and accept that failover requires SMB session re-establishment, or invest in true persistent-handle support by storing handle state in a shared etcd/FDB cluster; reuse CTDB-style clustered Samba for the Linux tier and document macOS as non-CA; adopt a new wire-compatible CA protocol extension (`DH3Q`) trading wire-compat for implementation simplicity. The server-side answer is locked by Decision 10 and [ADR-105](./ADR-105-fresh-rust-smb3-server.md): the framework's fresh Rust SMB server stores persistent-handle state in a cluster-wide handle table (etcd/Redis/PostgreSQL) and honors `DH2C` reconnect from any cluster node. The client-side answer is the subject of this ADR: the framework's SDK must ship an SMB client that can issue `DH2Q` on create, persist the `PersistentFileId` and `ClientGuid` across the reconnect, and issue `DH2C` on reconnect to resume the open.

The client-library choice is constrained by the persistent-handle requirement. The three traditional client options are:

1. **Platform-native SMB clients** — Windows `mrxsmb20.sys` (kernel-mode redirector), macOS SMBX (kernel extension / `smbx.kext`), Linux `cifs.ko` (kernel module). Platform-native clients are deeply integrated with their respective OSes (kernel cache, filesystem VFS integration, mount semantics) but they are (a) platform-specific (one code path per platform, defeating cross-platform parity), (b) not embeddable in a userspace SDK (the SDK's FileModule must run in-process, not as a kernel module), (c) closed-source on macOS, (d) lacking a stable programmatic API on Windows (`WNet` API is high-level and does not expose persistent-handle control), (e) lacking persistent-handle reconnect on macOS SMBX (Apple's SMBX has known quirks with multichannel and persistent handles per [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md)).

2. **Samba `libsmbclient`** — the userspace C client library shipped with Samba. `libsmbclient` is embeddable in a userspace SDK (it is a `.so` library) and supports persistent handles, but it inherits Samba's GPLv3 license (rejected by Decision 10 for the same reason), its C API is awkward to call from Rust (FFI boilerplate, manual memory management), and it carries Samba's 90+ CVE history (rejected by Decision 10's memory-safety posture).

3. **Fresh Rust SMB client** — written from scratch, using `pavao = "0.10"` and `smb-rs` as reference. The fresh implementation is the same choice Decision 10 made for the server (per ADR-105); the client follows the same logic.

Workshop Decision 11 §12 specifies that the SDK's `FileModule` "provides an SMB client (using `pavao = "0.10"` or the framework's own SMB client implementation, depending on `pavao`'s maturity) for accessing `\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\`". This ADR locks the choice: the framework's own Rust SMB client, not `pavao`, because `pavao` does not support persistent-handle reconnect.

## Decision

The framework's Client SDK ships a **fresh Rust SMB client** (`adrian-smb-client`) as the `FileModule`'s underlying transport. The client is async (`tokio`), memory-safe (Rust), and supports `DH2Q`/`DH2C` persistent-handle reconnect for CA shares. The client does not use Samba `libsmbclient`, does not use platform-native kernel clients (`mrxsmb20.sys`, SMBX, `cifs.ko`), and does not use `pavao` as the primary path (it is used as reference only). The client is exposed to SDK consumers via the `FileModule` API (per Decision 11 §12) and to platform-native consumers via the C ABI / JNI / Swift / Python / Go bindings.

### Concrete specification

1. **Rust crate.** The SMB client is `adrian-smb-client` (workspace member, library). Crates: `tokio = "1"` (async runtime), `tokio-util = "0.7"` (codec for length-delimited SMB2 frames), `bytes = "1"`, `nom = "7"` (binary parsing for SMB2 packets — shared with `adrian-smb-core` per ADR-105), `aes-gcm = "0.10"` (AES-128-GCM, AES-256-GCM decryption), `sha2 = "0.10"` (SHA-512 preauth integrity), `hmac = "0.12"` (HMAC for SMB 2.x signing), `gss-api = "0.1"` (Kerberos via MIT krb5 per [ADR-049](./ADR-049-standardize-mit-krb5.md)), `ntlm = "0.1"` (NTLMSSP — hand-rolled; shared with `adrian-smb-auth` per ADR-105), `rustls = "0.23"` (TLS for SMB Direct, optional), `tracing = "0.1"`, `thiserror = "1"`. The client reuses `adrian-smb-core` (the SMB2/3 protocol data structures and packet parsers shared with the server per ADR-105) — no protocol-parsing code is duplicated between client and server.

2. **Public API.** The client exposes a high-level API for SDK consumers:
   ```rust
   pub struct SmbClient { /* ... */ }
   impl SmbClient {
       pub async fn connect(&self, server: &str, share: &str) -> Result<TreeConnect, SmbError>;
       pub async fn create(&self, tree: &TreeConnect, path: &str, disposition: CreateDisposition, options: CreateOptions) -> Result<FileHandle, SmbError>;
       pub async fn read(&self, handle: &FileHandle, offset: u64, length: u32) -> Result<Vec<u8>, SmbError>;
       pub async fn write(&self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<u32, SmbError>;
       pub async fn close(&self, handle: FileHandle) -> Result<(), SmbError>;
       pub async fn query_directory(&self, handle: &FileHandle, pattern: &str) -> Result<Vec<DirEntry>, SmbError>;
   }
   pub struct FileHandle { client_guid: Uuid, persistent_id: u64, volatile_id: u64, tree: TreeConnect, /* ... */ }
   ```
   The `FileHandle` carries the `client_guid` and `persistent_id` needed for `DH2C` reconnect. The client persists these to disk (via the SDK's credential-cache mechanism) so that a process restart can resume an open after a server failover.

3. **Persistent-handle reconnect (DH2Q / DH2C).** When `SmbClient::create` is called with `CreateOptions::persistent_handle = true` (the default for CA-share opens), the client issues `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` with `SMB2_DHANDLE_FLAG_PERSISTENT` in the create context. The server's response includes `SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2` with the `PersistentFileId`. The client stores `(client_guid, persistent_id, volatile_id, tree_id, session_id)` in the `FileHandle` and persists it to disk via the SDK's credential-cache mechanism (`/var/lib/adrian/smb-handles/<handle-uuid>.json` on Linux; equivalent paths on Windows/macOS). If the SMB session is interrupted (TCP RST, server crash, network partition), the client attempts `DH2C` reconnect: it opens a new TCP connection to the server (or a different server in the cluster, per the share's CA-failover hint), issues `SMB2_NEGOTIATE` with the same `ClientGuid`, issues `SMB2_SESSION_SETUP` with the persisted `SessionId` (or re-authenticates if the session is expired), issues `SMB2_TREE_CONNECT` to the same share, and issues `SMB2_CREATE` with `SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2` containing the persisted `PersistentFileId`. The server resolves the persistent handle from the cluster-wide handle table (per ADR-105 §9), re-opens the file at the OS level, replays the saved state (byte offset, oplock state, lease state, brl state), and returns the resumed handle to the client. The client resumes I/O without losing the open. The reconnect time budget is 30 seconds (matching ADR-105's CA-share failover SLO); if reconnect fails within 30 seconds, the client returns `SmbError::PersistentHandleReconnectFailed` to the caller.

4. **Dialect negotiation.** The client negotiates SMB 3.1.1 by default, falling back to 3.0.2 / 3.0 / 2.1 / 2.0.2 if the server does not support 3.1.1. The client refuses SMB1 (per [ADR-043](./ADR-043-drop-smb1-support.md)). The client's `Negotiate` request advertises SHA-512 preauth integrity and AES-256-GCM/AES-128-GCM encryption (matching ADR-105's server-side defaults).

5. **Authentication.** The client uses the SDK's `AuthModule` (per Decision 11 §7) to acquire a Kerberos service ticket for `cifs/<host-fqdn>@<realm>` (via MIT krb5 per ADR-049). The client wraps the ticket in SPNEGO for `SMB2_SESSION_SETUP`. NTLM fallback is supported only when explicitly enabled (`smb.auth.ntlm = "allowed"` per ADR-105 §6) for stranded clients that cannot use Kerberos.

6. **SYSVOL access.** The SDK's `FileModule` (per Decision 11 §12) uses the SMB client for read-only access to `\\<domain>\SYSVOL\` and `\\<domain>\NETLOGON\` for policy distribution. The `FileModule` does not request persistent handles for SYSVOL reads (SYSVOL is read-only on the client side; a reconnect after failover re-opens the file at the same path without state loss). For user home shares and other writable shares, the `FileModule` requests persistent handles by default so that file-editing sessions survive server failover.

7. **Mount-style access (optional).** For customers who want a traditional mount-point experience (e.g., `mount -t adrian //server/share /mnt/share`), the SDK ships a FUSE integration on Linux (`adrian-smb-fuse` binary, using `fuser = "0.13"`), a WinFSP integration on Windows (`adrian-smb-winfs` binary, using the `winfsp` C library via FFI), and a macOS macFUSE integration (`adrian-smb-macfuse` binary). The mount-style integrations wrap the Rust SMB client; they are not the primary API (the `FileModule` API is the primary), but they support legacy applications that expect a filesystem path. The mount-style integrations inherit the persistent-handle reconnect behavior of the underlying client.

8. **No `pavao` as primary path.** `pavao = "0.10"` is referenced for ASN.1/SPNEGO/Negotiate packet structure (per Decision 11 §12 and ADR-105 Alternative C), but it is not the primary client library because (a) `pavao` does not support persistent-handle reconnect (`DH2Q`/`DH2C`) — it is a client-only library focused on basic file operations; (b) `pavao`'s async API is not `tokio`-native (it uses `smol`), requiring an async-runtime bridge that adds complexity; (c) `pavao`'s license (MIT) is compatible but its maintenance cadence (single maintainer) is a risk for an enterprise SDK. The framework's fresh client reuses `adrian-smb-core`'s protocol data structures (shared with the server), so the protocol-parsing code is written once and used by both client and server.

9. **Cross-platform operation.** The client runs on Linux (the primary platform for SDK consumers), Windows, and macOS. The client's TLS, TCP, and Kerberos dependencies are pure-Rust (`rustls`, `tokio`, `gss-api`), so there are no platform-native library dependencies. The client's persistent-handle cache is stored at platform-appropriate paths: `/var/lib/adrian/smb-handles/` on Linux, `C:\ProgramData\Adrian\smb-handles\` on Windows, `/Library/Adrian/smb-handles/` on macOS.

10. **Caching.** The client caches directory enumerations (`query_directory` results) in an in-process `moka` LRU (1000 entries, 30-second TTL) to reduce SMB round-trips for repeated `ls` calls. The client does not cache file contents (file-content caching is the responsibility of the caller; the SDK's `FileModule` provides a read-through cache for SYSVOL reads but not for general file reads). The client caches session-establishment state (Negotiate + Session Setup) for 5 minutes per `(server, user)` pair to reduce auth round-trips for repeated connections.

11. **Observability.** The client emits Prometheus metrics (`adrian_smb_client_connections_total{server,result}`, `adrian_smb_client_creates_total{share,persistent,result}`, `adrian_smb_client_reads_bytes_total`, `adrian_smb_client_writes_bytes_total`, `adrian_smb_client_reconnects_total{result}`, `adrian_smb_client_persistent_handle_reconnects_total{result}`). OpenTelemetry traces cover the per-operation path (Negotiate → Session Setup → Tree Connect → Create → Read/Write → Close). Audit logs (per [ADR-060](./ADR-060-structured-audit-logs-otel.md)) record every tree connect, file create, and file delete.

12. **AD FS migration (SMB-client-specific).** Customers migrating from Windows file servers (where the SMB client is `mrxsmb20.sys` invoked via `WNet` API or UNC paths) do not need to migrate their SMB client code — the framework's SDK is for framework-enrolled hosts that need programmatic SMB access to framework-hosted shares. Customers with existing `WNet`-based applications on Windows continue to use `mrxsmb20.sys` (which works against the framework's SMB server per ADR-105's MS-SMB2 wire compatibility); the SDK's SMB client is for applications that need the persistent-handle reconnect guarantee or that run on non-Windows platforms.

## Rationale

The framework chose a fresh Rust SMB client over Samba `libsmbclient` for the same reasons Decision 10 chose a fresh Rust server: GPLv3 license incompatibility, embedding difficulty, and memory-safety posture. `libsmbclient` is C, with an awkward API for Rust FFI; it carries Samba's 90+ CVE history; and it inherits Samba's GPLv3 license, which is incompatible with the framework's Apache-2.0 posture. The fresh Rust client shares `adrian-smb-core` with the server, so the protocol-parsing code is written once and audited once.

The framework chose a fresh Rust SMB client over platform-native kernel clients (`mrxsmb20.sys`, SMBX, `cifs.ko`) because (a) platform-native clients are not embeddable in a userspace SDK (the SDK's `FileModule` must run in-process, not as a kernel module); (b) platform-native clients are platform-specific, defeating cross-platform parity (one code path per platform); (c) platform-native clients do not expose a stable programmatic API for persistent-handle control (Windows `WNet` is high-level; macOS SMBX has no programmatic API; Linux `cifs.ko` is kernel-internal); (d) macOS SMBX has known persistent-handle quirks per [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md), making it unreliable for CA-share access.

The framework chose a fresh Rust SMB client over `pavao` as the primary path because `pavao` does not support persistent-handle reconnect (`DH2Q`/`DH2C`), which is the central requirement of PC-081. `pavao` is a fine library for basic SMB file operations, but it does not meet the framework's CA-share requirement. The fresh client reuses `adrian-smb-core`'s protocol data structures (shared with the server), so the protocol-parsing code is written once.

The persistent-handle reconnect design (persisting `client_guid`, `persistent_id`, `volatile_id`, `tree_id`, `session_id` to disk) is the standard CA-share client pattern documented in MS-SMB2 §3.2.7. The 30-second reconnect budget matches ADR-105's server-side CA-failover SLO. The disk persistence enables process-restart reconnect (a client process that crashes and restarts can resume its persistent handles), which is a stronger guarantee than Windows `mrxsmb20.sys` provides (the kernel client survives process restart but not OS reboot; the framework's SDK client survives both).

## Consequences

**Positive**. The framework's SDK ships a single SMB client (Rust) that works identically on Linux, Windows, and macOS — no platform-divergent client code. The client supports persistent-handle reconnect for CA shares, enabling file-editing sessions to survive server failover without loss. The client is memory-safe (Rust), eliminating the buffer-overflow/use-after-free class of bugs that `libsmbclient` carries. The client reuses `adrian-smb-core` with the server, so protocol-parsing code is written once and audited once. The client's disk-persisted handle cache enables process-restart reconnect, a stronger guarantee than platform-native kernel clients.

**Negative**. The fresh implementation is engineering effort on top of ADR-105's server effort (~8 person-weeks for the client, shared protocol-core code with the server). The client does not provide kernel-level filesystem integration (no VFS mount on Linux, no `srv2.sys`-equivalent on Windows); customers who need a traditional mount-point experience use the FUSE/WinFSP/macFUSE integrations (per §7), which add a userspace filesystem layer with its own performance characteristics. The client's persistent-handle cache is a new on-disk state that must be cleaned up on host unenrollment (the SDK's `adrian-cli unjoin` deletes the cache).

**Neutral**. Customers with existing `WNet`-based applications on Windows continue to use `mrxsmb20.sys` against the framework's SMB server (per ADR-105's wire compatibility); the SDK's SMB client is for applications that need the persistent-handle guarantee or that run on non-Windows platforms. Customers with existing `libsmbclient`-based applications must migrate to the SDK's `FileModule` API (the framework's migration guide documents the API mapping).

**Implementation cost**. ~8 person-weeks for v1 (part of the SDK's 30-pw budget per Decision 11): client core (3 pw, shared protocol core with server), persistent-handle reconnect (2 pw, highest-risk), SPNEGO + Kerberos (1 pw, shared with server), FUSE/WinFSP/macFUSE integrations (1 pw), caching + observability (1 pw).

**Operational impact**. SDK consumers use the `FileModule` API (per Decision 11 §12); the SMB client is transparent. Operators manage the persistent-handle cache via `adrian-cli file handles list` / `adrian-cli file handles purge`. The framework's `adrian-cli file mount //server/share /mnt/share` command wraps the FUSE/WinFSP/macFUSE integration for mount-style access.

## Alternatives Considered

### Alternative A: Samba `libsmbclient` as the SDK's SMB client

The SDK's `FileModule` calls `libsmbclient` via Rust FFI. Rejected because (a) GPLv3 license — Samba's `libsmbclient` is GPLv3, incompatible with the framework's Apache-2.0; (b) `libsmbclient`'s C API is awkward to call from Rust (manual memory management, opaque `SMBCCTX*` handles, callback-based auth); (c) `libsmbclient` carries Samba's 90+ CVE history (memory-corruption bugs in the SMB parsing layers); (d) `libsmbclient`'s persistent-handle support is incomplete (it supports durable handles v1 but not v2 with `DH2C` reconnect — the framework needs v2 for CA shares per ADR-105).

### Alternative B: Platform-native kernel clients (`mrxsmb20.sys` on Windows, SMBX on macOS, `cifs.ko` on Linux)

The SDK's `FileModule` calls platform-native APIs (`WNet` on Windows, `mount_smbfs` on macOS, `mount -t cifs` on Linux). Rejected because (a) platform-native clients are not embeddable in a userspace SDK (the SDK's `FileModule` must run in-process, not as a kernel module); (b) platform-native clients are platform-specific, requiring three separate code paths (defeating cross-platform parity per Decision 11); (c) platform-native clients do not expose a stable programmatic API for persistent-handle control — Windows `WNet` is high-level (file-open by UNC path, no persistent-handle options); macOS SMBX has no programmatic API at all (only `mount_smbfs`); Linux `cifs.ko` is kernel-internal (no userspace API for persistent handles); (d) macOS SMBX has known persistent-handle quirks per [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md), making it unreliable for CA-share access.

### Alternative C: `pavao` as the SDK's SMB client

The SDK's `FileModule` uses `pavao = "0.10"` directly. Rejected as the primary path because (a) `pavao` does not support persistent-handle reconnect (`DH2Q`/`DH2C`) — it is a client-only library focused on basic file operations; without persistent-handle reconnect, the SDK cannot meet PC-081's CA-share requirement; (b) `pavao`'s async API is not `tokio`-native (it uses `smol`), requiring an async-runtime bridge that adds complexity and breaks the SDK's `tokio`-native contract (per Decision 11 §1); (c) `pavao`'s maintenance cadence (single maintainer) is a risk for an enterprise SDK; (d) `pavao` does not share protocol-parsing code with the server (it has its own implementation), so the framework would maintain two SMB protocol parsers (server in `adrian-smb-core`, client in `pavao`), doubling the audit surface. `pavao` is used as reference for ASN.1/SPNEGO/Negotiate packet structure (per Decision 11 §12).

### Alternative D: Mount-style access only (no programmatic SDK API)

The SDK's `FileModule` does not provide a programmatic API; customers use the FUSE/WinFSP/macFUSE mount-style integrations exclusively. Rejected because (a) mount-style integrations add a userspace filesystem layer with its own performance characteristics (FUSE on Linux has per-syscall context-switch overhead; WinFSP on Windows has similar overhead); (b) mount-style integrations are not available in all deployment contexts (containers without `--privileged` cannot use FUSE; macOS requires macFUSE installation); (c) the SDK's value proposition includes a programmatic API for applications that need direct SMB access (e.g., a backup agent that reads files via SMB without mounting); (d) Decision 11 §12 explicitly specifies a `FileModule` programmatic API. The mount-style integrations are supported as an optional layer (per §7) on top of the programmatic API.

## Open Questions

- Should the SDK's SMB client support SMB multichannel (multiple TCP connections per session for aggregate throughput)? Current decision: yes in v1.1 — multichannel is important for high-throughput workloads (backup agents, video editing) but adds complexity (the client must coordinate multichannel state across persistent-handle reconnect). v1 ships single-channel only.
- Should the SDK's SMB client support SMB Direct (RDMA)? Current decision: no in v1 — SMB Direct is Linux-only and rare in enterprise client deployments. Revisit in v1.1 if customer demand warrants.
- Should the SDK's SMB client support oplocks (lease-based caching)? Current decision: yes in v1 — oplocks are required for performance on file-editing workloads (the client caches file metadata and content while it holds the oplock). The client requests oplocks on `create` by default; the server grants or denies based on the share's oplock policy.
- Should the persistent-handle cache be encrypted at rest? Current decision: no in v1 — the cache contains only `client_guid`, `persistent_id`, `volatile_id`, `tree_id`, `session_id` (no file contents, no credentials); the `session_id` is opaque to the client and is only valid while the server's session is alive. Revisit if security review identifies a risk.

## Cross-capability impact

- **File Gateway (PC-078 — SMB 3.1.1 server).** Addressed in [ADR-105](./ADR-105-fresh-rust-smb3-server.md). The client and server share `adrian-smb-core` for protocol data structures.
- **File Gateway (PC-079 — SMB1 removal).** Addressed in [ADR-043](./ADR-043-drop-smb1-support.md). The client refuses SMB1 negotiation.
- **File Gateway (PC-080 — DFS-N).** Addressed in [ADR-044](./ADR-044-dfs-n-via-dns-srv.md). The client follows DFS-N referrals via the framework's DNS SRV records.
- **File Gateway (PC-082 — ABE).** Addressed in [ADR-045](./ADR-045-abe-precomputed-index.md). The client receives ABE-filtered directory listings from the server; the client does not perform client-side ABE.
- **Client SDK (PC-085 — universal SDK).** Addressed by Decision 11. The SMB client is the `FileModule`'s underlying transport.
- **Client SDK (PC-091 — domain join).** Addressed by Decision 11 §9. The SMB client uses the host's machine Kerberos ticket (acquired during domain join) for authentication.
- **Core Directory.** The SMB client does not directly query the directory; the SDK's `DirectoryModule` does. The SMB client authenticates via the SDK's `AuthModule` (which uses MIT krb5 per ADR-049).
- **KDC.** The SMB client validates Kerberos tickets via the framework's KDC; the client's SPN (`cifs/<host-fqdn>`) is registered during host enrollment.
- **Policy Engine (Workshop Decision 7).** The `FileModule` provides the SDK's policy daemon with read-only SYSVOL access for policy distribution.
- **Operations (ADR-058).** The SDK runs as a StatefulSet sidecar in container-native deployments; the SDK's container image is the same across all platforms.
- **Migration (PC-130 SYSVOL migration).** The `FileModule` is the SDK-side consumer of the Git-backed SYSVOL-equivalent share.

## References

- [PC-081](../catalog/07-file-gateway.md) — problem statement
- [Workshop Decision 10](../workshop/decision-10-smb-server.md) — SMB server: fresh Rust SMB 3.1.1 server (server-side persistent-handle table)
- [Workshop Decision 11](../workshop/decision-11-client-sdk.md) — Client SDK: unified Rust core + platform-specific bindings (§12 FileModule)
- [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md) — `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2` structure, `CreateGuid` field, `DH2Q_FLAG_PERSISTENT` bit, lease break behavior during failover, Samba CTDB limitation
- [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md) — `ContinuouslyAvailable` registry flag, `SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE` bit in `TreeConnect.GetResponse`, CSV/SOFS prerequisite, persistent handle `DH2Q`/`DH2C` create contexts
- [ADR-043](./ADR-043-drop-smb1-support.md) — Drop SMB1 support (client refuses SMB1)
- [ADR-049](./ADR-049-standardize-mit-krb5.md) — MIT krb5 standardization (for SPNEGO initiator)
- [ADR-063](./ADR-063-unified-cross-platform-cli.md) — unified cross-platform CLI (`adrian-cli file` subcommand)
- [ADR-105](./ADR-105-fresh-rust-smb3-server.md) — Fresh Rust SMB 3.1.1 server (server-side persistent-handle table; client shares `adrian-smb-core`)
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2) — SMB2 protocol specification (§3.2.7 persistent-handle reconnect)
- [pavao](https://docs.rs/pavao) — Rust SMB client library (reference, not primary)
- [smb-rs](https://github.com/Avira/smb-rs) — emerging Rust SMB library (reference)
- [libsmbclient](https://www.samba.org/~gd/tmp/smbclient/docs/libsmbclient.html) — Samba client library (alternative considered and rejected)
