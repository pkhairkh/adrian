---
title: "File Gateway (SMB / DFS / Print) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: File Gateway
tags: [spec, file-gateway, smb, dfs, ipp, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# File Gateway (SMB / DFS / Print) — Technical Specification

## 1. Overview

The File Gateway ships a fresh Rust SMB 3.1.1 server with SHA-512 preauth integrity and AES-256-GCM encryption (no Samba, no `srv2.sys`), DFS-N-equivalent via DNS SRV records, Access-Based Enumeration via pre-computed per-share index, IPP Everywhere for print (MS-RPRN dropped, structurally eliminating PrintNightmare CVE-2021-34527), and Offline Files out of scope. The capability has zero blockers that block adoption but resolves three: PC-078 SMB 3.1.1 server, PC-079 SMB1 drop, PC-083 PrintNightmare mitigation.

Workshop Decision 10 rejected Samba (GPLv3 license conflict, embedding difficulty, memory-safety posture) and platform-native servers (Windows-only `srv2.sys`, closed-source macOS SMBX, no Linux equivalent). The fresh Rust implementation is ~15K lines targeting SMB 3.1.1 dialect with five fallback dialects for client compatibility. Pre-auth integrity hash (SHA-512 over the entire Negotiate exchange) is mixed into HKDF-SHA512 key derivation labeled `"SMBSigningKey"` / `"ServerIn"` / `"ServerOut"` per MS-SMB2 §3.2.5.2 — without it, a MITM can downgrade dialect negotiation. Authentication is Kerberos SPNEGO via GSSAPI preferred (SPN `cifs/<host-fqdn>@<realm>` registered at host enrollment); NTLM SPNEGO disabled by default per ADR-085.

The capability carries 7 ADRs: ADR-043 (drop SMB1), ADR-044 (DFS-N via DNS SRV), ADR-045 (ABE pre-computed index), ADR-046 (drop MS-RPRN, adopt IPP Everywhere), ADR-047 (Offline Files out of scope), ADR-105 (fresh Rust SMB 3.1.1 server), ADR-106 (SMB client in framework SDK). It resolves three of the framework's 23 blockers (PC-078 SMB 3.1.1, PC-079 SMB1 drop, PC-083 PrintNightmare). The capability is implemented as **four** Rust crates at Layer 3: `adrian-smb-server`, `adrian-smb-core`, `adrian-smb-client`, `adrian-print-service`. External dependencies include `tokio`, `rustls`, `ring`, `aes`, `aes-gcm`, `sha2`, `hmac`, `rasn`/`rasn-kerberos`, `gss-api`, `pavao` (SMB client reference), `hickory-server` (DNS).

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-smb-core` | 2 | SMB protocol primitives — dialect negotiation, preauth integrity hash, HKDF key derivation, signing, encryption, commands enum, struct definitions; shared by server and client | ADR-043, ADR-105 |
| `adrian-smb-server` | 3 | Fresh Rust SMB 3.1.1 server (~15K lines); dialects 2.0.2/2.1/3.0/3.0.2/3.1.1; SHA-512 preauth integrity (MS-SMB2 §3.2.5.1); AES-256-GCM mandatory for 3.1.1; AES-GMAC signing; TCP/445 only (no NetBIOS) | ADR-043, ADR-044, ADR-045, ADR-105 |
| `adrian-smb-client` | 3 | SMB client for SDK's `FileModule` (per ADR-106); persistent handles for SYSVOL access during GPO refresh; dialect fallback 3.1.1→3.0.2→3.0→2.1→2.0.2 | ADR-106 |
| `adrian-print-service` | 3 | IPP Everywhere (RFC 8011) print service; `cups` integration for legacy PostScript/PCL queues; MS-RPRN dropped (PrintNightmare structural mitigation) | ADR-046 |
| `adrian-smb-server` (cont.) | 3 | DFS-N-equivalent via DNS SRV records (`_smb._tcp.<domain>`); no DFS-R (Windows-only); framework-native Git-backed file distribution for roaming profiles | ADR-044 |
| `adrian-smb-server` (cont.) | 3 | ABE via pre-computed per-share index in FDB subspace 0x0D; index rebuilt on ACL change with 5-second eventual consistency; `FindFirst`/`FindNext` filtered server-side | ADR-045 |
| `adrian-smb-server` (cont.) | 3 | Offline Files out-of-scope banner; recommend sync clients (Syncthing, ownCloud) | ADR-047 |

## 3. Key types and traits

```rust
// crates/adrian-smb-core/src/lib.rs (per ADR-105)

use rasn::types::OctetString;

/// SMB 2+ dialects supported (per ADR-043, ADR-105).
/// SMB1 unconditionally dropped (no LANMAN fallback).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dialect {
    Smb202,        // 0x0202 — SMB 2.0.2 (Windows Server 2008)
    Smb210,        // 0x0210 — SMB 2.1 (Windows 7 / Server 2008 R2)
    Smb300,        // 0x0300 — SMB 3.0 (Windows 8 / Server 2012)
    Smb302,        // 0x0302 — SMB 3.0.2 (Windows 8.1 / Server 2012 R2)
    Smb311,        // 0x0311 — SMB 3.1.1 (Windows 10 / Server 2016+) — preferred
}

/// Preauth integrity hash per MS-SMB2 §3.2.5.1.
/// SHA-512 over the entire Negotiate exchange, mixed into
/// HKDF-SHA512 key derivation. Without it, a MITM can downgrade
/// dialect negotiation.
pub struct PreauthIntegrityHash {
    pub algorithm: PreauthIntegrityAlg,    // SHA-512 mandatory
    pub hash: [u8; 64],
}

pub enum PreauthIntegrityAlg { Sha512 }

/// HKDF-SHA512 key derivation per MS-SMB2 §3.2.5.2.
/// Labels: "SMBSigningKey", "ServerIn", "ServerOut",
///         "ClientIn", "ClientOut", "SMBEncryptionKey"
pub fn derive_key(
    preauth_hash: &[u8],
    session_id: u64,
    label: &str,
    context: Option<&[u8]>,
) -> Zeroizing<[u8; 32]>;

/// Encryption algorithms supported (per ADR-105).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionAlg {
    Aes256Ccm,     // AES-256-CCM (SMB 3.0+)
    Aes256Gcm,     // AES-256-GCM (SMB 3.1.1) — mandatory for 3.1.1
}

/// Signing algorithms supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningAlg {
    HmacSha256,    // AES-128-CMAC (SMB 3.0) — deprecated
    AesGmac,       // AES-GMAC (SMB 3.1.1) — preferred
}
```

```rust
// crates/adrian-smb-server/src/lib.rs (per ADR-105)

use adrian_smb_core::{Dialect, EncryptionAlg};
use tokio::net::TcpListener;

pub struct SmbServer {
    listener: TcpListener,                // TCP/445 only, no NetBIOS
    shares: DashMap<String, Share>,
    identity: Arc<dyn IdentityMapping>,
    pac_validator: Arc<dyn PacValidator>,
    abe_index: Arc<AbeIndex>,             // per-share ABE index per ADR-045
    config: SmbServerConfig,
}

impl SmbServer {
    pub async fn run(&self) -> Result<(), SmbError>;

    /// Handle SMB Negotiate (first command of every connection).
    /// Verifies client-dialect list intersects server-supported set;
    /// SHA-512 preauth integrity hash computed and stored for
    /// subsequent key derivation.
    pub async fn handle_negotiate(
        &self,
        req: NegotiateRequest,
    ) -> Result<NegotiateResponse, SmbError>;

    /// Handle SMB Session Setup (SPNEGO).
    /// Preferred: Kerberos SPNEGO (SPN cifs/<host-fqdn>@<realm>).
    /// Disabled by default: NTLM SPNEGO (per ADR-085).
    pub async fn handle_session_setup(
        &self,
        req: SessionSetupRequest,
        preauth_hash: &PreauthIntegrityHash,
    ) -> Result<SessionSetupResponse, SmbError>;

    /// Handle Tree Connect (per share).
    /// Validates share name, checks share-level ACL, returns TreeId.
    pub async fn handle_tree_connect(
        &self,
        req: TreeConnectRequest,
        principal: &Principal,
    ) -> Result<TreeConnectResponse, SmbError>;
}

/// ABE index (per ADR-045).
/// Pre-computed per-share in FDB subspace 0x0D.
/// Rebuilt on ACL change with 5-second eventual consistency.
pub struct AbeIndex {
    share_uuid: Uuid,
    store: Arc<dyn DirectoryStore>,
    cache: Cache<Uuid, AbeEntry>,         // 5-sec TTL
}

impl AbeIndex {
    /// Filter FindFirst/FindNext results server-side per ADR-045.
    /// Returns only entries the caller can see based on SD.
    pub async fn filter_listing(
        &self,
        parent_dnt: u64,
        caller_sids: &[Sid],
    ) -> Result<Vec<DirEntry>, SmbError>;

    /// Trigger rebuild when ACL on a child changes.
    pub async fn rebuild_for_subtree(&self, root_dnt: u64) -> Result<(), SmbError>;
}
```

```rust
// crates/adrian-smb-client/src/lib.rs (per ADR-106)

pub struct SmbClient {
    config: SmbClientConfig,
    runtime: tokio::runtime::Handle,
}

impl SmbClient {
    /// Persistent handle support — handles survive DC failover via
    /// Raft state machine replication (per ADR-058).
    pub async fn connect(&self, share_url: &str) -> Result<SmbSession, SmbError>;

    pub async fn list_dir(&self, session: &SmbSession, path: &str)
        -> Result<Vec<DirEntry>, SmbError>;
    pub async fn read_file(&self, session: &SmbSession, path: &str)
        -> Result<Vec<u8>, SmbError>;
    pub async fn write_file(&self, session: &SmbSession, path: &str, data: &[u8])
        -> Result<(), SmbError>;
}

/// Used by the SDK's FileModule for SYSVOL access during GPO refresh.
pub async fn read_sysvol_policy(share_url: &str, policy_uuid: Uuid)
    -> Result<Vec<u8>, SmbError>;
```

```rust
// crates/adrian-print-service/src/lib.rs (per ADR-046)

/// IPP Everywhere (RFC 8011) print service. No MS-RPRN
/// (PrintNightmare CVE-2021-34527 structural mitigation — no
/// spoolsv.exe, no driver install path that runs as SYSTEM).
pub struct PrintService {
    ipp_listener: TcpListener,            // TCP/631
    cups_integration: Option<CupsBackend>,// legacy PostScript/PCL queues
    config: PrintConfig,
}

impl PrintService {
    pub async fn handle_ipp_request(&self, req: IppRequest)
        -> Result<IppResponse, PrintError>;
    pub async fn list_printers(&self) -> Result<Vec<Printer>, PrintError>;
    pub async fn submit_job(&self, printer: &str, document: &[u8])
        -> Result<JobId, PrintError>;
}
```

## 4. Data model

```
FDB subspaces used by File Gateway:

  (0x0D, 0x01, share_uuid, parent_dnt:u64, child_dnt:u64)  — ABE index per ADR-045
    val: (allowed_sids: Vec<Sid>, denied_sids: Vec<Sid>, inherit_flags: u8)
    // Rebuilt on ACL change with 5-second eventual consistency.
    // FindFirst/FindNext filtered server-side using this index.

  (0x01, dnt(share_object), ATT_SHARE_PATH, _)
    → filesystem path backing the share (e.g. /var/adrian-shares/data/)

  (0x01, dnt(share_object), ATT_SHARE_ACL, _)
    → share-level Security Descriptor (who can connect to the share)

  (0x01, dnt(file_object), ATT_NT_SECURITY_DESCRIPTOR, _)
    → file-level SD (ref-counted via 0x03 sdtable per ADR-004)

  (0x0D, 0x02, share_uuid, handle_id:u64)  — persistent handles per ADR-106
    val: (path: String, lease_id: u64, principal_sid: Sid, expires_at: u64)
    // Survive DC failover via Raft replication of subspace 0x0D.

DFS-N equivalent (per ADR-044):
  DNS SRV records:
    _smb._tcp.<domain>            SRV 0 100 445 dc01.<domain>.
    _smb._tcp.<domain>            SRV 0 100 445 dc02.<domain>.
    _smb._tcp.<site>._sites.<domain>  SRV 0 100 445 dc01.<domain>.  (site-scoped)
  No DFS-R replication (Windows-only). Framework-native Git-backed
  file distribution for roaming profiles (per ADR-044) — sync client
  pushes profile changes to framework Git, hosts pull on login.

Share types:
  File share        — \\server\share → /var/adrian-shares/<share>/ on backing FS
  IPC$ share        — \\server\IPC$ → named pipes (adrian-cli RPC interface)
  Print$ share      — \\server\print$ → driver store (NOT EXECUTED per ADR-046;
                     drivers stored as reference, not loaded as code)
  SYSVOL share      — \\domain\SYSVOL → Git-backed policy repo via ADR-094
  NETLOGON share    — \\domain\NETLOGON → legacy logon scripts (read-only)

SMB 3.1.1 dialect on-wire state (per ADR-105):
  Negotiate exchange:
    1. Client → Negotiate Request (dialect list, capabilities, client GUID)
    2. Server → Negotiate Response (selected dialect, server GUID,
                cipher list, preauth integrity alg list, GSS/NLVM token)
  Preauth integrity hash (SHA-512) computed incrementally over both
  Negotiate messages; mixed into HKDF for Session Setup key derivation.
  Session Setup:
    3. Client → Session Setup Request 1 (SPNEGO NegTokenInit with Kerberos)
    4. Server → Session Setup Response (SPNEGO NegTokenResp, session ID)
    5. Client → Session Setup Request 2 (SPNEGO NegTokenResp final)
    6. Server → Session Setup Response (final, SessionFlags set)
  Tree Connect:
    7. Client → Tree Connect Request (\\server\share)
    8. Server → Tree Connect Response (TreeId, share type, maximal access)

Encryption:
  SMB 3.0+  — AES-256-CCM (per-message encryption)
  SMB 3.1.1 — AES-256-GCM (mandatory for 3.1.1 dialect)
  Each message: SMB2 TRANSFORM_HEADER prepended, body encrypted,
                signature computed via AES-GMAC over the header + ciphertext.
```

## 5. Protocol surface

```
SMB wire protocol (per MS-SMB2, ADR-105):

  TCP/445   — SMB direct (no NetBIOS over TCP 137-139)
  No UDP    — TCP only
  TLS       — not used (encryption is SMB-layer AES-GCM, not TLS)

SMB commands implemented (per MS-SMB2 §3.3.5):
  0x0000 NEGOTIATE              — dialect/capability negotiation
  0x0001 SESSION_SETUP          — SPNEGO auth (Kerberos preferred)
  0x0002 LOGOFF                 — session teardown
  0x0003 TREE_CONNECT           — connect to share
  0x0004 TREE_DISCONNECT
  0x0005 CREATE                 — open file/dir/named pipe
  0x0006 CLOSE                  — close handle (optionally persistent)
  0x0007 FLUSH
  0x0008 READ                   — read from file
  0x0009 WRITE                  — write to file
  0x000A LOCK                   — byte-range lock
  0x000B IOCTL                  — passthrough IOCTL
  0x000C CANCEL                 — cancel pending request
  0x000D ECHO                   — keepalive
  0x000E QUERY_DIRECTORY        — FindFirst / FindNext (ABE-filtered)
  0x000F CHANGE_NOTIFY          — directory change notification
  0x0010 QUERY_INFO             — file info (basic, standard, security, etc.)
  0x0011 SET_INFO
  0x0012 OPLOCK_BREAK           — oplock downgrade notification

SMB TRANSFORM_HEADER (per MS-SMB2 §2.2.41):
  EncryptionAlgorithm (AES-256-GCM for 3.1.1)
  Nonce (12 bytes, monotonic per session)
  Signature (16 bytes, AES-GMAC over header + ciphertext)

SMB3 multi-channel (per ADR-105 v2):
  Client opens multiple TCP connections to same server, each gets
  unique SessionId-via-ChannelSequence; bandwidth aggregated.

SMB Direct (RDMA) (per ADR-105, opt-in via rust-rdma FFI):
  Linux-only in v1; requires InfiniBand or RoCE NIC.
  Set smb.direct = "enabled" in server config.

IPP wire protocol (per RFC 8011, ADR-046):
  TCP/631    — IPP over HTTP
  HTTP POST /ipp  with Content-Type: application/ipp
  IPP operations:
    0x0002 Print-Job
    0x0003 Validate-Job
    0x0004 Create-Job
    0x0005 Send-Document
    0x0006 Cancel-Job
    0x0007 Get-Job-Attributes
    0x0008 Get-Jobs
    0x0009 Get-Printer-Attributes
    0x000A Hold-Job
    0x000B Release-Job
    0x000C Restart-Job
    0x0010 Pause-Printer
    0x0011 Resume-Printer
    0x0013 Set-Printer-Attributes
  IPP Everywhere (driverless): printer advertises document formats
  via Get-Printer-Attributes response (application/pdf, image/jpeg,
  image/urf). No driver install — print client converts document to
  supported format and submits.

cups integration (per ADR-046):
  Backend: cupsPrintFile() via libcups FFI
  Used for legacy PostScript/PCL queues only (rare in greenfield)
  NOT for driver install — drivers stored as reference, not executed
```

## 6. Configuration

```toml
# /etc/adrian/smb-server.toml — SMB server configuration

[server]
listen_addr            = "0.0.0.0:445"
max_connections        = 8192
dialects_supported     = ["smb202", "smb210", "smb300", "smb302", "smb311"]
default_dialect        = "smb311"                  # ADR-105
preauth_integrity      = "sha512"                  # mandatory per ADR-105
encryption_mandatory_311 = true                    # AES-256-GCM mandatory
signing_alg            = "aes-gmac"                # SMB 3.1.1 default
signing_required       = true
smb_direct_enabled     = false                     # RDMA, Linux-only in v1
multichannel_enabled   = false                     # v2

[auth]
spnego_preferred       = "kerberos"                # SPN cifs/<fqdn>@<realm>
ntlm_spnego_allowed    = false                     # per ADR-085
anonymous_allowed      = false                     # never on file shares
guest_allowed          = false                     # never
kerberos_pac_validation = true                     # per ADR-083
pac_full_checksum_required = true                  # per ADR-123

[shares]
  [shares.data]
  path                   = "/var/adrian-shares/data"
  description            = "Department file share"
  abe_enabled            = true                    # per ADR-045
  share_acl              = "S-1-5-21-...(Allow:FullControl)"
  continuously_available = false                   # v2
  encrypt_data           = true

  [shares.sysvol]
  path                   = "/var/adrian-shares/sysvol"   # Git-backed per ADR-094
  description            = "SYSVOL policy share"
  abe_enabled            = false
  share_acl              = "Authenticated Users:Read"
  read_only              = true

  [shares.netlogon]
  path                   = "/var/adrian-shares/netlogon"
  description            = "Legacy logon scripts (read-only)"
  share_acl              = "Authenticated Users:Read"
  read_only              = true

[dfs_n]                                # ADR-044
enabled                 = true
dns_srv_records         = true         # _smb._tcp.<domain>
site_aware              = true
roaming_profiles_via_git = true        # framework-native sync client

[abe_index]                            # ADR-045
rebuild_concurrency     = 8
eventual_consistency_secs = 5
cache_ttl_secs          = 5

[persistent_handles]                   # ADR-106
enabled                 = true
lease_timeout_secs      = 60
survive_dc_failover     = true         # Raft replication per ADR-058

[offline_files]                        # ADR-047
out_of_scope_banner     = true
recommend_sync_client   = "syncthing"

[print]                                # ADR-046
ipp_listen_addr         = "0.0.0.0:631"
ms_rprn_disabled        = true         # PrintNightmare structural mitigation
cups_integration        = false        # enable for legacy queues
driver_storage_share    = "print$"     # reference only, never executed

[audit]
otel_endpoint           = "http://otel-collector:4317"
emit_tree_connect       = true
emit_create             = true
emit_write              = true
emit_delete             = true
mitre_attack_mapping    = true

[observability]
prometheus_port         = 9105
auth_failure_rate_alert = 0.1
```

## 7. Error handling

```rust
// crates/adrian-smb-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum SmbError {
    #[error("SMB1 not supported (per ADR-043); client requested LANMAN dialect")]
    Smb1NotSupported,
    #[error("dialect negotiation failed: server={server:?}, client={client:?}")]
    DialectNegotiationFailed { server: Vec<Dialect>, client: Vec<Dialect> },
    #[error("preauth integrity hash mismatch — possible MITM")]
    PreauthIntegrityMismatch,
    #[error("encryption required for dialect 3.1.1; client did not advertise AES-256-GCM")]
    EncryptionRequired,
    #[error("signing required (server policy); client did not sign message")]
    SigningRequired,
    #[error("SPNEGO auth failed: {0}")]
    SpnegoFailed(String),
    #[error("NTLM SPNEGO disabled by policy (per ADR-085)")]
    NtlmDisabled,
    #[error("PAC validation failed: {0}")]
    PacValidationFailed(String),
    #[error("share not found: {0}")]
    ShareNotFound(String),
    #[error("access denied to {path}: {reason}")]
    AccessDenied { path: String, reason: String },
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("oplock conflict")]
    OplockConflict,
    #[error("byte-range lock conflict")]
    LockConflict,
    #[error("persistent handle expired: {0}")]
    HandleExpired(u64),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// crates/adrian-print-service/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum PrintError {
    #[error("IPP request malformed: {0}")]
    IppMalformed(String),
    #[error("printer not found: {0}")]
    PrinterNotFound(String),
    #[error("document format not supported by printer: {0}")]
    UnsupportedFormat(String),
    #[error("MS-RPRN disabled (per ADR-046); structural PrintNightmare mitigation")]
    MsRprnDisabled,
    #[error("cups integration disabled")]
    CupsDisabled,
    #[error("job rejected: queue full")]
    QueueFull,
}
```

**Error propagation.** SMB errors map to NTSTATUS codes per MS-SMB2 §3.3.4.1: `AccessDenied` → `0xC0000022 STATUS_ACCESS_DENIED`, `FileNotFound` → `0xC0000034 STATUS_OBJECT_NAME_NOT_FOUND`, `Smb1NotSupported` → `0xC00000BB STATUS_NOT_SUPPORTED`, `OplockConflict` → `0xC00000E5 STATUS_OPLOCK_NOT_GRANTED`. Print errors map to IPP status codes per RFC 8011 §13: `PrinterNotFound` → `0x040A not-found`, `UnsupportedFormat` → `0x040B attributes-not-supported`, `QueueFull` → `0x0501 printer-busy`. Every denied access emits an OTel audit event with MITRE ATT&CK mapping (`T1105 Ingress Tool Transfer`, `T1486 Data Encrypted for Impact`).

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - SMB dialect negotiation (server picks highest common dialect)
    - Preauth integrity hash SHA-512 computation
    - HKDF-SHA512 key derivation labeled "SMBSigningKey" / "ServerIn"
    - AES-256-GCM encrypt/decrypt round-trips
    - AES-GMAC signing verification
    - SPNEGO NegTokenInit/Resp round-trips
    - ABE index rebuild + lookup
    - Persistent handle expiration + recovery
    - IPP request/response round-trips
    - Share ACL enforcement
    - File SD inheritance

Integration tests — tests/integration/, real FDB + tokio
  Coverage:
    - Full SMB Negotiate → Session Setup → Tree Connect → Create →
      Read → Write → Close flow
    - SMB encryption mandatory enforcement (reject unencrypted 3.1.1)
    - SMB signing mandatory enforcement
    - ABE-filtered FindFirst/FindNext
    - DFS-N DNS SRV resolution
    - Persistent handle survival across simulated DC failover
    - SYSVOL share serving Git-backed policies (per ADR-094)
    - IPP Print-Job end-to-end against in-process print service
    - Cups integration (mock libcups)

Interop tests — tests/interop/
  Matrix:
    - Windows Server 2022 smbclient against framework SMB server
      (verify dialect 3.1.1, AES-256-GCM, AES-GMAC signing)
    - Samba 4.20 smbclient against framework SMB server
    - macOS 13+ smbclient against framework SMB server
    - Linux cifs-utils mount against framework SMB server
    - PowerShell New-SmbMapping against framework SMB server
    - cups client against framework IPP print service
    - iOS AirPrint against framework IPP print service

Property-based tests — proptest
  Parsers tested:
    - SMB2 command structures round-trips
    - SMB2 TRANSFORM_HEADER round-trips
    - Negotiate/Session Setup messages round-trips
    - IPP request/response round-trips
    - ABE index entries round-trips
  Corpus: 80+ property tests across SMB + print crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-105: fresh Rust SMB 3.1.1 server with SHA-512 preauth integrity
  - ADR-043: drop SMB1 (no LANMAN fallback)
  - AES-256-GCM encryption mandatory for 3.1.1
  - AES-GMAC signing
  - Kerberos SPNEGO auth (SPN cifs/<fqdn>@<realm>)
  - ADR-045: ABE via pre-computed per-share index in FDB subspace 0x0D
  - ADR-044: DFS-N-equivalent via DNS SRV records
  - ADR-046: IPP Everywhere print service (MS-RPRN dropped)

v1 (Phase 2):
  - ADR-106: full adrian-smb-client for SYSVOL access during GPO refresh
  - Continuously Available (CA) shares with persistent handles
    (survive DC failover via Raft replication per ADR-058)
  - SMB Direct (RDMA) opt-in via rust-rdma FFI (Linux-only)
  - Full persistent handle lifecycle (lease, break, recovery)
  - ADR-047: Offline Files out-of-scope banner + recommend sync client

v2 (Phase 3):
  - SMB multichannel (client opens multiple TCP connections)
  - Scale-out shares via FDB-backed metadata (share data on shared FS)
  - macOS SMBX interop testing (read-only compat for macOS clients)
  - SMB over QUIC (RFC 9405) for client-over-443
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1 | Async runtime + TCP listener |
| `rustls` | 0.23 | TLS (for management API; SMB uses SMB-layer crypto) |
| `ring` | 0.17 | HKDF-SHA512 key derivation |
| `aes` | 0.8 | AES block cipher for AES-256-GCM |
| `aes-gcm` | 0.10 | AES-256-GCM encryption (SMB 3.1.1 mandatory) |
| `sha2` | 0.10 | SHA-512 for preauth integrity hash |
| `hmac` | 0.12 | HMAC for older signing algorithms |
| `rasn` | 0.22 | ASN.1 + NDR for SMB structures |
| `rasn-kerberos` | 0.22 | Kerberos PAC types for auth |
| `gss-api` | 0.1 | GSSAPI bindings for SPNEGO |
| `pavao` | 0.1 | SMB client reference (for adrian-smb-client) |
| `hickory-server` | 0.24 | DNS server for DFS-N SRV records |
| `libcups-sys` | 0.1 | libcups FFI for legacy print queues |
| `rasn-pkix` | 0.22 | X.509 for TLS (management API only) |
| `zeroize` | 1.8 | Zeroize key material on drop |
| `thiserror` | 1 | SmbError + PrintError enums |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit events |
| `prometheus` | 0.13 | Metrics |
| `proptest` | 1 | Property-based tests |
| `uuid` | 1.10 | Share UUIDs, handle IDs |
| `adrian-storage-fdb` | * | FDB for ABE index (subspace 0x0D) |
| `adrian-identity-fdb` | * | IdentityMapping for SID lookup |
| `adrian-pac-validator` | * | PAC validation per ADR-083 |

## 11. References

- ADRs: [ADR-043](../adr/ADR-043-drop-smb1-support.md), [ADR-044](../adr/ADR-044-dfs-n-via-dns-srv.md), [ADR-045](../adr/ADR-045-abe-precomputed-index.md), [ADR-046](../adr/ADR-046-drop-msrprn-adopt-ipp-everywhere.md), [ADR-047](../adr/ADR-047-offline-files-out-of-scope.md), [ADR-058](../adr/ADR-058-container-native-dcs-operator.md), [ADR-083](../adr/ADR-083-pac-validation-rpc.md), [ADR-085](../adr/ADR-085-ntlm-client-only-rust-crate.md), [ADR-094](../adr/ADR-094-sysvol-replication-git-backed.md), [ADR-105](../adr/ADR-105-fresh-rust-smb3-server.md), [ADR-106](../adr/ADR-106-smb-client-persistent-handles-sdk-filemodule.md), [ADR-123](../adr/ADR-123-silver-ticket-mitigation.md)
- Workshop decisions: [Decision 10 — SMB Server](../workshop/decision-10-smb-server.md)
- KB files: [docs/07-file-print/01-smb-shares-internals.md](../docs/07-file-print/01-smb-shares-internals.md), [docs/07-file-print/02-dfs-n-dfs-r.md](../docs/07-file-print/02-dfs-n-dfs-r.md), [docs/07-file-print/03-print-services.md](../docs/07-file-print/03-print-services.md), [docs/02-protocols/03-smb-cifs-protocol.md](../docs/02-protocols/03-smb-cifs-protocol.md)
- RFCs: RFC 8011 (IPP/1.1), RFC 8010 (IPP/1.1 Encoding), RFC 9405 (SMB over QUIC), RFC 8446 (TLS 1.3, not directly used by SMB)
- MS-* specs: MS-SMB2 (SMB 2/3 Protocol), MS-SRVS (Server Service), MS-FSA (File System Algorithms), MS-RPRN (Print System, dropped per ADR-046), MS-DFSN (DFS Naming), MS-DV (Distributed File System: Replication, dropped)
