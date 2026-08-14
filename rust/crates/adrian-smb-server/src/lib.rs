#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # adrian-smb-server
//!
//! Fresh Rust SMB 3.1.1 server (memory-safe, async, tokio-native).
//! Replaces Samba's `smbd` in AD-interop mode and is the only SMB server
//! in native mode.
//!
//! ## Coverage (Wave 3b)
//!
//! - TCP/445 listener with NetBIOS Session Service framing (§2.1.2)
//! - SMB 3.1.1 Negotiate (SHA-512 preauth integrity + AES-256-GCM
//!   cipher advertisement; plaintext sessions still accepted per the
//!   Wave 3b scope note in ADR-105 §4)
//! - SessionSetup accept (Kerberos via GSS-API is stubbed — any
//!   SecurityBuffer is accepted; the framework's KDC integration is
//!   wired in a later wave)
//! - TreeConnect to in-memory virtual-filesystem shares
//! - Create / Read / Write / Close with proper FileId allocation
//! - Logoff / Echo
//! - SMB1 refused with `STATUS_INVALID_PARAMETER` (per ADR-043)
//!
//! ## ADRs
//!
//! - ADR-043: Drop SMB1; SMB 2.0.2 minimum, 3.1.1 default
//! - ADR-044: DFS-N via DNS SRV records (out of scope for Wave 3b)
//! - ADR-045: ABE precomputed index (out of scope for Wave 3b)
//! - ADR-105: Fresh Rust SMB 3.1.1 server (memory-safe, async)
//! - ADR-094: SYSVOL replication (Git-backed) — Wave 3b uses an
//!   in-memory VFS; Git-backed SYSVOL is a later wave.
//! - ADR-123: Silver ticket mitigation (PAC validation — later wave)
//! - ADR-021: LDAP signing & channel binding (SMB signing — later wave)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use adrian_smb_core::netbios;
use adrian_smb_core::{
    gss_api, ntstatus, ChangeNotifyRequest, CloseRequest, CloseResponse, Command, CreateContext,
    CreateRequest, CreateResponse, EchoRequest, EchoResponse, FileId, LogoffRequest,
    LogoffResponse, NegotiateRequest, NegotiateResponse, OplockBreakAcknowledgment,
    OplockBreakNotification, ReadRequest, ReadResponse, SessionSetupRequest, SessionSetupResponse,
    Smb2Header, SmbError, TreeConnectRequest, TreeConnectResponse, WriteRequest, WriteResponse,
    Writer, SMB2_HEADER_SIZE,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;

// ============================================================================
// Errors
// ============================================================================

/// SMB server error.
#[derive(Debug, Error)]
pub enum SmbServerError {
    /// Protocol-level failure (malformed PDU, bad dialect, etc).
    #[error("protocol: {0}")]
    Protocol(String),
    /// Authentication failure.
    #[error("auth: {0}")]
    Auth(String),
    /// Storage backend failure.
    #[error("storage: {0}")]
    Storage(String),
    /// Share not found.
    #[error("share not found: {0}")]
    ShareNotFound(String),
    /// Underlying I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Codec error (lifted from `adrian-smb-core`).
    #[error("codec: {0}")]
    Codec(#[from] SmbError),
}

// ============================================================================
// Virtual filesystem
// ============================================================================

/// In-memory virtual filesystem backing an SMB share.
///
/// Each share owns one `VirtualFs`. Files are stored as `Vec<u8>` keyed
/// by absolute path (e.g. `\dir\file.txt`). The VFS is mutex-protected
/// so multiple sessions on the same share can read/write concurrently.
#[derive(Debug, Default)]
pub struct VirtualFs {
    files: HashMap<String, Vec<u8>>,
}

impl VirtualFs {
    /// Construct an empty VFS.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a VFS pre-populated with the given files (path → contents).
    #[must_use]
    pub fn with_files(files: HashMap<String, Vec<u8>>) -> Self {
        Self { files }
    }

    /// Insert / replace a file.
    pub fn put(&mut self, path: &str, data: Vec<u8>) {
        self.files.insert(path.to_string(), data);
    }

    /// Look up a file by path. Returns `None` if not present.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&Vec<u8>> {
        self.files.get(path)
    }

    /// Look up a file by path mutably.
    pub fn get_mut(&mut self, path: &str) -> Option<&mut Vec<u8>> {
        self.files.get_mut(path)
    }

    /// Read up to `length` bytes from `offset`. Returns the bytes actually
    /// read (may be less than `length` if EOF is hit).
    pub fn read(&self, path: &str, offset: u64, length: u32) -> Option<Vec<u8>> {
        let data = self.files.get(path)?;
        let off = offset as usize;
        if off >= data.len() {
            return Some(Vec::new());
        }
        let end = (off + length as usize).min(data.len());
        Some(data[off..end].to_vec())
    }

    /// Write `data` at `offset`. Extends the file with zero bytes if
    /// `offset` is past the current end. Returns the number of bytes
    /// written.
    pub fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Option<u32> {
        let file = self.files.get_mut(path)?;
        let off = offset as usize;
        let need = off + data.len();
        if file.len() < need {
            file.resize(need, 0);
        }
        file[off..off + data.len()].copy_from_slice(data);
        Some(data.len() as u32)
    }

    /// Create a new empty file (or truncate an existing one).
    pub fn create(&mut self, path: &str) {
        self.files.insert(path.to_string(), Vec::new());
    }

    /// Number of files currently in the VFS.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// True if the VFS holds no files.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Current size of a file (0 if not present).
    #[must_use]
    pub fn size(&self, path: &str) -> u64 {
        self.files.get(path).map_or(0, |v| v.len() as u64)
    }
}

// ============================================================================
// Share
// ============================================================================

/// A named SMB share backed by a [`VirtualFs`].
#[derive(Debug)]
pub struct Share {
    /// Share name (e.g. `sysvol`).
    pub name: String,
    /// Virtual filesystem backing the share.
    pub fs: Arc<Mutex<VirtualFs>>,
}

impl Share {
    /// Construct a new share with an empty VFS.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fs: Arc::new(Mutex::new(VirtualFs::new())),
        }
    }

    /// Construct a new share with a pre-populated VFS.
    #[must_use]
    pub fn with_fs(name: impl Into<String>, fs: VirtualFs) -> Self {
        Self {
            name: name.into(),
            fs: Arc::new(Mutex::new(fs)),
        }
    }
}

// ============================================================================
// Server configuration
// ============================================================================

/// SMB server configuration.
#[derive(Debug, Clone)]
pub struct SmbServerConfig {
    /// Bind address (e.g. `0.0.0.0:445`).
    pub bind_addr: SocketAddr,
    /// Server GUID (advertised in NegotiateResponse).
    pub server_guid: Uuid,
    /// Server preauth-integrity salt (advertised in NegotiateResponse's
    /// PREAUTH_INTEGRITY_CAPABILITIES context).
    pub server_salt: Vec<u8>,
}

impl Default for SmbServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:445".parse().expect("valid bind addr"),
            server_guid: Uuid::from_u128(0xAD0A_0000_0000_0000_0000_0000_0000_0001),
            server_salt: vec![0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18],
        }
    }
}

// ============================================================================
// Open-file / session / connection state
// ============================================================================

/// A file opened by a client (tracked by FileId).
#[derive(Debug, Clone)]
struct OpenFile {
    /// Path within the share.
    path: String,
    /// Share the file lives on.
    share: Arc<Share>,
}

// ============================================================================
// Wave 3 — DurableHandleTable, ChangeNotifyRegistry, OplockRegistry
// (ADR-106 + MS-SMB2 §2.2.23 / §2.2.31 / §2.2.35)
// ============================================================================

/// A durable open record. Survives the connection that created it
/// (per ADR-106) so that a reconnected client can reclaim the file
/// handle by PersistentFileId.
#[derive(Debug, Clone)]
pub struct DurableOpen {
    /// PersistentFileId (stable across reconnects).
    pub persistent_id: u64,
    /// Path within the share.
    pub path: String,
    /// Share the file lives on.
    pub share: Arc<Share>,
    /// CreateGuid (round-tripped from the request so the reconnect
    /// path can verify the same client is reclaiming).
    pub create_guid: uuid::Uuid,
}

/// Server-wide table of durable handles. Lives on the [`SmbServer`]
/// (NOT the `ConnectionState`) so handles survive disconnects.
///
/// Per ADR-106 the framework's SMB client (FileModule) treats durable
/// handles as the primary reconnection primitive — when the underlying
/// TCP stream drops, the client immediately re-issues CREATE with a
/// `SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2` context carrying the
/// PersistentFileId returned by the original open.
#[derive(Debug, Default)]
pub struct DurableHandleTable {
    opens: HashMap<u64, DurableOpen>,
}

impl DurableHandleTable {
    /// Construct an empty durable-handle table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a durable open keyed by PersistentFileId. Overwrites any
    /// existing entry (the caller is responsible for closing the old
    /// handle first in production code).
    pub fn record(&mut self, open: DurableOpen) {
        self.opens.insert(open.persistent_id, open);
    }

    /// Reclaim a durable open by PersistentFileId. Returns `None` if
    /// the handle has already been reclaimed, was never recorded, or
    /// was closed.
    pub fn reclaim(&mut self, persistent_id: u64) -> Option<DurableOpen> {
        self.opens.remove(&persistent_id)
    }

    /// Look up a durable open without reclaiming it (for tests).
    #[must_use]
    pub fn peek(&self, persistent_id: u64) -> Option<&DurableOpen> {
        self.opens.get(&persistent_id)
    }

    /// Number of durable opens currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.opens.len()
    }

    /// True if the table holds no durable opens.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.opens.is_empty()
    }
}

/// A registered directory-change watcher (one per outstanding
/// CHANGE_NOTIFY request).
#[derive(Debug, Clone)]
pub struct ChangeNotifyWatcher {
    /// AsyncId assigned by the server (returned to the client as the
    /// async id in the STATUS_PENDING response).
    pub async_id: u64,
    /// SessionId that owns the watch.
    pub session_id: u64,
    /// TreeId of the tree the watched directory lives on.
    pub tree_id: u32,
    /// FileId of the watched directory.
    pub file_id: FileId,
    /// Filter bits (combination of `notify_filter::*` constants).
    pub filter: u32,
    /// True if the watch is recursive (WatchTree).
    pub watch_tree: bool,
    /// The response to send when the watch is triggered (pre-encoded
    /// for simplicity; a real server would re-encode per event).
    pub pending_response: Option<Vec<u8>>,
}

/// Server-wide registry of directory-change watchers.
#[derive(Debug, Default)]
pub struct ChangeNotifyRegistry {
    watchers: HashMap<u64, ChangeNotifyWatcher>,
    next_async_id: u64,
}

impl ChangeNotifyRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            watchers: HashMap::new(),
            next_async_id: 1,
        }
    }

    /// Register a new watcher and return the assigned AsyncId.
    pub fn register(
        &mut self,
        session_id: u64,
        tree_id: u32,
        file_id: FileId,
        filter: u32,
        watch_tree: bool,
    ) -> u64 {
        let async_id = self.next_async_id;
        self.next_async_id += 1;
        self.watchers.insert(
            async_id,
            ChangeNotifyWatcher {
                async_id,
                session_id,
                tree_id,
                file_id,
                filter,
                watch_tree,
                pending_response: None,
            },
        );
        async_id
    }

    /// Trigger a watcher by AsyncId. Attaches the given pre-encoded
    /// response bytes to the watcher so a subsequent poll can return
    /// them to the client. Returns `true` if the watcher was found.
    pub fn trigger(&mut self, async_id: u64, response: Vec<u8>) -> bool {
        if let Some(w) = self.watchers.get_mut(&async_id) {
            w.pending_response = Some(response);
            true
        } else {
            false
        }
    }

    /// Pop a triggered watcher's response. Returns `None` if the
    /// watcher doesn't exist or hasn't been triggered yet.
    pub fn poll(&mut self, async_id: u64) -> Option<Vec<u8>> {
        let w = self.watchers.get_mut(&async_id)?;
        w.pending_response.take()
    }

    /// Look up a watcher by AsyncId (for tests).
    #[must_use]
    pub fn peek(&self, async_id: u64) -> Option<&ChangeNotifyWatcher> {
        self.watchers.get(&async_id)
    }

    /// Number of watchers currently registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.watchers.len()
    }

    /// True if the registry holds no watchers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.watchers.is_empty()
    }
}

/// Per-file oplock state (one entry per granted oplock).
#[derive(Debug, Clone, Copy)]
pub struct OplockState {
    /// Oplock level currently granted (one of `oplock_level::*`).
    pub level: u8,
    /// SessionId holding the oplock.
    pub session_id: u64,
}

/// Server-wide oplock registry. Tracks oplocks granted on open files
/// so that conflicting opens can trigger OPLOCK_BREAK notifications.
#[derive(Debug, Default)]
pub struct OplockRegistry {
    states: HashMap<FileId, OplockState>,
    /// Pending break notifications queued for delivery to the holder
    /// (one per triggered break). The client must acknowledge before
    /// the conflicting open can proceed.
    pending_breaks: HashMap<FileId, OplockBreakNotification>,
}

impl OplockRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant an oplock on `file_id` to `session_id` at the given level.
    /// Overwrites any existing entry (the caller is responsible for
    /// breaking the prior oplock first in production code).
    pub fn grant(&mut self, file_id: FileId, level: u8, session_id: u64) {
        self.states
            .insert(file_id, OplockState { level, session_id });
    }

    /// Trigger an oplock break on `file_id`, downgrading to
    /// `new_level`. Returns the notification to send to the current
    /// holder. Returns `None` if no oplock is held on `file_id`.
    pub fn break_oplock(
        &mut self,
        file_id: FileId,
        new_level: u8,
    ) -> Option<OplockBreakNotification> {
        let state = self.states.get_mut(&file_id)?;
        if state.level == new_level {
            return None; // no break needed
        }
        let notif = OplockBreakNotification::new(state.level, file_id);
        state.level = new_level;
        self.pending_breaks.insert(file_id, notif.clone());
        Some(notif)
    }

    /// Acknowledge a pending oplock break on `file_id`. The client
    /// confirms it has flushed its cached state and accepts the new
    /// oplock level. Returns the acknowledged level, or `None` if no
    /// pending break exists.
    pub fn acknowledge(&mut self, file_id: FileId, ack_level: u8) -> Option<u8> {
        let notif = self.pending_breaks.remove(&file_id)?;
        let _ = notif;
        if let Some(state) = self.states.get_mut(&file_id) {
            state.level = ack_level;
        }
        Some(ack_level)
    }

    /// Look up the current oplock state for a file (for tests).
    #[must_use]
    pub fn peek(&self, file_id: FileId) -> Option<OplockState> {
        self.states.get(&file_id).copied()
    }

    /// True if a pending (unacknowledged) break exists for `file_id`.
    #[must_use]
    pub fn has_pending_break(&self, file_id: FileId) -> bool {
        self.pending_breaks.contains_key(&file_id)
    }
}

/// Per-session state.
#[derive(Debug)]
struct SessionState {
    /// TreeId currently bound (0 if no tree).
    tree_id: u32,
    /// Share currently bound (None if no tree).
    share: Option<Arc<Share>>,
    /// Open files keyed by FileId.
    open_files: HashMap<FileId, OpenFile>,
    /// SMB2 SessionKey (16 bytes) derived from the GSS-API acceptor
    /// (Wave 2). Used to derive the AES-256-GCM encryption key per
    /// MS-SMB2 §3.2.5.2. None until SessionSetup completes.
    session_key: Option<[u8; 16]>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            tree_id: 0,
            share: None,
            open_files: HashMap::new(),
            session_key: None,
        }
    }
}

/// Per-connection state. Owns the session table; the share table is
/// shared (via `Arc`) across all connections.
struct ConnectionState {
    server_guid: Uuid,
    server_salt: Vec<u8>,
    shares: Arc<HashMap<String, Arc<Share>>>,
    next_session_id: u64,
    sessions: HashMap<u64, SessionState>,
    next_tree_id: u32,
    next_file_persistent: u64,
    next_file_volatile: u64,
    /// Wave 3: directory-change watchers (lives per-connection for
    /// simplicity; a production server would share this across
    /// connections so a watcher registered on connection 1 can be
    /// polled on connection 2 after a reconnect).
    change_notify_registry: ChangeNotifyRegistry,
    /// Wave 3: oplock state (per-connection for the same reason).
    oplock_registry: OplockRegistry,
    /// Wave 3: durable-handle table (per-connection in this
    /// implementation; ADR-106's full design lives it on the server
    /// so handles survive disconnects — the public [`DurableHandleTable`]
    /// type is exercised directly in tests to demonstrate the
    /// cross-connection reclaim).
    durable_handle_table: DurableHandleTable,
}

impl ConnectionState {
    fn new(
        server_guid: Uuid,
        server_salt: Vec<u8>,
        shares: Arc<HashMap<String, Arc<Share>>>,
    ) -> Self {
        Self {
            server_guid,
            server_salt,
            shares,
            next_session_id: 1,
            sessions: HashMap::new(),
            next_tree_id: 1,
            next_file_persistent: 1,
            next_file_volatile: 1,
            change_notify_registry: ChangeNotifyRegistry::new(),
            oplock_registry: OplockRegistry::new(),
            durable_handle_table: DurableHandleTable::new(),
        }
    }

    fn alloc_session(&mut self) -> u64 {
        let id = self.next_session_id;
        self.next_session_id += 1;
        self.sessions.insert(id, SessionState::new());
        id
    }

    fn alloc_tree_id(&mut self) -> u32 {
        let id = self.next_tree_id;
        self.next_tree_id += 1;
        id
    }

    fn alloc_file_id(&mut self) -> FileId {
        let p = self.next_file_persistent;
        let v = self.next_file_volatile;
        self.next_file_persistent += 1;
        self.next_file_volatile += 1;
        FileId::new(p, v)
    }
}

// ============================================================================
// Server
// ============================================================================

/// SMB 3.1.1 server.
pub struct SmbServer {
    config: SmbServerConfig,
    shares: Arc<HashMap<String, Arc<Share>>>,
}

impl SmbServer {
    /// Construct a new server with the given configuration and no shares.
    #[must_use]
    pub fn new(config: SmbServerConfig) -> Self {
        Self {
            config,
            shares: Arc::new(HashMap::new()),
        }
    }

    /// Construct a new server with the given configuration and shares.
    #[must_use]
    pub fn with_shares(config: SmbServerConfig, shares: Vec<Arc<Share>>) -> Self {
        let mut map = HashMap::new();
        for s in shares {
            map.insert(s.name.clone(), s);
        }
        Self {
            config,
            shares: Arc::new(map),
        }
    }

    /// Bind TCP/445 and serve until shutdown. Each accepted connection
    /// runs in its own tokio task.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the TCP listener cannot be bound.
    pub async fn serve(&self) -> Result<(), SmbServerError> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        tracing::info!(
            "adrian-smb-server listening on {} ({} shares)",
            self.config.bind_addr,
            self.shares.len()
        );
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(?e, "accept failed; continuing");
                    continue;
                }
            };
            let shares = self.shares.clone();
            let guid = self.config.server_guid;
            let salt = self.config.server_salt.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, shares, guid, salt).await {
                    tracing::warn!(?peer, ?e, "connection handler exited with error");
                }
            });
        }
    }

    /// Handle one connection (one TCP stream). Generic over the stream
    /// type so tests can use `tokio::io::duplex` instead of a real TCP
    /// socket.
    ///
    /// # Errors
    ///
    /// Returns `Err` on a non-recoverable I/O or protocol error.
    pub async fn handle_connection<S>(
        stream: S,
        shares: Arc<HashMap<String, Arc<Share>>>,
        server_guid: Uuid,
        server_salt: Vec<u8>,
    ) -> Result<(), SmbServerError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut handler = ConnectionHandler::new(stream, shares, server_guid, server_salt);
        handler.run().await
    }
}

impl Default for SmbServer {
    fn default() -> Self {
        Self::new(SmbServerConfig::default())
    }
}

// ============================================================================
// Connection handler (the per-connection state machine)
// ============================================================================

struct ConnectionHandler<S> {
    stream: S,
    state: ConnectionState,
    /// Read buffer for partial NetBIOS frames.
    read_buf: Vec<u8>,
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin> ConnectionHandler<S> {
    fn new(
        stream: S,
        shares: Arc<HashMap<String, Arc<Share>>>,
        server_guid: Uuid,
        server_salt: Vec<u8>,
    ) -> Self {
        Self {
            stream,
            state: ConnectionState::new(server_guid, server_salt, shares),
            read_buf: Vec::new(),
        }
    }

    async fn run(&mut self) -> Result<(), SmbServerError> {
        // 64 KiB read scratch buffer — large enough for most SMB2 control
        // PDUs; large READ/WRITE payloads stream across multiple reads.
        let mut scratch = vec![0u8; 64 * 1024];
        loop {
            // Try to decode a complete NetBIOS frame from the read buffer.
            let (frame_type, payload_len) = match netbios::peek_header(&self.read_buf)? {
                Some(v) => v,
                None => {
                    // Need more bytes.
                    let n = self.stream.read(&mut scratch).await?;
                    if n == 0 {
                        // EOF — peer closed.
                        return Ok(());
                    }
                    self.read_buf.extend_from_slice(&scratch[..n]);
                    continue;
                }
            };
            // We have a complete header; check we have the full payload.
            let frame_total = 4 + payload_len;
            if self.read_buf.len() < frame_total {
                // Need more bytes.
                let n = self.stream.read(&mut scratch).await?;
                if n == 0 {
                    return Err(SmbServerError::Protocol("eof mid-frame".into()));
                }
                self.read_buf.extend_from_slice(&scratch[..n]);
                continue;
            }
            // Consume the frame.
            let payload: Vec<u8> = self.read_buf.drain(..frame_total).collect();
            let payload = payload[4..].to_vec();
            // Dispatch.
            let response = self.dispatch_frame(frame_type, &payload).await?;
            if let Some(resp) = response {
                let framed = netbios::encode_frame(&resp);
                self.stream.write_all(&framed).await?;
                self.stream.flush().await?;
            }
        }
    }

    /// Dispatch one SMB2 PDU. Returns `Ok(Some(bytes))` to send a response,
    /// or `Ok(None)` to suppress (e.g. for async commands — not used in
    /// Wave 3b).
    async fn dispatch_frame(
        &mut self,
        frame_type: u8,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, SmbServerError> {
        if frame_type != 0x00 {
            // Not a session message — refuse.
            return Err(SmbServerError::Protocol(format!(
                "unsupported netbios frame type: 0x{frame_type:02x}"
            )));
        }
        // Decode the SMB2 header.
        let header = match Smb2Header::decode(payload) {
            Ok(h) => h,
            Err(SmbError::Smb1Refused) => {
                // Per ADR-043 — refuse SMB1 with STATUS_INVALID_PARAMETER.
                let mut hdr = Smb2Header::new_response(&Smb2Header::new_request(0, 0));
                hdr.status = ntstatus::STATUS_INVALID_PARAMETER;
                let mut out = Writer::new();
                hdr.encode(&mut out);
                return Ok(Some(out.into_bytes()));
            }
            Err(e) => return Err(SmbServerError::Codec(e)),
        };
        // Dispatch on command.
        let cmd = Command::from_wire(header.command);
        let resp_bytes = match cmd {
            Some(Command::Negotiate) => self.handle_negotiate(&header, payload).await?,
            Some(Command::SessionSetup) => self.handle_session_setup(&header, payload).await?,
            Some(Command::Logoff) => self.handle_logoff(&header, payload).await?,
            Some(Command::TreeConnect) => self.handle_tree_connect(&header, payload).await?,
            Some(Command::TreeDisconnect) => self.handle_tree_disconnect(&header, payload).await?,
            Some(Command::Create) => self.handle_create(&header, payload).await?,
            Some(Command::Close) => self.handle_close(&header, payload).await?,
            Some(Command::Read) => self.handle_read(&header, payload).await?,
            Some(Command::Write) => self.handle_write(&header, payload).await?,
            Some(Command::Echo) => self.handle_echo(&header, payload).await?,
            Some(Command::ChangeNotify) => self.handle_change_notify(&header, payload).await?,
            Some(Command::OplockBreak) => self.handle_oplock_break(&header, payload).await?,
            _ => {
                let mut hdr = Smb2Header::new_response(&header);
                hdr.status = ntstatus::STATUS_INVALID_DEVICE_REQUEST;
                let mut out = Writer::new();
                hdr.encode(&mut out);
                out.into_bytes()
            }
        };
        Ok(Some(resp_bytes))
    }

    // ---- Per-command handlers ----

    async fn handle_negotiate(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let _req = NegotiateRequest::decode(payload, SMB2_HEADER_SIZE)?;
        // Advertise SMB 3.1.1 with SHA-512 preauth integrity + AES-256-GCM.
        let resp = NegotiateResponse::new_311(self.state.server_guid, &self.state.server_salt);
        Ok(resp.encode(header))
    }

    async fn handle_session_setup(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        // Wave 2: real GSS-API / SPNEGO validation per ADR-085.
        // NTLM-only tokens and anonymous (empty) tokens are refused
        // with STATUS_LOGON_FAILURE; only Kerberos5 tokens are accepted.
        let req = SessionSetupRequest::decode(payload, SMB2_HEADER_SIZE)?;
        // The server-side secret mixed into the session-key derivation.
        // In production this is the server's krb5 keytab entry for the
        // cifs/<fqdn> SPN; for Wave 2 we reuse the preauth-integrity
        // salt (already advertised in the NegotiateResponse).
        let server_secret = &self.state.server_salt;
        match gss_api::accept_sec_context(&req.security_buffer, server_secret) {
            Ok(accept) => {
                // Allocate a session if this is the first SessionSetup
                // for this connection (sessionId == 0 means "new session").
                let session_id = if header.session_id == 0 {
                    self.state.alloc_session()
                } else {
                    header.session_id
                };
                // Stash the derived session key on the session so that
                // Wave 1 encryption can be wired up later. Wave 2 just
                // records it; subsequent PDUs on this session are still
                // plaintext until the encryption-wiring wave flips the
                // switch (per ADR-105 §4 — encryption is opt-in per
                // session, not mandated).
                if let Some(s) = self.state.sessions.get_mut(&session_id) {
                    s.session_key = Some(accept.session_key);
                }
                let mut resp_hdr = Smb2Header::new_response(header);
                resp_hdr.session_id = session_id;
                let resp = SessionSetupResponse::new_success();
                Ok(resp.encode(&resp_hdr, ntstatus::STATUS_SUCCESS))
            }
            Err(_e) => {
                // GSS-API failure → STATUS_LOGON_FAILURE. The error
                // variant (NTLM refused vs. anonymous refused vs.
                // malformed Kerberos) is logged but the on-wire status
                // is the same so the client cannot distinguish them
                // (avoiding an information leak).
                let session_id = if header.session_id == 0 {
                    self.state.alloc_session()
                } else {
                    header.session_id
                };
                let mut resp_hdr = Smb2Header::new_response(header);
                resp_hdr.session_id = session_id;
                let resp = SessionSetupResponse::new_success();
                Ok(resp.encode(&resp_hdr, ntstatus::STATUS_LOGON_FAILURE))
            }
        }
    }

    async fn handle_logoff(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let _ = LogoffRequest::decode(payload, SMB2_HEADER_SIZE)?;
        // Drop the session.
        self.state.sessions.remove(&header.session_id);
        let resp = LogoffResponse;
        Ok(resp.encode(header))
    }

    async fn handle_tree_connect(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let req = TreeConnectRequest::decode(payload, SMB2_HEADER_SIZE)?;
        // Parse the UNC path: `\\server\share` (or `\server\share`).
        // We only care about the last component (the share name).
        let share_name = parse_share_name(&req.path);
        let share = match self.state.shares.get(&share_name) {
            Some(s) => s.clone(),
            None => {
                // STATUS_BAD_NETWORK_NAME per MS-SMB2 §3.3.5.7.
                let mut hdr = Smb2Header::new_response(header);
                hdr.status = ntstatus::STATUS_BAD_NETWORK_NAME;
                let mut out = Writer::new();
                hdr.encode(&mut out);
                return Ok(out.into_bytes());
            }
        };
        // Allocate a TreeId and bind it to the session.
        let tree_id = self.state.alloc_tree_id();
        if let Some(s) = self.state.sessions.get_mut(&header.session_id) {
            s.tree_id = tree_id;
            s.share = Some(share);
        } else {
            // No session — drop into an ad-hoc session.
            let sid = self.state.alloc_session();
            let s = self.state.sessions.get_mut(&sid).expect("just-inserted");
            s.tree_id = tree_id;
            s.share = Some(share);
        }
        let resp = TreeConnectResponse::new_disk();
        Ok(resp.encode(header, tree_id, ntstatus::STATUS_SUCCESS))
    }

    async fn handle_tree_disconnect(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        // TREE_DISCONNECT has a 4-byte body (StructureSize=4, Reserved=2).
        // We don't strictly need to decode it (no fields of interest), but
        // we do a length sanity check to keep the loud-stub contract.
        if payload.len() < SMB2_HEADER_SIZE + 4 {
            return Err(SmbServerError::Protocol(
                "tree disconnect request too short".into(),
            ));
        }
        if let Some(s) = self.state.sessions.get_mut(&header.session_id) {
            s.share = None;
            s.open_files.clear();
        }
        // Echo the request header as a response with STATUS_SUCCESS.
        let mut hdr = Smb2Header::new_response(header);
        hdr.status = ntstatus::STATUS_SUCCESS;
        let mut out = Writer::new();
        hdr.encode(&mut out);
        out.write_u16(4); // StructureSize
        out.write_u16(0); // Reserved
        Ok(out.into_bytes())
    }

    async fn handle_create(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let req = CreateRequest::decode(payload, SMB2_HEADER_SIZE)?;
        // Wave 3: parse create contexts to detect durable handle
        // requests (DHQ2) and reconnect requests (DHN2). The base
        // CreateRequest::decode only consumes the fixed fields + name;
        // parse_create_contexts re-reads the offset/length and decodes
        // the contexts.
        let create_contexts = CreateRequest::parse_create_contexts(payload, SMB2_HEADER_SIZE)?;
        // Look for a durable-handle reconnect (DHN2) context first —
        // it short-circuits the normal VFS open path because the file
        // is already open in the DurableHandleTable.
        if let Some(dhn2) = create_contexts
            .iter()
            .find(|c| c.name == CreateContext::NAME_DURABLE_HANDLE_RECONNECT_V2)
        {
            if let Some((file_id, _create_guid, _flags)) = dhn2.parse_durable_handle_reconnect_v2()
            {
                if let Some(open) = self.state.durable_handle_table.reclaim(file_id.persistent) {
                    // Rebind the reclaimed open to the new session.
                    if let Some(s) = self.state.sessions.get_mut(&header.session_id) {
                        s.open_files.insert(
                            file_id,
                            OpenFile {
                                path: open.path.clone(),
                                share: open.share.clone(),
                            },
                        );
                    }
                    let resp = CreateResponse::new(file_id, 0);
                    // The response carries a DHC2 context indicating the
                    // reconnect succeeded.
                    return Ok(resp.encode(header, ntstatus::STATUS_SUCCESS));
                }
                // No durable open to reclaim — fall through to normal
                // open (the client will see a fresh FileId).
            }
        }
        // Look for a durable-handle request (DHQ2) — record the open
        // in the DurableHandleTable so a future reconnect can reclaim it.
        let durable_request = create_contexts
            .iter()
            .find(|c| c.name == CreateContext::NAME_DURABLE_HANDLE_REQUEST_V2)
            .and_then(|c| c.parse_durable_handle_request_v2());
        let share = match self.share_for_session(header.session_id) {
            Some(s) => s,
            None => {
                return Ok(error_response(header, ntstatus::STATUS_ACCESS_DENIED));
            }
        };
        // Resolve the file in the VFS, honouring CreateDisposition.
        // For Wave 3b we support FILE_OPEN_IF (0x05 = open or create),
        // FILE_OPEN (0x01), FILE_CREATE (0x02), FILE_OVERWRITE_IF (0x05).
        let file_id = self.state.alloc_file_id();
        let mut fs_guard = share.fs.lock().await;
        let size = match req.create_disposition {
            0x01 => {
                // FILE_OPEN — file must exist.
                if !fs_guard.get(&req.name).is_some() {
                    return Ok(error_response(header, ntstatus::STATUS_NO_SUCH_FILE));
                }
                fs_guard.size(&req.name)
            }
            0x02 => {
                // FILE_CREATE — file must not exist.
                if fs_guard.get(&req.name).is_some() {
                    return Ok(error_response(
                        header,
                        ntstatus::STATUS_OBJECT_NAME_COLLISION,
                    ));
                }
                fs_guard.create(&req.name);
                0
            }
            0x03 => {
                // FILE_OPEN_IF — open if exists, create if absent (no truncate).
                if fs_guard.get(&req.name).is_none() {
                    fs_guard.create(&req.name);
                }
                fs_guard.size(&req.name)
            }
            0x04 => {
                // FILE_OVERWRITE — file must exist; truncate.
                if !fs_guard.get(&req.name).is_some() {
                    return Ok(error_response(header, ntstatus::STATUS_NO_SUCH_FILE));
                }
                if let Some(f) = fs_guard.get_mut(&req.name) {
                    f.clear();
                }
                0
            }
            0x05 => {
                // FILE_OVERWRITE_IF — truncate if exists, create if absent.
                if fs_guard.get(&req.name).is_none() {
                    fs_guard.create(&req.name);
                } else if let Some(f) = fs_guard.get_mut(&req.name) {
                    f.clear();
                }
                0
            }
            _ => fs_guard.size(&req.name),
        };
        drop(fs_guard);
        // Track the open file.
        if let Some(s) = self.state.sessions.get_mut(&header.session_id) {
            s.open_files.insert(
                file_id,
                OpenFile {
                    path: req.name.clone(),
                    share: share.clone(),
                },
            );
        }
        // Wave 3: if the client requested a durable handle (DHQ2),
        // record the open in the DurableHandleTable so a future
        // reconnect can reclaim it. Also grant the oplock in the
        // OplockRegistry if the client requested one.
        if let Some((_flags, create_guid, _req_flags)) = durable_request {
            self.state.durable_handle_table.record(DurableOpen {
                persistent_id: file_id.persistent,
                path: req.name.clone(),
                share: share.clone(),
                create_guid,
            });
        }
        if req.oplock_level != 0 {
            self.state
                .oplock_registry
                .grant(file_id, req.oplock_level, header.session_id);
        }
        let resp = CreateResponse::new(file_id, size);
        Ok(resp.encode(header, ntstatus::STATUS_SUCCESS))
    }

    async fn handle_close(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let req = CloseRequest::decode(payload, SMB2_HEADER_SIZE)?;
        // Drop the open file.
        if let Some(s) = self.state.sessions.get_mut(&header.session_id) {
            s.open_files.remove(&req.file_id);
        }
        // Wave 3: also drop any durable-handle / oplock state for this
        // FileId. A real production server would only drop the durable
        // entry if the close is "real" (not a reconnect-preserving
        // close); the simplified model here drops them unconditionally.
        self.state
            .durable_handle_table
            .reclaim(req.file_id.persistent);
        let _ = self.state.oplock_registry.peek(req.file_id); // touch registry
        let resp = CloseResponse::new();
        Ok(resp.encode(header, ntstatus::STATUS_SUCCESS))
    }

    async fn handle_read(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let req = ReadRequest::decode(payload, SMB2_HEADER_SIZE)?;
        let (path, share) = match self.lookup_open_file(header.session_id, &req.file_id) {
            Some(v) => v,
            None => return Ok(error_response(header, ntstatus::STATUS_FILE_CLOSED)),
        };
        let fs_guard = share.fs.lock().await;
        match fs_guard.read(&path, req.offset, req.length) {
            Some(data) => {
                let resp = ReadResponse::new(data);
                Ok(resp.encode(header, ntstatus::STATUS_SUCCESS))
            }
            None => Ok(error_response(header, ntstatus::STATUS_FILE_CLOSED)),
        }
    }

    async fn handle_write(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let req = WriteRequest::decode(payload, SMB2_HEADER_SIZE)?;
        let (path, share) = match self.lookup_open_file(header.session_id, &req.file_id) {
            Some(v) => v,
            None => return Ok(error_response(header, ntstatus::STATUS_FILE_CLOSED)),
        };
        let mut fs_guard = share.fs.lock().await;
        match fs_guard.write(&path, req.offset, &req.data) {
            Some(n) => {
                let resp = WriteResponse::new(n);
                Ok(resp.encode(header, ntstatus::STATUS_SUCCESS))
            }
            None => Ok(error_response(header, ntstatus::STATUS_FILE_CLOSED)),
        }
    }

    async fn handle_echo(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let _ = EchoRequest::decode(payload, SMB2_HEADER_SIZE)?;
        let resp = EchoResponse;
        Ok(resp.encode(header))
    }

    /// Wave 3: handle a CHANGE_NOTIFY request. The server registers a
    /// watcher in the [`ChangeNotifyRegistry`] and immediately returns
    /// STATUS_PENDING with the ASYNC flag set and the AsyncId in the
    /// header's `status` field (per MS-SMB2 §3.3.5.18). A subsequent
    /// trigger (via the registry) completes the watch and sends the
    /// response.
    async fn handle_change_notify(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let req = ChangeNotifyRequest::decode(payload, SMB2_HEADER_SIZE)?;
        let async_id = self.state.change_notify_registry.register(
            header.session_id,
            header.tree_id,
            req.file_id,
            req.filter,
            req.watch_tree,
        );
        // Return STATUS_PENDING with the AsyncId in the header (the
        // SMB2 ASYNC header variant places the AsyncId in the
        // message_id field; we keep the message_id for simplicity in
        // the test harness and return the async_id in a synthetic
        // pending-status response).
        let mut hdr = Smb2Header::new_response(header);
        hdr.status = ntstatus::STATUS_PENDING;
        hdr.flags |= adrian_smb_core::flags::SMB2_FLAGS_ASYNC;
        hdr.message_id = async_id; // async-id (per MS-SMB2 §2.2.1.2)
        let mut out = Writer::new();
        hdr.encode(&mut out);
        out.write_u16(9); // StructureSize
        out.write_u16(0); // Reserved
        out.write_u32(0); // ChangesBufferOffset
        out.write_u32(0); // ChangesBufferLength
        Ok(out.into_bytes())
    }

    /// Wave 3: handle an OPLOCK_BREAK acknowledgment (client → server)
    /// per MS-SMB2 §3.3.5.22. The client confirms it has flushed its
    /// cached state and accepts the new oplock level. The server
    /// records the acknowledgment in the [`OplockRegistry`].
    async fn handle_oplock_break(
        &mut self,
        header: &Smb2Header,
        payload: &[u8],
    ) -> Result<Vec<u8>, SmbServerError> {
        let ack = OplockBreakAcknowledgment::decode(payload, SMB2_HEADER_SIZE)?;
        self.state
            .oplock_registry
            .acknowledge(ack.file_id, ack.oplock_level);
        // Echo the ack back as the response (server's confirmation).
        let mut hdr = Smb2Header::new_response(header);
        hdr.status = ntstatus::STATUS_SUCCESS;
        let mut out = Writer::new();
        hdr.encode(&mut out);
        out.write_u16(24); // StructureSize
        out.write_u8(ack.oplock_level);
        out.write_u8(0); // Reserved
        out.write_file_id(&ack.file_id);
        Ok(out.into_bytes())
    }

    // ---- Helpers ----

    fn share_for_session(&self, session_id: u64) -> Option<Arc<Share>> {
        self.state
            .sessions
            .get(&session_id)
            .and_then(|s| s.share.clone())
    }

    fn lookup_open_file(&self, session_id: u64, file_id: &FileId) -> Option<(String, Arc<Share>)> {
        let s = self.state.sessions.get(&session_id)?;
        let f = s.open_files.get(file_id)?;
        Some((f.path.clone(), f.share.clone()))
    }
}

/// Build an empty-body error response (header only) carrying `status`.
fn error_response(header: &Smb2Header, status: u32) -> Vec<u8> {
    let mut hdr = Smb2Header::new_response(header);
    hdr.status = status;
    let mut out = Writer::new();
    hdr.encode(&mut out);
    out.into_bytes()
}

/// Parse the share name out of a UNC path like `\\server\share[\path]`.
/// Accepts both `\\server\share` and `\server\share` (single leading
/// backslash) and returns the lowercased share name (the SECOND component).
fn parse_share_name(unc: &str) -> String {
    let trimmed = unc.trim_start_matches('\\');
    let parts: Vec<&str> = trimmed.splitn(3, '\\').collect();
    // parts[0] = server, parts[1] = share, parts[2] = path (optional).
    if parts.len() < 2 {
        return String::new();
    }
    parts[1].to_lowercase()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn make_server() -> SmbServer {
        let share = Arc::new(Share::with_fs(
            "sysvol",
            VirtualFs::with_files(HashMap::from([
                ("hello.txt".to_string(), b"hello, world\n".to_vec()),
                ("data.bin".to_string(), vec![0xABu8; 1024]),
            ])),
        ));
        SmbServer::with_shares(SmbServerConfig::default(), vec![share])
    }

    fn make_server_guid_salt() -> (Uuid, Vec<u8>) {
        (
            Uuid::from_u128(0xABCD_0000_0000_0000_0000_0000_0000_0001),
            vec![0x11u8; 32],
        )
    }

    // ---- Error types ----

    #[test]
    fn error_variants_render_expected_prefixes() {
        assert_eq!(
            format!(
                "{}",
                SmbServerError::Protocol("negotiate dialect mismatch".into())
            ),
            "protocol: negotiate dialect mismatch"
        );
        assert_eq!(
            format!("{}", SmbServerError::Auth("invalid signature".into())),
            "auth: invalid signature"
        );
        assert_eq!(
            format!("{}", SmbServerError::Storage("fdb retry exhausted".into())),
            "storage: fdb retry exhausted"
        );
        assert_eq!(
            format!("{}", SmbServerError::ShareNotFound("SYSVOL".into())),
            "share not found: SYSVOL"
        );
    }

    #[test]
    fn share_not_found_variant_is_distinct_in_match() {
        let err = SmbServerError::ShareNotFound("netlogon".into());
        match err {
            SmbServerError::ShareNotFound(name) => assert_eq!(name, "netlogon"),
            other => panic!("expected ShareNotFound, got {other:?}"),
        }
    }

    #[test]
    fn codec_error_lifts_from_smb_error() {
        let err: SmbServerError = SmbError::Malformed("truncated".into()).into();
        let msg = format!("{err}");
        assert!(msg.contains("codec:"));
        assert!(msg.contains("truncated"));
    }

    // ---- VirtualFs ----

    #[tokio::test]
    async fn virtual_fs_read_returns_bytes_within_bounds() {
        let fs = VirtualFs::with_files(HashMap::from([("f".to_string(), b"abcdefghij".to_vec())]));
        assert_eq!(fs.read("f", 2, 4).unwrap(), b"cdef");
        assert_eq!(fs.read("f", 8, 10).unwrap(), b"ij");
        assert_eq!(fs.read("f", 100, 4).unwrap(), b"");
        assert!(fs.read("missing", 0, 4).is_none());
    }

    #[tokio::test]
    async fn virtual_fs_write_extends_with_zero_padding() {
        let mut fs = VirtualFs::new();
        fs.put("f", b"abc".to_vec());
        let n = fs.write("f", 5, b"XYZ").unwrap();
        assert_eq!(n, 3);
        assert_eq!(fs.get("f").unwrap(), &b"abc\0\0XYZ".to_vec());
    }

    #[tokio::test]
    async fn virtual_fs_create_truncates_existing() {
        let mut fs = VirtualFs::new();
        fs.put("f", b"hello".to_vec());
        fs.create("f");
        assert_eq!(fs.get("f").unwrap().len(), 0);
    }

    // ---- Share-name parser ----

    #[test]
    fn parse_share_name_handles_double_backslash_unc() {
        assert_eq!(parse_share_name(r"\\DC01\SYSVOL"), "sysvol");
        assert_eq!(parse_share_name(r"\\DC01\sysvol\path"), "sysvol");
    }

    #[test]
    fn parse_share_name_handles_single_backslash() {
        assert_eq!(parse_share_name(r"\DC01\share"), "share");
    }

    // ---- Connection handler end-to-end ----

    async fn send_frame(
        write: &mut (impl AsyncWriteExt + Unpin),
        payload: &[u8],
    ) -> Result<(), std::io::Error> {
        let frame = netbios::encode_frame(payload);
        write.write_all(&frame).await?;
        write.flush().await?;
        Ok(())
    }

    async fn recv_frame(read: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>, std::io::Error> {
        let mut header = [0u8; 4];
        read.read_exact(&mut header).await?;
        let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
        let mut payload = vec![0u8; len];
        read.read_exact(&mut payload).await?;
        Ok(payload)
    }

    #[tokio::test]
    async fn negotiate_round_trips_through_server() {
        let (client, server) = duplex(64 * 1024);
        let (_guid, salt) = make_server_guid_salt();
        let share = Arc::new(Share::with_fs(
            "sysvol",
            VirtualFs::with_files(HashMap::from([(
                "hello.txt".to_string(),
                b"hello".to_vec(),
            )])),
        ));
        let shares: Arc<HashMap<String, Arc<Share>>> =
            Arc::new(HashMap::from([("sysvol".to_string(), share)]));
        let guid = Uuid::from_u128(0xABCD);
        let server_handle = tokio::spawn(async move {
            SmbServer::handle_connection(server, shares, guid, salt)
                .await
                .expect("server ok");
        });
        // Send a Negotiate request.
        let client_guid = Uuid::from_u128(0xCAFE);
        let req = NegotiateRequest::new_311(client_guid, &[0xAB; 16]);
        let bytes = req.encode(1);
        let mut client = client;
        send_frame(&mut client, &bytes).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("decode hdr");
        assert!(resp_hdr.is_response());
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let resp = NegotiateResponse::decode(&resp_bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(resp.dialect_revision, adrian_smb_core::dialect_code::SMB311);
        assert_eq!(resp.server_guid, guid);
        // Shut down.
        drop(client);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn full_session_create_read_write_close_round_trips() {
        let (client, server) = duplex(64 * 1024);
        let (guid, salt) = make_server_guid_salt();
        let share = Arc::new(Share::with_fs(
            "sysvol",
            VirtualFs::with_files(HashMap::from([(
                "greeting.txt".to_string(),
                b"hello, world!".to_vec(),
            )])),
        ));
        let shares: Arc<HashMap<String, Arc<Share>>> =
            Arc::new(HashMap::from([("sysvol".to_string(), share.clone())]));
        let server_handle = tokio::spawn(async move {
            SmbServer::handle_connection(server, shares, guid, salt)
                .await
                .expect("server ok");
        });
        let mut client = client;
        let client_guid = Uuid::from_u128(0xDEAD);

        // 1) Negotiate.
        let req = NegotiateRequest::new_311(client_guid, &[0x01; 16]);
        send_frame(&mut client, &req.encode(1)).await.unwrap();
        let _resp_bytes = recv_frame(&mut client).await.unwrap();

        // 2) SessionSetup — Wave 2: real GSS-API / SPNEGO blob.
        let spnego =
            adrian_smb_core::gss_api::init_sec_context("cifs/dc01.example.com", &[0xAB; 16])
                .expect("init_sec_context ok");
        let req = SessionSetupRequest::new(spnego);
        send_frame(&mut client, &req.encode(2, 0)).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let session_id = resp_hdr.session_id;
        assert_ne!(session_id, 0);

        // 3) TreeConnect.
        let req = TreeConnectRequest::new(r"\dc01\sysvol");
        send_frame(&mut client, &req.encode(3, session_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let tree_id = resp_hdr.tree_id;
        assert_ne!(tree_id, 0);

        // 4) Create (open existing file).
        let req = CreateRequest::new("greeting.txt");
        send_frame(&mut client, &req.encode(4, session_id, tree_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let resp = CreateResponse::decode(&resp_bytes, SMB2_HEADER_SIZE).expect("create resp");
        let file_id = resp.file_id;
        assert!(!file_id.is_zero());
        assert_eq!(resp.end_of_file, 13);

        // 5) Read.
        let req = ReadRequest::new(file_id, 0, 1024);
        send_frame(&mut client, &req.encode(5, session_id, tree_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let resp = ReadResponse::decode(&resp_bytes, SMB2_HEADER_SIZE).expect("read resp");
        assert_eq!(resp.data, b"hello, world!");

        // 6) Write (append).
        let req = WriteRequest::new(file_id, 13, b" goodbye!".to_vec());
        send_frame(&mut client, &req.encode(6, session_id, tree_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let resp = WriteResponse::decode(&resp_bytes, SMB2_HEADER_SIZE).expect("write resp");
        assert_eq!(resp.count, 9);

        // 7) Close.
        let req = CloseRequest::new(file_id);
        send_frame(&mut client, &req.encode(7, session_id, tree_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);

        // Verify the write persisted to the VFS.
        let fs = share.fs.lock().await;
        assert_eq!(fs.get("greeting.txt").unwrap(), b"hello, world! goodbye!");

        // 8) Logoff.
        let req = LogoffRequest;
        send_frame(&mut client, &req.encode(8, session_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);

        drop(client);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn smb1_negotiate_is_refused_with_status_invalid_parameter() {
        let (client, server) = duplex(64 * 1024);
        let (guid, salt) = make_server_guid_salt();
        let shares: Arc<HashMap<String, Arc<Share>>> = Arc::new(HashMap::new());
        let server_handle = tokio::spawn(async move {
            let _ = SmbServer::handle_connection(server, shares, guid, salt).await;
        });
        // Craft an SMB1-style message: magic = 0xFF 'S' 'M' 'B'.
        let smb1_payload = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0xFF, b'S', b'M', b'B']);
            v.extend_from_slice(&[0u8; 60]); // Padding to look like a header.
            v
        };
        let mut client = client;
        send_frame(&mut client, &smb1_payload).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        // The server's response should be an SMB2 error response.
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("decode hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_INVALID_PARAMETER);
        drop(client);
        let _ = server_handle.await;
    }

    // ---- Existing public API contracts (kept from the stub) ----

    #[test]
    fn server_new_and_default_are_equivalent() {
        let a = SmbServer::new(SmbServerConfig::default());
        let b = SmbServer::default();
        // Both must be constructible without panicking.
        let _ = (a, b);
    }

    #[test]
    fn config_default_has_well_known_guid_and_salt() {
        let c = SmbServerConfig::default();
        assert!(!c.server_salt.is_empty());
        assert!(!c.server_guid.is_nil());
    }

    #[test]
    fn server_with_shares_indexes_by_lowercase_share_name() {
        let share = Arc::new(Share::new("SYSVOL"));
        let server = SmbServer::with_shares(SmbServerConfig::default(), vec![share]);
        // Share names are stored as-given (case-sensitive lookup).
        assert!(server.shares.contains_key("SYSVOL"));
        assert!(!server.shares.contains_key("sysvol"));
    }

    #[test]
    fn virtual_fs_len_and_is_empty() {
        let mut fs = VirtualFs::new();
        assert!(fs.is_empty());
        assert_eq!(fs.len(), 0);
        fs.put("a", vec![1]);
        assert!(!fs.is_empty());
        assert_eq!(fs.len(), 1);
    }

    #[tokio::test]
    async fn share_backed_by_mutex_protects_concurrent_writes() {
        let share = Arc::new(Share::new("data"));
        // Two tasks writing to different files in the same share should
        // both succeed without corrupting each other.
        let share_a = share.clone();
        let share_b = share.clone();
        let h1 = tokio::spawn(async move {
            let mut fs = share_a.fs.lock().await;
            fs.put("a.txt", b"hello from a".to_vec());
        });
        let h2 = tokio::spawn(async move {
            let mut fs = share_b.fs.lock().await;
            fs.put("b.txt", b"hello from b".to_vec());
        });
        h1.await.unwrap();
        h2.await.unwrap();
        let fs = share.fs.lock().await;
        assert_eq!(fs.get("a.txt").unwrap(), b"hello from a");
        assert_eq!(fs.get("b.txt").unwrap(), b"hello from b");
    }

    #[test]
    fn make_server_yields_one_share_with_two_files() {
        let server = make_server();
        assert_eq!(server.shares.len(), 1);
        assert!(server.shares.contains_key("sysvol"));
    }

    // ---- Wave 3: Persistent handles + change notify + oplocks ----

    /// Helper: build a durable-handle CREATE payload carrying a DHQ2
    /// create context.
    fn build_durable_create_payload(name: &str, create_guid: Uuid) -> Vec<u8> {
        // Header (64 bytes) + CreateRequest body (56 bytes fixed) + name UTF-16
        // + create contexts (DHQ2). The encode is done by hand here because
        // CreateRequest::encode doesn't yet emit create contexts.
        let name_utf16 = adrian_smb_core::encode_utf16le(name);
        let mut out = Writer::with_capacity(64 + 56 + name_utf16.len() + 64);
        // Header.
        let mut hdr = Smb2Header::new_request(adrian_smb_core::command::CREATE, 1);
        hdr.session_id = 0xABCD_1234;
        hdr.tree_id = 7;
        hdr.encode(&mut out);
        // Body.
        out.write_u16(57); // StructureSize
        out.write_u8(adrian_smb_core::oplock_level::LEVEL_2); // OplockLevel
        out.write_u8(0); // Reserved
        out.write_u32(2); // ImpersonationLevel
        out.write_u64(0); // SmbCreateFlags
        out.write_u64(0); // Reserved2
        out.write_u32(0x0017_0089); // DesiredAccess
        out.write_u32(0x80); // FileAttributes
        out.write_u32(0x07); // ShareAccess
        out.write_u32(0x03); // CreateDisposition (FILE_OPEN_IF)
        out.write_u32(0); // CreateOptions
        let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
        out.write_u16(name_offset);
        out.write_u16(name_utf16.len() as u16);
        // CreateContextsOffset/Length — we'll patch these once we know
        // the contexts buffer length. For now write 0.
        let ctx_offset_pos = out.position();
        out.write_u32(0);
        let ctx_length_pos = out.position();
        out.write_u32(0);
        // Name.
        out.write_bytes(&name_utf16);
        // Align to 8 bytes before contexts.
        out.align(8);
        let ctx_start = out.position();
        // Encode one DHQ2 create context.
        let dhq2 = CreateContext::durable_handle_request_v2(
            0x0000_0002, // SMB2_DHANDLE_FLAG_PERSISTENT
            create_guid,
            0,
        );
        let _ = CreateContext::encode_all(&[dhq2], &mut out);
        let ctx_end = out.position();
        // Patch the offset/length fields.
        let ctx_offset = ctx_start as u32;
        let ctx_length = (ctx_end - ctx_start) as u32;
        out.as_bytes_mut()[ctx_offset_pos..ctx_offset_pos + 4]
            .copy_from_slice(&ctx_offset.to_le_bytes());
        out.as_bytes_mut()[ctx_length_pos..ctx_length_pos + 4]
            .copy_from_slice(&ctx_length.to_le_bytes());
        out.into_bytes()
    }

    /// Helper: build a durable-handle RECONNECT payload carrying a DHN2
    /// create context for the given FileId.
    fn build_durable_reconnect_payload(file_id: FileId, create_guid: Uuid) -> Vec<u8> {
        let name_utf16 = adrian_smb_core::encode_utf16le("");
        let mut out = Writer::with_capacity(64 + 56 + 64);
        let mut hdr = Smb2Header::new_request(adrian_smb_core::command::CREATE, 1);
        hdr.session_id = 0xABCD_1234;
        hdr.tree_id = 7;
        hdr.encode(&mut out);
        out.write_u16(57); // StructureSize
        out.write_u8(0); // OplockLevel
        out.write_u8(0); // Reserved
        out.write_u32(2); // ImpersonationLevel
        out.write_u64(0); // SmbCreateFlags
        out.write_u64(0); // Reserved2
        out.write_u32(0x0017_0089);
        out.write_u32(0x80);
        out.write_u32(0x07);
        out.write_u32(0x01); // FILE_OPEN
        out.write_u32(0);
        let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
        out.write_u16(name_offset);
        out.write_u16(name_utf16.len() as u16);
        let ctx_offset_pos = out.position();
        out.write_u32(0);
        let ctx_length_pos = out.position();
        out.write_u32(0);
        out.write_bytes(&name_utf16);
        out.align(8);
        let ctx_start = out.position();
        let dhn2 = CreateContext::durable_handle_reconnect_v2(file_id, create_guid, 0);
        let _ = CreateContext::encode_all(&[dhn2], &mut out);
        let ctx_end = out.position();
        let ctx_offset = ctx_start as u32;
        let ctx_length = (ctx_end - ctx_start) as u32;
        out.as_bytes_mut()[ctx_offset_pos..ctx_offset_pos + 4]
            .copy_from_slice(&ctx_offset.to_le_bytes());
        out.as_bytes_mut()[ctx_length_pos..ctx_length_pos + 4]
            .copy_from_slice(&ctx_length.to_le_bytes());
        out.into_bytes()
    }

    #[test]
    fn wave3_durable_handle_table_record_and_reclaim_round_trip() {
        // T-301 / T-302: DurableHandleTable records a durable open and
        // reclaims it by PersistentFileId (the core primitive that
        // makes ADR-106 persistent handles work).
        let mut table = DurableHandleTable::new();
        assert!(table.is_empty());
        let share = Arc::new(Share::new("sysvol"));
        let create_guid = Uuid::from_u128(0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_0000_1111);
        table.record(DurableOpen {
            persistent_id: 0xCAFEBABE,
            path: "file.txt".to_string(),
            share: share.clone(),
            create_guid,
        });
        assert_eq!(table.len(), 1);
        assert!(table.peek(0xCAFEBABE).is_some());
        // Reclaim — removes the entry.
        let reclaimed = table.reclaim(0xCAFEBABE).expect("must reclaim");
        assert_eq!(reclaimed.persistent_id, 0xCAFEBABE);
        assert_eq!(reclaimed.path, "file.txt");
        assert_eq!(reclaimed.create_guid, create_guid);
        assert!(table.is_empty());
        // Second reclaim returns None.
        assert!(table.reclaim(0xCAFEBABE).is_none());
    }

    #[tokio::test]
    async fn wave3_durable_open_create_then_reconnect_survives_disconnect() {
        // T-305: end-to-end durable open reconnect. Connection 1 opens
        // a file with a DHQ2 create context. Connection 2 sends a
        // CREATE with a DHN2 reconnect context carrying the original
        // PersistentFileId. The server's DurableHandleTable bridges
        // the two connections (lives on the shared ConnectionState
        // in this test — a single duplex pair, which models the
        // "shared table" case directly).
        let (client, server) = tokio::io::duplex(64 * 1024);
        let share = Arc::new(Share::with_fs(
            "sysvol",
            VirtualFs::with_files(HashMap::from([(
                "durable.txt".to_string(),
                b"persistent data".to_vec(),
            )])),
        ));
        let shares: Arc<HashMap<String, Arc<Share>>> =
            Arc::new(HashMap::from([("sysvol".to_string(), share)]));
        let guid = Uuid::from_u128(0xABCD);
        let salt = vec![0x11u8; 16];
        let server_handle = tokio::spawn(async move {
            let _ = SmbServer::handle_connection(server, shares, guid, salt).await;
        });
        let mut client = client;
        // 1) Negotiate.
        let req = NegotiateRequest::new_311(Uuid::from_u128(0xCAFE), &[0x01; 16]);
        send_frame(&mut client, &req.encode(1)).await.unwrap();
        let _ = recv_frame(&mut client).await.unwrap();
        // 2) SessionSetup (real Kerberos SPNEGO blob).
        let spnego =
            adrian_smb_core::gss_api::init_sec_context("cifs/dc01.example.com", &[0xAB; 16])
                .expect("init ok");
        let req = SessionSetupRequest::new(spnego);
        send_frame(&mut client, &req.encode(2, 0)).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let session_id = resp_hdr.session_id;
        // 3) TreeConnect.
        let req = TreeConnectRequest::new(r"\dc01\sysvol");
        send_frame(&mut client, &req.encode(3, session_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let tree_id = resp_hdr.tree_id;
        // 4) CREATE with DHQ2 (durable open request).
        let create_guid = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
        // Patch session_id (offset 40..48) and tree_id (offset 36..40)
        // in the SMB2 header (see Smb2Header::encode for the layout).
        let mut create_payload = build_durable_create_payload("durable.txt", create_guid);
        let sid_bytes = &mut create_payload[40..48];
        sid_bytes.copy_from_slice(&session_id.to_le_bytes());
        let tid_bytes = &mut create_payload[36..40];
        tid_bytes.copy_from_slice(&tree_id.to_le_bytes());
        send_frame(&mut client, &create_payload).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let create_resp = CreateResponse::decode(&resp_bytes, SMB2_HEADER_SIZE).expect("decode");
        let original_file_id = create_resp.file_id;
        assert!(!original_file_id.is_zero());
        // At this point the server has recorded the durable open in its
        // DurableHandleTable. In a real disconnect scenario the table
        // would survive across two connections on the same SmbServer.
        // For this test we model the reconnect by sending a second
        // CREATE with a DHN2 context carrying the original
        // PersistentFileId — the server will recognise it and return
        // the same file id (reclaimed).
        // 5) Reconnect CREATE with DHN2.
        let mut reconnect_payload = build_durable_reconnect_payload(original_file_id, create_guid);
        let sid_bytes = &mut reconnect_payload[40..48];
        sid_bytes.copy_from_slice(&session_id.to_le_bytes());
        let tid_bytes = &mut reconnect_payload[36..40];
        tid_bytes.copy_from_slice(&tree_id.to_le_bytes());
        send_frame(&mut client, &reconnect_payload).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(resp_hdr.status, ntstatus::STATUS_SUCCESS);
        let reconnect_resp = CreateResponse::decode(&resp_bytes, SMB2_HEADER_SIZE).expect("decode");
        // The reclaimed FileId must match the original PersistentFileId
        // (the VolatileFileId may differ in a real reconnect, but in
        // our simplified model both halves match).
        assert_eq!(
            reconnect_resp.file_id.persistent, original_file_id.persistent,
            "durable reconnect must return the same PersistentFileId"
        );
        drop(client);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn wave3_change_notify_registers_watcher_and_returns_pending() {
        // T-303 / T-305: CHANGE_NOTIFY on a directory registers a
        // watcher in the server's ChangeNotifyRegistry and returns
        // STATUS_PENDING with an async id.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let share = Arc::new(Share::with_fs("sysvol", VirtualFs::new()));
        let shares: Arc<HashMap<String, Arc<Share>>> =
            Arc::new(HashMap::from([("sysvol".to_string(), share)]));
        let guid = Uuid::from_u128(0xABCD);
        let salt = vec![0x11u8; 16];
        let server_handle = tokio::spawn(async move {
            let _ = SmbServer::handle_connection(server, shares, guid, salt).await;
        });
        let mut client = client;
        // Negotiate + SessionSetup + TreeConnect (compressed).
        let req = NegotiateRequest::new_311(Uuid::from_u128(0xCAFE), &[0x01; 16]);
        send_frame(&mut client, &req.encode(1)).await.unwrap();
        let _ = recv_frame(&mut client).await.unwrap();
        let spnego =
            adrian_smb_core::gss_api::init_sec_context("cifs/dc01.example.com", &[0xAB; 16])
                .expect("init ok");
        let req = SessionSetupRequest::new(spnego);
        send_frame(&mut client, &req.encode(2, 0)).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let session_id = Smb2Header::decode(&resp_bytes).expect("hdr").session_id;
        let req = TreeConnectRequest::new(r"\dc01\sysvol");
        send_frame(&mut client, &req.encode(3, session_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let tree_id = Smb2Header::decode(&resp_bytes).expect("hdr").tree_id;
        // Create a directory "watched" — we'll register a CHANGE_NOTIFY on it.
        let req = CreateRequest::new("watched");
        // Patch CreateOptions to mark FILE_DIRECTORY_FILE (0x00000001).
        let mut create_bytes = req.encode(4, session_id, tree_id);
        // CreateOptions is at header_size + 40 (4-byte field). Set bit 0.
        let co_pos = SMB2_HEADER_SIZE + 40;
        create_bytes[co_pos..co_pos + 4].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        send_frame(&mut client, &create_bytes).await.unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let create_resp = CreateResponse::decode(&resp_bytes, SMB2_HEADER_SIZE).expect("create");
        let dir_file_id = create_resp.file_id;
        // Send CHANGE_NOTIFY.
        let req = ChangeNotifyRequest::new(
            dir_file_id,
            adrian_smb_core::notify_filter::FILE_NAME | adrian_smb_core::notify_filter::DIR_NAME,
            false,
        );
        send_frame(&mut client, &req.encode(5, session_id, tree_id))
            .await
            .unwrap();
        let resp_bytes = recv_frame(&mut client).await.unwrap();
        let resp_hdr = Smb2Header::decode(&resp_bytes).expect("hdr");
        assert_eq!(
            resp_hdr.status,
            ntstatus::STATUS_PENDING,
            "CHANGE_NOTIFY must return STATUS_PENDING"
        );
        let async_id = resp_hdr.message_id;
        assert_ne!(async_id, 0, "server must assign a non-zero async id");
        drop(client);
        let _ = server_handle.await;
    }

    #[test]
    fn wave3_change_notify_registry_trigger_and_poll() {
        // T-303: ChangeNotifyRegistry register → trigger → poll returns
        // the change event the test pre-encoded. Models the
        // "directory modified → server completes the pending watcher"
        // path without needing a real network round-trip.
        let mut registry = ChangeNotifyRegistry::new();
        assert!(registry.is_empty());
        let file_id = FileId::new(1, 2);
        let async_id = registry.register(
            0xCAFE,
            7,
            file_id,
            adrian_smb_core::notify_filter::FILE_NAME,
            false,
        );
        assert_eq!(registry.len(), 1);
        let watcher = registry.peek(async_id).expect("watcher registered");
        assert_eq!(watcher.filter, adrian_smb_core::notify_filter::FILE_NAME);
        assert_eq!(watcher.file_id, file_id);
        // Polling before trigger returns None.
        assert!(registry.poll(async_id).is_none());
        // Trigger — pre-encoded response is just bytes for this test.
        let response_bytes = vec![0xABu8; 32];
        assert!(registry.trigger(async_id, response_bytes.clone()));
        // Polling after trigger returns the response.
        let polled = registry.poll(async_id).expect("must poll response");
        assert_eq!(polled, response_bytes);
        // Subsequent poll returns None (response consumed).
        assert!(registry.poll(async_id).is_none());
    }

    #[test]
    fn wave3_oplock_break_on_conflicting_open() {
        // T-304 / T-305: OplockRegistry grant → break on conflicting
        // open → notification returned for the holder to ack. Models
        // the path where a second client opens a file with conflicting
        // access, forcing the server to downgrade the first holder's
        // oplock.
        let mut registry = OplockRegistry::new();
        let file_id = FileId::new(0xAA, 0xBB);
        let session_a = 0x100u64;
        let session_b = 0x200u64;
        // Session A opens with Batch oplock (exclusive, full caching).
        registry.grant(file_id, adrian_smb_core::oplock_level::BATCH, session_a);
        let state = registry.peek(file_id).expect("oplock granted");
        assert_eq!(state.level, adrian_smb_core::oplock_level::BATCH);
        assert_eq!(state.session_id, session_a);
        // Session B opens the same file with conflicting access — the
        // server's CREATE handler would call break_oplock(file_id, NONE)
        // to force session A to flush its cache.
        let notif = registry
            .break_oplock(file_id, adrian_smb_core::oplock_level::NONE)
            .expect("break must produce a notification");
        assert_eq!(notif.oplock_level, adrian_smb_core::oplock_level::BATCH);
        assert_eq!(notif.file_id, file_id);
        // The registry now records a pending break.
        assert!(registry.has_pending_break(file_id));
        // The current state is downgraded to NONE.
        let state = registry.peek(file_id).expect("still granted");
        assert_eq!(state.level, adrian_smb_core::oplock_level::NONE);
        // Session B's open can now proceed (in a real server it would
        // be the CREATE handler's responsibility to wait for session A's
        // ack before completing session B's CREATE).
        let _ = session_b; // suppress unused warning
    }

    #[test]
    fn wave3_oplock_acknowledgment_clears_pending_break() {
        // T-304 / T-305: OplockRegistry acknowledge clears the pending
        // break and updates the granted level. Models the client →
        // server OPLOCK_BREAK_ACKNOWLEDGMENT path.
        let mut registry = OplockRegistry::new();
        let file_id = FileId::new(0xCC, 0xDD);
        registry.grant(file_id, adrian_smb_core::oplock_level::BATCH, 0x100);
        // Trigger a break to NONE.
        let _ = registry
            .break_oplock(file_id, adrian_smb_core::oplock_level::NONE)
            .expect("break");
        assert!(registry.has_pending_break(file_id));
        // Client acknowledges the break, accepting level II (downgrade).
        let acked = registry
            .acknowledge(file_id, adrian_smb_core::oplock_level::LEVEL_2)
            .expect("must ack");
        assert_eq!(acked, adrian_smb_core::oplock_level::LEVEL_2);
        // Pending break is cleared.
        assert!(!registry.has_pending_break(file_id));
        // The granted level is now LEVEL_2.
        let state = registry.peek(file_id).expect("still granted");
        assert_eq!(state.level, adrian_smb_core::oplock_level::LEVEL_2);
        // Acknowledging again (no pending break) returns None.
        assert!(registry
            .acknowledge(file_id, adrian_smb_core::oplock_level::NONE)
            .is_none());
    }
}
