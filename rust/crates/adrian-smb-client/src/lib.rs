#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # adrian-smb-client
//!
//! Minimal SMB 3.1.1 client — backs the SDK's `FileModule`. Persistent
//! handles (resilient open) per ADR-106; used by the SDK's
//! macOS/Windows/Linux FileModule.
//!
//! ## Coverage (Wave 3b)
//!
//! - Connect over any `AsyncRead + AsyncWrite + Unpin` stream (real TCP
//!   via `tokio::net::TcpStream`, or in-memory `tokio::io::duplex` for
//!   tests).
//! - NetBIOS Session Service framing (4-byte length header + payload).
//! - SMB 3.1.1 Negotiate with SHA-512 preauth-integrity advertisement.
//! - SessionSetup (sends a dummy SPNEGO blob; the Wave 3b server accepts
//!   any blob per the stub documented in ADR-105 §6).
//! - TreeConnect to `\\server\share`.
//! - Create / Read / Write / Close with FileId tracking.
//! - Logoff.
//!
//! Real Kerberos / NTLM acceptor integration, persistent-handle table,
//! and DFS-N referral handling are deferred to later waves per ADR-105 /
//! ADR-106.
//!
//! ## ADRs
//!
//! - ADR-106: SMB client persistent handles (SDK FileModule)
//! - ADR-043: SMB1 dropped; SMB 2.0.2 minimum, 3.1.1 default
//! - ADR-107: Unified Rust core SDK (this client is the SDK's SMB backend)
//! - ADR-044: DFS-N via DNS SRV records (referral-aware client)

use adrian_smb_core::netbios;
use adrian_smb_core::{
    ntstatus, CloseRequest, CloseResponse, CreateRequest, CreateResponse, FileId, LogoffRequest,
    LogoffResponse, NegotiateRequest, NegotiateResponse, PreauthHash, ReadRequest, ReadResponse,
    SessionSetupRequest, SessionSetupResponse, Smb2Header, SmbError, TreeConnectRequest,
    TreeConnectResponse, WriteRequest, WriteResponse, SMB2_HEADER_SIZE,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

// ============================================================================
// Errors
// ============================================================================

/// SMB client error.
#[derive(Debug, Error)]
pub enum SmbClientError {
    /// Connection-level failure (TCP refused, TLS handshake, etc).
    #[error("connect: {0}")]
    Connect(String),
    /// Authentication failure.
    #[error("auth: {0}")]
    Auth(String),
    /// Share / tree-level failure (share not found, tree disconnected).
    #[error("share: {0}")]
    Share(String),
    /// File-level failure (file not found, file closed, EOF).
    #[error("file: {0}")]
    File(String),
    /// NT status code returned by the server.
    #[error("status: {0:#x}")]
    Status(u32),
    /// Underlying I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Codec error (lifted from `adrian-smb-core`).
    #[error("codec: {0}")]
    Codec(#[from] SmbError),
}

// ============================================================================
// Client state
// ============================================================================

/// SMB client session — owns one transport stream and the per-session
/// state machine (message IDs, session ID, tree ID, preauth hash).
pub struct SmbClient<S> {
    stream: S,
    client_guid: Uuid,
    next_message_id: u64,
    session_id: u64,
    tree_id: u32,
    /// Preauth-integrity hash chain (updated with every Negotiate /
    /// SessionSetup PDU). Not yet used for signing (Wave 3b plaintext).
    preauth: PreauthHash,
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin> SmbClient<S> {
    /// Construct a new client over an already-connected stream.
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            client_guid: Uuid::from_u128(0xAD0C_0000_0000_0000_0000_0000_0000_0001),
            next_message_id: 1,
            session_id: 0,
            tree_id: 0,
            preauth: PreauthHash::new(),
        }
    }

    /// Construct a new client with a specific client GUID (useful for tests).
    #[must_use]
    pub fn with_guid(stream: S, client_guid: Uuid) -> Self {
        Self {
            stream,
            client_guid,
            next_message_id: 1,
            session_id: 0,
            tree_id: 0,
            preauth: PreauthHash::new(),
        }
    }

    /// Borrow the underlying stream (for close / shutdown).
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Mutably borrow the underlying stream.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Current session ID (0 until SessionSetup completes).
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Current tree ID (0 until TreeConnect completes).
    #[must_use]
    pub fn tree_id(&self) -> u32 {
        self.tree_id
    }

    // ---- Transport primitives ----

    async fn send_raw(&mut self, payload: &[u8]) -> Result<(), SmbClientError> {
        let frame = netbios::encode_frame(payload);
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn recv_raw(&mut self) -> Result<Vec<u8>, SmbClientError> {
        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header).await?;
        let len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
        if len > 16 * 1024 * 1024 {
            return Err(SmbClientError::Connect(format!(
                "frame too large: {len} bytes"
            )));
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;
        Ok(payload)
    }

    /// Send `request` and wait for the matching response. Returns the
    /// response bytes (header + body).
    async fn round_trip(&mut self, request: &[u8]) -> Result<Vec<u8>, SmbClientError> {
        self.send_raw(request).await?;
        let resp = self.recv_raw().await?;
        // Decode the response header to surface NT status codes.
        let hdr = Smb2Header::decode(&resp)?;
        if hdr.status != ntstatus::STATUS_SUCCESS {
            return Err(SmbClientError::Status(hdr.status));
        }
        Ok(resp)
    }

    fn next_message_id(&mut self) -> u64 {
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }

    // ---- Protocol operations ----

    /// Send an SMB 3.1.1 NEGOTIATE request and return the server's
    /// response. Updates the preauth-integrity hash chain.
    pub async fn negotiate(&mut self) -> Result<NegotiateResponse, SmbClientError> {
        let salt = vec![0xCBu8; 32];
        let req = NegotiateRequest::new_311(self.client_guid, &salt);
        let bytes = req.encode(self.next_message_id());
        // Update preauth hash with the request bytes (per MS-SMB2 §3.2.5.1).
        self.preauth.update(&bytes);
        let resp_bytes = self.round_trip(&bytes).await?;
        // Update preauth hash with the response bytes.
        self.preauth.update(&resp_bytes);
        let resp = NegotiateResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp)
    }

    /// Send a SESSION_SETUP request (with the given SPNEGO blob) and
    /// return the server's response. The client adopts the session ID
    /// assigned by the server.
    pub async fn session_setup(
        &mut self,
        security_buffer: Vec<u8>,
    ) -> Result<SessionSetupResponse, SmbClientError> {
        let req = SessionSetupRequest::new(security_buffer);
        let bytes = req.encode(self.next_message_id(), self.session_id);
        // SessionSetup is part of the preauth-integrity chain (§3.2.5.1).
        self.preauth.update(&bytes);
        // We need to capture the session_id from the response header even
        // on non-success status (STATUS_MORE_PROCESSING_REQUIRED).
        self.send_raw(&bytes).await?;
        let resp_bytes = self.recv_raw().await?;
        self.preauth.update(&resp_bytes);
        let hdr = Smb2Header::decode(&resp_bytes)?;
        // Adopt the session ID.
        if hdr.session_id != 0 {
            self.session_id = hdr.session_id;
        }
        if hdr.status != ntstatus::STATUS_SUCCESS
            && hdr.status != ntstatus::STATUS_MORE_PROCESSING_REQUIRED
        {
            return Err(SmbClientError::Status(hdr.status));
        }
        let resp = SessionSetupResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp)
    }

    /// Send a TREE_CONNECT request to `\\server\share` and return the
    /// server's response. The client adopts the tree ID assigned by the
    /// server.
    pub async fn tree_connect(
        &mut self,
        path: &str,
    ) -> Result<TreeConnectResponse, SmbClientError> {
        let req = TreeConnectRequest::new(path);
        let bytes = req.encode(self.next_message_id(), self.session_id);
        let resp_bytes = self.round_trip(&bytes).await?;
        let hdr = Smb2Header::decode(&resp_bytes)?;
        if hdr.tree_id != 0 {
            self.tree_id = hdr.tree_id;
        }
        let resp = TreeConnectResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp)
    }

    /// Send a CREATE request for `name` (relative to the tree root) and
    /// return the server's response (which includes the granted FileId).
    pub async fn create(&mut self, name: &str) -> Result<CreateResponse, SmbClientError> {
        let req = CreateRequest::new(name);
        let bytes = req.encode(self.next_message_id(), self.session_id, self.tree_id);
        let resp_bytes = self.round_trip(&bytes).await?;
        let resp = CreateResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp)
    }

    /// Send a READ request for `length` bytes at `offset` on `file_id`.
    /// Returns the bytes actually read.
    pub async fn read(
        &mut self,
        file_id: FileId,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, SmbClientError> {
        let req = ReadRequest::new(file_id, offset, length);
        let bytes = req.encode(self.next_message_id(), self.session_id, self.tree_id);
        let resp_bytes = self.round_trip(&bytes).await?;
        let resp = ReadResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp.data)
    }

    /// Send a WRITE request carrying `data` to be written at `offset` on
    /// `file_id`. Returns the number of bytes written.
    pub async fn write(
        &mut self,
        file_id: FileId,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<u32, SmbClientError> {
        let req = WriteRequest::new(file_id, offset, data);
        let bytes = req.encode(self.next_message_id(), self.session_id, self.tree_id);
        let resp_bytes = self.round_trip(&bytes).await?;
        let resp = WriteResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp.count)
    }

    /// Send a CLOSE request for `file_id`. Returns the server's response.
    pub async fn close(&mut self, file_id: FileId) -> Result<CloseResponse, SmbClientError> {
        let req = CloseRequest::new(file_id);
        let bytes = req.encode(self.next_message_id(), self.session_id, self.tree_id);
        let resp_bytes = self.round_trip(&bytes).await?;
        let resp = CloseResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp)
    }

    /// Send a LOGOFF request. Drops the session on the server.
    pub async fn logoff(&mut self) -> Result<LogoffResponse, SmbClientError> {
        let req = LogoffRequest;
        let bytes = req.encode(self.next_message_id(), self.session_id);
        let resp_bytes = self.round_trip(&bytes).await?;
        let resp = LogoffResponse::decode(&resp_bytes, SMB2_HEADER_SIZE)?;
        Ok(resp)
    }

    /// Snapshot the current preauth-integrity hash (for debugging /
    /// test assertions).
    #[must_use]
    pub fn preauth_hash(&self) -> [u8; 64] {
        self.preauth.current()
    }
}

/// Convenience: connect to an SMB server over TCP, returning a client.
///
/// # Errors
///
/// Returns `Err` if the TCP connection cannot be established.
pub async fn connect_tcp(addr: &str) -> Result<SmbClient<tokio::net::TcpStream>, SmbClientError> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| SmbClientError::Connect(format!("tcp: {e}")))?;
    Ok(SmbClient::new(stream))
}

/// Build a default SPNEGO blob for the SessionSetup request. The Wave 3b
/// server accepts any blob, so this is a placeholder; real Kerberos /
/// NTLM tokens are wired in a later wave.
#[must_use]
pub fn default_spnego_blob() -> Vec<u8> {
    // Minimal SPNEGO NegTokenInit wrapping — not a real GSS-API blob,
    // just enough to exercise the codec.
    vec![0x60, 0x06, 0x06, 0x02, 0x2A, 0x03, 0x01, 0x00]
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_smb_server::{Share, SmbServer, VirtualFs};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::io::duplex;

    /// Stand up a server over a duplex pair and return a connected client
    /// plus the server's task handle.
    async fn spawn_server(
        files: HashMap<String, Vec<u8>>,
    ) -> (
        SmbClient<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<()>,
    ) {
        let (client_stream, server_stream) = duplex(64 * 1024);
        let share = Arc::new(Share::with_fs("sysvol", VirtualFs::with_files(files)));
        let shares: Arc<HashMap<String, Arc<Share>>> =
            Arc::new(HashMap::from([("sysvol".to_string(), share)]));
        let guid = Uuid::from_u128(0xABCD_0000_0000_0000_0000_0000_0000_0001);
        let salt = vec![0x11u8; 32];
        let handle = tokio::spawn(async move {
            let _ = SmbServer::handle_connection(server_stream, shares, guid, salt).await;
        });
        let client = SmbClient::with_guid(
            client_stream,
            Uuid::from_u128(0xCAFE_0000_0000_0000_0000_0000_0000_0001),
        );
        (client, handle)
    }

    // ---- Public API contracts ----

    #[test]
    fn error_variants_render_expected_prefixes() {
        assert_eq!(
            format!("{}", SmbClientError::Connect("tcp refused".into())),
            "connect: tcp refused"
        );
        assert_eq!(
            format!("{}", SmbClientError::Auth("spnego failed".into())),
            "auth: spnego failed"
        );
        assert_eq!(
            format!("{}", SmbClientError::Share("tree disconnected".into())),
            "share: tree disconnected"
        );
        assert_eq!(
            format!("{}", SmbClientError::File("not found".into())),
            "file: not found"
        );
        let io = SmbClientError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        ));
        assert!(format!("{io}").starts_with("io: "));
        let codec = SmbClientError::Codec(SmbError::Malformed("truncated".into()));
        assert!(format!("{codec}").contains("codec:"));
        let status = SmbClientError::Status(0xC000_0022);
        assert!(format!("{status}").contains("0xc0000022"));
    }

    #[test]
    fn io_error_converts_via_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "rst by peer");
        let smb_err: SmbClientError = io_err.into();
        match smb_err {
            SmbClientError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn default_spnego_blob_is_non_empty() {
        let blob = default_spnego_blob();
        assert!(!blob.is_empty());
        assert_eq!(blob[0], 0x60); // SPNECO NegTokenInit tag
    }

    // ---- End-to-end (duplex) ----

    #[tokio::test]
    async fn client_negotiate_round_trips_with_server() {
        let files = HashMap::from([("hello.txt".to_string(), b"hello".to_vec())]);
        let (mut client, server_handle) = spawn_server(files).await;
        let resp = client.negotiate().await.expect("negotiate ok");
        assert_eq!(resp.dialect_revision, adrian_smb_core::dialect_code::SMB311);
        assert!(!resp.server_guid.is_nil());
        // Preauth hash should be non-zero after Negotiate.
        let preauth = client.preauth_hash();
        assert!(preauth.iter().any(|&b| b != 0));
        drop(client);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn client_full_session_create_read_write_close_round_trips() {
        let files = HashMap::from([("greeting.txt".to_string(), b"hello, world!".to_vec())]);
        let (mut client, server_handle) = spawn_server(files).await;

        // Negotiate.
        let _ = client.negotiate().await.expect("negotiate");
        // SessionSetup.
        let _ = client
            .session_setup(default_spnego_blob())
            .await
            .expect("session setup");
        assert_ne!(client.session_id(), 0);
        // TreeConnect.
        let _ = client
            .tree_connect(r"\dc01\sysvol")
            .await
            .expect("tree connect");
        assert_ne!(client.tree_id(), 0);
        // Create.
        let create_resp = client.create("greeting.txt").await.expect("create");
        assert_eq!(create_resp.end_of_file, 13);
        let file_id = create_resp.file_id;
        assert!(!file_id.is_zero());
        // Read.
        let data = client.read(file_id, 0, 1024).await.expect("read");
        assert_eq!(data, b"hello, world!");
        // Write (append).
        let n = client
            .write(file_id, 13, b" goodbye!".to_vec())
            .await
            .expect("write");
        assert_eq!(n, 9);
        // Close.
        let _ = client.close(file_id).await.expect("close");
        // Logoff.
        let _ = client.logoff().await.expect("logoff");

        drop(client);
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn client_status_code_surfaces_on_unknown_share() {
        let files = HashMap::new();
        let (mut client, server_handle) = spawn_server(files).await;
        let _ = client.negotiate().await.expect("negotiate");
        let _ = client
            .session_setup(default_spnego_blob())
            .await
            .expect("session setup");
        // TreeConnect to a share that doesn't exist.
        let err = client
            .tree_connect(r"\dc01\nonexistent")
            .await
            .expect_err("should fail");
        match err {
            SmbClientError::Status(s) => {
                assert_eq!(s, ntstatus::STATUS_BAD_NETWORK_NAME);
            }
            other => panic!("expected Status, got {other:?}"),
        }
        drop(client);
        let _ = server_handle.await;
    }

    // ---- Public-API tests kept from the stub ----

    #[test]
    fn client_constructs_with_stream() {
        let (_client_stream, server_stream) = duplex(1024);
        let _client = SmbClient::new(server_stream);
    }

    #[test]
    fn client_with_guid_uses_provided_guid() {
        let (_client_stream, server_stream) = duplex(1024);
        let guid = Uuid::from_u128(0xDEAD_BEEF);
        let client = SmbClient::with_guid(server_stream, guid);
        // No public getter for the GUID — just assert construction works
        // without panic.
        let _ = client;
    }

    #[test]
    fn smb_client_error_status_display_is_hex() {
        let err = SmbClientError::Status(0xC000_0022);
        let msg = format!("{err}");
        assert!(msg.contains("status:"));
        assert!(msg.contains("0xc0000022"));
    }
}
