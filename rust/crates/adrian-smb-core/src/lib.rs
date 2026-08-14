#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # adrian-smb-core
//!
//! SMB 3.1.1 protocol primitives shared by `adrian-smb-server` and
//! `adrian-smb-client`. Wire codecs are hand-written against [MS-SMB2]
//! (no `rasn` / `pavao` dependency — SMB2 is plain little-endian
//! integers and length-prefixed byte arrays, not ASN.1).
//!
//! ## Coverage
//!
//! - [`Smb2Header`] — the 64-byte fixed SMB2 packet header (§2.2.1.1)
//! - [`NegotiateRequest`] / [`NegotiateResponse`] — command 0x0000 (§2.2.3)
//! - [`SessionSetupRequest`] / [`SessionSetupResponse`] — command 0x0001 (§2.2.5)
//! - [`TreeConnectRequest`] / [`TreeConnectResponse`] — command 0x0003 (§2.2.8/9)
//! - [`CreateRequest`] / [`CreateResponse`] — command 0x0005 (§2.2.13/14)
//! - [`ReadRequest`] / [`ReadResponse`] — command 0x0008 (§2.2.19/20)
//! - [`WriteRequest`] / [`WriteResponse`] — command 0x0009 (§2.2.21/22)
//! - [`CloseRequest`] / [`CloseResponse`] — command 0x0006 (§2.2.14/15)
//! - [`LogoffRequest`] / [`LogoffResponse`] — command 0x0002 (§2.2.2/3)
//! - [`EchoRequest`] / [`EchoResponse`] — command 0x000d (§2.2.28/29)
//! - [`PreauthHash`] — SHA-512 pre-auth integrity hash (§3.2.5.1)
//! - [`TransformHeader`] — SMB 3.1.1 transform header for encrypted PDUs (§2.2.41)
//! - [`SmbEncryptionKey`] — AES-256-GCM session encryption key (§3.2.5.2)
//! - [`encrypt_pdu`] / [`decrypt_pdu`] — AEAD encrypt/decrypt of SMB2 PDUs (§3.2.4.3)
//!
//! ## ADRs
//!
//! - ADR-043: Drop SMB1; SMB 2.0.2 minimum, 3.1.1 default
//! - ADR-105: Fresh Rust SMB 3.1.1 server (memory-safe, async)
//! - ADR-106: SMB client with persistent handles (SDK FileModule)

use thiserror::Error;
use zeroize::Zeroize;

// ============================================================================
// Errors
// ============================================================================

/// SMB protocol error (codec / transport level).
#[derive(Debug, Error)]
pub enum SmbError {
    /// PDU is malformed (wrong magic, truncated, etc).
    #[error("malformed: {0}")]
    Malformed(String),
    /// NT status code returned by the peer.
    #[error("status: {0:#x}")]
    Status(u32),
    /// Dialect unsupported (e.g. SMB1 refused per ADR-043).
    #[error("dialect unsupported")]
    DialectUnsupported,
    /// SMB1 refused per ADR-043.
    #[error("smb1 refused (per ADR-043)")]
    Smb1Refused,
    /// Encryption failure (cipher not negotiated, AEAD tag mismatch, etc).
    #[error("encryption: {0}")]
    Encryption(String),
    /// Pre-auth integrity hash mismatch (downgrade / MITM detection).
    #[error("integrity: {0}")]
    Integrity(String),
    /// Underlying I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// NT status codes (subset used by this crate). MS-ERREF.
// ============================================================================

/// NT status codes (subset). All `STATUS_*` constants per MS-ERREF.
pub mod ntstatus {
    /// `0x00000000` — success.
    pub const STATUS_SUCCESS: u32 = 0x0000_0000;
    /// `0xC000000D` — invalid SMB2 parameter.
    pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    /// `0xC0000010` — invalid device request (e.g. wrong command for session).
    pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    /// `0xC000000F` — `STATUS_NO_SUCH_FILE` (create with `FILE_OPEN` on missing).
    pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
    /// `0xC0000011` — read past end of file (with `SL_READ_AT_OFFSET`).
    pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
    /// `0xC0000016` — `STATUS_MORE_PROCESSING_REQUIRED` (mid session-setup).
    pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    /// `0xC0000022` — `STATUS_ACCESS_DENIED`.
    pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    /// `0xC0000034` — `STATUS_OBJECT_NAME_NOT_FOUND` (tree connect unknown share).
    pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    /// `0xC0000035` — `STATUS_OBJECT_NAME_COLLISION` (create with `FILE_CREATE`
    /// on existing).
    pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    /// `0xC000006D` — `STATUS_LOGON_FAILURE` (Kerberos / NTLM auth refused).
    pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
    /// `0xC00000CC` — `STATUS_BAD_NETWORK_NAME` (share not on this server).
    pub const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
    /// `0xC0000128` — `STATUS_FILE_CLOSED` (file handle unknown).
    pub const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
}

// ============================================================================
// Wire constants — magic bytes, header sizes, command codes, flags, dialects
// ============================================================================

/// SMB2 magic: `0xFE 'S' 'M' 'B'` (the first 4 bytes of every SMB2 packet).
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// SMB1 magic: `0xFF 'S' 'M' 'B'` — refused per ADR-043.
pub const SMB1_MAGIC: [u8; 4] = [0xFF, b'S', b'M', b'B'];

/// SMB2 Transform-header magic: `0xFD 'S' 'M' 'B'` (encrypted PDU prefix).
pub const SMB2_TRANSFORM_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];

/// SMB2 fixed header size (bytes).
pub const SMB2_HEADER_SIZE: usize = 64;

/// SMB2 Transform-header fixed size (bytes).
pub const SMB2_TRANSFORM_HEADER_SIZE: usize = 52;

/// Maximum SMB2 PDU size (1 MiB; matches Windows Server default).
pub const MAX_SMB2_MESSAGE_SIZE: u32 = 1 << 20;

/// SMB2 command codes per MS-SMB2 §2.2.1.1.
pub mod command {
    /// `0x0000` — NEGOTIATE.
    pub const NEGOTIATE: u16 = 0x0000;
    /// `0x0001` — SESSION_SETUP.
    pub const SESSION_SETUP: u16 = 0x0001;
    /// `0x0002` — LOGOFF.
    pub const LOGOFF: u16 = 0x0002;
    /// `0x0003` — TREE_CONNECT.
    pub const TREE_CONNECT: u16 = 0x0003;
    /// `0x0004` — TREE_DISCONNECT.
    pub const TREE_DISCONNECT: u16 = 0x0004;
    /// `0x0005` — CREATE.
    pub const CREATE: u16 = 0x0005;
    /// `0x0006` — CLOSE.
    pub const CLOSE: u16 = 0x0006;
    /// `0x0008` — READ.
    pub const READ: u16 = 0x0008;
    /// `0x0009` — WRITE.
    pub const WRITE: u16 = 0x0009;
    /// `0x000D` — ECHO.
    pub const ECHO: u16 = 0x000D;
    /// `0x00F2` — TRANSFORM (encrypted PDU).
    pub const TRANSFORM: u16 = 0x00F2;
}

/// SMB2 header Flags bits per MS-SMB2 §2.2.1.2.
pub mod flags {
    /// `0x00000001` — RESPONSE (server→client).
    pub const SMB2_FLAGS_RESPONSE: u32 = 0x0000_0001;
    /// `0x00000002` — ASYNC (async-id variant).
    pub const SMB2_FLAGS_ASYNC: u32 = 0x0000_0002;
    /// `0x00000004` — RELATED_OPERATIONS (chained request).
    pub const SMB2_FLAGS_RELATED_OPERATIONS: u32 = 0x0000_0004;
    /// `0x00000008` — SIGNED (signature valid).
    pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;
    /// `0x20000000` — REPLAY_OPERATION (3.1.1+).
    pub const SMB2_FLAGS_REPLAY_OPERATION: u32 = 0x2000_0000;
}

/// SMB2 dialect wire codes (u16 LE per MS-SMB2 §2.2.3.1.1 / §2.2.4.1.2).
pub mod dialect_code {
    /// `0x0202` — SMB 2.0.2 (minimum supported per ADR-043).
    pub const SMB202: u16 = 0x0202;
    /// `0x0210` — SMB 2.1.
    pub const SMB210: u16 = 0x0210;
    /// `0x0300` — SMB 3.0.
    pub const SMB300: u16 = 0x0300;
    /// `0x0302` — SMB 3.0.2.
    pub const SMB302: u16 = 0x0302;
    /// `0x0311` — SMB 3.1.1 (default per ADR-043 / ADR-105).
    pub const SMB311: u16 = 0x0311;
}

/// SMB2 negotiate SecurityMode bits per MS-SMB2 §2.2.3.1.3 / §2.2.4.1.3.
pub mod security_mode {
    /// `0x0001` — SMB2_NEGOTIATE_SIGNING_ENABLED.
    pub const SIGNING_ENABLED: u16 = 0x0001;
    /// `0x0002` — SMB2_NEGOTIATE_SIGNING_REQUIRED.
    pub const SIGNING_REQUIRED: u16 = 0x0002;
}

/// SMB2 negotiate Capabilities bits per MS-SMB2 §2.2.3.1.4 / §2.2.4.1.5.
pub mod capabilities {
    /// `0x00000001` — SMB2_GLOBAL_CAP_DFS.
    pub const DFS: u32 = 0x0000_0001;
    /// `0x00000002` — SMB2_GLOBAL_CAP_LEASING.
    pub const LEASING: u32 = 0x0000_0002;
    /// `0x00000004` — SMB2_GLOBAL_CAP_LARGE_MTU.
    pub const LARGE_MTU: u32 = 0x0000_0004;
    /// `0x00000008` — SMB2_GLOBAL_CAP_MULTI_CHANNEL.
    pub const MULTI_CHANNEL: u32 = 0x0000_0008;
    /// `0x00000010` — SMB2_GLOBAL_CAP_PERSISTENT_HANDLES.
    pub const PERSISTENT_HANDLES: u32 = 0x0000_0010;
    /// `0x00000020` — SMB2_GLOBAL_CAP_DIRECTORY_LEASING.
    pub const DIRECTORY_LEASING: u32 = 0x0000_0020;
    /// `0x00000040` — SMB2_GLOBAL_CAP_ENCRYPTION (3.0/3.0.2).
    pub const ENCRYPTION: u32 = 0x0000_0040;
}

/// Negotiate context types per MS-SMB2 §2.2.3.1.6 / §2.2.4.1.6.
pub mod negotiate_context_type {
    /// `0x0001` — `SMB2_PREAUTH_INTEGRITY_CAPABILITIES`.
    pub const PREAUTH_INTEGRITY: u16 = 0x0001;
    /// `0x0002` — `SMB2_ENCRYPTION_CAPABILITIES`.
    pub const ENCRYPTION: u16 = 0x0002;
    /// `0x0007` — `SMB2_SIGNING_CAPABILITIES`.
    pub const SIGNING: u16 = 0x0007;
}

/// Preauth integrity hash algorithm IDs per MS-SMB2 §2.2.3.1.6.1.
pub mod preauth_hash_algo {
    /// `0x0001` — SHA-512 (the only algorithm defined by MS-SMB2 §3.2.5.1.1).
    pub const SHA512: u16 = 0x0001;
}

/// Encryption cipher IDs per MS-SMB2 §2.2.3.1.6.2.
pub mod cipher {
    /// `0x0001` — AES-128-CCM.
    pub const AES_128_CCM: u16 = 0x0001;
    /// `0x0002` — AES-128-GCM.
    pub const AES_128_GCM: u16 = 0x0002;
    /// `0x0003` — AES-256-CCM.
    pub const AES_256_CCM: u16 = 0x0003;
    /// `0x0004` — AES-256-GCM (the framework default per ADR-105 §4).
    pub const AES_256_GCM: u16 = 0x0004;
}

/// Signing algorithm IDs per MS-SMB2 §2.2.3.1.6.4 (3.1.1+).
pub mod signing_algo {
    /// `0x0000` — HMAC-SHA256 (2.x+ default).
    pub const HMAC_SHA256: u16 = 0x0000;
    /// `0x0001` — AES-CMAC (3.0+).
    pub const AES_CMAC: u16 = 0x0001;
    /// `0x0002` — AES-GMAC (3.1.1+ default per ADR-105 §5).
    pub const AES_GMAC: u16 = 0x0002;
}

/// TreeConnect ShareType values per MS-SMB2 §2.2.9.2.
pub mod share_type {
    /// `0x01` — disk share.
    pub const DISK: u8 = 0x01;
    /// `0x02` — named-pipe share.
    pub const PIPE: u8 = 0x02;
    /// `0x03` — print share.
    pub const PRINT: u8 = 0x03;
}

/// SMB2 dialect revision (typed wrapper).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// SMB 2.0.2 (minimum supported per ADR-043).
    Smb202,
    /// SMB 2.1.
    Smb210,
    /// SMB 3.0.
    Smb300,
    /// SMB 3.0.2.
    Smb302,
    /// SMB 3.1.1 (default per ADR-043 / ADR-105).
    Smb311,
}

impl Dialect {
    /// Encode to the wire u16.
    #[must_use]
    pub fn to_wire(self) -> u16 {
        match self {
            Dialect::Smb202 => dialect_code::SMB202,
            Dialect::Smb210 => dialect_code::SMB210,
            Dialect::Smb300 => dialect_code::SMB300,
            Dialect::Smb302 => dialect_code::SMB302,
            Dialect::Smb311 => dialect_code::SMB311,
        }
    }

    /// Decode from the wire u16. Returns `None` for unknown dialect codes.
    #[must_use]
    pub fn from_wire(v: u16) -> Option<Self> {
        match v {
            dialect_code::SMB202 => Some(Dialect::Smb202),
            dialect_code::SMB210 => Some(Dialect::Smb210),
            dialect_code::SMB300 => Some(Dialect::Smb300),
            dialect_code::SMB302 => Some(Dialect::Smb302),
            dialect_code::SMB311 => Some(Dialect::Smb311),
            _ => None,
        }
    }

    /// True for SMB 3.1.1 (the framework default per ADR-043).
    #[must_use]
    pub fn is_311(self) -> bool {
        matches!(self, Dialect::Smb311)
    }
}

/// SMB2 command code (typed wrapper around the wire code).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Command {
    /// `0x0000` — NEGOTIATE.
    Negotiate = 0x0000,
    /// `0x0001` — SESSION_SETUP.
    SessionSetup = 0x0001,
    /// `0x0002` — LOGOFF.
    Logoff = 0x0002,
    /// `0x0003` — TREE_CONNECT.
    TreeConnect = 0x0003,
    /// `0x0004` — TREE_DISCONNECT.
    TreeDisconnect = 0x0004,
    /// `0x0005` — CREATE.
    Create = 0x0005,
    /// `0x0006` — CLOSE.
    Close = 0x0006,
    /// `0x0008` — READ.
    Read = 0x0008,
    /// `0x0009` — WRITE.
    Write = 0x0009,
    /// `0x000D` — ECHO.
    Echo = 0x000d,
    /// `0x00F2` — TRANSFORM (encrypted PDU).
    Transform = 0x00F2,
}

impl Command {
    /// Encode to the wire u16.
    #[must_use]
    pub fn to_wire(self) -> u16 {
        self as u16
    }

    /// Decode from the wire u16.
    #[must_use]
    pub fn from_wire(v: u16) -> Option<Self> {
        match v {
            0x0000 => Some(Command::Negotiate),
            0x0001 => Some(Command::SessionSetup),
            0x0002 => Some(Command::Logoff),
            0x0003 => Some(Command::TreeConnect),
            0x0004 => Some(Command::TreeDisconnect),
            0x0005 => Some(Command::Create),
            0x0006 => Some(Command::Close),
            0x0008 => Some(Command::Read),
            0x0009 => Some(Command::Write),
            0x000D => Some(Command::Echo),
            0x00F2 => Some(Command::Transform),
            _ => None,
        }
    }
}

// ============================================================================
// Reader/Writer helpers (no unsafe — plain slice indexing).
// ============================================================================

/// Cursor-style reader over a borrowed byte slice. Used by every `decode`
/// function. Tracks an absolute position from the start of the SMB2 message
/// (header + body) so SMB2's absolute-offset fields work directly.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Construct a reader at position 0 over `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Construct a reader at absolute position `pos`.
    pub fn at(buf: &'a [u8], pos: usize) -> Result<Self, SmbError> {
        if pos > buf.len() {
            return Err(SmbError::Malformed(format!(
                "seek past end: {pos} > {}",
                buf.len()
            )));
        }
        Ok(Self { buf, pos })
    }

    /// Remaining unread bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Current absolute position.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Seek to an absolute position.
    pub fn seek(&mut self, pos: usize) -> Result<(), SmbError> {
        if pos > self.buf.len() {
            return Err(SmbError::Malformed(format!(
                "seek past end: {pos} > {}",
                self.buf.len()
            )));
        }
        self.pos = pos;
        Ok(())
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, SmbError> {
        if self.pos + 1 > self.buf.len() {
            return Err(SmbError::Malformed("eof reading u8".into()));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a u16 little-endian.
    pub fn read_u16(&mut self) -> Result<u16, SmbError> {
        if self.pos + 2 > self.buf.len() {
            return Err(SmbError::Malformed("eof reading u16".into()));
        }
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a u32 little-endian.
    pub fn read_u32(&mut self) -> Result<u32, SmbError> {
        if self.pos + 4 > self.buf.len() {
            return Err(SmbError::Malformed("eof reading u32".into()));
        }
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read a u64 little-endian.
    pub fn read_u64(&mut self) -> Result<u64, SmbError> {
        if self.pos + 8 > self.buf.len() {
            return Err(SmbError::Malformed("eof reading u64".into()));
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read `n` raw bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], SmbError> {
        if self.pos + n > self.buf.len() {
            return Err(SmbError::Malformed(format!(
                "eof reading {n} bytes at pos {}",
                self.pos
            )));
        }
        let v = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(v)
    }

    /// Read a 16-byte UUID (server/client GUID; 128-bit).
    pub fn read_uuid(&mut self) -> Result<uuid::Uuid, SmbError> {
        let b = self.read_bytes(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        Ok(uuid::Uuid::from_bytes(arr))
    }

    /// Read a 16-byte file-id (PersistentFileId || VolatileFileId).
    pub fn read_file_id(&mut self) -> Result<FileId, SmbError> {
        let persistent = self.read_u64()?;
        let volatile_ = self.read_u64()?;
        Ok(FileId {
            persistent,
            volatile_,
        })
    }

    /// Read a 16-byte raw signature.
    pub fn read_signature(&mut self) -> Result<[u8; 16], SmbError> {
        let b = self.read_bytes(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        Ok(arr)
    }
}

/// Append-only byte writer. Used by every `encode` function. Plain
/// `Vec<u8>` wrapper so we get amortised O(1) `push` and zero-copy
/// `extend_from_slice`.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Construct an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an empty writer with pre-allocated `capacity`.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Finalise: return the underlying byte vector.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Current write position (= length).
    #[must_use]
    pub fn position(&self) -> usize {
        self.buf.len()
    }

    /// Write a single byte.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a u16 little-endian.
    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a u32 little-endian.
    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a u64 little-endian.
    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write raw bytes.
    pub fn write_bytes(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// Write a 16-byte UUID.
    pub fn write_uuid(&mut self, v: uuid::Uuid) {
        self.buf.extend_from_slice(v.as_bytes());
    }

    /// Write a 16-byte file-id.
    pub fn write_file_id(&mut self, v: &FileId) {
        self.write_u64(v.persistent);
        self.write_u64(v.volatile_);
    }

    /// Pad with `n` zero bytes (used for SMB2 8-byte alignment).
    pub fn pad(&mut self, n: usize) {
        self.buf.extend(std::iter::repeat_n(0u8, n));
    }

    /// Align to `alignment` (must be a power of two or 1).
    pub fn align(&mut self, alignment: usize) {
        debug_assert!(
            alignment == 1 || alignment.is_power_of_two(),
            "alignment must be power-of-two or 1, got {alignment}"
        );
        if alignment <= 1 {
            return;
        }
        let mask = alignment - 1;
        let rem = self.buf.len() & mask;
        if rem != 0 {
            let pad = alignment - rem;
            self.buf.extend(std::iter::repeat_n(0u8, pad));
        }
    }
}

/// Encode a Rust string as UTF-16LE bytes (no length prefix).
///
/// SMB2 paths are passed as UTF-16LE per MS-SMB2 §2.2.9. This helper
/// replaces the `wchar_t[]` encoding that Windows performs natively.
#[must_use]
pub fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Decode UTF-16LE bytes back to a Rust `String`. Replaces invalid
/// surrogates with U+FFFD per RFC 3629.
#[must_use]
pub fn decode_utf16le(bytes: &[u8]) -> String {
    if !bytes.len().is_multiple_of(2) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

// ============================================================================
// SMB2 fixed header (64 bytes) — MS-SMB2 §2.2.1.1 / §2.2.1.2
// ============================================================================

/// SMB2 packet header (64-byte fixed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Smb2Header {
    /// CreditCharge (number of credits this request consumes).
    pub credit_charge: u16,
    /// Status (responses) / ChannelSequence (requests, low 16 bits).
    pub status: u32,
    /// Command code (see [`command`] / [`Command`]).
    pub command: u16,
    /// CreditRequest (requests) / CreditResponse (responses).
    pub credits: u16,
    /// Flags (see [`flags`]).
    pub flags: u32,
    /// NextCommand offset (for chained messages; 0 = no chain).
    pub next_command: u32,
    /// MessageId (sequence number).
    pub message_id: u64,
    /// ProcessId (low 16 bits meaningful; high 16 reserved).
    pub process_id: u32,
    /// TreeId (tree-connection scope; 0 for Negotiate / SessionSetup / Echo).
    pub tree_id: u32,
    /// SessionId (session scope; 0 for Negotiate).
    pub session_id: u64,
    /// Signature (16 bytes; zero if not signed).
    pub signature: [u8; 16],
}

impl Smb2Header {
    /// Build a fresh request header.
    #[must_use]
    pub fn new_request(command: u16, message_id: u64) -> Self {
        Self {
            credit_charge: 1,
            status: 0,
            command,
            credits: 1,
            flags: 0,
            next_command: 0,
            message_id,
            process_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        }
    }

    /// Build a response header mirroring the request's routing fields.
    #[must_use]
    pub fn new_response(req: &Smb2Header) -> Self {
        Self {
            credit_charge: 1,
            status: 0,
            command: req.command,
            credits: 1,
            flags: flags::SMB2_FLAGS_RESPONSE,
            next_command: 0,
            message_id: req.message_id,
            process_id: req.process_id,
            tree_id: req.tree_id,
            session_id: req.session_id,
            signature: [0; 16],
        }
    }

    /// True if this header marks a response (server→client).
    #[must_use]
    pub fn is_response(&self) -> bool {
        self.flags & flags::SMB2_FLAGS_RESPONSE != 0
    }

    /// True if this header is signed.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.flags & flags::SMB2_FLAGS_SIGNED != 0
    }

    /// Encode to a 64-byte buffer.
    pub fn encode(&self, out: &mut Writer) {
        out.write_bytes(&SMB2_MAGIC);
        out.write_u16(SMB2_HEADER_SIZE as u16); // StructureSize = 64
        out.write_u16(self.credit_charge);
        out.write_u32(self.status);
        out.write_u16(self.command);
        out.write_u16(self.credits);
        out.write_u32(self.flags);
        out.write_u32(self.next_command);
        out.write_u64(self.message_id);
        out.write_u32(self.process_id);
        out.write_u32(self.tree_id);
        out.write_u64(self.session_id);
        out.write_bytes(&self.signature);
    }

    /// Decode from a 64+ byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, SmbError> {
        if buf.len() < SMB2_HEADER_SIZE {
            return Err(SmbError::Malformed(format!(
                "header too short: {} < {SMB2_HEADER_SIZE}",
                buf.len()
            )));
        }
        if buf[0..4] != SMB2_MAGIC {
            if buf[0..4] == SMB1_MAGIC {
                return Err(SmbError::Smb1Refused);
            }
            return Err(SmbError::Malformed(format!(
                "bad magic: {:02x?} (expected {:02x?})",
                &buf[0..4],
                SMB2_MAGIC
            )));
        }
        let mut r = Reader::new(buf);
        r.seek(4)?;
        let structure_size = r.read_u16()?;
        if structure_size != SMB2_HEADER_SIZE as u16 {
            return Err(SmbError::Malformed(format!(
                "bad header StructureSize: {structure_size} (expected {SMB2_HEADER_SIZE})"
            )));
        }
        let credit_charge = r.read_u16()?;
        let status = r.read_u32()?;
        let command = r.read_u16()?;
        let credits = r.read_u16()?;
        let flags_v = r.read_u32()?;
        let next_command = r.read_u32()?;
        let message_id = r.read_u64()?;
        let process_id = r.read_u32()?;
        let tree_id = r.read_u32()?;
        let session_id = r.read_u64()?;
        let signature = r.read_signature()?;
        Ok(Self {
            credit_charge,
            status,
            command,
            credits,
            flags: flags_v,
            next_command,
            message_id,
            process_id,
            tree_id,
            session_id,
            signature,
        })
    }
}

// ============================================================================
// FileId (16 bytes: PersistentFileId || VolatileFileId) — MS-SMB2 §2.2.14.6
// ============================================================================

/// SMB2 FileId (16 bytes: PersistentFileId || VolatileFileId).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    /// PersistentFileId (8 bytes) — stable across reconnects for durable handles.
    pub persistent: u64,
    /// VolatileFileId (8 bytes) — may change on reconnect.
    pub volatile_: u64,
}

impl FileId {
    /// Build a FileId from two u64s.
    #[must_use]
    pub const fn new(persistent: u64, volatile_: u64) -> Self {
        Self {
            persistent,
            volatile_,
        }
    }

    /// Zero FileId (used as a sentinel).
    pub const ZERO: FileId = FileId::new(0, 0);

    /// True if both halves are zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.persistent == 0 && self.volatile_ == 0
    }
}

// ============================================================================
// NegotiateContext (8-byte aligned, type+len+reserved+data) — §2.2.3.1.6
// ============================================================================

/// A single NegotiateContext entry (type + data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiateContext {
    /// ContextType (e.g. 0x0001 = preauth integrity).
    pub context_type: u16,
    /// Raw context Data (callers interpret per ContextType).
    pub data: Vec<u8>,
}

impl NegotiateContext {
    /// Build a PREAUTH_INTEGRITY_CAPABILITIES context (SHA-512 + salt).
    #[must_use]
    pub fn preauth_integrity(hash_algos: &[u16], salt: &[u8]) -> Self {
        let mut data = Vec::with_capacity(4 + hash_algos.len() * 2 + salt.len());
        data.extend_from_slice(&(hash_algos.len() as u16).to_le_bytes());
        data.extend_from_slice(&(salt.len() as u16).to_le_bytes());
        for &h in hash_algos {
            data.extend_from_slice(&h.to_le_bytes());
        }
        data.extend_from_slice(salt);
        Self {
            context_type: negotiate_context_type::PREAUTH_INTEGRITY,
            data,
        }
    }

    /// Build an ENCRYPTION_CAPABILITIES context (list of cipher IDs).
    #[must_use]
    pub fn encryption(ciphers: &[u16]) -> Self {
        let mut data = Vec::with_capacity(2 + ciphers.len() * 2);
        data.extend_from_slice(&(ciphers.len() as u16).to_le_bytes());
        for &c in ciphers {
            data.extend_from_slice(&c.to_le_bytes());
        }
        Self {
            context_type: negotiate_context_type::ENCRYPTION,
            data,
        }
    }

    /// Build a SIGNING_CAPABILITIES context (list of signing algos).
    #[must_use]
    pub fn signing(algos: &[u16]) -> Self {
        let mut data = Vec::with_capacity(2 + algos.len() * 2);
        data.extend_from_slice(&(algos.len() as u16).to_le_bytes());
        for &a in algos {
            data.extend_from_slice(&a.to_le_bytes());
        }
        Self {
            context_type: negotiate_context_type::SIGNING,
            data,
        }
    }

    /// Parse a PREAUTH_INTEGRITY context's data into (hash_algos, salt).
    ///
    /// Returns `None` if the data is malformed.
    #[must_use]
    pub fn parse_preauth(&self) -> Option<(Vec<u16>, Vec<u8>)> {
        if self.context_type != negotiate_context_type::PREAUTH_INTEGRITY {
            return None;
        }
        if self.data.len() < 4 {
            return None;
        }
        let hash_count = u16::from_le_bytes([self.data[0], self.data[1]]) as usize;
        let salt_len = u16::from_le_bytes([self.data[2], self.data[3]]) as usize;
        let need = 4 + hash_count * 2 + salt_len;
        if self.data.len() < need {
            return None;
        }
        let mut algos = Vec::with_capacity(hash_count);
        for i in 0..hash_count {
            let off = 4 + i * 2;
            algos.push(u16::from_le_bytes([self.data[off], self.data[off + 1]]));
        }
        let salt = self.data[4 + hash_count * 2..need].to_vec();
        Some((algos, salt))
    }

    /// Parse an ENCRYPTION context's data into cipher IDs.
    #[must_use]
    pub fn parse_encryption(&self) -> Option<Vec<u16>> {
        if self.context_type != negotiate_context_type::ENCRYPTION {
            return None;
        }
        if self.data.len() < 2 {
            return None;
        }
        let n = u16::from_le_bytes([self.data[0], self.data[1]]) as usize;
        if self.data.len() < 2 + n * 2 {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let off = 2 + i * 2;
            out.push(u16::from_le_bytes([self.data[off], self.data[off + 1]]));
        }
        Some(out)
    }

    /// Encode a sequence of contexts into `out`, with 8-byte alignment
    /// between consecutive entries (per MS-SMB2 §2.2.3.1.6).
    pub fn encode_all(ctxs: &[NegotiateContext], out: &mut Writer) {
        for (i, ctx) in ctxs.iter().enumerate() {
            if i > 0 {
                out.align(8);
            }
            out.write_u16(ctx.context_type);
            out.write_u16(ctx.data.len() as u16);
            out.write_u32(0); // Reserved
            out.write_bytes(&ctx.data);
        }
    }

    /// Decode a sequence of contexts from `buf` (length-bounded by `len`).
    pub fn decode_all(buf: &[u8]) -> Result<Vec<NegotiateContext>, SmbError> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 8 <= buf.len() {
            let context_type = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
            let data_len = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            let data_start = pos + 8;
            if data_start + data_len > buf.len() {
                return Err(SmbError::Malformed(
                    "negotiate context data truncated".into(),
                ));
            }
            let data = buf[data_start..data_start + data_len].to_vec();
            out.push(NegotiateContext { context_type, data });
            // Advance and align to 8.
            let next = data_start + data_len;
            let rem = next % 8;
            pos = if rem == 0 { next } else { next + (8 - rem) };
        }
        Ok(out)
    }
}

// ============================================================================
// Negotiate request/response — §2.2.3 / §2.2.4
// ============================================================================

/// SMB2 NEGOTIATE request (command 0x0000). MS-SMB2 §2.2.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiateRequest {
    /// Dialects the client offers (in order of preference).
    pub dialects: Vec<Dialect>,
    /// Security mode (signing enabled / required).
    pub security_mode: u16,
    /// Client capabilities bitmask.
    pub capabilities: u32,
    /// ClientGuid (16 bytes).
    pub client_guid: uuid::Uuid,
    /// Negotiate contexts (only meaningful when SMB 3.1.1 is offered).
    pub negotiate_contexts: Vec<NegotiateContext>,
}

impl NegotiateRequest {
    /// Build a default SMB 3.1.1 negotiate request with SHA-512 preauth
    /// integrity and AES-256-GCM encryption (the framework default per
    /// ADR-105 §3-4).
    #[must_use]
    pub fn new_311(client_guid: uuid::Uuid, client_salt: &[u8]) -> Self {
        Self {
            dialects: vec![Dialect::Smb311],
            security_mode: security_mode::SIGNING_ENABLED,
            capabilities: capabilities::LARGE_MTU | capabilities::ENCRYPTION,
            client_guid,
            negotiate_contexts: vec![
                NegotiateContext::preauth_integrity(&[preauth_hash_algo::SHA512], client_salt),
                NegotiateContext::encryption(&[cipher::AES_256_GCM, cipher::AES_128_GCM]),
                NegotiateContext::signing(&[signing_algo::AES_GMAC, signing_algo::HMAC_SHA256]),
            ],
        }
    }

    /// Encode just the negotiate body (NOT including the SMB2 header) into
    /// `out`. Returns the offsets needed for the SMB2 header (the absolute
    /// offset of the negotiate-context list, and its byte length).
    ///
    /// `header_size` is the SMB2 header size in front of this body — used
    /// to convert relative offsets to absolute (header-relative) offsets.
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> (u32, u32) {
        let dialect_count = self.dialects.len() as u16;
        out.write_u16(36); // StructureSize
        out.write_u16(dialect_count);
        out.write_u16(self.security_mode);
        out.write_u16(0); // Reserved
        out.write_u32(self.capabilities);
        out.write_uuid(self.client_guid);
        // Compute the absolute offset of the NegotiateContextList.
        // header_size + 36 (fixed body) + dialect_count*2 + padding to 8.
        let dialects_len = dialect_count as usize * 2;
        let pre_pad = header_size + 36 + dialects_len;
        let pad = (8 - (pre_pad % 8)) % 8;
        let ctx_offset = if self.negotiate_contexts.is_empty() {
            0
        } else {
            (pre_pad + pad) as u32
        };
        out.write_u32(ctx_offset);
        out.write_u16(self.negotiate_contexts.len() as u16);
        out.write_u16(0); // Reserved2
        for d in &self.dialects {
            out.write_u16(d.to_wire());
        }
        if !self.negotiate_contexts.is_empty() {
            out.align(8);
            let ctx_start = out.position();
            NegotiateContext::encode_all(&self.negotiate_contexts, out);
            let ctx_end = out.position();
            debug_assert_eq!(ctx_start, ctx_offset as usize);
            let _ = ctx_start; // suppress unused warning in release
            return (ctx_offset, (ctx_end - ctx_start) as u32);
        }
        (ctx_offset, 0)
    }

    /// Encode the full SMB2 NEGOTIATE request (header + body).
    pub fn encode(&self, message_id: u64) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 64);
        let hdr = Smb2Header::new_request(command::NEGOTIATE, message_id);
        hdr.encode(&mut out);
        let (ctx_offset, _ctx_len) = self.encode_body(&mut out, SMB2_HEADER_SIZE);
        let _ = ctx_offset;
        out.into_bytes()
    }

    /// Decode the body (header already consumed). `buf` is the entire SMB2
    /// message (header + body); `header_size` is the SMB2 header size (64).
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 36 {
            return Err(SmbError::Malformed("negotiate request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 36 {
            return Err(SmbError::Malformed(format!(
                "negotiate request StructureSize {structure_size} != 36"
            )));
        }
        let dialect_count = r.read_u16()? as usize;
        let security_mode = r.read_u16()?;
        let _reserved = r.read_u16()?;
        let capabilities = r.read_u32()?;
        let client_guid = r.read_uuid()?;
        let negotiate_context_offset = r.read_u32()? as usize;
        let negotiate_context_count = r.read_u16()? as usize;
        let _reserved2 = r.read_u16()?;
        // Read dialects.
        let mut dialects = Vec::with_capacity(dialect_count);
        for _ in 0..dialect_count {
            let code = r.read_u16()?;
            dialects.push(Dialect::from_wire(code).ok_or_else(|| {
                SmbError::Malformed(format!("unknown dialect code: 0x{code:04x}"))
            })?);
        }
        // Read negotiate contexts (absolute offset from start of message).
        let mut negotiate_contexts = Vec::new();
        if negotiate_context_count > 0 {
            if negotiate_context_offset == 0 || negotiate_context_offset >= buf.len() {
                return Err(SmbError::Malformed(format!(
                    "bad negotiate context offset: {negotiate_context_offset}"
                )));
            }
            // Align offset up to 8 if needed (defensive).
            let aligned = (negotiate_context_offset + 7) & !7;
            let ctx_buf = &buf[aligned.min(buf.len())..];
            negotiate_contexts = NegotiateContext::decode_all(ctx_buf)?;
            // Truncate to expected count (decoder may over-read trailing bytes).
            negotiate_contexts.truncate(negotiate_context_count);
        }
        Ok(Self {
            dialects,
            security_mode,
            capabilities,
            client_guid,
            negotiate_contexts,
        })
    }
}

/// SMB2 NEGOTIATE response (command 0x0000). MS-SMB2 §2.2.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiateResponse {
    /// Server-selected security mode (signing enabled / required).
    pub security_mode: u16,
    /// Server-selected dialect revision (e.g. 0x0311).
    pub dialect_revision: u16,
    /// Server capabilities bitmask.
    pub capabilities: u32,
    /// ServerGuid (16 bytes).
    pub server_guid: uuid::Uuid,
    /// MaxTransactSize (bytes the server will accept in a single transact).
    pub max_transact_size: u32,
    /// MaxReadSize (bytes the server will return in a single READ).
    pub max_read_size: u32,
    /// MaxWriteSize (bytes the server will accept in a single WRITE).
    pub max_write_size: u32,
    /// SystemTime (NT time — 100-ns intervals since 1601-01-01).
    pub system_time: u64,
    /// BootTime (NT time).
    pub boot_time: u64,
    /// SecurityBuffer (GSS-API / SPNEGO blob; may be empty for our stub auth).
    pub security_buffer: Vec<u8>,
    /// Negotiate contexts (only present when dialect is 3.1.1).
    pub negotiate_contexts: Vec<NegotiateContext>,
}

impl NegotiateResponse {
    /// Build a default SMB 3.1.1 negotiate response with SHA-512 preauth
    /// integrity and AES-256-GCM encryption (the framework default per
    /// ADR-105 §3-4). The server advertises the
    /// `SMB2_GLOBAL_CAP_ENCRYPTION` capability (T-105) so that clients
    /// know to encrypt PDUs on this session. Plaintext sessions are
    /// still tolerated when the client does not request encryption —
    /// the flag is an advertisement, not a mandate.
    #[must_use]
    pub fn new_311(server_guid: uuid::Uuid, server_salt: &[u8]) -> Self {
        Self {
            security_mode: security_mode::SIGNING_ENABLED,
            dialect_revision: dialect_code::SMB311,
            capabilities: capabilities::LARGE_MTU | capabilities::ENCRYPTION,
            server_guid,
            max_transact_size: MAX_SMB2_MESSAGE_SIZE,
            max_read_size: MAX_SMB2_MESSAGE_SIZE,
            max_write_size: MAX_SMB2_MESSAGE_SIZE,
            system_time: 0,
            boot_time: 0,
            security_buffer: Vec::new(),
            negotiate_contexts: vec![
                NegotiateContext::preauth_integrity(&[preauth_hash_algo::SHA512], server_salt),
                NegotiateContext::encryption(&[cipher::AES_256_GCM, cipher::AES_128_GCM]),
                NegotiateContext::signing(&[signing_algo::AES_GMAC, signing_algo::HMAC_SHA256]),
            ],
        }
    }

    /// Encode just the response body (NOT including the SMB2 header) into
    /// `out`. Returns the absolute offset of the negotiate-context list.
    ///
    /// # Pre-conditions
    ///
    /// `out.position()` MUST equal `header_size` (the SMB2 header has
    /// already been written into `out`).
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> u32 {
        debug_assert_eq!(out.position(), header_size);
        let has_ctx = !self.negotiate_contexts.is_empty();
        // Pre-encode the NegotiateContextList into a temp buffer so we know
        // its length before writing the fixed SecurityBufferOffset field.
        let mut ctx_buf = Writer::new();
        if has_ctx {
            NegotiateContext::encode_all(&self.negotiate_contexts, &mut ctx_buf);
        }
        let ctx_len = ctx_buf.as_bytes().len();
        out.write_u16(65); // StructureSize
        out.write_u16(self.security_mode);
        out.write_u16(self.dialect_revision);
        out.write_u16(self.negotiate_contexts.len() as u16);
        // NegotiateContextOffset: the fixed structure is 64 bytes; the
        // NegotiateContextList starts immediately after (header_size + 64
        // is already a multiple of 8, so no padding needed).
        let ctx_offset = if has_ctx {
            (header_size + 64) as u32
        } else {
            0
        };
        out.write_u32(ctx_offset);
        out.write_uuid(self.server_guid);
        out.write_u32(self.capabilities);
        out.write_u32(self.max_transact_size);
        out.write_u32(self.max_read_size);
        out.write_u32(self.max_write_size);
        out.write_u64(self.system_time);
        out.write_u64(self.boot_time);
        // SecurityBufferOffset — comes after the NegotiateContextList
        // (and is 8-byte aligned).
        let after_ctx = header_size + 64 + ctx_len;
        let sb_align_pad = (8 - (after_ctx % 8)) % 8;
        let sb_offset = if self.security_buffer.is_empty() {
            0
        } else {
            (after_ctx + sb_align_pad) as u32
        };
        out.write_u16(sb_offset as u16);
        out.write_u16(self.security_buffer.len() as u16);
        // Verify we wrote exactly 64 bytes of fixed structure.
        debug_assert_eq!(out.position(), header_size + 64);
        // Write NegotiateContextList (if any).
        if has_ctx {
            out.write_bytes(ctx_buf.as_bytes());
        }
        // Pad and write SecurityBuffer (if any).
        if !self.security_buffer.is_empty() {
            out.align(8);
            out.write_bytes(&self.security_buffer);
        }
        ctx_offset
    }

    /// Encode the full SMB2 NEGOTIATE response (header + body).
    pub fn encode(&self, request_header: &Smb2Header) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 128);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = ntstatus::STATUS_SUCCESS;
        hdr.encode(&mut out);
        self.encode_body(&mut out, SMB2_HEADER_SIZE);
        out.into_bytes()
    }

    /// Decode the body (header already consumed). `buf` is the entire SMB2
    /// message (header + body); `header_size` is the SMB2 header size (64).
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 64 {
            return Err(SmbError::Malformed("negotiate response too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 65 {
            return Err(SmbError::Malformed(format!(
                "negotiate response StructureSize {structure_size} != 65"
            )));
        }
        let security_mode = r.read_u16()?;
        let dialect_revision = r.read_u16()?;
        let negotiate_context_count = r.read_u16()? as usize;
        let negotiate_context_offset = r.read_u32()? as usize;
        let server_guid = r.read_uuid()?;
        let capabilities = r.read_u32()?;
        let max_transact_size = r.read_u32()?;
        let max_read_size = r.read_u32()?;
        let max_write_size = r.read_u32()?;
        let system_time = r.read_u64()?;
        let boot_time = r.read_u64()?;
        let security_buffer_offset = r.read_u16()? as usize;
        let security_buffer_length = r.read_u16()? as usize;
        // Read security buffer (absolute offset from start of message).
        let security_buffer = if security_buffer_length == 0 {
            Vec::new()
        } else {
            if security_buffer_offset + security_buffer_length > buf.len() {
                return Err(SmbError::Malformed(
                    "negotiate response security buffer truncated".into(),
                ));
            }
            buf[security_buffer_offset..security_buffer_offset + security_buffer_length].to_vec()
        };
        // Read negotiate contexts (only if 3.1.1).
        let mut negotiate_contexts = Vec::new();
        if negotiate_context_count > 0 {
            if negotiate_context_offset == 0 || negotiate_context_offset >= buf.len() {
                return Err(SmbError::Malformed(format!(
                    "bad negotiate context offset: {negotiate_context_offset}"
                )));
            }
            let aligned = (negotiate_context_offset + 7) & !7;
            let ctx_buf = &buf[aligned.min(buf.len())..];
            negotiate_contexts = NegotiateContext::decode_all(ctx_buf)?;
            negotiate_contexts.truncate(negotiate_context_count);
        }
        Ok(Self {
            security_mode,
            dialect_revision,
            capabilities,
            server_guid,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            boot_time,
            security_buffer,
            negotiate_contexts,
        })
    }
}

// ============================================================================
// SessionSetup request/response — §2.2.5
// ============================================================================

/// SMB2 SESSION_SETUP request (command 0x0001). MS-SMB2 §2.2.5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSetupRequest {
    /// Flags (0x00 = normal, 0x01 = binding).
    pub flags: u8,
    /// SecurityMode (signing enabled / required).
    pub security_mode: u16,
    /// Capabilities (always 0 for SMB 3.x — channel-binding only).
    pub capabilities: u32,
    /// Channel (0 = None, 1 = RDMA V1).
    pub channel: u32,
    /// SecurityBuffer (GSS-API / SPNEGO blob).
    pub security_buffer: Vec<u8>,
    /// PreviousSessionId (for reconnect-after-disconnect).
    pub previous_session_id: u64,
}

impl SessionSetupRequest {
    /// Build a minimal session-setup request with the given SPNEGO blob.
    #[must_use]
    pub fn new(security_buffer: Vec<u8>) -> Self {
        Self {
            flags: 0,
            security_mode: security_mode::SIGNING_ENABLED,
            capabilities: 0,
            channel: 0,
            security_buffer,
            previous_session_id: 0,
        }
    }

    /// Encode the body (NOT including the SMB2 header). Returns the
    /// security-buffer's absolute offset (from start of SMB2 message).
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> u32 {
        out.write_u16(25); // StructureSize
        out.write_u8(self.flags);
        out.write_u8((self.security_mode & 0xFF) as u8);
        // security_mode is u16 — but the wire format has it as a single
        // byte here. Encode the low byte (high byte is reserved/0).
        out.write_u32(self.capabilities);
        out.write_u32(self.channel);
        let sb_off = (header_size + 24) as u32;
        out.write_u16(sb_off as u16);
        out.write_u16(self.security_buffer.len() as u16);
        out.write_u64(self.previous_session_id);
        // Buffer (security_buffer).
        out.write_bytes(&self.security_buffer);
        sb_off
    }

    /// Encode the full SMB2 SESSION_SETUP request.
    pub fn encode(&self, message_id: u64, session_id: u64) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 64);
        let mut hdr = Smb2Header::new_request(command::SESSION_SETUP, message_id);
        hdr.session_id = session_id;
        hdr.encode(&mut out);
        self.encode_body(&mut out, SMB2_HEADER_SIZE);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 24 {
            return Err(SmbError::Malformed(
                "session setup request too short".into(),
            ));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 25 {
            return Err(SmbError::Malformed(format!(
                "session setup request StructureSize {structure_size} != 25"
            )));
        }
        let flags = r.read_u8()?;
        let security_mode_low = r.read_u8()? as u16;
        let capabilities = r.read_u32()?;
        let channel = r.read_u32()?;
        let sb_off = r.read_u16()? as usize;
        let sb_len = r.read_u16()? as usize;
        let previous_session_id = r.read_u64()?;
        let security_buffer = if sb_len == 0 {
            Vec::new()
        } else {
            if sb_off + sb_len > buf.len() {
                return Err(SmbError::Malformed(
                    "session setup security buffer truncated".into(),
                ));
            }
            buf[sb_off..sb_off + sb_len].to_vec()
        };
        Ok(Self {
            flags,
            security_mode: security_mode_low,
            capabilities,
            channel,
            security_buffer,
            previous_session_id,
        })
    }
}

/// SMB2 SESSION_SETUP response (command 0x0001). MS-SMB2 §2.2.6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSetupResponse {
    /// SessionFlags (0x01=IsGuest, 0x02=IsNull, 0x04=EncryptData).
    pub session_flags: u16,
    /// SecurityBuffer (SPNEGO continuation token; may be empty on success).
    pub security_buffer: Vec<u8>,
}

impl SessionSetupResponse {
    /// Build a minimal session-setup response (success, no flags).
    #[must_use]
    pub fn new_success() -> Self {
        Self {
            session_flags: 0,
            security_buffer: Vec::new(),
        }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> u32 {
        out.write_u16(9); // StructureSize
        out.write_u16(self.session_flags);
        let sb_off = (header_size + 8) as u32;
        out.write_u16(sb_off as u16);
        out.write_u16(self.security_buffer.len() as u16);
        out.write_bytes(&self.security_buffer);
        sb_off
    }

    /// Encode the full SMB2 SESSION_SETUP response.
    pub fn encode(&self, request_header: &Smb2Header, status: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 32);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = status;
        hdr.encode(&mut out);
        self.encode_body(&mut out, SMB2_HEADER_SIZE);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 8 {
            return Err(SmbError::Malformed(
                "session setup response too short".into(),
            ));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 9 {
            return Err(SmbError::Malformed(format!(
                "session setup response StructureSize {structure_size} != 9"
            )));
        }
        let session_flags = r.read_u16()?;
        let sb_off = r.read_u16()? as usize;
        let sb_len = r.read_u16()? as usize;
        let security_buffer = if sb_len == 0 {
            Vec::new()
        } else {
            if sb_off + sb_len > buf.len() {
                return Err(SmbError::Malformed(
                    "session setup response security buffer truncated".into(),
                ));
            }
            buf[sb_off..sb_off + sb_len].to_vec()
        };
        Ok(Self {
            session_flags,
            security_buffer,
        })
    }
}

// ============================================================================
// TreeConnect request/response — §2.2.8 / §2.2.9
// ============================================================================

/// SMB2 TREE_CONNECT request (command 0x0003). MS-SMB2 §2.2.8.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeConnectRequest {
    /// UNC path (`\\server\share`, UTF-16LE on the wire).
    pub path: String,
}

impl TreeConnectRequest {
    /// Build a new TreeConnect request for `\\server\share`.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> u32 {
        out.write_u16(9); // StructureSize
        out.write_u16(0); // Reserved
        let path_offset = (header_size + 8) as u32;
        out.write_u16(path_offset as u16);
        let path_utf16 = encode_utf16le(&self.path);
        out.write_u16(path_utf16.len() as u16);
        out.write_bytes(&path_utf16);
        path_offset
    }

    /// Encode the full SMB2 TREE_CONNECT request.
    pub fn encode(&self, message_id: u64, session_id: u64) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 64);
        let mut hdr = Smb2Header::new_request(command::TREE_CONNECT, message_id);
        hdr.session_id = session_id;
        hdr.encode(&mut out);
        self.encode_body(&mut out, SMB2_HEADER_SIZE);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 8 {
            return Err(SmbError::Malformed("tree connect request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 9 {
            return Err(SmbError::Malformed(format!(
                "tree connect request StructureSize {structure_size} != 9"
            )));
        }
        let _reserved = r.read_u16()?;
        let path_offset = r.read_u16()? as usize;
        let path_length = r.read_u16()? as usize;
        if path_length == 0 {
            return Ok(Self {
                path: String::new(),
            });
        }
        if path_offset + path_length > buf.len() {
            return Err(SmbError::Malformed("tree connect path truncated".into()));
        }
        let path = decode_utf16le(&buf[path_offset..path_offset + path_length]);
        Ok(Self { path })
    }
}

/// SMB2 TREE_CONNECT response (command 0x0003). MS-SMB2 §2.2.9.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeConnectResponse {
    /// ShareType (0x01=Disk, 0x02=Pipe, 0x03=Print).
    pub share_type: u8,
    /// ShareFlags (per MS-SMB2 §2.2.9.2).
    pub share_flags: u32,
    /// Capabilities (per MS-SMB2 §2.2.9.3).
    pub capabilities: u32,
    /// MaximalAccess (mask of granted access rights).
    pub maximal_access: u32,
}

impl TreeConnectResponse {
    /// Build a default disk-share TreeConnect response.
    #[must_use]
    pub fn new_disk() -> Self {
        Self {
            share_type: share_type::DISK,
            share_flags: 0,
            capabilities: 0,
            maximal_access: 0x001F_01FF, // FILE_ALL_ACCESS generic
        }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer) {
        out.write_u16(16); // StructureSize
        out.write_u8(self.share_type);
        out.write_u8(0); // Reserved
        out.write_u32(self.share_flags);
        out.write_u32(self.capabilities);
        out.write_u32(self.maximal_access);
    }

    /// Encode the full SMB2 TREE_CONNECT response.
    pub fn encode(&self, request_header: &Smb2Header, tree_id: u32, status: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 16);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = status;
        hdr.tree_id = tree_id;
        hdr.encode(&mut out);
        self.encode_body(&mut out);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 16 {
            return Err(SmbError::Malformed(
                "tree connect response too short".into(),
            ));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 16 {
            return Err(SmbError::Malformed(format!(
                "tree connect response StructureSize {structure_size} != 16"
            )));
        }
        let share_type = r.read_u8()?;
        let _reserved = r.read_u8()?;
        let share_flags = r.read_u32()?;
        let capabilities = r.read_u32()?;
        let maximal_access = r.read_u32()?;
        Ok(Self {
            share_type,
            share_flags,
            capabilities,
            maximal_access,
        })
    }
}

// ============================================================================
// Create request/response — §2.2.13 / §2.2.14
// ============================================================================

/// SMB2 CREATE request (command 0x0005). MS-SMB2 §2.2.13.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateRequest {
    /// OplockLevel (0x00=None, 0x01=II, 0x02=Level2 (deprecated), 0x08=Batch).
    pub oplock_level: u8,
    /// ImpersonationLevel (3=Identification, 4=Impersonation).
    pub impersonation_level: u32,
    /// SmbCreateFlags (always 0 for SMB 3.x).
    pub smb_create_flags: u64,
    /// DesiredAccess (FILE_GENERIC_READ/WRITE/EXECUTE, etc).
    pub desired_access: u32,
    /// FileAttributes (FILE_ATTRIBUTE_NORMAL = 0x80).
    pub file_attributes: u32,
    /// ShareAccess (FILE_SHARE_READ/WRITE/DELETE).
    pub share_access: u32,
    /// CreateDisposition (FILE_SUPERSEDE/OPEN/CREATE/OPEN_IF/OVERWRITE/OVERWRITE_IF).
    pub create_disposition: u32,
    /// CreateOptions (FILE_DIRECTORY_FILE, etc).
    pub create_options: u32,
    /// Name (UTF-16LE; relative to tree root).
    pub name: String,
}

impl CreateRequest {
    /// Build a CREATE request for the given file path (UTF-8 → UTF-16LE on wire).
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            oplock_level: 0,
            impersonation_level: 2, // Impersonation
            smb_create_flags: 0,
            desired_access: 0x0017_0089, // FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE
            file_attributes: 0x80,       // FILE_ATTRIBUTE_NORMAL
            share_access: 0x07,          // READ | WRITE | DELETE
            create_disposition: 0x03,    // FILE_OPEN_IF (open or create; do not truncate)
            create_options: 0,
            name: name.into(),
        }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> u32 {
        out.write_u16(57); // StructureSize
        out.write_u8(self.oplock_level);
        out.write_u8(0); // Reserved
        out.write_u32(self.impersonation_level);
        out.write_u64(self.smb_create_flags);
        out.write_u64(0); // Reserved2
        out.write_u32(self.desired_access);
        out.write_u32(self.file_attributes);
        out.write_u32(self.share_access);
        out.write_u32(self.create_disposition);
        out.write_u32(self.create_options);
        let name_offset = (header_size + 56) as u32;
        out.write_u16(name_offset as u16);
        let name_utf16 = encode_utf16le(&self.name);
        out.write_u16(name_utf16.len() as u16);
        // CreateContextsOffset/Length (we don't support create contexts).
        out.write_u32(0);
        out.write_u32(0);
        // Buffer (name).
        out.write_bytes(&name_utf16);
        name_offset
    }

    /// Encode the full SMB2 CREATE request.
    pub fn encode(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 64);
        let mut hdr = Smb2Header::new_request(command::CREATE, message_id);
        hdr.session_id = session_id;
        hdr.tree_id = tree_id;
        hdr.encode(&mut out);
        self.encode_body(&mut out, SMB2_HEADER_SIZE);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 56 {
            return Err(SmbError::Malformed("create request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 57 {
            return Err(SmbError::Malformed(format!(
                "create request StructureSize {structure_size} != 57"
            )));
        }
        let oplock_level = r.read_u8()?;
        let _reserved = r.read_u8()?;
        let impersonation_level = r.read_u32()?;
        let smb_create_flags = r.read_u64()?;
        let _reserved2 = r.read_u64()?;
        let desired_access = r.read_u32()?;
        let file_attributes = r.read_u32()?;
        let share_access = r.read_u32()?;
        let create_disposition = r.read_u32()?;
        let create_options = r.read_u32()?;
        let name_offset = r.read_u16()? as usize;
        let name_length = r.read_u16()? as usize;
        let _ctx_offset = r.read_u32()?;
        let _ctx_length = r.read_u32()?;
        let name = if name_length == 0 {
            String::new()
        } else {
            if name_offset + name_length > buf.len() {
                return Err(SmbError::Malformed("create name truncated".into()));
            }
            decode_utf16le(&buf[name_offset..name_offset + name_length])
        };
        Ok(Self {
            oplock_level,
            impersonation_level,
            smb_create_flags,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            name,
        })
    }
}

/// SMB2 CREATE response (command 0x0005). MS-SMB2 §2.2.14.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateResponse {
    /// OplockLevel granted.
    pub oplock_level: u8,
    /// Flags (0x01=ReplayOperation, 0x02=PersistentHandle).
    pub flags: u8,
    /// CreateAction (FILE_SUPERSEDED/OPENED/CREATED/OVERWRITTEN = 0/1/2/3).
    pub create_action: u32,
    /// CreationTime (NT time).
    pub creation_time: u64,
    /// LastAccessTime (NT time).
    pub last_access_time: u64,
    /// LastWriteTime (NT time).
    pub last_write_time: u64,
    /// ChangeTime (NT time).
    pub change_time: u64,
    /// AllocationSize (rounded up to FS block size).
    pub allocation_size: u64,
    /// EndofFile (logical size).
    pub end_of_file: u64,
    /// FileAttributes.
    pub file_attributes: u32,
    /// Granted FileId.
    pub file_id: FileId,
}

impl CreateResponse {
    /// Build a CREATE response for a newly-opened file with the given FileId
    /// and size.
    #[must_use]
    pub fn new(file_id: FileId, size: u64) -> Self {
        Self {
            oplock_level: 0,
            flags: 0,
            create_action: 1, // FILE_OPENED
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: size,
            end_of_file: size,
            file_attributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            file_id,
        }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer) {
        out.write_u16(89); // StructureSize
        out.write_u8(self.oplock_level);
        out.write_u8(self.flags);
        out.write_u32(self.create_action);
        out.write_u64(self.creation_time);
        out.write_u64(self.last_access_time);
        out.write_u64(self.last_write_time);
        out.write_u64(self.change_time);
        out.write_u64(self.allocation_size);
        out.write_u64(self.end_of_file);
        out.write_u32(self.file_attributes);
        out.write_u32(0); // Reserved2
        out.write_file_id(&self.file_id);
        out.write_u32(0); // CreateContextsOffset
        out.write_u32(0); // CreateContextsLength
    }

    /// Encode the full SMB2 CREATE response.
    pub fn encode(&self, request_header: &Smb2Header, status: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 88);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = status;
        hdr.encode(&mut out);
        self.encode_body(&mut out);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 88 {
            return Err(SmbError::Malformed("create response too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 89 {
            return Err(SmbError::Malformed(format!(
                "create response StructureSize {structure_size} != 89"
            )));
        }
        let oplock_level = r.read_u8()?;
        let flags = r.read_u8()?;
        let create_action = r.read_u32()?;
        let creation_time = r.read_u64()?;
        let last_access_time = r.read_u64()?;
        let last_write_time = r.read_u64()?;
        let change_time = r.read_u64()?;
        let allocation_size = r.read_u64()?;
        let end_of_file = r.read_u64()?;
        let file_attributes = r.read_u32()?;
        let _reserved2 = r.read_u32()?;
        let file_id = r.read_file_id()?;
        // Create contexts (we don't support them).
        let _ctx_offset = r.read_u32()?;
        let _ctx_length = r.read_u32()?;
        Ok(Self {
            oplock_level,
            flags,
            create_action,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            file_attributes,
            file_id,
        })
    }
}

// ============================================================================
// Read request/response — §2.2.19 / §2.2.20
// ============================================================================

/// SMB2 READ request (command 0x0008). MS-SMB2 §2.2.19.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    /// Length (bytes to read).
    pub length: u32,
    /// Offset (byte offset within the file).
    pub offset: u64,
    /// FileId.
    pub file_id: FileId,
    /// MinimumCount (server MUST read at least this many bytes or return EOF).
    pub minimum_count: u32,
}

impl ReadRequest {
    /// Build a READ request for `length` bytes starting at `offset` on
    /// `file_id`.
    #[must_use]
    pub fn new(file_id: FileId, offset: u64, length: u32) -> Self {
        Self {
            length,
            offset,
            file_id,
            minimum_count: 1,
        }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer) {
        out.write_u16(49); // StructureSize
        out.write_u8(0); // Padding
        out.write_u8(0); // Flags
        out.write_u32(self.length);
        out.write_u64(self.offset);
        out.write_file_id(&self.file_id);
        out.write_u32(self.minimum_count);
        out.write_u32(0); // Channel
        out.write_u32(0); // RemainingBytes
        out.write_u16(0); // ReadChannelInfoOffset
        out.write_u16(0); // ReadChannelInfoLength
                          // (Buffer is empty — channel info not supported.)
    }

    /// Encode the full SMB2 READ request.
    pub fn encode(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 48);
        let mut hdr = Smb2Header::new_request(command::READ, message_id);
        hdr.session_id = session_id;
        hdr.tree_id = tree_id;
        hdr.encode(&mut out);
        self.encode_body(&mut out);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 48 {
            return Err(SmbError::Malformed("read request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 49 {
            return Err(SmbError::Malformed(format!(
                "read request StructureSize {structure_size} != 49"
            )));
        }
        let _padding = r.read_u8()?;
        let _flags = r.read_u8()?;
        let length = r.read_u32()?;
        let offset = r.read_u64()?;
        let file_id = r.read_file_id()?;
        let minimum_count = r.read_u32()?;
        Ok(Self {
            length,
            offset,
            file_id,
            minimum_count,
        })
    }
}

/// SMB2 READ response (command 0x0008). MS-SMB2 §2.2.20.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadResponse {
    /// Data read (the actual file bytes).
    pub data: Vec<u8>,
}

impl ReadResponse {
    /// Build a READ response carrying `data`.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> u32 {
        out.write_u16(17); // StructureSize
        let data_offset = (header_size + 16) as u32;
        out.write_u8(data_offset as u8);
        out.write_u8(0); // Reserved
        out.write_u32(self.data.len() as u32);
        out.write_u32(0); // DataRemaining
        out.write_u32(0); // Flags
                          // Pad to 8-byte alignment before data (per MS-SMB2 §2.2.20 the data
                          // follows immediately after the fixed portion, but Windows aligns
                          // it to 8 for performance).
        out.align(8);
        out.write_bytes(&self.data);
        data_offset
    }

    /// Encode the full SMB2 READ response.
    pub fn encode(&self, request_header: &Smb2Header, status: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 16 + self.data.len());
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = status;
        hdr.credit_charge = self.data.len().div_ceil(65536).max(1) as u16;
        hdr.encode(&mut out);
        self.encode_body(&mut out, SMB2_HEADER_SIZE);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 16 {
            return Err(SmbError::Malformed("read response too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 17 {
            return Err(SmbError::Malformed(format!(
                "read response StructureSize {structure_size} != 17"
            )));
        }
        let data_offset = r.read_u8()? as usize;
        let _reserved = r.read_u8()?;
        let data_length = r.read_u32()? as usize;
        let _data_remaining = r.read_u32()?;
        let _flags = r.read_u32()?;
        if data_length == 0 {
            return Ok(Self { data: Vec::new() });
        }
        if data_offset + data_length > buf.len() {
            return Err(SmbError::Malformed("read response data truncated".into()));
        }
        Ok(Self {
            data: buf[data_offset..data_offset + data_length].to_vec(),
        })
    }
}

// ============================================================================
// Write request/response — §2.2.21 / §2.2.22
// ============================================================================

/// SMB2 WRITE request (command 0x0009). MS-SMB2 §2.2.21.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRequest {
    /// Length (bytes to write).
    pub length: u32,
    /// Offset (byte offset within the file).
    pub offset: u64,
    /// FileId.
    pub file_id: FileId,
    /// Data (the bytes to write).
    pub data: Vec<u8>,
}

impl WriteRequest {
    /// Build a WRITE request carrying `data` to be written at `offset` on
    /// `file_id`.
    #[must_use]
    pub fn new(file_id: FileId, offset: u64, data: Vec<u8>) -> Self {
        let length = data.len() as u32;
        Self {
            length,
            offset,
            file_id,
            data,
        }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer, header_size: usize) -> u32 {
        out.write_u16(49); // StructureSize
        let data_offset = (header_size + 48) as u32;
        out.write_u8(data_offset as u8);
        out.write_u8(0); // Reserved
        out.write_u32(self.length);
        out.write_u64(self.offset);
        out.write_file_id(&self.file_id);
        out.write_u32(0); // Channel
        out.write_u32(0); // RemainingBytes
        out.write_u16(0); // WriteChannelInfoOffset
        out.write_u16(0); // WriteChannelInfoLength
        out.write_u32(0); // Flags
        out.write_bytes(&self.data);
        data_offset
    }

    /// Encode the full SMB2 WRITE request.
    pub fn encode(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 48 + self.data.len());
        let mut hdr = Smb2Header::new_request(command::WRITE, message_id);
        hdr.session_id = session_id;
        hdr.tree_id = tree_id;
        hdr.credit_charge = self.data.len().div_ceil(65536).max(1) as u16;
        hdr.encode(&mut out);
        self.encode_body(&mut out, SMB2_HEADER_SIZE);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 48 {
            return Err(SmbError::Malformed("write request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 49 {
            return Err(SmbError::Malformed(format!(
                "write request StructureSize {structure_size} != 49"
            )));
        }
        let data_offset = r.read_u8()? as usize;
        let _reserved = r.read_u8()?;
        let length = r.read_u32()?;
        let offset = r.read_u64()?;
        let file_id = r.read_file_id()?;
        let _channel = r.read_u32()?;
        let _remaining = r.read_u32()?;
        let _ch_info_off = r.read_u16()?;
        let _ch_info_len = r.read_u16()?;
        let _flags = r.read_u32()?;
        let data = if length == 0 {
            Vec::new()
        } else {
            if data_offset + length as usize > buf.len() {
                return Err(SmbError::Malformed("write data truncated".into()));
            }
            buf[data_offset..data_offset + length as usize].to_vec()
        };
        Ok(Self {
            length,
            offset,
            file_id,
            data,
        })
    }
}

/// SMB2 WRITE response (command 0x0009). MS-SMB2 §2.2.22.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteResponse {
    /// Count (bytes actually written).
    pub count: u32,
}

impl WriteResponse {
    /// Build a WRITE response reporting `count` bytes written.
    #[must_use]
    pub fn new(count: u32) -> Self {
        Self { count }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer) {
        out.write_u16(17); // StructureSize
        out.write_u16(0); // Reserved
        out.write_u32(self.count);
        out.write_u32(0); // Remaining
        out.write_u16(0); // WriteChannelInfoOffset
        out.write_u16(0); // WriteChannelInfoLength
    }

    /// Encode the full SMB2 WRITE response.
    pub fn encode(&self, request_header: &Smb2Header, status: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 16);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = status;
        hdr.encode(&mut out);
        self.encode_body(&mut out);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 16 {
            return Err(SmbError::Malformed("write response too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 17 {
            return Err(SmbError::Malformed(format!(
                "write response StructureSize {structure_size} != 17"
            )));
        }
        let _reserved = r.read_u16()?;
        let count = r.read_u32()?;
        Ok(Self { count })
    }
}

// ============================================================================
// Close request/response — §2.2.14 / §2.2.15
// ============================================================================

/// SMB2 CLOSE request (command 0x0006). MS-SMB2 §2.2.14.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRequest {
    /// Flags (0x01 = PostQueryAttrib — response includes file metadata).
    pub flags: u16,
    /// FileId.
    pub file_id: FileId,
}

impl CloseRequest {
    /// Build a CLOSE request for `file_id` (no post-query-attrib).
    #[must_use]
    pub fn new(file_id: FileId) -> Self {
        Self { flags: 0, file_id }
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer) {
        out.write_u16(24); // StructureSize
        out.write_u16(self.flags);
        out.write_u32(0); // Reserved
        out.write_file_id(&self.file_id);
    }

    /// Encode the full SMB2 CLOSE request.
    pub fn encode(&self, message_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 24);
        let mut hdr = Smb2Header::new_request(command::CLOSE, message_id);
        hdr.session_id = session_id;
        hdr.tree_id = tree_id;
        hdr.encode(&mut out);
        self.encode_body(&mut out);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 24 {
            return Err(SmbError::Malformed("close request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 24 {
            return Err(SmbError::Malformed(format!(
                "close request StructureSize {structure_size} != 24"
            )));
        }
        let flags = r.read_u16()?;
        let _reserved = r.read_u32()?;
        let file_id = r.read_file_id()?;
        Ok(Self { flags, file_id })
    }
}

/// SMB2 CLOSE response (command 0x0006). MS-SMB2 §2.2.15.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CloseResponse {
    /// Flags (echo of request flags).
    pub flags: u16,
    /// CreationTime (NT time).
    pub creation_time: u64,
    /// LastAccessTime (NT time).
    pub last_access_time: u64,
    /// LastWriteTime (NT time).
    pub last_write_time: u64,
    /// ChangeTime (NT time).
    pub change_time: u64,
    /// AllocationSize.
    pub allocation_size: u64,
    /// EndofFile (logical size).
    pub end_of_file: u64,
    /// FileAttributes.
    pub file_attributes: u32,
}

impl CloseResponse {
    /// Build an empty (no post-query-attrib) CLOSE response.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode the body.
    pub fn encode_body(&self, out: &mut Writer) {
        out.write_u16(60); // StructureSize
        out.write_u16(self.flags);
        out.write_u32(0); // Reserved
        out.write_u64(self.creation_time);
        out.write_u64(self.last_access_time);
        out.write_u64(self.last_write_time);
        out.write_u64(self.change_time);
        out.write_u64(self.allocation_size);
        out.write_u64(self.end_of_file);
        out.write_u32(self.file_attributes);
    }

    /// Encode the full SMB2 CLOSE response.
    pub fn encode(&self, request_header: &Smb2Header, status: u32) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 60);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = status;
        hdr.encode(&mut out);
        self.encode_body(&mut out);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 60 {
            return Err(SmbError::Malformed("close response too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 60 {
            return Err(SmbError::Malformed(format!(
                "close response StructureSize {structure_size} != 60"
            )));
        }
        let flags = r.read_u16()?;
        let _reserved = r.read_u32()?;
        let creation_time = r.read_u64()?;
        let last_access_time = r.read_u64()?;
        let last_write_time = r.read_u64()?;
        let change_time = r.read_u64()?;
        let allocation_size = r.read_u64()?;
        let end_of_file = r.read_u64()?;
        let file_attributes = r.read_u32()?;
        Ok(Self {
            flags,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            allocation_size,
            end_of_file,
            file_attributes,
        })
    }
}

// ============================================================================
// Logoff / Echo — §2.2.2 / §2.2.3 and §2.2.28 / §2.2.29
// ============================================================================

/// SMB2 LOGOFF request (command 0x0002). MS-SMB2 §2.2.2.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LogoffRequest;

impl LogoffRequest {
    /// Encode the full SMB2 LOGOFF request.
    pub fn encode(&self, message_id: u64, session_id: u64) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 4);
        let mut hdr = Smb2Header::new_request(command::LOGOFF, message_id);
        hdr.session_id = session_id;
        hdr.encode(&mut out);
        out.write_u16(4); // StructureSize
        out.write_u16(0); // Reserved
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 4 {
            return Err(SmbError::Malformed("logoff request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 4 {
            return Err(SmbError::Malformed(format!(
                "logoff request StructureSize {structure_size} != 4"
            )));
        }
        Ok(Self)
    }
}

/// SMB2 LOGOFF response (command 0x0002). MS-SMB2 §2.2.3.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LogoffResponse;

impl LogoffResponse {
    /// Encode the full SMB2 LOGOFF response.
    pub fn encode(&self, request_header: &Smb2Header) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 4);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = ntstatus::STATUS_SUCCESS;
        hdr.encode(&mut out);
        out.write_u16(4);
        out.write_u16(0);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 4 {
            return Err(SmbError::Malformed("logoff response too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 4 {
            return Err(SmbError::Malformed(format!(
                "logoff response StructureSize {structure_size} != 4"
            )));
        }
        Ok(Self)
    }
}

/// SMB2 ECHO request (command 0x000D). MS-SMB2 §2.2.28.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EchoRequest;

impl EchoRequest {
    /// Encode the full SMB2 ECHO request.
    pub fn encode(&self, message_id: u64) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 4);
        let hdr = Smb2Header::new_request(command::ECHO, message_id);
        hdr.encode(&mut out);
        out.write_u16(4);
        out.write_u16(0);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 4 {
            return Err(SmbError::Malformed("echo request too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 4 {
            return Err(SmbError::Malformed(format!(
                "echo request StructureSize {structure_size} != 4"
            )));
        }
        Ok(Self)
    }
}

/// SMB2 ECHO response (command 0x000D). MS-SMB2 §2.2.29.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EchoResponse;

impl EchoResponse {
    /// Encode the full SMB2 ECHO response.
    pub fn encode(&self, request_header: &Smb2Header) -> Vec<u8> {
        let mut out = Writer::with_capacity(SMB2_HEADER_SIZE + 4);
        let mut hdr = Smb2Header::new_response(request_header);
        hdr.status = ntstatus::STATUS_SUCCESS;
        hdr.encode(&mut out);
        out.write_u16(4);
        out.write_u16(0);
        out.into_bytes()
    }

    /// Decode the body.
    pub fn decode(buf: &[u8], header_size: usize) -> Result<Self, SmbError> {
        if buf.len() < header_size + 4 {
            return Err(SmbError::Malformed("echo response too short".into()));
        }
        let mut r = Reader::at(buf, header_size)?;
        let structure_size = r.read_u16()?;
        if structure_size != 4 {
            return Err(SmbError::Malformed(format!(
                "echo response StructureSize {structure_size} != 4"
            )));
        }
        Ok(Self)
    }
}

// ============================================================================
// TransformHeader (encrypted PDU prefix) — §2.2.41
// ============================================================================

/// SMB2 Transform header (52-byte fixed prefix on encrypted PDUs). §2.2.41.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransformHeader {
    /// Signature (16 bytes — top 16 bytes of the AEAD tag).
    pub signature: [u8; 16],
    /// Nonce (16 bytes — for AES-256-GCM the low 12 bytes are the nonce
    /// and the high 4 bytes are reserved).
    pub nonce: [u8; 16],
    /// OriginalMessageSize (unencrypted PDU size, in bytes).
    pub original_message_size: u32,
    /// Flags (0x0001 = Encrypted).
    pub flags: u16,
    /// SessionId this encrypted PDU belongs to.
    pub session_id: u64,
}

impl TransformHeader {
    /// Build a fresh transform header with zeroed signature/nonce.
    #[must_use]
    pub fn new(original_message_size: u32, session_id: u64) -> Self {
        Self {
            signature: [0; 16],
            nonce: [0; 16],
            original_message_size,
            flags: 0x0001,
            session_id,
        }
    }

    /// Encode to a 52-byte buffer.
    pub fn encode(&self, out: &mut Writer) {
        out.write_bytes(&SMB2_TRANSFORM_MAGIC);
        out.write_bytes(&self.signature);
        out.write_bytes(&self.nonce);
        out.write_u32(self.original_message_size);
        out.write_u16(0); // Reserved
        out.write_u16(self.flags);
        out.write_u64(self.session_id);
    }

    /// Decode from a 52+ byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, SmbError> {
        if buf.len() < SMB2_TRANSFORM_HEADER_SIZE {
            return Err(SmbError::Malformed(format!(
                "transform header too short: {} < {SMB2_TRANSFORM_HEADER_SIZE}",
                buf.len()
            )));
        }
        if buf[0..4] != SMB2_TRANSFORM_MAGIC {
            return Err(SmbError::Malformed(format!(
                "bad transform magic: {:02x?}",
                &buf[0..4]
            )));
        }
        let mut r = Reader::at(buf, 4)?;
        let signature = r.read_signature()?;
        let nonce_bytes = r.read_bytes(16)?;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(nonce_bytes);
        let original_message_size = r.read_u32()?;
        let _reserved = r.read_u16()?;
        let flags = r.read_u16()?;
        let session_id = r.read_u64()?;
        Ok(Self {
            signature,
            nonce,
            original_message_size,
            flags,
            session_id,
        })
    }
}

// ============================================================================
// PreauthHash — SHA-512 chained pre-auth integrity hash per MS-SMB2 §3.2.5.1
// ============================================================================

/// SHA-512 pre-auth integrity hash, chained over Negotiate + SessionSetup
/// messages per MS-SMB2 §3.2.5.1.
///
/// The initial hash value is 512 bits of zeros. For each message, the
/// hash is updated as `SHA-512(prev_hash || message)`. The final hash
/// value is mixed into the session-key derivation (HKDF-SHA-512 labeled
/// `"SMBSigningKey"` / `"ServerIn"` / `"ServerOut"` per §3.2.5.2).
#[derive(Debug, Clone)]
pub struct PreauthHash {
    state: [u8; 64],
}

impl Default for PreauthHash {
    fn default() -> Self {
        Self::new()
    }
}

impl PreauthHash {
    /// Construct a fresh preauth hash (initial value = 64 bytes of zeros).
    #[must_use]
    pub fn new() -> Self {
        Self { state: [0u8; 64] }
    }

    /// Feed `data` into the hash chain. The new state is
    /// `SHA-512(prev_state || data)`.
    pub fn update(&mut self, data: &[u8]) {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(self.state);
        h.update(data);
        let out = h.finalize();
        self.state.copy_from_slice(&out);
    }

    /// Feed multiple byte slices in order (convenience for header+body).
    pub fn update_all(&mut self, parts: &[&[u8]]) {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(self.state);
        for p in parts {
            h.update(*p);
        }
        let out = h.finalize();
        self.state.copy_from_slice(&out);
    }

    /// Snapshot the current hash value (does not consume self).
    #[must_use]
    pub fn current(&self) -> [u8; 64] {
        self.state
    }

    /// Finalize: consume self and return the hash value.
    #[must_use]
    pub fn finalize(self) -> [u8; 64] {
        self.state
    }

    /// One-shot: compute the preauth hash over the given messages
    /// (typically `[negotiate_request, negotiate_response]`).
    #[must_use]
    pub fn compute(messages: &[&[u8]]) -> [u8; 64] {
        let mut h = Self::new();
        for m in messages {
            h.update(m);
        }
        h.finalize()
    }
}

// ============================================================================
// SmbEncryptionKey — AES-256-GCM session encryption key (§3.2.5.2)
// ============================================================================

/// AES-256-GCM session encryption key (32 bytes) for SMB 3.1.1 encrypted
/// PDUs. Derived from the SessionKey via HKDF-SHA-512 labeled
/// `"SMBSessionKey"` with the preauth-integrity hash as context, per
/// MS-SMB2 §3.2.5.2.1.
///
/// In SMB 3.1.1 the client and server each derive two keys
/// (ServerIn / ServerOut) by appending the direction label; for the
/// symmetric AES-256-GCM cipher used by this framework the same 32-byte
/// key serves both directions in tests (a real deployment would derive
/// two separate keys per §3.2.5.2.1).
#[derive(Clone, Zeroize)]
pub struct SmbEncryptionKey([u8; 32]);

impl SmbEncryptionKey {
    /// Wrap an existing 32-byte key.
    #[must_use]
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// Build a deterministic test key from a fixed seed. NOT for
    /// production use — production code must call
    /// [`SmbEncryptionKey::derive_from_session_key`].
    #[must_use]
    pub fn for_test(seed: u8) -> Self {
        Self([seed; 32])
    }

    /// Derive an AES-256-GCM encryption key from the session key and
    /// preauth-integrity hash per MS-SMB2 §3.2.5.2.1.
    ///
    /// The KDF is HKDF-SHA-512 with:
    ///   - IKM = `session_key`
    ///   - salt = `preauth_hash` (64 bytes for SHA-512)
    ///   - info = `b"SMBSessionKey" || preauth_hash`
    ///   - L   = 32 bytes (AES-256 key length)
    ///
    /// # Errors
    ///
    /// Returns [`SmbError::Encryption`] if `session_key` is empty (the
    /// KDF requires a non-zero IKM length).
    pub fn derive_from_session_key(
        session_key: &[u8],
        preauth_hash: &[u8; 64],
    ) -> Result<Self, SmbError> {
        if session_key.is_empty() {
            return Err(SmbError::Encryption(
                "session key is empty (KDF requires non-zero IKM)".into(),
            ));
        }
        // HKDF-SHA-512 (RFC 5869) — extract then expand.
        let prk = hkdf_extract_sha512(preauth_hash, session_key);
        // info = "SMBSessionKey" || preauth_hash (per MS-SMB2 §3.2.5.2.1).
        let mut info = Vec::with_capacity(14 + preauth_hash.len());
        info.extend_from_slice(b"SMBSessionKey");
        info.extend_from_slice(preauth_hash);
        let okm = hkdf_expand_sha512(&prk, &info, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm);
        Ok(Self(key))
    }

    /// Borrow the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SmbEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid leaking key material in debug output.
        f.debug_struct("SmbEncryptionKey")
            .field("len", &32)
            .finish_non_exhaustive()
    }
}

/// HKDF-Extract step (RFC 5869 §2.2) using HMAC-SHA-512.
fn hkdf_extract_sha512(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(salt).expect("HMAC accepts any salt length");
    mac.update(ikm);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// HKDF-Expand step (RFC 5869 §2.3) using HMAC-SHA-512. Returns `L` bytes.
fn hkdf_expand_sha512(prk: &[u8; 64], info: &[u8], length: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let hash_len = 64usize;
    let n = length.div_ceil(hash_len);
    let mut t_prev: Vec<u8> = Vec::new();
    let mut okm = Vec::with_capacity(length);
    for counter in 1..=n {
        let mut mac = HmacSha512::new_from_slice(prk).expect("HMAC accepts any PRK length");
        mac.update(&t_prev);
        mac.update(info);
        mac.update(&[counter as u8]);
        let block = mac.finalize().into_bytes();
        okm.extend_from_slice(&block);
        t_prev = block.to_vec();
    }
    okm.truncate(length);
    okm
}

// ============================================================================
// AES-256-GCM PDU encrypt / decrypt (§3.2.4.3 / §3.1.4.3)
// ============================================================================

/// AES-256-GCM nonce length (12 bytes per MS-SMB2 §3.2.5.2.1).
pub const AES_256_GCM_NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length (16 bytes per MS-SMB2 §3.2.5.2.1).
pub const AES_256_GCM_TAG_LEN: usize = 16;

/// Encrypt an SMB2 PDU using AES-256-GCM and return the framed
/// `SMB2_TRANSFORM_HEADER || ciphertext` byte stream (ready for
/// NetBIOS framing).
///
/// Per MS-SMB2 §3.2.4.3:
///   1. Allocate a 12-byte random nonce; place it in the low 12 bytes
///      of the transform header's 16-byte Nonce field (the high 4
///      bytes are reserved and set to zero).
///   2. Build the 52-byte transform header with `Signature = 0`,
///      `OriginalMessageSize = plaintext.len()`, `Flags = 0x0001`
///      (Encrypted), `SessionId = session_id`.
///   3. Compute AES-256-GCM over `plaintext` with the nonce and AAD =
///      the 52-byte transform header (Signature already zeroed).
///   4. The 16-byte GCM tag goes into the transform header's
///      `Signature` field; the ciphertext (no tag appended) follows
///      the header on the wire.
///
/// # Errors
///
/// Returns [`SmbError::Encryption`] if AES-GCM fails (only possible on
/// nonce length mismatch, which is statically guaranteed not to happen
/// here).
pub fn encrypt_pdu(
    key: &SmbEncryptionKey,
    plaintext: &[u8],
    session_id: u64,
    nonce_seed: [u8; AES_256_GCM_NONCE_LEN],
) -> Result<Vec<u8>, SmbError> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key};

    // 1) Pack the 12-byte nonce into the low 12 bytes of the 16-byte
    //    Nonce field (high 4 bytes reserved = 0).
    let mut nonce_field = [0u8; 16];
    nonce_field[..AES_256_GCM_NONCE_LEN].copy_from_slice(&nonce_seed);

    // 2) Build the transform header (Signature = 0).
    let transform = TransformHeader {
        signature: [0u8; 16],
        nonce: nonce_field,
        original_message_size: plaintext.len() as u32,
        flags: 0x0001,
        session_id,
    };
    let mut header_bytes = Vec::with_capacity(SMB2_TRANSFORM_HEADER_SIZE);
    let mut w = Writer::new();
    transform.encode(&mut w);
    header_bytes.extend_from_slice(w.as_bytes());
    debug_assert_eq!(header_bytes.len(), SMB2_TRANSFORM_HEADER_SIZE);

    // 3) AES-256-GCM encrypt with AAD = the 52-byte header (Signature
    //    is already zero).
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce_obj = aes_gcm::Nonce::from_slice(&nonce_seed);
    let ciphertext_with_tag = cipher
        .encrypt(
            nonce_obj,
            Payload {
                msg: plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|e| SmbError::Encryption(format!("aes-256-gcm encrypt: {e}")))?;
    // aes-gcm appends the 16-byte tag to the ciphertext. Split it off.
    let ct_len = ciphertext_with_tag.len();
    if ct_len < AES_256_GCM_TAG_LEN {
        return Err(SmbError::Encryption(
            "aes-256-gcm produced ciphertext shorter than tag".into(),
        ));
    }
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ct_len - AES_256_GCM_TAG_LEN);

    // 4) Place the 16-byte tag into the Signature field.
    let mut out = header_bytes;
    debug_assert_eq!(out[4..20].len(), 16);
    out[4..20].copy_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Decrypt an SMB2 PDU previously encrypted with [`encrypt_pdu`].
///
/// `frame` MUST be the complete `SMB2_TRANSFORM_HEADER || ciphertext`
/// (no NetBIOS framing). The function:
///   1. Decodes the 52-byte transform header.
///   2. Verifies the Flags have bit 0x0001 set (Encrypted).
///   3. Reconstructs the AAD = the 52-byte header with the Signature
///      field zeroed (it currently holds the GCM tag).
///   4. Recombines `ciphertext || tag` and calls AES-256-GCM decrypt.
///
/// # Errors
///
/// Returns [`SmbError::Malformed`] if the frame is too short or the
/// transform magic is wrong. Returns [`SmbError::Encryption`] if the
/// GCM tag verification fails (tampering, wrong key, etc).
pub fn decrypt_pdu(key: &SmbEncryptionKey, frame: &[u8]) -> Result<Vec<u8>, SmbError> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key};

    if frame.len() < SMB2_TRANSFORM_HEADER_SIZE {
        return Err(SmbError::Malformed(format!(
            "encrypted frame too short: {} < {SMB2_TRANSFORM_HEADER_SIZE}",
            frame.len()
        )));
    }
    let header = TransformHeader::decode(frame)?;
    if header.flags & 0x0001 == 0 {
        return Err(SmbError::Encryption(
            "transform header Flags bit 0x0001 (Encrypted) not set".into(),
        ));
    }
    let ciphertext_body = &frame[SMB2_TRANSFORM_HEADER_SIZE..];
    // AAD = header with Signature (bytes 4..20) zeroed.
    let mut aad = frame[..SMB2_TRANSFORM_HEADER_SIZE].to_vec();
    for b in &mut aad[4..20] {
        *b = 0;
    }
    // Recombine ciphertext || tag for AES-GCM decrypt.
    let mut cipher_with_tag = Vec::with_capacity(ciphertext_body.len() + AES_256_GCM_TAG_LEN);
    cipher_with_tag.extend_from_slice(ciphertext_body);
    cipher_with_tag.extend_from_slice(&header.signature);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = &header.nonce[..AES_256_GCM_NONCE_LEN];
    let nonce_obj = aes_gcm::Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(
            nonce_obj,
            Payload {
                msg: &cipher_with_tag,
                aad: &aad,
            },
        )
        .map_err(|e| SmbError::Encryption(format!("aes-256-gcm decrypt: {e}")))?;
    Ok(plaintext)
}

// ============================================================================
// GSS-API / SPNEGO — Kerberos session setup (MS-SMB2 §3.2.5.3, RFC 4178)
// ============================================================================

/// GSS-API / SPNEGO mechanism OIDs (DER-encoded, without the leading
/// `06 LL` tag/length bytes — just the OID body). Used by [`gss_api`]
/// to classify the offered mechanisms in a NegTokenInit.
pub mod gss_api {
    use super::SmbError;

    /// SPNEGO OID body: `1.3.6.1.5.5.2` (RFC 4178).
    pub const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

    /// Kerberos5 OID body: `1.2.840.113554.1.2.2` (RFC 4121 / MS-KILE).
    pub const KERBEROS5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

    /// NTLMSSP OID body: `1.3.6.1.4.1.311.2.2.10` (per ADR-085 — client-only).
    pub const NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

    /// Synthetic Kerberos AP-REQ marker — the first 7 bytes of every
    /// mechToken produced by [`init_sec_context`] / accepted by
    /// [`accept_sec_context`]. The marker spells `b"KRBAUTH"` and is
    /// followed by the target SPN (UTF-8, length-prefixed) and a
    /// 16-byte client nonce.
    pub const KRB_AUTH_MARKER: &[u8] = b"KRBAUTH";

    /// GSS-API acceptor result.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AcceptResult {
        /// Session key derived from the Kerberos mechToken (16 bytes).
        /// Used as the SMB2 SessionKey for signing/encryption key
        /// derivation per MS-SMB2 §3.2.5.2.
        pub session_key: [u8; 16],
        /// SPNEGO response token to return to the client (empty on
        /// completion — no further round-trips needed).
        pub response_token: Vec<u8>,
        /// True when the context is fully established; false when the
        /// acceptor needs another token from the client (continued
        /// authentication — not used in the synthetic implementation).
        pub completed: bool,
    }

    /// A classification of the offered mechanism(s) in an SPNEGO
    /// NegTokenInit blob.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum MechClass {
        /// Kerberos5 was offered (and is accepted).
        Kerberos,
        /// Only NTLM was offered (refused per ADR-085).
        NtlmOnly,
        /// No recognised mechanisms were offered (anonymous / unknown).
        Unknown,
    }

    /// Inspect a GSS-API initial token and classify the offered
    /// mechanism(s). This is a minimal hand-rolled DER walker: it scans
    /// the blob for the well-known OID bodies (Kerberos5, NTLMSSP) and
    /// returns the strongest classification.
    ///
    /// The function does NOT verify the SPNEGO NegTokenInit structure
    /// strictly — it looks for the OID bodies anywhere in the blob,
    /// which is robust to DER length-encoding variations and to
    /// non-canonical encoders (e.g. Samba's Heimdal-derived encoder).
    #[must_use]
    pub fn classify_mech(token: &[u8]) -> MechClass {
        let mut has_krb = false;
        let mut has_ntlm = false;
        // Sliding-window search for the OID bodies. OIDs in DER are
        // preceded by `06 LL` (tag 06, length LL) but we just look for
        // the body to keep the walker trivial.
        if contains_subslice(token, KERBEROS5) {
            has_krb = true;
        }
        if contains_subslice(token, NTLMSSP) {
            has_ntlm = true;
        }
        if has_krb {
            MechClass::Kerberos
        } else if has_ntlm {
            MechClass::NtlmOnly
        } else {
            MechClass::Unknown
        }
    }

    /// Accept a GSS-API security context (server-side SPNEGO acceptor).
    ///
    /// The function:
    ///   1. Classifies the offered mechanisms via [`classify_mech`].
    ///   2. Refuses NTLM-only tokens (per ADR-085) and unknown / empty
    ///      tokens (anonymous — refused per MS-SMB2 §3.2.5.3).
    ///   3. Extracts the Kerberos mechToken (looking for the
    ///      [`KRB_AUTH_MARKER`] sentinel and parsing the SPN + client
    ///      nonce that follows it).
    ///   4. Derives a 16-byte session key from
    ///      `HKDF-SHA-256(mechToken || server_secret, "SMBSessionKey")`.
    ///
    /// # Errors
    ///
    /// Returns [`SmbError::Encryption`] (re-used as the "auth" error
    /// surface, since the SMB layer maps it to `STATUS_LOGON_FAILURE`)
    /// when:
    ///   - the token is empty (anonymous refused),
    ///   - only NTLM is offered (ADR-085),
    ///   - the mechanism is unknown,
    ///   - the Kerberos mechToken cannot be parsed.
    pub fn accept_sec_context(
        input_token: &[u8],
        server_secret: &[u8],
    ) -> Result<AcceptResult, SmbError> {
        if input_token.is_empty() {
            return Err(SmbError::Encryption(
                "anonymous session setup refused (token empty)".into(),
            ));
        }
        let class = classify_mech(input_token);
        match class {
            MechClass::NtlmOnly => Err(SmbError::Encryption(
                "NTLM session setup refused per ADR-085 (client-only)".into(),
            )),
            MechClass::Unknown => Err(SmbError::Encryption(
                "unknown mechanism — anonymous session setup refused".into(),
            )),
            MechClass::Kerberos => {
                // Extract the synthetic Kerberos mechToken (KRBAUTH || spn_len(u8) || spn || nonce[16]).
                let mech_token = extract_mech_token(input_token)?;
                if mech_token.len() < KRB_AUTH_MARKER.len() + 1 + 16 {
                    return Err(SmbError::Encryption(format!(
                        "Kerberos mechToken too short: {} bytes",
                        mech_token.len()
                    )));
                }
                if &mech_token[..KRB_AUTH_MARKER.len()] != KRB_AUTH_MARKER {
                    return Err(SmbError::Encryption(
                        "Kerberos mechToken marker missing".into(),
                    ));
                }
                // Derive a deterministic 16-byte session key from the
                // mechToken + server_secret using HKDF-SHA-256.
                let mut ikm = Vec::with_capacity(mech_token.len() + server_secret.len());
                ikm.extend_from_slice(&mech_token);
                ikm.extend_from_slice(server_secret);
                let session_key = derive_smb_session_key(&ikm, b"SMBSessionKey");
                Ok(AcceptResult {
                    session_key,
                    response_token: Vec::new(),
                    completed: true,
                })
            }
        }
    }

    /// Initialize a GSS-API security context (client-side SPNEGO
    /// initiator) for `target_spn`. Returns an SPNEGO NegTokenInit
    /// blob suitable for the SessionSetup request's SecurityBuffer.
    ///
    /// The blob advertises Kerberos5 as the only mechanism (so the
    /// server's [`accept_sec_context`] never falls back to NTLM) and
    /// carries a synthetic AP-REQ containing the SPN and a 16-byte
    /// client nonce.
    ///
    /// # Errors
    ///
    /// Returns [`SmbError::Encryption`] only if the SPN is empty.
    pub fn init_sec_context(target_spn: &str, client_secret: &[u8]) -> Result<Vec<u8>, SmbError> {
        if target_spn.is_empty() {
            return Err(SmbError::Encryption(
                "init_sec_context: target SPN must not be empty".into(),
            ));
        }
        // Build the synthetic Kerberos mechToken:
        //   KRBAUTH || spn_len(u8 LE) || spn_utf8 || client_nonce[16]
        let spn_bytes = target_spn.as_bytes();
        if spn_bytes.len() > 255 {
            return Err(SmbError::Encryption(format!(
                "target SPN too long ({} bytes > 255)",
                spn_bytes.len()
            )));
        }
        let mut mech_token = Vec::with_capacity(KRB_AUTH_MARKER.len() + 1 + spn_bytes.len() + 16);
        mech_token.extend_from_slice(KRB_AUTH_MARKER);
        mech_token.push(spn_bytes.len() as u8);
        mech_token.extend_from_slice(spn_bytes);
        // 16-byte deterministic client nonce derived from client_secret
        // (production code would use a CSPRNG; the framework's KDC
        // integration is wired in a later wave).
        let mut client_nonce = [0u8; 16];
        let secret_len = client_secret.len().min(16);
        client_nonce[..secret_len].copy_from_slice(&client_secret[..secret_len]);
        mech_token.extend_from_slice(&client_nonce);

        // Build the SPNEGO NegTokenInit DER blob:
        //   [APPLICATION 0] SEQUENCE {
        //     SPNEGO_OID,
        //     [0] NegTokenInit SEQUENCE {
        //       [0] MechTypeList SEQUENCE OF { Kerberos5_OID },
        //       [2] MechToken OCTET STRING { mech_token }
        //     }
        //   }
        let krb_oid_tlv = der_oid(KERBEROS5);
        let spnego_oid_tlv = der_oid(SPNEGO);
        let mech_token_tlv = der_octet_string(&mech_token);

        // MechTypeList = SEQUENCE OF { Kerberos5 }
        let mech_type_list = der_sequence(&krb_oid_tlv);
        // [0] mechTypes (context tag 0, constructed)
        let mech_types_tlv = der_context_constructed(0, &mech_type_list);
        // [2] mechToken (context tag 2, constructed)
        let mech_token_ctx_tlv = der_context_constructed(2, &mech_token_tlv);
        // NegTokenInit = SEQUENCE { mechTypes, mechToken }
        let neg_token_init =
            der_sequence(&[mech_types_tlv.as_slice(), mech_token_ctx_tlv.as_slice()].concat());
        // [0] NegTokenInit wrapper (context tag 0, constructed)
        let neg_token_init_ctx = der_context_constructed(0, &neg_token_init);
        // InitialContextToken = [APPLICATION 0] SEQUENCE { SPNEGO_OID, NegTokenInit-wrapped }
        let inner = [spnego_oid_tlv.as_slice(), neg_token_init_ctx.as_slice()].concat();
        let initial_context_token = der_application_constructed(0, &inner);
        Ok(initial_context_token)
    }

    /// Derive a 16-byte SMB session key from `ikm` using HKDF-SHA-256
    /// (RFC 5869) with the given label as `info`.
    fn derive_smb_session_key(ikm: &[u8], label: &[u8]) -> [u8; 16] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        // HKDF-Extract: PRK = HMAC-SHA-256(salt="", ikm)
        let mut mac = HmacSha256::new_from_slice(&[]).expect("HMAC accepts empty salt");
        mac.update(ikm);
        let prk = mac.finalize().into_bytes();
        // HKDF-Expand: T(1) = HMAC-SHA-256(PRK, info || 0x01)
        let mut mac = HmacSha256::new_from_slice(&prk).expect("HMAC accepts PRK");
        mac.update(label);
        mac.update(&[0x01]);
        let t1 = mac.finalize().into_bytes();
        let mut key = [0u8; 16];
        key.copy_from_slice(&t1[..16]);
        key
    }

    /// Extract the synthetic Kerberos mechToken from an SPNEGO
    /// NegTokenInit blob. Walks the DER looking for an OCTET STRING
    /// whose body starts with the [`KRB_AUTH_MARKER`].
    fn extract_mech_token(blob: &[u8]) -> Result<Vec<u8>, SmbError> {
        // Sliding-window search for the marker.
        let marker_len = KRB_AUTH_MARKER.len();
        for i in 0..blob.len().saturating_sub(marker_len) {
            if &blob[i..i + marker_len] == KRB_AUTH_MARKER {
                // Found the marker — the mechToken is the marker + the
                // following spn_len + spn + nonce[16] bytes. We don't
                // strictly know the length here (we'd need to parse the
                // surrounding OCTET STRING TLV), so we conservatively
                // return everything from the marker to the end of the
                // blob. The caller validates the minimum length and
                // only reads the SPN + 16-byte nonce prefix.
                return Ok(blob[i..].to_vec());
            }
        }
        Err(SmbError::Encryption(
            "Kerberos mechToken marker not found in SPNEGO blob".into(),
        ))
    }

    // ---- Minimal DER encoders (definite-length) ----

    fn der_encode_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else if len <= 0xFFFF {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        } else {
            // SPNEGO blobs are tiny; 3-byte length encoding is the
            // most we ever need.
            vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
        }
    }

    fn der_oid(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + body.len());
        out.push(0x06); // OBJECT IDENTIFIER
        out.extend(der_encode_len(body.len()));
        out.extend_from_slice(body);
        out
    }

    fn der_octet_string(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + body.len());
        out.push(0x04); // OCTET STRING
        out.extend(der_encode_len(body.len()));
        out.extend_from_slice(body);
        out
    }

    fn der_sequence(contents: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + contents.len());
        out.push(0x30); // SEQUENCE
        out.extend(der_encode_len(contents.len()));
        out.extend_from_slice(contents);
        out
    }

    fn der_context_constructed(tag: u8, contents: &[u8]) -> Vec<u8> {
        debug_assert!(tag < 0x20, "context tag must fit in 5 bits");
        let mut out = Vec::with_capacity(2 + contents.len());
        out.push(0xA0 | tag); // context tag, constructed
        out.extend(der_encode_len(contents.len()));
        out.extend_from_slice(contents);
        out
    }

    fn der_application_constructed(tag: u8, contents: &[u8]) -> Vec<u8> {
        debug_assert!(tag < 0x20, "application tag must fit in 5 bits");
        let mut out = Vec::with_capacity(2 + contents.len());
        out.push(0x60 | tag); // application tag, constructed
        out.extend(der_encode_len(contents.len()));
        out.extend_from_slice(contents);
        out
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    // ---- Tests for the gss_api module ----

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn classify_mech_detects_kerberos_oid() {
            let blob = init_sec_context("cifs/dc01.example.com", &[0xAB; 16]).expect("init ok");
            assert_eq!(classify_mech(&blob), MechClass::Kerberos);
        }

        #[test]
        fn classify_mech_detects_ntlm_only_blob() {
            // Hand-craft an NTLM-only SPNEGO blob.
            let ntlm_oid_tlv = der_oid(NTLMSSP);
            let mech_list = der_sequence(&ntlm_oid_tlv);
            let mech_types_tlv = der_context_constructed(0, &mech_list);
            let neg_init = der_sequence(&mech_types_tlv);
            let neg_init_ctx = der_context_constructed(0, &neg_init);
            let spnego_oid_tlv = der_oid(SPNEGO);
            let inner = [spnego_oid_tlv.as_slice(), neg_init_ctx.as_slice()].concat();
            let blob = der_application_constructed(0, &inner);
            assert_eq!(classify_mech(&blob), MechClass::NtlmOnly);
        }

        #[test]
        fn classify_mech_returns_unknown_for_empty_blob() {
            assert_eq!(classify_mech(&[]), MechClass::Unknown);
        }
    }
}

// ============================================================================
// NetBIOS Session Service framing — used by the transport
// ============================================================================

/// NetBIOS Session Service header: 1 byte type (0x00 = session message) +
/// 3 bytes big-endian length. Used on TCP/445 for SMB2 message framing.
pub mod netbios {
    use super::SmbError;

    /// Encode a NetBIOS Session Service frame: type=0x00, 3-byte big-endian
    /// length, then `payload`.
    pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        debug_assert!(len < 0x0100_0000, "netbios frame too large");
        let mut out = Vec::with_capacity(4 + len);
        out.push(0x00); // type = session message
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
        out.extend_from_slice(payload);
        out
    }

    /// Decode the 4-byte NetBIOS header from `buf` and return
    /// `(frame_type, payload_length)`. Returns `Ok(None)` if `buf` has
    /// fewer than 4 bytes available (caller should read more).
    pub fn peek_header(buf: &[u8]) -> Result<Option<(u8, usize)>, SmbError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let frame_type = buf[0];
        let length = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
        Ok(Some((frame_type, length)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SMB2 header round-trip ----

    #[test]
    fn smb2_header_request_round_trips() {
        let hdr = Smb2Header {
            credit_charge: 1,
            status: 0,
            command: command::NEGOTIATE,
            credits: 31,
            flags: 0,
            next_command: 0,
            message_id: 42,
            process_id: 0xDEAD_BEEF,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };
        let mut out = Writer::new();
        hdr.encode(&mut out);
        assert_eq!(out.position(), 64);
        let decoded = Smb2Header::decode(out.as_bytes()).expect("decode header");
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn smb2_header_response_round_trips_with_status_and_signature() {
        let mut sig = [0u8; 16];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let hdr = Smb2Header {
            credit_charge: 2,
            status: ntstatus::STATUS_ACCESS_DENIED,
            command: command::READ,
            credits: 1,
            flags: flags::SMB2_FLAGS_RESPONSE | flags::SMB2_FLAGS_SIGNED,
            next_command: 0,
            message_id: 0xCAFE_BABE,
            process_id: 1,
            tree_id: 7,
            session_id: 0x1234_5678_9ABC_DEF0,
            signature: sig,
        };
        let mut out = Writer::new();
        hdr.encode(&mut out);
        assert_eq!(out.position(), 64);
        let decoded = Smb2Header::decode(out.as_bytes()).expect("decode header");
        assert_eq!(decoded, hdr);
        assert!(decoded.is_response());
        assert!(decoded.is_signed());
    }

    #[test]
    fn smb2_header_decode_rejects_short_buffer() {
        let buf = [0u8; 32];
        let err = Smb2Header::decode(&buf).expect_err("should reject short");
        assert!(matches!(err, SmbError::Malformed(_)));
    }

    #[test]
    fn smb2_header_decode_rejects_bad_magic() {
        let mut out = Writer::new();
        out.write_bytes(&[0xAA, 0xBB, 0xCC, 0xDD]); // bad magic
        out.write_u16(64);
        out.write_bytes(&[0u8; 58]);
        let err = Smb2Header::decode(out.as_bytes()).expect_err("should reject bad magic");
        assert!(matches!(err, SmbError::Malformed(_)));
    }

    #[test]
    fn smb2_header_decode_refuses_smb1_magic() {
        // Per ADR-043 — SMB1 magic must surface Smb1Refused so the server
        // can reply with STATUS_INVALID_PARAMETER and close the connection.
        let mut out = Writer::new();
        out.write_bytes(&SMB1_MAGIC);
        out.write_u16(64);
        out.write_bytes(&[0u8; 58]);
        let err = Smb2Header::decode(out.as_bytes()).expect_err("should refuse SMB1");
        assert!(matches!(err, SmbError::Smb1Refused), "got {err:?}");
    }

    // ---- Negotiate round-trip ----

    #[test]
    fn negotiate_request_round_trips_with_311_contexts() {
        let client_guid = uuid::Uuid::from_u128(0xABCD_1234_5678_0000_0000_0000_0000_0001);
        let salt = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let req = NegotiateRequest::new_311(client_guid, &salt);
        let bytes = req.encode(1);
        // Header magic + StructureSize.
        assert_eq!(&bytes[0..4], &SMB2_MAGIC);
        let decoded = NegotiateRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode req");
        assert_eq!(decoded, req);
        // 3 contexts: preauth integrity, encryption, signing.
        assert_eq!(decoded.negotiate_contexts.len(), 3);
    }

    #[test]
    fn negotiate_response_round_trips_with_311_contexts() {
        let server_guid = uuid::Uuid::from_u128(0x9999_9999_9999_9999_9999_9999_9999_9999);
        let salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let resp = NegotiateResponse::new_311(server_guid, &salt);
        let req_hdr = Smb2Header::new_request(command::NEGOTIATE, 1);
        let bytes = resp.encode(&req_hdr);
        assert_eq!(&bytes[0..4], &SMB2_MAGIC);
        let decoded = NegotiateResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(decoded, resp);
        assert_eq!(decoded.dialect_revision, dialect_code::SMB311);
    }

    #[test]
    fn negotiate_context_preauth_integrity_round_trips() {
        let salt = [0x11u8; 32];
        let ctx = NegotiateContext::preauth_integrity(&[preauth_hash_algo::SHA512], &salt);
        let (algos, decoded_salt) = ctx.parse_preauth().expect("parse preauth");
        assert_eq!(algos, vec![preauth_hash_algo::SHA512]);
        assert_eq!(decoded_salt, salt.to_vec());
    }

    #[test]
    fn negotiate_context_encryption_round_trips() {
        let ctx = NegotiateContext::encryption(&[cipher::AES_256_GCM, cipher::AES_128_GCM]);
        let ciphers = ctx.parse_encryption().expect("parse encryption");
        assert_eq!(ciphers, vec![cipher::AES_256_GCM, cipher::AES_128_GCM]);
    }

    // ---- SessionSetup round-trip ----

    #[test]
    fn session_setup_round_trips_with_spnego_blob() {
        let blob = vec![0x60, 0x06, 0x06, 0x02, 0x2A, 0x03, 0x01, 0x00]; // dummy SPNEGO
        let req = SessionSetupRequest::new(blob.clone());
        let bytes = req.encode(1, 0xABCD_1234);
        let decoded = SessionSetupRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode");
        assert_eq!(decoded, req);
        assert_eq!(decoded.security_buffer, blob);
    }

    #[test]
    fn session_setup_response_round_trips() {
        let resp = SessionSetupResponse::new_success();
        let req_hdr = Smb2Header::new_request(command::SESSION_SETUP, 1);
        let bytes = resp.encode(&req_hdr, ntstatus::STATUS_SUCCESS);
        let decoded = SessionSetupResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode");
        assert_eq!(decoded, resp);
    }

    // ---- TreeConnect round-trip ----

    #[test]
    fn tree_connect_round_trips_with_unc_path() {
        let path = r"\dc01\sysvol".to_string();
        let req = TreeConnectRequest::new(path.clone());
        let bytes = req.encode(2, 0xCAFE);
        let decoded = TreeConnectRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode");
        assert_eq!(decoded, req);
        assert_eq!(decoded.path, path);
    }

    #[test]
    fn tree_connect_response_round_trips_disk_share() {
        let resp = TreeConnectResponse::new_disk();
        let req_hdr = Smb2Header::new_request(command::TREE_CONNECT, 2);
        let bytes = resp.encode(&req_hdr, 7, ntstatus::STATUS_SUCCESS);
        let decoded = TreeConnectResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode");
        assert_eq!(decoded, resp);
        assert_eq!(decoded.share_type, share_type::DISK);
    }

    // ---- Create / Read / Write / Close round-trip ----

    #[test]
    fn create_request_response_round_trips() {
        let req = CreateRequest::new(r"\share\file.txt");
        let bytes = req.encode(3, 0x100, 7);
        let decoded = CreateRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode req");
        assert_eq!(decoded, req);

        let file_id = FileId::new(0xAAAA_BBBB_CCCC_DDDD, 0x1111_2222_3333_4444);
        let resp = CreateResponse::new(file_id, 4096);
        let req_hdr = Smb2Header::new_request(command::CREATE, 3);
        let bytes = resp.encode(&req_hdr, ntstatus::STATUS_SUCCESS);
        let decoded = CreateResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(decoded, resp);
        assert_eq!(decoded.file_id, file_id);
    }

    #[test]
    fn read_request_response_round_trips() {
        let file_id = FileId::new(1, 2);
        let req = ReadRequest::new(file_id, 1024, 4096);
        let bytes = req.encode(4, 0x100, 7);
        let decoded = ReadRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode req");
        assert_eq!(decoded, req);

        let data = vec![0xABu8; 4096];
        let resp = ReadResponse::new(data.clone());
        let req_hdr = Smb2Header::new_request(command::READ, 4);
        let bytes = resp.encode(&req_hdr, ntstatus::STATUS_SUCCESS);
        let decoded = ReadResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(decoded, resp);
        assert_eq!(decoded.data, data);
    }

    #[test]
    fn write_request_response_round_trips() {
        let file_id = FileId::new(3, 4);
        let data = vec![0xCDu8; 1234];
        let req = WriteRequest::new(file_id, 0, data.clone());
        let bytes = req.encode(5, 0x100, 7);
        let decoded = WriteRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode req");
        assert_eq!(decoded, req);
        assert_eq!(decoded.data, data);

        let resp = WriteResponse::new(1234);
        let req_hdr = Smb2Header::new_request(command::WRITE, 5);
        let bytes = resp.encode(&req_hdr, ntstatus::STATUS_SUCCESS);
        let decoded = WriteResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn close_request_response_round_trips() {
        let file_id = FileId::new(5, 6);
        let req = CloseRequest::new(file_id);
        let bytes = req.encode(6, 0x100, 7);
        let decoded = CloseRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode req");
        assert_eq!(decoded, req);

        let resp = CloseResponse::new();
        let req_hdr = Smb2Header::new_request(command::CLOSE, 6);
        let bytes = resp.encode(&req_hdr, ntstatus::STATUS_SUCCESS);
        let decoded = CloseResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(decoded, resp);
    }

    // ---- Logoff / Echo round-trip ----

    #[test]
    fn logoff_round_trips() {
        let req = LogoffRequest;
        let bytes = req.encode(7, 0xDEAD_BEEF);
        let decoded = LogoffRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode req");
        assert_eq!(decoded, req);

        let req_hdr = Smb2Header::new_request(command::LOGOFF, 7);
        let resp = LogoffResponse;
        let bytes = resp.encode(&req_hdr);
        let decoded = LogoffResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn echo_round_trips() {
        let req = EchoRequest;
        let bytes = req.encode(8);
        let decoded = EchoRequest::decode(&bytes, SMB2_HEADER_SIZE).expect("decode req");
        assert_eq!(decoded, req);

        let req_hdr = Smb2Header::new_request(command::ECHO, 8);
        let resp = EchoResponse;
        let bytes = resp.encode(&req_hdr);
        let decoded = EchoResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode resp");
        assert_eq!(decoded, resp);
    }

    // ---- Preauth integrity SHA-512 ----

    #[test]
    fn preauth_hash_chains_sha512_correctly() {
        // MS-SMB2 §3.2.5.1: H_0 = 0^512 ; H_{i+1} = SHA-512(H_i || msg_i)
        // Verify against the canonical first step:
        //   H_1 = SHA-512(0^512 || b"hello")
        use sha2::{Digest, Sha512};
        let mut h1 = Sha512::new();
        h1.update([0u8; 64]);
        h1.update(b"hello");
        let expected = h1.finalize();

        let mut p = PreauthHash::new();
        p.update(b"hello");
        assert_eq!(p.current(), expected.as_slice());
    }

    #[test]
    fn preauth_hash_two_step_chain_matches_one_shot() {
        let mut p = PreauthHash::new();
        p.update(b"negotiate-request-bytes");
        p.update(b"negotiate-response-bytes");
        let chained = p.finalize();

        let one_shot = PreauthHash::compute(&[
            b"negotiate-request-bytes" as &[u8],
            b"negotiate-response-bytes" as &[u8],
        ]);
        assert_eq!(chained.as_slice(), one_shot.as_slice());
    }

    // ---- Transform header round-trip ----

    #[test]
    fn transform_header_round_trips() {
        let mut sig = [0u8; 16];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = 0xF0u8.wrapping_add(i as u8);
        }
        let hdr = TransformHeader {
            signature: sig,
            nonce,
            original_message_size: 1234,
            flags: 0x0001,
            session_id: 0xABCD_1234,
        };
        let mut out = Writer::new();
        hdr.encode(&mut out);
        assert_eq!(out.position(), 52);
        let decoded = TransformHeader::decode(out.as_bytes()).expect("decode");
        assert_eq!(decoded, hdr);
    }

    // ---- Wave 1: AES-256-GCM encryption ----

    /// Helper: build a deterministic 12-byte nonce for tests (production
    /// code MUST use a CSPRNG; this is a test-only fixture so the
    /// round-trip is reproducible).
    fn test_nonce(counter: u8) -> [u8; AES_256_GCM_NONCE_LEN] {
        [
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, counter,
        ]
    }

    #[test]
    fn wave1_encrypt_decrypt_pdu_round_trips() {
        // T-102 / T-103: encrypt_pdu followed by decrypt_pdu returns the
        // original plaintext byte-for-byte.
        let key = SmbEncryptionKey::for_test(0xA5);
        let plaintext = b"hello, encrypted SMB world!\n";
        let session_id = 0xCAFE_BABE_1234_5678u64;
        let frame = encrypt_pdu(&key, plaintext, session_id, test_nonce(1)).expect("encrypt ok");
        // Frame = 52-byte transform header + ciphertext (== plaintext len
        // for AES-GCM since the tag is stored in the Signature field).
        assert_eq!(frame.len(), SMB2_TRANSFORM_HEADER_SIZE + plaintext.len());
        let decoded = decrypt_pdu(&key, &frame).expect("decrypt ok");
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn wave1_tampered_ciphertext_is_rejected() {
        // T-106 negative path: flipping a single ciphertext byte MUST
        // surface a decrypt error (GCM tag verification failure).
        let key = SmbEncryptionKey::for_test(0x3C);
        let plaintext = b"sensitive payload";
        let mut frame = encrypt_pdu(&key, plaintext, 0x100, test_nonce(2)).expect("encrypt ok");
        // Flip the first ciphertext byte (just after the 52-byte header).
        frame[SMB2_TRANSFORM_HEADER_SIZE] ^= 0xFF;
        let err = decrypt_pdu(&key, &frame).expect_err("must reject tampered ciphertext");
        assert!(
            matches!(err, SmbError::Encryption(ref msg) if msg.contains("decrypt")),
            "expected Encryption error, got {err:?}"
        );
    }

    #[test]
    fn wave1_wrong_key_is_rejected() {
        // T-106 negative path: decrypting with a different key MUST fail
        // (the GCM tag was computed under the original key).
        let key_a = SmbEncryptionKey::for_test(0x01);
        let key_b = SmbEncryptionKey::for_test(0x02);
        let plaintext = b"confidential";
        let frame = encrypt_pdu(&key_a, plaintext, 0x200, test_nonce(3)).expect("encrypt ok");
        let err = decrypt_pdu(&key_b, &frame).expect_err("must reject wrong key");
        assert!(
            matches!(err, SmbError::Encryption(ref msg) if msg.contains("decrypt")),
            "expected Encryption error, got {err:?}"
        );
    }

    #[test]
    fn wave1_transform_header_round_trips_through_encrypt_decrypt() {
        // T-104: the TransformHeader emitted by encrypt_pdu round-trips
        // through TransformHeader::decode, carrying the right session id,
        // OriginalMessageSize, Flags, and nonce.
        let key = SmbEncryptionKey::for_test(0x77);
        let plaintext = b"round-trip through codec";
        let session_id = 0x1234_AAAA_BBBB_CCCCu64;
        let nonce = test_nonce(4);
        let frame = encrypt_pdu(&key, plaintext, session_id, nonce).expect("encrypt ok");
        let header = TransformHeader::decode(&frame).expect("decode header");
        // OriginalMessageSize matches the plaintext length.
        assert_eq!(header.original_message_size, plaintext.len() as u32);
        // Flags has bit 0x0001 (Encrypted) set.
        assert_ne!(header.flags & 0x0001, 0);
        // SessionId is carried through.
        assert_eq!(header.session_id, session_id);
        // Nonce: the low 12 bytes match the input nonce; the high 4
        // bytes are reserved and must be zero.
        assert_eq!(&header.nonce[..AES_256_GCM_NONCE_LEN], &nonce);
        assert_eq!(&header.nonce[AES_256_GCM_NONCE_LEN..], &[0u8; 4]);
        // Signature is non-zero (it holds the 16-byte GCM tag).
        assert!(header.signature.iter().any(|&b| b != 0));
    }

    #[test]
    fn wave1_negotiate_response_advertises_encryption_capability() {
        // T-105: NegotiateResponse::new_311 must set the
        // SMB2_GLOBAL_CAP_ENCRYPTION capability bit so that clients know
        // to encrypt PDUs on this session.
        let server_guid = uuid::Uuid::from_u128(0xAAAA_0000_0000_0000_0000_0000_0000_0001);
        let salt = [0xABu8; 16];
        let resp = NegotiateResponse::new_311(server_guid, &salt);
        assert_ne!(
            resp.capabilities & capabilities::ENCRYPTION,
            0,
            "NegotiateResponse must advertise SMB2_GLOBAL_CAP_ENCRYPTION"
        );
        // Round-trip through encode/decode to ensure the flag survives the wire.
        let req_hdr = Smb2Header::new_request(command::NEGOTIATE, 1);
        let bytes = resp.encode(&req_hdr);
        let decoded = NegotiateResponse::decode(&bytes, SMB2_HEADER_SIZE).expect("decode");
        assert_ne!(decoded.capabilities & capabilities::ENCRYPTION, 0);
    }

    // ---- SMB1 refused ----

    #[test]
    fn smb1_magic_is_detected_and_refused_at_header_decode() {
        let mut out = Writer::new();
        out.write_bytes(&SMB1_MAGIC);
        out.write_u16(64);
        out.write_bytes(&[0u8; 58]);
        let err = Smb2Header::decode(out.as_bytes()).expect_err("must refuse");
        assert!(matches!(err, SmbError::Smb1Refused), "got {err:?}");
    }

    // ---- NetBIOS framing ----

    #[test]
    fn netbios_frame_round_trips() {
        let payload = vec![0xABu8; 100];
        let frame = netbios::encode_frame(&payload);
        assert_eq!(frame.len(), 4 + 100);
        assert_eq!(frame[0], 0x00);
        assert_eq!(&frame[4..], &payload);
        let (frame_type, length) = netbios::peek_header(&frame)
            .expect("peek")
            .expect("some header");
        assert_eq!(frame_type, 0x00);
        assert_eq!(length, 100);
    }

    #[test]
    fn netbios_peek_header_returns_none_for_short_buffer() {
        let buf = [0u8; 2];
        let result = netbios::peek_header(&buf).expect("ok");
        assert!(result.is_none());
    }

    // ---- UTF-16LE helpers ----

    #[test]
    fn utf16le_round_trips_ascii() {
        let s = r"\server\share\file.txt";
        let bytes = encode_utf16le(s);
        let decoded = decode_utf16le(&bytes);
        assert_eq!(decoded, s);
    }

    #[test]
    fn utf16le_round_trips_non_ascii() {
        let s = "héllo wörld 中文";
        let bytes = encode_utf16le(s);
        let decoded = decode_utf16le(&bytes);
        assert_eq!(decoded, s);
    }

    // ---- Dialect / Command ----

    #[test]
    fn dialect_round_trips_through_wire_code() {
        for d in [
            Dialect::Smb202,
            Dialect::Smb210,
            Dialect::Smb300,
            Dialect::Smb302,
            Dialect::Smb311,
        ] {
            assert_eq!(Dialect::from_wire(d.to_wire()), Some(d));
        }
        assert_eq!(Dialect::from_wire(0xFFFF), None);
    }

    #[test]
    fn command_round_trips_through_wire_code() {
        for c in [
            Command::Negotiate,
            Command::SessionSetup,
            Command::Logoff,
            Command::TreeConnect,
            Command::TreeDisconnect,
            Command::Create,
            Command::Close,
            Command::Read,
            Command::Write,
            Command::Echo,
            Command::Transform,
        ] {
            assert_eq!(Command::from_wire(c.to_wire()), Some(c));
        }
        assert_eq!(Command::from_wire(0xFFFF), None);
    }

    // ---- Existing public API contracts ----

    #[test]
    fn dialect_equality_and_distinctness() {
        assert_eq!(Dialect::Smb311, Dialect::Smb311);
        assert_ne!(Dialect::Smb311, Dialect::Smb302);
        assert_ne!(Dialect::Smb202, Dialect::Smb311);
    }

    #[test]
    fn dialect_variants_cover_minimum_and_default() {
        let all = [
            Dialect::Smb202,
            Dialect::Smb210,
            Dialect::Smb300,
            Dialect::Smb302,
            Dialect::Smb311,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "variants {i} and {j} collide");
            }
        }
    }

    #[test]
    fn command_values_match_ms_smb2() {
        assert_eq!(Command::Negotiate as u16, 0x0000);
        assert_eq!(Command::SessionSetup as u16, 0x0001);
        assert_eq!(Command::TreeConnect as u16, 0x0003);
        assert_eq!(Command::TreeDisconnect as u16, 0x0004);
        assert_eq!(Command::Create as u16, 0x0005);
        assert_eq!(Command::Close as u16, 0x0006);
        assert_eq!(Command::Read as u16, 0x0008);
        assert_eq!(Command::Write as u16, 0x0009);
        assert_eq!(Command::Transform as u16, 0x00F2);
    }

    #[test]
    fn smb_error_malformed_display() {
        let err = SmbError::Malformed("short header".into());
        let msg = format!("{}", err);
        assert!(msg.contains("malformed"));
        assert!(msg.contains("short header"));
    }

    #[test]
    fn smb_error_status_display_hex() {
        let err = SmbError::Status(0xC000_0022);
        let msg = format!("{}", err);
        assert!(msg.contains("status:"));
        assert!(msg.contains("0xc0000022"));
    }

    #[test]
    fn smb_error_dialect_unsupported_display() {
        let err = SmbError::DialectUnsupported;
        assert_eq!(format!("{}", err), "dialect unsupported");
    }

    #[test]
    fn smb_error_smb1_refused_display() {
        let err = SmbError::Smb1Refused;
        let msg = format!("{}", err);
        assert!(msg.contains("smb1 refused"));
    }

    #[test]
    fn file_id_zero_predicate_works() {
        assert!(FileId::ZERO.is_zero());
        assert!(!FileId::new(1, 0).is_zero());
        assert!(!FileId::new(0, 1).is_zero());
    }
}
