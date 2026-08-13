//! # adrian-smb-core
//!
//! SMB 3.1.1 protocol primitives shared by `adrian-smb-server` and
//! `adrian-smb-client`. Wire codecs via `rasn`; no I/O.
//!
//! ## ADRs
//!
//! - ADR-043: Drop SMB1; SMB 2.0.2 minimum, 3.1.1 default
//! - ADR-105: Fresh Rust SMB 3.1.1 server (memory-safe, async)
//! - ADR-106: SMB client with persistent handles (SDK FileModule)

use thiserror::Error;

/// SMB dialect revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Smb202,
    Smb210,
    Smb300,
    Smb302,
    Smb311,
}

/// SMB command code (subset).
#[derive(Clone, Copy, Debug)]
#[repr(u16)]
pub enum Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Read = 0x0008,
    Write = 0x0009,
    Transform = 0x00F2,
}

#[derive(Debug, Error)]
pub enum SmbError {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("status: {0:#x}")]
    Status(u32),
    #[error("dialect unsupported")]
    DialectUnsupported,
}

/// SMB2 NEGOTIATE request (decoded).
pub struct NegotiateRequest {
    pub dialects: Vec<Dialect>,
}

/// Encode/decode helpers. TODO: full rasn-backed wire codecs.
pub fn encode_negotiate(_req: &NegotiateRequest) -> Result<Vec<u8>, SmbError> {
    Err(SmbError::Malformed("not yet implemented".into()))
}

pub fn decode_negotiate(_bytes: &[u8]) -> Result<NegotiateRequest, SmbError> {
    Err(SmbError::Malformed("not yet implemented".into()))
}
