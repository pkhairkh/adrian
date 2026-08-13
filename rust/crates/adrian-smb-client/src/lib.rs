//! # adrian-smb-client
//!
//! SMB client — backs the SDK's `FileModule`. Persistent handles (resilient
//! open) per ADR-106; used by the SDK's macOS/Windows/Linux FileModule.
//!
//! ## ADRs
//!
//! - ADR-106: SMB client persistent handles (SDK FileModule)
//! - ADR-043: SMB1 dropped; SMB 2.0.2 minimum, 3.1.1 default
//! - ADR-107: Unified Rust core SDK (this client is the SDK's SMB backend)
//! - ADR-044: DFS-N via DNS SRV records (referral-aware client)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmbClientError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("share: {0}")]
    Share(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// SMB client session.
pub struct SmbClient {
    // TODO: hold tokio TCP+TLS stream, session table
}

impl SmbClient {
    pub fn new() -> Self {
        Self {}
    }

    /// Connect to `\\server\share` with persistent handle support (ADR-106).
    pub async fn connect(&self, _server: &str, _share: &str) -> Result<(), SmbClientError> {
        // TODO: implement negotiate + session setup + tree connect
        Err(SmbClientError::Connect("not yet implemented".into()))
    }

    /// Open a file with a durable handle.
    pub async fn open(&self, _path: &str) -> Result<u64, SmbClientError> {
        // TODO: implement SMB2 CREATE with durable flag
        Err(SmbClientError::Share("not yet implemented".into()))
    }
}

impl Default for SmbClient {
    fn default() -> Self {
        Self::new()
    }
}
