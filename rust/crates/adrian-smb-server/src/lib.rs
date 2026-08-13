//! # adrian-smb-server
//!
//! Fresh Rust SMB 3.1.1 server (memory-safe, async, tokio-native). Replaces
//! Samba's `smbd` in AD-interop mode and is the only SMB server in native mode.
//!
//! ## ADRs
//!
//! - ADR-043: Drop SMB1; SMB 2.0.2 minimum, 3.1.1 default
//! - ADR-044: DFS-N via DNS SRV records
//! - ADR-045: ABE precomputed index
//! - ADR-105: Fresh Rust SMB 3.1.1 server (memory-safe, async)
//! - ADR-094: SYSVOL replication (Git-backed) consumed by this server
//! - ADR-123: Silver ticket mitigation (PAC validation on every accept)
//! - ADR-021: LDAP signing & channel binding (SMB signing required)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmbServerError {
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("share not found: {0}")]
    ShareNotFound(String),
}

/// SMB 3.1.1 server.
pub struct SmbServer {
    // TODO: hold Arc<FdbDirectoryStore>, Arc<SmbShareRegistry>, rustls acceptor
}

impl SmbServer {
    pub fn new() -> Self {
        Self {}
    }

    /// Bind TCP/445 and serve until shutdown.
    pub async fn serve(&self) -> Result<(), SmbServerError> {
        // TODO: implement SMB 3.1.1 negotiation, session setup, tree connect
        Err(SmbServerError::Protocol("not yet implemented".into()))
    }
}

impl Default for SmbServer {
    fn default() -> Self {
        Self::new()
    }
}
