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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_and_default_construct_without_state() {
        // Per ADR-107 / ADR-106: the SMB client is constructed by the SDK
        // FileModule. `new()` and `default()` must yield a usable handle
        // (today, a zero-state struct) without touching the network.
        let a = SmbClient::new();
        let b = SmbClient::default();
        let _ = (a, b);
    }

    #[tokio::test]
    async fn connect_returns_loud_connect_error() {
        // Loud stub convention — `connect` is not yet wired to TCP+TLS, so
        // it MUST surface `SmbClientError::Connect` (the documented variant
        // for connection-level failures). Returning Ok(()) would silently
        // mislead the SDK FileModule into believing a session is open.
        let client = SmbClient::new();
        let err = client
            .connect("dc01.adrian.example", "sysvol")
            .await
            .expect_err("connect must surface Connect until implemented");
        assert!(matches!(err, SmbClientError::Connect(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn open_returns_loud_share_error() {
        // ADR-106: durable/persistent handle open is implemented later. The
        // stub MUST surface `Share` (the variant documented for tree-level
        // failures) rather than fabricating a handle id, so callers never
        // mistake a stub for a real FileId.
        let client = SmbClient::new();
        let err = client
            .open(r"\adrian\sysvol\policy.gpo")
            .await
            .expect_err("open must surface Share until implemented");
        assert!(matches!(err, SmbClientError::Share(_)), "got {:?}", err);
    }

    #[test]
    fn io_error_converts_via_from() {
        // `SmbClientError::Io(#[from] std::io::Error)` — the `?` operator
        // must transparently lift I/O errors (read/write on the TCP+TLS
        // stream) into the client's error enum. Per ADR-106.
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "rst by peer");
        let smb_err: SmbClientError = io_err.into();
        match smb_err {
            SmbClientError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
            }
            other => panic!("expected Io, got {:?}", other),
        }
    }

    #[test]
    fn error_variants_render_expected_prefixes() {
        // Display strings are part of the public diagnostic contract —
        // SDK FileModule maps them to platform-native error codes.
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
        let io = SmbClientError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        ));
        let msg = format!("{}", io);
        assert!(msg.starts_with("io: "), "msg={}", msg);
        assert!(msg.contains("eof"), "msg={}", msg);
    }
}
