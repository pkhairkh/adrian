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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_new_and_default_are_equivalent() {
        // Per ADR-105: SmbServer is constructed once per accept loop. Both
        // `new()` and `default()` must yield a ready-to-serve instance; the
        // Default impl exists so the server can be plugged into generic
        // service launchers.
        let a = SmbServer::new();
        let b = SmbServer::default();
        // Both must be constructible without panicking — the only state they
        // hold (today) is none, so any panic would be a regression.
        let _ = (a, b);
    }

    #[tokio::test]
    async fn serve_returns_loud_protocol_error() {
        // Per the framework's "loud stub" convention: every unimplemented
        // method must surface a typed error variant rather than panic or
        // silently succeed. `serve` is not yet wired to bind TCP/445, so it
        // MUST return `SmbServerError::Protocol` (the variant documented for
        // SMB-protocol-level failures). ADR-105 / ADR-043.
        let server = SmbServer::new();
        let err = server
            .serve()
            .await
            .expect_err("serve must surface Protocol until implemented");
        assert!(matches!(err, SmbServerError::Protocol(_)), "got {:?}", err);
    }

    #[test]
    fn error_variants_render_expected_prefixes() {
        // Display strings are part of the public diagnostic contract — logs,
        // CLI output, and audit entries key off these prefixes.
        let protocol = SmbServerError::Protocol("negotiate dialect mismatch".into());
        assert_eq!(
            format!("{}", protocol),
            "protocol: negotiate dialect mismatch"
        );

        let auth = SmbServerError::Auth("invalid signature".into());
        assert_eq!(format!("{}", auth), "auth: invalid signature");

        let storage = SmbServerError::Storage("fdb transaction retry exhausted".into());
        assert_eq!(
            format!("{}", storage),
            "storage: fdb transaction retry exhausted"
        );

        let share = SmbServerError::ShareNotFound("SYSVOL".into());
        assert_eq!(format!("{}", share), "share not found: SYSVOL");
    }

    #[test]
    fn error_variants_are_distinct_debug_representations() {
        // Error variants must remain distinguishable in Debug output so that
        // `tracing` spans and error reporters can route them correctly.
        let variants = [
            SmbServerError::Protocol("p".into()),
            SmbServerError::Auth("a".into()),
            SmbServerError::Storage("s".into()),
            SmbServerError::ShareNotFound("shr".into()),
        ];
        let debugs: Vec<String> = variants.iter().map(|e| format!("{:?}", e)).collect();
        let unique: std::collections::HashSet<_> = debugs.iter().collect();
        assert_eq!(
            unique.len(),
            variants.len(),
            "error variant Debug reprs collided: {:?}",
            debugs
        );
    }

    #[test]
    fn share_not_found_variant_is_unit_like_in_match() {
        // Per ADR-105 + ADR-094 (SYSVOL git-backed replication), missing
        // shares must surface as `ShareNotFound` — not the generic Storage
        // variant — so the SDK FileModule can map them to a distinct
        // client-facing error code.
        let err = SmbServerError::ShareNotFound("netlogon".into());
        match err {
            SmbServerError::ShareNotFound(name) => assert_eq!(name, "netlogon"),
            other => panic!("expected ShareNotFound, got {:?}", other),
        }
    }
}
