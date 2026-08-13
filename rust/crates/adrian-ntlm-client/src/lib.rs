//! # adrian-ntlm-client
//!
//! NTLM client-only (NTLMv2 with channel binding). No server-side NTLM —
//! pass-the-hash mitigation (ADR-086). Gated by `ad-interop` feature.
//!
//! ## ADRs
//!
//! - ADR-085: NTLM client-only Rust crate
//! - ADR-086: Pass-the-hash defense (no server-side NTLM)
//! - ADR-112: macOS NTLM client Rust crate
//! - ADR-021: LDAP signing & channel binding
//! - ADR-011: RC4 disabled; NTLMv2-only

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NtlmError {
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("auth failed: {0}")]
    AuthFailed(String),
    #[error("channel binding required (ADR-021)")]
    ChannelBindingRequired,
    #[error("credentials unavailable")]
    CredentialsUnavailable,
}

/// NTLM message types (MS-NLMP §2.2).
#[derive(Clone, Copy, Debug)]
pub enum NtlmMessageType {
    Negotiate = 1,
    Challenge = 2,
    Authenticate = 3,
}

/// NTLM client session.
pub struct NtlmClient {
    // TODO: hold workstation, domain, credential handle
}

impl NtlmClient {
    pub fn new() -> Self {
        Self {}
    }

    /// Build NEGOTIATE message (type 1, MS-NLMP §2.2.1.1).
    pub fn build_negotiate(&self) -> Result<Vec<u8>, NtlmError> {
        // TODO: implement
        Err(NtlmError::Protocol("not yet implemented".into()))
    }

    /// Process CHALLENGE (type 2) and produce AUTHENTICATE (type 3) with
    /// NTLMv2 response and channel binding (ADR-021).
    pub fn build_authenticate(
        &self,
        _challenge: &[u8],
        _channel_binding: Option<&[u8]>,
    ) -> Result<Vec<u8>, NtlmError> {
        // TODO: implement NTLMv2 + MIC + channel binding
        Err(NtlmError::Protocol("not yet implemented".into()))
    }
}

impl Default for NtlmClient {
    fn default() -> Self {
        Self::new()
    }
}
