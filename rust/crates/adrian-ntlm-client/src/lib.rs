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

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-NLMP §2.2 pins the three message type numbers; these are wire-
    /// stable and used in the type-3 AUTHENTICATE message's "message type"
    /// field, so any drift would break interop with Windows / MIT / Samba.
    #[test]
    fn ntlm_message_type_constants() {
        assert_eq!(NtlmMessageType::Negotiate as u8, 1);
        assert_eq!(NtlmMessageType::Challenge as u8, 2);
        assert_eq!(NtlmMessageType::Authenticate as u8, 3);
    }

    /// The three `NtlmMessageType` variants must round-trip through `Copy`
    /// and `Clone` — the client code passes the current type through several
    /// async boundaries.
    #[test]
    fn ntlm_message_type_is_copy_and_distinct() {
        // Compile-time bound assertions — if a future refactor drops
        // `Copy` or `Clone` from the derive list, this test fails to build.
        fn _assert_copy<T: Copy>() {}
        fn _assert_clone<T: Clone>() {}
        _assert_copy::<NtlmMessageType>();
        _assert_clone::<NtlmMessageType>();

        let a = NtlmMessageType::Negotiate;
        let b = a; // Copy
                   // Distinct Debug names so the wire codec can switch on them.
        let names: Vec<String> = [
            NtlmMessageType::Negotiate,
            NtlmMessageType::Challenge,
            NtlmMessageType::Authenticate,
        ]
        .iter()
        .map(|t| format!("{t:?}"))
        .collect();
        let unique: std::collections::HashSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), 3);
        // `b` must still be usable after the copy (Copy, not move).
        assert_eq!(b as u8, 1);
    }

    /// `NtlmClient::new()` and `NtlmClient::default()` must both succeed —
    /// the client is constructed lazily from the platform credential cache
    /// at first use, so an empty construction must always work.
    #[test]
    fn ntlm_client_default_equals_new() {
        let _a = NtlmClient::new();
        let _b = NtlmClient::default();
    }

    /// `build_negotiate` is a loud stub (ADR-085) — must surface
    /// `NtlmError::Protocol`, not panic. Until MS-NLMP §2.2.1.1 is
    /// implemented, callers rely on the typed error to fall back to
    /// Kerberos (ADR-088).
    #[test]
    fn build_negotiate_returns_protocol_not_implemented() {
        let client = NtlmClient::new();
        let res = client.build_negotiate();
        assert!(res.is_err(), "build_negotiate must surface a typed error");
        match res.unwrap_err() {
            NtlmError::Protocol(msg) => assert!(msg.contains("not yet implemented")),
            other => panic!("expected NtlmError::Protocol, got {other:?}"),
        }
    }

    /// `build_authenticate` is a loud stub — must surface
    /// `NtlmError::Protocol`. Channel binding (ADR-021) is mandatory at
    /// the call site but the type-3 message itself is not yet emitted.
    #[test]
    fn build_authenticate_returns_protocol_not_implemented() {
        let client = NtlmClient::new();
        // Synthetic 8-byte challenge — the stub doesn't read it.
        let challenge = [0u8; 8];
        let cb: Option<&[u8]> = Some(&[0u8; 32]);
        let res = client.build_authenticate(&challenge, cb);
        assert!(res.is_err());
        match res.unwrap_err() {
            NtlmError::Protocol(msg) => assert!(msg.contains("not yet implemented")),
            other => panic!("expected NtlmError::Protocol, got {other:?}"),
        }
    }

    /// `build_authenticate` must accept `None` for channel binding without
    /// panicking — even though ADR-021 mandates channel binding at the
    /// LDAP layer, the type-3 builder itself must remain well-defined for
    /// callers that have not yet computed the bindings hash.
    #[test]
    fn build_authenticate_accepts_no_channel_binding() {
        let client = NtlmClient::new();
        let challenge = [0u8; 8];
        let res = client.build_authenticate(&challenge, None);
        assert!(matches!(res, Err(NtlmError::Protocol(_))));
    }

    /// Verify the `Display` impls of `NtlmError` — these surface in LDAP
    /// / SMB client diagnostics, so the strings are stable.
    #[test]
    fn ntlm_error_display_messages() {
        assert_eq!(
            NtlmError::Protocol("bad signature".into()).to_string(),
            "protocol: bad signature"
        );
        assert_eq!(
            NtlmError::AuthFailed("wrong password".into()).to_string(),
            "auth failed: wrong password"
        );
        assert_eq!(
            NtlmError::ChannelBindingRequired.to_string(),
            "channel binding required (ADR-021)"
        );
        assert_eq!(
            NtlmError::CredentialsUnavailable.to_string(),
            "credentials unavailable"
        );
    }
}
