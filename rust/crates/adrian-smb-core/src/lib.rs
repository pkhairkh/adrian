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
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialect_equality_and_distinctness() {
        // Per ADR-043: SMB 3.1.1 is the default dialect. Dialects must be
        // PartialEq/Eq so negotiate responses can match the highest common
        // dialect.
        assert_eq!(Dialect::Smb311, Dialect::Smb311);
        assert_ne!(Dialect::Smb311, Dialect::Smb302);
        assert_ne!(Dialect::Smb202, Dialect::Smb311);
    }

    #[test]
    fn dialect_variants_cover_minimum_and_default() {
        // Per ADR-043: SMB 2.0.2 minimum (Smb202), 3.1.1 default (Smb311).
        let all = [
            Dialect::Smb202,
            Dialect::Smb210,
            Dialect::Smb300,
            Dialect::Smb302,
            Dialect::Smb311,
        ];
        // Distinct pairwise — no two variants compare equal.
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "variants {} and {} collide", i, j);
            }
        }
    }

    #[test]
    fn command_values_match_ms_smb2() {
        // Per MS-SMB2 §2.2.1.1 (Command field). Sanity-check the
        // repr(u16) values so wire codecs stay stable across releases.
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
        assert!(msg.contains("malformed"), "msg={}", msg);
        assert!(msg.contains("short header"), "msg={}", msg);
    }

    #[test]
    fn smb_error_status_display_hex() {
        // Per MS-SMB2 §2.2.1.4 — NT status codes are printed in hex.
        let err = SmbError::Status(0xC000_0022); // STATUS_ACCESS_DENIED
        let msg = format!("{}", err);
        assert!(msg.contains("status:"), "msg={}", msg);
        assert!(msg.contains("0xc0000022"), "msg={}", msg);
    }

    #[test]
    fn smb_error_dialect_unsupported_display() {
        let err = SmbError::DialectUnsupported;
        let msg = format!("{}", err);
        assert_eq!(msg, "dialect unsupported");
    }

    #[test]
    fn negotiate_request_construction() {
        // A typical client offers SMB 3.0.2 and 3.1.1; the server picks the
        // highest dialect both support (per MS-SMB2 §3.3.5.4 / ADR-043).
        let req = NegotiateRequest {
            dialects: vec![Dialect::Smb302, Dialect::Smb311],
        };
        assert_eq!(req.dialects.len(), 2);
        assert_eq!(req.dialects[1], Dialect::Smb311);
    }

    #[test]
    fn negotiate_request_supports_legacy_only_offers() {
        // Per ADR-043, SMB1 is dropped — but a client may still offer only
        // SMB 2.0.2 (Smb202) and the server-side negotiate handler will
        // accept it as the minimum supported dialect.
        let req = NegotiateRequest {
            dialects: vec![Dialect::Smb202],
        };
        assert_eq!(req.dialects, vec![Dialect::Smb202]);
    }

    #[test]
    fn encode_negotiate_returns_malformed() {
        // Wire codec is not yet implemented (TODO rasn-backed). Until then
        // encode_negotiate MUST surface Malformed rather than Ok with empty
        // bytes — clients must not mistake an empty payload for a valid
        // NEGOTIATE message.
        let req = NegotiateRequest {
            dialects: vec![Dialect::Smb311],
        };
        let result = encode_negotiate(&req);
        let err = result.expect_err("encode_negotiate should return Malformed");
        assert!(matches!(err, SmbError::Malformed(_)), "{:?}", err);
    }

    #[test]
    fn decode_negotiate_returns_malformed_for_empty_input() {
        let result = decode_negotiate(&[]);
        let err = result.expect_err("decode_negotiate should return Malformed");
        assert!(matches!(err, SmbError::Malformed(_)), "{:?}", err);
    }

    #[test]
    fn decode_negotiate_returns_malformed_for_arbitrary_bytes() {
        // Even non-empty garbage bytes can't be decoded yet — the stub
        // rejects all input with Malformed.
        let bytes = [0xFE, 0x53, 0x4D, 0x42, 0x00, 0x00, 0x00, 0x00];
        let result = decode_negotiate(&bytes);
        let err = result.expect_err("decode_negotiate should return Malformed");
        assert!(matches!(err, SmbError::Malformed(_)), "{:?}", err);
    }
}
