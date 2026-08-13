//! # adrian-kdc-interop
//!
//! MS-KILE conformance tests against MIT krb5 1.21+, Heimdal 7.x+, and
//! Windows Server 2022+. Dev-dependency only — drives `tests/interop/`.
//!
//! ## ADRs
//!
//! - ADR-082: PAC byte-identity modulo two documented divergences
//!   (LogonServer name, PAC_REQUESTOR machine SID format)
//! - ADR-018: KDC horizontal scaling — interop validation across pool
//! - ADR-013: Cross-realm TGT referral interop

use thiserror::Error;

#[derive(Debug, Error)]
pub enum InteropError {
    #[error("interop target unavailable: {0}")]
    TargetUnavailable(String),
    #[error("wire mismatch: {0}")]
    WireMismatch(String),
}

/// Interop test matrix targets.
#[derive(Clone, Copy, Debug)]
pub enum InteropTarget {
    MitKrb5_1_21,
    Heimdal7,
    WindowsServer2022,
    FreeIPA4_10,
}

/// Run the PAC byte-identity test (ADR-082) — captures a Windows-issued PAC
/// and a framework-issued PAC for the same principal; verifies byte-identity
/// modulo the two documented divergences.
pub async fn run_pac_byte_identity(_target: InteropTarget) -> Result<(), InteropError> {
    // TODO: implement interop test driver
    Err(InteropError::TargetUnavailable(
        "not yet implemented".into(),
    ))
}

/// Run the AS-REQ/AS-REP wire-compat test matrix.
pub async fn run_as_exchange_matrix(_target: InteropTarget) -> Result<(), InteropError> {
    Err(InteropError::TargetUnavailable(
        "not yet implemented".into(),
    ))
}
