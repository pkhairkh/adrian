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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `InteropTarget` variant must be `Clone + Copy` — the matrix
    /// runner fans them out across the KDC pool (ADR-018) and a single
    /// target value may be referenced by multiple concurrent test cases.
    #[test]
    fn interop_target_is_clone_copy() {
        // Compile-time bound assertions — if a future refactor drops
        // `Copy` or `Clone` from the derive list, this test fails to build.
        fn _assert_copy<T: Copy>() {}
        fn _assert_clone<T: Clone>() {}
        _assert_copy::<InteropTarget>();
        _assert_clone::<InteropTarget>();

        let a = InteropTarget::MitKrb5_1_21;
        let b = a; // Copy
        let c = b; // Copy again — `a` is still usable (Copy, not move).
                   // The variants must also be Debug-printable for the test reporter.
        assert!(format!("{a:?} {b:?} {c:?}").contains("MitKrb5"));
    }

    /// The four documented interop targets (ADR-018 / ADR-082 / ADR-013)
    /// cover the MS-KILE conformance matrix. This test pins the variant
    /// set so a later wave cannot silently drop a target.
    #[test]
    fn interop_target_variants_are_documented_set() {
        let targets = [
            InteropTarget::MitKrb5_1_21,
            InteropTarget::Heimdal7,
            InteropTarget::WindowsServer2022,
            InteropTarget::FreeIPA4_10,
        ];
        // Four targets, each with a distinct Debug name.
        let names: Vec<String> = targets.iter().map(|t| format!("{t:?}")).collect();
        let unique: std::collections::HashSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), 4, "interop target variants must be distinct");
    }

    /// `InteropError::TargetUnavailable` Display formatting must be stable
    /// — it is surfaced to the CI matrix runner.
    #[test]
    fn interop_error_target_unavailable_display() {
        let err = InteropError::TargetUnavailable("mit krb5 container down".into());
        assert_eq!(
            err.to_string(),
            "interop target unavailable: mit krb5 container down"
        );
    }

    /// `InteropError::WireMismatch` Display formatting — surfaced when
    /// ADR-082 byte-identity modulo divergences fails.
    #[test]
    fn interop_error_wire_mismatch_display() {
        let err = InteropError::WireMismatch("PAC_LOGON_INFO buffer length differs".into());
        assert_eq!(
            err.to_string(),
            "wire mismatch: PAC_LOGON_INFO buffer length differs"
        );
    }

    /// `run_pac_byte_identity` is a loud stub until the interop test driver
    /// is wired (Wave 4b). It must return `TargetUnavailable`, not panic.
    #[tokio::test]
    async fn run_pac_byte_identity_returns_target_unavailable() {
        let res = run_pac_byte_identity(InteropTarget::WindowsServer2022).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            InteropError::TargetUnavailable(msg) => {
                assert!(msg.contains("not yet implemented"));
            }
            other => panic!("expected TargetUnavailable, got {other:?}"),
        }
    }

    /// `run_as_exchange_matrix` is also a loud stub returning
    /// `TargetUnavailable` until the wire-compat driver lands.
    #[tokio::test]
    async fn run_as_exchange_matrix_returns_target_unavailable() {
        let res = run_as_exchange_matrix(InteropTarget::MitKrb5_1_21).await;
        assert!(res.is_err());
        match res.unwrap_err() {
            InteropError::TargetUnavailable(msg) => {
                assert!(msg.contains("not yet implemented"));
            }
            other => panic!("expected TargetUnavailable, got {other:?}"),
        }
    }

    /// Each documented interop target must drive the PAC byte-identity
    /// stub and surface the same `TargetUnavailable` error. This guards
    /// against an enum exhaustiveness bug where one variant accidentally
    /// short-circuits to `WireMismatch`.
    #[tokio::test]
    async fn pac_byte_identity_stub_is_uniform_across_targets() {
        let targets = [
            InteropTarget::MitKrb5_1_21,
            InteropTarget::Heimdal7,
            InteropTarget::WindowsServer2022,
            InteropTarget::FreeIPA4_10,
        ];
        for t in targets {
            let res = run_pac_byte_identity(t).await;
            assert!(
                matches!(res, Err(InteropError::TargetUnavailable(_))),
                "target {t:?} did not surface TargetUnavailable"
            );
        }
    }
}
