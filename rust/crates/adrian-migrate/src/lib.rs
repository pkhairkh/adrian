//! # adrian-migrate
//!
//! Migration tooling — `audit-ntlm`, `plan-ntlm`, `sidhistory`, `passwords`,
//! `sysvol`. Used during parallel-run AD → framework migration.
//!
//! ## ADRs
//!
//! - ADR-126: sIDHistory injection/migration
//! - ADR-127: GPO translation
//! - ADR-128: Kerberos cross-realm migration
//! - ADR-129: Password hash migration
//! - ADR-130: SYSVOL migration
//! - ADR-086: Pass-the-hash defense (NTLM audit)
//! - ADR-122: DCSync mitigation (audit during migration)
//! - ADR-124: sIDHistory injection mitigation

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("source ad: {0}")]
    SourceAd(String),
    #[error("target framework: {0}")]
    TargetFramework(String),
    #[error("validation: {0}")]
    Validation(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// NTLM audit configuration.
#[derive(Clone, Debug)]
pub struct NtlmAuditConfig {
    pub source_dc: String,
    pub window_hours: u32,
}

/// Run the NTLM audit pass (per ADR-086).
pub async fn audit_ntlm(_config: &NtlmAuditConfig) -> Result<(), MigrationError> {
    // TODO: scrape DC event logs, classify NTLM auth events
    Err(MigrationError::SourceAd("not yet implemented".into()))
}

/// Plan NTLM phase-out (per ADR-086 + ADR-011).
pub async fn plan_ntlm(_config: &NtlmAuditConfig) -> Result<(), MigrationError> {
    Err(MigrationError::Validation("not yet implemented".into()))
}

/// sIDHistory migration (per ADR-126 + ADR-124).
pub async fn migrate_sidhistory(_source: &str, _target: &str) -> Result<(), MigrationError> {
    Err(MigrationError::SourceAd("not yet implemented".into()))
}

/// Password hash migration (per ADR-129).
pub async fn migrate_passwords(_source: &str, _target: &str) -> Result<(), MigrationError> {
    Err(MigrationError::SourceAd("not yet implemented".into()))
}

/// SYSVOL migration (per ADR-130).
pub async fn migrate_sysvol(_source: &str, _target: &str) -> Result<(), MigrationError> {
    Err(MigrationError::SourceAd("not yet implemented".into()))
}

/// Kerberos cross-realm migration (per ADR-128).
pub async fn migrate_kerberos(_source: &str, _target: &str) -> Result<(), MigrationError> {
    Err(MigrationError::SourceAd("not yet implemented".into()))
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-migrate`. Per the task instructions these
    //! cover type construction (`NtlmAuditConfig`), error variants, the
    //! `#[from] std::io::Error` conversion, and the loud-stub behaviour of
    //! each migration entry point — no real AD source / FDB target is
    //! contacted.

    use super::*;

    #[test]
    fn migration_error_variants_render_messages() {
        // Every `#[error("…")]` template must render — catches regressions
        // in the format strings surfaced to the operator running
        // `adrian migrate …` (ADR-086 / ADR-126 / ADR-129 / ADR-130).
        assert_eq!(
            MigrationError::SourceAd("dc01 unreachable".into()).to_string(),
            "source ad: dc01 unreachable"
        );
        assert_eq!(
            MigrationError::TargetFramework("fdb write rejected".into()).to_string(),
            "target framework: fdb write rejected"
        );
        assert_eq!(
            MigrationError::Validation("sIDHistory collision on S-1-5-21-…-1013".into())
                .to_string(),
            "validation: sIDHistory collision on S-1-5-21-…-1013"
        );
        assert_eq!(
            MigrationError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "sysvol"))
                .to_string(),
            "io: sysvol"
        );
    }

    #[test]
    fn migration_error_io_conversion_preserves_kind() {
        // `MigrationError::Io(#[from] std::io::Error)` — exercising the
        // conversion guards the `?` ergonomics used by future SYSVOL
        // migration code (ADR-130). We also verify the underlying kind is
        // preserved so callers can dispatch on `ErrorKind` for retry.
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let migrate_err: MigrationError = io_err.into();
        match migrate_err {
            MigrationError::Io(inner) => {
                assert_eq!(inner.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(inner.to_string().contains("denied"));
            }
            other => panic!("expected MigrationError::Io, got {other:?}"),
        }
    }

    #[test]
    fn ntlm_audit_config_constructs_with_expected_fields() {
        // The NTLM audit config drives both `audit_ntlm` and `plan_ntlm`.
        // Verifying field propagation guards the seam used by the CLI's
        // `adrian migrate audit-ntlm` subcommand (ADR-086).
        let config = NtlmAuditConfig {
            source_dc: "dc01.adrian.dev".into(),
            window_hours: 168, // 7-day audit window
        };
        assert_eq!(config.source_dc, "dc01.adrian.dev");
        assert_eq!(config.window_hours, 168);
    }

    #[test]
    fn audit_ntlm_stub_returns_source_ad_error() {
        // Loud-stub contract (ADR-086): until DC event-log scraping is
        // implemented, `audit_ntlm` must surface `MigrationError::SourceAd`
        // rather than silently succeed or panic.
        let config = NtlmAuditConfig {
            source_dc: "dc01".into(),
            window_hours: 24,
        };
        let rt = tokio::runtime::Runtime::new().expect("build runtime");
        let err = rt
            .block_on(audit_ntlm(&config))
            .expect_err("expected MigrationError::SourceAd");
        match err {
            MigrationError::SourceAd(msg) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            other => panic!("expected MigrationError::SourceAd, got {other:?}"),
        }
    }

    #[test]
    fn all_migration_entry_points_return_loud_stub_errors() {
        // Every unimplemented migration entry point must surface a
        // documented `MigrationError` variant (no silent Ok, no panic).
        // This is the framework-wide loud-stub convention — catching
        // regressions here guards the entire `adrian migrate` CLI surface.
        let rt = tokio::runtime::Runtime::new().expect("build runtime");
        // `plan_ntlm` → Validation (per ADR-086 + ADR-011).
        let config = NtlmAuditConfig {
            source_dc: "dc01".into(),
            window_hours: 24,
        };
        match rt.block_on(plan_ntlm(&config)) {
            Err(MigrationError::Validation(msg)) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            other => panic!("plan_ntlm: expected Validation, got {other:?}"),
        }
        // `migrate_sidhistory` → SourceAd (per ADR-126 + ADR-124).
        match rt.block_on(migrate_sidhistory("src", "tgt")) {
            Err(MigrationError::SourceAd(msg)) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            other => panic!("migrate_sidhistory: expected SourceAd, got {other:?}"),
        }
        // `migrate_passwords` → SourceAd (per ADR-129).
        match rt.block_on(migrate_passwords("src", "tgt")) {
            Err(MigrationError::SourceAd(msg)) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            other => panic!("migrate_passwords: expected SourceAd, got {other:?}"),
        }
        // `migrate_sysvol` → SourceAd (per ADR-130).
        match rt.block_on(migrate_sysvol("src", "tgt")) {
            Err(MigrationError::SourceAd(msg)) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            other => panic!("migrate_sysvol: expected SourceAd, got {other:?}"),
        }
        // `migrate_kerberos` → SourceAd (per ADR-128).
        match rt.block_on(migrate_kerberos("src", "tgt")) {
            Err(MigrationError::SourceAd(msg)) => {
                assert!(msg.contains("not yet implemented"), "got: {msg}")
            }
            other => panic!("migrate_kerberos: expected SourceAd, got {other:?}"),
        }
    }
}
