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
