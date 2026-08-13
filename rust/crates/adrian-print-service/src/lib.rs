//! # adrian-print-service
//!
//! IPP Everywhere print service (RFC 8011). Replaces MS-RPRN; integrates with
//! CUPS on Linux/macOS and the Windows print spooler via IPP driver model.
//!
//! ## ADRs
//!
//! - ADR-046: Drop MS-RPRN; adopt IPP Everywhere
//! - ADR-047: Offline files out of scope (print not affected)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrintError {
    #[error("ipp: {0}")]
    Ipp(String),
    #[error("printer not found: {0}")]
    PrinterNotFound(String),
    #[error("spooler: {0}")]
    Spooler(String),
}

/// IPP Everywhere print service.
pub struct PrintService {
    // TODO: hold printer registry, IPP request router
}

impl PrintService {
    pub fn new() -> Self {
        Self {}
    }

    /// Build the IPP axum router (RFC 8011 endpoints).
    pub fn router(&self) -> axum::Router {
        // TODO: wire IPP operations: Print-Job, Get-Jobs, Get-Printer-Attributes, etc.
        axum::Router::new()
    }
}

impl Default for PrintService {
    fn default() -> Self {
        Self::new()
    }
}
