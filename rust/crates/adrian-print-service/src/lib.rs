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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_new_and_default_construct_without_state() {
        // Per ADR-046: PrintService replaces MS-RPRN with IPP Everywhere.
        // Both `new()` and `default()` must yield a ready-to-serve instance
        // (today a zero-state struct) so it can be embedded in an axum
        // server or a tokio task without conditional construction logic.
        let a = PrintService::new();
        let b = PrintService::default();
        let _ = (a, b);
    }

    #[test]
    fn router_returns_empty_but_not_panic() {
        // Per ADR-046: the IPP axum router is wired lazily — today the stub
        // returns an empty `Router` (no RFC 8011 operations attached yet).
        // The contract is: this MUST NOT panic, and callers can layer
        // additional routes on top. A future wave attaches Print-Job,
        // Get-Jobs, Get-Printer-Attributes, etc.
        let svc = PrintService::new();
        let router = svc.router();
        // axum::Router is not PartialEq, but we can at least confirm the
        // call returns (no panic) and yields a value we can move.
        drop(router);
    }

    #[test]
    fn error_variants_render_expected_prefixes() {
        // Display strings are part of the public diagnostic contract — the
        // CUPS integration layer and IPP client both key off these prefixes
        // when surfacing errors to end users.
        assert_eq!(
            format!("{}", PrintError::Ipp("version-not-supported".into())),
            "ipp: version-not-supported"
        );
        assert_eq!(
            format!("{}", PrintError::PrinterNotFound("HP-LaserJet-4".into())),
            "printer not found: HP-LaserJet-4"
        );
        assert_eq!(
            format!("{}", PrintError::Spooler("queue stalled".into())),
            "spooler: queue stalled"
        );
    }

    #[test]
    fn printer_not_found_variant_is_matchable() {
        // Per ADR-046: IPP Get-Printer-Attributes on an unknown printer
        // MUST surface as `PrinterNotFound` (not the generic Ipp variant),
        // so the axum handler can map it to a 404 IPP status code rather
        // than a 500.
        let err = PrintError::PrinterNotFound("missing-printer".into());
        match err {
            PrintError::PrinterNotFound(name) => assert_eq!(name, "missing-printer"),
            other => panic!("expected PrinterNotFound, got {:?}", other),
        }
    }

    #[test]
    fn error_variants_are_distinct_debug_representations() {
        // Error variants must remain distinguishable in Debug output so
        // that tracing/audit logs can route them correctly.
        let variants = [
            PrintError::Ipp("i".into()),
            PrintError::PrinterNotFound("p".into()),
            PrintError::Spooler("s".into()),
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
}
