//! # adrian-acme-server
//!
//! ACME endpoint — RFC 8555 (core), RFC 8737 (tls-alpn-01), RFC 8823 (ARI
//! renewal information). Primary enrollment path in native mode.
//!
//! ## ADRs
//!
//! - ADR-095: ACME primary; MS-WCCE bridge for AD-interop
//! - ADR-096: cert-profile.yaml replaces AD CS templates
//! - ADR-097: Cross-platform autoenroll via ACME
//! - ADR-098: NDES/SCEP replacement bridge

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("malformed request: {0}")]
    Malformed(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("rate limited")]
    RateLimited,
    #[error("ca: {0}")]
    Ca(String),
}

/// ACME account.
#[derive(Clone, Debug)]
pub struct AcmeAccount {
    pub kid: String,
    pub contact: Vec<String>,
    pub status: AccountStatus,
}

#[derive(Clone, Copy, Debug)]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

/// ACME server (RFC 8555). Mounted under `/acme/directory`.
pub struct AcmeServer {
    // TODO: hold Arc<CaService>, account store, nonce cache
}

impl AcmeServer {
    pub fn new() -> Self {
        Self {}
    }

    /// Serve the ACME directory + endpoints on the given axum router.
    pub fn router(&self) -> axum::Router {
        // TODO: wire /directory, /new-nonce, /new-account, /new-order, etc.
        axum::Router::new()
    }

    /// Serve ARI (RFC 8823) renewal-info endpoint.
    pub fn ari_router(&self) -> axum::Router {
        // TODO: wire /draft-ietf-acme-ari
        axum::Router::new()
    }
}

impl Default for AcmeServer {
    fn default() -> Self {
        Self::new()
    }
}
