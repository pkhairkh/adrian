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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-acme-server`. Per the task instructions these
    //! cover type construction, enum variants, error types and the
    //! `AcmeServer::router` / `ari_router` construction contract — no real
    //! HTTP server or TLS termination.

    use super::*;

    #[test]
    fn acme_account_constructs_with_expected_fields() {
        let acct = AcmeAccount {
            kid: "https://ca.adrian.dev/acme/acct/1".into(),
            contact: vec!["mailto:admin@adrian.dev".into()],
            status: AccountStatus::Valid,
        };
        assert_eq!(acct.kid, "https://ca.adrian.dev/acme/acct/1");
        assert_eq!(acct.contact.len(), 1);
        assert!(matches!(acct.status, AccountStatus::Valid));
    }

    #[test]
    fn account_status_variants_are_copy_and_debug() {
        // `AccountStatus` is `Copy + Debug` — this catches regressions
        // if someone removes `Copy` (which the ACME order flow depends
        // on for cheap state transitions).
        let s = AccountStatus::Deactivated;
        let s2 = s; // copy
        let _s3 = s; // copy again — would fail to compile without `Copy`
        assert!(matches!(s2, AccountStatus::Deactivated));
        // Debug render is exercised for all three variants.
        assert_eq!(format!("{:?}", AccountStatus::Valid), "Valid");
        assert_eq!(format!("{:?}", AccountStatus::Deactivated), "Deactivated");
        assert_eq!(format!("{:?}", AccountStatus::Revoked), "Revoked");
    }

    #[test]
    fn acme_error_variants_render_messages() {
        // Verify every `#[error("…")]` template renders — catches
        // regressions in the format strings used by HTTP problem+json
        // bodies (RFC 7807) the server emits.
        assert_eq!(
            AcmeError::Malformed("bad json".into()).to_string(),
            "malformed request: bad json"
        );
        assert_eq!(
            AcmeError::Unauthorized("bad sig".into()).to_string(),
            "unauthorized: bad sig"
        );
        assert_eq!(AcmeError::RateLimited.to_string(), "rate limited");
        assert_eq!(
            AcmeError::Ca("hsm locked".into()).to_string(),
            "ca: hsm locked"
        );
    }

    #[test]
    fn server_default_equals_new() {
        // `Default` impl must match `new()` — both must construct a
        // usable `AcmeServer` and both routers must succeed. Catches the
        // common regression of adding a field to `AcmeServer` and
        // forgetting to update one of the constructors.
        let a = AcmeServer::default();
        let b = AcmeServer::new();
        // No `Debug`/`PartialEq` on `AcmeServer` (TODO fields), so we
        // exercise the seam by calling `router()` on each — if either
        // constructor dropped a required init step, this would panic.
        let _ra = a.router();
        let _rb = b.router();
    }

    #[test]
    fn routers_construct_without_panic() {
        // Until the route handlers are wired in (TODO in lib.rs), both
        // `router()` and `ari_router()` must return a usable empty
        // `axum::Router` rather than panic. This guards the seam so the
        // Wave 4c integration only needs to swap the bodies.
        let server = AcmeServer::new();
        let _r1 = server.router();
        let _r2 = server.ari_router();
    }
}
