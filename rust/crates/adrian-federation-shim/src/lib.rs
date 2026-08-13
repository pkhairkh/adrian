//! # adrian-federation-shim
//!
//! Keycloak sidecar (Rust `axum`) — WS-Trust bridge for legacy STS clients,
//! JWKS rollover webhook, and SAML/OIDC brokering glue.
//!
//! ## ADRs
//!
//! - ADR-038: JWKS endpoint + webhook rollover
//! - ADR-039: OIDC primary; WS-Trust bridge
//! - ADR-040: SAML replay & clock-skew policy
//! - ADR-041: Strict OIDC default-resource compat
//! - ADR-100: Keycloak replaces AD FS farm
//! - ADR-102: Rust shim replaces WAP
//! - ADR-103: Keycloak StatefulSet (no primary/secondary)
//! - ADR-104: Keycloak identity brokering + HRD

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("upstream keycloak: {0}")]
    Upstream(String),
    #[error("wstrust: {0}")]
    WsTrust(String),
    #[error("jwks rollover: {0}")]
    JwksRollover(String),
    #[error("saml replay detected")]
    SamlReplay,
}

/// Federation shim — Rust sidecar in front of Keycloak StatefulSet.
pub struct FederationShim {
    // TODO: hold Arc<axum::Router>, moka cache for JWKS/replay
}

impl FederationShim {
    pub fn new() -> Self {
        Self {}
    }

    /// Build the axum router with WS-Trust + JWKS-webhook endpoints.
    pub fn router(&self) -> axum::Router {
        // TODO: wire /trust/2005/usernamemixed, /jwks/rollover, /saml/replay-cache
        axum::Router::new()
    }

    /// Push a refreshed JWKS to all relying parties via webhook (ADR-038).
    pub async fn push_jwks_rollover(&self) -> Result<(), FederationError> {
        // TODO: implement
        Err(FederationError::JwksRollover("not yet implemented".into()))
    }
}

impl Default for FederationShim {
    fn default() -> Self {
        Self::new()
    }
}
