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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-federation-shim`. Per the task instructions
    //! these cover type construction, error variants, the axum router
    //! construction contract, and the loud-stub behaviour of
    //! `push_jwks_rollover` — no real Keycloak upstream or webhook fan-out.

    use super::*;

    #[test]
    fn federation_error_variants_render_messages() {
        // Each variant maps to a distinct HTTP status or log line once
        // the sidecar is wired — verify the `#[error("…")]` templates
        // render so logs stay parseable.
        assert_eq!(
            FederationError::Upstream("503".into()).to_string(),
            "upstream keycloak: 503"
        );
        assert_eq!(
            FederationError::WsTrust("bad RST".into()).to_string(),
            "wstrust: bad RST"
        );
        assert_eq!(
            FederationError::JwksRollover("no keys".into()).to_string(),
            "jwks rollover: no keys"
        );
        assert_eq!(
            FederationError::SamlReplay.to_string(),
            "saml replay detected"
        );
    }

    #[test]
    fn saml_replay_is_unit_variant() {
        // `SamlReplay` carries no payload (the replay itself is logged
        // elsewhere) — this guards the unit-variant shape so call sites
        // that match on it don't silently break if a payload is added.
        let e = FederationError::SamlReplay;
        assert!(matches!(e, FederationError::SamlReplay));
    }

    #[test]
    fn router_constructs_without_panic() {
        // Until the route handlers are wired in (TODO in lib.rs),
        // `router()` must return a usable empty `axum::Router` rather
        // than panic. This guards the seam so the Wave 4c integration
        // only needs to swap the body.
        let shim = FederationShim::new();
        let _r = shim.router();
    }

    #[tokio::test]
    async fn push_jwks_rollover_stub_returns_jwks_rollover_error() {
        // Loud-stub contract: until ADR-038 webhook fan-out lands,
        // `push_jwks_rollover` must surface
        // `FederationError::JwksRollover` rather than panic.
        let shim = FederationShim::new();
        let err = shim.push_jwks_rollover().await.unwrap_err();
        assert!(matches!(err, FederationError::JwksRollover(_)));
        assert!(err.to_string().contains("not yet implemented"));
    }

    #[tokio::test]
    async fn default_equals_new() {
        // `Default` impl must match `new()` — both must construct a
        // usable `FederationShim` whose `router()` returns a usable
        // `axum::Router`. Catches the common regression of adding a
        // field to `FederationShim` and forgetting to update `Default`.
        let a = FederationShim::default();
        let b = FederationShim::new();
        let _ra = a.router();
        let _rb = b.router();
        // Both must surface the same stub error from `push_jwks_rollover`.
        let ea = a.push_jwks_rollover().await.unwrap_err();
        let eb = b.push_jwks_rollover().await.unwrap_err();
        assert!(matches!(ea, FederationError::JwksRollover(_)));
        assert!(matches!(eb, FederationError::JwksRollover(_)));
    }
}
