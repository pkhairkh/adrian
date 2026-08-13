//! # adrian-claims-engine
//!
//! AD FS claim rule language compatibility layer. Translates legacy AD FS
//! claim rules into CEL selectors for the federation shim.
//!
//! ## ADRs
//!
//! - ADR-100: Keycloak replaces AD FS farm (WID/SQL/WAP)
//! - ADR-101: AD FS claim rule language compatibility
//! - ADR-102: Rust shim replaces WAP
//! - ADR-104: Keycloak identity brokering + HRD

use adrian_policy_cel::CelSelector;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClaimsError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("compile to CEL: {0}")]
    Compile(String),
    #[error("eval: {0}")]
    Eval(String),
}

/// Parsed AD FS claim rule (claim rule language grammar).
pub struct ClaimRule {
    pub source: String,
}

impl ClaimRule {
    /// Parse one AD FS claim rule.
    pub fn parse(source: impl Into<String>) -> Result<Self, ClaimsError> {
        // TODO: parse CRL grammar per ADR-101
        Ok(Self {
            source: source.into(),
        })
    }

    /// Compile to a CEL selector consumable by the federation shim.
    pub fn to_cel(&self) -> Result<CelSelector, ClaimsError> {
        // TODO: translate claim rule → CEL
        CelSelector::compile("true").map_err(|e| ClaimsError::Compile(e.to_string()))
    }
}
