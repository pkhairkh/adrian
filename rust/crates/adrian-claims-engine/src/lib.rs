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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-claims-engine`. Per the task instructions
    //! these cover type construction, error variants, the parse → to_cel
    //! pipeline, and the loud-stub behaviour of `ClaimRule::parse` /
    //! `ClaimRule::to_cel` — no real CEL evaluation or external service.

    use super::*;

    #[test]
    fn parse_preserves_source_text() {
        // Until the CRL grammar parser is wired in (ADR-101 TODO),
        // `parse` is permissive and stores the source verbatim. This
        // guards the seam so the future parser only needs to swap the
        // body, not the signature.
        let rule_text = "=> issue(Type = \"role\", Value = \"admin\");";
        let rule = ClaimRule::parse(rule_text).expect("parse");
        assert_eq!(rule.source, rule_text);
    }

    #[test]
    fn parse_accepts_owned_and_borrowed_strings() {
        // `impl Into<String>` should accept `&'static str`, `String`,
        // and anything else string-like — exercising both keeps the
        // generic bound from regressing to a concrete type.
        let owned: String = "=> issue(Type=\"x\");".into();
        let _r1 = ClaimRule::parse(owned).expect("owned");
        let _r2 = ClaimRule::parse("=> issue(Type=\"x\");").expect("borrowed");
    }

    #[test]
    fn to_cel_returns_compiled_selector() {
        // Loud-stub contract: `to_cel` currently delegates to
        // `CelSelector::compile("true")`. Until the ADR-101 translator
        // lands, the contract is "any ClaimRule compiles to a selector
        // that returns Ok from `compile`" — verify that contract.
        let rule = ClaimRule::parse("=> issue(Type = \"role\");").unwrap();
        let selector = rule.to_cel().expect("to_cel");
        // `CelSelector::eval` is itself a loud stub that surfaces
        // `CelError::Eval` containing the source — verify the selector
        // we built is the literal "true" stub.
        let err = selector.eval(&serde_json::Value::Null).unwrap_err();
        assert!(err.to_string().contains("true"));
    }

    #[test]
    fn claims_error_variants_render_messages() {
        // Verify every `#[error("…")]` template renders — catches
        // regressions in the format strings used by logs and HTTP
        // bodies the federation shim emits.
        assert_eq!(ClaimsError::Parse("eof".into()).to_string(), "parse: eof");
        assert_eq!(
            ClaimsError::Compile("no binding".into()).to_string(),
            "compile to CEL: no binding"
        );
        assert_eq!(
            ClaimsError::Eval("undefined".into()).to_string(),
            "eval: undefined"
        );
    }
}
