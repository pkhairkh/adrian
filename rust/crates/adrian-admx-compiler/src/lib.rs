//! # adrian-admx-compiler
//!
//! `admx2adrian` — ADMX → declarative canonical JSON compiler.
//! Gated by `ad-interop`; native-only deployments author JSON directly.
//!
//! ## ADRs
//!
//! - ADR-090: ADMX → declarative JSON compiler
//! - ADR-091: GPP preferences cross-platform compilation
//! - ADR-127: GPO translation (admx/preg/gpttmpl → declarative)
//! - ADR-089: Declarative policy ↔ GPC/GPT synthesis

use adrian_policy_core::PolicyDoc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdmxError {
    #[error("admx parse: {0}")]
    Parse(String),
    #[error("semantic: {0}")]
    Semantic(String),
}

/// ADMX policy definition (parsed).
pub struct AdmxPolicy {
    // TODO: hold quick_xml reader state
    pub name: String,
    pub class: String, // user | machine
}

/// Compile an ADMX/ADML pair into canonical policy documents.
pub fn compile(_admx_path: &str, _adml_path: &str) -> Result<Vec<PolicyDoc>, AdmxError> {
    // TODO: parse ADMX/ADML, emit PolicyDoc per ADR-090
    Err(AdmxError::Parse("not yet implemented".into()))
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-admx-compiler`. Per the task instructions
    //! these cover type construction, error variants and the loud-stub
    //! behaviour of `compile` — no real ADMX/ADML parsing or file I/O.

    use super::*;

    #[test]
    fn admx_policy_constructs_with_name_and_class() {
        // `AdmxPolicy` is a parsed ADMX policy definition. Until the
        // quick_xml-backed parser is wired in (ADR-090 TODO), verify that
        // the public fields exist and accept the documented values.
        let p = AdmxPolicy {
            name: "EnableAdrian".into(),
            class: "machine".into(),
        };
        assert_eq!(p.name, "EnableAdrian");
        assert_eq!(p.class, "machine");
    }

    #[test]
    fn admx_policy_class_accepts_user_variant() {
        // ADMX §`policy` `class` attribute is one of `user` / `machine`
        // per MS-GPREG; the field is a `String` (not an enum) by design
        // to forward-declare new classes without a recompile.
        let p = AdmxPolicy {
            name: "UserPolicy".into(),
            class: "user".into(),
        };
        assert_eq!(p.class, "user");
    }

    #[test]
    fn compile_stub_returns_parse_error() {
        // Loud-stub contract: until ADR-090 lands, `compile` must surface
        // `AdmxError::Parse` rather than panic or `todo!`. This guards
        // the seam so the integration in Wave 4c only needs to swap the
        // body, not the signature.
        let err = compile("nonexistent.admx", "nonexistent.adml").unwrap_err();
        assert!(matches!(err, AdmxError::Parse(_)));
        assert!(err.to_string().contains("not yet implemented"));
    }

    #[test]
    fn admx_error_variants_render_messages() {
        let parse = AdmxError::Parse("xml eof".into());
        let semantic = AdmxError::Semantic("bad class".into());
        assert_eq!(parse.to_string(), "admx parse: xml eof");
        assert_eq!(semantic.to_string(), "semantic: bad class");
    }
}
