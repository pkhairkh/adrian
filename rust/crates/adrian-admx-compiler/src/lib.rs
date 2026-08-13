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
