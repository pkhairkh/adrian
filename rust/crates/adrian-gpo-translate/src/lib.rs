//! # adrian-gpo-translate
//!
//! GPO translation wrapper — `admx2adrian` + `preg2adrian` + `gpttmpl2adrian`.
//! End-to-end GPO → canonical declarative JSON. Consumed by `adrian-migrate`
//! and exposed as `adrian gpo-translate` CLI subcommand.
//!
//! Gated by `ad-interop` feature flag (native-only deployments author JSON
//! directly without ADMX/PReg input).
//!
//! ## ADRs
//!
//! - ADR-127: GPO translation
//! - ADR-090: ADMX → declarative JSON compiler
//! - ADR-091: GPP preferences cross-platform compilation
//! - ADR-089: Declarative policy ↔ GPC/GPT synthesis
//! - ADR-092: PolicyExecutor trait + synthetic Windows CSE
//! - ADR-130: SYSVOL migration (this crate processes SYSVOL GPOs)

use adrian_policy_core::PolicyDoc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GpoTranslateError {
    #[error("admx: {0}")]
    Admx(String),
    #[error("preg: {0}")]
    Preg(String),
    #[error("gpttmpl: {0}")]
    GptTmpl(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Input formats supported by the translator.
#[derive(Clone, Copy, Debug)]
pub enum InputFormat {
    Admx,
    Preg,
    GptTmpl,
    GppXml,
}

/// Translate a single GPO source artifact into canonical policy documents.
pub async fn translate(
    _format: InputFormat,
    _input_path: &str,
) -> Result<Vec<PolicyDoc>, GpoTranslateError> {
    // TODO: dispatch to adrian-admx-compiler / adrian-policy-preg / inline GptTmpl parser
    Err(GpoTranslateError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "not yet implemented",
    )))
}

/// Translate an entire SYSVOL GPO directory (per ADR-130).
pub async fn translate_gpo_directory(_gpo_path: &str) -> Result<Vec<PolicyDoc>, GpoTranslateError> {
    Err(GpoTranslateError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "not yet implemented",
    )))
}
