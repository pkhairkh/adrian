//! # adrian-policy-cel
//!
//! Common Expression Language (CEL) selector for role-based policy binding.
//! Used by `adrian-claims-engine` (AD FS CRL compat) and policy distribution.
//!
//! ## ADRs
//!
//! - ADR-030: Role-based policy binding
//! - ADR-101: AD FS claim rule language compatibility

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CelError {
    #[error("compile: {0}")]
    Compile(String),
    #[error("eval: {0}")]
    Eval(String),
}

/// Compiled CEL expression.
pub struct CelSelector {
    // TODO: hold compiled cel::Program
    source: String,
}

impl CelSelector {
    pub fn compile(source: impl Into<String>) -> Result<Self, CelError> {
        // TODO: compile via `cel` crate once integrated
        Ok(Self {
            source: source.into(),
        })
    }

    /// Evaluate against a JSON host-facts document (ADR-026).
    pub fn eval(&self, _facts: &serde_json::Value) -> Result<serde_json::Value, CelError> {
        // TODO: implement evaluation
        Err(CelError::Eval(format!(
            "not yet implemented: {}",
            self.source
        )))
    }
}
