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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-policy-cel`. Per the task instructions these
    //! cover type construction, error variants and the loud-stub behaviour
    //! of `CelSelector::eval` — no real CEL evaluation or external service.

    use super::*;

    #[test]
    fn compile_returns_ok_for_any_source() {
        // Until the `cel` crate is integrated, `compile` is permissive:
        // it must accept any string and not panic. This guards the
        // signature so future integration only swaps the inner field.
        let sel = CelSelector::compile("host.os == 'linux'").expect("compile");
        // We can't read `source` directly (private), but `eval` echoes it
        // back via the loud-stub error message — that's the contract.
        let err = sel.eval(&serde_json::Value::Null).unwrap_err();
        assert!(err.to_string().contains("host.os == 'linux'"));
    }

    #[test]
    fn compile_accepts_owned_and_borrowed_strings() {
        // `impl Into<String>` should accept `&'static str`, `String`, and
        // anything else string-like — exercising both keeps the generic
        // bound from regressing to a concrete type.
        let owned: String = "owned".into();
        let _s1 = CelSelector::compile(owned).expect("owned");
        let _s2 = CelSelector::compile("borrowed").expect("borrowed");
    }

    #[test]
    fn eval_stub_returns_eval_error_with_source() {
        let sel = CelSelector::compile("user.groups.contains('admins')").unwrap();
        let facts = serde_json::json!({ "user": { "groups": ["admins"] } });
        let err = sel.eval(&facts).unwrap_err();
        assert!(matches!(err, CelError::Eval(_)));
        assert!(err.to_string().contains("not yet implemented"));
        assert!(err.to_string().contains("user.groups.contains('admins')"));
    }

    #[test]
    fn cel_error_variants_render_messages() {
        let compile = CelError::Compile("syntax".into());
        let eval = CelError::Eval("no binding".into());
        assert_eq!(compile.to_string(), "compile: syntax");
        assert_eq!(eval.to_string(), "eval: no binding");
    }
}
