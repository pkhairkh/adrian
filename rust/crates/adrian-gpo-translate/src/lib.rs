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

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-gpo-translate`. Per the task instructions
    //! these cover type construction (`InputFormat` variants), error types,
    //! the `#[from] std::io::Error` conversion, and the loud-stub behaviour
    //! of `translate` / `translate_gpo_directory` — no real ADMX/PReg/GptTmpl
    //! file is read.

    use super::*;

    #[test]
    fn gpo_translate_error_variants_render_messages() {
        // Every `#[error("…")]` template must render — catches regressions
        // in the format strings surfaced to the CLI's `adrian gpo-translate`
        // subcommand (ADR-127) and to `adrian migrate sysvol` (ADR-130).
        assert_eq!(
            GpoTranslateError::Admx("missing <policyDefinitions>".into()).to_string(),
            "admx: missing <policyDefinitions>"
        );
        assert_eq!(
            GpoTranslateError::Preg("bad PReg signature".into()).to_string(),
            "preg: bad PReg signature"
        );
        assert_eq!(
            GpoTranslateError::GptTmpl("INI parse error".into()).to_string(),
            "gpttmpl: INI parse error"
        );
        assert_eq!(
            GpoTranslateError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "GPO_IN"))
                .to_string(),
            "io: GPO_IN"
        );
    }

    #[test]
    fn gpo_translate_error_io_conversion_preserves_kind() {
        // `GpoTranslateError::Io(#[from] std::io::Error)` — exercising the
        // conversion guards the `?` ergonomics used by the future SYSVOL
        // walker (ADR-130). We verify the underlying kind is preserved so
        // callers can dispatch on `ErrorKind` (NotFound vs PermissionDenied).
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let translate_err: GpoTranslateError = io_err.into();
        match translate_err {
            GpoTranslateError::Io(inner) => {
                assert_eq!(inner.kind(), std::io::ErrorKind::NotFound);
                assert!(inner.to_string().contains("missing"));
            }
            other => panic!("expected GpoTranslateError::Io, got {other:?}"),
        }
    }

    #[test]
    fn input_format_variants_are_copy_and_debug() {
        // `InputFormat` is `Copy + Debug` — this catches regressions if
        // someone removes `Copy` (which the translator dispatches on for
        // cheap `match` arms), and exercises Debug rendering so the CLI's
        // `--format` arg parsing can format errors with `{:?}`.
        let f = InputFormat::Admx;
        let _f2 = f; // copy — would fail to compile without `Copy`
        assert!(matches!(f, InputFormat::Admx));
        assert_eq!(format!("{:?}", InputFormat::Admx), "Admx");
        assert_eq!(format!("{:?}", InputFormat::Preg), "Preg");
        assert_eq!(format!("{:?}", InputFormat::GptTmpl), "GptTmpl");
        assert_eq!(format!("{:?}", InputFormat::GppXml), "GppXml");
    }

    #[test]
    fn translate_stub_returns_io_unsupported() {
        // Loud-stub contract (ADR-127 / ADR-090): until the ADMX/PReg/GptTmpl
        // dispatch is implemented, `translate` must surface
        // `GpoTranslateError::Io` with `ErrorKind::Unsupported` (per the
        // stub's `std::io::Error::new` call) rather than silently succeed or
        // panic. We exercise every `InputFormat` variant to ensure the
        // dispatch-on-enum contract holds for all four branches.
        let rt = tokio::runtime::Runtime::new().expect("build runtime");
        for fmt in [
            InputFormat::Admx,
            InputFormat::Preg,
            InputFormat::GptTmpl,
            InputFormat::GppXml,
        ] {
            match rt.block_on(translate(fmt, "/dev/null")) {
                Err(GpoTranslateError::Io(inner)) => {
                    assert_eq!(
                        inner.kind(),
                        std::io::ErrorKind::Unsupported,
                        "translate({fmt:?}): expected Unsupported, got {:?}",
                        inner.kind()
                    );
                }
                other => panic!("translate({fmt:?}): expected Io, got {other:?}"),
            }
        }
    }

    #[test]
    fn translate_gpo_directory_stub_returns_io_unsupported() {
        // Loud-stub contract (ADR-130): until the SYSVOL GPO directory walker
        // is implemented, `translate_gpo_directory` must surface
        // `GpoTranslateError::Io` with `ErrorKind::Unsupported` rather than
        // silently succeed or panic.
        let rt = tokio::runtime::Runtime::new().expect("build runtime");
        match rt.block_on(translate_gpo_directory("/sysvol/{GUID}")) {
            Err(GpoTranslateError::Io(inner)) => {
                assert_eq!(inner.kind(), std::io::ErrorKind::Unsupported);
                assert!(inner.to_string().contains("not yet implemented"));
            }
            other => panic!("expected GpoTranslateError::Io, got {other:?}"),
        }
    }
}
