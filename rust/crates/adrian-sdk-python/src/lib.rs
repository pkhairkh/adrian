//! # adrian-sdk-python
//!
//! Python bindings (via `pyo3`) for the Adrian SDK. Built with `maturin`
//! into `adrian` Python module. Internally manages a tokio runtime per
//! `AdrianClient` instance.
//!
//! ## ADRs
//!
//! - ADR-107: Unified Rust core SDK
//! - ADR-108: SSPI-equivalent auth abstraction
//! - ADR-063: Unified cross-platform CLI (Python bindings for glue scripts)

// pyo3's `#[classmethod]` macro expansion includes a `map_err(Into::into)`
// on a value that is already `PyErr`, which trips clippy::useless_conversion.
// The conversion is harmless (it's a no-op at runtime) and is a known
// artifact of pyo3 0.22's macro codegen; allow it crate-wide.
#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;
use pyo3::types::PyType;
use std::sync::OnceLock;

use adrian_sdk::AdrianClient;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build adrian-sdk-python runtime")
    })
}

/// Adrian SDK Python client.
#[pyclass]
pub struct AdrianPyClient {
    inner: AdrianClient,
}

#[pymethods]
impl AdrianPyClient {
    /// Construct a new client.
    #[new]
    pub fn new() -> Self {
        Self {
            inner: AdrianClient::new(),
        }
    }

    /// Join the host to the framework domain. Returns True on success.
    pub fn join(&self, domain: &str) -> bool {
        let result = runtime().block_on(async { self.inner.join(domain).await });
        result.is_ok()
    }

    /// Class-level constructor helper for `AdrianPyClient()`.
    #[classmethod]
    pub fn from_config(_cls: &Bound<'_, PyType>, _config_path: &str) -> PyResult<Self> {
        // TODO: load config from YAML
        Ok(Self::new())
    }
}

impl Default for AdrianPyClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Python module entry point.
#[pymodule]
fn adrian(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AdrianPyClient>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pyclient_new_constructs_inner_client() {
        // Per ADR-107: AdrianPyClient wraps an `AdrianClient`. The `#[new]`
        // constructor is called by Python as `AdrianPyClient()`. We test
        // the Rust-side constructor directly (without spinning up a Python
        // interpreter) — it must not panic and must not touch the network.
        let _client = AdrianPyClient::new();
    }

    #[test]
    fn pyclient_join_returns_false_until_implemented() {
        // The underlying `AdrianClient::join` surfaces `SdkError::NotJoined`
        // (loud stub). The Python binding converts `Ok` -> `True` and any
        // `Err` -> `False` per its public Python contract. Until `join` is
        // wired, the Python-facing call MUST return `False` — never raise,
        // never silently return `True`.
        let client = AdrianPyClient::new();
        assert!(
            !client.join("adrian.example"),
            "join must return False until the SDK join is implemented"
        );
    }

    #[test]
    fn runtime_singleton_is_idempotent() {
        // Per ADR-107: the Python binding stores its tokio runtime in a
        // `OnceLock` so every `AdrianPyClient::join` call `block_on`s on
        // the same multi-threaded runtime. Calling `runtime()` repeatedly
        // MUST return the same `&'static Runtime` — otherwise the binding
        // would leak a fresh runtime per call (each carrying its own
        // thread pool), which would be especially costly for long-lived
        // Python interpreters.
        let r1 = runtime();
        let r2 = runtime();
        assert!(std::ptr::eq(r1, r2), "runtime() must return a singleton");
    }
}
