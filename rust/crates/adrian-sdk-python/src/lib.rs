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

/// Python module entry point.
#[pymodule]
fn adrian(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AdrianPyClient>()?;
    Ok(())
}
