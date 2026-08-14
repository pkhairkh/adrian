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
//!
//! ## Wave 4 surface
//!
//! Wave 4 adds the new `AdrianPySdk` class that wraps the unified
//! `AdrianSdk` (per ADR-107 §Decision) and exposes the 6 Python-facing
//! operations per T-401:
//! - `AdrianPySdk()` — constructs an `AdrianSdk::with_default_stubs()`.
//! - `join_realm(domain) -> bool` — delegates to the legacy
//!   `AdrianClient::join` (the trait-based SDK doesn't expose `join`).
//! - `authenticate(principal, password) -> Optional[str]` — calls
//!   `sdk.auth.authenticate_kerberos(principal, password)` and returns
//!   the principal string on success or `None` on failure.
//! - `search_directory(filter) -> Optional[List[Dict]]` — calls
//!   `sdk.directory.search(filter)` and returns a list of `{dn,
//!   attributes: List[Tuple[str, bytes]]}` dicts on success or `None`.
//! - `apply_policy(name, version) -> Optional[Dict]` — calls
//!   `sdk.policy.apply(DeclarativePolicy { name, version, settings: [] })`
//!   and returns a dict `{name, version, applied_at, rollback_token}` on
//!   success or `None`.
//! - `mount_share(server, share) -> Optional[Dict]` — calls
//!   `sdk.file.mount_share(server, share, default_token)` and returns
//!   `{server, share, mount_path}` on success or `None`.
//! - `enroll_cert(profile, csr, subject) -> Optional[bytes]` — calls
//!   `sdk.cert.enroll(CertEnrollRequest { profile, csr, subject })` and
//!   returns the cert DER bytes on success or `None`.
//!
//! The legacy `AdrianPyClient` class is preserved for backward compat
//! with v0.5.0 callers.

// pyo3's `#[classmethod]` macro expansion includes a `map_err(Into::into)`
// on a value that is already `PyErr`, which trips clippy::useless_conversion.
// The conversion is harmless (it's a no-op at runtime) and is a known
// artifact of pyo3 0.22's macro codegen; allow it crate-wide.
#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyType};
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

/// Adrian SDK Python client (legacy surface — wraps `AdrianClient`).
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

// =========================================================================
// Wave 4: `AdrianPySdk` — the new unified-SDK Python surface.
//
// Wraps `AdrianSdk::with_default_stubs()` (the trait-object SDK per
// ADR-107 §Decision) and exposes the 6 Python-facing operations per
// T-401. The legacy `AdrianPyClient` above is kept for backward compat
// with v0.5.0 callers; new consumers should prefer `AdrianPySdk`.
// =========================================================================

/// Adrian unified SDK Python binding (Wave 4 — ADR-107).
///
/// Wraps `AdrianSdk::with_default_stubs()` internally. Each method
/// delegates to the corresponding SDK module trait (`auth`,
/// `directory`, `policy`, `file`, `cert`). The default stubs return
/// typed `SdkError` variants; this class surfaces them as `None`
/// return values (matching Python's "exception-or-None" convention for
/// optional results) — callers can detect failure by checking for
/// `None`. A future wave may surface typed Python exceptions per
/// `SdkError` variant.
#[pyclass]
pub struct AdrianPySdk {
    sdk: std::sync::Arc<adrian_sdk::AdrianSdk>,
}

#[pymethods]
impl AdrianPySdk {
    /// Construct a new `AdrianPySdk` with the framework's default stub
    /// impls. Production callers inject custom impls via the Rust
    /// `AdrianSdk::builder()` API; the Python binding exposes only the
    /// default-stub construction today.
    #[new]
    pub fn new() -> Self {
        Self {
            sdk: std::sync::Arc::new(adrian_sdk::AdrianSdk::with_default_stubs()),
        }
    }

    /// Join the host to the framework domain. Delegates to the legacy
    /// `AdrianClient::join` (the trait-based SDK doesn't expose `join`
    /// — it's host-platform glue per ADR-107).
    ///
    /// Returns `True` on success, `False` on failure. Until `join` is
    /// wired (ADR-107), returns `False`.
    pub fn join_realm(&self, domain: &str) -> bool {
        let client = AdrianClient::new();
        let result = runtime().block_on(async { client.join(domain).await });
        result.is_ok()
    }

    /// Authenticate via Kerberos (RFC 4120 AS-REQ). Calls
    /// `sdk.auth.authenticate_kerberos(principal, password)` and
    /// returns the principal string on success or `None` on failure
    /// (matching Python's "exception-or-None" convention for optional
    /// results).
    pub fn authenticate(&self, principal: &str, password: &str) -> Option<String> {
        let result = runtime().block_on(self.sdk.auth.authenticate_kerberos(principal, password));
        match result {
            Ok(token) => Some(token.principal),
            Err(_) => None,
        }
    }

    /// Search the directory with an RFC 4515 filter string. Calls
    /// `sdk.directory.search(filter)` and returns a list of `{dn,
    /// attributes: List[Tuple[str, bytes]]}` dicts on success or
    /// `None` on failure.
    pub fn search_directory<'py>(
        &self,
        py: Python<'py>,
        filter: &str,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        match self.search_directory_core(filter) {
            Ok(entries) => {
                let list = PyList::empty_bound(py);
                for entry in entries {
                    let dict = PyDict::new_bound(py);
                    dict.set_item("dn", entry.dn)?;
                    let attrs = PyList::empty_bound(py);
                    for (name, value) in entry.attributes {
                        let tuple = (name, value.as_slice());
                        attrs.append(tuple)?;
                    }
                    dict.set_item("attributes", attrs)?;
                    list.append(dict)?;
                }
                Ok(Some(list.into_any()))
            }
            Err(_) => Ok(None),
        }
    }

    /// Apply a declarative policy (name + version). Calls
    /// `sdk.policy.apply(DeclarativePolicy { name, version, settings: [] })`
    /// and returns a dict `{name, version, applied_at, rollback_token}`
    /// on success or `None` on failure.
    pub fn apply_policy<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        version: &str,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        match self.apply_policy_core(name, version) {
            Ok(applied) => {
                let dict = PyDict::new_bound(py);
                dict.set_item("name", applied.name)?;
                dict.set_item("version", applied.version)?;
                dict.set_item("applied_at", applied.applied_at)?;
                dict.set_item(
                    "rollback_token",
                    pyo3::types::PyList::new_bound(py, applied.rollback_token.iter().copied()),
                )?;
                Ok(Some(dict.into_any()))
            }
            Err(_) => Ok(None),
        }
    }

    /// Mount an SMB share (`\\server\share`). Calls
    /// `sdk.file.mount_share(server, share, default_token)` and returns
    /// a dict `{server, share, mount_path}` on success or `None` on
    /// failure. The actual mount syscall is the operator daemon's job
    /// — the SDK returns the conventional mount path.
    pub fn mount_share<'py>(
        &self,
        py: Python<'py>,
        server: &str,
        share: &str,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        match self.mount_share_core(server, share) {
            Ok(mounted) => {
                let dict = PyDict::new_bound(py);
                dict.set_item("server", mounted.server)?;
                dict.set_item("share", mounted.share)?;
                dict.set_item("mount_path", mounted.mount_path)?;
                Ok(Some(dict.into_any()))
            }
            Err(_) => Ok(None),
        }
    }

    /// Enroll a certificate via ACME (RFC 8555). Calls
    /// `sdk.cert.enroll(CertEnrollRequest { profile, csr, subject })`
    /// and returns the cert DER bytes on success or `None` on failure.
    pub fn enroll_cert<'py>(
        &self,
        py: Python<'py>,
        profile: &str,
        csr: &[u8],
        subject: &str,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        match self.enroll_cert_core(profile, csr, subject) {
            Ok(cert_der) => {
                let bytes = pyo3::types::PyList::new_bound(py, cert_der.iter().copied());
                Ok(Some(bytes.into_any()))
            }
            Err(_) => Ok(None),
        }
    }

    /// Class-level constructor helper. Reserved for future YAML config
    /// loading (currently delegates to `new()`).
    #[classmethod]
    pub fn from_config(_cls: &Bound<'_, PyType>, _config_path: &str) -> PyResult<Self> {
        // TODO: load config from YAML
        Ok(Self::new())
    }
}

impl Default for AdrianPySdk {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure-Rust core implementations (outside `#[pymethods]` so pyo3 doesn't
/// try to wrap them as Python-callable methods). Used by Wave 4 tests to
/// verify the dispatch path without spinning up a Python interpreter,
/// but always compiled so the public `#[pymethods]` methods can delegate
/// to them.
impl AdrianPySdk {
    /// Pure-Rust core of `search_directory` — returns the raw
    /// `Vec<DirEntry>` on success or `SdkError` on failure.
    fn search_directory_core(
        &self,
        filter: &str,
    ) -> Result<Vec<adrian_sdk::DirEntry>, adrian_sdk::SdkError> {
        runtime().block_on(self.sdk.directory.search(filter))
    }

    /// Pure-Rust core of `apply_policy`.
    fn apply_policy_core(
        &self,
        name: &str,
        version: &str,
    ) -> Result<adrian_sdk::AppliedPolicy, adrian_sdk::SdkError> {
        let policy = adrian_sdk::DeclarativePolicy {
            name: name.to_string(),
            version: version.to_string(),
            settings: Vec::new(),
        };
        runtime().block_on(self.sdk.policy.apply(&policy))
    }

    /// Pure-Rust core of `mount_share`.
    fn mount_share_core(
        &self,
        server: &str,
        share: &str,
    ) -> Result<adrian_sdk::MountedShare, adrian_sdk::SdkError> {
        let token = adrian_sdk::AuthToken {
            principal: "<python-default>".into(),
            expiry: None,
            kind: adrian_sdk::AuthTokenKind::Kerberos,
        };
        runtime().block_on(self.sdk.file.mount_share(server, share, &token))
    }

    /// Pure-Rust core of `enroll_cert`.
    fn enroll_cert_core(
        &self,
        profile: &str,
        csr: &[u8],
        subject: &str,
    ) -> Result<Vec<u8>, adrian_sdk::SdkError> {
        let req = adrian_sdk::CertEnrollRequest {
            profile: profile.to_string(),
            csr: csr.to_vec(),
            subject: subject.to_string(),
        };
        runtime().block_on(self.sdk.cert.enroll(req))
    }
}

/// Python module entry point.
#[pymodule]
fn adrian(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AdrianPyClient>()?;
    m.add_class::<AdrianPySdk>()?;
    // Wave 4: the SDK methods surface failure as `None` (matching
    // Python's "exception-or-None" convention for optional results).
    // Future waves may surface typed Python exceptions per `SdkError`
    // variant via `pyo3::create_exception!` (which requires the
    // `#[pyclass]` annotation); that's out of scope for Wave 4.
    Ok(())
}

// =========================================================================
// Python exception types (Wave 4 — reserved for future wave).
//
// Wave 4 surfaces failure as `None` return values (matching Python's
// "exception-or-None" convention for optional results). A future wave
// will surface typed Python exceptions per `SdkError` variant via
// `pyo3::create_exception!` (which requires the `#[pyclass]` annotation
// + `PyTypeInfo` impl). The structs below are placeholders for that
// future work — they're not exposed via the `#[pymodule]` entry point
// yet.
// =========================================================================

/// Raised when the framework is not yet joined (mirrors
/// `SdkError::NotJoined`). Reserved for a future wave.
#[derive(Debug)]
pub struct NotJoinedError;

impl std::fmt::Display for NotJoinedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "adrian: not joined")
    }
}

/// Generic Adrian error (mirrors `SdkError::*` variants that don't
/// have a dedicated exception type yet). Reserved for a future wave.
#[derive(Debug)]
pub struct AdrianError(String);

impl std::fmt::Display for AdrianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "adrian: {}", self.0)
    }
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

    // -----------------------------------------------------------------
    // Wave 4 tests — `AdrianPySdk` (the new unified-SDK surface).
    // -----------------------------------------------------------------

    #[test]
    fn wave4_pysdk_new_constructs_inner_sdk() {
        // The `#[new]` constructor is called by Python as
        // `AdrianPySdk()`. We test the Rust-side constructor directly
        // (without spinning up a Python interpreter) — it must not
        // panic and must not touch the network.
        let _sdk = AdrianPySdk::new();
    }

    /// Wave 4 + T-402 (join + auth flow): `AdrianPySdk::authenticate`
    /// delegates to `sdk.auth.authenticate_kerberos`. The default stub
    /// returns `Err(SdkError::Auth(...))`, which the Python binding
    /// surfaces as `None` (matching Python's "exception-or-None"
    /// convention for optional results).
    #[test]
    fn wave4_pysdk_authenticate_returns_none_with_default_stub() {
        let sdk = AdrianPySdk::new();
        let result = sdk.authenticate("alice@ADRIAN.EXAMPLE", "pw");
        assert!(
            result.is_none(),
            "default stub must surface None (not raise); got: {result:?}"
        );
    }

    /// Wave 4 + T-402 (search directory): `AdrianPySdk::search_directory`
    /// delegates to `sdk.directory.search`. The default stub returns
    /// `Err(SdkError::Directory(...))`, which the Python binding
    /// surfaces as `None`. We test the pure-Rust `_core` method to
    /// avoid needing an embedded Python interpreter in the test binary.
    #[test]
    fn wave4_pysdk_search_directory_returns_err_with_default_stub() {
        let sdk = AdrianPySdk::new();
        let result = sdk.search_directory_core("(objectClass=*)");
        assert!(
            result.is_err(),
            "default stub must return Err; got: {result:?}"
        );
        match result {
            Err(adrian_sdk::SdkError::Directory(msg)) => {
                assert!(
                    msg.contains("(objectClass=*)"),
                    "error must contain filter; got: {msg}"
                );
                assert!(
                    msg.contains("with_url"),
                    "error must name the with_url constructor; got: {msg}"
                );
            }
            other => panic!("expected SdkError::Directory; got: {other:?}"),
        }
    }

    /// Wave 4 + T-402 (enroll cert): `AdrianPySdk::enroll_cert`
    /// delegates to `sdk.cert.enroll`. The default stub returns
    /// `Err(SdkError::Cert(...))`, which the Python binding surfaces
    /// as `None`. We test the pure-Rust `_core` method.
    #[test]
    fn wave4_pysdk_enroll_cert_returns_err_with_default_stub() {
        let sdk = AdrianPySdk::new();
        let csr: [u8; 4] = [0x30, 0x82, 0x01, 0x00];
        let result = sdk.enroll_cert_core("adrian-webserver", &csr, "CN=dc01.adrian.example");
        assert!(
            result.is_err(),
            "default stub must return Err; got: {result:?}"
        );
        match result {
            Err(adrian_sdk::SdkError::Cert(msg)) => {
                assert!(
                    msg.contains("adrian-webserver"),
                    "error must contain profile; got: {msg}"
                );
                assert!(
                    msg.contains("with_ca"),
                    "error must name the with_ca constructor; got: {msg}"
                );
            }
            other => panic!("expected SdkError::Cert; got: {other:?}"),
        }
    }

    /// Wave 4 + T-402 (apply policy): `AdrianPySdk::apply_policy`
    /// delegates to `sdk.policy.apply`. The default stub returns
    /// `Err(SdkError::Policy(...))`, which the Python binding surfaces
    /// as `None`. We test the pure-Rust `_core` method.
    #[test]
    fn wave4_pysdk_apply_policy_returns_err_with_default_stub() {
        let sdk = AdrianPySdk::new();
        let result = sdk.apply_policy_core("baseline-workstation", "1.0.0");
        assert!(
            result.is_err(),
            "default stub must return Err; got: {result:?}"
        );
        match result {
            Err(adrian_sdk::SdkError::Policy(msg)) => {
                assert!(
                    msg.contains("baseline-workstation"),
                    "error must contain policy name; got: {msg}"
                );
                assert!(
                    msg.contains("with_executor"),
                    "error must name the with_executor constructor; got: {msg}"
                );
            }
            other => panic!("expected SdkError::Policy; got: {other:?}"),
        }
    }

    /// Wave 4 + T-402 (mount share): `AdrianPySdk::mount_share`
    /// delegates to `sdk.file.mount_share`. The default stub returns
    /// `Err(SdkError::File(...))`, which the Python binding surfaces
    /// as `None`. We test the pure-Rust `_core` method.
    #[test]
    fn wave4_pysdk_mount_share_returns_err_with_default_stub() {
        let sdk = AdrianPySdk::new();
        let result = sdk.mount_share_core("dc01.adrian.example", "sysvol");
        assert!(
            result.is_err(),
            "default stub must return Err; got: {result:?}"
        );
        match result {
            Err(adrian_sdk::SdkError::File(msg)) => {
                assert!(
                    msg.contains("dc01.adrian.example"),
                    "error must contain server; got: {msg}"
                );
                assert!(
                    msg.contains("sysvol"),
                    "error must contain share; got: {msg}"
                );
                assert!(
                    msg.contains("with_smb_addr"),
                    "error must name the with_smb_addr constructor; got: {msg}"
                );
            }
            other => panic!("expected SdkError::File; got: {other:?}"),
        }
    }
}
