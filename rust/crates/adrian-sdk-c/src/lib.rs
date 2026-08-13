//! # adrian-sdk-c
//!
//! C ABI bindings for `adrian-sdk`. Generated headers via `cbindgen` for
//! consumption by C/C++/Go/Ruby/Node hosts. Internally creates a tokio
//! runtime and `block_on`s for blocking API.
//!
//! ## ADRs
//!
//! - ADR-107: Unified Rust core SDK
//! - ADR-108: SSPI-equivalent auth abstraction (C ABI exposed as `AdrianAuth*`)
//! - ADR-109: Cross-platform LDAP client (C ABI for `ldap_adrian_*`)

use std::ffi::c_void;
use std::sync::OnceLock;

use adrian_sdk::AdrianClient;

/// Opaque client handle.
pub type AdrianClientHandle = *mut c_void;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build adrian-sdk-c runtime")
    })
}

/// Construct a new client. Caller must free with `adrian_client_free`.
///
/// # Safety
/// Returns a heap pointer; caller owns it.
#[no_mangle]
pub unsafe extern "C" fn adrian_client_new() -> AdrianClientHandle {
    let client = Box::new(AdrianClient::new());
    Box::into_raw(client) as AdrianClientHandle
}

/// Free a client previously returned by `adrian_client_new`.
///
/// # Safety
/// `handle` must be a valid pointer returned by `adrian_client_new` and not
/// previously freed.
#[no_mangle]
pub unsafe extern "C" fn adrian_client_free(handle: AdrianClientHandle) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut AdrianClient));
}

/// Blocking join — wraps `AdrianClient::join` via `block_on`.
///
/// # Safety
/// `handle` must be valid; `domain` must be a null-terminated C string or NULL.
#[no_mangle]
pub unsafe extern "C" fn adrian_client_join(
    handle: AdrianClientHandle,
    domain: *const std::os::raw::c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let client = &*(handle as *const AdrianClient);
    let domain_str = if domain.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(domain)
            .to_string_lossy()
            .into_owned()
    };
    let result = runtime().block_on(async { client.join(&domain_str).await });
    match result {
        Ok(()) => 0,
        Err(_) => -2,
    }
}
