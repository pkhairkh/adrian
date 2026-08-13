//! # adrian-sdk-swift
//!
//! Swift bindings for the Adrian SDK. Compiled as a static library consumed
//! by `AdrianSDK.xcframework`. The Swift side wraps these C-ABI entry points
//! via `swift-bridge` (integration pending — currently uses hand-rolled C ABI).
//!
//! ## ADRs
//!
//! - ADR-048: PSSO Extension + macOS join
//! - ADR-056: Modern macOS Kerberos path (PSSO)
//! - ADR-107: Unified Rust core SDK
//! - ADR-112: macOS NTLM client Rust crate
//! - ADR-117: Apple Heimdal fork staleness mitigated

use std::ffi::c_void;
use std::sync::OnceLock;

use adrian_sdk::AdrianClient;

/// Opaque Swift-facing handle.
pub type AdrianClientRef = *mut c_void;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build adrian-sdk-swift runtime")
    })
}

/// Construct a new client. Pair with `adrian_swift_client_release`.
///
/// # Safety
/// Returns a heap pointer; caller must release.
#[no_mangle]
pub unsafe extern "C" fn adrian_swift_client_new() -> AdrianClientRef {
    let client = Box::new(AdrianClient::new());
    Box::into_raw(client) as AdrianClientRef
}

/// Release a client.
///
/// # Safety
/// `handle` must be a valid pointer returned by `adrian_swift_client_new`.
#[no_mangle]
pub unsafe extern "C" fn adrian_swift_client_release(handle: AdrianClientRef) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut AdrianClient));
}

/// Blocking join. Returns 0 on success, negative on error.
///
/// # Safety
/// `handle` and `domain` (null-terminated C string) must be valid.
#[no_mangle]
pub unsafe extern "C" fn adrian_swift_client_join(
    handle: AdrianClientRef,
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
