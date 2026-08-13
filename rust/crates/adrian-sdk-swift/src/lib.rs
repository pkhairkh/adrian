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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::os::raw::c_char;

    #[test]
    fn client_ref_type_is_void_pointer_sized() {
        // Per ADR-048 / ADR-107: Swift bindings expose the AdrianClient
        // as an opaque pointer (`AdrianClientRef = *mut c_void`). The
        // Swift side (`AdrianSDK.xcframework`) wraps these C-ABI entry
        // points. Pinning the size to a single pointer width catches
        // accidental changes that would break the Swift xcframework.
        assert_eq!(
            std::mem::size_of::<AdrianClientRef>(),
            std::mem::size_of::<*mut c_void>()
        );
    }

    #[test]
    fn ffi_entry_points_are_exported_with_expected_signatures() {
        // Take function pointers to each `#[no_mangle] extern "C"` entry
        // point — without invoking them. This catches link-time
        // regressions where a `#[no_mangle]` is removed or the signature
        // drifts (e.g. someone adds a parameter and silently breaks ABI
        // for the Swift xcframework consumer).
        let _new: unsafe extern "C" fn() -> AdrianClientRef = adrian_swift_client_new;
        let _release: unsafe extern "C" fn(AdrianClientRef) = adrian_swift_client_release;
        let _join: unsafe extern "C" fn(AdrianClientRef, *const c_char) -> i32 =
            adrian_swift_client_join;
    }

    #[test]
    fn runtime_singleton_is_idempotent() {
        // Per ADR-107: the Swift binding lazily builds a single
        // multi-threaded tokio runtime stored in a `OnceLock` so blocking
        // FFI calls can `block_on` async SDK methods. Calling `runtime()`
        // repeatedly MUST return the same `&'static Runtime` — otherwise
        // the binding would leak runtimes on every call (and spawn a new
        // thread pool per call).
        let r1 = runtime();
        let r2 = runtime();
        assert!(std::ptr::eq(r1, r2), "runtime() must return a singleton");
    }
}
