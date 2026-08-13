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
//!
//! ## Crate-level safety
//!
//! `#![deny(unsafe_code)]` is the framework-wide safety posture. The C ABI
//! is the exception: FFI inherently requires `unsafe` because (a) raw
//! pointers from C are not borrow-checked, (b) the calling convention
//! `extern "C"` is itself an unsafe boundary, and (c) lifetime / aliasing
//! guarantees cannot be enforced across the FFI divide.
//!
//! Each `#[no_mangle] pub unsafe extern "C" fn ...` entry point below
//! carries `#[allow(unsafe_code)]` plus a `# Safety` doc-section that
//! spells out the caller's responsibility (valid handle, valid C string,
//! valid buffer length, etc.). The `deny` at crate root catches any
//! *unintended* unsafe code (e.g. a stray `unsafe { ... }` block in a
//! helper function); the `allow` on each entry point is deliberate.

#![deny(unsafe_code)]

use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;

use adrian_sdk::AdrianClient;
use adrian_sdk::AdrianSdk;
use adrian_sdk::AuthToken;

/// Opaque client handle (legacy `AdrianClient` per ADR-107 original
/// draft). Re-exported for backward compatibility with Wave 4 FFI
/// consumers (`adrian_client_*` family).
pub type AdrianClientHandle = *mut c_void;

/// Opaque SDK handle (new `AdrianSdk` per ADR-107 §Decision). Returned
/// by `adrian_sdk_new`; freed by `adrian_sdk_free`.
pub type AdrianSdkHandle = *mut c_void;

/// Opaque auth-token handle. Returned by `adrian_sdk_auth_kerberos` (and
/// the other `adrian_sdk_auth_*` entry points); freed by
/// `adrian_auth_token_free`.
pub type AuthTokenHandle = *mut c_void;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build adrian-sdk-c runtime")
    })
}

// =========================================================================
// Legacy AdrianClient FFI (Wave 4 stub surface — kept for backward
// compatibility; new consumers should use `adrian_sdk_*` below).
// =========================================================================

/// Construct a new legacy client. Caller must free with `adrian_client_free`.
///
/// # Safety
/// Returns a heap pointer; caller owns it.
#[no_mangle]
#[allow(unsafe_code)]
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
#[allow(unsafe_code)]
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
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_client_join(
    handle: AdrianClientHandle,
    domain: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let client = &*(handle as *const AdrianClient);
    let domain_str = if domain.is_null() {
        String::new()
    } else {
        CStr::from_ptr(domain).to_string_lossy().into_owned()
    };
    let result = runtime().block_on(async { client.join(&domain_str).await });
    match result {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

// =========================================================================
// New unified SDK FFI (Wave 5a — ADR-107 §Decision).
//
// The `adrian_sdk_*` family exposes the new builder-constructed
// `AdrianSdk` core + trait-object module API to C/C++/Go/Ruby/Node hosts.
// Internally creates an `AdrianSdk::with_default_stubs()` (the framework's
// standard stub impls) and routes calls through `runtime().block_on(...)`.
//
// Per ADR-107 §Consequences: this crate is the foundation for all other
// bindings (JNI, Swift, Python, Go) — every language with FFI calls
// through these entry points.
// =========================================================================

/// Construct a new `AdrianSdk` with the framework's default stub module
/// impls (`KerberosAuthModule`, `LdapDirectoryModule`,
/// `DeclarativePolicyModule`, `SmbFileModule`, `AcmeCertModule`).
///
/// Production callers inject custom impls via the Rust `AdrianSdk::builder()`
/// API; the C ABI exposes only the default-stub construction today.
///
/// Returns an opaque heap pointer; caller MUST free with `adrian_sdk_free`.
/// Returns NULL on allocation failure (extremely unlikely — the SDK
/// constructor is infallible per `AdrianSdk::with_default_stubs`).
///
/// # Safety
/// The returned pointer is owned by the caller until `adrian_sdk_free`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_sdk_new() -> AdrianSdkHandle {
    let sdk = Box::new(AdrianSdk::with_default_stubs());
    Box::into_raw(sdk) as AdrianSdkHandle
}

/// Free an `AdrianSdk` previously returned by `adrian_sdk_new`.
///
/// # Safety
/// `handle` MUST be a valid pointer returned by `adrian_sdk_new` and not
/// previously freed. Passing NULL is a no-op.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_sdk_free(handle: AdrianSdkHandle) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut AdrianSdk));
}

/// Authenticate via Kerberos (password-based, RFC 4120 AS-REQ).
///
/// On success, returns an opaque `AuthTokenHandle` (caller MUST free with
/// `adrian_auth_token_free`). On failure, returns NULL — call
/// `adrian_last_error_message()` (TODO Wave 5b) for the error string.
///
/// # Safety
/// - `handle` MUST be a valid `AdrianSdkHandle` from `adrian_sdk_new`.
/// - `principal` MUST be a NUL-terminated UTF-8 C string, or NULL
///   (treated as the empty string).
/// - `password` MUST be a NUL-terminated UTF-8 C string, or NULL.
/// - The returned `AuthTokenHandle` is owned by the caller until freed.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_sdk_auth_kerberos(
    handle: AdrianSdkHandle,
    principal: *const c_char,
    password: *const c_char,
) -> AuthTokenHandle {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let sdk = &*(handle as *const AdrianSdk);
    let principal_str = cstr_to_string(principal);
    let password_str = cstr_to_string(password);
    let result = runtime().block_on(async {
        sdk.auth
            .authenticate_kerberos(&principal_str, &password_str)
            .await
    });
    match result {
        Ok(token) => {
            let boxed = Box::new(token);
            Box::into_raw(boxed) as AuthTokenHandle
        }
        Err(_err) => std::ptr::null_mut(),
    }
}

/// Free an `AuthToken` previously returned by `adrian_sdk_auth_kerberos`
/// (or any of the `adrian_sdk_auth_*` entry points).
///
/// # Safety
/// `handle` MUST be a valid `AuthTokenHandle` from one of the
/// `adrian_sdk_auth_*` functions, or NULL. Passing NULL is a no-op.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_auth_token_free(handle: AuthTokenHandle) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut AuthToken));
}

/// Get the principal string from an `AuthToken`.
///
/// Returns a NUL-terminated UTF-8 C string owned by the caller. The
/// caller MUST free it with `adrian_free_string`. Returns NULL if
/// `handle` is NULL or if the principal contains an interior NUL byte
/// (impossible for valid UPN/SPN strings).
///
/// # Safety
/// - `handle` MUST be a valid `AuthTokenHandle` from one of the
///   `adrian_sdk_auth_*` functions, or NULL.
/// - The returned `*const c_char` is owned by the caller until freed
///   with `adrian_free_string`. Use-after-free is undefined behavior.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_auth_token_get_principal(handle: AuthTokenHandle) -> *const c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    let token = &*(handle as *const AuthToken);
    match CString::new(token.principal.as_str()) {
        Ok(s) => s.into_raw(),
        // Principal contains an interior NUL — invalid UPN/SPN. Return
        // NULL so the caller can detect the failure.
        Err(_) => std::ptr::null(),
    }
}

/// Free a C string previously returned by `adrian_auth_token_get_principal`
/// (or any future `adrian_*` function that returns a `*const c_char`
/// owned by the caller).
///
/// # Safety
/// - `ptr` MUST be a valid pointer returned by `CString::into_raw`
///   (i.e. by `adrian_auth_token_get_principal` or a similar function),
///   or NULL. Passing any other pointer is undefined behavior.
/// - The pointer MUST NOT have been previously freed (double-free is UB).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_free_string(ptr: *const c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr as *mut c_char));
}

/// Helper: convert a possibly-NULL `*const c_char` into a Rust `String`.
/// NULL becomes the empty string. Invalid UTF-8 is replaced with the
/// replacement character (per `CStr::to_string_lossy`).
///
/// This helper is safe to call with any `*const c_char` (including NULL);
/// the unsafe `CStr::from_ptr` deref is wrapped here.
#[allow(unsafe_code)]
unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::os::raw::c_char;

    #[test]
    fn handle_type_is_void_pointer_sized() {
        // Per ADR-107: the C ABI exposes AdrianClient as an opaque void
        // pointer. Callers (C/C++/Go/Ruby/Node hosts) must never deref
        // into the struct layout — the handle is only valid for passing
        // back to the `adrian_client_*` family. This test pins the
        // handle to a single-pointer-sized type so any future change to
        // the alias (e.g. accidentally exposing the inner type) is
        // caught at compile/test time.
        assert_eq!(
            std::mem::size_of::<AdrianClientHandle>(),
            std::mem::size_of::<*mut c_void>()
        );
    }

    #[test]
    fn ffi_entry_points_are_exported_with_expected_signatures() {
        // Take function pointers to each `#[no_mangle] extern "C"` entry
        // point — without invoking them. This catches link-time
        // regressions where a `#[no_mangle]` is removed or the signature
        // drifts (e.g. someone adds a parameter and silently breaks ABI
        // for downstream cbindgen-generated headers).
        let _new: unsafe extern "C" fn() -> AdrianClientHandle = adrian_client_new;
        let _free: unsafe extern "C" fn(AdrianClientHandle) = adrian_client_free;
        let _join: unsafe extern "C" fn(AdrianClientHandle, *const c_char) -> i32 =
            adrian_client_join;
    }

    #[test]
    fn runtime_singleton_is_idempotent() {
        // Per ADR-107: the C ABI lazily builds a single multi-threaded
        // tokio runtime stored in a `OnceLock` so blocking FFI calls can
        // `block_on` async SDK methods. Calling `runtime()` repeatedly
        // MUST return the same `&'static Runtime` — otherwise the
        // binding would leak runtimes on every call.
        let r1 = runtime();
        let r2 = runtime();
        assert!(std::ptr::eq(r1, r2), "runtime() must return a singleton");
    }

    // -----------------------------------------------------------------
    // Wave 5a tests — new unified SDK FFI entry points.
    // -----------------------------------------------------------------

    #[test]
    fn sdk_handle_aliases_are_pointer_sized() {
        // Per ADR-107: the C ABI exposes `AdrianSdk` and `AuthToken`
        // as opaque void pointers. Pin both to pointer-size so any
        // accidental widening (e.g. to a struct) is caught here rather
        // than as an ABI break for downstream cbindgen consumers.
        assert_eq!(
            std::mem::size_of::<AdrianSdkHandle>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<AuthTokenHandle>(),
            std::mem::size_of::<*mut c_void>()
        );
    }

    #[test]
    fn new_ffi_entry_points_are_exported_with_expected_signatures() {
        // Function-pointer probe — catches ABI drift in the Wave 5a
        // `adrian_sdk_*` / `adrian_auth_token_*` / `adrian_free_string`
        // family. Per ADR-107 §Consequences, this is the foundation for
        // JNI / Swift / Python / Go bindings, so the signatures MUST
        // remain stable.
        let _sdk_new: unsafe extern "C" fn() -> AdrianSdkHandle = adrian_sdk_new;
        let _sdk_free: unsafe extern "C" fn(AdrianSdkHandle) = adrian_sdk_free;
        let _auth_kerb: unsafe extern "C" fn(
            AdrianSdkHandle,
            *const c_char,
            *const c_char,
        ) -> AuthTokenHandle = adrian_sdk_auth_kerberos;
        let _tok_free: unsafe extern "C" fn(AuthTokenHandle) = adrian_auth_token_free;
        let _get_princ: unsafe extern "C" fn(AuthTokenHandle) -> *const c_char =
            adrian_auth_token_get_principal;
        let _free_str: unsafe extern "C" fn(*const c_char) = adrian_free_string;
    }

    #[allow(unsafe_code)]
    #[test]
    fn adrian_sdk_new_returns_non_null_handle() {
        // `adrian_sdk_new` constructs an `AdrianSdk::with_default_stubs()`
        // on the heap and returns the raw pointer. MUST be non-null
        // (the stub constructors are infallible per ADR-107 §Decision).
        // SAFETY: `adrian_sdk_new` returns a fresh heap pointer; we free
        // it immediately with `adrian_sdk_free`.
        let handle = unsafe { adrian_sdk_new() };
        assert!(!handle.is_null(), "adrian_sdk_new must return non-null");
        // SAFETY: `handle` was just returned by `adrian_sdk_new`.
        unsafe { adrian_sdk_free(handle) };
    }

    #[allow(unsafe_code)]
    #[test]
    fn adrian_sdk_free_accepts_null_without_crashing() {
        // Per the safety contract on `adrian_sdk_free`: passing NULL
        // MUST be a no-op (defensive free). This matches the C standard
        // `free(NULL)` convention.
        // SAFETY: NULL is explicitly documented as a no-op for all three
        // free functions.
        unsafe {
            adrian_sdk_free(std::ptr::null_mut());
            adrian_auth_token_free(std::ptr::null_mut());
            adrian_free_string(std::ptr::null());
        }
    }

    #[allow(unsafe_code)]
    #[test]
    fn adrian_sdk_auth_kerberos_returns_null_for_stub_failure() {
        // The default `KerberosAuthModule` stub returns
        // `Err(SdkError::Auth(...))` per ADR-108 — the C ABI MUST
        // surface that failure as NULL (the FFI equivalent of
        // `Result::Err`). Returning a non-null token would silently
        // mislead C callers into thinking they have a TGT.
        //
        // SAFETY: `handle` is fresh from `adrian_sdk_new` and is freed
        // before this test returns. The C string literals are valid
        // NUL-terminated UTF-8.
        let handle = unsafe { adrian_sdk_new() };
        assert!(!handle.is_null());
        let principal = c"alice@ADRIAN.EXAMPLE".as_ptr();
        let password = c"password123".as_ptr();
        let token = unsafe { adrian_sdk_auth_kerberos(handle, principal, password) };
        assert!(
            token.is_null(),
            "stub auth must surface NULL — got non-null token"
        );
        // SAFETY: `handle` was just returned by `adrian_sdk_new`.
        unsafe { adrian_sdk_free(handle) };
    }
}
