//! # adrian-sdk-jni
//!
//! JNI bindings for Java/Kotlin consumers. Internally holds a tokio runtime
//! and exposes `dev.adrian.sdk.AdrianClient` Java class with native methods.
//!
//! ## ADRs
//!
//! - ADR-107: Unified Rust core SDK
//! - ADR-108: SSPI-equivalent auth abstraction

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jlong};
use jni::JNIEnv;
use std::sync::OnceLock;

use adrian_sdk::AdrianClient;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build adrian-sdk-jni runtime")
    })
}

/// `dev.adrian.sdk.AdrianClient.newClient()` native impl.
///
/// # Safety
/// JNI contract — `env` and `class` must be valid JNI handles.
#[no_mangle]
pub unsafe extern "system" fn Java_dev_adrian_sdk_AdrianClient_newClient(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let client = Box::new(AdrianClient::new());
    Box::into_raw(client) as jlong
}

/// `dev.adrian.sdk.AdrianClient.join(domain)` native impl.
///
/// # Safety
/// JNI contract — pointers must be valid.
#[no_mangle]
pub unsafe extern "system" fn Java_dev_adrian_sdk_AdrianClient_join(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    domain: JString,
) -> jboolean {
    if handle == 0 {
        return 0;
    }
    let client = &mut *(handle as *mut AdrianClient);
    let domain_str: String = env
        .get_string(&domain)
        .map(|s| s.into())
        .unwrap_or_default();
    let result = runtime().block_on(async { client.join(&domain_str).await });
    match result {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Free the native handle.
///
/// # Safety
/// JNI contract.
#[no_mangle]
pub unsafe extern "system" fn Java_dev_adrian_sdk_AdrianClient_free(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    drop(Box::from_raw(handle as *mut AdrianClient));
}

// =========================================================================
// Wave 3: New `AdrianSdk` JNI entry points (ADR-107).
//
// The legacy `AdrianClient_*` JNI functions above wrap the original
// `AdrianClient::new()` / `join()` surface (Wave 4 stub). Wave 3 adds
// the new `AdrianSdk` JNI surface that routes through the C ABI in
// `adrian-sdk-c` per ADR-107 §Consequences: the C ABI is the
// foundation for every language binding (JNI, Swift, Python, Go), so
// JNI's `AdrianSdk` class delegates to `adrian_sdk_c::adrian_sdk_*`
// rather than calling `adrian_sdk::AdrianSdk` directly. This keeps ABI
// stability + error handling consistent across all bindings.
//
// The Java class `dev.adrian.sdk.AdrianSdk` exposes:
// - `newSdk()` — `Java_dev_adrian_sdk_AdrianSdk_newSdk`
// - `freeSdk(handle)` — `Java_dev_adrian_sdk_AdrianSdk_freeSdk`
// - `authenticateKerberos(handle, principal, password) -> long` —
//   `Java_dev_adrian_sdk_AdrianSdk_authenticateKerberos`
//
// Returns a `jlong` carrying the `AuthTokenHandle` (0 on failure —
// matches the C ABI convention where null means error).
// =========================================================================

/// `dev.adrian.sdk.AdrianSdk.newSdk()` native impl. Constructs an
/// `AdrianSdk` via `adrian_sdk_c::adrian_sdk_new()` and returns the
/// handle as a `jlong`. Caller MUST free with `freeSdk(handle)`.
///
/// # Safety
/// JNI contract — `env` and `class` must be valid JNI handles. The
/// returned `jlong` is a heap pointer owned by the caller until
/// `freeSdk` is invoked.
#[no_mangle]
pub unsafe extern "system" fn Java_dev_adrian_sdk_AdrianSdk_newSdk(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    // SAFETY: `adrian_sdk_c::adrian_sdk_new` is `unsafe extern "C"` because
    // it returns a raw heap pointer; calling it from a JNI native method
    // is safe as long as the caller eventually frees the handle (which
    // `freeSdk` does).
    let handle = unsafe { adrian_sdk_c::adrian_sdk_new() };
    handle as jlong
}

/// `dev.adrian.sdk.AdrianSdk.freeSdk(handle)` native impl. Calls
/// `adrian_sdk_c::adrian_sdk_free(handle)`. Passing `0` is a no-op.
///
/// # Safety
/// JNI contract — `handle` MUST be a valid `jlong` returned by `newSdk`
/// and not previously freed (double-free is UB).
#[no_mangle]
pub unsafe extern "system" fn Java_dev_adrian_sdk_AdrianSdk_freeSdk(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: `handle` was returned by `newSdk` (which wraps
    // `adrian_sdk_c::adrian_sdk_new`); casting it back to the C ABI's
    // `AdrianSdkHandle` (`*mut c_void`) and freeing via
    // `adrian_sdk_c::adrian_sdk_free` matches the C ABI's ownership
    // contract.
    unsafe {
        adrian_sdk_c::adrian_sdk_free(handle as adrian_sdk_c::AdrianSdkHandle);
    }
}

/// `dev.adrian.sdk.AdrianSdk.authenticateKerberos(handle, principal, password)`
/// native impl. Calls `adrian_sdk_c::adrian_sdk_auth_kerberos(...)` and
/// returns the AuthToken handle as a `jlong`. Returns `0` on failure
/// (matching the C ABI's null-on-error convention) — Java callers should
/// check for `0L` and surface an error to the user.
///
/// # Safety
/// JNI contract — `handle` MUST be valid; `principal` and `password` MUST
/// be valid `JString` references (or `null`, treated as empty strings).
#[no_mangle]
pub unsafe extern "system" fn Java_dev_adrian_sdk_AdrianSdk_authenticateKerberos(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    principal: JString,
    password: JString,
) -> jlong {
    if handle == 0 {
        return 0;
    }
    // Convert JString -> String -> CString. Invalid UTF-16 / interior NULs
    // fall back to empty strings (matching the C ABI's null-means-empty
    // convention).
    let principal_str: String = env
        .get_string(&principal)
        .map(|s| s.into())
        .unwrap_or_default();
    let password_str: String = env
        .get_string(&password)
        .map(|s| s.into())
        .unwrap_or_default();
    let principal_c = std::ffi::CString::new(principal_str).unwrap_or_default();
    let password_c = std::ffi::CString::new(password_str).unwrap_or_default();
    // SAFETY: `handle` was returned by `newSdk`; `principal_c` and
    // `password_c` are valid NUL-terminated C strings. The C ABI's
    // `adrian_sdk_auth_kerberos` accepts these and returns either a valid
    // `AuthTokenHandle` or NULL.
    let token_handle = unsafe {
        adrian_sdk_c::adrian_sdk_auth_kerberos(
            handle as adrian_sdk_c::AdrianSdkHandle,
            principal_c.as_ptr(),
            password_c.as_ptr(),
        )
    };
    token_handle as jlong
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jni_entry_points_are_exported_with_expected_signatures() {
        // Per ADR-107: the JNI binding exposes the AdrianClient Java class
        // via three `extern "system"` (Windows stdcall on x86 JNI, C ABI
        // elsewhere) native methods. We take function pointers — without
        // invoking the FFI — so any drift in `#[no_mangle]` or the
        // argument types (JNIEnv/JClass/JString/JLong/JBoolean) is caught
        // at test time rather than at JVM link time on a downstream
        // consumer.
        let _new: unsafe extern "system" fn(JNIEnv, JClass) -> jlong =
            Java_dev_adrian_sdk_AdrianClient_newClient;
        let _join: unsafe extern "system" fn(JNIEnv, JClass, jlong, JString) -> jboolean =
            Java_dev_adrian_sdk_AdrianClient_join;
        let _free: unsafe extern "system" fn(JNIEnv, JClass, jlong) =
            Java_dev_adrian_sdk_AdrianClient_free;
    }

    #[test]
    fn runtime_singleton_is_idempotent() {
        // The JNI binding stores its tokio runtime in a `OnceLock` so
        // every native method `block_on`s on the same multi-threaded
        // runtime. Repeated `runtime()` calls MUST return the same
        // `&'static Runtime` — otherwise the binding would leak a fresh
        // runtime per call (each carrying its own thread pool).
        let r1 = runtime();
        let r2 = runtime();
        assert!(std::ptr::eq(r1, r2), "runtime() must return a singleton");
    }

    #[test]
    fn jni_symbols_use_system_abi() {
        // JNI on Windows x86 uses stdcall (`extern "system"`); everywhere
        // else `extern "system"` resolves to the C ABI. Taking the
        // pointer as `extern "system"` (rather than `extern "C"`)
        // verifies the binding uses the JNI-correct ABI — a common
        // Windows-JVM crash source if accidentally declared as `extern "C"`.
        let _new: unsafe extern "system" fn(JNIEnv, JClass) -> jlong =
            Java_dev_adrian_sdk_AdrianClient_newClient;
        let _ = _new; // pin the symbol; do not invoke
    }

    // -----------------------------------------------------------------
    // Wave 3 tests — new `AdrianSdk` JNI entry points that route
    // through `adrian-sdk-c` per ADR-107 §Consequences.
    // -----------------------------------------------------------------

    #[test]
    fn wave3_adrian_sdk_jni_entry_points_are_exported() {
        // Function-pointer probe — catches ABI drift in the Wave 3
        // `Java_dev_adrian_sdk_AdrianSdk_*` family. Per ADR-107
        // §Consequences, this is the canonical JNI surface that other
        // JVM consumers (Kotlin, Scala, Clojure) link against, so the
        // signatures MUST remain stable.
        let _new: unsafe extern "system" fn(JNIEnv, JClass) -> jlong =
            Java_dev_adrian_sdk_AdrianSdk_newSdk;
        let _free: unsafe extern "system" fn(JNIEnv, JClass, jlong) =
            Java_dev_adrian_sdk_AdrianSdk_freeSdk;
        let _auth: unsafe extern "system" fn(JNIEnv, JClass, jlong, JString, JString) -> jlong =
            Java_dev_adrian_sdk_AdrianSdk_authenticateKerberos;
    }

    /// Wave 3 JNI join round-trip: invoke `Java_dev_adrian_sdk_AdrianSdk_newSdk`
    /// and verify it returns a non-zero `jlong` (i.e. a valid SDK handle
    /// via `adrian_sdk_c::adrian_sdk_new`). Then free it via
    /// `Java_dev_adrian_sdk_AdrianSdk_freeSdk` and verify the call is a
    /// no-op on handle `0` (defensive free).
    ///
    /// We can't load a JVM in a unit test, but we CAN invoke the JNI
    /// function via its Rust entry point — the JNIEnv isn't actually
    /// dereferenced by `newSdk` (only `freeSdk` ignores it; `newSdk`
    /// just calls `adrian_sdk_c::adrian_sdk_new()`). To pass a JNIEnv,
    /// we'd need to construct one, which requires a JVM — instead, we
    /// verify the call path indirectly by invoking the underlying
    /// `adrian_sdk_c::adrian_sdk_new` / `_free` directly and confirming
    /// they return / accept valid handles.
    #[test]
    fn wave3_jni_join_round_trip_via_c_abi() {
        // SAFETY: `adrian_sdk_c::adrian_sdk_new` is `unsafe extern "C"`
        // because it returns a raw heap pointer; calling it from a test
        // is safe as long as we free the handle via `adrian_sdk_free`.
        let handle = unsafe { adrian_sdk_c::adrian_sdk_new() };
        assert!(
            !handle.is_null(),
            "adrian_sdk_new must return a non-null handle"
        );
        // SAFETY: `handle` was just returned by `adrian_sdk_new`; the
        // ownership contract is satisfied by this `adrian_sdk_free` call.
        unsafe { adrian_sdk_c::adrian_sdk_free(handle) };
        // Defensive free: passing NULL MUST be a no-op (matches the C
        // standard `free(NULL)` convention per the safety contract on
        // `adrian_sdk_free`).
        // SAFETY: NULL is explicitly documented as a no-op.
        unsafe { adrian_sdk_c::adrian_sdk_free(std::ptr::null_mut()) };
    }

    /// Wave 3 JNI auth round-trip: invoke the underlying
    /// `adrian_sdk_c::adrian_sdk_auth_kerberos` (the same C function
    /// `Java_dev_adrian_sdk_AdrianSdk_authenticateKerberos` calls) with
    /// a fresh SDK handle + a stub principal/password. The default stub
    /// `KerberosAuthModule` returns `Err(SdkError::Auth(...))`, which
    /// the C ABI surfaces as NULL — proving the auth dispatch path is
    /// alive (round-trip through the C ABI → SDK trait object → stub
    /// error → NULL).
    #[test]
    fn wave3_jni_auth_round_trip_surfaces_stub_error_as_null() {
        // SAFETY: `adrian_sdk_new` is `unsafe extern "C"`; calling it
        // returns a fresh heap pointer we free at the end.
        let handle = unsafe { adrian_sdk_c::adrian_sdk_new() };
        assert!(!handle.is_null());
        let principal = c"alice@ADRIAN.EXAMPLE";
        let password = c"pw";
        // SAFETY: `handle` is valid; `principal` and `password` are
        // valid NUL-terminated C string literals.
        let token = unsafe {
            adrian_sdk_c::adrian_sdk_auth_kerberos(handle, principal.as_ptr(), password.as_ptr())
        };
        // The default stub returns Err(SdkError::Auth(...)) — the C ABI
        // surfaces that as NULL. A non-null token would mean the stub
        // returned Ok, which would silently mislead Java callers into
        // thinking they have a TGT.
        assert!(
            token.is_null(),
            "default stub must surface NULL (token handle); got non-null"
        );
        // SAFETY: `handle` was returned by `adrian_sdk_new` above and
        // hasn't been freed.
        unsafe { adrian_sdk_c::adrian_sdk_free(handle) };
    }
}
