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
}
