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
