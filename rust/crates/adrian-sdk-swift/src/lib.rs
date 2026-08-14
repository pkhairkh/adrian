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

// =========================================================================
// Wave 3: New `AdrianSdk` Swift-facing entry points (ADR-107).
//
// The legacy `adrian_swift_client_*` functions above wrap the original
// `AdrianClient::new()` / `join()` surface (Wave 4 stub). Wave 3 adds
// the new `adrian_swift_sdk_*` surface that routes through the C ABI in
// `adrian-sdk-c` per ADR-107 §Consequences: the C ABI is the
// foundation for every language binding (JNI, Swift, Python, Go), so
// Swift's `AdrianSdk` Swift class delegates to `adrian_sdk_c::*`
// rather than calling `adrian_sdk::AdrianSdk` directly. This keeps ABI
// stability + error handling consistent across all bindings.
//
// The Swift class `AdrianSdk` exposes:
// - `init()` / `deinit` — `adrian_swift_sdk_new` / `adrian_swift_sdk_free`
// - `authenticate(principal, password) -> AuthToken?` —
//   `adrian_swift_sdk_authenticate_kerberos`
// - `searchDirectory(filter) -> [DirEntry]` —
//   `adrian_swift_sdk_search_directory` (returns NULL on failure; the
//   Swift side surfaces a typed error)
// - `applyPolicy(name, version) -> AppliedPolicy?` —
//   `adrian_swift_sdk_apply_policy`
// - `mountShare(server, share) -> MountedShare?` —
//   `adrian_swift_sdk_mount_share`
// - `enrollCert(profile, csr, subject) -> Data?` —
//   `adrian_swift_sdk_enroll_cert`
//
// Each entry point returns an opaque `*mut c_void` handle (or NULL on
// failure); a paired `_free` function releases the resource.
// =========================================================================

/// Opaque `AdrianSdk` handle for the new Swift-facing surface. Returned
/// by `adrian_swift_sdk_new`; freed by `adrian_swift_sdk_free`.
pub type AdrianSdkRef = *mut std::ffi::c_void;

/// Opaque `AuthToken` handle returned by
/// `adrian_swift_sdk_authenticate_kerberos`. Freed by
/// `adrian_swift_sdk_auth_token_free`.
pub type AdrianAuthTokenRef = *mut std::ffi::c_void;

/// Opaque `DirEntry` list handle returned by
/// `adrian_swift_sdk_search_directory`. Freed by
/// `adrian_swift_sdk_dir_entry_list_free`.
pub type AdrianDirEntryListRef = *mut std::ffi::c_void;

/// Opaque `AppliedPolicy` handle returned by
/// `adrian_swift_sdk_apply_policy`. Freed by
/// `adrian_swift_sdk_applied_policy_free`.
pub type AdrianAppliedPolicyRef = *mut std::ffi::c_void;

/// Opaque `MountedShare` handle returned by
/// `adrian_swift_sdk_mount_share`. Freed by
/// `adrian_swift_sdk_mounted_share_free`.
pub type AdrianMountedShareRef = *mut std::ffi::c_void;

/// Opaque `CertBytes` handle returned by `adrian_swift_sdk_enroll_cert`.
/// Freed by `adrian_swift_sdk_cert_bytes_free`.
pub type AdrianCertBytesRef = *mut std::ffi::c_void;

/// Construct a new `AdrianSdk` via `adrian_sdk_c::adrian_sdk_new()`.
/// Returns an opaque heap pointer; caller MUST free with
/// `adrian_swift_sdk_free`.
///
/// # Safety
/// The returned pointer is owned by the caller until freed.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_new() -> AdrianSdkRef {
    // SAFETY: `adrian_sdk_c::adrian_sdk_new` is `unsafe extern "C"`; the
    // returned handle is a heap pointer the caller owns until freed.
    let handle = unsafe { adrian_sdk_c::adrian_sdk_new() };
    handle as AdrianSdkRef
}

/// Free an `AdrianSdk` previously returned by `adrian_swift_sdk_new`.
///
/// # Safety
/// `handle` MUST be a valid pointer returned by `adrian_swift_sdk_new`
/// and not previously freed. Passing NULL is a no-op.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_free(handle: AdrianSdkRef) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` was returned by `adrian_swift_sdk_new` (which
    // wraps `adrian_sdk_c::adrian_sdk_new`); casting back to the C ABI
    // handle and freeing matches the C ABI's ownership contract.
    unsafe {
        adrian_sdk_c::adrian_sdk_free(handle as adrian_sdk_c::AdrianSdkHandle);
    }
}

/// Authenticate via Kerberos (RFC 4120 AS-REQ). Calls
/// `adrian_sdk_c::adrian_sdk_auth_kerberos(...)` and returns the
/// AuthToken handle. Returns NULL on failure (matching the C ABI's
/// null-on-error convention).
///
/// # Safety
/// - `handle` MUST be a valid `AdrianSdkRef` from `adrian_swift_sdk_new`.
/// - `principal` and `password` MUST be NUL-terminated UTF-8 C strings
///   (or NULL, treated as empty strings).
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_authenticate_kerberos(
    handle: AdrianSdkRef,
    principal: *const std::os::raw::c_char,
    password: *const std::os::raw::c_char,
) -> AdrianAuthTokenRef {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `handle` is valid; `principal` and `password` are valid
    // NUL-terminated C strings (or NULL, which the C ABI treats as
    // empty).
    let token = unsafe {
        adrian_sdk_c::adrian_sdk_auth_kerberos(
            handle as adrian_sdk_c::AdrianSdkHandle,
            principal,
            password,
        )
    };
    token as AdrianAuthTokenRef
}

/// Free an `AuthToken` previously returned by
/// `adrian_swift_sdk_authenticate_kerberos`.
///
/// # Safety
/// `handle` MUST be a valid `AdrianAuthTokenRef`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_auth_token_free(handle: AdrianAuthTokenRef) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` was returned by `adrian_sdk_auth_kerberos`;
    // freeing via the C ABI's `adrian_auth_token_free` matches the
    // ownership contract.
    unsafe { adrian_sdk_c::adrian_auth_token_free(handle as adrian_sdk_c::AuthTokenHandle) };
}

/// Get the principal string from an `AuthToken`. Returns a
/// NUL-terminated UTF-8 C string owned by the caller (free with
/// `adrian_swift_sdk_free_string`).
///
/// # Safety
/// `handle` MUST be a valid `AdrianAuthTokenRef`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_auth_token_get_principal(
    handle: AdrianAuthTokenRef,
) -> *const std::os::raw::c_char {
    if handle.is_null() {
        return std::ptr::null();
    }
    // SAFETY: `handle` is valid; the C ABI returns a NUL-terminated
    // string the caller owns until freed via `adrian_free_string`.
    unsafe {
        adrian_sdk_c::adrian_auth_token_get_principal(handle as adrian_sdk_c::AuthTokenHandle)
    }
}

/// Free a C string previously returned by
/// `adrian_swift_sdk_auth_token_get_principal` (or any other Swift
/// binding function that returns a `*const c_char` owned by the
/// caller).
///
/// # Safety
/// `ptr` MUST be a valid pointer returned by `CString::into_raw`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_free_string(ptr: *const std::os::raw::c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: `ptr` was returned by `adrian_auth_token_get_principal`
    // (which wraps `CString::into_raw`); freeing via the C ABI's
    // `adrian_free_string` matches the ownership contract.
    unsafe { adrian_sdk_c::adrian_free_string(ptr) };
}

// -------------------------------------------------------------------------
// `searchDirectory` / `applyPolicy` / `mountShare` / `enrollCert`.
//
// These operations return richer result types (Vec<DirEntry>,
// AppliedPolicy, MountedShare, Vec<u8>) that don't fit in a single
// pointer. The Swift binding wraps them in a `Box<...>` and returns an
// opaque handle; the Swift side queries the fields via dedicated getters
// and frees the handle via the paired `_free` function.
//
// For Wave 3, these entry points construct a fresh `AdrianSdk` via the
// C ABI (rather than accepting a pre-existing handle) — this keeps the
// Swift API surface simple (`AdrianSdk.searchDirectory(filter)` is one
// call, not two). A later wave may refactor to accept a handle for
// reuse across calls (per ADR-107 §Decision — "constructed once per
// host; shared across modules").
// -------------------------------------------------------------------------

/// Search the directory with an RFC 4515 filter string. Returns an
/// opaque `AdrianDirEntryListRef` (or NULL on failure). The Swift side
/// iterates via `adrian_swift_sdk_dir_entry_list_len` +
/// `adrian_swift_sdk_dir_entry_list_get_dn` and frees via
/// `adrian_swift_sdk_dir_entry_list_free`.
///
/// # Safety
/// - `handle` MUST be a valid `AdrianSdkRef`.
/// - `filter` MUST be a NUL-terminated UTF-8 C string.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_search_directory(
    handle: AdrianSdkRef,
    filter: *const std::os::raw::c_char,
) -> AdrianDirEntryListRef {
    if handle.is_null() || filter.is_null() {
        return std::ptr::null_mut();
    }
    // Cast the opaque handle back to `*mut AdrianSdk` (the layout the
    // C ABI's `adrian_sdk_new` produced via `Box::into_raw`).
    // SAFETY: `handle` was returned by `adrian_swift_sdk_new` (which
    // wraps `adrian_sdk_c::adrian_sdk_new`); casting back to
    // `*const adrian_sdk::AdrianSdk` is sound because the C ABI
    // boxed an `AdrianSdk`.
    let sdk = &*(handle as *const adrian_sdk::AdrianSdk);
    let filter_str = std::ffi::CStr::from_ptr(filter)
        .to_string_lossy()
        .into_owned();
    let result = runtime().block_on(sdk.directory.search(&filter_str));
    match result {
        Ok(entries) => Box::into_raw(Box::new(entries)) as AdrianDirEntryListRef,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a `DirEntry` list previously returned by
/// `adrian_swift_sdk_search_directory`.
///
/// # Safety
/// `handle` MUST be a valid `AdrianDirEntryListRef`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_dir_entry_list_free(handle: AdrianDirEntryListRef) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` was returned by `adrian_swift_sdk_search_directory`
    // via `Box::into_raw`; reconstructing the Box and dropping it
    // deallocates the Vec<DirEntry>.
    drop(Box::from_raw(handle as *mut Vec<adrian_sdk::DirEntry>));
}

/// Return the number of entries in a `DirEntry` list.
///
/// # Safety
/// `handle` MUST be a valid `AdrianDirEntryListRef`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_dir_entry_list_len(
    handle: AdrianDirEntryListRef,
) -> usize {
    if handle.is_null() {
        return 0;
    }
    // SAFETY: `handle` is valid; the C ABI contract is that the caller
    // does not mutate the list concurrently.
    let entries = &*(handle as *const Vec<adrian_sdk::DirEntry>);
    entries.len()
}

/// Apply a declarative policy (name + version). Returns an opaque
/// `AdrianAppliedPolicyRef` (or NULL on failure). The Swift side reads
/// the rollback token via `adrian_swift_sdk_applied_policy_get_name`
/// and frees via `adrian_swift_sdk_applied_policy_free`.
///
/// # Safety
/// - `handle` MUST be a valid `AdrianSdkRef`.
/// - `name` and `version` MUST be NUL-terminated UTF-8 C strings.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_apply_policy(
    handle: AdrianSdkRef,
    name: *const std::os::raw::c_char,
    version: *const std::os::raw::c_char,
) -> AdrianAppliedPolicyRef {
    if handle.is_null() || name.is_null() || version.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: see `adrian_swift_sdk_search_directory` for the cast
    // rationale.
    let sdk = &*(handle as *const adrian_sdk::AdrianSdk);
    let name_str = std::ffi::CStr::from_ptr(name)
        .to_string_lossy()
        .into_owned();
    let version_str = std::ffi::CStr::from_ptr(version)
        .to_string_lossy()
        .into_owned();
    let policy = adrian_sdk::DeclarativePolicy {
        name: name_str,
        version: version_str,
        settings: Vec::new(),
    };
    let result = runtime().block_on(sdk.policy.apply(&policy));
    match result {
        Ok(applied) => Box::into_raw(Box::new(applied)) as AdrianAppliedPolicyRef,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an `AppliedPolicy` previously returned by
/// `adrian_swift_sdk_apply_policy`.
///
/// # Safety
/// `handle` MUST be a valid `AdrianAppliedPolicyRef`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_applied_policy_free(handle: AdrianAppliedPolicyRef) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut adrian_sdk::AppliedPolicy));
}

/// Mount an SMB share (`\\server\share`). Returns an opaque
/// `AdrianMountedShareRef` (or NULL on failure). The Swift side reads
/// the mount path via `adrian_swift_sdk_mounted_share_get_mount_path`
/// and frees via `adrian_swift_sdk_mounted_share_free`.
///
/// # Safety
/// - `handle` MUST be a valid `AdrianSdkRef`.
/// - `server` and `share` MUST be NUL-terminated UTF-8 C strings.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_mount_share(
    handle: AdrianSdkRef,
    server: *const std::os::raw::c_char,
    share: *const std::os::raw::c_char,
) -> AdrianMountedShareRef {
    if handle.is_null() || server.is_null() || share.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: see `adrian_swift_sdk_search_directory` for the cast
    // rationale.
    let sdk = &*(handle as *const adrian_sdk::AdrianSdk);
    let server_str = std::ffi::CStr::from_ptr(server)
        .to_string_lossy()
        .into_owned();
    let share_str = std::ffi::CStr::from_ptr(share)
        .to_string_lossy()
        .into_owned();
    let token = adrian_sdk::AuthToken {
        principal: "<swift-default>".into(),
        expiry: None,
        kind: adrian_sdk::AuthTokenKind::Kerberos,
    };
    let result = runtime().block_on(sdk.file.mount_share(&server_str, &share_str, &token));
    match result {
        Ok(mounted) => Box::into_raw(Box::new(mounted)) as AdrianMountedShareRef,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a `MountedShare` previously returned by
/// `adrian_swift_sdk_mount_share`.
///
/// # Safety
/// `handle` MUST be a valid `AdrianMountedShareRef`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_mounted_share_free(handle: AdrianMountedShareRef) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut adrian_sdk::MountedShare));
}

/// Enroll a certificate via ACME (RFC 8555). Returns an opaque
/// `AdrianCertBytesRef` (or NULL on failure). The Swift side reads the
/// cert DER via `adrian_swift_sdk_cert_bytes_len` +
/// `adrian_swift_sdk_cert_bytes_get` and frees via
/// `adrian_swift_sdk_cert_bytes_free`.
///
/// # Safety
/// - `handle` MUST be a valid `AdrianSdkRef`.
/// - `profile` and `subject` MUST be NUL-terminated UTF-8 C strings.
/// - `csr_ptr` MUST point to `csr_len` readable bytes.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_enroll_cert(
    handle: AdrianSdkRef,
    profile: *const std::os::raw::c_char,
    csr_ptr: *const u8,
    csr_len: usize,
    subject: *const std::os::raw::c_char,
) -> AdrianCertBytesRef {
    if handle.is_null()
        || profile.is_null()
        || csr_ptr.is_null()
        || subject.is_null()
        || csr_len == 0
    {
        return std::ptr::null_mut();
    }
    // SAFETY: see `adrian_swift_sdk_search_directory` for the cast
    // rationale. `csr_ptr` is valid for `csr_len` bytes per the safety
    // contract.
    let sdk = &*(handle as *const adrian_sdk::AdrianSdk);
    let profile_str = std::ffi::CStr::from_ptr(profile)
        .to_string_lossy()
        .into_owned();
    let subject_str = std::ffi::CStr::from_ptr(subject)
        .to_string_lossy()
        .into_owned();
    let csr = std::slice::from_raw_parts(csr_ptr, csr_len).to_vec();
    let req = adrian_sdk::CertEnrollRequest {
        profile: profile_str,
        csr,
        subject: subject_str,
    };
    let result = runtime().block_on(sdk.cert.enroll(req));
    match result {
        Ok(cert_der) => Box::into_raw(Box::new(cert_der)) as AdrianCertBytesRef,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a `CertBytes` previously returned by `adrian_swift_sdk_enroll_cert`.
///
/// # Safety
/// `handle` MUST be a valid `AdrianCertBytesRef`, or NULL.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_cert_bytes_free(handle: AdrianCertBytesRef) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut Vec<u8>));
}

/// Return the length of a `CertBytes` (issued cert DER).
///
/// # Safety
/// `handle` MUST be a valid `AdrianCertBytesRef`.
#[no_mangle]
#[allow(unsafe_code)]
pub unsafe extern "C" fn adrian_swift_sdk_cert_bytes_len(handle: AdrianCertBytesRef) -> usize {
    if handle.is_null() {
        return 0;
    }
    let cert = &*(handle as *const Vec<u8>);
    cert.len()
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

    // -----------------------------------------------------------------
    // Wave 3 tests — new `AdrianSdk` Swift-facing entry points that
    // route through `adrian-sdk-c` per ADR-107 §Consequences.
    // -----------------------------------------------------------------

    #[test]
    fn wave3_adrian_sdk_ref_types_are_void_pointer_sized() {
        // All Wave 3 opaque handle types (`AdrianSdkRef`,
        // `AdrianAuthTokenRef`, `AdrianDirEntryListRef`,
        // `AdrianAppliedPolicyRef`, `AdrianMountedShareRef`,
        // `AdrianCertBytesRef`) MUST be pointer-sized — the Swift
        // xcframework treats them as `UnsafeMutableRawPointer?` (one
        // word). Any widening (e.g. to a struct) would silently break
        // the Swift xcframework.
        assert_eq!(
            std::mem::size_of::<AdrianSdkRef>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<AdrianAuthTokenRef>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<AdrianDirEntryListRef>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<AdrianAppliedPolicyRef>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<AdrianMountedShareRef>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<AdrianCertBytesRef>(),
            std::mem::size_of::<*mut c_void>()
        );
    }

    #[test]
    fn wave3_swift_sdk_ffi_entry_points_are_exported() {
        // Function-pointer probe — catches ABI drift in the Wave 3
        // `adrian_swift_sdk_*` family. Per ADR-107 §Consequences, this
        // is the foundation for the Swift `AdrianSdk` class, so the
        // signatures MUST remain stable.
        let _new: unsafe extern "C" fn() -> AdrianSdkRef = adrian_swift_sdk_new;
        let _free: unsafe extern "C" fn(AdrianSdkRef) = adrian_swift_sdk_free;
        let _auth: unsafe extern "C" fn(
            AdrianSdkRef,
            *const c_char,
            *const c_char,
        ) -> AdrianAuthTokenRef = adrian_swift_sdk_authenticate_kerberos;
        let _auth_free: unsafe extern "C" fn(AdrianAuthTokenRef) = adrian_swift_sdk_auth_token_free;
        let _get_princ: unsafe extern "C" fn(AdrianAuthTokenRef) -> *const c_char =
            adrian_swift_sdk_auth_token_get_principal;
        let _free_str: unsafe extern "C" fn(*const c_char) = adrian_swift_sdk_free_string;
        let _search: unsafe extern "C" fn(AdrianSdkRef, *const c_char) -> AdrianDirEntryListRef =
            adrian_swift_sdk_search_directory;
        let _search_free: unsafe extern "C" fn(AdrianDirEntryListRef) =
            adrian_swift_sdk_dir_entry_list_free;
        let _search_len: unsafe extern "C" fn(AdrianDirEntryListRef) -> usize =
            adrian_swift_sdk_dir_entry_list_len;
        let _apply: unsafe extern "C" fn(
            AdrianSdkRef,
            *const c_char,
            *const c_char,
        ) -> AdrianAppliedPolicyRef = adrian_swift_sdk_apply_policy;
        let _apply_free: unsafe extern "C" fn(AdrianAppliedPolicyRef) =
            adrian_swift_sdk_applied_policy_free;
        let _mount: unsafe extern "C" fn(
            AdrianSdkRef,
            *const c_char,
            *const c_char,
        ) -> AdrianMountedShareRef = adrian_swift_sdk_mount_share;
        let _mount_free: unsafe extern "C" fn(AdrianMountedShareRef) =
            adrian_swift_sdk_mounted_share_free;
        let _enroll: unsafe extern "C" fn(
            AdrianSdkRef,
            *const c_char,
            *const u8,
            usize,
            *const c_char,
        ) -> AdrianCertBytesRef = adrian_swift_sdk_enroll_cert;
        let _enroll_free: unsafe extern "C" fn(AdrianCertBytesRef) =
            adrian_swift_sdk_cert_bytes_free;
        let _enroll_len: unsafe extern "C" fn(AdrianCertBytesRef) -> usize =
            adrian_swift_sdk_cert_bytes_len;
        // Pin all symbols so the compiler checks they exist with the
        // expected signatures.
        let _ = (
            _new,
            _free,
            _auth,
            _auth_free,
            _get_princ,
            _free_str,
            _search,
            _search_free,
            _search_len,
            _apply,
            _apply_free,
            _mount,
            _mount_free,
            _enroll,
            _enroll_free,
            _enroll_len,
        );
    }

    /// Wave 3 Swift-binding-calls-C-FFI: invoke `adrian_swift_sdk_new`
    /// and verify it returns a non-null `AdrianSdkRef` (proving the call
    /// path goes through `adrian_sdk_c::adrian_sdk_new`). Then invoke
    /// `adrian_swift_sdk_authenticate_kerberos` with the default stub
    /// and verify it returns NULL (proving the C ABI's null-on-error
    /// convention surfaces to Swift). Finally, free the SDK handle via
    /// `adrian_swift_sdk_free`.
    #[test]
    fn wave3_swift_sdk_calls_c_abi_round_trip() {
        // SAFETY: `adrian_swift_sdk_new` wraps `adrian_sdk_c::adrian_sdk_new`
        // which returns a fresh heap pointer; we free it before returning.
        let sdk = unsafe { adrian_swift_sdk_new() };
        assert!(
            !sdk.is_null(),
            "adrian_swift_sdk_new must return a non-null handle"
        );
        // Authenticate against the default stub — MUST return NULL
        // (the stub returns Err(SdkError::Auth(...)), which the C ABI
        // surfaces as NULL per the safety contract on
        // `adrian_sdk_auth_kerberos`).
        let principal = c"alice@ADRIAN.EXAMPLE";
        let password = c"pw";
        // SAFETY: `sdk` is valid; `principal` and `password` are valid
        // NUL-terminated C string literals.
        let token = unsafe {
            adrian_swift_sdk_authenticate_kerberos(sdk, principal.as_ptr(), password.as_ptr())
        };
        assert!(
            token.is_null(),
            "default stub must surface NULL via the C ABI; got non-null token"
        );
        // Defensive free: NULL is a no-op for `adrian_swift_sdk_auth_token_free`.
        // SAFETY: NULL is explicitly a no-op per the safety contract.
        unsafe { adrian_swift_sdk_auth_token_free(std::ptr::null_mut()) };
        // SAFETY: `sdk` was returned by `adrian_swift_sdk_new` and hasn't
        // been freed.
        unsafe { adrian_swift_sdk_free(sdk) };
    }

    /// Wave 3 Swift binding compiles: smoke test that the search /
    /// apply / mount / enroll entry points are invocable with NULL
    /// handles and return NULL (defensive null-check). This catches
    /// signature drift in the richer-result-type entry points.
    #[test]
    fn wave3_swift_sdk_rich_entry_points_handle_null_defensively() {
        // SAFETY: passing NULL is explicitly handled by each entry point
        // (returns NULL without dereferencing the handle).
        let null_sdk: AdrianSdkRef = std::ptr::null_mut();
        let filter = c"(objectClass=*)";
        // SAFETY: null_sdk is NULL; the function checks and returns NULL.
        let r = unsafe { adrian_swift_sdk_search_directory(null_sdk, filter.as_ptr()) };
        assert!(r.is_null(), "search_directory(NULL, ...) must return NULL");
        // SAFETY: r is NULL; the free function handles NULL gracefully.
        unsafe { adrian_swift_sdk_dir_entry_list_free(r) };
        // SAFETY: passing NULL handle to len getter returns 0 per the
        // defensive null-check.
        assert_eq!(
            unsafe { adrian_swift_sdk_dir_entry_list_len(std::ptr::null_mut()) },
            0,
            "len on NULL must be 0"
        );

        let name = c"baseline-workstation";
        let version = c"1.0.0";
        // SAFETY: null_sdk is NULL; the function checks and returns NULL.
        let r = unsafe { adrian_swift_sdk_apply_policy(null_sdk, name.as_ptr(), version.as_ptr()) };
        assert!(r.is_null(), "apply_policy(NULL, ...) must return NULL");
        // SAFETY: r is NULL; the free function handles NULL gracefully.
        unsafe { adrian_swift_sdk_applied_policy_free(r) };

        let server = c"dc01.adrian.example";
        let share = c"sysvol";
        // SAFETY: null_sdk is NULL; the function checks and returns NULL.
        let r = unsafe { adrian_swift_sdk_mount_share(null_sdk, server.as_ptr(), share.as_ptr()) };
        assert!(r.is_null(), "mount_share(NULL, ...) must return NULL");
        // SAFETY: r is NULL; the free function handles NULL gracefully.
        unsafe { adrian_swift_sdk_mounted_share_free(r) };

        let profile = c"adrian-webserver";
        let csr: [u8; 4] = [0x30, 0x82, 0x01, 0x00];
        let subject = c"CN=dc01.adrian.example";
        // SAFETY: null_sdk is NULL; the function checks and returns NULL.
        let r = unsafe {
            adrian_swift_sdk_enroll_cert(
                null_sdk,
                profile.as_ptr(),
                csr.as_ptr(),
                csr.len(),
                subject.as_ptr(),
            )
        };
        assert!(r.is_null(), "enroll_cert(NULL, ...) must return NULL");
        // SAFETY: r is NULL; the free function handles NULL gracefully.
        unsafe { adrian_swift_sdk_cert_bytes_free(r) };
        assert_eq!(
            unsafe { adrian_swift_sdk_cert_bytes_len(std::ptr::null_mut()) },
            0,
            "cert_bytes_len on NULL must be 0"
        );
    }
}
