---
title: "Client SDK (cross-platform library) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Client SDK
tags: [spec, client-sdk, ffi, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Client SDK (cross-platform library) — Technical Specification

## 1. Overview

The Client SDK is the unified Rust core (`adrian-sdk`) with platform-specific bindings (C ABI / JNI / Swift / pyo3 / cgo) exposing authentication, directory query, policy application, cert enrollment, file client, and federation token validation across Windows, macOS, and Linux from one API surface. It is the seam that lets `pam_adrian.so`, `adrianlsa.dll`, and `AdrianOpenDirectory.bundle` all delegate to the same Rust core — eliminating the cross-platform drift that plagues AD's SSPI/PAM/OpenDirectory split.

Workshop Decision 11 rejected gRPC-based SDK (runtime dependency too heavy for edge/embedded) and per-platform wrappers (no API consistency). The Rust core exposes both `async` methods (for Rust consumers via `tokio`) and blocking methods (for FFI consumers via `tokio::runtime::Runtime::block_on`). Platform-native integrations are additive, not replacing: `pam_adrian.so` + `nss_adrian.so.2` on Linux (alongside SSSD), `adrianlsa.dll` LSA Authentication Package on Windows (alongside SSPI), `AdrianOpenDirectory.bundle` on macOS (alongside OpenDirectory). This means existing platform-native apps keep working; new apps use the SDK for cross-platform consistency.

The capability carries 9 ADRs: ADR-048 (PSSO Extension as modern macOS path; Jamf Connect migration), ADR-049 (standardize on MIT krb5 on Linux/macOS), ADR-050 (authselect as standard PAM profile mechanism), ADR-051 (KCM on Linux; API: on macOS; unified cache abstraction), ADR-107 (unified Rust core SDK with platform-specific bindings), ADR-108 (SSPI-equivalent AuthModule abstraction), ADR-109 (cross-platform LDAP client library), ADR-110 (SID-to-UID mapping via UUID-primary identity), ADR-111 (unified ticket cache abstraction). It resolves two blockers (PC-085 no universal SDK, PC-089 ID mapping).

The capability is implemented as **seven** Rust crates at Layer 3: `adrian-sdk` (Rust core, ~8K lines), `adrian-sdk-c` (C ABI via `cbindgen`), `adrian-sdk-jni` (JNI bindings), `adrian-sdk-swift` (Swift via `swift-bridge`), `adrian-sdk-python` (pyo3 + maturin), `adrian-kerberos-renewd` (TGT renewal daemon), `adrian-kerberos-sync` (macOS PSSO sync daemon). External dependencies include `tokio`, `serde`, `ldap3`, `pavao`, `rustls`, `openidconnect`, `saml2`, `cbindgen`, `jni`, `swift-bridge`, `pyo3`, `maturin`, `pam-bindings`, `libc`, `windows`, `objc2`, `core-foundation`, `systemd`, `gss-api`, `kcm-client`, `security-framework`.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-sdk` | 3 | Rust core SDK; `AdrianClient` with `auth()`, `directory()`, `policy()`, `cert()`, `file()`, `federation()` modules; ~8K lines | ADR-107, ADR-108, ADR-109, ADR-110, ADR-111 |
| `adrian-sdk-c` | 4 | C ABI via `cbindgen`; exposes blocking methods via `tokio::runtime::Runtime::block_on`; headers in `include/adrian/` | ADR-107 |
| `adrian-sdk-jni` | 4 | JNI bindings for Java/Kotlin consumers; `dev.adrian.sdk.AdrianClient` class | ADR-107 |
| `adrian-sdk-swift` | 4 | Swift bindings via `swift-bridge`; `AdrianSDK` Swift package | ADR-107 |
| `adrian-sdk-python` | 4 | Python bindings via `pyo3` + `maturin`; `adrian` PyPI package | ADR-107 |
| `adrian-kerberos-renewd` | 4 | TGT renewal daemon; runs at 50% TGT lifetime; Linux systemd, macOS launchd, Windows service | ADR-049, ADR-051, ADR-111 |
| `adrian-kerberos-sync` | 4 | macOS PSSO sync daemon; bridges PSSO extension tickets to framework KCM-equivalent | ADR-048, ADR-056 |

## 3. Key types and traits

```rust
// crates/adrian-sdk/src/lib.rs (per ADR-107, ADR-108)

use adrian_auth_core::{Principal, CredentialHandle, Privilege, LogonType};
use adrian_sid::Sid;
use uuid::Uuid;

/// Unified Adrian client. Construct once per process, share across
/// threads. Exposes six modules: auth, directory, policy, cert,
/// file, federation.
pub struct AdrianClient {
    inner: Arc<ClientInner>,
}

impl AdrianClient {
    pub fn new(config: ClientConfig) -> Result<Self, SdkError>;
    pub fn auth(&self) -> &AuthModule;
    pub fn directory(&self) -> &DirectoryModule;
    pub fn policy(&self) -> &PolicyModule;
    pub fn cert(&self) -> &CertModule;
    pub fn file(&self) -> &FileModule;
    pub fn federation(&self) -> &FederationModule;
}

/// SSPI-equivalent AuthModule (per ADR-108).
pub struct AuthModule { /* ... */ }

impl AuthModule {
    /// Acquire Kerberos TGT for principal. Returns CredentialHandle.
    pub async fn acquire_kerberos(
        &self, principal: &str, password: Option<&str>,
    ) -> Result<CredentialHandle, SdkError>;

    /// Acquire NTLM client credential (NTLMv2 only per ADR-085).
    pub async fn acquire_ntlm_client(
        &self, principal: &str,
    ) -> Result<CredentialHandle, SdkError>;

    /// Acquire certificate credential (smart card / FIDO2).
    pub async fn acquire_cert(
        &self, cert_id: &str,
    ) -> Result<CredentialHandle, SdkError>;

    /// Acquire OAuth2 token (via framework Federation Gateway).
    pub async fn acquire_oauth2(
        &self, client_id: &str, scopes: &[&str],
    ) -> Result<CredentialHandle, SdkError>;

    /// SSPI-equivalent init_security_context.
    /// Returns token to send to server; may require multiple round trips.
    pub async fn init_security_context(
        &self, credential: &CredentialHandle, target: &str,
        channel_binding: Option<&[u8]>,  // RFC 5929
    ) -> Result<SecurityContext, SdkError>;

    /// SSPI-equivalent accept_security_context (server side).
    pub async fn accept_security_context(
        &self, token: &[u8], channel_binding: Option<&[u8]>,
    ) -> Result<Principal, SdkError>;

    /// Validate token + return Principal (called by services).
    pub async fn validate_token(
        &self, token: &Token, expected_audience: &str,
    ) -> Result<Principal, SdkError>;
}
```

```rust
// crates/adrian-sdk/src/directory.rs (per ADR-109)

use ldap3::{LdapConn, SearchEntry};

/// Cross-platform LDAP client (Wldap32 equivalent) built on ldap3.
/// AD-specific extended controls per ADR-006.
pub struct DirectoryModule {
    conn: LdapConn,
    identity: Arc<dyn IdentityMapping>,
}

impl DirectoryModule {
    /// Bind via GSS-SPNEGO using Kerberos credential.
    pub async fn bind_spnego(
        &self, credential: &CredentialHandle,
    ) -> Result<(), SdkError>;

    /// Search with AD controls (per ADR-006).
    pub async fn search(
        &self, base: &str, scope: Scope, filter: &str,
        controls: &[LdapControl],         // DirSync, ASQ, cross-domain move, etc.
    ) -> Result<Vec<SearchEntry>, SdkError>;

    /// Cross-domain move (per ADR-075).
    pub async fn cross_domain_move(
        &self, source_dn: &str, target_dn: &str,
    ) -> Result<Uuid, SdkError>;

    /// Tree-delete extended operation.
    pub async fn tree_delete(&self, root_dn: &str) -> Result<(), SdkError>;

    /// SID-to-UID mapping (per ADR-110).
    pub async fn sid_to_uid(&self, sid: &Sid) -> Result<u32, SdkError>;
    pub async fn uid_to_sid(&self, uid: u32) -> Result<Sid, SdkError>;

    /// UUID-primary identity lookup (per ADR-110).
    pub async fn get_object_by_uuid(
        &self, uuid: Uuid, attrs: &[&str],
    ) -> Result<SearchEntry, SdkError>;
}
```

```rust
// crates/adrian-sdk/src/policy.rs (per ADR-113)

pub struct PolicyModule {
    daemon_url: String,            // ws://policyd.corp.example.com/v1/events
    state_db: rusqlite::Connection,
}

impl PolicyModule {
    pub async fn refresh(&self) -> Result<ApplyResult, SdkError>;
    pub async fn rollback(&self, transaction_id: Uuid) -> Result<(), SdkError>;
    pub async fn drift(&self) -> Result<DriftReport, SdkError>;
    pub async fn applied_policies(&self) -> Result<Vec<Uuid>, SdkError>;
}
```

```rust
// crates/adrian-sdk/src/ticket_cache.rs (per ADR-051, ADR-111)

/// Unified TicketCache abstraction — eliminates FILE:/KEYRING:/KCM:/
/// API: divergence across platforms. Every platform sees the same
/// TicketCache API.
#[async_trait]
pub trait TicketCache: Send + Sync {
    async fn store(&self, principal: &str, ticket: &Ticket) -> Result<(), SdkError>;
    async fn retrieve(&self, principal: &str) -> Result<Option<Ticket>, SdkError>;
    async fn list(&self) -> Result<Vec<String>, SdkError>;
    async fn destroy(&self, principal: &str) -> Result<(), SdkError>;
}

pub struct KcmCache;          // Linux: KCM kernel keyring via kcm-client
pub struct ApiCache;          // macOS: API:Initialdefaultcache via security-framework
pub struct LsaCache;          // Windows: LSA in-memory cache
pub struct FileCache;         // portable fallback: ~/.adrian/tickets/

impl TicketCache for KcmCache { /* ... */ }
impl TicketCache for ApiCache { /* ... */ }
impl TicketCache for LsaCache { /* ... */ }
impl TicketCache for FileCache { /* ... */ }

/// adrian-kerberos-renewd: renews TGT at 50% lifetime (per ADR-111).
pub struct Renewd {
    cache: Arc<dyn TicketCache>,
    kdc_url: String,
    renew_at_percent: u32,         // 50 per ADR-111
    check_interval_secs: u64,
}
```

```rust
// crates/adrian-sdk-c/src/lib.rs (per ADR-107)

use adrian_sdk::AdrianClient;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static CLIENT: OnceLock<AdrianClient> = OnceLock::new();

/// Initialize the SDK. Returns 0 on success, negative errno on failure.
/// Must be called once per process before any other SDK function.
#[no_mangle]
pub extern "C" fn adrian_init(config_path: *const c_char) -> i32 {
    let runtime = Runtime::new().map_err(|_| -1).unwrap();
    RUNTIME.set(runtime).map_err(|_| -2).unwrap();
    let config = ClientConfig::load(config_path_str(config_path)).unwrap();
    CLIENT.set(AdrianClient::new(config).unwrap()).map_err(|_| -3).unwrap();
    0
}

/// Blocking authenticate (uses RUNTIME.block_on internally).
/// Returns PrincipalHandle > 0 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn adrian_authenticate_kerberos(
    principal: *const c_char,
    password: *const c_char,    // nullable
) -> u64 {
    let runtime = RUNTIME.get().unwrap();
    let client = CLIENT.get().unwrap();
    runtime.block_on(async {
        client.auth().acquire_kerberos(cstr_to_str(principal),
                                       cstr_to_opt_str(password)).await
    }).map(|h| Box::into_raw(Box::new(h)) as u64).unwrap_or(0)
}

/// Get UPN from principal handle. Caller frees with adrian_string_free.
#[no_mangle]
pub extern "C" fn adrian_principal_upn(handle: u64) -> *mut c_char;

#[no_mangle]
pub extern "C" fn adrian_string_free(s: *mut c_char);

#[no_mangle]
pub extern "C" fn adrian_principal_free(handle: u64);
```

## 4. Data model

The Client SDK has no dedicated FDB subspaces — it consumes Core Directory subspaces via the LDAP/GSS-SPNEGO protocol. Per-host state lives in local SQLite databases and the platform ticket cache.

```
Per-host state (per ADR-110, ADR-111, ADR-092):

  /var/lib/adrian/sdk_state.db (Linux)          — SQLite
  /Library/Application Support/Adrian/sdk_state.db (macOS)
  %APPDATA%/Adrian/sdk_state.db (Windows)

  CREATE TABLE id_mapping_cache (               -- per ADR-110
    sid TEXT PRIMARY KEY,
    uuid TEXT NOT NULL,
    uid INTEGER,
    username TEXT NOT NULL,
    cached_at INTEGER NOT NULL,
    ttl_secs INTEGER NOT NULL
  );

  CREATE TABLE policy_state (                    -- per ADR-025
    transaction_id TEXT PRIMARY KEY,
    policy_uuid TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    applied_at INTEGER NOT NULL,
    shadow_paths TEXT NOT NULL,
    status TEXT NOT NULL
  );

  CREATE TABLE kerberos_tickets (                -- per ADR-111, sync with cache
    principal TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    renew_until INTEGER NOT NULL,
    ticket_blob BLOB NOT NULL
  );

  CREATE TABLE enrollment_state (                -- per ADR-097
    host_uuid TEXT PRIMARY KEY,
    enrolled_at INTEGER NOT NULL,
    cert_serial INTEGER,
    cert_expires_at INTEGER,
    tpm2_ak_pub TEXT,
    apple_se_attestation TEXT
  );

Platform-secure credential stores (per ADR-086):
  Linux:   kernel keyring ("user" keytype, "adrian:<principal>")
           OR systemd-creds at /var/lib/adrian/creds/
  macOS:   Keychain (generic item, service "adrian", account=<principal>)
           OR Secure Enclave for FIDO2 credentials
  Windows: DPAPI CryptProtectData() at %APPDATA%/Adrian/creds/<principal>.bin
           OR Credential Guard VSM-protected LSA secret

PAM/NSS/LSA/OpenDirectory integration (per ADR-050):
  Linux:
    /etc/pam.d/adrian-authselect.profile
      auth       sufficient   pam_adrian.so try_first_pass
      account    sufficient   pam_adrian.so
      password   sufficient   pam_adrian.so
      session    sufficient   pam_adrian.so

    /etc/nsswitch.conf:
      passwd: files adrian
      group:  files adrian
      shadow: files adrian

    adrian-with-sudo authselect profile (per ADR-114):
      authselect select adrian-with-sudo --force

  macOS:
    /Library/OpenDirectory/Plugins/AdrianOpenDirectory.bundle
      — registered via odpluginreg
      — wraps DSOpenDirNode, DSRecordCopyValues
      — PSSO Extension bridges system Kerberos to adrian Kerberos
        via adrian-kerberos-sync daemon (per ADR-048)

  Windows:
    %WINDIR%/System32/adrianlsa.dll
      — registered as LSA Authentication Package
      — LsaApLogonUserExEx called by lsass.exe
      — Credential Guard compatible (VSM-isolated)
      — Installed via adrian-cli install --windows

Identity mapping algorithm (per ADR-110):
  Greenfield deterministic mode:
    uuid_to_uid(uuid) = (uuid_to_u64(uuid) % (2^31 - 65536)) + 65536
    sid_to_uid(sid)   = uuid_to_uid(sid_to_uuid(sid))

  Migrated directory-stored mode:
    uuid_to_uid(uuid) = lookup((0x06, 0x04, uuid))
    Collision detection: FDB atomic-add counter re-allocates UID
    Migration tool: adrian-cli migrate from-{sssd,winbind,pbis,dsconfigad}
                    translates existing UIDs to directory-stored mappings.
```

## 5. Protocol surface

```
SDK API surface (per ADR-107, ADR-108):

  Async API (Rust consumers via tokio):
    adrian_sdk::AdrianClient::new(config) -> AdrianClient
    client.auth().acquire_kerberos(principal, password) -> CredentialHandle
    client.auth().init_security_context(cred, target, cb) -> SecurityContext
    client.auth().accept_security_context(token, cb) -> Principal
    client.directory().bind_spnego(cred) -> ()
    client.directory().search(base, scope, filter, controls) -> Vec<SearchEntry>
    client.policy().refresh() -> ApplyResult
    client.policy().drift() -> DriftReport
    client.cert().enroll(profile, csr) -> Certificate
    client.file().read_file("\\server\share\path") -> Vec<u8>
    client.federation().oidc_authorize(client_id, scopes, redirect) -> AuthCode

  Blocking API (FFI consumers via tokio::runtime::block_on):
    Same methods, suffixed _blocking (e.g. acquire_kerberos_blocking).

C ABI (per ADR-107, in adrian-sdk-c):
  /usr/include/adrian/adrian.h
    adrian_init(config_path) -> int32
    adrian_authenticate_kerberos(principal, password) -> uint64 handle
    adrian_principal_upn(handle) -> char*
    adrian_principal_sid(handle) -> char*
    adrian_principal_group_sids(handle) -> char**
    adrian_principal_free(handle)
    adrian_string_free(s)
    adrian_directory_search(filter, ...) -> int32
    adrian_policy_refresh() -> int32
    adrian_cert_enroll(profile, csr) -> int64
    adrian_shutdown()

JNI bindings (per ADR-107, in adrian-sdk-jni):
  Java class: dev.adrian.sdk.AdrianClient
    Methods mirror the async API; CompletableFuture return types.
  Maven artifact: dev.adrian:adrian-sdk:1.0.0

Swift bindings (per ADR-107, in adrian-sdk-swift):
  Swift class: AdrianSDK.AdrianClient
    Methods mirror the async API; async/await return types.
  Swift package: https://github.com/adrian-framework/adrian-swift

Python bindings (per ADR-107, in adrian-sdk-python):
  Python class: adrian.AdrianClient
    Methods mirror the async API; asyncio coroutines.
  PyPI package: adrian (installed via `pip install adrian`)

Platform integrations (per ADR-050, ADR-056):
  Linux:
    pam_adrian.so     — PAM module (auth, account, password, session)
    nss_adrian.so.2   — NSS provider (passwd, group, shadow)
    adrian-policyd    — Policy daemon (systemd unit)
    adrian-kerberos-renewd — TGT renewal daemon (systemd unit)
    adrian-kerberos-sync   — (macOS only)

  macOS:
    AdrianOpenDirectory.bundle — OpenDirectory plugin
    com.adrian.kerberos-sync   — launchd daemon
    com.adrian.policyd         — launchd daemon
    com.adrian.renewd          — launchd daemon
    PSSO Extension MDM profile — com.apple.configuration-ext.platform-sso
      (Hardware_Bound mode default for T2/Apple Silicon,
       Password fallback for Intel-without-T2)

  Windows:
    adrianlsa.dll           — LSA Authentication Package
    adrian-policyd.exe      — Windows service
    adrian-renewd.exe       — Windows service
    adrian-group-policy-cse.dll — Synthetic CSE for legacy apps (per ADR-092)
```

## 6. Configuration

```toml
# /etc/adrian/sdk.toml — Client SDK configuration

[client]
realm                  = "corp.example.com"
domain_controllers     = ["dc01.corp.example.com", "dc02.corp.example.com"]
kdc_servers            = ["dc01.corp.example.com", "dc02.corp.example.com"]
ldap_url               = "ldaps://dc01.corp.example.com"
policy_daemon_url      = "wss://policy.corp.example.com/v1/events"
federation_url         = "https://idp.corp.example.com"
acme_directory_url     = "https://ca.corp.example.com/acme/directory"
smb_share_url          = "file://corp.example.com/sysvol"

[auth]                                  # per ADR-108
preferred_method        = "kerberos"    # kerberos | cert | oauth2 | ntlm-client
fast_armor_required     = true          # ADR-012
pac_validation_required = true          # ADR-083

[ticket_cache]                          # per ADR-051, ADR-111
backend                 = "platform-default"
  # linux: kcm
  # macos: api:
  # windows: lsa
renewd_enabled          = true
renew_at_percent        = 50            # ADR-111
check_interval_secs     = 300

[identity_mapping]                      # per ADR-110
mode                    = "deterministic"  # deterministic | directory-stored
directory_stored_fallback = true        # on collision, fall back to directory
cache_ttl_secs          = 3600

[policy]                                # per ADR-025, ADR-092
state_db_path           = "/var/lib/adrian/sdk_state.db"
auto_refresh            = true
refresh_interval_secs   = 1800          # 30 min default
websocket_push          = true          # ADR-028

[enrollment]                            # per ADR-097
attestation_type        = "platform-default"
  # linux: tpm2
  # macos: apple-secure-enclave
  # windows: tpm2 + windows-hello
auto_renewal            = true

[credential_store]                      # per ADR-086
backend                 = "platform-default"
  # linux: kernel_keyring | systemd_creds
  # macos: keychain | secure_enclave
  # windows: dpapi | credential_guard
zeroize_on_drop         = true

[platform_linux]                        # per ADR-050
pam_module              = "/lib/security/pam_adrian.so"
nss_module              = "/lib/x86_64-linux-gnu/libnss_adrian.so.2"
authselect_profile      = "adrian-with-sudo"

[platform_macos]                        # per ADR-048, ADR-056
psso_extension_id       = "com.adrian.psso"
psso_hardware_bound     = true          # T2/Apple Silicon default
opendirectory_bundle    = "/Library/OpenDirectory/Plugins/AdrianOpenDirectory.bundle"
kerberos_sync_daemon    = "com.adrian.kerberos-sync"
legacy_agent_migration  = true          # detect NoMAD, Jamf, Centrify, etc.

[platform_windows]                      # per ADR-107
lsa_package             = "adrianlsa.dll"
credential_guard_aware  = true

[audit]
otel_endpoint           = "http://otel-collector:4317"
emit_auth_events        = true
emit_policy_events      = true
emit_ticket_events      = true
```

## 7. Error handling

```rust
// crates/adrian-sdk/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("client not initialized — call adrian_init first")]
    NotInitialized,
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("Kerberos TGT acquisition failed: {0}")]
    KerberosTgtFailed(String),
    #[error("NTLM client error: {0}")]
    NtlmClient(String),
    #[error("SPNEGO init_security_context failed: {0}")]
    SpnegoInitFailed(String),
    #[error("SPNEGO accept_security_context failed: {0}")]
    SpnegoAcceptFailed(String),
    #[error("LDAP error: {0}")]
    Ldap(String),
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("SID-to-UID mapping not found for SID {0}")]
    SidMappingNotFound(String),
    #[error("UID collision on deterministic mapping for UUID {0}; "
            "falling back to directory-stored")]
    UidCollisionFallback(Uuid),
    #[error("ticket cache error: {0}")]
    TicketCache(String),
    #[error("ticket expired for principal {0}")]
    TicketExpired(String),
    #[error("policy apply failed: {0}")]
    PolicyApplyFailed(String),
    #[error("cert enrollment failed: {0}")]
    CertEnrollmentFailed(String),
    #[error("file operation failed: {0}")]
    FileOperationFailed(String),
    #[error("federation token validation failed: {0}")]
    FederationValidationFailed(String),
    #[error("platform integration error: {0}")]
    PlatformIntegration(String),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}
```

**Error propagation.** SDK errors map to platform-native error codes: PAM → `PAM_AUTH_ERR` (7), `PAM_PERM_DENIED` (6), `PAM_SYSTEM_ERR` (4); NSS → `NSS_STATUS_NOTFOUND` (0), `NSS_STATUS_UNAVAIL` (2); LSA → `STATUS_LOGON_FAILURE` (0xC000006D), `STATUS_WRONG_PASSWORD` (0xC000006A), `STATUS_NO_SUCH_USER` (0xC0000064); OpenDirectory → `eNotInstalledByOdpluginreg` (-3400), `eNotAuthorized` (-3401). FFI functions return negative errno codes (`-EINVAL` for `NotInitialized`, `-EACCES` for `AuthFailed`). Java throws `AdrianSdkException`, Swift throws `AdrianError`, Python raises `adrian.AdrianError`. Every SDK error emits an OTel audit event with MITRE ATT&CK mapping for authentication failures.

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - AdrianClient construction + config validation
    - AuthModule: all 4 acquire_* methods (mock KDC, NTLM, cert, OAuth2)
    - AuthModule: init_security_context / accept_security_context
    - DirectoryModule: bind_spnego, search with all AD controls
    - PolicyModule: refresh, rollback, drift detection
    - CertModule: enroll, renew, revoke
    - FileModule: read_file, write_file, persistent handles
    - FederationModule: oidc_authorize, token validation
    - TicketCache: store/retrieve/list/destroy for all 4 backends
    - IdentityMapping: deterministic algorithm + collision fallback
    - C ABI: every exported function round-trips via FFI
    - JNI bindings: every method round-trips via mock JVM
    - Swift bindings: every method round-trips via mock Swift runtime
    - Python bindings: every method round-trips via pyo3 mock

Integration tests — tests/integration/, real FDB + KDC + tokio
  Coverage:
    - Full Kerberos auth flow (acquire_kerberos → init_security_context
      → validate_token → Principal)
    - LDAP search via GSS-SPNEGO bind with all 11 AD controls
    - Cross-domain move (per ADR-075) via DirectoryModule
    - Policy refresh via WebSocket push (per ADR-028)
    - Cert enrollment via ACME adrian-attest-01 (per ADR-097)
    - File read via SMB client (per ADR-106)
    - Federation OIDC code-flow end-to-end
    - TGT renewal at 50% lifetime (adrian-kerberos-renewd)
    - Platform integration: PAM auth on Linux, LSA auth on Windows,
      OpenDirectory auth on macOS

Interop tests — tests/interop/
  Matrix:
    - PAM auth via sshd on Ubuntu 22.04, RHEL 9, Debian 12
    - LSA auth via runas.exe on Windows Server 2022, Windows 11
    - OpenDirectory auth via dscl on macOS 13, 14
    - C ABI consumer: C++ test app on all 3 platforms
    - JNI consumer: Java 17 test app on all 3 platforms
    - Swift consumer: Swift 5.9 test app on macOS 13+
    - Python consumer: Python 3.11 test app on all 3 platforms
    - macOS PSSO Extension MDM profile via Profile Manager + Jamf Pro
    - Windows LSA via adrianlsa.dll loaded into lsass.exe (test VM)

Property-based tests — proptest
  Parsers tested:
    - All 4 TicketCache backends round-trip tickets
    - SID↔UID mapping deterministic algorithm (1000 UUIDs)
    - LDAP filter parser round-trips
    - PReg adapter round-trips
  Corpus: 80+ property tests across SDK crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-107: Rust core SDK with AdrianClient (auth + directory modules)
  - ADR-108: SSPI-equivalent AuthModule (acquire_kerberos/ntlm/cert/oauth2)
  - ADR-109: cross-platform LDAP client library
  - ADR-110: SID-to-UID mapping (deterministic + directory-stored)
  - ADR-111: unified TicketCache abstraction (KCM/API:/LSA/File)
  - ADR-049: MIT krb5 standard on Linux/macOS (via system Kerberos)
  - C ABI + Python bindings
  - PAM + NSS provider for Linux (pam_adrian.so, nss_adrian.so.2)
  - adrian-kerberos-renewd daemon

v1 (Phase 2):
  - JNI bindings for Java/Kotlin consumers
  - Swift bindings via swift-bridge
  - ADR-050: authselect as standard PAM profile mechanism
              (adrian-with-sudo profile)
  - PolicyModule + CertModule + FileModule + FederationModule
  - LSA Authentication Package for Windows (adrianlsa.dll)
  - OpenDirectory plugin for macOS (AdrianOpenDirectory.bundle)
  - ADR-048: PSSO Extension + Jamf Connect migration tools
              (adrian-cli migrate from-jamf-connect)
  - adrian-kerberos-sync daemon (macOS PSSO bridge)

v2 (Phase 3):
  - Go bindings via cgo
  - Full adrian-cli cross-platform CLI
  - Offline mode with delta sync (host agent caches directory
    subset for disconnected operation)
  - DDM-first authoring for macOS 14+ payloads (per ADR-052)
  - FIDO2 credential handle in Principal (per ADR-084)
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1 | Async runtime + block_on for FFI |
| `serde` / `serde_json` | 1 | Config + state DB serialization |
| `ldap3` | 0.11 | LDAP client (with all AD controls per ADR-006) |
| `pavao` | 0.1 | SMB client reference for FileModule |
| `rustls` | 0.23 | TLS for federation + policyd WebSocket |
| `openidconnect` | 3.3 | OIDC client for FederationModule |
| `saml2` | 0.6 | SAML client for legacy federation |
| `cbindgen` | 0.27 | C header generation (adrian-sdk-c) |
| `jni` | 0.21 | JNI bindings (adrian-sdk-jni) |
| `swift-bridge` | 0.4 | Swift bindings (adrian-sdk-swift) |
| `pyo3` | 0.21 | Python bindings (adrian-sdk-python) |
| `maturin` | 1.4 | Build tool for adrian-sdk-python wheel |
| `pam-bindings` | 0.1 | PAM module bindings (pam_adrian.so) |
| `libc` | 0.2 | POSIX bindings (NSS, getpwnam, etc.) |
| `windows` | 0.54 | Windows APIs for LSA + DPAPI |
| `objc2` | 0.5 | macOS Objective-C runtime |
| `core-foundation` | 0.10 | macOS CoreFoundation for OpenDirectory |
| `systemd` | 0.10 | systemd-creds for credential store alt |
| `gss-api` | 0.1 | GSSAPI for SPNEGO |
| `kcm-client` | 0.1 | KCM kernel keyring client (Linux) |
| `security-framework` | 2 | macOS Keychain + SecItem APIs |
| `rusqlite` | 0.31 | SQLite for per-host state DB |
| `uuid` | 1.10 | UUIDs for principals, policies |
| `thiserror` | 1 | SdkError enum |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit events |
| `proptest` | 1 | Property-based tests |
| `adrian-auth-core` | * | Principal type, AuthContext trait |
| `adrian-storage-core` | * | DirectoryStore trait (transitive) |
| `adrian-identity-core` | * | IdentityMapping trait |
| `adrian-policy-core` | * | PolicyDoc type for PolicyModule |
| `adrian-smb-client` | * | SMB client for FileModule |
| `adrian-ntlm-client` | * | NTLM client for AuthModule |

## 11. References

- ADRs: [ADR-006](../adr/ADR-006-ad-ldap-controls.md), [ADR-012](../adr/ADR-012-fast-armoring-required.md), [ADR-025](../adr/ADR-025-transactional-policy-rollback.md), [ADR-028](../adr/ADR-028-push-based-policy-websocket.md), [ADR-048](../adr/ADR-048-psso-macos-jamf-connect-migration.md), [ADR-049](../adr/ADR-049-standardize-mit-krb5.md), [ADR-050](../adr/ADR-050-authselect-standard-pam.md), [ADR-051](../adr/ADR-051-kcm-linux-api-macos-cache-abstraction.md), [ADR-052](../adr/ADR-052-ddm-first-authoring.md), [ADR-056](../adr/ADR-056-psso-modern-macos-kerberos-path.md), [ADR-075](../adr/ADR-075-cross-domain-move.md), [ADR-083](../adr/ADR-083-pac-validation-rpc.md), [ADR-084](../adr/ADR-084-pkinit-fido2-webauthn-bridge.md), [ADR-086](../adr/ADR-086-pass-the-hash-defense.md), [ADR-092](../adr/ADR-092-policy-executor-trait-synthetic-windows-cse.md), [ADR-097](../adr/ADR-097-cross-platform-autoenroll-acme.md), [ADR-106](../adr/ADR-106-smb-client-persistent-handles-sdk-filemodule.md), [ADR-107](../adr/ADR-107-unified-rust-core-sdk.md), [ADR-108](../adr/ADR-108-sspi-equivalent-auth-abstraction.md), [ADR-109](../adr/ADR-109-cross-platform-ldap-client.md), [ADR-110](../adr/ADR-110-sid-to-uid-mapping-uuid-primary.md), [ADR-111](../adr/ADR-111-unified-ticket-cache-abstraction.md)
- Workshop decisions: [Decision 11 — Client SDK](../workshop/decision-11-client-sdk.md)
- KB files: [docs/09-linux-equivalents/10-pam-nss-stack.md](../docs/09-linux-equivalents/10-pam-nss-stack.md), [docs/08-macos-equivalents/01-opendirectory-internals.md](../docs/08-macos-equivalents/01-opendirectory-internals.md), [docs/08-macos-equivalents/05-kerberos-sso-extension.md](../docs/08-macos-equivalents/05-kerberos-sso-extension.md)
- RFCs: RFC 4120 (Kerberos), RFC 4178 (SPNEGO), RFC 4511-4513 (LDAP), RFC 5929 (TLS Channel Binding), RFC 6806 (FAST), RFC 6749 (OAuth 2.0), RFC 8252 (OAuth Native Apps)
- MS-* specs: MS-LSAD / MS-LSAR (LSA, for adrianlsa.dll), MS-NRPC (Netlogon, for PAC validation RPC), MS-KILE (Kerberos PAC), MS-APDS (Authentication Protocol Domain Support)
