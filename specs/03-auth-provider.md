---
title: "Auth Provider (NTLM, SASL, SSPI-equivalent) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: Auth Provider
tags: [spec, auth-provider, ntlm, sspi, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# Auth Provider (NTLM, SASL, SSPI-equivalent) — Technical Specification

## 1. Overview

The Auth Provider is the framework's cross-protocol authentication surface: NTLM posture (drop server, client-only), LDAP signing and channel binding, NTP time-sync, structured Kerberos audit events, the SSPI-equivalent unified `AuthModule` abstraction, the unified `Principal` token type, S4U constrained delegation, and pass-the-hash defense. It is the seam that makes `pam_adrian.so`, `adrianlsa.dll`, and `AdrianOpenDirectory.bundle` all delegate to the same Rust core — eliminating the cross-platform drift that plagues AD's SSPI/PAM/OpenDirectory split.

The capability carries 7 ADRs: ADR-021 (LDAP signing + channel binding + EPA mandatory), ADR-022 (NTP via chrony, drop MS-SNTP), ADR-023 (structured Kerberos audit events in OTel format), ADR-085 (NTLM client-only, server NOT SUPPORTED), ADR-086 (pass-the-hash three-layer defense), ADR-087 (S4U2Self + S4U2Proxy + RBCD with Bronze Bit mitigation), and ADR-088 (unified `Principal` type and `AuthModule` SSPI-equivalent). It resolves two of the framework's 23 blockers (PC-037 NTLM relay, PC-038 PtH defense) plus two high-severity problems.

Workshop Decision 6 took the sharp NTLM posture: framework infrastructure accepts zero NTLM (no PetitPotam, no PtH surface against framework services), while framework-managed clients can still authenticate outbound to legacy services via the isolated `adrian-ntlm-client` crate. The unified `Principal` (ADR-088) is the single authorization token type across all platforms — `pam_adrian.so`, `adrianlsa.dll`, and `AdrianOpenDirectory.bundle` all delegate to the same Rust core.

The capability is implemented as two Rust crates at Layer 1–3: `adrian-auth-core` (the `AuthContext` trait and `Principal` type, Layer 1) and `adrian-ntlm-client` (the NTLM client-only crate, ~3K lines, Layer 3, gated by `ad-interop`). The SSPI-equivalent `AuthModule` lives in `adrian-sdk` (per ADR-108) and is documented in the Client SDK spec. External dependencies include `md4`, `hmac`, `sha2` (NTLM crypto), `rasn`/`rasn-pkix` (NTLM/SPNEGO encoding), `keyring` (platform-secure credential store), `windows`, `gss-api`, `pam-bindings`, `core-foundation`, `objc2`, `zeroize`, `cryptoki`, `systemd`.

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-auth-core` | 1 | `AuthContext` trait, `Principal` type, `CredentialHandle` enum, `LogonType`, `Privilege` types | ADR-021, ADR-022, ADR-023, ADR-087, ADR-088 |
| `adrian-ntlm-client` | 3 | NTLM client-only (~3K lines); NTLMv2 only; RFC 5929 channel binding; EPA EPHEMERAL flag; platform-secure-credential-store via `keyring`. Gated by `ad-interop`. | ADR-085, ADR-086 |

The SSPI-equivalent `AuthModule` is in `adrian-sdk` (Layer 3, per ADR-108) and is documented in `08-client-sdk.md`; this spec covers the auth-core trait and the NTLM client.

## 3. Key types and traits

```rust
// crates/adrian-auth-core/src/lib.rs

use adrian_sid::Sid;
use uuid::Uuid;
use std::time::SystemTime;

/// The unified authentication context — single token type
/// across all platforms (per ADR-088). pam_adrian.so,
/// adrianlsa.dll, AdrianOpenDirectory.bundle all delegate
/// to the same Rust core.
#[async_trait]
pub trait AuthContext: Send + Sync {
    async fn authenticate(&self, credential: &Credential)
        -> Result<Principal, AuthError>;
    async fn whoami(&self) -> Result<Principal, AuthError>;
    async fn delegate(&self, principal: &Principal, target: &str)
        -> Result<CredentialHandle, AuthError>;
    async fn has_privilege(&self, principal: &Principal, p: Privilege)
        -> Result<bool, AuthError>;
    async fn logon_type(&self) -> LogonType;
}

/// Unified Principal type (per ADR-088).
#[derive(Clone, Debug)]
pub struct Principal {
    pub sid: Sid,
    pub upn: String,
    pub group_sids: Vec<Sid>,         // recursive tokenGroups expansion
    pub primary_group_sid: Sid,
    pub privileges: Vec<Privilege>,
    pub logon_type: LogonType,
    pub logon_time: SystemTime,
    pub logon_server: String,         // "adrian-dc01" (≤16 chars ASCII)
    pub credential_handle: CredentialHandle,
    pub pac: Option<Pac>,             // populated for Kerberos logons
}

/// Credential handle variants cover all auth methods.
#[derive(Clone, Debug)]
pub enum CredentialHandle {
    KerberosTgt { service_ticket: Vec<u8>, session_key: Vec<u8> },
    NtlmHash { hash: Zeroizing<Vec<u8>>, hash_type: NtlmHashType },
    Certificate { der: Vec<u8>, key_handle: SignerHandle },
    OAuth2Token { access_token: String, refresh_token: Option<String>, expires_at: SystemTime },
    Fido2 { credential_id: Vec<u8>, sign_count: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogonType {
    Interactive,      // PAM / LsaLogonUser interactive
    Network,          // Kerberos / NTLM over network
    NetworkCleartext, // rare; only for legacy AD-interop
    Service,          // gMSA service logon
    Batch,            // scheduled task
    Proxy,            // S4U2Self
    CachedInteractive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Privilege {
    SeAssignPrimaryToken,
    SeBackupPrivilege,
    SeDebugPrivilege,
    SeImpersonatePrivilege,
    SeLoadDriverPrivilege,
    SeSecurityPrivilege,
    SeTakeOwnershipPrivilege,
    SeTcbPrivilege,
    // ... 36 privileges total, mapped 1:1 to Windows LUID privileges
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NtlmHashType { Ntlmv1Disabled, Ntlmv2 }
```

```rust
// crates/adrian-ntlm-client/src/lib.rs (per ADR-085)

use adrian_auth_core::{CredentialHandle, NtlmHashType};

/// NTLM client-only. NTLMv2 only (Ntlmv1 unconditionally disabled).
/// RFC 5929 channel binding. EPA EPHEMERAL flag.
/// Platform-secure-credential-store via `keyring` crate — NT hash
/// never persisted to disk unencrypted.
///
/// The framework's server side returns 401 Unauthorized / LDAP
/// strongAuthRequired when an NTLM token is presented to a
/// framework service.
pub struct NtlmClient {
    credential_store: Arc<dyn NtlmCredentialStore>,
    config: NtlmClientConfig,
}

impl NtlmClient {
    /// Type 1 (Negotiate) message. Server receives this and
    /// either returns 401 / strongAuthRequired (framework services)
    /// or returns Type 2 (Challenge) (legacy services).
    pub fn build_negotiate(&self, target: &str) -> Result<NegotiateMsg, AuthError>;

    /// Type 3 (Authenticate) message — NTLMv2 response with
    /// HMAC-MD5 over server challenge + client challenge + target info.
    pub fn build_authenticate(
        &self,
        challenge: &ChallengeMsg,
        credential: &NtlmCredential,
        channel_binding: Option<&ChannelBinding>,  // RFC 5929
    ) -> Result<AuthenticateMsg, AuthError>;

    /// EPA EPHEMERAL flag — client demands server prove it
    /// has fresh ephemeral key material, preventing replay.
    pub fn requires_epa_ephemeral(&self) -> bool { true }
}

/// Three layers of pass-the-hash defense (per ADR-086):
///   1. Server-side elimination — framework services accept zero NTLM
///   2. HSM-bound PEK — AD-interop users' NT hashes encrypted at rest
///      with HSM-resident Password Encryption Key (PEK)
///   3. Platform isolation — NT hash never leaves platform-secure
///      credential store (Linux kernel keyring, macOS Keychain/SE,
///      Windows DPAPI/Credential Guard)
pub trait NtlmCredentialStore: Send + Sync {
    fn load(&self, upn: &str) -> Result<Zeroizing<NtlmHash>, AuthError>;
    fn store(&self, upn: &str, hash: NtlmHash) -> Result<(), AuthError>;
    fn rotate(&self, upn: &str, new_hash: NtlmHash) -> Result<(), AuthError>;
}

pub struct NtlmHash {
    pub hash: Zeroizing<[u8; 16]>,    // MD4 over UTF-16 password
    pub hash_type: NtlmHashType,      // always Ntlmv2 in v1
}
```

```rust
// crates/adrian-auth-core/src/audit.rs (per ADR-023)

use opentelemetry::KeyValue;

/// Structured Kerberos audit events in OpenTelemetry log format.
/// Every AS-REQ, TGS-REQ, kpasswd, S4U2Self, S4U2Proxy emits one
/// audit event with MITRE ATT&CK mapping.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub event_id: u32,                // 4769-equivalent (TGS-REQ), 4768 (AS-REQ), etc.
    pub timestamp: SystemTime,
    pub outcome: AuditOutcome,        // Success | Failure | Audit
    pub principal: String,
    pub target: Option<String>,
    pub source_addr: IpAddr,
    pub etype: Option<u32>,           // 0x12, 0x13, 0x17 (RC4 — flag alert!)
    pub logon_type: LogonType,
    pub mitre_attack: Vec<&'static str>,  // ["T1558.001", "Steal or Forge Kerberos Tickets:Golden Ticket"]
    pub attributes: Vec<KeyValue>,    // extra context
}

pub enum AuditOutcome { Success, Failure, Audit }
```

## 4. Data model

The Auth Provider has no dedicated FDB subspaces — it consumes the Core Directory subspaces for principal data, and stores NTLM client credentials in the platform-secure credential store (not in FDB).

```
Auth-relevant FDB keys (cross-referenced to Core Directory subspaces):

  (0x01, dnt(user), ATT_UNICODE_PWD, _)
    → AD-interop mode: encrypted NT hash (16 bytes) encrypted with PEK.
      PEK itself is HSM-bound (per ADR-086 layer 2) — a per-DC
      PEK is stored at (0x01, dnt(domain), ATT_PEK_LIST, _) and
      the actual key material is in the HSM at label "adrian-pek".
    → Native mode: NOT STORED. Users authenticate via PKINIT,
      Kerberos password, or FIDO2. NT hashes only exist transiently
      in the credential_handle.

  (0x01, dnt(user), ATT_SUPPLEMENTAL_CREDENTIALS, _)
    → W2K-style supplemental credentials including NTLM hash
      (used by AD-interop services accepting NTLM, e.g. legacy SQL
      Server). Encrypted with PEK.

  (0x01, dnt(user), ATT_USER_CERTIFICATE, _)
    → X.509 certificates for PKINIT smart-card logon.

  (0x01, dnt(user), ATT_MS_DS_ALLOWED_TO_ACT_ON_BEHALF_OF_OTHER_IDENTITY, _)
    → RBCD ACL per ADR-087. List of SIDs allowed to impersonate
      via S4U2Proxy to this service.

  (0x01, dnt(service), ATT_MS_DS_ALLOWED_TO_DELEGATE_TO, _)
    → Classic S4U2Proxy forward-delegation list per ADR-087.

  (0x08, ts, event_id)
    → Audit events (per ADR-023). MITRE ATT&CK mapping stored
      in the OTel log attributes, not in FDB itself.

Platform-secure credential store layout (not FDB):
  Linux:   kernel keyring keytype "user" description "adrian:ntlm:<upn>"
           OR systemd-creds at /var/lib/adrian/creds/<upn>.cred
  macOS:   Keychain item class "generic", service "adrian-ntlm", account=<upn>
           OR Secure Enclave via kSecAttrTokenIDSecureEnclaveTokenID
  Windows: DPAPI CryptProtectData() blob at
           %APPDATA%\Adrian\ntlm\<upn>.bin
           OR Credential Guard VSM-protected LSA secret
```

The three-layer pass-the-hash defense (ADR-086) means there is no PtH target in the framework's native mode — framework services accept zero NTLM tokens, NT hashes are never persisted to FDB unencrypted (and never persisted at all in native mode), and on the client side, NT hashes are stored only in the platform-secure credential store with `zeroize`-wrapped memory.

## 5. Protocol surface

```
LDAP auth protocol (per ADR-021):
  Simple bind             — anonymous only; plaintext passwords rejected
  SASL/EXTERNAL           — TLS client cert
  SASL/GSS-SPNEGO         — Kerberos SPNEGO preferred; NTLM SPNEGO disabled
  SASL/GSSAPI             — pure Kerberos (no SPNEGO wrap)
  Channel binding         — RFC 5929 tls-server-end-point, MANDATORY by default
  LDAP signing            — HMAC-SHA1 over LDAP payload, MANDATORY by default
  EPA (Extended Protection for Auth) — MANDATORY by default
  StartTLS                — required before any non-anonymous bind on port 389

NTLM wire protocol (per ADR-085, client-only):
  Type 1 (Negotiate) — client → server, flags + version
  Type 2 (Challenge) — server → client, 8-byte challenge + target info
  Type 3 (Authenticate) — client → server, NTLMv2 response + 8-byte
                            client challenge + HMAC-MD5 over (challenge
                            + client challenge + target info)
  NTLMv1 — UNCONDITIONALLY DISABLED (rejected by client and server)
  NTLMv2 — only supported version

NTLMSSP padata type (per RFC 4178 SPNEGO):
  GSS-API OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
  Framework services return reject on NTLMSSP mech in SPNEGO NegTokenInit.

NTLM client target services (where framework clients may use NTLM outbound):
  Legacy SQL Server (pre-2017 with NTLM-only config)
  Legacy SMB servers (Samba 3.x, Windows Server 2003 R2)
  Legacy HTTP servers (NTLM auth providers, e.g. old IIS)
  Legacy POP3/IMAP/SMTP servers (NTLM SASL)

SASL mechs supported by framework LDAP server:
  GSS-SPNEGO    — preferred (Kerberos via SPNEGO)
  GSSAPI        — pure Kerberos
  EXTERNAL      — TLS client cert
  (no DIGEST-MD5, no CRAM-MD5, no PLAIN, no LOGIN)

NTP (per ADR-022):
  chrony on Linux/macOS; w32time service on Windows
  Drop MS-SNTP entirely — no signed NTP, no netlogon time sync
  Alert on clock skew >5 minutes (Kerberos max skew)
  NTP servers configured via DHCP or static /etc/chrony/chrony.conf

S4U2Self (per ADR-087, PA-FOR-USER padata 129):
  Client sends TGS-REQ with PA-FOR-USER padata naming target user
  KDC verifies caller has service-class TGT for the service principal
  KDC returns TGS-REP with service ticket to caller, naming target user
  in cname. Forwardable flag set per caller's TGT forwardable bit.

S4U2Proxy (per ADR-087, constrained_delegation KDC option bit 14):
  Client sends TGS-REQ with additional_ticket = [evidence ticket from S4U2Self]
  KDC verifies service is in msDS-AllowedToDelegateTo for the target
  OR (RBCD) verifies caller's SID is in msDS-AllowedToActOnBehalfOfOtherIdentity
  on the target. Bronze Bit check (CVE-2020-17049): if evidence ticket
  is not forwardable, KDC rejects with KDC_ERR_BADOPTION unless caller
  has TGS-REQ cname == additional_ticket cname.
```

## 6. Configuration

```toml
# /etc/adrian/auth.toml — Auth Provider configuration

[ldap_auth]
signing_required        = true        # ADR-021
channel_binding_required = true       # ADR-021
epa_required            = true        # ADR-021
tls_min_version         = "1.2"       # 1.3 preferred
anonymous_bind          = false
simple_bind_plaintext   = false       # never
sasl_mechs_allowed      = ["GSS-SPNEGO", "GSSAPI", "EXTERNAL"]
ntlm_spnego_allowed     = false       # framework LDAP server rejects NTLMSSP

[ntlm_client]                          # ADR-085
enabled                 = true         # gated by ad-interop feature
ntlmv1_disabled         = true         # always true
ntlmv2_enabled          = true
channel_binding_required = true        # RFC 5929
epa_ephemeral_required  = true         # EPA EPHEMERAL flag
credential_store        = "platform-default"
  # linux: kernel_keyring | systemd_creds | file
  # macos: keychain | secure_enclave
  # windows: dpapi | credential_guard
audit_all_uses          = true         # log every NTLM client use

[pth_defense]                          # ADR-086
server_side_elimination = true         # framework services accept zero NTLM
hsm_bounded_pek         = true         # AD-interop mode
platform_isolation      = true         # always
zeroize_wrappers        = true         # always
hsm_module              = "pkcs11"     # enterprise-hsm feature
hsm_library             = "/usr/lib/softhsm/libsofthsm2.so"
pek_key_label           = "adrian-pek"

[s4u]                                  # ADR-087
s4u2self_enabled        = true
s4u2proxy_enabled       = true
rbcd_enabled            = true
bronze_bit_strict       = true         # CVE-2020-17049 mitigation
audit_all_s4u           = true

[ntp]                                  # ADR-022
server                  = "time.corp.example.com"
client                  = "chrony"     # chrony on Linux/macOS, w32time on Windows
drop_ms_sntp            = true
skew_alert_threshold    = "5m"

[audit]                                # ADR-023
otel_log_endpoint       = "http://otel-collector:4317"
emit_as_req             = true
emit_tgs_req            = true
emit_kpasswd            = true
emit_s4u                = true
emit_ntlm_client        = true
emit_ldap_bind          = true
mitre_attack_mapping    = true
alert_on_rc4            = true         # ADR-064 Kerberoasting detection
alert_on_ptt            = true         # pass-the-ticket heuristic
```

## 7. Error handling

```rust
// crates/adrian-auth-core/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("authentication failed for {0}")]
    AuthFailed(String),
    #[error("LDAP signing required (per ADR-021); client sent unsigned bind")]
    LdapSigningRequired,
    #[error("channel binding required (per ADR-021); client did not provide tls-server-end-point")]
    ChannelBindingRequired,
    #[error("EPA required (per ADR-021); client did not provide channel binding")]
    EpaRequired,
    #[error("NTLM not accepted by framework services (per ADR-085)")]
    NtlmRejected,
    #[error("NTLMv1 unconditionally disabled (per ADR-085)")]
    Ntlmv1Disabled,
    #[error("NTLMv2 client credential not found for {0}")]
    NtlmCredentialNotFound(String),
    #[error("NTLM credential store access failed: {0}")]
    CredentialStoreError(String),
    #[error("S4U2Self denied: principal {principal} not allowed to impersonate {target}")]
    S4u2SelfDenied { principal: String, target: String },
    #[error("S4U2Proxy denied: service {service} not in delegation list for {target}")]
    S4u2ProxyDenied { service: String, target: String },
    #[error("Bronze Bit check failed: evidence ticket not forwardable (CVE-2020-17049)")]
    BronzeBitMismatch,
    #[error("clock skew {skew} exceeds threshold {threshold}")]
    ClockSkew { skew: Duration, threshold: Duration },
    #[error("privilege {0:?} not held")]
    PrivilegeNotHeld(Privilege),
    #[error("credential store error: {0}")]
    Io(#[from] std::io::Error),
}

// crates/adrian-ntlm-client/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum NtlmClientError {
    #[error("server returned 401 Unauthorized to NTLM Negotiate (framework service)")]
    ServerRejectedNtlm,
    #[error("server returned NTLMv1 challenge; client refuses (per ADR-085)")]
    ServerNtlmv1Only,
    #[error("channel binding required by policy but server did not advertise support")]
    NoChannelBindingSupport,
    #[error("credential store access failed: {0}")]
    CredentialStoreAccess(String),
    #[error("HSM PEK unwrap failed: {0}")]
    PekUnwrapFailed(String),
    #[error("NTLM exchange timeout after {0:?}")]
    Timeout(Duration),
    #[error("auth core: {0}")]
    AuthCore(#[from] AuthError),
}
```

**Error propagation.** LDAP auth errors map to LDAP result codes: `AuthFailed` → `invalidCredentials (49)`, `LdapSigningRequired` → `strongAuthRequired (8)`, `ChannelBindingRequired` → `confidentialityRequired (13)`. NTLM client errors map to HTTP 401 with `WWW-Authenticate: NTLM` header for retry, or surface to the calling app via `NtlmClientError`. S4U errors map to KDC errors `KDC_ERR_BADOPTION` or `KDC_ERR_S_PRINCIPAL_UNKNOWN`. Every auth error emits an OTel audit event (per ADR-023) with MITRE ATT&CK mapping; `NtlmRejected` from a framework service is alert-worthy (likely a misconfigured client).

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - NTLMv2 response computation (HMAC-MD5 over challenge+targetinfo)
    - NTLMv2 channel binding hash (RFC 5922 — RFC 5929 typo intentional)
    - EPA EPHEMERAL flag negotiation
    - PEK unwrap (HSM mock) round-trip
    - S4U2Self permission matrix (positive + negative cases)
    - S4U2Proxy RBCD vs classic delegation paths
    - Bronze Bit check (CVE-2020-17049 regression test)
    - Principal tokenGroups recursive expansion
    - Privilege enum LUID mapping
    - Zeroize on drop for all credential_handle variants

Integration tests — tests/integration/, real FDB + tokio rt-multi-thread
  Coverage:
    - LDAP GSS-SPNEGO bind end-to-end (Kerberos via MIT krb5)
    - LDAP signing enforcement (reject unsigned bind)
    - LDAP channel binding enforcement (reject without CB)
    - NTLM client outbound to Samba 3.x legacy server (Type 1/2/3 flow)
    - NTLM client credential store round-trip on all 3 platforms
    - S4U2Self + S4U2Proxy full flow with real KDC
    - RBCD permission check (positive + negative)
    - Bronze Bit check rejects forged forwardable bit
    - chrony NTP sync; clock skew alert fires at 5m threshold

Interop tests — tests/interop/
  Matrix:
    - Windows Server 2022 LDAP client against framework LDAP server
      (verify signing + CB + EPA enforcement)
    - .NET 8 NegotiateStream against framework LDAP server
    - Python ldap3 against framework LDAP server (with + without CB)
    - Samba 4.20 smbclient against framework SMB server (Kerberos)
    - Old Samba 3.x smbclient against framework SMB server (NTLM client outbound)
    - Java 17 GSS-API against framework LDAP server
    - Real-world legacy SQL Server 2008 against framework client (NTLM)

Property-based tests — proptest
  Parsers tested:
    - NTLMSSP Type 1/2/3 message round-trips
    - SPNEGO NegTokenInit / NegTokenResp round-trips
    - PA-FOR-USER padata round-trips
    - RBCD ACL blob round-trips
  Corpus: 50+ property tests across auth crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-021: LDAP signing + channel binding + EPA mandatory by default
  - ADR-085: NTLM client-only crate (NTLMv2, channel binding, EPA EPHEMERAL)
  - ADR-088: unified Principal type + AuthContext trait
  - ADR-022: chrony NTP, drop MS-SNTP
  - ADR-023: structured Kerberos audit events in OTel format
  - ADR-086: three-layer PtH defense (server-side elimination,
             HSM-bound PEK, platform isolation, zeroize wrappers)

v1 (Phase 2):
  - ADR-087: S4U2Self + S4U2Proxy (constrained delegation, RBCD)
             with Bronze Bit (CVE-2020-17049) mitigation
  - Full AuthModule SSPI-equivalent in adrian-sdk (per ADR-108)
  - RBCD ACL audit events
  - HSM-bound PEK for AD-interop NT hash at-rest encryption
  - FIDO2 credential handle in Principal

v2 (Phase 3):
  - OAuth2 token exchange to Kerberos cross-token flow
  - PKINIT-FIDO2 in native mode (eliminates NTLM entirely)
  - Predictive auth-failure alerting via OTel anomaly scoring
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `md4` | 0.10 | MD4 for NT hash derivation (legacy compat) |
| `hmac` | 0.12 | HMAC for NTLMv2 response + LDAP signing |
| `sha2` | 0.10 | SHA-256 for HKDF and channel binding |
| `rasn` | 0.22 | ASN.1 for SPNEGO NegTokenInit/Resp |
| `rasn-pkix` | 0.22 | X.509 in SPNEGO mech list |
| `keyring` | 3 | Platform-secure credential store (Linux keyring / macOS Keychain / Windows DPAPI) |
| `windows` | 0.54 | `windows-sys` for DPAPI + Credential Guard + LSA APIs |
| `gss-api` | 0.1 | GSSAPI bindings for Linux SPNEGO |
| `pam-bindings` | 0.1 | PAM module bindings for `pam_adrian.so` |
| `core-foundation` | 0.10 | macOS Keychain framework |
| `objc2` | 0.5 | macOS Objective-C runtime for Security framework |
| `zeroize` | 1.8 | Zeroize-on-drop for NT hash memory |
| `cryptoki` | 0.5 | PKCS#11 for HSM-bound PEK |
| `systemd` | 0.10 | systemd-creds for Linux credential store alt |
| `tokio` | 1 | Async runtime |
| `thiserror` | 1 | AuthError + NtlmClientError enums |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit event emission (per ADR-023) |
| `proptest` | 1 | Property-based tests |
| `adrian-sid` | * | Sid type |
| `adrian-storage-core` | * | DirectoryStore trait |
| `adrian-identity-core` | * | IdentityMapping trait |
| `adrian-kdc` | * | For S4U2Self/S4U2Proxy KDC interactions |

## 11. References

- ADRs: [ADR-021](../adr/ADR-021-ldap-signing-channel-binding.md), [ADR-022](../adr/ADR-022-ntp-chrony-time-sync.md), [ADR-023](../adr/ADR-023-kerberos-audit-events.md), [ADR-085](../adr/ADR-085-ntlm-client-only-rust-crate.md), [ADR-086](../adr/ADR-086-pass-the-hash-defense.md), [ADR-087](../adr/ADR-087-s4u-constrained-delegation.md), [ADR-088](../adr/ADR-088-unified-token-abstraction.md), [ADR-108](../adr/ADR-108-sspi-equivalent-auth-abstraction.md)
- Workshop decisions: [Decision 6 — NTLM Decision](../workshop/decision-06-ntlm-decision.md)
- KB files: [docs/02-protocols/04-ntlm-internals.md](../docs/02-protocols/04-ntlm-internals.md), [docs/02-protocols/02-ldap-protocol.md](../docs/02-protocols/02-ldap-protocol.md), [docs/02-protocols/07-ntp-time-sync.md](../docs/02-protocols/07-ntp-time-sync.md)
- RFCs: RFC 4178 (SPNEGO), RFC 5929 (TLS Channel Binding), RFC 4513 (LDAP Authentication), RFC 5801 (SASL GS2), RFC 6680 (GSS-API Naming), RFC 8080 (NTLMSSP — informational)
- MS-* specs: MS-NLMP (NTLM), MS-APDS (Authentication Protocol Domain Support), MS-SFU (Service for User), MS-KILE (Kerberos PAC), MS-LSAD / MS-LSAR (LSA, for `adrianlsa.dll`)
