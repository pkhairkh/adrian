---
title: "KDC (Kerberos Key Distribution Center) — Technical Specification"
audience: rust-engineers
status: Draft
version: 0.1.0
capability: KDC
tags: [spec, kdc, kerberos, rust, implementation]
related:
  - ./README.md
  - ../finaldraft/03-capability-deep-dives.md
  - ../finaldraft/04-rust-workspace-design.md
  - ../adr/README.md
last_updated: 2026-08-13
---

# KDC (Kerberos Key Distribution Center) — Technical Specification

## 1. Overview

The KDC is the framework's authentication authority: it issues Ticket-Granting Tickets (TGTs) and service tickets, builds and signs MS-KILE-conformant Privilege Attribute Certificates (PACs), supports FAST armoring, PKINIT (smart-card and FIDO2/WebAuthn), kpasswd, cross-realm TGT referral, gMSA KDS root key rotation, and S4U2Self/S4U2Proxy constrained delegation. Every AD-aware service — IIS, SQL Server, SMB, COM+, HTTP Negotiate — reads authorization data from the PAC, so a byte-non-identical PAC breaks the entire downstream service ecosystem. The KDC is the second-most-critical capability in the framework and the longest pole on the v1 critical path after Core Directory.

This capability carries 13 ADRs: ADR-011 through ADR-020 (RC4 deprecation with AES default, FAST armoring required, cross-realm TGT referral, AES-SHA384 etype 0x13, HSM-bound krbtgt rotation, SPN uniqueness, UPN uniqueness, KDC horizontal scaling, kpasswd, gMSA KDS rotation) and ADR-082 through ADR-084 (MS-KILE PAC generation with 9 buffer types, PAC validation RPC, PKINIT-FIDO2/WebAuthn bridge). It resolves three of the framework's 23 blockers (PC-023 MS-KILE profile, PC-024 RC4 default, PC-030 krbtgt rotation) plus four high-severity problems.

Workshop Decision 5 chose a fresh Rust KDC over Samba's GPLv3 Heimdal fork and MIT-krb5-plus-plugin, justifying the ~30K-line investment on license cleanliness and PAC correctness. The KDC is implemented as four Rust crates: `adrian-kdc` (the ~30K-line server with all etypes, FAST, PKINIT, kpasswd, S4U), `adrian-kdc-interop` (MS-KILE conformance tests vs Windows Server 2022, dev-dependency only), `adrian-pkinit-bridge` (FIDO2/WebAuthn + RFC 4556 PKINIT, ~4K lines), and `adrian-pac-validator` (the unified PAC validator used by every service that consumes Kerberos tickets). External dependencies include `rasn`/`rasn-kerberos` (ASN.1 encoding), `ring`/`aes`/`sha1`/`sha2`/`hmac`/`md4` (crypto primitives), `cryptoki` (PKCS#11 HSM), `x509-cert` (PKINIT), `webauthn-rs` (FIDO2), and `proptest` (parser tests).

## 2. Crate structure

| Crate | Layer | Role | ADRs implemented |
|-------|-------|------|------------------|
| `adrian-kdc` | 3 | KDC server (~30K lines); AS-REQ/TGS-REQ path; 9-buffer PAC builder; FAST; kpasswd; S4U2Self/S4U2Proxy; gMSA KDS; cross-realm referral; etypes 0x12/0x13/0x17 | ADR-011, ADR-012, ADR-013, ADR-014, ADR-015, ADR-016, ADR-017, ADR-018, ADR-019, ADR-020, ADR-082, ADR-087 |
| `adrian-kdc-interop` | 3 | MS-KILE conformance tests vs Windows Server 2022; PAC byte-identity test; dev-dependency only | ADR-082 |
| `adrian-pkinit-bridge` | 3 | RFC 4556 smart-card PKINIT + FIDO2/WebAuthn PKINIT (PA-FIDO2-AS-REQ vendor padata 0xAB); ~4K lines | ADR-084 |
| `adrian-pac-validator` | 2 | Unified PAC validator (`libframework_pac_validator.dylib`); local Ed25519 signature verification + legacy `NetrLogonSamLogonEx` RPC fallback | ADR-083, ADR-123 |

## 3. Key types and traits

```rust
// crates/adrian-kdc/src/lib.rs

use rasn_kerberos::{KdcReq, KdcRep};
use uuid::Uuid;
use adrian_sid::Sid;

/// The KDC service. Horizontally scalable (per ADR-018); every
/// instance holds an HSM-derived krbtgt key handle (not the key
/// material), so all instances emit byte-identical PACs for the
/// same input principal.
pub struct Kdc {
    store: Arc<dyn DirectoryStore>,
    identity: Arc<dyn IdentityMapping>,
    schema: Arc<ArcSwap<SchemaProjection>>,
    krbtgt: KrbtgtKeyHandle,         // HSM-bound, ADR-015
    kds_root_keys: KdsRootKeyRing,   // gMSA, ADR-020
    pac_builder: PacBuilder,
    config: KdcConfig,
}

impl Kdc {
    pub async fn handle_as_req(&self, req: KdcReq) -> Result<KdcRep, KdcError>;
    pub async fn handle_tgs_req(&self, req: KdcReq) -> Result<KdcRep, KdcError>;
    pub async fn handle_kpasswd(&self, req: KpasswdMessage) -> Result<KpasswdReply, KdcError>;
    pub async fn handle_s4u2self(&self, req: S4u2SelfReq) -> Result<KdcRep, KdcError>;
    pub async fn handle_s4u2proxy(&self, req: S4u2ProxyReq) -> Result<KdcRep, KdcError>;
}
```

```rust
// crates/adrian-kdc/src/pac.rs (per ADR-082)

/// MS-KILE-conformant PAC. 9 buffer types emitted on every TGT;
/// byte-identity invariant vs Windows Server 2022+ maintained
/// modulo two documented divergences (LogonServer name,
/// PAC_REQUESTOR machine SID format).
#[derive(Clone, Debug)]
pub struct Pac {
    pub logon_info:           LogonInfo,             // 0x01 KERB_VALIDATION_INFO
    pub credentials:          PacCredentials,        // 0x02
    pub server_checksum:      PacSignature,          // 0x06 (HMAC-SHA1-96 over PAC minus signatures)
    pub kdc_checksum:         PacSignature,          // 0x07 (HMAC over server_checksum)
    pub client_info:          PacClientInfo,         // 0x0A
    pub constrained_delegation: Option<S4uDelegationInfo>, // 0x0B
    pub upn_dns_info:         UpnDnsInfo,            // 0x0C
    pub client_claims:        Option<PacClaims>,     // 0x09
    pub device_claims:        Option<PacClaims>,     // 0x0F
    pub ticket_checksum:      Option<PacSignature>,  // 0x0E — silver-ticket mitigation, ADR-123
    pub full_checksum:        Option<PacSignature>,  // 0x13 — full PAC checksum
    pub requestor:            Option<PacRequestor>,  // 0x12
}

pub struct PacBuilder {
    krbtgt_key_handle: KrbtgtKeyHandle,
    kdc_key_handle: KdcKeyHandle,
    logon_server_name: String,         // "adrian-dc01" (≤16 chars, ASCII)
    machine_sid: Sid,                  // PAC_REQUESTOR machine SID format
}

impl PacBuilder {
    pub async fn build_for_tgt(
        &self,
        principal: &Principal,
        logon_type: LogonType,
        client_addr: Option<IpAddr>,
    ) -> Result<Pac, KdcError>;

    pub async fn build_for_service_ticket(
        &self,
        tgt_pac: &Pac,
        service: &ServicePrincipal,
        include_ticket_checksum: bool,  // mandatory per ADR-123
    ) -> Result<Pac, KdcError>;
}

/// Etypes supported (per ADR-011, ADR-014).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Etype {
    Aes256CtsHmacSha196,  // 0x12 — default
    Aes128CtsHmacSha196,  // 0x13 — preferred when both client+server support
    Aes256CtsHmacSha384,  // 0x17 — AD-interop legacy
    Rc4Hmac,              // 0x17 (Microsoft private-use) — disabled by default
}
```

```rust
// crates/adrian-pkinit-bridge/src/lib.rs (per ADR-084)

#[async_trait]
pub trait PkinitModule: Send + Sync {
    async fn process_pa_pkinit(
        &self,
        as_req: &KdcReq,
        pa_data: &PaPkAsReq,
    ) -> Result<PaPkAsRep, KdcError>;
}

pub struct SmartCardPkinit {            // RFC 4556
    ca_cert_pool: rustls::RootCertStore,
    cert_verifier: Arc<dyn ClientCertVerifier>,
}

pub struct Fido2Pkinit {                // vendor padata 0xAB, ADR-084
    webauthn: webauthn_rs::Webauthn,
    relying_party: String,
    /// FIDO2-attested credentials mapped to AD users via
    /// userCertificate + extension 1.3.6.1.4.1.311.21.19 (adrian-fido2)
    credential_map: Arc<dyn Fido2CredentialDirectory>,
}
```

```rust
// crates/adrian-pac-validator/src/lib.rs (per ADR-083)

/// Two-layer PAC validation: local Ed25519 signature verification
/// (≤50 µs, zero DC roundtrip) using HSM-derived krbtgt public key,
/// plus legacy NetrLogonSamLogonEx (MS-NRPC opnum 45) RPC path for
/// AD-interop services that opt in.
#[async_trait]
pub trait PacValidator: Send + Sync {
    async fn validate(
        &self,
        ticket: &ServiceTicket,
        pac: &Pac,
        opts: ValidateOpts,
    ) -> Result<ValidationReport, PacError>;
}

pub struct ValidateOpts {
    pub require_full_checksum: bool,     // ADR-123: mandatory for service tickets
    pub require_ticket_checksum: bool,   // ADR-123: mandatory KDC-side, default service-side
    pub legacy_rpc_fallback: bool,       // false in native mode, true in AD-interop
    pub max_age_secs: u64,               // reject tickets older than this
}
```

## 4. Data model

The KDC has no dedicated FDB subspaces of its own — it consumes the Core Directory subspaces (`0x01` objects, `0x06` identity mapping, `0x07` tombstones) for principal data. The krbtgt and KDS root keys are stored as encrypted secret attributes on the `krbtgt` and `KDSROOTKEY` directory objects respectively; the actual key material is HSM-bound (per ADR-015) and never persisted in FDB.

```
KDC-relevant FDB keys (cross-referenced to Core Directory subspaces):

  (0x01, dnt(krbtgt), ATT_SUPPLEMENTAL_CREDENTIALS, _)
    → encrypyed supplemental credentials (key the KDC uses to
      decrypt the user's TGT-encrypted pre-auth data).
      Value encrypted with PEK (Password Encryption Key), which
      is itself HSM-bound in AD-interop mode (per ADR-086).

  (0x01, dnt(user), ATT_KRB_PRINCIPAL_NAME, _)
    → Kerberos principal name (e.g. "alice@CORP.EXAMPLE.COM")

  (0x01, dnt(user), ATT_SERVICE_PRINCIPAL_NAME, _)
    → SPN values (multi-valued). Pre-commit KDC/DSA check enforces
      forest-wide uniqueness per ADR-016; conflict returned as
      KdcError::SpnExists.

  (0x01, dnt(user), ATT_USER_PRINCIPAL_NAME, _)
    → UPN. Forest-wide uniqueness enforced at write time per ADR-017.

  (0x01, dnt(user), ATT_PRIMARY_GROUP_ID, _)
    → RID of primary group (combined with domain SID for
      PrimaryGroupSid in PAC).

  (0x01, dnt(user), ATT_TOKEN_GROUPS_NO_GC_ACCEPTABLE, _)
    → constructed attribute; DSA-side union of nested group
      memberships per ADR-009. Used for PAC group_sids.

  (0x01, dnt(KDSROOTKEY_*), ATT_MS_KDS_PROVROOT_KEY, _)
    → gMSA KDS root key blob (per ADR-020). Includes key_id,
      effective_time, expiry_time. Key material is HSM-bound.

  (0x06, 0x01, user_uuid) → user_sid
    → IdentityMapping used to translate UUID→SID for PAC.

gMSA KDS root key ring (in-memory, refreshed every 5 min):
  struct KdsRootKeyRing {
    keys: Vec<KdsRootKey>,        // sorted by effective_time
  }
  struct KdsRootKey {
    key_id: Guid,                 // ATT_MS_KDS_KDF_PARAM_ID
    effective_time: SystemTime,   // ATT_MS_KDS_CREATE_TIME
    expiry_time: SystemTime,      // ATT_MS_KDS_USE_TIME + 30d
    hsm_handle: HsmKeyHandle,     // cryptoki key handle
    kdf_param: KdfParam,          // ATT_MS_KDS_KDF_PARAM
  }

krbtgt key rotation state (per ADR-015):
  struct KrbtgtKeyHandle {
    current: HsmKeyHandle,        // active for new TGTs
    previous: HsmKeyHandle,       // honored for 24h overlap
    rotation_due: SystemTime,     // next rotation time
    rotation_interval: Duration,  // 30 days default
  }
  // rotation: create new key in HSM, swap current → previous,
  // schedule previous for destruction after 24h.
```

## 5. Protocol surface

```
KDC wire protocol (per RFC 4120 + MS-KILE):

  UDP/TCP 88   — AS-REQ / AS-REP (Authentication Service)
                 TGS-REQ / TGS-REP (Ticket-Granting Service)
                 RFC 4120 §3.1.3, §3.3
  UDP/TCP 464  — kpasswd (RFC 3244, ADR-019)
                 Change-password + set-password
  HTTPS        — KDC proxy (MS-KKDCP) for client-over-443
                 per RFC 6611 (KKDCP)

AS-REQ padata types processed:
  0x01  PA-TGS-REQ (forwarded for cross-realm)
  0x02  PA-ENC-TIMESTAMP (legacy pre-auth, AES etypes)
  0x05  PA-ENC-UNIX-TIME
  0x10  PA-PK-AS-REQ (RFC 4556 smart-card PKINIT)
  0x80  PA-FIDO2-AS-REQ (vendor, ADR-084 — FIDO2/WebAuthn)
  0x4B  PA-FX-FAST (RFC 6806 FAST armor, ADR-012)
  0x81  PA-EPAK-AS-REQ (anonymous PKINIT armor, RFC 6112)
  0x9A  PA-PKINIT-KX (PKINIT reply key, RFC 6806)
  0xA0  PA-REQ-ENC-PA-REP ( Armouring required indicator )
  0xA5  PA-SUPPORTED-ENCTYPES (MS-KILE)
  0xAB  PA-FIDO2-AS-REP (vendor reply, ADR-084)

TGS-REQ padata types processed:
  0x01  PA-TGS-REQ (the TGT)
  0x80  PA-FOR-USER (129 — S4U2Self, ADR-087)
  0x81  PA-FOR-USER-2 (constrained_delegation KDC option bit 14 — S4U2Proxy)
  0x9A  PA-PKINIT-KX

TGS-REQ KDC options enforced (per ADR-087):
  bit 14 (constrained_delegation) — S4U2Proxy
  bit 26 (forwardable)            — strict forwardable flag validation
                                     (Bronze Bit CVE-2020-17049 mitigation)
  bit 27 (forwarded)              — only valid with forwardable TGT
  bit 28 (renewable)
  bit 30 (canonicalize)

FAST (RFC 6806, ADR-012):
  Required by default — AS-REQs without FAST armor get KRB-ERROR 0x85
  (KDC_ERR_PREAUTH_REQUIRED) with PA-FX-FAST-REQ hint.
  Armor TGT may be: anonymous PKINIT (RFC 6112, per ADR-084) or
  user's own TGT.

kpasswd (RFC 3244, ADR-019):
  AP-REQ over TCP/464; pw_change (0xFF80) and pw_set (0xFF81) ops.
  REST wrapper at https://kdc.corp.example.com/api/v1/password for
  self-service UIs; mTLS auth, audit-logged.

PAC wire format (per ADR-082, MS-KILE §2.2):
  Sequence of PAC_INFO_BUFFER entries + signature buffers.
  Buffer types:
    0x01  KERB_VALIDATION_INFO (NDR-encoded; the workhorse)
    0x02  PAC_CREDENTIALS (encrypted credentials, e.g. NTLM hash)
    0x06  PAC_SERVER_CHECKSUM (HMAC-SHA1-96 over PAC minus sigs)
    0x07  PAC_PRIVSVR_CHECKSUM (HMAC over server_checksum, signed by krbtgt)
    0x09  PAC_CLIENT_CLAIMS_INFO
    0x0A  PAC_CLIENT_INFO (client ID + name)
    0x0B  PAC_CONSTRAINED_DELEGATION (S4U)
    0x0C  PAC_UPN_DNS_INFO
    0x0E  PAC_BUFFER_TICKET_CHECKSUM (per ADR-123 — silver-ticket mitigation)
    0x0F  PAC_DEVICE_CLAIMS_INFO
    0x12  PAC_REQUESTOR (per ADR-082)
    0x13  PAC_FULL_CHECKSUM (per ADR-082)

PKINIT wire (per ADR-084):
  RFC 4556 (smart-card): PA-PK-AS-REQ carries SignedData with
    client X.509 cert; KDC validates against NTAuthCertificates
    (per ADR-099, per-tenant trust store).
  FIDO2/WebAuthn (vendor): PA-FIDO2-AS-REQ (padata 0x80) carries
    WebAuthn assertion signed by hardware-bound credential.
    Credential mapped to AD user via adrian-fido2 schema extension
    (OID 1.3.6.1.4.1.311.21.19).

Cross-realm TGT referral (per ADR-013, RFC 4120 §3.3.3):
  When TGS-REQ names a principal in a foreign realm, the KDC
  returns a referral TGT encrypted in the cross-realm krbtgt key.
  Strict Transited field validation per RFC 4120 §3.3.3.1.
```

## 6. Configuration

```toml
# /etc/adrian/kdc.toml — KDC configuration

[kdc]
realm                  = "CORP.EXAMPLE.COM"
listen_addr            = "0.0.0.0:88"
kpasswd_listen_addr    = "0.0.0.0:464"
kproxy_listen_addr     = "0.0.0.0:443"   # MS-KKDCP
default_etype          = "aes256-cts-hmac-sha1-96"   # 0x12 (ADR-011)
preferred_etypes       = ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"]
rc4_enabled            = false                       # ADR-011
fast_required          = true                        # ADR-012
anonymous_pkinit_armor = true                        # ADR-084, RFC 6112
ticket_lifetime        = "10h"
renewable_lifetime     = "7d"
krbtgt_rotation_days   = 30                          # ADR-015
krbtgt_overlap_hours   = 24                          # ADR-015
pac_full_checksum_mode = "required"                 # required|supported|audit|disabled (ADR-117)
pac_ticket_checksum_mode = "required"                # ADR-123 silver-ticket mitigation
pac_validation_rpc     = true                        # ADR-083 legacy path

[hsm]                                  # enterprise-hsm feature
module                 = "pkcs11"      # pkcs11|cng
library                = "/usr/lib/softhsm/libsofthsm2.so"
slot_id                = 0
pin                    = "@file:/etc/adrian/hsm-pin"
krbtgt_key_label       = "adrian-krbtgt"
kds_root_key_label     = "adrian-kds-root"
kdc_key_label          = "adrian-kdc-signing"

[pkinit]
smartcard_enabled      = true                        # RFC 4556
fido2_enabled          = false                       # ADR-084 (Phase 3)
ntauth_cert_store      = "ldap:///CN=NTAuthCertificates,..."
fido2_relying_party    = "adrian.corp.example.com"
fido2_user_verification = "required"                 # required|preferred|discouraged

[s4u]                                  # ADR-087
s4u2self_enabled       = true
s4u2proxy_enabled      = true
rbcd_enabled           = true
bronze_bit_strict      = true                        # CVE-2020-17049 mitigation

[cross_realm]                          # ADR-013
capaths_file           = "/etc/adrian/capaths.conf"
trust_dns_discovery    = true
default_transited_policy = "always_check"            # always_check|trust_realms

[gmsa]                                 # ADR-020
kds_root_key_rotation_days = 30
kds_root_key_overlap_hours = 24
managed_service_account_default_pwd_length = 120

[audit]                                # ADR-023
as_req_logged          = true
tgs_req_logged         = true
etype_17_alerting      = true                        # ADR-064 Kerberoasting detection
sensitive_spn_alerting = true                        # MSSQL$, HTTP$, HOST$
otel_log_endpoint      = "http://otel-collector:4317"
mitre_attack_mapping   = true

[observability]
prometheus_port        = 9101
as_req_rate_target     = 5000   # per-second target
tgs_req_rate_target    = 25000  # per-second target
p95_latency_ms_target  = 50
```

## 7. Error handling

```rust
// crates/adrian-kdc/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum KdcError {
    #[error("principal not found: {0}")]
    PrincipalNotFound(String),
    #[error("pre-authentication failed for {principal}: {reason}")]
    PreAuthFailed { principal: String, reason: String },
    #[error("FAST armor required (KRB5KDC_ERR_PREAUTH_REQUIRED)")]
    FastRequired,
    #[error("etype not supported: 0x{0:x}")]
    UnsupportedEtype(u32),
    #[error("rc4 disabled by policy (per ADR-011); client requested etype 0x17")]
    Rc4Disabled,
    #[error("SPN already exists: {0}")]
    SpnExists(String),
    #[error("UPN already exists: {0}")]
    UpnExists(String),
    #[error("key version mismatch for {principal}: expected {expected}, got {actual}")]
    KeyVersionMismatch { principal: String, expected: u32, actual: u32 },
    #[error("HSM operation failed: {0}")]
    HsmError(String),
    #[error("PKINIT cert validation failed: {0}")]
    PkinitCertInvalid(String),
    #[error("FIDO2 assertion invalid: {0}")]
    Fido2AssertionInvalid(String),
    #[error("S4U2Self denied: {principal} not allowed to impersonate {target}")]
    S4u2SelfDenied { principal: String, target: String },
    #[error("S4U2Proxy denied: service {service} not in constrained delegation list for {target}")]
    S4u2ProxyDenied { service: String, target: String },
    #[error("Bronze Bit check failed: forwardable flag mismatch (CVE-2020-17049)")]
    BronzeBitMismatch,
    #[error("transited field validation failed: {0}")]
    TransitedFieldInvalid(String),
    #[error("kpasswd denied: weak password (does not meet policy)")]
    WeakPassword,
    #[error("storage layer: {0}")]
    Storage(#[from] DirectoryError),
}

// crates/adrian-pac-validator/src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum PacError {
    #[error("PAC server_checksum invalid")]
    ServerChecksumInvalid,
    #[error("PAC kdc_checksum invalid (golden-ticket suspect)")]
    KdcChecksumInvalid,
    #[error("PAC full_checksum invalid (per ADR-082 0x13 buffer)")]
    FullChecksumInvalid,
    #[error("PAC ticket_checksum invalid (silver-ticket suspect, per ADR-123)")]
    TicketChecksumInvalid,
    #[error("PAC requestor field mismatch")]
    RequestorMismatch,
    #[error("PAC expired: issued {issued}, max age {max_age_secs}s")]
    Expired { issued: SystemTime, max_age_secs: u64 },
    #[error("PAC logon_info malformed: {0}")]
    LogonInfoMalformed(String),
    #[error("PAC group SID contains sIDHistory entry blocked by trust policy (ADR-124)")]
    BlockedSidHistory,
    #[error("PAC validation RPC to {partner} failed: {reason}")]
    ValidationRpcFailed { partner: String, reason: String },
}
```

**Error propagation strategy.** KDC errors are translated 1:1 to Kerberos KRB-ERROR codes per RFC 4120 §5.9.1: `KdcError::PreAuthFailed` → `KDC_ERR_PREAUTH_FAILED (24)`, `KdcError::FastRequired` → `KDC_ERR_PREAUTH_REQUIRED (25)` with PA-FX-FAST-REQ hint, `KdcError::UnsupportedEtype` → `KDC_ERR_ETYPE_NOTSUPP (18)`, `KdcError::SpnExists` / `UpnExists` returned to LDAP modify as `LDAP_ATTRIBUTE_OR_VALUE_EXISTS`. Every KRB-ERROR includes the canonical realm name and the KDC's preferred etypes via PA-SUPPORTED-ENCTYPES (0xA5). Audit events (per ADR-023) are emitted for every failed AS-REQ/TGS-REQ with MITRE ATT&CK mapping (`T1210 Exploitation of Remote Services`, `T1558 Steal or Forge Kerberos Tickets`).

## 8. Testing strategy

```
Unit tests — per-crate, src/*.rs #[cfg(test)] modules
  Target: ≥80% line coverage (cargo-tarpaulin)
  Coverage:
    - AS-REQ / AS-REP encoder + decoder round-trips (rasn proptest, 100 cases)
    - TGS-REQ / TGS-REP encoder + decoder round-trips
    - 9-buffer PAC serialization byte-identity vs Windows-captured reference
    - FAST armor key derivation (RFC 6806 §3.2.4) HKDF-SHA1 over KRB-FX-CF
    - AES-256-CTS-HMAC-SHA1-96 key derivation (RFC 3962) over passphrase
    - PKINIT SignedData construction (RFC 4556)
    - FIDO2 assertion verification (webauthn-rs)
    - krbtgt key rotation overlap (current + previous both honored ≤24h)
    - S4U2Self / S4U2Proxy permission matrix
    - Bronze Bit check (CVE-2020-17049 regression test)
    - gMSA KDS root key derivation (MS-KILE §3.1.2)

Integration tests — tests/integration/, real FDB + tokio rt-multi-thread
  Coverage:
    - Full AS-REQ → TGS-REQ → service ticket flow
    - FAST-required enforcement (AS-REQ without armor → KRB-ERROR)
    - kpasswd change-password + set-password
    - Cross-realm TGT referral (two-realm test setup)
    - PKINIT smart-card end-to-end
    - PAC validation: local Ed25519 path + legacy RPC path
    - krbtgt rotation: issue TGT with current key, validate with previous
    - gMSA KDS root key derivation + service account password retrieval

Interop tests — tests/interop/, Docker Compose + Windows Server 2022 VM
  Critical: PAC byte-identity test (per ADR-082)
    - Capture Windows-issued PAC for principal alice@CORP.EXAMPLE.COM
      via kinit + kvno + kirbi extraction.
    - Capture framework-issued PAC for same principal via adrian-cli.
    - Compare byte-identity modulo two documented divergences:
      (a) LogonServer: "ADRIAN-DC01" (framework) vs "WIN-DC01" (Windows)
      (b) PAC_REQUESTOR machine SID: framework uses S-1-5-21-<domain>-<host>
          Windows uses S-1-5-21-<domain>-<host>$ (trailing $)
  Matrix:
    - Windows Server 2022 kinit/klist/kvno against framework KDC
    - MIT krb5 1.21 kinit against framework KDC (FAST, PKINIT)
    - Samba 4.20 samba-tool against framework KDC (cross-realm trust)
    - Java 17 GSS-API against framework KDC
    - .NET 8 KerberosRequest against framework KDC

Property-based tests — proptest
  Parsers tested:
    - AS-REQ / AS-REP / TGS-REQ / TGS-REP (rasn)
    - PAC_INFO_BUFFER sequence
    - KdcReq / KdcRep / KRB-ERROR / EncKdcRepPart
    - PrincipalName / EncryptionKey / Ticket
    - AuthorizationData (PAC is one AuthorizationData entry)
  Corpus: 100+ property tests across KDC crates
```

## 9. Implementation phases

```
MVP (Phase 1):
  - ADR-082: MS-KILE PAC builder, 9 buffer types, byte-identity
  - ADR-011: AES-256 (0x12) default, RC4 (0x17) disabled
  - ADR-015: HSM-bound krbtgt, 30-day auto-rotation, 2-key overlap
  - ADR-012: FAST armoring required by default
  - ADR-019: kpasswd (RFC 3244) + REST wrapper
  - ADR-018: KDC horizontal scaling (stateless pool)
  - ADR-023: Kerberos audit events in OTel format
  - ADR-083: PAC validation RPC (legacy path)

v1 (Phase 2):
  - ADR-016: SPN uniqueness pre-commit check
  - ADR-017: UPN uniqueness forest-wide
  - ADR-013: Cross-realm TGT referral (RFC 4120 §3.3.3)
  - ADR-087: S4U2Self + S4U2Proxy (constrained delegation, RBCD)
  - ADR-020: gMSA KDS root key rotation
  - ADR-084: PKINIT smart-card (RFC 4556)
  - ADR-123: PAC_BUFFER_TICKET_CHECKSUM mandatory KDC-side

v2 (Phase 3):
  - ADR-014: etype 0x13 (AES-SHA384) preferred when both sides support
  - ADR-084: PKINIT FIDO2/WebAuthn bridge (PA-FIDO2-AS-REQ 0x80)
  - Per-realm KDC sharding (Tier-2 ORQ; not yet a numbered ADR)
  - Predictive PAC caching for high-traffic service tickets
```

## 10. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `rasn` | 0.22 | ASN.1 + DER encoding for Kerberos messages |
| `rasn-kerberos` | 0.22 | Kerberos message types (KdcReq, KdcRep, Ticket, PAC) |
| `ring` | 0.17 | Crypto primitives (AES, HMAC, key derivation) |
| `aes` | 0.8 | AES block cipher for etypes 0x12/0x13/0x17 |
| `sha1` | 0.10 | SHA-1 for HMAC-SHA1-96 (etype 0x12) |
| `sha2` | 0.10 | SHA-256/384 for etype 0x13 + HKDF |
| `hmac` | 0.12 | HMAC for checksums and PRF |
| `md4` | 0.10 | MD4 for NTLM hash derivation (legacy compat) |
| `cryptoki` | 0.5 | PKCS#11 HSM binding for krbtgt + KDS keys |
| `x509-cert` | 0.2 | X.509 cert parsing for PKINIT |
| `webauthn-rs` | 0.5 | FIDO2/WebAuthn for PKINIT-FIDO2 (per ADR-084) |
| `tokio` | 1 | Async runtime, UDP+TCP listeners |
| `thiserror` | 1 | KdcError + PacError enums |
| `tracing` | 0.1 | Structured logging |
| `opentelemetry` | 0.24 | OTel audit event emission (per ADR-023) |
| `prometheus` | 0.13 | Metrics (AS-REQ rate, TGS-REQ rate, p95 latency) |
| `proptest` | 1 | Property-based tests for ASN.1 parsers |
| `uuid` | 1.10 | UUID types in PAC |
| `adrian-storage-core` | * | DirectoryStore trait |
| `adrian-identity-core` | * | IdentityMapping trait |
| `adrian-sid` | * | Sid type |

## 11. References

- ADRs: [ADR-011](../adr/ADR-011-rc4-deprecation-aes-default.md), [ADR-012](../adr/ADR-012-fast-armoring-required.md), [ADR-013](../adr/ADR-013-cross-realm-tgt-referral.md), [ADR-014](../adr/ADR-014-aes-sha384-etype-0x13.md), [ADR-015](../adr/ADR-015-krbtgt-hsm-rotation.md), [ADR-016](../adr/ADR-016-spn-uniqueness.md), [ADR-017](../adr/ADR-017-upn-uniqueness.md), [ADR-018](../adr/ADR-018-kdc-horizontal-scaling.md), [ADR-019](../adr/ADR-019-kpasswd-password-change.md), [ADR-020](../adr/ADR-020-gmsa-kds-rotation.md), [ADR-082](../adr/ADR-082-ms-kile-pac-generation.md), [ADR-083](../adr/ADR-083-pac-validation-rpc.md), [ADR-084](../adr/ADR-084-pkinit-fido2-webauthn-bridge.md), [ADR-087](../adr/ADR-087-s4u-constrained-delegation.md), [ADR-123](../adr/ADR-123-silver-ticket-mitigation.md)
- Workshop decisions: [Decision 5 — KDC Implementation](../workshop/decision-05-kdc-implementation.md)
- KB files: [docs/02-protocols/01-kerberos-internals.md](../docs/02-protocols/01-kerberos-internals.md), [docs/02-protocols/08-spn-upn-pac.md](../docs/02-protocols/08-spn-upn-pac.md)
- RFCs: RFC 4120 (Kerberos), RFC 4121 (Kerberos Cipher Suites), RFC 3961 (Encryption and Checksum Specs), RFC 3962 (AES Encryption), RFC 4556 (PKINIT), RFC 6112 (Anonymous PKINIT), RFC 6806 (FAST), RFC 3244 (kpasswd), RFC 6611 (KKDCP)
- MS-* specs: MS-KILE (Kerberos Protocol Extensions), MS-PAC (Privilege Attribute Certificate), MS-SFU (Service for User), MS-KKDCP (KDC Proxy)
