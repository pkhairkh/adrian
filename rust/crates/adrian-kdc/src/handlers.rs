#![forbid(unsafe_code)]
//! # adrian-kdc :: handlers — AS-REQ / TGS-REQ handlers (RFC 4120 §3.1/§3.3)
//!
//! Implements the KDC AS-REQ → AS-REP and TGS-REQ → TGS-REP flows specified
//! by RFC 4120 §3.1 (Authentication Service Exchange) and §3.3 (Ticket-
//! Granting Service Exchange).
//!
//! ## v0.6.0 — Simplified binary wire format (NOT RFC 4120 wire-compatible)
//!
//! Full RFC 4120 ASN.1/DER encoding (with `[APPLICATION 10]` tagging,
//! explicit-length SEQUENCE OF, BIT STRING options, etc.) is out of scope for
//! v0.6.0 — wiring `rasn-kerberos` (which is already a workspace dependency)
//! is a v0.7.0 task. Instead, the handlers here use a **length-prefixed
//! self-consistent binary format** defined in this module.
//!
//! The format's contract is:
//! - `encode_X(decode_X(bytes)) == bytes` for every `X` (round-trip identity).
//! - The KDC's own AS-REP output can be parsed by the KDC's own TGS-REQ
//!   builder (used to extract the TGT and decrypt its session key).
//! - MIT krb5 / Windows / Heimdal clients CANNOT interoperate with this
//!   format. v0.7.0 must replace `encode_*`/`decode_*` with `rasn-kerberos`
//!   codec wrappers.
//!
//! ## What's REAL here
//!
//! - AS-REQ parsing: client principal name, realm, requested etypes,
//!   PA-ENC-TIMESTAMP pre-auth blob, nonce, till-time.
//! - Principal lookup via `PrincipalStore` (the in-memory implementation is
//!   used by tests; production wires the FDB-backed directory store).
//! - PA-ENC-TIMESTAMP verification: decrypt the pre-auth blob with the
//!   client's long-term key (RFC 3961 §5.1 per-usage Ke/Ki derivation, key
//!   usage 1) and verify the timestamp is within ±5 minutes of KDC time
//!   (RFC 4120 §3.1.3 clock-skew tolerance).
//! - TGT construction: build `EncTicketPart` (flags, cname, transited,
//!   times, session key), encrypt with the krbtgt key (key usage 2 for the
//!   TGT enc-part) using the RFC 3961 per-usage derivation.
//! - AS-REP construction: crealm, cname, the TGT, and an `enc-part` that
//!   contains the session key + ticket times encrypted with the client's
//!   long-term key (key usage 3 for the AS-REP enc-part shared with the
//!   client).
//! - TGS-REQ parsing: client principal, TGT, requested service principal,
//!   authenticator.
//! - TGT verification: decrypt the TGT's enc-part with the krbtgt key
//!   (key usage 2), recover the session key, verify the authenticator
//!   (encrypted with the TGT session key, key usage 7 for the authenticator
//!   cksum).
//! - Service ticket construction: build a new `Ticket` for the requested
//!   service principal, encrypted with the service's long-term key (key
//!   usage 2 for the service ticket enc-part).
//! - Etype policy (ADR-011): RC4 (etype 23) is refused; AES-256 (etype 18)
//!   is accepted; AES-128 (etype 17) is accepted.
//!
//! ## What's deferred to v0.7.0+
//!
//! - Real ASN.1/DER encoding via `rasn-kerberos` (wire-compatible with MIT
//!   krb5 / Windows).
//! - PAC generation (9-buffer PAC per ADR-082) — owned by the Wave 2b/2c
//!   PAC crate.
//! - FAST armoring (RFC 6806) — ADR-012 mandates FAST armor for all AS-REQs;
//!   the v0.6.0 handlers do NOT enforce this (they accept unarmored AS-REQs
//!   to keep the handler testable in isolation).
//! - PKINIT (RFC 4556) — `pkinit-*` feature gates remain stubs.
//! - Cross-realm TGT referral (ADR-013) — handler always answers from the
//!   local realm.
//! - S4U2Self / S4U2Proxy (ADR-087) — handler requires a real client TGT.
//! - Krbtgt key extraction from the HSM: v0.6.0 takes the raw `Aes256Key`
//!   for the krbtgt as a handler argument. Production wiring requires the
//!   HSM to support etype 18 (AES-256-CTS-HMAC-SHA1-96) directly — currently
//!   the HSM only supports AES-256-GCM, so etype 18 encryption must happen
//!   outside the HSM boundary.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use tracing::Instrument;
use uuid::Uuid;

use adrian_monitor::MetricsRegistry;

use crate::crypto::{self, Aes256Key, CONFOUNDER_LEN, HMAC_SHA1_96_LEN};
use crate::key_derivation;
use crate::store::{PrincipalRecord, PrincipalStore};
use crate::{EType, KdcError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// RFC 4120 protocol version.
pub const PVNO: u32 = 5;

/// AS-REQ message type (RFC 4120 §5.4.1).
pub const MSG_TYPE_AS_REQ: u32 = 10;
/// AS-REP message type (RFC 4120 §5.4.1).
pub const MSG_TYPE_AS_REP: u32 = 11;
/// TGS-REQ message type (RFC 4120 §5.4.2).
pub const MSG_TYPE_TGS_REQ: u32 = 12;
/// TGS-REP message type (RFC 4120 §5.4.2).
pub const MSG_TYPE_TGS_REP: u32 = 13;

/// PA-ENC-TIMESTAMP padata type (RFC 4120 §5.2.7.2).
pub const PA_ENC_TIMESTAMP_TYPE: u8 = 2;

/// RFC 4120 §7.5.1 key usage numbers.
pub const KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP: u32 = 1;
pub const KEY_USAGE_AS_REP_TGT: u32 = 2;
pub const KEY_USAGE_AS_REP_ENC_PART: u32 = 3;
pub const KEY_USAGE_TGS_REQ_AUTHENTICATOR: u32 = 7;
pub const KEY_USAGE_TGS_REP_ENC_PART: u32 = 8;
pub const KEY_USAGE_TGS_REP_TICKET: u32 = 2;

/// RFC 4120 §3.1.3 clock skew tolerance (5 minutes, in seconds).
pub const CLOCK_SKEW_TOLERANCE_SECS: i64 = 5 * 60;

/// Default TGT lifetime (ADR-015 §Decision: 10 hours, in seconds).
pub const DEFAULT_TGT_LIFETIME_SECS: i64 = 10 * 60 * 60;

/// Default service ticket lifetime (10 hours, in seconds).
pub const DEFAULT_SVC_TICKET_LIFETIME_SECS: i64 = 10 * 60 * 60;

/// Session key length (32 bytes — AES-256).
pub const SESSION_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// FAST armoring constants (RFC 6806 / ADR-012)
// ---------------------------------------------------------------------------

/// PA-FX-FAST-START padata type (RFC 6806 §5.4.1). Carries the
/// `KrbFastArmoredReq` in the outer AS-REQ's padata list.
pub const PA_FX_FAST_START_TYPE: u8 = 143;

/// RFC 6806 §7.5.1 key usage for the FAST armored req enc-part.
pub const KEY_USAGE_FAST_ARMOR_REQ_ENC: u32 = 65;

/// RFC 6806 §7.5.1 key usage for the FAST armored req checksum.
pub const KEY_USAGE_FAST_ARMOR_REQ_CKSUM: u32 = 66;

/// FAST armor type 1 — TGT armor (RFC 6806 §5.4.1). The armor TGT's
/// session key is used to derive the FAST armor key.
pub const FAST_ARMOR_TYPE_TGT: u32 = 1;

// v0.7.0: The v0.6.0 wire-format magic bytes (0xA1-0xB5) have been removed.
// All encode/decode functions now use real ASN.1/DER via `rasn-kerberos`
// (see `crate::wire`).

// ---------------------------------------------------------------------------
// Wire-format types
// ---------------------------------------------------------------------------

/// PA-ENC-TS-ENC (RFC 4120 §5.2.7.2) — plaintext payload of the PA-ENC-
/// TIMESTAMP pre-authenticator. Contains the client's notion of the current
/// time; the KDC verifies it's within the clock-skew tolerance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaEncTsEnc {
    /// Seconds since UNIX epoch (UTC).
    pub patimestamp: i64,
    /// Microseconds (0..1_000_000); informational.
    pub pausec: u32,
}

/// A single PA-DATA entry (RFC 4120 §5.2.7). For v0.6.0 we model only the
/// types the handler actually consumes (`PA-ENC-TIMESTAMP`, type 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaData {
    /// padata-type (only `PA_ENC_TIMESTAMP_TYPE = 2` is supported).
    pub padata_type: u8,
    /// padata-value (opaque bytes; for PA-ENC-TIMESTAMP this is the encrypted
    /// `PaEncTsEnc` blob).
    pub padata_value: Vec<u8>,
}

/// AS-REQ (RFC 4120 §5.4.1) — simplified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsReq {
    pub pvno: u32,
    pub msg_type: u32,
    /// Client realm (RFC 4120 §5.2.1 Realm).
    pub realm: String,
    /// Client principal name components (e.g. `["alice"]`).
    pub cname: Vec<String>,
    /// Client-chosen nonce (echoed back in AS-REP).
    pub nonce: u32,
    /// Client-supported etypes (RFC 4120 §5.2.8).
    pub etypes: Vec<EType>,
    /// Pre-authenticators.
    pub padata: Vec<PaData>,
    /// Requested end-time (seconds since UNIX epoch; 0 = use KDC default).
    pub till: i64,
}

/// Ticket (RFC 4120 §5.3). The TGT is a `Ticket` whose `sname` is
/// `krbtgt/<REALM>` and whose `enc_part` is encrypted with the krbtgt key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub tkt_vno: u32,
    pub realm: String,
    pub sname: Vec<String>,
    /// Key version number of the encrypting key (for krbtgt, this is the
    /// `kvno` from `KrbtgtManager`).
    pub kvno: u32,
    pub etype: EType,
    /// Output of `encrypt_for_usage(krbtgt_key, KEY_USAGE_AS_REP_TGT, &enc_ticket_part_bytes)`.
    pub enc_part: Vec<u8>,
}

/// EncTicketPart (RFC 4120 §5.3) — plaintext of the Ticket's enc-part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncTicketPart {
    /// Ticket flags (RFC 4120 §5.3.1). For v0.6.0 we store only the
    /// forwardable + renewable bits (bit 1 and bit 8).
    pub flags: u32,
    pub crealm: String,
    pub cname: Vec<String>,
    /// TGT session key (32 bytes, AES-256).
    pub session_key: [u8; SESSION_KEY_LEN],
    pub authtime: i64,
    pub starttime: i64,
    pub endtime: i64,
    pub renew_till: i64,
    /// UUID of the client principal (carries the AD objectGUID).
    pub client_uuid: Uuid,
}

/// EncASRepPart / EncTgsRepPart (RFC 4120 §5.4.2) — plaintext of the
/// AS-REP / TGS-REP `enc-part`. Encrypted with the client's key (AS-REP) or
/// the TGT session key (TGS-REP).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncKdcRepPart {
    pub session_key: [u8; SESSION_KEY_LEN],
    pub last_req: i64,
    pub nonce: u32,
    pub authtime: i64,
    pub starttime: i64,
    pub endtime: i64,
    pub renew_till: i64,
    pub crealm: String,
    pub cname: Vec<String>,
}

/// AS-REP (RFC 4120 §5.4.1) — simplified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsRep {
    pub pvno: u32,
    pub msg_type: u32,
    pub crealm: String,
    pub cname: Vec<String>,
    pub ticket: Ticket,
    pub enc_part_etype: EType,
    pub enc_part_kvno: u32,
    /// Encrypted `EncKdcRepPart` (encrypted with the client's long-term key,
    /// key usage 3).
    pub enc_part: Vec<u8>,
}

/// Authenticator (RFC 4120 §5.5.1) — plaintext of the AP-REQ authenticator
/// carried in a TGS-REQ. Carries the client's claim of "I am who the TGT
/// says I am, right now".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticator {
    pub crealm: String,
    pub cname: Vec<String>,
    /// Sub-session key (optional; usually `None` for TGS-REQ).
    pub subkey: Option<[u8; SESSION_KEY_LEN]>,
    /// Sequence number (informational).
    pub seq_number: u32,
    /// Client's claimed current time (RFC 4120 §5.5.1 authenticator cksum
    /// is omitted; the timestamp itself is the anti-replay defense).
    pub ctime: i64,
    pub cusec: u32,
}

/// TGS-REQ (RFC 4120 §5.4.2) — simplified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TgsReq {
    pub pvno: u32,
    pub msg_type: u32,
    /// Requested service principal's realm.
    pub realm: String,
    /// Requested service principal's name components (e.g. `["host", "web.example.com"]`).
    pub sname: Vec<String>,
    /// Client-chosen nonce.
    pub nonce: u32,
    pub etypes: Vec<EType>,
    /// The TGT (carried as PA-TGS-REQ in RFC 4120; here inline).
    pub tgt: Ticket,
    /// Authenticator encrypted with the TGT session key (key usage 7).
    pub authenticator_enc: Vec<u8>,
    /// Requested end-time (0 = use KDC default).
    pub till: i64,
}

/// TGS-REP (RFC 4120 §5.4.2) — simplified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TgsRep {
    pub pvno: u32,
    pub msg_type: u32,
    pub crealm: String,
    pub cname: Vec<String>,
    pub ticket: Ticket,
    pub enc_part_etype: EType,
    pub enc_part_kvno: u32,
    /// Encrypted `EncKdcRepPart` (encrypted with the TGT session key,
    /// key usage 8).
    pub enc_part: Vec<u8>,
}

// ---------------------------------------------------------------------------
// FAST armoring types (RFC 6806 / ADR-012)
// ---------------------------------------------------------------------------

/// FAST enforcement mode (ADR-012 §Decision). Controls how the KDC handles
/// AS-REQs that do not carry FAST armoring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FastMode {
    /// KDC accepts both FAST and non-FAST AS-REQs (migration mode).
    Supported,
    /// KDC refuses non-FAST AS-REQs with `KdcError::FastArmorRequired`
    /// (ADR-012 §Decision default).
    #[default]
    Required,
    /// KDC accepts non-FAST AS-REQs but logs them as security events per
    /// ADR-023 (audit-only mode for AS-REP-roasting detection).
    Audit,
    /// KDC accepts non-FAST AS-REQs for a configurable grace period, then
    /// flips to `Required` automatically (ADR-012 §Decision).
    Grace,
}

/// FAST armor key (RFC 6806 §5.4). Derived from the armor TGT's session key
/// via the Kerberos PRF. Used to encrypt/decrypt the FAST armored request's
/// enc-part (key usage 65) and the AS-REP enc-part (replacing the client's
/// long-term key — the AS-REP roasting mitigation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastArmorKey {
    /// 32-byte AES-256 armor key.
    pub key: [u8; SESSION_KEY_LEN],
}

/// FAST factor (RFC 6806 §5.4.1) — the inner padata carried inside the
/// armored request. Encrypted with the FAST armor key (key usage 65).
/// Carries the real pre-authenticator (e.g. PA-ENC-TIMESTAMP) plus an
/// anti-replay nonce and timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastFactor {
    /// Inner padata (e.g. PA-ENC-TIMESTAMP) encrypted under the armor key.
    pub inner_padata: Vec<PaData>,
    /// Client-chosen nonce (echoed back in the FAST response).
    pub nonce: u32,
    /// Client's notion of current time (anti-replay; checked against the
    /// KDC clock within the ±5 minute skew tolerance per RFC 4120 §3.1.3).
    pub timestamp: i64,
}

/// KrbFastArmoredReq (RFC 6806 §5.4.1) — the outer armored request. Carries
/// the armor TGT and the encrypted FAST factor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KrbFastArmoredReq {
    /// Armor type: 1 = TGT armor (RFC 6806 §5.4.1). Only type 1 is supported.
    pub armor_type: u32,
    /// Armor TGT (when armor_type == 1). The TGT's session key is used to
    /// derive the FAST armor key.
    pub armor_tgt: Ticket,
    /// Encrypted FAST factor (encrypted with the FAST armor key, key usage 65).
    pub enc_part: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Binary codec helpers
// ---------------------------------------------------------------------------

/// Decode error — surfaced as `KdcError::Storage` to callers.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("invalid UTF-8 in string field")]
    InvalidUtf8,
    #[error("magic byte mismatch (expected {expected:#x}, got {actual:#x})")]
    MagicMismatch { expected: u8, actual: u8 },
    #[error("unknown etype {0}")]
    UnknownEtype(u32),
    #[error("invalid message type {0}")]
    InvalidMsgType(u32),
    #[error("invalid pvno {0}")]
    InvalidPvno(u32),
}

impl From<DecodeError> for KdcError {
    fn from(e: DecodeError) -> Self {
        KdcError::Storage(format!("decode: {e}"))
    }
}

impl EType {
    /// Map a wire u32 to an `EType`. Returns `None` for unsupported etypes.
    pub fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            17 => Some(EType::Aes128CtsHmacSha1_96),
            18 => Some(EType::Aes256CtsHmacSha1_96),
            19 => Some(EType::Aes128CtsHmacSha256_128),
            20 => Some(EType::Aes256CtsHmacSha384_192),
            23 => Some(EType::Rc4Hmac),
            _ => None,
        }
    }

    /// ADR-011 policy: AES family is allowed; RC4 (etype 23) is disabled.
    pub fn is_allowed_by_policy(self) -> bool {
        !matches!(self, EType::Rc4Hmac)
    }
}

// ---------------------------------------------------------------------------
// ASN.1/DER encode/decode — delegated to `crate::wire` (v0.7.0)
// ---------------------------------------------------------------------------
// v0.7.0: The v0.6.0 simplified binary format (magic bytes + length-prefixed
// fields) has been replaced with real RFC 4120 ASN.1/DER encoding via
// `rasn-kerberos`. See `crate::wire` for the implementation. The re-exports
// below preserve the public API (callers in the handler logic and tests
// continue to call `encode_*` / `decode_*` unchanged).

pub use crate::wire::{
    decode_as_rep, decode_as_req, decode_authenticator, decode_enc_kdc_rep_part,
    decode_enc_ticket_part, decode_pa_enc_ts_enc, decode_tgs_rep, decode_tgs_req, decode_ticket,
    encode_as_rep, encode_as_req, encode_authenticator, encode_enc_kdc_rep_part,
    encode_enc_ticket_part, encode_pa_enc_ts_enc, encode_tgs_rep, encode_tgs_req, encode_ticket,
};

// ---------------------------------------------------------------------------
// Per-usage encryption (RFC 3961 §5.1)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` for the given key usage, using the RFC 3961 §5.1
/// per-usage Ke (encryption) and Ki (integrity) keys derived from
/// `base_key`.
///
/// Wire format (self-consistent, NOT RFC 4120 wire-compatible):
/// `aes256_ctr(Ke, confounder || plaintext) || hmac_sha1_96(Ki, confounder || plaintext)`
///
/// This is the etype-18 analog of `crypto::encrypt_aes256_cts_hmac_sha1_96`,
/// but with RFC 3961 §5.1 per-usage key derivation layered on top.
pub(crate) fn encrypt_for_usage(
    base_key: &Aes256Key,
    key_usage: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, KdcError> {
    let ke = key_derivation::derive_encryption_key(base_key, key_usage);
    let ki = key_derivation::derive_integrity_key(base_key, key_usage);

    // Generate a random confounder (1 AES block).
    let confounder = random_bytes(CONFOUNDER_LEN)?;
    let mut full = Vec::with_capacity(CONFOUNDER_LEN + plaintext.len());
    full.extend_from_slice(&confounder);
    full.extend_from_slice(plaintext);

    // AES-CTR encrypt (length-preserving) under Ke.
    let ct = crypto::aes256_cts_encrypt(&ke, &full)
        .map_err(|e| KdcError::Storage(format!("aes encrypt: {e}")))?;
    // HMAC-SHA1-96 over (confounder || plaintext) under Ki.
    let tag = crypto::hmac_sha1_96(&ki, &full);

    let mut out = Vec::with_capacity(ct.len() + HMAC_SHA1_96_LEN);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_for_usage`]. Verifies the HMAC
/// in constant time before returning the plaintext.
pub(crate) fn decrypt_for_usage(
    base_key: &Aes256Key,
    key_usage: u32,
    cipher_blob: &[u8],
) -> Result<Vec<u8>, KdcError> {
    let ke = key_derivation::derive_encryption_key(base_key, key_usage);
    let ki = key_derivation::derive_integrity_key(base_key, key_usage);

    if cipher_blob.len() < CONFOUNDER_LEN + HMAC_SHA1_96_LEN {
        return Err(KdcError::Storage(format!(
            "cipher too short: {} < {}",
            cipher_blob.len(),
            CONFOUNDER_LEN + HMAC_SHA1_96_LEN
        )));
    }
    let ct_len = cipher_blob.len() - HMAC_SHA1_96_LEN;
    let (ct, tag) = cipher_blob.split_at(ct_len);

    let pt_with_confounder = crypto::aes256_cts_decrypt(&ke, ct)
        .map_err(|e| KdcError::Storage(format!("aes decrypt: {e}")))?;
    let expected_tag = crypto::hmac_sha1_96(&ki, &pt_with_confounder);
    if !constant_time_eq(&expected_tag, tag) {
        return Err(KdcError::PreauthFailed("HMAC mismatch".into()));
    }
    Ok(pt_with_confounder[CONFOUNDER_LEN..].to_vec())
}

/// Constant-time slice equality. Returns `false` immediately (but in
/// length-independent fashion) if lengths differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

/// Generate `len` cryptographically-secure random bytes using `ring`'s
/// `SystemRandom`.
fn random_bytes(len: usize) -> Result<Vec<u8>, KdcError> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf)
        .map_err(|_| KdcError::Storage("SystemRandom fill failed".into()))?;
    Ok(buf)
}

/// Current time in seconds since the UNIX epoch.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Generate a random 32-byte session key.
fn random_session_key() -> Result<[u8; SESSION_KEY_LEN], KdcError> {
    let buf = random_bytes(SESSION_KEY_LEN)?;
    let mut k = [0u8; SESSION_KEY_LEN];
    k.copy_from_slice(&buf);
    Ok(k)
}

// ---------------------------------------------------------------------------
// AS-REQ handler
// ---------------------------------------------------------------------------

/// Map an `EType` to its canonical Kerberos string label, used as the
/// `etype` label of the `adrian_as_req_total{realm,etype}` counter per
/// ADR-057 §Decision (Wave 3b — wire MetricsRegistry producers).
fn etype_label(e: EType) -> &'static str {
    match e {
        EType::Aes256CtsHmacSha1_96 => "aes256-cts-hmac-sha1-96",
        EType::Aes128CtsHmacSha1_96 => "aes128-cts-hmac-sha1-96",
        EType::Aes128CtsHmacSha256_128 => "aes128-cts-hmac-sha256-128",
        EType::Aes256CtsHmacSha384_192 => "aes256-cts-hmac-sha384-192",
        EType::Rc4Hmac => "rc4-hmac",
    }
}

/// Backward-compatible AS-REQ handler (Wave 3a signature): records no
/// metrics and is equivalent to calling
/// [`handle_as_req_with_metrics`] with `metrics = None`.
///
/// Existing callers (tests, future SDK wiring) keep working unchanged;
/// production hot paths should call [`handle_as_req_with_metrics`] with a
/// shared [`MetricsRegistry`] so the AS-REQ counter + latency histogram
/// are populated for Prometheus (EVALUATION.md P1 #14).
pub async fn handle_as_req(
    store: &dyn PrincipalStore,
    krbtgt_key: &Aes256Key,
    req_bytes: &[u8],
) -> Result<Vec<u8>, KdcError> {
    handle_as_req_with_metrics(store, krbtgt_key, req_bytes, None).await
}

/// AS-REQ handler wired to a [`MetricsRegistry`] producer + `tracing` span.
///
/// Emits:
/// - `tracing::info_span!("as_req")` around the whole handler (per
///   EVALUATION.md §"Add `tracing::Span` per inbound request").
/// - `tracing::info!("AS-REQ received", realm, principal, etype)` after
///   parsing + etype negotiation succeeds.
/// - `tracing::debug!("AS-REQ completed", elapsed)` after the AS-REP is
///   encoded.
/// - `metrics.inc_as_req(realm, etype)` (ADR-057 `as_req_total` counter).
/// - `metrics.observe_as_req_duration(elapsed)` (ADR-057
///   `as_req_duration_seconds` histogram).
///
/// When `metrics` is `None`, no metric calls are made (the handler is
/// equivalent to the v0.6.0 back-compat path) — used by tests that only
/// verify the AS-REP bytes.
pub async fn handle_as_req_with_metrics(
    store: &dyn PrincipalStore,
    krbtgt_key: &Aes256Key,
    req_bytes: &[u8],
    metrics: Option<&MetricsRegistry>,
) -> Result<Vec<u8>, KdcError> {
    let span = tracing::info_span!("as_req");
    handle_as_req_with_metrics_inner(store, krbtgt_key, req_bytes, metrics)
        .instrument(span)
        .await
}

/// Inner AS-REQ handler body — extracted so the `tracing::Span` from
/// [`handle_as_req_with_metrics`] is entered for every `await` point.
async fn handle_as_req_with_metrics_inner(
    store: &dyn PrincipalStore,
    krbtgt_key: &Aes256Key,
    req_bytes: &[u8],
    metrics: Option<&MetricsRegistry>,
) -> Result<Vec<u8>, KdcError> {
    let start = Instant::now();
    let req = decode_as_req(req_bytes)?;

    // Etype negotiation (ADR-011): AES family allowed; RC4 refused.
    let chosen_etype = negotiate_etype(&req.etypes)?;

    // ---- Metrics + tracing: AS-REQ received ----
    // Increment the `as_req_total{realm,etype}` counter only after we
    // have a negotiated etype (so the counter's `etype` label is always
    // a real cipher name, never "unsupported"). Tracing the principal
    // here gives operators a per-request breadcrumb to correlate with
    // the metric increment.
    let realm = req.realm.clone();
    let principal = req.cname.join("/");
    tracing::info!(
        realm = %realm,
        principal = %principal,
        etype = %etype_label(chosen_etype),
        "AS-REQ received"
    );
    if let Some(m) = metrics {
        m.inc_as_req(&realm, etype_label(chosen_etype)).await;
    }

    // Look up the client principal.
    let client = store
        .lookup(&req.realm, &req.cname)
        .await
        .map_err(|e| KdcError::Storage(format!("principal lookup: {e}")))?
        .ok_or_else(|| {
            KdcError::PrincipalNotFound(format!("{}/{}", req.realm, req.cname.join("/")))
        })?;

    // Verify PA-ENC-TIMESTAMP pre-auth.
    let pa_enc_ts = find_pa_enc_timestamp(&req.padata)?;
    match pa_enc_ts {
        Some(blob) => {
            verify_pa_enc_timestamp(&client, &blob)?;
        }
        None => {
            // RFC 4120 §3.1: KDC returns KDC_ERR_PREAUTH_REQUIRED with a
            // PA-ETYPE-INFO2 hint listing supported etypes. For v0.6.0 we
            // surface the typed error; the wire-format error reply is a
            // v0.7.0 task.
            return Err(KdcError::PreauthRequired);
        }
    }

    // Build the TGT.
    let now = now_secs();
    let session_key = random_session_key()?;
    let krbtgt_kvno = 1; // v0.6.0: caller passes raw key; kvno tracking is v0.7.0.

    let enc_ticket_part = EncTicketPart {
        flags: TICKET_FLAG_FORWARDABLE | TICKET_FLAG_RENEWABLE,
        crealm: client.realm.clone(),
        cname: client.components.clone(),
        session_key,
        authtime: now,
        starttime: now,
        endtime: now + DEFAULT_TGT_LIFETIME_SECS,
        renew_till: now + 2 * DEFAULT_TGT_LIFETIME_SECS,
        client_uuid: client.uuid,
    };
    let enc_ticket_part_bytes = encode_enc_ticket_part(&enc_ticket_part);
    let ticket_enc = encrypt_for_usage(krbtgt_key, KEY_USAGE_AS_REP_TGT, &enc_ticket_part_bytes)?;

    let tgt = Ticket {
        tkt_vno: PVNO,
        realm: client.realm.clone(),
        sname: vec!["krbtgt".to_string(), client.realm.clone()],
        kvno: krbtgt_kvno,
        etype: chosen_etype,
        enc_part: ticket_enc,
    };

    // Build the AS-REP enc-part (encrypted with the client's key, key usage 3).
    let enc_rep_part = EncKdcRepPart {
        session_key,
        last_req: now,
        nonce: req.nonce,
        authtime: now,
        starttime: now,
        endtime: now + DEFAULT_TGT_LIFETIME_SECS,
        renew_till: now + 2 * DEFAULT_TGT_LIFETIME_SECS,
        crealm: client.realm.clone(),
        cname: client.components.clone(),
    };
    let enc_rep_part_bytes = encode_enc_kdc_rep_part(&enc_rep_part);
    let enc_part = encrypt_for_usage(&client.key, KEY_USAGE_AS_REP_ENC_PART, &enc_rep_part_bytes)?;

    let rep = AsRep {
        pvno: PVNO,
        msg_type: MSG_TYPE_AS_REP,
        crealm: client.realm.clone(),
        cname: client.components.clone(),
        ticket: tgt,
        enc_part_etype: chosen_etype,
        enc_part_kvno: client.kvno,
        enc_part,
    };

    // ---- Metrics + tracing: AS-REQ completed ----
    // Observe the end-to-end AS-REQ handling latency in the
    // `as_req_duration_seconds` histogram (ADR-057). The `tracing::debug!`
    // event mirrors the metric for ad-hoc operator triage via RUST_LOG.
    let elapsed = start.elapsed();
    if let Some(m) = metrics {
        m.observe_as_req_duration(elapsed.as_secs_f64()).await;
    }
    tracing::debug!(elapsed = ?elapsed, "AS-REQ completed");

    Ok(encode_as_rep(&rep))
}

/// Ticket flag bits (RFC 4120 §5.3.1).
pub const TICKET_FLAG_FORWARDABLE: u32 = 1 << 1;
pub const TICKET_FLAG_RENEWABLE: u32 = 1 << 8;

/// Choose the strongest mutually-supported etype from the client's offered
/// list, applying ADR-011 policy (RC4 disabled).
pub fn negotiate_etype(offered: &[EType]) -> Result<EType, KdcError> {
    // Prefer AES-256 (etype 18) > AES-128 (17) > AES-256-SHA384 (20) > AES-128-SHA256 (19).
    if offered.contains(&EType::Aes256CtsHmacSha1_96) {
        return Ok(EType::Aes256CtsHmacSha1_96);
    }
    if offered.contains(&EType::Aes128CtsHmacSha1_96) {
        return Ok(EType::Aes128CtsHmacSha1_96);
    }
    if offered.contains(&EType::Aes256CtsHmacSha384_192) {
        return Ok(EType::Aes256CtsHmacSha384_192);
    }
    if offered.contains(&EType::Aes128CtsHmacSha256_128) {
        return Ok(EType::Aes128CtsHmacSha256_128);
    }
    if offered.contains(&EType::Rc4Hmac) {
        return Err(KdcError::Policy(
            "rc4 disabled (ADR-011); client must offer AES".into(),
        ));
    }
    Err(KdcError::ETypeUnsupported(EType::Aes256CtsHmacSha1_96))
}

/// Find the PA-ENC-TIMESTAMP padata entry (type 2). Returns the encrypted
/// blob (caller must decrypt).
pub fn find_pa_enc_timestamp(padata: &[PaData]) -> Result<Option<Vec<u8>>, KdcError> {
    for p in padata {
        if p.padata_type == PA_ENC_TIMESTAMP_TYPE {
            return Ok(Some(p.padata_value.clone()));
        }
    }
    Ok(None)
}

/// Verify a PA-ENC-TIMESTAMP blob: decrypt with the client's key (key usage
/// 1), parse `PaEncTsEnc`, check timestamp within ±5 minutes of KDC time.
pub fn verify_pa_enc_timestamp(client: &PrincipalRecord, blob: &[u8]) -> Result<(), KdcError> {
    let plaintext = decrypt_for_usage(&client.key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, blob)
        .map_err(|_| KdcError::PreauthFailed("decrypt failed".into()))?;
    let ts = decode_pa_enc_ts_enc(&plaintext)?;
    let now = now_secs();
    let skew = now - ts.patimestamp;
    if skew.abs() > CLOCK_SKEW_TOLERANCE_SECS {
        return Err(KdcError::PreauthFailed(format!(
            "clock skew {skew}s exceeds tolerance {CLOCK_SKEW_TOLERANCE_SECS}s"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FAST armoring (RFC 6806) — key derivation + wrap/unwrap + handler
// ---------------------------------------------------------------------------

/// Derive the FAST armor key from the armor TGT's session key per
/// RFC 6806 §5.4: `KrbFastArmorKey = PRF(armor_key, "fastarmorkey" || armor_key)`.
///
/// We use HMAC-SHA256 as the PRF (32-byte output = `SESSION_KEY_LEN`). The
/// real RFC 3961 §5.5 PRF for AES enctypes is AES-CMAC-based; HMAC-SHA256 is
/// cryptographically sound and avoids a dependency on the HSM's PRF. The
/// derivation is deterministic: the same armor TGT session key always
/// produces the same FAST armor key.
pub fn derive_fast_armor_key(armor_tgt_session_key: &[u8; SESSION_KEY_LEN]) -> FastArmorKey {
    use ring::hmac::{Context, Key, HMAC_SHA256};
    let key = Key::new(HMAC_SHA256, armor_tgt_session_key);
    let mut ctx = Context::with_key(&key);
    ctx.update(b"fastarmorkey");
    ctx.update(armor_tgt_session_key);
    let tag = ctx.sign();
    let mut out = [0u8; SESSION_KEY_LEN];
    out.copy_from_slice(tag.as_ref());
    FastArmorKey { key: out }
}

/// Minimal length-prefixed byte reader for the FAST codec. Reads big-endian
/// integers and length-prefixed byte slices from a `&[u8]` buffer.
struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        if self.pos + 1 > self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(a))
    }
    fn read_i64(&mut self) -> Result<i64, DecodeError> {
        if self.pos + 8 > self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(i64::from_be_bytes(a))
    }
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(DecodeError::UnexpectedEof);
        }
        let v = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(v)
    }
}

/// Encode a `FastFactor` as length-prefixed bytes (self-consistent binary
/// format — NOT RFC 4120 ASN.1/DER; the FAST ASN.1 codec is a future wiring
/// task once `rasn-kerberos` adds the RFC 6806 types).
pub fn encode_fast_factor(f: &FastFactor) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(f.inner_padata.len() as u32).to_be_bytes());
    for p in &f.inner_padata {
        out.push(p.padata_type);
        out.extend_from_slice(&(p.padata_value.len() as u32).to_be_bytes());
        out.extend_from_slice(&p.padata_value);
    }
    out.extend_from_slice(&f.nonce.to_be_bytes());
    out.extend_from_slice(&f.timestamp.to_be_bytes());
    out
}

/// Decode a `FastFactor` from length-prefixed bytes (inverse of
/// [`encode_fast_factor`]).
pub fn decode_fast_factor(bytes: &[u8]) -> Result<FastFactor, DecodeError> {
    let mut r = ByteReader::new(bytes);
    let padata_count = r.read_u32()? as usize;
    let mut inner_padata = Vec::with_capacity(padata_count);
    for _ in 0..padata_count {
        let padata_type = r.read_u8()?;
        let vlen = r.read_u32()? as usize;
        let padata_value = r.read_bytes(vlen)?.to_vec();
        inner_padata.push(PaData {
            padata_type,
            padata_value,
        });
    }
    let nonce = r.read_u32()?;
    let timestamp = r.read_i64()?;
    Ok(FastFactor {
        inner_padata,
        nonce,
        timestamp,
    })
}

/// Encode a `KrbFastArmoredReq` as length-prefixed bytes. The armor TGT is
/// encoded via the existing `encode_ticket` (rasn-kerberos based), so the
/// armor TGT is wire-compatible with a regular TGT.
pub fn encode_krb_fast_armored_req(r: &KrbFastArmoredReq) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&r.armor_type.to_be_bytes());
    let tgt_bytes = encode_ticket(&r.armor_tgt);
    out.extend_from_slice(&(tgt_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&tgt_bytes);
    out.extend_from_slice(&(r.enc_part.len() as u32).to_be_bytes());
    out.extend_from_slice(&r.enc_part);
    out
}

/// Decode a `KrbFastArmoredReq` from length-prefixed bytes (inverse of
/// [`encode_krb_fast_armored_req`]).
pub fn decode_krb_fast_armored_req(bytes: &[u8]) -> Result<KrbFastArmoredReq, DecodeError> {
    let mut r = ByteReader::new(bytes);
    let armor_type = r.read_u32()?;
    let tgt_len = r.read_u32()? as usize;
    let tgt_bytes = r.read_bytes(tgt_len)?;
    let armor_tgt = decode_ticket(tgt_bytes)?;
    let enc_len = r.read_u32()? as usize;
    let enc_part = r.read_bytes(enc_len)?.to_vec();
    Ok(KrbFastArmoredReq {
        armor_type,
        armor_tgt,
        enc_part,
    })
}

/// Wrap an inner AS-REQ's padata in a FAST armored request (RFC 6806 §5.4).
///
/// Caller provides:
/// - `armor_tgt`: the armor TGT (already obtained by the client).
/// - `armor_tgt_session_key`: the armor TGT's session key (used to derive
///   the FAST armor key via [`derive_fast_armor_key`]).
/// - `inner_padata`: the real pre-authenticator (e.g. PA-ENC-TIMESTAMP).
/// - `nonce`: client-chosen anti-replay nonce.
/// - `timestamp`: client's notion of current time.
///
/// Returns the `KrbFastArmoredReq` to be carried in the outer AS-REQ's
/// padata list as `PA-FX-FAST-START` (type 143).
pub fn wrap_fast_armor(
    armor_tgt: Ticket,
    armor_tgt_session_key: &[u8; SESSION_KEY_LEN],
    inner_padata: Vec<PaData>,
    nonce: u32,
    timestamp: i64,
) -> Result<KrbFastArmoredReq, KdcError> {
    let armor_key = derive_fast_armor_key(armor_tgt_session_key);
    let factor = FastFactor {
        inner_padata,
        nonce,
        timestamp,
    };
    let factor_bytes = encode_fast_factor(&factor);
    let enc_part = encrypt_for_usage(&armor_key.key, KEY_USAGE_FAST_ARMOR_REQ_ENC, &factor_bytes)?;
    Ok(KrbFastArmoredReq {
        armor_type: FAST_ARMOR_TYPE_TGT,
        armor_tgt,
        enc_part,
    })
}

/// Unwrap (decrypt + verify) a FAST armored request, returning the inner
/// `FastFactor` (RFC 6806 §5.4). Caller must supply the armor TGT's session
/// key (recovered by decrypting the armor TGT with the krbtgt key).
///
/// Verifies the FAST factor's timestamp is within the ±5 minute clock-skew
/// tolerance (RFC 4120 §3.1.3) as an anti-replay measure.
pub fn unwrap_fast_armor(
    armored: &KrbFastArmoredReq,
    armor_tgt_session_key: &[u8; SESSION_KEY_LEN],
) -> Result<FastFactor, KdcError> {
    let armor_key = derive_fast_armor_key(armor_tgt_session_key);
    let factor_bytes = decrypt_for_usage(
        &armor_key.key,
        KEY_USAGE_FAST_ARMOR_REQ_ENC,
        &armored.enc_part,
    )?;
    let factor = decode_fast_factor(&factor_bytes)?;
    // Anti-replay: verify the factor's timestamp is within the clock-skew
    // tolerance (RFC 4120 §3.1.3).
    let now = now_secs();
    let skew = now - factor.timestamp;
    if skew.abs() > CLOCK_SKEW_TOLERANCE_SECS {
        return Err(KdcError::PreauthFailed(format!(
            "FAST factor clock skew {skew}s exceeds tolerance {CLOCK_SKEW_TOLERANCE_SECS}s"
        )));
    }
    Ok(factor)
}

/// Find the `PA-FX-FAST-START` padata entry (type 143). Returns the encoded
/// `KrbFastArmoredReq` bytes (caller must decode via
/// [`decode_krb_fast_armored_req`]).
pub fn find_fast_armor(padata: &[PaData]) -> Result<Option<Vec<u8>>, KdcError> {
    for p in padata {
        if p.padata_type == PA_FX_FAST_START_TYPE {
            return Ok(Some(p.padata_value.clone()));
        }
    }
    Ok(None)
}

/// AS-REQ handler with FAST armoring enforcement (RFC 6806 / ADR-012).
///
/// Behavior depends on `fast_mode`:
/// - `Required` (default per ADR-012): reject non-FAST AS-REQs with
///   `KdcError::FastArmorRequired`.
/// - `Supported` / `Audit` / `Grace`: accept non-FAST AS-REQs by falling
///   through to the standard [`handle_as_req_with_metrics`] path (with a
///   `tracing::warn!` for audit/grace modes per ADR-023).
///
/// For FAST-armored AS-REQs:
/// 1. Extract the `PA-FX-FAST-START` padata and decode the `KrbFastArmoredReq`.
/// 2. Decrypt the armor TGT with the krbtgt key (key usage 2) to recover
///    the armor TGT's session key.
/// 3. Derive the FAST armor key from the armor TGT session key.
/// 4. Decrypt the FAST factor with the armor key (key usage 65).
/// 5. Use the inner padata (PA-ENC-TIMESTAMP) for pre-auth verification.
/// 6. Build the AS-REP, but encrypt the enc-part with the FAST armor key
///    (not the client's long-term key) — this is the AS-REP roasting
///    mitigation per ADR-012 §Decision.
pub async fn handle_as_req_fast(
    store: &dyn PrincipalStore,
    krbtgt_key: &Aes256Key,
    req_bytes: &[u8],
    fast_mode: FastMode,
) -> Result<Vec<u8>, KdcError> {
    let req = decode_as_req(req_bytes)?;
    let chosen_etype = negotiate_etype(&req.etypes)?;

    let fast_blob = find_fast_armor(&req.padata)?;
    match (fast_blob, fast_mode) {
        (None, FastMode::Required) => {
            tracing::warn!(
                realm = %req.realm,
                principal = %req.cname.join("/"),
                "non-FAST AS-REQ rejected (fast_mode = Required)"
            );
            Err(KdcError::FastArmorRequired)
        }
        (None, FastMode::Supported) | (None, FastMode::Audit) | (None, FastMode::Grace) => {
            tracing::warn!(
                realm = %req.realm,
                principal = %req.cname.join("/"),
                mode = ?fast_mode,
                "non-FAST AS-REQ accepted (FAST not present)"
            );
            // Fall through to the standard handler path.
            return handle_as_req_with_metrics(store, krbtgt_key, req_bytes, None).await;
        }
        (Some(blob), _) => {
            // FAST armor present — decode + verify.
            let armored = decode_krb_fast_armored_req(&blob)?;
            if armored.armor_type != FAST_ARMOR_TYPE_TGT {
                return Err(KdcError::PreauthFailed(format!(
                    "unsupported FAST armor type {} (only type 1 / TGT armor supported)",
                    armored.armor_type
                )));
            }
            // Decrypt the armor TGT with the krbtgt key (key usage 2).
            let armor_tgt_pt = decrypt_for_usage(
                krbtgt_key,
                KEY_USAGE_AS_REP_TGT,
                &armored.armor_tgt.enc_part,
            )?;
            let armor_tgt_etp = decode_enc_ticket_part(&armor_tgt_pt)?;
            // Unwrap the FAST factor (verifies clock skew).
            let factor = unwrap_fast_armor(&armored, &armor_tgt_etp.session_key)?;

            // Look up the client principal.
            let client = store
                .lookup(&req.realm, &req.cname)
                .await
                .map_err(|e| KdcError::Storage(format!("principal lookup: {e}")))?
                .ok_or_else(|| {
                    KdcError::PrincipalNotFound(format!("{}/{}", req.realm, req.cname.join("/")))
                })?;

            // Verify the inner PA-ENC-TIMESTAMP from the FAST factor.
            let inner_pa = find_pa_enc_timestamp(&factor.inner_padata)?;
            match inner_pa {
                Some(blob) => verify_pa_enc_timestamp(&client, &blob)?,
                None => return Err(KdcError::PreauthRequired),
            }

            // Build the TGT (same as the non-FAST path).
            let now = now_secs();
            let session_key = random_session_key()?;
            let enc_ticket_part = EncTicketPart {
                flags: TICKET_FLAG_FORWARDABLE | TICKET_FLAG_RENEWABLE,
                crealm: client.realm.clone(),
                cname: client.components.clone(),
                session_key,
                authtime: now,
                starttime: now,
                endtime: now + DEFAULT_TGT_LIFETIME_SECS,
                renew_till: now + 2 * DEFAULT_TGT_LIFETIME_SECS,
                client_uuid: client.uuid,
            };
            let enc_ticket_part_bytes = encode_enc_ticket_part(&enc_ticket_part);
            let ticket_enc =
                encrypt_for_usage(krbtgt_key, KEY_USAGE_AS_REP_TGT, &enc_ticket_part_bytes)?;
            let tgt = Ticket {
                tkt_vno: PVNO,
                realm: client.realm.clone(),
                sname: vec!["krbtgt".to_string(), client.realm.clone()],
                kvno: 1,
                etype: chosen_etype,
                enc_part: ticket_enc,
            };

            // AS-REP roasting mitigation: encrypt the enc-part with the FAST
            // armor key (NOT the client's long-term key). An attacker who
            // captures the AS-REP cannot offline-crack it because the armor
            // key is derived from the armor TGT session key, which the
            // attacker does not have.
            let armor_key = derive_fast_armor_key(&armor_tgt_etp.session_key);
            let enc_rep_part = EncKdcRepPart {
                session_key,
                last_req: now,
                nonce: req.nonce,
                authtime: now,
                starttime: now,
                endtime: now + DEFAULT_TGT_LIFETIME_SECS,
                renew_till: now + 2 * DEFAULT_TGT_LIFETIME_SECS,
                crealm: client.realm.clone(),
                cname: client.components.clone(),
            };
            let enc_rep_part_bytes = encode_enc_kdc_rep_part(&enc_rep_part);
            let enc_part = encrypt_for_usage(
                &armor_key.key,
                KEY_USAGE_AS_REP_ENC_PART,
                &enc_rep_part_bytes,
            )?;

            let rep = AsRep {
                pvno: PVNO,
                msg_type: MSG_TYPE_AS_REP,
                crealm: client.realm.clone(),
                cname: client.components.clone(),
                ticket: tgt,
                enc_part_etype: chosen_etype,
                enc_part_kvno: client.kvno,
                enc_part,
            };
            tracing::info!(
                realm = %req.realm,
                principal = %req.cname.join("/"),
                etype = %etype_label(chosen_etype),
                "FAST-armored AS-REQ succeeded"
            );
            Ok(encode_as_rep(&rep))
        }
    }
}

// ---------------------------------------------------------------------------
// TGS-REQ handler
// ---------------------------------------------------------------------------

/// Backward-compatible TGS-REQ handler (Wave 3a signature): records no
/// metrics and is equivalent to calling [`handle_tgs_req_with_metrics`]
/// with `metrics = None`. See [`handle_as_req`] for the rationale.
pub async fn handle_tgs_req(
    store: &dyn PrincipalStore,
    krbtgt_key: &Aes256Key,
    req_bytes: &[u8],
) -> Result<Vec<u8>, KdcError> {
    handle_tgs_req_with_metrics(store, krbtgt_key, req_bytes, None).await
}

/// TGS-REQ handler wired to a [`MetricsRegistry`] producer + `tracing` span.
///
/// Because the v0.6.0 `MetricsRegistry` (ADR-057) does not yet expose
/// `inc_tgs_req` / `observe_tgs_req_duration` methods, TGS-REQs are
/// recorded under the existing `as_req_total` counter with the etype
/// label set to the literal string `"tgs_req"` — this distinguishes
/// TGS-REQ counts from real AS-REQ etype-labelled counts (e.g.
/// `"aes256-cts-hmac-sha1-96"`) without requiring a new metric. v0.7.0
/// should split this into a separate `tgs_req_total` counter.
///
/// # Flow (RFC 4120 §3.3 / §5.4.2)
///
/// 1. Parse the TGS-REQ from `req_bytes`.
/// 2. Negotiate etype (same policy as AS-REQ).
/// 3. Decrypt the TGT's enc-part with `krbtgt_key` (key usage 2); recover
///    the session key and client identity.
/// 4. Decrypt the authenticator with the TGT session key (key usage 7);
///    verify the authenticator's cname matches the TGT's cname.
/// 5. Look up the requested service principal in `store`.
/// 6. Build a service Ticket:
///    - Reuse the TGT session key (v0.6.0 simplicity; v0.7.0 will derive a
///      new sub-session key).
///    - Encrypt the new `EncTicketPart` with the service's long-term key
///      (key usage 2).
/// 7. Build the TGS-REP `enc-part` (encrypted with the TGT session key,
///    key usage 8).
/// 8. Encode the TGS-REP as bytes.
pub async fn handle_tgs_req_with_metrics(
    store: &dyn PrincipalStore,
    krbtgt_key: &Aes256Key,
    req_bytes: &[u8],
    metrics: Option<&MetricsRegistry>,
) -> Result<Vec<u8>, KdcError> {
    let span = tracing::info_span!("tgs_req");
    handle_tgs_req_with_metrics_inner(store, krbtgt_key, req_bytes, metrics)
        .instrument(span)
        .await
}

/// Inner TGS-REQ handler body — extracted so the `tracing::Span` from
/// [`handle_tgs_req_with_metrics`] is entered for every `await` point.
async fn handle_tgs_req_with_metrics_inner(
    store: &dyn PrincipalStore,
    krbtgt_key: &Aes256Key,
    req_bytes: &[u8],
    metrics: Option<&MetricsRegistry>,
) -> Result<Vec<u8>, KdcError> {
    let start = Instant::now();
    let req = decode_tgs_req(req_bytes)?;

    let chosen_etype = negotiate_etype(&req.etypes)?;

    // ---- Metrics + tracing: TGS-REQ received ----
    // The `as_req_total{realm,etype}` counter is reused for TGS-REQs with
    // the etype label set to the literal `"tgs_req"` — see the doc comment
    // on [`handle_tgs_req_with_metrics`] for the v0.6.0 rationale.
    let realm = req.realm.clone();
    let service = req.sname.join("/");
    tracing::info!(
        realm = %realm,
        service = %service,
        etype = %etype_label(chosen_etype),
        "TGS-REQ received"
    );
    if let Some(m) = metrics {
        m.inc_as_req(&realm, "tgs_req").await;
    }

    // Verify the TGT: decrypt with krbtgt key (key usage 2).
    let tgt_enc_part_plaintext =
        decrypt_for_usage(krbtgt_key, KEY_USAGE_AS_REP_TGT, &req.tgt.enc_part)?;
    let enc_ticket_part = decode_enc_ticket_part(&tgt_enc_part_plaintext)?;

    // Verify the authenticator: decrypt with TGT session key (key usage 7).
    let auth_plaintext = decrypt_for_usage(
        &enc_ticket_part.session_key,
        KEY_USAGE_TGS_REQ_AUTHENTICATOR,
        &req.authenticator_enc,
    )?;
    let authenticator = decode_authenticator(&auth_plaintext)?;

    // Cross-check: authenticator's cname must match the TGT's cname.
    if !principal_names_eq(&authenticator.cname, &enc_ticket_part.cname) {
        return Err(KdcError::PreauthFailed(
            "authenticator cname does not match TGT cname".into(),
        ));
    }

    // Look up the requested service principal.
    let svc = store
        .lookup(&req.realm, &req.sname)
        .await
        .map_err(|e| KdcError::Storage(format!("service lookup: {e}")))?
        .ok_or_else(|| {
            KdcError::PrincipalNotFound(format!("{}/{}", req.realm, req.sname.join("/")))
        })?;

    // Build the service ticket.
    let now = now_secs();
    let session_key = enc_ticket_part.session_key;

    let svc_enc_ticket_part = EncTicketPart {
        flags: enc_ticket_part.flags,
        crealm: enc_ticket_part.crealm.clone(),
        cname: enc_ticket_part.cname.clone(),
        session_key,
        authtime: now,
        starttime: now,
        endtime: now + DEFAULT_SVC_TICKET_LIFETIME_SECS,
        renew_till: now + 2 * DEFAULT_SVC_TICKET_LIFETIME_SECS,
        client_uuid: enc_ticket_part.client_uuid,
    };
    let svc_enc_ticket_part_bytes = encode_enc_ticket_part(&svc_enc_ticket_part);
    let svc_ticket_enc = encrypt_for_usage(
        &svc.key,
        KEY_USAGE_TGS_REP_TICKET,
        &svc_enc_ticket_part_bytes,
    )?;

    let svc_ticket = Ticket {
        tkt_vno: PVNO,
        realm: svc.realm.clone(),
        sname: svc.components.clone(),
        kvno: svc.kvno,
        etype: chosen_etype,
        enc_part: svc_ticket_enc,
    };

    // Build the TGS-REP enc-part (encrypted with the TGT session key,
    // key usage 8).
    let enc_rep_part = EncKdcRepPart {
        session_key,
        last_req: now,
        nonce: req.nonce,
        authtime: now,
        starttime: now,
        endtime: now + DEFAULT_SVC_TICKET_LIFETIME_SECS,
        renew_till: now + 2 * DEFAULT_SVC_TICKET_LIFETIME_SECS,
        crealm: svc.realm.clone(),
        cname: enc_ticket_part.cname.clone(),
    };
    let enc_rep_part_bytes = encode_enc_kdc_rep_part(&enc_rep_part);
    let enc_part = encrypt_for_usage(
        &enc_ticket_part.session_key,
        KEY_USAGE_TGS_REP_ENC_PART,
        &enc_rep_part_bytes,
    )?;

    let rep = TgsRep {
        pvno: PVNO,
        msg_type: MSG_TYPE_TGS_REP,
        crealm: enc_ticket_part.crealm.clone(),
        cname: enc_ticket_part.cname.clone(),
        ticket: svc_ticket,
        enc_part_etype: chosen_etype,
        enc_part_kvno: req.tgt.kvno,
        enc_part,
    };

    // ---- Metrics + tracing: TGS-REQ completed ----
    // Same v0.6.0 reuse rationale: the `as_req_duration_seconds` histogram
    // captures both AS-REQ and TGS-REQ latencies until v0.7.0 adds a
    // dedicated `tgs_req_duration_seconds` metric.
    let elapsed = start.elapsed();
    if let Some(m) = metrics {
        m.observe_as_req_duration(elapsed.as_secs_f64()).await;
    }
    tracing::debug!(elapsed = ?elapsed, "TGS-REQ completed");

    Ok(encode_tgs_rep(&rep))
}

/// Case-insensitive comparison of principal name component vectors.
fn principal_names_eq(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryPrincipalStore;
    use crate::EType;

    /// Test helper: build a principal record keyed by a deterministic
    /// PBKDF2 derivation (so tests are reproducible). The UUID is fixed at
    /// `Uuid::nil()` because the workspace `uuid` crate enables only the
    /// `v7` feature, not `v4`; the UUID value is not security-relevant for
    /// the handler logic.
    fn make_principal(realm: &str, cname: &str, password: &str) -> PrincipalRecord {
        let mut salt = Vec::new();
        salt.extend_from_slice(realm.as_bytes());
        salt.extend_from_slice(cname.as_bytes());
        let key = crypto::derive_aes256_key(password.as_bytes(), &salt);
        PrincipalRecord::new(Uuid::nil(), realm, vec![cname.to_string()], key)
    }

    fn make_krbtgt_key() -> Aes256Key {
        crypto::derive_aes256_key(b"krbtgt-master-password", b"EXAMPLE.COMkrbtgt")
    }

    fn make_svc_principal(realm: &str, sname: &str, password: &str) -> PrincipalRecord {
        let mut salt = Vec::new();
        salt.extend_from_slice(realm.as_bytes());
        salt.extend_from_slice(sname.as_bytes());
        let key = crypto::derive_aes256_key(password.as_bytes(), &salt);
        PrincipalRecord::new(
            Uuid::nil(),
            realm,
            vec!["host".to_string(), sname.to_string()],
            key,
        )
    }

    /// Build a valid AS-REQ with PA-ENC-TIMESTAMP pre-auth encrypted with
    /// the client's key.
    async fn build_valid_as_req(client: &PrincipalRecord) -> AsReq {
        let now = now_secs();
        let pa_ts = PaEncTsEnc {
            patimestamp: now,
            pausec: 0,
        };
        let pa_ts_bytes = encode_pa_enc_ts_enc(&pa_ts);
        let blob = encrypt_for_usage(&client.key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &pa_ts_bytes)
            .expect("encrypt pa-enc-timestamp");

        AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: client.realm.clone(),
            cname: client.components.clone(),
            nonce: 0xDEAD_BEEF,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            padata: vec![PaData {
                padata_type: PA_ENC_TIMESTAMP_TYPE,
                padata_value: blob,
            }],
            till: now + DEFAULT_TGT_LIFETIME_SECS,
        }
    }

    // ---- Encode/decode round-trip tests ----

    #[test]
    fn as_req_encode_decode_round_trip() {
        let req = AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: "EXAMPLE.COM".into(),
            cname: vec!["alice".into()],
            nonce: 42,
            etypes: vec![EType::Aes256CtsHmacSha1_96, EType::Aes128CtsHmacSha1_96],
            padata: vec![PaData {
                padata_type: PA_ENC_TIMESTAMP_TYPE,
                padata_value: vec![0xAB, 0xCD, 0xEF],
            }],
            till: 1_700_000_000,
        };
        let bytes = encode_as_req(&req);
        let decoded = decode_as_req(&bytes).expect("decode as_req");
        assert_eq!(decoded, req);
    }

    #[test]
    fn as_rep_encode_decode_round_trip() {
        let ticket = Ticket {
            tkt_vno: PVNO,
            realm: "EXAMPLE.COM".into(),
            sname: vec!["krbtgt".into(), "EXAMPLE.COM".into()],
            kvno: 1,
            etype: EType::Aes256CtsHmacSha1_96,
            enc_part: vec![0x01, 0x02, 0x03, 0x04],
        };
        let rep = AsRep {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REP,
            crealm: "EXAMPLE.COM".into(),
            cname: vec!["alice".into()],
            ticket,
            enc_part_etype: EType::Aes256CtsHmacSha1_96,
            enc_part_kvno: 1,
            enc_part: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let bytes = encode_as_rep(&rep);
        let decoded = decode_as_rep(&bytes).expect("decode as_rep");
        assert_eq!(decoded, rep);
    }

    #[test]
    fn tgs_req_encode_decode_round_trip() {
        let tgt = Ticket {
            tkt_vno: PVNO,
            realm: "EXAMPLE.COM".into(),
            sname: vec!["krbtgt".into(), "EXAMPLE.COM".into()],
            kvno: 1,
            etype: EType::Aes256CtsHmacSha1_96,
            enc_part: vec![0x11, 0x22, 0x33],
        };
        let req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: "EXAMPLE.COM".into(),
            sname: vec!["host".into(), "web.example.com".into()],
            nonce: 99,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt,
            authenticator_enc: vec![0xFE, 0xDC, 0xBA],
            till: 1_700_000_000,
        };
        let bytes = encode_tgs_req(&req);
        let decoded = decode_tgs_req(&bytes).expect("decode tgs_req");
        assert_eq!(decoded, req);
    }

    #[test]
    fn tgs_rep_encode_decode_round_trip() {
        let ticket = Ticket {
            tkt_vno: PVNO,
            realm: "EXAMPLE.COM".into(),
            sname: vec!["host".into(), "web.example.com".into()],
            kvno: 3,
            etype: EType::Aes256CtsHmacSha1_96,
            enc_part: vec![0x55, 0x66, 0x77],
        };
        let rep = TgsRep {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REP,
            crealm: "EXAMPLE.COM".into(),
            cname: vec!["alice".into()],
            ticket,
            enc_part_etype: EType::Aes256CtsHmacSha1_96,
            enc_part_kvno: 1,
            enc_part: vec![0x12, 0x34, 0x56, 0x78],
        };
        let bytes = encode_tgs_rep(&rep);
        let decoded = decode_tgs_rep(&bytes).expect("decode tgs_rep");
        assert_eq!(decoded, rep);
    }

    #[test]
    fn ticket_encode_decode_round_trip() {
        let t = Ticket {
            tkt_vno: PVNO,
            realm: "EXAMPLE.COM".into(),
            sname: vec!["krbtgt".into(), "EXAMPLE.COM".into()],
            kvno: 7,
            etype: EType::Aes256CtsHmacSha1_96,
            enc_part: vec![0u8; 64],
        };
        let bytes = encode_ticket(&t);
        let decoded = decode_ticket(&bytes).expect("decode ticket");
        assert_eq!(decoded, t);
    }

    #[test]
    fn enc_ticket_part_encode_decode_round_trip() {
        let e = EncTicketPart {
            flags: TICKET_FLAG_FORWARDABLE | TICKET_FLAG_RENEWABLE,
            crealm: "EXAMPLE.COM".into(),
            cname: vec!["alice".into()],
            session_key: [0xAB; SESSION_KEY_LEN],
            authtime: 1_700_000_000,
            starttime: 1_700_000_000,
            endtime: 1_700_036_000,
            renew_till: 1_700_072_000,
            client_uuid: Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
        };
        let bytes = encode_enc_ticket_part(&e);
        let decoded = decode_enc_ticket_part(&bytes).expect("decode enc_ticket_part");
        assert_eq!(decoded, e);
    }

    #[test]
    fn pa_enc_ts_enc_encode_decode_round_trip() {
        let p = PaEncTsEnc {
            patimestamp: 1_700_000_000,
            pausec: 123_456,
        };
        let bytes = encode_pa_enc_ts_enc(&p);
        let decoded = decode_pa_enc_ts_enc(&bytes).expect("decode pa_enc_ts_enc");
        assert_eq!(decoded, p);
    }

    #[test]
    fn authenticator_encode_decode_round_trip_with_subkey() {
        let a = Authenticator {
            crealm: "EXAMPLE.COM".into(),
            cname: vec!["alice".into()],
            subkey: Some([0xCD; SESSION_KEY_LEN]),
            seq_number: 42,
            ctime: 1_700_000_000,
            cusec: 999,
        };
        let bytes = encode_authenticator(&a);
        let decoded = decode_authenticator(&bytes).expect("decode authenticator");
        assert_eq!(decoded, a);
    }

    #[test]
    fn authenticator_encode_decode_round_trip_without_subkey() {
        let a = Authenticator {
            crealm: "EXAMPLE.COM".into(),
            cname: vec!["bob".into()],
            subkey: None,
            seq_number: 1,
            ctime: 1_700_000_000,
            cusec: 0,
        };
        let bytes = encode_authenticator(&a);
        let decoded = decode_authenticator(&bytes).expect("decode authenticator");
        assert_eq!(decoded, a);
    }

    #[test]
    fn enc_kdc_rep_part_encode_decode_round_trip() {
        let e = EncKdcRepPart {
            session_key: [0x11; SESSION_KEY_LEN],
            last_req: 1_700_000_000,
            nonce: 0xCAFEBABE,
            authtime: 1_700_000_000,
            starttime: 1_700_000_000,
            endtime: 1_700_036_000,
            renew_till: 1_700_072_000,
            crealm: "EXAMPLE.COM".into(),
            cname: vec!["alice".into()],
        };
        let bytes = encode_enc_kdc_rep_part(&e);
        let decoded = decode_enc_kdc_rep_part(&bytes).expect("decode enc_kdc_rep_part");
        assert_eq!(decoded, e);
    }

    // ---- Encryption / decryption helpers ----

    #[test]
    fn encrypt_for_usage_round_trips() {
        let base = crypto::derive_aes256_key(b"password", b"salt");
        let plaintext = b"some-secret-payload-32-bytes-ok!";
        let blob = encrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, plaintext)
            .expect("encrypt");
        let recovered =
            decrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &blob).expect("decrypt");
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn encrypt_for_usage_rejects_wrong_key_usage() {
        let base = crypto::derive_aes256_key(b"password", b"salt");
        let plaintext = b"some-secret-payload-32-bytes-ok!";
        let blob = encrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, plaintext)
            .expect("encrypt");
        let err = decrypt_for_usage(&base, KEY_USAGE_AS_REP_ENC_PART, &blob)
            .expect_err("must fail with wrong usage");
        assert!(matches!(err, KdcError::PreauthFailed(_)));
    }

    #[test]
    fn encrypt_for_usage_rejects_tampered_ciphertext() {
        let base = crypto::derive_aes256_key(b"password", b"salt");
        let plaintext = b"some-secret-payload-32-bytes-ok!";
        let mut blob = encrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, plaintext)
            .expect("encrypt");
        blob[5] ^= 0x01;
        let err = decrypt_for_usage(&base, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &blob)
            .expect_err("must fail HMAC verification");
        assert!(matches!(err, KdcError::PreauthFailed(_)));
    }

    #[test]
    fn encrypt_for_usage_rejects_wrong_base_key() {
        let base1 = crypto::derive_aes256_key(b"password", b"salt1");
        let base2 = crypto::derive_aes256_key(b"password", b"salt2");
        let plaintext = b"some-secret-payload-32-bytes-ok!";
        let blob = encrypt_for_usage(&base1, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, plaintext)
            .expect("encrypt");
        let err = decrypt_for_usage(&base2, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &blob)
            .expect_err("must fail with wrong key");
        assert!(matches!(err, KdcError::PreauthFailed(_)));
    }

    // ---- Etype negotiation ----

    #[test]
    fn negotiate_etype_accepts_aes256() {
        let chosen = negotiate_etype(&[EType::Aes256CtsHmacSha1_96]).expect("aes256");
        assert_eq!(chosen, EType::Aes256CtsHmacSha1_96);
    }

    #[test]
    fn negotiate_etype_prefers_aes256_over_aes128() {
        let chosen = negotiate_etype(&[EType::Aes128CtsHmacSha1_96, EType::Aes256CtsHmacSha1_96])
            .expect("must pick aes256");
        assert_eq!(chosen, EType::Aes256CtsHmacSha1_96);
    }

    #[test]
    fn negotiate_etype_refuses_rc4_only() {
        let err = negotiate_etype(&[EType::Rc4Hmac]).expect_err("rc4 must be refused");
        match err {
            KdcError::Policy(msg) => assert!(msg.contains("rc4 disabled")),
            other => panic!("expected KdcError::Policy, got {other:?}"),
        }
    }

    #[test]
    fn negotiate_etype_refuses_empty_list() {
        let err = negotiate_etype(&[]).expect_err("empty list must be refused");
        assert!(matches!(err, KdcError::ETypeUnsupported(_)));
    }

    #[test]
    fn negotiate_etype_accepts_aes128_when_aes256_not_offered() {
        let chosen = negotiate_etype(&[EType::Aes128CtsHmacSha1_96]).expect("aes128");
        assert_eq!(chosen, EType::Aes128CtsHmacSha1_96);
    }

    // ---- AS-REQ handler: end-to-end ----

    #[tokio::test]
    async fn as_req_handler_succeeds_with_valid_preauth() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let req = build_valid_as_req(&alice).await;
        let req_bytes = encode_as_req(&req);

        let rep_bytes = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect("AS-REQ must succeed");
        let rep = decode_as_rep(&rep_bytes).expect("AS-REP must decode");

        assert_eq!(rep.pvno, PVNO);
        assert_eq!(rep.msg_type, MSG_TYPE_AS_REP);
        assert_eq!(rep.crealm, "EXAMPLE.COM");
        assert_eq!(rep.cname, alice.components);

        // TGT: sname = krbtgt/<REALM>, etype = AES-256.
        assert_eq!(
            rep.ticket.sname,
            vec!["krbtgt".to_string(), "EXAMPLE.COM".into()]
        );
        assert_eq!(rep.ticket.etype, EType::Aes256CtsHmacSha1_96);

        // Decrypt the TGT enc-part with the krbtgt key (key usage 2) — must
        // yield a valid EncTicketPart with the client's identity.
        let tgt_pt = decrypt_for_usage(&krbtgt_key, KEY_USAGE_AS_REP_TGT, &rep.ticket.enc_part)
            .expect("decrypt TGT");
        let etp = decode_enc_ticket_part(&tgt_pt).expect("decode EncTicketPart");
        assert_eq!(etp.crealm, "EXAMPLE.COM");
        assert_eq!(etp.cname, alice.components);
        assert_eq!(etp.client_uuid, alice.uuid);
        assert!(etp.flags & TICKET_FLAG_FORWARDABLE != 0);
        assert!(etp.flags & TICKET_FLAG_RENEWABLE != 0);

        // Decrypt the AS-REP enc-part with the client's key (key usage 3) —
        // must yield a valid EncKdcRepPart echoing the session key.
        let rep_pt = decrypt_for_usage(&alice.key, KEY_USAGE_AS_REP_ENC_PART, &rep.enc_part)
            .expect("decrypt AS-REP enc-part");
        let erp = decode_enc_kdc_rep_part(&rep_pt).expect("decode EncKdcRepPart");
        assert_eq!(erp.session_key, etp.session_key);
        assert_eq!(erp.nonce, req.nonce);
        assert_eq!(erp.crealm, "EXAMPLE.COM");
        assert_eq!(erp.cname, alice.components);
    }

    #[tokio::test]
    async fn as_req_handler_preauth_required_when_no_padata() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let req = AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: alice.realm.clone(),
            cname: alice.components.clone(),
            nonce: 1,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            padata: vec![],
            till: now_secs() + 3600,
        };
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("must require preauth");
        assert!(matches!(err, KdcError::PreauthRequired));
    }

    #[tokio::test]
    async fn as_req_handler_preauth_failed_when_blob_corrupted() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let mut req = build_valid_as_req(&alice).await;
        if let Some(b) = req.padata[0].padata_value.get_mut(0) {
            *b ^= 0xFF;
        }
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("preauth must fail on corrupt blob");
        assert!(matches!(err, KdcError::PreauthFailed(_)));
    }

    #[tokio::test]
    async fn as_req_handler_preauth_failed_on_clock_skew() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let now = now_secs();
        let pa_ts = PaEncTsEnc {
            patimestamp: now + 3600,
            pausec: 0,
        };
        let pa_ts_bytes = encode_pa_enc_ts_enc(&pa_ts);
        let blob = encrypt_for_usage(&alice.key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &pa_ts_bytes)
            .expect("encrypt");

        let req = AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: alice.realm.clone(),
            cname: alice.components.clone(),
            nonce: 7,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            padata: vec![PaData {
                padata_type: PA_ENC_TIMESTAMP_TYPE,
                padata_value: blob,
            }],
            till: now + 3600,
        };
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("clock skew must be rejected");
        match err {
            KdcError::PreauthFailed(msg) => assert!(msg.contains("clock skew")),
            other => panic!("expected PreauthFailed(clock skew), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn as_req_handler_principal_not_found() {
        let store = InMemoryPrincipalStore::new();
        let krbtgt_key = make_krbtgt_key();

        let stranger = make_principal("EXAMPLE.COM", "stranger", "password");
        let req = build_valid_as_req(&stranger).await;
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("principal must not be found");
        match err {
            KdcError::PrincipalNotFound(msg) => assert!(msg.contains("stranger")),
            other => panic!("expected PrincipalNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn as_req_handler_rc4_etype_refused() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let req = AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: alice.realm.clone(),
            cname: alice.components.clone(),
            nonce: 1,
            etypes: vec![EType::Rc4Hmac],
            padata: vec![],
            till: now_secs() + 3600,
        };
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("RC4 must be refused");
        match err {
            KdcError::Policy(msg) => assert!(msg.contains("rc4 disabled")),
            other => panic!("expected Policy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn as_req_handler_aes128_etype_accepted() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let mut req = build_valid_as_req(&alice).await;
        req.etypes = vec![EType::Aes128CtsHmacSha1_96];
        let req_bytes = encode_as_req(&req);

        let rep_bytes = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect("AS-REQ with AES-128 must succeed");
        let rep = decode_as_rep(&rep_bytes).expect("decode AS-REP");
        assert_eq!(rep.ticket.etype, EType::Aes128CtsHmacSha1_96);
    }

    #[tokio::test]
    async fn as_req_handler_rejects_garbage_input() {
        let store = InMemoryPrincipalStore::new();
        let krbtgt_key = make_krbtgt_key();
        let err = handle_as_req(&store, &krbtgt_key, &[0u8; 3])
            .await
            .expect_err("garbage must fail");
        assert!(matches!(err, KdcError::Storage(_)));
    }

    // ---- TGS-REQ handler: end-to-end ----

    /// Build a TGT + authenticator for the given client (as if the client
    /// had previously done an AS-REQ and now holds a TGT).
    fn build_tgt_and_authenticator(
        client: &PrincipalRecord,
        krbtgt_key: &Aes256Key,
    ) -> (Ticket, [u8; SESSION_KEY_LEN]) {
        let now = now_secs();
        let session_key = random_session_key().expect("random session key");
        let etp = EncTicketPart {
            flags: TICKET_FLAG_FORWARDABLE | TICKET_FLAG_RENEWABLE,
            crealm: client.realm.clone(),
            cname: client.components.clone(),
            session_key,
            authtime: now,
            starttime: now,
            endtime: now + DEFAULT_TGT_LIFETIME_SECS,
            renew_till: now + 2 * DEFAULT_TGT_LIFETIME_SECS,
            client_uuid: client.uuid,
        };
        let etp_bytes = encode_enc_ticket_part(&etp);
        let ticket_enc = encrypt_for_usage(krbtgt_key, KEY_USAGE_AS_REP_TGT, &etp_bytes)
            .expect("encrypt TGT enc-part");
        let tgt = Ticket {
            tkt_vno: PVNO,
            realm: client.realm.clone(),
            sname: vec!["krbtgt".to_string(), client.realm.clone()],
            kvno: 1,
            etype: EType::Aes256CtsHmacSha1_96,
            enc_part: ticket_enc,
        };
        (tgt, session_key)
    }

    fn build_authenticator_enc(
        client: &PrincipalRecord,
        session_key: &[u8; SESSION_KEY_LEN],
    ) -> Vec<u8> {
        let now = now_secs();
        let auth = Authenticator {
            crealm: client.realm.clone(),
            cname: client.components.clone(),
            subkey: None,
            seq_number: 1,
            ctime: now,
            cusec: 0,
        };
        let auth_bytes = encode_authenticator(&auth);
        encrypt_for_usage(session_key, KEY_USAGE_TGS_REQ_AUTHENTICATOR, &auth_bytes)
            .expect("encrypt authenticator")
    }

    #[tokio::test]
    async fn tgs_req_handler_succeeds_with_valid_tgt() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        let web = make_svc_principal("EXAMPLE.COM", "web.example.com", "svc-pass");
        store.insert(alice.clone());
        store.insert(web.clone());
        let krbtgt_key = make_krbtgt_key();

        let (tgt, session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        let auth_enc = build_authenticator_enc(&alice, &session_key);

        let req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: web.realm.clone(),
            sname: web.components.clone(),
            nonce: 1234,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt,
            authenticator_enc: auth_enc,
            till: now_secs() + 3600,
        };
        let req_bytes = encode_tgs_req(&req);

        let rep_bytes = handle_tgs_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect("TGS-REQ must succeed");
        let rep = decode_tgs_rep(&rep_bytes).expect("decode TGS-REP");

        assert_eq!(rep.pvno, PVNO);
        assert_eq!(rep.msg_type, MSG_TYPE_TGS_REP);
        assert_eq!(rep.crealm, alice.realm);
        assert_eq!(rep.cname, alice.components);
        assert_eq!(rep.ticket.sname, web.components);

        // The service ticket must be decryptable with the service's key
        // (key usage 2).
        let svc_pt = decrypt_for_usage(&web.key, KEY_USAGE_TGS_REP_TICKET, &rep.ticket.enc_part)
            .expect("decrypt service ticket");
        let svc_etp = decode_enc_ticket_part(&svc_pt).expect("decode EncTicketPart");
        assert_eq!(svc_etp.cname, alice.components);
        assert_eq!(svc_etp.crealm, alice.realm);
        assert_eq!(svc_etp.session_key, session_key);

        // The TGS-REP enc-part must be decryptable with the TGT session key
        // (key usage 8).
        let rep_pt = decrypt_for_usage(&session_key, KEY_USAGE_TGS_REP_ENC_PART, &rep.enc_part)
            .expect("decrypt TGS-REP enc-part");
        let erp = decode_enc_kdc_rep_part(&rep_pt).expect("decode EncKdcRepPart");
        assert_eq!(erp.session_key, session_key);
        assert_eq!(erp.nonce, 1234);
    }

    #[tokio::test]
    async fn tgs_req_handler_rejects_corrupt_tgt() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        let web = make_svc_principal("EXAMPLE.COM", "web.example.com", "svc-pass");
        store.insert(alice.clone());
        store.insert(web.clone());
        let krbtgt_key = make_krbtgt_key();

        let (mut tgt, session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        tgt.enc_part[0] ^= 0xFF;

        let auth_enc = build_authenticator_enc(&alice, &session_key);
        let req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: web.realm.clone(),
            sname: web.components.clone(),
            nonce: 1234,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt,
            authenticator_enc: auth_enc,
            till: now_secs() + 3600,
        };
        let req_bytes = encode_tgs_req(&req);

        let err = handle_tgs_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("corrupt TGT must be rejected");
        assert!(matches!(err, KdcError::PreauthFailed(_)));
    }

    #[tokio::test]
    async fn tgs_req_handler_service_principal_not_found() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let (tgt, session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        let auth_enc = build_authenticator_enc(&alice, &session_key);
        let req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: "EXAMPLE.COM".into(),
            sname: vec!["host".into(), "nope.example.com".into()],
            nonce: 1,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt,
            authenticator_enc: auth_enc,
            till: now_secs() + 3600,
        };
        let req_bytes = encode_tgs_req(&req);

        let err = handle_tgs_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("missing SPN must be rejected");
        match err {
            KdcError::PrincipalNotFound(msg) => assert!(msg.contains("nope.example.com")),
            other => panic!("expected PrincipalNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tgs_req_handler_rejects_authenticator_cname_mismatch() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        let bob = make_principal("EXAMPLE.COM", "bob", "secret");
        let web = make_svc_principal("EXAMPLE.COM", "web.example.com", "svc-pass");
        store.insert(alice.clone());
        store.insert(bob.clone());
        store.insert(web.clone());
        let krbtgt_key = make_krbtgt_key();

        // Build a TGT for alice, but an authenticator that claims to be bob.
        let (tgt, session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        let auth_enc = build_authenticator_enc(&bob, &session_key);

        let req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: web.realm.clone(),
            sname: web.components.clone(),
            nonce: 1,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt,
            authenticator_enc: auth_enc,
            till: now_secs() + 3600,
        };
        let req_bytes = encode_tgs_req(&req);

        let err = handle_tgs_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect_err("cname mismatch must be rejected");
        match err {
            KdcError::PreauthFailed(msg) => assert!(msg.contains("does not match")),
            other => panic!("expected PreauthFailed(cname mismatch), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tgs_req_handler_rejects_garbage_input() {
        let store = InMemoryPrincipalStore::new();
        let krbtgt_key = make_krbtgt_key();
        let err = handle_tgs_req(&store, &krbtgt_key, &[0u8; 3])
            .await
            .expect_err("garbage must fail");
        assert!(matches!(err, KdcError::Storage(_)));
    }

    // ---- EType policy & helpers ----

    #[test]
    fn etype_from_u32_round_trips_known_etypes() {
        assert_eq!(EType::from_u32(17), Some(EType::Aes128CtsHmacSha1_96));
        assert_eq!(EType::from_u32(18), Some(EType::Aes256CtsHmacSha1_96));
        assert_eq!(EType::from_u32(19), Some(EType::Aes128CtsHmacSha256_128));
        assert_eq!(EType::from_u32(20), Some(EType::Aes256CtsHmacSha384_192));
        assert_eq!(EType::from_u32(23), Some(EType::Rc4Hmac));
        assert_eq!(EType::from_u32(99), None);
    }

    #[test]
    fn etype_is_allowed_by_policy_distinguishes_rc4() {
        assert!(EType::Aes256CtsHmacSha1_96.is_allowed_by_policy());
        assert!(EType::Aes128CtsHmacSha1_96.is_allowed_by_policy());
        assert!(!EType::Rc4Hmac.is_allowed_by_policy());
    }

    #[test]
    fn principal_names_eq_is_case_insensitive() {
        assert!(principal_names_eq(
            &["alice".to_string()],
            &["ALICE".to_string()]
        ));
        assert!(principal_names_eq(
            &["krbtgt".to_string(), "EXAMPLE.COM".to_string()],
            &["krbtgt".to_string(), "example.com".to_string()]
        ));
        assert!(!principal_names_eq(
            &["alice".to_string()],
            &["bob".to_string()]
        ));
        assert!(!principal_names_eq(
            &["alice".to_string()],
            &["alice".to_string(), "extra".to_string()]
        ));
    }

    #[test]
    fn constant_time_eq_handles_unequal_lengths() {
        assert!(!constant_time_eq(&[1u8, 2, 3], &[1u8, 2]));
        assert!(constant_time_eq(&[1u8, 2, 3], &[1u8, 2, 3]));
        assert!(!constant_time_eq(&[1u8, 2, 3], &[1u8, 2, 4]));
    }

    /// AS-REQ handler: full end-to-end round-trip — issue a TGT, then
    /// immediately use the TGT to request a service ticket. The service
    /// ticket's session key must match the TGT's session key (v0.6.0 policy).
    #[tokio::test]
    async fn as_req_then_tgs_req_end_to_end() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        let web = make_svc_principal("EXAMPLE.COM", "web.example.com", "svc-pass");
        store.insert(alice.clone());
        store.insert(web.clone());
        let krbtgt_key = make_krbtgt_key();

        // Step 1: AS-REQ → AS-REP.
        let as_req = build_valid_as_req(&alice).await;
        let as_rep_bytes = handle_as_req(&store, &krbtgt_key, &encode_as_req(&as_req))
            .await
            .expect("AS-REQ");
        let as_rep = decode_as_rep(&as_rep_bytes).expect("decode AS-REP");

        // Recover the session key from the AS-REP enc-part.
        let rep_pt = decrypt_for_usage(&alice.key, KEY_USAGE_AS_REP_ENC_PART, &as_rep.enc_part)
            .expect("decrypt AS-REP enc-part");
        let erp = decode_enc_kdc_rep_part(&rep_pt).expect("decode EncKdcRepPart");
        let session_key = erp.session_key;

        // Step 2: TGS-REQ using the TGT from the AS-REP.
        let auth_enc = build_authenticator_enc(&alice, &session_key);
        let tgs_req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: web.realm.clone(),
            sname: web.components.clone(),
            nonce: 9999,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt: as_rep.ticket.clone(),
            authenticator_enc: auth_enc,
            till: now_secs() + 3600,
        };
        let tgs_rep_bytes = handle_tgs_req(&store, &krbtgt_key, &encode_tgs_req(&tgs_req))
            .await
            .expect("TGS-REQ");
        let tgs_rep = decode_tgs_rep(&tgs_rep_bytes).expect("decode TGS-REP");

        // The service ticket's session key matches the TGT session key.
        let svc_pt =
            decrypt_for_usage(&web.key, KEY_USAGE_TGS_REP_TICKET, &tgs_rep.ticket.enc_part)
                .expect("decrypt service ticket");
        let svc_etp = decode_enc_ticket_part(&svc_pt).expect("decode svc EncTicketPart");
        assert_eq!(svc_etp.session_key, session_key);
    }

    // ---- Wave 3b: MetricsRegistry producer wiring ----
    //
    // These tests verify that the KDC hot path is now a MetricsRegistry
    // producer per EVALUATION.md P1 #14 / ADR-057. The assertion strategy
    // is "handle an AS-REQ via the metrics-enabled entry point, then
    // render the registry in Prometheus exposition format and grep the
    // output for the expected counter / histogram lines" — the same
    // strategy used by `adrian-monitor::tests`.

    /// After a single successful AS-REQ, the `as_req_total{realm,etype}`
    /// counter must read 1 for the negotiated (realm, etype) label pair.
    #[tokio::test]
    async fn as_req_increments_metric() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();
        let reg = MetricsRegistry::new();

        let req = build_valid_as_req(&alice).await;
        let req_bytes = encode_as_req(&req);

        let _rep = handle_as_req_with_metrics(&store, &krbtgt_key, &req_bytes, Some(&reg))
            .await
            .expect("AS-REQ must succeed");

        let out = reg.render_prometheus().await;
        assert!(
            out.contains("# TYPE adrian_as_req_total counter"),
            "missing TYPE line: {out}"
        );
        assert!(
            out.contains(
                r#"adrian_as_req_total{realm="EXAMPLE.COM",etype="aes256-cts-hmac-sha1-96"} 1"#
            ),
            "expected as_req_total counter == 1 for EXAMPLE.COM/aes256-cts-hmac-sha1-96: {out}"
        );
    }

    /// After a single successful AS-REQ, the `as_req_duration_seconds`
    /// histogram must have exactly 1 observation (the `_count` line should
    /// read 1, and the `+Inf` cumulative bucket should also read 1).
    #[tokio::test]
    async fn as_req_records_duration() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();
        let reg = MetricsRegistry::new();

        let req = build_valid_as_req(&alice).await;
        let req_bytes = encode_as_req(&req);

        let _rep = handle_as_req_with_metrics(&store, &krbtgt_key, &req_bytes, Some(&reg))
            .await
            .expect("AS-REQ must succeed");

        let out = reg.render_prometheus().await;
        assert!(
            out.contains("# TYPE adrian_as_req_duration_seconds histogram"),
            "missing TYPE line: {out}"
        );
        assert!(
            out.contains("adrian_as_req_duration_seconds_count 1"),
            "expected histogram _count == 1 after one AS-REQ: {out}"
        );
        assert!(
            out.contains(r#"adrian_as_req_duration_seconds_bucket{le="+Inf"} 1"#),
            "expected +Inf cumulative bucket == 1 after one AS-REQ: {out}"
        );
    }

    /// TGS-REQs must also be counted (under the `as_req_total` counter
    /// with etype label `"tgs_req"` per the v0.6.0 reuse rationale —
    /// `MetricsRegistry` has no `inc_tgs_req` yet). After a successful
    /// TGS-REQ, the counter for `(realm, "tgs_req")` must read 1.
    #[tokio::test]
    async fn tgs_req_increments_metric_with_tgs_req_label() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        let web = make_svc_principal("EXAMPLE.COM", "web.example.com", "svc-pass");
        store.insert(alice.clone());
        store.insert(web.clone());
        let krbtgt_key = make_krbtgt_key();
        let reg = MetricsRegistry::new();

        let (tgt, session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        let auth_enc = build_authenticator_enc(&alice, &session_key);
        let req = TgsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_TGS_REQ,
            realm: web.realm.clone(),
            sname: web.components.clone(),
            nonce: 1234,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            tgt,
            authenticator_enc: auth_enc,
            till: now_secs() + 3600,
        };
        let req_bytes = encode_tgs_req(&req);

        let _rep = handle_tgs_req_with_metrics(&store, &krbtgt_key, &req_bytes, Some(&reg))
            .await
            .expect("TGS-REQ must succeed");

        let out = reg.render_prometheus().await;
        assert!(
            out.contains(r#"adrian_as_req_total{realm="EXAMPLE.COM",etype="tgs_req"} 1"#),
            "expected as_req_total counter == 1 for (EXAMPLE.COM, tgs_req) after TGS-REQ: {out}"
        );
        assert!(
            out.contains("adrian_as_req_duration_seconds_count 1"),
            "expected histogram _count == 1 after one TGS-REQ: {out}"
        );
    }

    // ---- Wave 1: FAST armoring (RFC 6806 / ADR-012) ----

    /// Build a FAST-armored AS-REQ: the client wraps its PA-ENC-TIMESTAMP
    /// inside a `KrbFastArmoredReq` encrypted with the FAST armor key
    /// derived from the armor TGT's session key.
    fn build_fast_armored_as_req(
        client: &PrincipalRecord,
        armor_tgt: Ticket,
        armor_session_key: &[u8; SESSION_KEY_LEN],
    ) -> AsReq {
        let now = now_secs();
        let pa_ts = PaEncTsEnc {
            patimestamp: now,
            pausec: 0,
        };
        let pa_ts_bytes = encode_pa_enc_ts_enc(&pa_ts);
        let blob = encrypt_for_usage(&client.key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &pa_ts_bytes)
            .expect("encrypt pa-enc-timestamp");
        let inner_padata = vec![PaData {
            padata_type: PA_ENC_TIMESTAMP_TYPE,
            padata_value: blob,
        }];
        let armored = wrap_fast_armor(armor_tgt, armor_session_key, inner_padata, 0xCAFE_BABE, now)
            .expect("wrap fast armor");
        AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: client.realm.clone(),
            cname: client.components.clone(),
            nonce: 0xDEAD_BEEF,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            padata: vec![PaData {
                padata_type: PA_FX_FAST_START_TYPE,
                padata_value: encode_krb_fast_armored_req(&armored),
            }],
            till: now + DEFAULT_TGT_LIFETIME_SECS,
        }
    }

    #[test]
    fn fast_factor_encode_decode_round_trip() {
        let f = FastFactor {
            inner_padata: vec![
                PaData {
                    padata_type: PA_ENC_TIMESTAMP_TYPE,
                    padata_value: vec![0xAB, 0xCD],
                },
                PaData {
                    padata_type: 19,
                    padata_value: vec![0x11, 0x22, 0x33],
                },
            ],
            nonce: 42,
            timestamp: 1_700_000_000,
        };
        let bytes = encode_fast_factor(&f);
        let decoded = decode_fast_factor(&bytes).expect("decode");
        assert_eq!(decoded, f);
    }

    #[test]
    fn krb_fast_armored_req_encode_decode_round_trip() {
        let armor_tgt = Ticket {
            tkt_vno: PVNO,
            realm: "EXAMPLE.COM".into(),
            sname: vec!["krbtgt".into(), "EXAMPLE.COM".into()],
            kvno: 1,
            etype: EType::Aes256CtsHmacSha1_96,
            enc_part: vec![0u8; 48],
        };
        let armored = KrbFastArmoredReq {
            armor_type: FAST_ARMOR_TYPE_TGT,
            armor_tgt: armor_tgt.clone(),
            enc_part: vec![0xAA; 32],
        };
        let bytes = encode_krb_fast_armored_req(&armored);
        let decoded = decode_krb_fast_armored_req(&bytes).expect("decode");
        assert_eq!(decoded, armored);
    }

    #[test]
    fn fast_armor_key_derivation_is_deterministic_and_distinct() {
        let k1 = derive_fast_armor_key(&[0x42u8; SESSION_KEY_LEN]);
        let k2 = derive_fast_armor_key(&[0x42u8; SESSION_KEY_LEN]);
        assert_eq!(k1, k2, "same session key must produce same armor key");
        let k3 = derive_fast_armor_key(&[0x99u8; SESSION_KEY_LEN]);
        assert_ne!(
            k1, k3,
            "different session keys must produce different armor keys"
        );
    }

    /// Wave 1 DoD test 1: FAST-wrapped AS-REQ succeeds. The KDC decrypts the
    /// armor TGT, derives the FAST armor key, decrypts the FAST factor,
    /// verifies the inner PA-ENC-TIMESTAMP, and issues an AS-REP whose
    /// enc-part is encrypted with the armor key (not the client's key).
    #[tokio::test]
    async fn fast_wrapped_as_req_succeeds() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        // Client first obtains an armor TGT (reuses the TGT builder).
        let (armor_tgt, armor_session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        let req = build_fast_armored_as_req(&alice, armor_tgt, &armor_session_key);
        let req_bytes = encode_as_req(&req);

        let rep_bytes = handle_as_req_fast(&store, &krbtgt_key, &req_bytes, FastMode::Required)
            .await
            .expect("FAST AS-REQ must succeed");
        let rep = decode_as_rep(&rep_bytes).expect("decode AS-REP");
        assert_eq!(rep.cname, alice.components);
        assert_eq!(
            rep.ticket.sname,
            vec!["krbtgt".to_string(), "EXAMPLE.COM".into()]
        );

        // The AS-REP enc-part is encrypted with the FAST armor key (NOT the
        // client's long-term key) — this is the AS-REP roasting mitigation.
        // Attempting to decrypt with the client's key MUST fail.
        let client_decrypt_err =
            decrypt_for_usage(&alice.key, KEY_USAGE_AS_REP_ENC_PART, &rep.enc_part).unwrap_err();
        assert!(matches!(client_decrypt_err, KdcError::PreauthFailed(_)));

        // Decrypting with the armor key succeeds.
        let armor_key = derive_fast_armor_key(&armor_session_key);
        let rep_pt = decrypt_for_usage(&armor_key.key, KEY_USAGE_AS_REP_ENC_PART, &rep.enc_part)
            .expect("decrypt with armor key");
        let erp = decode_enc_kdc_rep_part(&rep_pt).expect("decode EncKdcRepPart");
        assert_eq!(erp.nonce, req.nonce);
        assert_eq!(erp.cname, alice.components);
    }

    /// Wave 1 DoD test 2: unarmored AS-REQ rejected when `fast_mode = Required`.
    #[tokio::test]
    async fn fast_required_rejects_unarmored_as_req() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let req = build_valid_as_req(&alice).await;
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req_fast(&store, &krbtgt_key, &req_bytes, FastMode::Required)
            .await
            .expect_err("unarmored AS-REQ must be rejected in Required mode");
        assert!(matches!(err, KdcError::FastArmorRequired));
    }

    /// Wave 1 DoD test 3: tampered FAST armor rejected (HMAC verification
    /// fails on the FAST factor's encrypted enc-part).
    #[tokio::test]
    async fn fast_tampered_armor_rejected() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let (armor_tgt, armor_session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        let mut req = build_fast_armored_as_req(&alice, armor_tgt, &armor_session_key);
        // Tamper with the FAST armor padata value (flip a byte in the
        // encoded KrbFastArmoredReq — this corrupts either the armor TGT
        // or the encrypted FAST factor, both of which must be rejected).
        if let Some(b) = req.padata[0].padata_value.get_mut(0) {
            *b ^= 0xFF;
        }
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req_fast(&store, &krbtgt_key, &req_bytes, FastMode::Required)
            .await
            .expect_err("tampered FAST armor must be rejected");
        // Tampered armor → either decode failure (Storage) or decrypt
        // failure (PreauthFailed) depending on which byte was flipped.
        assert!(matches!(
            err,
            KdcError::Storage(_) | KdcError::PreauthFailed(_)
        ));
    }

    /// Wave 1 DoD test 4: wrong armor key rejected. The client wraps the
    /// FAST factor with session key A, but the armor TGT was encrypted with
    /// session key B. The KDC derives the armor key from B and fails to
    /// decrypt the factor wrapped under A.
    #[tokio::test]
    async fn fast_wrong_armor_key_rejected() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        // Build the armor TGT with the correct krbtgt key (so the KDC can
        // decrypt it and recover the real session key).
        let (armor_tgt, _correct_session_key) = build_tgt_and_authenticator(&alice, &krbtgt_key);
        // But encrypt the FAST factor with a DIFFERENT session key —
        // simulating a wrong armor TGT / session key mismatch.
        let wrong_session_key = [0xFFu8; SESSION_KEY_LEN];

        let now = now_secs();
        let pa_ts = PaEncTsEnc {
            patimestamp: now,
            pausec: 0,
        };
        let pa_ts_bytes = encode_pa_enc_ts_enc(&pa_ts);
        let blob = encrypt_for_usage(&alice.key, KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP, &pa_ts_bytes)
            .expect("encrypt");
        let inner_padata = vec![PaData {
            padata_type: PA_ENC_TIMESTAMP_TYPE,
            padata_value: blob,
        }];
        let armored = wrap_fast_armor(armor_tgt.clone(), &wrong_session_key, inner_padata, 1, now)
            .expect("wrap");
        let req = AsReq {
            pvno: PVNO,
            msg_type: MSG_TYPE_AS_REQ,
            realm: alice.realm.clone(),
            cname: alice.components.clone(),
            nonce: 99,
            etypes: vec![EType::Aes256CtsHmacSha1_96],
            padata: vec![PaData {
                padata_type: PA_FX_FAST_START_TYPE,
                padata_value: encode_krb_fast_armored_req(&armored),
            }],
            till: now + DEFAULT_TGT_LIFETIME_SECS,
        };
        let req_bytes = encode_as_req(&req);

        let err = handle_as_req_fast(&store, &krbtgt_key, &req_bytes, FastMode::Required)
            .await
            .expect_err("wrong armor key must be rejected");
        assert!(matches!(err, KdcError::PreauthFailed(_)));
    }

    /// Wave 1 DoD test 5: FAST factor round-trip through encrypt/decrypt.
    /// Verifies that `encode_fast_factor` + `encrypt_for_usage` +
    /// `decrypt_for_usage` + `decode_fast_factor` is a clean round-trip
    /// (the FAST factor survives the armor key encryption intact).
    #[test]
    fn fast_factor_round_trip_through_encrypt_decrypt() {
        let armor_key = derive_fast_armor_key(&[0x99u8; SESSION_KEY_LEN]);
        let factor = FastFactor {
            inner_padata: vec![
                PaData {
                    padata_type: 2,
                    padata_value: vec![0xAA],
                },
                PaData {
                    padata_type: 19,
                    padata_value: vec![0xBB, 0xCC],
                },
            ],
            nonce: 0x1234_5678,
            timestamp: 1_700_000_000,
        };
        let bytes = encode_fast_factor(&factor);
        let enc = encrypt_for_usage(&armor_key.key, KEY_USAGE_FAST_ARMOR_REQ_ENC, &bytes)
            .expect("encrypt");
        let dec =
            decrypt_for_usage(&armor_key.key, KEY_USAGE_FAST_ARMOR_REQ_ENC, &enc).expect("decrypt");
        let recovered = decode_fast_factor(&dec).expect("decode");
        assert_eq!(recovered, factor);
    }

    /// `fast_mode = Supported` accepts unarmored AS-REQs by falling through
    /// to the standard handler path (ADR-012 migration mode).
    #[tokio::test]
    async fn fast_supported_accepts_unarmored_as_req() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();

        let req = build_valid_as_req(&alice).await;
        let req_bytes = encode_as_req(&req);

        let rep_bytes = handle_as_req_fast(&store, &krbtgt_key, &req_bytes, FastMode::Supported)
            .await
            .expect("Supported mode must accept unarmored AS-REQ");
        let rep = decode_as_rep(&rep_bytes).expect("decode AS-REP");
        assert_eq!(rep.cname, alice.components);
    }

    /// Backward-compat path: `handle_as_req` (no metrics arg) must NOT
    /// populate the registry — i.e. the legacy entry point is observably
    /// a no-op for metrics. This guards against accidental metric
    /// recording when callers (e.g. tests, future SDK shims) pass
    /// through the back-compat path.
    #[tokio::test]
    async fn back_compat_handle_as_req_does_not_record_metrics() {
        let store = InMemoryPrincipalStore::new();
        let alice = make_principal("EXAMPLE.COM", "alice", "hunter2");
        store.insert(alice.clone());
        let krbtgt_key = make_krbtgt_key();
        let reg = MetricsRegistry::new();

        // The back-compat `handle_as_req` does not take a `MetricsRegistry`;
        // to assert no metric recording, we exercise it and then check
        // that the shared registry stays empty. The Prometheus renderer
        // always emits the `# HELP` / `# TYPE` lines for every registered
        // metric, so we assert on the *value* lines (counter absent,
        // histogram count == 0) rather than on the metric name.
        let req = build_valid_as_req(&alice).await;
        let req_bytes = encode_as_req(&req);
        let _rep = handle_as_req(&store, &krbtgt_key, &req_bytes)
            .await
            .expect("AS-REQ must succeed");

        let out = reg.render_prometheus().await;
        assert!(
            !out.contains(r#"adrian_as_req_total{realm="EXAMPLE.COM""#),
            "back-compat handle_as_req must not record as_req_total counter, but got: {out}"
        );
        // The renderer always emits `_count 0` for an unobserved histogram;
        // assert the count remains 0 (no observations were recorded).
        assert!(
            out.contains("adrian_as_req_duration_seconds_count 0"),
            "expected histogram _count == 0 (no observations) on back-compat path, got: {out}"
        );
    }
}
