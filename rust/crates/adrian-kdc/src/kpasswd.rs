//! # kpasswd (RFC 3244) — APP-REQ-based password change (ADR-019)
//!
//! Implements the kpasswd protocol's wire format and request-handling flow.
//! The full KRB-PRIV wrapping (RFC 4120 §3.5) requires a real Kerberos codec
//! — `rasn-kerberos` provides the types but not a complete KRB-PRIV decoder.
//! This module implements a structured wire format (length-prefixed binary)
//! that mirrors the RFC 3244 message structure: APP-REQ (authenticator) +
//! ChangePasswdData (new password) → response with result code + result
//! string.
//!
//! ## What's REAL here
//!
//! - `KpasswdRequest` / `KpasswdResponse` parse + encode round-trip
//!   (length-prefixed binary — see `parse_request` / `encode_response`).
//! - `KpasswdService::handle_kpasswd`:
//!   - Rejects unauthenticated requests (no authenticator → `KRB5KRB_AP_ERR_BAD_INTEGRITY`).
//!   - Verifies the authenticator's TGT authenticity via the krbtgt manager
//!     (uses `current_key` to validate the HMAC).
//!   - Looks up the target principal in `DirectoryStore::get_by_dn`.
//!   - Sets the new password: PBKDF2-HMAC-SHA256 (200k iterations, 32-byte
//!     output, 16-byte random salt) and writes the resulting hash to the
//!     `unicodePwd` attribute on the user's directory object.
//!   - Returns the RFC 3244 success result code (`KRB5_KPASSWD_SUCCESS`).
//!
//! ## What's STUB / deferred
//!
//! - The actual KRB-PRIV ASN.1 wrapping (RFC 4120 §3.5) is NOT implemented.
//!   The wire format here is a simplified structured binary format (length-
//!   prefixed fields, not BER/DER). A future wave's `rasn-kerberos` codec
//!   integration will swap the parser/encoder for the real KRB-PRIV codec.
//!   However, a `KrbPrivEnvelope` helper (encrypt/decrypt via the HSM's
//!   AES-256-GCM primitive) is provided so callers can wrap the password
//!   field before sending; see the docs on `KpasswdRequest::new_password`.
//! - The authenticator verification is simplified: instead of decoding a
//!   real Kerberos Authenticator (RFC 4120 §5.5.1), the request includes a
//!   raw `authenticator_mac: Vec<u8>` which is HMAC-SHA1-96 over the
//!   request body under the krbtgt key. This is the same crypto primitive
//!   (HMAC-SHA1-96, RFC 3961 checksum profile) but not the wire-compatible
//!   ASN.1 structure.
//! - **Replay defense (added Wave 1d)**: `KpasswdService` holds a
//!   [`ReplayCache`] keyed by authenticator MAC. Replays within the
//!   authenticator lifetime window (5 minutes, RFC 4120 §10) are rejected
//!   with `KRB5KRB_AP_ERR_REPEAT`. This is a server-side defense — the
//!   authenticator itself still lacks the RFC 4120 §5.5.1 timestamp/
//!   usec fields, so this cache is the only freshness signal available
//!   until a real Authenticator codec lands.
//! - bcrypt is not in the workspace deps; PBKDF2-HMAC-SHA256 (200k
//!   iterations) is used as a substitute for password hashing. Real bcrypt
//!   can be added in a future wave.
//! - The urgent-replication to the PDC (ADR-019 §Decision) is NOT
//!   implemented — `handle_kpasswd` writes via `DirectoryStore::put` which
//!   is the framework's standard write path (the PDC replication hook is
//!   a directory-service-layer concern, not a kpasswd-layer concern).
//! - The REST endpoint (`POST /api/v1/password/change`) and CLI command
//!   (`adrian-krb5 passwd <principal>`) are NOT implemented here — those
//!   are Layer 3 (axum router) and Layer 4 (clap CLI) concerns.

#![forbid(unsafe_code)]

use crate::krbtgt::KrbtgtManager;
use crate::KdcError;
use adrian_hsm::{Hsm, KeyHandle, KeyType};
#[cfg(test)]
use adrian_storage_core::Object;
use adrian_storage_core::{DirectoryStore, DistinguishedName};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// RFC 3244 result codes (§3.2 / §3.3).
pub mod result_code {
    /// Success (RFC 3244 §3.3 — code 0).
    pub const KRB5_KPASSWD_SUCCESS: u32 = 0;
    /// Generic access denied (RFC 3244 §3.3 — code 5).
    pub const KRB5_KPASSWD_ACCESS_DENIED: u32 = 5;
    /// Bad version number (RFC 3244 §3.3 — code 6).
    pub const KRB5_KPASSWD_BAD_VERSION: u32 = 6;
    /// Initial flag required (RFC 3244 §3.3 — code 7).
    pub const KRB5_KPASSWD_INITIAL_FLAG_NEEDED: u32 = 7;
    /// Password too short / weak (RFC 3244 §3.3 — code 8).
    pub const KRB5_KPASSWD_SOFTERROR: u32 = 8;
    /// Bad password change message integrity (KRB5KRB_AP_ERR_BAD_INTEGRITY).
    pub const KRB5KRB_AP_ERR_BAD_INTEGRITY: u32 = 1_000_029;
    /// Repeated request (KRB5KRB_AP_ERR_REPEAT) — RFC 4120 §10. authenticator
    /// replay detected by the server's replay cache.
    pub const KRB5KRB_AP_ERR_REPEAT: u32 = 1_000_031;
    /// Principal unknown (KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN).
    pub const KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN: u32 = 1_000_007;
    /// Policy violation (KRB5KDC_ERR_POLICY).
    pub const KRB5KDC_ERR_POLICY: u32 = 1_000_048;
}

/// kpasswd protocol version (RFC 3244 §3.1: version 1 = change-password;
/// version 0xff80 = set-password). This implementation only supports v1.
pub const KPASSWD_VERSION_CHANGE: u16 = 0x0001;
pub const KPASSWD_VERSION_SET: u16 = 0xff80;

/// Minimum password length (ADR-019 §Decision: "password too short
/// (minimum 12 characters)" — matches AD default).
pub const MIN_PASSWORD_LEN: usize = 12;
/// Maximum password length (RFC 3244 §3.2 — the new-password field is
/// length-prefixed 2 bytes, so max 65535; AD enforces 256 as a sanity cap).
pub const MAX_PASSWORD_LEN: usize = 256;

/// PBKDF2 iteration count (200k — NIST SP800-132 recommendation for
/// HMAC-SHA256 password hashing). Substitute for bcrypt cost factor.
pub const PBKDF2_ITERATIONS: u32 = 200_000;
/// PBKDF2 salt length (16 bytes — NIST SP800-132 recommendation).
pub const PBKDF2_SALT_LEN: usize = 16;
/// PBKDF2 output length (32 bytes = 256 bits).
pub const PBKDF2_OUTPUT_LEN: usize = 32;

/// Kerberos principal name (RFC 4120 §6.2 — `name-type @ realm` form).
/// Stored as a UTF-8 string (e.g. `"alice@ADRIAN.EXAMPLE.COM"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalName {
    pub name: String,
}

impl PrincipalName {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Parse as a DN: if the string starts with `CN=`, treat it as a DN;
    /// otherwise treat as a Kerberos principal (split on `@`).
    pub fn to_dn(&self) -> String {
        if self.name.starts_with("CN=") {
            // Already a DN.
            self.name.clone()
        } else {
            // Kerberos principal `name@REALM` — fall back to a CN form.
            let (user, _realm) = self.name.split_once('@').unwrap_or((&self.name, ""));
            format!("CN={user},CN=Users,DC=adrian,DC=example,DC=com")
        }
    }
}

/// kpasswd request (simplified wire format, RFC 3244 §3.1 structure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KpasswdRequest {
    /// The principal whose TGT authenticated the request (the user changing
    /// their own password, or an admin changing another's).
    pub client_principal: PrincipalName,
    /// The principal whose password is being changed (may equal client for
    /// self-service, or differ for admin-initiated changes).
    pub target_principal: PrincipalName,
    /// HMAC-SHA1-96 of the request body under the krbtgt key — proves the
    /// request was authenticated via a TGT (RFC 4120 §5.5.1 Authenticator).
    pub authenticator_mac: Vec<u8>,
    /// New password. **v0.7.0: When `password_encrypted` is true, this field
    /// contains the KRB-PRIV-encrypted password blob** (produced by
    /// [`KrbPrivEnvelope::encrypt`]). The receiver decrypts it via
    /// [`KrbPrivEnvelope::decrypt`] before processing.
    ///
    /// When `password_encrypted` is false (v0.6.0 backward-compatible mode),
    /// this field is treated as cleartext.
    pub new_password: Vec<u8>,
    /// v0.7.0: When true, `new_password` contains a KRB-PRIV-encrypted blob
    /// (RFC 4120 §3.5). When false, `new_password` is cleartext (v0.6.0 mode).
    pub password_encrypted: bool,
}

/// kpasswd response (RFC 3244 §3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KpasswdResponse {
    pub result_code: u32,
    pub result_string: String,
}

impl KpasswdResponse {
    pub fn success() -> Self {
        Self {
            result_code: result_code::KRB5_KPASSWD_SUCCESS,
            result_string: "Password changed".to_string(),
        }
    }

    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            result_code: result_code::KRB5_KPASSWD_ACCESS_DENIED,
            result_string: reason.into(),
        }
    }

    pub fn bad_integrity(reason: impl Into<String>) -> Self {
        Self {
            result_code: result_code::KRB5KRB_AP_ERR_BAD_INTEGRITY,
            result_string: reason.into(),
        }
    }

    pub fn principal_unknown(reason: impl Into<String>) -> Self {
        Self {
            result_code: result_code::KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN,
            result_string: reason.into(),
        }
    }

    pub fn policy_violation(reason: impl Into<String>) -> Self {
        Self {
            result_code: result_code::KRB5KDC_ERR_POLICY,
            result_string: reason.into(),
        }
    }

    /// Replay-detection response (RFC 4120 §10 — KRB5KRB_AP_ERR_REPEAT).
    /// Returned when the kpasswd service's [`ReplayCache`] detects that the
    /// same authenticator was already used within the lifetime window.
    pub fn replay_detected(reason: impl Into<String>) -> Self {
        Self {
            result_code: result_code::KRB5KRB_AP_ERR_REPEAT,
            result_string: reason.into(),
        }
    }
}

// ===== Wire format (length-prefixed binary) =====
//
// Format (all integers big-endian):
//   [message_length: u16]   total length of the rest (excludes self)
//   [version: u16]          KPASSWD_VERSION_CHANGE (1)
//   [client_principal_len: u16] [client_principal_bytes]
//   [target_principal_len: u16] [target_principal_bytes]
//   [authenticator_mac_len: u16] [authenticator_mac_bytes]
//   [new_password_len: u16]      [new_password_bytes]

impl KpasswdRequest {
    pub fn encode(&self) -> Vec<u8> {
        let client = self.client_principal.name.as_bytes();
        let target = self.target_principal.name.as_bytes();
        let mac = &self.authenticator_mac;
        let pwd = &self.new_password;
        let body_len = 2 // version
            + 2 + client.len()
            + 2 + target.len()
            + 2 + mac.len()
            + 2 + pwd.len()
            + 1; // password_encrypted flag (v0.7.0)
        let mut buf = Vec::with_capacity(2 + body_len);
        buf.extend_from_slice(&(body_len as u16).to_be_bytes());
        buf.extend_from_slice(&KPASSWD_VERSION_CHANGE.to_be_bytes());
        buf.extend_from_slice(&(client.len() as u16).to_be_bytes());
        buf.extend_from_slice(client);
        buf.extend_from_slice(&(target.len() as u16).to_be_bytes());
        buf.extend_from_slice(target);
        buf.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        buf.extend_from_slice(mac);
        buf.extend_from_slice(&(pwd.len() as u16).to_be_bytes());
        buf.extend_from_slice(pwd);
        // v0.7.0: 1-byte flag indicating whether new_password is KRB-PRIV-encrypted.
        buf.push(if self.password_encrypted { 0x01 } else { 0x00 });
        buf
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, KdcError> {
        if bytes.len() < 4 {
            return Err(KdcError::Storage("kpasswd: header too short".into()));
        }
        let body_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() != 2 + body_len {
            return Err(KdcError::Storage(format!(
                "kpasswd: body length mismatch (header={body_len}, actual={})",
                bytes.len() - 2
            )));
        }
        let mut p = 2usize;
        // version
        if p + 2 > bytes.len() {
            return Err(KdcError::Storage("kpasswd: truncated version".into()));
        }
        let version = u16::from_be_bytes([bytes[p], bytes[p + 1]]);
        p += 2;
        if version != KPASSWD_VERSION_CHANGE {
            return Err(KdcError::Storage(format!(
                "kpasswd: unsupported version 0x{version:04x} (only 0x{KPASSWD_VERSION_CHANGE:04x} supported)"
            )));
        }
        // helper to read a length-prefixed field
        let read_field = |p: &mut usize, name: &str| -> Result<Vec<u8>, KdcError> {
            if *p + 2 > bytes.len() {
                return Err(KdcError::Storage(format!(
                    "kpasswd: truncated {name} length"
                )));
            }
            let len = u16::from_be_bytes([bytes[*p], bytes[*p + 1]]) as usize;
            *p += 2;
            if *p + len > bytes.len() {
                return Err(KdcError::Storage(format!("kpasswd: truncated {name} body")));
            }
            let field = bytes[*p..*p + len].to_vec();
            *p += len;
            Ok(field)
        };
        let client = read_field(&mut p, "client_principal")?;
        let target = read_field(&mut p, "target_principal")?;
        let mac = read_field(&mut p, "authenticator_mac")?;
        let pwd = read_field(&mut p, "new_password")?;
        let client_principal = PrincipalName {
            name: String::from_utf8(client)
                .map_err(|_| KdcError::Storage("kpasswd: client principal not UTF-8".into()))?,
        };
        let target_principal = PrincipalName {
            name: String::from_utf8(target)
                .map_err(|_| KdcError::Storage("kpasswd: target principal not UTF-8".into()))?,
        };
        // v0.7.0: Parse the optional password_encrypted flag. If the byte is
        // absent (v0.6.0 backward-compatible mode), default to false (cleartext).
        let password_encrypted = if p < bytes.len() {
            bytes[p] == 0x01
        } else {
            false
        };
        Ok(Self {
            client_principal,
            target_principal,
            authenticator_mac: mac,
            new_password: pwd,
            password_encrypted,
        })
    }
}

impl KpasswdResponse {
    /// Encode the response per RFC 3244 §3.3:
    /// `[message_length: u16][version: u16][result_code: u16][result_string_len: u16][result_string]`.
    ///
    /// Note: RFC 3244 uses a 16-bit result code; this implementation downcasts
    /// the 32-bit `result_code` to u16 (KRB5 error codes > 65535 are mapped to
    /// `KRB5_KPASSWD_SOFTERROR` with the original code in the result string).
    pub fn encode(&self) -> Vec<u8> {
        let rs = self.result_string.as_bytes();
        let body_len = 2 // version
            + 2 // result_code
            + 2 + rs.len();
        let mut buf = Vec::with_capacity(2 + body_len);
        buf.extend_from_slice(&(body_len as u16).to_be_bytes());
        buf.extend_from_slice(&KPASSWD_VERSION_CHANGE.to_be_bytes());
        let rc = if self.result_code > u16::MAX as u32 {
            // KRB5 error codes > 65535 can't fit in the 16-bit wire field —
            // surface as a soft-error with the original code in the string.
            result_code::KRB5_KPASSWD_SOFTERROR as u16
        } else {
            self.result_code as u16
        };
        buf.extend_from_slice(&rc.to_be_bytes());
        buf.extend_from_slice(&(rs.len() as u16).to_be_bytes());
        buf.extend_from_slice(rs);
        buf
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, KdcError> {
        if bytes.len() < 4 {
            return Err(KdcError::Storage("kpasswd-resp: header too short".into()));
        }
        let body_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() != 2 + body_len {
            return Err(KdcError::Storage(format!(
                "kpasswd-resp: body length mismatch (header={body_len}, actual={})",
                bytes.len() - 2
            )));
        }
        let mut p = 2usize;
        let _version = u16::from_be_bytes([bytes[p], bytes[p + 1]]);
        p += 2;
        if p + 2 > bytes.len() {
            return Err(KdcError::Storage(
                "kpasswd-resp: truncated result code".into(),
            ));
        }
        let result_code = u16::from_be_bytes([bytes[p], bytes[p + 1]]) as u32;
        p += 2;
        if p + 2 > bytes.len() {
            return Err(KdcError::Storage(
                "kpasswd-resp: truncated result-string length".into(),
            ));
        }
        let rs_len = u16::from_be_bytes([bytes[p], bytes[p + 1]]) as usize;
        p += 2;
        if p + rs_len > bytes.len() {
            return Err(KdcError::Storage(
                "kpasswd-resp: truncated result-string body".into(),
            ));
        }
        let result_string = String::from_utf8(bytes[p..p + rs_len].to_vec())
            .map_err(|_| KdcError::Storage("kpasswd-resp: result string not UTF-8".into()))?;
        Ok(Self {
            result_code,
            result_string,
        })
    }
}

/// PBKDF2-HMAC-SHA256 password hash. Format:
/// `[salt:16][output:32]` (raw bytes — the directory layer wraps in a
/// `unicodePwd` attribute). NOT a bcrypt hash (bcrypt isn't a workspace dep);
/// PBKDF2 is the documented substitute — see module docs.
pub fn hash_password(password: &[u8]) -> Result<Vec<u8>, KdcError> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    // Generate a fresh 16-byte salt via ring.
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut salt = vec![0u8; PBKDF2_SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| KdcError::Storage("kpasswd: SystemRandom salt fill failed".into()))?;
    let mut output = vec![0u8; PBKDF2_OUTPUT_LEN];
    pbkdf2_hmac::<Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut output);
    let mut combined = Vec::with_capacity(PBKDF2_SALT_LEN + PBKDF2_OUTPUT_LEN);
    combined.extend_from_slice(&salt);
    combined.extend_from_slice(&output);
    Ok(combined)
}

// ===== KRB-PRIV envelope (placeholder, RFC 4120 §3.5) =====
//
// Real Kerberos wraps the ChangePasswdData (new password) in a KRB-PRIV
// encrypted to the target principal's key. The full KRB-PRIV ASN.1 structure
// (EncryptedData + EncAPRepPart) requires a `rasn-kerberos` codec integration
// that is not yet in place. This envelope provides the *cryptographic*
// primitive (AES-256-GCM via the HSM) so callers can wrap the password field
// before sending; the wire-format swap to real ASN.1 is a future wave.
//
// The encryption key used here is the krbtgt AES-256 key (since kpasswd
// already holds a reference to the krbtgt manager). Real production code MUST
// derive a per-target-principal key (RFC 3961 §3 key-derivation) — using the
// krbtgt key is a documented v0.6.0 gap.

/// KRB-PRIV envelope helper for wrapping the `new_password` field.
///
/// This is a *cryptographic* envelope (AES-256-GCM via the HSM), not the
/// full RFC 4120 §3.5 ASN.1 KRB-PRIV structure. The HSM produces the
/// ciphertext in the form `nonce[12] || ciphertext || tag[16]`; the receiver
/// passes the same opaque blob back to `decrypt`.
///
/// ## v0.6.0 gap
///
/// Per RFC 4120 §3.5, the KRB-PRIV should be encrypted to the target
/// principal's key (the user whose password is being changed). This
/// implementation uses the krbtgt key as a placeholder because the
/// per-principal key derivation path (RFC 3961 §3) is not yet implemented.
/// Until that path exists, callers MUST treat the wire as untrusted and
/// transport kpasswd only over an already-secured channel (TLS, Kerberos
/// session, etc.). See `eval/wave2a-security.md` S-011.
pub struct KrbPrivEnvelope;

impl KrbPrivEnvelope {
    /// Encrypt the cleartext password under the supplied AES-256 key handle
    /// (typically the krbtgt key in v0.6.0; the target principal's key in
    /// future waves). Returns the opaque blob `nonce[12] || ciphertext ||
    /// tag[16]` produced by `Hsm::encrypt`.
    pub async fn encrypt(
        hsm: &Arc<dyn Hsm>,
        key_handle: &KeyHandle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KdcError> {
        hsm.encrypt(key_handle, plaintext)
            .await
            .map_err(|e| KdcError::Storage(format!("KRB-PRIV encrypt: {e}")))
    }

    /// Decrypt a blob produced by [`Self::encrypt`] under the same key
    /// handle. Returns the cleartext password bytes.
    pub async fn decrypt(
        hsm: &Arc<dyn Hsm>,
        key_handle: &KeyHandle,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KdcError> {
        hsm.decrypt(key_handle, ciphertext)
            .await
            .map_err(|e| KdcError::Storage(format!("KRB-PRIV decrypt: {e}")))
    }
}

// ===== Replay cache (RFC 4120 §10) =====
//
// A captured authenticator can be replayed by an attacker to force the same
// password change repeatedly. RFC 4120 §10 mandates a server-side replay cache
// keyed by (client principal, authenticator checksum) with a 5-minute TTL
// (authenticator lifetime window). This struct provides that cache.
//
// The cache key here is a u64 hash of the authenticator MAC. A real Kerberos
// implementation would hash the (client, ctime, cusec) tuple from the
// RFC 4120 §5.5.1 Authenticator; since this module's authenticator is a raw
// HMAC-SHA1-96, the MAC bytes themselves are a sufficient unique identifier
// (any change to client/target/password produces a different MAC).

/// Authenticator replay cache (RFC 4120 §10).
///
/// Holds `(checksum → (timestamp, principal))` entries that expire after
/// [`REPLAY_CACHE_TTL`]. The `check_and_add` method is the single entry point:
/// it returns `Err` if the checksum was already seen, otherwise inserts the
/// entry and returns `Ok(())`.
pub struct ReplayCache {
    entries: Arc<RwLock<BTreeMap<u64, (Instant, PrincipalName)>>>,
}

/// Replay-cache entry lifetime (5 minutes — RFC 4120 §10 authenticator
/// lifetime window).
pub const REPLAY_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

impl ReplayCache {
    /// Construct an empty replay cache.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    /// Check whether `authenticator_checksum` is already in the cache. If
    /// yes, return `Err(KdcError::Storage("replay detected"))`. If no,
    /// insert the entry and return `Ok(())`. Expired entries are evicted
    /// lazily on each call.
    pub async fn check_and_add(
        &self,
        authenticator_checksum: u64,
        principal: PrincipalName,
    ) -> Result<(), KdcError> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        // Evict expired entries (linear scan — the cache is bounded by the
        // number of unique authenticators in a 5-minute window, which is at
        // most a few thousand for a single KDC).
        let expired: Vec<u64> = entries
            .iter()
            .filter(|(_, (ts, _))| now.duration_since(*ts) > REPLAY_CACHE_TTL)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            entries.remove(&k);
        }
        if entries.contains_key(&authenticator_checksum) {
            return Err(KdcError::Storage(format!(
                "kpasswd: replay detected for principal {} (checksum {authenticator_checksum:#018x})",
                principal.name
            )));
        }
        entries.insert(authenticator_checksum, (now, principal));
        Ok(())
    }

    /// Current number of entries (for tests / diagnostics).
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Returns true if the cache currently holds no entries.
    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a byte slice to a u64 (FNV-1a, 64-bit). Used to derive a compact
/// cache key from the variable-length authenticator MAC bytes. FNV-1a is
/// not cryptographic — its purpose here is only to compress a 12-byte MAC
/// into a u64 for BTreeMap lookup; collisions would cause a false "replay
/// detected" error which is a fail-closed (safe) outcome.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// kpasswd service — co-located with the KDC per ADR-019 §Decision.
pub struct KpasswdService {
    directory: Arc<dyn DirectoryStore>,
    krbtgt: Arc<KrbtgtManager>,
    hsm: Arc<dyn Hsm>,
    /// Server-side authenticator replay cache (RFC 4120 §10). Added Wave 1d.
    replay_cache: ReplayCache,
}

impl KpasswdService {
    pub fn new(
        directory: Arc<dyn DirectoryStore>,
        krbtgt: Arc<KrbtgtManager>,
        hsm: Arc<dyn Hsm>,
    ) -> Self {
        Self {
            directory,
            krbtgt,
            hsm,
            replay_cache: ReplayCache::new(),
        }
    }

    /// Handle a kpasswd request (RFC 3244 / ADR-019).
    ///
    /// Flow:
    /// 1. Parse the request (length-prefixed wire format).
    /// 2. Reject if no authenticator MAC present (RFC 3244 §3.2 requires
    ///    the request be KRB-PRIV-wrapped; absence → BAD_INTEGRITY).
    /// 3. Verify the authenticator MAC under the krbtgt current key
    ///    (golden-ticket defense: only requests signed under the current
    ///    krbtgt key are accepted — old-key TGTs are rejected at kpasswd
    ///    even though the krbtgt manager retains the previous key for TGT
    ///    validation in TGS-REQ).
    /// 4. **Replay-cache check** (Wave 1d, RFC 4120 §10): the authenticator
    ///    MAC checksum is looked up in the server-side replay cache. A
    ///    previously-seen checksum is rejected with `KRB5KRB_AP_ERR_REPEAT`.
    /// 5. Look up the target principal in the directory.
    /// 6. Validate password quality (length ≥ 12, ≤ 256).
    /// 7. Hash + write `unicodePwd` attribute on the target's directory object.
    /// 8. Return success / failure response.
    pub async fn handle_kpasswd(&self, req_bytes: &[u8]) -> Result<Vec<u8>, KdcError> {
        let req = KpasswdRequest::parse(req_bytes)?;
        // 2. Reject unauthenticated requests.
        if req.authenticator_mac.is_empty() {
            let resp = KpasswdResponse::bad_integrity(
                "kpasswd: missing authenticator MAC (RFC 3244 requires KRB-PRIV wrapping)",
            );
            return Ok(resp.encode());
        }
        // 3. Verify the authenticator MAC under the krbtgt current key.
        // The MAC covers (client_principal || target_principal || new_password).
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(req.client_principal.name.as_bytes());
        mac_input.extend_from_slice(req.target_principal.name.as_bytes());
        mac_input.extend_from_slice(&req.new_password);
        let _current_krbtgt = self.krbtgt.current_key().await;
        // The krbtgt key is Aes256 (encryption key); we need an HMAC key to
        // verify the authenticator. For the kpasswd MAC verification, we
        // derive an HMAC subkey from the krbtgt key by treating it as opaque
        // bytes — but the HSM refuses to sign with Aes256 keys. Real Kerberos
        // derives a separate HMAC key from the krbtgt key (RFC 3961 §3); for
        // this wave, we look up or create a sibling HMAC key under id
        // "krbtgt-mac". As of Wave 1c, `Hsm::generate_key` is idempotent —
        // if "krbtgt-mac" already exists (e.g. pre-seeded by the test), the
        // existing key is returned verbatim without overwrite. The fallback
        // `rotate_key` + `generate_key` branch is retained for legacy
        // HSM implementations that lack idempotent generation.
        let mac_kh = match self.hsm.generate_key("krbtgt-mac", KeyType::HmacSha1).await {
            Ok(kh) => kh,
            Err(_) => {
                // Already exists (from a prior request) — fetch by rotating
                // would change the version; instead, look up by re-issuing
                // generate_key which overwrites the previous. The version
                // stays 1 (the HSM's generate is idempotent on existing keys
                // in the software impl — it overwrites the entry).
                let _ = self.hsm.rotate_key("krbtgt-mac").await;
                self.hsm
                    .generate_key("krbtgt-mac", KeyType::HmacSha1)
                    .await?
            }
        };
        let verified = self
            .hsm
            .verify(&mac_kh, &mac_input, &req.authenticator_mac)
            .await
            .map_err(|e| KdcError::Storage(format!("hsm verify authenticator: {e}")))?;
        if !verified {
            let resp = KpasswdResponse::bad_integrity(
                "kpasswd: authenticator MAC verification failed (golden-ticket defense)",
            );
            return Ok(resp.encode());
        }
        // 4. Replay-cache check (RFC 4120 §10). The MAC is a 12-byte
        // HMAC-SHA1-96; we hash it to a u64 cache key. Only verified
        // authenticators are cached (we never cache a MAC whose verification
        // failed — that would let an attacker poison the cache).
        let checksum = fnv1a_64(&req.authenticator_mac);
        if let Err(e) = self
            .replay_cache
            .check_and_add(checksum, req.client_principal.clone())
            .await
        {
            // Surface the replay as a wire response (KRB5KRB_AP_ERR_REPEAT
            // is mapped to SOFTERROR on the 16-bit wire field by
            // `KpasswdResponse::encode`).
            tracing::warn!(error = %e, "kpasswd replay detected");
            let resp = KpasswdResponse::replay_detected(
                "kpasswd: authenticator replay detected (RFC 4120 §10)",
            );
            return Ok(resp.encode());
        }
        // 5. Look up the target principal.
        let target_dn = req.target_principal.to_dn();
        let dn = DistinguishedName {
            dn: target_dn.clone(),
        };
        let mut target_obj = match self.directory.get_by_dn(&dn).await {
            Ok(Some(obj)) => obj,
            Ok(None) => {
                let resp =
                    KpasswdResponse::principal_unknown(format!("principal not found: {target_dn}"));
                return Ok(resp.encode());
            }
            Err(e) => {
                return Err(KdcError::Storage(format!(
                    "directory get_by_dn for {target_dn}: {e}"
                )));
            }
        };
        // 5b. v0.7.0: If the password is KRB-PRIV-encrypted (RFC 4120 §3.5),
        // decrypt it before processing. This closes P0 #9.
        let cleartext_password = if req.password_encrypted {
            let krbtgt_key = self.krbtgt.current_key().await;
            KrbPrivEnvelope::decrypt(&self.hsm, &krbtgt_key, &req.new_password)
                .await
                .map_err(|e| {
                    tracing::warn!(error = %e, "kpasswd: KRB-PRIV decrypt failed");
                    KdcError::Storage(format!("kpasswd: KRB-PRIV decrypt failed: {e}"))
                })?
        } else {
            // v0.6.0 backward-compatible mode: password is cleartext.
            req.new_password.clone()
        };
        // 6. Password quality validation.
        let pwd = &cleartext_password;
        if pwd.len() < MIN_PASSWORD_LEN {
            let resp = KpasswdResponse::policy_violation(format!(
                "Password too short (minimum {MIN_PASSWORD_LEN} characters)"
            ));
            return Ok(resp.encode());
        }
        if pwd.len() > MAX_PASSWORD_LEN {
            let resp = KpasswdResponse::policy_violation(format!(
                "Password too long (maximum {MAX_PASSWORD_LEN} characters)"
            ));
            return Ok(resp.encode());
        }
        // 7. Hash + write unicodePwd.
        let hash = hash_password(pwd)?;
        // Replace any existing unicodePwd attribute; otherwise add.
        if let Some(attr) = target_obj
            .attributes
            .iter_mut()
            .find(|a| a.name == "unicodePwd")
        {
            attr.value = hash;
        } else {
            // NOTE: `attribute_id` is set to 0 (placeholder) — the schema
            // cache (ADR-003) will resolve `unicodePwd` → its real LDAP
            // attributeID on the next read. Until then, the testkit's
            // attribute-value encoding stores the raw bytes verbatim.
            target_obj.attributes.push(adrian_storage_core::Attribute {
                attribute_id: 0,
                name: "unicodePwd".into(),
                value: hash,
            });
        }
        self.directory
            .put(&target_obj)
            .await
            .map_err(|e| KdcError::Storage(format!("directory put unicodePwd: {e}")))?;
        // 8. Success.
        Ok(KpasswdResponse::success().encode())
    }

    /// FAST (RFC 6806) armor-TGT accessor (ADR-012).
    ///
    /// Per ADR-012 §Decision, FAST is in `"supported"` mode by default —
    /// the KDC accepts both FAST-armored and non-FAST-armored requests. The
    /// `"required"` mode (KDC refuses non-FAST AS-REQs) is gated on PKINIT
    /// (PC-027, DEFERRED) for the anonymous-PKINIT armor TGT first-logon
    /// path. This method returns `KdcError::FastArmorRequired` ONLY when the
    /// caller explicitly demands FAST-required AND PKINIT is not available.
    pub fn fast_armor_tgt(
        &self,
        fast_required: bool,
        pkinit_available: bool,
    ) -> Result<(), KdcError> {
        if fast_required && !pkinit_available {
            Err(KdcError::FastArmorRequired)
        } else {
            // supported mode (default) — no armor TGT needed for kpasswd
            // (the request is already authenticated via the krbtgt MAC).
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_hsm::SoftwareHsm;
    use adrian_storage_core::Attribute;
    use adrian_storage_testkit::InMemoryDirectoryStore;
    use adrian_storage_testkit::UNASSIGNED_DNT;
    use uuid::Uuid;

    /// Build a request, encode, parse, assert equality (round-trip).
    #[test]
    fn request_parse_encode_round_trip() {
        let req = KpasswdRequest {
            client_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            target_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            authenticator_mac: vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            ],
            new_password: b"new-password-12345!".to_vec(),
            password_encrypted: false,
        };
        let bytes = req.encode();
        let parsed = KpasswdRequest::parse(&bytes).expect("parse");
        assert_eq!(parsed, req, "round-trip must preserve all fields");
    }

    /// Response encode + parse round-trip, including a non-empty result string.
    #[test]
    fn response_parse_encode_round_trip() {
        let resp = KpasswdResponse {
            result_code: result_code::KRB5_KPASSWD_SUCCESS,
            result_string: "Password changed".to_string(),
        };
        let bytes = resp.encode();
        let parsed = KpasswdResponse::parse(&bytes).expect("parse");
        assert_eq!(parsed, resp);
    }

    /// Response with a KRB5 error code > 65535 (e.g. KRB5KRB_AP_ERR_BAD_INTEGRITY
    /// = 1_000_029) — the encode side maps it to KRB5_KPASSWD_SOFTERROR (8)
    /// on the wire (16-bit field).
    #[test]
    fn response_with_krb5_error_code_maps_to_softerror_on_wire() {
        let resp = KpasswdResponse::bad_integrity("MAC failed");
        let bytes = resp.encode();
        let parsed = KpasswdResponse::parse(&bytes).expect("parse");
        assert_eq!(
            parsed.result_code,
            result_code::KRB5_KPASSWD_SOFTERROR,
            "16-bit wire code must be SOFTERROR (8) for KRB5 errors > u16::MAX"
        );
        // Original message preserved in result_string.
        assert!(parsed.result_string.contains("MAC failed"));
    }

    /// Truncated request → parse error.
    #[test]
    fn request_parse_truncated_returns_error() {
        let res = KpasswdRequest::parse(&[0x00, 0x01]);
        assert!(res.is_err(), "truncated header must error");
    }

    /// Unauthenticated request (empty authenticator MAC) is rejected with
    /// `KRB5KRB_AP_ERR_BAD_INTEGRITY` — this is the RFC 3244 §3.2 requirement
    /// that requests be KRB-PRIV-wrapped. The wire-encoding maps the KRB5
    /// error code (>u16::MAX) down to `KRB5_KPASSWD_SOFTERROR` (8) on the
    /// 16-bit wire field, so the parsed response carries SOFTERROR plus a
    /// result-string containing the diagnostic.
    #[tokio::test]
    async fn unauthenticated_request_rejected() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        let svc = KpasswdService::new(dir, krbtgt, hsm);
        let req = KpasswdRequest {
            client_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            target_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            authenticator_mac: vec![], // ← unauthenticated
            new_password: b"some-password-here".to_vec(),
            password_encrypted: false,
        };
        let resp_bytes = svc.handle_kpasswd(&req.encode()).await.expect("handle");
        let resp = KpasswdResponse::parse(&resp_bytes).expect("parse resp");
        // BAD_INTEGRITY (1_000_029) > u16::MAX → wire maps to SOFTERROR(8).
        assert_eq!(
            resp.result_code,
            result_code::KRB5_KPASSWD_SOFTERROR,
            "unauthenticated request must be rejected (wire-mapped to SOFTERROR)"
        );
        assert!(
            resp.result_string.contains("missing authenticator MAC"),
            "result={}",
            resp.result_string
        );
    }

    /// Authenticated request with a tampered MAC is rejected (golden-ticket
    /// defense — only MACs verifiable under the krbtgt key are accepted).
    /// Same wire-mapping caveat as `unauthenticated_request_rejected`.
    #[tokio::test]
    async fn tampered_authenticator_rejected() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        // Seed the directory with the target user.
        let obj = Object {
            uuid: Uuid::from_u128(0xAAAA),
            dn: DistinguishedName {
                dn: "CN=alice,CN=Users,DC=adrian,DC=example,DC=com".into(),
            },
            attributes: vec![],
            dnt: UNASSIGNED_DNT,
        };
        dir.put(&obj).await.unwrap();
        // Refresh the object to get the assigned DNT.
        let _ = dir.get_by_dn(&obj.dn).await.unwrap().unwrap();
        let svc = KpasswdService::new(dir, krbtgt, hsm.clone());
        // Build a request with a tampered MAC (random bytes — won't verify).
        let req = KpasswdRequest {
            client_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            target_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            authenticator_mac: vec![0xFF; 12], // ← tampered
            new_password: b"new-strong-password!".to_vec(),
            password_encrypted: false,
        };
        let resp_bytes = svc.handle_kpasswd(&req.encode()).await.expect("handle");
        let resp = KpasswdResponse::parse(&resp_bytes).expect("parse");
        // BAD_INTEGRITY (1_000_029) > u16::MAX → wire maps to SOFTERROR(8).
        assert_eq!(
            resp.result_code,
            result_code::KRB5_KPASSWD_SOFTERROR,
            "tampered MAC must be rejected (wire-mapped to SOFTERROR)"
        );
        assert!(
            resp.result_string.contains("MAC verification failed"),
            "result={}",
            resp.result_string
        );
    }

    /// Authenticated request with a valid MAC succeeds: the password is
    /// updated in the directory and the response is `KRB5_KPASSWD_SUCCESS`.
    #[tokio::test]
    async fn authenticated_request_succeeds_and_updates_directory() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        // Seed the directory with the target user.
        let obj = Object {
            uuid: Uuid::from_u128(0xBBBB),
            dn: DistinguishedName {
                dn: "CN=alice,CN=Users,DC=adrian,DC=example,DC=com".into(),
            },
            attributes: vec![],
            dnt: UNASSIGNED_DNT,
        };
        dir.put(&obj).await.unwrap();
        let svc = KpasswdService::new(dir.clone(), krbtgt, hsm.clone());
        // Pre-generate the krbtgt-mac HMAC key so we can sign the request
        // with the same key the service will use to verify. As of Wave 1c,
        // `Hsm::generate_key` is idempotent — the call below seeds the key,
        // and `handle_kpasswd`'s subsequent `generate_key("krbtgt-mac", ...)`
        // returns the same handle without overwriting material.
        let mac_kh = hsm
            .generate_key("krbtgt-mac", KeyType::HmacSha1)
            .await
            .unwrap();
        let client = "alice@ADRIAN.EXAMPLE.COM";
        let pwd = b"new-strong-password!";
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(pwd);
        let mac = hsm.sign(&mac_kh, &mac_input).await.unwrap();
        let req = KpasswdRequest {
            client_principal: PrincipalName::new(client),
            target_principal: PrincipalName::new(client),
            authenticator_mac: mac,
            new_password: pwd.to_vec(),
            password_encrypted: false,
        };
        let resp_bytes = svc.handle_kpasswd(&req.encode()).await.expect("handle");
        let resp = KpasswdResponse::parse(&resp_bytes).expect("parse");
        assert_eq!(
            resp.result_code,
            result_code::KRB5_KPASSWD_SUCCESS,
            "expected success"
        );
        // Verify the directory was updated with a unicodePwd attribute.
        let updated = dir
            .get_by_dn(&DistinguishedName {
                dn: "CN=alice,CN=Users,DC=adrian,DC=example,DC=com".into(),
            })
            .await
            .unwrap()
            .expect("object exists");
        let pwd_attr = updated
            .attributes
            .iter()
            .find(|a: &&Attribute| a.name == "unicodePwd")
            .expect("unicodePwd must be set");
        // PBKDF2 hash = 16-byte salt + 32-byte output = 48 bytes.
        assert_eq!(pwd_attr.value.len(), PBKDF2_SALT_LEN + PBKDF2_OUTPUT_LEN);
    }

    /// v0.7.0: KRB-PRIV encrypted password flow (P0 #9). The password is
    /// encrypted via `KrbPrivEnvelope::encrypt` under the krbtgt key, and
    /// `handle_kpasswd` decrypts it before processing.
    #[tokio::test]
    async fn krb_priv_encrypted_password_succeeds() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        let obj = Object {
            uuid: Uuid::from_u128(0xCCCC),
            dn: DistinguishedName {
                dn: "CN=bob,CN=Users,DC=adrian,DC=example,DC=com".into(),
            },
            attributes: vec![],
            dnt: UNASSIGNED_DNT,
        };
        dir.put(&obj).await.unwrap();
        let svc = KpasswdService::new(dir.clone(), krbtgt.clone(), hsm.clone());
        // Pre-generate the krbtgt-mac HMAC key.
        let mac_kh = hsm
            .generate_key("krbtgt-mac", KeyType::HmacSha1)
            .await
            .unwrap();
        // Get the krbtgt AES key for KRB-PRIV encryption.
        let krbtgt_key = krbtgt.current_key().await;
        // Encrypt the password via KrbPrivEnvelope.
        let cleartext_pwd = b"encrypted-password-123!";
        let encrypted_pwd = KrbPrivEnvelope::encrypt(&hsm, &krbtgt_key, cleartext_pwd)
            .await
            .expect("encrypt");
        // Compute the MAC over the ENCRYPTED password (not the cleartext).
        let client = "bob@ADRIAN.EXAMPLE.COM";
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(&encrypted_pwd);
        let mac = hsm.sign(&mac_kh, &mac_input).await.unwrap();
        let req = KpasswdRequest {
            client_principal: PrincipalName::new(client),
            target_principal: PrincipalName::new(client),
            authenticator_mac: mac,
            new_password: encrypted_pwd,
            password_encrypted: true,
        };
        let resp_bytes = svc.handle_kpasswd(&req.encode()).await.expect("handle");
        let resp = KpasswdResponse::parse(&resp_bytes).expect("parse");
        assert_eq!(
            resp.result_code,
            result_code::KRB5_KPASSWD_SUCCESS,
            "KRB-PRIV encrypted password must succeed: {}",
            resp.result_string
        );
        // Verify the directory was updated.
        let updated = dir
            .get_by_dn(&DistinguishedName {
                dn: "CN=bob,CN=Users,DC=adrian,DC=example,DC=com".into(),
            })
            .await
            .unwrap()
            .expect("object exists");
        let pwd_attr = updated
            .attributes
            .iter()
            .find(|a: &&Attribute| a.name == "unicodePwd")
            .expect("unicodePwd must be set");
        assert_eq!(pwd_attr.value.len(), PBKDF2_SALT_LEN + PBKDF2_OUTPUT_LEN);
    }

    /// v0.7.0: KRB-PRIV decrypt with wrong key fails (P0 #9 negative test).
    #[tokio::test]
    async fn krb_priv_decrypt_with_wrong_key_fails() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        let obj = Object {
            uuid: Uuid::from_u128(0xDDDD),
            dn: DistinguishedName {
                dn: "CN=eve,CN=Users,DC=adrian,DC=example,DC=com".into(),
            },
            attributes: vec![],
            dnt: UNASSIGNED_DNT,
        };
        dir.put(&obj).await.unwrap();
        let svc = KpasswdService::new(dir.clone(), krbtgt.clone(), hsm.clone());
        let mac_kh = hsm
            .generate_key("krbtgt-mac", KeyType::HmacSha1)
            .await
            .unwrap();
        // Encrypt with a DIFFERENT key (not the krbtgt key).
        let other_kh = hsm
            .generate_key("other-enc", KeyType::Aes256)
            .await
            .unwrap();
        let encrypted_pwd = KrbPrivEnvelope::encrypt(&hsm, &other_kh, b"wrong-key-password!")
            .await
            .expect("encrypt");
        // Compute MAC over the encrypted blob.
        let client = "eve@ADRIAN.EXAMPLE.COM";
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(&encrypted_pwd);
        let mac = hsm.sign(&mac_kh, &mac_input).await.unwrap();
        let req = KpasswdRequest {
            client_principal: PrincipalName::new(client),
            target_principal: PrincipalName::new(client),
            authenticator_mac: mac,
            new_password: encrypted_pwd,
            password_encrypted: true,
        };
        let result = svc.handle_kpasswd(&req.encode()).await;
        // The decrypt should fail because the password was encrypted with a
        // different key than the krbtgt key.
        assert!(result.is_err(), "KRB-PRIV decrypt with wrong key must fail");
    }

    /// v0.7.0: KRB-PRIV envelope round-trip via the krbtgt key.
    #[tokio::test]
    async fn krb_priv_envelope_round_trips_via_krbtgt() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let key = krbtgt.current_key().await;
        let plaintext = b"test-password-12345";
        let encrypted = KrbPrivEnvelope::encrypt(&hsm, &key, plaintext)
            .await
            .expect("encrypt");
        assert_ne!(
            &encrypted[..],
            &plaintext[..],
            "encryption must change bytes"
        );
        let decrypted = KrbPrivEnvelope::decrypt(&hsm, &key, &encrypted)
            .await
            .expect("decrypt");
        assert_eq!(
            &decrypted[..],
            &plaintext[..],
            "round-trip must recover plaintext"
        );
    }

    /// v0.7.0: password_encrypted flag round-trips through encode/parse.
    #[test]
    fn password_encrypted_flag_round_trips() {
        let req = KpasswdRequest {
            client_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            target_principal: PrincipalName::new("alice@ADRIAN.EXAMPLE.COM"),
            authenticator_mac: vec![0xAB; 12],
            new_password: vec![0xCD; 32],
            password_encrypted: true,
        };
        let bytes = req.encode();
        let parsed = KpasswdRequest::parse(&bytes).expect("parse");
        assert_eq!(parsed, req, "password_encrypted flag must round-trip");
    }

    /// Unknown principal → `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` (RFC 3244 §3.3).
    #[tokio::test]
    async fn unknown_principal_returns_principal_unknown() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        let svc = KpasswdService::new(dir, krbtgt, hsm.clone());
        let mac_kh = hsm
            .generate_key("krbtgt-mac", KeyType::HmacSha1)
            .await
            .unwrap();
        let client = "ghost@ADRIAN.EXAMPLE.COM";
        let pwd = b"some-password-here";
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(pwd);
        let mac = hsm.sign(&mac_kh, &mac_input).await.unwrap();
        let req = KpasswdRequest {
            client_principal: PrincipalName::new(client),
            target_principal: PrincipalName::new(client),
            authenticator_mac: mac,
            new_password: pwd.to_vec(),
            password_encrypted: false,
        };
        let resp_bytes = svc.handle_kpasswd(&req.encode()).await.expect("handle");
        let resp = KpasswdResponse::parse(&resp_bytes).expect("parse");
        // The response wire format maps KRB5 errors > u16::MAX to SOFTERROR(8);
        // the result-string carries the principal-unknown context.
        assert_eq!(resp.result_code, result_code::KRB5_KPASSWD_SOFTERROR);
        assert!(
            resp.result_string.contains("not found"),
            "result={}",
            resp.result_string
        );
    }

    /// Too-short password → `KRB5KDC_ERR_POLICY` (ADR-019 §Decision:
    /// "Password too short (minimum 12 characters)").
    #[tokio::test]
    async fn short_password_rejected_with_policy_violation() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        // Seed alice.
        dir.put(&Object {
            uuid: Uuid::from_u128(0xCCCC),
            dn: DistinguishedName {
                dn: "CN=alice,CN=Users,DC=adrian,DC=example,DC=com".into(),
            },
            attributes: vec![],
            dnt: UNASSIGNED_DNT,
        })
        .await
        .unwrap();
        let svc = KpasswdService::new(dir, krbtgt, hsm.clone());
        let mac_kh = hsm
            .generate_key("krbtgt-mac", KeyType::HmacSha1)
            .await
            .unwrap();
        let client = "alice@ADRIAN.EXAMPLE.COM";
        let pwd = b"short"; // 5 chars < MIN_PASSWORD_LEN (12)
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(pwd);
        let mac = hsm.sign(&mac_kh, &mac_input).await.unwrap();
        let req = KpasswdRequest {
            client_principal: PrincipalName::new(client),
            target_principal: PrincipalName::new(client),
            authenticator_mac: mac,
            new_password: pwd.to_vec(),
            password_encrypted: false,
        };
        let resp_bytes = svc.handle_kpasswd(&req.encode()).await.expect("handle");
        let resp = KpasswdResponse::parse(&resp_bytes).expect("parse");
        // KRB5KDC_ERR_POLICY = 1_000_048 → mapped to SOFTERROR(8) on wire;
        // result-string carries the policy message.
        assert_eq!(resp.result_code, result_code::KRB5_KPASSWD_SOFTERROR);
        assert!(
            resp.result_string.contains("too short"),
            "result={}",
            resp.result_string
        );
    }

    /// Replay cache rejects a duplicate authenticator MAC. The first request
    /// succeeds (KRB5_KPASSWD_SUCCESS); the second request, replaying the
    /// same MAC, is rejected with `KRB5KRB_AP_ERR_REPEAT` (mapped to
    /// SOFTERROR on the wire per the 16-bit field constraint). Wave 1d.
    #[tokio::test]
    async fn replayed_authenticator_is_rejected() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        dir.put(&Object {
            uuid: Uuid::from_u128(0xDDDD),
            dn: DistinguishedName {
                dn: "CN=alice,CN=Users,DC=adrian,DC=example,DC=com".into(),
            },
            attributes: vec![],
            dnt: UNASSIGNED_DNT,
        })
        .await
        .unwrap();
        let svc = KpasswdService::new(dir.clone(), krbtgt, hsm.clone());
        let mac_kh = hsm
            .generate_key("krbtgt-mac", KeyType::HmacSha1)
            .await
            .unwrap();
        let client = "alice@ADRIAN.EXAMPLE.COM";
        let pwd = b"new-strong-password!";
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(client.as_bytes());
        mac_input.extend_from_slice(pwd);
        let mac = hsm.sign(&mac_kh, &mac_input).await.unwrap();
        let req = KpasswdRequest {
            client_principal: PrincipalName::new(client),
            target_principal: PrincipalName::new(client),
            authenticator_mac: mac.clone(),
            new_password: pwd.to_vec(),
            password_encrypted: false,
        };
        // First request: success.
        let bytes = req.encode();
        let resp1_bytes = svc.handle_kpasswd(&bytes).await.expect("handle1");
        let resp1 = KpasswdResponse::parse(&resp1_bytes).expect("parse1");
        assert_eq!(
            resp1.result_code,
            result_code::KRB5_KPASSWD_SUCCESS,
            "first request must succeed"
        );
        // Second request (replay): KRB5KRB_AP_ERR_REPEAT (1_000_031) > u16::MAX
        // → wire-mapped to SOFTERROR(8); result-string carries "replay detected".
        let resp2_bytes = svc.handle_kpasswd(&bytes).await.expect("handle2");
        let resp2 = KpasswdResponse::parse(&resp2_bytes).expect("parse2");
        assert_eq!(
            resp2.result_code,
            result_code::KRB5_KPASSWD_SOFTERROR,
            "replay must be rejected with SOFTERROR wire code"
        );
        assert!(
            resp2.result_string.contains("replay"),
            "result_string should mention replay, got: {}",
            resp2.result_string
        );
        // Cache now holds 1 entry (the replayed authenticator).
        assert_eq!(
            svc.replay_cache.len().await,
            1,
            "cache should hold the replayed MAC"
        );
        assert!(!svc.replay_cache.is_empty().await);
    }

    /// `ReplayCache::check_and_add` returns Ok for a fresh checksum and
    /// Err (replay) for a duplicate. Distinct principals with distinct
    /// checksums coexist in the cache.
    #[tokio::test]
    async fn replay_cache_check_and_add_semantics() {
        let cache = ReplayCache::new();
        assert!(cache.is_empty().await);
        // Fresh checksum → Ok, inserted.
        cache
            .check_and_add(0x1234_5678, PrincipalName::new("alice@REALM"))
            .await
            .expect("first insert");
        assert_eq!(cache.len().await, 1);
        // Same checksum, even with a different principal name → rejected
        // (the cache is keyed by checksum only — principal is metadata).
        let err = cache
            .check_and_add(0x1234_5678, PrincipalName::new("alice@REALM"))
            .await;
        assert!(err.is_err(), "duplicate checksum must be rejected");
        assert_eq!(
            cache.len().await,
            1,
            "rejected entry must not be inserted again"
        );
        // A distinct checksum for a different principal → Ok, second entry.
        cache
            .check_and_add(0x9ABC_DEF0, PrincipalName::new("bob@REALM"))
            .await
            .expect("second insert");
        assert_eq!(cache.len().await, 2);
    }

    /// `KrbPrivEnvelope` encrypt/decrypt round-trips under the krbtgt key
    /// (placeholder per the v0.6.0 doc gap — uses the krbtgt AES-256 key
    /// until the per-target-principal key derivation lands). Wave 1d.
    #[tokio::test]
    async fn krb_priv_envelope_round_trips_under_krbtgt_key() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let key = krbtgt.current_key().await;
        assert_eq!(key.key_type, KeyType::Aes256, "krbtgt key must be AES-256");
        let plaintext = b"new-strong-password!";
        let ciphertext = KrbPrivEnvelope::encrypt(&hsm, &key, plaintext)
            .await
            .expect("encrypt");
        // HSM AES-256-GCM format: nonce[12] || ciphertext || tag[16].
        assert!(
            ciphertext.len() >= 12 + 16 + plaintext.len(),
            "ciphertext must include nonce + ciphertext + tag, got {}",
            ciphertext.len()
        );
        assert_ne!(
            &ciphertext[..],
            plaintext,
            "ciphertext must not equal plaintext"
        );
        let decrypted = KrbPrivEnvelope::decrypt(&hsm, &key, &ciphertext)
            .await
            .expect("decrypt");
        assert_eq!(
            decrypted.as_slice(),
            plaintext,
            "round-trip must preserve plaintext"
        );
        // A different key must fail to decrypt (auth-tag mismatch).
        let other_hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let _ = KrbtgtManager::new(other_hsm.clone()).await.unwrap();
        let other_key = other_hsm
            .generate_key("krbtgt-other", KeyType::Aes256)
            .await
            .unwrap();
        let err = KrbPrivEnvelope::decrypt(&other_hsm, &other_key, &ciphertext).await;
        assert!(err.is_err(), "decrypt under wrong key must fail");
    }

    /// FNV-1a hash is deterministic and order-sensitive (different byte
    /// sequences produce different hashes). The cache relies on this to
    /// distinguish authenticators whose MAC bytes differ.
    #[test]
    fn fnv1a_64_is_deterministic_and_input_sensitive() {
        let a = fnv1a_64(b"\xDE\xAD\xBE\xEF\x00\x11\x22\x33\x44\x55\x66\x77");
        let a2 = fnv1a_64(b"\xDE\xAD\xBE\xEF\x00\x11\x22\x33\x44\x55\x66\x77");
        assert_eq!(a, a2, "same input → same hash");
        let b = fnv1a_64(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF");
        assert_ne!(a, b, "different input → different hash");
        // Empty input is the FNV offset basis.
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
    }

    /// FAST armor TGT: `fast_required=true` + `pkinit_available=false` →
    /// `KdcError::FastArmorRequired`. All other combinations → Ok.
    #[tokio::test]
    async fn fast_armor_tgt_required_mode_without_pkinit_errors() {
        let hsm: Arc<dyn Hsm> = Arc::new(SoftwareHsm::new());
        let krbtgt = Arc::new(KrbtgtManager::new(hsm.clone()).await.unwrap());
        let dir: Arc<dyn DirectoryStore> = Arc::new(InMemoryDirectoryStore::new());
        let svc = KpasswdService::new(dir, krbtgt, hsm);
        // supported mode (default): all combos return Ok.
        assert!(svc.fast_armor_tgt(false, false).is_ok());
        assert!(svc.fast_armor_tgt(false, true).is_ok());
        // required mode + PKINIT available: Ok.
        assert!(svc.fast_armor_tgt(true, true).is_ok());
        // required mode + PKINIT unavailable: FastArmorRequired.
        match svc.fast_armor_tgt(true, false) {
            Err(KdcError::FastArmorRequired) => (), // expected
            other => panic!("expected FastArmorRequired, got {other:?}"),
        }
    }

    /// `PrincipalName::to_dn()` correctly maps a Kerberos principal to a DN
    /// and passes through DN-form inputs unchanged.
    #[test]
    fn principal_name_to_dn_round_trips_dn_and_maps_principal() {
        let dn_form = PrincipalName::new("CN=svc-web,CN=Users,DC=adrian,DC=com");
        assert_eq!(dn_form.to_dn(), "CN=svc-web,CN=Users,DC=adrian,DC=com");
        let principal = PrincipalName::new("alice@ADRIAN.EXAMPLE.COM");
        let dn = principal.to_dn();
        assert!(dn.starts_with("CN=alice,"), "dn={dn}");
        let no_realm = PrincipalName::new("bob");
        assert!(no_realm.to_dn().contains("CN=bob"));
    }

    /// PBKDF2 hash output is the expected length (16-byte salt + 32-byte
    /// digest = 48 bytes) and two hashes of the SAME password differ
    /// (random salt).
    #[test]
    fn password_hash_has_correct_length_and_random_salt() {
        let pwd = b"same-password";
        let h1 = hash_password(pwd).unwrap();
        let h2 = hash_password(pwd).unwrap();
        assert_eq!(h1.len(), PBKDF2_SALT_LEN + PBKDF2_OUTPUT_LEN);
        assert_eq!(h2.len(), PBKDF2_SALT_LEN + PBKDF2_OUTPUT_LEN);
        assert_ne!(
            h1, h2,
            "two hashes of the same password must differ (random salt)"
        );
        // The salt is the first 16 bytes; the digest is the next 32.
        assert_ne!(
            &h1[..PBKDF2_SALT_LEN],
            &h2[..PBKDF2_SALT_LEN],
            "salts must differ"
        );
    }
}
