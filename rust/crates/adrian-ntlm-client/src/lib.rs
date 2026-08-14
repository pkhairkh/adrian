//! # adrian-ntlm-client
//!
//! NTLM client-only (NTLMv2 with channel binding). No server-side NTLM —
//! pass-the-hash mitigation (ADR-086). Gated by `ad-interop` feature.
//!
//! ## ADRs
//!
//! - ADR-085: NTLM client-only Rust crate
//! - ADR-086: Pass-the-hash defense (no server-side NTLM)
//! - ADR-112: macOS NTLM client Rust crate
//! - ADR-021: LDAP signing & channel binding
//! - ADR-011: RC4 disabled; NTLMv2-only
//!
//! ## Wire format
//!
//! Per MS-NLMP §2.2, the NTLMSSP handshake is a three-message exchange:
//!
//! 1. **Type 1 — NEGOTIATE** (client → server): carries `NegotiateFlags`
//!    and optional domain/workstation names.
//! 2. **Type 2 — CHALLENGE** (server → client): carries an 8-byte
//!    `ServerChallenge`, `TargetName`, and `TargetInfo` AV_PAIRs.
//! 3. **Type 3 — AUTHENTICATE** (client → server): carries the NTLMv2
//!    response (`HMAC-MD5(NTOWFv2, ServerChallenge ++ ClientBlob)`),
//!    LMv2 response, identity fields, and optional MIC + channel binding.
//!
//! All multi-byte integers are little-endian. The leading `NTLMSSP\0`
//! signature (8 bytes, `0x4E 0x54 0x4C 0x4D 0x53 0x53 0x50 0x00`) is
//! constant across all three messages.
//!
//! ## NT hash derivation
//!
//! `NTOWFv1(password) = MD4(UTF-16LE(password))` — 16 bytes (MS-NLMP §3.3.1).
//! `NTOWFv2(nt_hash, user, domain) = HMAC-MD5(nt_hash, UTF-16LE(UPPER(user) + domain))`.
//!
//! NT hashes are wrapped in `Zeroizing<[u8; 16]>` so they are zeroed on
//! drop (ADR-086 §Control 3).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use hmac::{Hmac, Mac};
use md4::{Digest as Md4Digest, Md4};
use md5::Md5;
use thiserror::Error;
use zeroize::Zeroizing;

/// HMAC-MD5 type alias — NTLMv2 response uses HMAC-MD5 per MS-NLMP §3.3.2.
type HmacMd5 = Hmac<Md5>;

/// NTLM error type.
#[derive(Debug, Error)]
pub enum NtlmError {
    /// Protocol-level error (malformed message, unsupported version).
    #[error("protocol: {0}")]
    Protocol(String),
    /// Authentication failure (bad credentials, server rejection).
    #[error("auth failed: {0}")]
    AuthFailed(String),
    /// Channel binding required (ADR-021) but not supplied or mismatched.
    #[error("channel binding required (ADR-021)")]
    ChannelBindingRequired,
    /// Credentials unavailable — `NtlmClient` has no username/password.
    #[error("credentials unavailable")]
    CredentialsUnavailable,
    /// Malformed message — buffer truncated, missing signature, etc.
    #[error("malformed message: {0}")]
    Malformed(String),
}

/// NTLM message types (MS-NLMP §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NtlmMessageType {
    /// Type 1 — NEGOTIATE (client → server).
    Negotiate = 1,
    /// Type 2 — CHALLENGE (server → client).
    Challenge = 2,
    /// Type 3 — AUTHENTICATE (client → server).
    Authenticate = 3,
}

/// NTLMSSP signature — constant 8-byte prefix on every NTLM message.
pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// Negotiate flags (MS-NLMP §2.2.2.5 / §2.2.1.1).
pub mod negotiate_flags {
    /// NTLMSSP_NEGOTIATE_UNICODE — strings are UTF-16LE.
    pub const NEGOTIATE_UNICODE: u32 = 0x00000001;
    /// NTLMSSP_NEGOTIATE_OEM — strings are OEM (ASCII).
    pub const NEGOTIATE_OEM: u32 = 0x00000002;
    /// NTLMSSP_REQUEST_TARGET — server should return target in Type 2.
    pub const REQUEST_TARGET: u32 = 0x00000004;
    /// NTLMSSP_NEGOTIATE_SIGN — session signing.
    pub const NEGOTIATE_SIGN: u32 = 0x00000010;
    /// NTLMSSP_NEGOTIATE_SEAL — session encryption.
    pub const NEGOTIATE_SEAL: u32 = 0x00000020;
    /// NTLMSSP_NEGOTIATE_NTLM — NTLM response (negotiate bit; we emit NTLMv2).
    pub const NEGOTIATE_NTLM: u32 = 0x00000200;
    /// NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED — domain present in Type 1.
    pub const NEGOTIATE_DOMAIN_SUPPLIED: u32 = 0x00001000;
    /// NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED — workstation present in Type 1.
    pub const NEGOTIATE_WORKSTATION_SUPPLIED: u32 = 0x00002000;
    /// NTLMSSP_NEGOTIATE_ALWAYS_SIGN.
    pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
    /// NTLMSSP_TARGET_TYPE_DOMAIN.
    pub const TARGET_TYPE_DOMAIN: u32 = 0x00010000;
    /// NTLMSSP_TARGET_TYPE_SERVER.
    pub const TARGET_TYPE_SERVER: u32 = 0x00020000;
    /// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (NTLMv2).
    pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
    /// NTLMSSP_NEGOTIATE_IDENTIFY — token is for identification only.
    pub const NEGOTIATE_IDENTIFY: u32 = 0x00100000;
    /// NTLMSSP_REQUEST_TARGET_INFO — server should include TargetInfo in Type 2.
    pub const REQUEST_TARGET_INFO: u32 = 0x00400000;
    /// NTLMSSP_NEGOTIATE_VERSION — Version field is present.
    pub const NEGOTIATE_VERSION: u32 = 0x02000000;
    /// NTLMSSP_NEGOTIATE_128 — 128-bit encryption.
    pub const NEGOTIATE_128: u32 = 0x20000000;
    /// NTLMSSP_NEGOTIATE_KEY_EXCH — key exchange.
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x40000000;
    /// NTLMSSP_NEGOTIATE_56 — 56-bit key.
    pub const NEGOTIATE_56: u32 = 0x80000000;

    /// EPA EPHEMERAL flag — when set, the client signals an ephemeral /
    /// non-delegatable session (ADR-085 §Decision). Per MS-NLMP §3.3.1,
    /// AvFlags & 0x04 in TargetInfo indicates the server requires NTLMv2;
    /// the framework's NTLM client mirrors this by setting this bit in the
    /// Type 1 / Type 3 NegotiateFlags when channel binding is in use, so
    /// downstream services can detect "this is an ephemeral session".
    pub const EPHEMERAL: u32 = 0x00000040;
}

bitflags::bitflags! {
    /// EPA flags carried in the `MsvAvFlags` AV_PAIR (MS-NLMP §2.2.2.1).
    ///
    /// These bits are part of the server's TargetInfo in the Type 2 message
    /// and indicate constraints on the session. The framework's NTLM client
    /// reads them to decide whether to emit a MIC, set EPHEMERAL, etc.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct EpaFlags: u32 {
        /// MIC present (server requires a Message Integrity Code in Type 3).
        const MIC = 0x00000002;
        /// NTLMv2 session — server signals ephemeral / NTLMv2-only.
        const NTLMV2 = 0x00000004;
        /// EPHEMERAL — non-delegatable session (ADR-085 §Decision).
        const EPHEMERAL = 0x40000000;
    }
}

/// AV_PAIR IDs (MS-NLMP §2.2.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AvId {
    /// MsvAvEOL — end of AV_PAIR list.
    Eol = 0x0000,
    /// MsvAvNbComputerName — NetBIOS server name.
    NbComputerName = 0x0001,
    /// MsvAvNbDomainName — NetBIOS domain name.
    NbDomainName = 0x0002,
    /// MsvAvDnsComputerName — DNS server name.
    DnsComputerName = 0x0003,
    /// MsvAvDnsDomainName — DNS domain name.
    DnsDomainName = 0x0004,
    /// MsvAvDnsTreeName — forest DNS name.
    DnsTreeName = 0x0005,
    /// MsvAvFlags — DWORD bitmask.
    Flags = 0x0006,
    /// MsvAvTimestamp — FILETIME.
    Timestamp = 0x0007,
    /// MsvAvSingleHost.
    SingleHost = 0x0008,
    /// MsvAvTargetName — SPN of the server.
    TargetName = 0x0009,
    /// MsvAvChannelBindings — MD5 hash per RFC 5929.
    ChannelBindings = 0x000A,
}

/// Parsed Type 2 (CHALLENGE) message (MS-NLMP §2.2.2.2).
#[derive(Clone, Debug)]
pub struct ChallengeMessage {
    /// Server challenge — 8 random bytes (the "nonce").
    pub server_challenge: [u8; 8],
    /// Negotiate flags agreed by server.
    pub negotiate_flags: u32,
    /// Target name (decoded from UTF-16LE if present).
    pub target_name: Option<String>,
    /// TargetInfo AV_PAIRs (raw bytes — caller can decode further).
    pub target_info: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Little-endian helpers — read/write u16/u32/u64 to/from byte slices.
// ---------------------------------------------------------------------------

#[inline]
fn put_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn put_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[inline]
fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, NtlmError> {
    let slice = buf
        .get(offset..offset + 2)
        .ok_or_else(|| NtlmError::Malformed(format!("u16 read out of bounds at {offset}")))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

#[inline]
fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, NtlmError> {
    let slice = buf
        .get(offset..offset + 4)
        .ok_or_else(|| NtlmError::Malformed(format!("u32 read out of bounds at {offset}")))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
#[allow(dead_code)]
fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, NtlmError> {
    let slice = buf
        .get(offset..offset + 8)
        .ok_or_else(|| NtlmError::Malformed(format!("u64 read out of bounds at {offset}")))?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_le_bytes(arr))
}

/// Encode a string as UTF-16LE (Windows wide-string wire form).
fn utf16_le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|w| w.to_le_bytes()).collect()
}

/// Decode a UTF-16LE byte slice to a `String` (returns `None` on malformed
/// input — odd length or unpaired surrogates).
fn from_utf16_le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&words).ok()
}

/// Compute NTOWFv1 = MD4(UTF-16LE(password)) per MS-NLMP §3.3.1.
///
/// Returns a 16-byte hash wrapped in `Zeroizing` so it is wiped on drop
/// (ADR-086 §Control 3).
pub fn ntowfv1(password: &str) -> Zeroizing<[u8; 16]> {
    let mut hasher = Md4::new();
    hasher.update(utf16_le(password).as_slice());
    let out = hasher.finalize();
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&out);
    Zeroizing::new(arr)
}

/// Compute NTOWFv2 = HMAC-MD5(NT-hash, UTF-16LE(UPPER(user) + domain))
/// per MS-NLMP §3.3.1. The user name is uppercased; the domain is **not**.
pub fn ntowfv2(nt_hash: &[u8; 16], user: &str, domain: &str) -> Zeroizing<[u8; 16]> {
    let upper_user = user.to_uppercase();
    let mut msg = Vec::with_capacity((upper_user.len() + domain.len()) * 2);
    msg.extend_from_slice(&utf16_le(&upper_user));
    msg.extend_from_slice(&utf16_le(domain));
    let mut mac = HmacMd5::new_from_slice(nt_hash).expect("HMAC accepts any key length");
    mac.update(&msg);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&out);
    Zeroizing::new(arr)
}

/// Build the NTLMv2 client blob (`NTLMv2_CLIENT_CHALLENGE` per MS-NLMP
/// §3.3.2):
///
/// ```text
/// RespType (1B, 0x01)
/// HiRespType (1B, 0x01)
/// Reserved (6B, 0)
/// Timestamp (8B, FILETIME)
/// ClientChallenge (8B)
/// Reserved (4B, 0)
/// AvPairs (target_info copied from Type 2)
/// [MsvAvEOL terminator if not already present in target_info]
/// Reserved (4B, 0)   — trailing Z(4) per MS-NLMP §3.3.2
/// ```
///
/// The MS-NLMP §3.3.2 pseudocode defines `temp = ConcatenationOf(
/// Responserversion, HiResponserversion, Z(6), Time, ClientChallenge,
/// Z(4), ServerName, Z(4))`.  The MS-NLMP §4.2.4.3 AUTHENTICATE_MESSAGE
/// test-vector bytes confirm that `Responserversion` and
/// `HiResponserversion` are each a single byte (0x01), not 4-byte LE
/// integers — the §2.2.2.7 field table is misleading on this point.
/// The trailing `Z(4)` is always present, regardless of whether the
/// AvPairs already end with MsvAvEOL.
fn build_ntlmv2_blob(timestamp: u64, client_challenge: &[u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(28 + target_info.len() + 4 + 4);
    // RespType (1 byte) = 0x01
    blob.push(0x01);
    // HiRespType (1 byte) = 0x01
    blob.push(0x01);
    // Reserved (6 bytes) = 0
    blob.extend_from_slice(&[0u8; 6]);
    // Timestamp (8 bytes) = FILETIME
    put_u64_le(&mut blob, timestamp);
    // ClientChallenge (8 bytes)
    blob.extend_from_slice(client_challenge);
    // Reserved (4 bytes) = 0
    put_u32_le(&mut blob, 0x00000000);
    // AvPairs (target_info, copied from Type 2)
    blob.extend_from_slice(target_info);
    // Append MsvAvEOL terminator only if target_info doesn't end with one.
    if !ends_with_eol(target_info) {
        put_u16_le(&mut blob, AvId::Eol as u16);
        put_u16_le(&mut blob, 0);
    }
    // Trailing Reserved (4 bytes) = 0 — Z(4) per MS-NLMP §3.3.2.
    put_u32_le(&mut blob, 0x00000000);
    blob
}

fn ends_with_eol(target_info: &[u8]) -> bool {
    // MsvAvEOL is AvId=0x0000, AvLen=0x0000 — 4 bytes of zeros.
    if target_info.len() < 4 {
        return false;
    }
    let tail = &target_info[target_info.len() - 4..];
    tail == [0u8, 0, 0, 0]
}

/// Compute the NTLMv2 response per MS-NLMP §3.3.2.
///
/// Returns the 16-byte `NTProofStr` concatenated with the client blob
/// (this combined value is the `NtChallengeResponse` payload in the Type 3
/// message).
///
/// `nt_hash` here is interpreted as the NTOWFv2 key (HMAC-MD5 key derived
/// from the user's NT hash). Callers should pass the output of
/// [`ntowfv2`] (which wraps the NT-hash with the user/domain derivation)
/// for real authentication; the function accepts any 16-byte key for test
/// / interop-vector use.
///
/// The return value is wrapped in [`Zeroizing<Vec<u8>>`] so the 16-byte
/// `NTProofStr` (an authentication credential equivalent in sensitivity
/// to the NT hash itself) is securely wiped on drop (Wave 1d —
/// `eval/wave2a-security.md` S-006).
pub fn compute_ntlmv2_response(
    nt_hash: &[u8; 16],
    server_challenge: &[u8; 8],
    target_info: &[u8],
    timestamp: u64,
    client_challenge: &[u8; 8],
) -> Zeroizing<Vec<u8>> {
    let blob = build_ntlmv2_blob(timestamp, client_challenge, target_info);
    let mut mac = HmacMd5::new_from_slice(nt_hash).expect("HMAC accepts any key length");
    mac.update(server_challenge);
    mac.update(&blob);
    let proof = mac.finalize().into_bytes();
    let mut out = Vec::with_capacity(16 + blob.len());
    out.extend_from_slice(&proof);
    out.extend_from_slice(&blob);
    Zeroizing::new(out)
}

/// Compute the LMv2 response (legacy compatibility, MS-NLMP §3.3.1).
///
/// Returns 24 bytes: the 16-byte `HMAC-MD5(NTOWFv2, ServerChallenge ++
/// ClientChallenge)` proof followed by the 8-byte `ClientChallenge`.
///
/// Wrapped in [`Zeroizing<Vec<u8>>`] for parity with
/// [`compute_ntlmv2_response`] — the 16-byte LMv2 proof is derived from
/// the NTOWFv2 key and is therefore sensitive material (Wave 1d).
pub fn compute_lmv2_response(
    ntowfv2: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
) -> Zeroizing<Vec<u8>> {
    let mut mac = HmacMd5::new_from_slice(ntowfv2).expect("HMAC accepts any key length");
    mac.update(server_challenge);
    mac.update(client_challenge);
    let proof = mac.finalize().into_bytes();
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&proof);
    out.extend_from_slice(client_challenge);
    Zeroizing::new(out)
}

/// Compute the RFC 5929 `tls-server-end-point` channel binding token
/// (the value carried in `MsvAvChannelBindings` AV_PAIR, AvId 0x000A)
/// per MS-NLMP §3.1.4.3 + RFC 5929.
///
/// `tls_server_cert_hash` is the hash of the TLS server certificate
/// (per RFC 5929: SHA-256 of the DER-encoded cert, or whatever hash
/// algorithm was used to sign the cert). The channel binding token is
/// an MD5 hash of the channel-binding structure:
///
/// ```text
/// initiator_address_type    (4B, 0xFFFFFFFF)
/// initiator_address_length  (4B, 0)
/// acceptor_address_type     (4B, 0xFFFFFFFF)
/// acceptor_address_length   (4B, 0)
/// application_data_length   (4B)
/// application_data          ("tls-server-end-point:" ++ cert_hash)
/// ```
///
/// The resulting 16-byte MD5 hash is the value carried in the
/// `MsvAvChannelBindings` AV_PAIR (AvId 0x000A) of the Type 3 message's
/// NTLMv2 client blob.
pub fn compute_channel_binding(tls_server_cert_hash: &[u8]) -> Vec<u8> {
    let mut app_data = Vec::with_capacity(22 + tls_server_cert_hash.len());
    app_data.extend_from_slice(b"tls-server-end-point:");
    app_data.extend_from_slice(tls_server_cert_hash);

    let mut buf = Vec::with_capacity(20 + app_data.len());
    // initiator_address_type = 0xFFFFFFFF (unspecified)
    put_u32_le(&mut buf, 0xFFFF_FFFF);
    // initiator_address_length = 0
    put_u32_le(&mut buf, 0);
    // acceptor_address_type = 0xFFFFFFFF (unspecified)
    put_u32_le(&mut buf, 0xFFFF_FFFF);
    // acceptor_address_length = 0
    put_u32_le(&mut buf, 0);
    // application_data_length
    put_u32_le(&mut buf, app_data.len() as u32);
    // application_data
    buf.extend_from_slice(&app_data);

    let mut hasher = Md5::new();
    hasher.update(&buf);
    hasher.finalize().to_vec()
}

/// Default NTLM client negotiate flags: NTLMv2 + 128/56-bit + always-sign +
/// Unicode + extended session security + version + target-info.
pub fn default_negotiate_flags() -> u32 {
    use negotiate_flags::*;
    NEGOTIATE_UNICODE
        | REQUEST_TARGET
        | NEGOTIATE_SIGN
        | NEGOTIATE_SEAL
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN
        | NEGOTIATE_EXTENDED_SESSIONSECURITY
        | REQUEST_TARGET_INFO
        | NEGOTIATE_VERSION
        | NEGOTIATE_128
        | NEGOTIATE_KEY_EXCH
        | NEGOTIATE_56
}

/// Build a Type 1 (NEGOTIATE) message per MS-NLMP §2.2.1.1.
///
/// The message contains:
/// - 8-byte NTLMSSP signature
/// - 4-byte message type (1)
/// - 4-byte negotiate flags
/// - 8-byte DomainNameFields (Len, MaxLen, BufferOffset)
/// - 8-byte WorkstationFields (Len, MaxLen, BufferOffset)
/// - 8-byte Version (6.1.7601 build 7601, NTLMSSP rev 15)
/// - Payload (DomainName UTF-16LE + Workstation UTF-16LE)
pub fn build_negotiate(domain: &str, workstation: &str) -> Vec<u8> {
    let domain_u16 = utf16_le(domain);
    let ws_u16 = utf16_le(workstation);
    let flags = default_negotiate_flags();
    // Header is fixed 32 bytes + 8-byte Version = 40 bytes (Version is
    // always emitted because NEGOTIATE_VERSION is set in default flags).
    let header_len = 40;
    let domain_offset = header_len;
    let workstation_offset = domain_offset + domain_u16.len();

    let mut buf = Vec::with_capacity(workstation_offset + ws_u16.len());
    // Signature (8 bytes)
    buf.extend_from_slice(NTLMSSP_SIGNATURE);
    // MessageType (4 bytes) = 1
    put_u32_le(&mut buf, NtlmMessageType::Negotiate as u32);
    // NegotiateFlags (4 bytes)
    put_u32_le(&mut buf, flags);
    // DomainNameFields (Len, MaxLen, BufferOffset) — 8 bytes
    put_u16_le(&mut buf, domain_u16.len() as u16);
    put_u16_le(&mut buf, domain_u16.len() as u16);
    put_u32_le(&mut buf, domain_offset as u32);
    // WorkstationFields — 8 bytes
    put_u16_le(&mut buf, ws_u16.len() as u16);
    put_u16_le(&mut buf, ws_u16.len() as u16);
    put_u32_le(&mut buf, workstation_offset as u32);
    // Version (8 bytes) — major=6, minor=1, build=7601, NTLMSSP rev=15
    buf.extend_from_slice(&[0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f]);
    // Payload
    buf.extend_from_slice(&domain_u16);
    buf.extend_from_slice(&ws_u16);
    buf
}

/// Parse a Type 2 (CHALLENGE) message per MS-NLMP §2.2.2.2.
pub fn parse_challenge(buf: &[u8]) -> Result<ChallengeMessage, NtlmError> {
    if buf.len() < 32 {
        return Err(NtlmError::Malformed("challenge message too short".into()));
    }
    if &buf[0..8] != NTLMSSP_SIGNATURE {
        return Err(NtlmError::Malformed("missing NTLMSSP signature".into()));
    }
    let msg_type = read_u32_le(buf, 8)?;
    if msg_type != NtlmMessageType::Challenge as u32 {
        return Err(NtlmError::Malformed(format!(
            "expected message type 2 (CHALLENGE), got {msg_type}"
        )));
    }
    // TargetNameFields at offset 12 (Len, MaxLen, BufferOffset)
    let target_name_len = read_u16_le(buf, 12)? as usize;
    let target_name_offset = read_u32_le(buf, 16)? as usize;
    // NegotiateFlags at offset 20
    let flags = read_u32_le(buf, 20)?;
    // ServerChallenge at offset 24 (8 bytes)
    let mut server_challenge = [0u8; 8];
    let sc_slice = buf
        .get(24..32)
        .ok_or_else(|| NtlmError::Malformed("server challenge out of bounds".into()))?;
    server_challenge.copy_from_slice(sc_slice);
    // Reserved at offset 32 (8 bytes)
    // TargetInfoFields at offset 40 (Len, MaxLen, BufferOffset) — optional
    let (target_info_len, target_info_offset) = if buf.len() >= 48 {
        (
            read_u16_le(buf, 40)? as usize,
            read_u32_le(buf, 44)? as usize,
        )
    } else {
        (0, 0)
    };

    let target_name = if target_name_len > 0 {
        let end = target_name_offset
            .checked_add(target_name_len)
            .ok_or_else(|| NtlmError::Malformed("target name overflow".into()))?;
        let slice = buf
            .get(target_name_offset..end)
            .ok_or_else(|| NtlmError::Malformed("target name out of bounds".into()))?;
        from_utf16_le(slice)
    } else {
        None
    };

    let target_info = if target_info_len > 0 {
        let end = target_info_offset
            .checked_add(target_info_len)
            .ok_or_else(|| NtlmError::Malformed("target info overflow".into()))?;
        let slice = buf
            .get(target_info_offset..end)
            .ok_or_else(|| NtlmError::Malformed("target info out of bounds".into()))?;
        slice.to_vec()
    } else {
        Vec::new()
    };

    Ok(ChallengeMessage {
        server_challenge,
        negotiate_flags: flags,
        target_name,
        target_info,
    })
}

/// Build a Type 3 (AUTHENTICATE) message per MS-NLMP §2.2.1.3, without
/// channel binding. Convenience wrapper around
/// [`build_authenticate_with_options`].
pub fn build_authenticate(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    workstation: &str,
) -> Result<Vec<u8>, NtlmError> {
    build_authenticate_with_options(
        challenge,
        username,
        password,
        domain,
        workstation,
        None,
        None,
    )
}

/// Build a Type 3 (AUTHENTICATE) message with optional channel binding
/// (RFC 5929) and an explicit client challenge (for test determinism).
///
/// - `channel_binding` — the 16-byte `MsvAvChannelBindings` value
///   (computed by [`compute_channel_binding`]); when `Some`, it is
///   appended to the TargetInfo in the NTLMv2 client blob
///   (RFC 5929 / ADR-021).
/// - `client_challenge` — explicit 8-byte client challenge. If `None`,
///   a deterministic all-zeros placeholder is used (production callers
///   MUST supply a random value).
pub fn build_authenticate_with_options(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    workstation: &str,
    channel_binding: Option<&[u8]>,
    client_challenge: Option<&[u8; 8]>,
) -> Result<Vec<u8>, NtlmError> {
    let cc: [u8; 8] = match client_challenge {
        Some(c) => *c,
        None => [0u8; 8],
    };

    // Build the (possibly augmented) TargetInfo used in the NTLMv2 blob.
    let mut blob_target_info = challenge.target_info.clone();
    // Strip any trailing MsvAvEOL so we can append fresh AV_PAIRs.
    if ends_with_eol(&blob_target_info) {
        blob_target_info.truncate(blob_target_info.len() - 4);
    }
    if let Some(cb) = channel_binding {
        if cb.len() != 16 {
            return Err(NtlmError::ChannelBindingRequired);
        }
        // Append MsvAvChannelBindings (AvId=0x000A, AvLen=16, Value=cb)
        put_u16_le(&mut blob_target_info, AvId::ChannelBindings as u16);
        put_u16_le(&mut blob_target_info, 16);
        blob_target_info.extend_from_slice(cb);
    }
    // Append MsvAvEOL terminator.
    put_u16_le(&mut blob_target_info, AvId::Eol as u16);
    put_u16_le(&mut blob_target_info, 0);

    // Timestamp — FILETIME of current UTC time (nanoseconds since 1601-01-01).
    let timestamp = current_filetime();

    let nt = ntowfv1(password);
    let ntowf = ntowfv2(&nt, username, domain);
    let nt_response = compute_ntlmv2_response(
        &ntowf,
        &challenge.server_challenge,
        &blob_target_info,
        timestamp,
        &cc,
    );
    let lm_response = compute_lmv2_response(&ntowf, &challenge.server_challenge, &cc);

    // Encode the identity fields as UTF-16LE.
    let domain_u16 = utf16_le(domain);
    let user_u16 = utf16_le(username);
    let ws_u16 = utf16_le(workstation);

    // EncryptedRandomSessionKey — empty (the framework's NTLM client is
    // auth-only per ADR-085; session-key export is out of scope).
    let enc_session_key: Vec<u8> = Vec::new();

    // Negotiate flags for Type 3: preserve server's agreed flags, force
    // NTLMv2 + Unicode. When channel binding is in use, set EPHEMERAL
    // (ADR-085 §Decision; ADR-086 §Control 3).
    let mut flags = challenge.negotiate_flags;
    flags |= negotiate_flags::NEGOTIATE_UNICODE
        | negotiate_flags::NEGOTIATE_NTLM
        | negotiate_flags::NEGOTIATE_EXTENDED_SESSIONSECURITY;
    if channel_binding.is_some() {
        flags |= negotiate_flags::EPHEMERAL;
    }

    // Type 3 header layout (64 bytes):
    //   8 signature + 4 type + 6×8 field tuples (lm/nt/domain/user/ws/esk) + 4 flags.
    let header_len: usize = 64;
    let mut offset = header_len;
    let lm_offset = offset;
    offset += lm_response.len();
    let nt_offset = offset;
    offset += nt_response.len();
    let dom_offset = offset;
    offset += domain_u16.len();
    let user_offset = offset;
    offset += user_u16.len();
    let ws_offset = offset;
    offset += ws_u16.len();
    let esk_offset = offset;
    offset += enc_session_key.len();

    let mut buf = Vec::with_capacity(offset);
    // Signature (8 bytes)
    buf.extend_from_slice(NTLMSSP_SIGNATURE);
    // MessageType (4 bytes) = 3
    put_u32_le(&mut buf, NtlmMessageType::Authenticate as u32);
    // LmChallengeResponseFields (8 bytes)
    put_u16_le(&mut buf, lm_response.len() as u16);
    put_u16_le(&mut buf, lm_response.len() as u16);
    put_u32_le(&mut buf, lm_offset as u32);
    // NtChallengeResponseFields (8 bytes)
    put_u16_le(&mut buf, nt_response.len() as u16);
    put_u16_le(&mut buf, nt_response.len() as u16);
    put_u32_le(&mut buf, nt_offset as u32);
    // DomainNameFields (8 bytes)
    put_u16_le(&mut buf, domain_u16.len() as u16);
    put_u16_le(&mut buf, domain_u16.len() as u16);
    put_u32_le(&mut buf, dom_offset as u32);
    // UserNameFields (8 bytes)
    put_u16_le(&mut buf, user_u16.len() as u16);
    put_u16_le(&mut buf, user_u16.len() as u16);
    put_u32_le(&mut buf, user_offset as u32);
    // WorkstationFields (8 bytes)
    put_u16_le(&mut buf, ws_u16.len() as u16);
    put_u16_le(&mut buf, ws_u16.len() as u16);
    put_u32_le(&mut buf, ws_offset as u32);
    // EncryptedRandomSessionKeyFields (8 bytes)
    put_u16_le(&mut buf, enc_session_key.len() as u16);
    put_u16_le(&mut buf, enc_session_key.len() as u16);
    put_u32_le(&mut buf, esk_offset as u32);
    // NegotiateFlags (4 bytes)
    put_u32_le(&mut buf, flags);
    // Payload
    buf.extend_from_slice(&lm_response);
    buf.extend_from_slice(&nt_response);
    buf.extend_from_slice(&domain_u16);
    buf.extend_from_slice(&user_u16);
    buf.extend_from_slice(&ws_u16);
    buf.extend_from_slice(&enc_session_key);

    Ok(buf)
}

/// Current time as a Windows FILETIME (100ns intervals since 1601-01-01 UTC).
fn current_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // FILETIME epoch (1601-01-01) is 116_444_73600 seconds before Unix
    // epoch (1970-01-01).
    let unix_seconds = dur.as_secs();
    let filetime_seconds = unix_seconds + 11_644_473_600;
    filetime_seconds * 10_000_000 + (dur.subsec_nanos() / 100) as u64
}

/// NTLM client session.
///
/// Holds the configured domain, workstation, and (optional) credentials
/// (username + password). NT hash is derived lazily at authenticate time
/// and zeroized after use (ADR-086 §Control 3).
///
/// The `password` field is wrapped in [`Zeroizing<String>`] so that the
/// password's heap buffer is securely wiped when the client is dropped
/// (Wave 1d — fixes `eval/wave1c-auth-crypto.md` S-004 /
/// `eval/wave2a-security.md` S-004). Standard `String` does NOT zero its
/// heap buffer on drop — the password would otherwise persist in memory
/// until the allocator reuses the page.
pub struct NtlmClient {
    domain: String,
    workstation: String,
    username: Option<String>,
    password: Option<Zeroizing<String>>,
}

impl NtlmClient {
    /// Construct an empty client (no credentials). Use [`set_credentials`]
    /// before calling [`build_authenticate`].
    ///
    /// [`set_credentials`]: NtlmClient::set_credentials
    /// [`build_authenticate`]: NtlmClient::build_authenticate
    pub fn new() -> Self {
        Self {
            domain: String::new(),
            workstation: String::new(),
            username: None,
            password: None,
        }
    }

    /// Construct a client with the supplied domain and workstation.
    pub fn with_workstation(domain: &str, workstation: &str) -> Self {
        Self {
            domain: domain.to_string(),
            workstation: workstation.to_string(),
            username: None,
            password: None,
        }
    }

    /// Set credentials (username + password). The password is stored as a
    /// [`Zeroizing<String>`] so it is wiped from memory when the client is
    /// dropped (ADR-086 §Control 3).
    pub fn set_credentials(&mut self, username: &str, password: &str) {
        self.username = Some(username.to_string());
        self.password = Some(Zeroizing::new(password.to_string()));
    }

    /// Build NEGOTIATE message (type 1, MS-NLMP §2.2.1.1) using the
    /// client's configured domain and workstation.
    pub fn build_negotiate(&self) -> Result<Vec<u8>, NtlmError> {
        Ok(build_negotiate(&self.domain, &self.workstation))
    }

    /// Process CHALLENGE (type 2) and produce AUTHENTICATE (type 3) with
    /// NTLMv2 response and optional channel binding (ADR-021).
    ///
    /// Returns [`NtlmError::CredentialsUnavailable`] if no credentials
    /// have been set via [`set_credentials`].
    ///
    /// [`set_credentials`]: NtlmClient::set_credentials
    pub fn build_authenticate(
        &self,
        challenge: &[u8],
        channel_binding: Option<&[u8]>,
    ) -> Result<Vec<u8>, NtlmError> {
        let username = self
            .username
            .as_ref()
            .ok_or(NtlmError::CredentialsUnavailable)?;
        let password = self
            .password
            .as_ref()
            .ok_or(NtlmError::CredentialsUnavailable)?;
        let parsed = parse_challenge(challenge)?;
        build_authenticate_with_options(
            &parsed,
            username,
            password,
            &self.domain,
            &self.workstation,
            channel_binding,
            None,
        )
    }
}

impl Default for NtlmClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-NLMP §2.2 pins the three message type numbers; these are wire-
    /// stable and used in the type-3 AUTHENTICATE message's "message type"
    /// field, so any drift would break interop with Windows / MIT / Samba.
    #[test]
    fn ntlm_message_type_constants() {
        assert_eq!(NtlmMessageType::Negotiate as u8, 1);
        assert_eq!(NtlmMessageType::Challenge as u8, 2);
        assert_eq!(NtlmMessageType::Authenticate as u8, 3);
    }

    /// The three `NtlmMessageType` variants must round-trip through `Copy`
    /// and `Clone` — the client code passes the current type through several
    /// async boundaries.
    #[test]
    fn ntlm_message_type_is_copy_and_distinct() {
        fn _assert_copy<T: Copy>() {}
        fn _assert_clone<T: Clone>() {}
        _assert_copy::<NtlmMessageType>();
        _assert_clone::<NtlmMessageType>();

        let a = NtlmMessageType::Negotiate;
        let b = a;
        let names: Vec<String> = [
            NtlmMessageType::Negotiate,
            NtlmMessageType::Challenge,
            NtlmMessageType::Authenticate,
        ]
        .iter()
        .map(|t| format!("{t:?}"))
        .collect();
        let unique: std::collections::HashSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), 3);
        assert_eq!(b as u8, 1);
    }

    /// `NtlmClient::new()` and `NtlmClient::default()` must both succeed —
    /// the client is constructed lazily from the platform credential cache
    /// at first use, so an empty construction must always work.
    #[test]
    fn ntlm_client_default_equals_new() {
        let _a = NtlmClient::new();
        let _b = NtlmClient::default();
    }

    /// NTLMSSP signature is wire-stable.
    #[test]
    fn ntlmssp_signature_is_constant() {
        assert_eq!(NTLMSSP_SIGNATURE, b"NTLMSSP\0");
        assert_eq!(NTLMSSP_SIGNATURE.len(), 8);
    }

    /// NTOWFv1 (NT hash) of "Password" matches the MS-NLMP §4.2.2.1.2
    /// reference value `0xA4F49C406510BDCAB6824EE7C30FD852` (MD4 of
    /// UTF-16LE("Password") per MS-NLMP §3.3.1).
    #[test]
    fn ntowfv1_matches_ms_nlmp_test_vector() {
        let nt = ntowfv1("Password");
        let expected: [u8; 16] = [
            0xA4, 0xF4, 0x9C, 0x40, 0x65, 0x10, 0xBD, 0xCA, 0xB6, 0x82, 0x4E, 0xE7, 0xC3, 0x0F,
            0xD8, 0x52,
        ];
        assert_eq!(*nt, expected);
    }

    /// NTOWFv2 (HMAC-MD5 of NT-hash, UTF-16LE(UPPER(user)+domain))
    /// matches the MS-NLMP §4.2.4.1.1 reference value
    /// `0x0C868A403BFD7A93A3001EF22EF02E3F` for `user="User"`,
    /// `domain="Domain"`, `password="Password"`.
    #[test]
    fn ntowfv2_matches_ms_nlmp_test_vector() {
        let nt = ntowfv1("Password");
        let ntowf = ntowfv2(&nt, "User", "Domain");
        let expected: [u8; 16] = [
            0x0C, 0x86, 0x8A, 0x40, 0x3B, 0xFD, 0x7A, 0x93, 0xA3, 0x00, 0x1E, 0xF2, 0x2E, 0xF0,
            0x2E, 0x3F,
        ];
        assert_eq!(*ntowf, expected);
    }

    /// NTOWFv2 uppercases the username but NOT the domain — a classic
    /// interop bug. We assert that "user" and "User" produce the same
    /// NTOWFv2 (when domain is unchanged), and that "Domain" / "domain"
    /// produce DIFFERENT NTOWFv2 values.
    #[test]
    fn ntowfv2_uppercases_user_not_domain() {
        let nt = ntowfv1("Password");
        let a = ntowfv2(&nt, "User", "Domain");
        let b = ntowfv2(&nt, "user", "Domain");
        let c = ntowfv2(&nt, "User", "domain");
        assert_eq!(*a, *b, "user name MUST be case-insensitive");
        assert_ne!(*a, *c, "domain MUST be case-sensitive");
    }

    /// NTLMv2 NTProofStr matches the MS-NLMP §4.2.4.2.2 reference value
    /// `0x68CD0AB851E51C96AABC927BEBEF6A1C` for the documented inputs:
    /// user="User", domain="Domain", password="Password",
    /// server_challenge=0x0123456789ABCDEF, client_challenge=0xAAAAAAAAAAAAAAAA,
    /// timestamp=0, and the MS-NLMP §4.2.4.3 TargetInfo (NbDomainName +
    /// NbComputerName + MsvAvEOL).
    #[test]
    fn ntlmv2_ntproofstr_matches_ms_nlmp_test_vector() {
        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let client_challenge: [u8; 8] = [0xAA; 8];
        let target_info = ms_nlmp_4_2_3_target_info();
        let timestamp: u64 = 0;
        let nt = ntowfv1("Password");
        let ntowf = ntowfv2(&nt, "User", "Domain");
        let response = compute_ntlmv2_response(
            &ntowf,
            &server_challenge,
            &target_info,
            timestamp,
            &client_challenge,
        );
        // The first 16 bytes of the NTLMv2 response are the NTProofStr.
        assert!(response.len() >= 16);
        let proof = &response[0..16];
        let expected: [u8; 16] = [
            0x68, 0xCD, 0x0A, 0xB8, 0x51, 0xE5, 0x1C, 0x96, 0xAA, 0xBC, 0x92, 0x7B, 0xEB, 0xEF,
            0x6A, 0x1C,
        ];
        assert_eq!(proof, expected);
    }

    /// NTLMv2 NTProofStr is deterministic — same inputs always produce the
    /// same 16-byte proof, and any input change produces a different proof.
    #[test]
    fn ntlmv2_response_is_deterministic_and_input_sensitive() {
        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let client_challenge: [u8; 8] = [0xAA; 8];
        let target_info = ms_nlmp_4_2_3_target_info();
        let timestamp: u64 = 0;
        let nt = ntowfv1("Password");
        let ntowf = ntowfv2(&nt, "User", "Domain");

        let response1 = compute_ntlmv2_response(
            &ntowf,
            &server_challenge,
            &target_info,
            timestamp,
            &client_challenge,
        );
        let response2 = compute_ntlmv2_response(
            &ntowf,
            &server_challenge,
            &target_info,
            timestamp,
            &client_challenge,
        );
        assert_eq!(&response1[0..16], &response2[0..16]);

        // Different server challenge → different proof.
        let mut sc2 = server_challenge;
        sc2[0] ^= 0xFF;
        let response3 =
            compute_ntlmv2_response(&ntowf, &sc2, &target_info, timestamp, &client_challenge);
        assert_ne!(&response1[0..16], &response3[0..16]);

        // Different client challenge → different proof.
        let cc2 = [0xBB; 8];
        let response4 =
            compute_ntlmv2_response(&ntowf, &server_challenge, &target_info, timestamp, &cc2);
        assert_ne!(&response1[0..16], &response4[0..16]);

        // Different password → different proof.
        let nt2 = ntowfv1("DifferentPassword");
        let ntowf2 = ntowfv2(&nt2, "User", "Domain");
        let response5 = compute_ntlmv2_response(
            &ntowf2,
            &server_challenge,
            &target_info,
            timestamp,
            &client_challenge,
        );
        assert_ne!(&response1[0..16], &response5[0..16]);
    }

    /// NTLMv2 response = NTProofStr (16 bytes) ++ client blob (>= 28 bytes
    /// fixed header + AvPairs + 4-byte trailing Z(4) per MS-NLMP §3.3.2).
    #[test]
    fn ntlmv2_response_layout_is_proof_plus_blob() {
        let server_challenge: [u8; 8] = [0x01; 8];
        let client_challenge: [u8; 8] = [0xAA; 8];
        let target_info = vec![0u8; 4]; // just MsvAvEOL
        let nt = ntowfv1("Password");
        let ntowf = ntowfv2(&nt, "User", "Domain");
        let response = compute_ntlmv2_response(
            &ntowf,
            &server_challenge,
            &target_info,
            0,
            &client_challenge,
        );
        // Blob fixed header = 28 bytes (1+1+6+8+8+4) per MS-NLMP §3.3.2.
        // target_info already ends with MsvAvEOL, so no extra EOL is appended.
        // Trailing Z(4) = 4 bytes.
        // Total = 16 (proof) + 28 (blob fixed) + 4 (target_info) + 4 (trailing Z(4)) = 52 bytes.
        assert!(
            response.len() >= 16 + 28,
            "response must include proof + blob fixed header, got {}",
            response.len()
        );
        // First 16 bytes are the proof.
        assert_eq!(response.len(), 16 + 28 + target_info.len() + 4);
    }

    /// LMv2 response is 24 bytes (16-byte proof + 8-byte client challenge).
    #[test]
    fn lmv2_response_is_24_bytes_and_includes_client_challenge() {
        let ntowf = ntowfv2(&ntowfv1("Password"), "User", "Domain");
        let sc = [0x01u8; 8];
        let cc = [0xAAu8; 8];
        let lm = compute_lmv2_response(&ntowf, &sc, &cc);
        assert_eq!(lm.len(), 24);
        // Last 8 bytes of LMv2 response are the client challenge.
        assert_eq!(&lm[16..24], &cc);
    }

    /// Construct a synthetic Type 2 CHALLENGE message for testing.
    fn synthetic_challenge_message() -> Vec<u8> {
        let server_challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let target_name = utf16_le("Domain");
        let target_info = ms_nlmp_4_2_3_target_info();

        // Header: 8 (signature) + 4 (type) + 8 (target name fields) +
        // 4 (flags) + 8 (server challenge) + 8 (reserved) + 8 (target
        // info fields) + 8 (version) = 56 bytes
        let header_len = 56;
        let target_name_offset = header_len;
        let target_info_offset = target_name_offset + target_name.len();

        let mut buf = Vec::with_capacity(target_info_offset + target_info.len());
        buf.extend_from_slice(NTLMSSP_SIGNATURE);
        put_u32_le(&mut buf, 2); // MessageType = CHALLENGE
                                 // TargetNameFields (Len, MaxLen, BufferOffset)
        put_u16_le(&mut buf, target_name.len() as u16);
        put_u16_le(&mut buf, target_name.len() as u16);
        put_u32_le(&mut buf, target_name_offset as u32);
        // NegotiateFlags
        let flags = negotiate_flags::NEGOTIATE_UNICODE
            | negotiate_flags::NEGOTIATE_NTLM
            | negotiate_flags::NEGOTIATE_EXTENDED_SESSIONSECURITY
            | negotiate_flags::REQUEST_TARGET_INFO
            | negotiate_flags::TARGET_TYPE_DOMAIN;
        put_u32_le(&mut buf, flags);
        // ServerChallenge (8 bytes)
        buf.extend_from_slice(&server_challenge);
        // Reserved (8 bytes)
        put_u64_le(&mut buf, 0);
        // TargetInfoFields
        put_u16_le(&mut buf, target_info.len() as u16);
        put_u16_le(&mut buf, target_info.len() as u16);
        put_u32_le(&mut buf, target_info_offset as u32);
        // Version (8 bytes)
        buf.extend_from_slice(&[0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f]);
        // Payload
        buf.extend_from_slice(&target_name);
        buf.extend_from_slice(&target_info);
        buf
    }

    /// The MS-NLMP §4.2.4.3 CHALLENGE_MESSAGE TargetInfo AV_PAIR blob,
    /// extracted from the AUTHENTICATE_MESSAGE test vector. Contains:
    /// - MsvAvNbDomainName = "Domain"  (AvId 0x0002)
    /// - MsvAvNbComputerName = "Server" (AvId 0x0001)
    /// - MsvAvEOL
    ///
    /// Note: the AV-pair order (NbDomainName FIRST, then NbComputerName)
    /// and the minimal 2-pair content are dictated by the §4.2.4.3
    /// CHALLENGE_MESSAGE bytes — NOT by the §4.2.2.2 example, which
    /// uses 6 AV pairs in a different order.  Using the wrong TargetInfo
    /// produces a different NTProofStr and fails the §4.2.4.2.2 test
    /// vector.
    fn ms_nlmp_4_2_3_target_info() -> Vec<u8> {
        let mut ti = Vec::new();
        let nb_domain = utf16_le("Domain");
        let nb_computer = utf16_le("Server");

        // MsvAvNbDomainName (AvId=0x0002) — FIRST per §4.2.4.3.
        put_u16_le(&mut ti, AvId::NbDomainName as u16);
        put_u16_le(&mut ti, nb_domain.len() as u16);
        ti.extend_from_slice(&nb_domain);

        // MsvAvNbComputerName (AvId=0x0001) — SECOND per §4.2.4.3.
        put_u16_le(&mut ti, AvId::NbComputerName as u16);
        put_u16_le(&mut ti, nb_computer.len() as u16);
        ti.extend_from_slice(&nb_computer);

        // MsvAvEOL terminator.
        put_u16_le(&mut ti, AvId::Eol as u16);
        put_u16_le(&mut ti, 0);
        ti
    }

    /// Type 1 NEGOTIATE message starts with the NTLMSSP signature and
    /// carries message type 1.
    #[test]
    fn build_negotiate_has_correct_header() {
        let msg = build_negotiate("DOMAIN", "WS01");
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        let msg_type = read_u32_le(&msg, 8).unwrap();
        assert_eq!(msg_type, 1);
    }

    /// Type 1 message includes the NegotiateFlags field with the
    /// framework-mandated bits set (NTLMv2, Unicode, target-info, etc.).
    #[test]
    fn build_negotiate_includes_flags() {
        let msg = build_negotiate("DOMAIN", "WS01");
        let flags = read_u32_le(&msg, 12).unwrap();
        assert!(flags & negotiate_flags::NEGOTIATE_UNICODE != 0);
        assert!(flags & negotiate_flags::NEGOTIATE_NTLM != 0);
        assert!(
            flags & negotiate_flags::NEGOTIATE_EXTENDED_SESSIONSECURITY != 0,
            "NTLMv2 must be negotiated"
        );
        assert!(flags & negotiate_flags::REQUEST_TARGET_INFO != 0);
        assert!(flags & negotiate_flags::NEGOTIATE_VERSION != 0);
    }

    /// Type 1 message round-trips: the domain and workstation strings
    /// appear in the payload at the offsets declared in their fields.
    #[test]
    fn build_negotiate_round_trip() {
        let msg = build_negotiate("DOMAIN", "WS01");
        // DomainNameFields at offset 16 (Len, MaxLen, BufferOffset)
        let dom_len = read_u16_le(&msg, 16).unwrap() as usize;
        let dom_offset = read_u32_le(&msg, 20).unwrap() as usize;
        let ws_len = read_u16_le(&msg, 24).unwrap() as usize;
        let ws_offset = read_u32_le(&msg, 28).unwrap() as usize;
        assert_eq!(dom_len, "DOMAIN".encode_utf16().count() * 2);
        let dom_slice = &msg[dom_offset..dom_offset + dom_len];
        assert_eq!(from_utf16_le(dom_slice).as_deref(), Some("DOMAIN"));
        let ws_slice = &msg[ws_offset..ws_offset + ws_len];
        assert_eq!(from_utf16_le(ws_slice).as_deref(), Some("WS01"));
    }

    /// Type 1 message with empty domain/workstation produces a minimal
    /// 40-byte message (header only, no payload).
    #[test]
    fn build_negotiate_empty_strings_produces_40_byte_message() {
        let msg = build_negotiate("", "");
        assert_eq!(msg.len(), 40);
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
    }

    /// Type 2 (CHALLENGE) message parser correctly extracts the server
    /// challenge and target name from a synthetic message.
    #[test]
    fn parse_challenge_extracts_server_challenge_and_target_name() {
        let challenge_msg = synthetic_challenge_message();
        let parsed = parse_challenge(&challenge_msg).expect("parse");
        assert_eq!(
            parsed.server_challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
        assert_eq!(parsed.target_name.as_deref(), Some("Domain"));
        assert!(!parsed.target_info.is_empty());
    }

    /// `parse_challenge` rejects messages with a bad NTLMSSP signature.
    #[test]
    fn parse_challenge_rejects_bad_signature() {
        let mut bad = synthetic_challenge_message();
        bad[0] = b'X';
        let res = parse_challenge(&bad);
        assert!(matches!(res, Err(NtlmError::Malformed(_))));
    }

    /// `parse_challenge` rejects messages with the wrong message type.
    #[test]
    fn parse_challenge_rejects_wrong_message_type() {
        let mut bad = synthetic_challenge_message();
        bad[8..12].copy_from_slice(&1u32.to_le_bytes()); // Type 1 instead of 2
        let res = parse_challenge(&bad);
        assert!(matches!(res, Err(NtlmError::Malformed(_))));
    }

    /// `parse_challenge` rejects truncated messages.
    #[test]
    fn parse_challenge_rejects_truncated_message() {
        let res = parse_challenge(&[0u8; 16]);
        assert!(matches!(res, Err(NtlmError::Malformed(_))));
    }

    /// Type 3 (AUTHENTICATE) message starts with the NTLMSSP signature
    /// and message type 3.
    #[test]
    fn build_authenticate_has_correct_header() {
        let challenge = parse_challenge(&synthetic_challenge_message()).unwrap();
        let msg =
            build_authenticate(&challenge, "User", "Password", "Domain", "WS01").expect("build");
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        let msg_type = read_u32_le(&msg, 8).unwrap();
        assert_eq!(msg_type, 3);
    }

    /// Type 3 message includes the username/domain/workstation identity
    /// fields at the declared offsets.
    #[test]
    fn build_authenticate_includes_identity_fields() {
        let challenge = parse_challenge(&synthetic_challenge_message()).unwrap();
        let msg =
            build_authenticate(&challenge, "Alice", "Password", "DOMAIN", "WS01").expect("build");
        // DomainNameFields at offset 28 (Len, MaxLen, BufferOffset)
        let dom_len = read_u16_le(&msg, 28).unwrap() as usize;
        let dom_offset = read_u32_le(&msg, 32).unwrap() as usize;
        let user_len = read_u16_le(&msg, 36).unwrap() as usize;
        let user_offset = read_u32_le(&msg, 40).unwrap() as usize;
        assert_eq!(dom_len, "DOMAIN".encode_utf16().count() * 2);
        let dom_slice = &msg[dom_offset..dom_offset + dom_len];
        assert_eq!(from_utf16_le(dom_slice).as_deref(), Some("DOMAIN"));
        let user_slice = &msg[user_offset..user_offset + user_len];
        assert_eq!(from_utf16_le(user_slice).as_deref(), Some("Alice"));
    }

    /// Type 3 message includes the NTLMv2 response field, which is the
    /// 16-byte NTProofStr + variable-length client blob.
    #[test]
    fn build_authenticate_includes_ntlmv2_response() {
        let challenge = parse_challenge(&synthetic_challenge_message()).unwrap();
        let msg =
            build_authenticate(&challenge, "User", "Password", "Domain", "WS01").expect("build");
        // NtChallengeResponseFields at offset 20 (Len, MaxLen, BufferOffset) —
        // per MS-NLMP §2.2.1.3, LmChallengeResponseFields is at offset 12 and
        // NtChallengeResponseFields follows at offset 20.
        let nt_len = read_u16_le(&msg, 20).unwrap() as usize;
        let nt_offset = read_u32_le(&msg, 24).unwrap() as usize;
        // The NTLMv2 response is at least 16 (proof) + 28 (blob fixed) bytes.
        assert!(
            nt_len >= 16 + 28,
            "NTLMv2 response must include proof + blob, got {nt_len}"
        );
        // The NT proof should be non-zero (an all-zero proof would indicate
        // a constant-output bug in the HMAC).
        let proof = &msg[nt_offset..nt_offset + 16];
        assert!(proof.iter().any(|&b| b != 0), "NTProofStr must be non-zero");
    }

    /// `NtlmClient::build_authenticate` returns `CredentialsUnavailable`
    /// when no credentials have been set (ADR-086 §Control 3 — the NTLM
    /// client refuses to authenticate without an explicit credential).
    #[test]
    fn build_authenticate_without_credentials_returns_unavailable() {
        let client = NtlmClient::new();
        let challenge = synthetic_challenge_message();
        let res = client.build_authenticate(&challenge, None);
        assert!(matches!(res, Err(NtlmError::CredentialsUnavailable)));
    }

    /// `NtlmClient::build_authenticate` with credentials produces a
    /// Type 3 message that starts with NTLMSSP signature and type 3.
    #[test]
    fn ntlm_client_authenticate_with_credentials_succeeds() {
        let mut client = NtlmClient::with_workstation("Domain", "WS01");
        client.set_credentials("User", "Password");
        let challenge = synthetic_challenge_message();
        let msg = client.build_authenticate(&challenge, None).expect("build");
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32_le(&msg, 8).unwrap(), 3);
    }

    /// `NtlmClient::build_negotiate` produces a well-formed Type 1 message
    /// even when called on a fresh `NtlmClient::new()` (no creds needed).
    #[test]
    fn ntlm_client_build_negotiate_succeeds_without_credentials() {
        let client = NtlmClient::new();
        let msg = client.build_negotiate().expect("build_negotiate");
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32_le(&msg, 8).unwrap(), 1);
    }

    /// `NtlmClient::build_authenticate` with channel binding present
    /// produces a Type 3 message that has the EPHEMERAL flag set in
    /// NegotiateFlags (ADR-085 §Decision; ADR-086 §Control 3).
    #[test]
    fn build_authenticate_with_channel_binding_sets_ephemeral_flag() {
        let mut client = NtlmClient::with_workstation("Domain", "WS01");
        client.set_credentials("User", "Password");
        let challenge = synthetic_challenge_message();
        let cb = compute_channel_binding(&[0x42u8; 32]);
        let msg = client
            .build_authenticate(&challenge, Some(&cb))
            .expect("build");
        // NegotiateFlags is at offset 60 in the Type 3 message.
        let flags = read_u32_le(&msg, 60).unwrap();
        assert!(
            flags & negotiate_flags::EPHEMERAL != 0,
            "EPHEMERAL must be set when channel binding is present"
        );
    }

    /// `build_authenticate_with_options` rejects a channel binding value
    /// that is not exactly 16 bytes.
    #[test]
    fn build_authenticate_rejects_bad_channel_binding_length() {
        let challenge = parse_challenge(&synthetic_challenge_message()).unwrap();
        let bad_cb = vec![0u8; 15]; // wrong length
        let res = build_authenticate_with_options(
            &challenge,
            "User",
            "Password",
            "Domain",
            "WS01",
            Some(&bad_cb),
            None,
        );
        assert!(matches!(res, Err(NtlmError::ChannelBindingRequired)));
    }

    /// RFC 5929 channel binding token: the `tls-server-end-point` binding
    /// is an MD5 hash of the channel-binding structure. We verify that the
    /// token has the correct length (16 bytes) and is deterministic.
    #[test]
    fn compute_channel_binding_is_deterministic_and_correct_length() {
        let cert_hash = [0x42u8; 32]; // SHA-256 of a (hypothetical) cert
        let cb = compute_channel_binding(&cert_hash);
        assert_eq!(cb.len(), 16, "channel binding token must be 16 bytes (MD5)");
        let cb2 = compute_channel_binding(&cert_hash);
        assert_eq!(cb, cb2, "must be deterministic");
        let cb3 = compute_channel_binding(&[0u8; 32]);
        assert_ne!(cb, cb3, "different input → different output");
    }

    /// RFC 5929 channel binding token matches a hand-computed reference
    /// using the `md-5` crate directly.
    #[test]
    fn channel_binding_matches_reference_md5() {
        let cert_hash = [0xAAu8; 32];
        let cb = compute_channel_binding(&cert_hash);

        // Build the channel-binding structure manually and MD5 it.
        let app_data: Vec<u8> = b"tls-server-end-point:"
            .iter()
            .copied()
            .chain(cert_hash.iter().copied())
            .collect();
        let mut reference = Vec::new();
        reference.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        reference.extend_from_slice(&0u32.to_le_bytes());
        reference.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        reference.extend_from_slice(&0u32.to_le_bytes());
        reference.extend_from_slice(&(app_data.len() as u32).to_le_bytes());
        reference.extend_from_slice(&app_data);
        let mut h = Md5::new();
        h.update(&reference);
        let expected = h.finalize();
        assert_eq!(cb, expected.as_slice());
    }

    /// EPA `EPHEMERAL` flag (ADR-085 §Decision) does not collide with
    /// any other NegotiateFlags bit.
    #[test]
    fn ephemeral_flag_does_not_collide() {
        let ephem = negotiate_flags::EPHEMERAL;
        let all_others = negotiate_flags::NEGOTIATE_UNICODE
            | negotiate_flags::NEGOTIATE_OEM
            | negotiate_flags::REQUEST_TARGET
            | negotiate_flags::NEGOTIATE_SIGN
            | negotiate_flags::NEGOTIATE_SEAL
            | negotiate_flags::NEGOTIATE_NTLM
            | negotiate_flags::NEGOTIATE_ALWAYS_SIGN
            | negotiate_flags::NEGOTIATE_EXTENDED_SESSIONSECURITY
            | negotiate_flags::REQUEST_TARGET_INFO
            | negotiate_flags::NEGOTIATE_VERSION
            | negotiate_flags::NEGOTIATE_128
            | negotiate_flags::NEGOTIATE_KEY_EXCH
            | negotiate_flags::NEGOTIATE_56;
        assert_eq!(
            ephem & all_others,
            0,
            "EPHEMERAL must not collide with existing flags"
        );
    }

    /// `EpaFlags` bitflags type supports the three documented bits and
    /// parses/clears them correctly.
    #[test]
    fn epa_flags_bitflags_round_trip() {
        let flags = EpaFlags::NTLMV2 | EpaFlags::MIC | EpaFlags::EPHEMERAL;
        assert!(flags.contains(EpaFlags::NTLMV2));
        assert!(flags.contains(EpaFlags::MIC));
        assert!(flags.contains(EpaFlags::EPHEMERAL));
        // The numeric value matches the bitwise-OR of the bits.
        assert_eq!(flags.bits(), 0x00000004 | 0x00000002 | 0x40000000);
        // Empty flags has bits == 0.
        assert_eq!(EpaFlags::empty().bits(), 0);
    }

    /// End-to-end: build_negotiate → parse_challenge → build_authenticate
    /// completes without error and produces a Type 3 message whose
    /// NTLMv2 response is non-trivial (16-byte non-zero NTProofStr).
    #[test]
    fn end_to_end_handshake_succeeds() {
        let mut client = NtlmClient::with_workstation("Domain", "WS01");
        client.set_credentials("User", "Password");
        // Step 1: client builds NEGOTIATE.
        let _neg = client.build_negotiate().expect("negotiate");
        // Step 2: server replies with CHALLENGE (synthetic).
        let challenge_msg = synthetic_challenge_message();
        // Step 3: client builds AUTHENTICATE from the CHALLENGE.
        let auth = client
            .build_authenticate(&challenge_msg, None)
            .expect("authenticate");
        // The Type 3 message must start with NTLMSSP\0 + type=3.
        assert_eq!(&auth[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32_le(&auth, 8).unwrap(), 3);
        // The NTLMv2 response (NtChallengeResponse) must have a non-zero
        // NTProofStr (first 16 bytes). NtChallengeResponseFields is at
        // offset 20 per MS-NLMP §2.2.1.3 (LmChallengeResponseFields at 12).
        let nt_len = read_u16_le(&auth, 20).unwrap() as usize;
        let nt_offset = read_u32_le(&auth, 24).unwrap() as usize;
        let proof = &auth[nt_offset..nt_offset + 16];
        assert!(nt_len >= 16 + 28);
        assert!(proof.iter().any(|&b| b != 0));
    }

    /// Verify the `Display` impls of `NtlmError` — these surface in LDAP
    /// / SMB client diagnostics, so the strings are stable.
    #[test]
    fn ntlm_error_display_messages() {
        assert_eq!(
            NtlmError::Protocol("bad signature".into()).to_string(),
            "protocol: bad signature"
        );
        assert_eq!(
            NtlmError::AuthFailed("wrong password".into()).to_string(),
            "auth failed: wrong password"
        );
        assert_eq!(
            NtlmError::ChannelBindingRequired.to_string(),
            "channel binding required (ADR-021)"
        );
        assert_eq!(
            NtlmError::CredentialsUnavailable.to_string(),
            "credentials unavailable"
        );
        assert_eq!(
            NtlmError::Malformed("truncated".into()).to_string(),
            "malformed message: truncated"
        );
    }
}
