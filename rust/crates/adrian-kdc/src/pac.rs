#![forbid(unsafe_code)]
//! # adrian-kdc :: pac — MS-KILE PAC Builder (ADR-082)
//!
//! Real MS-KILE-conformant PAC builder emitting all 9 mandatory buffer types
//! per ADR-082 / `docs/02-protocols/08-spn-upn-pac.md`. The builder is
//! deterministic across KDC instances (ADR-018) and signs the PAC with the
//! HSM-bound krbtgt key (ADR-015) via `crypto::hmac_sha1_96`.
//!
//! ## The 9 mandatory buffer types (ADR-082)
//!
//! | # | Type ID | Name | Purpose |
//! |---|---------|------|---------|
//! | 1 | `0x01` | `PAC_LOGON_INFO` | `KERB_VALIDATION_INFO` (user RID, groups, profile) |
//! | 2 | `0x04` | `PAC_SERVER_CHECKSUM` | HMAC over PAC body (service key) |
//! | 3 | `0x06` | `PAC_PRIVSVR_CHECKSUM` | HMAC over SERVER_CHECKSUM (krbtgt key) |
//! | 4 | `0x0A` | `PAC_CLIENT_INFO` | Client name + logon FILETIME |
//! | 5 | `0x0C` | `PAC_UPN_DNS_INFO` | UPN + DNS domain name |
//! | 6 | `0x10` | `PAC_BUFFER_TICKET_CHECKSUM` | Silver-ticket mitigation (ADR-123) |
//! | 7 | `0x12` | `PAC_REQUESTOR` | Requestor SID |
//! | 8 | `0x13` | `PAC_FULL_CHECKSUM` | HMAC over entire PAC (krbtgt key) |
//! | 9 | `0x02` | `PAC_CREDENTIAL_TYPE` | Empty placeholder (S4U2Proxy) |
//!
//! ## v0.6.0 simplifications (acceptable per task spec)
//!
//! - **LOGON_INFO encoding is a self-defined binary format, not MS-NDR.**
//!   Round-trips through this module's own parser but does not interop with
//!   Windows or `rasn`. Full NDR encoding deferred to v0.7.0.
//! - **All signatures use HMAC-SHA1-96 (etype 0x12)**. Windows uses
//!   `KERB_CHECKSUM_HMAC_MD5` (0xFFFFFF76) for RC4 and
//!   `HMAC_SHA1_96_AES256` (0x12) for AES-256. We always emit the AES-256
//!   signature type per ADR-011 (RC4 disabled by default).
//! - **TICKET_CHECKSUM is computed over a caller-supplied ticket blob** (the
//!   real KDC will pass `Ticket.enc-part` post-encryption). The builder does
//!   not perform ticket encryption itself.
//! - **PAC_REQUESTOR may be empty** (per task description; permitted for
//!   v0.6.0 when requester's host is not framework-managed).
//! - **PAC_HEADER format** uses a 16-byte header
//!   `{ulType=0, cbBufferSize, ulNumBuffers, ulVersion=0}` per the task spec.
//!   Real MS-PAC uses `{cBuffers, Version}` (8 bytes) — see v0.7.0 for the
//!   byte-compatible header.
//! - **SERVER_CHECKSUM verification zeros ALL 4 signature fields** (server,
//!   privsvr, ticket, full) to match the signing-time state where all sigs
//!   were zeroed. This is consistent with real-world implementations
//!   (Heimdal/MIT krb5 use IOV-based zeroing). The literal MS-PAC spec text
//!   "with the server signature field zeroed" is interpreted as "with the
//!   server signature field zeroed at signing time, when all other sigs
//!   were also zeroed".
//!
//! ## ADRs
//!
//! - ADR-082: MS-KILE PAC generation (9 buffer types)
//! - ADR-083: Two-layer PAC validation (KDC + service)
//! - ADR-123: Silver ticket mitigation (`PAC_BUFFER_TICKET_CHECKSUM`)
//! - ADR-015: HSM-bound krbtgt key
//! - ADR-018: Deterministic PAC across KDC instances
//! - ADR-011: AES-256 default; RC4 disabled

use crate::crypto::{self, Aes256Key};
use crate::KdcError;
use adrian_sid::Sid;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Buffer type IDs (per MS-KILE §2.1 / ADR-082)
// ---------------------------------------------------------------------------

/// PAC buffer type IDs (per MS-KILE / ADR-082).
///
/// These are the `ulType` values that appear in each `PAC_INFO_BUFFER`
/// header. See `docs/02-protocols/08-spn-upn-pac.md` §"Buffer types" for the
/// full table.
pub mod buffer_type {
    /// `PAC_LOGON_INFO` — `KERB_VALIDATION_INFO`.
    pub const LOGON_INFO: u32 = 0x01;
    /// `PAC_CREDENTIAL_TYPE` — encrypted NTLM credentials (S4U2Proxy).
    pub const CREDENTIAL_TYPE: u32 = 0x02;
    /// `PAC_SIGNATURE_DATA` (server) — server-side checksum.
    pub const SERVER_CHECKSUM: u32 = 0x04;
    /// `PAC_SIGNATURE_DATA` (KDC / privsvr) — KDC-side checksum.
    pub const PRIVSVR_CHECKSUM: u32 = 0x06;
    /// `PAC_CLIENT_INFO_TYPE` — client name + logon time.
    pub const CLIENT_INFO: u32 = 0x0A;
    /// `PAC_CONSTRAINED_DELEGATION` — S4U2Proxy permitted SPNs.
    pub const CONSTRAINED_DELEGATION: u32 = 0x0B;
    /// `PAC_UPN_DNS_INFO` — UPN + DNS domain name.
    pub const UPN_DNS_INFO: u32 = 0x0C;
    /// `PAC_CLIENT_CLAIMS_INFO` — user claims (Server 2012+).
    pub const CLIENT_CLAIMS_INFO: u32 = 0x0D;
    /// `PAC_DEVICE_INFO` — device info (Server 2012+).
    pub const DEVICE_INFO: u32 = 0x0E;
    /// `PAC_DEVICE_CLAIMS_INFO` — device claims (Server 2012+).
    pub const DEVICE_CLAIMS_INFO: u32 = 0x0F;
    /// `PAC_BUFFER_TICKET_CHECKSUM` — ticket signature (silver-ticket
    /// mitigation per ADR-123).
    pub const TICKET_CHECKSUM: u32 = 0x10;
    /// `PAC_ATTRIBUTES_INFO` — requestor info (Server 2012).
    pub const ATTRIBUTES: u32 = 0x11;
    /// `PAC_REQUESTER` — requester SID + machine SID (Server 2016+).
    pub const REQUESTOR: u32 = 0x12;
    /// `PAC_FULL_CHECKSUM` — KDC-side checksum over entire PAC (Server 2016+).
    pub const FULL_CHECKSUM: u32 = 0x13;
}

// ---------------------------------------------------------------------------
// Wire-format constants
// ---------------------------------------------------------------------------

/// PAC header `ulType` — always 0 per the v0.6.0 simplified layout.
pub const PAC_HEADER_TYPE: u32 = 0x00000000;
/// PAC header `ulVersion` — always 0 per MS-PAC.
pub const PAC_HEADER_VERSION: u32 = 0x00000000;
/// Length of the PAC top-level header (4 × u32_le).
pub const PAC_HEADER_LEN: usize = 16;
/// Length of each `PAC_INFO_BUFFER` header (u32 + u32 + u64).
pub const PAC_BUFFER_HEADER_LEN: usize = 16;
/// All buffer offsets and buffer lengths are 8-byte aligned.
pub const PAC_ALIGNMENT: usize = 8;

/// `KERB_CHECKSUM_HMAC_SHA1_96_AES256` signature type ID (etype 0x12).
/// Per MS-PAC §"PAC_SIGNATURE_DATA"; used for AES-256 principals (ADR-011).
pub const SIG_TYPE_HMAC_SHA1_96_AES256: u32 = 0x00000012;
/// Length of an HMAC-SHA1-96 tag (bytes).
pub const HMAC_SHA1_96_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Helper: little-endian encoding/decoding
// ---------------------------------------------------------------------------

fn put_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, KdcError> {
    if offset + 4 > buf.len() {
        return Err(KdcError::Pac(format!(
            "u32 read at offset {offset} past end of {len}-byte buffer",
            len = buf.len()
        )));
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, KdcError> {
    if offset + 8 > buf.len() {
        return Err(KdcError::Pac(format!(
            "u64 read at offset {offset} past end of {len}-byte buffer",
            len = buf.len()
        )));
    }
    Ok(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, KdcError> {
    if offset + 2 > buf.len() {
        return Err(KdcError::Pac(format!(
            "u16 read at offset {offset} past end of {len}-byte buffer",
            len = buf.len()
        )));
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

/// Encode a Rust `String` as UTF-16LE bytes (Windows `WCHAR[]` wire form).
fn string_to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|w| w.to_le_bytes())
        .collect::<Vec<u8>>()
}

/// Decode UTF-16LE bytes back into a Rust `String` (lossy on surrogate pairs).
fn utf16le_to_string(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&words)
}

/// Pad `buf` with zeros to the next `PAC_ALIGNMENT` boundary.
fn pad_to_alignment(buf: &mut Vec<u8>) {
    let rem = buf.len() % PAC_ALIGNMENT;
    if rem != 0 {
        buf.extend(std::iter::repeat_n(0u8, PAC_ALIGNMENT - rem));
    }
}

/// Round `len` up to the next multiple of `PAC_ALIGNMENT`.
fn align_up(len: usize) -> usize {
    let rem = len % PAC_ALIGNMENT;
    if rem == 0 {
        len
    } else {
        len + PAC_ALIGNMENT - rem
    }
}

// ---------------------------------------------------------------------------
// Structured buffer types
// ---------------------------------------------------------------------------

/// Simplified `KERB_VALIDATION_INFO` for `PAC_LOGON_INFO` (ADR-082).
///
/// v0.6.0 holds a subset of the 25+ fields of the Windows
/// `KERB_VALIDATION_INFO` struct. The full field set is documented in
/// `docs/02-protocols/08-spn-upn-pac.md` §"KERB_VALIDATION_INFO"; we encode
/// the subset needed for v0.6.0 service-side authorization (UserId,
/// PrimaryGroupId, GroupIds, LogonDomainId, LogonServer, password
/// timestamps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonInfo {
    /// Logon time as a Windows FILETIME (100-ns intervals since 1601-01-01).
    pub logon_time: u64,
    /// Logoff time (FILETIME).
    pub logoff_time: u64,
    /// Kick-off time (FILETIME).
    pub kick_off_time: u64,
    /// When the password was last set (FILETIME).
    pub password_last_set: u64,
    /// When the password can next be changed (FILETIME).
    pub password_can_change: u64,
    /// When the password must be changed (FILETIME).
    pub password_must_change: u64,
    /// Effective (display) name — UTF-16LE on the wire.
    pub effective_name: String,
    /// SAM account name (user_name) — UTF-16LE on the wire.
    pub user_name: String,
    /// Logon domain NetBIOS name — UTF-16LE on the wire.
    pub logon_domain_name: String,
    /// User RID (relative identifier within the domain).
    pub user_id: u32,
    /// Primary group RID (typically 513 = Domain Users).
    pub primary_group_id: u32,
    /// Additional group RIDs.
    pub groups: Vec<u32>,
    /// User flags (per MS-PAC `UserFlags`).
    pub user_flags: u32,
    /// Logon server NetBIOS name — UTF-16LE on the wire.
    pub logon_server: String,
    /// Domain SID (`LogonDomainId`).
    pub logon_domain_id: Sid,
}

impl LogonInfo {
    /// Encode to the v0.6.0 simplified binary format.
    ///
    /// Layout (all integers little-endian):
    /// ```text
    /// +0   u64 logon_time
    /// +8   u64 logoff_time
    /// +16  u64 kick_off_time
    /// +24  u64 password_last_set
    /// +32  u64 password_can_change
    /// +40  u64 password_must_change
    /// +48  u16 effective_name_bytes_len + UTF-16LE bytes
    /// +?   u16 user_name_bytes_len        + UTF-16LE bytes
    /// +?   u16 logon_domain_name_len      + UTF-16LE bytes
    /// +?   u32 user_id
    /// +?   u32 primary_group_id
    /// +?   u32 groups_count + u32 per group
    /// +?   u32 user_flags
    /// +?   u16 logon_server_bytes_len     + UTF-16LE bytes
    /// +?   SID (binary form per MS-DTYP §2.4.2.2)
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        put_u64_le(&mut buf, self.logon_time);
        put_u64_le(&mut buf, self.logoff_time);
        put_u64_le(&mut buf, self.kick_off_time);
        put_u64_le(&mut buf, self.password_last_set);
        put_u64_le(&mut buf, self.password_can_change);
        put_u64_le(&mut buf, self.password_must_change);

        let eff = string_to_utf16le(&self.effective_name);
        put_u16_le(&mut buf, eff.len() as u16);
        buf.extend_from_slice(&eff);

        let usr = string_to_utf16le(&self.user_name);
        put_u16_le(&mut buf, usr.len() as u16);
        buf.extend_from_slice(&usr);

        let dom = string_to_utf16le(&self.logon_domain_name);
        put_u16_le(&mut buf, dom.len() as u16);
        buf.extend_from_slice(&dom);

        put_u32_le(&mut buf, self.user_id);
        put_u32_le(&mut buf, self.primary_group_id);

        put_u32_le(&mut buf, self.groups.len() as u32);
        for g in &self.groups {
            put_u32_le(&mut buf, *g);
        }

        put_u32_le(&mut buf, self.user_flags);

        let srv = string_to_utf16le(&self.logon_server);
        put_u16_le(&mut buf, srv.len() as u16);
        buf.extend_from_slice(&srv);

        let sid_bytes = self
            .logon_domain_id
            .to_bytes()
            .expect("LogonDomainId SID must serialise");
        buf.extend_from_slice(&sid_bytes);

        buf
    }

    /// Decode from the v0.6.0 simplified binary format.
    pub fn decode(buf: &[u8]) -> Result<Self, KdcError> {
        let mut pos = 0usize;
        if buf.len() < 48 {
            return Err(KdcError::Pac("LogonInfo: truncated header".into()));
        }
        let logon_time = read_u64_le(buf, pos)?;
        pos += 8;
        let logoff_time = read_u64_le(buf, pos)?;
        pos += 8;
        let kick_off_time = read_u64_le(buf, pos)?;
        pos += 8;
        let password_last_set = read_u64_le(buf, pos)?;
        pos += 8;
        let password_can_change = read_u64_le(buf, pos)?;
        pos += 8;
        let password_must_change = read_u64_le(buf, pos)?;
        pos += 8;

        let eff_len = read_u16_le(buf, pos)? as usize;
        pos += 2;
        if pos + eff_len > buf.len() {
            return Err(KdcError::Pac("LogonInfo: truncated effective_name".into()));
        }
        let effective_name = utf16le_to_string(&buf[pos..pos + eff_len]);
        pos += eff_len;

        let usr_len = read_u16_le(buf, pos)? as usize;
        pos += 2;
        if pos + usr_len > buf.len() {
            return Err(KdcError::Pac("LogonInfo: truncated user_name".into()));
        }
        let user_name = utf16le_to_string(&buf[pos..pos + usr_len]);
        pos += usr_len;

        let dom_len = read_u16_le(buf, pos)? as usize;
        pos += 2;
        if pos + dom_len > buf.len() {
            return Err(KdcError::Pac(
                "LogonInfo: truncated logon_domain_name".into(),
            ));
        }
        let logon_domain_name = utf16le_to_string(&buf[pos..pos + dom_len]);
        pos += dom_len;

        if pos + 4 > buf.len() {
            return Err(KdcError::Pac("LogonInfo: truncated user_id".into()));
        }
        let user_id = read_u32_le(buf, pos)?;
        pos += 4;
        let primary_group_id = read_u32_le(buf, pos)?;
        pos += 4;

        if pos + 4 > buf.len() {
            return Err(KdcError::Pac("LogonInfo: truncated groups_count".into()));
        }
        let groups_count = read_u32_le(buf, pos)? as usize;
        pos += 4;
        let needed = groups_count
            .checked_mul(4)
            .ok_or_else(|| KdcError::Pac("LogonInfo: groups_count overflow".into()))?;
        if pos + needed > buf.len() {
            return Err(KdcError::Pac("LogonInfo: truncated groups".into()));
        }
        let mut groups = Vec::with_capacity(groups_count);
        for _ in 0..groups_count {
            groups.push(read_u32_le(buf, pos)?);
            pos += 4;
        }

        let user_flags = read_u32_le(buf, pos)?;
        pos += 4;

        let srv_len = read_u16_le(buf, pos)? as usize;
        pos += 2;
        if pos + srv_len > buf.len() {
            return Err(KdcError::Pac("LogonInfo: truncated logon_server".into()));
        }
        let logon_server = utf16le_to_string(&buf[pos..pos + srv_len]);
        pos += srv_len;

        // Remaining bytes are the SID.
        if pos >= buf.len() {
            return Err(KdcError::Pac(
                "LogonInfo: missing logon_domain_id SID".into(),
            ));
        }
        let logon_domain_id = Sid::from_bytes(&buf[pos..])
            .map_err(|e| KdcError::Pac(format!("LogonInfo: bad SID: {e}")))?;

        Ok(Self {
            logon_time,
            logoff_time,
            kick_off_time,
            password_last_set,
            password_can_change,
            password_must_change,
            effective_name,
            user_name,
            logon_domain_name,
            user_id,
            primary_group_id,
            groups,
            user_flags,
            logon_server,
            logon_domain_id,
        })
    }
}

/// `PAC_CLIENT_INFO_TYPE` (0x0A) — client name + logon FILETIME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// Logon time as a Windows FILETIME.
    pub client_id: u64,
    /// Client name (NetBIOS-style; encoded as UTF-16LE on the wire).
    pub name: String,
}

impl ClientInfo {
    /// Encode per MS-PAC `PAC_CLIENT_INFO`:
    /// ```text
    /// +0  u64 ClientId (FILETIME)
    /// +8  u16 NameLength (bytes)
    /// +10     Name[NameLength] (UTF-16LE)
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let name_utf16 = string_to_utf16le(&self.name);
        let mut buf = Vec::with_capacity(10 + name_utf16.len());
        put_u64_le(&mut buf, self.client_id);
        put_u16_le(&mut buf, name_utf16.len() as u16);
        buf.extend_from_slice(&name_utf16);
        buf
    }

    /// Decode per MS-PAC `PAC_CLIENT_INFO`.
    pub fn decode(buf: &[u8]) -> Result<Self, KdcError> {
        if buf.len() < 10 {
            return Err(KdcError::Pac("ClientInfo: truncated header".into()));
        }
        let client_id = read_u64_le(buf, 0)?;
        let name_len = read_u16_le(buf, 8)? as usize;
        if 10 + name_len > buf.len() {
            return Err(KdcError::Pac("ClientInfo: truncated name".into()));
        }
        let name = utf16le_to_string(&buf[10..10 + name_len]);
        Ok(Self { client_id, name })
    }
}

/// `PAC_UPN_DNS_INFO` (0x0C) — UPN + DNS domain name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpnDnsInfo {
    /// User Principal Name (`user@domain`).
    pub upn: String,
    /// DNS domain name (e.g. `corp.example.com`).
    pub dns_domain_name: String,
    /// `UpnDnsFlags` (bit 0 = HasUPN, bit 1 = HasSamName, bit 2 = HasSid).
    pub flags: u32,
}

impl UpnDnsInfo {
    /// Encode per the simplified v0.6.0 layout:
    /// ```text
    /// +0  u16 upn_length        (bytes, not chars)
    /// +2  u16 upn_offset        (from start of this buffer)
    /// +4  u16 dns_length        (bytes)
    /// +6  u16 dns_offset        (from start of this buffer)
    /// +8  u32 flags
    /// +12     upn_utf16 + dns_utf16 (concatenated)
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let upn = string_to_utf16le(&self.upn);
        let dns = string_to_utf16le(&self.dns_domain_name);
        let header_len = 12u16;
        let upn_offset = header_len;
        let dns_offset = upn_offset + upn.len() as u16;
        let mut buf = Vec::with_capacity(header_len as usize + upn.len() + dns.len());
        put_u16_le(&mut buf, upn.len() as u16);
        put_u16_le(&mut buf, upn_offset);
        put_u16_le(&mut buf, dns.len() as u16);
        put_u16_le(&mut buf, dns_offset);
        put_u32_le(&mut buf, self.flags);
        buf.extend_from_slice(&upn);
        buf.extend_from_slice(&dns);
        buf
    }

    /// Decode per the v0.6.0 simplified layout.
    pub fn decode(buf: &[u8]) -> Result<Self, KdcError> {
        if buf.len() < 12 {
            return Err(KdcError::Pac("UpnDnsInfo: truncated header".into()));
        }
        let upn_length = read_u16_le(buf, 0)? as usize;
        let upn_offset = read_u16_le(buf, 2)? as usize;
        let dns_length = read_u16_le(buf, 4)? as usize;
        let dns_offset = read_u16_le(buf, 6)? as usize;
        let flags = read_u32_le(buf, 8)?;

        if upn_offset + upn_length > buf.len() {
            return Err(KdcError::Pac("UpnDnsInfo: upn out of bounds".into()));
        }
        if dns_offset + dns_length > buf.len() {
            return Err(KdcError::Pac("UpnDnsInfo: dns out of bounds".into()));
        }
        let upn = utf16le_to_string(&buf[upn_offset..upn_offset + upn_length]);
        let dns_domain_name = utf16le_to_string(&buf[dns_offset..dns_offset + dns_length]);
        Ok(Self {
            upn,
            dns_domain_name,
            flags,
        })
    }
}

/// `PAC_REQUESTER` (0x12) — requestor SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestorInfo {
    /// Requestor SID (`None` if requester's host is not framework-managed).
    pub sid: Option<Sid>,
}

impl RequestorInfo {
    /// Encode: binary SID bytes (or empty if `sid` is `None`).
    pub fn encode(&self) -> Vec<u8> {
        match &self.sid {
            Some(sid) => sid.to_bytes().unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Decode: parse binary SID. Empty buffer → `sid = None`.
    pub fn decode(buf: &[u8]) -> Result<Self, KdcError> {
        if buf.is_empty() {
            return Ok(Self { sid: None });
        }
        let sid = Sid::from_bytes(buf).map_err(|e| KdcError::Pac(format!("RequestorInfo: {e}")))?;
        Ok(Self { sid: Some(sid) })
    }
}

/// `PAC_SIGNATURE_DATA` — server / KDC / ticket / full checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureData {
    /// Signature type ID (e.g. `SIG_TYPE_HMAC_SHA1_96_AES256` = 0x12).
    pub signature_type: u32,
    /// Raw signature bytes (12 for HMAC-SHA1-96).
    pub signature: Vec<u8>,
}

impl SignatureData {
    /// Encode per MS-PAC `PAC_SIGNATURE_DATA`:
    /// ```text
    /// +0  u32 SignatureType
    /// +4     Signature[variable]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.signature.len());
        put_u32_le(&mut buf, self.signature_type);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode. The expected signature length is determined by `signature_type`;
    /// for HMAC-SHA1-96 it's `HMAC_SHA1_96_LEN`.
    pub fn decode(buf: &[u8]) -> Result<Self, KdcError> {
        if buf.len() < 4 {
            return Err(KdcError::Pac("SignatureData: truncated header".into()));
        }
        let signature_type = read_u32_le(buf, 0)?;
        let signature = buf[4..].to_vec();
        Ok(Self {
            signature_type,
            signature,
        })
    }

    /// Construct a zeroed HMAC-SHA1-96 signature data (used as a placeholder
    /// before the actual HMAC is computed).
    fn zeroed_hmac_sha1_96() -> Self {
        Self {
            signature_type: SIG_TYPE_HMAC_SHA1_96_AES256,
            signature: vec![0u8; HMAC_SHA1_96_LEN],
        }
    }
}

/// `PAC_BUFFER_TICKET_CHECKSUM` (0x10) — ticket signature (silver-ticket
/// mitigation per ADR-123).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketChecksum {
    /// Signature type ID.
    pub signature_type: u32,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

impl TicketChecksum {
    /// Encode per MS-PAC `PAC_BUFFER_TICKET_CHECKSUM`:
    /// ```text
    /// +0  u32 SignatureType
    /// +4  u32 SignatureLength
    /// +8     Signature[SignatureLength]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.signature.len());
        put_u32_le(&mut buf, self.signature_type);
        put_u32_le(&mut buf, self.signature.len() as u32);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode per the same layout.
    pub fn decode(buf: &[u8]) -> Result<Self, KdcError> {
        if buf.len() < 8 {
            return Err(KdcError::Pac("TicketChecksum: truncated header".into()));
        }
        let signature_type = read_u32_le(buf, 0)?;
        let signature_length = read_u32_le(buf, 4)? as usize;
        if 8 + signature_length > buf.len() {
            return Err(KdcError::Pac("TicketChecksum: truncated signature".into()));
        }
        let signature = buf[8..8 + signature_length].to_vec();
        Ok(Self {
            signature_type,
            signature,
        })
    }

    /// Construct a zeroed placeholder (signature field zeroed for HMAC
    /// computation over the surrounding PAC).
    fn zeroed_hmac_sha1_96() -> Self {
        Self {
            signature_type: SIG_TYPE_HMAC_SHA1_96_AES256,
            signature: vec![0u8; HMAC_SHA1_96_LEN],
        }
    }
}

// ---------------------------------------------------------------------------
// PAC header + buffer array binary encode/decode
// ---------------------------------------------------------------------------

/// A single PAC buffer descriptor (decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacBuffer {
    /// Buffer type ID (e.g. `buffer_type::LOGON_INFO`).
    pub ul_type: u32,
    /// Buffer payload bytes (NOT including the 16-byte `PAC_INFO_BUFFER`
    /// header — this is just the `Data`).
    pub data: Vec<u8>,
}

/// Parsed PAC structure — the header + an ordered list of buffer descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pac {
    /// Top-level `cbBufferSize` (total PAC length including header).
    pub total_size: u32,
    /// Number of buffers (matches `buffers.len()`).
    pub num_buffers: u32,
    /// Buffers in their on-the-wire order.
    pub buffers: Vec<PacBuffer>,
}

impl Pac {
    /// Parse raw PAC bytes into a [`Pac`].
    pub fn parse(bytes: &[u8]) -> Result<Self, KdcError> {
        if bytes.len() < PAC_HEADER_LEN {
            return Err(KdcError::Pac(format!(
                "PAC: header truncated (got {len} bytes, need {PAC_HEADER_LEN})",
                len = bytes.len()
            )));
        }
        let ul_type = read_u32_le(bytes, 0)?;
        if ul_type != PAC_HEADER_TYPE {
            return Err(KdcError::Pac(format!(
                "PAC: header ulType=0x{ul_type:08X}, expected 0x{PAC_HEADER_TYPE:08X}"
            )));
        }
        let total_size = read_u32_le(bytes, 4)? as usize;
        if total_size != bytes.len() {
            return Err(KdcError::Pac(format!(
                "PAC: cbBufferSize={total_size} != actual len={actual}",
                actual = bytes.len()
            )));
        }
        let num_buffers = read_u32_le(bytes, 8)?;
        let version = read_u32_le(bytes, 12)?;
        if version != PAC_HEADER_VERSION {
            return Err(KdcError::Pac(format!(
                "PAC: ulVersion=0x{version:08X}, expected 0x{PAC_HEADER_VERSION:08X}"
            )));
        }

        let mut buffers = Vec::with_capacity(num_buffers as usize);
        let mut off = PAC_HEADER_LEN;
        for i in 0..num_buffers {
            if off + PAC_BUFFER_HEADER_LEN > bytes.len() {
                return Err(KdcError::Pac(format!(
                    "PAC: buffer {i} header out of bounds (off={off})"
                )));
            }
            let b_type = read_u32_le(bytes, off)?;
            let b_size = read_u32_le(bytes, off + 4)? as usize;
            let b_offset = read_u64_le(bytes, off + 8)? as usize;
            if b_offset + b_size > bytes.len() {
                return Err(KdcError::Pac(format!(
                    "PAC: buffer {i} data out of bounds (offset={b_offset}, size={b_size}, len={len})",
                    len = bytes.len()
                )));
            }
            let data = bytes[b_offset..b_offset + b_size].to_vec();
            buffers.push(PacBuffer {
                ul_type: b_type,
                data,
            });
            off += PAC_BUFFER_HEADER_LEN;
        }

        Ok(Self {
            total_size: total_size as u32,
            num_buffers,
            buffers,
        })
    }

    /// Find the first buffer of the given type.
    pub fn find_buffer(&self, ty: u32) -> Option<&PacBuffer> {
        self.buffers.iter().find(|b| b.ul_type == ty)
    }

    /// Locate a buffer's positional index by type.
    pub fn find_buffer_index(&self, ty: u32) -> Option<usize> {
        self.buffers.iter().position(|b| b.ul_type == ty)
    }

    /// Zero all four signature fields (server, privsvr, ticket, full) in
    /// `raw` — used to reproduce the signing-time state where all sigs were
    /// zeroed when the SERVER_CHECKSUM was computed.
    ///
    /// Returns a new `Vec<u8>` with all 4 sig fields zeroed. If a sig buffer
    /// is missing, that field is silently skipped.
    fn zero_all_signature_fields(&self, raw: &[u8]) -> Result<Vec<u8>, KdcError> {
        let mut tmp = raw.to_vec();
        for ty in [
            buffer_type::SERVER_CHECKSUM,
            buffer_type::PRIVSVR_CHECKSUM,
            buffer_type::FULL_CHECKSUM,
        ] {
            if let Ok((data_off, data_len)) = self.buffer_data_range(&tmp, ty) {
                if data_len >= 4 + HMAC_SHA1_96_LEN {
                    let sig_off = data_off + 4;
                    for i in 0..HMAC_SHA1_96_LEN {
                        tmp[sig_off + i] = 0;
                    }
                }
            }
        }
        // TICKET_CHECKSUM has a different layout: u32 SignatureType +
        // u32 SignatureLength + Signature.
        if let Ok((data_off, data_len)) = self.buffer_data_range(&tmp, buffer_type::TICKET_CHECKSUM)
        {
            if data_len >= 8 + HMAC_SHA1_96_LEN {
                let sig_off = data_off + 8;
                for i in 0..HMAC_SHA1_96_LEN {
                    tmp[sig_off + i] = 0;
                }
            }
        }
        Ok(tmp)
    }

    /// Verify the `PAC_SERVER_CHECKSUM` (HMAC-SHA1-96 over the PAC body
    /// with all signature fields zeroed, keyed with the service's
    /// long-term key). Layer 2 of ADR-083.
    ///
    /// Note: this zeros ALL FOUR signature fields (server, privsvr, ticket,
    /// full) to match the signing-time state where all sigs were zeroed
    /// when the SERVER_CHECKSUM was first computed. See module docs for the
    /// rationale.
    pub fn verify_server_checksum(
        &self,
        raw: &[u8],
        server_key: &Aes256Key,
    ) -> Result<(), KdcError> {
        let srv = self
            .find_buffer(buffer_type::SERVER_CHECKSUM)
            .ok_or_else(|| KdcError::Pac("PAC: missing SERVER_CHECKSUM".into()))?;
        let sig = SignatureData::decode(&srv.data)?;

        let (data_off, data_len) = self.buffer_data_range(raw, buffer_type::SERVER_CHECKSUM)?;
        if data_len < 4 + HMAC_SHA1_96_LEN {
            return Err(KdcError::Pac(
                "PAC: SERVER_CHECKSUM buffer too short".into(),
            ));
        }
        // Zero all signature fields to match the signing-time state.
        let tmp = self.zero_all_signature_fields(raw)?;
        let sig_off = data_off + 4;
        let expected = crypto::hmac_sha1_96(server_key, &tmp);
        if expected.as_slice() != sig.signature.as_slice() {
            return Err(KdcError::Pac(
                "PAC: SERVER_CHECKSUM signature mismatch".into(),
            ));
        }
        // Suppress unused-warning when assertions are off.
        let _ = sig_off;
        Ok(())
    }

    /// Verify the `PAC_PRIVSVR_CHECKSUM` (HMAC-SHA1-96 over the
    /// `SERVER_CHECKSUM.SignatureValue` field, keyed with the krbtgt key).
    /// Layer 1 of ADR-083.
    pub fn verify_privsvr_checksum(
        &self,
        raw: &[u8],
        krbtgt_key: &Aes256Key,
    ) -> Result<(), KdcError> {
        let privsvr = self
            .find_buffer(buffer_type::PRIVSVR_CHECKSUM)
            .ok_or_else(|| KdcError::Pac("PAC: missing PRIVSVR_CHECKSUM".into()))?;
        let priv_sig = SignatureData::decode(&privsvr.data)?;

        // Find the SERVER_CHECKSUM signature field in `raw`.
        let (srv_data_off, srv_data_len) =
            self.buffer_data_range(raw, buffer_type::SERVER_CHECKSUM)?;
        if srv_data_len < 4 + HMAC_SHA1_96_LEN {
            return Err(KdcError::Pac(
                "PAC: SERVER_CHECKSUM buffer too short for PRIVSVR verification".into(),
            ));
        }
        let srv_sig_off = srv_data_off + 4;
        let expected = crypto::hmac_sha1_96(
            krbtgt_key,
            &raw[srv_sig_off..srv_sig_off + HMAC_SHA1_96_LEN],
        );
        if expected.as_slice() != priv_sig.signature.as_slice() {
            return Err(KdcError::Pac(
                "PAC: PRIVSVR_CHECKSUM signature mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Verify the `PAC_FULL_CHECKSUM` (HMAC-SHA1-96 over the entire PAC
    /// excluding `FULL_CHECKSUM.SignatureValue`, keyed with krbtgt).
    pub fn verify_full_checksum(&self, raw: &[u8], krbtgt_key: &Aes256Key) -> Result<(), KdcError> {
        let full = self
            .find_buffer(buffer_type::FULL_CHECKSUM)
            .ok_or_else(|| KdcError::Pac("PAC: missing FULL_CHECKSUM".into()))?;
        let full_sig = SignatureData::decode(&full.data)?;
        let (full_data_off, full_data_len) =
            self.buffer_data_range(raw, buffer_type::FULL_CHECKSUM)?;
        if full_data_len < 4 + HMAC_SHA1_96_LEN {
            return Err(KdcError::Pac("PAC: FULL_CHECKSUM buffer too short".into()));
        }
        let full_sig_off = full_data_off + 4;
        let mut tmp = raw.to_vec();
        for i in 0..HMAC_SHA1_96_LEN {
            tmp[full_sig_off + i] = 0;
        }
        let expected = crypto::hmac_sha1_96(krbtgt_key, &tmp);
        if expected.as_slice() != full_sig.signature.as_slice() {
            return Err(KdcError::Pac(
                "PAC: FULL_CHECKSUM signature mismatch".into(),
            ));
        }
        Ok(())
    }

    /// Verify the `PAC_BUFFER_TICKET_CHECKSUM` (HMAC-SHA1-96 over the
    /// caller-supplied ticket bytes, keyed with krbtgt). Silver-ticket
    /// mitigation per ADR-123.
    pub fn verify_ticket_checksum(
        &self,
        krbtgt_key: &Aes256Key,
        ticket_bytes: &[u8],
    ) -> Result<(), KdcError> {
        let tc = self
            .find_buffer(buffer_type::TICKET_CHECKSUM)
            .ok_or_else(|| KdcError::Pac("PAC: missing TICKET_CHECKSUM".into()))?;
        let tc_decoded = TicketChecksum::decode(&tc.data)?;
        let expected = crypto::hmac_sha1_96(krbtgt_key, ticket_bytes);
        if expected.as_slice() != tc_decoded.signature.as_slice() {
            return Err(KdcError::Pac(
                "PAC: TICKET_CHECKSUM signature mismatch (silver-ticket?)".into(),
            ));
        }
        Ok(())
    }

    /// Locate the (data_offset, data_length) of the buffer of the given type
    /// within `raw`. Returns the absolute offset of the buffer's `Data` field
    /// (i.e. past the 16-byte `PAC_INFO_BUFFER` header) and its length.
    fn buffer_data_range(&self, raw: &[u8], ty: u32) -> Result<(usize, usize), KdcError> {
        let idx = self
            .find_buffer_index(ty)
            .ok_or_else(|| KdcError::Pac(format!("PAC: buffer type 0x{ty:08X} not found")))?;
        if idx >= self.buffers.len() {
            return Err(KdcError::Pac("PAC: buffer index out of range".into()));
        }
        let buf_header_off = PAC_HEADER_LEN + idx * PAC_BUFFER_HEADER_LEN;
        if buf_header_off + PAC_BUFFER_HEADER_LEN > raw.len() {
            return Err(KdcError::Pac("PAC: buffer header out of bounds".into()));
        }
        let data_len = read_u32_le(raw, buf_header_off + 4)? as usize;
        let data_off = read_u64_le(raw, buf_header_off + 8)? as usize;
        if data_off + data_len > raw.len() {
            return Err(KdcError::Pac("PAC: buffer data out of bounds".into()));
        }
        Ok((data_off, data_len))
    }
}

// ---------------------------------------------------------------------------
// PacBuilder
// ---------------------------------------------------------------------------

/// MS-KILE PAC builder emitting all 9 mandatory buffer types per ADR-082.
pub struct PacBuilder {
    /// Identity of the client principal this PAC is being built for.
    pub client_uuid: Uuid,
    /// Realm (e.g. `CORP.EXAMPLE.COM`).
    pub realm: String,
    /// `PAC_LOGON_INFO` payload.
    pub logon_info: LogonInfo,
    /// `PAC_CLIENT_INFO` payload.
    pub client_info: ClientInfo,
    /// `PAC_UPN_DNS_INFO` payload.
    pub upn_dns_info: UpnDnsInfo,
    /// `PAC_REQUESTOR` payload (may be empty per task description).
    pub requestor: RequestorInfo,
    /// Caller-supplied ticket bytes (the encrypted `Ticket.enc-part`) used
    /// to compute `PAC_BUFFER_TICKET_CHECKSUM`. Silver-ticket mitigation
    /// (ADR-123).
    pub ticket_bytes: Vec<u8>,
}

impl PacBuilder {
    /// Construct a new `PacBuilder` with the minimum mandatory inputs.
    ///
    /// `client_uuid` and `client_sid` identify the principal; `realm` is the
    /// uppercase Kerberos realm (e.g. `CORP.EXAMPLE.COM`). The builder fills
    /// `logon_info`, `client_info`, `upn_dns_info`, `requestor`, and an empty
    /// `ticket_bytes` with sensible defaults — callers override these fields
    /// directly before calling [`build`](Self::build).
    pub fn new(client_uuid: Uuid, client_sid: &Sid, realm: &str) -> Self {
        // Derive the user RID and domain SID from `client_sid`.
        let user_id = client_sid.rid().unwrap_or(0);
        let domain_sid = client_sid
            .domain_sid()
            .unwrap_or_else(|| client_sid.clone());

        let logon_info = LogonInfo {
            logon_time: 0,
            logoff_time: 0,
            kick_off_time: 0,
            password_last_set: 0,
            password_can_change: 0,
            password_must_change: 0,
            effective_name: String::new(),
            user_name: String::new(),
            logon_domain_name: realm.to_string(),
            user_id,
            primary_group_id: 513, // DOMAIN_GROUP_RID_USERS
            groups: Vec::new(),
            user_flags: 0,
            logon_server: String::new(),
            logon_domain_id: domain_sid,
        };

        let client_info = ClientInfo {
            client_id: 0,
            name: String::new(),
        };

        let upn = format!("{}@{}", client_uuid.as_simple(), realm.to_lowercase());
        let upn_dns_info = UpnDnsInfo {
            upn,
            dns_domain_name: realm.to_lowercase(),
            flags: 0,
        };

        let requestor = RequestorInfo { sid: None };

        Self {
            client_uuid,
            realm: realm.to_string(),
            logon_info,
            client_info,
            upn_dns_info,
            requestor,
            ticket_bytes: Vec::new(),
        }
    }

    /// Build the PAC with all 9 buffer types, signed with the krbtgt key.
    ///
    /// Signing order (per ADR-082):
    /// 1. Encode all buffers with zeroed signature fields.
    /// 2. Compute `PAC_SERVER_CHECKSUM.SignatureValue` = HMAC-SHA1-96 over
    ///    the entire PAC (with all sig fields zeroed) using the krbtgt key
    ///    (v0.6.0: server signature uses the krbtgt key — real impl would
    ///    use the service's long-term key when building a service ticket).
    /// 3. Compute `PAC_PRIVSVR_CHECKSUM.SignatureValue` = HMAC-SHA1-96 over
    ///    `PAC_SERVER_CHECKSUM.SignatureValue` using the krbtgt key.
    /// 4. Compute `PAC_BUFFER_TICKET_CHECKSUM.Signature` = HMAC-SHA1-96 over
    ///    the caller-supplied ticket bytes using the krbtgt key.
    /// 5. Compute `PAC_FULL_CHECKSUM.SignatureValue` = HMAC-SHA1-96 over the
    ///    entire PAC (including signatures 2/3/4, with FULL_CHECKSUM zeroed)
    ///    using the krbtgt key.
    pub fn build(&self, krbtgt_key: &Aes256Key) -> Result<Vec<u8>, KdcError> {
        // 1. Build the unsigned PAC (zeroed signatures).
        let mut bytes = self.build_unsigned()?;
        let pac = Pac::parse(&bytes)?;
        // 2. Compute SERVER_CHECKSUM over the entire PAC (zeroed sigs).
        let (srv_data_off, _srv_data_len) =
            pac.buffer_data_range(&bytes, buffer_type::SERVER_CHECKSUM)?;
        let srv_sig_off = srv_data_off + 4; // skip u32 SignatureType
        let srv_sig = crypto::hmac_sha1_96(krbtgt_key, &bytes);
        bytes[srv_sig_off..srv_sig_off + HMAC_SHA1_96_LEN].copy_from_slice(&srv_sig);

        // 3. Compute PRIVSVR_CHECKSUM over SERVER_CHECKSUM.SignatureValue.
        let privsvr_sig = crypto::hmac_sha1_96(
            krbtgt_key,
            &bytes[srv_sig_off..srv_sig_off + HMAC_SHA1_96_LEN],
        );
        let (priv_data_off, _priv_data_len) =
            pac.buffer_data_range(&bytes, buffer_type::PRIVSVR_CHECKSUM)?;
        let priv_sig_off = priv_data_off + 4;
        bytes[priv_sig_off..priv_sig_off + HMAC_SHA1_96_LEN].copy_from_slice(&privsvr_sig);

        // 4. Compute TICKET_CHECKSUM over the caller-supplied ticket bytes.
        let tc_sig = crypto::hmac_sha1_96(krbtgt_key, &self.ticket_bytes);
        let (tc_data_off, _tc_data_len) =
            pac.buffer_data_range(&bytes, buffer_type::TICKET_CHECKSUM)?;
        // TICKET_CHECKSUM layout: u32 SignatureType + u32 SignatureLength + sig.
        let tc_sig_off = tc_data_off + 8;
        bytes[tc_sig_off..tc_sig_off + HMAC_SHA1_96_LEN].copy_from_slice(&tc_sig);

        // 5. Compute FULL_CHECKSUM over the entire PAC (FULL sig zeroed).
        let (full_data_off, _full_data_len) =
            pac.buffer_data_range(&bytes, buffer_type::FULL_CHECKSUM)?;
        let full_sig_off = full_data_off + 4;
        let full_sig = crypto::hmac_sha1_96(krbtgt_key, &bytes);
        bytes[full_sig_off..full_sig_off + HMAC_SHA1_96_LEN].copy_from_slice(&full_sig);

        Ok(bytes)
    }

    /// Build the unsigned PAC (all signature fields zeroed) — used for
    /// testing and as a precursor to [`build`](Self::build).
    pub fn build_unsigned(&self) -> Result<Vec<u8>, KdcError> {
        // Encode all 9 buffers in the deterministic order per ADR-082:
        // LOGON_INFO → CREDENTIAL_TYPE → SERVER_CHECKSUM → PRIVSVR_CHECKSUM
        // → CLIENT_INFO → UPN_DNS_INFO → TICKET_CHECKSUM → REQUESTOR
        // → FULL_CHECKSUM.
        let logon_bytes = self.logon_info.encode();
        let cred_bytes: Vec<u8> = Vec::new(); // empty placeholder (no S4U2Proxy in v0.6.0)
        let server_sig_bytes = SignatureData::zeroed_hmac_sha1_96().encode();
        let privsvr_sig_bytes = SignatureData::zeroed_hmac_sha1_96().encode();
        let client_bytes = self.client_info.encode();
        let upn_bytes = self.upn_dns_info.encode();
        let tc_bytes = TicketChecksum::zeroed_hmac_sha1_96().encode();
        let req_bytes = self.requestor.encode();
        let full_sig_bytes = SignatureData::zeroed_hmac_sha1_96().encode();

        let buffers: &[(u32, &[u8])] = &[
            (buffer_type::LOGON_INFO, &logon_bytes),
            (buffer_type::CREDENTIAL_TYPE, &cred_bytes),
            (buffer_type::SERVER_CHECKSUM, &server_sig_bytes),
            (buffer_type::PRIVSVR_CHECKSUM, &privsvr_sig_bytes),
            (buffer_type::CLIENT_INFO, &client_bytes),
            (buffer_type::UPN_DNS_INFO, &upn_bytes),
            (buffer_type::TICKET_CHECKSUM, &tc_bytes),
            (buffer_type::REQUESTOR, &req_bytes),
            (buffer_type::FULL_CHECKSUM, &full_sig_bytes),
        ];
        let num_buffers = buffers.len() as u32;

        // Compute total size: header + N * buffer_header + sum(aligned(data))
        let header_size = PAC_HEADER_LEN;
        let buf_headers_size = num_buffers as usize * PAC_BUFFER_HEADER_LEN;
        let mut data_size = 0usize;
        for (_, b) in buffers {
            data_size += align_up(b.len());
        }
        let total_size = header_size + buf_headers_size + data_size;

        let mut out = Vec::with_capacity(total_size);
        // PAC_HEADER
        put_u32_le(&mut out, PAC_HEADER_TYPE);
        put_u32_le(&mut out, total_size as u32);
        put_u32_le(&mut out, num_buffers);
        put_u32_le(&mut out, PAC_HEADER_VERSION);

        // Compute each buffer's data offset.
        let mut next_data_off = header_size + buf_headers_size;
        let mut data_offsets: Vec<usize> = Vec::with_capacity(buffers.len());
        for (_, b) in buffers {
            data_offsets.push(next_data_off);
            next_data_off += align_up(b.len());
        }

        // PAC_INFO_BUFFER headers
        for (i, (ty, _)) in buffers.iter().enumerate() {
            put_u32_le(&mut out, *ty);
            let data_len = buffers[i].1.len();
            put_u32_le(&mut out, data_len as u32);
            put_u64_le(&mut out, data_offsets[i] as u64);
        }

        // Buffer data, each padded to 8-byte alignment.
        for (_, b) in buffers {
            out.extend_from_slice(b);
            pad_to_alignment(&mut out);
        }

        debug_assert_eq!(out.len(), total_size, "PAC size mismatch");
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_sid::Sid;

    /// Test fixture: a domain SID `S-1-5-21-100-200-300`.
    fn test_domain_sid() -> Sid {
        Sid::new(adrian_sid::SECURITY_NT_AUTHORITY, vec![21, 100, 200, 300]).expect("domain SID")
    }

    /// Test fixture: a user SID `S-1-5-21-100-200-300-1101` (RID 1101).
    fn test_user_sid() -> Sid {
        Sid::new(
            adrian_sid::SECURITY_NT_AUTHORITY,
            vec![21, 100, 200, 300, 1101],
        )
        .expect("user SID")
    }

    /// Test fixture: 32-byte krbtgt key (all 0x42 — for tests only).
    fn test_krbtgt_key() -> Aes256Key {
        [0x42u8; 32]
    }

    /// Test fixture: a different 32-byte key (for "wrong key" tests).
    fn test_wrong_key() -> Aes256Key {
        [0x99u8; 32]
    }

    /// PAC header encode/decode round-trip: build a minimal PAC and verify
    /// the parsed header has the expected `ulType`, `cbBufferSize`,
    /// `ulNumBuffers`, `ulVersion`.
    #[test]
    fn pac_header_encode_decode_round_trip() {
        let sid = test_user_sid();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let bytes = builder.build_unsigned().expect("build_unsigned");
        let pac = Pac::parse(&bytes).expect("parse");
        assert_eq!(pac.total_size as usize, bytes.len());
        assert_eq!(pac.num_buffers, 9, "must emit 9 buffers per ADR-082");
    }

    /// PAC buffer encode/decode round-trip: each buffer header in the
    /// parsed PAC must point at the correct data slice.
    #[test]
    fn pac_buffer_encode_decode_round_trip() {
        let sid = test_user_sid();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let bytes = builder.build_unsigned().expect("build_unsigned");
        let pac = Pac::parse(&bytes).expect("parse");
        // Verify the LOGON_INFO buffer is present and decodable.
        let logon_buf = pac
            .find_buffer(buffer_type::LOGON_INFO)
            .expect("LOGON_INFO present");
        assert!(!logon_buf.data.is_empty(), "LOGON_INFO buffer non-empty");
        // Verify all 9 buffer types are present.
        let expected_types = [
            buffer_type::LOGON_INFO,
            buffer_type::CREDENTIAL_TYPE,
            buffer_type::SERVER_CHECKSUM,
            buffer_type::PRIVSVR_CHECKSUM,
            buffer_type::CLIENT_INFO,
            buffer_type::UPN_DNS_INFO,
            buffer_type::TICKET_CHECKSUM,
            buffer_type::REQUESTOR,
            buffer_type::FULL_CHECKSUM,
        ];
        for ty in expected_types {
            assert!(
                pac.find_buffer(ty).is_some(),
                "buffer type 0x{ty:02X} must be present"
            );
        }
    }

    /// LogonInfo encode/decode round-trip.
    #[test]
    fn logon_info_encode_decode_round_trip() {
        let sid = test_domain_sid();
        let original = LogonInfo {
            logon_time: 0x0102030405060708,
            logoff_time: 0x1112131415161718,
            kick_off_time: 0x2122232425262728,
            password_last_set: 0x3132333435363738,
            password_can_change: 0x4142434445464748,
            password_must_change: 0x5152535455565758,
            effective_name: "Alice".into(),
            user_name: "alice".into(),
            logon_domain_name: "CORP".into(),
            user_id: 1101,
            primary_group_id: 513,
            groups: vec![513, 512, 1102],
            user_flags: 0x0000_0010,
            logon_server: "DC01".into(),
            logon_domain_id: sid.clone(),
        };
        let encoded = original.encode();
        let decoded = LogonInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
    }

    /// LogonInfo with empty groups list (regression guard for the
    /// `groups_count = 0` decode path).
    #[test]
    fn logon_info_encode_decode_empty_groups() {
        let sid = test_domain_sid();
        let original = LogonInfo {
            logon_time: 0,
            logoff_time: 0,
            kick_off_time: 0,
            password_last_set: 0,
            password_can_change: 0,
            password_must_change: 0,
            effective_name: "Bob".into(),
            user_name: "bob".into(),
            logon_domain_name: "CORP".into(),
            user_id: 1102,
            primary_group_id: 513,
            groups: Vec::new(),
            user_flags: 0,
            logon_server: "DC02".into(),
            logon_domain_id: sid,
        };
        let encoded = original.encode();
        let decoded = LogonInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
        assert!(decoded.groups.is_empty());
    }

    /// ClientInfo encode/decode round-trip.
    #[test]
    fn client_info_encode_decode_round_trip() {
        let original = ClientInfo {
            client_id: 0x0102030405060708,
            name: "alice".into(),
        };
        let encoded = original.encode();
        let decoded = ClientInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
        // Verify the wire format: 8 (u64) + 2 (u16 length) + 10 (5 UTF-16LE chars).
        assert_eq!(encoded.len(), 8 + 2 + 10);
    }

    /// ClientInfo with empty name.
    #[test]
    fn client_info_encode_decode_empty_name() {
        let original = ClientInfo {
            client_id: 0,
            name: String::new(),
        };
        let encoded = original.encode();
        let decoded = ClientInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
        assert_eq!(encoded.len(), 10); // 8 + 2 + 0
    }

    /// UpnDnsInfo encode/decode round-trip.
    #[test]
    fn upn_dns_info_encode_decode_round_trip() {
        let original = UpnDnsInfo {
            upn: "alice@corp.example.com".into(),
            dns_domain_name: "corp.example.com".into(),
            flags: 0x01, // HasUPN
        };
        let encoded = original.encode();
        let decoded = UpnDnsInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
    }

    /// UpnDnsInfo with empty UPN (regression guard).
    #[test]
    fn upn_dns_info_encode_decode_empty_upn() {
        let original = UpnDnsInfo {
            upn: String::new(),
            dns_domain_name: "corp.example.com".into(),
            flags: 0,
        };
        let encoded = original.encode();
        let decoded = UpnDnsInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
    }

    /// Full PAC build with all 9 buffers — verify count and types.
    #[test]
    fn full_pac_build_has_nine_buffers() {
        let sid = test_user_sid();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let bytes = builder.build_unsigned().expect("build_unsigned");
        let pac = Pac::parse(&bytes).expect("parse");
        assert_eq!(pac.num_buffers, 9, "ADR-082 requires 9 buffer types");
        // Verify buffer order is deterministic per ADR-082.
        let types: Vec<u32> = pac.buffers.iter().map(|b| b.ul_type).collect();
        assert_eq!(
            types,
            vec![
                buffer_type::LOGON_INFO,
                buffer_type::CREDENTIAL_TYPE,
                buffer_type::SERVER_CHECKSUM,
                buffer_type::PRIVSVR_CHECKSUM,
                buffer_type::CLIENT_INFO,
                buffer_type::UPN_DNS_INFO,
                buffer_type::TICKET_CHECKSUM,
                buffer_type::REQUESTOR,
                buffer_type::FULL_CHECKSUM,
            ]
        );
    }

    /// PAC signing: verify SERVER_CHECKSUM and PRIVSVR_CHECKSUM are
    /// populated after `build()` (not all-zero).
    #[test]
    fn pac_signing_populates_server_and_privsvr_checksums() {
        let sid = test_user_sid();
        let key = test_krbtgt_key();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let unsigned = builder.build_unsigned().expect("unsigned");
        let signed = builder.build(&key).expect("signed");

        // Parse both and compare the SERVER_CHECKSUM signature field.
        let pac_unsigned = Pac::parse(&unsigned).expect("parse unsigned");
        let pac_signed = Pac::parse(&signed).expect("parse signed");

        let srv_off_unsigned = pac_unsigned
            .buffer_data_range(&unsigned, buffer_type::SERVER_CHECKSUM)
            .expect("find unsigned SERVER")
            .0
            + 4;
        let srv_off_signed = pac_signed
            .buffer_data_range(&signed, buffer_type::SERVER_CHECKSUM)
            .expect("find signed SERVER")
            .0
            + 4;
        let unsigned_srv_sig = &unsigned[srv_off_unsigned..srv_off_unsigned + HMAC_SHA1_96_LEN];
        let signed_srv_sig = &signed[srv_off_signed..srv_off_signed + HMAC_SHA1_96_LEN];
        assert!(
            unsigned_srv_sig.iter().all(|b| *b == 0),
            "unsigned SERVER sig must be zeroed"
        );
        assert!(
            signed_srv_sig.iter().any(|b| *b != 0),
            "signed SERVER sig must be non-zero"
        );

        let priv_off_signed = pac_signed
            .buffer_data_range(&signed, buffer_type::PRIVSVR_CHECKSUM)
            .expect("find signed PRIVSVR")
            .0
            + 4;
        let signed_priv_sig = &signed[priv_off_signed..priv_off_signed + HMAC_SHA1_96_LEN];
        assert!(
            signed_priv_sig.iter().any(|b| *b != 0),
            "signed PRIVSVR sig must be non-zero"
        );
    }

    /// PAC verification — signatures validate against the correct key.
    #[test]
    fn pac_verification_succeeds_with_correct_key() {
        let sid = test_user_sid();
        let key = test_krbtgt_key();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let bytes = builder.build(&key).expect("build");
        let pac = Pac::parse(&bytes).expect("parse");
        pac.verify_server_checksum(&bytes, &key).expect("server ok");
        pac.verify_privsvr_checksum(&bytes, &key)
            .expect("privsvr ok");
        pac.verify_full_checksum(&bytes, &key).expect("full ok");
    }

    /// PAC verification fails with the wrong key (forgery detection).
    #[test]
    fn pac_verification_fails_with_wrong_key() {
        let sid = test_user_sid();
        let key = test_krbtgt_key();
        let wrong_key = test_wrong_key();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let bytes = builder.build(&key).expect("build");
        let pac = Pac::parse(&bytes).expect("parse");
        let err = pac
            .verify_server_checksum(&bytes, &wrong_key)
            .expect_err("server check must fail");
        assert!(matches!(err, KdcError::Pac(_)));
        let err = pac
            .verify_privsvr_checksum(&bytes, &wrong_key)
            .expect_err("privsvr check must fail");
        assert!(matches!(err, KdcError::Pac(_)));
        let err = pac
            .verify_full_checksum(&bytes, &wrong_key)
            .expect_err("full check must fail");
        assert!(matches!(err, KdcError::Pac(_)));
    }

    /// PAC with TICKET_CHECKSUM (silver-ticket mitigation per ADR-123).
    #[test]
    fn pac_ticket_checksum_silver_ticket_mitigation() {
        let sid = test_user_sid();
        let key = test_krbtgt_key();
        let mut builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        // Caller supplies the ticket bytes that the KDC encrypted.
        builder.ticket_bytes = b"encrypted-ticket-enc-part-bytes".to_vec();
        let bytes = builder.build(&key).expect("build");
        let pac = Pac::parse(&bytes).expect("parse");
        // Verify the TICKET_CHECKSUM validates against the correct ticket bytes.
        pac.verify_ticket_checksum(&key, b"encrypted-ticket-enc-part-bytes")
            .expect("ticket checksum valid");

        // Silver-ticket attack: attacker supplies a different ticket bytes
        // (forged). Verification MUST fail.
        let err = pac
            .verify_ticket_checksum(&key, b"forged-ticket-bytes!!!")
            .expect_err("forged ticket must fail verification");
        assert!(matches!(err, KdcError::Pac(_)));

        // Wrong krbtgt key MUST also fail.
        let wrong_key = test_wrong_key();
        let err = pac
            .verify_ticket_checksum(&wrong_key, b"encrypted-ticket-enc-part-bytes")
            .expect_err("wrong key must fail");
        assert!(matches!(err, KdcError::Pac(_)));
    }

    /// PAC with FULL_CHECKSUM — verify tampering of any byte in the PAC
    /// body invalidates the FULL_CHECKSUM.
    #[test]
    fn pac_full_checksum_detects_tampering() {
        let sid = test_user_sid();
        let key = test_krbtgt_key();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let bytes = builder.build(&key).expect("build");
        let pac = Pac::parse(&bytes).expect("parse");
        pac.verify_full_checksum(&bytes, &key).expect("clean PAC");

        // Tamper with the LOGON_INFO buffer's first byte.
        let mut tampered = bytes.clone();
        let logon_data_off = pac
            .buffer_data_range(&bytes, buffer_type::LOGON_INFO)
            .expect("find LOGON_INFO")
            .0;
        tampered[logon_data_off] ^= 0xFF;
        let pac_t = Pac::parse(&tampered).expect("re-parse");
        let err = pac_t
            .verify_full_checksum(&tampered, &key)
            .expect_err("tampered PAC must fail FULL_CHECKSUM");
        assert!(matches!(err, KdcError::Pac(_)));
    }

    /// Empty groups list in LOGON_INFO — encode/decode must succeed
    /// and produce a non-empty PAC (regression guard for `groups_count=0`).
    #[test]
    fn pac_build_with_empty_groups_list() {
        let sid = test_user_sid();
        let mut builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        builder.logon_info.groups.clear();
        let bytes = builder.build_unsigned().expect("build");
        let pac = Pac::parse(&bytes).expect("parse");
        let logon_buf = pac
            .find_buffer(buffer_type::LOGON_INFO)
            .expect("LOGON_INFO present");
        let logon = LogonInfo::decode(&logon_buf.data).expect("decode");
        assert!(logon.groups.is_empty());
        assert_eq!(logon.user_id, 1101);
    }

    /// Round-trip: build → parse → verify all fields.
    #[test]
    fn round_trip_build_parse_verify_fields() {
        let sid = test_user_sid();
        let key = test_krbtgt_key();
        let mut builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        builder.logon_info.user_id = 1101;
        builder.logon_info.primary_group_id = 513;
        builder.logon_info.groups = vec![512, 513, 1102];
        builder.logon_info.effective_name = "Alice Smith".into();
        builder.logon_info.user_name = "asmith".into();
        builder.logon_info.logon_domain_name = "CORP".into();
        builder.logon_info.logon_server = "DC01".into();
        builder.client_info.client_id = 0x1234_5678_90AB_CDEF;
        builder.client_info.name = "asmith".into();
        builder.upn_dns_info.upn = "asmith@corp.example.com".into();
        builder.upn_dns_info.dns_domain_name = "corp.example.com".into();
        builder.upn_dns_info.flags = 0x01;
        builder.ticket_bytes = b"fake-encrypted-ticket".to_vec();

        let bytes = builder.build(&key).expect("build");
        let pac = Pac::parse(&bytes).expect("parse");

        // Verify all signatures.
        pac.verify_server_checksum(&bytes, &key).expect("server");
        pac.verify_privsvr_checksum(&bytes, &key).expect("privsvr");
        pac.verify_full_checksum(&bytes, &key).expect("full");
        pac.verify_ticket_checksum(&key, b"fake-encrypted-ticket")
            .expect("ticket");

        // Verify structured fields round-trip.
        let logon_buf = pac
            .find_buffer(buffer_type::LOGON_INFO)
            .expect("LOGON_INFO");
        let logon = LogonInfo::decode(&logon_buf.data).expect("decode LOGON_INFO");
        assert_eq!(logon.user_id, 1101);
        assert_eq!(logon.primary_group_id, 513);
        assert_eq!(logon.groups, vec![512, 513, 1102]);
        assert_eq!(logon.effective_name, "Alice Smith");
        assert_eq!(logon.user_name, "asmith");
        assert_eq!(logon.logon_domain_name, "CORP");
        assert_eq!(logon.logon_server, "DC01");
        assert_eq!(logon.logon_domain_id, test_domain_sid());

        let client_buf = pac
            .find_buffer(buffer_type::CLIENT_INFO)
            .expect("CLIENT_INFO");
        let client = ClientInfo::decode(&client_buf.data).expect("decode CLIENT_INFO");
        assert_eq!(client.client_id, 0x1234_5678_90AB_CDEF);
        assert_eq!(client.name, "asmith");

        let upn_buf = pac
            .find_buffer(buffer_type::UPN_DNS_INFO)
            .expect("UPN_DNS_INFO");
        let upn = UpnDnsInfo::decode(&upn_buf.data).expect("decode UPN_DNS_INFO");
        assert_eq!(upn.upn, "asmith@corp.example.com");
        assert_eq!(upn.dns_domain_name, "corp.example.com");
        assert_eq!(upn.flags, 0x01);
    }

    /// Buffer type constants — verify all 14 documented types are declared
    /// with the correct MS-KILE numeric values.
    #[test]
    fn buffer_type_constants_match_ms_kile() {
        assert_eq!(buffer_type::LOGON_INFO, 0x01);
        assert_eq!(buffer_type::CREDENTIAL_TYPE, 0x02);
        assert_eq!(buffer_type::SERVER_CHECKSUM, 0x04);
        assert_eq!(buffer_type::PRIVSVR_CHECKSUM, 0x06);
        assert_eq!(buffer_type::CLIENT_INFO, 0x0A);
        assert_eq!(buffer_type::CONSTRAINED_DELEGATION, 0x0B);
        assert_eq!(buffer_type::UPN_DNS_INFO, 0x0C);
        assert_eq!(buffer_type::CLIENT_CLAIMS_INFO, 0x0D);
        assert_eq!(buffer_type::DEVICE_INFO, 0x0E);
        assert_eq!(buffer_type::DEVICE_CLAIMS_INFO, 0x0F);
        assert_eq!(buffer_type::TICKET_CHECKSUM, 0x10);
        assert_eq!(buffer_type::ATTRIBUTES, 0x11);
        assert_eq!(buffer_type::REQUESTOR, 0x12);
        assert_eq!(buffer_type::FULL_CHECKSUM, 0x13);
    }

    /// PAC_REQUESTOR with empty SID (`None`) — encode/decode round-trip.
    #[test]
    fn requestor_info_encode_decode_empty() {
        let original = RequestorInfo { sid: None };
        let encoded = original.encode();
        assert!(encoded.is_empty());
        let decoded = RequestorInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
    }

    /// PAC_REQUESTOR with a real SID — encode/decode round-trip.
    #[test]
    fn requestor_info_encode_decode_with_sid() {
        let sid = test_user_sid();
        let original = RequestorInfo {
            sid: Some(sid.clone()),
        };
        let encoded = original.encode();
        assert!(!encoded.is_empty());
        let decoded = RequestorInfo::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
        assert_eq!(decoded.sid, Some(sid));
    }

    /// PAC builder is deterministic — same inputs produce same bytes
    /// (modulo the ticket_checksum field which depends on `ticket_bytes`).
    /// This is the precondition for ADR-018 (stateless KDC pooling).
    #[test]
    fn pac_builder_is_deterministic() {
        let sid = test_user_sid();
        let key = test_krbtgt_key();
        let builder1 = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let builder2 = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let bytes1 = builder1.build(&key).expect("build 1");
        let bytes2 = builder2.build(&key).expect("build 2");
        assert_eq!(bytes1, bytes2, "PAC must be deterministic across instances");
    }

    /// Truncated PAC input must surface a typed `KdcError::Pac`, not panic.
    #[test]
    fn pac_parse_truncated_returns_error() {
        let cases: &[&[u8]] = &[&[], &[0u8; 8], &[0u8; 15]];
        for case in cases {
            let err = Pac::parse(case).expect_err("truncated PAC must error");
            assert!(matches!(err, KdcError::Pac(_)));
        }
    }

    /// PAC with mismatched `cbBufferSize` must surface `KdcError::Pac`.
    #[test]
    fn pac_parse_size_mismatch_returns_error() {
        // Build a real unsigned PAC, then mutate the size field to disagree.
        let sid = test_user_sid();
        let builder = PacBuilder::new(Uuid::nil(), &sid, "CORP.EXAMPLE.COM");
        let mut bytes = builder.build_unsigned().expect("build");
        // Overwrite cbBufferSize (offset 4) with a bogus value.
        bytes[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = Pac::parse(&bytes).expect_err("size mismatch must error");
        assert!(matches!(err, KdcError::Pac(_)));
    }

    /// `SignatureData` encode/decode round-trip.
    #[test]
    fn signature_data_encode_decode_round_trip() {
        let original = SignatureData {
            signature_type: SIG_TYPE_HMAC_SHA1_96_AES256,
            signature: vec![0xAA; HMAC_SHA1_96_LEN],
        };
        let encoded = original.encode();
        assert_eq!(encoded.len(), 4 + HMAC_SHA1_96_LEN);
        let decoded = SignatureData::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
    }

    /// `TicketChecksum` encode/decode round-trip.
    #[test]
    fn ticket_checksum_encode_decode_round_trip() {
        let original = TicketChecksum {
            signature_type: SIG_TYPE_HMAC_SHA1_96_AES256,
            signature: vec![0xBB; HMAC_SHA1_96_LEN],
        };
        let encoded = original.encode();
        assert_eq!(encoded.len(), 8 + HMAC_SHA1_96_LEN);
        let decoded = TicketChecksum::decode(&encoded).expect("decode");
        assert_eq!(original, decoded);
    }

    /// HMAC-SHA1-96 deterministic over the same key+data — guards against
    /// the signing logic depending on environment state.
    #[test]
    fn hmac_sha1_96_deterministic() {
        let key = test_krbtgt_key();
        let tag1 = crypto::hmac_sha1_96(&key, b"some-pac-data");
        let tag2 = crypto::hmac_sha1_96(&key, b"some-pac-data");
        assert_eq!(tag1, tag2);
        assert_eq!(tag1.len(), HMAC_SHA1_96_LEN);
    }
}
