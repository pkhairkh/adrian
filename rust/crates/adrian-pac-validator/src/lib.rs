#![forbid(unsafe_code)]
//! # adrian-pac-validator
//!
//! Unified PAC validator — MS-KILE buffer parsing + two-layer checksum
//! validation per ADR-083. Closes P0 priority #5 from EVALUATION.md.
//!
//! ## v0.6.0 implementation
//!
//! Real PAC parser + constant-time signature verification. Compatible with
//! the `adrian-kdc::pac::PacBuilder` output from Wave 2b.
//!
//! ## ADRs
//!
//! - ADR-082: MS-KILE-conformant PAC generation (9 buffer types)
//! - ADR-083: Two-layer PAC validation (KDC + service)
//! - ADR-123: Silver ticket mitigation (TICKET_CHECKSUM on every service accept)
//! - ADR-015: krbtgt HSM binding (Ed25519 signature)

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// PAC header on-wire type (always 0x00000000).
const PAC_HEADER_TYPE: u32 = 0x00000000;
/// PAC header version (always 0x00000000).
const PAC_HEADER_VERSION: u32 = 0x00000000;
/// PAC header length (4 * u32_le = 16 bytes).
const PAC_HEADER_LEN: usize = 16;
/// PAC buffer entry header length (u32 type + u32 size + u64 offset = 16 bytes).
const PAC_BUFFER_HEADER_LEN: usize = 16;

/// PAC buffer type tags per MS-KILE §2.1 (matching the Wave 2b builder's constants).
pub mod buffer_type {
    /// `0x01` — Logon info (KERB_VALIDATION_INFO).
    pub const LOGON_INFO: u32 = 0x01;
    /// `0x02` — Credentials type.
    pub const CREDENTIAL_TYPE: u32 = 0x02;
    /// `0x04` — Server checksum (HMAC-SHA1-96 over PAC body).
    pub const SERVER_CHECKSUM: u32 = 0x04;
    /// `0x06` — KDC/privsvr checksum (HMAC-SHA1-96 over server checksum).
    pub const PRIVSVR_CHECKSUM: u32 = 0x06;
    /// `0x0A` — Client info (name + logon FILETIME).
    pub const CLIENT_INFO: u32 = 0x0A;
    /// `0x0B` — Constrained delegation.
    pub const CONSTRAINED_DELEGATION: u32 = 0x0B;
    /// `0x0C` — UPN + DNS info.
    pub const UPN_DNS_INFO: u32 = 0x0C;
    /// `0x0D` — Client claims.
    pub const CLIENT_CLAIMS: u32 = 0x0D;
    /// `0x0E` — Device info.
    pub const DEVICE_INFO: u32 = 0x0E;
    /// `0x10` — Ticket checksum (silver ticket mitigation, ADR-123).
    pub const TICKET_CHECKSUM: u32 = 0x10;
    /// `0x12` — Requestor SID.
    pub const REQUESTOR: u32 = 0x12;
    /// `0x13` — Full PAC checksum.
    pub const FULL_CHECKSUM: u32 = 0x13;
}

/// PAC validation error.
#[derive(Debug, thiserror::Error)]
pub enum PacValidationError {
    /// Malformed PAC bytes.
    #[error("malformed PAC: {0}")]
    Malformed(String),
    /// Signature mismatch.
    #[error("signature mismatch: {0}")]
    SignatureMismatch(String),
    /// Expired PAC.
    #[error("expired PAC")]
    Expired,
    /// Required buffer missing.
    #[error("missing required buffer: type 0x{0:02X}")]
    MissingBuffer(u32),
}

/// A single PAC buffer entry (type + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacBuffer {
    /// Buffer type ID (e.g. `buffer_type::LOGON_INFO`).
    pub ul_type: u32,
    /// Buffer payload bytes (not including the 16-byte entry header).
    pub data: Vec<u8>,
}

/// Parsed PAC structure — the header + an ordered list of buffer entries.
#[derive(Debug, Clone)]
pub struct Pac {
    /// Total PAC byte length (including header).
    pub total_size: u32,
    /// Number of buffers.
    pub num_buffers: u32,
    /// Buffers in their on-wire order.
    pub buffers: Vec<PacBuffer>,
}

impl Pac {
    /// Parse raw PAC bytes into a [`Pac`].
    ///
    /// The wire format (matching the Wave 2b `PacBuilder`):
    /// ```text
    /// Header (16 bytes):
    ///   ulType:        u32_le (0x00000000)
    ///   cbBufferSize:  u32_le (total PAC length)
    ///   ulNumBuffers:  u32_le
    ///   ulVersion:     u32_le (0x00000000)
    ///
    /// Buffer entry (16 bytes header + data):
    ///   ulType:        u32_le
    ///   cbBufferSize:  u32_le (data length, not including header)
    ///   Offset:        u64_le (from start of PAC, 8-byte aligned)
    ///   Data:          [u8; cbBufferSize]
    /// ```
    pub fn parse(bytes: &[u8]) -> Result<Self, PacValidationError> {
        if bytes.len() < PAC_HEADER_LEN {
            return Err(PacValidationError::Malformed(format!(
                "header truncated (got {len} bytes, need {PAC_HEADER_LEN})",
                len = bytes.len()
            )));
        }
        let ul_type = read_u32_le(bytes, 0)?;
        if ul_type != PAC_HEADER_TYPE {
            return Err(PacValidationError::Malformed(format!(
                "header ulType=0x{ul_type:08X}, expected 0x{PAC_HEADER_TYPE:08X}"
            )));
        }
        let total_size = read_u32_le(bytes, 4)? as usize;
        if total_size != bytes.len() {
            return Err(PacValidationError::Malformed(format!(
                "cbBufferSize={total_size} != actual len={actual}",
                actual = bytes.len()
            )));
        }
        let num_buffers = read_u32_le(bytes, 8)?;
        let version = read_u32_le(bytes, 12)?;
        if version != PAC_HEADER_VERSION {
            return Err(PacValidationError::Malformed(format!(
                "ulVersion=0x{version:08X}, expected 0x{PAC_HEADER_VERSION:08X}"
            )));
        }

        let mut buffers = Vec::with_capacity(num_buffers as usize);
        let mut off = PAC_HEADER_LEN;
        for i in 0..num_buffers {
            if off + PAC_BUFFER_HEADER_LEN > bytes.len() {
                return Err(PacValidationError::Malformed(format!(
                    "buffer {i} header out of bounds (off={off})"
                )));
            }
            let b_type = read_u32_le(bytes, off)?;
            let b_size = read_u32_le(bytes, off + 4)? as usize;
            let b_offset = read_u64_le(bytes, off + 8)? as usize;

            // Validate offset is 8-byte aligned and within bounds.
            if !b_offset.is_multiple_of(8) {
                return Err(PacValidationError::Malformed(format!(
                    "buffer {i} offset {b_offset} not 8-byte aligned"
                )));
            }
            if b_offset + b_size > bytes.len() {
                return Err(PacValidationError::Malformed(format!(
                    "buffer {i} data out of bounds (offset={b_offset}, size={b_size}, pac_len={})",
                    bytes.len()
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

    /// Find a buffer by type.
    pub fn get_buffer(&self, buffer_type: u32) -> Option<&PacBuffer> {
        self.buffers.iter().find(|b| b.ul_type == buffer_type)
    }

    /// Get the LOGON_INFO buffer data.
    pub fn logon_info(&self) -> Option<&[u8]> {
        self.get_buffer(buffer_type::LOGON_INFO)
            .map(|b| b.data.as_slice())
    }

    /// Get the SERVER_CHECKSUM buffer data.
    pub fn server_checksum(&self) -> Option<&[u8]> {
        self.get_buffer(buffer_type::SERVER_CHECKSUM)
            .map(|b| b.data.as_slice())
    }

    /// Get the PRIVSVR_CHECKSUM buffer data.
    pub fn privsvr_checksum(&self) -> Option<&[u8]> {
        self.get_buffer(buffer_type::PRIVSVR_CHECKSUM)
            .map(|b| b.data.as_slice())
    }

    /// Get the CLIENT_INFO buffer data.
    pub fn client_info(&self) -> Option<&[u8]> {
        self.get_buffer(buffer_type::CLIENT_INFO)
            .map(|b| b.data.as_slice())
    }

    /// Get the UPN_DNS_INFO buffer data.
    pub fn upn_dns_info(&self) -> Option<&[u8]> {
        self.get_buffer(buffer_type::UPN_DNS_INFO)
            .map(|b| b.data.as_slice())
    }

    /// Get the TICKET_CHECKSUM buffer data (ADR-123 silver ticket mitigation).
    pub fn ticket_checksum(&self) -> Option<&[u8]> {
        self.get_buffer(buffer_type::TICKET_CHECKSUM)
            .map(|b| b.data.as_slice())
    }

    /// Validate the KDC (privsvr) checksum — Layer 1 of ADR-083.
    ///
    /// This verifies that the PAC was issued by a trusted KDC by checking
    /// the PRIVSVR_CHECKSUM (HMAC-SHA1-96 over the SERVER_CHECKSUM signature,
    /// using the krbtgt key).
    ///
    /// # Arguments
    /// * `krbtgt_key` — The krbtgt long-term key (32 bytes for AES-256).
    pub fn validate_kdc_checksum(&self, krbtgt_key: &[u8]) -> Result<(), PacValidationError> {
        let server_buf = self
            .server_checksum()
            .ok_or(PacValidationError::MissingBuffer(
                buffer_type::SERVER_CHECKSUM,
            ))?;
        let privsvr_buf = self
            .privsvr_checksum()
            .ok_or(PacValidationError::MissingBuffer(
                buffer_type::PRIVSVR_CHECKSUM,
            ))?;

        // The SERVER_CHECKSUM buffer contains: signature_type (4 bytes) + signature (12 bytes)
        if server_buf.len() < 4 + 12 {
            return Err(PacValidationError::Malformed(format!(
                "SERVER_CHECKSUM too short ({} bytes, need >= 16)",
                server_buf.len()
            )));
        }
        let server_sig = &server_buf[4..16]; // 12-byte HMAC-SHA1-96

        // The PRIVSVR_CHECKSUM buffer contains: signature_type (4 bytes) + signature (12 bytes)
        if privsvr_buf.len() < 4 + 12 {
            return Err(PacValidationError::Malformed(format!(
                "PRIVSVR_CHECKSUM too short ({} bytes, need >= 16)",
                privsvr_buf.len()
            )));
        }
        let privsvr_sig = &privsvr_buf[4..16]; // 12-byte HMAC-SHA1-96

        // Compute HMAC-SHA1-96 over the SERVER_CHECKSUM signature field using krbtgt key.
        let expected_sig = compute_hmac_sha1_96(krbtgt_key, server_sig);

        // Constant-time comparison.
        if expected_sig.ct_eq(privsvr_sig).unwrap_u8() == 0 {
            return Err(PacValidationError::SignatureMismatch(
                "PRIVSVR_CHECKSUM does not match (KDC signature verification failed)".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate the service checksum — Layer 2 of ADR-083.
    ///
    /// This verifies the PAC's integrity by recomputing the SERVER_CHECKSUM
    /// (HMAC-SHA1-96 over the entire PAC with all signature fields zeroed,
    /// using the service's long-term key).
    ///
    /// # Arguments
    /// * `service_key` — The service principal's long-term key (32 bytes for AES-256).
    pub fn validate_service_checksum(
        &self,
        service_key: &[u8],
        pac_bytes: &[u8],
    ) -> Result<(), PacValidationError> {
        let server_buf = self
            .server_checksum()
            .ok_or(PacValidationError::MissingBuffer(
                buffer_type::SERVER_CHECKSUM,
            ))?;

        if server_buf.len() < 4 + 12 {
            return Err(PacValidationError::Malformed(format!(
                "SERVER_CHECKSUM too short ({} bytes, need >= 16)",
                server_buf.len()
            )));
        }
        let stored_sig = &server_buf[4..16]; // 12-byte HMAC-SHA1-96

        // To verify: zero all signature fields in a copy of the PAC, then
        // compute HMAC-SHA1-96 over the modified PAC with the service key.
        let mut pac_copy = pac_bytes.to_vec();

        // Zero all signature fields (SERVER_CHECKSUM, PRIVSVR_CHECKSUM, TICKET_CHECKSUM, FULL_CHECKSUM).
        zero_signature_fields(&mut pac_copy, &self.buffers)?;

        // Compute HMAC-SHA1-96 over the zeroed-sig PAC with the service key.
        let expected_sig = compute_hmac_sha1_96(service_key, &pac_copy);

        // Constant-time comparison.
        if expected_sig.ct_eq(stored_sig).unwrap_u8() == 0 {
            return Err(PacValidationError::SignatureMismatch(
                "SERVER_CHECKSUM does not match (service signature verification failed)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Full validation: both KDC and service checksums (ADR-083 two-layer).
    ///
    /// Also validates the TICKET_CHECKSUM if present (ADR-123 silver ticket
    /// mitigation).
    pub fn validate(
        &self,
        pac_bytes: &[u8],
        service_key: &[u8],
        krbtgt_key: &[u8],
    ) -> Result<(), PacValidationError> {
        // Layer 2: verify service checksum.
        self.validate_service_checksum(service_key, pac_bytes)?;
        // Layer 1: verify KDC checksum.
        self.validate_kdc_checksum(krbtgt_key)?;
        // Optional: verify TICKET_CHECKSUM if present (ADR-123).
        if let Some(ticket_buf) = self.ticket_checksum() {
            if ticket_buf.len() >= 4 + 12 {
                let ticket_sig = &ticket_buf[4..16];
                // The TICKET_CHECKSUM is computed over the ticket bytes.
                // For v0.6.0, we verify that the checksum is present and
                // non-zero. Full ticket checksum verification requires the
                // ticket bytes, which the caller must provide separately.
                if ticket_sig.iter().all(|&b| b == 0) {
                    return Err(PacValidationError::SignatureMismatch(
                        "TICKET_CHECKSUM is all zeros (silver ticket mitigation not enforced)"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Zero all signature fields in the PAC copy (for HMAC verification).
fn zero_signature_fields(
    pac_bytes: &mut [u8],
    buffers: &[PacBuffer],
) -> Result<(), PacValidationError> {
    for buf in buffers {
        match buf.ul_type {
            buffer_type::SERVER_CHECKSUM
            | buffer_type::PRIVSVR_CHECKSUM
            | buffer_type::TICKET_CHECKSUM
            | buffer_type::FULL_CHECKSUM
                if buf.data.len() >= 16 =>
            {
                // Each signature buffer has: signature_type (4 bytes) + signature (12 bytes).
                // Zero the signature field (bytes 4..16).
                let pac_offset = find_buffer_offset(pac_bytes, buf.ul_type)?;
                if pac_offset + 16 <= pac_bytes.len() {
                    pac_bytes[pac_offset + 4..pac_offset + 16].fill(0);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Find the data offset of a buffer type in the raw PAC bytes.
fn find_buffer_offset(pac_bytes: &[u8], target_type: u32) -> Result<usize, PacValidationError> {
    if pac_bytes.len() < PAC_HEADER_LEN {
        return Err(PacValidationError::Malformed("PAC too short".into()));
    }
    let num_buffers = read_u32_le(pac_bytes, 8)?;
    let mut off = PAC_HEADER_LEN;
    for _ in 0..num_buffers {
        if off + PAC_BUFFER_HEADER_LEN > pac_bytes.len() {
            break;
        }
        let b_type = read_u32_le(pac_bytes, off)?;
        let _b_size = read_u32_le(pac_bytes, off + 4)?;
        let b_offset = read_u64_le(pac_bytes, off + 8)? as usize;
        if b_type == target_type {
            return Ok(b_offset);
        }
        off += PAC_BUFFER_HEADER_LEN;
    }
    Err(PacValidationError::MissingBuffer(target_type))
}

/// Compute HMAC-SHA1-96 (HMAC-SHA1 truncated to 12 bytes).
fn compute_hmac_sha1_96(key: &[u8], data: &[u8]) -> [u8; 12] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, PacValidationError> {
    if off + 4 > buf.len() {
        return Err(PacValidationError::Malformed(format!(
            "u32 read out of bounds at offset {off}"
        )));
    }
    Ok(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

fn read_u64_le(buf: &[u8], off: usize) -> Result<u64, PacValidationError> {
    if off + 8 > buf.len() {
        return Err(PacValidationError::Malformed(format!(
            "u64 read out of bounds at offset {off}"
        )));
    }
    Ok(u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ]))
}

// =========================================================================
// KERB_VALIDATION_INFO (MS-NDR encoded LOGON_INFO buffer)
// =========================================================================
//
// Per MS-PAC §2.1 + MS-DTYP, the LOGON_INFO buffer (PAC buffer type 0x01)
// contains an NDR20-encoded KERB_VALIDATION_INFO structure.  This is a
// top-level NDR struct with embedded pointers for the RPC_UNICODE_STRING
// fields and the conformant arrays (GroupIds, ExtraSids, ResourceGroups).
//
// The NDR20 wire layout (4-byte pointers) is:
//   [fixed-size fields: 6 FILETIMEs = 48 bytes]
//   [6 RPC_UNICODE_STRING headers: 6 × (u16 Length, u16 MaxLength, u4 ptr) = 72 bytes]
//   [LogonCount: u16, BadPasswordCount: u16]
//   [UserId: u32, PrimaryGroupId: u32]
//   [GroupIds pointer: u32 (0 if empty)]
//   [UserFlags: u32]
//   [UserSessionKey: 2 × u64 = 16 bytes]
//   [LogonServer, LogonDomainName: 2 × RPC_UNICODE_STRING header]
//   [LogonDomainId pointer: u32 (SID pointer)]
//   [UserAccountControl: u32, SubAuthStatus: u32]
//   [LastSuccessfulILogon, LastFailedILogon: 2 × FILETIME]
//   [FailedILogonCount: u32, Reserved3: u32]
//   [ExtraSids pointer: u32]
//   [ResourceGroupDomainSid pointer: u32]
//   [ResourceGroups pointer: u32]
//   [— conformant data follows in pointer order —]
//
// This implementation encodes/decodes a representative subset of the
// fields (the ones the framework's PAC validator actually inspects).
// Strings and SIDs are always emitted; the GroupIds / ExtraSids /
// ResourceGroups arrays are optional (encoded as null pointers when
// empty).

use adrian_dcerpc::ndr::{NdrReader, NdrWriter};

/// A KERB_VALIDATION_INFO structure (per MS-PAC §2.1 / MS-DTYP) encoded
/// as a PAC LOGON_INFO buffer.  This is the NDR20 on-wire representation
/// of the user's logon context — the KDC fills it in at TGT-issue time
/// and the service validates it at accept time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerbValidationInfo {
    /// LogonTime (FILETIME — 100ns ticks since 1601-01-01 UTC).
    pub logon_time: u64,
    /// LogoffTime (FILETIME; 0 = never).
    pub logoff_time: u64,
    /// KickOffTime (FILETIME; 0 = never).
    pub kickoff_time: u64,
    /// PasswordLastSet (FILETIME).
    pub password_last_set: u64,
    /// PasswordCanChange (FILETIME).
    pub password_can_change: u64,
    /// PasswordMustChange (FILETIME; 0 = never).
    pub password_must_change: u64,
    /// EffectiveName (the user's sAMAccountName).
    pub effective_name: String,
    /// FullName (displayName).
    pub full_name: String,
    /// LogonScript.
    pub logon_script: String,
    /// ProfilePath.
    pub profile_path: String,
    /// HomeDirectory.
    pub home_directory: String,
    /// HomeDirectoryDrive.
    pub home_directory_drive: String,
    /// LogonCount (u16).
    pub logon_count: u16,
    /// BadPasswordCount (u16).
    pub bad_password_count: u16,
    /// UserId (RID — e.g. 500 for Administrator).
    pub user_id: u32,
    /// PrimaryGroupId (e.g. 513 for Domain Users).
    pub primary_group_id: u32,
    /// GroupIds — list of (group_rid, attributes) pairs.
    pub group_ids: Vec<(u32, u32)>,
    /// UserFlags.
    pub user_flags: u32,
    /// UserSessionKey (2 × u64 = 16 bytes).
    pub user_session_key: [u8; 16],
    /// LogonServer (NetBIOS name).
    pub logon_server: String,
    /// LogonDomainName (NetBIOS name).
    pub logon_domain_name: String,
    /// LogonDomainId (domain SID, binary per MS-DTYP §2.4.2).
    pub logon_domain_id: Vec<u8>,
    /// UserAccountControl flags.
    pub user_account_control: u32,
    /// SubAuthStatus.
    pub sub_auth_status: u32,
    /// LastSuccessfulILogon (FILETIME).
    pub last_successful_ilogon: u64,
    /// LastFailedILogon (FILETIME).
    pub last_failed_ilogon: u64,
    /// FailedILogonCount.
    pub failed_ilogon_count: u32,
    /// Reserved3.
    pub reserved3: u32,
    /// ExtraSids — list of (sid_bytes, attributes) pairs.
    pub extra_sids: Vec<(Vec<u8>, u32)>,
    /// ResourceGroupDomainSid (binary SID, or empty if not present).
    pub resource_group_domain_sid: Vec<u8>,
    /// ResourceGroups — list of (group_rid, attributes) pairs.
    pub resource_groups: Vec<(u32, u32)>,
}

impl KerbValidationInfo {
    /// Encode this structure as NDR20 bytes suitable for use as a PAC
    /// LOGON_INFO buffer (type 0x01).  Uses 4-byte pointers (NDR20).
    ///
    /// The encoding strategy is:
    /// 1. Write all fixed-size fields in order.
    /// 2. For each RPC_UNICODE_STRING, write a header (Length, MaxLength,
    ///    pointer) and record the pointer value (the byte offset of the
    ///    string data relative to the start of the structure, filled in
    ///    during the fixup pass).
    /// 3. For each conformant array, write a pointer (0 if empty).
    /// 4. After all fixed fields, write the conformant data (strings,
    ///    SIDs, arrays) in the order their pointers appeared.
    pub fn encode_ndr(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        // 6 FILETIMEs (each u64, 8-byte aligned).
        w.write_uint64(self.logon_time);
        w.write_uint64(self.logoff_time);
        w.write_uint64(self.kickoff_time);
        w.write_uint64(self.password_last_set);
        w.write_uint64(self.password_can_change);
        w.write_uint64(self.password_must_change);

        // 6 RPC_UNICODE_STRING headers — each is (u16 Length, u16 MaxLength, u32 pointer).
        // The pointers are filled in during a fixup pass; for now we write
        // placeholder 0s and record the field positions.
        let str_fields = [
            &self.effective_name,
            &self.full_name,
            &self.logon_script,
            &self.profile_path,
            &self.home_directory,
            &self.home_directory_drive,
        ];
        let mut str_ptr_positions = Vec::with_capacity(6);
        for s in &str_fields {
            let units: Vec<u16> = s.encode_utf16().collect();
            let byte_len = (units.len() * 2) as u16;
            w.align(2);
            w.write_uint16_raw(byte_len); // Length (no NUL)
            w.write_uint16_raw(byte_len.saturating_add(2)); // MaxLength (with NUL)
            w.align(4);
            let ptr_pos = w.position();
            w.write_uint32_raw(0); // placeholder pointer
            str_ptr_positions.push((ptr_pos, s.as_str()));
        }

        // LogonCount + BadPasswordCount (u16 each, 2-byte aligned).
        w.align(2);
        w.write_uint16_raw(self.logon_count);
        w.write_uint16_raw(self.bad_password_count);

        // UserId + PrimaryGroupId (u32 each, 4-byte aligned).
        w.write_uint32(self.user_id);
        w.write_uint32(self.primary_group_id);

        // GroupIds pointer (0 if empty — null pointer).
        let group_ids_ptr_pos = {
            w.align(4);
            let p = w.position();
            w.write_uint32_raw(0); // placeholder
            p
        };

        // UserFlags (u32).
        w.write_uint32(self.user_flags);

        // UserSessionKey (2 × u64, 8-byte aligned).
        w.write_uint64(u64::from_le_bytes(
            self.user_session_key[0..8].try_into().unwrap(),
        ));
        w.write_uint64(u64::from_le_bytes(
            self.user_session_key[8..16].try_into().unwrap(),
        ));

        // LogonServer + LogonDomainName (2 × RPC_UNICODE_STRING header).
        let str_fields2 = [&self.logon_server, &self.logon_domain_name];
        let mut str_ptr_positions2 = Vec::with_capacity(2);
        for s in &str_fields2 {
            let units: Vec<u16> = s.encode_utf16().collect();
            let byte_len = (units.len() * 2) as u16;
            w.align(2);
            w.write_uint16_raw(byte_len);
            w.write_uint16_raw(byte_len.saturating_add(2));
            w.align(4);
            let ptr_pos = w.position();
            w.write_uint32_raw(0);
            str_ptr_positions2.push((ptr_pos, s.as_str()));
        }

        // LogonDomainId pointer (SID, 0 if empty).
        let logon_domain_id_ptr_pos = {
            w.align(4);
            let p = w.position();
            w.write_uint32_raw(0);
            p
        };

        // UserAccountControl + SubAuthStatus (u32 each).
        w.write_uint32(self.user_account_control);
        w.write_uint32(self.sub_auth_status);

        // LastSuccessfulILogon + LastFailedILogon (FILETIMEs).
        w.write_uint64(self.last_successful_ilogon);
        w.write_uint64(self.last_failed_ilogon);

        // FailedILogonCount + Reserved3 (u32 each).
        w.write_uint32(self.failed_ilogon_count);
        w.write_uint32(self.reserved3);

        // ExtraSids pointer (0 if empty).
        let extra_sids_ptr_pos = {
            w.align(4);
            let p = w.position();
            w.write_uint32_raw(0);
            p
        };

        // ResourceGroupDomainSid pointer (0 if empty).
        let rg_domain_sid_ptr_pos = {
            w.align(4);
            let p = w.position();
            w.write_uint32_raw(0);
            p
        };

        // ResourceGroups pointer (0 if empty).
        let resource_groups_ptr_pos = {
            w.align(4);
            let p = w.position();
            w.write_uint32_raw(0);
            p
        };

        // ---- Conformant data (in pointer order) ----

        let mut buf = w.into_bytes();

        // 6 RPC_UNICODE_STRINGs (effective_name ... home_directory_drive).
        for (ptr_pos, s) in &str_ptr_positions {
            if s.is_empty() {
                continue;
            }
            // Write the conformant string data at the end of the buffer.
            let data_offset = buf.len() as u32;
            // NDR conformant string: max_count, offset, actual_count, data.
            let units: Vec<u16> = s.encode_utf16().collect();
            let max_count = (units.len() + 1) as u32; // +1 for NUL
            buf.extend_from_slice(&max_count.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes()); // offset
            buf.extend_from_slice(&max_count.to_le_bytes()); // actual_count
            for u in &units {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes()); // NUL terminator
                                                        // Fixup the pointer.
            buf[*ptr_pos..*ptr_pos + 4].copy_from_slice(&data_offset.to_le_bytes());
        }

        // GroupIds conformant array.
        if !self.group_ids.is_empty() {
            let data_offset = buf.len() as u32;
            let count = self.group_ids.len() as u32;
            buf.extend_from_slice(&count.to_le_bytes()); // max_count
            for (rid, attrs) in &self.group_ids {
                buf.extend_from_slice(&rid.to_le_bytes());
                buf.extend_from_slice(&attrs.to_le_bytes());
            }
            buf[group_ids_ptr_pos..group_ids_ptr_pos + 4]
                .copy_from_slice(&data_offset.to_le_bytes());
        }

        // 2 more RPC_UNICODE_STRINGs (logon_server, logon_domain_name).
        for (ptr_pos, s) in &str_ptr_positions2 {
            if s.is_empty() {
                continue;
            }
            let data_offset = buf.len() as u32;
            let units: Vec<u16> = s.encode_utf16().collect();
            let max_count = (units.len() + 1) as u32;
            buf.extend_from_slice(&max_count.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&max_count.to_le_bytes());
            for u in &units {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf[*ptr_pos..*ptr_pos + 4].copy_from_slice(&data_offset.to_le_bytes());
        }

        // LogonDomainId (SID).
        if !self.logon_domain_id.is_empty() {
            let data_offset = buf.len() as u32;
            // SID is a conformant array: max_count (u32) + Revision (u8) +
            // SubAuthorityCount (u8) + 6 authority bytes + sub-authorities.
            // The conformant array max_count = total SID byte length.
            let sid = &self.logon_domain_id;
            buf.extend_from_slice(&(sid.len() as u32).to_le_bytes());
            buf.extend_from_slice(sid);
            buf[logon_domain_id_ptr_pos..logon_domain_id_ptr_pos + 4]
                .copy_from_slice(&data_offset.to_le_bytes());
        }

        // ExtraSids conformant array of KERB_SID_AND_ATTRIBUTES.
        if !self.extra_sids.is_empty() {
            let data_offset = buf.len() as u32;
            let count = self.extra_sids.len() as u32;
            buf.extend_from_slice(&count.to_le_bytes()); // max_count
            for (sid, attrs) in &self.extra_sids {
                // KERB_SID_AND_ATTRIBUTES: SID pointer (u32) + Attributes (u32).
                let sid_ptr_offset = buf.len() as u32;
                buf.extend_from_slice(&0u32.to_le_bytes()); // placeholder SID pointer
                buf.extend_from_slice(&attrs.to_le_bytes());
                // Write the SID data at the end.
                let sid_data_offset = buf.len() as u32;
                buf.extend_from_slice(&(sid.len() as u32).to_le_bytes());
                buf.extend_from_slice(sid);
                // Fixup the SID pointer.
                buf[sid_ptr_offset as usize..sid_ptr_offset as usize + 4]
                    .copy_from_slice(&sid_data_offset.to_le_bytes());
            }
            buf[extra_sids_ptr_pos..extra_sids_ptr_pos + 4]
                .copy_from_slice(&data_offset.to_le_bytes());
        }

        // ResourceGroupDomainSid (SID).
        if !self.resource_group_domain_sid.is_empty() {
            let data_offset = buf.len() as u32;
            let sid = &self.resource_group_domain_sid;
            buf.extend_from_slice(&(sid.len() as u32).to_le_bytes());
            buf.extend_from_slice(sid);
            buf[rg_domain_sid_ptr_pos..rg_domain_sid_ptr_pos + 4]
                .copy_from_slice(&data_offset.to_le_bytes());
        }

        // ResourceGroups conformant array.
        if !self.resource_groups.is_empty() {
            let data_offset = buf.len() as u32;
            let count = self.resource_groups.len() as u32;
            buf.extend_from_slice(&count.to_le_bytes());
            for (rid, attrs) in &self.resource_groups {
                buf.extend_from_slice(&rid.to_le_bytes());
                buf.extend_from_slice(&attrs.to_le_bytes());
            }
            buf[resource_groups_ptr_pos..resource_groups_ptr_pos + 4]
                .copy_from_slice(&data_offset.to_le_bytes());
        }

        buf
    }

    /// Decode an NDR20-encoded KERB_VALIDATION_INFO from the given bytes
    /// (the LOGON_INFO buffer payload — typically `Pac::logon_info()`).
    ///
    /// This is the inverse of [`encode_ndr`](Self::encode_ndr).  Only the
    /// fields the validator inspects are decoded; unknown trailing bytes
    /// are ignored.
    pub fn decode_ndr(bytes: &[u8]) -> Result<Self, PacValidationError> {
        let mut r = NdrReader::new(bytes);
        let logon_time = r.read_uint64().map_err(ndr_err)?;
        let logoff_time = r.read_uint64().map_err(ndr_err)?;
        let kickoff_time = r.read_uint64().map_err(ndr_err)?;
        let password_last_set = r.read_uint64().map_err(ndr_err)?;
        let password_can_change = r.read_uint64().map_err(ndr_err)?;
        let password_must_change = r.read_uint64().map_err(ndr_err)?;

        // 6 RPC_UNICODE_STRING headers.
        let mut str_ptrs = Vec::with_capacity(6);
        let mut str_fields = Vec::with_capacity(6);
        for _ in 0..6 {
            let length = r.read_uint16_raw().map_err(ndr_err)?;
            let max_length = r.read_uint16_raw().map_err(ndr_err)?;
            let ptr = r.read_uint32().map_err(ndr_err)?;
            str_ptrs.push(ptr);
            str_fields.push((length, max_length));
        }

        let logon_count = r.read_uint16().map_err(ndr_err)?;
        let bad_password_count = r.read_uint16().map_err(ndr_err)?;
        let user_id = r.read_uint32().map_err(ndr_err)?;
        let primary_group_id = r.read_uint32().map_err(ndr_err)?;
        let group_ids_ptr = r.read_uint32().map_err(ndr_err)?;
        let user_flags = r.read_uint32().map_err(ndr_err)?;
        let key_lo = r.read_uint64().map_err(ndr_err)?;
        let key_hi = r.read_uint64().map_err(ndr_err)?;
        let mut user_session_key = [0u8; 16];
        user_session_key[0..8].copy_from_slice(&key_lo.to_le_bytes());
        user_session_key[8..16].copy_from_slice(&key_hi.to_le_bytes());

        // 2 more RPC_UNICODE_STRING headers.
        let mut str_ptrs2 = Vec::with_capacity(2);
        let mut str_fields2 = Vec::with_capacity(2);
        for _ in 0..2 {
            let length = r.read_uint16_raw().map_err(ndr_err)?;
            let max_length = r.read_uint16_raw().map_err(ndr_err)?;
            let ptr = r.read_uint32().map_err(ndr_err)?;
            str_ptrs2.push(ptr);
            str_fields2.push((length, max_length));
        }

        let logon_domain_id_ptr = r.read_uint32().map_err(ndr_err)?;
        let user_account_control = r.read_uint32().map_err(ndr_err)?;
        let sub_auth_status = r.read_uint32().map_err(ndr_err)?;
        let last_successful_ilogon = r.read_uint64().map_err(ndr_err)?;
        let last_failed_ilogon = r.read_uint64().map_err(ndr_err)?;
        let failed_ilogon_count = r.read_uint32().map_err(ndr_err)?;
        let reserved3 = r.read_uint32().map_err(ndr_err)?;
        let extra_sids_ptr = r.read_uint32().map_err(ndr_err)?;
        let rg_domain_sid_ptr = r.read_uint32().map_err(ndr_err)?;
        let resource_groups_ptr = r.read_uint32().map_err(ndr_err)?;

        // Decode the conformant data by following pointers.
        let read_string_at = |bytes: &[u8], ptr: u32| -> Result<String, PacValidationError> {
            if ptr == 0 {
                return Ok(String::new());
            }
            let p = ptr as usize;
            if p + 12 > bytes.len() {
                return Err(PacValidationError::Malformed(
                    "string pointer out of bounds".into(),
                ));
            }
            let max_count = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
            let _offset = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap());
            let actual_count = u32::from_le_bytes(bytes[p + 8..p + 12].try_into().unwrap());
            let byte_len = actual_count as usize * 2;
            if p + 12 + byte_len > bytes.len() {
                return Err(PacValidationError::Malformed(
                    "string data out of bounds".into(),
                ));
            }
            let mut units = Vec::with_capacity(actual_count as usize);
            for i in 0..actual_count as usize {
                let off = p + 12 + i * 2;
                units.push(u16::from_le_bytes([bytes[off], bytes[off + 1]]));
            }
            // Strip the trailing NUL terminator (the NDR conformant string
            // format always includes one — see encode_ndr's max_count = len + 1).
            while units.last() == Some(&0) {
                units.pop();
            }
            let _ = max_count; // suppress unused warning
            Ok(String::from_utf16_lossy(&units))
        };

        let effective_name = read_string_at(bytes, str_ptrs[0])?;
        let full_name = read_string_at(bytes, str_ptrs[1])?;
        let logon_script = read_string_at(bytes, str_ptrs[2])?;
        let profile_path = read_string_at(bytes, str_ptrs[3])?;
        let home_directory = read_string_at(bytes, str_ptrs[4])?;
        let home_directory_drive = read_string_at(bytes, str_ptrs[5])?;
        let logon_server = read_string_at(bytes, str_ptrs2[0])?;
        let logon_domain_name = read_string_at(bytes, str_ptrs2[1])?;

        // Decode GroupIds conformant array.
        let group_ids = read_conformant_u32_pairs(bytes, group_ids_ptr)?;

        // Decode LogonDomainId SID.
        let logon_domain_id = read_sid(bytes, logon_domain_id_ptr)?;

        // Decode ExtraSids.
        let extra_sids = read_extra_sids(bytes, extra_sids_ptr)?;

        // Decode ResourceGroupDomainSid.
        let resource_group_domain_sid = read_sid(bytes, rg_domain_sid_ptr)?;

        // Decode ResourceGroups.
        let resource_groups = read_conformant_u32_pairs(bytes, resource_groups_ptr)?;

        let _ = str_fields; // (length, max_length) not needed for decode
        let _ = str_fields2;

        Ok(Self {
            logon_time,
            logoff_time,
            kickoff_time,
            password_last_set,
            password_can_change,
            password_must_change,
            effective_name,
            full_name,
            logon_script,
            profile_path,
            home_directory,
            home_directory_drive,
            logon_count,
            bad_password_count,
            user_id,
            primary_group_id,
            group_ids,
            user_flags,
            user_session_key,
            logon_server,
            logon_domain_name,
            logon_domain_id,
            user_account_control,
            sub_auth_status,
            last_successful_ilogon,
            last_failed_ilogon,
            failed_ilogon_count,
            reserved3,
            extra_sids,
            resource_group_domain_sid,
            resource_groups,
        })
    }
}

/// Read a conformant array of (u32, u32) pairs at the given NDR pointer.
fn read_conformant_u32_pairs(
    bytes: &[u8],
    ptr: u32,
) -> Result<Vec<(u32, u32)>, PacValidationError> {
    if ptr == 0 {
        return Ok(Vec::new());
    }
    let p = ptr as usize;
    if p + 4 > bytes.len() {
        return Err(PacValidationError::Malformed(
            "array count out of bounds".into(),
        ));
    }
    let count = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = p + 4 + i * 8;
        if off + 8 > bytes.len() {
            return Err(PacValidationError::Malformed(
                "array element out of bounds".into(),
            ));
        }
        let rid = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let attrs = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
        out.push((rid, attrs));
    }
    Ok(out)
}

/// Read a SID at the given NDR pointer (conformant array of bytes).
fn read_sid(bytes: &[u8], ptr: u32) -> Result<Vec<u8>, PacValidationError> {
    if ptr == 0 {
        return Ok(Vec::new());
    }
    let p = ptr as usize;
    if p + 4 > bytes.len() {
        return Err(PacValidationError::Malformed(
            "sid count out of bounds".into(),
        ));
    }
    let count = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
    if p + 4 + count > bytes.len() {
        return Err(PacValidationError::Malformed(
            "sid data out of bounds".into(),
        ));
    }
    Ok(bytes[p + 4..p + 4 + count].to_vec())
}

/// Read the ExtraSids conformant array (KERB_SID_AND_ATTRIBUTES[]).
fn read_extra_sids(bytes: &[u8], ptr: u32) -> Result<Vec<(Vec<u8>, u32)>, PacValidationError> {
    if ptr == 0 {
        return Ok(Vec::new());
    }
    let p = ptr as usize;
    if p + 4 > bytes.len() {
        return Err(PacValidationError::Malformed(
            "extra_sids count out of bounds".into(),
        ));
    }
    let count = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = p + 4 + i * 8;
        if off + 8 > bytes.len() {
            return Err(PacValidationError::Malformed(
                "extra_sids element out of bounds".into(),
            ));
        }
        let sid_ptr = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let attrs = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
        let sid = read_sid(bytes, sid_ptr)?;
        out.push((sid, attrs));
    }
    Ok(out)
}

/// Map an `adrian_dcerpc::DceRpcError` to a `PacValidationError`.
fn ndr_err(e: adrian_dcerpc::DceRpcError) -> PacValidationError {
    PacValidationError::Malformed(format!("NDR decode error: {e}"))
}

impl Pac {
    /// Validate the TICKET_CHECKSUM (ADR-123 silver ticket mitigation).
    ///
    /// The TICKET_CHECKSUM (PAC buffer type 0x10) is an HMAC-SHA1-96
    /// over the ticket's enc-part bytes, keyed by the krbtgt long-term
    /// key.  A silver-ticket attack forges a service ticket with a
    /// valid-looking PAC but no TICKET_CHECKSUM (or a TICKET_CHECKSUM
    /// that doesn't match the ticket's enc-part) — this method detects
    /// both cases.
    ///
    /// # Arguments
    /// * `krbtgt_key` — The krbtgt long-term key (32 bytes for AES-256).
    /// * `ticket_enc_part` — The raw bytes of the Kerberos ticket's
    ///   enc-part (the `EncTicketPart` ASN.1 DER encoding, as exposed
    ///   by the KDC's ticket-decryption path).
    ///
    /// # Errors
    /// Returns `MissingBuffer(0x10)` if no TICKET_CHECKSUM buffer is
    /// present.  Returns `SignatureMismatch` if the checksum is all
    /// zeros or doesn't match `HMAC-SHA1-96(krbtgt_key, ticket_enc_part)`.
    pub fn validate_ticket_checksum(
        &self,
        krbtgt_key: &[u8],
        ticket_enc_part: &[u8],
    ) -> Result<(), PacValidationError> {
        let ticket_buf = self
            .ticket_checksum()
            .ok_or(PacValidationError::MissingBuffer(
                buffer_type::TICKET_CHECKSUM,
            ))?;
        if ticket_buf.len() < 4 + 12 {
            return Err(PacValidationError::Malformed(format!(
                "TICKET_CHECKSUM too short ({} bytes, need >= 16)",
                ticket_buf.len()
            )));
        }
        let stored_sig = &ticket_buf[4..16];
        // Silver-ticket mitigation: reject all-zero checksums.
        if stored_sig.iter().all(|&b| b == 0) {
            return Err(PacValidationError::SignatureMismatch(
                "TICKET_CHECKSUM is all zeros (silver ticket mitigation not enforced)".into(),
            ));
        }
        let expected_sig = compute_hmac_sha1_96(krbtgt_key, ticket_enc_part);
        if expected_sig.ct_eq(stored_sig).unwrap_u8() == 0 {
            return Err(PacValidationError::SignatureMismatch(
                "TICKET_CHECKSUM does not match the ticket enc-part (silver ticket detected)"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Build a minimal PAC for testing (compatible with the Wave 2b builder format).
#[cfg(test)]
fn build_test_pac(server_key: &[u8], krbtgt_key: &[u8]) -> Vec<u8> {
    let num_buffers: u32 = 2;
    let header_len = PAC_HEADER_LEN;
    let entry_header_len = PAC_BUFFER_HEADER_LEN;
    let sig_data_len = 4 + 12; // 16 bytes per signature buffer

    // Buffer data offsets (8-byte aligned):
    let server_data_off = header_len + (num_buffers as usize) * entry_header_len;
    let privsvr_data_off = server_data_off + sig_data_len;

    let total_size = header_len + (num_buffers as usize) * entry_header_len + 2 * sig_data_len;

    let mut pac = vec![0u8; total_size];

    // Header
    pac[0..4].copy_from_slice(&PAC_HEADER_TYPE.to_le_bytes());
    pac[4..8].copy_from_slice(&(total_size as u32).to_le_bytes());
    pac[8..12].copy_from_slice(&num_buffers.to_le_bytes());
    pac[12..16].copy_from_slice(&PAC_HEADER_VERSION.to_le_bytes());

    // SERVER_CHECKSUM entry header
    let mut off = header_len;
    pac[off..off + 4].copy_from_slice(&buffer_type::SERVER_CHECKSUM.to_le_bytes());
    pac[off + 4..off + 8].copy_from_slice(&(sig_data_len as u32).to_le_bytes());
    pac[off + 8..off + 16].copy_from_slice(&(server_data_off as u64).to_le_bytes());
    off += entry_header_len;

    // PRIVSVR_CHECKSUM entry header
    pac[off..off + 4].copy_from_slice(&buffer_type::PRIVSVR_CHECKSUM.to_le_bytes());
    pac[off + 4..off + 8].copy_from_slice(&(sig_data_len as u32).to_le_bytes());
    pac[off + 8..off + 16].copy_from_slice(&(privsvr_data_off as u64).to_le_bytes());

    // Write sig_type fields (0x12 = HMAC-SHA1-96 for AES-256) but leave sig bytes as zero.
    pac[server_data_off..server_data_off + 4].copy_from_slice(&0x12u32.to_le_bytes());
    pac[privsvr_data_off..privsvr_data_off + 4].copy_from_slice(&0x12u32.to_le_bytes());

    // At this point, the PAC has header + entry headers + sig_type fields, with
    // all signature bytes (bytes 4..16 of each sig buffer) = 0. This is the
    // "zeroed-sig" state over which the SERVER_CHECKSUM should be computed.
    let server_sig = compute_hmac_sha1_96(server_key, &pac);

    // Write the server signature.
    pac[server_data_off + 4..server_data_off + 16].copy_from_slice(&server_sig);

    // Compute PRIVSVR_CHECKSUM = HMAC over the server signature bytes.
    let privsvr_sig = compute_hmac_sha1_96(krbtgt_key, &server_sig);
    pac[privsvr_data_off + 4..privsvr_data_off + 16].copy_from_slice(&privsvr_sig);

    pac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_type_constants() {
        assert_eq!(buffer_type::LOGON_INFO, 0x01);
        assert_eq!(buffer_type::SERVER_CHECKSUM, 0x04);
        assert_eq!(buffer_type::PRIVSVR_CHECKSUM, 0x06);
        assert_eq!(buffer_type::CLIENT_INFO, 0x0A);
        assert_eq!(buffer_type::UPN_DNS_INFO, 0x0C);
        assert_eq!(buffer_type::TICKET_CHECKSUM, 0x10);
        assert_eq!(buffer_type::REQUESTOR, 0x12);
        assert_eq!(buffer_type::FULL_CHECKSUM, 0x13);
    }

    #[test]
    fn parse_rejects_too_short() {
        let err = Pac::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, PacValidationError::Malformed(_)));
    }

    #[test]
    fn parse_rejects_wrong_header_type() {
        let mut pac = vec![0u8; 32];
        pac[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // wrong ulType
        pac[4..8].copy_from_slice(&32u32.to_le_bytes()); // cbBufferSize
        pac[8..12].copy_from_slice(&0u32.to_le_bytes()); // numBuffers
        pac[12..16].copy_from_slice(&0u32.to_le_bytes()); // version
        let err = Pac::parse(&pac).unwrap_err();
        assert!(matches!(err, PacValidationError::Malformed(_)));
    }

    #[test]
    fn parse_rejects_size_mismatch() {
        let mut pac = vec![0u8; 32];
        pac[0..4].copy_from_slice(&0u32.to_le_bytes()); // ulType = 0
        pac[4..8].copy_from_slice(&99u32.to_le_bytes()); // cbBufferSize != 32
        pac[8..12].copy_from_slice(&0u32.to_le_bytes());
        pac[12..16].copy_from_slice(&0u32.to_le_bytes());
        let err = Pac::parse(&pac).unwrap_err();
        assert!(matches!(err, PacValidationError::Malformed(_)));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let mut pac = vec![0u8; 16];
        pac[0..4].copy_from_slice(&0u32.to_le_bytes());
        pac[4..8].copy_from_slice(&16u32.to_le_bytes());
        pac[8..12].copy_from_slice(&0u32.to_le_bytes());
        pac[12..16].copy_from_slice(&1u32.to_le_bytes()); // wrong version
        let err = Pac::parse(&pac).unwrap_err();
        assert!(matches!(err, PacValidationError::Malformed(_)));
    }

    #[test]
    fn parse_empty_pac() {
        let mut pac = vec![0u8; 16];
        pac[0..4].copy_from_slice(&0u32.to_le_bytes());
        pac[4..8].copy_from_slice(&16u32.to_le_bytes());
        pac[8..12].copy_from_slice(&0u32.to_le_bytes());
        pac[12..16].copy_from_slice(&0u32.to_le_bytes());
        let parsed = Pac::parse(&pac).unwrap();
        assert_eq!(parsed.num_buffers, 0);
        assert!(parsed.buffers.is_empty());
    }

    #[test]
    fn parse_with_buffers() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        assert_eq!(pac.num_buffers, 2);
        assert_eq!(pac.buffers.len(), 2);
        assert_eq!(pac.buffers[0].ul_type, buffer_type::SERVER_CHECKSUM);
        assert_eq!(pac.buffers[1].ul_type, buffer_type::PRIVSVR_CHECKSUM);
    }

    #[test]
    fn validate_kdc_checksum_succeeds_with_correct_key() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        pac.validate_kdc_checksum(&krbtgt_key).unwrap();
    }

    #[test]
    fn validate_kdc_checksum_fails_with_wrong_key() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let wrong_key = [0xEFu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        let err = pac.validate_kdc_checksum(&wrong_key).unwrap_err();
        assert!(matches!(err, PacValidationError::SignatureMismatch(_)));
    }

    #[test]
    fn validate_service_checksum_succeeds_with_correct_key() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        // Note: validate_service_checksum requires the PAC to have been
        // signed with zeroed sig fields, then sigs computed. Our test PAC
        // computes the server sig over the all-zero-body (which IS the
        // zeroed-sig state), so this should pass.
        pac.validate_service_checksum(&server_key, &pac_bytes)
            .unwrap();
    }

    #[test]
    fn validate_service_checksum_fails_with_wrong_key() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let wrong_key = [0xEFu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        let err = pac
            .validate_service_checksum(&wrong_key, &pac_bytes)
            .unwrap_err();
        assert!(matches!(err, PacValidationError::SignatureMismatch(_)));
    }

    #[test]
    fn validate_full_fails_without_server_checksum() {
        // Build a PAC with only PRIVSVR_CHECKSUM (no SERVER_CHECKSUM).
        let mut pac = vec![0u8; 16 + 16 + 16]; // header + 1 entry + 1 data
        pac[0..4].copy_from_slice(&0u32.to_le_bytes());
        let len = pac.len() as u32;
        pac[4..8].copy_from_slice(&len.to_le_bytes());
        pac[8..12].copy_from_slice(&1u32.to_le_bytes()); // 1 buffer
        pac[12..16].copy_from_slice(&0u32.to_le_bytes());
        // Entry: PRIVSVR_CHECKSUM
        pac[16..20].copy_from_slice(&buffer_type::PRIVSVR_CHECKSUM.to_le_bytes());
        pac[20..24].copy_from_slice(&16u32.to_le_bytes()); // size
        pac[24..32].copy_from_slice(&32u64.to_le_bytes()); // offset
        let parsed = Pac::parse(&pac).unwrap();
        let err = parsed.validate_kdc_checksum(&[0u8; 32]).unwrap_err();
        assert!(matches!(err, PacValidationError::MissingBuffer(_)));
    }

    #[test]
    fn get_buffer_accessors() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        assert!(pac.server_checksum().is_some());
        assert!(pac.privsvr_checksum().is_some());
        assert!(pac.logon_info().is_none()); // not in our test PAC
        assert!(pac.client_info().is_none());
        assert!(pac.upn_dns_info().is_none());
        assert!(pac.ticket_checksum().is_none());
    }

    #[test]
    fn parse_rejects_misaligned_offset() {
        // Build a PAC with a misaligned buffer offset.
        let mut pac = vec![0u8; 48];
        pac[0..4].copy_from_slice(&0u32.to_le_bytes());
        pac[4..8].copy_from_slice(&48u32.to_le_bytes());
        pac[8..12].copy_from_slice(&1u32.to_le_bytes()); // 1 buffer
        pac[12..16].copy_from_slice(&0u32.to_le_bytes());
        // Buffer entry with misaligned offset (17, not 8-byte aligned)
        pac[16..20].copy_from_slice(&buffer_type::LOGON_INFO.to_le_bytes());
        pac[20..24].copy_from_slice(&4u32.to_le_bytes()); // size
        pac[24..32].copy_from_slice(&17u64.to_le_bytes()); // offset = 17 (misaligned)
        let err = Pac::parse(&pac).unwrap_err();
        assert!(matches!(err, PacValidationError::Malformed(_)));
    }

    #[test]
    fn parse_rejects_out_of_bounds_offset() {
        let mut pac = vec![0u8; 32];
        pac[0..4].copy_from_slice(&0u32.to_le_bytes());
        pac[4..8].copy_from_slice(&32u32.to_le_bytes());
        pac[8..12].copy_from_slice(&1u32.to_le_bytes());
        pac[12..16].copy_from_slice(&0u32.to_le_bytes());
        pac[16..20].copy_from_slice(&buffer_type::LOGON_INFO.to_le_bytes());
        pac[20..24].copy_from_slice(&100u32.to_le_bytes()); // size = 100 (way too big)
        pac[24..32].copy_from_slice(&32u64.to_le_bytes()); // offset = 32
        let err = Pac::parse(&pac).unwrap_err();
        assert!(matches!(err, PacValidationError::Malformed(_)));
    }

    #[test]
    fn validate_full_both_layers_succeed() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        pac.validate(&pac_bytes, &server_key, &krbtgt_key).unwrap();
    }

    #[test]
    fn validate_full_fails_with_wrong_service_key() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let wrong_service_key = [0xFFu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        let err = pac
            .validate(&pac_bytes, &wrong_service_key, &krbtgt_key)
            .unwrap_err();
        assert!(matches!(err, PacValidationError::SignatureMismatch(_)));
    }

    #[test]
    fn validate_full_fails_with_wrong_krbtgt_key() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let wrong_krbtgt_key = [0xFFu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key);
        let pac = Pac::parse(&pac_bytes).unwrap();
        let err = pac
            .validate(&pac_bytes, &server_key, &wrong_krbtgt_key)
            .unwrap_err();
        assert!(matches!(err, PacValidationError::SignatureMismatch(_)));
    }

    // ---- Wave 3: NDR-encoded KERB_VALIDATION_INFO + ticket checksum -----

    /// Build a sample KERB_VALIDATION_INFO for testing.
    fn sample_kerb_validation_info() -> KerbValidationInfo {
        KerbValidationInfo {
            logon_time: 132_500_000_000_000_000, // 2024-01-01ish
            logoff_time: 0,
            kickoff_time: 0,
            password_last_set: 132_400_000_000_000_000,
            password_can_change: 132_400_000_000_000_000,
            password_must_change: 0,
            effective_name: "Administrator".into(),
            full_name: "Adrian Admin".into(),
            logon_script: "".into(),
            profile_path: "".into(),
            home_directory: "\\\\server\\share$".into(),
            home_directory_drive: "Z:".into(),
            logon_count: 42,
            bad_password_count: 0,
            user_id: 500,                                  // Administrator RID
            primary_group_id: 513,                         // Domain Users
            group_ids: vec![(512, 7), (513, 7), (519, 7)], // Admins, Users, Ent Admins
            user_flags: 0,
            user_session_key: [0x42u8; 16],
            logon_server: "DC01".into(),
            logon_domain_name: "DOMAIN".into(),
            logon_domain_id: vec![
                0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xAA, 0xBB,
                0xCC, 0xDD,
            ],
            user_account_control: 0x00000200, // NORMAL_ACCOUNT
            sub_auth_status: 0,
            last_successful_ilogon: 0,
            last_failed_ilogon: 0,
            failed_ilogon_count: 0,
            reserved3: 0,
            extra_sids: vec![(
                vec![
                    0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xAA,
                    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00,
                ],
                7,
            )],
            resource_group_domain_sid: vec![],
            resource_groups: vec![],
        }
    }

    #[test]
    fn ndr_kerb_validation_info_round_trips() {
        let original = sample_kerb_validation_info();
        let encoded = original.encode_ndr();
        assert!(!encoded.is_empty(), "encoded bytes should be non-empty");
        let decoded = KerbValidationInfo::decode_ndr(&encoded).expect("decode");
        assert_eq!(original, decoded, "round-trip should preserve all fields");
    }

    #[test]
    fn ndr_kerb_validation_info_preserves_user_id_and_groups() {
        let original = sample_kerb_validation_info();
        let encoded = original.encode_ndr();
        let decoded = KerbValidationInfo::decode_ndr(&encoded).expect("decode");
        assert_eq!(decoded.user_id, 500, "UserId should be 500 (Administrator)");
        assert_eq!(
            decoded.primary_group_id, 513,
            "PrimaryGroupId should be 513"
        );
        assert_eq!(
            decoded.group_ids.len(),
            3,
            "should have 3 group memberships"
        );
        assert_eq!(
            decoded.group_ids[0],
            (512, 7),
            "first group should be Admins"
        );
        assert_eq!(decoded.effective_name, "Administrator");
        assert_eq!(decoded.logon_domain_name, "DOMAIN");
    }

    /// Build a PAC with LOGON_INFO + SERVER_CHECKSUM + PRIVSVR_CHECKSUM +
    /// TICKET_CHECKSUM buffers for Wave 3 tests.
    fn build_test_pac_with_ndr_logon_info_and_ticket_checksum(
        server_key: &[u8],
        krbtgt_key: &[u8],
        ticket_enc_part: &[u8],
    ) -> Vec<u8> {
        let logon_info = sample_kerb_validation_info();
        let logon_info_bytes = logon_info.encode_ndr();
        let sig_data_len = 4 + 12; // 16 bytes per signature buffer

        // 4 buffers: LOGON_INFO, SERVER_CHECKSUM, PRIVSVR_CHECKSUM, TICKET_CHECKSUM
        let num_buffers: u32 = 4;
        let header_len = PAC_HEADER_LEN;
        let entry_header_len = PAC_BUFFER_HEADER_LEN;

        // Data offsets (8-byte aligned):
        let mut off = header_len + (num_buffers as usize) * entry_header_len;
        // Align to 8
        off = (off + 7) & !7;
        let logon_info_off = off;
        off += logon_info_bytes.len();
        off = (off + 7) & !7;
        let server_data_off = off;
        off += sig_data_len;
        let privsvr_data_off = off;
        off += sig_data_len;
        let ticket_data_off = off;
        off += sig_data_len;

        let total_size = off;
        let mut pac = vec![0u8; total_size];

        // Header
        pac[0..4].copy_from_slice(&PAC_HEADER_TYPE.to_le_bytes());
        pac[4..8].copy_from_slice(&(total_size as u32).to_le_bytes());
        pac[8..12].copy_from_slice(&num_buffers.to_le_bytes());
        pac[12..16].copy_from_slice(&PAC_HEADER_VERSION.to_le_bytes());

        // Buffer entry headers
        let mut entry_off = header_len;
        // LOGON_INFO
        pac[entry_off..entry_off + 4].copy_from_slice(&buffer_type::LOGON_INFO.to_le_bytes());
        pac[entry_off + 4..entry_off + 8]
            .copy_from_slice(&(logon_info_bytes.len() as u32).to_le_bytes());
        pac[entry_off + 8..entry_off + 16].copy_from_slice(&(logon_info_off as u64).to_le_bytes());
        entry_off += entry_header_len;
        // SERVER_CHECKSUM
        pac[entry_off..entry_off + 4].copy_from_slice(&buffer_type::SERVER_CHECKSUM.to_le_bytes());
        pac[entry_off + 4..entry_off + 8].copy_from_slice(&(sig_data_len as u32).to_le_bytes());
        pac[entry_off + 8..entry_off + 16].copy_from_slice(&(server_data_off as u64).to_le_bytes());
        entry_off += entry_header_len;
        // PRIVSVR_CHECKSUM
        pac[entry_off..entry_off + 4].copy_from_slice(&buffer_type::PRIVSVR_CHECKSUM.to_le_bytes());
        pac[entry_off + 4..entry_off + 8].copy_from_slice(&(sig_data_len as u32).to_le_bytes());
        pac[entry_off + 8..entry_off + 16]
            .copy_from_slice(&(privsvr_data_off as u64).to_le_bytes());
        entry_off += entry_header_len;
        // TICKET_CHECKSUM
        pac[entry_off..entry_off + 4].copy_from_slice(&buffer_type::TICKET_CHECKSUM.to_le_bytes());
        pac[entry_off + 4..entry_off + 8].copy_from_slice(&(sig_data_len as u32).to_le_bytes());
        pac[entry_off + 8..entry_off + 16].copy_from_slice(&(ticket_data_off as u64).to_le_bytes());

        // LOGON_INFO data
        pac[logon_info_off..logon_info_off + logon_info_bytes.len()]
            .copy_from_slice(&logon_info_bytes);

        // Sig type fields (0x12 = HMAC-SHA1-96)
        pac[server_data_off..server_data_off + 4].copy_from_slice(&0x12u32.to_le_bytes());
        pac[privsvr_data_off..privsvr_data_off + 4].copy_from_slice(&0x12u32.to_le_bytes());
        pac[ticket_data_off..ticket_data_off + 4].copy_from_slice(&0x12u32.to_le_bytes());

        // Zero all sig fields, then compute SERVER_CHECKSUM over the zeroed-sig PAC.
        // (SERVER_CHECKSUM and TICKET_CHECKSUM sig fields are already zero.)
        let server_sig = compute_hmac_sha1_96(server_key, &pac);
        pac[server_data_off + 4..server_data_off + 16].copy_from_slice(&server_sig);

        // PRIVSVR_CHECKSUM = HMAC over the server signature.
        let privsvr_sig = compute_hmac_sha1_96(krbtgt_key, &server_sig);
        pac[privsvr_data_off + 4..privsvr_data_off + 16].copy_from_slice(&privsvr_sig);

        // TICKET_CHECKSUM = HMAC over the ticket enc-part.
        let ticket_sig = compute_hmac_sha1_96(krbtgt_key, ticket_enc_part);
        pac[ticket_data_off + 4..ticket_data_off + 16].copy_from_slice(&ticket_sig);

        pac
    }

    #[test]
    fn pac_with_ndr_logon_info_parses_and_decodes() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let ticket_enc_part = [0x42u8; 64];
        let pac_bytes = build_test_pac_with_ndr_logon_info_and_ticket_checksum(
            &server_key,
            &krbtgt_key,
            &ticket_enc_part,
        );
        let pac = Pac::parse(&pac_bytes).expect("parse");
        assert_eq!(pac.num_buffers, 4);
        // LOGON_INFO should be present and decodable.
        let logon_info_bytes = pac.logon_info().expect("LOGON_INFO present");
        let kvi =
            KerbValidationInfo::decode_ndr(logon_info_bytes).expect("decode KERB_VALIDATION_INFO");
        assert_eq!(kvi.user_id, 500);
        assert_eq!(kvi.effective_name, "Administrator");
        assert_eq!(kvi.group_ids.len(), 3);
    }

    #[test]
    fn ticket_checksum_validates_with_correct_key_and_ticket() {
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let ticket_enc_part = [0x42u8; 64];
        let pac_bytes = build_test_pac_with_ndr_logon_info_and_ticket_checksum(
            &server_key,
            &krbtgt_key,
            &ticket_enc_part,
        );
        let pac = Pac::parse(&pac_bytes).expect("parse");
        pac.validate_ticket_checksum(&krbtgt_key, &ticket_enc_part)
            .expect("TICKET_CHECKSUM should validate");
    }

    #[test]
    fn ticket_checksum_rejects_wrong_ticket_bytes_as_silver_ticket() {
        // A silver-ticket attack forges a service ticket with a valid-looking
        // PAC but a TICKET_CHECKSUM that doesn't match the actual ticket
        // enc-part.  This test verifies the validator detects the mismatch.
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let real_ticket = [0x42u8; 64];
        let forged_ticket = [0x99u8; 64]; // different bytes
        let pac_bytes = build_test_pac_with_ndr_logon_info_and_ticket_checksum(
            &server_key,
            &krbtgt_key,
            &real_ticket,
        );
        let pac = Pac::parse(&pac_bytes).expect("parse");
        let err = pac
            .validate_ticket_checksum(&krbtgt_key, &forged_ticket)
            .unwrap_err();
        assert!(
            matches!(err, PacValidationError::SignatureMismatch(_)),
            "silver-ticket mismatch should be detected"
        );
    }

    #[test]
    fn ticket_checksum_missing_returns_missing_buffer_error() {
        // A PAC without a TICKET_CHECKSUM buffer should be rejected when
        // validate_ticket_checksum is called (ADR-123 requires the buffer
        // on every service accept).
        let server_key = [0xABu8; 32];
        let krbtgt_key = [0xCDu8; 32];
        let pac_bytes = build_test_pac(&server_key, &krbtgt_key); // no TICKET_CHECKSUM
        let pac = Pac::parse(&pac_bytes).unwrap();
        let err = pac
            .validate_ticket_checksum(&krbtgt_key, &[0u8; 64])
            .unwrap_err();
        assert!(matches!(err, PacValidationError::MissingBuffer(0x10)));
    }
}
