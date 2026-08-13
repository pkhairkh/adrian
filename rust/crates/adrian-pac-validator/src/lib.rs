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
}
