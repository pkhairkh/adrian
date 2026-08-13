//! NDR (Network Data Representation) encoding/decoding primitives.
//!
//! Implements NDR20 (little-endian) per [C706] §14 / MS-RPCE §2.1. NDR20
//! is the only transfer syntax negotiated in v1; NDR64 is a future-wave
//! concern.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::DceRpcError;
use uuid::Uuid;

/// The NDR 2.0 transfer syntax UUID (`8A885D04-1CEB-11C9-9FE8-08002B104860`,
/// per [C706] §14.1 — `NDR_TRANSFER_SYNTAX`).
pub const NDR_TRANSFER_SYNTAX_UUID: Uuid = Uuid::from_bytes([
    0x8A, 0x88, 0x5D, 0x04, 0x1C, 0xEB, 0x11, 0xC9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
]);

/// The NDR 2.0 transfer syntax version (2.0, encoded as `2u32`).
pub const NDR_TRANSFER_SYNTAX_VERSION: u32 = 2;

/// Default max transmit fragment size used by Windows for AD-interop
/// (per MS-DRSR reference traffic — 5840 bytes).
pub const DEFAULT_MAX_XMIT_FRAG: u16 = 5840;

/// Default max receive fragment size used by Windows for AD-interop.
pub const DEFAULT_MAX_RECV_FRAG: u16 = 5840;

/// An NDR writer — append-only buffer with alignment support.
#[derive(Debug, Default, Clone)]
pub struct NdrWriter {
    buf: Vec<u8>,
}

impl NdrWriter {
    /// Construct an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an empty writer with `capacity` bytes pre-allocated.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Finalise: return the underlying byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Current write position (= length).
    #[must_use]
    pub fn position(&self) -> usize {
        self.buf.len()
    }

    /// Pad with zero bytes until the write position is a multiple of
    /// `alignment` (per [C706] §14.2.2 — alignment must be a power of
    /// two, or 1 for a no-op).
    pub fn align(&mut self, alignment: usize) {
        debug_assert!(
            alignment == 1 || alignment.is_power_of_two(),
            "alignment must be a power of two or 1, got {alignment}"
        );
        if alignment <= 1 {
            return;
        }
        let mask = alignment - 1;
        let rem = self.buf.len() & mask;
        if rem != 0 {
            let pad = alignment - rem;
            self.buf.extend(std::iter::repeat_n(0u8, pad));
        }
    }

    /// Write a raw byte slice (no alignment, no length prefix).
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Write a single `u8` (no alignment).
    pub fn write_uint8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a `u16` little-endian, after aligning to 2 bytes.
    pub fn write_uint16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a `u32` little-endian, after aligning to 4 bytes.
    pub fn write_uint32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a `u64` little-endian, after aligning to 8 bytes.
    pub fn write_uint64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a UUID as its canonical 16-byte RFC 4122 layout (no
    /// alignment — UUIDs are fixed-width 16-byte fields per [C706] §14.3.6).
    pub fn write_uuid(&mut self, uuid: Uuid) {
        self.buf.extend_from_slice(uuid.as_bytes());
    }

    /// Write a conformant-varying array of bytes (per [C706] §14.3.3).
    ///
    /// Wire layout: `max_count: u32, offset: u32 = 0, actual_count: u32 = max_count, data...`.
    pub fn write_conformant_array(&mut self, data: &[u8]) {
        let max_count = data.len() as u32;
        self.write_uint32(max_count);
        self.write_uint32(0); // offset
        self.write_uint32(max_count); // actual_count
        self.write_bytes(data);
    }

    /// Write an NDR conformant-varying string (UTF-16LE code units with a
    /// trailing NUL, per [C706] §14.3.4 / MS-RPCE §2.1).
    pub fn write_string(&mut self, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        let max_count = (units.len() + 1) as u32; // +1 for trailing NUL
        self.write_uint32(max_count);
        self.write_uint32(0); // offset
        self.write_uint32(max_count); // actual_count
        for u in units {
            self.buf.extend_from_slice(&u.to_le_bytes());
        }
        // trailing NUL (0x0000).
        self.buf.extend_from_slice(&0u16.to_le_bytes());
    }
}

/// An NDR reader — cursor over a borrowed slice.
#[derive(Debug, Clone, Copy)]
pub struct NdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    /// Construct a reader over `buf`.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current cursor position.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Remaining bytes in the buffer.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Total buffer length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn require(&self, n: usize) -> Result<(), DceRpcError> {
        if self.pos.checked_add(n).is_none_or(|end| end > self.buf.len()) {
            return Err(DceRpcError::Ndr(format!(
                "short read: requested {n} bytes at offset {}, have {} remaining",
                self.pos,
                self.remaining()
            )));
        }
        Ok(())
    }

    /// Advance the cursor until it is a multiple of `alignment`.
    pub fn align(&mut self, alignment: usize) -> Result<(), DceRpcError> {
        debug_assert!(
            alignment == 1 || alignment.is_power_of_two(),
            "alignment must be a power of two or 1, got {alignment}"
        );
        if alignment <= 1 {
            return Ok(());
        }
        let mask = alignment - 1;
        let rem = self.pos & mask;
        if rem != 0 {
            let pad = alignment - rem;
            self.require(pad)?;
            self.pos += pad;
        }
        Ok(())
    }

    /// Read `n` raw bytes (no alignment).
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DceRpcError> {
        self.require(n)?;
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read `N` raw bytes into a fixed array (no alignment).
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DceRpcError> {
        let slice = self.read_bytes(N)?;
        slice.try_into().map_err(|_| {
            DceRpcError::Ndr(format!("internal: {N}-byte slice conversion failed"))
        })
    }

    /// Read a single `u8` (no alignment).
    pub fn read_uint8(&mut self) -> Result<u8, DceRpcError> {
        self.require(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a little-endian `u16` after aligning to 2 bytes.
    pub fn read_uint16(&mut self) -> Result<u16, DceRpcError> {
        self.align(2)?;
        let arr = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(arr))
    }

    /// Read a little-endian `u32` after aligning to 4 bytes.
    pub fn read_uint32(&mut self) -> Result<u32, DceRpcError> {
        self.align(4)?;
        let arr = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Read a little-endian `u64` after aligning to 8 bytes.
    pub fn read_uint64(&mut self) -> Result<u64, DceRpcError> {
        self.align(8)?;
        let arr = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(arr))
    }

    /// Read a 16-byte UUID in canonical RFC 4122 layout.
    pub fn read_uuid(&mut self) -> Result<Uuid, DceRpcError> {
        let bytes = self.read_array::<16>()?;
        Ok(Uuid::from_bytes(bytes))
    }

    /// Read a conformant-varying array of bytes (per [C706] §14.3.3).
    pub fn read_conformant_array(&mut self) -> Result<Vec<u8>, DceRpcError> {
        let max_count = self.read_uint32()?;
        let _offset = self.read_uint32()?;
        let actual_count = self.read_uint32()?;
        if actual_count > max_count {
            return Err(DceRpcError::Ndr(format!(
                "conformant array: actual_count {actual_count} > max_count {max_count}"
            )));
        }
        let data = self.read_bytes(actual_count as usize)?.to_vec();
        Ok(data)
    }

    /// Read an NDR conformant-varying UTF-16LE string (per [C706]
    /// §14.3.4 / MS-RPCE §2.1).
    pub fn read_string(&mut self) -> Result<String, DceRpcError> {
        let max_count = self.read_uint32()? as usize;
        let _offset = self.read_uint32()?;
        let actual_count = self.read_uint32()? as usize;
        if actual_count > max_count {
            return Err(DceRpcError::Ndr(format!(
                "ndr string: actual_count {actual_count} > max_count {max_count}"
            )));
        }
        let byte_len = actual_count.checked_mul(2).ok_or_else(|| {
            DceRpcError::Ndr("ndr string: actual_count overflowed when doubled".into())
        })?;
        let bytes = self.read_bytes(byte_len)?;
        let mut units: Vec<u16> = Vec::with_capacity(actual_count);
        for chunk in bytes.chunks_exact(2) {
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        if units.last() == Some(&0u16) {
            units.pop();
        }
        String::from_utf16(&units).map_err(|e| {
            DceRpcError::Ndr(format!("ndr string: utf-16 decode failed: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndr_uint8_round_trip() {
        let mut w = NdrWriter::new();
        w.write_uint8(0xAB);
        w.write_uint8(0x00);
        w.write_uint8(0xFF);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAB, 0x00, 0xFF]);

        let mut r = NdrReader::new(&bytes);
        assert_eq!(r.read_uint8().unwrap(), 0xAB);
        assert_eq!(r.read_uint8().unwrap(), 0x00);
        assert_eq!(r.read_uint8().unwrap(), 0xFF);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn ndr_uint16_little_endian_with_alignment() {
        let mut w = NdrWriter::new();
        w.write_uint8(0x01);
        w.write_uint16(0x0203);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0x01, 0x00, 0x03, 0x02]);

        let mut r = NdrReader::new(&bytes);
        assert_eq!(r.read_uint8().unwrap(), 0x01);
        assert_eq!(r.read_uint16().unwrap(), 0x0203);
    }

    #[test]
    fn ndr_uint32_little_endian_with_alignment() {
        let mut w = NdrWriter::new();
        w.write_uint8(0xAA);
        w.write_uint32(0x01020304);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAA, 0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01]);

        let mut r = NdrReader::new(&bytes);
        assert_eq!(r.read_uint8().unwrap(), 0xAA);
        assert_eq!(r.read_uint32().unwrap(), 0x01020304);
    }

    #[test]
    fn ndr_uint64_little_endian_with_alignment() {
        let mut w = NdrWriter::new();
        w.write_uint64(0x01020304_05060708);
        let bytes = w.into_bytes();
        assert_eq!(
            bytes,
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );

        let mut r = NdrReader::new(&bytes);
        assert_eq!(r.read_uint64().unwrap(), 0x01020304_05060708);
    }

    #[test]
    fn ndr_align_no_op_when_already_aligned() {
        let mut w = NdrWriter::new();
        w.write_uint32(1);
        w.align(4);
        w.write_uint32(2);
        assert_eq!(w.position(), 8);
        assert_eq!(w.as_bytes(), &[1, 0, 0, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn ndr_reader_detects_short_read() {
        let mut r = NdrReader::new(&[0u8; 3]);
        let result = r.read_uint32();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DceRpcError::Ndr(_)));
        assert!(format!("{err}").contains("short read"));
    }

    #[test]
    fn ndr_conformant_array_round_trip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut w = NdrWriter::new();
        w.write_conformant_array(&data);
        let bytes = w.into_bytes();

        let mut r = NdrReader::new(&bytes);
        let decoded = r.read_conformant_array().unwrap();
        assert_eq!(decoded, data);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn ndr_conformant_array_empty_round_trip() {
        let mut w = NdrWriter::new();
        w.write_conformant_array(&[]);
        let bytes = w.into_bytes();
        let mut r = NdrReader::new(&bytes);
        let decoded = r.read_conformant_array().unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn ndr_string_ascii_round_trip() {
        let s = "DC=adrian,DC=example,DC=com";
        let mut w = NdrWriter::new();
        w.write_string(s);
        let bytes = w.into_bytes();

        let mut r = NdrReader::new(&bytes);
        let decoded = r.read_string().unwrap();
        assert_eq!(decoded, s);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn ndr_string_unicode_round_trip() {
        let s = "Adrián — ünïcödé";
        let mut w = NdrWriter::new();
        w.write_string(s);
        let bytes = w.into_bytes();

        let mut r = NdrReader::new(&bytes);
        let decoded = r.read_string().unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn ndr_string_empty_round_trip() {
        let mut w = NdrWriter::new();
        w.write_string("");
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 12 + 2);

        let mut r = NdrReader::new(&bytes);
        let decoded = r.read_string().unwrap();
        assert_eq!(decoded, "");
    }

    #[test]
    fn ndr_uuid_round_trip() {
        let uuid = Uuid::from_u128(0xE3514235_4B06_11D1_AB04_00C04FC2DCD2);
        let mut w = NdrWriter::new();
        w.write_uuid(uuid);
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes, uuid.as_bytes());

        let mut r = NdrReader::new(&bytes);
        let decoded = r.read_uuid().unwrap();
        assert_eq!(decoded, uuid);
    }

    #[test]
    fn ndr_transfer_syntax_constant_matches_ndr20_spec() {
        assert_eq!(
            NDR_TRANSFER_SYNTAX_UUID.to_string().to_uppercase(),
            "8A885D04-1CEB-11C9-9FE8-08002B104860"
        );
        assert_eq!(NDR_TRANSFER_SYNTAX_VERSION, 2);
    }

    #[test]
    fn ndr_mixed_field_round_trip() {
        let mut w = NdrWriter::new();
        w.write_uint8(0x11);
        w.write_uint16(0x2233);
        w.write_uint32(0x44556677);
        w.write_uint64(0x8899AABB_CCDDEEFF);
        let uuid = Uuid::from_u128(0x12345678_1234_ABCD_EF00_0123456789AC);
        w.write_uuid(uuid);
        let bytes = w.into_bytes();

        let mut r = NdrReader::new(&bytes);
        assert_eq!(r.read_uint8().unwrap(), 0x11);
        assert_eq!(r.read_uint16().unwrap(), 0x2233);
        assert_eq!(r.read_uint32().unwrap(), 0x44556677);
        assert_eq!(r.read_uint64().unwrap(), 0x8899AABB_CCDDEEFF);
        assert_eq!(r.read_uuid().unwrap(), uuid);
        assert_eq!(r.remaining(), 0);
    }
}
