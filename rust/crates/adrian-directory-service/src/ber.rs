//! BER (Basic Encoding Rules) codec primitives for LDAP messages
//! (RFC 4511 §5.1).
//!
//! BER uses Tag-Length-Value (TLV) encoding:
//! - **Tag**: 1 byte for tag numbers < 31 (the only form LDAP uses). The
//!   high 2 bits are the class (`UNIVERSAL`/`APPLICATION`/`CONTEXT`/
//!   `PRIVATE`), bit 5 is the constructed flag, and the low 5 bits are the
//!   tag number.
//! - **Length**: 1 byte for the short form (lengths 0-127), or multi-byte
//!   long form (first byte = `0x80 | num_length_bytes`, then big-endian
//!   length bytes). LDAP forbids the indefinite form (`0x80` with no
//!   following bytes — RFC 4511 §5.1).
//! - **Value**: the content octets.
//!
//! ## Tag classes used by LDAP
//!
//! - `UNIVERSAL` (`0x00`): built-in types — `INTEGER`, `OCTET STRING`,
//!   `SEQUENCE`, `BOOLEAN`, `ENUMERATED`, `NULL`.
//! - `APPLICATION` (`0x40`): LDAP protocol operations — `BindRequest`
//!   (`[APPLICATION 0]`), `SearchRequest` (`[APPLICATION 3]`), etc.
//! - `CONTEXT` (`0x80`): `CHOICE` alternatives — filter types
//!   (`[0]`=`and`, `[3]`=`equalityMatch`, `[7]`=`present`, ...),
//!   authentication choices (`[0]`=`simple`, `[3]`=`sasl`).
//! - `PRIVATE` (`0xC0`): not used by LDAP.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

// ---- Tag class bits (high 2 bits of the tag byte) ----

/// `0x00` — universal class (built-in ASN.1 types).
pub const CLASS_UNIVERSAL: u8 = 0x00;
/// `0x40` — application class (LDAP protocol operations).
pub const CLASS_APPLICATION: u8 = 0x40;
/// `0x80` — context class (CHOICE alternatives).
pub const CLASS_CONTEXT: u8 = 0x80;
/// `0xC0` — private class (unused by LDAP).
pub const CLASS_PRIVATE: u8 = 0xC0;

/// `0x20` — constructed bit (set for SEQUENCE, SET, and constructed
/// application/context tags).
pub const CONSTRUCTED: u8 = 0x20;

// ---- Universal tag numbers (low 5 bits when class is UNIVERSAL).
// The full tag byte includes CLASS_UNIVERSAL (0x00) and, for SEQUENCE/SET,
// the CONSTRUCTED bit. ----

/// `0x01` — BOOLEAN (universal, primitive).
pub const TAG_BOOLEAN: u8 = 0x01;
/// `0x02` — INTEGER (universal, primitive).
pub const TAG_INTEGER: u8 = 0x02;
/// `0x04` — OCTET STRING (universal, primitive).
pub const TAG_OCTET_STRING: u8 = 0x04;
/// `0x05` — NULL (universal, primitive).
pub const TAG_NULL: u8 = 0x05;
/// `0x06` — OBJECT IDENTIFIER (universal, primitive).
pub const TAG_OID: u8 = 0x06;
/// `0x0A` — ENUMERATED (universal, primitive).
pub const TAG_ENUMERATED: u8 = 0x0A;
/// `0x30` — SEQUENCE (universal, constructed). `(0x10 | CONSTRUCTED)`.
pub const TAG_SEQUENCE: u8 = 0x10 | CONSTRUCTED;
/// `0x31` — SET (universal, constructed). `(0x11 | CONSTRUCTED)`.
pub const TAG_SET: u8 = 0x11 | CONSTRUCTED;

// ---- Application tag bytes for LDAP protocol operations (RFC 4511 §4.1.1).
// These already include CLASS_APPLICATION (0x40) and the CONSTRUCTED bit
// where applicable. ----

/// `0x60` — BindRequest (`[APPLICATION 0]` constructed).
pub const APP_BIND_REQUEST: u8 = CLASS_APPLICATION | CONSTRUCTED;
/// `0x61` — BindResponse (`[APPLICATION 1]` constructed).
pub const APP_BIND_RESPONSE: u8 = CLASS_APPLICATION | CONSTRUCTED | 1;
/// `0x42` — UnbindRequest (`[APPLICATION 2]` primitive NULL).
pub const APP_UNBIND_REQUEST: u8 = CLASS_APPLICATION | 2;
/// `0x63` — SearchRequest (`[APPLICATION 3]` constructed).
pub const APP_SEARCH_REQUEST: u8 = CLASS_APPLICATION | CONSTRUCTED | 3;
/// `0x64` — SearchResultEntry (`[APPLICATION 4]` constructed).
pub const APP_SEARCH_RESULT_ENTRY: u8 = CLASS_APPLICATION | CONSTRUCTED | 4;
/// `0x65` — SearchResultDone (`[APPLICATION 5]` constructed).
pub const APP_SEARCH_RESULT_DONE: u8 = CLASS_APPLICATION | CONSTRUCTED | 5;
/// `0x66` — ModifyRequest (`[APPLICATION 6]` constructed).
pub const APP_MODIFY_REQUEST: u8 = CLASS_APPLICATION | CONSTRUCTED | 6;
/// `0x67` — ModifyResponse (`[APPLICATION 7]` constructed).
pub const APP_MODIFY_RESPONSE: u8 = CLASS_APPLICATION | CONSTRUCTED | 7;
/// `0x68` — AddRequest (`[APPLICATION 8]` constructed).
pub const APP_ADD_REQUEST: u8 = CLASS_APPLICATION | CONSTRUCTED | 8;
/// `0x69` — AddResponse (`[APPLICATION 9]` constructed).
pub const APP_ADD_RESPONSE: u8 = CLASS_APPLICATION | CONSTRUCTED | 9;
/// `0x4A` — DelRequest (`[APPLICATION 10]` primitive OCTET STRING).
pub const APP_DEL_REQUEST: u8 = CLASS_APPLICATION | 10;
/// `0x6B` — DelResponse (`[APPLICATION 11]` constructed).
pub const APP_DEL_RESPONSE: u8 = CLASS_APPLICATION | CONSTRUCTED | 11;

// ---- Context tag bytes for LDAP search filters (RFC 4511 §4.5.1). ----

/// `0xA0` — `and` filter (`[0]` constructed).
pub const FILTER_AND: u8 = CLASS_CONTEXT | CONSTRUCTED;
/// `0xA1` — `or` filter (`[1]` constructed).
pub const FILTER_OR: u8 = CLASS_CONTEXT | CONSTRUCTED | 1;
/// `0xA2` — `not` filter (`[2]` constructed).
pub const FILTER_NOT: u8 = CLASS_CONTEXT | CONSTRUCTED | 2;
/// `0xA3` — `equalityMatch` filter (`[3]` constructed).
pub const FILTER_EQUALITY: u8 = CLASS_CONTEXT | CONSTRUCTED | 3;
/// `0xA4` — `substrings` filter (`[4]` constructed).
pub const FILTER_SUBSTRINGS: u8 = CLASS_CONTEXT | CONSTRUCTED | 4;
/// `0xA5` — `greaterOrEqual` filter (`[5]` constructed).
pub const FILTER_GE: u8 = CLASS_CONTEXT | CONSTRUCTED | 5;
/// `0xA6` — `lessOrEqual` filter (`[6]` constructed).
pub const FILTER_LE: u8 = CLASS_CONTEXT | CONSTRUCTED | 6;
/// `0x87` — `present` filter (`[7]` primitive).
pub const FILTER_PRESENT: u8 = CLASS_CONTEXT | 7;
/// `0xA8` — `approxMatch` filter (`[8]` constructed).
pub const FILTER_APPROX: u8 = CLASS_CONTEXT | CONSTRUCTED | 8;

// ---- Context tag bytes for authentication choices (RFC 4511 §4.2.1). ----

/// `0x80` — `simple` authentication (`[0]` primitive OCTET STRING).
pub const AUTH_SIMPLE: u8 = CLASS_CONTEXT;
/// `0xA3` — `sasl` authentication (`[3]` constructed).
pub const AUTH_SASL: u8 = CLASS_CONTEXT | CONSTRUCTED | 3;

// ---- Context tag bytes for substring choices (RFC 4511 §4.5.1). ----

/// `0x80` — `initial` substring (`[0]` primitive).
pub const SUBSTRING_INITIAL: u8 = CLASS_CONTEXT;
/// `0x81` — `any` substring (`[1]` primitive).
pub const SUBSTRING_ANY: u8 = CLASS_CONTEXT | 1;
/// `0x82` — `final` substring (`[2]` primitive).
pub const SUBSTRING_FINAL: u8 = CLASS_CONTEXT | 2;

// ---- Context tag bytes for the LDAPMessage `controls` field (RFC 4511
// §4.1.1). ----

/// `0xA0` — `controls` field of `LDAPMessage` (`[0]` constructed).
pub const CONTROLS_TAG: u8 = CLASS_CONTEXT | CONSTRUCTED;

/// A parsed BER TLV (Tag-Length-Value) borrowing from the input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// The full tag byte (class + constructed bit + tag number).
    pub tag: u8,
    /// The value bytes (content octets).
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Returns `true` if this TLV's tag has the CONSTRUCTED bit set.
    pub fn is_constructed(&self) -> bool {
        self.tag & CONSTRUCTED != 0
    }

    /// Returns the tag-class bits (high 2 bits of the tag byte).
    pub fn class(&self) -> u8 {
        self.tag & 0xC0
    }

    /// Returns the tag number (low 5 bits of the tag byte).
    pub fn number(&self) -> u8 {
        self.tag & 0x1F
    }
}

/// Error type for BER encode/decode operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BerError {
    /// The input was empty where a TLV was expected.
    #[error("BER empty input")]
    Empty,
    /// Truncated input (not enough bytes to decode a complete TLV).
    #[error("BER truncated: {0}")]
    Truncated(&'static str),
    /// Invalid length encoding (e.g. indefinite form, or reserved 0xFF).
    #[error("BER invalid length: {0}")]
    InvalidLength(String),
    /// Unexpected tag (expected one tag, got another).
    #[error("BER unexpected tag: expected {expected:#04x}, got {actual:#04x}")]
    UnexpectedTag {
        /// The expected tag byte.
        expected: u8,
        /// The actual tag byte encountered.
        actual: u8,
    },
    /// Invalid INTEGER encoding (empty, or more than 8 bytes).
    #[error("BER invalid integer: {0}")]
    InvalidInteger(String),
    /// Invalid string encoding (not valid UTF-8).
    #[error("BER invalid UTF-8 string: {0}")]
    InvalidUtf8(String),
    /// Trailing data after the parsed TLV.
    #[error("BER trailing data: {0} bytes")]
    TrailingData(usize),
    /// Unknown protocol op tag.
    #[error("BER unknown protocol op tag: {0:#04x}")]
    UnknownProtocolOp(u8),
    /// Unknown filter tag.
    #[error("BER unknown filter tag: {0:#04x}")]
    UnknownFilter(u8),
    /// Long-form tag numbers (tag & 0x1F == 0x1F) are not supported in LDAP.
    #[error("BER long-form tag not supported: {0:#04x}")]
    LongFormTag(u8),
    /// INTEGER value out of the valid range for the target type.
    #[error("BER integer out of range: {0}")]
    OutOfRange(String),
}

/// Encode a BER length into `out` (short form for 0-127, long form
/// otherwise).
pub fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        // Long form: first byte = 0x80 | num_length_bytes, then big-endian
        // length bytes (minimum number of bytes to represent the length).
        let mut bytes = Vec::with_capacity(8);
        let mut n = len;
        while n > 0 {
            bytes.insert(0, (n & 0xFF) as u8);
            n >>= 8;
        }
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

/// Encode a TLV (tag + length + value) into `out`.
pub fn encode_tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    encode_length(value.len(), out);
    out.extend_from_slice(value);
}

/// Decode a single TLV from the front of `bytes`. Returns the parsed TLV
/// and the remaining bytes (after the TLV).
///
/// Returns [`BerError::Empty`] if `bytes` is empty, or
/// [`BerError::Truncated`] if `bytes` does not contain a complete TLV
/// (the caller may read more bytes and retry).
pub fn decode_tlv(bytes: &[u8]) -> Result<(Tlv<'_>, &[u8]), BerError> {
    if bytes.is_empty() {
        return Err(BerError::Empty);
    }
    let tag = bytes[0];
    // LDAP never uses long-form tags (tag & 0x1F == 0x1F). Reject them.
    if tag & 0x1F == 0x1F {
        return Err(BerError::LongFormTag(tag));
    }
    if bytes.len() < 2 {
        return Err(BerError::Truncated("missing length byte"));
    }
    let first_len = bytes[1];
    let (len, header_len) = if first_len < 0x80 {
        // Short form: length is the single byte itself.
        (first_len as usize, 2)
    } else {
        let num_bytes = (first_len & 0x7F) as usize;
        if num_bytes == 0 {
            // Indefinite-length form (0x80) — forbidden by RFC 4511 §5.1.
            return Err(BerError::InvalidLength(
                "indefinite length form not supported in LDAP".into(),
            ));
        }
        if num_bytes > 4 {
            return Err(BerError::InvalidLength(format!(
                "length too large: {} bytes",
                num_bytes
            )));
        }
        if bytes.len() < 2 + num_bytes {
            return Err(BerError::Truncated("truncated long-form length"));
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (bytes[2 + i] as usize);
        }
        (len, 2 + num_bytes)
    };
    if bytes.len() < header_len + len {
        return Err(BerError::Truncated("value shorter than declared length"));
    }
    let value = &bytes[header_len..header_len + len];
    let rest = &bytes[header_len + len..];
    Ok((Tlv { tag, value }, rest))
}

/// Peek at the tag of the next TLV without consuming it. Returns
/// [`BerError::Empty`] if `bytes` is empty.
pub fn peek_tag(bytes: &[u8]) -> Result<u8, BerError> {
    if bytes.is_empty() {
        return Err(BerError::Empty);
    }
    Ok(bytes[0])
}

// ---- Primitive type encoders ----

/// Encode a BOOLEAN into `out` (universal tag `0x01`).
pub fn encode_bool(b: bool, out: &mut Vec<u8>) {
    encode_tlv(TAG_BOOLEAN, &[if b { 0xFF } else { 0x00 }], out);
}

/// Decode a BOOLEAN from a TLV value.
pub fn decode_bool_value(value: &[u8]) -> Result<bool, BerError> {
    if value.len() != 1 {
        return Err(BerError::InvalidInteger(format!(
            "BOOLEAN must be 1 byte, got {}",
            value.len()
        )));
    }
    Ok(value[0] != 0x00)
}

/// Encode a signed INTEGER into `out` (universal tag `0x02`). Uses the
/// minimum number of bytes (per BER §8.3.2) and adds a leading `0x00` or
/// `0xFF` byte to disambiguate the sign when needed.
pub fn encode_integer(n: i64, out: &mut Vec<u8>) {
    let bytes = int_to_bytes(n);
    encode_tlv(TAG_INTEGER, &bytes, out);
}

/// Encode an ENUMERATED (same encoding as INTEGER, but tag `0x0A`).
pub fn encode_enumerated(n: i64, out: &mut Vec<u8>) {
    let bytes = int_to_bytes(n);
    encode_tlv(TAG_ENUMERATED, &bytes, out);
}

/// Convert a signed 64-bit integer to its minimum-byte big-endian two's
/// complement representation (per BER §8.3.2).
fn int_to_bytes(n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![0x00];
    }
    let mut bytes = Vec::with_capacity(8);
    let mut x = n;
    // Shift bytes off the right end until only the sign bits remain.
    while x != 0 && x != -1 {
        bytes.insert(0, (x & 0xFF) as u8);
        x >>= 8;
    }
    if bytes.is_empty() {
        // n is exactly 0 or -1 — emit a single sign byte.
        bytes.push(if n >= 0 { 0x00 } else { 0xFF });
    } else if n >= 0 && (bytes[0] & 0x80) != 0 {
        // Positive number whose high bit is set — prepend 0x00 to keep it
        // positive.
        bytes.insert(0, 0x00);
    } else if n < 0 && (bytes[0] & 0x80) == 0 {
        // Negative number whose high bit is clear — prepend 0xFF to keep
        // it negative.
        bytes.insert(0, 0xFF);
    }
    bytes
}

/// Decode a signed INTEGER from a TLV value (big-endian two's complement,
/// 1-8 bytes).
pub fn decode_integer_value(value: &[u8]) -> Result<i64, BerError> {
    if value.is_empty() {
        return Err(BerError::InvalidInteger("empty INTEGER".into()));
    }
    if value.len() > 8 {
        return Err(BerError::InvalidInteger(format!(
            "INTEGER too large: {} bytes",
            value.len()
        )));
    }
    // Sign-extend: if the high bit is set, start from all-1s; else start
    // from 0.
    let mut n = if value[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in value {
        n = (n << 8) | (b as i64 & 0xFF);
    }
    Ok(n)
}

/// Encode an OCTET STRING into `out` (universal tag `0x04`).
pub fn encode_octet_string(bytes: &[u8], out: &mut Vec<u8>) {
    encode_tlv(TAG_OCTET_STRING, bytes, out);
}

/// Encode a UTF-8 string as an OCTET STRING (LDAP `LDAPString` / `LDAPDN`
/// are both OCTET STRINGs containing UTF-8).
pub fn encode_string(s: &str, out: &mut Vec<u8>) {
    encode_octet_string(s.as_bytes(), out);
}

/// Decode a UTF-8 string from an OCTET STRING value.
pub fn decode_string_value(value: &[u8]) -> Result<String, BerError> {
    std::str::from_utf8(value)
        .map(String::from)
        .map_err(|e| BerError::InvalidUtf8(e.to_string()))
}

/// Encode a NULL into `out` (universal tag `0x05`, zero-length value).
pub fn encode_null(out: &mut Vec<u8>) {
    encode_tlv(TAG_NULL, &[], out);
}

/// Encode a SEQUENCE of pre-encoded elements into `out`. Each element is
/// already a complete TLV (tag + length + value); they are concatenated
/// and wrapped in a `SEQUENCE` (tag `0x30`).
pub fn encode_sequence(elements: &[Vec<u8>], out: &mut Vec<u8>) {
    let mut value = Vec::new();
    for e in elements {
        value.extend_from_slice(e);
    }
    encode_tlv(TAG_SEQUENCE, &value, out);
}

/// Encode a SET of pre-encoded elements into `out` (tag `0x31`). Used by
/// `PartialAttribute.vals` (a SET OF AttributeValue, per RFC 4511 §4.1.5
/// — though most implementations accept either SET or SEQUENCE; we emit
/// SET for spec-conformance).
pub fn encode_set(elements: &[Vec<u8>], out: &mut Vec<u8>) {
    let mut value = Vec::new();
    for e in elements {
        value.extend_from_slice(e);
    }
    encode_tlv(TAG_SET, &value, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_length_short_form() {
        let mut out = Vec::new();
        encode_length(0, &mut out);
        encode_length(127, &mut out);
        assert_eq!(out, vec![0x00, 0x7F]);
    }

    #[test]
    fn encode_length_long_form() {
        let mut out = Vec::new();
        encode_length(128, &mut out);
        encode_length(256, &mut out);
        encode_length(65536, &mut out);
        // 128 → 0x81 0x80 (one length byte: 0x80)
        // 256 → 0x82 0x01 0x00 (two length bytes: 0x0100)
        // 65536 → 0x83 0x01 0x00 0x00 (three length bytes: 0x010000)
        assert_eq!(
            out,
            vec![0x81, 0x80, 0x82, 0x01, 0x00, 0x83, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn decode_tlv_short_form() {
        // SEQUENCE of length 3, value [0x01, 0x02, 0x03]
        let bytes = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let (tlv, rest) = decode_tlv(&bytes).unwrap();
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.value, &[0x01, 0x02, 0x03]);
        assert!(rest.is_empty());
        assert!(tlv.is_constructed());
        assert_eq!(tlv.class(), CLASS_UNIVERSAL);
    }

    #[test]
    fn decode_tlv_long_form_length() {
        // OCTET STRING of length 200, with long-form length (0x81 0xC8).
        let mut bytes = vec![0x04, 0x81, 0xC8];
        bytes.extend(std::iter::repeat_n(0xAA, 200));
        let (tlv, rest) = decode_tlv(&bytes).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value.len(), 200);
        assert!(rest.is_empty());
    }

    #[test]
    fn decode_tlv_empty_input() {
        let bytes: Vec<u8> = vec![];
        let err = decode_tlv(&bytes).unwrap_err();
        assert_eq!(err, BerError::Empty);
    }

    #[test]
    fn decode_tlv_truncated_value() {
        // Declares length 5 but only provides 3 bytes.
        let bytes = vec![0x04, 0x05, 0x01, 0x02, 0x03];
        let err = decode_tlv(&bytes).unwrap_err();
        assert!(matches!(err, BerError::Truncated(_)));
    }

    #[test]
    fn decode_tlv_rejects_indefinite_length() {
        // Indefinite form (0x80 as the length byte) is forbidden by LDAP.
        let bytes = vec![0x30, 0x80, 0x01, 0x02, 0x03, 0x00, 0x00];
        let err = decode_tlv(&bytes).unwrap_err();
        assert!(matches!(err, BerError::InvalidLength(_)));
    }

    #[test]
    fn decode_tlv_rejects_long_form_tag() {
        // Tag with all 5 low bits set (0x1F) → long-form tag, not supported.
        let bytes = vec![0x1F, 0x01, 0x00];
        let err = decode_tlv(&bytes).unwrap_err();
        assert!(matches!(err, BerError::LongFormTag(_)));
    }

    #[test]
    fn encode_integer_zero() {
        let mut out = Vec::new();
        encode_integer(0, &mut out);
        // 02 01 00
        assert_eq!(out, vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn encode_integer_one() {
        let mut out = Vec::new();
        encode_integer(1, &mut out);
        // 02 01 01
        assert_eq!(out, vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn encode_integer_128_requires_leading_zero() {
        let mut out = Vec::new();
        encode_integer(128, &mut out);
        // 02 02 00 80 (leading 0x00 keeps the high bit clear → positive)
        assert_eq!(out, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn encode_integer_negative_one() {
        let mut out = Vec::new();
        encode_integer(-1, &mut out);
        // 02 01 FF
        assert_eq!(out, vec![0x02, 0x01, 0xFF]);
    }

    #[test]
    fn encode_integer_negative_129_requires_leading_ff() {
        let mut out = Vec::new();
        encode_integer(-129, &mut out);
        // 02 02 FF 7F (leading 0xFF keeps the high bit set → negative)
        assert_eq!(out, vec![0x02, 0x02, 0xFF, 0x7F]);
    }

    #[test]
    fn decode_integer_round_trip() {
        for n in [
            0i64,
            1,
            127,
            128,
            255,
            256,
            65535,
            65536,
            -1,
            -127,
            -128,
            -129,
            i32::MAX as i64,
            i32::MIN as i64,
            i64::MAX,
            i64::MIN,
        ] {
            let mut out = Vec::new();
            encode_integer(n, &mut out);
            // Strip the tag and length to get the value bytes.
            let (tlv, rest) = decode_tlv(&out).unwrap();
            assert!(rest.is_empty());
            let decoded = decode_integer_value(tlv.value).unwrap();
            assert_eq!(decoded, n, "round-trip failed for {}", n);
        }
    }

    #[test]
    fn encode_bool_true_false() {
        let mut out = Vec::new();
        encode_bool(true, &mut out);
        encode_bool(false, &mut out);
        // 01 01 FF   01 01 00
        assert_eq!(out, vec![0x01, 0x01, 0xFF, 0x01, 0x01, 0x00]);
    }

    #[test]
    fn encode_null_round_trip() {
        let mut out = Vec::new();
        encode_null(&mut out);
        // 05 00
        assert_eq!(out, vec![0x05, 0x00]);
        let (tlv, _) = decode_tlv(&out).unwrap();
        assert_eq!(tlv.tag, TAG_NULL);
        assert!(tlv.value.is_empty());
    }

    #[test]
    fn encode_string_round_trip() {
        let mut out = Vec::new();
        encode_string("CN=alice,DC=adrian", &mut out);
        let (tlv, _) = decode_tlv(&out).unwrap();
        assert_eq!(tlv.tag, TAG_OCTET_STRING);
        assert_eq!(
            decode_string_value(tlv.value).unwrap(),
            "CN=alice,DC=adrian"
        );
    }

    #[test]
    fn encode_sequence_wraps_elements() {
        let mut e1 = Vec::new();
        encode_integer(1, &mut e1);
        let mut e2 = Vec::new();
        encode_string("hi", &mut e2);
        let mut out = Vec::new();
        encode_sequence(&[e1, e2], &mut out);
        // 30 07  02 01 01  04 02 68 69
        assert_eq!(
            out,
            vec![0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0x68, 0x69]
        );
    }

    #[test]
    fn peek_tag_returns_first_byte() {
        let bytes = vec![0x60, 0x00];
        assert_eq!(peek_tag(&bytes).unwrap(), 0x60);
    }

    #[test]
    fn peek_tag_empty_returns_error() {
        let bytes: Vec<u8> = vec![];
        assert_eq!(peek_tag(&bytes).unwrap_err(), BerError::Empty);
    }
}
