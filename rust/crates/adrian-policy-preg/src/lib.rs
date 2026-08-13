//! # adrian-policy-preg
//!
//! PReg adapter — read/write Windows `Registry.pol` (PReg format per
//! MS-GPREG §2.2). The PReg format is the binary file that AD Group Policy
//! places at `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}\Machine\Registry.pol`
//! (and `User\Registry.pol`). The framework's policy distribution service
//! synthesises this file from canonical JSON per ADR-029 §3 when serving
//! legacy Windows `gpsvc.dll` clients.
//!
//! ## PReg wire format (MS-GPREG §2.2)
//!
//! A `Registry.pol` file is:
//! - A 6-byte signature: ASCII `PReg\x00\x00` (4 chars + 2 NULs).
//! - A sequence of UTF-16LE-encoded records, each of the form
//!   `[key;value;type;size;data;]` where:
//!   - `key`, `value` are UTF-16LE strings (no NUL terminator; the `;`
//!     separates fields).
//!   - `type` is a decimal ASCII number (1 = REG_SZ, 2 = REG_EXPAND_SZ,
//!     3 = REG_BINARY, 4 = REG_DWORD, 7 = REG_MULTI_SZ, 11 = REG_QWORD).
//!   - `size` is the byte length of the decoded `data` as decimal ASCII.
//!   - `data` is hex-encoded ASCII (two hex chars per byte).
//!   - The `[`, `]`, `;` delimiters are themselves encoded as UTF-16LE.
//!
//! ## ADRs
//!
//! - ADR-029: JSON canonical policy + PReg adapter
//! - ADR-089: Declarative policy ↔ GPC/GPT synthesis
//! - ADR-092: PolicyExecutor trait + synthetic Windows CSE
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-schema-traits` for shared traits; no async I/O — pure encoding.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// Registry value type IDs (per MS-GPREG §2.4 — these are the standard
/// Windows registry type numbers, not framework-specific).
pub mod reg_value {
    /// REG_NONE — no value type.
    pub const REG_NONE: u32 = 0;
    /// REG_SZ — null-terminated Unicode string (encoded UTF-16LE in PReg).
    pub const REG_SZ: u32 = 1;
    /// REG_EXPAND_SZ — string with `%VAR%` references (encoded UTF-16LE).
    pub const REG_EXPAND_SZ: u32 = 2;
    /// REG_BINARY — raw binary.
    pub const REG_BINARY: u32 = 3;
    /// REG_DWORD — 32-bit little-endian unsigned int.
    pub const REG_DWORD: u32 = 4;
    /// REG_DWORD_BIG_ENDIAN — 32-bit big-endian (rare).
    pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
    /// REG_MULTI_SZ — sequence of null-terminated strings, double-null-terminated.
    pub const REG_MULTI_SZ: u32 = 7;
    /// REG_QWORD — 64-bit little-endian unsigned int.
    pub const REG_QWORD: u32 = 11;
}

/// Error type for PReg encoding/decoding operations.
#[derive(Debug, Error)]
pub enum PregError {
    /// The PReg byte stream is malformed (per MS-GPREG §2.2 — bad signature,
    /// truncated record, bad hex digits, non-UTF-16LE field, etc.).
    #[error("invalid PReg format: {0}")]
    Invalid(String),
    /// I/O error from underlying read/write (per `std::io::Error`).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Single PReg registry entry — one `[key;value;type;size;data;]` record
/// in a `Registry.pol` file (per MS-GPREG §2.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PregEntry {
    /// The registry key path (e.g. `Software\Adrian\Framework`).
    pub key: String,
    /// The registry value name (e.g. `Enabled`).
    pub value_name: String,
    /// The registry value type (per MS-GPREG §2.4 — see [`reg_value`]).
    pub value_type: u32,
    /// The value data, as raw bytes. For REG_SZ / REG_EXPAND_SZ this is
    /// UTF-16LE-encoded (no NUL terminator in the struct; the encoder
    /// appends one in the wire form). For REG_DWORD this is 4
    /// little-endian bytes. For REG_MULTI_SZ this is a sequence of
    /// UTF-16LE strings each NUL-terminated, plus a final NUL terminator.
    pub value: Vec<u8>,
}

impl PregEntry {
    /// Construct a new `PregEntry` with the given key, value name, type,
    /// and raw data bytes. Convenience constructor that avoids the
    /// struct-literal ceremony at call sites.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        value_name: impl Into<String>,
        value_type: u32,
        value: Vec<u8>,
    ) -> Self {
        Self {
            key: key.into(),
            value_name: value_name.into(),
            value_type,
            value,
        }
    }

    /// The size, in bytes, of the decoded value data — the `size` field
    /// of the PReg record (per MS-GPREG §2.2.1). Always equal to
    /// `self.value.len()`.
    #[must_use]
    pub fn size(&self) -> u32 {
        u32::try_from(self.value.len()).unwrap_or(u32::MAX)
    }
}

/// PReg file (Registry.pol) — a parsed in-memory representation of a
/// `Registry.pol` byte stream (per MS-GPREG §2.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PregFile {
    /// The entries in the file, in their on-disk order.
    pub entries: Vec<PregEntry>,
}

/// The 6-byte PReg file signature: ASCII `PReg\x00\x00` (4 chars + 2 NULs).
pub const PREG_SIGNATURE: &[u8] = b"PReg\x00\x00";

impl PregFile {
    /// Construct an empty `PregFile`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a `Registry.pol` byte stream (per MS-GPREG §2.2). Returns
    /// `Err(PregError::Invalid)` if the signature is wrong, the records
    /// are truncated, or any field fails to decode as UTF-16LE / hex.
    ///
    /// This implementation is per ADR-029 §3 — it is the legacy-import
    /// path that the framework's migration tooling (per ADR-055) uses to
    /// read existing AD `Registry.pol` files into canonical JSON.
    pub fn parse(bytes: &[u8]) -> Result<Self, PregError> {
        decode_preg_file(bytes)
    }

    /// Serialize back to `Registry.pol` bytes (per MS-GPREG §2.2). The
    /// output is byte-identical for any structurally-equal `PregFile`
    /// (deterministic — required for Git diffability per ADR-031 and
    /// for the PReg round-trip test in ADR-090 §8 CI).
    ///
    /// Errors:
    /// - `PregError::Invalid` if any entry's `value_type` or `value`
    ///   cannot be encoded (e.g. a non-finite `size`).
    pub fn serialize(&self) -> Result<Vec<u8>, PregError> {
        Ok(encode_preg_file(self))
    }
}

// ---- free-function API (per Wave 4a task spec) -----------------------------

/// Encode a `PregFile` into the on-disk PReg byte format (per MS-GPREG
/// §2.2 — see [`PREG_SIGNATURE`] and the record format documented at the
/// crate root).
///
/// Deterministic: two `PregFile`s that compare `==` produce identical
/// bytes (per ADR-031 §Git-diffability and ADR-090 §8 CI regression
/// contract).
#[must_use]
pub fn encode_preg_file(file: &PregFile) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREG_SIGNATURE.len() + file.entries.len() * 64);
    out.extend_from_slice(PREG_SIGNATURE);
    for entry in &file.entries {
        // `[` delimiter as UTF-16LE (0x5B 0x00).
        out.extend_from_slice(&[0x5B, 0x00]);
        encode_field_utf16(&mut out, &entry.key);
        out.extend_from_slice(&[0x3B, 0x00]); // ';'
        encode_field_utf16(&mut out, &entry.value_name);
        out.extend_from_slice(&[0x3B, 0x00]); // ';'
                                              // type as decimal ASCII digits, UTF-16LE
        encode_field_utf16(&mut out, &entry.value_type.to_string());
        out.extend_from_slice(&[0x3B, 0x00]); // ';'
                                              // size as decimal ASCII digits, UTF-16LE
        let size = entry.size();
        encode_field_utf16(&mut out, &size.to_string());
        out.extend_from_slice(&[0x3B, 0x00]); // ';'
                                              // data as hex-encoded ASCII, UTF-16LE
        let mut hex = String::with_capacity(entry.value.len() * 2);
        for b in &entry.value {
            // uppercase hex per MS-GPREG §2.2.1 examples (samba-gpupdate
            // accepts both cases; we emit uppercase for byte-stability).
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{:02X}", b);
        }
        encode_field_utf16(&mut out, &hex);
        out.extend_from_slice(&[0x3B, 0x00]); // ';'
        out.extend_from_slice(&[0x5D, 0x00]); // ']'
    }
    out
}

/// Decode a PReg byte stream into a `PregFile` (per MS-GPREG §2.2 — the
/// reverse of [`encode_preg_file`]).
pub fn decode_preg_file(bytes: &[u8]) -> Result<PregFile, PregError> {
    if bytes.len() < PREG_SIGNATURE.len() {
        return Err(PregError::Invalid(format!(
            "file too short for PReg signature ({} < {})",
            bytes.len(),
            PREG_SIGNATURE.len()
        )));
    }
    if &bytes[..PREG_SIGNATURE.len()] != PREG_SIGNATURE {
        // Show the actual signature bytes for diagnostics.
        let mut sig = String::new();
        for &b in &bytes[..PREG_SIGNATURE.len()] {
            sig.push(if b.is_ascii_graphic() || b == 0 {
                char::from(b)
            } else {
                '?'
            });
        }
        return Err(PregError::Invalid(format!("bad PReg signature: {sig:?}")));
    }
    let mut pos = PREG_SIGNATURE.len();
    let mut entries = Vec::new();

    while pos < bytes.len() {
        // Skip stray bytes between records (PReg files sometimes have
        // a trailing NUL or whitespace). We only treat `[` as a record
        // start.
        if bytes[pos] != b'[' {
            // Allow EOF
            if pos == bytes.len() {
                break;
            }
            // Allow a single trailing NUL padding byte (some Windows tools
            // emit one) — otherwise reject.
            if pos == bytes.len() - 1 && bytes[pos] == 0x00 {
                break;
            }
            return Err(PregError::Invalid(format!(
                "expected '[' at offset {pos} but got byte 0x{:02X}",
                bytes[pos]
            )));
        }
        // We are now positioned at a UTF-16LE `[`. Consume it (2 bytes).
        if pos + 1 >= bytes.len() || bytes[pos + 1] != 0x00 {
            return Err(PregError::Invalid(format!(
                "non-UTF-16LE '[' at offset {pos} (high byte = 0x{:02X})",
                bytes.get(pos + 1).copied().unwrap_or(0)
            )));
        }
        pos += 2;

        // Read 5 fields separated by `;`, then expect `]`.
        let mut fields: Vec<String> = Vec::with_capacity(5);
        for i in 0..5 {
            let (field, next) = read_utf16_until_semi(&bytes[pos..], i)?;
            fields.push(field);
            pos += next;
        }
        // Expect closing `]`.
        if pos >= bytes.len() || bytes[pos] != b']' || bytes.get(pos + 1) != Some(&0x00) {
            return Err(PregError::Invalid(format!(
                "expected UTF-16LE ']' at offset {pos} but got {:?}",
                bytes.get(pos..pos + 2).unwrap_or(&[])
            )));
        }
        pos += 2;

        let key = fields[0].clone();
        let value_name = fields[1].clone();
        let value_type: u32 = fields[2]
            .parse()
            .map_err(|e| PregError::Invalid(format!("bad type field {:?}: {e}", fields[2])))?;
        let size: u32 = fields[3]
            .parse()
            .map_err(|e| PregError::Invalid(format!("bad size field {:?}: {e}", fields[3])))?;
        let data_hex = fields[4].clone();
        let value = decode_hex(&data_hex)?;
        if u32::try_from(value.len()).map_err(|_| {
            PregError::Invalid(format!("decoded data length overflow: {}", value.len()))
        })? != size
        {
            return Err(PregError::Invalid(format!(
                "size field ({size}) != decoded data length ({})",
                value.len()
            )));
        }
        entries.push(PregEntry {
            key,
            value_name,
            value_type,
            value,
        });
    }

    Ok(PregFile { entries })
}

// ---- helpers ---------------------------------------------------------------

/// Encode a Rust `&str` as UTF-16LE bytes and append to `out`.
fn encode_field_utf16(out: &mut Vec<u8>, s: &str) {
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
}

/// Read a UTF-16LE string until a `;` (semicolon) delimiter.
/// Returns the decoded Rust `String` and the number of bytes consumed
/// (including the trailing `;` which acts as the field terminator).
fn read_utf16_until_semi(buf: &[u8], field_idx: usize) -> Result<(String, usize), PregError> {
    let mut code_units: Vec<u16> = Vec::new();
    let mut i = 0;
    loop {
        if i + 1 >= buf.len() {
            return Err(PregError::Invalid(format!(
                "truncated UTF-16LE field {field_idx} (no terminating ';')"
            )));
        }
        let lo = buf[i];
        let hi = buf[i + 1];
        let u = u16::from_le_bytes([lo, hi]);
        i += 2;
        if u == b';' as u16 {
            // Found the terminator. Decode what we accumulated.
            let s = String::from_utf16(&code_units).map_err(|e| {
                PregError::Invalid(format!("non-UTF-16LE in field {field_idx}: {e}"))
            })?;
            return Ok((s, i));
        }
        code_units.push(u);
    }
}

/// Decode a hex-encoded ASCII string (e.g. `"0102FF"`) into raw bytes
/// (`[0x01, 0x02, 0xFF]`). Accepts both upper- and lower-case hex.
fn decode_hex(s: &str) -> Result<Vec<u8>, PregError> {
    if !s.len().is_multiple_of(2) {
        return Err(PregError::Invalid(format!(
            "hex data has odd length ({}): {s:?}",
            s.len()
        )));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, PregError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(PregError::Invalid(format!(
            "bad hex digit 0x{b:02X} in data field"
        ))),
    }
}

// ---- typed-value helpers (per Wave 4a task spec: REG_SZ, REG_DWORD, etc.) --

/// Encode a Rust string into the REG_SZ wire form: UTF-16LE + a single
/// trailing NUL code unit (2 bytes). Per MS-GPREG §2.2.1, REG_SZ data
/// is the string's UTF-16LE bytes followed by a UTF-16LE NUL terminator.
#[must_use]
pub fn encode_reg_sz(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    out.extend_from_slice(&[0x00, 0x00]); // trailing NUL
    out
}

/// Decode REG_SZ bytes (UTF-16LE + NUL terminator) into a Rust `String`.
/// Trailing NULs are stripped.
pub fn decode_reg_sz(bytes: &[u8]) -> Result<String, PregError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(PregError::Invalid(format!(
            "REG_SZ data has odd byte length ({})",
            bytes.len()
        )));
    }
    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // Strip trailing NUL(s).
    while units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16(&units)
        .map_err(|e| PregError::Invalid(format!("REG_SZ data is not valid UTF-16LE: {e}")))
}

/// Encode a `u32` as REG_DWORD (4 bytes, little-endian).
#[must_use]
pub fn encode_reg_dword(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// Decode 4 little-endian bytes as a `u32` REG_DWORD value.
pub fn decode_reg_dword(bytes: &[u8]) -> Result<u32, PregError> {
    if bytes.len() != 4 {
        return Err(PregError::Invalid(format!(
            "REG_DWORD data length {} != 4",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(arr))
}

/// Encode a list of Rust strings as REG_MULTI_SZ: each string UTF-16LE
/// + NUL terminator, then a final empty-string NUL terminator. Per
///   MS-GPREG §2.2.1.
#[must_use]
pub fn encode_reg_multi_sz(strings: &[String]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for s in strings {
        out.extend(s.encode_utf16().flat_map(|u| u.to_le_bytes()));
        out.extend_from_slice(&[0x00, 0x00]); // string NUL terminator
    }
    out.extend_from_slice(&[0x00, 0x00]); // final list terminator
    out
}

/// Decode REG_MULTI_SZ bytes into a list of Rust strings. The trailing
/// empty-string terminator is stripped from the result.
pub fn decode_reg_multi_sz(bytes: &[u8]) -> Result<Vec<String>, PregError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(PregError::Invalid(format!(
            "REG_MULTI_SZ data has odd byte length ({})",
            bytes.len()
        )));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut out = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    let mut saw_final_terminator = false;
    for u in units {
        if u == 0 {
            if current.is_empty() {
                // Either the final terminator or a spurious empty entry
                // between two strings. Per MS-GPREG, an empty current at
                // a NUL means the list ends here.
                saw_final_terminator = true;
                break;
            }
            let s = String::from_utf16(&current)
                .map_err(|e| PregError::Invalid(format!("REG_MULTI_SZ entry not UTF-16LE: {e}")))?;
            out.push(s);
            current.clear();
        } else {
            current.push(u);
        }
    }
    let _ = saw_final_terminator; // tracked but not enforced strictly
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Behavioral tests for `adrian-policy-preg`. Per the Wave 4a task
    //! instructions these cover the real PReg wire format end-to-end:
    //! signature, record framing, UTF-16LE field encoding, hex data
    //! encoding, and the typed-value helpers (REG_SZ, REG_DWORD,
    //! REG_BINARY, REG_MULTI_SZ). The loud-stub tests from the previous
    //! wave have been replaced by real round-trip tests.

    use super::*;

    /// Build a small but representative `PregFile` with one entry of
    /// each common type. Reused by multiple tests.
    fn sample_file() -> PregFile {
        PregFile {
            entries: vec![
                // REG_DWORD: Enabled=1
                PregEntry::new(
                    "Software\\Adrian\\Framework",
                    "Enabled",
                    reg_value::REG_DWORD,
                    encode_reg_dword(1),
                ),
                // REG_SZ: DisplayName="Adrian"
                PregEntry::new(
                    "Software\\Adrian\\Framework",
                    "DisplayName",
                    reg_value::REG_SZ,
                    encode_reg_sz("Adrian"),
                ),
                // REG_BINARY: 4 raw bytes
                PregEntry::new(
                    "Software\\Adrian\\Framework",
                    "Signature",
                    reg_value::REG_BINARY,
                    vec![0xDE, 0xAD, 0xBE, 0xEF],
                ),
                // REG_MULTI_SZ: list of strings
                PregEntry::new(
                    "Software\\Adrian\\Framework",
                    "Modules",
                    reg_value::REG_MULTI_SZ,
                    encode_reg_multi_sz(&["core".into(), "policy".into()]),
                ),
            ],
        }
    }

    #[test]
    fn preg_entry_size_reflects_value_length() {
        let e = PregEntry::new("k", "v", reg_value::REG_DWORD, vec![1, 2, 3, 4]);
        assert_eq!(e.size(), 4);
    }

    #[test]
    fn preg_file_holds_entries_vector() {
        let file = sample_file();
        assert_eq!(file.entries.len(), 4);
        assert_eq!(file.entries[0].value_name, "Enabled");
        assert_eq!(file.entries[2].value_type, reg_value::REG_BINARY);
    }

    #[test]
    fn encode_emits_signature_and_one_record_per_entry() {
        let file = sample_file();
        let bytes = encode_preg_file(&file);
        assert_eq!(&bytes[..PREG_SIGNATURE.len()], PREG_SIGNATURE);
        // Count the number of UTF-16LE '[' markers (0x5B 0x00) — should
        // equal the entry count.
        let record_starts: Vec<usize> = bytes
            .windows(2)
            .enumerate()
            .skip(PREG_SIGNATURE.len())
            .filter_map(|(i, w)| if w == [0x5B, 0x00] { Some(i) } else { None })
            .collect();
        assert_eq!(record_starts.len(), file.entries.len());
    }

    #[test]
    fn round_trip_preserves_all_entries() {
        let file = sample_file();
        let bytes = encode_preg_file(&file);
        let back = decode_preg_file(&bytes).expect("decode");
        assert_eq!(back, file);
    }

    #[test]
    fn round_trip_empty_file_is_just_signature() {
        let file = PregFile::new();
        let bytes = encode_preg_file(&file);
        assert_eq!(bytes, PREG_SIGNATURE);
        let back = decode_preg_file(&bytes).expect("decode");
        assert!(back.entries.is_empty());
    }

    #[test]
    fn decode_rejects_bad_signature() {
        let err = decode_preg_file(b"PREG\0\0garbage").unwrap_err();
        assert!(matches!(err, PregError::Invalid(_)));
        assert!(err.to_string().contains("bad PReg signature"));
    }

    #[test]
    fn decode_rejects_truncated_record() {
        // Signature + a single `[` with no terminator.
        let mut bytes = PREG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0x5B, 0x00]);
        let err = decode_preg_file(&bytes).unwrap_err();
        assert!(matches!(err, PregError::Invalid(_)));
        assert!(err.to_string().contains("truncated UTF-16LE"));
    }

    #[test]
    fn reg_sz_round_trips_through_typed_helpers() {
        let s = "Héllo, 世界";
        let bytes = encode_reg_sz(s);
        let back = decode_reg_sz(&bytes).expect("decode");
        assert_eq!(back, s);
    }

    #[test]
    fn reg_dword_round_trips_through_typed_helpers() {
        for v in [0u32, 1, 0xDEAD_BEEF, 0xFFFF_FFFF] {
            let bytes = encode_reg_dword(v);
            assert_eq!(bytes.len(), 4);
            let back = decode_reg_dword(&bytes).expect("decode");
            assert_eq!(back, v);
        }
    }

    #[test]
    fn reg_multi_sz_round_trips_through_typed_helpers() {
        let strings: Vec<String> = vec!["first".into(), "second".into(), "third".into()];
        let bytes = encode_reg_multi_sz(&strings);
        let back = decode_reg_multi_sz(&bytes).expect("decode");
        assert_eq!(back, strings);
    }

    #[test]
    fn preg_entry_with_reg_binary_data_round_trips() {
        let entry = PregEntry::new(
            "Software\\Test",
            "Blob",
            reg_value::REG_BINARY,
            vec![0x00, 0xFF, 0x80, 0x7F],
        );
        let file = PregFile {
            entries: vec![entry.clone()],
        };
        let bytes = encode_preg_file(&file);
        let back = decode_preg_file(&bytes).expect("decode");
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0], entry);
    }

    #[test]
    fn preg_error_io_conversion_from_std_io_error() {
        // `PregError::Io` is `#[from] std::io::Error` — exercising the
        // conversion guards the `?` ergonomics used by future I/O code.
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let preg_err: PregError = io_err.into();
        assert!(matches!(preg_err, PregError::Io(_)));
        assert!(preg_err.to_string().contains("missing"));
    }
}
