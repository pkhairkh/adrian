//! # adrian-policy-preg
//!
//! PReg adapter — read/write Windows `Registry.pol` (PReg format per MS-GPREG).
//! Gated by the `ad-interop` feature flag.
//!
//! ## ADRs
//!
//! - ADR-029: JSON canonical policy + PReg adapter
//! - ADR-089: Declarative policy ↔ GPC/GPT synthesis
//! - ADR-092: PolicyExecutor trait + synthetic Windows CSE

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PregError {
    #[error("invalid PReg format: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Single PReg registry entry.
#[derive(Clone, Debug)]
pub struct PregEntry {
    pub key: String,
    pub value_name: String,
    pub value_type: u32,
    pub value: Vec<u8>,
}

/// PReg file (Registry.pol) reader/writer.
pub struct PregFile {
    pub entries: Vec<PregEntry>,
}

impl PregFile {
    /// Parse a `Registry.pol` byte stream (MS-GPREG §2.2).
    pub fn parse(_bytes: &[u8]) -> Result<Self, PregError> {
        // TODO: implement PReg parser
        Err(PregError::Invalid("not yet implemented".into()))
    }

    /// Serialize back to `Registry.pol` bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, PregError> {
        // TODO: implement PReg serializer
        Err(PregError::Invalid("not yet implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-policy-preg`. Per the task instructions these
    //! cover type construction, error variants and the loud-stub behaviour
    //! of `PregFile::parse` / `PregFile::serialize` — no real file I/O.

    use super::*;

    #[test]
    fn preg_entry_constructs_with_expected_fields() {
        let entry = PregEntry {
            key: "Software\\Adrian\\Framework".into(),
            value_name: "Enabled".into(),
            value_type: 4, // REG_DWORD per MS-PREG §2.4
            value: vec![0x01, 0x00, 0x00, 0x00],
        };
        assert_eq!(entry.key, "Software\\Adrian\\Framework");
        assert_eq!(entry.value_name, "Enabled");
        assert_eq!(entry.value_type, 4);
        assert_eq!(entry.value, vec![0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn preg_file_holds_entries_vector() {
        let file = PregFile {
            entries: vec![
                PregEntry {
                    key: "k1".into(),
                    value_name: "v1".into(),
                    value_type: 1,
                    value: vec![],
                },
                PregEntry {
                    key: "k2".into(),
                    value_name: "v2".into(),
                    value_type: 4,
                    value: vec![0u8; 4],
                },
            ],
        };
        assert_eq!(file.entries.len(), 2);
        assert_eq!(file.entries[0].value_name, "v1");
        assert_eq!(file.entries[1].value_type, 4);
    }

    #[test]
    fn parse_stub_returns_invalid_error() {
        // Loud-stub contract: until MS-GPREG §2.2 parsing is implemented,
        // `parse` must surface `PregError::Invalid` rather than panic.
        // (`PregFile` doesn't yet `derive(Debug)`, so we match by hand
        // rather than call `unwrap_err()` which requires `Debug`.)
        match PregFile::parse(&[]) {
            Ok(_) => panic!("expected PregError::Invalid, got Ok"),
            Err(PregError::Invalid(msg)) => assert!(msg.contains("not yet implemented")),
            Err(other) => panic!("expected PregError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn serialize_stub_returns_invalid_error() {
        let file = PregFile { entries: vec![] };
        // Same `Debug` consideration as `parse_stub_returns_invalid_error`.
        match file.serialize() {
            Ok(_) => panic!("expected PregError::Invalid, got Ok"),
            Err(PregError::Invalid(msg)) => assert!(msg.contains("not yet implemented")),
            Err(other) => panic!("expected PregError::Invalid, got {other:?}"),
        }
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
