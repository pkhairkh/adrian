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
