//! # adrian-sid
//!
//! SID (Security Identifier) type per MS-DTYP §2.4.2.
//!
//! SIDs are the AD-interop wire-format currency for security principals (per
//! Decision 3 §Decision). The framework's internal primary key is a UUIDv7,
//! but every principal also carries a SID as a first-class attribute
//! (`objectSid`), and the `IdentityMapping` trait translates between the two.
//!
//! ## ADRs
//!
//! - ADR-110: SID-to-UID mapping (UUID-primary)
//! - ADR-126: sIDHistory migration via DRSAddSidHistory
//! - ADR-124: sIDHistory injection mitigation
//!
//! ## Layer
//!
//! Layer 0 — foundation (no internal dependencies). Pure data type, no I/O.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The maximum number of sub-authorities in a SID (per MS-DTYP §2.4.2).
pub const MAX_SUB_AUTHORITIES: usize = 15;

/// A SID revision (per MS-DTYP §2.4.2, always 1 in v1).
pub const SID_REVISION: u8 = 1;

/// A Security Identifier (SID) per MS-DTYP §2.4.2.
///
/// Wire format: `S-Revision-IdentifierAuthority-SubAuthority1-...-SubAuthorityN`
/// (e.g. `S-1-5-21-3623811015-3361044348-30300820-1013`).
///
/// Per Decision 3, SIDs are stored as a first-class attribute on every
/// principal (`objectSid`); the framework's internal primary key is a UUIDv7.
/// The `IdentityMapping` trait (`adrian-identity-core`) translates between the
/// two.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sid {
    /// The 6-byte identifier authority (per MS-DTYP §2.4.2). For AD-issued
    /// SIDs this is always `0x000000000005` (SECURITY_NT_AUTHORITY).
    pub identifier_authority: [u8; 6],
    /// The sub-authority values (per MS-DTYP §2.4.2). For an AD domain SID,
    /// the first sub-authority is always `21` and the next three identify the
    /// domain; the final sub-authority is the RID (relative identifier).
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Construct a new SID from an identifier authority and sub-authorities.
    pub fn new(identifier_authority: [u8; 6], sub_authorities: Vec<u32>) -> Self {
        Self {
            identifier_authority,
            sub_authorities,
        }
    }

    /// Return the RID (the last sub-authority) of this SID, or `None` if the
    /// SID has no sub-authorities.
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }

    /// Return the domain SID (this SID with the final sub-authority stripped),
    /// or `None` if this SID has fewer than two sub-authorities.
    pub fn domain_sid(&self) -> Option<Sid> {
        if self.sub_authorities.len() < 2 {
            return None;
        }
        Some(Sid {
            identifier_authority: self.identifier_authority,
            sub_authorities: self.sub_authorities[..self.sub_authorities.len() - 1].to_vec(),
        })
    }

    /// Serialise this SID to its binary wire form (per MS-DTYP §2.4.2.2):
    /// `Revision | SubAuthorityCount | IdentifierAuthority[6] |
    /// SubAuthority[SubAuthorityCount]` (little-endian, 8-byte header +
    /// 4 bytes per sub-authority).
    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: implement per MS-DTYP §2.4.2.2.
        let count = self.sub_authorities.len() as u8;
        let mut out = Vec::with_capacity(8 + 4 * self.sub_authorities.len());
        out.push(SID_REVISION);
        out.push(count);
        out.extend_from_slice(&self.identifier_authority);
        for sa in &self.sub_authorities {
            out.extend_from_slice(&sa.to_le_bytes());
        }
        out
    }

    /// Deserialise a SID from its binary wire form (per MS-DTYP §2.4.2.2).
    pub fn from_bytes(buf: &[u8]) -> Result<Self, SidError> {
        // TODO: implement per MS-DTYP §2.4.2.2.
        if buf.len() < 8 {
            return Err(SidError::Truncated);
        }
        if buf[0] != SID_REVISION {
            return Err(SidError::UnsupportedRevision(buf[0]));
        }
        let count = buf[1] as usize;
        if count > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(count));
        }
        if buf.len() < 8 + 4 * count {
            return Err(SidError::Truncated);
        }
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&buf[2..8]);
        let mut sub_authorities = Vec::with_capacity(count);
        for i in 0..count {
            let off = 8 + 4 * i;
            sub_authorities.push(u32::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ]));
        }
        Ok(Self {
            identifier_authority,
            sub_authorities,
        })
    }
}

/// Error type for SID parsing and serialisation.
#[derive(Debug, Error)]
pub enum SidError {
    /// The SID wire form was truncated.
    #[error("truncated SID wire form")]
    Truncated,
    /// The SID revision is not 1 (per MS-DTYP §2.4.2).
    #[error("unsupported SID revision: {0}")]
    UnsupportedRevision(u8),
    /// The SID has more than 15 sub-authorities (per MS-DTYP §2.4.2).
    #[error("too many sub-authorities: {0}")]
    TooManySubAuthorities(usize),
    /// The SID string form did not parse (per MS-DTYP §2.4.2.1).
    #[error("invalid SID string: {0}")]
    InvalidString(String),
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // S-Revision-IdentifierAuthority-SubAuthority1-...-SubAuthorityN
        // The identifier authority is decimal if ≤ 2^32-1, else hex.
        // TODO: implement hex form per MS-DTYP §2.4.2.1 for authorities > 2^32.
        let auth = u64::from_be_bytes([
            0,
            0,
            self.identifier_authority[0],
            self.identifier_authority[1],
            self.identifier_authority[2],
            self.identifier_authority[3],
            self.identifier_authority[4],
            self.identifier_authority[5],
        ]);
        write!(f, "S-{}-{}", SID_REVISION, auth)?;
        for sa in &self.sub_authorities {
            write!(f, "-{}", sa)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Sid {
    type Err = SidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: implement per MS-DTYP §2.4.2.1 (handle hex authority form).
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts[0] != "S" {
            return Err(SidError::InvalidString(s.to_string()));
        }
        let revision: u8 = parts[1]
            .parse()
            .map_err(|_| SidError::InvalidString(s.to_string()))?;
        if revision != SID_REVISION {
            return Err(SidError::UnsupportedRevision(revision));
        }
        let auth: u64 = parts[2]
            .parse()
            .map_err(|_| SidError::InvalidString(s.to_string()))?;
        let mut identifier_authority = [0u8; 6];
        identifier_authority[2..].copy_from_slice(&auth.to_be_bytes()[2..]);
        let mut sub_authorities = Vec::with_capacity(parts.len() - 3);
        for p in &parts[3..] {
            sub_authorities.push(
                p.parse::<u32>()
                    .map_err(|_| SidError::InvalidString(s.to_string()))?,
            );
        }
        if sub_authorities.len() > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(sub_authorities.len()));
        }
        Ok(Sid {
            identifier_authority,
            sub_authorities,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_string_form() {
        let s = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let sid: Sid = s.parse().unwrap();
        assert_eq!(sid.to_string(), s);
    }

    #[test]
    fn round_trip_wire_form() {
        let s = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let sid: Sid = s.parse().unwrap();
        let bytes = sid.to_bytes();
        let sid2 = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid, sid2);
    }

    #[test]
    fn rid_extraction() {
        let sid: Sid = "S-1-5-21-3623811015-3361044348-30300820-1013"
            .parse()
            .unwrap();
        assert_eq!(sid.rid(), Some(1013));
        assert_eq!(
            sid.domain_sid().unwrap().to_string(),
            "S-1-5-21-3623811015-3361044348-30300820"
        );
    }
}
