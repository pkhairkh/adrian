//! # adrian-sid
//!
//! SID (Security Identifier) type per MS-DTYP §2.4.2.
//!
//! SIDs are the AD-interop wire-format currency for security principals (per
//! Decision 3 §Decision). The framework's internal primary key is a UUIDv7,
//! but every principal also carries a SID as a first-class attribute
//! (`objectSid`), and the `IdentityMapping` trait translates between the two.
//!
//! ## Wire format (binary)
//!
//! Per MS-DTYP §2.4.2.2, the binary SID layout is:
//!
//! ```text
//! +-----------+----------------------+------------------------------+
//! | Revision  | SubAuthorityCount    | IdentifierAuthority[6] (BE)  |
//! |   (1B)    |      (1B)            |                              |
//! +-----------+----------------------+------------------------------+
//! | SubAuthority[0] (4B, LE) | SubAuthority[1] (4B, LE) | ...      |
//! +--------------------------+--------------------------+------------+
//! ```
//!
//! - Revision is always `1` (SID_REVISION).
//! - SubAuthorityCount is at most 15 (MAX_SUB_AUTHORITIES).
//! - IdentifierAuthority is a 6-byte big-endian unsigned integer.
//! - Each SubAuthority is a 4-byte little-endian unsigned integer.
//!
//! ## String format (SDDL)
//!
//! Per MS-DTYP §2.4.2.1, the SDDL string form is:
//!
//! ```text
//! S-Revision-IdentifierAuthority-SubAuthority1-...-SubAuthorityN
//! ```
//!
//! The IdentifierAuthority is rendered in **decimal** when its value fits in
//! 32 bits (≤ `2^32 − 1`), and in **hexadecimal** prefixed with `0x` when
//! larger (e.g. `S-1-0x1000000000000-...`). Both forms are accepted on parse;
//! the canonical form is always produced on format.
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

/// The fixed size of a SID binary header: `Revision(1) + SubAuthorityCount(1)
/// + IdentifierAuthority[6]` (per MS-DTYP §2.4.2.2).
pub const SID_BINARY_HEADER_LEN: usize = 8;

/// The largest identifier-authority value that fits in 32 bits and is
/// therefore rendered in decimal in SDDL form (per MS-DTYP §2.4.2.1).
/// Larger values use the `0x`-prefixed hexadecimal form.
pub const MAX_DECIMAL_AUTHORITY: u64 = u32::MAX as u64; // 2^32 - 1

// ---------------------------------------------------------------------------
// Well-known identifier authorities (MS-DTYP §2.4.2.4 / WinNT.h
// SECURITY_*_AUTHORITY constants).
// ---------------------------------------------------------------------------

/// `SECURITY_NULL_SID_AUTHORITY` — identifier authority `0`.
pub const SECURITY_NULL_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 0];

/// `SECURITY_WORLD_SID_AUTHORITY` — identifier authority `1` (Everyone,
/// Local, etc.).
pub const SECURITY_WORLD_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 1];

/// `SECURITY_LOCAL_SID_AUTHORITY` — identifier authority `2`.
pub const SECURITY_LOCAL_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 2];

/// `SECURITY_CREATOR_SID_AUTHORITY` — identifier authority `3`
/// (Creator Owner, Creator Group, etc.).
pub const SECURITY_CREATOR_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 3];

/// `SECURITY_NT_AUTHORITY` — identifier authority `5`. This is the
/// authority under which all Windows NT-issued SIDs fall (all domain
/// accounts, builtin groups, well-known service accounts, etc.).
pub const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// `SECURITY_RESOURCE_MANAGER_AUTHORITY` — identifier authority `9`.
pub const SECURITY_RESOURCE_MANAGER_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 9];

// ---------------------------------------------------------------------------
// Well-known RIDs (WinNT.h DOMAIN_USER_RID_* / DOMAIN_GROUP_RID_*).
// ---------------------------------------------------------------------------

/// RID of the default domain Administrator account (`S-1-5-21-...-500`).
pub const DOMAIN_USER_RID_ADMIN: u32 = 500;

/// RID of the default domain Guest account (`S-1-5-21-...-501`).
pub const DOMAIN_USER_RID_GUEST: u32 = 501;

/// RID of the Domain Admins group (`S-1-5-21-...-512`).
pub const DOMAIN_GROUP_RID_ADMINS: u32 = 512;

/// RID of the Domain Users group (`S-1-5-21-...-513`).
pub const DOMAIN_GROUP_RID_USERS: u32 = 513;

/// RID of the Domain Guests group (`S-1-5-21-...-514`).
pub const DOMAIN_GROUP_RID_GUESTS: u32 = 514;

/// RID of the Domain Computers group (`S-1-5-21-...-515`).
pub const DOMAIN_GROUP_RID_COMPUTERS: u32 = 515;

/// RID of the Domain Controllers group (`S-1-5-21-...-516`).
pub const DOMAIN_GROUP_RID_CONTROLLERS: u32 = 516;

/// RID of the Cert Publishers group (`S-1-5-21-...-517`).
pub const DOMAIN_GROUP_RID_CERT_ADMINS: u32 = 517;

/// RID of the Schema Admins group (`S-1-5-21-...-518`).
pub const DOMAIN_GROUP_RID_SCHEMA_ADMINS: u32 = 518;

/// RID of the Enterprise Admins group (`S-1-5-21-...-519`).
pub const DOMAIN_GROUP_RID_ENTERPRISE_ADMINS: u32 = 519;

/// RID of the Group Policy Creator Owners group (`S-1-5-21-...-520`).
pub const DOMAIN_GROUP_RID_POLICY_ADMINS: u32 = 520;

/// The first sub-authority of every Windows AD domain SID (the well-known
/// "21" that identifies a domain-relative RID namespace).
pub const DOMAIN_SID_MARKER: u32 = 21;

/// The first sub-authority of every Builtin domain SID (`S-1-5-32-*`).
pub const BUILTIN_DOMAIN_MARKER: u32 = 32;

/// The RID that identifies the Builtin Administrators group
/// (`S-1-5-32-544`).
pub const BUILTIN_RID_ADMINS: u32 = 544;

/// The RID that identifies the Builtin Users group (`S-1-5-32-545`).
pub const BUILTIN_RID_USERS: u32 = 545;

/// The RID that identifies the Builtin Guests group (`S-1-5-32-546`).
pub const BUILTIN_RID_GUESTS: u32 = 546;

/// The RID that identifies the Builtin Account Operators group
/// (`S-1-5-32-548`).
pub const BUILTIN_RID_ACCOUNT_OPS: u32 = 548;

/// The RID that identifies the Builtin Server Operators group
/// (`S-1-5-32-549`).
pub const BUILTIN_RID_SYSTEM_OPS: u32 = 549;

/// The RID that identifies the Builtin Print Operators group
/// (`S-1-5-32-550`).
pub const BUILTIN_RID_PRINT_OPS: u32 = 550;

/// The RID that identifies the Builtin Backup Operators group
/// (`S-1-5-32-551`).
pub const BUILTIN_RID_BACKUP_OPS: u32 = 551;

// ---------------------------------------------------------------------------
// Well-known RIDs under SECURITY_NT_AUTHORITY (no domain component).
// ---------------------------------------------------------------------------

/// RID of the Anonymous logon (`S-1-5-7`).
pub const SECURITY_ANONYMOUS_LOGON_RID: u32 = 7;

/// RID of the Authenticated Users group (`S-1-5-11`).
pub const SECURITY_AUTHENTICATED_USER_RID: u32 = 11;

/// RID of the Local System account (`S-1-5-18`).
pub const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;

/// RID of the Local Service account (`S-1-5-19`).
pub const SECURITY_LOCAL_SERVICE_RID: u32 = 19;

/// RID of the Network Service account (`S-1-5-20`).
pub const SECURITY_NETWORK_SERVICE_RID: u32 = 20;

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
    ///
    /// Returns `Err(SidError::TooManySubAuthorities)` if the caller supplies
    /// more than [`MAX_SUB_AUTHORITIES`] (15) sub-authorities — MS-DTYP
    /// §2.4.2 forbids this and the binary wire form cannot represent it.
    pub fn new(identifier_authority: [u8; 6], sub_authorities: Vec<u32>) -> Result<Self, SidError> {
        if sub_authorities.len() > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(sub_authorities.len()));
        }
        Ok(Self {
            identifier_authority,
            sub_authorities,
        })
    }

    /// Construct a SID without validation. Used internally by well-known
    /// constructors whose sub-authority counts are statically known to be
    /// valid.
    const fn new_unchecked(identifier_authority: [u8; 6], sub_authorities: Vec<u32>) -> Self {
        Self {
            identifier_authority,
            sub_authorities,
        }
    }

    /// Returns the number of sub-authorities in this SID.
    #[must_use]
    pub fn sub_authority_count(&self) -> usize {
        self.sub_authorities.len()
    }

    /// Returns the identifier authority as a 48-bit unsigned integer
    /// (the 6 bytes interpreted big-endian, per MS-DTYP §2.4.2.2).
    #[must_use]
    pub fn authority_value(&self) -> u64 {
        u64::from_be_bytes([
            0,
            0,
            self.identifier_authority[0],
            self.identifier_authority[1],
            self.identifier_authority[2],
            self.identifier_authority[3],
            self.identifier_authority[4],
            self.identifier_authority[5],
        ])
    }

    /// Return the RID (the last sub-authority) of this SID, or `None` if the
    /// SID has no sub-authorities.
    #[must_use]
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }

    /// Return the domain SID (this SID with the final sub-authority stripped),
    /// or `None` if this SID has fewer than two sub-authorities.
    ///
    /// For a domain account SID `S-1-5-21-X-Y-Z-RID`, the domain SID is
    /// `S-1-5-21-X-Y-Z`. For a builtin SID `S-1-5-32-RID`, the domain SID
    /// is `S-1-5-32`. For a SID with fewer than two sub-authorities
    /// (e.g. `S-1-5-18`), there is no meaningful domain SID and `None` is
    /// returned.
    #[must_use]
    pub fn domain_sid(&self) -> Option<Sid> {
        if self.sub_authorities.len() < 2 {
            return None;
        }
        let mut sub = self.sub_authorities.clone();
        sub.pop();
        // sub_authorities count strictly decreases, so it cannot exceed
        // MAX_SUB_AUTHORITIES here.
        Some(Sid::new_unchecked(self.identifier_authority, sub))
    }

    /// Serialise this SID to its binary wire form (per MS-DTYP §2.4.2.2):
    /// `Revision | SubAuthorityCount | IdentifierAuthority[6] |
    /// SubAuthority[SubAuthorityCount]` (little-endian per sub-authority,
    /// 8-byte header + 4 bytes per sub-authority).
    ///
    /// Returns `Err(SidError::TooManySubAuthorities)` if the SID has more
    /// than [`MAX_SUB_AUTHORITIES`] sub-authorities — this can only happen
    /// if the SID was constructed via `Deserialize` (the `new()` constructor
    /// validates up-front).
    pub fn to_bytes(&self) -> Result<Vec<u8>, SidError> {
        if self.sub_authorities.len() > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(self.sub_authorities.len()));
        }
        let count = self.sub_authorities.len() as u8;
        let mut out = Vec::with_capacity(SID_BINARY_HEADER_LEN + 4 * self.sub_authorities.len());
        out.push(SID_REVISION);
        out.push(count);
        out.extend_from_slice(&self.identifier_authority);
        for sa in &self.sub_authorities {
            out.extend_from_slice(&sa.to_le_bytes());
        }
        Ok(out)
    }

    /// Deserialise a SID from its binary wire form (per MS-DTYP §2.4.2.2).
    ///
    /// Trailing bytes after the declared sub-authority count are rejected
    /// (return `Err(SidError::TrailingBytes)`) so that callers cannot be
    /// tricked by a SID blob with appended attacker-controlled data.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, SidError> {
        if buf.len() < SID_BINARY_HEADER_LEN {
            return Err(SidError::Truncated);
        }
        if buf[0] != SID_REVISION {
            return Err(SidError::UnsupportedRevision(buf[0]));
        }
        let count = buf[1] as usize;
        if count > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(count));
        }
        let expected_len = SID_BINARY_HEADER_LEN + 4 * count;
        if buf.len() < expected_len {
            return Err(SidError::Truncated);
        }
        if buf.len() > expected_len {
            return Err(SidError::TrailingBytes(buf.len() - expected_len));
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

    // -----------------------------------------------------------------------
    // Well-known SID constructors (MS-DTYP §2.4.2.4).
    // -----------------------------------------------------------------------

    /// The Null SID (`S-1-0-0`).
    #[must_use]
    pub fn null_sid() -> Self {
        Self::new_unchecked(SECURITY_NULL_SID_AUTHORITY, vec![0])
    }

    /// Everyone / World (`S-1-1-0`).
    #[must_use]
    pub fn everyone() -> Self {
        Self::new_unchecked(SECURITY_WORLD_SID_AUTHORITY, vec![0])
    }

    /// Local (`S-1-2-0`).
    #[must_use]
    pub fn local() -> Self {
        Self::new_unchecked(SECURITY_LOCAL_SID_AUTHORITY, vec![0])
    }

    /// Creator Owner (`S-1-3-0`).
    #[must_use]
    pub fn creator_owner() -> Self {
        Self::new_unchecked(SECURITY_CREATOR_SID_AUTHORITY, vec![0])
    }

    /// Anonymous logon (`S-1-5-7`).
    #[must_use]
    pub fn anonymous_logon() -> Self {
        Self::new_unchecked(SECURITY_NT_AUTHORITY, vec![SECURITY_ANONYMOUS_LOGON_RID])
    }

    /// Authenticated Users (`S-1-5-11`).
    #[must_use]
    pub fn authenticated_users() -> Self {
        Self::new_unchecked(SECURITY_NT_AUTHORITY, vec![SECURITY_AUTHENTICATED_USER_RID])
    }

    /// Local System (`S-1-5-18`).
    #[must_use]
    pub fn local_system() -> Self {
        Self::new_unchecked(SECURITY_NT_AUTHORITY, vec![SECURITY_LOCAL_SYSTEM_RID])
    }

    /// Local Service (`S-1-5-19`).
    #[must_use]
    pub fn local_service() -> Self {
        Self::new_unchecked(SECURITY_NT_AUTHORITY, vec![SECURITY_LOCAL_SERVICE_RID])
    }

    /// Network Service (`S-1-5-20`).
    #[must_use]
    pub fn network_service() -> Self {
        Self::new_unchecked(SECURITY_NT_AUTHORITY, vec![SECURITY_NETWORK_SERVICE_RID])
    }

    /// Builtin Administrators (`S-1-5-32-544`).
    #[must_use]
    pub fn builtin_administrators() -> Self {
        Self::new_unchecked(
            SECURITY_NT_AUTHORITY,
            vec![BUILTIN_DOMAIN_MARKER, BUILTIN_RID_ADMINS],
        )
    }

    /// Builtin Users (`S-1-5-32-545`).
    #[must_use]
    pub fn builtin_users() -> Self {
        Self::new_unchecked(
            SECURITY_NT_AUTHORITY,
            vec![BUILTIN_DOMAIN_MARKER, BUILTIN_RID_USERS],
        )
    }

    /// Builtin Guests (`S-1-5-32-546`).
    #[must_use]
    pub fn builtin_guests() -> Self {
        Self::new_unchecked(
            SECURITY_NT_AUTHORITY,
            vec![BUILTIN_DOMAIN_MARKER, BUILTIN_RID_GUESTS],
        )
    }

    // -----------------------------------------------------------------------
    // Detection / classification helpers.
    // -----------------------------------------------------------------------

    /// Returns `true` if this SID is in the NT authority (`S-1-5-*`).
    #[must_use]
    pub fn is_nt_authority(&self) -> bool {
        self.identifier_authority == SECURITY_NT_AUTHORITY
    }

    /// Returns `true` if this SID is in the Builtin domain (`S-1-5-32-*`).
    #[must_use]
    pub fn is_builtin(&self) -> bool {
        self.is_nt_authority()
            && self.sub_authorities.first().copied() == Some(BUILTIN_DOMAIN_MARKER)
    }

    /// Returns `true` if this SID is an AD domain SID — i.e. `S-1-5-21-X-Y-Z`
    /// with exactly four sub-authorities (the well-known domain marker `21`
    /// followed by three domain-identifier sub-authorities).
    ///
    /// A domain *account* SID like `S-1-5-21-X-Y-Z-RID` (5 sub-authorities)
    /// is **not** a domain SID; it is an account SID whose [`domain_sid`]
    /// returns `S-1-5-21-X-Y-Z`.
    #[must_use]
    pub fn is_domain_sid(&self) -> bool {
        self.is_nt_authority()
            && self.sub_authorities.len() == 4
            && self.sub_authorities[0] == DOMAIN_SID_MARKER
    }

    /// Returns `true` if this SID is an AD domain account SID — i.e.
    /// `S-1-5-21-X-Y-Z-RID` with exactly five sub-authorities.
    #[must_use]
    pub fn is_domain_account_sid(&self) -> bool {
        self.is_nt_authority()
            && self.sub_authorities.len() == 5
            && self.sub_authorities[0] == DOMAIN_SID_MARKER
    }

    /// Returns `true` if this SID is one of the well-known single-component
    /// SIDs (no domain): `S-1-0-0`, `S-1-1-0`, `S-1-5-7`, `S-1-5-11`,
    /// `S-1-5-18`, `S-1-5-19`, `S-1-5-20`, etc. — i.e. a SID with at most
    /// one sub-authority that is not a domain or builtin SID.
    #[must_use]
    pub fn is_well_known_singleton(&self) -> bool {
        !self.is_domain_sid()
            && !self.is_domain_account_sid()
            && !self.is_builtin()
            && self.sub_authorities.len() <= 1
    }
}

/// Error type for SID parsing and serialisation.
#[derive(Debug, Error)]
pub enum SidError {
    /// The SID wire form was truncated.
    #[error("truncated SID wire form")]
    Truncated,
    /// The SID wire form had trailing bytes after the declared sub-authority
    /// count — i.e. the buffer is longer than `8 + 4 * SubAuthorityCount`.
    /// This is treated as malformed input (defence against SID-blob
    /// smuggling).
    #[error("{0} trailing byte(s) after SID wire form")]
    TrailingBytes(usize),
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
        // Per MS-DTYP §2.4.2.1: the identifier authority is rendered in
        // decimal if its value fits in 32 bits (≤ 2^32-1), otherwise in
        // hexadecimal prefixed with "0x".
        let auth = self.authority_value();
        write!(f, "S-{}", SID_REVISION)?;
        if auth <= MAX_DECIMAL_AUTHORITY {
            write!(f, "-{}", auth)?;
        } else {
            write!(f, "-0x{:X}", auth)?;
        }
        for sa in &self.sub_authorities {
            write!(f, "-{}", sa)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Sid {
    type Err = SidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Per MS-DTYP §2.4.2.1: S-Revision-IdentifierAuthority-SubAuth...
        // - S must be the literal character "S" (uppercase).
        // - Revision must be 1.
        // - IdentifierAuthority is decimal (≤ 2^32-1) OR hex with "0x" prefix
        //   (≤ 2^48-1).
        // - SubAuthorities are decimal u32.
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 {
            return Err(SidError::InvalidString(s.to_string()));
        }
        if parts[0] != "S" {
            return Err(SidError::InvalidString(s.to_string()));
        }
        let revision: u8 = parts[1]
            .parse()
            .map_err(|_| SidError::InvalidString(s.to_string()))?;
        if revision != SID_REVISION {
            return Err(SidError::UnsupportedRevision(revision));
        }
        let auth_str = parts[2];
        let auth: u64 = if let Some(hex_str) = auth_str
            .strip_prefix("0x")
            .or_else(|| auth_str.strip_prefix("0X"))
        {
            u64::from_str_radix(hex_str, 16).map_err(|_| SidError::InvalidString(s.to_string()))?
        } else {
            auth_str
                .parse::<u64>()
                .map_err(|_| SidError::InvalidString(s.to_string()))?
        };
        if auth > (1u64 << 48) - 1 {
            // Identifier authority is a 6-byte value; values larger than 2^48-1
            // cannot be represented.
            return Err(SidError::InvalidString(s.to_string()));
        }
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&auth.to_be_bytes()[2..]);

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

impl TryFrom<&[u8]> for Sid {
    type Error = SidError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Original Wave-0 tests (unchanged, validating that the rewrite is
    // behavioural-compatible).
    // -----------------------------------------------------------------------

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
        let bytes = sid.to_bytes().unwrap();
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

    #[test]
    fn well_known_sids() {
        let sid: Sid = "S-1-1-0".parse().unwrap();
        assert_eq!(sid.sub_authorities, vec![0]);
        assert_eq!(sid.rid(), Some(0));

        let sid: Sid = "S-1-5-18".parse().unwrap();
        assert_eq!(sid.sub_authorities, vec![18]);

        let sid: Sid = "S-1-5-32-544".parse().unwrap();
        assert_eq!(sid.sub_authorities, vec![32, 544]);
        assert_eq!(sid.rid(), Some(544));

        let sid: Sid = "S-1-5-21-3623811015-3361044348-30300820-512"
            .parse()
            .unwrap();
        assert_eq!(sid.rid(), Some(512));
    }

    #[test]
    fn wire_form_structure() {
        let sid: Sid = "S-1-5-21-100-200-300-1000".parse().unwrap();
        let bytes = sid.to_bytes().unwrap();
        assert_eq!(bytes.len(), 8 + 4 * 5);
        assert_eq!(bytes[0], SID_REVISION);
        assert_eq!(bytes[1], 5);
        assert_eq!(&bytes[2..8], &[0, 0, 0, 0, 0, 5]);
    }

    #[test]
    fn from_bytes_truncated() {
        assert!(Sid::from_bytes(&[]).is_err());
        assert!(Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5]).is_err());
    }

    #[test]
    fn from_bytes_bad_revision() {
        let buf = [2u8, 0, 0, 0, 0, 0, 0, 5];
        assert!(matches!(
            Sid::from_bytes(&buf),
            Err(SidError::UnsupportedRevision(2))
        ));
    }

    #[test]
    fn domain_sid_no_rid() {
        let sid: Sid = "S-1-5-21".parse().unwrap();
        assert!(sid.domain_sid().is_none());
    }

    #[test]
    fn display_matches_string_parse() {
        let sids = [
            "S-1-1-0",
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-3623811015-3361044348-30300820-1013",
        ];
        for s in sids {
            let sid: Sid = s.parse().unwrap();
            assert_eq!(sid.to_string(), s, "round-trip failed for {}", s);
        }
    }

    // -----------------------------------------------------------------------
    // New Wave-1c tests: well-known constructors, classification, hex
    // authority form, edge cases (max sub-auth, 0 sub-auth, trailing-bytes
    // rejection, large authority).
    // -----------------------------------------------------------------------

    #[test]
    fn well_known_constructors_match_sddl_strings() {
        assert_eq!(Sid::null_sid().to_string(), "S-1-0-0");
        assert_eq!(Sid::everyone().to_string(), "S-1-1-0");
        assert_eq!(Sid::local().to_string(), "S-1-2-0");
        assert_eq!(Sid::creator_owner().to_string(), "S-1-3-0");
        assert_eq!(Sid::anonymous_logon().to_string(), "S-1-5-7");
        assert_eq!(Sid::authenticated_users().to_string(), "S-1-5-11");
        assert_eq!(Sid::local_system().to_string(), "S-1-5-18");
        assert_eq!(Sid::local_service().to_string(), "S-1-5-19");
        assert_eq!(Sid::network_service().to_string(), "S-1-5-20");
        assert_eq!(Sid::builtin_administrators().to_string(), "S-1-5-32-544");
        assert_eq!(Sid::builtin_users().to_string(), "S-1-5-32-545");
        assert_eq!(Sid::builtin_guests().to_string(), "S-1-5-32-546");
    }

    #[test]
    fn well_known_constructors_round_trip_through_bytes() {
        let sids = [
            Sid::null_sid(),
            Sid::everyone(),
            Sid::anonymous_logon(),
            Sid::local_system(),
            Sid::builtin_administrators(),
        ];
        for sid in sids {
            let bytes = sid.to_bytes().unwrap();
            let decoded = Sid::from_bytes(&bytes).unwrap();
            assert_eq!(sid, decoded, "wire round-trip failed for {}", sid);
        }
    }

    #[test]
    fn classification_helpers_detect_domain_and_builtin_sids() {
        // Account SID: S-1-5-21-X-Y-Z-RID
        let account: Sid = "S-1-5-21-100-200-300-1013".parse().unwrap();
        assert!(account.is_nt_authority());
        assert!(account.is_domain_account_sid());
        assert!(!account.is_domain_sid());
        assert!(!account.is_builtin());

        // Domain SID: S-1-5-21-X-Y-Z
        let domain: Sid = "S-1-5-21-100-200-300".parse().unwrap();
        assert!(domain.is_domain_sid());
        assert!(!domain.is_domain_account_sid());

        // Builtin: S-1-5-32-544
        let builtin: Sid = "S-1-5-32-544".parse().unwrap();
        assert!(builtin.is_builtin());
        assert!(!builtin.is_domain_sid());

        // Local System: S-1-5-18 (singleton, not domain/builtin)
        let singleton: Sid = "S-1-5-18".parse().unwrap();
        assert!(singleton.is_well_known_singleton());
        assert!(!singleton.is_builtin());
        assert!(!singleton.is_domain_sid());

        // Everyone: S-1-1-0 — not NT authority at all.
        let everyone: Sid = "S-1-1-0".parse().unwrap();
        assert!(!everyone.is_nt_authority());
        assert!(everyone.is_well_known_singleton());
    }

    #[test]
    fn domain_sid_extraction_for_account_sid() {
        let account: Sid = "S-1-5-21-100-200-300-1013".parse().unwrap();
        let domain = account.domain_sid().unwrap();
        assert_eq!(domain.to_string(), "S-1-5-21-100-200-300");
        assert!(domain.is_domain_sid());
        // Stripping a domain SID yields the grandparent (S-1-5-21-100-200),
        // which is no longer a valid domain SID.
        let parent = domain.domain_sid().unwrap();
        assert_eq!(parent.to_string(), "S-1-5-21-100-200");
        assert!(!parent.is_domain_sid());
    }

    #[test]
    fn domain_sid_extraction_for_builtin_sid_yields_s_1_5_32() {
        let admins: Sid = "S-1-5-32-544".parse().unwrap();
        let parent = admins.domain_sid().unwrap();
        assert_eq!(parent.to_string(), "S-1-5-32");
        // The parent has only one sub-authority, so it has no domain SID.
        assert!(parent.domain_sid().is_none());
    }

    #[test]
    fn zero_sub_authority_sid_round_trips() {
        // S-1-5 (NT authority, no sub-authorities) — valid per MS-DTYP.
        let sid: Sid = "S-1-5".parse().unwrap();
        assert!(sid.sub_authorities.is_empty());
        assert_eq!(sid.rid(), None);
        assert_eq!(sid.domain_sid(), None);
        assert_eq!(sid.to_string(), "S-1-5");
        let bytes = sid.to_bytes().unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], SID_REVISION);
        assert_eq!(bytes[1], 0);
        assert_eq!(&bytes[2..8], &[0, 0, 0, 0, 0, 5]);
        let decoded = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid, decoded);
    }

    #[test]
    fn max_sub_authorities_sid_round_trips() {
        // 15 sub-authorities (the MS-DTYP maximum).
        let mut sub_auths: Vec<u32> = (1..=15).collect();
        let sid = Sid::new(SECURITY_NT_AUTHORITY, sub_auths.clone()).unwrap();
        assert_eq!(sid.sub_authority_count(), 15);
        let bytes = sid.to_bytes().unwrap();
        assert_eq!(bytes.len(), 8 + 4 * 15);
        assert_eq!(bytes[1], 15);
        let decoded = Sid::from_bytes(&bytes).unwrap();
        assert_eq!(sid, decoded);
        assert_eq!(
            decoded.to_string(),
            format!(
                "S-1-5-{}",
                sub_auths
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join("-")
            )
        );
        // Borrow sub_auths back for the assertion above (it was moved).
        sub_auths = decoded.sub_authorities.clone();
        assert_eq!(sub_auths, (1..=15u32).collect::<Vec<_>>());
    }

    #[test]
    fn new_rejects_more_than_max_sub_authorities() {
        let too_many: Vec<u32> = (0..16).collect();
        let err = Sid::new(SECURITY_NT_AUTHORITY, too_many).unwrap_err();
        assert!(matches!(err, SidError::TooManySubAuthorities(16)));
    }

    #[test]
    fn from_bytes_rejects_trailing_bytes() {
        // A valid 8-byte header (S-1-5, zero sub-authorities) + 1 trailing
        // byte must be rejected as malformed input.
        let mut buf = vec![1u8, 0, 0, 0, 0, 0, 0, 5];
        buf.push(0xFF);
        let err = Sid::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, SidError::TrailingBytes(1)));
    }

    #[test]
    fn from_bytes_rejects_count_above_max() {
        // Header claims 16 sub-authorities (above the 15 max).
        let buf = [1u8, 16, 0, 0, 0, 0, 0, 5];
        let err = Sid::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, SidError::TooManySubAuthorities(16)));
    }

    #[test]
    fn hex_authority_form_for_large_authority() {
        // Authority value 2^48 - 1 = 0xFFFFFFFFFFFF — must be rendered in
        // hex form per MS-DTYP §2.4.2.1.
        let sid = Sid::new([0xFF; 6], vec![1, 2, 3]).unwrap();
        let s = sid.to_string();
        assert_eq!(s, "S-1-0xFFFFFFFFFFFF-1-2-3");

        // And parsing the canonical hex form back must round-trip.
        let parsed: Sid = s.parse().unwrap();
        assert_eq!(parsed, sid);

        // Authority value 2^32 (exactly one above the decimal threshold) —
        // must also use hex form. 2^32 = 0x000100000000 in 6 bytes BE.
        let sid2 = Sid::new([0x00, 0x01, 0x00, 0x00, 0x00, 0x00], vec![]).unwrap();
        assert_eq!(sid2.to_string(), "S-1-0x100000000");
        assert_eq!(sid2.authority_value(), 1u64 << 32);
    }

    #[test]
    fn hex_authority_form_uppercase_and_lowercase_prefix_both_accepted() {
        // Parse-side leniency: both "0x" and "0X" prefixes should be accepted.
        let upper: Sid = "S-1-0XAB-100".parse().unwrap();
        let lower: Sid = "S-1-0xAB-100".parse().unwrap();
        assert_eq!(upper, lower);
        assert_eq!(upper.authority_value(), 0xAB);
        assert_eq!(upper.sub_authorities, vec![100]);
    }

    #[test]
    fn decimal_authority_at_boundary_uses_decimal_form() {
        // 2^32-1 = 4294967295 = 0x0000FFFFFFFF in 6 bytes BE — the largest
        // authority value rendered in decimal form.
        let sid = Sid::new([0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF], vec![42]).unwrap();
        assert_eq!(sid.to_string(), "S-1-4294967295-42");
        let parsed: Sid = sid.to_string().parse().unwrap();
        assert_eq!(parsed, sid);
    }

    #[test]
    fn from_str_rejects_authority_above_48_bits() {
        // 2^48 cannot fit in a 6-byte identifier authority — must error.
        let s = "S-1-0x1000000000000-1";
        let err: SidError = s.parse::<Sid>().unwrap_err();
        assert!(matches!(err, SidError::InvalidString(_)));
    }

    #[test]
    fn from_str_rejects_lowercase_s_prefix() {
        // Per MS-DTYP §2.4.2.1 the "S-" prefix must be uppercase.
        let err: SidError = "s-1-5-18".parse::<Sid>().unwrap_err();
        assert!(matches!(err, SidError::InvalidString(_)));
    }

    #[test]
    fn from_str_rejects_too_few_components() {
        // "S-1" has only 2 components — too few.
        let err: SidError = "S-1".parse::<Sid>().unwrap_err();
        assert!(matches!(err, SidError::InvalidString(_)));
    }

    #[test]
    fn from_str_rejects_non_numeric_sub_authority() {
        let err: SidError = "S-1-5-foo".parse::<Sid>().unwrap_err();
        assert!(matches!(err, SidError::InvalidString(_)));
    }

    #[test]
    fn from_str_rejects_revision_other_than_one() {
        let err: SidError = "S-2-5-18".parse::<Sid>().unwrap_err();
        assert!(matches!(err, SidError::UnsupportedRevision(2)));
    }

    #[test]
    fn from_str_rejects_too_many_sub_authorities() {
        // 16 sub-authorities (one above the max).
        let s = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16";
        let err: SidError = s.parse::<Sid>().unwrap_err();
        assert!(matches!(err, SidError::TooManySubAuthorities(16)));
    }

    #[test]
    fn authority_value_helper() {
        let nt: Sid = "S-1-5-18".parse().unwrap();
        assert_eq!(nt.authority_value(), 5);
        let null_sid: Sid = "S-1-0-0".parse().unwrap();
        assert_eq!(null_sid.authority_value(), 0);
        let big: Sid = "S-1-0xFFFFFFFFFFFF-1".parse().unwrap();
        assert_eq!(big.authority_value(), 0xFFFFFFFFFFFF);
    }

    #[test]
    fn try_from_slice_works() {
        let sid: Sid = "S-1-5-18".parse().unwrap();
        let bytes = sid.to_bytes().unwrap();
        let sid2: Sid = bytes.as_slice().try_into().unwrap();
        assert_eq!(sid, sid2);
    }

    #[test]
    fn serde_round_trips() {
        let sid: Sid = "S-1-5-21-100-200-300-1013".parse().unwrap();
        let json = serde_json::to_string(&sid).unwrap();
        let decoded: Sid = serde_json::from_str(&json).unwrap();
        assert_eq!(sid, decoded);
    }

    #[test]
    fn eq_and_hash_consistency() {
        let a: Sid = "S-1-5-21-100-200-300-1013".parse().unwrap();
        let b: Sid = "S-1-5-21-100-200-300-1013".parse().unwrap();
        let c: Sid = "S-1-5-21-100-200-300-1014".parse().unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Same hash for equal SIDs.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn domain_sid_for_real_world_ad_sid() {
        // Real-world AD domain SID for a user (RID 1103).
        let s = "S-1-5-21-3623811015-3361044348-30300820-1103";
        let sid: Sid = s.parse().unwrap();
        assert!(sid.is_domain_account_sid());
        assert_eq!(sid.rid(), Some(1103));
        let domain = sid.domain_sid().unwrap();
        assert_eq!(
            domain.to_string(),
            "S-1-5-21-3623811015-3361044348-30300820"
        );
        assert!(domain.is_domain_sid());
    }

    #[test]
    fn is_well_known_singleton_for_bare_authority() {
        // S-1-5 has zero sub-authorities — a bare NT authority SID. It is
        // neither a domain SID, nor a builtin SID, nor an account SID.
        let bare: Sid = "S-1-5".parse().unwrap();
        assert!(bare.is_well_known_singleton());
        // S-1-0 (a bare null authority, no sub-authorities) — also a
        // singleton per our definition.
        let bare_null: Sid = "S-1-0".parse().unwrap();
        assert!(bare_null.is_well_known_singleton());
    }

    #[test]
    fn sub_authority_count_helper() {
        let sid: Sid = "S-1-5-21-100-200-300-1013".parse().unwrap();
        assert_eq!(sid.sub_authority_count(), 5);
        let minimal: Sid = "S-1-5".parse().unwrap();
        assert_eq!(minimal.sub_authority_count(), 0);
    }
}
