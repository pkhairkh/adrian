//! LDAP search filter (RFC 4511 §4.5.1 + RFC 4515 string representation).
//!
//! A [`Filter`] is the structured ASN.1 form carried in a `SearchRequest`
//! on the wire. The string form (RFC 4515) is what users typically type
//! (e.g. `(&(objectClass=user)(cn=alice))`); [`parse_filter`] converts
//! the string form to the structured form, and [`Filter::to_string`]
//! converts back.
//!
//! ## Supported filter types
//!
//! - `present` — `(objectClass=*)`
//! - `equalityMatch` — `(cn=alice)`
//! - `substrings` — `(cn=al*ce)` (initial/any/final)
//! - `greaterOrEqual` — `(cn>=alice)`
//! - `lessOrEqual` — `(cn<=alice)`
//! - `approxMatch` — `(cn~=alice)` (treated as equality by the DSA)
//! - `and` — `(&(f1)(f2)...)`
//! - `or` — `(|(f1)(f2)...)`
//! - `not` — `(!(f))`
//!
//! Escaping per RFC 4515 §3: `\xx` (hex byte) and `\(`, `\)`, `\*`, `\\`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::ber::{
    self, decode_string_value, BerError, CONSTRUCTED, FILTER_AND, FILTER_APPROX, FILTER_EQUALITY,
    FILTER_GE, FILTER_LE, FILTER_NOT, FILTER_OR, FILTER_PRESENT, FILTER_SUBSTRINGS, SUBSTRING_ANY,
    SUBSTRING_FINAL, SUBSTRING_INITIAL, TAG_OCTET_STRING, TAG_SEQUENCE,
};
use std::fmt;

/// A parsed LDAP search filter (RFC 4511 §4.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// `and` — conjunction of sub-filters (`[0]` SET OF Filter).
    And(Vec<Filter>),
    /// `or` — disjunction of sub-filters (`[1]` SET OF Filter).
    Or(Vec<Filter>),
    /// `not` — negation of a single sub-filter (`[2]` Filter).
    Not(Box<Filter>),
    /// `equalityMatch` — `(attr=value)` (`[3]` AttributeValueAssertion).
    Equality {
        /// The attribute description (e.g. `cn`, `objectClass`).
        attribute: String,
        /// The assertion value (raw bytes — LDAP values are octet strings).
        value: Vec<u8>,
    },
    /// `substrings` — `(attr=init*any*fin)` (`[4]` SubstringFilter).
    Substrings {
        /// The attribute description.
        attribute: String,
        /// The substring choices (initial / any / final).
        substrings: Vec<Substring>,
    },
    /// `greaterOrEqual` — `(attr>=value)` (`[5]` AttributeValueAssertion).
    GreaterOrEqual {
        /// The attribute description.
        attribute: String,
        /// The assertion value.
        value: Vec<u8>,
    },
    /// `lessOrEqual` — `(attr<=value)` (`[6]` AttributeValueAssertion).
    LessOrEqual {
        /// The attribute description.
        attribute: String,
        /// The assertion value.
        value: Vec<u8>,
    },
    /// `present` — `(attr=*)` (`[7]` AttributeDescription, primitive).
    Present(String),
    /// `approxMatch` — `(attr~=value)` (`[8]` AttributeValueAssertion).
    /// Treated as equality by the DSA (AD behaviour — `approxMatch` is
    /// case-insensitive equality on string attributes).
    Approx {
        /// The attribute description.
        attribute: String,
        /// The assertion value.
        value: Vec<u8>,
    },
}

/// A substring choice within a [`Filter::Substrings`] (RFC 4511 §4.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Substring {
    /// `initial` — the substring before the first `*` (`[0]` AssertionValue).
    Initial(Vec<u8>),
    /// `any` — a substring between two `*`s (`[1]` AssertionValue).
    Any(Vec<u8>),
    /// `final` — the substring after the last `*` (`[2]` AssertionValue).
    Final(Vec<u8>),
}

impl Filter {
    /// Construct a `present` filter: `(attribute=*)`.
    pub fn present(attribute: impl Into<String>) -> Self {
        Filter::Present(attribute.into())
    }

    /// Construct an `equalityMatch` filter: `(attribute=value)`.
    pub fn equality(attribute: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Filter::Equality {
            attribute: attribute.into(),
            value: value.into(),
        }
    }

    /// Construct an `and` filter: `(&(f1)(f2)...)`.
    pub fn and(sub: Vec<Filter>) -> Self {
        Filter::And(sub)
    }

    /// Construct an `or` filter: `(|(f1)(f2)...)`.
    pub fn or(sub: Vec<Filter>) -> Self {
        Filter::Or(sub)
    }

    /// Construct a `not` filter: `(!(f))`.
    #[allow(clippy::should_implement_trait)]
    pub fn not(f: Filter) -> Self {
        Filter::Not(Box::new(f))
    }

    /// Encode this filter's TLV value into `out` (without the outer tag —
    /// the tag depends on the variant, so callers use [`Filter::encode`]
    /// which emits the full TLV).
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Filter::And(subs) | Filter::Or(subs) => {
                let tag = if matches!(self, Filter::And(_)) {
                    FILTER_AND
                } else {
                    FILTER_OR
                };
                let mut value = Vec::new();
                for s in subs {
                    s.encode(&mut value);
                }
                ber::encode_tlv(tag, &value, out);
            }
            Filter::Not(inner) => {
                let mut value = Vec::new();
                inner.encode(&mut value);
                ber::encode_tlv(FILTER_NOT, &value, out);
            }
            Filter::Equality { attribute, value }
            | Filter::GreaterOrEqual { attribute, value }
            | Filter::LessOrEqual { attribute, value }
            | Filter::Approx { attribute, value } => {
                let tag = match self {
                    Filter::Equality { .. } => FILTER_EQUALITY,
                    Filter::GreaterOrEqual { .. } => FILTER_GE,
                    Filter::LessOrEqual { .. } => FILTER_LE,
                    Filter::Approx { .. } => FILTER_APPROX,
                    _ => unreachable!(),
                };
                let mut body = Vec::new();
                ber::encode_string(attribute, &mut body);
                ber::encode_tlv(TAG_OCTET_STRING, value, &mut body);
                ber::encode_tlv(tag, &body, out);
            }
            Filter::Present(attr) => {
                // present is primitive — just emit the attribute name as
                // the value of a [7] primitive tag.
                ber::encode_tlv(FILTER_PRESENT, attr.as_bytes(), out);
            }
            Filter::Substrings {
                attribute,
                substrings,
            } => {
                let mut body = Vec::new();
                ber::encode_string(attribute, &mut body);
                // SEQUENCE OF substring CHOICE
                let mut seq = Vec::new();
                for s in substrings {
                    let (tag, val) = match s {
                        Substring::Initial(v) => (SUBSTRING_INITIAL, v),
                        Substring::Any(v) => (SUBSTRING_ANY, v),
                        Substring::Final(v) => (SUBSTRING_FINAL, v),
                    };
                    ber::encode_tlv(tag, val, &mut seq);
                }
                ber::encode_tlv(TAG_SEQUENCE | CONSTRUCTED, &seq, &mut body);
                ber::encode_tlv(FILTER_SUBSTRINGS, &body, out);
            }
        }
    }

    /// Decode a filter from a TLV with the given tag and value bytes.
    pub fn decode_from_tlv(tag: u8, value: &[u8]) -> Result<Filter, BerError> {
        match tag {
            FILTER_AND => {
                let mut subs = Vec::new();
                let mut rest = value;
                while !rest.is_empty() {
                    let (tlv, remaining) = ber::decode_tlv(rest)?;
                    subs.push(Filter::decode_from_tlv(tlv.tag, tlv.value)?);
                    rest = remaining;
                }
                Ok(Filter::And(subs))
            }
            FILTER_OR => {
                let mut subs = Vec::new();
                let mut rest = value;
                while !rest.is_empty() {
                    let (tlv, remaining) = ber::decode_tlv(rest)?;
                    subs.push(Filter::decode_from_tlv(tlv.tag, tlv.value)?);
                    rest = remaining;
                }
                Ok(Filter::Or(subs))
            }
            FILTER_NOT => {
                let (tlv, rest) = ber::decode_tlv(value)?;
                if !rest.is_empty() {
                    return Err(BerError::TrailingData(rest.len()));
                }
                Ok(Filter::Not(Box::new(Filter::decode_from_tlv(
                    tlv.tag, tlv.value,
                )?)))
            }
            FILTER_EQUALITY | FILTER_GE | FILTER_LE | FILTER_APPROX => {
                // AttributeValueAssertion ::= SEQUENCE { attributeDesc, assertionValue }
                let (attr_tlv, rest) = ber::decode_tlv(value)?;
                if rest.is_empty() {
                    return Err(BerError::Truncated("missing assertion value"));
                }
                let (val_tlv, rest) = ber::decode_tlv(rest)?;
                if !rest.is_empty() {
                    return Err(BerError::TrailingData(rest.len()));
                }
                let attribute = decode_string_value(attr_tlv.value)?;
                let v = val_tlv.value.to_vec();
                Ok(match tag {
                    FILTER_EQUALITY => Filter::Equality {
                        attribute,
                        value: v,
                    },
                    FILTER_GE => Filter::GreaterOrEqual {
                        attribute,
                        value: v,
                    },
                    FILTER_LE => Filter::LessOrEqual {
                        attribute,
                        value: v,
                    },
                    FILTER_APPROX => Filter::Approx {
                        attribute,
                        value: v,
                    },
                    _ => unreachable!(),
                })
            }
            FILTER_PRESENT => {
                // primitive: value is the attribute name bytes.
                let attribute = decode_string_value(value)?;
                Ok(Filter::Present(attribute))
            }
            FILTER_SUBSTRINGS => {
                // SubstringFilter ::= SEQUENCE { type, SEQUENCE OF substring CHOICE }
                let (attr_tlv, rest) = ber::decode_tlv(value)?;
                let attribute = decode_string_value(attr_tlv.value)?;
                let (seq_tlv, rest) = ber::decode_tlv(rest)?;
                if !rest.is_empty() {
                    return Err(BerError::TrailingData(rest.len()));
                }
                let mut subs = Vec::new();
                let mut s_rest = seq_tlv.value;
                while !s_rest.is_empty() {
                    let (s_tlv, s_remaining) = ber::decode_tlv(s_rest)?;
                    let v = s_tlv.value.to_vec();
                    let sub = match s_tlv.tag {
                        SUBSTRING_INITIAL => Substring::Initial(v),
                        SUBSTRING_ANY => Substring::Any(v),
                        SUBSTRING_FINAL => Substring::Final(v),
                        t => return Err(BerError::UnknownFilter(t)),
                    };
                    subs.push(sub);
                    s_rest = s_remaining;
                }
                Ok(Filter::Substrings {
                    attribute,
                    substrings: subs,
                })
            }
            t => Err(BerError::UnknownFilter(t)),
        }
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Filter::And(subs) => {
                f.write_str("(&")?;
                for s in subs {
                    write!(f, "{}", s)?;
                }
                f.write_str(")")
            }
            Filter::Or(subs) => {
                f.write_str("(|")?;
                for s in subs {
                    write!(f, "{}", s)?;
                }
                f.write_str(")")
            }
            Filter::Not(inner) => write!(f, "(!{})", inner),
            Filter::Equality { attribute, value } => {
                write!(f, "({}={})", attribute, escape_value(value))
            }
            Filter::Substrings {
                attribute,
                substrings,
            } => {
                write!(f, "({}=", attribute)?;
                for s in substrings {
                    match s {
                        Substring::Initial(v) => write!(f, "{}", escape_value(v))?,
                        Substring::Any(v) => write!(f, "*{}*", escape_value(v))?,
                        Substring::Final(v) => write!(f, "{}", escape_value(v))?,
                    }
                }
                f.write_str(")")
            }
            Filter::GreaterOrEqual { attribute, value } => {
                write!(f, "({}>={})", attribute, escape_value(value))
            }
            Filter::LessOrEqual { attribute, value } => {
                write!(f, "({}<={})", attribute, escape_value(value))
            }
            Filter::Present(attr) => write!(f, "({}=*)", attr),
            Filter::Approx { attribute, value } => {
                write!(f, "({}~={})", attribute, escape_value(value))
            }
        }
    }
}

/// Escape a filter value per RFC 4515 §3 (only escapes the bytes that
/// must be escaped: `*`, `(`, `)`, `\`, and NUL).
fn escape_value(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0x00 => out.push_str("\\00"),
            _ => {
                // For printable ASCII, emit as-is; for non-printable, use
                // hex form.
                if (0x20..=0x7E).contains(&b) {
                    out.push(b as char);
                } else {
                    out.push_str(&format!("\\{:02x}", b));
                }
            }
        }
    }
    out
}

// ---- RFC 4515 string parser ----

/// Parse an RFC 4515 string filter (e.g. `(&(objectClass=user)(cn=alice))`)
/// into a structured [`Filter`].
pub fn parse_filter(s: &str) -> Result<Filter, FilterParseError> {
    let bytes = s.as_bytes();
    let mut pos = 0;
    // Skip leading whitespace.
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    let f = parse_filter_inner(bytes, &mut pos)?;
    // Skip trailing whitespace.
    while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
        pos += 1;
    }
    if pos != bytes.len() {
        return Err(FilterParseError::TrailingData(pos));
    }
    Ok(f)
}

/// Error type for RFC 4515 filter parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterParseError {
    /// The filter did not start with `(`.
    #[error("expected '(' at position {0}")]
    ExpectedOpenParen(usize),
    /// The filter did not end with `)`.
    #[error("expected ')' at position {0}")]
    ExpectedCloseParen(usize),
    /// An empty filter component `()`.
    #[error("empty filter at position {0}")]
    Empty(usize),
    /// An unsupported filter operator was encountered.
    #[error("unsupported operator {0:?} at position {1}")]
    UnsupportedOperator(char, usize),
    /// A bare `*` (not part of a substring filter) was encountered in a
    /// value.
    #[error("bare '*' in value at position {0}")]
    BareStar(usize),
    /// The input ended before the filter was complete.
    #[error("unexpected end of input at position {0}")]
    UnexpectedEof(usize),
    /// Trailing data after the filter.
    #[error("trailing data at position {0}")]
    TrailingData(usize),
    /// An invalid escape sequence `\xx`.
    #[error("invalid escape sequence at position {0}")]
    InvalidEscape(usize),
}

fn parse_filter_inner(bytes: &[u8], pos: &mut usize) -> Result<Filter, FilterParseError> {
    if *pos >= bytes.len() {
        return Err(FilterParseError::UnexpectedEof(*pos));
    }
    if bytes[*pos] != b'(' {
        return Err(FilterParseError::ExpectedOpenParen(*pos));
    }
    *pos += 1;
    if *pos >= bytes.len() {
        return Err(FilterParseError::UnexpectedEof(*pos));
    }
    let c = bytes[*pos];
    let filter = match c {
        b'&' | b'|' => {
            *pos += 1;
            let mut subs = Vec::new();
            while *pos < bytes.len() && bytes[*pos] == b'(' {
                subs.push(parse_filter_inner(bytes, pos)?);
            }
            if subs.is_empty() {
                return Err(FilterParseError::Empty(*pos));
            }
            if c == b'&' {
                Filter::And(subs)
            } else {
                Filter::Or(subs)
            }
        }
        b'!' => {
            *pos += 1;
            let inner = parse_filter_inner(bytes, pos)?;
            Filter::Not(Box::new(inner))
        }
        _ => {
            // Simple filter: attr op value
            parse_simple_filter(bytes, pos)?
        }
    };
    // Expect ')'.
    if *pos >= bytes.len() {
        return Err(FilterParseError::UnexpectedEof(*pos));
    }
    if bytes[*pos] != b')' {
        return Err(FilterParseError::ExpectedCloseParen(*pos));
    }
    *pos += 1;
    Ok(filter)
}

/// Parse a simple filter `(attr=value)` / `(attr>=value)` / `(attr=*)` /
/// `(attr=init*any*fin)` after the leading `(` has been consumed.
fn parse_simple_filter(bytes: &[u8], pos: &mut usize) -> Result<Filter, FilterParseError> {
    // Read attribute name (up to =, <, >, ~, or ).
    let attr_start = *pos;
    while *pos < bytes.len() && !matches!(bytes[*pos], b'=' | b'<' | b'>' | b'~' | b')') {
        *pos += 1;
    }
    if *pos >= bytes.len() {
        return Err(FilterParseError::UnexpectedEof(*pos));
    }
    let attr = std::str::from_utf8(&bytes[attr_start..*pos])
        .map_err(|_| FilterParseError::InvalidEscape(attr_start))?
        .trim()
        .to_string();
    if attr.is_empty() {
        return Err(FilterParseError::Empty(attr_start));
    }
    // Read operator.
    let op = bytes[*pos];
    *pos += 1;
    // Handle >=, <=, ~=
    if matches!(op, b'<' | b'>' | b'~') {
        if *pos >= bytes.len() || bytes[*pos] != b'=' {
            return Err(FilterParseError::UnsupportedOperator(op as char, *pos));
        }
        *pos += 1;
    } else if op != b'=' {
        return Err(FilterParseError::UnsupportedOperator(op as char, *pos));
    }
    // Read value (until ')'), handling escapes and `*`.
    let value = parse_value(bytes, pos)?;
    let f = match op {
        b'=' => {
            // Could be present, substrings, or equality.
            if value == ValueTokens::Present {
                Filter::Present(attr)
            } else if let ValueTokens::Substrings(parts) = value {
                Filter::Substrings {
                    attribute: attr,
                    substrings: parts,
                }
            } else {
                let ValueTokens::Single(v) = value else {
                    unreachable!()
                };
                Filter::Equality {
                    attribute: attr,
                    value: v,
                }
            }
        }
        b'>' => Filter::GreaterOrEqual {
            attribute: attr,
            value: value.into_bytes(),
        },
        b'<' => Filter::LessOrEqual {
            attribute: attr,
            value: value.into_bytes(),
        },
        b'~' => Filter::Approx {
            attribute: attr,
            value: value.into_bytes(),
        },
        _ => unreachable!(),
    };
    Ok(f)
}

/// The parsed value of a simple filter, distinguishing `*` (present),
/// `init*any*fin` (substrings), and a plain value (equality/GE/LE/approx).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueTokens {
    /// `(attr=*)` — present filter.
    Present,
    /// `(attr=al*ce*ic)` — substrings filter.
    Substrings(Vec<Substring>),
    /// A plain value (no `*`).
    Single(Vec<u8>),
}

impl ValueTokens {
    fn into_bytes(self) -> Vec<u8> {
        match self {
            ValueTokens::Single(v) => v,
            ValueTokens::Present => Vec::new(),
            ValueTokens::Substrings(_) => Vec::new(),
        }
    }
}

/// Parse a value (the part after `=`/`>=`/`<=`/`~=` until `)`),
/// recognizing `*` separators and `\xx` escapes.
fn parse_value(bytes: &[u8], pos: &mut usize) -> Result<ValueTokens, FilterParseError> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut current = Vec::new();
    let mut saw_star = false;
    while *pos < bytes.len() && bytes[*pos] != b')' {
        match bytes[*pos] {
            b'*' => {
                saw_star = true;
                parts.push(std::mem::take(&mut current));
                *pos += 1;
            }
            b'\\' => {
                *pos += 1;
                if *pos + 1 >= bytes.len() {
                    return Err(FilterParseError::InvalidEscape(*pos));
                }
                let h1 = hex_digit(bytes[*pos])?;
                let h2 = hex_digit(bytes[*pos + 1])?;
                current.push((h1 << 4) | h2);
                *pos += 2;
            }
            b => {
                current.push(b);
                *pos += 1;
            }
        }
    }
    if saw_star {
        // Push the final part (after the last `*`).
        parts.push(current);
        // Convert parts to Substring choices: first = Initial (if non-empty),
        // last = Final (if non-empty), middle = Any.
        // But if first/last is empty, that means the filter starts/ends
        // with `*` — no Initial/Final.
        let mut subs = Vec::new();
        let n = parts.len();
        for (i, p) in parts.into_iter().enumerate() {
            if p.is_empty() {
                // Empty part: leading or trailing `*`, or `**`.
                continue;
            }
            if i == 0 {
                subs.push(Substring::Initial(p));
            } else if i == n - 1 {
                subs.push(Substring::Final(p));
            } else {
                subs.push(Substring::Any(p));
            }
        }
        // Special case: `(attr=*)` — single empty part, no substrings.
        if subs.is_empty() {
            Ok(ValueTokens::Present)
        } else {
            Ok(ValueTokens::Substrings(subs))
        }
    } else {
        Ok(ValueTokens::Single(current))
    }
}

fn hex_digit(b: u8) -> Result<u8, FilterParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(FilterParseError::InvalidEscape(b as usize)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_present_filter() {
        let f = parse_filter("(objectClass=*)").unwrap();
        assert_eq!(f, Filter::Present("objectClass".into()));
    }

    #[test]
    fn parse_equality_filter() {
        let f = parse_filter("(cn=alice)").unwrap();
        assert_eq!(
            f,
            Filter::Equality {
                attribute: "cn".into(),
                value: b"alice".to_vec(),
            }
        );
    }

    #[test]
    fn parse_and_filter() {
        let f = parse_filter("(&(objectClass=user)(cn=alice))").unwrap();
        assert_eq!(
            f,
            Filter::And(vec![
                Filter::Equality {
                    attribute: "objectClass".into(),
                    value: b"user".to_vec(),
                },
                Filter::Equality {
                    attribute: "cn".into(),
                    value: b"alice".to_vec(),
                },
            ])
        );
    }

    #[test]
    fn parse_or_filter() {
        let f = parse_filter("(|(cn=alice)(cn=bob))").unwrap();
        assert_eq!(
            f,
            Filter::Or(vec![
                Filter::Equality {
                    attribute: "cn".into(),
                    value: b"alice".to_vec(),
                },
                Filter::Equality {
                    attribute: "cn".into(),
                    value: b"bob".to_vec(),
                },
            ])
        );
    }

    #[test]
    fn parse_not_filter() {
        let f = parse_filter("(!(cn=alice))").unwrap();
        assert_eq!(
            f,
            Filter::Not(Box::new(Filter::Equality {
                attribute: "cn".into(),
                value: b"alice".to_vec(),
            }))
        );
    }

    #[test]
    fn parse_substrings_filter() {
        let f = parse_filter("(cn=al*ce)").unwrap();
        assert_eq!(
            f,
            Filter::Substrings {
                attribute: "cn".into(),
                substrings: vec![
                    Substring::Initial(b"al".to_vec()),
                    Substring::Final(b"ce".to_vec()),
                ],
            }
        );
    }

    #[test]
    fn parse_substrings_with_any() {
        let f = parse_filter("(cn=al*x*ce)").unwrap();
        assert_eq!(
            f,
            Filter::Substrings {
                attribute: "cn".into(),
                substrings: vec![
                    Substring::Initial(b"al".to_vec()),
                    Substring::Any(b"x".to_vec()),
                    Substring::Final(b"ce".to_vec()),
                ],
            }
        );
    }

    #[test]
    fn parse_ge_filter() {
        let f = parse_filter("(uid>=1000)").unwrap();
        assert_eq!(
            f,
            Filter::GreaterOrEqual {
                attribute: "uid".into(),
                value: b"1000".to_vec(),
            }
        );
    }

    #[test]
    fn parse_le_filter() {
        let f = parse_filter("(uid<=2000)").unwrap();
        assert_eq!(
            f,
            Filter::LessOrEqual {
                attribute: "uid".into(),
                value: b"2000".to_vec(),
            }
        );
    }

    #[test]
    fn parse_approx_filter() {
        let f = parse_filter("(cn~=alice)").unwrap();
        assert_eq!(
            f,
            Filter::Approx {
                attribute: "cn".into(),
                value: b"alice".to_vec(),
            }
        );
    }

    #[test]
    fn parse_nested_and_or_not() {
        let f = parse_filter("(&(|(cn=alice)(cn=bob))(!(objectClass=computer)))").unwrap();
        assert_eq!(
            f,
            Filter::And(vec![
                Filter::Or(vec![
                    Filter::Equality {
                        attribute: "cn".into(),
                        value: b"alice".to_vec(),
                    },
                    Filter::Equality {
                        attribute: "cn".into(),
                        value: b"bob".to_vec(),
                    },
                ]),
                Filter::Not(Box::new(Filter::Equality {
                    attribute: "objectClass".into(),
                    value: b"computer".to_vec(),
                })),
            ])
        );
    }

    #[test]
    fn parse_escape_sequence() {
        let f = parse_filter("(cn=al\\29ice)").unwrap();
        // \29 = ')'
        assert_eq!(
            f,
            Filter::Equality {
                attribute: "cn".into(),
                value: b"al)ice".to_vec(),
            }
        );
    }

    #[test]
    fn parse_error_missing_close_paren() {
        let err = parse_filter("(cn=alice").unwrap_err();
        assert!(matches!(err, FilterParseError::UnexpectedEof(_)));
    }

    #[test]
    fn parse_error_empty() {
        let err = parse_filter("()").unwrap_err();
        assert!(matches!(err, FilterParseError::Empty(_)));
    }

    #[test]
    fn display_round_trip_present() {
        let f = Filter::present("objectClass");
        assert_eq!(f.to_string(), "(objectClass=*)");
        let parsed = parse_filter(&f.to_string()).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn display_round_trip_equality() {
        let f = Filter::equality("cn", "alice");
        assert_eq!(f.to_string(), "(cn=alice)");
        let parsed = parse_filter(&f.to_string()).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn display_round_trip_and() {
        let f = Filter::and(vec![
            Filter::equality("objectClass", "user"),
            Filter::equality("cn", "alice"),
        ]);
        assert_eq!(f.to_string(), "(&(objectClass=user)(cn=alice))");
        let parsed = parse_filter(&f.to_string()).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn ber_round_trip_present() {
        let f = Filter::present("objectClass");
        let mut out = Vec::new();
        f.encode(&mut out);
        let (tlv, rest) = ber::decode_tlv(&out).unwrap();
        assert!(rest.is_empty());
        assert_eq!(tlv.tag, FILTER_PRESENT);
        let decoded = Filter::decode_from_tlv(tlv.tag, tlv.value).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn ber_round_trip_equality() {
        let f = Filter::equality("cn", "alice");
        let mut out = Vec::new();
        f.encode(&mut out);
        let (tlv, rest) = ber::decode_tlv(&out).unwrap();
        assert!(rest.is_empty());
        assert_eq!(tlv.tag, FILTER_EQUALITY);
        let decoded = Filter::decode_from_tlv(tlv.tag, tlv.value).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn ber_round_trip_and() {
        let f = Filter::and(vec![
            Filter::equality("objectClass", "user"),
            Filter::equality("cn", "alice"),
        ]);
        let mut out = Vec::new();
        f.encode(&mut out);
        let (tlv, rest) = ber::decode_tlv(&out).unwrap();
        assert!(rest.is_empty());
        assert_eq!(tlv.tag, FILTER_AND);
        let decoded = Filter::decode_from_tlv(tlv.tag, tlv.value).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn ber_round_trip_not() {
        let f = Filter::not(Filter::equality("cn", "alice"));
        let mut out = Vec::new();
        f.encode(&mut out);
        let (tlv, rest) = ber::decode_tlv(&out).unwrap();
        assert!(rest.is_empty());
        assert_eq!(tlv.tag, FILTER_NOT);
        let decoded = Filter::decode_from_tlv(tlv.tag, tlv.value).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn ber_round_trip_substrings() {
        let f = Filter::Substrings {
            attribute: "cn".into(),
            substrings: vec![
                Substring::Initial(b"al".to_vec()),
                Substring::Any(b"x".to_vec()),
                Substring::Final(b"ce".to_vec()),
            ],
        };
        let mut out = Vec::new();
        f.encode(&mut out);
        let (tlv, rest) = ber::decode_tlv(&out).unwrap();
        assert!(rest.is_empty());
        assert_eq!(tlv.tag, FILTER_SUBSTRINGS);
        let decoded = Filter::decode_from_tlv(tlv.tag, tlv.value).unwrap();
        assert_eq!(decoded, f);
    }
}
