//! LDAP message types (RFC 4511 §4) and their BER encode/decode impls.
//!
//! The wire-level [`LdapMessage`] wraps a [`ProtocolOp`] (the
//! `protocolOp` CHOICE) and an optional list of [`Control`]s. Each
//! `ProtocolOp` variant has its own BER encoder that emits the
//! appropriate `[APPLICATION N]` tag.
//!
//! ## Naming convention
//!
//! The handler-level structs [`SearchRequest`] and [`SearchResultEntry`]
//! use snake_case field names (matching the existing v0.6 API). The
//! wire-level types use the RFC 4511 ASN.1 names where they differ
//! (e.g. [`LdapResult::matched_dn`] mirrors `matchedDN`).
//!
//! ## Round-trip property
//!
//! Every type in this module satisfies `decode(encode(x)) == x` — see the
//! per-type unit tests at the bottom of the file.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::ber::{
    self, decode_bool_value, decode_integer_value, decode_string_value, BerError, AUTH_SASL,
    AUTH_SIMPLE, CONTROLS_TAG, TAG_BOOLEAN, TAG_ENUMERATED, TAG_INTEGER, TAG_OCTET_STRING,
    TAG_SEQUENCE, TAG_SET,
};
use crate::filter::Filter;

// Re-export the application-tag constants for handlers and tests.
pub use crate::ber::{
    APP_ADD_REQUEST, APP_ADD_RESPONSE, APP_BIND_REQUEST, APP_BIND_RESPONSE, APP_DEL_REQUEST,
    APP_DEL_RESPONSE, APP_MODIFY_REQUEST, APP_MODIFY_RESPONSE, APP_SEARCH_REQUEST,
    APP_SEARCH_RESULT_DONE, APP_SEARCH_RESULT_ENTRY, APP_UNBIND_REQUEST,
};

/// An LDAP message ID (RFC 4511 §4.1.1.1). Positive integer; clients
/// typically start at 1 and increment per request.
pub type MessageId = i32;

/// An LDAP result code (RFC 4511 §4.1.9). Only the codes used by this
/// crate's handlers are listed; unknown codes round-trip via
/// [`ResultCode::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ResultCode {
    /// `success(0)` — operation completed successfully.
    Success = 0,
    /// `operationsError(1)` — server internal error.
    OperationsError = 1,
    /// `protocolError(2)` — malformed or invalid request.
    ProtocolError = 2,
    /// `timeLimitExceeded(3)` — search exceeded the time limit.
    TimeLimitExceeded = 3,
    /// `sizeLimitExceeded(4)` — search exceeded the size limit.
    SizeLimitExceeded = 4,
    /// `compareFalse(5)` — compare evaluated to false.
    CompareFalse = 5,
    /// `compareTrue(6)` — compare evaluated to true.
    CompareTrue = 6,
    /// `authMethodNotSupported(7)` — bind method not supported.
    AuthMethodNotSupported = 7,
    /// `strongerAuthRequired(8)` — stronger authentication required.
    StrongerAuthRequired = 8,
    /// `referral(10)` — refer the client elsewhere.
    Referral = 10,
    /// `adminLimitExceeded(11)` — admin limit exceeded.
    AdminLimitExceeded = 11,
    /// `noSuchAttribute(16)` — attribute does not exist on the entry.
    NoSuchAttribute = 16,
    /// `undefinedAttributeType(17)` — attribute type not defined in schema.
    UndefinedAttributeType = 17,
    /// `inappropriateMatching(18)` — filter uses an unsupported match type.
    InappropriateMatching = 18,
    /// `constraintViolation(19)` — attribute value violates a constraint.
    ConstraintViolation = 19,
    /// `attributeOrValueExists(20)` — add/modify would create a duplicate.
    AttributeOrValueExists = 20,
    /// `invalidAttributeSyntax(21)` — attribute value syntax invalid.
    InvalidAttributeSyntax = 21,
    /// `noSuchObject(32)` — base object not found.
    NoSuchObject = 32,
    /// `invalidDNSyntax(34)` — DN syntax invalid.
    InvalidDNSyntax = 34,
    /// `inappropriateAuthentication(48)` — bind type not allowed for this DN.
    InappropriateAuthentication = 48,
    /// `invalidCredentials(49)` — wrong DN/password.
    InvalidCredentials = 49,
    /// `insufficientAccessRights(50)` — ACL denied the operation.
    InsufficientAccessRights = 50,
    /// `busy(51)` — server too busy.
    Busy = 51,
    /// `unavailable(52)` — server unavailable.
    Unavailable = 52,
    /// `unwillingToPerform(53)` — server refuses the operation.
    UnwillingToPerform = 53,
    /// `loopDetect(54)` — referral loop detected.
    LoopDetect = 54,
    /// `namingViolation(64)` — DN violates naming rules.
    NamingViolation = 64,
    /// `objectClassViolation(65)` — entry violates object class rules.
    ObjectClassViolation = 65,
    /// `notAllowedOnNonLeaf(66)` — operation only allowed on leaf entries.
    NotAllowedOnNonLeaf = 66,
    /// `entryAlreadyExists(68)` — add would create a duplicate DN.
    EntryAlreadyExists = 68,
    /// `other(80)` — catch-all for unspecified errors.
    Other = 80,
}

impl ResultCode {
    /// Encode the result code as an ENUMERATED value into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        ber::encode_enumerated(*self as i64, out);
    }

    /// Decode a result code from an ENUMERATED TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<ResultCode, BerError> {
        let n = decode_integer_value(value)?;
        Ok(match n {
            0 => ResultCode::Success,
            1 => ResultCode::OperationsError,
            2 => ResultCode::ProtocolError,
            3 => ResultCode::TimeLimitExceeded,
            4 => ResultCode::SizeLimitExceeded,
            5 => ResultCode::CompareFalse,
            6 => ResultCode::CompareTrue,
            7 => ResultCode::AuthMethodNotSupported,
            8 => ResultCode::StrongerAuthRequired,
            10 => ResultCode::Referral,
            11 => ResultCode::AdminLimitExceeded,
            16 => ResultCode::NoSuchAttribute,
            17 => ResultCode::UndefinedAttributeType,
            18 => ResultCode::InappropriateMatching,
            19 => ResultCode::ConstraintViolation,
            20 => ResultCode::AttributeOrValueExists,
            21 => ResultCode::InvalidAttributeSyntax,
            32 => ResultCode::NoSuchObject,
            34 => ResultCode::InvalidDNSyntax,
            48 => ResultCode::InappropriateAuthentication,
            49 => ResultCode::InvalidCredentials,
            50 => ResultCode::InsufficientAccessRights,
            51 => ResultCode::Busy,
            52 => ResultCode::Unavailable,
            53 => ResultCode::UnwillingToPerform,
            54 => ResultCode::LoopDetect,
            64 => ResultCode::NamingViolation,
            65 => ResultCode::ObjectClassViolation,
            66 => ResultCode::NotAllowedOnNonLeaf,
            68 => ResultCode::EntryAlreadyExists,
            _ => ResultCode::Other,
        })
    }
}

/// An `LDAPResult` (RFC 4511 §4.1.9) — the common result envelope shared
/// by `BindResponse`, `SearchResultDone`, `ModifyResponse`, `AddResponse`,
/// and `DelResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    /// The result code (ENUMERATED).
    pub result_code: ResultCode,
    /// The matched DN (often empty on success).
    pub matched_dn: String,
    /// A human-readable diagnostic message (often empty on success).
    pub diagnostic_message: String,
}

impl LdapResult {
    /// Construct a successful result with empty matched DN and diagnostic.
    pub fn success() -> Self {
        LdapResult {
            result_code: ResultCode::Success,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
        }
    }

    /// Construct an error result with the given code and diagnostic.
    pub fn error(code: ResultCode, diagnostic: impl Into<String>) -> Self {
        LdapResult {
            result_code: code,
            matched_dn: String::new(),
            diagnostic_message: diagnostic.into(),
        }
    }

    /// Encode the LDAPResult's *components* (resultCode + matchedDN +
    /// diagnosticMessage) into `out` — without the outer SEQUENCE tag.
    /// Callers wrap this in the appropriate `[APPLICATION N]` SEQUENCE.
    pub fn encode_components(&self, out: &mut Vec<u8>) {
        self.result_code.encode(out);
        ber::encode_string(&self.matched_dn, out);
        ber::encode_string(&self.diagnostic_message, out);
    }

    /// Decode the three LDAPResult components from `bytes`, returning
    /// the result and any remaining bytes (for extended result types like
    /// `BindResponse` that have extra trailing fields).
    pub fn decode_components(bytes: &[u8]) -> Result<(LdapResult, &[u8]), BerError> {
        let (code_tlv, rest) = ber::decode_tlv(bytes)?;
        if code_tlv.tag != TAG_ENUMERATED {
            return Err(BerError::UnexpectedTag {
                expected: TAG_ENUMERATED,
                actual: code_tlv.tag,
            });
        }
        let result_code = ResultCode::decode_from_value(code_tlv.value)?;
        let (dn_tlv, rest) = ber::decode_tlv(rest)?;
        if dn_tlv.tag != TAG_OCTET_STRING {
            return Err(BerError::UnexpectedTag {
                expected: TAG_OCTET_STRING,
                actual: dn_tlv.tag,
            });
        }
        let matched_dn = decode_string_value(dn_tlv.value)?;
        let (msg_tlv, rest) = ber::decode_tlv(rest)?;
        if msg_tlv.tag != TAG_OCTET_STRING {
            return Err(BerError::UnexpectedTag {
                expected: TAG_OCTET_STRING,
                actual: msg_tlv.tag,
            });
        }
        let diagnostic_message = decode_string_value(msg_tlv.value)?;
        Ok((
            LdapResult {
                result_code,
                matched_dn,
                diagnostic_message,
            },
            rest,
        ))
    }
}

/// An LDAP search request (RFC 4511 §4.5).
///
/// This is the handler-level type used by [`handle_search`](crate::handle_search);
/// the BER encoder/decoder produces/consumes the wire form directly from
/// this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    /// The base DN of the search (`baseObject`).
    pub base_dn: String,
    /// The search scope (0=base, 1=one-level, 2=subtree, per RFC 4511
    /// §4.5.1).
    pub scope: u8,
    /// The deref-aliases policy (per RFC 4511 §4.5.1).
    pub deref_aliases: u8,
    /// The size limit (0 = no limit).
    pub size_limit: i32,
    /// The time limit (0 = no limit).
    pub time_limit: i32,
    /// The search filter (structured form — RFC 4511 wire encoding).
    pub filter: Filter,
    /// The attributes to return (empty = all user attributes; `*` = all;
    /// `1.1` = no attributes).
    pub attributes: Vec<String>,
    /// Whether to return attribute types only (no values).
    pub types_only: bool,
}

impl SearchRequest {
    /// Encode as a `[APPLICATION 3]` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        ber::encode_string(&self.base_dn, &mut body);
        ber::encode_enumerated(self.scope as i64, &mut body);
        ber::encode_enumerated(self.deref_aliases as i64, &mut body);
        ber::encode_integer(self.size_limit as i64, &mut body);
        ber::encode_integer(self.time_limit as i64, &mut body);
        ber::encode_bool(self.types_only, &mut body);
        self.filter.encode(&mut body);
        // attributes — SEQUENCE OF LDAPString
        let mut attrs = Vec::new();
        for a in &self.attributes {
            let mut s = Vec::new();
            ber::encode_string(a, &mut s);
            attrs.push(s);
        }
        ber::encode_sequence(&attrs, &mut body);
        ber::encode_tlv(APP_SEARCH_REQUEST, &body, out);
    }

    /// Decode from a TLV with the given value (the inside of the
    /// `[APPLICATION 3]` SEQUENCE).
    pub fn decode_from_value(value: &[u8]) -> Result<SearchRequest, BerError> {
        let (base_tlv, rest) = ber::decode_tlv(value)?;
        let base_dn = decode_string_value(base_tlv.value)?;
        let (scope_tlv, rest) = ber::decode_tlv(rest)?;
        if scope_tlv.tag != TAG_ENUMERATED {
            return Err(BerError::UnexpectedTag {
                expected: TAG_ENUMERATED,
                actual: scope_tlv.tag,
            });
        }
        let scope = decode_integer_value(scope_tlv.value)? as u8;
        let (deref_tlv, rest) = ber::decode_tlv(rest)?;
        let deref_aliases = decode_integer_value(deref_tlv.value)? as u8;
        let (size_tlv, rest) = ber::decode_tlv(rest)?;
        let size_limit = decode_integer_value(size_tlv.value)? as i32;
        let (time_tlv, rest) = ber::decode_tlv(rest)?;
        let time_limit = decode_integer_value(time_tlv.value)? as i32;
        let (types_tlv, rest) = ber::decode_tlv(rest)?;
        if types_tlv.tag != TAG_BOOLEAN {
            return Err(BerError::UnexpectedTag {
                expected: TAG_BOOLEAN,
                actual: types_tlv.tag,
            });
        }
        let types_only = decode_bool_value(types_tlv.value)?;
        let (filter_tlv, rest) = ber::decode_tlv(rest)?;
        let filter = Filter::decode_from_tlv(filter_tlv.tag, filter_tlv.value)?;
        let (attrs_tlv, rest) = ber::decode_tlv(rest)?;
        if attrs_tlv.tag != TAG_SEQUENCE {
            return Err(BerError::UnexpectedTag {
                expected: TAG_SEQUENCE,
                actual: attrs_tlv.tag,
            });
        }
        let mut attributes = Vec::new();
        let mut a_rest = attrs_tlv.value;
        while !a_rest.is_empty() {
            let (a_tlv, a_remaining) = ber::decode_tlv(a_rest)?;
            attributes.push(decode_string_value(a_tlv.value)?);
            a_rest = a_remaining;
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(SearchRequest {
            base_dn,
            scope,
            deref_aliases,
            size_limit,
            time_limit,
            filter,
            attributes,
            types_only,
        })
    }
}

/// An LDAP search result entry (RFC 4511 §4.5.2).
///
/// The `attributes` field is a list of `(name, values)` pairs where each
/// value is a list of byte strings (multi-valued attributes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultEntry {
    /// The entry's DN (`objectName`).
    pub dn: String,
    /// The entry's attributes (`PartialAttributeList`).
    pub attributes: Vec<(String, Vec<Vec<u8>>)>,
}

impl SearchResultEntry {
    /// Encode as a `[APPLICATION 4]` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        ber::encode_string(&self.dn, &mut body);
        // PartialAttributeList — SEQUENCE OF PartialAttribute
        let mut attrs = Vec::new();
        for (name, vals) in &self.attributes {
            let mut pa = Vec::new();
            ber::encode_string(name, &mut pa);
            // vals — SET OF AttributeValue (each OCTET STRING)
            let mut set_elems = Vec::new();
            for v in vals {
                let mut s = Vec::new();
                ber::encode_tlv(TAG_OCTET_STRING, v, &mut s);
                set_elems.push(s);
            }
            ber::encode_set(&set_elems, &mut pa);
            let mut wrapped = Vec::new();
            ber::encode_tlv(TAG_SEQUENCE, &pa, &mut wrapped);
            attrs.push(wrapped);
        }
        let mut list = Vec::new();
        ber::encode_sequence(&attrs, &mut list);
        body.extend_from_slice(&list);
        ber::encode_tlv(APP_SEARCH_RESULT_ENTRY, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<SearchResultEntry, BerError> {
        let (dn_tlv, rest) = ber::decode_tlv(value)?;
        let dn = decode_string_value(dn_tlv.value)?;
        let (list_tlv, rest) = ber::decode_tlv(rest)?;
        if list_tlv.tag != TAG_SEQUENCE {
            return Err(BerError::UnexpectedTag {
                expected: TAG_SEQUENCE,
                actual: list_tlv.tag,
            });
        }
        let mut attributes = Vec::new();
        let mut l_rest = list_tlv.value;
        while !l_rest.is_empty() {
            let (pa_tlv, l_remaining) = ber::decode_tlv(l_rest)?;
            if pa_tlv.tag != TAG_SEQUENCE {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SEQUENCE,
                    actual: pa_tlv.tag,
                });
            }
            let (name_tlv, pa_rest) = ber::decode_tlv(pa_tlv.value)?;
            let name = decode_string_value(name_tlv.value)?;
            let (set_tlv, pa_rest) = ber::decode_tlv(pa_rest)?;
            if set_tlv.tag != TAG_SET {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SET,
                    actual: set_tlv.tag,
                });
            }
            let mut vals = Vec::new();
            let mut s_rest = set_tlv.value;
            while !s_rest.is_empty() {
                let (v_tlv, s_remaining) = ber::decode_tlv(s_rest)?;
                vals.push(v_tlv.value.to_vec());
                s_rest = s_remaining;
            }
            attributes.push((name, vals));
            if !pa_rest.is_empty() {
                return Err(BerError::TrailingData(pa_rest.len()));
            }
            l_rest = l_remaining;
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(SearchResultEntry { dn, attributes })
    }
}

/// A search result done (RFC 4511 §4.5.3) — `LDAPResult` wrapped in
/// `[APPLICATION 5]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultDone {
    /// The result.
    pub result: LdapResult,
}

impl SearchResultDone {
    /// Encode as `[APPLICATION 5]`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        self.result.encode_components(&mut body);
        ber::encode_tlv(APP_SEARCH_RESULT_DONE, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<SearchResultDone, BerError> {
        let (result, rest) = LdapResult::decode_components(value)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(SearchResultDone { result })
    }
}

/// A bind authentication choice (RFC 4511 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationChoice {
    /// `simple [0] OCTET STRING` — the password bytes (empty for anonymous).
    Simple(Vec<u8>),
    /// `sasl [3] SaslCredentials` — SASL mechanism + optional credentials.
    Sasl(SaslCredentials),
}

/// SASL credentials (RFC 4511 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaslCredentials {
    /// The SASL mechanism name (e.g. `GSSAPI`, `EXTERNAL`).
    pub mechanism: String,
    /// Optional SASL credentials (server-specific).
    pub credentials: Option<Vec<u8>>,
}

/// A bind request (RFC 4511 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    /// The LDAP protocol version (1, 2, or 3).
    pub version: u8,
    /// The bind DN (empty for anonymous bind).
    pub name: String,
    /// The authentication choice.
    pub authentication: AuthenticationChoice,
}

impl BindRequest {
    /// Encode as `[APPLICATION 0]` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        ber::encode_integer(self.version as i64, &mut body);
        ber::encode_string(&self.name, &mut body);
        match &self.authentication {
            AuthenticationChoice::Simple(pw) => {
                ber::encode_tlv(AUTH_SIMPLE, pw, &mut body);
            }
            AuthenticationChoice::Sasl(sasl) => {
                let mut sasl_body = Vec::new();
                ber::encode_string(&sasl.mechanism, &mut sasl_body);
                if let Some(creds) = &sasl.credentials {
                    ber::encode_tlv(TAG_OCTET_STRING, creds, &mut sasl_body);
                }
                ber::encode_tlv(AUTH_SASL, &sasl_body, &mut body);
            }
        }
        ber::encode_tlv(APP_BIND_REQUEST, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<BindRequest, BerError> {
        let (ver_tlv, rest) = ber::decode_tlv(value)?;
        if ver_tlv.tag != crate::ber::TAG_INTEGER {
            return Err(BerError::UnexpectedTag {
                expected: crate::ber::TAG_INTEGER,
                actual: ver_tlv.tag,
            });
        }
        let version = decode_integer_value(ver_tlv.value)? as u8;
        let (name_tlv, rest) = ber::decode_tlv(rest)?;
        let name = decode_string_value(name_tlv.value)?;
        let (auth_tlv, rest) = ber::decode_tlv(rest)?;
        let authentication = match auth_tlv.tag {
            AUTH_SIMPLE => AuthenticationChoice::Simple(auth_tlv.value.to_vec()),
            AUTH_SASL => {
                let (mech_tlv, sasl_rest) = ber::decode_tlv(auth_tlv.value)?;
                let mechanism = decode_string_value(mech_tlv.value)?;
                let credentials = if sasl_rest.is_empty() {
                    None
                } else {
                    let (cred_tlv, sasl_rest) = ber::decode_tlv(sasl_rest)?;
                    if !sasl_rest.is_empty() {
                        return Err(BerError::TrailingData(sasl_rest.len()));
                    }
                    Some(cred_tlv.value.to_vec())
                };
                AuthenticationChoice::Sasl(SaslCredentials {
                    mechanism,
                    credentials,
                })
            }
            t => {
                return Err(BerError::UnexpectedTag {
                    expected: AUTH_SIMPLE,
                    actual: t,
                });
            }
        };
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(BindRequest {
            version,
            name,
            authentication,
        })
    }
}

/// A bind response (RFC 4511 §4.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindResponse {
    /// The result (LDAPResult components).
    pub result: LdapResult,
    /// Optional server SASL credentials (`[7] OCTET STRING`).
    pub server_sasl_creds: Option<Vec<u8>>,
}

impl BindResponse {
    /// Construct a successful bind response with no server SASL creds.
    pub fn success() -> Self {
        BindResponse {
            result: LdapResult::success(),
            server_sasl_creds: None,
        }
    }

    /// Construct an error bind response.
    pub fn error(code: ResultCode, diagnostic: impl Into<String>) -> Self {
        BindResponse {
            result: LdapResult::error(code, diagnostic),
            server_sasl_creds: None,
        }
    }

    /// Encode as `[APPLICATION 1]` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        self.result.encode_components(&mut body);
        if let Some(creds) = &self.server_sasl_creds {
            // [7] OCTET STRING — primitive context tag.
            ber::encode_tlv(crate::ber::CLASS_CONTEXT | 7, creds, &mut body);
        }
        ber::encode_tlv(APP_BIND_RESPONSE, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<BindResponse, BerError> {
        let (result, rest) = LdapResult::decode_components(value)?;
        let server_sasl_creds = if rest.is_empty() {
            None
        } else {
            let (cred_tlv, rest) = ber::decode_tlv(rest)?;
            if !rest.is_empty() {
                return Err(BerError::TrailingData(rest.len()));
            }
            Some(cred_tlv.value.to_vec())
        };
        Ok(BindResponse {
            result,
            server_sasl_creds,
        })
    }
}

/// An unbind request (RFC 4511 §4.3) — `[APPLICATION 2] NULL`. Has no
/// fields and no response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnbindRequest;

impl UnbindRequest {
    /// Encode as `[APPLICATION 2] NULL` (empty value).
    pub fn encode(&self, out: &mut Vec<u8>) {
        ber::encode_tlv(APP_UNBIND_REQUEST, &[], out);
    }

    /// Decode — the value must be empty.
    pub fn decode_from_value(value: &[u8]) -> Result<UnbindRequest, BerError> {
        if !value.is_empty() {
            return Err(BerError::TrailingData(value.len()));
        }
        Ok(UnbindRequest)
    }
}

/// A modify-request operation (RFC 4511 §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModificationOp {
    /// `add(0)` — add a value to an attribute.
    Add = 0,
    /// `delete(1)` — remove a value (or all values) from an attribute.
    Delete = 1,
    /// `replace(2)` — replace all values of an attribute.
    Replace = 2,
}

impl ModificationOp {
    /// Encode as ENUMERATED.
    pub fn encode(&self, out: &mut Vec<u8>) {
        ber::encode_enumerated(*self as i64, out);
    }

    /// Decode from an ENUMERATED value.
    pub fn decode_from_value(value: &[u8]) -> Result<ModificationOp, BerError> {
        let n = decode_integer_value(value)?;
        Ok(match n {
            0 => ModificationOp::Add,
            1 => ModificationOp::Delete,
            2 => ModificationOp::Replace,
            _ => return Err(BerError::OutOfRange(format!("unknown modify op: {}", n))),
        })
    }
}

/// A single modify change (RFC 4511 §4.6) — `(operation, modification)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The operation (add / delete / replace).
    pub operation: ModificationOp,
    /// The attribute to modify, with its (new) values.
    pub modification: (String, Vec<Vec<u8>>),
}

/// A modify request (RFC 4511 §4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyRequest {
    /// The DN of the object to modify.
    pub object: String,
    /// The list of changes to apply.
    pub changes: Vec<Change>,
}

impl ModifyRequest {
    /// Encode as `[APPLICATION 6]` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        ber::encode_string(&self.object, &mut body);
        // changes — SEQUENCE OF change SEQUENCE { ENUMERATED, PartialAttribute }
        let mut changes_seq = Vec::new();
        for change in &self.changes {
            let mut change_body = Vec::new();
            change.operation.encode(&mut change_body);
            // PartialAttribute — SEQUENCE { type, SET OF value }
            let mut pa = Vec::new();
            ber::encode_string(&change.modification.0, &mut pa);
            let mut set_elems = Vec::new();
            for v in &change.modification.1 {
                let mut s = Vec::new();
                ber::encode_tlv(TAG_OCTET_STRING, v, &mut s);
                set_elems.push(s);
            }
            ber::encode_set(&set_elems, &mut pa);
            let mut wrapped = Vec::new();
            ber::encode_tlv(TAG_SEQUENCE, &pa, &mut wrapped);
            change_body.extend_from_slice(&wrapped);
            let mut change_tlv = Vec::new();
            ber::encode_tlv(TAG_SEQUENCE, &change_body, &mut change_tlv);
            changes_seq.extend_from_slice(&change_tlv);
        }
        let mut changes_wrapped = Vec::new();
        ber::encode_tlv(TAG_SEQUENCE, &changes_seq, &mut changes_wrapped);
        body.extend_from_slice(&changes_wrapped);
        ber::encode_tlv(APP_MODIFY_REQUEST, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<ModifyRequest, BerError> {
        let (obj_tlv, rest) = ber::decode_tlv(value)?;
        let object = decode_string_value(obj_tlv.value)?;
        let (changes_seq_tlv, rest) = ber::decode_tlv(rest)?;
        if changes_seq_tlv.tag != TAG_SEQUENCE {
            return Err(BerError::UnexpectedTag {
                expected: TAG_SEQUENCE,
                actual: changes_seq_tlv.tag,
            });
        }
        let mut changes = Vec::new();
        let mut c_rest = changes_seq_tlv.value;
        while !c_rest.is_empty() {
            let (change_tlv, c_remaining) = ber::decode_tlv(c_rest)?;
            if change_tlv.tag != TAG_SEQUENCE {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SEQUENCE,
                    actual: change_tlv.tag,
                });
            }
            let (op_tlv, ch_rest) = ber::decode_tlv(change_tlv.value)?;
            let operation = ModificationOp::decode_from_value(op_tlv.value)?;
            let (pa_tlv, _ch_rest) = ber::decode_tlv(ch_rest)?;
            if pa_tlv.tag != TAG_SEQUENCE {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SEQUENCE,
                    actual: pa_tlv.tag,
                });
            }
            let (name_tlv, pa_rest) = ber::decode_tlv(pa_tlv.value)?;
            let name = decode_string_value(name_tlv.value)?;
            let (set_tlv, pa_rest) = ber::decode_tlv(pa_rest)?;
            if set_tlv.tag != TAG_SET {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SET,
                    actual: set_tlv.tag,
                });
            }
            let mut vals = Vec::new();
            let mut s_rest = set_tlv.value;
            while !s_rest.is_empty() {
                let (v_tlv, s_remaining) = ber::decode_tlv(s_rest)?;
                vals.push(v_tlv.value.to_vec());
                s_rest = s_remaining;
            }
            if !pa_rest.is_empty() {
                return Err(BerError::TrailingData(pa_rest.len()));
            }
            changes.push(Change {
                operation,
                modification: (name, vals),
            });
            c_rest = c_remaining;
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(ModifyRequest { object, changes })
    }
}

/// A modify response (RFC 4511 §4.6) — `LDAPResult` in `[APPLICATION 7]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyResponse {
    /// The result.
    pub result: LdapResult,
}

impl ModifyResponse {
    /// Construct a successful modify response.
    pub fn success() -> Self {
        ModifyResponse {
            result: LdapResult::success(),
        }
    }

    /// Encode as `[APPLICATION 7]`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        self.result.encode_components(&mut body);
        ber::encode_tlv(APP_MODIFY_RESPONSE, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<ModifyResponse, BerError> {
        let (result, rest) = LdapResult::decode_components(value)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(ModifyResponse { result })
    }
}

/// An add request (RFC 4511 §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    /// The DN of the entry to add.
    pub entry: String,
    /// The entry's attributes (same shape as `SearchResultEntry.attributes`).
    pub attributes: Vec<(String, Vec<Vec<u8>>)>,
}

impl AddRequest {
    /// Encode as `[APPLICATION 8]` SEQUENCE.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        ber::encode_string(&self.entry, &mut body);
        // AttributeList — SEQUENCE OF Attribute (same shape as PartialAttribute)
        let mut attrs = Vec::new();
        for (name, vals) in &self.attributes {
            let mut pa = Vec::new();
            ber::encode_string(name, &mut pa);
            let mut set_elems = Vec::new();
            for v in vals {
                let mut s = Vec::new();
                ber::encode_tlv(TAG_OCTET_STRING, v, &mut s);
                set_elems.push(s);
            }
            ber::encode_set(&set_elems, &mut pa);
            let mut wrapped = Vec::new();
            ber::encode_tlv(TAG_SEQUENCE, &pa, &mut wrapped);
            attrs.push(wrapped);
        }
        let mut list = Vec::new();
        ber::encode_sequence(&attrs, &mut list);
        body.extend_from_slice(&list);
        ber::encode_tlv(APP_ADD_REQUEST, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<AddRequest, BerError> {
        let (entry_tlv, rest) = ber::decode_tlv(value)?;
        let entry = decode_string_value(entry_tlv.value)?;
        let (list_tlv, rest) = ber::decode_tlv(rest)?;
        if list_tlv.tag != TAG_SEQUENCE {
            return Err(BerError::UnexpectedTag {
                expected: TAG_SEQUENCE,
                actual: list_tlv.tag,
            });
        }
        let mut attributes = Vec::new();
        let mut l_rest = list_tlv.value;
        while !l_rest.is_empty() {
            let (pa_tlv, l_remaining) = ber::decode_tlv(l_rest)?;
            if pa_tlv.tag != TAG_SEQUENCE {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SEQUENCE,
                    actual: pa_tlv.tag,
                });
            }
            let (name_tlv, pa_rest) = ber::decode_tlv(pa_tlv.value)?;
            let name = decode_string_value(name_tlv.value)?;
            let (set_tlv, pa_rest) = ber::decode_tlv(pa_rest)?;
            if set_tlv.tag != TAG_SET {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SET,
                    actual: set_tlv.tag,
                });
            }
            let mut vals = Vec::new();
            let mut s_rest = set_tlv.value;
            while !s_rest.is_empty() {
                let (v_tlv, s_remaining) = ber::decode_tlv(s_rest)?;
                vals.push(v_tlv.value.to_vec());
                s_rest = s_remaining;
            }
            attributes.push((name, vals));
            if !pa_rest.is_empty() {
                return Err(BerError::TrailingData(pa_rest.len()));
            }
            l_rest = l_remaining;
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(AddRequest { entry, attributes })
    }
}

/// An add response (RFC 4511 §4.7) — `LDAPResult` in `[APPLICATION 9]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddResponse {
    /// The result.
    pub result: LdapResult,
}

impl AddResponse {
    /// Construct a successful add response.
    pub fn success() -> Self {
        AddResponse {
            result: LdapResult::success(),
        }
    }

    /// Encode as `[APPLICATION 9]`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        self.result.encode_components(&mut body);
        ber::encode_tlv(APP_ADD_RESPONSE, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<AddResponse, BerError> {
        let (result, rest) = LdapResult::decode_components(value)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(AddResponse { result })
    }
}

/// A delete request (RFC 4511 §4.8) — `[APPLICATION 10] LDAPDN`. Just a
/// DN string with a primitive application tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelRequest {
    /// The DN of the entry to delete.
    pub entry: String,
}

impl DelRequest {
    /// Construct a new delete request for the given DN.
    pub fn new(entry: impl Into<String>) -> Self {
        DelRequest {
            entry: entry.into(),
        }
    }

    /// Encode as `[APPLICATION 10]` (primitive OCTET STRING, no SEQUENCE
    /// wrapper).
    pub fn encode(&self, out: &mut Vec<u8>) {
        ber::encode_tlv(APP_DEL_REQUEST, self.entry.as_bytes(), out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<DelRequest, BerError> {
        Ok(DelRequest {
            entry: decode_string_value(value)?,
        })
    }
}

/// A delete response (RFC 4511 §4.8) — `LDAPResult` in `[APPLICATION 11]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelResponse {
    /// The result.
    pub result: LdapResult,
}

impl DelResponse {
    /// Construct a successful delete response.
    pub fn success() -> Self {
        DelResponse {
            result: LdapResult::success(),
        }
    }

    /// Encode as `[APPLICATION 11]`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        self.result.encode_components(&mut body);
        ber::encode_tlv(APP_DEL_RESPONSE, &body, out);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<DelResponse, BerError> {
        let (result, rest) = LdapResult::decode_components(value)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(DelResponse { result })
    }
}

/// An LDAP control (RFC 4511 §4.1.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// The control's OID (`controlType`).
    pub control_type: String,
    /// Whether the control is critical (`criticality`, default false).
    pub criticality: bool,
    /// Optional control value (`controlValue`, OCTET STRING).
    pub control_value: Option<Vec<u8>>,
}

impl Control {
    /// Encode as a SEQUENCE into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        ber::encode_string(&self.control_type, &mut body);
        // criticality defaults to FALSE — only emit if true or if
        // control_value is present (to disambiguate). For simplicity,
        // always emit criticality (spec-legal).
        ber::encode_bool(self.criticality, &mut body);
        if let Some(v) = &self.control_value {
            ber::encode_tlv(TAG_OCTET_STRING, v, &mut body);
        }
        let mut wrapped = Vec::new();
        ber::encode_tlv(TAG_SEQUENCE, &body, &mut wrapped);
        out.extend_from_slice(&wrapped);
    }

    /// Decode from a TLV value.
    pub fn decode_from_value(value: &[u8]) -> Result<Control, BerError> {
        let (oid_tlv, rest) = ber::decode_tlv(value)?;
        let control_type = decode_string_value(oid_tlv.value)?;
        // criticality is optional (DEFAULT FALSE); control_value is optional.
        let mut criticality = false;
        let mut control_value = None;
        let mut rest = rest;
        if !rest.is_empty() {
            let (next_tlv, r) = ber::decode_tlv(rest)?;
            if next_tlv.tag == TAG_BOOLEAN {
                criticality = decode_bool_value(next_tlv.value)?;
                rest = r;
            } else if next_tlv.tag == TAG_OCTET_STRING {
                control_value = Some(next_tlv.value.to_vec());
                rest = r;
            } else {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_BOOLEAN,
                    actual: next_tlv.tag,
                });
            }
        }
        if !rest.is_empty() {
            let (cv_tlv, r) = ber::decode_tlv(rest)?;
            if cv_tlv.tag != TAG_OCTET_STRING {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_OCTET_STRING,
                    actual: cv_tlv.tag,
                });
            }
            control_value = Some(cv_tlv.value.to_vec());
            rest = r;
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(Control {
            control_type,
            criticality,
            control_value,
        })
    }
}

// ---- AD-interop LDAP controls (ADR-006) ----
//
// Microsoft Active Directory extends LDAP with a set of controls under
// the `1.2.840.113556.1.4.*` OID arc. AD-aware clients (Windows LDAP,
// third-party tools that interop with AD) expect these controls to be
// understood by any server that claims AD-compatibility. The Adrian DSA
// implements the four most-commonly-used controls per ADR-006:
//
// - Paged results (RFC 2696 / `LDAP_SERVER_PAGED_RESULT_OID`)
// - Server-side sort (RFC 2891 / `LDAP_SERVER_SORT_OID`)
// - SD flags (`LDAP_SERVER_SD_FLAGS_OID` — controls which parts of the
//   `nTSecurityDescriptor` attribute are returned)
// - Extended DN (`LDAP_SERVER_EXTENDED_DN_OID` — appends `;<GUID>` and
//   `;<SID>` to DNs in search responses)

/// `1.2.840.113556.1.4.319` — paged results control OID (RFC 2696,
/// also `LDAP_SERVER_PAGED_RESULT_OID` per MS-ADTS).
pub const LDAP_SERVER_PAGED_RESULT_OID: &str = "1.2.840.113556.1.4.319";

/// `1.2.840.113556.1.4.473` — server-side sort request control OID
/// (RFC 2891, also `LDAP_SERVER_SORT_OID`).
pub const LDAP_SERVER_SORT_OID: &str = "1.2.840.113556.1.4.473";

/// `1.2.840.113556.1.4.474` — server-side sort response control OID
/// (RFC 2891, also `LDAP_SERVER_SORT_RESPONSE_OID`).
pub const LDAP_SERVER_SORT_RESPONSE_OID: &str = "1.2.840.113556.1.4.474";

/// `1.2.840.113556.1.4.801` — security descriptor flags control OID
/// (`LDAP_SERVER_SD_FLAGS_OID` per MS-ADTS §3.1.1.3.4.1).
pub const LDAP_SERVER_SD_FLAGS_OID: &str = "1.2.840.113556.1.4.801";

/// `1.2.840.113556.1.4.529` — extended DN control OID
/// (`LDAP_SERVER_EXTENDED_DN_OID` per MS-ADTS §3.1.1.3.4.2).
pub const LDAP_SERVER_EXTENDED_DN_OID: &str = "1.2.840.113556.1.4.529";

/// A paged-results control value (RFC 2696 §2).
///
/// Wire form: `SEQUENCE { size INTEGER (0), cookie OCTET STRING }`.
/// `size` is the page size on the request and the estimated result-set
/// size on the response. `cookie` is opaque server state; an empty
/// cookie on the response signals "no more pages".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PagedResultValue {
    /// Page size (request) or estimated result-set size (response).
    /// 0 on the request means "abandon paged search".
    pub size: i32,
    /// Opaque server state. Empty cookie on a response means "no more
    /// pages".
    pub cookie: Vec<u8>,
}

impl PagedResultValue {
    /// Encode as a BER SEQUENCE suitable for use as a `controlValue`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        ber::encode_integer(self.size as i64, &mut body);
        ber::encode_tlv(TAG_OCTET_STRING, &self.cookie, &mut body);
        let mut out = Vec::new();
        ber::encode_tlv(TAG_SEQUENCE, &body, &mut out);
        out
    }

    /// Decode from BER bytes (the contents of a `controlValue`).
    pub fn decode(bytes: &[u8]) -> Result<Self, BerError> {
        let (seq_tlv, rest) = ber::decode_tlv(bytes)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        let (size_tlv, rest) = ber::decode_tlv(seq_tlv.value)?;
        if size_tlv.tag != TAG_INTEGER {
            return Err(BerError::UnexpectedTag {
                expected: TAG_INTEGER,
                actual: size_tlv.tag,
            });
        }
        let size = decode_integer_value(size_tlv.value)? as i32;
        let (cookie_tlv, rest) = ber::decode_tlv(rest)?;
        if cookie_tlv.tag != TAG_OCTET_STRING {
            return Err(BerError::UnexpectedTag {
                expected: TAG_OCTET_STRING,
                actual: cookie_tlv.tag,
            });
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(Self {
            size,
            cookie: cookie_tlv.value.to_vec(),
        })
    }

    /// Build a request `Control` for paged results with the given page
    /// size and (typically empty) cookie.
    pub fn request_control(page_size: i32, cookie: Vec<u8>, criticality: bool) -> Control {
        Control {
            control_type: LDAP_SERVER_PAGED_RESULT_OID.into(),
            criticality,
            control_value: Some(
                PagedResultValue {
                    size: page_size,
                    cookie,
                }
                .encode(),
            ),
        }
    }
}

/// A single sort key in a server-side sort request (RFC 2891 §1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortKey {
    /// Attribute description to sort by.
    pub attribute: String,
    /// If `true`, sort in reverse order.
    pub reverse: bool,
    /// Optional matching rule OID (e.g. `caseExactMatch`).
    pub ordering_rule: Option<String>,
}

/// A server-side sort request value (RFC 2891 §1.1).
///
/// Wire form: `SEQUENCE OF SEQUENCE { attributeDescription, reverseOrder
/// BOOLEAN DEFAULT FALSE, orderingRule [0] MatchingRuleId OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SortRequestValue {
    /// The list of sort keys (multiple = tie-breakers).
    pub keys: Vec<SortKey>,
}

/// Context-specific tag `[0]` for the optional `orderingRule` field of
/// a `SortKey` (RFC 2891 §1.1).
const SORT_ORDERING_RULE_TAG: u8 = crate::ber::CLASS_CONTEXT;

impl SortRequestValue {
    /// Encode as a BER SEQUENCE OF SEQUENCE suitable for use as a
    /// `controlValue`.
    pub fn encode(&self) -> Vec<u8> {
        let mut seq = Vec::new();
        for key in &self.keys {
            let mut key_body = Vec::new();
            ber::encode_string(&key.attribute, &mut key_body);
            // reverseOrder defaults to FALSE — only emit if TRUE.
            if key.reverse {
                ber::encode_bool(true, &mut key_body);
            }
            if let Some(rule) = &key.ordering_rule {
                ber::encode_tlv(SORT_ORDERING_RULE_TAG, rule.as_bytes(), &mut key_body);
            }
            ber::encode_tlv(TAG_SEQUENCE, &key_body, &mut seq);
        }
        let mut out = Vec::new();
        ber::encode_tlv(TAG_SEQUENCE, &seq, &mut out);
        out
    }

    /// Decode from BER bytes (the contents of a `controlValue`).
    pub fn decode(bytes: &[u8]) -> Result<Self, BerError> {
        let (seq_tlv, rest) = ber::decode_tlv(bytes)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        let mut keys = Vec::new();
        let mut rest = seq_tlv.value;
        while !rest.is_empty() {
            let (key_tlv, remaining) = ber::decode_tlv(rest)?;
            if key_tlv.tag != TAG_SEQUENCE {
                return Err(BerError::UnexpectedTag {
                    expected: TAG_SEQUENCE,
                    actual: key_tlv.tag,
                });
            }
            let (attr_tlv, krest) = ber::decode_tlv(key_tlv.value)?;
            let attribute = decode_string_value(attr_tlv.value)?;
            let mut reverse = false;
            let mut ordering_rule = None;
            let mut krest = krest;
            while !krest.is_empty() {
                let (next_tlv, r) = ber::decode_tlv(krest)?;
                match next_tlv.tag {
                    TAG_BOOLEAN => {
                        reverse = decode_bool_value(next_tlv.value)?;
                    }
                    SORT_ORDERING_RULE_TAG => {
                        ordering_rule = Some(decode_string_value(next_tlv.value)?);
                    }
                    _ => {
                        return Err(BerError::UnexpectedTag {
                            expected: TAG_BOOLEAN,
                            actual: next_tlv.tag,
                        });
                    }
                }
                krest = r;
            }
            keys.push(SortKey {
                attribute,
                reverse,
                ordering_rule,
            });
            rest = remaining;
        }
        Ok(Self { keys })
    }

    /// Build a request `Control` for server-side sorting.
    pub fn request_control(keys: Vec<SortKey>, criticality: bool) -> Control {
        Control {
            control_type: LDAP_SERVER_SORT_OID.into(),
            criticality,
            control_value: Some(Self { keys }.encode()),
        }
    }
}

/// Server-side sort result codes (RFC 2891 §1.2). Only the values
/// used by this implementation are listed; unknown codes round-trip via
/// the `Other` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SortResultCode {
    /// `success (0)` — sort succeeded.
    Success = 0,
    /// `operationsError (1)`.
    OperationsError = 1,
    /// `timeLimitExceeded (3)`.
    TimeLimitExceeded = 3,
    /// `strongAuthRequired (8)`.
    StrongAuthRequired = 8,
    /// `adminLimitExceeded (11)`.
    AdminLimitExceeded = 11,
    /// `noSuchAttribute (16)`.
    NoSuchAttribute = 16,
    /// `inappropriateMatching (18)`.
    InappropriateMatching = 18,
    /// `insufficientAccessRights (50)`.
    InsufficientAccessRights = 50,
    /// `busy (51)`.
    Busy = 51,
    /// `unwillingToPerform (53)`.
    UnwillingToPerform = 53,
    /// `other (80)`.
    Other = 80,
}

impl SortResultCode {
    /// Convert to the i32 wire value.
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// Convert from an i32 wire value. Unknown values map to `Other`.
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Success,
            1 => Self::OperationsError,
            3 => Self::TimeLimitExceeded,
            8 => Self::StrongAuthRequired,
            11 => Self::AdminLimitExceeded,
            16 => Self::NoSuchAttribute,
            18 => Self::InappropriateMatching,
            50 => Self::InsufficientAccessRights,
            51 => Self::Busy,
            53 => Self::UnwillingToPerform,
            80 => Self::Other,
            _ => Self::Other,
        }
    }
}

/// A server-side sort response value (RFC 2891 §1.2).
///
/// Wire form: `SEQUENCE { sortResult ENUMERATED, attributeType [0]
/// AttributeDescription OPTIONAL }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortResponseValue {
    /// The sort result code.
    pub sort_result: SortResultCode,
    /// If the sort failed because the attribute was unrecognized, the
    /// offending attribute type is named here.
    pub attribute_type: Option<String>,
}

impl SortResponseValue {
    /// Encode as a BER SEQUENCE suitable for use as a `controlValue`.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        ber::encode_enumerated(self.sort_result.as_i32() as i64, &mut body);
        if let Some(attr) = &self.attribute_type {
            ber::encode_tlv(SORT_ORDERING_RULE_TAG, attr.as_bytes(), &mut body);
        }
        let mut out = Vec::new();
        ber::encode_tlv(TAG_SEQUENCE, &body, &mut out);
        out
    }

    /// Decode from BER bytes (the contents of a `controlValue`).
    pub fn decode(bytes: &[u8]) -> Result<Self, BerError> {
        let (seq_tlv, rest) = ber::decode_tlv(bytes)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        let (res_tlv, rest) = ber::decode_tlv(seq_tlv.value)?;
        if res_tlv.tag != TAG_ENUMERATED {
            return Err(BerError::UnexpectedTag {
                expected: TAG_ENUMERATED,
                actual: res_tlv.tag,
            });
        }
        let sort_result = SortResultCode::from_i32(decode_integer_value(res_tlv.value)? as i32);
        let attribute_type = if rest.is_empty() {
            None
        } else {
            let (attr_tlv, rest) = ber::decode_tlv(rest)?;
            if attr_tlv.tag != SORT_ORDERING_RULE_TAG {
                return Err(BerError::UnexpectedTag {
                    expected: SORT_ORDERING_RULE_TAG,
                    actual: attr_tlv.tag,
                });
            }
            if !rest.is_empty() {
                return Err(BerError::TrailingData(rest.len()));
            }
            Some(decode_string_value(attr_tlv.value)?)
        };
        Ok(Self {
            sort_result,
            attribute_type,
        })
    }

    /// Build a response `Control` for server-side sorting. Response
    /// controls are never marked critical.
    pub fn response_control(
        sort_result: SortResultCode,
        attribute_type: Option<String>,
    ) -> Control {
        Control {
            control_type: LDAP_SERVER_SORT_RESPONSE_OID.into(),
            criticality: false,
            control_value: Some(
                Self {
                    sort_result,
                    attribute_type,
                }
                .encode(),
            ),
        }
    }
}

/// Bit flags for the SD flags control (`LDAP_SERVER_SD_FLAGS_OID` per
/// MS-ADTS §3.1.1.3.4.1). When a client requests
/// `nTSecurityDescriptor`, the server returns only the parts of the SD
/// selected by these flags — saving wire bandwidth when the client only
/// needs the DACL, for example.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SdFlags(pub i32);

impl SdFlags {
    /// `OWNER_SECURITY_INFORMATION (0x1)` — return the owner field.
    pub const OWNER: Self = Self(0x1);
    /// `GROUP_SECURITY_INFORMATION (0x2)` — return the primary group.
    pub const GROUP: Self = Self(0x2);
    /// `DACL_SECURITY_INFORMATION (0x4)` — return the DACL.
    pub const DACL: Self = Self(0x4);
    /// `SACL_SECURITY_INFORMATION (0x8)` — return the SACL (requires
    /// `SE_SECURITY_NAME` privilege).
    pub const SACL: Self = Self(0x8);

    /// Combine two flag sets with bitwise OR.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True if the OWNER bit is set.
    pub const fn wants_owner(self) -> bool {
        self.0 & Self::OWNER.0 != 0
    }

    /// True if the GROUP bit is set.
    pub const fn wants_group(self) -> bool {
        self.0 & Self::GROUP.0 != 0
    }

    /// True if the DACL bit is set.
    pub const fn wants_dacl(self) -> bool {
        self.0 & Self::DACL.0 != 0
    }

    /// True if the SACL bit is set.
    pub const fn wants_sacl(self) -> bool {
        self.0 & Self::SACL.0 != 0
    }

    /// Encode as a BER SEQUENCE wrapping a single INTEGER (the wire form
    /// per MS-ADTS).
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        ber::encode_integer(self.0 as i64, &mut body);
        let mut out = Vec::new();
        ber::encode_tlv(TAG_SEQUENCE, &body, &mut out);
        out
    }

    /// Decode from BER bytes (the contents of a `controlValue`).
    pub fn decode(bytes: &[u8]) -> Result<Self, BerError> {
        let (seq_tlv, rest) = ber::decode_tlv(bytes)?;
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        let (int_tlv, rest) = ber::decode_tlv(seq_tlv.value)?;
        if int_tlv.tag != TAG_INTEGER {
            return Err(BerError::UnexpectedTag {
                expected: TAG_INTEGER,
                actual: int_tlv.tag,
            });
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        Ok(Self(decode_integer_value(int_tlv.value)? as i32))
    }

    /// Build a request `Control` for SD flags.
    pub fn request_control(self, criticality: bool) -> Control {
        Control {
            control_type: LDAP_SERVER_SD_FLAGS_OID.into(),
            criticality,
            control_value: Some(self.encode()),
        }
    }
}

/// Format flag for the extended DN control (`LDAP_SERVER_EXTENDED_DN_OID`
/// per MS-ADTS §3.1.1.3.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtendedDnFormat {
    /// `0` — return the GUID/SID as a hex string. This is the default
    /// and the format AD uses for backward compatibility.
    #[default]
    HexString = 0,
    /// `1` — return the GUID/SID in the `<GUID=...>` string form.
    StringForm = 1,
}

/// Extended DN control value (MS-ADTS §3.1.1.3.4.2). The control value
/// is a single INTEGER (0 or 1) specifying the GUID/SID format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtendedDnValue {
    /// The requested format.
    pub format: ExtendedDnFormat,
}

impl ExtendedDnValue {
    /// Encode as a single BER INTEGER (the wire form per MS-ADTS).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ber::encode_integer(self.format as i64, &mut out);
        out
    }

    /// Decode from BER bytes (the contents of a `controlValue`).
    pub fn decode(bytes: &[u8]) -> Result<Self, BerError> {
        let (int_tlv, rest) = ber::decode_tlv(bytes)?;
        if int_tlv.tag != TAG_INTEGER {
            return Err(BerError::UnexpectedTag {
                expected: TAG_INTEGER,
                actual: int_tlv.tag,
            });
        }
        if !rest.is_empty() {
            return Err(BerError::TrailingData(rest.len()));
        }
        let v = decode_integer_value(int_tlv.value)?;
        let format = match v {
            0 => ExtendedDnFormat::HexString,
            1 => ExtendedDnFormat::StringForm,
            _ => {
                return Err(BerError::OutOfRange(format!(
                    "ExtendedDn format must be 0 or 1, got {}",
                    v
                )));
            }
        };
        Ok(Self { format })
    }

    /// Build a request `Control` for extended DN.
    pub fn request_control(format: ExtendedDnFormat, criticality: bool) -> Control {
        Control {
            control_type: LDAP_SERVER_EXTENDED_DN_OID.into(),
            criticality,
            control_value: Some(Self { format }.encode()),
        }
    }
}

/// The `protocolOp` CHOICE of an `LDAPMessage` (RFC 4511 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolOp {
    /// `[APPLICATION 0]` BindRequest.
    BindRequest(BindRequest),
    /// `[APPLICATION 1]` BindResponse.
    BindResponse(BindResponse),
    /// `[APPLICATION 2]` UnbindRequest (NULL).
    UnbindRequest(UnbindRequest),
    /// `[APPLICATION 3]` SearchRequest.
    SearchRequest(SearchRequest),
    /// `[APPLICATION 4]` SearchResultEntry.
    SearchResultEntry(SearchResultEntry),
    /// `[APPLICATION 5]` SearchResultDone.
    SearchResultDone(SearchResultDone),
    /// `[APPLICATION 6]` ModifyRequest.
    ModifyRequest(ModifyRequest),
    /// `[APPLICATION 7]` ModifyResponse.
    ModifyResponse(ModifyResponse),
    /// `[APPLICATION 8]` AddRequest.
    AddRequest(AddRequest),
    /// `[APPLICATION 9]` AddResponse.
    AddResponse(AddResponse),
    /// `[APPLICATION 10]` DelRequest (LDAPDN).
    DelRequest(DelRequest),
    /// `[APPLICATION 11]` DelResponse.
    DelResponse(DelResponse),
}

impl ProtocolOp {
    /// Encode the protocol op (with its `[APPLICATION N]` tag) into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ProtocolOp::BindRequest(r) => r.encode(out),
            ProtocolOp::BindResponse(r) => r.encode(out),
            ProtocolOp::UnbindRequest(r) => r.encode(out),
            ProtocolOp::SearchRequest(r) => r.encode(out),
            ProtocolOp::SearchResultEntry(r) => r.encode(out),
            ProtocolOp::SearchResultDone(r) => r.encode(out),
            ProtocolOp::ModifyRequest(r) => r.encode(out),
            ProtocolOp::ModifyResponse(r) => r.encode(out),
            ProtocolOp::AddRequest(r) => r.encode(out),
            ProtocolOp::AddResponse(r) => r.encode(out),
            ProtocolOp::DelRequest(r) => r.encode(out),
            ProtocolOp::DelResponse(r) => r.encode(out),
        }
    }

    /// Decode a protocol op from a TLV with the given tag and value.
    pub fn decode_from_tlv(tag: u8, value: &[u8]) -> Result<ProtocolOp, BerError> {
        match tag {
            APP_BIND_REQUEST => Ok(ProtocolOp::BindRequest(BindRequest::decode_from_value(
                value,
            )?)),
            APP_BIND_RESPONSE => Ok(ProtocolOp::BindResponse(BindResponse::decode_from_value(
                value,
            )?)),
            APP_UNBIND_REQUEST => Ok(ProtocolOp::UnbindRequest(UnbindRequest::decode_from_value(
                value,
            )?)),
            APP_SEARCH_REQUEST => Ok(ProtocolOp::SearchRequest(SearchRequest::decode_from_value(
                value,
            )?)),
            APP_SEARCH_RESULT_ENTRY => Ok(ProtocolOp::SearchResultEntry(
                SearchResultEntry::decode_from_value(value)?,
            )),
            APP_SEARCH_RESULT_DONE => Ok(ProtocolOp::SearchResultDone(
                SearchResultDone::decode_from_value(value)?,
            )),
            APP_MODIFY_REQUEST => Ok(ProtocolOp::ModifyRequest(ModifyRequest::decode_from_value(
                value,
            )?)),
            APP_MODIFY_RESPONSE => Ok(ProtocolOp::ModifyResponse(
                ModifyResponse::decode_from_value(value)?,
            )),
            APP_ADD_REQUEST => Ok(ProtocolOp::AddRequest(AddRequest::decode_from_value(
                value,
            )?)),
            APP_ADD_RESPONSE => Ok(ProtocolOp::AddResponse(AddResponse::decode_from_value(
                value,
            )?)),
            APP_DEL_REQUEST => Ok(ProtocolOp::DelRequest(DelRequest::decode_from_value(
                value,
            )?)),
            APP_DEL_RESPONSE => Ok(ProtocolOp::DelResponse(DelResponse::decode_from_value(
                value,
            )?)),
            t => Err(BerError::UnknownProtocolOp(t)),
        }
    }
}

/// An LDAP message (RFC 4511 §4.1.1) — the top-level PDU exchanged
/// between client and server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapMessage {
    /// The message ID (positive integer, client-assigned).
    pub message_id: MessageId,
    /// The protocol operation.
    pub protocol_op: ProtocolOp,
    /// Optional controls (`[0] Controls`).
    pub controls: Vec<Control>,
}

impl LdapMessage {
    /// Encode as a SEQUENCE (the LDAPMessage top-level wrapper).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut body = Vec::new();
        ber::encode_integer(self.message_id as i64, &mut body);
        self.protocol_op.encode(&mut body);
        if !self.controls.is_empty() {
            let mut controls_body = Vec::new();
            for c in &self.controls {
                c.encode(&mut controls_body);
            }
            ber::encode_tlv(CONTROLS_TAG, &controls_body, &mut body);
        }
        ber::encode_tlv(TAG_SEQUENCE, &body, &mut out);
        out
    }

    /// Decode a single LdapMessage from `bytes`. Returns the parsed
    /// message and the number of bytes consumed.
    pub fn decode(bytes: &[u8]) -> Result<LdapMessage, BerError> {
        let (msg_tlv, _rest) = ber::decode_tlv(bytes)?;
        if msg_tlv.tag != TAG_SEQUENCE {
            return Err(BerError::UnexpectedTag {
                expected: TAG_SEQUENCE,
                actual: msg_tlv.tag,
            });
        }
        let (id_tlv, rest) = ber::decode_tlv(msg_tlv.value)?;
        if id_tlv.tag != crate::ber::TAG_INTEGER {
            return Err(BerError::UnexpectedTag {
                expected: crate::ber::TAG_INTEGER,
                actual: id_tlv.tag,
            });
        }
        let message_id = decode_integer_value(id_tlv.value)? as MessageId;
        let (op_tlv, rest) = ber::decode_tlv(rest)?;
        let protocol_op = ProtocolOp::decode_from_tlv(op_tlv.tag, op_tlv.value)?;
        let controls = if rest.is_empty() {
            Vec::new()
        } else {
            let (ctrl_tlv, rest) = ber::decode_tlv(rest)?;
            if ctrl_tlv.tag != CONTROLS_TAG {
                return Err(BerError::UnexpectedTag {
                    expected: CONTROLS_TAG,
                    actual: ctrl_tlv.tag,
                });
            }
            let mut controls = Vec::new();
            let mut c_rest = ctrl_tlv.value;
            while !c_rest.is_empty() {
                let (c_tlv, c_remaining) = ber::decode_tlv(c_rest)?;
                if c_tlv.tag != TAG_SEQUENCE {
                    return Err(BerError::UnexpectedTag {
                        expected: TAG_SEQUENCE,
                        actual: c_tlv.tag,
                    });
                }
                controls.push(Control::decode_from_value(c_tlv.value)?);
                c_rest = c_remaining;
            }
            if !rest.is_empty() {
                return Err(BerError::TrailingData(rest.len()));
            }
            controls
        };
        Ok(LdapMessage {
            message_id,
            protocol_op,
            controls,
        })
    }
}

// (No trailing private imports — every imported item is used above.)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;

    fn round_trip<T>(
        orig: T,
        encode: fn(&T, &mut Vec<u8>),
        decode_tag: u8,
        decode: fn(&[u8]) -> Result<T, BerError>,
    ) -> T
    where
        T: std::fmt::Debug + PartialEq,
    {
        let mut out = Vec::new();
        encode(&orig, &mut out);
        let (tlv, rest) = ber::decode_tlv(&out).unwrap();
        assert!(rest.is_empty(), "trailing bytes after TLV");
        assert_eq!(tlv.tag, decode_tag, "wrong application tag");
        decode(tlv.value).unwrap()
    }

    #[test]
    fn result_code_round_trip() {
        for &code in &[
            ResultCode::Success,
            ResultCode::OperationsError,
            ResultCode::InvalidCredentials,
            ResultCode::NoSuchObject,
            ResultCode::Other,
        ] {
            let mut out = Vec::new();
            code.encode(&mut out);
            let (tlv, _) = ber::decode_tlv(&out).unwrap();
            assert_eq!(tlv.tag, TAG_ENUMERATED);
            assert_eq!(ResultCode::decode_from_value(tlv.value).unwrap(), code);
        }
    }

    #[test]
    fn ldap_result_round_trip() {
        let orig = LdapResult {
            result_code: ResultCode::InvalidCredentials,
            matched_dn: "CN=alice".into(),
            diagnostic_message: "bad password".into(),
        };
        let mut out = Vec::new();
        orig.encode_components(&mut out);
        let (decoded, rest) = LdapResult::decode_components(&out).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, orig);
    }

    #[test]
    fn search_request_round_trip() {
        let orig = SearchRequest {
            base_dn: "DC=adrian,DC=example,DC=com".into(),
            scope: 2,
            deref_aliases: 0,
            size_limit: 1000,
            time_limit: 30,
            filter: Filter::and(vec![
                Filter::equality("objectClass", "user"),
                Filter::equality("cn", "alice"),
            ]),
            attributes: vec!["cn".into(), "memberOf".into()],
            types_only: false,
        };
        let decoded = round_trip(
            orig.clone(),
            SearchRequest::encode,
            APP_SEARCH_REQUEST,
            SearchRequest::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn search_result_entry_round_trip() {
        let orig = SearchResultEntry {
            dn: "CN=alice,DC=adrian,DC=example,DC=com".into(),
            attributes: vec![
                ("cn".into(), vec![b"alice".to_vec()]),
                (
                    "objectClass".into(),
                    vec![b"user".to_vec(), b"person".to_vec()],
                ),
                ("memberOf".into(), vec![b"CN=Admins,DC=adrian".to_vec()]),
            ],
        };
        let decoded = round_trip(
            orig.clone(),
            SearchResultEntry::encode,
            APP_SEARCH_RESULT_ENTRY,
            SearchResultEntry::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn search_result_done_round_trip() {
        let orig = SearchResultDone {
            result: LdapResult {
                result_code: ResultCode::Success,
                matched_dn: "".into(),
                diagnostic_message: "".into(),
            },
        };
        let decoded = round_trip(
            orig.clone(),
            SearchResultDone::encode,
            APP_SEARCH_RESULT_DONE,
            SearchResultDone::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn bind_request_anonymous_round_trip() {
        let orig = BindRequest {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Simple(Vec::new()),
        };
        let decoded = round_trip(
            orig.clone(),
            BindRequest::encode,
            APP_BIND_REQUEST,
            BindRequest::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn bind_request_simple_round_trip() {
        let orig = BindRequest {
            version: 3,
            name: "CN=alice,DC=adrian,DC=example,DC=com".into(),
            authentication: AuthenticationChoice::Simple(b"s3cret".to_vec()),
        };
        let decoded = round_trip(
            orig.clone(),
            BindRequest::encode,
            APP_BIND_REQUEST,
            BindRequest::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn bind_response_success_round_trip() {
        let orig = BindResponse::success();
        let decoded = round_trip(
            orig.clone(),
            BindResponse::encode,
            APP_BIND_RESPONSE,
            BindResponse::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn bind_response_error_round_trip() {
        let orig = BindResponse::error(
            ResultCode::InvalidCredentials,
            "invalid DN/password combination",
        );
        let decoded = round_trip(
            orig.clone(),
            BindResponse::encode,
            APP_BIND_RESPONSE,
            BindResponse::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn unbind_request_round_trip() {
        let orig = UnbindRequest;
        let mut out = Vec::new();
        orig.encode(&mut out);
        let (tlv, _) = ber::decode_tlv(&out).unwrap();
        assert_eq!(tlv.tag, APP_UNBIND_REQUEST);
        let decoded = UnbindRequest::decode_from_value(tlv.value).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn modify_request_round_trip() {
        let orig = ModifyRequest {
            object: "CN=alice,DC=adrian,DC=example,DC=com".into(),
            changes: vec![Change {
                operation: ModificationOp::Replace,
                modification: ("displayName".into(), vec![b"Alice Liddell".to_vec()]),
            }],
        };
        let decoded = round_trip(
            orig.clone(),
            ModifyRequest::encode,
            APP_MODIFY_REQUEST,
            ModifyRequest::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn modify_response_round_trip() {
        let orig = ModifyResponse::success();
        let decoded = round_trip(
            orig.clone(),
            ModifyResponse::encode,
            APP_MODIFY_RESPONSE,
            ModifyResponse::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn add_request_round_trip() {
        let orig = AddRequest {
            entry: "CN=bob,DC=adrian,DC=example,DC=com".into(),
            attributes: vec![
                ("cn".into(), vec![b"bob".to_vec()]),
                ("objectClass".into(), vec![b"user".to_vec()]),
            ],
        };
        let decoded = round_trip(
            orig.clone(),
            AddRequest::encode,
            APP_ADD_REQUEST,
            AddRequest::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn add_response_round_trip() {
        let orig = AddResponse::success();
        let decoded = round_trip(
            orig.clone(),
            AddResponse::encode,
            APP_ADD_RESPONSE,
            AddResponse::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn del_request_round_trip() {
        let orig = DelRequest::new("CN=bob,DC=adrian,DC=example,DC=com");
        let mut out = Vec::new();
        orig.encode(&mut out);
        let (tlv, _) = ber::decode_tlv(&out).unwrap();
        assert_eq!(tlv.tag, APP_DEL_REQUEST);
        let decoded = DelRequest::decode_from_value(tlv.value).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn del_response_round_trip() {
        let orig = DelResponse::success();
        let decoded = round_trip(
            orig.clone(),
            DelResponse::encode,
            APP_DEL_RESPONSE,
            DelResponse::decode_from_value,
        );
        assert_eq!(decoded, orig);
    }

    #[test]
    fn ldap_message_round_trip_bind() {
        let orig = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                authentication: AuthenticationChoice::Simple(Vec::new()),
            }),
            controls: Vec::new(),
        };
        let bytes = orig.encode();
        let decoded = LdapMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn ldap_message_round_trip_search() {
        let orig = LdapMessage {
            message_id: 42,
            protocol_op: ProtocolOp::SearchRequest(SearchRequest {
                base_dn: "DC=adrian,DC=example,DC=com".into(),
                scope: 2,
                deref_aliases: 0,
                size_limit: 0,
                time_limit: 0,
                filter: Filter::present("objectClass"),
                attributes: Vec::new(),
                types_only: false,
            }),
            controls: Vec::new(),
        };
        let bytes = orig.encode();
        let decoded = LdapMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn ldap_message_round_trip_with_controls() {
        let orig = LdapMessage {
            message_id: 7,
            protocol_op: ProtocolOp::SearchRequest(SearchRequest {
                base_dn: "".into(),
                scope: 0,
                deref_aliases: 0,
                size_limit: 0,
                time_limit: 0,
                filter: Filter::present("objectClass"),
                attributes: Vec::new(),
                types_only: false,
            }),
            controls: vec![Control {
                control_type: "1.2.840.113556.1.4.319".into(), // paged results
                criticality: true,
                control_value: Some(vec![0x04, 0x02, 0x00, 0x00]),
            }],
        };
        let bytes = orig.encode();
        let decoded = LdapMessage::decode(&bytes).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn control_decode_without_criticality() {
        // A control with only OID + control_value (no criticality) —
        // criticality defaults to FALSE per RFC 4511 §4.1.11.
        let mut body = Vec::new();
        ber::encode_string("1.2.3.4", &mut body);
        ber::encode_tlv(TAG_OCTET_STRING, &[0xAA, 0xBB], &mut body);
        let mut out = Vec::new();
        ber::encode_tlv(TAG_SEQUENCE, &body, &mut out);
        let (tlv, _) = ber::decode_tlv(&out).unwrap();
        let decoded = Control::decode_from_value(tlv.value).unwrap();
        assert_eq!(decoded.control_type, "1.2.3.4");
        assert_eq!(decoded.criticality, false);
        assert_eq!(decoded.control_value, Some(vec![0xAA, 0xBB]));
    }

    // ---- AD-interop control tests (ADR-006) ----

    #[test]
    fn paged_results_request_round_trip() {
        // A client sends a paged-results request asking for a 500-entry
        // page with an empty cookie (initial page).
        let ctrl = PagedResultValue::request_control(500, Vec::new(), true);
        assert_eq!(ctrl.control_type, LDAP_SERVER_PAGED_RESULT_OID);
        assert!(ctrl.criticality);
        let value = ctrl.control_value.expect("control_value must be present");
        let decoded = PagedResultValue::decode(&value).unwrap();
        assert_eq!(decoded.size, 500);
        assert!(decoded.cookie.is_empty());
    }

    #[test]
    fn paged_results_response_round_trip() {
        // The server responds with the next cookie to use for the
        // subsequent page; an empty cookie signals "no more pages".
        let resp = PagedResultValue {
            size: 0,
            cookie: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = resp.encode();
        let decoded = PagedResultValue::decode(&bytes).unwrap();
        assert_eq!(decoded, resp);
        // And the terminal-response case: empty cookie.
        let terminal = PagedResultValue {
            size: 0,
            cookie: Vec::new(),
        };
        let bytes = terminal.encode();
        let decoded = PagedResultValue::decode(&bytes).unwrap();
        assert_eq!(decoded, terminal);
    }

    #[test]
    fn sort_request_round_trip() {
        // Client requests sorting by `sn` ascending, then `cn` descending
        // as a tie-breaker.
        let keys = vec![
            SortKey {
                attribute: "sn".into(),
                reverse: false,
                ordering_rule: None,
            },
            SortKey {
                attribute: "cn".into(),
                reverse: true,
                ordering_rule: Some("caseExactMatch".into()),
            },
        ];
        let ctrl = SortRequestValue::request_control(keys.clone(), false);
        assert_eq!(ctrl.control_type, LDAP_SERVER_SORT_OID);
        assert!(!ctrl.criticality);
        let value = ctrl.control_value.expect("control_value must be present");
        let decoded = SortRequestValue::decode(&value).unwrap();
        assert_eq!(decoded.keys, keys);
    }

    #[test]
    fn sort_response_round_trip() {
        // The server reports sort success.
        let ctrl = SortResponseValue::response_control(SortResultCode::Success, None);
        assert_eq!(ctrl.control_type, LDAP_SERVER_SORT_RESPONSE_OID);
        assert!(!ctrl.criticality);
        let value = ctrl.control_value.expect("control_value must be present");
        let decoded = SortResponseValue::decode(&value).unwrap();
        assert_eq!(decoded.sort_result, SortResultCode::Success);
        assert!(decoded.attribute_type.is_none());
        // And the failure case: name the offending attribute.
        let ctrl = SortResponseValue::response_control(
            SortResultCode::NoSuchAttribute,
            Some("nonexistent".into()),
        );
        let value = ctrl.control_value.expect("control_value must be present");
        let decoded = SortResponseValue::decode(&value).unwrap();
        assert_eq!(decoded.sort_result, SortResultCode::NoSuchAttribute);
        assert_eq!(decoded.attribute_type.as_deref(), Some("nonexistent"));
    }

    #[test]
    fn sd_flags_request_round_trip() {
        // Client requests OWNER | GROUP | DACL (0x7) — typical for an
        // ACL-editing tool that doesn't need the SACL.
        let flags = SdFlags::OWNER.union(SdFlags::GROUP).union(SdFlags::DACL);
        assert_eq!(flags.0, 0x7);
        assert!(flags.wants_owner());
        assert!(flags.wants_group());
        assert!(flags.wants_dacl());
        assert!(!flags.wants_sacl());
        let ctrl = flags.request_control(true);
        assert_eq!(ctrl.control_type, LDAP_SERVER_SD_FLAGS_OID);
        assert!(ctrl.criticality);
        let value = ctrl.control_value.expect("control_value must be present");
        let decoded = SdFlags::decode(&value).unwrap();
        assert_eq!(decoded, flags);
    }

    #[test]
    fn sd_flags_decode_rejects_non_integer() {
        // If a malformed client sends a control_value that isn't a
        // SEQUENCE{INTEGER}, decode should fail loudly.
        let bogus = vec![0x04, 0x01, 0x42]; // OCTET STRING, not SEQUENCE
        assert!(SdFlags::decode(&bogus).is_err());
    }

    #[test]
    fn extended_dn_request_round_trip() {
        // Client requests hex-string format (0) — the default AD format.
        let ctrl = ExtendedDnValue::request_control(ExtendedDnFormat::HexString, false);
        assert_eq!(ctrl.control_type, LDAP_SERVER_EXTENDED_DN_OID);
        assert!(!ctrl.criticality);
        let value = ctrl.control_value.expect("control_value must be present");
        let decoded = ExtendedDnValue::decode(&value).unwrap();
        assert_eq!(decoded.format, ExtendedDnFormat::HexString);
        // And the string-form (1) variant.
        let ctrl = ExtendedDnValue::request_control(ExtendedDnFormat::StringForm, true);
        let value = ctrl.control_value.expect("control_value must be present");
        let decoded = ExtendedDnValue::decode(&value).unwrap();
        assert_eq!(decoded.format, ExtendedDnFormat::StringForm);
    }

    #[test]
    fn extended_dn_decode_rejects_invalid_format() {
        // Only 0 and 1 are valid format integers per MS-ADTS.
        // Encode the integer 2 manually.
        let mut bytes = Vec::new();
        ber::encode_integer(2, &mut bytes);
        let err = ExtendedDnValue::decode(&bytes).unwrap_err();
        assert!(
            matches!(err, BerError::OutOfRange(_)),
            "expected OutOfRange, got {:?}",
            err
        );
    }
}
