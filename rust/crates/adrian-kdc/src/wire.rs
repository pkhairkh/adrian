#![forbid(unsafe_code)]
//! # adrian-kdc :: wire — ASN.1/DER encoding via rasn-kerberos (v0.7.0)
//!
//! Replaces the v0.6.0 simplified binary format (magic bytes + length-prefixed
//! fields) with real RFC 4120 ASN.1/DER encoding using the `rasn-kerberos`
//! crate. This makes the KDC wire-compatible with MIT krb5 / Windows / Heimdal.
//!
//! ## Design
//!
//! The handler logic uses simplified Rust structs (`AsReq`, `AsRep`, `Ticket`,
//! etc.) defined in [`crate::handlers`]. This module provides `encode_*` /
//! `decode_*` functions that:
//!
//! 1. Convert our simplified structs → `rasn_kerberos` types
//! 2. Use `rasn::der::encode` / `rasn::der::decode` for DER serialization
//! 3. Convert `rasn_kerberos` types → our simplified structs on decode
//!
//! ## Field mapping notes
//!
//! - **`EncTicketPart.client_uuid`** (Adrian-specific, not in RFC 4120): stored
//!   in `authorization_data` as a single entry with `type = -128` (reserved for
//!   local use per RFC 4120 §5.2.6) and `data = 16 UUID bytes`.
//! - **`flags` (u32)**: mapped to `TicketFlags(BitString)` via big-endian bytes.
//! - **`last_req` (i64)**: mapped to a single `LastReqValue { type: 0, value }`.
//! - **`EncKdcRepPart.srealm` / `sname`**: not in our struct; we set them to
//!   the same value as `crealm` / `cname` (the KDC always echoes the client's
//!   identity, and the service realm/name is carried in the Ticket).
//! - **TGS-REQ**: the TGT + encrypted authenticator are wrapped in an `ApReq`
//!   inside `PA-TGS-REQ` padata (type 1), per RFC 4120 §3.3.

use bytes::Bytes;
use chrono::{DateTime, FixedOffset, Utc};
use rasn::der;
use rasn::types::{GeneralString, Integer, OctetString, SequenceOf};
// Note: KerberosTime.0 is pub (DateTime<FixedOffset>); GeneralString inner is
// private — use `.as_bytes()` to access it.
use rasn_kerberos as rk;
use uuid::Uuid;

use crate::handlers::{
    AsRep, AsReq, Authenticator, EncKdcRepPart, EncTicketPart, PaData, PaEncTsEnc, Ticket, TgsRep,
    TgsReq, DecodeError, PVNO,
};
use crate::EType;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PA-TGS-REQ padata type (RFC 4120 §5.2.7.1).
const PA_TGS_REQ_TYPE: i32 = 1;

/// AP-REQ message type (RFC 4120 §5.5.1).
const MSG_TYPE_AP_REQ: i32 = 14;

/// Authenticator version number (RFC 4120 §5.5.1).
const AUTHENTICATOR_VNO: i32 = 5;

/// AuthorizationData type for Adrian client_uuid (reserved for local use).
/// RFC 4120 §5.2.6: "Negative values ... are reserved for local use."
const AD_CLIENT_UUID_TYPE: i32 = -128;

/// NT-PRINCIPAL name type (RFC 4120 §6.2).
const NT_PRINCIPAL: i32 = 1;

/// AES-256 encryption type constant (for EncryptionKey.keytype when encoding
/// session keys, per ADR-011).
const ENCRYPTION_TYPE_AES256: i32 = 18;

// ---------------------------------------------------------------------------
// Helper conversions
// ---------------------------------------------------------------------------

/// Convert a UNIX timestamp (seconds) to a `KerberosTime` (GeneralizedTime).
fn to_krb_time(secs: i64) -> rk::KerberosTime {
    let dt: DateTime<Utc> = DateTime::from_timestamp(secs, 0)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
    let fixed: DateTime<FixedOffset> = dt.fixed_offset();
    rk::KerberosTime(fixed)
}

/// Convert a `KerberosTime` back to a UNIX timestamp (seconds).
fn from_krb_time(t: &rk::KerberosTime) -> i64 {
    t.0.timestamp()
}

/// Convert a `Vec<String>` to a `rasn_kerberos::PrincipalName`.
fn to_principal_name(components: &[String]) -> rk::PrincipalName {
    rk::PrincipalName {
        r#type: NT_PRINCIPAL,
        string: components
            .iter()
            .map(|s| GeneralString::try_from(s.as_bytes()))
            .collect::<Result<_, _>>()
            .unwrap_or_default(),
    }
}

/// Convert a `rasn_kerberos::PrincipalName` back to `Vec<String>`.
fn from_principal_name(pn: &rk::PrincipalName) -> Vec<String> {
    pn.string
        .iter()
        .map(|gs| String::from_utf8_lossy(gs.as_bytes()).into_owned())
        .collect()
}

/// Convert a `u32` to a `TicketFlags(BitString)` via big-endian bytes.
fn to_ticket_flags(flags: u32) -> rk::TicketFlags {
    rk::TicketFlags(rk::KerberosFlags::from_vec(flags.to_be_bytes().to_vec()))
}

/// Convert a `TicketFlags(BitString)` back to `u32`.
fn from_ticket_flags(tf: &rk::TicketFlags) -> u32 {
    let bytes: Vec<u8> = tf.0.clone().into_vec();
    let mut arr = [0u8; 4];
    let len = bytes.len().min(4);
    arr[4 - len..].copy_from_slice(&bytes[..len]);
    u32::from_be_bytes(arr)
}

/// Convert an `EType` to an `Integer`.
// (etype_to_int / int_to_etype removed — fields that need i32 use `as i32`
// directly; fields that need Integer use Integer::from(...).)

/// Convert a `Vec<u8>` to an `OctetString` (bytes::Bytes).
fn to_octet_string(v: &[u8]) -> OctetString {
    Bytes::from(v.to_vec())
}

/// Convert an `EType` + `kvno` + `cipher` to `EncryptedData`.
fn to_encrypted_data(etype: EType, kvno: u32, cipher: &[u8]) -> rk::EncryptedData {
    rk::EncryptedData {
        etype: etype as i32,
        kvno: Some(kvno),
        cipher: to_octet_string(cipher),
    }
}

/// Extract `(etype, kvno, cipher)` from `EncryptedData`.
fn from_encrypted_data(ed: &rk::EncryptedData) -> Result<(EType, u32, Vec<u8>), DecodeError> {
    let etype = EType::from_u32(ed.etype as u32)
        .ok_or_else(|| DecodeError::UnknownEtype(ed.etype as u32))?;
    let kvno = ed.kvno.unwrap_or(0);
    let cipher = ed.cipher.to_vec();
    Ok((etype, kvno, cipher))
}

/// Convert a session key (`[u8; 32]`) to `EncryptionKey`.
fn to_encryption_key(key: &[u8; 32]) -> rk::EncryptionKey {
    rk::EncryptionKey {
        r#type: ENCRYPTION_TYPE_AES256,
        value: to_octet_string(key),
    }
}

/// Extract a session key from `EncryptionKey`.
fn from_encryption_key(ek: &rk::EncryptionKey) -> Result<[u8; 32], DecodeError> {
    let bytes = ek.value.to_vec();
    if bytes.len() != 32 {
        return Err(DecodeError::UnexpectedEof);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Convert our `PaData` to `rasn_kerberos::PaData`.
fn to_rk_pa_data(p: &PaData) -> rk::PaData {
    rk::PaData {
        r#type: p.padata_type as i32,
        value: to_octet_string(&p.padata_value),
    }
}

/// Convert `rasn_kerberos::PaData` to our `PaData`.
fn from_rk_pa_data(p: &rk::PaData) -> PaData {
    PaData {
        padata_type: p.r#type as u8,
        padata_value: p.value.to_vec(),
    }
}

/// Encode a `Uuid` into an `AuthorizationData` (single entry, type -128).
fn uuid_to_auth_data(uuid: &Uuid) -> Option<rk::AuthorizationData> {
    Some(vec![rk::AuthorizationDataValue {
        r#type: AD_CLIENT_UUID_TYPE,
        data: to_octet_string(uuid.as_bytes()),
    }])
}

/// Extract a `Uuid` from `AuthorizationData` (looks for type -128 entry).
fn uuid_from_auth_data(ad: &Option<rk::AuthorizationData>) -> Result<Uuid, DecodeError> {
    if let Some(entries) = ad {
        for entry in entries {
            if entry.r#type == AD_CLIENT_UUID_TYPE {
                let bytes = entry.data.to_vec();
                if bytes.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&bytes);
                    return Ok(Uuid::from_bytes(arr));
                }
            }
        }
    }
    // Fallback: if no UUID entry found, return nil UUID (shouldn't happen for
    // self-encoded messages).
    Ok(Uuid::nil())
}

// ---------------------------------------------------------------------------
// PaEncTsEnc
// ---------------------------------------------------------------------------

pub fn encode_pa_enc_ts_enc(p: &PaEncTsEnc) -> Vec<u8> {
    let rk_ts = rk::PaEncTsEnc {
        patimestamp: rk::KerberosTime::from(to_krb_time(p.patimestamp)),
        pausec: if p.pausec > 0 {
            Some(Integer::from(p.pausec as i64))
        } else {
            None
        },
    };
    der::encode(&rk_ts).unwrap_or_default()
}

pub fn decode_pa_enc_ts_enc(b: &[u8]) -> Result<PaEncTsEnc, DecodeError> {
    let rk_ts: rk::PaEncTsEnc = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    Ok(PaEncTsEnc {
        patimestamp: from_krb_time(&rk_ts.patimestamp),
        pausec: rk_ts.pausec.as_ref().map(|i| match i {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => 0,
        }).unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// EncTicketPart
// ---------------------------------------------------------------------------

pub fn encode_enc_ticket_part(e: &EncTicketPart) -> Vec<u8> {
    let rk_e = rk::EncTicketPart {
        flags: to_ticket_flags(e.flags),
        key: to_encryption_key(&e.session_key),
        crealm: GeneralString::try_from(e.crealm.as_bytes()).unwrap_or_default(),
        cname: to_principal_name(&e.cname),
        transited: rk::TransitedEncoding {
            r#type: 0_i32,
            contents: to_octet_string(&[]),
        },
        auth_time: to_krb_time(e.authtime),
        start_time: Some(to_krb_time(e.starttime)),
        end_time: to_krb_time(e.endtime),
        renew_till: Some(to_krb_time(e.renew_till)),
        caddr: None,
        authorization_data: uuid_to_auth_data(&e.client_uuid),
    };
    der::encode(&rk_e).unwrap_or_default()
}

pub fn decode_enc_ticket_part(b: &[u8]) -> Result<EncTicketPart, DecodeError> {
    let rk_e: rk::EncTicketPart = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    Ok(EncTicketPart {
        flags: from_ticket_flags(&rk_e.flags),
        crealm: String::from_utf8_lossy(&rk_e.crealm.as_bytes()).into_owned(),
        cname: from_principal_name(&rk_e.cname),
        session_key: from_encryption_key(&rk_e.key)?,
        authtime: from_krb_time(&rk_e.auth_time),
        starttime: rk_e.start_time.as_ref().map(from_krb_time).unwrap_or(0),
        endtime: from_krb_time(&rk_e.end_time),
        renew_till: rk_e.renew_till.as_ref().map(from_krb_time).unwrap_or(0),
        client_uuid: uuid_from_auth_data(&rk_e.authorization_data)?,
    })
}

// ---------------------------------------------------------------------------
// Ticket
// ---------------------------------------------------------------------------

pub fn encode_ticket(t: &Ticket) -> Vec<u8> {
    let rk_t = rk::Ticket {
        tkt_vno: Integer::from(t.tkt_vno as i64),
        realm: GeneralString::try_from(t.realm.as_bytes()).unwrap_or_default(),
        sname: to_principal_name(&t.sname),
        enc_part: to_encrypted_data(t.etype, t.kvno, &t.enc_part),
    };
    der::encode(&rk_t).unwrap_or_default()
}

pub fn decode_ticket(b: &[u8]) -> Result<Ticket, DecodeError> {
    let rk_t: rk::Ticket = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    let (etype, kvno, enc_part) = from_encrypted_data(&rk_t.enc_part)?;
    Ok(Ticket {
        tkt_vno: match &rk_t.tkt_vno {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => PVNO,
        },
        realm: String::from_utf8_lossy(&rk_t.realm.as_bytes()).into_owned(),
        sname: from_principal_name(&rk_t.sname),
        kvno,
        etype,
        enc_part,
    })
}

// ---------------------------------------------------------------------------
// EncKdcRepPart
// ---------------------------------------------------------------------------

pub fn encode_enc_kdc_rep_part(e: &EncKdcRepPart) -> Vec<u8> {
    let rk_e = rk::EncKdcRepPart {
        key: to_encryption_key(&e.session_key),
        last_req: vec![rk::LastReqValue {
            r#type: 0,
            value: to_krb_time(e.last_req),
        }],
        nonce: e.nonce,
        key_expiration: None,
        flags: to_ticket_flags(0),
        auth_time: to_krb_time(e.authtime),
        start_time: Some(to_krb_time(e.starttime)),
        end_time: to_krb_time(e.endtime),
        renew_till: Some(to_krb_time(e.renew_till)),
        srealm: GeneralString::try_from(e.crealm.as_bytes()).unwrap_or_default(),
        sname: to_principal_name(&e.cname),
        caddr: None,
        encrypted_pa_data: None,
    };
    der::encode(&rk_e).unwrap_or_default()
}

pub fn decode_enc_kdc_rep_part(b: &[u8]) -> Result<EncKdcRepPart, DecodeError> {
    let rk_e: rk::EncKdcRepPart = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    let last_req = rk_e
        .last_req
        .first()
        .map(|lr| from_krb_time(&lr.value))
        .unwrap_or(0);
    Ok(EncKdcRepPart {
        session_key: from_encryption_key(&rk_e.key)?,
        last_req,
        nonce: rk_e.nonce,
        authtime: from_krb_time(&rk_e.auth_time),
        starttime: rk_e.start_time.as_ref().map(from_krb_time).unwrap_or(0),
        endtime: from_krb_time(&rk_e.end_time),
        renew_till: rk_e.renew_till.as_ref().map(from_krb_time).unwrap_or(0),
        crealm: String::from_utf8_lossy(&rk_e.srealm.as_bytes()).into_owned(),
        cname: from_principal_name(&rk_e.sname),
    })
}

// ---------------------------------------------------------------------------
// AsReq
// ---------------------------------------------------------------------------

pub fn encode_as_req(r: &AsReq) -> Vec<u8> {
    let padata: SequenceOf<rk::PaData> = r.padata.iter().map(to_rk_pa_data).collect();
    let etypes: SequenceOf<i32> = r.etypes.iter().map(|e| *e as i32).collect();
    let rk_req = rk::AsReq(rk::KdcReq {
        pvno: Integer::from(r.pvno as i64),
        msg_type: Integer::from(r.msg_type as i64),
        padata: Some(padata),
        req_body: rk::KdcReqBody {
            kdc_options: rk::KdcOptions::reserved(),
            cname: Some(to_principal_name(&r.cname)),
            realm: GeneralString::try_from(r.realm.as_bytes()).unwrap_or_default(),
            sname: None,
            from: None,
            till: to_krb_time(r.till),
            rtime: None,
            nonce: r.nonce,
            etype: etypes,
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    der::encode(&rk_req).unwrap_or_default()
}

pub fn decode_as_req(b: &[u8]) -> Result<AsReq, DecodeError> {
    let rk_req: rk::AsReq = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    let inner = rk_req.0;
    let padata: Vec<PaData> = inner
        .padata
        .unwrap_or_default()
        .iter()
        .map(from_rk_pa_data)
        .collect();
    let etypes: Vec<EType> = inner
        .req_body
        .etype
        .iter()
        .filter_map(|i| EType::from_u32(*i as u32))
        .collect();
    let cname = inner
        .req_body
        .cname
        .as_ref()
        .map(|c| from_principal_name(c))
        .unwrap_or_default();
    Ok(AsReq {
        pvno: match &inner.pvno {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => PVNO,
        },
        msg_type: match &inner.msg_type {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => 10,
        },
        realm: String::from_utf8_lossy(&inner.req_body.realm.as_bytes()).into_owned(),
        cname,
        nonce: inner.req_body.nonce,
        etypes,
        padata,
        till: from_krb_time(&inner.req_body.till),
    })
}

// ---------------------------------------------------------------------------
// AsRep
// ---------------------------------------------------------------------------

pub fn encode_as_rep(r: &AsRep) -> Vec<u8> {
    let rk_rep = rk::AsRep(rk::KdcRep {
        pvno: Integer::from(r.pvno as i64),
        msg_type: Integer::from(r.msg_type as i64),
        padata: None,
        crealm: GeneralString::try_from(r.crealm.as_bytes()).unwrap_or_default(),
        cname: to_principal_name(&r.cname),
        ticket: encode_ticket_to_rk(&r.ticket),
        enc_part: to_encrypted_data(r.enc_part_etype, r.enc_part_kvno, &r.enc_part),
    });
    der::encode(&rk_rep).unwrap_or_default()
}

pub fn decode_as_rep(b: &[u8]) -> Result<AsRep, DecodeError> {
    let rk_rep: rk::AsRep = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    let inner = rk_rep.0;
    let ticket = decode_ticket_from_rk(&inner.ticket)?;
    let (etype, kvno, enc_part) = from_encrypted_data(&inner.enc_part)?;
    Ok(AsRep {
        pvno: match &inner.pvno {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => PVNO,
        },
        msg_type: match &inner.msg_type {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => 11,
        },
        crealm: String::from_utf8_lossy(&inner.crealm.as_bytes()).into_owned(),
        cname: from_principal_name(&inner.cname),
        ticket,
        enc_part_etype: etype,
        enc_part_kvno: kvno,
        enc_part,
    })
}

// ---------------------------------------------------------------------------
// TgsReq
// ---------------------------------------------------------------------------

/// Wrap a TGT + encrypted authenticator into an ApReq for PA-TGS-REQ.
fn build_ap_req(tgt: &Ticket, authenticator_enc: &[u8]) -> rk::ApReq {
    rk::ApReq {
        pvno: Integer::from(PVNO as i64),
        msg_type: Integer::from(MSG_TYPE_AP_REQ),
        ap_options: rk::ApOptions(rk::KerberosFlags::from_vec(vec![0u8; 4])),
        ticket: encode_ticket_to_rk(tgt),
        authenticator: rk::EncryptedData {
            etype: tgt.etype as i32,
            kvno: None,
            cipher: to_octet_string(authenticator_enc),
        },
    }
}

/// Extract TGT + encrypted authenticator from an ApReq.
fn parse_ap_req(ap_req: &rk::ApReq) -> Result<(Ticket, Vec<u8>), DecodeError> {
    let tgt = decode_ticket_from_rk(&ap_req.ticket)?;
    let authenticator_enc = ap_req.authenticator.cipher.to_vec();
    Ok((tgt, authenticator_enc))
}

pub fn encode_tgs_req(r: &TgsReq) -> Vec<u8> {
    let ap_req = build_ap_req(&r.tgt, &r.authenticator_enc);
    let ap_req_bytes = der::encode(&ap_req).unwrap_or_default();
    let padata: SequenceOf<rk::PaData> = vec![rk::PaData {
        r#type: PA_TGS_REQ_TYPE,
        value: to_octet_string(&ap_req_bytes),
    }];
    let etypes: SequenceOf<i32> = r.etypes.iter().map(|e| *e as i32).collect();
    let rk_req = rk::TgsReq(rk::KdcReq {
        pvno: Integer::from(r.pvno as i64),
        msg_type: Integer::from(r.msg_type as i64),
        padata: Some(padata),
        req_body: rk::KdcReqBody {
            kdc_options: rk::KdcOptions::reserved(),
            cname: None,
            realm: GeneralString::try_from(r.realm.as_bytes()).unwrap_or_default(),
            sname: Some(to_principal_name(&r.sname)),
            from: None,
            till: to_krb_time(r.till),
            rtime: None,
            nonce: r.nonce,
            etype: etypes,
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    der::encode(&rk_req).unwrap_or_default()
}

pub fn decode_tgs_req(b: &[u8]) -> Result<TgsReq, DecodeError> {
    let rk_req: rk::TgsReq = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    let inner = rk_req.0;

    // Extract TGT + authenticator from PA-TGS-REQ padata.
    let mut tgt = Ticket {
        tkt_vno: PVNO,
        realm: String::new(),
        sname: vec![],
        kvno: 0,
        etype: EType::Aes256CtsHmacSha1_96,
        enc_part: vec![],
    };
    let mut authenticator_enc = vec![];
    if let Some(padata_list) = &inner.padata {
        for p in padata_list {
            if p.r#type == PA_TGS_REQ_TYPE {
                let ap_req_bytes = p.value.to_vec();
                let ap_req: rk::ApReq =
                    der::decode(&ap_req_bytes).map_err(|_| DecodeError::UnexpectedEof)?;
                let (t, a) = parse_ap_req(&ap_req)?;
                tgt = t;
                authenticator_enc = a;
                break;
            }
        }
    }

    let sname = inner
        .req_body
        .sname
        .as_ref()
        .map(|s| from_principal_name(s))
        .unwrap_or_default();
    let etypes: Vec<EType> = inner
        .req_body
        .etype
        .iter()
        .filter_map(|i| EType::from_u32(*i as u32))
        .collect();
    Ok(TgsReq {
        pvno: match &inner.pvno {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => PVNO,
        },
        msg_type: match &inner.msg_type {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => 12,
        },
        realm: String::from_utf8_lossy(&inner.req_body.realm.as_bytes()).into_owned(),
        sname,
        nonce: inner.req_body.nonce,
        etypes,
        tgt,
        authenticator_enc,
        till: from_krb_time(&inner.req_body.till),
    })
}

// ---------------------------------------------------------------------------
// TgsRep
// ---------------------------------------------------------------------------

pub fn encode_tgs_rep(r: &TgsRep) -> Vec<u8> {
    let rk_rep = rk::TgsRep(rk::KdcRep {
        pvno: Integer::from(r.pvno as i64),
        msg_type: Integer::from(r.msg_type as i64),
        padata: None,
        crealm: GeneralString::try_from(r.crealm.as_bytes()).unwrap_or_default(),
        cname: to_principal_name(&r.cname),
        ticket: encode_ticket_to_rk(&r.ticket),
        enc_part: to_encrypted_data(r.enc_part_etype, r.enc_part_kvno, &r.enc_part),
    });
    der::encode(&rk_rep).unwrap_or_default()
}

pub fn decode_tgs_rep(b: &[u8]) -> Result<TgsRep, DecodeError> {
    let rk_rep: rk::TgsRep = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    let inner = rk_rep.0;
    let ticket = decode_ticket_from_rk(&inner.ticket)?;
    let (etype, kvno, enc_part) = from_encrypted_data(&inner.enc_part)?;
    Ok(TgsRep {
        pvno: match &inner.pvno {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => PVNO,
        },
        msg_type: match &inner.msg_type {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => 13,
        },
        crealm: String::from_utf8_lossy(&inner.crealm.as_bytes()).into_owned(),
        cname: from_principal_name(&inner.cname),
        ticket,
        enc_part_etype: etype,
        enc_part_kvno: kvno,
        enc_part,
    })
}

// ---------------------------------------------------------------------------
// Authenticator
// ---------------------------------------------------------------------------

pub fn encode_authenticator(a: &Authenticator) -> Vec<u8> {
    let rk_a = rk::Authenticator {
        authenticator_vno: Integer::from(AUTHENTICATOR_VNO),
        crealm: GeneralString::try_from(a.crealm.as_bytes()).unwrap_or_default(),
        cname: to_principal_name(&a.cname),
        cksum: None,
        cusec: Integer::from(a.cusec as i64),
        ctime: to_krb_time(a.ctime),
        subkey: a.subkey.as_ref().map(|k| to_encryption_key(k)),
        seq_number: Some(a.seq_number),
        authorization_data: None,
    };
    der::encode(&rk_a).unwrap_or_default()
}

pub fn decode_authenticator(b: &[u8]) -> Result<Authenticator, DecodeError> {
    let rk_a: rk::Authenticator = der::decode(b).map_err(|_| DecodeError::UnexpectedEof)?;
    let subkey = rk_a
        .subkey
        .as_ref()
        .map(|k| from_encryption_key(k))
        .transpose()?;
    Ok(Authenticator {
        crealm: String::from_utf8_lossy(&rk_a.crealm.as_bytes()).into_owned(),
        cname: from_principal_name(&rk_a.cname),
        subkey,
        seq_number: rk_a.seq_number.unwrap_or(0),
        ctime: from_krb_time(&rk_a.ctime),
        cusec: match &rk_a.cusec {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => 0,
        },
    })
}

// ---------------------------------------------------------------------------
// Internal helpers: Ticket ↔ rk::Ticket (without re-encoding via DER)
// ---------------------------------------------------------------------------

fn encode_ticket_to_rk(t: &Ticket) -> rk::Ticket {
    rk::Ticket {
        tkt_vno: Integer::from(t.tkt_vno as i64),
        realm: GeneralString::try_from(t.realm.as_bytes()).unwrap_or_default(),
        sname: to_principal_name(&t.sname),
        enc_part: to_encrypted_data(t.etype, t.kvno, &t.enc_part),
    }
}

fn decode_ticket_from_rk(t: &rk::Ticket) -> Result<Ticket, DecodeError> {
    let (etype, kvno, enc_part) = from_encrypted_data(&t.enc_part)?;
    Ok(Ticket {
        tkt_vno: match &t.tkt_vno {
            Integer::Primitive(v) => *v as u32,
            Integer::Variable(_) => PVNO,
        },
        realm: String::from_utf8_lossy(&t.realm.as_bytes()).into_owned(),
        sname: from_principal_name(&t.sname),
        kvno,
        etype,
        enc_part,
    })
}
