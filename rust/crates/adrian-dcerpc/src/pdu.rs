//! DCE/RPC connection-oriented PDU encoding/decoding (per MS-RPCE §2.1 /
//! [C706] §12.6).
//!
//! Only the Bind (PTYPE=11) and Bind_ack (PTYPE=12) PDUs are implemented
//! in v1 — they are the minimum needed to negotiate a context before
//! sending Request PDUs. Request / Response / Fault / Bind_nak /
//! Alter_context / Alter_context_resp are deferred to a later wave that
//! implements a full server endpoint (`DceRpcEndpoint::run`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::ndr::{NdrReader, NdrWriter};
use crate::DceRpcError;
use uuid::Uuid;

// ---- Constants -----------------------------------------------------------

/// PDU type for Bind (per [C706] §12.6.1, MS-RPCE §2.1).
pub const PTYPE_BIND: u8 = 11;
/// PDU type for Bind_ack (per [C706] §12.6.2, MS-RPCE §2.1).
pub const PTYPE_BIND_ACK: u8 = 12;
/// PDU type for Request (per [C706] §12.6.1).
pub const PTYPE_REQUEST: u8 = 0;
/// PDU type for Response (per [C706] §12.6.1).
pub const PTYPE_RESPONSE: u8 = 2;

/// PFC_FIRST_FRAG flag (per [C706] §12.6).
pub const PFC_FIRST_FRAG: u8 = 0x01;
/// PFC_LAST_FRAG flag (per [C706] §12.6).
pub const PFC_LAST_FRAG: u8 = 0x02;
/// PFC_CONC_MPX flag (per [C706] §12.6 — concurrent multiplexing).
pub const PFC_CONC_MPX: u8 = 0x10;

/// NDR20 data representation (little-endian, ASCII, IEEE float).
/// Encoded as `0x10 0x00 0x00 0x00`.
pub const NDR20_DATA_REP: u32 = 0x00000010;

/// Common header size for connection-oriented PDU (16 bytes, per [C706]
/// §12.6.1).
pub const COMMON_HEADER_SIZE: usize = 16;

/// Bind ack result codes (per [C706] §12.6.2 — `p_result_t.result`).
pub mod ack_result {
    /// Acceptance — interface and transfer syntax negotiated successfully.
    pub const ACCEPTANCE: u16 = 0;
    /// User rejection — caller is not authorized to use this interface.
    pub const USER_REJECTION: u16 = 1;
    /// Provider rejection — server does not support this interface/version.
    pub const PROVIDER_REJECTION: u16 = 2;
}

/// Bind ack reason codes (per [C706] §12.6.2 — `p_result_t.reason`, only
/// meaningful when `result != ACCEPTANCE`).
pub mod ack_reason {
    /// Reason not specified.
    pub const REASON_NOT_SPECIFIED: u16 = 0;
    /// Abstract syntax not supported.
    pub const ABSTRACT_SYNTAX_NOT_SUPPORTED: u16 = 1;
    /// Proposed transfer syntaxes not supported.
    pub const PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED: u16 = 2;
    /// Local limit exceeded.
    pub const LOCAL_LIMIT_EXCEEDED: u16 = 3;
}

// ---- Types ---------------------------------------------------------------

/// A `p_cont_elem_t` — one context element in a Bind PDU (per [C706]
/// §12.6.1 / MS-RPCE §2.2.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PContextElem {
    /// Caller-assigned context ID (echoed by the server in Bind_ack and
    /// used in subsequent Request PDUs).
    pub p_cont_id: u16,
    /// The abstract syntax: interface UUID + interface version
    /// `(major, minor)`.
    pub abstract_syntax: (Uuid, (u16, u16)),
    /// Proposed transfer syntaxes — typically just NDR 2.0, but a client
    /// may propose multiple and the server picks one.
    pub transfer_syntaxes: Vec<(Uuid, u32)>,
}

impl PContextElem {
    /// Construct a context element proposing NDR 2.0 for the given
    /// interface UUID + version, with `p_cont_id = 0`.
    #[must_use]
    pub fn new(iface: Uuid, version: (u16, u16)) -> Self {
        Self {
            p_cont_id: 0,
            abstract_syntax: (iface, version),
            transfer_syntaxes: vec![(
                crate::ndr::NDR_TRANSFER_SYNTAX_UUID,
                crate::ndr::NDR_TRANSFER_SYNTAX_VERSION,
            )],
        }
    }
}

/// A Bind PDU (PTYPE=11, per [C706] §12.6.1 / MS-RPCE §2.2.1).
#[derive(Debug, Clone)]
pub struct BindPdu {
    /// RPC version (always 5 in v1).
    pub rpc_vers: u8,
    /// RPC minor version (always 0 in v1).
    pub rpc_vers_minor: u8,
    /// PFC flags (typically `PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_CONC_MPX`).
    pub pfc_flags: u8,
    /// Data representation (always NDR20 in v1).
    pub data_rep: u32,
    /// Caller-chosen call ID; echoed in the Bind_ack.
    pub call_id: u32,
    /// Max transmit fragment size the client will accept.
    pub max_xmit_frag: u16,
    /// Max receive fragment size the client will accept.
    pub max_recv_frag: u16,
    /// Association group ID (0 = request a new group).
    pub assoc_group_id: u32,
    /// Context elements (typically 1 in v1 — one interface per Bind).
    pub context_elements: Vec<PContextElem>,
}

impl BindPdu {
    /// Construct a minimal Bind PDU for the given interface + version,
    /// with default values that match Windows DRA reference traffic.
    #[must_use]
    pub fn new(interface: Uuid, version: (u16, u16)) -> Self {
        Self {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_CONC_MPX,
            data_rep: NDR20_DATA_REP,
            call_id: 1,
            max_xmit_frag: crate::ndr::DEFAULT_MAX_XMIT_FRAG,
            max_recv_frag: crate::ndr::DEFAULT_MAX_RECV_FRAG,
            assoc_group_id: 0,
            context_elements: vec![PContextElem::new(interface, version)],
        }
    }

    /// The PDU type for a Bind is always `PTYPE_BIND` (11) — included
    /// for API symmetry with the decoder.
    #[must_use]
    pub fn ptype(&self) -> u8 {
        PTYPE_BIND
    }
}

/// A `p_result_t` — one per-context result in a Bind_ack (per [C706]
/// §12.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PResult {
    /// Result code (`ACCEPTANCE`, `USER_REJECTION`, `PROVIDER_REJECTION`).
    pub result: u16,
    /// Reason code (only meaningful if `result != ACCEPTANCE`).
    pub reason: u16,
    /// The transfer syntax the server selected (only meaningful if
    /// `result == ACCEPTANCE`).
    pub transfer_syntax: (Uuid, u32),
}

/// A Bind_ack PDU (PTYPE=12, per [C706] §12.6.2 / MS-RPCE §2.2.2).
#[derive(Debug, Clone)]
pub struct BindAckPdu {
    /// RPC version (echoes the Bind's rpc_vers).
    pub rpc_vers: u8,
    /// RPC minor version (echoes the Bind's rpc_vers_minor).
    pub rpc_vers_minor: u8,
    /// PFC flags (echoes the Bind's pfc_flags).
    pub pfc_flags: u8,
    /// Data representation (echoes the Bind's data_rep).
    pub data_rep: u32,
    /// Call ID (echoes the Bind's call_id).
    pub call_id: u32,
    /// Negotiated max transmit fragment size.
    pub max_xmit_frag: u16,
    /// Negotiated max receive fragment size.
    pub max_recv_frag: u16,
    /// Association group ID assigned by the server.
    pub assoc_group_id: u32,
    /// Secondary address (`sec_addr` / `port_spec` — NUL-terminated string
    /// per [C706] §12.6.2). Typically the dynamic TCP port the server
    /// listens on for subsequent requests.
    pub sec_addr: String,
    /// Per-context results (one per Bind context element).
    pub p_results: Vec<PResult>,
}

// ---- Bind encode/decode --------------------------------------------------

/// Encode a Bind PDU to wire bytes (per [C706] §12.6.1 / MS-RPCE §2.2.1).
///
/// The returned `Vec<u8>` contains the full PDU — common header (16
/// bytes) + Bind body — with `frag_length` patched in to match the
/// actual byte count.
pub fn encode_bind_pdu(pdu: &BindPdu) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);

    // ---- common header (16 bytes, fixed byte layout, no NDR alignment) ----
    w.write_uint8(pdu.rpc_vers);
    w.write_uint8(pdu.rpc_vers_minor);
    w.write_uint8(PTYPE_BIND);
    w.write_uint8(pdu.pfc_flags);
    w.write_bytes(&pdu.data_rep.to_le_bytes());
    let frag_length_pos = w.position();
    w.write_bytes(&0u16.to_le_bytes()); // frag_length placeholder
    w.write_bytes(&0u16.to_le_bytes()); // auth_length = 0
    w.write_bytes(&pdu.call_id.to_le_bytes());

    // ---- bind body ----
    w.write_bytes(&pdu.max_xmit_frag.to_le_bytes());
    w.write_bytes(&pdu.max_recv_frag.to_le_bytes());
    w.write_bytes(&pdu.assoc_group_id.to_le_bytes());
    // p_context_elem: n_context_elem (1 byte) + reserved (1) + reserved2 (2).
    let n_ctx = pdu.context_elements.len() as u8;
    w.write_uint8(n_ctx);
    w.write_uint8(0); // reserved
    w.write_bytes(&0u16.to_le_bytes()); // reserved2

    for ctx in &pdu.context_elements {
        w.write_bytes(&ctx.p_cont_id.to_le_bytes());
        let n_ts = ctx.transfer_syntaxes.len() as u8;
        w.write_uint8(n_ts);
        w.write_uint8(0); // reserved
                          // abstract_syntax: 16-byte UUID + 4-byte version (major in upper 16).
        w.write_uuid(ctx.abstract_syntax.0);
        let iface_ver =
            ((ctx.abstract_syntax.1 .0 as u32) << 16) | (ctx.abstract_syntax.1 .1 as u32);
        w.write_bytes(&iface_ver.to_le_bytes());
        for ts in &ctx.transfer_syntaxes {
            w.write_uuid(ts.0);
            w.write_bytes(&ts.1.to_le_bytes());
        }
    }

    // Patch frag_length with the actual total length.
    let total = w.position() as u16;
    let mut bytes = w.into_bytes();
    bytes[frag_length_pos..frag_length_pos + 2].copy_from_slice(&total.to_le_bytes());
    bytes
}

/// Decode a Bind PDU from wire bytes (per [C706] §12.6.1).
///
/// Verifies `ptype == PTYPE_BIND` and `frag_length == buf.len()`.
pub fn decode_bind_pdu(buf: &[u8]) -> Result<BindPdu, DceRpcError> {
    if buf.len() < COMMON_HEADER_SIZE {
        return Err(DceRpcError::Ndr(format!(
            "bind pdu too short: {} < {COMMON_HEADER_SIZE}",
            buf.len()
        )));
    }
    let mut r = NdrReader::new(buf);
    let rpc_vers = r.read_uint8()?;
    let rpc_vers_minor = r.read_uint8()?;
    let ptype = r.read_uint8()?;
    if ptype != PTYPE_BIND {
        return Err(DceRpcError::Ndr(format!(
            "decode_bind_pdu: expected ptype {PTYPE_BIND}, got {ptype}"
        )));
    }
    let pfc_flags = r.read_uint8()?;
    let data_rep = u32::from_le_bytes(r.read_array::<4>()?);
    let frag_length = u16::from_le_bytes(r.read_array::<2>()?);
    let _auth_length = u16::from_le_bytes(r.read_array::<2>()?);
    let call_id = u32::from_le_bytes(r.read_array::<4>()?);

    let max_xmit_frag = u16::from_le_bytes(r.read_array::<2>()?);
    let max_recv_frag = u16::from_le_bytes(r.read_array::<2>()?);
    let assoc_group_id = u32::from_le_bytes(r.read_array::<4>()?);
    let n_ctx = r.read_uint8()?;
    let _reserved = r.read_uint8()?;
    let _reserved2 = u16::from_le_bytes(r.read_array::<2>()?);

    let mut context_elements = Vec::with_capacity(n_ctx as usize);
    for _ in 0..n_ctx {
        let p_cont_id = u16::from_le_bytes(r.read_array::<2>()?);
        let n_ts = r.read_uint8()?;
        let _reserved = r.read_uint8()?;
        let iface_uuid = r.read_uuid()?;
        let iface_ver_u32 = u32::from_le_bytes(r.read_array::<4>()?);
        let iface_ver = (
            (iface_ver_u32 >> 16) as u16,
            (iface_ver_u32 & 0xFFFF) as u16,
        );
        let mut tss = Vec::with_capacity(n_ts as usize);
        for _ in 0..n_ts {
            let ts_uuid = r.read_uuid()?;
            let ts_ver = u32::from_le_bytes(r.read_array::<4>()?);
            tss.push((ts_uuid, ts_ver));
        }
        context_elements.push(PContextElem {
            p_cont_id,
            abstract_syntax: (iface_uuid, iface_ver),
            transfer_syntaxes: tss,
        });
    }

    if frag_length as usize != buf.len() {
        return Err(DceRpcError::Ndr(format!(
            "bind pdu frag_length {frag_length} != buf.len() {}",
            buf.len()
        )));
    }

    Ok(BindPdu {
        rpc_vers,
        rpc_vers_minor,
        pfc_flags,
        data_rep,
        call_id,
        max_xmit_frag,
        max_recv_frag,
        assoc_group_id,
        context_elements,
    })
}

// ---- Bind_ack encode/decode ----------------------------------------------

/// Encode a Bind_ack PDU to wire bytes (per [C706] §12.6.2 / MS-RPCE
/// §2.2.2).
pub fn encode_bind_ack_pdu(pdu: &BindAckPdu) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);

    // ---- common header ----
    w.write_uint8(pdu.rpc_vers);
    w.write_uint8(pdu.rpc_vers_minor);
    w.write_uint8(PTYPE_BIND_ACK);
    w.write_uint8(pdu.pfc_flags);
    w.write_bytes(&pdu.data_rep.to_le_bytes());
    let frag_length_pos = w.position();
    w.write_bytes(&0u16.to_le_bytes()); // frag_length placeholder
    w.write_bytes(&0u16.to_le_bytes()); // auth_length = 0
    w.write_bytes(&pdu.call_id.to_le_bytes());

    // ---- bind_ack body ----
    w.write_bytes(&pdu.max_xmit_frag.to_le_bytes());
    w.write_bytes(&pdu.max_recv_frag.to_le_bytes());
    w.write_bytes(&pdu.assoc_group_id.to_le_bytes());

    // sec_addr: 2-byte length prefix + NUL-terminated string.
    let sec_addr_bytes = pdu.sec_addr.as_bytes();
    let sec_addr_len = (sec_addr_bytes.len() + 1) as u16;
    w.write_bytes(&sec_addr_len.to_le_bytes());
    w.write_bytes(sec_addr_bytes);
    w.write_uint8(0); // trailing NUL

    // Pad to 4-byte boundary before p_result_list.
    w.align(4);

    // p_result_list: n_results (2 bytes) + reserved (2 bytes) + results[].
    let n_results = pdu.p_results.len() as u16;
    w.write_bytes(&n_results.to_le_bytes());
    w.write_bytes(&0u16.to_le_bytes()); // reserved
    for res in &pdu.p_results {
        w.write_bytes(&res.result.to_le_bytes());
        w.write_bytes(&res.reason.to_le_bytes());
        w.write_uuid(res.transfer_syntax.0);
        w.write_bytes(&res.transfer_syntax.1.to_le_bytes());
    }

    // Patch frag_length with the actual total length.
    let total = w.position() as u16;
    let mut bytes = w.into_bytes();
    bytes[frag_length_pos..frag_length_pos + 2].copy_from_slice(&total.to_le_bytes());
    bytes
}

/// Decode a Bind_ack PDU from wire bytes (per [C706] §12.6.2).
///
/// Verifies `ptype == PTYPE_BIND_ACK` and `frag_length == buf.len()`.
pub fn decode_bind_ack_pdu(buf: &[u8]) -> Result<BindAckPdu, DceRpcError> {
    if buf.len() < COMMON_HEADER_SIZE {
        return Err(DceRpcError::Ndr(format!(
            "bind_ack pdu too short: {} < {COMMON_HEADER_SIZE}",
            buf.len()
        )));
    }
    let mut r = NdrReader::new(buf);
    let rpc_vers = r.read_uint8()?;
    let rpc_vers_minor = r.read_uint8()?;
    let ptype = r.read_uint8()?;
    if ptype != PTYPE_BIND_ACK {
        return Err(DceRpcError::Ndr(format!(
            "decode_bind_ack_pdu: expected ptype {PTYPE_BIND_ACK}, got {ptype}"
        )));
    }
    let pfc_flags = r.read_uint8()?;
    let data_rep = u32::from_le_bytes(r.read_array::<4>()?);
    let frag_length = u16::from_le_bytes(r.read_array::<2>()?);
    let _auth_length = u16::from_le_bytes(r.read_array::<2>()?);
    let call_id = u32::from_le_bytes(r.read_array::<4>()?);

    let max_xmit_frag = u16::from_le_bytes(r.read_array::<2>()?);
    let max_recv_frag = u16::from_le_bytes(r.read_array::<2>()?);
    let assoc_group_id = u32::from_le_bytes(r.read_array::<4>()?);

    let sec_addr_len = r.read_uint16()? as usize;
    let sec_addr_bytes = r.read_bytes(sec_addr_len)?;
    let trimmed = sec_addr_bytes.strip_suffix(b"\0").unwrap_or(sec_addr_bytes);
    let sec_addr = std::str::from_utf8(trimmed)
        .map_err(|e| DceRpcError::Ndr(format!("bind_ack sec_addr utf8: {e}")))?
        .to_string();

    // Pad to 4-byte boundary before p_result_list.
    r.align(4)?;

    let n_results = r.read_uint16()?;
    let _reserved = r.read_uint16()?;
    let mut p_results = Vec::with_capacity(n_results as usize);
    for _ in 0..n_results {
        let result = r.read_uint16()?;
        let reason = r.read_uint16()?;
        let ts_uuid = r.read_uuid()?;
        let ts_ver = u32::from_le_bytes(r.read_array::<4>()?);
        p_results.push(PResult {
            result,
            reason,
            transfer_syntax: (ts_uuid, ts_ver),
        });
    }

    if frag_length as usize != buf.len() {
        return Err(DceRpcError::Ndr(format!(
            "bind_ack pdu frag_length {frag_length} != buf.len() {}",
            buf.len()
        )));
    }

    Ok(BindAckPdu {
        rpc_vers,
        rpc_vers_minor,
        pfc_flags,
        data_rep,
        call_id,
        max_xmit_frag,
        max_recv_frag,
        assoc_group_id,
        sec_addr,
        p_results,
    })
}

// ---- Request/Response (minimal, used by the TCP transport) --------------

/// Common-header + Request body header size (16 + 8 = 24 bytes).
pub const REQUEST_HEADER_SIZE: usize = COMMON_HEADER_SIZE + 8;
/// Common-header + Response body header size (16 + 8 = 24 bytes, per
/// [C706] §12.6.1 — Response body has only `alloc_hint + p_cont_id +
/// cancel_count + reserved`, no extra padding; stub data starts at offset
/// 24 which is already 8-aligned).
pub const RESPONSE_HEADER_SIZE: usize = COMMON_HEADER_SIZE + 8;

/// Encode a Request PDU (PTYPE=0) carrying the given stub data (per
/// [C706] §12.6.1 / MS-RPCE §2.2.6.4).
///
/// `alloc_hint` is set to the stub data size (including the opnum prefix).
/// The `opnum` is encoded as the first 2 bytes of the stub data (per IDL
/// contract — the DCE/RPC connection-oriented Request header does NOT
/// carry opnum as a separate field; the client stub prepends it to the
/// NDR-typed argument list). Callers that already include the opnum in
/// `stub` should pass `opnum = 0` to avoid double-encoding.
pub fn encode_request_pdu(call_id: u32, ctxt_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let total_stub_len = 2 + stub.len();
    let total_len = REQUEST_HEADER_SIZE + total_stub_len;
    let mut w = NdrWriter::with_capacity(total_len);

    // Common header (16 bytes).
    w.write_uint8(5); // rpc_vers
    w.write_uint8(0); // rpc_vers_minor
    w.write_uint8(PTYPE_REQUEST);
    w.write_uint8(PFC_FIRST_FRAG | PFC_LAST_FRAG);
    w.write_bytes(&NDR20_DATA_REP.to_le_bytes());
    w.write_bytes(&(total_len as u16).to_le_bytes());
    w.write_bytes(&0u16.to_le_bytes()); // auth_length
    w.write_bytes(&call_id.to_le_bytes());

    // Request body header (8 bytes): alloc_hint + p_cont_id + cancel_count + reserved.
    let alloc_hint = total_stub_len as u32;
    w.write_bytes(&alloc_hint.to_le_bytes());
    w.write_bytes(&ctxt_id.to_le_bytes());
    w.write_uint8(0); // cancel_count
    w.write_uint8(0); // reserved

    // Stub data: opnum (2 bytes, little-endian) + the actual stub bytes.
    w.write_bytes(&opnum.to_le_bytes());
    w.write_bytes(stub);
    w.into_bytes()
}

/// Decode a Response PDU (PTYPE=2). Returns the stub data bytes (the
/// bytes after the Response body header, per [C706] §12.6.1).
pub fn decode_response_pdu(buf: &[u8]) -> Result<Vec<u8>, DceRpcError> {
    if buf.len() < RESPONSE_HEADER_SIZE {
        return Err(DceRpcError::Ndr(format!(
            "response pdu too short: {} < {RESPONSE_HEADER_SIZE}",
            buf.len()
        )));
    }
    let ptype = buf[2];
    if ptype != PTYPE_RESPONSE {
        return Err(DceRpcError::Ndr(format!(
            "expected response (ptype={PTYPE_RESPONSE}), got ptype {ptype}"
        )));
    }
    let stub = &buf[RESPONSE_HEADER_SIZE..];
    Ok(stub.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndr::{
        DEFAULT_MAX_RECV_FRAG, DEFAULT_MAX_XMIT_FRAG, NDR_TRANSFER_SYNTAX_UUID,
        NDR_TRANSFER_SYNTAX_VERSION,
    };

    fn drsuapi_iface() -> Uuid {
        Uuid::from_u128(0xE3514235_4B06_11D1_AB04_00C04FC2DCD2)
    }

    #[test]
    fn bind_pdu_round_trip_single_context() {
        let pdu = BindPdu::new(drsuapi_iface(), (4, 0));
        let bytes = encode_bind_pdu(&pdu);
        let decoded = decode_bind_pdu(&bytes).unwrap();

        assert_eq!(decoded.rpc_vers, 5);
        assert_eq!(decoded.rpc_vers_minor, 0);
        assert_eq!(
            decoded.pfc_flags,
            PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_CONC_MPX
        );
        assert_eq!(decoded.data_rep, NDR20_DATA_REP);
        assert_eq!(decoded.call_id, 1);
        assert_eq!(decoded.max_xmit_frag, DEFAULT_MAX_XMIT_FRAG);
        assert_eq!(decoded.max_recv_frag, DEFAULT_MAX_RECV_FRAG);
        assert_eq!(decoded.assoc_group_id, 0);
        assert_eq!(decoded.context_elements.len(), 1);

        let ctx = &decoded.context_elements[0];
        assert_eq!(ctx.p_cont_id, 0);
        assert_eq!(ctx.abstract_syntax, (drsuapi_iface(), (4, 0)));
        assert_eq!(ctx.transfer_syntaxes.len(), 1);
        assert_eq!(
            ctx.transfer_syntaxes[0],
            (NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION)
        );
    }

    #[test]
    fn bind_pdu_wire_layout_matches_spec() {
        let pdu = BindPdu::new(drsuapi_iface(), (4, 0));
        let bytes = encode_bind_pdu(&pdu);

        // Common header (16 bytes):
        assert_eq!(bytes[0], 5);
        assert_eq!(bytes[1], 0);
        assert_eq!(bytes[2], PTYPE_BIND);
        assert_eq!(bytes[3], PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_CONC_MPX);
        assert_eq!(bytes[4..8], [0x10, 0x00, 0x00, 0x00]);
        let frag_length = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        assert_eq!(frag_length, bytes.len());
        assert_eq!(bytes[10..12], [0x00, 0x00]);
        let call_id = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(call_id, 1);

        // Bind body:
        let max_xmit_frag = u16::from_le_bytes([bytes[16], bytes[17]]);
        assert_eq!(max_xmit_frag, DEFAULT_MAX_XMIT_FRAG);
        let max_recv_frag = u16::from_le_bytes([bytes[18], bytes[19]]);
        assert_eq!(max_recv_frag, DEFAULT_MAX_RECV_FRAG);
        let assoc_group_id = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        assert_eq!(assoc_group_id, 0);
        assert_eq!(bytes[24], 1);

        // First context element starts at offset 28.
        let p_cont_id = u16::from_le_bytes([bytes[28], bytes[29]]);
        assert_eq!(p_cont_id, 0);
        assert_eq!(bytes[30], 1);
        assert_eq!(bytes[31], 0);
        assert_eq!(&bytes[32..48], drsuapi_iface().as_bytes());
        let iface_ver = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]);
        assert_eq!(iface_ver, 4u32 << 16);
        assert_eq!(&bytes[52..68], NDR_TRANSFER_SYNTAX_UUID.as_bytes());
        let ts_ver = u32::from_le_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]);
        assert_eq!(ts_ver, NDR_TRANSFER_SYNTAX_VERSION);

        // Total = 16 (common header) + 12 (bind body) + 44 (ctx element).
        assert_eq!(bytes.len(), 72);
    }

    #[test]
    fn bind_pdu_decode_rejects_wrong_ptype() {
        let mut bytes = encode_bind_pdu(&BindPdu::new(drsuapi_iface(), (4, 0)));
        bytes[2] = PTYPE_BIND_ACK;
        let result = decode_bind_pdu(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DceRpcError::Ndr(_)));
        assert!(format!("{err}").contains("expected ptype 11"));
    }

    #[test]
    fn bind_pdu_decode_rejects_short_buffer() {
        let buf = [0u8; 10];
        let result = decode_bind_pdu(&buf);
        assert!(result.is_err());
        assert!(matches!(result, Err(DceRpcError::Ndr(_))));
    }

    #[test]
    fn bind_pdu_decode_rejects_frag_length_mismatch() {
        let mut bytes = encode_bind_pdu(&BindPdu::new(drsuapi_iface(), (4, 0)));
        bytes[8] = 0xFF;
        bytes[9] = 0xFF;
        let result = decode_bind_pdu(&bytes);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("frag_length"));
    }

    #[test]
    fn bind_pdu_round_trip_two_contexts() {
        let mut pdu = BindPdu::new(drsuapi_iface(), (4, 0));
        pdu.context_elements.push(PContextElem {
            p_cont_id: 1,
            abstract_syntax: (
                Uuid::from_u128(0x12345778_1234_ABCD_EF00_0123456789AC),
                (1, 0),
            ),
            transfer_syntaxes: vec![(NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION)],
        });
        let bytes = encode_bind_pdu(&pdu);
        let decoded = decode_bind_pdu(&bytes).unwrap();
        assert_eq!(decoded.context_elements.len(), 2);
        assert_eq!(
            decoded.context_elements[0].abstract_syntax.0,
            drsuapi_iface()
        );
        assert_eq!(
            decoded.context_elements[1].abstract_syntax.0,
            Uuid::from_u128(0x12345778_1234_ABCD_EF00_0123456789AC)
        );
        assert_eq!(decoded.context_elements[1].p_cont_id, 1);
    }

    #[test]
    fn bind_ack_pdu_round_trip_acceptance() {
        let pdu = BindAckPdu {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_CONC_MPX,
            data_rep: NDR20_DATA_REP,
            call_id: 7,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0xDEAD_BEEF,
            sec_addr: "1025".to_string(),
            p_results: vec![PResult {
                result: ack_result::ACCEPTANCE,
                reason: 0,
                transfer_syntax: (NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION),
            }],
        };
        let bytes = encode_bind_ack_pdu(&pdu);
        let decoded = decode_bind_ack_pdu(&bytes).unwrap();

        assert_eq!(decoded.rpc_vers, 5);
        assert_eq!(decoded.rpc_vers_minor, 0);
        assert_eq!(decoded.call_id, 7);
        assert_eq!(decoded.max_xmit_frag, 4280);
        assert_eq!(decoded.max_recv_frag, 4280);
        assert_eq!(decoded.assoc_group_id, 0xDEAD_BEEF);
        assert_eq!(decoded.sec_addr, "1025");
        assert_eq!(decoded.p_results.len(), 1);
        assert_eq!(decoded.p_results[0].result, ack_result::ACCEPTANCE);
        assert_eq!(
            decoded.p_results[0].transfer_syntax,
            (NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION)
        );
    }

    #[test]
    fn bind_ack_pdu_round_trip_provider_rejection() {
        let pdu = BindAckPdu {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            data_rep: NDR20_DATA_REP,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            sec_addr: String::new(),
            p_results: vec![PResult {
                result: ack_result::PROVIDER_REJECTION,
                reason: ack_reason::ABSTRACT_SYNTAX_NOT_SUPPORTED,
                transfer_syntax: (Uuid::nil(), 0),
            }],
        };
        let bytes = encode_bind_ack_pdu(&pdu);
        let decoded = decode_bind_ack_pdu(&bytes).unwrap();
        assert_eq!(decoded.p_results[0].result, ack_result::PROVIDER_REJECTION);
        assert_eq!(
            decoded.p_results[0].reason,
            ack_reason::ABSTRACT_SYNTAX_NOT_SUPPORTED
        );
    }

    #[test]
    fn bind_ack_pdu_sec_addr_padding_rounds_to_4() {
        let pdu = BindAckPdu {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            data_rep: NDR20_DATA_REP,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            sec_addr: "1024".to_string(),
            p_results: vec![PResult {
                result: ack_result::ACCEPTANCE,
                reason: 0,
                transfer_syntax: (NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION),
            }],
        };
        let bytes = encode_bind_ack_pdu(&pdu);
        let decoded = decode_bind_ack_pdu(&bytes).unwrap();
        assert_eq!(decoded.sec_addr, "1024");
    }

    #[test]
    fn bind_ack_pdu_decode_rejects_wrong_ptype() {
        let mut bytes = encode_bind_ack_pdu(&BindAckPdu {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            data_rep: NDR20_DATA_REP,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            sec_addr: String::new(),
            p_results: vec![PResult {
                result: ack_result::ACCEPTANCE,
                reason: 0,
                transfer_syntax: (NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION),
            }],
        });
        bytes[2] = PTYPE_BIND;
        let result = decode_bind_ack_pdu(&bytes);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expected ptype 12"));
    }

    #[test]
    fn bind_ack_pdu_round_trip_multiple_results() {
        let pdu = BindAckPdu {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_CONC_MPX,
            data_rep: NDR20_DATA_REP,
            call_id: 42,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0xCAFE_F00D,
            sec_addr: "49152".to_string(),
            p_results: vec![
                PResult {
                    result: ack_result::ACCEPTANCE,
                    reason: 0,
                    transfer_syntax: (NDR_TRANSFER_SYNTAX_UUID, NDR_TRANSFER_SYNTAX_VERSION),
                },
                PResult {
                    result: ack_result::PROVIDER_REJECTION,
                    reason: ack_reason::ABSTRACT_SYNTAX_NOT_SUPPORTED,
                    transfer_syntax: (Uuid::nil(), 0),
                },
            ],
        };
        let bytes = encode_bind_ack_pdu(&pdu);
        let decoded = decode_bind_ack_pdu(&bytes).unwrap();
        assert_eq!(decoded.p_results.len(), 2);
        assert_eq!(decoded.p_results[0].result, ack_result::ACCEPTANCE);
        assert_eq!(decoded.p_results[1].result, ack_result::PROVIDER_REJECTION);
        assert_eq!(
            decoded.p_results[1].reason,
            ack_reason::ABSTRACT_SYNTAX_NOT_SUPPORTED
        );
    }

    #[test]
    fn request_pdu_wire_layout_matches_spec() {
        let stub = [0xAA, 0xBB, 0xCC];
        let bytes = encode_request_pdu(7, 0, 4, &stub);

        assert_eq!(bytes[0], 5);
        assert_eq!(bytes[2], PTYPE_REQUEST);
        assert_eq!(bytes[3], PFC_FIRST_FRAG | PFC_LAST_FRAG);
        let frag_length = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        assert_eq!(frag_length, bytes.len());
        let call_id = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(call_id, 7);

        let alloc_hint = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        assert_eq!(alloc_hint, 5);
        let ctxt_id = u16::from_le_bytes([bytes[20], bytes[21]]);
        assert_eq!(ctxt_id, 0);
        assert_eq!(bytes[22], 0);
        assert_eq!(bytes[23], 0);

        let opnum = u16::from_le_bytes([bytes[24], bytes[25]]);
        assert_eq!(opnum, 4);
        assert_eq!(&bytes[26..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn response_pdu_decode_returns_stub_data() {
        let stub = [0x11, 0x22, 0x33, 0x44];
        let mut buf = Vec::with_capacity(RESPONSE_HEADER_SIZE + stub.len());
        buf.push(5);
        buf.push(0);
        buf.push(PTYPE_RESPONSE);
        buf.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
        buf.extend_from_slice(&NDR20_DATA_REP.to_le_bytes());
        let total = (RESPONSE_HEADER_SIZE + stub.len()) as u16;
        buf.extend_from_slice(&total.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&(stub.len() as u32).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&stub);

        let decoded = decode_response_pdu(&buf).unwrap();
        assert_eq!(decoded, stub.to_vec());
    }

    #[test]
    fn response_pdu_decode_rejects_wrong_ptype() {
        let mut buf = vec![0u8; RESPONSE_HEADER_SIZE];
        buf[2] = PTYPE_REQUEST;
        let result = decode_response_pdu(&buf);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expected response"));
    }

    #[test]
    fn response_pdu_decode_rejects_short_buffer() {
        let buf = vec![0u8; 10];
        let result = decode_response_pdu(&buf);
        assert!(result.is_err());
        assert!(matches!(result, Err(DceRpcError::Ndr(_))));
    }
}
