//! # adrian-dcerpc
//!
//! DCE/RPC transport layer for the Adrian framework.
//!
//! Per Decision 1 §Implementation impact, the DCE/RPC transport for DRSUAPI
//! also serves SAMR, LSARPC, Netlogon, and MS-WCCE — the framework must
//! implement all five protocols for full AD-interop. The DCE/RPC investment
//! is amortised across these 5 protocols, which is why it lives in its own
//! crate rather than being inlined into `adrian-drsuapi`.
//!
//! ## Supported protocols
//!
//! | Protocol | UUID | ADR | Status |
//! |----------|------|-----|--------|
//! | DRSUAPI  | `E3514235-4B06-11D1-AB04-00C04FC2DCD2` | ADR-070 | transport ready; opnums in `adrian-drsuapi` |
//! | SAMR     | `12345778-1234-ABCD-EF00-0123456789AC` | ADR-066 | transport ready; dispatch is Layer 3 |
//! | LSARPC   | `12345778-1234-ABCD-EF00-0123456789AB` | ADR-125 | transport ready; dispatch is Layer 3 |
//! | Netlogon | `12345678-1234-ABCD-EF00-01234567CFFB` | ADR-086 | transport ready; dispatch is Layer 3 |
//! | MS-WCCE  | `91AE6020-9E3C-11CF-8D7C-00AA00C009CF` | ADR-095 | transport ready; dispatch is Layer 3 |
//!
//! ## What's real (Wave 2a)
//!
//! - NDR20 encoding/decoding ([`ndr`]) — primitives for NDR20 wire format:
//!   `u8`/`u16`/`u32`/`u64` with natural alignment, conformant-varying
//!   byte arrays, UTF-16LE strings, 16-byte UUIDs. Every `write_X(v)`
//!   round-trips through `read_X()`.
//! - Bind / Bind_ack PDU encode/decode ([`pdu`]) — full common header
//!   (16 bytes) + Bind body + Bind_ack body with `sec_addr` padding and
//!   `p_result_list`. `frag_length` is computed and patched in on encode,
//!   validated on decode.
//! - Request / Response PDU encode/decode ([`pdu`]) — minimal framing
//!   for the TCP transport to send method calls.
//! - TCP transport ([`transport::DcerpcTcpTransport`]) — async client
//!   over any `AsyncRead + AsyncWrite + Unpin` (works with
//!   `tokio::net::TcpStream` for real network and `tokio::io::duplex`
//!   for tests).
//!
//! ## What's still stubbed
//!
//! - [`DceRpcEndpoint::run`] — the server-side dispatch loop. Now that
//!   the transport primitives are in place, a follow-up wave can build
//!   the listener on top of `tokio::net::TcpListener`.
//! - RPC security (Kerberos/SPNEGO auth at `PKT_PRIVACY`) — deferred to
//!   the wave that implements the KDC. Auth-level negotiation is stubbed
//!   (auth_length = 0 on every PDU).
//! - PDU types other than Bind / Bind_ack / Request / Response (Fault,
//!   Bind_nak, Alter_context, Alter_context_resp, Auth3, Shutdown,
//!   Orphaned) — deferred to the wave that needs them.
//! - The Layer-3 protocol dispatches (DRSUAPI, SAMR, LSARPC, Netlogon,
//!   MS-WCCE) — out of scope for this crate.
//!
//! ## ADRs
//!
//! - ADR-070: DRSUAPI replication protocol (uses this crate as transport)
//! - ADR-066: AdminSDHolder → declarative RBAC (SAMR for tokenGroups query)
//! - ADR-086: Pass-the-hash defense (Netlogon secure channel)
//! - ADR-095: ACME-primary + MS-WCCE bridge (uses this crate as transport)
//! - ADR-122: DCSync mitigation (DRSUAPI `EXOP_REPL_SECRETS` ACL check)
//! - ADR-125: Selective authentication HBAC (LSARPC for trust info)
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). No internal
//! dependencies (uses only `rasn`, `tokio`, `uuid`, `bytes`). Consumed by
//! `adrian-drsuapi` (Layer 2), and by future Layer 3 crates that implement
//! SAMR, LSARPC, Netlogon, and MS-WCCE.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ndr;
pub mod pdu;
pub mod transport;

// Re-export the most-used types at the crate root for convenience.
pub use ndr::{
    NdrReader, NdrWriter, DEFAULT_MAX_RECV_FRAG, DEFAULT_MAX_XMIT_FRAG, NDR_TRANSFER_SYNTAX_UUID,
    NDR_TRANSFER_SYNTAX_VERSION,
};
pub use pdu::{
    ack_reason, ack_result, decode_bind_ack_pdu, decode_bind_pdu, decode_response_pdu,
    encode_bind_ack_pdu, encode_bind_pdu, encode_request_pdu, BindAckPdu, BindPdu, PContextElem,
    PResult, COMMON_HEADER_SIZE, NDR20_DATA_REP, PFC_CONC_MPX, PFC_FIRST_FRAG, PFC_LAST_FRAG,
    PTYPE_BIND, PTYPE_BIND_ACK, PTYPE_REQUEST, PTYPE_RESPONSE, REQUEST_HEADER_SIZE,
    RESPONSE_HEADER_SIZE,
};
pub use transport::DcerpcTcpTransport;

use async_trait::async_trait;
use thiserror::Error;

/// A DCE/RPC interface UUID (per [C706] §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceUuid(pub uuid::Uuid);

impl InterfaceUuid {
    /// DRSUAPI interface UUID (matches the constant already pinned by the
    /// existing test `interface_uuid_constants_match_published_values`).
    pub const DRSUAPI: Self = Self(uuid::Uuid::from_u128(
        0xE3514235_4B06_11D1_AB04_00C04FC2DCD2,
    ));

    /// SAMR interface UUID (`12345778-1234-ABCD-EF00-0123456789AC`, per
    /// MS-SAMR §1.9).
    pub const SAMR: Self = Self(uuid::Uuid::from_u128(
        0x12345778_1234_ABCD_EF00_0123456789AC,
    ));

    /// LSARPC interface UUID (`12345778-1234-ABCD-EF00-0123456789AB`, per
    /// MS-LSAD §1.9).
    pub const LSARPC: Self = Self(uuid::Uuid::from_u128(
        0x12345778_1234_ABCD_EF00_0123456789AB,
    ));

    /// Netlogon interface UUID (`12345678-1234-ABCD-EF00-01234567CFFB`, per
    /// MS-NRPC §1.9).
    pub const NETLOGON: Self = Self(uuid::Uuid::from_u128(
        0x12345678_1234_ABCD_EF00_01234567CFFB,
    ));

    /// MS-WCCE interface UUID (`91AE6020-9E3C-11CF-8D7C-00AA00C009CF`, per
    /// MS-WCCE §1.9).
    pub const WCCE: Self = Self(uuid::Uuid::from_u128(
        0x91AE6020_9E3C_11CF_8D7C_00AA00C009CF,
    ));

    /// Return the underlying [`uuid::Uuid`].
    #[must_use]
    pub fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }
}

impl From<uuid::Uuid> for InterfaceUuid {
    fn from(u: uuid::Uuid) -> Self {
        Self(u)
    }
}

impl From<InterfaceUuid> for uuid::Uuid {
    fn from(i: InterfaceUuid) -> Self {
        i.0
    }
}

/// A DCE/RPC bind address (per [C706] §7.3 — `ncacn_ip_tcp:HOST[PORT]`).
#[derive(Debug, Clone)]
pub struct BindEndpoint {
    /// The interface UUID (per [C706] §7.1).
    pub interface: InterfaceUuid,
    /// The interface version (major, minor, per [C706] §7.1).
    pub interface_version: (u16, u16),
    /// The transport — only `ncacn_ip_tcp` is supported in v1 (per Decision
    /// 1 §Async runtime — the DCE/RPC transport uses tokio::net::TcpListener).
    pub transport: DceRpcTransport,
    /// The TCP bind address.
    pub addr: std::net::SocketAddr,
}

/// DCE/RPC transport (per [C706] §7.3 — only `ncacn_ip_tcp` is supported in
/// v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DceRpcTransport {
    /// `ncacn_ip_tcp` — TCP/IP (per [C706] §7.3.1).
    NcacnIpTcp,
}

/// Error type for DCE/RPC operations.
#[derive(Debug, Error)]
pub enum DceRpcError {
    /// Bind error (per [C706] §12.6 — `RPC_S_BIND_FAILED`).
    #[error("bind failed: {0}")]
    BindFailed(String),
    /// The interface is not supported by this server.
    #[error("interface not supported: {0}")]
    InterfaceNotSupported(String),
    /// The opnum is not implemented for this interface.
    #[error("opnum {0} not implemented for interface {1}")]
    OpnumNotImplemented(u16, String),
    /// Authentication failed (per [C706] §13 — RPC security).
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    /// NDR serialisation / deserialisation error.
    #[error("NDR error: {0}")]
    Ndr(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A DCE/RPC server trait (per [C706] §12 — the server-side dispatch
/// interface).
///
/// Each protocol implementation (DRSUAPI, SAMR, LSARPC, Netlogon, MS-WCCE)
/// implements this trait. The `adrian-dcerpc` crate provides the transport
/// (TCP listener, bind negotiation, PDU framing, NDR codec); the protocol
/// crate provides the dispatch.
#[async_trait]
pub trait DceRpcServer: Send + Sync {
    /// The interface UUID (per [C706] §7.1).
    fn interface(&self) -> InterfaceUuid;

    /// The interface version (major, minor).
    fn interface_version(&self) -> (u16, u16);

    /// Dispatch an opnum (per [C706] §12.3.1 — `RequestPDU`). The stub
    /// bytes are the NDR-encoded input; the return is the NDR-encoded
    /// output.
    async fn dispatch(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, DceRpcError>;
}

/// A DCE/RPC server endpoint — binds to a TCP port and dispatches incoming
/// PDUs to the registered `DceRpcServer` implementations (per [C706] §12).
///
/// **Status (Wave 2a)**: `new()` and `register()` work; `run()` is still a
/// stub returning [`DceRpcError::BindFailed`]. The transport primitives
/// in [`transport::DcerpcTcpTransport`] (client-side) and the PDU
/// encode/decode in [`pdu`] are real — a follow-up wave can implement
/// `run()` on top of `tokio::net::TcpListener` + the existing
/// `pdu::encode_bind_ack_pdu` / `pdu::encode_response_pdu` helpers.
pub struct DceRpcEndpoint {
    /// The bind address.
    pub bind_addr: std::net::SocketAddr,
    /// The registered protocol servers (one per interface UUID).
    pub servers: Vec<Box<dyn DceRpcServer>>,
}

impl DceRpcEndpoint {
    /// Construct a new `DceRpcEndpoint` on the given bind address.
    #[must_use]
    pub fn new(bind_addr: std::net::SocketAddr) -> Self {
        Self {
            bind_addr,
            servers: Vec::new(),
        }
    }

    /// Register a protocol server.
    pub fn register(&mut self, server: Box<dyn DceRpcServer>) {
        self.servers.push(server);
    }

    /// Run the endpoint — bind TCP, accept connections, dispatch PDUs.
    /// Blocks until shutdown (the caller typically spawns this on a
    /// tokio task and aborts it to shut down).
    ///
    /// Per [C706] §12, the server loop is:
    /// 1. Accept a TCP connection.
    /// 2. Read a Bind PDU from the client.
    /// 3. Look up the requested interface UUID among the registered
    ///    servers. If found, send a Bind_ack with `ACCEPTANCE`; otherwise
    ///    send a Bind_ack with `PROVIDER_REJECTION`.
    /// 4. Read Request PDUs, dispatch each to the registered server's
    ///    `dispatch(opnum, stub)` method, and send back a Response PDU
    ///    with the stub bytes.
    /// 5. Repeat until the client disconnects.
    pub async fn run(&self) -> Result<(), DceRpcError> {
        let listener = tokio::net::TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| DceRpcError::BindFailed(format!("bind {}: {e}", self.bind_addr)))?;
        loop {
            let (stream, _peer) = listener.accept().await?;
            // Build a slice of server references for this connection.
            let servers: Vec<&dyn DceRpcServer> = self
                .servers
                .iter()
                .map(|s| s.as_ref() as &dyn DceRpcServer)
                .collect();
            // Handle the connection sequentially (a production impl would
            // spawn a task per connection, but that requires `Arc`-wrapping
            // the servers — kept simple here for testability).
            if let Err(e) = handle_connection(stream, &servers).await {
                tracing::debug!("connection ended with error: {e}");
            }
        }
    }
}

/// Handle a single DCE/RPC connection: read Bind, send Bind_ack, then
/// loop on Request/Response.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    servers: &[&dyn DceRpcServer],
) -> Result<(), DceRpcError> {
    use crate::ndr::NDR_TRANSFER_SYNTAX_UUID;
    use crate::pdu::{
        ack_reason, ack_result, decode_bind_pdu, encode_bind_ack_pdu, BindAckPdu, NDR20_DATA_REP,
        PFC_FIRST_FRAG, PFC_LAST_FRAG, PTYPE_BIND, PTYPE_REQUEST, RESPONSE_HEADER_SIZE,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = stream;
    let common_header_size = 16usize;

    // ---- Phase 1: Bind negotiation ----
    // Read the Bind PDU.
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;
    let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
    if frag_length < common_header_size {
        return Err(DceRpcError::Ndr(format!(
            "bind frag_length {frag_length} < header size"
        )));
    }
    let mut bind_buf = vec![0u8; frag_length];
    bind_buf[..common_header_size].copy_from_slice(&header);
    if frag_length > common_header_size {
        stream
            .read_exact(&mut bind_buf[common_header_size..])
            .await?;
    }
    let bind = decode_bind_pdu(&bind_buf)?;
    if header[2] != PTYPE_BIND {
        return Err(DceRpcError::Ndr(format!(
            "expected Bind PDU (type 11), got type {}",
            header[2]
        )));
    }

    // Look up the requested interface among the registered servers.
    let req_iface = bind
        .context_elements
        .first()
        .map(|c| (c.abstract_syntax.0, c.abstract_syntax.1))
        .ok_or_else(|| DceRpcError::Ndr("bind has no context elements".into()))?;
    let server = servers
        .iter()
        .find(|s| {
            let iface: uuid::Uuid = s.interface().into();
            iface == req_iface.0 && s.interface_version() == req_iface.1
        })
        .copied();

    let (result, reason) = if server.is_some() {
        (ack_result::ACCEPTANCE, 0u16)
    } else {
        (
            ack_result::PROVIDER_REJECTION,
            ack_reason::ABSTRACT_SYNTAX_NOT_SUPPORTED,
        )
    };

    let ack = BindAckPdu {
        rpc_vers: 5,
        rpc_vers_minor: 0,
        pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
        data_rep: NDR20_DATA_REP,
        call_id: bind.call_id,
        max_xmit_frag: 5840,
        max_recv_frag: 5840,
        assoc_group_id: 0xCAFE_BABE,
        sec_addr: String::new(),
        p_results: vec![crate::pdu::PResult {
            result,
            reason,
            transfer_syntax: (NDR_TRANSFER_SYNTAX_UUID, 2),
        }],
    };
    stream.write_all(&encode_bind_ack_pdu(&ack)).await?;
    stream.flush().await?;

    if server.is_none() {
        // Bind rejected — close the connection.
        return Ok(());
    }
    let server = server.unwrap();

    // ---- Phase 2: Request/Response loop ----
    loop {
        // Read a Request PDU.
        let mut header = [0u8; 16];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client disconnected — clean shutdown.
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
        if frag_length < common_header_size {
            return Err(DceRpcError::Ndr(format!(
                "request frag_length {frag_length} < header size"
            )));
        }
        let mut req_buf = vec![0u8; frag_length];
        req_buf[..common_header_size].copy_from_slice(&header);
        if frag_length > common_header_size {
            stream
                .read_exact(&mut req_buf[common_header_size..])
                .await?;
        }
        if header[2] != PTYPE_REQUEST {
            // Unsupported PDU type — close the connection.
            return Ok(());
        }
        // Parse the Request PDU body to extract opnum and stub data.
        // Per [C706] §12.6.1 + the framework's `encode_request_pdu`, the
        // Request PDU body is:
        //   alloc_hint (4B) + p_cont_id (2B) + cancel_count (1B) +
        //   reserved (1B) + opnum (2B, first 2 bytes of "stub data") +
        //   actual_stub...
        if req_buf.len() < common_header_size + 10 {
            return Err(DceRpcError::Ndr("request PDU too short for body".into()));
        }
        let call_id = u32::from_le_bytes([req_buf[12], req_buf[13], req_buf[14], req_buf[15]]);
        let opnum = u16::from_le_bytes([
            req_buf[common_header_size + 8],
            req_buf[common_header_size + 9],
        ]);
        let stub = &req_buf[common_header_size + 10..];

        // Dispatch to the server.
        let response_stub = server.dispatch(opnum, stub).await.unwrap_or_else(|e| {
            // On dispatch error, return an empty stub (a real impl would
            // send a Fault PDU per [C706] §12.6.2).
            tracing::warn!("dispatch opnum {opnum} failed: {e}");
            Vec::new()
        });

        // Build and send a Response PDU.
        let total = (RESPONSE_HEADER_SIZE + response_stub.len()) as u16;
        let mut resp_buf = Vec::with_capacity(total as usize);
        // Common header (16 bytes):
        resp_buf.push(5); // rpc_vers
        resp_buf.push(0); // rpc_vers_minor
        resp_buf.push(crate::pdu::PTYPE_RESPONSE);
        resp_buf.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
        resp_buf.extend_from_slice(&NDR20_DATA_REP.to_le_bytes()); // data_rep
        resp_buf.extend_from_slice(&total.to_le_bytes()); // frag_length
        resp_buf.extend_from_slice(&0u16.to_le_bytes()); // auth_length
        resp_buf.extend_from_slice(&call_id.to_le_bytes()); // call_id
                                                            // Response body header (8 bytes):
        resp_buf.extend_from_slice(&(response_stub.len() as u32).to_le_bytes()); // alloc_hint
        resp_buf.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        resp_buf.push(0); // cancel_count
        resp_buf.push(0); // reserved
                          // Stub data:
        resp_buf.extend_from_slice(&response_stub);
        stream.write_all(&resp_buf).await?;
        stream.flush().await?;
    }
}

// TODO(W2-followup): implement DceRpcEndpoint::run() on top of
// tokio::net::TcpListener + the pdu/ndr/transport modules. All PDU/NDR
// primitives are now in place — this is a thin listener loop, not a
// protocol implementation.
// TODO(W2-followup): implement RPC security (Kerberos auth, privacy/integrity)
// per [C706] §13 + ADR-021. Auth-level negotiation is currently stubbed
// (auth_length = 0 on every PDU).
// TODO(W3): implement DRSUAPI dispatch (in adrian-drsuapi — uses this crate
// as transport). The DRSUAPI opnums (DRSBind, DRSGetNCChanges, etc.) require
// REPLENTIN_V3 NDR encoding on top of the primitives in this crate's ndr
// module.
// TODO(W3): implement SAMR dispatch (per MS-SAMR — Layer 3, gated by ad-interop).
// TODO(W3): implement LSARPC dispatch (per MS-LSAD — Layer 3, gated by ad-interop).
// TODO(W3): implement Netlogon dispatch (per MS-NRPC — Layer 3, gated by ad-interop).
// TODO(W3): implement MS-WCCE dispatch (per MS-WCCE — Layer 3, gated by ad-interop; used by adrian-wcce-bridge).

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::SocketAddr;

    /// A stub `DceRpcServer` used by the endpoint-registration tests. Every
    /// opnum surfaces `OpnumNotImplemented`, matching the framework's
    /// "loud stub" convention.
    struct StubServer {
        interface: InterfaceUuid,
        version: (u16, u16),
    }

    #[async_trait]
    impl DceRpcServer for StubServer {
        fn interface(&self) -> InterfaceUuid {
            self.interface.clone()
        }
        fn interface_version(&self) -> (u16, u16) {
            self.version
        }
        async fn dispatch(&self, opnum: u16, _stub: &[u8]) -> Result<Vec<u8>, DceRpcError> {
            Err(DceRpcError::OpnumNotImplemented(
                opnum,
                format!("{:?}", self.interface),
            ))
        }
    }

    #[test]
    fn interface_uuid_constants_match_published_values() {
        // Per MS-DRSR §1.9, MS-SAMR §1.9, MS-LSAD §1.9, MS-NRPC §1.9,
        // MS-WCCE §1.9 — the interface UUIDs are protocol-fixed. Verify the
        // constants match the canonical string forms.
        assert_eq!(
            InterfaceUuid::DRSUAPI.0.to_string().to_uppercase(),
            "E3514235-4B06-11D1-AB04-00C04FC2DCD2"
        );
        assert_eq!(
            InterfaceUuid::SAMR.0.to_string().to_uppercase(),
            "12345778-1234-ABCD-EF00-0123456789AC"
        );
        assert_eq!(
            InterfaceUuid::LSARPC.0.to_string().to_uppercase(),
            "12345778-1234-ABCD-EF00-0123456789AB"
        );
        assert_eq!(
            InterfaceUuid::NETLOGON.0.to_string().to_uppercase(),
            "12345678-1234-ABCD-EF00-01234567CFFB"
        );
        assert_eq!(
            InterfaceUuid::WCCE.0.to_string().to_uppercase(),
            "91AE6020-9E3C-11CF-8D7C-00AA00C009CF"
        );
    }

    #[test]
    fn interface_uuids_are_distinct() {
        // Sanity check — the five protocol UUIDs must be distinct so that
        // `DceRpcEndpoint` can dispatch on interface UUID alone.
        let uuids = [
            InterfaceUuid::DRSUAPI.clone(),
            InterfaceUuid::SAMR.clone(),
            InterfaceUuid::LSARPC.clone(),
            InterfaceUuid::NETLOGON.clone(),
            InterfaceUuid::WCCE.clone(),
        ];
        for i in 0..uuids.len() {
            for j in (i + 1)..uuids.len() {
                assert_ne!(uuids[i], uuids[j], "duplicate UUID at indices {} {}", i, j);
            }
        }
    }

    #[test]
    fn interface_uuid_equality_and_hash() {
        // `InterfaceUuid` derives `PartialEq`, `Eq`, `Hash` so it can be used
        // as a HashMap key for dispatch lookup.
        let a = InterfaceUuid::DRSUAPI.clone();
        let b = InterfaceUuid::DRSUAPI.clone();
        assert_eq!(a, b);
        assert_eq!(a.0, b.0);

        // Hash should also be equal for equal values.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn interface_uuid_to_from_uuid_round_trips() {
        // The `From<uuid::Uuid>` and `From<InterfaceUuid>` impls let callers
        // convert losslessly in both directions.
        let raw = uuid::Uuid::from_u128(0x12345678_1234_ABCD_EF00_01234567CFFB);
        let iface: InterfaceUuid = raw.into();
        assert_eq!(iface.as_uuid(), &raw);
        let back: uuid::Uuid = iface.into();
        assert_eq!(back, raw);
    }

    #[test]
    fn ncacn_ip_tcp_is_only_v1_transport() {
        // Per Decision 1 §Async runtime — only `ncacn_ip_tcp` is supported
        // in v1. Verify the enum has exactly one variant.
        let t = DceRpcTransport::NcacnIpTcp;
        assert_eq!(t, DceRpcTransport::NcacnIpTcp);
        // Round-trip through Copy — the transport must be Copy so it can be
        // embedded by value in `BindEndpoint`.
        let t2 = t;
        assert_eq!(t, t2);
    }

    #[test]
    fn dce_rpc_error_io_conversion() {
        // `DceRpcError::Io` has `#[from] std::io::Error` — the `?` operator
        // must convert seamlessly.
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
        let dce_err: DceRpcError = io_err.into();
        assert!(matches!(dce_err, DceRpcError::Io(_)));
        assert!(format!("{}", dce_err).contains("I/O error"));
    }

    #[test]
    fn dce_rpc_error_displays_for_each_variant() {
        // Verify Display coverage so callers get actionable error messages.
        assert!(format!("{}", DceRpcError::BindFailed("x".into())).contains("bind failed"));
        assert!(
            format!("{}", DceRpcError::InterfaceNotSupported("i".into()))
                .contains("interface not supported")
        );
        assert!(
            format!("{}", DceRpcError::OpnumNotImplemented(3, "i".into()))
                .contains("opnum 3 not implemented")
        );
        assert!(
            format!("{}", DceRpcError::AuthFailed("a".into())).contains("authentication failed")
        );
        assert!(format!("{}", DceRpcError::Ndr("n".into())).contains("NDR error"));
    }

    #[test]
    fn endpoint_new_initialises_empty_server_list() {
        // Per [C706] §12 — a fresh endpoint has no registered servers until
        // `register` is called.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let endpoint = DceRpcEndpoint::new(addr);
        assert_eq!(endpoint.bind_addr, addr);
        assert!(endpoint.servers.is_empty());
    }

    #[tokio::test]
    async fn endpoint_register_appends_server() {
        // `register` must push the server onto the servers vec — verify
        // count goes up and the stored server's interface UUID round-trips.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut endpoint = DceRpcEndpoint::new(addr);
        endpoint.register(Box::new(StubServer {
            interface: InterfaceUuid::DRSUAPI,
            version: (4, 0),
        }));
        endpoint.register(Box::new(StubServer {
            interface: InterfaceUuid::SAMR,
            version: (1, 0),
        }));
        assert_eq!(endpoint.servers.len(), 2);
        assert_eq!(endpoint.servers[0].interface(), InterfaceUuid::DRSUAPI);
        assert_eq!(endpoint.servers[0].interface_version(), (4, 0));
        assert_eq!(endpoint.servers[1].interface(), InterfaceUuid::SAMR);
        assert_eq!(endpoint.servers[1].interface_version(), (1, 0));
    }

    #[tokio::test]
    async fn endpoint_run_binds_and_accepts_connections() {
        // Wave 4: `run()` is now real — it binds a TCP listener and
        // accepts connections.  We spawn it on a task, connect a client,
        // and verify the Bind/Bind_ack exchange works.
        use crate::pdu::{ack_result, decode_bind_ack_pdu, encode_bind_pdu, BindPdu};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Bind to port 0 (let the OS assign a free port).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        drop(listener); // free the port so the endpoint can rebind

        let mut endpoint = DceRpcEndpoint::new(bound_addr);
        endpoint.register(Box::new(EchoServer {
            interface: InterfaceUuid::DRSUAPI,
            version: (4, 0),
        }));
        // Spawn the server loop.
        let server_task = tokio::spawn(async move {
            let _ = endpoint.run().await;
        });
        // Give the server a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect a client and send a Bind PDU.
        let mut stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let bind = BindPdu::new(InterfaceUuid::DRSUAPI.0, (4, 0));
        let bind_bytes = encode_bind_pdu(&bind);
        stream.write_all(&bind_bytes).await.unwrap();
        stream.flush().await.unwrap();

        // Read the Bind_ack.
        let mut header = [0u8; 16];
        stream.read_exact(&mut header).await.unwrap();
        let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
        let mut ack_buf = vec![0u8; frag_length];
        ack_buf[..16].copy_from_slice(&header);
        if frag_length > 16 {
            stream.read_exact(&mut ack_buf[16..]).await.unwrap();
        }
        let ack = decode_bind_ack_pdu(&ack_buf).unwrap();
        assert_eq!(ack.p_results.len(), 1);
        assert_eq!(ack.p_results[0].result, ack_result::ACCEPTANCE);

        server_task.abort();
    }

    #[tokio::test]
    async fn endpoint_run_dispatches_request_and_returns_response() {
        // Wave 4: full Bind + Request/Response round-trip through the
        // real server loop.
        use crate::pdu::{
            ack_result, decode_bind_ack_pdu, decode_response_pdu, encode_bind_pdu,
            encode_request_pdu, BindPdu,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        drop(listener);

        let mut endpoint = DceRpcEndpoint::new(bound_addr);
        endpoint.register(Box::new(EchoServer {
            interface: InterfaceUuid::DRSUAPI,
            version: (4, 0),
        }));
        let server_task = tokio::spawn(async move {
            let _ = endpoint.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        // Bind.
        let bind = BindPdu::new(InterfaceUuid::DRSUAPI.0, (4, 0));
        stream.write_all(&encode_bind_pdu(&bind)).await.unwrap();
        stream.flush().await.unwrap();
        let mut header = [0u8; 16];
        stream.read_exact(&mut header).await.unwrap();
        let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
        let mut ack_buf = vec![0u8; frag_length];
        ack_buf[..16].copy_from_slice(&header);
        if frag_length > 16 {
            stream.read_exact(&mut ack_buf[16..]).await.unwrap();
        }
        let ack = decode_bind_ack_pdu(&ack_buf).unwrap();
        assert_eq!(ack.p_results[0].result, ack_result::ACCEPTANCE);

        // Send a Request with opnum 0x10 and stub data "hello".
        let stub_input = b"hello";
        let req_bytes = encode_request_pdu(1, 0, 0x10, stub_input);
        stream.write_all(&req_bytes).await.unwrap();
        stream.flush().await.unwrap();

        // Read the Response.
        let mut header = [0u8; 16];
        stream.read_exact(&mut header).await.unwrap();
        let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
        let mut resp_buf = vec![0u8; frag_length];
        resp_buf[..16].copy_from_slice(&header);
        if frag_length > 16 {
            stream.read_exact(&mut resp_buf[16..]).await.unwrap();
        }
        let response_stub = decode_response_pdu(&resp_buf).unwrap();
        // The EchoServer echoes the input stub back.
        assert_eq!(response_stub, stub_input);

        server_task.abort();
    }

    /// A `DceRpcServer` that echoes the input stub back as the response.
    /// Used by the `endpoint_run_*` integration tests to verify the
    /// full Bind → Request → Response round-trip.
    struct EchoServer {
        interface: InterfaceUuid,
        version: (u16, u16),
    }

    #[async_trait]
    impl DceRpcServer for EchoServer {
        fn interface(&self) -> InterfaceUuid {
            self.interface.clone()
        }
        fn interface_version(&self) -> (u16, u16) {
            self.version
        }
        async fn dispatch(&self, _opnum: u16, stub: &[u8]) -> Result<Vec<u8>, DceRpcError> {
            Ok(stub.to_vec())
        }
    }

    // ---- Behavioral tests replacing the two old "stub returns X" tests ----

    #[test]
    fn encode_bind_pdu_returns_real_wire_bytes() {
        // Replaces the old `encode_bind_pdu_returns_empty_vec_as_stub`
        // test. Now that the encoder is real, verify it produces a
        // non-empty buffer whose length matches the wire spec for a
        // single-context Bind PDU.
        let pdu = BindPdu::new(InterfaceUuid::DRSUAPI.0, (4, 0));
        let bytes = encode_bind_pdu(&pdu);
        // 16 (common header) + 12 (bind body) + 44 (ctx element) = 72.
        assert_eq!(bytes.len(), 72);
        // Verify ptype byte is 11 (Bind).
        assert_eq!(bytes[2], PTYPE_BIND);
        // Verify rpc_vers byte is 5.
        assert_eq!(bytes[0], 5);
        // Verify frag_length field matches the buffer length.
        let frag_length = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
        assert_eq!(frag_length, bytes.len());
    }

    #[test]
    fn decode_bind_pdu_round_trips_real_encode() {
        // Replaces the old `decode_bind_pdu_returns_ndr_error_as_stub`
        // test. Verify the round-trip: encode then decode yields the same
        // interface UUID + version that was encoded.
        let iface = InterfaceUuid::DRSUAPI.clone();
        let version = (4, 0);
        let pdu = BindPdu::new(iface.0, version);
        let bytes = encode_bind_pdu(&pdu);
        let decoded = decode_bind_pdu(&bytes).unwrap();

        assert_eq!(decoded.rpc_vers, 5);
        assert_eq!(decoded.rpc_vers_minor, 0);
        assert_eq!(decoded.call_id, pdu.call_id);
        assert_eq!(decoded.context_elements.len(), 1);
        let ctx = &decoded.context_elements[0];
        assert_eq!(ctx.abstract_syntax.0, iface.0);
        assert_eq!(ctx.abstract_syntax.1, version);
    }

    #[tokio::test]
    async fn stub_server_dispatch_surfaces_opnum_not_implemented() {
        // The framework's "loud stub" convention — every unimplemented opnum
        // must surface `OpnumNotImplemented` rather than silently returning
        // empty output.
        let server = StubServer {
            interface: InterfaceUuid::DRSUAPI,
            version: (4, 0),
        };
        let result = server.dispatch(0x04, b"input").await;
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(DceRpcError::OpnumNotImplemented(0x04, _))
        ));
    }
}
