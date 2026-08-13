//! Async DCE/RPC TCP transport (`ncacn_ip_tcp`).
//!
//! Wraps any `AsyncRead + AsyncWrite + Unpin` stream (e.g.
//! `tokio::net::TcpStream` for real network, `tokio::io::duplex` for
//! unit tests) and frames PDUs per [C706] §12.6.1.
//!
//! Only the client-side transport is implemented in v1. The server
//! endpoint (`DceRpcEndpoint::run`) is deferred to a later wave that
//! also implements Fault / Bind_nak / Alter_context dispatch.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::pdu::{self, ack_result, BindAckPdu, BindPdu, COMMON_HEADER_SIZE};
use crate::DceRpcError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// An async DCE/RPC transport over `ncacn_ip_tcp`.
///
/// Generic over the stream type so that tests can use
/// `tokio::io::duplex` instead of a real TCP socket. The default
/// concrete type is `DcerpcTcpTransport<TcpStream>` (real network).
pub struct DcerpcTcpTransport<S> {
    stream: S,
    call_id_counter: u32,
}

impl DcerpcTcpTransport<TcpStream> {
    /// Connect to `addr` (e.g. `"127.0.0.1:135"` for the endpoint mapper,
    /// or `"dc01.example.com:49152"` for a dynamic DRSUAPI port) and
    /// return a transport.
    pub async fn connect(addr: &str) -> Result<Self, DceRpcError> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            stream,
            call_id_counter: 0,
        })
    }
}

impl<S> DcerpcTcpTransport<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    /// Construct a transport over an existing stream (used by tests with
    /// `tokio::io::duplex`).
    #[must_use]
    pub fn from_stream(stream: S) -> Self {
        Self {
            stream,
            call_id_counter: 0,
        }
    }

    /// Borrow the underlying stream (e.g. for graceful shutdown).
    #[must_use]
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Consume the transport and return the underlying stream.
    pub fn into_stream(self) -> S {
        self.stream
    }

    fn next_call_id(&mut self) -> u32 {
        self.call_id_counter = self.call_id_counter.wrapping_add(1);
        self.call_id_counter
    }

    /// Send a Bind PDU and await a Bind_ack.
    ///
    /// If the server rejects the bind (`ack_result != ACCEPTANCE` for any
    /// context), returns [`DceRpcError::InterfaceNotSupported`].
    pub async fn send_bind(&mut self, pdu: &BindPdu) -> Result<BindAckPdu, DceRpcError> {
        let bytes = pdu::encode_bind_pdu(pdu);
        self.stream.write_all(&bytes).await?;
        let resp = self.read_pdu().await?;
        let ack = pdu::decode_bind_ack_pdu(&resp)?;
        // Check that the server accepted the bind for every context.
        for r in &ack.p_results {
            if r.result != ack_result::ACCEPTANCE {
                return Err(DceRpcError::InterfaceNotSupported(format!(
                    "bind rejected by server: result={} reason={} (call_id={})",
                    r.result, r.reason, ack.call_id
                )));
            }
        }
        Ok(ack)
    }

    /// Send a Request PDU and await a Response PDU. Returns the stub
    /// data bytes from the response (the bytes after the Response body
    /// header, per [C706] §12.6.1).
    ///
    /// The `opnum` is encoded as the first 2 bytes of the stub data per
    /// IDL contract (see [`pdu::encode_request_pdu`] for the wire layout).
    pub async fn send_request(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, DceRpcError> {
        let call_id = self.next_call_id();
        let req = pdu::encode_request_pdu(call_id, 0, opnum, stub);
        self.stream.write_all(&req).await?;
        let resp = self.read_pdu().await?;
        pdu::decode_response_pdu(&resp)
    }

    /// Read a single complete PDU from the stream. The PDU's `frag_length`
    /// field tells us how many bytes to read in total; we read the 16-byte
    /// common header first, then the remaining `frag_length - 16` bytes
    /// of the body.
    pub async fn read_pdu(&mut self) -> Result<Vec<u8>, DceRpcError> {
        let mut header = [0u8; COMMON_HEADER_SIZE];
        self.stream.read_exact(&mut header).await?;
        let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
        if frag_length < COMMON_HEADER_SIZE {
            return Err(DceRpcError::Ndr(format!(
                "frag_length {frag_length} < common header size {COMMON_HEADER_SIZE}"
            )));
        }
        let mut buf = vec![0u8; frag_length];
        buf[..COMMON_HEADER_SIZE].copy_from_slice(&header);
        if frag_length > COMMON_HEADER_SIZE {
            self.stream
                .read_exact(&mut buf[COMMON_HEADER_SIZE..])
                .await?;
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndr::NDR_TRANSFER_SYNTAX_UUID;
    use crate::pdu::{
        ack_reason, NDR20_DATA_REP, PFC_FIRST_FRAG, PFC_LAST_FRAG, PTYPE_RESPONSE,
        RESPONSE_HEADER_SIZE,
    };
    use tokio::io::duplex;
    use uuid::Uuid;

    fn drsuapi_iface() -> Uuid {
        Uuid::from_u128(0xE3514235_4B06_11D1_AB04_00C04FC2DCD2)
    }

    /// Construct a server-side task that:
    /// - Reads a Bind PDU from the client.
    /// - Sends a Bind_ack with `ACCEPTANCE` for the requested interface.
    /// - Reads a Request PDU.
    /// - Sends a Response PDU echoing the stub data back to the client.
    async fn server_handle_bind_and_request(
        mut server_rx: impl tokio::io::AsyncRead + Unpin,
        mut server_tx: impl tokio::io::AsyncWrite + Unpin,
        response_stub: Vec<u8>,
    ) {
        let mut header = [0u8; COMMON_HEADER_SIZE];
        server_rx.read_exact(&mut header).await.unwrap();
        let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
        let mut bind_buf = vec![0u8; frag_length];
        bind_buf[..COMMON_HEADER_SIZE].copy_from_slice(&header);
        if frag_length > COMMON_HEADER_SIZE {
            server_rx
                .read_exact(&mut bind_buf[COMMON_HEADER_SIZE..])
                .await
                .unwrap();
        }
        let bind = pdu::decode_bind_pdu(&bind_buf).unwrap();
        assert_eq!(bind.ptype(), crate::pdu::PTYPE_BIND);

        let ack = BindAckPdu {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            data_rep: NDR20_DATA_REP,
            call_id: bind.call_id,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0xCAFE_BABE,
            sec_addr: "49152".to_string(),
            p_results: vec![crate::pdu::PResult {
                result: ack_result::ACCEPTANCE,
                reason: 0,
                transfer_syntax: (NDR_TRANSFER_SYNTAX_UUID, 2),
            }],
        };
        let ack_bytes = pdu::encode_bind_ack_pdu(&ack);
        server_tx.write_all(&ack_bytes).await.unwrap();
        server_tx.flush().await.unwrap();

        let mut header = [0u8; COMMON_HEADER_SIZE];
        server_rx.read_exact(&mut header).await.unwrap();
        let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
        let mut req_buf = vec![0u8; frag_length];
        req_buf[..COMMON_HEADER_SIZE].copy_from_slice(&header);
        if frag_length > COMMON_HEADER_SIZE {
            server_rx
                .read_exact(&mut req_buf[COMMON_HEADER_SIZE..])
                .await
                .unwrap();
        }
        assert_eq!(req_buf[2], crate::pdu::PTYPE_REQUEST);
        let call_id = u32::from_le_bytes([req_buf[12], req_buf[13], req_buf[14], req_buf[15]]);

        let total = (RESPONSE_HEADER_SIZE + response_stub.len()) as u16;
        let mut resp_buf = Vec::with_capacity(total as usize);
        resp_buf.push(5);
        resp_buf.push(0);
        resp_buf.push(PTYPE_RESPONSE);
        resp_buf.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
        resp_buf.extend_from_slice(&NDR20_DATA_REP.to_le_bytes());
        resp_buf.extend_from_slice(&total.to_le_bytes());
        resp_buf.extend_from_slice(&0u16.to_le_bytes());
        resp_buf.extend_from_slice(&call_id.to_le_bytes());
        resp_buf.extend_from_slice(&(response_stub.len() as u32).to_le_bytes());
        resp_buf.extend_from_slice(&0u16.to_le_bytes());
        resp_buf.push(0);
        resp_buf.push(0);
        resp_buf.extend_from_slice(&response_stub);
        server_tx.write_all(&resp_buf).await.unwrap();
        server_tx.flush().await.unwrap();
    }

    #[tokio::test]
    async fn transport_send_bind_round_trips_via_duplex() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_rx, server_tx) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            server_handle_bind_and_request(server_rx, server_tx, vec![]).await;
        });

        let mut transport = DcerpcTcpTransport::from_stream(client_stream);
        let bind = BindPdu::new(drsuapi_iface(), (4, 0));
        let ack = transport.send_bind(&bind).await.unwrap();

        assert_eq!(ack.call_id, bind.call_id);
        assert_eq!(ack.assoc_group_id, 0xCAFE_BABE);
        assert_eq!(ack.p_results.len(), 1);
        assert_eq!(ack.p_results[0].result, ack_result::ACCEPTANCE);

        // The server task is still waiting for a request PDU (which this
        // test does not send — it only verifies the bind round-trip). Give
        // it a brief grace window, then abort it; we only care that the
        // bind/ack pipeline works end-to-end.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), server_task).await;
    }

    #[tokio::test]
    async fn transport_send_request_returns_stub_data() {
        let (client_stream, server_stream) = duplex(4096);
        let (server_rx, server_tx) = tokio::io::split(server_stream);

        let expected_response = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let server_response = expected_response.clone();
        let server_task = tokio::spawn(async move {
            server_handle_bind_and_request(server_rx, server_tx, server_response).await;
        });

        let mut transport = DcerpcTcpTransport::from_stream(client_stream);
        transport
            .send_bind(&BindPdu::new(drsuapi_iface(), (4, 0)))
            .await
            .unwrap();
        let stub_input = b"hello";
        let response = transport.send_request(4, stub_input).await.unwrap();
        assert_eq!(response, expected_response);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn transport_send_bind_surfaces_interface_not_supported_on_rejection() {
        let (client_stream, server_stream) = duplex(4096);
        let (mut server_rx, mut server_tx) = tokio::io::split(server_stream);

        let server_task = tokio::spawn(async move {
            let mut header = [0u8; COMMON_HEADER_SIZE];
            server_rx.read_exact(&mut header).await.unwrap();
            let frag_length = u16::from_le_bytes([header[8], header[9]]) as usize;
            let mut buf = vec![0u8; frag_length];
            buf[..COMMON_HEADER_SIZE].copy_from_slice(&header);
            if frag_length > COMMON_HEADER_SIZE {
                server_rx
                    .read_exact(&mut buf[COMMON_HEADER_SIZE..])
                    .await
                    .unwrap();
            }
            let bind = pdu::decode_bind_pdu(&buf).unwrap();
            let ack = BindAckPdu {
                rpc_vers: 5,
                rpc_vers_minor: 0,
                pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
                data_rep: NDR20_DATA_REP,
                call_id: bind.call_id,
                max_xmit_frag: 4280,
                max_recv_frag: 4280,
                assoc_group_id: 0,
                sec_addr: String::new(),
                p_results: vec![crate::pdu::PResult {
                    result: ack_result::PROVIDER_REJECTION,
                    reason: ack_reason::ABSTRACT_SYNTAX_NOT_SUPPORTED,
                    transfer_syntax: (Uuid::nil(), 0),
                }],
            };
            server_tx
                .write_all(&pdu::encode_bind_ack_pdu(&ack))
                .await
                .unwrap();
            server_tx.flush().await.unwrap();
        });

        let mut transport = DcerpcTcpTransport::from_stream(client_stream);
        let result = transport
            .send_bind(&BindPdu::new(drsuapi_iface(), (4, 0)))
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DceRpcError::InterfaceNotSupported(_)));
        assert!(format!("{err}").contains("bind rejected"));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn transport_read_pdu_handles_multiple_frags_in_stream() {
        let (client_stream, mut server_stream) = duplex(4096);

        let ack1 = BindAckPdu {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            pfc_flags: PFC_FIRST_FRAG | PFC_LAST_FRAG,
            data_rep: NDR20_DATA_REP,
            call_id: 1,
            max_xmit_frag: 5840,
            max_recv_frag: 5840,
            assoc_group_id: 0,
            sec_addr: String::new(),
            p_results: vec![crate::pdu::PResult {
                result: ack_result::ACCEPTANCE,
                reason: 0,
                transfer_syntax: (NDR_TRANSFER_SYNTAX_UUID, 2),
            }],
        };
        let ack2 = BindAckPdu {
            call_id: 2,
            ..ack1.clone()
        };
        let bytes1 = pdu::encode_bind_ack_pdu(&ack1);
        let bytes2 = pdu::encode_bind_ack_pdu(&ack2);
        let mut combined = Vec::new();
        combined.extend_from_slice(&bytes1);
        combined.extend_from_slice(&bytes2);
        server_stream.write_all(&combined).await.unwrap();
        server_stream.flush().await.unwrap();

        let mut transport = DcerpcTcpTransport::from_stream(client_stream);
        let p1 = transport.read_pdu().await.unwrap();
        let p2 = transport.read_pdu().await.unwrap();
        assert_eq!(p1.len(), bytes1.len());
        assert_eq!(p2.len(), bytes2.len());
        let decoded1 = pdu::decode_bind_ack_pdu(&p1).unwrap();
        let decoded2 = pdu::decode_bind_ack_pdu(&p2).unwrap();
        assert_eq!(decoded1.call_id, 1);
        assert_eq!(decoded2.call_id, 2);
    }

    #[tokio::test]
    async fn transport_read_pdu_errors_on_short_header() {
        let (client_stream, mut server_stream) = duplex(4096);
        server_stream.write_all(&[0u8; 4]).await.unwrap();
        drop(server_stream);

        let mut transport = DcerpcTcpTransport::from_stream(client_stream);
        let result = transport.read_pdu().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(DceRpcError::Io(_))));
    }

    #[tokio::test]
    async fn transport_read_pdu_errors_on_frag_length_below_header_size() {
        let (client_stream, mut server_stream) = duplex(4096);
        let mut malformed = vec![0u8; 16];
        malformed[8] = 5;
        malformed[9] = 0;
        server_stream.write_all(&malformed).await.unwrap();
        server_stream.flush().await.unwrap();
        drop(server_stream);

        let mut transport = DcerpcTcpTransport::from_stream(client_stream);
        let result = transport.read_pdu().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(DceRpcError::Ndr(_))));
        assert!(format!("{}", result.unwrap_err()).contains("frag_length"));
    }

    #[tokio::test]
    async fn transport_into_stream_returns_underlying_stream() {
        let (client_stream, _server_stream) = duplex(4096);
        let transport = DcerpcTcpTransport::from_stream(client_stream);
        let _stream = transport.into_stream();
    }
}
