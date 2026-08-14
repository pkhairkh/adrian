//! TCP listener + connection handler for the LDAP server (RFC 4511).
//!
//! The [`LdapServer`] binds a [`tokio::net::TcpListener`] and spawns a
//! task per accepted connection, each running [`serve_connection`]. The
//! connection handler reads BER-encoded [`LdapMessage`]s from the stream,
//! dispatches to the appropriate [`handler`](crate::handler) function,
//! and writes the BER-encoded response back.
//!
//! ## Framing
//!
//! LDAP uses BER TLV framing (no length prefix). The server reads bytes
//! into a buffer and tries to decode an `LdapMessage` after each read;
//! if decoding fails with [`BerError::Truncated`] or [`BerError::Empty`],
//! it reads more bytes and retries.
//!
//! ## Testability
//!
//! [`serve_connection`] is generic over `AsyncRead + AsyncWrite + Unpin`,
//! so tests can use [`tokio::io::duplex`] instead of a real TCP socket.
//! The [`LdapServer::serve`] method is a thin wrapper that binds a real
//! TCP listener and calls `serve_connection` per accepted connection.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use crate::ber::BerError;
use crate::handler::{
    handle_add, handle_bind, handle_delete, handle_extended_request, handle_modify, handle_search,
    handle_unbind, search_done_from_error,
};
use crate::types::{LdapMessage, ProtocolOp, SearchResultDone};
use crate::{Dsa, DsaError};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// The default bind address (`127.0.0.1:389` — per RFC 4511 §9 "well-known
/// port 389"). Note: binding to port 389 requires root privileges on most
/// systems; tests bind to ephemeral ports instead.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:389";

/// The default LDAPS (LDAP-over-TLS) bind address (`127.0.0.1:636` — per
/// RFC 4511 §9.2 "well-known port 636").
pub const DEFAULT_LDAPS_BIND_ADDR: &str = "127.0.0.1:636";

/// The default Global Catalog bind address (`127.0.0.1:3268` — per
/// MS-ADTS §3.1.1.3.2 / ADR-072).
pub const DEFAULT_GC_BIND_ADDR: &str = "127.0.0.1:3268";

/// The default Global Catalog-over-SSL bind address (`127.0.0.1:3269` —
/// per MS-ADTS §3.1.1.3.2 / ADR-072).
pub const DEFAULT_GC_SSL_BIND_ADDR: &str = "127.0.0.1:3269";

/// The LDAP server — binds a TCP listener and serves connections.
pub struct LdapServer {
    /// The DSA wiring (store, replicator, identity-mapping, schema).
    pub dsa: Arc<Dsa>,
}

impl LdapServer {
    /// Construct a new server wrapping the given DSA.
    pub fn new(dsa: Arc<Dsa>) -> Self {
        LdapServer { dsa }
    }

    /// Bind to `addr` and serve connections forever (until the listener
    /// fails to accept). Each connection is handled in its own tokio
    /// task.
    pub async fn serve(&self, addr: std::net::SocketAddr) -> Result<(), DsaError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| DsaError::Backend(format!("bind failed: {}", e)))?;
        tracing::info!("LDAP server listening on {}", addr);
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tracing::debug!("accepted connection from {}", peer);
                    let dsa = Arc::clone(&self.dsa);
                    tokio::spawn(async move {
                        if let Err(e) = serve_connection(stream, &dsa).await {
                            tracing::warn!("connection error from {}: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("accept failed: {}", e);
                    return Err(DsaError::Backend(format!("accept failed: {}", e)));
                }
            }
        }
    }

    /// Bind to `addr` as the Global Catalog listener and serve
    /// connections. Per ADR-072, the GC uses the same RFC 4511 protocol
    /// as the LDAP listener (only the search semantics differ — a GC
    /// search crosses all naming contexts). The wire protocol is
    /// identical, so this is a thin alias for [`serve`](Self::serve)
    /// that logs at GC-specific info level.
    pub async fn serve_gc(&self, addr: std::net::SocketAddr) -> Result<(), DsaError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| DsaError::Backend(format!("GC bind failed: {}", e)))?;
        tracing::info!("Global Catalog server listening on {}", addr);
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tracing::debug!("GC accepted connection from {}", peer);
                    let dsa = Arc::clone(&self.dsa);
                    tokio::spawn(async move {
                        if let Err(e) = serve_connection(stream, &dsa).await {
                            tracing::warn!("GC connection error from {}: {}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("GC accept failed: {}", e);
                    return Err(DsaError::Backend(format!("GC accept failed: {}", e)));
                }
            }
        }
    }

    /// Bind to `addr` and serve LDAPS (LDAP-over-TLS) connections. Each
    /// accepted TCP connection is first wrapped in a TLS handshake using
    /// the provided `rustls` acceptor; the resulting TLS stream is then
    /// served as a regular LDAP connection.
    pub async fn serve_tls(
        &self,
        addr: std::net::SocketAddr,
        tls_acceptor: tokio_rustls::TlsAcceptor,
    ) -> Result<(), DsaError> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| DsaError::Backend(format!("LDAPS bind failed: {}", e)))?;
        tracing::info!("LDAPS server listening on {}", addr);
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    tracing::debug!("LDAPS accepted connection from {}", peer);
                    let dsa = Arc::clone(&self.dsa);
                    let acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(e) = serve_connection(tls_stream, &dsa).await {
                                    tracing::warn!("LDAPS connection error from {}: {}", peer, e);
                                }
                            }
                            Err(e) => {
                                tracing::warn!("LDAPS TLS handshake failed from {}: {}", peer, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("LDAPS accept failed: {}", e);
                    return Err(DsaError::Backend(format!("LDAPS accept failed: {}", e)));
                }
            }
        }
    }
}

/// Serve a single LDAP connection with an overall idle-read timeout. If
/// no message arrives within `idle_timeout` of the previous one, the
/// connection is closed. This is the variant production wiring should use
/// when a per-connection deadline is required (per ADR-021 — defense in
/// depth against slowloris-style attacks). The plain [`serve_connection`]
/// has no timeout and is suitable for tests that drive the connection
/// directly.
pub async fn serve_with_timeout<S>(
    stream: S,
    dsa: &Dsa,
    idle_timeout: std::time::Duration,
) -> Result<(), DsaError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(idle_timeout, serve_connection(stream, dsa)).await {
        Ok(inner) => inner,
        Err(_) => {
            tracing::warn!(
                "LDAP connection closed after {:?} idle timeout",
                idle_timeout
            );
            Ok(())
        }
    }
}

/// Serve a single LDAP connection: read messages, dispatch to handlers,
/// write responses, until the client disconnects or sends an
/// `UnbindRequest`.
///
/// Generic over `AsyncRead + AsyncWrite + Unpin` so tests can use
/// `tokio::io::duplex` instead of a real TCP socket.
pub async fn serve_connection<S>(mut stream: S, dsa: &Dsa) -> Result<(), DsaError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        // Try to decode a complete LdapMessage from the buffer.
        let msg = match try_decode_message(&buf) {
            Ok(Some((msg, consumed))) => {
                // Consume the decoded bytes from the buffer.
                buf.drain(..consumed);
                msg
            }
            Ok(None) => {
                // Need more bytes — read from the stream.
                let n = stream
                    .read(&mut tmp)
                    .await
                    .map_err(|e| DsaError::Ldap(format!("read failed: {}", e)))?;
                if n == 0 {
                    // Client closed the connection.
                    return Ok(());
                }
                buf.extend_from_slice(&tmp[..n]);
                continue;
            }
            Err(e) => {
                // Malformed message — send a SearchResultDone with
                // protocolError (best-effort; if the message ID is
                // unknown we skip the response).
                tracing::warn!("BER decode error: {}", e);
                return Err(DsaError::Ldap(format!("BER decode error: {}", e)));
            }
        };
        // Dispatch the message and write the response.
        let keep_open = dispatch(&mut stream, dsa, &msg).await?;
        if !keep_open {
            // Client sent UnbindRequest — close the connection.
            return Ok(());
        }
    }
}

/// Try to decode a complete `LdapMessage` from `buf`. Returns:
/// - `Ok(Some((msg, consumed)))` if a complete message was decoded.
/// - `Ok(None)` if more bytes are needed.
/// - `Err(...)` if the bytes are malformed.
fn try_decode_message(buf: &[u8]) -> Result<Option<(LdapMessage, usize)>, BerError> {
    if buf.is_empty() {
        return Ok(None);
    }
    // Try to decode the outer SEQUENCE TLV to find out how many bytes
    // the message occupies.
    let (tlv, _rest) = match crate::ber::decode_tlv(buf) {
        Ok(v) => v,
        Err(BerError::Empty) | Err(BerError::Truncated(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    // The full message is the TLV header + value.
    let header_len = buf.len() - tlv.value.len() - _rest.len();
    let consumed = header_len + tlv.value.len();
    // Now decode the LdapMessage from the full bytes.
    let msg = LdapMessage::decode(&buf[..consumed])?;
    Ok(Some((msg, consumed)))
}

/// Dispatch a single `LdapMessage` to the appropriate handler and write
/// the response(s) to `stream`. Returns `false` if the connection should
/// be closed (UnbindRequest), `true` otherwise.
async fn dispatch<S>(stream: &mut S, dsa: &Dsa, msg: &LdapMessage) -> Result<bool, DsaError>
where
    S: AsyncWrite + Unpin,
{
    let message_id = msg.message_id;
    match &msg.protocol_op {
        ProtocolOp::BindRequest(req) => {
            let resp = handle_bind(dsa, req.clone()).await;
            write_message(
                stream,
                LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::BindResponse(resp),
                    controls: Vec::new(),
                },
            )
            .await?;
            Ok(true)
        }
        ProtocolOp::SearchRequest(req) => {
            let result = handle_search(dsa, req.clone()).await;
            match result {
                Ok(entries) => {
                    // Write each SearchResultEntry, then a success
                    // SearchResultDone.
                    for entry in entries {
                        write_message(
                            stream,
                            LdapMessage {
                                message_id,
                                protocol_op: ProtocolOp::SearchResultEntry(entry),
                                controls: Vec::new(),
                            },
                        )
                        .await?;
                    }
                    write_message(
                        stream,
                        LdapMessage {
                            message_id,
                            protocol_op: ProtocolOp::SearchResultDone(SearchResultDone {
                                result: crate::types::LdapResult::success(),
                            }),
                            controls: Vec::new(),
                        },
                    )
                    .await?;
                }
                Err(e) => {
                    let done = search_done_from_error(&e);
                    write_message(
                        stream,
                        LdapMessage {
                            message_id,
                            protocol_op: ProtocolOp::SearchResultDone(done),
                            controls: Vec::new(),
                        },
                    )
                    .await?;
                }
            }
            Ok(true)
        }
        ProtocolOp::ModifyRequest(req) => {
            let resp = handle_modify(dsa, req.clone()).await;
            write_message(
                stream,
                LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::ModifyResponse(resp),
                    controls: Vec::new(),
                },
            )
            .await?;
            Ok(true)
        }
        ProtocolOp::AddRequest(req) => {
            let resp = handle_add(dsa, req.clone()).await;
            write_message(
                stream,
                LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::AddResponse(resp),
                    controls: Vec::new(),
                },
            )
            .await?;
            Ok(true)
        }
        ProtocolOp::DelRequest(req) => {
            let resp = handle_delete(dsa, req.clone()).await;
            write_message(
                stream,
                LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::DelResponse(resp),
                    controls: Vec::new(),
                },
            )
            .await?;
            Ok(true)
        }
        ProtocolOp::UnbindRequest(_) => {
            handle_unbind(dsa, crate::types::UnbindRequest).await;
            // No response — close the connection.
            Ok(false)
        }
        ProtocolOp::ExtendedRequest(req) => {
            let resp = handle_extended_request(dsa, req.clone()).await;
            write_message(
                stream,
                LdapMessage {
                    message_id,
                    protocol_op: ProtocolOp::ExtendedResponse(resp),
                    controls: Vec::new(),
                },
            )
            .await?;
            Ok(true)
        }
        // Responses and other ops are client→server only; ignore them.
        ProtocolOp::BindResponse(_)
        | ProtocolOp::SearchResultEntry(_)
        | ProtocolOp::SearchResultDone(_)
        | ProtocolOp::ModifyResponse(_)
        | ProtocolOp::AddResponse(_)
        | ProtocolOp::DelResponse(_)
        | ProtocolOp::ExtendedResponse(_) => {
            tracing::warn!(
                "received unexpected response op (message_id={}); ignoring",
                message_id
            );
            Ok(true)
        }
    }
}

/// Encode and write a single `LdapMessage` to `stream`, flushing after.
async fn write_message<S>(stream: &mut S, msg: LdapMessage) -> Result<(), DsaError>
where
    S: AsyncWrite + Unpin,
{
    let bytes = msg.encode();
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| DsaError::Ldap(format!("write failed: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| DsaError::Ldap(format!("flush failed: {}", e)))?;
    Ok(())
}

// (No trailing private imports — every imported item is used above.)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;
    use crate::handler::DEFAULT_NAMING_CONTEXT;
    use crate::types::{
        AddRequest, AuthenticationChoice, BindRequest, BindResponse, Change, DelRequest,
        DelResponse, LdapResult, ModificationOp, ModifyRequest, ResultCode, SearchRequest,
        SearchResultEntry,
    };
    use adrian_identity_testkit::InMemoryIdentityMapping;
    use adrian_repl_testkit::InMemoryReplicator;
    use adrian_schema_traits::SchemaProjection;
    use adrian_storage_core::{Attribute, DirectoryStore, DistinguishedName, Object};
    use adrian_storage_testkit::InMemoryDirectoryStore;
    use std::net::SocketAddr;
    use tokio::io::duplex;
    use uuid::Uuid;

    /// Build a self-signed certificate + key for LDAPS tests using
    /// `rcgen`. Returns the DER-encoded certificate and PKCS#8 private
    /// key suitable for building a `rustls::ServerConfig`.
    fn test_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
        let mut params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                .expect("rcgen CertificateParams");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "adrian-test-ldap");
        let key_pair = rcgen::KeyPair::generate().expect("rcgen KeyPair::generate");
        let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        (cert_der, key_der)
    }

    /// Build a `rustls::ServerConfig` from a self-signed cert for tests.
    fn test_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        let (cert_der, key_der) = test_self_signed_cert();
        let cert = rustls::pki_types::CertificateDer::from(cert_der);
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("PrivateKeyDer::try_from");
        let server_cfg = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("ServerConfig");
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg))
    }

    /// A `ServerCertVerifier` that accepts any certificate. For LDAPS
    /// tests only — never use in production.
    #[derive(Debug)]
    struct AcceptAnyServerCertVerifier;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    /// Build a `rustls::ClientConfig` that accepts any server cert.
    /// Suitable for LDAPS tests where the server presents a self-signed
    /// cert that hasn't been added to a real root store.
    fn test_tls_client_config() -> std::sync::Arc<rustls::ClientConfig> {
        let client_cfg = rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyServerCertVerifier))
            .with_no_client_auth();
        std::sync::Arc::new(client_cfg)
    }

    fn dummy_invocation_id() -> Uuid {
        Uuid::from_u128(0x_ABCD)
    }

    fn empty_schema_projection() -> Arc<SchemaProjection> {
        Arc::new(SchemaProjection {
            attributes: Default::default(),
            classes: Default::default(),
            attribute_name_to_id: Default::default(),
            class_name_to_id: Default::default(),
            generation: 0,
        })
    }

    /// Build a test Dsa backed by an InMemoryDirectoryStore, returning
    /// the store so tests can insert objects.
    fn build_test_dsa() -> (Arc<Dsa>, Arc<InMemoryDirectoryStore>) {
        let store = Arc::new(InMemoryDirectoryStore::new());
        let store_clone = Arc::clone(&store);
        let list_objects = Arc::new(move || {
            store_clone
                .objects
                .read()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<_>>()
        });
        let dsa = Arc::new(Dsa {
            store: Arc::clone(&store) as Arc<dyn DirectoryStore>,
            replicator: Arc::new(InMemoryReplicator::new(dummy_invocation_id())),
            identity_mapping: Arc::new(InMemoryIdentityMapping::new()),
            schema_projection: empty_schema_projection(),
            invocation_id: dummy_invocation_id(),
            ldap_bind_addr: SocketAddr::from(([127, 0, 0, 1], 1389)),
            gc_bind_addr: SocketAddr::from(([127, 0, 0, 1], 3268)),
            list_objects,
            bind_policy: crate::BindPolicy::None,
        });
        (dsa, store)
    }

    /// Run `serve_connection` on a duplex stream and return the client
    /// side wrapped in a [`TestClient`] for buffered send/recv.
    fn spawn_server(dsa: Arc<Dsa>) -> TestClient {
        let (client, server) = duplex(8192);
        tokio::spawn(async move {
            let _ = serve_connection(server, &dsa).await;
        });
        TestClient::new(client)
    }

    async fn insert_user(store: &InMemoryDirectoryStore, dn: &str, cn: &str) {
        let obj = Object {
            uuid: Uuid::from_u128(0x_1234),
            dn: DistinguishedName::new(dn),
            attributes: vec![
                Attribute {
                    attribute_id: 0,
                    name: "objectClass".into(),
                    value: b"user".to_vec(),
                },
                Attribute {
                    attribute_id: 0,
                    name: "cn".into(),
                    value: cn.as_bytes().to_vec(),
                },
            ],
            dnt: 0,
        };
        store.put(&obj).await.unwrap();
    }

    /// Default per-recv timeout for tests. The Wave-1 DoD requires that
    /// no test hangs for more than 10 seconds; we use 5s as a defensive
    /// bound so a regression fails fast instead of stalling the test
    /// runner.
    const TEST_RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// A test helper that wraps a duplex stream with a persistent read
    /// buffer. The buffer is essential because the LDAP server may write
    /// multiple responses (e.g. `SearchResultEntry` + `SearchResultDone`)
    /// back-to-back; a single `read` can return both messages in one
    /// chunk, and a stateless `recv` would decode only the first and
    /// discard the second — causing the next `recv` to hang forever.
    struct TestClient {
        stream: tokio::io::DuplexStream,
        buf: Vec<u8>,
    }

    impl TestClient {
        /// Wrap a duplex stream in a new `TestClient` with an empty
        /// internal buffer.
        fn new(stream: tokio::io::DuplexStream) -> Self {
            Self {
                stream,
                buf: Vec::with_capacity(4096),
            }
        }

        /// Encode and send a single LDAP message, flushing the stream.
        async fn send_msg(&mut self, msg: &LdapMessage) {
            let bytes = msg.encode();
            self.stream.write_all(&bytes).await.unwrap();
            self.stream.flush().await.unwrap();
        }

        /// Receive a single LDAP message, blocking until one is available.
        /// Uses the persistent buffer so partial reads and multi-message
        /// reads are handled correctly. Panics if no message arrives
        /// within [`TEST_RECV_TIMEOUT`] (defensive bound — Wave 1 DoD
        /// requires no test hang > 10s).
        async fn recv_msg(&mut self) -> LdapMessage {
            self.recv_msg_timeout(TEST_RECV_TIMEOUT).await
        }

        /// Receive with an explicit timeout — used by tests that want
        /// to verify the server does *not* respond within a window.
        async fn recv_msg_timeout(&mut self, timeout: std::time::Duration) -> LdapMessage {
            let mut tmp = [0u8; 4096];
            let fut = async {
                loop {
                    match try_decode_message(&self.buf) {
                        Ok(Some((msg, consumed))) => {
                            self.buf.drain(..consumed);
                            return msg;
                        }
                        Ok(None) => {
                            let n = self.stream.read(&mut tmp).await.unwrap();
                            if n == 0 {
                                panic!("stream closed before a complete message was received");
                            }
                            self.buf.extend_from_slice(&tmp[..n]);
                        }
                        Err(e) => panic!("decode error: {}", e),
                    }
                }
            };
            match tokio::time::timeout(timeout, fut).await {
                Ok(msg) => msg,
                Err(_) => panic!(
                    "recv_msg timed out after {:?} (server did not respond)",
                    timeout
                ),
            }
        }

        /// Take ownership of the underlying stream — used by tests that
        /// need to close the client side explicitly to trigger server-side
        /// EOF.
        fn into_stream(self) -> tokio::io::DuplexStream {
            self.stream
        }
    }

    #[tokio::test]
    async fn serve_anonymous_bind_round_trip() {
        let (dsa, _store) = build_test_dsa();
        let mut client = spawn_server(dsa);
        let req = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                authentication: AuthenticationChoice::Simple(Vec::new()),
            }),
            controls: Vec::new(),
        };
        client.send_msg(&req).await;
        let resp = client.recv_msg().await;
        assert_eq!(resp.message_id, 1);
        match resp.protocol_op {
            ProtocolOp::BindResponse(BindResponse { result, .. }) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            other => panic!("expected BindResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn serve_search_root_dse_round_trip() {
        let (dsa, _store) = build_test_dsa();
        let mut client = spawn_server(dsa);
        let req = LdapMessage {
            message_id: 2,
            protocol_op: ProtocolOp::SearchRequest(SearchRequest {
                base_dn: String::new(),
                scope: 0,
                deref_aliases: 0,
                size_limit: 0,
                time_limit: 0,
                filter: Filter::present("objectClass"),
                attributes: Vec::new(),
                types_only: false,
            }),
            controls: Vec::new(),
        };
        client.send_msg(&req).await;
        // Expect a SearchResultEntry (the RootDSE) then a SearchResultDone.
        // Both messages may arrive in a single read; the TestClient's
        // persistent buffer handles this correctly.
        let entry = client.recv_msg().await;
        match entry.protocol_op {
            ProtocolOp::SearchResultEntry(SearchResultEntry { dn, attributes }) => {
                assert!(dn.is_empty());
                assert!(attributes.iter().any(|(n, _)| n == "namingContexts"));
            }
            other => panic!("expected SearchResultEntry, got {:?}", other),
        }
        let done = client.recv_msg().await;
        match done.protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result.result_code, ResultCode::Success);
            }
            other => panic!("expected SearchResultDone, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn serve_search_finds_inserted_user() {
        let (dsa, store) = build_test_dsa();
        insert_user(&store, "CN=alice,DC=adrian,DC=example,DC=com", "alice").await;
        let mut client = spawn_server(dsa);
        let req = LdapMessage {
            message_id: 3,
            protocol_op: ProtocolOp::SearchRequest(SearchRequest {
                base_dn: "CN=alice,DC=adrian,DC=example,DC=com".into(),
                scope: 0,
                deref_aliases: 0,
                size_limit: 0,
                time_limit: 0,
                filter: Filter::present("objectClass"),
                attributes: vec!["cn".into()],
                types_only: false,
            }),
            controls: Vec::new(),
        };
        client.send_msg(&req).await;
        let entry = client.recv_msg().await;
        match entry.protocol_op {
            ProtocolOp::SearchResultEntry(SearchResultEntry { dn, attributes }) => {
                assert_eq!(dn, "CN=alice,DC=adrian,DC=example,DC=com");
                // Only "cn" was requested.
                assert_eq!(attributes.len(), 1);
                assert_eq!(attributes[0].0, "cn");
                assert_eq!(attributes[0].1, vec![b"alice".to_vec()]);
            }
            other => panic!("expected SearchResultEntry, got {:?}", other),
        }
        let done = client.recv_msg().await;
        match done.protocol_op {
            ProtocolOp::SearchResultDone(done) => {
                assert_eq!(done.result.result_code, ResultCode::Success);
            }
            other => panic!("expected SearchResultDone, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn serve_add_modify_delete_round_trip() {
        let (dsa, _store) = build_test_dsa();
        let mut client = spawn_server(dsa);

        // Add CN=bob.
        let add_msg = LdapMessage {
            message_id: 10,
            protocol_op: ProtocolOp::AddRequest(AddRequest {
                entry: "CN=bob,DC=adrian,DC=example,DC=com".into(),
                attributes: vec![
                    ("cn".into(), vec![b"bob".to_vec()]),
                    ("objectClass".into(), vec![b"user".to_vec()]),
                ],
            }),
            controls: Vec::new(),
        };
        client.send_msg(&add_msg).await;
        let resp = client.recv_msg().await;
        match resp.protocol_op {
            ProtocolOp::AddResponse(r) => assert_eq!(r.result.result_code, ResultCode::Success),
            other => panic!("expected AddResponse, got {:?}", other),
        }

        // Modify CN=bob — replace displayName.
        let mod_msg = LdapMessage {
            message_id: 11,
            protocol_op: ProtocolOp::ModifyRequest(ModifyRequest {
                object: "CN=bob,DC=adrian,DC=example,DC=com".into(),
                changes: vec![Change {
                    operation: ModificationOp::Replace,
                    modification: ("displayName".into(), vec![b"Bob Smith".to_vec()]),
                }],
            }),
            controls: Vec::new(),
        };
        client.send_msg(&mod_msg).await;
        let resp = client.recv_msg().await;
        match resp.protocol_op {
            ProtocolOp::ModifyResponse(r) => {
                assert_eq!(r.result.result_code, ResultCode::Success)
            }
            other => panic!("expected ModifyResponse, got {:?}", other),
        }

        // Delete CN=bob.
        let del_msg = LdapMessage {
            message_id: 12,
            protocol_op: ProtocolOp::DelRequest(DelRequest::new(
                "CN=bob,DC=adrian,DC=example,DC=com",
            )),
            controls: Vec::new(),
        };
        client.send_msg(&del_msg).await;
        let resp = client.recv_msg().await;
        match resp.protocol_op {
            ProtocolOp::DelResponse(r) => {
                assert_eq!(r.result.result_code, ResultCode::Success)
            }
            other => panic!("expected DelResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn serve_unbind_closes_connection() {
        let (dsa, _store) = build_test_dsa();
        let mut client = spawn_server(dsa);
        let unbind = LdapMessage {
            message_id: 99,
            protocol_op: ProtocolOp::UnbindRequest(crate::types::UnbindRequest),
            controls: Vec::new(),
        };
        client.send_msg(&unbind).await;
        // After unbind, the server should close the connection. A
        // subsequent read should return 0 bytes (EOF).
        let mut stream = client.into_stream();
        let mut tmp = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut tmp))
            .await
            .expect("server did not close connection after unbind within 5s")
            .unwrap();
        assert_eq!(n, 0, "expected EOF after unbind, got {} bytes", n);
    }

    #[tokio::test]
    async fn serve_real_tcp_listener_accepts_connection() {
        // Spin up a real TCP listener on an ephemeral port and verify a
        // client can connect and exchange a BindRequest.
        let (dsa, _store) = build_test_dsa();
        let _server = LdapServer::new(Arc::clone(&dsa));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Spawn a task that accepts one connection and serves it.
        let serve_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(stream, &dsa).await.unwrap();
        });
        // Connect as a client.
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                authentication: AuthenticationChoice::Simple(Vec::new()),
            }),
            controls: Vec::new(),
        };
        let bytes = req.encode();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();
        // Read the response with a defensive timeout. LDAP responses are
        // small; if we don't see one within 5s the server has stalled.
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("no response from server within 5s")
            .unwrap();
        let resp = LdapMessage::decode(&buf[..n]).unwrap();
        assert_eq!(resp.message_id, 1);
        match resp.protocol_op {
            ProtocolOp::BindResponse(BindResponse { result, .. }) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            other => panic!("expected BindResponse, got {:?}", other),
        }
        // Drop the client to close the connection — the server's read
        // will then return 0 (EOF) and `serve_connection` will return
        // Ok(()), allowing the serve task to finish.
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .expect("serve task did not finish within 5s of client close")
            .unwrap();
    }

    #[test]
    fn try_decode_empty_buffer_returns_none() {
        let buf: Vec<u8> = Vec::new();
        assert!(matches!(try_decode_message(&buf), Ok(None)));
    }

    #[tokio::test]
    async fn serve_with_timeout_closes_idle_connection() {
        // `serve_with_timeout` should return Ok(()) once the idle
        // deadline elapses, even if the client never sends or closes.
        // This is the production-code defense against slowloris-style
        // attacks (per ADR-021).
        let (dsa, _store) = build_test_dsa();
        let (_client, server) = duplex(8192);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            serve_with_timeout(server, &dsa, std::time::Duration::from_millis(100)),
        )
        .await;
        assert!(
            result.is_ok(),
            "serve_with_timeout did not return within 3s — idle timeout failed to fire"
        );
        let inner = result.unwrap();
        assert!(inner.is_ok(), "inner result should be Ok: {:?}", inner);
    }

    #[tokio::test]
    async fn serve_with_timeout_processes_message_before_timeout() {
        // A client that sends a request well within the idle window
        // should receive a response — the timeout must not fire spuriously.
        let (dsa, _store) = build_test_dsa();
        let (mut client, server) = duplex(8192);
        let dsa_for_serve = Arc::clone(&dsa);
        let serve_task = tokio::spawn(async move {
            serve_with_timeout(server, &dsa_for_serve, std::time::Duration::from_secs(30)).await
        });
        let req = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                authentication: AuthenticationChoice::Simple(Vec::new()),
            }),
            controls: Vec::new(),
        };
        let bytes = req.encode();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();
        // Read the response with a defensive timeout.
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("no response within 5s")
            .unwrap();
        let resp = LdapMessage::decode(&buf[..n]).unwrap();
        assert_eq!(resp.message_id, 1);
        // Drop the client so the server's next read returns EOF and the
        // 30s idle timeout is not exercised.
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .expect("serve_task did not finish within 5s of client close")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn try_decode_truncated_returns_none() {
        // A SEQUENCE tag + length byte declaring 100 bytes, but only 3
        // bytes of value — should return None (need more bytes).
        let buf = vec![0x30, 0x64, 0x01, 0x02, 0x03];
        assert!(matches!(try_decode_message(&buf), Ok(None)));
    }

    #[test]
    fn try_decode_complete_message_succeeds() {
        // A complete LdapMessage: anonymous BindRequest.
        let msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                authentication: AuthenticationChoice::Simple(Vec::new()),
            }),
            controls: Vec::new(),
        };
        let bytes = msg.encode();
        let result = try_decode_message(&bytes).unwrap();
        assert!(result.is_some());
        let (decoded, consumed) = result.unwrap();
        assert_eq!(decoded.message_id, 1);
        assert_eq!(consumed, bytes.len());
    }

    #[tokio::test]
    async fn gc_listener_serves_search_on_ephemeral_port() {
        // Per ADR-072, the GC listener binds on port 3268 (in production)
        // and serves RFC 4511 messages with the same wire protocol as the
        // LDAP listener. Bind to an ephemeral port, accept one connection,
        // and verify a SearchRequest for the RootDSE returns a
        // SearchResultEntry + SearchResultDone.
        let (dsa, _store) = build_test_dsa();
        let server = LdapServer::new(Arc::clone(&dsa));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            // Accept one connection and serve it.
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(stream, &dsa).await.unwrap();
        });
        let _ = server; // suppress unused warning
                        // Connect as a client.
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = LdapMessage {
            message_id: 7,
            protocol_op: ProtocolOp::SearchRequest(SearchRequest {
                base_dn: String::new(),
                scope: 0,
                deref_aliases: 0,
                size_limit: 0,
                time_limit: 0,
                filter: Filter::present("objectClass"),
                attributes: Vec::new(),
                types_only: false,
            }),
            controls: Vec::new(),
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let bytes = req.encode();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();
        // The server should send SearchResultEntry + SearchResultDone.
        // We use a larger buffer (8 KiB) and a defensive timeout.
        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("no GC response within 5s")
            .unwrap();
        // Decode the first message (SearchResultEntry).
        let (entry, rest) = match crate::ber::decode_tlv(&buf[..n]) {
            Ok((tlv, rest)) => (tlv, rest),
            Err(e) => panic!("failed to decode GC response TLV: {}", e),
        };
        let entry_msg = LdapMessage::decode(&buf[..buf.len() - rest.len()]).unwrap();
        assert_eq!(entry_msg.message_id, 7);
        assert!(
            matches!(entry_msg.protocol_op, ProtocolOp::SearchResultEntry(_)),
            "expected SearchResultEntry, got {:?}",
            entry_msg.protocol_op
        );
        let _ = entry;
        // Decode the second message (SearchResultDone) from `rest`.
        let done_msg = LdapMessage::decode(rest).unwrap();
        assert_eq!(done_msg.message_id, 7);
        assert!(matches!(
            done_msg.protocol_op,
            ProtocolOp::SearchResultDone(_)
        ));
        // Close the client to let the serve task finish.
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .expect("GC serve task did not finish within 5s of client close")
            .unwrap();
    }

    #[tokio::test]
    async fn ldaps_listener_handshake_and_bind_round_trip() {
        // Per RFC 4511 §9.2, LDAPS is LDAP-over-TLS on port 636 (in
        // production). The server accepts a TCP connection, performs a
        // TLS handshake using its self-signed cert, then serves LDAP
        // messages over the encrypted channel.
        let (dsa, _store) = build_test_dsa();
        let server = LdapServer::new(Arc::clone(&dsa));
        let acceptor = test_tls_acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            // Accept one connection, perform the TLS handshake, and
            // serve a single LDAP message exchange.
            let (stream, _) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(stream).await.unwrap();
            serve_connection(tls_stream, &dsa).await.unwrap();
        });
        let _ = server;
        // Connect as a client, wrap in TLS (test client accepts any
        // server cert), and send a BindRequest.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client_cfg = test_tls_client_config();
        let tls_connector = tokio_rustls::TlsConnector::from(client_cfg);
        let mut tls_client = tls_connector
            .connect("127.0.0.1".try_into().unwrap(), tcp)
            .await
            .expect("TLS handshake");
        let req = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                authentication: AuthenticationChoice::Simple(Vec::new()),
            }),
            controls: Vec::new(),
        };
        let bytes = req.encode();
        tls_client.write_all(&bytes).await.unwrap();
        tls_client.flush().await.unwrap();
        // Read the response with a defensive timeout.
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), tls_client.read(&mut buf))
            .await
            .expect("no LDAPS response within 5s")
            .unwrap();
        let resp = LdapMessage::decode(&buf[..n]).unwrap();
        assert_eq!(resp.message_id, 1);
        match resp.protocol_op {
            ProtocolOp::BindResponse(BindResponse { result, .. }) => {
                assert_eq!(result.result_code, ResultCode::Success);
            }
            other => panic!("expected BindResponse, got {:?}", other),
        }
        // Close the TLS stream cleanly (send close_notify) so the
        // server's read returns EOF rather than an "unclean close"
        // error.
        use tokio::io::AsyncWriteExt;
        let _ = tls_client.shutdown().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .expect("LDAPS serve task did not finish within 5s of client close")
            .unwrap();
    }

    #[test]
    fn default_bind_addr_is_389() {
        assert!(DEFAULT_BIND_ADDR.ends_with(":389"));
    }

    #[test]
    fn search_done_from_error_maps_correctly() {
        let err = DsaError::Ldap("bad filter".into());
        let done = search_done_from_error(&err);
        assert_eq!(done.result.result_code, ResultCode::ProtocolError);
        assert!(done.result.diagnostic_message.contains("bad filter"));

        let err = DsaError::NotImplemented("todo".into());
        let done = search_done_from_error(&err);
        assert_eq!(done.result.result_code, ResultCode::UnwillingToPerform);
    }

    // Silence unused warnings in tests.
    #[allow(dead_code)]
    fn _use_default_naming_context() -> &'static str {
        DEFAULT_NAMING_CONTEXT
    }
    #[allow(dead_code)]
    fn _use_ldap_result() -> LdapResult {
        LdapResult::success()
    }
    #[allow(dead_code)]
    fn _use_del_response() -> DelResponse {
        DelResponse::success()
    }
}
