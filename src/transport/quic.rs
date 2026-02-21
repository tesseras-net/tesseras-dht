use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use tokio::sync::{Mutex, mpsc};

use metrics::{counter, gauge};
use tracing::instrument;

use super::Transport;
use super::rate_limit::RateLimiter;
use crate::error::TesseraError;
use crate::protocol::Message;

const DEFAULT_RATE_LIMIT_PER_SECOND: u32 = 50;
const DEFAULT_RATE_LIMIT_BURST: u32 = 10;
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const RATE_LIMIT_MAX_IDLE: Duration = Duration::from_secs(300);
const RESPONSE_ONESHOT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CLIENT_RESPONSE_TIMEOUT_SECS: u64 = 30;
const MAX_POOL_SIZE: usize = 128;
const POOL_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// Maximum wire message size: 4 MB data + 1 KB envelope overhead.
pub(crate) const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024 + 1024;
/// Maximum number of pending inbound response senders (prevents unbounded HashMap growth).
const MAX_PENDING_RESPONSES: usize = 4096;

pub(crate) struct PoolEntry {
    conn: quinn::Connection,
    last_used: tokio::time::Instant,
}

/// QUIC-based transport using quinn.
/// Each RPC is a bi-directional stream: request goes out, response comes back on the same stream.
pub struct QuicTransport {
    endpoint: Endpoint,
    local_addr: SocketAddr,
    /// Inbound requests routed by the acceptor task
    request_rx: Mutex<mpsc::Receiver<(SocketAddr, Message)>>,
    /// For routing responses back to the correct inbound stream
    inbound_response_senders:
        Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Message>>>>,
    /// Cached outbound QUIC connections keyed by remote address, with LRU eviction
    connection_pool: Arc<Mutex<HashMap<SocketAddr, PoolEntry>>>,
    /// Timeout for waiting on RPC responses from peers
    client_response_timeout: Duration,
    /// Handles for background tasks so we can abort them on shutdown
    background_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl QuicTransport {
    /// Create a new QUIC transport listening on the given address.
    pub async fn new(bind_addr: SocketAddr) -> Result<Self, TesseraError> {
        // Generate self-signed certificate
        let cert =
            rcgen::generate_simple_self_signed(vec!["tessera".to_string()])
                .map_err(|e| {
                    TesseraError::Network(format!("cert gen: {}", e))
                })?;
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(
            cert.key_pair.serialize_der(),
        )
        .map_err(|e| TesseraError::Network(format!("key: {}", e)))?;

        // Server config
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
            .map_err(|e| TesseraError::Network(format!("server tls: {}", e)))?;
        server_crypto.alpn_protocols = vec![b"tessera/1".to_vec()];
        let server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| {
                    TesseraError::Network(format!("quic server config: {}", e))
                })?,
        ));

        // Client config (skip cert verification for P2P)
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"tessera/1".to_vec()];
        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| {
                    TesseraError::Network(format!("quic client config: {}", e))
                })?,
        ));

        let socket = create_udp_socket(bind_addr)?;
        let runtime = Arc::new(quinn::TokioRuntime);
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(|e| TesseraError::Network(format!("bind: {}", e)))?;
        endpoint.set_default_client_config(client_config);

        let local_addr = endpoint
            .local_addr()
            .map_err(|e| TesseraError::Network(format!("local addr: {}", e)))?;

        let (request_tx, request_rx) = mpsc::channel(256);
        let inbound_response_senders: Arc<
            Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Message>>>,
        > = Arc::new(Mutex::new(HashMap::new()));

        // Spawn acceptor loop with per-IP rate limiting
        let ep = endpoint.clone();
        let resp_senders = inbound_response_senders.clone();
        let rate_per_second = std::env::var("TESSERA_RATE_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_SECOND);
        let rate_burst = std::env::var("TESSERA_RATE_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_BURST);
        let rate_limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(
            rate_per_second,
            rate_burst,
        )));

        let connection_pool: Arc<Mutex<HashMap<SocketAddr, PoolEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let mut background_tasks = Vec::new();

        // Periodic rate limiter cleanup
        let rl_cleanup = rate_limiter.clone();
        background_tasks.push(tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(RATE_LIMIT_CLEANUP_INTERVAL);
            interval.tick().await; // consume immediate tick
            loop {
                interval.tick().await;
                rl_cleanup
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .cleanup(RATE_LIMIT_MAX_IDLE);
            }
        }));

        let pool_for_inbound = connection_pool.clone();
        background_tasks.push(tokio::spawn(async move {
            tracing::debug!("QUIC acceptor loop started");
            while let Some(incoming) = ep.accept().await {
                tracing::debug!("QUIC: incoming connection");
                let request_tx = request_tx.clone();
                let resp_senders = resp_senders.clone();
                let rate_limiter = rate_limiter.clone();
                let pool_for_inbound = pool_for_inbound.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!("QUIC: connection failed: {}", e);
                            return;
                        }
                    };
                    let remote_addr = conn.remote_address();
                    tracing::debug!(
                        "QUIC: accepted connection from {}",
                        remote_addr
                    );

                    // Cache inbound connection for reuse (NAT traversal).
                    // This allows the relay handler to forward messages to
                    // NATed peers via their existing inbound connection.
                    {
                        let mut pool = pool_for_inbound.lock().await;
                        // LRU eviction if pool is full
                        if pool.len() >= MAX_POOL_SIZE
                            && let Some((&oldest_addr, _)) =
                                pool.iter().min_by_key(|(_, entry)| entry.last_used)
                        {
                            pool.remove(&oldest_addr);
                            counter!(crate::metrics::CONN_POOL_EVICTION_TOTAL).increment(1);
                        }
                        pool.insert(
                            remote_addr,
                            PoolEntry {
                                conn: conn.clone(),
                                last_used: tokio::time::Instant::now(),
                            },
                        );
                        gauge!(crate::metrics::CONN_POOL_SIZE).set(pool.len() as f64);
                        counter!(crate::metrics::CONN_POOL_INBOUND_TOTAL).increment(1);
                    }

                    loop {
                        let stream = match conn.accept_bi().await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::debug!(
                                    "QUIC: accept_bi error from {}: {}",
                                    remote_addr,
                                    e
                                );
                                break;
                            }
                        };
                        tracing::debug!(
                            "QUIC: accepted bi stream from {}",
                            remote_addr
                        );
                        let (mut send, mut recv) = stream;
                        let request_tx = request_tx.clone();
                        let resp_senders = resp_senders.clone();
                        let rate_limiter = rate_limiter.clone();

                        tokio::spawn(async move {
                            // Per-IP rate limit check
                            if !rate_limiter
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .check(remote_addr.ip())
                            {
                                metrics::counter!(crate::metrics::RATE_LIMIT_REJECTED_TOTAL, crate::metrics::LABEL_LIMITER => "quic").increment(1);
                                tracing::warn!(
                                    "rate limited stream from {}",
                                    remote_addr
                                );
                                return;
                            }

                            tracing::debug!(
                                "QUIC: reading request from {}",
                                remote_addr
                            );
                            // Read request
                            let data = match read_message(&mut recv).await {
                                Ok(d) => d,
                                Err(e) => {
                                    tracing::debug!(
                                        "QUIC: read request failed from {}: {}",
                                        remote_addr,
                                        e
                                    );
                                    return;
                                }
                            };
                            let msg = match Message::from_bytes(&data) {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::debug!(
                                        "QUIC: deserialize failed from {}: {}",
                                        remote_addr,
                                        e
                                    );
                                    return;
                                }
                            };
                            tracing::debug!(
                                "QUIC: got request msg_id={} from {}",
                                msg.msg_id,
                                remote_addr
                            );

                            let msg_id = msg.msg_id;

                            // Create a oneshot for the response
                            let (resp_tx, resp_rx) =
                                tokio::sync::oneshot::channel();
                            {
                                let mut senders = resp_senders.lock().await;
                                if senders.len() >= MAX_PENDING_RESPONSES {
                                    tracing::warn!(
                                        "dropping inbound request: too many pending responses ({})",
                                        senders.len()
                                    );
                                    return;
                                }
                                if senders.contains_key(&msg_id) {
                                    tracing::warn!(
                                        "dropping inbound request: duplicate msg_id={}",
                                        msg_id
                                    );
                                    return;
                                }
                                senders.insert(msg_id, resp_tx);
                            }

                            // Forward request to the node
                            if request_tx
                                .send((remote_addr, msg))
                                .await
                                .is_err()
                            {
                                resp_senders.lock().await.remove(&msg_id);
                                return;
                            }

                            // Wait for the response (with timeout)
                            let resp = match tokio::time::timeout(
                                RESPONSE_ONESHOT_TIMEOUT,
                                resp_rx,
                            )
                            .await
                            {
                                Ok(Ok(resp)) => resp,
                                _ => {
                                    resp_senders.lock().await.remove(&msg_id);
                                    return;
                                }
                            };

                            // Write response back on the same stream
                            let resp_data = match resp.to_bytes() {
                                Ok(d) => d,
                                Err(_) => return,
                            };
                            let _ = write_message(&mut send, &resp_data).await;
                            let _ = send.finish();
                        });
                    }
                });
            }
        }));

        // Periodic connection pool cleanup (remove dead connections)
        let pool_cleanup = connection_pool.clone();
        background_tasks.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(POOL_CLEANUP_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                let mut pool = pool_cleanup.lock().await;
                pool.retain(|_, entry| entry.conn.close_reason().is_none());
            }
        }));

        let client_timeout_secs = std::env::var("TESSERA_CLIENT_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_CLIENT_RESPONSE_TIMEOUT_SECS);

        Ok(Self {
            endpoint,
            local_addr,
            request_rx: Mutex::new(request_rx),
            inbound_response_senders,
            connection_pool,
            client_response_timeout: Duration::from_secs(client_timeout_secs),
            background_tasks: std::sync::Mutex::new(background_tasks),
        })
    }

    /// Get a cached connection or create a new one.
    /// Uses LRU eviction when the pool reaches MAX_POOL_SIZE.
    #[instrument(skip(self), fields(addr = %addr))]
    async fn get_or_create_connection(
        &self,
        addr: &SocketAddr,
    ) -> Result<quinn::Connection, TesseraError> {
        let mut pool = self.connection_pool.lock().await;
        if let Some(entry) = pool.get_mut(addr) {
            if entry.conn.close_reason().is_none() {
                entry.last_used = tokio::time::Instant::now();
                counter!(crate::metrics::CONN_POOL_HIT_TOTAL).increment(1);
                return Ok(entry.conn.clone());
            }
            pool.remove(addr);
        }
        counter!(crate::metrics::CONN_POOL_MISS_TOTAL).increment(1);
        drop(pool);

        tracing::debug!("connection_pool: creating new connection to {}", addr);
        let connecting = self
            .endpoint
            .connect(*addr, "tessera")
            .map_err(|e| TesseraError::Network(format!("connect: {}", e)))?;
        let conn =
            tokio::time::timeout(self.client_response_timeout, connecting)
                .await
                .map_err(|_| {
                    tracing::debug!(
                        "connection_pool: connect timed out to {}",
                        addr,
                    );
                    TesseraError::Timeout
                })?
                .map_err(|e| {
                    tracing::debug!(
                        "connection_pool: connect failed to {}: {}",
                        addr,
                        e
                    );
                    TesseraError::Network(format!("connect: {}", e))
                })?;

        let mut pool = self.connection_pool.lock().await;

        // Evict LRU if pool is full
        if pool.len() >= MAX_POOL_SIZE
            && let Some((&oldest_addr, _)) =
                pool.iter().min_by_key(|(_, entry)| entry.last_used)
        {
            pool.remove(&oldest_addr);
            counter!(crate::metrics::CONN_POOL_EVICTION_TOTAL).increment(1);
        }

        pool.insert(
            *addr,
            PoolEntry {
                conn: conn.clone(),
                last_used: tokio::time::Instant::now(),
            },
        );
        gauge!(crate::metrics::CONN_POOL_SIZE).set(pool.len() as f64);
        Ok(conn)
    }

    /// Remove a cached connection (e.g. after a stream error).
    async fn evict_connection(&self, addr: &SocketAddr) {
        let mut pool = self.connection_pool.lock().await;
        pool.remove(addr);
        gauge!(crate::metrics::CONN_POOL_SIZE).set(pool.len() as f64);
    }

    /// Gracefully shut down the QUIC transport.
    ///
    /// Closes the QUIC endpoint and aborts all background tasks (acceptor,
    /// rate limiter cleanup, connection pool cleanup).
    pub fn shutdown(&self) {
        // Close the QUIC endpoint — this causes ep.accept() to return None,
        // stopping the acceptor loop.
        self.endpoint.close(0u32.into(), b"shutdown");

        // Abort remaining background tasks (cleanup loops)
        if let Ok(tasks) = self.background_tasks.lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }

    /// Returns a reference to the connection pool (for testing).
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &Arc<Mutex<HashMap<SocketAddr, PoolEntry>>> {
        &self.connection_pool
    }

    /// Open a bi-directional stream on an existing connection and perform the RPC.
    #[instrument(skip(self, conn, data), fields(addr = %addr, data_len = data.len()))]
    async fn send_on_connection(
        &self,
        conn: &quinn::Connection,
        data: &[u8],
        addr: &SocketAddr,
    ) -> Result<Message, TesseraError> {
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            tracing::debug!("send_request: open_bi failed to {}: {}", addr, e);
            TesseraError::Network(format!("open stream: {}", e))
        })?;

        write_message(&mut send, data).await?;
        send.finish()
            .map_err(|e| TesseraError::Network(format!("finish: {}", e)))?;

        let resp_data = tokio::time::timeout(
            self.client_response_timeout,
            read_message(&mut recv),
        )
        .await
        .map_err(|_| TesseraError::Timeout)?
        .map_err(|e| {
            tracing::debug!(
                "send_request: read response failed from {}: {}",
                addr,
                e
            );
            TesseraError::Network(format!("read response: {}", e))
        })?;

        Message::from_bytes(&resp_data)
            .map_err(|e| TesseraError::Serialization(format!("{}", e)))
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Transport for QuicTransport {
    #[instrument(skip(self, msg), fields(addr = %addr, msg_id = msg.msg_id))]
    async fn send_request(
        &self,
        addr: &SocketAddr,
        msg: Message,
    ) -> Result<Message, TesseraError> {
        let data = msg
            .to_bytes()
            .map_err(|e| TesseraError::Serialization(format!("{}", e)))?;

        // First attempt: use pooled (or fresh) connection.
        // get_or_create_connection already has a connect timeout, so if
        // we fail here the peer is likely dead — return immediately.
        let conn = self.get_or_create_connection(addr).await?;
        match self.send_on_connection(&conn, &data, addr).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                // Evict stale connection and retry once with a fresh one.
                // Only retry if this was a pooled (possibly stale) connection,
                // not if we just created it (which would mean the peer is down).
                self.evict_connection(addr).await;

                // Check: if the connection was freshly created (pool miss),
                // retrying won't help — the peer is unreachable.
                if matches!(e, TesseraError::Timeout) {
                    return Err(e);
                }
            }
        }

        tracing::debug!(
            "send_request: retrying with fresh connection to {}",
            addr
        );
        let conn = self.get_or_create_connection(addr).await?;
        self.send_on_connection(&conn, &data, addr).await
    }

    async fn recv_request(
        &self,
    ) -> Result<(SocketAddr, Message), TesseraError> {
        let mut rx = self.request_rx.lock().await;
        rx.recv()
            .await
            .ok_or(TesseraError::Network("acceptor closed".into()))
    }

    async fn send_response(
        &self,
        _addr: &SocketAddr,
        msg: Message,
    ) -> Result<(), TesseraError> {
        // Route the response back through the oneshot channel to the acceptor task,
        // which will write it on the original bi-directional stream.
        let mut senders = self.inbound_response_senders.lock().await;
        if let Some(tx) = senders.remove(&msg.msg_id) {
            let _ = tx.send(msg);
            Ok(())
        } else {
            Err(TesseraError::Network(
                "no pending request for this response".into(),
            ))
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Length-prefixed message writing (4-byte big-endian length + data).
async fn write_message(
    send: &mut quinn::SendStream,
    data: &[u8],
) -> Result<(), TesseraError> {
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(TesseraError::Network("outbound message too large".into()));
    }
    let len = u32::try_from(data.len()).map_err(|_| {
        TesseraError::Network("message exceeds u32 length".into())
    })?;
    let len_bytes = len.to_be_bytes();
    send.write_all(&len_bytes)
        .await
        .map_err(|e| TesseraError::Network(format!("write len: {}", e)))?;
    send.write_all(data)
        .await
        .map_err(|e| TesseraError::Network(format!("write data: {}", e)))?;
    Ok(())
}

/// Length-prefixed message reading.
async fn read_message(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, TesseraError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| TesseraError::Network(format!("read len: {}", e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(TesseraError::Network("message too large".into()));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| TesseraError::Network(format!("read data: {}", e)))?;
    Ok(buf)
}

/// Create a UDP socket with dual-stack support for IPv6 addresses.
///
/// On IPv6 sockets, sets `IPV6_V6ONLY=false` so a single `[::]:port` socket
/// accepts both IPv4 and IPv6 traffic (dual-stack). This is the default on
/// Linux but not on BSD/macOS, so we set it explicitly for cross-platform
/// consistency.
fn create_udp_socket(
    addr: SocketAddr,
) -> Result<std::net::UdpSocket, TesseraError> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| TesseraError::Network(format!("socket: {}", e)))?;

    if addr.is_ipv6()
        && let Err(e) = socket.set_only_v6(false)
    {
        tracing::debug!(%e, "unable to make socket dual-stack, continuing as IPv6-only");
    }

    socket
        .set_nonblocking(true)
        .map_err(|e| TesseraError::Network(format!("nonblocking: {}", e)))?;
    socket
        .bind(&addr.into())
        .map_err(|e| TesseraError::Network(format!("bind: {}", e)))?;

    Ok(socket.into())
}

/// Certificate verifier that skips all verification (for P2P self-signed certs).
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
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
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PowProof;
    use crate::protocol::Payload;

    #[test]
    fn test_max_message_size_constant_exists() {
        // The constant should be ~4MB, not 16MB
        const { assert!(super::MAX_MESSAGE_SIZE <= 5 * 1024 * 1024) };
        const { assert!(super::MAX_MESSAGE_SIZE > 4 * 1024 * 1024) };
    }

    #[tokio::test]
    async fn test_quic_ping_pong() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let transport_a = Arc::new(
            QuicTransport::new("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let transport_b = Arc::new(
            QuicTransport::new("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );

        let addr_b = transport_b.local_addr();

        // Spawn B's handler
        let tb = transport_b.clone();
        let handler = tokio::spawn(async move {
            let (from_addr, req) = tb.recv_request().await.unwrap();
            assert!(matches!(req.payload, Payload::PingRequest));

            let resp = req.response(
                [2u8; 32],
                [2u8; 32],
                PowProof {
                    nonce: 0,
                    difficulty: 0,
                },
                Payload::PingResponse {
                    observed_addr: None,
                },
            );
            tb.send_response(&from_addr, resp).await.unwrap();
        });

        // A sends request to B
        let req = Message::new(
            [1u8; 32],
            [1u8; 32],
            PowProof {
                nonce: 0,
                difficulty: 0,
            },
            Payload::PingRequest,
        );
        let resp = transport_a.send_request(&addr_b, req).await.unwrap();
        assert!(matches!(resp.payload, Payload::PingResponse { .. }));

        handler.await.unwrap();
    }

    #[tokio::test]
    async fn test_quic_concurrent_streams() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let transport_a = Arc::new(
            QuicTransport::new("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let transport_b = Arc::new(
            QuicTransport::new("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );

        let addr_b = transport_b.local_addr();
        let n = 10;

        // Spawn B's handler: respond to N pings
        let tb = transport_b.clone();
        let handler = tokio::spawn(async move {
            for _ in 0..n {
                let (from_addr, req) = tb.recv_request().await.unwrap();
                assert!(matches!(req.payload, Payload::PingRequest));
                let resp = req.response(
                    [2u8; 32],
                    [2u8; 32],
                    PowProof {
                        nonce: 0,
                        difficulty: 0,
                    },
                    Payload::PingResponse {
                        observed_addr: None,
                    },
                );
                tb.send_response(&from_addr, resp).await.unwrap();
            }
        });

        // Send N concurrent pings from A to B
        let mut handles = Vec::new();
        for _ in 0..n {
            let ta = transport_a.clone();
            let addr = addr_b;
            handles.push(tokio::spawn(async move {
                let req = Message::new(
                    [1u8; 32],
                    [1u8; 32],
                    PowProof {
                        nonce: 0,
                        difficulty: 0,
                    },
                    Payload::PingRequest,
                );
                ta.send_request(&addr, req).await
            }));
        }

        // All should succeed
        for h in handles {
            let resp = h.await.unwrap().unwrap();
            assert!(matches!(resp.payload, Payload::PingResponse { .. }));
        }

        // Connection pool should contain exactly 1 connection to B
        let pool = transport_a.pool().lock().await;
        assert_eq!(pool.len(), 1, "pool should have exactly 1 connection");
        assert!(pool.contains_key(&addr_b), "pool should have B's address");

        handler.await.unwrap();
    }

    #[tokio::test]
    async fn test_quic_dual_stack_bind() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Bind to IPv6 loopback — create_udp_socket should handle this.
        let transport = QuicTransport::new("[::1]:0".parse().unwrap())
            .await
            .unwrap();
        let addr = transport.local_addr();
        assert!(addr.is_ipv6(), "expected IPv6 local address, got {}", addr);
        assert_ne!(addr.port(), 0, "expected assigned port");
    }
}
