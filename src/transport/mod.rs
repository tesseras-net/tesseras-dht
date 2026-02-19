//! Network transport layer: QUIC, in-memory (for tests), mDNS discovery, DNS bootstrap, and NAT traversal.
//!
//! The [`Transport`] trait abstracts send/receive operations so the node actor can use
//! [`QuicTransport`](quic::QuicTransport) in production or [`InMemoryTransport`] in tests.

pub mod dns_bootstrap;
pub mod mdns;
pub mod nat;
pub mod quic;
pub mod rate_limit;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

use crate::error::TesseraError;
use crate::protocol::Message;

/// Abstract transport layer. Allows swapping QUIC for in-memory in tests.
pub trait Transport: Send + Sync + 'static {
    /// Send a message and wait for a response (request-response pattern).
    fn send_request(
        &self,
        addr: &SocketAddr,
        msg: Message,
    ) -> impl Future<Output = Result<Message, TesseraError>> + Send;

    /// Get the next inbound request. Returns (sender_addr, message).
    fn recv_request(
        &self,
    ) -> impl Future<Output = Result<(SocketAddr, Message), TesseraError>> + Send;

    /// Send a response back to a specific address.
    fn send_response(
        &self,
        addr: &SocketAddr,
        msg: Message,
    ) -> impl Future<Output = Result<(), TesseraError>> + Send;

    /// Get the local address this transport is listening on.
    fn local_addr(&self) -> SocketAddr;
}

/// Shared state for in-memory transport (used in tests).
/// Maps SocketAddr → channel for delivering messages.
pub type InMemoryNetwork =
    Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Message)>>>>;

/// In-memory transport for testing. No real network I/O.
///
/// Uses a background router task that reads from the raw inbox and
/// routes responses to pending oneshot channels, while forwarding
/// requests to the request queue.
pub struct InMemoryTransport {
    local_addr: SocketAddr,
    network: InMemoryNetwork,
    /// Inbound requests (routed by background task)
    request_rx: Mutex<mpsc::Receiver<(SocketAddr, Message)>>,
    /// Pending response channels keyed by message ID
    pending_responses:
        Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Message>>>>,
}

impl InMemoryTransport {
    /// Create a new in-memory transport and register it in the shared network.
    pub async fn new(local_addr: SocketAddr, network: InMemoryNetwork) -> Self {
        let (raw_tx, mut raw_rx) = mpsc::channel::<(SocketAddr, Message)>(256);
        let (request_tx, request_rx) =
            mpsc::channel::<(SocketAddr, Message)>(256);

        network.lock().await.insert(local_addr, raw_tx);

        let pending_responses: Arc<
            Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Message>>>,
        > = Arc::new(Mutex::new(HashMap::new()));

        // Background router: reads all incoming messages and routes them
        let pending = pending_responses.clone();
        tokio::spawn(async move {
            while let Some((addr, msg)) = raw_rx.recv().await {
                if !msg.is_request() {
                    // Try to route as a response
                    let mut guard = pending.lock().await;
                    if let Some(tx) = guard.remove(&msg.msg_id) {
                        let _ = tx.send(msg);
                        continue;
                    }
                }
                // Forward as an inbound request
                if request_tx.send((addr, msg)).await.is_err() {
                    break;
                }
            }
        });

        Self {
            local_addr,
            network,
            request_rx: Mutex::new(request_rx),
            pending_responses,
        }
    }
}

impl Transport for InMemoryTransport {
    async fn send_request(
        &self,
        addr: &SocketAddr,
        msg: Message,
    ) -> Result<Message, TesseraError> {
        let msg_id = msg.msg_id;

        // Set up a oneshot channel to receive the response
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_responses.lock().await.insert(msg_id, tx);

        // Send to the target's inbox and wait for response
        let result = async {
            let network = self.network.lock().await;
            let target_tx = network.get(addr).ok_or(TesseraError::Network(
                format!("no route to {}", addr),
            ))?;
            target_tx.send((self.local_addr, msg)).await.map_err(|_| {
                TesseraError::Network(format!("channel closed for {}", addr))
            })?;
            drop(network);

            // Wait for response with timeout
            tokio::time::timeout(std::time::Duration::from_secs(5), rx)
                .await
                .map_err(|_| TesseraError::Timeout)?
                .map_err(|_| {
                    TesseraError::Network("response channel dropped".into())
                })
        }
        .await;

        // Clean up pending entry on any error path
        if result.is_err() {
            self.pending_responses.lock().await.remove(&msg_id);
        }

        result
    }

    async fn recv_request(
        &self,
    ) -> Result<(SocketAddr, Message), TesseraError> {
        let mut rx = self.request_rx.lock().await;
        rx.recv()
            .await
            .ok_or(TesseraError::Network("inbox closed".into()))
    }

    async fn send_response(
        &self,
        addr: &SocketAddr,
        msg: Message,
    ) -> Result<(), TesseraError> {
        let network = self.network.lock().await;
        let target_tx = network
            .get(addr)
            .ok_or(TesseraError::Network(format!("no route to {}", addr)))?;
        target_tx.send((self.local_addr, msg)).await.map_err(|_| {
            TesseraError::Network(format!("channel closed for {}", addr))
        })?;
        Ok(())
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Create a new shared in-memory network.
pub fn new_in_memory_network() -> InMemoryNetwork {
    Arc::new(Mutex::new(HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Payload;

    #[tokio::test]
    async fn test_pending_responses_cleaned_on_timeout() {
        let network = new_in_memory_network();
        let addr1: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:5002".parse().unwrap();
        let t1 = InMemoryTransport::new(addr1, network.clone()).await;
        // addr2 exists in network but nobody reads from it — messages will timeout
        let _t2 = InMemoryTransport::new(addr2, network.clone()).await;

        let msg = Message::new(
            [1u8; 32],
            [1u8; 32],
            crate::identity::PowProof {
                nonce: 0,
                difficulty: 0,
            },
            Payload::PingRequest,
        );
        let result = t1.send_request(&addr2, msg).await;
        assert!(result.is_err()); // timeout

        // The pending_responses map should be empty after timeout cleanup
        let pending = t1.pending_responses.lock().await;
        assert!(
            pending.is_empty(),
            "pending_responses leaked: {} entries",
            pending.len()
        );
    }

    #[tokio::test]
    async fn test_in_memory_request_response() {
        let network = new_in_memory_network();
        let addr_a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:2000".parse().unwrap();

        let transport_a = InMemoryTransport::new(addr_a, network.clone()).await;
        let transport_b = InMemoryTransport::new(addr_b, network.clone()).await;

        let transport_a = Arc::new(transport_a);
        let transport_b = Arc::new(transport_b);

        // Spawn B's handler
        let tb = transport_b.clone();
        let handler = tokio::spawn(async move {
            let (from_addr, req) = tb.recv_request().await.unwrap();
            assert_eq!(from_addr, addr_a);
            assert!(matches!(req.payload, Payload::PingRequest));

            let resp = req.response(
                [2u8; 32],
                [2u8; 32],
                crate::identity::PowProof {
                    nonce: 0,
                    difficulty: 0,
                },
                Payload::PingResponse,
            );
            tb.send_response(&from_addr, resp).await.unwrap();
        });

        // A sends request to B
        let req = Message::new(
            [1u8; 32],
            [1u8; 32],
            crate::identity::PowProof {
                nonce: 0,
                difficulty: 0,
            },
            Payload::PingRequest,
        );
        let resp = transport_a.send_request(&addr_b, req).await.unwrap();
        assert!(matches!(resp.payload, Payload::PingResponse));

        handler.await.unwrap();
    }
}
