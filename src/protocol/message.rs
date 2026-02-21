use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::identity::{Keypair, PowProof};
use crate::routing::NodeInfoSerde;

/// Unique identifier for correlating requests and responses.
pub type MessageId = u64;

/// Content key: SHA-256 hash identifying a piece of content.
pub type ContentKey = [u8; 32];

/// Chunk hash: SHA-256 hash identifying an erasure-coded chunk.
pub type ChunkHash = [u8; 32];

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

fn default_protocol_version() -> u8 {
    PROTOCOL_VERSION
}

/// Top-level message envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub msg_id: MessageId,
    pub sender_id: [u8; 32],
    pub sender_key: [u8; 32],
    pub pow_proof: PowProof,
    pub payload: Payload,
    /// Ed25519 signature over (msg_id || sender_id || serialized_payload).
    #[serde(default)]
    pub signature: Vec<u8>,
    /// If true, the sender is a client-only node and should NOT be added
    /// to the receiver's routing table (it will not accept inbound connections).
    #[serde(default)]
    pub client_mode: bool,
    /// Wire protocol version for forward/backward compatibility.
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u8,
}

/// The payload discriminated by operation type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Payload {
    // --- Requests ---
    /// Heartbeat request. The response is [`PingResponse`](Payload::PingResponse).
    PingRequest,
    /// Find the `k` closest nodes to `target`. Response: [`FindNodeResponse`](Payload::FindNodeResponse).
    FindNodeRequest { target: [u8; 32] },
    /// Look up providers for a content key. Response: [`GetProvidersResponse`](Payload::GetProvidersResponse).
    GetProvidersRequest { key: ContentKey },
    /// Announce that the sender provides content for `key` at `addresses`.
    AddProviderRequest {
        key: ContentKey,
        addresses: Vec<SocketAddr>,
    },
    /// Retrieve an erasure-coded chunk by hash. Response: [`GetChunkResponse`](Payload::GetChunkResponse).
    GetChunkRequest { chunk_hash: ChunkHash },
    /// Store an erasure-coded chunk. Response: [`PutChunkResponse`](Payload::PutChunkResponse).
    PutChunkRequest {
        chunk_hash: ChunkHash,
        data: Vec<u8>,
    },
    /// Forward an inner message to `target_id` via this node as relay.
    RelayRequest {
        target_id: [u8; 32],
        payload: Vec<u8>,
        /// Hop counter: incremented at each relay. Rejected if >= MAX_RELAY_HOPS.
        #[serde(default)]
        relay_hops: u8,
    },
    /// Request forwarded via relay asking the target to connect back to the requester.
    /// Used for NAT traversal: when peer C can't reach NATed peer A, C sends a
    /// ConnectRequest via relay asking A to initiate a connection to C.
    ConnectRequest {
        requester_addrs: Vec<SocketAddr>,
        requester_id: [u8; 32],
        requester_key: [u8; 32],
    },

    // --- Responses ---
    /// Response to [`PingRequest`](Payload::PingRequest).
    PingResponse {
        /// The remote address observed by the responder (for NAT traversal).
        /// Older nodes that don't send this field will deserialize as `None`.
        #[serde(default)]
        observed_addr: Option<SocketAddr>,
    },
    /// Closest known nodes to the requested target.
    FindNodeResponse { nodes: Vec<NodeInfoSerde> },
    /// Known providers for the key, plus closer nodes for iterative lookup.
    GetProvidersResponse {
        providers: Vec<NodeInfoSerde>,
        closer_nodes: Vec<NodeInfoSerde>,
    },
    /// Acknowledgement of a provider announcement.
    AddProviderResponse { ok: bool },
    /// The requested chunk data (empty if not found).
    GetChunkResponse { data: Vec<u8> },
    /// Acknowledgement of a chunk store operation.
    PutChunkResponse { ok: bool },
    /// Result of a relay attempt. `payload` contains the serialized inner response.
    RelayResponse { ok: bool, payload: Vec<u8> },
    /// Response to [`ConnectRequest`](Payload::ConnectRequest).
    ConnectResponse { ok: bool },

    // --- Error ---
    /// Generic error response with a numeric code and human-readable message.
    Error { code: u16, message: String },
}

impl Message {
    /// Create a new message with a random ID.
    pub fn new(
        sender_id: [u8; 32],
        sender_key: [u8; 32],
        pow_proof: PowProof,
        payload: Payload,
    ) -> Self {
        Self {
            msg_id: rand::random(),
            sender_id,
            sender_key,
            pow_proof,
            payload,
            signature: vec![],
            client_mode: false,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    /// Create a response to this message.
    pub fn response(
        &self,
        sender_id: [u8; 32],
        sender_key: [u8; 32],
        pow_proof: PowProof,
        payload: Payload,
    ) -> Self {
        Self {
            msg_id: self.msg_id,
            sender_id,
            sender_key,
            pow_proof,
            payload,
            signature: vec![],
            client_mode: false,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    /// Compute the bytes that are signed: msg_id || sender_id || serialized_payload.
    fn signing_bytes(&self) -> Option<Vec<u8>> {
        let payload_bytes = rmp_serde::to_vec(&self.payload).ok()?;
        let mut buf = Vec::with_capacity(8 + 32 + payload_bytes.len());
        buf.extend_from_slice(&self.msg_id.to_be_bytes());
        buf.extend_from_slice(&self.sender_id);
        buf.extend_from_slice(&payload_bytes);
        Some(buf)
    }

    /// Sign this message with the given keypair.
    pub fn sign(&mut self, keypair: &Keypair) {
        if let Some(bytes) = self.signing_bytes() {
            let sig = keypair.sign(&bytes);
            self.signature = sig.to_bytes().to_vec();
        }
    }

    /// Verify the signature against the sender_key.
    pub fn verify_signature(&self) -> bool {
        use ed25519_dalek::Verifier;
        if self.signature.len() != 64 {
            return false;
        }
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.sender_key)
        else {
            return false;
        };
        let Ok(sig_bytes): Result<[u8; 64], _> =
            self.signature[..64].try_into()
        else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let Some(bytes) = self.signing_bytes() else {
            return false;
        };
        vk.verify(&bytes, &sig).is_ok()
    }

    /// Serialize to MessagePack bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec(self)
    }

    /// Deserialize from MessagePack bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }

    /// Check if this is a request.
    pub fn is_request(&self) -> bool {
        matches!(
            self.payload,
            Payload::PingRequest
                | Payload::FindNodeRequest { .. }
                | Payload::GetProvidersRequest { .. }
                | Payload::AddProviderRequest { .. }
                | Payload::GetChunkRequest { .. }
                | Payload::PutChunkRequest { .. }
                | Payload::RelayRequest { .. }
                | Payload::ConnectRequest { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pow() -> PowProof {
        PowProof {
            nonce: 0,
            difficulty: 0,
        }
    }

    #[test]
    fn test_message_sign_and_verify() {
        use crate::identity::Keypair;

        let kp = Keypair::generate();
        let mut msg = Message::new(
            *kp.node_id().as_bytes(),
            kp.public_key_bytes(),
            test_pow(),
            Payload::PingRequest,
        );

        msg.sign(&kp);
        assert!(msg.verify_signature());
    }

    #[test]
    fn test_message_tampered_payload_fails_verification() {
        use crate::identity::Keypair;

        let kp = Keypair::generate();
        let mut msg = Message::new(
            *kp.node_id().as_bytes(),
            kp.public_key_bytes(),
            test_pow(),
            Payload::PingRequest,
        );

        msg.sign(&kp);
        // Tamper with the payload
        msg.payload = Payload::FindNodeRequest { target: [99u8; 32] };
        assert!(!msg.verify_signature());
    }

    #[test]
    fn test_message_wrong_key_fails_verification() {
        use crate::identity::Keypair;

        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let mut msg = Message::new(
            *kp1.node_id().as_bytes(),
            kp1.public_key_bytes(),
            test_pow(),
            Payload::PingRequest,
        );

        msg.sign(&kp1);
        // Replace sender_key with a different key
        msg.sender_key = kp2.public_key_bytes();
        assert!(!msg.verify_signature());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip_ping() {
        let msg = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::PingRequest,
        );
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.msg_id, msg.msg_id);
        assert_eq!(decoded.sender_id, msg.sender_id);
        assert!(matches!(decoded.payload, Payload::PingRequest));
    }

    #[test]
    fn test_serialize_deserialize_find_node() {
        let target = [42u8; 32];
        let msg = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::FindNodeRequest { target },
        );
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        match decoded.payload {
            Payload::FindNodeRequest { target: t } => assert_eq!(t, target),
            _ => panic!("wrong payload type"),
        }
    }

    #[test]
    fn test_serialize_deserialize_find_node_response() {
        let nodes = vec![NodeInfoSerde {
            node_id: [3u8; 32],
            public_key: [4u8; 32],
            addresses: vec!["192.168.1.1:4433".parse().unwrap()],
        }];
        let msg = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::FindNodeResponse {
                nodes: nodes.clone(),
            },
        );
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        match decoded.payload {
            Payload::FindNodeResponse { nodes: n } => {
                assert_eq!(n.len(), 1);
                assert_eq!(n[0].node_id, [3u8; 32]);
            }
            _ => panic!("wrong payload type"),
        }
    }

    #[test]
    fn test_serialize_put_chunk() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let msg = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::PutChunkRequest {
                chunk_hash: [5u8; 32],
                data: data.clone(),
            },
        );
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        match decoded.payload {
            Payload::PutChunkRequest {
                chunk_hash,
                data: d,
            } => {
                assert_eq!(chunk_hash, [5u8; 32]);
                assert_eq!(d, data);
            }
            _ => panic!("wrong payload type"),
        }
    }

    #[test]
    fn test_response_preserves_msg_id() {
        let req = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::PingRequest,
        );
        let resp = req.response(
            [3u8; 32],
            [4u8; 32],
            PowProof {
                nonce: 42,
                difficulty: 8,
            },
            Payload::PingResponse {
                observed_addr: None,
            },
        );
        assert_eq!(req.msg_id, resp.msg_id);
    }

    #[test]
    fn test_is_request() {
        let req = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::PingRequest,
        );
        assert!(req.is_request());

        let resp = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::PingResponse {
                observed_addr: None,
            },
        );
        assert!(!resp.is_request());
    }

    #[test]
    fn test_protocol_version_default() {
        let msg = Message::new(
            [1u8; 32],
            [2u8; 32],
            test_pow(),
            Payload::PingRequest,
        );
        assert_eq!(msg.protocol_version, PROTOCOL_VERSION);

        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
    }
}
