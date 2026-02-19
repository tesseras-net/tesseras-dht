//! Node identity: Ed25519 keypairs, SHA-256 node IDs, XOR distance, and proof-of-work.
//!
//! Every node derives its [`NodeId`] as `SHA-256(public_key)`. The [`PowProof`] mechanism
//! provides anti-Sybil protection by requiring computational work to generate a valid identity.

mod keypair;
mod node_id;
mod pow;

pub use keypair::{Keypair, derive_node_id, verify_node_id};
pub use node_id::{Distance, NodeId};
pub use pow::PowProof;
