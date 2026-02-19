use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::NodeId;

/// An Ed25519 keypair that defines a node's identity.
/// The NodeId is derived as SHA-256(public_key).
pub struct Keypair {
    signing_key: SigningKey,
}

impl Clone for Keypair {
    fn clone(&self) -> Self {
        Self::from_secret_bytes(self.signing_key.as_bytes())
    }
}

impl Keypair {
    /// Generate a new random keypair.
    ///
    /// # Examples
    ///
    /// ```
    /// use tesseras_dht::identity::Keypair;
    ///
    /// let kp = Keypair::generate();
    /// let node_id = kp.node_id();
    /// ```
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::fill(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        Self { signing_key }
    }

    /// Restore from existing secret key bytes (32 bytes).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the secret key bytes for persistence.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Get the public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the public key as raw bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Derive the NodeId from the public key: SHA-256(public_key).
    pub fn node_id(&self) -> NodeId {
        derive_node_id(&self.public_key())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message)
    }
}

/// Derive a NodeId from a public key: SHA-256(public_key_bytes).
pub fn derive_node_id(public_key: &VerifyingKey) -> NodeId {
    let hash = Sha256::digest(public_key.as_bytes());
    let mut id_bytes = [0u8; 32];
    id_bytes.copy_from_slice(&hash);
    NodeId::from_bytes(id_bytes)
}

/// Verify that a NodeId was correctly derived from a public key.
pub fn verify_node_id(node_id: &NodeId, public_key: &VerifyingKey) -> bool {
    let expected = derive_node_id(public_key);
    *node_id == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generates_unique_ids() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        assert_ne!(kp1.node_id(), kp2.node_id());
    }

    #[test]
    fn test_node_id_derivation_is_deterministic() {
        let kp = Keypair::generate();
        assert_eq!(kp.node_id(), kp.node_id());
    }

    #[test]
    fn test_node_id_verification() {
        let kp = Keypair::generate();
        let node_id = kp.node_id();
        assert!(verify_node_id(&node_id, &kp.public_key()));

        let fake_id = NodeId::random();
        assert!(!verify_node_id(&fake_id, &kp.public_key()));
    }

    #[test]
    fn test_keypair_restore_from_secret() {
        let kp1 = Keypair::generate();
        let secret = *kp1.secret_bytes();
        let kp2 = Keypair::from_secret_bytes(&secret);
        assert_eq!(kp1.node_id(), kp2.node_id());
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        use ed25519_dalek::Verifier;
        let kp = Keypair::generate();
        let message = b"hello tessera";
        let sig = kp.sign(message);
        assert!(kp.public_key().verify(message, &sig).is_ok());
    }
}
