use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Proof of work for anti-Sybil protection.
/// The nonce must satisfy: SHA-256(public_key || nonce) has `difficulty` leading zero bits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowProof {
    pub nonce: u64,
    pub difficulty: u8,
}

impl PowProof {
    /// Generate a proof of work for the given public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use tesseras_dht::identity::{Keypair, PowProof};
    ///
    /// let kp = Keypair::generate();
    /// let proof = PowProof::generate(&kp.public_key_bytes(), 8);
    /// assert!(proof.verify(&kp.public_key_bytes()));
    /// ```
    pub fn generate(public_key: &[u8; 32], difficulty: u8) -> Self {
        let mut nonce: u64 = 0;
        loop {
            if verify_pow_hash(public_key, nonce, difficulty) {
                return Self { nonce, difficulty };
            }
            nonce += 1;
        }
    }

    /// Verify this proof of work against a public key.
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        verify_pow_hash(public_key, self.nonce, self.difficulty)
    }

    /// Verify this proof meets a minimum difficulty threshold.
    pub fn verify_with_min_difficulty(
        &self,
        public_key: &[u8; 32],
        min_difficulty: u8,
    ) -> bool {
        self.difficulty >= min_difficulty
            && verify_pow_hash(public_key, self.nonce, self.difficulty)
    }
}

/// Check if SHA-256(public_key || nonce_bytes) has the required leading zero bits.
fn verify_pow_hash(public_key: &[u8; 32], nonce: u64, difficulty: u8) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.update(nonce.to_le_bytes());
    let hash = hasher.finalize();
    leading_zero_bits(&hash) >= difficulty as usize
}

/// Count leading zero bits in a byte slice.
fn leading_zero_bits(data: &[u8]) -> usize {
    for (i, byte) in data.iter().enumerate() {
        if *byte != 0 {
            return i * 8 + byte.leading_zeros() as usize;
        }
    }
    data.len() * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_generation_and_verification() {
        let public_key = [42u8; 32];
        let proof = PowProof::generate(&public_key, 8);
        assert!(proof.verify(&public_key));
        assert_eq!(proof.difficulty, 8);
    }

    #[test]
    fn test_pow_fails_with_wrong_key() {
        let public_key = [42u8; 32];
        let proof = PowProof::generate(&public_key, 8);
        let wrong_key = [99u8; 32];
        assert!(!proof.verify(&wrong_key));
    }

    #[test]
    fn test_pow_difficulty_zero_is_trivial() {
        let public_key = [1u8; 32];
        let proof = PowProof::generate(&public_key, 0);
        assert!(proof.verify(&public_key));
        assert_eq!(proof.nonce, 0); // first try always works with difficulty 0
    }

    #[test]
    fn test_leading_zero_bits() {
        assert_eq!(leading_zero_bits(&[0b0000_0000, 0b1000_0000]), 8);
        assert_eq!(leading_zero_bits(&[0b0000_0001]), 7);
        assert_eq!(leading_zero_bits(&[0b1000_0000]), 0);
        assert_eq!(leading_zero_bits(&[0b0000_0000, 0b0000_0000]), 16);
    }
}
