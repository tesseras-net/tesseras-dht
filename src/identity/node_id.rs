use std::fmt;

/// A 256-bit node identifier in the Kademlia keyspace.
/// Derived from SHA-256(Ed25519 public key).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create a NodeId from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// XOR distance between two NodeIds.
    pub fn distance(&self, other: &NodeId) -> Distance {
        let mut result = [0u8; 32];
        for (i, byte) in result.iter_mut().enumerate() {
            *byte = self.0[i] ^ other.0[i];
        }
        Distance(result)
    }

    /// Common Prefix Length — the number of leading zero bits in the XOR distance.
    /// This determines which k-bucket a peer belongs to.
    /// Returns 0..=255. Returns 256 only if both IDs are identical.
    pub fn common_prefix_length(&self, other: &NodeId) -> usize {
        let dist = self.distance(other);
        dist.leading_zeros()
    }

    /// Generate a random NodeId (for testing and ID generation).
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        Self(bytes)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex::encode(&self.0[..4]))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// XOR distance between two nodes. Implements Ord for distance comparison.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Distance([u8; 32]);

impl Distance {
    /// Count leading zero bits.
    pub fn leading_zeros(&self) -> usize {
        for (i, byte) in self.0.iter().enumerate() {
            if *byte != 0 {
                return i * 8 + byte.leading_zeros() as usize;
            }
        }
        256
    }

    /// Check if this distance is zero (identical nodes).
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Ord for Distance {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for Distance {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Distance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Distance(lz={})", self.leading_zeros())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distance_is_symmetric() {
        let a = NodeId::random();
        let b = NodeId::random();
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn test_distance_to_self_is_zero() {
        let a = NodeId::random();
        let dist = a.distance(&a);
        assert!(dist.is_zero());
        assert_eq!(dist.leading_zeros(), 256);
    }

    #[test]
    fn test_common_prefix_length() {
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 0b1111_0000;
        b_bytes[0] = 0b1111_1000; // differs at bit 4
        let a = NodeId::from_bytes(a_bytes);
        let b = NodeId::from_bytes(b_bytes);
        assert_eq!(a.common_prefix_length(&b), 4);
    }

    #[test]
    fn test_common_prefix_length_zero() {
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 0b1000_0000;
        b_bytes[0] = 0b0000_0000; // differs at bit 0
        let a = NodeId::from_bytes(a_bytes);
        let b = NodeId::from_bytes(b_bytes);
        assert_eq!(a.common_prefix_length(&b), 0);
    }

    #[test]
    fn test_distance_ordering() {
        let origin = NodeId::from_bytes([0u8; 32]);

        let mut close_bytes = [0u8; 32];
        close_bytes[31] = 1; // distance = 1
        let close = NodeId::from_bytes(close_bytes);

        let mut far_bytes = [0u8; 32];
        far_bytes[0] = 1; // distance = 2^248
        let far = NodeId::from_bytes(far_bytes);

        assert!(origin.distance(&close) < origin.distance(&far));
    }

    #[test]
    fn test_random_ids_are_unique() {
        let a = NodeId::random();
        let b = NodeId::random();
        assert_ne!(a, b);
    }
}
