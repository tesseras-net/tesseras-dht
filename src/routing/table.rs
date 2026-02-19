use std::time::Duration;

use crate::identity::NodeId;

use super::bucket::{InsertResult, KBucket, NodeInfo};

/// Kademlia routing table: 256 k-buckets indexed by Common Prefix Length.
pub struct RoutingTable {
    local_id: NodeId,
    k: usize,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// Create a new routing table for the given local node ID.
    pub fn new(local_id: NodeId, k: usize) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(KBucket::new(k));
        }
        Self {
            local_id,
            k,
            buckets,
        }
    }

    /// Get the local node ID.
    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    /// Get the k parameter.
    pub fn k(&self) -> usize {
        self.k
    }

    /// Try to insert a node into the appropriate bucket.
    /// Never insert ourselves.
    pub fn insert(&mut self, node: NodeInfo) -> InsertResult {
        if node.node_id == self.local_id {
            return InsertResult::Updated; // silently ignore self
        }
        let bucket_idx = self.bucket_index(&node.node_id);
        self.buckets[bucket_idx].insert(node)
    }

    /// Evict a failed node from its bucket and insert a replacement.
    pub fn evict_and_insert(
        &mut self,
        failed_id: &NodeId,
        new_node: NodeInfo,
    ) -> bool {
        let bucket_idx = self.bucket_index(failed_id);
        self.buckets[bucket_idx].evict_and_insert(failed_id, new_node)
    }

    /// Remove a node from the routing table.
    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].remove(node_id)
    }

    /// Record a failure for a node.
    pub fn record_failure(&mut self, node_id: &NodeId, max_failures: u8) {
        let bucket_idx = self.bucket_index(node_id);
        self.buckets[bucket_idx].record_failure(node_id, max_failures);
    }

    /// Mark a node as seen (update last_seen, reset fail_count).
    pub fn mark_seen(&mut self, node_id: &NodeId) {
        let bucket_idx = self.bucket_index(node_id);
        if let Some(node) = self.buckets[bucket_idx]
            .nodes_mut()
            .iter_mut()
            .find(|n| n.node_id == *node_id)
        {
            node.mark_seen();
        }
    }

    /// Find the k closest nodes to a target ID.
    /// Returns nodes sorted by distance (closest first).
    ///
    /// Walks outward from the target's bucket to collect candidates,
    /// avoiding a full scan of all 256 buckets in the common case.
    pub fn closest_nodes(
        &self,
        target: &NodeId,
        count: usize,
    ) -> Vec<NodeInfo> {
        let center = self.bucket_index(target) as isize;
        let mut candidates: Vec<(NodeId, &NodeInfo)> =
            Vec::with_capacity(count);

        // Walk outward from the target's bucket
        let mut lo = center;
        let mut hi = center + 1;

        while candidates.len() < count && (lo >= 0 || hi < 256) {
            if lo >= 0 {
                for node in self.buckets[lo as usize].nodes() {
                    candidates.push((node.node_id, node));
                }
                lo -= 1;
            }
            if hi < 256 {
                for node in self.buckets[hi as usize].nodes() {
                    candidates.push((node.node_id, node));
                }
                hi += 1;
            }
        }

        // Final sort by XOR distance (bucket boundaries don't perfectly
        // align with XOR distance ordering)
        candidates.sort_by(|(id_a, _), (id_b, _)| {
            target.distance(id_a).cmp(&target.distance(id_b))
        });

        candidates
            .into_iter()
            .take(count)
            .map(|(_, info)| info.clone())
            .collect()
    }

    /// Total number of peers in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Whether the routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot all nodes as serializable structs (for persistence).
    pub fn all_nodes_serde(&self) -> Vec<super::NodeInfoSerde> {
        let mut result = Vec::new();
        for bucket in &self.buckets {
            for node in bucket.nodes() {
                result.push(super::NodeInfoSerde {
                    node_id: *node.node_id.as_bytes(),
                    public_key: node.public_key,
                    addresses: node.addresses.clone(),
                });
            }
        }
        result
    }

    /// Get a reference to a specific bucket.
    pub fn bucket(&self, index: usize) -> &KBucket {
        &self.buckets[index]
    }

    /// Returns indices of non-empty buckets not updated within the given duration.
    pub fn stale_bucket_indices(&self, max_age: Duration) -> Vec<usize> {
        let cutoff = std::time::Instant::now() - max_age;
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| !b.is_empty() && b.last_updated() < cutoff)
            .map(|(i, _)| i)
            .collect()
    }

    /// Generate a random NodeId that falls in the given bucket index.
    ///
    /// The generated ID shares `bucket_index` prefix bits with the local ID,
    /// then differs at bit position `bucket_index`.
    pub fn random_id_for_bucket(&self, bucket_index: usize) -> NodeId {
        let mut bytes: [u8; 32] = rand::random();
        let local = self.local_id.as_bytes();
        // Copy first `bucket_index` bits from local_id
        for bit in 0..bucket_index.min(256) {
            let byte_idx = bit / 8;
            let bit_mask = 0x80u8 >> (bit % 8);
            bytes[byte_idx] =
                (bytes[byte_idx] & !bit_mask) | (local[byte_idx] & bit_mask);
        }
        // Ensure bit at position `bucket_index` differs from local_id
        if bucket_index < 256 {
            let byte_idx = bucket_index / 8;
            let bit_mask = 0x80u8 >> (bucket_index % 8);
            let local_bit = local[byte_idx] & bit_mask;
            if bytes[byte_idx] & bit_mask == local_bit {
                bytes[byte_idx] ^= bit_mask;
            }
        }
        NodeId::from_bytes(bytes)
    }

    /// Determine which bucket a node ID belongs to.
    fn bucket_index(&self, node_id: &NodeId) -> usize {
        let cpl = self.local_id.common_prefix_length(node_id);
        // CPL of 256 means identical IDs (shouldn't happen, but clamp to 255)
        cpl.min(255)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeId;

    fn make_node_with_id(id_bytes: [u8; 32]) -> NodeInfo {
        NodeInfo::new(
            NodeId::from_bytes(id_bytes),
            [0u8; 32],
            vec!["127.0.0.1:4433".parse().unwrap()],
        )
    }

    #[test]
    fn test_insert_and_find_closest() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let mut rt = RoutingTable::new(local_id, 20);

        // Insert nodes at various distances
        for i in 1..=10u8 {
            let mut id_bytes = [0u8; 32];
            id_bytes[31] = i;
            rt.insert(make_node_with_id(id_bytes));
        }

        assert_eq!(rt.len(), 10);

        // Find 3 closest to local_id (distance = 0)
        let target = NodeId::from_bytes([0u8; 32]);
        let closest = rt.closest_nodes(&target, 3);
        assert_eq!(closest.len(), 3);
        // Closest should be id_bytes[31] = 1, 2, 3
        assert_eq!(*closest[0].node_id.as_bytes().last().unwrap(), 1);
        assert_eq!(*closest[1].node_id.as_bytes().last().unwrap(), 2);
        assert_eq!(*closest[2].node_id.as_bytes().last().unwrap(), 3);
    }

    #[test]
    fn test_does_not_insert_self() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let mut rt = RoutingTable::new(local_id, 20);
        let self_node = make_node_with_id([0u8; 32]);
        rt.insert(self_node);
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn test_bucket_index_assignment() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let rt = RoutingTable::new(local_id, 20);

        // Node with first bit different → CPL 0 → bucket 0
        let mut far_bytes = [0u8; 32];
        far_bytes[0] = 0x80; // 1000_0000
        assert_eq!(rt.bucket(0).len(), 0);

        // This is just checking the index calculation
        let far_id = NodeId::from_bytes(far_bytes);
        assert_eq!(local_id.common_prefix_length(&far_id), 0);
    }

    #[test]
    fn test_all_nodes_serde() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let mut rt = RoutingTable::new(local_id, 20);

        for i in 1..=3u8 {
            let mut id_bytes = [0u8; 32];
            id_bytes[31] = i;
            rt.insert(make_node_with_id(id_bytes));
        }

        let all = rt.all_nodes_serde();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_remove_node() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let mut rt = RoutingTable::new(local_id, 20);
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 1;
        let node = make_node_with_id(id_bytes);
        let node_id = node.node_id;

        rt.insert(node);
        assert_eq!(rt.len(), 1);
        assert!(rt.remove(&node_id));
        assert_eq!(rt.len(), 0);
    }

    #[test]
    fn test_random_id_for_bucket() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let rt = RoutingTable::new(local_id, 20);

        // Generate IDs for several bucket indices and verify they land correctly
        for bucket_idx in [0, 1, 7, 128, 255] {
            let id = rt.random_id_for_bucket(bucket_idx);
            let cpl = local_id.common_prefix_length(&id);
            assert_eq!(
                cpl, bucket_idx,
                "random ID for bucket {} has CPL {}",
                bucket_idx, cpl
            );
        }
    }

    #[test]
    fn test_stale_bucket_indices() {
        let local_id = NodeId::from_bytes([0u8; 32]);
        let mut rt = RoutingTable::new(local_id, 20);

        // Insert a node (bucket 0: first bit differs)
        let mut far_bytes = [0u8; 32];
        far_bytes[0] = 0x80;
        rt.insert(make_node_with_id(far_bytes));

        // Just inserted — should not be stale with a 1-hour threshold
        let stale = rt.stale_bucket_indices(Duration::from_secs(3600));
        assert!(stale.is_empty());

        // With zero threshold — everything non-empty is stale
        let stale = rt.stale_bucket_indices(Duration::ZERO);
        assert!(stale.contains(&0));
    }
}
