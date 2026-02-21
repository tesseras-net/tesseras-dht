use std::net::SocketAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

/// Maximum number of addresses stored per peer to prevent unbounded growth.
const MAX_PEER_ADDRS: usize = 8;

/// Returns true if the address is a LAN/private/loopback address.
/// Used to sort local addresses first when merging peer addresses,
/// so `send_request_any` tries faster LAN paths before external NAT addresses.
fn is_lan_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local()
        }
        std::net::IpAddr::V6(ip) => ip.is_loopback(),
    }
}

/// Information about a known peer in the network.
#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub node_id: NodeId,
    pub public_key: [u8; 32],
    pub addresses: Vec<SocketAddr>,
    pub last_seen: Instant,
    pub fail_count: u8,
}

/// Serializable version of NodeInfo for persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfoSerde {
    pub node_id: [u8; 32],
    pub public_key: [u8; 32],
    pub addresses: Vec<SocketAddr>,
}

impl NodeInfo {
    /// Create a new peer info entry with zero failures and the current timestamp.
    pub fn new(
        node_id: NodeId,
        public_key: [u8; 32],
        addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            node_id,
            public_key,
            addresses,
            last_seen: Instant::now(),
            fail_count: 0,
        }
    }

    /// Mark this peer as just seen (reset fail count, update timestamp).
    pub fn mark_seen(&mut self) {
        self.last_seen = Instant::now();
        self.fail_count = 0;
    }

    /// Record a failed RPC attempt.
    pub fn record_failure(&mut self) {
        self.fail_count = self.fail_count.saturating_add(1);
    }
}

/// A single k-bucket in the routing table.
/// Holds up to `k` nodes, ordered by last_seen (oldest first).
/// Has a replacement cache for nodes that couldn't be inserted into a full bucket.
pub struct KBucket {
    k: usize,
    nodes: Vec<NodeInfo>,
    replacement_cache: Vec<NodeInfo>,
    max_cache_size: usize,
    last_updated: Instant,
}

/// Result of trying to insert a node into a full bucket.
pub enum InsertResult {
    /// Node was inserted successfully.
    Inserted,
    /// Bucket is full. The caller should ping this node (the least-recently-seen).
    /// If it doesn't respond, call `evict_and_insert` with the new node.
    BucketFull { lrs_node_id: NodeId },
    /// Node was already in the bucket (updated last_seen).
    Updated,
}

impl KBucket {
    /// Create an empty k-bucket with the given capacity.
    pub fn new(k: usize) -> Self {
        Self {
            k,
            nodes: Vec::with_capacity(k),
            replacement_cache: Vec::new(),
            max_cache_size: k,
            last_updated: Instant::now(),
        }
    }

    /// When this bucket was last updated (insert or evict_and_insert).
    pub fn last_updated(&self) -> Instant {
        self.last_updated
    }

    /// Number of nodes in this bucket.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether this bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether this bucket is full.
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.k
    }

    /// Get all nodes in this bucket (oldest first).
    pub fn nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    /// Get mutable access to nodes (for RoutingTable.mark_seen).
    pub fn nodes_mut(&mut self) -> &mut Vec<NodeInfo> {
        &mut self.nodes
    }

    /// Get the replacement cache.
    pub fn replacement_cache(&self) -> &[NodeInfo] {
        &self.replacement_cache
    }

    /// Try to insert a node. If the node is already present, update it.
    pub fn insert(&mut self, node: NodeInfo) -> InsertResult {
        // Check if node already exists — update it
        if let Some(existing) =
            self.nodes.iter_mut().find(|n| n.node_id == node.node_id)
        {
            existing.mark_seen();
            // Merge addresses: add new ones, dedup, prefer LAN addrs first
            for addr in &node.addresses {
                if !existing.addresses.contains(addr) {
                    existing.addresses.push(*addr);
                }
            }
            existing.addresses.sort_by_key(|a| !is_lan_addr(a));
            existing.addresses.truncate(MAX_PEER_ADDRS);
            self.last_updated = Instant::now();
            return InsertResult::Updated;
        }

        // Bucket has space — insert
        if !self.is_full() {
            self.nodes.push(node);
            self.last_updated = Instant::now();
            return InsertResult::Inserted;
        }

        // Bucket full — add to replacement cache and report LRS node
        let lrs_node_id = self.nodes[0].node_id;
        self.add_to_cache(node);
        InsertResult::BucketFull { lrs_node_id }
    }

    /// Evict the least-recently-seen node and insert the new one.
    /// Called after the LRS node failed to respond to a ping.
    pub fn evict_and_insert(
        &mut self,
        failed_id: &NodeId,
        new_node: NodeInfo,
    ) -> bool {
        if let Some(pos) =
            self.nodes.iter().position(|n| n.node_id == *failed_id)
        {
            self.nodes.remove(pos);
            let new_id = new_node.node_id;
            self.nodes.push(new_node);
            // Also remove from cache if present
            self.replacement_cache.retain(|n| n.node_id != new_id);
            self.last_updated = Instant::now();
            true
        } else {
            false
        }
    }

    /// Remove a node by ID.
    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| n.node_id == *node_id)
        {
            self.nodes.remove(pos);
            // Promote from replacement cache if available
            if let Some(replacement) = self.replacement_cache.pop() {
                self.nodes.push(replacement);
            }
            true
        } else {
            false
        }
    }

    /// Record a failure for a node. If fail_count exceeds max, evict it.
    pub fn record_failure(&mut self, node_id: &NodeId, max_failures: u8) {
        if let Some(node) =
            self.nodes.iter_mut().find(|n| n.node_id == *node_id)
        {
            node.record_failure();
            if node.fail_count >= max_failures {
                let id = node.node_id;
                self.remove(&id);
            }
        }
    }

    /// Add a node to the replacement cache (bounded size).
    fn add_to_cache(&mut self, node: NodeInfo) {
        // Remove if already in cache
        self.replacement_cache.retain(|n| n.node_id != node.node_id);
        // Add to end (most recent)
        self.replacement_cache.push(node);
        // Trim to max size
        while self.replacement_cache.len() > self.max_cache_size {
            self.replacement_cache.remove(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id_byte: u8) -> NodeInfo {
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = id_byte;
        NodeInfo::new(
            NodeId::from_bytes(id_bytes),
            [id_byte; 32],
            vec!["127.0.0.1:4433".parse().unwrap()],
        )
    }

    #[test]
    fn test_insert_into_empty_bucket() {
        let mut bucket = KBucket::new(20);
        let node = make_node(1);
        assert!(matches!(bucket.insert(node), InsertResult::Inserted));
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_insert_duplicate_updates() {
        let mut bucket = KBucket::new(20);
        let node = make_node(1);
        bucket.insert(node);
        let node2 = make_node(1);
        assert!(matches!(bucket.insert(node2), InsertResult::Updated));
        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_bucket_full_returns_lrs() {
        let mut bucket = KBucket::new(2);
        bucket.insert(make_node(1));
        bucket.insert(make_node(2));
        let result = bucket.insert(make_node(3));
        match result {
            InsertResult::BucketFull { lrs_node_id } => {
                assert_eq!(lrs_node_id, make_node(1).node_id);
            }
            _ => panic!("expected BucketFull"),
        }
    }

    #[test]
    fn test_evict_and_insert() {
        let mut bucket = KBucket::new(2);
        let n1 = make_node(1);
        let n1_id = n1.node_id;
        bucket.insert(n1);
        bucket.insert(make_node(2));

        let n3 = make_node(3);
        assert!(bucket.evict_and_insert(&n1_id, n3));
        assert_eq!(bucket.len(), 2);
        assert!(
            bucket
                .nodes()
                .iter()
                .any(|n| n.node_id == make_node(3).node_id)
        );
        assert!(!bucket.nodes().iter().any(|n| n.node_id == n1_id));
    }

    #[test]
    fn test_remove_promotes_from_cache() {
        let mut bucket = KBucket::new(2);
        bucket.insert(make_node(1));
        bucket.insert(make_node(2));
        // Node 3 goes to replacement cache
        bucket.insert(make_node(3));
        assert_eq!(bucket.replacement_cache().len(), 1);

        // Remove node 1 — node 3 should be promoted
        let n1_id = make_node(1).node_id;
        bucket.remove(&n1_id);
        assert_eq!(bucket.len(), 2);
        assert!(
            bucket
                .nodes()
                .iter()
                .any(|n| n.node_id == make_node(3).node_id)
        );
        assert_eq!(bucket.replacement_cache().len(), 0);
    }

    #[test]
    fn test_record_failure_evicts() {
        let mut bucket = KBucket::new(20);
        let n1 = make_node(1);
        let n1_id = n1.node_id;
        bucket.insert(n1);

        bucket.record_failure(&n1_id, 2);
        assert_eq!(bucket.len(), 1); // still there after 1 failure
        bucket.record_failure(&n1_id, 2);
        assert_eq!(bucket.len(), 0); // evicted after 2 failures
    }
}
