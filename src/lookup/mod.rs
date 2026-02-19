//! Iterative Kademlia FIND_NODE lookup algorithm.
//!
//! Implements the standard iterative lookup: queries `alpha` peers per round,
//! collects closer nodes, and converges on the `k` closest nodes to a target.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;

use tracing::instrument;

use crate::identity::NodeId;
use crate::routing::NodeInfo;

const MAX_ROUNDS: usize = 10;

/// Run an iterative Kademlia FIND_NODE lookup.
///
/// - `target`: the NodeId we're searching for
/// - `self_id`: our own NodeId (excluded from queries)
/// - `seed_nodes`: initial closest nodes from routing table
/// - `k`: replication parameter (max results)
/// - `alpha`: concurrency parameter (parallel queries per round)
/// - `send_find_node`: closure that sends a FindNode RPC to (peer_id, addrs)
///    and returns `Some((responder_id, responder_addr, returned_nodes))` on
///    success, or `None` on failure (caller handles failure recording).
///    Receives all addresses for the peer so it can try fallback (S19).
#[instrument(skip(seed_nodes, send_find_node), fields(target = %hex::encode(&target.as_bytes()[..4]), k, alpha))]
pub async fn iterative_find_node<F, Fut>(
    target: NodeId,
    self_id: NodeId,
    seed_nodes: Vec<NodeInfo>,
    k: usize,
    alpha: usize,
    send_find_node: F,
) -> Vec<NodeInfo>
where
    F: Fn(NodeId, Vec<SocketAddr>) -> Fut + Send + Sync,
    Fut: Future<Output = Option<(NodeId, SocketAddr, Vec<NodeInfo>)>>
        + Send
        + 'static,
{
    let mut queried: HashSet<NodeId> = HashSet::new();
    queried.insert(self_id);

    let mut closest: Vec<NodeInfo> = seed_nodes;

    for _round in 0..MAX_ROUNDS {
        let to_query: Vec<(NodeId, Vec<SocketAddr>)> = closest
            .iter()
            .filter(|n| {
                !queried.contains(&n.node_id) && !n.addresses.is_empty()
            })
            .take(alpha)
            .map(|n| (n.node_id, n.addresses.clone()))
            .collect();

        if to_query.is_empty() {
            break;
        }

        for (peer_id, _) in &to_query {
            queried.insert(*peer_id);
        }

        // Query in parallel
        let mut handles = Vec::new();
        for (peer_id, addrs) in to_query {
            let fut = send_find_node(peer_id, addrs);
            handles.push(tokio::spawn(fut));
        }

        // Collect results
        let mut improved = false;
        for handle in handles {
            let result = match handle.await {
                Ok(Some(result)) => result,
                _ => continue,
            };

            let (_resp_id, _resp_addr, returned_nodes) = result;

            for node in returned_nodes {
                if node.node_id == self_id {
                    continue;
                }
                if (closest.len() < k
                    || target.distance(&node.node_id)
                        < target.distance(&closest.last().unwrap().node_id))
                    && !closest.iter().any(|c| c.node_id == node.node_id)
                {
                    closest.push(node);
                    improved = true;
                }
            }
        }

        closest.sort_by(|a, b| {
            target
                .distance(&a.node_id)
                .cmp(&target.distance(&b.node_id))
        });
        closest.truncate(k);

        if !improved {
            break;
        }
    }

    closest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_info(id_byte: u8, port: u16) -> NodeInfo {
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = id_byte;
        NodeInfo::new(
            NodeId::from_bytes(id_bytes),
            [0u8; 32],
            vec![format!("127.0.0.1:{}", port).parse().unwrap()],
        )
    }

    #[tokio::test]
    async fn test_lookup_converges_with_no_new_nodes() {
        // Seed with 2 nodes, callback returns empty -> should converge in 1 round
        let seeds = vec![make_node_info(1, 1001), make_node_info(2, 1002)];
        let self_id = NodeId::from_bytes([0xFF; 32]);

        let result = iterative_find_node(
            NodeId::from_bytes([0u8; 32]),
            self_id,
            seeds.clone(),
            20,
            3,
            |peer_id, addrs| async move { Some((peer_id, addrs[0], vec![])) },
        )
        .await;

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_lookup_discovers_closer_nodes() {
        // Seed with node 0x10, callback returns node 0x01 (closer to target 0x00)
        let seeds = vec![make_node_info(0x10, 2001)];
        let self_id = NodeId::from_bytes([0xFF; 32]);
        let closer = make_node_info(0x01, 2002);

        let closer_clone = closer.clone();
        let result = iterative_find_node(
            NodeId::from_bytes([0u8; 32]),
            self_id,
            seeds,
            20,
            3,
            move |peer_id, addrs| {
                let c = closer_clone.clone();
                async move { Some((peer_id, addrs[0], vec![c])) }
            },
        )
        .await;

        assert_eq!(
            result[0].node_id, closer.node_id,
            "closest node should be first"
        );
    }

    #[tokio::test]
    async fn test_lookup_handles_rpc_failures() {
        let seeds = vec![make_node_info(1, 3001), make_node_info(2, 3002)];
        let self_id = NodeId::from_bytes([0xFF; 32]);

        // All RPCs fail
        let result = iterative_find_node(
            NodeId::from_bytes([0u8; 32]),
            self_id,
            seeds.clone(),
            20,
            3,
            |_peer_id, _addrs| async move { None },
        )
        .await;

        // Should still return the seed nodes (they were never removed)
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_lookup_skips_self() {
        let self_id = NodeId::from_bytes([0x01; 32]);
        let seeds = vec![make_node_info(2, 4001)];
        let self_info = NodeInfo::new(
            self_id,
            [0u8; 32],
            vec!["127.0.0.1:4000".parse().unwrap()],
        );

        let self_clone = self_info.clone();
        let result = iterative_find_node(
            NodeId::from_bytes([0u8; 32]),
            self_id,
            seeds,
            20,
            3,
            move |peer_id, addrs| {
                let s = self_clone.clone();
                async move { Some((peer_id, addrs[0], vec![s])) }
            },
        )
        .await;

        assert!(!result.iter().any(|n| n.node_id == self_id));
    }

    #[tokio::test]
    async fn test_lookup_respects_k_limit() {
        let seeds: Vec<NodeInfo> = (0..25u8)
            .map(|i| make_node_info(i + 1, 5000 + i as u16))
            .collect();
        let self_id = NodeId::from_bytes([0xFF; 32]);

        let result = iterative_find_node(
            NodeId::from_bytes([0u8; 32]),
            self_id,
            seeds,
            20,
            3,
            |peer_id, addrs| async move { Some((peer_id, addrs[0], vec![])) },
        )
        .await;

        assert!(result.len() <= 20);
    }
}
