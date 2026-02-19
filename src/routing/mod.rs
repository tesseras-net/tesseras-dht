//! Kademlia routing table with 256 k-buckets indexed by common prefix length.
//!
//! Each [`KBucket`] holds up to `k` peers ordered by last-seen time, with a replacement
//! cache for overflow. The [`RoutingTable`] provides closest-node lookups via XOR distance.

mod bucket;
mod table;

pub use bucket::{InsertResult, KBucket, NodeInfo, NodeInfoSerde};
pub use table::RoutingTable;
