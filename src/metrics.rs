use metrics::{describe_counter, describe_gauge, describe_histogram};

use crate::protocol::Payload;

// --- Counter names ---

pub const RPC_INBOUND_TOTAL: &str = "tessera_rpc_inbound_total";
pub const STORE_TOTAL: &str = "tessera_store_total";
pub const RETRIEVE_TOTAL: &str = "tessera_retrieve_total";
pub const VERIFICATION_FAILURE_TOTAL: &str =
    "tessera_verification_failure_total";
pub const RATE_LIMIT_REJECTED_TOTAL: &str = "tessera_rate_limit_rejected_total";
pub const CHUNK_PUT_TOTAL: &str = "tessera_chunk_put_total";
pub const CHUNK_GET_TOTAL: &str = "tessera_chunk_get_total";
pub const CONN_POOL_HIT_TOTAL: &str = "tessera_conn_pool_hit_total";
pub const CONN_POOL_MISS_TOTAL: &str = "tessera_conn_pool_miss_total";
pub const CONN_POOL_EVICTION_TOTAL: &str = "tessera_conn_pool_eviction_total";
pub const HANDLER_DROPPED_TOTAL: &str = "tessera_handler_dropped_total";
pub const PROVIDER_EXPIRED_TOTAL: &str = "tessera_provider_expired_total";
pub const PROVIDER_REPUBLISHED_TOTAL: &str =
    "tessera_provider_republished_total";
pub const RELAY_FORWARD_TOTAL: &str = "tessera_relay_forward_total";
pub const LOOKUP_TOTAL: &str = "tessera_lookup_total";
pub const BOOTSTRAP_TOTAL: &str = "tessera_bootstrap_total";
pub const REPLICATION_CHUNKS_SENT_TOTAL: &str =
    "tessera_replication_chunks_sent_total";
pub const REPLICATION_TRIGGER_TOTAL: &str = "tessera_replication_trigger_total";
pub const CONN_POOL_INBOUND_TOTAL: &str = "tessera_conn_pool_inbound_total";

// --- Gauge names ---

pub const ROUTING_TABLE_SIZE: &str = "tessera_routing_table_size";
pub const CHUNK_STORAGE_USED_BYTES: &str = "tessera_chunk_storage_used_bytes";
pub const CHUNK_STORAGE_MAX_BYTES: &str = "tessera_chunk_storage_max_bytes";
pub const CONN_POOL_SIZE: &str = "tessera_conn_pool_size";

// --- Histogram names ---

pub const STORE_DURATION_SECONDS: &str = "tessera_store_duration_seconds";
pub const RETRIEVE_DURATION_SECONDS: &str = "tessera_retrieve_duration_seconds";
pub const LOOKUP_DURATION_SECONDS: &str = "tessera_lookup_duration_seconds";
pub const RPC_HANDLER_DURATION_SECONDS: &str =
    "tessera_rpc_handler_duration_seconds";

// --- Label keys ---

pub const LABEL_RPC_TYPE: &str = "rpc_type";
pub const LABEL_STATUS: &str = "status";
pub const LABEL_REASON: &str = "reason";
pub const LABEL_LIMITER: &str = "limiter";
pub const LABEL_TYPE: &str = "type";

/// Register metric descriptions with the global recorder.
///
/// Call this once after installing a metrics recorder (e.g. Prometheus exporter).
/// Without a recorder installed, these calls are no-ops.
pub fn describe_metrics() {
    // Counters
    describe_counter!(RPC_INBOUND_TOTAL, "Total inbound RPC messages by type");
    describe_counter!(STORE_TOTAL, "Total tessera store operations");
    describe_counter!(RETRIEVE_TOTAL, "Total tessera retrieve operations");
    describe_counter!(
        VERIFICATION_FAILURE_TOTAL,
        "Total inbound messages rejected by verification"
    );
    describe_counter!(
        RATE_LIMIT_REJECTED_TOTAL,
        "Total requests rejected by rate limiters"
    );
    describe_counter!(CHUNK_PUT_TOTAL, "Total chunk put operations");
    describe_counter!(CHUNK_GET_TOTAL, "Total chunk get operations");
    describe_counter!(CONN_POOL_HIT_TOTAL, "Connection pool cache hits");
    describe_counter!(CONN_POOL_MISS_TOTAL, "Connection pool cache misses");
    describe_counter!(
        CONN_POOL_EVICTION_TOTAL,
        "Connection pool LRU evictions"
    );
    describe_counter!(
        HANDLER_DROPPED_TOTAL,
        "Inbound messages dropped due to handler limit"
    );
    describe_counter!(
        PROVIDER_EXPIRED_TOTAL,
        "Provider records cleaned up as expired"
    );
    describe_counter!(
        PROVIDER_REPUBLISHED_TOTAL,
        "Provider records republished"
    );
    describe_counter!(RELAY_FORWARD_TOTAL, "Relay forward attempts");
    describe_counter!(LOOKUP_TOTAL, "Iterative lookup operations");
    describe_counter!(BOOTSTRAP_TOTAL, "Bootstrap operations");
    describe_counter!(
        REPLICATION_CHUNKS_SENT_TOTAL,
        "Chunks proactively replicated to new nodes"
    );
    describe_counter!(
        REPLICATION_TRIGGER_TOTAL,
        "Proactive replication triggers (reactive or periodic)"
    );
    describe_counter!(
        CONN_POOL_INBOUND_TOTAL,
        "Inbound connections cached in connection pool"
    );

    // Gauges
    describe_gauge!(ROUTING_TABLE_SIZE, "Number of peers in routing table");
    describe_gauge!(
        CHUNK_STORAGE_USED_BYTES,
        "Bytes of chunk storage currently used"
    );
    describe_gauge!(
        CHUNK_STORAGE_MAX_BYTES,
        "Maximum chunk storage capacity in bytes"
    );
    describe_gauge!(CONN_POOL_SIZE, "Current connection pool size");

    // Histograms
    describe_histogram!(
        STORE_DURATION_SECONDS,
        "Duration of tessera store operations"
    );
    describe_histogram!(
        RETRIEVE_DURATION_SECONDS,
        "Duration of tessera retrieve operations"
    );
    describe_histogram!(
        LOOKUP_DURATION_SECONDS,
        "Duration of iterative lookup operations"
    );
    describe_histogram!(
        RPC_HANDLER_DURATION_SECONDS,
        "Duration of inbound RPC handler execution"
    );
}

/// Map a [`Payload`] variant to a short label value for the `rpc_type` label.
pub fn payload_type_label(p: &Payload) -> &'static str {
    match p {
        Payload::PingRequest => "ping",
        Payload::FindNodeRequest { .. } => "find_node",
        Payload::GetProvidersRequest { .. } => "get_providers",
        Payload::AddProviderRequest { .. } => "add_provider",
        Payload::GetChunkRequest { .. } => "get_chunk",
        Payload::PutChunkRequest { .. } => "put_chunk",
        Payload::RelayRequest { .. } => "relay",
        Payload::PingResponse { .. } => "ping_resp",
        Payload::FindNodeResponse { .. } => "find_node_resp",
        Payload::GetProvidersResponse { .. } => "get_providers_resp",
        Payload::AddProviderResponse { .. } => "add_provider_resp",
        Payload::GetChunkResponse { .. } => "get_chunk_resp",
        Payload::PutChunkResponse { .. } => "put_chunk_resp",
        Payload::RelayResponse { .. } => "relay_resp",
        Payload::ConnectRequest { .. } => "connect",
        Payload::ConnectResponse { .. } => "connect_resp",
        Payload::Error { .. } => "error",
    }
}
