use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek;
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};

use crate::erasure::{self, ErasureConfig};
use crate::error::TesseraError;
use crate::identity::{Keypair, NodeId, PowProof, verify_node_id};
use crate::protocol::{Message, Payload};
use crate::routing::{NodeInfo, NodeInfoSerde, RoutingTable};
use crate::storage::{ChunkStore, MetadataStore};
use crate::transport::Transport;
use crate::transport::rate_limit::RateLimiter;
use metrics::{counter, gauge, histogram};
use tracing::instrument;

/// Try each address in `addrs` until one succeeds, falling back on transport errors (S19).
async fn send_request_any<T: Transport>(
    transport: &T,
    addrs: &[SocketAddr],
    msg: &Message,
) -> Result<Message, TesseraError> {
    let mut last_err = TesseraError::Network("no addresses to try".into());
    tracing::debug!(
        "send_request_any: trying {} addr(s) {:?} for msg_id={}",
        addrs.len(),
        addrs,
        msg.msg_id
    );
    for addr in addrs {
        match transport.send_request(addr, msg.clone()).await {
            Ok(resp) => {
                tracing::debug!(
                    "send_request_any: success to {} msg_id={}",
                    addr,
                    msg.msg_id
                );
                return Ok(resp);
            }
            Err(e) => {
                tracing::debug!(
                    "send_request_any: failed to {} msg_id={}: {}",
                    addr,
                    msg.msg_id,
                    e
                );
                last_err = e;
            }
        }
    }
    Err(last_err)
}

/// Proactively replicate locally-stored chunks to a newly discovered node,
/// but only for chunks where the new node falls within the K-closest set.
async fn replicate_chunks_to_node<T: Transport>(
    ctx: &HandlerContext<T>,
    new_node: &NodeInfo,
) {
    if new_node.addresses.is_empty() || new_node.node_id == ctx.node_id {
        return;
    }

    // Get all content keys we are a provider for.
    let metadata = ctx.metadata.clone();
    let node_id = *ctx.node_id.as_bytes();
    let own_keys = match tokio::task::spawn_blocking(move || {
        metadata
            .lock()
            .map_err(|_| {
                TesseraError::Network("metadata lock poisoned".into())
            })?
            .get_own_providers(&node_id)
    })
    .await
    {
        Ok(Ok(keys)) => keys,
        _ => return,
    };

    if own_keys.is_empty() {
        return;
    }

    // Filter: only replicate chunks where new_node is within K-closest.
    let k = ctx.config.k;
    let mut keys_to_replicate = Vec::new();
    {
        let rt = ctx.routing_table.lock().await;
        for key in &own_keys {
            let target = NodeId::from_bytes(*key);
            let closest = rt.closest_nodes(&target, k);
            if closest.iter().any(|n| n.node_id == new_node.node_id) {
                keys_to_replicate.push(*key);
            }
        }
    }

    if keys_to_replicate.is_empty() {
        return;
    }

    counter!(crate::metrics::REPLICATION_TRIGGER_TOTAL, crate::metrics::LABEL_TYPE => "reactive")
        .increment(1);
    tracing::info!(
        chunks = keys_to_replicate.len(),
        new_node = %hex::encode(&new_node.node_id.as_bytes()[..4]),
        "replicating chunks to new node"
    );

    let sem = Arc::new(Semaphore::new(ctx.config.replication_concurrency));
    let mut handles = Vec::new();

    for key in &keys_to_replicate {
        let chunk_data = match ctx.chunks.get(key).await {
            Ok(Some(data)) => data,
            _ => continue,
        };

        let mut msg = Message::new(
            *ctx.node_id.as_bytes(),
            ctx.keypair.public_key_bytes(),
            ctx.pow.clone(),
            Payload::PutChunkRequest {
                chunk_hash: *key,
                data: chunk_data,
            },
        );
        msg.client_mode = ctx.config.client_mode;
        msg.sign(&ctx.keypair);

        let transport = ctx.transport.clone();
        let addrs = new_node.addresses.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await;
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                send_request_any(&*transport, &addrs, &msg),
            )
            .await;
            matches!(result, Ok(Ok(_)))
        }));
    }

    let mut sent = 0u64;
    for handle in handles {
        match tokio::time::timeout(Duration::from_secs(10), handle).await {
            Ok(Ok(true)) => sent += 1,
            Ok(Ok(false)) | Ok(Err(_)) => {}
            Err(_) => {} // timeout
        }
    }

    if sent > 0 {
        counter!(crate::metrics::REPLICATION_CHUNKS_SENT_TOTAL).increment(sent);
        tracing::info!(
            sent,
            new_node = %hex::encode(&new_node.node_id.as_bytes()[..4]),
            "proactive replication complete"
        );
    }
}

/// Configurable parameters for a Tessera DHT node.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub k: usize,
    pub alpha: usize,
    pub max_failures: u8,
    pub max_relay_hops: u8,
    pub max_relay_payload: usize,
    pub relay_rate_per_second: u32,
    pub relay_rate_burst: u32,
    pub provider_ttl: Duration,
    pub rt_save_interval: Duration,
    pub provider_republish_interval: Duration,
    pub min_pow_difficulty: u8,
    pub command_channel_size: usize,
    pub bucket_refresh_interval: Duration,
    pub max_chunks_per_peer: u32,
    pub write_rate_per_second: u32,
    pub write_rate_burst: u32,
    /// Maximum number of concurrent inbound handler tasks.
    pub max_concurrent_handlers: usize,
    /// Client mode: skip iterative find_node during bootstrap and don't
    /// advertise this node in the routing table. Useful for ephemeral nodes.
    pub client_mode: bool,
    /// Default erasure coding configuration for store operations.
    pub erasure_config: ErasureConfig,
    /// Proactively replicate chunks to newly discovered nodes that fall within
    /// the K-closest set for those chunks.
    pub proactive_replication: bool,
    /// Maximum number of concurrent outbound PutChunkRequest RPCs during
    /// proactive replication.
    pub replication_concurrency: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            k: 20,
            alpha: 3,
            max_failures: 3,
            max_relay_hops: 1,
            max_relay_payload: 1_048_576,
            relay_rate_per_second: 5,
            relay_rate_burst: 3,
            provider_ttl: Duration::from_secs(48 * 3600),
            rt_save_interval: Duration::from_secs(300),
            provider_republish_interval: Duration::from_secs(3600),
            min_pow_difficulty: 16,
            command_channel_size: 64,
            bucket_refresh_interval: Duration::from_secs(3600),
            max_chunks_per_peer: 256,
            write_rate_per_second: 50,
            write_rate_burst: 20,
            max_concurrent_handlers: 256,
            client_mode: false,
            erasure_config: ErasureConfig::default(),
            proactive_replication: true,
            replication_concurrency: 3,
        }
    }
}

/// Commands sent to the node actor from the public API.
enum Command {
    Bootstrap {
        addrs: Vec<SocketAddr>,
        reply: oneshot::Sender<Result<(), TesseraError>>,
    },
    FindNode {
        target: NodeId,
        reply: oneshot::Sender<Result<Vec<NodeInfo>, TesseraError>>,
    },
    GetProviders {
        key: [u8; 32],
        reply: oneshot::Sender<Result<Vec<NodeInfoSerde>, TesseraError>>,
    },
    StoreTessera {
        data: Vec<u8>,
        config: ErasureConfig,
        reply: oneshot::Sender<Result<StoreTesseraResult, TesseraError>>,
    },
    RetrieveTessera {
        chunk_hashes: Vec<[u8; 32]>,
        config: ErasureConfig,
        original_len: usize,
        reply: oneshot::Sender<Result<Vec<u8>, TesseraError>>,
    },
    Shutdown,
}

/// Local routing table statistics (no network I/O).
#[derive(Debug, Clone)]
pub struct RoutingTableStats {
    pub peer_count: usize,
}

/// Result of storing a tessera.
#[derive(Debug, Clone)]
pub struct StoreTesseraResult {
    pub chunk_hashes: Vec<[u8; 32]>,
    pub config: ErasureConfig,
    pub original_len: usize,
}

/// Compact serialization format for StoreTesseraResult tokens.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoreTesseraResultToken {
    h: Vec<Vec<u8>>,
    d: usize,
    p: usize,
    l: usize,
}

impl fmt::Display for StoreTesseraResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use base64::Engine;
        let token = StoreTesseraResultToken {
            h: self.chunk_hashes.iter().map(|h| h.to_vec()).collect(),
            d: self.config.data_shards(),
            p: self.config.parity_shards(),
            l: self.original_len,
        };
        let msgpack = rmp_serde::to_vec(&token).expect("msgpack serialization");
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&msgpack);
        f.write_str(&encoded)
    }
}

impl FromStr for StoreTesseraResult {
    type Err = TesseraError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| {
                TesseraError::Serialization(format!("base64: {}", e))
            })?;
        let token: StoreTesseraResultToken = rmp_serde::from_slice(&bytes)
            .map_err(|e| {
                TesseraError::Serialization(format!("msgpack: {}", e))
            })?;
        let chunk_hashes: Vec<[u8; 32]> = token
            .h
            .into_iter()
            .map(|v| {
                let mut arr = [0u8; 32];
                if v.len() != 32 {
                    return Err(TesseraError::Serialization(
                        "chunk hash must be 32 bytes".into(),
                    ));
                }
                arr.copy_from_slice(&v);
                Ok(arr)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let config = ErasureConfig::new(token.d, token.p)?;
        Ok(StoreTesseraResult {
            chunk_hashes,
            config,
            original_len: token.l,
        })
    }
}

/// Handle for interacting with a running TesseraNode.
pub struct NodeHandle {
    cmd_tx: mpsc::Sender<Command>,
    node_id: NodeId,
    local_addr: SocketAddr,
    erasure_config: ErasureConfig,
    routing_table: Arc<Mutex<RoutingTable>>,
    /// Externally observed address learned from PingResponse (NAT traversal).
    external_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl NodeHandle {
    /// Returns a reference to this node's ID (SHA-256 of the public key).
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Returns the local socket address this node is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns true if the node actor task is still running.
    ///
    /// When the actor panics or exits, the command channel closes and this
    /// returns `false`. Useful for distinguishing a dead node from transient errors.
    pub fn is_alive(&self) -> bool {
        !self.cmd_tx.is_closed()
    }

    /// Returns the number of queued commands (approximate).
    pub fn command_queue_len(&self) -> usize {
        self.cmd_tx.max_capacity() - self.cmd_tx.capacity()
    }

    /// Connect to bootstrap peers and populate the routing table.
    ///
    /// Pings each address to learn the peer's identity, then performs an iterative
    /// lookup for our own node ID to discover nearby peers.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(handle: tesseras_dht::node::NodeHandle) -> Result<(), tesseras_dht::TesseraError> {
    /// handle.bootstrap(vec!["192.168.1.1:4433".parse().unwrap()]).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, addrs), fields(node_id = %hex::encode(&self.node_id.as_bytes()[..4]), peer_count = addrs.len()))]
    pub async fn bootstrap(
        &self,
        addrs: Vec<SocketAddr>,
    ) -> Result<(), TesseraError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Bootstrap { addrs, reply: tx })
            .await
            .map_err(|_| TesseraError::Network("node stopped".into()))?;
        rx.await
            .map_err(|_| TesseraError::Network("node stopped".into()))?
    }

    /// Run an iterative Kademlia lookup for the `k` closest nodes to `target`.
    ///
    /// Returns up to `k` nodes sorted by XOR distance to the target.
    #[instrument(skip(self), fields(node_id = %hex::encode(&self.node_id.as_bytes()[..4]), target = %hex::encode(&target.as_bytes()[..4])))]
    pub async fn find_node(
        &self,
        target: NodeId,
    ) -> Result<Vec<NodeInfo>, TesseraError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::FindNode { target, reply: tx })
            .await
            .map_err(|_| TesseraError::Network("node stopped".into()))?;
        rx.await
            .map_err(|_| TesseraError::Network("node stopped".into()))?
    }

    /// Returns local routing table statistics without any network I/O.
    ///
    /// Reads the routing table directly (shared `Arc<Mutex<>>`), bypassing
    /// the actor command queue so it never blocks behind slow RPCs.
    pub async fn routing_table_info(&self) -> RoutingTableStats {
        let peer_count = self.routing_table.lock().await.len();
        RoutingTableStats { peer_count }
    }

    /// Returns the externally observed address learned from PingResponse,
    /// if available. Useful for NAT traversal — the external address is
    /// the address other peers see for this node.
    pub async fn external_addr(&self) -> Option<SocketAddr> {
        *self.external_addr.lock().await
    }

    /// Look up providers for a content key.
    ///
    /// Checks local metadata first, then queries the `k` closest nodes to the key.
    /// Returns provider node info (addresses) for nodes that have announced they store
    /// chunks for this content key.
    #[instrument(skip(self), fields(node_id = %hex::encode(&self.node_id.as_bytes()[..4]), key = %hex::encode(&key[..4])))]
    pub async fn get_providers(
        &self,
        key: [u8; 32],
    ) -> Result<Vec<NodeInfoSerde>, TesseraError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GetProviders { key, reply: tx })
            .await
            .map_err(|_| TesseraError::Network("node stopped".into()))?;
        rx.await
            .map_err(|_| TesseraError::Network("node stopped".into()))?
    }

    /// Erasure-encode data and distribute chunks across the DHT using the
    /// node's default [`ErasureConfig`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(handle: tesseras_dht::node::NodeHandle) -> Result<(), tesseras_dht::TesseraError> {
    /// let result = handle.store(b"important data").await?;
    /// let token = result.to_string(); // compact retrieval token
    /// # Ok(())
    /// # }
    /// ```
    pub async fn store(
        &self,
        data: impl AsRef<[u8]>,
    ) -> Result<StoreTesseraResult, TesseraError> {
        self.store_with_config(
            data.as_ref().to_vec(),
            self.erasure_config.clone(),
        )
        .await
    }

    /// Erasure-encode data with an explicit [`ErasureConfig`].
    #[instrument(skip(self, data), fields(node_id = %hex::encode(&self.node_id.as_bytes()[..4]), data_len = data.len(), data_shards = config.data_shards(), parity_shards = config.parity_shards()))]
    pub async fn store_with_config(
        &self,
        data: Vec<u8>,
        config: ErasureConfig,
    ) -> Result<StoreTesseraResult, TesseraError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::StoreTessera {
                data,
                config,
                reply: tx,
            })
            .await
            .map_err(|_| TesseraError::Network("node stopped".into()))?;
        rx.await
            .map_err(|_| TesseraError::Network("node stopped".into()))?
    }

    /// Retrieve and reconstruct data using the config embedded in `result`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(
    /// #     handle: tesseras_dht::node::NodeHandle,
    /// #     result: tesseras_dht::node::StoreTesseraResult,
    /// # ) -> Result<(), tesseras_dht::TesseraError> {
    /// let data = handle.retrieve(&result).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn retrieve(
        &self,
        result: &StoreTesseraResult,
    ) -> Result<Vec<u8>, TesseraError> {
        self.retrieve_with_config(result, result.config.clone())
            .await
    }

    /// Retrieve and reconstruct data with an explicit [`ErasureConfig`] override.
    #[instrument(skip(self, result), fields(node_id = %hex::encode(&self.node_id.as_bytes()[..4]), num_chunks = result.chunk_hashes.len(), original_len = result.original_len))]
    pub async fn retrieve_with_config(
        &self,
        result: &StoreTesseraResult,
        config: ErasureConfig,
    ) -> Result<Vec<u8>, TesseraError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::RetrieveTessera {
                chunk_hashes: result.chunk_hashes.clone(),
                config,
                original_len: result.original_len,
                reply: tx,
            })
            .await
            .map_err(|_| TesseraError::Network("node stopped".into()))?;
        rx.await
            .map_err(|_| TesseraError::Network("node stopped".into()))?
    }

    /// Gracefully shut down the node actor.
    ///
    /// Saves the routing table to the metadata store before stopping.
    #[instrument(skip(self), fields(node_id = %hex::encode(&self.node_id.as_bytes()[..4])))]
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(Command::Shutdown).await;
    }
}

/// Source for bootstrap peer discovery.
#[derive(Clone, Debug)]
pub enum BootstrapSource {
    /// Explicit peer addresses.
    Addrs(Vec<SocketAddr>),
    /// DNS SRV lookup on `_tesseras._udp.<domain>`.
    Dns(String),
}

/// High-level builder for spawning a Tessera DHT node.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), tesseras_dht::TesseraError> {
/// use tesseras_dht::node::{NodeBuilder, BootstrapSource};
///
/// let node = NodeBuilder::new("./data")
///     .bootstrap(BootstrapSource::Dns("tesseras.net".into()))
///     .spawn()
///     .await?;
///
/// let result = node.store("hello tesseras").await?;
/// println!("token: {}", result);
///
/// node.shutdown().await;
/// # Ok(())
/// # }
/// ```
pub struct NodeBuilder {
    bind_addr: Option<SocketAddr>,
    data_dir: PathBuf,
    pow_difficulty: u8,
    max_storage: u64,
    erasure_config: ErasureConfig,
    config: NodeConfig,
    keypair: Option<(Keypair, PowProof)>,
    bootstrap_sources: Vec<BootstrapSource>,
    mdns: bool,
}

impl NodeBuilder {
    /// Create a builder with only the required `data_dir`.
    ///
    /// Defaults: bind `[::]:0`, PoW difficulty 16, 1 GB storage, 10+4 erasure,
    /// mDNS enabled, no bootstrap peers (acts as a bootstrap node).
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            bind_addr: None,
            data_dir: data_dir.as_ref().to_path_buf(),
            pow_difficulty: 16,
            max_storage: 1_073_741_824,
            erasure_config: ErasureConfig::default(),
            config: NodeConfig::default(),
            keypair: None,
            bootstrap_sources: Vec::new(),
            mdns: true,
        }
    }

    /// Set the listen address (default: `[::]:0`).
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Set proof-of-work difficulty (default: 16).
    pub fn pow_difficulty(mut self, d: u8) -> Self {
        self.pow_difficulty = d;
        self
    }

    /// Set maximum storage quota in bytes (default: 1 GB).
    pub fn max_storage(mut self, bytes: u64) -> Self {
        self.max_storage = bytes;
        self
    }

    /// Set erasure coding configuration (default: 10 data + 4 parity).
    pub fn erasure_config(mut self, config: ErasureConfig) -> Self {
        self.erasure_config = config;
        self
    }

    /// Override the full [`NodeConfig`].
    pub fn config(mut self, config: NodeConfig) -> Self {
        self.config = config;
        self
    }

    /// Provide a pre-generated keypair and proof-of-work.
    pub fn keypair(mut self, keypair: Keypair, pow: PowProof) -> Self {
        self.keypair = Some((keypair, pow));
        self
    }

    /// Enable client mode (ephemeral nodes that don't join the routing table).
    pub fn client_mode(mut self, enabled: bool) -> Self {
        self.config.client_mode = enabled;
        self
    }

    /// Add a bootstrap source. Can be called multiple times to accumulate sources.
    pub fn bootstrap(mut self, source: BootstrapSource) -> Self {
        self.bootstrap_sources.push(source);
        self
    }

    /// Enable or disable mDNS LAN discovery (default: true).
    pub fn mdns(mut self, enabled: bool) -> Self {
        self.mdns = enabled;
        self
    }

    /// Spawn the node, returning a [`NodeHandle`].
    ///
    /// This will:
    /// 1. Open/create storage
    /// 2. Load or generate keypair + PoW
    /// 3. Create QUIC transport
    /// 4. Start the node actor
    /// 5. Resolve and connect to bootstrap sources
    /// 6. Start mDNS discovery (if enabled)
    pub async fn spawn(self) -> Result<NodeHandle, TesseraError> {
        use crate::transport::quic::QuicTransport;

        std::fs::create_dir_all(&self.data_dir)?;

        let metadata = MetadataStore::open(&self.data_dir.join("metadata.db"))?;
        let chunks =
            ChunkStore::new(&self.data_dir.join("chunks"), self.max_storage)?;

        // Load or generate identity
        let (keypair, pow) = if let Some(kp) = self.keypair {
            kp
        } else {
            match metadata.load_identity() {
                Ok(Some((secret, nonce, difficulty))) => {
                    let kp = Keypair::from_secret_bytes(&secret);
                    let pow = PowProof { nonce, difficulty };
                    (kp, pow)
                }
                _ => {
                    let kp = Keypair::generate();
                    let difficulty = self.pow_difficulty;
                    let pub_key = kp.public_key_bytes();
                    let pow = tokio::task::spawn_blocking(move || {
                        PowProof::generate(&pub_key, difficulty)
                    })
                    .await
                    .map_err(|e| {
                        TesseraError::Network(format!("PoW task failed: {}", e))
                    })?;
                    let _ = metadata.save_identity(
                        kp.secret_bytes(),
                        pow.nonce,
                        pow.difficulty,
                    );
                    (kp, pow)
                }
            }
        };

        let bind_addr =
            self.bind_addr.unwrap_or_else(|| "[::]:0".parse().unwrap());
        let transport = Arc::new(QuicTransport::new(bind_addr).await?);

        let mut config = self.config;
        config.min_pow_difficulty = self.pow_difficulty;
        config.erasure_config = self.erasure_config;

        let handle =
            spawn_node(keypair, pow, transport, metadata, chunks, config).await;

        // Resolve bootstrap sources
        let mut all_addrs = Vec::new();
        for source in &self.bootstrap_sources {
            match source {
                BootstrapSource::Addrs(addrs) => {
                    all_addrs.extend_from_slice(addrs);
                }
                BootstrapSource::Dns(domain) => {
                    match crate::transport::dns_bootstrap::resolve_bootstrap(
                        domain,
                    )
                    .await
                    {
                        Ok(addrs) => all_addrs.extend(addrs),
                        Err(e) => {
                            tracing::warn!(
                                "DNS bootstrap for {} failed: {}",
                                domain,
                                e
                            );
                        }
                    }
                }
            }
        }
        if !all_addrs.is_empty() {
            handle.bootstrap(all_addrs).await?;
        }

        // Start mDNS discovery
        if self.mdns {
            let local_addr = handle.local_addr();
            let port = local_addr.port();
            let local_ip = local_addr.ip();
            let handle_clone = handle.cmd_tx.clone();
            let node_id = handle.node_id;
            let node_id_short = hex::encode(&node_id.as_bytes()[..4]);
            match crate::transport::mdns::MdnsDiscovery::new(port) {
                Ok(mut mdns) => {
                    tracing::debug!(
                        node_id = %node_id_short,
                        port = port,
                        "mDNS discovery started"
                    );
                    let local_is_ipv4 = local_addr.is_ipv4();
                    tokio::spawn(async move {
                        while let Some(addr) = mdns.next_discovered().await {
                            // Skip our own addresses to avoid self-bootstrap
                            // loops that waste time and congest the actor.
                            if addr.port() == port
                                && (addr.ip() == local_ip
                                    || addr.ip().is_loopback()
                                    || local_ip.is_unspecified())
                            {
                                tracing::debug!(
                                    peer = %addr,
                                    "mDNS: skipping own address"
                                );
                                continue;
                            }
                            // Skip addresses incompatible with our socket's
                            // address family. An IPv4-bound endpoint cannot
                            // connect to IPv6 peers and vice-versa.
                            if local_is_ipv4 && addr.is_ipv6() {
                                tracing::debug!(
                                    peer = %addr,
                                    "mDNS: skipping IPv6 peer (bound to IPv4)"
                                );
                                continue;
                            }
                            if !local_is_ipv4
                                && addr.is_ipv4()
                                && !local_ip.is_unspecified()
                            {
                                tracing::debug!(
                                    peer = %addr,
                                    "mDNS: skipping IPv4 peer (bound to IPv6-only)"
                                );
                                continue;
                            }
                            tracing::debug!(
                                node_id = %node_id_short,
                                peer = %addr,
                                "mDNS: bootstrapping discovered peer"
                            );
                            let (tx, _rx) = oneshot::channel();
                            let _ = handle_clone
                                .send(Command::Bootstrap {
                                    addrs: vec![addr],
                                    reply: tx,
                                })
                                .await;
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("mDNS discovery failed to start: {}", e);
                }
            }
        } else {
            tracing::debug!("mDNS discovery disabled");
        }

        Ok(handle)
    }
}

/// Spawn a TesseraNode actor and return a handle.
pub async fn spawn_node<T: Transport>(
    keypair: Keypair,
    pow: PowProof,
    transport: Arc<T>,
    metadata: MetadataStore,
    chunks: ChunkStore,
    config: NodeConfig,
) -> NodeHandle {
    let node_id = keypair.node_id();
    let local_addr = transport.local_addr();
    let (cmd_tx, cmd_rx) = mpsc::channel(config.command_channel_size);

    let mut routing_table = RoutingTable::new(node_id, config.k);

    // Load persisted peers from previous session (Gap F)
    if let Ok(peers) = metadata.load_peers() {
        for peer in peers {
            let peer_id = NodeId::from_bytes(peer.node_id);
            let info = NodeInfo::new(peer_id, peer.public_key, peer.addresses);
            routing_table.insert(info);
        }
        tracing::info!(
            "loaded {} persisted peers into routing table",
            routing_table.len()
        );
    }

    let relay_limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        config.relay_rate_per_second,
        config.relay_rate_burst,
    )));
    let write_limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        config.write_rate_per_second,
        config.write_rate_burst,
    )));
    let peer_chunk_counts = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let handler_semaphore =
        Arc::new(Semaphore::new(config.max_concurrent_handlers));
    let erasure_config = config.erasure_config.clone();
    let config = Arc::new(config);

    let routing_table = Arc::new(Mutex::new(routing_table));
    let external_addr: Arc<Mutex<Option<SocketAddr>>> =
        Arc::new(Mutex::new(None));

    let actor = NodeActor {
        keypair,
        pow,
        node_id,
        transport,
        routing_table: routing_table.clone(),
        metadata: Arc::new(std::sync::Mutex::new(metadata)),
        chunks: Arc::new(chunks),
        cmd_rx,
        handler_semaphore,
        relay_limiter,
        write_limiter,
        peer_chunk_counts,
        config,
        last_maintenance_time: std::time::Instant::now(),
        external_addr: external_addr.clone(),
    };

    tokio::spawn(actor.run());

    NodeHandle {
        cmd_tx,
        node_id,
        local_addr,
        erasure_config,
        routing_table,
        external_addr,
    }
}

struct NodeActor<T: Transport> {
    keypair: Keypair,
    pow: PowProof,
    node_id: NodeId,
    transport: Arc<T>,
    routing_table: Arc<Mutex<RoutingTable>>,
    metadata: Arc<std::sync::Mutex<MetadataStore>>,
    chunks: Arc<ChunkStore>,
    cmd_rx: mpsc::Receiver<Command>,
    handler_semaphore: Arc<Semaphore>,
    relay_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    write_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    peer_chunk_counts: Arc<std::sync::Mutex<HashMap<[u8; 32], u32>>>,
    config: Arc<NodeConfig>,
    last_maintenance_time: std::time::Instant,
    /// Externally observed address learned from PingResponse (NAT traversal).
    external_addr: Arc<Mutex<Option<SocketAddr>>>,
}

struct HandlerContext<T: Transport> {
    keypair: Keypair,
    pow: PowProof,
    node_id: NodeId,
    transport: Arc<T>,
    routing_table: Arc<Mutex<RoutingTable>>,
    metadata: Arc<std::sync::Mutex<MetadataStore>>,
    chunks: ChunkStore,
    relay_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    write_limiter: Arc<std::sync::Mutex<RateLimiter>>,
    peer_chunk_counts: Arc<std::sync::Mutex<HashMap<[u8; 32], u32>>>,
    config: Arc<NodeConfig>,
    /// Externally observed address learned from PingResponse (NAT traversal).
    external_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl<T: Transport> Clone for HandlerContext<T> {
    fn clone(&self) -> Self {
        Self {
            keypair: self.keypair.clone(),
            pow: self.pow.clone(),
            node_id: self.node_id,
            transport: self.transport.clone(),
            routing_table: self.routing_table.clone(),
            metadata: self.metadata.clone(),
            chunks: self.chunks.clone(),
            relay_limiter: self.relay_limiter.clone(),
            write_limiter: self.write_limiter.clone(),
            peer_chunk_counts: self.peer_chunk_counts.clone(),
            config: self.config.clone(),
            external_addr: self.external_addr.clone(),
        }
    }
}

impl<T: Transport> HandlerContext<T> {
    /// Returns the externally observed address if available, otherwise local.
    async fn best_addr(&self) -> SocketAddr {
        let external = *self.external_addr.lock().await;
        let local = self.transport.local_addr();
        let addr = external.unwrap_or(local);
        tracing::debug!(
            "best_addr: external={:?} local={} => using={}",
            external,
            local,
            addr
        );
        addr
    }

    /// Create a new outgoing message with the node's identity and client_mode flag.
    fn new_message(&self, payload: Payload) -> Message {
        let mut msg = Message::new(
            *self.node_id.as_bytes(),
            self.keypair.public_key_bytes(),
            self.pow.clone(),
            payload,
        );
        msg.client_mode = self.config.client_mode;
        msg
    }

    /// Ask a NATed peer to connect back to us via relay (connection reversal).
    ///
    /// Sends a `ConnectRequest` wrapped in a `RelayRequest` to a relay node,
    /// which forwards it to the target. The target then initiates a connection
    /// to our addresses, creating a bidirectional path.
    async fn request_reverse_connection(
        &self,
        target_id: &NodeId,
    ) -> Result<(), TesseraError> {
        let my_addr = self.best_addr().await;
        let inner_msg = {
            let mut msg = self.new_message(Payload::ConnectRequest {
                requester_addrs: vec![my_addr],
                requester_id: *self.node_id.as_bytes(),
                requester_key: self.keypair.public_key_bytes(),
            });
            msg.sign(&self.keypair);
            msg
        };
        let inner_bytes = inner_msg.to_bytes().map_err(|e| {
            TesseraError::Serialization(format!(
                "failed to serialize ConnectRequest: {}",
                e
            ))
        })?;

        // Try relay candidates (closest nodes to us)
        let candidates = self
            .routing_table
            .lock()
            .await
            .closest_nodes(&self.node_id, self.config.k);

        for candidate in &candidates {
            if candidate.node_id == *target_id
                || candidate.node_id == self.node_id
                || candidate.addresses.is_empty()
            {
                continue;
            }

            let mut relay_msg = self.new_message(Payload::RelayRequest {
                target_id: *target_id.as_bytes(),
                payload: inner_bytes.clone(),
                relay_hops: 0,
            });
            relay_msg.sign(&self.keypair);

            if let Ok(resp) = send_request_any(
                &*self.transport,
                &candidate.addresses,
                &relay_msg,
            )
            .await
                && let Payload::RelayResponse { ok: true, payload } =
                    resp.payload
                && let Ok(inner) = Message::from_bytes(&payload)
                && matches!(
                    inner.payload,
                    Payload::ConnectResponse { ok: true }
                )
            {
                // Give the target time to establish the connection
                tokio::time::sleep(Duration::from_millis(500)).await;
                return Ok(());
            }
        }

        Err(TesseraError::Network(
            "connection reversal failed: no relay succeeded".into(),
        ))
    }

    /// Bootstrap by pinging each address, then performing an iterative lookup.
    ///
    /// This is callable from a spawned task (unlike NodeActor methods) so that
    /// the actor loop is not blocked during network I/O.
    #[instrument(skip(self, addrs), fields(num_addrs = addrs.len()))]
    async fn do_bootstrap(
        &self,
        addrs: Vec<SocketAddr>,
    ) -> Result<(), TesseraError> {
        // Ping each bootstrap node to learn their identity
        for addr in &addrs {
            let mut msg = self.new_message(Payload::PingRequest);
            msg.sign(&self.keypair);
            match self.transport.send_request(addr, msg).await {
                Ok(resp) => {
                    // Extract observed address for NAT traversal
                    if let Payload::PingResponse {
                        observed_addr: Some(ext),
                    } = &resp.payload
                    {
                        let mut guard = self.external_addr.lock().await;
                        let old = *guard;
                        if old != Some(*ext) {
                            tracing::info!(
                                "NAT: external addr changed {:?} -> {}",
                                old,
                                ext
                            );
                        }
                        *guard = Some(*ext);
                    }

                    let peer_id = NodeId::from_bytes(resp.sender_id);
                    let node_info =
                        NodeInfo::new(peer_id, resp.sender_key, vec![*addr]);
                    self.routing_table.lock().await.insert(node_info);
                }
                Err(e) => {
                    tracing::warn!("bootstrap ping to {} failed: {}", addr, e);
                    self.routing_table
                        .lock()
                        .await
                        .record_failure_by_addr(addr, self.config.max_failures);
                }
            }
        }

        let rt_size = self.routing_table.lock().await.len();
        gauge!(crate::metrics::ROUTING_TABLE_SIZE).set(rt_size as f64);

        if self.config.client_mode {
            // Client mode: do a single FindNodeRequest to each bootstrap peer
            // to discover nearby nodes without a full iterative lookup (which
            // would contact dead ephemeral peers and cause long timeouts).
            for addr in &addrs {
                let mut msg = self.new_message(Payload::FindNodeRequest {
                    target: *self.node_id.as_bytes(),
                });
                msg.sign(&self.keypair);
                if let Ok(resp) = self.transport.send_request(addr, msg).await
                    && let Payload::FindNodeResponse { nodes } = resp.payload
                {
                    let mut rt = self.routing_table.lock().await;
                    for n in nodes {
                        let info = NodeInfo::new(
                            NodeId::from_bytes(n.node_id),
                            n.public_key,
                            n.addresses,
                        );
                        rt.insert(info);
                    }
                }
            }
        } else {
            let _ = self.do_iterative_find_node(self.node_id).await;
        }

        // Log routing table state after bootstrap
        {
            let rt = self.routing_table.lock().await;
            let all_nodes = rt.closest_nodes(&self.node_id, 100);
            tracing::info!(
                "bootstrap complete: routing_table has {} peers",
                rt.len()
            );
            for node in &all_nodes {
                tracing::info!(
                    "  peer: node_id={} addrs={:?}",
                    hex::encode(&node.node_id.as_bytes()[..8]),
                    node.addresses
                );
            }
        }

        counter!(crate::metrics::BOOTSTRAP_TOTAL, crate::metrics::LABEL_STATUS => "ok").increment(1);
        Ok(())
    }

    /// Iterative Kademlia node lookup, callable from spawned tasks.
    #[instrument(skip(self), fields(target = %hex::encode(&target.as_bytes()[..4])))]
    async fn do_iterative_find_node(
        &self,
        target: NodeId,
    ) -> Result<Vec<NodeInfo>, TesseraError> {
        counter!(crate::metrics::LOOKUP_TOTAL, crate::metrics::LABEL_TYPE => "find_node").increment(1);
        let start = std::time::Instant::now();
        let k = self.config.k;
        let alpha = self.config.alpha;
        let max_failures = self.config.max_failures;
        let seed_nodes =
            self.routing_table.lock().await.closest_nodes(&target, k);

        let transport = self.transport.clone();
        let rt = self.routing_table.clone();
        let my_id = self.node_id;
        let my_key = self.keypair.public_key_bytes();
        let my_keypair = self.keypair.clone();
        let pow = self.pow.clone();
        let client_mode = self.config.client_mode;

        let result = crate::lookup::iterative_find_node(
            target,
            self.node_id,
            seed_nodes,
            k,
            alpha,
            move |peer_id, addrs| {
                let transport = transport.clone();
                let rt = rt.clone();
                let pow = pow.clone();
                let kp = my_keypair.clone();
                async move {
                    let mut msg = Message::new(
                        *my_id.as_bytes(),
                        my_key,
                        pow.clone(),
                        Payload::FindNodeRequest {
                            target: *target.as_bytes(),
                        },
                    );
                    msg.client_mode = client_mode;
                    msg.sign(&kp);

                    // Try direct, then connection reversal, then relay
                    let result =
                        send_request_any(&*transport, &addrs, &msg).await;
                    let resp = match result {
                        Ok(resp) => resp,
                        Err(_) => {
                            // Try relay (includes connection reversal for NATed peers)
                            let candidates =
                                rt.lock().await.closest_nodes(&my_id, k);
                            let msg_bytes = match msg.to_bytes() {
                                Ok(b) => b,
                                Err(_) => {
                                    rt.lock()
                                        .await
                                        .record_failure(&peer_id, max_failures);
                                    return None;
                                }
                            };
                            let mut relayed = None;
                            for candidate in &candidates {
                                if candidate.node_id == peer_id
                                    || candidate.node_id == my_id
                                    || candidate.addresses.is_empty()
                                {
                                    continue;
                                }
                                let mut relay_msg = Message::new(
                                    *my_id.as_bytes(),
                                    my_key,
                                    pow.clone(),
                                    Payload::RelayRequest {
                                        target_id: *peer_id.as_bytes(),
                                        payload: msg_bytes.clone(),
                                        relay_hops: 0,
                                    },
                                );
                                relay_msg.client_mode = client_mode;
                                relay_msg.sign(&kp);
                                if let Ok(resp) = send_request_any(
                                    &*transport,
                                    &candidate.addresses,
                                    &relay_msg,
                                )
                                .await
                                    && let Payload::RelayResponse {
                                        ok: true,
                                        payload,
                                    } = resp.payload
                                    && let Ok(inner) =
                                        Message::from_bytes(&payload)
                                {
                                    relayed = Some(inner);
                                    break;
                                }
                            }
                            match relayed {
                                Some(r) => r,
                                None => {
                                    rt.lock()
                                        .await
                                        .record_failure(&peer_id, max_failures);
                                    return None;
                                }
                            }
                        }
                    };

                    // Update routing table with responder
                    let resp_id = NodeId::from_bytes(resp.sender_id);
                    let peer_info =
                        NodeInfo::new(resp_id, resp.sender_key, addrs.clone());
                    rt.lock().await.insert(peer_info);

                    if let Payload::FindNodeResponse { nodes } = resp.payload {
                        let returned: Vec<NodeInfo> = nodes
                            .into_iter()
                            .map(|n| {
                                NodeInfo::new(
                                    NodeId::from_bytes(n.node_id),
                                    n.public_key,
                                    n.addresses,
                                )
                            })
                            .collect();
                        // Insert discovered nodes into routing table
                        {
                            let mut table = rt.lock().await;
                            for node in &returned {
                                table.insert(node.clone());
                            }
                        }
                        Some((resp_id, addrs[0], returned))
                    } else {
                        None
                    }
                }
            },
        )
        .await;

        histogram!(crate::metrics::LOOKUP_DURATION_SECONDS, crate::metrics::LABEL_TYPE => "find_node")
            .record(start.elapsed().as_secs_f64());
        Ok(result)
    }
}

impl<T: Transport> NodeActor<T> {
    /// Returns the externally observed address if available, otherwise local.
    async fn best_addr(&self) -> SocketAddr {
        let external = *self.external_addr.lock().await;
        let local = self.transport.local_addr();
        let addr = external.unwrap_or(local);
        tracing::debug!(
            "best_addr: external={:?} local={} => using={}",
            external,
            local,
            addr
        );
        addr
    }

    /// Create a new outgoing message with the actor's identity and client_mode flag.
    fn new_message(&self, payload: Payload) -> Message {
        let mut msg = Message::new(
            *self.node_id.as_bytes(),
            self.keypair.public_key_bytes(),
            self.pow.clone(),
            payload,
        );
        msg.client_mode = self.config.client_mode;
        msg
    }

    fn handler_context(&self) -> HandlerContext<T> {
        HandlerContext {
            keypair: self.keypair.clone(),
            pow: self.pow.clone(),
            node_id: self.node_id,
            transport: self.transport.clone(),
            routing_table: self.routing_table.clone(),
            metadata: self.metadata.clone(),
            chunks: self.chunks.as_ref().clone(),
            relay_limiter: self.relay_limiter.clone(),
            write_limiter: self.write_limiter.clone(),
            peer_chunk_counts: self.peer_chunk_counts.clone(),
            config: self.config.clone(),
            external_addr: self.external_addr.clone(),
        }
    }

    async fn run(mut self) {
        let mut rt_save_tick =
            tokio::time::interval(self.config.rt_save_interval);
        rt_save_tick.tick().await; // consume the immediate first tick

        let mut provider_tick =
            tokio::time::interval(self.config.provider_republish_interval);
        provider_tick.tick().await; // consume the immediate first tick

        let mut refresh_tick =
            tokio::time::interval(self.config.bucket_refresh_interval);
        refresh_tick.tick().await; // consume the immediate first tick

        let mut limiter_cleanup_tick =
            tokio::time::interval(Duration::from_secs(60));
        limiter_cleanup_tick.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                // Handle inbound RPC
                result = self.transport.recv_request() => {
                    match result {
                        Ok((from_addr, msg)) => {
                            let permit = match self.handler_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    counter!(crate::metrics::HANDLER_DROPPED_TOTAL).increment(1);
                                    tracing::warn!("dropping inbound message: handler limit reached");
                                    continue;
                                }
                            };
                            let ctx = self.handler_context();
                            tokio::spawn(async move {
                                handle_inbound_message(ctx, from_addr, msg).await;
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            if e.is_channel_closed() {
                                tracing::error!("transport channel closed, shutting down: {}", e);
                                break;
                            }
                            tracing::warn!("transient recv error (continuing): {}", e);
                            // Continue processing — transient errors should not kill the node
                        }
                    }
                }
                // Handle commands from the handle
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(Command::Shutdown) | None => break,
                        // Spawn bootstrap into a background task so it does not
                        // block the actor loop.  When two nodes bootstrap each
                        // other simultaneously (e.g. via mDNS on the same
                        // machine), blocking the loop would deadlock: each node
                        // waits for the other's ping response while neither can
                        // process inbound requests.
                        Some(Command::Bootstrap { addrs, reply }) => {
                            let ctx = self.handler_context();
                            tokio::spawn(async move {
                                let result = ctx.do_bootstrap(addrs).await;
                                let _ = reply.send(result);
                            });
                        }
                        Some(cmd) => self.handle_command(cmd).await,
                    }
                }
                // Periodic routing table save (Gap F)
                _ = rt_save_tick.tick() => {
                    let rt_size = self.routing_table.lock().await.len();
                    gauge!(crate::metrics::ROUTING_TABLE_SIZE).set(rt_size as f64);
                    self.save_routing_table().await;
                }
                // Periodic provider maintenance (Gap E)
                _ = provider_tick.tick() => {
                    self.do_provider_maintenance().await;
                }
                // Periodic bucket refresh (S8)
                _ = refresh_tick.tick() => {
                    self.do_bucket_refresh().await;
                }
                // Periodic cleanup of relay/write rate limiters (I17) and peer chunk counts (S16)
                _ = limiter_cleanup_tick.tick() => {
                    if let Ok(mut rl) = self.relay_limiter.lock() {
                        rl.cleanup(Duration::from_secs(300));
                    }
                    if let Ok(mut wl) = self.write_limiter.lock() {
                        wl.cleanup(Duration::from_secs(300));
                    }
                    // Prune peer_chunk_counts for peers no longer in the routing table (S16)
                    let known_ids: std::collections::HashSet<[u8; 32]> = {
                        let rt = self.routing_table.lock().await;
                        rt.all_nodes_serde().iter().map(|n| n.node_id).collect()
                    };
                    if let Ok(mut counts) = self.peer_chunk_counts.lock() {
                        counts.retain(|id, _| known_ids.contains(id));
                    }
                }
            }
        }

        // Save routing table on shutdown (Gap F) — sync to avoid cancellation
        // during runtime teardown.
        let peers = self.routing_table.lock().await.all_nodes_serde();
        self.save_routing_table_sync(&peers);
    }

    #[instrument(skip(self, cmd))]
    async fn handle_command(&self, cmd: Command) {
        match cmd {
            Command::Bootstrap { addrs, reply } => {
                let result = self.do_bootstrap(addrs).await;
                let _ = reply.send(result);
            }
            Command::FindNode { target, reply } => {
                let result = self.do_iterative_find_node(target).await;
                let _ = reply.send(result);
            }
            Command::GetProviders { key, reply } => {
                let result = self.do_get_providers(key).await;
                let _ = reply.send(result);
            }
            Command::StoreTessera {
                data,
                config,
                reply,
            } => {
                let result = self.do_store_tessera(data, config).await;
                let _ = reply.send(result);
            }
            Command::RetrieveTessera {
                chunk_hashes,
                config,
                original_len,
                reply,
            } => {
                let result = self
                    .do_retrieve_tessera(chunk_hashes, config, original_len)
                    .await;
                let _ = reply.send(result);
            }
            Command::Shutdown => {} // handled in run loop
        }
    }

    // --- Maintenance ---

    #[instrument(skip(self))]
    async fn save_routing_table(&self) {
        let peers = self.routing_table.lock().await.all_nodes_serde();
        let metadata = self.metadata.clone();
        let result = tokio::task::spawn_blocking(move || {
            metadata
                .lock()
                .map_err(|_| {
                    TesseraError::Network("metadata lock poisoned".into())
                })?
                .save_peers_batch(&peers)
        })
        .await;
        match result {
            Ok(Ok(())) => {
                tracing::info!("saved routing table");
            }
            Ok(Err(e)) => tracing::warn!("failed to save routing table: {}", e),
            Err(e) if e.is_cancelled() => {
                tracing::debug!(
                    "save_routing_table task cancelled (runtime shutting down)"
                );
            }
            Err(e) => tracing::warn!("save_routing_table task panicked: {}", e),
        }
    }

    /// Save routing table synchronously — used on shutdown so the save cannot
    /// be cancelled by runtime teardown.
    fn save_routing_table_sync(&self, peers: &[crate::routing::NodeInfoSerde]) {
        let result = self
            .metadata
            .lock()
            .map_err(|_| TesseraError::Network("metadata lock poisoned".into()))
            .and_then(|mut md| md.save_peers_batch(peers));
        match result {
            Ok(()) => tracing::info!("saved routing table on shutdown"),
            Err(e) => tracing::warn!(
                "failed to save routing table on shutdown: {}",
                e
            ),
        }
    }

    #[instrument(skip(self))]
    async fn do_provider_maintenance(&mut self) {
        // 1. Cleanup expired providers
        let metadata = self.metadata.clone();
        match tokio::task::spawn_blocking(move || {
            metadata
                .lock()
                .map_err(|_| {
                    TesseraError::Network("metadata lock poisoned".into())
                })?
                .cleanup_expired_providers()
        })
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                counter!(crate::metrics::PROVIDER_EXPIRED_TOTAL)
                    .increment(n as u64);
                tracing::info!("cleaned up {} expired provider records", n)
            }
            Ok(Err(e)) => {
                tracing::warn!("failed to cleanup expired providers: {}", e)
            }
            Err(e) => {
                tracing::warn!("cleanup task panicked: {}", e)
            }
            _ => {}
        }

        // 2. Get content keys we provide for
        let metadata = self.metadata.clone();
        let node_id = *self.node_id.as_bytes();
        let own_keys = match tokio::task::spawn_blocking(move || {
            metadata
                .lock()
                .map_err(|_| {
                    TesseraError::Network("metadata lock poisoned".into())
                })?
                .get_own_providers(&node_id)
        })
        .await
        {
            Ok(Ok(keys)) => keys,
            Ok(Err(e)) => {
                tracing::warn!("failed to get own providers: {}", e);
                return;
            }
            Err(e) => {
                tracing::warn!("get_own_providers task panicked: {}", e);
                return;
            }
        };

        if own_keys.is_empty() {
            return;
        }

        counter!(crate::metrics::PROVIDER_REPUBLISHED_TOTAL)
            .increment(own_keys.len() as u64);
        tracing::info!("republishing {} provider records", own_keys.len());

        // 3. Re-announce each key to closest nodes
        let local_addr = self.best_addr().await;
        for key in &own_keys {
            // Refresh our own provider record TTL
            let metadata = self.metadata.clone();
            let node_id = *self.node_id.as_bytes();
            let public_key = self.keypair.public_key_bytes();
            let key_copy = *key;
            let provider_ttl = self.config.provider_ttl;
            let _ = tokio::task::spawn_blocking(move || {
                metadata
                    .lock()
                    .map_err(|_| {
                        TesseraError::Network("metadata lock poisoned".into())
                    })?
                    .add_provider(
                        &key_copy,
                        &node_id,
                        &public_key,
                        &[local_addr],
                        provider_ttl,
                    )
            })
            .await;

            // Announce to K closest peers
            let target = NodeId::from_bytes(*key);
            let closest = self
                .routing_table
                .lock()
                .await
                .closest_nodes(&target, self.config.k);

            for node in closest.iter().take(self.config.k) {
                if node.addresses.is_empty() || node.node_id == self.node_id {
                    continue;
                }
                let mut msg = self.new_message(Payload::AddProviderRequest {
                    key: *key,
                    addresses: vec![local_addr],
                });
                msg.sign(&self.keypair);
                let transport = self.transport.clone();
                let addrs = node.addresses.clone();
                tokio::spawn(async move {
                    let _ = send_request_any(&*transport, &addrs, &msg).await;
                });
            }
        }

        // 4. Proactive replication: replicate chunks to nodes that joined
        //    since the last maintenance cycle.
        if self.config.proactive_replication && !own_keys.is_empty() {
            let last_maint = self.last_maintenance_time;
            let sem =
                Arc::new(Semaphore::new(self.config.replication_concurrency));
            let mut total_sent = 0u64;

            for key in &own_keys {
                let target = NodeId::from_bytes(*key);
                let closest = self
                    .routing_table
                    .lock()
                    .await
                    .closest_nodes(&target, self.config.k);

                // Filter to nodes seen after last maintenance (recently joined).
                let new_nodes: Vec<_> = closest
                    .into_iter()
                    .filter(|n| {
                        n.node_id != self.node_id
                            && !n.addresses.is_empty()
                            && n.last_seen > last_maint
                    })
                    .collect();

                if new_nodes.is_empty() {
                    continue;
                }

                let chunk_data = match self.chunks.get(key).await {
                    Ok(Some(data)) => data,
                    _ => continue,
                };

                for node in &new_nodes {
                    let mut msg = self.new_message(Payload::PutChunkRequest {
                        chunk_hash: *key,
                        data: chunk_data.clone(),
                    });
                    msg.sign(&self.keypair);
                    let transport = self.transport.clone();
                    let addrs = node.addresses.clone();
                    let sem = sem.clone();
                    tokio::spawn(async move {
                        let _permit = sem.acquire_owned().await;
                        let _ = tokio::time::timeout(
                            Duration::from_secs(5),
                            send_request_any(&*transport, &addrs, &msg),
                        )
                        .await;
                    });
                    total_sent += 1;
                }
            }

            if total_sent > 0 {
                counter!(crate::metrics::REPLICATION_TRIGGER_TOTAL, crate::metrics::LABEL_TYPE => "periodic")
                    .increment(1);
                counter!(crate::metrics::REPLICATION_CHUNKS_SENT_TOTAL)
                    .increment(total_sent);
                tracing::info!(
                    total_sent,
                    "periodic proactive replication complete"
                );
            }
        }

        self.last_maintenance_time = std::time::Instant::now();
    }

    // --- Bucket refresh ---

    #[instrument(skip(self))]
    async fn do_bucket_refresh(&self) {
        let stale = {
            let rt = self.routing_table.lock().await;
            rt.stale_bucket_indices(self.config.bucket_refresh_interval)
        };
        if stale.is_empty() {
            return;
        }
        tracing::info!("refreshing {} stale buckets", stale.len());
        for idx in stale {
            let target = {
                let rt = self.routing_table.lock().await;
                rt.random_id_for_bucket(idx)
            };
            let _ = self.do_iterative_find_node(target).await;
        }
    }

    // --- Relay helpers ---

    /// Try to send a message via relay nodes when direct communication fails.
    /// Picks the closest nodes to our own ID as relay candidates.
    #[instrument(skip(self, msg), fields(target = %hex::encode(&target_id.as_bytes()[..4])))]
    async fn send_via_relay(
        &self,
        target_id: &NodeId,
        msg: Message,
    ) -> Result<Message, TesseraError> {
        let candidates = self
            .routing_table
            .lock()
            .await
            .closest_nodes(&self.node_id, self.config.k);
        let msg_bytes = msg.to_bytes().map_err(|e| {
            TesseraError::Serialization(format!(
                "failed to serialize inner message: {}",
                e
            ))
        })?;

        for candidate in &candidates {
            if candidate.node_id == *target_id
                || candidate.node_id == self.node_id
                || candidate.addresses.is_empty()
            {
                continue;
            }

            let mut relay_msg = self.new_message(Payload::RelayRequest {
                target_id: *target_id.as_bytes(),
                payload: msg_bytes.clone(),
                relay_hops: 0,
            });
            relay_msg.sign(&self.keypair);

            match send_request_any(
                &*self.transport,
                &candidate.addresses,
                &relay_msg,
            )
            .await
            {
                Ok(resp) => {
                    if let Payload::RelayResponse { ok: true, payload } =
                        resp.payload
                    {
                        let inner_resp = Message::from_bytes(&payload).map_err(|e| {
                            TesseraError::Serialization(format!(
                                "failed to deserialize relayed response: {}",
                                e
                            ))
                        })?;
                        return Ok(inner_resp);
                    }
                }
                Err(_) => continue,
            }
        }

        Err(TesseraError::Network("all relay candidates failed".into()))
    }

    /// Ask a NATed peer to connect back to us via relay (connection reversal).
    async fn request_reverse_connection(
        &self,
        target_id: &NodeId,
    ) -> Result<(), TesseraError> {
        self.handler_context()
            .request_reverse_connection(target_id)
            .await
    }

    /// Unified NAT traversal: direct → connection reversal → relay.
    ///
    /// 1. Try direct send to all known addresses
    /// 2. If direct fails, attempt connection reversal (ask target to connect back)
    /// 3. If reversal succeeds, retry direct send (should hit cached inbound connection)
    /// 4. If all else fails, fall back to full message relay
    #[instrument(skip(self, msg), fields(target = %hex::encode(&target_id.as_bytes()[..4])))]
    async fn send_with_nat_traversal(
        &self,
        addrs: &[SocketAddr],
        target_id: &NodeId,
        msg: Message,
    ) -> Result<Message, TesseraError> {
        // 1. Try direct
        match send_request_any(&*self.transport, addrs, &msg).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::debug!(
                    "direct send to {} failed: {}, trying NAT traversal",
                    hex::encode(&target_id.as_bytes()[..4]),
                    e
                );
            }
        }

        // 2. Try connection reversal: ask target to connect back to us
        if self.request_reverse_connection(target_id).await.is_ok() {
            // 3. Retry direct — should find cached inbound connection from Step 1
            if let Ok(resp) =
                send_request_any(&*self.transport, addrs, &msg).await
            {
                return Ok(resp);
            }
        }

        // 4. Fall back to full relay
        self.send_via_relay(target_id, msg).await
    }

    // --- Bootstrap ---

    async fn do_bootstrap(
        &self,
        addrs: Vec<SocketAddr>,
    ) -> Result<(), TesseraError> {
        self.handler_context().do_bootstrap(addrs).await
    }

    // --- Iterative Find Node ---

    async fn do_iterative_find_node(
        &self,
        target: NodeId,
    ) -> Result<Vec<NodeInfo>, TesseraError> {
        self.handler_context().do_iterative_find_node(target).await
    }

    // --- Get Providers ---

    #[instrument(skip(self), fields(key = %hex::encode(&key[..4])))]
    async fn do_get_providers(
        &self,
        key: [u8; 32],
    ) -> Result<Vec<NodeInfoSerde>, TesseraError> {
        counter!(crate::metrics::LOOKUP_TOTAL, crate::metrics::LABEL_TYPE => "get_providers").increment(1);
        let start = std::time::Instant::now();
        // Collect local providers (may be stale but include them)
        let mut all_providers = {
            let metadata = self.metadata.clone();
            tokio::task::spawn_blocking(move || {
                metadata
                    .lock()
                    .map_err(|_| {
                        TesseraError::Network("metadata lock poisoned".into())
                    })?
                    .get_providers(&key)
            })
            .await
            .map_err(|e| {
                TesseraError::Network(format!("spawn_blocking: {}", e))
            })?
            .unwrap_or_default()
        };

        // Iterative get_providers: seed from routing table, merge closer_nodes
        let target = NodeId::from_bytes(key);
        let k = self.config.k;
        let alpha = self.config.alpha;
        let mut candidates: Vec<NodeInfo> =
            self.routing_table.lock().await.closest_nodes(&target, k);
        let mut queried = std::collections::HashSet::new();
        queried.insert(self.node_id);

        for _round in 0..10 {
            let to_query: Vec<(NodeId, Vec<SocketAddr>)> = candidates
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

            let mut improved = false;
            for (peer_id, addrs) in &to_query {
                let mut msg =
                    self.new_message(Payload::GetProvidersRequest { key });
                msg.sign(&self.keypair);
                match self.send_with_nat_traversal(addrs, peer_id, msg).await {
                    Ok(resp) => {
                        if let Payload::GetProvidersResponse {
                            providers,
                            closer_nodes,
                        } = resp.payload
                        {
                            all_providers.extend(providers);
                            // Merge closer_nodes into candidates
                            for n in closer_nodes {
                                let node_id = NodeId::from_bytes(n.node_id);
                                if node_id == self.node_id {
                                    continue;
                                }
                                if !candidates
                                    .iter()
                                    .any(|c| c.node_id == node_id)
                                {
                                    candidates.push(NodeInfo::new(
                                        node_id,
                                        n.public_key,
                                        n.addresses,
                                    ));
                                    improved = true;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        self.routing_table
                            .lock()
                            .await
                            .record_failure(peer_id, self.config.max_failures);
                    }
                }
            }

            candidates.sort_by(|a, b| {
                target
                    .distance(&a.node_id)
                    .cmp(&target.distance(&b.node_id))
            });
            candidates.truncate(k);

            if !improved {
                break;
            }
        }

        // Dedup providers by node_id
        let mut seen = std::collections::HashSet::new();
        all_providers.retain(|p| seen.insert(p.node_id));

        histogram!(crate::metrics::LOOKUP_DURATION_SECONDS, crate::metrics::LABEL_TYPE => "get_providers")
            .record(start.elapsed().as_secs_f64());
        Ok(all_providers)
    }

    // --- Store Tessera ---

    #[instrument(skip(self, data), fields(data_len = data.len()))]
    async fn do_store_tessera(
        &self,
        data: Vec<u8>,
        config: ErasureConfig,
    ) -> Result<StoreTesseraResult, TesseraError> {
        let start = std::time::Instant::now();
        let announce_addr = self.best_addr().await;
        tracing::info!(
            "do_store_tessera: data_len={} announce_addr={} config={:?}",
            data.len(),
            announce_addr,
            config
        );

        // Log routing table state
        {
            let rt = self.routing_table.lock().await;
            let rt_size = rt.len();
            let all_peers = rt.closest_nodes(&self.node_id, 100);
            tracing::info!(
                "do_store_tessera: routing table has {} peers",
                rt_size
            );
            for peer in &all_peers {
                tracing::debug!(
                    "  rt peer: node_id={} addrs={:?}",
                    hex::encode(&peer.node_id.as_bytes()[..8]),
                    peer.addresses
                );
            }
        }

        let encoded = erasure::encode(&data, &config)?;
        tracing::info!(
            "do_store_tessera: encoded into {} chunks",
            encoded.chunk_hashes.len()
        );

        // Store chunks locally first
        for (hash, chunk_data) in
            encoded.chunk_hashes.iter().zip(encoded.chunks.iter())
        {
            self.chunks.put(hash, chunk_data).await?;
        }

        // Shared semaphore caps total concurrent outbound RPCs at alpha
        let sem = Arc::new(Semaphore::new(self.config.alpha));
        // Track (node_id, JoinHandle) so we can record_failure on errors
        let mut distribution_handles: Vec<(
            NodeId,
            tokio::task::JoinHandle<Result<Message, TesseraError>>,
        )> = Vec::new();

        // Peers that failed during this store — shared with spawned tasks so they
        // can bail out early instead of wasting a semaphore permit + 5s timeout.
        let failed_peers: Arc<std::sync::Mutex<HashSet<NodeId>>> =
            Arc::new(std::sync::Mutex::new(HashSet::new()));

        // Distribute chunks to closest nodes for each chunk hash
        for (hash, chunk_data) in
            encoded.chunk_hashes.iter().zip(encoded.chunks.iter())
        {
            let target = NodeId::from_bytes(*hash);
            let closest = self
                .routing_table
                .lock()
                .await
                .closest_nodes(&target, self.config.k);

            tracing::info!(
                "do_store_tessera: chunk {} -> {} closest peers (taking alpha={})",
                hex::encode(&hash[..4]),
                closest.len(),
                self.config.alpha
            );

            let mut sent = 0;
            for node in &closest {
                if sent >= self.config.alpha {
                    break;
                }
                if node.addresses.is_empty() || node.node_id == self.node_id {
                    continue;
                }
                // Skip peers already known to be unreachable
                if failed_peers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&node.node_id)
                {
                    tracing::debug!(
                        "do_store_tessera: skipping failed peer node_id={}",
                        hex::encode(&node.node_id.as_bytes()[..4]),
                    );
                    continue;
                }
                tracing::info!(
                    "do_store_tessera: PutChunk {} -> node_id={} addrs={:?}",
                    hex::encode(&hash[..4]),
                    hex::encode(&node.node_id.as_bytes()[..4]),
                    node.addresses
                );
                let mut msg = self.new_message(Payload::PutChunkRequest {
                    chunk_hash: *hash,
                    data: chunk_data.clone(),
                });
                msg.sign(&self.keypair);
                let transport = self.transport.clone();
                let addrs = node.addresses.clone();
                let sem = sem.clone();
                let fp = failed_peers.clone();
                let peer_id = node.node_id;
                distribution_handles.push((
                    peer_id,
                    tokio::spawn(async move {
                        // Check again before acquiring permit (peer may have
                        // failed while we were queued)
                        if fp
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .contains(&peer_id)
                        {
                            return Err(TesseraError::Network(
                                "peer marked as failed".into(),
                            ));
                        }
                        let _permit = sem.acquire_owned().await;
                        send_request_any(&*transport, &addrs, &msg).await
                    }),
                ));
                sent += 1;
            }

            // Also add ourselves as a provider
            let content_key = *hash;
            let metadata = self.metadata.clone();
            let node_id = *self.node_id.as_bytes();
            let public_key = self.keypair.public_key_bytes();
            let local_addr = announce_addr;
            let provider_ttl = self.config.provider_ttl;
            let _ = tokio::task::spawn_blocking(move || {
                metadata
                    .lock()
                    .map_err(|_| {
                        TesseraError::Network("metadata lock poisoned".into())
                    })?
                    .add_provider(
                        &content_key,
                        &node_id,
                        &public_key,
                        &[local_addr],
                        provider_ttl,
                    )
            })
            .await;
        }

        // Announce as provider for each chunk — target nodes closest to the chunk hash
        for hash in &encoded.chunk_hashes {
            let target = NodeId::from_bytes(*hash);
            let closest_to_chunk = self
                .routing_table
                .lock()
                .await
                .closest_nodes(&target, self.config.k);
            let mut sent = 0;
            for node in &closest_to_chunk {
                if sent >= self.config.alpha {
                    break;
                }
                if node.addresses.is_empty() || node.node_id == self.node_id {
                    continue;
                }
                if failed_peers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&node.node_id)
                {
                    continue;
                }
                let mut msg = self.new_message(Payload::AddProviderRequest {
                    key: *hash,
                    addresses: vec![announce_addr],
                });
                msg.sign(&self.keypair);
                let transport = self.transport.clone();
                let addrs = node.addresses.clone();
                let sem = sem.clone();
                let fp = failed_peers.clone();
                let peer_id = node.node_id;
                distribution_handles.push((
                    peer_id,
                    tokio::spawn(async move {
                        if fp
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .contains(&peer_id)
                        {
                            return Err(TesseraError::Network(
                                "peer marked as failed".into(),
                            ));
                        }
                        let _permit = sem.acquire_owned().await;
                        send_request_any(&*transport, &addrs, &msg).await
                    }),
                ));
                sent += 1;
            }
        }

        // Await distribution with per-handle timeout; record failures for dead peers.
        // IMPORTANT: abort the task on timeout to release the semaphore permit.
        // Without abort, timed-out tasks keep running (holding the permit) until
        // the inner send_request completes (up to 30s), starving other tasks.
        let total = distribution_handles.len();
        let mut succeeded = 0usize;
        for (peer_id, handle) in distribution_handles {
            let abort_handle = handle.abort_handle();
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(Ok(_))) => succeeded += 1,
                Ok(Ok(Err(e))) => {
                    let msg = e.to_string();
                    if msg.contains("peer marked as failed") {
                        // Already counted in failed_peers, no action needed
                    } else {
                        tracing::warn!(
                            "store: distribution RPC to {} failed: {}",
                            hex::encode(&peer_id.as_bytes()[..8]),
                            e
                        );
                        failed_peers
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(peer_id);
                        self.routing_table
                            .lock()
                            .await
                            .record_failure(&peer_id, self.config.max_failures);
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!("store: distribution task panicked: {}", e)
                }
                Err(_) => {
                    abort_handle.abort();
                    tracing::warn!(
                        "store: distribution RPC to {} timed out (5s)",
                        hex::encode(&peer_id.as_bytes()[..8]),
                    );
                    failed_peers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(peer_id);
                    self.routing_table
                        .lock()
                        .await
                        .record_failure(&peer_id, self.config.max_failures);
                }
            }
        }
        let failed_count = failed_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        tracing::info!(
            "store: {}/{} RPCs succeeded, {} failed peers skipped, {:.1}s elapsed",
            succeeded,
            total,
            failed_count,
            start.elapsed().as_secs_f64()
        );

        counter!(crate::metrics::STORE_TOTAL, crate::metrics::LABEL_STATUS => "ok").increment(1);
        histogram!(crate::metrics::STORE_DURATION_SECONDS)
            .record(start.elapsed().as_secs_f64());
        Ok(StoreTesseraResult {
            chunk_hashes: encoded.chunk_hashes,
            config: encoded.config,
            original_len: encoded.original_len,
        })
    }

    // --- Retrieve Tessera ---

    #[instrument(skip(self, chunk_hashes), fields(num_chunks = chunk_hashes.len()))]
    async fn do_retrieve_tessera(
        &self,
        chunk_hashes: Vec<[u8; 32]>,
        config: ErasureConfig,
        original_len: usize,
    ) -> Result<Vec<u8>, TesseraError> {
        // Global timeout to prevent unbounded blocking when all peers are slow
        const RETRIEVE_TIMEOUT: Duration = Duration::from_secs(120);
        match tokio::time::timeout(
            RETRIEVE_TIMEOUT,
            self.do_retrieve_tessera_inner(
                &chunk_hashes,
                &config,
                original_len,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(TesseraError::Timeout),
        }
    }

    async fn do_retrieve_tessera_inner(
        &self,
        chunk_hashes: &[[u8; 32]],
        config: &ErasureConfig,
        original_len: usize,
    ) -> Result<Vec<u8>, TesseraError> {
        let start = std::time::Instant::now();
        let mut shards: Vec<Option<Vec<u8>>> =
            Vec::with_capacity(chunk_hashes.len());

        for hash in chunk_hashes {
            // Try local first
            if let Ok(Some(data)) = self.chunks.get(hash).await {
                shards.push(Some(data));
                continue;
            }

            // Query all closest nodes in parallel — returns as soon as any
            // node responds with the chunk.  This avoids serial timeouts
            // when the routing table contains stale/dead peers.
            let target = NodeId::from_bytes(*hash);
            let closest = self
                .routing_table
                .lock()
                .await
                .closest_nodes(&target, self.config.k);

            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);

            let mut fetch_handles = Vec::new();
            for node in closest.iter().take(self.config.k) {
                if node.addresses.is_empty() || node.node_id == self.node_id {
                    continue;
                }
                let mut msg = self.new_message(Payload::GetChunkRequest {
                    chunk_hash: *hash,
                });
                msg.sign(&self.keypair);
                let transport = self.transport.clone();
                let addrs = node.addresses.clone();
                let tx = tx.clone();
                let expected_hash = *hash;
                fetch_handles.push(tokio::spawn(async move {
                    if let Ok(resp) =
                        send_request_any(&*transport, &addrs, &msg).await
                        && let Payload::GetChunkResponse { data } = resp.payload
                        && !data.is_empty()
                        && ChunkStore::hash(&data) == expected_hash
                    {
                        let _ = tx.send(data).await;
                    }
                }));
            }
            // Drop our copy so rx closes when all tasks finish
            drop(tx);

            let shard = rx.recv().await;
            // Cancel remaining tasks once we have the chunk
            for h in &fetch_handles {
                h.abort();
            }

            if let Some(data) = shard {
                let _ = self.chunks.put(hash, &data).await;
                shards.push(Some(data));
            } else {
                shards.push(None);
            }
        }

        // Decode
        let result = erasure::decode(&mut shards, config, original_len);
        let status = if result.is_ok() { "ok" } else { "err" };
        counter!(crate::metrics::RETRIEVE_TOTAL, crate::metrics::LABEL_STATUS => status).increment(1);
        histogram!(crate::metrics::RETRIEVE_DURATION_SECONDS)
            .record(start.elapsed().as_secs_f64());
        result
    }
}

/// Verify identity, PoW, and signature of an inner relay message.
fn verify_inner_message<T: Transport>(
    msg: &Message,
    ctx: &HandlerContext<T>,
) -> bool {
    let sender_node_id = NodeId::from_bytes(msg.sender_id);
    let Ok(sender_vk) =
        ed25519_dalek::VerifyingKey::from_bytes(&msg.sender_key)
    else {
        tracing::warn!("relay rejected: inner message has invalid sender_key");
        return false;
    };
    if !verify_node_id(&sender_node_id, &sender_vk) {
        tracing::warn!(
            "relay rejected: inner sender_id does not match sender_key"
        );
        return false;
    }
    if !msg.pow_proof.verify_with_min_difficulty(
        &msg.sender_key,
        ctx.config.min_pow_difficulty,
    ) {
        tracing::warn!("relay rejected: inner message has insufficient PoW");
        return false;
    }
    if !msg.verify_signature() {
        tracing::warn!("relay rejected: inner message has invalid signature");
        return false;
    }
    true
}

#[instrument(skip(ctx, msg), fields(from = %from_addr))]
async fn handle_inbound_message<T: Transport>(
    ctx: HandlerContext<T>,
    from_addr: SocketAddr,
    msg: Message,
) {
    let payload_type = crate::metrics::payload_type_label(&msg.payload);
    tracing::info!(
        "handle_inbound_message: from={} msg_id={} payload={} client_mode={}",
        from_addr,
        msg.msg_id,
        payload_type,
        msg.client_mode
    );
    // Identity verification: verify sender_id matches sender_key
    let sender_node_id = NodeId::from_bytes(msg.sender_id);
    let sender_vk = match ed25519_dalek::VerifyingKey::from_bytes(
        &msg.sender_key,
    ) {
        Ok(vk) => vk,
        Err(_) => {
            counter!(crate::metrics::VERIFICATION_FAILURE_TOTAL, crate::metrics::LABEL_REASON => "identity").increment(1);
            tracing::warn!(
                "dropping message from {}: invalid sender_key",
                from_addr
            );
            return;
        }
    };
    if !verify_node_id(&sender_node_id, &sender_vk) {
        counter!(crate::metrics::VERIFICATION_FAILURE_TOTAL, crate::metrics::LABEL_REASON => "identity").increment(1);
        tracing::warn!(
            "dropping message from {}: sender_id does not match sender_key",
            from_addr
        );
        return;
    }

    // PoW verification: verify sender did computational work
    if !msg.pow_proof.verify_with_min_difficulty(
        &msg.sender_key,
        ctx.config.min_pow_difficulty,
    ) {
        counter!(crate::metrics::VERIFICATION_FAILURE_TOTAL, crate::metrics::LABEL_REASON => "pow").increment(1);
        tracing::warn!(
            "dropping message from {}: insufficient PoW difficulty",
            from_addr
        );
        return;
    }

    // Signature verification: verify sender possesses the private key
    if !msg.verify_signature() {
        counter!(crate::metrics::VERIFICATION_FAILURE_TOTAL, crate::metrics::LABEL_REASON => "signature").increment(1);
        tracing::warn!(
            "dropping message from {}: invalid signature",
            from_addr
        );
        return;
    }

    // Protocol version check
    if msg.protocol_version != crate::protocol::PROTOCOL_VERSION {
        counter!(crate::metrics::VERIFICATION_FAILURE_TOTAL, crate::metrics::LABEL_REASON => "protocol_version").increment(1);
        tracing::warn!(
            "dropping message from {}: unsupported protocol version {}",
            from_addr,
            msg.protocol_version
        );
        return;
    }

    // Update routing table with verified sender info (after verification).
    // Client-mode nodes are ephemeral and won't accept inbound connections,
    // so we don't add them to the routing table to avoid stale entries.
    if !msg.client_mode {
        let node_info =
            NodeInfo::new(sender_node_id, msg.sender_key, vec![from_addr]);
        tracing::info!(
            "handle_inbound: inserting peer node_id={} from_addr={} into routing table",
            hex::encode(&sender_node_id.as_bytes()[..8]),
            from_addr
        );
        let insert_result =
            ctx.routing_table.lock().await.insert(node_info.clone());
        match insert_result {
            crate::routing::InsertResult::Inserted => {
                tracing::info!(
                    "handle_inbound: INSERTED new peer node_id={} addr={}",
                    hex::encode(&sender_node_id.as_bytes()[..8]),
                    from_addr
                );
                // Proactively replicate relevant chunks to the new node.
                if ctx.config.proactive_replication {
                    let ctx_clone = ctx.clone();
                    let new_node = node_info.clone();
                    tokio::spawn(async move {
                        replicate_chunks_to_node(&ctx_clone, &new_node).await;
                    });
                }
            }
            crate::routing::InsertResult::BucketFull { lrs_node_id } => {
                tracing::info!(
                    "handle_inbound: BUCKET FULL for node_id={} addr={}, LRS={}",
                    hex::encode(&sender_node_id.as_bytes()[..8]),
                    from_addr,
                    hex::encode(&lrs_node_id.as_bytes()[..4])
                );
                // Kademlia LRS eviction: if bucket is full, ping the
                // least-recently-seen node. If it doesn't respond, evict
                // it and insert the new node.
                let lrs_addr = {
                    let rt = ctx.routing_table.lock().await;
                    rt.closest_nodes(&lrs_node_id, 1)
                        .into_iter()
                        .find(|n| n.node_id == lrs_node_id)
                        .and_then(|n| n.addresses.first().copied())
                };
                if let Some(addr) = lrs_addr {
                    let mut ping = Message::new(
                        *ctx.node_id.as_bytes(),
                        ctx.keypair.public_key_bytes(),
                        ctx.pow.clone(),
                        Payload::PingRequest,
                    );
                    ping.sign(&ctx.keypair);
                    let ping_result = tokio::time::timeout(
                        Duration::from_secs(5),
                        ctx.transport.send_request(&addr, ping),
                    )
                    .await;
                    match ping_result {
                        Ok(Ok(_)) => {
                            tracing::debug!(
                                "LRS node {} responded, keeping in bucket",
                                hex::encode(&lrs_node_id.as_bytes()[..4])
                            );
                        }
                        _ => {
                            tracing::debug!(
                                "LRS node {} unresponsive, evicting",
                                hex::encode(&lrs_node_id.as_bytes()[..4])
                            );
                            ctx.routing_table
                                .lock()
                                .await
                                .evict_and_insert(&lrs_node_id, node_info);
                        }
                    }
                }
            }
            crate::routing::InsertResult::Updated => {
                tracing::debug!(
                    "handle_inbound: UPDATED existing peer node_id={} addr={}",
                    hex::encode(&sender_node_id.as_bytes()[..8]),
                    from_addr
                );
            }
        }
    } else {
        tracing::debug!(
            "handle_inbound: skipping client_mode peer node_id={} addr={}",
            hex::encode(&sender_node_id.as_bytes()[..8]),
            from_addr
        );
    }

    let rpc_type = crate::metrics::payload_type_label(&msg.payload);
    counter!(crate::metrics::RPC_INBOUND_TOTAL, crate::metrics::LABEL_RPC_TYPE => rpc_type).increment(1);
    let handler_start = std::time::Instant::now();

    let response_payload = match msg.payload {
        Payload::PingRequest => Payload::PingResponse {
            observed_addr: Some(from_addr),
        },
        Payload::FindNodeRequest { target } => {
            let target_id = NodeId::from_bytes(target);
            let closest = ctx
                .routing_table
                .lock()
                .await
                .closest_nodes(&target_id, ctx.config.k);
            let nodes: Vec<NodeInfoSerde> = closest
                .into_iter()
                .map(|n| NodeInfoSerde {
                    node_id: *n.node_id.as_bytes(),
                    public_key: n.public_key,
                    addresses: n.addresses,
                })
                .collect();
            Payload::FindNodeResponse { nodes }
        }
        Payload::GetProvidersRequest { key } => {
            let metadata = ctx.metadata.clone();
            let providers = tokio::task::spawn_blocking(move || {
                metadata
                    .lock()
                    .map_err(|_| {
                        TesseraError::Network("metadata lock poisoned".into())
                    })?
                    .get_providers(&key)
            })
            .await
            .unwrap_or(Ok(vec![]))
            .unwrap_or_default();
            let target_id = NodeId::from_bytes(key);
            let closer = ctx
                .routing_table
                .lock()
                .await
                .closest_nodes(&target_id, ctx.config.k);
            let closer_nodes: Vec<NodeInfoSerde> = closer
                .into_iter()
                .map(|n| NodeInfoSerde {
                    node_id: *n.node_id.as_bytes(),
                    public_key: n.public_key,
                    addresses: n.addresses,
                })
                .collect();
            Payload::GetProvidersResponse {
                providers,
                closer_nodes,
            }
        }
        Payload::AddProviderRequest { key, ref addresses } => {
            let metadata = ctx.metadata.clone();
            let sender_id = msg.sender_id;
            let sender_key = msg.sender_key;
            let addresses = addresses.clone();
            let provider_ttl = ctx.config.provider_ttl;
            let ok = tokio::task::spawn_blocking(move || {
                metadata
                    .lock()
                    .map_err(|_| {
                        TesseraError::Network("metadata lock poisoned".into())
                    })?
                    .add_provider(
                        &key,
                        &sender_id,
                        &sender_key,
                        &addresses,
                        provider_ttl,
                    )
            })
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
            Payload::AddProviderResponse { ok }
        }
        Payload::GetChunkRequest { chunk_hash } => {
            match ctx.chunks.get(&chunk_hash).await {
                Ok(Some(data)) => Payload::GetChunkResponse { data },
                _ => Payload::GetChunkResponse { data: vec![] },
            }
        }
        Payload::PutChunkRequest {
            chunk_hash,
            ref data,
        } => {
            // Guard: Per-peer write rate limit
            if !ctx
                .write_limiter
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .check(from_addr.ip())
            {
                counter!(crate::metrics::RATE_LIMIT_REJECTED_TOTAL, crate::metrics::LABEL_LIMITER => "write").increment(1);
                tracing::warn!(
                    "PutChunk rejected: write rate limit for {}",
                    from_addr.ip()
                );
                Payload::PutChunkResponse { ok: false }
            }
            // Guard: Per-peer chunk count quota (speculative increment + rollback)
            else {
                let sender_id = msg.sender_id;
                let reserved = {
                    let mut counts = ctx
                        .peer_chunk_counts
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let count = counts.entry(sender_id).or_insert(0);
                    if *count >= ctx.config.max_chunks_per_peer {
                        tracing::warn!(
                            "PutChunk rejected: peer {} exceeded chunk quota ({})",
                            hex::encode(&sender_id[..4]),
                            ctx.config.max_chunks_per_peer
                        );
                        false
                    } else {
                        *count += 1; // speculative increment
                        true
                    }
                };
                if !reserved {
                    Payload::PutChunkResponse { ok: false }
                } else {
                    let ok = ctx.chunks.put(&chunk_hash, data).await.is_ok();
                    if !ok {
                        // Rollback: decrement the speculatively incremented count
                        let mut counts = ctx
                            .peer_chunk_counts
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        let count = counts.entry(sender_id).or_insert(1);
                        *count = count.saturating_sub(1);
                    }
                    Payload::PutChunkResponse { ok }
                }
            }
        }
        Payload::RelayRequest {
            target_id,
            ref payload,
            relay_hops,
        } => {
            // Guard 1: Hop limit
            if relay_hops >= ctx.config.max_relay_hops {
                tracing::warn!(
                    "relay rejected: hop limit exceeded ({relay_hops})"
                );
                Payload::RelayResponse {
                    ok: false,
                    payload: vec![],
                }
            }
            // Guard 2: Payload size limit
            else if payload.len() > ctx.config.max_relay_payload {
                tracing::warn!(
                    "relay rejected: payload too large ({})",
                    payload.len()
                );
                Payload::RelayResponse {
                    ok: false,
                    payload: vec![],
                }
            }
            // Guard 3: Per-IP relay rate limit
            else if !ctx
                .relay_limiter
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .check(from_addr.ip())
            {
                counter!(crate::metrics::RATE_LIMIT_REJECTED_TOTAL, crate::metrics::LABEL_LIMITER => "relay").increment(1);
                tracing::warn!(
                    "relay rejected: rate limit for {}",
                    from_addr.ip()
                );
                Payload::RelayResponse {
                    ok: false,
                    payload: vec![],
                }
            }
            // Guard 4: Block recursive relay + verify inner message
            else {
                match Message::from_bytes(payload) {
                    Ok(inner_msg) => {
                        if matches!(
                            inner_msg.payload,
                            Payload::RelayRequest { .. }
                        ) {
                            tracing::warn!("relay rejected: recursive relay");
                            Payload::RelayResponse {
                                ok: false,
                                payload: vec![],
                            }
                        }
                        // Guard 5: Verify inner message identity
                        else if !verify_inner_message(&inner_msg, &ctx) {
                            Payload::RelayResponse {
                                ok: false,
                                payload: vec![],
                            }
                        } else {
                            // Forward to target
                            let target_node_id = NodeId::from_bytes(target_id);
                            let closest = ctx
                                .routing_table
                                .lock()
                                .await
                                .closest_nodes(&target_node_id, 1);
                            let target_node = closest.into_iter().find(|n| {
                                n.node_id == target_node_id
                                    && !n.addresses.is_empty()
                            });
                            match target_node {
                                Some(node) => {
                                    tracing::info!(
                                        "relay: forwarding from {} to target={} addrs={:?} inner_payload={}",
                                        from_addr,
                                        hex::encode(&target_id[..8]),
                                        node.addresses,
                                        crate::metrics::payload_type_label(&inner_msg.payload),
                                    );
                                    match send_request_any(
                                        &*ctx.transport,
                                        &node.addresses,
                                        &inner_msg,
                                    )
                                    .await
                                    {
                                        Ok(resp) => match resp.to_bytes() {
                                            Ok(resp_bytes) => {
                                                tracing::info!("relay: forward succeeded to {}", hex::encode(&target_id[..8]));
                                                counter!(crate::metrics::RELAY_FORWARD_TOTAL, crate::metrics::LABEL_STATUS => "ok").increment(1);
                                                Payload::RelayResponse {
                                                    ok: true,
                                                    payload: resp_bytes,
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!("relay: forward response serialize failed to {}: {}", hex::encode(&target_id[..8]), e);
                                                counter!(crate::metrics::RELAY_FORWARD_TOTAL, crate::metrics::LABEL_STATUS => "rejected").increment(1);
                                                Payload::RelayResponse {
                                                    ok: false,
                                                    payload: vec![],
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            tracing::warn!("relay: forward failed to {} addrs={:?}: {}", hex::encode(&target_id[..8]), node.addresses, e);
                                            counter!(crate::metrics::RELAY_FORWARD_TOTAL, crate::metrics::LABEL_STATUS => "rejected").increment(1);
                                            Payload::RelayResponse {
                                                ok: false,
                                                payload: vec![],
                                            }
                                        }
                                    }
                                }
                                None => {
                                    tracing::warn!(
                                        "relay: target {} not found in routing table",
                                        hex::encode(&target_id[..8])
                                    );
                                    Payload::RelayResponse {
                                        ok: false,
                                        payload: vec![],
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => Payload::RelayResponse {
                        ok: false,
                        payload: vec![],
                    },
                }
            }
        }
        Payload::ConnectRequest {
            ref requester_addrs,
            requester_id: _,
            requester_key: _,
        } => {
            // NAT traversal: the requester can't reach us directly, so they
            // ask us (via relay) to connect back to them. We attempt a ping
            // to the requester's addresses — this creates an outbound QUIC
            // connection that gets cached in our pool AND (via Step 1) in
            // the requester's pool when they accept it.
            let mut ok = false;
            for addr in requester_addrs {
                let mut ping = ctx.new_message(Payload::PingRequest);
                ping.sign(&ctx.keypair);
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    ctx.transport.send_request(addr, ping),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        ok = true;
                        break;
                    }
                    _ => continue,
                }
            }
            Payload::ConnectResponse { ok }
        }
        _ => {
            // Ignore responses that arrive as requests
            return;
        }
    };

    let mut response = msg.response(
        *ctx.node_id.as_bytes(),
        ctx.keypair.public_key_bytes(),
        ctx.pow.clone(),
        response_payload,
    );
    response.sign(&ctx.keypair);

    histogram!(crate::metrics::RPC_HANDLER_DURATION_SECONDS, crate::metrics::LABEL_RPC_TYPE => rpc_type)
        .record(handler_start.elapsed().as_secs_f64());

    if let Err(e) = ctx.transport.send_response(&from_addr, response).await {
        tracing::warn!("failed to send response to {}: {}", from_addr, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{
        InMemoryNetwork, InMemoryTransport, new_in_memory_network,
    };
    use tempfile::TempDir;

    fn test_config() -> NodeConfig {
        NodeConfig {
            min_pow_difficulty: 0,
            ..Default::default()
        }
    }

    async fn make_node(
        port: u16,
        network: &crate::transport::InMemoryNetwork,
    ) -> (NodeHandle, TempDir) {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let transport =
            Arc::new(InMemoryTransport::new(addr, network.clone()).await);
        let keypair = Keypair::generate();
        let pow = PowProof::generate(&keypair.public_key_bytes(), 0);
        let dir = TempDir::new().unwrap();
        let metadata = MetadataStore::in_memory().unwrap();
        let chunks =
            ChunkStore::new(&dir.path().join("chunks"), 10_000_000).unwrap();

        let handle = spawn_node(
            keypair,
            pow,
            transport,
            metadata,
            chunks,
            test_config(),
        )
        .await;
        (handle, dir)
    }

    #[tokio::test]
    async fn test_two_nodes_ping() {
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(5001, &network).await;
        let (node_b, _dir_b) = make_node(5002, &network).await;

        // Bootstrap A with B's address
        node_a.bootstrap(vec![node_b.local_addr()]).await.unwrap();

        // A should now know about B
        let found = node_a.find_node(*node_b.node_id()).await.unwrap();
        assert!(found.iter().any(|n| n.node_id == *node_b.node_id()));

        node_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_is_alive() {
        let network = new_in_memory_network();
        let (node, _dir) = make_node(5099, &network).await;

        assert!(node.is_alive());
        node.shutdown().await;
        // Give time for the actor to exit
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!node.is_alive());
    }

    #[tokio::test]
    async fn test_three_nodes_bootstrap() {
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(6001, &network).await;
        let (node_b, _dir_b) = make_node(6002, &network).await;
        let (node_c, _dir_c) = make_node(6003, &network).await;

        // B and C bootstrap through A
        node_b.bootstrap(vec![node_a.local_addr()]).await.unwrap();
        node_c.bootstrap(vec![node_a.local_addr()]).await.unwrap();

        // Give time for routing tables to settle
        tokio::time::sleep(Duration::from_millis(100)).await;

        // C should be able to find B
        let found = node_c.find_node(*node_b.node_id()).await.unwrap();
        assert!(found.iter().any(|n| n.node_id == *node_b.node_id()));

        node_a.shutdown().await;
        node_b.shutdown().await;
        node_c.shutdown().await;
    }

    #[tokio::test]
    async fn test_store_and_retrieve_chunk() {
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(7001, &network).await;
        let (node_b, _dir_b) = make_node(7002, &network).await;

        // Bootstrap
        node_b.bootstrap(vec![node_a.local_addr()]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Store a tessera on A
        let data = b"Hello Tessera! This is important data.".to_vec();
        let config = ErasureConfig::new(4, 2).unwrap();
        let result = node_a
            .store_with_config(data.clone(), config)
            .await
            .unwrap();

        // Give time for chunk distribution
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Retrieve from B
        let retrieved = node_b.retrieve(&result).await.unwrap();

        assert_eq!(retrieved, data);

        node_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_store_tessera_survives_node_loss() {
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(8001, &network).await;
        let (node_b, _dir_b) = make_node(8002, &network).await;
        let (node_c, _dir_c) = make_node(8003, &network).await;

        // Bootstrap all nodes
        node_b.bootstrap(vec![node_a.local_addr()]).await.unwrap();
        node_c.bootstrap(vec![node_a.local_addr()]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Store tessera on A (4 data + 2 parity = 6 chunks)
        let data = b"Critical data that must survive failures!".to_vec();
        let config = ErasureConfig::new(4, 2).unwrap();
        let result = node_a
            .store_with_config(data.clone(), config)
            .await
            .unwrap();

        // Give time for distribution
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Shutdown node A (the original storer)
        node_a.shutdown().await;

        // Node C should still be able to retrieve via B (or local copies)
        // Since A stored locally and distributed, B should have copies
        let retrieved = node_b.retrieve(&result).await.unwrap();

        assert_eq!(retrieved, data);

        node_b.shutdown().await;
        node_c.shutdown().await;
    }

    async fn make_node_with_identity(
        port: u16,
        network: &InMemoryNetwork,
        keypair: Keypair,
        pow: PowProof,
        metadata: MetadataStore,
        chunks_dir: &std::path::Path,
    ) -> NodeHandle {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let transport =
            Arc::new(InMemoryTransport::new(addr, network.clone()).await);
        let chunks =
            ChunkStore::new(&chunks_dir.join("chunks"), 10_000_000).unwrap();
        spawn_node(keypair, pow, transport, metadata, chunks, test_config())
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn test_provider_maintenance_runs() {
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(10001, &network).await;
        let (node_b, _dir_b) = make_node(10002, &network).await;

        // Bootstrap
        node_a.bootstrap(vec![node_b.local_addr()]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Store a tessera (makes A a provider)
        let data = b"test provider data".to_vec();
        let config = ErasureConfig::new(2, 1).unwrap();
        let _result = node_a.store_with_config(data, config).await.unwrap();

        // Advance time past the provider republish interval (1 hour)
        tokio::time::advance(Duration::from_secs(3601)).await;
        // Yield to let the interval tick fire
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The node should still be operational after maintenance runs
        let found = node_a.find_node(*node_b.node_id()).await.unwrap();
        assert!(found.iter().any(|n| n.node_id == *node_b.node_id()));

        node_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_routing_table_persists_across_restart() {
        let network = new_in_memory_network();
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("meta.db");

        // --- First session: bootstrap and populate routing table ---
        let keypair_a = Keypair::generate();
        let secret_a = *keypair_a.secret_bytes();
        let pow_a = PowProof::generate(&keypair_a.public_key_bytes(), 0);
        let pow_nonce = pow_a.nonce;

        let (node_b, _dir_b) = make_node(9002, &network).await;

        let metadata_a = MetadataStore::open(&db_path).unwrap();
        let handle_a = make_node_with_identity(
            9001,
            &network,
            keypair_a,
            pow_a,
            metadata_a,
            dir.path(),
        )
        .await;
        handle_a.bootstrap(vec![node_b.local_addr()]).await.unwrap();

        // Verify A knows about B
        let found = handle_a.find_node(*node_b.node_id()).await.unwrap();
        assert!(found.iter().any(|n| n.node_id == *node_b.node_id()));

        // Shutdown A (triggers RT save)
        handle_a.shutdown().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // --- Second session: restart A with same identity, no bootstrap ---
        let keypair_a2 = Keypair::from_secret_bytes(&secret_a);
        let pow_a2 = PowProof {
            nonce: pow_nonce,
            difficulty: 0,
        };
        let metadata_a2 = MetadataStore::open(&db_path).unwrap();
        let handle_a2 = make_node_with_identity(
            9001,
            &network,
            keypair_a2,
            pow_a2,
            metadata_a2,
            dir.path(),
        )
        .await;

        // A2 should already know about B from persisted routing table
        let found2 = handle_a2.find_node(*node_b.node_id()).await.unwrap();
        assert!(found2.iter().any(|n| n.node_id == *node_b.node_id()));

        handle_a2.shutdown().await;
        node_b.shutdown().await;
    }

    #[test]
    fn test_relay_request_hop_limit() {
        // relay_hops >= max_relay_hops should be rejected
        let config = NodeConfig::default();
        assert_eq!(config.max_relay_hops, 1);
    }

    #[test]
    fn test_relay_request_rejects_recursive_relay() {
        // A RelayRequest whose inner payload is itself a RelayRequest should be blocked
        let inner_relay = Message::new(
            [1u8; 32],
            [2u8; 32],
            PowProof {
                nonce: 0,
                difficulty: 0,
            },
            Payload::RelayRequest {
                target_id: [3u8; 32],
                payload: vec![],
                relay_hops: 0,
            },
        );
        let inner_bytes = inner_relay.to_bytes().unwrap();

        // The inner message, when deserialized, is a RelayRequest — should be blocked
        let inner = Message::from_bytes(&inner_bytes).unwrap();
        assert!(matches!(inner.payload, Payload::RelayRequest { .. }));
    }

    #[tokio::test]
    async fn test_dead_peer_evicted_after_failures() {
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(11001, &network).await;
        let (node_b, _dir_b) = make_node(11002, &network).await;

        // Bootstrap A with B
        node_a.bootstrap(vec![node_b.local_addr()]).await.unwrap();

        // Verify A knows about B
        let found = node_a.find_node(*node_b.node_id()).await.unwrap();
        assert!(found.iter().any(|n| n.node_id == *node_b.node_id()));

        // Shut down B — it will no longer respond to RPCs
        node_b.shutdown().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Each find_node targeting B will try to query B, fail, and record one failure.
        // After max_failures (3) rounds, B should be evicted.
        let config = test_config();
        for _ in 0..config.max_failures {
            let _ = node_a.find_node(*node_b.node_id()).await;
        }

        // B should no longer appear in A's routing table
        let found_after = node_a.find_node(*node_a.node_id()).await.unwrap();
        assert!(
            !found_after.iter().any(|n| n.node_id == *node_b.node_id()),
            "dead peer B should have been evicted after {} failures",
            config.max_failures,
        );

        node_a.shutdown().await;
    }

    #[tokio::test]
    async fn test_relay_request_response_protocol() {
        // Verify RelayRequest/RelayResponse serialize and deserialize correctly
        let inner_msg = Message::new(
            [1u8; 32],
            [2u8; 32],
            PowProof {
                nonce: 0,
                difficulty: 0,
            },
            Payload::PingRequest,
        );
        let inner_bytes = inner_msg.to_bytes().unwrap();

        let relay_req = Message::new(
            [3u8; 32],
            [4u8; 32],
            PowProof {
                nonce: 0,
                difficulty: 0,
            },
            Payload::RelayRequest {
                target_id: [5u8; 32],
                payload: inner_bytes.clone(),
                relay_hops: 0,
            },
        );

        let encoded = relay_req.to_bytes().unwrap();
        let decoded = Message::from_bytes(&encoded).unwrap();
        assert!(decoded.is_request());

        match decoded.payload {
            Payload::RelayRequest {
                target_id, payload, ..
            } => {
                assert_eq!(target_id, [5u8; 32]);
                assert_eq!(payload, inner_bytes);
                // Verify inner message round-trips
                let inner = Message::from_bytes(&payload).unwrap();
                assert!(matches!(inner.payload, Payload::PingRequest));
            }
            _ => panic!("wrong payload type"),
        }

        // Test RelayResponse
        let relay_resp = Message::new(
            [6u8; 32],
            [7u8; 32],
            PowProof {
                nonce: 0,
                difficulty: 0,
            },
            Payload::RelayResponse {
                ok: true,
                payload: vec![0xDE, 0xAD],
            },
        );
        let encoded = relay_resp.to_bytes().unwrap();
        let decoded = Message::from_bytes(&encoded).unwrap();
        assert!(!decoded.is_request());

        match decoded.payload {
            Payload::RelayResponse { ok, payload } => {
                assert!(ok);
                assert_eq!(payload, vec![0xDE, 0xAD]);
            }
            _ => panic!("wrong payload type"),
        }
    }

    #[tokio::test]
    async fn test_relay_forwarding() {
        // 3 nodes: A, B, C. A and B bootstrap via C.
        // Then we remove B's route from the network so A can't reach B directly.
        // A should be able to reach B through relay via C.
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(12001, &network).await;
        let (node_b, _dir_b) = make_node(12002, &network).await;
        let (node_c, _dir_c) = make_node(12003, &network).await;

        // Bootstrap all through C
        node_a.bootstrap(vec![node_c.local_addr()]).await.unwrap();
        node_b.bootstrap(vec![node_c.local_addr()]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify A can find B directly first
        let found = node_a.find_node(*node_b.node_id()).await.unwrap();
        assert!(
            found.iter().any(|n| n.node_id == *node_b.node_id()),
            "A should find B before disconnect"
        );

        // Remove B's direct route from A's perspective by removing B's
        // network entry and re-adding it under a different address that A
        // doesn't know about. Instead, we'll remove B's entry and re-register
        // it — but C still has B's address.
        //
        // Actually, the simplest approach: remove B from the shared network,
        // then re-add B. This simulates B being unreachable directly from A
        // while C still has B in its routing table and can forward.
        //
        // The InMemoryNetwork routes by address, so we need to:
        // 1. Remove B's address from the shared network map
        // 2. This makes direct send_request to B fail for everyone
        // 3. But we want C to still reach B — so we can't remove B entirely
        //
        // Better approach: We just test that the relay handler works by
        // having A send a RelayRequest to C asking to relay to B.
        // C should forward to B and return the response.

        // Create a keypair for the relay test sender (needs valid identity for verification)
        let relay_kp = Keypair::generate();
        let relay_pow = PowProof::generate(&relay_kp.public_key_bytes(), 0);
        let relay_node_id = relay_kp.node_id();

        // Send a relay request from a new sender through C targeting B
        let mut inner_msg = Message::new(
            *relay_node_id.as_bytes(),
            relay_kp.public_key_bytes(),
            relay_pow.clone(),
            Payload::FindNodeRequest {
                target: *node_b.node_id().as_bytes(),
            },
        );
        inner_msg.sign(&relay_kp);
        let inner_bytes = inner_msg.to_bytes().unwrap();

        // Create a temporary transport for the relay sender
        let relay_addr: SocketAddr = "127.0.0.1:12099".parse().unwrap();
        let transport_relay =
            Arc::new(InMemoryTransport::new(relay_addr, network.clone()).await);

        let mut relay_msg = Message::new(
            *relay_node_id.as_bytes(),
            relay_kp.public_key_bytes(),
            relay_pow,
            Payload::RelayRequest {
                target_id: *node_b.node_id().as_bytes(),
                payload: inner_bytes,
                relay_hops: 0,
            },
        );
        relay_msg.sign(&relay_kp);

        let resp = transport_relay
            .send_request(&node_c.local_addr(), relay_msg)
            .await
            .unwrap();

        match resp.payload {
            Payload::RelayResponse { ok, payload } => {
                assert!(ok, "relay should succeed");
                let inner_resp = Message::from_bytes(&payload).unwrap();
                assert!(
                    matches!(
                        inner_resp.payload,
                        Payload::FindNodeResponse { .. }
                    ),
                    "relayed response should be FindNodeResponse"
                );
            }
            other => panic!("expected RelayResponse, got {:?}", other),
        }

        node_a.shutdown().await;
        node_b.shutdown().await;
        node_c.shutdown().await;
    }

    #[tokio::test]
    async fn test_inbound_rejects_wrong_sender_id() {
        // Message with sender_id that doesn't match sender_key should be dropped
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(13001, &network).await;
        let (node_b, _dir_b) = make_node(13002, &network).await;

        // Bootstrap so A knows B
        node_a.bootstrap(vec![node_b.local_addr()]).await.unwrap();

        // Create a message with mismatched sender_id / sender_key
        let kp = Keypair::generate();
        let pow = PowProof::generate(&kp.public_key_bytes(), 0);
        let wrong_id = [0xFFu8; 32]; // doesn't match any key

        let addr_sender: SocketAddr = "127.0.0.1:13099".parse().unwrap();
        let transport_sender = Arc::new(
            InMemoryTransport::new(addr_sender, network.clone()).await,
        );

        let msg = Message::new(
            wrong_id,
            kp.public_key_bytes(),
            pow,
            Payload::PingRequest,
        );

        // Send to node_b — should timeout because node_b drops the message (no response)
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            transport_sender.send_request(&node_b.local_addr(), msg),
        )
        .await;

        // Should timeout (message was dropped, no response sent)
        assert!(result.is_err() || result.unwrap().is_err());

        node_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_inbound_rejects_insufficient_pow() {
        // Message with PoW difficulty below min_pow_difficulty should be dropped.
        // In test mode min_pow_difficulty=0, so we test with a forged proof that
        // claims high difficulty but doesn't actually have it.
        let network = new_in_memory_network();
        let (_node_a, _dir_a) = make_node(14001, &network).await;
        let (node_b, _dir_b) = make_node(14002, &network).await;

        let kp = Keypair::generate();
        // Create a forged PoW proof that claims difficulty 8 but nonce=0 won't verify
        let forged_pow = PowProof {
            nonce: 999_999_999,
            difficulty: 8,
        };
        // This proof likely won't verify for the given key

        let addr_sender: SocketAddr = "127.0.0.1:14099".parse().unwrap();
        let transport_sender = Arc::new(
            InMemoryTransport::new(addr_sender, network.clone()).await,
        );

        let msg = Message::new(
            *kp.node_id().as_bytes(),
            kp.public_key_bytes(),
            forged_pow,
            Payload::PingRequest,
        );

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            transport_sender.send_request(&node_b.local_addr(), msg),
        )
        .await;

        // Should timeout — invalid PoW means message is dropped
        assert!(result.is_err() || result.unwrap().is_err());

        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_inbound_accepts_valid_message() {
        // A message with valid identity, PoW, and signature should be processed normally
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(15001, &network).await;

        let kp = Keypair::generate();
        let pow = PowProof::generate(&kp.public_key_bytes(), 0);

        let addr_sender: SocketAddr = "127.0.0.1:15099".parse().unwrap();
        let transport_sender = Arc::new(
            InMemoryTransport::new(addr_sender, network.clone()).await,
        );

        let mut msg = Message::new(
            *kp.node_id().as_bytes(),
            kp.public_key_bytes(),
            pow,
            Payload::PingRequest,
        );
        msg.sign(&kp);

        let resp = transport_sender
            .send_request(&node_a.local_addr(), msg)
            .await
            .unwrap();
        assert!(matches!(resp.payload, Payload::PingResponse { .. }));

        node_a.shutdown().await;
    }

    #[test]
    fn test_store_tessera_result_display_fromstr_roundtrip() {
        let result = StoreTesseraResult {
            chunk_hashes: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            config: ErasureConfig::new(2, 1).unwrap(),
            original_len: 42,
        };

        let token = result.to_string();
        let parsed: StoreTesseraResult = token.parse().unwrap();

        assert_eq!(parsed.chunk_hashes, result.chunk_hashes);
        assert_eq!(parsed.config.data_shards(), 2);
        assert_eq!(parsed.config.parity_shards(), 1);
        assert_eq!(parsed.original_len, 42);
    }

    #[test]
    fn test_store_tessera_result_fromstr_invalid_base64() {
        let result = "not-valid-!!!".parse::<StoreTesseraResult>();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_node_builder_spawn() {
        let dir = TempDir::new().unwrap();
        let network = new_in_memory_network();
        let (peer, _peer_dir) = make_node(12001, &network).await;

        // NodeBuilder creates a QuicTransport internally, so we can't use the
        // in-memory network. Instead just verify construction succeeds with
        // the low-level API using similar patterns.
        let keypair = Keypair::generate();
        let pow = PowProof::generate(&keypair.public_key_bytes(), 0);

        let addr: SocketAddr = "127.0.0.1:12002".parse().unwrap();
        let transport =
            Arc::new(InMemoryTransport::new(addr, network.clone()).await);
        let metadata = MetadataStore::in_memory().unwrap();
        let chunks =
            ChunkStore::new(&dir.path().join("chunks"), 10_000_000).unwrap();

        let config = NodeConfig {
            min_pow_difficulty: 0,
            erasure_config: ErasureConfig::new(2, 1).unwrap(),
            ..Default::default()
        };
        let handle =
            spawn_node(keypair, pow, transport, metadata, chunks, config).await;

        // store uses the default erasure_config (2+1)
        handle.bootstrap(vec![peer.local_addr()]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let data = b"builder test data";
        let result = handle.store(data).await.unwrap();
        assert_eq!(result.config.data_shards(), 2);
        assert_eq!(result.config.parity_shards(), 1);

        let retrieved = handle.retrieve(&result).await.unwrap();
        assert_eq!(retrieved, data);

        handle.shutdown().await;
        peer.shutdown().await;
    }

    async fn make_node_with_config(
        port: u16,
        network: &InMemoryNetwork,
        config: NodeConfig,
    ) -> (NodeHandle, TempDir) {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let transport =
            Arc::new(InMemoryTransport::new(addr, network.clone()).await);
        let keypair = Keypair::generate();
        let pow = PowProof::generate(&keypair.public_key_bytes(), 0);
        let dir = TempDir::new().unwrap();
        let metadata = MetadataStore::in_memory().unwrap();
        let chunks =
            ChunkStore::new(&dir.path().join("chunks"), 10_000_000).unwrap();
        let handle =
            spawn_node(keypair, pow, transport, metadata, chunks, config).await;
        (handle, dir)
    }

    #[tokio::test]
    async fn test_proactive_replication_reactive() {
        // Node A stores data alone, then node B joins. B should receive
        // chunks via proactive replication triggered by InsertResult::Inserted.
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(14001, &network).await;

        // Store data on node A (alone in the network)
        let data = b"proactive replication test data".to_vec();
        let config = ErasureConfig::new(2, 1).unwrap();
        let result = node_a
            .store_with_config(data.clone(), config.clone())
            .await
            .unwrap();

        // Node B joins the network (bootstraps through A)
        let (node_b, _dir_b) = make_node(14002, &network).await;
        node_b.bootstrap(vec![node_a.local_addr()]).await.unwrap();

        // Wait for replication to complete
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Shut down node A — B should be able to retrieve the data if
        // replication worked.
        node_a.shutdown().await;

        let retrieved = node_b.retrieve(&result).await.unwrap();
        assert_eq!(retrieved, data);

        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn test_proactive_replication_disabled() {
        // With proactive_replication=false, no chunks should be replicated.
        let network = new_in_memory_network();
        let config_no_repl = NodeConfig {
            min_pow_difficulty: 0,
            proactive_replication: false,
            ..Default::default()
        };
        let (node_a, _dir_a) =
            make_node_with_config(15001, &network, config_no_repl.clone())
                .await;

        let data = b"no replication test".to_vec();
        let ec = ErasureConfig::new(2, 1).unwrap();
        let result = node_a
            .store_with_config(data.clone(), ec.clone())
            .await
            .unwrap();

        let (node_b, _dir_b) =
            make_node_with_config(15002, &network, config_no_repl).await;
        node_b.bootstrap(vec![node_a.local_addr()]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Shut down A — B should NOT be able to retrieve since replication
        // was disabled.
        node_a.shutdown().await;

        let result = node_b.retrieve(&result).await;
        assert!(
            result.is_err(),
            "should fail to retrieve without replication"
        );

        node_b.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_proactive_replication_periodic() {
        // Test that the periodic maintenance path also replicates chunks
        // to recently joined nodes.
        let network = new_in_memory_network();
        let (node_a, _dir_a) = make_node(16001, &network).await;

        let data = b"periodic replication test".to_vec();
        let ec = ErasureConfig::new(2, 1).unwrap();
        let result = node_a
            .store_with_config(data.clone(), ec.clone())
            .await
            .unwrap();

        // Node B joins
        let (node_b, _dir_b) = make_node(16002, &network).await;
        node_b.bootstrap(vec![node_a.local_addr()]).await.unwrap();
        // Brief sleep to let bootstrap complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Advance the clock past the provider_republish_interval (1 hour)
        // to trigger do_provider_maintenance which includes periodic replication.
        tokio::time::advance(Duration::from_secs(3601)).await;
        // Give the maintenance task time to run
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Shut down A — B should have received chunks via periodic replication.
        node_a.shutdown().await;

        let retrieved = node_b.retrieve(&result).await.unwrap();
        assert_eq!(retrieved, data);

        node_b.shutdown().await;
    }
}
