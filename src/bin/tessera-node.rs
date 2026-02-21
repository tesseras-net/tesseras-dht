use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tesseras_dht::identity::{Keypair, PowProof};
use tesseras_dht::node::{NodeConfig, StoreTesseraResult, spawn_node};
use tesseras_dht::storage::{ChunkStore, MetadataStore};
use tesseras_dht::transport::Transport;
use tesseras_dht::transport::quic::QuicTransport;

#[derive(Parser)]
#[command(name = "tessera-node", about = "Tessera DHT node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a persistent DHT node
    Start {
        /// Listen address
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
        /// Storage directory path
        #[arg(long, default_value = "./tessera-data")]
        storage: PathBuf,
        /// Bootstrap peer addresses (can be repeated)
        #[arg(long)]
        bootstrap: Vec<SocketAddr>,
        /// Proof-of-work difficulty
        #[arg(long, default_value_t = 16)]
        pow_difficulty: u8,
        /// Prometheus metrics listen address (requires --features prometheus)
        #[arg(long)]
        metrics_addr: Option<SocketAddr>,
    },
    /// Store a file via an ephemeral node
    Store {
        /// Bootstrap peer to connect to
        #[arg(long)]
        connect: SocketAddr,
        /// Path to the file to store
        #[arg(long)]
        file: PathBuf,
        /// Number of data shards for erasure coding
        #[arg(long, default_value_t = 10)]
        data_shards: usize,
        /// Number of parity shards for erasure coding
        #[arg(long, default_value_t = 4)]
        parity_shards: usize,
        /// Proof-of-work difficulty
        #[arg(long, default_value_t = 16)]
        pow_difficulty: u8,
    },
    /// Retrieve a tessera via an ephemeral node
    Get {
        /// Bootstrap peer to connect to
        #[arg(long)]
        connect: SocketAddr,
        /// Comma-separated hex-encoded chunk hashes
        #[arg(long)]
        hashes: String,
        /// Number of data shards
        #[arg(long)]
        data_shards: usize,
        /// Number of parity shards
        #[arg(long)]
        parity_shards: usize,
        /// Original data length in bytes
        #[arg(long)]
        original_len: usize,
        /// Output file path
        #[arg(long)]
        output: PathBuf,
        /// Proof-of-work difficulty
        #[arg(long, default_value_t = 16)]
        pow_difficulty: u8,
    },
}

fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let rt =
        tokio::runtime::Runtime::new().expect("failed to create Tokio runtime");
    rt.block_on(async_main());
}

async fn async_main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            listen,
            storage,
            bootstrap,
            pow_difficulty,
            metrics_addr,
        } => {
            cmd_start(listen, storage, bootstrap, pow_difficulty, metrics_addr)
                .await;
        }
        Commands::Store {
            connect,
            file,
            data_shards,
            parity_shards,
            pow_difficulty,
        } => {
            cmd_store(
                connect,
                file,
                data_shards,
                parity_shards,
                pow_difficulty,
            )
            .await;
        }
        Commands::Get {
            connect,
            hashes,
            data_shards,
            parity_shards,
            original_len,
            output,
            pow_difficulty,
        } => {
            cmd_get(
                connect,
                hashes,
                data_shards,
                parity_shards,
                original_len,
                output,
                pow_difficulty,
            )
            .await;
        }
    }
}

async fn cmd_start(
    listen_addr: SocketAddr,
    storage_path: PathBuf,
    bootstrap_addrs: Vec<SocketAddr>,
    pow_difficulty: u8,
    metrics_addr: Option<SocketAddr>,
) {
    // Install Prometheus metrics exporter if --metrics-addr is given
    #[cfg(feature = "prometheus")]
    if let Some(addr) = metrics_addr {
        let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
        builder
            .with_http_listener(addr)
            .install()
            .expect("failed to install Prometheus exporter");
        tesseras_dht::metrics::describe_metrics();
        println!("Prometheus metrics at http://{}/metrics", addr);
    }
    #[cfg(not(feature = "prometheus"))]
    if metrics_addr.is_some() {
        eprintln!(
            "Warning: --metrics-addr requires the 'prometheus' feature (build with --features prometheus)"
        );
    }

    std::fs::create_dir_all(&storage_path)
        .expect("failed to create storage directory");

    let metadata = MetadataStore::open(&storage_path.join("metadata.db"))
        .expect("failed to open metadata store");

    let chunks = ChunkStore::new(&storage_path.join("chunks"), 1_000_000_000)
        .expect("failed to create chunk store");

    // Load or generate identity
    let (keypair, pow) = match metadata
        .load_identity()
        .expect("failed to load identity from metadata store")
    {
        Some((secret, nonce, difficulty)) => {
            let kp = Keypair::from_secret_bytes(&secret);
            let pow = PowProof { nonce, difficulty };
            println!("Loaded identity: {}", kp.node_id());
            (kp, pow)
        }
        None => {
            let kp = Keypair::generate();
            println!(
                "Generating proof of work (difficulty {pow_difficulty})..."
            );
            let pow =
                PowProof::generate(&kp.public_key_bytes(), pow_difficulty);
            metadata
                .save_identity(kp.secret_bytes(), pow.nonce, pow.difficulty)
                .expect("failed to save identity");
            println!("New identity: {}", kp.node_id());
            (kp, pow)
        }
    };

    let transport = Arc::new(
        QuicTransport::new(listen_addr)
            .await
            .expect("failed to bind QUIC"),
    );

    println!("Listening on {}", transport.local_addr());

    let mut config = NodeConfig {
        min_pow_difficulty: pow_difficulty,
        ..NodeConfig::default()
    };
    if let Ok(v) = std::env::var("TESSERA_WRITE_RATE")
        && let Ok(n) = v.parse()
    {
        config.write_rate_per_second = n;
    }
    if let Ok(v) = std::env::var("TESSERA_WRITE_BURST")
        && let Ok(n) = v.parse()
    {
        config.write_rate_burst = n;
    }

    let handle =
        spawn_node(keypair, pow, transport, metadata, chunks, config).await;

    if !bootstrap_addrs.is_empty() {
        println!("Bootstrapping with {} peers...", bootstrap_addrs.len());
        if let Err(e) = handle.bootstrap(bootstrap_addrs).await {
            eprintln!("Bootstrap error: {}", e);
        } else {
            println!("Bootstrap complete");
        }
    }

    println!("Node running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for Ctrl+C");
    handle.shutdown().await;
    println!("Shutdown complete.");
}

async fn cmd_store(
    connect_addr: SocketAddr,
    file_path: PathBuf,
    data_shards: usize,
    parity_shards: usize,
    pow_difficulty: u8,
) {
    let data = std::fs::read(&file_path).expect("failed to read file");
    println!("Read {} bytes from {}", data.len(), file_path.display());

    let (handle, _tmp) = make_ephemeral_node(pow_difficulty).await;

    println!("Bootstrapping...");
    if let Err(e) = handle.bootstrap(vec![connect_addr]).await {
        eprintln!("Bootstrap failed: {}", e);
        handle.shutdown().await;
        std::process::exit(1);
    }

    let config =
        tesseras_dht::erasure::ErasureConfig::new(data_shards, parity_shards)
            .expect("invalid erasure config");

    println!(
        "Storing tessera ({} data + {} parity shards)...",
        data_shards, parity_shards
    );
    match handle.store_with_config(data, config).await {
        Ok(result) => {
            println!("Stored successfully. Retrieval metadata:");
            println!();
            let hashes: Vec<String> =
                result.chunk_hashes.iter().map(hex::encode).collect();
            println!("--hashes {}", hashes.join(","));
            println!("--data-shards {}", result.config.data_shards());
            println!("--parity-shards {}", result.config.parity_shards());
            println!("--original-len {}", result.original_len);
        }
        Err(e) => {
            eprintln!("Store failed: {}", e);
            handle.shutdown().await;
            std::process::exit(1);
        }
    }

    handle.shutdown().await;
}

async fn cmd_get(
    connect_addr: SocketAddr,
    hashes_str: String,
    data_shards: usize,
    parity_shards: usize,
    original_len: usize,
    output_path: PathBuf,
    pow_difficulty: u8,
) {
    let chunk_hashes: Vec<[u8; 32]> = hashes_str
        .split(',')
        .map(|h| {
            let bytes = hex::decode(h.trim()).unwrap_or_else(|e| {
                eprintln!("error: invalid hex in --hashes: {}", e);
                std::process::exit(1);
            });
            if bytes.len() != 32 {
                eprintln!(
                    "error: each hash must be 32 bytes (64 hex chars), got {}",
                    bytes.len()
                );
                std::process::exit(1);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();

    let config =
        tesseras_dht::erasure::ErasureConfig::new(data_shards, parity_shards)
            .expect("invalid erasure config");

    let expected = config.total_shards();
    if chunk_hashes.len() != expected {
        eprintln!(
            "error: expected {} hashes (data_shards + parity_shards), got {}",
            expected,
            chunk_hashes.len()
        );
        std::process::exit(1);
    }

    let (handle, _tmp) = make_ephemeral_node(pow_difficulty).await;

    println!("Bootstrapping...");
    if let Err(e) = handle.bootstrap(vec![connect_addr]).await {
        eprintln!("Bootstrap failed: {}", e);
        handle.shutdown().await;
        std::process::exit(1);
    }

    println!("Retrieving tessera ({} chunks)...", chunk_hashes.len());
    let result = StoreTesseraResult {
        chunk_hashes,
        config,
        original_len,
        block_size: 0,
        manifest_hash: None,
    };
    match handle.retrieve(&result).await {
        Ok(data) => {
            std::fs::write(&output_path, &data)
                .expect("failed to write output file");
            println!(
                "Retrieved {} bytes to {}",
                data.len(),
                output_path.display()
            );
        }
        Err(e) => {
            eprintln!("Retrieve failed: {}", e);
            handle.shutdown().await;
            std::process::exit(1);
        }
    }

    handle.shutdown().await;
}

/// Create an ephemeral node with a random identity for store/get commands.
/// Returns the handle and a TempDir that must be kept alive for the node's lifetime.
async fn make_ephemeral_node(
    pow_difficulty: u8,
) -> (tesseras_dht::node::NodeHandle, tempfile::TempDir) {
    let keypair = tesseras_dht::identity::Keypair::generate();
    let pow = tesseras_dht::identity::PowProof::generate(
        &keypair.public_key_bytes(),
        pow_difficulty,
    );

    let dir = tempfile::TempDir::new().expect("failed to create temp dir");
    let metadata = tesseras_dht::storage::MetadataStore::in_memory()
        .expect("failed to create in-memory metadata store");
    let chunks = tesseras_dht::storage::ChunkStore::new(
        &dir.path().join("chunks"),
        1_000_000_000,
    )
    .expect("failed to create chunk store");

    // Bind to any available port
    let listen_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let transport = Arc::new(
        QuicTransport::new(listen_addr)
            .await
            .expect("failed to bind QUIC"),
    );

    println!(
        "Ephemeral node {} on {}",
        keypair.node_id(),
        transport.local_addr()
    );

    let config = NodeConfig {
        min_pow_difficulty: pow_difficulty,
        client_mode: true,
        ..NodeConfig::default()
    };

    let handle =
        spawn_node(keypair, pow, transport, metadata, chunks, config).await;
    (handle, dir)
}
