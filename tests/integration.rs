use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tesseras_dht::erasure::ErasureConfig;
use tesseras_dht::identity::{Keypair, PowProof};
use tesseras_dht::node::{NodeConfig, NodeHandle, spawn_node};
use tesseras_dht::storage::{ChunkStore, MetadataStore};
use tesseras_dht::transport::{
    InMemoryNetwork, InMemoryTransport, new_in_memory_network,
};

use tempfile::TempDir;

async fn make_node(
    port: u16,
    network: &InMemoryNetwork,
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

    let config = NodeConfig {
        min_pow_difficulty: 0,
        ..Default::default()
    };
    let handle =
        spawn_node(keypair, pow, transport, metadata, chunks, config).await;
    (handle, dir)
}

#[tokio::test]
async fn test_full_lifecycle() {
    let network = new_in_memory_network();

    // 1. Create 5 nodes
    let (n1, _d1) = make_node(9001, &network).await;
    let (n2, _d2) = make_node(9002, &network).await;
    let (n3, _d3) = make_node(9003, &network).await;
    let (n4, _d4) = make_node(9004, &network).await;
    let (n5, _d5) = make_node(9005, &network).await;

    // 2. Bootstrap all through node 1
    n2.bootstrap(vec![n1.local_addr()]).await.unwrap();
    n3.bootstrap(vec![n1.local_addr()]).await.unwrap();
    n4.bootstrap(vec![n1.local_addr()]).await.unwrap();
    n5.bootstrap(vec![n1.local_addr()]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Node 1 stores a tessera (100KB)
    let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let config = ErasureConfig::new(4, 2).unwrap();
    let result = n1
        .store_tessera(data.clone(), config.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 4. Node 5 retrieves it
    let retrieved = n5
        .retrieve_tessera(
            result.chunk_hashes.clone(),
            result.config.clone(),
            result.original_len,
        )
        .await
        .unwrap();
    assert_eq!(retrieved, data);

    // 5. Shutdown nodes 2 and 3
    n2.shutdown().await;
    n3.shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Node 4 still retrieves it (erasure coding + local copies on remaining nodes)
    let retrieved2 = n4
        .retrieve_tessera(
            result.chunk_hashes.clone(),
            result.config.clone(),
            result.original_len,
        )
        .await
        .unwrap();
    assert_eq!(retrieved2, data);

    n1.shutdown().await;
    n4.shutdown().await;
    n5.shutdown().await;
}

#[tokio::test]
async fn test_multiple_tesseras() {
    let network = new_in_memory_network();
    let (n1, _d1) = make_node(10001, &network).await;
    let (n2, _d2) = make_node(10002, &network).await;
    let (n3, _d3) = make_node(10003, &network).await;

    n2.bootstrap(vec![n1.local_addr()]).await.unwrap();
    n3.bootstrap(vec![n1.local_addr()]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let config = ErasureConfig::new(4, 2).unwrap();

    // Store multiple tesseras
    let data1 = b"First tessera data".to_vec();
    let data2 = b"Second tessera with different content".to_vec();

    let result1 = n1
        .store_tessera(data1.clone(), config.clone())
        .await
        .unwrap();
    let result2 = n2
        .store_tessera(data2.clone(), config.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Retrieve from different nodes
    let r1 = n3
        .retrieve_tessera(
            result1.chunk_hashes,
            result1.config,
            result1.original_len,
        )
        .await
        .unwrap();
    let r2 = n3
        .retrieve_tessera(
            result2.chunk_hashes,
            result2.config,
            result2.original_len,
        )
        .await
        .unwrap();

    assert_eq!(r1, data1);
    assert_eq!(r2, data2);

    n1.shutdown().await;
    n2.shutdown().await;
    n3.shutdown().await;
}

#[tokio::test]
async fn test_node_discovery_transitivity() {
    let network = new_in_memory_network();
    let (n1, _d1) = make_node(11001, &network).await;
    let (n2, _d2) = make_node(11002, &network).await;
    let (n3, _d3) = make_node(11003, &network).await;

    // n2 knows n1, n3 knows n2 (chain)
    n2.bootstrap(vec![n1.local_addr()]).await.unwrap();
    n3.bootstrap(vec![n2.local_addr()]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // n3 should be able to discover n1 transitively
    let found = n3.find_node(*n1.node_id()).await.unwrap();
    assert!(
        found.iter().any(|n| n.node_id == *n1.node_id()),
        "n3 should discover n1 through n2"
    );

    n1.shutdown().await;
    n2.shutdown().await;
    n3.shutdown().await;
}
