# Tesseras DHT

Kademlia DHT with integrated chunk storage for the
[Tesseras](https://tesseras.net) P2P network.

## About

Tesseras DHT is the networking layer of the Tesseras project — a P2P network for
preserving human memories across millennia. It implements a Kademlia distributed
hash table with content-addressed chunk storage, enabling tesseras
(self-contained time capsules of photos, audio, video, and text) to be
replicated and retrieved across the network without relying on any central
server.

Built in Rust with an actor-based Tokio design, it provides QUIC transport,
Ed25519 identity with proof-of-work anti-Sybil protection, Reed-Solomon erasure
coding, mDNS/DNS discovery, STUN NAT traversal, and dual-stack IPv4+IPv6
support.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
tesseras-dht = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Embed a DHT node in your application:

```rust
use tesseras_dht::prelude::*;

#[tokio::main]
async fn main() -> Result<(), TesseraError> {
    let node = NodeBuilder::new("./data")
        .bootstrap(BootstrapSource::Dns("tesseras.net".into()))
        .spawn()
        .await?;

    // Store data with erasure coding (default 10 data + 4 parity shards)
    let result = node.store("hello tesseras").await?;
    let token = result.to_string();
    println!("Tessera: {token}");

    // Retrieve data (from saved token)
    let result: StoreTesseraResult = token.parse()?;
    let data = node.retrieve(&result).await?;
    assert_eq!(data, b"hello tesseras");

    node.shutdown().await;
    Ok(())
}
```

Advanced usage with custom settings:

```rust
use tesseras_dht::prelude::*;

#[tokio::main]
async fn main() -> Result<(), TesseraError> {
    let node = NodeBuilder::new("./data")
        .bind("[::]:4000".parse().unwrap())
        .bootstrap(BootstrapSource::Addrs(vec![
            "192.0.2.1:4000".parse().unwrap(),
        ]))
        .bootstrap(BootstrapSource::Dns("custom.example.com".into()))
        .mdns(false)
        .client_mode(true)
        .pow_difficulty(20)
        .max_storage(10_737_418_240) // 10 GB
        .spawn()
        .await?;

    node.shutdown().await;
    Ok(())
}
```

The low-level `spawn_node` API is still available for full control over
transport, storage, and identity.

## Links

- [Website](https://tesseras.net)
- [Documentation](https://tesseras.net/book/en/)
- [Source code](https://git.sr.ht/~ijanc/tesseras-dht) (primary)
- [GitHub mirror](https://github.com/tesseras-net/tesseras-dht)
- [Ticket tracker](https://todo.sr.ht/~ijanc/tesseras)
- [Mailing lists](https://tesseras.net/subscriptions/)

## License

ISC — see [LICENSE](LICENSE).
