//! # tessera-dht
//!
//! Kademlia DHT with integrated chunk storage for the Tesseras P2P network.
//!
//! ## Feature flags
//!
//! - **`cli`** — Enables the `tessera-node` binary and its dependencies (`tracing-subscriber`,
//!   `tempfile`). Without this feature, only the library is built.
//!
//!   ```sh
//!   cargo build --features cli   # build the tessera-node binary
//!   cargo build                  # library only
//!   ```

pub mod prelude;

pub mod erasure;
pub mod identity;
pub mod lookup;
pub mod metrics;
pub mod protocol;
pub mod routing;
pub mod storage;
pub mod transport;

pub mod node;

mod error;
pub use error::TesseraError;
