/// Errors returned by tessera-dht operations.
///
/// Each variant corresponds to a failure mode in the DHT: network I/O errors,
/// timeouts, storage issues, or data integrity problems.
#[derive(Debug, thiserror::Error)]
pub enum TesseraError {
    /// A network-level error (connection refused, channel closed, etc.).
    #[error("network: {0}")]
    Network(String),

    /// An RPC timed out waiting for a response.
    #[error("request timed out")]
    Timeout,

    /// No providers were found for the requested content key.
    #[error("no providers found for key")]
    NoProviders,

    /// Not enough erasure-coded chunks were available to reconstruct the data.
    #[error("insufficient chunks: need {needed}, got {got}")]
    InsufficientChunks { needed: usize, got: usize },

    /// The chunk store's disk quota has been exceeded.
    #[error("storage full: {available} bytes remaining")]
    StorageFull { available: u64 },

    /// Identity verification failed (node ID / public key mismatch, or chunk hash mismatch).
    #[error("invalid identity: {reason}")]
    InvalidIdentity { reason: String },

    /// SQLite metadata store error.
    #[error("storage: {0}")]
    Storage(#[from] rusqlite::Error),

    /// Reed-Solomon encode/decode failure.
    #[error("erasure coding: {0}")]
    ErasureCoding(String),

    /// MessagePack serialization or deserialization failure.
    #[error("serialization: {0}")]
    Serialization(String),

    /// I/O error (filesystem, spawn_blocking, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl TesseraError {
    /// Returns true if this error indicates the transport channel is permanently closed.
    pub fn is_channel_closed(&self) -> bool {
        matches!(self, TesseraError::Network(msg) if msg.contains("closed"))
    }
}
