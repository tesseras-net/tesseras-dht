//! Persistent storage: content-addressed chunks and SQLite metadata.
//!
//! [`ChunkStore`] stores erasure-coded chunks on the filesystem, indexed by SHA-256 hash.
//! [`MetadataStore`] persists node identity, routing table peers, and provider records in SQLite.

mod chunks;
mod sqlite;

pub use chunks::ChunkStore;
pub use sqlite::MetadataStore;
