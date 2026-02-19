use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use tracing::instrument;

use crate::error::TesseraError;
use crate::routing::NodeInfoSerde;

/// SQLite-backed metadata store for identity, routing table, and provider records.
pub struct MetadataStore {
    conn: Connection,
}

impl MetadataStore {
    /// Open or create a metadata store at the given path.
    pub fn open(path: &Path) -> Result<Self, TesseraError> {
        let conn = Connection::open(path)?;
        // Enable WAL mode for better concurrent read/write throughput (S17)
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let store = Self { conn };
        store.init_tables()?;
        Ok(store)
    }

    /// Create an in-memory store (for testing).
    pub fn in_memory() -> Result<Self, TesseraError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_tables()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<(), TesseraError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS identity (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                secret_key BLOB NOT NULL,
                pow_nonce INTEGER NOT NULL,
                pow_difficulty INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS routing_table (
                node_id BLOB PRIMARY KEY,
                public_key BLOB NOT NULL,
                addresses TEXT NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS providers (
                content_key BLOB NOT NULL,
                node_id BLOB NOT NULL,
                public_key BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000',
                addresses TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (content_key, node_id)
            );
            CREATE INDEX IF NOT EXISTS idx_providers_expires ON providers(expires_at);
            CREATE TABLE IF NOT EXISTS local_tesseras (
                tessera_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                chunk_hashes TEXT NOT NULL,
                data_shards INTEGER NOT NULL,
                parity_shards INTEGER NOT NULL
            );"
        )?;
        Ok(())
    }

    // --- Identity ---

    /// Save node identity (secret key + PoW).
    pub fn save_identity(
        &self,
        secret_key: &[u8; 32],
        pow_nonce: u64,
        pow_difficulty: u8,
    ) -> Result<(), TesseraError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO identity (id, secret_key, pow_nonce, pow_difficulty) VALUES (1, ?1, ?2, ?3)",
            params![secret_key.as_slice(), pow_nonce as i64, pow_difficulty as i32],
        )?;
        Ok(())
    }

    /// Load node identity. Returns (secret_key, pow_nonce, pow_difficulty).
    pub fn load_identity(
        &self,
    ) -> Result<Option<([u8; 32], u64, u8)>, TesseraError> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret_key, pow_nonce, pow_difficulty FROM identity WHERE id = 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let sk_blob: Vec<u8> = row.get(0)?;
            let nonce: i64 = row.get(1)?;
            let diff: i32 = row.get(2)?;
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&sk_blob);
            Ok(Some((sk, nonce as u64, diff as u8)))
        } else {
            Ok(None)
        }
    }

    // --- Routing Table ---

    /// Save a peer to the routing table.
    pub fn save_peer(&self, peer: &NodeInfoSerde) -> Result<(), TesseraError> {
        let addresses = serde_json::to_string(&peer.addresses)
            .map_err(|e| TesseraError::Serialization(e.to_string()))?;
        let now = now_secs();
        self.conn.execute(
            "INSERT OR REPLACE INTO routing_table (node_id, public_key, addresses, last_seen) VALUES (?1, ?2, ?3, ?4)",
            params![peer.node_id.as_slice(), peer.public_key.as_slice(), addresses, now],
        )?;
        Ok(())
    }

    /// Batch-save peers in a single transaction using INSERT OR REPLACE.
    /// Removes stale peers that are no longer in the provided list.
    #[instrument(skip(self, peers), fields(count = peers.len()))]
    pub fn save_peers_batch(
        &mut self,
        peers: &[NodeInfoSerde],
    ) -> Result<(), TesseraError> {
        let tx = self.conn.transaction()?;
        let now = now_secs();

        for peer in peers {
            let addresses = serde_json::to_string(&peer.addresses)
                .map_err(|e| TesseraError::Serialization(e.to_string()))?;
            tx.execute(
                "INSERT OR REPLACE INTO routing_table (node_id, public_key, addresses, last_seen) VALUES (?1, ?2, ?3, ?4)",
                params![peer.node_id.as_slice(), peer.public_key.as_slice(), addresses, now],
            )?;
        }

        // Remove stale peers no longer in the routing table.
        if peers.is_empty() {
            tx.execute("DELETE FROM routing_table", [])?;
        } else {
            let placeholders: Vec<String> =
                (1..=peers.len()).map(|i| format!("?{}", i)).collect();
            let sql = format!(
                "DELETE FROM routing_table WHERE node_id NOT IN ({})",
                placeholders.join(", ")
            );
            let params: Vec<&[u8]> =
                peers.iter().map(|p| p.node_id.as_slice()).collect();
            tx.execute(&sql, rusqlite::params_from_iter(params))?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Load all peers from the routing table.
    #[instrument(skip(self))]
    pub fn load_peers(&self) -> Result<Vec<NodeInfoSerde>, TesseraError> {
        let mut stmt = self.conn.prepare(
            "SELECT node_id, public_key, addresses FROM routing_table",
        )?;
        let rows = stmt.query_map([], |row| {
            let id_blob: Vec<u8> = row.get(0)?;
            let pk_blob: Vec<u8> = row.get(1)?;
            let addr_str: String = row.get(2)?;
            Ok((id_blob, pk_blob, addr_str))
        })?;
        let mut peers = Vec::new();
        for row in rows {
            let (id_blob, pk_blob, addr_str) = row?;
            let Some(node_id) = blob_to_array(&id_blob) else {
                continue;
            };
            let Some(public_key) = blob_to_array(&pk_blob) else {
                continue;
            };
            let addresses: Vec<SocketAddr> =
                match serde_json::from_str(&addr_str) {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        tracing::warn!(
                            "skipping peer with invalid addresses JSON: {}",
                            e
                        );
                        continue;
                    }
                };
            peers.push(NodeInfoSerde {
                node_id,
                public_key,
                addresses,
            });
        }
        Ok(peers)
    }

    /// Clear the routing table (for testing).
    pub fn clear_routing_table(&self) -> Result<(), TesseraError> {
        self.conn.execute("DELETE FROM routing_table", [])?;
        Ok(())
    }

    // --- Providers ---

    /// Add a provider record.
    #[instrument(skip(self, addresses), fields(key = %hex::encode(&content_key[..4]), node = %hex::encode(&node_id[..4])))]
    pub fn add_provider(
        &self,
        content_key: &[u8; 32],
        node_id: &[u8; 32],
        public_key: &[u8; 32],
        addresses: &[SocketAddr],
        ttl: Duration,
    ) -> Result<(), TesseraError> {
        let addr_str = serde_json::to_string(addresses)
            .map_err(|e| TesseraError::Serialization(e.to_string()))?;
        let expires_at = now_secs() + ttl.as_secs();
        self.conn.execute(
            "INSERT OR REPLACE INTO providers (content_key, node_id, public_key, addresses, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![content_key.as_slice(), node_id.as_slice(), public_key.as_slice(), addr_str, expires_at as i64],
        )?;
        Ok(())
    }

    /// Get providers for a content key (excluding expired).
    #[instrument(skip(self), fields(key = %hex::encode(&content_key[..4])))]
    pub fn get_providers(
        &self,
        content_key: &[u8; 32],
    ) -> Result<Vec<NodeInfoSerde>, TesseraError> {
        let now = now_secs();
        let mut stmt = self.conn.prepare(
            "SELECT node_id, public_key, addresses FROM providers WHERE content_key = ?1 AND expires_at > ?2",
        )?;
        let rows = stmt.query_map(
            params![content_key.as_slice(), now as i64],
            |row| {
                let id_blob: Vec<u8> = row.get(0)?;
                let pk_blob: Vec<u8> = row.get(1)?;
                let addr_str: String = row.get(2)?;
                Ok((id_blob, pk_blob, addr_str))
            },
        )?;
        let mut providers = Vec::new();
        for row in rows {
            let (id_blob, pk_blob, addr_str) = row?;
            let Some(node_id) = blob_to_array(&id_blob) else {
                continue;
            };
            let Some(public_key) = blob_to_array(&pk_blob) else {
                continue;
            };
            let addresses: Vec<SocketAddr> =
                match serde_json::from_str(&addr_str) {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        tracing::warn!(
                            "skipping provider with invalid addresses JSON: {}",
                            e
                        );
                        continue;
                    }
                };
            providers.push(NodeInfoSerde {
                node_id,
                public_key,
                addresses,
            });
        }
        Ok(providers)
    }

    /// Get content keys for which the given node_id is a provider (non-expired).
    pub fn get_own_providers(
        &self,
        node_id: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, TesseraError> {
        let now = now_secs();
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT content_key FROM providers WHERE node_id = ?1 AND expires_at > ?2",
        )?;
        let rows =
            stmt.query_map(params![node_id.as_slice(), now as i64], |row| {
                let blob: Vec<u8> = row.get(0)?;
                Ok(blob)
            })?;
        let mut keys = Vec::new();
        for row in rows {
            let blob = row?;
            let Some(key) = blob_to_array(&blob) else {
                continue;
            };
            keys.push(key);
        }
        Ok(keys)
    }

    /// Remove expired provider records.
    pub fn cleanup_expired_providers(&self) -> Result<usize, TesseraError> {
        let now = now_secs();
        let deleted = self.conn.execute(
            "DELETE FROM providers WHERE expires_at <= ?1",
            params![now as i64],
        )?;
        Ok(deleted)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Try to copy a blob into a fixed-size array. Returns None if length mismatches.
fn blob_to_array(blob: &[u8]) -> Option<[u8; 32]> {
    if blob.len() != 32 {
        tracing::warn!(
            "skipping row with invalid blob length {} (expected 32)",
            blob.len()
        );
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(blob);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_save_and_load() {
        let store = MetadataStore::in_memory().unwrap();
        let sk = [42u8; 32];
        store.save_identity(&sk, 123, 8).unwrap();

        let (loaded_sk, nonce, diff) = store.load_identity().unwrap().unwrap();
        assert_eq!(loaded_sk, sk);
        assert_eq!(nonce, 123);
        assert_eq!(diff, 8);
    }

    #[test]
    fn test_identity_not_found() {
        let store = MetadataStore::in_memory().unwrap();
        assert!(store.load_identity().unwrap().is_none());
    }

    #[test]
    fn test_peer_save_and_load() {
        let store = MetadataStore::in_memory().unwrap();
        let peer = NodeInfoSerde {
            node_id: [1u8; 32],
            public_key: [2u8; 32],
            addresses: vec!["192.168.1.1:4433".parse().unwrap()],
        };
        store.save_peer(&peer).unwrap();

        let peers = store.load_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, [1u8; 32]);
        assert_eq!(peers[0].addresses.len(), 1);
    }

    #[test]
    fn test_provider_add_and_get() {
        let store = MetadataStore::in_memory().unwrap();
        let content_key = [10u8; 32];
        let node_id = [20u8; 32];
        let public_key = [30u8; 32];
        let addrs = vec!["10.0.0.1:4433".parse().unwrap()];

        store
            .add_provider(
                &content_key,
                &node_id,
                &public_key,
                &addrs,
                Duration::from_secs(3600),
            )
            .unwrap();

        let providers = store.get_providers(&content_key).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].node_id, node_id);
        assert_eq!(providers[0].public_key, public_key);
    }

    #[test]
    fn test_get_own_providers() {
        let store = MetadataStore::in_memory().unwrap();
        let our_id = [1u8; 32];
        let our_pk = [11u8; 32];
        let other_id = [2u8; 32];
        let other_pk = [22u8; 32];
        let key_a = [10u8; 32];
        let key_b = [11u8; 32];
        let addrs = vec!["10.0.0.1:4433".parse().unwrap()];

        // We provide key_a and key_b
        store
            .add_provider(
                &key_a,
                &our_id,
                &our_pk,
                &addrs,
                Duration::from_secs(3600),
            )
            .unwrap();
        store
            .add_provider(
                &key_b,
                &our_id,
                &our_pk,
                &addrs,
                Duration::from_secs(3600),
            )
            .unwrap();
        // Someone else provides key_a too
        store
            .add_provider(
                &key_a,
                &other_id,
                &other_pk,
                &addrs,
                Duration::from_secs(3600),
            )
            .unwrap();

        let own = store.get_own_providers(&our_id).unwrap();
        assert_eq!(own.len(), 2);
        assert!(own.contains(&key_a));
        assert!(own.contains(&key_b));
    }

    #[test]
    fn test_save_peers_batch() {
        let mut store = MetadataStore::in_memory().unwrap();
        // Save an initial peer that will NOT be in the batch (should be removed)
        let stale = NodeInfoSerde {
            node_id: [99u8; 32],
            public_key: [99u8; 32],
            addresses: vec!["10.0.0.99:4433".parse().unwrap()],
        };
        store.save_peer(&stale).unwrap();

        // Batch save two peers
        let peers = vec![
            NodeInfoSerde {
                node_id: [1u8; 32],
                public_key: [2u8; 32],
                addresses: vec!["192.168.1.1:4433".parse().unwrap()],
            },
            NodeInfoSerde {
                node_id: [3u8; 32],
                public_key: [4u8; 32],
                addresses: vec!["192.168.1.2:4433".parse().unwrap()],
            },
        ];
        store.save_peers_batch(&peers).unwrap();

        let loaded = store.load_peers().unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(!loaded.iter().any(|p| p.node_id == [99u8; 32]));
        assert!(loaded.iter().any(|p| p.node_id == [1u8; 32]));
        assert!(loaded.iter().any(|p| p.node_id == [3u8; 32]));
    }

    #[test]
    fn test_save_peers_batch_empty() {
        let mut store = MetadataStore::in_memory().unwrap();
        let peer = NodeInfoSerde {
            node_id: [1u8; 32],
            public_key: [2u8; 32],
            addresses: vec!["192.168.1.1:4433".parse().unwrap()],
        };
        store.save_peer(&peer).unwrap();

        store.save_peers_batch(&[]).unwrap();
        let loaded = store.load_peers().unwrap();
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn test_provider_expiry() {
        let store = MetadataStore::in_memory().unwrap();
        let content_key = [10u8; 32];
        let node_id = [20u8; 32];
        let public_key = [30u8; 32];
        let addrs = vec!["10.0.0.1:4433".parse().unwrap()];

        // Add with 0 TTL (already expired)
        store
            .add_provider(
                &content_key,
                &node_id,
                &public_key,
                &addrs,
                Duration::from_secs(0),
            )
            .unwrap();

        let providers = store.get_providers(&content_key).unwrap();
        assert_eq!(providers.len(), 0); // expired

        let deleted = store.cleanup_expired_providers().unwrap();
        assert_eq!(deleted, 1);
    }
}
