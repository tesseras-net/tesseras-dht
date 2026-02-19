use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use metrics::{counter, gauge};
use sha2::{Digest, Sha256};
use tracing::instrument;

use crate::error::TesseraError;

/// Maximum size of a single chunk (4 MB).
const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

struct ChunkStoreInner {
    base_path: PathBuf,
    max_storage: u64,
    storage_used: AtomicU64,
}

/// Content-addressable filesystem storage for erasure-coded chunks.
/// Chunks are stored as files named by their SHA-256 hash, organized
/// in two-level prefix subdirectories to avoid large directories.
///
/// Example: chunk with hash "abcd1234..." is stored at:
///   <base_path>/ab/cd/abcd1234...chunk
#[derive(Clone)]
pub struct ChunkStore {
    inner: Arc<ChunkStoreInner>,
}

impl ChunkStore {
    /// Create a new chunk store at the given path.
    pub fn new(
        base_path: &Path,
        max_storage: u64,
    ) -> Result<Self, TesseraError> {
        std::fs::create_dir_all(base_path)?;
        let inner = ChunkStoreInner {
            base_path: base_path.to_path_buf(),
            max_storage,
            storage_used: AtomicU64::new(0),
        };
        let store = Self {
            inner: Arc::new(inner),
        };
        // Initialize from disk (blocking, but only at startup)
        let used = store.compute_storage_used_sync()?;
        store.inner.storage_used.store(used, Ordering::Release);
        gauge!(crate::metrics::CHUNK_STORAGE_MAX_BYTES).set(max_storage as f64);
        gauge!(crate::metrics::CHUNK_STORAGE_USED_BYTES).set(used as f64);
        Ok(store)
    }

    /// Store a chunk. Verifies data integrity: expected_hash must match.
    #[instrument(skip(self, data), fields(hash = %hex::encode(&expected_hash[..4]), data_len = data.len()))]
    pub async fn put(
        &self,
        expected_hash: &[u8; 32],
        data: &[u8],
    ) -> Result<(), TesseraError> {
        let inner = self.inner.clone();
        let hash = *expected_hash;
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            Self::put_sync(&inner, &hash, &data)
        })
        .await
        .map_err(|e| TesseraError::Io(std::io::Error::other(e)))?
    }

    /// Retrieve a chunk by hash.
    #[instrument(skip(self), fields(hash = %hex::encode(&hash[..4])))]
    pub async fn get(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, TesseraError> {
        let inner = self.inner.clone();
        let h = *hash;
        tokio::task::spawn_blocking(move || Self::get_sync(&inner, &h))
            .await
            .map_err(|e| TesseraError::Io(std::io::Error::other(e)))?
    }

    /// Check if a chunk exists.
    pub async fn has(&self, hash: &[u8; 32]) -> bool {
        let inner = self.inner.clone();
        let h = *hash;
        tokio::task::spawn_blocking(move || {
            Self::chunk_path_inner(&inner, &h).exists()
        })
        .await
        .unwrap_or(false)
    }

    /// Delete a chunk.
    #[instrument(skip(self), fields(hash = %hex::encode(&hash[..4])))]
    pub async fn delete(&self, hash: &[u8; 32]) -> Result<bool, TesseraError> {
        let inner = self.inner.clone();
        let h = *hash;
        tokio::task::spawn_blocking(move || Self::delete_sync(&inner, &h))
            .await
            .map_err(|e| TesseraError::Io(std::io::Error::other(e)))?
    }

    /// Compute SHA-256 hash of data.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }

    /// Get total storage used (cached, updated on writes).
    pub fn storage_used(&self) -> u64 {
        self.inner.storage_used.load(Ordering::Acquire)
    }

    /// Get maximum storage allowed.
    pub fn max_storage(&self) -> u64 {
        self.inner.max_storage
    }
}

// Private sync implementations (run inside spawn_blocking)
impl ChunkStore {
    fn put_sync(
        inner: &ChunkStoreInner,
        expected_hash: &[u8; 32],
        data: &[u8],
    ) -> Result<(), TesseraError> {
        // Per-chunk size limit
        if data.len() > MAX_CHUNK_SIZE {
            counter!(crate::metrics::CHUNK_PUT_TOTAL, crate::metrics::LABEL_STATUS => "err").increment(1);
            return Err(TesseraError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "chunk too large",
            )));
        }

        // Verify hash
        let actual_hash = Self::hash(data);
        if actual_hash != *expected_hash {
            counter!(crate::metrics::CHUNK_PUT_TOTAL, crate::metrics::LABEL_STATUS => "err").increment(1);
            return Err(TesseraError::InvalidIdentity {
                reason: "chunk hash mismatch".into(),
            });
        }

        let path = Self::chunk_path_inner(inner, expected_hash);
        if path.exists() {
            return Ok(()); // already stored (content-addressable = idempotent)
        }

        // Speculative quota reservation: atomically claim space, roll back on failure.
        let size = data.len() as u64;
        let prev = inner.storage_used.fetch_add(size, Ordering::AcqRel);
        if prev + size > inner.max_storage {
            inner.storage_used.fetch_sub(size, Ordering::Release);
            counter!(crate::metrics::CHUNK_PUT_TOTAL, crate::metrics::LABEL_STATUS => "err").increment(1);
            return Err(TesseraError::StorageFull {
                available: inner.max_storage.saturating_sub(prev),
            });
        }

        // Create parent directories
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            inner.storage_used.fetch_sub(size, Ordering::Release);
            return Err(TesseraError::Io(e));
        }

        if let Err(e) = std::fs::write(&path, data) {
            inner.storage_used.fetch_sub(size, Ordering::Release);
            counter!(crate::metrics::CHUNK_PUT_TOTAL, crate::metrics::LABEL_STATUS => "err").increment(1);
            return Err(TesseraError::Io(e));
        }

        gauge!(crate::metrics::CHUNK_STORAGE_USED_BYTES)
            .set(inner.storage_used.load(Ordering::Acquire) as f64);
        counter!(crate::metrics::CHUNK_PUT_TOTAL, crate::metrics::LABEL_STATUS => "ok").increment(1);
        Ok(())
    }

    fn get_sync(
        inner: &ChunkStoreInner,
        hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, TesseraError> {
        let path = Self::chunk_path_inner(inner, hash);
        if !path.exists() {
            counter!(crate::metrics::CHUNK_GET_TOTAL, crate::metrics::LABEL_STATUS => "miss").increment(1);
            return Ok(None);
        }
        let data = std::fs::read(&path)?;

        // Verify integrity on read
        let actual_hash = Self::hash(&data);
        if actual_hash != *hash {
            // Corrupted chunk — delete it
            let _ = std::fs::remove_file(&path);
            counter!(crate::metrics::CHUNK_GET_TOTAL, crate::metrics::LABEL_STATUS => "miss").increment(1);
            return Ok(None);
        }

        counter!(crate::metrics::CHUNK_GET_TOTAL, crate::metrics::LABEL_STATUS => "hit").increment(1);
        Ok(Some(data))
    }

    fn delete_sync(
        inner: &ChunkStoreInner,
        hash: &[u8; 32],
    ) -> Result<bool, TesseraError> {
        let path = Self::chunk_path_inner(inner, hash);
        if path.exists() {
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            std::fs::remove_file(&path)?;
            inner.storage_used.fetch_sub(len, Ordering::Release);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn compute_storage_used_sync(&self) -> Result<u64, TesseraError> {
        let mut total = 0u64;
        if let Ok(entries) = std::fs::read_dir(&self.inner.base_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir()
                    && let Ok(sub_entries) = std::fs::read_dir(entry.path())
                {
                    for sub_entry in sub_entries.flatten() {
                        if sub_entry.path().is_dir()
                            && let Ok(files) =
                                std::fs::read_dir(sub_entry.path())
                        {
                            for file in files.flatten() {
                                if let Ok(meta) = file.metadata() {
                                    total += meta.len();
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(total)
    }

    /// Build the filesystem path for a chunk hash.
    /// Hash "abcdef01..." → "<base>/ab/cd/abcdef01...chunk"
    fn chunk_path_inner(inner: &ChunkStoreInner, hash: &[u8; 32]) -> PathBuf {
        let hex = hex::encode(hash);
        inner
            .base_path
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{}.chunk", hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_put_and_get_chunk() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::new(dir.path(), 1_000_000).unwrap();

        let data = b"hello tessera chunk";
        let hash = ChunkStore::hash(data);

        store.put(&hash, data).await.unwrap();
        assert!(store.has(&hash).await);

        let retrieved = store.get(&hash).await.unwrap().unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_put_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::new(dir.path(), 1_000_000).unwrap();

        let data = b"duplicate test";
        let hash = ChunkStore::hash(data);

        store.put(&hash, data).await.unwrap();
        store.put(&hash, data).await.unwrap(); // no error
        assert_eq!(store.get(&hash).await.unwrap().unwrap(), data);
    }

    #[tokio::test]
    async fn test_hash_mismatch_rejected() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::new(dir.path(), 1_000_000).unwrap();

        let data = b"real data";
        let wrong_hash = [0u8; 32];

        let result = store.put(&wrong_hash, data).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::new(dir.path(), 1_000_000).unwrap();

        let hash = [99u8; 32];
        assert!(store.get(&hash).await.unwrap().is_none());
        assert!(!store.has(&hash).await);
    }

    #[tokio::test]
    async fn test_put_rejects_chunk_exceeding_max_size() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::new(dir.path(), 100_000_000).unwrap();

        // Create a chunk larger than MAX_CHUNK_SIZE (4 MB)
        let data = vec![0xAB; 5 * 1024 * 1024]; // 5 MB
        let hash = ChunkStore::hash(&data);
        let result = store.put(&hash, &data).await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(TesseraError::Io(ref e)) if e.to_string().contains("chunk too large")),
        );
    }

    #[tokio::test]
    async fn test_put_rejects_when_storage_full() {
        let dir = TempDir::new().unwrap();
        // Allow only 100 bytes total
        let store = ChunkStore::new(dir.path(), 100).unwrap();

        // Store a chunk that fits
        let data1 = b"small chunk";
        let hash1 = ChunkStore::hash(data1);
        store.put(&hash1, data1).await.unwrap();

        // Store a chunk that would exceed the quota
        let data2 = vec![0xCD; 200];
        let hash2 = ChunkStore::hash(&data2);
        let result = store.put(&hash2, &data2).await;
        assert!(matches!(result, Err(TesseraError::StorageFull { .. })));
    }

    #[tokio::test]
    async fn test_delete_chunk() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::new(dir.path(), 1_000_000).unwrap();

        let data = b"to be deleted";
        let hash = ChunkStore::hash(data);
        store.put(&hash, data).await.unwrap();

        assert!(store.delete(&hash).await.unwrap());
        assert!(!store.has(&hash).await);
        assert!(!store.delete(&hash).await.unwrap()); // already gone
    }
}
