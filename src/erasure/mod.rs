//! Reed-Solomon erasure coding for data durability.
//!
//! Data is split into `data_shards` pieces, then `parity_shards` redundancy pieces are
//! computed. Any `data_shards` out of the total can reconstruct the original data.

use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

use crate::error::TesseraError;

/// Configuration for erasure coding a tessera.
///
/// Fields are private to enforce validation. Use [`ErasureConfig::new()`] or
/// [`ErasureConfig::default()`] to construct.
#[derive(Clone, Debug)]
pub struct ErasureConfig {
    data_shards: usize,
    parity_shards: usize,
}

impl Default for ErasureConfig {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 4,
        }
    }
}

impl ErasureConfig {
    /// Create a validated erasure config.
    ///
    /// Returns an error if `data_shards < 1`, `parity_shards < 1`,
    /// or `data_shards + parity_shards > 256` (Reed-Solomon GF(2^8) limit).
    pub fn new(
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Self, TesseraError> {
        if data_shards == 0 {
            return Err(TesseraError::ErasureCoding(
                "data_shards must be >= 1".into(),
            ));
        }
        if parity_shards == 0 {
            return Err(TesseraError::ErasureCoding(
                "parity_shards must be >= 1".into(),
            ));
        }
        if data_shards + parity_shards > 256 {
            return Err(TesseraError::ErasureCoding(format!(
                "total shards {} exceeds GF(2^8) limit of 256",
                data_shards + parity_shards
            )));
        }
        Ok(Self {
            data_shards,
            parity_shards,
        })
    }

    /// Number of data shards.
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Number of parity (redundancy) shards.
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

/// Result of encoding a tessera into erasure-coded chunks.
pub struct EncodedTessera {
    /// Each chunk's data (data_shards + parity_shards entries).
    pub chunks: Vec<Vec<u8>>,
    /// SHA-256 hash of each chunk.
    pub chunk_hashes: Vec<[u8; 32]>,
    /// The erasure config used.
    pub config: ErasureConfig,
    /// Original data length (needed for decoding to strip padding).
    pub original_len: usize,
}

/// Encode data into erasure-coded chunks.
///
/// # Examples
///
/// ```
/// use tesseras_dht::erasure::{ErasureConfig, encode, decode};
///
/// let data = b"Hello, Tessera!";
/// let config = ErasureConfig::new(4, 2).unwrap();
/// let encoded = encode(data, &config).unwrap();
/// assert_eq!(encoded.chunks.len(), 6);
///
/// // Reconstruct (even with 2 missing shards)
/// let mut shards: Vec<Option<Vec<u8>>> = encoded.chunks.into_iter().map(Some).collect();
/// shards[0] = None;
/// shards[3] = None;
/// let recovered = decode(&mut shards, &config, data.len()).unwrap();
/// assert_eq!(recovered, data);
/// ```
pub fn encode(
    data: &[u8],
    config: &ErasureConfig,
) -> Result<EncodedTessera, TesseraError> {
    let rs = ReedSolomon::new(config.data_shards, config.parity_shards)
        .map_err(|e| TesseraError::ErasureCoding(format!("init: {}", e)))?;

    let shard_size = data.len().div_ceil(config.data_shards);

    // Create data shards (with padding on the last one)
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(config.total_shards());
    for i in 0..config.data_shards {
        let start = i * shard_size;
        let end = ((i + 1) * shard_size).min(data.len());
        let mut shard = Vec::with_capacity(shard_size);
        if start < data.len() {
            shard.extend_from_slice(&data[start..end]);
        }
        // Pad to shard_size
        shard.resize(shard_size, 0);
        shards.push(shard);
    }

    // Create empty parity shards
    for _ in 0..config.parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    // Encode (fills parity shards)
    rs.encode(&mut shards)
        .map_err(|e| TesseraError::ErasureCoding(format!("encode: {}", e)))?;

    // Compute hashes
    let chunk_hashes: Vec<[u8; 32]> = shards
        .iter()
        .map(|shard| {
            let digest = Sha256::digest(shard);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&digest);
            hash
        })
        .collect();

    Ok(EncodedTessera {
        chunks: shards,
        chunk_hashes,
        config: config.clone(),
        original_len: data.len(),
    })
}

/// Decode data from erasure-coded chunks.
///
/// `shards` must have exactly `total_shards` entries.
/// Missing shards are represented as `None`.
/// At least `data_shards` shards must be present (`Some`).
///
/// # Examples
///
/// ```
/// use tesseras_dht::erasure::{ErasureConfig, encode, decode};
///
/// let data = b"recover me";
/// let config = ErasureConfig::new(2, 1).unwrap();
/// let encoded = encode(data, &config).unwrap();
/// let mut shards: Vec<Option<Vec<u8>>> = encoded.chunks.into_iter().map(Some).collect();
/// shards[1] = None; // lose one shard
/// let recovered = decode(&mut shards, &config, data.len()).unwrap();
/// assert_eq!(recovered, data);
/// ```
pub fn decode(
    shards: &mut [Option<Vec<u8>>],
    config: &ErasureConfig,
    original_len: usize,
) -> Result<Vec<u8>, TesseraError> {
    if shards.len() != config.total_shards() {
        return Err(TesseraError::ErasureCoding(format!(
            "expected {} shards, got {}",
            config.total_shards(),
            shards.len()
        )));
    }

    let present = shards.iter().filter(|s| s.is_some()).count();
    if present < config.data_shards {
        return Err(TesseraError::InsufficientChunks {
            needed: config.data_shards,
            got: present,
        });
    }

    let rs = ReedSolomon::new(config.data_shards, config.parity_shards)
        .map_err(|e| TesseraError::ErasureCoding(format!("init: {}", e)))?;

    rs.reconstruct(shards).map_err(|e| {
        TesseraError::ErasureCoding(format!("reconstruct: {}", e))
    })?;

    // Concatenate data shards and trim to original length
    let mut result = Vec::with_capacity(original_len);
    for data in shards.iter().take(config.data_shards).flatten() {
        result.extend_from_slice(data);
    }
    result.truncate(original_len);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_no_loss() {
        let data = b"Hello, Tessera! This is a test of erasure coding.";
        let config = ErasureConfig::new(4, 2).unwrap();

        let encoded = encode(data, &config).unwrap();
        assert_eq!(encoded.chunks.len(), 6);
        assert_eq!(encoded.chunk_hashes.len(), 6);

        let mut shards: Vec<Option<Vec<u8>>> =
            encoded.chunks.into_iter().map(Some).collect();
        let decoded = decode(&mut shards, &config, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_with_loss() {
        let data = b"Important memories that must survive node failures!";
        let config = ErasureConfig::new(4, 2).unwrap();

        let encoded = encode(data, &config).unwrap();

        // Lose 2 shards (the maximum we can tolerate with 2 parity)
        let mut shards: Vec<Option<Vec<u8>>> =
            encoded.chunks.into_iter().map(Some).collect();
        shards[0] = None; // lose first data shard
        shards[3] = None; // lose last data shard

        let decoded = decode(&mut shards, &config, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_too_many_lost_shards() {
        let data = b"This won't survive too much loss";
        let config = ErasureConfig::new(4, 2).unwrap();

        let encoded = encode(data, &config).unwrap();

        // Lose 3 shards (more than parity can handle)
        let mut shards: Vec<Option<Vec<u8>>> =
            encoded.chunks.into_iter().map(Some).collect();
        shards[0] = None;
        shards[1] = None;
        shards[2] = None;

        let result = decode(&mut shards, &config, data.len());
        assert!(result.is_err());
    }

    #[test]
    fn test_default_config() {
        let config = ErasureConfig::default();
        assert_eq!(config.data_shards, 10);
        assert_eq!(config.parity_shards, 4);
        assert_eq!(config.total_shards(), 14);
    }

    #[test]
    fn test_erasure_config_rejects_zero_data_shards() {
        let result = ErasureConfig::new(0, 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_erasure_config_rejects_zero_parity_shards() {
        let result = ErasureConfig::new(10, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_erasure_config_rejects_exceeding_256_total() {
        let result = ErasureConfig::new(200, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_erasure_config_accepts_valid_params() {
        let config = ErasureConfig::new(10, 4).unwrap();
        assert_eq!(config.data_shards, 10);
        assert_eq!(config.parity_shards, 4);
    }

    #[test]
    fn test_large_data() {
        // 1 MB of data
        let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let config = ErasureConfig::new(10, 4).unwrap();

        let encoded = encode(&data, &config).unwrap();
        assert_eq!(encoded.chunks.len(), 14);

        // Lose 4 shards
        let mut shards: Vec<Option<Vec<u8>>> =
            encoded.chunks.into_iter().map(Some).collect();
        shards[2] = None;
        shards[5] = None;
        shards[8] = None;
        shards[11] = None;

        let decoded = decode(&mut shards, &config, data.len()).unwrap();
        assert_eq!(decoded, data);
    }
}
