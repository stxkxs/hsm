//! Compression Support
//!
//! Provides optional compression for stored keys using zstd.

use crate::backend::{StorageError, StorageResult};
use serde::{Deserialize, Serialize};

/// Compression level (1-22, higher = better compression but slower)
const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// Compressed data wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedData {
    /// Compressed bytes
    pub compressed: Vec<u8>,
    /// Original uncompressed size
    pub original_size: usize,
    /// Compression ratio (percentage)
    pub ratio: f64,
}

impl CompressedData {
    /// Get compression ratio as a percentage
    pub fn compression_ratio(&self) -> f64 {
        self.ratio
    }

    /// Get space saved in bytes
    pub fn space_saved(&self) -> usize {
        if self.original_size > self.compressed.len() {
            self.original_size - self.compressed.len()
        } else {
            0
        }
    }
}

/// Compress data using zstd
///
/// # Arguments
///
/// * `data` - Raw data to compress
/// * `level` - Compression level (1-22), None uses default (3)
///
/// # Returns
///
/// Compressed data with metadata
pub fn compress(data: &[u8], level: Option<i32>) -> StorageResult<CompressedData> {
    let level = level.unwrap_or(DEFAULT_COMPRESSION_LEVEL);

    let compressed = zstd::encode_all(data, level)
        .map_err(|e| StorageError::OperationFailed(format!("Compression failed: {}", e)))?;

    let original_size = data.len();
    let compressed_size = compressed.len();

    let ratio = if original_size > 0 {
        (compressed_size as f64 / original_size as f64) * 100.0
    } else {
        100.0
    };

    Ok(CompressedData {
        compressed,
        original_size,
        ratio,
    })
}

/// Decompress data using zstd
///
/// # Arguments
///
/// * `compressed` - Compressed data
///
/// # Returns
///
/// Decompressed data
pub fn decompress(compressed: &CompressedData) -> StorageResult<Vec<u8>> {
    let decompressed = zstd::decode_all(&compressed.compressed[..])
        .map_err(|e| StorageError::OperationFailed(format!("Decompression failed: {}", e)))?;

    // Verify size matches
    if decompressed.len() != compressed.original_size {
        return Err(StorageError::CorruptionDetected(format!(
            "Decompressed size mismatch: expected {}, got {}",
            compressed.original_size,
            decompressed.len()
        )));
    }

    Ok(decompressed)
}

/// Compression statistics
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    /// Total bytes compressed
    pub total_input: u64,
    /// Total bytes after compression
    pub total_output: u64,
    /// Number of compression operations
    pub operations: u64,
    /// Average compression ratio
    pub avg_ratio: f64,
}

impl CompressionStats {
    /// Create new compression stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Update stats with a new compression operation
    pub fn record(&mut self, input_size: usize, output_size: usize) {
        self.total_input += input_size as u64;
        self.total_output += output_size as u64;
        self.operations += 1;

        // Recalculate average ratio
        if self.total_input > 0 {
            self.avg_ratio = (self.total_output as f64 / self.total_input as f64) * 100.0;
        }
    }

    /// Get total space saved
    pub fn space_saved(&self) -> u64 {
        if self.total_input > self.total_output {
            self.total_input - self.total_output
        } else {
            0
        }
    }

    /// Get space saved as a percentage
    pub fn space_saved_percent(&self) -> f64 {
        if self.total_input > 0 {
            (self.space_saved() as f64 / self.total_input as f64) * 100.0
        } else {
            0.0
        }
    }
}

impl std::fmt::Display for CompressionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Compression Stats: {} ops, {:.2}% avg ratio, {:.2}% space saved",
            self.operations,
            self.avg_ratio,
            self.space_saved_percent()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let data = b"This is some test data that should compress well because it has repetition repetition repetition";

        let compressed = compress(data, None).unwrap();
        assert!(
            compressed.compressed.len() < data.len(),
            "Data should be compressed"
        );
        assert_eq!(compressed.original_size, data.len());

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_empty() {
        let data = b"";
        let compressed = compress(data, None).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_small() {
        let data = b"hi";
        let compressed = compress(data, None).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_large() {
        // Create 1MB of repetitive data
        let data = vec![b'A'; 1024 * 1024];
        let compressed = compress(&data, None).unwrap();

        // Should compress very well (lots of repetition)
        assert!(
            compressed.compressed.len() < data.len() / 10,
            "Should compress to < 10% of original"
        );

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_levels() {
        let data = b"Test data for compression level testing".repeat(100);

        let level1 = compress(&data, Some(1)).unwrap();
        let level9 = compress(&data, Some(9)).unwrap();
        let level22 = compress(&data, Some(22)).unwrap();

        // Higher levels should compress better (or at least not worse)
        assert!(level22.compressed.len() <= level9.compressed.len());
        assert!(level9.compressed.len() <= level1.compressed.len() * 2); // Allow some variance
    }

    #[test]
    fn test_compression_ratio() {
        let data = b"AAAAAAAAAA".repeat(100); // Very repetitive
        let compressed = compress(&data, None).unwrap();

        assert!(
            compressed.compression_ratio() < 10.0,
            "Should compress to < 10%"
        );
        assert!(compressed.space_saved() > 900, "Should save > 900 bytes");
    }

    #[test]
    fn test_compression_stats() {
        let mut stats = CompressionStats::new();

        // Record some compressions
        stats.record(1000, 500); // 50% compression
        stats.record(2000, 1000); // 50% compression
        stats.record(3000, 1500); // 50% compression

        assert_eq!(stats.operations, 3);
        assert_eq!(stats.total_input, 6000);
        assert_eq!(stats.total_output, 3000);
        assert_eq!(stats.avg_ratio, 50.0);
        assert_eq!(stats.space_saved(), 3000);
        assert_eq!(stats.space_saved_percent(), 50.0);
    }

    #[test]
    fn test_random_data() {
        use rand::RngCore;

        // Random data shouldn't compress well
        let mut data = vec![0u8; 1024];
        rand::rngs::OsRng.fill_bytes(&mut data);

        let compressed = compress(&data, None).unwrap();
        // Random data might actually expand slightly due to overhead
        // Just verify it decompresses correctly
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
