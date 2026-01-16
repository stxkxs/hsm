//! Compression support for backup data.

use crate::error::{BackupError, Result};

/// Compression level (0-21, where 6 is a good balance)
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 6;

/// Compressed data wrapper
#[derive(Debug, Clone)]
pub struct CompressedData {
    /// Compressed bytes
    pub data: Vec<u8>,
    /// Original size before compression
    pub original_size: usize,
    /// Compressed size
    pub compressed_size: usize,
}

impl CompressedData {
    /// Calculate compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        1.0 - (self.compressed_size as f64 / self.original_size as f64)
    }

    /// Calculate size reduction percentage
    pub fn size_reduction_percent(&self) -> f64 {
        self.compression_ratio() * 100.0
    }
}

/// Backup compression manager
pub struct CompressionManager {
    compression_level: i32,
}

impl Default for CompressionManager {
    fn default() -> Self {
        Self::new(DEFAULT_COMPRESSION_LEVEL)
    }
}

impl CompressionManager {
    /// Create a new compression manager with specified level
    pub fn new(compression_level: i32) -> Self {
        Self { compression_level }
    }

    /// Compress data using zstd
    pub fn compress(&self, data: &[u8]) -> Result<CompressedData> {
        if data.is_empty() {
            return Err(BackupError::EmptyData);
        }

        let original_size = data.len();

        let compressed = zstd::encode_all(data, self.compression_level)
            .map_err(|e| BackupError::CompressionFailed(e.to_string()))?;

        let compressed_size = compressed.len();

        Ok(CompressedData {
            data: compressed,
            original_size,
            compressed_size,
        })
    }

    /// Decompress data using zstd
    pub fn decompress(&self, compressed: &[u8]) -> Result<Vec<u8>> {
        if compressed.is_empty() {
            return Err(BackupError::EmptyData);
        }

        zstd::decode_all(compressed).map_err(|e| BackupError::DecompressionFailed(e.to_string()))
    }

    /// Compress and serialize data to postcard
    pub fn compress_serialized<T: serde::Serialize>(&self, data: &T) -> Result<CompressedData> {
        let serialized =
            postcard::to_allocvec(data).map_err(|e| BackupError::Serialization(e.to_string()))?;

        self.compress(&serialized)
    }

    /// Decompress and deserialize data from postcard
    pub fn decompress_deserialize<T: serde::de::DeserializeOwned>(
        &self,
        compressed: &[u8],
    ) -> Result<T> {
        let decompressed = self.decompress(compressed)?;

        postcard::from_bytes(&decompressed).map_err(|e| BackupError::Deserialization(e.to_string()))
    }

    /// Get compression level
    pub fn compression_level(&self) -> i32 {
        self.compression_level
    }

    /// Set compression level (0-21)
    pub fn set_compression_level(&mut self, level: i32) {
        self.compression_level = level.clamp(0, 21);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_compress_decompress() {
        let manager = CompressionManager::default();
        let data = b"This is test data that should compress well. ".repeat(100);

        let compressed = manager.compress(&data).unwrap();
        assert!(compressed.compressed_size < compressed.original_size);

        let decompressed = manager.decompress(&compressed.data).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_ratio() {
        let manager = CompressionManager::default();
        let data = b"a".repeat(1000);

        let compressed = manager.compress(&data).unwrap();
        let ratio = compressed.compression_ratio();

        assert!(ratio > 0.8); // Should compress very well
        assert!(compressed.size_reduction_percent() > 80.0);
    }

    #[test]
    fn test_empty_data() {
        let manager = CompressionManager::default();
        let result = manager.compress(&[]);
        assert!(matches!(result, Err(BackupError::EmptyData)));
    }

    #[test]
    fn test_different_compression_levels() {
        let data = b"test data ".repeat(100);

        // Level 1 (fast)
        let manager_fast = CompressionManager::new(1);
        let compressed_fast = manager_fast.compress(&data).unwrap();

        // Level 19 (high compression)
        let manager_high = CompressionManager::new(19);
        let compressed_high = manager_high.compress(&data).unwrap();

        // Higher level should compress better
        assert!(compressed_high.compressed_size <= compressed_fast.compressed_size);

        // Both should decompress correctly
        assert_eq!(
            manager_fast.decompress(&compressed_fast.data).unwrap(),
            data
        );
        assert_eq!(
            manager_high.decompress(&compressed_high.data).unwrap(),
            data
        );
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        id: u64,
        name: String,
        values: Vec<u32>,
    }

    #[test]
    fn test_compress_serialized() {
        let manager = CompressionManager::default();
        let test_data = TestData {
            id: 12345,
            name: "test".to_string(),
            values: vec![1, 2, 3, 4, 5],
        };

        let compressed = manager.compress_serialized(&test_data).unwrap();
        assert!(compressed.compressed_size > 0);

        let decompressed: TestData = manager.decompress_deserialize(&compressed.data).unwrap();

        assert_eq!(decompressed, test_data);
    }

    #[test]
    fn test_large_data_compression() {
        let manager = CompressionManager::default();

        // Create large repetitive data
        let mut large_data = Vec::new();
        for i in 0..10000 {
            large_data.extend_from_slice(format!("line_{}\n", i % 100).as_bytes());
        }

        let compressed = manager.compress(&large_data).unwrap();

        // Should achieve significant compression
        assert!(compressed.compression_ratio() > 0.5);

        let decompressed = manager.decompress(&compressed.data).unwrap();
        assert_eq!(decompressed, large_data);
    }

    #[test]
    fn test_set_compression_level() {
        let mut manager = CompressionManager::new(10);
        assert_eq!(manager.compression_level(), 10);

        manager.set_compression_level(15);
        assert_eq!(manager.compression_level(), 15);

        // Test clamping
        manager.set_compression_level(100);
        assert_eq!(manager.compression_level(), 21);

        manager.set_compression_level(-5);
        assert_eq!(manager.compression_level(), 0);
    }

    #[test]
    fn test_compression_metadata() {
        let manager = CompressionManager::default();
        let data = b"test".repeat(100);

        let compressed = manager.compress(&data).unwrap();

        assert_eq!(compressed.original_size, 400);
        assert!(compressed.compressed_size < 400);
        assert!(compressed.compression_ratio() > 0.0);
        assert!(compressed.size_reduction_percent() > 0.0);
    }
}
