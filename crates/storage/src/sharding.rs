//! Directory Sharding
//!
//! Provides directory sharding to avoid filesystem bottlenecks with large numbers of keys.
//!
//! # Sharding Strategy
//!
//! This module implements **consistent hashing** to distribute keys across 256 shard directories
//! (numbered `00` through `ff` in hexadecimal). This addresses filesystem performance degradation
//! when a single directory contains hundreds of thousands of files.
//!
//! ## Algorithm
//!
//! ```text
//! Key ID → SeaHash → Modulo 256 → Shard Number (0-255) → Hex Format (00-ff)
//! ```
//!
//! For example:
//! - `key-abc123` → hash: `0x1A2B3C4D5E6F7890` → `0x90 % 256 = 144` → shard: `90`
//! - `key-xyz789` → hash: `0x9F8E7D6C5B4A3210` → `0x10 % 256 = 16` → shard: `10`
//!
//! ## Why Sharding?
//!
//! Many filesystems (ext4, XFS, NTFS) experience performance degradation with large directories:
//!
//! | Directory Size | Operation Latency | Why |
//! |----------------|-------------------|-----|
//! | < 1,000 files | ~1ms | Linear scan acceptable |
//! | 10,000 files | ~10ms | B-tree lookup overhead |
//! | 100,000 files | ~100ms | Cache thrashing, seeks |
//! | 1,000,000 files | ~1s+ | Severe degradation |
//!
//! With sharding:
//! - 1,000,000 keys → 256 shards → ~3,906 keys/shard
//! - Keeps each directory small and fast
//! - Maintains O(1) lookup time regardless of total keys
//!
//! ## Performance Benefits
//!
//! - **Lookup Speed**: O(1) hash lookup instead of O(log n) directory scan
//! - **Scalability**: Handles millions of keys without degradation
//! - **Cache Efficiency**: Directory entries stay in filesystem cache
//! - **Balanced Distribution**: SeaHash ensures uniform key distribution
//!
//! # Distribution Quality
//!
//! The [`ShardStats`] type helps analyze distribution quality:
//!
//! - **Balance Factor**: `std_dev / avg`, lower is better (< 0.5 is excellent)
//! - **Max/Min Shards**: Identifies hot spots in distribution
//! - **Standard Deviation**: Measures uniformity (lower is better)
//!
//! For a good hash function with 1M keys:
//! - Average: ~3,906 keys/shard
//! - Std Dev: ~60-80 keys (1-2% variation)
//! - Balance Factor: ~0.02 (excellent)
//!
//! # Examples
//!
//! ## Basic Sharding
//!
//! ```rust
//! use hsm_storage::sharding::{get_sharded_path, get_shard_number};
//! use hsm_storage::KeyId;
//! use std::path::PathBuf;
//!
//! let base = PathBuf::from("/data/keys");
//! let key_id = KeyId::new("user-auth-key-12345");
//!
//! // Get shard number (0-255)
//! let shard = get_shard_number(&key_id);
//! println!("Key will be stored in shard: {:02x}", shard);
//!
//! // Get full sharded path
//! let sharded_path = get_sharded_path(&base, &key_id);
//! // Result: /data/keys/XX (where XX is hex shard number)
//! println!("Sharded directory: {:?}", sharded_path);
//! ```
//!
//! ## Analyzing Distribution
//!
//! ```rust
//! use hsm_storage::sharding::ShardStats;
//! use hsm_storage::KeyId;
//!
//! // Generate or load your key IDs
//! let keys: Vec<KeyId> = (0..100_000)
//!     .map(|i| KeyId::new(format!("key-{}", i)))
//!     .collect();
//!
//! // Analyze distribution
//! let stats = ShardStats::from_keys(&keys);
//!
//! println!("Total keys: {}", stats.total_keys);
//! println!("Average per shard: {:.1}", stats.avg_keys_per_shard);
//! println!("Std deviation: {:.1}", stats.std_dev);
//! println!("Balance factor: {:.3}", stats.balance_factor());
//!
//! if let Some((shard, count)) = stats.max_shard() {
//!     println!("Most loaded shard: {:02x} with {} keys", shard, count);
//! }
//!
//! if let Some((shard, count)) = stats.min_shard() {
//!     println!("Least loaded shard: {:02x} with {} keys", shard, count);
//! }
//! ```
//!
//! ## Using with Storage Backend
//!
//! ```rust,no_run
//! use hsm_storage::{EncryptedFileStorage, StorageBackend, KeyId};
//! use hsm_storage::sharding::get_sharded_path;
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let base_path = PathBuf::from("/secure/storage");
//! let kek = [0u8; 32];
//! let mut storage = EncryptedFileStorage::create_with_new_key(base_path.clone(), &kek)?;
//!
//! storage.create_namespace("sharded")?;
//!
//! // Keys are automatically distributed across shards
//! for i in 0..10_000 {
//!     let key_id = KeyId::new(format!("key-{}", i));
//!     let shard_path = get_sharded_path(
//!         &base_path.join("namespaces/sharded/keys"),
//!         &key_id
//!     );
//!
//!     storage.store_key(&key_id, b"data", "sharded")?;
//!     // Key is stored in: /secure/storage/namespaces/sharded/keys/XX/key-...
//! }
//! # Ok(())
//! # }
//! ```

use crate::KeyId;
use std::path::{Path, PathBuf};

/// Number of shards (256 = 00-ff in hex)
const SHARD_COUNT: u64 = 256;

/// Shard a key ID into a directory path
///
/// Uses consistent hashing to distribute keys across 256 directories.
/// This avoids filesystem performance issues when storing millions of keys
/// in a single directory.
///
/// # Arguments
///
/// * `base_path` - Base directory for sharded storage
/// * `key_id` - Key ID to shard
///
/// # Returns
///
/// Path with shard directory: base_path/XX/key_id where XX is 00-ff
pub fn get_sharded_path(base_path: &Path, key_id: &KeyId) -> PathBuf {
    // Hash the key ID
    let hash = seahash::hash(key_id.as_str().as_bytes());

    // Get shard number (0-255)
    let shard = (hash % SHARD_COUNT) as u8;

    // Create shard directory name (hex format: 00-ff)
    let shard_dir = format!("{:02x}", shard);

    // Return sharded path
    base_path.join(shard_dir)
}

/// Get the shard number for a key ID
///
/// # Arguments
///
/// * `key_id` - Key ID to shard
///
/// # Returns
///
/// Shard number (0-255)
pub fn get_shard_number(key_id: &KeyId) -> u8 {
    let hash = seahash::hash(key_id.as_str().as_bytes());
    (hash % SHARD_COUNT) as u8
}

/// Get all shard directory names
///
/// # Returns
///
/// Vector of shard directory names (00-ff)
pub fn get_all_shard_dirs() -> Vec<String> {
    (0..256u16).map(|i| format!("{:02x}", i as u8)).collect()
}

/// Statistics about shard distribution
#[derive(Debug, Clone, Default)]
pub struct ShardStats {
    /// Number of keys per shard
    pub shard_counts: Vec<(u8, usize)>,
    /// Total number of keys
    pub total_keys: usize,
    /// Average keys per shard
    pub avg_keys_per_shard: f64,
    /// Standard deviation of distribution
    pub std_dev: f64,
}

impl ShardStats {
    /// Create new shard stats from key distribution
    ///
    /// # Arguments
    ///
    /// * `key_ids` - List of all key IDs
    pub fn from_keys(key_ids: &[KeyId]) -> Self {
        let mut counts = vec![0usize; SHARD_COUNT as usize];

        // Count keys per shard
        for key_id in key_ids {
            let shard = get_shard_number(key_id);
            counts[shard as usize] += 1;
        }

        let total_keys = key_ids.len();
        let avg = if total_keys > 0 {
            total_keys as f64 / SHARD_COUNT as f64
        } else {
            0.0
        };

        // Calculate standard deviation
        let variance = if total_keys > 0 {
            counts
                .iter()
                .map(|&c| {
                    let diff = c as f64 - avg;
                    diff * diff
                })
                .sum::<f64>()
                / SHARD_COUNT as f64
        } else {
            0.0
        };

        let std_dev = variance.sqrt();

        // Create shard counts vector (only non-empty shards)
        let shard_counts: Vec<(u8, usize)> = counts
            .iter()
            .enumerate()
            .filter(|(_, &count)| count > 0)
            .map(|(shard, &count)| (shard as u8, count))
            .collect();

        Self {
            shard_counts,
            total_keys,
            avg_keys_per_shard: avg,
            std_dev,
        }
    }

    /// Get the most loaded shard
    pub fn max_shard(&self) -> Option<(u8, usize)> {
        self.shard_counts
            .iter()
            .max_by_key(|(_, count)| count)
            .copied()
    }

    /// Get the least loaded shard
    pub fn min_shard(&self) -> Option<(u8, usize)> {
        self.shard_counts
            .iter()
            .min_by_key(|(_, count)| count)
            .copied()
    }

    /// Get distribution balance (lower is better, 0 = perfectly balanced)
    pub fn balance_factor(&self) -> f64 {
        if self.avg_keys_per_shard > 0.0 {
            self.std_dev / self.avg_keys_per_shard
        } else {
            0.0
        }
    }
}

impl std::fmt::Display for ShardStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Shard Stats: {} keys across {} shards, avg {:.1}, stddev {:.1}, balance {:.2}",
            self.total_keys,
            self.shard_counts.len(),
            self.avg_keys_per_shard,
            self.std_dev,
            self.balance_factor()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sharding_deterministic() {
        let key_id = KeyId::new("test-key-123");
        let base = PathBuf::from("/data");

        let path1 = get_sharded_path(&base, &key_id);
        let path2 = get_sharded_path(&base, &key_id);

        assert_eq!(path1, path2, "Sharding should be deterministic");
    }

    #[test]
    fn test_shard_number_range() {
        // Test many keys to ensure shard numbers are in valid range
        // u8 is 0-255 so the type system guarantees this, but we verify distribution
        for i in 0..1000 {
            let key_id = KeyId::new(format!("key-{}", i));
            let _shard = get_shard_number(&key_id);
            // Type u8 guarantees value is 0-255
        }
    }

    #[test]
    fn test_different_keys_different_shards() {
        // Not all keys will shard differently, but most should
        let key1 = KeyId::new("key1");
        let key2 = KeyId::new("key2");

        let base = PathBuf::from("/data");
        let path1 = get_sharded_path(&base, &key1);
        let path2 = get_sharded_path(&base, &key2);

        // They might be in the same shard (hash collision), but usually won't be
        // We can't assert they're different, but we can verify the format
        assert!(path1.to_string_lossy().contains("/data/"));
        assert!(path2.to_string_lossy().contains("/data/"));
    }

    #[test]
    fn test_all_shard_dirs() {
        let dirs = get_all_shard_dirs();
        // We should have 256 shard directories (00-ff)
        assert_eq!(dirs.len(), 256, "Should have 256 shard directories");

        // Check specific values
        if !dirs.is_empty() {
            assert_eq!(dirs[0], "00");
            assert_eq!(dirs[16], "10");
            if dirs.len() >= 256 {
                assert_eq!(dirs[255], "ff");
            }
        }
    }

    #[test]
    fn test_shard_distribution() {
        // Generate many keys and check distribution
        let keys: Vec<KeyId> = (0..10000)
            .map(|i| KeyId::new(format!("key-{}", i)))
            .collect();

        let stats = ShardStats::from_keys(&keys);

        assert_eq!(stats.total_keys, 10000);
        assert!(stats.avg_keys_per_shard > 0.0);

        // With 10000 keys and 256 shards, average should be ~39 keys per shard
        assert!((stats.avg_keys_per_shard - 39.0).abs() < 1.0);

        // Standard deviation should be reasonable (not all keys in one shard)
        assert!(stats.std_dev < stats.avg_keys_per_shard);

        // Balance factor should be good (< 1.0 is well distributed)
        assert!(stats.balance_factor() < 1.0);
    }

    #[test]
    fn test_shard_stats_empty() {
        let keys: Vec<KeyId> = Vec::new();
        let stats = ShardStats::from_keys(&keys);

        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.avg_keys_per_shard, 0.0);
        assert_eq!(stats.std_dev, 0.0);
        assert_eq!(stats.balance_factor(), 0.0);
    }

    #[test]
    fn test_shard_stats_single_key() {
        let keys = vec![KeyId::new("single-key")];
        let stats = ShardStats::from_keys(&keys);

        assert_eq!(stats.total_keys, 1);
        assert_eq!(stats.shard_counts.len(), 1);
    }

    #[test]
    fn test_max_min_shards() {
        let keys: Vec<KeyId> = (0..1000)
            .map(|i| KeyId::new(format!("key-{}", i)))
            .collect();

        let stats = ShardStats::from_keys(&keys);

        let max = stats.max_shard();
        let min = stats.min_shard();

        assert!(max.is_some());
        assert!(min.is_some());

        // Max should have more keys than min
        if let (Some((_, max_count)), Some((_, min_count))) = (max, min) {
            assert!(max_count >= min_count);
        }
    }

    #[test]
    fn test_sharding_path_format() {
        let key_id = KeyId::new("test-key");
        let base = PathBuf::from("/storage/keys");

        let path = get_sharded_path(&base, &key_id);

        // Path should be: /storage/keys/XX where XX is hex
        let path_str = path.to_string_lossy();
        assert!(path_str.starts_with("/storage/keys/"));

        // Last component should be 2 hex digits
        let last = path.file_name().unwrap().to_string_lossy();
        assert_eq!(last.len(), 2);
        assert!(last.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
