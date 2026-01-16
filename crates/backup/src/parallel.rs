//! Parallel backup processing using rayon.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::{BackupError, Result};

/// Represents a key for parallel processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelKey {
    /// Key identifier
    pub id: String,
    /// Encrypted key data
    pub data: Vec<u8>,
}

/// Parallel backup processor
pub struct ParallelProcessor {
    /// Number of threads to use (0 = auto)
    num_threads: usize,
}

impl Default for ParallelProcessor {
    fn default() -> Self {
        Self::new(0)
    }
}

impl ParallelProcessor {
    /// Create a new parallel processor
    /// Use 0 for automatic thread count
    pub fn new(num_threads: usize) -> Self {
        Self { num_threads }
    }

    /// Process keys in parallel with a given function
    pub fn process_keys<F, R>(&self, keys: Vec<ParallelKey>, process_fn: F) -> Result<Vec<R>>
    where
        F: Fn(&ParallelKey) -> Result<R> + Sync + Send,
        R: Send,
    {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        // Configure thread pool if specified
        let result = if self.num_threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.num_threads)
                .build()
                .map_err(|e| BackupError::InvalidFormat(e.to_string()))?
                .install(|| self.parallel_process(&keys, &process_fn))
        } else {
            self.parallel_process(&keys, &process_fn)
        };

        result
    }

    fn parallel_process<F, R>(&self, keys: &[ParallelKey], process_fn: &F) -> Result<Vec<R>>
    where
        F: Fn(&ParallelKey) -> Result<R> + Sync + Send,
        R: Send,
    {
        keys.par_iter().map(process_fn).collect::<Result<Vec<_>>>()
    }

    /// Process keys in batches
    pub fn process_batches<F, R>(
        &self,
        keys: Vec<ParallelKey>,
        batch_size: usize,
        process_fn: F,
    ) -> Result<Vec<Vec<R>>>
    where
        F: Fn(&[ParallelKey]) -> Result<Vec<R>> + Sync + Send,
        R: Send,
    {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        if batch_size == 0 {
            return Err(BackupError::InvalidFormat(
                "Batch size must be > 0".to_string(),
            ));
        }

        let batches: Vec<&[ParallelKey]> = keys.chunks(batch_size).collect();

        batches
            .par_iter()
            .map(|batch| process_fn(batch))
            .collect::<Result<Vec<_>>>()
    }

    /// Encrypt multiple keys in parallel
    pub fn parallel_encrypt<F>(
        &self,
        keys: Vec<ParallelKey>,
        encrypt_fn: F,
    ) -> Result<Vec<ParallelKey>>
    where
        F: Fn(&ParallelKey) -> Result<ParallelKey> + Sync + Send,
    {
        self.process_keys(keys, encrypt_fn)
    }

    /// Decrypt multiple keys in parallel
    pub fn parallel_decrypt<F>(
        &self,
        keys: Vec<ParallelKey>,
        decrypt_fn: F,
    ) -> Result<Vec<ParallelKey>>
    where
        F: Fn(&ParallelKey) -> Result<ParallelKey> + Sync + Send,
    {
        self.process_keys(keys, decrypt_fn)
    }

    /// Get optimal batch size based on number of keys
    pub fn optimal_batch_size(num_keys: usize) -> usize {
        let num_cpus = num_cpus();
        let ideal_batches = num_cpus * 4; // 4 batches per CPU

        if num_keys < ideal_batches {
            return 1;
        }

        (num_keys + ideal_batches - 1) / ideal_batches
    }

    /// Get number of available CPUs
    pub fn num_cpus(&self) -> usize {
        num_cpus()
    }
}

/// Get number of CPUs available
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key(id: &str) -> ParallelKey {
        ParallelKey {
            id: id.to_string(),
            data: format!("data_{}", id).into_bytes(),
        }
    }

    #[test]
    fn test_process_keys() {
        let processor = ParallelProcessor::default();
        let keys = vec![
            create_test_key("key1"),
            create_test_key("key2"),
            create_test_key("key3"),
        ];

        let results = processor
            .process_keys(keys, |key| Ok(key.id.clone()))
            .unwrap();

        assert_eq!(results.len(), 3);
        assert!(results.contains(&"key1".to_string()));
        assert!(results.contains(&"key2".to_string()));
        assert!(results.contains(&"key3".to_string()));
    }

    #[test]
    fn test_parallel_encrypt() {
        let processor = ParallelProcessor::default();
        let keys = vec![create_test_key("key1"), create_test_key("key2")];

        let encrypted = processor
            .parallel_encrypt(keys.clone(), |key| {
                // Simple "encryption" for testing
                let mut encrypted_key = key.clone();
                encrypted_key.data.iter_mut().for_each(|b| *b ^= 0xFF);
                Ok(encrypted_key)
            })
            .unwrap();

        assert_eq!(encrypted.len(), 2);
        assert_ne!(encrypted[0].data, keys[0].data);
    }

    #[test]
    fn test_parallel_decrypt() {
        let processor = ParallelProcessor::default();
        let keys = vec![create_test_key("key1"), create_test_key("key2")];

        // Encrypt then decrypt
        let encrypted = processor
            .parallel_encrypt(keys.clone(), |key| {
                let mut encrypted_key = key.clone();
                encrypted_key.data.iter_mut().for_each(|b| *b ^= 0xFF);
                Ok(encrypted_key)
            })
            .unwrap();

        let decrypted = processor
            .parallel_decrypt(encrypted, |key| {
                let mut decrypted_key = key.clone();
                decrypted_key.data.iter_mut().for_each(|b| *b ^= 0xFF);
                Ok(decrypted_key)
            })
            .unwrap();

        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].data, keys[0].data);
        assert_eq!(decrypted[1].data, keys[1].data);
    }

    #[test]
    fn test_process_batches() {
        let processor = ParallelProcessor::default();
        let keys: Vec<_> = (0..10)
            .map(|i| create_test_key(&format!("key{}", i)))
            .collect();

        let results = processor
            .process_batches(keys, 3, |batch| {
                Ok(batch.iter().map(|k| k.id.len()).collect())
            })
            .unwrap();

        assert_eq!(results.len(), 4); // 10 keys / 3 batch_size = 4 batches
        assert_eq!(results[0].len(), 3); // First batch
        assert_eq!(results[1].len(), 3); // Second batch
        assert_eq!(results[2].len(), 3); // Third batch
        assert_eq!(results[3].len(), 1); // Last batch
    }

    #[test]
    fn test_empty_keys() {
        let processor = ParallelProcessor::default();
        let keys: Vec<ParallelKey> = Vec::new();

        let results = processor
            .process_keys(keys, |key| Ok(key.id.clone()))
            .unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_error_handling() {
        let processor = ParallelProcessor::default();
        let keys = vec![create_test_key("key1"), create_test_key("error_key")];

        let result = processor.process_keys(keys, |key| {
            if key.id == "error_key" {
                Err(BackupError::EmptyData)
            } else {
                Ok(key.id.clone())
            }
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_optimal_batch_size() {
        assert_eq!(ParallelProcessor::optimal_batch_size(10), 1);
        assert!(ParallelProcessor::optimal_batch_size(1000) > 1);
    }

    #[test]
    fn test_num_cpus() {
        let processor = ParallelProcessor::default();
        assert!(processor.num_cpus() >= 1);
    }

    #[test]
    fn test_custom_thread_count() {
        let processor = ParallelProcessor::new(2);
        let keys: Vec<_> = (0..100)
            .map(|i| create_test_key(&format!("key{}", i)))
            .collect();

        let results = processor
            .process_keys(keys, |key| Ok(key.id.clone()))
            .unwrap();

        assert_eq!(results.len(), 100);
    }

    #[test]
    fn test_large_parallel_workload() {
        let processor = ParallelProcessor::default();
        let keys: Vec<_> = (0..1000)
            .map(|i| create_test_key(&format!("key{}", i)))
            .collect();

        let results = processor
            .parallel_encrypt(keys.clone(), |key| {
                // Simulate some work
                let mut encrypted = key.clone();
                encrypted.data = encrypted.data.iter().map(|b| b.wrapping_add(1)).collect();
                Ok(encrypted)
            })
            .unwrap();

        assert_eq!(results.len(), 1000);
    }

    #[test]
    fn test_zero_batch_size() {
        let processor = ParallelProcessor::default();
        let keys = vec![create_test_key("key1")];

        let result = processor.process_batches(keys, 0, |batch| {
            Ok(batch.iter().map(|k| k.id.clone()).collect())
        });

        assert!(result.is_err());
    }
}
