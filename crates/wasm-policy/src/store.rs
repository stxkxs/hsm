//! Policy storage and caching.
//!
//! This module provides storage for WASM policies with LRU caching
//! of compiled modules for efficient execution.

use crate::error::{PolicyError, Result};
use crate::policy::{Policy, PolicyId, PolicyMetadata};
use dashmap::DashMap;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};
use wasmtime::Module;

/// Policy store with compiled module caching.
pub struct PolicyStore {
    /// Policy metadata storage.
    policies: DashMap<PolicyId, Policy>,

    /// Compiled module cache.
    module_cache: Arc<Mutex<LruCache<PolicyId, Arc<Module>>>>,

    /// Wasmtime engine for compilation.
    engine: wasmtime::Engine,

    /// Optional persistent storage path.
    storage_path: Option<PathBuf>,

    /// Maximum cache size.
    max_cache_size: usize,
}

impl PolicyStore {
    /// Create a new in-memory policy store.
    pub fn new(engine: wasmtime::Engine) -> Result<Self> {
        Self::with_cache_size(engine, 100)
    }

    /// Create a new policy store with custom cache size.
    pub fn with_cache_size(engine: wasmtime::Engine, cache_size: usize) -> Result<Self> {
        let cache = LruCache::new(
            NonZeroUsize::new(cache_size)
                .ok_or_else(|| PolicyError::Internal("Cache size must be non-zero".into()))?,
        );

        Ok(Self {
            policies: DashMap::new(),
            module_cache: Arc::new(Mutex::new(cache)),
            engine,
            storage_path: None,
            max_cache_size: cache_size,
        })
    }

    /// Create a policy store with persistent storage.
    pub fn with_storage<P: AsRef<Path>>(engine: wasmtime::Engine, path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;

        let mut store = Self::with_cache_size(engine, 100)?;
        store.storage_path = Some(path.clone());

        // Load existing policies
        store.load_from_disk()?;

        Ok(store)
    }

    /// Register a new policy.
    pub fn register(&self, policy: Policy) -> Result<()> {
        let id = policy.metadata.id.clone();

        // Check size limit
        if policy.bytecode().len() > crate::MAX_POLICY_SIZE {
            return Err(PolicyError::InvalidBytecode(format!(
                "Policy exceeds maximum size of {} bytes",
                crate::MAX_POLICY_SIZE
            )));
        }

        // Validate bytecode by compiling
        let module = Module::new(&self.engine, policy.bytecode())
            .map_err(|e| PolicyError::CompilationFailed(e.to_string()))?;

        // Validate exports
        Self::validate_exports(&module)?;

        // Store policy
        self.policies.insert(id.clone(), policy.clone());

        // Cache compiled module
        self.module_cache.lock().put(id.clone(), Arc::new(module));

        // Persist if storage is configured
        if let Some(ref path) = self.storage_path {
            self.save_policy_to_disk(path, &policy)?;
        }

        info!(policy_id = %id, "Policy registered");
        Ok(())
    }

    /// Get a policy by ID.
    pub fn get(&self, id: &PolicyId) -> Option<Policy> {
        self.policies.get(id).map(|p| p.clone())
    }

    /// Get a compiled module for a policy.
    pub fn get_module(&self, id: &PolicyId) -> Result<Arc<Module>> {
        // Check cache first
        {
            let mut cache = self.module_cache.lock();
            if let Some(module) = cache.get(id) {
                return Ok(module.clone());
            }
        }

        // Compile if not cached
        let policy = self
            .policies
            .get(id)
            .ok_or_else(|| PolicyError::NotFound(id.to_string()))?;

        let module = Module::new(&self.engine, policy.bytecode())
            .map_err(|e| PolicyError::CompilationFailed(e.to_string()))?;

        let module = Arc::new(module);
        self.module_cache.lock().put(id.clone(), module.clone());

        debug!(policy_id = %id, "Compiled and cached policy module");
        Ok(module)
    }

    /// Update a policy.
    pub fn update(&self, policy: Policy) -> Result<()> {
        let id = policy.metadata.id.clone();

        if !self.policies.contains_key(&id) {
            return Err(PolicyError::NotFound(id.to_string()));
        }

        // Validate and compile
        let module = Module::new(&self.engine, policy.bytecode())
            .map_err(|e| PolicyError::CompilationFailed(e.to_string()))?;

        Self::validate_exports(&module)?;

        // Update storage
        self.policies.insert(id.clone(), policy.clone());

        // Update cache
        self.module_cache.lock().put(id.clone(), Arc::new(module));

        // Persist if storage is configured
        if let Some(ref path) = self.storage_path {
            self.save_policy_to_disk(path, &policy)?;
        }

        info!(policy_id = %id, "Policy updated");
        Ok(())
    }

    /// Remove a policy.
    pub fn remove(&self, id: &PolicyId) -> Result<()> {
        self.policies
            .remove(id)
            .ok_or_else(|| PolicyError::NotFound(id.to_string()))?;

        // Remove from cache
        self.module_cache.lock().pop(id);

        // Remove from disk if storage is configured
        if let Some(ref path) = self.storage_path {
            let policy_path = path.join(format!("{}.policy", id.as_str()));
            let _ = std::fs::remove_file(&policy_path);
        }

        info!(policy_id = %id, "Policy removed");
        Ok(())
    }

    /// List all policy IDs.
    pub fn list(&self) -> Vec<PolicyId> {
        self.policies.iter().map(|r| r.key().clone()).collect()
    }

    /// List all policy metadata.
    pub fn list_metadata(&self) -> Vec<PolicyMetadata> {
        self.policies.iter().map(|r| r.metadata.clone()).collect()
    }

    /// Get policies applicable to a context.
    pub fn find_applicable(
        &self,
        namespace: &str,
        key_id: &str,
        chain_id: &str,
        tx_type: &str,
    ) -> Vec<Policy> {
        let mut policies: Vec<_> = self
            .policies
            .iter()
            .filter(|p| {
                p.metadata.enabled && p.metadata.applies_to(namespace, key_id, chain_id, tx_type)
            })
            .map(|p| p.clone())
            .collect();

        // Sort by priority (lower = higher priority)
        policies.sort_by_key(|p| p.metadata.priority);
        policies
    }

    /// Enable a policy.
    pub fn enable(&self, id: &PolicyId) -> Result<()> {
        let mut policy = self
            .policies
            .get_mut(id)
            .ok_or_else(|| PolicyError::NotFound(id.to_string()))?;
        policy.metadata.enabled = true;
        policy.metadata.updated_at = chrono::Utc::now();

        // Persist if storage is configured
        if let Some(ref path) = self.storage_path {
            self.save_policy_to_disk(path, &policy)?;
        }

        Ok(())
    }

    /// Disable a policy.
    pub fn disable(&self, id: &PolicyId) -> Result<()> {
        let mut policy = self
            .policies
            .get_mut(id)
            .ok_or_else(|| PolicyError::NotFound(id.to_string()))?;
        policy.metadata.enabled = false;
        policy.metadata.updated_at = chrono::Utc::now();

        // Persist if storage is configured
        if let Some(ref path) = self.storage_path {
            self.save_policy_to_disk(path, &policy)?;
        }

        Ok(())
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        let cache = self.module_cache.lock();
        CacheStats {
            size: cache.len(),
            capacity: self.max_cache_size,
        }
    }

    /// Clear the module cache.
    pub fn clear_cache(&self) {
        self.module_cache.lock().clear();
    }

    /// Validate that a module has the required exports.
    fn validate_exports(module: &Module) -> Result<()> {
        let mut has_evaluate = false;

        for export in module.exports() {
            if export.name() == "evaluate" {
                has_evaluate = true;
                // Check it's a function
                if export.ty().func().is_none() {
                    return Err(PolicyError::InvalidExportSignature {
                        name: "evaluate".into(),
                        expected: "function".into(),
                        actual: "non-function".into(),
                    });
                }
            }
        }

        if !has_evaluate {
            return Err(PolicyError::MissingExport("evaluate".into()));
        }

        Ok(())
    }

    /// Load policies from disk.
    fn load_from_disk(&self) -> Result<()> {
        let path = match &self.storage_path {
            Some(p) => p,
            None => return Ok(()),
        };

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path.extension().is_some_and(|e| e == "policy") {
                match self.load_policy_from_disk(&file_path) {
                    Ok(policy) => {
                        let id = policy.metadata.id.clone();
                        self.policies.insert(id.clone(), policy);
                        debug!(policy_id = %id, "Loaded policy from disk");
                    }
                    Err(e) => {
                        tracing::warn!(path = ?file_path, error = %e, "Failed to load policy");
                    }
                }
            }
        }

        Ok(())
    }

    /// Load a single policy from disk.
    fn load_policy_from_disk(&self, path: &Path) -> Result<Policy> {
        let data = std::fs::read(path)?;

        // Format: [metadata_len: u32][metadata_json][bytecode]
        if data.len() < 4 {
            return Err(PolicyError::InvalidBytecode("File too small".into()));
        }

        let metadata_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + metadata_len {
            return Err(PolicyError::InvalidBytecode(
                "Invalid metadata length".into(),
            ));
        }

        let metadata: PolicyMetadata = serde_json::from_slice(&data[4..4 + metadata_len])?;
        let bytecode = data[4 + metadata_len..].to_vec();

        Ok(Policy::new(metadata, bytecode))
    }

    /// Save a policy to disk.
    fn save_policy_to_disk(&self, dir: &Path, policy: &Policy) -> Result<()> {
        let metadata_json = serde_json::to_vec(&policy.metadata)?;
        let metadata_len = (metadata_json.len() as u32).to_le_bytes();

        let mut data = Vec::with_capacity(4 + metadata_json.len() + policy.bytecode().len());
        data.extend_from_slice(&metadata_len);
        data.extend_from_slice(&metadata_json);
        data.extend_from_slice(policy.bytecode());

        let path = dir.join(format!("{}.policy", policy.metadata.id.as_str()));
        std::fs::write(&path, &data)?;

        Ok(())
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current cache size.
    pub size: usize,
    /// Maximum cache capacity.
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> wasmtime::Engine {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        wasmtime::Engine::new(&config).unwrap()
    }

    // Minimal valid WASM module with evaluate function
    fn test_wasm_bytes() -> Vec<u8> {
        // (module
        //   (func (export "evaluate") (param i32 i32) (result i32)
        //     i32.const 1  ;; return Allow
        //   )
        //   (memory (export "memory") 1)
        // )
        wat::parse_str(
            r#"
            (module
                (func (export "evaluate") (param i32 i32) (result i32)
                    i32.const 1
                )
                (memory (export "memory") 1)
            )
        "#,
        )
        .unwrap()
    }

    #[test]
    fn test_policy_store_register() {
        let store = PolicyStore::new(test_engine()).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("test-policy"),
            "Test Policy",
            "1.0.0",
            "hash123",
            100,
        );
        let policy = Policy::new(metadata, test_wasm_bytes());

        store.register(policy).unwrap();
        assert_eq!(store.list().len(), 1);
    }

    #[test]
    fn test_policy_store_get_module() {
        let store = PolicyStore::new(test_engine()).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("test-policy"),
            "Test Policy",
            "1.0.0",
            "hash123",
            100,
        );
        let policy = Policy::new(metadata, test_wasm_bytes());

        store.register(policy).unwrap();

        let module = store.get_module(&PolicyId::new("test-policy")).unwrap();
        assert!(module.exports().any(|e| e.name() == "evaluate"));
    }

    #[test]
    fn test_policy_store_find_applicable() {
        let store = PolicyStore::new(test_engine()).unwrap();

        // Policy for production namespace
        let metadata1 = PolicyMetadata::new(
            PolicyId::new("prod-policy"),
            "Production Policy",
            "1.0.0",
            "hash1",
            100,
        )
        .for_namespace("production");
        store
            .register(Policy::new(metadata1, test_wasm_bytes()))
            .unwrap();

        // Policy for all namespaces
        let metadata2 = PolicyMetadata::new(
            PolicyId::new("global-policy"),
            "Global Policy",
            "1.0.0",
            "hash2",
            100,
        );
        store
            .register(Policy::new(metadata2, test_wasm_bytes()))
            .unwrap();

        let applicable = store.find_applicable("production", "key-1", "1", "transfer");
        assert_eq!(applicable.len(), 2);

        let applicable = store.find_applicable("staging", "key-1", "1", "transfer");
        assert_eq!(applicable.len(), 1);
        assert_eq!(applicable[0].metadata.id.as_str(), "global-policy");
    }

    #[test]
    fn test_policy_store_enable_disable() {
        let store = PolicyStore::new(test_engine()).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("test-policy"),
            "Test Policy",
            "1.0.0",
            "hash123",
            100,
        );
        store
            .register(Policy::new(metadata, test_wasm_bytes()))
            .unwrap();

        let id = PolicyId::new("test-policy");

        store.disable(&id).unwrap();
        let policy = store.get(&id).unwrap();
        assert!(!policy.metadata.enabled);

        store.enable(&id).unwrap();
        let policy = store.get(&id).unwrap();
        assert!(policy.metadata.enabled);
    }
}
