//! Secret storage backend implementations.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use getrandom;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::lease::{Lease, LeaseConfig, LeaseError, LeaseEvent, LeaseId, LeaseManager};
use crate::secret::{Secret, SecretData, SecretError, SecretId, SecretMetadata, SecretPath};

/// Secret store operations.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Create a new secret.
    async fn create(
        &self,
        path: SecretPath,
        data: SecretData,
        metadata: SecretMetadata,
    ) -> Result<Secret, SecretError>;

    /// Get a secret (latest version).
    async fn get(&self, path: &SecretPath) -> Result<(Secret, SecretData), SecretError>;

    /// Get a specific version.
    async fn get_version(
        &self,
        path: &SecretPath,
        version: u32,
    ) -> Result<(Secret, SecretData), SecretError>;

    /// Update a secret (creates new version).
    async fn update(&self, path: &SecretPath, data: SecretData) -> Result<Secret, SecretError>;

    /// Delete a secret (all versions).
    async fn delete(&self, path: &SecretPath) -> Result<(), SecretError>;

    /// Destroy a specific version (soft delete).
    async fn destroy_version(&self, path: &SecretPath, version: u32) -> Result<(), SecretError>;

    /// List secrets under a path prefix.
    async fn list(&self, prefix: &SecretPath) -> Result<Vec<SecretPath>, SecretError>;

    /// Get metadata without decrypting.
    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata, SecretError>;

    /// Update metadata.
    async fn update_metadata(
        &self,
        path: &SecretPath,
        metadata: SecretMetadata,
    ) -> Result<(), SecretError>;

    /// Check if a secret exists at the given path.
    async fn exists(&self, path: &SecretPath) -> Result<bool, SecretError>;

    /// Get the version count for a secret.
    async fn version_count(&self, path: &SecretPath) -> Result<u32, SecretError>;
}

/// Secrets manager combining store, leases, and encryption.
pub struct SecretsManager {
    store: Arc<dyn SecretStore>,
    lease_manager: LeaseManager,
    #[allow(dead_code)]
    encryption_key_id: String,
}

impl SecretsManager {
    /// Create a new secrets manager.
    pub fn new(
        store: Arc<dyn SecretStore>,
        encryption_key_id: String,
    ) -> (Self, mpsc::Receiver<LeaseEvent>) {
        let (lease_manager, lease_rx) = LeaseManager::new(LeaseConfig::default());

        (
            Self {
                store,
                lease_manager,
                encryption_key_id,
            },
            lease_rx,
        )
    }

    /// Create a secrets manager with custom lease configuration.
    pub fn with_lease_config(
        store: Arc<dyn SecretStore>,
        encryption_key_id: String,
        lease_config: LeaseConfig,
    ) -> (Self, mpsc::Receiver<LeaseEvent>) {
        let (lease_manager, lease_rx) = LeaseManager::new(lease_config);

        (
            Self {
                store,
                lease_manager,
                encryption_key_id,
            },
            lease_rx,
        )
    }

    /// Get the underlying store.
    pub fn store(&self) -> &dyn SecretStore {
        self.store.as_ref()
    }

    /// Get the lease manager.
    pub fn lease_manager(&self) -> &LeaseManager {
        &self.lease_manager
    }

    /// Create a secret with lease.
    pub async fn create_secret(
        &self,
        path: SecretPath,
        data: SecretData,
        metadata: SecretMetadata,
        client_id: String,
        ttl: Option<Duration>,
    ) -> Result<(Secret, Lease), SecretError> {
        let secret = self.store.create(path, data, metadata).await?;

        let lease = self.lease_manager.create_lease(
            secret.id.clone(),
            secret.current_version,
            client_id,
            ttl,
        );

        Ok((secret, lease))
    }

    /// Read a secret with lease.
    pub async fn read_secret(
        &self,
        path: &SecretPath,
        version: Option<u32>,
        client_id: String,
        ttl: Option<Duration>,
    ) -> Result<(SecretData, Lease), SecretError> {
        let (secret, data) = match version {
            Some(v) => self.store.get_version(path, v).await?,
            None => self.store.get(path).await?,
        };

        let lease = self.lease_manager.create_lease(
            secret.id.clone(),
            version.unwrap_or(secret.current_version),
            client_id,
            ttl,
        );

        Ok((data, lease))
    }

    /// Update a secret with lease.
    pub async fn update_secret(
        &self,
        path: &SecretPath,
        data: SecretData,
        client_id: String,
        ttl: Option<Duration>,
    ) -> Result<(Secret, Lease), SecretError> {
        let secret = self.store.update(path, data).await?;

        let lease = self.lease_manager.create_lease(
            secret.id.clone(),
            secret.current_version,
            client_id,
            ttl,
        );

        Ok((secret, lease))
    }

    /// Delete a secret and revoke all associated leases.
    pub async fn delete_secret(&self, path: &SecretPath) -> Result<(), SecretError> {
        // Get the secret to find its ID for lease revocation
        let (secret, _) = self.store.get(path).await?;

        // Revoke all leases for this secret
        self.lease_manager.revoke_all(&secret.id);

        // Delete the secret
        self.store.delete(path).await
    }

    /// Renew a lease.
    pub fn renew_lease(
        &self,
        lease_id: &LeaseId,
        increment: Option<Duration>,
    ) -> Result<Lease, LeaseError> {
        self.lease_manager.renew_lease(lease_id, increment)
    }

    /// Revoke a lease.
    pub fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), LeaseError> {
        self.lease_manager.revoke_lease(lease_id)
    }

    /// Revoke all leases for a secret.
    pub fn revoke_secret_leases(&self, secret_id: &SecretId) -> usize {
        self.lease_manager.revoke_all(secret_id)
    }

    /// Validate a lease.
    pub fn validate_lease(&self, lease_id: &LeaseId) -> Result<Lease, LeaseError> {
        self.lease_manager.validate_lease(lease_id)
    }

    /// List client's active leases.
    pub fn list_client_leases(&self, client_id: &str) -> Vec<Lease> {
        self.lease_manager.list_client_leases(client_id)
    }
}

/// In-memory implementation for testing.
pub struct InMemorySecretStore {
    secrets: RwLock<HashMap<SecretPath, Secret>>,
    data: RwLock<HashMap<(SecretId, u32), SecretData>>,
}

impl InMemorySecretStore {
    /// Create a new in-memory secret store.
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
            data: RwLock::new(HashMap::new()),
        }
    }

    /// Get the number of secrets in the store.
    pub fn secret_count(&self) -> usize {
        self.secrets.read().len()
    }

    /// Get the total number of versions across all secrets.
    pub fn version_count(&self) -> usize {
        self.data.read().len()
    }

    /// Clear all secrets and versions.
    pub fn clear(&self) {
        self.secrets.write().clear();
        self.data.write().clear();
    }
}

impl Default for InMemorySecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretStore for InMemorySecretStore {
    async fn create(
        &self,
        path: SecretPath,
        data: SecretData,
        metadata: SecretMetadata,
    ) -> Result<Secret, SecretError> {
        let mut secrets = self.secrets.write();

        // Check if secret already exists
        if secrets.contains_key(&path) {
            return Err(SecretError::AlreadyExists(path.0.clone()));
        }

        let now = Utc::now();
        let secret = Secret {
            id: SecretId::new(),
            path: path.clone(),
            current_version: 1,
            metadata,
            created_at: now,
            updated_at: now,
        };

        secrets.insert(path, secret.clone());
        self.data.write().insert((secret.id.clone(), 1), data);

        Ok(secret)
    }

    async fn get(&self, path: &SecretPath) -> Result<(Secret, SecretData), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?
            .clone();

        let data = self.data.read();
        let secret_data = data
            .get(&(secret.id.clone(), secret.current_version))
            .ok_or(SecretError::VersionNotFound(secret.current_version))?
            .clone();

        Ok((secret, secret_data))
    }

    async fn get_version(
        &self,
        path: &SecretPath,
        version: u32,
    ) -> Result<(Secret, SecretData), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?
            .clone();

        if version > secret.current_version || version == 0 {
            return Err(SecretError::VersionNotFound(version));
        }

        let data = self.data.read();
        let secret_data = data
            .get(&(secret.id.clone(), version))
            .ok_or(SecretError::VersionNotFound(version))?
            .clone();

        Ok((secret, secret_data))
    }

    async fn update(&self, path: &SecretPath, data: SecretData) -> Result<Secret, SecretError> {
        let mut secrets = self.secrets.write();
        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        secret.current_version += 1;
        secret.updated_at = Utc::now();

        let new_version = secret.current_version;
        let secret_clone = secret.clone();

        drop(secrets);

        self.data
            .write()
            .insert((secret_clone.id.clone(), new_version), data);

        Ok(secret_clone)
    }

    async fn delete(&self, path: &SecretPath) -> Result<(), SecretError> {
        let secret = self
            .secrets
            .write()
            .remove(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        // Remove all versions
        let mut data = self.data.write();
        for v in 1..=secret.current_version {
            data.remove(&(secret.id.clone(), v));
        }

        Ok(())
    }

    async fn destroy_version(&self, path: &SecretPath, version: u32) -> Result<(), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        if version > secret.current_version || version == 0 {
            return Err(SecretError::VersionNotFound(version));
        }

        // Don't allow destroying the current version
        if version == secret.current_version {
            return Err(SecretError::InvalidPath(
                "Cannot destroy the current version".to_string(),
            ));
        }

        let mut data = self.data.write();
        data.remove(&(secret.id.clone(), version))
            .ok_or(SecretError::VersionNotFound(version))?;

        Ok(())
    }

    async fn list(&self, prefix: &SecretPath) -> Result<Vec<SecretPath>, SecretError> {
        let secrets = self.secrets.read();
        let paths: Vec<_> = secrets
            .keys()
            .filter(|p| p.starts_with(prefix))
            .cloned()
            .collect();
        Ok(paths)
    }

    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata, SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        Ok(secret.metadata.clone())
    }

    async fn update_metadata(
        &self,
        path: &SecretPath,
        metadata: SecretMetadata,
    ) -> Result<(), SecretError> {
        let mut secrets = self.secrets.write();
        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        secret.metadata = metadata;
        secret.updated_at = Utc::now();
        Ok(())
    }

    async fn exists(&self, path: &SecretPath) -> Result<bool, SecretError> {
        Ok(self.secrets.read().contains_key(path))
    }

    async fn version_count(&self, path: &SecretPath) -> Result<u32, SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        Ok(secret.current_version)
    }
}

/// Encrypted storage backend using AES-256-GCM.
///
/// This implementation encrypts secret data before storing and decrypts on retrieval.
/// It uses hsm-crypto-engine for AES-256-GCM authenticated encryption.
///
/// # Security
///
/// - All secret data is encrypted at rest using AES-256-GCM
/// - Each secret version gets a unique nonce
/// - Metadata is stored alongside encrypted data for integrity
/// - Encryption key should be derived from a master key
pub struct EncryptedSecretStore {
    /// In-memory storage for secrets (metadata)
    secrets: RwLock<HashMap<SecretPath, Secret>>,
    /// Encrypted secret data by (secret_id, version)
    encrypted_data: RwLock<HashMap<(SecretId, u32), Vec<u8>>>,
    /// Encryption key (32 bytes for AES-256)
    encryption_key: hsm_crypto_engine::KeyMaterial,
}

impl EncryptedSecretStore {
    /// Create a new encrypted secret store with a random encryption key.
    ///
    /// # Security
    ///
    /// In production, the encryption key should be derived from a master key
    /// managed by the HSM key manager, not randomly generated.
    pub fn new() -> Self {
        let mut key_bytes = vec![0u8; 32];
        getrandom::fill(&mut key_bytes).expect("Failed to generate encryption key");
        Self {
            secrets: RwLock::new(HashMap::new()),
            encrypted_data: RwLock::new(HashMap::new()),
            encryption_key: hsm_crypto_engine::KeyMaterial::from_bytes(key_bytes),
        }
    }

    /// Create a new encrypted secret store with a specific encryption key.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte AES-256 encryption key
    ///
    /// # Panics
    ///
    /// Panics if the key is not exactly 32 bytes.
    pub fn with_key(key: Vec<u8>) -> Self {
        assert_eq!(key.len(), 32, "Encryption key must be 32 bytes");
        Self {
            secrets: RwLock::new(HashMap::new()),
            encrypted_data: RwLock::new(HashMap::new()),
            encryption_key: hsm_crypto_engine::KeyMaterial::from_bytes(key),
        }
    }

    /// Encrypt secret data using AES-256-GCM.
    fn encrypt_data(&self, data: &SecretData) -> Result<Vec<u8>, SecretError> {
        let serialized = serde_json::to_vec(data)
            .map_err(|e| SecretError::Encryption(format!("Serialization failed: {}", e)))?;

        hsm_crypto_engine::symmetric::aes_gcm::AesGcmEngine::encrypt_aes256(
            &self.encryption_key,
            &serialized,
            None,
        )
        .map_err(|e| SecretError::Encryption(format!("Encryption failed: {}", e)))
    }

    /// Decrypt secret data using AES-256-GCM.
    fn decrypt_data(&self, encrypted: &[u8]) -> Result<SecretData, SecretError> {
        let decrypted = hsm_crypto_engine::symmetric::aes_gcm::AesGcmEngine::decrypt_aes256(
            &self.encryption_key,
            encrypted,
            None,
        )
        .map_err(|e| SecretError::Decryption(format!("Decryption failed: {}", e)))?;

        serde_json::from_slice(&decrypted)
            .map_err(|e| SecretError::Decryption(format!("Deserialization failed: {}", e)))
    }

    /// Get the number of secrets in the store.
    pub fn secret_count(&self) -> usize {
        self.secrets.read().len()
    }

    /// Get the total number of encrypted versions across all secrets.
    pub fn version_count_total(&self) -> usize {
        self.encrypted_data.read().len()
    }

    /// Clear all secrets and versions.
    pub fn clear(&self) {
        self.secrets.write().clear();
        self.encrypted_data.write().clear();
    }
}

impl Default for EncryptedSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretStore for EncryptedSecretStore {
    async fn create(
        &self,
        path: SecretPath,
        data: SecretData,
        metadata: SecretMetadata,
    ) -> Result<Secret, SecretError> {
        let mut secrets = self.secrets.write();

        // Check if secret already exists
        if secrets.contains_key(&path) {
            return Err(SecretError::AlreadyExists(path.0.clone()));
        }

        // Encrypt the secret data
        let encrypted = self.encrypt_data(&data)?;

        let now = Utc::now();
        let secret = Secret {
            id: SecretId::new(),
            path: path.clone(),
            current_version: 1,
            metadata,
            created_at: now,
            updated_at: now,
        };

        secrets.insert(path, secret.clone());
        self.encrypted_data
            .write()
            .insert((secret.id.clone(), 1), encrypted);

        Ok(secret)
    }

    async fn get(&self, path: &SecretPath) -> Result<(Secret, SecretData), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?
            .clone();

        let data = self.encrypted_data.read();
        let encrypted = data
            .get(&(secret.id.clone(), secret.current_version))
            .ok_or(SecretError::VersionNotFound(secret.current_version))?
            .clone();

        let decrypted = self.decrypt_data(&encrypted)?;

        Ok((secret, decrypted))
    }

    async fn get_version(
        &self,
        path: &SecretPath,
        version: u32,
    ) -> Result<(Secret, SecretData), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?
            .clone();

        if version > secret.current_version || version == 0 {
            return Err(SecretError::VersionNotFound(version));
        }

        let data = self.encrypted_data.read();
        let encrypted = data
            .get(&(secret.id.clone(), version))
            .ok_or(SecretError::VersionNotFound(version))?
            .clone();

        let decrypted = self.decrypt_data(&encrypted)?;

        Ok((secret, decrypted))
    }

    async fn update(&self, path: &SecretPath, data: SecretData) -> Result<Secret, SecretError> {
        let mut secrets = self.secrets.write();
        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        // Encrypt the new version
        let encrypted = self.encrypt_data(&data)?;

        secret.current_version += 1;
        secret.updated_at = Utc::now();

        let new_version = secret.current_version;
        let secret_clone = secret.clone();

        drop(secrets);

        self.encrypted_data
            .write()
            .insert((secret_clone.id.clone(), new_version), encrypted);

        Ok(secret_clone)
    }

    async fn delete(&self, path: &SecretPath) -> Result<(), SecretError> {
        let secret = self
            .secrets
            .write()
            .remove(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        // Remove all encrypted versions
        let mut data = self.encrypted_data.write();
        for v in 1..=secret.current_version {
            data.remove(&(secret.id.clone(), v));
        }

        Ok(())
    }

    async fn destroy_version(&self, path: &SecretPath, version: u32) -> Result<(), SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;

        if version > secret.current_version || version == 0 {
            return Err(SecretError::VersionNotFound(version));
        }

        // Don't allow destroying the current version
        if version == secret.current_version {
            return Err(SecretError::InvalidPath(
                "Cannot destroy the current version".to_string(),
            ));
        }

        let mut data = self.encrypted_data.write();
        data.remove(&(secret.id.clone(), version))
            .ok_or(SecretError::VersionNotFound(version))?;

        Ok(())
    }

    async fn list(&self, prefix: &SecretPath) -> Result<Vec<SecretPath>, SecretError> {
        let secrets = self.secrets.read();
        let paths: Vec<_> = secrets
            .keys()
            .filter(|p| p.starts_with(prefix))
            .cloned()
            .collect();
        Ok(paths)
    }

    async fn get_metadata(&self, path: &SecretPath) -> Result<SecretMetadata, SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        Ok(secret.metadata.clone())
    }

    async fn update_metadata(
        &self,
        path: &SecretPath,
        metadata: SecretMetadata,
    ) -> Result<(), SecretError> {
        let mut secrets = self.secrets.write();
        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        secret.metadata = metadata;
        secret.updated_at = Utc::now();
        Ok(())
    }

    async fn exists(&self, path: &SecretPath) -> Result<bool, SecretError> {
        Ok(self.secrets.read().contains_key(path))
    }

    async fn version_count(&self, path: &SecretPath) -> Result<u32, SecretError> {
        let secrets = self.secrets.read();
        let secret = secrets
            .get(path)
            .ok_or_else(|| SecretError::NotFound(path.0.clone()))?;
        Ok(secret.current_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;

    #[tokio::test]
    async fn test_create_and_get_secret() {
        let store = InMemorySecretStore::new();

        let path = SecretPath::new("/app/database").unwrap();
        let mut data = SecretData::new();
        data.insert("username", SecretValue::string("admin"));
        data.insert("password", SecretValue::string("secret123"));

        let metadata = SecretMetadata::new().with_description("Database credentials");

        let secret = store.create(path.clone(), data, metadata).await.unwrap();

        assert_eq!(secret.current_version, 1);
        assert_eq!(secret.path, path);

        let (retrieved_secret, retrieved_data) = store.get(&path).await.unwrap();

        assert_eq!(retrieved_secret.id, secret.id);
        assert_eq!(
            retrieved_data.get("username").unwrap().as_str(),
            Some("admin")
        );
        assert_eq!(
            retrieved_data.get("password").unwrap().as_str(),
            Some("secret123")
        );
    }

    #[tokio::test]
    async fn test_create_duplicate_fails() {
        let store = InMemorySecretStore::new();

        let path = SecretPath::new("/app/database").unwrap();
        let data = SecretData::new();

        store
            .create(path.clone(), data.clone(), SecretMetadata::default())
            .await
            .unwrap();

        // Second create should fail
        let result = store.create(path, data, SecretMetadata::default()).await;

        assert!(matches!(result, Err(SecretError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_update_creates_version() {
        let store = InMemorySecretStore::new();

        let path = SecretPath::new("/app/api-key").unwrap();

        // Create initial version
        let mut data1 = SecretData::new();
        data1.insert("key", SecretValue::string("key-v1"));
        let secret = store
            .create(path.clone(), data1, SecretMetadata::default())
            .await
            .unwrap();
        assert_eq!(secret.current_version, 1);

        // Update to v2
        let mut data2 = SecretData::new();
        data2.insert("key", SecretValue::string("key-v2"));
        let secret = store.update(&path, data2).await.unwrap();
        assert_eq!(secret.current_version, 2);

        // Update to v3
        let mut data3 = SecretData::new();
        data3.insert("key", SecretValue::string("key-v3"));
        let secret = store.update(&path, data3).await.unwrap();
        assert_eq!(secret.current_version, 3);

        // Read latest should be v3
        let (_, latest_data) = store.get(&path).await.unwrap();
        assert_eq!(latest_data.get("key").unwrap().as_str(), Some("key-v3"));
    }

    #[tokio::test]
    async fn test_get_specific_version() {
        let store = InMemorySecretStore::new();

        let path = SecretPath::new("/app/api-key").unwrap();

        // Create and update
        let mut data1 = SecretData::new();
        data1.insert("key", SecretValue::string("key-v1"));
        store
            .create(path.clone(), data1, SecretMetadata::default())
            .await
            .unwrap();

        let mut data2 = SecretData::new();
        data2.insert("key", SecretValue::string("key-v2"));
        store.update(&path, data2).await.unwrap();

        // Get v1
        let (_, v1_data) = store.get_version(&path, 1).await.unwrap();
        assert_eq!(v1_data.get("key").unwrap().as_str(), Some("key-v1"));

        // Get v2
        let (_, v2_data) = store.get_version(&path, 2).await.unwrap();
        assert_eq!(v2_data.get("key").unwrap().as_str(), Some("key-v2"));

        // Get invalid version
        let result = store.get_version(&path, 3).await;
        assert!(matches!(result, Err(SecretError::VersionNotFound(3))));

        let result = store.get_version(&path, 0).await;
        assert!(matches!(result, Err(SecretError::VersionNotFound(0))));
    }

    #[tokio::test]
    async fn test_delete_secret() {
        let store = InMemorySecretStore::new();

        let path = SecretPath::new("/app/temp").unwrap();

        // Create and update a couple times
        let data = SecretData::new();
        store
            .create(path.clone(), data.clone(), SecretMetadata::default())
            .await
            .unwrap();
        store.update(&path, data.clone()).await.unwrap();
        store.update(&path, data).await.unwrap();

        assert!(store.exists(&path).await.unwrap());
        assert_eq!(store.version_count(), 3);

        // Delete
        store.delete(&path).await.unwrap();

        assert!(!store.exists(&path).await.unwrap());
        assert_eq!(store.version_count(), 0);

        // Get should fail
        let result = store.get(&path).await;
        assert!(matches!(result, Err(SecretError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_destroy_version() {
        let store = InMemorySecretStore::new();

        let path = SecretPath::new("/app/rotating").unwrap();

        // Create and update
        let mut data1 = SecretData::new();
        data1.insert("key", SecretValue::string("key-v1"));
        store
            .create(path.clone(), data1, SecretMetadata::default())
            .await
            .unwrap();

        let mut data2 = SecretData::new();
        data2.insert("key", SecretValue::string("key-v2"));
        store.update(&path, data2).await.unwrap();

        // Destroy v1
        store.destroy_version(&path, 1).await.unwrap();

        // v1 should be gone
        let result = store.get_version(&path, 1).await;
        assert!(matches!(result, Err(SecretError::VersionNotFound(1))));

        // v2 (current) should still exist
        let (_, v2_data) = store.get_version(&path, 2).await.unwrap();
        assert_eq!(v2_data.get("key").unwrap().as_str(), Some("key-v2"));

        // Cannot destroy current version
        let result = store.destroy_version(&path, 2).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let store = InMemorySecretStore::new();

        // Create secrets in different paths
        let paths = [
            "/app/database/prod",
            "/app/database/dev",
            "/app/api/key1",
            "/app/api/key2",
            "/other/secret",
        ];

        for p in &paths {
            let path = SecretPath::new(*p).unwrap();
            store
                .create(path, SecretData::new(), SecretMetadata::default())
                .await
                .unwrap();
        }

        // List all under /app
        let app_secrets = store.list(&SecretPath::new("/app").unwrap()).await.unwrap();
        assert_eq!(app_secrets.len(), 4);

        // List under /app/database
        let db_secrets = store
            .list(&SecretPath::new("/app/database").unwrap())
            .await
            .unwrap();
        assert_eq!(db_secrets.len(), 2);

        // List under /other
        let other_secrets = store
            .list(&SecretPath::new("/other").unwrap())
            .await
            .unwrap();
        assert_eq!(other_secrets.len(), 1);

        // List under non-existent path
        let empty = store
            .list(&SecretPath::new("/nonexistent").unwrap())
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn test_metadata_operations() {
        let store = InMemorySecretStore::new();

        let path = SecretPath::new("/app/secret").unwrap();
        let metadata = SecretMetadata::new()
            .with_description("Original description")
            .with_owner("admin");

        store
            .create(path.clone(), SecretData::new(), metadata)
            .await
            .unwrap();

        // Get metadata
        let retrieved = store.get_metadata(&path).await.unwrap();
        assert_eq!(
            retrieved.description,
            Some("Original description".to_string())
        );
        assert_eq!(retrieved.owner, Some("admin".to_string()));

        // Update metadata
        let new_metadata = SecretMetadata::new()
            .with_description("Updated description")
            .with_owner("new-owner")
            .with_label("env", "production");

        store.update_metadata(&path, new_metadata).await.unwrap();

        // Verify update
        let updated = store.get_metadata(&path).await.unwrap();
        assert_eq!(updated.description, Some("Updated description".to_string()));
        assert_eq!(updated.owner, Some("new-owner".to_string()));
        assert_eq!(updated.labels.get("env"), Some(&"production".to_string()));
    }

    #[tokio::test]
    async fn test_secrets_manager_create_with_lease() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

        let path = SecretPath::new("/app/database").unwrap();
        let mut data = SecretData::new();
        data.insert("username", SecretValue::string("admin"));
        data.insert("password", SecretValue::string("secret123"));

        let (secret, lease) = manager
            .create_secret(
                path.clone(),
                data,
                SecretMetadata::default(),
                "test-client".to_string(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(secret.current_version, 1);
        assert!(lease.is_valid());
        assert_eq!(lease.client_id, "test-client");
    }

    #[tokio::test]
    async fn test_secrets_manager_read_with_lease() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

        let path = SecretPath::new("/app/database").unwrap();
        let mut data = SecretData::new();
        data.insert("username", SecretValue::string("admin"));

        manager
            .create_secret(
                path.clone(),
                data,
                SecretMetadata::default(),
                "creator".to_string(),
                None,
            )
            .await
            .unwrap();

        // Read with a different client
        let (read_data, lease) = manager
            .read_secret(&path, None, "reader".to_string(), None)
            .await
            .unwrap();

        assert_eq!(read_data.get("username").unwrap().as_str(), Some("admin"));
        assert!(lease.is_valid());
        assert_eq!(lease.client_id, "reader");
    }

    #[tokio::test]
    async fn test_secrets_manager_lease_operations() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

        let path = SecretPath::new("/app/database").unwrap();

        let (_, lease) = manager
            .create_secret(
                path,
                SecretData::new(),
                SecretMetadata::default(),
                "test-client".to_string(),
                Some(Duration::hours(1)),
            )
            .await
            .unwrap();

        // Validate lease
        assert!(manager.validate_lease(&lease.id).is_ok());

        // Renew lease
        let renewed = manager
            .renew_lease(&lease.id, Some(Duration::hours(2)))
            .unwrap();
        assert!(renewed.expires_at > lease.expires_at);

        // Revoke lease
        manager.revoke_lease(&lease.id).unwrap();

        // Should no longer validate
        assert!(manager.validate_lease(&lease.id).is_err());
    }

    #[tokio::test]
    async fn test_secrets_manager_delete_revokes_leases() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

        let path = SecretPath::new("/app/database").unwrap();

        // Create secret and get lease
        let (_, lease1) = manager
            .create_secret(
                path.clone(),
                SecretData::new(),
                SecretMetadata::default(),
                "client1".to_string(),
                None,
            )
            .await
            .unwrap();

        // Read to get another lease
        let (_, lease2) = manager
            .read_secret(&path, None, "client2".to_string(), None)
            .await
            .unwrap();

        // Both leases valid
        assert!(manager.validate_lease(&lease1.id).is_ok());
        assert!(manager.validate_lease(&lease2.id).is_ok());

        // Delete secret
        manager.delete_secret(&path).await.unwrap();

        // Both leases should be revoked
        assert!(manager.validate_lease(&lease1.id).is_err());
        assert!(manager.validate_lease(&lease2.id).is_err());
    }

    #[tokio::test]
    async fn test_secrets_manager_list_client_leases() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

        // Create multiple secrets with leases for same client
        for i in 1..=3 {
            let path = SecretPath::new(format!("/app/secret{}", i)).unwrap();
            manager
                .create_secret(
                    path,
                    SecretData::new(),
                    SecretMetadata::default(),
                    "test-client".to_string(),
                    None,
                )
                .await
                .unwrap();
        }

        let leases = manager.list_client_leases("test-client");
        assert_eq!(leases.len(), 3);
    }

    // ======================== EncryptedSecretStore Tests ========================

    #[tokio::test]
    async fn test_encrypted_store_create_and_get() {
        let store = EncryptedSecretStore::new();

        let path = SecretPath::new("/secure/database").unwrap();
        let mut data = SecretData::new();
        data.insert("username", SecretValue::string("admin"));
        data.insert("password", SecretValue::string("super-secret-password"));

        let metadata = SecretMetadata::new().with_description("Encrypted database credentials");

        let secret = store.create(path.clone(), data, metadata).await.unwrap();

        assert_eq!(secret.current_version, 1);
        assert_eq!(secret.path, path);

        // Verify we can retrieve and decrypt the secret
        let (retrieved_secret, retrieved_data) = store.get(&path).await.unwrap();

        assert_eq!(retrieved_secret.id, secret.id);
        assert_eq!(
            retrieved_data.get("username").unwrap().as_str(),
            Some("admin")
        );
        assert_eq!(
            retrieved_data.get("password").unwrap().as_str(),
            Some("super-secret-password")
        );
    }

    #[tokio::test]
    async fn test_encrypted_store_update_creates_new_encrypted_version() {
        let store = EncryptedSecretStore::new();

        let path = SecretPath::new("/secure/api-key").unwrap();

        // Create initial version
        let mut data1 = SecretData::new();
        data1.insert("key", SecretValue::string("key-v1-secret"));
        let secret = store
            .create(path.clone(), data1, SecretMetadata::default())
            .await
            .unwrap();
        assert_eq!(secret.current_version, 1);

        // Update to v2
        let mut data2 = SecretData::new();
        data2.insert("key", SecretValue::string("key-v2-secret"));
        let secret = store.update(&path, data2).await.unwrap();
        assert_eq!(secret.current_version, 2);

        // Read latest should be v2 (and decrypted correctly)
        let (_, latest_data) = store.get(&path).await.unwrap();
        assert_eq!(
            latest_data.get("key").unwrap().as_str(),
            Some("key-v2-secret")
        );

        // Can still read v1 (and decrypt it)
        let (_, v1_data) = store.get_version(&path, 1).await.unwrap();
        assert_eq!(v1_data.get("key").unwrap().as_str(), Some("key-v1-secret"));
    }

    #[tokio::test]
    async fn test_encrypted_store_data_is_actually_encrypted() {
        let store = EncryptedSecretStore::new();

        let path = SecretPath::new("/secure/test").unwrap();
        let plaintext_password = "my-secret-password-12345";

        let mut data = SecretData::new();
        data.insert("password", SecretValue::string(plaintext_password));

        let secret = store
            .create(path.clone(), data, SecretMetadata::default())
            .await
            .unwrap();

        // Access the raw encrypted data and verify it's not plaintext
        let encrypted_data = store.encrypted_data.read();
        let raw_encrypted = encrypted_data.get(&(secret.id.clone(), 1)).unwrap();

        // The raw bytes should not contain the plaintext password
        let raw_str = String::from_utf8_lossy(raw_encrypted);
        assert!(
            !raw_str.contains(plaintext_password),
            "Plaintext password found in encrypted data!"
        );

        // The encrypted data should be larger than just the plaintext (includes nonce + tag)
        assert!(
            raw_encrypted.len() > plaintext_password.len() + 28,
            "Encrypted data seems too small"
        );

        // But we can still decrypt it correctly
        let (_, decrypted_data) = store.get(&path).await.unwrap();
        assert_eq!(
            decrypted_data.get("password").unwrap().as_str(),
            Some(plaintext_password)
        );
    }

    #[tokio::test]
    async fn test_encrypted_store_with_custom_key() {
        // Create two stores with the same key
        let key = vec![0x42u8; 32];
        let store1 = EncryptedSecretStore::with_key(key.clone());
        let store2 = EncryptedSecretStore::with_key(key);

        let path = SecretPath::new("/shared/secret").unwrap();
        let mut data = SecretData::new();
        data.insert("value", SecretValue::string("shared-secret-data"));

        // Create in store1
        let secret = store1
            .create(path.clone(), data, SecretMetadata::default())
            .await
            .unwrap();

        // Copy the encrypted data to store2 (simulating data transfer)
        {
            let encrypted_data = store1.encrypted_data.read();
            let raw = encrypted_data.get(&(secret.id.clone(), 1)).unwrap().clone();
            drop(encrypted_data);

            store2.secrets.write().insert(path.clone(), secret.clone());
            store2
                .encrypted_data
                .write()
                .insert((secret.id.clone(), 1), raw);
        }

        // Store2 should be able to decrypt the data
        let (_, decrypted_data) = store2.get(&path).await.unwrap();
        assert_eq!(
            decrypted_data.get("value").unwrap().as_str(),
            Some("shared-secret-data")
        );
    }

    #[tokio::test]
    async fn test_encrypted_store_wrong_key_fails_decryption() {
        // Create store with one key
        let key1 = vec![0x42u8; 32];
        let store1 = EncryptedSecretStore::with_key(key1);

        let path = SecretPath::new("/secure/secret").unwrap();
        let mut data = SecretData::new();
        data.insert("value", SecretValue::string("secret-data"));

        let secret = store1
            .create(path.clone(), data, SecretMetadata::default())
            .await
            .unwrap();

        // Create another store with a different key
        let key2 = vec![0x43u8; 32];
        let store2 = EncryptedSecretStore::with_key(key2);

        // Copy the encrypted data to store2
        {
            let encrypted_data = store1.encrypted_data.read();
            let raw = encrypted_data.get(&(secret.id.clone(), 1)).unwrap().clone();
            drop(encrypted_data);

            store2.secrets.write().insert(path.clone(), secret.clone());
            store2
                .encrypted_data
                .write()
                .insert((secret.id.clone(), 1), raw);
        }

        // Store2 with wrong key should fail to decrypt
        let result = store2.get(&path).await;
        assert!(result.is_err(), "Should fail with wrong decryption key");
    }

    #[tokio::test]
    async fn test_encrypted_store_delete_removes_encrypted_data() {
        let store = EncryptedSecretStore::new();

        let path = SecretPath::new("/secure/temp").unwrap();

        // Create and update a couple times
        let mut data = SecretData::new();
        data.insert("key", SecretValue::string("value"));
        store
            .create(path.clone(), data.clone(), SecretMetadata::default())
            .await
            .unwrap();
        store.update(&path, data.clone()).await.unwrap();
        store.update(&path, data).await.unwrap();

        assert!(store.exists(&path).await.unwrap());
        assert_eq!(store.version_count_total(), 3);

        // Delete
        store.delete(&path).await.unwrap();

        assert!(!store.exists(&path).await.unwrap());
        assert_eq!(store.version_count_total(), 0);
    }

    #[tokio::test]
    async fn test_encrypted_store_binary_data() {
        let store = EncryptedSecretStore::new();

        let path = SecretPath::new("/secure/binary").unwrap();
        let binary_data: Vec<u8> = (0..=255).collect();

        let mut data = SecretData::new();
        data.insert("binary_key", SecretValue::binary(binary_data.clone()));

        store
            .create(path.clone(), data, SecretMetadata::default())
            .await
            .unwrap();

        let (_, retrieved_data) = store.get(&path).await.unwrap();
        let retrieved_binary = retrieved_data.get("binary_key").unwrap().as_bytes();

        assert_eq!(retrieved_binary, binary_data);
    }
}
