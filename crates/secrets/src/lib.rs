#![deny(unsafe_code)]
//! HSM Secrets Manager
//!
//! This crate provides secrets management capabilities similar to HashiCorp Vault,
//! AWS Secrets Manager, or Azure Key Vault. It supports:
//!
//! - Storing arbitrary key-value secrets with encryption at rest
//! - Automatic versioning with configurable retention
//! - Lease-based access with automatic expiration and revocation
//! - Path-based hierarchical organization
//!
//! # Quick Start
//!
//! ```rust
//! use hsm_secrets::{
//!     InMemorySecretStore, SecretData, SecretMetadata, SecretPath,
//!     SecretValue, SecretsManager,
//! };
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create an in-memory store (use EncryptedSecretStore for production)
//! let store = Arc::new(InMemorySecretStore::new());
//! let (manager, mut lease_events) = SecretsManager::new(store, "encryption-key-id".into());
//!
//! // Create a secret
//! let path = SecretPath::new("/app/database")?;
//! let mut data = SecretData::new();
//! data.insert("username", SecretValue::string("admin"));
//! data.insert("password", SecretValue::string("secret123"));
//!
//! let (secret, lease) = manager.create_secret(
//!     path.clone(),
//!     data,
//!     SecretMetadata::new().with_description("Database credentials"),
//!     "my-app".to_string(),
//!     None, // Use default TTL
//! ).await?;
//!
//! println!("Created secret with ID: {}", secret.id);
//! println!("Lease expires at: {}", lease.expires_at);
//!
//! // Read the secret
//! let (read_data, read_lease) = manager.read_secret(
//!     &path,
//!     None, // Latest version
//!     "my-app".to_string(),
//!     None,
//! ).await?;
//!
//! println!("Username: {:?}", read_data.get("username"));
//!
//! // Renew the lease
//! let renewed = manager.renew_lease(&read_lease.id, None)?;
//! println!("Lease renewed until: {}", renewed.expires_at);
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! The secrets manager is composed of several components:
//!
//! - **SecretStore**: Trait for pluggable storage backends
//!   - `InMemorySecretStore`: For testing and development
//!   - `EncryptedSecretStore`: For production (uses hsm-storage and hsm-crypto-engine)
//!
//! - **LeaseManager**: Manages temporary access grants with automatic expiration
//!
//! - **VersionManager**: Handles version retention and cleanup policies
//!
//! - **SecretsManager**: High-level API combining store and lease management
//!
//! # Secret Organization
//!
//! Secrets are organized hierarchically using paths:
//!
//! ```text
//! /
//! ├── app/
//! │   ├── database/
//! │   │   ├── prod
//! │   │   └── dev
//! │   └── api/
//! │       ├── key1
//! │       └── key2
//! └── infrastructure/
//!     └── ssh-keys/
//!         └── deploy
//! ```
//!
//! # Versioning
//!
//! Every update to a secret creates a new version:
//!
//! ```rust,ignore
//! // Update creates version 2
//! let (updated_secret, _) = manager.update_secret(&path, new_data, client, None).await?;
//! assert_eq!(updated_secret.current_version, 2);
//!
//! // Read a specific version
//! let (v1_data, _) = manager.read_secret(&path, Some(1), client, None).await?;
//! ```
//!
//! # Leases
//!
//! All secret access is granted through leases:
//!
//! - Leases have a TTL (time-to-live) that can be configured
//! - Leases can be renewed before they expire
//! - Leases can be revoked at any time
//! - When a secret is deleted, all its leases are automatically revoked
//!
//! # Error Handling
//!
//! The crate uses `SecretError` for secret operations and `LeaseError` for lease operations:
//!
//! ```rust,ignore
//! match manager.read_secret(&path, None, client, None).await {
//!     Ok((data, lease)) => { /* use the data */ }
//!     Err(SecretError::NotFound(path)) => { /* secret doesn't exist */ }
//!     Err(SecretError::AccessDenied) => { /* no permission */ }
//!     Err(e) => { /* other error */ }
//! }
//! ```

pub mod lease;
pub mod secret;
pub mod store;
pub mod version;

// Re-export main types for convenience
pub use lease::{Lease, LeaseConfig, LeaseError, LeaseEvent, LeaseId, LeaseManager};
pub use secret::{
    RotationConfig, RotationInterval, Secret, SecretData, SecretError, SecretId, SecretMetadata,
    SecretPath, SecretValue,
};
pub use store::{EncryptedSecretStore, InMemorySecretStore, SecretStore, SecretsManager};
pub use version::{EncryptedSecretData, SecretVersion, VersionManager, VersionPolicy};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use chrono::Duration;
    use std::sync::Arc;

    /// Test complete secret lifecycle: create, read, update, version access, delete
    #[tokio::test]
    async fn test_complete_secret_lifecycle() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

        let path = SecretPath::new("/app/database").unwrap();

        // 1. Create secret
        let mut data = SecretData::new();
        data.insert("username", SecretValue::string("admin"));
        data.insert("password", SecretValue::string("password-v1"));

        let (secret, create_lease) = manager
            .create_secret(
                path.clone(),
                data,
                SecretMetadata::new()
                    .with_description("Database credentials")
                    .with_owner("dba-team"),
                "app-server".to_string(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(secret.current_version, 1);
        assert!(create_lease.is_valid());

        // 2. Read secret
        let (read_data, read_lease) = manager
            .read_secret(&path, None, "app-server".to_string(), None)
            .await
            .unwrap();

        assert_eq!(read_data.get("username").unwrap().as_str(), Some("admin"));
        assert_eq!(
            read_data.get("password").unwrap().as_str(),
            Some("password-v1")
        );
        assert!(read_lease.is_valid());

        // 3. Update secret (new version)
        let mut new_data = SecretData::new();
        new_data.insert("username", SecretValue::string("admin"));
        new_data.insert("password", SecretValue::string("password-v2"));

        let (updated_secret, _) = manager
            .update_secret(&path, new_data, "app-server".to_string(), None)
            .await
            .unwrap();

        assert_eq!(updated_secret.current_version, 2);

        // 4. Read old version
        let (v1_data, _) = manager
            .read_secret(&path, Some(1), "app-server".to_string(), None)
            .await
            .unwrap();

        assert_eq!(
            v1_data.get("password").unwrap().as_str(),
            Some("password-v1")
        );

        // 5. Read latest version
        let (latest_data, _) = manager
            .read_secret(&path, None, "app-server".to_string(), None)
            .await
            .unwrap();

        assert_eq!(
            latest_data.get("password").unwrap().as_str(),
            Some("password-v2")
        );

        // 6. Delete secret
        manager.delete_secret(&path).await.unwrap();

        // All leases should be revoked
        assert!(manager.validate_lease(&create_lease.id).is_err());
        assert!(manager.validate_lease(&read_lease.id).is_err());

        // Secret should be gone
        let result = manager
            .read_secret(&path, None, "app-server".to_string(), None)
            .await;
        assert!(matches!(result, Err(SecretError::NotFound(_))));
    }

    /// Test lease lifecycle: create, renew, revoke
    #[tokio::test]
    async fn test_lease_lifecycle() {
        let store = Arc::new(InMemorySecretStore::new());
        let lease_config = LeaseConfig::new()
            .with_default_ttl(Duration::hours(1))
            .with_max_ttl(Duration::hours(24))
            .with_renewable(true);

        let (manager, mut rx) =
            SecretsManager::with_lease_config(store, "test-key".to_string(), lease_config);

        let path = SecretPath::new("/app/secret").unwrap();

        // Create secret
        let (_, lease) = manager
            .create_secret(
                path.clone(),
                SecretData::new(),
                SecretMetadata::default(),
                "test-client".to_string(),
                Some(Duration::minutes(30)),
            )
            .await
            .unwrap();

        assert!(lease.is_valid());
        assert!(lease.renewable);

        // Renew lease
        let original_expires = lease.expires_at;
        let renewed = manager
            .renew_lease(&lease.id, Some(Duration::hours(2)))
            .unwrap();

        assert!(renewed.expires_at > original_expires);

        // Check renewal event
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, LeaseEvent::Renewed(_, _)));

        // Revoke lease
        manager.revoke_lease(&lease.id).unwrap();

        // Check revocation event
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, LeaseEvent::Revoked(_)));

        // Lease should no longer be valid
        assert!(manager.validate_lease(&lease.id).is_err());
    }

    /// Test hierarchical path operations
    #[tokio::test]
    async fn test_path_hierarchy() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

        // Create secrets in a hierarchy
        let paths = [
            "/prod/app1/database",
            "/prod/app1/redis",
            "/prod/app2/database",
            "/staging/app1/database",
        ];

        for p in &paths {
            let path = SecretPath::new(*p).unwrap();
            manager
                .create_secret(
                    path,
                    SecretData::new(),
                    SecretMetadata::default(),
                    "admin".to_string(),
                    None,
                )
                .await
                .unwrap();
        }

        // List all prod secrets
        let prod_secrets = store
            .list(&SecretPath::new("/prod").unwrap())
            .await
            .unwrap();
        assert_eq!(prod_secrets.len(), 3);

        // List app1 secrets
        let app1_secrets = store
            .list(&SecretPath::new("/prod/app1").unwrap())
            .await
            .unwrap();
        assert_eq!(app1_secrets.len(), 2);

        // List staging secrets
        let staging_secrets = store
            .list(&SecretPath::new("/staging").unwrap())
            .await
            .unwrap();
        assert_eq!(staging_secrets.len(), 1);
    }

    /// Test version cleanup policy
    #[test]
    fn test_version_policy_cleanup() {
        let secret_id = SecretId::new();
        let policy = VersionPolicy::new()
            .with_max_versions(3)
            .with_min_retention(Duration::days(1))
            .with_auto_destroy(true);

        let manager = VersionManager::new(policy);

        // Create versions with varying ages
        let now = chrono::Utc::now();
        let versions: Vec<SecretVersion> = (1..=5)
            .map(|v| SecretVersion {
                secret_id: secret_id.clone(),
                version: v,
                data: EncryptedSecretData::unencrypted_placeholder(),
                created_at: now - Duration::days((5 - v) as i64 * 2), // v1 is 8 days old, v5 is 0 days
                created_by: None,
                destroyed: false,
                destroyed_at: None,
            })
            .collect();

        let to_cleanup = manager.versions_to_cleanup(&versions);

        // v1 and v2 should be marked for cleanup (exceed max_versions and past retention)
        assert!(to_cleanup.contains(&1));
        assert!(to_cleanup.contains(&2));
        assert!(!to_cleanup.contains(&3));
        assert!(!to_cleanup.contains(&4));
        assert!(!to_cleanup.contains(&5));
    }

    /// Test binary and JSON secret values
    #[tokio::test]
    async fn test_secret_value_types() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

        let path = SecretPath::new("/app/mixed-types").unwrap();

        let mut data = SecretData::new();
        data.insert("string_value", SecretValue::string("hello"));
        data.insert("binary_value", SecretValue::binary(vec![0x01, 0x02, 0x03]));
        data.insert(
            "json_value",
            SecretValue::json(serde_json::json!({
                "nested": {
                    "key": "value"
                }
            })),
        );

        manager
            .create_secret(
                path.clone(),
                data,
                SecretMetadata::default(),
                "test".to_string(),
                None,
            )
            .await
            .unwrap();

        let (read_data, _) = manager
            .read_secret(&path, None, "test".to_string(), None)
            .await
            .unwrap();

        assert_eq!(read_data.get("string_value").unwrap().type_name(), "string");
        assert_eq!(read_data.get("binary_value").unwrap().type_name(), "binary");
        assert_eq!(read_data.get("json_value").unwrap().type_name(), "json");

        assert_eq!(
            read_data.get("binary_value").unwrap().as_bytes(),
            vec![0x01, 0x02, 0x03]
        );
    }

    /// Test metadata operations
    #[tokio::test]
    async fn test_metadata_updates() {
        let store = Arc::new(InMemorySecretStore::new());
        let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

        let path = SecretPath::new("/app/secret").unwrap();

        // Create with metadata
        let initial_metadata = SecretMetadata::new()
            .with_description("Initial description")
            .with_owner("team-a")
            .with_label("env", "dev");

        manager
            .create_secret(
                path.clone(),
                SecretData::new(),
                initial_metadata,
                "admin".to_string(),
                None,
            )
            .await
            .unwrap();

        // Update metadata
        let updated_metadata = SecretMetadata::new()
            .with_description("Updated description")
            .with_owner("team-b")
            .with_label("env", "prod")
            .with_label("version", "2.0");

        store
            .update_metadata(&path, updated_metadata)
            .await
            .unwrap();

        // Verify update
        let metadata = store.get_metadata(&path).await.unwrap();
        assert_eq!(
            metadata.description,
            Some("Updated description".to_string())
        );
        assert_eq!(metadata.owner, Some("team-b".to_string()));
        assert_eq!(metadata.labels.get("env"), Some(&"prod".to_string()));
        assert_eq!(metadata.labels.get("version"), Some(&"2.0".to_string()));
    }
}
