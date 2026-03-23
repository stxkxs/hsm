//! Integration tests for the hsm-secrets crate.
//!
//! These tests exercise the public API end-to-end using the InMemorySecretStore,
//! covering CRUD operations, versioning, path listing, lease management, and edge cases.

use hsm_secrets::{
    EncryptedSecretData, InMemorySecretStore, LeaseConfig, LeaseError, LeaseEvent, SecretData,
    SecretError, SecretId, SecretMetadata, SecretPath, SecretStore, SecretValue, SecretVersion,
    SecretsManager, VersionManager, VersionPolicy,
};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// 1. Secret store creation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_secret_store() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    // Store starts empty
    assert_eq!(store.secret_count(), 0);
    assert_eq!(store.version_count(), 0);

    // Manager's lease_manager is accessible
    assert!(manager.lease_manager().active_lease_count() == 0);
}

#[tokio::test]
async fn test_create_secret_store_with_custom_lease_config() {
    let store = Arc::new(InMemorySecretStore::new());
    let config = LeaseConfig::new()
        .with_default_ttl(chrono::Duration::minutes(15))
        .with_max_ttl(chrono::Duration::hours(2))
        .with_renewable(false);

    let (manager, _rx) = SecretsManager::with_lease_config(store, "test-key".to_string(), config);

    // The lease config should affect created leases
    let path = SecretPath::new("/test/secret").unwrap();
    let (_, lease) = manager
        .create_secret(
            path,
            SecretData::new(),
            SecretMetadata::default(),
            "client".to_string(),
            None,
        )
        .await
        .unwrap();

    assert!(!lease.renewable);
}

// ---------------------------------------------------------------------------
// 2. CRUD operations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_secret() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let path = SecretPath::new("/app/db-creds").unwrap();
    let mut data = SecretData::new();
    data.insert("user", SecretValue::string("admin"));
    data.insert("pass", SecretValue::string("hunter2"));

    let metadata = SecretMetadata::new()
        .with_description("DB credentials")
        .with_owner("platform-team");

    let (secret, lease) = manager
        .create_secret(path.clone(), data, metadata, "deployer".to_string(), None)
        .await
        .unwrap();

    assert_eq!(secret.current_version, 1);
    assert_eq!(secret.path, path);
    assert!(lease.is_valid());
    assert_eq!(store.secret_count(), 1);
    assert_eq!(store.version_count(), 1);
}

#[tokio::test]
async fn test_create_duplicate_secret_fails() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/app/dup").unwrap();

    manager
        .create_secret(
            path.clone(),
            SecretData::new(),
            SecretMetadata::default(),
            "client".to_string(),
            None,
        )
        .await
        .unwrap();

    let result = manager
        .create_secret(
            path,
            SecretData::new(),
            SecretMetadata::default(),
            "client".to_string(),
            None,
        )
        .await;

    assert!(matches!(result, Err(SecretError::AlreadyExists(_))));
}

#[tokio::test]
async fn test_read_secret_latest() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/app/read-test").unwrap();
    let mut data = SecretData::new();
    data.insert("key", SecretValue::string("value"));

    manager
        .create_secret(
            path.clone(),
            data,
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    let (read_data, lease) = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await
        .unwrap();

    assert_eq!(read_data.get("key").unwrap().as_str(), Some("value"));
    assert!(lease.is_valid());
}

#[tokio::test]
async fn test_read_nonexistent_secret() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/does/not/exist").unwrap();
    let result = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await;

    assert!(matches!(result, Err(SecretError::NotFound(_))));
}

#[tokio::test]
async fn test_update_secret() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let path = SecretPath::new("/app/update-test").unwrap();
    let mut data = SecretData::new();
    data.insert("val", SecretValue::string("v1"));

    manager
        .create_secret(
            path.clone(),
            data,
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    let mut data_v2 = SecretData::new();
    data_v2.insert("val", SecretValue::string("v2"));

    let (updated, _lease) = manager
        .update_secret(&path, data_v2, "c".to_string(), None)
        .await
        .unwrap();

    assert_eq!(updated.current_version, 2);
    assert_eq!(store.version_count(), 2);

    // Latest read should return v2
    let (read_data, _) = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await
        .unwrap();
    assert_eq!(read_data.get("val").unwrap().as_str(), Some("v2"));
}

#[tokio::test]
async fn test_update_nonexistent_secret_fails() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/missing").unwrap();
    let result = manager
        .update_secret(&path, SecretData::new(), "c".to_string(), None)
        .await;

    assert!(matches!(result, Err(SecretError::NotFound(_))));
}

#[tokio::test]
async fn test_delete_secret() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let path = SecretPath::new("/app/to-delete").unwrap();
    let mut data = SecretData::new();
    data.insert("key", SecretValue::string("val"));

    let (_, create_lease) = manager
        .create_secret(
            path.clone(),
            data,
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    // Also read to get another lease
    let (_, read_lease) = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await
        .unwrap();

    manager.delete_secret(&path).await.unwrap();

    // Store should be empty
    assert_eq!(store.secret_count(), 0);
    assert_eq!(store.version_count(), 0);

    // Leases for this secret should be revoked
    assert!(manager.validate_lease(&create_lease.id).is_err());
    assert!(manager.validate_lease(&read_lease.id).is_err());

    // Reading should return NotFound
    let result = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await;
    assert!(matches!(result, Err(SecretError::NotFound(_))));
}

#[tokio::test]
async fn test_delete_nonexistent_secret_fails() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/ghost").unwrap();
    let result = manager.delete_secret(&path).await;
    assert!(matches!(result, Err(SecretError::NotFound(_))));
}

// ---------------------------------------------------------------------------
// 3. Version management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_versions_and_specific_reads() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let path = SecretPath::new("/app/versioned").unwrap();

    // Create v1
    let mut d1 = SecretData::new();
    d1.insert("val", SecretValue::string("one"));
    manager
        .create_secret(
            path.clone(),
            d1,
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    // Update to v2
    let mut d2 = SecretData::new();
    d2.insert("val", SecretValue::string("two"));
    manager
        .update_secret(&path, d2, "c".to_string(), None)
        .await
        .unwrap();

    // Update to v3
    let mut d3 = SecretData::new();
    d3.insert("val", SecretValue::string("three"));
    let (secret_v3, _) = manager
        .update_secret(&path, d3, "c".to_string(), None)
        .await
        .unwrap();

    assert_eq!(secret_v3.current_version, 3);

    // Read each specific version
    let (data_v1, _) = manager
        .read_secret(&path, Some(1), "c".to_string(), None)
        .await
        .unwrap();
    assert_eq!(data_v1.get("val").unwrap().as_str(), Some("one"));

    let (data_v2, _) = manager
        .read_secret(&path, Some(2), "c".to_string(), None)
        .await
        .unwrap();
    assert_eq!(data_v2.get("val").unwrap().as_str(), Some("two"));

    let (data_v3, _) = manager
        .read_secret(&path, Some(3), "c".to_string(), None)
        .await
        .unwrap();
    assert_eq!(data_v3.get("val").unwrap().as_str(), Some("three"));

    // Latest (None) should equal v3
    let (data_latest, _) = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await
        .unwrap();
    assert_eq!(data_latest.get("val").unwrap().as_str(), Some("three"));
}

#[tokio::test]
async fn test_read_invalid_version_numbers() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/app/ver-edge").unwrap();
    manager
        .create_secret(
            path.clone(),
            SecretData::new(),
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    // Version 0 should fail
    let result = manager
        .read_secret(&path, Some(0), "c".to_string(), None)
        .await;
    assert!(matches!(result, Err(SecretError::VersionNotFound(0))));

    // Version 999 (beyond current) should fail
    let result = manager
        .read_secret(&path, Some(999), "c".to_string(), None)
        .await;
    assert!(matches!(result, Err(SecretError::VersionNotFound(999))));
}

#[tokio::test]
async fn test_destroy_version() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let path = SecretPath::new("/app/destroy-ver").unwrap();

    // Create v1
    let mut d1 = SecretData::new();
    d1.insert("val", SecretValue::string("one"));
    manager
        .create_secret(
            path.clone(),
            d1,
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    // Update to v2
    let mut d2 = SecretData::new();
    d2.insert("val", SecretValue::string("two"));
    manager
        .update_secret(&path, d2, "c".to_string(), None)
        .await
        .unwrap();

    // Destroy v1
    store.destroy_version(&path, 1).await.unwrap();

    // Reading v1 should now fail
    let result = manager
        .read_secret(&path, Some(1), "c".to_string(), None)
        .await;
    assert!(matches!(result, Err(SecretError::VersionNotFound(1))));

    // v2 should still be accessible
    let (data_v2, _) = manager
        .read_secret(&path, Some(2), "c".to_string(), None)
        .await
        .unwrap();
    assert_eq!(data_v2.get("val").unwrap().as_str(), Some("two"));
}

#[tokio::test]
async fn test_cannot_destroy_current_version() {
    let store = Arc::new(InMemorySecretStore::new());

    let path = SecretPath::new("/app/no-destroy-current").unwrap();
    store
        .create(path.clone(), SecretData::new(), SecretMetadata::default())
        .await
        .unwrap();

    let result = store.destroy_version(&path, 1).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_version_count_on_store() {
    let store = Arc::new(InMemorySecretStore::new());
    let trait_store: &dyn SecretStore = store.as_ref();
    let path = SecretPath::new("/app/vcount").unwrap();

    trait_store
        .create(path.clone(), SecretData::new(), SecretMetadata::default())
        .await
        .unwrap();
    assert_eq!(trait_store.version_count(&path).await.unwrap(), 1);

    trait_store.update(&path, SecretData::new()).await.unwrap();
    assert_eq!(trait_store.version_count(&path).await.unwrap(), 2);

    trait_store.update(&path, SecretData::new()).await.unwrap();
    assert_eq!(trait_store.version_count(&path).await.unwrap(), 3);
}

#[tokio::test]
async fn test_version_policy_cleanup_logic() {
    let policy = VersionPolicy::new()
        .with_max_versions(2)
        .with_min_retention(chrono::Duration::days(1))
        .with_auto_destroy(true);

    let manager = VersionManager::new(policy);
    let secret_id = SecretId::new();
    let now = chrono::Utc::now();

    let versions: Vec<SecretVersion> = vec![
        SecretVersion {
            secret_id: secret_id.clone(),
            version: 1,
            data: EncryptedSecretData::unencrypted_placeholder(),
            created_at: now - chrono::Duration::days(30),
            created_by: None,
            destroyed: false,
            destroyed_at: None,
        },
        SecretVersion {
            secret_id: secret_id.clone(),
            version: 2,
            data: EncryptedSecretData::unencrypted_placeholder(),
            created_at: now - chrono::Duration::days(10),
            created_by: None,
            destroyed: false,
            destroyed_at: None,
        },
        SecretVersion {
            secret_id: secret_id.clone(),
            version: 3,
            data: EncryptedSecretData::unencrypted_placeholder(),
            created_at: now - chrono::Duration::hours(1),
            created_by: None,
            destroyed: false,
            destroyed_at: None,
        },
    ];

    let to_cleanup = manager.versions_to_cleanup(&versions);

    // v1 exceeds max_versions (2) and is past min_retention (30 days > 1 day) -> cleanup
    assert!(to_cleanup.contains(&1));
    // v2 and v3 should be kept (top 2 versions)
    assert!(!to_cleanup.contains(&2));
    assert!(!to_cleanup.contains(&3));
}

#[tokio::test]
async fn test_version_policy_keep_all() {
    let policy = VersionPolicy::keep_all();
    let manager = VersionManager::new(policy);
    let secret_id = SecretId::new();
    let now = chrono::Utc::now();

    let versions: Vec<SecretVersion> = (1..=20)
        .map(|v| SecretVersion {
            secret_id: secret_id.clone(),
            version: v,
            data: EncryptedSecretData::unencrypted_placeholder(),
            created_at: now - chrono::Duration::days((20 - v) as i64),
            created_by: None,
            destroyed: false,
            destroyed_at: None,
        })
        .collect();

    let to_cleanup = manager.versions_to_cleanup(&versions);
    assert!(to_cleanup.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Path listing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_secrets_under_prefix() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let paths = [
        "/org/team-a/db/prod",
        "/org/team-a/db/staging",
        "/org/team-a/cache/prod",
        "/org/team-b/db/prod",
        "/other/secret",
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

    // List under /org/team-a
    let team_a = store
        .list(&SecretPath::new("/org/team-a").unwrap())
        .await
        .unwrap();
    assert_eq!(team_a.len(), 3);

    // List under /org/team-a/db
    let team_a_db = store
        .list(&SecretPath::new("/org/team-a/db").unwrap())
        .await
        .unwrap();
    assert_eq!(team_a_db.len(), 2);

    // List under /org (should include team-a and team-b)
    let org = store.list(&SecretPath::new("/org").unwrap()).await.unwrap();
    assert_eq!(org.len(), 4);

    // List under /other
    let other = store
        .list(&SecretPath::new("/other").unwrap())
        .await
        .unwrap();
    assert_eq!(other.len(), 1);

    // List under non-matching prefix
    let empty = store
        .list(&SecretPath::new("/nonexistent").unwrap())
        .await
        .unwrap();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn test_list_root_returns_all() {
    let store = Arc::new(InMemorySecretStore::new());

    for p in ["/a", "/b/c", "/d/e/f"] {
        store
            .create(
                SecretPath::new(p).unwrap(),
                SecretData::new(),
                SecretMetadata::default(),
            )
            .await
            .unwrap();
    }

    let all = store.list(&SecretPath::new("/").unwrap()).await.unwrap();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn test_exists_check() {
    let store = Arc::new(InMemorySecretStore::new());

    let path = SecretPath::new("/check/exists").unwrap();
    assert!(!store.exists(&path).await.unwrap());

    store
        .create(path.clone(), SecretData::new(), SecretMetadata::default())
        .await
        .unwrap();
    assert!(store.exists(&path).await.unwrap());

    store.delete(&path).await.unwrap();
    assert!(!store.exists(&path).await.unwrap());
}

// ---------------------------------------------------------------------------
// 5. Lease management
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_lease_created_on_every_operation() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/app/lease-ops").unwrap();

    // Create produces a lease
    let (_, create_lease) = manager
        .create_secret(
            path.clone(),
            SecretData::new(),
            SecretMetadata::default(),
            "c1".to_string(),
            None,
        )
        .await
        .unwrap();
    assert!(create_lease.is_valid());
    assert_eq!(create_lease.client_id, "c1");

    // Read produces a lease
    let (_, read_lease) = manager
        .read_secret(&path, None, "c2".to_string(), None)
        .await
        .unwrap();
    assert!(read_lease.is_valid());
    assert_eq!(read_lease.client_id, "c2");

    // Update produces a lease
    let (_, update_lease) = manager
        .update_secret(&path, SecretData::new(), "c3".to_string(), None)
        .await
        .unwrap();
    assert!(update_lease.is_valid());
    assert_eq!(update_lease.client_id, "c3");
}

#[tokio::test]
async fn test_lease_renew_and_revoke() {
    let store = Arc::new(InMemorySecretStore::new());
    let config = LeaseConfig::new()
        .with_default_ttl(chrono::Duration::hours(1))
        .with_max_ttl(chrono::Duration::hours(24))
        .with_renewable(true);

    let (manager, mut rx) =
        SecretsManager::with_lease_config(store, "test-key".to_string(), config);

    let path = SecretPath::new("/app/lease-renew").unwrap();
    let (_, lease) = manager
        .create_secret(
            path,
            SecretData::new(),
            SecretMetadata::default(),
            "client".to_string(),
            Some(chrono::Duration::minutes(10)),
        )
        .await
        .unwrap();

    // Renew
    let original_expires = lease.expires_at;
    let renewed = manager
        .renew_lease(&lease.id, Some(chrono::Duration::hours(2)))
        .unwrap();
    assert!(renewed.expires_at > original_expires);

    // Should get a Renewed event
    let event = rx.try_recv().unwrap();
    assert!(matches!(event, LeaseEvent::Renewed(_, _)));

    // Revoke
    manager.revoke_lease(&lease.id).unwrap();
    let event = rx.try_recv().unwrap();
    assert!(matches!(event, LeaseEvent::Revoked(_)));

    // Validate should fail
    assert!(matches!(
        manager.validate_lease(&lease.id),
        Err(LeaseError::Revoked)
    ));
}

#[tokio::test]
async fn test_lease_not_renewable() {
    let store = Arc::new(InMemorySecretStore::new());
    let config = LeaseConfig::new().with_renewable(false);

    let (manager, _rx) = SecretsManager::with_lease_config(store, "test-key".to_string(), config);

    let path = SecretPath::new("/app/no-renew").unwrap();
    let (_, lease) = manager
        .create_secret(
            path,
            SecretData::new(),
            SecretMetadata::default(),
            "client".to_string(),
            None,
        )
        .await
        .unwrap();

    let result = manager.renew_lease(&lease.id, None);
    assert!(matches!(result, Err(LeaseError::NotRenewable)));
}

#[tokio::test]
async fn test_list_client_leases() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    for i in 0..3 {
        let path = SecretPath::new(format!("/app/secret-{}", i)).unwrap();
        manager
            .create_secret(
                path,
                SecretData::new(),
                SecretMetadata::default(),
                "worker-1".to_string(),
                None,
            )
            .await
            .unwrap();
    }

    let path_other = SecretPath::new("/app/secret-other").unwrap();
    manager
        .create_secret(
            path_other,
            SecretData::new(),
            SecretMetadata::default(),
            "worker-2".to_string(),
            None,
        )
        .await
        .unwrap();

    let w1_leases = manager.list_client_leases("worker-1");
    assert_eq!(w1_leases.len(), 3);

    let w2_leases = manager.list_client_leases("worker-2");
    assert_eq!(w2_leases.len(), 1);

    let w3_leases = manager.list_client_leases("worker-3");
    assert!(w3_leases.is_empty());
}

#[tokio::test]
async fn test_revoke_all_secret_leases() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/app/multi-lease").unwrap();
    let (secret, lease1) = manager
        .create_secret(
            path.clone(),
            SecretData::new(),
            SecretMetadata::default(),
            "c1".to_string(),
            None,
        )
        .await
        .unwrap();

    let (_, lease2) = manager
        .read_secret(&path, None, "c2".to_string(), None)
        .await
        .unwrap();

    let revoked_count = manager.revoke_secret_leases(&secret.id);
    assert_eq!(revoked_count, 2);

    assert!(manager.validate_lease(&lease1.id).is_err());
    assert!(manager.validate_lease(&lease2.id).is_err());
}

// ---------------------------------------------------------------------------
// 6. Edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_secret_data() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/app/empty").unwrap();
    let data = SecretData::new();
    assert!(data.is_empty());

    let (secret, _) = manager
        .create_secret(
            path.clone(),
            data,
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(secret.current_version, 1);

    let (read_data, _) = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await
        .unwrap();
    assert!(read_data.is_empty());
    assert_eq!(read_data.len(), 0);
}

#[tokio::test]
async fn test_special_characters_in_paths() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    // Paths with hyphens, underscores, dots, and numbers
    let valid_paths = [
        "/app/my-secret",
        "/app/my_secret",
        "/app/my.secret",
        "/app/secret123",
        "/app/UPPER",
        "/a/b/c/d/e/f/g/h",
    ];

    for p in &valid_paths {
        let path = SecretPath::new(*p).unwrap();
        manager
            .create_secret(
                path,
                SecretData::new(),
                SecretMetadata::default(),
                "c".to_string(),
                None,
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn test_invalid_path_validation() {
    // Empty path
    assert!(matches!(
        SecretPath::new(""),
        Err(SecretError::InvalidPath(_))
    ));

    // No leading slash
    assert!(matches!(
        SecretPath::new("app/secret"),
        Err(SecretError::InvalidPath(_))
    ));

    // Double slash
    assert!(matches!(
        SecretPath::new("/app//secret"),
        Err(SecretError::InvalidPath(_))
    ));
}

#[tokio::test]
async fn test_secret_value_types_roundtrip() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store, "test-key".to_string());

    let path = SecretPath::new("/app/types").unwrap();
    let mut data = SecretData::new();
    data.insert("str", SecretValue::string("hello world"));
    data.insert("bin", SecretValue::binary(vec![0x00, 0xFF, 0x42]));
    data.insert(
        "json",
        SecretValue::json(serde_json::json!({
            "nested": { "array": [1, 2, 3] },
            "bool": true
        })),
    );

    manager
        .create_secret(
            path.clone(),
            data,
            SecretMetadata::default(),
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    let (read_data, _) = manager
        .read_secret(&path, None, "c".to_string(), None)
        .await
        .unwrap();

    assert_eq!(read_data.get("str").unwrap().as_str(), Some("hello world"));
    assert_eq!(read_data.get("str").unwrap().type_name(), "string");

    assert_eq!(
        read_data.get("bin").unwrap().as_bytes(),
        vec![0x00, 0xFF, 0x42]
    );
    assert_eq!(read_data.get("bin").unwrap().type_name(), "binary");

    assert_eq!(read_data.get("json").unwrap().type_name(), "json");
}

#[tokio::test]
async fn test_large_number_of_secrets() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let count = 100;
    for i in 0..count {
        let path = SecretPath::new(format!("/bulk/secret-{}", i)).unwrap();
        let mut data = SecretData::new();
        data.insert("index", SecretValue::string(i.to_string()));

        manager
            .create_secret(
                path,
                data,
                SecretMetadata::default(),
                "bulk-loader".to_string(),
                None,
            )
            .await
            .unwrap();
    }

    assert_eq!(store.secret_count(), count);

    let all = store
        .list(&SecretPath::new("/bulk").unwrap())
        .await
        .unwrap();
    assert_eq!(all.len(), count);
}

#[tokio::test]
async fn test_metadata_with_labels() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let path = SecretPath::new("/app/labeled").unwrap();
    let metadata = SecretMetadata::new()
        .with_description("A labeled secret")
        .with_owner("security-team")
        .with_label("env", "production")
        .with_label("region", "us-east-1")
        .with_label("tier", "critical");

    manager
        .create_secret(
            path.clone(),
            SecretData::new(),
            metadata,
            "c".to_string(),
            None,
        )
        .await
        .unwrap();

    let read_metadata = store.get_metadata(&path).await.unwrap();
    assert_eq!(
        read_metadata.description,
        Some("A labeled secret".to_string())
    );
    assert_eq!(read_metadata.owner, Some("security-team".to_string()));
    assert_eq!(
        read_metadata.labels.get("env"),
        Some(&"production".to_string())
    );
    assert_eq!(
        read_metadata.labels.get("region"),
        Some(&"us-east-1".to_string())
    );
    assert_eq!(
        read_metadata.labels.get("tier"),
        Some(&"critical".to_string())
    );
}

#[tokio::test]
async fn test_update_metadata() {
    let store = Arc::new(InMemorySecretStore::new());

    let path = SecretPath::new("/app/meta-update").unwrap();
    store
        .create(
            path.clone(),
            SecretData::new(),
            SecretMetadata::new().with_description("original"),
        )
        .await
        .unwrap();

    store
        .update_metadata(
            &path,
            SecretMetadata::new()
                .with_description("updated")
                .with_owner("new-owner"),
        )
        .await
        .unwrap();

    let meta = store.get_metadata(&path).await.unwrap();
    assert_eq!(meta.description, Some("updated".to_string()));
    assert_eq!(meta.owner, Some("new-owner".to_string()));
}

#[tokio::test]
async fn test_secret_path_join_and_parent() {
    let base = SecretPath::new("/org/team").unwrap();
    let child = base.join("secrets").unwrap();
    assert_eq!(child.as_str(), "/org/team/secrets");

    let parent = child.parent().unwrap();
    assert_eq!(parent.as_str(), "/org/team");

    let grandparent = parent.parent().unwrap();
    assert_eq!(grandparent.as_str(), "/org");

    let root_parent = SecretPath::new("/").unwrap();
    assert!(root_parent.parent().is_none());
}

#[tokio::test]
async fn test_secret_path_name() {
    let path = SecretPath::new("/org/team/secret-name").unwrap();
    assert_eq!(path.name(), "secret-name");

    let root = SecretPath::new("/").unwrap();
    assert_eq!(root.name(), "");
}

#[tokio::test]
async fn test_create_read_delete_cycle_multiple_times() {
    let store = Arc::new(InMemorySecretStore::new());
    let (manager, _rx) = SecretsManager::new(store.clone(), "test-key".to_string());

    let path = SecretPath::new("/app/cycle").unwrap();

    for i in 0..5 {
        let mut data = SecretData::new();
        data.insert("iteration", SecretValue::string(i.to_string()));

        manager
            .create_secret(
                path.clone(),
                data,
                SecretMetadata::default(),
                "c".to_string(),
                None,
            )
            .await
            .unwrap();

        let (read_data, _) = manager
            .read_secret(&path, None, "c".to_string(), None)
            .await
            .unwrap();
        assert_eq!(
            read_data.get("iteration").unwrap().as_str(),
            Some(i.to_string().as_str())
        );

        manager.delete_secret(&path).await.unwrap();

        // Verify it's gone
        assert!(!store.exists(&path).await.unwrap());
    }
}

#[tokio::test]
async fn test_clear_store() {
    let store = Arc::new(InMemorySecretStore::new());

    for i in 0..5 {
        store
            .create(
                SecretPath::new(format!("/s/{}", i)).unwrap(),
                SecretData::new(),
                SecretMetadata::default(),
            )
            .await
            .unwrap();
    }

    assert_eq!(store.secret_count(), 5);
    store.clear();
    assert_eq!(store.secret_count(), 0);
    assert_eq!(store.version_count(), 0);
}

#[tokio::test]
async fn test_secret_data_remove_key() {
    let mut data = SecretData::new();
    data.insert("keep", SecretValue::string("yes"));
    data.insert("remove", SecretValue::string("no"));

    assert_eq!(data.len(), 2);

    let removed = data.remove("remove");
    assert!(removed.is_some());
    assert_eq!(data.len(), 1);
    assert!(data.get("keep").is_some());
    assert!(data.get("remove").is_none());

    // Remove nonexistent key returns None
    assert!(data.remove("ghost").is_none());
}

#[tokio::test]
async fn test_lease_custom_ttl_capped_by_max() {
    let store = Arc::new(InMemorySecretStore::new());
    let config = LeaseConfig::new()
        .with_default_ttl(chrono::Duration::hours(1))
        .with_max_ttl(chrono::Duration::hours(2));

    let (manager, _rx) = SecretsManager::with_lease_config(store, "test-key".to_string(), config);

    let path = SecretPath::new("/app/ttl-cap").unwrap();
    let (_, lease) = manager
        .create_secret(
            path,
            SecretData::new(),
            SecretMetadata::default(),
            "c".to_string(),
            Some(chrono::Duration::hours(100)), // Way over max
        )
        .await
        .unwrap();

    // The lease TTL should be capped at max (2 hours)
    let remaining = lease.remaining_time();
    assert!(remaining <= chrono::Duration::hours(2));
    assert!(remaining > chrono::Duration::minutes(119)); // close to 2h
}
