//! Version management for secrets.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::secret::SecretId;

/// A specific version of a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// The secret this version belongs to.
    pub secret_id: SecretId,
    /// Version number (1-indexed).
    pub version: u32,
    /// The encrypted secret data.
    pub data: EncryptedSecretData,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Who created this version.
    pub created_by: Option<String>,
    /// Whether this version has been destroyed.
    pub destroyed: bool,
    /// Destruction timestamp.
    pub destroyed_at: Option<DateTime<Utc>>,
}

impl SecretVersion {
    /// Create a new secret version.
    pub fn new(
        secret_id: SecretId,
        version: u32,
        data: EncryptedSecretData,
        created_by: Option<String>,
    ) -> Self {
        Self {
            secret_id,
            version,
            data,
            created_at: Utc::now(),
            created_by,
            destroyed: false,
            destroyed_at: None,
        }
    }

    /// Mark this version as destroyed.
    pub fn destroy(&mut self) {
        if !self.destroyed {
            self.destroyed = true;
            self.destroyed_at = Some(Utc::now());
        }
    }

    /// Check if this version is usable (not destroyed).
    pub fn is_usable(&self) -> bool {
        !self.destroyed
    }
}

/// Encrypted secret data (stored at rest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecretData {
    /// Encryption algorithm used.
    pub algorithm: String,
    /// Key ID used for encryption.
    pub key_id: String,
    /// Encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// Nonce/IV.
    pub nonce: Vec<u8>,
}

impl EncryptedSecretData {
    /// Create new encrypted secret data.
    pub fn new(
        algorithm: impl Into<String>,
        key_id: impl Into<String>,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            key_id: key_id.into(),
            ciphertext,
            nonce,
        }
    }

    /// Create a placeholder for unencrypted (in-memory) data.
    /// This is used for the in-memory store where data isn't actually encrypted.
    pub fn unencrypted_placeholder() -> Self {
        Self {
            algorithm: "none".to_string(),
            key_id: "none".to_string(),
            ciphertext: Vec::new(),
            nonce: Vec::new(),
        }
    }
}

/// Version retention policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionPolicy {
    /// Maximum number of versions to keep.
    pub max_versions: Option<u32>,
    /// Minimum time to keep versions.
    pub min_retention: Option<Duration>,
    /// Whether to auto-destroy old versions.
    pub auto_destroy: bool,
}

impl Default for VersionPolicy {
    fn default() -> Self {
        Self {
            max_versions: Some(10),
            min_retention: Some(Duration::days(7)),
            auto_destroy: false,
        }
    }
}

impl VersionPolicy {
    /// Create a new version policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of versions to keep.
    pub fn with_max_versions(mut self, max: u32) -> Self {
        self.max_versions = Some(max);
        self
    }

    /// Set the minimum retention period.
    pub fn with_min_retention(mut self, retention: Duration) -> Self {
        self.min_retention = Some(retention);
        self
    }

    /// Enable auto-destroy of old versions.
    pub fn with_auto_destroy(mut self, enabled: bool) -> Self {
        self.auto_destroy = enabled;
        self
    }

    /// Create a policy that keeps all versions.
    pub fn keep_all() -> Self {
        Self {
            max_versions: None,
            min_retention: None,
            auto_destroy: false,
        }
    }

    /// Create a policy that keeps only the latest version.
    pub fn keep_latest_only() -> Self {
        Self {
            max_versions: Some(1),
            min_retention: None,
            auto_destroy: true,
        }
    }
}

/// Version manager for a secret.
pub struct VersionManager {
    policy: VersionPolicy,
}

impl VersionManager {
    /// Create a new version manager with the given policy.
    pub fn new(policy: VersionPolicy) -> Self {
        Self { policy }
    }

    /// Create a version manager with default policy.
    pub fn with_default_policy() -> Self {
        Self::new(VersionPolicy::default())
    }

    /// Get the policy.
    pub fn policy(&self) -> &VersionPolicy {
        &self.policy
    }

    /// Update the policy.
    pub fn set_policy(&mut self, policy: VersionPolicy) {
        self.policy = policy;
    }

    /// Determine which versions should be cleaned up.
    pub fn versions_to_cleanup(&self, versions: &[SecretVersion]) -> Vec<u32> {
        let mut to_cleanup = Vec::new();
        let now = Utc::now();

        // Sort by version descending (newest first)
        let mut sorted: Vec<_> = versions.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        for (i, version) in sorted.iter().enumerate() {
            // Skip already destroyed versions
            if version.destroyed {
                continue;
            }

            let should_cleanup = match self.policy.max_versions {
                Some(max) if i >= max as usize => {
                    // This version exceeds the max count
                    // Check minimum retention before marking for cleanup
                    match self.policy.min_retention {
                        Some(min_ret) => now.signed_duration_since(version.created_at) > min_ret,
                        None => true,
                    }
                }
                _ => false,
            };

            if should_cleanup && self.policy.auto_destroy {
                to_cleanup.push(version.version);
            }
        }

        to_cleanup
    }

    /// Check if a version can be cleaned up.
    pub fn can_cleanup(&self, version: &SecretVersion, current_version: u32) -> bool {
        // Never cleanup the current version
        if version.version == current_version {
            return false;
        }

        // Already destroyed versions don't need cleanup
        if version.destroyed {
            return false;
        }

        // Check minimum retention
        if let Some(min_ret) = self.policy.min_retention {
            let age = Utc::now().signed_duration_since(version.created_at);
            if age <= min_ret {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_version(secret_id: &SecretId, version: u32, age_days: i64) -> SecretVersion {
        SecretVersion {
            secret_id: secret_id.clone(),
            version,
            data: EncryptedSecretData::unencrypted_placeholder(),
            created_at: Utc::now() - Duration::days(age_days),
            created_by: None,
            destroyed: false,
            destroyed_at: None,
        }
    }

    #[test]
    fn test_version_creation() {
        let secret_id = SecretId::new();
        let data = EncryptedSecretData::new("AES-256-GCM", "key-123", vec![1, 2, 3], vec![4, 5, 6]);
        let version = SecretVersion::new(secret_id.clone(), 1, data, Some("admin".to_string()));

        assert_eq!(version.version, 1);
        assert_eq!(version.created_by, Some("admin".to_string()));
        assert!(!version.destroyed);
        assert!(version.is_usable());
    }

    #[test]
    fn test_version_destruction() {
        let secret_id = SecretId::new();
        let data = EncryptedSecretData::unencrypted_placeholder();
        let mut version = SecretVersion::new(secret_id, 1, data, None);

        assert!(version.is_usable());

        version.destroy();

        assert!(!version.is_usable());
        assert!(version.destroyed);
        assert!(version.destroyed_at.is_some());
    }

    #[test]
    fn test_version_policy_default() {
        let policy = VersionPolicy::default();

        assert_eq!(policy.max_versions, Some(10));
        assert!(policy.min_retention.is_some());
        assert!(!policy.auto_destroy);
    }

    #[test]
    fn test_version_policy_keep_all() {
        let policy = VersionPolicy::keep_all();

        assert!(policy.max_versions.is_none());
        assert!(policy.min_retention.is_none());
        assert!(!policy.auto_destroy);
    }

    #[test]
    fn test_version_policy_keep_latest() {
        let policy = VersionPolicy::keep_latest_only();

        assert_eq!(policy.max_versions, Some(1));
        assert!(policy.auto_destroy);
    }

    #[test]
    fn test_version_manager_cleanup_detection() {
        let secret_id = SecretId::new();
        let policy = VersionPolicy::new()
            .with_max_versions(3)
            .with_min_retention(Duration::days(1))
            .with_auto_destroy(true);

        let manager = VersionManager::new(policy);

        // Create 5 versions, with varying ages
        let versions = vec![
            create_test_version(&secret_id, 1, 10), // Old, should be cleaned
            create_test_version(&secret_id, 2, 8),  // Old, should be cleaned
            create_test_version(&secret_id, 3, 5),  // Keep (within max)
            create_test_version(&secret_id, 4, 2),  // Keep (within max)
            create_test_version(&secret_id, 5, 0),  // Keep (within max, latest)
        ];

        let to_cleanup = manager.versions_to_cleanup(&versions);

        // Versions 1 and 2 should be marked for cleanup
        assert_eq!(to_cleanup.len(), 2);
        assert!(to_cleanup.contains(&1));
        assert!(to_cleanup.contains(&2));
    }

    #[test]
    fn test_version_manager_respects_min_retention() {
        let secret_id = SecretId::new();
        let policy = VersionPolicy::new()
            .with_max_versions(2)
            .with_min_retention(Duration::days(30)) // 30 day minimum
            .with_auto_destroy(true);

        let manager = VersionManager::new(policy);

        // Create 3 versions, but all are too young to cleanup
        let versions = vec![
            create_test_version(&secret_id, 1, 10), // Exceeds max but within retention
            create_test_version(&secret_id, 2, 5),
            create_test_version(&secret_id, 3, 0),
        ];

        let to_cleanup = manager.versions_to_cleanup(&versions);

        // No versions should be cleaned up due to minimum retention
        assert!(to_cleanup.is_empty());
    }

    #[test]
    fn test_version_manager_no_auto_destroy() {
        let secret_id = SecretId::new();
        let policy = VersionPolicy::new()
            .with_max_versions(2)
            .with_auto_destroy(false); // Auto-destroy disabled

        let manager = VersionManager::new(policy);

        let versions = vec![
            create_test_version(&secret_id, 1, 100),
            create_test_version(&secret_id, 2, 50),
            create_test_version(&secret_id, 3, 0),
        ];

        let to_cleanup = manager.versions_to_cleanup(&versions);

        // No versions marked because auto_destroy is false
        assert!(to_cleanup.is_empty());
    }

    #[test]
    fn test_can_cleanup() {
        let secret_id = SecretId::new();
        let policy = VersionPolicy::new().with_min_retention(Duration::days(7));

        let manager = VersionManager::new(policy);

        // Old version - can be cleaned
        let old_version = create_test_version(&secret_id, 1, 10);
        assert!(manager.can_cleanup(&old_version, 3));

        // Recent version - cannot be cleaned due to retention
        let recent_version = create_test_version(&secret_id, 2, 1);
        assert!(!manager.can_cleanup(&recent_version, 3));

        // Current version - never cleanup
        let current = create_test_version(&secret_id, 3, 0);
        assert!(!manager.can_cleanup(&current, 3));

        // Already destroyed - no need to cleanup
        let mut destroyed = create_test_version(&secret_id, 1, 10);
        destroyed.destroy();
        assert!(!manager.can_cleanup(&destroyed, 3));
    }
}
