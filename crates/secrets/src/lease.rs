//! Lease management for secrets.
//!
//! Leases provide temporary access to secrets with automatic expiration
//! and revocation capabilities.

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::secret::SecretId;

/// A lease granting temporary access to a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// Unique lease ID.
    pub id: LeaseId,
    /// Secret being accessed.
    pub secret_id: SecretId,
    /// Secret version.
    pub version: u32,
    /// Client identity.
    pub client_id: String,
    /// When the lease was created.
    pub created_at: DateTime<Utc>,
    /// When the lease expires.
    pub expires_at: DateTime<Utc>,
    /// Whether the lease has been revoked.
    pub revoked: bool,
    /// Whether the lease is renewable.
    pub renewable: bool,
    /// Maximum total TTL.
    pub max_ttl: Option<Duration>,
}

impl Lease {
    /// Check if this lease is currently valid.
    pub fn is_valid(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }

    /// Get the remaining time until expiration.
    pub fn remaining_time(&self) -> Duration {
        if self.revoked {
            Duration::zero()
        } else {
            let remaining = self.expires_at.signed_duration_since(Utc::now());
            if remaining < Duration::zero() {
                Duration::zero()
            } else {
                remaining
            }
        }
    }

    /// Get the remaining time in seconds.
    pub fn remaining_seconds(&self) -> i64 {
        self.remaining_time().num_seconds()
    }
}

/// Lease identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub String);

impl LeaseId {
    /// Create a new random lease ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create a lease ID from an existing string.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for LeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for LeaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lease configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseConfig {
    /// Default TTL for new leases.
    pub default_ttl: Duration,
    /// Maximum TTL allowed.
    pub max_ttl: Duration,
    /// Whether leases are renewable.
    pub renewable: bool,
}

impl Default for LeaseConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::hours(1),
            max_ttl: Duration::hours(24),
            renewable: true,
        }
    }
}

impl LeaseConfig {
    /// Create a new lease config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default TTL.
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Set the maximum TTL.
    pub fn with_max_ttl(mut self, ttl: Duration) -> Self {
        self.max_ttl = ttl;
        self
    }

    /// Set whether leases are renewable.
    pub fn with_renewable(mut self, renewable: bool) -> Self {
        self.renewable = renewable;
        self
    }
}

/// Event when a lease expires or is revoked.
#[derive(Debug, Clone)]
pub enum LeaseEvent {
    /// A lease has expired.
    Expired(LeaseId),
    /// A lease has been revoked.
    Revoked(LeaseId),
    /// A lease has been renewed.
    Renewed(LeaseId, DateTime<Utc>),
}

/// Manages active leases.
pub struct LeaseManager {
    leases: Arc<RwLock<HashMap<LeaseId, Lease>>>,
    config: LeaseConfig,
    event_tx: mpsc::Sender<LeaseEvent>,
}

impl LeaseManager {
    /// Create a new lease manager.
    pub fn new(config: LeaseConfig) -> (Self, mpsc::Receiver<LeaseEvent>) {
        let (tx, rx) = mpsc::channel(1000);
        (
            Self {
                leases: Arc::new(RwLock::new(HashMap::new())),
                config,
                event_tx: tx,
            },
            rx,
        )
    }

    /// Create a new lease manager with default configuration.
    pub fn with_default_config() -> (Self, mpsc::Receiver<LeaseEvent>) {
        Self::new(LeaseConfig::default())
    }

    /// Get the configuration.
    pub fn config(&self) -> &LeaseConfig {
        &self.config
    }

    /// Create a new lease.
    pub fn create_lease(
        &self,
        secret_id: SecretId,
        version: u32,
        client_id: String,
        ttl: Option<Duration>,
    ) -> Lease {
        let now = Utc::now();
        let ttl = ttl.unwrap_or(self.config.default_ttl);
        let ttl = std::cmp::min(ttl, self.config.max_ttl);

        let lease = Lease {
            id: LeaseId::new(),
            secret_id,
            version,
            client_id,
            created_at: now,
            expires_at: now + ttl,
            revoked: false,
            renewable: self.config.renewable,
            max_ttl: Some(self.config.max_ttl),
        };

        self.leases.write().insert(lease.id.clone(), lease.clone());

        // Schedule expiration check
        self.schedule_expiration(lease.id.clone(), ttl);

        lease
    }

    /// Schedule an expiration check for a lease.
    fn schedule_expiration(&self, lease_id: LeaseId, ttl: Duration) {
        let leases = self.leases.clone();
        let event_tx = self.event_tx.clone();

        tokio::spawn(async move {
            // Convert chrono Duration to std Duration
            let sleep_duration = ttl.to_std().unwrap_or(std::time::Duration::from_secs(0));
            tokio::time::sleep(sleep_duration).await;

            let mut leases_guard = leases.write();
            if let Some(lease) = leases_guard.get_mut(&lease_id) {
                if !lease.revoked && Utc::now() >= lease.expires_at {
                    lease.revoked = true;
                    let _ = event_tx.try_send(LeaseEvent::Expired(lease_id));
                }
            }
        });
    }

    /// Renew a lease.
    pub fn renew_lease(
        &self,
        lease_id: &LeaseId,
        increment: Option<Duration>,
    ) -> Result<Lease, LeaseError> {
        let mut leases = self.leases.write();
        let lease = leases.get_mut(lease_id).ok_or(LeaseError::NotFound)?;

        if lease.revoked {
            return Err(LeaseError::Revoked);
        }
        if !lease.renewable {
            return Err(LeaseError::NotRenewable);
        }

        let now = Utc::now();

        // Check if already expired
        if now >= lease.expires_at {
            lease.revoked = true;
            return Err(LeaseError::Expired);
        }

        let increment = increment.unwrap_or(self.config.default_ttl);

        // Check max TTL
        let new_expires = now + increment;
        let max_expires = lease.created_at + lease.max_ttl.unwrap_or(self.config.max_ttl);

        lease.expires_at = std::cmp::min(new_expires, max_expires);

        // Send renewal event
        let _ = self
            .event_tx
            .try_send(LeaseEvent::Renewed(lease_id.clone(), lease.expires_at));

        // Schedule new expiration check
        let remaining = lease.expires_at.signed_duration_since(now);
        if remaining > Duration::zero() {
            // Clone lease_id for the scheduled task
            let lease_id_clone = lease_id.clone();
            let leases_clone = self.leases.clone();
            let event_tx = self.event_tx.clone();

            tokio::spawn(async move {
                let sleep_duration = remaining
                    .to_std()
                    .unwrap_or(std::time::Duration::from_secs(0));
                tokio::time::sleep(sleep_duration).await;

                let mut leases_guard = leases_clone.write();
                if let Some(lease) = leases_guard.get_mut(&lease_id_clone) {
                    if !lease.revoked && Utc::now() >= lease.expires_at {
                        lease.revoked = true;
                        let _ = event_tx.try_send(LeaseEvent::Expired(lease_id_clone));
                    }
                }
            });
        }

        Ok(lease.clone())
    }

    /// Revoke a lease.
    pub fn revoke_lease(&self, lease_id: &LeaseId) -> Result<(), LeaseError> {
        let mut leases = self.leases.write();
        let lease = leases.get_mut(lease_id).ok_or(LeaseError::NotFound)?;

        if !lease.revoked {
            lease.revoked = true;
            let _ = self
                .event_tx
                .try_send(LeaseEvent::Revoked(lease_id.clone()));
        }

        Ok(())
    }

    /// Revoke all leases for a secret.
    pub fn revoke_all(&self, secret_id: &SecretId) -> usize {
        let mut leases = self.leases.write();
        let mut count = 0;

        for lease in leases.values_mut() {
            if &lease.secret_id == secret_id && !lease.revoked {
                lease.revoked = true;
                let _ = self
                    .event_tx
                    .try_send(LeaseEvent::Revoked(lease.id.clone()));
                count += 1;
            }
        }

        count
    }

    /// Validate a lease and return it if valid.
    pub fn validate_lease(&self, lease_id: &LeaseId) -> Result<Lease, LeaseError> {
        let leases = self.leases.read();
        let lease = leases.get(lease_id).ok_or(LeaseError::NotFound)?;

        if lease.revoked {
            return Err(LeaseError::Revoked);
        }
        if Utc::now() >= lease.expires_at {
            return Err(LeaseError::Expired);
        }

        Ok(lease.clone())
    }

    /// Get a lease without validation.
    pub fn get_lease(&self, lease_id: &LeaseId) -> Option<Lease> {
        self.leases.read().get(lease_id).cloned()
    }

    /// List all active leases for a client.
    pub fn list_client_leases(&self, client_id: &str) -> Vec<Lease> {
        self.leases
            .read()
            .values()
            .filter(|l| l.client_id == client_id && l.is_valid())
            .cloned()
            .collect()
    }

    /// List all active leases for a secret.
    pub fn list_secret_leases(&self, secret_id: &SecretId) -> Vec<Lease> {
        self.leases
            .read()
            .values()
            .filter(|l| &l.secret_id == secret_id && l.is_valid())
            .cloned()
            .collect()
    }

    /// Count active leases.
    pub fn active_lease_count(&self) -> usize {
        self.leases.read().values().filter(|l| l.is_valid()).count()
    }

    /// Remove expired and revoked leases from memory.
    pub fn cleanup_expired(&self) -> usize {
        let mut leases = self.leases.write();
        let now = Utc::now();

        let to_remove: Vec<LeaseId> = leases
            .iter()
            .filter(|(_, l)| l.revoked || now >= l.expires_at)
            .map(|(id, _)| id.clone())
            .collect();

        let count = to_remove.len();
        for id in to_remove {
            leases.remove(&id);
        }

        count
    }
}

/// Errors that can occur during lease operations.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("Lease not found")]
    NotFound,

    #[error("Lease has been revoked")]
    Revoked,

    #[error("Lease has expired")]
    Expired,

    #[error("Lease is not renewable")]
    NotRenewable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_id_generation() {
        let id1 = LeaseId::new();
        let id2 = LeaseId::new();
        assert_ne!(id1, id2);
        assert!(!id1.as_str().is_empty());
    }

    #[test]
    fn test_lease_config_builder() {
        let config = LeaseConfig::new()
            .with_default_ttl(Duration::minutes(30))
            .with_max_ttl(Duration::hours(4))
            .with_renewable(false);

        assert_eq!(config.default_ttl, Duration::minutes(30));
        assert_eq!(config.max_ttl, Duration::hours(4));
        assert!(!config.renewable);
    }

    #[test]
    fn test_lease_validity() {
        let lease = Lease {
            id: LeaseId::new(),
            secret_id: SecretId::new(),
            version: 1,
            client_id: "test-client".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            revoked: false,
            renewable: true,
            max_ttl: Some(Duration::hours(24)),
        };

        assert!(lease.is_valid());
        assert!(lease.remaining_seconds() > 0);
    }

    #[test]
    fn test_lease_expired() {
        let lease = Lease {
            id: LeaseId::new(),
            secret_id: SecretId::new(),
            version: 1,
            client_id: "test-client".to_string(),
            created_at: Utc::now() - Duration::hours(2),
            expires_at: Utc::now() - Duration::hours(1),
            revoked: false,
            renewable: true,
            max_ttl: Some(Duration::hours(24)),
        };

        assert!(!lease.is_valid());
        assert_eq!(lease.remaining_seconds(), 0);
    }

    #[test]
    fn test_lease_revoked() {
        let lease = Lease {
            id: LeaseId::new(),
            secret_id: SecretId::new(),
            version: 1,
            client_id: "test-client".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(1),
            revoked: true,
            renewable: true,
            max_ttl: Some(Duration::hours(24)),
        };

        assert!(!lease.is_valid());
        assert_eq!(lease.remaining_seconds(), 0);
    }

    #[tokio::test]
    async fn test_lease_manager_create() {
        let config = LeaseConfig::new().with_default_ttl(Duration::hours(1));
        let (manager, _rx) = LeaseManager::new(config);

        let lease = manager.create_lease(SecretId::new(), 1, "test-client".to_string(), None);

        assert!(lease.is_valid());
        assert!(lease.renewable);

        // Should be able to validate
        let validated = manager.validate_lease(&lease.id).unwrap();
        assert_eq!(validated.id, lease.id);
    }

    #[tokio::test]
    async fn test_lease_manager_custom_ttl() {
        let config = LeaseConfig::new()
            .with_default_ttl(Duration::hours(1))
            .with_max_ttl(Duration::hours(2));
        let (manager, _rx) = LeaseManager::new(config);

        // Custom TTL within limit
        let lease = manager.create_lease(
            SecretId::new(),
            1,
            "test-client".to_string(),
            Some(Duration::minutes(30)),
        );

        // TTL should be 30 minutes
        let remaining = lease.remaining_time();
        assert!(remaining <= Duration::minutes(30));
        assert!(remaining > Duration::minutes(29));
    }

    #[tokio::test]
    async fn test_lease_manager_ttl_capped() {
        let config = LeaseConfig::new()
            .with_default_ttl(Duration::hours(1))
            .with_max_ttl(Duration::hours(2));
        let (manager, _rx) = LeaseManager::new(config);

        // Request TTL exceeding max
        let lease = manager.create_lease(
            SecretId::new(),
            1,
            "test-client".to_string(),
            Some(Duration::hours(5)),
        );

        // TTL should be capped at 2 hours
        let remaining = lease.remaining_time();
        assert!(remaining <= Duration::hours(2));
    }

    #[tokio::test]
    async fn test_lease_manager_revoke() {
        let (manager, mut rx) = LeaseManager::new(LeaseConfig::default());

        let lease = manager.create_lease(SecretId::new(), 1, "test-client".to_string(), None);

        assert!(manager.validate_lease(&lease.id).is_ok());

        // Revoke
        manager.revoke_lease(&lease.id).unwrap();

        // Should no longer validate
        assert!(matches!(
            manager.validate_lease(&lease.id),
            Err(LeaseError::Revoked)
        ));

        // Should receive revocation event
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, LeaseEvent::Revoked(_)));
    }

    #[tokio::test]
    async fn test_lease_manager_renew() {
        let config = LeaseConfig::new()
            .with_default_ttl(Duration::hours(1))
            .with_max_ttl(Duration::hours(24));
        let (manager, _rx) = LeaseManager::new(config);

        let lease = manager.create_lease(
            SecretId::new(),
            1,
            "test-client".to_string(),
            Some(Duration::minutes(30)),
        );

        let original_expires = lease.expires_at;

        // Renew for another hour
        let renewed = manager
            .renew_lease(&lease.id, Some(Duration::hours(1)))
            .unwrap();

        assert!(renewed.expires_at > original_expires);
    }

    #[tokio::test]
    async fn test_lease_manager_renew_not_renewable() {
        let config = LeaseConfig::new().with_renewable(false);
        let (manager, _rx) = LeaseManager::new(config);

        let lease = manager.create_lease(SecretId::new(), 1, "test-client".to_string(), None);

        // Should fail to renew
        assert!(matches!(
            manager.renew_lease(&lease.id, None),
            Err(LeaseError::NotRenewable)
        ));
    }

    #[tokio::test]
    async fn test_lease_manager_revoke_all() {
        let (manager, _rx) = LeaseManager::new(LeaseConfig::default());

        let secret_id = SecretId::new();

        // Create multiple leases for the same secret
        manager.create_lease(secret_id.clone(), 1, "client1".to_string(), None);
        manager.create_lease(secret_id.clone(), 1, "client2".to_string(), None);
        manager.create_lease(secret_id.clone(), 2, "client1".to_string(), None);

        // And one for a different secret
        let other_secret = SecretId::new();
        let other_lease = manager.create_lease(other_secret, 1, "client1".to_string(), None);

        assert_eq!(manager.active_lease_count(), 4);

        // Revoke all for the first secret
        let revoked = manager.revoke_all(&secret_id);
        assert_eq!(revoked, 3);

        // Other secret's lease should still be valid
        assert!(manager.validate_lease(&other_lease.id).is_ok());
        assert_eq!(manager.active_lease_count(), 1);
    }

    #[tokio::test]
    async fn test_lease_manager_list_client_leases() {
        let (manager, _rx) = LeaseManager::new(LeaseConfig::default());

        let secret1 = SecretId::new();
        let secret2 = SecretId::new();

        manager.create_lease(secret1.clone(), 1, "client1".to_string(), None);
        manager.create_lease(secret1.clone(), 2, "client1".to_string(), None);
        manager.create_lease(secret2.clone(), 1, "client2".to_string(), None);

        let client1_leases = manager.list_client_leases("client1");
        assert_eq!(client1_leases.len(), 2);

        let client2_leases = manager.list_client_leases("client2");
        assert_eq!(client2_leases.len(), 1);

        let client3_leases = manager.list_client_leases("client3");
        assert!(client3_leases.is_empty());
    }

    #[tokio::test]
    async fn test_lease_manager_cleanup_expired() {
        let config = LeaseConfig::new().with_default_ttl(Duration::milliseconds(10));
        let (manager, _rx) = LeaseManager::new(config);

        // Create a lease with very short TTL
        let _lease = manager.create_lease(
            SecretId::new(),
            1,
            "test-client".to_string(),
            Some(Duration::milliseconds(1)),
        );

        // Wait for expiration
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cleanup should remove the expired lease
        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.active_lease_count(), 0);
    }
}
