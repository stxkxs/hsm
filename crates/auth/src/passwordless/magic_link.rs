//! Magic Link Authentication
//!
//! Provides email-based passwordless authentication via one-time magic links.
//! Links are time-limited and single-use for security.

use crate::error::{AuthError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Magic link token (sent to user via email)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MagicLinkToken(String);

impl MagicLinkToken {
    /// Create a new magic link token
    fn new() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        Self(hex::encode(bytes))
    }

    /// Get the token value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the token for storage
    fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl std::fmt::Debug for MagicLinkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MagicLinkToken(***)")
    }
}

/// Magic link stored in the system
#[derive(Debug, Clone)]
pub struct MagicLink {
    /// Token hash (not the plaintext token)
    pub token_hash: String,
    /// Email address
    pub email: String,
    /// User ID (if known)
    pub user_id: Option<String>,
    /// Creation time
    pub created_at: Instant,
    /// Expiration duration
    pub expires_in: Duration,
    /// Whether this link has been used
    pub used: bool,
    /// IP address of requester
    pub request_ip: Option<String>,
    /// User agent of requester
    pub user_agent: Option<String>,
    /// Custom data to pass through
    pub extra_data: Option<String>,
}

impl MagicLink {
    /// Check if the magic link has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.expires_in
    }

    /// Check if the magic link is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.used
    }

    /// Time remaining until expiration
    pub fn time_remaining(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed > self.expires_in {
            None
        } else {
            Some(self.expires_in - elapsed)
        }
    }
}

/// Request to send a magic link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkRequest {
    /// Email address to send link to
    pub email: String,
    /// Optional user ID
    pub user_id: Option<String>,
    /// Redirect URL after verification
    pub redirect_url: Option<String>,
    /// Custom data to include
    pub extra_data: Option<String>,
}

/// Magic link verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkVerification {
    /// Email address that was verified
    pub email: String,
    /// User ID (if provided during request)
    pub user_id: Option<String>,
    /// Extra data from the request
    pub extra_data: Option<String>,
    /// Time the link was created
    pub link_created_at: i64,
}

/// Magic link configuration
#[derive(Debug, Clone)]
pub struct MagicLinkConfig {
    /// Link expiration time
    pub expires_in: Duration,
    /// Maximum number of pending links per email
    pub max_pending_per_email: usize,
    /// Rate limit: minimum time between requests for same email
    pub rate_limit_interval: Duration,
    /// Base URL for magic links
    pub base_url: String,
}

impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::from_secs(900), // 15 minutes
            max_pending_per_email: 3,
            rate_limit_interval: Duration::from_secs(60), // 1 minute
            base_url: "https://example.com/auth/magic-link/verify".to_string(),
        }
    }
}

/// Magic link manager
pub struct MagicLinkManager {
    /// Configuration
    config: MagicLinkConfig,
    /// Pending magic links (token_hash -> MagicLink)
    pending: DashMap<String, MagicLink>,
    /// Last request time per email (for rate limiting)
    last_request: DashMap<String, Instant>,
}

impl MagicLinkManager {
    /// Create a new magic link manager
    pub fn new(config: MagicLinkConfig) -> Self {
        Self {
            config,
            pending: DashMap::new(),
            last_request: DashMap::new(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(MagicLinkConfig::default())
    }

    /// Set base URL
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.config.base_url = base_url.into();
        self
    }

    /// Create a new magic link
    pub fn create_magic_link(
        &self,
        request: MagicLinkRequest,
        request_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(MagicLinkToken, String)> {
        let email = request.email.to_lowercase();

        // Rate limiting
        if let Some(last) = self.last_request.get(&email) {
            if last.elapsed() < self.config.rate_limit_interval {
                return Err(AuthError::RateLimitExceeded(format!(
                    "Please wait {} seconds before requesting another magic link",
                    (self.config.rate_limit_interval - last.elapsed()).as_secs()
                )));
            }
        }

        // Check pending link count
        let pending_count = self
            .pending
            .iter()
            .filter(|entry| entry.value().email == email && entry.value().is_valid())
            .count();

        if pending_count >= self.config.max_pending_per_email {
            return Err(AuthError::RateLimitExceeded(
                "Too many pending magic links for this email".to_string(),
            ));
        }

        // Generate token
        let token = MagicLinkToken::new();
        let token_hash = token.hash();

        // Create magic link
        let magic_link = MagicLink {
            token_hash: token_hash.clone(),
            email: email.clone(),
            user_id: request.user_id,
            created_at: Instant::now(),
            expires_in: self.config.expires_in,
            used: false,
            request_ip,
            user_agent,
            extra_data: request.extra_data,
        };

        // Store
        self.pending.insert(token_hash.clone(), magic_link);
        self.last_request.insert(email, Instant::now());

        // Build verification URL
        let verification_url = format!("{}?token={}", self.config.base_url, token.as_str());

        Ok((token, verification_url))
    }

    /// Verify a magic link token
    pub fn verify(&self, token: &str) -> Result<MagicLinkVerification> {
        // Hash the provided token
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        // Find and validate the magic link
        let mut magic_link = self.pending.get_mut(&token_hash).ok_or_else(|| {
            AuthError::InvalidSession("Invalid or expired magic link".to_string())
        })?;

        if magic_link.used {
            return Err(AuthError::InvalidSession(
                "Magic link already used".to_string(),
            ));
        }

        if magic_link.is_expired() {
            return Err(AuthError::SessionExpired);
        }

        // Mark as used
        magic_link.used = true;

        // Build verification result
        let created_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - magic_link.created_at.elapsed().as_secs() as i64;

        Ok(MagicLinkVerification {
            email: magic_link.email.clone(),
            user_id: magic_link.user_id.clone(),
            extra_data: magic_link.extra_data.clone(),
            link_created_at: created_timestamp,
        })
    }

    /// Invalidate all magic links for an email
    pub fn invalidate_for_email(&self, email: &str) -> usize {
        let email = email.to_lowercase();
        let mut count = 0;

        self.pending.iter_mut().for_each(|mut entry| {
            if entry.value().email == email && !entry.value().used {
                entry.value_mut().used = true;
                count += 1;
            }
        });

        count
    }

    /// Cleanup expired and used magic links
    pub fn cleanup(&self) -> usize {
        let before = self.pending.len();
        self.pending
            .retain(|_, link| !link.used && !link.is_expired());
        before - self.pending.len()
    }

    /// Get pending link count for an email
    pub fn pending_count(&self, email: &str) -> usize {
        let email = email.to_lowercase();
        self.pending
            .iter()
            .filter(|entry| entry.value().email == email && entry.value().is_valid())
            .count()
    }

    /// Get total pending link count
    pub fn total_pending(&self) -> usize {
        self.pending
            .iter()
            .filter(|entry| entry.value().is_valid())
            .count()
    }
}

impl Default for MagicLinkManager {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_magic_link() {
        let manager =
            MagicLinkManager::with_defaults().with_base_url("https://auth.example.com/verify");

        let request = MagicLinkRequest {
            email: "user@example.com".to_string(),
            user_id: Some("user-123".to_string()),
            redirect_url: None,
            extra_data: None,
        };

        let (token, url) = manager.create_magic_link(request, None, None).unwrap();

        assert!(!token.as_str().is_empty());
        assert!(url.contains("auth.example.com"));
        assert!(url.contains(token.as_str()));
    }

    #[test]
    fn test_verify_magic_link() {
        let manager = MagicLinkManager::with_defaults();

        let request = MagicLinkRequest {
            email: "user@example.com".to_string(),
            user_id: None,
            redirect_url: None,
            extra_data: Some("test-data".to_string()),
        };

        let (token, _) = manager.create_magic_link(request, None, None).unwrap();

        // Verify
        let verification = manager.verify(token.as_str()).unwrap();
        assert_eq!(verification.email, "user@example.com");
        assert_eq!(verification.extra_data, Some("test-data".to_string()));

        // Second verification should fail
        assert!(manager.verify(token.as_str()).is_err());
    }

    #[test]
    fn test_rate_limiting() {
        let config = MagicLinkConfig {
            rate_limit_interval: Duration::from_secs(60),
            ..Default::default()
        };
        let manager = MagicLinkManager::new(config);

        let request = MagicLinkRequest {
            email: "user@example.com".to_string(),
            user_id: None,
            redirect_url: None,
            extra_data: None,
        };

        // First request succeeds
        assert!(manager
            .create_magic_link(request.clone(), None, None)
            .is_ok());

        // Second request should be rate limited
        let result = manager.create_magic_link(request, None, None);
        assert!(matches!(result, Err(AuthError::RateLimitExceeded(_))));
    }

    #[test]
    fn test_invalidate_for_email() {
        let config = MagicLinkConfig {
            rate_limit_interval: Duration::from_millis(0),
            ..Default::default()
        };
        let manager = MagicLinkManager::new(config);

        // Create multiple links
        for _ in 0..3 {
            let request = MagicLinkRequest {
                email: "user@example.com".to_string(),
                user_id: None,
                redirect_url: None,
                extra_data: None,
            };
            manager.create_magic_link(request, None, None).unwrap();
        }

        assert_eq!(manager.pending_count("user@example.com"), 3);

        // Invalidate
        let count = manager.invalidate_for_email("user@example.com");
        assert_eq!(count, 3);
        assert_eq!(manager.pending_count("user@example.com"), 0);
    }

    #[test]
    fn test_cleanup() {
        let config = MagicLinkConfig {
            expires_in: Duration::from_millis(1),
            rate_limit_interval: Duration::from_millis(0),
            ..Default::default()
        };
        let manager = MagicLinkManager::new(config);

        let request = MagicLinkRequest {
            email: "user@example.com".to_string(),
            user_id: None,
            redirect_url: None,
            extra_data: None,
        };
        manager.create_magic_link(request, None, None).unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        let cleaned = manager.cleanup();
        assert_eq!(cleaned, 1);
    }
}
