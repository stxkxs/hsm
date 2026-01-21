// Rate limiting module to prevent DoS attacks
// Uses token bucket algorithm with per-identity and per-namespace limits

use crate::error::{AuthError, Result};
use crate::mtls::ClientIdentity;
use dashmap::DashMap;
use std::num::NonZeroU32;
use std::sync::Arc;

// Use governor for rate limiting with token bucket algorithm
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorLimiter,
};

/// Type alias for the governor rate limiter to reduce type complexity
type BucketLimiter = GovernorLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Type alias for a map of string keys to rate limiters
type LimiterMap = DashMap<String, Arc<BucketLimiter>>;

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per second for global limit
    pub global_rps: u32,
    /// Requests per second per identity
    pub per_identity_rps: u32,
    /// Requests per second per namespace
    pub per_namespace_rps: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_rps: 10000,       // 10k RPS globally
            per_identity_rps: 100,   // 100 RPS per client
            per_namespace_rps: 1000, // 1k RPS per namespace
        }
    }
}

/// Rate limiter for authentication and authorization operations
pub struct RateLimiter {
    /// Global rate limiter
    global: Arc<BucketLimiter>,

    /// Per-identity rate limiters (keyed by common name)
    per_identity: Arc<LimiterMap>,

    /// Per-namespace rate limiters
    per_namespace: Arc<LimiterMap>,

    /// Configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter with default configuration
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a new rate limiter with custom configuration
    pub fn with_config(config: RateLimitConfig) -> Self {
        let global_quota = Quota::per_second(NonZeroU32::new(config.global_rps).unwrap());
        let global = Arc::new(GovernorLimiter::direct(global_quota));

        Self {
            global,
            per_identity: Arc::new(DashMap::new()),
            per_namespace: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Check rate limit for a request
    /// Returns Ok(()) if allowed, Err if rate limit exceeded
    pub fn check(&self, identity: &ClientIdentity, namespace: &str) -> Result<()> {
        // 1. Check global limit
        if self.global.check().is_err() {
            metrics::counter!("auth.rate_limit.global_exceeded").increment(1);
            return Err(AuthError::RateLimitExceeded("global".to_string()));
        }

        // 2. Check per-identity limit
        let identity_limiter = self
            .per_identity
            .entry(identity.common_name.clone())
            .or_insert_with(|| {
                let quota =
                    Quota::per_second(NonZeroU32::new(self.config.per_identity_rps).unwrap());
                Arc::new(GovernorLimiter::direct(quota))
            });

        if identity_limiter.check().is_err() {
            metrics::counter!("auth.rate_limit.identity_exceeded").increment(1);
            return Err(AuthError::RateLimitExceeded(format!(
                "identity: {}",
                identity.common_name
            )));
        }

        // 3. Check per-namespace limit
        let namespace_limiter = self
            .per_namespace
            .entry(namespace.to_string())
            .or_insert_with(|| {
                let quota =
                    Quota::per_second(NonZeroU32::new(self.config.per_namespace_rps).unwrap());
                Arc::new(GovernorLimiter::direct(quota))
            });

        if namespace_limiter.check().is_err() {
            metrics::counter!("auth.rate_limit.namespace_exceeded").increment(1);
            return Err(AuthError::RateLimitExceeded(format!(
                "namespace: {}",
                namespace
            )));
        }

        metrics::counter!("auth.rate_limit.allowed").increment(1);
        Ok(())
    }

    /// Check global rate limit only
    pub fn check_global(&self) -> Result<()> {
        if self.global.check().is_err() {
            metrics::counter!("auth.rate_limit.global_exceeded").increment(1);
            return Err(AuthError::RateLimitExceeded("global".to_string()));
        }
        Ok(())
    }

    /// Check per-identity rate limit only
    pub fn check_identity(&self, identity: &ClientIdentity) -> Result<()> {
        let identity_limiter = self
            .per_identity
            .entry(identity.common_name.clone())
            .or_insert_with(|| {
                let quota =
                    Quota::per_second(NonZeroU32::new(self.config.per_identity_rps).unwrap());
                Arc::new(GovernorLimiter::direct(quota))
            });

        if identity_limiter.check().is_err() {
            metrics::counter!("auth.rate_limit.identity_exceeded").increment(1);
            return Err(AuthError::RateLimitExceeded(format!(
                "identity: {}",
                identity.common_name
            )));
        }
        Ok(())
    }

    /// Check per-namespace rate limit only
    pub fn check_namespace(&self, namespace: &str) -> Result<()> {
        let namespace_limiter = self
            .per_namespace
            .entry(namespace.to_string())
            .or_insert_with(|| {
                let quota =
                    Quota::per_second(NonZeroU32::new(self.config.per_namespace_rps).unwrap());
                Arc::new(GovernorLimiter::direct(quota))
            });

        if namespace_limiter.check().is_err() {
            metrics::counter!("auth.rate_limit.namespace_exceeded").increment(1);
            return Err(AuthError::RateLimitExceeded(format!(
                "namespace: {}",
                namespace
            )));
        }
        Ok(())
    }

    /// Get current configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Reset rate limits (for testing)
    #[cfg(test)]
    pub fn reset(&self) {
        self.per_identity.clear();
        self.per_namespace.clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;

    fn create_test_identity(cn: &str, namespace: &str) -> ClientIdentity {
        ClientIdentity::new(
            cn.to_string(),
            None,
            namespace.to_string(),
            vec![Role::User],
            "123456".to_string(),
        )
    }

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.config().global_rps, 10000);
        assert_eq!(limiter.config().per_identity_rps, 100);
        assert_eq!(limiter.config().per_namespace_rps, 1000);
    }

    #[test]
    fn test_rate_limiter_allows_normal_traffic() {
        let limiter = RateLimiter::new();
        let identity = create_test_identity("client1", "ns1");

        // Should allow a reasonable number of requests
        for _ in 0..10 {
            assert!(limiter.check(&identity, "ns1").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_excessive_traffic() {
        let config = RateLimitConfig {
            global_rps: 1000,
            per_identity_rps: 5, // Very low limit for testing
            per_namespace_rps: 100,
        };
        let limiter = RateLimiter::with_config(config);
        let identity = create_test_identity("client1", "ns1");

        // First few requests should succeed
        for _ in 0..5 {
            let _ = limiter.check(&identity, "ns1");
        }

        // Additional requests should be rate limited
        let result = limiter.check(&identity, "ns1");
        assert!(result.is_err());

        if let Err(AuthError::RateLimitExceeded(msg)) = result {
            assert!(msg.contains("identity"));
        } else {
            panic!("Expected rate limit error");
        }
    }

    #[test]
    fn test_global_rate_limit() {
        let limiter = RateLimiter::new();

        // Should allow requests under global limit
        for _ in 0..10 {
            assert!(limiter.check_global().is_ok());
        }
    }

    #[test]
    fn test_per_namespace_isolation() {
        let limiter = RateLimiter::new();
        let identity1 = create_test_identity("client1", "ns1");
        let identity2 = create_test_identity("client2", "ns2");

        // Requests to different namespaces should not interfere
        assert!(limiter.check(&identity1, "ns1").is_ok());
        assert!(limiter.check(&identity2, "ns2").is_ok());
    }
}
