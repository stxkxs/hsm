//! JWKS caching for JWT validation

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// JWKS cache errors
#[derive(Debug, Error)]
pub enum JwksCacheError {
    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(String),
    /// Parse error
    #[error("Parse error: {0}")]
    Parse(String),
}

/// JSON Web Key Set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    /// List of keys
    pub keys: Vec<serde_json::Value>,
}

/// Cached JWKS entry
#[derive(Debug, Clone)]
struct CachedJwks {
    /// The JWKS
    jwks: Jwks,
    /// Fetch timestamp
    #[allow(dead_code)]
    fetched_at: DateTime<Utc>,
    /// Expiration
    expires_at: DateTime<Utc>,
}

/// JWKS cache for efficient key lookups
pub struct JwksCache {
    /// Cache by URI
    cache: DashMap<String, CachedJwks>,
    /// Default TTL
    default_ttl: Duration,
    /// Minimum TTL (to prevent cache stampede)
    min_ttl: Duration,
    /// HTTP client
    client: reqwest::Client,
    /// Refresh lock to prevent concurrent fetches
    refresh_locks: DashMap<String, Arc<RwLock<()>>>,
}

impl JwksCache {
    /// Create a new JWKS cache
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            default_ttl: Duration::minutes(15),
            min_ttl: Duration::minutes(1),
            client: reqwest::Client::new(),
            refresh_locks: DashMap::new(),
        }
    }

    /// Create with custom TTL
    pub fn with_ttl(default_ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            default_ttl,
            min_ttl: Duration::minutes(1),
            client: reqwest::Client::new(),
            refresh_locks: DashMap::new(),
        }
    }

    /// Get JWKS for a URI
    pub async fn get_jwks(&self, uri: &str) -> Result<Jwks, JwksCacheError> {
        // Check cache first
        if let Some(cached) = self.cache.get(uri) {
            if Utc::now() < cached.expires_at {
                return Ok(cached.jwks.clone());
            }
        }

        // Fetch fresh JWKS
        self.refresh_jwks(uri).await
    }

    /// Get a specific key by ID
    pub async fn get_key(
        &self,
        uri: &str,
        kid: &str,
    ) -> Result<Option<serde_json::Value>, JwksCacheError> {
        let jwks = self.get_jwks(uri).await?;

        let key = jwks.keys.iter().find(|k| {
            k.get("kid")
                .and_then(|v| v.as_str())
                .map(|k| k == kid)
                .unwrap_or(false)
        });

        Ok(key.cloned())
    }

    /// Refresh JWKS from the provider
    async fn refresh_jwks(&self, uri: &str) -> Result<Jwks, JwksCacheError> {
        // Get or create refresh lock for this URI
        let lock = self
            .refresh_locks
            .entry(uri.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone();

        // Acquire write lock
        let _guard = lock.write().await;

        // Double-check cache (another thread might have refreshed)
        if let Some(cached) = self.cache.get(uri) {
            if Utc::now() < cached.expires_at - self.min_ttl {
                return Ok(cached.jwks.clone());
            }
        }

        // Fetch from URI
        let response = self
            .client
            .get(uri)
            .send()
            .await
            .map_err(|e: reqwest::Error| JwksCacheError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(JwksCacheError::Http(format!("HTTP {}: {}", status, text)));
        }

        let jwks: Jwks = response
            .json::<Jwks>()
            .await
            .map_err(|e: reqwest::Error| JwksCacheError::Parse(e.to_string()))?;

        // Cache the result
        let now = Utc::now();
        self.cache.insert(
            uri.to_string(),
            CachedJwks {
                jwks: jwks.clone(),
                fetched_at: now,
                expires_at: now + self.default_ttl,
            },
        );

        Ok(jwks)
    }

    /// Force refresh JWKS (bypasses cache)
    pub async fn force_refresh(&self, uri: &str) -> Result<Jwks, JwksCacheError> {
        self.cache.remove(uri);
        self.refresh_jwks(uri).await
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let total = self.cache.len();
        let now = Utc::now();
        let expired = self.cache.iter().filter(|e| e.expires_at < now).count();

        CacheStats {
            total_entries: total,
            expired_entries: expired,
            valid_entries: total - expired,
        }
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) {
        let now = Utc::now();
        self.cache.retain(|_, v| v.expires_at > now);
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total entries in cache
    pub total_entries: usize,
    /// Expired entries
    pub expired_entries: usize,
    /// Valid entries
    pub valid_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = JwksCache::new();
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 0);
    }

    #[test]
    fn test_cache_with_ttl() {
        let cache = JwksCache::with_ttl(Duration::hours(1));
        assert_eq!(cache.default_ttl, Duration::hours(1));
    }

    #[test]
    fn test_cache_clear() {
        let cache = JwksCache::new();
        // Manually insert a test entry
        cache.cache.insert(
            "test".to_string(),
            CachedJwks {
                jwks: Jwks { keys: vec![] },
                fetched_at: Utc::now(),
                expires_at: Utc::now() + Duration::hours(1),
            },
        );

        assert_eq!(cache.stats().total_entries, 1);
        cache.clear();
        assert_eq!(cache.stats().total_entries, 0);
    }
}
