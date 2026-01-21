//! REST API Configuration
//!
//! Configuration options for the REST API server.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// REST API server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestApiConfig {
    /// Server bind address (default: 127.0.0.1:8080)
    pub bind_addr: SocketAddr,

    /// CORS configuration
    pub cors: CorsConfig,

    /// Request limits
    pub limits: RequestLimits,

    /// TLS configuration (optional)
    pub tls: Option<TlsConfig>,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins (default: none - must be explicitly configured)
    pub allowed_origins: Vec<String>,

    /// Allowed methods (default: GET, POST, DELETE)
    pub allowed_methods: Vec<String>,

    /// Allowed headers
    pub allowed_headers: Vec<String>,

    /// Whether to allow credentials
    pub allow_credentials: bool,

    /// Max age for preflight cache (seconds)
    pub max_age_seconds: u64,
}

/// Request limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLimits {
    /// Maximum request body size in bytes (default: 1MB)
    pub max_body_size: usize,

    /// Request timeout in seconds (default: 30)
    pub request_timeout_seconds: u64,

    /// Maximum concurrent requests (default: 1000)
    pub max_concurrent_requests: usize,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to server certificate
    pub cert_path: String,

    /// Path to server private key
    pub key_path: String,

    /// Path to CA certificate for mTLS (optional)
    pub ca_cert_path: Option<String>,

    /// Require client certificates (mTLS)
    pub require_client_cert: bool,
}

impl Default for RestApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".parse().expect("valid default address"),
            cors: CorsConfig::default(),
            limits: RequestLimits::default(),
            tls: None,
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            // No origins allowed by default - must be explicitly configured
            allowed_origins: vec![],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Authorization".to_string(),
                "Content-Type".to_string(),
                "X-Request-ID".to_string(),
            ],
            allow_credentials: false,
            max_age_seconds: 3600,
        }
    }
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_body_size: 1024 * 1024, // 1MB
            request_timeout_seconds: 30,
            max_concurrent_requests: 1000,
        }
    }
}

impl RestApiConfig {
    /// Create a development configuration with permissive settings
    ///
    /// **WARNING**: Do not use in production!
    pub fn development() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".parse().expect("valid address"),
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allow_credentials: true,
                ..Default::default()
            },
            limits: RequestLimits::default(),
            tls: None,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check for wildcard origins in production
        if self.cors.allowed_origins.contains(&"*".to_string()) && self.tls.is_some() {
            return Err("Wildcard CORS origin should not be used with TLS in production".to_string());
        }

        // Ensure reasonable limits
        if self.limits.max_body_size > 100 * 1024 * 1024 {
            return Err("Max body size exceeds 100MB limit".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RestApiConfig::default();
        assert_eq!(config.bind_addr.port(), 8080);
        assert!(config.cors.allowed_origins.is_empty());
    }

    #[test]
    fn test_development_config() {
        let config = RestApiConfig::development();
        assert!(config.cors.allowed_origins.contains(&"*".to_string()));
    }

    #[test]
    fn test_config_validation() {
        let config = RestApiConfig::default();
        assert!(config.validate().is_ok());
    }
}
