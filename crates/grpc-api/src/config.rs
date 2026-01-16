use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server bind address
    pub bind_address: String,

    /// HTTP/2 settings
    pub http2: Http2Config,

    /// TLS configuration
    pub tls: Option<TlsConfig>,

    /// Connection limits
    pub limits: LimitsConfig,

    /// Cache configuration
    pub cache: CacheConfig,

    /// Tracing configuration
    pub tracing: TracingConfig,

    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:50051".to_string(),
            http2: Http2Config::default(),
            tls: None,
            limits: LimitsConfig::default(),
            cache: CacheConfig::default(),
            tracing: TracingConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

/// HTTP/2 configuration optimized for high performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Config {
    /// HTTP/2 keepalive interval (seconds)
    pub keepalive_interval_secs: u64,

    /// HTTP/2 keepalive timeout (seconds)
    pub keepalive_timeout_secs: u64,

    /// Enable HTTP/2 adaptive window sizing
    pub adaptive_window: bool,

    /// Initial connection window size (bytes)
    pub initial_connection_window_size: u32,

    /// Initial stream window size (bytes)
    pub initial_stream_window_size: u32,

    /// Maximum concurrent streams per connection
    pub max_concurrent_streams: u32,

    /// Enable TCP_NODELAY
    pub tcp_nodelay: bool,

    /// Maximum frame size (bytes)
    pub max_frame_size: u32,

    /// Maximum message size for decoding (bytes)
    pub max_decoding_message_size: usize,

    /// Maximum message size for encoding (bytes)
    pub max_encoding_message_size: usize,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            keepalive_interval_secs: 30,
            keepalive_timeout_secs: 10,
            adaptive_window: true,
            initial_connection_window_size: 1024 * 1024, // 1MB
            initial_stream_window_size: 1024 * 1024,     // 1MB
            max_concurrent_streams: 1000,
            tcp_nodelay: true,
            max_frame_size: 1024 * 1024,                // 1MB
            max_decoding_message_size: 8 * 1024 * 1024, // 8MB
            max_encoding_message_size: 8 * 1024 * 1024, // 8MB
        }
    }
}

/// TLS configuration for mTLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Server certificate path
    pub cert_path: PathBuf,

    /// Server private key path
    pub key_path: PathBuf,

    /// Client CA certificate path (for mTLS)
    pub client_ca_path: Option<PathBuf>,

    /// Require client certificates
    pub require_client_cert: bool,
}

/// Connection and request limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,

    /// Request timeout (seconds)
    pub request_timeout_secs: u64,

    /// Maximum batch size
    pub max_batch_size: usize,

    /// Maximum message size (bytes)
    pub max_message_size: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            request_timeout_secs: 30,
            max_batch_size: 1000,
            max_message_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,

    /// GetKey cache capacity
    pub get_key_capacity: usize,

    /// GetKey cache TTL (seconds)
    pub get_key_ttl_secs: u64,

    /// Verify cache capacity
    pub verify_capacity: usize,

    /// Verify cache TTL (seconds)
    pub verify_ttl_secs: u64,

    /// Cache cleanup interval (seconds)
    pub cleanup_interval_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            get_key_capacity: 10000,
            get_key_ttl_secs: 300, // 5 minutes
            verify_capacity: 50000,
            verify_ttl_secs: 60,       // 1 minute
            cleanup_interval_secs: 60, // 1 minute
        }
    }
}

/// Distributed tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    pub enabled: bool,

    /// OTLP endpoint for trace export
    pub otlp_endpoint: Option<String>,

    /// Service name for tracing
    pub service_name: String,

    /// Sampling rate (0.0 to 1.0)
    pub sampling_rate: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: None,
            service_name: "hsm-grpc-api".to_string(),
            sampling_rate: 1.0,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breakers
    pub enabled: bool,

    /// Failure threshold before opening circuit
    pub failure_threshold: u64,

    /// Success threshold before closing circuit
    pub success_threshold: u64,

    /// Timeout before attempting to close circuit (seconds)
    pub timeout_secs: u64,

    /// Maximum number of concurrent requests when half-open
    pub half_open_max_requests: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            success_threshold: 2,
            timeout_secs: 60,
            half_open_max_requests: 1,
        }
    }
}

impl Http2Config {
    pub fn keepalive_interval(&self) -> Duration {
        Duration::from_secs(self.keepalive_interval_secs)
    }

    pub fn keepalive_timeout(&self) -> Duration {
        Duration::from_secs(self.keepalive_timeout_secs)
    }
}

impl LimitsConfig {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}

impl CacheConfig {
    pub fn get_key_ttl(&self) -> Duration {
        Duration::from_secs(self.get_key_ttl_secs)
    }

    pub fn verify_ttl(&self) -> Duration {
        Duration::from_secs(self.verify_ttl_secs)
    }

    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.cleanup_interval_secs)
    }
}

impl CircuitBreakerConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0:50051");
        assert!(config.cache.enabled);
        assert!(config.circuit_breaker.enabled);
    }

    #[test]
    fn test_http2_config_defaults() {
        let config = Http2Config::default();
        assert_eq!(config.keepalive_interval_secs, 30);
        assert_eq!(config.max_concurrent_streams, 1000);
        assert!(config.adaptive_window);
        assert!(config.tcp_nodelay);
    }

    #[test]
    fn test_limits_config_defaults() {
        let config = LimitsConfig::default();
        assert_eq!(config.max_connections, 10000);
        assert_eq!(config.request_timeout_secs, 30);
        assert_eq!(config.max_batch_size, 1000);
    }

    #[test]
    fn test_cache_config_defaults() {
        let config = CacheConfig::default();
        assert!(config.enabled);
        assert_eq!(config.get_key_capacity, 10000);
        assert_eq!(config.verify_capacity, 50000);
    }

    #[test]
    fn test_duration_conversions() {
        let http2_config = Http2Config::default();
        assert_eq!(http2_config.keepalive_interval(), Duration::from_secs(30));

        let limits_config = LimitsConfig::default();
        assert_eq!(limits_config.request_timeout(), Duration::from_secs(30));

        let cache_config = CacheConfig::default();
        assert_eq!(cache_config.get_key_ttl(), Duration::from_secs(300));
    }
}
