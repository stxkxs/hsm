//! gRPC API Server for Hardware Security Module (HSM)
//!
//! This crate provides a production-grade gRPC API server for HSM cryptographic operations.
//! It handles key management, signing, verification, encryption, and decryption through a
//! secure, performant, and fault-tolerant interface.
//!
//! # Architecture
//!
//! The API server is built on several key components:
//!
//! - **Protocol Buffers**: Type-safe API definitions (see [`proto::hsm`])
//! - **HTTP/2 Transport**: High-performance gRPC with optimized flow control
//! - **TLS/mTLS**: Secure transport with optional mutual authentication
//! - **Middleware Chain**: Authentication, logging, and metrics collection
//! - **Circuit Breaker**: Fault tolerance to prevent cascading failures
//! - **Response Caching**: LRU caching for read-heavy operations
//! - **Request Validation**: Security limits to prevent DoS attacks
//!
//! # Middleware Chain
//!
//! Requests flow through the following middleware layers:
//!
//! ```text
//! ┌─────────────────────┐
//! │   Client Request    │
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │  1. TLS/mTLS Auth   │  ◄─── Transport security
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │ 2. Request Logging  │  ◄─── Structured logging with tracing
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │ 3. Metrics          │  ◄─── Operation counters & latency
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │ 4. Authentication   │  ◄─── Session validation (TODO)
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │ 5. Validation       │  ◄─── Input sanitization & size limits
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │ 6. Circuit Breaker  │  ◄─── Fault tolerance
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │ 7. Cache Lookup     │  ◄─── Response cache (if applicable)
//! └──────────┬──────────┘
//!            ▼
//! ┌─────────────────────┐
//! │   Business Logic    │  ◄─── Crypto operations
//! └─────────────────────┘
//! ```
//!
//! # Circuit Breaker Pattern
//!
//! The circuit breaker protects downstream services from cascading failures:
//!
//! - **Closed State**: Normal operation, all requests pass through
//! - **Open State**: After threshold failures, reject requests immediately
//! - **Half-Open State**: After timeout, allow limited requests to test recovery
//!
//! Configuration:
//! - `failure_threshold`: Consecutive failures before opening (default: 5)
//! - `success_threshold`: Successes needed to close from half-open (default: 2)
//! - `timeout`: Time before attempting recovery (default: 60s)
//! - `half_open_max_requests`: Concurrent requests in half-open state (default: 1)
//!
//! See [`circuit_breaker`] module for details.
//!
//! # Security Features
//!
//! ## TLS Configuration
//!
//! The server supports both TLS and mutual TLS (mTLS):
//!
//! ```text
//! TLS Mode:
//! - Server presents certificate to client
//! - Client verifies server identity
//! - Traffic encrypted but client not authenticated
//!
//! mTLS Mode:
//! - Server presents certificate to client
//! - Client presents certificate to server
//! - Both parties verify each other's identity
//! - Used for service-to-service authentication
//! ```
//!
//! Configuration options (see [`config::TlsConfig`]):
//! - `cert_path`: Server certificate (PEM format)
//! - `key_path`: Server private key (PEM format)
//! - `client_ca_path`: CA certificate for client verification (optional, enables mTLS)
//! - `require_client_cert`: Enforce client certificate validation
//!
//! ## Input Validation
//!
//! All inputs are validated before processing (see [`validation`] module):
//!
//! - **Key ID size**: Max 256 bytes (prevents memory exhaustion)
//! - **Namespace size**: Max 256 bytes, alphanumeric + hyphens/underscores only
//! - **Message size**: Max 10MB (prevents DoS via large messages)
//! - **Batch size**: Max 1000 items (prevents unbounded processing)
//! - **Metadata**: Max 100 entries, 256-byte keys, 1KB values
//!
//! # Performance Optimizations
//!
//! ## HTTP/2 Configuration
//!
//! Optimized for high throughput and low latency:
//!
//! - **Keepalive**: Detects dead connections (interval: 30s, timeout: 10s)
//! - **Adaptive Window**: Automatic flow control tuning
//! - **Initial Windows**: Connection: 1MB, Stream: 1MB (high throughput)
//! - **Max Concurrent Streams**: 100 (prevents resource exhaustion)
//! - **TCP_NODELAY**: Disabled Nagle's algorithm for low latency
//! - **Max Frame Size**: 16KB (optimal for most networks)
//!
//! See [`config::Http2Config`] for tuning options.
//!
//! ## Response Caching
//!
//! LRU caching for frequently accessed operations:
//!
//! - **GetKey**: Cache key metadata (default: 10,000 entries)
//! - **Verify**: Cache signature verification results (default: 5,000 entries)
//! - **TTL**: 5 minutes for all cached responses
//! - **Automatic Cleanup**: Background task removes expired entries
//!
//! See [`cache`] module for details.
//!
//! # Examples
//!
//! ## Basic Server Setup
//!
//! ```no_run
//! use grpc_api::{config::ServerConfig, server::create_server};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create server with default configuration
//!     let config = ServerConfig::default();
//!     let server = create_server(&config)?;
//!
//!     // Bind and serve
//!     let addr: std::net::SocketAddr = "0.0.0.0:50051".parse()?;
//!     println!("HSM gRPC server listening on {}", addr);
//!
//!     // Note: In production, you would add your service implementations here
//!     // server.add_service(hsm_service).serve(addr).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Server with TLS
//!
//! ```no_run
//! use grpc_api::config::{ServerConfig, TlsConfig};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ServerConfig {
//!     tls: Some(TlsConfig {
//!         cert_path: "/path/to/server.crt".into(),
//!         key_path: "/path/to/server.key".into(),
//!         client_ca_path: None, // No mTLS
//!         require_client_cert: false,
//!     }),
//!     ..Default::default()
//! };
//! # Ok(())
//! # }
//! ```
//!
//! ## Server with mTLS (Mutual Authentication)
//!
//! ```no_run
//! use grpc_api::config::{ServerConfig, TlsConfig};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ServerConfig {
//!     tls: Some(TlsConfig {
//!         cert_path: "/path/to/server.crt".into(),
//!         key_path: "/path/to/server.key".into(),
//!         client_ca_path: Some("/path/to/client-ca.crt".into()),
//!         require_client_cert: true,
//!     }),
//!     ..Default::default()
//! };
//! # Ok(())
//! # }
//! ```
//!
//! ## Using Circuit Breaker
//!
//! ```no_run
//! use grpc_api::{CircuitBreaker, CircuitBreakerConfig};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure circuit breaker
//! let config = CircuitBreakerConfig {
//!     failure_threshold: 5,
//!     success_threshold: 2,
//!     timeout: Duration::from_secs(60),
//!     half_open_max_requests: 1,
//! };
//!
//! let circuit_breaker = CircuitBreaker::new(config);
//!
//! // Execute operation with circuit breaker protection
//! let result = circuit_breaker.call(|| {
//!     // Your operation here
//!     Ok::<_, ()>(())
//! });
//! # Ok(())
//! # }
//! ```
//!
//! ## Input Validation
//!
//! ```no_run
//! use grpc_api::validation::{validate_key_id, validate_namespace, validate_data_size};
//!
//! # fn main() -> Result<(), tonic::Status> {
//! // Validate key ID (max 256 bytes)
//! validate_key_id(b"my-key-123")?;
//!
//! // Validate namespace (alphanumeric + hyphens/underscores, max 256 bytes)
//! validate_namespace("production-keys")?;
//!
//! // Validate data size for signing (max 10MB)
//! let message = b"data to sign";
//! validate_data_size(message, "sign")?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Response Caching
//!
//! ```no_run
//! use grpc_api::{ResponseCache, CacheKey};
//!
//! # fn main() {
//! // Create cache with default capacity
//! let cache = ResponseCache::default();
//!
//! // Cache a GetKey response
//! let key = CacheKey::GetKey {
//!     key_id: b"key-123".to_vec(),
//!     namespace: "namespace".to_string(),
//! };
//! cache.get_key_cache.insert(key.clone(), vec![/* response data */]);
//!
//! // Retrieve from cache
//! if let Some(response) = cache.get_key_cache.get(&key) {
//!     println!("Cache hit!");
//! }
//! # }
//! ```
//!
//! # Production Deployment
//!
//! ## Kubernetes Deployment Considerations
//!
//! - **Health Checks**: The server includes a health check service at `hsm.v1.Health`
//! - **Graceful Shutdown**: Use [`server::shutdown_signal`] to handle SIGTERM/SIGINT
//! - **Metrics**: Expose Prometheus metrics on a separate port (default: 9090)
//! - **TLS Certificates**: Mount as Kubernetes secrets
//! - **Cache Cleanup**: Background task runs every 5 minutes by default
//!
//! ## Monitoring
//!
//! Key metrics to monitor:
//! - Request rate and latency (p50, p95, p99)
//! - Circuit breaker state transitions
//! - Cache hit ratio
//! - Error rates by type
//! - Connection count and duration
//!
//! See [`crate::metrics`] documentation for full list of available metrics.

pub mod cache;
pub mod circuit_breaker;
pub mod config;
pub mod error;
pub mod grpc_web;
pub mod middleware;
pub mod server;
pub mod tracing_support;
pub mod validation;

/// Protocol Buffer definitions for the HSM API
///
/// This module contains the generated gRPC service definitions and message types.
/// The proto file is located at `proto/hsm/v1/hsm.proto`.
///
/// # Key Message Types
///
/// - [`GenerateKeyRequest`], [`GenerateKeyResponse`]: Key generation
/// - [`SignRequest`], [`SignResponse`]: Digital signature creation
/// - [`BatchSignRequest`], [`BatchSignResponse`]: Batch signing operations
/// - [`BatchEncryptRequest`], [`BatchEncryptResponse`]: Batch encryption
/// - [`BatchDecryptRequest`], [`BatchDecryptResponse`]: Batch decryption
/// - [`BatchVerifyRequest`], [`BatchVerifyResponse`]: Batch verification
/// - [`HealthCheckRequest`], [`HealthCheckResponse`]: Health monitoring
pub mod proto {
    pub mod hsm {
        tonic::include_proto!("hsm.v1");
    }
}

pub use error::{ApiError, Result};

// Re-export common types for convenience
pub use proto::hsm::{
    BatchDecryptRequest, BatchDecryptResponse, BatchEncryptRequest, BatchEncryptResponse,
    BatchSignRequest, BatchSignResponse, BatchVerifyRequest, BatchVerifyResponse,
    GenerateKeyRequest, GenerateKeyResponse, HealthCheckRequest, HealthCheckResponse, SignRequest,
    SignResponse,
};

// Re-export configuration types
pub use config::{CacheConfig, Http2Config, LimitsConfig, ServerConfig, TlsConfig};

// Re-export cache types
pub use cache::{CacheKey, ResponseCache};

// Re-export circuit breaker
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};

// Re-export gRPC-Web support
pub use grpc_web::{create_cors_layer, create_grpc_web_layer, grpc_web_layer, GrpcWebConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_imports() {
        assert!(std::mem::size_of::<ApiError>() > 0);
    }

    #[test]
    fn test_proto_types() {
        let _req = HealthCheckRequest {
            service: "test".to_string(),
        };
    }
}
