//! gRPC-Web Support
//!
//! Enables browser clients to communicate with the gRPC server using gRPC-Web protocol.
//!
//! # Overview
//!
//! gRPC-Web is a JavaScript implementation of gRPC for browser clients. It allows
//! web applications to make gRPC calls without requiring a gRPC proxy like Envoy.
//!
//! # Protocol Support
//!
//! This module supports:
//! - `application/grpc-web+proto`: Binary gRPC-Web with protobuf encoding
//! - `application/grpc-web-text+proto`: Base64-encoded gRPC-Web (for debugging)
//!
//! # Security
//!
//! CORS is configured restrictively by default:
//! - Only explicitly allowed origins can make requests
//! - Credentials are not allowed by default
//! - Only necessary headers are exposed
//!
//! # Example
//!
//! ```no_run
//! use grpc_api::grpc_web::{GrpcWebConfig, create_grpc_web_layer};
//! use tonic::transport::Server;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = GrpcWebConfig {
//!         enabled: true,
//!         allowed_origins: vec!["https://example.com".to_string()],
//!         ..Default::default()
//!     };
//!
//!     if let Some(layer) = create_grpc_web_layer(&config) {
//!         // Apply layer to server
//!     }
//!
//!     Ok(())
//! }
//! ```

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::Method;
use serde::{Deserialize, Serialize};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// gRPC-Web configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcWebConfig {
    /// Whether gRPC-Web is enabled
    pub enabled: bool,

    /// Allowed origins for CORS
    /// Use specific origins in production, not wildcards
    pub allowed_origins: Vec<String>,

    /// Whether to allow credentials (cookies, authorization headers)
    pub allow_credentials: bool,

    /// Maximum age for CORS preflight cache (seconds)
    pub max_age_seconds: u64,

    /// Expose grpc-status and grpc-message headers to browser
    pub expose_grpc_headers: bool,
}

impl Default for GrpcWebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_origins: vec![],
            allow_credentials: false,
            max_age_seconds: 3600,
            expose_grpc_headers: true,
        }
    }
}

impl GrpcWebConfig {
    /// Create a development configuration with permissive settings
    ///
    /// **WARNING**: Do not use in production!
    pub fn development() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            allow_credentials: true,
            max_age_seconds: 3600,
            expose_grpc_headers: true,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.allowed_origins.is_empty() {
            return Err("gRPC-Web enabled but no allowed origins configured".to_string());
        }

        // Warn about wildcard origins (but allow them)
        if self.allowed_origins.contains(&"*".to_string()) {
            tracing::warn!("gRPC-Web CORS configured with wildcard origin - not recommended for production");
        }

        Ok(())
    }
}

/// Create a CORS layer for gRPC-Web
///
/// Returns a configured CORS layer that allows gRPC-Web requests from
/// the specified origins.
pub fn create_cors_layer(config: &GrpcWebConfig) -> CorsLayer {
    let allowed_origins = if config.allowed_origins.contains(&"*".to_string()) {
        AllowOrigin::any()
    } else {
        let origins: Vec<_> = config
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        AllowOrigin::list(origins)
    };

    let mut cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            CONTENT_TYPE,
            AUTHORIZATION,
            "x-grpc-web".parse().unwrap(),
            "x-user-agent".parse().unwrap(),
        ])
        .max_age(std::time::Duration::from_secs(config.max_age_seconds));

    if config.expose_grpc_headers {
        cors = cors.expose_headers([
            "grpc-status".parse().unwrap(),
            "grpc-message".parse().unwrap(),
            "grpc-encoding".parse().unwrap(),
            "grpc-accept-encoding".parse().unwrap(),
        ]);
    }

    if config.allow_credentials {
        cors = cors.allow_credentials(true);
    }

    cors
}

/// Create gRPC-Web layer if enabled
///
/// Returns a tonic-web layer that translates gRPC-Web protocol to gRPC,
/// or None if gRPC-Web is disabled.
pub fn create_grpc_web_layer(config: &GrpcWebConfig) -> Option<tonic_web::GrpcWebLayer> {
    if config.enabled {
        Some(tonic_web::GrpcWebLayer::new())
    } else {
        None
    }
}

/// Create a gRPC-Web service wrapper
///
/// This layer can be applied to a gRPC service to enable gRPC-Web protocol support.
/// Use with the tonic-web layer approach:
///
/// ```ignore
/// let layer = tonic_web::GrpcWebLayer::new();
/// server.layer(layer).serve(addr).await?;
/// ```
pub fn grpc_web_layer() -> tonic_web::GrpcWebLayer {
    tonic_web::GrpcWebLayer::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GrpcWebConfig::default();
        assert!(!config.enabled);
        assert!(config.allowed_origins.is_empty());
    }

    #[test]
    fn test_development_config() {
        let config = GrpcWebConfig::development();
        assert!(config.enabled);
        assert!(config.allowed_origins.contains(&"http://localhost:3000".to_string()));
    }

    #[test]
    fn test_validation_no_origins() {
        let config = GrpcWebConfig {
            enabled: true,
            allowed_origins: vec![],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_with_origins() {
        let config = GrpcWebConfig {
            enabled: true,
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_create_grpc_web_layer_disabled() {
        let config = GrpcWebConfig::default();
        assert!(create_grpc_web_layer(&config).is_none());
    }

    #[test]
    fn test_create_grpc_web_layer_enabled() {
        let config = GrpcWebConfig {
            enabled: true,
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        assert!(create_grpc_web_layer(&config).is_some());
    }
}
