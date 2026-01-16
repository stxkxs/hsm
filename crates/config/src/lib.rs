//! Configuration management for the HSM (Hardware Security Module) system.
//!
//! This crate provides comprehensive configuration management including:
//! - Loading configuration from files (YAML, TOML, JSON)
//! - Environment variable overrides
//! - Configuration validation
//! - Default configurations for different environments
//!
//! # Examples
//!
//! ## Loading configuration from a file
//!
//! ```rust,no_run
//! use hsm_config::load_config;
//!
//! let config = load_config("config.yaml").expect("Failed to load config");
//! println!("Server running on {}:{}", config.server.host, config.server.port);
//! ```
//!
//! ## Using default configurations
//!
//! ```rust
//! use hsm_config::HsmConfig;
//!
//! // Development configuration
//! let dev_config = HsmConfig::development();
//!
//! // Production configuration
//! let prod_config = HsmConfig::production();
//!
//! // Test configuration
//! let test_config = HsmConfig::test();
//! ```
//!
//! ## Building custom configuration
//!
//! ```rust,no_run
//! use hsm_config::ConfigLoader;
//!
//! let config = ConfigLoader::from_file("base.yaml")
//!     .expect("Failed to load base config")
//!     .merge_file("override.yaml")
//!     .expect("Failed to merge override")
//!     .with_env()
//!     .expect("Failed to add env vars")
//!     .build_and_validate()
//!     .expect("Failed to build config");
//! ```
//!
//! ## Environment variables
//!
//! Environment variables can override configuration values using the prefix `HSM_`
//! and double underscores for nested keys:
//!
//! ```bash
//! export HSM_SERVER__PORT=9000
//! export HSM_SERVER__HOST=0.0.0.0
//! export HSM_SECURITY__ENCRYPTION_AT_REST=true
//! ```

pub mod backup;
pub mod defaults;
pub mod encryption;
pub mod loader;
pub mod manager;
pub mod schema;
pub mod validator;

// Re-export main types for convenience
pub use loader::{load_config, load_config_unchecked, load_from_env, ConfigLoader, LoadError};
pub use schema::{
    AccessControl, EncryptionAlgorithm, HsmConfig, KeyPolicies, LogFormat, LogLevel, LogOutput,
    LoggingConfig, MetricsConfig, MetricsFormat, NamespaceConfig, SecurityConfig, ServerConfig,
    StorageBackend, StorageConfig, SyncMode,
};
pub use validator::{validate, ValidationError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = HsmConfig::default();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_development_config_is_valid() {
        let config = HsmConfig::development();
        if let Err(e) = validate(&config) {
            eprintln!("Validation error: {:?}", e);
        }
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_production_config_is_valid() {
        let config = HsmConfig::production();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_test_config_is_valid() {
        let config = HsmConfig::test();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let original = HsmConfig::default();
        let yaml = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: HsmConfig = serde_yaml::from_str(&yaml).expect("Failed to deserialize");
        assert_eq!(original, deserialized);
    }
}
