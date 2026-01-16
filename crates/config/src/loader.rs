//! Configuration loading from various sources.

use crate::schema::HsmConfig;
use crate::validator::ValidationError;
use config::{Config, ConfigError, Environment, File, FileFormat};
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during configuration loading.
#[derive(Debug, Error)]
pub enum LoadError {
    /// Configuration file error
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML parsing error
    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// TOML parsing error
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Configuration loader for the HSM system.
pub struct ConfigLoader {
    builder: Config,
}

impl ConfigLoader {
    /// Creates a new configuration loader.
    pub fn new() -> Self {
        Self {
            builder: Config::builder().build().unwrap_or_default(),
        }
    }

    /// Loads configuration from a file.
    ///
    /// Supported formats: YAML, TOML, JSON (auto-detected from extension)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let format = Self::detect_format(path)?;

        let builder = Config::builder()
            .add_source(File::from(path).format(format))
            .build()?;

        Ok(Self { builder })
    }

    /// Loads configuration from a YAML string.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, LoadError> {
        let _config: HsmConfig = serde_yaml::from_str(yaml)?;
        let builder = Config::builder()
            .add_source(config::File::from_str(yaml, FileFormat::Yaml))
            .build()?;

        Ok(Self { builder })
    }

    /// Loads configuration from a TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, LoadError> {
        let builder = Config::builder()
            .add_source(config::File::from_str(toml_str, FileFormat::Toml))
            .build()?;

        Ok(Self { builder })
    }

    /// Adds environment variable overrides.
    ///
    /// Environment variables should be prefixed with `HSM_` and use double
    /// underscores for nested keys, e.g., `HSM_SERVER__PORT=8080`.
    pub fn with_env(mut self) -> Result<Self, LoadError> {
        self.builder = Config::builder()
            .add_source(self.builder)
            .add_source(
                Environment::with_prefix("HSM")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        Ok(self)
    }

    /// Merges with another configuration file.
    pub fn merge_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let format = Self::detect_format(path)?;

        self.builder = Config::builder()
            .add_source(self.builder)
            .add_source(File::from(path).format(format))
            .build()?;

        Ok(self)
    }

    /// Builds the final configuration.
    pub fn build(self) -> Result<HsmConfig, LoadError> {
        let config: HsmConfig = self.builder.try_deserialize()?;
        Ok(config)
    }

    /// Builds and validates the final configuration.
    pub fn build_and_validate(self) -> Result<HsmConfig, LoadError> {
        let config = self.build()?;
        crate::validator::validate(&config)?;
        Ok(config)
    }

    /// Detects file format from extension.
    fn detect_format(path: &Path) -> Result<FileFormat, LoadError> {
        let extension = path.extension().and_then(|s| s.to_str()).ok_or_else(|| {
            LoadError::Config(ConfigError::Message(
                "Cannot detect file format from extension".to_string(),
            ))
        })?;

        match extension.to_lowercase().as_str() {
            "yaml" | "yml" => Ok(FileFormat::Yaml),
            "toml" => Ok(FileFormat::Toml),
            "json" => Ok(FileFormat::Json),
            _ => Err(LoadError::Config(ConfigError::Message(format!(
                "Unsupported file format: {}",
                extension
            )))),
        }
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to load configuration from a file with environment overrides.
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<HsmConfig, LoadError> {
    ConfigLoader::from_file(path)?
        .with_env()?
        .build_and_validate()
}

/// Loads configuration from a file without validation.
pub fn load_config_unchecked<P: AsRef<Path>>(path: P) -> Result<HsmConfig, LoadError> {
    ConfigLoader::from_file(path)?.with_env()?.build()
}

/// Loads configuration from environment variables only.
pub fn load_from_env() -> Result<HsmConfig, LoadError> {
    let builder = Config::builder()
        .add_source(
            Environment::with_prefix("HSM")
                .separator("__")
                .try_parsing(true),
        )
        .build()?;

    let config: HsmConfig = builder.try_deserialize()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_string_loading() {
        let yaml = r#"
server:
  host: "0.0.0.0"
  port: 9000
  max_connections: 500
  timeout_seconds: 60
  tls_enabled: false
  worker_threads: 4

storage:
  backend: "memory"
  data_dir: "/tmp/test"
  cache_size_bytes: 1048576
  wal_enabled: false
  sync_mode: "none"
  max_file_size_bytes: 10485760
  backup_interval_seconds: 0

security:
  key_derivation_iterations: 50000
  encryption_at_rest: true
  encryption_algorithm: "aes256gcm"
  key_size_bits: 256
  session_timeout_seconds: 7200
  max_auth_attempts: 5
  lockout_duration_seconds: 600
  audit_log_enabled: true
  require_strong_passwords: true
  min_password_length: 10

logging:
  level: "debug"
  format: "json"
  output: "console"
  max_file_size_bytes: 10485760
  max_backup_files: 5
  colored: true
  include_timestamps: true
  include_module_path: true

metrics:
  enabled: true
  format: "prometheus"
  listen_addr: "127.0.0.1"
  listen_port: 9090
  collection_interval_seconds: 60
  enable_histograms: true
  histogram_buckets: [0.1, 1.0, 10.0]
  retention_seconds: 86400

namespaces: {}
"#;

        let result = ConfigLoader::from_yaml_str(yaml);
        assert!(result.is_ok());

        let config = result.unwrap().build().unwrap();
        assert_eq!(config.server.port, 9000);
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.security.min_password_length, 10);
    }

    #[test]
    fn test_toml_string_loading() {
        let toml_str = r#"
[server]
host = "localhost"
port = 8080
max_connections = 100
timeout_seconds = 30
tls_enabled = false
worker_threads = 2

[storage]
backend = "memory"
data_dir = "/tmp/data"
cache_size_bytes = 1048576
wal_enabled = false
sync_mode = "none"
max_file_size_bytes = 10485760
backup_interval_seconds = 0

[security]
key_derivation_iterations = 10000
encryption_at_rest = false
encryption_algorithm = "aes256gcm"
key_size_bits = 256
session_timeout_seconds = 3600
max_auth_attempts = 3
lockout_duration_seconds = 300
audit_log_enabled = false
require_strong_passwords = false
min_password_length = 8

[logging]
level = "info"
format = "text"
output = "console"
max_file_size_bytes = 10485760
max_backup_files = 3
colored = true
include_timestamps = true
include_module_path = false

[metrics]
enabled = false
format = "prometheus"
listen_addr = "127.0.0.1"
listen_port = 9090
collection_interval_seconds = 60
enable_histograms = false
histogram_buckets = [1.0, 10.0]
retention_seconds = 3600

[namespaces]
"#;

        let result = ConfigLoader::from_toml_str(toml_str);
        assert!(result.is_ok());

        let config = result.unwrap().build().unwrap();
        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 8080);
    }
}
