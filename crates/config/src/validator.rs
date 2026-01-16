//! Configuration validation logic.

use crate::schema::*;
use thiserror::Error;

/// Validation errors.
#[derive(Debug, Error, PartialEq)]
pub enum ValidationError {
    /// Invalid port number
    #[error("Invalid port number: {0}")]
    InvalidPort(u16),

    /// Invalid host address
    #[error("Invalid host address: {0}")]
    InvalidHost(String),

    /// Invalid timeout value
    #[error("Invalid timeout: {0} (must be > 0)")]
    InvalidTimeout(u64),

    /// TLS configuration error
    #[error("TLS is enabled but {0} is not specified")]
    TlsConfigMissing(String),

    /// Invalid path
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Invalid cache size
    #[error("Invalid cache size: {0} (must be > 0)")]
    InvalidCacheSize(u64),

    /// Invalid file size
    #[error("Invalid file size: {0} (must be > 0)")]
    InvalidFileSize(u64),

    /// Invalid key derivation iterations
    #[error("Invalid key derivation iterations: {0} (must be >= 1000)")]
    InvalidKeyDerivationIterations(u32),

    /// Invalid key size
    #[error("Invalid key size: {0} (must be one of 128, 192, or 256)")]
    InvalidKeySize(u32),

    /// Invalid session timeout
    #[error("Invalid session timeout: {0} (must be between 60 and 86400)")]
    InvalidSessionTimeout(u64),

    /// Invalid password length
    #[error("Invalid minimum password length: {0} (must be >= 8)")]
    InvalidPasswordLength(usize),

    /// Invalid max auth attempts
    #[error("Invalid max auth attempts: {0} (must be > 0)")]
    InvalidMaxAuthAttempts(u32),

    /// Invalid histogram buckets
    #[error("Invalid histogram buckets: must have at least one bucket")]
    InvalidHistogramBuckets,

    /// Invalid collection interval
    #[error("Invalid collection interval: {0} (must be > 0)")]
    InvalidCollectionInterval(u64),

    /// Invalid retention period
    #[error("Invalid retention period: {0} (must be > 0)")]
    InvalidRetentionPeriod(u64),

    /// Invalid max connections
    #[error("Invalid max connections: {0} (must be > 0)")]
    InvalidMaxConnections(usize),

    /// Invalid CIDR notation
    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    /// Namespace validation error
    #[error("Namespace '{0}' validation error: {1}")]
    NamespaceError(String, String),

    /// Generic validation error
    #[error("Validation error: {0}")]
    Generic(String),
}

/// Validates the entire HSM configuration.
///
/// This performs both structural validation (using validator crate) and
/// business logic validation (custom rules).
pub fn validate(config: &HsmConfig) -> Result<(), ValidationError> {
    // Run custom business logic validation
    // Note: Structural validation via #[derive(Validate)] is available but
    // not used here to provide more specific error messages
    validate_server(&config.server)?;
    validate_storage(&config.storage)?;
    validate_security(&config.security)?;
    validate_logging(&config.logging)?;
    validate_metrics(&config.metrics)?;
    validate_namespaces(&config.namespaces)?;

    Ok(())
}

/// Validates server configuration.
fn validate_server(config: &ServerConfig) -> Result<(), ValidationError> {
    // Validate host
    if config.host.is_empty() {
        return Err(ValidationError::InvalidHost("empty host".to_string()));
    }

    // Validate port (0 is allowed for auto-assignment in tests)
    // Port validation is mostly handled by the type system (u16)

    // Validate max_connections
    if config.max_connections == 0 {
        return Err(ValidationError::InvalidMaxConnections(0));
    }

    // Validate timeout
    if config.timeout_seconds == 0 {
        return Err(ValidationError::InvalidTimeout(0));
    }

    // Validate TLS configuration
    if config.tls_enabled {
        if config.tls_cert_path.is_none() {
            return Err(ValidationError::TlsConfigMissing(
                "tls_cert_path".to_string(),
            ));
        }
        if config.tls_key_path.is_none() {
            return Err(ValidationError::TlsConfigMissing(
                "tls_key_path".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validates storage configuration.
fn validate_storage(config: &StorageConfig) -> Result<(), ValidationError> {
    // Validate data directory
    if config.data_dir.as_os_str().is_empty() {
        return Err(ValidationError::InvalidPath(
            "data_dir cannot be empty".to_string(),
        ));
    }

    // Validate cache size
    if config.cache_size_bytes == 0 {
        return Err(ValidationError::InvalidCacheSize(0));
    }

    // Validate max file size
    if config.max_file_size_bytes == 0 {
        return Err(ValidationError::InvalidFileSize(0));
    }

    // Validate backup configuration
    if config.backup_interval_seconds > 0 && config.backup_dir.is_none() {
        return Err(ValidationError::Generic(
            "backup_dir must be specified when backup_interval_seconds > 0".to_string(),
        ));
    }

    Ok(())
}

/// Validates security configuration.
fn validate_security(config: &SecurityConfig) -> Result<(), ValidationError> {
    // Validate key derivation iterations (minimum for security)
    if config.key_derivation_iterations < 1000 {
        return Err(ValidationError::InvalidKeyDerivationIterations(
            config.key_derivation_iterations,
        ));
    }

    // Validate key size
    if ![128, 192, 256].contains(&config.key_size_bits) {
        return Err(ValidationError::InvalidKeySize(config.key_size_bits));
    }

    // Validate session timeout (1 minute to 24 hours)
    if config.session_timeout_seconds < 60 || config.session_timeout_seconds > 86400 {
        return Err(ValidationError::InvalidSessionTimeout(
            config.session_timeout_seconds,
        ));
    }

    // Validate max auth attempts
    if config.max_auth_attempts == 0 {
        return Err(ValidationError::InvalidMaxAuthAttempts(0));
    }

    // Validate password requirements
    if config.require_strong_passwords && config.min_password_length < 8 {
        return Err(ValidationError::InvalidPasswordLength(
            config.min_password_length,
        ));
    }

    // Validate audit log configuration
    if config.audit_log_enabled && config.audit_log_path.is_none() {
        return Err(ValidationError::Generic(
            "audit_log_path must be specified when audit_log_enabled is true".to_string(),
        ));
    }

    Ok(())
}

/// Validates logging configuration.
fn validate_logging(config: &LoggingConfig) -> Result<(), ValidationError> {
    // Validate file path when needed
    match config.output {
        LogOutput::File | LogOutput::Both => {
            if config.file_path.is_none() {
                return Err(ValidationError::Generic(
                    "file_path must be specified for file or both output modes".to_string(),
                ));
            }
        }
        LogOutput::Console => {}
    }

    // Validate max file size
    if config.max_file_size_bytes == 0 {
        return Err(ValidationError::InvalidFileSize(0));
    }

    // Validate max backup files
    if config.max_backup_files == 0 {
        return Err(ValidationError::Generic(
            "max_backup_files must be > 0".to_string(),
        ));
    }

    Ok(())
}

/// Validates metrics configuration.
fn validate_metrics(config: &MetricsConfig) -> Result<(), ValidationError> {
    if !config.enabled {
        return Ok(());
    }

    // Validate listen address
    if config.listen_addr.is_empty() {
        return Err(ValidationError::InvalidHost(
            "metrics listen_addr cannot be empty".to_string(),
        ));
    }

    // Validate collection interval
    if config.collection_interval_seconds == 0 {
        return Err(ValidationError::InvalidCollectionInterval(0));
    }

    // Validate retention period
    if config.retention_seconds == 0 {
        return Err(ValidationError::InvalidRetentionPeriod(0));
    }

    // Validate histogram buckets
    if config.enable_histograms && config.histogram_buckets.is_empty() {
        return Err(ValidationError::InvalidHistogramBuckets);
    }

    // Validate histogram buckets are in ascending order
    if config.enable_histograms {
        let mut prev = 0.0;
        for &bucket in &config.histogram_buckets {
            if bucket <= prev {
                return Err(ValidationError::Generic(
                    "histogram_buckets must be in ascending order".to_string(),
                ));
            }
            prev = bucket;
        }
    }

    Ok(())
}

/// Validates namespace configurations.
fn validate_namespaces(
    namespaces: &std::collections::HashMap<String, NamespaceConfig>,
) -> Result<(), ValidationError> {
    for (name, config) in namespaces {
        validate_namespace(name, config)?;
    }
    Ok(())
}

/// Validates a single namespace configuration.
fn validate_namespace(name: &str, config: &NamespaceConfig) -> Result<(), ValidationError> {
    // Validate namespace name
    if name.is_empty() {
        return Err(ValidationError::NamespaceError(
            name.to_string(),
            "namespace name cannot be empty".to_string(),
        ));
    }

    // Validate max_keys if specified
    if let Some(max_keys) = config.max_keys {
        if max_keys == 0 {
            return Err(ValidationError::NamespaceError(
                name.to_string(),
                "max_keys must be > 0 if specified".to_string(),
            ));
        }
    }

    // Validate CIDR notation in access control
    for ip in &config.access_control.allowed_ips {
        validate_cidr(ip)?;
    }

    for ip in &config.access_control.denied_ips {
        validate_cidr(ip)?;
    }

    // Validate max concurrent sessions
    if config.access_control.max_concurrent_sessions == 0 {
        return Err(ValidationError::NamespaceError(
            name.to_string(),
            "max_concurrent_sessions must be > 0".to_string(),
        ));
    }

    Ok(())
}

/// Validates CIDR notation (basic validation).
fn validate_cidr(cidr: &str) -> Result<(), ValidationError> {
    if cidr.is_empty() {
        return Err(ValidationError::InvalidCidr("empty CIDR".to_string()));
    }

    // Basic CIDR format check (simplified)
    if !cidr.contains('/') && !cidr.contains(':') && !cidr.chars().any(|c| c.is_ascii_digit()) {
        return Err(ValidationError::InvalidCidr(cidr.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_default_config() {
        let config = HsmConfig::default();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_valid_development_config() {
        let config = HsmConfig::development();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_valid_production_config() {
        let config = HsmConfig::production();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_valid_test_config() {
        let config = HsmConfig::test();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn test_invalid_empty_host() {
        let mut config = HsmConfig::default();
        config.server.host = "".to_string();
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidHost(_))
        ));
    }

    #[test]
    fn test_invalid_zero_max_connections() {
        let mut config = HsmConfig::default();
        config.server.max_connections = 0;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidMaxConnections(_))
        ));
    }

    #[test]
    fn test_invalid_zero_timeout() {
        let mut config = HsmConfig::default();
        config.server.timeout_seconds = 0;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidTimeout(_))
        ));
    }

    #[test]
    fn test_tls_enabled_without_cert() {
        let mut config = HsmConfig::default();
        config.server.tls_enabled = true;
        config.server.tls_cert_path = None;
        config.server.tls_key_path = None;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::TlsConfigMissing(_))
        ));
    }

    #[test]
    fn test_invalid_key_derivation_iterations() {
        let mut config = HsmConfig::default();
        config.security.key_derivation_iterations = 500;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidKeyDerivationIterations(_))
        ));
    }

    #[test]
    fn test_invalid_key_size() {
        let mut config = HsmConfig::default();
        config.security.key_size_bits = 512;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidKeySize(_))
        ));
    }

    #[test]
    fn test_invalid_session_timeout_too_short() {
        let mut config = HsmConfig::default();
        config.security.session_timeout_seconds = 30;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidSessionTimeout(_))
        ));
    }

    #[test]
    fn test_invalid_session_timeout_too_long() {
        let mut config = HsmConfig::default();
        config.security.session_timeout_seconds = 100000;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidSessionTimeout(_))
        ));
    }

    #[test]
    fn test_invalid_password_length() {
        let mut config = HsmConfig::default();
        config.security.require_strong_passwords = true;
        config.security.min_password_length = 4;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidPasswordLength(_))
        ));
    }

    #[test]
    fn test_invalid_zero_cache_size() {
        let mut config = HsmConfig::default();
        config.storage.cache_size_bytes = 0;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidCacheSize(_))
        ));
    }

    #[test]
    fn test_audit_log_enabled_without_path() {
        let mut config = HsmConfig::default();
        config.security.audit_log_enabled = true;
        config.security.audit_log_path = None;
        assert!(matches!(
            validate(&config),
            Err(ValidationError::Generic(_))
        ));
    }

    #[test]
    fn test_invalid_histogram_buckets_empty() {
        let mut config = HsmConfig::default();
        config.metrics.enable_histograms = true;
        config.metrics.histogram_buckets = vec![];
        assert!(matches!(
            validate(&config),
            Err(ValidationError::InvalidHistogramBuckets)
        ));
    }

    #[test]
    fn test_invalid_histogram_buckets_not_ascending() {
        let mut config = HsmConfig::default();
        config.metrics.enable_histograms = true;
        config.metrics.histogram_buckets = vec![1.0, 0.5, 2.0];
        assert!(matches!(
            validate(&config),
            Err(ValidationError::Generic(_))
        ));
    }
}
