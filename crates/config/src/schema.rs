//! Configuration schema definitions for the HSM system.
//!
//! This module defines the complete configuration schema with validation constraints
//! to ensure safe and secure HSM operation. All configuration structs use the
//! `validator` crate to enforce constraints at deserialization time.
//!
//! # Validation Strategy
//!
//! Configuration validation occurs in two phases:
//!
//! 1. **Structural Validation** (serde deserialization)
//!    - Type checking, required fields, format validation
//! 2. **Constraint Validation** (validator crate)
//!    - Range checks, length limits, custom business logic
//!
//! # Validation Constraints
//!
//! ## Server Configuration
//! - `host`: Non-empty string
//! - `port`: 1024-65535 (unprivileged port range)
//! - `max_connections`: 1-100,000
//! - `timeout_seconds`: ≥1
//! - `worker_threads`: 0 = auto-detect CPU count
//!
//! ## Storage Configuration
//! - `cache_size_bytes`: ≥1 byte
//! - `max_file_size_bytes`: ≥1 byte
//! - `backup_interval_seconds`: 0 = disabled
//!
//! ## Security Configuration
//! - `key_derivation_iterations`: ≥100,000 (OWASP minimum)
//! - `key_size_bits`: 256/384/521 (ECC) or 2048/3072/4096 (RSA)
//! - `session_timeout_seconds`: 60-86400 (1 minute - 24 hours)
//! - `max_auth_attempts`: 1-10
//! - `lockout_duration_seconds`: ≥60 (1 minute minimum)
//! - `min_password_length`: 8-128 characters
//!
//! ## Logging Configuration
//! - `level`: trace/debug/info/warn/error
//! - `max_file_size_bytes`: ≥1 byte
//! - `max_backup_files`: ≥0
//!
//! ## Metrics Configuration
//! - `port`: 1024-65535 (unprivileged port range)
//!
//! # Examples
//!
//! ## Loading and validating configuration
//!
//! ```rust,no_run
//! use hsm_config::{load_config, validate};
//!
//! // Load from file (auto-validates)
//! let config = load_config("config.yaml").expect("Failed to load config");
//!
//! // Manual validation
//! validate(&config).expect("Configuration validation failed");
//! ```
//!
//! ## Using default configurations
//!
//! ```rust
//! use hsm_config::HsmConfig;
//!
//! // Development config (relaxed security, verbose logging)
//! let dev_config = HsmConfig::development();
//!
//! // Production config (strict security, minimal logging)
//! let prod_config = HsmConfig::production();
//!
//! // Test config (in-memory storage, fast operations)
//! let test_config = HsmConfig::test();
//! ```
//!
//! ## Environment variable overrides
//!
//! Environment variables override configuration file values:
//!
//! ```bash
//! # Override server port
//! export HSM_SERVER__PORT=9000
//!
//! # Override security settings
//! export HSM_SECURITY__SESSION_TIMEOUT_SECONDS=7200
//! export HSM_SECURITY__ENCRYPTION_AT_REST=true
//!
//! # Override logging level
//! export HSM_LOGGING__LEVEL=debug
//! ```
//!
//! ```rust,no_run
//! use hsm_config::load_from_env;
//!
//! // Load config with env var overrides
//! let config = load_from_env().expect("Failed to load");
//! ```
//!
//! # Validation Error Handling
//!
//! ```rust,no_run
//! use hsm_config::{load_config, validate};
//!
//! match load_config("config.yaml") {
//!     Ok(config) => {
//!         println!("Configuration loaded successfully");
//!     }
//!     Err(e) => {
//!         eprintln!("Configuration error: {}", e);
//!         // Specific validation errors are detailed in the error message
//!     }
//! }
//! ```
//!
//! # Security Considerations
//!
//! ## Key Derivation Iterations
//! - Minimum: 100,000 iterations (OWASP recommendation as of 2024)
//! - Higher values increase security but slow down key derivation
//! - Adjust based on hardware capabilities and security requirements
//!
//! ## Session Timeouts
//! - Shorter timeouts increase security but reduce usability
//! - Recommended: 3600s (1 hour) for standard operations
//! - Use shorter timeouts (≤900s) for highly sensitive operations
//!
//! ## Key Sizes
//! - RSA: Minimum 2048 bits, recommended 3072+ for long-term security
//! - ECC: Minimum 256 bits (P-256), use 384+ for higher security
//! - Ed25519: Always 256 bits (curve25519)
//!
//! ## Password Policies
//! - Minimum 8 characters (enforced by validation)
//! - Recommended: Require mixed case, numbers, special characters
//! - Consider using passphrases (longer, memorable phrases)
//!
//! # Hot Reload Support
//!
//! The configuration system supports hot reload of certain settings without
//! restarting the HSM server:
//!
//! - Logging level changes
//! - Session timeout adjustments
//! - Rate limiting parameters
//!
//! Settings that require restart:
//! - Server host/port
//! - TLS certificates
//! - Storage backend
//! - Encryption algorithm

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use validator::Validate;

/// Root configuration structure for the HSM system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate, Default)]
pub struct HsmConfig {
    /// Server configuration
    #[validate(nested)]
    pub server: ServerConfig,
    /// Storage configuration
    #[validate(nested)]
    pub storage: StorageConfig,
    /// Security configuration
    #[validate(nested)]
    pub security: SecurityConfig,
    /// Logging configuration
    #[validate(nested)]
    pub logging: LoggingConfig,
    /// Metrics configuration
    #[validate(nested)]
    pub metrics: MetricsConfig,
    /// Namespace-specific configurations
    #[serde(default)]
    pub namespaces: HashMap<String, NamespaceConfig>,
}

/// Server configuration settings.
///
/// Controls the HTTP/gRPC server behavior including network binding,
/// concurrency, and TLS settings.
///
/// # Validation Constraints
///
/// - `host`: Must be non-empty (validates: `length(min = 1)`)
/// - `port`: Must be in unprivileged range 1024-65535 (validates: `range(min = 1024, max = 65535)`)
/// - `max_connections`: 1-100,000 concurrent connections (validates: `range(min = 1, max = 100000)`)
/// - `timeout_seconds`: At least 1 second (validates: `range(min = 1)`)
/// - `worker_threads`: 0 = auto-detect CPU cores, >0 = explicit thread count
///
/// # Examples
///
/// ```rust
/// use hsm_config::ServerConfig;
/// use std::path::PathBuf;
///
/// let config = ServerConfig {
///     host: "0.0.0.0".to_string(),
///     port: 8443,
///     max_connections: 1000,
///     timeout_seconds: 30,
///     tls_enabled: true,
///     tls_cert_path: Some(PathBuf::from("/etc/hsm/server.crt")),
///     tls_key_path: Some(PathBuf::from("/etc/hsm/server.key")),
///     worker_threads: 0, // Auto-detect
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct ServerConfig {
    /// Server host address (e.g., "0.0.0.0", "127.0.0.1", "::1")
    #[validate(length(min = 1))]
    pub host: String,

    /// Server port (1024-65535, unprivileged range)
    #[validate(range(min = 1024, max = 65535))]
    pub port: u16,

    /// Maximum number of concurrent client connections (1-100,000)
    #[validate(range(min = 1, max = 100000))]
    pub max_connections: usize,

    /// Connection timeout in seconds (minimum 1 second)
    #[validate(range(min = 1))]
    pub timeout_seconds: u64,

    /// Enable TLS encryption for client connections
    pub tls_enabled: bool,

    /// Path to TLS certificate file (required if tls_enabled is true)
    pub tls_cert_path: Option<PathBuf>,

    /// Path to TLS private key file (required if tls_enabled is true)
    pub tls_key_path: Option<PathBuf>,

    /// Number of worker threads (0 = auto-detect from CPU cores)
    pub worker_threads: usize,
}

/// Storage configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackend,
    /// Base directory for file-based storage
    pub data_dir: PathBuf,
    /// Maximum cache size in bytes
    #[validate(range(min = 1))]
    pub cache_size_bytes: u64,
    /// Enable write-ahead logging
    pub wal_enabled: bool,
    /// Sync mode for durability
    pub sync_mode: SyncMode,
    /// Maximum file size in bytes (for rotating logs)
    #[validate(range(min = 1))]
    pub max_file_size_bytes: u64,
    /// Backup directory
    pub backup_dir: Option<PathBuf>,
    /// Automatic backup interval in seconds (0 = disabled)
    pub backup_interval_seconds: u64,
}

/// Storage backend type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    /// File-based storage
    File,
    /// In-memory storage (for testing)
    Memory,
    /// SQLite database
    Sqlite,
}

/// Sync mode for storage durability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SyncMode {
    /// No synchronization (fastest, least durable)
    None,
    /// Normal synchronization
    Normal,
    /// Full synchronization (slowest, most durable)
    Full,
}

/// Security configuration settings.
///
/// Configures cryptographic parameters, authentication policies, and
/// security-critical timeouts.
///
/// # Validation Constraints
///
/// - `key_derivation_iterations`: ≥100,000 (OWASP 2024 minimum)
/// - `key_size_bits`: 256/384/521 (ECC) or 2048/3072/4096 (RSA)
/// - `session_timeout_seconds`: 60-86400 (1 minute to 24 hours)
/// - `max_auth_attempts`: 1-10 failed attempts before lockout
/// - `lockout_duration_seconds`: ≥60 seconds (1 minute minimum)
/// - `min_password_length`: 8-128 characters
///
/// # Security Recommendations
///
/// - **Key Derivation**: Use ≥100,000 iterations, increase based on hardware
/// - **Session Timeout**: 3600s (1 hour) for normal ops, ≤900s for sensitive ops
/// - **Key Sizes**: RSA ≥3072 or ECC ≥384 for long-term security
/// - **Auth Attempts**: 3-5 attempts typical, shorter lockouts for high-security
///
/// # Examples
///
/// ```rust
/// use hsm_config::{SecurityConfig, EncryptionAlgorithm};
/// use std::path::PathBuf;
///
/// // High-security production configuration
/// let config = SecurityConfig {
///     key_derivation_iterations: 200_000, // 2x minimum for added security
///     encryption_at_rest: true,
///     encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
///     key_size_bits: 3072, // RSA 3072-bit for long-term security
///     session_timeout_seconds: 1800, // 30 minutes
///     max_auth_attempts: 3,
///     lockout_duration_seconds: 300, // 5 minutes
///     audit_log_enabled: true,
///     audit_log_path: Some(PathBuf::from("/var/log/hsm/audit.log")),
///     require_strong_passwords: true,
///     min_password_length: 12, // Longer for stronger security
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct SecurityConfig {
    /// PBKDF2 iterations for master key derivation (minimum 100,000 per OWASP)
    ///
    /// Higher values increase security against brute-force attacks but slow
    /// down key derivation. Adjust based on hardware capabilities.
    #[validate(range(min = 100000))]
    pub key_derivation_iterations: u32,

    /// Enable encryption of keys at rest in storage
    pub encryption_at_rest: bool,

    /// Algorithm for encryption at rest
    pub encryption_algorithm: EncryptionAlgorithm,

    /// Key size in bits - must be 256/384/521 (ECC) or 2048/3072/4096 (RSA)
    ///
    /// ECC curves: 256 (P-256), 384 (P-384), 521 (P-521)
    /// RSA sizes: 2048 (minimum), 3072 (recommended), 4096 (high security)
    #[validate(custom(function = "validate_key_size"))]
    pub key_size_bits: u32,

    /// Session expiration timeout in seconds (60-86400, i.e., 1 minute - 24 hours)
    ///
    /// Shorter timeouts increase security at the cost of user convenience.
    /// Recommended: 3600 (1 hour) for standard operations.
    #[validate(range(min = 60, max = 86400))]
    pub session_timeout_seconds: u64,

    /// Maximum failed authentication attempts before account lockout (1-10)
    #[validate(range(min = 1, max = 10))]
    pub max_auth_attempts: u32,

    /// Duration of account lockout after max failed attempts (minimum 60 seconds)
    #[validate(range(min = 60))]
    pub lockout_duration_seconds: u64,

    /// Enable tamper-evident audit logging
    pub audit_log_enabled: bool,

    /// Path to audit log file
    pub audit_log_path: Option<PathBuf>,

    /// Enforce strong password requirements (mixed case, numbers, special chars)
    pub require_strong_passwords: bool,

    /// Minimum password/passphrase length (8-128 characters)
    #[validate(range(min = 8, max = 128))]
    pub min_password_length: usize,
}

/// Validates that key_size_bits is a secure, standard key size.
///
/// Allowed values:
/// - ECC: 256 (P-256), 384 (P-384), 521 (P-521)
/// - RSA: 2048, 3072, 4096
///
/// # Errors
///
/// Returns validation error if key size is not in the allowed list.
fn validate_key_size(key_size: u32) -> Result<(), validator::ValidationError> {
    // Allow common secure key sizes: 256, 384, 521 (ECC), 2048, 3072, 4096 (RSA)
    const ALLOWED: [u32; 6] = [256, 384, 521, 2048, 3072, 4096];
    if ALLOWED.contains(&key_size) {
        Ok(())
    } else {
        Err(validator::ValidationError::new("invalid_key_size"))
    }
}

/// Encryption algorithm options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

/// Logging configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Log format
    pub format: LogFormat,
    /// Log output destination
    pub output: LogOutput,
    /// Log file path (required if output is File or Both)
    pub file_path: Option<PathBuf>,
    /// Maximum log file size in bytes
    #[validate(range(min = 1))]
    pub max_file_size_bytes: u64,
    /// Maximum number of rotated log files to keep
    #[validate(range(min = 1, max = 1000))]
    pub max_backup_files: u32,
    /// Enable colored output (for console)
    pub colored: bool,
    /// Include timestamps
    pub include_timestamps: bool,
    /// Include module paths
    pub include_module_path: bool,
}

/// Log level enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Error level
    Error,
    /// Warning level
    Warn,
    /// Info level
    Info,
    /// Debug level
    Debug,
    /// Trace level
    Trace,
}

/// Log format options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Plain text format
    Text,
    /// JSON format
    Json,
    /// Compact format
    Compact,
}

/// Log output destination.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    /// Console output
    Console,
    /// File output
    File,
    /// Both console and file
    Both,
}

/// Metrics configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Validate)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Metrics export format
    pub format: MetricsFormat,
    /// Metrics listen address
    #[validate(length(min = 1))]
    pub listen_addr: String,
    /// Metrics listen port
    #[validate(range(min = 1024, max = 65535))]
    pub listen_port: u16,
    /// Collection interval in seconds
    #[validate(range(min = 1, max = 3600))]
    pub collection_interval_seconds: u64,
    /// Enable histograms
    pub enable_histograms: bool,
    /// Histogram buckets
    #[validate(custom(function = "validate_histogram_buckets"))]
    pub histogram_buckets: Vec<f64>,
    /// Retention period in seconds
    #[validate(range(min = 60))]
    pub retention_seconds: u64,
}

fn validate_histogram_buckets(buckets: &[f64]) -> Result<(), validator::ValidationError> {
    if buckets.is_empty() {
        return Err(validator::ValidationError::new("empty_histogram_buckets"));
    }

    // Check if buckets are in ascending order
    for i in 1..buckets.len() {
        if buckets[i] <= buckets[i - 1] {
            return Err(validator::ValidationError::new(
                "histogram_buckets_not_ascending",
            ));
        }
    }

    Ok(())
}

/// Metrics format options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MetricsFormat {
    /// Prometheus format
    Prometheus,
    /// JSON format
    Json,
    /// StatsD format
    Statsd,
}

/// Namespace-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NamespaceConfig {
    /// Namespace description
    pub description: Option<String>,
    /// Maximum keys allowed in this namespace
    pub max_keys: Option<usize>,
    /// Key generation policies
    pub key_policies: KeyPolicies,
    /// Access control settings
    pub access_control: AccessControl,
    /// Encryption requirements
    pub encryption_required: bool,
    /// Allowed key algorithms
    pub allowed_algorithms: Vec<String>,
}

/// Key generation and management policies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyPolicies {
    /// Allow key generation
    pub allow_generation: bool,
    /// Allow key import
    pub allow_import: bool,
    /// Allow key export
    pub allow_export: bool,
    /// Allow key deletion
    pub allow_deletion: bool,
    /// Require key backup
    pub require_backup: bool,
    /// Key rotation interval in days (0 = no rotation)
    pub rotation_interval_days: u32,
}

/// Access control settings for a namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessControl {
    /// Allowed IP addresses (CIDR notation)
    pub allowed_ips: Vec<String>,
    /// Denied IP addresses (CIDR notation)
    pub denied_ips: Vec<String>,
    /// Require client certificates
    pub require_client_cert: bool,
    /// Allowed client certificate fingerprints
    pub allowed_cert_fingerprints: Vec<String>,
    /// Maximum concurrent sessions
    pub max_concurrent_sessions: usize,
}

impl Default for KeyPolicies {
    fn default() -> Self {
        Self {
            allow_generation: true,
            allow_import: true,
            allow_export: false,
            allow_deletion: true,
            require_backup: false,
            rotation_interval_days: 0,
        }
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        Self {
            allowed_ips: vec![],
            denied_ips: vec![],
            require_client_cert: false,
            allowed_cert_fingerprints: vec![],
            max_concurrent_sessions: 10,
        }
    }
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            description: None,
            max_keys: None,
            key_policies: KeyPolicies::default(),
            access_control: AccessControl::default(),
            encryption_required: true,
            allowed_algorithms: vec![],
        }
    }
}
