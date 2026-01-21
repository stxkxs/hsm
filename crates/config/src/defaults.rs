//! Default configuration values for the HSM system.

use crate::schema::*;
use std::path::PathBuf;

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8443,
            max_connections: 1000,
            timeout_seconds: 30,
            tls_enabled: true,
            tls_cert_path: Some(PathBuf::from("/etc/hsm/tls/cert.pem")),
            tls_key_path: Some(PathBuf::from("/etc/hsm/tls/key.pem")),
            worker_threads: 0, // 0 = number of CPU cores
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::File,
            data_dir: PathBuf::from("/var/lib/hsm/data"),
            cache_size_bytes: 100 * 1024 * 1024, // 100 MB
            wal_enabled: true,
            sync_mode: SyncMode::Normal,
            max_file_size_bytes: 1024 * 1024 * 1024, // 1 GB
            backup_dir: Some(PathBuf::from("/var/lib/hsm/backup")),
            backup_interval_seconds: 3600, // 1 hour
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            key_derivation_iterations: 100_000,
            encryption_at_rest: true,
            encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
            key_size_bits: 256,
            session_timeout_seconds: 3600, // 1 hour
            max_auth_attempts: 3,
            lockout_duration_seconds: 900, // 15 minutes
            audit_log_enabled: true,
            audit_log_path: Some(PathBuf::from("/var/log/hsm/audit.log")),
            require_strong_passwords: true,
            min_password_length: 12,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
            output: LogOutput::Both,
            file_path: Some(PathBuf::from("/var/log/hsm/hsm.log")),
            max_file_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_backup_files: 10,
            colored: true,
            include_timestamps: true,
            include_module_path: true,
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            format: MetricsFormat::Prometheus,
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 9090,
            collection_interval_seconds: 60,
            enable_histograms: true,
            histogram_buckets: vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
            retention_seconds: 86400, // 24 hours
        }
    }
}

impl HsmConfig {
    /// Creates a new configuration with all default values.
    pub fn with_defaults() -> Self {
        Self::default()
    }

    /// Creates a development configuration with relaxed security settings.
    pub fn development() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                max_connections: 100,
                timeout_seconds: 60,
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
                worker_threads: 2,
            },
            storage: StorageConfig {
                backend: StorageBackend::Memory,
                data_dir: PathBuf::from("./data"),
                cache_size_bytes: 10 * 1024 * 1024, // 10 MB
                wal_enabled: false,
                sync_mode: SyncMode::None,
                max_file_size_bytes: 100 * 1024 * 1024, // 100 MB
                backup_dir: None,
                backup_interval_seconds: 0, // Disabled
            },
            security: SecurityConfig {
                key_derivation_iterations: 100_000, // Must be >= 100000
                encryption_at_rest: false,
                encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
                key_size_bits: 256,
                session_timeout_seconds: 86400, // 24 hours
                max_auth_attempts: 10,          // Must be between 1 and 10
                lockout_duration_seconds: 60,   // Must be >= 60
                audit_log_enabled: false,
                audit_log_path: None,
                require_strong_passwords: false,
                min_password_length: 8, // Must be >= 8
            },
            logging: LoggingConfig {
                level: LogLevel::Debug,
                format: LogFormat::Compact,
                output: LogOutput::Console,
                file_path: None,
                max_file_size_bytes: 10 * 1024 * 1024, // 10 MB
                max_backup_files: 3,
                colored: true,
                include_timestamps: true,
                include_module_path: true,
            },
            metrics: MetricsConfig {
                enabled: false,
                format: MetricsFormat::Prometheus,
                listen_addr: "127.0.0.1".to_string(),
                listen_port: 9090,
                collection_interval_seconds: 60,
                enable_histograms: false,
                histogram_buckets: vec![0.1, 1.0, 10.0],
                retention_seconds: 3600, // 1 hour
            },
            namespaces: Default::default(),
        }
    }

    /// Creates a production configuration with enhanced security settings.
    pub fn production() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8443,
                max_connections: 5000,
                timeout_seconds: 30,
                tls_enabled: true,
                tls_cert_path: Some(PathBuf::from("/etc/hsm/tls/cert.pem")),
                tls_key_path: Some(PathBuf::from("/etc/hsm/tls/key.pem")),
                worker_threads: 0, // Auto-detect CPU cores
            },
            storage: StorageConfig {
                backend: StorageBackend::File,
                data_dir: PathBuf::from("/var/lib/hsm/data"),
                cache_size_bytes: 500 * 1024 * 1024, // 500 MB
                wal_enabled: true,
                sync_mode: SyncMode::Full,
                max_file_size_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
                backup_dir: Some(PathBuf::from("/var/lib/hsm/backup")),
                backup_interval_seconds: 1800, // 30 minutes
            },
            security: SecurityConfig {
                key_derivation_iterations: 200_000, // Enhanced security
                encryption_at_rest: true,
                encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
                key_size_bits: 256,
                session_timeout_seconds: 1800, // 30 minutes
                max_auth_attempts: 3,
                lockout_duration_seconds: 1800, // 30 minutes
                audit_log_enabled: true,
                audit_log_path: Some(PathBuf::from("/var/log/hsm/audit.log")),
                require_strong_passwords: true,
                min_password_length: 16,
            },
            logging: LoggingConfig {
                level: LogLevel::Info,
                format: LogFormat::Json,
                output: LogOutput::Both,
                file_path: Some(PathBuf::from("/var/log/hsm/hsm.log")),
                max_file_size_bytes: 500 * 1024 * 1024, // 500 MB
                max_backup_files: 30,
                colored: false,
                include_timestamps: true,
                include_module_path: true,
            },
            metrics: MetricsConfig {
                enabled: true,
                format: MetricsFormat::Prometheus,
                listen_addr: "127.0.0.1".to_string(),
                listen_port: 9090,
                collection_interval_seconds: 30,
                enable_histograms: true,
                histogram_buckets: vec![
                    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                    10.0,
                ],
                retention_seconds: 604800, // 7 days
            },
            namespaces: Default::default(),
        }
    }

    /// Creates a test configuration optimized for testing.
    pub fn test() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8888, // Fixed port for tests (port 0 fails range validation)
                max_connections: 10,
                timeout_seconds: 5,
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
                worker_threads: 1,
            },
            storage: StorageConfig {
                backend: StorageBackend::Memory,
                data_dir: PathBuf::from("/tmp/hsm-test"),
                cache_size_bytes: 1024 * 1024, // 1 MB
                wal_enabled: false,
                sync_mode: SyncMode::None,
                max_file_size_bytes: 10 * 1024 * 1024, // 10 MB
                backup_dir: None,
                backup_interval_seconds: 0,
            },
            security: SecurityConfig {
                key_derivation_iterations: 100_000, // Must be >= 100000
                encryption_at_rest: false,
                encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
                key_size_bits: 256,
                session_timeout_seconds: 3600,
                max_auth_attempts: 10,
                lockout_duration_seconds: 60, // Must be >= 60
                audit_log_enabled: false,
                audit_log_path: None,
                require_strong_passwords: false,
                min_password_length: 8, // Must be >= 8
            },
            logging: LoggingConfig {
                level: LogLevel::Error,
                format: LogFormat::Compact,
                output: LogOutput::Console,
                file_path: None,
                max_file_size_bytes: 1024 * 1024, // 1 MB
                max_backup_files: 1,
                colored: false,
                include_timestamps: false,
                include_module_path: false,
            },
            metrics: MetricsConfig {
                enabled: false,
                format: MetricsFormat::Prometheus,
                listen_addr: "127.0.0.1".to_string(),
                listen_port: 9999, // Must be >= 1024
                collection_interval_seconds: 3600,
                enable_histograms: false,
                histogram_buckets: vec![1.0],
                retention_seconds: 60,
            },
            namespaces: Default::default(),
        }
    }
}
