//! Integration tests for the config crate.

use hsm_config::{
    validate, AccessControl, ConfigLoader, EncryptionAlgorithm, HsmConfig, KeyPolicies, LogFormat,
    LogLevel, LogOutput, NamespaceConfig, StorageBackend, SyncMode, ValidationError,
};

#[test]
fn test_default_config_creation() {
    let config = HsmConfig::default();

    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 8443);
    assert!(config.server.tls_enabled);
    assert!(config.security.encryption_at_rest);
    assert_eq!(config.logging.level, LogLevel::Info);
    assert!(config.metrics.enabled);
}

#[test]
fn test_development_config() {
    let config = HsmConfig::development();

    assert_eq!(config.server.port, 8080);
    assert!(!config.server.tls_enabled);
    assert_eq!(config.storage.backend, StorageBackend::Memory);
    assert!(!config.security.encryption_at_rest);
    assert_eq!(config.logging.level, LogLevel::Debug);
    assert!(!config.metrics.enabled);
}

#[test]
fn test_production_config() {
    let config = HsmConfig::production();

    assert_eq!(config.server.host, "0.0.0.0");
    assert_eq!(config.server.port, 8443);
    assert!(config.server.tls_enabled);
    assert_eq!(config.storage.sync_mode, SyncMode::Full);
    assert!(config.security.encryption_at_rest);
    assert_eq!(config.security.key_derivation_iterations, 200_000);
    assert_eq!(config.logging.format, LogFormat::Json);
}

#[test]
fn test_test_config() {
    let config = HsmConfig::test();

    assert_eq!(config.server.port, 8888); // Fixed port for tests (port 0 fails validation)
    assert_eq!(config.storage.backend, StorageBackend::Memory);
    assert_eq!(config.security.key_derivation_iterations, 100_000); // Must be >= 100000 for validation
    assert_eq!(config.logging.level, LogLevel::Error);
}

#[test]
fn test_yaml_config_loading() {
    let yaml = r#"
server:
  host: "localhost"
  port: 9000
  max_connections: 500
  timeout_seconds: 60
  tls_enabled: false
  worker_threads: 4

storage:
  backend: "memory"
  data_dir: "/tmp/test"
  cache_size_bytes: 10485760
  wal_enabled: false
  sync_mode: "none"
  max_file_size_bytes: 104857600
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

    let config = ConfigLoader::from_yaml_str(yaml)
        .expect("Failed to parse YAML")
        .build()
        .expect("Failed to build config");

    assert_eq!(config.server.host, "localhost");
    assert_eq!(config.server.port, 9000);
    assert_eq!(config.security.min_password_length, 10);
}

#[test]
fn test_toml_config_loading() {
    let toml_str = r#"
[server]
host = "0.0.0.0"
port = 8080
max_connections = 100
timeout_seconds = 30
tls_enabled = false
worker_threads = 2

[storage]
backend = "file"
data_dir = "/var/lib/hsm"
cache_size_bytes = 104857600
wal_enabled = true
sync_mode = "normal"
max_file_size_bytes = 1073741824
backup_interval_seconds = 3600

[security]
key_derivation_iterations = 100000
encryption_at_rest = true
encryption_algorithm = "aes256gcm"
key_size_bits = 256
session_timeout_seconds = 3600
max_auth_attempts = 3
lockout_duration_seconds = 900
audit_log_enabled = true
require_strong_passwords = true
min_password_length = 12

[logging]
level = "info"
format = "text"
output = "console"
max_file_size_bytes = 104857600
max_backup_files = 10
colored = true
include_timestamps = true
include_module_path = true

[metrics]
enabled = true
format = "prometheus"
listen_addr = "127.0.0.1"
listen_port = 9090
collection_interval_seconds = 60
enable_histograms = true
histogram_buckets = [0.01, 0.1, 1.0, 10.0]
retention_seconds = 86400

[namespaces]
"#;

    let config = ConfigLoader::from_toml_str(toml_str)
        .expect("Failed to parse TOML")
        .build()
        .expect("Failed to build config");

    assert_eq!(config.server.host, "0.0.0.0");
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.storage.backend, StorageBackend::File);
}

#[test]
fn test_namespace_configuration() {
    let mut config = HsmConfig::default();

    let namespace = NamespaceConfig {
        description: Some("Test namespace".to_string()),
        max_keys: Some(1000),
        key_policies: KeyPolicies {
            allow_generation: true,
            allow_import: true,
            allow_export: false,
            allow_deletion: true,
            require_backup: true,
            rotation_interval_days: 90,
        },
        access_control: AccessControl {
            allowed_ips: vec!["192.168.1.0/24".to_string()],
            denied_ips: vec![],
            require_client_cert: true,
            allowed_cert_fingerprints: vec!["abc123".to_string()],
            max_concurrent_sessions: 5,
        },
        encryption_required: true,
        allowed_algorithms: vec!["RSA".to_string(), "ECDSA".to_string()],
    };

    config.namespaces.insert("test".to_string(), namespace);

    assert_eq!(config.namespaces.len(), 1);
    let ns = config.namespaces.get("test").unwrap();
    assert_eq!(ns.max_keys, Some(1000));
    assert!(ns.key_policies.require_backup);
}

#[test]
fn test_yaml_with_namespaces() {
    let yaml = r#"
server:
  host: "127.0.0.1"
  port: 8443
  max_connections: 1000
  timeout_seconds: 30
  tls_enabled: true
  tls_cert_path: "/etc/hsm/cert.pem"
  tls_key_path: "/etc/hsm/key.pem"
  worker_threads: 0

storage:
  backend: "file"
  data_dir: "/var/lib/hsm/data"
  cache_size_bytes: 104857600
  wal_enabled: true
  sync_mode: "normal"
  max_file_size_bytes: 1073741824
  backup_interval_seconds: 3600
  backup_dir: "/var/lib/hsm/backup"

security:
  key_derivation_iterations: 100000
  encryption_at_rest: true
  encryption_algorithm: "aes256gcm"
  key_size_bits: 256
  session_timeout_seconds: 3600
  max_auth_attempts: 3
  lockout_duration_seconds: 900
  audit_log_enabled: true
  audit_log_path: "/var/log/hsm/audit.log"
  require_strong_passwords: true
  min_password_length: 12

logging:
  level: "info"
  format: "text"
  output: "both"
  file_path: "/var/log/hsm/hsm.log"
  max_file_size_bytes: 104857600
  max_backup_files: 10
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
  histogram_buckets: [0.001, 0.01, 0.1, 1.0, 10.0]
  retention_seconds: 86400

namespaces:
  production:
    description: "Production namespace"
    max_keys: 10000
    encryption_required: true
    allowed_algorithms: ["RSA", "ECDSA", "AES"]
    key_policies:
      allow_generation: true
      allow_import: true
      allow_export: false
      allow_deletion: false
      require_backup: true
      rotation_interval_days: 90
    access_control:
      allowed_ips: ["10.0.0.0/8"]
      denied_ips: []
      require_client_cert: true
      allowed_cert_fingerprints: []
      max_concurrent_sessions: 10
  development:
    description: "Development namespace"
    max_keys: 100
    encryption_required: false
    allowed_algorithms: []
    key_policies:
      allow_generation: true
      allow_import: true
      allow_export: true
      allow_deletion: true
      require_backup: false
      rotation_interval_days: 0
    access_control:
      allowed_ips: []
      denied_ips: []
      require_client_cert: false
      allowed_cert_fingerprints: []
      max_concurrent_sessions: 100
"#;

    let config = ConfigLoader::from_yaml_str(yaml)
        .expect("Failed to parse YAML")
        .build_and_validate()
        .expect("Failed to validate config");

    assert_eq!(config.namespaces.len(), 2);
    assert!(config.namespaces.contains_key("production"));
    assert!(config.namespaces.contains_key("development"));

    let prod_ns = config.namespaces.get("production").unwrap();
    assert_eq!(prod_ns.max_keys, Some(10000));
    assert!(prod_ns.encryption_required);
    assert_eq!(prod_ns.key_policies.rotation_interval_days, 90);
}

#[test]
fn test_file_loading_from_tempfile() {
    let yaml = r#"
server:
  host: "test.example.com"
  port: 7777
  max_connections: 250
  timeout_seconds: 45
  tls_enabled: false
  worker_threads: 4

storage:
  backend: "memory"
  data_dir: "/tmp/hsm"
  cache_size_bytes: 5242880
  wal_enabled: false
  sync_mode: "none"
  max_file_size_bytes: 52428800
  backup_interval_seconds: 0

security:
  key_derivation_iterations: 25000
  encryption_at_rest: false
  encryption_algorithm: "chacha20poly1305"
  key_size_bits: 256
  session_timeout_seconds: 1800
  max_auth_attempts: 10
  lockout_duration_seconds: 300
  audit_log_enabled: false
  require_strong_passwords: false
  min_password_length: 8

logging:
  level: "warn"
  format: "compact"
  output: "console"
  max_file_size_bytes: 10485760
  max_backup_files: 3
  colored: false
  include_timestamps: true
  include_module_path: false

metrics:
  enabled: false
  format: "json"
  listen_addr: "0.0.0.0"
  listen_port: 8080
  collection_interval_seconds: 120
  enable_histograms: false
  histogram_buckets: [1.0]
  retention_seconds: 3600

namespaces: {}
"#;

    let temp_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("Failed to create temp file");
    std::fs::write(temp_file.path(), yaml).expect("Failed to write temp file");

    let config = ConfigLoader::from_file(temp_file.path())
        .expect("Failed to load from file")
        .build()
        .expect("Failed to build config");

    assert_eq!(config.server.host, "test.example.com");
    assert_eq!(config.server.port, 7777);
    assert_eq!(
        config.security.encryption_algorithm,
        EncryptionAlgorithm::ChaCha20Poly1305
    );
}

#[test]
fn test_config_validation_success() {
    let config = HsmConfig::default();
    let result = validate(&config);
    assert!(result.is_ok());
}

#[test]
fn test_config_validation_failure_empty_host() {
    let mut config = HsmConfig::default();
    config.server.host = "".to_string();
    let result = validate(&config);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        ValidationError::InvalidHost(_)
    ));
}

#[test]
fn test_config_validation_failure_zero_timeout() {
    let mut config = HsmConfig::default();
    config.server.timeout_seconds = 0;
    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_config_validation_tls_missing_cert() {
    let mut config = HsmConfig::default();
    config.server.tls_enabled = true;
    config.server.tls_cert_path = None;
    config.server.tls_key_path = None;
    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_config_validation_weak_key_derivation() {
    let mut config = HsmConfig::default();
    config.security.key_derivation_iterations = 500;
    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_config_serialization_yaml() {
    let config = HsmConfig::development();
    let yaml = serde_yaml::to_string(&config).expect("Failed to serialize to YAML");
    let deserialized: HsmConfig =
        serde_yaml::from_str(&yaml).expect("Failed to deserialize from YAML");

    assert_eq!(config.server.host, deserialized.server.host);
    assert_eq!(config.server.port, deserialized.server.port);
    assert_eq!(config.storage.backend, deserialized.storage.backend);
}

#[test]
fn test_metrics_config_validation() {
    let mut config = HsmConfig::default();
    config.metrics.enabled = true;
    config.metrics.enable_histograms = true;
    config.metrics.histogram_buckets = vec![]; // Invalid: empty buckets

    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_metrics_histogram_buckets_ordering() {
    let mut config = HsmConfig::default();
    config.metrics.enabled = true;
    config.metrics.enable_histograms = true;
    config.metrics.histogram_buckets = vec![1.0, 0.5, 2.0]; // Invalid: not ascending

    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_storage_backend_variants() {
    let mut config = HsmConfig::default();

    config.storage.backend = StorageBackend::File;
    assert!(validate(&config).is_ok());

    config.storage.backend = StorageBackend::Memory;
    assert!(validate(&config).is_ok());

    config.storage.backend = StorageBackend::Sqlite;
    assert!(validate(&config).is_ok());
}

#[test]
fn test_sync_mode_variants() {
    let mut config = HsmConfig::default();

    config.storage.sync_mode = SyncMode::None;
    assert!(validate(&config).is_ok());

    config.storage.sync_mode = SyncMode::Normal;
    assert!(validate(&config).is_ok());

    config.storage.sync_mode = SyncMode::Full;
    assert!(validate(&config).is_ok());
}

#[test]
fn test_log_level_variants() {
    let levels = vec![
        LogLevel::Error,
        LogLevel::Warn,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Trace,
    ];

    for level in levels {
        let mut config = HsmConfig::default();
        config.logging.level = level;
        assert!(validate(&config).is_ok());
    }
}

#[test]
fn test_log_output_file_requires_path() {
    let mut config = HsmConfig::default();
    config.logging.output = LogOutput::File;
    config.logging.file_path = None;

    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_encryption_algorithm_variants() {
    let mut config = HsmConfig::default();

    config.security.encryption_algorithm = EncryptionAlgorithm::Aes256Gcm;
    assert!(validate(&config).is_ok());

    config.security.encryption_algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
    assert!(validate(&config).is_ok());
}

#[test]
fn test_invalid_key_size() {
    let mut config = HsmConfig::default();
    config.security.key_size_bits = 512; // Invalid: only 128, 192, 256 allowed

    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_session_timeout_bounds() {
    let mut config = HsmConfig::default();

    // Too short
    config.security.session_timeout_seconds = 30;
    assert!(validate(&config).is_err());

    // Too long
    config.security.session_timeout_seconds = 100000;
    assert!(validate(&config).is_err());

    // Valid range
    config.security.session_timeout_seconds = 3600;
    assert!(validate(&config).is_ok());
}

#[test]
fn test_namespace_max_keys_validation() {
    let mut config = HsmConfig::default();
    let namespace = NamespaceConfig {
        max_keys: Some(0), // Invalid: must be > 0
        ..Default::default()
    };

    config.namespaces.insert("test".to_string(), namespace);

    let result = validate(&config);
    assert!(result.is_err());
}

#[test]
fn test_access_control_defaults() {
    let ac = AccessControl::default();
    assert_eq!(ac.allowed_ips.len(), 0);
    assert_eq!(ac.denied_ips.len(), 0);
    assert!(!ac.require_client_cert);
    assert_eq!(ac.max_concurrent_sessions, 10);
}

#[test]
fn test_key_policies_defaults() {
    let kp = KeyPolicies::default();
    assert!(kp.allow_generation);
    assert!(kp.allow_import);
    assert!(!kp.allow_export);
    assert!(kp.allow_deletion);
    assert!(!kp.require_backup);
    assert_eq!(kp.rotation_interval_days, 0);
}

#[test]
fn test_complete_production_workflow() {
    // This test simulates a complete production configuration workflow
    let yaml = r#"
server:
  host: "0.0.0.0"
  port: 8443
  max_connections: 5000
  timeout_seconds: 30
  tls_enabled: true
  tls_cert_path: "/etc/hsm/tls/cert.pem"
  tls_key_path: "/etc/hsm/tls/key.pem"
  worker_threads: 0

storage:
  backend: "file"
  data_dir: "/var/lib/hsm/data"
  cache_size_bytes: 524288000
  wal_enabled: true
  sync_mode: "full"
  max_file_size_bytes: 2147483648
  backup_dir: "/var/lib/hsm/backup"
  backup_interval_seconds: 1800

security:
  key_derivation_iterations: 200000
  encryption_at_rest: true
  encryption_algorithm: "aes256gcm"
  key_size_bits: 256
  session_timeout_seconds: 1800
  max_auth_attempts: 3
  lockout_duration_seconds: 1800
  audit_log_enabled: true
  audit_log_path: "/var/log/hsm/audit.log"
  require_strong_passwords: true
  min_password_length: 16

logging:
  level: "info"
  format: "json"
  output: "both"
  file_path: "/var/log/hsm/hsm.log"
  max_file_size_bytes: 524288000
  max_backup_files: 30
  colored: false
  include_timestamps: true
  include_module_path: true

metrics:
  enabled: true
  format: "prometheus"
  listen_addr: "127.0.0.1"
  listen_port: 9090
  collection_interval_seconds: 30
  enable_histograms: true
  histogram_buckets: [0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
  retention_seconds: 604800

namespaces:
  prod-keys:
    description: "Production key namespace"
    max_keys: 50000
    encryption_required: true
    allowed_algorithms: ["RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"]
    key_policies:
      allow_generation: true
      allow_import: true
      allow_export: false
      allow_deletion: false
      require_backup: true
      rotation_interval_days: 365
    access_control:
      allowed_ips: ["10.0.0.0/8", "172.16.0.0/12"]
      denied_ips: []
      require_client_cert: true
      allowed_cert_fingerprints: []
      max_concurrent_sessions: 100
"#;

    let config = ConfigLoader::from_yaml_str(yaml)
        .expect("Failed to parse production config")
        .build_and_validate()
        .expect("Production config validation failed");

    assert_eq!(config.server.max_connections, 5000);
    assert_eq!(config.security.key_derivation_iterations, 200000);
    assert_eq!(config.storage.sync_mode, SyncMode::Full);
    assert!(config.namespaces.contains_key("prod-keys"));

    let ns = config.namespaces.get("prod-keys").unwrap();
    assert_eq!(ns.max_keys, Some(50000));
    assert!(!ns.key_policies.allow_export);
    assert!(ns.key_policies.require_backup);
}
