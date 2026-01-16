# Module 9: Configuration Management - Phase 2 Enhancements

## Current Status
- ✅ 1,523 lines of code
- ✅ Compiles successfully
- ✅ Basic configuration loading
- ✅ TOML/YAML support

## Performance Enhancements

### 1. Configuration Caching (Priority: HIGH)
**Goal**: < 1μs for config reads

**Tasks**:
- [ ] Cache parsed configuration in memory
- [ ] Use Arc for zero-copy config access
- [ ] Add change detection for hot reload
- [ ] Profile config access overhead
- [ ] Benchmark cached vs uncached

**Cached configuration**:
```rust
use std::sync::Arc;
use parking_lot::RwLock;

pub struct ConfigManager {
    // Cached configuration (read-optimized)
    config: Arc<RwLock<Arc<Config>>>,

    // File watcher for hot reload
    watcher: Watcher,
}

impl ConfigManager {
    pub fn get_config(&self) -> Arc<Config> {
        // Fast read-only access (no cloning)
        self.config.read().clone()
    }

    pub fn reload_config(&self) -> Result<()> {
        let new_config = self.load_from_file()?;

        // Atomic swap
        let mut guard = self.config.write();
        *guard = Arc::new(new_config);

        Ok(())
    }
}

// Usage: zero-cost config access
let config = config_manager.get_config();
let port = config.grpc.port;  // No locks held during access
```

**Target**: < 1μs for config reads

### 2. Lazy Loading (Priority: MEDIUM)
**Goal**: Fast startup time

**Tasks**:
- [ ] Load config sections on-demand
- [ ] Defer optional section parsing
- [ ] Add parallel config loading
- [ ] Profile startup time
- [ ] Optimize parsing performance

## Security Enhancements

### 1. Secret Management (Priority: CRITICAL)
**Goal**: Secure handling of sensitive config values

**Tasks**:
- [ ] Never log sensitive config values
- [ ] Add secret encryption at rest
- [ ] Integrate with secret stores (HashiCorp Vault, AWS Secrets Manager)
- [ ] Add secret rotation
- [ ] Audit secret access

**Secret handling**:
```rust
use secrecy::{Secret, ExposeSecret};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone)]
pub struct Config {
    pub database: DatabaseConfig,
    pub tls: TlsConfig,

    // Sensitive values wrapped in Secret
    #[serde(deserialize_with = "deserialize_secret")]
    pub master_key: Secret<Vec<u8>>,

    #[serde(deserialize_with = "deserialize_secret")]
    pub db_password: Secret<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database", &self.database)
            .field("tls", &self.tls)
            .field("master_key", &"<redacted>")
            .field("db_password", &"<redacted>")
            .finish()
    }
}

// Never log secrets
fn deserialize_secret<'de, D>(deserializer: D) -> Result<Secret<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Secret::new(s))
}
```

### 2. Configuration Validation (Priority: CRITICAL)
**Goal**: Reject invalid configurations

**Tasks**:
- [ ] Add comprehensive validation rules
- [ ] Validate all constraints (ranges, formats)
- [ ] Add security policy validation
- [ ] Test with invalid configs
- [ ] Document validation rules

**Validation**:
```rust
use validator::{Validate, ValidationError};

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct Config {
    #[validate(nested)]
    pub grpc: GrpcConfig,

    #[validate(nested)]
    pub crypto: CryptoConfig,

    #[validate(nested)]
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct GrpcConfig {
    #[validate(range(min = 1024, max = 65535))]
    pub port: u16,

    #[validate(length(min = 1))]
    pub bind_address: String,

    #[validate(range(min = 1, max = 100000))]
    pub max_connections: usize,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CryptoConfig {
    #[validate(custom = "validate_key_sizes")]
    pub allowed_key_sizes: Vec<usize>,

    #[validate(custom = "validate_algorithms")]
    pub enabled_algorithms: Vec<String>,
}

fn validate_key_sizes(sizes: &[usize]) -> Result<(), ValidationError> {
    // Only allow secure key sizes
    let allowed = vec![2048, 3072, 4096, 256, 384, 521];

    for size in sizes {
        if !allowed.contains(size) {
            return Err(ValidationError::new("invalid_key_size"));
        }
    }

    Ok(())
}

impl Config {
    pub fn load_and_validate(path: &Path) -> Result<Self> {
        let config: Config = Self::load_from_file(path)?;

        // Validate all constraints
        config.validate()
            .map_err(|e| ConfigError::ValidationFailed(e))?;

        // Additional security checks
        Self::validate_security_policy(&config)?;

        Ok(config)
    }

    fn validate_security_policy(config: &Config) -> Result<()> {
        // Ensure TLS is enabled
        if !config.tls.enabled {
            return Err(ConfigError::TlsRequired);
        }

        // Ensure minimum key sizes
        if config.crypto.min_key_size < 2048 {
            return Err(ConfigError::InsecureKeySize);
        }

        // Ensure audit logging is enabled
        if !config.audit.enabled {
            return Err(ConfigError::AuditRequired);
        }

        Ok(())
    }
}
```

### 3. Configuration Encryption (Priority: HIGH)
**Goal**: Encrypt sensitive config files

**Tasks**:
- [ ] Encrypt config files at rest
- [ ] Add config decryption on load
- [ ] Implement key derivation from passphrase
- [ ] Add config file integrity checks
- [ ] Test encryption/decryption

**Encrypted config**:
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub struct EncryptedConfigManager {
    cipher: Aes256Gcm,
}

impl EncryptedConfigManager {
    pub fn load_encrypted_config(&self, path: &Path, passphrase: &str) -> Result<Config> {
        // Read encrypted file
        let encrypted_data = std::fs::read(path)?;

        // Extract nonce and ciphertext
        let (nonce, ciphertext) = self.split_nonce_ciphertext(&encrypted_data)?;

        // Derive key from passphrase
        let key = self.derive_key(passphrase)?;

        // Decrypt
        let cipher = Aes256Gcm::new(Key::from_slice(&key));
        let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| ConfigError::DecryptionFailed)?;

        // Parse TOML/YAML
        let config: Config = toml::from_slice(&plaintext)?;

        Ok(config)
    }

    pub fn save_encrypted_config(&self, config: &Config, path: &Path, passphrase: &str) -> Result<()> {
        // Serialize config
        let plaintext = toml::to_vec(config)?;

        // Derive key
        let key = self.derive_key(passphrase)?;

        // Generate nonce
        let nonce = self.generate_nonce();

        // Encrypt
        let cipher = Aes256Gcm::new(Key::from_slice(&key));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| ConfigError::EncryptionFailed)?;

        // Combine nonce + ciphertext
        let encrypted = self.combine_nonce_ciphertext(&nonce, &ciphertext);

        // Write to file
        std::fs::write(path, encrypted)?;

        Ok(())
    }
}
```

### 4. Configuration Access Control (Priority: MEDIUM)
**Goal**: Restrict config access

**Tasks**:
- [ ] Add file permission checks
- [ ] Implement config read auditing
- [ ] Restrict config modifications
- [ ] Add config change logging
- [ ] Test access control

### 5. Secure Defaults (Priority: HIGH)
**Goal**: Security by default

**Tasks**:
- [ ] Set secure default values
- [ ] Require explicit opt-in for insecure settings
- [ ] Add warnings for insecure configs
- [ ] Document security implications
- [ ] Test default configuration

**Secure defaults**:
```rust
impl Default for Config {
    fn default() -> Self {
        Config {
            // TLS enabled by default
            tls: TlsConfig {
                enabled: true,
                min_version: TlsVersion::Tls13,
                client_cert_required: true,
            },

            // Secure crypto defaults
            crypto: CryptoConfig {
                min_key_size: 2048,
                enabled_algorithms: vec![
                    "Ed25519".to_string(),
                    "ECDSA-P256".to_string(),
                    "RSA-2048".to_string(),
                ],
            },

            // Audit enabled by default
            audit: AuditConfig {
                enabled: true,
                log_level: AuditLevel::All,
                tamper_evident: true,
            },

            // Rate limiting enabled
            rate_limiting: RateLimitConfig {
                enabled: true,
                per_identity: 1000,  // requests per minute
                per_namespace: 10000,
            },
        }
    }
}
```

## Feature Enhancements

### 1. Hot Reload (Priority: HIGH)
**Goal**: Update config without restart

**Tasks**:
- [ ] Implement file watching
- [ ] Add config reload trigger
- [ ] Validate before applying changes
- [ ] Add rollback on invalid config
- [ ] Test hot reload functionality

**Hot reload**:
```rust
use notify::{Watcher, RecursiveMode, watcher};
use std::sync::mpsc::channel;

pub struct HotReloadManager {
    config: Arc<RwLock<Arc<Config>>>,
    config_path: PathBuf,
}

impl HotReloadManager {
    pub fn start_watching(&self) -> Result<()> {
        let (tx, rx) = channel();
        let mut watcher = watcher(tx, Duration::from_secs(1))?;

        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;

        let config = self.config.clone();
        let config_path = self.config_path.clone();

        tokio::spawn(async move {
            while let Ok(event) = rx.recv() {
                match event {
                    DebouncedEvent::Write(_) | DebouncedEvent::Create(_) => {
                        info!("Config file changed, reloading...");

                        match Self::load_and_validate(&config_path) {
                            Ok(new_config) => {
                                // Atomic swap
                                let mut guard = config.write();
                                *guard = Arc::new(new_config);

                                info!("Config reloaded successfully");
                            }
                            Err(e) => {
                                error!("Failed to reload config: {}", e);
                                // Keep old config
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }
}
```

### 2. Environment Variable Override (Priority: HIGH)
**Goal**: 12-factor app compatibility

**Tasks**:
- [ ] Support environment variable overrides
- [ ] Add prefix for HSM env vars
- [ ] Document env var naming
- [ ] Test env var precedence
- [ ] Add env var validation

**Environment overrides**:
```rust
use std::env;

impl Config {
    pub fn load_with_env_overrides(path: &Path) -> Result<Self> {
        let mut config = Self::load_from_file(path)?;

        // Override with environment variables
        // Format: HSM_SECTION_KEY

        if let Ok(port) = env::var("HSM_GRPC_PORT") {
            config.grpc.port = port.parse()?;
        }

        if let Ok(bind) = env::var("HSM_GRPC_BIND_ADDRESS") {
            config.grpc.bind_address = bind;
        }

        if let Ok(level) = env::var("HSM_LOG_LEVEL") {
            config.logging.level = level.parse()?;
        }

        // Validate after overrides
        config.validate()?;

        Ok(config)
    }
}
```

### 3. Multi-Environment Support (Priority: MEDIUM)
**Goal**: Different configs per environment

**Tasks**:
- [ ] Support environment-specific configs
- [ ] Add config inheritance
- [ ] Implement config merging
- [ ] Test multi-environment setups
- [ ] Document environment strategy

**Multi-environment**:
```rust
pub struct ConfigLoader {
    base_path: PathBuf,
}

impl ConfigLoader {
    pub fn load_for_environment(&self, env: &str) -> Result<Config> {
        // Load base config
        let base_config = self.load_base()?;

        // Load environment-specific config
        let env_config_path = self.base_path.join(format!("config.{}.toml", env));

        if env_config_path.exists() {
            let env_config: PartialConfig = Self::load_from_file(&env_config_path)?;

            // Merge configs (env overrides base)
            let merged = self.merge_configs(base_config, env_config)?;

            Ok(merged)
        } else {
            Ok(base_config)
        }
    }
}
```

### 4. Schema Validation (Priority: MEDIUM)
**Goal**: Validate config structure

**Tasks**:
- [ ] Add JSON schema for config
- [ ] Validate config against schema
- [ ] Add schema versioning
- [ ] Generate schema docs
- [ ] Test schema validation

### 5. Configuration Templates (Priority: LOW)
**Goal**: Easy config generation

**Tasks**:
- [ ] Add config templates for common scenarios
- [ ] Implement config generator
- [ ] Add interactive config wizard
- [ ] Document templates
- [ ] Test generated configs

## Reliability Enhancements

### 1. Configuration Versioning (Priority: HIGH)
**Goal**: Track config changes

**Tasks**:
- [ ] Add config version field
- [ ] Implement version migration
- [ ] Add backward compatibility checks
- [ ] Test version upgrades
- [ ] Document version history

**Versioning**:
```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "version")]
pub enum ConfigVersion {
    #[serde(rename = "1.0")]
    V1_0(ConfigV1_0),

    #[serde(rename = "2.0")]
    V2_0(ConfigV2_0),
}

impl ConfigVersion {
    pub fn migrate_to_latest(self) -> Result<Config> {
        match self {
            ConfigVersion::V1_0(v1) => {
                // Migrate V1 to V2
                let v2 = Self::migrate_v1_to_v2(v1)?;
                Ok(v2.into())
            }
            ConfigVersion::V2_0(v2) => {
                Ok(v2.into())
            }
        }
    }
}
```

### 2. Configuration Backup (Priority: MEDIUM)
**Goal**: Backup config before changes

**Tasks**:
- [ ] Auto-backup config on changes
- [ ] Add config rollback
- [ ] Implement config history
- [ ] Test backup/restore
- [ ] Document backup procedures

### 3. Validation on Startup (Priority: CRITICAL)
**Goal**: Fail fast on invalid config

**Tasks**:
- [ ] Validate config before starting services
- [ ] Add startup health checks
- [ ] Test with invalid configs
- [ ] Add helpful error messages
- [ ] Document validation errors

**Startup validation**:
```rust
pub struct HsmServer {
    config: Arc<Config>,
}

impl HsmServer {
    pub async fn start() -> Result<Self> {
        // Load and validate config FIRST
        let config = Config::load_and_validate("config.toml")?;

        // Validate dependencies are available
        Self::validate_dependencies(&config).await?;

        // Validate certificates exist and are valid
        Self::validate_certificates(&config).await?;

        // Validate storage is accessible
        Self::validate_storage(&config).await?;

        // All checks passed - start server
        let server = Self {
            config: Arc::new(config),
        };

        Ok(server)
    }

    async fn validate_dependencies(config: &Config) -> Result<()> {
        // Check database connection
        if let Some(ref db_config) = config.database {
            db_config.test_connection().await?;
        }

        // Check storage directory exists and is writable
        tokio::fs::metadata(&config.storage.data_dir).await?;

        Ok(())
    }
}
```

### 4. Configuration Monitoring (Priority: MEDIUM)
**Goal**: Monitor config changes

**Tasks**:
- [ ] Add metrics for config reloads
- [ ] Track config change events
- [ ] Alert on config validation failures
- [ ] Add config audit trail
- [ ] Monitor config file integrity

## Testing Enhancements

### 1. Validation Tests (Priority: CRITICAL)
**Goal**: Comprehensive validation coverage

**Tasks**:
- [ ] Test all validation rules
- [ ] Test with invalid values
- [ ] Test edge cases
- [ ] Test security policy enforcement
- [ ] Achieve 100% validation coverage

**Validation tests**:
```rust
#[test]
fn test_invalid_port_rejected() {
    let config = Config {
        grpc: GrpcConfig {
            port: 99999,  // Invalid port
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn test_insecure_key_size_rejected() {
    let config = Config {
        crypto: CryptoConfig {
            min_key_size: 1024,  // Too small
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(Config::validate_security_policy(&config).is_err());
}

#[test]
fn test_tls_disabled_rejected() {
    let config = Config {
        tls: TlsConfig {
            enabled: false,  // Insecure
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(Config::validate_security_policy(&config).is_err());
}
```

### 2. Hot Reload Tests (Priority: HIGH)
**Goal**: Verify hot reload works

**Tasks**:
- [ ] Test config file changes
- [ ] Test validation during reload
- [ ] Test rollback on invalid config
- [ ] Test concurrent reloads
- [ ] Verify no downtime

### 3. Secret Handling Tests (Priority: HIGH)
**Goal**: Verify secrets never leak

**Tasks**:
- [ ] Test secrets are redacted in logs
- [ ] Test secrets are redacted in debug output
- [ ] Test secret encryption
- [ ] Verify secret zeroization
- [ ] Audit all secret access points

### 4. Multi-Environment Tests (Priority: MEDIUM)
**Goal**: Test config merging

**Tasks**:
- [ ] Test base config loading
- [ ] Test environment overrides
- [ ] Test config merging logic
- [ ] Test env var overrides
- [ ] Verify precedence order

## Success Metrics

**Performance**:
- ✅ Config read: < 1μs (cached)
- ✅ Hot reload: < 100ms
- ✅ Startup validation: < 1s

**Security**:
- ✅ Secrets never logged
- ✅ All configs validated
- ✅ Secure defaults enforced
- ✅ Config encryption works

**Reliability**:
- ✅ Hot reload works without downtime
- ✅ Invalid configs rejected at startup
- ✅ Config backup/restore works
- ✅ > 95% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement secret management with redaction
4. Add comprehensive validation
5. Implement hot reload functionality
6. Add secure defaults
7. Verify secrets never leak
8. Test validation thoroughly
9. Achieve all success metrics
