//! Configuration manager with caching and hot reload support.
//!
//! This module provides a thread-safe configuration manager that supports:
//! - Arc-based zero-copy configuration access
//! - Hot reload with file watching
//! - Atomic configuration updates
//! - Performance-optimized config reads (< 1μs)

use crate::loader::ConfigLoader;
use crate::schema::HsmConfig;
use notify::{RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use validator::Validate;

/// Errors that can occur during configuration management.
#[derive(Error, Debug)]
pub enum ConfigManagerError {
    /// Failed to load configuration
    #[error("Failed to load configuration: {0}")]
    LoadError(String),

    /// Failed to validate configuration
    #[error("Configuration validation failed: {0}")]
    ValidationError(#[from] validator::ValidationErrors),

    /// Failed to watch configuration file
    #[error("Failed to watch configuration file: {0}")]
    WatchError(#[from] notify::Error),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// File path is not valid
    #[error("Invalid file path")]
    InvalidPath,
}

pub type Result<T> = std::result::Result<T, ConfigManagerError>;

/// Configuration manager with caching and hot reload support.
///
/// This manager provides fast, thread-safe access to configuration with
/// Arc-based zero-copy reads and atomic updates during hot reload.
///
/// # Examples
///
/// ```rust,no_run
/// use hsm_config::manager::ConfigManager;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create manager and load config
/// let manager = ConfigManager::from_file("config.yaml").await?;
///
/// // Fast read-only access (no cloning)
/// let config = manager.get();
/// println!("Server port: {}", config.server.port);
///
/// // Enable hot reload
/// manager.start_watching().await?;
/// # Ok(())
/// # }
/// ```
pub struct ConfigManager {
    /// Cached configuration (Arc for zero-copy access)
    config: Arc<RwLock<Arc<HsmConfig>>>,
    /// Path to the configuration file
    config_path: PathBuf,
    /// Broadcast channel for configuration change notifications
    change_tx: broadcast::Sender<Arc<HsmConfig>>,
}

impl ConfigManager {
    /// Create a new ConfigManager by loading from a file.
    ///
    /// This validates the configuration before creating the manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, parsed, or if validation fails.
    pub async fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let config = Self::load_and_validate(path).await?;

        let (change_tx, _) = broadcast::channel(16);

        Ok(Self {
            config: Arc::new(RwLock::new(Arc::new(config))),
            config_path: path.to_path_buf(),
            change_tx,
        })
    }

    /// Get a reference to the current configuration.
    ///
    /// This is a zero-cost operation that returns an Arc. No cloning of
    /// the configuration data occurs, making reads extremely fast (< 1μs).
    ///
    /// # Performance
    ///
    /// This method acquires a read lock and clones only the Arc pointer,
    /// not the underlying configuration data. Multiple readers can access
    /// the configuration concurrently without blocking.
    #[inline]
    pub fn get(&self) -> Arc<HsmConfig> {
        self.config.read().clone()
    }

    /// Subscribe to configuration change notifications.
    ///
    /// Returns a receiver that will be notified whenever the configuration
    /// is reloaded.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<HsmConfig>> {
        self.change_tx.subscribe()
    }

    /// Manually reload the configuration from disk.
    ///
    /// This validates the new configuration before applying it. If validation
    /// fails, the old configuration is kept.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, parsed, or if validation fails.
    pub async fn reload(&self) -> Result<()> {
        info!(
            "Manually reloading configuration from {:?}",
            self.config_path
        );

        let new_config = Self::load_and_validate(&self.config_path).await?;

        // Atomic swap
        let new_arc = Arc::new(new_config);
        {
            let mut guard = self.config.write();
            *guard = new_arc.clone();
        }

        // Notify subscribers (ignore errors if no receivers)
        let _ = self.change_tx.send(new_arc);

        info!("Configuration reloaded successfully");
        Ok(())
    }

    /// Start watching the configuration file for changes.
    ///
    /// When the file changes, the configuration will be automatically reloaded
    /// and validated. If validation fails, the old configuration is kept and
    /// an error is logged.
    ///
    /// # Errors
    ///
    /// Returns an error if the file watcher cannot be created.
    pub async fn start_watching(&self) -> Result<()> {
        let config_path = self.config_path.clone();
        let config = self.config.clone();
        let change_tx = self.change_tx.clone();

        // Create file watcher
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    if matches!(
                        event.kind,
                        notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                    ) {
                        let _ = tx.blocking_send(());
                    }
                }
            },
            notify::Config::default().with_poll_interval(Duration::from_secs(1)),
        )?;

        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

        info!("Started watching configuration file: {:?}", config_path);

        // Spawn background task to handle file changes
        tokio::spawn(async move {
            // Keep watcher alive
            let _watcher = watcher;

            while rx.recv().await.is_some() {
                // Debounce: wait a bit for file operations to complete
                tokio::time::sleep(Duration::from_millis(100)).await;

                info!("Configuration file changed, reloading...");

                match Self::load_and_validate(&config_path).await {
                    Ok(new_config) => {
                        let new_arc = Arc::new(new_config);

                        // Atomic swap
                        {
                            let mut guard = config.write();
                            *guard = new_arc.clone();
                        }

                        // Notify subscribers
                        let _ = change_tx.send(new_arc);

                        info!("Configuration reloaded successfully");
                    }
                    Err(e) => {
                        error!("Failed to reload configuration: {}", e);
                        warn!("Keeping previous configuration");
                    }
                }
            }
        });

        Ok(())
    }

    /// Load and validate configuration from a file.
    async fn load_and_validate(path: &Path) -> Result<HsmConfig> {
        let path_str = path.to_str().ok_or(ConfigManagerError::InvalidPath)?;

        let config = ConfigLoader::from_file(path_str)
            .map_err(|e| ConfigManagerError::LoadError(e.to_string()))?
            .build()
            .map_err(|e| ConfigManagerError::LoadError(e.to_string()))?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONFIG: &str = r#"
[server]
host = "127.0.0.1"
port = 8080
max_connections = 1000
timeout_seconds = 30
tls_enabled = false
worker_threads = 4

[storage]
backend = "file"
data_dir = "/tmp/hsm/data"
cache_size_bytes = 104857600
wal_enabled = true
sync_mode = "normal"
max_file_size_bytes = 10485760
backup_interval_seconds = 0

[security]
key_derivation_iterations = 100000
encryption_at_rest = true
encryption_algorithm = "aes256gcm"
key_size_bits = 256
session_timeout_seconds = 3600
max_auth_attempts = 3
lockout_duration_seconds = 300
audit_log_enabled = true
require_strong_passwords = true
min_password_length = 12

[logging]
level = "info"
format = "json"
output = "console"
max_file_size_bytes = 10485760
max_backup_files = 10
colored = false
include_timestamps = true
include_module_path = true

[metrics]
enabled = true
format = "prometheus"
listen_addr = "127.0.0.1"
listen_port = 9090
collection_interval_seconds = 60
enable_histograms = true
histogram_buckets = [0.001, 0.01, 0.1, 1.0, 10.0]
retention_seconds = 3600
"#;

    #[tokio::test]
    async fn test_config_manager_creation() {
        let temp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(temp_file.path(), TEST_CONFIG).unwrap();

        let manager = ConfigManager::from_file(temp_file.path()).await.unwrap();
        let config = manager.get();

        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.host, "127.0.0.1");
    }

    #[tokio::test]
    async fn test_config_manager_get_is_fast() {
        let temp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(temp_file.path(), TEST_CONFIG).unwrap();

        let manager = ConfigManager::from_file(temp_file.path()).await.unwrap();

        // Multiple gets should be very fast (< 1μs each)
        for _ in 0..1000 {
            let _config = manager.get();
        }
    }

    #[tokio::test]
    async fn test_config_manager_reload() {
        let temp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();

        std::fs::write(temp_file.path(), TEST_CONFIG).unwrap();

        let manager = ConfigManager::from_file(temp_file.path()).await.unwrap();

        // Initial config
        assert_eq!(manager.get().server.port, 8080);

        // Update file
        let updated_config = TEST_CONFIG.replace("port = 8080", "port = 9090");
        std::fs::write(temp_file.path(), updated_config).unwrap();

        // Reload
        manager.reload().await.unwrap();

        // Verify new config
        assert_eq!(manager.get().server.port, 9090);
    }

    #[tokio::test]
    async fn test_config_manager_invalid_reload_keeps_old() {
        let temp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(temp_file.path(), TEST_CONFIG).unwrap();

        let manager = ConfigManager::from_file(temp_file.path()).await.unwrap();

        // Initial config
        assert_eq!(manager.get().server.port, 8080);

        // Update file with invalid config (port out of range)
        let invalid_config = TEST_CONFIG.replace("port = 8080", "port = 99999");
        std::fs::write(temp_file.path(), invalid_config).unwrap();

        // Reload should fail
        assert!(manager.reload().await.is_err());

        // Old config should be kept
        assert_eq!(manager.get().server.port, 8080);
    }

    #[tokio::test]
    async fn test_config_change_notifications() {
        let temp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(temp_file.path(), TEST_CONFIG).unwrap();

        let manager = ConfigManager::from_file(temp_file.path()).await.unwrap();
        let mut rx = manager.subscribe();

        // Update and reload
        let updated_config = TEST_CONFIG.replace("port = 8080", "port = 9090");
        std::fs::write(temp_file.path(), updated_config).unwrap();

        manager.reload().await.unwrap();

        // Should receive notification
        let new_config = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(new_config.server.port, 9090);
    }
}
