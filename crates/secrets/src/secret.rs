//! Core secret types and operations for the secrets manager.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret stored in the secrets manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Unique identifier.
    pub id: SecretId,
    /// Path for hierarchical organization.
    pub path: SecretPath,
    /// Current version number.
    pub current_version: u32,
    /// Metadata (not encrypted).
    pub metadata: SecretMetadata,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Secret identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretId(pub String);

impl SecretId {
    /// Create a new random secret ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create a secret ID from an existing string.
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Path for organizing secrets hierarchically.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretPath(pub String);

impl SecretPath {
    /// Create a new secret path with validation.
    pub fn new(path: impl Into<String>) -> Result<Self, SecretError> {
        let path = path.into();

        // Validate path format
        if path.is_empty() {
            return Err(SecretError::InvalidPath("Path cannot be empty".into()));
        }
        if !path.starts_with('/') {
            return Err(SecretError::InvalidPath("Path must start with /".into()));
        }
        if path.contains("//") {
            return Err(SecretError::InvalidPath("Path cannot contain //".into()));
        }

        Ok(Self(path))
    }

    /// Create a path without validation (use with caution).
    pub fn from_string_unchecked(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Join a segment to this path.
    pub fn join(&self, segment: &str) -> Result<Self, SecretError> {
        if segment.is_empty() {
            return Err(SecretError::InvalidPath("Segment cannot be empty".into()));
        }
        if segment.contains('/') {
            return Err(SecretError::InvalidPath("Segment cannot contain /".into()));
        }

        let new_path = if self.0.ends_with('/') {
            format!("{}{}", self.0, segment)
        } else {
            format!("{}/{}", self.0, segment)
        };
        Self::new(new_path)
    }

    /// Get the parent path.
    pub fn parent(&self) -> Option<Self> {
        let path = self.0.trim_end_matches('/');
        if path.is_empty() {
            return None;
        }
        path.rfind('/').map(|i| {
            let parent = &path[..i];
            if parent.is_empty() {
                Self("/".to_string())
            } else {
                Self(parent.to_string())
            }
        })
    }

    /// Get the name (last segment) of the path.
    pub fn name(&self) -> &str {
        let path = self.0.trim_end_matches('/');
        path.rsplit('/').next().unwrap_or(path)
    }

    /// Get the full path as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this path starts with the given prefix.
    pub fn starts_with(&self, prefix: &SecretPath) -> bool {
        self.0.starts_with(&prefix.0)
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Metadata for a secret (stored unencrypted for querying).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Custom labels.
    pub labels: HashMap<String, String>,
    /// Description.
    pub description: Option<String>,
    /// Rotation configuration.
    pub rotation: Option<RotationConfig>,
    /// Expiration time.
    pub expires_at: Option<DateTime<Utc>>,
    /// Owner identity.
    pub owner: Option<String>,
}

impl SecretMetadata {
    /// Create new empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the owner.
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    /// Add a label.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Set the expiration time.
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set the rotation configuration.
    pub fn with_rotation(mut self, rotation: RotationConfig) -> Self {
        self.rotation = Some(rotation);
        self
    }
}

/// The actual secret data (encrypted at rest).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretData {
    /// Key-value pairs.
    #[zeroize(skip)] // HashMap doesn't implement Zeroize
    pub data: HashMap<String, SecretValue>,
}

impl SecretData {
    /// Create new empty secret data.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Insert a key-value pair.
    pub fn insert(&mut self, key: impl Into<String>, value: SecretValue) {
        self.data.insert(key.into(), value);
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&SecretValue> {
        self.data.get(key)
    }

    /// Remove a value by key.
    pub fn remove(&mut self, key: &str) -> Option<SecretValue> {
        self.data.remove(key)
    }

    /// Check if the data is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the number of key-value pairs.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Get an iterator over the keys.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.data.keys()
    }

    /// Get an iterator over the key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &SecretValue)> {
        self.data.iter()
    }
}

impl Default for SecretData {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretData")
            .field("keys", &self.data.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// A single secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretValue {
    /// A string value.
    String(String),
    /// A binary value.
    Binary(Vec<u8>),
    /// A JSON value.
    Json(serde_json::Value),
}

impl SecretValue {
    /// Create a string value.
    pub fn string(s: impl Into<String>) -> Self {
        SecretValue::String(s.into())
    }

    /// Create a binary value.
    pub fn binary(b: impl Into<Vec<u8>>) -> Self {
        SecretValue::Binary(b.into())
    }

    /// Create a JSON value.
    pub fn json(j: serde_json::Value) -> Self {
        SecretValue::Json(j)
    }

    /// Get as a string reference if this is a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SecretValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            SecretValue::String(s) => s.as_bytes().to_vec(),
            SecretValue::Binary(b) => b.clone(),
            SecretValue::Json(j) => j.to_string().into_bytes(),
        }
    }

    /// Get the type name of this value.
    pub fn type_name(&self) -> &'static str {
        match self {
            SecretValue::String(_) => "string",
            SecretValue::Binary(_) => "binary",
            SecretValue::Json(_) => "json",
        }
    }
}

impl From<String> for SecretValue {
    fn from(s: String) -> Self {
        SecretValue::String(s)
    }
}

impl From<&str> for SecretValue {
    fn from(s: &str) -> Self {
        SecretValue::String(s.to_string())
    }
}

impl From<Vec<u8>> for SecretValue {
    fn from(b: Vec<u8>) -> Self {
        SecretValue::Binary(b)
    }
}

impl From<serde_json::Value> for SecretValue {
    fn from(j: serde_json::Value) -> Self {
        SecretValue::Json(j)
    }
}

/// Rotation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Rotation interval.
    pub interval: RotationInterval,
    /// Rotation function/engine.
    pub engine: String,
    /// Engine-specific configuration.
    pub config: serde_json::Value,
    /// Last rotation time.
    pub last_rotated_at: Option<DateTime<Utc>>,
    /// Next scheduled rotation.
    pub next_rotation_at: Option<DateTime<Utc>>,
}

impl RotationConfig {
    /// Create a new rotation config.
    pub fn new(interval: RotationInterval, engine: impl Into<String>) -> Self {
        Self {
            interval,
            engine: engine.into(),
            config: serde_json::Value::Null,
            last_rotated_at: None,
            next_rotation_at: None,
        }
    }

    /// Set the engine configuration.
    pub fn with_config(mut self, config: serde_json::Value) -> Self {
        self.config = config;
        self
    }
}

/// Rotation interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationInterval {
    /// Rotate every N seconds.
    Seconds(u64),
    /// Rotate every N days.
    Days(u32),
    /// Cron expression.
    Cron(String),
    /// Manual rotation only.
    Manual,
}

impl RotationInterval {
    /// Get the duration in seconds, if applicable.
    pub fn as_seconds(&self) -> Option<u64> {
        match self {
            RotationInterval::Seconds(s) => Some(*s),
            RotationInterval::Days(d) => Some(*d as u64 * 24 * 60 * 60),
            RotationInterval::Cron(_) => None,
            RotationInterval::Manual => None,
        }
    }
}

/// Errors that can occur during secret operations.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Version not found: {0}")]
    VersionNotFound(u32),

    #[error("Secret already exists: {0}")]
    AlreadyExists(String),

    #[error("Access denied")]
    AccessDenied,

    #[error("Lease expired")]
    LeaseExpired,

    #[error("Rotation failed: {0}")]
    RotationFailed(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_id_generation() {
        let id1 = SecretId::new();
        let id2 = SecretId::new();
        assert_ne!(id1, id2);
        assert!(!id1.as_str().is_empty());
    }

    #[test]
    fn test_secret_path_validation() {
        // Valid paths
        assert!(SecretPath::new("/").is_ok());
        assert!(SecretPath::new("/app").is_ok());
        assert!(SecretPath::new("/app/database").is_ok());
        assert!(SecretPath::new("/app/database/prod").is_ok());

        // Invalid paths
        assert!(SecretPath::new("").is_err());
        assert!(SecretPath::new("app").is_err());
        assert!(SecretPath::new("/app//database").is_err());
    }

    #[test]
    fn test_secret_path_join() {
        let path = SecretPath::new("/app").unwrap();
        let joined = path.join("database").unwrap();
        assert_eq!(joined.as_str(), "/app/database");

        // Cannot join with empty or paths containing /
        assert!(path.join("").is_err());
        assert!(path.join("foo/bar").is_err());
    }

    #[test]
    fn test_secret_path_parent() {
        let path = SecretPath::new("/app/database/prod").unwrap();
        let parent = path.parent().unwrap();
        assert_eq!(parent.as_str(), "/app/database");

        let grandparent = parent.parent().unwrap();
        assert_eq!(grandparent.as_str(), "/app");

        let root = SecretPath::new("/").unwrap();
        assert!(root.parent().is_none());
    }

    #[test]
    fn test_secret_path_name() {
        let path = SecretPath::new("/app/database").unwrap();
        assert_eq!(path.name(), "database");

        let root = SecretPath::new("/").unwrap();
        assert_eq!(root.name(), "");
    }

    #[test]
    fn test_secret_data_operations() {
        let mut data = SecretData::new();
        assert!(data.is_empty());

        data.insert("username", SecretValue::string("admin"));
        data.insert("password", SecretValue::string("secret123"));

        assert_eq!(data.len(), 2);
        assert!(!data.is_empty());

        assert_eq!(data.get("username").unwrap().as_str(), Some("admin"));
        assert_eq!(data.get("password").unwrap().as_str(), Some("secret123"));
        assert!(data.get("nonexistent").is_none());

        data.remove("password");
        assert_eq!(data.len(), 1);
    }

    #[test]
    fn test_secret_value_types() {
        let s = SecretValue::string("hello");
        assert_eq!(s.as_str(), Some("hello"));
        assert_eq!(s.type_name(), "string");

        let b = SecretValue::binary(vec![1, 2, 3]);
        assert_eq!(b.as_bytes(), vec![1, 2, 3]);
        assert_eq!(b.type_name(), "binary");

        let j = SecretValue::json(serde_json::json!({"key": "value"}));
        assert_eq!(j.type_name(), "json");
    }

    #[test]
    fn test_secret_metadata_builder() {
        let metadata = SecretMetadata::new()
            .with_description("Test secret")
            .with_owner("admin")
            .with_label("env", "production");

        assert_eq!(metadata.description.unwrap(), "Test secret");
        assert_eq!(metadata.owner.unwrap(), "admin");
        assert_eq!(metadata.labels.get("env").unwrap(), "production");
    }

    #[test]
    fn test_rotation_interval() {
        assert_eq!(RotationInterval::Seconds(3600).as_seconds(), Some(3600));
        assert_eq!(RotationInterval::Days(1).as_seconds(), Some(86400));
        assert!(RotationInterval::Manual.as_seconds().is_none());
    }
}
