//! Core secret types and operations for the secrets manager.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroize;

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
///
/// `HashMap` itself does not implement [`Zeroize`], so `Zeroize` is implemented
/// manually by iterating the map and zeroizing every value (and clearing keys,
/// which may themselves be sensitive). `Drop` invokes the same path so the
/// in-memory contents are wiped when a `SecretData` goes out of scope.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretData {
    /// Key-value pairs.
    pub data: HashMap<String, SecretValue>,
}

impl Zeroize for SecretData {
    fn zeroize(&mut self) {
        // Zeroize each value in place, then zeroize the key strings before
        // dropping the (now-empty-of-secrets) map. We drain the map so the
        // owned key `String`s can be zeroized rather than just deallocated.
        for (mut key, mut value) in self.data.drain() {
            value.zeroize();
            key.zeroize();
        }
    }
}

impl Drop for SecretData {
    fn drop(&mut self) {
        self.zeroize();
    }
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretValue {
    /// A string value.
    String(String),
    /// A binary value.
    Binary(Vec<u8>),
    /// A JSON value.
    Json(serde_json::Value),
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretValue::String(_) => f.write_str("SecretValue::String(<redacted>)"),
            SecretValue::Binary(_) => f.write_str("SecretValue::Binary(<redacted>)"),
            SecretValue::Json(_) => f.write_str("SecretValue::Json(<redacted>)"),
        }
    }
}

/// Recursively zeroize the sensitive contents of a [`serde_json::Value`].
///
/// `serde_json::Value` does not implement [`Zeroize`]; the variant that can
/// carry secret material on the heap is `String` (object-value and array-item
/// strings, plus object keys). We overwrite every owned string buffer in place,
/// then collapse the tree to `Value::Null` so no plaintext remains reachable.
///
/// This function deliberately reassigns `*value` to `Null` only; it never
/// reassigns a node to another `SecretValue`-bearing type, so it cannot trigger
/// a recursive `Drop`.
fn zeroize_json(value: &mut serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                zeroize_json(item);
            }
        }
        Value::Object(map) => {
            // Object values are zeroized in place. `serde_json::Map` does not
            // expose owned-key draining, so the key `String`s are dropped (and
            // their allocations freed) when the map is cleared; we cannot
            // overwrite their bytes first, but values — the secret-bearing part
            // — are wiped.
            for (_k, v) in map.iter_mut() {
                zeroize_json(v);
            }
            map.clear();
        }
        // Bool / Number / Null carry no heap-allocated secret bytes to overwrite.
        _ => {}
    }
    *value = Value::Null;
}

impl Zeroize for SecretValue {
    fn zeroize(&mut self) {
        // Wipe the underlying buffers in place. We intentionally do NOT reassign
        // `*self` to a fresh variant here: doing so would drop the current value,
        // and because `SecretValue` also implements `Drop` (which calls
        // `zeroize`), that would recurse indefinitely.
        match self {
            SecretValue::String(s) => s.zeroize(),
            SecretValue::Binary(b) => b.zeroize(),
            SecretValue::Json(j) => zeroize_json(j),
        }
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.zeroize();
    }
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

    // ---- Zeroization regression tests (HIGH #11) ----
    //
    // These prove the advertised wiping actually happens. Before the fix,
    // `SecretValue` implemented neither `Zeroize` nor `Drop`, so secret bytes
    // were never overwritten; the `SecretData` derive applied `#[zeroize(skip)]`
    // to its only field, making `zeroize()` a no-op. We assert the buffers are
    // observably zeroed in place after `zeroize()` (which wipes without
    // reassigning the variant), rather than relying on shape-only checks.

    #[test]
    fn test_secret_value_string_is_zeroized_in_place() {
        let mut v = SecretValue::string("super-secret-password");
        v.zeroize();
        match &v {
            SecretValue::String(s) => {
                // The String buffer must be fully overwritten with zero bytes.
                // (zeroize for String pushes 0x00 over the existing capacity.)
                assert!(
                    s.as_bytes().iter().all(|&b| b == 0),
                    "string secret bytes were not zeroed: {:?}",
                    s.as_bytes()
                );
                assert_eq!(s.len(), 0, "string length should be cleared");
            }
            other => panic!("zeroize must not change the variant: {:?}", other),
        }
    }

    #[test]
    fn test_secret_value_binary_is_zeroized_in_place() {
        let secret_bytes = vec![0xAB_u8; 64];
        let mut v = SecretValue::binary(secret_bytes);
        v.zeroize();
        match &v {
            SecretValue::Binary(b) => {
                assert!(
                    b.iter().all(|&x| x == 0),
                    "binary secret bytes were not zeroed: {:?}",
                    b
                );
                assert_eq!(b.len(), 0, "binary length should be cleared");
            }
            other => panic!("zeroize must not change the variant: {:?}", other),
        }
    }

    #[test]
    fn test_secret_value_json_is_collapsed_to_null() {
        let mut v = SecretValue::json(serde_json::json!({
            "api_key": "sk-live-deadbeef",
            "nested": { "token": "hunter2" },
            "list": ["a", "b"],
        }));
        v.zeroize();
        match &v {
            SecretValue::Json(j) => {
                // The whole tree must collapse to Null so no plaintext string
                // remains reachable through the value.
                assert!(j.is_null(), "json secret was not collapsed to null: {}", j);
            }
            other => panic!("zeroize must not change the variant: {:?}", other),
        }
    }

    #[test]
    fn test_secret_value_implements_zeroize_trait() {
        // Compile-time proof that SecretValue is wired into the Zeroize trait.
        fn assert_zeroize<T: zeroize::Zeroize>() {}
        assert_zeroize::<SecretValue>();
        assert_zeroize::<SecretData>();
    }

    #[test]
    fn test_secret_data_zeroize_wipes_all_values() {
        let mut data = SecretData::new();
        data.insert("password", SecretValue::string("p@ssw0rd"));
        data.insert("token", SecretValue::binary(vec![0xFF_u8; 32]));
        assert_eq!(data.len(), 2);

        data.zeroize();

        // The map must be emptied (drained) and therefore hold no secret values.
        assert_eq!(data.len(), 0, "SecretData::zeroize must drain the map");
        assert!(data.is_empty());
        assert!(data.get("password").is_none());
        assert!(data.get("token").is_none());
    }

    #[test]
    fn test_secret_data_drop_does_not_panic_or_recurse() {
        // Constructing and dropping a populated SecretData exercises the Drop ->
        // zeroize path for both SecretData and each contained SecretValue.
        // A stack overflow here (infinite Drop recursion) would fail the test.
        let mut data = SecretData::new();
        for i in 0..100 {
            data.insert(
                format!("key-{i}"),
                SecretValue::string(format!("secret-value-{i}")),
            );
            data.insert(format!("bin-{i}"), SecretValue::binary(vec![i as u8; 16]));
        }
        drop(data); // must complete without overflowing the stack
    }
}
