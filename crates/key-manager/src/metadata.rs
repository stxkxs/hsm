use super::key::{KeyId, KeyState, KeyType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Key metadata (everything except the key material itself)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub key_type: KeyType,
    pub state: KeyState,
    pub namespace: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
    pub previous_version: Option<KeyId>,
    pub operation_count: u64,
    pub labels: HashMap<String, String>,
    pub fingerprint: String, // SHA-256 of public key or key ID
}

impl KeyMetadata {
    pub fn from_key(key: &super::key::Key) -> Self {
        Self {
            id: key.id,
            key_type: key.key_type,
            state: key.state,
            namespace: key.namespace.clone(),
            created_at: key.created_at,
            updated_at: Utc::now(),
            version: key.version,
            previous_version: key.previous_version,
            operation_count: key.operation_count,
            labels: HashMap::new(),
            fingerprint: Self::compute_fingerprint(&key.id),
        }
    }

    fn compute_fingerprint(key_id: &KeyId) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key_id.as_string().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Filter for querying keys
#[derive(Debug, Clone, Default)]
pub struct KeyFilter {
    pub key_type: Option<KeyType>,
    pub state: Option<KeyState>,
    pub labels: HashMap<String, String>,
}
