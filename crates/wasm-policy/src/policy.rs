//! Policy types and metadata.

use crate::limits::ResourceLimits;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Unique identifier for a policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(pub String);

impl PolicyId {
    /// Create a new policy ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for PolicyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PolicyId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Decision returned by a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum PolicyDecision {
    /// Deny the transaction.
    Deny = 0,
    /// Allow the transaction.
    Allow = 1,
    /// Require additional approval.
    RequireApproval = 2,
}

impl PolicyDecision {
    /// Convert from i32 (WASM return value).
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(PolicyDecision::Deny),
            1 => Some(PolicyDecision::Allow),
            2 => Some(PolicyDecision::RequireApproval),
            _ => None,
        }
    }

    /// Check if the decision allows the transaction.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    /// Check if the decision denies the transaction.
    pub fn is_denied(&self) -> bool {
        matches!(self, PolicyDecision::Deny)
    }

    /// Check if the decision requires approval.
    pub fn requires_approval(&self) -> bool {
        matches!(self, PolicyDecision::RequireApproval)
    }
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyDecision::Deny => write!(f, "deny"),
            PolicyDecision::Allow => write!(f, "allow"),
            PolicyDecision::RequireApproval => write!(f, "require_approval"),
        }
    }
}

/// Metadata about a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    /// Policy ID.
    pub id: PolicyId,

    /// Human-readable name.
    pub name: String,

    /// Description of what the policy does.
    #[serde(default)]
    pub description: String,

    /// Version string.
    pub version: String,

    /// ABI version the policy was compiled for.
    pub abi_version: u32,

    /// Author/owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last update timestamp.
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Whether the policy is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Priority (lower = higher priority, evaluated first).
    #[serde(default)]
    pub priority: i32,

    /// Namespaces this policy applies to.
    #[serde(default)]
    pub namespaces: HashSet<String>,

    /// Key IDs this policy applies to (empty = all keys).
    #[serde(default)]
    pub key_ids: HashSet<String>,

    /// Chain IDs this policy applies to (empty = all chains).
    #[serde(default)]
    pub chain_ids: HashSet<String>,

    /// Transaction types this policy applies to (empty = all types).
    #[serde(default)]
    pub tx_types: HashSet<String>,

    /// Custom resource limits (overrides defaults).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_limits: Option<ResourceLimits>,

    /// SHA-256 hash of the WASM bytecode.
    pub bytecode_hash: String,

    /// Size of the WASM bytecode in bytes.
    pub bytecode_size: usize,

    /// Tags for organization.
    #[serde(default)]
    pub tags: HashSet<String>,
}

fn default_enabled() -> bool {
    true
}

impl PolicyMetadata {
    /// Create new policy metadata.
    pub fn new(
        id: PolicyId,
        name: impl Into<String>,
        version: impl Into<String>,
        bytecode_hash: impl Into<String>,
        bytecode_size: usize,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id,
            name: name.into(),
            description: String::new(),
            version: version.into(),
            abi_version: crate::ABI_VERSION,
            author: None,
            created_at: now,
            updated_at: now,
            enabled: true,
            priority: 0,
            namespaces: HashSet::new(),
            key_ids: HashSet::new(),
            chain_ids: HashSet::new(),
            tx_types: HashSet::new(),
            resource_limits: None,
            bytecode_hash: bytecode_hash.into(),
            bytecode_size,
            tags: HashSet::new(),
        }
    }

    /// Set description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set author.
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Set priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Add namespace filter.
    pub fn for_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespaces.insert(namespace.into());
        self
    }

    /// Add key ID filter.
    pub fn for_key(mut self, key_id: impl Into<String>) -> Self {
        self.key_ids.insert(key_id.into());
        self
    }

    /// Add chain ID filter.
    pub fn for_chain(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_ids.insert(chain_id.into());
        self
    }

    /// Add transaction type filter.
    pub fn for_tx_type(mut self, tx_type: impl Into<String>) -> Self {
        self.tx_types.insert(tx_type.into());
        self
    }

    /// Set custom resource limits.
    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = Some(limits);
        self
    }

    /// Disable the policy.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.insert(tag.into());
        self
    }

    /// Check if policy applies to a given context.
    pub fn applies_to(&self, namespace: &str, key_id: &str, chain_id: &str, tx_type: &str) -> bool {
        // Check namespace filter
        if !self.namespaces.is_empty() && !self.namespaces.contains(namespace) {
            return false;
        }

        // Check key ID filter
        if !self.key_ids.is_empty() && !self.key_ids.contains(key_id) {
            return false;
        }

        // Check chain ID filter
        if !self.chain_ids.is_empty() && !self.chain_ids.contains(chain_id) {
            return false;
        }

        // Check transaction type filter
        if !self.tx_types.is_empty() && !self.tx_types.contains(tx_type) {
            return false;
        }

        true
    }
}

/// A compiled policy ready for execution.
#[derive(Clone)]
pub struct Policy {
    /// Policy metadata.
    pub metadata: PolicyMetadata,

    /// Raw WASM bytecode.
    bytecode: Vec<u8>,
}

impl Policy {
    /// Create a new policy from bytecode.
    pub fn new(metadata: PolicyMetadata, bytecode: Vec<u8>) -> Self {
        Self { metadata, bytecode }
    }

    /// Get the bytecode.
    pub fn bytecode(&self) -> &[u8] {
        &self.bytecode
    }

    /// Compute SHA-256 hash of bytecode.
    pub fn compute_hash(bytecode: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(bytecode);
        hex::encode(hash)
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("metadata", &self.metadata)
            .field("bytecode_len", &self.bytecode.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_decision_conversion() {
        assert_eq!(PolicyDecision::from_i32(0), Some(PolicyDecision::Deny));
        assert_eq!(PolicyDecision::from_i32(1), Some(PolicyDecision::Allow));
        assert_eq!(
            PolicyDecision::from_i32(2),
            Some(PolicyDecision::RequireApproval)
        );
        assert_eq!(PolicyDecision::from_i32(3), None);
    }

    #[test]
    fn test_policy_metadata_filters() {
        let metadata =
            PolicyMetadata::new(PolicyId::new("test"), "Test Policy", "1.0.0", "hash", 1000)
                .for_namespace("production")
                .for_chain("1");

        // Should match production namespace and chain 1
        assert!(metadata.applies_to("production", "any-key", "1", "transfer"));

        // Should not match different namespace
        assert!(!metadata.applies_to("staging", "any-key", "1", "transfer"));

        // Should not match different chain
        assert!(!metadata.applies_to("production", "any-key", "137", "transfer"));
    }

    #[test]
    fn test_policy_hash() {
        let bytecode = b"test bytecode";
        let hash = Policy::compute_hash(bytecode);
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }
}
