use super::TemplateId;
use crate::rbac::Permission;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Session scope for restricting session capabilities
///
/// Scopes allow creating sessions with limited permissions, key access,
/// operation counts, or rate limits. This is essential for:
/// - Principle of least privilege
/// - Temporary elevated access
/// - Delegated sessions with restricted capabilities
///
/// # Examples
///
/// ```rust
/// use hsm_auth::session::SessionScope;
/// use hsm_auth::rbac::Permission;
///
/// // Create a scope that only allows signing with specific keys
/// let scope = SessionScope::new()
///     .with_operations(vec![Permission::Sign, Permission::Encrypt])
///     .with_keys(vec!["key-1".to_string(), "key-2".to_string()])
///     .with_max_operations(100)
///     .with_rate_limit(10);
///
/// assert!(scope.is_operation_allowed(&Permission::Sign));
/// assert!(!scope.is_operation_allowed(&Permission::DeleteKey));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionScope {
    /// Allowed operations (None = all operations allowed)
    pub allowed_operations: Option<Vec<Permission>>,
    /// Allowed keys (None = all keys allowed)
    pub allowed_keys: Option<Vec<String>>,
    /// Maximum number of operations before session expires
    pub max_operations: Option<u64>,
    /// Rate limit (operations per second)
    pub rate_limit: Option<u32>,
    /// Allowed namespaces (None = inherit from identity)
    pub allowed_namespaces: Option<Vec<String>>,
}

impl Default for SessionScope {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionScope {
    /// Create an unrestricted scope
    pub fn new() -> Self {
        Self {
            allowed_operations: None,
            allowed_keys: None,
            max_operations: None,
            rate_limit: None,
            allowed_namespaces: None,
        }
    }

    /// Create a scope with specific operations
    pub fn with_operations(mut self, operations: Vec<Permission>) -> Self {
        self.allowed_operations = Some(operations);
        self
    }

    /// Create a scope with specific keys
    pub fn with_keys(mut self, keys: Vec<String>) -> Self {
        self.allowed_keys = Some(keys);
        self
    }

    /// Set maximum operations
    pub fn with_max_operations(mut self, max: u64) -> Self {
        self.max_operations = Some(max);
        self
    }

    /// Set rate limit
    pub fn with_rate_limit(mut self, ops_per_second: u32) -> Self {
        self.rate_limit = Some(ops_per_second);
        self
    }

    /// Set allowed namespaces
    pub fn with_namespaces(mut self, namespaces: Vec<String>) -> Self {
        self.allowed_namespaces = Some(namespaces);
        self
    }

    /// Check if an operation is allowed
    pub fn is_operation_allowed(&self, operation: &Permission) -> bool {
        match &self.allowed_operations {
            Some(ops) => ops.contains(operation),
            None => true, // All operations allowed if not restricted
        }
    }

    /// Check if a key is allowed
    pub fn is_key_allowed(&self, key_id: &str) -> bool {
        match &self.allowed_keys {
            Some(keys) => keys.iter().any(|k| k == key_id),
            None => true, // All keys allowed if not restricted
        }
    }

    /// Check if a namespace is allowed
    pub fn is_namespace_allowed(&self, namespace: &str) -> bool {
        match &self.allowed_namespaces {
            Some(ns) => ns.iter().any(|n| n == namespace),
            None => true, // All namespaces allowed if not restricted
        }
    }

    /// Check if this scope is more restrictive than another
    /// (can only grant subset of parent's permissions)
    pub fn is_subset_of(&self, parent: &SessionScope) -> bool {
        // Check operations
        if let Some(child_ops) = &self.allowed_operations {
            if let Some(parent_ops) = &parent.allowed_operations {
                if !child_ops.iter().all(|op| parent_ops.contains(op)) {
                    return false;
                }
            }
        }

        // Check keys
        if let Some(child_keys) = &self.allowed_keys {
            if let Some(parent_keys) = &parent.allowed_keys {
                let parent_set: HashSet<_> = parent_keys.iter().collect();
                if !child_keys.iter().all(|k| parent_set.contains(k)) {
                    return false;
                }
            }
        }

        // Check max operations (child must be <= parent)
        if let Some(child_max) = self.max_operations {
            if let Some(parent_max) = parent.max_operations {
                if child_max > parent_max {
                    return false;
                }
            }
        }

        // Check rate limit (child must be <= parent)
        if let Some(child_rate) = self.rate_limit {
            if let Some(parent_rate) = parent.rate_limit {
                if child_rate > parent_rate {
                    return false;
                }
            }
        }

        true
    }

    /// Merge two scopes, taking the most restrictive combination
    pub fn intersect(&self, other: &SessionScope) -> SessionScope {
        SessionScope {
            allowed_operations: match (&self.allowed_operations, &other.allowed_operations) {
                (Some(a), Some(b)) => {
                    let set_b: HashSet<_> = b.iter().collect();
                    Some(a.iter().filter(|op| set_b.contains(op)).cloned().collect())
                }
                (Some(a), None) => Some(a.clone()),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            },
            allowed_keys: match (&self.allowed_keys, &other.allowed_keys) {
                (Some(a), Some(b)) => {
                    let set_b: HashSet<_> = b.iter().collect();
                    Some(a.iter().filter(|k| set_b.contains(k)).cloned().collect())
                }
                (Some(a), None) => Some(a.clone()),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            },
            max_operations: match (self.max_operations, other.max_operations) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            rate_limit: match (self.rate_limit, other.rate_limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            allowed_namespaces: match (&self.allowed_namespaces, &other.allowed_namespaces) {
                (Some(a), Some(b)) => {
                    let set_b: HashSet<_> = b.iter().collect();
                    Some(a.iter().filter(|n| set_b.contains(n)).cloned().collect())
                }
                (Some(a), None) => Some(a.clone()),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            },
        }
    }
}

/// Session template for creating sessions with predefined configurations
///
/// Templates allow administrators to define reusable session configurations
/// that can be quickly applied. This is useful for:
/// - Standard session types (e.g., "signing-only", "backup-admin")
/// - Enforcing organization-wide session policies
/// - Quick session provisioning
///
/// # Examples
///
/// ```rust
/// use hsm_auth::session::{SessionTemplate, SessionScope};
/// use hsm_auth::rbac::Permission;
///
/// // Create a template for signing-only sessions
/// let template = SessionTemplate::new("signing-only", "Signing Only")
///     .with_scope(
///         SessionScope::new()
///             .with_operations(vec![Permission::Sign])
///             .with_rate_limit(100)
///     )
///     .with_ttl(3600); // 1 hour
///
/// assert_eq!(template.name, "Signing Only");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTemplate {
    /// Unique template identifier
    pub id: TemplateId,
    /// Human-readable name
    pub name: String,
    /// Description of the template
    pub description: Option<String>,
    /// Session scope restrictions
    pub scope: SessionScope,
    /// Default TTL in seconds
    pub default_ttl_seconds: i64,
    /// Whether sessions created from this template can be delegated
    pub allow_delegation: bool,
    /// Maximum delegation depth (0 = no delegation)
    pub max_delegation_depth: u32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
}

impl SessionTemplate {
    /// Create a new session template
    pub fn new(id: &str, name: &str) -> Self {
        let now = Utc::now();
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: None,
            scope: SessionScope::new(),
            default_ttl_seconds: 3600, // 1 hour default
            allow_delegation: false,
            max_delegation_depth: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the scope
    pub fn with_scope(mut self, scope: SessionScope) -> Self {
        self.scope = scope;
        self.updated_at = Utc::now();
        self
    }

    /// Set the TTL
    pub fn with_ttl(mut self, ttl_seconds: i64) -> Self {
        self.default_ttl_seconds = ttl_seconds;
        self.updated_at = Utc::now();
        self
    }

    /// Set description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self.updated_at = Utc::now();
        self
    }

    /// Enable delegation
    pub fn with_delegation(mut self, max_depth: u32) -> Self {
        self.allow_delegation = max_depth > 0;
        self.max_delegation_depth = max_depth;
        self.updated_at = Utc::now();
        self
    }
}
