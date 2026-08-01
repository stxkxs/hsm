//! Policy storage and persistence

use super::types::{Policy, PolicyId, PolicyScope};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::sync::Arc;

/// Policy store for managing policies
pub struct PolicyStore {
    /// Policies by ID
    policies: Arc<DashMap<PolicyId, Policy>>,
    /// Index by scope
    scope_index: Arc<DashMap<String, Vec<PolicyId>>>,
}

impl PolicyStore {
    /// Create a new policy store
    pub fn new() -> Self {
        Self {
            policies: Arc::new(DashMap::new()),
            scope_index: Arc::new(DashMap::new()),
        }
    }

    /// Add a policy
    pub fn add(&self, policy: Policy) -> PolicyId {
        let id = policy.id;
        let scope_key = Self::scope_key(&policy.scope);

        // Add to main store
        self.policies.insert(id, policy);

        // Add to scope index
        self.scope_index.entry(scope_key).or_default().push(id);

        id
    }

    /// Get a policy by ID
    pub fn get(&self, id: &PolicyId) -> Option<Policy> {
        self.policies.get(id).map(|p| p.clone())
    }

    /// Update a policy
    pub fn update(&self, id: &PolicyId, updater: impl FnOnce(&mut Policy)) -> Option<Policy> {
        let mut policy = self.policies.get_mut(id)?;
        updater(&mut policy);
        policy.updated_at = Utc::now();
        policy.version += 1;
        Some(policy.clone())
    }

    /// Delete a policy
    pub fn delete(&self, id: &PolicyId) -> Option<Policy> {
        let (_, policy) = self.policies.remove(id)?;

        // Remove from scope index
        let scope_key = Self::scope_key(&policy.scope);
        self.scope_index.alter(&scope_key, |_, mut ids| {
            ids.retain(|pid| pid != id);
            ids
        });

        Some(policy)
    }

    /// Get all policies for a scope
    pub fn get_for_scope(&self, scope: &PolicyScope) -> Vec<Policy> {
        let scope_key = Self::scope_key(scope);
        self.scope_index
            .get(&scope_key)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.policies.get(id).map(|p| p.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all enabled policies for a scope, sorted by priority
    pub fn get_enabled_for_scope(&self, scope: &PolicyScope) -> Vec<Policy> {
        let mut policies = self.get_for_scope(scope);
        policies.retain(|p| p.enabled);
        policies.sort_by_key(|p| Reverse(p.priority));
        policies
    }

    /// Get policies applicable to a key
    pub fn get_for_key(&self, key_id: &str, namespace: &str) -> Vec<Policy> {
        let mut policies = Vec::new();

        // Global policies
        policies.extend(self.get_enabled_for_scope(&PolicyScope::Global));

        // Namespace policies
        policies.extend(self.get_enabled_for_scope(&PolicyScope::Namespace(namespace.to_string())));

        // Key-specific policies
        policies.extend(self.get_enabled_for_scope(&PolicyScope::Key(key_id.to_string())));

        // Sort by priority
        policies.sort_by_key(|p| Reverse(p.priority));
        policies
    }

    /// List all policies
    pub fn list(&self) -> Vec<Policy> {
        self.policies.iter().map(|r| r.clone()).collect()
    }

    /// Count policies
    pub fn count(&self) -> usize {
        self.policies.len()
    }

    /// Enable a policy
    pub fn enable(&self, id: &PolicyId) -> bool {
        self.update(id, |p| p.enabled = true).is_some()
    }

    /// Disable a policy
    pub fn disable(&self, id: &PolicyId) -> bool {
        self.update(id, |p| p.enabled = false).is_some()
    }

    /// Convert scope to string key
    fn scope_key(scope: &PolicyScope) -> String {
        match scope {
            PolicyScope::Global => "global".to_string(),
            PolicyScope::Namespace(ns) => format!("ns:{}", ns),
            PolicyScope::Key(key) => format!("key:{}", key),
            PolicyScope::User(user) => format!("user:{}", user),
            PolicyScope::Asset(asset) => format!("asset:{}", asset),
        }
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy snapshot for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    /// Policies
    pub policies: Vec<Policy>,
    /// Snapshot timestamp
    pub timestamp: chrono::DateTime<Utc>,
    /// Version
    pub version: u32,
}

impl PolicyStore {
    /// Create a snapshot of all policies
    pub fn snapshot(&self) -> PolicySnapshot {
        PolicySnapshot {
            policies: self.list(),
            timestamp: Utc::now(),
            version: 1,
        }
    }

    /// Restore from a snapshot
    pub fn restore(&self, snapshot: PolicySnapshot) -> usize {
        let mut count = 0;
        for policy in snapshot.policies {
            self.add(policy);
            count += 1;
        }
        count
    }

    /// Export to JSON
    pub fn export_json(&self) -> String {
        serde_json::to_string_pretty(&self.snapshot()).unwrap_or_default()
    }

    /// Import from JSON
    pub fn import_json(&self, json: &str) -> Result<usize, serde_json::Error> {
        let snapshot: PolicySnapshot = serde_json::from_str(json)?;
        Ok(self.restore(snapshot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_add_and_get_policy() {
        let store = PolicyStore::new();

        let policy = Policy::new(
            "Test Policy",
            PolicyScope::Global,
            json!({"max_value": 1000}),
        );
        let id = policy.id;

        store.add(policy);

        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.name, "Test Policy");
    }

    #[test]
    fn test_get_for_scope() {
        let store = PolicyStore::new();

        // Add global policy
        store.add(Policy::new("Global", PolicyScope::Global, json!({})));

        // Add namespace policy
        store.add(Policy::new(
            "Namespace",
            PolicyScope::Namespace("prod".to_string()),
            json!({}),
        ));

        let global = store.get_for_scope(&PolicyScope::Global);
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].name, "Global");

        let ns = store.get_for_scope(&PolicyScope::Namespace("prod".to_string()));
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].name, "Namespace");
    }

    #[test]
    fn test_priority_ordering() {
        let store = PolicyStore::new();

        // Add policies with different priorities
        store.add(Policy::new("Low", PolicyScope::Global, json!({})).with_priority(1));
        store.add(Policy::new("High", PolicyScope::Global, json!({})).with_priority(10));
        store.add(Policy::new("Medium", PolicyScope::Global, json!({})).with_priority(5));

        let policies = store.get_enabled_for_scope(&PolicyScope::Global);
        assert_eq!(policies[0].name, "High");
        assert_eq!(policies[1].name, "Medium");
        assert_eq!(policies[2].name, "Low");
    }

    #[test]
    fn test_enable_disable() {
        let store = PolicyStore::new();

        let policy = Policy::new("Test", PolicyScope::Global, json!({}));
        let id = policy.id;
        store.add(policy);

        assert_eq!(store.get_enabled_for_scope(&PolicyScope::Global).len(), 1);

        store.disable(&id);
        assert_eq!(store.get_enabled_for_scope(&PolicyScope::Global).len(), 0);

        store.enable(&id);
        assert_eq!(store.get_enabled_for_scope(&PolicyScope::Global).len(), 1);
    }

    #[test]
    fn test_export_import() {
        let store = PolicyStore::new();

        store.add(Policy::new("Policy1", PolicyScope::Global, json!({"a": 1})));
        store.add(Policy::new("Policy2", PolicyScope::Global, json!({"b": 2})));

        let json = store.export_json();

        let new_store = PolicyStore::new();
        let count = new_store.import_json(&json).unwrap();

        assert_eq!(count, 2);
        assert_eq!(new_store.count(), 2);
    }

    #[test]
    fn test_delete_policy() {
        let store = PolicyStore::new();

        let policy = Policy::new("Test", PolicyScope::Global, json!({}));
        let id = policy.id;
        store.add(policy);

        assert!(store.get(&id).is_some());
        store.delete(&id);
        assert!(store.get(&id).is_none());
    }
}
