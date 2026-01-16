use crate::error::{AuthError, Result};
use crate::mtls::ClientIdentity;
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;

/// Namespace access control entry
#[derive(Clone)]
struct NamespaceAcl {
    /// Allowed clients (by common name)
    allowed_clients: HashSet<String>,
    /// Whether this ACL is restricted (true) or allows all (false)
    is_restricted: bool,
}

/// Namespace metadata for caching
#[derive(Clone)]
struct NamespaceMetadata {
    acl: NamespaceAcl,
}

/// Namespace access control manager
/// Ensures cryptographic isolation between namespaces
/// Optimized with DashMap for concurrent access (target: < 50μs for namespace resolution)
pub struct NamespaceManager {
    /// DashMap for concurrent namespace access
    namespaces: Arc<DashMap<String, NamespaceMetadata>>,
}

impl NamespaceManager {
    /// Create a new namespace manager with concurrent access support
    pub fn new() -> Self {
        Self {
            namespaces: Arc::new(DashMap::new()),
        }
    }

    /// Create a new namespace (lock-free)
    pub fn create_namespace(&self, namespace: &str) -> Result<()> {
        if namespace.is_empty() {
            return Err(AuthError::InvalidCertificate(
                "Namespace name cannot be empty".to_string(),
            ));
        }

        if self.namespaces.contains_key(namespace) {
            return Err(AuthError::Internal(format!(
                "Namespace {} already exists",
                namespace
            )));
        }

        let metadata = NamespaceMetadata {
            acl: NamespaceAcl {
                allowed_clients: HashSet::new(),
                is_restricted: false,
            },
        };

        self.namespaces.insert(namespace.to_string(), metadata);
        metrics::counter!("auth.namespace.created").increment(1);
        Ok(())
    }

    /// Delete a namespace
    pub fn delete_namespace(&self, namespace: &str) -> Result<()> {
        if self.namespaces.remove(namespace).is_none() {
            return Err(AuthError::Internal(format!(
                "Namespace {} does not exist",
                namespace
            )));
        }
        metrics::counter!("auth.namespace.deleted").increment(1);
        Ok(())
    }

    /// Grant access to a namespace for a client (lock-free)
    pub fn grant_access(&self, namespace: &str, client_cn: &str) -> Result<()> {
        if let Some(mut metadata) = self.namespaces.get_mut(namespace) {
            metadata.acl.allowed_clients.insert(client_cn.to_string());
            metadata.acl.is_restricted = true;
            Ok(())
        } else {
            // Create namespace if it doesn't exist
            let mut acl = NamespaceAcl {
                allowed_clients: HashSet::new(),
                is_restricted: true,
            };
            acl.allowed_clients.insert(client_cn.to_string());

            let metadata = NamespaceMetadata { acl };

            self.namespaces.insert(namespace.to_string(), metadata);
            Ok(())
        }
    }

    /// Revoke access to a namespace for a client
    pub fn revoke_access(&self, namespace: &str, client_cn: &str) -> Result<()> {
        if let Some(mut metadata) = self.namespaces.get_mut(namespace) {
            metadata.acl.allowed_clients.remove(client_cn);
            Ok(())
        } else {
            Err(AuthError::Internal(format!(
                "Namespace {} does not exist",
                namespace
            )))
        }
    }

    /// Check if a client has access to a namespace (optimized, target: < 50μs)
    pub fn has_access(&self, identity: &ClientIdentity, namespace: &str) -> bool {
        // First check if the identity's namespace matches
        if identity.namespace != namespace {
            return false;
        }

        // Then check the ACL with fast DashMap lookup
        if let Some(metadata) = self.namespaces.get(namespace) {
            // If ACL is not restricted, allow all clients with matching namespace
            if !metadata.acl.is_restricted {
                return true;
            }
            // Otherwise, check if client is in allowed list
            metadata.acl.allowed_clients.contains(&identity.common_name)
        } else {
            // Namespace doesn't exist, but if it matches identity's namespace, allow it
            // This allows auto-creation of namespaces
            true
        }
    }

    /// Require that a client has access to a namespace
    pub fn require_access(&self, identity: &ClientIdentity, namespace: &str) -> Result<()> {
        if self.has_access(identity, namespace) {
            Ok(())
        } else {
            Err(AuthError::NamespaceAccessDenied(format!(
                "Client {} does not have access to namespace {}",
                identity.common_name, namespace
            )))
        }
    }

    /// Get all namespaces a client has access to (optimized with DashMap)
    pub fn get_accessible_namespaces(&self, identity: &ClientIdentity) -> Vec<String> {
        let mut namespaces = Vec::new();

        for entry in self.namespaces.iter() {
            let namespace = entry.key();
            let metadata = entry.value();

            if identity.namespace == *namespace
                && (!metadata.acl.is_restricted
                    || metadata.acl.allowed_clients.contains(&identity.common_name))
            {
                namespaces.push(namespace.clone());
            }
        }

        // If no namespaces found but identity has a namespace, include it
        if namespaces.is_empty() && !identity.namespace.is_empty() {
            namespaces.push(identity.namespace.clone());
        }

        namespaces
    }

    /// List all namespaces (lock-free)
    pub fn list_namespaces(&self) -> Vec<String> {
        self.namespaces.iter().map(|e| e.key().clone()).collect()
    }

    /// Get clients with access to a namespace
    pub fn get_namespace_clients(&self, namespace: &str) -> Option<Vec<String>> {
        self.namespaces
            .get(namespace)
            .map(|metadata| metadata.acl.allowed_clients.iter().cloned().collect())
    }
}

impl Default for NamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;

    fn create_test_identity(cn: &str, namespace: &str) -> ClientIdentity {
        ClientIdentity::new(
            cn.to_string(),
            None,
            namespace.to_string(),
            vec![Role::User],
            "123456".to_string(),
        )
    }

    #[test]
    fn test_create_namespace() {
        let manager = NamespaceManager::new();
        assert!(manager.create_namespace("test-ns").is_ok());
        assert!(manager.create_namespace("test-ns").is_err()); // Already exists
    }

    #[test]
    fn test_delete_namespace() {
        let manager = NamespaceManager::new();
        manager.create_namespace("test-ns").unwrap();
        assert!(manager.delete_namespace("test-ns").is_ok());
        assert!(manager.delete_namespace("test-ns").is_err()); // Already deleted
    }

    #[test]
    fn test_grant_and_revoke_access() {
        let manager = NamespaceManager::new();
        manager.create_namespace("test-ns").unwrap();

        assert!(manager.grant_access("test-ns", "client1").is_ok());
        assert!(manager.revoke_access("test-ns", "client1").is_ok());
    }

    #[test]
    fn test_has_access() {
        let manager = NamespaceManager::new();
        let identity = create_test_identity("client1", "test-ns");

        // Auto-created namespace - should have access
        assert!(manager.has_access(&identity, "test-ns"));

        // Different namespace - no access
        assert!(!manager.has_access(&identity, "other-ns"));
    }

    #[test]
    fn test_has_access_with_acl() {
        let manager = NamespaceManager::new();
        manager.create_namespace("test-ns").unwrap();
        manager.grant_access("test-ns", "client1").unwrap();

        let identity1 = create_test_identity("client1", "test-ns");
        let identity2 = create_test_identity("client2", "test-ns");

        // client1 should have access
        assert!(manager.has_access(&identity1, "test-ns"));

        // client2 should not have access (not in ACL)
        assert!(!manager.has_access(&identity2, "test-ns"));
    }

    #[test]
    fn test_require_access() {
        let manager = NamespaceManager::new();
        let identity = create_test_identity("client1", "test-ns");

        assert!(manager.require_access(&identity, "test-ns").is_ok());
        assert!(manager.require_access(&identity, "other-ns").is_err());
    }

    #[test]
    fn test_get_accessible_namespaces() {
        let manager = NamespaceManager::new();
        manager.create_namespace("ns1").unwrap();
        manager.create_namespace("ns2").unwrap();
        manager.grant_access("ns1", "client1").unwrap();

        let identity = create_test_identity("client1", "ns1");
        let namespaces = manager.get_accessible_namespaces(&identity);

        assert!(namespaces.contains(&"ns1".to_string()));
        assert!(!namespaces.contains(&"ns2".to_string()));
    }

    #[test]
    fn test_list_namespaces() {
        let manager = NamespaceManager::new();
        manager.create_namespace("ns1").unwrap();
        manager.create_namespace("ns2").unwrap();

        let namespaces = manager.list_namespaces();
        assert_eq!(namespaces.len(), 2);
        assert!(namespaces.contains(&"ns1".to_string()));
        assert!(namespaces.contains(&"ns2".to_string()));
    }

    #[test]
    fn test_get_namespace_clients() {
        let manager = NamespaceManager::new();
        manager.create_namespace("test-ns").unwrap();
        manager.grant_access("test-ns", "client1").unwrap();
        manager.grant_access("test-ns", "client2").unwrap();

        let clients = manager.get_namespace_clients("test-ns").unwrap();
        assert_eq!(clients.len(), 2);
        assert!(clients.contains(&"client1".to_string()));
        assert!(clients.contains(&"client2".to_string()));
    }
}
