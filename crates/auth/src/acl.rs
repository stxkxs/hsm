use crate::error::{AuthError, Result};
use crate::mtls::ClientIdentity;
use crate::rbac::Permission;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Key identifier type
pub type KeyId = String;

/// Access Control List for a specific key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAcl {
    /// Key identifier
    pub key_id: KeyId,

    /// Allowed clients (by common name)
    pub allowed_clients: HashSet<String>,

    /// Denied clients (by common name) - takes precedence over allowed
    pub denied_clients: HashSet<String>,

    /// Required permissions for this key
    pub required_permissions: HashSet<Permission>,

    /// Whether this key is restricted to specific clients
    /// If false, all authenticated clients with proper permissions can access
    pub is_restricted: bool,
}

impl KeyAcl {
    /// Create a new unrestricted key ACL
    pub fn new(key_id: KeyId) -> Self {
        Self {
            key_id,
            allowed_clients: HashSet::new(),
            denied_clients: HashSet::new(),
            required_permissions: HashSet::new(),
            is_restricted: false,
        }
    }

    /// Create a restricted key ACL
    pub fn new_restricted(key_id: KeyId, allowed_clients: HashSet<String>) -> Self {
        Self {
            key_id,
            allowed_clients,
            denied_clients: HashSet::new(),
            required_permissions: HashSet::new(),
            is_restricted: true,
        }
    }

    /// Allow a client access to this key
    pub fn allow_client(&mut self, client_cn: &str) {
        self.allowed_clients.insert(client_cn.to_string());
        self.is_restricted = true;
    }

    /// Deny a client access to this key
    pub fn deny_client(&mut self, client_cn: &str) {
        self.denied_clients.insert(client_cn.to_string());
    }

    /// Remove a client from allowed list
    pub fn remove_allowed(&mut self, client_cn: &str) {
        self.allowed_clients.remove(client_cn);
    }

    /// Remove a client from denied list
    pub fn remove_denied(&mut self, client_cn: &str) {
        self.denied_clients.remove(client_cn);
    }

    /// Add a required permission
    pub fn require_permission(&mut self, permission: Permission) {
        self.required_permissions.insert(permission);
    }

    /// Remove a required permission
    pub fn remove_permission(&mut self, permission: &Permission) {
        self.required_permissions.remove(permission);
    }

    /// Check if a client is allowed to access this key (client-identity only).
    ///
    /// This does NOT enforce `required_permissions`; callers that know the
    /// operation being attempted should prefer [`KeyAcl::can_access_with_permission`]
    /// so that the per-key required-permission set is enforced (finding #23).
    pub fn can_access(&self, client_cn: &str) -> bool {
        // Deny list takes precedence
        if self.denied_clients.contains(client_cn) {
            return false;
        }

        // If not restricted, allow all
        if !self.is_restricted {
            return true;
        }

        // If restricted, check allowed list
        self.allowed_clients.contains(client_cn)
    }

    /// Check if a client may perform `permission` on this key.
    ///
    /// Enforces both the client allow/deny lists AND the per-key
    /// `required_permissions` set: when `required_permissions` is non-empty the
    /// requested `permission` MUST be a member, otherwise access is denied
    /// (default-deny for operations the key was not provisioned for). When the
    /// set is empty, no permission gate is applied beyond the client checks.
    pub fn can_access_with_permission(&self, client_cn: &str, permission: &Permission) -> bool {
        // Client allow/deny list (and restriction) checks first.
        if !self.can_access(client_cn) {
            return false;
        }

        // Per-key required-permission gate. Empty set => no gate.
        if self.required_permissions.is_empty() {
            return true;
        }

        self.required_permissions.contains(permission)
    }
}

/// ACL Manager for managing per-key access control
pub struct AclManager {
    acls: Arc<RwLock<HashMap<KeyId, KeyAcl>>>,
}

impl AclManager {
    /// Create a new ACL manager
    pub fn new() -> Self {
        Self {
            acls: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create an ACL for a key
    pub fn create_acl(&self, key_id: KeyId, restricted: bool) -> KeyAcl {
        let acl = if restricted {
            KeyAcl::new_restricted(key_id.clone(), HashSet::new())
        } else {
            KeyAcl::new(key_id.clone())
        };

        let mut acls = self.acls.write();
        acls.insert(key_id, acl.clone());
        acl
    }

    /// Get an ACL for a key
    pub fn get_acl(&self, key_id: &str) -> Option<KeyAcl> {
        let acls = self.acls.read();
        acls.get(key_id).cloned()
    }

    /// Update an ACL
    pub fn update_acl(&self, acl: KeyAcl) {
        let mut acls = self.acls.write();
        acls.insert(acl.key_id.clone(), acl);
    }

    /// Delete an ACL
    pub fn delete_acl(&self, key_id: &str) -> bool {
        let mut acls = self.acls.write();
        acls.remove(key_id).is_some()
    }

    /// Allow a client access to a key
    pub fn allow_client(&self, key_id: &str, client_cn: &str) -> Result<()> {
        let mut acls = self.acls.write();
        let acl = acls
            .get_mut(key_id)
            .ok_or_else(|| AuthError::InvalidAcl(format!("ACL not found for key {}", key_id)))?;

        acl.allow_client(client_cn);
        Ok(())
    }

    /// Deny a client access to a key
    pub fn deny_client(&self, key_id: &str, client_cn: &str) -> Result<()> {
        let mut acls = self.acls.write();
        let acl = acls
            .get_mut(key_id)
            .ok_or_else(|| AuthError::InvalidAcl(format!("ACL not found for key {}", key_id)))?;

        acl.deny_client(client_cn);
        Ok(())
    }

    /// Check if a client can access a key
    pub fn can_access(&self, key_id: &str, identity: &ClientIdentity) -> bool {
        let acls = self.acls.read();
        if let Some(acl) = acls.get(key_id) {
            acl.can_access(&identity.common_name)
        } else {
            // No ACL means unrestricted access
            true
        }
    }

    /// Require that a client can access a key
    pub fn require_access(&self, key_id: &str, identity: &ClientIdentity) -> Result<()> {
        if self.can_access(key_id, identity) {
            Ok(())
        } else {
            Err(AuthError::PermissionDenied(format!(
                "Client {} does not have access to key {}",
                identity.common_name, key_id
            )))
        }
    }

    /// Check if a client may perform `permission` on a key, enforcing the key's
    /// `required_permissions` set (finding #23).
    ///
    /// If no ACL row exists for the key this returns `true` (unrestricted),
    /// matching [`AclManager::can_access`].
    pub fn can_access_with_permission(
        &self,
        key_id: &str,
        identity: &ClientIdentity,
        permission: &Permission,
    ) -> bool {
        let acls = self.acls.read();
        if let Some(acl) = acls.get(key_id) {
            acl.can_access_with_permission(&identity.common_name, permission)
        } else {
            // No ACL means unrestricted access.
            true
        }
    }

    /// Require that a client may perform `permission` on a key, enforcing the
    /// key's `required_permissions` set (finding #23). Returns
    /// [`AuthError::PermissionDenied`] on denial so it threads cleanly through
    /// the REST API's `?` error handling.
    pub fn require_access_with_permission(
        &self,
        key_id: &str,
        identity: &ClientIdentity,
        permission: &Permission,
    ) -> Result<()> {
        if self.can_access_with_permission(key_id, identity, permission) {
            Ok(())
        } else {
            Err(AuthError::PermissionDenied(format!(
                "Client {} does not have access to key {} for permission {}",
                identity.common_name, key_id, permission
            )))
        }
    }

    /// Get all keys accessible by a client
    pub fn get_accessible_keys(&self, identity: &ClientIdentity) -> Vec<KeyId> {
        let acls = self.acls.read();
        acls.iter()
            .filter(|(_, acl)| acl.can_access(&identity.common_name))
            .map(|(key_id, _)| key_id.clone())
            .collect()
    }

    /// Get all keys in a namespace
    pub fn get_namespace_keys(&self, namespace: &str) -> Vec<KeyId> {
        let acls = self.acls.read();
        acls.keys()
            .filter(|key_id| key_id.starts_with(&format!("{}:", namespace)))
            .cloned()
            .collect()
    }

    /// List all ACLs
    pub fn list_acls(&self) -> Vec<KeyAcl> {
        let acls = self.acls.read();
        acls.values().cloned().collect()
    }
}

impl Default for AclManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;

    fn create_test_identity(cn: &str) -> ClientIdentity {
        ClientIdentity::new(
            cn.to_string(),
            None,
            "default".to_string(),
            vec![Role::User],
            "123456".to_string(),
        )
    }

    #[test]
    fn test_key_acl_unrestricted() {
        let acl = KeyAcl::new("key1".to_string());
        assert!(!acl.is_restricted);
        assert!(acl.can_access("anyone"));
    }

    #[test]
    fn test_key_acl_restricted() {
        let mut allowed = HashSet::new();
        allowed.insert("client1".to_string());
        let acl = KeyAcl::new_restricted("key1".to_string(), allowed);

        assert!(acl.is_restricted);
        assert!(acl.can_access("client1"));
        assert!(!acl.can_access("client2"));
    }

    #[test]
    fn test_key_acl_deny() {
        let mut acl = KeyAcl::new("key1".to_string());
        acl.deny_client("client1");

        assert!(!acl.can_access("client1"));
        assert!(acl.can_access("client2")); // Not restricted, only denied
    }

    #[test]
    fn test_key_acl_allow() {
        let mut acl = KeyAcl::new("key1".to_string());
        acl.allow_client("client1");
        acl.allow_client("client2");

        assert!(acl.is_restricted);
        assert!(acl.can_access("client1"));
        assert!(acl.can_access("client2"));
        assert!(!acl.can_access("client3"));
    }

    #[test]
    fn test_acl_manager_create() {
        let manager = AclManager::new();
        let acl = manager.create_acl("key1".to_string(), false);

        assert_eq!(acl.key_id, "key1");
        assert!(!acl.is_restricted);
        assert!(manager.get_acl("key1").is_some());
    }

    #[test]
    fn test_acl_manager_allow_deny() {
        let manager = AclManager::new();
        manager.create_acl("key1".to_string(), true);

        manager.allow_client("key1", "client1").unwrap();
        manager.deny_client("key1", "client2").unwrap();

        let identity1 = create_test_identity("client1");
        let identity2 = create_test_identity("client2");

        assert!(manager.can_access("key1", &identity1));
        assert!(!manager.can_access("key1", &identity2));
    }

    #[test]
    fn test_acl_manager_require_access() {
        let manager = AclManager::new();
        manager.create_acl("key1".to_string(), true);
        manager.allow_client("key1", "client1").unwrap();

        let identity1 = create_test_identity("client1");
        let identity2 = create_test_identity("client2");

        assert!(manager.require_access("key1", &identity1).is_ok());
        assert!(manager.require_access("key1", &identity2).is_err());
    }

    #[test]
    fn test_acl_manager_get_accessible_keys() {
        let manager = AclManager::new();
        manager.create_acl("key1".to_string(), true);
        manager.create_acl("key2".to_string(), true);
        manager.create_acl("key3".to_string(), false);

        manager.allow_client("key1", "client1").unwrap();
        manager.allow_client("key2", "client1").unwrap();

        let identity = create_test_identity("client1");
        let keys = manager.get_accessible_keys(&identity);

        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string())); // Unrestricted
    }

    #[test]
    fn test_acl_manager_delete() {
        let manager = AclManager::new();
        manager.create_acl("key1".to_string(), false);

        assert!(manager.delete_acl("key1"));
        assert!(!manager.delete_acl("key1")); // Already deleted
        assert!(manager.get_acl("key1").is_none());
    }

    #[test]
    fn test_key_acl_permissions() {
        let mut acl = KeyAcl::new("key1".to_string());
        acl.require_permission(Permission::Sign);
        acl.require_permission(Permission::Encrypt);

        assert!(acl.required_permissions.contains(&Permission::Sign));
        assert!(acl.required_permissions.contains(&Permission::Encrypt));

        acl.remove_permission(&Permission::Sign);
        assert!(!acl.required_permissions.contains(&Permission::Sign));
    }

    // --- Finding #23: required_permissions enforcement ----------------------

    /// An ACL with `required_permissions = {Sign}` must REJECT a request for a
    /// different permission (e.g. Encrypt) even though the client passes the
    /// allow-list check. Pre-fix `required_permissions` was stored but never
    /// consulted, so this would have been allowed.
    #[test]
    fn test_key_acl_required_permission_rejects_wrong_permission() {
        let mut acl = KeyAcl::new("key1".to_string());
        acl.require_permission(Permission::Sign);

        // Client is allowed (unrestricted), but the operation must match the
        // required permission set.
        assert!(acl.can_access("client1")); // legacy client-only check still passes
        assert!(acl.can_access_with_permission("client1", &Permission::Sign));
        assert!(
            !acl.can_access_with_permission("client1", &Permission::Encrypt),
            "Encrypt must be denied when only Sign is in required_permissions"
        );
        assert!(
            !acl.can_access_with_permission("client1", &Permission::DeleteKey),
            "DeleteKey must be denied when only Sign is in required_permissions"
        );
    }

    /// An empty `required_permissions` set imposes no permission gate (only the
    /// client allow/deny list applies).
    #[test]
    fn test_key_acl_empty_required_permissions_allows_any() {
        let acl = KeyAcl::new("key1".to_string());
        assert!(acl.required_permissions.is_empty());
        assert!(acl.can_access_with_permission("anyone", &Permission::Sign));
        assert!(acl.can_access_with_permission("anyone", &Permission::Decrypt));
    }

    /// The deny-list still takes precedence even when the requested permission
    /// is in the required set.
    #[test]
    fn test_key_acl_required_permission_respects_deny_list() {
        let mut acl = KeyAcl::new("key1".to_string());
        acl.require_permission(Permission::Sign);
        acl.deny_client("client1");

        assert!(!acl.can_access_with_permission("client1", &Permission::Sign));
    }

    /// Manager-level enforcement: a key provisioned to require Sign rejects an
    /// Encrypt request through `require_access_with_permission`, and permits a
    /// matching Sign request.
    #[test]
    fn test_acl_manager_require_access_with_permission() {
        let manager = AclManager::new();
        let mut acl = manager.create_acl("key1".to_string(), false);
        acl.require_permission(Permission::Sign);
        manager.update_acl(acl);

        let identity = create_test_identity("client1");

        assert!(manager
            .require_access_with_permission("key1", &identity, &Permission::Sign)
            .is_ok());
        assert!(
            manager
                .require_access_with_permission("key1", &identity, &Permission::Encrypt)
                .is_err(),
            "manager must reject an operation not in required_permissions"
        );
    }

    /// A restricted key with a required permission must reject a client that is
    /// not on the allow-list, regardless of the requested permission.
    #[test]
    fn test_acl_manager_required_permission_with_restriction() {
        let manager = AclManager::new();
        manager.create_acl("key1".to_string(), true);
        manager.allow_client("key1", "client1").unwrap();
        // Add the required permission to the stored ACL.
        let mut acl = manager.get_acl("key1").unwrap();
        acl.require_permission(Permission::Sign);
        manager.update_acl(acl);

        let allowed = create_test_identity("client1");
        let denied = create_test_identity("client2");

        // Allowed client + matching permission => ok.
        assert!(manager
            .require_access_with_permission("key1", &allowed, &Permission::Sign)
            .is_ok());
        // Allowed client + wrong permission => denied.
        assert!(manager
            .require_access_with_permission("key1", &allowed, &Permission::Decrypt)
            .is_err());
        // Disallowed client => denied even for the right permission.
        assert!(manager
            .require_access_with_permission("key1", &denied, &Permission::Sign)
            .is_err());
    }

    /// No ACL row means unrestricted access for any permission.
    #[test]
    fn test_acl_manager_no_acl_allows_any_permission() {
        let manager = AclManager::new();
        let identity = create_test_identity("client1");
        assert!(manager
            .require_access_with_permission("unknown-key", &identity, &Permission::Sign)
            .is_ok());
    }
}
