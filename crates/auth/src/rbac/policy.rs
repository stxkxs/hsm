use crate::error::{AuthError, Result};
use crate::rbac::{Permission, Role};
use std::collections::{HashMap, HashSet};

/// RBAC policy engine for permission checks
pub struct RbacPolicy {
    role_permissions: HashMap<Role, HashSet<Permission>>,
}

impl RbacPolicy {
    /// Create a new RBAC policy with default permissions
    pub fn new() -> Self {
        let mut policy = Self {
            role_permissions: HashMap::new(),
        };

        policy.initialize_default_permissions();
        policy
    }

    /// Initialize default permissions for each role
    fn initialize_default_permissions(&mut self) {
        // Admin has all permissions
        let admin_permissions: HashSet<Permission> = Permission::all().into_iter().collect();
        self.role_permissions.insert(Role::Admin, admin_permissions);

        // Operator permissions
        let operator_permissions = HashSet::from([
            Permission::GenerateKey,
            Permission::ImportKey,
            Permission::Sign,
            Permission::Encrypt,
            Permission::Decrypt,
            Permission::RotateKey,
            Permission::ViewMetadata,
            Permission::ManageAcls,
            Permission::BackupKeys,
        ]);
        self.role_permissions
            .insert(Role::Operator, operator_permissions);

        // User permissions
        let user_permissions = HashSet::from([
            Permission::Sign,
            Permission::Encrypt,
            Permission::Decrypt,
            Permission::ViewMetadata,
        ]);
        self.role_permissions.insert(Role::User, user_permissions);

        // Auditor permissions (read-only)
        let auditor_permissions =
            HashSet::from([Permission::ViewMetadata, Permission::ViewAuditLogs]);
        self.role_permissions
            .insert(Role::Auditor, auditor_permissions);
    }

    /// Check if a role has a specific permission
    pub fn can(&self, role: &Role, permission: &Permission) -> bool {
        self.role_permissions
            .get(role)
            .map(|perms| perms.contains(permission))
            .unwrap_or(false)
    }

    /// Check if any of the given roles has the permission
    pub fn can_any(&self, roles: &[Role], permission: &Permission) -> bool {
        roles.iter().any(|role| self.can(role, permission))
    }

    /// Check if all of the given roles have the permission
    pub fn can_all(&self, roles: &[Role], permission: &Permission) -> bool {
        roles.iter().all(|role| self.can(role, permission))
    }

    /// Require that a role has a specific permission, or return an error
    pub fn require(&self, role: &Role, permission: &Permission) -> Result<()> {
        if self.can(role, permission) {
            Ok(())
        } else {
            Err(AuthError::PermissionDenied(format!(
                "Role {} does not have permission {}",
                role, permission
            )))
        }
    }

    /// Require that at least one of the roles has the permission
    pub fn require_any(&self, roles: &[Role], permission: &Permission) -> Result<()> {
        if self.can_any(roles, permission) {
            Ok(())
        } else {
            Err(AuthError::PermissionDenied(format!(
                "None of the roles have permission {}",
                permission
            )))
        }
    }

    /// Get all permissions for a role
    pub fn get_permissions(&self, role: &Role) -> Option<&HashSet<Permission>> {
        self.role_permissions.get(role)
    }

    /// Grant a permission to a role
    pub fn grant(&mut self, role: Role, permission: Permission) {
        self.role_permissions
            .entry(role)
            .or_default()
            .insert(permission);
    }

    /// Revoke a permission from a role
    pub fn revoke(&mut self, role: &Role, permission: &Permission) -> bool {
        self.role_permissions
            .get_mut(role)
            .map(|perms| perms.remove(permission))
            .unwrap_or(false)
    }

    /// Get all roles that have a specific permission
    pub fn roles_with_permission(&self, permission: &Permission) -> Vec<Role> {
        self.role_permissions
            .iter()
            .filter(|(_, perms)| perms.contains(permission))
            .map(|(role, _)| *role)
            .collect()
    }
}

impl Default for RbacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_permissions() {
        let policy = RbacPolicy::new();

        // Admin should have all permissions
        assert!(policy.can(&Role::Admin, &Permission::GenerateKey));
        assert!(policy.can(&Role::Admin, &Permission::ExportKey));
        assert!(policy.can(&Role::Admin, &Permission::ManageNamespaces));

        // Operator should have operational permissions
        assert!(policy.can(&Role::Operator, &Permission::GenerateKey));
        assert!(policy.can(&Role::Operator, &Permission::Sign));
        assert!(!policy.can(&Role::Operator, &Permission::ExportKey));
        assert!(!policy.can(&Role::Operator, &Permission::ManageNamespaces));

        // User should have basic crypto permissions
        assert!(policy.can(&Role::User, &Permission::Sign));
        assert!(policy.can(&Role::User, &Permission::Encrypt));
        assert!(!policy.can(&Role::User, &Permission::GenerateKey));
        assert!(!policy.can(&Role::User, &Permission::DeleteKey));

        // Auditor should only have read permissions
        assert!(policy.can(&Role::Auditor, &Permission::ViewMetadata));
        assert!(policy.can(&Role::Auditor, &Permission::ViewAuditLogs));
        assert!(!policy.can(&Role::Auditor, &Permission::Sign));
        assert!(!policy.can(&Role::Auditor, &Permission::GenerateKey));
    }

    #[test]
    fn test_can_any() {
        let policy = RbacPolicy::new();

        let roles = vec![Role::User, Role::Auditor];
        assert!(policy.can_any(&roles, &Permission::ViewMetadata));
        assert!(!policy.can_any(&roles, &Permission::GenerateKey));

        let roles = vec![Role::Admin, Role::User];
        assert!(policy.can_any(&roles, &Permission::GenerateKey));
    }

    #[test]
    fn test_can_all() {
        let policy = RbacPolicy::new();

        let roles = vec![Role::User, Role::Operator];
        assert!(policy.can_all(&roles, &Permission::Sign));
        assert!(!policy.can_all(&roles, &Permission::GenerateKey));

        let roles = vec![Role::Admin, Role::Admin];
        assert!(policy.can_all(&roles, &Permission::GenerateKey));
    }

    #[test]
    fn test_require() {
        let policy = RbacPolicy::new();

        assert!(policy
            .require(&Role::Admin, &Permission::GenerateKey)
            .is_ok());
        assert!(policy
            .require(&Role::User, &Permission::GenerateKey)
            .is_err());
    }

    #[test]
    fn test_grant_and_revoke() {
        let mut policy = RbacPolicy::new();

        // Grant a new permission
        assert!(!policy.can(&Role::User, &Permission::GenerateKey));
        policy.grant(Role::User, Permission::GenerateKey);
        assert!(policy.can(&Role::User, &Permission::GenerateKey));

        // Revoke the permission
        assert!(policy.revoke(&Role::User, &Permission::GenerateKey));
        assert!(!policy.can(&Role::User, &Permission::GenerateKey));
    }

    #[test]
    fn test_roles_with_permission() {
        let policy = RbacPolicy::new();

        let roles = policy.roles_with_permission(&Permission::ViewMetadata);
        assert!(roles.contains(&Role::Admin));
        assert!(roles.contains(&Role::Operator));
        assert!(roles.contains(&Role::User));
        assert!(roles.contains(&Role::Auditor));

        let roles = policy.roles_with_permission(&Permission::ExportKey);
        assert_eq!(roles, vec![Role::Admin]);
    }

    #[test]
    fn test_get_permissions() {
        let policy = RbacPolicy::new();

        let admin_perms = policy.get_permissions(&Role::Admin).unwrap();
        assert_eq!(admin_perms.len(), Permission::all().len());

        let user_perms = policy.get_permissions(&Role::User).unwrap();
        assert!(user_perms.len() < admin_perms.len());
    }
}
