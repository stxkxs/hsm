use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    /// Permission bitflags for O(1) permission checking.
    ///
    /// Uses bitflags for extremely fast permission checks, targeting <100μs latency.
    /// Each permission is represented as a single bit, allowing bitwise operations
    /// for combining and checking permissions.
    ///
    /// # Performance
    ///
    /// - Permission check: O(1) bitwise AND operation
    /// - Target latency: <100μs
    /// - Memory overhead: 8 bytes per permission set
    ///
    /// # Examples
    ///
    /// ```
    /// use hsm_auth::rbac::{Permission, PermissionFlags};
    ///
    /// // Create flags from permissions
    /// let perms = vec![Permission::Sign, Permission::Encrypt];
    /// let flags = PermissionFlags::from_permissions(&perms);
    ///
    /// // Check permission (O(1) operation)
    /// assert!(flags.has_permission(&Permission::Sign));
    /// assert!(flags.has_permission(&Permission::Encrypt));
    /// assert!(!flags.has_permission(&Permission::DeleteKey));
    ///
    /// // Combine permission sets
    /// let crypto_ops = PermissionFlags::CRYPTO_OPS;
    /// assert!(crypto_ops.contains(PermissionFlags::SIGN));
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PermissionFlags: u64 {
        const GENERATE_KEY      = 1 << 0;
        const IMPORT_KEY        = 1 << 1;
        const DELETE_KEY        = 1 << 2;
        const SIGN              = 1 << 3;
        const ENCRYPT           = 1 << 4;
        const DECRYPT           = 1 << 5;
        const ROTATE_KEY        = 1 << 6;
        const VIEW_METADATA     = 1 << 7;
        const VIEW_AUDIT_LOGS   = 1 << 8;
        const EXPORT_KEY        = 1 << 9;
        const MANAGE_NAMESPACES = 1 << 10;
        const MANAGE_ACLS       = 1 << 11;
        const MANAGE_ROLES      = 1 << 12;
        const BACKUP_KEYS       = 1 << 13;
        const RESTORE_KEYS      = 1 << 14;

        // Commonly used permission sets for quick checks
        const READ_ONLY = Self::VIEW_METADATA.bits() | Self::VIEW_AUDIT_LOGS.bits();
        const CRYPTO_OPS = Self::SIGN.bits() | Self::ENCRYPT.bits() | Self::DECRYPT.bits();
        const ADMIN = Self::MANAGE_NAMESPACES.bits() | Self::MANAGE_ACLS.bits() | Self::MANAGE_ROLES.bits();
        const ALL = u64::MAX;
    }
}

/// Fine-grained permissions that can be granted to roles.
///
/// Permissions define specific operations that can be performed on HSM resources.
/// They are checked during authorization after mTLS authentication and session
/// validation, forming the second layer of the security model.
///
/// # Permission Categories
///
/// ## Key Management (privileged)
/// - `GenerateKey`, `ImportKey`, `DeleteKey`, `RotateKey`, `ExportKey`
///
/// ## Cryptographic Operations
/// - `Sign`, `Encrypt`, `Decrypt`
///
/// ## Observability
/// - `ViewMetadata`, `ViewAuditLogs`
///
/// ## Administrative (highly privileged)
/// - `ManageNamespaces`, `ManageAcls`, `ManageRoles`
///
/// ## Backup/Recovery (privileged)
/// - `BackupKeys`, `RestoreKeys`
///
/// # Examples
///
/// ```
/// use hsm_auth::rbac::Permission;
///
/// // Check if permission is privileged
/// assert!(Permission::ExportKey.is_privileged());
/// assert!(!Permission::Sign.is_privileged());
///
/// // Get all available permissions
/// let all = Permission::all();
/// assert_eq!(all.len(), 15);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    /// Generate a new cryptographic key
    GenerateKey,

    /// Import an existing key
    ImportKey,

    /// Delete a key
    DeleteKey,

    /// Sign data with a key
    Sign,

    /// Encrypt data with a key
    Encrypt,

    /// Decrypt data with a key
    Decrypt,

    /// Rotate a key
    RotateKey,

    /// View key metadata
    ViewMetadata,

    /// View audit logs
    ViewAuditLogs,

    /// Export a key (highly privileged)
    ExportKey,

    /// Manage namespaces
    ManageNamespaces,

    /// Manage ACLs
    ManageAcls,

    /// Manage roles and permissions
    ManageRoles,

    /// Backup keys
    BackupKeys,

    /// Restore keys
    RestoreKeys,
}

impl Permission {
    /// Get all available permissions
    pub fn all() -> Vec<Permission> {
        vec![
            Permission::GenerateKey,
            Permission::ImportKey,
            Permission::DeleteKey,
            Permission::Sign,
            Permission::Encrypt,
            Permission::Decrypt,
            Permission::RotateKey,
            Permission::ViewMetadata,
            Permission::ViewAuditLogs,
            Permission::ExportKey,
            Permission::ManageNamespaces,
            Permission::ManageAcls,
            Permission::ManageRoles,
            Permission::BackupKeys,
            Permission::RestoreKeys,
        ]
    }

    /// Check if this is a privileged permission (requires admin)
    pub fn is_privileged(&self) -> bool {
        matches!(
            self,
            Permission::ExportKey
                | Permission::ManageNamespaces
                | Permission::ManageRoles
                | Permission::DeleteKey
                | Permission::BackupKeys
                | Permission::RestoreKeys
        )
    }

    /// Get the string representation of the permission
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::GenerateKey => "generate_key",
            Permission::ImportKey => "import_key",
            Permission::DeleteKey => "delete_key",
            Permission::Sign => "sign",
            Permission::Encrypt => "encrypt",
            Permission::Decrypt => "decrypt",
            Permission::RotateKey => "rotate_key",
            Permission::ViewMetadata => "view_metadata",
            Permission::ViewAuditLogs => "view_audit_logs",
            Permission::ExportKey => "export_key",
            Permission::ManageNamespaces => "manage_namespaces",
            Permission::ManageAcls => "manage_acls",
            Permission::ManageRoles => "manage_roles",
            Permission::BackupKeys => "backup_keys",
            Permission::RestoreKeys => "restore_keys",
        }
    }

    /// Convert to PermissionFlags for fast checking
    pub fn to_flag(&self) -> PermissionFlags {
        match self {
            Permission::GenerateKey => PermissionFlags::GENERATE_KEY,
            Permission::ImportKey => PermissionFlags::IMPORT_KEY,
            Permission::DeleteKey => PermissionFlags::DELETE_KEY,
            Permission::Sign => PermissionFlags::SIGN,
            Permission::Encrypt => PermissionFlags::ENCRYPT,
            Permission::Decrypt => PermissionFlags::DECRYPT,
            Permission::RotateKey => PermissionFlags::ROTATE_KEY,
            Permission::ViewMetadata => PermissionFlags::VIEW_METADATA,
            Permission::ViewAuditLogs => PermissionFlags::VIEW_AUDIT_LOGS,
            Permission::ExportKey => PermissionFlags::EXPORT_KEY,
            Permission::ManageNamespaces => PermissionFlags::MANAGE_NAMESPACES,
            Permission::ManageAcls => PermissionFlags::MANAGE_ACLS,
            Permission::ManageRoles => PermissionFlags::MANAGE_ROLES,
            Permission::BackupKeys => PermissionFlags::BACKUP_KEYS,
            Permission::RestoreKeys => PermissionFlags::RESTORE_KEYS,
        }
    }
}

impl PermissionFlags {
    /// Convert a slice of Permissions to PermissionFlags
    pub fn from_permissions(permissions: &[Permission]) -> Self {
        permissions
            .iter()
            .fold(PermissionFlags::empty(), |acc, p| acc | p.to_flag())
    }

    /// Check if these flags contain a specific permission
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.contains(permission.to_flag())
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_display() {
        assert_eq!(Permission::GenerateKey.to_string(), "generate_key");
        assert_eq!(Permission::Sign.to_string(), "sign");
        assert_eq!(Permission::ViewAuditLogs.to_string(), "view_audit_logs");
    }

    #[test]
    fn test_is_privileged() {
        assert!(Permission::ExportKey.is_privileged());
        assert!(Permission::ManageNamespaces.is_privileged());
        assert!(Permission::DeleteKey.is_privileged());
        assert!(!Permission::Sign.is_privileged());
        assert!(!Permission::Encrypt.is_privileged());
        assert!(!Permission::ViewMetadata.is_privileged());
    }

    #[test]
    fn test_all_permissions() {
        let all = Permission::all();
        assert!(all.contains(&Permission::GenerateKey));
        assert!(all.contains(&Permission::Sign));
        assert!(all.contains(&Permission::ViewAuditLogs));
        assert_eq!(all.len(), 15);
    }
}
