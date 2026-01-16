use serde::{Deserialize, Serialize};

/// Roles that can be assigned to clients
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Full system access - can do everything
    Admin,

    /// Operational access - can manage keys and perform crypto operations
    Operator,

    /// Standard user - can use keys for crypto operations
    User,

    /// Read-only access - can view metadata and audit logs
    Auditor,
}

impl Role {
    /// Get the string representation of the role
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::User => "user",
            Role::Auditor => "auditor",
        }
    }

    /// Parse a role from a string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "user" => Some(Role::User),
            "auditor" => Some(Role::Auditor),
            _ => None,
        }
    }

    /// Get all available roles
    pub fn all() -> Vec<Role> {
        vec![Role::Admin, Role::Operator, Role::User, Role::Auditor]
    }

    /// Check if this role can assume another role's permissions
    pub fn can_assume(&self, other: &Role) -> bool {
        match self {
            Role::Admin => true, // Admin can assume any role
            Role::Operator => matches!(other, Role::User | Role::Auditor),
            Role::User => matches!(other, Role::Auditor),
            Role::Auditor => false, // Auditor cannot assume other roles
        }
    }

    /// Get the hierarchy level (higher = more privileged)
    pub fn hierarchy_level(&self) -> u8 {
        match self {
            Role::Admin => 3,
            Role::Operator => 2,
            Role::User => 1,
            Role::Auditor => 0,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_display() {
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Operator.to_string(), "operator");
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::Auditor.to_string(), "auditor");
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!(Role::from_str("admin"), Some(Role::Admin));
        assert_eq!(Role::from_str("OPERATOR"), Some(Role::Operator));
        assert_eq!(Role::from_str("User"), Some(Role::User));
        assert_eq!(Role::from_str("auditor"), Some(Role::Auditor));
        assert_eq!(Role::from_str("invalid"), None);
    }

    #[test]
    fn test_can_assume() {
        assert!(Role::Admin.can_assume(&Role::Operator));
        assert!(Role::Admin.can_assume(&Role::User));
        assert!(Role::Admin.can_assume(&Role::Auditor));

        assert!(Role::Operator.can_assume(&Role::User));
        assert!(Role::Operator.can_assume(&Role::Auditor));
        assert!(!Role::Operator.can_assume(&Role::Admin));

        assert!(Role::User.can_assume(&Role::Auditor));
        assert!(!Role::User.can_assume(&Role::Operator));
        assert!(!Role::User.can_assume(&Role::Admin));

        assert!(!Role::Auditor.can_assume(&Role::User));
        assert!(!Role::Auditor.can_assume(&Role::Operator));
        assert!(!Role::Auditor.can_assume(&Role::Admin));
    }

    #[test]
    fn test_hierarchy_level() {
        assert!(Role::Admin.hierarchy_level() > Role::Operator.hierarchy_level());
        assert!(Role::Operator.hierarchy_level() > Role::User.hierarchy_level());
        assert!(Role::User.hierarchy_level() > Role::Auditor.hierarchy_level());
    }

    #[test]
    fn test_all_roles() {
        let all = Role::all();
        assert_eq!(all.len(), 4);
        assert!(all.contains(&Role::Admin));
        assert!(all.contains(&Role::Operator));
        assert!(all.contains(&Role::User));
        assert!(all.contains(&Role::Auditor));
    }
}
