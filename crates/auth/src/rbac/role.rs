use serde::{Deserialize, Serialize};
use std::str::FromStr;

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

/// Error returned when parsing an invalid role string
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRoleError(String);

impl std::fmt::Display for ParseRoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid role: {}", self.0)
    }
}

impl std::error::Error for ParseRoleError {}

impl FromStr for Role {
    type Err = ParseRoleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "operator" => Ok(Role::Operator),
            "user" => Ok(Role::User),
            "auditor" => Ok(Role::Auditor),
            _ => Err(ParseRoleError(s.to_string())),
        }
    }
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

    /// Parse a role from a string (convenience method)
    pub fn parse(s: &str) -> Option<Self> {
        s.parse().ok()
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
        assert_eq!("admin".parse::<Role>().ok(), Some(Role::Admin));
        assert_eq!("OPERATOR".parse::<Role>().ok(), Some(Role::Operator));
        assert_eq!("User".parse::<Role>().ok(), Some(Role::User));
        assert_eq!("auditor".parse::<Role>().ok(), Some(Role::Auditor));
        assert!("invalid".parse::<Role>().is_err());
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
