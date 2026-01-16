use crate::error::{AuthError, Result};
use crate::rbac::Role;
use serde::{Deserialize, Serialize};

/// Client identity extracted from mTLS certificate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Common Name (CN) from certificate subject
    pub common_name: String,

    /// Organization (O) from certificate subject
    pub organization: Option<String>,

    /// Namespace this client has access to
    pub namespace: String,

    /// Roles assigned to this client
    pub roles: Vec<Role>,

    /// Certificate serial number for tracking
    pub serial_number: String,
}

impl ClientIdentity {
    /// Create a new client identity
    pub fn new(
        common_name: String,
        organization: Option<String>,
        namespace: String,
        roles: Vec<Role>,
        serial_number: String,
    ) -> Self {
        Self {
            common_name,
            organization,
            namespace,
            roles,
            serial_number,
        }
    }

    /// Check if this identity has a specific role
    pub fn has_role(&self, role: &Role) -> bool {
        self.roles.contains(role)
    }

    /// Check if this identity can access the given namespace
    pub fn can_access_namespace(&self, namespace: &str) -> bool {
        self.namespace == namespace
    }

    /// Validate that the identity has at least one role
    pub fn validate(&self) -> Result<()> {
        if self.roles.is_empty() {
            return Err(AuthError::InvalidCertificate(
                "Identity must have at least one role".to_string(),
            ));
        }

        if self.common_name.is_empty() {
            return Err(AuthError::InvalidCertificate(
                "Common name cannot be empty".to_string(),
            ));
        }

        if self.namespace.is_empty() {
            return Err(AuthError::InvalidCertificate(
                "Namespace cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_identity_creation() {
        let identity = ClientIdentity::new(
            "client1".to_string(),
            Some("org1".to_string()),
            "namespace1".to_string(),
            vec![Role::User],
            "123456".to_string(),
        );

        assert_eq!(identity.common_name, "client1");
        assert_eq!(identity.organization, Some("org1".to_string()));
        assert_eq!(identity.namespace, "namespace1");
        assert_eq!(identity.roles, vec![Role::User]);
    }

    #[test]
    fn test_has_role() {
        let identity = ClientIdentity::new(
            "client1".to_string(),
            None,
            "namespace1".to_string(),
            vec![Role::User, Role::Operator],
            "123456".to_string(),
        );

        assert!(identity.has_role(&Role::User));
        assert!(identity.has_role(&Role::Operator));
        assert!(!identity.has_role(&Role::Admin));
    }

    #[test]
    fn test_can_access_namespace() {
        let identity = ClientIdentity::new(
            "client1".to_string(),
            None,
            "namespace1".to_string(),
            vec![Role::User],
            "123456".to_string(),
        );

        assert!(identity.can_access_namespace("namespace1"));
        assert!(!identity.can_access_namespace("namespace2"));
    }

    #[test]
    fn test_validation() {
        let mut identity = ClientIdentity::new(
            "client1".to_string(),
            None,
            "namespace1".to_string(),
            vec![Role::User],
            "123456".to_string(),
        );

        assert!(identity.validate().is_ok());

        // Test with no roles
        identity.roles.clear();
        assert!(identity.validate().is_err());

        // Test with empty common name
        identity.roles = vec![Role::User];
        identity.common_name = "".to_string();
        assert!(identity.validate().is_err());

        // Test with empty namespace
        identity.common_name = "client1".to_string();
        identity.namespace = "".to_string();
        assert!(identity.validate().is_err());
    }
}
