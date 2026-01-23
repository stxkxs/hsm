//! OIDC claims processing

use super::provider::OidcProviderConfig;
use crate::{mtls::ClientIdentity, rbac::Role};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard OIDC claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// Subject (unique user identifier)
    pub sub: String,
    /// Issuer
    pub iss: Option<String>,
    /// Audience
    pub aud: Option<serde_json::Value>,
    /// Expiration time
    pub exp: Option<i64>,
    /// Issued at
    pub iat: Option<i64>,
    /// Not before
    pub nbf: Option<i64>,
    /// JWT ID
    pub jti: Option<String>,
    /// Name
    pub name: Option<String>,
    /// Email
    pub email: Option<String>,
    /// Email verified
    pub email_verified: Option<bool>,
    /// Groups/roles
    pub groups: Option<Vec<String>>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl OidcClaims {
    /// Get a custom claim value
    pub fn get_claim(&self, name: &str) -> Option<&serde_json::Value> {
        self.custom.get(name)
    }

    /// Get a claim as string
    pub fn get_string_claim(&self, name: &str) -> Option<String> {
        self.custom
            .get(name)
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Get a claim as string array
    pub fn get_string_array_claim(&self, name: &str) -> Option<Vec<String>> {
        self.custom.get(name).and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
        })
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.exp {
            let now = chrono::Utc::now().timestamp();
            now > exp
        } else {
            false // No exp claim means not expired
        }
    }

    /// Check if token is valid (not expired, not before nbf)
    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now().timestamp();

        // Check expiration
        if let Some(exp) = self.exp {
            if now > exp {
                return false;
            }
        }

        // Check not before
        if let Some(nbf) = self.nbf {
            if now < nbf {
                return false;
            }
        }

        true
    }

    /// Get audience(s) as a vector
    pub fn audiences(&self) -> Vec<String> {
        match &self.aud {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            _ => vec![],
        }
    }
}

/// Claims mapper for converting OIDC claims to HSM identity
pub struct ClaimsMapper {
    /// Provider configuration
    config: OidcProviderConfig,
    /// Role mappings (claim value -> HSM role)
    role_mappings: HashMap<String, Role>,
    /// Default role if no mapping found
    default_role: Role,
    /// Default namespace
    default_namespace: String,
}

impl ClaimsMapper {
    /// Create a new claims mapper
    pub fn new(config: OidcProviderConfig) -> Self {
        Self {
            config,
            role_mappings: HashMap::new(),
            default_role: Role::User,
            default_namespace: "default".to_string(),
        }
    }

    /// Add a role mapping
    pub fn with_role_mapping(mut self, claim_value: &str, role: Role) -> Self {
        self.role_mappings.insert(claim_value.to_string(), role);
        self
    }

    /// Set default role
    pub fn with_default_role(mut self, role: Role) -> Self {
        self.default_role = role;
        self
    }

    /// Set default namespace
    pub fn with_default_namespace(mut self, namespace: &str) -> Self {
        self.default_namespace = namespace.to_string();
        self
    }

    /// Map OIDC claims to HSM ClientIdentity
    pub fn map_to_identity(&self, claims: &OidcClaims) -> ClientIdentity {
        // Get common name (subject or name)
        let common_name = claims.name.clone().unwrap_or_else(|| claims.sub.clone());

        // Get organization (from issuer)
        let organization = claims.iss.clone();

        // Get namespace from custom claim
        let namespace = self
            .config
            .namespace_claim
            .as_ref()
            .and_then(|claim| claims.get_string_claim(claim))
            .unwrap_or_else(|| self.default_namespace.clone());

        // Get roles from claims
        let roles = self.map_roles(claims);

        // Use subject as certificate serial (for compatibility)
        let cert_serial = claims.sub.clone();

        ClientIdentity::new(common_name, organization, namespace, roles, cert_serial)
    }

    /// Map claim values to HSM roles
    fn map_roles(&self, claims: &OidcClaims) -> Vec<Role> {
        let mut roles = Vec::new();

        // Get roles from configured claim
        let claim_roles = self
            .config
            .roles_claim
            .as_ref()
            .and_then(|claim| claims.get_string_array_claim(claim))
            .or_else(|| claims.groups.clone())
            .unwrap_or_default();

        // Map each claim value to a role
        for claim_value in claim_roles {
            if let Some(role) = self.role_mappings.get(&claim_value) {
                roles.push(*role);
            } else {
                // Try to parse role from claim value
                if let Some(role) = self.parse_role(&claim_value) {
                    roles.push(role);
                }
            }
        }

        // Add default role if no roles found
        if roles.is_empty() {
            roles.push(self.default_role);
        }

        // Deduplicate
        roles.sort();
        roles.dedup();

        roles
    }

    /// Try to parse a role from a claim value
    fn parse_role(&self, value: &str) -> Option<Role> {
        let lower = value.to_lowercase();
        if lower.contains("admin") {
            Some(Role::Admin)
        } else if lower.contains("operator") {
            Some(Role::Operator)
        } else if lower.contains("auditor") {
            Some(Role::Auditor)
        } else if lower.contains("user") {
            Some(Role::User)
        } else {
            None
        }
    }

    /// Validate required claims
    pub fn validate_required_claims(&self, claims: &OidcClaims) -> Result<(), String> {
        for required in &self.config.required_claims {
            match required.as_str() {
                "sub" if claims.sub.is_empty() => {
                    return Err("Missing required claim: sub".to_string());
                }
                "email" if claims.email.is_none() => {
                    return Err("Missing required claim: email".to_string());
                }
                "name" if claims.name.is_none() => {
                    return Err("Missing required claim: name".to_string());
                }
                claim => {
                    if claims.get_claim(claim).is_none() {
                        return Err(format!("Missing required claim: {}", claim));
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate audience
    pub fn validate_audience(&self, claims: &OidcClaims) -> bool {
        let token_audiences = claims.audiences();
        self.config
            .audiences
            .iter()
            .any(|expected| token_audiences.contains(expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_claims() -> OidcClaims {
        OidcClaims {
            sub: "user123".to_string(),
            iss: Some("https://example.com".to_string()),
            aud: Some(serde_json::Value::String("client-id".to_string())),
            exp: Some(chrono::Utc::now().timestamp() + 3600),
            iat: Some(chrono::Utc::now().timestamp()),
            nbf: None,
            jti: Some("jwt-id-123".to_string()),
            name: Some("John Doe".to_string()),
            email: Some("john@example.com".to_string()),
            email_verified: Some(true),
            groups: Some(vec!["admin".to_string(), "users".to_string()]),
            custom: HashMap::new(),
        }
    }

    #[test]
    fn test_claims_validity() {
        let claims = create_test_claims();
        assert!(claims.is_valid());
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_expired_claims() {
        let mut claims = create_test_claims();
        claims.exp = Some(chrono::Utc::now().timestamp() - 100);
        assert!(!claims.is_valid());
        assert!(claims.is_expired());
    }

    #[test]
    fn test_claims_mapper() {
        let config = OidcProviderConfig::generic("https://example.com", "client-id")
            .with_roles_claim("groups");
        let mapper = ClaimsMapper::new(config)
            .with_role_mapping("admin", Role::Admin)
            .with_role_mapping("users", Role::User);

        let claims = create_test_claims();
        let identity = mapper.map_to_identity(&claims);

        assert_eq!(identity.common_name, "John Doe");
        assert!(identity.roles.contains(&Role::Admin));
    }

    #[test]
    fn test_audience_validation() {
        let config = OidcProviderConfig::generic("https://example.com", "client-id");
        let mapper = ClaimsMapper::new(config);

        let claims = create_test_claims();
        assert!(mapper.validate_audience(&claims));
    }

    #[test]
    fn test_multiple_audiences() {
        let claims = OidcClaims {
            sub: "user123".to_string(),
            iss: None,
            aud: Some(serde_json::json!(["client-id", "other-client"])),
            exp: None,
            iat: None,
            nbf: None,
            jti: None,
            name: None,
            email: None,
            email_verified: None,
            groups: None,
            custom: HashMap::new(),
        };

        let auds = claims.audiences();
        assert_eq!(auds.len(), 2);
        assert!(auds.contains(&"client-id".to_string()));
    }
}
