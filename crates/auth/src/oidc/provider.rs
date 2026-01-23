//! OIDC Provider configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Known OIDC providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OidcProvider {
    /// Okta
    Okta,
    /// Auth0
    Auth0,
    /// Azure Active Directory
    AzureAd,
    /// Google
    Google,
    /// Generic OIDC provider
    Generic,
}

impl OidcProvider {
    /// Get the default audience claim name
    pub fn audience_claim(&self) -> &str {
        match self {
            Self::AzureAd => "aud",
            _ => "aud",
        }
    }

    /// Get the default subject claim name
    pub fn subject_claim(&self) -> &str {
        "sub"
    }

    /// Get the default name claim
    pub fn name_claim(&self) -> &str {
        match self {
            Self::AzureAd => "name",
            Self::Okta => "name",
            Self::Auth0 => "name",
            _ => "name",
        }
    }

    /// Get the default email claim
    pub fn email_claim(&self) -> &str {
        "email"
    }

    /// Get the default groups/roles claim
    pub fn groups_claim(&self) -> &str {
        match self {
            Self::AzureAd => "groups",
            Self::Okta => "groups",
            Self::Auth0 => "https://example.com/roles",
            _ => "groups",
        }
    }
}

/// OIDC provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    /// Provider type
    pub provider: OidcProvider,
    /// Issuer URL (e.g., "https://example.okta.com")
    pub issuer: String,
    /// Client ID
    pub client_id: String,
    /// Client secret (optional, for confidential clients)
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    /// Expected audience(s)
    pub audiences: Vec<String>,
    /// JWKS URI (optional, discovered if not set)
    pub jwks_uri: Option<String>,
    /// Token endpoint (optional, discovered if not set)
    pub token_endpoint: Option<String>,
    /// Authorization endpoint (optional, discovered if not set)
    pub authorization_endpoint: Option<String>,
    /// Claim mappings (custom claim name -> standard claim)
    #[serde(default)]
    pub claim_mappings: HashMap<String, String>,
    /// Required claims (token must contain these)
    #[serde(default)]
    pub required_claims: Vec<String>,
    /// Namespace claim (claim containing HSM namespace)
    pub namespace_claim: Option<String>,
    /// Roles claim (claim containing HSM roles)
    pub roles_claim: Option<String>,
    /// Whether to validate token expiration
    #[serde(default = "default_true")]
    pub validate_exp: bool,
    /// Clock skew tolerance in seconds
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    /// Whether this provider is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_clock_skew() -> u64 {
    60
}

impl OidcProviderConfig {
    /// Create a new Okta provider config
    pub fn okta(domain: &str, client_id: &str) -> Self {
        Self {
            provider: OidcProvider::Okta,
            issuer: format!("https://{}", domain),
            client_id: client_id.to_string(),
            client_secret: None,
            audiences: vec![client_id.to_string()],
            jwks_uri: Some(format!("https://{}/oauth2/default/v1/keys", domain)),
            token_endpoint: Some(format!("https://{}/oauth2/default/v1/token", domain)),
            authorization_endpoint: Some(format!("https://{}/oauth2/default/v1/authorize", domain)),
            claim_mappings: HashMap::new(),
            required_claims: vec!["sub".to_string()],
            namespace_claim: Some("namespace".to_string()),
            roles_claim: Some("groups".to_string()),
            validate_exp: true,
            clock_skew_seconds: 60,
            enabled: true,
        }
    }

    /// Create a new Auth0 provider config
    pub fn auth0(domain: &str, client_id: &str, audience: &str) -> Self {
        Self {
            provider: OidcProvider::Auth0,
            issuer: format!("https://{}/", domain),
            client_id: client_id.to_string(),
            client_secret: None,
            audiences: vec![audience.to_string()],
            jwks_uri: Some(format!("https://{}/.well-known/jwks.json", domain)),
            token_endpoint: Some(format!("https://{}/oauth/token", domain)),
            authorization_endpoint: Some(format!("https://{}/authorize", domain)),
            claim_mappings: HashMap::new(),
            required_claims: vec!["sub".to_string()],
            namespace_claim: None,
            roles_claim: Some("https://example.com/roles".to_string()),
            validate_exp: true,
            clock_skew_seconds: 60,
            enabled: true,
        }
    }

    /// Create a new Azure AD provider config
    pub fn azure_ad(tenant_id: &str, client_id: &str) -> Self {
        Self {
            provider: OidcProvider::AzureAd,
            issuer: format!("https://login.microsoftonline.com/{}/v2.0", tenant_id),
            client_id: client_id.to_string(),
            client_secret: None,
            audiences: vec![client_id.to_string()],
            jwks_uri: Some(format!(
                "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
                tenant_id
            )),
            token_endpoint: Some(format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                tenant_id
            )),
            authorization_endpoint: Some(format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant_id
            )),
            claim_mappings: HashMap::new(),
            required_claims: vec!["sub".to_string()],
            namespace_claim: None,
            roles_claim: Some("groups".to_string()),
            validate_exp: true,
            clock_skew_seconds: 60,
            enabled: true,
        }
    }

    /// Create a new Google provider config
    pub fn google(client_id: &str) -> Self {
        Self {
            provider: OidcProvider::Google,
            issuer: "https://accounts.google.com".to_string(),
            client_id: client_id.to_string(),
            client_secret: None,
            audiences: vec![client_id.to_string()],
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            token_endpoint: Some("https://oauth2.googleapis.com/token".to_string()),
            authorization_endpoint: Some(
                "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            ),
            claim_mappings: HashMap::new(),
            required_claims: vec!["sub".to_string(), "email".to_string()],
            namespace_claim: None,
            roles_claim: None,
            validate_exp: true,
            clock_skew_seconds: 60,
            enabled: true,
        }
    }

    /// Create a generic OIDC provider config
    pub fn generic(issuer: &str, client_id: &str) -> Self {
        Self {
            provider: OidcProvider::Generic,
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            client_secret: None,
            audiences: vec![client_id.to_string()],
            jwks_uri: None, // Will be discovered
            token_endpoint: None,
            authorization_endpoint: None,
            claim_mappings: HashMap::new(),
            required_claims: vec!["sub".to_string()],
            namespace_claim: None,
            roles_claim: None,
            validate_exp: true,
            clock_skew_seconds: 60,
            enabled: true,
        }
    }

    /// Set client secret
    pub fn with_client_secret(mut self, secret: &str) -> Self {
        self.client_secret = Some(secret.to_string());
        self
    }

    /// Add an audience
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audiences.push(audience.to_string());
        self
    }

    /// Set namespace claim
    pub fn with_namespace_claim(mut self, claim: &str) -> Self {
        self.namespace_claim = Some(claim.to_string());
        self
    }

    /// Set roles claim
    pub fn with_roles_claim(mut self, claim: &str) -> Self {
        self.roles_claim = Some(claim.to_string());
        self
    }

    /// Add a claim mapping
    pub fn with_claim_mapping(mut self, custom: &str, standard: &str) -> Self {
        self.claim_mappings
            .insert(custom.to_string(), standard.to_string());
        self
    }

    /// Add a required claim
    pub fn require_claim(mut self, claim: &str) -> Self {
        self.required_claims.push(claim.to_string());
        self
    }

    /// Get the JWKS URI (configured or from discovery)
    pub fn get_jwks_uri(&self) -> Option<&str> {
        self.jwks_uri.as_deref()
    }

    /// Get the discovery URL
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_okta_config() {
        let config = OidcProviderConfig::okta("dev-123456.okta.com", "my-client-id");
        assert_eq!(config.provider, OidcProvider::Okta);
        assert!(config.issuer.contains("okta.com"));
    }

    #[test]
    fn test_auth0_config() {
        let config =
            OidcProviderConfig::auth0("myapp.auth0.com", "client-id", "https://api.example.com");
        assert_eq!(config.provider, OidcProvider::Auth0);
        assert!(config
            .audiences
            .contains(&"https://api.example.com".to_string()));
    }

    #[test]
    fn test_azure_ad_config() {
        let config = OidcProviderConfig::azure_ad("tenant-id", "client-id");
        assert_eq!(config.provider, OidcProvider::AzureAd);
        assert!(config.issuer.contains("microsoftonline.com"));
    }

    #[test]
    fn test_discovery_url() {
        let config = OidcProviderConfig::generic("https://example.com", "client-id");
        assert_eq!(
            config.discovery_url(),
            "https://example.com/.well-known/openid-configuration"
        );
    }
}
