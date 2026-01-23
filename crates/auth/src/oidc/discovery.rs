//! OpenID Connect Discovery

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Discovery error
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// HTTP error
    #[error("HTTP error: {0}")]
    Http(String),
    /// Parse error
    #[error("Parse error: {0}")]
    Parse(String),
}

/// OpenID Connect Discovery document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    /// Issuer identifier
    pub issuer: String,
    /// Authorization endpoint
    pub authorization_endpoint: Option<String>,
    /// Token endpoint
    pub token_endpoint: Option<String>,
    /// UserInfo endpoint
    pub userinfo_endpoint: Option<String>,
    /// JWKS URI
    pub jwks_uri: String,
    /// Registration endpoint
    pub registration_endpoint: Option<String>,
    /// Scopes supported
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Response types supported
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// Response modes supported
    #[serde(default)]
    pub response_modes_supported: Vec<String>,
    /// Grant types supported
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// Subject types supported
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    /// ID token signing algorithms supported
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Token endpoint auth methods supported
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Claims supported
    #[serde(default)]
    pub claims_supported: Vec<String>,
    /// Code challenge methods supported (PKCE)
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Revocation endpoint
    pub revocation_endpoint: Option<String>,
    /// Introspection endpoint
    pub introspection_endpoint: Option<String>,
    /// End session endpoint
    pub end_session_endpoint: Option<String>,
}

impl OidcDiscovery {
    /// Fetch discovery document from issuer
    pub async fn fetch(issuer: &str) -> Result<Self, DiscoveryError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        let client = reqwest::Client::new();
        let response = client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e: reqwest::Error| DiscoveryError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(DiscoveryError::Http(format!("HTTP {}: {}", status, text)));
        }

        response
            .json::<Self>()
            .await
            .map_err(|e: reqwest::Error| DiscoveryError::Parse(e.to_string()))
    }

    /// Check if a scope is supported
    pub fn supports_scope(&self, scope: &str) -> bool {
        self.scopes_supported.contains(&scope.to_string())
    }

    /// Check if a response type is supported
    pub fn supports_response_type(&self, response_type: &str) -> bool {
        self.response_types_supported
            .contains(&response_type.to_string())
    }

    /// Check if a grant type is supported
    pub fn supports_grant_type(&self, grant_type: &str) -> bool {
        self.grant_types_supported.contains(&grant_type.to_string())
    }

    /// Check if PKCE is supported
    pub fn supports_pkce(&self) -> bool {
        !self.code_challenge_methods_supported.is_empty()
    }

    /// Check if a claim is supported
    pub fn supports_claim(&self, claim: &str) -> bool {
        self.claims_supported.contains(&claim.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_discovery() -> OidcDiscovery {
        OidcDiscovery {
            issuer: "https://example.com".to_string(),
            authorization_endpoint: Some("https://example.com/authorize".to_string()),
            token_endpoint: Some("https://example.com/token".to_string()),
            userinfo_endpoint: Some("https://example.com/userinfo".to_string()),
            jwks_uri: "https://example.com/.well-known/jwks.json".to_string(),
            registration_endpoint: None,
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: vec!["query".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            token_endpoint_auth_methods_supported: vec!["client_secret_post".to_string()],
            claims_supported: vec!["sub".to_string(), "email".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            revocation_endpoint: None,
            introspection_endpoint: None,
            end_session_endpoint: None,
        }
    }

    #[test]
    fn test_supports_scope() {
        let discovery = create_test_discovery();
        assert!(discovery.supports_scope("openid"));
        assert!(!discovery.supports_scope("custom"));
    }

    #[test]
    fn test_supports_pkce() {
        let discovery = create_test_discovery();
        assert!(discovery.supports_pkce());
    }
}
