//! Social Login OAuth Providers
//!
//! Provides OAuth2/OIDC authentication support for social login providers:
//! - Google
//! - Apple
//! - GitHub
//! - Microsoft
//! - Facebook
//! - Twitter (X)
//! - Discord
//! - LinkedIn
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Social Login Flow                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  1. Initiate                                                      │
//! │     ┌──────────┐     ┌──────────────┐     ┌──────────────┐       │
//! │     │  Client  │────▶│  HSM Server  │────▶│  Provider    │       │
//! │     └──────────┘     └──────────────┘     │  Auth URL    │       │
//! │                             │              └──────────────┘       │
//! │                             ▼                                     │
//! │                      Generate state                               │
//! │                      Store in cache                               │
//! │                      Return auth URL                              │
//! │                                                                   │
//! │  2. Callback                                                      │
//! │     ┌──────────┐     ┌──────────────┐     ┌──────────────┐       │
//! │     │ Provider │────▶│  HSM Server  │────▶│  Token       │       │
//! │     │ Redirect │     │  /callback   │     │  Endpoint    │       │
//! │     └──────────┘     └──────────────┘     └──────────────┘       │
//! │                             │                    │                │
//! │                             ▼                    ▼                │
//! │                      Validate state       Exchange code           │
//! │                                           for tokens              │
//! │                             │                    │                │
//! │                             ▼                    ▼                │
//! │                      ┌──────────────────────────────────┐        │
//! │                      │     Fetch User Info              │        │
//! │                      │     Create HSM Session           │        │
//! │                      └──────────────────────────────────┘        │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{AuthError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Social login providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SocialProvider {
    /// Google OAuth2
    Google,
    /// Apple Sign In
    Apple,
    /// GitHub OAuth
    GitHub,
    /// Microsoft Identity Platform
    Microsoft,
    /// Facebook Login
    Facebook,
    /// Twitter/X OAuth 2.0
    Twitter,
    /// Discord OAuth2
    Discord,
    /// LinkedIn OAuth 2.0
    LinkedIn,
}

impl SocialProvider {
    /// Get the authorization URL for this provider
    pub fn auth_url(&self) -> &'static str {
        match self {
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            Self::Apple => "https://appleid.apple.com/auth/authorize",
            Self::GitHub => "https://github.com/login/oauth/authorize",
            Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            Self::Facebook => "https://www.facebook.com/v18.0/dialog/oauth",
            Self::Twitter => "https://twitter.com/i/oauth2/authorize",
            Self::Discord => "https://discord.com/api/oauth2/authorize",
            Self::LinkedIn => "https://www.linkedin.com/oauth/v2/authorization",
        }
    }

    /// Get the token URL for this provider
    pub fn token_url(&self) -> &'static str {
        match self {
            Self::Google => "https://oauth2.googleapis.com/token",
            Self::Apple => "https://appleid.apple.com/auth/token",
            Self::GitHub => "https://github.com/login/oauth/access_token",
            Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            Self::Facebook => "https://graph.facebook.com/v18.0/oauth/access_token",
            Self::Twitter => "https://api.twitter.com/2/oauth2/token",
            Self::Discord => "https://discord.com/api/oauth2/token",
            Self::LinkedIn => "https://www.linkedin.com/oauth/v2/accessToken",
        }
    }

    /// Get the user info URL for this provider
    pub fn userinfo_url(&self) -> &'static str {
        match self {
            Self::Google => "https://www.googleapis.com/oauth2/v3/userinfo",
            Self::Apple => "", // Apple returns user info in the id_token
            Self::GitHub => "https://api.github.com/user",
            Self::Microsoft => "https://graph.microsoft.com/v1.0/me",
            Self::Facebook => "https://graph.facebook.com/me?fields=id,name,email,picture",
            Self::Twitter => "https://api.twitter.com/2/users/me",
            Self::Discord => "https://discord.com/api/users/@me",
            Self::LinkedIn => "https://api.linkedin.com/v2/userinfo",
        }
    }

    /// Get the default scopes for this provider
    pub fn default_scopes(&self) -> Vec<&'static str> {
        match self {
            Self::Google => vec!["openid", "email", "profile"],
            Self::Apple => vec!["name", "email"],
            Self::GitHub => vec!["read:user", "user:email"],
            Self::Microsoft => vec!["openid", "email", "profile", "User.Read"],
            Self::Facebook => vec!["email", "public_profile"],
            Self::Twitter => vec!["tweet.read", "users.read", "offline.access"],
            Self::Discord => vec!["identify", "email"],
            Self::LinkedIn => vec!["openid", "profile", "email"],
        }
    }

    /// Get the response type for authorization
    pub fn response_type(&self) -> &'static str {
        match self {
            Self::Apple => "code id_token",
            Self::Twitter => "code",
            _ => "code",
        }
    }

    /// Whether this provider requires PKCE
    pub fn requires_pkce(&self) -> bool {
        matches!(self, Self::Twitter)
    }

    /// Whether this provider uses form post response mode
    pub fn uses_form_post(&self) -> bool {
        matches!(self, Self::Apple)
    }

    /// Get the email endpoint for GitHub (separate endpoint)
    pub fn email_url(&self) -> Option<&'static str> {
        match self {
            Self::GitHub => Some("https://api.github.com/user/emails"),
            _ => None,
        }
    }

    /// Parse from string
    pub fn parse_provider(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "google" => Some(Self::Google),
            "apple" => Some(Self::Apple),
            "github" => Some(Self::GitHub),
            "microsoft" => Some(Self::Microsoft),
            "facebook" => Some(Self::Facebook),
            "twitter" | "x" => Some(Self::Twitter),
            "discord" => Some(Self::Discord),
            "linkedin" => Some(Self::LinkedIn),
            _ => None,
        }
    }
}

impl std::fmt::Display for SocialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Google => write!(f, "google"),
            Self::Apple => write!(f, "apple"),
            Self::GitHub => write!(f, "github"),
            Self::Microsoft => write!(f, "microsoft"),
            Self::Facebook => write!(f, "facebook"),
            Self::Twitter => write!(f, "twitter"),
            Self::Discord => write!(f, "discord"),
            Self::LinkedIn => write!(f, "linkedin"),
        }
    }
}

/// Social login configuration for a specific provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialLoginConfig {
    /// Provider type
    pub provider: SocialProvider,
    /// OAuth client ID
    pub client_id: String,
    /// OAuth client secret
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Custom scopes (uses defaults if empty)
    #[serde(default)]
    pub scopes: Vec<String>,
    /// OAuth redirect URI (callback URL)
    pub redirect_uri: String,
    /// Whether this provider is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Custom authorization URL (overrides default)
    pub custom_auth_url: Option<String>,
    /// Custom token URL (overrides default)
    pub custom_token_url: Option<String>,
    /// Custom userinfo URL (overrides default)
    pub custom_userinfo_url: Option<String>,
    /// Additional authorization parameters
    #[serde(default)]
    pub additional_params: std::collections::HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl SocialLoginConfig {
    /// Create a new social login config
    pub fn new(
        provider: SocialProvider,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: Vec::new(),
            redirect_uri: redirect_uri.into(),
            enabled: true,
            custom_auth_url: None,
            custom_token_url: None,
            custom_userinfo_url: None,
            additional_params: std::collections::HashMap::new(),
        }
    }

    /// Create config for Google
    pub fn google(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::new(
            SocialProvider::Google,
            client_id,
            client_secret,
            redirect_uri,
        )
    }

    /// Create config for Apple
    pub fn apple(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        let mut config = Self::new(
            SocialProvider::Apple,
            client_id,
            client_secret,
            redirect_uri,
        );
        config
            .additional_params
            .insert("response_mode".to_string(), "form_post".to_string());
        config
    }

    /// Create config for GitHub
    pub fn github(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::new(
            SocialProvider::GitHub,
            client_id,
            client_secret,
            redirect_uri,
        )
    }

    /// Create config for Microsoft
    pub fn microsoft(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::new(
            SocialProvider::Microsoft,
            client_id,
            client_secret,
            redirect_uri,
        )
    }

    /// Create config for Facebook
    pub fn facebook(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::new(
            SocialProvider::Facebook,
            client_id,
            client_secret,
            redirect_uri,
        )
    }

    /// Create config for Twitter
    pub fn twitter(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::new(
            SocialProvider::Twitter,
            client_id,
            client_secret,
            redirect_uri,
        )
    }

    /// Create config for Discord
    pub fn discord(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::new(
            SocialProvider::Discord,
            client_id,
            client_secret,
            redirect_uri,
        )
    }

    /// Create config for LinkedIn
    pub fn linkedin(client_id: &str, client_secret: &str, redirect_uri: &str) -> Self {
        Self::new(
            SocialProvider::LinkedIn,
            client_id,
            client_secret,
            redirect_uri,
        )
    }

    /// Set custom scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Add an additional parameter
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_params.insert(key.into(), value.into());
        self
    }

    /// Get effective scopes (custom or default)
    pub fn effective_scopes(&self) -> Vec<&str> {
        if self.scopes.is_empty() {
            self.provider.default_scopes()
        } else {
            self.scopes.iter().map(|s| s.as_str()).collect()
        }
    }

    /// Get effective auth URL
    pub fn effective_auth_url(&self) -> &str {
        self.custom_auth_url
            .as_deref()
            .unwrap_or_else(|| self.provider.auth_url())
    }

    /// Get effective token URL
    pub fn effective_token_url(&self) -> &str {
        self.custom_token_url
            .as_deref()
            .unwrap_or_else(|| self.provider.token_url())
    }

    /// Get effective userinfo URL
    pub fn effective_userinfo_url(&self) -> &str {
        self.custom_userinfo_url
            .as_deref()
            .unwrap_or_else(|| self.provider.userinfo_url())
    }
}

/// OAuth state for CSRF protection
#[derive(Debug, Clone)]
pub struct OAuthState {
    /// State token
    pub state: String,
    /// PKCE code verifier (if required)
    pub code_verifier: Option<String>,
    /// Provider
    pub provider: SocialProvider,
    /// Creation time
    pub created_at: Instant,
    /// Nonce for OIDC
    pub nonce: Option<String>,
    /// Additional data to pass through
    pub extra_data: Option<String>,
}

impl OAuthState {
    /// Check if this state has expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// OAuth authorization request builder
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// Authorization URL
    pub url: String,
    /// State token for CSRF protection
    pub state: String,
    /// PKCE code verifier (keep secret, used in token exchange)
    pub code_verifier: Option<String>,
}

/// OAuth token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Expiration time in seconds
    pub expires_in: Option<u64>,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// Scopes granted
    pub scope: Option<String>,
    /// ID token (for OIDC providers)
    pub id_token: Option<String>,
}

/// Social user info from provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialUserInfo {
    /// Provider
    pub provider: SocialProvider,
    /// User ID from provider
    pub provider_user_id: String,
    /// Email address
    pub email: Option<String>,
    /// Whether email is verified
    pub email_verified: Option<bool>,
    /// Display name
    pub name: Option<String>,
    /// Given name (first name)
    pub given_name: Option<String>,
    /// Family name (last name)
    pub family_name: Option<String>,
    /// Profile picture URL
    pub picture: Option<String>,
    /// Locale/language
    pub locale: Option<String>,
    /// Raw claims from provider
    #[serde(default)]
    pub raw_claims: serde_json::Value,
}

impl SocialUserInfo {
    /// Get a display name (name, email, or ID)
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.email.clone())
            .unwrap_or_else(|| format!("{}:{}", self.provider, self.provider_user_id))
    }

    /// Get the identifier to use for HSM common_name
    pub fn common_name(&self) -> String {
        format!("{}:{}", self.provider, self.provider_user_id)
    }
}

/// Social login manager
pub struct SocialLoginManager {
    /// Provider configurations
    configs: DashMap<SocialProvider, SocialLoginConfig>,
    /// Pending OAuth states (state_token -> OAuthState)
    pending_states: DashMap<String, OAuthState>,
    /// State TTL
    state_ttl: Duration,
    /// HTTP client
    http_client: reqwest::Client,
}

impl SocialLoginManager {
    /// Create a new social login manager
    pub fn new() -> Self {
        Self {
            configs: DashMap::new(),
            pending_states: DashMap::new(),
            state_ttl: Duration::from_secs(600), // 10 minutes
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Create with custom state TTL
    pub fn with_state_ttl(mut self, ttl: Duration) -> Self {
        self.state_ttl = ttl;
        self
    }

    /// Register a provider configuration
    pub fn register_provider(&self, config: SocialLoginConfig) {
        self.configs.insert(config.provider, config);
    }

    /// Get provider configuration
    pub fn get_config(&self, provider: SocialProvider) -> Option<SocialLoginConfig> {
        self.configs.get(&provider).map(|c| c.clone())
    }

    /// Check if a provider is configured and enabled
    pub fn is_provider_enabled(&self, provider: SocialProvider) -> bool {
        self.configs
            .get(&provider)
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Get all enabled providers
    pub fn enabled_providers(&self) -> Vec<SocialProvider> {
        self.configs
            .iter()
            .filter(|c| c.enabled)
            .map(|c| *c.key())
            .collect()
    }

    /// Generate a secure random state token
    fn generate_state_token() -> String {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
        hex::encode(bytes)
    }

    /// Generate PKCE code verifier and challenge
    fn generate_pkce() -> (String, String) {
        let mut verifier_bytes = [0u8; 32];
        getrandom::getrandom(&mut verifier_bytes).expect("Failed to generate random bytes");
        let verifier = base64_url_encode(&verifier_bytes);

        // S256 challenge
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = base64_url_encode(&hasher.finalize());

        (verifier, challenge)
    }

    /// Initiate OAuth flow for a provider
    pub fn initiate_auth(
        &self,
        provider: SocialProvider,
        extra_data: Option<String>,
    ) -> Result<AuthorizationRequest> {
        let config = self
            .configs
            .get(&provider)
            .ok_or_else(|| AuthError::Internal(format!("Provider {} not configured", provider)))?;

        if !config.enabled {
            return Err(AuthError::Internal(format!(
                "Provider {} is not enabled",
                provider
            )));
        }

        // Generate state token
        let state = Self::generate_state_token();

        // Generate PKCE if required
        let (code_verifier, code_challenge) = if provider.requires_pkce() {
            let (verifier, challenge) = Self::generate_pkce();
            (Some(verifier), Some(challenge))
        } else {
            (None, None)
        };

        // Generate nonce for OIDC
        let nonce = if matches!(
            provider,
            SocialProvider::Google
                | SocialProvider::Apple
                | SocialProvider::Microsoft
                | SocialProvider::LinkedIn
        ) {
            Some(Self::generate_state_token())
        } else {
            None
        };

        // Build authorization URL
        let mut url = url::Url::parse(config.effective_auth_url())
            .map_err(|e| AuthError::Internal(format!("Invalid auth URL: {}", e)))?;

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("client_id", &config.client_id);
            params.append_pair("redirect_uri", &config.redirect_uri);
            params.append_pair("response_type", provider.response_type());
            params.append_pair("scope", &config.effective_scopes().join(" "));
            params.append_pair("state", &state);

            if let Some(ref n) = nonce {
                params.append_pair("nonce", n);
            }

            if let Some(ref challenge) = code_challenge {
                params.append_pair("code_challenge", challenge);
                params.append_pair("code_challenge_method", "S256");
            }

            // Add provider-specific params
            for (key, value) in &config.additional_params {
                params.append_pair(key, value);
            }
        }

        // Store state
        let oauth_state = OAuthState {
            state: state.clone(),
            code_verifier: code_verifier.clone(),
            provider,
            created_at: Instant::now(),
            nonce,
            extra_data,
        };
        self.pending_states.insert(state.clone(), oauth_state);

        Ok(AuthorizationRequest {
            url: url.to_string(),
            state,
            code_verifier,
        })
    }

    /// Validate and consume OAuth state
    pub fn validate_state(&self, state: &str) -> Result<OAuthState> {
        let (_, oauth_state) = self.pending_states.remove(state).ok_or_else(|| {
            AuthError::InvalidSession("Invalid or expired OAuth state".to_string())
        })?;

        if oauth_state.is_expired(self.state_ttl) {
            return Err(AuthError::SessionExpired);
        }

        Ok(oauth_state)
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(
        &self,
        provider: SocialProvider,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuthTokenResponse> {
        let config = self
            .configs
            .get(&provider)
            .ok_or_else(|| AuthError::Internal(format!("Provider {} not configured", provider)))?;

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
        ];

        if let Some(verifier) = code_verifier {
            params.push(("code_verifier", verifier));
        }

        let response = self
            .http_client
            .post(config.effective_token_url())
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Token request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::Internal(format!(
                "Token exchange failed: {}",
                error_text
            )));
        }

        let tokens: OAuthTokenResponse = response
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to parse token response: {}", e)))?;

        Ok(tokens)
    }

    /// Fetch user info from provider
    pub async fn fetch_user_info(
        &self,
        provider: SocialProvider,
        access_token: &str,
    ) -> Result<SocialUserInfo> {
        let config = self
            .configs
            .get(&provider)
            .ok_or_else(|| AuthError::Internal(format!("Provider {} not configured", provider)))?;

        let userinfo_url = config.effective_userinfo_url();

        // Apple returns user info in the ID token, not via API
        if provider == SocialProvider::Apple && userinfo_url.is_empty() {
            return Err(AuthError::Internal(
                "Apple user info must be extracted from id_token".to_string(),
            ));
        }

        let response = self
            .http_client
            .get(userinfo_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("User info request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::Internal(format!(
                "User info fetch failed: {}",
                error_text
            )));
        }

        let raw_claims: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to parse user info: {}", e)))?;

        // Parse provider-specific response
        let user_info = self.parse_user_info(provider, raw_claims)?;

        Ok(user_info)
    }

    /// Parse provider-specific user info response
    fn parse_user_info(
        &self,
        provider: SocialProvider,
        raw: serde_json::Value,
    ) -> Result<SocialUserInfo> {
        match provider {
            SocialProvider::Google => self.parse_google_user(&raw),
            SocialProvider::GitHub => self.parse_github_user(&raw),
            SocialProvider::Microsoft => self.parse_microsoft_user(&raw),
            SocialProvider::Facebook => self.parse_facebook_user(&raw),
            SocialProvider::Twitter => self.parse_twitter_user(&raw),
            SocialProvider::Discord => self.parse_discord_user(&raw),
            SocialProvider::LinkedIn => self.parse_linkedin_user(&raw),
            SocialProvider::Apple => Err(AuthError::Internal(
                "Use parse_apple_id_token instead".to_string(),
            )),
        }
    }

    fn parse_google_user(&self, raw: &serde_json::Value) -> Result<SocialUserInfo> {
        Ok(SocialUserInfo {
            provider: SocialProvider::Google,
            provider_user_id: raw["sub"].as_str().unwrap_or_default().to_string(),
            email: raw["email"].as_str().map(|s| s.to_string()),
            email_verified: raw["email_verified"].as_bool(),
            name: raw["name"].as_str().map(|s| s.to_string()),
            given_name: raw["given_name"].as_str().map(|s| s.to_string()),
            family_name: raw["family_name"].as_str().map(|s| s.to_string()),
            picture: raw["picture"].as_str().map(|s| s.to_string()),
            locale: raw["locale"].as_str().map(|s| s.to_string()),
            raw_claims: raw.clone(),
        })
    }

    fn parse_github_user(&self, raw: &serde_json::Value) -> Result<SocialUserInfo> {
        Ok(SocialUserInfo {
            provider: SocialProvider::GitHub,
            provider_user_id: raw["id"]
                .as_i64()
                .map(|i| i.to_string())
                .unwrap_or_default(),
            email: raw["email"].as_str().map(|s| s.to_string()),
            email_verified: None, // GitHub doesn't provide this in user endpoint
            name: raw["name"].as_str().map(|s| s.to_string()),
            given_name: None,
            family_name: None,
            picture: raw["avatar_url"].as_str().map(|s| s.to_string()),
            locale: None,
            raw_claims: raw.clone(),
        })
    }

    fn parse_microsoft_user(&self, raw: &serde_json::Value) -> Result<SocialUserInfo> {
        Ok(SocialUserInfo {
            provider: SocialProvider::Microsoft,
            provider_user_id: raw["id"].as_str().unwrap_or_default().to_string(),
            email: raw["mail"]
                .as_str()
                .or_else(|| raw["userPrincipalName"].as_str())
                .map(|s| s.to_string()),
            email_verified: None,
            name: raw["displayName"].as_str().map(|s| s.to_string()),
            given_name: raw["givenName"].as_str().map(|s| s.to_string()),
            family_name: raw["surname"].as_str().map(|s| s.to_string()),
            picture: None, // Microsoft Graph requires separate call for photo
            locale: raw["preferredLanguage"].as_str().map(|s| s.to_string()),
            raw_claims: raw.clone(),
        })
    }

    fn parse_facebook_user(&self, raw: &serde_json::Value) -> Result<SocialUserInfo> {
        Ok(SocialUserInfo {
            provider: SocialProvider::Facebook,
            provider_user_id: raw["id"].as_str().unwrap_or_default().to_string(),
            email: raw["email"].as_str().map(|s| s.to_string()),
            email_verified: None,
            name: raw["name"].as_str().map(|s| s.to_string()),
            given_name: raw["first_name"].as_str().map(|s| s.to_string()),
            family_name: raw["last_name"].as_str().map(|s| s.to_string()),
            picture: raw["picture"]["data"]["url"]
                .as_str()
                .map(|s| s.to_string()),
            locale: None,
            raw_claims: raw.clone(),
        })
    }

    fn parse_twitter_user(&self, raw: &serde_json::Value) -> Result<SocialUserInfo> {
        let data = &raw["data"];
        Ok(SocialUserInfo {
            provider: SocialProvider::Twitter,
            provider_user_id: data["id"].as_str().unwrap_or_default().to_string(),
            email: None, // Twitter requires elevated access for email
            email_verified: None,
            name: data["name"].as_str().map(|s| s.to_string()),
            given_name: None,
            family_name: None,
            picture: data["profile_image_url"].as_str().map(|s| s.to_string()),
            locale: None,
            raw_claims: raw.clone(),
        })
    }

    fn parse_discord_user(&self, raw: &serde_json::Value) -> Result<SocialUserInfo> {
        let avatar = if let (Some(id), Some(avatar)) = (raw["id"].as_str(), raw["avatar"].as_str())
        {
            Some(format!(
                "https://cdn.discordapp.com/avatars/{}/{}.png",
                id, avatar
            ))
        } else {
            None
        };

        Ok(SocialUserInfo {
            provider: SocialProvider::Discord,
            provider_user_id: raw["id"].as_str().unwrap_or_default().to_string(),
            email: raw["email"].as_str().map(|s| s.to_string()),
            email_verified: raw["verified"].as_bool(),
            name: raw["global_name"]
                .as_str()
                .or_else(|| raw["username"].as_str())
                .map(|s| s.to_string()),
            given_name: None,
            family_name: None,
            picture: avatar,
            locale: raw["locale"].as_str().map(|s| s.to_string()),
            raw_claims: raw.clone(),
        })
    }

    fn parse_linkedin_user(&self, raw: &serde_json::Value) -> Result<SocialUserInfo> {
        Ok(SocialUserInfo {
            provider: SocialProvider::LinkedIn,
            provider_user_id: raw["sub"].as_str().unwrap_or_default().to_string(),
            email: raw["email"].as_str().map(|s| s.to_string()),
            email_verified: raw["email_verified"].as_bool(),
            name: raw["name"].as_str().map(|s| s.to_string()),
            given_name: raw["given_name"].as_str().map(|s| s.to_string()),
            family_name: raw["family_name"].as_str().map(|s| s.to_string()),
            picture: raw["picture"].as_str().map(|s| s.to_string()),
            locale: raw["locale"].as_str().map(|s| s.to_string()),
            raw_claims: raw.clone(),
        })
    }

    /// Parse Apple ID token to extract user info
    pub fn parse_apple_id_token(&self, id_token: &str) -> Result<SocialUserInfo> {
        // Split JWT
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::Internal("Invalid ID token format".to_string()));
        }

        // Decode payload (base64url)
        let payload = base64_url_decode(parts[1])
            .map_err(|e| AuthError::Internal(format!("Failed to decode ID token: {}", e)))?;

        let claims: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| AuthError::Internal(format!("Failed to parse ID token claims: {}", e)))?;

        Ok(SocialUserInfo {
            provider: SocialProvider::Apple,
            provider_user_id: claims["sub"].as_str().unwrap_or_default().to_string(),
            email: claims["email"].as_str().map(|s| s.to_string()),
            email_verified: claims["email_verified"]
                .as_bool()
                .or_else(|| claims["email_verified"].as_str().map(|s| s == "true")),
            name: None, // Apple sends name only on first auth
            given_name: None,
            family_name: None,
            picture: None,
            locale: None,
            raw_claims: claims,
        })
    }

    /// Complete OAuth flow - validate state, exchange code, fetch user info
    pub async fn complete_auth(
        &self,
        state: &str,
        code: &str,
    ) -> Result<(OAuthTokenResponse, SocialUserInfo)> {
        // Validate state
        let oauth_state = self.validate_state(state)?;

        // Exchange code for tokens
        let tokens = self
            .exchange_code(
                oauth_state.provider,
                code,
                oauth_state.code_verifier.as_deref(),
            )
            .await?;

        // Fetch or parse user info
        let user_info = if oauth_state.provider == SocialProvider::Apple {
            if let Some(ref id_token) = tokens.id_token {
                self.parse_apple_id_token(id_token)?
            } else {
                return Err(AuthError::Internal(
                    "Apple auth requires id_token".to_string(),
                ));
            }
        } else {
            self.fetch_user_info(oauth_state.provider, &tokens.access_token)
                .await?
        };

        Ok((tokens, user_info))
    }

    /// Clean up expired states
    pub fn cleanup_expired_states(&self) -> usize {
        let before = self.pending_states.len();
        self.pending_states
            .retain(|_, state| !state.is_expired(self.state_ttl));
        before - self.pending_states.len()
    }

    /// Get GitHub user emails (requires separate API call)
    pub async fn fetch_github_emails(&self, access_token: &str) -> Result<Vec<GitHubEmail>> {
        let response = self
            .http_client
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Accept", "application/json")
            .header("User-Agent", "hsm-auth")
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("GitHub emails request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::Internal(format!(
                "GitHub emails fetch failed: {}",
                error_text
            )));
        }

        let emails: Vec<GitHubEmail> = response
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to parse GitHub emails: {}", e)))?;

        Ok(emails)
    }
}

impl Default for SocialLoginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// GitHub email entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubEmail {
    /// Email address
    pub email: String,
    /// Is this the primary email
    pub primary: bool,
    /// Is this email verified
    pub verified: bool,
    /// Visibility (public, private)
    pub visibility: Option<String>,
}

/// Base64 URL-safe encoding without padding
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

/// Base64 URL-safe decoding
fn base64_url_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_social_provider_urls() {
        assert!(SocialProvider::Google.auth_url().contains("google"));
        assert!(SocialProvider::GitHub.auth_url().contains("github"));
        assert!(SocialProvider::Apple.auth_url().contains("apple"));
        assert!(SocialProvider::Microsoft.auth_url().contains("microsoft"));
    }

    #[test]
    fn test_social_provider_scopes() {
        assert!(SocialProvider::Google.default_scopes().contains(&"email"));
        assert!(SocialProvider::GitHub
            .default_scopes()
            .contains(&"read:user"));
        assert!(SocialProvider::Discord
            .default_scopes()
            .contains(&"identify"));
    }

    #[test]
    fn test_social_login_config() {
        let config =
            SocialLoginConfig::google("client-id", "secret", "https://example.com/callback");
        assert_eq!(config.provider, SocialProvider::Google);
        assert_eq!(config.client_id, "client-id");
        assert!(config.enabled);
    }

    #[test]
    fn test_provider_from_str() {
        assert_eq!(
            SocialProvider::parse_provider("google"),
            Some(SocialProvider::Google)
        );
        assert_eq!(
            SocialProvider::parse_provider("GITHUB"),
            Some(SocialProvider::GitHub)
        );
        assert_eq!(SocialProvider::parse_provider("x"), Some(SocialProvider::Twitter));
        assert_eq!(SocialProvider::parse_provider("invalid"), None);
    }

    #[test]
    fn test_social_login_manager() {
        let manager = SocialLoginManager::new();

        // Register provider
        manager.register_provider(SocialLoginConfig::google(
            "client-id",
            "secret",
            "https://example.com/callback",
        ));

        assert!(manager.is_provider_enabled(SocialProvider::Google));
        assert!(!manager.is_provider_enabled(SocialProvider::GitHub));
    }

    #[test]
    fn test_initiate_auth() {
        let manager = SocialLoginManager::new();
        manager.register_provider(SocialLoginConfig::google(
            "test-client-id",
            "test-secret",
            "https://example.com/callback",
        ));

        let auth_request = manager.initiate_auth(SocialProvider::Google, None).unwrap();

        assert!(auth_request.url.contains("accounts.google.com"));
        assert!(auth_request.url.contains("client_id=test-client-id"));
        assert!(!auth_request.state.is_empty());
    }

    #[test]
    fn test_state_validation() {
        let manager = SocialLoginManager::new();
        manager.register_provider(SocialLoginConfig::google(
            "test-client-id",
            "test-secret",
            "https://example.com/callback",
        ));

        let auth_request = manager.initiate_auth(SocialProvider::Google, None).unwrap();

        // Valid state should work
        let state = manager.validate_state(&auth_request.state).unwrap();
        assert_eq!(state.provider, SocialProvider::Google);

        // Same state should fail (consumed)
        assert!(manager.validate_state(&auth_request.state).is_err());
    }

    #[test]
    fn test_social_user_info() {
        let user = SocialUserInfo {
            provider: SocialProvider::Google,
            provider_user_id: "123456".to_string(),
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            picture: None,
            locale: None,
            raw_claims: serde_json::json!({}),
        };

        assert_eq!(user.display_name(), "Test User");
        assert_eq!(user.common_name(), "google:123456");
    }
}
