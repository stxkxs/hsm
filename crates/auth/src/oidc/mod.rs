//! OpenID Connect (OIDC) Authentication
//!
//! Provides OIDC/OAuth2 authentication support including:
//! - JWT validation
//! - JWKS (JSON Web Key Set) caching
//! - Provider discovery
//! - Claims-to-identity mapping
//!
//! # Supported Providers
//!
//! - Okta
//! - Auth0
//! - Azure AD
//! - Google
//! - Generic OIDC-compliant providers
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     OIDC Authentication                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     │
//! │  │  JWT Token   │────▶│  Validator   │────▶│   Identity   │     │
//! │  │  (Bearer)    │     │  (JWKS)      │     │   Mapper     │     │
//! │  └──────────────┘     └──────────────┘     └──────────────┘     │
//! │                              │                    │              │
//! │                              ▼                    ▼              │
//! │                       ┌──────────────┐    ┌──────────────┐      │
//! │                       │   Provider   │    │  HSM Client  │      │
//! │                       │   Discovery  │    │   Identity   │      │
//! │                       └──────────────┘    └──────────────┘      │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod claims;
pub mod discovery;
pub mod jwt;
pub mod provider;
pub mod social;
pub mod token_cache;

pub use claims::{ClaimsMapper, OidcClaims};
pub use discovery::OidcDiscovery;
pub use jwt::{JwtValidationError, JwtValidator};
pub use provider::{OidcProvider, OidcProviderConfig};
pub use social::{
    AuthorizationRequest, GitHubEmail, OAuthState, OAuthTokenResponse, SocialLoginConfig,
    SocialLoginManager, SocialProvider, SocialUserInfo,
};
pub use token_cache::JwksCache;
