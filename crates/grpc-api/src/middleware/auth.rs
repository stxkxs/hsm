use crate::error::{ApiError, Result};
use hsm_auth::{AuthService, ClientIdentity, Permission};
use std::sync::Arc;
use tonic::Request;
use tracing::{debug, warn};

/// Authentication and authorization interceptor using AuthService
pub struct AuthInterceptor {
    /// Optional auth service - when None, authentication is disabled (dev mode)
    auth_service: Option<Arc<AuthService>>,
}

impl AuthInterceptor {
    /// Create a new AuthInterceptor with an AuthService
    pub fn new(auth_service: Option<Arc<AuthService>>) -> Self {
        if auth_service.is_none() {
            warn!("AuthInterceptor created without AuthService - authentication disabled");
        }
        Self { auth_service }
    }

    /// Create a stub AuthInterceptor for testing/development
    pub fn new_stub() -> Self {
        Self { auth_service: None }
    }

    /// Authenticate a request by validating the session
    pub async fn authenticate<T>(&self, request: &Request<T>) -> Result<ClientIdentity> {
        let metadata = request.metadata();

        let session_id = metadata
            .get("session-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::AuthenticationFailed("Missing session-id header".to_string())
            })?;

        match &self.auth_service {
            Some(auth) => {
                // Validate session with AuthService
                let identity = auth.validate_session(session_id).map_err(|e| {
                    debug!("Session validation failed: {}", e);
                    ApiError::AuthenticationFailed(format!("Invalid session: {}", e))
                })?;
                debug!("Authenticated client: {}", identity.common_name);
                Ok(identity)
            }
            None => {
                // Dev mode - return a stub identity
                warn!("Authentication is stubbed - using dev mode identity");
                Ok(ClientIdentity::new(
                    session_id.to_string(),
                    None,
                    "default".to_string(),
                    vec![hsm_auth::Role::Admin], // Dev mode has full access
                    "dev-serial".to_string(),
                ))
            }
        }
    }

    /// Authorize an operation using RBAC
    pub async fn authorize(
        &self,
        identity: &ClientIdentity,
        namespace: &str,
        permission: &Permission,
    ) -> Result<()> {
        match &self.auth_service {
            Some(auth) => {
                // Check namespace access
                auth.namespaces().require_access(identity, namespace).map_err(|e| {
                    ApiError::AuthorizationFailed(format!("Namespace access denied: {}", e))
                })?;

                // Check RBAC permission
                auth.rbac().require_any(&identity.roles, permission).map_err(|e| {
                    ApiError::AuthorizationFailed(format!("Permission denied: {}", e))
                })?;

                debug!(
                    "Authorized {} for {:?} in {}",
                    identity.common_name, permission, namespace
                );
                Ok(())
            }
            None => {
                // Dev mode - allow all
                Ok(())
            }
        }
    }

    /// Authorize key access with full ACL check
    pub async fn authorize_key_access(
        &self,
        identity: &ClientIdentity,
        key_id: &str,
        namespace: &str,
        permission: &Permission,
    ) -> Result<()> {
        match &self.auth_service {
            Some(auth) => {
                auth.authorize_key_access(identity, key_id, namespace, permission)
                    .map_err(|e| ApiError::AuthorizationFailed(format!("Key access denied: {}", e)))?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Authenticate and authorize in a single call
    pub async fn authenticate_and_authorize<T>(
        &self,
        request: &Request<T>,
        namespace: &str,
        permission: &Permission,
    ) -> Result<ClientIdentity> {
        let identity = self.authenticate(request).await?;
        self.authorize(&identity, namespace, permission).await?;
        Ok(identity)
    }

    /// Check if auth is enabled
    pub fn is_enabled(&self) -> bool {
        self.auth_service.is_some()
    }
}

impl Default for AuthInterceptor {
    fn default() -> Self {
        Self::new_stub()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_interceptor_creation() {
        let interceptor = AuthInterceptor::new_stub();
        assert!(!interceptor.is_enabled());
    }

    #[test]
    fn test_auth_interceptor_default_is_stub() {
        let interceptor = AuthInterceptor::default();
        assert!(!interceptor.is_enabled());
    }
}
