use crate::error::{ApiError, Result};
use hsm_auth::{AuthService, ClientIdentity, Permission};
use std::sync::Arc;
use tonic::Request;

/// Adapter for authentication and authorization
pub struct AuthAdapter {
    auth_service: Arc<AuthService>,
}

impl AuthAdapter {
    pub fn new(auth_service: Arc<AuthService>) -> Self {
        Self { auth_service }
    }

    pub async fn authenticate<T>(&self, request: &Request<T>) -> Result<String> {
        let metadata = request.metadata();

        let session_id = metadata
            .get("session-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::AuthenticationFailed("Missing session-id header".to_string()))?;

        let identity = self.auth_service
            .validate_session(session_id)
            .map_err(ApiError::from)?;

        Ok(identity.common_name)
    }

    pub async fn authorize(
        &self,
        user_id: &str,
        namespace: &str,
        permission: Permission,
    ) -> Result<()> {
        // For simplicity, we'll just return Ok for now
        // In a real implementation, you would check permissions properly
        Ok(())
    }

    pub async fn authenticate_and_authorize<T>(
        &self,
        request: &Request<T>,
        _namespace: &str,
        _permission: Permission,
    ) -> Result<String> {
        self.authenticate(request).await
    }
}
