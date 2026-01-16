use crate::error::{ApiError, Result};
use tonic::Request;
use tracing::warn;

/// Simple authentication stub
/// TODO: Integrate with actual AuthService once API is stable
pub struct AuthInterceptor;

impl AuthInterceptor {
    pub fn new() -> Self {
        Self
    }

    pub async fn authenticate<T>(&self, request: &Request<T>) -> Result<String> {
        let metadata = request.metadata();

        let session_id = metadata
            .get("session-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::AuthenticationFailed("Missing session-id header".to_string())
            })?;

        // TODO: Validate session with AuthService
        warn!("Authentication is stubbed - session validation not implemented");

        Ok(session_id.to_string())
    }

    pub async fn authorize(&self, _user_id: &str, _namespace: &str) -> Result<()> {
        // TODO: Check permissions with RBAC
        Ok(())
    }

    pub async fn authenticate_and_authorize<T>(
        &self,
        request: &Request<T>,
        namespace: &str,
    ) -> Result<String> {
        let user_id = self.authenticate(request).await?;
        self.authorize(&user_id, namespace).await?;
        Ok(user_id)
    }
}

impl Default for AuthInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_interceptor_creation() {
        let _interceptor = AuthInterceptor::new();
    }
}
