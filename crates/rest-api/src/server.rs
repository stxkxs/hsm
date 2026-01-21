//! REST API Server
//!
//! Main server implementation for the REST API.

use crate::config::RestApiConfig;
use crate::middleware::AppState;
use crate::routes::{create_router, create_router_with_cors};
use hsm_auth::SessionManager;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

/// REST API Server
pub struct RestApiServer {
    config: RestApiConfig,
    sessions: Arc<SessionManager>,
}

impl RestApiServer {
    /// Create a new REST API server
    pub fn new(config: RestApiConfig) -> Self {
        let sessions = Arc::new(SessionManager::new(3600)); // 1 hour default TTL
        Self { config, sessions }
    }

    /// Create a new REST API server with a shared session manager
    pub fn with_session_manager(config: RestApiConfig, sessions: Arc<SessionManager>) -> Self {
        Self { config, sessions }
    }

    /// Get the session manager (for testing or session creation)
    pub fn sessions(&self) -> Arc<SessionManager> {
        self.sessions.clone()
    }

    /// Start the server
    pub async fn serve(self) -> anyhow::Result<()> {
        // Validate configuration
        self.config
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid configuration: {}", e))?;

        let state = AppState::new(self.sessions.clone());

        // Create router based on CORS configuration
        let router = if self.config.cors.allowed_origins.is_empty() {
            create_router(state)
        } else {
            create_router_with_cors(state, self.config.cors.allowed_origins.clone())
        };

        // Bind to address
        let listener = TcpListener::bind(&self.config.bind_addr).await?;

        info!(
            address = %self.config.bind_addr,
            "REST API server starting"
        );

        // Serve requests
        axum::serve(listener, router).await?;

        Ok(())
    }

    /// Start the server with graceful shutdown
    pub async fn serve_with_shutdown(
        self,
        shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> anyhow::Result<()> {
        // Validate configuration
        self.config
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid configuration: {}", e))?;

        let state = AppState::new(self.sessions.clone());

        // Create router
        let router = if self.config.cors.allowed_origins.is_empty() {
            create_router(state)
        } else {
            create_router_with_cors(state, self.config.cors.allowed_origins.clone())
        };

        // Bind to address
        let listener = TcpListener::bind(&self.config.bind_addr).await?;

        info!(
            address = %self.config.bind_addr,
            "REST API server starting"
        );

        // Serve requests with graceful shutdown
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal)
            .await?;

        info!("REST API server stopped");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = RestApiConfig::default();
        let server = RestApiServer::new(config);
        assert_eq!(server.sessions.active_session_count(), 0);
    }

    #[test]
    fn test_server_with_session_manager() {
        let config = RestApiConfig::default();
        let sessions = Arc::new(SessionManager::new(7200));
        let server = RestApiServer::with_session_manager(config, sessions.clone());

        // Should share the same session manager
        assert!(Arc::ptr_eq(&server.sessions, &sessions));
    }
}
