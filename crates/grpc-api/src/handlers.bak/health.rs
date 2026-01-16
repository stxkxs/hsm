use crate::proto::hsm::{HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus};
use std::collections::HashMap;
use tonic::{Request, Response, Status};
use tracing::info;

pub struct HealthHandler;

impl HealthHandler {
    pub fn new() -> Self {
        Self
    }

    pub async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let req = request.into_inner();

        info!(service = %req.service, "Health check request");

        let mut details = HashMap::new();
        details.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
        details.insert("service".to_string(), "hsm-grpc-api".to_string());

        let response = HealthCheckResponse {
            status: ServingStatus::Serving as i32,
            message: "Service is healthy".to_string(),
            details,
        };

        Ok(Response::new(response))
    }
}

impl Default for HealthHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let handler = HealthHandler::new();
        let request = Request::new(HealthCheckRequest {
            service: "hsm".to_string(),
        });

        let response = handler.health_check(request).await.unwrap();
        let inner = response.into_inner();

        assert_eq!(inner.status, ServingStatus::Serving as i32);
        assert_eq!(inner.message, "Service is healthy");
        assert!(inner.details.contains_key("version"));
    }
}
