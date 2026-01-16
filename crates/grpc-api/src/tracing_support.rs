use crate::config::TracingConfig;
use std::time::SystemTime;
use tonic::{Request, Status};
use tracing::{info, Span};
use uuid::Uuid;

/// Request ID header name
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Extract or generate request ID from request
pub fn get_or_create_request_id<T>(request: &Request<T>) -> String {
    request
        .metadata()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// Add request ID to span
pub fn add_request_id_to_span(span: &Span, request_id: &str) {
    span.record("request_id", request_id);
}

/// Record request metadata in span
pub fn record_request_metadata<T>(span: &Span, method: &str, request_id: &str) {
    span.record("grpc.method", method);
    span.record("request_id", request_id);
    span.record(
        "timestamp",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
}

/// Record response status in span
pub fn record_response_status(span: &Span, status: &Status) {
    span.record("grpc.status_code", status.code() as i32);
    if !status.message().is_empty() {
        // Don't record full error message to avoid sensitive data leakage
        span.record("grpc.has_error", true);
    }
}

/// Initialize distributed tracing
pub fn init_tracing(config: &TracingConfig) -> anyhow::Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if config.enabled {
        if let Some(endpoint) = &config.otlp_endpoint {
            info!(
                "Initializing distributed tracing with OTLP endpoint: {}",
                endpoint
            );

            // Note: Full OTLP integration would require additional setup
            // For now, we just use structured logging
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        } else {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt_layer)
                .init();
        }
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    Ok(())
}

/// Tracing interceptor for gRPC requests
pub mod interceptor {
    use super::*;
    use tonic::service::Interceptor;

    #[derive(Clone)]
    pub struct TracingInterceptor;

    impl Interceptor for TracingInterceptor {
        fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
            // Get or create request ID
            let request_id = get_or_create_request_id(&request);

            // Add request ID to metadata
            request
                .metadata_mut()
                .insert(REQUEST_ID_HEADER, request_id.parse().unwrap());

            // Log request
            info!(
                request_id = %request_id,
                "gRPC request received"
            );

            Ok(request)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    #[test]
    fn test_get_or_create_request_id_existing() {
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert(REQUEST_ID_HEADER, MetadataValue::from_static("test-id-123"));

        let request_id = get_or_create_request_id(&request);
        assert_eq!(request_id, "test-id-123");
    }

    #[test]
    fn test_get_or_create_request_id_new() {
        let request = Request::new(());
        let request_id = get_or_create_request_id(&request);

        // Should be a valid UUID
        assert!(Uuid::parse_str(&request_id).is_ok());
    }

    #[test]
    fn test_tracing_config_default() {
        let config = TracingConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.service_name, "hsm-grpc-api");
        assert_eq!(config.sampling_rate, 1.0);
    }
}
