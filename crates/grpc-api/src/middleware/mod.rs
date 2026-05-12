//! Middleware components for request processing.
//!
//! This module provides middleware for the gRPC API server, handling cross-cutting
//! concerns like authentication, logging, and metrics collection.
//!
//! # Middleware Chain
//!
//! Middleware components are applied in the following order:
//!
//! 1. **Logging** ([`logging`]): Structured request/response logging
//! 2. **Metrics** ([`metrics`]): Operation counters and latency tracking
//! 3. **Authentication** ([`auth`]): Session validation and authorization
//!
//! # Architecture
//!
//! Each middleware is designed to be:
//! - **Composable**: Can be enabled/disabled independently
//! - **Zero-cost**: Minimal overhead when not in use
//! - **Thread-safe**: Uses atomic operations for lock-free performance
//!
//! # Examples
//!
//! Using the request logger:
//!
//! ```
//! use hsm_grpc_api::middleware::logging::RequestLogger;
//!
//! let logger = RequestLogger::new();
//!
//! // In your gRPC handler:
//! // let start = logger.log_request(&request, "SignRequest");
//! // ... process request ...
//! // logger.log_response("SignRequest", &result, start);
//! ```
//!
//! Using the metrics collector:
//!
//! ```
//! use hsm_grpc_api::middleware::metrics::MetricsCollector;
//!
//! let metrics = MetricsCollector::new();
//!
//! // Record a request
//! let timer = metrics.record_request();
//! // ... process request ...
//! timer.finish_success(); // or finish_error(code)
//! ```
//!
//! Using the auth interceptor:
//!
//! ```
//! use hsm_grpc_api::middleware::auth::AuthInterceptor;
//!
//! // Create a stub interceptor for development/testing
//! let auth = AuthInterceptor::new_stub();
//!
//! // In production, use with AuthService:
//! // let auth = AuthInterceptor::new(Some(auth_service));
//! ```

pub mod auth;
pub mod logging;
pub mod metrics;
