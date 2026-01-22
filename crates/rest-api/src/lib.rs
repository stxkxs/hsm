//! REST/JSON API Gateway for HSM
//!
//! This module provides a REST API wrapper around the HSM's gRPC API,
//! enabling easier integration for web clients and applications that
//! prefer JSON over Protocol Buffers.
//!
//! # Endpoints
//!
//! ## Key Management
//! - `POST /keys` - Generate a new key
//! - `GET /keys/:id` - Get key metadata
//! - `DELETE /keys/:id` - Delete a key
//! - `GET /keys` - List keys (with pagination)
//!
//! ## Cryptographic Operations
//! - `POST /keys/:id/sign` - Sign data
//! - `POST /keys/:id/verify` - Verify signature
//! - `POST /keys/:id/encrypt` - Encrypt data
//! - `POST /keys/:id/decrypt` - Decrypt data
//!
//! ## Audit
//! - `GET /audit` - Get audit log
//!
//! ## Health
//! - `GET /health` - Health check
//! - `GET /ready` - Readiness check
//!
//! # Authentication
//!
//! All endpoints (except health checks) require authentication via:
//! - `Authorization: Bearer <token>` header with session token
//! - Or mutual TLS client certificate
//!
//! # Example
//!
//! ```rust,no_run
//! use hsm_rest_api::{RestApiServer, RestApiConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = RestApiConfig::default();
//!     let server = RestApiServer::new(config);
//!     server.serve().await.unwrap();
//! }
//! ```

pub mod config;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod routes;
pub mod server;
pub mod types;

pub use config::RestApiConfig;
pub use error::{ApiError, Result};
pub use routes::{create_router, create_router_with_cors};
pub use server::RestApiServer;
