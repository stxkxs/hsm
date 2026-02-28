//! # REST/JSON API Gateway for HSM
//!
//! This module provides a REST API wrapper around the HSM's gRPC API,
//! enabling easier integration for web clients and applications that
//! prefer JSON over Protocol Buffers.
//!
//! ## Features
//!
//! - Full key lifecycle management (create, read, delete, rotate)
//! - Cryptographic operations (sign, verify, encrypt, decrypt)
//! - Bearer token and mTLS authentication
//! - Pagination for key listing
//! - CORS support for browser clients
//! - Audit log access
//! - Health and readiness endpoints
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     REST API Architecture                            │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐         │
//! │  │   Client     │────▶│  REST API    │────▶│   gRPC API   │         │
//! │  │  (Browser,   │     │  (this crate)│     │   (HSM Core) │         │
//! │  │   cURL, etc) │◀────│              │◀────│              │         │
//! │  └──────────────┘     └──────────────┘     └──────────────┘         │
//! │        │                     │                                       │
//! │        │ JSON/HTTP           │ Axum handlers                         │
//! │        │                     │ + middleware                          │
//! │        │                     │                                       │
//! │  ┌─────────────────────────────────────────────────────────────┐    │
//! │  │                     Middleware Stack                         │    │
//! │  ├──────────────┬──────────────┬──────────────┬────────────────┤    │
//! │  │    Auth      │    CORS      │   Logging    │  Rate Limit    │    │
//! │  └──────────────┴──────────────┴──────────────┴────────────────┘    │
//! │                                                                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Endpoint Reference
//!
//! | Method | Path              | Description                    | Auth Required |
//! |--------|-------------------|--------------------------------|---------------|
//! | POST   | `/keys`           | Generate a new key             | Yes           |
//! | GET    | `/keys`           | List keys (paginated)          | Yes           |
//! | GET    | `/keys/:id`       | Get key metadata               | Yes           |
//! | DELETE | `/keys/:id`       | Delete a key                   | Yes (Admin)   |
//! | POST   | `/keys/:id/sign`  | Sign data with key             | Yes           |
//! | POST   | `/keys/:id/verify`| Verify signature               | Yes           |
//! | POST   | `/keys/:id/encrypt`| Encrypt data                  | Yes           |
//! | POST   | `/keys/:id/decrypt`| Decrypt data                  | Yes           |
//! | GET    | `/audit`          | Get audit log entries          | Yes (Auditor) |
//! | GET    | `/health`         | Health check                   | No            |
//! | GET    | `/ready`          | Readiness check                | No            |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use hsm_rest_api::{RestApiServer, RestApiConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create server with default configuration
//!     let config = RestApiConfig::default();
//!     let server = RestApiServer::new(config);
//!
//!     // Start serving on configured address
//!     server.serve().await.unwrap();
//! }
//! ```
//!
//! ## Authentication
//!
//! All endpoints (except `/health` and `/ready`) require authentication.
//! Two methods are supported:
//!
//! ### Bearer Token Authentication
//!
//! Include the session token in the `Authorization` header:
//!
//! ```text
//! POST /keys HTTP/1.1
//! Host: hsm.example.com
//! Authorization: Bearer <session-token>
//! Content-Type: application/json
//!
//! {"algorithm": "Ed25519", "namespace": "default"}
//! ```
//!
//! ### mTLS Client Certificate
//!
//! Present a valid client certificate during the TLS handshake. The server
//! extracts identity from the certificate's Common Name (CN) field.
//!
//! ## Request/Response Examples
//!
//! ### Generate a Key
//!
//! ```text
//! POST /keys
//! Content-Type: application/json
//!
//! {
//!   "algorithm": "Ed25519",
//!   "namespace": "production",
//!   "label": "signing-key-001"
//! }
//!
//! Response 201 Created:
//! {
//!   "id": "key_abc123",
//!   "algorithm": "Ed25519",
//!   "namespace": "production",
//!   "created_at": "2024-01-15T10:30:00Z",
//!   "status": "active"
//! }
//! ```
//!
//! ### Sign Data
//!
//! ```text
//! POST /keys/key_abc123/sign
//! Content-Type: application/json
//!
//! {
//!   "data": "SGVsbG8gV29ybGQ=",  // base64-encoded message
//!   "encoding": "base64"
//! }
//!
//! Response 200 OK:
//! {
//!   "signature": "MEUCIQD2...",   // base64-encoded signature
//!   "key_id": "key_abc123",
//!   "algorithm": "Ed25519"
//! }
//! ```
//!
//! ### List Keys with Pagination
//!
//! ```text
//! GET /keys?namespace=production&limit=10&offset=0
//!
//! Response 200 OK:
//! {
//!   "keys": [
//!     {"id": "key_abc123", "algorithm": "Ed25519", ...},
//!     {"id": "key_def456", "algorithm": "ECDSA-P256", ...}
//!   ],
//!   "total": 42,
//!   "limit": 10,
//!   "offset": 0
//! }
//! ```
//!
//! ## Error Handling
//!
//! Errors are returned as JSON with HTTP status codes:
//!
//! ```text
//! HTTP/1.1 401 Unauthorized
//! Content-Type: application/json
//!
//! {
//!   "error": "unauthorized",
//!   "message": "Invalid or expired session token",
//!   "code": "AUTH_TOKEN_INVALID"
//! }
//! ```
//!
//! | Status Code | Description                        |
//! |-------------|------------------------------------|
//! | 400         | Bad request (invalid JSON/params)  |
//! | 401         | Authentication required            |
//! | 403         | Permission denied (insufficient RBAC role) |
//! | 404         | Key or resource not found          |
//! | 429         | Rate limit exceeded                |
//! | 500         | Internal server error              |
//!
//! ## CORS Configuration
//!
//! Enable CORS for browser clients:
//!
//! ```rust,ignore
//! use hsm_rest_api::{create_router_with_cors, RestApiConfig};
//!
//! # async fn example() {
//! let config = RestApiConfig::default();
//! let state = AppState::new(config);
//! let origins = vec!["https://example.com".to_string()];
//! let router = create_router_with_cors(state, origins);
//! // Router now accepts cross-origin requests
//! # }
//! ```
//!
//! ## Security Considerations
//!
//! - Always use HTTPS in production (TLS 1.2+ required)
//! - Rotate session tokens regularly
//! - Use short TTLs for sensitive operations
//! - Enable rate limiting to prevent abuse
//! - Audit logs capture all API calls for forensic analysis

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
