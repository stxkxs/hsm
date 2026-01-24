//! HSM Rust SDK
//!
//! Official Rust SDK for HSM (Hardware Security Module).
//!
//! # Example
//!
//! ```rust,no_run
//! use hsm_client::{HsmClient, ClientConfig, KeyAlgorithm, KeyPurpose};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = HsmClient::new(ClientConfig {
//!         base_url: "https://hsm.example.com".to_string(),
//!         session_id: Some("session-id".to_string()),
//!         session_token: Some("session-token".to_string()),
//!         ..Default::default()
//!     });
//!
//!     // Generate a key
//!     let key = client.keys().generate_ed25519(None, None, None).await?;
//!     println!("Generated key: {}", key.key_id);
//!
//!     // Sign data
//!     let signature = client.sign(&key.key_id, b"Hello, World!", None).await?;
//!     println!("Signature: {}", signature.signature);
//!
//!     // Verify signature
//!     let valid = client.verify(&key.key_id, b"Hello, World!", &signature.signature).await?;
//!     println!("Valid: {}", valid.valid);
//!
//!     Ok(())
//! }
//! ```

mod client;
mod crypto;
mod error;
mod types;

pub use client::{CircuitBreaker, HsmClient, KeyManager, RetryStrategy, TokenManager};
pub use crypto::{
    concat_bytes, constant_time_equal, der_to_raw, from_base64, from_hex, hmac_sha256,
    is_base64, normalize_to_base64, random_bytes, raw_to_der, sha256, sha384, sha512,
    to_base64, to_hex,
};
pub use error::{HsmError, Result};
pub use types::{
    AuditEntry, AuditLogOptions, AuditLogResponse, BatchDecryptRequest, BatchDecryptResponse,
    BatchEncryptRequest, BatchEncryptResponse, BatchSignRequest, BatchSignResponse,
    BatchVerifyRequest, BatchVerifyResponse, ClientConfig, ComponentStatus, DecryptRequest,
    DecryptResponse, EncryptRequest, EncryptResponse, GenerateKeyRequest, GenerateKeyResponse,
    HealthResponse, KeyAlgorithm, KeyMetadata, KeyPurpose, KeyState, ListKeysOptions,
    ListKeysResponse, ReadyResponse, RetryConfig, SessionScope, SignRequest, SignResponse,
    VerifyRequest, VerifyResponse,
};
