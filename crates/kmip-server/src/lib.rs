//! KMIP (Key Management Interoperability Protocol) Server
//!
//! This crate provides a KMIP 1.4+ server implementation for enterprise key management
//! integration. It implements the TTLV binary encoding format and core KMIP operations.
//!
//! # Features
//!
//! - TTLV (Tag-Type-Length-Value) binary codec
//! - Core operations: Create, Get, Activate, Revoke, Destroy
//! - Cryptographic operations: Encrypt, Decrypt, Sign
//! - TLS transport with mutual authentication
//! - Batch operations support
//!
//! # Example
//!
//! ```rust,ignore
//! use hsm_kmip::{KmipServer, KmipServerConfig, HsmClient};
//! use std::sync::Arc;
//!
//! // Create HSM client implementation
//! let hsm_client: Arc<dyn HsmClient> = todo!();
//!
//! // Create TLS configuration
//! let tls_config: Arc<rustls::ServerConfig> = todo!();
//!
//! // Create and run server
//! let config = KmipServerConfig {
//!     bind_address: "0.0.0.0:5696".to_string(),
//!     tls_config,
//!     hsm_client,
//! };
//!
//! let server = KmipServer::new(config);
//! // server.run().await?;
//! ```
//!
//! # KMIP Protocol
//!
//! KMIP uses a binary TTLV encoding over TLS. The standard port is 5696.
//! This implementation supports KMIP 1.4 protocol version.
//!
//! ## Supported Operations
//!
//! - **Create**: Generate a new cryptographic key
//! - **Get**: Retrieve key material and attributes
//! - **Activate**: Transition key from Pre-Active to Active state
//! - **Revoke**: Mark key as compromised or revoked
//! - **Destroy**: Permanently delete a key
//! - **Encrypt**: Encrypt data using a symmetric key
//! - **Decrypt**: Decrypt data using a symmetric key
//! - **Sign**: Sign data using a private key
//! - **Query**: Query server capabilities

pub mod operations;
pub mod protocol;
pub mod server;
pub mod ttlv;

// Re-export main types
pub use protocol::enums::*;
pub use server::{
    Attribute, AttributeValue, CryptoParams, EncryptResult, HsmClient, KeyInfo, KmipError,
    KmipServer, KmipServerConfig, RevocationReason, ServerInfo,
};
pub use ttlv::{Tag, Ttlv, TtlvDecoder, TtlvEncoder, TtlvError, TtlvType, TtlvValue};

/// KMIP protocol version supported by this implementation
pub const KMIP_VERSION_MAJOR: i32 = 1;
pub const KMIP_VERSION_MINOR: i32 = 4;

/// Default KMIP port
pub const KMIP_DEFAULT_PORT: u16 = 5696;
