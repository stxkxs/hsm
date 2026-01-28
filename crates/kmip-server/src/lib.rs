//! # KMIP (Key Management Interoperability Protocol) Server
//!
//! This crate provides a KMIP 1.4+ server implementation for enterprise key management
//! integration, enabling interoperability with enterprise KMS clients and applications.
//!
//! ## Features
//!
//! - **KMIP 1.4 Protocol**: Industry-standard key management protocol
//! - **TTLV Encoding**: Tag-Type-Length-Value binary codec
//! - **Core Operations**: Create, Get, Activate, Revoke, Destroy, Locate
//! - **Crypto Operations**: Encrypt, Decrypt, Sign, Verify, MAC
//! - **mTLS Transport**: Mutual TLS authentication on port 5696
//! - **Batch Operations**: Multiple operations in single request
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    KMIP Server Architecture                          │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌──────────────────────────────────────────────┐                   │
//! │  │          Enterprise KMIP Clients              │                   │
//! │  │  IBM Security Guardium │ Thales │ Vormetric  │                   │
//! │  │  HashiCorp Vault │ Custom Applications       │                   │
//! │  └──────────────────────────────────────────────┘                   │
//! │                         │                                            │
//! │                         │ KMIP/TLS (port 5696)                       │
//! │                         │ TTLV Binary Encoding                       │
//! │                         ▼                                            │
//! │  ┌──────────────────────────────────────────────┐                   │
//! │  │            KMIP Server (this crate)           │                   │
//! │  │                                                │                   │
//! │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐ │                   │
//! │  │  │   TTLV    │  │ Operation │  │   HSM     │ │                   │
//! │  │  │  Decoder  │─▶│  Handler  │─▶│  Client   │ │                   │
//! │  │  └───────────┘  └───────────┘  └───────────┘ │                   │
//! │  │                                                │                   │
//! │  └──────────────────────────────────────────────┘                   │
//! │                         │                                            │
//! │                         │ Internal API                               │
//! │                         ▼                                            │
//! │  ┌──────────────────────────────────────────────┐                   │
//! │  │                HSM Core                       │                   │
//! │  └──────────────────────────────────────────────┘                   │
//! │                                                                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Supported Operations
//!
//! | Operation | Description | State Transitions |
//! |-----------|-------------|-------------------|
//! | Create | Generate a new key | → Pre-Active |
//! | Register | Import existing key | → Pre-Active |
//! | Get | Retrieve key material | (no change) |
//! | GetAttributes | Get key metadata | (no change) |
//! | Locate | Search for keys | (no change) |
//! | Activate | Enable key for use | Pre-Active → Active |
//! | Revoke | Mark as compromised | Active → Compromised |
//! | Destroy | Delete key | Any → Destroyed |
//! | Encrypt | Encrypt data | (requires Active key) |
//! | Decrypt | Decrypt data | (requires Active key) |
//! | Sign | Sign data | (requires Active key) |
//! | Verify | Verify signature | (requires Active key) |
//! | Query | Server capabilities | (no auth required) |
//!
//! ## Quick Start
//!
//! ### Server Setup
//!
//! ```rust,ignore
//! use hsm_kmip::{KmipServer, KmipServerConfig, HsmClient};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create HSM client (connects to HSM core)
//!     let hsm_client = create_hsm_client().await?;
//!
//!     // Load TLS certificates for mTLS
//!     let tls_config = load_tls_config(
//!         "server.crt",
//!         "server.key",
//!         "ca.crt",
//!     )?;
//!
//!     // Configure and start the KMIP server
//!     let config = KmipServerConfig {
//!         bind_address: "0.0.0.0:5696".to_string(),
//!         tls_config: Arc::new(tls_config),
//!         hsm_client,
//!     };
//!
//!     let server = KmipServer::new(config);
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## KMIP Client Examples
//!
//! ### Create a Symmetric Key
//!
//! ```text
//! Request (TTLV):
//! ├── RequestHeader
//! │   ├── ProtocolVersion: 1.4
//! │   └── BatchCount: 1
//! └── BatchItem
//!     ├── Operation: Create
//!     └── RequestPayload
//!         ├── ObjectType: SymmetricKey
//!         └── TemplateAttribute
//!             ├── CryptographicAlgorithm: AES
//!             ├── CryptographicLength: 256
//!             └── Name: "my-aes-key"
//!
//! Response:
//! └── BatchItem
//!     ├── ResultStatus: Success
//!     └── ResponsePayload
//!         └── UniqueIdentifier: "key-uuid-here"
//! ```
//!
//! ### Get Key Material
//!
//! ```text
//! Request:
//! └── BatchItem
//!     ├── Operation: Get
//!     └── RequestPayload
//!         └── UniqueIdentifier: "key-uuid-here"
//!
//! Response:
//! └── BatchItem
//!     ├── ResultStatus: Success
//!     └── ResponsePayload
//!         ├── ObjectType: SymmetricKey
//!         └── SymmetricKey
//!             └── KeyBlock
//!                 ├── KeyFormatType: Raw
//!                 └── KeyValue: [key bytes]
//! ```
//!
//! ### Encrypt Data
//!
//! ```text
//! Request:
//! └── BatchItem
//!     ├── Operation: Encrypt
//!     └── RequestPayload
//!         ├── UniqueIdentifier: "key-uuid-here"
//!         ├── Data: [plaintext bytes]
//!         └── CryptographicParameters
//!             ├── BlockCipherMode: GCM
//!             └── RandomIV: true
//!
//! Response:
//! └── BatchItem
//!     └── ResponsePayload
//!         ├── Data: [ciphertext bytes]
//!         └── IVCounterNonce: [IV bytes]
//! ```
//!
//! ## TTLV Encoding
//!
//! KMIP uses Tag-Type-Length-Value encoding:
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┬──────────────┐
//! │    Tag       │    Type      │    Length    │    Value     │
//! │  (3 bytes)   │  (1 byte)    │  (4 bytes)   │  (variable)  │
//! └──────────────┴──────────────┴──────────────┴──────────────┘
//!
//! Types:
//!   0x01 = Structure (nested TTLV)
//!   0x02 = Integer
//!   0x03 = LongInteger
//!   0x04 = BigInteger
//!   0x05 = Enumeration
//!   0x06 = Boolean
//!   0x07 = TextString
//!   0x08 = ByteString
//!   0x09 = DateTime
//! ```
//!
//! ## Integration with Enterprise KMS
//!
//! ### HashiCorp Vault
//!
//! ```hcl
//! # Vault KMIP secrets engine configuration
//! vault secrets enable kmip
//! vault write kmip/config listen_addrs="0.0.0.0:5696"
//!
//! # Create a scope and role
//! vault write kmip/scope/prod/role/app operation_all=true
//! ```
//!
//! ### PyKMIP Client
//!
//! ```python
//! from kmip.pie.client import ProxyKmipClient
//!
//! client = ProxyKmipClient(
//!     hostname='hsm.example.com',
//!     port=5696,
//!     cert='/path/to/client.crt',
//!     key='/path/to/client.key',
//!     ca='/path/to/ca.crt',
//! )
//!
//! with client:
//!     # Create a key
//!     key_id = client.create(
//!         enums.CryptographicAlgorithm.AES,
//!         256,
//!         name='my-aes-key'
//!     )
//!
//!     # Activate the key
//!     client.activate(key_id)
//!
//!     # Encrypt data
//!     ciphertext, iv = client.encrypt(
//!         b'Hello, World!',
//!         uid=key_id,
//!         cryptographic_parameters={
//!             'block_cipher_mode': enums.BlockCipherMode.GCM
//!         }
//!     )
//! ```
//!
//! ## Security Considerations
//!
//! - **mTLS Required**: All connections must use mutual TLS authentication
//! - **Certificate Validation**: Server validates client certificates against CA
//! - **Key State Enforcement**: Operations only allowed on keys in appropriate states
//! - **Audit Logging**: All operations are logged for compliance

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
