# Plan 3.5: KMIP Protocol Support

## Overview

Implement KMIP (Key Management Interoperability Protocol) server support, allowing enterprise applications and tools that speak KMIP to interact with the HSM. KMIP is an OASIS standard widely used in enterprise key management.

## Goals

- KMIP 1.4+ protocol support
- Core operations: Create, Get, Activate, Revoke, Destroy
- Cryptographic operations: Encrypt, Decrypt, Sign, MAC
- TLS transport with mutual authentication
- Attribute management and querying
- Batch operations support

## KMIP Background

KMIP uses a binary TTLV (Tag-Type-Length-Value) encoding over TLS. Key operations include:

```
Create → Generate a new key
Register → Import an existing key
Get → Retrieve key material (if extractable)
GetAttributes → Get key metadata
Activate → Make key usable
Revoke → Revoke key (with reason)
Destroy → Delete key
Encrypt/Decrypt → Symmetric crypto operations
Sign/MAC → Asymmetric/MAC operations
```

## Dependencies

Create new crate `crates/kmip-server/Cargo.toml`:

```toml
[package]
name = "hsm-kmip"
version.workspace = true
edition.workspace = true

[dependencies]
# HSM integration
hsm-key-manager = { path = "../key-manager" }
hsm-crypto-engine = { path = "../crypto-engine" }
hsm-auth = { path = "../auth" }
hsm-audit = { path = "../audit" }

# Async runtime
tokio = { workspace = true, features = ["net", "io-util", "rt-multi-thread", "sync"] }

# TLS
tokio-rustls = { workspace = true }
rustls = { workspace = true }
rustls-pki-types = { workspace = true }

# Serialization (TTLV is custom, but need helpers)
bytes = "1.5"
byteorder = "1.5"

# Time
chrono = { workspace = true }

# Error handling
thiserror = { workspace = true }

# Logging
tracing = { workspace = true }

# Utilities
uuid = { version = "1.7", features = ["v4"] }
bitflags = "2.4"
```

## File Structure

```
crates/kmip-server/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API
│   ├── server.rs           # KMIP TLS server
│   ├── ttlv/
│   │   ├── mod.rs          # TTLV codec
│   │   ├── encoder.rs      # TTLV encoding
│   │   ├── decoder.rs      # TTLV decoding
│   │   └── types.rs        # TTLV primitive types
│   ├── protocol/
│   │   ├── mod.rs          # Protocol handling
│   │   ├── request.rs      # Request structures
│   │   ├── response.rs     # Response structures
│   │   ├── enums.rs        # KMIP enumerations
│   │   └── attributes.rs   # Attribute types
│   ├── operations/
│   │   ├── mod.rs          # Operation dispatcher
│   │   ├── create.rs       # Create operation
│   │   ├── get.rs          # Get operation
│   │   ├── activate.rs     # Activate operation
│   │   ├── revoke.rs       # Revoke operation
│   │   ├── destroy.rs      # Destroy operation
│   │   ├── encrypt.rs      # Encrypt operation
│   │   ├── decrypt.rs      # Decrypt operation
│   │   ├── sign.rs         # Sign operation
│   │   └── query.rs        # Query server capabilities
│   ├── state.rs            # Server state
│   └── error.rs            # Error types
└── tests/
    └── integration.rs
```

## Implementation Steps

### Step 1: Define TTLV Types

Create `crates/kmip-server/src/ttlv/types.rs`:

```rust
//! KMIP TTLV (Tag-Type-Length-Value) primitive types

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{self, Read, Write};

/// TTLV Tag (3 bytes, but stored as u32)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub u32);

impl Tag {
    // Common tags
    pub const REQUEST_MESSAGE: Tag = Tag(0x420078);
    pub const RESPONSE_MESSAGE: Tag = Tag(0x42007B);
    pub const REQUEST_HEADER: Tag = Tag(0x420077);
    pub const RESPONSE_HEADER: Tag = Tag(0x42007A);
    pub const REQUEST_BATCH_ITEM: Tag = Tag(0x42000F);
    pub const RESPONSE_BATCH_ITEM: Tag = Tag(0x42000F);
    pub const OPERATION: Tag = Tag(0x42005C);
    pub const RESULT_STATUS: Tag = Tag(0x42007F);
    pub const RESULT_REASON: Tag = Tag(0x42007E);
    pub const RESULT_MESSAGE: Tag = Tag(0x42007D);
    pub const UNIQUE_ID: Tag = Tag(0x420094);
    pub const OBJECT_TYPE: Tag = Tag(0x420057);
    pub const TEMPLATE_ATTRIBUTE: Tag = Tag(0x420091);
    pub const ATTRIBUTE: Tag = Tag(0x420008);
    pub const ATTRIBUTE_NAME: Tag = Tag(0x42000A);
    pub const ATTRIBUTE_VALUE: Tag = Tag(0x42000B);
    pub const CRYPTOGRAPHIC_ALGORITHM: Tag = Tag(0x420028);
    pub const CRYPTOGRAPHIC_LENGTH: Tag = Tag(0x42002A);
    pub const KEY_BLOCK: Tag = Tag(0x420040);
    pub const KEY_VALUE: Tag = Tag(0x420045);
    pub const KEY_MATERIAL: Tag = Tag(0x420043);
    pub const DATA: Tag = Tag(0x4200C2);
    pub const IV_COUNTER_NONCE: Tag = Tag(0x42003D);
    pub const PROTOCOL_VERSION: Tag = Tag(0x420069);
    pub const PROTOCOL_VERSION_MAJOR: Tag = Tag(0x42006A);
    pub const PROTOCOL_VERSION_MINOR: Tag = Tag(0x42006B);
    pub const BATCH_COUNT: Tag = Tag(0x42000D);
    pub const TIMESTAMP: Tag = Tag(0x420092);
}

/// TTLV Type (1 byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TtlvType {
    Structure = 0x01,
    Integer = 0x02,
    LongInteger = 0x03,
    BigInteger = 0x04,
    Enumeration = 0x05,
    Boolean = 0x06,
    TextString = 0x07,
    ByteString = 0x08,
    DateTime = 0x09,
    Interval = 0x0A,
}

impl TryFrom<u8> for TtlvType {
    type Error = TtlvError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(TtlvType::Structure),
            0x02 => Ok(TtlvType::Integer),
            0x03 => Ok(TtlvType::LongInteger),
            0x04 => Ok(TtlvType::BigInteger),
            0x05 => Ok(TtlvType::Enumeration),
            0x06 => Ok(TtlvType::Boolean),
            0x07 => Ok(TtlvType::TextString),
            0x08 => Ok(TtlvType::ByteString),
            0x09 => Ok(TtlvType::DateTime),
            0x0A => Ok(TtlvType::Interval),
            _ => Err(TtlvError::InvalidType(value)),
        }
    }
}

/// TTLV Value
#[derive(Debug, Clone, PartialEq)]
pub enum TtlvValue {
    Structure(Vec<Ttlv>),
    Integer(i32),
    LongInteger(i64),
    BigInteger(Vec<u8>),
    Enumeration(u32),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(i64),  // Unix timestamp
    Interval(u32),
}

/// Complete TTLV item
#[derive(Debug, Clone, PartialEq)]
pub struct Ttlv {
    pub tag: Tag,
    pub value: TtlvValue,
}

impl Ttlv {
    pub fn new(tag: Tag, value: TtlvValue) -> Self {
        Self { tag, value }
    }

    pub fn structure(tag: Tag, items: Vec<Ttlv>) -> Self {
        Self {
            tag,
            value: TtlvValue::Structure(items),
        }
    }

    pub fn integer(tag: Tag, value: i32) -> Self {
        Self {
            tag,
            value: TtlvValue::Integer(value),
        }
    }

    pub fn enumeration(tag: Tag, value: u32) -> Self {
        Self {
            tag,
            value: TtlvValue::Enumeration(value),
        }
    }

    pub fn text_string(tag: Tag, value: impl Into<String>) -> Self {
        Self {
            tag,
            value: TtlvValue::TextString(value.into()),
        }
    }

    pub fn byte_string(tag: Tag, value: Vec<u8>) -> Self {
        Self {
            tag,
            value: TtlvValue::ByteString(value),
        }
    }

    /// Get child item by tag
    pub fn get(&self, tag: Tag) -> Option<&Ttlv> {
        if let TtlvValue::Structure(items) = &self.value {
            items.iter().find(|item| item.tag == tag)
        } else {
            None
        }
    }

    /// Get all children with matching tag
    pub fn get_all(&self, tag: Tag) -> Vec<&Ttlv> {
        if let TtlvValue::Structure(items) = &self.value {
            items.iter().filter(|item| item.tag == tag).collect()
        } else {
            vec![]
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TtlvError {
    #[error("Invalid TTLV type: {0}")]
    InvalidType(u8),

    #[error("Unexpected end of data")]
    UnexpectedEof,

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}
```

### Step 2: Implement TTLV Encoder

Create `crates/kmip-server/src/ttlv/encoder.rs`:

```rust
use super::types::*;
use bytes::{BufMut, BytesMut};

pub struct TtlvEncoder;

impl TtlvEncoder {
    /// Encode a TTLV item to bytes
    pub fn encode(item: &Ttlv) -> Vec<u8> {
        let mut buf = BytesMut::new();
        Self::encode_item(&mut buf, item);
        buf.to_vec()
    }

    fn encode_item(buf: &mut BytesMut, item: &Ttlv) {
        // Tag (3 bytes)
        buf.put_u8((item.tag.0 >> 16) as u8);
        buf.put_u8((item.tag.0 >> 8) as u8);
        buf.put_u8(item.tag.0 as u8);

        // Type (1 byte) and value
        match &item.value {
            TtlvValue::Structure(items) => {
                buf.put_u8(TtlvType::Structure as u8);

                // Encode children to temporary buffer to get length
                let mut child_buf = BytesMut::new();
                for child in items {
                    Self::encode_item(&mut child_buf, child);
                }

                // Length (4 bytes)
                buf.put_u32(child_buf.len() as u32);

                // Value (children)
                buf.extend_from_slice(&child_buf);
            }

            TtlvValue::Integer(v) => {
                buf.put_u8(TtlvType::Integer as u8);
                buf.put_u32(4);  // Length
                buf.put_i32(*v);
                buf.put_u32(0);  // Padding to 8 bytes
            }

            TtlvValue::LongInteger(v) => {
                buf.put_u8(TtlvType::LongInteger as u8);
                buf.put_u32(8);  // Length
                buf.put_i64(*v);
            }

            TtlvValue::BigInteger(v) => {
                buf.put_u8(TtlvType::BigInteger as u8);
                buf.put_u32(v.len() as u32);
                buf.extend_from_slice(v);
                Self::pad_to_8(buf, v.len());
            }

            TtlvValue::Enumeration(v) => {
                buf.put_u8(TtlvType::Enumeration as u8);
                buf.put_u32(4);  // Length
                buf.put_u32(*v);
                buf.put_u32(0);  // Padding
            }

            TtlvValue::Boolean(v) => {
                buf.put_u8(TtlvType::Boolean as u8);
                buf.put_u32(8);  // Length
                buf.put_u64(if *v { 1 } else { 0 });
            }

            TtlvValue::TextString(v) => {
                buf.put_u8(TtlvType::TextString as u8);
                let bytes = v.as_bytes();
                buf.put_u32(bytes.len() as u32);
                buf.extend_from_slice(bytes);
                Self::pad_to_8(buf, bytes.len());
            }

            TtlvValue::ByteString(v) => {
                buf.put_u8(TtlvType::ByteString as u8);
                buf.put_u32(v.len() as u32);
                buf.extend_from_slice(v);
                Self::pad_to_8(buf, v.len());
            }

            TtlvValue::DateTime(v) => {
                buf.put_u8(TtlvType::DateTime as u8);
                buf.put_u32(8);
                buf.put_i64(*v);
            }

            TtlvValue::Interval(v) => {
                buf.put_u8(TtlvType::Interval as u8);
                buf.put_u32(4);
                buf.put_u32(*v);
                buf.put_u32(0);  // Padding
            }
        }
    }

    fn pad_to_8(buf: &mut BytesMut, len: usize) {
        let padding = (8 - (len % 8)) % 8;
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }
}
```

### Step 3: Implement TTLV Decoder

Create `crates/kmip-server/src/ttlv/decoder.rs`:

```rust
use super::types::*;
use bytes::{Buf, Bytes};

pub struct TtlvDecoder;

impl TtlvDecoder {
    /// Decode bytes to a TTLV item
    pub fn decode(data: &[u8]) -> Result<Ttlv, TtlvError> {
        let mut bytes = Bytes::copy_from_slice(data);
        Self::decode_item(&mut bytes)
    }

    fn decode_item(buf: &mut Bytes) -> Result<Ttlv, TtlvError> {
        if buf.remaining() < 8 {
            return Err(TtlvError::UnexpectedEof);
        }

        // Tag (3 bytes)
        let tag = Tag(
            ((buf.get_u8() as u32) << 16)
                | ((buf.get_u8() as u32) << 8)
                | (buf.get_u8() as u32),
        );

        // Type (1 byte)
        let ttlv_type = TtlvType::try_from(buf.get_u8())?;

        // Length (4 bytes)
        let length = buf.get_u32() as usize;

        if buf.remaining() < length {
            return Err(TtlvError::UnexpectedEof);
        }

        let value = match ttlv_type {
            TtlvType::Structure => {
                let mut structure_bytes = buf.copy_to_bytes(length);
                let mut items = Vec::new();
                while structure_bytes.has_remaining() {
                    items.push(Self::decode_item(&mut structure_bytes)?);
                }
                TtlvValue::Structure(items)
            }

            TtlvType::Integer => {
                let value = buf.get_i32();
                buf.advance(4);  // Skip padding
                TtlvValue::Integer(value)
            }

            TtlvType::LongInteger => {
                TtlvValue::LongInteger(buf.get_i64())
            }

            TtlvType::BigInteger => {
                let value = buf.copy_to_bytes(length).to_vec();
                Self::skip_padding(buf, length);
                TtlvValue::BigInteger(value)
            }

            TtlvType::Enumeration => {
                let value = buf.get_u32();
                buf.advance(4);  // Skip padding
                TtlvValue::Enumeration(value)
            }

            TtlvType::Boolean => {
                let value = buf.get_u64() != 0;
                TtlvValue::Boolean(value)
            }

            TtlvType::TextString => {
                let value = String::from_utf8(buf.copy_to_bytes(length).to_vec())
                    .map_err(|_| TtlvError::InvalidEncoding("Invalid UTF-8".into()))?;
                Self::skip_padding(buf, length);
                TtlvValue::TextString(value)
            }

            TtlvType::ByteString => {
                let value = buf.copy_to_bytes(length).to_vec();
                Self::skip_padding(buf, length);
                TtlvValue::ByteString(value)
            }

            TtlvType::DateTime => {
                TtlvValue::DateTime(buf.get_i64())
            }

            TtlvType::Interval => {
                let value = buf.get_u32();
                buf.advance(4);  // Skip padding
                TtlvValue::Interval(value)
            }
        };

        Ok(Ttlv { tag, value })
    }

    fn skip_padding(buf: &mut Bytes, length: usize) {
        let padding = (8 - (length % 8)) % 8;
        if padding > 0 && buf.remaining() >= padding {
            buf.advance(padding);
        }
    }
}
```

### Step 4: Define KMIP Enumerations

Create `crates/kmip-server/src/protocol/enums.rs`:

```rust
//! KMIP Enumerations

/// KMIP Operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Operation {
    Create = 0x00000001,
    CreateKeyPair = 0x00000002,
    Register = 0x00000003,
    ReKey = 0x00000004,
    DeriveKey = 0x00000005,
    Certify = 0x00000006,
    ReCertify = 0x00000007,
    Locate = 0x00000008,
    Check = 0x00000009,
    Get = 0x0000000A,
    GetAttributes = 0x0000000B,
    GetAttributeList = 0x0000000C,
    AddAttribute = 0x0000000D,
    ModifyAttribute = 0x0000000E,
    DeleteAttribute = 0x0000000F,
    ObtainLease = 0x00000010,
    GetUsageAllocation = 0x00000011,
    Activate = 0x00000012,
    Revoke = 0x00000013,
    Destroy = 0x00000014,
    Archive = 0x00000015,
    Recover = 0x00000016,
    Validate = 0x00000017,
    Query = 0x00000018,
    Cancel = 0x00000019,
    Poll = 0x0000001A,
    Notify = 0x0000001B,
    Put = 0x0000001C,
    Encrypt = 0x0000001F,
    Decrypt = 0x00000020,
    Sign = 0x00000021,
    SignatureVerify = 0x00000022,
    MAC = 0x00000023,
    MACVerify = 0x00000024,
    RNGRetrieve = 0x00000025,
    RNGSeed = 0x00000026,
    Hash = 0x00000027,
    CreateSplitKey = 0x00000028,
    JoinSplitKey = 0x00000029,
}

impl TryFrom<u32> for Operation {
    type Error = ();
    fn try_from(v: u32) -> Result<Self, ()> {
        match v {
            0x01 => Ok(Operation::Create),
            0x0A => Ok(Operation::Get),
            0x12 => Ok(Operation::Activate),
            0x13 => Ok(Operation::Revoke),
            0x14 => Ok(Operation::Destroy),
            0x18 => Ok(Operation::Query),
            0x1F => Ok(Operation::Encrypt),
            0x20 => Ok(Operation::Decrypt),
            0x21 => Ok(Operation::Sign),
            _ => Err(()),
        }
    }
}

/// Object Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ObjectType {
    Certificate = 0x00000001,
    SymmetricKey = 0x00000002,
    PublicKey = 0x00000003,
    PrivateKey = 0x00000004,
    SplitKey = 0x00000005,
    Template = 0x00000006,
    SecretData = 0x00000007,
    OpaqueObject = 0x00000008,
    PGPKey = 0x00000009,
}

/// Cryptographic Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CryptographicAlgorithm {
    DES = 0x00000001,
    TripleDES = 0x00000002,
    AES = 0x00000003,
    RSA = 0x00000004,
    DSA = 0x00000005,
    ECDSA = 0x00000006,
    HMACSHA1 = 0x00000007,
    HMACSHA224 = 0x00000008,
    HMACSHA256 = 0x00000009,
    HMACSHA384 = 0x0000000A,
    HMACSHA512 = 0x0000000B,
    HMACMD5 = 0x0000000C,
    DH = 0x0000000D,
    ECDH = 0x0000000E,
    ECMQV = 0x0000000F,
    Blowfish = 0x00000010,
    Camellia = 0x00000011,
    CAST5 = 0x00000012,
    IDEA = 0x00000013,
    MARS = 0x00000014,
    RC2 = 0x00000015,
    RC4 = 0x00000016,
    RC5 = 0x00000017,
    SKIPJACK = 0x00000018,
    Twofish = 0x00000019,
    EC = 0x0000001A,
    Ed25519 = 0x0000001B,
    Ed448 = 0x0000001C,
}

/// Result Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResultStatus {
    Success = 0x00000000,
    OperationFailed = 0x00000001,
    OperationPending = 0x00000002,
    OperationUndone = 0x00000003,
}

/// Result Reason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResultReason {
    ItemNotFound = 0x00000001,
    ResponseTooLarge = 0x00000002,
    AuthenticationNotSuccessful = 0x00000003,
    InvalidMessage = 0x00000004,
    OperationNotSupported = 0x00000005,
    MissingData = 0x00000006,
    InvalidField = 0x00000007,
    FeatureNotSupported = 0x00000008,
    OperationCanceledByRequester = 0x00000009,
    CryptographicFailure = 0x0000000A,
    IllegalOperation = 0x0000000B,
    PermissionDenied = 0x0000000C,
    ObjectArchived = 0x0000000D,
    IndexOutOfBounds = 0x0000000E,
    ApplicationNamespaceNotSupported = 0x0000000F,
    KeyFormatNotSupported = 0x00000010,
    KeyCompressionTypeNotSupported = 0x00000011,
    EncodingOptionError = 0x00000012,
    KeyValueNotPresent = 0x00000013,
    AttestationRequired = 0x00000014,
    AttestationFailed = 0x00000015,
    GeneralFailure = 0x00000100,
}

/// Key State (lifecycle)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyState {
    PreActive = 0x00000001,
    Active = 0x00000002,
    Deactivated = 0x00000003,
    Compromised = 0x00000004,
    Destroyed = 0x00000005,
    DestroyedCompromised = 0x00000006,
}
```

### Step 5: Implement KMIP Server

Create `crates/kmip-server/src/server.rs`:

```rust
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, error, debug};

use crate::ttlv::{TtlvDecoder, TtlvEncoder, Ttlv, Tag, TtlvValue};
use crate::protocol::enums::*;
use crate::operations;

/// KMIP Server configuration
pub struct KmipServerConfig {
    pub bind_address: String,
    pub tls_config: Arc<rustls::ServerConfig>,
    pub hsm_client: Arc<dyn HsmClient>,
}

/// Trait for HSM operations
#[async_trait::async_trait]
pub trait HsmClient: Send + Sync {
    async fn create_key(
        &self,
        algorithm: CryptographicAlgorithm,
        length: u32,
        attributes: &[Attribute],
    ) -> Result<String, KmipError>;

    async fn get_key(&self, unique_id: &str) -> Result<KeyInfo, KmipError>;
    async fn activate_key(&self, unique_id: &str) -> Result<(), KmipError>;
    async fn revoke_key(&self, unique_id: &str, reason: RevocationReason) -> Result<(), KmipError>;
    async fn destroy_key(&self, unique_id: &str) -> Result<(), KmipError>;

    async fn encrypt(
        &self,
        unique_id: &str,
        data: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<EncryptResult, KmipError>;

    async fn decrypt(
        &self,
        unique_id: &str,
        data: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, KmipError>;

    async fn sign(&self, unique_id: &str, data: &[u8]) -> Result<Vec<u8>, KmipError>;
}

/// KMIP Server
pub struct KmipServer {
    config: KmipServerConfig,
}

impl KmipServer {
    pub fn new(config: KmipServerConfig) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> Result<(), KmipError> {
        let listener = TcpListener::bind(&self.config.bind_address).await?;
        let acceptor = TlsAcceptor::from(self.config.tls_config.clone());

        info!("KMIP server listening on {}", self.config.bind_address);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!("New connection from {}", peer_addr);

            let acceptor = acceptor.clone();
            let hsm_client = self.config.hsm_client.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) = handle_connection(tls_stream, hsm_client).await {
                            error!("Connection error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("TLS handshake failed: {}", e);
                    }
                }
            });
        }
    }
}

async fn handle_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    hsm_client: Arc<dyn HsmClient>,
) -> Result<(), KmipError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        // Read message length (first 4 bytes after header)
        // KMIP messages are self-delimiting via TTLV structure
        let mut header = [0u8; 8];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        // Parse header to get length
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // Read rest of message
        let mut message = vec![0u8; 8 + length];
        message[..8].copy_from_slice(&header);
        stream.read_exact(&mut message[8..]).await?;

        // Decode request
        let request = TtlvDecoder::decode(&message)?;

        // Process request
        let response = process_request(&request, &hsm_client).await?;

        // Encode and send response
        let response_bytes = TtlvEncoder::encode(&response);
        stream.write_all(&response_bytes).await?;
    }

    Ok(())
}

async fn process_request(
    request: &Ttlv,
    hsm_client: &Arc<dyn HsmClient>,
) -> Result<Ttlv, KmipError> {
    // Parse request header
    let header = request.get(Tag::REQUEST_HEADER)
        .ok_or(KmipError::InvalidMessage("Missing request header".into()))?;

    // Get protocol version
    let version = header.get(Tag::PROTOCOL_VERSION);

    // Process batch items
    let batch_items = request.get_all(Tag::REQUEST_BATCH_ITEM);
    let mut response_items = Vec::new();

    for item in batch_items {
        let response_item = process_batch_item(item, hsm_client).await;
        response_items.push(response_item);
    }

    // Build response
    let response_header = Ttlv::structure(Tag::RESPONSE_HEADER, vec![
        Ttlv::structure(Tag::PROTOCOL_VERSION, vec![
            Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
            Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
        ]),
        Ttlv::new(Tag::TIMESTAMP, TtlvValue::DateTime(chrono::Utc::now().timestamp())),
        Ttlv::integer(Tag::BATCH_COUNT, response_items.len() as i32),
    ]);

    let mut response_parts = vec![response_header];
    response_parts.extend(response_items);

    Ok(Ttlv::structure(Tag::RESPONSE_MESSAGE, response_parts))
}

async fn process_batch_item(
    item: &Ttlv,
    hsm_client: &Arc<dyn HsmClient>,
) -> Ttlv {
    let operation = item.get(Tag::OPERATION)
        .and_then(|op| {
            if let TtlvValue::Enumeration(v) = &op.value {
                Operation::try_from(*v).ok()
            } else {
                None
            }
        });

    let result = match operation {
        Some(Operation::Create) => operations::create::handle(item, hsm_client).await,
        Some(Operation::Get) => operations::get::handle(item, hsm_client).await,
        Some(Operation::Activate) => operations::activate::handle(item, hsm_client).await,
        Some(Operation::Revoke) => operations::revoke::handle(item, hsm_client).await,
        Some(Operation::Destroy) => operations::destroy::handle(item, hsm_client).await,
        Some(Operation::Encrypt) => operations::encrypt::handle(item, hsm_client).await,
        Some(Operation::Decrypt) => operations::decrypt::handle(item, hsm_client).await,
        Some(Operation::Sign) => operations::sign::handle(item, hsm_client).await,
        Some(Operation::Query) => operations::query::handle(item, hsm_client).await,
        _ => Err(KmipError::OperationNotSupported),
    };

    match result {
        Ok(response_payload) => {
            Ttlv::structure(Tag::RESPONSE_BATCH_ITEM, vec![
                Ttlv::enumeration(Tag::OPERATION, operation.unwrap() as u32),
                Ttlv::enumeration(Tag::RESULT_STATUS, ResultStatus::Success as u32),
                response_payload,
            ])
        }
        Err(e) => {
            let (reason, message) = e.to_kmip_error();
            Ttlv::structure(Tag::RESPONSE_BATCH_ITEM, vec![
                Ttlv::enumeration(Tag::RESULT_STATUS, ResultStatus::OperationFailed as u32),
                Ttlv::enumeration(Tag::RESULT_REASON, reason as u32),
                Ttlv::text_string(Tag::RESULT_MESSAGE, message),
            ])
        }
    }
}

// Supporting types
#[derive(Debug)]
pub struct Attribute {
    pub name: String,
    pub value: AttributeValue,
}

#[derive(Debug)]
pub enum AttributeValue {
    TextString(String),
    Integer(i32),
    Boolean(bool),
    DateTime(i64),
}

#[derive(Debug)]
pub struct KeyInfo {
    pub unique_id: String,
    pub object_type: ObjectType,
    pub algorithm: CryptographicAlgorithm,
    pub length: u32,
    pub state: KeyState,
    pub key_material: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct EncryptResult {
    pub data: Vec<u8>,
    pub iv: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct RevocationReason {
    pub code: u32,
    pub message: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum KmipError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TTLV error: {0}")]
    Ttlv(#[from] crate::ttlv::types::TtlvError),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Operation not supported")]
    OperationNotSupported,

    #[error("Item not found: {0}")]
    ItemNotFound(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Cryptographic failure: {0}")]
    CryptographicFailure(String),
}

impl KmipError {
    fn to_kmip_error(&self) -> (ResultReason, String) {
        match self {
            KmipError::ItemNotFound(id) => {
                (ResultReason::ItemNotFound, format!("Key not found: {}", id))
            }
            KmipError::OperationNotSupported => {
                (ResultReason::OperationNotSupported, "Operation not supported".into())
            }
            KmipError::PermissionDenied => {
                (ResultReason::PermissionDenied, "Permission denied".into())
            }
            KmipError::CryptographicFailure(msg) => {
                (ResultReason::CryptographicFailure, msg.clone())
            }
            _ => {
                (ResultReason::GeneralFailure, self.to_string())
            }
        }
    }
}
```

### Step 6: Implement Create Operation

Create `crates/kmip-server/src/operations/create.rs`:

```rust
use std::sync::Arc;
use crate::ttlv::{Ttlv, Tag, TtlvValue};
use crate::protocol::enums::*;
use crate::server::{HsmClient, KmipError, Attribute};

pub async fn handle(
    request: &Ttlv,
    hsm_client: &Arc<dyn HsmClient>,
) -> Result<Ttlv, KmipError> {
    // Parse object type
    let object_type = request.get(Tag::OBJECT_TYPE)
        .and_then(|t| {
            if let TtlvValue::Enumeration(v) = &t.value {
                Some(*v)
            } else {
                None
            }
        })
        .ok_or(KmipError::InvalidMessage("Missing object type".into()))?;

    // Parse template attributes
    let template = request.get(Tag::TEMPLATE_ATTRIBUTE)
        .ok_or(KmipError::InvalidMessage("Missing template".into()))?;

    let mut algorithm = None;
    let mut length = None;
    let mut attributes = Vec::new();

    for attr in template.get_all(Tag::ATTRIBUTE) {
        if let (Some(name), Some(value)) = (attr.get(Tag::ATTRIBUTE_NAME), attr.get(Tag::ATTRIBUTE_VALUE)) {
            if let TtlvValue::TextString(name_str) = &name.value {
                match name_str.as_str() {
                    "Cryptographic Algorithm" => {
                        if let TtlvValue::Enumeration(v) = &value.value {
                            algorithm = Some(*v);
                        }
                    }
                    "Cryptographic Length" => {
                        if let TtlvValue::Integer(v) = &value.value {
                            length = Some(*v as u32);
                        }
                    }
                    _ => {
                        // Store other attributes
                    }
                }
            }
        }
    }

    let algorithm = algorithm.ok_or(KmipError::InvalidMessage("Missing algorithm".into()))?;
    let length = length.ok_or(KmipError::InvalidMessage("Missing length".into()))?;

    // Map to HSM algorithm
    let hsm_algorithm = match algorithm {
        v if v == CryptographicAlgorithm::AES as u32 => CryptographicAlgorithm::AES,
        v if v == CryptographicAlgorithm::RSA as u32 => CryptographicAlgorithm::RSA,
        v if v == CryptographicAlgorithm::ECDSA as u32 => CryptographicAlgorithm::ECDSA,
        v if v == CryptographicAlgorithm::Ed25519 as u32 => CryptographicAlgorithm::Ed25519,
        _ => return Err(KmipError::InvalidMessage("Unsupported algorithm".into())),
    };

    // Create key in HSM
    let unique_id = hsm_client.create_key(hsm_algorithm, length, &attributes).await?;

    // Build response
    Ok(Ttlv::structure(Tag(0x42007C), vec![  // ResponsePayload
        Ttlv::enumeration(Tag::OBJECT_TYPE, object_type),
        Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
    ]))
}
```

## Testing Requirements

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttlv_encode_decode_roundtrip() {
        let original = Ttlv::structure(Tag::REQUEST_MESSAGE, vec![
            Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
            Ttlv::text_string(Tag::UNIQUE_ID, "test-key-123"),
            Ttlv::byte_string(Tag::DATA, vec![1, 2, 3, 4]),
        ]);

        let encoded = TtlvEncoder::encode(&original);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_kmip_create_request_parsing() {
        // Test parsing a real KMIP Create request
    }
}
```

### Integration Tests

```bash
# Test with kmip-client tool
kmip-client --host localhost --port 5696 --cert client.pem create-key --algorithm AES --length 256

# Test with PyKMIP
python3 -c "
from kmip.services.kmip_client import KMIPProxyClient
client = KMIPProxyClient(host='localhost', port=5696)
client.open()
uid = client.create(algorithm='AES', length=256)
print(f'Created key: {uid}')
client.close()
"
```

## Success Metrics

- [ ] TTLV encoding/decoding matches spec
- [ ] PyKMIP client can connect and perform operations
- [ ] Create, Get, Activate, Revoke, Destroy work correctly
- [ ] Encrypt/Decrypt/Sign operations work
- [ ] Proper error responses for invalid requests
- [ ] TLS mutual authentication works
- [ ] Batch operations supported

## Notes

- KMIP is complex; start with minimal viable subset
- Test against PyKMIP for compatibility
- Consider using existing Rust KMIP libraries if available
- Protocol version negotiation is important for compatibility
