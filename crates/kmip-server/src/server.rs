//! KMIP Server implementation
//!
//! Provides a TLS-based KMIP server that accepts connections from KMIP clients,
//! processes TTLV-encoded requests, and returns TTLV-encoded responses.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::operations;
use crate::protocol::enums::*;
use crate::ttlv::{Tag, Ttlv, TtlvDecoder, TtlvEncoder, TtlvError, TtlvValue};

/// KMIP Server configuration
pub struct KmipServerConfig {
    /// Address to bind the server to (e.g., "0.0.0.0:5696")
    pub bind_address: String,
    /// TLS configuration for the server
    pub tls_config: Arc<rustls::ServerConfig>,
    /// HSM client for performing cryptographic operations
    pub hsm_client: Arc<dyn HsmClient>,
}

/// Trait for HSM operations
///
/// This trait defines the interface between the KMIP server and the underlying
/// HSM functionality. Implementations should integrate with the actual HSM modules.
#[async_trait::async_trait]
pub trait HsmClient: Send + Sync {
    /// Create a new key
    async fn create_key(
        &self,
        algorithm: CryptographicAlgorithm,
        length: u32,
        usage_mask: CryptographicUsageMask,
        attributes: &[Attribute],
    ) -> Result<String, KmipError>;

    /// Get key information
    async fn get_key(&self, unique_id: &str) -> Result<KeyInfo, KmipError>;

    /// Activate a key (transition from Pre-Active to Active)
    async fn activate_key(&self, unique_id: &str) -> Result<(), KmipError>;

    /// Revoke a key
    async fn revoke_key(&self, unique_id: &str, reason: RevocationReason) -> Result<(), KmipError>;

    /// Destroy a key
    async fn destroy_key(&self, unique_id: &str) -> Result<(), KmipError>;

    /// Encrypt data using a key
    async fn encrypt(
        &self,
        unique_id: &str,
        data: &[u8],
        iv: Option<&[u8]>,
        params: Option<CryptoParams>,
    ) -> Result<EncryptResult, KmipError>;

    /// Decrypt data using a key
    async fn decrypt(
        &self,
        unique_id: &str,
        data: &[u8],
        iv: Option<&[u8]>,
        params: Option<CryptoParams>,
    ) -> Result<Vec<u8>, KmipError>;

    /// Sign data using a key
    async fn sign(
        &self,
        unique_id: &str,
        data: &[u8],
        params: Option<CryptoParams>,
    ) -> Result<Vec<u8>, KmipError>;

    /// Get server information
    fn server_info(&self) -> ServerInfo;
}

/// KMIP Server
pub struct KmipServer {
    config: KmipServerConfig,
}

impl KmipServer {
    /// Create a new KMIP server with the given configuration
    pub fn new(config: KmipServerConfig) -> Self {
        Self { config }
    }

    /// Run the KMIP server
    ///
    /// This method binds to the configured address and accepts TLS connections.
    /// Each connection is handled in a separate task.
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
                            error!("Connection error from {}: {}", peer_addr, e);
                        }
                        debug!("Connection from {} closed", peer_addr);
                    }
                    Err(e) => {
                        error!("TLS handshake failed from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

/// Handle a single KMIP connection
async fn handle_connection<S>(
    mut stream: S,
    hsm_client: Arc<dyn HsmClient>,
) -> Result<(), KmipError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        // Read TTLV header (8 bytes: tag + type + length)
        let mut header = [0u8; 8];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client closed connection gracefully
                break;
            }
            Err(e) => return Err(e.into()),
        }

        // Parse header to get message length
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // Read rest of message
        let mut message = vec![0u8; 8 + length];
        message[..8].copy_from_slice(&header);
        stream.read_exact(&mut message[8..]).await?;

        debug!("Received KMIP message: {} bytes", message.len());

        // Decode request
        let request = match TtlvDecoder::decode(&message) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to decode KMIP request: {}", e);
                let error_response =
                    build_error_response(ResultReason::InvalidMessage, "Invalid message format");
                let response_bytes = TtlvEncoder::encode(&error_response);
                stream.write_all(&response_bytes).await?;
                continue;
            }
        };

        // Process request
        let response = process_request(&request, &hsm_client).await;

        // Encode and send response
        let response_bytes = TtlvEncoder::encode(&response);
        debug!("Sending KMIP response: {} bytes", response_bytes.len());
        stream.write_all(&response_bytes).await?;
    }

    Ok(())
}

/// Process a KMIP request and return a response
async fn process_request(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Ttlv {
    // Parse request header
    let header = match request.get(Tag::REQUEST_HEADER) {
        Some(h) => h,
        None => {
            return build_error_response(ResultReason::InvalidMessage, "Missing request header");
        }
    };

    // Get protocol version (for response)
    let (major, minor) = parse_protocol_version(header);

    // Process batch items
    let batch_items = request.get_all(Tag::REQUEST_BATCH_ITEM);
    let mut response_items = Vec::with_capacity(batch_items.len());

    for item in batch_items {
        let response_item = process_batch_item(item, hsm_client).await;
        response_items.push(response_item);
    }

    // Build response
    build_response(major, minor, response_items)
}

/// Parse protocol version from request header
fn parse_protocol_version(header: &Ttlv) -> (i32, i32) {
    let version = header.get(Tag::PROTOCOL_VERSION);
    if let Some(v) = version {
        let major = v
            .get(Tag::PROTOCOL_VERSION_MAJOR)
            .and_then(|m| m.value.as_integer())
            .unwrap_or(1);
        let minor = v
            .get(Tag::PROTOCOL_VERSION_MINOR)
            .and_then(|m| m.value.as_integer())
            .unwrap_or(4);
        (major, minor)
    } else {
        (1, 4) // Default to KMIP 1.4
    }
}

/// Process a single batch item
async fn process_batch_item(item: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Ttlv {
    // Get operation
    let operation = item.get(Tag::OPERATION).and_then(|op| {
        if let TtlvValue::Enumeration(v) = &op.value {
            Operation::try_from(*v).ok()
        } else {
            None
        }
    });

    let operation = match operation {
        Some(op) => op,
        None => {
            return build_batch_error_response(
                None,
                ResultReason::InvalidMessage,
                "Missing or invalid operation",
            );
        }
    };

    debug!("Processing operation: {:?}", operation);

    let result = match operation {
        Operation::Create => operations::create::handle(item, hsm_client).await,
        Operation::Get => operations::get::handle(item, hsm_client).await,
        Operation::Activate => operations::activate::handle(item, hsm_client).await,
        Operation::Revoke => operations::revoke::handle(item, hsm_client).await,
        Operation::Destroy => operations::destroy::handle(item, hsm_client).await,
        Operation::Encrypt => operations::encrypt::handle(item, hsm_client).await,
        Operation::Decrypt => operations::decrypt::handle(item, hsm_client).await,
        Operation::Sign => operations::sign::handle(item, hsm_client).await,
        Operation::Query => operations::query::handle(item, hsm_client).await,
        _ => Err(KmipError::OperationNotSupported(operation)),
    };

    match result {
        Ok(response_payload) => Ttlv::structure(
            Tag::RESPONSE_BATCH_ITEM,
            vec![
                Ttlv::enumeration(Tag::OPERATION, operation as u32),
                Ttlv::enumeration(Tag::RESULT_STATUS, ResultStatus::Success as u32),
                response_payload,
            ],
        ),
        Err(e) => {
            let (reason, message) = e.to_kmip_error();
            warn!("Operation {:?} failed: {}", operation, message);
            build_batch_error_response(Some(operation), reason, &message)
        }
    }
}

/// Build a complete KMIP response message
fn build_response(major: i32, minor: i32, batch_items: Vec<Ttlv>) -> Ttlv {
    let response_header = Ttlv::structure(
        Tag::RESPONSE_HEADER,
        vec![
            Ttlv::structure(
                Tag::PROTOCOL_VERSION,
                vec![
                    Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, major),
                    Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, minor),
                ],
            ),
            Ttlv::datetime(Tag::TIMESTAMP, chrono::Utc::now().timestamp()),
            Ttlv::integer(Tag::BATCH_COUNT, batch_items.len() as i32),
        ],
    );

    let mut parts = vec![response_header];
    parts.extend(batch_items);

    Ttlv::structure(Tag::RESPONSE_MESSAGE, parts)
}

/// Build an error response message
fn build_error_response(reason: ResultReason, message: &str) -> Ttlv {
    let response_header = Ttlv::structure(
        Tag::RESPONSE_HEADER,
        vec![
            Ttlv::structure(
                Tag::PROTOCOL_VERSION,
                vec![
                    Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                    Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
                ],
            ),
            Ttlv::datetime(Tag::TIMESTAMP, chrono::Utc::now().timestamp()),
            Ttlv::integer(Tag::BATCH_COUNT, 1),
        ],
    );

    let batch_item = Ttlv::structure(
        Tag::RESPONSE_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::RESULT_STATUS, ResultStatus::OperationFailed as u32),
            Ttlv::enumeration(Tag::RESULT_REASON, reason as u32),
            Ttlv::text_string(Tag::RESULT_MESSAGE, message),
        ],
    );

    Ttlv::structure(Tag::RESPONSE_MESSAGE, vec![response_header, batch_item])
}

/// Build a batch item error response
fn build_batch_error_response(
    operation: Option<Operation>,
    reason: ResultReason,
    message: &str,
) -> Ttlv {
    let mut items = Vec::new();

    if let Some(op) = operation {
        items.push(Ttlv::enumeration(Tag::OPERATION, op as u32));
    }

    items.push(Ttlv::enumeration(
        Tag::RESULT_STATUS,
        ResultStatus::OperationFailed as u32,
    ));
    items.push(Ttlv::enumeration(Tag::RESULT_REASON, reason as u32));
    items.push(Ttlv::text_string(Tag::RESULT_MESSAGE, message));

    Ttlv::structure(Tag::RESPONSE_BATCH_ITEM, items)
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Key attribute
#[derive(Debug, Clone)]
pub struct Attribute {
    pub name: String,
    pub value: AttributeValue,
}

/// Attribute value variants
#[derive(Debug, Clone)]
pub enum AttributeValue {
    TextString(String),
    Integer(i32),
    LongInteger(i64),
    Boolean(bool),
    DateTime(i64),
    ByteString(Vec<u8>),
    Enumeration(u32),
}

/// Information about a key
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub unique_id: String,
    pub object_type: ObjectType,
    pub algorithm: CryptographicAlgorithm,
    pub length: u32,
    pub state: KeyState,
    pub usage_mask: CryptographicUsageMask,
    pub key_material: Option<Vec<u8>>,
}

/// Result of an encryption operation
#[derive(Debug, Clone)]
pub struct EncryptResult {
    pub data: Vec<u8>,
    pub iv: Option<Vec<u8>>,
}

/// Revocation reason
#[derive(Debug, Clone)]
pub struct RevocationReason {
    pub code: RevocationReasonCode,
    pub message: Option<String>,
}

/// Cryptographic parameters
#[derive(Debug, Clone, Default)]
pub struct CryptoParams {
    pub block_cipher_mode: Option<BlockCipherMode>,
    pub padding_method: Option<PaddingMethod>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
}

/// Server information
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub vendor: String,
    pub server_name: String,
    pub server_version: String,
    pub supported_operations: Vec<Operation>,
}

// ============================================================================
// Error Types
// ============================================================================

/// KMIP error types
#[derive(Debug, thiserror::Error)]
pub enum KmipError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TTLV error: {0}")]
    Ttlv(#[from] TtlvError),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Operation not supported: {0:?}")]
    OperationNotSupported(Operation),

    #[error("Item not found: {0}")]
    ItemNotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Cryptographic failure: {0}")]
    CryptographicFailure(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),

    #[error("Missing data: {0}")]
    MissingData(String),
}

impl KmipError {
    /// Convert to KMIP error code and message
    pub fn to_kmip_error(&self) -> (ResultReason, String) {
        match self {
            KmipError::ItemNotFound(id) => {
                (ResultReason::ItemNotFound, format!("Key not found: {}", id))
            }
            KmipError::OperationNotSupported(op) => (
                ResultReason::OperationNotSupported,
                format!("Operation not supported: {:?}", op),
            ),
            KmipError::PermissionDenied(msg) => (ResultReason::PermissionDenied, msg.clone()),
            KmipError::CryptographicFailure(msg) => {
                (ResultReason::CryptographicFailure, msg.clone())
            }
            KmipError::InvalidState(msg) => (ResultReason::WrongKeyLifecycleState, msg.clone()),
            KmipError::InvalidMessage(msg) => (ResultReason::InvalidMessage, msg.clone()),
            KmipError::InvalidAttribute(msg) => (ResultReason::InvalidAttribute, msg.clone()),
            KmipError::MissingData(msg) => (ResultReason::MissingData, msg.clone()),
            KmipError::Io(e) => (ResultReason::GeneralFailure, format!("IO error: {}", e)),
            KmipError::Ttlv(e) => (ResultReason::InvalidMessage, format!("TTLV error: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protocol_version() {
        let header = Ttlv::structure(
            Tag::REQUEST_HEADER,
            vec![Ttlv::structure(
                Tag::PROTOCOL_VERSION,
                vec![
                    Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                    Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
                ],
            )],
        );

        let (major, minor) = parse_protocol_version(&header);
        assert_eq!(major, 1);
        assert_eq!(minor, 4);
    }

    #[test]
    fn test_parse_protocol_version_default() {
        let header = Ttlv::structure(Tag::REQUEST_HEADER, vec![]);
        let (major, minor) = parse_protocol_version(&header);
        assert_eq!(major, 1);
        assert_eq!(minor, 4);
    }

    #[test]
    fn test_build_response() {
        let batch_items = vec![Ttlv::structure(
            Tag::RESPONSE_BATCH_ITEM,
            vec![
                Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
                Ttlv::enumeration(Tag::RESULT_STATUS, ResultStatus::Success as u32),
            ],
        )];

        let response = build_response(1, 4, batch_items);
        assert_eq!(response.tag, Tag::RESPONSE_MESSAGE);
        assert!(response.get(Tag::RESPONSE_HEADER).is_some());
    }

    #[test]
    fn test_error_conversion() {
        let err = KmipError::ItemNotFound("key-123".to_string());
        let (reason, msg) = err.to_kmip_error();
        assert_eq!(reason, ResultReason::ItemNotFound);
        assert!(msg.contains("key-123"));

        let err = KmipError::OperationNotSupported(Operation::Archive);
        let (reason, _) = err.to_kmip_error();
        assert_eq!(reason, ResultReason::OperationNotSupported);
    }
}
