//! KMIP Server implementation
//!
//! Provides a TLS-based KMIP server that accepts connections from KMIP clients,
//! processes TTLV-encoded requests, and returns TTLV-encoded responses.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::operations;
use crate::protocol::enums::*;
use crate::ttlv::{Tag, Ttlv, TtlvDecoder, TtlvEncoder, TtlvError, TtlvValue};

/// Maximum size (in bytes) of a single KMIP message body the server will accept.
///
/// The TTLV header carries a fully attacker-controlled 32-bit length. Without a
/// cap, a client could declare a ~4 GiB body and force the server to allocate that
/// buffer before reading a single payload byte, exhausting memory. KMIP messages
/// are small in practice (key material, attributes, a little ciphertext); a few MiB
/// is generous. Anything larger is rejected before allocation.
pub const MAX_KMIP_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Maximum number of connections handled concurrently.
///
/// Bounds the number of in-flight connection tasks (and therefore the aggregate
/// buffer/stack memory and file descriptors) so a flood of connections cannot
/// exhaust server resources. Excess connections wait for a permit.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Maximum time allowed to read a single message (header + body) from a client.
///
/// Wraps `read_exact` so a client that opens a connection and sends a partial
/// message (or nothing) cannot tie up a connection slot indefinitely (slowloris).
const READ_TIMEOUT: Duration = Duration::from_secs(30);

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

        // Cap concurrent connections so a connection flood cannot exhaust memory
        // or file descriptors. Each accepted connection holds a permit for its
        // lifetime; the accept loop blocks for a permit once the cap is reached.
        let connection_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        info!("KMIP server listening on {}", self.config.bind_address);

        loop {
            // Acquire a connection permit before accepting. Holding the permit
            // across the accept means we stop pulling new connections off the
            // backlog while at capacity, applying backpressure to clients.
            let permit = connection_limiter
                .clone()
                .acquire_owned()
                .await
                .expect("connection semaphore is never closed");

            let (stream, peer_addr) = listener.accept().await?;
            debug!("New connection from {}", peer_addr);

            let acceptor = acceptor.clone();
            let hsm_client = self.config.hsm_client.clone();

            tokio::spawn(async move {
                // Permit is moved into the task and released when the task ends.
                let _permit = permit;
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

/// Outcome of attempting to read one framed KMIP message from a stream.
#[derive(Debug)]
enum FramedRead {
    /// A complete message of the given bytes was read.
    Message(Vec<u8>),
    /// The peer closed the connection gracefully before sending a (further) message.
    Eof,
}

/// Read a single length-prefixed KMIP/TTLV message from `stream`.
///
/// Security properties:
/// - The 8-byte header is read first; the declared body length is validated
///   against [`MAX_KMIP_MESSAGE_SIZE`] *before* any body buffer is allocated, so
///   an attacker cannot trigger a multi-gigabyte allocation with a forged length.
/// - Both the header read and the body read are wrapped in a [`READ_TIMEOUT`], so
///   a client that stalls mid-message cannot hold a connection open indefinitely.
async fn read_framed_message<S>(stream: &mut S) -> Result<FramedRead, KmipError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    // Read TTLV header (8 bytes: tag + type + length) under a timeout.
    let mut header = [0u8; 8];
    match tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // Client closed connection gracefully (possibly between messages).
            return Ok(FramedRead::Eof);
        }
        Ok(Err(e)) => return Err(e.into()),
        Err(_elapsed) => {
            return Err(KmipError::InvalidMessage(
                "timed out reading message header".to_string(),
            ));
        }
    }

    // Parse header to get message body length.
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

    // Reject oversized declarations BEFORE allocating. This is the critical check:
    // `length` is fully attacker-controlled, so never size a buffer from it unchecked.
    if length > MAX_KMIP_MESSAGE_SIZE {
        return Err(KmipError::InvalidMessage(format!(
            "declared message body length {length} exceeds maximum {MAX_KMIP_MESSAGE_SIZE}"
        )));
    }

    // Allocate exactly the validated size (bounded by the cap) and read the body
    // under a timeout.
    let mut message = vec![0u8; 8 + length];
    message[..8].copy_from_slice(&header);
    match tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut message[8..])).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_elapsed) => {
            return Err(KmipError::InvalidMessage(
                "timed out reading message body".to_string(),
            ));
        }
    }

    Ok(FramedRead::Message(message))
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
        let message = match read_framed_message(&mut stream).await? {
            FramedRead::Message(m) => m,
            FramedRead::Eof => break,
        };

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

    /// Build an 8-byte TTLV header declaring a body of `length` bytes for a
    /// Structure tag. (Type 0x01 = Structure; length is big-endian.)
    fn ttlv_header(length: u32) -> [u8; 8] {
        [
            0x42,
            0x00,
            0x78, // RequestMessage tag
            0x01, // Structure
            (length >> 24) as u8,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ]
    }

    /// Regression test for HIGH #13: an over-large declared body length must be
    /// rejected from the header alone, *before* any body buffer is allocated.
    ///
    /// The reader here supplies ONLY the 8-byte header that declares a ~4 GiB body
    /// (0xFFFF_FFFF). If the code allocated `vec![0u8; 8 + length]` from the
    /// attacker-controlled length (the original bug), this test would attempt a
    /// ~4 GiB allocation and would not return a clean error. With the fix it
    /// returns `InvalidMessage` having allocated nothing.
    #[tokio::test]
    async fn test_oversized_length_rejected_without_allocating() {
        let header = ttlv_header(u32::MAX); // ~4 GiB declared body
        let mut reader: &[u8] = &header[..];

        let result = read_framed_message(&mut reader).await;
        match result {
            Err(KmipError::InvalidMessage(msg)) => {
                assert!(
                    msg.contains("exceeds maximum"),
                    "expected size-cap rejection, got: {msg}"
                );
            }
            other => panic!("expected InvalidMessage rejection, got {other:?}"),
        }
    }

    /// A declared length exactly one byte over the cap is rejected; the body is
    /// never read (reader provides no body bytes, yet there is no EOF error).
    #[tokio::test]
    async fn test_length_just_over_cap_rejected() {
        let over = u32::try_from(MAX_KMIP_MESSAGE_SIZE + 1).unwrap();
        let header = ttlv_header(over);
        let mut reader: &[u8] = &header[..];

        let result = read_framed_message(&mut reader).await;
        assert!(
            matches!(result, Err(KmipError::InvalidMessage(_))),
            "length one over the cap must be rejected, got {result:?}"
        );
    }

    /// A well-formed, in-bounds message round-trips through the framed reader and
    /// decodes back to the original TTLV, proving the cap does not reject valid
    /// traffic and the body is read correctly.
    #[tokio::test]
    async fn test_in_bounds_message_reads_and_decodes() {
        let original = Ttlv::structure(
            Tag::REQUEST_MESSAGE,
            vec![Ttlv::integer(Tag::BATCH_COUNT, 1)],
        );
        let encoded = TtlvEncoder::encode(&original);
        assert!(encoded.len() <= MAX_KMIP_MESSAGE_SIZE);

        let mut reader: &[u8] = &encoded[..];
        let framed = read_framed_message(&mut reader).await.unwrap();
        let bytes = match framed {
            FramedRead::Message(m) => m,
            FramedRead::Eof => panic!("expected a message, got EOF"),
        };
        assert_eq!(bytes, encoded);

        let decoded = TtlvDecoder::decode(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    /// An empty stream (peer closed before sending anything) yields a graceful EOF,
    /// not an error.
    #[tokio::test]
    async fn test_empty_stream_is_eof() {
        let mut reader: &[u8] = &[];
        let framed = read_framed_message(&mut reader).await.unwrap();
        assert!(matches!(framed, FramedRead::Eof));
    }

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
