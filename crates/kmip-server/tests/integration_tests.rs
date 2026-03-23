//! Integration tests for the KMIP server crate.
//!
//! These tests exercise the public API end-to-end, including:
//! - TTLV encode/decode roundtrips for every value type
//! - Create, Get, Destroy operations via mock HsmClient
//! - Error handling for invalid/malformed requests

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use hsm_kmip::operations;
use hsm_kmip::{
    Attribute, CryptoParams, CryptographicAlgorithm, CryptographicUsageMask, EncryptResult,
    HsmClient, KeyInfo, KeyState, KmipError, ObjectType, Operation, RevocationReason, ServerInfo,
    Tag, Ttlv, TtlvDecoder, TtlvEncoder, TtlvError, TtlvType, TtlvValue,
};

// ============================================================================
// Mock HsmClient
// ============================================================================

/// In-memory mock of the HsmClient trait for testing KMIP operations
/// without a real HSM backend.
struct MockHsmClient {
    keys: Mutex<HashMap<String, KeyInfo>>,
    next_id: Mutex<u64>,
}

impl MockHsmClient {
    fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }
}

#[async_trait::async_trait]
impl HsmClient for MockHsmClient {
    async fn create_key(
        &self,
        algorithm: CryptographicAlgorithm,
        length: u32,
        usage_mask: CryptographicUsageMask,
        _attributes: &[Attribute],
    ) -> Result<String, KmipError> {
        let mut next_id = self.next_id.lock().await;
        let id = format!("mock-key-{}", *next_id);
        *next_id += 1;

        // Generate fake key material of the right byte length
        let key_bytes = vec![0xABu8; (length / 8) as usize];

        let info = KeyInfo {
            unique_id: id.clone(),
            object_type: ObjectType::SymmetricKey,
            algorithm,
            length,
            state: KeyState::PreActive,
            usage_mask,
            key_material: Some(key_bytes),
        };

        self.keys.lock().await.insert(id.clone(), info);
        Ok(id)
    }

    async fn get_key(&self, unique_id: &str) -> Result<KeyInfo, KmipError> {
        self.keys
            .lock()
            .await
            .get(unique_id)
            .cloned()
            .ok_or_else(|| KmipError::ItemNotFound(unique_id.to_string()))
    }

    async fn activate_key(&self, unique_id: &str) -> Result<(), KmipError> {
        let mut keys = self.keys.lock().await;
        let info = keys
            .get_mut(unique_id)
            .ok_or_else(|| KmipError::ItemNotFound(unique_id.to_string()))?;
        info.state = KeyState::Active;
        Ok(())
    }

    async fn revoke_key(
        &self,
        unique_id: &str,
        _reason: RevocationReason,
    ) -> Result<(), KmipError> {
        let mut keys = self.keys.lock().await;
        let info = keys
            .get_mut(unique_id)
            .ok_or_else(|| KmipError::ItemNotFound(unique_id.to_string()))?;
        info.state = KeyState::Compromised;
        Ok(())
    }

    async fn destroy_key(&self, unique_id: &str) -> Result<(), KmipError> {
        let mut keys = self.keys.lock().await;
        if keys.remove(unique_id).is_none() {
            return Err(KmipError::ItemNotFound(unique_id.to_string()));
        }
        Ok(())
    }

    async fn encrypt(
        &self,
        unique_id: &str,
        data: &[u8],
        _iv: Option<&[u8]>,
        _params: Option<CryptoParams>,
    ) -> Result<EncryptResult, KmipError> {
        // Verify key exists
        let keys = self.keys.lock().await;
        if !keys.contains_key(unique_id) {
            return Err(KmipError::ItemNotFound(unique_id.to_string()));
        }
        // Trivial "encryption": reverse the bytes
        Ok(EncryptResult {
            data: data.iter().rev().copied().collect(),
            iv: Some(vec![0u8; 12]),
        })
    }

    async fn decrypt(
        &self,
        unique_id: &str,
        data: &[u8],
        _iv: Option<&[u8]>,
        _params: Option<CryptoParams>,
    ) -> Result<Vec<u8>, KmipError> {
        let keys = self.keys.lock().await;
        if !keys.contains_key(unique_id) {
            return Err(KmipError::ItemNotFound(unique_id.to_string()));
        }
        Ok(data.iter().rev().copied().collect())
    }

    async fn sign(
        &self,
        unique_id: &str,
        _data: &[u8],
        _params: Option<CryptoParams>,
    ) -> Result<Vec<u8>, KmipError> {
        let keys = self.keys.lock().await;
        if !keys.contains_key(unique_id) {
            return Err(KmipError::ItemNotFound(unique_id.to_string()));
        }
        Ok(vec![0xAAu8; 64])
    }

    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            vendor: "Test Vendor".to_string(),
            server_name: "Mock KMIP Server".to_string(),
            server_version: "0.1.0-test".to_string(),
            supported_operations: vec![
                Operation::Create,
                Operation::Get,
                Operation::Activate,
                Operation::Destroy,
                Operation::Query,
            ],
        }
    }
}

// ============================================================================
// Helper functions for building KMIP request messages
// ============================================================================

/// Build a full KMIP Create request for a symmetric key.
fn build_create_request(algorithm: CryptographicAlgorithm, length: i32) -> Ttlv {
    Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
            Ttlv::enumeration(Tag::OBJECT_TYPE, ObjectType::SymmetricKey as u32),
            Ttlv::structure(
                Tag::TEMPLATE_ATTRIBUTE,
                vec![
                    Ttlv::structure(
                        Tag::ATTRIBUTE,
                        vec![
                            Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                            Ttlv::enumeration(Tag::ATTRIBUTE_VALUE, algorithm as u32),
                        ],
                    ),
                    Ttlv::structure(
                        Tag::ATTRIBUTE,
                        vec![
                            Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Length"),
                            Ttlv::integer(Tag::ATTRIBUTE_VALUE, length),
                        ],
                    ),
                ],
            ),
        ],
    )
}

/// Build a KMIP Get request for a given unique ID.
fn build_get_request(unique_id: &str) -> Ttlv {
    Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Get as u32),
            Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
        ],
    )
}

/// Build a KMIP Destroy request for a given unique ID.
fn build_destroy_request(unique_id: &str) -> Ttlv {
    Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Destroy as u32),
            Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
        ],
    )
}

/// Extract the unique ID from a Create or Get response payload.
fn extract_unique_id(response_payload: &Ttlv) -> Option<&str> {
    response_payload
        .get(Tag::UNIQUE_ID)
        .and_then(|t| t.value.as_text_string())
}

// ============================================================================
// 1. TTLV Encoding/Decoding Roundtrip Tests
// ============================================================================

#[test]
fn ttlv_roundtrip_integer() {
    let original = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 42);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_negative_integer() {
    let original = Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, -999);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_long_integer() {
    let original = Ttlv::long_integer(Tag::TIMESTAMP, i64::MAX);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_enumeration() {
    let original = Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_boolean_true() {
    let original = Ttlv::boolean(Tag::ATTRIBUTE_VALUE, true);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_boolean_false() {
    let original = Ttlv::boolean(Tag::ATTRIBUTE_VALUE, false);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_text_string_short() {
    let original = Ttlv::text_string(Tag::UNIQUE_ID, "abc");
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_text_string_exact_8_bytes() {
    // Exactly 8 bytes means zero padding needed.
    let original = Ttlv::text_string(Tag::UNIQUE_ID, "12345678");
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_text_string_long() {
    let long_str = "a]".repeat(100); // 200 chars
    let original = Ttlv::text_string(Tag::UNIQUE_ID, &long_str);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_empty_text_string() {
    let original = Ttlv::text_string(Tag::UNIQUE_ID, "");
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_byte_string() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01];
    let original = Ttlv::byte_string(Tag::DATA, data);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_empty_byte_string() {
    let original = Ttlv::byte_string(Tag::DATA, vec![]);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_datetime() {
    let timestamp = 1704067200i64; // 2024-01-01 00:00:00 UTC
    let original = Ttlv::datetime(Tag::TIMESTAMP, timestamp);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_interval() {
    let original = Ttlv::interval(Tag::ATTRIBUTE_VALUE, 86400); // 1 day
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_big_integer() {
    let big = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    let original = Ttlv::big_integer(Tag::ATTRIBUTE_VALUE, big);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_flat_structure() {
    let original = Ttlv::structure(
        Tag::PROTOCOL_VERSION,
        vec![
            Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
            Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
        ],
    );
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_nested_structure() {
    let original = Ttlv::structure(
        Tag::REQUEST_MESSAGE,
        vec![
            Ttlv::structure(
                Tag::REQUEST_HEADER,
                vec![
                    Ttlv::structure(
                        Tag::PROTOCOL_VERSION,
                        vec![
                            Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                            Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
                        ],
                    ),
                    Ttlv::integer(Tag::BATCH_COUNT, 2),
                ],
            ),
            Ttlv::structure(
                Tag::REQUEST_BATCH_ITEM,
                vec![
                    Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
                    Ttlv::text_string(Tag::UNIQUE_ID, "key-abc-123"),
                    Ttlv::byte_string(Tag::DATA, vec![1, 2, 3, 4, 5]),
                    Ttlv::boolean(Tag::ATTRIBUTE_VALUE, true),
                ],
            ),
        ],
    );
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_empty_structure() {
    let original = Ttlv::structure(Tag::TEMPLATE_ATTRIBUTE, vec![]);
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn ttlv_roundtrip_mixed_types_in_structure() {
    let original = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::integer(Tag::CRYPTOGRAPHIC_LENGTH, 256),
            Ttlv::enumeration(
                Tag::CRYPTOGRAPHIC_ALGORITHM,
                CryptographicAlgorithm::Aes as u32,
            ),
            Ttlv::text_string(Tag::UNIQUE_ID, "my-test-key"),
            Ttlv::byte_string(Tag::DATA, vec![0xFF; 32]),
            Ttlv::boolean(Tag::ATTRIBUTE_VALUE, false),
            Ttlv::datetime(Tag::TIMESTAMP, 1700000000),
            Ttlv::long_integer(Tag::TIMESTAMP, 0x0102030405060708),
            Ttlv::interval(Tag::ATTRIBUTE_VALUE, 3600),
        ],
    );
    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

// ============================================================================
// 2. Create Operation Tests
// ============================================================================

#[tokio::test]
async fn create_symmetric_key_aes_256() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());
    let request = build_create_request(CryptographicAlgorithm::Aes, 256);

    let response = operations::create::handle(&request, &client).await.unwrap();

    // Response should be a RESPONSE_PAYLOAD structure
    assert_eq!(response.tag, Tag::RESPONSE_PAYLOAD);

    // Should contain ObjectType = SymmetricKey
    let obj_type = response
        .get(Tag::OBJECT_TYPE)
        .and_then(|t| t.value.as_enumeration())
        .unwrap();
    assert_eq!(obj_type, ObjectType::SymmetricKey as u32);

    // Should contain a UniqueIdentifier
    let unique_id = extract_unique_id(&response);
    assert!(unique_id.is_some());
    assert!(unique_id.unwrap().starts_with("mock-key-"));
}

#[tokio::test]
async fn create_symmetric_key_aes_128() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());
    let request = build_create_request(CryptographicAlgorithm::Aes, 128);

    let response = operations::create::handle(&request, &client).await.unwrap();
    let unique_id = extract_unique_id(&response).unwrap();
    assert!(!unique_id.is_empty());
}

#[tokio::test]
async fn create_key_missing_object_type() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Request without OBJECT_TYPE
    let request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
            Ttlv::structure(
                Tag::TEMPLATE_ATTRIBUTE,
                vec![
                    Ttlv::structure(
                        Tag::ATTRIBUTE,
                        vec![
                            Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                            Ttlv::enumeration(
                                Tag::ATTRIBUTE_VALUE,
                                CryptographicAlgorithm::Aes as u32,
                            ),
                        ],
                    ),
                    Ttlv::structure(
                        Tag::ATTRIBUTE,
                        vec![
                            Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Length"),
                            Ttlv::integer(Tag::ATTRIBUTE_VALUE, 256),
                        ],
                    ),
                ],
            ),
        ],
    );

    let result = operations::create::handle(&request, &client).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::MissingData(msg) => assert!(msg.contains("object type")),
        other => panic!("Expected MissingData, got: {:?}", other),
    }
}

#[tokio::test]
async fn create_key_missing_algorithm() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Request with ObjectType but missing algorithm in template
    let request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
            Ttlv::enumeration(Tag::OBJECT_TYPE, ObjectType::SymmetricKey as u32),
            Ttlv::structure(
                Tag::TEMPLATE_ATTRIBUTE,
                vec![Ttlv::structure(
                    Tag::ATTRIBUTE,
                    vec![
                        Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Length"),
                        Ttlv::integer(Tag::ATTRIBUTE_VALUE, 256),
                    ],
                )],
            ),
        ],
    );

    let result = operations::create::handle(&request, &client).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::MissingData(msg) => assert!(msg.contains("algorithm")),
        other => panic!("Expected MissingData, got: {:?}", other),
    }
}

#[tokio::test]
async fn create_key_missing_length() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Request with ObjectType and algorithm but missing length
    let request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
            Ttlv::enumeration(Tag::OBJECT_TYPE, ObjectType::SymmetricKey as u32),
            Ttlv::structure(
                Tag::TEMPLATE_ATTRIBUTE,
                vec![Ttlv::structure(
                    Tag::ATTRIBUTE,
                    vec![
                        Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                        Ttlv::enumeration(Tag::ATTRIBUTE_VALUE, CryptographicAlgorithm::Aes as u32),
                    ],
                )],
            ),
        ],
    );

    let result = operations::create::handle(&request, &client).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::MissingData(msg) => assert!(msg.contains("length")),
        other => panic!("Expected MissingData, got: {:?}", other),
    }
}

#[tokio::test]
async fn create_key_invalid_algorithm_for_symmetric() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // RSA is not valid for SymmetricKey
    let request = build_create_request(CryptographicAlgorithm::Rsa, 2048);

    let result = operations::create::handle(&request, &client).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::InvalidAttribute(msg) => {
            assert!(msg.contains("not valid for symmetric key"))
        }
        other => panic!("Expected InvalidAttribute, got: {:?}", other),
    }
}

#[tokio::test]
async fn create_multiple_keys_get_unique_ids() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    let r1 = operations::create::handle(
        &build_create_request(CryptographicAlgorithm::Aes, 256),
        &client,
    )
    .await
    .unwrap();

    let r2 = operations::create::handle(
        &build_create_request(CryptographicAlgorithm::Aes, 128),
        &client,
    )
    .await
    .unwrap();

    let id1 = extract_unique_id(&r1).unwrap();
    let id2 = extract_unique_id(&r2).unwrap();
    assert_ne!(id1, id2, "Each created key should have a unique identifier");
}

// ============================================================================
// 3. Get Operation Tests
// ============================================================================

#[tokio::test]
async fn get_key_after_create() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // First create a key
    let create_response = operations::create::handle(
        &build_create_request(CryptographicAlgorithm::Aes, 256),
        &client,
    )
    .await
    .unwrap();
    let key_id = extract_unique_id(&create_response).unwrap();

    // Now get it
    let get_request = build_get_request(key_id);
    let get_response = operations::get::handle(&get_request, &client)
        .await
        .unwrap();

    assert_eq!(get_response.tag, Tag::RESPONSE_PAYLOAD);

    // Verify ObjectType
    let obj_type = get_response
        .get(Tag::OBJECT_TYPE)
        .and_then(|t| t.value.as_enumeration())
        .unwrap();
    assert_eq!(obj_type, ObjectType::SymmetricKey as u32);

    // Verify UniqueIdentifier matches
    let returned_id = extract_unique_id(&get_response).unwrap();
    assert_eq!(returned_id, key_id);

    // Verify KeyBlock is present with key material
    let key_block = get_response.get(Tag::KEY_BLOCK).unwrap();

    let key_format = key_block
        .get(Tag::KEY_FORMAT_TYPE)
        .and_then(|t| t.value.as_enumeration())
        .unwrap();
    assert_eq!(key_format, hsm_kmip::KeyFormatType::Raw as u32);

    let key_value = key_block.get(Tag::KEY_VALUE).unwrap();
    let key_material = key_value
        .get(Tag::KEY_MATERIAL)
        .and_then(|t| t.value.as_byte_string())
        .unwrap();
    // AES-256 = 32 bytes
    assert_eq!(key_material.len(), 32);

    // Verify algorithm in key block
    let algo = key_block
        .get(Tag::CRYPTOGRAPHIC_ALGORITHM)
        .and_then(|t| t.value.as_enumeration())
        .unwrap();
    assert_eq!(algo, CryptographicAlgorithm::Aes as u32);

    // Verify length in key block
    let length = key_block
        .get(Tag::CRYPTOGRAPHIC_LENGTH)
        .and_then(|t| t.value.as_integer())
        .unwrap();
    assert_eq!(length, 256);
}

#[tokio::test]
async fn get_nonexistent_key_returns_error() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    let get_request = build_get_request("does-not-exist");
    let result = operations::get::handle(&get_request, &client).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::ItemNotFound(id) => assert_eq!(id, "does-not-exist"),
        other => panic!("Expected ItemNotFound, got: {:?}", other),
    }
}

#[tokio::test]
async fn get_key_missing_unique_id() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Get request without UNIQUE_ID
    let request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![Ttlv::enumeration(Tag::OPERATION, Operation::Get as u32)],
    );

    let result = operations::get::handle(&request, &client).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::MissingData(msg) => assert!(msg.contains("unique ID")),
        other => panic!("Expected MissingData, got: {:?}", other),
    }
}

// ============================================================================
// 4. Destroy Operation Tests
// ============================================================================

#[tokio::test]
async fn destroy_key_after_create() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Create a key
    let create_response = operations::create::handle(
        &build_create_request(CryptographicAlgorithm::Aes, 256),
        &client,
    )
    .await
    .unwrap();
    let key_id = extract_unique_id(&create_response).unwrap().to_string();

    // Destroy it
    let destroy_request = build_destroy_request(&key_id);
    let destroy_response = operations::destroy::handle(&destroy_request, &client)
        .await
        .unwrap();

    assert_eq!(destroy_response.tag, Tag::RESPONSE_PAYLOAD);
    let returned_id = extract_unique_id(&destroy_response).unwrap();
    assert_eq!(returned_id, key_id);

    // Verify key is gone: Get should fail
    let get_request = build_get_request(&key_id);
    let get_result = operations::get::handle(&get_request, &client).await;
    assert!(get_result.is_err());
    assert!(matches!(
        get_result.unwrap_err(),
        KmipError::ItemNotFound(_)
    ));
}

#[tokio::test]
async fn destroy_nonexistent_key_returns_error() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    let destroy_request = build_destroy_request("ghost-key");
    let result = operations::destroy::handle(&destroy_request, &client).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::ItemNotFound(id) => assert_eq!(id, "ghost-key"),
        other => panic!("Expected ItemNotFound, got: {:?}", other),
    }
}

#[tokio::test]
async fn destroy_key_missing_unique_id() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    let request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![Ttlv::enumeration(Tag::OPERATION, Operation::Destroy as u32)],
    );

    let result = operations::destroy::handle(&request, &client).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        KmipError::MissingData(msg) => assert!(msg.contains("unique ID")),
        other => panic!("Expected MissingData, got: {:?}", other),
    }
}

#[tokio::test]
async fn destroy_same_key_twice_fails_second_time() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Create a key
    let create_response = operations::create::handle(
        &build_create_request(CryptographicAlgorithm::Aes, 256),
        &client,
    )
    .await
    .unwrap();
    let key_id = extract_unique_id(&create_response).unwrap().to_string();

    // First destroy succeeds
    let result1 = operations::destroy::handle(&build_destroy_request(&key_id), &client).await;
    assert!(result1.is_ok());

    // Second destroy fails
    let result2 = operations::destroy::handle(&build_destroy_request(&key_id), &client).await;
    assert!(result2.is_err());
    assert!(matches!(result2.unwrap_err(), KmipError::ItemNotFound(_)));
}

// ============================================================================
// 5. Full Create-Get-Destroy Lifecycle Test
// ============================================================================

#[tokio::test]
async fn full_key_lifecycle_create_get_destroy() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Step 1: Create
    let create_resp = operations::create::handle(
        &build_create_request(CryptographicAlgorithm::Aes, 256),
        &client,
    )
    .await
    .unwrap();
    let key_id = extract_unique_id(&create_resp).unwrap().to_string();

    // Step 2: Get and verify
    let get_resp = operations::get::handle(&build_get_request(&key_id), &client)
        .await
        .unwrap();
    let retrieved_id = extract_unique_id(&get_resp).unwrap();
    assert_eq!(retrieved_id, key_id);

    // Step 3: Destroy
    let destroy_resp = operations::destroy::handle(&build_destroy_request(&key_id), &client)
        .await
        .unwrap();
    let destroyed_id = extract_unique_id(&destroy_resp).unwrap();
    assert_eq!(destroyed_id, key_id);

    // Step 4: Confirm gone
    let final_get = operations::get::handle(&build_get_request(&key_id), &client).await;
    assert!(final_get.is_err());
}

// ============================================================================
// 6. Error Handling Tests
// ============================================================================

#[test]
fn ttlv_decode_empty_buffer() {
    let result = TtlvDecoder::decode(&[]);
    assert!(matches!(result, Err(TtlvError::UnexpectedEof)));
}

#[test]
fn ttlv_decode_truncated_header() {
    // Only 5 bytes, need at least 8
    let result = TtlvDecoder::decode(&[0x42, 0x00, 0x78, 0x01, 0x00]);
    assert!(matches!(result, Err(TtlvError::UnexpectedEof)));
}

#[test]
fn ttlv_decode_invalid_type_byte() {
    // Valid tag + invalid type (0xFF) + length
    let data = [
        0x42, 0x00, 0x78, // Tag
        0xFF, // Invalid type
        0x00, 0x00, 0x00, 0x08, // Length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dummy value
    ];
    let result = TtlvDecoder::decode(&data);
    assert!(matches!(result, Err(TtlvError::InvalidType(0xFF))));
}

#[test]
fn ttlv_decode_truncated_value() {
    // Valid header claiming length=100 but only 4 bytes of value data
    let data = [
        0x42, 0x00, 0x78, // Tag
        0x07, // Type: TextString
        0x00, 0x00, 0x00, 0x64, // Length: 100
        0x41, 0x42, 0x43, 0x44, // Only 4 bytes
    ];
    let result = TtlvDecoder::decode(&data);
    assert!(matches!(result, Err(TtlvError::UnexpectedEof)));
}

#[test]
fn ttlv_type_try_from_all_valid_types() {
    assert_eq!(TtlvType::try_from(0x01).unwrap(), TtlvType::Structure);
    assert_eq!(TtlvType::try_from(0x02).unwrap(), TtlvType::Integer);
    assert_eq!(TtlvType::try_from(0x03).unwrap(), TtlvType::LongInteger);
    assert_eq!(TtlvType::try_from(0x04).unwrap(), TtlvType::BigInteger);
    assert_eq!(TtlvType::try_from(0x05).unwrap(), TtlvType::Enumeration);
    assert_eq!(TtlvType::try_from(0x06).unwrap(), TtlvType::Boolean);
    assert_eq!(TtlvType::try_from(0x07).unwrap(), TtlvType::TextString);
    assert_eq!(TtlvType::try_from(0x08).unwrap(), TtlvType::ByteString);
    assert_eq!(TtlvType::try_from(0x09).unwrap(), TtlvType::DateTime);
    assert_eq!(TtlvType::try_from(0x0A).unwrap(), TtlvType::Interval);
}

#[test]
fn ttlv_type_try_from_invalid() {
    assert!(TtlvType::try_from(0x00).is_err());
    assert!(TtlvType::try_from(0x0B).is_err());
    assert!(TtlvType::try_from(0xFF).is_err());
}

#[test]
fn ttlv_value_type_accessors_return_none_for_wrong_type() {
    let int_val = TtlvValue::Integer(42);
    assert!(int_val.as_integer().is_some());
    assert!(int_val.as_text_string().is_none());
    assert!(int_val.as_byte_string().is_none());
    assert!(int_val.as_enumeration().is_none());
    assert!(int_val.as_boolean().is_none());
    assert!(int_val.as_long_integer().is_none());
    assert!(int_val.as_structure().is_none());

    let text_val = TtlvValue::TextString("hello".into());
    assert!(text_val.as_text_string().is_some());
    assert!(text_val.as_integer().is_none());
}

#[test]
fn ttlv_structure_get_missing_tag_returns_none() {
    let structure = Ttlv::structure(
        Tag::REQUEST_MESSAGE,
        vec![Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1)],
    );
    assert!(structure.get(Tag::PROTOCOL_VERSION_MAJOR).is_some());
    assert!(structure.get(Tag::UNIQUE_ID).is_none());
}

#[test]
fn ttlv_non_structure_get_returns_none() {
    let item = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1);
    assert!(item.get(Tag::PROTOCOL_VERSION_MAJOR).is_none());
}

#[test]
fn ttlv_get_all_returns_multiple_matches() {
    let structure = Ttlv::structure(
        Tag::REQUEST_MESSAGE,
        vec![
            Ttlv::enumeration(Tag::OPERATION, 0x01),
            Ttlv::enumeration(Tag::OPERATION, 0x02),
            Ttlv::enumeration(Tag::OPERATION, 0x03),
        ],
    );
    let ops = structure.get_all(Tag::OPERATION);
    assert_eq!(ops.len(), 3);
}

#[test]
fn ttlv_encoded_size_matches_actual() {
    let items = vec![
        Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
        Ttlv::text_string(Tag::UNIQUE_ID, "hello world"),
        Ttlv::byte_string(Tag::DATA, vec![0xFF; 17]),
        Ttlv::boolean(Tag::ATTRIBUTE_VALUE, true),
        Ttlv::enumeration(Tag::OPERATION, 1),
        Ttlv::datetime(Tag::TIMESTAMP, 1700000000),
        Ttlv::long_integer(Tag::TIMESTAMP, i64::MIN),
        Ttlv::interval(Tag::ATTRIBUTE_VALUE, 999),
        Ttlv::structure(
            Tag::PROTOCOL_VERSION,
            vec![
                Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 2),
                Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 0),
            ],
        ),
    ];

    for item in &items {
        let encoded = TtlvEncoder::encode(item);
        let predicted = hsm_kmip::ttlv::encoded_size(item);
        assert_eq!(
            encoded.len(),
            predicted,
            "Size mismatch for {:?}",
            item.value.ttlv_type()
        );
    }
}

// ============================================================================
// 7. KMIP Error Conversion Tests
// ============================================================================

#[test]
fn kmip_error_to_kmip_error_conversions() {
    let cases: Vec<(KmipError, hsm_kmip::ResultReason)> = vec![
        (
            KmipError::ItemNotFound("k".into()),
            hsm_kmip::ResultReason::ItemNotFound,
        ),
        (
            KmipError::OperationNotSupported(Operation::Archive),
            hsm_kmip::ResultReason::OperationNotSupported,
        ),
        (
            KmipError::PermissionDenied("no".into()),
            hsm_kmip::ResultReason::PermissionDenied,
        ),
        (
            KmipError::CryptographicFailure("bad".into()),
            hsm_kmip::ResultReason::CryptographicFailure,
        ),
        (
            KmipError::InvalidState("wrong".into()),
            hsm_kmip::ResultReason::WrongKeyLifecycleState,
        ),
        (
            KmipError::InvalidMessage("malformed".into()),
            hsm_kmip::ResultReason::InvalidMessage,
        ),
        (
            KmipError::InvalidAttribute("bad attr".into()),
            hsm_kmip::ResultReason::InvalidAttribute,
        ),
        (
            KmipError::MissingData("missing".into()),
            hsm_kmip::ResultReason::MissingData,
        ),
    ];

    for (error, expected_reason) in cases {
        let (reason, _msg) = error.to_kmip_error();
        assert_eq!(reason, expected_reason, "Mismatch for error: {:?}", error);
    }
}

// ============================================================================
// 8. Activate Operation Test
// ============================================================================

#[tokio::test]
async fn activate_key_after_create() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    // Create
    let create_resp = operations::create::handle(
        &build_create_request(CryptographicAlgorithm::Aes, 256),
        &client,
    )
    .await
    .unwrap();
    let key_id = extract_unique_id(&create_resp).unwrap().to_string();

    // Activate
    let activate_request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Activate as u32),
            Ttlv::text_string(Tag::UNIQUE_ID, &key_id),
        ],
    );
    let activate_resp = operations::activate::handle(&activate_request, &client)
        .await
        .unwrap();

    let returned_id = extract_unique_id(&activate_resp).unwrap();
    assert_eq!(returned_id, key_id);
}

#[tokio::test]
async fn activate_nonexistent_key_fails() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    let request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Activate as u32),
            Ttlv::text_string(Tag::UNIQUE_ID, "no-such-key"),
        ],
    );

    let result = operations::activate::handle(&request, &client).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KmipError::ItemNotFound(_)));
}

// ============================================================================
// 9. Query Operation Test
// ============================================================================

#[tokio::test]
async fn query_supported_operations() {
    let client: Arc<dyn HsmClient> = Arc::new(MockHsmClient::new());

    let request = Ttlv::structure(
        Tag::REQUEST_BATCH_ITEM,
        vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Query as u32),
            Ttlv::enumeration(
                Tag::QUERY_FUNCTION,
                hsm_kmip::QueryFunction::QueryOperations as u32,
            ),
        ],
    );

    let response = operations::query::handle(&request, &client).await.unwrap();
    assert_eq!(response.tag, Tag::RESPONSE_PAYLOAD);

    // Should contain Operation enumerations
    let ops = response.get_all(Tag::OPERATION);
    assert!(
        !ops.is_empty(),
        "Query response should list supported operations"
    );

    // Should contain Create in the list
    let op_values: Vec<u32> = ops
        .iter()
        .filter_map(|t| t.value.as_enumeration())
        .collect();
    assert!(op_values.contains(&(Operation::Create as u32)));
    assert!(op_values.contains(&(Operation::Get as u32)));
    assert!(op_values.contains(&(Operation::Destroy as u32)));
}

// ============================================================================
// 10. TTLV Roundtrip of Complete KMIP-like Messages
// ============================================================================

#[test]
fn ttlv_roundtrip_full_create_request_message() {
    // Build a realistic full KMIP Create request message
    let original = Ttlv::structure(
        Tag::REQUEST_MESSAGE,
        vec![
            Ttlv::structure(
                Tag::REQUEST_HEADER,
                vec![
                    Ttlv::structure(
                        Tag::PROTOCOL_VERSION,
                        vec![
                            Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                            Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
                        ],
                    ),
                    Ttlv::integer(Tag::BATCH_COUNT, 1),
                ],
            ),
            Ttlv::structure(
                Tag::REQUEST_BATCH_ITEM,
                vec![
                    Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
                    Ttlv::enumeration(Tag::OBJECT_TYPE, ObjectType::SymmetricKey as u32),
                    Ttlv::structure(
                        Tag::TEMPLATE_ATTRIBUTE,
                        vec![
                            Ttlv::structure(
                                Tag::ATTRIBUTE,
                                vec![
                                    Ttlv::text_string(
                                        Tag::ATTRIBUTE_NAME,
                                        "Cryptographic Algorithm",
                                    ),
                                    Ttlv::enumeration(
                                        Tag::ATTRIBUTE_VALUE,
                                        CryptographicAlgorithm::Aes as u32,
                                    ),
                                ],
                            ),
                            Ttlv::structure(
                                Tag::ATTRIBUTE,
                                vec![
                                    Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Cryptographic Length"),
                                    Ttlv::integer(Tag::ATTRIBUTE_VALUE, 256),
                                ],
                            ),
                            Ttlv::structure(
                                Tag::ATTRIBUTE,
                                vec![
                                    Ttlv::text_string(Tag::ATTRIBUTE_NAME, "Name"),
                                    Ttlv::text_string(Tag::ATTRIBUTE_VALUE, "production-aes-key"),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    );

    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);

    // Verify we can navigate the decoded structure
    let header = decoded.get(Tag::REQUEST_HEADER).unwrap();
    let version = header.get(Tag::PROTOCOL_VERSION).unwrap();
    let major = version
        .get(Tag::PROTOCOL_VERSION_MAJOR)
        .unwrap()
        .value
        .as_integer()
        .unwrap();
    assert_eq!(major, 1);

    let batch_item = decoded.get(Tag::REQUEST_BATCH_ITEM).unwrap();
    let op = batch_item
        .get(Tag::OPERATION)
        .unwrap()
        .value
        .as_enumeration()
        .unwrap();
    assert_eq!(op, Operation::Create as u32);
}

#[test]
fn ttlv_roundtrip_full_response_message() {
    // Build a realistic KMIP response message
    let original = Ttlv::structure(
        Tag::RESPONSE_MESSAGE,
        vec![
            Ttlv::structure(
                Tag::RESPONSE_HEADER,
                vec![
                    Ttlv::structure(
                        Tag::PROTOCOL_VERSION,
                        vec![
                            Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                            Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
                        ],
                    ),
                    Ttlv::datetime(Tag::TIMESTAMP, 1704067200),
                    Ttlv::integer(Tag::BATCH_COUNT, 1),
                ],
            ),
            Ttlv::structure(
                Tag::RESPONSE_BATCH_ITEM,
                vec![
                    Ttlv::enumeration(Tag::OPERATION, Operation::Create as u32),
                    Ttlv::enumeration(Tag::RESULT_STATUS, hsm_kmip::ResultStatus::Success as u32),
                    Ttlv::structure(
                        Tag::RESPONSE_PAYLOAD,
                        vec![
                            Ttlv::enumeration(Tag::OBJECT_TYPE, ObjectType::SymmetricKey as u32),
                            Ttlv::text_string(Tag::UNIQUE_ID, "key-uuid-12345"),
                        ],
                    ),
                ],
            ),
        ],
    );

    let encoded = TtlvEncoder::encode(&original);
    let decoded = TtlvDecoder::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}
