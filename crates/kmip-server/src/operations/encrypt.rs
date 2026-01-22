//! KMIP Encrypt operation handler
//!
//! Encrypts data using a specified key.

use std::sync::Arc;

use crate::protocol::enums::*;
use crate::server::{CryptoParams, HsmClient, KmipError};
use crate::ttlv::{Tag, Ttlv};

/// Handle an Encrypt operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse unique ID
    let unique_id = payload
        .get(Tag::UNIQUE_ID)
        .and_then(|t| t.value.as_text_string())
        .ok_or_else(|| KmipError::MissingData("Missing unique ID".into()))?;

    // Parse data to encrypt
    let data = payload
        .get(Tag::DATA)
        .and_then(|t| t.value.as_byte_string())
        .ok_or_else(|| KmipError::MissingData("Missing data to encrypt".into()))?;

    // Parse optional IV/nonce
    let iv = payload
        .get(Tag::IV_COUNTER_NONCE)
        .and_then(|t| t.value.as_byte_string());

    // Parse optional cryptographic parameters
    let params = parse_crypto_params(payload);

    // Encrypt data
    let result = hsm_client.encrypt(unique_id, data, iv, params).await?;

    // Build response payload
    let mut response_items = vec![
        Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
        Ttlv::byte_string(Tag::DATA, result.data),
    ];

    if let Some(iv) = result.iv {
        response_items.push(Ttlv::byte_string(Tag::IV_COUNTER_NONCE, iv));
    }

    Ok(Ttlv::structure(Tag::RESPONSE_PAYLOAD, response_items))
}

/// Parse cryptographic parameters from request
fn parse_crypto_params(payload: &Ttlv) -> Option<CryptoParams> {
    let params_struct = payload.get(Tag::CRYPTOGRAPHIC_PARAMETERS)?;

    let block_cipher_mode = params_struct
        .get(Tag::BLOCK_CIPHER_MODE)
        .and_then(|t| t.value.as_enumeration())
        .and_then(|v| BlockCipherMode::try_from(v).ok());

    let padding_method = params_struct
        .get(Tag::PADDING_METHOD)
        .and_then(|t| t.value.as_enumeration())
        .and_then(|v| PaddingMethod::try_from(v).ok());

    let hashing_algorithm = params_struct
        .get(Tag::HASHING_ALGORITHM)
        .and_then(|t| t.value.as_enumeration())
        .and_then(|v| HashingAlgorithm::try_from(v).ok());

    Some(CryptoParams {
        block_cipher_mode,
        padding_method,
        hashing_algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_encrypt_request(unique_id: &str, data: &[u8]) -> Ttlv {
        Ttlv::structure(
            Tag::REQUEST_BATCH_ITEM,
            vec![
                Ttlv::enumeration(Tag::OPERATION, Operation::Encrypt as u32),
                Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
                Ttlv::byte_string(Tag::DATA, data.to_vec()),
            ],
        )
    }

    #[test]
    fn test_parse_encrypt_request() {
        let request = create_encrypt_request("encryption-key", b"plaintext data");

        let unique_id = request
            .get(Tag::UNIQUE_ID)
            .and_then(|t| t.value.as_text_string());
        assert_eq!(unique_id, Some("encryption-key"));

        let data = request
            .get(Tag::DATA)
            .and_then(|t| t.value.as_byte_string());
        assert_eq!(data, Some(b"plaintext data".as_slice()));
    }
}
