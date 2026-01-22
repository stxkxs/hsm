//! KMIP Decrypt operation handler
//!
//! Decrypts data using a specified key.

use std::sync::Arc;

use crate::protocol::enums::*;
use crate::server::{CryptoParams, HsmClient, KmipError};
use crate::ttlv::{Tag, Ttlv};

/// Handle a Decrypt operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse unique ID
    let unique_id = payload
        .get(Tag::UNIQUE_ID)
        .and_then(|t| t.value.as_text_string())
        .ok_or_else(|| KmipError::MissingData("Missing unique ID".into()))?;

    // Parse data to decrypt
    let data = payload
        .get(Tag::DATA)
        .and_then(|t| t.value.as_byte_string())
        .ok_or_else(|| KmipError::MissingData("Missing data to decrypt".into()))?;

    // Parse optional IV/nonce
    let iv = payload
        .get(Tag::IV_COUNTER_NONCE)
        .and_then(|t| t.value.as_byte_string());

    // Parse optional cryptographic parameters
    let params = parse_crypto_params(payload);

    // Decrypt data
    let plaintext = hsm_client.decrypt(unique_id, data, iv, params).await?;

    // Build response payload
    Ok(Ttlv::structure(
        Tag::RESPONSE_PAYLOAD,
        vec![
            Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
            Ttlv::byte_string(Tag::DATA, plaintext),
        ],
    ))
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

    fn create_decrypt_request(unique_id: &str, data: &[u8], iv: Option<&[u8]>) -> Ttlv {
        let mut items = vec![
            Ttlv::enumeration(Tag::OPERATION, Operation::Decrypt as u32),
            Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
            Ttlv::byte_string(Tag::DATA, data.to_vec()),
        ];

        if let Some(iv_data) = iv {
            items.push(Ttlv::byte_string(Tag::IV_COUNTER_NONCE, iv_data.to_vec()));
        }

        Ttlv::structure(Tag::REQUEST_BATCH_ITEM, items)
    }

    #[test]
    fn test_parse_decrypt_request() {
        let ciphertext = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let iv = vec![0x00, 0x01, 0x02, 0x03];
        let request = create_decrypt_request("decryption-key", &ciphertext, Some(&iv));

        let unique_id = request
            .get(Tag::UNIQUE_ID)
            .and_then(|t| t.value.as_text_string());
        assert_eq!(unique_id, Some("decryption-key"));

        let data = request
            .get(Tag::DATA)
            .and_then(|t| t.value.as_byte_string());
        assert_eq!(data, Some(ciphertext.as_slice()));

        let parsed_iv = request
            .get(Tag::IV_COUNTER_NONCE)
            .and_then(|t| t.value.as_byte_string());
        assert_eq!(parsed_iv, Some(iv.as_slice()));
    }
}
