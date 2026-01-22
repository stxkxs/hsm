//! KMIP Sign operation handler
//!
//! Signs data using a specified private key.

use std::sync::Arc;

use crate::protocol::enums::*;
use crate::server::{CryptoParams, HsmClient, KmipError};
use crate::ttlv::{Tag, Ttlv};

/// Handle a Sign operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse unique ID
    let unique_id = payload
        .get(Tag::UNIQUE_ID)
        .and_then(|t| t.value.as_text_string())
        .ok_or_else(|| KmipError::MissingData("Missing unique ID".into()))?;

    // Parse data to sign
    let data = payload
        .get(Tag::DATA)
        .and_then(|t| t.value.as_byte_string())
        .ok_or_else(|| KmipError::MissingData("Missing data to sign".into()))?;

    // Parse optional cryptographic parameters
    let params = parse_crypto_params(payload);

    // Sign data
    let signature = hsm_client.sign(unique_id, data, params).await?;

    // Build response payload
    Ok(Ttlv::structure(
        Tag::RESPONSE_PAYLOAD,
        vec![
            Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
            Ttlv::byte_string(Tag::SIGNATURE_DATA, signature),
        ],
    ))
}

/// Parse cryptographic parameters from request
fn parse_crypto_params(payload: &Ttlv) -> Option<CryptoParams> {
    let params_struct = payload.get(Tag::CRYPTOGRAPHIC_PARAMETERS)?;

    let padding_method = params_struct
        .get(Tag::PADDING_METHOD)
        .and_then(|t| t.value.as_enumeration())
        .and_then(|v| PaddingMethod::try_from(v).ok());

    let hashing_algorithm = params_struct
        .get(Tag::HASHING_ALGORITHM)
        .and_then(|t| t.value.as_enumeration())
        .and_then(|v| HashingAlgorithm::try_from(v).ok());

    Some(CryptoParams {
        block_cipher_mode: None,
        padding_method,
        hashing_algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_sign_request(unique_id: &str, data: &[u8]) -> Ttlv {
        Ttlv::structure(
            Tag::REQUEST_BATCH_ITEM,
            vec![
                Ttlv::enumeration(Tag::OPERATION, Operation::Sign as u32),
                Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
                Ttlv::byte_string(Tag::DATA, data.to_vec()),
            ],
        )
    }

    #[test]
    fn test_parse_sign_request() {
        let message = b"message to sign";
        let request = create_sign_request("signing-key", message);

        let unique_id = request
            .get(Tag::UNIQUE_ID)
            .and_then(|t| t.value.as_text_string());
        assert_eq!(unique_id, Some("signing-key"));

        let data = request
            .get(Tag::DATA)
            .and_then(|t| t.value.as_byte_string());
        assert_eq!(data, Some(message.as_slice()));
    }
}
