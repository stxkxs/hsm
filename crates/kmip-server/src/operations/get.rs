//! KMIP Get operation handler
//!
//! Retrieves a managed object (key material and/or attributes).

use std::sync::Arc;

use crate::protocol::enums::*;
use crate::server::{HsmClient, KmipError};
use crate::ttlv::{Tag, Ttlv};

/// Handle a Get operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse unique ID
    let unique_id = payload
        .get(Tag::UNIQUE_ID)
        .and_then(|t| t.value.as_text_string())
        .ok_or_else(|| KmipError::MissingData("Missing unique ID".into()))?;

    // Get key from HSM
    let key_info = hsm_client.get_key(unique_id).await?;

    // Build key block
    let mut key_block_items = vec![Ttlv::enumeration(
        Tag::KEY_FORMAT_TYPE,
        KeyFormatType::Raw as u32,
    )];

    // Add key value if material is available
    if let Some(material) = &key_info.key_material {
        key_block_items.push(Ttlv::structure(
            Tag::KEY_VALUE,
            vec![Ttlv::byte_string(Tag::KEY_MATERIAL, material.clone())],
        ));
    }

    key_block_items.push(Ttlv::enumeration(
        Tag::CRYPTOGRAPHIC_ALGORITHM,
        key_info.algorithm as u32,
    ));
    key_block_items.push(Ttlv::integer(
        Tag::CRYPTOGRAPHIC_LENGTH,
        key_info.length as i32,
    ));

    let key_block = Ttlv::structure(Tag::KEY_BLOCK, key_block_items);

    // Build response payload
    Ok(Ttlv::structure(
        Tag::RESPONSE_PAYLOAD,
        vec![
            Ttlv::enumeration(Tag::OBJECT_TYPE, key_info.object_type as u32),
            Ttlv::text_string(Tag::UNIQUE_ID, &key_info.unique_id),
            key_block,
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_get_request(unique_id: &str) -> Ttlv {
        Ttlv::structure(
            Tag::REQUEST_BATCH_ITEM,
            vec![
                Ttlv::enumeration(Tag::OPERATION, Operation::Get as u32),
                Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
            ],
        )
    }

    #[test]
    fn test_parse_get_request() {
        let request = create_get_request("test-key-123");

        let unique_id = request
            .get(Tag::UNIQUE_ID)
            .and_then(|t| t.value.as_text_string());
        assert_eq!(unique_id, Some("test-key-123"));
    }
}
