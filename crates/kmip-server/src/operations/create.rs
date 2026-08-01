//! KMIP Create operation handler
//!
//! Creates a new managed object (typically a symmetric or asymmetric key).

use std::sync::Arc;

use crate::protocol::enums::*;
use crate::server::{Attribute, HsmClient, KmipError};
use crate::ttlv::{Tag, Ttlv};

/// Handle a Create operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload (might be directly in batch item or in a nested payload)
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse object type
    let object_type = payload
        .get(Tag::OBJECT_TYPE)
        .and_then(|t| t.value.as_enumeration())
        .and_then(|v| ObjectType::try_from(v).ok())
        .ok_or_else(|| KmipError::MissingData("Missing or invalid object type".into()))?;

    // Parse template attributes
    let template = payload
        .get(Tag::TEMPLATE_ATTRIBUTE)
        .ok_or_else(|| KmipError::MissingData("Missing template attribute".into()))?;

    let mut algorithm = None;
    let mut length = None;
    let mut usage_mask = CryptographicUsageMask::empty();
    let mut attributes = Vec::new();

    // Parse attributes from template
    for attr in template.get_all(Tag::ATTRIBUTE) {
        let name = attr
            .get(Tag::ATTRIBUTE_NAME)
            .and_then(|n| n.value.as_text_string())
            .map(|s| s.to_string());

        let value = attr.get(Tag::ATTRIBUTE_VALUE);

        if let (Some(name), Some(value)) = (name, value) {
            match name.as_str() {
                "Cryptographic Algorithm" => {
                    if let Some(v) = value.value.as_enumeration() {
                        algorithm = CryptographicAlgorithm::try_from(v).ok();
                    }
                }
                "Cryptographic Length" => {
                    if let Some(v) = value.value.as_integer() {
                        length = Some(v as u32);
                    }
                }
                "Cryptographic Usage Mask" => {
                    if let Some(v) = value.value.as_integer() {
                        usage_mask = CryptographicUsageMask::from_bits_truncate(v as u32);
                    }
                }
                "Name" => {
                    // Handle name attribute
                    if let Some(s) = value.value.as_text_string() {
                        attributes.push(Attribute {
                            name: "Name".to_string(),
                            value: crate::server::AttributeValue::TextString(s.to_string()),
                        });
                    }
                }
                _ => {
                    // Store other attributes for HSM
                }
            }
        }
    }

    // Also check for direct cryptographic algorithm/length tags (KMIP 2.0 style)
    if algorithm.is_none() {
        algorithm = payload
            .get(Tag::CRYPTOGRAPHIC_ALGORITHM)
            .and_then(|t| t.value.as_enumeration())
            .and_then(|v| CryptographicAlgorithm::try_from(v).ok());
    }

    if length.is_none() {
        length = payload
            .get(Tag::CRYPTOGRAPHIC_LENGTH)
            .and_then(|t| t.value.as_integer())
            .map(|v| v as u32);
    }

    // Validate required fields
    let algorithm = algorithm
        .ok_or_else(|| KmipError::MissingData("Missing cryptographic algorithm".into()))?;
    let length =
        length.ok_or_else(|| KmipError::MissingData("Missing cryptographic length".into()))?;

    // Validate object type matches algorithm
    match object_type {
        ObjectType::SymmetricKey => {
            if !matches!(
                algorithm,
                CryptographicAlgorithm::Aes
                    | CryptographicAlgorithm::TripleDes
                    | CryptographicAlgorithm::ChaCha20
                    | CryptographicAlgorithm::Blowfish
                    | CryptographicAlgorithm::Camellia
            ) {
                return Err(KmipError::InvalidAttribute(
                    "Algorithm not valid for symmetric key".into(),
                ));
            }
        }
        ObjectType::PublicKey | ObjectType::PrivateKey
            if !matches!(
                algorithm,
                CryptographicAlgorithm::Rsa
                    | CryptographicAlgorithm::Ecdsa
                    | CryptographicAlgorithm::Ed25519
                    | CryptographicAlgorithm::Ed448
            ) =>
        {
            return Err(KmipError::InvalidAttribute(
                "Algorithm not valid for asymmetric key".into(),
            ));
        }
        _ => {}
    }

    // Create key in HSM
    let unique_id = hsm_client
        .create_key(algorithm, length, usage_mask, &attributes)
        .await?;

    // Build response payload
    Ok(Ttlv::structure(
        Tag::RESPONSE_PAYLOAD,
        vec![
            Ttlv::enumeration(Tag::OBJECT_TYPE, object_type as u32),
            Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_request(algorithm: u32, length: i32) -> Ttlv {
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
                                Ttlv::enumeration(Tag::ATTRIBUTE_VALUE, algorithm),
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

    #[test]
    fn test_parse_create_request() {
        let request = create_request(CryptographicAlgorithm::Aes as u32, 256);

        // Verify structure
        assert_eq!(request.tag, Tag::REQUEST_BATCH_ITEM);

        let object_type = request.get(Tag::OBJECT_TYPE).unwrap();
        assert_eq!(
            object_type.value.as_enumeration(),
            Some(ObjectType::SymmetricKey as u32)
        );

        let template = request.get(Tag::TEMPLATE_ATTRIBUTE).unwrap();
        assert_eq!(template.get_all(Tag::ATTRIBUTE).len(), 2);
    }
}
