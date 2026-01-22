//! KMIP Destroy operation handler
//!
//! Destroys a managed object, permanently removing it from the HSM.

use std::sync::Arc;

use crate::server::{HsmClient, KmipError};
use crate::ttlv::{Tag, Ttlv};

#[cfg(test)]
use crate::protocol::enums::Operation;

/// Handle a Destroy operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse unique ID
    let unique_id = payload
        .get(Tag::UNIQUE_ID)
        .and_then(|t| t.value.as_text_string())
        .ok_or_else(|| KmipError::MissingData("Missing unique ID".into()))?;

    // Destroy key in HSM
    hsm_client.destroy_key(unique_id).await?;

    // Build response payload
    Ok(Ttlv::structure(
        Tag::RESPONSE_PAYLOAD,
        vec![Ttlv::text_string(Tag::UNIQUE_ID, unique_id)],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_destroy_request(unique_id: &str) -> Ttlv {
        Ttlv::structure(
            Tag::REQUEST_BATCH_ITEM,
            vec![
                Ttlv::enumeration(Tag::OPERATION, Operation::Destroy as u32),
                Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
            ],
        )
    }

    #[test]
    fn test_parse_destroy_request() {
        let request = create_destroy_request("key-to-destroy");

        let unique_id = request
            .get(Tag::UNIQUE_ID)
            .and_then(|t| t.value.as_text_string());
        assert_eq!(unique_id, Some("key-to-destroy"));
    }
}
