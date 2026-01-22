//! KMIP Revoke operation handler
//!
//! Revokes a managed object, marking it as compromised or otherwise unusable.

use std::sync::Arc;

use crate::protocol::enums::*;
use crate::server::{HsmClient, KmipError, RevocationReason};
use crate::ttlv::{Tag, Ttlv};

/// Handle a Revoke operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse unique ID
    let unique_id = payload
        .get(Tag::UNIQUE_ID)
        .and_then(|t| t.value.as_text_string())
        .ok_or_else(|| KmipError::MissingData("Missing unique ID".into()))?;

    // Parse revocation reason
    let revocation_reason = payload.get(Tag::REVOCATION_REASON);

    let reason = if let Some(reason_struct) = revocation_reason {
        let code = reason_struct
            .get(Tag::REVOCATION_REASON_CODE)
            .and_then(|t| t.value.as_enumeration())
            .and_then(|v| RevocationReasonCode::try_from(v).ok())
            .unwrap_or(RevocationReasonCode::Unspecified);

        let message = reason_struct
            .get(Tag::REVOCATION_MESSAGE)
            .and_then(|t| t.value.as_text_string())
            .map(|s| s.to_string());

        RevocationReason { code, message }
    } else {
        RevocationReason {
            code: RevocationReasonCode::Unspecified,
            message: None,
        }
    };

    // Revoke key in HSM
    hsm_client.revoke_key(unique_id, reason).await?;

    // Build response payload
    Ok(Ttlv::structure(
        Tag::RESPONSE_PAYLOAD,
        vec![Ttlv::text_string(Tag::UNIQUE_ID, unique_id)],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_revoke_request(unique_id: &str, reason_code: RevocationReasonCode) -> Ttlv {
        Ttlv::structure(
            Tag::REQUEST_BATCH_ITEM,
            vec![
                Ttlv::enumeration(Tag::OPERATION, Operation::Revoke as u32),
                Ttlv::text_string(Tag::UNIQUE_ID, unique_id),
                Ttlv::structure(
                    Tag::REVOCATION_REASON,
                    vec![Ttlv::enumeration(
                        Tag::REVOCATION_REASON_CODE,
                        reason_code as u32,
                    )],
                ),
            ],
        )
    }

    #[test]
    fn test_parse_revoke_request() {
        let request = create_revoke_request("key-to-revoke", RevocationReasonCode::KeyCompromise);

        let unique_id = request
            .get(Tag::UNIQUE_ID)
            .and_then(|t| t.value.as_text_string());
        assert_eq!(unique_id, Some("key-to-revoke"));

        let reason = request.get(Tag::REVOCATION_REASON).unwrap();
        let code = reason
            .get(Tag::REVOCATION_REASON_CODE)
            .and_then(|t| t.value.as_enumeration());
        assert_eq!(code, Some(RevocationReasonCode::KeyCompromise as u32));
    }
}
