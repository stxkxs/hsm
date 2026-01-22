//! KMIP Query operation handler
//!
//! Queries the server for supported operations, object types, and other information.

use std::sync::Arc;

use crate::protocol::enums::*;
use crate::server::{HsmClient, KmipError};
use crate::ttlv::{Tag, Ttlv};

/// Handle a Query operation request
pub async fn handle(request: &Ttlv, hsm_client: &Arc<dyn HsmClient>) -> Result<Ttlv, KmipError> {
    // Get request payload
    let payload = request.get(Tag::REQUEST_PAYLOAD).unwrap_or(request);

    // Parse query functions
    let query_functions: Vec<QueryFunction> = payload
        .get_all(Tag::QUERY_FUNCTION)
        .iter()
        .filter_map(|t| t.value.as_enumeration())
        .filter_map(|v| QueryFunction::try_from(v).ok())
        .collect();

    let mut response_items = Vec::new();

    for func in &query_functions {
        match func {
            QueryFunction::QueryOperations => {
                let server_info = hsm_client.server_info();
                for op in &server_info.supported_operations {
                    response_items.push(Ttlv::enumeration(Tag::OPERATION, *op as u32));
                }
            }
            QueryFunction::QueryObjects => {
                // Return supported object types
                response_items.push(Ttlv::enumeration(
                    Tag::OBJECT_TYPE,
                    ObjectType::SymmetricKey as u32,
                ));
                response_items.push(Ttlv::enumeration(
                    Tag::OBJECT_TYPE,
                    ObjectType::PublicKey as u32,
                ));
                response_items.push(Ttlv::enumeration(
                    Tag::OBJECT_TYPE,
                    ObjectType::PrivateKey as u32,
                ));
            }
            QueryFunction::QueryServerInformation => {
                let server_info = hsm_client.server_info();
                response_items.push(Ttlv::structure(
                    Tag::SERVER_INFORMATION,
                    vec![
                        Ttlv::text_string(Tag::ATTRIBUTE_VALUE, &server_info.vendor),
                        Ttlv::text_string(Tag::ATTRIBUTE_VALUE, &server_info.server_name),
                        Ttlv::text_string(Tag::ATTRIBUTE_VALUE, &server_info.server_version),
                    ],
                ));
            }
            _ => {
                // Other query functions not yet supported
            }
        }
    }

    // If no specific query functions, return default info
    if query_functions.is_empty() {
        let server_info = hsm_client.server_info();
        for op in &server_info.supported_operations {
            response_items.push(Ttlv::enumeration(Tag::OPERATION, *op as u32));
        }
    }

    Ok(Ttlv::structure(Tag::RESPONSE_PAYLOAD, response_items))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_query_request(functions: &[QueryFunction]) -> Ttlv {
        let mut items = vec![Ttlv::enumeration(Tag::OPERATION, Operation::Query as u32)];

        for func in functions {
            items.push(Ttlv::enumeration(Tag::QUERY_FUNCTION, *func as u32));
        }

        Ttlv::structure(Tag::REQUEST_BATCH_ITEM, items)
    }

    #[test]
    fn test_parse_query_request() {
        let request = create_query_request(&[
            QueryFunction::QueryOperations,
            QueryFunction::QueryServerInformation,
        ]);

        let functions: Vec<_> = request
            .get_all(Tag::QUERY_FUNCTION)
            .iter()
            .filter_map(|t| t.value.as_enumeration())
            .collect();

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0], QueryFunction::QueryOperations as u32);
        assert_eq!(functions[1], QueryFunction::QueryServerInformation as u32);
    }
}
