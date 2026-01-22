//! TTLV Decoder
//!
//! Decodes the binary TTLV wire format into Ttlv structures.
//!
//! The wire format for each TTLV item is:
//! - Tag: 3 bytes (big-endian)
//! - Type: 1 byte
//! - Length: 4 bytes (big-endian)
//! - Value: variable length (padded to 8-byte boundary for most types)

use bytes::{Buf, Bytes};

use super::types::{Tag, Ttlv, TtlvError, TtlvType, TtlvValue};

/// TTLV Decoder for parsing bytes into Ttlv structures
pub struct TtlvDecoder;

impl TtlvDecoder {
    /// Decode bytes to a TTLV item
    pub fn decode(data: &[u8]) -> Result<Ttlv, TtlvError> {
        let mut bytes = Bytes::copy_from_slice(data);
        Self::decode_item(&mut bytes)
    }

    /// Decode from a Bytes buffer (consumes bytes as it decodes)
    pub fn decode_from_bytes(bytes: &mut Bytes) -> Result<Ttlv, TtlvError> {
        Self::decode_item(bytes)
    }

    fn decode_item(buf: &mut Bytes) -> Result<Ttlv, TtlvError> {
        // Need at least 8 bytes for header (tag + type + length)
        if buf.remaining() < 8 {
            return Err(TtlvError::UnexpectedEof);
        }

        // Tag (3 bytes, big-endian)
        let tag = Tag(((buf.get_u8() as u32) << 16)
            | ((buf.get_u8() as u32) << 8)
            | (buf.get_u8() as u32));

        // Type (1 byte)
        let ttlv_type = TtlvType::try_from(buf.get_u8())?;

        // Length (4 bytes, big-endian)
        let length = buf.get_u32() as usize;

        // Check we have enough data for the value
        let padded_length = Self::padded_length(ttlv_type, length);
        if buf.remaining() < padded_length {
            return Err(TtlvError::UnexpectedEof);
        }

        let value = match ttlv_type {
            TtlvType::Structure => {
                // Structure contains nested TTLV items
                let mut structure_bytes = buf.copy_to_bytes(length);
                let mut items = Vec::new();
                while structure_bytes.has_remaining() {
                    items.push(Self::decode_item(&mut structure_bytes)?);
                }
                TtlvValue::Structure(items)
            }

            TtlvType::Integer => {
                let value = buf.get_i32();
                buf.advance(4); // Skip 4 bytes padding
                TtlvValue::Integer(value)
            }

            TtlvType::LongInteger => TtlvValue::LongInteger(buf.get_i64()),

            TtlvType::BigInteger => {
                let value = buf.copy_to_bytes(length).to_vec();
                Self::skip_padding(buf, length);
                TtlvValue::BigInteger(value)
            }

            TtlvType::Enumeration => {
                let value = buf.get_u32();
                buf.advance(4); // Skip 4 bytes padding
                TtlvValue::Enumeration(value)
            }

            TtlvType::Boolean => {
                let value = buf.get_u64() != 0;
                TtlvValue::Boolean(value)
            }

            TtlvType::TextString => {
                let bytes = buf.copy_to_bytes(length);
                let value =
                    String::from_utf8(bytes.to_vec()).map_err(|_| TtlvError::InvalidUtf8)?;
                Self::skip_padding(buf, length);
                TtlvValue::TextString(value)
            }

            TtlvType::ByteString => {
                let value = buf.copy_to_bytes(length).to_vec();
                Self::skip_padding(buf, length);
                TtlvValue::ByteString(value)
            }

            TtlvType::DateTime => TtlvValue::DateTime(buf.get_i64()),

            TtlvType::Interval => {
                let value = buf.get_u32();
                buf.advance(4); // Skip 4 bytes padding
                TtlvValue::Interval(value)
            }
        };

        Ok(Ttlv { tag, value })
    }

    /// Calculate the padded length for a value based on its type
    fn padded_length(ttlv_type: TtlvType, length: usize) -> usize {
        match ttlv_type {
            // These types have fixed sizes and include padding in the value
            TtlvType::Integer | TtlvType::Enumeration | TtlvType::Interval => 8,
            TtlvType::LongInteger | TtlvType::DateTime | TtlvType::Boolean => 8,
            // Structure is not padded
            TtlvType::Structure => length,
            // Variable-length types are padded to 8-byte boundary
            TtlvType::BigInteger | TtlvType::TextString | TtlvType::ByteString => {
                let padding = (8 - (length % 8)) % 8;
                length + padding
            }
        }
    }

    /// Skip padding bytes to align to 8-byte boundary
    fn skip_padding(buf: &mut Bytes, length: usize) {
        let padding = (8 - (length % 8)) % 8;
        if padding > 0 && buf.remaining() >= padding {
            buf.advance(padding);
        }
    }
}

/// Helper to peek at the length of a TTLV message without decoding
///
/// This is primarily useful for reading KMIP request/response messages,
/// which are always Structure types. For structures, the length field
/// contains the exact byte count of the nested content (no padding).
///
/// For other TTLV types, padding may apply - use with caution for non-structure types.
pub fn peek_message_length(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    Some(8 + length) // header + value (for structures, this is exact; others may have padding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ttlv::encoder::TtlvEncoder;

    #[test]
    fn test_decode_integer() {
        let item = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 42);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.tag, Tag::PROTOCOL_VERSION_MAJOR);
        assert_eq!(decoded.value.as_integer(), Some(42));
    }

    #[test]
    fn test_decode_negative_integer() {
        let item = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, -123);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.value.as_integer(), Some(-123));
    }

    #[test]
    fn test_decode_long_integer() {
        let item = Ttlv::long_integer(Tag::TIMESTAMP, 0x0102030405060708i64);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.value.as_long_integer(), Some(0x0102030405060708i64));
    }

    #[test]
    fn test_decode_enumeration() {
        let item = Ttlv::enumeration(Tag::OPERATION, 0x00000001);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.tag, Tag::OPERATION);
        assert_eq!(decoded.value.as_enumeration(), Some(0x00000001));
    }

    #[test]
    fn test_decode_boolean_true() {
        let item = Ttlv::boolean(Tag::ATTRIBUTE_VALUE, true);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.value.as_boolean(), Some(true));
    }

    #[test]
    fn test_decode_boolean_false() {
        let item = Ttlv::boolean(Tag::ATTRIBUTE_VALUE, false);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.value.as_boolean(), Some(false));
    }

    #[test]
    fn test_decode_text_string() {
        let item = Ttlv::text_string(Tag::UNIQUE_ID, "test-key-123");
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.tag, Tag::UNIQUE_ID);
        assert_eq!(decoded.value.as_text_string(), Some("test-key-123"));
    }

    #[test]
    fn test_decode_text_string_exact_8() {
        let item = Ttlv::text_string(Tag::UNIQUE_ID, "12345678");
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.value.as_text_string(), Some("12345678"));
    }

    #[test]
    fn test_decode_byte_string() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let item = Ttlv::byte_string(Tag::DATA, data.clone());
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.tag, Tag::DATA);
        assert_eq!(decoded.value.as_byte_string(), Some(data.as_slice()));
    }

    #[test]
    fn test_decode_datetime() {
        let timestamp = 1704067200i64; // 2024-01-01 00:00:00 UTC
        let item = Ttlv::datetime(Tag::TIMESTAMP, timestamp);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        if let TtlvValue::DateTime(v) = decoded.value {
            assert_eq!(v, timestamp);
        } else {
            panic!("Expected DateTime value");
        }
    }

    #[test]
    fn test_decode_interval() {
        let item = Ttlv::interval(Tag::ATTRIBUTE_VALUE, 3600);
        let encoded = TtlvEncoder::encode(&item);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        if let TtlvValue::Interval(v) = decoded.value {
            assert_eq!(v, 3600);
        } else {
            panic!("Expected Interval value");
        }
    }

    #[test]
    fn test_decode_structure() {
        let structure = Ttlv::structure(
            Tag::PROTOCOL_VERSION,
            vec![
                Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
            ],
        );
        let encoded = TtlvEncoder::encode(&structure);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.tag, Tag::PROTOCOL_VERSION);
        assert!(decoded.is_structure());

        let major = decoded.get(Tag::PROTOCOL_VERSION_MAJOR).unwrap();
        assert_eq!(major.value.as_integer(), Some(1));

        let minor = decoded.get(Tag::PROTOCOL_VERSION_MINOR).unwrap();
        assert_eq!(minor.value.as_integer(), Some(4));
    }

    #[test]
    fn test_decode_nested_structure() {
        let message = Ttlv::structure(
            Tag::REQUEST_MESSAGE,
            vec![Ttlv::structure(
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
            )],
        );

        let encoded = TtlvEncoder::encode(&message);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(decoded.tag, Tag::REQUEST_MESSAGE);

        let header = decoded.get(Tag::REQUEST_HEADER).unwrap();
        let version = header.get(Tag::PROTOCOL_VERSION).unwrap();
        let major = version.get(Tag::PROTOCOL_VERSION_MAJOR).unwrap();
        assert_eq!(major.value.as_integer(), Some(1));
    }

    #[test]
    fn test_roundtrip_complex_message() {
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
                        Ttlv::enumeration(Tag::OPERATION, 0x01), // Create
                        Ttlv::text_string(Tag::UNIQUE_ID, "test-key-uuid"),
                        Ttlv::byte_string(Tag::DATA, vec![1, 2, 3, 4, 5]),
                    ],
                ),
            ],
        );

        let encoded = TtlvEncoder::encode(&original);
        let decoded = TtlvDecoder::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_decode_error_unexpected_eof() {
        let data = vec![0x42, 0x00, 0x78]; // Incomplete header
        let result = TtlvDecoder::decode(&data);
        assert!(matches!(result, Err(TtlvError::UnexpectedEof)));
    }

    #[test]
    fn test_decode_error_invalid_type() {
        // Valid header with invalid type byte (0xFF)
        let data = vec![
            0x42, 0x00, 0x78, // Tag
            0xFF, // Invalid type
            0x00, 0x00, 0x00, 0x08, // Length
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Value
        ];
        let result = TtlvDecoder::decode(&data);
        assert!(matches!(result, Err(TtlvError::InvalidType(0xFF))));
    }

    #[test]
    fn test_peek_message_length() {
        // For structures (like KMIP messages), peek_message_length gives exact total
        let structure = Ttlv::structure(
            Tag::REQUEST_MESSAGE,
            vec![Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1)],
        );
        let encoded = TtlvEncoder::encode(&structure);
        let length = peek_message_length(&encoded).unwrap();
        assert_eq!(length, encoded.len()); // Should match exactly for structures

        // For non-structure types, the length field is the value length, not including padding
        let item = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1);
        let encoded_int = TtlvEncoder::encode(&item);
        let peeked = peek_message_length(&encoded_int).unwrap();
        assert_eq!(peeked, 12); // 8 header + 4 (length field value, not padded)
        assert_eq!(encoded_int.len(), 16); // actual is 8 header + 4 int + 4 padding

        // Too short
        assert!(peek_message_length(&[0x42, 0x00]).is_none());
    }
}
