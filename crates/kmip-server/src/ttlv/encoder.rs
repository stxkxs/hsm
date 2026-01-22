//! TTLV Encoder
//!
//! Encodes TTLV data structures into the binary wire format defined by KMIP.
//!
//! The wire format for each TTLV item is:
//! - Tag: 3 bytes (big-endian)
//! - Type: 1 byte
//! - Length: 4 bytes (big-endian)
//! - Value: variable length (padded to 8-byte boundary for most types)

use bytes::{BufMut, BytesMut};

use super::types::{Ttlv, TtlvType, TtlvValue};

/// TTLV Encoder for converting Ttlv structures to bytes
pub struct TtlvEncoder;

impl TtlvEncoder {
    /// Encode a TTLV item to bytes
    pub fn encode(item: &Ttlv) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(256);
        Self::encode_item(&mut buf, item);
        buf.to_vec()
    }

    /// Encode a TTLV item into an existing buffer
    pub fn encode_into(buf: &mut BytesMut, item: &Ttlv) {
        Self::encode_item(buf, item);
    }

    fn encode_item(buf: &mut BytesMut, item: &Ttlv) {
        // Tag (3 bytes, big-endian)
        buf.put_u8((item.tag.0 >> 16) as u8);
        buf.put_u8((item.tag.0 >> 8) as u8);
        buf.put_u8(item.tag.0 as u8);

        // Type (1 byte) and value encoding
        match &item.value {
            TtlvValue::Structure(items) => {
                buf.put_u8(TtlvType::Structure as u8);

                // Encode children to temporary buffer to calculate length
                let mut child_buf = BytesMut::new();
                for child in items {
                    Self::encode_item(&mut child_buf, child);
                }

                // Length (4 bytes)
                buf.put_u32(child_buf.len() as u32);

                // Value (children) - structures are NOT padded
                buf.extend_from_slice(&child_buf);
            }

            TtlvValue::Integer(v) => {
                buf.put_u8(TtlvType::Integer as u8);
                buf.put_u32(4); // Length is always 4 for integer
                buf.put_i32(*v);
                buf.put_u32(0); // Padding to 8 bytes
            }

            TtlvValue::LongInteger(v) => {
                buf.put_u8(TtlvType::LongInteger as u8);
                buf.put_u32(8); // Length is always 8 for long integer
                buf.put_i64(*v);
            }

            TtlvValue::BigInteger(v) => {
                buf.put_u8(TtlvType::BigInteger as u8);
                buf.put_u32(v.len() as u32);
                buf.extend_from_slice(v);
                Self::pad_to_8(buf, v.len());
            }

            TtlvValue::Enumeration(v) => {
                buf.put_u8(TtlvType::Enumeration as u8);
                buf.put_u32(4); // Length is always 4 for enumeration
                buf.put_u32(*v);
                buf.put_u32(0); // Padding to 8 bytes
            }

            TtlvValue::Boolean(v) => {
                buf.put_u8(TtlvType::Boolean as u8);
                buf.put_u32(8); // Length is always 8 for boolean
                buf.put_u64(if *v { 1 } else { 0 });
            }

            TtlvValue::TextString(v) => {
                buf.put_u8(TtlvType::TextString as u8);
                let bytes = v.as_bytes();
                buf.put_u32(bytes.len() as u32);
                buf.extend_from_slice(bytes);
                Self::pad_to_8(buf, bytes.len());
            }

            TtlvValue::ByteString(v) => {
                buf.put_u8(TtlvType::ByteString as u8);
                buf.put_u32(v.len() as u32);
                buf.extend_from_slice(v);
                Self::pad_to_8(buf, v.len());
            }

            TtlvValue::DateTime(v) => {
                buf.put_u8(TtlvType::DateTime as u8);
                buf.put_u32(8); // Length is always 8 for datetime
                buf.put_i64(*v);
            }

            TtlvValue::Interval(v) => {
                buf.put_u8(TtlvType::Interval as u8);
                buf.put_u32(4); // Length is always 4 for interval
                buf.put_u32(*v);
                buf.put_u32(0); // Padding to 8 bytes
            }
        }
    }

    /// Add padding bytes to align to 8-byte boundary
    fn pad_to_8(buf: &mut BytesMut, len: usize) {
        let padding = (8 - (len % 8)) % 8;
        for _ in 0..padding {
            buf.put_u8(0);
        }
    }
}

/// Calculate the encoded size of a TTLV item without actually encoding
pub fn encoded_size(item: &Ttlv) -> usize {
    // Header: 3 (tag) + 1 (type) + 4 (length) = 8 bytes
    let header_size = 8;

    let value_size = match &item.value {
        TtlvValue::Structure(items) => items.iter().map(encoded_size).sum(),
        TtlvValue::Integer(_) => 8, // 4 + 4 padding
        TtlvValue::LongInteger(_) => 8,
        TtlvValue::BigInteger(v) => padded_len(v.len()),
        TtlvValue::Enumeration(_) => 8, // 4 + 4 padding
        TtlvValue::Boolean(_) => 8,
        TtlvValue::TextString(v) => padded_len(v.len()),
        TtlvValue::ByteString(v) => padded_len(v.len()),
        TtlvValue::DateTime(_) => 8,
        TtlvValue::Interval(_) => 8, // 4 + 4 padding
    };

    header_size + value_size
}

/// Calculate length with padding to 8-byte boundary
fn padded_len(len: usize) -> usize {
    let padding = (8 - (len % 8)) % 8;
    len + padding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ttlv::types::Tag;

    #[test]
    fn test_encode_integer() {
        let item = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1);
        let encoded = TtlvEncoder::encode(&item);

        // Tag: 0x42006A (3 bytes)
        assert_eq!(encoded[0], 0x42);
        assert_eq!(encoded[1], 0x00);
        assert_eq!(encoded[2], 0x6A);

        // Type: Integer (0x02)
        assert_eq!(encoded[3], 0x02);

        // Length: 4 (4 bytes big-endian)
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x04]);

        // Value: 1 (4 bytes big-endian)
        assert_eq!(&encoded[8..12], &[0x00, 0x00, 0x00, 0x01]);

        // Padding: 4 bytes
        assert_eq!(&encoded[12..16], &[0x00, 0x00, 0x00, 0x00]);

        // Total: 16 bytes
        assert_eq!(encoded.len(), 16);
    }

    #[test]
    fn test_encode_enumeration() {
        let item = Ttlv::enumeration(Tag::OPERATION, 0x00000001); // Create operation
        let encoded = TtlvEncoder::encode(&item);

        // Type: Enumeration (0x05)
        assert_eq!(encoded[3], 0x05);

        // Length: 4
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x04]);

        // Total: 16 bytes (header + 4 value + 4 padding)
        assert_eq!(encoded.len(), 16);
    }

    #[test]
    fn test_encode_text_string() {
        let item = Ttlv::text_string(Tag::UNIQUE_ID, "test");
        let encoded = TtlvEncoder::encode(&item);

        // Type: TextString (0x07)
        assert_eq!(encoded[3], 0x07);

        // Length: 4
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x04]);

        // Value: "test"
        assert_eq!(&encoded[8..12], b"test");

        // Padding: 4 bytes
        assert_eq!(&encoded[12..16], &[0x00, 0x00, 0x00, 0x00]);

        assert_eq!(encoded.len(), 16);
    }

    #[test]
    fn test_encode_text_string_exact_8() {
        let item = Ttlv::text_string(Tag::UNIQUE_ID, "12345678");
        let encoded = TtlvEncoder::encode(&item);

        // Length: 8
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x08]);

        // No padding needed for 8-byte string
        assert_eq!(encoded.len(), 16); // 8 header + 8 value
    }

    #[test]
    fn test_encode_byte_string() {
        let item = Ttlv::byte_string(Tag::DATA, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = TtlvEncoder::encode(&item);

        // Type: ByteString (0x08)
        assert_eq!(encoded[3], 0x08);

        // Length: 4
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x04]);

        // Value
        assert_eq!(&encoded[8..12], &[0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(encoded.len(), 16);
    }

    #[test]
    fn test_encode_boolean() {
        let item_true = Ttlv::boolean(Tag::ATTRIBUTE_VALUE, true);
        let encoded = TtlvEncoder::encode(&item_true);

        // Type: Boolean (0x06)
        assert_eq!(encoded[3], 0x06);

        // Length: 8
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x08]);

        // Value: 1 (as 8 bytes)
        assert_eq!(
            &encoded[8..16],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn test_encode_datetime() {
        let timestamp = 1704067200i64; // 2024-01-01 00:00:00 UTC
        let item = Ttlv::datetime(Tag::TIMESTAMP, timestamp);
        let encoded = TtlvEncoder::encode(&item);

        // Type: DateTime (0x09)
        assert_eq!(encoded[3], 0x09);

        // Length: 8
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x08]);

        // Value: timestamp as i64 big-endian
        let expected_bytes = timestamp.to_be_bytes();
        assert_eq!(&encoded[8..16], &expected_bytes);
    }

    #[test]
    fn test_encode_structure() {
        let structure = Ttlv::structure(
            Tag::PROTOCOL_VERSION,
            vec![
                Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
            ],
        );
        let encoded = TtlvEncoder::encode(&structure);

        // Type: Structure (0x01)
        assert_eq!(encoded[3], 0x01);

        // Length: 32 (2 integers, each 16 bytes)
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x20]);

        // First child starts at byte 8
        assert_eq!(encoded[8], 0x42); // Tag high byte
        assert_eq!(encoded[11], 0x02); // Type: Integer
    }

    #[test]
    fn test_encode_long_integer() {
        let item = Ttlv::long_integer(Tag::TIMESTAMP, 0x0102030405060708i64);
        let encoded = TtlvEncoder::encode(&item);

        // Type: LongInteger (0x03)
        assert_eq!(encoded[3], 0x03);

        // Length: 8
        assert_eq!(&encoded[4..8], &[0x00, 0x00, 0x00, 0x08]);

        // Value
        assert_eq!(
            &encoded[8..16],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_encoded_size() {
        let item = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1);
        assert_eq!(encoded_size(&item), 16); // 8 header + 8 value (4 + 4 padding)

        let item = Ttlv::text_string(Tag::UNIQUE_ID, "hello");
        assert_eq!(encoded_size(&item), 16); // 8 header + 8 value (5 + 3 padding)

        let item = Ttlv::text_string(Tag::UNIQUE_ID, "hello world!"); // 12 chars
        assert_eq!(encoded_size(&item), 24); // 8 header + 16 value (12 + 4 padding)
    }
}
