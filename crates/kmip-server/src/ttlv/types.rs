//! KMIP TTLV (Tag-Type-Length-Value) primitive types
//!
//! TTLV is the binary encoding format used by KMIP for all protocol messages.
//! Each item consists of:
//! - Tag: 3 bytes identifying the data element
//! - Type: 1 byte indicating the data type
//! - Length: 4 bytes specifying the value length
//! - Value: Variable length data (padded to 8-byte boundary for most types)

use std::io;

/// TTLV Tag (3 bytes, stored as u32 with high byte zero)
///
/// Tags identify the semantic meaning of each TTLV item.
/// They are defined by the KMIP specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(pub u32);

impl Tag {
    // Request/Response Messages
    pub const REQUEST_MESSAGE: Tag = Tag(0x420078);
    pub const RESPONSE_MESSAGE: Tag = Tag(0x42007B);
    pub const REQUEST_HEADER: Tag = Tag(0x420077);
    pub const RESPONSE_HEADER: Tag = Tag(0x42007A);
    pub const REQUEST_BATCH_ITEM: Tag = Tag(0x42000F);
    pub const RESPONSE_BATCH_ITEM: Tag = Tag(0x42000F);

    // Protocol versioning
    pub const PROTOCOL_VERSION: Tag = Tag(0x420069);
    pub const PROTOCOL_VERSION_MAJOR: Tag = Tag(0x42006A);
    pub const PROTOCOL_VERSION_MINOR: Tag = Tag(0x42006B);

    // Batch handling
    pub const BATCH_COUNT: Tag = Tag(0x42000D);
    pub const BATCH_ITEM: Tag = Tag(0x42000F);

    // Operation and result
    pub const OPERATION: Tag = Tag(0x42005C);
    pub const RESULT_STATUS: Tag = Tag(0x42007F);
    pub const RESULT_REASON: Tag = Tag(0x42007E);
    pub const RESULT_MESSAGE: Tag = Tag(0x42007D);

    // Key identification
    pub const UNIQUE_ID: Tag = Tag(0x420094);
    pub const OBJECT_TYPE: Tag = Tag(0x420057);

    // Attributes
    pub const TEMPLATE_ATTRIBUTE: Tag = Tag(0x420091);
    pub const ATTRIBUTE: Tag = Tag(0x420008);
    pub const ATTRIBUTE_NAME: Tag = Tag(0x42000A);
    pub const ATTRIBUTE_VALUE: Tag = Tag(0x42000B);
    pub const ATTRIBUTE_INDEX: Tag = Tag(0x420009);

    // Cryptographic parameters
    pub const CRYPTOGRAPHIC_ALGORITHM: Tag = Tag(0x420028);
    pub const CRYPTOGRAPHIC_LENGTH: Tag = Tag(0x42002A);
    pub const CRYPTOGRAPHIC_PARAMETERS: Tag = Tag(0x42002B);
    pub const BLOCK_CIPHER_MODE: Tag = Tag(0x420011);
    pub const PADDING_METHOD: Tag = Tag(0x42005F);
    pub const HASHING_ALGORITHM: Tag = Tag(0x420038);

    // Key block and material
    pub const KEY_BLOCK: Tag = Tag(0x420040);
    pub const KEY_FORMAT_TYPE: Tag = Tag(0x420042);
    pub const KEY_VALUE: Tag = Tag(0x420045);
    pub const KEY_MATERIAL: Tag = Tag(0x420043);
    pub const KEY_WRAPPING_DATA: Tag = Tag(0x420046);

    // Data fields
    pub const DATA: Tag = Tag(0x4200C2);
    pub const IV_COUNTER_NONCE: Tag = Tag(0x42003D);
    pub const SIGNATURE_DATA: Tag = Tag(0x42003F);
    pub const MAC_DATA: Tag = Tag(0x420030);

    // Timestamps
    pub const TIMESTAMP: Tag = Tag(0x420092);
    pub const INITIAL_DATE: Tag = Tag(0x420120);
    pub const ACTIVATION_DATE: Tag = Tag(0x420001);
    pub const DEACTIVATION_DATE: Tag = Tag(0x420121);
    pub const COMPROMISE_DATE: Tag = Tag(0x420122);
    pub const DESTROY_DATE: Tag = Tag(0x420123);

    // State and usage
    pub const STATE: Tag = Tag(0x42008D);
    pub const CRYPTOGRAPHIC_USAGE_MASK: Tag = Tag(0x42002C);

    // Revocation
    pub const REVOCATION_REASON: Tag = Tag(0x420081);
    pub const REVOCATION_REASON_CODE: Tag = Tag(0x420082);
    pub const REVOCATION_MESSAGE: Tag = Tag(0x420083);

    // Query
    pub const QUERY_FUNCTION: Tag = Tag(0x420074);
    pub const SERVER_INFORMATION: Tag = Tag(0x420088);
    pub const OPERATION_ENUM: Tag = Tag(0x42005D);

    // Response payload (generic)
    pub const RESPONSE_PAYLOAD: Tag = Tag(0x42007C);
    pub const REQUEST_PAYLOAD: Tag = Tag(0x420079);

    // Name and identifiers
    pub const NAME: Tag = Tag(0x420053);
    pub const NAME_VALUE: Tag = Tag(0x420055);
    pub const NAME_TYPE: Tag = Tag(0x420054);
}

impl From<u32> for Tag {
    fn from(value: u32) -> Self {
        Tag(value)
    }
}

impl From<Tag> for u32 {
    fn from(tag: Tag) -> Self {
        tag.0
    }
}

/// TTLV Type (1 byte)
///
/// Indicates the type of data stored in the Value field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TtlvType {
    /// Nested TTLV items
    Structure = 0x01,
    /// 32-bit signed integer (padded to 8 bytes)
    Integer = 0x02,
    /// 64-bit signed integer
    LongInteger = 0x03,
    /// Arbitrary precision integer
    BigInteger = 0x04,
    /// 32-bit enumeration value (padded to 8 bytes)
    Enumeration = 0x05,
    /// Boolean value (stored as 8-byte value)
    Boolean = 0x06,
    /// UTF-8 text string (padded to 8-byte boundary)
    TextString = 0x07,
    /// Arbitrary byte sequence (padded to 8-byte boundary)
    ByteString = 0x08,
    /// Unix timestamp as 64-bit signed integer
    DateTime = 0x09,
    /// Time interval in seconds (32-bit, padded to 8 bytes)
    Interval = 0x0A,
}

impl TryFrom<u8> for TtlvType {
    type Error = TtlvError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(TtlvType::Structure),
            0x02 => Ok(TtlvType::Integer),
            0x03 => Ok(TtlvType::LongInteger),
            0x04 => Ok(TtlvType::BigInteger),
            0x05 => Ok(TtlvType::Enumeration),
            0x06 => Ok(TtlvType::Boolean),
            0x07 => Ok(TtlvType::TextString),
            0x08 => Ok(TtlvType::ByteString),
            0x09 => Ok(TtlvType::DateTime),
            0x0A => Ok(TtlvType::Interval),
            _ => Err(TtlvError::InvalidType(value)),
        }
    }
}

impl From<TtlvType> for u8 {
    fn from(t: TtlvType) -> Self {
        t as u8
    }
}

/// TTLV Value variants
#[derive(Debug, Clone, PartialEq)]
pub enum TtlvValue {
    /// Nested structure containing child TTLV items
    Structure(Vec<Ttlv>),
    /// 32-bit signed integer
    Integer(i32),
    /// 64-bit signed integer
    LongInteger(i64),
    /// Arbitrary precision integer (big-endian, two's complement)
    BigInteger(Vec<u8>),
    /// 32-bit enumeration value
    Enumeration(u32),
    /// Boolean value
    Boolean(bool),
    /// UTF-8 text string
    TextString(String),
    /// Arbitrary byte sequence
    ByteString(Vec<u8>),
    /// Unix timestamp (seconds since epoch)
    DateTime(i64),
    /// Time interval in seconds
    Interval(u32),
}

impl TtlvValue {
    /// Returns the TTLV type for this value
    pub fn ttlv_type(&self) -> TtlvType {
        match self {
            TtlvValue::Structure(_) => TtlvType::Structure,
            TtlvValue::Integer(_) => TtlvType::Integer,
            TtlvValue::LongInteger(_) => TtlvType::LongInteger,
            TtlvValue::BigInteger(_) => TtlvType::BigInteger,
            TtlvValue::Enumeration(_) => TtlvType::Enumeration,
            TtlvValue::Boolean(_) => TtlvType::Boolean,
            TtlvValue::TextString(_) => TtlvType::TextString,
            TtlvValue::ByteString(_) => TtlvType::ByteString,
            TtlvValue::DateTime(_) => TtlvType::DateTime,
            TtlvValue::Interval(_) => TtlvType::Interval,
        }
    }

    /// Try to get as integer
    pub fn as_integer(&self) -> Option<i32> {
        match self {
            TtlvValue::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as long integer
    pub fn as_long_integer(&self) -> Option<i64> {
        match self {
            TtlvValue::LongInteger(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as enumeration
    pub fn as_enumeration(&self) -> Option<u32> {
        match self {
            TtlvValue::Enumeration(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as boolean
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            TtlvValue::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as text string
    pub fn as_text_string(&self) -> Option<&str> {
        match self {
            TtlvValue::TextString(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get as byte string
    pub fn as_byte_string(&self) -> Option<&[u8]> {
        match self {
            TtlvValue::ByteString(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get as structure
    pub fn as_structure(&self) -> Option<&[Ttlv]> {
        match self {
            TtlvValue::Structure(v) => Some(v),
            _ => None,
        }
    }
}

/// Complete TTLV item with tag and value
#[derive(Debug, Clone, PartialEq)]
pub struct Ttlv {
    /// The tag identifying this item
    pub tag: Tag,
    /// The value of this item
    pub value: TtlvValue,
}

impl Ttlv {
    /// Create a new TTLV item
    pub fn new(tag: Tag, value: TtlvValue) -> Self {
        Self { tag, value }
    }

    /// Create a structure TTLV item
    pub fn structure(tag: Tag, items: Vec<Ttlv>) -> Self {
        Self {
            tag,
            value: TtlvValue::Structure(items),
        }
    }

    /// Create an integer TTLV item
    pub fn integer(tag: Tag, value: i32) -> Self {
        Self {
            tag,
            value: TtlvValue::Integer(value),
        }
    }

    /// Create a long integer TTLV item
    pub fn long_integer(tag: Tag, value: i64) -> Self {
        Self {
            tag,
            value: TtlvValue::LongInteger(value),
        }
    }

    /// Create a big integer TTLV item
    pub fn big_integer(tag: Tag, value: Vec<u8>) -> Self {
        Self {
            tag,
            value: TtlvValue::BigInteger(value),
        }
    }

    /// Create an enumeration TTLV item
    pub fn enumeration(tag: Tag, value: u32) -> Self {
        Self {
            tag,
            value: TtlvValue::Enumeration(value),
        }
    }

    /// Create a boolean TTLV item
    pub fn boolean(tag: Tag, value: bool) -> Self {
        Self {
            tag,
            value: TtlvValue::Boolean(value),
        }
    }

    /// Create a text string TTLV item
    pub fn text_string(tag: Tag, value: impl Into<String>) -> Self {
        Self {
            tag,
            value: TtlvValue::TextString(value.into()),
        }
    }

    /// Create a byte string TTLV item
    pub fn byte_string(tag: Tag, value: Vec<u8>) -> Self {
        Self {
            tag,
            value: TtlvValue::ByteString(value),
        }
    }

    /// Create a datetime TTLV item
    pub fn datetime(tag: Tag, timestamp: i64) -> Self {
        Self {
            tag,
            value: TtlvValue::DateTime(timestamp),
        }
    }

    /// Create an interval TTLV item
    pub fn interval(tag: Tag, seconds: u32) -> Self {
        Self {
            tag,
            value: TtlvValue::Interval(seconds),
        }
    }

    /// Get a child item by tag (for structures only)
    pub fn get(&self, tag: Tag) -> Option<&Ttlv> {
        if let TtlvValue::Structure(items) = &self.value {
            items.iter().find(|item| item.tag == tag)
        } else {
            None
        }
    }

    /// Get all child items with matching tag (for structures only)
    pub fn get_all(&self, tag: Tag) -> Vec<&Ttlv> {
        if let TtlvValue::Structure(items) = &self.value {
            items.iter().filter(|item| item.tag == tag).collect()
        } else {
            vec![]
        }
    }

    /// Check if this is a structure
    pub fn is_structure(&self) -> bool {
        matches!(&self.value, TtlvValue::Structure(_))
    }

    /// Get the TTLV type of this item
    pub fn ttlv_type(&self) -> TtlvType {
        self.value.ttlv_type()
    }
}

/// TTLV encoding/decoding errors
#[derive(Debug, thiserror::Error)]
pub enum TtlvError {
    #[error("Invalid TTLV type byte: 0x{0:02X}")]
    InvalidType(u8),

    #[error("Unexpected end of data")]
    UnexpectedEof,

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("Invalid UTF-8 in text string")]
    InvalidUtf8,

    #[error("Length overflow: {0}")]
    LengthOverflow(usize),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_constants() {
        assert_eq!(Tag::REQUEST_MESSAGE.0, 0x420078);
        assert_eq!(Tag::RESPONSE_MESSAGE.0, 0x42007B);
        assert_eq!(Tag::UNIQUE_ID.0, 0x420094);
    }

    #[test]
    fn test_ttlv_type_conversion() {
        assert_eq!(TtlvType::try_from(0x01).unwrap(), TtlvType::Structure);
        assert_eq!(TtlvType::try_from(0x02).unwrap(), TtlvType::Integer);
        assert_eq!(TtlvType::try_from(0x07).unwrap(), TtlvType::TextString);
        assert!(TtlvType::try_from(0xFF).is_err());
    }

    #[test]
    fn test_ttlv_construction() {
        let item = Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1);
        assert_eq!(item.tag, Tag::PROTOCOL_VERSION_MAJOR);
        assert_eq!(item.value.as_integer(), Some(1));

        let item = Ttlv::text_string(Tag::UNIQUE_ID, "test-key");
        assert_eq!(item.value.as_text_string(), Some("test-key"));
    }

    #[test]
    fn test_ttlv_structure_access() {
        let structure = Ttlv::structure(
            Tag::REQUEST_MESSAGE,
            vec![
                Ttlv::integer(Tag::PROTOCOL_VERSION_MAJOR, 1),
                Ttlv::integer(Tag::PROTOCOL_VERSION_MINOR, 4),
                Ttlv::text_string(Tag::UNIQUE_ID, "key-123"),
            ],
        );

        assert!(structure.is_structure());
        assert_eq!(
            structure
                .get(Tag::PROTOCOL_VERSION_MAJOR)
                .unwrap()
                .value
                .as_integer(),
            Some(1)
        );
        assert_eq!(
            structure
                .get(Tag::UNIQUE_ID)
                .unwrap()
                .value
                .as_text_string(),
            Some("key-123")
        );
        assert!(structure.get(Tag::OPERATION).is_none());
    }

    #[test]
    fn test_ttlv_value_type() {
        assert_eq!(TtlvValue::Integer(42).ttlv_type(), TtlvType::Integer);
        assert_eq!(
            TtlvValue::TextString("test".into()).ttlv_type(),
            TtlvType::TextString
        );
        assert_eq!(
            TtlvValue::Structure(vec![]).ttlv_type(),
            TtlvType::Structure
        );
    }
}
