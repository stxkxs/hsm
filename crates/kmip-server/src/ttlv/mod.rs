//! TTLV (Tag-Type-Length-Value) codec for KMIP protocol
//!
//! TTLV is the binary encoding format used by KMIP for all protocol messages.
//! This module provides types, encoding, and decoding functionality.

mod decoder;
mod encoder;
pub mod types;

pub use decoder::{peek_message_length, TtlvDecoder};
pub use encoder::{encoded_size, TtlvEncoder};
pub use types::{Tag, Ttlv, TtlvError, TtlvType, TtlvValue};
