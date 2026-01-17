//! # ZK-SNARK Circuits
//!
//! Circuit definitions for zero-knowledge proofs in the audit system.
//!
//! This module re-exports the main circuit types for convenience.

pub use crate::event_proof::EventExistenceCircuit;
pub use crate::merkle_proof::MerkleProofCircuit;

/// Common circuit utilities
pub mod utils {
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;

    /// Convert a byte array to a field element
    ///
    /// Takes the first 31 bytes to ensure we stay within the field modulus
    pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> F {
        // Pad or truncate to 32 bytes
        let mut padded = [0u8; 32];
        let len = bytes.len().min(31); // Use 31 to stay within field modulus
        padded[..len].copy_from_slice(&bytes[..len]);

        F::from_le_bytes_mod_order(&padded)
    }

    /// Convert a field element back to bytes (approximate)
    pub fn field_to_bytes<F: PrimeField + CanonicalSerialize>(field: &F) -> Vec<u8> {
        let mut bytes = Vec::new();
        field
            .serialize_compressed(&mut bytes)
            .expect("Serialization should not fail");
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::utils::*;
    use ark_bn254::Fr;

    #[test]
    fn test_bytes_to_field_conversion() {
        let bytes = [1u8; 32];
        let field = bytes_to_field::<Fr>(&bytes);

        let recovered = field_to_bytes(&field);
        assert!(!recovered.is_empty());
    }
}
