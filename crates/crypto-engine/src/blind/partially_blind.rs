//! Partially Blind Signatures
//!
//! A variant where the signer can see some agreed-upon metadata (like
//! expiration date) but not the main message content.
//!
//! # Use Cases
//!
//! - **Credential issuance**: Sign credentials with visible expiration dates
//! - **Anonymous voting**: Sign ballots with visible election ID but hidden vote
//! - **Digital cash**: Issue tokens with visible denomination but hidden serial number
//!
//! # Protocol
//!
//! 1. Requester and signer agree on metadata (visible to both)
//! 2. Requester blinds message combined with metadata hash
//! 3. Signer validates metadata and signs the blinded message
//! 4. Requester unblinds to get signature
//! 5. Verifier checks signature against message + metadata
//!
//! # Example
//!
//! ```rust,ignore
//! use hsm_crypto_engine::blind::{PartiallyBlindEngine, BlindMetadata, RsaBlindEngine};
//!
//! let (private_key, public_key) = RsaBlindEngine::generate_keypair(2048)?;
//!
//! // Create visible metadata
//! let metadata = BlindMetadata::from_string("expires:2025-12-31");
//!
//! // Blind message with metadata
//! let message = b"credential content";
//! let (blinded, factor) = PartiallyBlindEngine::blind_with_metadata(
//!     &public_key, message, &metadata
//! )?;
//!
//! // Signer validates metadata before signing
//! let blind_sig = PartiallyBlindEngine::sign_blinded_with_metadata(
//!     &private_key, &blinded, &metadata,
//!     |m| m.info.starts_with(b"expires:")  // Validation function
//! )?;
//!
//! // Unblind and verify
//! let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor)?;
//! assert!(PartiallyBlindEngine::verify_with_metadata(&public_key, message, &metadata, &signature)?);
//! ```

use super::rsa_blind::{RsaBlindEngine, RsaBlindPrivateKey, RsaBlindPublicKey};
use super::types::*;
use crate::hash::digest::hash;
use crate::HashAlgorithm;

/// Partially blind signature engine.
///
/// Extends RSA blind signatures to allow the signer to see and validate
/// certain metadata while keeping the message content hidden.
pub struct PartiallyBlindEngine;

impl PartiallyBlindEngine {
    /// Blinds a message with visible metadata.
    ///
    /// The metadata (e.g., expiration date) is visible to the signer.
    /// The message content remains hidden.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's public key
    /// * `message` - The message content (hidden from signer)
    /// * `metadata` - Metadata visible to the signer
    ///
    /// # Returns
    ///
    /// Tuple of (blinded message, unblinding factor)
    ///
    /// # Security
    ///
    /// The metadata is cryptographically bound to the signature via hashing.
    /// Changing the metadata after signing will invalidate the signature.
    pub fn blind_with_metadata(
        public_key: &RsaBlindPublicKey,
        message: &[u8],
        metadata: &BlindMetadata,
    ) -> Result<(BlindedMessage, UnblindingFactor), BlindError> {
        // Hash metadata to bind it to the signature
        let metadata_hash = hash(&metadata.info, HashAlgorithm::Sha256)
            .map_err(|e| BlindError::BlindingFailed(e.to_string()))?;

        // Create binding: message || metadata_hash
        // This ensures the signature is bound to both the message and the metadata
        let mut combined = message.to_vec();
        combined.extend_from_slice(&metadata_hash);

        // Proceed with normal blinding on the combined data
        RsaBlindEngine::blind(public_key, &combined)
    }

    /// Signs a blinded message after validating metadata.
    ///
    /// The signer verifies the metadata is acceptable before signing.
    /// This allows policy enforcement (e.g., valid expiration dates)
    /// while maintaining blindness of the message content.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The signer's private key
    /// * `blinded_message` - The blinded message from the requester
    /// * `metadata` - The metadata (visible to signer)
    /// * `validator` - Function to validate the metadata
    ///
    /// # Returns
    ///
    /// A blind signature if metadata validation passes.
    ///
    /// # Errors
    ///
    /// Returns `BlindError::MetadataValidationFailed` if the validator returns false.
    pub fn sign_blinded_with_metadata<F>(
        private_key: &RsaBlindPrivateKey,
        blinded_message: &BlindedMessage,
        metadata: &BlindMetadata,
        validator: F,
    ) -> Result<BlindSignature, BlindError>
    where
        F: Fn(&BlindMetadata) -> bool,
    {
        // Validate metadata before signing
        if !validator(metadata) {
            return Err(BlindError::MetadataValidationFailed(
                "Metadata did not pass validation".into(),
            ));
        }

        // Sign the blinded message
        // Note: The signer cannot see the message content, only the metadata
        RsaBlindEngine::sign_blinded(private_key, blinded_message)
    }

    /// Verifies a partially blind signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The signer's public key
    /// * `message` - The original message content
    /// * `metadata` - The metadata bound to the signature
    /// * `signature` - The unblinded signature
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for the message and metadata.
    pub fn verify_with_metadata(
        public_key: &RsaBlindPublicKey,
        message: &[u8],
        metadata: &BlindMetadata,
        signature: &[u8],
    ) -> Result<bool, BlindError> {
        // Reconstruct the combined message the same way as during blinding
        let metadata_hash = hash(&metadata.info, HashAlgorithm::Sha256)
            .map_err(|e| BlindError::BlindingFailed(e.to_string()))?;

        let mut combined = message.to_vec();
        combined.extend_from_slice(&metadata_hash);

        RsaBlindEngine::verify(public_key, &combined, signature)
    }
}

/// Common metadata for credentials.
///
/// Provides structured metadata for credential issuance use cases.
#[derive(Debug, Clone)]
pub struct CredentialMetadata {
    /// Issue timestamp (Unix timestamp)
    pub issued_at: u64,
    /// Expiration timestamp (Unix timestamp)
    pub expires_at: u64,
    /// Credential type/scope (e.g., "voter", "member", "access")
    pub credential_type: String,
}

impl CredentialMetadata {
    /// Creates new credential metadata.
    pub fn new(issued_at: u64, expires_at: u64, credential_type: impl Into<String>) -> Self {
        Self {
            issued_at,
            expires_at,
            credential_type: credential_type.into(),
        }
    }

    /// Serializes to bytes for inclusion in signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(self.credential_type.as_bytes());
        bytes
    }

    /// Creates BlindMetadata from this credential metadata.
    pub fn to_blind_metadata(&self) -> BlindMetadata {
        BlindMetadata {
            info: self.to_bytes(),
        }
    }

    /// Checks if the credential is currently valid (not expired).
    pub fn is_valid_now(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now >= self.issued_at && now < self.expires_at
    }

    /// Checks if the credential will be valid for at least the specified duration.
    pub fn is_valid_for(&self, duration_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now >= self.issued_at && (now + duration_secs) < self.expires_at
    }
}

/// Metadata validator that accepts any metadata.
pub fn accept_all_metadata(_metadata: &BlindMetadata) -> bool {
    true
}

/// Creates a metadata validator that checks expiration format.
///
/// Accepts metadata that starts with "expires:" followed by a date.
pub fn expiration_validator(metadata: &BlindMetadata) -> bool {
    metadata.info.starts_with(b"expires:")
}

/// Creates a validator for credential metadata that checks validity period.
///
/// # Arguments
///
/// * `max_validity_secs` - Maximum allowed validity period in seconds
///
/// # Returns
///
/// A validator function that checks the credential metadata.
pub fn credential_validity_validator(max_validity_secs: u64) -> impl Fn(&BlindMetadata) -> bool {
    move |metadata: &BlindMetadata| {
        if metadata.info.len() < 16 {
            return false;
        }

        // Parse timestamps from bytes
        let issued_at = u64::from_be_bytes(metadata.info[0..8].try_into().unwrap_or([0; 8]));
        let expires_at = u64::from_be_bytes(metadata.info[8..16].try_into().unwrap_or([0; 8]));

        // Check validity period doesn't exceed maximum
        expires_at.saturating_sub(issued_at) <= max_validity_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_keypair() -> (RsaBlindPrivateKey, RsaBlindPublicKey) {
        RsaBlindEngine::generate_keypair(2048).unwrap()
    }

    #[test]
    fn test_partially_blind_basic() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"credential content";

        let valid_metadata = BlindMetadata::from_string("expires:2025-12-31");

        // Blind with metadata
        let (blinded, factor) =
            PartiallyBlindEngine::blind_with_metadata(&public_key, message, &valid_metadata)
                .unwrap();

        // Signer validates metadata before signing
        let blind_sig = PartiallyBlindEngine::sign_blinded_with_metadata(
            &private_key,
            &blinded,
            &valid_metadata,
            expiration_validator,
        )
        .unwrap();

        // Unblind
        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        // Verify with metadata
        assert!(PartiallyBlindEngine::verify_with_metadata(
            &public_key,
            message,
            &valid_metadata,
            &signature,
        )
        .unwrap());
    }

    #[test]
    fn test_metadata_validation_rejection() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"credential content";

        // Metadata that doesn't match expected format
        let invalid_metadata = BlindMetadata::from_string("invalid:format");

        let (blinded, _factor) =
            PartiallyBlindEngine::blind_with_metadata(&public_key, message, &invalid_metadata)
                .unwrap();

        // Signer rejects due to metadata validation failure
        let result = PartiallyBlindEngine::sign_blinded_with_metadata(
            &private_key,
            &blinded,
            &invalid_metadata,
            expiration_validator, // Expects "expires:" prefix
        );

        assert!(matches!(
            result,
            Err(BlindError::MetadataValidationFailed(_))
        ));
    }

    #[test]
    fn test_wrong_metadata_fails_verification() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"credential content";

        let original_metadata = BlindMetadata::from_string("expires:2025-12-31");
        let tampered_metadata = BlindMetadata::from_string("expires:2030-12-31");

        // Sign with original metadata
        let (blinded, factor) =
            PartiallyBlindEngine::blind_with_metadata(&public_key, message, &original_metadata)
                .unwrap();

        let blind_sig = PartiallyBlindEngine::sign_blinded_with_metadata(
            &private_key,
            &blinded,
            &original_metadata,
            accept_all_metadata,
        )
        .unwrap();

        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        // Verification with tampered metadata should fail
        assert!(!PartiallyBlindEngine::verify_with_metadata(
            &public_key,
            message,
            &tampered_metadata,
            &signature,
        )
        .unwrap());
    }

    #[test]
    fn test_wrong_message_fails_verification() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"original credential";
        let wrong_message = b"tampered credential";

        let metadata = BlindMetadata::from_string("expires:2025-12-31");

        let (blinded, factor) =
            PartiallyBlindEngine::blind_with_metadata(&public_key, message, &metadata).unwrap();

        let blind_sig = PartiallyBlindEngine::sign_blinded_with_metadata(
            &private_key,
            &blinded,
            &metadata,
            accept_all_metadata,
        )
        .unwrap();

        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        // Verification with wrong message should fail
        assert!(!PartiallyBlindEngine::verify_with_metadata(
            &public_key,
            wrong_message,
            &metadata,
            &signature,
        )
        .unwrap());
    }

    #[test]
    fn test_credential_metadata() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let credential = CredentialMetadata::new(
            now,
            now + 86400, // Valid for 1 day
            "voter",
        );

        assert!(credential.is_valid_now());
        assert!(credential.is_valid_for(3600)); // Valid for at least 1 hour
        assert!(!credential.is_valid_for(90000)); // Not valid for 25 hours

        let blind_metadata = credential.to_blind_metadata();
        assert!(!blind_metadata.info.is_empty());
    }

    #[test]
    fn test_credential_validity_validator() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create credential valid for 1 day
        let credential = CredentialMetadata::new(now, now + 86400, "access");
        let metadata = credential.to_blind_metadata();

        // Validator allowing up to 7 days
        let validator = credential_validity_validator(7 * 86400);
        assert!(validator(&metadata));

        // Validator allowing only 12 hours
        let strict_validator = credential_validity_validator(12 * 3600);
        assert!(!strict_validator(&metadata));
    }

    #[test]
    fn test_partially_blind_with_credential_metadata() {
        let (private_key, public_key) = generate_test_keypair();
        let message = b"user ID: 12345";

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let credential = CredentialMetadata::new(
            now,
            now + 86400 * 30, // Valid for 30 days
            "member",
        );
        let metadata = credential.to_blind_metadata();

        // Blind with credential metadata
        let (blinded, factor) =
            PartiallyBlindEngine::blind_with_metadata(&public_key, message, &metadata).unwrap();

        // Sign with validity check (max 90 days)
        let validator = credential_validity_validator(90 * 86400);
        let blind_sig = PartiallyBlindEngine::sign_blinded_with_metadata(
            &private_key,
            &blinded,
            &metadata,
            validator,
        )
        .unwrap();

        let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor).unwrap();

        assert!(PartiallyBlindEngine::verify_with_metadata(
            &public_key,
            message,
            &metadata,
            &signature
        )
        .unwrap());
    }
}
