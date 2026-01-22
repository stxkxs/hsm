//! Blind Signature module
//!
//! Blind signatures allow a signer to sign a message without seeing its content.
//! The signer learns nothing about the message, but the resulting signature
//! can be verified by anyone with the public key.
//!
//! # Schemes
//!
//! - **RSA Blind Signatures**: Based on Chaum's original 1983 scheme
//! - **Partially Blind Signatures**: Signer sees some metadata but not the message
//!
//! # Security Properties
//!
//! - **Blindness**: Signer cannot link unblinded signatures to blinding sessions
//! - **Unforgeability**: Cannot create valid signatures without signer participation
//! - **Unlinkability**: Same message signed twice produces identical final signatures
//!   but different blinded messages (due to random blinding factors)
//!
//! # Use Cases
//!
//! - **Anonymous voting**: Sign ballots without seeing votes
//! - **Digital cash**: Issue tokens without tracking spending
//! - **Privacy credentials**: Issue attributes without linking to identity
//! - **Certificate transparency**: Prove signing occurred without revealing content
//!
//! # Example: RSA Blind Signatures
//!
//! ```rust,ignore
//! use hsm_crypto_engine::blind::{RsaBlindEngine, RsaBlindPublicKey, RsaBlindPrivateKey};
//!
//! // Generate keypair
//! let (private_key, public_key) = RsaBlindEngine::generate_keypair(2048)?;
//!
//! // Requester blinds the message
//! let message = b"secret ballot vote";
//! let (blinded_message, unblinding_factor) = RsaBlindEngine::blind(&public_key, message)?;
//!
//! // Signer signs the blinded message (learns nothing about original)
//! let blind_signature = RsaBlindEngine::sign_blinded(&private_key, &blinded_message)?;
//!
//! // Requester unblinds to get valid signature
//! let signature = RsaBlindEngine::unblind(&public_key, &blind_signature, &unblinding_factor)?;
//!
//! // Anyone can verify
//! assert!(RsaBlindEngine::verify(&public_key, message, &signature)?);
//! ```
//!
//! # Example: Partially Blind Signatures
//!
//! ```rust,ignore
//! use hsm_crypto_engine::blind::{
//!     PartiallyBlindEngine, BlindMetadata, RsaBlindEngine,
//!     expiration_validator,
//! };
//!
//! // Generate keypair
//! let (private_key, public_key) = RsaBlindEngine::generate_keypair(2048)?;
//!
//! // Create visible metadata (signer can see this)
//! let metadata = BlindMetadata::from_str("expires:2025-12-31");
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
//!     expiration_validator,  // Only sign if metadata has valid expiration format
//! )?;
//!
//! // Unblind and verify
//! let signature = RsaBlindEngine::unblind(&public_key, &blind_sig, &factor)?;
//! assert!(PartiallyBlindEngine::verify_with_metadata(
//!     &public_key, message, &metadata, &signature
//! )?);
//! ```
//!
//! # Security Considerations
//!
//! - **RSA key size**: Use at least 2048 bits, prefer 3072+ for long-term security
//! - **Blinding factor**: Must be cryptographically random and coprime with modulus
//! - **Timing attacks**: Use constant-time operations where possible
//! - **Message encoding**: Uses PKCS#1 v1.5 padding with SHA-256 hash
//! - **Metadata binding**: Partially blind signatures cryptographically bind metadata

pub mod partially_blind;
pub mod rsa_blind;
pub mod types;

// Re-export main types for convenience
pub use partially_blind::{
    accept_all_metadata, credential_validity_validator, expiration_validator, CredentialMetadata,
    PartiallyBlindEngine,
};
pub use rsa_blind::{RsaBlindEngine, RsaBlindPrivateKey, RsaBlindPublicKey};
pub use types::{BlindError, BlindMetadata, BlindSignature, BlindedMessage, UnblindingFactor};
