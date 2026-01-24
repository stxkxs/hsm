//! Threshold scheme trait abstraction
//!
//! This module defines the common interface for all threshold cryptography schemes,
//! allowing them to be used interchangeably where appropriate.

use super::types::{
    GroupPublicKey, KeyShare, ParticipantId, SignatureShare, SigningCommitment, SigningNonce,
    ThresholdConfig, ThresholdError, ThresholdScheme, ThresholdSignature,
};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use zeroize::Zeroize;

/// Common trait for all threshold cryptography scheme implementations.
///
/// This trait provides a unified interface for different threshold signature
/// schemes (FROST, Threshold ECDSA, Threshold BLS), enabling generic code
/// that works with any supported scheme.
///
/// # Type Parameters
///
/// Each scheme defines its own concrete types for keys, commitments, and signatures
/// while implementing this common interface.
pub trait ThresholdSchemeOps: Send + Sync + Debug {
    /// The scheme identifier.
    fn scheme(&self) -> ThresholdScheme;

    /// Check if this scheme is FIPS 140-3 approved.
    fn is_fips_approved(&self) -> bool {
        self.scheme().is_fips_approved()
    }

    /// Get the number of signing rounds required.
    fn signing_rounds(&self) -> u8 {
        self.scheme().signing_rounds()
    }

    /// Get the signature size in bytes.
    fn signature_size(&self) -> usize {
        self.scheme().signature_size()
    }

    /// Get the public key size in bytes.
    fn public_key_size(&self) -> usize {
        self.scheme().public_key_size()
    }
}

/// Trait for key generation operations.
pub trait KeyGeneration: ThresholdSchemeOps {
    /// Secret share type for this scheme.
    type SecretShare: Clone + Zeroize + Send + Sync;

    /// Public share type for this scheme.
    type PublicShare: Clone + Serialize + DeserializeOwned + Send + Sync;

    /// Generate key shares using a trusted dealer.
    ///
    /// This method generates a complete set of key shares from a single trusted
    /// party. Use this when bootstrapping a system or when a trusted dealer is
    /// acceptable for your security model.
    ///
    /// # Arguments
    ///
    /// * `config` - The threshold configuration (t-of-n)
    ///
    /// # Returns
    ///
    /// A tuple of (group_public_key, key_shares) where key_shares has length n.
    fn trusted_dealer_keygen(
        config: ThresholdConfig,
    ) -> Result<(GroupPublicKey, Vec<KeyShare>), ThresholdError>;
}

/// Trait for signing operations.
pub trait Signing: ThresholdSchemeOps {
    /// Generate nonces and commitment for Round 1 of signing.
    ///
    /// This must be called once per signing session. The nonce must be kept
    /// secret and used only once. The commitment is broadcast to other participants.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    ///
    /// # Returns
    ///
    /// A tuple of (nonce, commitment) where nonce is secret and commitment is public.
    fn generate_nonces(
        key_share: &KeyShare,
    ) -> Result<(SigningNonce, SigningCommitment), ThresholdError>;

    /// Generate a signature share for Round 2 of signing.
    ///
    /// Called after receiving commitments from all participating signers.
    ///
    /// # Arguments
    ///
    /// * `key_share` - The participant's key share
    /// * `nonce` - The nonce from Round 1 (consumed)
    /// * `message` - The message to sign
    /// * `commitments` - Commitments from all participating signers
    ///
    /// # Returns
    ///
    /// The participant's signature share.
    fn sign_share(
        key_share: &KeyShare,
        nonce: SigningNonce,
        message: &[u8],
        commitments: &[SigningCommitment],
    ) -> Result<SignatureShare, ThresholdError>;

    /// Aggregate signature shares into a complete threshold signature.
    ///
    /// # Arguments
    ///
    /// * `message` - The signed message
    /// * `commitments` - Commitments from participating signers
    /// * `signature_shares` - Signature shares from participating signers
    /// * `group_public_key` - The group's public key
    ///
    /// # Returns
    ///
    /// The complete threshold signature.
    fn aggregate(
        message: &[u8],
        commitments: &[SigningCommitment],
        signature_shares: &[SignatureShare],
        group_public_key: &GroupPublicKey,
    ) -> Result<ThresholdSignature, ThresholdError>;
}

/// Trait for signature verification.
pub trait Verification: ThresholdSchemeOps {
    /// Verify a threshold signature.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The group's public key
    /// * `message` - The signed message
    /// * `signature` - The threshold signature
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    fn verify(
        public_key: &GroupPublicKey,
        message: &[u8],
        signature: &ThresholdSignature,
    ) -> Result<bool, ThresholdError>;
}

/// Trait for DKG (Distributed Key Generation) operations.
pub trait DistributedKeyGen: ThresholdSchemeOps {
    /// Round 1 package type.
    type Round1Package: Clone + Serialize + DeserializeOwned + Send + Sync;

    /// Round 2 package type.
    type Round2Package: Clone + Serialize + DeserializeOwned + Send + Sync;

    /// Execute Round 1 of DKG.
    ///
    /// Each participant generates their contribution and broadcasts it.
    fn dkg_round1(
        &self,
        participant_id: ParticipantId,
    ) -> Result<Self::Round1Package, ThresholdError>;

    /// Execute Round 2 of DKG.
    ///
    /// After receiving Round 1 packages from all participants, generate
    /// per-participant packages for Round 2.
    fn dkg_round2(
        &self,
        participant_id: ParticipantId,
        round1_packages: Vec<Self::Round1Package>,
    ) -> Result<Vec<Self::Round2Package>, ThresholdError>;

    /// Finalize DKG and produce key share.
    ///
    /// After receiving Round 2 packages, compute the final key share.
    fn dkg_finalize(
        &self,
        participant_id: ParticipantId,
        round2_packages: Vec<Self::Round2Package>,
    ) -> Result<(KeyShare, GroupPublicKey), ThresholdError>;
}

/// Trait for key refresh operations.
pub trait KeyRefresh: ThresholdSchemeOps {
    /// Refresh package type.
    type RefreshPackage: Clone + Serialize + DeserializeOwned + Send + Sync;

    /// Generate refresh contribution.
    ///
    /// Each participant generates a refresh polynomial with zero constant term.
    fn refresh_round1(&self, key_share: &KeyShare) -> Result<Self::RefreshPackage, ThresholdError>;

    /// Apply refresh packages to update key share.
    ///
    /// The public key remains unchanged after refresh.
    fn refresh_finalize(
        &self,
        key_share: &KeyShare,
        refresh_packages: Vec<Self::RefreshPackage>,
    ) -> Result<KeyShare, ThresholdError>;
}

/// Trait for resharing operations (changing threshold or participants).
pub trait Resharing: ThresholdSchemeOps {
    /// Resharing package type.
    type ResharingPackage: Clone + Serialize + DeserializeOwned + Send + Sync;

    /// Generate resharing packages for new participants.
    ///
    /// Old participants generate shares for each new participant.
    fn reshare_generate(
        &self,
        old_share: &KeyShare,
        new_participants: &[ParticipantId],
        new_threshold: u16,
    ) -> Result<Vec<Self::ResharingPackage>, ThresholdError>;

    /// Receive and combine resharing packages.
    ///
    /// New participants collect packages from old participants.
    fn reshare_receive(
        &self,
        new_participant_id: ParticipantId,
        packages: Vec<Self::ResharingPackage>,
        old_threshold: u16,
    ) -> Result<KeyShare, ThresholdError>;
}

/// Combined trait for a fully-featured threshold scheme.
pub trait FullThresholdScheme:
    KeyGeneration + Signing + Verification + DistributedKeyGen + KeyRefresh + Resharing
{
}

// Blanket implementation for any type that implements all required traits
impl<T> FullThresholdScheme for T where
    T: KeyGeneration + Signing + Verification + DistributedKeyGen + KeyRefresh + Resharing
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme_properties() {
        assert!(ThresholdScheme::FrostEd25519.is_fips_approved());
        assert!(ThresholdScheme::ThresholdEcdsaP256.is_fips_approved());
        assert!(!ThresholdScheme::ThresholdEcdsaSecp256k1.is_fips_approved());
        assert!(!ThresholdScheme::ThresholdBls12381.is_fips_approved());

        assert_eq!(ThresholdScheme::ThresholdBls12381.signing_rounds(), 1);
        assert_eq!(ThresholdScheme::FrostEd25519.signing_rounds(), 2);
        assert_eq!(ThresholdScheme::ThresholdEcdsaP256.signing_rounds(), 3);
    }
}
