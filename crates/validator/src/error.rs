//! Error types for the validator module.

use thiserror::Error;

/// Slashing-specific errors.
///
/// These errors indicate that a signing operation was blocked to prevent slashing.
/// **These errors should NEVER be ignored** - they indicate a serious security issue.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SlashingError {
    /// Attempted to sign a double vote (same target epoch, different root).
    #[error(
        "SLASHING PREVENTED: Double vote detected at target epoch {target_epoch}. \
             Existing root: {existing_root}, attempted root: {attempted_root}"
    )]
    DoubleVote {
        /// The target epoch where double voting was attempted
        target_epoch: u64,
        /// The signing root already recorded for this epoch
        existing_root: String,
        /// The signing root that was attempted
        attempted_root: String,
    },

    /// Attempted to sign a surrounding vote.
    #[error(
        "SLASHING PREVENTED: Surrounding vote detected. \
             New attestation (source: {new_source}, target: {new_target}) \
             surrounds existing attestation (source: {existing_source}, target: {existing_target})"
    )]
    SurroundingVote {
        /// Source epoch of the new attestation
        new_source: u64,
        /// Target epoch of the new attestation
        new_target: u64,
        /// Source epoch of the existing attestation that would be surrounded
        existing_source: u64,
        /// Target epoch of the existing attestation that would be surrounded
        existing_target: u64,
    },

    /// Attempted to sign a surrounded vote.
    #[error("SLASHING PREVENTED: Surrounded vote detected. \
             New attestation (source: {new_source}, target: {new_target}) \
             is surrounded by existing attestation (source: {existing_source}, target: {existing_target})")]
    SurroundedVote {
        /// Source epoch of the new attestation
        new_source: u64,
        /// Target epoch of the new attestation
        new_target: u64,
        /// Source epoch of the existing attestation that surrounds this one
        existing_source: u64,
        /// Target epoch of the existing attestation that surrounds this one
        existing_target: u64,
    },

    /// Attempted to propose two different blocks at the same slot.
    #[error(
        "SLASHING PREVENTED: Double block proposal at slot {slot}. \
             Existing root: {existing_root}, attempted root: {attempted_root}"
    )]
    DoubleBlockProposal {
        /// The slot where double proposal was attempted
        slot: u64,
        /// The signing root already recorded for this slot
        existing_root: String,
        /// The signing root that was attempted
        attempted_root: String,
    },

    /// Attempted to sign at the same block height twice (Babylon EOTS).
    #[error(
        "SLASHING PREVENTED: Double sign at height {height}. \
             EOTS key would be extractable if signed twice at same height."
    )]
    EotsDoubleSign {
        /// The block height where double signing was attempted
        height: u64,
    },

    /// Attestation source epoch is not greater than the minimum recorded.
    #[error(
        "SLASHING PREVENTED: Attestation source epoch {source_epoch} is not greater than \
             minimum source epoch {min_source_epoch}"
    )]
    SourceEpochTooLow {
        /// The source epoch of the attempted attestation
        source_epoch: u64,
        /// The minimum allowed source epoch
        min_source_epoch: u64,
    },

    /// Attestation target epoch is not greater than the minimum recorded.
    #[error(
        "SLASHING PREVENTED: Attestation target epoch {target_epoch} is not greater than \
             minimum target epoch {min_target_epoch}"
    )]
    TargetEpochTooLow {
        /// The target epoch of the attempted attestation
        target_epoch: u64,
        /// The minimum allowed target epoch
        min_target_epoch: u64,
    },

    /// Block slot is not greater than the minimum recorded.
    #[error("SLASHING PREVENTED: Block slot {slot} is not greater than minimum slot {min_slot}")]
    SlotTooLow {
        /// The slot of the attempted block
        slot: u64,
        /// The minimum allowed slot
        min_slot: u64,
    },
}

/// General validator errors.
#[derive(Debug, Error)]
pub enum ValidatorError {
    /// A slashing condition was detected.
    #[error(transparent)]
    Slashing(#[from] SlashingError),

    /// Validator not found.
    #[error("Validator not found: {public_key}")]
    ValidatorNotFound {
        /// The public key of the validator that was not found
        public_key: String,
    },

    /// Validator already exists.
    #[error("Validator already registered: {public_key}")]
    ValidatorAlreadyExists {
        /// The public key of the validator that already exists
        public_key: String,
    },

    /// Invalid public key format.
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey {
        /// Reason the public key is invalid
        reason: String,
    },

    /// Invalid signature.
    #[error("Invalid signature: {reason}")]
    InvalidSignature {
        /// Reason the signature is invalid
        reason: String,
    },

    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid interchange format.
    #[error("Invalid EIP-3076 interchange format: {reason}")]
    InvalidInterchange {
        /// Reason the interchange format is invalid
        reason: String,
    },

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for validator operations.
pub type Result<T> = std::result::Result<T, ValidatorError>;

/// Result type for slashing checks.
pub type SlashingResult<T> = std::result::Result<T, SlashingError>;

impl From<sled::Error> for ValidatorError {
    fn from(e: sled::Error) -> Self {
        ValidatorError::Database(e.to_string())
    }
}

impl From<serde_json::Error> for ValidatorError {
    fn from(e: serde_json::Error) -> Self {
        ValidatorError::Serialization(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slashing_error_display() {
        let err = SlashingError::DoubleVote {
            target_epoch: 100,
            existing_root: "0xabc".to_string(),
            attempted_root: "0xdef".to_string(),
        };

        let msg = err.to_string();
        assert!(msg.contains("SLASHING PREVENTED"));
        assert!(msg.contains("Double vote"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn test_surrounding_vote_error() {
        let err = SlashingError::SurroundingVote {
            new_source: 5,
            new_target: 20,
            existing_source: 10,
            existing_target: 15,
        };

        let msg = err.to_string();
        assert!(msg.contains("Surrounding vote"));
    }

    #[test]
    fn test_eots_double_sign_error() {
        let err = SlashingError::EotsDoubleSign { height: 12345 };

        let msg = err.to_string();
        assert!(msg.contains("EOTS"));
        assert!(msg.contains("12345"));
    }
}
