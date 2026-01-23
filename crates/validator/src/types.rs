//! Core types for the validator module.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A 32-byte signing root (hash of the data being signed).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SigningRoot(pub [u8; 32]);

impl SigningRoot {
    /// Create a new signing root from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a slice (must be exactly 32 bytes).
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice);
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Get the bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).ok()?;
        Self::from_slice(&bytes)
    }
}

impl fmt::Debug for SigningRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningRoot({})", self.to_hex())
    }
}

impl fmt::Display for SigningRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A BLS public key (48 bytes compressed G1 point).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlsPublicKey(pub Vec<u8>);

impl BlsPublicKey {
    /// Create a new BLS public key.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() == 48 {
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// Get the bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).ok()?;
        Self::new(bytes)
    }
}

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsPublicKey({})", self.to_hex())
    }
}

impl fmt::Display for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Ethereum epoch number.
pub type Epoch = u64;

/// Ethereum slot number.
pub type Slot = u64;

/// Babylon block height.
pub type BlockHeight = u64;

/// Validator index in the beacon chain.
pub type ValidatorIndex = u64;

/// Committee index for attestations.
pub type CommitteeIndex = u64;

/// Domain type for signature domain separation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum DomainType {
    /// Beacon proposer domain
    BeaconProposer = 0,
    /// Beacon attester domain
    BeaconAttester = 1,
    /// RANDAO reveal domain
    Randao = 2,
    /// Deposit domain
    Deposit = 3,
    /// Voluntary exit domain
    VoluntaryExit = 4,
    /// Selection proof domain
    SelectionProof = 5,
    /// Aggregate and proof domain
    AggregateAndProof = 6,
    /// Sync committee domain
    SyncCommittee = 7,
    /// Sync committee selection proof domain
    SyncCommitteeSelectionProof = 8,
    /// Contribution and proof domain
    ContributionAndProof = 9,
    /// BLS to execution change domain
    BlsToExecutionChange = 10,
    /// Application builder domain
    ApplicationBuilder = 11,
}

impl DomainType {
    /// Get the 4-byte domain type value.
    pub fn to_bytes(&self) -> [u8; 4] {
        (*self as u32).to_le_bytes()
    }
}

/// Fork information for computing signing domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkInfo {
    /// Current fork version (4 bytes)
    pub fork_version: [u8; 4],
    /// Genesis validators root (32 bytes)
    pub genesis_validators_root: [u8; 32],
}

impl ForkInfo {
    /// Create a new fork info.
    pub fn new(fork_version: [u8; 4], genesis_validators_root: [u8; 32]) -> Self {
        Self {
            fork_version,
            genesis_validators_root,
        }
    }

    /// Compute the domain for a given domain type.
    pub fn compute_domain(&self, domain_type: DomainType) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        // Compute fork data root
        let mut fork_data = [0u8; 64];
        fork_data[..4].copy_from_slice(&self.fork_version);
        fork_data[32..64].copy_from_slice(&self.genesis_validators_root);
        let fork_data_root: [u8; 32] = Sha256::digest(fork_data).into();

        // Domain = domain_type (4 bytes) || fork_data_root[:28]
        let mut domain = [0u8; 32];
        domain[..4].copy_from_slice(&domain_type.to_bytes());
        domain[4..32].copy_from_slice(&fork_data_root[..28]);

        domain
    }
}

/// Signing record for an attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationRecord {
    /// Source epoch of the attestation
    pub source_epoch: Epoch,
    /// Target epoch of the attestation
    pub target_epoch: Epoch,
    /// Signing root of the attestation data
    pub signing_root: SigningRoot,
    /// Timestamp when the attestation was signed
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

/// Signing record for a block proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    /// Slot of the block
    pub slot: Slot,
    /// Signing root of the block
    pub signing_root: SigningRoot,
    /// Timestamp when the block was signed
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

/// Validator status in the anti-slashing database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Validator is active and can sign
    Active,
    /// Validator is disabled (manual intervention required)
    Disabled,
    /// Validator has been slashed (cannot sign)
    Slashed,
    /// Validator is exiting
    Exiting,
    /// Validator has exited
    Exited,
}

/// Summary of a validator's signing history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSummary {
    /// The validator's public key
    pub public_key: BlsPublicKey,
    /// Current status
    pub status: ValidatorStatus,
    /// Minimum source epoch (for attestation protection)
    pub min_source_epoch: Option<Epoch>,
    /// Minimum target epoch (for attestation protection)
    pub min_target_epoch: Option<Epoch>,
    /// Minimum slot (for block proposal protection)
    pub min_slot: Option<Slot>,
    /// Total number of attestations signed
    pub attestation_count: u64,
    /// Total number of blocks proposed
    pub block_count: u64,
    /// Last activity timestamp
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
}

/// Statistics about slashing protection operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlashingStats {
    /// Total attestations signed
    pub attestations_signed: u64,
    /// Total blocks signed
    pub blocks_signed: u64,
    /// Total slashable operations prevented
    pub slashable_prevented: u64,
    /// Double votes prevented
    pub double_votes_prevented: u64,
    /// Surrounding votes prevented
    pub surrounding_votes_prevented: u64,
    /// Surrounded votes prevented
    pub surrounded_votes_prevented: u64,
    /// Double block proposals prevented
    pub double_blocks_prevented: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_root() {
        let bytes = [0xab; 32];
        let root = SigningRoot::new(bytes);

        assert_eq!(root.as_bytes(), &bytes);

        let hex = root.to_hex();
        assert!(hex.starts_with("0x"));

        let parsed = SigningRoot::from_hex(&hex).unwrap();
        assert_eq!(parsed, root);
    }

    #[test]
    fn test_bls_public_key() {
        let bytes = vec![0xcd; 48];
        let pk = BlsPublicKey::new(bytes.clone()).unwrap();

        assert_eq!(pk.as_bytes(), &bytes);

        // Wrong size should fail
        assert!(BlsPublicKey::new(vec![0; 47]).is_none());
        assert!(BlsPublicKey::new(vec![0; 49]).is_none());
    }

    #[test]
    fn test_fork_info_domain() {
        let fork_info = ForkInfo::new([0x01, 0x00, 0x00, 0x00], [0; 32]);

        let domain = fork_info.compute_domain(DomainType::BeaconAttester);
        assert_eq!(domain.len(), 32);

        // Domain type bytes should be at the start
        assert_eq!(&domain[..4], &DomainType::BeaconAttester.to_bytes());
    }

    #[test]
    fn test_domain_type_bytes() {
        assert_eq!(DomainType::BeaconProposer.to_bytes(), [0, 0, 0, 0]);
        assert_eq!(DomainType::BeaconAttester.to_bytes(), [1, 0, 0, 0]);
    }
}
