//! Shamir's Secret Sharing implementation for master key protection.
//!
//! This module implements Shamir's Secret Sharing Scheme (SSSS), a cryptographic
//! algorithm for splitting a secret into multiple shares such that a minimum
//! threshold of shares is required to reconstruct the original secret.
//!
//! # Shamir's Secret Sharing Workflow
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                  Secret Sharing Workflow                        │
//! ├────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  [Master Key: 32 bytes]                                          │
//! │         │                                                        │
//! │         ▼                                                        │
//! │  ┌──────────────────┐                                           │
//! │  │ split_secret()   │   Config: threshold=3, shares=5           │
//! │  └──────────────────┘                                           │
//! │         │                                                        │
//! │         ├─── Polynomial Construction (degree = threshold-1)     │
//! │         │    • P(x) = a₀ + a₁x + a₂x² + ... + aₙxⁿ             │
//! │         │    • a₀ = secret, a₁...aₙ = random                   │
//! │         │                                                        │
//! │         ├─── Evaluate Polynomial at Points                      │
//! │         │    • Share 1: P(1)                                    │
//! │         │    • Share 2: P(2)                                    │
//! │         │    • Share 3: P(3)                                    │
//! │         │    • Share 4: P(4)                                    │
//! │         │    • Share 5: P(5)                                    │
//! │         │                                                        │
//! │         └─── Validate: Reconstruct with threshold shares        │
//! │              (CRITICAL: Ensure reconstruction matches original) │
//! │                                                                  │
//! │         ▼                                                        │
//! │  [Share 1] [Share 2] [Share 3] [Share 4] [Share 5]              │
//! │     │          │          │          │          │               │
//! │     └──────────┴──────────┴──────────┴──────────┘               │
//! │                    │                                             │
//! │         Distribute to custodians                                │
//! │         (e.g., 5 different trustees)                            │
//! │                    │                                             │
//! │  ╔════════════════════════════════════════════════════╗         │
//! │  ║           RECOVERY SCENARIO                        ║         │
//! │  ╚════════════════════════════════════════════════════╝         │
//! │                    │                                             │
//! │         Collect threshold shares (3 out of 5)                   │
//! │                    │                                             │
//! │         ▼          ▼          ▼                                 │
//! │  [Share 2] [Share 3] [Share 5]                                  │
//! │         │          │          │                                 │
//! │         └──────────┴──────────┘                                 │
//! │                    │                                             │
//! │                    ▼                                             │
//! │         ┌──────────────────┐                                    │
//! │         │ recover_secret() │   Lagrange Interpolation           │
//! │         └──────────────────┘                                    │
//! │                    │                                             │
//! │         ├─── Verify threshold met (3 ≥ 3) ✓                    │
//! │         ├─── Verify share consistency                           │
//! │         └─── Lagrange interpolation to find P(0)                │
//! │                                                                  │
//! │                    ▼                                             │
//! │         [Master Key: 32 bytes]                                  │
//! │              (Reconstructed)                                    │
//! │                                                                  │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Properties
//!
//! - **Threshold Security**: Any k-1 shares reveal NO information about the secret
//! - **Perfect Secrecy**: Information-theoretically secure (not just computationally)
//! - **Share Independence**: Loss of shares up to threshold-1 doesn't compromise security
//! - **Validation**: Generated shares are automatically validated by test reconstruction
//!
//! # Common Configurations
//!
//! | Use Case | Threshold | Shares | Description |
//! |----------|-----------|--------|-------------|
//! | High Security | 3 | 5 | Require 3 custodians, tolerate 2 lost shares |
//! | Corporate | 2 | 3 | Require 2 executives, tolerate 1 lost share |
//! | Disaster Recovery | 5 | 7 | Require 5 regions, tolerate 2 lost shares |
//! | Critical Systems | 4 | 7 | Require 4 admins, high fault tolerance |
//!
//! # Examples
//!
//! ## Splitting a master key
//!
//! ```rust
//! use hsm_backup::shamir::{split_master_key, recover_master_key};
//!
//! // Original master key (32 bytes for AES-256)
//! let master_key = b"my_secret_master_key_32_bytes!!!";
//!
//! // Split into 5 shares, requiring 3 to reconstruct
//! let shares = split_master_key(master_key, 3, 5).unwrap();
//! assert_eq!(shares.len(), 5);
//!
//! // Each share contains metadata
//! assert_eq!(shares[0].threshold, 3);
//! assert_eq!(shares[0].total_shares, 5);
//!
//! // Distribute shares to different custodians
//! // In production: encrypt shares before storage
//! ```
//!
//! ## Recovering the master key
//!
//! ```rust
//! # use hsm_backup::shamir::{split_master_key, recover_master_key};
//! # let master_key = b"my_secret_master_key_32_bytes!!!";
//! # let shares = split_master_key(master_key, 3, 5).unwrap();
//!
//! // Collect at least 3 shares from custodians
//! let collected_shares = vec![
//!     shares[0].clone(),
//!     shares[2].clone(),
//!     shares[4].clone(),
//! ];
//!
//! // Recover the master key
//! let recovered = recover_master_key(&collected_shares).unwrap();
//! assert_eq!(recovered, master_key);
//! ```
//!
//! ## Share serialization for storage
//!
//! ```rust
//! use hsm_backup::shamir::{split_master_key, ShamirSecretSharing, ShamirConfig};
//!
//! # let master_key = b"my_secret_master_key_32_bytes!!!";
//! # let shares = split_master_key(master_key, 3, 5).unwrap();
//! let config = ShamirConfig::new(3, 5).unwrap();
//! let shamir = ShamirSecretSharing::new(config);
//!
//! // Serialize share to JSON for storage
//! let json = shamir.serialize_share(&shares[0]).unwrap();
//! // Store JSON to file, encrypted database, etc.
//!
//! // Later: deserialize from storage
//! let recovered_share = shamir.deserialize_share(&json).unwrap();
//! ```
//!
//! # Recovery Procedure
//!
//! In case of master key loss or disaster recovery:
//!
//! 1. **Identify Required Shares**: Determine threshold from share metadata
//! 2. **Collect Shares**: Gather at least threshold shares from custodians
//! 3. **Validate Shares**: Verify share consistency and count
//! 4. **Reconstruct Secret**: Use Lagrange interpolation to recover master key
//! 5. **Verify Recovery**: Confirm recovered key works for decryption
//! 6. **Re-split (Optional)**: Generate new shares and revoke old ones
//!
//! # Failure Scenarios
//!
//! ## Insufficient Shares
//! - **Problem**: Fewer than threshold shares collected
//! - **Error**: `BackupError::InsufficientShares`
//! - **Recovery**: Locate more shares or restore from backup
//!
//! ## Inconsistent Shares
//! - **Problem**: Shares from different splitting operations
//! - **Error**: `BackupError::InconsistentShares`
//! - **Recovery**: Verify shares belong to same set
//!
//! ## Corrupted Share
//! - **Problem**: Share data damaged or tampered
//! - **Error**: `BackupError::InvalidShare`
//! - **Recovery**: Use different share combination
//!
//! # Production Best Practices
//!
//! 1. **Encrypt Shares**: Never store shares in plaintext
//! 2. **Geographic Distribution**: Store shares in different physical locations
//! 3. **Access Control**: Require authentication to access shares
//! 4. **Audit Logging**: Log all share access and recovery attempts
//! 5. **Regular Testing**: Periodically test recovery procedure
//! 6. **Share Rotation**: Regenerate shares after recovery events
//! 7. **Minimum Threshold**: Use threshold ≥ 3 for production
//!
//! # Performance Characteristics
//!
//! - **Split Operation**: O(n·m) where n=shares, m=secret_size
//! - **Recovery Operation**: O(k·m) where k=threshold, m=secret_size
//! - **Validation Overhead**: ~2x split time (includes test reconstruction)
//!
//! # Security Considerations
//!
//! - Shares are zeroized on drop to prevent memory leaks
//! - Share validation ensures generated shares can reconstruct the secret
//! - No single share reveals any information about the secret
//! - System is information-theoretically secure (not just computationally)

use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BackupError, Result};

/// Configuration for Shamir's Secret Sharing
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ShamirConfig {
    /// Minimum number of shares needed to reconstruct the secret
    pub threshold: u8,
    /// Total number of shares to generate
    pub share_count: u8,
}

impl ShamirConfig {
    /// Create a new Shamir configuration
    pub fn new(threshold: u8, share_count: u8) -> Result<Self> {
        if threshold == 0 {
            return Err(BackupError::InvalidThreshold);
        }
        if share_count == 0 {
            return Err(BackupError::InvalidShareCount);
        }
        if threshold > share_count {
            return Err(BackupError::ThresholdExceedsShares);
        }
        if threshold == 1 {
            return Err(BackupError::InvalidThreshold);
        }

        Ok(Self {
            threshold,
            share_count,
        })
    }
}

/// A serializable share for storage
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SerializableShare {
    /// Share index (1-based)
    pub index: u8,
    /// Share data
    pub data: Vec<u8>,
    /// Threshold required for recovery
    pub threshold: u8,
    /// Total number of shares
    pub total_shares: u8,
}

/// Shamir's Secret Sharing manager
#[derive(ZeroizeOnDrop)]
pub struct ShamirSecretSharing {
    #[zeroize(skip)]
    sharks: Sharks,
    #[zeroize(skip)]
    config: ShamirConfig,
}

impl ShamirSecretSharing {
    /// Create a new Shamir Secret Sharing manager
    pub fn new(config: ShamirConfig) -> Self {
        let sharks = Sharks(config.threshold);
        Self { sharks, config }
    }

    /// Splits a secret into shares using Shamir's Secret Sharing.
    ///
    /// Uses polynomial interpolation to split the secret into multiple shares,
    /// where any threshold number of shares can reconstruct the original secret,
    /// but fewer than threshold shares reveal no information.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret data to split (e.g., master key)
    ///
    /// # Returns
    ///
    /// Returns a vector of `SerializableShare` objects, each containing:
    /// - Share index (1-based)
    /// - Share data
    /// - Threshold and total share count metadata
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Secret is empty (`BackupError::EmptyData`)
    /// - Share generation fails (`BackupError::ShareGenerationFailed`)
    /// - Share validation fails (`BackupError::ShareValidationFailed`)
    ///
    /// # Security
    ///
    /// **CRITICAL**: Generated shares are automatically validated by test reconstruction
    /// to ensure they can correctly recover the original secret. This prevents
    /// silent failures where shares appear valid but cannot reconstruct the secret.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use hsm_backup::shamir::{ShamirConfig, ShamirSecretSharing};
    ///
    /// let config = ShamirConfig::new(3, 5).unwrap();
    /// let shamir = ShamirSecretSharing::new(config);
    ///
    /// let master_key = b"my_secret_master_key_32_bytes!!!";
    /// let shares = shamir.split_secret(master_key).unwrap();
    ///
    /// assert_eq!(shares.len(), 5);
    /// assert_eq!(shares[0].threshold, 3);
    /// ```
    pub fn split_secret(&self, secret: &[u8]) -> Result<Vec<SerializableShare>> {
        if secret.is_empty() {
            return Err(BackupError::EmptyData);
        }

        // Generate shares using sharks
        let dealer = self.sharks.dealer(secret);
        let shares: Vec<Share> = dealer.take(self.config.share_count as usize).collect();

        if shares.len() != self.config.share_count as usize {
            return Err(BackupError::ShareGenerationFailed);
        }

        // Convert to serializable format
        let serializable_shares: Vec<SerializableShare> = shares
            .into_iter()
            .enumerate()
            .map(|(idx, share)| {
                let share_bytes = Vec::from(&share);
                SerializableShare {
                    index: (idx + 1) as u8,
                    data: share_bytes,
                    threshold: self.config.threshold,
                    total_shares: self.config.share_count,
                }
            })
            .collect();

        // CRITICAL: Validate shares by attempting reconstruction
        self.validate_generated_shares(&serializable_shares, secret)?;

        Ok(serializable_shares)
    }

    /// Validate generated shares (CRITICAL for security)
    fn validate_generated_shares(
        &self,
        shares: &[SerializableShare],
        original: &[u8],
    ) -> Result<()> {
        // Test reconstruction with minimum threshold
        let test_shares = &shares[..self.config.threshold as usize];
        let reconstructed = self.recover_secret(test_shares)?;

        // Verify reconstruction matches original
        if reconstructed != original {
            return Err(BackupError::ShareValidationFailed);
        }

        Ok(())
    }

    /// Recover a secret from shares
    pub fn recover_secret(&self, shares: &[SerializableShare]) -> Result<Vec<u8>> {
        if shares.is_empty() {
            return Err(BackupError::InsufficientShares);
        }

        if shares.len() < self.config.threshold as usize {
            return Err(BackupError::InsufficientShares);
        }

        // Verify all shares have consistent metadata
        let first_threshold = shares[0].threshold;
        let first_total = shares[0].total_shares;

        for share in shares.iter() {
            if share.threshold != first_threshold || share.total_shares != first_total {
                return Err(BackupError::InconsistentShares);
            }
        }

        // Convert to sharks Share format
        let sharks_shares: Result<Vec<Share>> = shares
            .iter()
            .map(|s| {
                Share::try_from(s.data.as_slice())
                    .map_err(|e| BackupError::InvalidShare(e.to_string()))
            })
            .collect();

        let sharks_shares = sharks_shares?;

        // Recover the secret
        let secret = self
            .sharks
            .recover(&sharks_shares)
            .map_err(|e| BackupError::RecoveryFailed(e.to_string()))?;

        Ok(secret)
    }

    /// Validate a set of shares without recovering
    pub fn validate_shares(&self, shares: &[SerializableShare]) -> Result<()> {
        if shares.is_empty() {
            return Err(BackupError::InsufficientShares);
        }

        // Check threshold
        if shares.len() < self.config.threshold as usize {
            return Err(BackupError::InsufficientShares);
        }

        // Verify metadata consistency
        let first_threshold = shares[0].threshold;
        let first_total = shares[0].total_shares;

        for share in shares.iter() {
            if share.threshold != first_threshold {
                return Err(BackupError::InconsistentShares);
            }
            if share.total_shares != first_total {
                return Err(BackupError::InconsistentShares);
            }
            if share.data.is_empty() {
                return Err(BackupError::InvalidShare("Empty share data".to_string()));
            }
        }

        Ok(())
    }

    /// Serialize a share to JSON
    pub fn serialize_share(&self, share: &SerializableShare) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(share).map_err(|e| BackupError::Serialization(e.to_string()))
    }

    /// Deserialize a share from JSON
    pub fn deserialize_share(&self, data: &[u8]) -> Result<SerializableShare> {
        serde_json::from_slice(data).map_err(|e| BackupError::Deserialization(e.to_string()))
    }
}

/// Split a master key into shares
pub fn split_master_key(
    master_key: &[u8],
    threshold: u8,
    share_count: u8,
) -> Result<Vec<SerializableShare>> {
    let config = ShamirConfig::new(threshold, share_count)?;
    let shamir = ShamirSecretSharing::new(config);
    shamir.split_secret(master_key)
}

/// Recover a master key from shares
pub fn recover_master_key(shares: &[SerializableShare]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(BackupError::InsufficientShares);
    }

    let threshold = shares[0].threshold;
    let total = shares[0].total_shares;

    let config = ShamirConfig::new(threshold, total)?;
    let shamir = ShamirSecretSharing::new(config);
    shamir.recover_secret(shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_config() {
        let config = ShamirConfig::new(3, 5).unwrap();
        assert_eq!(config.threshold, 3);
        assert_eq!(config.share_count, 5);
    }

    #[test]
    fn test_invalid_config() {
        assert!(ShamirConfig::new(0, 5).is_err());
        assert!(ShamirConfig::new(5, 0).is_err());
        assert!(ShamirConfig::new(6, 5).is_err());
        assert!(ShamirConfig::new(1, 5).is_err());
    }

    #[test]
    fn test_split_and_recover() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);

        let secret = b"my_secret_master_key_32_bytes!!!";
        let shares = shamir.split_secret(secret).unwrap();

        assert_eq!(shares.len(), 5);

        // Recover with exactly threshold shares
        let recovered = shamir.recover_secret(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        // Recover with more than threshold shares
        let recovered = shamir.recover_secret(&shares[0..4]).unwrap();
        assert_eq!(recovered, secret);

        // Recover with all shares
        let recovered = shamir.recover_secret(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);

        let secret = b"my_secret_master_key";
        let shares = shamir.split_secret(secret).unwrap();

        // Try to recover with fewer than threshold shares
        let result = shamir.recover_secret(&shares[0..2]);
        assert!(matches!(result, Err(BackupError::InsufficientShares)));
    }

    #[test]
    fn test_validate_shares() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);

        let secret = b"test_secret";
        let shares = shamir.split_secret(secret).unwrap();

        assert!(shamir.validate_shares(&shares[0..3]).is_ok());
        assert!(shamir.validate_shares(&shares).is_ok());
        assert!(matches!(
            shamir.validate_shares(&shares[0..2]),
            Err(BackupError::InsufficientShares)
        ));
    }

    #[test]
    fn test_serialize_deserialize_share() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);

        let secret = b"test_secret";
        let shares = shamir.split_secret(secret).unwrap();

        let json = shamir.serialize_share(&shares[0]).unwrap();
        let deserialized = shamir.deserialize_share(&json).unwrap();

        assert_eq!(deserialized.index, shares[0].index);
        assert_eq!(deserialized.data, shares[0].data);
        assert_eq!(deserialized.threshold, shares[0].threshold);
    }

    #[test]
    fn test_split_master_key_function() {
        let master_key = b"my_master_key_32_bytes_long!!!!!";
        let shares = split_master_key(master_key, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);
        assert_eq!(shares[0].threshold, 3);
    }

    #[test]
    fn test_recover_master_key_function() {
        let master_key = b"my_master_key_32_bytes_long!!!!!";
        let shares = split_master_key(master_key, 3, 5).unwrap();

        let recovered = recover_master_key(&shares[0..3]).unwrap();
        assert_eq!(recovered, master_key);
    }

    #[test]
    fn test_different_share_combinations() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);

        let secret = b"test_secret_data";
        let shares = shamir.split_secret(secret).unwrap();

        // Test different combinations of 3 shares
        let combos = vec![
            vec![&shares[0], &shares[1], &shares[2]],
            vec![&shares[0], &shares[2], &shares[4]],
            vec![&shares[1], &shares[3], &shares[4]],
        ];

        for combo in combos {
            let combo_owned: Vec<SerializableShare> = combo.iter().map(|&s| s.clone()).collect();
            let recovered = shamir.recover_secret(&combo_owned).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_empty_secret() {
        let config = ShamirConfig::new(3, 5).unwrap();
        let shamir = ShamirSecretSharing::new(config);

        let result = shamir.split_secret(&[]);
        assert!(matches!(result, Err(BackupError::EmptyData)));
    }
}
