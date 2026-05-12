//! Integration tests for Shamir's Secret Sharing functionality.

use hsm_backup::{
    recover_master_key, split_master_key, BackupError, SerializableShare, ShamirConfig,
    ShamirSecretSharing,
};

#[test]
fn test_shamir_split_recover_basic() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let secret = b"my_secret_master_key_32_bytes!!!";
    let shares = shamir.split_secret(secret).unwrap();

    assert_eq!(shares.len(), 5);

    // Verify each share has correct metadata
    for share in &shares {
        assert_eq!(share.threshold, 3);
        assert_eq!(share.total_shares, 5);
        assert!(share.data.len() > 0);
    }

    // Recover with exactly threshold shares
    let recovered = shamir.recover_secret(&shares[0..3]).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn test_shamir_different_combinations() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let secret = b"test_secret_data_here";
    let shares = shamir.split_secret(secret).unwrap();

    // Test different combinations of 3 shares
    let combinations = vec![
        vec![&shares[0], &shares[1], &shares[2]],
        vec![&shares[0], &shares[2], &shares[4]],
        vec![&shares[1], &shares[3], &shares[4]],
        vec![&shares[2], &shares[3], &shares[4]],
    ];

    for combo in combinations {
        let combo_owned: Vec<SerializableShare> = combo.iter().map(|&s| s.clone()).collect();
        let recovered = shamir.recover_secret(&combo_owned).unwrap();
        assert_eq!(recovered, secret);
    }
}

#[test]
fn test_shamir_insufficient_shares() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let secret = b"secret_data";
    let shares = shamir.split_secret(secret).unwrap();

    // Try to recover with only 2 shares (need 3)
    let result = shamir.recover_secret(&shares[0..2]);
    assert!(matches!(result, Err(BackupError::InsufficientShares)));

    // Try with only 1 share
    let result = shamir.recover_secret(&shares[0..1]);
    assert!(matches!(result, Err(BackupError::InsufficientShares)));
}

#[test]
fn test_shamir_config_validation() {
    // Valid configs
    assert!(ShamirConfig::new(3, 5).is_ok());
    assert!(ShamirConfig::new(2, 3).is_ok());
    assert!(ShamirConfig::new(5, 5).is_ok());

    // Invalid configs
    assert!(matches!(
        ShamirConfig::new(0, 5),
        Err(BackupError::InvalidThreshold)
    ));
    assert!(matches!(
        ShamirConfig::new(3, 0),
        Err(BackupError::InvalidShareCount)
    ));
    assert!(matches!(
        ShamirConfig::new(6, 5),
        Err(BackupError::ThresholdExceedsShares)
    ));
    assert!(matches!(
        ShamirConfig::new(1, 5),
        Err(BackupError::InvalidThreshold)
    ));
}

#[test]
fn test_shamir_share_serialization() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let secret = b"test_secret";
    let shares = shamir.split_secret(secret).unwrap();

    // Serialize and deserialize each share
    for original_share in &shares {
        let json = shamir.serialize_share(original_share).unwrap();

        // Verify it's valid JSON
        assert!(json.len() > 0);

        let deserialized = shamir.deserialize_share(&json).unwrap();

        assert_eq!(deserialized.index, original_share.index);
        assert_eq!(deserialized.data, original_share.data);
        assert_eq!(deserialized.threshold, original_share.threshold);
        assert_eq!(deserialized.total_shares, original_share.total_shares);
    }
}

#[test]
fn test_shamir_share_validation() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let secret = b"test_secret";
    let shares = shamir.split_secret(secret).unwrap();

    // Valid shares
    assert!(shamir.validate_shares(&shares).is_ok());
    assert!(shamir.validate_shares(&shares[0..3]).is_ok());
    assert!(shamir.validate_shares(&shares[0..4]).is_ok());

    // Insufficient shares
    assert!(matches!(
        shamir.validate_shares(&shares[0..2]),
        Err(BackupError::InsufficientShares)
    ));

    // Empty shares
    assert!(matches!(
        shamir.validate_shares(&[]),
        Err(BackupError::InsufficientShares)
    ));
}

#[test]
fn test_shamir_inconsistent_shares() {
    let shamir = ShamirSecretSharing::new(ShamirConfig::new(3, 5).unwrap());

    let mut shares = shamir.split_secret(b"test").unwrap();

    // Modify one share to have inconsistent threshold
    shares[1].threshold = 2;

    let result = shamir.validate_shares(&shares);
    assert!(matches!(result, Err(BackupError::InconsistentShares)));

    // Fix threshold, break total_shares
    shares[1].threshold = 3;
    shares[1].total_shares = 4;

    let result = shamir.validate_shares(&shares);
    assert!(matches!(result, Err(BackupError::InconsistentShares)));
}

#[test]
fn test_shamir_empty_secret() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let result = shamir.split_secret(&[]);
    assert!(matches!(result, Err(BackupError::EmptyData)));
}

#[test]
fn test_split_recover_master_key_functions() {
    let master_key = b"master_key_32_bytes_long_data!!!";

    // Split the master key
    let shares = split_master_key(master_key, 3, 5).unwrap();

    assert_eq!(shares.len(), 5);

    // Recover with minimum shares
    let recovered = recover_master_key(&shares[0..3]).unwrap();
    assert_eq!(recovered, master_key);

    // Recover with all shares
    let recovered = recover_master_key(&shares).unwrap();
    assert_eq!(recovered, master_key);
}

#[test]
fn test_large_secret_splitting() {
    let config = ShamirConfig::new(5, 10).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    // Create a 1KB secret
    let large_secret = vec![0x42u8; 1024];
    let shares = shamir.split_secret(&large_secret).unwrap();

    assert_eq!(shares.len(), 10);

    // Recover with exactly threshold
    let recovered = shamir.recover_secret(&shares[0..5]).unwrap();
    assert_eq!(recovered, large_secret);

    // Recover with more than threshold
    let recovered = shamir.recover_secret(&shares[0..7]).unwrap();
    assert_eq!(recovered, large_secret);
}

#[test]
fn test_multiple_split_operations() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    for i in 0..10 {
        let secret = format!("secret_number_{}", i);
        let shares = shamir.split_secret(secret.as_bytes()).unwrap();
        let recovered = shamir.recover_secret(&shares[0..3]).unwrap();

        assert_eq!(recovered, secret.as_bytes());
    }
}

#[test]
fn test_shamir_with_various_thresholds() {
    let test_cases = vec![(2, 3), (3, 5), (5, 7), (7, 10), (10, 15)];

    for (threshold, total) in test_cases {
        let config = ShamirConfig::new(threshold, total).unwrap();
        let shamir = ShamirSecretSharing::new(config);

        let secret = b"test_secret_data";
        let shares = shamir.split_secret(secret).unwrap();

        assert_eq!(shares.len(), total as usize);

        let recovered = shamir
            .recover_secret(&shares[0..threshold as usize])
            .unwrap();
        assert_eq!(recovered, secret);
    }
}

#[test]
fn test_share_index_uniqueness() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let shares = shamir.split_secret(b"test").unwrap();

    // Verify all indices are unique
    let mut indices = std::collections::HashSet::new();
    for share in &shares {
        assert!(indices.insert(share.index));
    }

    assert_eq!(indices.len(), 5);
}

#[test]
fn test_recover_empty_shares() {
    let config = ShamirConfig::new(3, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let result = shamir.recover_secret(&[]);
    assert!(matches!(result, Err(BackupError::InsufficientShares)));
}

#[test]
fn test_maximum_threshold() {
    // Test with threshold equal to total shares
    let config = ShamirConfig::new(5, 5).unwrap();
    let shamir = ShamirSecretSharing::new(config);

    let secret = b"test_secret";
    let shares = shamir.split_secret(secret).unwrap();

    // Need all 5 shares to recover
    let recovered = shamir.recover_secret(&shares).unwrap();
    assert_eq!(recovered, secret);

    // Cannot recover with 4 shares
    let result = shamir.recover_secret(&shares[0..4]);
    assert!(matches!(result, Err(BackupError::InsufficientShares)));
}

#[test]
fn test_serialized_shares_roundtrip() {
    let master_key = b"test_master_key_data_32_bytes!!!";
    let shares = split_master_key(master_key, 3, 5).unwrap();

    // Serialize all shares to JSON
    let json_shares: Vec<Vec<u8>> = shares
        .iter()
        .map(|s| serde_json::to_vec(s).unwrap())
        .collect();

    // Deserialize them back
    let deserialized_shares: Vec<SerializableShare> = json_shares
        .iter()
        .map(|j| serde_json::from_slice(j).unwrap())
        .collect();

    // Recover the master key
    let recovered = recover_master_key(&deserialized_shares[0..3]).unwrap();
    assert_eq!(recovered, master_key);
}

#[test]
fn test_concurrent_split_operations() {
    use std::sync::Arc;
    use std::thread;

    let config = Arc::new(ShamirConfig::new(3, 5).unwrap());
    let mut handles = vec![];

    for i in 0..10 {
        let config = Arc::clone(&config);
        let handle = thread::spawn(move || {
            let shamir = ShamirSecretSharing::new(*config);
            let secret = format!("secret_{}", i);
            shamir.split_secret(secret.as_bytes()).unwrap()
        });
        handles.push(handle);
    }

    for handle in handles {
        let shares = handle.join().unwrap();
        assert_eq!(shares.len(), 5);
    }
}
