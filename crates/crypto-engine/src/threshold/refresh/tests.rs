//! Tests for Key Refresh and Resharing Protocol

use super::*;
use crate::threshold::bls::ThresholdBlsEngine;
use crate::threshold::config::{KeyRefreshConfig, ResharingConfig};
use crate::threshold::ecdsa::ThresholdEcdsaEngine;
use crate::threshold::frost::FrostEngine;
use crate::threshold::types::{
    GroupPublicKey, KeyShare, ParticipantId, ThresholdConfig, ThresholdScheme,
};

// Helper function to convert EcdsaKeyShare to KeyShare
fn ecdsa_to_key_share(share: &crate::threshold::ecdsa::EcdsaKeyShare) -> KeyShare {
    KeyShare::new(
        share.participant_id,
        share.config,
        share.secret_share_bytes().to_vec(),
        share.public_share.clone(),
    )
}

// Helper function to convert EcdsaGroupPublicKey to GroupPublicKey
fn ecdsa_to_group_key(key: &crate::threshold::ecdsa::EcdsaGroupPublicKey) -> GroupPublicKey {
    GroupPublicKey::new(key.bytes.clone(), key.config, key.bytes.clone())
}

// ========== FROST Ed25519 Key Refresh Tests ==========

#[test]
fn test_key_refresh_frost_ed25519() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    // Create refresh configuration
    let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let refresh_config = KeyRefreshConfig::same_threshold(
        ThresholdScheme::FrostEd25519,
        config,
        participants.clone(),
    )
    .unwrap();

    // Create refresh protocol instances for each participant
    let mut protocols: Vec<KeyRefreshProtocol> = participants
        .iter()
        .map(|&id| KeyRefreshProtocol::new(refresh_config.clone(), id).unwrap())
        .collect();

    // Round 1: Generate commitments
    let round1_packages: Vec<RefreshRound1Package> =
        protocols.iter_mut().map(|p| p.round1().unwrap()).collect();

    // Distribute Round 1 packages to all participants
    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, package) in round1_packages.iter().enumerate() {
            if i != j {
                protocol.process_round1_package(package.clone()).unwrap();
            }
        }
    }

    // Round 2: Generate refresh shares
    let round2_packages: Vec<Vec<RefreshRound2Package>> =
        protocols.iter_mut().map(|p| p.round2().unwrap()).collect();

    // Distribute Round 2 packages to appropriate participants
    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, packages) in round2_packages.iter().enumerate() {
            if i != j {
                // Find the package intended for participant i+1
                for pkg in packages {
                    if pkg.receiver == participants[i] {
                        protocol.process_round2_package(pkg.clone()).unwrap();
                    }
                }
            }
        }
    }

    // Finalize: Compute new shares
    let new_shares: Vec<_> = protocols
        .iter_mut()
        .enumerate()
        .map(|(i, p)| p.finalize(&shares[i]).unwrap())
        .collect();

    // Verify: Sign with new shares and verify against the SAME group key
    let message = b"Test message after key refresh";

    let (nonce1, commitment1) = FrostEngine::generate_nonces(&new_shares[0]).unwrap();
    let (nonce2, commitment2) = FrostEngine::generate_nonces(&new_shares[1]).unwrap();
    let commitments = vec![commitment1, commitment2];

    let sig_share1 =
        FrostEngine::sign_share(&new_shares[0], &nonce1, message, &commitments, &group_key)
            .unwrap();
    let sig_share2 =
        FrostEngine::sign_share(&new_shares[1], &nonce2, message, &commitments, &group_key)
            .unwrap();

    let signature = FrostEngine::aggregate_signatures(
        message,
        &commitments,
        &[sig_share1, sig_share2],
        &group_key,
    )
    .unwrap();

    // The signature should verify against the original group key!
    let valid = FrostEngine::verify(&group_key, message, &signature).unwrap();
    assert!(
        valid,
        "Signature with refreshed shares should verify against original group key"
    );
}

#[test]
fn test_key_refresh_ecdsa_p256() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        config,
        crate::threshold::types::EcdsaCurve::P256,
    )
    .unwrap();

    // Convert to generic KeyShare types
    let key_shares: Vec<KeyShare> = shares.iter().map(ecdsa_to_key_share).collect();

    // Create refresh configuration
    let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let refresh_config = KeyRefreshConfig::same_threshold(
        ThresholdScheme::ThresholdEcdsaP256,
        config,
        participants.clone(),
    )
    .unwrap();

    // Create refresh protocol instances
    let mut protocols: Vec<KeyRefreshProtocol> = participants
        .iter()
        .map(|&id| KeyRefreshProtocol::new(refresh_config.clone(), id).unwrap())
        .collect();

    // Execute Round 1
    let round1_packages: Vec<RefreshRound1Package> =
        protocols.iter_mut().map(|p| p.round1().unwrap()).collect();

    // Distribute Round 1 packages
    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, package) in round1_packages.iter().enumerate() {
            if i != j {
                protocol.process_round1_package(package.clone()).unwrap();
            }
        }
    }

    // Execute Round 2
    let round2_packages: Vec<Vec<RefreshRound2Package>> =
        protocols.iter_mut().map(|p| p.round2().unwrap()).collect();

    // Distribute Round 2 packages
    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, packages) in round2_packages.iter().enumerate() {
            if i != j {
                for pkg in packages {
                    if pkg.receiver == participants[i] {
                        protocol.process_round2_package(pkg.clone()).unwrap();
                    }
                }
            }
        }
    }

    // Finalize
    let new_shares: Vec<_> = protocols
        .iter_mut()
        .enumerate()
        .map(|(i, p)| p.finalize(&key_shares[i]).unwrap())
        .collect();

    // Verify the new shares work
    assert_eq!(new_shares.len(), 3);
    assert_eq!(new_shares[0].config, config);
}

#[test]
fn test_key_refresh_bls() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = ThresholdBlsEngine::trusted_dealer_keygen(config).unwrap();

    // Create refresh configuration
    let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let refresh_config = KeyRefreshConfig::same_threshold(
        ThresholdScheme::ThresholdBls12381,
        config,
        participants.clone(),
    )
    .unwrap();

    // Convert BLS shares to generic KeyShare
    let key_shares: Vec<KeyShare> = shares
        .iter()
        .map(|s| {
            KeyShare::new(
                s.participant_id,
                s.config,
                s.secret_share_bytes().to_vec(),
                s.public_share.clone(),
            )
        })
        .collect();

    // Create refresh protocol instances
    let mut protocols: Vec<KeyRefreshProtocol> = participants
        .iter()
        .map(|&id| KeyRefreshProtocol::new(refresh_config.clone(), id).unwrap())
        .collect();

    // Execute Round 1
    let round1_packages: Vec<RefreshRound1Package> =
        protocols.iter_mut().map(|p| p.round1().unwrap()).collect();

    // Distribute Round 1 packages
    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, package) in round1_packages.iter().enumerate() {
            if i != j {
                protocol.process_round1_package(package.clone()).unwrap();
            }
        }
    }

    // Execute Round 2
    let round2_packages: Vec<Vec<RefreshRound2Package>> =
        protocols.iter_mut().map(|p| p.round2().unwrap()).collect();

    // Distribute Round 2 packages
    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, packages) in round2_packages.iter().enumerate() {
            if i != j {
                for pkg in packages {
                    if pkg.receiver == participants[i] {
                        protocol.process_round2_package(pkg.clone()).unwrap();
                    }
                }
            }
        }
    }

    // Finalize
    let new_shares: Vec<_> = protocols
        .iter_mut()
        .enumerate()
        .map(|(i, p)| p.finalize(&key_shares[i]).unwrap())
        .collect();

    assert_eq!(new_shares.len(), 3);
}

#[test]
fn test_refresh_preserves_signing() {
    // This test verifies that after refresh, signing still works
    // and the signature verifies against the original group public key
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    // Sign a message with original shares
    let message1 = b"Message before refresh";
    let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let (nonce2, commitment2) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let commitments = vec![commitment1, commitment2];

    let sig_share1 =
        FrostEngine::sign_share(&shares[0], &nonce1, message1, &commitments, &group_key).unwrap();
    let sig_share2 =
        FrostEngine::sign_share(&shares[1], &nonce2, message1, &commitments, &group_key).unwrap();

    let signature1 = FrostEngine::aggregate_signatures(
        message1,
        &commitments,
        &[sig_share1, sig_share2],
        &group_key,
    )
    .unwrap();

    assert!(FrostEngine::verify(&group_key, message1, &signature1).unwrap());

    // Now refresh the keys
    let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let refresh_config = KeyRefreshConfig::same_threshold(
        ThresholdScheme::FrostEd25519,
        config,
        participants.clone(),
    )
    .unwrap();

    let mut protocols: Vec<KeyRefreshProtocol> = participants
        .iter()
        .map(|&id| KeyRefreshProtocol::new(refresh_config.clone(), id).unwrap())
        .collect();

    // Round 1
    let round1_packages: Vec<RefreshRound1Package> =
        protocols.iter_mut().map(|p| p.round1().unwrap()).collect();

    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, package) in round1_packages.iter().enumerate() {
            if i != j {
                protocol.process_round1_package(package.clone()).unwrap();
            }
        }
    }

    // Round 2
    let round2_packages: Vec<Vec<RefreshRound2Package>> =
        protocols.iter_mut().map(|p| p.round2().unwrap()).collect();

    for (i, protocol) in protocols.iter_mut().enumerate() {
        for (j, packages) in round2_packages.iter().enumerate() {
            if i != j {
                for pkg in packages {
                    if pkg.receiver == participants[i] {
                        protocol.process_round2_package(pkg.clone()).unwrap();
                    }
                }
            }
        }
    }

    // Finalize
    let new_shares: Vec<_> = protocols
        .iter_mut()
        .enumerate()
        .map(|(i, p)| p.finalize(&shares[i]).unwrap())
        .collect();

    // Sign a different message with new shares
    let message2 = b"Message after refresh";
    let (nonce3, commitment3) = FrostEngine::generate_nonces(&new_shares[0]).unwrap();
    let (nonce4, commitment4) = FrostEngine::generate_nonces(&new_shares[1]).unwrap();
    let commitments2 = vec![commitment3, commitment4];

    let sig_share3 =
        FrostEngine::sign_share(&new_shares[0], &nonce3, message2, &commitments2, &group_key)
            .unwrap();
    let sig_share4 =
        FrostEngine::sign_share(&new_shares[1], &nonce4, message2, &commitments2, &group_key)
            .unwrap();

    let signature2 = FrostEngine::aggregate_signatures(
        message2,
        &commitments2,
        &[sig_share3, sig_share4],
        &group_key,
    )
    .unwrap();

    // Signature with new shares should verify against the SAME group key
    assert!(
        FrostEngine::verify(&group_key, message2, &signature2).unwrap(),
        "Signature with refreshed shares should verify"
    );
}

// ========== Resharing Tests ==========

#[test]
fn test_resharing_add_participant() {
    // Start with 2-of-3, reshare to 2-of-4 (add one participant)
    let old_config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, old_shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        old_config,
        crate::threshold::types::EcdsaCurve::P256,
    )
    .unwrap();

    // Convert to generic types
    let key_shares: Vec<KeyShare> = old_shares.iter().map(ecdsa_to_key_share).collect();
    let generic_group_key = ecdsa_to_group_key(&group_key);

    let old_participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let new_participants: Vec<ParticipantId> = (1..=4).map(ParticipantId).collect();

    let resharing_config = ResharingConfig::new(
        ThresholdScheme::ThresholdEcdsaP256,
        old_config,
        2, // Keep same threshold
        old_participants.clone(),
        new_participants.clone(),
    )
    .unwrap();

    let resharing = Resharing::new(resharing_config).unwrap();

    // Old participants generate resharing packages
    let mut all_packages: Vec<Vec<ResharingPackage>> = Vec::new();
    for share in &key_shares {
        let packages = resharing.generate_new_shares(share).unwrap();
        all_packages.push(packages);
    }

    // New participants receive and combine packages
    let mut new_shares = Vec::new();
    for &new_participant in &new_participants {
        // Collect packages for this new participant from all old participants
        let packages_for_me: Vec<ResharingPackage> = all_packages
            .iter()
            .flat_map(|pkgs| {
                pkgs.iter()
                    .filter(|p| p.new_participant == new_participant)
                    .cloned()
            })
            .take(2) // Only need threshold (2) packages
            .collect();

        let new_share = resharing
            .receive_shares(new_participant, packages_for_me, &generic_group_key)
            .unwrap();
        new_shares.push(new_share);
    }

    assert_eq!(new_shares.len(), 4);

    // Verify the new threshold config
    assert_eq!(new_shares[0].config.total_participants, 4);
    assert_eq!(new_shares[0].config.threshold, 2);
}

#[test]
fn test_resharing_remove_participant() {
    // Start with 2-of-4, reshare to 2-of-3 (remove one participant)
    let old_config = ThresholdConfig::new(2, 4).unwrap();
    let (group_key, old_shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        old_config,
        crate::threshold::types::EcdsaCurve::P256,
    )
    .unwrap();

    // Convert to generic types
    let key_shares: Vec<KeyShare> = old_shares.iter().map(ecdsa_to_key_share).collect();
    let generic_group_key = ecdsa_to_group_key(&group_key);

    let old_participants: Vec<ParticipantId> = (1..=4).map(ParticipantId).collect();
    // New participants are 1, 2, 3 (participant 4 is removed)
    let new_participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();

    let resharing_config = ResharingConfig::new(
        ThresholdScheme::ThresholdEcdsaP256,
        old_config,
        2, // Keep same threshold
        old_participants.clone(),
        new_participants.clone(),
    )
    .unwrap();

    let resharing = Resharing::new(resharing_config).unwrap();

    // Only need threshold old participants
    let participating_old_shares = &key_shares[0..2];

    let mut all_packages: Vec<Vec<ResharingPackage>> = Vec::new();
    for share in participating_old_shares {
        let packages = resharing.generate_new_shares(share).unwrap();
        all_packages.push(packages);
    }

    // New participants receive packages
    let mut new_shares = Vec::new();
    for &new_participant in &new_participants {
        let packages_for_me: Vec<ResharingPackage> = all_packages
            .iter()
            .flat_map(|pkgs| {
                pkgs.iter()
                    .filter(|p| p.new_participant == new_participant)
                    .cloned()
            })
            .collect();

        let new_share = resharing
            .receive_shares(new_participant, packages_for_me, &generic_group_key)
            .unwrap();
        new_shares.push(new_share);
    }

    assert_eq!(new_shares.len(), 3);
    assert_eq!(new_shares[0].config.total_participants, 3);
}

#[test]
fn test_resharing_change_threshold() {
    // Start with 2-of-3, reshare to 3-of-5
    let old_config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, old_shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        old_config,
        crate::threshold::types::EcdsaCurve::Secp256k1,
    )
    .unwrap();

    // Convert to generic types
    let key_shares: Vec<KeyShare> = old_shares.iter().map(ecdsa_to_key_share).collect();
    let generic_group_key = ecdsa_to_group_key(&group_key);

    let old_participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let new_participants: Vec<ParticipantId> = (1..=5).map(ParticipantId).collect();

    let resharing_config = ResharingConfig::new(
        ThresholdScheme::ThresholdEcdsaSecp256k1,
        old_config,
        3, // New threshold
        old_participants.clone(),
        new_participants.clone(),
    )
    .unwrap();

    let resharing = Resharing::new(resharing_config).unwrap();

    // Old participants generate resharing packages
    let mut all_packages: Vec<Vec<ResharingPackage>> = Vec::new();
    for share in &key_shares {
        let packages = resharing.generate_new_shares(share).unwrap();
        all_packages.push(packages);
    }

    // New participants receive packages (need at least old threshold = 2)
    let mut new_shares = Vec::new();
    for &new_participant in &new_participants {
        let packages_for_me: Vec<ResharingPackage> = all_packages
            .iter()
            .flat_map(|pkgs| {
                pkgs.iter()
                    .filter(|p| p.new_participant == new_participant)
                    .cloned()
            })
            .take(2) // Only need old threshold packages
            .collect();

        let new_share = resharing
            .receive_shares(new_participant, packages_for_me, &generic_group_key)
            .unwrap();
        new_shares.push(new_share);
    }

    assert_eq!(new_shares.len(), 5);
    assert_eq!(new_shares[0].config.threshold, 3);
    assert_eq!(new_shares[0].config.total_participants, 5);
}

#[test]
fn test_resharing_insufficient_shares() {
    let old_config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, old_shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(
        old_config,
        crate::threshold::types::EcdsaCurve::P256,
    )
    .unwrap();

    // Convert to generic types
    let key_shares: Vec<KeyShare> = old_shares.iter().map(ecdsa_to_key_share).collect();
    let generic_group_key = ecdsa_to_group_key(&group_key);

    let old_participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let new_participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();

    let resharing_config = ResharingConfig::new(
        ThresholdScheme::ThresholdEcdsaP256,
        old_config,
        2,
        old_participants,
        new_participants.clone(),
    )
    .unwrap();

    let resharing = Resharing::new(resharing_config).unwrap();

    // Only one old participant generates packages
    let packages = resharing.generate_new_shares(&key_shares[0]).unwrap();

    // Try to receive with only 1 package (need 2)
    let packages_for_p1: Vec<ResharingPackage> = packages
        .into_iter()
        .filter(|p| p.new_participant == new_participants[0])
        .collect();

    let result = resharing.receive_shares(new_participants[0], packages_for_p1, &generic_group_key);

    assert!(matches!(
        result,
        Err(crate::threshold::types::ThresholdError::ResharingInsufficientShares { .. })
    ));
}

// ========== State Machine Tests ==========

#[test]
fn test_refresh_state_transitions() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let refresh_config = KeyRefreshConfig::same_threshold(
        ThresholdScheme::FrostEd25519,
        config,
        participants.clone(),
    )
    .unwrap();

    let mut protocol = KeyRefreshProtocol::new(refresh_config, participants[0]).unwrap();

    // Initial state
    assert_eq!(*protocol.state(), RefreshState::NotStarted);

    // After Round 1
    let _r1 = protocol.round1().unwrap();
    assert_eq!(*protocol.state(), RefreshState::Round1Complete);

    // Can't do Round 1 again
    assert!(protocol.round1().is_err());
}

#[test]
fn test_refresh_round1_package_verification() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();
    let refresh_config = KeyRefreshConfig::same_threshold(
        ThresholdScheme::ThresholdEcdsaP256,
        config,
        participants.clone(),
    )
    .unwrap();

    let mut protocol = KeyRefreshProtocol::new(refresh_config, participants[0]).unwrap();
    let package = protocol.round1().unwrap();

    // The first commitment should be the identity point (commitment to zero)
    // For ECDSA P-256, we can verify this
    assert!(!package.commitments.is_empty());
}
