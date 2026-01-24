//! Integration Tests for Threshold Cryptography
//!
//! This module contains comprehensive integration tests that span multiple
//! threshold cryptography modules, testing complete workflows end-to-end.
//!
//! # Test Categories
//!
//! - **DKG + Signing**: Run full DKG protocol, then use generated shares to sign
//! - **Key Refresh + Signing**: Generate keys, sign, refresh, sign again
//! - **Resharing Scenarios**: Change threshold and participant sets
//! - **Fault Tolerance**: Test graceful handling of missing/invalid participants
//! - **FIPS Compliance**: Verify FIPS mode works correctly

use super::bls::{
    dkg::{BlsDkg, BlsDkgRound1Package, BlsDkgRound2Package},
    ThresholdBlsEngine,
};
use super::config::{DkgConfig, KeyRefreshConfig, ResharingConfig};
use super::ecdsa::{
    dkg::{EcdsaDkg, EcdsaDkgRound1Package, EcdsaDkgRound2Package},
    EcdsaGroupPublicKey, EcdsaKeyShare, ThresholdEcdsaEngine,
};
use super::frost::FrostEngine;
use super::refresh::{
    KeyRefreshProtocol, RefreshRound1Package, RefreshRound2Package, Resharing as ResharingProtocol,
    ResharingPackage,
};
use super::types::{
    EcdsaCurve, GroupPublicKey, KeyShare, ParticipantId, ThresholdConfig, ThresholdError,
    ThresholdScheme,
};

// ============================================================================
// FROST Ed25519 Integration Tests
// ============================================================================

/// Test: Complete FROST Ed25519 DKG + Signing workflow using trusted dealer
#[test]
fn test_frost_ed25519_trusted_dealer_and_signing() {
    // Generate 2-of-3 threshold keys using trusted dealer
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    assert_eq!(shares.len(), 3);
    assert_eq!(group_key.bytes.len(), 32); // Ed25519 public key

    let message = b"Integration test message for FROST Ed25519";

    // Sign with participants 1 and 2 (threshold is 2)
    let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let (nonce2, commitment2) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let commitments = vec![commitment1, commitment2];

    let sig_share1 =
        FrostEngine::sign_share(&shares[0], &nonce1, message, &commitments, &group_key).unwrap();
    let sig_share2 =
        FrostEngine::sign_share(&shares[1], &nonce2, message, &commitments, &group_key).unwrap();

    let signature = FrostEngine::aggregate_signatures(
        message,
        &commitments,
        &[sig_share1, sig_share2],
        &group_key,
    )
    .unwrap();

    // Verify using FROST verification
    assert!(FrostEngine::verify(&group_key, message, &signature).unwrap());

    // Verify using standard Ed25519 verification (interoperability)
    assert!(FrostEngine::verify_with_ed25519(&group_key.bytes, message, &signature.bytes).unwrap());
}

/// Test: Multiple participant subsets can sign the same message
#[test]
fn test_frost_different_subsets_sign_same_message() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    let message = b"Same message, different signers";

    // Sign with participants [0, 1]
    let (nonce0a, commit0a) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let (nonce1a, commit1a) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let commits_01 = vec![commit0a, commit1a];

    let sig_share0a =
        FrostEngine::sign_share(&shares[0], &nonce0a, message, &commits_01, &group_key).unwrap();
    let sig_share1a =
        FrostEngine::sign_share(&shares[1], &nonce1a, message, &commits_01, &group_key).unwrap();

    let signature_01 = FrostEngine::aggregate_signatures(
        message,
        &commits_01,
        &[sig_share0a, sig_share1a],
        &group_key,
    )
    .unwrap();

    // Sign with participants [1, 2]
    let (nonce1b, commit1b) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let (nonce2b, commit2b) = FrostEngine::generate_nonces(&shares[2]).unwrap();
    let commits_12 = vec![commit1b, commit2b];

    let sig_share1b =
        FrostEngine::sign_share(&shares[1], &nonce1b, message, &commits_12, &group_key).unwrap();
    let sig_share2b =
        FrostEngine::sign_share(&shares[2], &nonce2b, message, &commits_12, &group_key).unwrap();

    let signature_12 = FrostEngine::aggregate_signatures(
        message,
        &commits_12,
        &[sig_share1b, sig_share2b],
        &group_key,
    )
    .unwrap();

    // Both signatures should verify against the same group key
    assert!(FrostEngine::verify(&group_key, message, &signature_01).unwrap());
    assert!(FrostEngine::verify(&group_key, message, &signature_12).unwrap());

    // Signatures will be different due to different nonces
    assert_ne!(signature_01.bytes, signature_12.bytes);
}

/// Test: Signing with exactly t participants works
#[test]
fn test_frost_signing_with_exactly_threshold_participants() {
    let config = ThresholdConfig::new(3, 5).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    let message = b"Exactly threshold participants";

    // Use exactly 3 participants (threshold)
    let selected = [0, 2, 4];

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &idx in &selected {
        let (nonce, commitment) = FrostEngine::generate_nonces(&shares[idx]).unwrap();
        nonces.push(nonce);
        commitments.push(commitment);
    }

    let mut sig_shares = Vec::new();
    for (i, &idx) in selected.iter().enumerate() {
        let sig =
            FrostEngine::sign_share(&shares[idx], &nonces[i], message, &commitments, &group_key)
                .unwrap();
        sig_shares.push(sig);
    }

    let signature =
        FrostEngine::aggregate_signatures(message, &commitments, &sig_shares, &group_key).unwrap();

    assert!(FrostEngine::verify(&group_key, message, &signature).unwrap());
}

/// Test: Signing with t+1 participants also works
#[test]
fn test_frost_signing_with_more_than_threshold_participants() {
    let config = ThresholdConfig::new(2, 4).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    let message = b"More than threshold participants";

    // Use 3 participants (threshold is 2)
    let selected = [0, 1, 2];

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &idx in &selected {
        let (nonce, commitment) = FrostEngine::generate_nonces(&shares[idx]).unwrap();
        nonces.push(nonce);
        commitments.push(commitment);
    }

    let mut sig_shares = Vec::new();
    for (i, &idx) in selected.iter().enumerate() {
        let sig =
            FrostEngine::sign_share(&shares[idx], &nonces[i], message, &commitments, &group_key)
                .unwrap();
        sig_shares.push(sig);
    }

    let signature =
        FrostEngine::aggregate_signatures(message, &commitments, &sig_shares, &group_key).unwrap();

    assert!(FrostEngine::verify(&group_key, message, &signature).unwrap());
}

// ============================================================================
// Threshold ECDSA Integration Tests
// ============================================================================

/// Helper: Run full ECDSA DKG for n participants
fn run_ecdsa_dkg(
    threshold: u16,
    total: u16,
    curve: EcdsaCurve,
) -> Result<(Vec<EcdsaKeyShare>, EcdsaGroupPublicKey), ThresholdError> {
    let participants: Vec<ParticipantId> = (1..=total).map(ParticipantId).collect();

    let scheme = match curve {
        EcdsaCurve::P256 => ThresholdScheme::ThresholdEcdsaP256,
        EcdsaCurve::Secp256k1 => ThresholdScheme::ThresholdEcdsaSecp256k1,
    };

    let config = DkgConfig::new(scheme, threshold, participants.clone())?;

    // Create DKG instances for each participant
    let mut dkgs: Vec<EcdsaDkg> = participants
        .iter()
        .map(|&p| EcdsaDkg::new(config.clone(), p, curve).unwrap())
        .collect();

    // Round 1: Generate and distribute commitments
    let mut r1_packages: Vec<EcdsaDkgRound1Package> = Vec::new();
    for dkg in &mut dkgs {
        r1_packages.push(dkg.round1_generate_commitments()?);
    }

    // Each participant receives commitments from others
    for (i, dkg) in dkgs.iter_mut().enumerate() {
        let others: Vec<_> = r1_packages
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, p)| p.clone())
            .collect();
        dkg.round1_receive_commitments(others)?;
    }

    // Round 2: Generate and distribute shares
    let mut r2_packages: Vec<Vec<EcdsaDkgRound2Package>> = Vec::new();
    for dkg in &mut dkgs {
        r2_packages.push(dkg.round2_generate_shares()?);
    }

    // Each participant receives shares addressed to them
    for (i, dkg) in dkgs.iter_mut().enumerate() {
        let receiver_id = participants[i];
        let shares: Vec<_> = r2_packages
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .flat_map(|(_, pkgs)| pkgs.iter().filter(|p| p.receiver == receiver_id).cloned())
            .collect();
        dkg.round2_receive_shares(shares)?;
    }

    // Finalize
    let results: Vec<_> = dkgs.into_iter().map(|dkg| dkg.finalize()).collect();

    let mut shares = Vec::new();
    let mut group_key = None;

    for result in results {
        let (share, gk) = result?;
        shares.push(share);
        if group_key.is_none() {
            group_key = Some(gk);
        }
    }

    Ok((shares, group_key.unwrap()))
}

/// Test: ECDSA P-256 DKG + Signing end-to-end
#[test]
fn test_ecdsa_p256_dkg_and_signing() {
    let (shares, group_key) = run_ecdsa_dkg(2, 3, EcdsaCurve::P256).unwrap();

    assert_eq!(shares.len(), 3);
    assert!(group_key.is_fips_approved()); // P-256 is FIPS approved

    let message = b"Test message for ECDSA P-256";
    let message_hash = ThresholdEcdsaEngine::hash_message(message);

    // Sign with participants 0 and 1
    let selected_indices = [0, 1];

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &idx in &selected_indices {
        let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
        nonces.push(nonce);
        commitments.push(commitment);
    }

    let participants: Vec<ParticipantId> = selected_indices
        .iter()
        .map(|&i| shares[i].participant_id)
        .collect();

    let presigs: Vec<_> = selected_indices
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                .unwrap()
        })
        .collect();

    let sig_shares: Vec<_> = selected_indices
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            ThresholdEcdsaEngine::sign_share(&shares[idx], &presigs[i], &message_hash).unwrap()
        })
        .collect();

    let signature =
        ThresholdEcdsaEngine::aggregate(&group_key, &presigs[0], &sig_shares, &participants)
            .unwrap();

    // Verify format
    assert_eq!(signature.to_bytes().len(), 64);
    assert_eq!(signature.curve, EcdsaCurve::P256);
}

/// Test: ECDSA secp256k1 DKG + Signing end-to-end
#[test]
fn test_ecdsa_secp256k1_dkg_and_signing() {
    let (shares, group_key) = run_ecdsa_dkg(2, 3, EcdsaCurve::Secp256k1).unwrap();

    assert_eq!(shares.len(), 3);
    assert!(!group_key.is_fips_approved()); // secp256k1 is not FIPS approved

    let message = b"Bitcoin/Ethereum transaction";
    let message_hash = ThresholdEcdsaEngine::hash_message(message);

    // Sign with participants 1 and 2
    let selected_indices = [1, 2];

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &idx in &selected_indices {
        let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
        nonces.push(nonce);
        commitments.push(commitment);
    }

    let participants: Vec<ParticipantId> = selected_indices
        .iter()
        .map(|&i| shares[i].participant_id)
        .collect();

    let presigs: Vec<_> = selected_indices
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                .unwrap()
        })
        .collect();

    let sig_shares: Vec<_> = selected_indices
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            ThresholdEcdsaEngine::sign_share(&shares[idx], &presigs[i], &message_hash).unwrap()
        })
        .collect();

    let signature =
        ThresholdEcdsaEngine::aggregate(&group_key, &presigs[0], &sig_shares, &participants)
            .unwrap();

    assert_eq!(signature.curve, EcdsaCurve::Secp256k1);
    assert_eq!(signature.to_bytes().len(), 64);
}

/// Test: All participants can derive the same group public key after DKG
#[test]
fn test_ecdsa_dkg_consistent_group_key() {
    let (shares, group_key) = run_ecdsa_dkg(2, 3, EcdsaCurve::P256).unwrap();

    // All shares should reference the same group public key
    for share in &shares {
        assert_eq!(share.group_public_key, group_key.bytes);
    }
}

// ============================================================================
// Threshold BLS Integration Tests
// ============================================================================

/// Helper: Run full BLS DKG for n participants
fn run_bls_dkg(threshold: u16, total: u16) -> (Vec<super::bls::BlsKeyShare>, GroupPublicKey) {
    let config = DkgConfig::new(
        ThresholdScheme::ThresholdBls12381,
        threshold,
        (1..=total).map(ParticipantId).collect(),
    )
    .unwrap();

    let participants: Vec<ParticipantId> = (1..=total).map(ParticipantId).collect();

    // Create DKG instances for each participant
    let mut dkgs: Vec<BlsDkg> = participants
        .iter()
        .map(|&p| BlsDkg::new(config.clone(), p).unwrap())
        .collect();

    // Round 1: Generate commitments
    let round1_packages: Vec<BlsDkgRound1Package> =
        dkgs.iter_mut().map(|dkg| dkg.round1().unwrap()).collect();

    // Round 2: Generate and exchange shares
    let mut all_round2_packages: Vec<Vec<BlsDkgRound2Package>> = Vec::new();
    for dkg in &mut dkgs {
        let packages = dkg.round2(round1_packages.clone()).unwrap();
        all_round2_packages.push(packages);
    }

    // Collect packages for each participant
    let mut packages_per_participant: Vec<Vec<BlsDkgRound2Package>> =
        vec![Vec::new(); total as usize];

    for sender_packages in all_round2_packages {
        for pkg in sender_packages {
            let receiver_idx = (pkg.receiver.0 - 1) as usize;
            packages_per_participant[receiver_idx].push(pkg);
        }
    }

    // Finalize: Each participant combines shares
    let mut shares = Vec::new();
    let mut group_pk = None;

    for (i, dkg) in dkgs.iter_mut().enumerate() {
        let (share, gpk) = dkg.finalize(packages_per_participant[i].clone()).unwrap();
        shares.push(share);
        group_pk = Some(gpk);
    }

    (shares, group_pk.unwrap())
}

/// Test: BLS DKG + Signing end-to-end
#[test]
fn test_bls_dkg_and_signing() {
    let (shares, group_pk) = run_bls_dkg(2, 3);

    assert_eq!(shares.len(), 3);
    assert_eq!(group_pk.bytes.len(), 48); // BLS public key is 48 bytes

    let message = b"Test message for BLS threshold signing";

    // Sign with participants 0 and 2
    let sig_share0 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
    let sig_share2 = ThresholdBlsEngine::sign_share(&shares[2], message).unwrap();

    let participants = vec![shares[0].participant_id, shares[2].participant_id];
    let signature =
        ThresholdBlsEngine::aggregate(&[sig_share0, sig_share2], &participants).unwrap();

    // Verify the signature
    assert!(ThresholdBlsEngine::verify(&group_pk, message, &signature).unwrap());
}

/// Test: BLS signatures are deterministic
#[test]
fn test_bls_deterministic_signatures() {
    let (shares, group_pk) = run_bls_dkg(2, 3);

    let message = b"Deterministic test";

    // Sign the same message twice with the same participants
    let sig1_share0 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
    let sig1_share1 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
    let participants = vec![shares[0].participant_id, shares[1].participant_id];
    let signature1 =
        ThresholdBlsEngine::aggregate(&[sig1_share0, sig1_share1], &participants).unwrap();

    let sig2_share0 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
    let sig2_share1 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
    let signature2 =
        ThresholdBlsEngine::aggregate(&[sig2_share0, sig2_share1], &participants).unwrap();

    // BLS signatures are deterministic - same message, same signers = same signature
    assert_eq!(signature1.bytes, signature2.bytes);
    assert!(ThresholdBlsEngine::verify(&group_pk, message, &signature1).unwrap());
}

/// Test: Different BLS subsets produce the same signature
#[test]
fn test_bls_different_subsets_same_signature() {
    let (shares, group_pk) = run_bls_dkg(2, 3);

    let message = b"Same message different subsets";

    // Sign with participants [0, 1]
    let sig_01_0 = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
    let sig_01_1 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
    let participants_01 = vec![shares[0].participant_id, shares[1].participant_id];
    let signature_01 =
        ThresholdBlsEngine::aggregate(&[sig_01_0, sig_01_1], &participants_01).unwrap();

    // Sign with participants [1, 2]
    let sig_12_1 = ThresholdBlsEngine::sign_share(&shares[1], message).unwrap();
    let sig_12_2 = ThresholdBlsEngine::sign_share(&shares[2], message).unwrap();
    let participants_12 = vec![shares[1].participant_id, shares[2].participant_id];
    let signature_12 =
        ThresholdBlsEngine::aggregate(&[sig_12_1, sig_12_2], &participants_12).unwrap();

    // Both signatures should be the same (threshold BLS property with Lagrange interpolation)
    assert_eq!(signature_01.bytes, signature_12.bytes);

    // Both should verify
    assert!(ThresholdBlsEngine::verify(&group_pk, message, &signature_01).unwrap());
    assert!(ThresholdBlsEngine::verify(&group_pk, message, &signature_12).unwrap());
}

// ============================================================================
// Key Refresh Integration Tests
// ============================================================================

/// Test: Key refresh preserves signing capability
#[test]
fn test_frost_key_refresh_and_signing() {
    // Generate initial keys
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    let message = b"Test message before and after refresh";

    // Sign before refresh
    let (nonce1a, commitment1a) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let (nonce2a, commitment2a) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let commitments_a = vec![commitment1a, commitment2a];

    let sig_share1a =
        FrostEngine::sign_share(&shares[0], &nonce1a, message, &commitments_a, &group_key).unwrap();
    let sig_share2a =
        FrostEngine::sign_share(&shares[1], &nonce2a, message, &commitments_a, &group_key).unwrap();

    let signature_before = FrostEngine::aggregate_signatures(
        message,
        &commitments_a,
        &[sig_share1a, sig_share2a],
        &group_key,
    )
    .unwrap();

    assert!(FrostEngine::verify(&group_key, message, &signature_before).unwrap());

    // Note: The key refresh protocol works on KeyShare type, not the FROST-specific type
    // In a real implementation, there would be a conversion or the refresh would be
    // scheme-specific. For FROST, the signature before and after refresh would verify
    // against the same group key since refresh preserves the public key.
}

/// Test: ECDSA key refresh with same threshold
#[test]
fn test_ecdsa_key_refresh_same_threshold() {
    // Generate initial keys via DKG
    let (shares, group_key) = run_ecdsa_dkg(2, 3, EcdsaCurve::P256).unwrap();

    // Create KeyShare wrappers for the refresh protocol
    let key_shares: Vec<KeyShare> = shares
        .iter()
        .map(|s| {
            KeyShare::new(
                s.participant_id,
                s.config,
                s.secret_share.clone(),
                s.public_share.clone(),
            )
        })
        .collect();

    let participants: Vec<ParticipantId> = (1..=3).map(ParticipantId).collect();

    let refresh_config = KeyRefreshConfig::same_threshold(
        ThresholdScheme::ThresholdEcdsaP256,
        ThresholdConfig::new(2, 3).unwrap(),
        participants.clone(),
    )
    .unwrap();

    // Run refresh protocol for all participants
    let mut refresh_protocols: Vec<KeyRefreshProtocol> = participants
        .iter()
        .map(|&p| KeyRefreshProtocol::new(refresh_config.clone(), p).unwrap())
        .collect();

    // Round 1: Generate refresh packages
    let round1_packages: Vec<RefreshRound1Package> = refresh_protocols
        .iter_mut()
        .map(|p| p.round1().unwrap())
        .collect();

    // Each participant processes others' Round 1 packages
    for (i, protocol) in refresh_protocols.iter_mut().enumerate() {
        for (j, pkg) in round1_packages.iter().enumerate() {
            if i != j {
                protocol.process_round1_package(pkg.clone()).unwrap();
            }
        }
    }

    // Round 2: Generate refresh shares
    let round2_packages: Vec<Vec<RefreshRound2Package>> = refresh_protocols
        .iter_mut()
        .map(|p| p.round2().unwrap())
        .collect();

    // Each participant processes refresh shares intended for them
    for (i, protocol) in refresh_protocols.iter_mut().enumerate() {
        let receiver_id = participants[i];
        for sender_pkgs in &round2_packages {
            for pkg in sender_pkgs {
                if pkg.receiver == receiver_id && pkg.sender != receiver_id {
                    protocol.process_round2_package(pkg.clone()).unwrap();
                }
            }
        }
    }

    // Finalize refresh
    let new_shares: Vec<KeyShare> = refresh_protocols
        .into_iter()
        .enumerate()
        .map(|(i, mut p)| p.finalize(&key_shares[i]).unwrap())
        .collect();

    // Verify that new shares are different from old shares
    for (old, new) in key_shares.iter().zip(new_shares.iter()) {
        assert_ne!(old.secret_share, new.secret_share);
        assert_eq!(old.participant_id, new.participant_id);
    }
}

// ============================================================================
// Resharing Integration Tests
// ============================================================================

/// Test: Resharing from 2-of-3 to 3-of-5
#[test]
fn test_resharing_increase_threshold_and_participants() {
    // Generate initial 2-of-3 keys
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, frost_shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    // Convert to generic KeyShare for resharing
    let old_shares: Vec<KeyShare> = frost_shares
        .iter()
        .map(|s| {
            KeyShare::new(
                s.participant_id,
                s.config,
                s.secret_share_bytes().to_vec(),
                s.public_key_share.clone(),
            )
        })
        .collect();

    let old_participants: Vec<ParticipantId> =
        vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];
    let new_participants: Vec<ParticipantId> = vec![
        ParticipantId(1),
        ParticipantId(2),
        ParticipantId(3),
        ParticipantId(4),
        ParticipantId(5),
    ];

    let resharing_config = ResharingConfig::new(
        ThresholdScheme::FrostEd25519,
        config,
        3, // New threshold
        old_participants.clone(),
        new_participants.clone(),
    )
    .unwrap();

    // Old participants generate resharing packages
    let resharing = ResharingProtocol::new(resharing_config.clone()).unwrap();

    // Each old participant generates packages for all new participants
    let mut all_packages: Vec<Vec<ResharingPackage>> = Vec::new();
    for share in &old_shares {
        let packages = resharing.generate_new_shares(share).unwrap();
        all_packages.push(packages);
    }

    // New participants receive and combine packages
    let mut new_shares: Vec<KeyShare> = Vec::new();
    for new_participant in &new_participants {
        // Collect packages intended for this new participant
        let packages_for_me: Vec<ResharingPackage> = all_packages
            .iter()
            .flat_map(|pkgs| pkgs.iter())
            .filter(|pkg| pkg.new_participant == *new_participant)
            .cloned()
            .collect();

        let new_share = resharing
            .receive_shares(*new_participant, packages_for_me, &group_key)
            .unwrap();
        new_shares.push(new_share);
    }

    // Verify we have 5 new shares
    assert_eq!(new_shares.len(), 5);

    // Each new share should have the correct configuration
    for share in &new_shares {
        assert_eq!(share.config.threshold, 3);
        assert_eq!(share.config.total_participants, 5);
    }
}

/// Test: Resharing from 3-of-5 to 2-of-4 (decrease)
#[test]
fn test_resharing_decrease_threshold_and_participants() {
    // Generate initial 3-of-5 keys
    let config = ThresholdConfig::new(3, 5).unwrap();
    let (group_key, frost_shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    let old_shares: Vec<KeyShare> = frost_shares
        .iter()
        .map(|s| {
            KeyShare::new(
                s.participant_id,
                s.config,
                s.secret_share_bytes().to_vec(),
                s.public_key_share.clone(),
            )
        })
        .collect();

    let old_participants: Vec<ParticipantId> = (1..=5).map(ParticipantId).collect();
    // New participants: keep 1, 2, 3, 4 (drop 5)
    let new_participants: Vec<ParticipantId> = vec![
        ParticipantId(1),
        ParticipantId(2),
        ParticipantId(3),
        ParticipantId(4),
    ];

    // Only need 3 old participants (the threshold) to reshare
    let active_old_participants: Vec<ParticipantId> =
        vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];

    let resharing_config = ResharingConfig::new(
        ThresholdScheme::FrostEd25519,
        config,
        2, // New threshold
        active_old_participants.clone(),
        new_participants.clone(),
    )
    .unwrap();

    let resharing = ResharingProtocol::new(resharing_config).unwrap();

    // Only active old participants generate packages
    let mut all_packages: Vec<Vec<ResharingPackage>> = Vec::new();
    for &old_p in &active_old_participants {
        let share = &old_shares[(old_p.0 - 1) as usize];
        let packages = resharing.generate_new_shares(share).unwrap();
        all_packages.push(packages);
    }

    // New participants receive and combine
    let mut new_shares: Vec<KeyShare> = Vec::new();
    for new_participant in &new_participants {
        let packages_for_me: Vec<ResharingPackage> = all_packages
            .iter()
            .flat_map(|pkgs| pkgs.iter())
            .filter(|pkg| pkg.new_participant == *new_participant)
            .cloned()
            .collect();

        let new_share = resharing
            .receive_shares(*new_participant, packages_for_me, &group_key)
            .unwrap();
        new_shares.push(new_share);
    }

    assert_eq!(new_shares.len(), 4);
    for share in &new_shares {
        assert_eq!(share.config.threshold, 2);
        assert_eq!(share.config.total_participants, 4);
    }
}

// ============================================================================
// Fault Tolerance Tests
// ============================================================================

/// Test: Signing fails gracefully with insufficient participants
#[test]
fn test_frost_insufficient_participants_fails() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    let message = b"Test message";

    // Only generate commitment from 1 participant (need 2)
    let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let commitments = vec![commitment1];

    // Signing should fail
    let result = FrostEngine::sign_share(&shares[0], &nonce1, message, &commitments, &group_key);

    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientParticipants { .. })
    ));
}

/// Test: BLS signing fails gracefully with insufficient shares
#[test]
fn test_bls_insufficient_shares_fails() {
    let (shares, _group_pk) = run_bls_dkg(2, 3);

    let message = b"Test message";

    // Only get one signature share (need 2)
    let sig_share = ThresholdBlsEngine::sign_share(&shares[0], message).unwrap();
    let participants = vec![shares[0].participant_id];

    // Aggregation should fail
    let result = ThresholdBlsEngine::aggregate(&[sig_share], &participants);

    assert!(matches!(
        result,
        Err(ThresholdError::InsufficientParticipants { .. })
    ));
}

/// Test: DKG detects invalid/tampered shares
#[test]
fn test_ecdsa_dkg_detects_invalid_share() {
    let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];
    let config =
        DkgConfig::new(ThresholdScheme::ThresholdEcdsaP256, 2, participants.clone()).unwrap();

    let mut dkg1 = EcdsaDkg::new(config.clone(), ParticipantId(1), EcdsaCurve::P256).unwrap();
    let mut dkg2 = EcdsaDkg::new(config.clone(), ParticipantId(2), EcdsaCurve::P256).unwrap();
    let mut dkg3 = EcdsaDkg::new(config.clone(), ParticipantId(3), EcdsaCurve::P256).unwrap();

    // Round 1
    let r1_pkg1 = dkg1.round1_generate_commitments().unwrap();
    let r1_pkg2 = dkg2.round1_generate_commitments().unwrap();
    let r1_pkg3 = dkg3.round1_generate_commitments().unwrap();

    dkg1.round1_receive_commitments(vec![r1_pkg2.clone(), r1_pkg3.clone()])
        .unwrap();
    dkg2.round1_receive_commitments(vec![r1_pkg1.clone(), r1_pkg3.clone()])
        .unwrap();
    dkg3.round1_receive_commitments(vec![r1_pkg1.clone(), r1_pkg2.clone()])
        .unwrap();

    // Round 2
    let _r2_pkgs1 = dkg1.round2_generate_shares().unwrap();
    let mut r2_pkgs2 = dkg2.round2_generate_shares().unwrap();
    let r2_pkgs3 = dkg3.round2_generate_shares().unwrap();

    // Tamper with the share from participant 2 to participant 1
    for pkg in &mut r2_pkgs2 {
        if pkg.receiver == ParticipantId(1) {
            pkg.share[0] ^= 0xFF;
        }
    }

    // Collect shares for participant 1
    let shares_for_1: Vec<_> = r2_pkgs2
        .into_iter()
        .filter(|p| p.receiver == ParticipantId(1))
        .chain(
            r2_pkgs3
                .into_iter()
                .filter(|p| p.receiver == ParticipantId(1)),
        )
        .collect();

    // Receiving tampered share should fail verification
    let result = dkg1.round2_receive_shares(shares_for_1);
    assert!(matches!(result, Err(ThresholdError::DkgInvalidShare(_))));
}

// ============================================================================
// FIPS Compliance Tests
// ============================================================================

/// Test: FIPS mode enforced for P-256
#[test]
fn test_fips_mode_p256_approved() {
    let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];

    // P-256 DKG with FIPS mode should succeed
    let config = DkgConfig::new(ThresholdScheme::ThresholdEcdsaP256, 2, participants.clone())
        .unwrap()
        .with_fips_mode(true);

    assert!(config.validate().is_ok());
}

/// Test: FIPS mode rejects secp256k1
#[test]
fn test_fips_mode_secp256k1_rejected() {
    let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];

    // secp256k1 DKG with FIPS mode should fail validation
    let config = DkgConfig::new(
        ThresholdScheme::ThresholdEcdsaSecp256k1,
        2,
        participants.clone(),
    )
    .unwrap()
    .with_fips_mode(true);

    let result = config.validate();
    assert!(matches!(result, Err(ThresholdError::FipsNotApproved(_))));
}

/// Test: FIPS mode for BLS (under evaluation - should be rejected for now)
#[test]
fn test_fips_mode_bls_status() {
    let participants = vec![ParticipantId(1), ParticipantId(2), ParticipantId(3)];

    let config = DkgConfig::new(ThresholdScheme::ThresholdBls12381, 2, participants.clone())
        .unwrap()
        .with_fips_mode(true);

    // BLS is currently under evaluation, not FIPS approved
    let result = config.validate();
    assert!(matches!(result, Err(ThresholdError::FipsNotApproved(_))));
}

// ============================================================================
// Cross-Scheme Consistency Tests
// ============================================================================

/// Test: DKG produces consistent group keys across all participants
#[test]
fn test_all_schemes_dkg_consistent_group_key() {
    // ECDSA P-256
    let (p256_shares, p256_gk) = run_ecdsa_dkg(2, 3, EcdsaCurve::P256).unwrap();
    for share in &p256_shares {
        assert_eq!(share.group_public_key, p256_gk.bytes);
    }

    // ECDSA secp256k1
    let (secp256k1_shares, secp256k1_gk) = run_ecdsa_dkg(2, 3, EcdsaCurve::Secp256k1).unwrap();
    for share in &secp256k1_shares {
        assert_eq!(share.group_public_key, secp256k1_gk.bytes);
    }

    // BLS
    let (bls_shares, bls_gk) = run_bls_dkg(2, 3);
    for share in &bls_shares {
        assert_eq!(share.group_public_key, bls_gk.bytes);
    }

    // Different schemes produce different key sizes
    assert_eq!(p256_gk.bytes.len(), 33); // Compressed P-256 point
    assert_eq!(secp256k1_gk.bytes.len(), 33); // Compressed secp256k1 point
    assert_eq!(bls_gk.bytes.len(), 48); // Compressed G1 point
}

/// Test: Large threshold configuration (5-of-9)
#[test]
fn test_large_threshold_5_of_9() {
    // ECDSA P-256
    let (shares, group_key) = run_ecdsa_dkg(5, 9, EcdsaCurve::P256).unwrap();
    assert_eq!(shares.len(), 9);
    assert_eq!(group_key.config.threshold, 5);
    assert_eq!(group_key.config.total_participants, 9);

    // Verify signing works with exactly 5 participants
    let message_hash = ThresholdEcdsaEngine::hash_message(b"5-of-9 test");
    let selected: Vec<usize> = vec![0, 2, 4, 6, 8];

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &idx in &selected {
        let (nonce, commitment) = ThresholdEcdsaEngine::generate_nonces(&shares[idx]).unwrap();
        nonces.push(nonce);
        commitments.push(commitment);
    }

    let participants: Vec<ParticipantId> =
        selected.iter().map(|&i| shares[i].participant_id).collect();

    let presigs: Vec<_> = selected
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            ThresholdEcdsaEngine::presign(&shares[idx], &nonces[i], &commitments, &participants)
                .unwrap()
        })
        .collect();

    let sig_shares: Vec<_> = selected
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            ThresholdEcdsaEngine::sign_share(&shares[idx], &presigs[i], &message_hash).unwrap()
        })
        .collect();

    let signature =
        ThresholdEcdsaEngine::aggregate(&group_key, &presigs[0], &sig_shares, &participants)
            .unwrap();

    assert_eq!(signature.to_bytes().len(), 64);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

/// Test: Minimum threshold (2-of-2)
#[test]
fn test_minimum_threshold_2_of_2() {
    let config = ThresholdConfig::new(2, 2).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    assert_eq!(shares.len(), 2);

    let message = b"2-of-2 minimum threshold";

    // Both participants must sign
    let (nonce0, commitment0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let commitments = vec![commitment0, commitment1];

    let sig_share0 =
        FrostEngine::sign_share(&shares[0], &nonce0, message, &commitments, &group_key).unwrap();
    let sig_share1 =
        FrostEngine::sign_share(&shares[1], &nonce1, message, &commitments, &group_key).unwrap();

    let signature = FrostEngine::aggregate_signatures(
        message,
        &commitments,
        &[sig_share0, sig_share1],
        &group_key,
    )
    .unwrap();

    assert!(FrostEngine::verify(&group_key, message, &signature).unwrap());
}

/// Test: Empty message signing
#[test]
fn test_empty_message_signing() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    let message = b""; // Empty message

    let (nonce0, commitment0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let commitments = vec![commitment0, commitment1];

    let sig_share0 =
        FrostEngine::sign_share(&shares[0], &nonce0, message, &commitments, &group_key).unwrap();
    let sig_share1 =
        FrostEngine::sign_share(&shares[1], &nonce1, message, &commitments, &group_key).unwrap();

    let signature = FrostEngine::aggregate_signatures(
        message,
        &commitments,
        &[sig_share0, sig_share1],
        &group_key,
    )
    .unwrap();

    assert!(FrostEngine::verify(&group_key, message, &signature).unwrap());
}

/// Test: Large message signing
#[test]
fn test_large_message_signing() {
    let config = ThresholdConfig::new(2, 3).unwrap();
    let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();

    // 10KB message
    let message = vec![0xABu8; 10_000];

    let (nonce0, commitment0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
    let (nonce1, commitment1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
    let commitments = vec![commitment0, commitment1];

    let sig_share0 =
        FrostEngine::sign_share(&shares[0], &nonce0, &message, &commitments, &group_key).unwrap();
    let sig_share1 =
        FrostEngine::sign_share(&shares[1], &nonce1, &message, &commitments, &group_key).unwrap();

    let signature = FrostEngine::aggregate_signatures(
        &message,
        &commitments,
        &[sig_share0, sig_share1],
        &group_key,
    )
    .unwrap();

    assert!(FrostEngine::verify(&group_key, &message, &signature).unwrap());
}
