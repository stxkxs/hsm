//! Integration tests for the HSM Validator crate.
//!
//! These tests exercise the public API of the validator module end-to-end,
//! covering Ethereum anti-slashing protection, Babylon EOTS signing,
//! database persistence across restarts, concurrency safety, and
//! EIP-3076 interchange import/export.

use hsm_validator::{
    AttestationData, BeaconBlockHeader, Eip3076Interchange, EthereumValidator, ForkInfo,
    SlashingError, SlashingProtectionDb, ValidatorError, ValidatorService,
};
use std::sync::Arc;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a valid BLS secret key using the `blst` crate.
fn generate_bls_secret_key() -> Vec<u8> {
    use blst::min_pk::SecretKey;
    let mut ikm = [0u8; 32];
    getrandom::getrandom(&mut ikm).unwrap();
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    sk.to_bytes().to_vec()
}

/// Generate a *deterministic* BLS secret key from a seed byte.
/// Useful when we need the same key across DB restarts.
fn deterministic_bls_secret_key(seed: u8) -> Vec<u8> {
    use blst::min_pk::SecretKey;
    let ikm = [seed; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    sk.to_bytes().to_vec()
}

/// Canonical fork info used throughout all tests.
fn test_fork_info() -> ForkInfo {
    ForkInfo::new([0x01, 0x00, 0x00, 0x00], [0; 32])
}

/// Build an `AttestationData` with the given source/target epochs.
fn attestation(source_epoch: u64, target_epoch: u64) -> AttestationData {
    use hsm_validator::ethereum::Checkpoint;
    AttestationData {
        slot: target_epoch.wrapping_mul(32), // slot is cosmetic here
        index: 0,
        beacon_block_root: [0xaa; 32],
        source: Checkpoint {
            epoch: source_epoch,
            root: [0xbb; 32],
        },
        target: Checkpoint {
            epoch: target_epoch,
            root: [0xcc; 32],
        },
    }
}

/// Build an attestation whose beacon_block_root (and therefore signing root)
/// differs from the one produced by `attestation()`.
fn attestation_different_root(source_epoch: u64, target_epoch: u64) -> AttestationData {
    use hsm_validator::ethereum::Checkpoint;
    AttestationData {
        slot: target_epoch.wrapping_mul(32),
        index: 0,
        beacon_block_root: [0x11; 32], // different from attestation()
        source: Checkpoint {
            epoch: source_epoch,
            root: [0x22; 32],
        },
        target: Checkpoint {
            epoch: target_epoch,
            root: [0x33; 32],
        },
    }
}

/// Build a `BeaconBlockHeader` for the given slot.
fn block_header(slot: u64) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot,
        proposer_index: 42,
        parent_root: [0xdd; 32],
        state_root: [0xee; 32],
        body_root: [0xff; 32],
    }
}

/// Build a block header with different content (different signing root) for
/// the given slot.
fn block_header_different_root(slot: u64) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot,
        proposer_index: 42,
        parent_root: [0x01; 32],
        state_root: [0x02; 32],
        body_root: [0x03; 32],
    }
}

/// Create an `EthereumValidator` backed by an on-disk slashing DB in `dir`.
fn eth_validator_at(
    dir: &std::path::Path,
    secret_key: &[u8],
) -> (EthereumValidator, Arc<SlashingProtectionDb>) {
    let db = Arc::new(SlashingProtectionDb::open(dir).unwrap());
    let validator = EthereumValidator::new(secret_key, db.clone(), test_fork_info()).unwrap();
    (validator, db)
}

// ===========================================================================
// Ethereum Anti-Slashing Tests
// ===========================================================================

#[test]
fn test_eth_attestation_sign_succeeds() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    let sig = validator.sign_attestation(&attestation(10, 11)).unwrap();
    // BLS signatures are 96 bytes (compressed G2 point)
    assert_eq!(sig.len(), 96);
}

#[test]
fn test_eth_attestation_double_vote_blocked() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // First attestation succeeds
    validator.sign_attestation(&attestation(10, 11)).unwrap();

    // Second attestation at the SAME target epoch but with a different signing
    // root must be blocked (double vote).
    let result = validator.sign_attestation(&attestation_different_root(10, 11));
    assert!(
        matches!(&result, Err(ValidatorError::Slashing(SlashingError::DoubleVote { target_epoch, .. })) if *target_epoch == 11),
        "Expected DoubleVote error, got: {:?}",
        result,
    );
}

#[test]
fn test_eth_attestation_idempotent_same_root() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    let att = attestation(10, 11);
    let sig1 = validator.sign_attestation(&att).unwrap();
    let sig2 = validator.sign_attestation(&att).unwrap();
    // Signing the exact same attestation twice is idempotent.
    assert_eq!(sig1, sig2);
}

#[test]
fn test_eth_attestation_different_epochs_succeed() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // Non-overlapping attestations at different target epochs should all succeed.
    validator.sign_attestation(&attestation(10, 11)).unwrap();
    validator.sign_attestation(&attestation(11, 12)).unwrap();
    validator.sign_attestation(&attestation(12, 13)).unwrap();
}

#[test]
fn test_eth_attestation_surrounding_vote_blocked() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // Record attestation at (source=10, target=15)
    validator.sign_attestation(&attestation(10, 15)).unwrap();

    // A surrounding vote (source=5, target=20) must be blocked.
    let result = validator.sign_attestation(&attestation(5, 20));
    assert!(
        matches!(
            &result,
            Err(ValidatorError::Slashing(
                SlashingError::SurroundingVote { .. }
            ))
        ),
        "Expected SurroundingVote error, got: {:?}",
        result,
    );
}

#[test]
fn test_eth_attestation_surrounded_vote_blocked() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // Record a wide attestation at (source=5, target=20)
    validator.sign_attestation(&attestation(5, 20)).unwrap();

    // A surrounded vote (source=10, target=15) must be blocked.
    let result = validator.sign_attestation(&attestation(10, 15));
    assert!(
        matches!(
            &result,
            Err(ValidatorError::Slashing(
                SlashingError::SurroundedVote { .. }
            ))
        ),
        "Expected SurroundedVote error, got: {:?}",
        result,
    );
}

#[test]
fn test_eth_block_proposal_sign_succeeds() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    let sig = validator.sign_block(&block_header(100)).unwrap();
    assert_eq!(sig.len(), 96);
}

#[test]
fn test_eth_block_double_proposal_blocked() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // First proposal succeeds
    validator.sign_block(&block_header(100)).unwrap();

    // Second proposal at the SAME slot but with a different signing root must
    // be blocked (double block proposal).
    let result = validator.sign_block(&block_header_different_root(100));
    assert!(
        matches!(&result, Err(ValidatorError::Slashing(SlashingError::DoubleBlockProposal { slot, .. })) if *slot == 100),
        "Expected DoubleBlockProposal error, got: {:?}",
        result,
    );
}

#[test]
fn test_eth_block_different_slots_succeed() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    validator.sign_block(&block_header(100)).unwrap();
    validator.sign_block(&block_header(200)).unwrap();
    validator.sign_block(&block_header(300)).unwrap();
}

#[test]
fn test_eth_block_idempotent_same_root() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    let blk = block_header(100);
    let sig1 = validator.sign_block(&blk).unwrap();
    let sig2 = validator.sign_block(&blk).unwrap();
    assert_eq!(sig1, sig2);
}

#[test]
fn test_eth_signature_verification_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    let att = attestation(10, 11);
    let sig = validator.sign_attestation(&att).unwrap();

    // Recompute the signing root and verify
    let domain = test_fork_info().compute_domain(hsm_validator::DomainType::BeaconAttester);
    let signing_root = att.signing_root(&domain);
    let valid = hsm_validator::ethereum::verify_signature(
        validator.public_key().as_bytes(),
        signing_root.as_bytes(),
        &sig,
    )
    .unwrap();
    assert!(valid, "BLS signature verification must pass");
}

#[test]
fn test_eth_randao_and_voluntary_exit_succeed() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    let randao_sig = validator.sign_randao(42).unwrap();
    assert_eq!(randao_sig.len(), 96);

    let exit = hsm_validator::ethereum::VoluntaryExit {
        epoch: 100,
        validator_index: 7,
    };
    let exit_sig = validator.sign_voluntary_exit(&exit).unwrap();
    assert_eq!(exit_sig.len(), 96);
}

#[test]
fn test_eth_validator_summary_counts() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // Sign 3 attestations and 2 blocks
    for i in 0..3 {
        validator
            .sign_attestation(&attestation(i * 10, i * 10 + 1))
            .unwrap();
    }
    for slot in [100, 200] {
        validator.sign_block(&block_header(slot)).unwrap();
    }

    let summary = validator.summary().unwrap();
    assert_eq!(summary.attestation_count, 3);
    assert_eq!(summary.block_count, 2);
}

// ===========================================================================
// Babylon EOTS Tests
// ===========================================================================

#[cfg(feature = "babylon")]
mod babylon_tests {
    use super::*;
    use hsm_validator::babylon::{BabylonValidator, EotsKey, EotsSlashingDb};

    fn create_eots_key_at(dir: &std::path::Path) -> (EotsKey, Arc<EotsSlashingDb>) {
        let db = Arc::new(EotsSlashingDb::open(dir).unwrap());
        let key = EotsKey::generate("babylon-testnet", db.clone()).unwrap();
        (key, db)
    }

    #[test]
    fn test_babylon_eots_key_creation() {
        let tmp = TempDir::new().unwrap();
        let (key, _db) = create_eots_key_at(tmp.path());

        // Compressed secp256k1 public key = 33 bytes
        assert_eq!(key.public_key().len(), 33);
        assert_eq!(key.chain_id(), "babylon-testnet");
    }

    #[test]
    fn test_babylon_eots_sign_succeeds() {
        let tmp = TempDir::new().unwrap();
        let (key, _db) = create_eots_key_at(tmp.path());

        let sig = key.sign_finality_vote(100, &[0xab; 32]).unwrap();
        assert_eq!(sig.height, 100);
        assert_eq!(sig.block_hash, [0xab; 32]);
        assert_eq!(sig.signature.len(), 64);
        assert!(sig.recovery_id <= 1);
    }

    #[test]
    fn test_babylon_eots_double_sign_blocked() {
        let tmp = TempDir::new().unwrap();
        let (key, _db) = create_eots_key_at(tmp.path());

        // First sign succeeds
        key.sign_finality_vote(100, &[0xab; 32]).unwrap();

        // Second sign at SAME height (even with different block hash) must fail
        let result = key.sign_finality_vote(100, &[0xcd; 32]);
        assert!(
            matches!(&result, Err(ValidatorError::Slashing(SlashingError::EotsDoubleSign { height })) if *height == 100),
            "Expected EotsDoubleSign, got: {:?}",
            result,
        );
    }

    #[test]
    fn test_babylon_eots_different_heights_succeed() {
        let tmp = TempDir::new().unwrap();
        let (key, _db) = create_eots_key_at(tmp.path());

        key.sign_finality_vote(100, &[0xab; 32]).unwrap();
        key.sign_finality_vote(101, &[0xab; 32]).unwrap();
        key.sign_finality_vote(200, &[0xab; 32]).unwrap();

        let heights = key.get_signed_heights().unwrap();
        assert_eq!(heights, vec![100, 101, 200]);
    }

    #[test]
    fn test_babylon_eots_height_tracking() {
        let tmp = TempDir::new().unwrap();
        let (key, _db) = create_eots_key_at(tmp.path());

        assert!(!key.is_height_signed(100).unwrap());
        key.sign_finality_vote(100, &[0xab; 32]).unwrap();
        assert!(key.is_height_signed(100).unwrap());
        assert!(!key.is_height_signed(101).unwrap());
    }

    #[test]
    fn test_babylon_validator_wrapper() {
        let tmp = TempDir::new().unwrap();
        let (eots_key, _db) = create_eots_key_at(tmp.path());
        let validator = BabylonValidator::new(eots_key);

        assert_eq!(validator.public_key().len(), 33);
        let sig = validator.sign_finality_vote(500, &[0xff; 32]).unwrap();
        assert_eq!(sig.height, 500);

        let heights = validator.get_signed_heights().unwrap();
        assert_eq!(heights, vec![500]);
    }

    #[test]
    fn test_babylon_eots_persistence_across_restart() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("eots-persist");

        // Phase 1: sign at height 100
        let secret_key = {
            let db = Arc::new(EotsSlashingDb::open(&db_path).unwrap());
            let key = EotsKey::generate("babylon-testnet", db.clone()).unwrap();
            let sk_bytes = key.public_key().to_vec(); // we track pubkey for the check
            key.sign_finality_vote(100, &[0xab; 32]).unwrap();
            db.flush().unwrap();
            sk_bytes
        };
        // db and key are dropped here

        // Phase 2: re-open same DB, verify height 100 is already recorded
        {
            let db = Arc::new(EotsSlashingDb::open(&db_path).unwrap());
            let is_signed = db.is_height_signed(&secret_key, 100).unwrap();
            assert!(is_signed, "Height 100 must still be recorded after restart");
        }
    }

    #[test]
    fn test_babylon_eots_multiple_keys_independent() {
        let tmp = TempDir::new().unwrap();
        let db = Arc::new(EotsSlashingDb::open(tmp.path()).unwrap());

        let key1 = EotsKey::generate("babylon-testnet", db.clone()).unwrap();
        let key2 = EotsKey::generate("babylon-testnet", db.clone()).unwrap();

        // Both keys can sign at the same height
        key1.sign_finality_vote(100, &[0xab; 32]).unwrap();
        key2.sign_finality_vote(100, &[0xcd; 32]).unwrap();

        // But each key cannot double-sign
        let r1 = key1.sign_finality_vote(100, &[0xff; 32]);
        assert!(matches!(
            r1,
            Err(ValidatorError::Slashing(
                SlashingError::EotsDoubleSign { .. }
            ))
        ));

        let r2 = key2.sign_finality_vote(100, &[0xff; 32]);
        assert!(matches!(
            r2,
            Err(ValidatorError::Slashing(
                SlashingError::EotsDoubleSign { .. }
            ))
        ));
    }
}

// ===========================================================================
// Persistence Tests (Ethereum)
// ===========================================================================

#[test]
fn test_eth_persistence_attestation_survives_restart() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("eth-persist");
    let secret_key = deterministic_bls_secret_key(0x42);

    // Phase 1: sign attestation at target epoch 11
    {
        let (validator, db) = eth_validator_at(&db_path, &secret_key);
        validator.sign_attestation(&attestation(10, 11)).unwrap();
        db.flush().unwrap();
    }
    // validator and db are dropped

    // Phase 2: re-open same DB, same key. Double-vote must still be blocked.
    {
        let (validator, _db) = eth_validator_at(&db_path, &secret_key);
        let result = validator.sign_attestation(&attestation_different_root(10, 11));
        assert!(
            matches!(
                &result,
                Err(ValidatorError::Slashing(SlashingError::DoubleVote { .. }))
            ),
            "After restart, double vote at target epoch 11 must still be blocked. Got: {:?}",
            result,
        );
    }
}

#[test]
fn test_eth_persistence_block_survives_restart() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("eth-persist-block");
    let secret_key = deterministic_bls_secret_key(0x43);

    // Phase 1: sign block at slot 100
    {
        let (validator, db) = eth_validator_at(&db_path, &secret_key);
        validator.sign_block(&block_header(100)).unwrap();
        db.flush().unwrap();
    }

    // Phase 2: double proposal at slot 100 must still be blocked
    {
        let (validator, _db) = eth_validator_at(&db_path, &secret_key);
        let result = validator.sign_block(&block_header_different_root(100));
        assert!(
            matches!(
                &result,
                Err(ValidatorError::Slashing(
                    SlashingError::DoubleBlockProposal { .. }
                ))
            ),
            "After restart, double proposal at slot 100 must still be blocked. Got: {:?}",
            result,
        );
    }
}

#[test]
fn test_eth_persistence_surrounding_vote_survives_restart() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("eth-persist-surround");
    let secret_key = deterministic_bls_secret_key(0x44);

    // Phase 1: sign attestation at (10, 15)
    {
        let (validator, db) = eth_validator_at(&db_path, &secret_key);
        validator.sign_attestation(&attestation(10, 15)).unwrap();
        db.flush().unwrap();
    }

    // Phase 2: surrounding vote (5, 20) must still be blocked
    {
        let (validator, _db) = eth_validator_at(&db_path, &secret_key);
        let result = validator.sign_attestation(&attestation(5, 20));
        assert!(
            matches!(
                &result,
                Err(ValidatorError::Slashing(
                    SlashingError::SurroundingVote { .. }
                ))
            ),
            "After restart, surrounding vote must still be blocked. Got: {:?}",
            result,
        );
    }
}

// ===========================================================================
// Concurrency Tests
// ===========================================================================

#[test]
fn test_eth_multiple_validators_no_cross_contamination() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(SlashingProtectionDb::open(tmp.path()).unwrap());

    let sk1 = generate_bls_secret_key();
    let sk2 = generate_bls_secret_key();

    let v1 = EthereumValidator::new(&sk1, db.clone(), test_fork_info()).unwrap();
    let v2 = EthereumValidator::new(&sk2, db.clone(), test_fork_info()).unwrap();

    // Both validators can sign attestations at the same target epoch
    // (with their own signing roots) because they are independent entities.
    v1.sign_attestation(&attestation(10, 11)).unwrap();
    v2.sign_attestation(&attestation(10, 11)).unwrap();

    // Both can sign blocks at the same slot
    v1.sign_block(&block_header(100)).unwrap();
    v2.sign_block(&block_header(100)).unwrap();

    // But each validator individually cannot double-vote
    let r1 = v1.sign_attestation(&attestation_different_root(10, 11));
    assert!(matches!(
        r1,
        Err(ValidatorError::Slashing(SlashingError::DoubleVote { .. }))
    ));

    let r2 = v2.sign_attestation(&attestation_different_root(10, 11));
    assert!(matches!(
        r2,
        Err(ValidatorError::Slashing(SlashingError::DoubleVote { .. }))
    ));
}

#[test]
fn test_eth_concurrent_signing_different_validators() {
    use std::thread;

    let tmp = TempDir::new().unwrap();
    let db = Arc::new(SlashingProtectionDb::open(tmp.path()).unwrap());

    let num_validators = 8;
    let attestations_per_validator = 50;

    let mut handles = Vec::new();

    for v_idx in 0..num_validators {
        let db = db.clone();
        let handle = thread::spawn(move || {
            let sk = generate_bls_secret_key();
            let validator = EthereumValidator::new(&sk, db, test_fork_info()).unwrap();

            for i in 0..attestations_per_validator {
                let source = (v_idx * 1000 + i) as u64;
                let target = source + 1;
                validator
                    .sign_attestation(&attestation(source, target))
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Thread must not panic");
    }
}

#[test]
fn test_eth_concurrent_blocks_different_validators() {
    use std::thread;

    let tmp = TempDir::new().unwrap();
    let db = Arc::new(SlashingProtectionDb::open(tmp.path()).unwrap());

    let mut handles = Vec::new();

    for v_idx in 0..4u64 {
        let db = db.clone();
        let handle = thread::spawn(move || {
            let sk = generate_bls_secret_key();
            let validator = EthereumValidator::new(&sk, db, test_fork_info()).unwrap();

            for slot in 0..20u64 {
                // Each validator signs at the same slot range -- that is fine
                // because they are different validators.
                validator
                    .sign_block(&block_header(v_idx * 10000 + slot))
                    .unwrap();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Thread must not panic");
    }
}

// ===========================================================================
// EIP-3076 Interchange Tests
// ===========================================================================

#[test]
fn test_eip3076_export_import_roundtrip() {
    let tmp1 = TempDir::new().unwrap();
    let tmp2 = TempDir::new().unwrap();

    let secret_key = generate_bls_secret_key();

    // Build up signing history on service 1
    let service1 = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(ValidatorService::new(tmp1.path()))
        .unwrap();

    let validator = service1
        .create_ethereum_validator(&secret_key, test_fork_info())
        .unwrap();

    // Sign some attestations and blocks
    validator.sign_attestation(&attestation(10, 11)).unwrap();
    validator.sign_attestation(&attestation(11, 12)).unwrap();
    validator.sign_block(&block_header(100)).unwrap();
    validator.sign_block(&block_header(200)).unwrap();

    // Export
    let interchange = service1
        .export_ethereum_slashing_protection("0xgenesis", None)
        .unwrap();
    let json = interchange.to_json().unwrap();

    // Import into service 2
    let service2 = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(ValidatorService::new(tmp2.path()))
        .unwrap();

    let interchange2 = Eip3076Interchange::from_json(&json).unwrap();
    let result = service2
        .import_ethereum_slashing_protection(&interchange2)
        .unwrap();

    assert_eq!(result.validators_imported, 1);
    assert_eq!(result.attestations_imported, 2);
    assert_eq!(result.blocks_imported, 2);
}

#[test]
fn test_eip3076_import_blocks_previously_signed_slots() {
    let tmp = TempDir::new().unwrap();

    let pubkey_hex = "ab".repeat(48); // 48 bytes => 96 hex chars
    let root_hex = "11".repeat(32); // 32 bytes => 64 hex chars

    // Construct a minimal interchange file
    let json = format!(
        r#"{{
            "metadata": {{
                "interchange_format_version": "5",
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }},
            "data": [
                {{
                    "pubkey": "0x{pubkey_hex}",
                    "signed_blocks": [
                        {{"slot": "500", "signing_root": "0x{root_hex}"}}
                    ],
                    "signed_attestations": [
                        {{"source_epoch": "100", "target_epoch": "200", "signing_root": "0x{root_hex}"}}
                    ]
                }}
            ]
        }}"#,
    );

    let service = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(ValidatorService::new(tmp.path()))
        .unwrap();

    let interchange = Eip3076Interchange::from_json(&json).unwrap();
    service
        .import_ethereum_slashing_protection(&interchange)
        .unwrap();

    // Verify that min epochs/slots were set by checking the summary
    let pubkey_bytes = hex::decode(&pubkey_hex).unwrap();
    let summary = service
        .get_ethereum_validator_summary(&pubkey_bytes)
        .unwrap();

    assert_eq!(summary.min_source_epoch, Some(100));
    assert_eq!(summary.min_target_epoch, Some(200));
    assert_eq!(summary.min_slot, Some(500));
}

#[test]
fn test_eip3076_import_then_sign_at_lower_epoch_blocked() {
    let tmp = TempDir::new().unwrap();
    let secret_key = generate_bls_secret_key();

    let service = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(ValidatorService::new(tmp.path()))
        .unwrap();

    // Register a validator first
    let validator = service
        .create_ethereum_validator(&secret_key, test_fork_info())
        .unwrap();
    let _pubkey_hex = validator.public_key().to_hex();

    // Sign an attestation at (50, 60) so the validator has history
    validator.sign_attestation(&attestation(50, 60)).unwrap();

    // Now export, then re-import (simulating a migration that sets minimums)
    let interchange = service
        .export_ethereum_slashing_protection("0xgenesis", None)
        .unwrap();
    // The import sets min_source_epoch=50, min_target_epoch=60
    let _result = service
        .import_ethereum_slashing_protection(&interchange)
        .unwrap();

    // Attempting to sign with a source epoch below the minimum must fail
    let result = validator.sign_attestation(&attestation(10, 70));
    assert!(
        matches!(
            &result,
            Err(ValidatorError::Slashing(
                SlashingError::SourceEpochTooLow { .. }
            ))
        ),
        "Signing at source epoch below imported minimum must be blocked. Got: {:?}",
        result,
    );
}

#[test]
fn test_eip3076_json_roundtrip_compact() {
    let interchange = Eip3076Interchange::new("0xgenesis");
    let json = interchange.to_json_compact().unwrap();
    let parsed = Eip3076Interchange::from_json(&json).unwrap();
    assert_eq!(parsed.metadata.interchange_format_version, "5");
    assert_eq!(parsed.metadata.genesis_validators_root, "0xgenesis");
    assert!(parsed.data.is_empty());
}

// ===========================================================================
// ValidatorService Integration Tests
// ===========================================================================

#[test]
fn test_validator_service_lifecycle() {
    let tmp = TempDir::new().unwrap();

    let service = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(ValidatorService::new(tmp.path()))
        .unwrap();

    assert!(service.list_ethereum_validators().is_empty());

    // Create validators
    let sk1 = generate_bls_secret_key();
    let sk2 = generate_bls_secret_key();
    let v1 = service
        .create_ethereum_validator(&sk1, test_fork_info())
        .unwrap();
    let v2 = service
        .create_ethereum_validator(&sk2, test_fork_info())
        .unwrap();

    assert_eq!(service.list_ethereum_validators().len(), 2);

    // Retrieve by public key
    let retrieved = service.get_ethereum_validator(v1.public_key().as_bytes());
    assert!(retrieved.is_some());

    // Sign and check stats
    v1.sign_attestation(&attestation(10, 11)).unwrap();
    v2.sign_block(&block_header(100)).unwrap();

    let stats = service.ethereum_stats();
    assert_eq!(stats.attestations_signed, 1);
    assert_eq!(stats.blocks_signed, 1);
}

#[test]
fn test_validator_service_flush() {
    let tmp = TempDir::new().unwrap();
    let service = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(ValidatorService::new(tmp.path()))
        .unwrap();

    let sk = generate_bls_secret_key();
    let v = service
        .create_ethereum_validator(&sk, test_fork_info())
        .unwrap();
    v.sign_attestation(&attestation(1, 2)).unwrap();

    // flush must not panic
    service.flush().unwrap();
}

// ===========================================================================
// Edge Cases
// ===========================================================================

#[test]
fn test_eth_attestation_source_equals_target_minus_one() {
    // Minimal valid attestation: source just below target
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    validator.sign_attestation(&attestation(0, 1)).unwrap();
}

#[test]
fn test_eth_attestation_epoch_zero() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // Source and target can start at 0 (genesis)
    validator.sign_attestation(&attestation(0, 0)).unwrap();
}

#[test]
fn test_eth_block_slot_zero() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    validator.sign_block(&block_header(0)).unwrap();
}

#[test]
fn test_eth_large_epoch_values() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    let large = u64::MAX - 1;
    validator
        .sign_attestation(&attestation(large - 1, large))
        .unwrap();
    validator.sign_block(&block_header(large)).unwrap();
}

#[test]
fn test_eth_many_sequential_attestations() {
    let tmp = TempDir::new().unwrap();
    let (validator, _db) = eth_validator_at(tmp.path(), &generate_bls_secret_key());

    // Sign 100 sequential attestations to exercise the scan-prefix logic
    // in surrounding/surrounded vote detection.
    for i in 0u64..100 {
        validator.sign_attestation(&attestation(i, i + 1)).unwrap();
    }
}

#[test]
fn test_slashing_db_list_validators() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("list-validators-db");

    let sk1 = generate_bls_secret_key();

    // Phase 1: create a validator and flush the DB
    {
        let db = Arc::new(SlashingProtectionDb::open(&db_path).unwrap());
        let _v1 = EthereumValidator::new(&sk1, db.clone(), test_fork_info()).unwrap();
        let validators = db.list_validators().unwrap();
        assert_eq!(validators.len(), 1);
        db.flush().unwrap();
    }
    // db is dropped, releasing the sled lock

    // Phase 2: re-open and confirm the validator is still there
    {
        let db2 = SlashingProtectionDb::open(&db_path).unwrap();
        let validators = db2.list_validators().unwrap();
        assert!(
            !validators.is_empty(),
            "At least one validator should be registered after re-open"
        );
    }
}
