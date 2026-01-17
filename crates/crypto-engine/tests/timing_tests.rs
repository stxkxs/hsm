//! Timing side-channel tests using dudect statistical analysis.
//!
//! These tests use the dudect (DUde, is my code CTCT?) methodology to detect
//! timing leaks in cryptographic operations. The tests compare execution time
//! of operations on different input classes and use statistical t-tests to
//! determine if timing depends on secret data.
//!
//! # Interpretation
//!
//! - **p-value > 0.05**: Operation appears constant-time (PASS)
//! - **p-value ≤ 0.05**: Timing leak detected (FAIL)
//! - **t-statistic < 4.5**: No significant timing difference
//! - **t-statistic ≥ 4.5**: Statistically significant timing leak
//!
//! # References
//!
//! - "Dude, is my code constant time?" (Reparaz et al., 2017)
//! - https://github.com/oreparaz/dudect

use dudect_bencher::{ctbench_main, rand::Rng, BenchRng, Class, CtRunner};
use hsm_crypto_engine::constant_time::*;
use hsm_crypto_engine::symmetric::aes_gcm::AesGcmEngine;
use hsm_crypto_engine::KeyMaterial;

/// Test constant-time comparison of authentication tags.
///
/// This test verifies that tag comparison time is independent of:
/// - Which byte differs
/// - Position of the first difference
/// - Number of matching bytes
fn test_ct_compare_tags(runner: &mut CtRunner, rng: &mut BenchRng) {
    const TAG_SIZE: usize = 16; // 128-bit AES-GCM tag
    const ITERATIONS: usize = 10_000;

    let mut inputs: Vec<([u8; TAG_SIZE], [u8; TAG_SIZE])> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS {
        // Generate a random reference tag
        let mut reference_tag = [0u8; TAG_SIZE];
        rng.fill(&mut reference_tag);

        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        let mut test_tag = reference_tag;

        match class {
            Class::Left => {
                // Matching tag - do nothing
            }
            Class::Right => {
                // Non-matching tag - flip one random byte
                let flip_pos = rng.gen::<usize>() % TAG_SIZE;
                test_tag[flip_pos] ^= 0xFF;
            }
        }

        inputs.push((reference_tag, test_tag));
        classes.push(class);
    }

    // Benchmark the comparison
    // Timing should be independent of whether tags match or which byte differs
    for (class, tags) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = ct_compare(&tags.0, &tags.1);
        });
    }
}

/// Test constant-time comparison with varying difference positions.
///
/// This specifically tests that timing doesn't depend on WHERE the first
/// difference occurs (beginning, middle, or end of the array).
fn test_ct_compare_diff_position(runner: &mut CtRunner, rng: &mut BenchRng) {
    const SIZE: usize = 64;
    const ITERATIONS: usize = 10_000;

    let mut inputs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS {
        let reference = vec![0xAA; SIZE];
        let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };

        let test_data = match class {
            Class::Left => {
                // First byte differs
                let mut data = reference.clone();
                data[0] = 0xBB;
                data
            }
            Class::Right => {
                // Last byte differs
                let mut data = reference.clone();
                data[SIZE - 1] = 0xBB;
                data
            }
        };

        inputs.push((reference, test_data));
        classes.push(class);
    }

    for (class, data) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = ct_compare(&data.0, &data.1);
        });
    }
}

/// Test constant-time selection between two buffers.
///
/// Verifies that ct_select timing is independent of:
/// - Which option is selected (condition true vs false)
/// - Content of the buffers
/// - Differences between the buffers
fn test_ct_select(runner: &mut CtRunner, rng: &mut BenchRng) {
    const SIZE: usize = 32;
    const ITERATIONS: usize = 10_000;

    let mut inputs: Vec<(bool, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS {
        let option_a = vec![0xAA; SIZE];
        let option_b = vec![0xBB; SIZE];

        let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
        let condition = match class {
            Class::Left => true,
            Class::Right => false,
        };

        inputs.push((condition, option_a, option_b));
        classes.push(class);
    }

    for (class, input) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = ct_select(input.0, &input.1, &input.2);
        });
    }
}

/// Test AES-GCM decryption timing for different tag validity.
///
/// This test checks if AES-GCM decryption timing reveals whether the
/// authentication tag is valid or invalid. The underlying aes-gcm crate
/// claims constant-time verification, which we verify here.
fn test_aes_gcm_tag_verification(runner: &mut CtRunner, rng: &mut BenchRng) {
    const ITERATIONS: usize = 10_000;

    // Create a fixed key for testing
    let key = KeyMaterial::from_bytes(vec![0x42; 32]);
    let plaintext = b"test_message_for_timing_analysis";

    // Encrypt once to get a valid ciphertext
    let valid_ciphertext = AesGcmEngine::encrypt_aes256(&key, plaintext, None)
        .expect("encryption should succeed");

    let mut inputs: Vec<Vec<u8>> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS {
        let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };

        let test_ciphertext = match class {
            Class::Left => {
                // Valid ciphertext with correct tag
                valid_ciphertext.clone()
            }
            Class::Right => {
                // Invalid ciphertext with tampered tag
                let mut tampered = valid_ciphertext.clone();
                // Tamper with the last byte of the tag
                if let Some(last) = tampered.last_mut() {
                    *last ^= 0xFF;
                }
                tampered
            }
        };

        inputs.push(test_ciphertext);
        classes.push(class);
    }

    // Benchmark decryption
    // Timing should be independent of tag validity
    for (class, ciphertext) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = AesGcmEngine::decrypt_aes256(&key, &ciphertext, None);
        });
    }
}

/// Test constant-time behavior of tag verification with different tag values.
///
/// Specifically tests if timing depends on the Hamming distance between
/// expected and received tags (number of differing bits).
fn test_ct_verify_tag_hamming_distance(runner: &mut CtRunner, rng: &mut BenchRng) {
    const TAG_SIZE: usize = 16;
    const ITERATIONS: usize = 10_000;

    let mut inputs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS {
        let expected_tag = vec![0xAA; TAG_SIZE];
        let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };

        let received_tag = match class {
            Class::Left => {
                // Low Hamming distance: single bit flip
                let mut tag = expected_tag.clone();
                tag[0] ^= 0x01;
                tag
            }
            Class::Right => {
                // High Hamming distance: all bits flipped
                let mut tag = expected_tag.clone();
                for byte in tag.iter_mut() {
                    *byte ^= 0xFF;
                }
                tag
            }
        };

        inputs.push((expected_tag, received_tag));
        classes.push(class);
    }

    for (class, tags) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = ct_verify_tag(&tags.0, &tags.1);
        });
    }
}

/// Test that comparison timing doesn't depend on length.
///
/// While length is typically not secret, this test ensures that our
/// implementation correctly handles different-length inputs in constant time.
fn test_ct_compare_different_lengths(runner: &mut CtRunner, rng: &mut BenchRng) {
    const ITERATIONS: usize = 10_000;

    let mut inputs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS {
        let short_data = vec![0xAA; 16];
        let long_data = vec![0xAA; 64];

        let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };

        let test_pair = match class {
            Class::Left => {
                // Compare equal-length short arrays
                (short_data.clone(), short_data)
            }
            Class::Right => {
                // Compare different-length arrays (should return false quickly)
                (short_data, long_data)
            }
        };

        inputs.push(test_pair);
        classes.push(class);
    }

    for (class, data) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = ct_compare(&data.0, &data.1);
        });
    }
}

/// Test signature verification timing independence.
///
/// Verifies that signature comparison timing doesn't depend on:
/// - Which signature component differs (r vs s in ECDSA)
/// - Position of difference in signature bytes
fn test_ct_verify_signature(runner: &mut CtRunner, rng: &mut BenchRng) {
    const SIG_SIZE: usize = 64; // ECDSA P-256 signature size
    const ITERATIONS: usize = 10_000;

    let mut inputs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..ITERATIONS {
        let expected_sig = vec![0x12; SIG_SIZE];
        let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };

        let received_sig = match class {
            Class::Left => {
                // Difference in first half (r component)
                let mut sig = expected_sig.clone();
                sig[0] ^= 0xFF;
                sig
            }
            Class::Right => {
                // Difference in second half (s component)
                let mut sig = expected_sig.clone();
                sig[SIG_SIZE - 1] ^= 0xFF;
                sig
            }
        };

        inputs.push((expected_sig, received_sig));
        classes.push(class);
    }

    for (class, sigs) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || {
            let _ = ct_verify_signature(&sigs.0, &sigs.1);
        });
    }
}

ctbench_main!(
    test_ct_compare_tags,
    test_ct_compare_diff_position,
    test_ct_select,
    test_aes_gcm_tag_verification,
    test_ct_verify_tag_hamming_distance,
    test_ct_compare_different_lengths,
    test_ct_verify_signature
);
