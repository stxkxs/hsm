//! FIPS Self-Tests (Known Answer Tests)
//!
//! Implements power-on self-tests (POST) required by FIPS 140-3.
//! These tests verify that cryptographic algorithms are operating correctly.

use super::mode::FipsError;
use serde::{Deserialize, Serialize};

/// Self-test status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfTestStatus {
    /// Tests not yet run
    NotRun,
    /// Tests currently running
    Running,
    /// All tests passed
    Passed,
    /// One or more tests failed
    Failed,
}

/// Individual test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Test name
    pub name: String,
    /// Algorithm tested
    pub algorithm: String,
    /// Whether test passed
    pub passed: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Duration in microseconds
    pub duration_us: u64,
}

/// Overall self-test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResult {
    /// Overall status
    pub status: SelfTestStatus,
    /// Individual test results
    pub tests: Vec<TestResult>,
    /// Tests that failed
    pub failed_tests: Vec<TestResult>,
    /// Total duration in microseconds
    pub total_duration_us: u64,
}

/// Known Answer Test (KAT) definition
pub struct KnownAnswerTest {
    /// Test name
    pub name: &'static str,
    /// Algorithm being tested
    pub algorithm: &'static str,
    /// Input data
    pub input: &'static [u8],
    /// Expected output
    pub expected: &'static [u8],
    /// Test function
    pub test_fn: fn(&[u8]) -> Result<Vec<u8>, String>,
}

/// Threshold Known Answer Test definition
pub struct ThresholdKat {
    /// Test name
    pub name: &'static str,
    /// Threshold scheme being tested
    pub scheme: &'static str,
    /// Test function
    pub test_fn: fn() -> Result<(), String>,
}

/// Self-test runner
pub struct SelfTestRunner {
    tests: Vec<KnownAnswerTest>,
    threshold_tests: Vec<ThresholdKat>,
}

impl SelfTestRunner {
    /// Create a new self-test runner with all required tests
    pub fn new() -> Self {
        let tests = vec![
            // AES-256-GCM encryption.
            //
            // NIST GCM test vector (the canonical AES-256-GCM "Test Case 13/14"
            // set): key = 32 zero bytes, IV = 96-bit zero, empty AAD, plaintext
            // = 16 zero bytes. The expected value is the 16-byte ciphertext
            // followed by the 16-byte authentication tag, as produced by
            // `aes_gcm::Aes256Gcm::encrypt` (ciphertext || tag):
            //   ciphertext = cea7403d4d606b6e074ec5d3baf39d18
            //   tag        = d0d1c8a799996bf0265b98b5d48ab919
            // (The empty-plaintext variant of this key/IV yields tag
            // ae9b1771dba9cf62b39be017940330b4; with a 16-byte zero plaintext the
            // tag is the value below.)
            KnownAnswerTest {
                name: "AES-256-GCM Encrypt",
                algorithm: "AES-256-GCM",
                input: &[0u8; 16],
                expected: &[
                    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba,
                    0xf3, 0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b,
                    0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
                ],
                test_fn: test_aes_256_gcm,
            },
            // SHA-256
            KnownAnswerTest {
                name: "SHA-256",
                algorithm: "SHA-256",
                input: b"abc",
                expected: &[
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ],
                test_fn: test_sha256,
            },
            // SHA-384
            KnownAnswerTest {
                name: "SHA-384",
                algorithm: "SHA-384",
                input: b"abc",
                expected: &[
                    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a,
                    0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b,
                    0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc,
                    0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
                ],
                test_fn: test_sha384,
            },
            // SHA-512
            KnownAnswerTest {
                name: "SHA-512",
                algorithm: "SHA-512",
                input: b"abc",
                expected: &[
                    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae,
                    0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e,
                    0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1,
                    0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23,
                    0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
                ],
                test_fn: test_sha512,
            },
            // HMAC-SHA256 — RFC 4231 Test Case 2.
            //   key  = "Jefe"
            //   data = "what do ya want for nothing?"
            //   HMAC-SHA-256 =
            //     5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
            KnownAnswerTest {
                name: "HMAC-SHA256",
                algorithm: "HMAC-SHA256",
                input: b"what do ya want for nothing?",
                expected: &[
                    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08,
                    0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec,
                    0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
                ],
                test_fn: test_hmac_sha256,
            },
        ];

        // Threshold cryptography KATs.
        //
        // The FROST-Ed25519 KAT exercises the real operational signing path.
        // The Threshold-ECDSA-P256 entry is a "disabled-state" KAT: the signing
        // path fails closed (NotImplemented), so the KAT verifies it stays
        // disabled and the scheme is labelled "not operational" rather than
        // being reported as a passing crypto KAT.
        let threshold_tests = vec![
            ThresholdKat {
                name: "FROST-Ed25519-KAT",
                scheme: "FROST-Ed25519",
                test_fn: test_frost_ed25519_kat,
            },
            ThresholdKat {
                name: "Threshold-ECDSA-P256-KAT",
                scheme: "Threshold-ECDSA-P256 (not operational: signing disabled)",
                test_fn: test_threshold_ecdsa_p256_kat,
            },
        ];

        Self {
            tests,
            threshold_tests,
        }
    }

    /// Run all self-tests
    pub fn run_all_tests(&self) -> Result<SelfTestResult, FipsError> {
        let start = std::time::Instant::now();
        let mut results = Vec::new();
        let mut failed = Vec::new();

        for test in &self.tests {
            let test_start = std::time::Instant::now();
            let result = (test.test_fn)(test.input);

            let test_result = match result {
                Ok(output) => {
                    // For tests with specific expected output, verify
                    let passed = if test.expected.is_empty() {
                        true // No specific expected output, just check it ran
                    } else {
                        output == test.expected
                    };

                    TestResult {
                        name: test.name.to_string(),
                        algorithm: test.algorithm.to_string(),
                        passed,
                        error: if passed {
                            None
                        } else {
                            Some("Output mismatch".to_string())
                        },
                        duration_us: test_start.elapsed().as_micros() as u64,
                    }
                }
                Err(e) => TestResult {
                    name: test.name.to_string(),
                    algorithm: test.algorithm.to_string(),
                    passed: false,
                    error: Some(e),
                    duration_us: test_start.elapsed().as_micros() as u64,
                },
            };

            if !test_result.passed {
                failed.push(test_result.clone());
            }
            results.push(test_result);
        }

        let status = if failed.is_empty() {
            SelfTestStatus::Passed
        } else {
            SelfTestStatus::Failed
        };

        Ok(SelfTestResult {
            status,
            tests: results,
            failed_tests: failed,
            total_duration_us: start.elapsed().as_micros() as u64,
        })
    }

    /// Run a specific test by name
    pub fn run_test(&self, name: &str) -> Option<TestResult> {
        let test = self.tests.iter().find(|t| t.name == name)?;
        let start = std::time::Instant::now();
        let result = (test.test_fn)(test.input);

        Some(match result {
            Ok(output) => {
                let passed = if test.expected.is_empty() {
                    true
                } else {
                    output == test.expected
                };

                TestResult {
                    name: test.name.to_string(),
                    algorithm: test.algorithm.to_string(),
                    passed,
                    error: if passed {
                        None
                    } else {
                        Some("Output mismatch".to_string())
                    },
                    duration_us: start.elapsed().as_micros() as u64,
                }
            }
            Err(e) => TestResult {
                name: test.name.to_string(),
                algorithm: test.algorithm.to_string(),
                passed: false,
                error: Some(e),
                duration_us: start.elapsed().as_micros() as u64,
            },
        })
    }

    /// Get list of test names
    pub fn test_names(&self) -> Vec<&str> {
        self.tests.iter().map(|t| t.name).collect()
    }

    /// Get list of threshold test names
    pub fn threshold_test_names(&self) -> Vec<&str> {
        self.threshold_tests.iter().map(|t| t.name).collect()
    }

    /// Run all threshold-specific KATs
    pub fn run_threshold_tests(&self) -> Vec<TestResult> {
        self.threshold_tests
            .iter()
            .map(|test| {
                let start = std::time::Instant::now();
                let result = (test.test_fn)();

                match result {
                    Ok(()) => TestResult {
                        name: test.name.to_string(),
                        algorithm: test.scheme.to_string(),
                        passed: true,
                        error: None,
                        duration_us: start.elapsed().as_micros() as u64,
                    },
                    Err(e) => TestResult {
                        name: test.name.to_string(),
                        algorithm: test.scheme.to_string(),
                        passed: false,
                        error: Some(e),
                        duration_us: start.elapsed().as_micros() as u64,
                    },
                }
            })
            .collect()
    }

    /// Run a specific threshold test by name
    pub fn run_threshold_test(&self, name: &str) -> Option<TestResult> {
        let test = self.threshold_tests.iter().find(|t| t.name == name)?;
        let start = std::time::Instant::now();
        let result = (test.test_fn)();

        Some(match result {
            Ok(()) => TestResult {
                name: test.name.to_string(),
                algorithm: test.scheme.to_string(),
                passed: true,
                error: None,
                duration_us: start.elapsed().as_micros() as u64,
            },
            Err(e) => TestResult {
                name: test.name.to_string(),
                algorithm: test.scheme.to_string(),
                passed: false,
                error: Some(e),
                duration_us: start.elapsed().as_micros() as u64,
            },
        })
    }

    /// Run all tests including threshold tests
    pub fn run_all_tests_including_threshold(&self) -> Result<SelfTestResult, FipsError> {
        let start = std::time::Instant::now();
        let mut results = Vec::new();
        let mut failed = Vec::new();

        // Run standard tests
        for test in &self.tests {
            let test_start = std::time::Instant::now();
            let result = (test.test_fn)(test.input);

            let test_result = match result {
                Ok(output) => {
                    let passed = if test.expected.is_empty() {
                        true
                    } else {
                        output == test.expected
                    };

                    TestResult {
                        name: test.name.to_string(),
                        algorithm: test.algorithm.to_string(),
                        passed,
                        error: if passed {
                            None
                        } else {
                            Some("Output mismatch".to_string())
                        },
                        duration_us: test_start.elapsed().as_micros() as u64,
                    }
                }
                Err(e) => TestResult {
                    name: test.name.to_string(),
                    algorithm: test.algorithm.to_string(),
                    passed: false,
                    error: Some(e),
                    duration_us: test_start.elapsed().as_micros() as u64,
                },
            };

            if !test_result.passed {
                failed.push(test_result.clone());
            }
            results.push(test_result);
        }

        // Run threshold tests
        for test in &self.threshold_tests {
            let test_start = std::time::Instant::now();
            let result = (test.test_fn)();

            let test_result = match result {
                Ok(()) => TestResult {
                    name: test.name.to_string(),
                    algorithm: test.scheme.to_string(),
                    passed: true,
                    error: None,
                    duration_us: test_start.elapsed().as_micros() as u64,
                },
                Err(e) => TestResult {
                    name: test.name.to_string(),
                    algorithm: test.scheme.to_string(),
                    passed: false,
                    error: Some(e),
                    duration_us: test_start.elapsed().as_micros() as u64,
                },
            };

            if !test_result.passed {
                failed.push(test_result.clone());
            }
            results.push(test_result);
        }

        let status = if failed.is_empty() {
            SelfTestStatus::Passed
        } else {
            SelfTestStatus::Failed
        };

        Ok(SelfTestResult {
            status,
            tests: results,
            failed_tests: failed,
            total_duration_us: start.elapsed().as_micros() as u64,
        })
    }
}

impl Default for SelfTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

// Test functions

fn test_aes_256_gcm(input: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    let key = [0u8; 32];
    let nonce = [0u8; 12];

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Failed to create cipher: {}", e))?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), input)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Decrypt and verify
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    if plaintext != input {
        return Err("Round-trip verification failed".to_string());
    }

    Ok(ciphertext)
}

fn test_sha256(input: &[u8]) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    Ok(hasher.finalize().to_vec())
}

fn test_sha384(input: &[u8]) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha384};
    let mut hasher = Sha384::new();
    hasher.update(input);
    Ok(hasher.finalize().to_vec())
}

fn test_sha512(input: &[u8]) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(input);
    Ok(hasher.finalize().to_vec())
}

fn test_hmac_sha256(input: &[u8]) -> Result<Vec<u8>, String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // RFC 4231 Test Case 2 key.
    let key = b"Jefe";
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| format!("Failed to create HMAC: {}", e))?;

    mac.update(input);
    let result = mac.finalize();
    let result_bytes = result.into_bytes();

    // Verify
    let mut verify_mac =
        HmacSha256::new_from_slice(key).map_err(|e| format!("Failed to create HMAC: {}", e))?;
    verify_mac.update(input);
    verify_mac
        .verify_slice(&result_bytes)
        .map_err(|_| "HMAC verification failed".to_string())?;

    Ok(result_bytes.to_vec())
}

// ============ Threshold Cryptography KAT Functions ============

/// Known Answer Test for FROST Ed25519.
///
/// This runs the REAL FROST-Ed25519 threshold path end-to-end: trusted-dealer
/// keygen for a 2-of-3 scheme, a full two-round threshold signing over a fixed
/// message, aggregation, and verification of the aggregated signature against
/// the real group public key (both via FROST's verifier and standard Ed25519
/// verification). FROST signing is randomized, so we cannot match a fixed
/// signature byte string; instead the KAT asserts that the produced signature
/// actually verifies — and that a tampered message is rejected — which proves
/// the algorithm is operational rather than merely that the primitives link.
fn test_frost_ed25519_kat() -> Result<(), String> {
    use crate::threshold::frost::FrostEngine;
    use crate::threshold::types::ThresholdConfig;

    const KAT_MESSAGE: &[u8] = b"FIPS 186-5 FROST Ed25519 KAT message";

    let config = ThresholdConfig::new(2, 3).map_err(|e| format!("config: {e}"))?;
    let (group_key, shares) =
        FrostEngine::trusted_dealer_keygen(config).map_err(|e| format!("keygen: {e}"))?;

    // Round 1: participants 1 and 2 generate nonces + commitments.
    let (nonce0, commit0) =
        FrostEngine::generate_nonces(&shares[0]).map_err(|e| format!("nonces[0]: {e}"))?;
    let (nonce1, commit1) =
        FrostEngine::generate_nonces(&shares[1]).map_err(|e| format!("nonces[1]: {e}"))?;
    let commitments = vec![commit0, commit1];

    // Round 2: each participant produces a signature share.
    let share0 =
        FrostEngine::sign_share(&shares[0], &nonce0, KAT_MESSAGE, &commitments, &group_key)
            .map_err(|e| format!("sign_share[0]: {e}"))?;
    let share1 =
        FrostEngine::sign_share(&shares[1], &nonce1, KAT_MESSAGE, &commitments, &group_key)
            .map_err(|e| format!("sign_share[1]: {e}"))?;

    // Aggregate into a single Ed25519 signature.
    let signature =
        FrostEngine::aggregate_signatures(KAT_MESSAGE, &commitments, &[share0, share1], &group_key)
            .map_err(|e| format!("aggregate: {e}"))?;

    // The aggregated signature MUST verify against the real group key.
    if !FrostEngine::verify(&group_key, KAT_MESSAGE, &signature)
        .map_err(|e| format!("verify: {e}"))?
    {
        return Err("FROST aggregated signature failed verification".to_string());
    }

    // It must also verify as a standard Ed25519 signature.
    if !FrostEngine::verify_with_ed25519(&group_key.bytes, KAT_MESSAGE, &signature.bytes)
        .map_err(|e| format!("ed25519 verify: {e}"))?
    {
        return Err("FROST signature failed standard Ed25519 verification".to_string());
    }

    // NEGATIVE check: the signature must NOT verify against a different message.
    match FrostEngine::verify(&group_key, b"tampered message", &signature) {
        Ok(false) | Err(_) => {}
        Ok(true) => return Err("FROST signature verified against a tampered message".to_string()),
    }

    Ok(())
}

/// Known Answer Test for Threshold ECDSA P-256.
///
/// HONEST self-test: the threshold-ECDSA signing path is intentionally disabled
/// (fails closed with [`ThresholdError::NotImplemented`]) because the protocol
/// does not compute the modular inverse of the nonce and would otherwise emit
/// signatures that never verify. A "passing KAT" for a broken algorithm would
/// be false compliance, so this KAT instead asserts that the signing path is
/// correctly DISABLED: it drives keygen + nonce generation and then requires
/// that `presign` (and `sign_share`) return `NotImplemented`. The scheme is
/// reported as not operational; it is NOT presented as a passing crypto KAT.
fn test_threshold_ecdsa_p256_kat() -> Result<(), String> {
    use crate::threshold::ecdsa::ThresholdEcdsaEngine;
    use crate::threshold::types::{EcdsaCurve, ThresholdConfig, ThresholdError};

    let config = ThresholdConfig::new(2, 3).map_err(|e| format!("config: {e}"))?;
    let (group_key, shares) = ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256)
        .map_err(|e| format!("keygen: {e}"))?;

    // P-256 must be reported as FIPS-approved at the curve level even though
    // the threshold *signing* protocol is not operational.
    if !group_key.is_fips_approved() {
        return Err("P-256 threshold group key unexpectedly not FIPS approved".to_string());
    }

    // Round 1 succeeds (nonce generation is sound).
    let (nonce0, commit0) =
        ThresholdEcdsaEngine::generate_nonces(&shares[0]).map_err(|e| format!("nonces[0]: {e}"))?;
    let (_nonce1, commit1) =
        ThresholdEcdsaEngine::generate_nonces(&shares[1]).map_err(|e| format!("nonces[1]: {e}"))?;
    let commitments = vec![commit0, commit1];
    let participants = vec![shares[0].participant_id, shares[1].participant_id];

    // The signing path MUST fail closed: presign returns NotImplemented.
    match ThresholdEcdsaEngine::presign(&shares[0], &nonce0, &commitments, &participants) {
        Err(ThresholdError::NotImplemented(_)) => {}
        Err(e) => {
            return Err(format!(
                "threshold ECDSA presign expected NotImplemented, got error: {e}"
            ))
        }
        Ok(_) => {
            return Err(
                "threshold ECDSA presign UNEXPECTEDLY succeeded; broken signing path is enabled"
                    .to_string(),
            )
        }
    }

    // The KAT is honest: it confirms the broken algorithm is disabled rather
    // than claiming a passing signing KAT. Returning Ok here means "the disabled
    // state is correct", which the runner surfaces with the 'not operational'
    // label below.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_kat() {
        let result = test_sha256(b"abc").unwrap();
        assert_eq!(
            result,
            vec![
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn test_self_test_runner() {
        let runner = SelfTestRunner::new();
        let result = runner.run_all_tests().unwrap();

        assert_eq!(result.status, SelfTestStatus::Passed);
        assert!(result.failed_tests.is_empty());
    }

    #[test]
    fn test_individual_test() {
        let runner = SelfTestRunner::new();
        let result = runner.run_test("SHA-256").unwrap();

        assert!(result.passed);
    }

    #[test]
    fn test_aes_gcm_kat() {
        // NIST GCM vector: key/IV all zero, empty AAD, 16 zero-byte plaintext.
        // Result is ciphertext || tag.
        let result = test_aes_256_gcm(&[0u8; 16]).unwrap();
        assert_eq!(
            result,
            vec![
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
                0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
                0xd4, 0x8a, 0xb9, 0x19,
            ]
        );
    }

    #[test]
    fn test_hmac_kat() {
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?".
        let result = test_hmac_sha256(b"what do ya want for nothing?").unwrap();
        assert_eq!(
            result,
            vec![
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ]
        );
    }

    // ============ Threshold KAT Tests ============

    #[test]
    fn test_frost_ed25519_kat_passes() {
        let result = test_frost_ed25519_kat();
        assert!(result.is_ok(), "FROST Ed25519 KAT failed: {:?}", result);
    }

    #[test]
    fn test_threshold_ecdsa_p256_kat_passes() {
        // "Passes" here means the disabled-state check succeeded: the signing
        // path is correctly fail-closed. It is NOT a passing crypto signing KAT.
        let result = test_threshold_ecdsa_p256_kat();
        assert!(
            result.is_ok(),
            "Threshold ECDSA P-256 disabled-state KAT failed: {:?}",
            result
        );
    }

    /// The threshold-ECDSA KAT must FAIL if the signing path ever starts
    /// returning a signature instead of `NotImplemented`, so it can never be
    /// used to report a passing KAT for the broken algorithm. We assert the
    /// honest property directly: presign is fail-closed.
    #[test]
    fn test_threshold_ecdsa_p256_signing_is_disabled() {
        use crate::threshold::ecdsa::ThresholdEcdsaEngine;
        use crate::threshold::types::{EcdsaCurve, ThresholdConfig, ThresholdError};

        let config = ThresholdConfig::new(2, 3).unwrap();
        let (_group_key, shares) =
            ThresholdEcdsaEngine::trusted_dealer_keygen(config, EcdsaCurve::P256).unwrap();

        let (nonce0, commit0) = ThresholdEcdsaEngine::generate_nonces(&shares[0]).unwrap();
        let (_n1, commit1) = ThresholdEcdsaEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![commit0, commit1];
        let participants = vec![shares[0].participant_id, shares[1].participant_id];

        let result =
            ThresholdEcdsaEngine::presign(&shares[0], &nonce0, &commitments, &participants);
        assert!(
            matches!(result, Err(ThresholdError::NotImplemented(_))),
            "threshold ECDSA presign must fail closed with NotImplemented, got: {result:?}"
        );
    }

    /// The FROST KAT must reject a tampered signature — proving the verifier in
    /// the KAT is real, not a no-op. We tamper one byte of a real signature and
    /// require verification to fail.
    #[test]
    fn test_frost_ed25519_kat_rejects_tampered_signature() {
        use crate::threshold::frost::FrostEngine;
        use crate::threshold::types::ThresholdConfig;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let (group_key, shares) = FrostEngine::trusted_dealer_keygen(config).unwrap();
        let msg = b"frost negative test";

        let (n0, c0) = FrostEngine::generate_nonces(&shares[0]).unwrap();
        let (n1, c1) = FrostEngine::generate_nonces(&shares[1]).unwrap();
        let commitments = vec![c0, c1];
        let s0 = FrostEngine::sign_share(&shares[0], &n0, msg, &commitments, &group_key).unwrap();
        let s1 = FrostEngine::sign_share(&shares[1], &n1, msg, &commitments, &group_key).unwrap();
        let mut sig =
            FrostEngine::aggregate_signatures(msg, &commitments, &[s0, s1], &group_key).unwrap();

        assert!(FrostEngine::verify(&group_key, msg, &sig).unwrap());

        // Flip a bit in the signature: it must no longer verify.
        sig.bytes[0] ^= 0x01;
        let verified = FrostEngine::verify(&group_key, msg, &sig).unwrap_or(false);
        assert!(!verified, "tampered FROST signature unexpectedly verified");
    }

    #[test]
    fn test_self_test_runner_includes_threshold_tests() {
        let runner = SelfTestRunner::new();

        let threshold_names = runner.threshold_test_names();
        assert!(threshold_names.contains(&"FROST-Ed25519-KAT"));
        assert!(threshold_names.contains(&"Threshold-ECDSA-P256-KAT"));
    }

    #[test]
    fn test_run_threshold_tests() {
        let runner = SelfTestRunner::new();
        let results = runner.run_threshold_tests();

        assert_eq!(results.len(), 2);
        assert!(
            results.iter().all(|r| r.passed),
            "All threshold KATs should pass"
        );
    }

    #[test]
    fn test_run_individual_threshold_test() {
        let runner = SelfTestRunner::new();

        let frost_result = runner.run_threshold_test("FROST-Ed25519-KAT");
        assert!(frost_result.is_some());
        assert!(frost_result.unwrap().passed);

        let ecdsa_result = runner.run_threshold_test("Threshold-ECDSA-P256-KAT");
        assert!(ecdsa_result.is_some());
        assert!(ecdsa_result.unwrap().passed);

        // Non-existent test
        let none_result = runner.run_threshold_test("NonExistent-KAT");
        assert!(none_result.is_none());
    }

    #[test]
    fn test_run_all_tests_including_threshold() {
        let runner = SelfTestRunner::new();
        let result = runner.run_all_tests_including_threshold().unwrap();

        assert_eq!(result.status, SelfTestStatus::Passed);
        assert!(result.failed_tests.is_empty());

        // Should include both standard and threshold tests
        let test_names: Vec<&str> = result.tests.iter().map(|t| t.name.as_str()).collect();
        assert!(test_names.contains(&"SHA-256"));
        assert!(test_names.contains(&"FROST-Ed25519-KAT"));
        assert!(test_names.contains(&"Threshold-ECDSA-P256-KAT"));
    }
}
