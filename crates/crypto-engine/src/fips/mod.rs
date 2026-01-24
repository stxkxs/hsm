//! FIPS 140-3 Compliance Module
//!
//! Provides FIPS 140-3 compliance features for the HSM crypto engine:
//! - FIPS mode enforcement (only approved algorithms)
//! - Power-on self tests (POST) with Known Answer Tests (KAT)
//! - Continuous random number generator tests
//! - Module integrity verification
//! - FIPS audit logging
//!
//! # FIPS 140-3 Overview
//!
//! FIPS 140-3 is a U.S. government security standard for cryptographic modules.
//! Key requirements:
//!
//! - **Approved Algorithms**: Only NIST-approved algorithms may be used
//! - **Self Tests**: Module must verify correct operation on startup
//! - **RNG Testing**: Continuous testing of random number output
//! - **Module Integrity**: Binary must verify its own integrity
//! - **Key Zeroization**: Sensitive data must be securely erased
//!
//! # Approved Algorithms
//!
//! FIPS 140-3 approved algorithms (SP 800-140C):
//!
//! | Type | Algorithms |
//! |------|------------|
//! | Symmetric Encryption | AES (128, 192, 256 bit keys) |
//! | Hashing | SHA-2 (256, 384, 512), SHA-3 |
//! | Digital Signatures | RSA (2048+), ECDSA (P-256, P-384, P-521) |
//! | Key Agreement | DH, ECDH |
//! | Message Authentication | HMAC, CMAC |
//! | Random Number | SP 800-90A DRBG |
//!
//! # Usage
//!
//! ```rust,no_run
//! use hsm_crypto_engine::fips::{FipsMode, FipsError, Algorithm};
//!
//! // Initialize FIPS mode
//! let fips = FipsMode::initialize().expect("FIPS init failed");
//!
//! // Check if algorithm is approved
//! if fips.is_approved(Algorithm::Aes256) {
//!     // Use the algorithm
//! }
//!
//! // Get FIPS status
//! println!("FIPS mode: {}", fips.is_enabled());
//! println!("Self-test passed: {}", fips.self_test_passed());
//! ```

pub mod algorithms;
pub mod audit;
pub mod integrity;
pub mod mode;
pub mod rng;
pub mod self_test;

pub use algorithms::{Algorithm, ApprovedAlgorithms};
pub use audit::{FipsAuditEvent, FipsAuditEventType, FipsAuditHandler, FipsAuditLog};
pub use integrity::{IntegrityChecker, IntegrityResult, RuntimeIntegrityMonitor};
pub use mode::{
    is_fips_mode_requested, FipsError, FipsMode, FipsStatus, ThresholdConfig, ThresholdScheme,
};
pub use rng::FipsDrbg;
pub use self_test::{
    KnownAnswerTest, SelfTestResult, SelfTestRunner, SelfTestStatus, TestResult, ThresholdKat,
};
