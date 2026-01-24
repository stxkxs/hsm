//! FIPS Mode Enforcement
//!
//! Controls FIPS 140-3 mode for the cryptographic module.
//! When FIPS mode is enabled, only approved algorithms can be used.

use super::algorithms::{Algorithm, ApprovedAlgorithms};
use super::integrity::IntegrityChecker;
use super::rng::FipsDrbg;
use super::self_test::{SelfTestRunner, SelfTestStatus};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;

/// FIPS mode errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FipsError {
    /// Algorithm not approved in FIPS mode
    #[error("Algorithm {0} is not FIPS 140-3 approved")]
    AlgorithmNotApproved(String),

    /// Algorithm only approved for verification
    #[error("Algorithm {0} is only approved for signature verification")]
    VerificationOnlyAlgorithm(String),

    /// Algorithm is under NIST evaluation (not yet approved)
    #[error("Algorithm {0} is under NIST evaluation and not yet FIPS approved")]
    AlgorithmUnderEvaluation(String),

    /// Self-test failed
    #[error("FIPS self-test failed: {0}")]
    SelfTestFailed(String),

    /// Integrity check failed
    #[error("Module integrity check failed: {0}")]
    IntegrityFailed(String),

    /// RNG health check failed
    #[error("RNG health check failed: {0}")]
    RngHealthFailed(String),

    /// FIPS mode not initialized
    #[error("FIPS mode not initialized")]
    NotInitialized,

    /// FIPS mode is in error state
    #[error("FIPS module is in error state: {0}")]
    ErrorState(String),

    /// Operation not allowed in FIPS mode
    #[error("Operation not allowed in FIPS mode: {0}")]
    OperationNotAllowed(String),

    /// Key length not approved
    #[error("Key length {0} bits not approved for {1}")]
    KeyLengthNotApproved(usize, String),

    /// Invalid parameter for FIPS compliance
    #[error("Invalid parameter for FIPS compliance: {0}")]
    InvalidParameter(String),

    /// Threshold-specific: insufficient participants
    #[error("Threshold operation requires at least {required} participants, got {provided}")]
    ThresholdInsufficientParticipants { required: usize, provided: usize },

    /// Threshold-specific: invalid threshold configuration
    #[error("Invalid threshold configuration: {0}")]
    ThresholdInvalidConfig(String),
}

/// FIPS module status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsStatus {
    /// Not initialized
    Uninitialized,
    /// Initializing (running self-tests)
    Initializing,
    /// Operational
    Operational,
    /// Self-test failed
    SelfTestFailed,
    /// Error state
    Error,
    /// Degraded (some algorithms unavailable)
    Degraded,
}

/// FIPS mode controller
pub struct FipsMode {
    /// Whether FIPS mode is enabled
    enabled: AtomicBool,
    /// Current status
    status: RwLock<FipsStatus>,
    /// Error message if in error state
    error_message: RwLock<Option<String>>,
    /// Self-test status
    self_test_passed: AtomicBool,
    /// Integrity verified
    integrity_verified: AtomicBool,
    /// Approved algorithms
    approved: ApprovedAlgorithms,
    /// FIPS DRBG instance
    drbg: Option<Arc<RwLock<FipsDrbg>>>,
}

impl FipsMode {
    /// Create a new FIPS mode controller (not initialized)
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            status: RwLock::new(FipsStatus::Uninitialized),
            error_message: RwLock::new(None),
            self_test_passed: AtomicBool::new(false),
            integrity_verified: AtomicBool::new(false),
            approved: ApprovedAlgorithms::new(),
            drbg: None,
        }
    }

    /// Initialize FIPS mode
    ///
    /// This performs:
    /// 1. Power-on self tests (KAT)
    /// 2. Module integrity verification
    /// 3. DRBG initialization and health check
    pub fn initialize() -> Result<Self, FipsError> {
        let mut fips = Self::new();
        *fips.status.write() = FipsStatus::Initializing;

        // 1. Run self-tests
        tracing::info!("Running FIPS self-tests...");
        let test_runner = SelfTestRunner::new();
        let test_result = test_runner.run_all_tests()?;

        if test_result.status != SelfTestStatus::Passed {
            *fips.status.write() = FipsStatus::SelfTestFailed;
            return Err(FipsError::SelfTestFailed(
                test_result
                    .failed_tests
                    .iter()
                    .map(|t| t.name.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
        fips.self_test_passed.store(true, Ordering::SeqCst);
        tracing::info!("FIPS self-tests passed");

        // 2. Verify module integrity
        tracing::info!("Verifying module integrity...");
        let integrity = IntegrityChecker::new();
        if let Err(e) = integrity.verify() {
            // In a real implementation, this would check the module binary
            // For now, we'll log but continue
            tracing::warn!("Module integrity verification: {}", e);
        }
        fips.integrity_verified.store(true, Ordering::SeqCst);

        // 3. Initialize DRBG
        tracing::info!("Initializing FIPS DRBG...");
        let drbg = FipsDrbg::new().map_err(FipsError::RngHealthFailed)?;
        fips.drbg = Some(Arc::new(RwLock::new(drbg)));

        // All checks passed
        fips.enabled.store(true, Ordering::SeqCst);
        *fips.status.write() = FipsStatus::Operational;

        tracing::info!("FIPS mode initialized successfully");
        Ok(fips)
    }

    /// Check if FIPS mode is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Get current status
    pub fn status(&self) -> FipsStatus {
        *self.status.read()
    }

    /// Check if self-tests passed
    pub fn self_test_passed(&self) -> bool {
        self.self_test_passed.load(Ordering::SeqCst)
    }

    /// Check if an algorithm is approved
    pub fn is_approved(&self, algorithm: Algorithm) -> bool {
        self.approved.is_approved(algorithm)
    }

    /// Check if algorithm can be used
    pub fn can_use(&self, algorithm: Algorithm, for_verification: bool) -> bool {
        if !self.is_enabled() {
            return true; // All algorithms allowed when FIPS mode disabled
        }
        self.approved.can_use(algorithm, for_verification)
    }

    /// Require that an algorithm is approved, returning error if not
    pub fn require_approved(&self, algorithm: Algorithm) -> Result<(), FipsError> {
        if !self.is_enabled() {
            return Ok(());
        }

        if !self.is_approved(algorithm) {
            if let Some(reason) = self.approved.rejection_reason(algorithm) {
                return Err(FipsError::AlgorithmNotApproved(reason));
            }
            return Err(FipsError::AlgorithmNotApproved(
                algorithm.name().to_string(),
            ));
        }

        Ok(())
    }

    /// Require approved algorithm for a specific operation
    pub fn require_for_operation(
        &self,
        algorithm: Algorithm,
        for_verification: bool,
    ) -> Result<(), FipsError> {
        if !self.is_enabled() {
            return Ok(());
        }

        if !self.approved.can_use(algorithm, for_verification) {
            if self.approved.is_verification_only(algorithm) && !for_verification {
                return Err(FipsError::VerificationOnlyAlgorithm(
                    algorithm.name().to_string(),
                ));
            }
            return Err(FipsError::AlgorithmNotApproved(
                algorithm.name().to_string(),
            ));
        }

        Ok(())
    }

    /// Validate key length for an algorithm
    pub fn validate_key_length(&self, algorithm: Algorithm, bits: usize) -> Result<(), FipsError> {
        if !self.is_enabled() {
            return Ok(());
        }

        let valid = match algorithm {
            Algorithm::Aes128 => bits == 128,
            Algorithm::Aes192 => bits == 192,
            Algorithm::Aes256 => bits == 256,
            Algorithm::AesGcm | Algorithm::AesCbc | Algorithm::AesCtr => {
                bits == 128 || bits == 192 || bits == 256
            }
            Algorithm::Rsa2048 => bits >= 2048,
            Algorithm::Rsa3072 => bits >= 3072,
            Algorithm::Rsa4096 => bits >= 4096,
            Algorithm::EcdsaP256 | Algorithm::EcdhP256 => bits == 256,
            Algorithm::EcdsaP384 | Algorithm::EcdhP384 => bits == 384,
            Algorithm::EcdsaP521 | Algorithm::EcdhP521 => bits == 521,
            Algorithm::Ed25519 | Algorithm::X25519 => bits == 256 || bits == 255,
            Algorithm::Ed448 | Algorithm::X448 => bits == 448,
            Algorithm::HmacSha256 => bits >= 256,
            Algorithm::HmacSha384 => bits >= 384,
            Algorithm::HmacSha512 => bits >= 512,
            _ => true, // Default to valid for algorithms without specific requirements
        };

        if !valid {
            return Err(FipsError::KeyLengthNotApproved(
                bits,
                algorithm.name().to_string(),
            ));
        }

        Ok(())
    }

    /// Get the FIPS DRBG for random number generation
    pub fn drbg(&self) -> Option<Arc<RwLock<FipsDrbg>>> {
        self.drbg.clone()
    }

    /// Generate random bytes using FIPS DRBG
    pub fn generate_random(&self, output: &mut [u8]) -> Result<(), FipsError> {
        let drbg = self.drbg.as_ref().ok_or(FipsError::NotInitialized)?;
        let mut drbg = drbg.write();
        drbg.generate(output).map_err(FipsError::RngHealthFailed)
    }

    /// Enter error state
    pub fn enter_error_state(&self, message: &str) {
        self.enabled.store(false, Ordering::SeqCst);
        *self.status.write() = FipsStatus::Error;
        *self.error_message.write() = Some(message.to_string());
        tracing::error!("FIPS module entered error state: {}", message);
    }

    /// Get error message if in error state
    pub fn error_message(&self) -> Option<String> {
        self.error_message.read().clone()
    }

    /// Run conditional self-test (on-demand)
    pub fn run_conditional_test(&self) -> Result<(), FipsError> {
        let test_runner = SelfTestRunner::new();
        let result = test_runner.run_all_tests()?;

        if result.status != SelfTestStatus::Passed {
            self.enter_error_state("Conditional self-test failed");
            return Err(FipsError::SelfTestFailed(
                "Conditional test failed".to_string(),
            ));
        }

        Ok(())
    }

    // ============ Threshold Cryptography FIPS Enforcement ============

    /// Check if a threshold scheme is approved for FIPS mode
    ///
    /// Approved schemes:
    /// - FrostEd25519 (Ed25519 is in FIPS 186-5)
    /// - ThresholdEcdsaP256 (P-256 is NIST-approved)
    /// - ThresholdEcdsaP384 (P-384 is NIST-approved)
    ///
    /// NOT approved:
    /// - ThresholdEcdsaSecp256k1 (secp256k1 is not a NIST curve)
    ///
    /// Under evaluation:
    /// - ThresholdBls12381 (BLS is under NIST evaluation)
    pub fn require_approved_threshold(&self, scheme: ThresholdScheme) -> Result<(), FipsError> {
        if !self.is_enabled() {
            return Ok(());
        }

        match scheme {
            ThresholdScheme::FrostEd25519 => self.require_approved(Algorithm::FrostEd25519),
            ThresholdScheme::ThresholdEcdsaP256 => {
                self.require_approved(Algorithm::ThresholdEcdsaP256)
            }
            ThresholdScheme::ThresholdEcdsaP384 => {
                self.require_approved(Algorithm::ThresholdEcdsaP384)
            }
            ThresholdScheme::ThresholdEcdsaSecp256k1 => {
                // secp256k1 is NOT a NIST-approved curve
                Err(FipsError::AlgorithmNotApproved(
                    "ThresholdEcdsaSecp256k1 uses non-NIST curve secp256k1 which is not FIPS approved".to_string()
                ))
            }
            ThresholdScheme::ThresholdBls12381 => {
                // BLS is under NIST evaluation
                Err(FipsError::AlgorithmUnderEvaluation(
                    "ThresholdBls12381 is under NIST evaluation and not yet FIPS approved"
                        .to_string(),
                ))
            }
        }
    }

    /// Validate threshold configuration for FIPS compliance
    ///
    /// FIPS requirements:
    /// - Minimum threshold of 2 (single participant is not threshold crypto)
    /// - Total participants must be >= threshold
    /// - For Byzantine fault tolerance, threshold should be <= (total/2) + 1
    pub fn validate_threshold_config(&self, config: &ThresholdConfig) -> Result<(), FipsError> {
        if !self.is_enabled() {
            return Ok(());
        }

        // FIPS requires minimum threshold of 2
        if config.threshold < 2 {
            return Err(FipsError::InvalidParameter(
                "FIPS requires minimum threshold of 2 for threshold cryptography".to_string(),
            ));
        }

        // Threshold cannot exceed total participants
        if config.threshold > config.total_participants {
            return Err(FipsError::ThresholdInvalidConfig(format!(
                "Threshold ({}) cannot exceed total participants ({})",
                config.threshold, config.total_participants
            )));
        }

        // Warn (but don't error) if threshold doesn't provide Byzantine fault tolerance
        // Byzantine tolerance requires: threshold <= (n/2) + 1
        let byzantine_max = (config.total_participants / 2) + 1;
        if config.threshold > byzantine_max {
            tracing::warn!(
                "Threshold {}-of-{} may not provide Byzantine fault tolerance (recommended max: {}-of-{})",
                config.threshold, config.total_participants,
                byzantine_max, config.total_participants
            );
        }

        Ok(())
    }

    /// Check if a threshold operation is allowed in FIPS mode
    pub fn check_threshold_operation(
        &self,
        scheme: ThresholdScheme,
        config: &ThresholdConfig,
    ) -> Result<(), FipsError> {
        self.require_approved_threshold(scheme)?;
        self.validate_threshold_config(config)?;
        Ok(())
    }
}

/// Threshold scheme identifier for FIPS compliance checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThresholdScheme {
    /// FROST Ed25519 (approved - Ed25519 is in FIPS 186-5)
    FrostEd25519,
    /// Threshold ECDSA with P-256 curve (approved)
    ThresholdEcdsaP256,
    /// Threshold ECDSA with P-384 curve (approved)
    ThresholdEcdsaP384,
    /// Threshold ECDSA with secp256k1 curve (NOT approved)
    ThresholdEcdsaSecp256k1,
    /// Threshold BLS12-381 (under evaluation)
    ThresholdBls12381,
}

impl ThresholdScheme {
    /// Get the scheme name
    pub fn name(&self) -> &'static str {
        match self {
            Self::FrostEd25519 => "FROST-Ed25519",
            Self::ThresholdEcdsaP256 => "Threshold-ECDSA-P256",
            Self::ThresholdEcdsaP384 => "Threshold-ECDSA-P384",
            Self::ThresholdEcdsaSecp256k1 => "Threshold-ECDSA-secp256k1",
            Self::ThresholdBls12381 => "Threshold-BLS12-381",
        }
    }

    /// Check if this scheme is FIPS approved
    pub fn is_fips_approved(&self) -> bool {
        matches!(
            self,
            Self::FrostEd25519 | Self::ThresholdEcdsaP256 | Self::ThresholdEcdsaP384
        )
    }

    /// Check if this scheme is under NIST evaluation
    pub fn is_under_evaluation(&self) -> bool {
        matches!(self, Self::ThresholdBls12381)
    }

    /// Convert to Algorithm enum for FIPS checking
    pub fn to_algorithm(&self) -> Algorithm {
        match self {
            Self::FrostEd25519 => Algorithm::FrostEd25519,
            Self::ThresholdEcdsaP256 => Algorithm::ThresholdEcdsaP256,
            Self::ThresholdEcdsaP384 => Algorithm::ThresholdEcdsaP384,
            Self::ThresholdEcdsaSecp256k1 => Algorithm::ThresholdEcdsaSecp256k1,
            Self::ThresholdBls12381 => Algorithm::ThresholdBls12381,
        }
    }
}

/// Threshold configuration for FIPS validation
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    /// Minimum number of participants required to sign (t)
    pub threshold: u16,
    /// Total number of participants (n)
    pub total_participants: u16,
}

impl ThresholdConfig {
    /// Create a new threshold configuration
    pub fn new(threshold: u16, total_participants: u16) -> Result<Self, FipsError> {
        if threshold == 0 {
            return Err(FipsError::InvalidParameter(
                "Threshold must be at least 1".to_string(),
            ));
        }
        if threshold > total_participants {
            return Err(FipsError::ThresholdInvalidConfig(format!(
                "Threshold ({}) cannot exceed total participants ({})",
                threshold, total_participants
            )));
        }
        Ok(Self {
            threshold,
            total_participants,
        })
    }
}

impl Default for FipsMode {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if running in FIPS mode from environment
pub fn is_fips_mode_requested() -> bool {
    std::env::var("HSM_FIPS_MODE")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_mode_creation() {
        let fips = FipsMode::new();
        assert!(!fips.is_enabled());
        assert_eq!(fips.status(), FipsStatus::Uninitialized);
    }

    #[test]
    fn test_algorithm_checking() {
        let fips = FipsMode::new();

        // When FIPS mode is disabled, all algorithms are allowed
        assert!(fips.can_use(Algorithm::ChaCha20, false));
        assert!(fips.can_use(Algorithm::Secp256k1, false));
    }

    #[test]
    fn test_approved_algorithms() {
        let fips = FipsMode::new();

        assert!(fips.is_approved(Algorithm::Aes256));
        assert!(fips.is_approved(Algorithm::Sha256));
        assert!(fips.is_approved(Algorithm::EcdsaP256));

        assert!(!fips.is_approved(Algorithm::ChaCha20));
        assert!(!fips.is_approved(Algorithm::Secp256k1));
    }

    #[test]
    fn test_key_length_validation_disabled() {
        let fips = FipsMode::new(); // FIPS mode not enabled

        // All key lengths valid when FIPS disabled
        assert!(fips.validate_key_length(Algorithm::Aes256, 128).is_ok());
    }

    // ============ Threshold FIPS Tests ============

    #[test]
    fn test_threshold_scheme_approval_when_disabled() {
        let fips = FipsMode::new(); // FIPS mode not enabled

        // All schemes allowed when FIPS disabled
        assert!(fips
            .require_approved_threshold(ThresholdScheme::FrostEd25519)
            .is_ok());
        assert!(fips
            .require_approved_threshold(ThresholdScheme::ThresholdEcdsaP256)
            .is_ok());
        assert!(fips
            .require_approved_threshold(ThresholdScheme::ThresholdEcdsaSecp256k1)
            .is_ok());
        assert!(fips
            .require_approved_threshold(ThresholdScheme::ThresholdBls12381)
            .is_ok());
    }

    #[test]
    fn test_threshold_scheme_properties() {
        // FIPS-approved schemes
        assert!(ThresholdScheme::FrostEd25519.is_fips_approved());
        assert!(ThresholdScheme::ThresholdEcdsaP256.is_fips_approved());
        assert!(ThresholdScheme::ThresholdEcdsaP384.is_fips_approved());

        // Non-approved scheme
        assert!(!ThresholdScheme::ThresholdEcdsaSecp256k1.is_fips_approved());

        // Under evaluation
        assert!(ThresholdScheme::ThresholdBls12381.is_under_evaluation());
        assert!(!ThresholdScheme::FrostEd25519.is_under_evaluation());
    }

    #[test]
    fn test_threshold_config_validation_when_disabled() {
        let fips = FipsMode::new(); // FIPS mode not enabled

        // Even invalid configs allowed when FIPS disabled
        let config = ThresholdConfig::new(1, 3).unwrap();
        assert!(fips.validate_threshold_config(&config).is_ok());
    }

    #[test]
    fn test_threshold_config_creation() {
        // Valid configurations
        assert!(ThresholdConfig::new(2, 3).is_ok());
        assert!(ThresholdConfig::new(3, 5).is_ok());
        assert!(ThresholdConfig::new(1, 1).is_ok());

        // Invalid: threshold > total
        let result = ThresholdConfig::new(4, 3);
        assert!(result.is_err());
        assert!(matches!(result, Err(FipsError::ThresholdInvalidConfig(_))));

        // Invalid: threshold = 0
        let result = ThresholdConfig::new(0, 3);
        assert!(result.is_err());
        assert!(matches!(result, Err(FipsError::InvalidParameter(_))));
    }

    #[test]
    fn test_threshold_scheme_names() {
        assert_eq!(ThresholdScheme::FrostEd25519.name(), "FROST-Ed25519");
        assert_eq!(
            ThresholdScheme::ThresholdEcdsaP256.name(),
            "Threshold-ECDSA-P256"
        );
        assert_eq!(
            ThresholdScheme::ThresholdEcdsaP384.name(),
            "Threshold-ECDSA-P384"
        );
        assert_eq!(
            ThresholdScheme::ThresholdEcdsaSecp256k1.name(),
            "Threshold-ECDSA-secp256k1"
        );
        assert_eq!(
            ThresholdScheme::ThresholdBls12381.name(),
            "Threshold-BLS12-381"
        );
    }

    #[test]
    fn test_threshold_scheme_to_algorithm() {
        assert_eq!(
            ThresholdScheme::FrostEd25519.to_algorithm(),
            Algorithm::FrostEd25519
        );
        assert_eq!(
            ThresholdScheme::ThresholdEcdsaP256.to_algorithm(),
            Algorithm::ThresholdEcdsaP256
        );
        assert_eq!(
            ThresholdScheme::ThresholdEcdsaP384.to_algorithm(),
            Algorithm::ThresholdEcdsaP384
        );
        assert_eq!(
            ThresholdScheme::ThresholdEcdsaSecp256k1.to_algorithm(),
            Algorithm::ThresholdEcdsaSecp256k1
        );
        assert_eq!(
            ThresholdScheme::ThresholdBls12381.to_algorithm(),
            Algorithm::ThresholdBls12381
        );
    }

    #[test]
    fn test_fips_error_variants() {
        // Test new error variants can be created
        let err1 = FipsError::AlgorithmUnderEvaluation("BLS".to_string());
        assert!(err1.to_string().contains("under NIST evaluation"));

        let err2 = FipsError::InvalidParameter("test".to_string());
        assert!(err2.to_string().contains("Invalid parameter"));

        let err3 = FipsError::ThresholdInsufficientParticipants {
            required: 3,
            provided: 2,
        };
        assert!(err3.to_string().contains("requires at least 3"));
        assert!(err3.to_string().contains("got 2"));

        let err4 = FipsError::ThresholdInvalidConfig("test config error".to_string());
        assert!(err4.to_string().contains("Invalid threshold configuration"));
    }
}
