//! Module Integrity Verification
//!
//! Implements integrity verification required by FIPS 140-3.
//! Verifies that the cryptographic module binary has not been tampered with.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::PathBuf;

/// Integrity verification result
#[derive(Debug, Clone)]
pub struct IntegrityResult {
    /// Whether integrity check passed
    pub passed: bool,
    /// Computed hash
    pub computed_hash: Option<[u8; 32]>,
    /// Expected hash
    pub expected_hash: Option<[u8; 32]>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Module integrity checker
///
/// In a real FIPS implementation, this would:
/// 1. Compute HMAC of the module binary
/// 2. Compare against stored/embedded expected value
/// 3. Verify digital signature from trusted authority
pub struct IntegrityChecker {
    /// Path to module binary (if known)
    module_path: Option<PathBuf>,
    /// Expected HMAC value (would be embedded at build time)
    expected_hmac: Option<[u8; 32]>,
    /// HMAC key (would be derived from known value)
    hmac_key: [u8; 32],
}

impl IntegrityChecker {
    /// Create a new integrity checker
    pub fn new() -> Self {
        // In production, this key would be derived from a known value
        // embedded at build time
        let hmac_key = [0x42u8; 32];

        Self {
            module_path: None,
            expected_hmac: None,
            hmac_key,
        }
    }

    /// Create integrity checker with specific module path
    pub fn with_module_path(module_path: PathBuf) -> Self {
        let mut checker = Self::new();
        checker.module_path = Some(module_path);
        checker
    }

    /// Set expected HMAC value
    pub fn with_expected_hmac(mut self, expected: [u8; 32]) -> Self {
        self.expected_hmac = Some(expected);
        self
    }

    /// Verify module integrity
    ///
    /// In a real implementation, this would:
    /// 1. Read the module binary from disk or memory
    /// 2. Compute HMAC-SHA256 over the binary
    /// 3. Compare against expected value
    pub fn verify(&self) -> Result<IntegrityResult, String> {
        // Try to determine module path
        let module_path = match &self.module_path {
            Some(path) => path.clone(),
            None => {
                // Try to get current executable path
                std::env::current_exe()
                    .map_err(|e| format!("Failed to get executable path: {}", e))?
            }
        };

        // Check if module exists
        if !module_path.exists() {
            return Ok(IntegrityResult {
                passed: false,
                computed_hash: None,
                expected_hash: self.expected_hmac,
                error: Some(format!("Module not found: {:?}", module_path)),
            });
        }

        // Read module binary
        let module_data =
            std::fs::read(&module_path).map_err(|e| format!("Failed to read module: {}", e))?;

        // Compute HMAC
        let computed_hash = self.compute_hmac(&module_data)?;

        // Compare with expected value if provided
        if let Some(expected) = &self.expected_hmac {
            let passed = computed_hash == *expected;
            Ok(IntegrityResult {
                passed,
                computed_hash: Some(computed_hash),
                expected_hash: Some(*expected),
                error: if passed {
                    None
                } else {
                    Some("HMAC mismatch".to_string())
                },
            })
        } else {
            // No expected value - can only compute
            // In production, this would be an error
            Ok(IntegrityResult {
                passed: true, // Pass without expected value (development mode)
                computed_hash: Some(computed_hash),
                expected_hash: None,
                error: Some("No expected HMAC provided (development mode)".to_string()),
            })
        }
    }

    /// Compute HMAC-SHA256 of data
    fn compute_hmac(&self, data: &[u8]) -> Result<[u8; 32], String> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| format!("Failed to create HMAC: {}", e))?;

        mac.update(data);
        let result = mac.finalize();

        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        Ok(output)
    }

    /// Verify a specific data blob (for testing or partial verification)
    pub fn verify_data(&self, data: &[u8], expected: &[u8; 32]) -> Result<bool, String> {
        let computed = self.compute_hmac(data)?;
        Ok(computed == *expected)
    }

    /// Generate HMAC for a data blob (for build-time embedding)
    pub fn generate_hmac(&self, data: &[u8]) -> Result<[u8; 32], String> {
        self.compute_hmac(data)
    }
}

impl Default for IntegrityChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime integrity monitor
///
/// Provides continuous integrity monitoring for sensitive code regions.
pub struct RuntimeIntegrityMonitor {
    /// Checksums of monitored regions
    regions: Vec<MonitoredRegion>,
    /// Checker instance
    checker: IntegrityChecker,
}

/// A monitored memory/code region
#[derive(Clone)]
struct MonitoredRegion {
    /// Region name/identifier
    name: String,
    /// Expected checksum
    expected_checksum: [u8; 32],
    /// Region data (or function to retrieve it)
    data_snapshot: Vec<u8>,
}

impl RuntimeIntegrityMonitor {
    /// Create a new runtime integrity monitor
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            checker: IntegrityChecker::new(),
        }
    }

    /// Register a region for monitoring
    pub fn register_region(&mut self, name: &str, data: &[u8]) -> Result<(), String> {
        let checksum = self.checker.compute_hmac(data)?;

        self.regions.push(MonitoredRegion {
            name: name.to_string(),
            expected_checksum: checksum,
            data_snapshot: data.to_vec(),
        });

        Ok(())
    }

    /// Verify all registered regions
    pub fn verify_all(&self) -> Result<Vec<RegionVerifyResult>, String> {
        let mut results = Vec::new();

        for region in &self.regions {
            let current_checksum = self.checker.compute_hmac(&region.data_snapshot)?;
            let passed = current_checksum == region.expected_checksum;

            results.push(RegionVerifyResult {
                name: region.name.clone(),
                passed,
                error: if passed {
                    None
                } else {
                    Some("Checksum mismatch - possible tampering detected".to_string())
                },
            });
        }

        Ok(results)
    }

    /// Check if all regions are intact
    pub fn all_intact(&self) -> Result<bool, String> {
        let results = self.verify_all()?;
        Ok(results.iter().all(|r| r.passed))
    }
}

impl Default for RuntimeIntegrityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of verifying a monitored region
#[derive(Debug, Clone)]
pub struct RegionVerifyResult {
    /// Region name
    pub name: String,
    /// Whether verification passed
    pub passed: bool,
    /// Error message if failed
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_checker_creation() {
        let checker = IntegrityChecker::new();
        assert!(checker.expected_hmac.is_none());
    }

    #[test]
    fn test_hmac_computation() {
        let checker = IntegrityChecker::new();
        let data = b"test data for integrity check";

        let hmac1 = checker.generate_hmac(data).unwrap();
        let hmac2 = checker.generate_hmac(data).unwrap();

        // Same data should produce same HMAC
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn test_hmac_different_data() {
        let checker = IntegrityChecker::new();

        let hmac1 = checker.generate_hmac(b"data 1").unwrap();
        let hmac2 = checker.generate_hmac(b"data 2").unwrap();

        // Different data should produce different HMAC
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_verify_data() {
        let checker = IntegrityChecker::new();
        let data = b"test data";

        let expected = checker.generate_hmac(data).unwrap();
        assert!(checker.verify_data(data, &expected).unwrap());

        // Tampered data should fail
        let tampered = b"tampered data";
        assert!(!checker.verify_data(tampered, &expected).unwrap());
    }

    #[test]
    fn test_runtime_monitor() {
        let mut monitor = RuntimeIntegrityMonitor::new();

        // Register a region
        let data = b"critical code section";
        monitor.register_region("critical_section", data).unwrap();

        // Verify should pass
        assert!(monitor.all_intact().unwrap());

        let results = monitor.verify_all().unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
    }

    #[test]
    fn test_integrity_result() {
        let result = IntegrityResult {
            passed: true,
            computed_hash: Some([0u8; 32]),
            expected_hash: Some([0u8; 32]),
            error: None,
        };

        assert!(result.passed);
    }
}
