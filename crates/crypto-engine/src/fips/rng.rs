//! FIPS-Compliant Deterministic Random Bit Generator (DRBG)
//!
//! Implements SP 800-90A compliant DRBG for FIPS mode.
//! Uses HMAC-DRBG with SHA-256 as the underlying hash function.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum number of requests before reseed required
const RESEED_INTERVAL: u64 = 1 << 20; // 2^20 requests

/// Maximum number of bytes per request
const MAX_REQUEST_SIZE: usize = 1 << 16; // 64KB

/// Minimum entropy input length (bytes)
const MIN_ENTROPY_LENGTH: usize = 32;

/// FIPS DRBG state
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FipsDrbg {
    /// Key material
    key: [u8; 32],
    /// Value (counter)
    value: [u8; 32],
    /// Request counter since last reseed
    reseed_counter: u64,
    /// Maximum requests before requiring reseed
    #[zeroize(skip)]
    reseed_interval: u64,
    /// Whether instantiated
    #[zeroize(skip)]
    instantiated: bool,
}

impl FipsDrbg {
    /// Create and instantiate a new FIPS DRBG
    pub fn new() -> Result<Self, String> {
        let mut drbg = Self {
            key: [0u8; 32],
            value: [0u8; 32],
            reseed_counter: 0,
            reseed_interval: RESEED_INTERVAL,
            instantiated: false,
        };

        // Get entropy from OS
        let mut entropy = [0u8; 48];
        getrandom::getrandom(&mut entropy).map_err(|e| format!("Failed to get entropy: {}", e))?;

        // Get nonce
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|e| format!("Failed to get nonce: {}", e))?;

        // Instantiate
        drbg.instantiate(&entropy, &nonce, None)?;

        // Run health check
        drbg.health_check()?;

        Ok(drbg)
    }

    /// Instantiate the DRBG
    fn instantiate(
        &mut self,
        entropy: &[u8],
        nonce: &[u8],
        personalization: Option<&[u8]>,
    ) -> Result<(), String> {
        if entropy.len() < MIN_ENTROPY_LENGTH {
            return Err(format!(
                "Entropy input too short: {} < {}",
                entropy.len(),
                MIN_ENTROPY_LENGTH
            ));
        }

        // Seed material = entropy || nonce || personalization
        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(entropy);
        seed_material.extend_from_slice(nonce);
        if let Some(pers) = personalization {
            seed_material.extend_from_slice(pers);
        }

        // Initialize K and V
        self.key = [0u8; 32];
        self.value = [0x01u8; 32];

        // Update with seed material
        self.update(Some(&seed_material))?;

        self.reseed_counter = 1;
        self.instantiated = true;

        // Zeroize seed material
        seed_material.zeroize();

        Ok(())
    }

    /// Reseed the DRBG
    pub fn reseed(&mut self, entropy: &[u8], additional: Option<&[u8]>) -> Result<(), String> {
        if !self.instantiated {
            return Err("DRBG not instantiated".to_string());
        }

        if entropy.len() < MIN_ENTROPY_LENGTH {
            return Err(format!(
                "Entropy input too short: {} < {}",
                entropy.len(),
                MIN_ENTROPY_LENGTH
            ));
        }

        // Reseed material = entropy || additional
        let mut reseed_material = Vec::new();
        reseed_material.extend_from_slice(entropy);
        if let Some(add) = additional {
            reseed_material.extend_from_slice(add);
        }

        self.update(Some(&reseed_material))?;
        self.reseed_counter = 1;

        // Zeroize reseed material
        reseed_material.zeroize();

        Ok(())
    }

    /// Generate random bytes
    pub fn generate(&mut self, output: &mut [u8]) -> Result<(), String> {
        self.generate_with_additional(output, None)
    }

    /// Generate random bytes with additional input
    pub fn generate_with_additional(
        &mut self,
        output: &mut [u8],
        additional: Option<&[u8]>,
    ) -> Result<(), String> {
        if !self.instantiated {
            return Err("DRBG not instantiated".to_string());
        }

        if output.len() > MAX_REQUEST_SIZE {
            return Err(format!(
                "Requested {} bytes exceeds maximum {}",
                output.len(),
                MAX_REQUEST_SIZE
            ));
        }

        // Check if reseed is required
        if self.reseed_counter > self.reseed_interval {
            // Get fresh entropy and reseed
            let mut entropy = [0u8; 48];
            getrandom::getrandom(&mut entropy)
                .map_err(|e| format!("Failed to get entropy for reseed: {}", e))?;
            self.reseed(&entropy, None)?;
            entropy.zeroize();
        }

        // Update with additional input if provided
        if let Some(add) = additional {
            self.update(Some(add))?;
        }

        // Generate output
        let mut temp = Vec::new();
        while temp.len() < output.len() {
            self.value = self.hmac(&self.value)?;
            temp.extend_from_slice(&self.value);
        }

        // Copy to output
        output.copy_from_slice(&temp[..output.len()]);

        // Update state
        self.update(additional)?;
        self.reseed_counter += 1;

        // Zeroize temp
        temp.zeroize();

        Ok(())
    }

    /// Update function (HMAC_DRBG_Update)
    fn update(&mut self, provided_data: Option<&[u8]>) -> Result<(), String> {
        // K = HMAC(K, V || 0x00 || provided_data)
        let mut input = Vec::new();
        input.extend_from_slice(&self.value);
        input.push(0x00);
        if let Some(data) = provided_data {
            input.extend_from_slice(data);
        }
        self.key = self.hmac_with_key(&self.key, &input)?;
        input.zeroize();

        // V = HMAC(K, V)
        self.value = self.hmac(&self.value)?;

        // If provided_data is not empty:
        if provided_data.map(|d| !d.is_empty()).unwrap_or(false) {
            // K = HMAC(K, V || 0x01 || provided_data)
            let mut input = Vec::new();
            input.extend_from_slice(&self.value);
            input.push(0x01);
            input.extend_from_slice(provided_data.unwrap());
            self.key = self.hmac_with_key(&self.key, &input)?;
            input.zeroize();

            // V = HMAC(K, V)
            self.value = self.hmac(&self.value)?;
        }

        Ok(())
    }

    /// HMAC using current key
    fn hmac(&self, data: &[u8]) -> Result<[u8; 32], String> {
        self.hmac_with_key(&self.key, data)
    }

    /// HMAC with specified key
    fn hmac_with_key(&self, key: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|e| format!("HMAC creation failed: {}", e))?;
        mac.update(data);

        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        Ok(output)
    }

    /// Run health check (continuous random number generator test)
    fn health_check(&mut self) -> Result<(), String> {
        let mut prev = [0u8; 32];
        let mut current = [0u8; 32];

        // Generate first block
        self.generate(&mut prev)?;

        // Generate second block and compare
        self.generate(&mut current)?;

        // Blocks should not be equal (extremely unlikely with good RNG)
        if prev == current {
            return Err("CRNG test failed: consecutive outputs are identical".to_string());
        }

        prev.zeroize();
        current.zeroize();

        Ok(())
    }

    /// Check if instantiated
    pub fn is_instantiated(&self) -> bool {
        self.instantiated
    }

    /// Get reseed counter
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// Check if reseed is required
    pub fn needs_reseed(&self) -> bool {
        self.reseed_counter > self.reseed_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_creation() {
        let drbg = FipsDrbg::new().unwrap();
        assert!(drbg.is_instantiated());
    }

    #[test]
    fn test_drbg_generate() {
        let mut drbg = FipsDrbg::new().unwrap();
        let mut output = [0u8; 32];

        drbg.generate(&mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_drbg_uniqueness() {
        let mut drbg = FipsDrbg::new().unwrap();
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        drbg.generate(&mut output1).unwrap();
        drbg.generate(&mut output2).unwrap();

        // Outputs should be different
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_drbg_reseed() {
        let mut drbg = FipsDrbg::new().unwrap();

        let mut entropy = [0u8; 48];
        getrandom::getrandom(&mut entropy).unwrap();

        drbg.reseed(&entropy, None).unwrap();
        assert_eq!(drbg.reseed_counter(), 1);
    }

    #[test]
    fn test_max_request_size() {
        let mut drbg = FipsDrbg::new().unwrap();
        let mut large_output = vec![0u8; MAX_REQUEST_SIZE + 1];

        let result = drbg.generate(&mut large_output);
        assert!(result.is_err());
    }
}
