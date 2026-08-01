//! One-Time Password (OTP) Authentication
//!
//! Provides TOTP (Time-based OTP, RFC 6238) and HOTP (HMAC-based OTP, RFC 4226)
//! authentication support.

use crate::error::{AuthError, Result};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Constant-time comparison of two OTP code strings.
///
/// Compares the raw UTF-8 bytes with `subtle::ConstantTimeEq` so the comparison
/// time does not depend on which position first differs. Returns `false` for
/// length mismatch (length is not secret for fixed-width OTP codes).
fn ct_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison of two hex-encoded hashes.
///
/// Both inputs are decoded from hex to their raw bytes and compared with
/// `subtle::ConstantTimeEq`, so neither the byte position of a difference nor
/// the value of the candidate hash leaks via comparison timing.
fn ct_eq_hex_hash(stored_hex: &str, candidate_hex: &str) -> bool {
    let (stored, candidate) = match (hex::decode(stored_hex), hex::decode(candidate_hex)) {
        (Ok(s), Ok(c)) => (s, c),
        _ => return false,
    };
    if stored.len() != candidate.len() {
        return false;
    }
    stored.ct_eq(&candidate).into()
}

/// OTP algorithm type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpAlgorithm {
    /// SHA-1 (RFC 6238 default)
    #[default]
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
}

impl std::fmt::Display for OtpAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha1 => write!(f, "SHA1"),
            Self::Sha256 => write!(f, "SHA256"),
            Self::Sha512 => write!(f, "SHA512"),
        }
    }
}

/// OTP type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpType {
    /// Time-based OTP (RFC 6238)
    #[default]
    Totp,
    /// HMAC-based OTP (RFC 4226)
    Hotp,
}

/// OTP secret
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OtpSecret {
    /// Raw secret bytes
    secret: Vec<u8>,
}

impl OtpSecret {
    /// Create a new random secret
    pub fn generate() -> Self {
        Self::generate_with_length(20) // 160 bits, standard for SHA-1
    }

    /// Create a secret with specific length
    pub fn generate_with_length(length: usize) -> Self {
        let mut secret = vec![0u8; length];
        getrandom::fill(&mut secret).expect("Failed to generate random bytes");
        Self { secret }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { secret: bytes }
    }

    /// Create from base32 encoded string
    pub fn from_base32(encoded: &str) -> Result<Self> {
        let decoded = base32_decode(encoded)
            .ok_or_else(|| AuthError::Internal("Invalid base32 encoding".to_string()))?;
        Ok(Self { secret: decoded })
    }

    /// Get as base32 encoded string (for QR codes)
    pub fn to_base32(&self) -> String {
        base32_encode(&self.secret)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl std::fmt::Debug for OtpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OtpSecret(***)")
    }
}

/// OTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpConfig {
    /// OTP type (TOTP or HOTP)
    pub otp_type: OtpType,
    /// Algorithm
    pub algorithm: OtpAlgorithm,
    /// Number of digits (usually 6 or 8)
    pub digits: u32,
    /// Time step for TOTP (usually 30 seconds)
    pub period: u32,
    /// Counter for HOTP
    #[serde(default)]
    pub counter: u64,
    /// Issuer name (for QR code)
    pub issuer: String,
    /// Account name (for QR code)
    pub account_name: String,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self {
            otp_type: OtpType::Totp,
            algorithm: OtpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
            issuer: "HSM".to_string(),
            account_name: String::new(),
        }
    }
}

impl OtpConfig {
    /// Create TOTP config
    pub fn totp(issuer: &str, account_name: &str) -> Self {
        Self {
            otp_type: OtpType::Totp,
            issuer: issuer.to_string(),
            account_name: account_name.to_string(),
            ..Default::default()
        }
    }

    /// Create HOTP config
    pub fn hotp(issuer: &str, account_name: &str, counter: u64) -> Self {
        Self {
            otp_type: OtpType::Hotp,
            counter,
            issuer: issuer.to_string(),
            account_name: account_name.to_string(),
            ..Default::default()
        }
    }

    /// Set algorithm
    pub fn with_algorithm(mut self, algorithm: OtpAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set digits
    pub fn with_digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    /// Set period
    pub fn with_period(mut self, period: u32) -> Self {
        self.period = period;
        self
    }

    /// Generate otpauth:// URI for QR code
    pub fn to_uri(&self, secret: &OtpSecret) -> String {
        let otp_type = match self.otp_type {
            OtpType::Totp => "totp",
            OtpType::Hotp => "hotp",
        };

        let label = if self.issuer.is_empty() {
            url_encode(&self.account_name)
        } else {
            format!(
                "{}:{}",
                url_encode(&self.issuer),
                url_encode(&self.account_name)
            )
        };

        let mut uri = format!(
            "otpauth://{}/{}?secret={}&digits={}&algorithm={}",
            otp_type,
            label,
            secret.to_base32(),
            self.digits,
            self.algorithm
        );

        if !self.issuer.is_empty() {
            uri.push_str(&format!("&issuer={}", url_encode(&self.issuer)));
        }

        if self.otp_type == OtpType::Totp {
            uri.push_str(&format!("&period={}", self.period));
        } else {
            uri.push_str(&format!("&counter={}", self.counter));
        }

        uri
    }
}

/// TOTP validator
pub struct TotpValidator {
    /// Secret
    secret: OtpSecret,
    /// Configuration
    config: OtpConfig,
}

impl TotpValidator {
    /// Create a new TOTP validator
    pub fn new(secret: OtpSecret, config: OtpConfig) -> Self {
        Self { secret, config }
    }

    /// Generate the current TOTP code
    pub fn generate(&self) -> String {
        self.generate_at(current_timestamp())
    }

    /// Generate TOTP code at a specific timestamp
    pub fn generate_at(&self, timestamp: u64) -> String {
        let counter = timestamp / self.config.period as u64;
        self.generate_otp(counter)
    }

    /// Verify a TOTP code with time drift tolerance
    pub fn verify(&self, code: &str, tolerance: u32) -> bool {
        self.verify_at(code, current_timestamp(), tolerance)
    }

    /// Verify a TOTP code at a specific timestamp
    pub fn verify_at(&self, code: &str, timestamp: u64, tolerance: u32) -> bool {
        let current_counter = timestamp / self.config.period as u64;

        // Check current and surrounding time steps. We accumulate matches across
        // the entire tolerance window WITHOUT an early return: returning as soon
        // as a match is found would leak, via timing, how far into the window the
        // matching step was. Each candidate is compared in constant time.
        let mut matched = false;
        for i in 0..=tolerance {
            let candidate = self.generate_otp(current_counter.saturating_sub(i as u64));
            matched |= ct_eq_str(&candidate, code);
            if i > 0 {
                let candidate = self.generate_otp(current_counter + i as u64);
                matched |= ct_eq_str(&candidate, code);
            }
        }

        matched
    }

    /// Generate OTP for a counter value
    fn generate_otp(&self, counter: u64) -> String {
        let counter_bytes = counter.to_be_bytes();

        let hmac_result = match self.config.algorithm {
            OtpAlgorithm::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(self.secret.as_bytes())
                    .expect("HMAC can take any key size");
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes())
                    .expect("HMAC can take any key size");
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(self.secret.as_bytes())
                    .expect("HMAC can take any key size");
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Dynamic truncation
        let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;
        let binary = ((hmac_result[offset] & 0x7f) as u32) << 24
            | (hmac_result[offset + 1] as u32) << 16
            | (hmac_result[offset + 2] as u32) << 8
            | (hmac_result[offset + 3] as u32);

        let otp = binary % 10u32.pow(self.config.digits);
        format!("{:0width$}", otp, width = self.config.digits as usize)
    }

    /// Get the OTP URI for QR code generation
    pub fn uri(&self) -> String {
        self.config.to_uri(&self.secret)
    }
}

/// HOTP validator
pub struct HotpValidator {
    /// Secret
    secret: OtpSecret,
    /// Configuration
    config: OtpConfig,
    /// Current counter
    counter: u64,
}

impl HotpValidator {
    /// Create a new HOTP validator
    pub fn new(secret: OtpSecret, config: OtpConfig) -> Self {
        let counter = config.counter;
        Self {
            secret,
            config,
            counter,
        }
    }

    /// Generate the current HOTP code and increment counter
    pub fn generate(&mut self) -> String {
        let code = self.generate_at(self.counter);
        self.counter += 1;
        code
    }

    /// Generate HOTP code at a specific counter
    pub fn generate_at(&self, counter: u64) -> String {
        let counter_bytes = counter.to_be_bytes();

        let hmac_result = match self.config.algorithm {
            OtpAlgorithm::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(self.secret.as_bytes())
                    .expect("HMAC can take any key size");
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes())
                    .expect("HMAC can take any key size");
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            OtpAlgorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(self.secret.as_bytes())
                    .expect("HMAC can take any key size");
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Dynamic truncation
        let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;
        let binary = ((hmac_result[offset] & 0x7f) as u32) << 24
            | (hmac_result[offset + 1] as u32) << 16
            | (hmac_result[offset + 2] as u32) << 8
            | (hmac_result[offset + 3] as u32);

        let otp = binary % 10u32.pow(self.config.digits);
        format!("{:0width$}", otp, width = self.config.digits as usize)
    }

    /// Verify an HOTP code with look-ahead window
    pub fn verify(&mut self, code: &str, look_ahead: u32) -> bool {
        // Scan the whole look-ahead window without early return, comparing each
        // candidate in constant time. We record the matching offset and only
        // advance the counter after the loop so the comparison loop's timing does
        // not reveal where in the window the match occurred.
        let mut matched_offset: Option<u32> = None;
        for i in 0..=look_ahead {
            let candidate = self.generate_at(self.counter + i as u64);
            if ct_eq_str(&candidate, code) {
                matched_offset = Some(i);
            }
        }

        match matched_offset {
            Some(i) => {
                self.counter = self.counter + i as u64 + 1;
                true
            }
            None => false,
        }
    }

    /// Get current counter
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Get the OTP URI for QR code generation
    pub fn uri(&self) -> String {
        let mut config = self.config.clone();
        config.counter = self.counter;
        config.to_uri(&self.secret)
    }
}

/// OTP registration record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpRegistration {
    /// User ID
    pub user_id: String,
    /// Secret (base32 encoded, encrypted at rest)
    pub encrypted_secret: Vec<u8>,
    /// Configuration
    pub config: OtpConfig,
    /// Registration time
    pub registered_at: i64,
    /// Last used time
    pub last_used_at: Option<i64>,
    /// Whether this OTP is verified/confirmed
    pub verified: bool,
    /// Recovery codes (hashed)
    pub recovery_code_hashes: Vec<String>,
}

/// OTP manager for handling user registrations
pub struct OtpManager {
    /// User registrations (user_id -> OtpRegistration)
    registrations: DashMap<String, OtpRegistration>,
    /// Default config
    default_config: OtpConfig,
    /// Number of recovery codes to generate
    recovery_code_count: usize,
}

impl OtpManager {
    /// Create a new OTP manager
    pub fn new(issuer: &str) -> Self {
        let default_config = OtpConfig {
            issuer: issuer.to_string(),
            ..Default::default()
        };

        Self {
            registrations: DashMap::new(),
            default_config,
            recovery_code_count: 10,
        }
    }

    /// Start OTP registration for a user
    pub fn start_registration(
        &self,
        _user_id: &str,
        account_name: &str,
    ) -> (OtpSecret, String, Vec<String>) {
        let secret = OtpSecret::generate();
        let mut config = self.default_config.clone();
        config.account_name = account_name.to_string();

        let uri = config.to_uri(&secret);

        // Generate recovery codes
        let recovery_codes: Vec<String> = (0..self.recovery_code_count)
            .map(|_| generate_recovery_code())
            .collect();

        (secret, uri, recovery_codes)
    }

    /// Complete OTP registration
    pub fn complete_registration(
        &self,
        user_id: &str,
        secret: &OtpSecret,
        config: OtpConfig,
        code: &str,
        recovery_codes: &[String],
    ) -> Result<()> {
        // Verify the code first
        let validator = TotpValidator::new(secret.clone(), config.clone());
        if !validator.verify(code, 1) {
            return Err(AuthError::Unauthorized("Invalid OTP code".to_string()));
        }

        // Hash recovery codes
        let recovery_hashes: Vec<String> = recovery_codes
            .iter()
            .map(|c| hash_recovery_code(c))
            .collect();

        let registration = OtpRegistration {
            user_id: user_id.to_string(),
            encrypted_secret: secret.as_bytes().to_vec(), // Should be encrypted in production
            config,
            registered_at: current_timestamp() as i64,
            last_used_at: None,
            verified: true,
            recovery_code_hashes: recovery_hashes,
        };

        self.registrations.insert(user_id.to_string(), registration);
        Ok(())
    }

    /// Verify OTP for a user
    pub fn verify(&self, user_id: &str, code: &str) -> Result<bool> {
        let mut registration = self
            .registrations
            .get_mut(user_id)
            .ok_or_else(|| AuthError::InvalidSession("OTP not registered".to_string()))?;

        if !registration.verified {
            return Err(AuthError::InvalidSession("OTP not verified".to_string()));
        }

        let secret = OtpSecret::from_bytes(registration.encrypted_secret.clone());
        let validator = TotpValidator::new(secret, registration.config.clone());

        let valid = validator.verify(code, 1);
        if valid {
            registration.last_used_at = Some(current_timestamp() as i64);
        }

        Ok(valid)
    }

    /// Verify using a recovery code
    pub fn verify_recovery_code(&self, user_id: &str, code: &str) -> Result<bool> {
        let mut registration = self
            .registrations
            .get_mut(user_id)
            .ok_or_else(|| AuthError::InvalidSession("OTP not registered".to_string()))?;

        let code_hash = hash_recovery_code(code);

        // Compare against each stored hash in constant time (decode hex to bytes,
        // then `ct_eq`) so the comparison does not short-circuit on the first
        // differing byte. We scan all entries and record the matching index
        // afterwards to avoid leaking which code matched via timing.
        let mut matched_pos: Option<usize> = None;
        for (pos, stored) in registration.recovery_code_hashes.iter().enumerate() {
            if ct_eq_hex_hash(stored, &code_hash) {
                matched_pos = Some(pos);
            }
        }

        if let Some(pos) = matched_pos {
            registration.recovery_code_hashes.remove(pos);
            registration.last_used_at = Some(current_timestamp() as i64);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if user has OTP registered
    pub fn is_registered(&self, user_id: &str) -> bool {
        self.registrations.contains_key(user_id)
    }

    /// Remove OTP registration
    pub fn remove_registration(&self, user_id: &str) -> bool {
        self.registrations.remove(user_id).is_some()
    }

    /// Get remaining recovery code count
    pub fn recovery_codes_remaining(&self, user_id: &str) -> Option<usize> {
        self.registrations
            .get(user_id)
            .map(|r| r.recovery_code_hashes.len())
    }
}

impl Default for OtpManager {
    fn default() -> Self {
        Self::new("HSM")
    }
}

// Helper functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_recovery_code() -> String {
    let mut bytes = [0u8; 10];
    getrandom::fill(&mut bytes).expect("Failed to generate random bytes");
    // Format as XXXX-XXXX-XXXX
    let hex = hex::encode(&bytes[..6]);
    format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12])
}

fn hash_recovery_code(code: &str) -> String {
    use sha2::Digest;
    let normalized = code.to_uppercase().replace("-", "");
    let mut hasher = sha2::Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

// Base32 encoding/decoding (RFC 4648)
const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1f) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for c in encoded.to_uppercase().chars() {
        if c == '=' {
            continue;
        }

        let value = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };

        buffer = (buffer << 5) | value;
        bits_in_buffer += 5;

        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            result.push((buffer >> bits_in_buffer) as u8);
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        // RFC 6238 test vector
        let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec());
        let config = OtpConfig::totp("Test", "test@example.com");
        let validator = TotpValidator::new(secret, config);

        // Test at known timestamp (59 seconds)
        let code = validator.generate_at(59);
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn test_totp_verification() {
        let secret = OtpSecret::generate();
        let config = OtpConfig::totp("Test", "test@example.com");
        let validator = TotpValidator::new(secret, config);

        let code = validator.generate();
        assert!(validator.verify(&code, 1));
    }

    #[test]
    fn test_hotp_generation() {
        let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec());
        let config = OtpConfig::hotp("Test", "test@example.com", 0);
        let mut validator = HotpValidator::new(secret, config);

        let code1 = validator.generate();
        let code2 = validator.generate();

        assert_ne!(code1, code2);
        assert_eq!(validator.counter(), 2);
    }

    #[test]
    fn test_base32_encoding() {
        let data = b"Hello!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_otp_uri() {
        let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec());
        let config = OtpConfig::totp("HSM", "user@example.com");
        let uri = config.to_uri(&secret);

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("HSM"));
        assert!(uri.contains("secret="));
    }

    #[test]
    fn test_recovery_code() {
        let code = generate_recovery_code();
        assert_eq!(code.len(), 14); // XXXX-XXXX-XXXX
        assert!(code.contains('-'));
    }

    #[test]
    fn test_otp_manager() {
        let manager = OtpManager::new("TestApp");

        let user_id = "user-123";
        let (secret, uri, recovery_codes) = manager.start_registration(user_id, "test@example.com");

        assert!(!uri.is_empty());
        assert_eq!(recovery_codes.len(), 10);

        // Get current code
        let config = OtpConfig::totp("TestApp", "test@example.com");
        let validator = TotpValidator::new(secret.clone(), config.clone());
        let code = validator.generate();

        // Complete registration
        manager
            .complete_registration(user_id, &secret, config, &code, &recovery_codes)
            .unwrap();

        assert!(manager.is_registered(user_id));

        // Verify code
        let new_code = validator.generate();
        assert!(manager.verify(user_id, &new_code).unwrap());
    }

    #[test]
    fn test_ct_eq_str_matches_eq_semantics() {
        assert!(ct_eq_str("123456", "123456"));
        assert!(!ct_eq_str("123456", "123457"));
        assert!(!ct_eq_str("123456", "12345")); // length mismatch
        assert!(!ct_eq_str("000000", "999999"));
    }

    #[test]
    fn test_ct_eq_hex_hash() {
        let a = hash_recovery_code("ABCD-EFGH-1234");
        let b = hash_recovery_code("ABCD-EFGH-1234");
        let c = hash_recovery_code("WXYZ-1111-2222");
        assert!(ct_eq_hex_hash(&a, &b));
        assert!(!ct_eq_hex_hash(&a, &c));
        // Non-hex input must not panic and must compare unequal.
        assert!(!ct_eq_hex_hash("not-hex", &a));
    }

    #[test]
    fn test_recovery_code_ct_verification() {
        let manager = OtpManager::new("TestApp");
        let user_id = "user-rc";

        let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec());
        let config = OtpConfig::totp("TestApp", "rc@example.com");
        let validator = TotpValidator::new(secret.clone(), config.clone());
        let recovery_codes = vec!["AAAA-BBBB-CCCC".to_string(), "DDDD-EEEE-FFFF".to_string()];
        let code = validator.generate();
        manager
            .complete_registration(user_id, &secret, config, &code, &recovery_codes)
            .unwrap();

        // Wrong code rejected.
        assert!(!manager
            .verify_recovery_code(user_id, "ZZZZ-ZZZZ-ZZZZ")
            .unwrap());
        // Correct code (normalized) accepted.
        assert!(manager
            .verify_recovery_code(user_id, "AAAA-BBBB-CCCC")
            .unwrap());
        // Reuse of consumed code rejected.
        assert!(!manager
            .verify_recovery_code(user_id, "AAAA-BBBB-CCCC")
            .unwrap());
        // The other code still works.
        assert!(manager
            .verify_recovery_code(user_id, "dddd-eeee-ffff")
            .unwrap());
    }

    #[test]
    fn test_totp_verify_constant_time_window_still_correct() {
        let secret = OtpSecret::from_bytes(b"12345678901234567890".to_vec());
        let config = OtpConfig::totp("Test", "t@example.com");
        let validator = TotpValidator::new(secret, config);

        // Code from a step within the tolerance window must verify.
        let ts = 1_000_000u64;
        let prev = validator.generate_at(ts - 30);
        assert!(validator.verify_at(&prev, ts, 1));
        // A wholly wrong code must not verify.
        assert!(!validator.verify_at("000000", ts, 1));
    }
}
