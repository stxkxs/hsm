//! BIP-39: Mnemonic code for generating deterministic keys
//!
//! Provides mnemonic generation and seed derivation following BIP-39 specification.
//!
//! # Example
//!
//! ```rust
//! use hsm_blockchain::bip::bip39::{Mnemonic, MnemonicType, Language};
//!
//! // Generate a new 24-word mnemonic
//! let mnemonic = Mnemonic::generate(MnemonicType::Words24, Language::English).unwrap();
//!
//! // Convert to seed with optional passphrase
//! let seed = mnemonic.to_seed("optional passphrase");
//!
//! // Recover from phrase
//! let recovered = Mnemonic::from_phrase("abandon abandon abandon...", Language::English);
//! ```

use crate::error::{BlockchainError, Result};
use bip39 as bip39_crate;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Mnemonic word count
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MnemonicType {
    /// 12 words (128 bits entropy)
    Words12,
    /// 15 words (160 bits entropy)
    Words15,
    /// 18 words (192 bits entropy)
    Words18,
    /// 21 words (224 bits entropy)
    Words21,
    /// 24 words (256 bits entropy)
    Words24,
}

impl MnemonicType {
    /// Get the word count for this mnemonic type
    pub fn word_count(&self) -> usize {
        match self {
            MnemonicType::Words12 => 12,
            MnemonicType::Words15 => 15,
            MnemonicType::Words18 => 18,
            MnemonicType::Words21 => 21,
            MnemonicType::Words24 => 24,
        }
    }

    /// Get the entropy bits for this mnemonic type
    pub fn entropy_bits(&self) -> usize {
        match self {
            MnemonicType::Words12 => 128,
            MnemonicType::Words15 => 160,
            MnemonicType::Words18 => 192,
            MnemonicType::Words21 => 224,
            MnemonicType::Words24 => 256,
        }
    }
}

/// Language for mnemonic wordlist
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Language {
    /// English wordlist (default)
    #[default]
    English,
    /// Japanese wordlist
    Japanese,
    /// Korean wordlist
    Korean,
    /// Spanish wordlist
    Spanish,
    /// Chinese (Simplified) wordlist
    ChineseSimplified,
    /// Chinese (Traditional) wordlist
    ChineseTraditional,
    /// French wordlist
    French,
    /// Italian wordlist
    Italian,
    /// Czech wordlist
    Czech,
    /// Portuguese wordlist
    Portuguese,
}

impl Language {
    fn to_bip39_language(&self) -> bip39_crate::Language {
        // Note: bip39 v2.x only includes English by default.
        // Other languages require feature flags. For now, we only support English.
        // TODO: Enable other languages via feature flags if needed.
        match self {
            Language::English => bip39_crate::Language::English,
            // All other languages fall back to English - this is a limitation
            // of the current bip39 crate version. Users should use English.
            _ => bip39_crate::Language::English,
        }
    }

    /// Check if this language is fully supported
    pub fn is_supported(&self) -> bool {
        matches!(self, Language::English)
    }
}

/// BIP-39 seed (64 bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 64]);

impl Seed {
    /// Create a seed from raw bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the seed bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed([REDACTED])")
    }
}

/// BIP-39 Mnemonic
///
/// A mnemonic phrase that can be converted to a seed for HD wallet derivation.
/// The phrase is stored securely and zeroized on drop.
///
/// # Security
///
/// Clone is intentionally derived to support wallet workflows that need to
/// duplicate a mnemonic (e.g., backup flows). The `SecretString` field handles
/// its own zeroization. The `Drop` impl zeros the `word_count` field to avoid
/// leaking metadata about the mnemonic length.
#[derive(Clone)]
pub struct Mnemonic {
    phrase: SecretString,
    word_count: usize,
    language: Language,
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        // SecretString handles its own zeroization.
        // Zero word_count to prevent leaking mnemonic length metadata.
        self.word_count.zeroize();
    }
}

impl Mnemonic {
    /// Generate a new random mnemonic
    pub fn generate(mnemonic_type: MnemonicType, language: Language) -> Result<Self> {
        if !language.is_supported() {
            return Err(BlockchainError::InvalidMnemonic(
                "Only English is currently supported. Other languages require feature flags."
                    .to_string(),
            ));
        }
        let word_count = mnemonic_type.word_count();

        let mnemonic = bip39_crate::Mnemonic::generate_in(language.to_bip39_language(), word_count)
            .map_err(|e| BlockchainError::InvalidMnemonic(e.to_string()))?;
        let phrase = mnemonic.to_string();

        Ok(Self {
            phrase: SecretString::from(phrase),
            word_count,
            language,
        })
    }

    /// Create a mnemonic from a phrase
    pub fn from_phrase(phrase: &str, language: Language) -> Result<Self> {
        if !language.is_supported() {
            return Err(BlockchainError::InvalidMnemonic(
                "Only English is currently supported. Other languages require feature flags."
                    .to_string(),
            ));
        }
        let parsed =
            bip39_crate::Mnemonic::parse_in_normalized(language.to_bip39_language(), phrase)
                .map_err(|e| BlockchainError::InvalidMnemonic(e.to_string()))?;

        let word_count = parsed.word_count();

        Ok(Self {
            phrase: SecretString::from(phrase.to_string()),
            word_count,
            language,
        })
    }

    /// Create a mnemonic from entropy
    pub fn from_entropy(entropy: &[u8], language: Language) -> Result<Self> {
        if !language.is_supported() {
            return Err(BlockchainError::InvalidMnemonic(
                "Only English is currently supported. Other languages require feature flags."
                    .to_string(),
            ));
        }
        let mnemonic =
            bip39_crate::Mnemonic::from_entropy_in(language.to_bip39_language(), entropy)
                .map_err(|e| BlockchainError::InvalidMnemonic(e.to_string()))?;

        let phrase = mnemonic.to_string();
        let word_count = mnemonic.word_count();

        Ok(Self {
            phrase: SecretString::from(phrase),
            word_count,
            language,
        })
    }

    /// Convert mnemonic to seed
    ///
    /// The passphrase is optional (can be empty string).
    /// PBKDF2-HMAC-SHA512 is used with 2048 iterations.
    pub fn to_seed(&self, passphrase: &str) -> Seed {
        let phrase_str = self.phrase.expose_secret();
        let parsed = bip39_crate::Mnemonic::parse(phrase_str).expect("already validated");
        let seed_bytes = parsed.to_seed(passphrase);
        Seed::from_bytes(seed_bytes)
    }

    /// Get the phrase as a string (use with caution - exposes secret)
    pub fn phrase(&self) -> String {
        self.phrase.expose_secret().to_string()
    }

    /// Get the word count
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// Get the language
    pub fn language(&self) -> Language {
        self.language
    }

    /// Validate a phrase without creating a Mnemonic object
    pub fn validate(phrase: &str, language: Language) -> bool {
        if !language.is_supported() {
            return false;
        }
        bip39_crate::Mnemonic::parse_in_normalized(language.to_bip39_language(), phrase).is_ok()
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mnemonic")
            .field("phrase", &"[REDACTED]")
            .field("word_count", &self.word_count)
            .field("language", &self.language)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_12_words() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words12, Language::English).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        let phrase = mnemonic.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words24, Language::English).unwrap();
        assert_eq!(mnemonic.word_count(), 24);
        let phrase = mnemonic.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        // Standard BIP-39 test vector
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
    }

    #[test]
    fn test_mnemonic_to_seed() {
        // BIP-39 test vector
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("TREZOR");

        // Expected seed from BIP-39 test vectors
        let expected = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ).unwrap();

        assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result = Mnemonic::from_phrase("invalid mnemonic phrase", Language::English);
        assert!(result.is_err());
    }

    #[test]
    fn test_mnemonic_validate() {
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(Mnemonic::validate(valid, Language::English));

        let invalid = "invalid mnemonic phrase";
        assert!(!Mnemonic::validate(invalid, Language::English));
    }

    #[test]
    fn test_mnemonic_debug_redacts() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words12, Language::English).unwrap();
        let debug = format!("{:?}", mnemonic);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("abandon"));
    }

    proptest::proptest! {
        /// Parsing an arbitrary string as a BIP-39 mnemonic must never panic;
        /// invalid phrases must return `Err`.
        #[test]
        fn mnemonic_from_phrase_never_panics(phrase in ".*") {
            let _ = Mnemonic::from_phrase(&phrase, Language::English);
        }
    }
}
