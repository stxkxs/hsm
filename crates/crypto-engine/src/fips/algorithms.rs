//! FIPS 140-3 Approved Algorithms
//!
//! Defines the list of cryptographic algorithms approved for use in FIPS mode.
//! Based on NIST SP 800-140C and related standards.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Cryptographic algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    // Symmetric Encryption (SP 800-38A-D)
    /// AES-128 (approved)
    Aes128,
    /// AES-192 (approved)
    Aes192,
    /// AES-256 (approved)
    Aes256,
    /// AES-GCM (approved)
    AesGcm,
    /// AES-CBC (approved)
    AesCbc,
    /// AES-CTR (approved)
    AesCtr,
    /// ChaCha20 (not approved for FIPS)
    ChaCha20,
    /// ChaCha20-Poly1305 (not approved for FIPS)
    ChaCha20Poly1305,

    // Hash Functions (FIPS 180-4, FIPS 202)
    /// SHA-1 (deprecated, signature verification only)
    Sha1,
    /// SHA-256 (approved)
    Sha256,
    /// SHA-384 (approved)
    Sha384,
    /// SHA-512 (approved)
    Sha512,
    /// SHA-512/256 (approved)
    Sha512_256,
    /// SHA3-256 (approved)
    Sha3_256,
    /// SHA3-384 (approved)
    Sha3_384,
    /// SHA3-512 (approved)
    Sha3_512,
    /// SHAKE128 (approved)
    Shake128,
    /// SHAKE256 (approved)
    Shake256,
    /// Blake2b (not approved for FIPS)
    Blake2b,
    /// Blake3 (not approved for FIPS)
    Blake3,

    // Digital Signatures (FIPS 186-5)
    /// RSA-2048 (approved)
    Rsa2048,
    /// RSA-3072 (approved)
    Rsa3072,
    /// RSA-4096 (approved)
    Rsa4096,
    /// ECDSA P-256 (approved)
    EcdsaP256,
    /// ECDSA P-384 (approved)
    EcdsaP384,
    /// ECDSA P-521 (approved)
    EcdsaP521,
    /// Ed25519 (approved in FIPS 186-5)
    Ed25519,
    /// Ed448 (approved in FIPS 186-5)
    Ed448,
    /// secp256k1 (not approved for FIPS)
    Secp256k1,
    /// BLS12-381 (not approved for FIPS)
    Bls12381,

    // Message Authentication (FIPS 198-1, SP 800-38B)
    /// HMAC-SHA256 (approved)
    HmacSha256,
    /// HMAC-SHA384 (approved)
    HmacSha384,
    /// HMAC-SHA512 (approved)
    HmacSha512,
    /// CMAC-AES (approved)
    CmacAes,

    // Key Derivation (SP 800-108, SP 800-132, SP 800-56C)
    /// HKDF (approved)
    Hkdf,
    /// PBKDF2 (approved)
    Pbkdf2,
    /// SP800-108 KDF (approved)
    Sp800108Kdf,
    /// Argon2 (not approved for FIPS)
    Argon2,
    /// scrypt (not approved for FIPS)
    Scrypt,

    // Key Agreement (SP 800-56A, SP 800-56B)
    /// ECDH P-256 (approved)
    EcdhP256,
    /// ECDH P-384 (approved)
    EcdhP384,
    /// ECDH P-521 (approved)
    EcdhP521,
    /// X25519 (approved)
    X25519,
    /// X448 (approved)
    X448,
    /// DH (approved with appropriate parameters)
    Dh,

    // Random Number Generation (SP 800-90A)
    /// CTR_DRBG (approved)
    CtrDrbg,
    /// HMAC_DRBG (approved)
    HmacDrbg,
    /// Hash_DRBG (approved)
    HashDrbg,

    // Post-Quantum (under evaluation - NOT YET FIPS APPROVED)
    /// ML-KEM (Kyber) - under evaluation
    MlKem,
    /// ML-DSA (Dilithium) - under evaluation
    MlDsa,
    /// SLH-DSA (SPHINCS+) - under evaluation
    SlhDsa,

    // Threshold Cryptography (FIPS 186-5 / SP 800-186)
    /// Threshold ECDSA P-256 (approved - uses FIPS-approved P-256 curve)
    ThresholdEcdsaP256,
    /// Threshold ECDSA P-384 (approved - uses FIPS-approved P-384 curve)
    ThresholdEcdsaP384,
    /// Threshold ECDSA secp256k1 (NOT approved - non-NIST curve)
    ThresholdEcdsaSecp256k1,
    /// Threshold BLS12-381 (under evaluation)
    ThresholdBls12381,
    /// FROST Ed25519 (approved - Ed25519 is in FIPS 186-5)
    FrostEd25519,
}

impl Algorithm {
    /// Get the algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
            Self::AesGcm => "AES-GCM",
            Self::AesCbc => "AES-CBC",
            Self::AesCtr => "AES-CTR",
            Self::ChaCha20 => "ChaCha20",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha512_256 => "SHA-512/256",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Shake128 => "SHAKE128",
            Self::Shake256 => "SHAKE256",
            Self::Blake2b => "BLAKE2b",
            Self::Blake3 => "BLAKE3",
            Self::Rsa2048 => "RSA-2048",
            Self::Rsa3072 => "RSA-3072",
            Self::Rsa4096 => "RSA-4096",
            Self::EcdsaP256 => "ECDSA-P256",
            Self::EcdsaP384 => "ECDSA-P384",
            Self::EcdsaP521 => "ECDSA-P521",
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
            Self::Secp256k1 => "secp256k1",
            Self::Bls12381 => "BLS12-381",
            Self::HmacSha256 => "HMAC-SHA256",
            Self::HmacSha384 => "HMAC-SHA384",
            Self::HmacSha512 => "HMAC-SHA512",
            Self::CmacAes => "CMAC-AES",
            Self::Hkdf => "HKDF",
            Self::Pbkdf2 => "PBKDF2",
            Self::Sp800108Kdf => "SP800-108-KDF",
            Self::Argon2 => "Argon2",
            Self::Scrypt => "scrypt",
            Self::EcdhP256 => "ECDH-P256",
            Self::EcdhP384 => "ECDH-P384",
            Self::EcdhP521 => "ECDH-P521",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::Dh => "DH",
            Self::CtrDrbg => "CTR_DRBG",
            Self::HmacDrbg => "HMAC_DRBG",
            Self::HashDrbg => "Hash_DRBG",
            Self::MlKem => "ML-KEM",
            Self::MlDsa => "ML-DSA",
            Self::SlhDsa => "SLH-DSA",
            Self::ThresholdEcdsaP256 => "Threshold-ECDSA-P256",
            Self::ThresholdEcdsaP384 => "Threshold-ECDSA-P384",
            Self::ThresholdEcdsaSecp256k1 => "Threshold-ECDSA-secp256k1",
            Self::ThresholdBls12381 => "Threshold-BLS12-381",
            Self::FrostEd25519 => "FROST-Ed25519",
        }
    }

    /// Get the NIST standard reference
    pub fn standard(&self) -> Option<&'static str> {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => Some("FIPS 197"),
            Self::AesGcm => Some("SP 800-38D"),
            Self::AesCbc | Self::AesCtr => Some("SP 800-38A"),
            Self::Sha1 | Self::Sha256 | Self::Sha384 | Self::Sha512 | Self::Sha512_256 => {
                Some("FIPS 180-4")
            }
            Self::Sha3_256 | Self::Sha3_384 | Self::Sha3_512 | Self::Shake128 | Self::Shake256 => {
                Some("FIPS 202")
            }
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => Some("FIPS 186-5"),
            Self::EcdsaP256 | Self::EcdsaP384 | Self::EcdsaP521 => Some("FIPS 186-5"),
            Self::Ed25519 | Self::Ed448 => Some("FIPS 186-5"),
            Self::HmacSha256 | Self::HmacSha384 | Self::HmacSha512 => Some("FIPS 198-1"),
            Self::CmacAes => Some("SP 800-38B"),
            Self::Hkdf => Some("SP 800-56C"),
            Self::Pbkdf2 => Some("SP 800-132"),
            Self::Sp800108Kdf => Some("SP 800-108"),
            Self::EcdhP256 | Self::EcdhP384 | Self::EcdhP521 => Some("SP 800-56A"),
            Self::X25519 | Self::X448 => Some("SP 800-186"),
            Self::Dh => Some("SP 800-56A"),
            Self::CtrDrbg | Self::HmacDrbg | Self::HashDrbg => Some("SP 800-90A"),
            Self::ThresholdEcdsaP256 => Some("FIPS 186-5, SP 800-186"),
            Self::ThresholdEcdsaP384 => Some("FIPS 186-5, SP 800-186"),
            Self::FrostEd25519 => Some("FIPS 186-5"),
            _ => None,
        }
    }
}

/// Approved algorithms registry
pub struct ApprovedAlgorithms {
    /// Set of approved algorithms
    approved: HashSet<Algorithm>,
    /// Algorithms approved only for verification (e.g., SHA-1)
    verification_only: HashSet<Algorithm>,
    /// Algorithms under evaluation (PQC)
    under_evaluation: HashSet<Algorithm>,
}

impl ApprovedAlgorithms {
    /// Create new approved algorithms registry
    pub fn new() -> Self {
        let mut approved = HashSet::new();
        let mut verification_only = HashSet::new();
        let mut under_evaluation = HashSet::new();

        // Symmetric encryption
        approved.insert(Algorithm::Aes128);
        approved.insert(Algorithm::Aes192);
        approved.insert(Algorithm::Aes256);
        approved.insert(Algorithm::AesGcm);
        approved.insert(Algorithm::AesCbc);
        approved.insert(Algorithm::AesCtr);

        // Hash functions
        verification_only.insert(Algorithm::Sha1); // SHA-1 for verification only
        approved.insert(Algorithm::Sha256);
        approved.insert(Algorithm::Sha384);
        approved.insert(Algorithm::Sha512);
        approved.insert(Algorithm::Sha512_256);
        approved.insert(Algorithm::Sha3_256);
        approved.insert(Algorithm::Sha3_384);
        approved.insert(Algorithm::Sha3_512);
        approved.insert(Algorithm::Shake128);
        approved.insert(Algorithm::Shake256);

        // Digital signatures
        approved.insert(Algorithm::Rsa2048);
        approved.insert(Algorithm::Rsa3072);
        approved.insert(Algorithm::Rsa4096);
        approved.insert(Algorithm::EcdsaP256);
        approved.insert(Algorithm::EcdsaP384);
        approved.insert(Algorithm::EcdsaP521);
        approved.insert(Algorithm::Ed25519);
        approved.insert(Algorithm::Ed448);

        // Message authentication
        approved.insert(Algorithm::HmacSha256);
        approved.insert(Algorithm::HmacSha384);
        approved.insert(Algorithm::HmacSha512);
        approved.insert(Algorithm::CmacAes);

        // Key derivation
        approved.insert(Algorithm::Hkdf);
        approved.insert(Algorithm::Pbkdf2);
        approved.insert(Algorithm::Sp800108Kdf);

        // Key agreement
        approved.insert(Algorithm::EcdhP256);
        approved.insert(Algorithm::EcdhP384);
        approved.insert(Algorithm::EcdhP521);
        approved.insert(Algorithm::X25519);
        approved.insert(Algorithm::X448);
        approved.insert(Algorithm::Dh);

        // Random number generation
        approved.insert(Algorithm::CtrDrbg);
        approved.insert(Algorithm::HmacDrbg);
        approved.insert(Algorithm::HashDrbg);

        // Post-quantum (under evaluation)
        under_evaluation.insert(Algorithm::MlKem);
        under_evaluation.insert(Algorithm::MlDsa);
        under_evaluation.insert(Algorithm::SlhDsa);

        // Threshold cryptography - FIPS approved schemes
        // Threshold ECDSA with NIST curves is approved (FIPS 186-5, SP 800-186)
        approved.insert(Algorithm::ThresholdEcdsaP256);
        approved.insert(Algorithm::ThresholdEcdsaP384);
        // FROST Ed25519 is approved (Ed25519 is in FIPS 186-5)
        approved.insert(Algorithm::FrostEd25519);

        // Threshold BLS12-381 is under NIST evaluation
        under_evaluation.insert(Algorithm::ThresholdBls12381);

        // Note: ThresholdEcdsaSecp256k1 is NOT added to any approved set
        // because secp256k1 is not a NIST-approved curve

        Self {
            approved,
            verification_only,
            under_evaluation,
        }
    }

    /// Check if algorithm is approved
    pub fn is_approved(&self, algorithm: Algorithm) -> bool {
        self.approved.contains(&algorithm)
    }

    /// Check if algorithm is approved for verification only
    pub fn is_verification_only(&self, algorithm: Algorithm) -> bool {
        self.verification_only.contains(&algorithm)
    }

    /// Check if algorithm is under evaluation
    pub fn is_under_evaluation(&self, algorithm: Algorithm) -> bool {
        self.under_evaluation.contains(&algorithm)
    }

    /// Check if algorithm can be used (approved or verification only)
    pub fn can_use(&self, algorithm: Algorithm, for_verification: bool) -> bool {
        self.approved.contains(&algorithm)
            || (for_verification && self.verification_only.contains(&algorithm))
    }

    /// Get all approved algorithms
    pub fn all_approved(&self) -> impl Iterator<Item = &Algorithm> {
        self.approved.iter()
    }

    /// Get reason why algorithm is not approved
    pub fn rejection_reason(&self, algorithm: Algorithm) -> Option<String> {
        if self.approved.contains(&algorithm) {
            return None;
        }

        if self.verification_only.contains(&algorithm) {
            return Some(format!(
                "{} is approved for verification only",
                algorithm.name()
            ));
        }

        if self.under_evaluation.contains(&algorithm) {
            return Some(format!(
                "{} is under NIST evaluation and not yet FIPS approved",
                algorithm.name()
            ));
        }

        Some(format!(
            "{} is not a FIPS 140-3 approved algorithm",
            algorithm.name()
        ))
    }
}

impl Default for ApprovedAlgorithms {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approved_algorithms() {
        let approved = ApprovedAlgorithms::new();

        // Approved
        assert!(approved.is_approved(Algorithm::Aes256));
        assert!(approved.is_approved(Algorithm::Sha256));
        assert!(approved.is_approved(Algorithm::EcdsaP256));
        assert!(approved.is_approved(Algorithm::HmacSha256));

        // Not approved
        assert!(!approved.is_approved(Algorithm::ChaCha20));
        assert!(!approved.is_approved(Algorithm::Blake2b));
        assert!(!approved.is_approved(Algorithm::Secp256k1));
        assert!(!approved.is_approved(Algorithm::Argon2));
    }

    #[test]
    fn test_verification_only() {
        let approved = ApprovedAlgorithms::new();

        assert!(approved.is_verification_only(Algorithm::Sha1));
        assert!(!approved.is_approved(Algorithm::Sha1));
        assert!(approved.can_use(Algorithm::Sha1, true));
        assert!(!approved.can_use(Algorithm::Sha1, false));
    }

    #[test]
    fn test_under_evaluation() {
        let approved = ApprovedAlgorithms::new();

        assert!(approved.is_under_evaluation(Algorithm::MlKem));
        assert!(approved.is_under_evaluation(Algorithm::MlDsa));
        assert!(!approved.is_approved(Algorithm::MlKem));
    }

    #[test]
    fn test_rejection_reason() {
        let approved = ApprovedAlgorithms::new();

        assert!(approved.rejection_reason(Algorithm::Aes256).is_none());
        assert!(approved
            .rejection_reason(Algorithm::ChaCha20)
            .unwrap()
            .contains("not a FIPS"));
        assert!(approved
            .rejection_reason(Algorithm::Sha1)
            .unwrap()
            .contains("verification only"));
        assert!(approved
            .rejection_reason(Algorithm::MlKem)
            .unwrap()
            .contains("under NIST evaluation"));
    }

    #[test]
    fn test_threshold_algorithms_approval() {
        let approved = ApprovedAlgorithms::new();

        // FIPS-approved threshold schemes (NIST curves)
        assert!(approved.is_approved(Algorithm::ThresholdEcdsaP256));
        assert!(approved.is_approved(Algorithm::ThresholdEcdsaP384));
        assert!(approved.is_approved(Algorithm::FrostEd25519));

        // Non-NIST curve - NOT approved
        assert!(!approved.is_approved(Algorithm::ThresholdEcdsaSecp256k1));
        assert!(approved
            .rejection_reason(Algorithm::ThresholdEcdsaSecp256k1)
            .unwrap()
            .contains("not a FIPS"));

        // BLS is under evaluation
        assert!(approved.is_under_evaluation(Algorithm::ThresholdBls12381));
        assert!(!approved.is_approved(Algorithm::ThresholdBls12381));
        assert!(approved
            .rejection_reason(Algorithm::ThresholdBls12381)
            .unwrap()
            .contains("under NIST evaluation"));
    }

    #[test]
    fn test_threshold_algorithm_standards() {
        assert_eq!(
            Algorithm::ThresholdEcdsaP256.standard(),
            Some("FIPS 186-5, SP 800-186")
        );
        assert_eq!(
            Algorithm::ThresholdEcdsaP384.standard(),
            Some("FIPS 186-5, SP 800-186")
        );
        assert_eq!(Algorithm::FrostEd25519.standard(), Some("FIPS 186-5"));
        assert_eq!(Algorithm::ThresholdEcdsaSecp256k1.standard(), None);
        assert_eq!(Algorithm::ThresholdBls12381.standard(), None);
    }
}
