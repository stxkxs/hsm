//! Solana-specific cryptographic operations
//!
//! Provides support for:
//! - Solana address generation (Ed25519)
//! - Transaction parsing
//! - Message signing

pub mod transaction;

use crate::bip::bip32::DerivationPath;
use crate::error::{BlockchainError, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// SLIP-0010 ed25519 derivation.
///
/// Solana keys are derived with SLIP-0010 over the ed25519 curve, NOT by
/// reusing a secp256k1 BIP-32 scalar. The master node is produced with
/// `HMAC-SHA512(key = "ed25519 seed", data = seed)`, and every child uses
/// hardened derivation `HMAC-SHA512(key = c_par, data = 0x00 || k_par || ser32(i'))`.
/// Non-hardened (public) derivation is undefined for ed25519, so only hardened
/// indices are permitted (the standard Solana path is `m/44'/501'/account'/0'`).
fn slip10_ed25519_derive(seed: &[u8], path: &DerivationPath) -> Result<[u8; 32]> {
    // Master node.
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e| BlockchainError::DerivationFailed(e.to_string()))?;
    mac.update(seed);
    let i = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&i[..32]);
    chain_code.copy_from_slice(&i[32..]);

    // Child derivation (hardened only).
    for component in path.components() {
        if !component.hardened {
            // Zeroize working material before returning the error.
            key.zeroize();
            chain_code.zeroize();
            return Err(BlockchainError::InvalidDerivationPath(format!(
                "SLIP-0010 ed25519 requires hardened derivation; index {} is not hardened",
                component.index
            )));
        }
        if component.index >= 0x8000_0000 {
            key.zeroize();
            chain_code.zeroize();
            return Err(BlockchainError::InvalidDerivationPath(format!(
                "Derivation index out of range: {}",
                component.index
            )));
        }

        let hardened = component.index | 0x8000_0000;
        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| BlockchainError::DerivationFailed(e.to_string()))?;
        mac.update(&[0u8]);
        mac.update(&key);
        mac.update(&hardened.to_be_bytes());
        let i = mac.finalize().into_bytes();

        key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);
    }

    chain_code.zeroize();
    Ok(key)
}

/// Solana public key (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SolanaPublicKey([u8; 32]);

impl SolanaPublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(BlockchainError::InvalidPublicKey(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to base58 string
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Parse from base58 string
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| BlockchainError::InvalidPublicKey(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Returns `true` if these 32 bytes decompress to a valid ed25519 curve
    /// point. A Program Derived Address must NOT lie on the curve, so that no
    /// private key can ever exist for it.
    ///
    /// This matches Solana's `bytes_are_curve_point`, which is exactly
    /// `CompressedEdwardsY::decompress(...).is_some()`. `ed25519-dalek`'s
    /// `VerifyingKey::from_bytes` performs precisely this decompression (and no
    /// extra weak-key rejection), so it is an equivalent on-curve test.
    fn is_on_curve(bytes: &[u8; 32]) -> bool {
        ed25519_dalek::VerifyingKey::from_bytes(bytes).is_ok()
    }

    /// Derive the canonical SHA-256 program-address candidate for a given bump
    /// seed: `SHA256(seeds.. || [bump] || program_id || "ProgramDerivedAddress")`.
    fn create_program_address_candidate(
        seeds: &[&[u8]],
        bump: u8,
        program_id: &SolanaPublicKey,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id.as_bytes());
        hasher.update(b"ProgramDerivedAddress");

        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        bytes
    }

    /// Find a Program Derived Address (PDA) and its bump seed.
    ///
    /// Iterates the bump seed from 255 down to 0, computing
    /// `SHA256(seeds.. || [bump] || program_id || "ProgramDerivedAddress")` for
    /// each, and returns the first candidate that is *off-curve* (i.e. does NOT
    /// decompress to a valid ed25519 point). An off-curve address guarantees no
    /// corresponding private key exists, which is the entire security property
    /// of a PDA.
    ///
    /// This is the canonical Solana `Pubkey::find_program_address` algorithm.
    /// The previous implementation simply returned the `bump == 254` candidate
    /// without ever checking the curve, which is incorrect and could return an
    /// on-curve (spendable) address (LOW #32).
    pub fn find_program_address(seeds: &[&[u8]], program_id: &SolanaPublicKey) -> (Self, u8) {
        for bump in (0u8..=255).rev() {
            let candidate = Self::create_program_address_candidate(seeds, bump, program_id);
            if !Self::is_on_curve(&candidate) {
                return (Self(candidate), bump);
            }
        }
        // It is cryptographically infeasible for all 256 bump seeds to land
        // on-curve; Solana itself panics in this case.
        panic!("unable to find a viable program address bump seed");
    }
}

impl fmt::Debug for SolanaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SolanaPublicKey({})", self.to_base58())
    }
}

impl fmt::Display for SolanaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Solana keypair
#[derive(Clone)]
pub struct SolanaKeypair {
    /// Secret key (32 bytes)
    secret: [u8; 32],
    /// Public key
    public: SolanaPublicKey,
}

impl SolanaKeypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self::from_secret(&secret)
    }

    /// Create from secret key bytes
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        use ed25519_dalek::{SigningKey, VerifyingKey};

        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key: VerifyingKey = (&signing_key).into();

        Self {
            secret: *secret,
            public: SolanaPublicKey(verifying_key.to_bytes()),
        }
    }

    /// Derive a Solana keypair from a BIP-39 seed using SLIP-0010 ed25519.
    ///
    /// This is the standard Solana derivation. The 64-byte BIP-39 seed (from
    /// [`crate::bip::bip39::Mnemonic::to_seed`]) is fed into SLIP-0010 ed25519
    /// derivation along a hardened-only path such as `m/44'/501'/0'/0'` (see
    /// [`DerivationPath::solana`]). The resulting 32-byte scalar is used as the
    /// ed25519 secret seed.
    ///
    /// # Errors
    ///
    /// Returns [`BlockchainError::InvalidDerivationPath`] if the path contains a
    /// non-hardened component, since ed25519 SLIP-0010 only supports hardened
    /// derivation.
    pub fn from_seed_slip10(seed: &[u8], path: &DerivationPath) -> Result<Self> {
        let mut secret = slip10_ed25519_derive(seed, path)?;
        let keypair = Self::from_secret(&secret);
        secret.zeroize();
        Ok(keypair)
    }

    /// Get the public key
    pub fn public_key(&self) -> &SolanaPublicKey {
        &self.public
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&self.secret);
        let signature = signing_key.sign(message);
        signature.to_bytes()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(&self.public.0);
        if let Ok(vk) = verifying_key {
            if let Ok(sig) = Signature::from_slice(signature) {
                return vk.verify(message, &sig).is_ok();
            }
        }
        false
    }
}

impl fmt::Debug for SolanaKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolanaKeypair")
            .field("secret", &"[REDACTED]")
            .field("public", &self.public)
            .finish()
    }
}

impl Drop for SolanaKeypair {
    fn drop(&mut self) {
        // Zeroize secret key
        self.secret.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_base58() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let pubkey = SolanaPublicKey::from_bytes(bytes);
        let base58 = pubkey.to_base58();

        let recovered = SolanaPublicKey::from_base58(&base58).unwrap();
        assert_eq!(pubkey, recovered);
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = SolanaKeypair::generate();
        let pubkey = keypair.public_key();

        // Public key should be 32 bytes
        assert_eq!(pubkey.as_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = SolanaKeypair::generate();
        let message = b"Hello, Solana!";

        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature));

        // Wrong message should fail
        assert!(!keypair.verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_deterministic_keypair() {
        let secret = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let keypair1 = SolanaKeypair::from_secret(&secret);
        let keypair2 = SolanaKeypair::from_secret(&secret);

        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_keypair_debug_redacts() {
        let keypair = SolanaKeypair::generate();
        let debug = format!("{:?}", keypair);
        assert!(debug.contains("REDACTED"));
    }

    /// SLIP-0010 ed25519 master/child known-answer test from the SLIP-0010
    /// specification (Test vector 1 for ed25519, seed `000102...0f`).
    #[test]
    fn test_slip10_ed25519_spec_vectors() {
        use crate::bip::bip32::{ChildNumber, DerivationPath};

        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        // Master key (empty path).
        let master = super::slip10_ed25519_derive(&seed, &DerivationPath::master()).unwrap();
        assert_eq!(
            hex::encode(master),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );

        // m/0'
        let m0 = super::slip10_ed25519_derive(
            &seed,
            &DerivationPath::from_components(vec![ChildNumber::hardened(0)]),
        )
        .unwrap();
        assert_eq!(
            hex::encode(m0),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
    }

    /// Known-answer test against the canonical Solana wallet derivation.
    ///
    /// The standard BIP-39 test mnemonic ("abandon ... about", empty
    /// passphrase) at the standard Solana path `m/44'/501'/0'/0'` derives the
    /// well-known address `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` (as
    /// produced by the Solana CLI / Phantom). Previously `from_hd_key` fed a
    /// secp256k1 BIP-32 scalar into ed25519, yielding an entirely different,
    /// non-standard key (HIGH #15).
    #[test]
    fn test_solana_standard_wallet_vector() {
        use crate::bip::bip32::DerivationPath;
        use crate::bip::bip39::{Language, Mnemonic};

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("");

        let path = DerivationPath::solana(0); // m/44'/501'/0'/0'
        let keypair = SolanaKeypair::from_seed_slip10(seed.as_bytes(), &path).unwrap();

        assert_eq!(
            keypair.public_key().to_base58(),
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
        );

        // The derived key must still sign and verify correctly.
        let msg = b"solana slip-0010 derivation";
        let sig = keypair.sign(msg);
        assert!(keypair.verify(msg, &sig));
    }

    /// PDA known-answer test, cross-checked against an independent Python
    /// reference that performs a real ed25519 point decompression for the
    /// on-curve test.
    ///
    /// `find_program_address([b"hello"], Token program)` yields the address
    /// below with bump 254; `[b""]` under the System program yields its address
    /// with bump 255. The returned address must be off-curve (LOW #32).
    #[test]
    fn test_pda_known_answer() {
        let token =
            SolanaPublicKey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let (pda, bump) = SolanaPublicKey::find_program_address(&[b"hello"], &token);
        assert_eq!(
            pda.to_base58(),
            "4HB6s1bAiAPk8kxSatGd3U7bKArXXSoDfemfu23UZBdw"
        );
        assert_eq!(bump, 254);
        // A PDA must never be a valid curve point.
        assert!(!SolanaPublicKey::is_on_curve(pda.as_bytes()));

        let system = SolanaPublicKey::from_base58("11111111111111111111111111111111").unwrap();
        let (pda2, bump2) = SolanaPublicKey::find_program_address(&[b""], &system);
        assert_eq!(
            pda2.to_base58(),
            "Cu7NwqCXSmsR5vgGA3Vw9uYVViPi3kQvkbKByVQ8nPY9"
        );
        assert_eq!(bump2, 255);
        assert!(!SolanaPublicKey::is_on_curve(pda2.as_bytes()));
    }

    /// The PDA derivation must be deterministic.
    #[test]
    fn test_pda_deterministic() {
        let prog =
            SolanaPublicKey::from_base58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let a = SolanaPublicKey::find_program_address(&[b"vault", b"seed2"], &prog);
        let b = SolanaPublicKey::find_program_address(&[b"vault", b"seed2"], &prog);
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
        assert!(!SolanaPublicKey::is_on_curve(a.0.as_bytes()));
    }

    /// Sanity check the on-curve predicate: a real ed25519 public key IS on the
    /// curve (so the PDA off-curve guarantee is meaningful).
    #[test]
    fn test_is_on_curve_true_for_real_pubkey() {
        let kp = SolanaKeypair::generate();
        assert!(SolanaPublicKey::is_on_curve(kp.public_key().as_bytes()));
    }

    /// SLIP-0010 ed25519 only supports hardened derivation; a path with a
    /// non-hardened component must be rejected rather than silently producing a
    /// non-standard key.
    #[test]
    fn test_solana_rejects_non_hardened_path() {
        use crate::bip::bip32::{ChildNumber, DerivationPath};

        let seed = [7u8; 64];
        let path = DerivationPath::from_components(vec![
            ChildNumber::hardened(44),
            ChildNumber::hardened(501),
            ChildNumber::normal(0), // not hardened
        ]);
        assert!(SolanaKeypair::from_seed_slip10(&seed, &path).is_err());
    }
}
