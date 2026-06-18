//! Babylon EOTS (Extractable One-Time Signatures) Support
//!
//! This module provides finality provider signing with anti-slashing protection
//! for the Babylon Bitcoin staking protocol.
//!
//! # EOTS Security Model
//!
//! EOTS (Extractable One-Time Signatures) are a cryptographic primitive where:
//! - Signing the same message twice at the same block height reveals the private key
//! - This provides an economic slashing mechanism for Bitcoin staking
//!
//! # Slashing Protection
//!
//! The anti-slashing protection for EOTS is **even more critical** than for Ethereum:
//! - Double signing doesn't just result in slashing penalties
//! - It **reveals the private key**, allowing anyone to steal all funds
//!
//! # Security
//!
//! - Protection **cannot be disabled**
//! - Atomic check-and-sign prevents race conditions
//! - Persistent storage survives restarts

use crate::error::{Result, SlashingError, ValidatorError};
use crate::types::*;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Db, Tree};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info};

/// Tree name for EOTS height tracking
const EOTS_HEIGHTS_TREE: &str = "eots_heights";
const EOTS_KEYS_TREE: &str = "eots_keys";

/// EOTS key data stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EotsKeyData {
    /// Public key (33 bytes compressed)
    public_key: Vec<u8>,
    /// Chain ID (e.g., "babylon-mainnet")
    chain_id: String,
    /// Created timestamp
    created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity
    last_activity: chrono::DateTime<chrono::Utc>,
    /// Total signatures
    signature_count: u64,
}

/// Babylon EOTS Anti-Slashing Database.
///
/// This database tracks all EOTS signing heights to prevent double-signing.
/// **Protection cannot be disabled.**
///
/// # Critical Security Note
///
/// Unlike Ethereum where double-signing results in slashing penalties,
/// EOTS double-signing **reveals the private key**. This makes the
/// anti-slashing protection absolutely critical.
pub struct EotsSlashingDb {
    /// The underlying database
    db: Db,
    /// Keys tree
    keys: Tree,
    /// Heights tree (keyed by public key, stores signed heights)
    heights: Tree,
    /// Per-key locks
    key_locks: Arc<dashmap::DashMap<Vec<u8>, Arc<RwLock<()>>>>,
}

impl EotsSlashingDb {
    /// Open or create an EOTS slashing protection database.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        // SECURITY: Disable sled's periodic background flush (default 500ms). EOTS
        // double-signing reveals the private key, so a height record MUST be durable on
        // disk before the signature is produced. We flush explicitly inside
        // check_and_record_height while holding the per-key write lock. Relying on the
        // background flush would leave a crash window in which the record is lost.
        let db = sled::Config::new()
            .path(path.as_ref())
            .flush_every_ms(None)
            .open()?;

        let keys = db.open_tree(EOTS_KEYS_TREE)?;
        let heights = db.open_tree(EOTS_HEIGHTS_TREE)?;

        info!(
            "Opened EOTS slashing protection database at {:?}",
            path.as_ref()
        );

        Ok(Self {
            db,
            keys,
            heights,
            key_locks: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Create an in-memory database (for testing and benchmarking only).
    #[cfg(any(test, feature = "test-util"))]
    pub fn in_memory() -> Result<Self> {
        let db = sled::Config::new()
            .temporary(true)
            .flush_every_ms(None)
            .open()?;

        let keys = db.open_tree(EOTS_KEYS_TREE)?;
        let heights = db.open_tree(EOTS_HEIGHTS_TREE)?;

        Ok(Self {
            db,
            keys,
            heights,
            key_locks: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// Register a new EOTS key.
    pub fn register_key(&self, public_key: &[u8], chain_id: &str) -> Result<()> {
        if self.keys.contains_key(public_key)? {
            return Err(ValidatorError::ValidatorAlreadyExists {
                public_key: hex::encode(public_key),
            });
        }

        let now = chrono::Utc::now();
        let data = EotsKeyData {
            public_key: public_key.to_vec(),
            chain_id: chain_id.to_string(),
            created_at: now,
            last_activity: now,
            signature_count: 0,
        };

        let encoded = serde_json::to_vec(&data)?;
        self.keys.insert(public_key, encoded)?;

        self.key_locks
            .entry(public_key.to_vec())
            .or_insert_with(|| Arc::new(RwLock::new(())));

        info!(
            key = %hex::encode(&public_key[..8]),
            chain_id,
            "Registered new EOTS key"
        );

        Ok(())
    }

    /// Get the lock for a key.
    fn get_key_lock(&self, public_key: &[u8]) -> Arc<RwLock<()>> {
        self.key_locks
            .entry(public_key.to_vec())
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone()
    }

    /// Height key for storage.
    fn height_key(&self, public_key: &[u8], height: BlockHeight) -> Vec<u8> {
        let mut key = Vec::with_capacity(public_key.len() + 9);
        key.extend_from_slice(public_key);
        key.push(b':');
        key.extend_from_slice(&height.to_be_bytes());
        key
    }

    /// Check if signing at a height would be slashable and record it atomically.
    ///
    /// # CRITICAL SECURITY
    ///
    /// This function prevents EOTS double-signing. Double-signing with EOTS
    /// **reveals the private key**, which would allow anyone to steal all funds.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The EOTS public key
    /// * `height` - The block height being signed
    ///
    /// # Returns
    ///
    /// - `Ok(())` if safe to sign (height recorded)
    /// - `Err(SlashingError::EotsDoubleSign)` if already signed at this height
    pub fn check_and_record_height(
        &self,
        public_key: &[u8],
        height: BlockHeight,
    ) -> std::result::Result<(), SlashingError> {
        // Acquire exclusive lock
        let lock = self.get_key_lock(public_key);
        let _guard = lock.write();

        let height_key = self.height_key(public_key, height);

        // Check if already signed at this height.
        //
        // SECURITY (fail closed): a sled read error MUST NOT be treated as "not signed".
        // For EOTS, double-signing the same height *reveals the private key*, so a read
        // error must abort signing with DatabaseError rather than fall through and sign
        // again. (`contains_key(..).unwrap_or(false)` previously failed OPEN here.)
        match self.heights.contains_key(&height_key) {
            Ok(true) => {
                error!(
                    key = %hex::encode(&public_key[..8]),
                    height,
                    "EOTS DOUBLE SIGN PREVENTED - Private key would have been revealed!"
                );
                return Err(SlashingError::EotsDoubleSign { height });
            }
            Ok(false) => {}
            Err(e) => {
                error!(
                    key = %hex::encode(&public_key[..8]),
                    height,
                    error = %e,
                    "EOTS slashing DB read error - refusing to sign (fail closed)"
                );
                return Err(SlashingError::DatabaseError(format!(
                    "Failed to read EOTS height record: {e}"
                )));
            }
        }

        // Record the height
        let now = chrono::Utc::now();
        let timestamp = now.timestamp().to_le_bytes();
        self.heights.insert(&height_key, &timestamp).map_err(|e| {
            SlashingError::DatabaseError(format!("Failed to record EOTS height: {e}"))
        })?;

        // SECURITY (durability before signing): the EOTS height record MUST be durable on
        // disk before the caller produces a signature. EOTS double-signing reveals the
        // private key, so this is the most safety-critical flush in the crate. We flush
        // WHILE STILL HOLDING the per-key write lock and only return Ok once fsync
        // succeeds. If the flush fails we report DatabaseError and the caller must NOT
        // sign. Without this, a crash in sled's background-flush window would lose the
        // record and permit an irreversible key-revealing double-sign on restart.
        self.db.flush().map_err(|e| {
            error!(
                key = %hex::encode(&public_key[..8]),
                height,
                error = %e,
                "Failed to flush EOTS height record to disk - refusing to sign"
            );
            SlashingError::DatabaseError(format!("Failed to flush EOTS height record: {e}"))
        })?;

        // Update key metadata (best-effort; durability of the height record above is what
        // guards against double-signing).
        if let Ok(Some(data)) = self.keys.get(public_key) {
            if let Ok(mut key_data) = serde_json::from_slice::<EotsKeyData>(&data) {
                key_data.last_activity = now;
                key_data.signature_count += 1;
                if let Ok(encoded) = serde_json::to_vec(&key_data) {
                    let _ = self.keys.insert(public_key, encoded);
                }
            }
        }

        debug!(
            key = %hex::encode(&public_key[..8]),
            height,
            "Recorded EOTS signing height"
        );

        Ok(())
    }

    /// Check if a height has been signed (without recording).
    pub fn is_height_signed(&self, public_key: &[u8], height: BlockHeight) -> Result<bool> {
        let height_key = self.height_key(public_key, height);
        Ok(self.heights.contains_key(&height_key)?)
    }

    /// Get all signed heights for a key.
    pub fn get_signed_heights(&self, public_key: &[u8]) -> Result<Vec<BlockHeight>> {
        let prefix = {
            let mut p = public_key.to_vec();
            p.push(b':');
            p
        };

        let mut heights = Vec::new();
        for item in self.heights.scan_prefix(&prefix) {
            let (key, _) = item?;
            // Extract height from key
            if key.len() > prefix.len() {
                let height_bytes = &key[prefix.len()..];
                if height_bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(height_bytes);
                    heights.push(u64::from_be_bytes(arr));
                }
            }
        }

        heights.sort();
        Ok(heights)
    }

    /// Flush to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

/// An EOTS key for Babylon finality providers.
///
/// This struct wraps a secp256k1 signing key with anti-slashing protection.
/// **Protection cannot be disabled.**
pub struct EotsKey {
    /// The signing key
    signing_key: SigningKey,
    /// Public key (compressed, 33 bytes)
    public_key: Vec<u8>,
    /// Chain ID
    chain_id: String,
    /// Reference to the slashing database
    slashing_db: Arc<EotsSlashingDb>,
}

impl EotsKey {
    /// Create a new EOTS key from a secret key.
    ///
    /// # Arguments
    ///
    /// * `secret_key_bytes` - The 32-byte secp256k1 secret key
    /// * `chain_id` - The Babylon chain ID
    /// * `slashing_db` - Reference to the EOTS slashing database
    pub fn new(
        secret_key_bytes: &[u8],
        chain_id: &str,
        slashing_db: Arc<EotsSlashingDb>,
    ) -> Result<Self> {
        let signing_key = SigningKey::from_slice(secret_key_bytes).map_err(|e| {
            ValidatorError::InvalidPublicKey {
                reason: format!("Invalid secp256k1 secret key: {:?}", e),
            }
        })?;

        let public_key = signing_key.verifying_key().to_sec1_bytes().to_vec();

        // Register in slashing database
        if !slashing_db.keys.contains_key(&public_key).unwrap_or(false) {
            slashing_db.register_key(&public_key, chain_id)?;
        }

        Ok(Self {
            signing_key,
            public_key,
            chain_id: chain_id.to_string(),
            slashing_db,
        })
    }

    /// Generate a new random EOTS key.
    pub fn generate(chain_id: &str, slashing_db: Arc<EotsSlashingDb>) -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = signing_key.verifying_key().to_sec1_bytes().to_vec();

        slashing_db.register_key(&public_key, chain_id)?;

        info!(
            key = %hex::encode(&public_key[..8]),
            chain_id,
            "Generated new EOTS key"
        );

        Ok(Self {
            signing_key,
            public_key,
            chain_id: chain_id.to_string(),
            slashing_db,
        })
    }

    /// Get the public key (compressed, 33 bytes).
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Sign a finality vote with slashing protection.
    ///
    /// # CRITICAL SECURITY
    ///
    /// This function will **refuse to sign** if the same height has been
    /// signed before. This is essential because EOTS double-signing
    /// **reveals the private key**.
    ///
    /// # Arguments
    ///
    /// * `height` - The block height being voted on
    /// * `block_hash` - The hash of the block being voted on
    ///
    /// # Returns
    ///
    /// - `Ok(signature)` if safe to sign
    /// - `Err(SlashingError::EotsDoubleSign)` if already signed at this height
    pub fn sign_finality_vote(
        &self,
        height: BlockHeight,
        block_hash: &[u8; 32],
    ) -> Result<EotsSignature> {
        // Check and record in slashing database BEFORE signing
        self.slashing_db
            .check_and_record_height(&self.public_key, height)
            .map_err(ValidatorError::Slashing)?;

        // Create the message to sign
        let message = self.create_vote_message(height, block_hash);
        let message_hash: [u8; 32] = Sha256::digest(&message).into();

        // Sign
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&message_hash)
            .map_err(|e| ValidatorError::Crypto(e.to_string()))?;

        debug!(
            key = %hex::encode(&self.public_key[..8]),
            height,
            block_hash = %hex::encode(&block_hash[..8]),
            "Signed EOTS finality vote"
        );

        Ok(EotsSignature {
            height,
            block_hash: *block_hash,
            signature: signature.to_bytes().to_vec(),
            recovery_id: recovery_id.to_byte(),
        })
    }

    /// Create the vote message for a given height and block hash.
    fn create_vote_message(&self, height: BlockHeight, block_hash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(8 + 32 + self.chain_id.len());
        message.extend_from_slice(&height.to_le_bytes());
        message.extend_from_slice(block_hash);
        message.extend_from_slice(self.chain_id.as_bytes());
        message
    }

    /// Check if a height has already been signed.
    pub fn is_height_signed(&self, height: BlockHeight) -> Result<bool> {
        self.slashing_db.is_height_signed(&self.public_key, height)
    }

    /// Get all heights that have been signed.
    pub fn get_signed_heights(&self) -> Result<Vec<BlockHeight>> {
        self.slashing_db.get_signed_heights(&self.public_key)
    }
}

/// An EOTS signature with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EotsSignature {
    /// Block height that was signed
    pub height: BlockHeight,
    /// Block hash that was signed
    pub block_hash: [u8; 32],
    /// The ECDSA signature (64 bytes, r || s)
    pub signature: Vec<u8>,
    /// Recovery ID (0 or 1)
    pub recovery_id: u8,
}

impl EotsSignature {
    /// Convert to bytes (height || block_hash || signature || recovery_id).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 32 + 64 + 1);
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.block_hash);
        bytes.extend_from_slice(&self.signature);
        bytes.push(self.recovery_id);
        bytes
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

/// Babylon validator (finality provider) with anti-slashing protection.
pub struct BabylonValidator {
    /// The EOTS key
    eots_key: EotsKey,
}

impl BabylonValidator {
    /// Create a new Babylon validator.
    pub fn new(eots_key: EotsKey) -> Self {
        Self { eots_key }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &[u8] {
        self.eots_key.public_key()
    }

    /// Sign a finality vote.
    pub fn sign_finality_vote(
        &self,
        height: BlockHeight,
        block_hash: &[u8; 32],
    ) -> Result<EotsSignature> {
        self.eots_key.sign_finality_vote(height, block_hash)
    }

    /// Get all signed heights.
    pub fn get_signed_heights(&self) -> Result<Vec<BlockHeight>> {
        self.eots_key.get_signed_heights()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_eots_key() -> (EotsKey, Arc<EotsSlashingDb>) {
        let db = Arc::new(EotsSlashingDb::in_memory().unwrap());
        let key = EotsKey::generate("babylon-testnet", db.clone()).unwrap();
        (key, db)
    }

    #[test]
    fn test_eots_key_generation() {
        let (key, _db) = create_test_eots_key();

        // Public key should be 33 bytes (compressed secp256k1)
        assert_eq!(key.public_key().len(), 33);
        assert_eq!(key.chain_id(), "babylon-testnet");
    }

    #[test]
    fn test_eots_sign_finality_vote() {
        let (key, _db) = create_test_eots_key();

        let height = 12345;
        let block_hash = [0xab; 32];

        let signature = key.sign_finality_vote(height, &block_hash).unwrap();

        assert_eq!(signature.height, height);
        assert_eq!(signature.block_hash, block_hash);
        assert_eq!(signature.signature.len(), 64);
        assert!(signature.recovery_id <= 1);
    }

    #[test]
    fn test_eots_double_sign_prevented() {
        let (key, _db) = create_test_eots_key();

        let height = 12345;
        let block_hash1 = [0xab; 32];
        let block_hash2 = [0xcd; 32];

        // First signature succeeds
        key.sign_finality_vote(height, &block_hash1).unwrap();

        // Second signature at same height fails
        let result = key.sign_finality_vote(height, &block_hash2);
        assert!(matches!(
            result,
            Err(ValidatorError::Slashing(
                SlashingError::EotsDoubleSign { .. }
            ))
        ));
    }

    #[test]
    fn test_eots_different_heights_ok() {
        let (key, _db) = create_test_eots_key();

        let block_hash = [0xab; 32];

        // Can sign at different heights
        key.sign_finality_vote(100, &block_hash).unwrap();
        key.sign_finality_vote(101, &block_hash).unwrap();
        key.sign_finality_vote(102, &block_hash).unwrap();

        let heights = key.get_signed_heights().unwrap();
        assert_eq!(heights, vec![100, 101, 102]);
    }

    #[test]
    fn test_eots_height_tracking() {
        let (key, _db) = create_test_eots_key();

        let block_hash = [0xab; 32];

        assert!(!key.is_height_signed(100).unwrap());

        key.sign_finality_vote(100, &block_hash).unwrap();

        assert!(key.is_height_signed(100).unwrap());
        assert!(!key.is_height_signed(101).unwrap());
    }

    #[test]
    fn test_babylon_validator() {
        let (eots_key, _db) = create_test_eots_key();
        let validator = BabylonValidator::new(eots_key);

        let height = 12345;
        let block_hash = [0xab; 32];

        let signature = validator.sign_finality_vote(height, &block_hash).unwrap();
        assert_eq!(signature.height, height);
    }

    #[test]
    fn test_eots_idempotent_check() {
        let db = Arc::new(EotsSlashingDb::in_memory().unwrap());

        let pubkey = vec![0x02; 33]; // Fake compressed pubkey
        db.register_key(&pubkey, "babylon-testnet").unwrap();

        // First check succeeds
        db.check_and_record_height(&pubkey, 100).unwrap();

        // Second check at same height fails
        let result = db.check_and_record_height(&pubkey, 100);
        assert!(matches!(
            result,
            Err(SlashingError::EotsDoubleSign { height: 100 })
        ));
    }

    // ---------------------------------------------------------------------
    // CRITICAL #4 (EOTS): durability-before-signature regression test.
    //
    // For Babylon EOTS, signing the same height twice does not merely incur a
    // slashing penalty - it REVEALS THE PRIVATE KEY. The height record therefore
    // MUST be durable on disk before `sign_finality_vote` returns a signature.
    //
    // We simulate a crash by re-executing the test binary as a child that records
    // the height (via check_and_record_height, which flushes internally) and then
    // calls `std::process::abort()` - terminating WITHOUT running sled's Drop-flush.
    // The DB is opened with `flush_every_ms(None)`, so only the explicit in-function
    // flush can persist the record. The parent reopens and asserts the height is
    // still recorded (so a restart cannot double-sign and leak the key).
    //
    // Before the fix the height lived only in the in-memory IO buffer and was lost
    // on the abort, so on restart the height would appear unsigned and a second
    // signature (key reveal) would be permitted - this test would FAIL.
    // ---------------------------------------------------------------------

    const EOTS_CRASH_CHILD_ENV: &str = "HSM_VALIDATOR_EOTS_CRASH_CHILD";
    const EOTS_CRASH_PUBKEY: [u8; 33] = [0x02u8; 33];
    const EOTS_CRASH_HEIGHT: BlockHeight = 777;

    fn eots_maybe_run_crash_child() {
        if std::env::var(EOTS_CRASH_CHILD_ENV).is_err() {
            return;
        }
        let path = std::env::var("HSM_VALIDATOR_EOTS_CRASH_PATH").unwrap();
        let db = EotsSlashingDb::open(&path).unwrap();
        db.register_key(&EOTS_CRASH_PUBKEY, "babylon-testnet")
            .unwrap();
        db.check_and_record_height(&EOTS_CRASH_PUBKEY, EOTS_CRASH_HEIGHT)
            .unwrap();
        // Crash immediately after the record returned Ok: abort skips destructors so
        // sled's Drop-flush never runs. Only the in-function flush can have persisted.
        std::process::abort();
    }

    #[test]
    fn test_eots_height_durable_before_signature_returned() {
        eots_maybe_run_crash_child();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("eots-db");

        let exe = std::env::current_exe().expect("current_exe");
        let status = std::process::Command::new(exe)
            .arg("--exact")
            .arg("babylon::tests::test_eots_height_durable_before_signature_returned")
            .env(EOTS_CRASH_CHILD_ENV, "1")
            .env("HSM_VALIDATOR_EOTS_CRASH_PATH", &db_path)
            .status()
            .expect("spawn eots crash child");
        assert!(
            !status.success(),
            "eots crash child should have aborted, got {status:?}"
        );

        // Reopen from a fresh process; the height must have survived the crash.
        let db = EotsSlashingDb::open(&db_path).unwrap();
        assert!(
            db.is_height_signed(&EOTS_CRASH_PUBKEY, EOTS_CRASH_HEIGHT)
                .unwrap(),
            "EOTS height must be durable across a crash (flush before signature) - \
             otherwise a restart could double-sign and reveal the private key"
        );

        // And the durable record must block a second sign at that height (key reveal).
        let result = db.check_and_record_height(&EOTS_CRASH_PUBKEY, EOTS_CRASH_HEIGHT);
        assert!(
            matches!(result, Err(SlashingError::EotsDoubleSign { .. })),
            "after crash recovery the recorded height must prevent an EOTS double sign, got {result:?}"
        );
    }
}
