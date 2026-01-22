use hsm_crypto_engine::KeyMaterial;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique key identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(Uuid);

impl KeyId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_string(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key type specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    /// secp256k1 ECDSA (Bitcoin/Ethereum)
    Secp256k1,
    /// BLS12-381 (Ethereum 2.0 validators)
    Bls12381,
    Ed25519,
    Ed448,
    Aes128,
    Aes256,
}

impl KeyType {
    pub fn is_asymmetric(&self) -> bool {
        matches!(
            self,
            KeyType::Rsa2048
                | KeyType::Rsa3072
                | KeyType::Rsa4096
                | KeyType::EcdsaP256
                | KeyType::EcdsaP384
                | KeyType::EcdsaP521
                | KeyType::Secp256k1
                | KeyType::Bls12381
                | KeyType::Ed25519
                | KeyType::Ed448
        )
    }

    pub fn is_symmetric(&self) -> bool {
        !self.is_asymmetric()
    }

    /// Returns the private key size in bytes for this key type
    pub fn private_key_size(&self) -> usize {
        match self {
            KeyType::Ed25519 => 32,
            KeyType::EcdsaP256 => 32,
            KeyType::EcdsaP384 => 48,
            KeyType::EcdsaP521 => 66,
            KeyType::Secp256k1 => 32,
            KeyType::Bls12381 => 32,
            KeyType::Rsa2048 => 256, // Approximate, actual DER encoding varies
            KeyType::Rsa3072 => 384,
            KeyType::Rsa4096 => 512,
            KeyType::Ed448 => 57,
            KeyType::Aes128 => 16,
            KeyType::Aes256 => 32,
        }
    }
}

/// Key lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is being created
    Pending,
    /// Key is active and can be used
    Active,
    /// Key is deactivated but not deleted
    Deactivated,
    /// Key is compromised and should not be used
    Compromised,
    /// Key is scheduled for destruction
    Destroyed,
}

/// Key usage policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsagePolicy {
    /// Can be used for signing
    pub can_sign: bool,
    /// Can be used for encryption
    pub can_encrypt: bool,
    /// Can be used for key derivation
    pub can_derive: bool,
    /// Can be exported (encrypted only)
    pub can_export: bool,
    /// Maximum number of operations (None = unlimited)
    pub max_operations: Option<u64>,
    /// Expiration time (None = no expiration)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for KeyUsagePolicy {
    fn default() -> Self {
        Self {
            can_sign: true,
            can_encrypt: true,
            can_derive: false,
            can_export: false,
            max_operations: None,
            expires_at: None,
        }
    }
}

/// Complete key structure
#[derive(Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Key {
    pub id: KeyId,
    pub key_type: KeyType,
    pub private_material: Option<KeyMaterial>, // None for public-only keys
    pub public_material: Option<Vec<u8>>,      // None for symmetric keys
    pub state: KeyState,
    pub namespace: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub policy: KeyUsagePolicy,
    pub version: u32,
    pub previous_version: Option<KeyId>, // For rotation tracking
    pub operation_count: u64,
}

impl Key {
    pub fn can_use(&self) -> bool {
        self.state == KeyState::Active && !self.is_expired()
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.policy.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }

    pub fn increment_operations(&mut self) {
        self.operation_count += 1;
    }

    pub fn has_reached_max_operations(&self) -> bool {
        if let Some(max) = self.policy.max_operations {
            self.operation_count >= max
        } else {
            false
        }
    }
}

// Implement Debug to prevent key material from being logged
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("key_type", &self.key_type)
            .field("state", &self.state)
            .field("namespace", &self.namespace)
            .field("created_at", &self.created_at)
            .field("version", &self.version)
            .field("previous_version", &self.previous_version)
            .field("operation_count", &self.operation_count)
            .field("private_material", &"<redacted>")
            .field(
                "public_material",
                &if self.public_material.is_some() {
                    "<present>"
                } else {
                    "<none>"
                },
            )
            .finish()
    }
}

/// Key specification for generation
#[derive(Debug, Clone)]
pub struct KeySpec {
    pub key_type: KeyType,
    pub namespace: String,
    pub policy: KeyUsagePolicy,
    pub labels: std::collections::HashMap<String, String>,
}
