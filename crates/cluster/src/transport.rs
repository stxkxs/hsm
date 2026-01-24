//! Secure cluster transport

use crate::config::{NodeId, TransportConfig};
use crate::error::{ClusterError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Cluster transport key manager
pub struct TransportKeyManager {
    /// Master cluster key
    master_key: [u8; 32],

    /// Current epoch
    epoch: u64,

    /// Derived encryption key
    encryption_key: [u8; 32],
}

impl TransportKeyManager {
    /// Create a new transport key manager
    pub fn new(master_key: [u8; 32]) -> Result<Self> {
        let mut manager = Self {
            master_key,
            epoch: 0,
            encryption_key: [0u8; 32],
        };

        manager.derive_encryption_key()?;
        Ok(manager)
    }

    /// Derive encryption key using HKDF
    fn derive_encryption_key(&mut self) -> Result<()> {
        let hk = Hkdf::<Sha256>::new(None, &self.master_key);

        let info = format!("hsm-cluster-transport-{}", self.epoch);
        hk.expand(info.as_bytes(), &mut self.encryption_key)
            .map_err(|_| ClusterError::Encryption("HKDF expansion failed".to_string()))?;

        Ok(())
    }

    /// Rotate to next epoch
    pub fn rotate_epoch(&mut self) -> Result<()> {
        self.epoch += 1;
        self.derive_encryption_key()
    }

    /// Encrypt data for transport
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| ClusterError::Encryption(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|e| ClusterError::Encryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ClusterError::Encryption(e.to_string()))?;

        Ok(EncryptedMessage {
            epoch: self.epoch,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    /// Decrypt data from transport
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        if message.epoch != self.epoch {
            return Err(ClusterError::Encryption(format!(
                "Epoch mismatch: expected {}, got {}",
                self.epoch, message.epoch
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| ClusterError::Encryption(e.to_string()))?;

        let nonce = Nonce::from_slice(&message.nonce);

        cipher
            .decrypt(nonce, message.ciphertext.as_slice())
            .map_err(|e| ClusterError::Encryption(e.to_string()))
    }

    /// Get current epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Drop for TransportKeyManager {
    fn drop(&mut self) {
        // Zeroize sensitive key material
        self.master_key.fill(0);
        self.encryption_key.fill(0);
    }
}

/// Encrypted message
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// Key epoch
    pub epoch: u64,

    /// Nonce
    pub nonce: Vec<u8>,

    /// Ciphertext
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Epoch (8 bytes)
        bytes.extend_from_slice(&self.epoch.to_be_bytes());

        // Nonce length + nonce
        bytes.push(self.nonce.len() as u8);
        bytes.extend_from_slice(&self.nonce);

        // Ciphertext
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 9 {
            return Err(ClusterError::Encryption("Message too short".to_string()));
        }

        let epoch = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let nonce_len = bytes[8] as usize;

        if bytes.len() < 9 + nonce_len {
            return Err(ClusterError::Encryption("Invalid nonce length".to_string()));
        }

        let nonce = bytes[9..9 + nonce_len].to_vec();
        let ciphertext = bytes[9 + nonce_len..].to_vec();

        Ok(Self {
            epoch,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_encryption() {
        let master_key = [1u8; 32];
        let manager = TransportKeyManager::new(master_key).unwrap();

        let plaintext = b"Hello, cluster!";
        let encrypted = manager.encrypt(plaintext).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_message_serialization() {
        let msg = EncryptedMessage {
            epoch: 1,
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            ciphertext: vec![10, 20, 30],
        };

        let bytes = msg.to_bytes();
        let restored = EncryptedMessage::from_bytes(&bytes).unwrap();

        assert_eq!(restored.epoch, msg.epoch);
        assert_eq!(restored.nonce, msg.nonce);
        assert_eq!(restored.ciphertext, msg.ciphertext);
    }

    #[test]
    fn test_epoch_rotation() {
        let master_key = [1u8; 32];
        let mut manager = TransportKeyManager::new(master_key).unwrap();

        assert_eq!(manager.epoch(), 0);

        manager.rotate_epoch().unwrap();
        assert_eq!(manager.epoch(), 1);
    }
}
