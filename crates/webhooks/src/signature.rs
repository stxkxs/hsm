//! Webhook signature generation and verification

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Webhook signer for HMAC-SHA256 signatures
pub struct WebhookSigner {
    secret: Vec<u8>,
}

impl WebhookSigner {
    /// Create a new signer with the given secret
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
        }
    }

    /// Create a new signer from bytes
    pub fn from_bytes(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }

    /// Sign a payload
    ///
    /// The signature format is: `sha256=<hex_signature>`
    pub fn sign(&self, payload: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key size");
        mac.update(payload);
        let result = mac.finalize();
        format!("sha256={}", hex::encode(result.into_bytes()))
    }

    /// Sign a payload with timestamp
    ///
    /// This creates a signature over `timestamp.payload` to prevent replay attacks.
    pub fn sign_with_timestamp(&self, payload: &[u8], timestamp: i64) -> String {
        let message = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC accepts any key size");
        mac.update(message.as_bytes());
        let result = mac.finalize();
        format!("sha256={}", hex::encode(result.into_bytes()))
    }

    /// Verify a signature
    pub fn verify(&self, payload: &[u8], signature: &str) -> bool {
        let expected = self.sign(payload);
        constant_time_compare(&expected, signature)
    }

    /// Verify a signature with timestamp
    pub fn verify_with_timestamp(&self, payload: &[u8], timestamp: i64, signature: &str) -> bool {
        let expected = self.sign_with_timestamp(payload, timestamp);
        constant_time_compare(&expected, signature)
    }

    /// Verify and check timestamp freshness
    ///
    /// Rejects signatures older than `max_age_seconds`.
    pub fn verify_fresh(
        &self,
        payload: &[u8],
        timestamp: i64,
        signature: &str,
        max_age_seconds: i64,
    ) -> bool {
        let now = chrono::Utc::now().timestamp();
        let age = now - timestamp;

        // Reject if too old or in the future
        if age < 0 || age > max_age_seconds {
            return false;
        }

        self.verify_with_timestamp(payload, timestamp, signature)
    }
}

/// Constant-time string comparison
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut result = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Generate a secure random secret
pub fn generate_secret(length: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Header names for webhook signatures
pub mod headers {
    /// Signature header
    pub const SIGNATURE: &str = "X-Webhook-Signature";
    /// Timestamp header
    pub const TIMESTAMP: &str = "X-Webhook-Timestamp";
    /// Unique ID header
    pub const ID: &str = "X-Webhook-ID";
    /// Event type header
    pub const EVENT_TYPE: &str = "X-Webhook-Event";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let signer = WebhookSigner::new("test_secret_key_123");
        let payload = b"test payload";

        let signature = signer.sign(payload);
        assert!(signature.starts_with("sha256="));
        assert!(signer.verify(payload, &signature));
    }

    #[test]
    fn test_wrong_payload() {
        let signer = WebhookSigner::new("test_secret_key_123");
        let signature = signer.sign(b"original payload");
        assert!(!signer.verify(b"different payload", &signature));
    }

    #[test]
    fn test_wrong_signature() {
        let signer = WebhookSigner::new("test_secret_key_123");
        let payload = b"test payload";
        assert!(!signer.verify(payload, "sha256=invalid_signature"));
    }

    #[test]
    fn test_sign_with_timestamp() {
        let signer = WebhookSigner::new("test_secret_key_123");
        let payload = b"test payload";
        let timestamp = 1704067200i64; // Fixed timestamp for testing

        let signature = signer.sign_with_timestamp(payload, timestamp);
        assert!(signer.verify_with_timestamp(payload, timestamp, &signature));

        // Different timestamp should fail
        assert!(!signer.verify_with_timestamp(payload, timestamp + 1, &signature));
    }

    #[test]
    fn test_verify_fresh() {
        let signer = WebhookSigner::new("test_secret_key_123");
        let payload = b"test payload";
        let now = chrono::Utc::now().timestamp();

        let signature = signer.sign_with_timestamp(payload, now);
        assert!(signer.verify_fresh(payload, now, &signature, 300)); // 5 minute tolerance

        // Old timestamp should fail
        let old_timestamp = now - 600; // 10 minutes ago
        let old_signature = signer.sign_with_timestamp(payload, old_timestamp);
        assert!(!signer.verify_fresh(payload, old_timestamp, &old_signature, 300));
    }

    #[test]
    fn test_generate_secret() {
        let secret1 = generate_secret(32);
        let secret2 = generate_secret(32);

        assert_eq!(secret1.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "def"));
        assert!(!constant_time_compare("abc", "abcd"));
    }
}
