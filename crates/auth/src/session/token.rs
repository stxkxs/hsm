use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session token (opaque, securely generated)
///
/// The plaintext token is returned to the client once and zeroized on drop.
/// Only the hash is stored server-side.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken(String);

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionToken([REDACTED])")
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison for token equality
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for SessionToken {}

/// Hashed session token for secure storage.
///
/// Only the SHA-256 hash of the token is stored, never the plaintext.
/// This prevents token leakage if the session store is compromised.
#[derive(Debug, Clone)]
pub struct HashedToken([u8; 32]);

impl HashedToken {
    /// Create a hashed token from a plaintext token
    pub fn from_token(token: &SessionToken) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.0.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Self(hash)
    }

    /// Verify that a plaintext token matches this hash
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify(&self, token: &SessionToken) -> bool {
        let computed = Self::from_token(token);
        self.0.ct_eq(&computed.0).into()
    }
}

impl SessionToken {
    /// Create a new secure session token
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes);
        Self(hex::encode(token_bytes))
    }

    /// Get the token string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Create from string (for validation)
    pub fn from_string(s: String) -> Self {
        Self(s)
    }
}

impl Default for SessionToken {
    fn default() -> Self {
        Self::new()
    }
}
