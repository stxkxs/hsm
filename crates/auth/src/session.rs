use crate::error::{AuthError, Result};
use crate::mtls::ClientIdentity;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session ID type (cryptographically secure)
pub type SessionId = String;

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

/// Client session information with expiration and hijacking detection.
///
/// Sessions provide stateful authentication for clients after successful mTLS
/// authentication. Each session has a unique ID, associated client identity,
/// expiration timestamp, and optional metadata for security monitoring.
///
/// # Lifecycle
///
/// 1. **Creation**: Generated after successful mTLS authentication via `SessionManager::create_session()`
/// 2. **Active**: Session remains valid until expiration or explicit deletion
/// 3. **Validation**: Each request validates session via `SessionManager::validate_session()`
/// 4. **Expiration**: Session automatically expires after TTL or manual deletion
///
/// # Security Features
///
/// - **Cryptographically Secure IDs**: SHA-256 hashed random session IDs
/// - **Hijacking Detection**: Optional client IP and User-Agent tracking
/// - **Token Rotation**: Session tokens can be rotated for additional security
/// - **Automatic Expiration**: TTL-based expiration with last_accessed tracking
///
/// # Examples
///
/// ```rust
/// use hsm_auth::{Session, ClientIdentity, Role};
/// use chrono::Utc;
///
/// let identity = ClientIdentity::new(
///     "client-1".to_string(),
///     Some("Acme Corp".to_string()),
///     "default".to_string(),
///     vec![Role::User],
///     "serial-123".to_string(),
/// );
///
/// let result = Session::create(identity, 3600); // 1 hour TTL
///
/// assert!(result.session.is_valid());
/// assert!(!result.session.is_expired());
/// // result.token contains the plaintext token to send to the client
/// ```
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier
    pub id: SessionId,

    /// Client identity associated with this session
    pub identity: ClientIdentity,

    /// Session creation time
    pub created_at: DateTime<Utc>,

    /// Session last access time
    pub last_accessed: DateTime<Utc>,

    /// Session expiration time
    pub expires_at: DateTime<Utc>,

    /// Hashed session token (only hash is stored, never plaintext)
    pub token_hash: HashedToken,

    /// Number of operations performed in this session (for auto-rotation)
    pub operation_count: u64,

    /// TLS fingerprint (JA3) for hijacking detection
    pub tls_fingerprint: Option<String>,

    /// Session metadata for hijacking detection
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
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

/// Session creation result containing the session and the plaintext token.
///
/// The plaintext token is returned only once during session creation.
/// It should be sent to the client and never stored server-side.
pub struct SessionCreationResult {
    /// The session (with hashed token)
    pub session: Session,
    /// The plaintext token (returned to client once, then discarded)
    pub token: SessionToken,
}

impl Session {
    /// Create a new session with secure token
    ///
    /// Returns a SessionCreationResult containing the session (with hashed token)
    /// and the plaintext token to be sent to the client.
    pub fn create(identity: ClientIdentity, ttl_seconds: i64) -> SessionCreationResult {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds);
        let id = Self::generate_session_id();
        let token = SessionToken::new();
        let token_hash = HashedToken::from_token(&token);

        let session = Self {
            id,
            identity,
            created_at: now,
            last_accessed: now,
            expires_at,
            token_hash,
            operation_count: 0,
            tls_fingerprint: None,
            client_ip: None,
            user_agent: None,
        };

        SessionCreationResult { session, token }
    }

    /// Create a new session with metadata for hijacking detection
    pub fn new_with_metadata(
        identity: ClientIdentity,
        ttl_seconds: i64,
        client_ip: Option<String>,
        user_agent: Option<String>,
        tls_fingerprint: Option<String>,
    ) -> SessionCreationResult {
        let result = Self::create(identity, ttl_seconds);
        let mut session = result.session;
        session.client_ip = client_ip;
        session.user_agent = user_agent;
        session.tls_fingerprint = tls_fingerprint;
        SessionCreationResult {
            session,
            token: result.token,
        }
    }

    /// Verify a token against this session's stored hash
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_token(&self, token: &SessionToken) -> bool {
        self.token_hash.verify(token)
    }

    /// Increment operation count and check if rotation is needed
    pub fn increment_operation(&mut self) -> bool {
        self.operation_count += 1;
        // Recommend rotation after 1000 operations
        self.operation_count >= 1000
    }

    /// Generate a cryptographically secure session ID
    fn generate_session_id() -> SessionId {
        let mut rng = rand::thread_rng();
        let mut session_id_bytes = [0u8; 32];
        rng.fill(&mut session_id_bytes);

        // Hash for additional security
        let mut hasher = Sha256::new();
        hasher.update(session_id_bytes);
        hex::encode(hasher.finalize())
    }

    /// Rotate session token (for security)
    ///
    /// Returns the new plaintext token to be sent to the client.
    /// The old token is invalidated immediately.
    pub fn rotate_token(&mut self) -> SessionToken {
        let new_token = SessionToken::new();
        self.token_hash = HashedToken::from_token(&new_token);
        self.operation_count = 0; // Reset operation count after rotation
        metrics::counter!("auth.session.token_rotation").increment(1);
        new_token
    }

    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session is valid
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Update the last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
    }

    /// Extend the session expiration
    pub fn extend(&mut self, additional_seconds: i64) {
        self.expires_at += Duration::seconds(additional_seconds);
    }
}

/// Session manager for tracking active client sessions with lock-free concurrency.
///
/// Manages the lifecycle of client sessions including creation, validation,
/// extension, token rotation, and cleanup. Uses DashMap for lock-free concurrent
/// access to support high-throughput scenarios.
///
/// # Architecture
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │              SessionManager Architecture                     │
/// ├─────────────────────────────────────────────────────────────┤
/// │                                                               │
/// │  ┌─────────────────────────────────────────────────┐        │
/// │  │   DashMap<SessionId, Session>                   │        │
/// │  │   (Lock-free concurrent hash map)               │        │
/// │  ├─────────────────────────────────────────────────┤        │
/// │  │  session-abc123 → Session {                     │        │
/// │  │    id: "abc123",                                │        │
/// │  │    identity: ClientIdentity,                    │        │
/// │  │    created_at: 2024-01-15 10:00:00,             │        │
/// │  │    last_accessed: 2024-01-15 10:30:00,          │        │
/// │  │    expires_at: 2024-01-15 11:00:00,             │        │
/// │  │    token: SessionToken,                         │        │
/// │  │    client_ip: Some("192.168.1.100"),            │        │
/// │  │    user_agent: Some("HSM Client/1.0")           │        │
/// │  │  }                                               │        │
/// │  └─────────────────────────────────────────────────┘        │
/// │                                                               │
/// │  Operations (all lock-free):                                 │
/// │  • create_session()    - Insert new session                  │
/// │  • validate_session()  - Check expiry + update last_accessed │
/// │  • delete_session()    - Remove session                      │
/// │  • cleanup_expired()   - Batch remove expired sessions       │
/// │  • extend_session()    - Update expiration time              │
/// │  • rotate_token()      - Generate new session token          │
/// │                                                               │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// # Performance Characteristics
///
/// - **Session Lookup**: O(1), target <50μs
/// - **Concurrent Operations**: Lock-free, >10,000 sessions supported
/// - **Memory Overhead**: ~200 bytes per session
/// - **Cleanup Performance**: O(n) where n = total sessions
///
/// # Examples
///
/// ## Basic session management
///
/// ```rust
/// use hsm_auth::{SessionManager, ClientIdentity, Role};
///
/// let manager = SessionManager::new(3600); // 1 hour TTL
///
/// let identity = ClientIdentity::new(
///     "client-1".to_string(),
///     Some("Acme Corp".to_string()),
///     "default".to_string(),
///     vec![Role::User],
///     "serial-123".to_string(),
/// );
///
/// // Create session - returns session + plaintext token
/// let result = manager.create_session(identity);
/// // result.token should be returned to client (send only once!)
///
/// // Later: validate session by ID
/// let validated = manager.validate_session(&result.session.id).unwrap();
/// assert_eq!(validated.id, result.session.id);
///
/// // Or validate with token (more secure)
/// let validated = manager.validate_session_with_token(&result.session.id, &result.token).unwrap();
///
/// // Extend session lifetime
/// manager.extend_session(&result.session.id, 1800).unwrap(); // +30 minutes
///
/// // Delete when done
/// manager.delete_session(&result.session.id).unwrap();
/// ```
///
/// ## Session hijacking detection
///
/// ```rust
/// use hsm_auth::{SessionManager, ClientIdentity, Role};
///
/// let manager = SessionManager::new(3600);
///
/// # let identity = ClientIdentity::new(
/// #     "client-1".to_string(),
/// #     Some("Acme Corp".to_string()),
/// #     "default".to_string(),
/// #     vec![Role::User],
/// #     "serial-123".to_string(),
/// # );
///
/// // Create session with metadata (including TLS fingerprint)
/// let result = manager.create_session_with_metadata(
///     identity,
///     Some("192.168.1.100".to_string()),
///     Some("HSM Client/1.0".to_string()),
///     None, // TLS fingerprint (JA3)
/// );
///
/// // Validate with IP check (detects hijacking)
/// let validated = manager.validate_session_with_metadata(
///     &result.session.id,
///     &result.token,
///     Some("192.168.1.100".to_string()), // Same IP = OK
///     Some("HSM Client/1.0".to_string()),
///     None,
/// );
/// assert!(validated.is_ok());
///
/// // Different IP would fail with hijacking error
/// let rejected = manager.validate_session_with_metadata(
///     &result.session.id,
///     &result.token,
///     Some("10.0.0.1".to_string()), // Different IP = Hijacking!
///     None,
///     None,
/// );
/// assert!(rejected.is_err()); // Returns InvalidSession error
/// ```
///
/// ## Periodic cleanup
///
/// ```rust
/// use hsm_auth::SessionManager;
/// use std::time::Duration;
///
/// let manager = SessionManager::new(60); // 1 minute TTL
///
/// // In production: run cleanup periodically
/// // tokio::spawn(async move {
/// //     let mut interval = tokio::time::interval(Duration::from_secs(60));
/// //     loop {
/// //         interval.tick().await;
/// //         let removed = manager.cleanup_expired();
/// //         println!("Cleaned up {} expired sessions", removed);
/// //     }
/// // });
/// ```
///
/// # Thread Safety
///
/// All methods are thread-safe and use lock-free operations via DashMap.
/// Multiple threads can safely create, validate, and delete sessions concurrently.
pub struct SessionManager {
    /// DashMap for concurrent session access (target: < 50μs lookup)
    sessions: Arc<DashMap<SessionId, Session>>,
    /// Legacy sessions for backward compatibility
    #[allow(dead_code)]
    legacy_sessions: Arc<RwLock<HashMap<SessionId, Session>>>,
    default_ttl: i64,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(default_ttl_seconds: i64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            legacy_sessions: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: default_ttl_seconds,
        }
    }

    /// Create a new session for a client (lock-free, concurrent)
    ///
    /// Returns the session ID and the plaintext token. The token should be
    /// returned to the client once and never stored server-side.
    pub fn create_session(&self, identity: ClientIdentity) -> SessionCreationResult {
        let result = Session::create(identity, self.default_ttl);
        self.sessions
            .insert(result.session.id.clone(), result.session.clone());
        metrics::counter!("auth.session.created").increment(1);
        result
    }

    /// Create a session with metadata for hijacking detection
    ///
    /// Returns the session ID and the plaintext token. The token should be
    /// returned to the client once and never stored server-side.
    pub fn create_session_with_metadata(
        &self,
        identity: ClientIdentity,
        client_ip: Option<String>,
        user_agent: Option<String>,
        tls_fingerprint: Option<String>,
    ) -> SessionCreationResult {
        let result = Session::new_with_metadata(
            identity,
            self.default_ttl,
            client_ip,
            user_agent,
            tls_fingerprint,
        );
        self.sessions
            .insert(result.session.id.clone(), result.session.clone());
        metrics::counter!("auth.session.created").increment(1);
        result
    }

    /// Get a session by ID (lock-free read)
    pub fn get_session(&self, session_id: &str) -> Result<Session> {
        self.sessions
            .get(session_id)
            .map(|s| s.clone())
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))
    }

    /// Validate and get a session
    pub fn validate_session(&self, session_id: &str) -> Result<Session> {
        let mut session_ref = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        if session_ref.is_expired() {
            metrics::counter!("auth.session.expired").increment(1);
            return Err(AuthError::SessionExpired);
        }

        session_ref.touch();
        metrics::counter!("auth.session.validated").increment(1);
        Ok(session_ref.clone())
    }

    /// Validate session with token verification
    ///
    /// This method validates the session by checking both the session ID and token.
    /// Uses constant-time token comparison to prevent timing attacks.
    pub fn validate_session_with_token(
        &self,
        session_id: &str,
        token: &SessionToken,
    ) -> Result<Session> {
        let mut session_ref = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        if session_ref.is_expired() {
            metrics::counter!("auth.session.expired").increment(1);
            return Err(AuthError::SessionExpired);
        }

        // Verify token with constant-time comparison
        if !session_ref.verify_token(token) {
            metrics::counter!("auth.session.invalid_token").increment(1);
            return Err(AuthError::InvalidSession("Invalid session token".to_string()));
        }

        // Check if token rotation is recommended
        let needs_rotation = session_ref.increment_operation();
        if needs_rotation {
            metrics::counter!("auth.session.rotation_recommended").increment(1);
        }

        session_ref.touch();
        metrics::counter!("auth.session.validated").increment(1);
        Ok(session_ref.clone())
    }

    /// Validate session with hijacking detection (IP, User-Agent, TLS fingerprint)
    pub fn validate_session_with_metadata(
        &self,
        session_id: &str,
        token: &SessionToken,
        client_ip: Option<String>,
        user_agent: Option<String>,
        tls_fingerprint: Option<String>,
    ) -> Result<Session> {
        let session_ref = self
            .sessions
            .get(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        if session_ref.is_expired() {
            metrics::counter!("auth.session.expired").increment(1);
            return Err(AuthError::SessionExpired);
        }

        // Verify token first with constant-time comparison
        if !session_ref.verify_token(token) {
            metrics::counter!("auth.session.invalid_token").increment(1);
            return Err(AuthError::InvalidSession("Invalid session token".to_string()));
        }

        // Session hijacking detection: IP check
        if let Some(ref stored_ip) = session_ref.client_ip {
            if let Some(ref current_ip) = client_ip {
                if stored_ip != current_ip {
                    metrics::counter!("auth.session.hijacking_ip_mismatch").increment(1);
                    return Err(AuthError::InvalidSession(
                        "Session validation failed".to_string(), // Generic message for security
                    ));
                }
            }
        }

        // Session hijacking detection: User-Agent check
        if let Some(ref stored_ua) = session_ref.user_agent {
            if let Some(ref current_ua) = user_agent {
                if stored_ua != current_ua {
                    metrics::counter!("auth.session.hijacking_ua_mismatch").increment(1);
                    return Err(AuthError::InvalidSession(
                        "Session validation failed".to_string(), // Generic message for security
                    ));
                }
            }
        }

        // Session hijacking detection: TLS fingerprint (JA3) check
        if let Some(ref stored_fp) = session_ref.tls_fingerprint {
            if let Some(ref current_fp) = tls_fingerprint {
                if stored_fp != current_fp {
                    metrics::counter!("auth.session.hijacking_tls_mismatch").increment(1);
                    return Err(AuthError::InvalidSession(
                        "Session validation failed".to_string(), // Generic message for security
                    ));
                }
            }
        }

        drop(session_ref);

        // Touch the session and increment operation count
        let mut session_mut = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;
        let needs_rotation = session_mut.increment_operation();
        if needs_rotation {
            metrics::counter!("auth.session.rotation_recommended").increment(1);
        }
        session_mut.touch();
        metrics::counter!("auth.session.validated").increment(1);
        Ok(session_mut.clone())
    }

    /// Delete a session
    pub fn delete_session(&self, session_id: &str) -> Result<()> {
        self.sessions
            .remove(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;
        metrics::counter!("auth.session.deleted").increment(1);
        Ok(())
    }

    /// Extend a session's expiration
    pub fn extend_session(&self, session_id: &str, additional_seconds: i64) -> Result<()> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        session.extend(additional_seconds);
        Ok(())
    }

    /// Rotate session token for security
    ///
    /// Returns the new plaintext token to be sent to the client.
    /// The old token is invalidated immediately. Rotation should occur:
    /// - After N operations (recommended: 1000)
    /// - When client permissions change
    /// - Periodically for long-lived sessions
    pub fn rotate_session_token(&self, session_id: &str) -> Result<SessionToken> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        let new_token = session.rotate_token();
        Ok(new_token)
    }

    /// Force rotate tokens for a client when their permissions change
    ///
    /// This invalidates all existing tokens for the client and returns
    /// new tokens that must be distributed to the client.
    pub fn rotate_client_tokens(&self, client_cn: &str) -> Vec<(SessionId, SessionToken)> {
        let mut results = Vec::new();

        for mut entry in self.sessions.iter_mut() {
            if entry.identity.common_name == client_cn {
                let new_token = entry.rotate_token();
                results.push((entry.id.clone(), new_token));
            }
        }

        metrics::counter!("auth.session.permission_rotation").increment(results.len() as u64);
        results
    }

    /// Clean up expired sessions (concurrent-safe)
    pub fn cleanup_expired(&self) -> usize {
        let initial_count = self.sessions.len();
        self.sessions.retain(|_, session| session.is_valid());
        let removed = initial_count - self.sessions.len();
        metrics::counter!("auth.session.cleanup").increment(removed as u64);
        removed
    }

    /// Get all active sessions
    pub fn get_active_sessions(&self) -> Vec<Session> {
        self.sessions
            .iter()
            .filter(|s| s.is_valid())
            .map(|s| s.clone())
            .collect()
    }

    /// Get sessions for a specific client
    pub fn get_client_sessions(&self, client_cn: &str) -> Vec<Session> {
        self.sessions
            .iter()
            .filter(|s| s.identity.common_name == client_cn && s.is_valid())
            .map(|s| s.clone())
            .collect()
    }

    /// Get the number of active sessions
    pub fn active_session_count(&self) -> usize {
        self.sessions.iter().filter(|s| s.is_valid()).count()
    }

    /// Delete all sessions for a client
    pub fn delete_client_sessions(&self, client_cn: &str) -> usize {
        let initial_count = self.sessions.len();
        self.sessions
            .retain(|_, s| s.identity.common_name != client_cn);
        initial_count - self.sessions.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        // Default TTL: 1 hour
        Self::new(3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::Role;

    fn create_test_identity(cn: &str) -> ClientIdentity {
        ClientIdentity::new(
            cn.to_string(),
            None,
            "default".to_string(),
            vec![Role::User],
            "123456".to_string(),
        )
    }

    #[test]
    fn test_create_session() {
        let identity = create_test_identity("client1");
        let result = Session::create(identity.clone(), 3600);

        assert_eq!(result.session.identity.common_name, "client1");
        assert!(result.session.is_valid());
        assert!(!result.session.is_expired());
    }

    #[test]
    fn test_session_token_verification() {
        let identity = create_test_identity("client1");
        let result = Session::create(identity, 3600);

        // Token should verify against the session
        assert!(result.session.verify_token(&result.token));

        // Wrong token should not verify
        let wrong_token = SessionToken::new();
        assert!(!result.session.verify_token(&wrong_token));
    }

    #[test]
    fn test_hashed_token_constant_time() {
        let token = SessionToken::new();
        let hash = HashedToken::from_token(&token);

        // Same token should verify
        assert!(hash.verify(&token));

        // Different token should not verify
        let other_token = SessionToken::new();
        assert!(!hash.verify(&other_token));
    }

    #[test]
    fn test_session_expiration() {
        let identity = create_test_identity("client1");
        let result = Session::create(identity, -1); // Already expired
        let mut session = result.session;

        assert!(!session.is_valid());
        assert!(session.is_expired());

        // Extend the session
        session.extend(3600);
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_manager_create() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        assert!(manager.get_session(&result.session.id).is_ok());
    }

    #[test]
    fn test_session_manager_validate_with_token() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        // Should validate with correct token
        assert!(manager
            .validate_session_with_token(&result.session.id, &result.token)
            .is_ok());

        // Should fail with wrong token
        let wrong_token = SessionToken::new();
        assert!(manager
            .validate_session_with_token(&result.session.id, &wrong_token)
            .is_err());

        // Should fail with wrong session ID
        assert!(manager
            .validate_session_with_token("invalid-id", &result.token)
            .is_err());
    }

    #[test]
    fn test_session_manager_validate() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        assert!(manager.validate_session(&result.session.id).is_ok());
        assert!(manager.validate_session("invalid-id").is_err());
    }

    #[test]
    fn test_session_manager_delete() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        assert!(manager.delete_session(&result.session.id).is_ok());
        assert!(manager.get_session(&result.session.id).is_err());
    }

    #[test]
    fn test_session_manager_extend() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        let original_expires = result.session.expires_at;
        manager
            .extend_session(&result.session.id, 1800)
            .expect("extend should succeed");

        let updated = manager
            .get_session(&result.session.id)
            .expect("session should exist");
        assert!(updated.expires_at > original_expires);
    }

    #[test]
    fn test_token_rotation() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session(identity);

        // Original token should work
        assert!(manager
            .validate_session_with_token(&result.session.id, &result.token)
            .is_ok());

        // Rotate the token
        let new_token = manager
            .rotate_session_token(&result.session.id)
            .expect("rotation should succeed");

        // Old token should no longer work
        assert!(manager
            .validate_session_with_token(&result.session.id, &result.token)
            .is_err());

        // New token should work
        assert!(manager
            .validate_session_with_token(&result.session.id, &new_token)
            .is_ok());
    }

    #[test]
    fn test_operation_count_for_rotation() {
        let identity = create_test_identity("client1");
        let result = Session::create(identity, 3600);
        let mut session = result.session;

        // Operation count starts at 0
        assert_eq!(session.operation_count, 0);

        // Should not recommend rotation initially
        for _ in 0..999 {
            assert!(!session.increment_operation());
        }

        // Should recommend rotation at 1000 operations
        assert!(session.increment_operation());
    }

    #[test]
    fn test_cleanup_expired() {
        let manager = SessionManager::new(-1); // Create expired sessions
        let identity1 = create_test_identity("client1");
        let identity2 = create_test_identity("client2");

        manager.create_session(identity1);
        manager.create_session(identity2);

        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 2);
        assert_eq!(manager.active_session_count(), 0);
    }

    #[test]
    fn test_get_client_sessions() {
        let manager = SessionManager::new(3600);
        let identity1 = create_test_identity("client1");
        let identity2 = create_test_identity("client2");

        manager.create_session(identity1.clone());
        manager.create_session(identity1.clone());
        manager.create_session(identity2);

        let client1_sessions = manager.get_client_sessions("client1");
        assert_eq!(client1_sessions.len(), 2);

        let client2_sessions = manager.get_client_sessions("client2");
        assert_eq!(client2_sessions.len(), 1);
    }

    #[test]
    fn test_delete_client_sessions() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        manager.create_session(identity.clone());
        manager.create_session(identity.clone());

        let deleted = manager.delete_client_sessions("client1");
        assert_eq!(deleted, 2);
        assert_eq!(manager.get_client_sessions("client1").len(), 0);
    }

    #[test]
    fn test_active_session_count() {
        let manager = SessionManager::new(3600);
        assert_eq!(manager.active_session_count(), 0);

        let identity = create_test_identity("client1");
        manager.create_session(identity);
        assert_eq!(manager.active_session_count(), 1);
    }

    #[test]
    fn test_rotate_client_tokens() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        let result1 = manager.create_session(identity.clone());
        let result2 = manager.create_session(identity.clone());

        // Rotate all tokens for client1
        let rotated = manager.rotate_client_tokens("client1");
        assert_eq!(rotated.len(), 2);

        // Old tokens should no longer work
        assert!(manager
            .validate_session_with_token(&result1.session.id, &result1.token)
            .is_err());
        assert!(manager
            .validate_session_with_token(&result2.session.id, &result2.token)
            .is_err());

        // New tokens should work
        for (session_id, new_token) in rotated {
            assert!(manager
                .validate_session_with_token(&session_id, &new_token)
                .is_ok());
        }
    }

    #[test]
    fn test_hijacking_detection_ip() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let result = manager.create_session_with_metadata(
            identity,
            Some("192.168.1.100".to_string()),
            Some("TestClient/1.0".to_string()),
            None,
        );

        // Same IP should work
        assert!(manager
            .validate_session_with_metadata(
                &result.session.id,
                &result.token,
                Some("192.168.1.100".to_string()),
                Some("TestClient/1.0".to_string()),
                None,
            )
            .is_ok());

        // Different IP should fail (hijacking detection)
        assert!(manager
            .validate_session_with_metadata(
                &result.session.id,
                &result.token,
                Some("10.0.0.1".to_string()),
                Some("TestClient/1.0".to_string()),
                None,
            )
            .is_err());
    }

    #[test]
    fn test_session_token_debug_redacts() {
        let token = SessionToken::new();
        let debug_output = format!("{:?}", token);
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains(token.as_str()));
    }
}
