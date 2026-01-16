use crate::error::{AuthError, Result};
use crate::mtls::ClientIdentity;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Session ID type (cryptographically secure)
pub type SessionId = String;

/// Session token (opaque, hashed)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken(String);

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
/// let session = Session::new(identity, 3600); // 1 hour TTL
///
/// assert!(session.is_valid());
/// assert!(!session.is_expired());
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

    /// Session token (for rotation)
    pub token: SessionToken,

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

impl Session {
    /// Create a new session with secure token
    pub fn new(identity: ClientIdentity, ttl_seconds: i64) -> Self {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds);
        let id = Self::generate_session_id();
        let token = SessionToken::new();

        Self {
            id,
            identity,
            created_at: now,
            last_accessed: now,
            expires_at,
            token,
            client_ip: None,
            user_agent: None,
        }
    }

    /// Create a new session with metadata for hijacking detection
    pub fn new_with_metadata(
        identity: ClientIdentity,
        ttl_seconds: i64,
        client_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        let mut session = Self::new(identity, ttl_seconds);
        session.client_ip = client_ip;
        session.user_agent = user_agent;
        session
    }

    /// Generate a cryptographically secure session ID
    fn generate_session_id() -> SessionId {
        let mut rng = rand::thread_rng();
        let mut session_id_bytes = [0u8; 32];
        rng.fill(&mut session_id_bytes);

        // Hash for additional security
        let mut hasher = Sha256::new();
        hasher.update(&session_id_bytes);
        hex::encode(hasher.finalize())
    }

    /// Rotate session token (for security)
    pub fn rotate_token(&mut self) {
        self.token = SessionToken::new();
        metrics::counter!("auth.session.token_rotation").increment(1);
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
        self.expires_at = self.expires_at + Duration::seconds(additional_seconds);
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
/// // Create session
/// let session = manager.create_session(identity);
///
/// // Later: validate session
/// let validated = manager.validate_session(&session.id).unwrap();
/// assert_eq!(validated.id, session.id);
///
/// // Extend session lifetime
/// manager.extend_session(&session.id, 1800).unwrap(); // +30 minutes
///
/// // Delete when done
/// manager.delete_session(&session.id).unwrap();
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
/// // Create session with metadata
/// let session = manager.create_session_with_metadata(
///     identity,
///     Some("192.168.1.100".to_string()),
///     Some("HSM Client/1.0".to_string()),
/// );
///
/// // Validate with IP check (detects hijacking)
/// let result = manager.validate_session_with_metadata(
///     &session.id,
///     Some("192.168.1.100".to_string()), // Same IP = OK
///     Some("HSM Client/1.0".to_string()),
/// );
/// assert!(result.is_ok());
///
/// // Different IP would fail with hijacking error
/// let result = manager.validate_session_with_metadata(
///     &session.id,
///     Some("10.0.0.1".to_string()), // Different IP = Hijacking!
///     None,
/// );
/// assert!(result.is_err()); // Returns InvalidSession error
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
    pub fn create_session(&self, identity: ClientIdentity) -> Session {
        let session = Session::new(identity, self.default_ttl);
        self.sessions.insert(session.id.clone(), session.clone());
        metrics::counter!("auth.session.created").increment(1);
        session
    }

    /// Create a session with metadata for hijacking detection
    pub fn create_session_with_metadata(
        &self,
        identity: ClientIdentity,
        client_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Session {
        let session = Session::new_with_metadata(identity, self.default_ttl, client_ip, user_agent);
        self.sessions.insert(session.id.clone(), session.clone());
        metrics::counter!("auth.session.created").increment(1);
        session
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

    /// Validate session with hijacking detection
    pub fn validate_session_with_metadata(
        &self,
        session_id: &str,
        client_ip: Option<String>,
        _user_agent: Option<String>,
    ) -> Result<Session> {
        let session_ref = self
            .sessions
            .get(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        if session_ref.is_expired() {
            metrics::counter!("auth.session.expired").increment(1);
            return Err(AuthError::SessionExpired);
        }

        // Session hijacking detection
        if let Some(ref stored_ip) = session_ref.client_ip {
            if let Some(ref current_ip) = client_ip {
                if stored_ip != current_ip {
                    metrics::counter!("auth.session.hijacking_attempt").increment(1);
                    return Err(AuthError::InvalidSession(
                        "Session hijacking detected: IP mismatch".to_string(),
                    ));
                }
            }
        }

        drop(session_ref);

        // Touch the session
        let mut session_mut = self.sessions.get_mut(session_id).unwrap();
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
    pub fn rotate_session_token(&self, session_id: &str) -> Result<SessionToken> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        session.rotate_token();
        Ok(session.token.clone())
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
        let session = Session::new(identity.clone(), 3600);

        assert_eq!(session.identity.common_name, "client1");
        assert!(session.is_valid());
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expiration() {
        let identity = create_test_identity("client1");
        let mut session = Session::new(identity, -1); // Already expired

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
        let session = manager.create_session(identity);

        assert!(manager.get_session(&session.id).is_ok());
    }

    #[test]
    fn test_session_manager_validate() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let session = manager.create_session(identity);

        assert!(manager.validate_session(&session.id).is_ok());
        assert!(manager.validate_session("invalid-id").is_err());
    }

    #[test]
    fn test_session_manager_delete() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let session = manager.create_session(identity);

        assert!(manager.delete_session(&session.id).is_ok());
        assert!(manager.get_session(&session.id).is_err());
    }

    #[test]
    fn test_session_manager_extend() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");
        let session = manager.create_session(identity);

        let original_expires = session.expires_at;
        manager.extend_session(&session.id, 1800).unwrap();

        let updated = manager.get_session(&session.id).unwrap();
        assert!(updated.expires_at > original_expires);
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
}
