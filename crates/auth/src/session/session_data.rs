use super::scope::{SessionScope, SessionTemplate};
use super::token::{HashedToken, SessionToken};
use super::{SessionId, TemplateId};
use crate::mtls::ClientIdentity;
use crate::rbac::Permission;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

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
/// - **Scoped Permissions**: Sessions can be restricted to specific operations/keys
/// - **Delegation**: Sessions can spawn child sessions with restricted permissions
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

    /// Session scope restrictions
    pub scope: Option<SessionScope>,

    /// Parent session ID (for delegated sessions)
    pub parent_session_id: Option<SessionId>,

    /// Delegation depth (0 = root session)
    pub delegation_depth: u32,

    /// Maximum delegation depth allowed
    pub max_delegation_depth: u32,

    /// Whether this session can create delegated sessions
    pub allow_delegation: bool,

    /// Template ID if created from a template
    pub template_id: Option<TemplateId>,
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
            scope: None,
            parent_session_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            allow_delegation: false,
            template_id: None,
        };

        SessionCreationResult { session, token }
    }

    /// Create a new session with a scope restriction
    pub fn create_with_scope(
        identity: ClientIdentity,
        ttl_seconds: i64,
        scope: SessionScope,
    ) -> SessionCreationResult {
        let result = Self::create(identity, ttl_seconds);
        let mut session = result.session;
        session.scope = Some(scope);
        SessionCreationResult {
            session,
            token: result.token,
        }
    }

    /// Create a session from a template
    pub fn create_from_template(
        identity: ClientIdentity,
        template: &SessionTemplate,
    ) -> SessionCreationResult {
        let result = Self::create(identity, template.default_ttl_seconds);
        let mut session = result.session;
        session.scope = Some(template.scope.clone());
        session.allow_delegation = template.allow_delegation;
        session.max_delegation_depth = template.max_delegation_depth;
        session.template_id = Some(template.id.clone());
        SessionCreationResult {
            session,
            token: result.token,
        }
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

    /// Check if an operation is allowed by this session's scope
    pub fn is_operation_allowed(&self, operation: &Permission) -> bool {
        match &self.scope {
            Some(scope) => scope.is_operation_allowed(operation),
            None => true,
        }
    }

    /// Check if a key is allowed by this session's scope
    pub fn is_key_allowed(&self, key_id: &str) -> bool {
        match &self.scope {
            Some(scope) => scope.is_key_allowed(key_id),
            None => true,
        }
    }

    /// Check if a namespace is allowed by this session's scope
    pub fn is_namespace_allowed(&self, namespace: &str) -> bool {
        match &self.scope {
            Some(scope) => scope.is_namespace_allowed(namespace),
            None => true,
        }
    }

    /// Check if this session can delegate to another
    pub fn can_delegate(&self) -> bool {
        self.allow_delegation && self.delegation_depth < self.max_delegation_depth
    }

    /// Get remaining delegation depth
    pub fn remaining_delegation_depth(&self) -> u32 {
        if !self.allow_delegation {
            return 0;
        }
        self.max_delegation_depth
            .saturating_sub(self.delegation_depth)
    }

    /// Check if max operations limit is reached
    pub fn is_operation_limit_reached(&self) -> bool {
        if let Some(scope) = &self.scope {
            if let Some(max_ops) = scope.max_operations {
                return self.operation_count >= max_ops;
            }
        }
        false
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
    pub(super) fn generate_session_id() -> SessionId {
        let mut session_id_bytes = [0u8; 32];
        getrandom::fill(&mut session_id_bytes)
            .expect("Failed to generate secure random bytes for session ID");

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
