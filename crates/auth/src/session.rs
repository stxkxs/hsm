use crate::error::{AuthError, Result};
use crate::mtls::ClientIdentity;
use crate::rbac::Permission;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session ID type (cryptographically secure)
pub type SessionId = String;

/// Template ID type
pub type TemplateId = String;

/// Session scope for restricting session capabilities
///
/// Scopes allow creating sessions with limited permissions, key access,
/// operation counts, or rate limits. This is essential for:
/// - Principle of least privilege
/// - Temporary elevated access
/// - Delegated sessions with restricted capabilities
///
/// # Examples
///
/// ```rust
/// use hsm_auth::session::SessionScope;
/// use hsm_auth::rbac::Permission;
///
/// // Create a scope that only allows signing with specific keys
/// let scope = SessionScope::new()
///     .with_operations(vec![Permission::Sign, Permission::Encrypt])
///     .with_keys(vec!["key-1".to_string(), "key-2".to_string()])
///     .with_max_operations(100)
///     .with_rate_limit(10);
///
/// assert!(scope.is_operation_allowed(&Permission::Sign));
/// assert!(!scope.is_operation_allowed(&Permission::DeleteKey));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionScope {
    /// Allowed operations (None = all operations allowed)
    pub allowed_operations: Option<Vec<Permission>>,
    /// Allowed keys (None = all keys allowed)
    pub allowed_keys: Option<Vec<String>>,
    /// Maximum number of operations before session expires
    pub max_operations: Option<u64>,
    /// Rate limit (operations per second)
    pub rate_limit: Option<u32>,
    /// Allowed namespaces (None = inherit from identity)
    pub allowed_namespaces: Option<Vec<String>>,
}

impl Default for SessionScope {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionScope {
    /// Create an unrestricted scope
    pub fn new() -> Self {
        Self {
            allowed_operations: None,
            allowed_keys: None,
            max_operations: None,
            rate_limit: None,
            allowed_namespaces: None,
        }
    }

    /// Create a scope with specific operations
    pub fn with_operations(mut self, operations: Vec<Permission>) -> Self {
        self.allowed_operations = Some(operations);
        self
    }

    /// Create a scope with specific keys
    pub fn with_keys(mut self, keys: Vec<String>) -> Self {
        self.allowed_keys = Some(keys);
        self
    }

    /// Set maximum operations
    pub fn with_max_operations(mut self, max: u64) -> Self {
        self.max_operations = Some(max);
        self
    }

    /// Set rate limit
    pub fn with_rate_limit(mut self, ops_per_second: u32) -> Self {
        self.rate_limit = Some(ops_per_second);
        self
    }

    /// Set allowed namespaces
    pub fn with_namespaces(mut self, namespaces: Vec<String>) -> Self {
        self.allowed_namespaces = Some(namespaces);
        self
    }

    /// Check if an operation is allowed
    pub fn is_operation_allowed(&self, operation: &Permission) -> bool {
        match &self.allowed_operations {
            Some(ops) => ops.contains(operation),
            None => true, // All operations allowed if not restricted
        }
    }

    /// Check if a key is allowed
    pub fn is_key_allowed(&self, key_id: &str) -> bool {
        match &self.allowed_keys {
            Some(keys) => keys.iter().any(|k| k == key_id),
            None => true, // All keys allowed if not restricted
        }
    }

    /// Check if a namespace is allowed
    pub fn is_namespace_allowed(&self, namespace: &str) -> bool {
        match &self.allowed_namespaces {
            Some(ns) => ns.iter().any(|n| n == namespace),
            None => true, // All namespaces allowed if not restricted
        }
    }

    /// Check if this scope is more restrictive than another
    /// (can only grant subset of parent's permissions)
    pub fn is_subset_of(&self, parent: &SessionScope) -> bool {
        // Check operations
        if let Some(child_ops) = &self.allowed_operations {
            if let Some(parent_ops) = &parent.allowed_operations {
                if !child_ops.iter().all(|op| parent_ops.contains(op)) {
                    return false;
                }
            }
        }

        // Check keys
        if let Some(child_keys) = &self.allowed_keys {
            if let Some(parent_keys) = &parent.allowed_keys {
                let parent_set: HashSet<_> = parent_keys.iter().collect();
                if !child_keys.iter().all(|k| parent_set.contains(k)) {
                    return false;
                }
            }
        }

        // Check max operations (child must be <= parent)
        if let Some(child_max) = self.max_operations {
            if let Some(parent_max) = parent.max_operations {
                if child_max > parent_max {
                    return false;
                }
            }
        }

        // Check rate limit (child must be <= parent)
        if let Some(child_rate) = self.rate_limit {
            if let Some(parent_rate) = parent.rate_limit {
                if child_rate > parent_rate {
                    return false;
                }
            }
        }

        true
    }

    /// Merge two scopes, taking the most restrictive combination
    pub fn intersect(&self, other: &SessionScope) -> SessionScope {
        SessionScope {
            allowed_operations: match (&self.allowed_operations, &other.allowed_operations) {
                (Some(a), Some(b)) => {
                    let set_b: HashSet<_> = b.iter().collect();
                    Some(a.iter().filter(|op| set_b.contains(op)).cloned().collect())
                }
                (Some(a), None) => Some(a.clone()),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            },
            allowed_keys: match (&self.allowed_keys, &other.allowed_keys) {
                (Some(a), Some(b)) => {
                    let set_b: HashSet<_> = b.iter().collect();
                    Some(a.iter().filter(|k| set_b.contains(k)).cloned().collect())
                }
                (Some(a), None) => Some(a.clone()),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            },
            max_operations: match (self.max_operations, other.max_operations) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            rate_limit: match (self.rate_limit, other.rate_limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            allowed_namespaces: match (&self.allowed_namespaces, &other.allowed_namespaces) {
                (Some(a), Some(b)) => {
                    let set_b: HashSet<_> = b.iter().collect();
                    Some(a.iter().filter(|n| set_b.contains(n)).cloned().collect())
                }
                (Some(a), None) => Some(a.clone()),
                (None, Some(b)) => Some(b.clone()),
                (None, None) => None,
            },
        }
    }
}

/// Session template for creating sessions with predefined configurations
///
/// Templates allow administrators to define reusable session configurations
/// that can be quickly applied. This is useful for:
/// - Standard session types (e.g., "signing-only", "backup-admin")
/// - Enforcing organization-wide session policies
/// - Quick session provisioning
///
/// # Examples
///
/// ```rust
/// use hsm_auth::session::{SessionTemplate, SessionScope};
/// use hsm_auth::rbac::Permission;
///
/// // Create a template for signing-only sessions
/// let template = SessionTemplate::new("signing-only", "Signing Only")
///     .with_scope(
///         SessionScope::new()
///             .with_operations(vec![Permission::Sign])
///             .with_rate_limit(100)
///     )
///     .with_ttl(3600); // 1 hour
///
/// assert_eq!(template.name, "Signing Only");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTemplate {
    /// Unique template identifier
    pub id: TemplateId,
    /// Human-readable name
    pub name: String,
    /// Description of the template
    pub description: Option<String>,
    /// Session scope restrictions
    pub scope: SessionScope,
    /// Default TTL in seconds
    pub default_ttl_seconds: i64,
    /// Whether sessions created from this template can be delegated
    pub allow_delegation: bool,
    /// Maximum delegation depth (0 = no delegation)
    pub max_delegation_depth: u32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,
}

impl SessionTemplate {
    /// Create a new session template
    pub fn new(id: &str, name: &str) -> Self {
        let now = Utc::now();
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: None,
            scope: SessionScope::new(),
            default_ttl_seconds: 3600, // 1 hour default
            allow_delegation: false,
            max_delegation_depth: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the scope
    pub fn with_scope(mut self, scope: SessionScope) -> Self {
        self.scope = scope;
        self.updated_at = Utc::now();
        self
    }

    /// Set the TTL
    pub fn with_ttl(mut self, ttl_seconds: i64) -> Self {
        self.default_ttl_seconds = ttl_seconds;
        self.updated_at = Utc::now();
        self
    }

    /// Set description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self.updated_at = Utc::now();
        self
    }

    /// Enable delegation
    pub fn with_delegation(mut self, max_depth: u32) -> Self {
        self.allow_delegation = max_depth > 0;
        self.max_delegation_depth = max_depth;
        self.updated_at = Utc::now();
        self
    }
}

/// Rate limiter state for a session
#[derive(Debug)]
pub struct RateLimiterState {
    /// Operations in current window
    operations: AtomicU64,
    /// Window start time
    window_start: RwLock<DateTime<Utc>>,
    /// Operations per second limit
    limit: u32,
}

impl RateLimiterState {
    /// Create a new rate limiter
    pub fn new(limit: u32) -> Self {
        Self {
            operations: AtomicU64::new(0),
            window_start: RwLock::new(Utc::now()),
            limit,
        }
    }

    /// Check and increment rate limiter
    /// Returns Ok(()) if allowed, Err if rate limited
    pub fn check_and_increment(&self) -> std::result::Result<(), &'static str> {
        let now = Utc::now();
        let mut window_start = self.window_start.write();

        // Reset window if more than 1 second has passed
        if now.signed_duration_since(*window_start).num_seconds() >= 1 {
            *window_start = now;
            self.operations.store(1, Ordering::SeqCst);
            return Ok(());
        }

        // Check if within limit
        let current = self.operations.fetch_add(1, Ordering::SeqCst);
        if current >= self.limit as u64 {
            self.operations.fetch_sub(1, Ordering::SeqCst);
            return Err("Rate limit exceeded");
        }

        Ok(())
    }

    /// Get current operation count in window
    pub fn current_count(&self) -> u64 {
        self.operations.load(Ordering::SeqCst)
    }
}

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

    /// Session scope restrictions (CubeSigner compatibility)
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
/// │  │    scope: Some(SessionScope),                   │        │
/// │  │    client_ip: Some("192.168.1.100"),            │        │
/// │  │    user_agent: Some("HSM Client/1.0")           │        │
/// │  │  }                                               │        │
/// │  └─────────────────────────────────────────────────┘        │
/// │                                                               │
/// │  ┌─────────────────────────────────────────────────┐        │
/// │  │   DashMap<TemplateId, SessionTemplate>          │        │
/// │  │   (Session templates for quick provisioning)    │        │
/// │  └─────────────────────────────────────────────────┘        │
/// │                                                               │
/// │  Operations (all lock-free):                                 │
/// │  • create_session()         - Insert new session             │
/// │  • create_scoped_session()  - Session with restrictions      │
/// │  • create_from_template()   - Session from template          │
/// │  • delegate_session()       - Create child session           │
/// │  • validate_session()       - Check expiry + scope           │
/// │  • delete_session()         - Remove session                 │
/// │  • cleanup_expired()        - Batch remove expired sessions  │
/// │  • extend_session()         - Update expiration time         │
/// │  • rotate_token()           - Generate new session token     │
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
    /// Session templates
    templates: Arc<DashMap<TemplateId, SessionTemplate>>,
    /// Rate limiters per session (only created for rate-limited sessions)
    rate_limiters: Arc<DashMap<SessionId, Arc<RateLimiterState>>>,
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
            templates: Arc::new(DashMap::new()),
            rate_limiters: Arc::new(DashMap::new()),
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

    /// Create a scoped session with restricted permissions (CubeSigner compatibility)
    ///
    /// Scoped sessions are restricted to specific operations, keys, or have
    /// operation limits. This is essential for:
    /// - Principle of least privilege
    /// - Temporary elevated access
    /// - Rate-limited API access
    pub fn create_scoped_session(
        &self,
        identity: ClientIdentity,
        scope: SessionScope,
        ttl_seconds: Option<i64>,
    ) -> SessionCreationResult {
        let ttl = ttl_seconds.unwrap_or(self.default_ttl);
        let result = Session::create_with_scope(identity, ttl, scope.clone());

        // Set up rate limiter if configured
        if let Some(rate_limit) = scope.rate_limit {
            self.rate_limiters.insert(
                result.session.id.clone(),
                Arc::new(RateLimiterState::new(rate_limit)),
            );
        }

        self.sessions
            .insert(result.session.id.clone(), result.session.clone());
        metrics::counter!("auth.session.created").increment(1);
        metrics::counter!("auth.session.scoped").increment(1);
        result
    }

    /// Create a session from a template
    ///
    /// Templates provide reusable session configurations for quick provisioning.
    pub fn create_session_from_template(
        &self,
        identity: ClientIdentity,
        template_id: &str,
    ) -> Result<SessionCreationResult> {
        let template = self.templates.get(template_id).ok_or_else(|| {
            AuthError::InvalidSession(format!("Template not found: {}", template_id))
        })?;

        let result = Session::create_from_template(identity, &template);

        // Set up rate limiter if configured
        if let Some(rate_limit) = template.scope.rate_limit {
            self.rate_limiters.insert(
                result.session.id.clone(),
                Arc::new(RateLimiterState::new(rate_limit)),
            );
        }

        self.sessions
            .insert(result.session.id.clone(), result.session.clone());
        metrics::counter!("auth.session.created").increment(1);
        metrics::counter!("auth.session.from_template").increment(1);
        Ok(result)
    }

    /// Delegate a session to create a child session with restricted permissions
    ///
    /// Delegation allows creating child sessions with equal or more restrictive
    /// permissions than the parent. This is useful for:
    /// - Temporary access grants
    /// - Service-to-service authentication
    /// - Limited-scope API tokens
    ///
    /// # Arguments
    /// * `parent_session_id` - The session to delegate from
    /// * `restricted_scope` - Additional restrictions (must be subset of parent)
    /// * `ttl_seconds` - TTL for delegated session (cannot exceed parent's remaining TTL)
    ///
    /// # Returns
    /// A new session with restricted permissions and a reference to the parent
    pub fn delegate_session(
        &self,
        parent_session_id: &str,
        restricted_scope: SessionScope,
        ttl_seconds: i64,
    ) -> Result<SessionCreationResult> {
        let parent = self
            .sessions
            .get(parent_session_id)
            .ok_or_else(|| AuthError::InvalidSession("Parent session not found".to_string()))?;

        // Check if parent can delegate
        if !parent.can_delegate() {
            return Err(AuthError::Unauthorized(
                "Session cannot delegate".to_string(),
            ));
        }

        // Check if parent is expired
        if parent.is_expired() {
            return Err(AuthError::SessionExpired);
        }

        // Calculate maximum allowed TTL (cannot exceed parent's remaining time)
        let parent_remaining = parent
            .expires_at
            .signed_duration_since(Utc::now())
            .num_seconds()
            .max(0);
        let effective_ttl = ttl_seconds.min(parent_remaining);

        // Merge scopes (most restrictive combination)
        let effective_scope = match &parent.scope {
            Some(parent_scope) => parent_scope.intersect(&restricted_scope),
            None => restricted_scope.clone(),
        };

        // Verify the restricted scope is actually a subset
        if let Some(parent_scope) = &parent.scope {
            if !restricted_scope.is_subset_of(parent_scope) {
                return Err(AuthError::Unauthorized(
                    "Delegated scope must be subset of parent scope".to_string(),
                ));
            }
        }

        // Create the delegated session
        let now = Utc::now();
        let expires_at = now + Duration::seconds(effective_ttl);
        let id = Session::generate_session_id();
        let token = SessionToken::new();
        let token_hash = HashedToken::from_token(&token);

        let delegated = Session {
            id,
            identity: parent.identity.clone(),
            created_at: now,
            last_accessed: now,
            expires_at,
            token_hash,
            operation_count: 0,
            tls_fingerprint: parent.tls_fingerprint.clone(),
            client_ip: parent.client_ip.clone(),
            user_agent: parent.user_agent.clone(),
            scope: Some(effective_scope.clone()),
            parent_session_id: Some(parent_session_id.to_string()),
            delegation_depth: parent.delegation_depth + 1,
            max_delegation_depth: parent.max_delegation_depth,
            allow_delegation: parent.remaining_delegation_depth() > 1,
            template_id: parent.template_id.clone(),
        };

        // Set up rate limiter if configured
        if let Some(rate_limit) = effective_scope.rate_limit {
            self.rate_limiters.insert(
                delegated.id.clone(),
                Arc::new(RateLimiterState::new(rate_limit)),
            );
        }

        let session_id = delegated.id.clone();
        self.sessions.insert(session_id, delegated.clone());

        metrics::counter!("auth.session.delegated").increment(1);

        Ok(SessionCreationResult {
            session: delegated,
            token,
        })
    }

    /// Validate session with scope checks
    ///
    /// This method validates the session and optionally checks if a specific
    /// operation/key is allowed by the session's scope.
    pub fn validate_scoped_session(
        &self,
        session_id: &str,
        token: &SessionToken,
        operation: Option<&Permission>,
        key_id: Option<&str>,
    ) -> Result<Session> {
        let mut session_ref = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| AuthError::InvalidSession("Session not found".to_string()))?;

        // Check expiration
        if session_ref.is_expired() {
            metrics::counter!("auth.session.expired").increment(1);
            return Err(AuthError::SessionExpired);
        }

        // Verify token
        if !session_ref.verify_token(token) {
            metrics::counter!("auth.session.invalid_token").increment(1);
            return Err(AuthError::InvalidSession(
                "Invalid session token".to_string(),
            ));
        }

        // Check operation limit
        if session_ref.is_operation_limit_reached() {
            metrics::counter!("auth.session.operation_limit").increment(1);
            return Err(AuthError::InvalidSession(
                "Operation limit reached".to_string(),
            ));
        }

        // Check rate limit
        if let Some(rate_limiter) = self.rate_limiters.get(session_id) {
            if rate_limiter.check_and_increment().is_err() {
                metrics::counter!("auth.session.rate_limited").increment(1);
                return Err(AuthError::RateLimited);
            }
        }

        // Check operation permission
        if let Some(op) = operation {
            if !session_ref.is_operation_allowed(op) {
                metrics::counter!("auth.session.operation_denied").increment(1);
                return Err(AuthError::PermissionDenied(format!(
                    "Operation {} not allowed by session scope",
                    op
                )));
            }
        }

        // Check key permission
        if let Some(key) = key_id {
            if !session_ref.is_key_allowed(key) {
                metrics::counter!("auth.session.key_denied").increment(1);
                return Err(AuthError::PermissionDenied(format!(
                    "Key {} not allowed by session scope",
                    key
                )));
            }
        }

        // Update operation count and last accessed
        session_ref.increment_operation();
        session_ref.touch();

        metrics::counter!("auth.session.validated").increment(1);
        Ok(session_ref.clone())
    }

    // === Template Management ===

    /// Register a session template
    pub fn register_template(&self, template: SessionTemplate) -> Result<()> {
        if self.templates.contains_key(&template.id) {
            return Err(AuthError::InvalidSession(format!(
                "Template already exists: {}",
                template.id
            )));
        }
        metrics::counter!("auth.template.registered").increment(1);
        self.templates.insert(template.id.clone(), template);
        Ok(())
    }

    /// Update a session template
    pub fn update_template(&self, template: SessionTemplate) -> Result<()> {
        if !self.templates.contains_key(&template.id) {
            return Err(AuthError::InvalidSession(format!(
                "Template not found: {}",
                template.id
            )));
        }
        metrics::counter!("auth.template.updated").increment(1);
        self.templates.insert(template.id.clone(), template);
        Ok(())
    }

    /// Delete a session template
    pub fn delete_template(&self, template_id: &str) -> Result<()> {
        self.templates.remove(template_id).ok_or_else(|| {
            AuthError::InvalidSession(format!("Template not found: {}", template_id))
        })?;
        metrics::counter!("auth.template.deleted").increment(1);
        Ok(())
    }

    /// Get a session template
    pub fn get_template(&self, template_id: &str) -> Option<SessionTemplate> {
        self.templates.get(template_id).map(|t| t.clone())
    }

    /// List all session templates
    pub fn list_templates(&self) -> Vec<SessionTemplate> {
        self.templates.iter().map(|t| t.clone()).collect()
    }

    /// Get all delegated sessions for a parent
    pub fn get_delegated_sessions(&self, parent_session_id: &str) -> Vec<Session> {
        self.sessions
            .iter()
            .filter(|s| {
                s.parent_session_id
                    .as_ref()
                    .map(|p| p == parent_session_id)
                    .unwrap_or(false)
            })
            .filter(|s| s.is_valid())
            .map(|s| s.clone())
            .collect()
    }

    /// Revoke a session and all its delegated children
    pub fn revoke_session_cascade(&self, session_id: &str) -> usize {
        let mut revoked = 0;

        // Find all descendant sessions using a worklist algorithm
        let mut to_revoke: Vec<String> = vec![session_id.to_string()];
        let mut i = 0;

        while i < to_revoke.len() {
            // Clone the current ID to avoid borrow conflicts
            let current_id = to_revoke[i].clone();

            // Find all children of the current session
            let children: Vec<String> = self
                .sessions
                .iter()
                .filter(|entry| entry.parent_session_id.as_ref() == Some(&current_id))
                .map(|entry| entry.id.clone())
                .collect();

            to_revoke.extend(children);
            i += 1;
        }

        // Revoke all sessions
        for id in to_revoke {
            if self.sessions.remove(&id).is_some() {
                self.rate_limiters.remove(&id);
                revoked += 1;
            }
        }

        metrics::counter!("auth.session.revoked_cascade").increment(revoked as u64);
        revoked
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
            return Err(AuthError::InvalidSession(
                "Invalid session token".to_string(),
            ));
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
            return Err(AuthError::InvalidSession(
                "Invalid session token".to_string(),
            ));
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
        // Clean up rate limiter if exists
        self.rate_limiters.remove(session_id);
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
        // Collect expired session IDs
        let expired_ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|s| !s.is_valid())
            .map(|s| s.id.clone())
            .collect();

        // Remove expired sessions
        self.sessions.retain(|_, session| session.is_valid());

        // Clean up rate limiters for expired sessions
        for id in &expired_ids {
            self.rate_limiters.remove(id);
        }

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

    // === Session Scope Tests ===

    #[test]
    fn test_session_scope_default() {
        let scope = SessionScope::new();
        // Default scope allows everything
        assert!(scope.is_operation_allowed(&Permission::Sign));
        assert!(scope.is_operation_allowed(&Permission::DeleteKey));
        assert!(scope.is_key_allowed("any-key"));
        assert!(scope.is_namespace_allowed("any-namespace"));
    }

    #[test]
    fn test_session_scope_operations() {
        let scope =
            SessionScope::new().with_operations(vec![Permission::Sign, Permission::Encrypt]);

        assert!(scope.is_operation_allowed(&Permission::Sign));
        assert!(scope.is_operation_allowed(&Permission::Encrypt));
        assert!(!scope.is_operation_allowed(&Permission::DeleteKey));
        assert!(!scope.is_operation_allowed(&Permission::Decrypt));
    }

    #[test]
    fn test_session_scope_keys() {
        let scope = SessionScope::new().with_keys(vec!["key-1".to_string(), "key-2".to_string()]);

        assert!(scope.is_key_allowed("key-1"));
        assert!(scope.is_key_allowed("key-2"));
        assert!(!scope.is_key_allowed("key-3"));
    }

    #[test]
    fn test_session_scope_namespaces() {
        let scope =
            SessionScope::new().with_namespaces(vec!["prod".to_string(), "staging".to_string()]);

        assert!(scope.is_namespace_allowed("prod"));
        assert!(scope.is_namespace_allowed("staging"));
        assert!(!scope.is_namespace_allowed("dev"));
    }

    #[test]
    fn test_session_scope_is_subset() {
        let parent = SessionScope::new()
            .with_operations(vec![
                Permission::Sign,
                Permission::Encrypt,
                Permission::Decrypt,
            ])
            .with_keys(vec![
                "key-1".to_string(),
                "key-2".to_string(),
                "key-3".to_string(),
            ])
            .with_max_operations(1000)
            .with_rate_limit(100);

        // Valid subset
        let child = SessionScope::new()
            .with_operations(vec![Permission::Sign])
            .with_keys(vec!["key-1".to_string()])
            .with_max_operations(500)
            .with_rate_limit(50);
        assert!(child.is_subset_of(&parent));

        // Invalid: operation not in parent
        let invalid_ops =
            SessionScope::new().with_operations(vec![Permission::Sign, Permission::DeleteKey]);
        assert!(!invalid_ops.is_subset_of(&parent));

        // Invalid: key not in parent
        let invalid_keys =
            SessionScope::new().with_keys(vec!["key-1".to_string(), "key-unknown".to_string()]);
        assert!(!invalid_keys.is_subset_of(&parent));

        // Invalid: max_operations exceeds parent
        let invalid_max = SessionScope::new().with_max_operations(2000);
        assert!(!invalid_max.is_subset_of(&parent));
    }

    #[test]
    fn test_session_scope_intersect() {
        let scope1 = SessionScope::new()
            .with_operations(vec![Permission::Sign, Permission::Encrypt])
            .with_keys(vec!["key-1".to_string(), "key-2".to_string()])
            .with_max_operations(1000)
            .with_rate_limit(100);

        let scope2 = SessionScope::new()
            .with_operations(vec![Permission::Sign, Permission::Decrypt])
            .with_keys(vec!["key-2".to_string(), "key-3".to_string()])
            .with_max_operations(500)
            .with_rate_limit(50);

        let intersection = scope1.intersect(&scope2);

        // Only Sign is in both
        assert!(intersection.is_operation_allowed(&Permission::Sign));
        assert!(!intersection.is_operation_allowed(&Permission::Encrypt));
        assert!(!intersection.is_operation_allowed(&Permission::Decrypt));

        // Only key-2 is in both
        assert!(intersection.is_key_allowed("key-2"));
        assert!(!intersection.is_key_allowed("key-1"));
        assert!(!intersection.is_key_allowed("key-3"));

        // Takes minimum
        assert_eq!(intersection.max_operations, Some(500));
        assert_eq!(intersection.rate_limit, Some(50));
    }

    // === Session Template Tests ===

    #[test]
    fn test_session_template_creation() {
        let template = SessionTemplate::new("signing-only", "Signing Only")
            .with_scope(
                SessionScope::new()
                    .with_operations(vec![Permission::Sign])
                    .with_rate_limit(100),
            )
            .with_ttl(3600)
            .with_description("Template for signing-only sessions")
            .with_delegation(2);

        assert_eq!(template.id, "signing-only");
        assert_eq!(template.name, "Signing Only");
        assert_eq!(template.default_ttl_seconds, 3600);
        assert!(template.allow_delegation);
        assert_eq!(template.max_delegation_depth, 2);
    }

    #[test]
    fn test_template_registration() {
        let manager = SessionManager::new(3600);

        let template = SessionTemplate::new("test-template", "Test Template");
        assert!(manager.register_template(template.clone()).is_ok());

        // Duplicate registration should fail
        assert!(manager.register_template(template).is_err());

        // Get template
        let retrieved = manager.get_template("test-template");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Template");
    }

    #[test]
    fn test_template_crud() {
        let manager = SessionManager::new(3600);

        let template = SessionTemplate::new("test", "Test");
        manager.register_template(template).unwrap();

        // List templates
        let templates = manager.list_templates();
        assert_eq!(templates.len(), 1);

        // Update template
        let updated = SessionTemplate::new("test", "Updated Test");
        assert!(manager.update_template(updated).is_ok());

        let retrieved = manager.get_template("test").unwrap();
        assert_eq!(retrieved.name, "Updated Test");

        // Delete template
        assert!(manager.delete_template("test").is_ok());
        assert!(manager.get_template("test").is_none());
    }

    // === Scoped Session Tests ===

    #[test]
    fn test_create_scoped_session() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        let scope = SessionScope::new()
            .with_operations(vec![Permission::Sign])
            .with_keys(vec!["key-1".to_string()]);

        let result = manager.create_scoped_session(identity, scope, None);

        assert!(result.session.scope.is_some());
        assert!(result.session.is_operation_allowed(&Permission::Sign));
        assert!(!result.session.is_operation_allowed(&Permission::DeleteKey));
        assert!(result.session.is_key_allowed("key-1"));
        assert!(!result.session.is_key_allowed("key-2"));
    }

    #[test]
    fn test_create_session_from_template() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        let template = SessionTemplate::new("signing-only", "Signing Only")
            .with_scope(
                SessionScope::new()
                    .with_operations(vec![Permission::Sign])
                    .with_rate_limit(100),
            )
            .with_ttl(1800)
            .with_delegation(1);

        manager.register_template(template).unwrap();

        let result = manager
            .create_session_from_template(identity, "signing-only")
            .unwrap();

        assert!(result.session.is_operation_allowed(&Permission::Sign));
        assert!(!result.session.is_operation_allowed(&Permission::Encrypt));
        assert_eq!(result.session.template_id, Some("signing-only".to_string()));
        assert!(result.session.allow_delegation);
    }

    #[test]
    fn test_validate_scoped_session() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        let scope = SessionScope::new()
            .with_operations(vec![Permission::Sign])
            .with_keys(vec!["key-1".to_string()]);

        let result = manager.create_scoped_session(identity, scope, None);

        // Allowed operation and key
        assert!(manager
            .validate_scoped_session(
                &result.session.id,
                &result.token,
                Some(&Permission::Sign),
                Some("key-1"),
            )
            .is_ok());

        // Disallowed operation
        assert!(manager
            .validate_scoped_session(
                &result.session.id,
                &result.token,
                Some(&Permission::DeleteKey),
                None,
            )
            .is_err());

        // Disallowed key
        assert!(manager
            .validate_scoped_session(&result.session.id, &result.token, None, Some("key-2"),)
            .is_err());
    }

    #[test]
    fn test_scoped_session_operation_limit() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        let scope = SessionScope::new().with_max_operations(3);

        let result = manager.create_scoped_session(identity, scope, None);

        // First 3 operations should succeed
        for _ in 0..3 {
            assert!(manager
                .validate_scoped_session(&result.session.id, &result.token, None, None)
                .is_ok());
        }

        // 4th operation should fail due to limit
        assert!(manager
            .validate_scoped_session(&result.session.id, &result.token, None, None)
            .is_err());
    }

    // === Session Delegation Tests ===

    #[test]
    fn test_session_delegation() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        // Create parent session with delegation enabled
        let scope =
            SessionScope::new().with_operations(vec![Permission::Sign, Permission::Encrypt]);

        let parent_result = manager.create_scoped_session(identity, scope, None);
        let parent_id = parent_result.session.id.clone();

        // Manually enable delegation on parent
        {
            let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
            parent.allow_delegation = true;
            parent.max_delegation_depth = 2;
        }

        // Delegate with more restricted scope
        let child_scope = SessionScope::new().with_operations(vec![Permission::Sign]);

        let child_result = manager
            .delegate_session(&parent_id, child_scope, 1800)
            .unwrap();

        assert_eq!(
            child_result.session.parent_session_id,
            Some(parent_id.clone())
        );
        assert_eq!(child_result.session.delegation_depth, 1);
        assert!(child_result.session.is_operation_allowed(&Permission::Sign));
        assert!(!child_result
            .session
            .is_operation_allowed(&Permission::Encrypt));
    }

    #[test]
    fn test_delegation_cannot_exceed_parent_scope() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        // Parent only allows Sign
        let scope = SessionScope::new().with_operations(vec![Permission::Sign]);

        let parent_result = manager.create_scoped_session(identity, scope, None);
        let parent_id = parent_result.session.id.clone();

        // Enable delegation
        {
            let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
            parent.allow_delegation = true;
            parent.max_delegation_depth = 1;
        }

        // Try to delegate with operations not in parent (should fail)
        let invalid_scope =
            SessionScope::new().with_operations(vec![Permission::Sign, Permission::Encrypt]); // Encrypt not allowed

        let result = manager.delegate_session(&parent_id, invalid_scope, 1800);
        assert!(result.is_err());
    }

    #[test]
    fn test_delegation_without_permission() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        // Create session without delegation enabled
        let result = manager.create_session(identity);

        // Try to delegate (should fail)
        let scope = SessionScope::new();
        assert!(manager
            .delegate_session(&result.session.id, scope, 1800)
            .is_err());
    }

    #[test]
    fn test_delegation_depth_limit() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        // Create parent with max depth of 1
        let scope = SessionScope::new();
        let parent_result = manager.create_scoped_session(identity, scope, None);
        let parent_id = parent_result.session.id.clone();

        {
            let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
            parent.allow_delegation = true;
            parent.max_delegation_depth = 1;
        }

        // First delegation should succeed
        let child_result = manager
            .delegate_session(&parent_id, SessionScope::new(), 1800)
            .unwrap();
        assert_eq!(child_result.session.delegation_depth, 1);
        assert!(!child_result.session.allow_delegation); // Can't delegate further

        // Child cannot delegate (depth limit reached)
        assert!(manager
            .delegate_session(&child_result.session.id, SessionScope::new(), 900)
            .is_err());
    }

    #[test]
    fn test_revoke_session_cascade() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        // Create parent
        let scope = SessionScope::new();
        let parent_result = manager.create_scoped_session(identity.clone(), scope, None);
        let parent_id = parent_result.session.id.clone();

        {
            let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
            parent.allow_delegation = true;
            parent.max_delegation_depth = 3;
        }

        // Create children
        let child1 = manager
            .delegate_session(&parent_id, SessionScope::new(), 1800)
            .unwrap();
        let child2 = manager
            .delegate_session(&parent_id, SessionScope::new(), 1800)
            .unwrap();

        // Create grandchild from child1
        {
            let mut child = manager.sessions.get_mut(&child1.session.id).unwrap();
            child.allow_delegation = true;
        }
        let grandchild = manager
            .delegate_session(&child1.session.id, SessionScope::new(), 900)
            .unwrap();

        // Total: 4 sessions (parent + 2 children + 1 grandchild)
        assert_eq!(manager.active_session_count(), 4);

        // Revoke parent - should cascade to all descendants
        let revoked = manager.revoke_session_cascade(&parent_id);
        assert_eq!(revoked, 4);
        assert_eq!(manager.active_session_count(), 0);

        // All sessions should be gone
        assert!(manager.get_session(&parent_id).is_err());
        assert!(manager.get_session(&child1.session.id).is_err());
        assert!(manager.get_session(&child2.session.id).is_err());
        assert!(manager.get_session(&grandchild.session.id).is_err());
    }

    #[test]
    fn test_get_delegated_sessions() {
        let manager = SessionManager::new(3600);
        let identity = create_test_identity("client1");

        // Create parent
        let parent_result =
            manager.create_scoped_session(identity.clone(), SessionScope::new(), None);
        let parent_id = parent_result.session.id.clone();

        {
            let mut parent = manager.sessions.get_mut(&parent_id).unwrap();
            parent.allow_delegation = true;
            parent.max_delegation_depth = 2;
        }

        // Create children
        manager
            .delegate_session(&parent_id, SessionScope::new(), 1800)
            .unwrap();
        manager
            .delegate_session(&parent_id, SessionScope::new(), 1800)
            .unwrap();

        // Get delegated sessions
        let delegated = manager.get_delegated_sessions(&parent_id);
        assert_eq!(delegated.len(), 2);
    }

    // === Rate Limiter Tests ===

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiterState::new(3);

        // First 3 should succeed
        assert!(limiter.check_and_increment().is_ok());
        assert!(limiter.check_and_increment().is_ok());
        assert!(limiter.check_and_increment().is_ok());

        // 4th should fail
        assert!(limiter.check_and_increment().is_err());

        assert_eq!(limiter.current_count(), 3);
    }
}
