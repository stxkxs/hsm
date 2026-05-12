use super::rate_limiter::RateLimiterState;
use super::scope::{SessionScope, SessionTemplate};
use super::session_data::{Session, SessionCreationResult};
use super::token::{HashedToken, SessionToken};
use super::{SessionId, TemplateId};
use crate::error::{AuthError, Result};
use crate::mtls::ClientIdentity;
use crate::rbac::Permission;
use chrono::{Duration, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

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
    pub(super) sessions: Arc<DashMap<SessionId, Session>>,
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

    /// Create a scoped session with restricted permissions
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

        // Release the DashMap read guard before any writes to `self.sessions`.
        // Holding `parent` across `self.sessions.insert(...)` below would deadlock
        // when parent_session_id and delegated.id hash to the same DashMap shard
        // (hash-seed dependent — passes on some platforms, hangs on others).
        drop(parent);

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
    #[deprecated(since = "0.2.0", note = "Use validate_session_with_token for security")]
    #[allow(deprecated)]
    pub fn validate_session(&self, session_id: &str) -> Result<Session> {
        tracing::warn!(
            session_id = session_id,
            "validate_session called without token verification - use validate_session_with_token instead"
        );
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
