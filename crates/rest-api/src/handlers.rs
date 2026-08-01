//! REST API Request Handlers
//!
//! Handler functions for each REST endpoint.

use crate::error::{ApiError, Result};
use crate::middleware::AppState;
use crate::types::{
    AuditEntry, AuditLogResponse, ComponentStatus, CreateNamespaceRequest, DecryptRequest,
    DecryptResponse, DevLoginRequest, EncryptRequest, EncryptResponse, GenerateKeyRequest,
    GenerateKeyResponse, HealthResponse, KeyAlgorithm, KeyMetadataResponse, KeyPurpose,
    ListKeysResponse, LoginResponse, MeResponse, NamespaceResponse, ReadyResponse, SignRequest,
    SignResponse, UserInfo, VerifyRequest, VerifyResponse, WebhookCreateRequest, WebhookResponse,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hsm_audit::EventType;
use hsm_auth::{ClientIdentity, Permission};
use hsm_crypto_engine::{
    asymmetric::{ecdsa, ed25519, rsa},
    KeyMaterial,
};
use hsm_key_manager::{KeyFilter, KeyId, KeySpec, KeyState, KeyType, KeyUsagePolicy};
use hsm_webhooks::delivery::WebhookDeliverer;
use hsm_webhooks::{
    EventFilter, Webhook, WebhookConfig, WebhookEvent, WebhookEventType, WebhookSigner,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============================================================================
// Authorization & Audit Helpers
//
// These tie the REST handlers into the three authorization layers implemented
// in `hsm_auth` (RBAC, namespace isolation, per-key ACLs) and the
// tamper-evident audit log in `hsm_audit`. Prior to this wiring the REST API
// enforced authentication ONLY — any authenticated client could perform any
// operation in any namespace on any key, and nothing was audited.
// ============================================================================

/// Enforce that at least one of the caller's roles grants `permission`.
///
/// Returns `ApiError::Forbidden` (HTTP 403) on denial. This is authorization
/// layer 2 (RBAC).
fn require_rbac(state: &AppState, identity: &ClientIdentity, permission: Permission) -> Result<()> {
    state
        .rbac
        .require_any(&identity.roles, &permission)
        .map_err(|_| {
            ApiError::Forbidden(format!(
                "role(s) {:?} lack permission {}",
                identity.roles, permission
            ))
        })
}

/// Resolve the namespace an operation runs in and enforce namespace isolation
/// (authorization layer 1).
///
/// The operating namespace is NEVER taken at face value from the request: a
/// caller may only act in a namespace they have access to. When the request
/// omits a namespace, the caller's own `identity.namespace` is used. When the
/// request names a namespace, `NamespaceManager::require_access` must pass
/// (which, for the default manager, requires it to equal the identity's
/// namespace unless explicit cross-namespace grants exist).
fn resolve_namespace(
    state: &AppState,
    identity: &ClientIdentity,
    requested: Option<&str>,
) -> Result<String> {
    let ns = requested.unwrap_or(identity.namespace.as_str());
    state
        .namespaces
        .require_access(identity, ns)
        .map_err(|_| ApiError::Forbidden(format!("no access to namespace {}", ns)))?;
    Ok(ns.to_string())
}

/// Enforce the per-key ACL for `permission` (authorization layer 3).
///
/// Keys with no ACL row are unrestricted; restricted keys default-deny.
fn require_acl(
    state: &AppState,
    identity: &ClientIdentity,
    key_id: &str,
    permission: Permission,
) -> Result<()> {
    state
        .acls
        .require_access_with_permission(key_id, identity, &permission)
        .map_err(|_| ApiError::Forbidden(format!("ACL denies access to key {}", key_id)))
}

/// Record an audit event fail-closed.
///
/// If an audit logger is attached and the write fails, the operation is failed
/// (`ApiError::Internal`) so that no crypto or key-lifecycle action completes
/// without a durable, tamper-evident record. When no logger is attached (unit
/// tests), this is a no-op.
async fn audit_success(
    state: &AppState,
    event_type: EventType,
    operation: &str,
    namespace: &str,
    client_id: &str,
    key_id: Option<String>,
) -> Result<()> {
    if let Some(audit) = state.audit.as_ref() {
        audit
            .log_success(
                event_type,
                operation.to_string(),
                namespace.to_string(),
                client_id.to_string(),
                key_id,
            )
            .await
            .map_err(|e| ApiError::Internal(format!("audit write failed: {}", e)))?;
    }
    Ok(())
}

/// Record a failed-operation audit event (best-effort).
///
/// Failures here are logged but do not mask the original error returned to the
/// caller.
async fn audit_failure(
    state: &AppState,
    event_type: EventType,
    operation: &str,
    namespace: &str,
    client_id: &str,
    key_id: Option<String>,
    reason: &str,
) {
    if let Some(audit) = state.audit.as_ref() {
        if let Err(e) = audit
            .log_failure(
                event_type,
                operation.to_string(),
                namespace.to_string(),
                client_id.to_string(),
                key_id,
                reason.to_string(),
            )
            .await
        {
            tracing::error!(error = %e, "failed to write failure audit event");
        }
    }
}

/// Run a blocking key-manager operation on the dedicated blocking thread pool,
/// off the async runtime workers.
///
/// Key generation/rotation are CPU-bound (RSA) and persistence does blocking
/// disk I/O; executing them on a runtime worker would block every other request
/// scheduled on that worker. The closure's own `Result` is returned unchanged so
/// callers can still branch on it (e.g. to emit a failure audit event); only a
/// task panic is mapped to `ApiError::Internal`.
async fn spawn_km<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::Internal(format!("key-manager task panicked: {}", e)))
}

// ============================================================================
// Type Conversions
// ============================================================================

/// Convert REST API KeyAlgorithm to key-manager KeyType
fn to_key_type(algo: &KeyAlgorithm) -> Result<KeyType> {
    match algo {
        KeyAlgorithm::Ed25519 => Ok(KeyType::Ed25519),
        KeyAlgorithm::EcdsaP256 => Ok(KeyType::EcdsaP256),
        KeyAlgorithm::EcdsaP384 => Ok(KeyType::EcdsaP384),
        KeyAlgorithm::Rsa2048 => Ok(KeyType::Rsa2048),
        KeyAlgorithm::Rsa3072 => Ok(KeyType::Rsa3072),
        KeyAlgorithm::Rsa4096 => Ok(KeyType::Rsa4096),
        KeyAlgorithm::Aes128 | KeyAlgorithm::Aes256 => Err(ApiError::BadRequest(
            "Symmetric key generation is not supported via REST API. Use the gRPC API instead."
                .to_string(),
        )),
    }
}

/// Convert key-manager KeyType to REST API KeyAlgorithm
fn to_key_algorithm(key_type: KeyType) -> KeyAlgorithm {
    match key_type {
        KeyType::Ed25519 => KeyAlgorithm::Ed25519,
        KeyType::EcdsaP256 => KeyAlgorithm::EcdsaP256,
        KeyType::EcdsaP384 => KeyAlgorithm::EcdsaP384,
        KeyType::Rsa2048 => KeyAlgorithm::Rsa2048,
        KeyType::Rsa3072 => KeyAlgorithm::Rsa3072,
        KeyType::Rsa4096 => KeyAlgorithm::Rsa4096,
        _ => KeyAlgorithm::Ed25519, // Default fallback
    }
}

/// Convert KeyPurpose to KeyUsagePolicy
fn to_usage_policy(purpose: &KeyPurpose) -> KeyUsagePolicy {
    match purpose {
        KeyPurpose::Sign => KeyUsagePolicy {
            can_sign: true,
            can_encrypt: false,
            can_derive: false,
            can_export: false,
            max_operations: None,
            expires_at: None,
        },
        KeyPurpose::Encrypt => KeyUsagePolicy {
            can_sign: false,
            can_encrypt: true,
            can_derive: false,
            can_export: false,
            max_operations: None,
            expires_at: None,
        },
        KeyPurpose::General => KeyUsagePolicy {
            can_sign: true,
            can_encrypt: true,
            can_derive: false,
            can_export: false,
            max_operations: None,
            expires_at: None,
        },
    }
}

// ============================================================================
// Authentication Endpoints
// ============================================================================

/// Development login endpoint (for testing only)
///
/// This endpoint is only available in development/debug builds.
/// Username determines the role:
/// - "admin" → Admin role
/// - "operator" → Operator role
/// - "auditor" → Auditor role
/// - anything else → User role
///
/// Password must be "dev" for development mode.
///
/// # Safety
/// This endpoint is gated behind `#[cfg(debug_assertions)]` and will
/// not be compiled into release builds.
#[cfg(debug_assertions)]
pub async fn dev_login(
    State(state): State<AppState>,
    Json(request): Json<DevLoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Only allow "dev" password in development mode
    if request.password != "dev" {
        return Err(ApiError::Unauthorized("Invalid credentials".to_string()));
    }

    tracing::info!(username = %request.username, "Development login attempt");

    // Determine roles based on username
    let roles = if request.username.contains("admin") {
        vec![hsm_auth::Role::Admin]
    } else if request.username.contains("operator") {
        vec![hsm_auth::Role::Operator]
    } else if request.username.contains("auditor") {
        vec![hsm_auth::Role::Auditor]
    } else {
        vec![hsm_auth::Role::User]
    };

    // Create client identity
    let identity = ClientIdentity::new(
        request.username.clone(),
        Some("Development".to_string()),
        "default".to_string(),
        roles.clone(),
        format!("dev-{}", uuid::Uuid::new_v4()),
    );

    // Create session
    let session_result = state.sessions.create_session(identity);

    // Calculate expiration (1 hour from now)
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);

    // Format token as session_id:token
    let token = format!(
        "{}:{}",
        session_result.session.id,
        session_result.token.as_str()
    );

    let role_names: Vec<String> = roles.iter().map(|r| format!("{:?}", r)).collect();

    let response = LoginResponse {
        token,
        user: UserInfo {
            username: request.username,
            roles: role_names,
            namespace: "default".to_string(),
        },
        expires_at: expires_at.to_rfc3339(),
    };

    metrics::counter!("rest_api.auth.dev_login").increment(1);

    Ok(Json(response))
}

/// Get current user endpoint
pub async fn me(
    State(_state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Result<Json<MeResponse>> {
    let role_names: Vec<String> = identity.roles.iter().map(|r| format!("{:?}", r)).collect();

    let response = MeResponse {
        user: UserInfo {
            username: identity.common_name.clone(),
            roles: role_names,
            namespace: identity.namespace.clone(),
        },
        session_id: identity.serial_number.clone(),
        created_at: chrono::Utc::now().to_rfc3339(), // Would be stored in session
    };

    Ok(Json(response))
}

/// Logout endpoint
pub async fn logout(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Result<StatusCode> {
    tracing::info!(client = %identity.common_name, "Logout");

    // The session ID is stored in serial_number field for dev sessions
    // In production, would extract from auth header
    if let Err(e) = state.sessions.delete_session(&identity.serial_number) {
        tracing::warn!(error = %e, client = %identity.common_name, "Failed to delete session during logout");
    }

    metrics::counter!("rest_api.auth.logout").increment(1);

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Health Endpoints
// ============================================================================

/// Health check endpoint (no auth required)
pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    })
}

/// Readiness check endpoint (no auth required)
pub async fn ready_check(State(state): State<AppState>) -> Json<ReadyResponse> {
    let mut components = HashMap::new();

    // Check session manager
    components.insert(
        "session_manager".to_string(),
        ComponentStatus {
            status: "healthy".to_string(),
            message: Some(format!(
                "{} active sessions",
                state.sessions.active_session_count()
            )),
        },
    );

    // Check key manager by listing keys in default namespace
    let key_manager_status = match state.key_manager.list_keys("default", KeyFilter::default()) {
        Ok(_) => ComponentStatus {
            status: "healthy".to_string(),
            message: Some("Key manager operational".to_string()),
        },
        Err(e) => ComponentStatus {
            status: "degraded".to_string(),
            message: Some(format!("Key manager error: {}", e)),
        },
    };
    components.insert("key_manager".to_string(), key_manager_status);

    Json(ReadyResponse {
        ready: true,
        components,
    })
}

// ============================================================================
// Key Management Endpoints
// ============================================================================

/// Generate a new key
pub async fn generate_key(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Json(request): Json<GenerateKeyRequest>,
) -> Result<(StatusCode, Json<GenerateKeyResponse>)> {
    tracing::info!(
        client = %identity.common_name,
        algorithm = ?request.algorithm,
        namespace = %request.namespace,
        "Generating new key"
    );

    // Authorization: RBAC (layer 2) + namespace isolation (layer 1).
    require_rbac(&state, &identity, Permission::GenerateKey)?;
    let namespace = resolve_namespace(&state, &identity, Some(&request.namespace))?;

    // Convert to key-manager types
    let key_type = to_key_type(&request.algorithm)?;
    let policy = to_usage_policy(&request.purpose);

    // Create key spec
    let spec = KeySpec {
        key_type,
        namespace: namespace.clone(),
        policy,
        labels: request.labels.clone(),
    };

    // Generate the key on the blocking thread pool. Key generation is CPU-bound
    // (RSA can take hundreds of ms) and write-through persistence does blocking
    // disk I/O; running either on the async runtime workers would stall every
    // other in-flight request on that worker.
    let km = state.key_manager.clone();
    let gen_result = spawn_km(move || km.generate_key(spec)).await?;
    let key_id = match gen_result {
        Ok(id) => id,
        Err(e) => {
            audit_failure(
                &state,
                EventType::KeyGeneration,
                "generate_key",
                &namespace,
                &identity.common_name,
                None,
                &e.to_string(),
            )
            .await;
            return Err(ApiError::Internal(format!("Key generation failed: {}", e)));
        }
    };

    // Get the key to retrieve public key
    let key = state
        .key_manager
        .get_key(&key_id, &namespace)
        .map_err(|e| ApiError::Internal(format!("Failed to retrieve key: {}", e)))?;

    // Create a per-key ACL row so subsequent operations are governed by layer 3.
    // Created unrestricted (any client with the right RBAC permission and
    // namespace access may use it); operators can later restrict it.
    state.acls.create_acl(key_id.to_string(), false);

    // Audit fail-closed BEFORE returning success.
    audit_success(
        &state,
        EventType::KeyGeneration,
        "generate_key",
        &namespace,
        &identity.common_name,
        Some(key_id.to_string()),
    )
    .await?;

    // Encode public key
    let public_key = key.public_material.as_ref().map(|pk| BASE64.encode(pk));

    let response = GenerateKeyResponse {
        key_id: key_id.to_string(),
        algorithm: request.algorithm,
        purpose: request.purpose,
        public_key,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    metrics::counter!("rest_api.keys.generated").increment(1);

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get key metadata
pub async fn get_key(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
) -> Result<Json<KeyMetadataResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Getting key metadata"
    );

    // Authorization: RBAC ViewMetadata + namespace isolation (caller's own ns).
    require_rbac(&state, &identity, Permission::ViewMetadata)?;
    let namespace = resolve_namespace(&state, &identity, None)?;

    // Parse key ID
    let key_id = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    // Per-key ACL (layer 3).
    require_acl(
        &state,
        &identity,
        &key_id.to_string(),
        Permission::ViewMetadata,
    )?;

    // Look up metadata strictly within the caller's namespace — never a
    // cross-tenant "default" fallback.
    let metadata = state
        .key_manager
        .get_metadata(&key_id, &namespace)
        .map_err(|e| ApiError::NotFound(format!("Key not found: {}", e)))?;

    // Determine purpose based on key type (signing keys are Ed25519, ECDSA, RSA)
    let purpose = match metadata.key_type {
        KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaP384 => KeyPurpose::Sign,
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => KeyPurpose::General,
        _ => KeyPurpose::Encrypt,
    };

    let response = KeyMetadataResponse {
        key_id: metadata.id.to_string(),
        algorithm: to_key_algorithm(metadata.key_type),
        purpose,
        namespace: metadata.namespace,
        public_key: Some(metadata.fingerprint),
        created_at: metadata.created_at.to_rfc3339(),
        last_used: None,
        labels: metadata.labels,
        active: metadata.state == KeyState::Active,
    };

    Ok(Json(response))
}

/// Delete a key
pub async fn delete_key(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
) -> Result<StatusCode> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Deleting key"
    );

    // Authorization: DeleteKey is privileged (Admin only) + namespace isolation.
    require_rbac(&state, &identity, Permission::DeleteKey)?;
    let namespace = resolve_namespace(&state, &identity, None)?;

    // Parse key ID
    let key_id = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    // Per-key ACL (layer 3).
    require_acl(
        &state,
        &identity,
        &key_id.to_string(),
        Permission::DeleteKey,
    )?;

    // Delete strictly within the caller's namespace (blocking pool: disk I/O).
    let km = state.key_manager.clone();
    let delete_ns = namespace.clone();
    let delete_result = spawn_km(move || km.delete_key(&key_id, &delete_ns)).await?;
    if let Err(e) = delete_result {
        audit_failure(
            &state,
            EventType::KeyDeletion,
            "delete_key",
            &namespace,
            &identity.common_name,
            Some(key_id.to_string()),
            &e.to_string(),
        )
        .await;
        return Err(ApiError::NotFound(format!("Key not found: {}", e)));
    }

    // Drop the per-key ACL row now that the key is gone.
    state.acls.delete_acl(&key_id.to_string());

    // Audit fail-closed before returning success.
    audit_success(
        &state,
        EventType::KeyDeletion,
        "delete_key",
        &namespace,
        &identity.common_name,
        Some(key_id.to_string()),
    )
    .await?;

    metrics::counter!("rest_api.keys.deleted").increment(1);

    Ok(StatusCode::NO_CONTENT)
}

/// Rotate a key (creates new version, deactivates old)
pub async fn rotate_key(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
) -> Result<Json<GenerateKeyResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Rotating key"
    );

    // Authorization: RBAC RotateKey + namespace isolation (caller's own ns).
    require_rbac(&state, &identity, Permission::RotateKey)?;
    let namespace = resolve_namespace(&state, &identity, None)?;

    // Parse key ID
    let key_id_parsed = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    // Per-key ACL (layer 3).
    require_acl(
        &state,
        &identity,
        &key_id_parsed.to_string(),
        Permission::RotateKey,
    )?;

    // Look up original key metadata strictly within the caller's namespace.
    state
        .key_manager
        .get_metadata(&key_id_parsed, &namespace)
        .map_err(|e| ApiError::NotFound(format!("Key not found: {}", e)))?;

    // Rotate key on the blocking pool (generates a fresh key + persists).
    let km = state.key_manager.clone();
    let rotate_ns = namespace.clone();
    let rotate_result = spawn_km(move || km.rotate_key(&key_id_parsed, &rotate_ns)).await?;
    let new_key_id = match rotate_result {
        Ok(id) => id,
        Err(e) => {
            audit_failure(
                &state,
                EventType::KeyRotation,
                "rotate_key",
                &namespace,
                &identity.common_name,
                Some(key_id_parsed.to_string()),
                &e.to_string(),
            )
            .await;
            return Err(ApiError::Internal(format!("Key rotation failed: {}", e)));
        }
    };

    // Get the new key
    let new_key = state
        .key_manager
        .get_key(&new_key_id, &namespace)
        .map_err(|e| ApiError::Internal(format!("Failed to retrieve rotated key: {}", e)))?;

    // Provision an ACL row for the new key version.
    state.acls.create_acl(new_key_id.to_string(), false);

    // Audit fail-closed before returning success.
    audit_success(
        &state,
        EventType::KeyRotation,
        "rotate_key",
        &namespace,
        &identity.common_name,
        Some(new_key_id.to_string()),
    )
    .await?;

    // Determine purpose based on key type
    let purpose = match new_key.key_type {
        KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaP384 => KeyPurpose::Sign,
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => KeyPurpose::General,
        _ => KeyPurpose::Encrypt,
    };

    let public_key = new_key.public_material.as_ref().map(|pk| BASE64.encode(pk));

    let response = GenerateKeyResponse {
        key_id: new_key_id.to_string(),
        algorithm: to_key_algorithm(new_key.key_type),
        purpose,
        public_key,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    metrics::counter!("rest_api.keys.rotated").increment(1);

    Ok(Json(response))
}

/// Query parameters for listing keys
#[derive(Debug, Deserialize)]
pub struct ListKeysQuery {
    /// Namespace filter
    pub namespace: Option<String>,
    /// Maximum results per page
    pub limit: Option<u32>,
    /// Pagination cursor
    pub cursor: Option<String>,
}

/// List keys
pub async fn list_keys(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<ListKeysResponse>> {
    // Authorization: RBAC ViewMetadata + namespace isolation. The query may
    // name a namespace but the caller must have access to it; otherwise their
    // own namespace is used. A caller can NEVER list another tenant's keys by
    // passing `?namespace=other`.
    require_rbac(&state, &identity, Permission::ViewMetadata)?;
    let namespace = resolve_namespace(&state, &identity, query.namespace.as_deref())?;

    tracing::info!(
        client = %identity.common_name,
        namespace = %namespace,
        "Listing keys"
    );

    // List keys from key manager
    let metadata_list = state
        .key_manager
        .list_keys(&namespace, KeyFilter::default())
        .map_err(|e| ApiError::Internal(format!("Failed to list keys: {}", e)))?;

    // Apply limit
    let limit = query.limit.unwrap_or(100) as usize;
    let keys: Vec<KeyMetadataResponse> = metadata_list
        .into_iter()
        .take(limit)
        .map(|m| {
            // Determine purpose based on key type
            let purpose = match m.key_type {
                KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaP384 => KeyPurpose::Sign,
                KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => KeyPurpose::General,
                _ => KeyPurpose::Encrypt,
            };
            KeyMetadataResponse {
                key_id: m.id.to_string(),
                algorithm: to_key_algorithm(m.key_type),
                purpose,
                namespace: m.namespace,
                public_key: Some(m.fingerprint),
                created_at: m.created_at.to_rfc3339(),
                last_used: None,
                labels: m.labels,
                active: m.state == KeyState::Active,
            }
        })
        .collect();

    let total = keys.len() as u64;

    let response = ListKeysResponse {
        keys,
        total,
        next_cursor: None,
    };

    Ok(Json(response))
}

// ============================================================================
// Cryptographic Operation Endpoints
// ============================================================================

/// Sign data
pub async fn sign_data(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Signing data"
    );

    // Authorization: RBAC Sign + namespace isolation + per-key ACL.
    require_rbac(&state, &identity, Permission::Sign)?;
    let namespace = resolve_namespace(&state, &identity, None)?;

    // Decode the data
    let data = BASE64
        .decode(&request.data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 data: {}", e)))?;

    // Parse key ID
    let key_id_parsed = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    require_acl(
        &state,
        &identity,
        &key_id_parsed.to_string(),
        Permission::Sign,
    )?;

    // Get the key strictly within the caller's namespace.
    let key = state
        .key_manager
        .get_key(&key_id_parsed, &namespace)
        .map_err(|e| ApiError::NotFound(format!("Key not found: {}", e)))?;

    // Get private key material
    let private_key = key
        .private_material
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Key has no private material".to_string()))?;

    // Sign based on key type
    let sign_result: std::result::Result<(Vec<u8>, &'static str), ApiError> = match key.key_type {
        KeyType::Ed25519 => ed25519::Ed25519Engine::sign(private_key, &data)
            .map(|sig| (sig, "ED25519"))
            .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e))),
        KeyType::EcdsaP256 => ecdsa::EcdsaEngine::sign_p256(private_key, &data)
            .map(|sig| (sig, "ECDSA_P256"))
            .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e))),
        KeyType::EcdsaP384 => ecdsa::EcdsaEngine::sign_p384(private_key, &data)
            .map(|sig| (sig, "ECDSA_P384"))
            .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e))),
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            rsa::RsaEngine::sign_pkcs1v15_sha256(private_key, &data)
                .map(|sig| (sig, "RSA_PKCS1_V15"))
                .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e)))
        }
        _ => Err(ApiError::BadRequest(
            "Key type does not support signing".to_string(),
        )),
    };

    let (signature, algorithm) = match sign_result {
        Ok(v) => v,
        Err(e) => {
            audit_failure(
                &state,
                EventType::Sign,
                "sign",
                &namespace,
                &identity.common_name,
                Some(key_id_parsed.to_string()),
                &e.to_string(),
            )
            .await;
            return Err(e);
        }
    };

    // Increment operation counter
    let _ = state
        .key_manager
        .increment_operations(&key_id_parsed, &namespace);

    // Audit fail-closed before returning the signature.
    audit_success(
        &state,
        EventType::Sign,
        "sign",
        &namespace,
        &identity.common_name,
        Some(key_id_parsed.to_string()),
    )
    .await?;

    metrics::counter!("rest_api.crypto.sign").increment(1);

    Ok(Json(SignResponse {
        signature: BASE64.encode(&signature),
        algorithm: algorithm.to_string(),
    }))
}

/// Verify signature
pub async fn verify_signature(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Verifying signature"
    );

    // Authorization: verification reads the public key. Require ViewMetadata
    // (read access) + namespace isolation + per-key ACL.
    require_rbac(&state, &identity, Permission::ViewMetadata)?;
    let namespace = resolve_namespace(&state, &identity, None)?;

    // Decode the data and signature
    let data = BASE64
        .decode(&request.data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 data: {}", e)))?;

    let signature = BASE64
        .decode(&request.signature)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 signature: {}", e)))?;

    // Parse key ID
    let key_id_parsed = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    require_acl(
        &state,
        &identity,
        &key_id_parsed.to_string(),
        Permission::ViewMetadata,
    )?;

    // Get the key strictly within the caller's namespace.
    let key = state
        .key_manager
        .get_key(&key_id_parsed, &namespace)
        .map_err(|e| ApiError::NotFound(format!("Key not found: {}", e)))?;

    // Get public key material
    let public_key = key
        .public_material
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Key has no public material".to_string()))?;

    // Verify based on key type
    // Note: Invalid signatures return Err from the crypto engine, so we convert those to valid=false
    let valid = match key.key_type {
        KeyType::Ed25519 => {
            ed25519::Ed25519Engine::verify(public_key, &data, &signature).unwrap_or(false)
        }
        KeyType::EcdsaP256 => {
            ecdsa::EcdsaEngine::verify_p256(public_key, &data, &signature).unwrap_or(false)
        }
        KeyType::EcdsaP384 => {
            ecdsa::EcdsaEngine::verify_p384(public_key, &data, &signature).unwrap_or(false)
        }
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            rsa::RsaEngine::verify_pkcs1v15_sha256(public_key, &data, &signature).unwrap_or(false)
        }
        _ => {
            return Err(ApiError::BadRequest(
                "Key type does not support verification".to_string(),
            ))
        }
    };

    // Verification is read-only; record it best-effort (do not fail the op on
    // an audit-write error for a non-mutating call).
    audit_failure_ignore_ok(
        &state,
        EventType::Verify,
        "verify",
        &namespace,
        &identity.common_name,
        Some(key_id_parsed.to_string()),
        valid,
    )
    .await;

    metrics::counter!("rest_api.crypto.verify").increment(1);

    Ok(Json(VerifyResponse { valid }))
}

/// Record a verify outcome best-effort. Logs success when `valid`, otherwise a
/// failure event noting the signature did not verify. Never fails the request.
async fn audit_failure_ignore_ok(
    state: &AppState,
    event_type: EventType,
    operation: &str,
    namespace: &str,
    client_id: &str,
    key_id: Option<String>,
    valid: bool,
) {
    if state.audit.is_none() {
        return;
    }
    if valid {
        let _ = audit_success(state, event_type, operation, namespace, client_id, key_id).await;
    } else {
        audit_failure(
            state,
            event_type,
            operation,
            namespace,
            client_id,
            key_id,
            "signature did not verify",
        )
        .await;
    }
}

/// Encrypt data
pub async fn encrypt_data(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
    Json(request): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Encrypting data"
    );

    // Authorization: RBAC Encrypt + namespace isolation + per-key ACL.
    require_rbac(&state, &identity, Permission::Encrypt)?;
    let namespace = resolve_namespace(&state, &identity, None)?;

    // Parse and ACL-check the target key id.
    let key_id_parsed = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;
    require_acl(
        &state,
        &identity,
        &key_id_parsed.to_string(),
        Permission::Encrypt,
    )?;

    // Decode the plaintext
    let plaintext = BASE64
        .decode(&request.plaintext)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 plaintext: {}", e)))?;

    // For asymmetric keys, encryption is typically done with the public key
    // For symmetric keys (AES), we would use the key directly
    // Currently, we only support asymmetric keys in the key manager

    // Use AES-GCM for encryption (generate ephemeral key for demo)
    use hsm_crypto_engine::symmetric::aes_gcm::AesGcmEngine;

    // Generate a random 256-bit key
    let mut key_bytes = vec![0u8; 32];
    getrandom::fill(&mut key_bytes)
        .map_err(|e| ApiError::Internal(format!("Key generation failed: {}", e)))?;
    let key = KeyMaterial::from_bytes(key_bytes);

    // Get AAD if provided
    let aad = request
        .aad
        .as_ref()
        .map(|a| BASE64.decode(a))
        .transpose()
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 AAD: {}", e)))?;

    // Encrypt (returns nonce || ciphertext || tag combined)
    let ciphertext_with_nonce = match AesGcmEngine::encrypt_aes256(&key, &plaintext, aad.as_deref())
    {
        Ok(c) => c,
        Err(e) => {
            audit_failure(
                &state,
                EventType::Encrypt,
                "encrypt",
                &namespace,
                &identity.common_name,
                Some(key_id_parsed.to_string()),
                &e.to_string(),
            )
            .await;
            return Err(ApiError::Internal(format!("Encryption failed: {}", e)));
        }
    };

    // Extract nonce (first 12 bytes) and ciphertext+tag (rest)
    let nonce = &ciphertext_with_nonce[..12];
    let ciphertext_and_tag = &ciphertext_with_nonce[12..];

    // Audit fail-closed before returning ciphertext.
    audit_success(
        &state,
        EventType::Encrypt,
        "encrypt",
        &namespace,
        &identity.common_name,
        Some(key_id_parsed.to_string()),
    )
    .await?;

    metrics::counter!("rest_api.crypto.encrypt").increment(1);

    Ok(Json(EncryptResponse {
        ciphertext: BASE64.encode(ciphertext_and_tag),
        nonce: BASE64.encode(nonce),
        tag: None, // Tag is included in ciphertext for AES-GCM
    }))
}

/// Decrypt data
///
/// Note: Decryption requires symmetric key storage, which is not yet implemented
/// in the REST API. Use the gRPC API for decryption operations.
pub async fn decrypt_data(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
    Json(_request): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Decrypting data"
    );

    // Authorize before doing anything, even though the operation itself is not
    // yet implemented (fail-closed: an unauthorized caller gets 403, not 501).
    require_rbac(&state, &identity, Permission::Decrypt)?;
    let _namespace = resolve_namespace(&state, &identity, None)?;
    let key_id_parsed = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;
    require_acl(
        &state,
        &identity,
        &key_id_parsed.to_string(),
        Permission::Decrypt,
    )?;

    Err(ApiError::NotImplemented(
        "Decryption is not yet available via REST API. Use the gRPC API for decryption operations."
            .to_string(),
    ))
}

// ============================================================================
// Audit Endpoints
// ============================================================================

/// Query parameters for audit log
#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    /// Start time filter (RFC 3339)
    pub start: Option<String>,
    /// End time filter (RFC 3339)
    pub end: Option<String>,
    /// Event type filter
    pub event_type: Option<String>,
    /// Actor filter
    pub actor: Option<String>,
    /// Maximum results per page
    pub limit: Option<u32>,
    /// Pagination cursor
    pub cursor: Option<String>,
}

/// Get audit log
///
/// Requires the `ViewAuditLogs` permission (Admin or Auditor roles). Returns
/// the tamper-evident events recorded by the [`AsyncAuditLogger`](hsm_audit::AsyncAuditLogger), filtered by
/// the optional query parameters.
pub async fn get_audit_log(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>> {
    tracing::info!(
        client = %identity.common_name,
        event_type = ?query.event_type,
        "Fetching audit log"
    );

    // Authorization: only Auditor/Admin may read the audit trail.
    require_rbac(&state, &identity, Permission::ViewAuditLogs)?;

    // Without an attached logger there is nothing to read.
    let Some(audit) = state.audit.as_ref() else {
        return Ok(Json(AuditLogResponse {
            entries: vec![],
            total: 0,
            next_cursor: None,
        }));
    };

    // Read the full recorded range, then filter. Sequences are 1-based.
    let last = audit.current_sequence();
    let mut events = if last == 0 {
        Vec::new()
    } else {
        audit
            .get_events_range(1, last)
            .map_err(|e| ApiError::Internal(format!("audit read failed: {}", e)))?
    };

    // Apply optional filters.
    if let Some(event_type) = query.event_type.as_deref() {
        // Match against the serde snake_case representation of the event type.
        events.retain(|e| {
            serde_json::to_value(&e.event_type)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .map(|s| s == event_type)
                .unwrap_or(false)
        });
    }
    if let Some(actor) = query.actor.as_deref() {
        events.retain(|e| e.client_id == actor);
    }
    if let Some(start) = query.start.as_deref() {
        if let Ok(start_ts) = chrono::DateTime::parse_from_rfc3339(start) {
            events.retain(|e| e.timestamp >= start_ts);
        }
    }
    if let Some(end) = query.end.as_deref() {
        if let Ok(end_ts) = chrono::DateTime::parse_from_rfc3339(end) {
            events.retain(|e| e.timestamp <= end_ts);
        }
    }

    let total = events.len() as u64;

    let limit = query.limit.unwrap_or(100) as usize;
    let entries: Vec<AuditEntry> = events
        .into_iter()
        .take(limit)
        .map(audit_event_to_entry)
        .collect();

    Ok(Json(AuditLogResponse {
        entries,
        total,
        next_cursor: None,
    }))
}

/// Convert an `hsm_audit::AuditEvent` into the REST `AuditEntry` shape.
fn audit_event_to_entry(event: hsm_audit::AuditEvent) -> AuditEntry {
    use hsm_audit::OperationResult;

    let (result, details) = match &event.result {
        OperationResult::Success => ("success".to_string(), None),
        OperationResult::Failure { reason } => ("failure".to_string(), Some(reason.clone())),
    };

    let event_type = serde_json::to_value(&event.event_type)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    AuditEntry {
        id: event.sequence.to_string(),
        timestamp: event.timestamp.to_rfc3339(),
        event_type,
        actor: event.client_id,
        resource: event.key_id,
        action: event.operation,
        result,
        details,
    }
}

// ============================================================================
// Namespace management handlers
//
// Namespaces are the multi-tenancy isolation boundary. Listing returns only the
// namespaces the caller can access; creating and deleting require the
// privileged ManageNamespaces permission.
// ============================================================================

/// Build the API view of a namespace, computing the live key count from the key
/// manager. `created_at` is empty when the namespace is not tracked (e.g. the
/// caller's implicit default namespace); policy attachment is not yet wired.
fn namespace_response(state: &AppState, name: &str) -> NamespaceResponse {
    let created_at = state
        .namespaces
        .created_at(name)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default();
    let key_count = state
        .key_manager
        .list_keys(name, KeyFilter::default())
        .map(|keys| keys.len())
        .unwrap_or(0);
    NamespaceResponse {
        name: name.to_string(),
        created_at,
        key_count,
        policies: Vec::new(),
    }
}

/// `GET /namespaces` — list all namespaces (admin management view).
///
/// Namespace management is an administrative operation gated by the
/// `ManageNamespaces` permission, distinct from the per-tenant isolation that
/// governs key and crypto operations.
pub async fn list_namespaces(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Result<Json<Vec<NamespaceResponse>>> {
    require_rbac(&state, &identity, Permission::ManageNamespaces)?;
    let out = state
        .namespaces
        .list_namespaces()
        .iter()
        .map(|name| namespace_response(&state, name))
        .collect();
    Ok(Json(out))
}

/// `POST /namespaces` — create a namespace (privileged) and grant the caller
/// access to it.
pub async fn create_namespace(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<(StatusCode, Json<NamespaceResponse>)> {
    require_rbac(&state, &identity, Permission::ManageNamespaces)?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest(
            "namespace name cannot be empty".to_string(),
        ));
    }
    state
        .namespaces
        .create_namespace(name)
        .map_err(|e| ApiError::Conflict(e.to_string()))?;
    audit_success(
        &state,
        EventType::ConfigChange,
        "create_namespace",
        name,
        &identity.common_name,
        None,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(namespace_response(&state, name))))
}

/// `GET /namespaces/{name}` — fetch a single namespace (admin management view).
pub async fn get_namespace(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(name): Path<String>,
) -> Result<Json<NamespaceResponse>> {
    require_rbac(&state, &identity, Permission::ManageNamespaces)?;
    if state.namespaces.created_at(&name).is_none() {
        return Err(ApiError::NotFound(format!("namespace {} not found", name)));
    }
    Ok(Json(namespace_response(&state, &name)))
}

/// `DELETE /namespaces/{name}` — delete a namespace (privileged).
pub async fn delete_namespace(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(name): Path<String>,
) -> Result<StatusCode> {
    require_rbac(&state, &identity, Permission::ManageNamespaces)?;
    state
        .namespaces
        .delete_namespace(&name)
        .map_err(|_| ApiError::NotFound(format!("namespace {} not found", name)))?;
    audit_success(
        &state,
        EventType::ConfigChange,
        "delete_namespace",
        &name,
        &identity.common_name,
        None,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Webhook management handlers
//
// All webhook routes require the privileged ManageWebhooks permission. The
// signing secret is never returned; responses expose only a SHA-256 digest.
// ============================================================================

/// SHA-256 hex digest of a webhook signing secret (so the secret is never
/// returned to clients).
fn secret_hash(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(digest)
}

/// Map subscribed event-type strings to an [`EventFilter`]. An empty list means
/// "all events"; an unknown event name is a client error.
fn events_to_filter(events: &[String]) -> Result<EventFilter> {
    if events.is_empty() {
        return Ok(EventFilter::all());
    }
    let mut types = Vec::with_capacity(events.len());
    for e in events {
        let ty = WebhookEventType::parse(e)
            .ok_or_else(|| ApiError::BadRequest(format!("unknown event type: {}", e)))?;
        types.push(ty);
    }
    Ok(EventFilter::events(&types))
}

/// Build the API view of a webhook (secret redacted to a hash).
fn webhook_response(w: &Webhook) -> WebhookResponse {
    let mut events: Vec<String> = w
        .filter
        .include_events
        .iter()
        .map(|t| t.as_str().to_string())
        .collect();
    events.sort();
    WebhookResponse {
        id: w.id.clone(),
        url: w.config.url.clone(),
        events,
        status: if w.config.enabled {
            "active".to_string()
        } else {
            "inactive".to_string()
        },
        secret_hash: secret_hash(&w.config.secret),
        created_at: w.created_at.to_rfc3339(),
        last_triggered: w.last_delivery.map(|t| t.to_rfc3339()),
        failure_count: w.failure_count,
    }
}

/// `GET /webhooks` — list all registered webhooks.
pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Result<Json<Vec<WebhookResponse>>> {
    require_rbac(&state, &identity, Permission::ManageWebhooks)?;
    let out = state.webhooks.list().iter().map(webhook_response).collect();
    Ok(Json(out))
}

/// `POST /webhooks` — register a new webhook.
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Json(req): Json<WebhookCreateRequest>,
) -> Result<(StatusCode, Json<WebhookResponse>)> {
    require_rbac(&state, &identity, Permission::ManageWebhooks)?;
    if req.url.trim().is_empty() {
        return Err(ApiError::BadRequest("webhook url is required".to_string()));
    }
    let secret = req
        .secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::BadRequest("webhook secret is required".to_string()))?;
    let filter = events_to_filter(&req.events)?;
    let config = WebhookConfig::new(&req.url, secret);
    let webhook = Webhook::new(&req.url, config, &identity.common_name).with_filter(filter);
    let stored = webhook.clone();
    state.webhooks.register(webhook);
    audit_success(
        &state,
        EventType::ConfigChange,
        "create_webhook",
        &identity.namespace,
        &identity.common_name,
        Some(stored.id.clone()),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(webhook_response(&stored))))
}

/// `GET /webhooks/{id}` — fetch a single webhook.
pub async fn get_webhook(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(id): Path<String>,
) -> Result<Json<WebhookResponse>> {
    require_rbac(&state, &identity, Permission::ManageWebhooks)?;
    let webhook = state
        .webhooks
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("webhook {} not found", id)))?;
    Ok(Json(webhook_response(&webhook)))
}

/// `PUT /webhooks/{id}` — update a webhook's url, events, or secret.
pub async fn update_webhook(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(id): Path<String>,
    Json(req): Json<WebhookCreateRequest>,
) -> Result<Json<WebhookResponse>> {
    require_rbac(&state, &identity, Permission::ManageWebhooks)?;
    // Validate the event list before mutating.
    let filter = events_to_filter(&req.events)?;
    let updated = state
        .webhooks
        .update(&id, |w| {
            if !req.url.trim().is_empty() {
                w.config.url = req.url.clone();
            }
            if !req.events.is_empty() {
                w.filter = filter;
            }
            if let Some(secret) = req.secret.as_deref().filter(|s| !s.is_empty()) {
                w.config.secret = secret.to_string();
            }
        })
        .ok_or_else(|| ApiError::NotFound(format!("webhook {} not found", id)))?;
    audit_success(
        &state,
        EventType::ConfigChange,
        "update_webhook",
        &identity.namespace,
        &identity.common_name,
        Some(id),
    )
    .await?;
    Ok(Json(webhook_response(&updated)))
}

/// `DELETE /webhooks/{id}` — remove a webhook.
pub async fn delete_webhook(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    require_rbac(&state, &identity, Permission::ManageWebhooks)?;
    state
        .webhooks
        .delete(&id)
        .ok_or_else(|| ApiError::NotFound(format!("webhook {} not found", id)))?;
    audit_success(
        &state,
        EventType::ConfigChange,
        "delete_webhook",
        &identity.namespace,
        &identity.common_name,
        Some(id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /webhooks/{id}/test` — deliver a signed `webhook.test` event to the
/// webhook's URL and report whether the endpoint accepted it (HTTP 2xx).
pub async fn test_webhook(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(id): Path<String>,
) -> Result<Json<TestWebhookResponse>> {
    require_rbac(&state, &identity, Permission::ManageWebhooks)?;
    let webhook = state
        .webhooks
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("webhook {} not found", id)))?;

    let event = WebhookEvent::new(
        WebhookEventType::Test,
        &identity.namespace,
        serde_json::json!({
            "message": "HSM webhook connectivity test",
            "webhook_id": id,
        }),
    );
    let signer = WebhookSigner::new(&webhook.config.secret);
    let deliverer = WebhookDeliverer::new();
    let success = match deliverer
        .deliver(
            &webhook.config.url,
            &event,
            &signer,
            &webhook.config.headers,
        )
        .await
    {
        Ok(result) => result
            .http_status
            .map(|s| (200..300).contains(&s))
            .unwrap_or(false),
        Err(_) => false,
    };
    Ok(Json(TestWebhookResponse { success }))
}

/// Result of a webhook connectivity test.
#[derive(serde::Serialize)]
pub struct TestWebhookResponse {
    /// Whether the endpoint accepted the test delivery (HTTP 2xx).
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "0.1.0".to_string(),
            uptime_seconds: 3600,
        };

        let json = serde_json::to_string(&response).expect("serialization should succeed");
        assert!(json.contains("healthy"));
    }

    #[test]
    fn test_to_key_type() {
        assert!(matches!(
            to_key_type(&KeyAlgorithm::Ed25519),
            Ok(KeyType::Ed25519)
        ));
        assert!(matches!(
            to_key_type(&KeyAlgorithm::EcdsaP256),
            Ok(KeyType::EcdsaP256)
        ));
        assert!(to_key_type(&KeyAlgorithm::Aes256).is_err());
    }

    fn admin_identity() -> ClientIdentity {
        use hsm_auth::Role;
        ClientIdentity::new(
            "admin".to_string(),
            None,
            "default".to_string(),
            vec![Role::Admin],
            "test-serial".to_string(),
        )
    }

    fn test_state() -> AppState {
        use hsm_auth::SessionManager;
        use std::sync::Arc;
        AppState::new(Arc::new(SessionManager::new(3600)))
    }

    #[tokio::test]
    async fn test_namespace_handlers_roundtrip() {
        let state = test_state();
        let admin = admin_identity();

        let (status, created) = create_namespace(
            State(state.clone()),
            Extension(admin.clone()),
            Json(CreateNamespaceRequest {
                name: "team-a".to_string(),
            }),
        )
        .await
        .expect("create_namespace should succeed");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.0.name, "team-a");

        let listed = list_namespaces(State(state.clone()), Extension(admin.clone()))
            .await
            .expect("list_namespaces");
        assert!(listed.0.iter().any(|n| n.name == "team-a"));

        let got = get_namespace(
            State(state.clone()),
            Extension(admin.clone()),
            Path("team-a".to_string()),
        )
        .await
        .expect("get_namespace");
        assert_eq!(got.0.name, "team-a");

        let deleted = delete_namespace(
            State(state.clone()),
            Extension(admin),
            Path("team-a".to_string()),
        )
        .await
        .expect("delete_namespace");
        assert_eq!(deleted, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_webhook_handlers_roundtrip() {
        let state = test_state();
        let admin = admin_identity();

        let (status, created) = create_webhook(
            State(state.clone()),
            Extension(admin.clone()),
            Json(WebhookCreateRequest {
                url: "https://example.com/hook".to_string(),
                events: vec!["key.created".to_string()],
                secret: Some("s3cr3t".to_string()),
            }),
        )
        .await
        .expect("create_webhook should succeed");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.0.url, "https://example.com/hook");
        assert_eq!(created.0.events, vec!["key.created".to_string()]);
        // The signing secret must never be returned verbatim.
        assert_ne!(created.0.secret_hash, "s3cr3t");
        assert!(!created.0.secret_hash.is_empty());
        let id = created.0.id.clone();

        let listed = list_webhooks(State(state.clone()), Extension(admin.clone()))
            .await
            .expect("list_webhooks");
        assert!(listed.0.iter().any(|w| w.id == id));

        // An unknown event type is rejected as a client error.
        let bad = create_webhook(
            State(state.clone()),
            Extension(admin.clone()),
            Json(WebhookCreateRequest {
                url: "https://example.com/x".to_string(),
                events: vec!["not.a.real.event".to_string()],
                secret: Some("x".to_string()),
            }),
        )
        .await;
        assert!(bad.is_err(), "unknown event type must be rejected");

        let deleted = delete_webhook(
            State(state.clone()),
            Extension(admin.clone()),
            Path(id.clone()),
        )
        .await
        .expect("delete_webhook");
        assert_eq!(deleted, StatusCode::NO_CONTENT);

        // The webhook is gone after deletion.
        assert!(get_webhook(State(state), Extension(admin), Path(id))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn generate_key_handler_succeeds_via_blocking_pool() {
        // Exercises the full generate path now that key generation runs on the
        // blocking thread pool (RBAC -> namespace -> spawn_blocking generate ->
        // ACL -> audit -> response).
        let state = test_state();
        let admin = admin_identity();

        let (status, response) = generate_key(
            State(state),
            Extension(admin),
            Json(GenerateKeyRequest {
                key_id: None,
                algorithm: KeyAlgorithm::Ed25519,
                purpose: KeyPurpose::Sign,
                namespace: "default".to_string(),
                labels: std::collections::HashMap::new(),
            }),
        )
        .await
        .expect("generate_key should succeed");

        assert_eq!(status, StatusCode::CREATED);
        assert!(!response.0.key_id.is_empty());
        assert!(response.0.public_key.is_some());
    }

    #[tokio::test]
    async fn test_webhook_create_requires_secret_and_url() {
        let state = test_state();
        let admin = admin_identity();

        // Missing secret.
        assert!(create_webhook(
            State(state.clone()),
            Extension(admin.clone()),
            Json(WebhookCreateRequest {
                url: "https://example.com/hook".to_string(),
                events: vec![],
                secret: None,
            }),
        )
        .await
        .is_err());

        // Empty url.
        assert!(create_webhook(
            State(state),
            Extension(admin),
            Json(WebhookCreateRequest {
                url: "".to_string(),
                events: vec![],
                secret: Some("s".to_string()),
            }),
        )
        .await
        .is_err());
    }
}
