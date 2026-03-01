//! REST API Request Handlers
//!
//! Handler functions for each REST endpoint.

use crate::error::{ApiError, Result};
use crate::middleware::AppState;
use crate::types::{
    AuditLogResponse, ComponentStatus, DecryptRequest, DecryptResponse, DevLoginRequest,
    EncryptRequest, EncryptResponse, GenerateKeyRequest, GenerateKeyResponse, HealthResponse,
    KeyAlgorithm, KeyMetadataResponse, KeyPurpose, ListKeysResponse, LoginResponse, MeResponse,
    ReadyResponse, SignRequest, SignResponse, UserInfo, VerifyRequest, VerifyResponse,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hsm_auth::ClientIdentity;
use hsm_crypto_engine::{
    asymmetric::{ecdsa, ed25519, rsa},
    KeyMaterial,
};
use hsm_key_manager::{KeyFilter, KeyId, KeySpec, KeyState, KeyType, KeyUsagePolicy};
use serde::Deserialize;
use std::collections::HashMap;

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
            "Symmetric keys not supported via REST API".to_string(),
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
    let _ = state.sessions.delete_session(&identity.serial_number);

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

    // Convert to key-manager types
    let key_type = to_key_type(&request.algorithm)?;
    let policy = to_usage_policy(&request.purpose);

    // Create key spec
    let spec = KeySpec {
        key_type,
        namespace: request.namespace.clone(),
        policy,
        labels: request.labels.clone(),
    };

    // Generate key using key manager
    let key_id = state
        .key_manager
        .generate_key(spec)
        .map_err(|e| ApiError::Internal(format!("Key generation failed: {}", e)))?;

    // Get the key to retrieve public key
    let key = state
        .key_manager
        .get_key(&key_id, &request.namespace)
        .map_err(|e| ApiError::Internal(format!("Failed to retrieve key: {}", e)))?;

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

    // Parse key ID
    let key_id = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    // Try to get metadata from default namespace first, then try common namespaces
    let metadata = state
        .key_manager
        .get_metadata(&key_id, "default")
        .or_else(|_| {
            state
                .key_manager
                .get_metadata(&key_id, &identity.common_name)
        })
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

    // Parse key ID
    let key_id = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    // Delete from default namespace
    state
        .key_manager
        .delete_key(&key_id, "default")
        .or_else(|_| state.key_manager.delete_key(&key_id, &identity.common_name))
        .map_err(|e| ApiError::NotFound(format!("Key not found: {}", e)))?;

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

    // Parse key ID
    let key_id_parsed = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    // Try to get original key metadata first
    let original_metadata = state
        .key_manager
        .get_metadata(&key_id_parsed, "default")
        .or_else(|_| {
            state
                .key_manager
                .get_metadata(&key_id_parsed, &identity.common_name)
        })
        .map_err(|e| ApiError::NotFound(format!("Key not found: {}", e)))?;

    // Rotate key
    let new_key_id = state
        .key_manager
        .rotate_key(&key_id_parsed, &original_metadata.namespace)
        .map_err(|e| ApiError::Internal(format!("Key rotation failed: {}", e)))?;

    // Get the new key
    let new_key = state
        .key_manager
        .get_key(&new_key_id, &original_metadata.namespace)
        .map_err(|e| ApiError::Internal(format!("Failed to retrieve rotated key: {}", e)))?;

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
    let namespace = query.namespace.as_deref().unwrap_or("default");

    tracing::info!(
        client = %identity.common_name,
        namespace = %namespace,
        "Listing keys"
    );

    // List keys from key manager
    let metadata_list = state
        .key_manager
        .list_keys(namespace, KeyFilter::default())
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

    // Decode the data
    let data = BASE64
        .decode(&request.data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 data: {}", e)))?;

    // Parse key ID
    let key_id_parsed = KeyId::from_string(&key_id)
        .map_err(|_| ApiError::BadRequest("Invalid key ID format".to_string()))?;

    // Get the key
    let key = state
        .key_manager
        .get_key(&key_id_parsed, "default")
        .or_else(|_| {
            state
                .key_manager
                .get_key(&key_id_parsed, &identity.common_name)
        })
        .map_err(|e| ApiError::NotFound(format!("Key not found: {}", e)))?;

    // Get private key material
    let private_key = key
        .private_material
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("Key has no private material".to_string()))?;

    // Sign based on key type
    let (signature, algorithm) = match key.key_type {
        KeyType::Ed25519 => {
            let sig = ed25519::Ed25519Engine::sign(private_key, &data)
                .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e)))?;
            (sig, "ED25519")
        }
        KeyType::EcdsaP256 => {
            let sig = ecdsa::EcdsaEngine::sign_p256(private_key, &data)
                .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e)))?;
            (sig, "ECDSA_P256")
        }
        KeyType::EcdsaP384 => {
            let sig = ecdsa::EcdsaEngine::sign_p384(private_key, &data)
                .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e)))?;
            (sig, "ECDSA_P384")
        }
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let sig = rsa::RsaEngine::sign_pkcs1v15_sha256(private_key, &data)
                .map_err(|e| ApiError::Internal(format!("Signing failed: {}", e)))?;
            (sig, "RSA_PKCS1_V15")
        }
        _ => {
            return Err(ApiError::BadRequest(
                "Key type does not support signing".to_string(),
            ))
        }
    };

    // Increment operation counter
    let _ = state
        .key_manager
        .increment_operations(&key_id_parsed, "default");

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

    // Get the key
    let key = state
        .key_manager
        .get_key(&key_id_parsed, "default")
        .or_else(|_| {
            state
                .key_manager
                .get_key(&key_id_parsed, &identity.common_name)
        })
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

    metrics::counter!("rest_api.crypto.verify").increment(1);

    Ok(Json(VerifyResponse { valid }))
}

/// Encrypt data
pub async fn encrypt_data(
    State(_state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
    Json(request): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Encrypting data"
    );

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
    getrandom::getrandom(&mut key_bytes)
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
    let ciphertext_with_nonce = AesGcmEngine::encrypt_aes256(&key, &plaintext, aad.as_deref())
        .map_err(|e| ApiError::Internal(format!("Encryption failed: {}", e)))?;

    // Extract nonce (first 12 bytes) and ciphertext+tag (rest)
    let nonce = &ciphertext_with_nonce[..12];
    let ciphertext_and_tag = &ciphertext_with_nonce[12..];

    metrics::counter!("rest_api.crypto.encrypt").increment(1);

    Ok(Json(EncryptResponse {
        ciphertext: BASE64.encode(ciphertext_and_tag),
        nonce: BASE64.encode(nonce),
        tag: None, // Tag is included in ciphertext for AES-GCM
    }))
}

/// Decrypt data
///
/// Note: This endpoint requires the encryption key to be provided or stored.
/// Currently returns an error as symmetric key storage is not yet implemented.
#[allow(unreachable_code)]
pub async fn decrypt_data(
    State(_state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key_id): Path<String>,
    Json(request): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>> {
    tracing::info!(
        client = %identity.common_name,
        key_id = %key_id,
        "Decrypting data"
    );

    // Decode the ciphertext and nonce
    let _ciphertext = BASE64
        .decode(&request.ciphertext)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 ciphertext: {}", e)))?;

    let _nonce = BASE64
        .decode(&request.nonce)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 nonce: {}", e)))?;

    // Note: In a real implementation, we would retrieve the encryption key
    // associated with the key_id from storage. For now, we return an error
    // indicating the key is needed.
    Err(ApiError::BadRequest(
        "Symmetric key retrieval not implemented. Encryption keys must be stored separately."
            .to_string(),
    ))

    // TODO: Implement symmetric key retrieval and decryption
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
pub async fn get_audit_log(
    State(_state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>> {
    tracing::info!(
        client = %identity.common_name,
        event_type = ?query.event_type,
        "Fetching audit log"
    );

    // Note: Full audit integration would require adding the audit module to dependencies
    // and implementing proper log retrieval. For now, return empty.
    let response = AuditLogResponse {
        entries: vec![],
        total: 0,
        next_cursor: None,
    };

    Ok(Json(response))
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
}
