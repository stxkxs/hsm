// Simplified handlers for Module 4
// These implement the core HSM operations by delegating to key-manager and crypto-engine.

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
use crate::error::ApiError;
use crate::middleware::metrics::MetricsCollector;
use crate::proto::hsm::*;
use crate::validation::{
    validate_algorithm, validate_batch_size, validate_data_size, validate_key_id,
    validate_metadata, validate_namespace,
};
use hsm_crypto_engine::{
    asymmetric::{ecdsa, ed25519, rsa},
    symmetric::aes_gcm::AesGcmEngine,
    KeyMaterial,
};
use hsm_key_manager::{
    DefaultKeyManager, Error as KeyManagerError, KeyFilter, KeyId, KeyManager, KeySpec, KeyState,
    KeyType,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};
use tracing::info;

pub struct SimpleHsmHandler {
    metrics: MetricsCollector,
    key_manager: Arc<dyn KeyManager>,
    key_manager_breaker: Arc<CircuitBreaker>,
}

impl Default for SimpleHsmHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleHsmHandler {
    pub fn new() -> Self {
        Self::with_key_manager(Arc::new(DefaultKeyManager::new()))
    }

    pub fn with_key_manager(key_manager: Arc<dyn KeyManager>) -> Self {
        Self {
            metrics: MetricsCollector::new(),
            key_manager,
            key_manager_breaker: Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
                failure_threshold: 10,
                success_threshold: 2,
                timeout: Duration::from_secs(30),
                half_open_max_requests: 2,
            })),
        }
    }

    /// Run a key-manager operation through the circuit breaker.
    ///
    /// Returns `Status::unavailable` when the breaker is open or saturated, otherwise
    /// propagates the inner Result. The breaker is configured to tolerate transient
    /// failures (10 consecutive errors) and recover quickly (30s) so backend hiccups
    /// don't cascade into request floods.
    fn run_km<F, T>(&self, op: F) -> std::result::Result<T, Status>
    where
        F: FnOnce() -> std::result::Result<T, KeyManagerError>,
    {
        match self.key_manager_breaker.call(op) {
            Ok(inner) => inner.map_err(|e| Status::from(ApiError::from(e))),
            Err(CircuitBreakerError::CircuitOpen) => Err(Status::unavailable(
                "key-manager unavailable (circuit breaker open); retry after backoff",
            )),
            Err(CircuitBreakerError::TooManyRequests) => Err(Status::resource_exhausted(
                "key-manager recovering; too many in-flight requests",
            )),
        }
    }

    // ========================================================================
    // Health Check
    // ========================================================================

    pub fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> std::result::Result<Response<HealthCheckResponse>, Status> {
        let timer = self.metrics.record_request();

        let response = HealthCheckResponse {
            status: health_check_response::ServingStatus::Serving as i32,
            message: "Service is healthy".to_string(),
            details: HashMap::new(),
        };

        timer.finish_success();
        Ok(Response::new(response))
    }

    // ========================================================================
    // Key Management
    // ========================================================================

    pub fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> std::result::Result<Response<GenerateKeyResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_namespace(&req.namespace)?;
        validate_metadata(&req.metadata)?;

        // Convert proto KeyType to key-manager KeyType
        let key_type = proto_key_type_to_km(req.key_type)?;

        // Build usage policy from proto policy (if present)
        let policy = req
            .policy
            .as_ref()
            .map(proto_policy_to_km)
            .unwrap_or_default();

        let spec = KeySpec {
            key_type,
            namespace: req.namespace.clone(),
            policy,
            labels: req.metadata.clone(),
        };

        // Generate key
        let key_id = self.run_km(|| self.key_manager.generate_key(spec))?;

        // Retrieve the key to get the public material
        let key = self.run_km(|| self.key_manager.get_key(&key_id, &req.namespace))?;

        let public_key = key.public_material.clone().unwrap_or_default();

        // Build metadata for response
        let metadata = Some(build_key_metadata(
            &key_id,
            &req.namespace,
            key_type,
            KeyState::Active,
            key.version,
        ));

        info!(key_id = %key_id, namespace = %req.namespace, "Key generated");
        timer.finish_success();

        Ok(Response::new(GenerateKeyResponse {
            key_id: key_id.to_string(),
            public_key,
            metadata,
        }))
    }

    pub fn get_key(
        &self,
        request: Request<GetKeyRequest>,
    ) -> std::result::Result<Response<GetKeyResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_key_id(req.key_id.as_bytes())?;
        validate_namespace(&req.namespace)?;

        // Parse key ID
        let key_id = KeyId::from_string(&req.key_id)
            .map_err(|_| Status::invalid_argument("Invalid key ID format"))?;

        // Get key metadata
        let km_metadata = self.run_km(|| self.key_manager.get_metadata(&key_id, &req.namespace))?;

        // Get public key material (best-effort; deactivated keys may not allow get_key).
        // Skip the breaker here: this is a best-effort lookup and we don't want a transient
        // failure to count against the breaker's threshold since we'd return an empty key anyway.
        let public_key = self
            .key_manager
            .get_key(&key_id, &req.namespace)
            .ok()
            .and_then(|k| k.public_material.clone())
            .unwrap_or_default();

        let metadata = Some(build_key_metadata(
            &km_metadata.id,
            &km_metadata.namespace,
            km_metadata.key_type,
            km_metadata.state,
            km_metadata.version,
        ));

        timer.finish_success();

        Ok(Response::new(GetKeyResponse {
            metadata,
            public_key,
        }))
    }

    pub fn delete_key(
        &self,
        request: Request<DeleteKeyRequest>,
    ) -> std::result::Result<Response<DeleteKeyResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_key_id(req.key_id.as_bytes())?;
        validate_namespace(&req.namespace)?;

        // Parse key ID
        let key_id = KeyId::from_string(&req.key_id)
            .map_err(|_| Status::invalid_argument("Invalid key ID format"))?;

        // Delete key
        self.run_km(|| self.key_manager.delete_key(&key_id, &req.namespace))?;

        info!(key_id = %req.key_id, namespace = %req.namespace, "Key deleted");
        timer.finish_success();

        Ok(Response::new(DeleteKeyResponse { success: true }))
    }

    pub fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> std::result::Result<Response<RotateKeyResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_key_id(req.key_id.as_bytes())?;
        validate_namespace(&req.namespace)?;

        // Parse key ID
        let key_id = KeyId::from_string(&req.key_id)
            .map_err(|_| Status::invalid_argument("Invalid key ID format"))?;

        // Rotate key
        let new_key_id = self.run_km(|| self.key_manager.rotate_key(&key_id, &req.namespace))?;

        // Get new key metadata
        let new_key = self.run_km(|| self.key_manager.get_key(&new_key_id, &req.namespace))?;

        let metadata = Some(build_key_metadata(
            &new_key_id,
            &req.namespace,
            new_key.key_type,
            new_key.state,
            new_key.version,
        ));

        info!(
            old_key_id = %req.key_id,
            new_key_id = %new_key_id,
            namespace = %req.namespace,
            "Key rotated"
        );
        timer.finish_success();

        Ok(Response::new(RotateKeyResponse {
            new_key_id: new_key_id.to_string(),
            metadata,
        }))
    }

    /// List keys in a namespace.
    ///
    /// Note: The proto defines `ListKeys` as a streaming RPC (`returns (stream KeyMetadata)`).
    /// This simplified handler returns a collected `Vec<KeyMetadata>` instead. The full streaming
    /// implementation would live in a `tonic::async_trait` service impl.
    pub fn list_keys_collected(
        &self,
        namespace: &str,
        filter_state: i32,
        max_results: i32,
    ) -> std::result::Result<Vec<KeyMetadata>, Status> {
        let ns = if namespace.is_empty() {
            "default"
        } else {
            validate_namespace(namespace)?;
            namespace
        };

        let filter = KeyFilter {
            state: proto_key_state_to_km(filter_state),
            ..Default::default()
        };

        let metadata_list = self.run_km(|| self.key_manager.list_keys(ns, filter))?;

        let limit = if max_results > 0 {
            max_results as usize
        } else {
            100
        };

        let keys: Vec<KeyMetadata> = metadata_list
            .into_iter()
            .take(limit)
            .map(|m| build_key_metadata(&m.id, &m.namespace, m.key_type, m.state, m.version))
            .collect();

        Ok(keys)
    }

    // ========================================================================
    // Cryptographic Operations
    // ========================================================================

    pub fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> std::result::Result<Response<SignResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_key_id(&req.key_id)?;
        validate_namespace(&req.namespace)?;
        validate_data_size(&req.data, "sign")?;
        if !req.algorithm.is_empty() {
            validate_algorithm(&req.algorithm)?;
        }

        // Parse key ID from bytes
        let key_id_str = String::from_utf8(req.key_id.clone())
            .map_err(|_| Status::invalid_argument("key_id must be valid UTF-8"))?;
        let key_id = KeyId::from_string(&key_id_str)
            .map_err(|_| Status::invalid_argument("Invalid key ID format"))?;

        // Get the key
        let key = self.run_km(|| self.key_manager.get_key(&key_id, &req.namespace))?;

        // Get private key material
        let private_key = key.private_material.as_ref().ok_or_else(|| {
            Status::failed_precondition("Key has no private material for signing")
        })?;

        // Sign based on key type
        let (signature, algorithm) = sign_with_key(key.key_type, private_key, &req.data)
            .map_err(|e| Status::from(ApiError::CryptoError(e)))?;

        // Increment operation counter (best-effort)
        let _ = self
            .key_manager
            .increment_operations(&key_id, &req.namespace);

        info!(key_id = %key_id_str, algorithm = %algorithm, "Data signed");
        timer.finish_success();

        Ok(Response::new(SignResponse {
            signature,
            algorithm,
        }))
    }

    pub fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> std::result::Result<Response<VerifyResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_key_id(&req.key_id)?;
        validate_namespace(&req.namespace)?;
        validate_data_size(&req.data, "verify")?;
        crate::validation::validate_signature_size(&req.signature)?;

        // Parse key ID from bytes
        let key_id_str = String::from_utf8(req.key_id.clone())
            .map_err(|_| Status::invalid_argument("key_id must be valid UTF-8"))?;
        let key_id = KeyId::from_string(&key_id_str)
            .map_err(|_| Status::invalid_argument("Invalid key ID format"))?;

        // Get the key
        let key = self.run_km(|| self.key_manager.get_key(&key_id, &req.namespace))?;

        // Get public key material
        let public_key = key.public_material.as_ref().ok_or_else(|| {
            Status::failed_precondition("Key has no public material for verification")
        })?;

        // Verify based on key type
        let valid = verify_with_key(key.key_type, public_key, &req.data, &req.signature);

        timer.finish_success();

        Ok(Response::new(VerifyResponse { valid }))
    }

    pub fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> std::result::Result<Response<EncryptResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_key_id(&req.key_id)?;
        validate_namespace(&req.namespace)?;
        crate::validation::validate_plaintext_size(&req.plaintext)?;

        // Parse key ID from bytes
        let key_id_str = String::from_utf8(req.key_id.clone())
            .map_err(|_| Status::invalid_argument("key_id must be valid UTF-8"))?;
        let key_id = KeyId::from_string(&key_id_str)
            .map_err(|_| Status::invalid_argument("Invalid key ID format"))?;

        // Get the key
        let key = self.run_km(|| self.key_manager.get_key(&key_id, &req.namespace))?;

        // Get key material for encryption
        let key_material = key
            .private_material
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("Key has no material for encryption"))?;

        // Determine AAD
        let aad = if req.associated_data.is_empty() {
            None
        } else {
            Some(req.associated_data.as_slice())
        };

        // Derive an AES-256 key from the key material
        let encryption_key = derive_aes_key(key.key_type, key_material);

        let ciphertext_with_nonce =
            AesGcmEngine::encrypt_aes256(&encryption_key, &req.plaintext, aad)
                .map_err(|e| Status::from(ApiError::CryptoError(e.to_string())))?;

        // The AES-GCM engine prepends a 12-byte nonce to the ciphertext
        let nonce = ciphertext_with_nonce[..12].to_vec();
        let ciphertext = ciphertext_with_nonce[12..].to_vec();

        // Increment operation counter (best-effort)
        let _ = self
            .key_manager
            .increment_operations(&key_id, &req.namespace);

        info!(key_id = %key_id_str, "Data encrypted");
        timer.finish_success();

        Ok(Response::new(EncryptResponse { ciphertext, nonce }))
    }

    pub fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> std::result::Result<Response<DecryptResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate inputs
        validate_key_id(&req.key_id)?;
        validate_namespace(&req.namespace)?;
        crate::validation::validate_ciphertext_size(&req.ciphertext)?;

        if req.nonce.is_empty() {
            return Err(Status::invalid_argument("nonce is required for decryption"));
        }

        // Parse key ID from bytes
        let key_id_str = String::from_utf8(req.key_id.clone())
            .map_err(|_| Status::invalid_argument("key_id must be valid UTF-8"))?;
        let key_id = KeyId::from_string(&key_id_str)
            .map_err(|_| Status::invalid_argument("Invalid key ID format"))?;

        // Get the key
        let key = self.run_km(|| self.key_manager.get_key(&key_id, &req.namespace))?;

        // Get key material for decryption
        let key_material = key
            .private_material
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("Key has no material for decryption"))?;

        // Determine AAD
        let aad = if req.associated_data.is_empty() {
            None
        } else {
            Some(req.associated_data.as_slice())
        };

        // Reconstruct the nonce || ciphertext format expected by the engine
        let mut combined = Vec::with_capacity(req.nonce.len() + req.ciphertext.len());
        combined.extend_from_slice(&req.nonce);
        combined.extend_from_slice(&req.ciphertext);

        // Derive AES key (same logic as encrypt)
        let decryption_key = derive_aes_key(key.key_type, key_material);

        let plaintext = AesGcmEngine::decrypt_aes256(&decryption_key, &combined, aad)
            .map_err(|e| Status::from(ApiError::CryptoError(e.to_string())))?;

        // Increment operation counter (best-effort)
        let _ = self
            .key_manager
            .increment_operations(&key_id, &req.namespace);

        info!(key_id = %key_id_str, "Data decrypted");
        timer.finish_success();

        Ok(Response::new(DecryptResponse { plaintext }))
    }

    // ========================================================================
    // Batch Operations
    // ========================================================================

    pub fn batch_sign(
        &self,
        request: Request<BatchSignRequest>,
    ) -> std::result::Result<Response<BatchSignResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        validate_batch_size(req.requests.len(), "sign")?;

        let mut responses = Vec::with_capacity(req.requests.len());
        let mut errors = Vec::with_capacity(req.requests.len());

        for sign_req in &req.requests {
            match self.sign(Request::new(sign_req.clone())) {
                Ok(resp) => {
                    responses.push(resp.into_inner());
                    errors.push(String::new());
                }
                Err(status) => {
                    responses.push(SignResponse {
                        signature: Vec::new(),
                        algorithm: String::new(),
                    });
                    errors.push(status.message().to_string());
                }
            }
        }

        timer.finish_success();
        Ok(Response::new(BatchSignResponse { responses, errors }))
    }

    pub fn batch_verify(
        &self,
        request: Request<BatchVerifyRequest>,
    ) -> std::result::Result<Response<BatchVerifyResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        validate_batch_size(req.requests.len(), "verify")?;

        let mut responses = Vec::with_capacity(req.requests.len());
        let mut errors = Vec::with_capacity(req.requests.len());

        for verify_req in &req.requests {
            match self.verify(Request::new(verify_req.clone())) {
                Ok(resp) => {
                    responses.push(resp.into_inner());
                    errors.push(String::new());
                }
                Err(status) => {
                    responses.push(VerifyResponse { valid: false });
                    errors.push(status.message().to_string());
                }
            }
        }

        timer.finish_success();
        Ok(Response::new(BatchVerifyResponse { responses, errors }))
    }

    pub fn batch_encrypt(
        &self,
        request: Request<BatchEncryptRequest>,
    ) -> std::result::Result<Response<BatchEncryptResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        validate_batch_size(req.requests.len(), "encrypt")?;

        let mut responses = Vec::with_capacity(req.requests.len());
        let mut errors = Vec::with_capacity(req.requests.len());

        for encrypt_req in &req.requests {
            match self.encrypt(Request::new(encrypt_req.clone())) {
                Ok(resp) => {
                    responses.push(resp.into_inner());
                    errors.push(String::new());
                }
                Err(status) => {
                    responses.push(EncryptResponse {
                        ciphertext: Vec::new(),
                        nonce: Vec::new(),
                    });
                    errors.push(status.message().to_string());
                }
            }
        }

        timer.finish_success();
        Ok(Response::new(BatchEncryptResponse { responses, errors }))
    }

    pub fn batch_decrypt(
        &self,
        request: Request<BatchDecryptRequest>,
    ) -> std::result::Result<Response<BatchDecryptResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        validate_batch_size(req.requests.len(), "decrypt")?;

        let mut responses = Vec::with_capacity(req.requests.len());
        let mut errors = Vec::with_capacity(req.requests.len());

        for decrypt_req in &req.requests {
            match self.decrypt(Request::new(decrypt_req.clone())) {
                Ok(resp) => {
                    responses.push(resp.into_inner());
                    errors.push(String::new());
                }
                Err(status) => {
                    responses.push(DecryptResponse {
                        plaintext: Vec::new(),
                    });
                    errors.push(status.message().to_string());
                }
            }
        }

        timer.finish_success();
        Ok(Response::new(BatchDecryptResponse { responses, errors }))
    }

    // ========================================================================
    // Audit
    // ========================================================================

    pub fn get_audit_log(
        &self,
        request: Request<GetAuditLogRequest>,
    ) -> std::result::Result<Response<GetAuditLogResponse>, Status> {
        let timer = self.metrics.record_request();
        let req = request.into_inner();

        // Validate namespace if provided
        if !req.namespace.is_empty() {
            validate_namespace(&req.namespace)?;
        }

        // Note: Full audit integration requires the audit module to be wired in.
        // For now, return an empty log with the correct response structure.
        info!(
            namespace = %req.namespace,
            "Audit log requested (returning empty; audit module not yet wired)"
        );

        timer.finish_success();

        Ok(Response::new(GetAuditLogResponse {
            entries: vec![],
            next_page_token: String::new(),
            total_count: 0,
        }))
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Get current timestamp as seconds since UNIX epoch.
fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Convert a proto KeyType enum value (i32) to key-manager KeyType.
fn proto_key_type_to_km(proto_kt: i32) -> std::result::Result<KeyType, Status> {
    match proto_kt {
        1 => Ok(KeyType::Rsa2048),
        2 => Ok(KeyType::Rsa4096),
        3 => Ok(KeyType::EcdsaP256),
        4 => Ok(KeyType::EcdsaP384),
        5 => Ok(KeyType::Ed25519),
        6 => Ok(KeyType::Aes256),
        _ => Err(Status::invalid_argument(format!(
            "Invalid or unsupported key type: {}",
            proto_kt
        ))),
    }
}

/// Convert a key-manager KeyType to proto KeyType i32 value.
fn km_key_type_to_proto(km_kt: KeyType) -> i32 {
    match km_kt {
        KeyType::Rsa2048 => 1,
        KeyType::Rsa4096 => 2,
        KeyType::EcdsaP256 => 3,
        KeyType::EcdsaP384 => 4,
        KeyType::Ed25519 => 5,
        KeyType::Aes256 => 6,
        KeyType::Rsa3072 => 1, // Map to RSA_2048 as closest available
        KeyType::Aes128 => 6,  // Map to AES_256 as closest available
        _ => 0,                // Unspecified for types not in proto
    }
}

/// Convert a proto KeyState enum value (i32) to key-manager KeyState Option.
fn proto_key_state_to_km(proto_ks: i32) -> Option<KeyState> {
    match proto_ks {
        1 => Some(KeyState::Active),
        2 => Some(KeyState::Deactivated),
        3 => Some(KeyState::Compromised),
        4 => Some(KeyState::Destroyed),
        _ => None, // Unspecified means no filter
    }
}

/// Convert a key-manager KeyState to proto KeyState i32 value.
fn km_key_state_to_proto(km_ks: KeyState) -> i32 {
    match km_ks {
        KeyState::Pending => 0,
        KeyState::Active => 1,
        KeyState::Deactivated => 2,
        KeyState::Compromised => 3,
        KeyState::Destroyed => 4,
    }
}

/// Convert a proto KeyUsagePolicy to key-manager KeyUsagePolicy.
fn proto_policy_to_km(
    proto_policy: &crate::proto::hsm::KeyUsagePolicy,
) -> hsm_key_manager::KeyUsagePolicy {
    let mut can_sign = false;
    let mut can_encrypt = false;
    let mut can_derive = false;
    let can_export = proto_policy.exportable;

    for usage in &proto_policy.allowed_usages {
        match *usage {
            1 => can_sign = true,       // KEY_USAGE_SIGN
            2 => {}                     // KEY_USAGE_VERIFY (implicit with sign)
            3 => can_encrypt = true,    // KEY_USAGE_ENCRYPT
            4 => {}                     // KEY_USAGE_DECRYPT (implicit with encrypt)
            5 | 6 => can_derive = true, // KEY_USAGE_WRAP / KEY_USAGE_UNWRAP
            _ => {}
        }
    }

    // If no usages specified, default to sign + encrypt
    if proto_policy.allowed_usages.is_empty() {
        can_sign = true;
        can_encrypt = true;
    }

    let max_operations = if proto_policy.max_uses > 0 {
        Some(proto_policy.max_uses as u64)
    } else {
        None
    };

    // Proto expiry_time is seconds since UNIX epoch; convert to Option<DateTime<Utc>>
    let expires_at = if proto_policy.expiry_time > 0 {
        use std::time::{Duration, UNIX_EPOCH};
        let system_time = UNIX_EPOCH + Duration::from_secs(proto_policy.expiry_time as u64);
        // Convert SystemTime to chrono::DateTime requires the chrono feature.
        // Instead, we'll use None here since chrono isn't a direct dependency.
        // The key-manager will enforce expiration if set.
        let _ = system_time;
        None
    } else {
        None
    };

    hsm_key_manager::KeyUsagePolicy {
        can_sign,
        can_encrypt,
        can_derive,
        can_export,
        max_operations,
        expires_at,
    }
}

/// Build a proto KeyMetadata message from key-manager data.
fn build_key_metadata(
    key_id: &KeyId,
    namespace: &str,
    key_type: KeyType,
    state: KeyState,
    version: u32,
) -> KeyMetadata {
    let now = now_timestamp();

    KeyMetadata {
        key_id: key_id.to_string(),
        namespace: namespace.to_string(),
        key_type: km_key_type_to_proto(key_type),
        state: km_key_state_to_proto(state),
        policy: None,
        created_at: now,
        updated_at: now,
        version: version.to_string(),
    }
}

/// Sign data using the appropriate algorithm for the key type.
fn sign_with_key(
    key_type: KeyType,
    private_key: &KeyMaterial,
    data: &[u8],
) -> std::result::Result<(Vec<u8>, String), String> {
    match key_type {
        KeyType::Ed25519 => {
            let sig = ed25519::Ed25519Engine::sign(private_key, data).map_err(|e| e.to_string())?;
            Ok((sig, "ED25519".to_string()))
        }
        KeyType::EcdsaP256 => {
            let sig =
                ecdsa::EcdsaEngine::sign_p256(private_key, data).map_err(|e| e.to_string())?;
            Ok((sig, "ECDSA_P256".to_string()))
        }
        KeyType::EcdsaP384 => {
            let sig =
                ecdsa::EcdsaEngine::sign_p384(private_key, data).map_err(|e| e.to_string())?;
            Ok((sig, "ECDSA_P384".to_string()))
        }
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            let sig = rsa::RsaEngine::sign_pkcs1v15_sha256(private_key, data)
                .map_err(|e| e.to_string())?;
            Ok((sig, "RSA_PKCS1_V15".to_string()))
        }
        _ => Err(format!("Key type {:?} does not support signing", key_type)),
    }
}

/// Verify a signature using the appropriate algorithm for the key type.
/// Returns false for invalid signatures (rather than error) to match the REST handler pattern.
fn verify_with_key(key_type: KeyType, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    match key_type {
        KeyType::Ed25519 => {
            ed25519::Ed25519Engine::verify(public_key, data, signature).unwrap_or(false)
        }
        KeyType::EcdsaP256 => {
            ecdsa::EcdsaEngine::verify_p256(public_key, data, signature).unwrap_or(false)
        }
        KeyType::EcdsaP384 => {
            ecdsa::EcdsaEngine::verify_p384(public_key, data, signature).unwrap_or(false)
        }
        KeyType::Rsa2048 | KeyType::Rsa3072 | KeyType::Rsa4096 => {
            rsa::RsaEngine::verify_pkcs1v15_sha256(public_key, data, signature).unwrap_or(false)
        }
        _ => false,
    }
}

/// Derive an AES-256 key from the given key material.
/// For symmetric keys (Aes256, Aes128), the key material is used directly.
/// For asymmetric keys, the first 32 bytes of private key material are used.
fn derive_aes_key(key_type: KeyType, key_material: &KeyMaterial) -> KeyMaterial {
    match key_type {
        KeyType::Aes256 | KeyType::Aes128 => key_material.clone(),
        _ => {
            let key_bytes = key_material.as_bytes();
            let aes_key_bytes = if key_bytes.len() >= 32 {
                key_bytes[..32].to_vec()
            } else {
                let mut padded = key_bytes.to_vec();
                padded.resize(32, 0);
                padded
            };
            KeyMaterial::from_bytes(aes_key_bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check() {
        let handler = SimpleHsmHandler::new();
        let request = Request::new(HealthCheckRequest {
            service: String::new(),
        });
        let response = handler.health_check(request);
        assert!(response.is_ok());
        let resp = response.unwrap().into_inner();
        assert_eq!(
            resp.status,
            health_check_response::ServingStatus::Serving as i32
        );
        assert_eq!(resp.message, "Service is healthy");
    }

    #[test]
    fn test_generate_and_get_key() {
        let handler = SimpleHsmHandler::new();

        // Generate a key
        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5, // ED25519
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_response = handler.generate_key(gen_request);
        assert!(
            gen_response.is_ok(),
            "generate_key failed: {:?}",
            gen_response.err()
        );

        let gen_resp = gen_response.unwrap().into_inner();
        assert!(!gen_resp.key_id.is_empty());
        assert!(!gen_resp.public_key.is_empty());

        // Get the key
        let get_request = Request::new(GetKeyRequest {
            key_id: gen_resp.key_id.clone(),
            namespace: "test-ns".to_string(),
        });
        let get_response = handler.get_key(get_request);
        assert!(
            get_response.is_ok(),
            "get_key failed: {:?}",
            get_response.err()
        );

        let get_resp = get_response.unwrap().into_inner();
        assert!(get_resp.metadata.is_some());
        let meta = get_resp.metadata.unwrap();
        assert_eq!(meta.key_id, gen_resp.key_id);
    }

    #[test]
    fn test_delete_key() {
        let handler = SimpleHsmHandler::new();

        // Generate a key first
        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5, // ED25519
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_resp = handler.generate_key(gen_request).unwrap().into_inner();

        // Delete it
        let del_request = Request::new(DeleteKeyRequest {
            key_id: gen_resp.key_id.clone(),
            namespace: "test-ns".to_string(),
        });
        let del_response = handler.delete_key(del_request);
        assert!(del_response.is_ok());
        assert!(del_response.unwrap().into_inner().success);
    }

    #[test]
    fn test_rotate_key() {
        let handler = SimpleHsmHandler::new();

        // Generate a key first
        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5, // ED25519
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_resp = handler.generate_key(gen_request).unwrap().into_inner();

        // Rotate it
        let rot_request = Request::new(RotateKeyRequest {
            key_id: gen_resp.key_id.clone(),
            namespace: "test-ns".to_string(),
        });
        let rot_response = handler.rotate_key(rot_request);
        assert!(
            rot_response.is_ok(),
            "rotate_key failed: {:?}",
            rot_response.err()
        );

        let rot_resp = rot_response.unwrap().into_inner();
        assert!(!rot_resp.new_key_id.is_empty());
        assert_ne!(rot_resp.new_key_id, gen_resp.key_id);
    }

    #[test]
    fn test_sign_and_verify() {
        let handler = SimpleHsmHandler::new();

        // Generate a key
        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5, // ED25519
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_resp = handler.generate_key(gen_request).unwrap().into_inner();

        let key_id_bytes = gen_resp.key_id.as_bytes().to_vec();
        let data = b"Hello, HSM!".to_vec();

        // Sign
        let sign_request = Request::new(SignRequest {
            key_id: key_id_bytes.clone(),
            namespace: "test-ns".to_string(),
            data: data.clone(),
            algorithm: String::new(),
        });
        let sign_response = handler.sign(sign_request);
        assert!(
            sign_response.is_ok(),
            "sign failed: {:?}",
            sign_response.err()
        );

        let sign_resp = sign_response.unwrap().into_inner();
        assert!(!sign_resp.signature.is_empty());
        assert_eq!(sign_resp.algorithm, "ED25519");

        // Verify valid signature
        let verify_request = Request::new(VerifyRequest {
            key_id: key_id_bytes.clone(),
            namespace: "test-ns".to_string(),
            data: data.clone(),
            signature: sign_resp.signature.clone(),
            algorithm: "ED25519".to_string(),
        });
        let verify_response = handler.verify(verify_request);
        assert!(
            verify_response.is_ok(),
            "verify failed: {:?}",
            verify_response.err()
        );
        assert!(verify_response.unwrap().into_inner().valid);

        // Verify with wrong data should return valid=false
        let verify_wrong = Request::new(VerifyRequest {
            key_id: key_id_bytes,
            namespace: "test-ns".to_string(),
            data: b"Wrong data".to_vec(),
            signature: sign_resp.signature,
            algorithm: "ED25519".to_string(),
        });
        let verify_wrong_resp = handler.verify(verify_wrong);
        assert!(verify_wrong_resp.is_ok());
        assert!(!verify_wrong_resp.unwrap().into_inner().valid);
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let handler = SimpleHsmHandler::new();

        // Generate an Ed25519 key (we derive an AES key from its private material)
        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5, // ED25519
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_resp = handler.generate_key(gen_request).unwrap().into_inner();
        let key_id_bytes = gen_resp.key_id.as_bytes().to_vec();

        let plaintext = b"Secret message for encryption".to_vec();

        // Encrypt
        let enc_request = Request::new(EncryptRequest {
            key_id: key_id_bytes.clone(),
            namespace: "test-ns".to_string(),
            plaintext: plaintext.clone(),
            associated_data: Vec::new(),
        });
        let enc_response = handler.encrypt(enc_request);
        assert!(
            enc_response.is_ok(),
            "encrypt failed: {:?}",
            enc_response.err()
        );

        let enc_resp = enc_response.unwrap().into_inner();
        assert!(!enc_resp.ciphertext.is_empty());
        assert!(!enc_resp.nonce.is_empty());

        // Decrypt
        let dec_request = Request::new(DecryptRequest {
            key_id: key_id_bytes,
            namespace: "test-ns".to_string(),
            ciphertext: enc_resp.ciphertext,
            nonce: enc_resp.nonce,
            associated_data: Vec::new(),
        });
        let dec_response = handler.decrypt(dec_request);
        assert!(
            dec_response.is_ok(),
            "decrypt failed: {:?}",
            dec_response.err()
        );

        let dec_resp = dec_response.unwrap().into_inner();
        assert_eq!(dec_resp.plaintext, plaintext);
    }

    #[test]
    fn test_batch_sign() {
        let handler = SimpleHsmHandler::new();

        // Generate a key
        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5, // ED25519
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_resp = handler.generate_key(gen_request).unwrap().into_inner();
        let key_id_bytes = gen_resp.key_id.as_bytes().to_vec();

        // Create batch sign request
        let requests = vec![
            SignRequest {
                key_id: key_id_bytes.clone(),
                namespace: "test-ns".to_string(),
                data: b"message 1".to_vec(),
                algorithm: String::new(),
            },
            SignRequest {
                key_id: key_id_bytes,
                namespace: "test-ns".to_string(),
                data: b"message 2".to_vec(),
                algorithm: String::new(),
            },
        ];

        let batch_request = Request::new(BatchSignRequest {
            requests,
            parallel: false,
        });
        let batch_response = handler.batch_sign(batch_request);
        assert!(batch_response.is_ok());

        let batch_resp = batch_response.unwrap().into_inner();
        assert_eq!(batch_resp.responses.len(), 2);
        assert_eq!(batch_resp.errors.len(), 2);
        // Both should succeed
        assert!(batch_resp.errors[0].is_empty());
        assert!(batch_resp.errors[1].is_empty());
        assert!(!batch_resp.responses[0].signature.is_empty());
        assert!(!batch_resp.responses[1].signature.is_empty());
    }

    #[test]
    fn test_get_audit_log() {
        let handler = SimpleHsmHandler::new();
        let request = Request::new(GetAuditLogRequest {
            namespace: "test-ns".to_string(),
            start_time: 0,
            end_time: 0,
            user_id: String::new(),
            operation: String::new(),
            page_size: 10,
            page_token: String::new(),
        });
        let response = handler.get_audit_log(request);
        assert!(response.is_ok());
        let resp = response.unwrap().into_inner();
        assert_eq!(resp.total_count, 0);
        assert!(resp.entries.is_empty());
    }

    #[test]
    fn test_list_keys_collected() {
        let handler = SimpleHsmHandler::new();

        // Generate two keys
        for _ in 0..2 {
            let gen_request = Request::new(GenerateKeyRequest {
                namespace: "list-ns".to_string(),
                key_type: 5, // ED25519
                policy: None,
                metadata: HashMap::new(),
            });
            handler.generate_key(gen_request).unwrap();
        }

        // List them
        let result = handler.list_keys_collected("list-ns", 0, 10);
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_invalid_key_id() {
        let handler = SimpleHsmHandler::new();
        let request = Request::new(GetKeyRequest {
            key_id: String::new(), // Empty key ID
            namespace: "test-ns".to_string(),
        });
        let response = handler.get_key(request);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_invalid_namespace() {
        let handler = SimpleHsmHandler::new();
        let request = Request::new(GenerateKeyRequest {
            namespace: "invalid namespace!".to_string(), // Invalid chars
            key_type: 5,
            policy: None,
            metadata: HashMap::new(),
        });
        let response = handler.generate_key(request);
        assert!(response.is_err());
        assert_eq!(response.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn test_proto_key_type_conversion() {
        assert!(matches!(proto_key_type_to_km(1), Ok(KeyType::Rsa2048)));
        assert!(matches!(proto_key_type_to_km(5), Ok(KeyType::Ed25519)));
        assert!(proto_key_type_to_km(99).is_err());
    }

    #[test]
    fn test_km_key_state_conversion() {
        assert_eq!(km_key_state_to_proto(KeyState::Active), 1);
        assert_eq!(km_key_state_to_proto(KeyState::Destroyed), 4);
    }

    #[test]
    fn test_encrypt_with_aad() {
        let handler = SimpleHsmHandler::new();

        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5, // ED25519
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_resp = handler.generate_key(gen_request).unwrap().into_inner();
        let key_id_bytes = gen_resp.key_id.as_bytes().to_vec();

        let plaintext = b"data with AAD".to_vec();
        let aad = b"additional authenticated data".to_vec();

        // Encrypt with AAD
        let enc_request = Request::new(EncryptRequest {
            key_id: key_id_bytes.clone(),
            namespace: "test-ns".to_string(),
            plaintext: plaintext.clone(),
            associated_data: aad.clone(),
        });
        let enc_resp = handler.encrypt(enc_request).unwrap().into_inner();

        // Decrypt with correct AAD
        let dec_request = Request::new(DecryptRequest {
            key_id: key_id_bytes.clone(),
            namespace: "test-ns".to_string(),
            ciphertext: enc_resp.ciphertext.clone(),
            nonce: enc_resp.nonce.clone(),
            associated_data: aad,
        });
        let dec_resp = handler.decrypt(dec_request).unwrap().into_inner();
        assert_eq!(dec_resp.plaintext, plaintext);

        // Decrypt with wrong AAD should fail
        let dec_wrong = Request::new(DecryptRequest {
            key_id: key_id_bytes,
            namespace: "test-ns".to_string(),
            ciphertext: enc_resp.ciphertext,
            nonce: enc_resp.nonce,
            associated_data: b"wrong aad".to_vec(),
        });
        assert!(handler.decrypt(dec_wrong).is_err());
    }

    #[test]
    fn test_decrypt_missing_nonce() {
        let handler = SimpleHsmHandler::new();

        let gen_request = Request::new(GenerateKeyRequest {
            namespace: "test-ns".to_string(),
            key_type: 5,
            policy: None,
            metadata: HashMap::new(),
        });
        let gen_resp = handler.generate_key(gen_request).unwrap().into_inner();
        let key_id_bytes = gen_resp.key_id.as_bytes().to_vec();

        let dec_request = Request::new(DecryptRequest {
            key_id: key_id_bytes,
            namespace: "test-ns".to_string(),
            ciphertext: b"some ciphertext".to_vec(),
            nonce: Vec::new(), // Missing nonce
            associated_data: Vec::new(),
        });
        let result = handler.decrypt(dec_request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }
}
