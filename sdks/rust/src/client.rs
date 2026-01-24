//! HSM Client Implementation

use crate::crypto::normalize_to_base64;
use crate::error::{parse_error_response, HsmError, Result};
use crate::types::*;
use parking_lot::RwLock;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Token manager for handling session tokens.
pub struct TokenManager {
    session_id: RwLock<Option<String>>,
    session_token: RwLock<Option<String>>,
    operation_count: AtomicU32,
    max_operations: u32,
}

impl TokenManager {
    /// Create a new token manager.
    pub fn new(session_id: Option<String>, session_token: Option<String>) -> Self {
        Self {
            session_id: RwLock::new(session_id),
            session_token: RwLock::new(session_token),
            operation_count: AtomicU32::new(0),
            max_operations: 900,
        }
    }

    /// Set credentials.
    pub fn set_credentials(&self, session_id: String, session_token: String) {
        *self.session_id.write() = Some(session_id);
        *self.session_token.write() = Some(session_token);
        self.operation_count.store(0, Ordering::SeqCst);
    }

    /// Clear credentials.
    pub fn clear_credentials(&self) {
        *self.session_id.write() = None;
        *self.session_token.write() = None;
        self.operation_count.store(0, Ordering::SeqCst);
    }

    /// Check if authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.session_id.read().is_some() && self.session_token.read().is_some()
    }

    /// Get authorization header.
    pub fn get_authorization_header(&self) -> Option<String> {
        let id = self.session_id.read();
        let token = self.session_token.read();
        match (id.as_ref(), token.as_ref()) {
            (Some(id), Some(token)) => Some(format!("Bearer {}:{}", id, token)),
            _ => None,
        }
    }

    /// Increment operation count.
    pub fn increment_operation_count(&self) -> bool {
        let count = self.operation_count.fetch_add(1, Ordering::SeqCst) + 1;
        count >= self.max_operations
    }

    /// Get operation count.
    pub fn operation_count(&self) -> u32 {
        self.operation_count.load(Ordering::SeqCst)
    }
}

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker for resilient connections.
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    last_failure_time: RwLock<Option<Instant>>,
    success_count: AtomicU32,
    failure_threshold: u32,
    recovery_timeout: Duration,
    success_threshold: u32,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    pub fn new(failure_threshold: u32, recovery_timeout: Duration, success_threshold: u32) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            last_failure_time: RwLock::new(None),
            success_count: AtomicU32::new(0),
            failure_threshold,
            recovery_timeout,
            success_threshold,
        }
    }

    /// Check if request should be allowed.
    pub fn can_request(&self) -> bool {
        let state = *self.state.read();
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(last_failure) = *self.last_failure_time.read() {
                    if last_failure.elapsed() >= self.recovery_timeout {
                        *self.state.write() = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::SeqCst);
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        let state = *self.state.read();
        match state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.success_threshold {
                    *self.state.write() = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                }
            }
            CircuitState::Closed => {
                self.failure_count.store(0, Ordering::SeqCst);
            }
            _ => {}
        }
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        *self.last_failure_time.write() = Some(Instant::now());

        let state = *self.state.read();
        if state == CircuitState::HalfOpen || count >= self.failure_threshold {
            *self.state.write() = CircuitState::Open;
        }
    }

    /// Get current state.
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Reset the circuit breaker.
    pub fn reset(&self) {
        *self.state.write() = CircuitState::Closed;
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
    }
}

/// Retry strategy with exponential backoff.
pub struct RetryStrategy {
    max_retries: u32,
    base_delay: Duration,
    max_delay: Duration,
    jitter: f64,
    retry_on_status: Vec<u16>,
}

impl RetryStrategy {
    /// Create a new retry strategy.
    pub fn new(config: Option<RetryConfig>) -> Self {
        let config = config.unwrap_or_default();
        Self {
            max_retries: config.max_retries,
            base_delay: config.base_delay,
            max_delay: config.max_delay,
            jitter: config.jitter,
            retry_on_status: config.retry_on_status,
        }
    }

    /// Check if status code should be retried.
    pub fn should_retry(&self, status_code: u16, attempt: u32) -> bool {
        attempt < self.max_retries && self.retry_on_status.contains(&status_code)
    }

    /// Calculate delay for next retry.
    pub fn get_delay(&self, attempt: u32) -> Duration {
        let exponential_delay = self.base_delay * 2u32.pow(attempt);
        let capped_delay = exponential_delay.min(self.max_delay);
        let jitter_amount = capped_delay.mul_f64(self.jitter * rand_f64());
        capped_delay + jitter_amount
    }

    /// Sleep for the calculated delay.
    pub async fn sleep(&self, attempt: u32) {
        let delay = self.get_delay(attempt);
        tokio::time::sleep(delay).await;
    }
}

fn rand_f64() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos as f64) / (u32::MAX as f64)
}

/// Key manager for convenient key operations.
pub struct KeyManager {
    client: Arc<HsmClient>,
}

impl KeyManager {
    /// Generate an Ed25519 signing key.
    pub async fn generate_ed25519(
        &self,
        key_id: Option<String>,
        namespace: Option<String>,
        labels: Option<HashMap<String, String>>,
    ) -> Result<GenerateKeyResponse> {
        self.client
            .generate_key(GenerateKeyRequest {
                key_id,
                algorithm: KeyAlgorithm::Ed25519,
                purpose: KeyPurpose::Sign,
                namespace,
                labels,
            })
            .await
    }

    /// Generate an ECDSA P-256 key.
    pub async fn generate_ecdsa_p256(
        &self,
        key_id: Option<String>,
        namespace: Option<String>,
        labels: Option<HashMap<String, String>>,
    ) -> Result<GenerateKeyResponse> {
        self.client
            .generate_key(GenerateKeyRequest {
                key_id,
                algorithm: KeyAlgorithm::EcdsaP256,
                purpose: KeyPurpose::Sign,
                namespace,
                labels,
            })
            .await
    }

    /// Generate an RSA key.
    pub async fn generate_rsa(
        &self,
        size: u32,
        key_id: Option<String>,
        namespace: Option<String>,
        labels: Option<HashMap<String, String>>,
    ) -> Result<GenerateKeyResponse> {
        let algorithm = match size {
            2048 => KeyAlgorithm::Rsa2048,
            3072 => KeyAlgorithm::Rsa3072,
            4096 => KeyAlgorithm::Rsa4096,
            _ => return Err(HsmError::validation(format!("Invalid RSA size: {}", size))),
        };

        self.client
            .generate_key(GenerateKeyRequest {
                key_id,
                algorithm,
                purpose: KeyPurpose::Sign,
                namespace,
                labels,
            })
            .await
    }

    /// Generate an AES encryption key.
    pub async fn generate_aes(
        &self,
        size: u32,
        key_id: Option<String>,
        namespace: Option<String>,
        labels: Option<HashMap<String, String>>,
    ) -> Result<GenerateKeyResponse> {
        let algorithm = match size {
            128 => KeyAlgorithm::Aes128,
            256 => KeyAlgorithm::Aes256,
            _ => return Err(HsmError::validation(format!("Invalid AES size: {}", size))),
        };

        self.client
            .generate_key(GenerateKeyRequest {
                key_id,
                algorithm,
                purpose: KeyPurpose::Encrypt,
                namespace,
                labels,
            })
            .await
    }

    /// Get key metadata.
    pub async fn get(&self, key_id: &str) -> Result<KeyMetadata> {
        self.client.get_key(key_id).await
    }

    /// List keys.
    pub async fn list(&self, options: Option<ListKeysOptions>) -> Result<ListKeysResponse> {
        self.client.list_keys(options).await
    }

    /// Delete a key.
    pub async fn delete(&self, key_id: &str) -> Result<()> {
        self.client.delete_key(key_id).await
    }

    /// Check if a key exists.
    pub async fn exists(&self, key_id: &str) -> bool {
        self.client.get_key(key_id).await.is_ok()
    }
}

/// HSM Client for interacting with HSM server.
pub struct HsmClient {
    base_url: String,
    http_client: Client,
    headers: HashMap<String, String>,
    token_manager: TokenManager,
    circuit_breaker: CircuitBreaker,
    retry_strategy: RetryStrategy,
}

impl HsmClient {
    /// Create a new HSM client.
    pub fn new(config: ClientConfig) -> Arc<Self> {
        let base_url = config.base_url.trim_end_matches('/').to_string();

        let http_client = Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Arc::new(Self {
            base_url,
            http_client,
            headers: config.headers,
            token_manager: TokenManager::new(config.session_id, config.session_token),
            circuit_breaker: CircuitBreaker::new(5, Duration::from_secs(30), 2),
            retry_strategy: RetryStrategy::new(config.retry),
        })
    }

    /// Get key manager.
    pub fn keys(self: &Arc<Self>) -> KeyManager {
        KeyManager {
            client: Arc::clone(self),
        }
    }

    /// Set credentials.
    pub fn set_credentials(&self, session_id: String, session_token: String) {
        self.token_manager.set_credentials(session_id, session_token);
    }

    /// Clear credentials.
    pub fn clear_credentials(&self) {
        self.token_manager.clear_credentials();
    }

    /// Check if authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.token_manager.is_authenticated()
    }

    /// Get circuit state.
    pub fn circuit_state(&self) -> CircuitState {
        self.circuit_breaker.state()
    }

    /// Reset circuit breaker.
    pub fn reset_circuit_breaker(&self) {
        self.circuit_breaker.reset();
    }

    /// Get operation count.
    pub fn operation_count(&self) -> u32 {
        self.token_manager.operation_count()
    }

    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        attempt: u32,
    ) -> Result<T> {
        if !self.circuit_breaker.can_request() {
            return Err(HsmError::CircuitOpen);
        }

        let url = format!("{}{}", self.base_url, path);

        let mut request = self.http_client.request(method.clone(), &url);

        for (key, value) in &self.headers {
            request = request.header(key, value);
        }

        if let Some(auth) = self.token_manager.get_authorization_header() {
            request = request.header("Authorization", auth);
        }

        if let Some(body) = &body {
            request = request.json(body);
        }

        let response = request.send().await.map_err(|e| {
            self.circuit_breaker.record_failure();
            HsmError::Network {
                message: e.to_string(),
                source: Some(e),
            }
        })?;

        let status = response.status().as_u16();

        if status >= 400 {
            let error_body: serde_json::Value = response.json().await.unwrap_or_default();

            if self.retry_strategy.should_retry(status, attempt) {
                self.circuit_breaker.record_failure();
                self.retry_strategy.sleep(attempt).await;
                return self.request(method, path, body, attempt + 1).await;
            }

            self.circuit_breaker.record_failure();
            return Err(parse_error_response(status, &error_body));
        }

        self.circuit_breaker.record_success();
        self.token_manager.increment_operation_count();

        let text = response.text().await?;
        if text.is_empty() {
            return serde_json::from_str("{}").map_err(Into::into);
        }

        serde_json::from_str(&text).map_err(Into::into)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::GET, path, None, 0).await
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T> {
        self.request(reqwest::Method::POST, path, Some(body), 0).await
    }

    async fn delete<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::DELETE, path, None, 0).await
    }

    /// Check server health.
    pub async fn health(&self) -> Result<HealthResponse> {
        self.get("/health").await
    }

    /// Check server readiness.
    pub async fn ready(&self) -> Result<ReadyResponse> {
        self.get("/ready").await
    }

    /// Generate a new key.
    pub async fn generate_key(&self, request: GenerateKeyRequest) -> Result<GenerateKeyResponse> {
        self.post("/keys", serde_json::to_value(request)?).await
    }

    /// Get key metadata.
    pub async fn get_key(&self, key_id: &str) -> Result<KeyMetadata> {
        self.get(&format!("/keys/{}", urlencoding::encode(key_id)))
            .await
    }

    /// List keys.
    pub async fn list_keys(&self, options: Option<ListKeysOptions>) -> Result<ListKeysResponse> {
        let mut path = "/keys".to_string();
        if let Some(opts) = options {
            let mut params = Vec::new();
            if let Some(ns) = opts.namespace {
                params.push(format!("namespace={}", urlencoding::encode(&ns)));
            }
            if let Some(limit) = opts.limit {
                params.push(format!("limit={}", limit));
            }
            if let Some(cursor) = opts.cursor {
                params.push(format!("cursor={}", urlencoding::encode(&cursor)));
            }
            if let Some(state) = opts.state {
                params.push(format!("state={:?}", state));
            }
            if !params.is_empty() {
                path = format!("{}?{}", path, params.join("&"));
            }
        }
        self.get(&path).await
    }

    /// Delete a key.
    pub async fn delete_key(&self, key_id: &str) -> Result<()> {
        let _: serde_json::Value = self
            .delete(&format!("/keys/{}", urlencoding::encode(key_id)))
            .await?;
        Ok(())
    }

    /// Sign data with a key.
    pub async fn sign(
        &self,
        key_id: &str,
        data: &[u8],
        hash_algorithm: Option<&str>,
    ) -> Result<SignResponse> {
        let mut body = serde_json::json!({
            "data": normalize_to_base64(data),
        });
        if let Some(alg) = hash_algorithm {
            body["hash_algorithm"] = serde_json::Value::String(alg.to_string());
        }
        self.post(
            &format!("/keys/{}/sign", urlencoding::encode(key_id)),
            body,
        )
        .await
    }

    /// Verify a signature.
    pub async fn verify(
        &self,
        key_id: &str,
        data: &[u8],
        signature: &str,
    ) -> Result<VerifyResponse> {
        let body = serde_json::json!({
            "data": normalize_to_base64(data),
            "signature": signature,
        });
        self.post(
            &format!("/keys/{}/verify", urlencoding::encode(key_id)),
            body,
        )
        .await
    }

    /// Encrypt data with a key.
    pub async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&str>,
    ) -> Result<EncryptResponse> {
        let mut body = serde_json::json!({
            "plaintext": normalize_to_base64(plaintext),
        });
        if let Some(aad) = aad {
            body["aad"] = serde_json::Value::String(aad.to_string());
        }
        self.post(
            &format!("/keys/{}/encrypt", urlencoding::encode(key_id)),
            body,
        )
        .await
    }

    /// Decrypt data with a key.
    pub async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &str,
        nonce: &str,
        tag: Option<&str>,
        aad: Option<&str>,
    ) -> Result<DecryptResponse> {
        let mut body = serde_json::json!({
            "ciphertext": ciphertext,
            "nonce": nonce,
        });
        if let Some(tag) = tag {
            body["tag"] = serde_json::Value::String(tag.to_string());
        }
        if let Some(aad) = aad {
            body["aad"] = serde_json::Value::String(aad.to_string());
        }
        self.post(
            &format!("/keys/{}/decrypt", urlencoding::encode(key_id)),
            body,
        )
        .await
    }

    /// Get audit log entries.
    pub async fn get_audit_log(
        &self,
        options: Option<AuditLogOptions>,
    ) -> Result<AuditLogResponse> {
        let mut path = "/audit".to_string();
        if let Some(opts) = options {
            let mut params = Vec::new();
            if let Some(ns) = opts.namespace {
                params.push(format!("namespace={}", urlencoding::encode(&ns)));
            }
            if let Some(start) = opts.start_time {
                params.push(format!("start_time={}", urlencoding::encode(&start)));
            }
            if let Some(end) = opts.end_time {
                params.push(format!("end_time={}", urlencoding::encode(&end)));
            }
            if let Some(user) = opts.user_id {
                params.push(format!("user_id={}", urlencoding::encode(&user)));
            }
            if let Some(op) = opts.operation {
                params.push(format!("operation={}", urlencoding::encode(&op)));
            }
            if let Some(limit) = opts.limit {
                params.push(format!("limit={}", limit));
            }
            if let Some(cursor) = opts.cursor {
                params.push(format!("cursor={}", urlencoding::encode(&cursor)));
            }
            if !params.is_empty() {
                path = format!("{}?{}", path, params.join("&"));
            }
        }
        self.get(&path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_manager() {
        let tm = TokenManager::new(Some("session".into()), Some("token".into()));
        assert!(tm.is_authenticated());
        assert_eq!(
            tm.get_authorization_header(),
            Some("Bearer session:token".to_string())
        );

        tm.clear_credentials();
        assert!(!tm.is_authenticated());
    }

    #[test]
    fn test_circuit_breaker() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30), 2);
        assert!(cb.can_request());
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_request());

        cb.reset();
        assert!(cb.can_request());
    }
}
