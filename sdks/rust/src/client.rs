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
    ///
    /// The exponential term saturates at `max_delay` instead of overflowing:
    /// `base_delay * 2^attempt` panics once `attempt` reaches 32, and this is a
    /// public method that callers may drive with an arbitrary attempt number.
    pub fn get_delay(&self, attempt: u32) -> Duration {
        let capped_delay = 2u32
            .checked_pow(attempt)
            .and_then(|factor| self.base_delay.checked_mul(factor))
            .unwrap_or(self.max_delay)
            .min(self.max_delay);
        let jitter_amount = capped_delay.mul_f64(self.jitter * rand_f64());
        capped_delay + jitter_amount
    }

    /// Sleep for the calculated delay.
    pub async fn sleep(&self, attempt: u32) {
        let delay = self.get_delay(attempt);
        tokio::time::sleep(delay).await;
    }
}

/// Uniform random value in `[0, 1)`, used to jitter retry backoff.
///
/// Drawn from the OS CSPRNG rather than the clock: jitter exists to de-correlate
/// retries across clients, and a clock-derived value gives every client that
/// failed at the same instant nearly the same delay — exactly the thundering
/// herd it is meant to prevent. Falls back to the clock only if the entropy
/// source is unavailable, so backoff never panics.
fn rand_f64() -> f64 {
    let raw = getrandom::u32().unwrap_or_else(|_| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    });
    f64::from(raw) / (f64::from(u32::MAX) + 1.0)
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
        self.token_manager
            .set_credentials(session_id, session_token);
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

    /// Send a request, retrying retryable statuses with exponential backoff.
    ///
    /// The retry loop is written iteratively rather than as a recursive `async fn`:
    /// a recursive `async fn` builds an infinitely sized future and would need
    /// `Box::pin` indirection (plus a heap allocation and a stack frame per attempt).
    /// The recursion here is pure tail recursion over `attempt`, so a `loop` is both
    /// the cheaper and the more direct expression of it.
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        attempt: u32,
    ) -> Result<T> {
        let mut attempt = attempt;

        loop {
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
                if e.is_timeout() {
                    HsmError::Timeout
                } else {
                    HsmError::Network {
                        message: e.to_string(),
                        source: Some(e),
                    }
                }
            })?;

            let status = response.status().as_u16();

            if status >= 400 {
                let error_body: serde_json::Value = response.json().await.unwrap_or_default();

                self.circuit_breaker.record_failure();

                if self.retry_strategy.should_retry(status, attempt) {
                    self.retry_strategy.sleep(attempt).await;
                    attempt += 1;
                    continue;
                }

                return Err(parse_error_response(status, &error_body));
            }

            self.circuit_breaker.record_success();
            self.token_manager.increment_operation_count();

            let text = response.text().await?;
            if text.trim().is_empty() {
                return serde_json::from_str("{}").map_err(Into::into);
            }

            return serde_json::from_str(&text).map_err(Into::into);
        }
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::GET, path, None, 0).await
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T> {
        self.request(reqwest::Method::POST, path, Some(body), 0)
            .await
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
        self.get(&list_keys_path(options.as_ref())).await
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
        self.post(&format!("/keys/{}/sign", urlencoding::encode(key_id)), body)
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
        self.get(&audit_log_path(options.as_ref())).await
    }
}

/// Join `base` with the already-encoded `params`, omitting `?` when empty.
fn with_query(base: &str, params: &[String]) -> String {
    if params.is_empty() {
        base.to_string()
    } else {
        format!("{}?{}", base, params.join("&"))
    }
}

/// Build the `/keys` request path for the given filter options.
fn list_keys_path(options: Option<&ListKeysOptions>) -> String {
    let Some(opts) = options else {
        return "/keys".to_string();
    };

    let mut params = Vec::new();
    if let Some(ns) = &opts.namespace {
        params.push(format!("namespace={}", urlencoding::encode(ns)));
    }
    if let Some(limit) = opts.limit {
        params.push(format!("limit={}", limit));
    }
    if let Some(cursor) = &opts.cursor {
        params.push(format!("cursor={}", urlencoding::encode(cursor)));
    }
    if let Some(state) = opts.state {
        // `as_str`, not `Debug`: the API expects the SCREAMING_SNAKE_CASE wire
        // value (`ACTIVE`), which is what the Go/Python/TypeScript SDKs send.
        params.push(format!("state={}", urlencoding::encode(state.as_str())));
    }
    with_query("/keys", &params)
}

/// Build the `/audit` request path for the given filter options.
fn audit_log_path(options: Option<&AuditLogOptions>) -> String {
    let Some(opts) = options else {
        return "/audit".to_string();
    };

    let mut params = Vec::new();
    if let Some(ns) = &opts.namespace {
        params.push(format!("namespace={}", urlencoding::encode(ns)));
    }
    if let Some(start) = &opts.start_time {
        params.push(format!("start_time={}", urlencoding::encode(start)));
    }
    if let Some(end) = &opts.end_time {
        params.push(format!("end_time={}", urlencoding::encode(end)));
    }
    if let Some(user) = &opts.user_id {
        params.push(format!("user_id={}", urlencoding::encode(user)));
    }
    if let Some(op) = &opts.operation {
        params.push(format!("operation={}", urlencoding::encode(op)));
    }
    if let Some(limit) = opts.limit {
        params.push(format!("limit={}", limit));
    }
    if let Some(cursor) = &opts.cursor {
        params.push(format!("cursor={}", urlencoding::encode(cursor)));
    }
    with_query("/audit", &params)
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

    #[test]
    fn key_state_query_value_matches_the_wire_format() {
        // `format!("{:?}", KeyState::Active)` yields "Active", which the API does
        // not accept. The query string must carry the serde representation.
        for state in [
            KeyState::Active,
            KeyState::Inactive,
            KeyState::Compromised,
            KeyState::Destroyed,
        ] {
            let serialized = serde_json::to_string(&state).unwrap();
            assert_eq!(
                format!("\"{}\"", state.as_str()),
                serialized,
                "as_str drifted from the Serialize impl"
            );
            assert_ne!(state.as_str(), format!("{:?}", state));
        }
    }

    #[test]
    fn get_delay_saturates_instead_of_overflowing() {
        let strategy = RetryStrategy::new(Some(RetryConfig {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            jitter: 0.0,
            retry_on_status: vec![429],
        }));

        assert_eq!(strategy.get_delay(0), Duration::from_millis(100));
        assert_eq!(strategy.get_delay(1), Duration::from_millis(200));
        assert_eq!(strategy.get_delay(2), Duration::from_millis(400));
        // 2^32 overflowed `u32::pow` and panicked before; now it clamps.
        assert_eq!(strategy.get_delay(32), Duration::from_secs(5));
        assert_eq!(strategy.get_delay(u32::MAX), Duration::from_secs(5));
    }

    #[test]
    fn percent_encoding_is_safe_in_both_path_and_query_position() {
        // The same helper encodes path segments (`/keys/{key_id}`) and query
        // values. It must percent-encode everything outside the RFC 3986
        // unreserved set, and must NOT use the `application/x-www-form-urlencoded`
        // convention of writing a space as `+` — that would be a literal `+` when
        // a server parses it as a path segment.
        assert_eq!(urlencoding::encode("a b"), "a%20b");
        assert_eq!(urlencoding::encode("a/b"), "a%2Fb");
        assert_eq!(urlencoding::encode("a?b"), "a%3Fb");
        assert_eq!(urlencoding::encode("a#b"), "a%23b");
        assert_eq!(urlencoding::encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencoding::encode("a+b"), "a%2Bb");
        assert_eq!(urlencoding::encode("100%"), "100%25");
        assert_eq!(urlencoding::encode("a..b"), "a..b");
        // Unreserved characters survive untouched in both positions.
        assert_eq!(urlencoding::encode("Az0-_.~"), "Az0-_.~");
    }

    #[test]
    fn list_keys_path_encodes_and_omits_empty_query() {
        assert_eq!(list_keys_path(None), "/keys");
        assert_eq!(
            list_keys_path(Some(&ListKeysOptions::default())),
            "/keys",
            "an all-None filter must not append a bare `?`"
        );
        assert_eq!(
            list_keys_path(Some(&ListKeysOptions {
                namespace: Some("prod team".into()),
                limit: Some(25),
                cursor: Some("a+b/c=".into()),
                state: Some(KeyState::Active),
            })),
            "/keys?namespace=prod%20team&limit=25&cursor=a%2Bb%2Fc%3D&state=ACTIVE"
        );
    }

    #[test]
    fn audit_log_path_encodes_every_filter() {
        assert_eq!(audit_log_path(None), "/audit");
        assert_eq!(audit_log_path(Some(&AuditLogOptions::default())), "/audit");
        assert_eq!(
            audit_log_path(Some(&AuditLogOptions {
                namespace: Some("prod".into()),
                start_time: Some("2026-07-31T00:00:00Z".into()),
                end_time: Some("2026-07-31T23:59:59Z".into()),
                user_id: Some("svc/a&b".into()),
                operation: Some("sign key".into()),
                limit: Some(100),
                cursor: Some("c=1".into()),
            })),
            "/audit?namespace=prod\
             &start_time=2026-07-31T00%3A00%3A00Z\
             &end_time=2026-07-31T23%3A59%3A59Z\
             &user_id=svc%2Fa%26b\
             &operation=sign%20key\
             &limit=100\
             &cursor=c%3D1"
        );
    }

    #[test]
    fn retry_jitter_is_not_clock_correlated() {
        // Clock-derived jitter gives every caller that failed in the same instant
        // the same delay, which is precisely what jitter must avoid.
        let samples: Vec<f64> = (0..64).map(|_| rand_f64()).collect();
        assert!(samples.iter().all(|v| (0.0..1.0).contains(v)));
        let distinct = samples
            .iter()
            .map(|v| v.to_bits())
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(distinct > 32, "only {} distinct jitter values", distinct);
    }
}
