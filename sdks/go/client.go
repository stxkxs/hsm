package hsm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is the HSM client for interacting with the HSM server.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	headers        map[string]string
	tokenManager   *TokenManager
	circuitBreaker *CircuitBreaker
	retryStrategy  *RetryStrategy
	Keys           *KeyManager
}

// NewClient creates a new HSM client.
func NewClient(config ClientConfig) *Client {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	baseURL := strings.TrimSuffix(config.BaseURL, "/")

	client := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		headers:        config.Headers,
		tokenManager:   NewTokenManager(config.SessionID, config.SessionToken),
		circuitBreaker: NewCircuitBreaker(5, 30*time.Second, 2),
		retryStrategy:  NewRetryStrategy(config.Retry),
	}

	client.Keys = &KeyManager{client: client}
	return client
}

// TokenManager handles session tokens.
type TokenManager struct {
	mu             sync.RWMutex
	sessionID      string
	sessionToken   string
	operationCount int
	maxOperations  int
}

// NewTokenManager creates a new TokenManager.
func NewTokenManager(sessionID, sessionToken string) *TokenManager {
	return &TokenManager{
		sessionID:     sessionID,
		sessionToken:  sessionToken,
		maxOperations: 900,
	}
}

// SetCredentials sets new credentials.
func (tm *TokenManager) SetCredentials(sessionID, sessionToken string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.sessionID = sessionID
	tm.sessionToken = sessionToken
	tm.operationCount = 0
}

// ClearCredentials clears credentials.
func (tm *TokenManager) ClearCredentials() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.sessionID = ""
	tm.sessionToken = ""
	tm.operationCount = 0
}

// IsAuthenticated checks if authenticated.
func (tm *TokenManager) IsAuthenticated() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.sessionID != "" && tm.sessionToken != ""
}

// GetAuthorizationHeader returns the authorization header value.
func (tm *TokenManager) GetAuthorizationHeader() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if tm.sessionID == "" || tm.sessionToken == "" {
		return ""
	}
	return fmt.Sprintf("Bearer %s:%s", tm.sessionID, tm.sessionToken)
}

// IncrementOperationCount increments the operation count.
func (tm *TokenManager) IncrementOperationCount() bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.operationCount++
	return tm.operationCount >= tm.maxOperations
}

// OperationCount returns the current operation count.
func (tm *TokenManager) OperationCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.operationCount
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            string
	failureCount     int
	lastFailureTime  time.Time
	successCount     int
	failureThreshold int
	recoveryTimeout  time.Duration
	successThreshold int
}

// NewCircuitBreaker creates a new CircuitBreaker.
func NewCircuitBreaker(failureThreshold int, recoveryTimeout time.Duration, successThreshold int) *CircuitBreaker {
	return &CircuitBreaker{
		state:            "closed",
		failureThreshold: failureThreshold,
		recoveryTimeout:  recoveryTimeout,
		successThreshold: successThreshold,
	}
}

// CanRequest checks if a request should be allowed.
func (cb *CircuitBreaker) CanRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == "closed" {
		return true
	}

	if cb.state == "open" {
		if time.Since(cb.lastFailureTime) >= cb.recoveryTimeout {
			cb.state = "half-open"
			cb.successCount = 0
			return true
		}
		return false
	}

	return true
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == "half-open" {
		cb.successCount++
		if cb.successCount >= cb.successThreshold {
			cb.state = "closed"
			cb.failureCount = 0
		}
	} else if cb.state == "closed" {
		cb.failureCount = 0
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.lastFailureTime = time.Now()

	if cb.state == "half-open" {
		cb.state = "open"
	} else if cb.failureCount >= cb.failureThreshold {
		cb.state = "open"
	}
}

// State returns the current state.
func (cb *CircuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Reset resets the circuit breaker.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = "closed"
	cb.failureCount = 0
	cb.successCount = 0
}

// RetryStrategy implements retry with exponential backoff.
type RetryStrategy struct {
	maxRetries    int
	baseDelay     time.Duration
	maxDelay      time.Duration
	jitter        float64
	retryOnStatus map[int]bool
}

// NewRetryStrategy creates a new RetryStrategy.
func NewRetryStrategy(config *RetryConfig) *RetryStrategy {
	if config == nil {
		config = DefaultRetryConfig()
	}

	statusMap := make(map[int]bool)
	for _, s := range config.RetryOnStatus {
		statusMap[s] = true
	}

	return &RetryStrategy{
		maxRetries:    config.MaxRetries,
		baseDelay:     config.BaseDelay,
		maxDelay:      config.MaxDelay,
		jitter:        config.Jitter,
		retryOnStatus: statusMap,
	}
}

// ShouldRetry checks if a status code should be retried.
func (rs *RetryStrategy) ShouldRetry(statusCode int, attempt int) bool {
	return attempt < rs.maxRetries && rs.retryOnStatus[statusCode]
}

// GetDelay calculates delay for next retry.
func (rs *RetryStrategy) GetDelay(attempt int) time.Duration {
	exponentialDelay := rs.baseDelay * time.Duration(1<<uint(attempt))
	if exponentialDelay > rs.maxDelay {
		exponentialDelay = rs.maxDelay
	}
	jitterAmount := time.Duration(float64(exponentialDelay) * rs.jitter * rand.Float64())
	return exponentialDelay + jitterAmount
}

// Sleep sleeps for the calculated delay.
func (rs *RetryStrategy) Sleep(ctx context.Context, attempt int) error {
	delay := rs.GetDelay(attempt)
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// request makes an HTTP request.
func (c *Client) request(ctx context.Context, method, path string, body interface{}, attempt int) ([]byte, error) {
	if !c.circuitBreaker.CanRequest() {
		return nil, &Error{Message: "circuit breaker is open", Code: "CIRCUIT_OPEN"}
	}

	reqURL := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	authHeader := c.tokenManager.GetAuthorizationHeader()
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.circuitBreaker.RecordFailure()
		return nil, NewNetworkError(err.Error(), err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.circuitBreaker.RecordFailure()
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var errorBody map[string]interface{}
		_ = json.Unmarshal(respBody, &errorBody)

		if c.retryStrategy.ShouldRetry(resp.StatusCode, attempt) {
			c.circuitBreaker.RecordFailure()
			if err := c.retryStrategy.Sleep(ctx, attempt); err != nil {
				return nil, err
			}
			return c.request(ctx, method, path, body, attempt+1)
		}

		c.circuitBreaker.RecordFailure()
		return nil, parseErrorResponse(resp.StatusCode, errorBody)
	}

	c.circuitBreaker.RecordSuccess()
	c.tokenManager.IncrementOperationCount()

	return respBody, nil
}

// get makes a GET request.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	return c.request(ctx, "GET", path, nil, 0)
}

// post makes a POST request.
func (c *Client) post(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return c.request(ctx, "POST", path, body, 0)
}

// delete makes a DELETE request.
func (c *Client) delete(ctx context.Context, path string) ([]byte, error) {
	return c.request(ctx, "DELETE", path, nil, 0)
}

// SetCredentials sets session credentials.
func (c *Client) SetCredentials(sessionID, sessionToken string) {
	c.tokenManager.SetCredentials(sessionID, sessionToken)
}

// ClearCredentials clears session credentials.
func (c *Client) ClearCredentials() {
	c.tokenManager.ClearCredentials()
}

// IsAuthenticated checks if the client is authenticated.
func (c *Client) IsAuthenticated() bool {
	return c.tokenManager.IsAuthenticated()
}

// CircuitState returns the circuit breaker state.
func (c *Client) CircuitState() string {
	return c.circuitBreaker.State()
}

// ResetCircuitBreaker resets the circuit breaker.
func (c *Client) ResetCircuitBreaker() {
	c.circuitBreaker.Reset()
}

// OperationCount returns the operation count.
func (c *Client) OperationCount() int {
	return c.tokenManager.OperationCount()
}

// Health checks server health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	data, err := c.get(ctx, "/health")
	if err != nil {
		return nil, err
	}
	var resp HealthResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Ready checks server readiness.
func (c *Client) Ready(ctx context.Context) (*ReadyResponse, error) {
	data, err := c.get(ctx, "/ready")
	if err != nil {
		return nil, err
	}
	var resp ReadyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateKey generates a new key.
func (c *Client) GenerateKey(ctx context.Context, req GenerateKeyRequest) (*GenerateKeyResponse, error) {
	data, err := c.post(ctx, "/keys", req)
	if err != nil {
		return nil, err
	}
	var resp GenerateKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetKey gets key metadata.
func (c *Client) GetKey(ctx context.Context, keyID string) (*KeyMetadata, error) {
	data, err := c.get(ctx, "/keys/"+url.PathEscape(keyID))
	if err != nil {
		return nil, err
	}
	var resp KeyMetadata
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListKeys lists keys.
func (c *Client) ListKeys(ctx context.Context, opts *ListKeysOptions) (*ListKeysResponse, error) {
	path := "/keys"
	if opts != nil {
		params := url.Values{}
		if opts.Namespace != "" {
			params.Set("namespace", opts.Namespace)
		}
		if opts.Limit > 0 {
			params.Set("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			params.Set("cursor", opts.Cursor)
		}
		if opts.State != "" {
			params.Set("state", string(opts.State))
		}
		if len(params) > 0 {
			path += "?" + params.Encode()
		}
	}

	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var resp ListKeysResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteKey deletes a key.
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	_, err := c.delete(ctx, "/keys/"+url.PathEscape(keyID))
	return err
}

// Sign signs data with a key.
func (c *Client) Sign(ctx context.Context, keyID string, data []byte, hashAlgorithm string) (*SignResponse, error) {
	req := map[string]interface{}{
		"data": ToBase64(data),
	}
	if hashAlgorithm != "" {
		req["hash_algorithm"] = hashAlgorithm
	}

	respData, err := c.post(ctx, "/keys/"+url.PathEscape(keyID)+"/sign", req)
	if err != nil {
		return nil, err
	}
	var resp SignResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Verify verifies a signature.
func (c *Client) Verify(ctx context.Context, keyID string, data []byte, signature string) (*VerifyResponse, error) {
	req := map[string]interface{}{
		"data":      ToBase64(data),
		"signature": signature,
	}

	respData, err := c.post(ctx, "/keys/"+url.PathEscape(keyID)+"/verify", req)
	if err != nil {
		return nil, err
	}
	var resp VerifyResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Encrypt encrypts data with a key.
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext []byte, aad string) (*EncryptResponse, error) {
	req := map[string]interface{}{
		"plaintext": ToBase64(plaintext),
	}
	if aad != "" {
		req["aad"] = aad
	}

	respData, err := c.post(ctx, "/keys/"+url.PathEscape(keyID)+"/encrypt", req)
	if err != nil {
		return nil, err
	}
	var resp EncryptResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Decrypt decrypts data with a key.
func (c *Client) Decrypt(ctx context.Context, keyID string, ciphertext, nonce, tag, aad string) (*DecryptResponse, error) {
	req := map[string]interface{}{
		"ciphertext": ciphertext,
		"nonce":      nonce,
	}
	if tag != "" {
		req["tag"] = tag
	}
	if aad != "" {
		req["aad"] = aad
	}

	respData, err := c.post(ctx, "/keys/"+url.PathEscape(keyID)+"/decrypt", req)
	if err != nil {
		return nil, err
	}
	var resp DecryptResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAuditLog gets audit log entries.
func (c *Client) GetAuditLog(ctx context.Context, opts *AuditLogOptions) (*AuditLogResponse, error) {
	path := "/audit"
	if opts != nil {
		params := url.Values{}
		if opts.Namespace != "" {
			params.Set("namespace", opts.Namespace)
		}
		if opts.StartTime != nil {
			params.Set("start_time", opts.StartTime.Format(time.RFC3339))
		}
		if opts.EndTime != nil {
			params.Set("end_time", opts.EndTime.Format(time.RFC3339))
		}
		if opts.UserID != "" {
			params.Set("user_id", opts.UserID)
		}
		if opts.Operation != "" {
			params.Set("operation", opts.Operation)
		}
		if opts.Limit > 0 {
			params.Set("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			params.Set("cursor", opts.Cursor)
		}
		if len(params) > 0 {
			path += "?" + params.Encode()
		}
	}

	data, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var resp AuditLogResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// KeyManager provides high-level key management operations.
type KeyManager struct {
	client *Client
}

// GenerateEd25519 generates an Ed25519 signing key.
func (km *KeyManager) GenerateEd25519(ctx context.Context, keyID, namespace string, labels map[string]string) (*GenerateKeyResponse, error) {
	return km.client.GenerateKey(ctx, GenerateKeyRequest{
		KeyID:     keyID,
		Algorithm: KeyAlgorithmEd25519,
		Purpose:   KeyPurposeSign,
		Namespace: namespace,
		Labels:    labels,
	})
}

// GenerateEcdsaP256 generates an ECDSA P-256 key.
func (km *KeyManager) GenerateEcdsaP256(ctx context.Context, keyID, namespace string, labels map[string]string) (*GenerateKeyResponse, error) {
	return km.client.GenerateKey(ctx, GenerateKeyRequest{
		KeyID:     keyID,
		Algorithm: KeyAlgorithmEcdsaP256,
		Purpose:   KeyPurposeSign,
		Namespace: namespace,
		Labels:    labels,
	})
}

// GenerateRSA generates an RSA key.
func (km *KeyManager) GenerateRSA(ctx context.Context, size int, keyID, namespace string, labels map[string]string) (*GenerateKeyResponse, error) {
	var alg KeyAlgorithm
	switch size {
	case 2048:
		alg = KeyAlgorithmRSA2048
	case 3072:
		alg = KeyAlgorithmRSA3072
	case 4096:
		alg = KeyAlgorithmRSA4096
	default:
		return nil, NewValidationError(fmt.Sprintf("invalid RSA size: %d", size), "size")
	}

	return km.client.GenerateKey(ctx, GenerateKeyRequest{
		KeyID:     keyID,
		Algorithm: alg,
		Purpose:   KeyPurposeSign,
		Namespace: namespace,
		Labels:    labels,
	})
}

// GenerateAES generates an AES encryption key.
func (km *KeyManager) GenerateAES(ctx context.Context, size int, keyID, namespace string, labels map[string]string) (*GenerateKeyResponse, error) {
	var alg KeyAlgorithm
	switch size {
	case 128:
		alg = KeyAlgorithmAES128
	case 256:
		alg = KeyAlgorithmAES256
	default:
		return nil, NewValidationError(fmt.Sprintf("invalid AES size: %d", size), "size")
	}

	return km.client.GenerateKey(ctx, GenerateKeyRequest{
		KeyID:     keyID,
		Algorithm: alg,
		Purpose:   KeyPurposeEncrypt,
		Namespace: namespace,
		Labels:    labels,
	})
}

// Get gets key metadata.
func (km *KeyManager) Get(ctx context.Context, keyID string) (*KeyMetadata, error) {
	return km.client.GetKey(ctx, keyID)
}

// List lists keys.
func (km *KeyManager) List(ctx context.Context, opts *ListKeysOptions) (*ListKeysResponse, error) {
	return km.client.ListKeys(ctx, opts)
}

// Delete deletes a key.
func (km *KeyManager) Delete(ctx context.Context, keyID string) error {
	return km.client.DeleteKey(ctx, keyID)
}

// Exists checks if a key exists.
func (km *KeyManager) Exists(ctx context.Context, keyID string) bool {
	_, err := km.client.GetKey(ctx, keyID)
	return err == nil
}
