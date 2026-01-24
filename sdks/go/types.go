// Package hsm provides a Go SDK for interacting with the HSM (Hardware Security Module) server.
package hsm

import "time"

// KeyAlgorithm represents supported key algorithms.
type KeyAlgorithm string

const (
	KeyAlgorithmEd25519   KeyAlgorithm = "ED25519"
	KeyAlgorithmEcdsaP256 KeyAlgorithm = "ECDSA_P256"
	KeyAlgorithmEcdsaP384 KeyAlgorithm = "ECDSA_P384"
	KeyAlgorithmRSA2048   KeyAlgorithm = "RSA2048"
	KeyAlgorithmRSA3072   KeyAlgorithm = "RSA3072"
	KeyAlgorithmRSA4096   KeyAlgorithm = "RSA4096"
	KeyAlgorithmAES128    KeyAlgorithm = "AES128"
	KeyAlgorithmAES256    KeyAlgorithm = "AES256"
)

// KeyPurpose represents key purpose/usage.
type KeyPurpose string

const (
	KeyPurposeSign    KeyPurpose = "SIGN"
	KeyPurposeEncrypt KeyPurpose = "ENCRYPT"
	KeyPurposeGeneral KeyPurpose = "GENERAL"
)

// KeyState represents key state.
type KeyState string

const (
	KeyStateActive      KeyState = "ACTIVE"
	KeyStateInactive    KeyState = "INACTIVE"
	KeyStateCompromised KeyState = "COMPROMISED"
	KeyStateDestroyed   KeyState = "DESTROYED"
)

// GenerateKeyRequest represents a request to generate a new key.
type GenerateKeyRequest struct {
	KeyID     string            `json:"key_id,omitempty"`
	Algorithm KeyAlgorithm      `json:"algorithm"`
	Purpose   KeyPurpose        `json:"purpose"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// GenerateKeyResponse represents the response after generating a key.
type GenerateKeyResponse struct {
	KeyID     string       `json:"key_id"`
	Algorithm KeyAlgorithm `json:"algorithm"`
	Purpose   KeyPurpose   `json:"purpose"`
	PublicKey string       `json:"public_key,omitempty"`
	CreatedAt string       `json:"created_at"`
}

// KeyMetadata represents key metadata.
type KeyMetadata struct {
	KeyID     string            `json:"key_id"`
	Algorithm KeyAlgorithm      `json:"algorithm"`
	Purpose   KeyPurpose        `json:"purpose"`
	Namespace string            `json:"namespace"`
	PublicKey string            `json:"public_key,omitempty"`
	CreatedAt string            `json:"created_at"`
	LastUsed  string            `json:"last_used,omitempty"`
	Labels    map[string]string `json:"labels"`
	Active    bool              `json:"active"`
}

// ListKeysResponse represents the response for listing keys.
type ListKeysResponse struct {
	Keys       []KeyMetadata `json:"keys"`
	Total      int64         `json:"total"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// ListKeysOptions represents options for listing keys.
type ListKeysOptions struct {
	Namespace string
	Limit     int
	Cursor    string
	State     KeyState
}

// SignRequest represents a request to sign data.
type SignRequest struct {
	Data          string `json:"data"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// SignResponse represents the sign response.
type SignResponse struct {
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
}

// VerifyRequest represents a request to verify a signature.
type VerifyRequest struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// VerifyResponse represents the verify response.
type VerifyResponse struct {
	Valid bool `json:"valid"`
}

// EncryptRequest represents a request to encrypt data.
type EncryptRequest struct {
	Plaintext string `json:"plaintext"`
	AAD       string `json:"aad,omitempty"`
}

// EncryptResponse represents the encrypt response.
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag,omitempty"`
}

// DecryptRequest represents a request to decrypt data.
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag,omitempty"`
	AAD        string `json:"aad,omitempty"`
}

// DecryptResponse represents the decrypt response.
type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

// BatchSignItem represents a single item in batch sign request.
type BatchSignItem struct {
	KeyID         string `json:"key_id"`
	Data          string `json:"data"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// BatchSignRequest represents a batch sign request.
type BatchSignRequest struct {
	Requests []BatchSignItem `json:"requests"`
}

// BatchSignResponse represents a batch sign response.
type BatchSignResponse struct {
	Results []SignResponse `json:"results"`
	Errors  []string       `json:"errors"`
}

// BatchVerifyItem represents a single item in batch verify request.
type BatchVerifyItem struct {
	KeyID     string `json:"key_id"`
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// BatchVerifyRequest represents a batch verify request.
type BatchVerifyRequest struct {
	Requests []BatchVerifyItem `json:"requests"`
}

// BatchVerifyResponse represents a batch verify response.
type BatchVerifyResponse struct {
	Results []VerifyResponse `json:"results"`
	Errors  []string         `json:"errors"`
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Actor     string `json:"actor"`
	Resource  string `json:"resource,omitempty"`
	Action    string `json:"action"`
	Result    string `json:"result"`
	Details   string `json:"details,omitempty"`
}

// AuditLogResponse represents the audit log response.
type AuditLogResponse struct {
	Entries    []AuditEntry `json:"entries"`
	Total      int64        `json:"total"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

// AuditLogOptions represents options for querying audit logs.
type AuditLogOptions struct {
	Namespace string
	StartTime *time.Time
	EndTime   *time.Time
	UserID    string
	Operation string
	Limit     int
	Cursor    string
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// ComponentStatus represents component status for readiness check.
type ComponentStatus struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// ReadyResponse represents the readiness check response.
type ReadyResponse struct {
	Ready      bool                       `json:"ready"`
	Components map[string]ComponentStatus `json:"components"`
}

// ClientConfig represents the HSM client configuration.
type ClientConfig struct {
	BaseURL      string
	SessionID    string
	SessionToken string
	Timeout      time.Duration
	Headers      map[string]string
	Retry        *RetryConfig
}

// RetryConfig represents retry configuration.
type RetryConfig struct {
	MaxRetries    int
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	Jitter        float64
	RetryOnStatus []int
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:    3,
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		Jitter:        0.1,
		RetryOnStatus: []int{429, 502, 503, 504},
	}
}
