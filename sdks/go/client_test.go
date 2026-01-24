package hsm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL:      "https://hsm.example.com",
		SessionID:    "test-session",
		SessionToken: "test-token",
	})

	assert.NotNil(t, client)
	assert.Equal(t, "https://hsm.example.com", client.baseURL)
}

func TestClientTrimsTrailingSlash(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "https://hsm.example.com/",
	})

	assert.Equal(t, "https://hsm.example.com", client.baseURL)
}

func TestIsAuthenticated(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL:      "https://hsm.example.com",
		SessionID:    "test-session",
		SessionToken: "test-token",
	})

	assert.True(t, client.IsAuthenticated())
}

func TestIsNotAuthenticated(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "https://hsm.example.com",
	})

	assert.False(t, client.IsAuthenticated())
}

func TestClearCredentials(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL:      "https://hsm.example.com",
		SessionID:    "test-session",
		SessionToken: "test-token",
	})

	client.ClearCredentials()
	assert.False(t, client.IsAuthenticated())
}

func TestSetCredentials(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "https://hsm.example.com",
	})

	client.SetCredentials("new-session", "new-token")
	assert.True(t, client.IsAuthenticated())
}

func TestCircuitBreakerState(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "https://hsm.example.com",
	})

	assert.Equal(t, "closed", client.CircuitState())
}

func TestOperationCount(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL: "https://hsm.example.com",
	})

	assert.Equal(t, 0, client.OperationCount())
}

func TestCryptoToBase64(t *testing.T) {
	data := []byte("Hello")
	result := ToBase64(data)
	assert.Equal(t, "SGVsbG8=", result)
}

func TestCryptoFromBase64(t *testing.T) {
	result, err := FromBase64("SGVsbG8=")
	assert.NoError(t, err)
	assert.Equal(t, []byte("Hello"), result)
}

func TestIsBase64Valid(t *testing.T) {
	assert.True(t, IsBase64("SGVsbG8="))
	assert.True(t, IsBase64(""))
	assert.True(t, IsBase64("YWJj"))
}

func TestIsBase64Invalid(t *testing.T) {
	assert.False(t, IsBase64("Hello"))
	assert.False(t, IsBase64("abc"))
}

func TestAuthenticationError(t *testing.T) {
	err := NewAuthenticationError("Invalid credentials")
	assert.Equal(t, 401, err.StatusCode)
	assert.Equal(t, "AUTHENTICATION_FAILED", err.Code)
	assert.Contains(t, err.Error(), "Invalid credentials")
}

func TestNotFoundError(t *testing.T) {
	err := NewNotFoundError("Key", "key-123")
	assert.Equal(t, 404, err.StatusCode)
	assert.Equal(t, "Key", err.Resource)
	assert.Equal(t, "key-123", err.ResourceID)
	assert.Contains(t, err.Error(), "Key not found: key-123")
}

func TestRateLimitError(t *testing.T) {
	err := NewRateLimitError("Too many requests", 60)
	assert.Equal(t, 429, err.StatusCode)
	assert.Equal(t, 60, err.RetryAfter)
}

func TestNetworkError(t *testing.T) {
	cause := assert.AnError
	err := NewNetworkError("Connection refused", cause)
	assert.Equal(t, "NETWORK_ERROR", err.Code)
	assert.Equal(t, cause, err.Unwrap())
}

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, config.BaseDelay)
	assert.Equal(t, 5*time.Second, config.MaxDelay)
	assert.Contains(t, config.RetryOnStatus, 429)
}
