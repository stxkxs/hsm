package hsm

import "fmt"

// BaseError is the common error payload shared by every HSM error type.
//
// It is embedded (as *BaseError) by the concrete error types below. The type is
// deliberately NOT named Error: embedding a type named Error promotes a *field*
// called Error, which shadows the promoted Error() string method and stops the
// embedder from satisfying the error interface.
type BaseError struct {
	Message    string
	StatusCode int
	Code       string
	Details    map[string]interface{}
}

// Compile-time proof that every exported error type actually satisfies the
// error interface. If an embedded base type is ever renamed back to something
// that collides with the promoted Error() method, this block fails to build
// instead of failing at every call site.
var (
	_ error = (*BaseError)(nil)
	_ error = (*AuthenticationError)(nil)
	_ error = (*AuthorizationError)(nil)
	_ error = (*NotFoundError)(nil)
	_ error = (*ValidationError)(nil)
	_ error = (*RateLimitError)(nil)
	_ error = (*NetworkError)(nil)
	_ error = (*TimeoutError)(nil)
	_ error = (*ServerError)(nil)
)

func (e *BaseError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Code != "" {
		return fmt.Sprintf("%s (code: %s, status: %d)", e.Message, e.Code, e.StatusCode)
	}
	return e.Message
}

// AuthenticationError represents an authentication failure.
type AuthenticationError struct {
	*BaseError
}

// NewAuthenticationError creates a new AuthenticationError.
func NewAuthenticationError(message string) *AuthenticationError {
	return &AuthenticationError{
		BaseError: &BaseError{
			Message:    message,
			StatusCode: 401,
			Code:       "AUTHENTICATION_FAILED",
		},
	}
}

// AuthorizationError represents an authorization failure.
type AuthorizationError struct {
	*BaseError
}

// NewAuthorizationError creates a new AuthorizationError.
func NewAuthorizationError(message string) *AuthorizationError {
	return &AuthorizationError{
		BaseError: &BaseError{
			Message:    message,
			StatusCode: 403,
			Code:       "AUTHORIZATION_FAILED",
		},
	}
}

// NotFoundError represents a resource not found error.
type NotFoundError struct {
	*BaseError
	Resource   string
	ResourceID string
}

// NewNotFoundError creates a new NotFoundError.
func NewNotFoundError(resource, resourceID string) *NotFoundError {
	return &NotFoundError{
		BaseError: &BaseError{
			Message:    fmt.Sprintf("%s not found: %s", resource, resourceID),
			StatusCode: 404,
			Code:       "NOT_FOUND",
		},
		Resource:   resource,
		ResourceID: resourceID,
	}
}

// ValidationError represents a validation failure.
type ValidationError struct {
	*BaseError
	Field string
}

// NewValidationError creates a new ValidationError.
func NewValidationError(message string, field string) *ValidationError {
	return &ValidationError{
		BaseError: &BaseError{
			Message:    message,
			StatusCode: 400,
			Code:       "VALIDATION_ERROR",
		},
		Field: field,
	}
}

// RateLimitError represents a rate limit exceeded error.
type RateLimitError struct {
	*BaseError
	RetryAfter int
}

// NewRateLimitError creates a new RateLimitError.
func NewRateLimitError(message string, retryAfter int) *RateLimitError {
	return &RateLimitError{
		BaseError: &BaseError{
			Message:    message,
			StatusCode: 429,
			Code:       "RATE_LIMIT_EXCEEDED",
		},
		RetryAfter: retryAfter,
	}
}

// NetworkError represents a network error.
type NetworkError struct {
	*BaseError
	Cause error
}

// NewNetworkError creates a new NetworkError.
func NewNetworkError(message string, cause error) *NetworkError {
	return &NetworkError{
		BaseError: &BaseError{
			Message: message,
			Code:    "NETWORK_ERROR",
		},
		Cause: cause,
	}
}

func (e *NetworkError) Unwrap() error {
	return e.Cause
}

// TimeoutError represents a timeout error.
type TimeoutError struct {
	*BaseError
}

// NewTimeoutError creates a new TimeoutError.
func NewTimeoutError() *TimeoutError {
	return &TimeoutError{
		BaseError: &BaseError{
			Message: "request timed out",
			Code:    "TIMEOUT",
		},
	}
}

// ServerError represents a server error.
type ServerError struct {
	*BaseError
}

// NewServerError creates a new ServerError.
func NewServerError(message string, statusCode int) *ServerError {
	return &ServerError{
		BaseError: &BaseError{
			Message:    message,
			StatusCode: statusCode,
			Code:       "SERVER_ERROR",
		},
	}
}

// parseErrorResponse parses an error response from the server.
func parseErrorResponse(statusCode int, body map[string]interface{}) error {
	message := "Unknown error"
	if msg, ok := body["message"].(string); ok {
		message = msg
	}

	switch statusCode {
	case 400:
		return NewValidationError(message, "")
	case 401:
		return NewAuthenticationError(message)
	case 403:
		return NewAuthorizationError(message)
	case 404:
		return NewNotFoundError("Resource", "unknown")
	case 429:
		retryAfter := 0
		if ra, ok := body["retry_after"].(float64); ok {
			retryAfter = int(ra)
		}
		return NewRateLimitError(message, retryAfter)
	default:
		if statusCode >= 500 {
			return NewServerError(message, statusCode)
		}
		return &BaseError{
			Message:    message,
			StatusCode: statusCode,
		}
	}
}
