package hsm

import "fmt"

// Error represents an HSM error.
type Error struct {
	Message    string
	StatusCode int
	Code       string
	Details    map[string]interface{}
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (code: %s, status: %d)", e.Message, e.Code, e.StatusCode)
	}
	return e.Message
}

// AuthenticationError represents an authentication failure.
type AuthenticationError struct {
	*Error
}

// NewAuthenticationError creates a new AuthenticationError.
func NewAuthenticationError(message string) *AuthenticationError {
	return &AuthenticationError{
		Error: &Error{
			Message:    message,
			StatusCode: 401,
			Code:       "AUTHENTICATION_FAILED",
		},
	}
}

// AuthorizationError represents an authorization failure.
type AuthorizationError struct {
	*Error
}

// NewAuthorizationError creates a new AuthorizationError.
func NewAuthorizationError(message string) *AuthorizationError {
	return &AuthorizationError{
		Error: &Error{
			Message:    message,
			StatusCode: 403,
			Code:       "AUTHORIZATION_FAILED",
		},
	}
}

// NotFoundError represents a resource not found error.
type NotFoundError struct {
	*Error
	Resource   string
	ResourceID string
}

// NewNotFoundError creates a new NotFoundError.
func NewNotFoundError(resource, resourceID string) *NotFoundError {
	return &NotFoundError{
		Error: &Error{
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
	*Error
	Field string
}

// NewValidationError creates a new ValidationError.
func NewValidationError(message string, field string) *ValidationError {
	return &ValidationError{
		Error: &Error{
			Message:    message,
			StatusCode: 400,
			Code:       "VALIDATION_ERROR",
		},
		Field: field,
	}
}

// RateLimitError represents a rate limit exceeded error.
type RateLimitError struct {
	*Error
	RetryAfter int
}

// NewRateLimitError creates a new RateLimitError.
func NewRateLimitError(message string, retryAfter int) *RateLimitError {
	return &RateLimitError{
		Error: &Error{
			Message:    message,
			StatusCode: 429,
			Code:       "RATE_LIMIT_EXCEEDED",
		},
		RetryAfter: retryAfter,
	}
}

// NetworkError represents a network error.
type NetworkError struct {
	*Error
	Cause error
}

// NewNetworkError creates a new NetworkError.
func NewNetworkError(message string, cause error) *NetworkError {
	return &NetworkError{
		Error: &Error{
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
	*Error
}

// NewTimeoutError creates a new TimeoutError.
func NewTimeoutError() *TimeoutError {
	return &TimeoutError{
		Error: &Error{
			Message: "request timed out",
			Code:    "TIMEOUT",
		},
	}
}

// ServerError represents a server error.
type ServerError struct {
	*Error
}

// NewServerError creates a new ServerError.
func NewServerError(message string, statusCode int) *ServerError {
	return &ServerError{
		Error: &Error{
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
		return &Error{
			Message:    message,
			StatusCode: statusCode,
		}
	}
}
