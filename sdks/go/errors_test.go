package hsm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllErrorTypesImplementError guards the regression that motivated renaming
// the embedded base type: embedding a type named Error promotes a field named
// Error, which shadows the promoted Error() method and makes the embedder fail
// to satisfy the error interface.
func TestAllErrorTypesImplementError(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"BaseError", &BaseError{Message: "boom"}},
		{"AuthenticationError", NewAuthenticationError("bad creds")},
		{"AuthorizationError", NewAuthorizationError("forbidden")},
		{"NotFoundError", NewNotFoundError("Key", "key-1")},
		{"ValidationError", NewValidationError("bad field", "size")},
		{"RateLimitError", NewRateLimitError("slow down", 30)},
		{"NetworkError", NewNetworkError("dial failed", errors.New("econnrefused"))},
		{"TimeoutError", NewTimeoutError()},
		{"ServerError", NewServerError("kaboom", 503)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotNil(t, tc.err)
			assert.NotEmpty(t, tc.err.Error())
		})
	}
}

func TestBaseErrorMessageFormatting(t *testing.T) {
	withCode := &BaseError{Message: "boom", Code: "X", StatusCode: 418}
	assert.Equal(t, "boom (code: X, status: 418)", withCode.Error())

	withoutCode := &BaseError{Message: "plain"}
	assert.Equal(t, "plain", withoutCode.Error())
}

func TestErrorsAsConcreteTypes(t *testing.T) {
	// parseErrorResponse returns a plain `error`; callers must be able to
	// recover the concrete type with errors.As.
	var ve *ValidationError
	require.True(t, errors.As(parseErrorResponse(400, map[string]interface{}{"message": "bad input"}), &ve))
	assert.Equal(t, 400, ve.StatusCode)
	assert.Equal(t, "VALIDATION_ERROR", ve.Code)
	assert.Equal(t, "bad input", ve.Message)

	var ae *AuthenticationError
	require.True(t, errors.As(parseErrorResponse(401, map[string]interface{}{"message": "nope"}), &ae))
	assert.Equal(t, 401, ae.StatusCode)

	var re *RateLimitError
	require.True(t, errors.As(parseErrorResponse(429, map[string]interface{}{"message": "slow", "retry_after": float64(42)}), &re))
	assert.Equal(t, 42, re.RetryAfter)

	var se *ServerError
	require.True(t, errors.As(parseErrorResponse(503, map[string]interface{}{"message": "down"}), &se))
	assert.Equal(t, 503, se.StatusCode)

	// A status with no dedicated type falls through to the bare base error.
	var be *BaseError
	fallback := parseErrorResponse(418, map[string]interface{}{"message": "teapot"})
	require.True(t, errors.As(fallback, &be))
	assert.Equal(t, 418, be.StatusCode)

	// And the fallback must not be mistaken for a specific type.
	var notFound *NotFoundError
	assert.False(t, errors.As(fallback, &notFound))
}

func TestErrorsAsThroughFmtWrapping(t *testing.T) {
	inner := NewNotFoundError("Key", "key-123")
	wrapped := fmt.Errorf("get key: %w", inner)

	var nfe *NotFoundError
	require.True(t, errors.As(wrapped, &nfe))
	assert.Equal(t, "Key", nfe.Resource)
	assert.Equal(t, "key-123", nfe.ResourceID)
	assert.Equal(t, 404, nfe.StatusCode)
	assert.True(t, errors.Is(wrapped, inner))
}

func TestNetworkErrorUnwrapChain(t *testing.T) {
	sentinel := errors.New("connection refused")
	netErr := NewNetworkError("dial tcp: connect", sentinel)

	// Direct unwrap.
	assert.Equal(t, sentinel, netErr.Unwrap())

	// errors.Is must see through NetworkError.Unwrap...
	assert.True(t, errors.Is(netErr, sentinel))

	// ...and through an additional fmt.Errorf %w layer on top of it.
	wrapped := fmt.Errorf("request failed: %w", netErr)
	assert.True(t, errors.Is(wrapped, sentinel))

	var recovered *NetworkError
	require.True(t, errors.As(wrapped, &recovered))
	assert.Equal(t, "NETWORK_ERROR", recovered.Code)
	assert.Equal(t, sentinel, recovered.Cause)

	// An unrelated sentinel must not match.
	assert.False(t, errors.Is(netErr, errors.New("connection refused")))
}

func TestNetworkErrorUnwrapWithNilCause(t *testing.T) {
	netErr := NewNetworkError("dial tcp: connect", nil)
	assert.Nil(t, netErr.Unwrap())
	assert.False(t, errors.Is(netErr, errors.New("anything")))
	assert.Contains(t, netErr.Error(), "dial tcp: connect")
}

func TestPromotedFieldsRemainAccessible(t *testing.T) {
	// The rename must not have hidden the base payload from embedders.
	ve := NewValidationError("field is required", "namespace")
	assert.Equal(t, "namespace", ve.Field)
	assert.Equal(t, "field is required", ve.Message)
	assert.Equal(t, "VALIDATION_ERROR", ve.Code)
	assert.Equal(t, 400, ve.StatusCode)
	assert.Nil(t, ve.Details)

	// The embedded value is reachable by its type name too.
	assert.Equal(t, ve.BaseError.Error(), ve.Error())
}

func TestTimeoutAndAuthorizationErrors(t *testing.T) {
	te := NewTimeoutError()
	assert.Equal(t, "TIMEOUT", te.Code)
	assert.Contains(t, te.Error(), "request timed out")

	ze := NewAuthorizationError("no access to namespace")
	assert.Equal(t, 403, ze.StatusCode)
	assert.Equal(t, "AUTHORIZATION_FAILED", ze.Code)
	assert.Contains(t, ze.Error(), "no access to namespace")
}
