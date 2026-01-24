"""
HSM Client Exceptions

Custom exception types for the HSM Python SDK.
"""

from typing import Any, Optional


class HsmError(Exception):
    """Base exception class for HSM errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.details = details or {}

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"status_code={self.status_code}, "
            f"code={self.code!r})"
        )


class AuthenticationError(HsmError):
    """Error when authentication fails."""

    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(message, status_code=401, code="AUTHENTICATION_FAILED")


class AuthorizationError(HsmError):
    """Error when authorization fails."""

    def __init__(self, message: str = "Authorization failed") -> None:
        super().__init__(message, status_code=403, code="AUTHORIZATION_FAILED")


class NotFoundError(HsmError):
    """Error when a resource is not found."""

    def __init__(self, resource: str, resource_id: str) -> None:
        message = f"{resource} not found: {resource_id}"
        super().__init__(message, status_code=404, code="NOT_FOUND")
        self.resource = resource
        self.resource_id = resource_id


class ValidationError(HsmError):
    """Error when input validation fails."""

    def __init__(self, message: str, *, field: Optional[str] = None) -> None:
        super().__init__(message, status_code=400, code="VALIDATION_ERROR")
        self.field = field


class RateLimitError(HsmError):
    """Error when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        *,
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(message, status_code=429, code="RATE_LIMIT_EXCEEDED")
        self.retry_after = retry_after


class NetworkError(HsmError):
    """Error when a network request fails."""

    def __init__(self, message: str = "Network error") -> None:
        super().__init__(message, code="NETWORK_ERROR")


class TimeoutError(HsmError):
    """Error when request times out."""

    def __init__(self, message: str = "Request timed out") -> None:
        super().__init__(message, code="TIMEOUT")


class ServerError(HsmError):
    """Error when server returns an error."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message, status_code=status_code, code="SERVER_ERROR")


class CryptoError(HsmError):
    """Error when a cryptographic operation fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CRYPTO_ERROR")


class SessionError(HsmError):
    """Error when session is invalid or expired."""

    def __init__(self, message: str = "Session error") -> None:
        super().__init__(message, status_code=401, code="SESSION_ERROR")


def parse_error_response(status_code: int, body: Any) -> HsmError:
    """Parse an error response from the server."""
    message = "Unknown error"
    if isinstance(body, dict):
        message = body.get("message", message)

    if status_code == 400:
        return ValidationError(message)
    elif status_code == 401:
        return AuthenticationError(message)
    elif status_code == 403:
        return AuthorizationError(message)
    elif status_code == 404:
        return NotFoundError("Resource", "unknown")
    elif status_code == 429:
        retry_after = body.get("retry_after") if isinstance(body, dict) else None
        return RateLimitError(message, retry_after=retry_after)
    elif status_code >= 500:
        return ServerError(message, status_code)
    else:
        return HsmError(message, status_code=status_code)
