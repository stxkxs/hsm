"""
HSM Client Exceptions

Custom exception types for the HSM Python SDK.
"""

from typing import Any


class HsmError(Exception):
    """Base exception class for HSM errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        details: dict[str, Any] | None = None,
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

    def __init__(
        self,
        resource: str,
        resource_id: str,
        *,
        message: str | None = None,
    ) -> None:
        super().__init__(
            message or f"{resource} not found: {resource_id}",
            status_code=404,
            code="NOT_FOUND",
        )
        self.resource = resource
        self.resource_id = resource_id


class ValidationError(HsmError):
    """Error when input validation fails."""

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message, status_code=400, code="VALIDATION_ERROR")
        self.field = field


class RateLimitError(HsmError):
    """Error when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        *,
        retry_after: int | None = None,
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
    """Parse an error response from the server.

    The server error body is ``{"error": <code>, "message": <human>, "details": <optional>}``.
    The returned exception keeps the SDK's own stable ``code`` taxonomy, while the server's
    machine-readable ``error`` code and any ``details`` are preserved on ``.details`` so no
    diagnostic information from the response is lost.
    """
    fields: dict[str, Any] = body if isinstance(body, dict) else {}
    message = fields.get("message") or "Unknown error"

    error: HsmError
    if status_code == 400:
        error = ValidationError(message)
    elif status_code == 401:
        error = AuthenticationError(message)
    elif status_code == 403:
        error = AuthorizationError(message)
    elif status_code == 404:
        # Preserve the server's message instead of replacing it with a placeholder.
        error = NotFoundError("Resource", "unknown", message=message)
    elif status_code == 429:
        error = RateLimitError(message, retry_after=fields.get("retry_after"))
    elif status_code >= 500:
        error = ServerError(message, status_code)
    else:
        error = HsmError(message, status_code=status_code)

    details: dict[str, Any] = {}
    if fields.get("error") is not None:
        details["error"] = fields["error"]
    if fields.get("details") is not None:
        details["details"] = fields["details"]
    error.details = details
    return error
