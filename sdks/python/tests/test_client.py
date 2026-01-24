"""
HSM Client Tests
"""

import pytest
from hsm_client import (
    HsmClient,
    create_client,
    HsmClientConfig,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    NetworkError,
    to_base64,
    from_base64,
)
from hsm_client.crypto import is_base64, normalize_to_base64


class TestHsmClient:
    """Tests for HsmClient."""

    def test_create_client(self) -> None:
        """Test client creation."""
        client = create_client(
            "https://hsm.example.com",
            session_id="test-session",
            session_token="test-token",
        )
        assert isinstance(client, HsmClient)

    def test_client_strips_trailing_slash(self) -> None:
        """Test that trailing slash is stripped from base URL."""
        config = HsmClientConfig(base_url="https://hsm.example.com/")
        client = HsmClient(config)
        assert client._base_url == "https://hsm.example.com"

    def test_is_authenticated(self) -> None:
        """Test authentication check."""
        client = create_client(
            "https://hsm.example.com",
            session_id="test-session",
            session_token="test-token",
        )
        assert client.is_authenticated()

    def test_is_not_authenticated(self) -> None:
        """Test not authenticated when no credentials."""
        client = create_client("https://hsm.example.com")
        assert not client.is_authenticated()

    def test_clear_credentials(self) -> None:
        """Test clearing credentials."""
        client = create_client(
            "https://hsm.example.com",
            session_id="test-session",
            session_token="test-token",
        )
        client.clear_credentials()
        assert not client.is_authenticated()

    def test_set_credentials(self) -> None:
        """Test setting new credentials."""
        client = create_client("https://hsm.example.com")
        client.set_credentials("new-session", "new-token")
        assert client.is_authenticated()


class TestCryptoUtils:
    """Tests for crypto utilities."""

    def test_to_base64_bytes(self) -> None:
        """Test encoding bytes to base64."""
        data = b"Hello"
        assert to_base64(data) == "SGVsbG8="

    def test_to_base64_string(self) -> None:
        """Test encoding string to base64."""
        assert to_base64("Hello") == "SGVsbG8="

    def test_from_base64(self) -> None:
        """Test decoding base64 to bytes."""
        result = from_base64("SGVsbG8=")
        assert result == b"Hello"

    def test_is_base64_valid(self) -> None:
        """Test valid base64 detection."""
        assert is_base64("SGVsbG8=")
        assert is_base64("")
        assert is_base64("YWJj")  # "abc"

    def test_is_base64_invalid(self) -> None:
        """Test invalid base64 detection."""
        assert not is_base64("Hello")
        assert not is_base64("abc")  # Not padded correctly

    def test_normalize_to_base64(self) -> None:
        """Test normalizing data to base64."""
        # Bytes
        assert normalize_to_base64(b"Hello") == "SGVsbG8="
        # String (non-base64)
        assert normalize_to_base64("Hello") == "SGVsbG8="
        # Already base64
        assert normalize_to_base64("SGVsbG8=") == "SGVsbG8="


class TestExceptions:
    """Tests for exception classes."""

    def test_authentication_error(self) -> None:
        """Test AuthenticationError."""
        error = AuthenticationError("Invalid credentials")
        assert error.status_code == 401
        assert error.code == "AUTHENTICATION_FAILED"
        assert str(error) == "Invalid credentials"

    def test_not_found_error(self) -> None:
        """Test NotFoundError."""
        error = NotFoundError("Key", "key-123")
        assert error.status_code == 404
        assert error.message == "Key not found: key-123"
        assert error.resource == "Key"
        assert error.resource_id == "key-123"

    def test_rate_limit_error(self) -> None:
        """Test RateLimitError."""
        error = RateLimitError("Too many requests", retry_after=60)
        assert error.status_code == 429
        assert error.retry_after == 60

    def test_network_error(self) -> None:
        """Test NetworkError."""
        error = NetworkError("Connection refused")
        assert error.code == "NETWORK_ERROR"


class TestCircuitBreaker:
    """Tests for circuit breaker."""

    def test_initial_state(self) -> None:
        """Test circuit breaker starts closed."""
        client = create_client("https://hsm.example.com")
        assert client.circuit_state == "closed"

    def test_reset(self) -> None:
        """Test circuit breaker reset."""
        client = create_client("https://hsm.example.com")
        client.reset_circuit_breaker()
        assert client.circuit_state == "closed"


class TestOperationCount:
    """Tests for operation counting."""

    def test_initial_count(self) -> None:
        """Test operation count starts at zero."""
        client = create_client("https://hsm.example.com")
        assert client.operation_count == 0
