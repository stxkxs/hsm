"""
HSM Client

Main client class for interacting with the HSM server.
"""

import asyncio
import random
from datetime import datetime
from typing import Any, AsyncIterator, Optional, Union
from urllib.parse import quote, urlencode

import httpx

from hsm_client.crypto import normalize_to_base64
from hsm_client.exceptions import (
    HsmError,
    NetworkError,
    TimeoutError,
    parse_error_response,
)
from hsm_client.keys import KeyManager
from hsm_client.models import (
    AuditEntry,
    AuditLogOptions,
    AuditLogResponse,
    BatchDecryptRequest,
    BatchDecryptResponse,
    BatchEncryptRequest,
    BatchEncryptResponse,
    BatchSignRequest,
    BatchSignResponse,
    BatchVerifyRequest,
    BatchVerifyResponse,
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    GenerateKeyRequest,
    GenerateKeyResponse,
    HealthResponse,
    HsmClientConfig,
    KeyMetadata,
    ListKeysOptions,
    ListKeysResponse,
    ReadyResponse,
    RetryConfig,
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)


class TokenManager:
    """Token manager for handling session tokens."""

    def __init__(
        self,
        session_id: Optional[str] = None,
        session_token: Optional[str] = None,
        max_operations_before_rotation: int = 900,
    ) -> None:
        self._session_id = session_id
        self._session_token = session_token
        self._operation_count = 0
        self._max_operations = max_operations_before_rotation

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    @property
    def session_token(self) -> Optional[str]:
        return self._session_token

    def set_credentials(self, session_id: str, session_token: str) -> None:
        """Set new credentials."""
        self._session_id = session_id
        self._session_token = session_token
        self._operation_count = 0

    def clear_credentials(self) -> None:
        """Clear credentials."""
        self._session_id = None
        self._session_token = None
        self._operation_count = 0

    def is_authenticated(self) -> bool:
        """Check if authenticated."""
        return self._session_id is not None and self._session_token is not None

    def get_authorization_header(self) -> Optional[str]:
        """Get authorization header value."""
        if not self._session_id or not self._session_token:
            return None
        return f"Bearer {self._session_id}:{self._session_token}"

    async def increment_operation_count(self) -> bool:
        """Increment operation count and check if rotation is needed."""
        self._operation_count += 1
        return self._operation_count >= self._max_operations

    @property
    def operation_count(self) -> int:
        return self._operation_count


class CircuitBreaker:
    """Circuit breaker for resilient connections."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        self._state: str = "closed"
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._success_count = 0
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold

    def can_request(self) -> bool:
        """Check if request should be allowed."""
        if self._state == "closed":
            return True

        if self._state == "open":
            import time

            elapsed = time.time() - self._last_failure_time
            if elapsed >= self._recovery_timeout:
                self._state = "half-open"
                self._success_count = 0
                return True
            return False

        # half-open: allow limited requests
        return True

    def record_success(self) -> None:
        """Record a successful request."""
        if self._state == "half-open":
            self._success_count += 1
            if self._success_count >= self._success_threshold:
                self._state = "closed"
                self._failure_count = 0
        elif self._state == "closed":
            self._failure_count = 0

    def record_failure(self) -> None:
        """Record a failed request."""
        import time

        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._state == "half-open":
            self._state = "open"
        elif self._failure_count >= self._failure_threshold:
            self._state = "open"

    @property
    def state(self) -> str:
        return self._state

    def reset(self) -> None:
        """Reset the circuit breaker."""
        self._state = "closed"
        self._failure_count = 0
        self._success_count = 0


class RetryStrategy:
    """Retry strategy with exponential backoff."""

    def __init__(self, config: Optional[RetryConfig] = None) -> None:
        config = config or RetryConfig()
        self._max_retries = config.max_retries
        self._base_delay = config.base_delay
        self._max_delay = config.max_delay
        self._jitter = config.jitter
        self._retry_on_status = set(config.retry_on_status)

    def should_retry(self, status_code: int, attempt: int) -> bool:
        """Check if status code should be retried."""
        return attempt < self._max_retries and status_code in self._retry_on_status

    def should_retry_error(self, error: Exception, attempt: int) -> bool:
        """Check if error should be retried."""
        if attempt >= self._max_retries:
            return False
        return isinstance(error, (NetworkError, httpx.NetworkError, httpx.TimeoutException))

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for next retry."""
        exponential_delay = self._base_delay * (2**attempt)
        capped_delay = min(exponential_delay, self._max_delay)
        jitter_amount = capped_delay * self._jitter * random.random()
        return capped_delay + jitter_amount

    async def sleep(self, attempt: int) -> None:
        """Sleep for the calculated delay."""
        delay = self.get_delay(attempt)
        await asyncio.sleep(delay)


class HsmClient:
    """HSM Client for interacting with HSM server."""

    def __init__(self, config: HsmClientConfig) -> None:
        self._base_url = config.base_url.rstrip("/")
        self._timeout = config.timeout
        self._headers = config.headers.copy()
        self._token_manager = TokenManager(config.session_id, config.session_token)
        self._circuit_breaker = CircuitBreaker()
        self._retry_strategy = RetryStrategy(config.retry)
        self._client = httpx.AsyncClient(timeout=config.timeout)
        self.keys = KeyManager(self)

    async def __aenter__(self) -> "HsmClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
        attempt: int = 0,
    ) -> Any:
        """Make an HTTP request."""
        if not self._circuit_breaker.can_request():
            raise HsmError("Circuit breaker is open", code="CIRCUIT_OPEN")

        url = f"{self._base_url}{path}"
        headers = {"Content-Type": "application/json", **self._headers}

        auth_header = self._token_manager.get_authorization_header()
        if auth_header:
            headers["Authorization"] = auth_header

        try:
            response = await self._client.request(
                method,
                url,
                json=body,
                headers=headers,
            )

            if not response.is_success:
                try:
                    error_body = response.json()
                except Exception:
                    error_body = {}

                if self._retry_strategy.should_retry(response.status_code, attempt):
                    self._circuit_breaker.record_failure()
                    await self._retry_strategy.sleep(attempt)
                    return await self._request(method, path, body, attempt + 1)

                self._circuit_breaker.record_failure()
                raise parse_error_response(response.status_code, error_body)

            self._circuit_breaker.record_success()
            await self._token_manager.increment_operation_count()

            if not response.text:
                return {}

            return response.json()

        except httpx.TimeoutException as e:
            self._circuit_breaker.record_failure()
            raise TimeoutError() from e

        except httpx.NetworkError as e:
            if self._retry_strategy.should_retry_error(e, attempt):
                self._circuit_breaker.record_failure()
                await self._retry_strategy.sleep(attempt)
                return await self._request(method, path, body, attempt + 1)
            self._circuit_breaker.record_failure()
            raise NetworkError(str(e)) from e

    async def _get(self, path: str) -> Any:
        return await self._request("GET", path)

    async def _post(self, path: str, body: Optional[dict[str, Any]] = None) -> Any:
        return await self._request("POST", path, body)

    async def _delete(self, path: str) -> Any:
        return await self._request("DELETE", path)

    # =========================================================================
    # Authentication
    # =========================================================================

    def set_credentials(self, session_id: str, session_token: str) -> None:
        """Set session credentials."""
        self._token_manager.set_credentials(session_id, session_token)

    def clear_credentials(self) -> None:
        """Clear session credentials."""
        self._token_manager.clear_credentials()

    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._token_manager.is_authenticated()

    # =========================================================================
    # Health Check
    # =========================================================================

    async def health(self) -> HealthResponse:
        """Check server health."""
        data = await self._get("/health")
        return HealthResponse(**data)

    async def ready(self) -> ReadyResponse:
        """Check server readiness."""
        data = await self._get("/ready")
        return ReadyResponse(**data)

    # =========================================================================
    # Key Management
    # =========================================================================

    async def generate_key(self, request: GenerateKeyRequest) -> GenerateKeyResponse:
        """Generate a new key."""
        data = await self._post("/keys", request.model_dump(exclude_none=True))
        return GenerateKeyResponse(**data)

    async def get_key(self, key_id: str) -> KeyMetadata:
        """Get key metadata."""
        data = await self._get(f"/keys/{quote(key_id, safe='')}")
        return KeyMetadata(**data)

    async def list_keys(
        self, options: Optional[ListKeysOptions] = None
    ) -> ListKeysResponse:
        """List keys."""
        params = {}
        if options:
            if options.namespace:
                params["namespace"] = options.namespace
            if options.limit:
                params["limit"] = str(options.limit)
            if options.cursor:
                params["cursor"] = options.cursor
            if options.state:
                params["state"] = options.state.value

        query = f"?{urlencode(params)}" if params else ""
        data = await self._get(f"/keys{query}")
        return ListKeysResponse(**data)

    async def delete_key(self, key_id: str) -> None:
        """Delete a key."""
        await self._delete(f"/keys/{quote(key_id, safe='')}")

    # =========================================================================
    # Cryptographic Operations
    # =========================================================================

    async def sign(
        self,
        key_id: str,
        data: Union[bytes, str],
        hash_algorithm: Optional[str] = None,
    ) -> SignResponse:
        """Sign data with a key."""
        body = {
            "data": normalize_to_base64(data),
        }
        if hash_algorithm:
            body["hash_algorithm"] = hash_algorithm
        result = await self._post(f"/keys/{quote(key_id, safe='')}/sign", body)
        return SignResponse(**result)

    async def verify(
        self,
        key_id: str,
        data: Union[bytes, str],
        signature: str,
    ) -> VerifyResponse:
        """Verify a signature."""
        body = {
            "data": normalize_to_base64(data),
            "signature": signature,
        }
        result = await self._post(f"/keys/{quote(key_id, safe='')}/verify", body)
        return VerifyResponse(**result)

    async def encrypt(
        self,
        key_id: str,
        plaintext: Union[bytes, str],
        aad: Optional[str] = None,
    ) -> EncryptResponse:
        """Encrypt data with a key."""
        body: dict[str, Any] = {
            "plaintext": normalize_to_base64(plaintext),
        }
        if aad:
            body["aad"] = aad
        result = await self._post(f"/keys/{quote(key_id, safe='')}/encrypt", body)
        return EncryptResponse(**result)

    async def decrypt(
        self,
        key_id: str,
        ciphertext: str,
        nonce: str,
        tag: Optional[str] = None,
        aad: Optional[str] = None,
    ) -> DecryptResponse:
        """Decrypt data with a key."""
        body: dict[str, Any] = {
            "ciphertext": ciphertext,
            "nonce": nonce,
        }
        if tag:
            body["tag"] = tag
        if aad:
            body["aad"] = aad
        result = await self._post(f"/keys/{quote(key_id, safe='')}/decrypt", body)
        return DecryptResponse(**result)

    # =========================================================================
    # Batch Operations
    # =========================================================================

    async def batch_sign(self, request: BatchSignRequest) -> BatchSignResponse:
        """Sign multiple messages in batch."""
        body = {"requests": [r.model_dump(exclude_none=True) for r in request.requests]}
        result = await self._post("/keys/batch/sign", body)
        return BatchSignResponse(**result)

    async def batch_verify(self, request: BatchVerifyRequest) -> BatchVerifyResponse:
        """Verify multiple signatures in batch."""
        body = {"requests": [r.model_dump(exclude_none=True) for r in request.requests]}
        result = await self._post("/keys/batch/verify", body)
        return BatchVerifyResponse(**result)

    async def batch_encrypt(self, request: BatchEncryptRequest) -> BatchEncryptResponse:
        """Encrypt multiple messages in batch."""
        body = {"requests": [r.model_dump(exclude_none=True) for r in request.requests]}
        result = await self._post("/keys/batch/encrypt", body)
        return BatchEncryptResponse(**result)

    async def batch_decrypt(self, request: BatchDecryptRequest) -> BatchDecryptResponse:
        """Decrypt multiple messages in batch."""
        body = {"requests": [r.model_dump(exclude_none=True) for r in request.requests]}
        result = await self._post("/keys/batch/decrypt", body)
        return BatchDecryptResponse(**result)

    # =========================================================================
    # Audit
    # =========================================================================

    async def get_audit_log(
        self, options: Optional[AuditLogOptions] = None
    ) -> AuditLogResponse:
        """Get audit log entries."""
        params = {}
        if options:
            if options.namespace:
                params["namespace"] = options.namespace
            if options.start_time:
                time = (
                    options.start_time.isoformat()
                    if isinstance(options.start_time, datetime)
                    else options.start_time
                )
                params["start_time"] = time
            if options.end_time:
                time = (
                    options.end_time.isoformat()
                    if isinstance(options.end_time, datetime)
                    else options.end_time
                )
                params["end_time"] = time
            if options.user_id:
                params["user_id"] = options.user_id
            if options.operation:
                params["operation"] = options.operation
            if options.limit:
                params["limit"] = str(options.limit)
            if options.cursor:
                params["cursor"] = options.cursor

        query = f"?{urlencode(params)}" if params else ""
        data = await self._get(f"/audit{query}")
        return AuditLogResponse(**data)

    async def stream_audit_log(
        self, options: Optional[AuditLogOptions] = None
    ) -> AsyncIterator[AuditEntry]:
        """Stream audit log entries with automatic pagination."""
        cursor: Optional[str] = None
        while True:
            opts = options or AuditLogOptions()
            opts.cursor = cursor
            response = await self.get_audit_log(opts)
            for entry in response.entries:
                yield entry
            cursor = response.next_cursor
            if not cursor:
                break

    # =========================================================================
    # Utility Methods
    # =========================================================================

    @property
    def circuit_state(self) -> str:
        """Get the circuit breaker state."""
        return self._circuit_breaker.state

    def reset_circuit_breaker(self) -> None:
        """Reset the circuit breaker."""
        self._circuit_breaker.reset()

    @property
    def operation_count(self) -> int:
        """Get the operation count."""
        return self._token_manager.operation_count


def create_client(
    base_url: str,
    *,
    session_id: Optional[str] = None,
    session_token: Optional[str] = None,
    timeout: float = 30.0,
    headers: Optional[dict[str, str]] = None,
    retry: Optional[RetryConfig] = None,
) -> HsmClient:
    """Create a new HSM client."""
    config = HsmClientConfig(
        base_url=base_url,
        session_id=session_id,
        session_token=session_token,
        timeout=timeout,
        headers=headers or {},
        retry=retry,
    )
    return HsmClient(config)
