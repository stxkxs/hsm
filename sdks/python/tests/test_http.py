"""
HSM Client HTTP-layer tests.

These exercise the client against a mocked transport so that the request the SDK
actually puts on the wire, and the way it interprets responses, are both covered.
"""

import json
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

from hsm_client import (
    AuditLogOptions,
    AuthenticationError,
    AuthorizationError,
    BatchSignItem,
    BatchSignRequest,
    GenerateKeyRequest,
    HsmClient,
    HsmError,
    KeyAlgorithm,
    KeyPurpose,
    NetworkError,
    NotFoundError,
    RateLimitError,
    RetryConfig,
    ServerError,
    SignResponse,
    TimeoutError,
    ValidationError,
    create_client,
)

BASE = "https://hsm.example.com"

KEY_METADATA = {
    "key_id": "key-1",
    "algorithm": "ED25519",
    "purpose": "SIGN",
    "namespace": "default",
    "created_at": "2026-01-01T00:00:00Z",
}


def client(**kwargs: Any) -> HsmClient:
    return create_client(BASE, **kwargs)


class TestRequestWireFormat:
    """What the SDK actually sends."""

    async def test_generate_key_serializes_enums_as_strings(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json={
                "key_id": "key-1",
                "algorithm": "ED25519",
                "purpose": "SIGN",
                "created_at": "2026-01-01T00:00:00Z",
            }
        )
        async with client() as c:
            await c.generate_key(
                GenerateKeyRequest(
                    algorithm=KeyAlgorithm.ED25519,
                    purpose=KeyPurpose.SIGN,
                    namespace="my-app",
                )
            )

        req = httpx_mock.get_request()
        assert req is not None
        assert req.method == "POST"
        assert str(req.url) == f"{BASE}/keys"
        # Enums must go out as their plain string values, not "KeyAlgorithm.ED25519".
        assert json.loads(req.content) == {
            "algorithm": "ED25519",
            "purpose": "SIGN",
            "namespace": "my-app",
            "labels": {},
        }

    async def test_auth_header_format(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=KEY_METADATA)
        async with client(session_id="sid", session_token="stok") as c:
            await c.get_key("key-1")

        req = httpx_mock.get_request()
        assert req is not None
        assert req.headers["Authorization"] == "Bearer sid:stok"

    async def test_no_auth_header_when_unauthenticated(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=KEY_METADATA)
        async with client() as c:
            await c.get_key("key-1")

        req = httpx_mock.get_request()
        assert req is not None
        assert "Authorization" not in req.headers

    async def test_key_id_is_url_escaped(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=KEY_METADATA)
        async with client() as c:
            await c.get_key("ns/key with space")

        req = httpx_mock.get_request()
        assert req is not None
        # The slash must be escaped so it cannot create a new path segment.
        assert req.url.raw_path == b"/keys/ns%2Fkey%20with%20space"

    async def test_sign_base64_encodes_bytes(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"signature": "c2ln", "algorithm": "ED25519"})
        async with client() as c:
            result = await c.sign("key-1", b"Hello, World!", hash_algorithm="SHA-256")

        req = httpx_mock.get_request()
        assert req is not None
        assert json.loads(req.content) == {
            "data": "SGVsbG8sIFdvcmxkIQ==",
            "hash_algorithm": "SHA-256",
        }
        assert result.signature == "c2ln"

    async def test_sign_str_that_looks_like_base64_is_passed_through(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """Documents a sharp edge: `str` input is only *guessed* to be base64.

        "test" is 4 chars from the base64 alphabet, so it is forwarded verbatim and the
        server signs b"\\xb5\\xeb-". Callers with raw data must pass `bytes`.
        """
        httpx_mock.add_response(json={"signature": "c2ln", "algorithm": "ED25519"})
        async with client() as c:
            await c.sign("key-1", "test")
        req = httpx_mock.get_request()
        assert req is not None
        assert json.loads(req.content)["data"] == "test"

        httpx_mock.reset()
        httpx_mock.add_response(json={"signature": "c2ln", "algorithm": "ED25519"})
        async with client() as c:
            await c.sign("key-1", b"test")
        req = httpx_mock.get_request()
        assert req is not None
        assert json.loads(req.content)["data"] == "dGVzdA=="

    async def test_sign_omits_absent_hash_algorithm(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"signature": "c2ln", "algorithm": "ED25519"})
        async with client() as c:
            await c.sign("key-1", b"data")

        req = httpx_mock.get_request()
        assert req is not None
        assert "hash_algorithm" not in json.loads(req.content)

    async def test_encrypt_decrypt_bodies(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"ciphertext": "Y3Q=", "nonce": "bm9uY2U=", "tag": "dGFn"})
        async with client() as c:
            enc = await c.encrypt("key-1", b"secret", aad="ctx")
        req = httpx_mock.get_request()
        assert req is not None
        assert json.loads(req.content) == {
            "plaintext": "c2VjcmV0",
            "aad": "ctx",
        }
        assert enc.tag == "dGFn"

        httpx_mock.reset()
        httpx_mock.add_response(json={"plaintext": "c2VjcmV0"})
        async with client() as c:
            dec = await c.decrypt("key-1", "Y3Q=", "bm9uY2U=", tag="dGFn", aad="ctx")
        req = httpx_mock.get_request()
        assert req is not None
        assert json.loads(req.content) == {
            "ciphertext": "Y3Q=",
            "nonce": "bm9uY2U=",
            "tag": "dGFn",
            "aad": "ctx",
        }
        assert dec.plaintext == "c2VjcmV0"

    async def test_list_keys_query_params(self, httpx_mock: HTTPXMock) -> None:
        from hsm_client import ListKeysOptions
        from hsm_client.models import KeyState

        httpx_mock.add_response(json={"keys": [], "total": 0, "next_cursor": None})
        async with client() as c:
            await c.list_keys(
                ListKeysOptions(namespace="ns", limit=50, cursor="cur", state=KeyState.ACTIVE)
            )

        req = httpx_mock.get_request()
        assert req is not None
        assert dict(req.url.params) == {
            "namespace": "ns",
            "limit": "50",
            "cursor": "cur",
            "state": "ACTIVE",
        }

    async def test_batch_sign(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json={
                "results": [
                    {"signature": "c2ln", "algorithm": "ED25519"},
                    {"error": "key not found"},
                ]
            }
        )
        async with client() as c:
            resp = await c.batch_sign(
                BatchSignRequest(
                    requests=[
                        BatchSignItem(key_id="key-a", data="ZGF0YQ=="),
                        BatchSignItem(key_id="key-b", data="ZGF0YQ=="),
                    ]
                )
            )

        req = httpx_mock.get_request()
        assert req is not None
        assert req.url.path == "/keys/batch/sign"
        assert json.loads(req.content) == {
            "requests": [
                {"key_id": "key-a", "data": "ZGF0YQ=="},
                {"key_id": "key-b", "data": "ZGF0YQ=="},
            ]
        }
        assert isinstance(resp.results[0], SignResponse)
        assert resp.results[1] == {"error": "key not found"}

    async def test_empty_response_body_is_tolerated(self, httpx_mock: HTTPXMock) -> None:
        # DELETE typically answers 204 with no body.
        httpx_mock.add_response(status_code=204)
        async with client() as c:
            await c.delete_key("key-1")
        assert httpx_mock.get_request() is not None


class TestErrorMapping:
    """Status codes map onto the right exception types."""

    @pytest.mark.parametrize(
        ("status", "exc"),
        [
            (400, ValidationError),
            (401, AuthenticationError),
            (403, AuthorizationError),
            (404, NotFoundError),
            (429, RateLimitError),
            (500, ServerError),
            (503, ServerError),
        ],
    )
    async def test_status_to_exception(
        self, httpx_mock: HTTPXMock, status: int, exc: type[HsmError]
    ) -> None:
        httpx_mock.add_response(
            status_code=status,
            json={"error": "some_code", "message": "boom"},
            is_reusable=True,
        )
        # Disable retries so 429/503 surface immediately.
        async with client(retry=RetryConfig(max_retries=0)) as c:
            with pytest.raises(exc) as info:
                await c.get_key("key-1")
        assert info.value.status_code == status

    async def test_404_preserves_server_message(self, httpx_mock: HTTPXMock) -> None:
        """Regression: the 404 branch used to discard the server message."""
        httpx_mock.add_response(
            status_code=404,
            json={"error": "key_not_found", "message": "key 'abc' does not exist"},
        )
        async with client() as c:
            with pytest.raises(NotFoundError) as info:
                await c.get_key("abc")

        assert info.value.message == "key 'abc' does not exist"
        assert str(info.value) == "key 'abc' does not exist"

    async def test_server_error_code_and_details_are_preserved(self, httpx_mock: HTTPXMock) -> None:
        """Regression: the server's `error` code and `details` used to be dropped."""
        httpx_mock.add_response(
            status_code=400,
            json={
                "error": "invalid_algorithm",
                "message": "unsupported algorithm",
                "details": "algorithm must be one of ED25519, RSA2048",
            },
        )
        async with client() as c:
            with pytest.raises(ValidationError) as info:
                await c.get_key("key-1")

        assert info.value.code == "VALIDATION_ERROR"  # SDK taxonomy is stable
        assert info.value.details["error"] == "invalid_algorithm"
        assert info.value.details["details"] == "algorithm must be one of ED25519, RSA2048"

    async def test_non_json_error_body_does_not_crash(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=500, text="<html>gateway blew up</html>")
        async with client(retry=RetryConfig(max_retries=0)) as c:
            with pytest.raises(ServerError) as info:
                await c.get_key("key-1")
        assert info.value.message == "Unknown error"

    async def test_rate_limit_retry_after(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=429, json={"message": "slow down", "retry_after": 30})
        async with client(retry=RetryConfig(max_retries=0)) as c:
            with pytest.raises(RateLimitError) as info:
                await c.get_key("key-1")
        assert info.value.retry_after == 30


class TestRetries:
    """Retry strategy actually drives the request loop."""

    async def test_retries_retryable_status_then_succeeds(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={"message": "unavailable"})
        httpx_mock.add_response(status_code=503, json={"message": "unavailable"})
        httpx_mock.add_response(json={"status": "ok", "version": "1.0", "uptime_seconds": 5})

        async with client(retry=RetryConfig(max_retries=3, base_delay=0.001)) as c:
            health = await c.health()

        assert health.status == "ok"
        assert len(httpx_mock.get_requests()) == 3

    async def test_does_not_retry_non_retryable_status(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=400, json={"message": "bad"})
        async with client(retry=RetryConfig(max_retries=3, base_delay=0.001)) as c:
            with pytest.raises(ValidationError):
                await c.health()
        assert len(httpx_mock.get_requests()) == 1

    async def test_gives_up_after_max_retries(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={"message": "unavailable"}, is_reusable=True)
        async with client(retry=RetryConfig(max_retries=2, base_delay=0.001)) as c:
            with pytest.raises(ServerError):
                await c.health()
        # initial attempt + 2 retries
        assert len(httpx_mock.get_requests()) == 3

    async def test_retries_timeouts(self, httpx_mock: HTTPXMock) -> None:
        """Regression: timeouts were raised immediately, never retried."""
        httpx_mock.add_exception(httpx.ReadTimeout("too slow"), is_reusable=True)
        async with client(retry=RetryConfig(max_retries=2, base_delay=0.001)) as c:
            with pytest.raises(TimeoutError):
                await c.health()
        assert len(httpx_mock.get_requests()) == 3

    async def test_retries_network_errors(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("refused"), is_reusable=True)
        async with client(retry=RetryConfig(max_retries=2, base_delay=0.001)) as c:
            with pytest.raises(NetworkError):
                await c.health()
        assert len(httpx_mock.get_requests()) == 3


class TestCircuitBreaker:
    async def test_opens_after_repeated_failures_and_blocks(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("refused"), is_reusable=True)
        async with client(retry=RetryConfig(max_retries=0)) as c:
            for _ in range(5):
                with pytest.raises(NetworkError):
                    await c.health()
            assert c.circuit_state == "open"

            # Once open, requests are rejected without hitting the network.
            before = len(httpx_mock.get_requests())
            with pytest.raises(HsmError) as info:
                await c.health()
            assert info.value.code == "CIRCUIT_OPEN"
            assert len(httpx_mock.get_requests()) == before

            c.reset_circuit_breaker()
            assert c.circuit_state == "closed"


class TestOperationCount:
    async def test_counts_only_successful_operations(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=KEY_METADATA, is_reusable=True)
        async with client() as c:
            assert c.operation_count == 0
            await c.get_key("key-1")
            await c.get_key("key-1")
            assert c.operation_count == 2


class TestKeyManager:
    async def test_generate_ed25519_uses_sign_purpose(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json={
                "key_id": "key-1",
                "algorithm": "ED25519",
                "purpose": "SIGN",
                "created_at": "2026-01-01T00:00:00Z",
            }
        )
        async with client() as c:
            await c.keys.generate_ed25519(namespace="my-app", labels={"env": "prod"})

        req = httpx_mock.get_request()
        assert req is not None
        body = json.loads(req.content)
        assert body == {
            "algorithm": "ED25519",
            "purpose": "SIGN",
            "namespace": "my-app",
            "labels": {"env": "prod"},
        }

    @pytest.mark.parametrize(("size", "algorithm"), [(2048, "RSA2048"), (4096, "RSA4096")])
    async def test_generate_rsa(self, httpx_mock: HTTPXMock, size: int, algorithm: str) -> None:
        httpx_mock.add_response(
            json={
                "key_id": "key-1",
                "algorithm": algorithm,
                "purpose": "SIGN",
                "created_at": "2026-01-01T00:00:00Z",
            }
        )
        async with client() as c:
            await c.keys.generate_rsa(size)
        req = httpx_mock.get_request()
        assert req is not None
        assert json.loads(req.content)["algorithm"] == algorithm

    async def test_generate_rsa_rejects_bad_size(self) -> None:
        async with client() as c:
            with pytest.raises(ValueError, match="Invalid RSA size"):
                await c.keys.generate_rsa(1024)

    async def test_generate_aes_rejects_bad_size(self) -> None:
        async with client() as c:
            with pytest.raises(ValueError, match="Invalid AES size"):
                await c.keys.generate_aes(192)

    async def test_exists_true(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=KEY_METADATA)
        async with client() as c:
            assert await c.keys.exists("key-1") is True

    async def test_exists_false_on_404(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=404, json={"message": "nope"})
        async with client() as c:
            assert await c.keys.exists("key-1") is False

    async def test_exists_propagates_non_404_failures(self, httpx_mock: HTTPXMock) -> None:
        """Regression: an outage used to be reported as 'key does not exist'."""
        httpx_mock.add_exception(httpx.ConnectError("dns failure"), is_reusable=True)
        async with client(retry=RetryConfig(max_retries=0)) as c:
            with pytest.raises(NetworkError):
                await c.keys.exists("key-1")

    async def test_exists_propagates_auth_failures(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=401, json={"message": "bad token"})
        async with client() as c:
            with pytest.raises(AuthenticationError):
                await c.keys.exists("key-1")

    async def test_list_all_paginates(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json={
                "keys": [KEY_METADATA | {"key_id": "key-1"}],
                "total": 2,
                "next_cursor": "cur2",
            }
        )
        httpx_mock.add_response(
            json={
                "keys": [KEY_METADATA | {"key_id": "key-2"}],
                "total": 2,
                "next_cursor": None,
            }
        )
        async with client() as c:
            found = [k.key_id async for k in c.keys.list_all(namespace="ns")]

        assert found == ["key-1", "key-2"]
        requests = httpx_mock.get_requests()
        assert "cursor" not in dict(requests[0].url.params)
        assert dict(requests[1].url.params)["cursor"] == "cur2"


class TestAuditLog:
    async def test_stream_paginates(self, httpx_mock: HTTPXMock) -> None:
        entry = {
            "id": "e1",
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "crypto_operation",
            "actor": "svc",
            "action": "sign",
            "result": "success",
        }
        httpx_mock.add_response(json={"entries": [entry], "total": 2, "next_cursor": "cur2"})
        httpx_mock.add_response(
            json={"entries": [entry | {"id": "e2"}], "total": 2, "next_cursor": None}
        )
        async with client() as c:
            ids = [e.id async for e in c.stream_audit_log(AuditLogOptions(namespace="ns"))]
        assert ids == ["e1", "e2"]

    async def test_stream_does_not_mutate_caller_options(self, httpx_mock: HTTPXMock) -> None:
        """Regression: streaming used to write the cursor back into the caller's object."""
        httpx_mock.add_response(json={"entries": [], "total": 0, "next_cursor": "cur2"})
        httpx_mock.add_response(json={"entries": [], "total": 0, "next_cursor": None})

        options = AuditLogOptions(namespace="ns")
        async with client() as c:
            async for _ in c.stream_audit_log(options):
                pass

        assert options.cursor is None
        assert options.namespace == "ns"

    async def test_datetime_bounds_are_isoformatted(self, httpx_mock: HTTPXMock) -> None:
        from datetime import datetime, timezone

        httpx_mock.add_response(json={"entries": [], "total": 0, "next_cursor": None})
        async with client() as c:
            await c.get_audit_log(
                AuditLogOptions(
                    start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    end_time="2026-02-01T00:00:00Z",
                )
            )

        req = httpx_mock.get_request()
        assert req is not None
        params = dict(req.url.params)
        assert params["start_time"] == "2026-01-01T00:00:00+00:00"
        assert params["end_time"] == "2026-02-01T00:00:00Z"


class TestHealth:
    async def test_health(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"status": "ok", "version": "1.2.3", "uptime_seconds": 42})
        async with client() as c:
            health = await c.health()
        assert (health.status, health.version, health.uptime_seconds) == ("ok", "1.2.3", 42)

    async def test_ready(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json={
                "ready": True,
                "components": {"storage": {"status": "ok", "message": None}},
            }
        )
        async with client() as c:
            ready = await c.ready()
        assert ready.ready is True
        assert ready.components["storage"].status == "ok"
