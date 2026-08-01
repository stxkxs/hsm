# hsm-client

Official Python SDK for the [HSM](https://github.com/stxkxs/hsm) (Hardware Security Module) service.

The client is fully asynchronous (built on [httpx](https://www.python-httpx.org/)), fully typed
(ships a `py.typed` marker), and models every request/response with
[pydantic](https://docs.pydantic.dev/) v2.

## Requirements

- Python 3.10+
- `httpx >= 0.28`
- `pydantic >= 2.12`

## Installation

```bash
pip install hsm-client
```

From a checkout of this repository:

```bash
cd sdks/python
pip install -e '.[dev]'
```

## Quick start

```python
import asyncio

from hsm_client import KeyAlgorithm, create_client


async def main() -> None:
    async with create_client(
        "https://hsm.example.com",
        session_id="session-id",
        session_token="session-token",
    ) as client:
        # Generate an Ed25519 signing key
        key = await client.keys.generate_ed25519(namespace="my-app")

        # Sign some data (bytes and str are both accepted)
        signed = await client.sign(key.key_id, b"Hello, World!")

        # Verify the signature
        result = await client.verify(key.key_id, b"Hello, World!", signed.signature)
        assert result.valid


asyncio.run(main())
```

`create_client` is the convenience constructor. The equivalent explicit form is:

```python
from hsm_client import HsmClient, HsmClientConfig

client = HsmClient(HsmClientConfig(base_url="https://hsm.example.com"))
```

`HsmClient` is an async context manager. If you construct one without `async with`,
call `await client.close()` when you are done so the underlying connection pool is released.

## Authentication

Credentials are sent as an `Authorization: Bearer <session_id>:<session_token>` header.

```python
client.set_credentials("session-id", "session-token")
client.is_authenticated()  # True
client.clear_credentials()
```

## Key management

The `client.keys` namespace exposes algorithm-specific helpers:

```python
await client.keys.generate_ed25519(namespace="my-app")
await client.keys.generate_ecdsa_p256()
await client.keys.generate_ecdsa_p384()
await client.keys.generate_rsa(2048)     # 2048 | 3072 | 4096
await client.keys.generate_aes(256)      # 128 | 256

await client.keys.get("key-id")
await client.keys.exists("key-id")
await client.keys.delete("key-id")
```

`list` returns a single page; `list_all` transparently follows the cursor:

```python
page = await client.keys.list(namespace="my-app", limit=100)

async for key in client.keys.list_all(namespace="my-app"):
    print(key.key_id, key.algorithm)
```

For full control, use the lower-level request model:

```python
from hsm_client import GenerateKeyRequest, KeyAlgorithm, KeyPurpose

await client.generate_key(
    GenerateKeyRequest(
        key_id="my-key",
        algorithm=KeyAlgorithm.ED25519,
        purpose=KeyPurpose.SIGN,
        namespace="my-app",
        labels={"env": "prod"},
    )
)
```

## Cryptographic operations

```python
sig = await client.sign("key-id", b"message")
ok = await client.verify("key-id", b"message", sig.signature)

enc = await client.encrypt("key-id", b"secret", aad="context")
dec = await client.decrypt("key-id", enc.ciphertext, enc.nonce, tag=enc.tag, aad="context")
```

Binary payloads are base64-encoded for you. `bytes` are always encoded; a `str` that is
already valid base64 is passed through unchanged, otherwise it is UTF-8 encoded first.

> **Pass `bytes`, not `str`, for anything you did not base64-encode yourself.**
> The `str` path guesses, and the guess is ambiguous: any string whose length is a
> multiple of 4 drawn from the base64 alphabet is assumed to *already* be base64.
> `sign(key, "test")` therefore signs the three bytes `b"\xb5\xeb-"`, not `b"test"`.
> `sign(key, b"test")` always signs exactly `b"test"`.

## Batch operations

```python
from hsm_client import BatchSignItem, BatchSignRequest

resp = await client.batch_sign(
    BatchSignRequest(
        requests=[
            BatchSignItem(key_id="key-a", data="bWVzc2FnZQ=="),
            BatchSignItem(key_id="key-b", data="bWVzc2FnZQ=="),
        ]
    )
)
```

Each entry of `resp.results` is either the success model (`SignResponse`) or a
`dict` describing the per-item error.

## Audit log

```python
from hsm_client import AuditLogOptions

page = await client.get_audit_log(AuditLogOptions(namespace="my-app", limit=100))

async for entry in client.stream_audit_log(AuditLogOptions(namespace="my-app")):
    print(entry.timestamp, entry.action, entry.result)
```

## Health

```python
health = await client.health()   # HealthResponse(status=..., version=..., uptime_seconds=...)
ready = await client.ready()     # ReadyResponse(ready=..., components={...})
```

## Resilience

Every request goes through a retry strategy and a circuit breaker.

```python
from hsm_client import RetryConfig, create_client

client = create_client(
    "https://hsm.example.com",
    timeout=30.0,
    retry=RetryConfig(
        max_retries=3,
        base_delay=0.1,
        max_delay=5.0,
        jitter=0.1,
        retry_on_status=[429, 502, 503, 504],
    ),
)

client.circuit_state          # "closed" | "open" | "half-open"
client.reset_circuit_breaker()
```

Retries use exponential backoff with jitter and apply to the configured status codes as
well as to network and timeout errors.

## Errors

All errors derive from `HsmError`, which carries `message`, `status_code`, `code` and `details`.

| Exception | Status | `code` |
| --- | --- | --- |
| `ValidationError` | 400 | `VALIDATION_ERROR` |
| `AuthenticationError` | 401 | `AUTHENTICATION_FAILED` |
| `SessionError` | 401 | `SESSION_ERROR` |
| `AuthorizationError` | 403 | `AUTHORIZATION_FAILED` |
| `NotFoundError` | 404 | `NOT_FOUND` |
| `RateLimitError` | 429 | `RATE_LIMIT_EXCEEDED` |
| `ServerError` | 5xx | `SERVER_ERROR` |
| `NetworkError` | — | `NETWORK_ERROR` |
| `TimeoutError` | — | `TIMEOUT` |
| `CryptoError` | — | `CRYPTO_ERROR` |

```python
from hsm_client import HsmError, NotFoundError

try:
    await client.keys.get("missing")
except NotFoundError:
    ...
except HsmError as exc:
    print(exc.code, exc.status_code, exc.message)
```

Note that `hsm_client.TimeoutError` shadows the builtin `TimeoutError` when star-imported;
prefer `from hsm_client import exceptions` if that matters to you.

## Crypto utilities

```python
from hsm_client import from_base64, from_hex, to_base64, to_hex
from hsm_client.crypto import (
    constant_time_compare,
    der_to_raw,
    hmac_sha256,
    random_bytes,
    raw_to_der,
    sha256,
    sha384,
    sha512,
)
```

`der_to_raw` / `raw_to_der` convert ECDSA signatures between DER and the 64-byte
`R || S` form expected by Ethereum and similar chains.

## Development

```bash
pip install -e '.[dev]'
pytest
mypy hsm_client
ruff check .
```

## License

MIT OR Apache-2.0
