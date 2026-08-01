"""
HSM Python SDK

Official Python SDK for HSM (Hardware Security Module).

Example Usage::

    from hsm_client import create_client

    async with create_client(
        "https://hsm.example.com",
        session_id="session-id",
        session_token="session-token",
    ) as client:
        # Generate a key
        key = await client.keys.generate_ed25519(namespace="my-app")

        # Sign data
        result = await client.sign(key.key_id, b"Hello, World!")

        # Verify signature
        verified = await client.verify(key.key_id, b"Hello, World!", result.signature)
        assert verified.valid

``HsmClient`` itself takes a single ``HsmClientConfig``::

    from hsm_client import HsmClient, HsmClientConfig

    client = HsmClient(HsmClientConfig(base_url="https://hsm.example.com"))
"""

from hsm_client.client import HsmClient, create_client
from hsm_client.crypto import (
    from_base64,
    from_hex,
    to_base64,
    to_hex,
)
from hsm_client.exceptions import (
    AuthenticationError,
    AuthorizationError,
    CryptoError,
    HsmError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    ServerError,
    SessionError,
    TimeoutError,
    ValidationError,
)
from hsm_client.models import (
    # Audit
    AuditEntry,
    AuditLogOptions,
    AuditLogResponse,
    BatchDecryptItem,
    BatchDecryptRequest,
    BatchDecryptResponse,
    BatchEncryptItem,
    BatchEncryptRequest,
    BatchEncryptResponse,
    # Batch operations
    BatchSignItem,
    BatchSignRequest,
    BatchSignResponse,
    BatchVerifyItem,
    BatchVerifyRequest,
    BatchVerifyResponse,
    ComponentStatus,
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    GenerateKeyRequest,
    GenerateKeyResponse,
    # Health
    HealthResponse,
    # Config
    HsmClientConfig,
    # Key management
    KeyAlgorithm,
    KeyMetadata,
    KeyPurpose,
    KeyState,
    ListKeysOptions,
    ListKeysResponse,
    ReadyResponse,
    RetryConfig,
    SessionScope,
    # Cryptographic operations
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
)

__version__ = "0.1.0"
__all__ = [
    # Client
    "HsmClient",
    "create_client",
    # Models
    "KeyAlgorithm",
    "KeyPurpose",
    "KeyState",
    "GenerateKeyRequest",
    "GenerateKeyResponse",
    "KeyMetadata",
    "ListKeysResponse",
    "ListKeysOptions",
    "SignRequest",
    "SignResponse",
    "VerifyRequest",
    "VerifyResponse",
    "EncryptRequest",
    "EncryptResponse",
    "DecryptRequest",
    "DecryptResponse",
    "BatchSignItem",
    "BatchSignRequest",
    "BatchSignResponse",
    "BatchVerifyItem",
    "BatchVerifyRequest",
    "BatchVerifyResponse",
    "BatchEncryptItem",
    "BatchEncryptRequest",
    "BatchEncryptResponse",
    "BatchDecryptItem",
    "BatchDecryptRequest",
    "BatchDecryptResponse",
    "AuditEntry",
    "AuditLogResponse",
    "AuditLogOptions",
    "HealthResponse",
    "ReadyResponse",
    "ComponentStatus",
    "HsmClientConfig",
    "RetryConfig",
    "SessionScope",
    # Exceptions
    "HsmError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ValidationError",
    "RateLimitError",
    "NetworkError",
    "TimeoutError",
    "ServerError",
    "CryptoError",
    "SessionError",
    # Crypto utilities
    "to_base64",
    "from_base64",
    "to_hex",
    "from_hex",
]
