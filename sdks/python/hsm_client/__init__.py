"""
HSM Python SDK

Official Python SDK for HSM (Hardware Security Module).

Example Usage::

    from hsm_client import HsmClient

    client = HsmClient(
        base_url="https://hsm.example.com",
        session_id="session-id",
        session_token="session-token",
    )

    # Generate a key
    key = await client.keys.generate_ed25519(namespace="my-app")

    # Sign data
    result = await client.sign(key.key_id, data=b"Hello, World!")

    # Verify signature
    valid = await client.verify(
        key.key_id,
        data=b"Hello, World!",
        signature=result.signature,
    )
"""

from hsm_client.client import HsmClient, create_client
from hsm_client.models import (
    # Key management
    KeyAlgorithm,
    KeyPurpose,
    KeyState,
    GenerateKeyRequest,
    GenerateKeyResponse,
    KeyMetadata,
    ListKeysResponse,
    ListKeysOptions,
    # Cryptographic operations
    SignRequest,
    SignResponse,
    VerifyRequest,
    VerifyResponse,
    EncryptRequest,
    EncryptResponse,
    DecryptRequest,
    DecryptResponse,
    # Batch operations
    BatchSignRequest,
    BatchSignResponse,
    BatchVerifyRequest,
    BatchVerifyResponse,
    BatchEncryptRequest,
    BatchEncryptResponse,
    BatchDecryptRequest,
    BatchDecryptResponse,
    # Audit
    AuditEntry,
    AuditLogResponse,
    AuditLogOptions,
    # Health
    HealthResponse,
    ReadyResponse,
    ComponentStatus,
    # Config
    HsmClientConfig,
    RetryConfig,
    SessionScope,
)
from hsm_client.exceptions import (
    HsmError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationError,
    RateLimitError,
    NetworkError,
    TimeoutError,
    ServerError,
    CryptoError,
    SessionError,
)
from hsm_client.crypto import (
    to_base64,
    from_base64,
    to_hex,
    from_hex,
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
    "BatchSignRequest",
    "BatchSignResponse",
    "BatchVerifyRequest",
    "BatchVerifyResponse",
    "BatchEncryptRequest",
    "BatchEncryptResponse",
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
