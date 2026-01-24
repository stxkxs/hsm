"""
HSM Client Models

Pydantic models for request and response types.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ============================================================================
# Key Management Types
# ============================================================================


class KeyAlgorithm(str, Enum):
    """Supported key algorithms."""

    ED25519 = "ED25519"
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_P384 = "ECDSA_P384"
    RSA2048 = "RSA2048"
    RSA3072 = "RSA3072"
    RSA4096 = "RSA4096"
    AES128 = "AES128"
    AES256 = "AES256"


class KeyPurpose(str, Enum):
    """Key purpose/usage."""

    SIGN = "SIGN"
    ENCRYPT = "ENCRYPT"
    GENERAL = "GENERAL"


class KeyState(str, Enum):
    """Key state."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    COMPROMISED = "COMPROMISED"
    DESTROYED = "DESTROYED"


class GenerateKeyRequest(BaseModel):
    """Request to generate a new key."""

    key_id: Optional[str] = Field(None, description="Unique key identifier")
    algorithm: KeyAlgorithm = Field(..., description="Key algorithm")
    purpose: KeyPurpose = Field(KeyPurpose.GENERAL, description="Key purpose")
    namespace: str = Field("default", description="Namespace for the key")
    labels: dict[str, str] = Field(default_factory=dict, description="Key labels")


class GenerateKeyResponse(BaseModel):
    """Response after generating a key."""

    key_id: str = Field(..., description="Generated key ID")
    algorithm: KeyAlgorithm = Field(..., description="Key algorithm")
    purpose: KeyPurpose = Field(..., description="Key purpose")
    public_key: Optional[str] = Field(None, description="Public key (base64)")
    created_at: str = Field(..., description="Creation timestamp")


class KeyMetadata(BaseModel):
    """Key metadata."""

    key_id: str = Field(..., description="Key ID")
    algorithm: KeyAlgorithm = Field(..., description="Key algorithm")
    purpose: KeyPurpose = Field(..., description="Key purpose")
    namespace: str = Field(..., description="Namespace")
    public_key: Optional[str] = Field(None, description="Public key (base64)")
    created_at: str = Field(..., description="Creation timestamp")
    last_used: Optional[str] = Field(None, description="Last used timestamp")
    labels: dict[str, str] = Field(default_factory=dict, description="Key labels")
    active: bool = Field(True, description="Whether the key is active")


class ListKeysResponse(BaseModel):
    """List keys response."""

    keys: list[KeyMetadata] = Field(..., description="List of keys")
    total: int = Field(..., description="Total count")
    next_cursor: Optional[str] = Field(None, description="Next page cursor")


class ListKeysOptions(BaseModel):
    """List keys options."""

    namespace: Optional[str] = None
    limit: Optional[int] = None
    cursor: Optional[str] = None
    state: Optional[KeyState] = None


# ============================================================================
# Cryptographic Operation Types
# ============================================================================


class SignRequest(BaseModel):
    """Request to sign data."""

    data: str = Field(..., description="Data to sign (base64)")
    hash_algorithm: Optional[str] = Field(None, description="Hash algorithm")


class SignResponse(BaseModel):
    """Sign response."""

    signature: str = Field(..., description="Signature (base64)")
    algorithm: str = Field(..., description="Algorithm used")


class VerifyRequest(BaseModel):
    """Request to verify a signature."""

    data: str = Field(..., description="Original data (base64)")
    signature: str = Field(..., description="Signature to verify (base64)")


class VerifyResponse(BaseModel):
    """Verify response."""

    valid: bool = Field(..., description="Whether the signature is valid")


class EncryptRequest(BaseModel):
    """Request to encrypt data."""

    plaintext: str = Field(..., description="Plaintext data (base64)")
    aad: Optional[str] = Field(None, description="Additional authenticated data")


class EncryptResponse(BaseModel):
    """Encrypt response."""

    ciphertext: str = Field(..., description="Ciphertext (base64)")
    nonce: str = Field(..., description="Nonce (base64)")
    tag: Optional[str] = Field(None, description="Authentication tag (base64)")


class DecryptRequest(BaseModel):
    """Request to decrypt data."""

    ciphertext: str = Field(..., description="Ciphertext (base64)")
    nonce: str = Field(..., description="Nonce (base64)")
    tag: Optional[str] = Field(None, description="Authentication tag (base64)")
    aad: Optional[str] = Field(None, description="Additional authenticated data")


class DecryptResponse(BaseModel):
    """Decrypt response."""

    plaintext: str = Field(..., description="Decrypted plaintext (base64)")


# ============================================================================
# Batch Operation Types
# ============================================================================


class BatchSignItem(BaseModel):
    """Single item in batch sign request."""

    key_id: str
    data: str
    hash_algorithm: Optional[str] = None


class BatchSignRequest(BaseModel):
    """Batch sign request."""

    requests: list[BatchSignItem]


class BatchSignResponse(BaseModel):
    """Batch sign response."""

    results: list[SignResponse | dict[str, str]]


class BatchVerifyItem(BaseModel):
    """Single item in batch verify request."""

    key_id: str
    data: str
    signature: str


class BatchVerifyRequest(BaseModel):
    """Batch verify request."""

    requests: list[BatchVerifyItem]


class BatchVerifyResponse(BaseModel):
    """Batch verify response."""

    results: list[VerifyResponse | dict[str, str]]


class BatchEncryptItem(BaseModel):
    """Single item in batch encrypt request."""

    key_id: str
    plaintext: str
    aad: Optional[str] = None


class BatchEncryptRequest(BaseModel):
    """Batch encrypt request."""

    requests: list[BatchEncryptItem]


class BatchEncryptResponse(BaseModel):
    """Batch encrypt response."""

    results: list[EncryptResponse | dict[str, str]]


class BatchDecryptItem(BaseModel):
    """Single item in batch decrypt request."""

    key_id: str
    ciphertext: str
    nonce: str
    tag: Optional[str] = None
    aad: Optional[str] = None


class BatchDecryptRequest(BaseModel):
    """Batch decrypt request."""

    requests: list[BatchDecryptItem]


class BatchDecryptResponse(BaseModel):
    """Batch decrypt response."""

    results: list[DecryptResponse | dict[str, str]]


# ============================================================================
# Audit Types
# ============================================================================


class AuditEntry(BaseModel):
    """Audit log entry."""

    id: str = Field(..., description="Entry ID")
    timestamp: str = Field(..., description="Timestamp")
    event_type: str = Field(..., description="Event type")
    actor: str = Field(..., description="Actor")
    resource: Optional[str] = Field(None, description="Resource")
    action: str = Field(..., description="Action")
    result: str = Field(..., description="Result")
    details: Optional[str] = Field(None, description="Details")


class AuditLogResponse(BaseModel):
    """Audit log response."""

    entries: list[AuditEntry] = Field(..., description="Audit entries")
    total: int = Field(..., description="Total count")
    next_cursor: Optional[str] = Field(None, description="Next page cursor")


class AuditLogOptions(BaseModel):
    """Audit log query options."""

    namespace: Optional[str] = None
    start_time: Optional[str | datetime] = None
    end_time: Optional[str | datetime] = None
    user_id: Optional[str] = None
    operation: Optional[str] = None
    limit: Optional[int] = None
    cursor: Optional[str] = None


# ============================================================================
# Health Types
# ============================================================================


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status")
    version: str = Field(..., description="Service version")
    uptime_seconds: int = Field(..., description="Uptime in seconds")


class ComponentStatus(BaseModel):
    """Component status for readiness check."""

    status: str = Field(..., description="Component status")
    message: Optional[str] = Field(None, description="Optional message")


class ReadyResponse(BaseModel):
    """Readiness check response."""

    ready: bool = Field(..., description="Whether the service is ready")
    components: dict[str, ComponentStatus] = Field(..., description="Component status")


# ============================================================================
# Configuration Types
# ============================================================================


class RetryConfig(BaseModel):
    """Retry configuration."""

    max_retries: int = Field(3, description="Maximum number of retries")
    base_delay: float = Field(0.1, description="Base delay in seconds")
    max_delay: float = Field(5.0, description="Maximum delay in seconds")
    jitter: float = Field(0.1, description="Jitter factor")
    retry_on_status: list[int] = Field(
        default_factory=lambda: [429, 502, 503, 504],
        description="Status codes to retry on",
    )


class SessionScope(BaseModel):
    """Session scope for limiting session capabilities."""

    allowed_operations: Optional[list[str]] = None
    allowed_keys: Optional[list[str]] = None
    max_operations: Optional[int] = None
    rate_limit: Optional[int] = None


class HsmClientConfig(BaseModel):
    """HSM Client configuration."""

    base_url: str = Field(..., description="Base URL of the HSM server")
    session_id: Optional[str] = Field(None, description="Session ID")
    session_token: Optional[str] = Field(None, description="Session token")
    timeout: float = Field(30.0, description="Request timeout in seconds")
    headers: dict[str, str] = Field(default_factory=dict, description="Custom headers")
    retry: Optional[RetryConfig] = None
