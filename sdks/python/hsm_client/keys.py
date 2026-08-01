"""
HSM Key Management

High-level key management operations.
"""

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Protocol

from hsm_client.exceptions import NotFoundError
from hsm_client.models import (
    GenerateKeyRequest,
    GenerateKeyResponse,
    KeyAlgorithm,
    KeyMetadata,
    KeyPurpose,
    ListKeysOptions,
    ListKeysResponse,
)

if TYPE_CHECKING:
    from hsm_client.client import HsmClient


class KeyManagerClient(Protocol):
    """Protocol for key manager client operations."""

    async def generate_key(self, request: GenerateKeyRequest) -> GenerateKeyResponse: ...

    async def get_key(self, key_id: str) -> KeyMetadata: ...

    async def list_keys(self, options: ListKeysOptions | None = None) -> ListKeysResponse: ...

    async def delete_key(self, key_id: str) -> None: ...


class KeyManager:
    """Key management class for convenient key operations."""

    def __init__(self, client: "HsmClient") -> None:
        self._client = client

    async def generate(
        self,
        algorithm: KeyAlgorithm,
        *,
        purpose: KeyPurpose = KeyPurpose.GENERAL,
        key_id: str | None = None,
        namespace: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> GenerateKeyResponse:
        """Generate a new key with specified options."""
        request = GenerateKeyRequest(
            key_id=key_id,
            algorithm=algorithm,
            purpose=purpose,
            namespace=namespace or "default",
            labels=labels or {},
        )
        return await self._client.generate_key(request)

    async def generate_ed25519(
        self,
        *,
        key_id: str | None = None,
        namespace: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> GenerateKeyResponse:
        """Generate an Ed25519 signing key."""
        return await self.generate(
            KeyAlgorithm.ED25519,
            purpose=KeyPurpose.SIGN,
            key_id=key_id,
            namespace=namespace,
            labels=labels,
        )

    async def generate_ecdsa_p256(
        self,
        *,
        key_id: str | None = None,
        namespace: str | None = None,
        labels: dict[str, str] | None = None,
        purpose: KeyPurpose = KeyPurpose.SIGN,
    ) -> GenerateKeyResponse:
        """Generate an ECDSA P-256 key."""
        return await self.generate(
            KeyAlgorithm.ECDSA_P256,
            purpose=purpose,
            key_id=key_id,
            namespace=namespace,
            labels=labels,
        )

    async def generate_ecdsa_p384(
        self,
        *,
        key_id: str | None = None,
        namespace: str | None = None,
        labels: dict[str, str] | None = None,
        purpose: KeyPurpose = KeyPurpose.SIGN,
    ) -> GenerateKeyResponse:
        """Generate an ECDSA P-384 key."""
        return await self.generate(
            KeyAlgorithm.ECDSA_P384,
            purpose=purpose,
            key_id=key_id,
            namespace=namespace,
            labels=labels,
        )

    async def generate_rsa(
        self,
        size: int,
        *,
        key_id: str | None = None,
        namespace: str | None = None,
        labels: dict[str, str] | None = None,
        purpose: KeyPurpose = KeyPurpose.SIGN,
    ) -> GenerateKeyResponse:
        """Generate an RSA key."""
        algorithm_map = {
            2048: KeyAlgorithm.RSA2048,
            3072: KeyAlgorithm.RSA3072,
            4096: KeyAlgorithm.RSA4096,
        }
        if size not in algorithm_map:
            raise ValueError(f"Invalid RSA size: {size}. Must be 2048, 3072, or 4096.")
        return await self.generate(
            algorithm_map[size],
            purpose=purpose,
            key_id=key_id,
            namespace=namespace,
            labels=labels,
        )

    async def generate_aes(
        self,
        size: int,
        *,
        key_id: str | None = None,
        namespace: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> GenerateKeyResponse:
        """Generate an AES encryption key."""
        algorithm_map = {
            128: KeyAlgorithm.AES128,
            256: KeyAlgorithm.AES256,
        }
        if size not in algorithm_map:
            raise ValueError(f"Invalid AES size: {size}. Must be 128 or 256.")
        return await self.generate(
            algorithm_map[size],
            purpose=KeyPurpose.ENCRYPT,
            key_id=key_id,
            namespace=namespace,
            labels=labels,
        )

    async def get(self, key_id: str) -> KeyMetadata:
        """Get key metadata."""
        return await self._client.get_key(key_id)

    async def list(
        self,
        *,
        namespace: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> ListKeysResponse:
        """List all keys."""
        options = ListKeysOptions(namespace=namespace, limit=limit, cursor=cursor)
        return await self._client.list_keys(options)

    async def list_all(
        self,
        *,
        namespace: str | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[KeyMetadata]:
        """List all keys with automatic pagination."""
        cursor: str | None = None
        while True:
            response = await self.list(namespace=namespace, limit=limit, cursor=cursor)
            for key in response.keys:
                yield key
            cursor = response.next_cursor
            if not cursor:
                break

    async def delete(self, key_id: str) -> None:
        """Delete a key."""
        await self._client.delete_key(key_id)

    async def exists(self, key_id: str) -> bool:
        """Check if a key exists.

        Only a 404 from the server means "absent". Any other failure (auth, network,
        timeout, server error) is propagated rather than being reported as ``False``,
        so an outage is never mistaken for a missing key.
        """
        try:
            await self._client.get_key(key_id)
        except NotFoundError:
            return False
        return True
