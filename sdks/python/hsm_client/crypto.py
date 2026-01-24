"""
HSM Crypto Utilities

Utility functions for cryptographic operations.
"""

import base64
import hashlib
import hmac
import os
import re
from typing import Union


def to_base64(data: Union[bytes, str]) -> str:
    """Encode bytes to base64."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def from_base64(data: str) -> bytes:
    """Decode base64 to bytes."""
    return base64.b64decode(data)


def is_base64(data: str) -> bool:
    """Check if string is valid base64."""
    if not data:
        return True
    if len(data) % 4 != 0:
        return False
    pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
    return bool(pattern.match(data))


def to_hex(data: bytes) -> str:
    """Encode bytes to hex."""
    return data.hex()


def from_hex(data: str) -> bytes:
    """Decode hex to bytes."""
    if data.startswith("0x"):
        data = data[2:]
    return bytes.fromhex(data)


def normalize_to_base64(data: Union[bytes, str]) -> str:
    """Normalize data to base64 for API requests."""
    if isinstance(data, bytes):
        return to_base64(data)
    if is_base64(data):
        return data
    return to_base64(data.encode("utf-8"))


def sha256(data: Union[bytes, str]) -> bytes:
    """Hash data using SHA-256."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def sha384(data: Union[bytes, str]) -> bytes:
    """Hash data using SHA-384."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha384(data).digest()


def sha512(data: Union[bytes, str]) -> bytes:
    """Hash data using SHA-512."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha512(data).digest()


def hmac_sha256(key: bytes, data: Union[bytes, str]) -> bytes:
    """Compute HMAC-SHA256."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte arrays in constant time."""
    return hmac.compare_digest(a, b)


def random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return os.urandom(length)


def concat_bytes(*arrays: bytes) -> bytes:
    """Concatenate multiple byte arrays."""
    return b"".join(arrays)


def der_to_raw(der_signature: bytes) -> bytes:
    """
    Convert signature format from DER to raw (R || S).

    Useful for Ethereum and other chains that expect raw format.
    """
    if not der_signature or der_signature[0] != 0x30:
        # Already in raw format or invalid
        return der_signature

    offset = 2  # Skip 0x30 and length byte

    # Parse R
    if der_signature[offset] != 0x02:
        raise ValueError("Invalid DER signature")
    offset += 1
    r_len = der_signature[offset]
    offset += 1
    r = der_signature[offset : offset + r_len]
    offset += r_len

    # Parse S
    if der_signature[offset] != 0x02:
        raise ValueError("Invalid DER signature")
    offset += 1
    s_len = der_signature[offset]
    offset += 1
    s = der_signature[offset : offset + s_len]

    # Remove leading zeros if present
    if r[0] == 0x00 and len(r) > 32:
        r = r[1:]
    if s[0] == 0x00 and len(s) > 32:
        s = s[1:]

    # Pad to 32 bytes each
    r_padded = r.rjust(32, b"\x00")
    s_padded = s.rjust(32, b"\x00")

    return r_padded + s_padded


def raw_to_der(raw_signature: bytes) -> bytes:
    """
    Convert signature format from raw (R || S) to DER.
    """
    if len(raw_signature) != 64:
        # Might already be DER or invalid
        return raw_signature

    r = raw_signature[:32]
    s = raw_signature[32:64]

    # Remove leading zeros
    r = r.lstrip(b"\x00") or b"\x00"
    s = s.lstrip(b"\x00") or b"\x00"

    # Add leading zero if high bit is set (to ensure positive integer)
    if r[0] & 0x80:
        r = b"\x00" + r
    if s[0] & 0x80:
        s = b"\x00" + s

    total_len = 4 + len(r) + len(s)

    return bytes(
        [
            0x30,  # SEQUENCE
            total_len,
            0x02,  # INTEGER (R)
            len(r),
            *r,
            0x02,  # INTEGER (S)
            len(s),
            *s,
        ]
    )
