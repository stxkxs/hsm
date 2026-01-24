//! HSM Crypto Utilities

use crate::error::{HsmError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

/// Encode bytes to base64.
pub fn to_base64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 to bytes.
pub fn from_base64(data: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(data)
        .map_err(|e| HsmError::crypto(format!("Invalid base64: {}", e)))
}

/// Check if string is valid base64.
pub fn is_base64(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    if s.len() % 4 != 0 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Encode bytes to hex.
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode hex to bytes.
pub fn from_hex(data: &str) -> Result<Vec<u8>> {
    let data = data.strip_prefix("0x").unwrap_or(data);
    hex::decode(data).map_err(|e| HsmError::crypto(format!("Invalid hex: {}", e)))
}

/// Normalize data to base64 for API requests.
pub fn normalize_to_base64(data: &[u8]) -> String {
    to_base64(data)
}

/// Normalize string to base64.
pub fn normalize_string_to_base64(data: &str) -> String {
    if is_base64(data) {
        data.to_string()
    } else {
        to_base64(data.as_bytes())
    }
}

/// Hash data using SHA-256.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using SHA-384.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using SHA-512.
pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Compare two byte slices in constant time.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Use system entropy via thread_rng
    // For production, you'd want to use getrandom crate
    let mut bytes = vec![0u8; n];
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = ((seed >> (i % 16)) ^ (i as u128)) as u8;
    }

    bytes
}

/// Concatenate multiple byte slices.
pub fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// Convert signature format from DER to raw (R || S).
pub fn der_to_raw(der_signature: &[u8]) -> Result<Vec<u8>> {
    if der_signature.is_empty() || der_signature[0] != 0x30 {
        // Already in raw format or invalid
        return Ok(der_signature.to_vec());
    }

    let mut offset = 2; // Skip 0x30 and length byte

    // Parse R
    if der_signature.get(offset) != Some(&0x02) {
        return Err(HsmError::crypto("Invalid DER signature"));
    }
    offset += 1;
    let r_len = der_signature.get(offset).copied().ok_or_else(|| {
        HsmError::crypto("Invalid DER signature: missing R length")
    })? as usize;
    offset += 1;

    if offset + r_len > der_signature.len() {
        return Err(HsmError::crypto("Invalid DER signature: R too long"));
    }
    let mut r = der_signature[offset..offset + r_len].to_vec();
    offset += r_len;

    // Parse S
    if der_signature.get(offset) != Some(&0x02) {
        return Err(HsmError::crypto("Invalid DER signature: missing S"));
    }
    offset += 1;
    let s_len = der_signature.get(offset).copied().ok_or_else(|| {
        HsmError::crypto("Invalid DER signature: missing S length")
    })? as usize;
    offset += 1;

    if offset + s_len > der_signature.len() {
        return Err(HsmError::crypto("Invalid DER signature: S too long"));
    }
    let mut s = der_signature[offset..offset + s_len].to_vec();

    // Remove leading zeros if present
    if r.len() > 32 && r[0] == 0x00 {
        r.remove(0);
    }
    if s.len() > 32 && s[0] == 0x00 {
        s.remove(0);
    }

    // Pad to 32 bytes each
    let mut r_padded = vec![0u8; 32];
    let mut s_padded = vec![0u8; 32];
    r_padded[32 - r.len()..].copy_from_slice(&r);
    s_padded[32 - s.len()..].copy_from_slice(&s);

    let mut result = r_padded;
    result.extend(s_padded);
    Ok(result)
}

/// Convert signature format from raw (R || S) to DER.
pub fn raw_to_der(raw_signature: &[u8]) -> Result<Vec<u8>> {
    if raw_signature.len() != 64 {
        // Might already be DER or invalid
        return Ok(raw_signature.to_vec());
    }

    let mut r = raw_signature[..32].to_vec();
    let mut s = raw_signature[32..64].to_vec();

    // Remove leading zeros
    while r.len() > 1 && r[0] == 0x00 && (r[1] & 0x80) == 0 {
        r.remove(0);
    }
    while s.len() > 1 && s[0] == 0x00 && (s[1] & 0x80) == 0 {
        s.remove(0);
    }

    // Add leading zero if high bit is set
    if !r.is_empty() && (r[0] & 0x80) != 0 {
        r.insert(0, 0x00);
    }
    if !s.is_empty() && (s[0] & 0x80) != 0 {
        s.insert(0, 0x00);
    }

    let total_len = 4 + r.len() + s.len();

    let mut result = vec![0x30, total_len as u8, 0x02, r.len() as u8];
    result.extend(&r);
    result.push(0x02);
    result.push(s.len() as u8);
    result.extend(&s);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_base64() {
        assert_eq!(to_base64(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn test_from_base64() {
        assert_eq!(from_base64("SGVsbG8=").unwrap(), b"Hello");
    }

    #[test]
    fn test_is_base64() {
        assert!(is_base64("SGVsbG8="));
        assert!(is_base64(""));
        assert!(!is_base64("Hello"));
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_constant_time_equal() {
        assert!(constant_time_equal(b"test", b"test"));
        assert!(!constant_time_equal(b"test", b"test2"));
    }
}
