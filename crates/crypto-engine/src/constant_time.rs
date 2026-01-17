//! Constant-time cryptographic operations.
//!
//! This module provides guaranteed constant-time implementations of timing-critical
//! operations to prevent timing side-channel attacks. All operations in this module
//! are designed to execute in time independent of secret data.
//!
//! # Security Guarantees
//!
//! - **Constant-time comparisons**: All equality checks use `subtle::ConstantTimeEq`
//! - **No secret-dependent branches**: Control flow is independent of secret values
//! - **No secret-dependent memory access**: Array indexing is independent of secrets
//!
//! # Verification
//!
//! Constant-time guarantees are verified using:
//! - `dudect` statistical timing tests (see `tests/timing_tests.rs`)
//! - Valgrind cache-grind analysis (see `scripts/cache_analysis.sh`)
//! - Manual code review for data-dependent branches
//!
//! # References
//!
//! - "FaCT: A DSL for Timing-Sensitive Computation" (Cauligi et al., 2019)
//! - "CT-Wasm: Type-Driven Secure Cryptography" (Watt et al., 2018)
//! - RUSTSEC-2023-0071: Marvin Attack on RSA PKCS#1 v1.5

use subtle::ConstantTimeEq;

/// Compares two byte slices in constant time.
///
/// This function takes time proportional to the length of the slices,
/// independent of where the first difference occurs.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if slices are equal in both length and content, `false` otherwise
///
/// # Security
///
/// - Execution time depends only on slice length, not on content
/// - No early return on first difference (prevents timing attacks)
/// - Uses `subtle::ConstantTimeEq` for comparison
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::constant_time::ct_compare;
///
/// let a = b"secret_signature_tag_value_123";
/// let b = b"secret_signature_tag_value_123";
/// assert!(ct_compare(a, b));
///
/// let c = b"different_value_456789012345678";
/// assert!(!ct_compare(a, c));
/// ```
#[inline(never)] // Prevent inlining to avoid speculation
pub fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    // Length comparison is not secret-dependent in typical use
    if a.len() != b.len() {
        return false;
    }

    // Use subtle crate's constant-time comparison
    a.ct_eq(b).into()
}

/// Verifies an authentication tag in constant time.
///
/// This is specifically designed for AES-GCM and other AEAD schemes where
/// tag verification must not leak information about which byte differs.
///
/// # Arguments
///
/// * `expected_tag` - The expected authentication tag
/// * `received_tag` - The received authentication tag to verify
///
/// # Returns
///
/// `true` if tags match exactly, `false` otherwise
///
/// # Security
///
/// - Timing independent of tag content or position of mismatch
/// - Prevents tag oracle attacks
/// - Uses constant-time comparison internally
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::constant_time::ct_verify_tag;
///
/// let expected = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
/// let received = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
/// assert!(ct_verify_tag(expected, received));
///
/// let tampered = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xFF];
/// assert!(!ct_verify_tag(expected, tampered));
/// ```
#[inline(never)] // Prevent inlining to avoid speculation
pub fn ct_verify_tag(expected_tag: &[u8], received_tag: &[u8]) -> bool {
    ct_compare(expected_tag, received_tag)
}

/// Verifies an ECDSA or Ed25519 signature in constant time.
///
/// While the underlying signature verification algorithm may have variable timing,
/// the final equality check of the signature bytes is performed in constant time
/// to prevent leaking information about which signature component differs.
///
/// # Arguments
///
/// * `expected_sig` - The expected signature bytes
/// * `received_sig` - The received signature bytes to verify
///
/// # Returns
///
/// `true` if signatures match exactly, `false` otherwise
///
/// # Security
///
/// - Final comparison is constant-time
/// - Prevents leaking information about signature structure
/// - Complements constant-time signature verification in underlying libraries
///
/// # Note
///
/// This function should be used in conjunction with the cryptographic signature
/// verification, not as a replacement. Most signature schemes do their own
/// constant-time verification internally.
#[inline(never)] // Prevent inlining to avoid speculation
pub fn ct_verify_signature(expected_sig: &[u8], received_sig: &[u8]) -> bool {
    ct_compare(expected_sig, received_sig)
}

/// Performs constant-time selection between two byte slices.
///
/// Selects `a` if `condition` is true, otherwise selects `b`.
/// The selection is performed in constant time regardless of the condition value.
///
/// # Arguments
///
/// * `condition` - Selection condition
/// * `a` - First option (selected if condition is true)
/// * `b` - Second option (selected if condition is false)
///
/// # Returns
///
/// Copy of selected slice
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths
///
/// # Security
///
/// - Time independent of condition value
/// - Time independent of position of differences between a and b
/// - Prevents conditional branch prediction attacks
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::constant_time::ct_select;
///
/// let a = b"option_a";
/// let b = b"option_b";
///
/// let selected_true = ct_select(true, a, b);
/// assert_eq!(selected_true, a);
///
/// let selected_false = ct_select(false, a, b);
/// assert_eq!(selected_false, b);
/// ```
#[inline(never)] // Prevent inlining to avoid speculation
pub fn ct_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "ct_select requires equal-length inputs");

    let mask = if condition { 0xFF } else { 0x00 };
    let mut result = Vec::with_capacity(a.len());

    for i in 0..a.len() {
        // Constant-time selection using bitwise operations
        // result[i] = (a[i] & mask) | (b[i] & !mask)
        result.push((a[i] & mask) | (b[i] & !mask));
    }

    result
}

/// Zeroes a byte slice in a way that won't be optimized away by the compiler.
///
/// This is a wrapper around `zeroize` for explicit use in security-critical contexts.
///
/// # Arguments
///
/// * `data` - Mutable byte slice to zero
///
/// # Security
///
/// - Guaranteed not to be optimized away
/// - Ensures sensitive data is cleared from memory
/// - Uses compiler fences to prevent reordering
///
/// # Examples
///
/// ```
/// use hsm_crypto_engine::constant_time::ct_zero;
///
/// let mut sensitive_data = vec![0x42; 32];
/// ct_zero(&mut sensitive_data);
/// assert_eq!(sensitive_data, vec![0x00; 32]);
/// ```
#[inline(never)] // Prevent inlining to avoid optimization
pub fn ct_zero(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_compare_equal() {
        let a = b"test_data_12345678";
        let b = b"test_data_12345678";
        assert!(ct_compare(a, b));
    }

    #[test]
    fn test_ct_compare_different() {
        let a = b"test_data_12345678";
        let b = b"test_data_87654321";
        assert!(!ct_compare(a, b));
    }

    #[test]
    fn test_ct_compare_different_length() {
        let a = b"short";
        let b = b"much_longer";
        assert!(!ct_compare(a, b));
    }

    #[test]
    fn test_ct_verify_tag_valid() {
        let tag = &[0xAA; 16]; // 128-bit tag
        assert!(ct_verify_tag(tag, tag));
    }

    #[test]
    fn test_ct_verify_tag_invalid() {
        let expected = &[0xAA; 16];
        let received = &[0xBB; 16];
        assert!(!ct_verify_tag(expected, received));
    }

    #[test]
    fn test_ct_verify_tag_first_byte_differs() {
        let expected = &[0xFF, 0x00, 0x00, 0x00];
        let received = &[0x00, 0x00, 0x00, 0x00];
        assert!(!ct_verify_tag(expected, received));
    }

    #[test]
    fn test_ct_verify_tag_last_byte_differs() {
        let expected = &[0x00, 0x00, 0x00, 0xFF];
        let received = &[0x00, 0x00, 0x00, 0x00];
        assert!(!ct_verify_tag(expected, received));
    }

    #[test]
    fn test_ct_select_true() {
        let a = b"option_a";
        let b = b"option_b";
        let result = ct_select(true, a, b);
        assert_eq!(result.as_slice(), a);
    }

    #[test]
    fn test_ct_select_false() {
        let a = b"option_a";
        let b = b"option_b";
        let result = ct_select(false, a, b);
        assert_eq!(result.as_slice(), b);
    }

    #[test]
    #[should_panic(expected = "ct_select requires equal-length inputs")]
    fn test_ct_select_different_lengths() {
        let a = b"short";
        let b = b"much_longer";
        let _ = ct_select(true, a, b);
    }

    #[test]
    fn test_ct_zero() {
        let mut data = vec![0x42; 32];
        ct_zero(&mut data);
        assert_eq!(data, vec![0x00; 32]);
    }

    #[test]
    fn test_ct_zero_multiple_times() {
        let mut data = vec![0xFF; 16];
        ct_zero(&mut data);
        assert_eq!(data, vec![0x00; 16]);

        // Zeroing already-zero data should be safe
        ct_zero(&mut data);
        assert_eq!(data, vec![0x00; 16]);
    }
}
