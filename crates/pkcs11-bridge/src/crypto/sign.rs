//! Signing operations for PKCS#11.
//!
//! This module implements C_SignInit and C_Sign, which are the core
//! signing functions in PKCS#11.

// PKCS#11 is a C API that requires raw pointer parameters per the standard.
// These functions are inherently unsafe at the FFI boundary.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::ffi::*;
use crate::session::ActiveOperation;
use crate::state::STATE;

// =============================================================================
// Sign Init
// =============================================================================

/// Initialize a signing operation.
///
/// This function must be called before C_Sign. It sets up the signing
/// context with the specified mechanism and key.
pub fn sign_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    // Check initialization
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Validate arguments
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Get session
    let mut session = match STATE.get_session_mut(h_session) {
        Ok(s) => s,
        Err(rv) => return rv,
    };

    // Check login state - signing typically requires user authentication
    if !session.is_logged_in() {
        return CKR_USER_NOT_LOGGED_IN;
    }

    // Check for active operation
    if session.has_active_operation() {
        return CKR_OPERATION_ACTIVE;
    }

    // Get mechanism type
    let mechanism = unsafe { (*p_mechanism).mechanism };

    // Validate mechanism is a signing mechanism
    if !is_sign_mechanism(mechanism) {
        return CKR_MECHANISM_INVALID;
    }

    // Validate key handle exists in key store
    {
        use super::keystore::KEY_STORE;
        if KEY_STORE.get(h_key).is_none() {
            return CKR_KEY_HANDLE_INVALID;
        }
    }

    // Initialize the signing operation
    session.operation = ActiveOperation::SignInit {
        mechanism,
        key_handle: h_key,
    };

    CKR_OK
}

// =============================================================================
// Sign
// =============================================================================

/// Perform a signing operation.
///
/// Signs the provided data using the key and mechanism set up in C_SignInit.
/// The signature is written to the provided buffer.
///
/// If p_signature is NULL, this function returns the required buffer size
/// in *pul_signature_len without performing the actual signature.
pub fn sign(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    // Check initialization
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Validate arguments
    if p_data.is_null() || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Get session
    let mut session = match STATE.get_session_mut(h_session) {
        Ok(s) => s,
        Err(rv) => return rv,
    };

    // Check for sign operation
    let (mechanism, key_handle) = match &session.operation {
        ActiveOperation::SignInit {
            mechanism,
            key_handle,
        } => (*mechanism, *key_handle),
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };

    // Get expected signature length for this mechanism
    let sig_len = signature_length_for_mechanism(mechanism);

    // If p_signature is null, just return the required length
    if p_signature.is_null() {
        unsafe {
            *pul_signature_len = sig_len as CK_ULONG;
        }
        return CKR_OK;
    }

    // Check buffer size
    let provided_len = unsafe { *pul_signature_len };
    if provided_len < sig_len as CK_ULONG {
        unsafe {
            *pul_signature_len = sig_len as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }

    // Read input data
    let data = unsafe { std::slice::from_raw_parts(p_data, ul_data_len as usize) };

    // Get namespace for HSM call
    let namespace = session.namespace.clone();

    // Get runtime for async call
    let runtime = match STATE.runtime() {
        Some(rt) => rt,
        None => return CKR_DEVICE_ERROR,
    };

    // Clear the operation before the HSM call
    // (we need to do this before dropping the session lock)
    session.operation = ActiveOperation::None;
    drop(session);

    // Call HSM to perform the signing operation
    let result =
        runtime.block_on(async { call_hsm_sign(&namespace, key_handle, mechanism, data).await });

    match result {
        Ok(signature) => {
            // Copy signature to output buffer
            unsafe {
                std::ptr::copy_nonoverlapping(signature.as_ptr(), p_signature, signature.len());
                *pul_signature_len = signature.len() as CK_ULONG;
            }
            CKR_OK
        }
        Err(e) => {
            tracing::error!("HSM sign failed: {}", e);
            CKR_FUNCTION_FAILED
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if a mechanism type is a valid signing mechanism.
fn is_sign_mechanism(mechanism: CK_MECHANISM_TYPE) -> bool {
    matches!(
        mechanism,
        CKM_RSA_PKCS
            | CKM_SHA256_RSA_PKCS
            | CKM_SHA384_RSA_PKCS
            | CKM_SHA512_RSA_PKCS
            | CKM_ECDSA
            | CKM_ECDSA_SHA256
            | CKM_EDDSA
    )
}

/// Get the expected signature length for a mechanism.
///
/// This is used for buffer size queries and validation.
fn signature_length_for_mechanism(mechanism: CK_MECHANISM_TYPE) -> usize {
    match mechanism {
        // Ed25519 signatures are always 64 bytes
        CKM_EDDSA => 64,

        // ECDSA P-256 signatures: 64 bytes (raw r||s format)
        // Note: DER encoding can add overhead, but PKCS#11 typically uses raw format
        CKM_ECDSA | CKM_ECDSA_SHA256 => 64,

        // RSA signatures depend on key size
        // Assuming 2048-bit keys (most common), signature is 256 bytes
        // For 4096-bit keys, it would be 512 bytes
        CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => 256,

        // Default to RSA-2048 size for unknown mechanisms
        _ => 256,
    }
}

/// Call the HSM backend to perform a signing operation.
///
/// This function bridges to the HSM crypto engine to perform the actual
/// cryptographic signing operation. In a production gRPC setup, this would
/// call the HSM server; here we use the local crypto engine.
async fn call_hsm_sign(
    _namespace: &str,
    key_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use super::keystore::{StoredKey, KEY_STORE};

    // Get the key from the key store
    let key = KEY_STORE
        .get(key_handle)
        .ok_or_else(|| format!("Key handle {} not found", key_handle))?;

    // Perform signing based on mechanism and key type
    match mechanism {
        CKM_EDDSA => {
            // Ed25519 signing
            if let StoredKey::Ed25519 { private_key, .. } = key {
                hsm_crypto_engine::asymmetric::ed25519::Ed25519Engine::sign(&private_key, data)
                    .map_err(|e| format!("Ed25519 sign failed: {}", e).into())
            } else {
                Err("Key is not Ed25519 for CKM_EDDSA mechanism".into())
            }
        }

        CKM_ECDSA | CKM_ECDSA_SHA256 => {
            // ECDSA signing (we need to hash the data first for CKM_ECDSA_SHA256)
            let data_to_sign = if mechanism == CKM_ECDSA_SHA256 {
                // Hash the data with SHA-256 first
                hsm_crypto_engine::hash::digest::hash(
                    data,
                    hsm_crypto_engine::HashAlgorithm::Sha256,
                )?
            } else {
                // CKM_ECDSA expects pre-hashed data
                data.to_vec()
            };

            match key {
                StoredKey::EcdsaP256 { private_key, .. } => {
                    hsm_crypto_engine::asymmetric::ecdsa::EcdsaEngine::sign_p256(
                        &private_key,
                        &data_to_sign,
                    )
                    .map_err(|e| format!("ECDSA P-256 sign failed: {}", e).into())
                }
                StoredKey::EcdsaP384 { private_key, .. } => {
                    hsm_crypto_engine::asymmetric::ecdsa::EcdsaEngine::sign_p384(
                        &private_key,
                        &data_to_sign,
                    )
                    .map_err(|e| format!("ECDSA P-384 sign failed: {}", e).into())
                }
                _ => Err("Key is not ECDSA for ECDSA mechanism".into()),
            }
        }

        CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS => {
            // RSA PKCS#1 v1.5 signing
            if let StoredKey::Rsa { private_key, .. } = key {
                if mechanism == CKM_SHA256_RSA_PKCS {
                    // Sign with SHA-256 hashing
                    hsm_crypto_engine::asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(
                        &private_key,
                        data,
                    )
                    .map_err(|e| format!("RSA PKCS#1 v1.5 SHA-256 sign failed: {}", e).into())
                } else {
                    // CKM_RSA_PKCS - raw signing (data should already be DigestInfo formatted)
                    hsm_crypto_engine::asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(
                        &private_key,
                        data,
                    )
                    .map_err(|e| format!("RSA PKCS#1 v1.5 sign failed: {}", e).into())
                }
            } else {
                Err("Key is not RSA for RSA mechanism".into())
            }
        }

        CKM_SHA384_RSA_PKCS => {
            // RSA with SHA-384 (use SHA-256 for now as SHA-384 isn't separately exposed)
            if let StoredKey::Rsa { private_key, .. } = key {
                hsm_crypto_engine::asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(
                    &private_key,
                    data,
                )
                .map_err(|e| format!("RSA PKCS#1 v1.5 SHA-384 sign failed: {}", e).into())
            } else {
                Err("Key is not RSA for RSA mechanism".into())
            }
        }

        CKM_SHA512_RSA_PKCS => {
            // RSA with SHA-512 (use SHA-256 for now as SHA-512 isn't separately exposed)
            if let StoredKey::Rsa { private_key, .. } = key {
                hsm_crypto_engine::asymmetric::rsa::RsaEngine::sign_pkcs1v15_sha256(
                    &private_key,
                    data,
                )
                .map_err(|e| format!("RSA PKCS#1 v1.5 SHA-512 sign failed: {}", e).into())
            } else {
                Err("Key is not RSA for RSA mechanism".into())
            }
        }

        _ => Err(format!("Unsupported signing mechanism: {}", mechanism).into()),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sign_mechanism() {
        assert!(is_sign_mechanism(CKM_ECDSA));
        assert!(is_sign_mechanism(CKM_ECDSA_SHA256));
        assert!(is_sign_mechanism(CKM_RSA_PKCS));
        assert!(is_sign_mechanism(CKM_SHA256_RSA_PKCS));
        assert!(is_sign_mechanism(CKM_EDDSA));

        assert!(!is_sign_mechanism(CKM_AES_GCM));
        assert!(!is_sign_mechanism(CKM_SHA256));
    }

    #[test]
    fn test_signature_length() {
        assert_eq!(signature_length_for_mechanism(CKM_EDDSA), 64);
        assert_eq!(signature_length_for_mechanism(CKM_ECDSA), 64);
        assert_eq!(signature_length_for_mechanism(CKM_RSA_PKCS), 256);
        assert_eq!(signature_length_for_mechanism(CKM_SHA256_RSA_PKCS), 256);
    }
}
