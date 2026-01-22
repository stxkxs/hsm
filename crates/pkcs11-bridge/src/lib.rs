#![allow(non_camel_case_types)]

//! PKCS#11 Bridge for HSM
//!
//! This library provides a PKCS#11 v2.40 compliant interface to the HSM,
//! allowing legacy applications (OpenSSL, browsers, Java KeyStore, etc.)
//! to use HSM cryptographic services.
//!
//! # Architecture
//!
//! The library acts as a bridge between the PKCS#11 C API and the HSM gRPC API:
//!
//! ```text
//! Application (OpenSSL, etc.)
//!         |
//!         | PKCS#11 C API
//!         v
//!   +-----------------+
//!   | pkcs11-bridge   |
//!   | (this library)  |
//!   +-----------------+
//!         |
//!         | gRPC (mTLS)
//!         v
//!   +-----------------+
//!   |      HSM        |
//!   +-----------------+
//! ```
//!
//! # Slots and Tokens
//!
//! Each HSM namespace is exposed as a PKCS#11 slot/token pair.
//! The namespace to slot mapping is configured via environment variables.
//!
//! # Thread Safety
//!
//! This library is fully thread-safe. Multiple threads can call PKCS#11
//! functions concurrently, and sessions are protected by appropriate locking.

pub mod crypto;
pub mod ffi;
pub mod session;
pub mod state;

use ffi::*;
use session::Session;
use state::STATE;

// =============================================================================
// Function List (Main Export)
// =============================================================================

/// The function list - main export of the PKCS#11 library.
///
/// This static is accessed by C_GetFunctionList to provide the complete
/// set of PKCS#11 functions to the calling application.
///
/// # Safety
///
/// This is a mutable static for FFI compatibility. Access is controlled
/// through the C_GetFunctionList function which returns a pointer to it.
static mut FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(c_initialize),
    C_Finalize: Some(c_finalize),
    C_GetInfo: Some(c_get_info),
    C_GetFunctionList: Some(c_get_function_list),
    C_GetSlotList: Some(c_get_slot_list),
    C_GetSlotInfo: Some(c_get_slot_info),
    C_GetTokenInfo: Some(c_get_token_info),
    C_GetMechanismList: Some(c_get_mechanism_list),
    C_GetMechanismInfo: Some(c_get_mechanism_info),
    C_InitToken: None, // Not supported - tokens are managed by HSM
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(c_open_session),
    C_CloseSession: Some(c_close_session),
    C_CloseAllSessions: Some(c_close_all_sessions),
    C_GetSessionInfo: Some(c_get_session_info),
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(c_login),
    C_Logout: Some(c_logout),
    C_CreateObject: None, // Keys created via HSM API
    C_CopyObject: None,
    C_DestroyObject: None, // TODO: Implement
    C_GetObjectSize: None,
    C_GetAttributeValue: None, // TODO: Implement
    C_SetAttributeValue: None,
    C_FindObjectsInit: None, // TODO: Implement
    C_FindObjects: None,
    C_FindObjectsFinal: None,
    C_EncryptInit: None, // TODO: Implement
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: None, // TODO: Implement
    C_Decrypt: None,
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None, // TODO: Implement
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(c_sign_init),
    C_Sign: Some(c_sign),
    C_SignUpdate: None,
    C_SignFinal: None,
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None, // TODO: Implement
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None, // TODO: Implement
    C_GenerateKeyPair: None,
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: None, // TODO: Implement
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

// =============================================================================
// Core Functions
// =============================================================================

/// C_GetFunctionList - The main entry point for PKCS#11.
///
/// Applications call this function to obtain a pointer to the function list.
/// This is the only function that can be called without prior initialization.
///
/// # Safety
///
/// This function is called from C code. The caller must provide a valid
/// pointer to store the function list pointer.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    c_get_function_list(pp_function_list)
}

extern "C" fn c_get_function_list(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    unsafe {
        *pp_function_list = std::ptr::addr_of_mut!(FUNCTION_LIST);
    }

    CKR_OK
}

/// C_Initialize - Initialize the PKCS#11 library.
extern "C" fn c_initialize(_p_init_args: CK_VOID_PTR) -> CK_RV {
    // Initialize tracing (optional, for debugging)
    let _ = tracing_subscriber::fmt::try_init();

    STATE.initialize()
}

/// C_Finalize - Finalize the PKCS#11 library.
extern "C" fn c_finalize(_p_reserved: CK_VOID_PTR) -> CK_RV {
    STATE.finalize()
}

/// C_GetInfo - Get library information.
extern "C" fn c_get_info(p_info: CK_INFO_PTR) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let info = CK_INFO {
        cryptoki_version: CK_VERSION {
            major: 2,
            minor: 40,
        },
        manufacturer_id: padded_string("HSM Project"),
        flags: 0,
        library_description: padded_string("HSM PKCS#11 Bridge"),
        library_version: CK_VERSION { major: 1, minor: 0 },
    };

    unsafe {
        *p_info = info;
    }

    CKR_OK
}

// =============================================================================
// Slot and Token Functions
// =============================================================================

/// C_GetSlotList - Get list of slot IDs.
extern "C" fn c_get_slot_list(
    token_present: CK_BBOOL,
    p_slot_list: CK_SLOT_ID_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let slot_count = STATE.slot_count();

    // For this implementation, all slots always have tokens present
    let _ = token_present;

    if p_slot_list.is_null() {
        // Just return the count
        unsafe {
            *pul_count = slot_count as CK_ULONG;
        }
        return CKR_OK;
    }

    // Check if buffer is large enough
    let provided_count = unsafe { *pul_count };
    if (provided_count as usize) < slot_count {
        unsafe {
            *pul_count = slot_count as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }

    // Fill in slot IDs (0, 1, 2, ...)
    unsafe {
        for i in 0..slot_count {
            *p_slot_list.add(i) = i as CK_SLOT_ID;
        }
        *pul_count = slot_count as CK_ULONG;
    }

    CKR_OK
}

/// C_GetSlotInfo - Get information about a slot.
extern "C" fn c_get_slot_info(slot_id: CK_SLOT_ID, p_info: CK_SLOT_INFO_PTR) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Validate slot ID
    if slot_id as usize >= STATE.slot_count() {
        return CKR_SLOT_ID_INVALID;
    }

    // Get namespace name for this slot
    let namespace = STATE
        .get_namespace(slot_id)
        .unwrap_or_else(|| "unknown".to_string());
    let description = format!("HSM Namespace: {}", namespace);

    let info = CK_SLOT_INFO {
        slot_description: padded_string(&description),
        manufacturer_id: padded_string("HSM Project"),
        flags: CKF_TOKEN_PRESENT | CKF_HW_SLOT,
        hardware_version: CK_VERSION { major: 1, minor: 0 },
        firmware_version: CK_VERSION { major: 1, minor: 0 },
    };

    unsafe {
        *p_info = info;
    }

    CKR_OK
}

/// C_GetTokenInfo - Get information about a token.
extern "C" fn c_get_token_info(slot_id: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Validate slot ID
    if slot_id as usize >= STATE.slot_count() {
        return CKR_SLOT_ID_INVALID;
    }

    // Get namespace name for this slot
    let namespace = STATE
        .get_namespace(slot_id)
        .unwrap_or_else(|| "default".to_string());

    let info = CK_TOKEN_INFO {
        label: padded_string(&namespace),
        manufacturer_id: padded_string("HSM Project"),
        model: padded_string("Software HSM"),
        serial_number: padded_char_string(&format!("{:016}", slot_id)),
        flags: CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED,
        max_session_count: CK_ULONG::MAX, // Unlimited
        session_count: STATE.sessions().len() as CK_ULONG,
        max_rw_session_count: CK_ULONG::MAX,
        rw_session_count: STATE.sessions().iter().filter(|s| s.read_write).count() as CK_ULONG,
        max_pin_len: 256,
        min_pin_len: 4,
        total_public_memory: CK_ULONG::MAX, // Not applicable
        free_public_memory: CK_ULONG::MAX,
        total_private_memory: CK_ULONG::MAX,
        free_private_memory: CK_ULONG::MAX,
        hardware_version: CK_VERSION { major: 1, minor: 0 },
        firmware_version: CK_VERSION { major: 1, minor: 0 },
        utc_time: padded_char_string(""),
    };

    unsafe {
        *p_info = info;
    }

    CKR_OK
}

/// C_GetMechanismList - Get list of supported mechanisms.
extern "C" fn c_get_mechanism_list(
    slot_id: CK_SLOT_ID,
    p_mechanism_list: CK_MECHANISM_TYPE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Validate slot ID
    if slot_id as usize >= STATE.slot_count() {
        return CKR_SLOT_ID_INVALID;
    }

    // Supported mechanisms
    const MECHANISMS: &[CK_MECHANISM_TYPE] = &[
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        CKM_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_EC_KEY_PAIR_GEN,
        CKM_ECDSA,
        CKM_ECDSA_SHA256,
        CKM_EDDSA,
        CKM_AES_KEY_GEN,
        CKM_AES_CBC,
        CKM_AES_GCM,
        CKM_SHA256,
        CKM_SHA384,
        CKM_SHA512,
    ];

    if p_mechanism_list.is_null() {
        // Just return the count
        unsafe {
            *pul_count = MECHANISMS.len() as CK_ULONG;
        }
        return CKR_OK;
    }

    // Check if buffer is large enough
    let provided_count = unsafe { *pul_count };
    if (provided_count as usize) < MECHANISMS.len() {
        unsafe {
            *pul_count = MECHANISMS.len() as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }

    // Copy mechanisms to output
    unsafe {
        for (i, mech) in MECHANISMS.iter().enumerate() {
            *p_mechanism_list.add(i) = *mech;
        }
        *pul_count = MECHANISMS.len() as CK_ULONG;
    }

    CKR_OK
}

/// C_GetMechanismInfo - Get information about a mechanism.
extern "C" fn c_get_mechanism_info(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    p_info: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Validate slot ID
    if slot_id as usize >= STATE.slot_count() {
        return CKR_SLOT_ID_INVALID;
    }

    let info = match mechanism_type {
        CKM_RSA_PKCS_KEY_PAIR_GEN => CK_MECHANISM_INFO {
            min_key_size: 2048,
            max_key_size: 4096,
            flags: CKF_GENERATE_KEY_PAIR,
        },
        CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => {
            CK_MECHANISM_INFO {
                min_key_size: 2048,
                max_key_size: 4096,
                flags: CKF_SIGN | CKF_VERIFY,
            }
        }
        CKM_EC_KEY_PAIR_GEN => CK_MECHANISM_INFO {
            min_key_size: 256,
            max_key_size: 521,
            flags: CKF_GENERATE_KEY_PAIR,
        },
        CKM_ECDSA | CKM_ECDSA_SHA256 => CK_MECHANISM_INFO {
            min_key_size: 256,
            max_key_size: 521,
            flags: CKF_SIGN | CKF_VERIFY,
        },
        CKM_EDDSA => CK_MECHANISM_INFO {
            min_key_size: 256, // Ed25519
            max_key_size: 256,
            flags: CKF_SIGN | CKF_VERIFY,
        },
        CKM_AES_KEY_GEN => CK_MECHANISM_INFO {
            min_key_size: 128,
            max_key_size: 256,
            flags: CKF_GENERATE,
        },
        CKM_AES_CBC | CKM_AES_GCM => CK_MECHANISM_INFO {
            min_key_size: 128,
            max_key_size: 256,
            flags: CKF_ENCRYPT | CKF_DECRYPT,
        },
        CKM_SHA256 | CKM_SHA384 | CKM_SHA512 => CK_MECHANISM_INFO {
            min_key_size: 0,
            max_key_size: 0,
            flags: CKF_DIGEST,
        },
        _ => return CKR_MECHANISM_INVALID,
    };

    unsafe {
        *p_info = info;
    }

    CKR_OK
}

// =============================================================================
// Session Functions
// =============================================================================

/// C_OpenSession - Open a session on a slot.
extern "C" fn c_open_session(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _p_application: CK_VOID_PTR,
    _notify: CK_NOTIFY,
    ph_session: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if ph_session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // PKCS#11 requires CKF_SERIAL_SESSION to be set
    if (flags & CKF_SERIAL_SESSION) == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    // Validate slot ID
    let namespace = match STATE.get_namespace(slot_id) {
        Some(ns) => ns,
        None => return CKR_SLOT_ID_INVALID,
    };

    // Allocate session handle
    let handle = STATE.allocate_session_handle();

    // Create session
    let read_write = (flags & CKF_RW_SESSION) != 0;
    let session = Session::new(handle, slot_id, namespace, read_write);

    // Store session
    STATE.sessions().insert(handle, session);

    unsafe {
        *ph_session = handle;
    }

    CKR_OK
}

/// C_CloseSession - Close a session.
extern "C" fn c_close_session(h_session: CK_SESSION_HANDLE) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    match STATE.sessions().remove(&h_session) {
        Some(_) => CKR_OK,
        None => CKR_SESSION_HANDLE_INVALID,
    }
}

/// C_CloseAllSessions - Close all sessions on a slot.
extern "C" fn c_close_all_sessions(slot_id: CK_SLOT_ID) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Validate slot ID
    if slot_id as usize >= STATE.slot_count() {
        return CKR_SLOT_ID_INVALID;
    }

    STATE.close_all_sessions_for_slot(slot_id);

    CKR_OK
}

/// C_GetSessionInfo - Get session information.
extern "C" fn c_get_session_info(
    h_session: CK_SESSION_HANDLE,
    p_info: CK_SESSION_INFO_PTR,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let session = match STATE.get_session(h_session) {
        Ok(s) => s,
        Err(rv) => return rv,
    };

    let info = session.get_info();

    unsafe {
        *p_info = info;
    }

    CKR_OK
}

/// C_Login - Log in to a token.
extern "C" fn c_login(
    h_session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    p_pin: CK_UTF8CHAR_PTR,
    ul_pin_len: CK_ULONG,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // PIN can be NULL for tokens that don't require it
    let pin = if p_pin.is_null() || ul_pin_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(p_pin, ul_pin_len as usize) }
    };

    let mut session = match STATE.get_session_mut(h_session) {
        Ok(s) => s,
        Err(rv) => return rv,
    };

    session.login(user_type, pin)
}

/// C_Logout - Log out from a token.
extern "C" fn c_logout(h_session: CK_SESSION_HANDLE) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    let mut session = match STATE.get_session_mut(h_session) {
        Ok(s) => s,
        Err(rv) => return rv,
    };

    session.logout()
}

// =============================================================================
// Signing Functions
// =============================================================================

/// C_SignInit - Initialize a signing operation.
extern "C" fn c_sign_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    crypto::sign::sign_init(h_session, p_mechanism, h_key)
}

/// C_Sign - Perform a signing operation.
extern "C" fn c_sign(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    crypto::sign::sign(
        h_session,
        p_data,
        ul_data_len,
        p_signature,
        pul_signature_len,
    )
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::sync::Once;

    // Global state tests need special handling because:
    // 1. The OnceCell for runtime can only be set once per process
    // 2. Tests run in the same process, potentially in parallel
    //
    // We use a Once guard to ensure initialization happens exactly once
    // across all tests, then individual tests check and handle state.

    static INIT_ONCE: Once = Once::new();

    fn ensure_initialized() {
        INIT_ONCE.call_once(|| {
            let rv = c_initialize(ptr::null_mut());
            // Could be OK or ALREADY_INITIALIZED depending on test order
            assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
        });

        // If finalized by another test, re-initialize
        if !STATE.is_initialized() {
            STATE.reinitialize_for_test();
        }
    }

    #[test]
    fn test_get_function_list() {
        let mut func_list: *mut CK_FUNCTION_LIST = ptr::null_mut();

        let rv = c_get_function_list(&mut func_list);
        assert_eq!(rv, CKR_OK);
        assert!(!func_list.is_null());

        unsafe {
            let fl = &*func_list;
            assert_eq!(fl.version.major, 2);
            assert_eq!(fl.version.minor, 40);
            assert!(fl.C_Initialize.is_some());
            assert!(fl.C_Finalize.is_some());
        }
    }

    #[test]
    fn test_get_function_list_null() {
        let rv = c_get_function_list(ptr::null_mut());
        assert_eq!(rv, CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_info() {
        ensure_initialized();

        let mut info: CK_INFO = unsafe { std::mem::zeroed() };
        let rv = c_get_info(&mut info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.cryptoki_version.major, 2);
        assert_eq!(info.cryptoki_version.minor, 40);
    }

    #[test]
    fn test_get_slot_list() {
        ensure_initialized();

        // Get count
        let mut count: CK_ULONG = 0;
        let rv = c_get_slot_list(CK_FALSE, ptr::null_mut(), &mut count);
        assert_eq!(rv, CKR_OK);
        assert!(count >= 1); // At least "default" namespace

        // Get slots
        let mut slots = vec![0 as CK_SLOT_ID; count as usize];
        let rv = c_get_slot_list(CK_FALSE, slots.as_mut_ptr(), &mut count);
        assert_eq!(rv, CKR_OK);
    }

    #[test]
    fn test_session_lifecycle() {
        ensure_initialized();

        // Open session
        let mut session: CK_SESSION_HANDLE = 0;
        let rv = c_open_session(
            0,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        );
        assert_eq!(rv, CKR_OK);
        assert_ne!(session, 0);

        // Get session info
        let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
        let rv = c_get_session_info(session, &mut info);
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.slot_id, 0);
        assert_eq!(info.flags & CKF_RW_SESSION, CKF_RW_SESSION);

        // Close session
        let rv = c_close_session(session);
        assert_eq!(rv, CKR_OK);

        // Double close should fail
        let rv = c_close_session(session);
        assert_eq!(rv, CKR_SESSION_HANDLE_INVALID);
    }

    #[test]
    fn test_login_logout() {
        ensure_initialized();

        // Open session
        let mut session: CK_SESSION_HANDLE = 0;
        let rv = c_open_session(
            0,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        );
        assert_eq!(rv, CKR_OK);

        // Login
        let pin = b"1234";
        let rv = c_login(
            session,
            CKU_USER,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
        );
        assert_eq!(rv, CKR_OK);

        // Double login should fail
        let rv = c_login(
            session,
            CKU_USER,
            pin.as_ptr() as *mut _,
            pin.len() as CK_ULONG,
        );
        assert_eq!(rv, CKR_USER_ALREADY_LOGGED_IN);

        // Logout
        let rv = c_logout(session);
        assert_eq!(rv, CKR_OK);

        // Double logout should fail
        let rv = c_logout(session);
        assert_eq!(rv, CKR_USER_NOT_LOGGED_IN);

        c_close_session(session);
    }

    // Note: test_initialize_finalize is removed because the global state
    // pattern with OnceCell doesn't support re-initialization in the same
    // process. In a real deployment, the library is loaded once per process.
}
