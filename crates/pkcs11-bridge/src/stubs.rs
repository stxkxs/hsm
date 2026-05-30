//! Stub functions for unimplemented PKCS#11 operations.
//!
//! Each stub returns `CKR_FUNCTION_NOT_SUPPORTED` so that callers get an
//! explicit error rather than a NULL function pointer crash.

#![allow(non_snake_case)]

use crate::ffi::*;

// Signature: (CK_SESSION_HANDLE) -> CK_RV
extern "C" fn stub_session(_: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV
extern "C" fn stub_session_object(_: CK_SESSION_HANDLE, _: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV
extern "C" fn stub_session_bytes(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV
extern "C" fn stub_session_buf_out(_: CK_SESSION_HANDLE, _: CK_BYTE_PTR, _: CK_ULONG_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV
extern "C" fn stub_session_mechanism(_: CK_SESSION_HANDLE, _: CK_MECHANISM_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV
extern "C" fn stub_session_mechanism_key(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV
extern "C" fn stub_session_data_buf(
    _: CK_SESSION_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV
// Used for C_Verify
extern "C" fn stub_session_data_sig(
    _: CK_SESSION_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV
extern "C" fn stub_session_object_size(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV
extern "C" fn stub_session_object_attrs(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV
extern "C" fn stub_session_attrs(_: CK_SESSION_HANDLE, _: CK_ATTRIBUTE_PTR, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV
extern "C" fn stub_create_object(
    _: CK_SESSION_HANDLE,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV
extern "C" fn stub_copy_object(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV
extern "C" fn stub_find_objects(
    _: CK_SESSION_HANDLE,
    _: CK_OBJECT_HANDLE_PTR,
    _: CK_ULONG,
    _: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV
extern "C" fn stub_session_pin(_: CK_SESSION_HANDLE, _: CK_UTF8CHAR_PTR, _: CK_ULONG) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV
extern "C" fn stub_set_pin(
    _: CK_SESSION_HANDLE,
    _: CK_UTF8CHAR_PTR,
    _: CK_ULONG,
    _: CK_UTF8CHAR_PTR,
    _: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) -> CK_RV
extern "C" fn stub_init_token(
    _: CK_SLOT_ID,
    _: CK_UTF8CHAR_PTR,
    _: CK_ULONG,
    _: CK_UTF8CHAR_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) -> CK_RV
extern "C" fn stub_set_operation_state(
    _: CK_SESSION_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: CK_FUNCTION_LIST.C_GenerateKey
extern "C" fn stub_generate_key(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: CK_FUNCTION_LIST.C_GenerateKeyPair
extern "C" fn stub_generate_key_pair(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE_PTR,
    _: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: CK_FUNCTION_LIST.C_WrapKey
extern "C" fn stub_wrap_key(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
    _: CK_OBJECT_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: CK_FUNCTION_LIST.C_UnwrapKey
extern "C" fn stub_unwrap_key(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
    _: CK_BYTE_PTR,
    _: CK_ULONG,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: CK_FUNCTION_LIST.C_DeriveKey
extern "C" fn stub_derive_key(
    _: CK_SESSION_HANDLE,
    _: CK_MECHANISM_PTR,
    _: CK_OBJECT_HANDLE,
    _: CK_ATTRIBUTE_PTR,
    _: CK_ULONG,
    _: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Signature: (CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV
extern "C" fn stub_wait_for_slot_event(_: CK_FLAGS, _: CK_SLOT_ID_PTR, _: CK_VOID_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// ============================================================================
// Public accessors for use in the function list
// ============================================================================

pub const INIT_TOKEN: extern "C" fn(
    CK_SLOT_ID,
    CK_UTF8CHAR_PTR,
    CK_ULONG,
    CK_UTF8CHAR_PTR,
) -> CK_RV = stub_init_token;
pub const INIT_PIN: extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV =
    stub_session_pin;
pub const SET_PIN: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_UTF8CHAR_PTR,
    CK_ULONG,
    CK_UTF8CHAR_PTR,
    CK_ULONG,
) -> CK_RV = stub_set_pin;
pub const GET_OPERATION_STATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_buf_out;
pub const SET_OPERATION_STATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
) -> CK_RV = stub_set_operation_state;
pub const CREATE_OBJECT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV = stub_create_object;
pub const COPY_OBJECT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV = stub_copy_object;
pub const DESTROY_OBJECT: extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV =
    stub_session_object;
pub const GET_OBJECT_SIZE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_object_size;
pub const GET_ATTRIBUTE_VALUE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
) -> CK_RV = stub_session_object_attrs;
pub const SET_ATTRIBUTE_VALUE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
) -> CK_RV = stub_session_object_attrs;
pub const FIND_OBJECTS_INIT: extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV =
    stub_session_attrs;
pub const FIND_OBJECTS: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE_PTR,
    CK_ULONG,
    CK_ULONG_PTR,
) -> CK_RV = stub_find_objects;
pub const FIND_OBJECTS_FINAL: extern "C" fn(CK_SESSION_HANDLE) -> CK_RV = stub_session;
pub const ENCRYPT_INIT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
) -> CK_RV = stub_session_mechanism_key;
pub const ENCRYPT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const ENCRYPT_UPDATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const ENCRYPT_FINAL: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV =
    stub_session_buf_out;
pub const DECRYPT_INIT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
) -> CK_RV = stub_session_mechanism_key;
pub const DECRYPT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const DECRYPT_UPDATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const DECRYPT_FINAL: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV =
    stub_session_buf_out;
pub const DIGEST_INIT: extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV =
    stub_session_mechanism;
pub const DIGEST: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const DIGEST_UPDATE: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV =
    stub_session_bytes;
pub const DIGEST_KEY: extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV =
    stub_session_object;
pub const DIGEST_FINAL: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV =
    stub_session_buf_out;
pub const SIGN_UPDATE: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV =
    stub_session_bytes;
pub const SIGN_FINAL: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV =
    stub_session_buf_out;
pub const SIGN_RECOVER_INIT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
) -> CK_RV = stub_session_mechanism_key;
pub const SIGN_RECOVER: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const VERIFY_INIT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
) -> CK_RV = stub_session_mechanism_key;
pub const VERIFY: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG,
) -> CK_RV = stub_session_data_sig;
pub const VERIFY_UPDATE: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV =
    stub_session_bytes;
pub const VERIFY_FINAL: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV =
    stub_session_bytes;
pub const VERIFY_RECOVER_INIT: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
) -> CK_RV = stub_session_mechanism_key;
pub const VERIFY_RECOVER: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const DIGEST_ENCRYPT_UPDATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const DECRYPT_DIGEST_UPDATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const SIGN_ENCRYPT_UPDATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const DECRYPT_VERIFY_UPDATE: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_session_data_buf;
pub const GENERATE_KEY: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV = stub_generate_key;
pub const GENERATE_KEY_PAIR: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV = stub_generate_key_pair;
pub const WRAP_KEY: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV = stub_wrap_key;
pub const UNWRAP_KEY: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV = stub_unwrap_key;
pub const DERIVE_KEY: extern "C" fn(
    CK_SESSION_HANDLE,
    CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE,
    CK_ATTRIBUTE_PTR,
    CK_ULONG,
    CK_OBJECT_HANDLE_PTR,
) -> CK_RV = stub_derive_key;
pub const SEED_RANDOM: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV =
    stub_session_bytes;
pub const GENERATE_RANDOM: extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV =
    stub_session_bytes;
pub const GET_FUNCTION_STATUS: extern "C" fn(CK_SESSION_HANDLE) -> CK_RV = stub_session;
pub const CANCEL_FUNCTION: extern "C" fn(CK_SESSION_HANDLE) -> CK_RV = stub_session;
pub const WAIT_FOR_SLOT_EVENT: extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV =
    stub_wait_for_slot_event;
