//! FFI types matching PKCS#11 C definitions (v2.40)
//!
//! This module defines all the C-compatible types, constants, and structures
//! needed for PKCS#11 compliance.
//!
//! The type names follow the PKCS#11 specification naming conventions (CK_*),
//! which use screaming snake case rather than Rust's camelCase convention.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::c_void;

// =============================================================================
// PKCS#11 Type Aliases
// =============================================================================

pub type CK_BYTE = u8;
pub type CK_CHAR = u8;
pub type CK_UTF8CHAR = u8;
pub type CK_BBOOL = u8;
pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_LONG = std::ffi::c_long;
pub type CK_FLAGS = CK_ULONG;

// Pointer types
pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_CHAR_PTR = *mut CK_CHAR;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_VOID_PTR = *mut c_void;
pub type CK_UTF8CHAR_PTR = *mut CK_UTF8CHAR;

// Handle types
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;
pub type CK_NOTIFICATION = CK_ULONG;

// Handle pointer types
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;

// Return value type
pub type CK_RV = CK_ULONG;

// Callback type
pub type CK_NOTIFY =
    Option<extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) -> CK_RV>;

// =============================================================================
// Return Value Constants
// =============================================================================

pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_CANCEL: CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY: CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED: CK_RV = 0x00000006;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x00000012;
pub const CKR_DEVICE_ERROR: CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY: CK_RV = 0x00000031;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_KEY_HANDLE_INVALID: CK_RV = 0x00000060;
pub const CKR_KEY_SIZE_RANGE: CK_RV = 0x00000062;
pub const CKR_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000063;
pub const CKR_MECHANISM_INVALID: CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x00000071;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE: CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT: CK_RV = 0x000000A0;
pub const CKR_SESSION_CLOSED: CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT: CK_RV = 0x000000B1;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x000000B2;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;
pub const CKR_SESSION_READ_ONLY: CK_RV = 0x000000B5;
pub const CKR_SIGNATURE_INVALID: CK_RV = 0x000000C0;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED: CK_RV = 0x000000E1;
pub const CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN: CK_RV = 0x00000101;
pub const CKR_USER_TYPE_INVALID: CK_RV = 0x00000103;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;

// =============================================================================
// Boolean Constants
// =============================================================================

pub const CK_FALSE: CK_BBOOL = 0;
pub const CK_TRUE: CK_BBOOL = 1;

// =============================================================================
// User Types
// =============================================================================

pub const CKU_SO: CK_USER_TYPE = 0; // Security Officer
pub const CKU_USER: CK_USER_TYPE = 1;

// =============================================================================
// Session Flags
// =============================================================================

pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;

// =============================================================================
// Token Flags
// =============================================================================

pub const CKF_TOKEN_PRESENT: CK_FLAGS = 0x00000001;
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x00000400;
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x00000004;
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x00000008;

// =============================================================================
// Slot Flags
// =============================================================================

pub const CKF_HW_SLOT: CK_FLAGS = 0x00000004;

// =============================================================================
// Mechanism Types
// =============================================================================

pub const CKM_RSA_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000000;
pub const CKM_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000001;
pub const CKM_SHA256_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000040;
pub const CKM_SHA384_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000041;
pub const CKM_SHA512_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000042;
pub const CKM_SHA256: CK_MECHANISM_TYPE = 0x00000250;
pub const CKM_SHA384: CK_MECHANISM_TYPE = 0x00000260;
pub const CKM_SHA512: CK_MECHANISM_TYPE = 0x00000270;
pub const CKM_EC_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001040;
pub const CKM_ECDSA: CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA256: CK_MECHANISM_TYPE = 0x00001043;
pub const CKM_EDDSA: CK_MECHANISM_TYPE = 0x00001057; // Ed25519
pub const CKM_AES_KEY_GEN: CK_MECHANISM_TYPE = 0x00001080;
pub const CKM_AES_CBC: CK_MECHANISM_TYPE = 0x00001082;
pub const CKM_AES_GCM: CK_MECHANISM_TYPE = 0x00001087;

// =============================================================================
// Mechanism Flags
// =============================================================================

pub const CKF_SIGN: CK_FLAGS = 0x00000800;
pub const CKF_VERIFY: CK_FLAGS = 0x00002000;
pub const CKF_ENCRYPT: CK_FLAGS = 0x00000100;
pub const CKF_DECRYPT: CK_FLAGS = 0x00000200;
pub const CKF_DIGEST: CK_FLAGS = 0x00000400;
pub const CKF_GENERATE_KEY_PAIR: CK_FLAGS = 0x00010000;
pub const CKF_GENERATE: CK_FLAGS = 0x00008000;

// =============================================================================
// Object Classes
// =============================================================================

pub const CKO_PUBLIC_KEY: CK_ULONG = 0x00000002;
pub const CKO_PRIVATE_KEY: CK_ULONG = 0x00000003;
pub const CKO_SECRET_KEY: CK_ULONG = 0x00000004;
pub const CKO_CERTIFICATE: CK_ULONG = 0x00000001;

// =============================================================================
// Key Types
// =============================================================================

pub const CKK_RSA: CK_ULONG = 0x00000000;
pub const CKK_EC: CK_ULONG = 0x00000003;
pub const CKK_AES: CK_ULONG = 0x0000001F;
pub const CKK_EC_EDWARDS: CK_ULONG = 0x00000040; // Ed25519

// =============================================================================
// Attribute Types
// =============================================================================

pub const CKA_CLASS: CK_ULONG = 0x00000000;
pub const CKA_TOKEN: CK_ULONG = 0x00000001;
pub const CKA_PRIVATE: CK_ULONG = 0x00000002;
pub const CKA_LABEL: CK_ULONG = 0x00000003;
pub const CKA_KEY_TYPE: CK_ULONG = 0x00000100;
pub const CKA_ID: CK_ULONG = 0x00000102;
pub const CKA_SENSITIVE: CK_ULONG = 0x00000103;
pub const CKA_ENCRYPT: CK_ULONG = 0x00000104;
pub const CKA_DECRYPT: CK_ULONG = 0x00000105;
pub const CKA_SIGN: CK_ULONG = 0x00000108;
pub const CKA_VERIFY: CK_ULONG = 0x0000010A;
pub const CKA_MODULUS_BITS: CK_ULONG = 0x00000121;
pub const CKA_VALUE_LEN: CK_ULONG = 0x00000161;
pub const CKA_EC_PARAMS: CK_ULONG = 0x00000180;
pub const CKA_EC_POINT: CK_ULONG = 0x00000181;

// =============================================================================
// Session States
// =============================================================================

pub const CKS_RO_PUBLIC_SESSION: CK_ULONG = 0;
pub const CKS_RO_USER_FUNCTIONS: CK_ULONG = 1;
pub const CKS_RW_PUBLIC_SESSION: CK_ULONG = 2;
pub const CKS_RW_USER_FUNCTIONS: CK_ULONG = 3;
pub const CKS_RW_SO_FUNCTIONS: CK_ULONG = 4;

// =============================================================================
// Invalid Handle
// =============================================================================

pub const CK_INVALID_HANDLE: CK_ULONG = 0;

// =============================================================================
// Structures
// =============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
pub struct CK_INFO {
    pub cryptoki_version: CK_VERSION,
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub library_description: [CK_UTF8CHAR; 32],
    pub library_version: CK_VERSION,
}

#[repr(C)]
pub struct CK_SLOT_INFO {
    pub slot_description: [CK_UTF8CHAR; 64],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub flags: CK_FLAGS,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
}

#[repr(C)]
pub struct CK_TOKEN_INFO {
    pub label: [CK_UTF8CHAR; 32],
    pub manufacturer_id: [CK_UTF8CHAR; 32],
    pub model: [CK_UTF8CHAR; 16],
    pub serial_number: [CK_CHAR; 16],
    pub flags: CK_FLAGS,
    pub max_session_count: CK_ULONG,
    pub session_count: CK_ULONG,
    pub max_rw_session_count: CK_ULONG,
    pub rw_session_count: CK_ULONG,
    pub max_pin_len: CK_ULONG,
    pub min_pin_len: CK_ULONG,
    pub total_public_memory: CK_ULONG,
    pub free_public_memory: CK_ULONG,
    pub total_private_memory: CK_ULONG,
    pub free_private_memory: CK_ULONG,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
    pub utc_time: [CK_CHAR; 16],
}

#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub parameter: CK_VOID_PTR,
    pub parameter_len: CK_ULONG,
}

#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub type_: CK_ULONG,
    pub value: CK_VOID_PTR,
    pub value_len: CK_ULONG,
}

#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slot_id: CK_SLOT_ID,
    pub state: CK_ULONG,
    pub flags: CK_FLAGS,
    pub device_error: CK_ULONG,
}

// =============================================================================
// Structure Pointer Types
// =============================================================================

pub type CK_INFO_PTR = *mut CK_INFO;
pub type CK_SLOT_INFO_PTR = *mut CK_SLOT_INFO;
pub type CK_TOKEN_INFO_PTR = *mut CK_TOKEN_INFO;
pub type CK_MECHANISM_PTR = *mut CK_MECHANISM;
pub type CK_MECHANISM_INFO_PTR = *mut CK_MECHANISM_INFO;
pub type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;
pub type CK_SESSION_INFO_PTR = *mut CK_SESSION_INFO;

// =============================================================================
// Function List Structure
// =============================================================================

/// The main function list structure - this is the primary export of a PKCS#11 library.
/// Applications call C_GetFunctionList to obtain a pointer to this structure.
#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize: Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>,
    pub C_Finalize: Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>,
    pub C_GetInfo: Option<extern "C" fn(CK_INFO_PTR) -> CK_RV>,
    pub C_GetFunctionList: Option<extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV>,
    pub C_GetSlotList: Option<extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_GetSlotInfo: Option<extern "C" fn(CK_SLOT_ID, CK_SLOT_INFO_PTR) -> CK_RV>,
    pub C_GetTokenInfo: Option<extern "C" fn(CK_SLOT_ID, CK_TOKEN_INFO_PTR) -> CK_RV>,
    pub C_GetMechanismList:
        Option<extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_GetMechanismInfo:
        Option<extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR) -> CK_RV>,
    pub C_InitToken:
        Option<extern "C" fn(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) -> CK_RV>,
    pub C_InitPIN: Option<extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV>,
    pub C_SetPIN: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_UTF8CHAR_PTR,
            CK_ULONG,
            CK_UTF8CHAR_PTR,
            CK_ULONG,
        ) -> CK_RV,
    >,
    pub C_OpenSession: Option<
        extern "C" fn(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR) -> CK_RV,
    >,
    pub C_CloseSession: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CloseAllSessions: Option<extern "C" fn(CK_SLOT_ID) -> CK_RV>,
    pub C_GetSessionInfo: Option<extern "C" fn(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR) -> CK_RV>,
    pub C_GetOperationState:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SetOperationState: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_BYTE_PTR,
            CK_ULONG,
            CK_OBJECT_HANDLE,
            CK_OBJECT_HANDLE,
        ) -> CK_RV,
    >,
    pub C_Login:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV>,
    pub C_Logout: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CreateObject: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV,
    >,
    pub C_CopyObject: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_OBJECT_HANDLE,
            CK_ATTRIBUTE_PTR,
            CK_ULONG,
            CK_OBJECT_HANDLE_PTR,
        ) -> CK_RV,
    >,
    pub C_DestroyObject: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_GetObjectSize:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV>,
    pub C_GetAttributeValue: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV,
    >,
    pub C_SetAttributeValue: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV,
    >,
    pub C_FindObjectsInit:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_FindObjects: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_FindObjectsFinal: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_EncryptInit:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Encrypt: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_EncryptUpdate: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_EncryptFinal:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DecryptInit:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Decrypt: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_DecryptUpdate: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_DecryptFinal:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DigestInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV>,
    pub C_Digest: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_DigestUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_DigestKey: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DigestFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SignInit:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Sign: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_SignUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_SignFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SignRecoverInit:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_SignRecover: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_VerifyInit:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Verify: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    >,
    pub C_VerifyUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_VerifyFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_VerifyRecoverInit:
        Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_VerifyRecover: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_DigestEncryptUpdate: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_DecryptDigestUpdate: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_SignEncryptUpdate: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_DecryptVerifyUpdate: Option<
        extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    >,
    pub C_GenerateKey: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_MECHANISM_PTR,
            CK_ATTRIBUTE_PTR,
            CK_ULONG,
            CK_OBJECT_HANDLE_PTR,
        ) -> CK_RV,
    >,
    pub C_GenerateKeyPair: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_MECHANISM_PTR,
            CK_ATTRIBUTE_PTR,
            CK_ULONG,
            CK_ATTRIBUTE_PTR,
            CK_ULONG,
            CK_OBJECT_HANDLE_PTR,
            CK_OBJECT_HANDLE_PTR,
        ) -> CK_RV,
    >,
    pub C_WrapKey: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_MECHANISM_PTR,
            CK_OBJECT_HANDLE,
            CK_OBJECT_HANDLE,
            CK_BYTE_PTR,
            CK_ULONG_PTR,
        ) -> CK_RV,
    >,
    pub C_UnwrapKey: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_MECHANISM_PTR,
            CK_OBJECT_HANDLE,
            CK_BYTE_PTR,
            CK_ULONG,
            CK_ATTRIBUTE_PTR,
            CK_ULONG,
            CK_OBJECT_HANDLE_PTR,
        ) -> CK_RV,
    >,
    pub C_DeriveKey: Option<
        extern "C" fn(
            CK_SESSION_HANDLE,
            CK_MECHANISM_PTR,
            CK_OBJECT_HANDLE,
            CK_ATTRIBUTE_PTR,
            CK_ULONG,
            CK_OBJECT_HANDLE_PTR,
        ) -> CK_RV,
    >,
    pub C_SeedRandom: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_GenerateRandom: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_GetFunctionStatus: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CancelFunction: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_WaitForSlotEvent: Option<extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV>,
}

pub type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;

// =============================================================================
// Helper Functions
// =============================================================================

/// Create a padded UTF-8 string array for PKCS#11 structures.
/// The string is left-aligned and padded with spaces.
pub fn padded_string<const N: usize>(s: &str) -> [CK_UTF8CHAR; N] {
    let mut result = [b' '; N];
    let bytes = s.as_bytes();
    let len = bytes.len().min(N);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

/// Create a padded CHAR string array for PKCS#11 structures.
pub fn padded_char_string<const N: usize>(s: &str) -> [CK_CHAR; N] {
    let mut result = [b' '; N];
    let bytes = s.as_bytes();
    let len = bytes.len().min(N);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padded_string() {
        let result: [u8; 32] = padded_string("HSM Project");
        assert_eq!(&result[..11], b"HSM Project");
        assert_eq!(result[11], b' ');
        assert_eq!(result[31], b' ');
    }

    #[test]
    fn test_version_size() {
        assert_eq!(std::mem::size_of::<CK_VERSION>(), 2);
    }

    #[test]
    fn test_mechanism_alignment() {
        // Verify C-compatible alignment
        assert_eq!(
            std::mem::align_of::<CK_MECHANISM>(),
            std::mem::align_of::<*mut c_void>()
        );
    }
}
