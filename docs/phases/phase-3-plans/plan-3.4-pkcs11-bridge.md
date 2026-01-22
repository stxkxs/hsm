# Plan 3.4: PKCS#11 Bridge

## Overview

Create a PKCS#11 shared library that acts as a bridge to the HSM, allowing legacy applications (OpenSSL, browsers, Java KeyStore, etc.) to use the HSM transparently via the standard PKCS#11 interface.

## Goals

- Implement PKCS#11 v2.40 compliant shared library
- Support core cryptographic operations (sign, verify, encrypt, decrypt)
- Support key management operations (generate, import, export)
- Multi-slot support for namespaces
- Session management with authentication
- Thread-safe implementation

## PKCS#11 Background

PKCS#11 (Cryptoki) is a C API standard for cryptographic tokens. Applications load a `.so`/`.dylib`/`.dll` and call functions like:

```c
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, ...);
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, ...);
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, ...);
```

## Dependencies

Create new crate `crates/pkcs11-bridge/Cargo.toml`:

```toml
[package]
name = "hsm-pkcs11"
version.workspace = true
edition.workspace = true

[lib]
crate-type = ["cdylib"]  # Shared library

[dependencies]
# HSM client
hsm-grpc-api = { path = "../grpc-api" }
tonic = { workspace = true }
tokio = { workspace = true, features = ["rt-multi-thread", "sync"] }

# PKCS#11 bindings
pkcs11 = "0.5"           # PKCS#11 types and constants
# OR build from scratch with:
# libc = "0.2"

# Concurrency
parking_lot = { workspace = true }
dashmap = "6.1"
once_cell = "1.19"

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }

# Logging
tracing = { workspace = true }

# Configuration
config = "0.14"
directories = "5.0"
```

## File Structure

```
crates/pkcs11-bridge/
├── Cargo.toml
├── src/
│   ├── lib.rs              # C exports and initialization
│   ├── ffi.rs              # FFI types and conversions
│   ├── state.rs            # Global state management
│   ├── session.rs          # Session management
│   ├── slot.rs             # Slot/token management
│   ├── object.rs           # Object (key) management
│   ├── mechanism.rs        # Supported mechanisms
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── sign.rs         # Signing operations
│   │   ├── verify.rs       # Verification operations
│   │   ├── encrypt.rs      # Encryption operations
│   │   ├── decrypt.rs      # Decryption operations
│   │   ├── digest.rs       # Hash operations
│   │   └── keygen.rs       # Key generation
│   ├── config.rs           # Configuration loading
│   └── error.rs            # Error handling
├── include/
│   └── pkcs11.h            # PKCS#11 header (reference)
└── tests/
    └── integration.rs      # Integration tests
```

## Implementation Steps

### Step 1: Define FFI Types

Create `crates/pkcs11-bridge/src/ffi.rs`:

```rust
//! FFI types matching PKCS#11 C definitions

use std::ffi::c_void;

// PKCS#11 type aliases
pub type CK_BYTE = u8;
pub type CK_CHAR = u8;
pub type CK_UTF8CHAR = u8;
pub type CK_BBOOL = u8;
pub type CK_ULONG = std::ffi::c_ulong;
pub type CK_LONG = std::ffi::c_long;
pub type CK_FLAGS = CK_ULONG;

pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_CHAR_PTR = *mut CK_CHAR;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_VOID_PTR = *mut c_void;

// Handle types
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;

pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;

// Return value
pub type CK_RV = CK_ULONG;

// Return value constants
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
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;
pub const CKR_SESSION_READ_ONLY: CK_RV = 0x000000B5;
pub const CKR_SIGNATURE_INVALID: CK_RV = 0x000000C0;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED: CK_RV = 0x000000E1;
pub const CKR_USER_NOT_LOGGED_IN: CK_RV = 0x00000101;
pub const CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x00000100;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;

// Boolean values
pub const CK_FALSE: CK_BBOOL = 0;
pub const CK_TRUE: CK_BBOOL = 1;

// User types
pub const CKU_SO: CK_ULONG = 0;  // Security Officer
pub const CKU_USER: CK_ULONG = 1;

// Session flags
pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;

// Mechanism types
pub const CKM_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000001;
pub const CKM_RSA_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000000;
pub const CKM_SHA256_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000040;
pub const CKM_SHA384_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000041;
pub const CKM_SHA512_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000042;
pub const CKM_ECDSA: CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA256: CK_MECHANISM_TYPE = 0x00001043;
pub const CKM_EC_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001040;
pub const CKM_AES_KEY_GEN: CK_MECHANISM_TYPE = 0x00001080;
pub const CKM_AES_CBC: CK_MECHANISM_TYPE = 0x00001082;
pub const CKM_AES_GCM: CK_MECHANISM_TYPE = 0x00001087;
pub const CKM_SHA256: CK_MECHANISM_TYPE = 0x00000250;
pub const CKM_SHA384: CK_MECHANISM_TYPE = 0x00000260;
pub const CKM_SHA512: CK_MECHANISM_TYPE = 0x00000270;
pub const CKM_EDDSA: CK_MECHANISM_TYPE = 0x00001057;  // Ed25519

// Object classes
pub const CKO_PUBLIC_KEY: CK_ULONG = 0x00000002;
pub const CKO_PRIVATE_KEY: CK_ULONG = 0x00000003;
pub const CKO_SECRET_KEY: CK_ULONG = 0x00000004;
pub const CKO_CERTIFICATE: CK_ULONG = 0x00000001;

// Key types
pub const CKK_RSA: CK_ULONG = 0x00000000;
pub const CKK_EC: CK_ULONG = 0x00000003;
pub const CKK_AES: CK_ULONG = 0x0000001F;
pub const CKK_EC_EDWARDS: CK_ULONG = 0x00000040;  // Ed25519

// Structures
#[repr(C)]
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
pub struct CK_ATTRIBUTE {
    pub type_: CK_ULONG,
    pub value: CK_VOID_PTR,
    pub value_len: CK_ULONG,
}

pub type CK_INFO_PTR = *mut CK_INFO;
pub type CK_SLOT_INFO_PTR = *mut CK_SLOT_INFO;
pub type CK_TOKEN_INFO_PTR = *mut CK_TOKEN_INFO;
pub type CK_MECHANISM_PTR = *mut CK_MECHANISM;
pub type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;
pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;

// Function list (the main export)
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
    pub C_GetMechanismList: Option<extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_GetMechanismInfo: Option<extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV>,
    pub C_InitToken: Option<extern "C" fn(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) -> CK_RV>,
    pub C_InitPIN: Option<extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV>,
    pub C_SetPIN: Option<extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV>,
    pub C_OpenSession: Option<extern "C" fn(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR) -> CK_RV>,
    pub C_CloseSession: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CloseAllSessions: Option<extern "C" fn(CK_SLOT_ID) -> CK_RV>,
    pub C_GetSessionInfo: Option<extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV>,
    pub C_GetOperationState: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SetOperationState: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Login: Option<extern "C" fn(CK_SESSION_HANDLE, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV>,
    pub C_Logout: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CreateObject: Option<extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    pub C_CopyObject: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    pub C_DestroyObject: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_GetObjectSize: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV>,
    pub C_GetAttributeValue: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_SetAttributeValue: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_FindObjectsInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_FindObjects: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV>,
    pub C_FindObjectsFinal: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_EncryptInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Encrypt: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_EncryptUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_EncryptFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DecryptInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Decrypt: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DecryptUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DecryptFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DigestInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV>,
    pub C_Digest: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DigestUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_DigestKey: Option<extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_DigestFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SignInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Sign: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SignUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_SignFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SignRecoverInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_SignRecover: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_VerifyInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_Verify: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_VerifyUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_VerifyFinal: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_VerifyRecoverInit: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV>,
    pub C_VerifyRecover: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DigestEncryptUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DecryptDigestUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_SignEncryptUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_DecryptVerifyUpdate: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_GenerateKey: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    pub C_GenerateKeyPair: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    pub C_WrapKey: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV>,
    pub C_UnwrapKey: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    pub C_DeriveKey: Option<extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV>,
    pub C_SeedRandom: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_GenerateRandom: Option<extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV>,
    pub C_GetFunctionStatus: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_CancelFunction: Option<extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>,
    pub C_WaitForSlotEvent: Option<extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV>,
}

pub type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;

// Additional types needed
pub type CK_NOTIFY = Option<extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) -> CK_RV>;
pub type CK_NOTIFICATION = CK_ULONG;
pub type CK_UTF8CHAR_PTR = *mut CK_UTF8CHAR;

#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slot_id: CK_SLOT_ID,
    pub state: CK_ULONG,
    pub flags: CK_FLAGS,
    pub device_error: CK_ULONG,
}
```

### Step 2: Global State Management

Create `crates/pkcs11-bridge/src/state.rs`:

```rust
use parking_lot::RwLock;
use dashmap::DashMap;
use once_cell::sync::OnceCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::runtime::Runtime;

use crate::session::Session;
use crate::ffi::*;

/// Global state for the PKCS#11 library
pub struct GlobalState {
    pub initialized: AtomicBool,
    pub runtime: OnceCell<Runtime>,
    pub sessions: DashMap<CK_SESSION_HANDLE, Session>,
    pub next_session_handle: AtomicU64,
    pub config: RwLock<Option<Pkcs11Config>>,
}

impl GlobalState {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            runtime: OnceCell::new(),
            sessions: DashMap::new(),
            next_session_handle: AtomicU64::new(1),
            config: RwLock::new(None),
        }
    }

    pub fn initialize(&self) -> CK_RV {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }

        // Create tokio runtime for async HSM client
        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(_) => {
                self.initialized.store(false, Ordering::SeqCst);
                return CKR_HOST_MEMORY;
            }
        };

        if self.runtime.set(runtime).is_err() {
            self.initialized.store(false, Ordering::SeqCst);
            return CKR_GENERAL_ERROR;
        }

        // Load configuration
        match load_config() {
            Ok(config) => {
                *self.config.write() = Some(config);
            }
            Err(_) => {
                self.initialized.store(false, Ordering::SeqCst);
                return CKR_DEVICE_ERROR;
            }
        }

        CKR_OK
    }

    pub fn finalize(&self) -> CK_RV {
        if !self.initialized.swap(false, Ordering::SeqCst) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }

        // Close all sessions
        self.sessions.clear();

        CKR_OK
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn allocate_session_handle(&self) -> CK_SESSION_HANDLE {
        self.next_session_handle.fetch_add(1, Ordering::SeqCst)
    }
}

/// Global state singleton
pub static STATE: GlobalState = GlobalState::new();

/// Configuration for PKCS#11 bridge
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    pub hsm_endpoint: String,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub ca_cert_path: Option<String>,
    pub namespaces: Vec<String>,  // Each namespace = one slot
}

fn load_config() -> Result<Pkcs11Config, Box<dyn std::error::Error>> {
    // Load from:
    // 1. Environment variables (HSM_ENDPOINT, etc.)
    // 2. Config file (~/.hsm/pkcs11.toml)
    // 3. Default values

    let endpoint = std::env::var("HSM_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:50051".to_string());

    let namespaces = std::env::var("HSM_NAMESPACES")
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or_else(|_| vec!["default".to_string()]);

    Ok(Pkcs11Config {
        hsm_endpoint: endpoint,
        client_cert_path: std::env::var("HSM_CLIENT_CERT").ok(),
        client_key_path: std::env::var("HSM_CLIENT_KEY").ok(),
        ca_cert_path: std::env::var("HSM_CA_CERT").ok(),
        namespaces,
    })
}
```

### Step 3: Main Library Entry Point

Create `crates/pkcs11-bridge/src/lib.rs`:

```rust
//! PKCS#11 Bridge for HSM
//!
//! This library provides a PKCS#11 compliant interface to the HSM,
//! allowing legacy applications to use HSM cryptographic services.

mod ffi;
mod state;
mod session;
mod slot;
mod object;
mod mechanism;
mod crypto;
mod config;
mod error;

use ffi::*;
use state::STATE;

/// The function list - main export of the library
static mut FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
    C_Initialize: Some(c_initialize),
    C_Finalize: Some(c_finalize),
    C_GetInfo: Some(c_get_info),
    C_GetFunctionList: Some(c_get_function_list),
    C_GetSlotList: Some(c_get_slot_list),
    C_GetSlotInfo: Some(c_get_slot_info),
    C_GetTokenInfo: Some(c_get_token_info),
    C_GetMechanismList: Some(c_get_mechanism_list),
    C_GetMechanismInfo: Some(c_get_mechanism_info),
    C_InitToken: None,  // Not supported
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
    C_CreateObject: None,  // Keys created via HSM API
    C_CopyObject: None,
    C_DestroyObject: Some(c_destroy_object),
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(c_get_attribute_value),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(c_find_objects_init),
    C_FindObjects: Some(c_find_objects),
    C_FindObjectsFinal: Some(c_find_objects_final),
    C_EncryptInit: Some(c_encrypt_init),
    C_Encrypt: Some(c_encrypt),
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: Some(c_decrypt_init),
    C_Decrypt: Some(c_decrypt),
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: Some(c_digest_init),
    C_Digest: Some(c_digest),
    C_DigestUpdate: Some(c_digest_update),
    C_DigestKey: None,
    C_DigestFinal: Some(c_digest_final),
    C_SignInit: Some(c_sign_init),
    C_Sign: Some(c_sign),
    C_SignUpdate: None,
    C_SignFinal: None,
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: Some(c_verify_init),
    C_Verify: Some(c_verify),
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: Some(c_generate_key),
    C_GenerateKeyPair: Some(c_generate_key_pair),
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: Some(c_generate_random),
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

// === Core Functions ===

#[no_mangle]
pub extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    c_get_function_list(pp_function_list)
}

extern "C" fn c_get_function_list(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe {
        *pp_function_list = &mut FUNCTION_LIST;
    }
    CKR_OK
}

extern "C" fn c_initialize(_p_init_args: CK_VOID_PTR) -> CK_RV {
    STATE.initialize()
}

extern "C" fn c_finalize(_p_reserved: CK_VOID_PTR) -> CK_RV {
    STATE.finalize()
}

extern "C" fn c_get_info(p_info: CK_INFO_PTR) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let info = CK_INFO {
        cryptoki_version: CK_VERSION { major: 2, minor: 40 },
        manufacturer_id: padded_string("HSM Project", 32),
        flags: 0,
        library_description: padded_string("HSM PKCS#11 Bridge", 32),
        library_version: CK_VERSION { major: 1, minor: 0 },
    };

    unsafe {
        *p_info = info;
    }
    CKR_OK
}

// === Session Functions ===

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
    if (flags & CKF_SERIAL_SESSION) == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    // Validate slot ID
    let config = STATE.config.read();
    let config = match config.as_ref() {
        Some(c) => c,
        None => return CKR_DEVICE_ERROR,
    };

    if slot_id as usize >= config.namespaces.len() {
        return CKR_SLOT_ID_INVALID;
    }

    let namespace = config.namespaces[slot_id as usize].clone();
    drop(config);

    // Create session
    let handle = STATE.allocate_session_handle();
    let session = session::Session::new(
        handle,
        slot_id,
        namespace,
        (flags & CKF_RW_SESSION) != 0,
    );

    STATE.sessions.insert(handle, session);

    unsafe {
        *ph_session = handle;
    }
    CKR_OK
}

extern "C" fn c_close_session(h_session: CK_SESSION_HANDLE) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    match STATE.sessions.remove(&h_session) {
        Some(_) => CKR_OK,
        None => CKR_SESSION_HANDLE_INVALID,
    }
}

// ... implement remaining functions ...

// === Crypto Operation Stubs ===

extern "C" fn c_sign_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    crypto::sign::sign_init(h_session, p_mechanism, h_key)
}

extern "C" fn c_sign(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    crypto::sign::sign(h_session, p_data, ul_data_len, p_signature, pul_signature_len)
}

// Helper function
fn padded_string<const N: usize>(s: &str, _size: usize) -> [CK_UTF8CHAR; N] {
    let mut result = [b' '; N];
    let bytes = s.as_bytes();
    let len = bytes.len().min(N);
    result[..len].copy_from_slice(&bytes[..len]);
    result
}

// Add remaining extern "C" function stubs that delegate to modules...
```

### Step 4: Implement Session Management

Create `crates/pkcs11-bridge/src/session.rs`:

```rust
use crate::ffi::*;
use std::sync::atomic::{AtomicU32, Ordering};

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    RoPublic,
    RoUser,
    RwPublic,
    RwUser,
    RwSo,
}

/// Active cryptographic operation
#[derive(Debug)]
pub enum ActiveOperation {
    None,
    SignInit { mechanism: CK_MECHANISM_TYPE, key_handle: CK_OBJECT_HANDLE },
    VerifyInit { mechanism: CK_MECHANISM_TYPE, key_handle: CK_OBJECT_HANDLE },
    EncryptInit { mechanism: CK_MECHANISM_TYPE, key_handle: CK_OBJECT_HANDLE },
    DecryptInit { mechanism: CK_MECHANISM_TYPE, key_handle: CK_OBJECT_HANDLE },
    DigestInit { mechanism: CK_MECHANISM_TYPE, data: Vec<u8> },
    FindObjects { template: Vec<(CK_ULONG, Vec<u8>)>, results: Vec<CK_OBJECT_HANDLE>, position: usize },
}

/// PKCS#11 Session
pub struct Session {
    pub handle: CK_SESSION_HANDLE,
    pub slot_id: CK_SLOT_ID,
    pub namespace: String,
    pub read_write: bool,
    pub state: SessionState,
    pub operation: ActiveOperation,
    pub logged_in_user: Option<CK_ULONG>,
}

impl Session {
    pub fn new(
        handle: CK_SESSION_HANDLE,
        slot_id: CK_SLOT_ID,
        namespace: String,
        read_write: bool,
    ) -> Self {
        Self {
            handle,
            slot_id,
            namespace,
            read_write,
            state: if read_write {
                SessionState::RwPublic
            } else {
                SessionState::RoPublic
            },
            operation: ActiveOperation::None,
            logged_in_user: None,
        }
    }

    pub fn login(&mut self, user_type: CK_ULONG) -> CK_RV {
        if self.logged_in_user.is_some() {
            return CKR_USER_ALREADY_LOGGED_IN;
        }

        self.logged_in_user = Some(user_type);
        self.state = match (self.read_write, user_type) {
            (true, CKU_SO) => SessionState::RwSo,
            (true, CKU_USER) => SessionState::RwUser,
            (false, CKU_USER) => SessionState::RoUser,
            _ => return CKR_USER_TYPE_INVALID,
        };

        CKR_OK
    }

    pub fn logout(&mut self) -> CK_RV {
        if self.logged_in_user.is_none() {
            return CKR_USER_NOT_LOGGED_IN;
        }

        self.logged_in_user = None;
        self.state = if self.read_write {
            SessionState::RwPublic
        } else {
            SessionState::RoPublic
        };

        CKR_OK
    }

    pub fn is_logged_in(&self) -> bool {
        self.logged_in_user.is_some()
    }
}

const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x000000B2;
const CKR_USER_TYPE_INVALID: CK_RV = 0x00000103;
```

### Step 5: Implement Signing Operations

Create `crates/pkcs11-bridge/src/crypto/sign.rs`:

```rust
use crate::ffi::*;
use crate::state::STATE;
use crate::session::ActiveOperation;

pub fn sign_init(
    h_session: CK_SESSION_HANDLE,
    p_mechanism: CK_MECHANISM_PTR,
    h_key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut session = match STATE.sessions.get_mut(&h_session) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };

    if !session.is_logged_in() {
        return CKR_USER_NOT_LOGGED_IN;
    }

    if !matches!(session.operation, ActiveOperation::None) {
        return CKR_OPERATION_ACTIVE;
    }

    let mechanism = unsafe { (*p_mechanism).mechanism };

    // Validate mechanism
    if !is_sign_mechanism(mechanism) {
        return CKR_MECHANISM_INVALID;
    }

    session.operation = ActiveOperation::SignInit {
        mechanism,
        key_handle: h_key,
    };

    CKR_OK
}

pub fn sign(
    h_session: CK_SESSION_HANDLE,
    p_data: CK_BYTE_PTR,
    ul_data_len: CK_ULONG,
    p_signature: CK_BYTE_PTR,
    pul_signature_len: CK_ULONG_PTR,
) -> CK_RV {
    if !STATE.is_initialized() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if p_data.is_null() || pul_signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut session = match STATE.sessions.get_mut(&h_session) {
        Some(s) => s,
        None => return CKR_SESSION_HANDLE_INVALID,
    };

    let (mechanism, key_handle) = match &session.operation {
        ActiveOperation::SignInit { mechanism, key_handle } => (*mechanism, *key_handle),
        _ => return CKR_OPERATION_NOT_INITIALIZED,
    };

    // Get expected signature length
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

    // Call HSM to sign
    let runtime = match STATE.runtime.get() {
        Some(rt) => rt,
        None => return CKR_DEVICE_ERROR,
    };

    let result = runtime.block_on(async {
        call_hsm_sign(&session.namespace, key_handle, mechanism, data).await
    });

    match result {
        Ok(signature) => {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    signature.as_ptr(),
                    p_signature,
                    signature.len(),
                );
                *pul_signature_len = signature.len() as CK_ULONG;
            }
            session.operation = ActiveOperation::None;
            CKR_OK
        }
        Err(_) => {
            session.operation = ActiveOperation::None;
            CKR_FUNCTION_FAILED
        }
    }
}

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

fn signature_length_for_mechanism(mechanism: CK_MECHANISM_TYPE) -> usize {
    match mechanism {
        CKM_EDDSA => 64,  // Ed25519
        CKM_ECDSA | CKM_ECDSA_SHA256 => 64,  // P-256 (can be up to 72 with DER)
        CKM_RSA_PKCS | CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => 256,  // 2048-bit
        _ => 256,
    }
}

async fn call_hsm_sign(
    namespace: &str,
    key_handle: CK_OBJECT_HANDLE,
    mechanism: CK_MECHANISM_TYPE,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Connect to HSM and call Sign RPC
    // Map PKCS#11 mechanism to HSM algorithm
    // Map key handle to HSM key ID

    todo!("Implement HSM gRPC call")
}
```

## Testing Requirements

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_finalize() {
        let mut func_list: *mut CK_FUNCTION_LIST = std::ptr::null_mut();

        // Get function list
        let rv = C_GetFunctionList(&mut func_list);
        assert_eq!(rv, CKR_OK);
        assert!(!func_list.is_null());

        // Initialize
        let c_init = unsafe { (*func_list).C_Initialize.unwrap() };
        let rv = c_init(std::ptr::null_mut());
        assert_eq!(rv, CKR_OK);

        // Double initialize should fail
        let rv = c_init(std::ptr::null_mut());
        assert_eq!(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED);

        // Finalize
        let c_final = unsafe { (*func_list).C_Finalize.unwrap() };
        let rv = c_final(std::ptr::null_mut());
        assert_eq!(rv, CKR_OK);
    }

    #[test]
    fn test_session_lifecycle() {
        // Initialize
        // Open session
        // Login
        // Perform operation
        // Logout
        // Close session
        // Finalize
    }
}
```

### Integration Tests with OpenSSL

```bash
# Test with pkcs11-tool
pkcs11-tool --module ./target/release/libhsm_pkcs11.dylib --list-slots
pkcs11-tool --module ./target/release/libhsm_pkcs11.dylib --list-mechanisms
pkcs11-tool --module ./target/release/libhsm_pkcs11.dylib --login --pin 1234 --list-objects

# Test signing with OpenSSL
openssl pkeyutl -engine pkcs11 -keyform engine -sign \
    -inkey "pkcs11:token=HSM;object=mykey" \
    -in data.txt -out signature.bin
```

## Success Metrics

- [ ] OpenSSL can load and use the PKCS#11 module
- [ ] pkcs11-tool can list slots, mechanisms, and objects
- [ ] Sign/verify operations work through PKCS#11
- [ ] Multiple concurrent sessions work correctly
- [ ] Thread-safe operation under load
- [ ] Proper error codes returned for all failure cases

## Security Considerations

- PIN is mapped to HSM session token, not stored
- Session handles are randomized to prevent guessing
- Object handles are mapped, not exposing internal IDs
- No private key material passes through the bridge
