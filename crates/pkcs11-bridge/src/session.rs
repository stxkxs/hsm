//! PKCS#11 Session management.
//!
//! This module handles session lifecycle, authentication state,
//! and active cryptographic operations.

use crate::ffi::*;
use sha2::{Digest, Sha256};

// =============================================================================
// Session State
// =============================================================================

/// Represents the authentication state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Read-only session, no user logged in
    RoPublic,
    /// Read-only session, user logged in
    RoUser,
    /// Read-write session, no user logged in
    RwPublic,
    /// Read-write session, user logged in
    RwUser,
    /// Read-write session, security officer logged in
    RwSo,
}

impl SessionState {
    /// Convert to PKCS#11 session state constant.
    pub fn to_ck_state(self) -> CK_ULONG {
        match self {
            SessionState::RoPublic => CKS_RO_PUBLIC_SESSION,
            SessionState::RoUser => CKS_RO_USER_FUNCTIONS,
            SessionState::RwPublic => CKS_RW_PUBLIC_SESSION,
            SessionState::RwUser => CKS_RW_USER_FUNCTIONS,
            SessionState::RwSo => CKS_RW_SO_FUNCTIONS,
        }
    }
}

// =============================================================================
// Active Operations
// =============================================================================

/// Represents an active cryptographic operation on a session.
///
/// PKCS#11 requires that operations be initialized before use,
/// and only one operation of each type can be active at a time.
#[derive(Debug, Default)]
pub enum ActiveOperation {
    /// No active operation
    #[default]
    None,

    /// SignInit has been called, waiting for Sign
    SignInit {
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    },

    /// VerifyInit has been called, waiting for Verify
    VerifyInit {
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    },

    /// EncryptInit has been called, waiting for Encrypt
    EncryptInit {
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    },

    /// DecryptInit has been called, waiting for Decrypt
    DecryptInit {
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    },

    /// DigestInit has been called, accumulating data
    DigestInit {
        mechanism: CK_MECHANISM_TYPE,
        /// Accumulated data for multi-part digest
        data: Vec<u8>,
    },

    /// FindObjectsInit has been called, search in progress
    FindObjects {
        /// Search template (attribute type, value)
        template: Vec<(CK_ULONG, Vec<u8>)>,
        /// Object handles matching the search
        results: Vec<CK_OBJECT_HANDLE>,
        /// Current position in results
        position: usize,
    },
}

// =============================================================================
// Session
// =============================================================================

/// Maximum number of PIN attempts before lockout
const MAX_PIN_ATTEMPTS: u8 = 3;

/// Represents a PKCS#11 session.
///
/// A session is opened on a specific slot (namespace) and maintains
/// authentication state and active cryptographic operations.
pub struct Session {
    /// Session handle (unique identifier)
    pub handle: CK_SESSION_HANDLE,

    /// Slot ID this session is opened on
    pub slot_id: CK_SLOT_ID,

    /// Namespace associated with this slot
    pub namespace: String,

    /// Whether this is a read-write session
    pub read_write: bool,

    /// Current session state (authentication level)
    pub state: SessionState,

    /// Currently active cryptographic operation
    pub operation: ActiveOperation,

    /// Logged in user type (if any)
    pub logged_in_user: Option<CK_USER_TYPE>,

    /// Session-specific authentication token (from HSM login)
    pub auth_token: Option<String>,

    /// Failed PIN attempt counter
    pin_attempts: u8,

    /// Stored PIN hash (SHA-256) for validation
    /// In production, this would come from the token/slot configuration
    pin_hash: Option<Vec<u8>>,
}

impl Session {
    /// Create a new session.
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
            auth_token: None,
            pin_attempts: 0,
            pin_hash: None,
        }
    }

    /// Set the expected PIN hash for this session's slot.
    /// The hash should be SHA-256 of the correct PIN.
    pub fn set_pin_hash(&mut self, pin_hash: Vec<u8>) {
        self.pin_hash = Some(pin_hash);
    }

    /// Log in a user.
    ///
    /// The PIN is used to authenticate with the HSM and obtain a session token.
    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: &[u8]) -> CK_RV {
        // Check if already logged in
        if self.logged_in_user.is_some() {
            return CKR_USER_ALREADY_LOGGED_IN;
        }

        // Check if PIN is locked due to too many failed attempts
        if self.pin_attempts >= MAX_PIN_ATTEMPTS {
            return CKR_PIN_LOCKED;
        }

        // Validate user type
        let new_state = match (self.read_write, user_type) {
            (true, CKU_SO) => SessionState::RwSo,
            (true, CKU_USER) => SessionState::RwUser,
            (false, CKU_USER) => SessionState::RoUser,
            (false, CKU_SO) => {
                // SO cannot log into read-only session
                return CKR_SESSION_READ_ONLY;
            }
            _ => return CKR_USER_TYPE_INVALID,
        };

        // Validate PIN: hash the provided PIN and compare against stored hash
        if let Some(expected_hash) = &self.pin_hash {
            let mut hasher = Sha256::new();
            hasher.update(pin);
            let pin_hash = hasher.finalize().to_vec();

            if pin_hash != *expected_hash {
                self.pin_attempts += 1;
                if self.pin_attempts >= MAX_PIN_ATTEMPTS {
                    return CKR_PIN_LOCKED;
                }
                return CKR_PIN_INCORRECT;
            }
        }

        // PIN validated successfully - reset attempt counter
        self.pin_attempts = 0;
        self.logged_in_user = Some(user_type);
        self.state = new_state;
        tracing::warn!(
            "HSM backend authentication is not yet integrated; session token not issued"
        );
        self.auth_token = None;

        CKR_OK
    }

    /// Log out the current user.
    ///
    /// Note: HSM backend session token invalidation is not yet implemented.
    /// Currently only clears local session state.
    pub fn logout(&mut self) -> CK_RV {
        // Check if logged in
        if self.logged_in_user.is_none() {
            return CKR_USER_NOT_LOGGED_IN;
        }

        self.logged_in_user = None;
        self.auth_token = None;
        self.state = if self.read_write {
            SessionState::RwPublic
        } else {
            SessionState::RoPublic
        };

        // Clear any active operation that requires login
        self.operation = ActiveOperation::None;

        CKR_OK
    }

    /// Check if a user is logged in.
    #[inline]
    pub fn is_logged_in(&self) -> bool {
        self.logged_in_user.is_some()
    }

    /// Get session info structure.
    pub fn get_info(&self) -> CK_SESSION_INFO {
        CK_SESSION_INFO {
            slot_id: self.slot_id,
            state: self.state.to_ck_state(),
            flags: CKF_SERIAL_SESSION | if self.read_write { CKF_RW_SESSION } else { 0 },
            device_error: 0,
        }
    }

    /// Check if an operation is active.
    pub fn has_active_operation(&self) -> bool {
        !matches!(self.operation, ActiveOperation::None)
    }

    /// Clear the active operation.
    pub fn clear_operation(&mut self) {
        self.operation = ActiveOperation::None;
    }

    /// Set up a sign operation.
    pub fn init_sign(
        &mut self,
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        if self.has_active_operation() {
            return CKR_OPERATION_ACTIVE;
        }

        self.operation = ActiveOperation::SignInit {
            mechanism,
            key_handle,
        };

        CKR_OK
    }

    /// Set up a verify operation.
    pub fn init_verify(
        &mut self,
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        if self.has_active_operation() {
            return CKR_OPERATION_ACTIVE;
        }

        self.operation = ActiveOperation::VerifyInit {
            mechanism,
            key_handle,
        };

        CKR_OK
    }

    /// Set up an encrypt operation.
    pub fn init_encrypt(
        &mut self,
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        if self.has_active_operation() {
            return CKR_OPERATION_ACTIVE;
        }

        self.operation = ActiveOperation::EncryptInit {
            mechanism,
            key_handle,
        };

        CKR_OK
    }

    /// Set up a decrypt operation.
    pub fn init_decrypt(
        &mut self,
        mechanism: CK_MECHANISM_TYPE,
        key_handle: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        if self.has_active_operation() {
            return CKR_OPERATION_ACTIVE;
        }

        self.operation = ActiveOperation::DecryptInit {
            mechanism,
            key_handle,
        };

        CKR_OK
    }

    /// Set up a digest operation.
    pub fn init_digest(&mut self, mechanism: CK_MECHANISM_TYPE) -> CK_RV {
        if self.has_active_operation() {
            return CKR_OPERATION_ACTIVE;
        }

        self.operation = ActiveOperation::DigestInit {
            mechanism,
            data: Vec::new(),
        };

        CKR_OK
    }

    /// Set up a find objects operation.
    pub fn init_find_objects(&mut self, template: Vec<(CK_ULONG, Vec<u8>)>) -> CK_RV {
        if self.has_active_operation() {
            return CKR_OPERATION_ACTIVE;
        }

        self.operation = ActiveOperation::FindObjects {
            template,
            results: Vec::new(), // Will be populated when search is performed
            position: 0,
        };

        CKR_OK
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: compute SHA-256 of a PIN
    fn hash_pin(pin: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(pin);
        hasher.finalize().to_vec()
    }

    #[test]
    fn test_session_new() {
        let session = Session::new(1, 0, "default".to_string(), true);
        assert_eq!(session.handle, 1);
        assert_eq!(session.slot_id, 0);
        assert!(session.read_write);
        assert_eq!(session.state, SessionState::RwPublic);
        assert!(!session.is_logged_in());
    }

    #[test]
    fn test_session_login_logout() {
        let mut session = Session::new(1, 0, "default".to_string(), true);
        session.set_pin_hash(hash_pin(b"1234"));

        // Login as user
        let rv = session.login(CKU_USER, b"1234");
        assert_eq!(rv, CKR_OK);
        assert!(session.is_logged_in());
        assert_eq!(session.state, SessionState::RwUser);

        // Double login should fail
        let rv = session.login(CKU_USER, b"1234");
        assert_eq!(rv, CKR_USER_ALREADY_LOGGED_IN);

        // Logout
        let rv = session.logout();
        assert_eq!(rv, CKR_OK);
        assert!(!session.is_logged_in());
        assert_eq!(session.state, SessionState::RwPublic);

        // Double logout should fail
        let rv = session.logout();
        assert_eq!(rv, CKR_USER_NOT_LOGGED_IN);
    }

    #[test]
    fn test_pin_incorrect() {
        let mut session = Session::new(1, 0, "default".to_string(), true);
        session.set_pin_hash(hash_pin(b"correct_pin"));

        let rv = session.login(CKU_USER, b"wrong_pin");
        assert_eq!(rv, CKR_PIN_INCORRECT);
        assert!(!session.is_logged_in());
    }

    #[test]
    fn test_pin_lockout_after_max_attempts() {
        let mut session = Session::new(1, 0, "default".to_string(), true);
        session.set_pin_hash(hash_pin(b"correct_pin"));

        // Attempt 1 - wrong
        let rv = session.login(CKU_USER, b"wrong1");
        assert_eq!(rv, CKR_PIN_INCORRECT);

        // Attempt 2 - wrong
        let rv = session.login(CKU_USER, b"wrong2");
        assert_eq!(rv, CKR_PIN_INCORRECT);

        // Attempt 3 - wrong, triggers lockout
        let rv = session.login(CKU_USER, b"wrong3");
        assert_eq!(rv, CKR_PIN_LOCKED);

        // Even correct PIN should fail now
        let rv = session.login(CKU_USER, b"correct_pin");
        assert_eq!(rv, CKR_PIN_LOCKED);
    }

    #[test]
    fn test_session_state_to_ck() {
        assert_eq!(SessionState::RoPublic.to_ck_state(), CKS_RO_PUBLIC_SESSION);
        assert_eq!(SessionState::RoUser.to_ck_state(), CKS_RO_USER_FUNCTIONS);
        assert_eq!(SessionState::RwPublic.to_ck_state(), CKS_RW_PUBLIC_SESSION);
        assert_eq!(SessionState::RwUser.to_ck_state(), CKS_RW_USER_FUNCTIONS);
        assert_eq!(SessionState::RwSo.to_ck_state(), CKS_RW_SO_FUNCTIONS);
    }

    #[test]
    fn test_operation_exclusivity() {
        let mut session = Session::new(1, 0, "default".to_string(), true);

        // First operation should succeed
        let rv = session.init_sign(CKM_ECDSA, 1);
        assert_eq!(rv, CKR_OK);

        // Second operation should fail (operation active)
        let rv = session.init_verify(CKM_ECDSA, 2);
        assert_eq!(rv, CKR_OPERATION_ACTIVE);

        // Clear and try again
        session.clear_operation();
        let rv = session.init_verify(CKM_ECDSA, 2);
        assert_eq!(rv, CKR_OK);
    }

    #[test]
    fn test_get_session_info() {
        let session = Session::new(1, 0, "default".to_string(), true);
        let info = session.get_info();

        assert_eq!(info.slot_id, 0);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION);
        assert_eq!(info.flags & CKF_RW_SESSION, CKF_RW_SESSION);
        assert_eq!(info.flags & CKF_SERIAL_SESSION, CKF_SERIAL_SESSION);
    }
}
