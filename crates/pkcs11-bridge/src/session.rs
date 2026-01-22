//! PKCS#11 Session management.
//!
//! This module handles session lifecycle, authentication state,
//! and active cryptographic operations.

use crate::ffi::*;

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
        }
    }

    /// Log in a user.
    ///
    /// The PIN is used to authenticate with the HSM and obtain a session token.
    pub fn login(&mut self, user_type: CK_USER_TYPE, _pin: &[u8]) -> CK_RV {
        // Check if already logged in
        if self.logged_in_user.is_some() {
            return CKR_USER_ALREADY_LOGGED_IN;
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

        // TODO: Actually authenticate with HSM using the PIN
        // For now, we just update the local state
        // In a real implementation, this would:
        // 1. Call HSM login API with namespace and PIN
        // 2. Store the returned session token
        // 3. Return appropriate error if authentication fails

        self.logged_in_user = Some(user_type);
        self.state = new_state;
        self.auth_token = Some("placeholder_token".to_string()); // TODO: Real HSM token

        CKR_OK
    }

    /// Log out the current user.
    pub fn logout(&mut self) -> CK_RV {
        // Check if logged in
        if self.logged_in_user.is_none() {
            return CKR_USER_NOT_LOGGED_IN;
        }

        // TODO: Invalidate HSM session token

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
