//! Global state management for the PKCS#11 library.
//!
//! This module manages the global state of the PKCS#11 library, including:
//! - Initialization state
//! - Tokio runtime for async HSM client calls
//! - Session management
//! - Configuration

use dashmap::DashMap;
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::runtime::Runtime;

use crate::ffi::*;
use crate::session::Session;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the PKCS#11 bridge.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// HSM gRPC endpoint (e.g., "https://localhost:50051")
    pub hsm_endpoint: String,
    /// Path to client certificate for mTLS (optional)
    pub client_cert_path: Option<String>,
    /// Path to client private key for mTLS (optional)
    pub client_key_path: Option<String>,
    /// Path to CA certificate for verifying HSM server (optional)
    pub ca_cert_path: Option<String>,
    /// Namespaces to expose as slots (each namespace = one slot)
    pub namespaces: Vec<String>,
}

impl Default for Pkcs11Config {
    fn default() -> Self {
        Self {
            hsm_endpoint: "https://localhost:50051".to_string(),
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
            namespaces: vec!["default".to_string()],
        }
    }
}

/// Load configuration from environment variables and/or config file.
fn load_config() -> Result<Pkcs11Config, String> {
    // Load from environment variables (highest priority)
    let endpoint =
        std::env::var("HSM_ENDPOINT").unwrap_or_else(|_| "https://localhost:50051".to_string());

    let namespaces = std::env::var("HSM_NAMESPACES")
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or_else(|_| vec!["default".to_string()]);

    let client_cert_path = std::env::var("HSM_CLIENT_CERT").ok();
    let client_key_path = std::env::var("HSM_CLIENT_KEY").ok();
    let ca_cert_path = std::env::var("HSM_CA_CERT").ok();

    Ok(Pkcs11Config {
        hsm_endpoint: endpoint,
        client_cert_path,
        client_key_path,
        ca_cert_path,
        namespaces,
    })
}

// =============================================================================
// Global State
// =============================================================================

/// Global state for the PKCS#11 library.
///
/// This structure holds all state needed for the library's operation.
/// It is designed for concurrent access from multiple threads.
pub struct GlobalState {
    /// Whether the library has been initialized via C_Initialize
    pub initialized: AtomicBool,

    /// Tokio runtime for async HSM client calls
    /// Created lazily on first use after initialization
    runtime: OnceCell<Runtime>,

    /// Active sessions, keyed by session handle
    /// Uses Lazy for initialization since DashMap::new() is not const
    sessions: Lazy<DashMap<CK_SESSION_HANDLE, Session>>,

    /// Counter for generating unique session handles
    next_session_handle: AtomicU64,

    /// Library configuration
    /// Uses Lazy for initialization since RwLock::new() is not const
    config: Lazy<RwLock<Option<Pkcs11Config>>>,
}

impl GlobalState {
    /// Initialize the PKCS#11 library.
    ///
    /// This must be called before any other PKCS#11 function (except C_GetFunctionList).
    /// Returns CKR_OK on success, or an appropriate error code.
    pub fn initialize(&self) -> CK_RV {
        // Check if already initialized (atomic swap to avoid race conditions)
        if self.initialized.swap(true, Ordering::SeqCst) {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }

        // Create tokio runtime for async HSM client calls
        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("Failed to create tokio runtime: {}", e);
                self.initialized.store(false, Ordering::SeqCst);
                return CKR_HOST_MEMORY;
            }
        };

        if self.runtime.set(runtime).is_err() {
            tracing::error!("Failed to set runtime (already set)");
            self.initialized.store(false, Ordering::SeqCst);
            return CKR_GENERAL_ERROR;
        }

        // Load configuration
        match load_config() {
            Ok(config) => {
                tracing::info!(
                    "PKCS#11 bridge initialized with {} slot(s)",
                    config.namespaces.len()
                );
                *self.config.write() = Some(config);
            }
            Err(e) => {
                tracing::error!("Failed to load configuration: {}", e);
                self.initialized.store(false, Ordering::SeqCst);
                return CKR_DEVICE_ERROR;
            }
        }

        CKR_OK
    }

    /// Finalize the PKCS#11 library.
    ///
    /// This releases all resources and closes all sessions.
    /// After this call, C_Initialize must be called again before using the library.
    pub fn finalize(&self) -> CK_RV {
        // Check if initialized (atomic swap to avoid race conditions)
        if !self.initialized.swap(false, Ordering::SeqCst) {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }

        // Close all sessions
        self.sessions.clear();

        // Clear configuration
        *self.config.write() = None;

        tracing::info!("PKCS#11 bridge finalized");

        CKR_OK
    }

    /// Check if the library is initialized.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Allocate a new unique session handle.
    pub fn allocate_session_handle(&self) -> CK_SESSION_HANDLE {
        self.next_session_handle.fetch_add(1, Ordering::SeqCst)
    }

    /// Get a reference to the tokio runtime.
    /// Returns None if the library is not initialized.
    pub fn runtime(&self) -> Option<&Runtime> {
        self.runtime.get()
    }

    /// Get the number of configured slots (namespaces).
    pub fn slot_count(&self) -> usize {
        self.config
            .read()
            .as_ref()
            .map(|c| c.namespaces.len())
            .unwrap_or(0)
    }

    /// Get the namespace for a given slot ID.
    pub fn get_namespace(&self, slot_id: CK_SLOT_ID) -> Option<String> {
        self.config
            .read()
            .as_ref()
            .and_then(|c| c.namespaces.get(slot_id as usize).cloned())
    }

    /// Close all sessions for a given slot.
    pub fn close_all_sessions_for_slot(&self, slot_id: CK_SLOT_ID) {
        self.sessions
            .retain(|_, session| session.slot_id != slot_id);
    }

    /// Get a session by handle, returning an error if not found.
    pub fn get_session(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<dashmap::mapref::one::Ref<'_, CK_SESSION_HANDLE, Session>, CK_RV> {
        self.sessions.get(&handle).ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    /// Get a mutable session by handle, returning an error if not found.
    pub fn get_session_mut(
        &self,
        handle: CK_SESSION_HANDLE,
    ) -> Result<dashmap::mapref::one::RefMut<'_, CK_SESSION_HANDLE, Session>, CK_RV> {
        self.sessions
            .get_mut(&handle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    /// Get direct access to the sessions DashMap.
    pub fn sessions(&self) -> &DashMap<CK_SESSION_HANDLE, Session> {
        &self.sessions
    }

    /// Re-initialize the library state after finalize (for testing).
    /// This is only useful when the runtime OnceCell has already been set.
    #[cfg(test)]
    pub fn reinitialize_for_test(&self) {
        use std::sync::atomic::Ordering;
        self.initialized.store(true, Ordering::SeqCst);
        if self.config.read().is_none() {
            *self.config.write() = Some(Pkcs11Config::default());
        }
    }
}

// =============================================================================
// Global Singleton
// =============================================================================

/// The global state singleton for the PKCS#11 library.
pub static STATE: GlobalState = GlobalState {
    initialized: AtomicBool::new(false),
    runtime: OnceCell::new(),
    sessions: Lazy::new(DashMap::new),
    next_session_handle: AtomicU64::new(1),
    config: Lazy::new(|| RwLock::new(None)),
};

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Tests that modify STATE should be run with --test-threads=1
    // because they share global state.

    #[test]
    fn test_config_default() {
        let config = Pkcs11Config::default();
        assert_eq!(config.hsm_endpoint, "https://localhost:50051");
        assert_eq!(config.namespaces, vec!["default"]);
    }
}
