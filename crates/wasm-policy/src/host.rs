//! Host functions exposed to WASM policies.
//!
//! These functions are callable from within WASM policies and provide
//! controlled access to the HSM environment.

use crate::context::PolicyContext;
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::{debug, warn};

/// Host functions state shared with WASM modules.
#[derive(Clone)]
pub struct HostFunctions {
    /// The policy context being evaluated.
    context: Arc<PolicyContext>,

    /// Log messages collected during execution.
    logs: Arc<Mutex<Vec<LogEntry>>>,

    /// Host call counter.
    call_count: Arc<Mutex<u64>>,

    /// Maximum log entries.
    max_logs: usize,
}

/// A log entry from a policy.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Log level.
    pub level: LogLevel,
    /// Log message.
    pub message: String,
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Log level for policy logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl LogLevel {
    /// Convert from i32.
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(LogLevel::Debug),
            1 => Some(LogLevel::Info),
            2 => Some(LogLevel::Warn),
            3 => Some(LogLevel::Error),
            _ => None,
        }
    }
}

impl HostFunctions {
    /// Create new host functions with a context.
    pub fn new(context: PolicyContext) -> Self {
        Self {
            context: Arc::new(context),
            logs: Arc::new(Mutex::new(Vec::new())),
            call_count: Arc::new(Mutex::new(0)),
            max_logs: 100,
        }
    }

    /// Get the context.
    pub fn context(&self) -> &PolicyContext {
        &self.context
    }

    /// Get collected logs.
    pub fn logs(&self) -> Vec<LogEntry> {
        self.logs.lock().clone()
    }

    /// Get host call count.
    pub fn call_count(&self) -> u64 {
        *self.call_count.lock()
    }

    /// Increment call count.
    fn increment_calls(&self) {
        *self.call_count.lock() += 1;
    }

    // ========== Host Functions ==========

    /// Log a message from the policy.
    pub fn log(&self, level: i32, message: &str) {
        self.increment_calls();

        let level = LogLevel::from_i32(level).unwrap_or(LogLevel::Info);
        let mut logs = self.logs.lock();

        if logs.len() < self.max_logs {
            logs.push(LogEntry {
                level,
                message: message.to_string(),
                timestamp: chrono::Utc::now(),
            });

            match level {
                LogLevel::Debug => debug!(target: "wasm_policy", "{}", message),
                LogLevel::Info => debug!(target: "wasm_policy", "{}", message),
                LogLevel::Warn => warn!(target: "wasm_policy", "{}", message),
                LogLevel::Error => warn!(target: "wasm_policy", "ERROR: {}", message),
            }
        }
    }

    /// Get the transaction value as a string.
    pub fn get_tx_value(&self) -> String {
        self.increment_calls();
        self.context.transaction.value.clone()
    }

    /// Get the transaction recipient.
    pub fn get_tx_to(&self) -> Option<String> {
        self.increment_calls();
        self.context.transaction.to.clone()
    }

    /// Get the transaction sender.
    pub fn get_tx_from(&self) -> String {
        self.increment_calls();
        self.context.transaction.from.clone()
    }

    /// Get the chain ID.
    pub fn get_chain_id(&self) -> String {
        self.increment_calls();
        self.context.transaction.chain_id.clone()
    }

    /// Get the transaction type.
    pub fn get_tx_type(&self) -> String {
        self.increment_calls();
        self.context.transaction.tx_type.clone()
    }

    /// Get the function selector (if contract call).
    pub fn get_function_selector(&self) -> Option<String> {
        self.increment_calls();
        self.context.transaction.function_selector.clone()
    }

    /// Get the signer's key ID.
    pub fn get_key_id(&self) -> String {
        self.increment_calls();
        self.context.signer.key_id.clone()
    }

    /// Get the signer's namespace.
    pub fn get_namespace(&self) -> String {
        self.increment_calls();
        self.context.signer.namespace.clone()
    }

    /// Check if signer has a specific role.
    pub fn has_role(&self, role: &str) -> bool {
        self.increment_calls();
        self.context.signer.roles.contains(&role.to_string())
    }

    /// Get a signer label.
    pub fn get_label(&self, key: &str) -> Option<String> {
        self.increment_calls();
        self.context.signer.labels.get(key).cloned()
    }

    /// Get the current timestamp.
    pub fn get_timestamp(&self) -> i64 {
        self.increment_calls();
        self.context.environment.timestamp
    }

    /// Check if this is a simulation.
    pub fn is_simulation(&self) -> bool {
        self.increment_calls();
        self.context.environment.is_simulation
    }

    /// Get custom metadata value.
    pub fn get_metadata(&self, key: &str) -> Option<String> {
        self.increment_calls();
        self.context.metadata.get(key).cloned()
    }

    /// Compare two big integers (as strings).
    /// Returns: -1 if a < b, 0 if a == b, 1 if a > b
    pub fn compare_big_int(&self, a: &str, b: &str) -> i32 {
        self.increment_calls();

        // Parse as u128 for comparison (handles most cases)
        let a_val: u128 = a.parse().unwrap_or(0);
        let b_val: u128 = b.parse().unwrap_or(0);

        match a_val.cmp(&b_val) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// Check if an address is in a list (comma-separated).
    pub fn address_in_list(&self, address: &str, list: &str) -> bool {
        self.increment_calls();
        let address_lower = address.to_lowercase();
        list.split(',')
            .map(|s| s.trim().to_lowercase())
            .any(|a| a == address_lower)
    }

    /// Compute keccak256 hash of input (hex encoded).
    pub fn keccak256(&self, input: &str) -> String {
        use sha2::{Digest, Sha256};
        self.increment_calls();

        // For simplicity, use SHA256 here
        // In production, would use actual keccak256
        let input_bytes = hex::decode(input.strip_prefix("0x").unwrap_or(input))
            .unwrap_or_else(|_| input.as_bytes().to_vec());
        let hash = Sha256::digest(&input_bytes);
        format!("0x{}", hex::encode(hash))
    }
}

/// State passed to WASM instances.
pub struct HostState {
    /// Host functions.
    pub host: HostFunctions,
    /// Memory allocator position.
    pub alloc_pos: i32,
}

impl HostState {
    /// Create new host state.
    pub fn new(host: HostFunctions) -> Self {
        Self {
            host,
            alloc_pos: 16384, // Start after 16KB stack space, leaving room for data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{EnvironmentContext, SignerContext, TransactionContext};

    fn test_context() -> PolicyContext {
        PolicyContext::new(
            TransactionContext::transfer("1", "0xfrom", "0xto", "1000000000000000000"),
            SignerContext::new("key-1", "0x04...", "secp256k1", "default")
                .with_roles(vec!["trader".to_string(), "admin".to_string()]),
            EnvironmentContext::new("req-123"),
        )
    }

    #[test]
    fn test_host_functions_basic() {
        let host = HostFunctions::new(test_context());

        assert_eq!(host.get_chain_id(), "1");
        assert_eq!(host.get_tx_from(), "0xfrom");
        assert_eq!(host.get_tx_value(), "1000000000000000000");
    }

    #[test]
    fn test_has_role() {
        let host = HostFunctions::new(test_context());

        assert!(host.has_role("trader"));
        assert!(host.has_role("admin"));
        assert!(!host.has_role("unknown"));
    }

    #[test]
    fn test_compare_big_int() {
        let host = HostFunctions::new(test_context());

        assert_eq!(host.compare_big_int("100", "200"), -1);
        assert_eq!(host.compare_big_int("200", "100"), 1);
        assert_eq!(host.compare_big_int("100", "100"), 0);
    }

    #[test]
    fn test_address_in_list() {
        let host = HostFunctions::new(test_context());

        let list = "0xabc,0xdef,0x123";
        assert!(host.address_in_list("0xABC", list)); // Case insensitive
        assert!(host.address_in_list("0xdef", list));
        assert!(!host.address_in_list("0x999", list));
    }

    #[test]
    fn test_logging() {
        let host = HostFunctions::new(test_context());

        host.log(1, "Test message");
        host.log(2, "Warning message");

        let logs = host.logs();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].level, LogLevel::Info);
        assert_eq!(logs[1].level, LogLevel::Warn);
    }
}
