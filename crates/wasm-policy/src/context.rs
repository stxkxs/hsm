//! Policy execution context.
//!
//! This module defines the context passed to policies during evaluation.
//! The context contains information about the transaction, signer, and environment.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Context passed to policies during evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// The transaction being evaluated.
    pub transaction: TransactionContext,

    /// Information about the signer.
    pub signer: SignerContext,

    /// Environment information.
    pub environment: EnvironmentContext,

    /// Custom metadata (key-value pairs).
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl PolicyContext {
    /// Create a new policy context.
    pub fn new(
        transaction: TransactionContext,
        signer: SignerContext,
        environment: EnvironmentContext,
    ) -> Self {
        Self {
            transaction,
            signer,
            environment,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the context.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Serialize to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Transaction information for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionContext {
    /// Transaction type (e.g., "ethereum_transfer", "bitcoin_send", "starknet_invoke").
    pub tx_type: String,

    /// Chain ID or network identifier.
    pub chain_id: String,

    /// Recipient address (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,

    /// Sender address.
    pub from: String,

    /// Transaction value in smallest unit (wei, satoshi, etc.) as string.
    #[serde(default)]
    pub value: String,

    /// Transaction data (hex encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,

    /// Gas limit (for EVM chains).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,

    /// Gas price in wei (for EVM chains).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<String>,

    /// Max fee per gas (EIP-1559).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<String>,

    /// Max priority fee per gas (EIP-1559).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<String>,

    /// Nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,

    /// Contract function selector (first 4 bytes of data).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_selector: Option<String>,

    /// Decoded function name (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,

    /// Decoded function arguments (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_args: Option<Vec<FunctionArg>>,

    /// Token transfers (for ERC-20, etc.).
    #[serde(default)]
    pub token_transfers: Vec<TokenTransfer>,

    /// Raw transaction hash (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

impl TransactionContext {
    /// Create a simple transfer transaction context.
    pub fn transfer(
        chain_id: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            tx_type: "transfer".to_string(),
            chain_id: chain_id.into(),
            from: from.into(),
            to: Some(to.into()),
            value: value.into(),
            data: None,
            gas_limit: None,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
            function_selector: None,
            function_name: None,
            function_args: None,
            token_transfers: Vec::new(),
            tx_hash: None,
        }
    }

    /// Create a contract call transaction context.
    pub fn contract_call(
        chain_id: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        data: impl Into<String>,
    ) -> Self {
        let data_str = data.into();
        let function_selector = if data_str.len() >= 10 {
            Some(data_str[..10].to_string())
        } else {
            None
        };

        Self {
            tx_type: "contract_call".to_string(),
            chain_id: chain_id.into(),
            from: from.into(),
            to: Some(to.into()),
            value: "0".to_string(),
            data: Some(data_str),
            gas_limit: None,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
            function_selector,
            function_name: None,
            function_args: None,
            token_transfers: Vec::new(),
            tx_hash: None,
        }
    }
}

/// Decoded function argument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionArg {
    /// Argument name.
    pub name: String,
    /// Argument type (e.g., "address", "uint256").
    pub arg_type: String,
    /// Argument value as string.
    pub value: String,
}

/// Token transfer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransfer {
    /// Token contract address.
    pub token_address: String,
    /// Token symbol (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Token decimals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    /// Recipient address.
    pub to: String,
    /// Transfer amount in smallest unit.
    pub amount: String,
}

/// Signer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerContext {
    /// Key ID being used for signing.
    pub key_id: String,

    /// Public key (hex encoded).
    pub public_key: String,

    /// Key type (e.g., "secp256k1", "ed25519", "stark").
    pub key_type: String,

    /// Namespace the key belongs to.
    pub namespace: String,

    /// User ID requesting the signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Session ID (if using session-based auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Roles assigned to the user/session.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Labels attached to the key.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl SignerContext {
    /// Create a new signer context.
    pub fn new(
        key_id: impl Into<String>,
        public_key: impl Into<String>,
        key_type: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            public_key: public_key.into(),
            key_type: key_type.into(),
            namespace: namespace.into(),
            user_id: None,
            session_id: None,
            roles: Vec::new(),
            labels: HashMap::new(),
        }
    }

    /// Add user ID.
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Add session ID.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Add roles.
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = roles;
        self
    }

    /// Add a label.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// Environment information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentContext {
    /// Current timestamp (Unix seconds).
    pub timestamp: i64,

    /// Request ID for tracing.
    pub request_id: String,

    /// Source IP address (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    /// User agent (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// Geographic location (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_location: Option<GeoLocation>,

    /// Whether this is a test/simulation request.
    #[serde(default)]
    pub is_simulation: bool,
}

impl EnvironmentContext {
    /// Create a new environment context with current timestamp.
    pub fn new(request_id: impl Into<String>) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            request_id: request_id.into(),
            source_ip: None,
            user_agent: None,
            geo_location: None,
            is_simulation: false,
        }
    }

    /// Set source IP.
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set as simulation.
    pub fn as_simulation(mut self) -> Self {
        self.is_simulation = true;
        self
    }
}

/// Geographic location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Country code (ISO 3166-1 alpha-2).
    pub country: String,
    /// Region/state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// City.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_serialization() {
        let tx = TransactionContext::transfer("1", "0xabc", "0xdef", "1000000000000000000");
        let signer = SignerContext::new("key-1", "0x04...", "secp256k1", "default");
        let env = EnvironmentContext::new("req-123");

        let context = PolicyContext::new(tx, signer, env).with_metadata("custom", "value");

        let bytes = context.to_json_bytes().unwrap();
        let parsed = PolicyContext::from_json_bytes(&bytes).unwrap();

        assert_eq!(parsed.transaction.chain_id, "1");
        assert_eq!(parsed.metadata.get("custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_contract_call_context() {
        let tx = TransactionContext::contract_call(
            "1",
            "0xsender",
            "0xcontract",
            "0xa9059cbb000000000000000000000000recipient0000000000000000000000000000000amount",
        );

        assert_eq!(tx.tx_type, "contract_call");
        assert_eq!(tx.function_selector, Some("0xa9059cbb".to_string()));
    }
}
